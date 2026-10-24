//! P-256 key types, principal ids, canonical transcripts, the principal
//! registry and verification for the concordium/structmux identity design
//! (structmux `docs/superpowers/specs/2026-10-11-daemon-mesh-schema-design.md`;
//! verification: `2026-10-12-fleet-phase1b-identity-verification-design.md`).
//! Pure: no I/O, no clock, no key storage. Every primitive comes from
//! `rust_jwk_duo` (re-exported as [`jwk_duo`]); this crate owns byte layouts,
//! validation and verification.
//!
//! Verified types have no public constructor, so code that needs one
//! cannot skip the check that produces it:
//!
//! ```compile_fail,E0451
//! fn forge(r: identity_crypto::Resolver) -> identity_crypto::Resolver { identity_crypto::Resolver { ..r } }
//! ```
//! ```compile_fail,E0451
//! fn forge(d: identity_crypto::VerifiedDocument) -> identity_crypto::VerifiedDocument { identity_crypto::VerifiedDocument { ..d } }
//! ```
//! ```compile_fail,E0451
//! fn forge(c: identity_crypto::VerifiedChain) -> identity_crypto::VerifiedChain { identity_crypto::VerifiedChain { ..c } }
//! ```
//! ```compile_fail,E0451
//! fn forge(p: identity_crypto::VerifiedPeerRevocation) -> identity_crypto::VerifiedPeerRevocation { identity_crypto::VerifiedPeerRevocation { ..p } }
//! ```
//! ```compile_fail,E0451
//! fn forge(a: identity_crypto::VerifiedApproval) -> identity_crypto::VerifiedApproval { identity_crypto::VerifiedApproval { ..a } }
//! ```
//! ```compile_fail,E0451
//! fn forge(e: identity_crypto::VerifiedEntry) -> identity_crypto::VerifiedEntry { identity_crypto::VerifiedEntry { ..e } }
//! ```

mod authority;
mod accepted;
mod error;
mod principal;
mod registry;
mod resolver;
mod verify;
mod public_key;
mod signature;
pub mod transcripts;

#[cfg(test)]
pub(crate) mod testkit;

pub use authority::{verify_signed_document, AuthorityChain, VerifiedDocument};
pub use accepted::AcceptedChains;
pub use error::{Error, Result};
pub use principal::{PrincipalId, ShortId};
pub use public_key::{PublicKey, PublicKeyDuo};
pub use registry::{AllowedHost, PrincipalKind, VerifiedBinding, VerifiedEntry};
pub use resolver::{Resolver, VerifiedPeerRevocation};
pub use verify::{
    verify_approval, verify_chain, verify_peer_revocation, verify_signed_message, AcceptedAt, Host,
    VerifiedApproval, VerifiedChain, VerifiedMessage, When,
    MAX_SESSION_SECONDS, MAX_UNLISTED_DELEGATION_SECONDS, SKEW_SECONDS,
};
pub use signature::{verify_p256, VerifiedSignature};
pub use rust_jwk_duo as jwk_duo;

/// The absolute path to this crate's `proto/` directory, resolved at this
/// crate's compile time so it is right for path and git dependencies alike.
/// A consumer importing `identitycrypto/v1/identity.proto` lists this crate
/// under `[build-dependencies]` and passes this to `compile_protos`.
pub fn proto_include_dir() -> &'static str {
    concat!(env!("CARGO_MANIFEST_DIR"), "/proto")
}

/// Generated from `proto/identitycrypto/v1/identity.proto`. Private: the
/// only public path to these types is [`pb`].
#[allow(clippy::useless_borrows_in_formatting)] // pbjson-build 0.7 output
mod proto {
    pub mod identitycrypto {
        pub mod v1 {
            include!(concat!(env!("OUT_DIR"), "/identitycrypto.v1.rs"));
            include!(concat!(env!("OUT_DIR"), "/identitycrypto.v1.serde.rs"));
        }
    }
}

/// The wire types. `PublicKey` at the crate root is the validated Rust type;
/// `pb::PublicKey` is the proto.
pub use proto::identitycrypto::v1 as pb;

#[cfg(test)]
mod proto_tests {
    use super::*;
    use prost::Message;

    fn key(b: u8) -> pb::PublicKey {
        pb::PublicKey { scheme: pb::KeyScheme::EcdsaP256 as i32, key: vec![b; 65] }
    }

    #[test]
    fn enum_discriminants_are_pinned() {
        assert_eq!(pb::KeyScheme::Unspecified as i32, 0);
        assert!(pb::KeyScheme::try_from(1).is_err() && pb::KeyScheme::try_from(2).is_err(), "1 and 2 are reserved");
        assert_eq!(pb::KeyScheme::EcdsaP256 as i32, 3);
        assert_eq!(pb::KeyPurpose::Unspecified as i32, 0);
        assert_eq!(pb::KeyPurpose::Root as i32, 1);
        assert_eq!(pb::KeyPurpose::Device as i32, 2);
        assert_eq!(pb::KeyPurpose::Approval as i32, 3);
        assert_eq!(pb::KeyPurpose::Encryption as i32, 4);
        assert_eq!(pb::PrincipalKind::Unspecified as i32, 0);
        assert_eq!(pb::PrincipalKind::Human as i32, 1);
        assert_eq!(pb::PrincipalKind::Agent as i32, 2);
        assert_eq!(pb::PrincipalKind::Daemon as i32, 3);
    }

    fn round_trip<M: Message + Default + PartialEq + std::fmt::Debug>(m: M) {
        let back = M::decode(m.encode_to_vec().as_slice()).unwrap();
        assert_eq!(back, m);
    }

    fn cert() -> pb::DelegationCert {
        pb::DelegationCert {
            not_before_unix_seconds: 1, not_after_unix_seconds: 2, signature: vec![9; 64],
            principal_genesis: Some(key(1)), mode: 1, device: Some(key(2)), session: Some(key(3)),
            host_genesis: Some(key(4)), subject: Some("3b6a27bcceb6a42d/i5".into()),
        }
    }

    fn delegation() -> pb::KeyDelegation {
        pb::KeyDelegation {
            principal_genesis: Some(key(1)), signing_root: Some(key(1)), purpose: pb::KeyPurpose::Device as i32,
            delegated: Some(key(2)), delegated_encryption: Some(key(3)), issued_at_unix_seconds: 5,
            not_after_unix_seconds: 6, signature: vec![7; 64],
        }
    }

    #[test]
    fn every_message_round_trips_through_protobuf() {
        round_trip(key(1)); round_trip(cert());
        round_trip(pb::PublicKeyDuo { signing: Some(key(1)), encryption: Some(key(2)) });
        round_trip(delegation());
        round_trip(pb::RootRotation { principal_genesis: Some(key(1)), old_root: Some(key(1)), new_root: Some(key(2)), issued_at_unix_seconds: 3, signature: vec![1; 64] });
        round_trip(pb::KeyRevocation { principal_genesis: Some(key(1)), revoked: Some(key(2)), revoked_by: Some(key(1)), revoked_at_unix_seconds: 3, signature: vec![1; 64] });
        round_trip(pb::SignedMessage {
            signer: Some(pb::SignerChain { chain: Some(pb::signer_chain::Chain::SelfRooted(pb::SelfRooted { device: Some(delegation()), session: Some(cert()) })) }),
            audience: "structmux:3b6a27bcceb6a42d".into(), nonce: vec![1; 16], issued_at_unix_seconds: 4,
            in_reply_to_nonce: Some(vec![2; 16]), body_type: "type.googleapis.com/x.Y".into(), body: vec![1, 2, 3], signature: vec![3; 64],
        });
        round_trip(pb::SignerChain { chain: Some(pb::signer_chain::Chain::HostVouched(pb::HostVouched { host_device: Some(delegation()), session: Some(cert()) })) });
        round_trip(pb::SignedDocument { signer_genesis: Some(key(1)), signing: Some(key(1)), document_type: "t".into(), version: u64::MAX, issued_at_unix_seconds: 1, expires_at_unix_seconds: 7, body: vec![1], signature: vec![2; 64], signer_rotations: vec![] });
        round_trip(pb::Approval { principal_genesis: Some(key(1)), approval_key: Some(key(2)), device: Some(key(3)), audience: "a".into(), request_id: "r1".into(), request_digest: vec![0; 32], accept: true, issued_at_unix_seconds: 1, signature: vec![1; 64] });
        round_trip(pb::PeerRevocation { revoker_genesis: Some(key(1)), approval_key: Some(key(2)), target_genesis: Some(key(3)), revoked: None, issued_at_unix_seconds: 1, signature: vec![1; 64], document_id: vec![5; 32] });
        let entry = pb::RegistryEntry {
            principal_id: "p256:04".into(), kind: pb::PrincipalKind::Daemon as i32,
            name: Some("laptop".into()), frozen: true,
            current_root: Some(pb::PublicKeyDuo { signing: Some(key(1)), encryption: Some(key(2)) }),
            rotations: vec![], revocations: vec![],
            devices: vec![pb::DeviceBinding { device: Some(delegation()), approval: Some(delegation()), host_daemon_id: Some("p256:05".into()) }],
            allowed_hosts: vec!["*".into()],
        };
        round_trip(pb::RegistryCarrier { registry: Some(pb::PrincipalRegistry { entries: vec![entry], allow_peer_revocation: true }) });
        round_trip(pb::AcceptedChains { principals: vec![pb::AcceptedPrincipal { principal_id: "p256:04".into(), kind: 3, rotations: vec![] }] });
        round_trip(pb::DeliveryAttestation { key_id: "k".into(), batch_sequence: 1, attested_at: Some(prost_types::Timestamp { seconds: 1, nanos: 2 }), messages: vec![pb::AttestedMessage { message_id: "m".into(), room_id: "r".into(), body_text: "b".into(), delegation_cert: Some(cert()), author_genesis: Some(key(1)) }], signature: vec![1; 64], recipient_devices: vec![key(5), key(6)] });
    }

    #[test]
    fn pbjson_round_trips_public_key_and_delegation_cert() {
        let k = key(1); let json = serde_json::to_string(&k).unwrap();
        assert_eq!(serde_json::from_str::<pb::PublicKey>(&json).unwrap(), k);
        let c = cert(); let json = serde_json::to_string(&c).unwrap();
        assert_eq!(serde_json::from_str::<pb::DelegationCert>(&json).unwrap(), c);
    }

    #[test]
    fn proto_include_dir_points_at_the_real_proto_file() {
        let path = std::path::Path::new(proto_include_dir()).join("identitycrypto/v1/identity.proto");
        assert!(path.exists(), "{} should exist", path.display());
    }
}
