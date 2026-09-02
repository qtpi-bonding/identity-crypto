//! Cryptographic identity primitives for the grorg/gait/multimatrix
//! agent-identity design (`concordat/2026-09-01-agent-identity-model-design.md`
//! in the `concordium` monorepo). This crate is deliberately narrow: it
//! builds the canonical signed transcripts and verifies raw ed25519
//! signatures. It does not do RPC calls, storage, or key generation/storage
//! -- those stay in each consumer's own repo. The point of pulling this
//! specific ~150 lines out on its own is that a single wrong byte in a
//! transcript layout breaks every cross-repo signature; having exactly one
//! implementation removes that whole class of bug by construction instead
//! of relying on review to catch drift between independently-written
//! copies.

pub mod transcripts;

/// Generated from `proto/identitycrypto/v1/identity.proto` -- the two
/// pieces of this design nobody repo owns: `KeyScheme` (the discriminant
/// every transcript embeds as a raw byte, previously and accidentally
/// re-defined identically in grorg/gait/multimatrix's own protos) and
/// `DelegationCert` (session-delegation, minted locally, never owned by
/// any one repo's storage). Everything else -- Agent/AgentKey and grorg's
/// RPC surface, gait's Event/Provenance log, multimatrix's RoomMessage --
/// stays defined in its one real owner's own proto, not here.
pub mod proto {
    pub mod identitycrypto {
        pub mod v1 {
            include!(concat!(env!("OUT_DIR"), "/identitycrypto.v1.rs"));
        }
    }
}

pub use proto::identitycrypto::v1::{DelegationCert, KeyScheme};

use anyhow::{anyhow, Context, Result};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

/// Decode a hex-encoded ed25519 public key (grorg's `AgentKey.public_key`
/// wire type) into its raw 32 bytes. Never hex-encode a value that's
/// already gone through this.
pub fn hex_decode_32(public_key_hex: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(public_key_hex).context("public_key is not valid hex")?;
    bytes
        .try_into()
        .map_err(|_| anyhow!("ed25519 public key must be 32 bytes"))
}

/// Verify a raw ed25519 signature against a hex-encoded public key.
pub fn verify_ed25519(public_key_hex: &str, message: &[u8], signature: &[u8]) -> Result<bool> {
    let public_bytes = hex_decode_32(public_key_hex)?;
    let verifying_key = VerifyingKey::from_bytes(&public_bytes)
        .map_err(|e| anyhow!("invalid ed25519 public key: {e}"))?;
    let sig_bytes: [u8; 64] = signature
        .try_into()
        .map_err(|_| anyhow!("ed25519 signature must be 64 bytes"))?;
    let signature = Signature::from_bytes(&sig_bytes);
    Ok(verifying_key.verify(message, &signature).is_ok())
}

#[cfg(test)]
mod proto_tests {
    use super::*;

    #[test]
    fn key_scheme_discriminants_are_pinned() {
        // Load-bearing: every transcript in this crate serializes a scheme
        // as a raw byte. Changing any of these numbers is a breaking
        // change for every repo that depends on this crate.
        assert_eq!(KeyScheme::Unspecified as i32, 0);
        assert_eq!(KeyScheme::Ed25519 as i32, 1);
        assert_eq!(KeyScheme::Secp256k1Schnorr as i32, 2);
    }

    #[test]
    fn key_scheme_try_from_round_trips_every_known_value() {
        assert_eq!(KeyScheme::try_from(0).unwrap(), KeyScheme::Unspecified);
        assert_eq!(KeyScheme::try_from(1).unwrap(), KeyScheme::Ed25519);
        assert_eq!(KeyScheme::try_from(2).unwrap(), KeyScheme::Secp256k1Schnorr);
    }

    #[test]
    fn key_scheme_unknown_discriminant_errors() {
        assert!(KeyScheme::try_from(99).is_err());
    }

    #[test]
    fn delegation_cert_round_trips_through_protobuf_bytes() {
        use prost::Message;
        let cert = DelegationCert {
            agent_id: "agent-1".into(),
            device_public_key: vec![1u8; 32],
            session_public_key: vec![2u8; 32],
            not_before_unix_seconds: 100,
            not_after_unix_seconds: 200,
            signature: vec![3u8; 64],
        };
        let bytes = cert.encode_to_vec();
        let decoded = DelegationCert::decode(bytes.as_slice()).unwrap();
        assert_eq!(cert, decoded);
    }
}

#[cfg(test)]
mod verify_tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    #[test]
    fn genuine_signature_verifies() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let hex_pub = hex::encode(signing_key.verifying_key().to_bytes());
        let msg = b"hello";
        let sig = signing_key.sign(msg);
        assert!(verify_ed25519(&hex_pub, msg, &sig.to_bytes()).unwrap());
    }

    #[test]
    fn tampered_message_does_not_verify() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let hex_pub = hex::encode(signing_key.verifying_key().to_bytes());
        let sig = signing_key.sign(b"hello");
        assert!(!verify_ed25519(&hex_pub, b"goodbye", &sig.to_bytes()).unwrap());
    }

    #[test]
    fn malformed_hex_errors_rather_than_panics() {
        assert!(verify_ed25519("not-hex", b"msg", &[0u8; 64]).is_err());
    }
}
