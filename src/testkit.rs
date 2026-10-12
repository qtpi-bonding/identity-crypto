//! Test fixtures: real P-256 keys and real signatures. Nothing here builds
//! a verified type by hand; tests reach those only through the public
//! verify functions.
#![allow(dead_code, clippy::items_after_test_module)]

use crate::jwk_duo::{GenerationService, SigningKeyPair};
use crate::transcripts::*;
use crate::{pb, PrincipalId, PublicKey};
use prost::Message;

pub const T0: i64 = 1_700_000_000;
pub const DAY: i64 = 86_400;
pub const DOC_TYPE: &str = "type.googleapis.com/test.v1.RegistryDocument";

pub fn pk(k: &PublicKey) -> Option<pb::PublicKey> {
    Some(pb::PublicKey::from(k))
}

pub fn enc_key() -> PublicKey {
    PublicKey::from(GenerationService::generate_key_duo().encryption_key_pair())
}

pub struct Signer(SigningKeyPair);

impl Signer {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self(SigningKeyPair::generate())
    }

    pub fn public(&self) -> PublicKey {
        PublicKey::from(&self.0)
    }

    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        self.0.sign_bytes(msg).unwrap().to_vec()
    }
}

/// A self-rooted principal: `roots[0]` is the genesis key, the last is current.
pub struct Principal {
    roots: Vec<Signer>,
    root_enc: PublicKey,
    pub rotations: Vec<pb::RootRotation>,
}

impl Principal {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            roots: vec![Signer::new()],
            root_enc: enc_key(),
            rotations: vec![],
        }
    }

    pub fn genesis(&self) -> PublicKey {
        self.roots[0].public()
    }

    pub fn id(&self) -> PrincipalId {
        PrincipalId::from_genesis(self.genesis())
    }

    pub fn root(&self) -> &Signer {
        self.roots.last().unwrap()
    }

    pub fn root_at(&self, i: usize) -> &Signer {
        &self.roots[i]
    }

    pub fn rotate(&mut self, at: i64) {
        let new = Signer::new();
        let mut rotation = pb::RootRotation {
            principal_genesis: pk(&self.genesis()),
            old_root: pk(&self.root().public()),
            new_root: pk(&new.public()),
            issued_at_unix_seconds: at,
            signature: vec![],
        };
        rotation.signature = self
            .root()
            .sign(&root_rotation_transcript(&rotation).unwrap());
        self.rotations.push(rotation);
        self.roots.push(new);
    }

    pub fn current_root(&self) -> pb::PublicKeyDuo {
        pb::PublicKeyDuo {
            signing: pk(&self.root().public()),
            encryption: pk(&self.root_enc),
        }
    }

    pub fn sign_delegation(&self, delegation: &mut pb::KeyDelegation) {
        delegation.signature = self
            .root()
            .sign(&key_delegation_transcript(delegation).unwrap());
    }

    /// A DEVICE delegation of a fresh duo, signed by the current root.
    pub fn delegate_device(
        &self,
        issued_at: i64,
        not_after: i64,
    ) -> (Signer, pb::KeyDelegation) {
        let device = Signer::new();
        let mut delegation = pb::KeyDelegation {
            principal_genesis: pk(&self.genesis()),
            signing_root: pk(&self.root().public()),
            purpose: pb::KeyPurpose::Device as i32,
            delegated: pk(&device.public()),
            delegated_encryption: pk(&enc_key()),
            issued_at_unix_seconds: issued_at,
            not_after_unix_seconds: not_after,
            signature: vec![],
        };
        self.sign_delegation(&mut delegation);
        (device, delegation)
    }

    /// An APPROVAL delegation of a fresh key, signed by the current root.
    pub fn delegate_approval(
        &self,
        issued_at: i64,
        not_after: i64,
    ) -> (Signer, pb::KeyDelegation) {
        let key = Signer::new();
        let mut delegation = pb::KeyDelegation {
            principal_genesis: pk(&self.genesis()),
            signing_root: pk(&self.root().public()),
            purpose: pb::KeyPurpose::Approval as i32,
            delegated: pk(&key.public()),
            delegated_encryption: None,
            issued_at_unix_seconds: issued_at,
            not_after_unix_seconds: not_after,
            signature: vec![],
        };
        self.sign_delegation(&mut delegation);
        (key, delegation)
    }

    /// A revocation of `revoked` signed by the current root.
    pub fn revoke(&self, revoked: &PublicKey, at: i64) -> pb::KeyRevocation {
        let mut revocation = pb::KeyRevocation {
            principal_genesis: pk(&self.genesis()),
            revoked: pk(revoked),
            revoked_by: pk(&self.root().public()),
            revoked_at_unix_seconds: at,
            signature: vec![],
        };
        revocation.signature = self
            .root()
            .sign(&key_revocation_transcript(&revocation).unwrap());
        revocation
    }
}

/// A registry entry for a self-rooted principal, carrying its rotations.
pub fn entry(p: &Principal, kind: pb::PrincipalKind) -> pb::RegistryEntry {
    pb::RegistryEntry {
        principal_id: p.id().to_string(),
        kind: kind as i32,
        current_root: Some(p.current_root()),
        rotations: p.rotations.clone(),
        ..Default::default()
    }
}

pub fn carrier_body(reg: &pb::PrincipalRegistry) -> Vec<u8> {
    pb::RegistryCarrier {
        registry: Some(reg.clone()),
    }
    .encode_to_vec()
}

/// A document signed by `authority`'s current root, carrying its rotations.
pub fn sign_document(
    authority: &Principal,
    version: u64,
    body: Vec<u8>,
) -> pb::SignedDocument {
    let mut document = pb::SignedDocument {
        signer_genesis: pk(&authority.genesis()),
        signing: pk(&authority.root().public()),
        document_type: DOC_TYPE.into(),
        version,
        issued_at_unix_seconds: T0,
        expires_at_unix_seconds: T0 + 90 * DAY,
        body,
        signature: vec![],
        signer_rotations: authority.rotations.clone(),
    };
    resign_document(authority, &mut document);
    document
}

pub fn resign_document(authority: &Principal, document: &mut pb::SignedDocument) {
    document.signature = authority
        .root()
        .sign(&signed_document_transcript(document).unwrap());
}

/// A session cert under `device` for `principal`, signed by `device`.
pub fn session_cert(
    device: &Signer,
    principal: &PublicKey,
    host: Option<&PublicKey>,
    subject: Option<&str>,
    not_before: i64,
    not_after: i64,
) -> (Signer, pb::DelegationCert) {
    let session = Signer::new();
    let mut cert = pb::DelegationCert {
        not_before_unix_seconds: not_before,
        not_after_unix_seconds: not_after,
        signature: vec![],
        principal_genesis: pk(principal),
        mode: u32::from(host.is_some()),
        device: pk(&device.public()),
        session: pk(&session.public()),
        host_genesis: host.and_then(pk),
        subject: subject.map(str::to_string),
    };
    sign_cert(device, &mut cert);
    (session, cert)
}

pub fn sign_cert(device: &Signer, cert: &mut pb::DelegationCert) {
    cert.signature = device
        .sign(&session_delegation_transcript(cert).unwrap());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify_p256;

    #[test]
    fn fixtures_sign_for_real() {
        let mut principal = Principal::new();
        principal.rotate(T0);
        let (_, delegation) = principal.delegate_device(T0, T0 + DAY);
        assert!(verify_p256(
            &principal.root().public(),
            &key_delegation_transcript(&delegation).unwrap(),
            &delegation.signature
        )
        .is_ok());
        let document = sign_document(&principal, 1, vec![1]);
        assert!(verify_p256(
            &principal.root().public(),
            &signed_document_transcript(&document).unwrap(),
            &document.signature
        )
        .is_ok());
        assert_eq!(document.signer_rotations.len(), 1);
    }
}
