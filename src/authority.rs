//! The authority's root chain and verified documents (1b spec section 3).

use crate::transcripts::{root_rotation_transcript, signed_document_transcript};
use crate::{pb, verify_p256, Error, PrincipalId, PublicKey, Result};
use sha2::{Digest, Sha256};

fn req(k: Option<&pb::PublicKey>, field: &'static str) -> Result<PublicKey> {
    PublicKey::try_from(k.ok_or(Error::MissingField(field))?)
}

/// Checks a rotation list from `genesis`; returns the roots, genesis first.
pub(crate) fn rotation_roots(
    genesis: &PublicKey,
    rotations: &[pb::RootRotation],
) -> Result<Vec<PublicKey>> {
    let mut roots = vec![genesis.clone()];
    for r in rotations {
        if &req(r.principal_genesis.as_ref(), "rotations.principal_genesis")? != genesis {
            return Err(Error::ChainMismatch("rotation principal"));
        }
        let old = req(r.old_root.as_ref(), "rotations.old_root")?;
        let new = req(r.new_root.as_ref(), "rotations.new_root")?;
        if Some(&old) != roots.last() {
            return Err(Error::ChainMismatch("rotation old_root"));
        }
        if roots.contains(&new) {
            return Err(Error::RotationCycle);
        }
        verify_p256(&old, &root_rotation_transcript(r)?, &r.signature)?;
        roots.push(new);
    }
    Ok(roots)
}

/// The authority's genesis key and accepted rotations.
#[derive(Clone, Debug, PartialEq)]
pub struct AuthorityChain {
    roots: Vec<PublicKey>,
    rotations: Vec<pb::RootRotation>,
}

impl AuthorityChain {
    pub fn genesis(genesis: PublicKey) -> Self {
        Self {
            roots: vec![genesis],
            rotations: vec![],
        }
    }

    pub fn from_rotations(
        genesis: PublicKey,
        rotations: &[pb::RootRotation],
    ) -> Result<Self> {
        Ok(Self {
            roots: rotation_roots(&genesis, rotations)?,
            rotations: rotations.to_vec(),
        })
    }

    pub fn principal(&self) -> PrincipalId {
        PrincipalId::from_genesis(self.roots[0].clone())
    }

    pub fn head(&self) -> &PublicKey {
        self.roots.last().expect("never empty")
    }

    pub fn roots(&self) -> &[PublicKey] {
        &self.roots
    }

    pub fn rotations(&self) -> &[pb::RootRotation] {
        &self.rotations
    }

    pub fn is_prefix_of(&self, other: &AuthorityChain) -> bool {
        self.roots.len() <= other.roots.len()
            && self.roots[..] == other.roots[..self.roots.len()]
    }
}

/// A document whose signature, signer and root chain have been checked.
#[derive(Clone, Debug)]
pub struct VerifiedDocument {
    id: [u8; 32],
    chain: AuthorityChain,
    document_type: String,
    version: u64,
    issued_at: i64,
    expires_at: i64,
    body: Vec<u8>,
}

impl VerifiedDocument {
    pub fn document_type(&self) -> &str {
        &self.document_type
    }

    pub fn version(&self) -> u64 {
        self.version
    }

    pub fn issued_at(&self) -> i64 {
        self.issued_at
    }

    pub fn expires_at(&self) -> i64 {
        self.expires_at
    }

    pub fn body(&self) -> &[u8] {
        &self.body
    }

    pub fn id(&self) -> &[u8; 32] {
        &self.id
    }

    pub fn authority(&self) -> PrincipalId {
        self.chain.principal()
    }

    pub fn authority_chain(&self) -> &AuthorityChain {
        &self.chain
    }
}

pub fn verify_signed_document(
    doc: &pb::SignedDocument,
    expected_type: &str,
    accepted: &AuthorityChain,
) -> Result<VerifiedDocument> {
    if doc.signature.is_empty() {
        return Err(Error::EmptySignature);
    }
    if doc.expires_at_unix_seconds == 0 {
        return Err(Error::InvalidField {
            field: "expires_at_unix_seconds",
            reason: "0 is not an expiry; write i64::MAX for none",
        });
    }
    if doc.document_type != expected_type {
        return Err(Error::WrongDocumentType);
    }
    let signer = req(doc.signer_genesis.as_ref(), "signer_genesis")?;
    if &signer != accepted.roots.first().expect("never empty") {
        return Err(Error::NotAuthority);
    }
    let chain = AuthorityChain::from_rotations(signer, &doc.signer_rotations)?;
    let n = accepted.roots.len().min(chain.roots.len());
    if chain.roots[..n] != accepted.roots[..n] {
        return Err(Error::RootFork {
            principal: accepted.principal(),
        });
    }
    if chain.roots.len() < accepted.roots.len() {
        return Err(Error::StaleRoot);
    }
    let signing = req(doc.signing.as_ref(), "signing")?;
    if &signing != chain.head() {
        return Err(Error::NotCurrentRoot);
    }
    let transcript = signed_document_transcript(doc)?;
    verify_p256(&signing, &transcript, &doc.signature)?;
    let mut id = [0u8; 32];
    id.copy_from_slice(&Sha256::digest(&transcript));
    Ok(VerifiedDocument {
        id,
        chain,
        document_type: doc.document_type.clone(),
        version: doc.version,
        issued_at: doc.issued_at_unix_seconds,
        expires_at: doc.expires_at_unix_seconds,
        body: doc.body.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::*;
    use prost::Message;

    fn accept(p: &Principal) -> AuthorityChain { AuthorityChain::genesis(p.genesis()) }

    #[test]
    fn accepts_a_document_from_the_genesis_root() {
        let p = Principal::new();
        let doc = sign_document(&p, 3, vec![9]);
        let v = verify_signed_document(&doc, DOC_TYPE, &accept(&p)).unwrap();
        assert_eq!((v.version(), v.body(), v.document_type()), (3, &[9u8][..], DOC_TYPE));
        assert_eq!(v.authority(), p.id());
        assert_eq!(v.authority_chain().head(), &p.genesis());
    }

    #[test]
    fn extends_equal_prefix_and_fork() {
        let mut p = Principal::new();
        let accepted_at_genesis = accept(&p);
        p.rotate(T0);
        let v = verify_signed_document(&sign_document(&p, 2, vec![]), DOC_TYPE, &accepted_at_genesis).unwrap();
        let accepted_now = v.authority_chain().clone();
        assert_eq!(accepted_now.head(), &p.root().public());
        assert!(verify_signed_document(&sign_document(&p, 3, vec![]), DOC_TYPE, &accepted_now).is_ok());
        let mut stale = sign_document(&p, 4, vec![]);
        stale.signer_rotations.clear();
        stale.signing = pk(&p.genesis());
        stale.signature = p.root_at(0).sign(&crate::transcripts::signed_document_transcript(&stale).unwrap());
        assert_eq!(verify_signed_document(&stale, DOC_TYPE, &accepted_now).unwrap_err(), Error::StaleRoot);
        let mut fork = pb::RootRotation {
            principal_genesis: pk(&p.genesis()), old_root: pk(&p.genesis()),
            new_root: pk(&Signer::new().public()), issued_at_unix_seconds: T0, signature: vec![],
        };
        fork.signature = p.root_at(0).sign(&crate::transcripts::root_rotation_transcript(&fork).unwrap());
        let mut forked = sign_document(&p, 5, vec![]);
        forked.signer_rotations = vec![fork];
        assert!(matches!(verify_signed_document(&forked, DOC_TYPE, &accepted_now), Err(Error::RootFork { .. })));
    }

    #[test]
    fn rejections() {
        let p = Principal::new();
        let a = accept(&p);
        let base = sign_document(&p, 1, vec![]);
        let mut empty = base.clone(); empty.signature.clear();
        assert_eq!(verify_signed_document(&empty, DOC_TYPE, &a).unwrap_err(), Error::EmptySignature);
        let mut never = base.clone(); never.expires_at_unix_seconds = 0; resign_document(&p, &mut never);
        assert!(matches!(verify_signed_document(&never, DOC_TYPE, &a), Err(Error::InvalidField { field: "expires_at_unix_seconds", .. })));
        assert_eq!(verify_signed_document(&base, "other", &a).unwrap_err(), Error::WrongDocumentType);
        let stranger = Principal::new();
        assert_eq!(verify_signed_document(&sign_document(&stranger, 1, vec![]), DOC_TYPE, &a).unwrap_err(), Error::NotAuthority);
        let mut wrong_signing = base.clone(); wrong_signing.signing = pk(&Signer::new().public());
        assert_eq!(verify_signed_document(&wrong_signing, DOC_TYPE, &a).unwrap_err(), Error::NotCurrentRoot);
        let mut tampered = base.clone(); tampered.version = 2;
        assert_eq!(verify_signed_document(&tampered, DOC_TYPE, &a).unwrap_err(), Error::BadSignature);
        assert!(verify_signed_document(&base, DOC_TYPE, &a).is_ok());
    }

    #[test]
    fn rotation_list_checks() {
        let mut p = Principal::new();
        p.rotate(T0);
        p.rotate(T0 + 1);
        let g = p.genesis();
        assert_eq!(rotation_roots(&g, &p.rotations).unwrap().len(), 3);
        let mut bad_sig = p.rotations.clone();
        bad_sig[1].signature = p.root_at(0).sign(&crate::transcripts::root_rotation_transcript(&bad_sig[1]).unwrap());
        assert_eq!(rotation_roots(&g, &bad_sig).unwrap_err(), Error::BadSignature);
        let swapped = vec![p.rotations[1].clone(), p.rotations[0].clone()];
        assert_eq!(rotation_roots(&g, &swapped).unwrap_err(), Error::ChainMismatch("rotation old_root"));
        let q = { let mut q = Principal::new(); q.rotate(T0); q };
        assert_eq!(rotation_roots(&g, &q.rotations).unwrap_err(), Error::ChainMismatch("rotation principal"));
        let mut back = pb::RootRotation {
            principal_genesis: pk(&g), old_root: pk(&p.root().public()), new_root: pk(&g),
            issued_at_unix_seconds: T0 + 2, signature: vec![],
        };
        back.signature = p.root().sign(&crate::transcripts::root_rotation_transcript(&back).unwrap());
        let mut cyc = p.rotations.clone(); cyc.push(back);
        assert_eq!(rotation_roots(&g, &cyc).unwrap_err(), Error::RotationCycle);
    }

    #[test]
    fn document_id_survives_reencoding() {
        let p = Principal::new();
        let doc = sign_document(&p, 1, vec![1, 2, 3]);
        let mut bytes = doc.encode_to_vec();
        bytes.extend([0xa0, 0x06, 0x01]);
        let relayed = pb::SignedDocument::decode(bytes.as_slice()).unwrap();
        let a = AuthorityChain::genesis(p.genesis());
        let id1 = *verify_signed_document(&doc, DOC_TYPE, &a).unwrap().id();
        let id2 = *verify_signed_document(&relayed, DOC_TYPE, &a).unwrap().id();
        assert_eq!(id1, id2);
        let mut want = [0u8; 32];
        want.copy_from_slice(&sha2::Sha256::digest(crate::transcripts::signed_document_transcript(&doc).unwrap()));
        assert_eq!(id1, want);
    }

    #[test]
    fn prefix_relation() {
        let mut p = Principal::new();
        let a0 = AuthorityChain::genesis(p.genesis());
        p.rotate(T0);
        let a1 = AuthorityChain::from_rotations(p.genesis(), &p.rotations).unwrap();
        assert!(a0.is_prefix_of(&a1) && a1.is_prefix_of(&a1) && !a1.is_prefix_of(&a0));
    }
}