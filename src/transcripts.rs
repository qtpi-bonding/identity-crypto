//! Canonical transcripts: the exact bytes each signature in the identity
//! design covers (schema section 3; phase 1a spec section 5).

//! Encoding: a NUL-terminated ASCII tag, then fields in order. `var(x)` is a
//! u32 big-endian byte length then `x` (UTF-8 bytes for strings); `KEY` is
//! `scheme u8 ‖ var(key bytes)`; `PRINCIPAL` is `KEY(genesis)`; `opt(x)` is
//! `00`, or `01 ‖ x`; integers are big-endian at their natural width.
//! Every function validates while it encodes, so signer and verifier (which
//! call the same function) can never produce bytes for invalid input.

use crate::{pb, Error, PrincipalId, PublicKey, Result};

pub const KEY_CHALLENGE_TAG: &str = "identitycrypto.key-challenge.v1";
pub const PRINCIPAL_RENAME_TAG: &str = "identitycrypto.principal-rename.v1";
pub const KEY_DELEGATION_TAG: &str = "identitycrypto.key-delegation.v1";
pub const KEY_REVOCATION_TAG: &str = "identitycrypto.key-revocation.v1";
pub const ROOT_ROTATION_TAG: &str = "identitycrypto.root-rotation.v1";
pub const SESSION_DELEGATION_TAG: &str = "identitycrypto.session-delegation.v1";
pub const SIGNED_MESSAGE_TAG: &str = "identitycrypto.signed-message.v1";
pub const SIGNED_DOCUMENT_TAG: &str = "identitycrypto.signed-document.v1";
pub const APPROVAL_TAG: &str = "identitycrypto.approval.v1";
pub const PEER_REVOCATION_TAG: &str = "identitycrypto.peer-revocation.v1";
pub const DELIVERY_ATTESTATION_TAG: &str = "identitycrypto.delivery-attestation.v1";
pub const REQUEST_DIGEST_TAG: &str = "identitycrypto.request-digest.v1";

pub const ALL_TAGS: [&str; 12] = [
    KEY_CHALLENGE_TAG,
    PRINCIPAL_RENAME_TAG,
    KEY_DELEGATION_TAG,
    KEY_REVOCATION_TAG,
    ROOT_ROTATION_TAG,
    SESSION_DELEGATION_TAG,
    SIGNED_MESSAGE_TAG,
    SIGNED_DOCUMENT_TAG,
    APPROVAL_TAG,
    PEER_REVOCATION_TAG,
    DELIVERY_ATTESTATION_TAG,
    REQUEST_DIGEST_TAG,
];

struct Enc(Vec<u8>);

impl Enc {
    fn new(tag: &str) -> Self {
        let mut b = tag.as_bytes().to_vec();
        b.push(0);
        Self(b)
    }
    fn finish(self) -> Vec<u8> { self.0 }
    fn var(&mut self, x: &[u8]) -> Result<()> {
        let n = u32::try_from(x.len()).map_err(|_| Error::InvalidField { field: "length", reason: "exceeds u32" })?;
        self.0.extend_from_slice(&n.to_be_bytes());
        self.0.extend_from_slice(x);
        Ok(())
    }
    fn key(&mut self, k: &PublicKey) -> Result<()> {
        self.u8("scheme", k.scheme() as i64)?;
        self.var(k.as_bytes())
    }
    fn principal(&mut self, genesis: &PublicKey) -> Result<()> { self.key(genesis) }
    fn absent(&mut self) { self.0.push(0); }
    fn present(&mut self) { self.0.push(1); }
    fn opt_key(&mut self, k: Option<&PublicKey>) -> Result<()> {
        match k {
            Some(k) => { self.present(); self.key(k) }
            None => { self.absent(); Ok(()) }
        }
    }
    fn u8(&mut self, field: &'static str, v: i64) -> Result<()> {
        let b = u8::try_from(v).map_err(|_| Error::ScalarOutOfRange { field, value: v })?;
        self.0.push(b);
        Ok(())
    }
    fn i64(&mut self, v: i64) { self.0.extend_from_slice(&v.to_be_bytes()); }
    fn u64(&mut self, v: u64) { self.0.extend_from_slice(&v.to_be_bytes()); }
    fn i32(&mut self, v: i32) { self.0.extend_from_slice(&v.to_be_bytes()); }
    fn u32(&mut self, field: &'static str, n: usize) -> Result<()> {
        let n = u32::try_from(n).map_err(|_| Error::InvalidField { field, reason: "too many" })?;
        self.0.extend_from_slice(&n.to_be_bytes());
        Ok(())
    }
    fn fixed(&mut self, field: &'static str, x: &[u8], n: usize) -> Result<()> {
        if x.len() != n { return Err(Error::BadLength { field, expected: n, actual: x.len() }); }
        self.0.extend_from_slice(x);
        Ok(())
    }
}

fn non_empty(field: &'static str, x: &[u8]) -> Result<()> {
    if x.is_empty() { return Err(Error::InvalidField { field, reason: "empty" }); }
    Ok(())
}

/// A required key field: absent is `MissingField(field)`.
fn req(k: Option<&pb::PublicKey>, field: &'static str) -> Result<PublicKey> {
    PublicKey::try_from(k.ok_or(Error::MissingField(field))?)
}

fn opt_key(k: Option<&pb::PublicKey>) -> Result<Option<PublicKey>> {
    k.map(PublicKey::try_from).transpose()
}

/// `key-challenge.v1 := tag ‖ len(audience) ‖ len(nonce) ‖ KEY(new)`.
pub fn key_challenge_transcript(audience: &str, nonce: &[u8], new: &PublicKey) -> Result<Vec<u8>> {
    non_empty("audience", audience.as_bytes())?;
    non_empty("nonce", nonce)?;
    let mut e = Enc::new(KEY_CHALLENGE_TAG);
    e.var(audience.as_bytes())?;
    e.var(nonce)?;
    e.key(new)?;
    Ok(e.finish())
}

/// `principal-rename.v1 := tag ‖ len(nonce) ‖ PRINCIPAL ‖ len(new_name)`.
pub fn principal_rename_transcript(nonce: &[u8], principal: &PrincipalId, new_name: &str) -> Result<Vec<u8>> {
    non_empty("nonce", nonce)?;
    non_empty("new_name", new_name.as_bytes())?;
    let mut e = Enc::new(PRINCIPAL_RENAME_TAG);
    e.var(nonce)?;
    e.principal(principal.genesis())?;
    e.var(new_name.as_bytes())?;
    Ok(e.finish())
}

/// `key-delegation.v1 := tag ‖ PRINCIPAL ‖ KEY(signing_root) ‖ purpose u8 ‖ KEY(delegated)
/// ‖ opt(KEY(delegated_encryption)) ‖ issued_at ‖ not_after`.
pub fn key_delegation_transcript(d: &pb::KeyDelegation) -> Result<Vec<u8>> {
    let principal = req(d.principal_genesis.as_ref(), "principal_genesis")?;
    let root = req(d.signing_root.as_ref(), "signing_root")?;
    let purpose = match pb::KeyPurpose::try_from(d.purpose) {
        Ok(p @ (pb::KeyPurpose::Device | pb::KeyPurpose::Approval)) => p,
        _ => return Err(Error::InvalidField { field: "purpose", reason: "must be DEVICE or APPROVAL" }),
    };
    let delegated = req(d.delegated.as_ref(), "delegated")?;
    let encryption = match (purpose, d.delegated_encryption.as_ref()) {
        (pb::KeyPurpose::Device, None) => return Err(Error::MissingField("delegated_encryption")),
        (pb::KeyPurpose::Approval, Some(_)) => {
            return Err(Error::InvalidField { field: "delegated_encryption", reason: "forbidden for APPROVAL" })
        }
        (_, k) => opt_key(k)?,
    };
    let encryption_clash = match &encryption {
        Some(e) => e == &root || e == &delegated,
        None => false,
    };
    if root == delegated || encryption_clash {
        return Err(Error::NotDistinct("signing_root, delegated, delegated_encryption"));
    }
    let mut e = Enc::new(KEY_DELEGATION_TAG);
    e.principal(&principal)?;
    e.key(&root)?;
    e.u8("purpose", i64::from(d.purpose))?;
    e.key(&delegated)?;
    e.opt_key(encryption.as_ref())?;
    e.i64(d.issued_at_unix_seconds);
    e.i64(d.not_after_unix_seconds);
    Ok(e.finish())
}

/// `key-revocation.v1 := tag ‖ PRINCIPAL ‖ KEY(revoked) ‖ KEY(revoked_by) ‖ revoked_at`.
/// `revoked == revoked_by` (self-revocation) is legitimate.
pub fn key_revocation_transcript(r: &pb::KeyRevocation) -> Result<Vec<u8>> {
    let principal = req(r.principal_genesis.as_ref(), "principal_genesis")?;
    let revoked = req(r.revoked.as_ref(), "revoked")?;
    let revoked_by = req(r.revoked_by.as_ref(), "revoked_by")?;
    let mut e = Enc::new(KEY_REVOCATION_TAG);
    e.principal(&principal)?;
    e.key(&revoked)?;
    e.key(&revoked_by)?;
    e.i64(r.revoked_at_unix_seconds);
    Ok(e.finish())
}

/// `root-rotation.v1 := tag ‖ PRINCIPAL ‖ KEY(old_root) ‖ KEY(new_root) ‖ issued_at`.
pub fn root_rotation_transcript(r: &pb::RootRotation) -> Result<Vec<u8>> {
    let principal = req(r.principal_genesis.as_ref(), "principal_genesis")?;
    let old_root = req(r.old_root.as_ref(), "old_root")?;
    let new_root = req(r.new_root.as_ref(), "new_root")?;
    if old_root == new_root {
        return Err(Error::NotDistinct("old_root, new_root"));
    }
    let mut e = Enc::new(ROOT_ROTATION_TAG);
    e.principal(&principal)?;
    e.key(&old_root)?;
    e.key(&new_root)?;
    e.i64(r.issued_at_unix_seconds);
    Ok(e.finish())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwk_duo::SigningKeyPair;

    pub(crate) fn k() -> PublicKey {
        PublicKey::from(&SigningKeyPair::generate())
    }

    pub(crate) fn pk(key: &PublicKey) -> Option<pb::PublicKey> {
        Some(pb::PublicKey::from(key))
    }

    fn key_bytes(key: &PublicKey) -> Vec<u8> {
        let mut v = vec![3u8, 0, 0, 0, 65];
        v.extend_from_slice(key.as_bytes());
        v
    }

    #[test]
    fn tags_are_distinct_and_prefix_free() {
        for (i, a) in ALL_TAGS.iter().enumerate() {
            assert!(a.starts_with("identitycrypto.") && a.ends_with(".v1"), "{a}");
            for (j, b) in ALL_TAGS.iter().enumerate() {
                if i != j {
                    assert!(!b.starts_with(a), "{a} is a prefix of {b}");
                }
            }
        }
    }

    #[test]
    fn key_challenge_layout() {
        let new = k();
        let t = key_challenge_transcript("aud", &[7, 8], &new).unwrap();
        let mut want = b"identitycrypto.key-challenge.v1\0".to_vec();
        want.extend_from_slice(&[0, 0, 0, 3]);
        want.extend_from_slice(b"aud");
        want.extend_from_slice(&[0, 0, 0, 2, 7, 8]);
        want.extend_from_slice(&key_bytes(&new));
        assert_eq!(t, want);
    }

    #[test]
    fn lengths_count_utf8_bytes() {
        let t = key_challenge_transcript("ü", &[1], &k()).unwrap();
        let start = KEY_CHALLENGE_TAG.len() + 1;
        assert_eq!(&t[start..start + 6], &[0, 0, 0, 2, 0xc3, 0xbc]);
    }

    #[test]
    fn one_byte_scalars_reject_out_of_range() {
        let mut e = Enc::new("t");
        assert_eq!(e.u8("x", 256), Err(Error::ScalarOutOfRange { field: "x", value: 256 }));
        assert_eq!(e.u8("x", -1), Err(Error::ScalarOutOfRange { field: "x", value: -1 }));
        assert!(e.u8("x", 255).is_ok());
    }

    #[test]
    fn key_challenge_rejects_empty_audience_and_nonce() {
        let new = k();
        assert_eq!(
            key_challenge_transcript("", &[1], &new),
            Err(Error::InvalidField { field: "audience", reason: "empty" })
        );
        assert_eq!(
            key_challenge_transcript("a", &[], &new),
            Err(Error::InvalidField { field: "nonce", reason: "empty" })
        );
    }

    #[test]
    fn principal_rename_layout_and_checks() {
        let p = PrincipalId::from_genesis(k());
        let t = principal_rename_transcript(&[1], &p, "x").unwrap();
        let mut want = b"identitycrypto.principal-rename.v1\0".to_vec();
        want.extend_from_slice(&[0, 0, 0, 1, 1]);
        want.extend_from_slice(&key_bytes(p.genesis()));
        want.extend_from_slice(&[0, 0, 0, 1, b'x']);
        assert_eq!(t, want);
        assert_eq!(
            principal_rename_transcript(&[1], &p, ""),
            Err(Error::InvalidField { field: "new_name", reason: "empty" })
        );
        assert_eq!(
            principal_rename_transcript(&[], &p, "x"),
            Err(Error::InvalidField { field: "nonce", reason: "empty" })
        );
    }

    /// Genesis and current root differ (a rotated principal), so the field
    /// order of the two is pinned by the layout tests.
    pub(crate) fn delegation(purpose: pb::KeyPurpose) -> pb::KeyDelegation {
        pb::KeyDelegation {
            principal_genesis: pk(&k()),
            signing_root: pk(&k()),
            purpose: purpose as i32,
            delegated: pk(&k()),
            delegated_encryption: (purpose == pb::KeyPurpose::Device).then(|| pb::PublicKey::from(&k())),
            issued_at_unix_seconds: 1_700_000_000,
            not_after_unix_seconds: 1_702_592_000,
            signature: vec![],
        }
    }

    #[test]
    fn key_delegation_layout() {
        let d = delegation(pb::KeyPurpose::Device);
        let t = key_delegation_transcript(&d).unwrap();
        let key = |p: &Option<pb::PublicKey>| key_bytes(&PublicKey::try_from(p.as_ref().unwrap()).unwrap());
        let mut want = b"identitycrypto.key-delegation.v1\0".to_vec();
        want.extend(key(&d.principal_genesis));
        want.extend(key(&d.signing_root));
        want.push(2);
        want.extend(key(&d.delegated));
        want.push(1);
        want.extend(key(&d.delegated_encryption));
        want.extend(1_700_000_000i64.to_be_bytes());
        want.extend(1_702_592_000i64.to_be_bytes());
        assert_eq!(t, want);
        let a = delegation(pb::KeyPurpose::Approval);
        assert!(key_delegation_transcript(&a).is_ok());
    }

    #[test]
    fn key_delegation_checks() {
        let purpose = |p: i32| {
            let mut d = delegation(pb::KeyPurpose::Device);
            d.purpose = p;
            key_delegation_transcript(&d)
        };
        let bad_purpose = Err(Error::InvalidField { field: "purpose", reason: "must be DEVICE or APPROVAL" });
        for p in [0, 1, 4, 99] {
            assert_eq!(purpose(p), bad_purpose, "purpose {p}");
        }
        let mut d = delegation(pb::KeyPurpose::Device);
        d.delegated_encryption = None;
        assert_eq!(key_delegation_transcript(&d), Err(Error::MissingField("delegated_encryption")));
        let mut a = delegation(pb::KeyPurpose::Approval);
        a.delegated_encryption = pk(&k());
        assert_eq!(
            key_delegation_transcript(&a),
            Err(Error::InvalidField { field: "delegated_encryption", reason: "forbidden for APPROVAL" })
        );
        let not_distinct = Err(Error::NotDistinct("signing_root, delegated, delegated_encryption"));
        let mut d = delegation(pb::KeyPurpose::Device);
        d.delegated = d.signing_root.clone();
        assert_eq!(key_delegation_transcript(&d), not_distinct);
        let mut d = delegation(pb::KeyPurpose::Device);
        d.delegated_encryption = d.delegated.clone();
        assert_eq!(key_delegation_transcript(&d), not_distinct);
        let mut d = delegation(pb::KeyPurpose::Device);
        d.delegated_encryption = d.signing_root.clone();
        assert_eq!(key_delegation_transcript(&d), not_distinct);
        let mut d = delegation(pb::KeyPurpose::Device);
        d.principal_genesis = None;
        assert_eq!(key_delegation_transcript(&d), Err(Error::MissingField("principal_genesis")));
    }

    #[test]
    fn key_revocation_layout_and_self_revocation() {
        let (p, r, by) = (k(), k(), k());
        let rev = pb::KeyRevocation {
            principal_genesis: pk(&p), revoked: pk(&r), revoked_by: pk(&by),
            revoked_at_unix_seconds: -5, signature: vec![],
        };
        let t = key_revocation_transcript(&rev).unwrap();
        let mut want = b"identitycrypto.key-revocation.v1\0".to_vec();
        want.extend(key_bytes(&p));
        want.extend(key_bytes(&r));
        want.extend(key_bytes(&by));
        want.extend((-5i64).to_be_bytes());
        assert_eq!(t, want);
        let own = pb::KeyRevocation { revoked_by: pk(&r), ..rev.clone() };
        assert!(key_revocation_transcript(&own).is_ok());
        let missing = pb::KeyRevocation { revoked_by: None, ..rev };
        assert_eq!(key_revocation_transcript(&missing), Err(Error::MissingField("revoked_by")));
    }

    #[test]
    fn root_rotation_layout_and_distinctness() {
        let (p, old, new) = (k(), k(), k());
        let rot = pb::RootRotation {
            principal_genesis: pk(&p), old_root: pk(&old), new_root: pk(&new),
            issued_at_unix_seconds: 9, signature: vec![],
        };
        let mut want = b"identitycrypto.root-rotation.v1\0".to_vec();
        want.extend(key_bytes(&p));
        want.extend(key_bytes(&old));
        want.extend(key_bytes(&new));
        want.extend(9i64.to_be_bytes());
        assert_eq!(root_rotation_transcript(&rot).unwrap(), want);
        let same = pb::RootRotation { new_root: pk(&old), ..rot };
        assert_eq!(root_rotation_transcript(&same), Err(Error::NotDistinct("old_root, new_root")));
    }
}
