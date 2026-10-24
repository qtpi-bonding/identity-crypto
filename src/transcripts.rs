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

pub const CLIENT_REQUEST_DIGEST_TAG: &str = "identitycrypto.client-request-digest.v1";

pub const ALL_TAGS: [&str; 13] = [
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
    CLIENT_REQUEST_DIGEST_TAG,
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

/// `session-delegation.v1 := tag ‖ mode u8 ‖ PRINCIPAL ‖ opt(PRINCIPAL host) ‖ opt(len(subject))
/// ‖ KEY(device) ‖ KEY(session) ‖ not_before ‖ not_after`.
pub fn session_delegation_transcript(c: &pb::DelegationCert) -> Result<Vec<u8>> {
    let mut e = Enc::new(SESSION_DELEGATION_TAG);
    encode_cert_body(&mut e, c)?;
    Ok(e.finish())
}

fn encode_cert_body(e: &mut Enc, c: &pb::DelegationCert) -> Result<()> {
    if c.mode > 1 { return Err(Error::InvalidField { field: "mode", reason: "must be 0 or 1" }); }
    let principal = req(c.principal_genesis.as_ref(), "principal_genesis")?;
    let (host, subject) = if c.mode == 0 {
        if c.host_genesis.is_some() { return Err(Error::InvalidField { field: "host_genesis", reason: "forbidden in mode 0" }); }
        if c.subject.is_some() { return Err(Error::InvalidField { field: "subject", reason: "forbidden in mode 0" }); }
        (None, None)
    } else {
        let host = req(c.host_genesis.as_ref(), "host_genesis")?;
        let subject = c.subject.as_deref().ok_or(Error::MissingField("subject"))?;
        non_empty("subject", subject.as_bytes())?;
        (Some(host), Some(subject))
    };
    let device = req(c.device.as_ref(), "device")?;
    let session = req(c.session.as_ref(), "session")?;
    if device == session { return Err(Error::NotDistinct("device, session")); }
    e.u8("mode", i64::from(c.mode))?;
    e.principal(&principal)?;
    match &host { Some(h) => { e.present(); e.principal(h)?; }, None => e.absent() }
    match subject { Some(s) => { e.present(); e.var(s.as_bytes())?; }, None => e.absent() }
    e.key(&device)?; e.key(&session)?;
    e.i64(c.not_before_unix_seconds); e.i64(c.not_after_unix_seconds);
    Ok(())
}

pub fn signed_message_transcript(m: &pb::SignedMessage) -> Result<Vec<u8>> {
    use pb::signer_chain::Chain;
    let chain = m.signer.as_ref().ok_or(Error::MissingField("signer"))?.chain.as_ref().ok_or(Error::MissingField("signer.chain"))?;
    let (cert, paths) = match chain {
        Chain::SelfRooted(s) => (s.session.as_ref(), ["signer.self_rooted.session", "signer.self_rooted.session.principal_genesis", "signer.self_rooted.session.session"]),
        Chain::HostVouched(h) => (h.session.as_ref(), ["signer.host_vouched.session", "signer.host_vouched.session.principal_genesis", "signer.host_vouched.session.session"]),
    };
    let cert = cert.ok_or(Error::MissingField(paths[0]))?;
    let principal = req(cert.principal_genesis.as_ref(), paths[1])?;
    let session = req(cert.session.as_ref(), paths[2])?;
    non_empty("audience", m.audience.as_bytes())?;
    non_empty("body_type", m.body_type.as_bytes())?;
    let mut e = Enc::new(SIGNED_MESSAGE_TAG);
    e.principal(&principal)?; e.key(&session)?; e.var(m.audience.as_bytes())?;
    e.fixed("nonce", &m.nonce, 16)?; e.i64(m.issued_at_unix_seconds);
    match &m.in_reply_to_nonce { Some(n) => { e.present(); e.fixed("in_reply_to_nonce", n, 16)?; }, None => e.absent() }
    e.var(m.body_type.as_bytes())?; e.var(&m.body)?;
    Ok(e.finish())
}

pub fn signed_document_transcript(d: &pb::SignedDocument) -> Result<Vec<u8>> {
    let signer = req(d.signer_genesis.as_ref(), "signer_genesis")?;
    let signing = req(d.signing.as_ref(), "signing")?;
    non_empty("document_type", d.document_type.as_bytes())?;
    let mut e = Enc::new(SIGNED_DOCUMENT_TAG);
    e.principal(&signer)?; e.key(&signing)?; e.var(d.document_type.as_bytes())?;
    e.u64(d.version); e.i64(d.issued_at_unix_seconds); e.i64(d.expires_at_unix_seconds); e.var(&d.body)?;
    Ok(e.finish())
}

/// `approval.v1 := tag ‖ PRINCIPAL ‖ KEY(approval) ‖ KEY(device) ‖ len(audience)
/// ‖ len(request_id) ‖ request_digest[32] ‖ accept u8 ‖ issued_at`.
pub fn approval_transcript(a: &pb::Approval) -> Result<Vec<u8>> {
    let principal = req(a.principal_genesis.as_ref(), "principal_genesis")?;
    let approval_key = req(a.approval_key.as_ref(), "approval_key")?;
    let device = req(a.device.as_ref(), "device")?;
    if approval_key == device { return Err(Error::NotDistinct("approval_key, device")); }
    non_empty("audience", a.audience.as_bytes())?;
    let mut e = Enc::new(APPROVAL_TAG);
    e.principal(&principal)?; e.key(&approval_key)?; e.key(&device)?;
    e.var(a.audience.as_bytes())?; e.var(a.request_id.as_bytes())?;
    e.fixed("request_digest", &a.request_digest, 32)?;
    e.u8("accept", i64::from(a.accept))?; e.i64(a.issued_at_unix_seconds);
    Ok(e.finish())
}

/// `peer-revocation.v1 := tag ‖ PRINCIPAL(revoker) ‖ KEY(approval) ‖ PRINCIPAL(target)
/// ‖ opt(KEY(revoked)) ‖ issued_at ‖ document_id[32]`.
pub fn peer_revocation_transcript(p: &pb::PeerRevocation) -> Result<Vec<u8>> {
    let revoker = req(p.revoker_genesis.as_ref(), "revoker_genesis")?;
    let approval_key = req(p.approval_key.as_ref(), "approval_key")?;
    let target = req(p.target_genesis.as_ref(), "target_genesis")?;
    let revoked = opt_key(p.revoked.as_ref())?;
    let mut e = Enc::new(PEER_REVOCATION_TAG);
    e.principal(&revoker)?; e.key(&approval_key)?; e.principal(&target)?;
    e.opt_key(revoked.as_ref())?; e.i64(p.issued_at_unix_seconds);
    e.fixed("document_id", &p.document_id, 32)?;
    Ok(e.finish())
}

/// ```text
/// delivery-attestation.v1 := tag ‖ u32 count ‖ KEY(recipient_device)…
///                            ‖ len(key_id) ‖ batch_sequence u64
///                            ‖ attested_at.seconds i64 ‖ attested_at.nanos i32
///                            ‖ u32 count ‖ MESSAGE…
/// MESSAGE := len(message_id) ‖ len(room_id) ‖ KEY(author)
///            ‖ len(body_text) ‖ CERT
/// CERT    := the cert's session-delegation.v1 bytes without the tag, then len(signature)
/// ```
pub fn delivery_attestation_transcript(a: &pb::DeliveryAttestation) -> Result<Vec<u8>> {
    let mut e = Enc::new(DELIVERY_ATTESTATION_TAG);
    e.u32("recipient_devices", a.recipient_devices.len())?;
    for r in &a.recipient_devices {
        e.key(&PublicKey::try_from(r)?)?;
    }
    e.var(a.key_id.as_bytes())?;
    e.u64(a.batch_sequence);
    let at = a.attested_at.as_ref().ok_or(Error::MissingField("attested_at"))?;
    if !(0..=999_999_999).contains(&at.nanos) {
        return Err(Error::InvalidField { field: "attested_at.nanos", reason: "out of range" });
    }
    e.i64(at.seconds);
    e.i32(at.nanos);
    e.u32("messages", a.messages.len())?;
    for m in &a.messages {
        e.var(m.message_id.as_bytes())?;
        e.var(m.room_id.as_bytes())?;
        let author = req(m.author_genesis.as_ref(), "messages.author_genesis")?;
        let cert = m.delegation_cert.as_ref().ok_or(Error::MissingField("messages.delegation_cert"))?;
        e.key(&author)?;
        e.var(m.body_text.as_bytes())?;
        encode_cert_body(&mut e, cert)?;
        e.var(&cert.signature)?;
    }
    Ok(e.finish())
}

/// What an `Approval` covers (schema 5.2).
#[derive(Clone, Copy)]
pub struct RequestDigestInput<'a> {
    pub requester: &'a PrincipalId,
    pub host: &'a PrincipalId,
    pub subject: Option<&'a str>,
    pub instance_id: &'a str,
    pub action_id: &'a str,
    pub parameters: &'a [u8],
    pub request_id: &'a str,
    pub target: &'a PrincipalId,
}

/// `request-digest.v1 := tag ‖ PRINCIPAL(requester) ‖ PRINCIPAL(host) ‖ opt(len(subject))
/// ‖ len(instance_id) ‖ len(action_id) ‖ len(parameters) ‖ len(request_id) ‖ PRINCIPAL(target)`.
pub fn request_digest_transcript(i: &RequestDigestInput<'_>) -> Result<Vec<u8>> {
    if let Some(subject) = i.subject { non_empty("subject", subject.as_bytes())?; }
    non_empty("instance_id", i.instance_id.as_bytes())?;
    non_empty("action_id", i.action_id.as_bytes())?;
    non_empty("request_id", i.request_id.as_bytes())?;
    let mut e = Enc::new(REQUEST_DIGEST_TAG);
    e.principal(i.requester.genesis())?; e.principal(i.host.genesis())?;
    match i.subject {
        Some(s) => { e.present(); e.var(s.as_bytes())?; }
        None => e.absent(),
    }
    e.var(i.instance_id.as_bytes())?; e.var(i.action_id.as_bytes())?;
    e.var(i.parameters)?; e.var(i.request_id.as_bytes())?;
    e.principal(i.target.genesis())?;
    Ok(e.finish())
}

/// `Approval.request_digest`: SHA-256 of `request_digest_transcript`.
pub fn request_digest(i: &RequestDigestInput<'_>) -> Result<[u8; 32]> {
    use sha2::{Digest, Sha256};
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(request_digest_transcript(i)?));
    Ok(out)
}

/// What an `Approval` covers for a requester with no host daemon or instance.
///
/// For requesters that connect with a self-rooted chain (a structmux client
/// session; mode 0 forbids a subject). A requester that can carry a subject (a
/// host-vouched agent) uses `request_digest`. An absent `host` covers both
/// `Host::Hostless` and `Host::Unhosted`; that is sound because the requester
/// principal already fixes its kind. An absent `resource` means the request
/// names no resource.
#[derive(Clone, Copy)]
pub struct ClientRequestDigestInput<'a> {
    pub requester: &'a PrincipalId,
    pub host: Option<&'a PrincipalId>,
    pub resource: Option<(&'a str, &'a str)>,
    pub message_kind: &'a str,
    pub body: &'a [u8],
    pub request_id: &'a str,
    pub target: &'a PrincipalId,
}

/// `client-request-digest.v1 := tag ‖ PRINCIPAL(requester) ‖ opt(PRINCIPAL(host))
/// ‖ opt(len(resource_kind) ‖ len(resource_id)) ‖ len(message_kind) ‖ len(body)
/// ‖ len(request_id) ‖ PRINCIPAL(target)`.
pub fn client_request_digest_transcript(i: &ClientRequestDigestInput<'_>) -> Result<Vec<u8>> {
    if let Some((kind, id)) = i.resource {
        non_empty("resource_kind", kind.as_bytes())?;
        non_empty("resource_id", id.as_bytes())?;
    }
    non_empty("message_kind", i.message_kind.as_bytes())?;
    non_empty("request_id", i.request_id.as_bytes())?;
    let mut e = Enc::new(CLIENT_REQUEST_DIGEST_TAG);
    e.principal(i.requester.genesis())?;
    match i.host {
        Some(h) => { e.present(); e.principal(h.genesis())?; }
        None => e.absent(),
    }
    match i.resource {
        Some((kind, id)) => { e.present(); e.var(kind.as_bytes())?; e.var(id.as_bytes())?; }
        None => e.absent(),
    }
    e.var(i.message_kind.as_bytes())?;
    e.var(i.body)?;
    e.var(i.request_id.as_bytes())?;
    e.principal(i.target.genesis())?;
    Ok(e.finish())
}

/// `Approval.request_digest` for a client request: SHA-256 of `client_request_digest_transcript`.
pub fn client_request_digest(i: &ClientRequestDigestInput<'_>) -> Result<[u8; 32]> {
    use sha2::{Digest, Sha256};
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(client_request_digest_transcript(i)?));
    Ok(out)
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

    pub(crate) fn cert0() -> pb::DelegationCert {
        let device = k();
        pb::DelegationCert {
            principal_genesis: pk(&device), mode: 0, device: pk(&device), session: pk(&k()),
            host_genesis: None, subject: None, not_before_unix_seconds: 1,
            not_after_unix_seconds: 2, signature: vec![0xab; 64],
        }
    }

    pub(crate) fn cert1() -> pb::DelegationCert {
        pb::DelegationCert {
            principal_genesis: pk(&k()), mode: 1, host_genesis: pk(&k()),
            subject: Some("3b6a27bcceb6a42d/i5".into()), ..cert0()
        }
    }

    fn attested() -> pb::AttestedMessage {
        pb::AttestedMessage {
            message_id: "m".into(),
            room_id: "r".into(),
            body_text: "hi".into(),
            delegation_cert: Some(cert1()),
            author_genesis: Some(pb::PublicKey::from(&k())),
        }
    }

    pub(crate) fn attestation() -> pb::DeliveryAttestation {
        pb::DeliveryAttestation {
            recipient_devices: vec![pb::PublicKey::from(&k()), pb::PublicKey::from(&k())],
            key_id: "kid".into(),
            batch_sequence: 9,
            attested_at: Some(crate::Timestamp { seconds: 100, nanos: 5 }),
            messages: vec![attested(), attested()],
            signature: vec![],
        }
    }

    #[test]
    fn delivery_attestation_empty_layout() {
        let a = pb::DeliveryAttestation {
            recipient_devices: vec![], key_id: String::new(), batch_sequence: 0,
            attested_at: Some(crate::Timestamp { seconds: 0, nanos: 0 }),
            messages: vec![], signature: vec![],
        };
        let mut want = b"identitycrypto.delivery-attestation.v1\0".to_vec();
        want.extend([0, 0, 0, 0]);
        want.extend([0, 0, 0, 0]);
        want.extend(0u64.to_be_bytes());
        want.extend(0i64.to_be_bytes());
        want.extend(0i32.to_be_bytes());
        want.extend([0, 0, 0, 0]);
        assert_eq!(delivery_attestation_transcript(&a).unwrap(), want);
    }

    #[test]
    fn delivery_attestation_message_layout() {
        let mut a = attestation();
        a.recipient_devices.clear();
        a.messages = vec![attested()];
        let m = &a.messages[0];
        let cert = m.delegation_cert.clone().unwrap();
        let t = delivery_attestation_transcript(&a).unwrap();
        let mut tail = vec![0, 0, 0, 1, b'm', 0, 0, 0, 1, b'r'];
        tail.extend(key_bytes(&PublicKey::try_from(m.author_genesis.as_ref().unwrap()).unwrap()));
        tail.extend([0, 0, 0, 2, b'h', b'i']);
        let cert_bytes = session_delegation_transcript(&cert).unwrap();
        tail.extend(&cert_bytes[SESSION_DELEGATION_TAG.len() + 1..]);
        tail.extend([0, 0, 0, 64]);
        tail.extend([0xab; 64]);
        assert!(t.ends_with(&tail));
    }

    #[test]
    fn delivery_attestation_checks() {
        let with = |f: &dyn Fn(&mut pb::DeliveryAttestation)| {
            let mut a = attestation();
            f(&mut a);
            delivery_attestation_transcript(&a)
        };
        assert!(with(&|_| {}).is_ok());
        assert_eq!(with(&|a| a.attested_at = None), Err(Error::MissingField("attested_at")));
        let bad_nanos = Err(Error::InvalidField { field: "attested_at.nanos", reason: "out of range" });
        assert_eq!(with(&|a| a.attested_at.as_mut().unwrap().nanos = 1_000_000_000), bad_nanos);
        assert_eq!(with(&|a| a.attested_at.as_mut().unwrap().nanos = -1), bad_nanos);
    }

    #[test]
    fn message_without_author_genesis_is_rejected() {
        let mut a = attestation();
        a.messages[1].author_genesis = None;
        assert_eq!(
            delivery_attestation_transcript(&a),
            Err(Error::MissingField("messages.author_genesis"))
        );
    }

    #[test]
    fn message_without_delegation_cert_is_rejected() {
        let mut a = attestation();
        a.messages[1].delegation_cert = None;
        assert_eq!(
            delivery_attestation_transcript(&a),
            Err(Error::MissingField("messages.delegation_cert"))
        );
    }

    #[test]
    fn message_missing_both_reports_author_first() {
        let mut a = attestation();
        a.messages[0].author_genesis = None;
        a.messages[0].delegation_cert = None;
        assert_eq!(
            delivery_attestation_transcript(&a),
            Err(Error::MissingField("messages.author_genesis"))
        );
    }

    #[test]
    fn delivery_attestation_rejects_foreign_schemes_deep_inside() {
        let mut a = attestation();
        let cert = a.messages[1].delegation_cert.as_mut().unwrap();
        cert.session.as_mut().unwrap().scheme = 1; // formerly ED25519, now reserved
        assert_eq!(
            delivery_attestation_transcript(&a),
            Err(Error::UnsupportedScheme(1))
        );
        let mut a = attestation();
        a.recipient_devices[1].key = vec![4; 65];
        assert!(matches!(delivery_attestation_transcript(&a), Err(Error::InvalidKey(_))));
    }

    pub(crate) fn message() -> pb::SignedMessage {
        pb::SignedMessage {
            signer: Some(pb::SignerChain { chain: Some(pb::signer_chain::Chain::SelfRooted(pb::SelfRooted {
                device: Some(delegation(pb::KeyPurpose::Device)), session: Some(cert0()),
            }))}), audience: "structmux-fleet:3b6a27bcceb6a42d".into(), nonce: vec![5; 16],
            issued_at_unix_seconds: 7, in_reply_to_nonce: None,
            body_type: "type.googleapis.com/structmux.v1.FleetRequest".into(), body: vec![1,2,3], signature: vec![],
        }
    }

    #[test]
    fn session_delegation_layouts() {
        let c = cert0();
        let key = |p: &Option<pb::PublicKey>| key_bytes(&PublicKey::try_from(p.as_ref().unwrap()).unwrap());
        let mut want = b"identitycrypto.session-delegation.v1\0".to_vec(); want.push(0);
        want.extend(key(&c.principal_genesis)); want.extend([0,0]); want.extend(key(&c.device)); want.extend(key(&c.session));
        want.extend(1i64.to_be_bytes()); want.extend(2i64.to_be_bytes());
        assert_eq!(session_delegation_transcript(&c).unwrap(), want);
        let c = cert1(); let mut want = b"identitycrypto.session-delegation.v1\0".to_vec(); want.push(1);
        want.extend(key(&c.principal_genesis)); want.push(1); want.extend(key(&c.host_genesis)); want.push(1);
        want.extend([0,0,0,19]); want.extend(b"3b6a27bcceb6a42d/i5"); want.extend(key(&c.device)); want.extend(key(&c.session));
        want.extend(1i64.to_be_bytes()); want.extend(2i64.to_be_bytes());
        assert_eq!(session_delegation_transcript(&c).unwrap(), want);
    }

    #[test]
    fn session_delegation_checks() {
        let run = |f: &dyn Fn(&mut pb::DelegationCert), base: fn() -> pb::DelegationCert| { let mut c=base(); f(&mut c); session_delegation_transcript(&c) };
        assert_eq!(run(&|c| c.mode=2, cert0), Err(Error::InvalidField{field:"mode",reason:"must be 0 or 1"}));
        assert_eq!(run(&|c| c.host_genesis=pk(&k()), cert0), Err(Error::InvalidField{field:"host_genesis",reason:"forbidden in mode 0"}));
        assert_eq!(run(&|c| c.subject=Some(String::new()), cert0), Err(Error::InvalidField{field:"subject",reason:"forbidden in mode 0"}));
        assert_eq!(run(&|c| c.host_genesis=None, cert1), Err(Error::MissingField("host_genesis")));
        assert_eq!(run(&|c| c.subject=None, cert1), Err(Error::MissingField("subject")));
        assert_eq!(run(&|c| c.subject=Some(String::new()), cert1), Err(Error::InvalidField{field:"subject",reason:"empty"}));
        assert_eq!(run(&|c| c.session=c.device.clone(), cert0), Err(Error::NotDistinct("device, session")));
        assert_eq!(run(&|c| c.session=c.device.clone(), cert1), Err(Error::NotDistinct("device, session")));
        assert_eq!(run(&|c| c.device=None, cert0), Err(Error::MissingField("device")));
    }

    #[test]
    fn signed_message_layout() {
        let mut m=message(); m.in_reply_to_nonce=Some(vec![6;16]); let cert=cert0();
        if let Some(pb::signer_chain::Chain::SelfRooted(s))=m.signer.as_mut().and_then(|s|s.chain.as_mut()) { s.session=Some(cert.clone()); }
        let key=|p:&Option<pb::PublicKey>|key_bytes(&PublicKey::try_from(p.as_ref().unwrap()).unwrap());
        let mut want=b"identitycrypto.signed-message.v1\0".to_vec(); want.extend(key(&cert.principal_genesis)); want.extend(key(&cert.session));
        want.extend((m.audience.len() as u32).to_be_bytes()); want.extend(m.audience.as_bytes()); want.extend([5;16]); want.extend(7i64.to_be_bytes());
        want.push(1); want.extend([6;16]); want.extend((m.body_type.len() as u32).to_be_bytes()); want.extend(m.body_type.as_bytes()); want.extend([0,0,0,3,1,2,3]);
        assert_eq!(signed_message_transcript(&m).unwrap(),want);
    }

    #[test]
    fn signed_message_checks() {
        let mut m=message(); m.signer=None; assert_eq!(signed_message_transcript(&m),Err(Error::MissingField("signer")));
        let mut m=message(); m.signer=Some(pb::SignerChain{chain:None}); assert_eq!(signed_message_transcript(&m),Err(Error::MissingField("signer.chain")));
        let mut m=message(); m.signer=Some(pb::SignerChain{chain:Some(pb::signer_chain::Chain::HostVouched(pb::HostVouched{host_device:None,session:None}))}); assert_eq!(signed_message_transcript(&m),Err(Error::MissingField("signer.host_vouched.session")));
        let mut m=message(); m.signer=Some(pb::SignerChain{chain:Some(pb::signer_chain::Chain::HostVouched(pb::HostVouched{host_device:None,session:Some(cert1())}))}); assert!(signed_message_transcript(&m).is_ok());
        let mut m=message(); m.nonce=vec![5;15]; assert_eq!(signed_message_transcript(&m),Err(Error::BadLength{field:"nonce",expected:16,actual:15}));
        let mut m=message(); m.in_reply_to_nonce=Some(vec![]); assert_eq!(signed_message_transcript(&m),Err(Error::BadLength{field:"in_reply_to_nonce",expected:16,actual:0}));
        let mut m=message(); m.audience.clear(); assert_eq!(signed_message_transcript(&m),Err(Error::InvalidField{field:"audience",reason:"empty"}));
        let mut m=message(); m.body_type.clear(); assert_eq!(signed_message_transcript(&m),Err(Error::InvalidField{field:"body_type",reason:"empty"}));
    }

    #[test]
    fn signed_document_layout_and_checks() {
        let (g,s)=(k(),k()); let d=pb::SignedDocument{signer_genesis:pk(&g),signing:pk(&s),document_type:"t".into(),version:u64::MAX,issued_at_unix_seconds:1,expires_at_unix_seconds:0,body:vec![9],signature:vec![],signer_rotations:vec![]};
        let mut want=b"identitycrypto.signed-document.v1\0".to_vec(); want.extend(key_bytes(&g)); want.extend(key_bytes(&s)); want.extend([0,0,0,1,b't']); want.extend(u64::MAX.to_be_bytes()); want.extend(1i64.to_be_bytes()); want.extend(0i64.to_be_bytes()); want.extend([0,0,0,1,9]);
        assert_eq!(signed_document_transcript(&d).unwrap(),want);
        let empty=pb::SignedDocument{document_type:String::new(),..d}; assert_eq!(signed_document_transcript(&empty),Err(Error::InvalidField{field:"document_type",reason:"empty"}));
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

    pub(crate) fn approval() -> pb::Approval {
        pb::Approval {
            principal_genesis: pk(&k()), approval_key: pk(&k()), device: pk(&k()),
            audience: "structmux:3b6a27bcceb6a42d".into(), request_id: "r4".into(),
            request_digest: vec![0x11; 32], accept: true, issued_at_unix_seconds: 3, signature: vec![],
        }
    }

    pub(crate) fn peer_revocation() -> pb::PeerRevocation {
        pb::PeerRevocation {
            revoker_genesis: pk(&k()), approval_key: pk(&k()), target_genesis: pk(&k()),
            revoked: None, issued_at_unix_seconds: 4, signature: vec![], document_id: vec![0x22; 32],
        }
    }

    #[test]
    fn approval_layout_and_checks() {
        let a = approval();
        let key = |p: &Option<pb::PublicKey>| key_bytes(&PublicKey::try_from(p.as_ref().unwrap()).unwrap());
        let mut want = b"identitycrypto.approval.v1\0".to_vec();
        want.extend(key(&a.principal_genesis)); want.extend(key(&a.approval_key)); want.extend(key(&a.device));
        want.extend((a.audience.len() as u32).to_be_bytes()); want.extend(a.audience.as_bytes());
        want.extend([0, 0, 0, 2, b'r', b'4']); want.extend([0x11; 32]); want.push(1); want.extend(3i64.to_be_bytes());
        assert_eq!(approval_transcript(&a).unwrap(), want);
        let rejected = pb::Approval { accept: false, ..approval() };
        assert_eq!(approval_transcript(&rejected).unwrap()[want.len() - 9], 0);
        let short = pb::Approval { request_digest: vec![0; 31], ..approval() };
        assert_eq!(approval_transcript(&short), Err(Error::BadLength { field: "request_digest", expected: 32, actual: 31 }));
        let a = approval(); let same = pb::Approval { device: a.approval_key.clone(), ..a };
        assert_eq!(approval_transcript(&same), Err(Error::NotDistinct("approval_key, device")));
        let empty = pb::Approval { audience: String::new(), ..approval() };
        assert_eq!(approval_transcript(&empty), Err(Error::InvalidField { field: "audience", reason: "empty" }));
    }

    #[test]
    fn peer_revocation_layout_and_checks() {
        let p = peer_revocation();
        let key = |p: &Option<pb::PublicKey>| key_bytes(&PublicKey::try_from(p.as_ref().unwrap()).unwrap());
        let mut want = b"identitycrypto.peer-revocation.v1\0".to_vec();
        want.extend(key(&p.revoker_genesis)); want.extend(key(&p.approval_key)); want.extend(key(&p.target_genesis));
        want.push(0); want.extend(4i64.to_be_bytes()); want.extend([0x22; 32]);
        assert_eq!(peer_revocation_transcript(&p).unwrap(), want);
        let one_key = pb::PeerRevocation { revoked: pk(&k()), ..peer_revocation() };
        let t = peer_revocation_transcript(&one_key).unwrap(); assert_eq!(t.len(), want.len() + 70);
        let missing = pb::PeerRevocation { target_genesis: None, ..peer_revocation() };
        assert_eq!(peer_revocation_transcript(&missing), Err(Error::MissingField("target_genesis")));
        let short = pb::PeerRevocation { document_id: vec![0x22; 31], ..peer_revocation() };
        assert_eq!(peer_revocation_transcript(&short), Err(Error::BadLength { field: "document_id", expected: 32, actual: 31 }));
    }

    #[test]
    fn request_digest_layout() {
        let (r, h, t) = (PrincipalId::from_genesis(k()), PrincipalId::from_genesis(k()), PrincipalId::from_genesis(k()));
        let input = RequestDigestInput { requester: &r, host: &h, subject: Some("s/i1"), instance_id: "s/i1", action_id: "run", parameters: &[9, 9], request_id: "r4", target: &t };
        let mut want = b"identitycrypto.request-digest.v1\0".to_vec();
        want.extend(key_bytes(r.genesis())); want.extend(key_bytes(h.genesis())); want.extend([1, 0, 0, 0, 4]); want.extend(b"s/i1");
        want.extend([0, 0, 0, 4]); want.extend(b"s/i1"); want.extend([0, 0, 0, 3]); want.extend(b"run");
        want.extend([0, 0, 0, 2, 9, 9]); want.extend([0, 0, 0, 2, b'r', b'4']); want.extend(key_bytes(t.genesis()));
        assert_eq!(request_digest_transcript(&input).unwrap(), want);
        use sha2::{Digest, Sha256}; assert_eq!(request_digest(&input).unwrap().as_slice(), Sha256::digest(&want).as_slice());
        let no_subject = RequestDigestInput { subject: None, parameters: &[], ..input };
        assert_eq!(request_digest_transcript(&no_subject).unwrap()[KEY_BYTES_OFFSET_AFTER_TWO_PRINCIPALS], 0);
    }

    const KEY_BYTES_OFFSET_AFTER_TWO_PRINCIPALS: usize = REQUEST_DIGEST_TAG.len() + 1 + 70 + 70;

    #[test]
    fn request_digest_checks() {
        let (r, h, t) = (PrincipalId::from_genesis(k()), PrincipalId::from_genesis(k()), PrincipalId::from_genesis(k()));
        let base = RequestDigestInput { requester: &r, host: &h, subject: None, instance_id: "s/i1", action_id: "run", parameters: &[], request_id: "r4", target: &t };
        let empty = |field: &'static str| -> Result<Vec<u8>> { Err(Error::InvalidField { field, reason: "empty" }) };
        assert_eq!(request_digest_transcript(&RequestDigestInput { subject: Some(""), ..base }), empty("subject"));
        assert_eq!(request_digest_transcript(&RequestDigestInput { instance_id: "", ..base }), empty("instance_id"));
        assert_eq!(request_digest_transcript(&RequestDigestInput { action_id: "", ..base }), empty("action_id"));
        assert_eq!(request_digest_transcript(&RequestDigestInput { request_id: "", ..base }), empty("request_id"));
        assert!(request_digest_transcript(&base).is_ok(), "empty parameters are allowed");
    }

    #[test]
    fn client_request_digest_layout() {
        use sha2::{Digest, Sha256};
        let (r, h, t) = (PrincipalId::from_genesis(k()), PrincipalId::from_genesis(k()), PrincipalId::from_genesis(k()));
        let bare = ClientRequestDigestInput { requester: &r, host: None, resource: None, message_kind: "edit_arrangement", body: &[9, 9], request_id: "r4", target: &t };
        let mut want = b"identitycrypto.client-request-digest.v1\0".to_vec();
        want.extend(key_bytes(r.genesis())); want.push(0); want.push(0);
        want.extend([0, 0, 0, 16]); want.extend(b"edit_arrangement");
        want.extend([0, 0, 0, 2, 9, 9]); want.extend([0, 0, 0, 2, b'r', b'4']); want.extend(key_bytes(t.genesis()));
        assert_eq!(client_request_digest_transcript(&bare).unwrap(), want);
        assert_eq!(client_request_digest(&bare).unwrap().as_slice(), Sha256::digest(&want).as_slice());

        let full = ClientRequestDigestInput { host: Some(&h), resource: Some(("instance", "i1")), ..bare };
        let mut want = b"identitycrypto.client-request-digest.v1\0".to_vec();
        want.extend(key_bytes(r.genesis()));
        want.push(1); want.extend(key_bytes(h.genesis()));
        want.push(1); want.extend([0, 0, 0, 8]); want.extend(b"instance"); want.extend([0, 0, 0, 2]); want.extend(b"i1");
        want.extend([0, 0, 0, 16]); want.extend(b"edit_arrangement");
        want.extend([0, 0, 0, 2, 9, 9]); want.extend([0, 0, 0, 2, b'r', b'4']); want.extend(key_bytes(t.genesis()));
        assert_eq!(client_request_digest_transcript(&full).unwrap(), want);
        assert_eq!(client_request_digest(&full).unwrap().as_slice(), Sha256::digest(&want).as_slice());
    }

    #[test]
    fn client_request_digest_rejects_empty_fields() {
        let (r, t) = (PrincipalId::from_genesis(k()), PrincipalId::from_genesis(k()));
        let base = ClientRequestDigestInput { requester: &r, host: None, resource: Some(("instance", "i1")), message_kind: "start_instance", body: &[], request_id: "r4", target: &t };
        let empty = |field: &'static str| -> Result<Vec<u8>> { Err(Error::InvalidField { field, reason: "empty" }) };
        let tr = |i: ClientRequestDigestInput<'_>| client_request_digest_transcript(&i);
        assert_eq!(tr(ClientRequestDigestInput { resource: Some(("", "i1")), ..base }), empty("resource_kind"));
        assert_eq!(tr(ClientRequestDigestInput { resource: Some(("instance", "")), ..base }), empty("resource_id"));
        assert_eq!(tr(ClientRequestDigestInput { message_kind: "", ..base }), empty("message_kind"));
        assert_eq!(tr(ClientRequestDigestInput { request_id: "", ..base }), empty("request_id"));
        // Order when several are empty: resource_kind, resource_id, message_kind, request_id.
        assert_eq!(tr(ClientRequestDigestInput { resource: Some(("", "")), message_kind: "", request_id: "", ..base }), empty("resource_kind"));
        assert_eq!(tr(ClientRequestDigestInput { resource: Some(("instance", "")), message_kind: "", request_id: "", ..base }), empty("resource_id"));
        assert_eq!(tr(ClientRequestDigestInput { message_kind: "", request_id: "", ..base }), empty("message_kind"));
        // A resource is only checked when present; an empty body is allowed.
        assert!(tr(ClientRequestDigestInput { resource: None, ..base }).is_ok());
        assert!(tr(base).is_ok(), "empty body is allowed");
    }

    #[test]
    fn client_request_digest_is_sensitive_to_every_field() {
        let (r, r2) = (PrincipalId::from_genesis(k()), PrincipalId::from_genesis(k()));
        let (h, h2) = (PrincipalId::from_genesis(k()), PrincipalId::from_genesis(k()));
        let (t, t2) = (PrincipalId::from_genesis(k()), PrincipalId::from_genesis(k()));
        let base = ClientRequestDigestInput { requester: &r, host: Some(&h), resource: Some(("instance", "i1")), message_kind: "start_instance", body: &[1, 2, 3], request_id: "r4", target: &t };
        let d = |i: ClientRequestDigestInput<'_>| client_request_digest(&i).unwrap();
        let want = d(base);
        let flips = [
            ("requester", d(ClientRequestDigestInput { requester: &r2, ..base })),
            ("host absent", d(ClientRequestDigestInput { host: None, ..base })),
            ("host", d(ClientRequestDigestInput { host: Some(&h2), ..base })),
            ("resource absent", d(ClientRequestDigestInput { resource: None, ..base })),
            ("resource kind", d(ClientRequestDigestInput { resource: Some(("arrangement", "i1")), ..base })),
            ("resource id", d(ClientRequestDigestInput { resource: Some(("instance", "i2")), ..base })),
            ("message kind", d(ClientRequestDigestInput { message_kind: "stop_instance", ..base })),
            ("body", d(ClientRequestDigestInput { body: &[1, 2, 4], ..base })),
            ("body empty", d(ClientRequestDigestInput { body: &[], ..base })),
            ("request id", d(ClientRequestDigestInput { request_id: "r5", ..base })),
            ("target", d(ClientRequestDigestInput { target: &t2, ..base })),
        ];
        for (name, got) in &flips { assert_ne!(*got, want, "flipping {name} left the digest unchanged"); }
        let one_byte = d(ClientRequestDigestInput { body: &[0], ..base });
        let empty = d(ClientRequestDigestInput { body: &[], ..base });
        assert_ne!(one_byte, empty, "an empty body differs from a one-byte body");
        // Moving bytes between adjacent variable-length fields must not collide.
        let a = d(ClientRequestDigestInput { resource: Some(("ab", "c")), ..base });
        let b = d(ClientRequestDigestInput { resource: Some(("a", "bc")), ..base });
        assert_ne!(a, b);
    }

    #[test]
    fn the_two_digest_forms_never_collide() {
        use sha2::{Digest, Sha256};
        let (r, h, t) = (PrincipalId::from_genesis(k()), PrincipalId::from_genesis(k()), PrincipalId::from_genesis(k()));
        let agent = RequestDigestInput { requester: &r, host: &h, subject: None, instance_id: "i1", action_id: "run", parameters: &[1], request_id: "r4", target: &t };
        let client = ClientRequestDigestInput { requester: &r, host: Some(&h), resource: Some(("i1", "run")), message_kind: "run", body: &[1], request_id: "r4", target: &t };
        assert_ne!(request_digest(&agent).unwrap(), client_request_digest(&client).unwrap());
        let (a, c) = (request_digest_transcript(&agent).unwrap(), client_request_digest_transcript(&client).unwrap());
        let common = a.iter().zip(&c).take_while(|(x, y)| x == y).count();
        assert!(common < REQUEST_DIGEST_TAG.len(), "the transcripts diverge inside the tag");
        assert_eq!(Sha256::digest(&c).as_slice(), client_request_digest(&client).unwrap().as_slice());
    }
}
