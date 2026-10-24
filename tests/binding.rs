//! For every transcript: changing any one encoded field changes the bytes,
//! and inputs whose naive concatenation collides do not collide.

use identity_crypto::jwk_duo::SigningKeyPair;
use identity_crypto::transcripts::*;
use identity_crypto::{pb, PrincipalId, PublicKey, Result};

fn k() -> PublicKey {
    PublicKey::from(&SigningKeyPair::generate())
}
fn pk() -> Option<pb::PublicKey> {
    Some(pb::PublicKey::from(&k()))
}

type Mutation<T> = (&'static str, Box<dyn Fn(&mut T)>);

fn assert_binds<T: Clone>(name: &str, base: T, f: impl Fn(&T) -> Result<Vec<u8>>, mutations: Vec<Mutation<T>>) {
    let baseline = f(&base).unwrap_or_else(|e| panic!("{name} baseline: {e}"));
    for (field, mutate) in mutations {
        let mut changed = base.clone();
        mutate(&mut changed);
        let out = f(&changed).unwrap_or_else(|e| panic!("{name}.{field}: {e}"));
        assert_ne!(out, baseline, "{name}: changing {field} must change the transcript");
    }
}

fn cert(mode: u32) -> pb::DelegationCert {
    let device = pk();
    pb::DelegationCert {
        principal_genesis: if mode == 0 { device.clone() } else { pk() },
        mode,
        device,
        session: pk(),
        host_genesis: if mode == 1 { pk() } else { None },
        subject: if mode == 1 { Some("aaaaaaaaaaaaaaaa/i1".into()) } else { None },
        not_before_unix_seconds: 1,
        not_after_unix_seconds: 2,
        signature: vec![1; 64],
    }
}

#[test]
fn key_challenge_binds_every_field() {
    let base = ("aud".to_string(), vec![1u8], k());
    assert_binds(
        "key_challenge",
        base,
        |(a, n, key)| key_challenge_transcript(a, n, key),
        vec![
            ("audience", Box::new(|b| b.0.push('x'))),
            ("nonce", Box::new(|b| b.1.push(2))),
            ("new", Box::new(|b| b.2 = k())),
        ],
    );
}

#[test]
fn principal_rename_binds_every_field() {
    let base = (vec![1u8], PrincipalId::from_genesis(k()), "n".to_string());
    assert_binds(
        "principal_rename",
        base,
        |(n, p, name)| principal_rename_transcript(n, p, name),
        vec![
            ("nonce", Box::new(|b| b.0.push(2))),
            ("principal", Box::new(|b| b.1 = PrincipalId::from_genesis(k()))),
            ("new_name", Box::new(|b| b.2.push('x'))),
        ],
    );
}

#[test]
fn key_delegation_binds_every_field() {
    let root = pk();
    let base = pb::KeyDelegation {
        principal_genesis: root.clone(), signing_root: root, purpose: pb::KeyPurpose::Device as i32,
        delegated: pk(), delegated_encryption: pk(), issued_at_unix_seconds: 1, not_after_unix_seconds: 2,
        signature: vec![],
    };
    assert_binds(
        "key_delegation",
        base,
        key_delegation_transcript,
        vec![
            ("principal_genesis", Box::new(|d| d.principal_genesis = pk())),
            ("signing_root", Box::new(|d| d.signing_root = pk())),
            ("purpose", Box::new(|d| {
                d.purpose = pb::KeyPurpose::Approval as i32;
                d.delegated_encryption = None;
            })),
            ("delegated", Box::new(|d| d.delegated = pk())),
            ("delegated_encryption", Box::new(|d| d.delegated_encryption = pk())),
            ("issued_at", Box::new(|d| d.issued_at_unix_seconds += 1)),
            ("not_after", Box::new(|d| d.not_after_unix_seconds += 1)),
        ],
    );
}

#[test]
fn key_revocation_and_rotation_bind_every_field() {
    let base = pb::KeyRevocation {
        principal_genesis: pk(), revoked: pk(), revoked_by: pk(), revoked_at_unix_seconds: 1, signature: vec![],
    };
    assert_binds(
        "key_revocation",
        base,
        key_revocation_transcript,
        vec![
            ("principal_genesis", Box::new(|r| r.principal_genesis = pk())),
            ("revoked", Box::new(|r| r.revoked = pk())),
            ("revoked_by", Box::new(|r| r.revoked_by = pk())),
            ("revoked_at", Box::new(|r| r.revoked_at_unix_seconds += 1)),
        ],
    );
    let base = pb::RootRotation {
        principal_genesis: pk(), old_root: pk(), new_root: pk(), issued_at_unix_seconds: 1, signature: vec![],
    };
    assert_binds(
        "root_rotation",
        base,
        root_rotation_transcript,
        vec![
            ("principal_genesis", Box::new(|r| r.principal_genesis = pk())),
            ("old_root", Box::new(|r| r.old_root = pk())),
            ("new_root", Box::new(|r| r.new_root = pk())),
            ("issued_at", Box::new(|r| r.issued_at_unix_seconds += 1)),
        ],
    );
}

#[test]
fn session_delegation_binds_every_field() {
    assert_binds(
        "session_delegation",
        cert(1),
        session_delegation_transcript,
        vec![
            ("mode", Box::new(|c| {
                c.mode = 0;
                c.host_genesis = None;
                c.subject = None;
            })),
            ("principal_genesis", Box::new(|c| c.principal_genesis = pk())),
            ("host_genesis", Box::new(|c| c.host_genesis = pk())),
            ("subject", Box::new(|c| c.subject.as_mut().unwrap().push('x'))),
            ("device", Box::new(|c| c.device = pk())),
            ("session", Box::new(|c| c.session = pk())),
            ("not_before", Box::new(|c| c.not_before_unix_seconds += 1)),
            ("not_after", Box::new(|c| c.not_after_unix_seconds += 1)),
        ],
    );
}

#[test]
fn signed_message_binds_every_field_and_present_empty_differs_from_absent() {
    let base = pb::SignedMessage {
        signer: Some(pb::SignerChain {
            chain: Some(pb::signer_chain::Chain::SelfRooted(pb::SelfRooted { device: None, session: Some(cert(0)) })),
        }),
        audience: "a".into(), nonce: vec![1; 16], issued_at_unix_seconds: 1, in_reply_to_nonce: None,
        body_type: "t".into(), body: vec![], signature: vec![],
    };
    let set_session = |m: &mut pb::SignedMessage, f: &dyn Fn(&mut pb::DelegationCert)| {
        if let Some(pb::signer_chain::Chain::SelfRooted(s)) = m.signer.as_mut().and_then(|s| s.chain.as_mut()) {
            f(s.session.as_mut().unwrap());
        }
    };
    assert_binds(
        "signed_message",
        base.clone(),
        signed_message_transcript,
        vec![
            ("principal", Box::new(move |m| set_session(m, &|c| c.principal_genesis = pk()))),
            ("session", Box::new(move |m| set_session(m, &|c| c.session = pk()))),
            ("audience", Box::new(|m| m.audience.push('x'))),
            ("nonce", Box::new(|m| m.nonce[0] = 2)),
            ("issued_at", Box::new(|m| m.issued_at_unix_seconds += 1)),
            ("in_reply_to_nonce", Box::new(|m| m.in_reply_to_nonce = Some(vec![0; 16]))),
            ("body_type", Box::new(|m| m.body_type.push('x'))),
            ("body", Box::new(|m| m.body.push(1))),
        ],
    );
    // opt(): an absent reply nonce (00) differs from a present one even when
    // the rest is identical.
    let mut replying = base.clone();
    replying.in_reply_to_nonce = Some(vec![0; 16]);
    assert_ne!(signed_message_transcript(&base).unwrap(), signed_message_transcript(&replying).unwrap());
}

#[test]
fn signed_document_approval_and_peer_revocation_bind_every_field() {
    let base = pb::SignedDocument {
        signer_genesis: pk(), signing: pk(), document_type: "t".into(), version: 1, issued_at_unix_seconds: 1,
        expires_at_unix_seconds: 2, body: vec![1], signature: vec![], signer_rotations: vec![],
    };
    assert_binds(
        "signed_document",
        base,
        signed_document_transcript,
        vec![
            ("signer_genesis", Box::new(|d| d.signer_genesis = pk())),
            ("signing", Box::new(|d| d.signing = pk())),
            ("document_type", Box::new(|d| d.document_type.push('x'))),
            ("version", Box::new(|d| d.version += 1)),
            ("issued_at", Box::new(|d| d.issued_at_unix_seconds += 1)),
            ("expires_at", Box::new(|d| d.expires_at_unix_seconds += 1)),
            ("body", Box::new(|d| d.body.push(2))),
        ],
    );
    let base = pb::Approval {
        principal_genesis: pk(), approval_key: pk(), device: pk(), audience: "a".into(), request_id: "r".into(),
        request_digest: vec![0; 32], accept: true, issued_at_unix_seconds: 1, signature: vec![],
    };
    assert_binds(
        "approval",
        base,
        approval_transcript,
        vec![
            ("principal_genesis", Box::new(|a| a.principal_genesis = pk())),
            ("approval_key", Box::new(|a| a.approval_key = pk())),
            ("device", Box::new(|a| a.device = pk())),
            ("audience", Box::new(|a| a.audience.push('x'))),
            ("request_id", Box::new(|a| a.request_id.push('x'))),
            ("request_digest", Box::new(|a| a.request_digest[0] = 1)),
            ("accept", Box::new(|a| a.accept = false)),
            ("issued_at", Box::new(|a| a.issued_at_unix_seconds += 1)),
        ],
    );
    let base = pb::PeerRevocation {
        revoker_genesis: pk(), approval_key: pk(), target_genesis: pk(), revoked: None,
        issued_at_unix_seconds: 1, signature: vec![], document_id: vec![7; 32],
    };
    assert_binds(
        "peer_revocation",
        base,
        peer_revocation_transcript,
        vec![
            ("revoker_genesis", Box::new(|p| p.revoker_genesis = pk())),
            ("approval_key", Box::new(|p| p.approval_key = pk())),
            ("target_genesis", Box::new(|p| p.target_genesis = pk())),
            ("revoked", Box::new(|p| p.revoked = pk())),
            ("issued_at", Box::new(|p| p.issued_at_unix_seconds += 1)),
            ("document_id", Box::new(|p| p.document_id[0] ^= 1)),
        ],
    );
}

#[test]
fn delivery_attestation_binds_every_field() {
    let message = pb::AttestedMessage {
        message_id: "m".into(), room_id: "r".into(), body_text: "b".into(),
        delegation_cert: Some(cert(1)), author_genesis: pk(),
    };
    let base = pb::DeliveryAttestation {
        recipient_devices: vec![pb::PublicKey::from(&k())], key_id: "k".into(), batch_sequence: 1,
        attested_at: Some(prost_types::Timestamp { seconds: 1, nanos: 1 }),
        messages: vec![message.clone(), pb::AttestedMessage { message_id: "n".into(), ..message }],
        signature: vec![],
    };
    assert_binds(
        "delivery_attestation",
        base,
        delivery_attestation_transcript,
        vec![
            ("recipient_devices", Box::new(|a| a.recipient_devices.push(pb::PublicKey::from(&k())))),
            ("key_id", Box::new(|a| a.key_id.push('x'))),
            ("batch_sequence", Box::new(|a| a.batch_sequence += 1)),
            ("attested_at.seconds", Box::new(|a| a.attested_at.as_mut().unwrap().seconds += 1)),
            ("attested_at.nanos", Box::new(|a| a.attested_at.as_mut().unwrap().nanos += 1)),
            ("messages.message_id", Box::new(|a| a.messages[0].message_id.push('x'))),
            ("messages.room_id", Box::new(|a| a.messages[0].room_id.push('x'))),
            ("messages.author_genesis", Box::new(|a| a.messages[0].author_genesis = pk())),
            ("messages.body_text", Box::new(|a| a.messages[0].body_text.push('x'))),
            ("messages.delegation_cert", Box::new(|a| a.messages[0].delegation_cert.as_mut().unwrap().not_after_unix_seconds += 1)),
            ("messages.delegation_cert.signature", Box::new(|a| a.messages[0].delegation_cert.as_mut().unwrap().signature[0] = 2)),
            ("message order", Box::new(|a| a.messages.swap(0, 1))),
        ],
    );
}

#[test]
fn request_digest_binds_every_field() {
    let ids: Vec<PrincipalId> = (0..6).map(|_| PrincipalId::from_genesis(k())).collect();
    let base = RequestDigestInput {
        requester: &ids[0], host: &ids[1], subject: Some("s/i1"), instance_id: "s/i1",
        action_id: "run", parameters: &[1], request_id: "r4", target: &ids[2],
    };
    let baseline = request_digest_transcript(&base).unwrap();
    let changed = [
        ("requester", RequestDigestInput { requester: &ids[3], ..base }),
        ("host", RequestDigestInput { host: &ids[4], ..base }),
        ("subject", RequestDigestInput { subject: None, ..base }),
        ("instance_id", RequestDigestInput { instance_id: "s/i2", ..base }),
        ("action_id", RequestDigestInput { action_id: "stop", ..base }),
        ("parameters", RequestDigestInput { parameters: &[2], ..base }),
        ("request_id", RequestDigestInput { request_id: "r5", ..base }),
        ("target", RequestDigestInput { target: &ids[5], ..base }),
    ];
    for (field, input) in changed {
        assert_ne!(request_digest_transcript(&input).unwrap(), baseline, "request_digest: {field}");
    }
}

#[test]
fn no_concatenation_ambiguity() {
    let key = k();
    assert_ne!(
        key_challenge_transcript("ab", b"c", &key).unwrap(),
        key_challenge_transcript("a", b"bc", &key).unwrap()
    );
    let p = PrincipalId::from_genesis(k());
    assert_ne!(
        principal_rename_transcript(b"ab", &p, "c").unwrap(),
        principal_rename_transcript(b"a", &p, "bc").unwrap()
    );
}
