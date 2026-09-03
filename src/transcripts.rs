//! Canonical, domain-separated, fixed-width byte encodings for every
//! signature the agent-identity design verifies. See
//! `concordat/2026-09-01-agent-identity-model-design.md` §1/§1b/§2/§3 (in
//! the `concordium` monorepo this crate was extracted out of) for the exact
//! layout each of these implements: a NUL-terminated ASCII domain tag, then
//! each field in order, fixed-width scalars written as-is, variable-length
//! values length-prefixed with a 4-byte big-endian unsigned integer.
//!
//! This is the single implementation all three original consumers (grorg,
//! for server-side verification; gait, for client-side signing; multimatrix,
//! for admission-time verification) depend on, rather than each
//! independently reimplementing byte-identical logic. A single wrong byte
//! at this layer breaks every cross-repo signature, not a rare edge case.

fn with_len_prefixed(buf: &mut Vec<u8>, value: &[u8]) {
    buf.extend_from_slice(&(value.len() as u32).to_be_bytes());
    buf.extend_from_slice(value);
}

/// Outer "prove you hold this key right now" signature, used by
/// `RegisterAgent`'s genesis root and `AddAgentKey`'s new device key alike.
pub fn self_proof_transcript(nonce: &[u8], new_public_key: &[u8; 32], scheme: i32) -> Vec<u8> {
    let mut buf = b"grorg.key-challenge.v1\0".to_vec();
    with_len_prefixed(&mut buf, nonce);
    buf.extend_from_slice(new_public_key);
    buf.push(scheme as u8);
    buf
}

/// `RenameAgent`'s authorization signature: the agent's current root key
/// vouching for a new human-facing name, bound to a single-use challenge
/// nonce so a captured signature can never be replayed (unlike
/// delegation/revocation/rotation, a rename's inputs can repeat --
/// renaming back to a prior name -- so it needs the same nonce-based
/// anti-replay `self_proof_transcript` uses, not the challenge-free shape
/// those other three use).
pub fn rename_transcript(nonce: &[u8], agent_id: &str, new_name: &str) -> Vec<u8> {
    let mut buf = b"grorg.agent-rename.v1\0".to_vec();
    with_len_prefixed(&mut buf, nonce);
    with_len_prefixed(&mut buf, agent_id.as_bytes());
    with_len_prefixed(&mut buf, new_name.as_bytes());
    buf
}

/// Inner "an existing authority approved this addition" signature: root
/// delegating a device key via `AddAgentKey`.
pub fn delegation_transcript(agent_id: &str, new_public_key: &[u8; 32], scheme: i32) -> Vec<u8> {
    let mut buf = b"grorg.key-delegation.v1\0".to_vec();
    with_len_prefixed(&mut buf, agent_id.as_bytes());
    buf.extend_from_slice(new_public_key);
    buf.push(scheme as u8);
    buf
}

/// `RevokeAgentKey`'s authorization signature (self- or root-signed).
pub fn revocation_transcript(agent_id: &str, public_key_being_revoked: &[u8; 32]) -> Vec<u8> {
    let mut buf = b"grorg.key-revocation.v1\0".to_vec();
    with_len_prefixed(&mut buf, agent_id.as_bytes());
    buf.extend_from_slice(public_key_being_revoked);
    buf
}

/// `RotateRoot`'s authorization signature: the OLD root vouching for the new one.
pub fn rotation_transcript(agent_id: &str, new_root_public_key: &[u8; 32]) -> Vec<u8> {
    let mut buf = b"grorg.root-rotation.v1\0".to_vec();
    with_len_prefixed(&mut buf, agent_id.as_bytes());
    buf.extend_from_slice(new_root_public_key);
    buf
}

/// gait-local session-key delegation: a device key vouching for a session
/// key that is never registered with grorg at all. Signed by the device
/// key; verified by anyone who already trusts that device key (via grorg's
/// `ListAgentKeys`), travels with every signed event rather than being
/// pre-registered anywhere.
pub fn session_delegation_transcript(
    agent_id: &str,
    device_public_key: &[u8; 32],
    session_public_key: &[u8; 32],
    not_before_unix_seconds: i64,
    not_after_unix_seconds: i64,
) -> Vec<u8> {
    let mut buf = b"gait.session-delegation.v1\0".to_vec();
    with_len_prefixed(&mut buf, agent_id.as_bytes());
    buf.extend_from_slice(device_public_key);
    buf.extend_from_slice(session_public_key);
    buf.extend_from_slice(&not_before_unix_seconds.to_be_bytes());
    buf.extend_from_slice(&not_after_unix_seconds.to_be_bytes());
    buf
}

/// Canonical byte layout for `DeliveryAttestation.signature`. See
/// concordat/2026-09-02-cross-agent-message-attribution-design.md §2a.
/// `body_text` travels inside this transcript directly -- there is no
/// separate hash to reconcile against a differently-transmitted copy.
pub fn delivery_attestation_transcript(
    attestation: &crate::DeliveryAttestation,
) -> Vec<u8> {
    let mut buf = b"identitycrypto.delivery-attestation.v1\0".to_vec();
    buf.extend_from_slice(
        &(attestation.recipient_device_public_keys.len() as u32).to_be_bytes(),
    );
    for key in &attestation.recipient_device_public_keys {
        with_len_prefixed(&mut buf, key);
    }
    with_len_prefixed(&mut buf, attestation.key_id.as_bytes());
    buf.extend_from_slice(&attestation.batch_sequence.to_be_bytes());
    let (attested_at_secs, attested_at_nanos) = attestation
        .attested_at
        .as_ref()
        .map(|t| (t.seconds, t.nanos))
        .unwrap_or((0, 0));
    buf.extend_from_slice(&attested_at_secs.to_be_bytes());
    buf.extend_from_slice(&attested_at_nanos.to_be_bytes());
    for message in &attestation.messages {
        with_len_prefixed(&mut buf, message.message_id.as_bytes());
        with_len_prefixed(&mut buf, message.room_id.as_bytes());
        with_len_prefixed(&mut buf, message.author_agent_id.as_bytes());
        with_len_prefixed(&mut buf, message.body_text.as_bytes());
        buf.extend_from_slice(&message.verification_outcome.to_be_bytes());
        match &message.delegation_cert {
            None => buf.push(0x00),
            Some(cert) => {
                buf.push(0x01);
                with_len_prefixed(&mut buf, cert.agent_id.as_bytes());
                with_len_prefixed(&mut buf, &cert.device_public_key);
                with_len_prefixed(&mut buf, &cert.session_public_key);
                buf.extend_from_slice(&cert.not_before_unix_seconds.to_be_bytes());
                buf.extend_from_slice(&cert.not_after_unix_seconds.to_be_bytes());
            }
        }
    }
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_attested_message(id: &str) -> crate::AttestedMessage {
        crate::AttestedMessage {
            message_id: id.into(),
            room_id: "room-general".into(),
            author_agent_id: "agent-2".into(),
            body_text: "hello".into(),
            verification_outcome: crate::VerificationOutcome::DirectKey as i32,
            delegation_cert: None,
        }
    }

    fn sample_attestation(messages: Vec<crate::AttestedMessage>) -> crate::DeliveryAttestation {
        crate::DeliveryAttestation {
            recipient_device_public_keys: vec![vec![7u8; 32]],
            key_id: "mm-key-2026-09".into(),
            batch_sequence: 1,
            attested_at: Some(prost_types::Timestamp { seconds: 100, nanos: 0 }),
            messages,
            signature: Vec::new(),
        }
    }

    #[test]
    fn delivery_attestation_transcript_has_stable_domain() {
        let t = delivery_attestation_transcript(&sample_attestation(vec![sample_attested_message("m1")]));
        assert!(t.starts_with(b"identitycrypto.delivery-attestation.v1\0"));
    }

    #[test]
    fn delivery_attestation_transcript_binds_message_order() {
        let a = sample_attestation(vec![sample_attested_message("m1"), sample_attested_message("m2")]);
        let b = sample_attestation(vec![sample_attested_message("m2"), sample_attested_message("m1")]);
        assert_ne!(
            delivery_attestation_transcript(&a),
            delivery_attestation_transcript(&b),
            "reordering the same messages must change the transcript"
        );
    }

    #[test]
    fn delivery_attestation_transcript_binds_body_text() {
        let mut tampered = sample_attested_message("m1");
        tampered.body_text = "goodbye".into();
        assert_ne!(
            delivery_attestation_transcript(&sample_attestation(vec![sample_attested_message("m1")])),
            delivery_attestation_transcript(&sample_attestation(vec![tampered])),
            "a substituted body_text must change the transcript"
        );
    }

    #[test]
    fn delivery_attestation_transcript_binds_recipient_and_sequence() {
        let msgs = vec![sample_attested_message("m1")];
        let mut a = sample_attestation(msgs.clone());
        let mut b = sample_attestation(msgs);
        b.recipient_device_public_keys = vec![vec![9u8; 32]];
        assert_ne!(delivery_attestation_transcript(&a), delivery_attestation_transcript(&b));
        a.batch_sequence = 2;
        let c = sample_attestation(vec![sample_attested_message("m1")]);
        assert_ne!(delivery_attestation_transcript(&a), delivery_attestation_transcript(&c));
    }

    #[test]
    fn delivery_attestation_transcript_binds_the_full_recipient_list_not_just_membership() {
        let msgs = vec![sample_attested_message("m1")];
        let mut one_key = sample_attestation(msgs.clone());
        one_key.recipient_device_public_keys = vec![vec![7u8; 32]];
        let mut two_keys = sample_attestation(msgs);
        two_keys.recipient_device_public_keys = vec![vec![7u8; 32], vec![8u8; 32]];
        assert_ne!(
            delivery_attestation_transcript(&one_key),
            delivery_attestation_transcript(&two_keys),
            "adding an extra recipient device key must change the transcript"
        );
    }

    #[test]
    fn delivery_attestation_transcript_binds_verification_outcome_without_truncation() {
        let mut system = sample_attested_message("m1");
        system.verification_outcome = crate::VerificationOutcome::System as i32;
        assert_ne!(
            delivery_attestation_transcript(&sample_attestation(vec![sample_attested_message("m1")])),
            delivery_attestation_transcript(&sample_attestation(vec![system])),
        );
    }

    #[test]
    fn delivery_attestation_transcript_binds_attested_at_nanos() {
        let msgs = vec![sample_attested_message("m1")];
        let mut a = sample_attestation(msgs.clone());
        let mut b = sample_attestation(msgs);
        a.attested_at = Some(prost_types::Timestamp { seconds: 100, nanos: 0 });
        b.attested_at = Some(prost_types::Timestamp { seconds: 100, nanos: 1 });
        assert_ne!(delivery_attestation_transcript(&a), delivery_attestation_transcript(&b));
    }

    #[test]
    fn delivery_attestation_transcript_binds_delegation_cert_presence() {
        let mut delegated = sample_attested_message("m1");
        delegated.delegation_cert = Some(crate::DelegationCert {
            agent_id: "agent-2".into(),
            device_public_key: vec![1u8; 32],
            session_public_key: vec![2u8; 32],
            not_before_unix_seconds: 0,
            not_after_unix_seconds: 100,
            signature: vec![3u8; 64],
        });
        assert_ne!(
            delivery_attestation_transcript(&sample_attestation(vec![sample_attested_message("m1")])),
            delivery_attestation_transcript(&sample_attestation(vec![delegated])),
        );
    }

    #[test]
    fn delivery_attestation_transcript_length_prefixes_delegation_cert_key_bytes() {
        let mut a = sample_attested_message("m1");
        a.delegation_cert = Some(crate::DelegationCert {
            agent_id: "agent-2".into(),
            device_public_key: vec![1u8; 31],
            session_public_key: [1u8, 2u8].repeat(33),
            not_before_unix_seconds: 0,
            not_after_unix_seconds: 100,
            signature: vec![3u8; 64],
        });
        let mut b = sample_attested_message("m1");
        b.delegation_cert = Some(crate::DelegationCert {
            agent_id: "agent-2".into(),
            device_public_key: vec![1u8; 32],
            session_public_key: {
                let mut v = [1u8, 2u8].repeat(33);
                v.pop();
                v
            },
            not_before_unix_seconds: 0,
            not_after_unix_seconds: 100,
            signature: vec![3u8; 64],
        });
        assert_ne!(
            delivery_attestation_transcript(&sample_attestation(vec![a])),
            delivery_attestation_transcript(&sample_attestation(vec![b])),
            "differing key-length boundaries must not collide to the same transcript bytes"
        );
    }

    #[test]
    fn self_proof_transcript_has_stable_domain_and_layout() {
        let key = [7u8; 32];
        let t = self_proof_transcript(b"nonce", &key, 1);
        assert!(t.starts_with(b"grorg.key-challenge.v1\0"));
        // domain(23) + len-prefix(4) + "nonce"(5) + key(32) + scheme(1)
        assert_eq!(t.len(), 23 + 4 + 5 + 32 + 1);
        assert_eq!(&t[t.len() - 1..], &[1u8]);
    }

    #[test]
    fn delegation_transcript_binds_agent_id() {
        let key = [9u8; 32];
        let a = delegation_transcript("agent-a", &key, 1);
        let b = delegation_transcript("agent-b", &key, 1);
        assert_ne!(a, b, "different agent_id must produce a different transcript");
    }

    #[test]
    fn different_domains_never_collide_for_the_same_inputs() {
        let key = [3u8; 32];
        let self_proof = self_proof_transcript(b"x", &key, 1);
        let delegation = delegation_transcript("x", &key, 1);
        assert_ne!(self_proof, delegation);
    }

    #[test]
    fn revocation_transcript_binds_agent_id_and_key() {
        let key_a = [1u8; 32];
        let key_b = [2u8; 32];
        assert_ne!(
            revocation_transcript("agent-a", &key_a),
            revocation_transcript("agent-a", &key_b),
        );
        assert_ne!(
            revocation_transcript("agent-a", &key_a),
            revocation_transcript("agent-b", &key_a),
        );
    }

    #[test]
    fn rotation_transcript_binds_agent_id_and_new_key() {
        let key_a = [1u8; 32];
        let key_b = [2u8; 32];
        assert_ne!(
            rotation_transcript("agent-a", &key_a),
            rotation_transcript("agent-a", &key_b),
        );
    }

    #[test]
    fn rename_transcript_has_stable_domain_and_layout() {
        let t = rename_transcript(b"nonce", "agent-a", "new-name");
        assert!(t.starts_with(b"grorg.agent-rename.v1\0"));
        // domain(22) + len-prefix(4) + "nonce"(5) + len-prefix(4) + "agent-a"(7) + len-prefix(4) + "new-name"(8)
        assert_eq!(t.len(), 22 + 4 + 5 + 4 + 7 + 4 + 8);
    }

    #[test]
    fn rename_transcript_binds_nonce() {
        let a = rename_transcript(b"nonce-a", "agent-a", "same-name");
        let b = rename_transcript(b"nonce-b", "agent-a", "same-name");
        assert_ne!(a, b, "different nonce must produce a different transcript -- this is what makes replay impossible");
    }

    #[test]
    fn rename_transcript_binds_agent_id() {
        let a = rename_transcript(b"nonce", "agent-a", "same-name");
        let b = rename_transcript(b"nonce", "agent-b", "same-name");
        assert_ne!(a, b, "different agent_id must produce a different transcript");
    }

    #[test]
    fn rename_transcript_binds_new_name() {
        let a = rename_transcript(b"nonce", "agent-a", "old-name");
        let b = rename_transcript(b"nonce", "agent-a", "new-name");
        assert_ne!(a, b, "different new_name must produce a different transcript");
    }

    #[test]
    fn rename_transcript_domain_never_collides_with_self_proof_transcript() {
        // Both embed a nonce; different domains and different trailing
        // shapes must still never collide.
        let key = [3u8; 32];
        let self_proof = self_proof_transcript(b"nonce", &key, 1);
        let rename = rename_transcript(b"nonce", "agent-x", "agent-x");
        assert_ne!(self_proof, rename);
    }

    #[test]
    fn session_delegation_transcript_has_stable_domain_and_layout() {
        let device = [4u8; 32];
        let session = [5u8; 32];
        let t = session_delegation_transcript("agent-a", &device, &session, 100, 200);
        assert!(t.starts_with(b"gait.session-delegation.v1\0"));
        // domain(27) + len-prefix(4) + "agent-a"(7) + device(32) + session(32) + not_before(8) + not_after(8)
        assert_eq!(t.len(), 27 + 4 + 7 + 32 + 32 + 8 + 8);
    }

    #[test]
    fn session_delegation_transcript_binds_the_window() {
        let device = [4u8; 32];
        let session = [5u8; 32];
        let a = session_delegation_transcript("agent-a", &device, &session, 100, 200);
        let b = session_delegation_transcript("agent-a", &device, &session, 100, 999);
        assert_ne!(a, b, "a different not_after must change the transcript");
    }
}
