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

#[cfg(test)]
mod tests {
    use super::*;

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
