//! Agent-key standing verification: whether a claimed public key was, at
//! `msg_timestamp`, a live and correctly-scoped key for signing -- either
//! directly ([`verify`]) or via a delegated session key
//! ([`verify_delegated`]).
//!
//! Moved here from multimatrix-ops's `agentkey.rs`/`delegation.rs`
//! (2026-09): both were already pure functions over a caller-supplied key
//! list, with zero dependency on any transport, storage, or dispatch
//! concept -- multimatrix-ops was never this policy's real owner, it just
//! wrote the check first. A second consumer wanting to verify an agent's
//! key standing (structmux, checking an off-host agent before granting it
//! a route in) would otherwise have had to depend on a work-dispatch crate
//! for a signature check, and the likely real outcome is a THIRD
//! reimplementation of a check that already existed twice inside
//! multimatrix alone (this module's own logic, and
//! `multimatrix-bridge::attestation`'s separate pinned-key check). One
//! shared check every caller calls, rather than growing its own copy --
//! the same rule that made bridge attestation mandatory.
//!
//! [`AgentKeyRecord`] is deliberately NOT `grorg_proto::AgentKey`:
//! grorg-proto already depends on identity-crypto (for the shared
//! [`crate::KeyScheme`] type and `proto_include_dir()`), so identity-crypto
//! depending back on grorg-proto would be a straight dependency cycle
//! (identity-crypto -> grorg-proto -> identity-crypto). This tiny local
//! record carries only the fields either verifier actually reads;
//! grorg-proto (which owns `AgentKey` and already depends on this crate)
//! provides `From<&grorg_proto::AgentKey> for AgentKeyRecord` on its own
//! side -- legal under the orphan rule since `AgentKey` is local to that
//! crate, and it keeps identity-crypto itself ignorant of grorg's schema
//! entirely.

use crate::KeyScheme;
use anyhow::Result;
use ed25519_dalek::Verifier;
use prost_types::Timestamp;

/// How long a device key or a delegation cert's own window is allowed to
/// have already lapsed (or not yet begun), to absorb clock skew between
/// whoever minted the cert and whoever is verifying it now.
pub const CLOCK_SKEW_TOLERANCE_SECONDS: i64 = 30;

/// The subset of an agent's key record either verifier reads. See the
/// module doc for why this isn't `grorg_proto::AgentKey` directly.
#[derive(Clone, Debug, PartialEq)]
pub struct AgentKeyRecord {
    pub public_key: String,
    pub scheme: KeyScheme,
    /// True only for grorg's `KEY_PURPOSE_DEVICE` -- the one purpose
    /// distinction [`verify_delegated`]'s device-key lookup reads. Neither
    /// verifier here ever reads ROOT vs. UNSPECIFIED, so this doesn't
    /// expose grorg's full purpose taxonomy, just the one bit that matters.
    pub is_device_key: bool,
    pub created_at: Option<Timestamp>,
    pub revoked_at: Option<Timestamp>,
}

/// Verify a message signature against an agent's known keys (all of them,
/// active and revoked -- a signature made before revocation must still
/// verify; concordat §5.6). Checks, all must pass:
/// 1. `claimed_public_key_hex` is present in `keys` for this agent.
/// 2. That key's `scheme` matches the caller-supplied `scheme`.
/// 3. If the key has a `created_at`, the message was not timestamped
///    before the key existed (absent for legacy pre-purpose rows --
///    unaffected, no lower bound applied at all).
/// 4. The key was not revoked before `msg_timestamp`, and the ed25519
///    signature itself checks out.
pub fn verify(
    keys: &[AgentKeyRecord],
    claimed_public_key_hex: &str,
    scheme: KeyScheme,
    msg: &[u8],
    sig: &[u8],
    msg_timestamp: Timestamp,
) -> Result<bool> {
    let Some(key) = keys.iter().find(|k| k.public_key == claimed_public_key_hex) else {
        return Ok(false);
    };

    if key.scheme != scheme {
        return Ok(false);
    }

    if let Some(created_at) = &key.created_at {
        if !timestamp_before_or_eq(created_at, &msg_timestamp) {
            // The message claims to have been signed before this key even
            // existed -- reject, same shape as the revoked_at check below.
            return Ok(false);
        }
    }

    if let Some(revoked_at) = &key.revoked_at {
        if timestamp_before_or_eq(revoked_at, &msg_timestamp) {
            return Ok(false);
        }
    }

    match scheme {
        KeyScheme::Ed25519 => raw_ed25519_verify(claimed_public_key_hex, msg, sig),
        KeyScheme::Secp256k1Schnorr => {
            anyhow::bail!("KeyScheme::Secp256k1Schnorr has no implementation yet")
        }
        KeyScheme::Unspecified => anyhow::bail!("KeyScheme::Unspecified cannot be verified"),
    }
}

/// Verifies the whole chain for a session-signed submission: the message
/// signature against the session key the cert names, the cert's own
/// signature against a known DEVICE key for this agent, the cert's
/// structural window, and both the device key's and cert's clock-skew-
/// tolerant validity windows against the receiver's own clock
/// (`msg_timestamp` -- never the message's self-reported timestamp).
pub fn verify_delegated(
    keys: &[AgentKeyRecord],
    agent_id: &str,
    cert: &crate::DelegationCert,
    claimed_session_public_key_hex: &str,
    msg: &[u8],
    sig: &[u8],
    msg_timestamp: Timestamp,
) -> Result<bool> {
    if cert.agent_id != agent_id {
        return Ok(false);
    }

    // Structural check FIRST, no tolerance applied -- an inverted or empty
    // window must never pass, regardless of how the two bounds compare
    // once independently widened.
    if cert.not_before_unix_seconds >= cert.not_after_unix_seconds {
        return Ok(false);
    }

    let device_public_key_hex = hex::encode(&cert.device_public_key);
    let Some(device_key) = keys
        .iter()
        .find(|k| k.public_key == device_public_key_hex && k.is_device_key)
    else {
        return Ok(false);
    };
    if device_key.scheme != KeyScheme::Ed25519 {
        return Ok(false);
    }

    let receipt_seconds = msg_timestamp.seconds;
    let t = CLOCK_SKEW_TOLERANCE_SECONDS;

    if let Some(created_at) = &device_key.created_at {
        if lower_bound_ok(created_at.seconds, t, receipt_seconds) != Some(true) {
            return Ok(false);
        }
    }
    // No clock-skew tolerance here, unlike the bounds below: revoked_at is
    // grorg's own record, read back from grorg via ListAgentKeys -- there
    // is no second, possibly-skewed clock to reconcile it against, unlike
    // not_before/not_after (issued by whoever minted the cert) or
    // created_at (also grorg's, but see the deliberate legacy exception
    // for keys with none set). A revoked key is the emergency stop; it
    // must take effect the instant grorg records it, not up to
    // CLOCK_SKEW_TOLERANCE_SECONDS later. Matches verify()'s equally
    // strict revoked_at check on the direct-key path.
    if let Some(revoked_at) = &device_key.revoked_at {
        if timestamp_before_or_eq(revoked_at, &msg_timestamp) {
            return Ok(false);
        }
    }
    if lower_bound_ok(cert.not_before_unix_seconds, t, receipt_seconds) != Some(true) {
        return Ok(false);
    }
    if upper_bound_ok(cert.not_after_unix_seconds, t, receipt_seconds) != Some(true) {
        return Ok(false);
    }

    // Inner check: the cert's own signature, against the DEVICE key.
    let transcript = cert_transcript(cert)?;
    if !raw_ed25519_verify(&device_public_key_hex, &transcript, &cert.signature)? {
        return Ok(false);
    }

    // The claimed session key on the submission must be the exact one the
    // cert names -- a message can't claim a different session key than the
    // one the device actually delegated to.
    let session_public_key_hex = hex::encode(&cert.session_public_key);
    if session_public_key_hex != claimed_session_public_key_hex {
        return Ok(false);
    }

    // Outer check: the message signature, against the SESSION key. Session
    // keys are never registered with grorg at all -- this is the one
    // signature in this whole design verified against a key that came
    // entirely from the submission itself, authorized only by the chain
    // above.
    raw_ed25519_verify(&session_public_key_hex, msg, sig)
}

/// Adapts `DelegationCert`'s `Vec<u8>` fields to `transcripts::
/// session_delegation_transcript`'s fixed-width `&[u8; 32]` signature. A
/// wrong-length key here is a malformed cert -- reject before ever reaching
/// signature verification.
fn cert_transcript(cert: &crate::DelegationCert) -> Result<Vec<u8>> {
    let device: [u8; 32] = cert
        .device_public_key
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("DelegationCert.device_public_key must be 32 bytes"))?;
    let session: [u8; 32] = cert
        .session_public_key
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("DelegationCert.session_public_key must be 32 bytes"))?;
    Ok(crate::transcripts::session_delegation_transcript(
        &cert.agent_id,
        &device,
        &session,
        cert.not_before_unix_seconds,
        cert.not_after_unix_seconds,
    ))
}

/// `value - tolerance <= receipt_time`: `value` is a lower bound (a key's
/// `created_at`, a cert's `not_before`) widened earlier to absorb clock
/// skew. `None` on overflow rather than wrapping into a bound that means
/// the opposite of what it says.
fn lower_bound_ok(value: i64, tolerance: i64, receipt_time: i64) -> Option<bool> {
    value.checked_sub(tolerance).map(|lo| lo <= receipt_time)
}

/// `receipt_time < value + tolerance`: `value` is an upper bound (a key's
/// `revoked_at`, a cert's `not_after`) widened later to absorb clock skew.
/// `None` on overflow, same reasoning as [`lower_bound_ok`].
fn upper_bound_ok(value: i64, tolerance: i64, receipt_time: i64) -> Option<bool> {
    value.checked_add(tolerance).map(|hi| receipt_time < hi)
}

/// Neither Timestamp value has an `Ord` impl -- compare the (seconds,
/// nanos) tuple directly. `a <= b` means the event `a` names had already
/// happened by the time `b` claims to be.
fn timestamp_before_or_eq(a: &Timestamp, b: &Timestamp) -> bool {
    (a.seconds, a.nanos) <= (b.seconds, b.nanos)
}

/// Raw ed25519 verification returning `Result<bool>`, distinct from this
/// crate's own [`crate::verify_ed25519`] (which collapses malformed input
/// and "signature does not verify" into the same `Err` via its witness
/// type). The agent-key policy above needs those cases kept apart: a
/// malformed hex key or wrong-length signature is a caller bug worth
/// erroring on, while "does not verify" is an ordinary `Ok(false)` result
/// callers branch on routinely. Parsing itself is shared with
/// `crate::verify_ed25519` via `decode_verifying_key`/`decode_signature`,
/// so the two functions can never drift on how a key or signature is
/// decoded -- only on what they do once decoding succeeds.
fn raw_ed25519_verify(public_key_hex: &str, msg: &[u8], sig: &[u8]) -> Result<bool> {
    let verifying_key = crate::decode_verifying_key(public_key_hex)?;
    let signature = crate::decode_signature(sig)?;
    Ok(verifying_key.verify(msg, &signature).is_ok())
}

#[cfg(test)]
mod verify_tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    fn key(public_key_hex: &str, revoked_at: Option<Timestamp>) -> AgentKeyRecord {
        AgentKeyRecord {
            public_key: public_key_hex.to_string(),
            scheme: KeyScheme::Ed25519,
            is_device_key: false,
            created_at: None,
            revoked_at,
        }
    }

    fn key_with_created_at(public_key_hex: &str, created_at: Timestamp) -> AgentKeyRecord {
        AgentKeyRecord {
            created_at: Some(created_at),
            is_device_key: true,
            ..key(public_key_hex, None)
        }
    }

    #[test]
    fn genuine_signature_from_a_non_revoked_key_verifies() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_hex = hex::encode(signing_key.verifying_key().to_bytes());
        let msg = b"hello room log";
        let sig = signing_key.sign(msg);

        let keys = vec![key(&public_hex, None)];
        let ok = verify(
            &keys, &public_hex, KeyScheme::Ed25519, msg, &sig.to_bytes(),
            Timestamp { seconds: 1_000, nanos: 0 },
        )
        .unwrap();
        assert!(ok);
    }

    #[test]
    fn signature_after_revocation_does_not_verify() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_hex = hex::encode(signing_key.verifying_key().to_bytes());
        let msg = b"hello room log";
        let sig = signing_key.sign(msg);
        let keys = vec![key(&public_hex, Some(Timestamp { seconds: 500, nanos: 0 }))];
        let ok = verify(
            &keys, &public_hex, KeyScheme::Ed25519, msg, &sig.to_bytes(),
            Timestamp { seconds: 1_000, nanos: 0 },
        )
        .unwrap();
        assert!(!ok, "message timestamped after revoked_at must not verify");
    }

    #[test]
    fn signature_before_revocation_still_verifies() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_hex = hex::encode(signing_key.verifying_key().to_bytes());
        let msg = b"hello room log";
        let sig = signing_key.sign(msg);
        let keys = vec![key(&public_hex, Some(Timestamp { seconds: 2_000, nanos: 0 }))];
        let ok = verify(
            &keys, &public_hex, KeyScheme::Ed25519, msg, &sig.to_bytes(),
            Timestamp { seconds: 1_000, nanos: 0 },
        )
        .unwrap();
        assert!(ok, "a signature made before revocation must still verify");
    }

    #[test]
    fn tampered_message_against_a_known_key_does_not_verify() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_hex = hex::encode(signing_key.verifying_key().to_bytes());
        let sig = signing_key.sign(b"hello room log");

        let keys = vec![key(&public_hex, None)];
        let ok = verify(
            &keys, &public_hex, KeyScheme::Ed25519,
            b"a different message entirely", &sig.to_bytes(),
            Timestamp { seconds: 1_000, nanos: 0 },
        )
        .unwrap();
        assert!(!ok, "a signature over a different message must not verify");
    }

    #[test]
    fn claimed_scheme_mismatching_the_registered_key_does_not_verify() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_hex = hex::encode(signing_key.verifying_key().to_bytes());
        let msg = b"hello room log";
        let sig = signing_key.sign(msg);
        let keys = vec![key(&public_hex, None)];
        let ok = verify(
            &keys, &public_hex, KeyScheme::Secp256k1Schnorr, msg, &sig.to_bytes(),
            Timestamp { seconds: 1_000, nanos: 0 },
        )
        .unwrap();
        assert!(!ok, "a scheme mismatch must not verify, regardless of a valid signature");
    }

    #[test]
    fn unimplemented_scheme_matching_the_registered_key_errors_rather_than_silently_passing() {
        let public_hex = "aa".repeat(32);
        let keys = vec![AgentKeyRecord { scheme: KeyScheme::Secp256k1Schnorr, ..key(&public_hex, None) }];
        let err = verify(
            &keys, &public_hex, KeyScheme::Secp256k1Schnorr, b"msg", &[0u8; 64],
            Timestamp { seconds: 1_000, nanos: 0 },
        )
        .unwrap_err();
        assert!(err.to_string().contains("no implementation"));
    }

    #[test]
    fn malformed_hex_public_key_errors_rather_than_panicking() {
        let keys = vec![key("not-hex-at-all", None)];
        let err = verify(
            &keys, "not-hex-at-all", KeyScheme::Ed25519, b"msg", &[0u8; 64],
            Timestamp { seconds: 1_000, nanos: 0 },
        )
        .unwrap_err();
        assert!(err.to_string().contains("hex"));
    }

    #[test]
    fn wrong_length_signature_errors_rather_than_panicking() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_hex = hex::encode(signing_key.verifying_key().to_bytes());
        let keys = vec![key(&public_hex, None)];
        let err = verify(
            &keys, &public_hex, KeyScheme::Ed25519, b"msg", &[0u8; 10],
            Timestamp { seconds: 1_000, nanos: 0 },
        )
        .unwrap_err();
        assert!(err.to_string().contains("64 bytes"));
    }

    #[test]
    fn unknown_public_key_does_not_verify() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_hex = hex::encode(signing_key.verifying_key().to_bytes());
        let msg = b"hello room log";
        let sig = signing_key.sign(msg);
        let keys: Vec<AgentKeyRecord> = vec![];
        let ok = verify(
            &keys, &public_hex, KeyScheme::Ed25519, msg, &sig.to_bytes(),
            Timestamp { seconds: 1_000, nanos: 0 },
        )
        .unwrap();
        assert!(!ok, "a public key not present in the agent's key list must not verify");
    }

    #[test]
    fn a_message_timestamped_before_the_keys_own_creation_does_not_verify() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_hex = hex::encode(signing_key.verifying_key().to_bytes());
        let msg = b"hello room log";
        let sig = signing_key.sign(msg);
        let keys = vec![key_with_created_at(&public_hex, Timestamp { seconds: 2_000, nanos: 0 })];
        let ok = verify(
            &keys, &public_hex, KeyScheme::Ed25519, msg, &sig.to_bytes(),
            Timestamp { seconds: 1_000, nanos: 0 }, // before the key was even created
        )
        .unwrap();
        assert!(!ok, "a message claiming to predate the key's own creation must not verify");
    }

    #[test]
    fn a_message_timestamped_after_creation_and_before_revocation_still_verifies() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_hex = hex::encode(signing_key.verifying_key().to_bytes());
        let msg = b"hello room log";
        let sig = signing_key.sign(msg);
        let keys = vec![key_with_created_at(&public_hex, Timestamp { seconds: 500, nanos: 0 })];
        let ok = verify(
            &keys, &public_hex, KeyScheme::Ed25519, msg, &sig.to_bytes(),
            Timestamp { seconds: 1_000, nanos: 0 },
        )
        .unwrap();
        assert!(ok, "a message timestamped comfortably after creation and with no revocation must still verify");
    }

    #[test]
    fn a_key_with_no_created_at_set_is_unaffected_legacy_behavior() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_hex = hex::encode(signing_key.verifying_key().to_bytes());
        let msg = b"hello room log";
        let sig = signing_key.sign(msg);
        let keys = vec![key(&public_hex, None)];
        let ok = verify(
            &keys, &public_hex, KeyScheme::Ed25519, msg, &sig.to_bytes(),
            Timestamp { seconds: 1, nanos: 0 }, // long before any real key would exist -- must not matter
        )
        .unwrap();
        assert!(ok, "a legacy key with no created_at must be unaffected by this check");
    }
}

#[cfg(test)]
mod verify_delegated_tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    fn device_key(public_key_hex: &str) -> AgentKeyRecord {
        AgentKeyRecord {
            public_key: public_key_hex.into(),
            scheme: KeyScheme::Ed25519,
            is_device_key: true,
            created_at: Some(Timestamp { seconds: 0, nanos: 0 }),
            revoked_at: None,
        }
    }

    fn make_cert(
        device_signing: &SigningKey,
        session_signing: &SigningKey,
        agent_id: &str,
        not_before: i64,
        not_after: i64,
    ) -> crate::DelegationCert {
        let mut cert = crate::DelegationCert {
            agent_id: agent_id.into(),
            device_public_key: device_signing.verifying_key().to_bytes().to_vec(),
            session_public_key: session_signing.verifying_key().to_bytes().to_vec(),
            not_before_unix_seconds: not_before,
            not_after_unix_seconds: not_after,
            signature: Vec::new(),
        };
        let transcript = cert_transcript(&cert).unwrap();
        cert.signature = device_signing.sign(&transcript).to_bytes().to_vec();
        cert
    }

    #[test]
    fn a_genuine_delegated_message_within_the_certs_window_verifies() {
        let device_signing = SigningKey::generate(&mut OsRng);
        let session_signing = SigningKey::generate(&mut OsRng);
        let device_pub_hex = hex::encode(device_signing.verifying_key().to_bytes());
        let session_pub_hex = hex::encode(session_signing.verifying_key().to_bytes());
        let cert = make_cert(&device_signing, &session_signing, "agent-1", 500, 2_000);

        let msg = b"hello from a session key";
        let sig = session_signing.sign(msg).to_bytes().to_vec();

        let keys = vec![device_key(&device_pub_hex)];
        let ok = verify_delegated(
            &keys, "agent-1", &cert, &session_pub_hex, msg, &sig,
            Timestamp { seconds: 1_000, nanos: 0 },
        )
        .unwrap();
        assert!(ok);
    }

    #[test]
    fn a_cert_signed_by_a_non_device_key_is_rejected() {
        let attacker_signing = SigningKey::generate(&mut OsRng);
        let session_signing = SigningKey::generate(&mut OsRng);
        let session_pub_hex = hex::encode(session_signing.verifying_key().to_bytes());
        let cert = make_cert(&attacker_signing, &session_signing, "agent-1", 500, 2_000);
        let msg = b"forged delegation";
        let sig = session_signing.sign(msg).to_bytes().to_vec();

        let result = verify_delegated(
            &[], "agent-1", &cert, &session_pub_hex, msg, &sig,
            Timestamp { seconds: 1_000, nanos: 0 },
        )
        .unwrap();
        assert!(!result, "a cert whose device key isn't a known DEVICE key for this agent must not verify");
    }

    #[test]
    fn a_structurally_inverted_window_is_rejected_before_any_tolerance_is_applied() {
        let device_signing = SigningKey::generate(&mut OsRng);
        let session_signing = SigningKey::generate(&mut OsRng);
        let device_pub_hex = hex::encode(device_signing.verifying_key().to_bytes());
        let session_pub_hex = hex::encode(session_signing.verifying_key().to_bytes());
        let cert = make_cert(&device_signing, &session_signing, "agent-1", 100, 99);
        let msg = b"malformed window";
        let sig = session_signing.sign(msg).to_bytes().to_vec();
        let keys = vec![device_key(&device_pub_hex)];

        let result = verify_delegated(
            &keys, "agent-1", &cert, &session_pub_hex, msg, &sig,
            Timestamp { seconds: 100, nanos: 0 },
        )
        .unwrap();
        assert!(!result, "not_before >= not_after must be rejected structurally, not pass under widened tolerance");
    }

    #[test]
    fn a_revoked_device_key_invalidates_an_otherwise_valid_cert() {
        let device_signing = SigningKey::generate(&mut OsRng);
        let session_signing = SigningKey::generate(&mut OsRng);
        let device_pub_hex = hex::encode(device_signing.verifying_key().to_bytes());
        let session_pub_hex = hex::encode(session_signing.verifying_key().to_bytes());
        let cert = make_cert(&device_signing, &session_signing, "agent-1", 500, 2_000);
        let msg = b"session message after device revocation";
        let sig = session_signing.sign(msg).to_bytes().to_vec();

        let mut revoked = device_key(&device_pub_hex);
        revoked.revoked_at = Some(Timestamp { seconds: 600, nanos: 0 });
        let result = verify_delegated(
            &[revoked], "agent-1", &cert, &session_pub_hex, msg, &sig,
            Timestamp { seconds: 1_000, nanos: 0 }, // well after revocation, even with tolerance
        )
        .unwrap();
        assert!(!result, "a device key revoked before the message's receipt time must invalidate delegated messages, even mid-cert-window");
    }

    #[test]
    fn a_device_key_revoked_one_second_before_receipt_is_rejected_with_no_grace_period() {
        // Pins the fix: revoked_at must NOT get the same
        // CLOCK_SKEW_TOLERANCE_SECONDS grace period not_before/not_after
        // get. Before the fix, a revocation at T still authorized a
        // delegated message received at T+1s (well inside the 30s
        // tolerance window) -- this must now fail immediately.
        let device_signing = SigningKey::generate(&mut OsRng);
        let session_signing = SigningKey::generate(&mut OsRng);
        let device_pub_hex = hex::encode(device_signing.verifying_key().to_bytes());
        let session_pub_hex = hex::encode(session_signing.verifying_key().to_bytes());
        let cert = make_cert(&device_signing, &session_signing, "agent-1", 500, 2_000);
        let msg = b"session message one second after revocation";
        let sig = session_signing.sign(msg).to_bytes().to_vec();

        let mut revoked = device_key(&device_pub_hex);
        revoked.revoked_at = Some(Timestamp { seconds: 999, nanos: 0 });
        let result = verify_delegated(
            &[revoked], "agent-1", &cert, &session_pub_hex, msg, &sig,
            Timestamp { seconds: 1_000, nanos: 0 }, // 1s after revocation -- inside the old 30s tolerance
        )
        .unwrap();
        assert!(!result, "revocation must take effect immediately, with no clock-skew grace period, unlike not_before/not_after");
    }

    #[test]
    fn delegation_cert_transcript_matches_the_shared_session_delegation_transcript() {
        // cert_transcript is only an adapter over crate::transcripts::
        // session_delegation_transcript -- prove it doesn't drift from the
        // canonical byte layout that gait signs against.
        let device = [4u8; 32];
        let session = [5u8; 32];
        let cert = crate::DelegationCert {
            agent_id: "agent-a".into(),
            device_public_key: device.to_vec(),
            session_public_key: session.to_vec(),
            not_before_unix_seconds: 100,
            not_after_unix_seconds: 200,
            signature: Vec::new(),
        };
        let via_adapter = cert_transcript(&cert).unwrap();
        let direct = crate::transcripts::session_delegation_transcript("agent-a", &device, &session, 100, 200);
        assert_eq!(via_adapter, direct);
    }
}
