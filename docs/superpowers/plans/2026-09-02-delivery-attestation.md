# Delivery Attestation Types Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the shared `VerificationOutcome`/`AttestedMessage`/`DeliveryAttestation`
proto types and the `delivery_attestation_transcript` canonical byte encoding
that multimatrix (producer) and gait (consumer) both need, so a delivery
batch's authorship, content, and verification outcome can be signed once and
verified independently by more than one consumer.

**Architecture:** Pure additions to this crate's existing proto file and
`transcripts.rs` module — no new files, no new dependencies. Follows the
exact conventions already established by `KeyScheme`/`DelegationCert` and by
`session_delegation_transcript`.

**Tech Stack:** `prost`/`prost-build`, `pbjson`/`pbjson-build` (already
wired in `build.rs`), `ed25519-dalek` (already a dependency).

**Spec:** `concordat/2026-09-02-cross-agent-message-attribution-design.md`
§2, §2a (in the `concordium` monorepo this crate was extracted out of).

## Global Constraints

- Variable-length transcript fields are length-prefixed with a 4-byte
  **big-endian** `u32` (`with_len_prefixed`, already defined in
  `transcripts.rs` — reuse it, don't redefine it).
- Fixed-width scalars use `.to_be_bytes()`, matching every existing
  transcript function in this file.
- Every new transcript function gets its own NUL-terminated ASCII domain
  separator, never reusing another function's domain string.
- `identity-crypto` must never depend on multimatrix's or gait's own proto
  packages — `VerificationOutcome` is defined here even though multimatrix
  is its only producer today, exactly like `DelegationCert`.

---

### Task 1: `VerificationOutcome`, `AttestedMessage`, `DeliveryAttestation` proto types

**Files:**
- Modify: `proto/identitycrypto/v1/identity.proto`
- Modify: `src/lib.rs:53` (the `pub use` line)
- Test: `src/lib.rs`'s existing `proto_tests` module

**Interfaces:**
- Produces: `identitycrypto::v1::VerificationOutcome` (enum, discriminants
  `Unspecified = 0`, `DirectKey = 1`, `DelegatedKey = 2`),
  `identitycrypto::v1::AttestedMessage` (fields: `message_id: String`,
  `room_id: String`, `author_agent_id: String`, `body_text: String`,
  `verification_outcome: i32`, `delegation_cert: Option<DelegationCert>`),
  `identitycrypto::v1::DeliveryAttestation` (fields: `recipient_agent_id:
  String`, `key_id: String`, `batch_sequence: u64`, `attested_at: Option<
  prost_types::Timestamp>`, `messages: Vec<AttestedMessage>`, `signature:
  Vec<u8>`). All re-exported at the crate root: `identity_crypto::{
  AttestedMessage, DeliveryAttestation, VerificationOutcome}`.

- [ ] **Step 1: Write the failing test**

Add to `src/lib.rs`'s `proto_tests` module:

```rust
#[test]
fn verification_outcome_discriminants_are_pinned() {
    assert_eq!(VerificationOutcome::Unspecified as i32, 0);
    assert_eq!(VerificationOutcome::DirectKey as i32, 1);
    assert_eq!(VerificationOutcome::DelegatedKey as i32, 2);
}

#[test]
fn delivery_attestation_round_trips_through_protobuf_bytes() {
    use prost::Message;
    let attestation = DeliveryAttestation {
        recipient_agent_id: "agent-1".into(),
        key_id: "mm-key-2026-09".into(),
        batch_sequence: 42,
        attested_at: Some(prost_types::Timestamp { seconds: 1_700_000_000, nanos: 0 }),
        messages: vec![AttestedMessage {
            message_id: "msg-1".into(),
            room_id: "room-general".into(),
            author_agent_id: "agent-2".into(),
            body_text: "hello".into(),
            verification_outcome: VerificationOutcome::DirectKey as i32,
            delegation_cert: None,
        }],
        signature: vec![9u8; 64],
    };
    let bytes = attestation.encode_to_vec();
    let decoded = DeliveryAttestation::decode(bytes.as_slice()).unwrap();
    assert_eq!(attestation, decoded);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p identity-crypto verification_outcome_discriminants_are_pinned`
Expected: FAIL to compile — `VerificationOutcome` does not exist yet.

- [ ] **Step 3: Add the proto types**

Append to `proto/identitycrypto/v1/identity.proto` (after the existing
`DelegationCert` message):

```proto
enum VerificationOutcome {
  VERIFICATION_OUTCOME_UNSPECIFIED = 0;
  VERIFICATION_OUTCOME_DIRECT_KEY = 1;
  VERIFICATION_OUTCOME_DELEGATED_KEY = 2;
}

// One message inside a signed delivery batch. `body_text` is authoritative
// here -- the recipient never separately reconstructs it from anything
// else, so there is nothing to reconcile a hash against. See
// concordat/2026-09-02-cross-agent-message-attribution-design.md.
message AttestedMessage {
  string message_id = 1;
  string room_id = 2;
  string author_agent_id = 3;
  string body_text = 4;
  VerificationOutcome verification_outcome = 5;
  DelegationCert delegation_cert = 6;
}

// Signed once per delivery batch by the delivering service's own key (not
// an AgentKey -- a service identity). See
// identity_crypto::transcripts::delivery_attestation_transcript for the
// exact canonical byte layout `signature` covers.
message DeliveryAttestation {
  string recipient_agent_id = 1;
  string key_id = 2;
  uint64 batch_sequence = 3;
  google.protobuf.Timestamp attested_at = 4;
  repeated AttestedMessage messages = 5;
  bytes signature = 6;
}
```

This file has no existing `import "google/protobuf/timestamp.proto";` line
— add it at the top, after `package identitycrypto.v1;`, since
`DeliveryAttestation.attested_at` needs it:

```proto
import "google/protobuf/timestamp.proto";
```

Update `src/lib.rs:53`:

```rust
pub use proto::identitycrypto::v1::{
    AttestedMessage, DelegationCert, DeliveryAttestation, KeyScheme, VerificationOutcome,
};
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p identity-crypto`
Expected: PASS, including the two new tests and every pre-existing test
(confirms the new `import` and messages didn't break `KeyScheme`/
`DelegationCert` codegen).

- [ ] **Step 5: Commit**

```bash
git add proto/identitycrypto/v1/identity.proto src/lib.rs
git commit -m "feat: add VerificationOutcome/AttestedMessage/DeliveryAttestation proto types"
```

---

### Task 2: `delivery_attestation_transcript` canonical encoding

**Files:**
- Modify: `src/transcripts.rs`

**Interfaces:**
- Consumes: `AttestedMessage`, `DeliveryAttestation` (Task 1).
- Produces: `identity_crypto::transcripts::delivery_attestation_transcript(
  attestation: &DeliveryAttestation) -> Vec<u8>` — callers sign/verify this
  return value directly with `ed25519-dalek`/`identity_crypto::verify_ed25519`
  (no new sign/verify wrapper needed; this crate only ever exposed
  verification, not signing, and that stays true here).

- [ ] **Step 1: Write the failing test**

Add to `src/transcripts.rs`'s `tests` module:

```rust
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
        recipient_agent_id: "agent-1".into(),
        key_id: "mm-key-2026-09".into(),
        batch_sequence: 1,
        attested_at: Some(prost_types::Timestamp { seconds: 100, nanos: 0 }),
        messages,
        signature: Vec::new(), // never included in its own transcript
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
    b.recipient_agent_id = "agent-99".into();
    assert_ne!(delivery_attestation_transcript(&a), delivery_attestation_transcript(&b));
    a.batch_sequence = 2;
    let c = sample_attestation(vec![sample_attested_message("m1")]);
    assert_ne!(delivery_attestation_transcript(&a), delivery_attestation_transcript(&c));
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p identity-crypto delivery_attestation_transcript`
Expected: FAIL to compile — `delivery_attestation_transcript` does not
exist yet.

- [ ] **Step 3: Implement the transcript function**

Append to `src/transcripts.rs`, before the `#[cfg(test)]` module:

```rust
/// Canonical byte layout for `DeliveryAttestation.signature`. See
/// concordat/2026-09-02-cross-agent-message-attribution-design.md §2a.
/// `body_text` travels inside this transcript directly -- there is no
/// separate hash to reconcile against a differently-transmitted copy.
pub fn delivery_attestation_transcript(attestation: &crate::DeliveryAttestation) -> Vec<u8> {
    let mut buf = b"identitycrypto.delivery-attestation.v1\0".to_vec();
    with_len_prefixed(&mut buf, attestation.recipient_agent_id.as_bytes());
    with_len_prefixed(&mut buf, attestation.key_id.as_bytes());
    buf.extend_from_slice(&attestation.batch_sequence.to_be_bytes());
    let attested_at_secs = attestation.attested_at.as_ref().map(|t| t.seconds).unwrap_or(0);
    buf.extend_from_slice(&attested_at_secs.to_be_bytes());
    for message in &attestation.messages {
        with_len_prefixed(&mut buf, message.message_id.as_bytes());
        with_len_prefixed(&mut buf, message.room_id.as_bytes());
        with_len_prefixed(&mut buf, message.author_agent_id.as_bytes());
        with_len_prefixed(&mut buf, message.body_text.as_bytes());
        buf.push(message.verification_outcome as u8);
        match &message.delegation_cert {
            None => buf.push(0x00),
            Some(cert) => {
                buf.push(0x01);
                with_len_prefixed(&mut buf, cert.agent_id.as_bytes());
                buf.extend_from_slice(&cert.device_public_key);
                buf.extend_from_slice(&cert.session_public_key);
                buf.extend_from_slice(&cert.not_before_unix_seconds.to_be_bytes());
                buf.extend_from_slice(&cert.not_after_unix_seconds.to_be_bytes());
            }
        }
    }
    buf
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p identity-crypto`
Expected: PASS, all tests including the five new ones.

- [ ] **Step 5: Commit**

```bash
git add src/transcripts.rs
git commit -m "feat: add delivery_attestation_transcript canonical encoding"
```

---

## Coordination note for whoever executes this plan

Once both tasks are committed, **push to `origin/main`** (a local-only
commit silently blocks every downstream pinned-git-rev dependency — this
has happened twice already in this project's history, for grorg and gait).
Report the resulting commit SHA back so multimatrix's and gait's plans
(`2026-09-02-cross-agent-attestation-multimatrix.md`,
`2026-09-02-cross-agent-attestation-gait.md`) can bump their
`identity-crypto` git-rev pin to it.
