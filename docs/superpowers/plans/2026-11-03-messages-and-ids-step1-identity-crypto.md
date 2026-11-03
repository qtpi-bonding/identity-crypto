# Messages and ids, step 1: identity-crypto 0.9.0 and identity-keyfile 0.9.0 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give identity-crypto the `Message`/`Delivery` wire types and their transcripts, the daemon standing grant with a co-signed `DaemonHosted` chain, a resolver-free check of a carried message, the check of a deliverer's root→device delegation, and give identity-keyfile a layout with the root outside the device folder.

**Architecture:** Wire changes go in `proto/identitycrypto/v1/identity.proto`. `DeliveryAttestation` and `AttestedMessage` are deleted outright (no reserved shims beyond proto field-number hygiene inside surviving messages). A new `SignerChain` arm `DaemonHosted` carries both device delegations and a second signature by the agent device; `verify_chain` accepts it under the registry rules below. identity-keyfile gains `IdentityLayout` and `_at` variants of every directory entry point; the existing `dir` functions become `IdentityLayout::single(dir)` wrappers with unchanged behaviour.

**Tech Stack:** Rust 2021, prost 0.13 + pbjson 0.7, rust_jwk_duo (P-256), Python 3 + `cryptography` for independent vectors (`vectors/gen.py`).

**Spec:** `/Users/aicoder/Documents/systematic-action/concordium/docs/superpowers/specs/2026-11-03-messages-and-ids-design.md` (step 1 of "Order"). The companion plan `/Users/aicoder/Documents/my-libs/message-attestation/docs/superpowers/plans/2026-11-03-messages-and-ids-step1-message-attestation.md` consumes the names defined here.

## Global Constraints

- Every cargo command goes through `/Users/aicoder/Documents/systematic-action/scripts/cargo-slot` (written `$SLOT` below). Full gates use `$SLOT --all`. Never run bare `cargo build`/`cargo test`.
- No backward compatibility: deleted types, functions, tags, tests, vector cases and README/metadata text go in the same commit that deletes the code. Nothing deprecated is left behind.
- Version: both crates `0.8.0` → `0.9.0` (breaking). identity-keyfile's path dependency becomes `version = "0.9.0"`.
- Commit messages: no `Claude-Session` trailer. End every message with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- Never read secrets, `.env` files or private key files; test keys come from `identity_crypto::testkit` / `identity_keyfile::generate()`.
- Vectors: `vectors/gen.py` is independent of the Rust code. A mismatch is decided against this plan's layouts, never by regenerating to match Rust. Run it with `cd vectors && .venv/bin/python gen.py` (create `.venv` from `requirements.txt` if missing).
- Transcript tags: `identitycrypto.hosted-session.v1`, `identitycrypto.delivery.v1`. `identitycrypto.delivery-attestation.v1` is deleted.
- Message ids, room ids and the 64-target cap are message-attestation's rules, not transcript rules. Transcripts only reject what they cannot encode (missing, empty where noted, bad key, mismatched counts).

## Review Focus

1. **An unregistered agent whose root was rotated** (the common structmux case: no owner signature per agent). Expected: `DaemonHosted` accepts it when the carried `agent_rotations` chain ends at the delegation's `signing_root`, and refuses a chain that does not (Task 4, `unregistered_rotated_agent_needs_its_rotations`).
2. **A daemon with the grant naming an agent that lists other hosts.** Expected: explicit `allowed_hosts` wins both ways: listed daemon accepted without the grant, unlisted daemon refused despite it (Task 4, `explicit_allowed_hosts_win_over_the_grant`).
3. **A `DaemonHosted` cert whose agent co-signature is missing, empty, or by the daemon device.** Expected: refused; the daemon alone can never mint a hosted session (Task 4, `co_signature_is_required_and_must_be_the_agent_device`).
4. **Redelivery after the author's 24 h session expired.** Expected: `verify_carried_message` checks no clock at all and still accepts an intact message (Task 5, `expired_session_still_verifies_when_carried`).
5. **Split layout with the root folder placed inside the device folder, or two `create_or_load_at` racing on a fresh split layout.** Expected: the first is refused at construction; the race yields one principal (Task 6, `split_refuses_root_inside_device_dir`, `split_create_or_load_races_to_one_identity`).

---

## File Structure

| File | Responsibility | Change |
|---|---|---|
| `proto/identitycrypto/v1/identity.proto` | wire types | add `Target`, `Targets`, `Message`, `Delivery`, `DaemonHosted`, `RegistryEntry.hosts_held_agents`; delete `AttestedMessage`, `DeliveryAttestation` |
| `src/transcripts.rs` | canonical bytes | add `hosted_session_transcript`, `delivery_transcript`, two tags; `DaemonHosted` arm in `signed_message_transcript`; delete `delivery_attestation_transcript` and its tag |
| `src/session.rs` | minting | add `mint_hosted_session`, `HostingDaemon`, `HostedAgent`, `HostedSessionCredential` |
| `src/registry.rs` | registry rules | `hosts_held_agents` (DAEMON only); allow `allowed_hosts` on self-rooted AGENT |
| `src/verify.rs` | chain + message checks | `DaemonHosted` arm of `verify_chain`; `verify_carried_message`, `CarriedMessage`, `verify_root_device_delegation`; trusted-devices verifier refuses the new arm |
| `src/testkit.rs` | fixtures | `hosted_chain`, `Fleet.daemon_grant` |
| `src/lib.rs` | exports, proto tests | new re-exports; proto round-trips |
| `tests/json.rs`, `tests/binding.rs`, `tests/vectors.rs` | integration tests | rewritten for `Delivery`; new transcripts |
| `vectors/gen.py` (+ regenerated `transcripts.json`, `messages.json`, `signatures.json`) | independent vectors | new functions and cases; delivery_attestation cases deleted |
| `identity-keyfile/src/layout.rs` (new) | `IdentityLayout` | split/single layout and its locks |
| `identity-keyfile/src/keys.rs` | entry points | `_at` variants; `dir` functions delegate |
| `identity-keyfile/tests/split.rs` (new) | split layout tests | |
| `README.md`, `identity-keyfile/README.md`, `metadata/metadata.yaml`, both `Cargo.toml` | docs, versions | |

---

### Task 1: Wire types (and deletion of the attestation types)

**Files:**
- Modify: `proto/identitycrypto/v1/identity.proto:79-104` (SignerChain, add DaemonHosted), `:140-163` (delete), `:189-204` (RegistryEntry)
- Modify: `src/transcripts.rs` (delete `delivery_attestation_transcript`, `DELIVERY_ATTESTATION_TAG`, its unit tests and fixtures `attested()`, `attestation()`; add the `DaemonHosted` arm to `signed_message_transcript`)
- Modify: `src/verify.rs` (`verify_chain` and `verify_signed_message_trusted_devices` arms)
- Modify: `src/lib.rs:171` (proto round-trip test), `tests/json.rs` (rewrite), `tests/binding.rs:249-275` (delete `delivery_attestation_binds_every_field`), `tests/vectors.rs:135-158` (delete arm)
- Modify: `vectors/gen.py` (delete `delivery_attestation` function, its `TAGS`/`FUNCTIONS` entries and the 13 `delivery_attestation …` cases), regenerate vectors

**Interfaces:**
- Produces (proto, field numbers fixed):

```proto
message SignerChain {
  oneof chain {
    SelfRooted self_rooted = 1;
    HostVouched host_vouched = 2;
    DaemonHosted daemon_hosted = 3;
  }
}
message DaemonHosted {                     // an agent with its own keys, run by a daemon that holds them
  KeyDelegation host_device = 1;           // daemon root -> daemon device
  KeyDelegation agent_device = 2;          // agent root -> agent device
  DelegationCert session = 3;              // daemon device -> session, mode 1, principal_genesis = the agent
  bytes agent_signature = 4;               // agent device over hosted-session.v1
  repeated RootRotation agent_rotations = 5;  // agent genesis -> ... -> agent_device.signing_root; read only when the agent has no registry entry
}

message Target {
  oneof target {
    string room_id = 1;
    string recipient_id = 2;               // canonical p256:<hex>
  }
}
message Targets { repeated Target targets = 1; }

// The body of an author's SignedMessage. The author is the SignedMessage
// signer, never a field.
message Message {
  string message_id = 1;
  repeated Target to = 2;
  optional string reply_to = 3;
  repeated string references = 4;
  repeated string mentions = 5;            // canonical p256:<hex> ids
  google.protobuf.Timestamp authored_at = 6;
  string body = 7;
}

// Per recipient, signed by the deliverer. messages are carried verbatim;
// via[i] belongs to messages[i].
message Delivery {
  string delivery_id = 1;
  string recipient_id = 2;
  repeated PublicKey recipient_devices = 3;
  uint64 sequence = 4;                     // per (recipient_id, signer principal)
  google.protobuf.Timestamp attested_at = 5;
  repeated SignedMessage messages = 6;
  repeated Targets via = 7;
  KeyDelegation signer_device = 8;         // the deliverer's root -> device delegation; the deliverer is its principal_genesis
  bytes signature = 9;                     // the signer_device's key over delivery.v1
}
```

  `RegistryEntry` gains `bool hosts_held_agents = 12;` (comment: `DAEMON: may host any agent whose device key it holds (DaemonHosted). Grant-only.`). Rewrite the comments at `:194` and `:201` to: `// Self-rooted (HUMAN, DAEMON, SERVICE, and an AGENT with keys)` and `// AGENT: DAEMON principal ids, or "*". Required for an AGENT without keys; for an AGENT with keys it overrides any daemon's hosts_held_agents.` Update the file's header comment (`…and the delivery attestation`) to `…and the message delivery`.
- Produces (Rust): `pb::Message`, `pb::Delivery`, `pb::Target` (oneof enum `pb::target::Target::{RoomId, RecipientId}`), `pb::Targets`, `pb::DaemonHosted`, `pb::signer_chain::Chain::DaemonHosted`.
- `verify_chain` gets a temporary `Chain::DaemonHosted(_) => Err(Error::ChainMismatch("signer.daemon_hosted"))`; Task 4 replaces it. `verify_signed_message_trusted_devices` gets the same arm permanently (it accepts mode 0 only).
- `signed_message_transcript` arm paths: `["signer.daemon_hosted.session", "signer.daemon_hosted.session.principal_genesis", "signer.daemon_hosted.session.session"]`.

- [ ] **Step 1: Write the failing tests**

In `src/lib.rs` `proto_tests::every_message_round_trips_through_protobuf`, replace the `DeliveryAttestation` line with round-trips of:

```rust
let target = |r: bool| pb::Target { target: Some(if r { pb::target::Target::RoomId("design".into()) } else { pb::target::Target::RecipientId("p256:04".into()) }) };
let message = pb::Message {
    message_id: "m-1".into(), to: vec![target(true), target(false)], reply_to: Some("m-0".into()),
    references: vec!["m-0".into()], mentions: vec!["p256:04".into()],
    authored_at: Some(Timestamp { seconds: 1, nanos: 2 }), body: "hi".into(),
};
round_trip(message);
let hosted = pb::DaemonHosted { host_device: Some(delegation()), agent_device: Some(delegation()), session: Some(cert()), agent_signature: vec![4; 64], agent_rotations: vec![] };
round_trip(pb::SignerChain { chain: Some(pb::signer_chain::Chain::DaemonHosted(hosted)) });
round_trip(pb::Delivery {
    delivery_id: "d-1".into(), recipient_id: "p256:04".into(), recipient_devices: vec![key(5)], sequence: u64::MAX,
    attested_at: Some(Timestamp { seconds: 1, nanos: 2 }), messages: vec![pb::SignedMessage::default()],
    via: vec![pb::Targets { targets: vec![target(true)] }], signer_device: Some(delegation()), signature: vec![1; 64],
});
```

and add `hosts_held_agents: true` to the `RegistryEntry` literal in that test. Rewrite `tests/json.rs` around `pb::Delivery` (header doc: "proto3-JSON for `Delivery`: the carried form in `_meta`"), keeping each existing test's assertion style and replacing `delivery_attestation_transcript` with nothing (JSON tests assert JSON only):
- `delivery_json_round_trip`: a full `Delivery` → `serde_json::to_value` → back equals the original.
- `delivery_json_field_names_are_camel_case`: keys of the object are exactly `["attestedAt","deliveryId","messages","recipientDevices","recipientId","sequence","signature","signerDevice","via"]` (sorted); `sequence` is the string `"18446744073709551615"` for `u64::MAX`; `attestedAt` ends with `Z`.
- `message_target_json_uses_the_oneof_field_name`: `serde_json::to_value(target(true))` is `{"roomId":"design"}`.
- `unknown_field_is_rejected` and `duplicate_field_is_rejected`: as the existing tests, on `pb::Delivery`.

- [ ] **Step 2: Run them to verify they fail**

Run: `$SLOT cargo test -p identity-crypto --lib proto_tests` and `$SLOT cargo test -p identity-crypto --test json`
Expected: compile errors: `pb::Message`, `pb::Delivery`, `pb::Target`, `pb::DaemonHosted` not found.

- [ ] **Step 3: Implement the proto changes and the deletions listed under Files**

Edit the proto as in Interfaces. Delete `delivery_attestation_transcript`, `DELIVERY_ATTESTATION_TAG` (and from `ALL_TAGS`, now length 12 until Task 2), the transcript unit tests `delivery_attestation_*`, `message_without_*`, `message_missing_both_reports_author_first`, and the `attested()`/`attestation()` fixtures. Delete the binding test and the vectors arm. In `gen.py`, delete `delivery_attestation`, its `TAGS` and `FUNCTIONS` entries, the `message()`/`da` helpers and the 13 cases. Add the two `Chain::DaemonHosted` arms in `src/verify.rs` and the transcript arm in `signed_message_transcript`.

- [ ] **Step 4: Regenerate vectors and set the count**

Run: `cd /Users/aicoder/Documents/my-libs/identity-crypto/vectors && .venv/bin/python gen.py && git diff --stat .`
Expected: `transcripts.json` and `signatures.json` shrink; `transcripts.json` has 87 cases. Change `tests/vectors.rs` `assert_eq!(checked, 100, …)` to `87`.

- [ ] **Step 5: Run the crate's tests**

Run: `$SLOT cargo test -p identity-crypto`
Expected: PASS (all targets, including `vectors`, `json`, `binding`).

- [ ] **Step 6: Commit**

```bash
git add proto src tests vectors
git commit -m "identity-crypto: Message, Delivery and DaemonHosted wire types; delete DeliveryAttestation

DeliveryAttestation, AttestedMessage, delivery_attestation_transcript and
the delivery-attestation.v1 tag are deleted, with their tests and the 13
generator cases. Message and Delivery replace them (messages-and-ids spec).
verify_chain refuses DaemonHosted until the next commits add its rules.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2: `hosted-session.v1` and `delivery.v1` transcripts, with independent vectors

**Files:**
- Modify: `src/transcripts.rs` (tags, two functions, layout tests)
- Modify: `tests/binding.rs` (two binding tests), `tests/vectors.rs` (two arms, a `daemon_hosted` chain arm, messages.json hosted case)
- Modify: `vectors/gen.py` (two functions, `signed_message` daemon_hosted cases, messages.json hosted case); regenerate

**Interfaces:**
- Consumes: Task 1 proto types; existing `encode_cert_body`, `signed_message_transcript`.
- Produces:

```rust
pub const HOSTED_SESSION_TAG: &str = "identitycrypto.hosted-session.v1";
pub const DELIVERY_TAG: &str = "identitycrypto.delivery.v1";
// ALL_TAGS: [&str; 14] (12 after Task 1, plus these two).

/// `hosted-session.v1 := tag ‖ CERT body (as session-delegation.v1, without its tag)`.
/// The cert must be mode 1; the agent device signs these bytes.
pub fn hosted_session_transcript(c: &pb::DelegationCert) -> Result<Vec<u8>>;

/// ```text
/// delivery.v1 := tag ‖ PRINCIPAL(signer_device.principal_genesis) ‖ KEY(signer_device.delegated)
///                ‖ len(delivery_id) ‖ len(recipient_id)
///                ‖ u32 count ‖ KEY(recipient_device)…
///                ‖ sequence u64 ‖ attested_at.seconds i64 ‖ attested_at.nanos i32
///                ‖ u32 count ‖ ENTRY…
/// ENTRY  := len(signed-message.v1 bytes of messages[i]) ‖ len(messages[i].signature) ‖ TARGETS(via[i])
/// TARGETS:= u32 count ‖ TARGET…
/// TARGET := kind u8 (1 room_id, 2 recipient_id) ‖ len(value)
/// ```
pub fn delivery_transcript(d: &pb::Delivery) -> Result<Vec<u8>>;
```

  Validation, in this order, with these errors: `signer_device` absent → `MissingField("signer_device")`; its `principal_genesis` / `delegated` absent → `MissingField("signer_device.principal_genesis")` / `MissingField("signer_device.delegated")` (bad keys: their `PublicKey::try_from` error); `delivery_id` empty → `InvalidField { field: "delivery_id", reason: "empty" }`; `recipient_id` empty → `InvalidField { field: "recipient_id", reason: "empty" }`; each recipient device via `PublicKey::try_from` (its error); `attested_at` absent → `MissingField("attested_at")`; nanos outside `0..=999_999_999` → `InvalidField { field: "attested_at.nanos", reason: "out of range" }`; `via.len() != messages.len()` → `InvalidField { field: "via", reason: "one entry per message" }`; then per message: `signed_message_transcript` errors pass through; a `Target` with no oneof set → `MissingField("via.target")`; an empty target value → `InvalidField { field: "via.target", reason: "empty" }`. The delegation's own signature and window are not transcript concerns; `verify_root_device_delegation` (Task 5) checks them.

  Decision recorded here: the deliverer signs each message's `signed-message.v1` bytes and its signature, not the signer-chain bytes. That transcript already fixes the author's genesis, session key, audience and body, which is what the deliverer vouches for; the chain is checked by the deliverer against its directory and checked for integrity by the recipient (Task 5).

- [ ] **Step 1: Write the failing layout tests in `src/transcripts.rs`**

- `hosted_session_layout`: for `cert1()`, `hosted_session_transcript(&c)` equals `b"identitycrypto.hosted-session.v1\0"` followed by `session_delegation_transcript(&c)[SESSION_DELEGATION_TAG.len() + 1..]`.
- `hosted_session_requires_mode_1`: `hosted_session_transcript(&cert0())` is `Err(InvalidField { field: "mode", reason: "must be 1 for a hosted session" })`.
- `delivery_empty_layout`: a `Delivery` with `signer_device` = `delegation(Device)` (genesis `G`, delegated `D`), `delivery_id "d"`, `recipient_id "r"`, no devices, `sequence 1`, `attested_at {2, 3}`, no messages, no via gives exactly `tag ‖ key_bytes(G) ‖ key_bytes(D) ‖ 00000001 'd' ‖ 00000001 'r' ‖ 00000000 ‖ 0000000000000001 ‖ 0000000000000002 ‖ 00000003 ‖ 00000000`.
- `delivery_entry_layout`: one message (`message()` fixture) with via `[room "a", recipient "p256:04"]`: the bytes after the message count are `var(signed_message_transcript(&m)) ‖ var(&m.signature) ‖ 00000002 ‖ 01 ‖ 00000001 'a' ‖ 02 ‖ 00000007 "p256:04"`.
- `delivery_checks`: each validation error above, asserted with `assert_eq!` on the exact `Error`.

Add to `tests/binding.rs`: `hosted_session_binds_every_field` (mutations as the session-delegation binding test, mode-1 cert) and `delivery_binds_every_field` (mutations: `signer_device.principal_genesis`, `signer_device.delegated`, `delivery_id`, `recipient_id`, `recipient_devices` push, `sequence`, `attested_at.seconds`, `attested_at.nanos`, `messages[0].body`, `messages[0].signature`, `via[0]` room→recipient with same text, `via[0]` push). Plus `delivery_entry_boundaries_do_not_collide`: via `["ab"]` + `["c"]` vs `["a"]` + `["bc"]` over two messages produce different bytes.

- [ ] **Step 2: Run to verify they fail**

Run: `$SLOT cargo test -p identity-crypto --lib transcripts` and `$SLOT cargo test -p identity-crypto --test binding`
Expected: FAIL to compile (`hosted_session_transcript`, `delivery_transcript` not found).

- [ ] **Step 3: Implement the two functions and tags in `src/transcripts.rs`**

`hosted_session_transcript` checks `c.mode == 1` first, then reuses `encode_cert_body`. `delivery_transcript` reuses `signed_message_transcript` for each entry.

- [ ] **Step 4: Add the independent vectors in `vectors/gen.py`**

Add `"hosted_session"` and `"delivery"` to `TAGS` and `FUNCTIONS`. `hosted_session(i)` raises `VectorError("InvalidField", "mode")` unless mode is 1, else `tag ‖ cert_body(i)`. `delivery(i)` mirrors the layout and error order above, calling the existing `signed_message` per entry. Extend `signed_message` callers: the chain name is already interpolated into the paths, so `"daemon_hosted"` needs no new code. Cases (exact names):

- `hosted_session`, `hosted_session non-ascii subject` (subject `"sübject/ñ"`), `hosted_session mode 0` (InvalidField mode), `hosted_session without subject` (MissingField subject), `hosted_session session is device` (NotDistinct "device, session"): 5.
- `signed_message daemon-hosted` (`with_(sm, chain="daemon_hosted", session=CERT1)`), `signed_message daemon-hosted missing session` (session None → MissingField `signer.daemon_hosted.session`): 2.
- With `dl = {"signer_device": {"principal_genesis": K(20), "delegated": K(21)}, "delivery_id": "d-1", "recipient_id": "p256:" + raw_pub(7).hex(), "recipient_devices": [K(15), K(16)], "sequence": "7", "attested_at": {"seconds": "1700000000", "nanos": "123456789"}, "messages": [{"message": sm, "signature": "ab"*64}], "via": [[{"room_id": "design"}]]}`: `delivery one message`, `delivery room and recipient via, two messages`, `delivery empty messages` (messages and via `[]`), `delivery max sequence and min seconds` (`U64_MAX`, `I64_MIN`, nanos 999999999), `delivery no timestamp` (MissingField attested_at), `delivery nanos too big` (InvalidField attested_at.nanos), `delivery empty delivery id` (InvalidField delivery_id), `delivery empty recipient id` (InvalidField recipient_id), `delivery via count differs` (InvalidField via), `delivery target unset` (`[{}]` → MissingField via.target), `delivery off-curve recipient device` (InvalidKey, field None), `delivery message missing session` (MissingField `signer.self_rooted.session`), `delivery signer device missing` (`signer_device: None` → MissingField signer_device): 13. (gen.py only encodes the two keys of `signer_device`; the Rust arm fills the other delegation fields with defaults.)

`messages()` gains a third case `"daemon-hosted message"`: daemon device scalar 33 signs a mode-1 cert (principal = agent genesis scalar 34, host = daemon genesis scalar 35, device 33, session 32, subject `"3b6a27bcceb6a42d/i5"`); agent device scalar 36 signs `hosted_session(cert)`; the session signs the `daemon_hosted` signed-message transcript. Extra fields: `"chain": "daemon_hosted"`, `"agent_device_key"`, `"hosted_transcript_hex"`, `"agent_signature_hex"`.

- [ ] **Step 5: Regenerate and wire the Rust vector tests**

Run: `cd vectors && .venv/bin/python gen.py`
In `tests/vectors.rs`: add `"hosted_session"` and `"delivery"` arms to `run` (build `pb::Delivery` from the JSON; a via target object with neither key becomes `pb::Target { target: None }`), add `Some("daemon_hosted")` to the chain match (`pb::DaemonHosted { session, ..Default::default() }`), set the count to `107`, and in `message_vector` build the chain from `case["message"]["chain"]` (default `self_rooted`); for `daemon_hosted` also assert `hosted_session_transcript(&cert)` hex equals `hosted_transcript_hex` and `verify_p256(agent_device, …, agent_signature)` is `Ok`. Count in `message_vector` becomes `3`.

- [ ] **Step 6: Run**

Run: `$SLOT cargo test -p identity-crypto`
Expected: PASS; `transcripts_match_the_independent_generator` checks 107 cases, `message_vector` 3.

- [ ] **Step 7: Commit** (`identity-crypto: hosted-session.v1 and delivery.v1 transcripts with independent vectors`, body names the 20 new cases and the count change 87 → 107, then the Co-Authored-By line).

---

### Task 3: Minting a hosted session

**Files:**
- Modify: `src/session.rs`, `src/lib.rs` (re-exports), `src/testkit.rs`

**Interfaces:**
- Consumes: `hosted_session_transcript` (Task 2), `check_session_span`, `sign`.
- Produces:

```rust
/// The daemon side of a hosted session: its device key and that device's delegation from the daemon root.
pub struct HostingDaemon<'a> { pub device: &'a jwk_duo::SigningKeyPair, pub device_delegation: &'a pb::KeyDelegation }
/// The agent side: its device key, that device's delegation from the agent root, and the agent's root rotations (empty if never rotated).
pub struct HostedAgent<'a> { pub device: &'a jwk_duo::SigningKeyPair, pub device_delegation: &'a pb::KeyDelegation, pub rotations: &'a [pb::RootRotation] }

pub fn mint_hosted_session(daemon: HostingDaemon<'_>, agent: HostedAgent<'_>, subject: &str, not_before_unix: i64, not_after_unix: i64) -> Result<HostedSessionCredential>;

/// Not Clone; Debug shows only the public half.
pub struct HostedSessionCredential { /* chain: pb::DaemonHosted, key */ }
impl HostedSessionCredential {
    pub fn cert(&self) -> &pb::DelegationCert;
    pub fn session_public_key(&self) -> PublicKey;
    pub fn not_after_unix(&self) -> i64;
    /// Builds a DaemonHosted SignedMessage and signs signed-message.v1 with the session key.
    #[allow(clippy::too_many_arguments)]
    pub fn sign_message(&self, audience: &str, nonce: [u8; 16], issued_at_unix: i64, in_reply_to_nonce: Option<[u8; 16]>, body_type: &str, body: &[u8]) -> Result<pb::SignedMessage>;
}
```

  Re-export `mint_hosted_session, HostedAgent, HostedSessionCredential, HostingDaemon` from the crate root. The cert: mode 1, `principal_genesis` = `agent.device_delegation.principal_genesis`, `host_genesis` = `daemon.device_delegation.principal_genesis`, `device` = daemon device, `subject` = `subject`, signed by the daemon device over `session-delegation.v1`; `agent_signature` = agent device over `hosted-session.v1`; `agent_rotations` = `agent.rotations`.

  Refusals (before any signing): span via `check_session_span`; `daemon.device_delegation.delegated` ≠ daemon device public → `ChainMismatch("host_device.delegated")`; same for the agent → `ChainMismatch("agent_device.delegated")`; either delegation's purpose not DEVICE → `ChainMismatch("host_device.purpose")` / `ChainMismatch("agent_device.purpose")`; subject not starting with `"<daemon short id>/"` → `InvalidField { field: "subject", reason: "must start with the host daemon's short id and /" }`.

- Produces (testkit): `pub fn hosted_chain(daemon: &Principal, agent: &Principal, subject: &str, nb: i64, na: i64) -> (Signer, pb::SignerChain)`: delegates fresh devices for both with window `(T0, T0 + 30 * DAY)`, carries `agent.rotations`, signs as above; built on `mint_hosted_session` is not possible because it returns no `Signer`, so it composes `session_cert` + `Signer::sign(&hosted_session_transcript(..))`. Also `Fleet` gains `pub daemon_grant: bool` (default `false`), written into the daemon entry's `hosts_held_agents` by `Fleet::registry`.

- [ ] **Step 1: Write the failing tests (in `src/session.rs` tests)**

- `hosted_cert_is_signed_by_the_daemon_device_and_co_signed_by_the_agent_device`: `verify_p256(daemon_device_pub, &session_delegation_transcript(cert), &cert.signature)` is Ok; `verify_p256(agent_device_pub, &hosted_session_transcript(cert), &agent_signature)` is Ok; `cert.mode == 1`, `host_genesis` and `principal_genesis` are the two genesis keys.
- `hosted_message_verifies_under_the_session_key`: `sign_message(..)` output's chain is `DaemonHosted` with both delegations, and `verify_p256(&cred.session_public_key(), &signed_message_transcript(&m), &m.signature)` is Ok.
- `mint_hosted_session_refusals`: each refusal above returns exactly the listed `Error`.
- doc test on `HostedSessionCredential`: ```` ```compile_fail ```` asserting it is not `Clone`, as for `SessionCredential`.

- [ ] **Step 2: Run to verify they fail**

Run: `$SLOT cargo test -p identity-crypto --lib session`
Expected: FAIL to compile (`mint_hosted_session` not found).

- [ ] **Step 3: Implement in `src/session.rs`, the testkit helper and `Fleet.daemon_grant`**

- [ ] **Step 4: Run**

Run: `$SLOT cargo test -p identity-crypto --lib session` then `$SLOT cargo test -p identity-crypto --doc`
Expected: PASS.

- [ ] **Step 5: Commit** (`identity-crypto: mint_hosted_session and HostedSessionCredential`).

---

### Task 4: The standing grant and the `DaemonHosted` chain rules

**Files:**
- Modify: `src/registry.rs:122-196` (kind rules; `VerifiedEntry.hosts_held_agents`)
- Modify: `src/verify.rs` (`verify_chain` DaemonHosted arm; a `carried_device` helper)
- Modify: `src/resolver.rs` tests (`agent_checks`), `src/verify.rs` tests

**Interfaces:**
- Consumes: `hosted_chain`, `Fleet.daemon_grant` (Task 3); `hosted_session_transcript` (Task 2); `rotation_roots` (`authority.rs`); `device_current`, `check_cert`, `check_unlisted_span`.
- Produces: `VerifiedEntry::hosts_held_agents(&self) -> bool`. `verify_chain` returns, for a `DaemonHosted` chain, `VerifiedChain { principal: agent, kind: PrincipalKind::Agent, host: Host::Daemon(daemon), subject: Some(subject), device: <daemon device>, session_key, session_not_after }`.

Registry rules (in `check_registry`):
- `hosts_held_agents == true` on any kind but DAEMON → `InvalidRegistry { field: "entries.hosts_held_agents", reason: "only for DAEMON" }`.
- Delete the `Agent if self_rooted && !allowed_hosts.is_empty()` rule. A self-rooted AGENT may list `allowed_hosts`; a keyless AGENT still needs at least one (rule kept). The either/or now means only: keyless agents are host-vouched.

`verify_chain` `DaemonHosted(h)` rules, in this order (errors exact):
1. `host_device`, `agent_device`, `session` present, else `MissingField("daemon_hosted.host_device" | "daemon_hosted.agent_device" | "daemon_hosted.session")`; `agent_signature` non-empty, else `MissingField("daemon_hosted.agent_signature")`.
2. daemon = `from_genesis(host_device.principal_genesis)`; entry missing → `UnknownPrincipal`; kind ≠ DAEMON → `WrongKind`; frozen → `Frozen`.
3. `cert.mode != 1` → `ChainMismatch("session.mode")`; `host_genesis` ≠ daemon genesis → `ChainMismatch("session.host_genesis")`; subject absent → `MissingField("session.subject")`; not prefixed `"<daemon short id>/"` → `NotVouched`.
4. agent = `from_genesis(cert.principal_genesis)`; `agent_device.principal_genesis` ≠ cert's → `ChainMismatch("agent_device.principal_genesis")`.
5. Agent entry present: kind ≠ AGENT or not self-rooted → `WrongKind`; frozen → `Frozen`; authorisation: if `allowed_hosts` is non-empty it decides alone (`Any` or this daemon, else `NotVouched`); if empty, `daemon_entry.hosts_held_agents()` else `NotVouched`; agent device = `device_current(agent_device, entry, r, at)`; `agent_rotations` are ignored.
   Agent entry absent: daemon without the grant → `UnknownPrincipal`; agent device = `carried_device(agent_device, &agent, &h.agent_rotations, at)`: `rotation_roots(genesis, rotations)` (its errors), `signing_root` ≠ last root → `ChainMismatch("agent_device.signing_root")`, purpose ≠ DEVICE → `ChainMismatch("agent_device.purpose")`, signature (`verify_p256` error), `not_after == 0` → `InvalidField { field: "agent_device.not_after_unix_seconds", reason: "0 is not an expiry" }`, `check_unlisted_span("agent_device.not_after_unix_seconds", ..)`, `issued_at > at + SKEW` → `NotYetValid("agent device delegation")`, `at > not_after` → `Expired("agent device delegation")`.
6. daemon device = `device_current(host_device, daemon_entry, r, at)`; `(session_key, not_after) = check_cert(cert, &daemon_device, at)`.
7. `verify_p256(&agent_device, &hosted_session_transcript(cert)?, &h.agent_signature)` (its error, `BadSignature`).

- [ ] **Step 1: Write the failing tests**

In `src/resolver.rs` `agent_checks`, replace the assertion that a self-rooted agent with `allowed_hosts = ["*"]` is invalid with `assert!(…is_ok())`. Add `hosts_held_agents_only_on_daemon`: setting it on the HUMAN, AGENT and a SERVICE entry is `invalid(…, "entries.hosts_held_agents")`; on the daemon it loads and `r.entry(&f.daemon.id()).unwrap().hosts_held_agents()` is true.

In `src/verify.rs` tests (each uses a fresh self-rooted `agent = Principal::new()` and `hosted_chain(&f.daemon, &agent, &subject_on(&f.daemon, "i5"), T0, T0 + 3600)`):
- `granted_daemon_hosts_an_unregistered_agent`: with `f.daemon_grant = true`, `verify_chain` gives `(principal, kind, host, subject) == (agent.id(), Agent, Host::Daemon(f.daemon.id()), Some("<short>/i5"))`.
- `ungranted_daemon_cannot_host_an_unregistered_agent`: grant false → `UnknownPrincipal`.
- `granted_daemon_hosts_a_registered_agent_with_no_allowed_hosts`: agent entry via `entry(&agent, Agent)`, grant true → Ok; grant false → `NotVouched`.
- `explicit_allowed_hosts_win_over_the_grant`: agent entry `allowed_hosts = [f.daemon.id()]`, grant false → Ok; `allowed_hosts = [Principal::new().id()]`, grant true → `NotVouched`.
- `co_signature_is_required_and_must_be_the_agent_device`: empty `agent_signature` → `MissingField("daemon_hosted.agent_signature")`; signature replaced by one from the daemon device over the same transcript → `BadSignature`.
- `unregistered_rotated_agent_needs_its_rotations`: `agent.rotate(T0)` before `hosted_chain`; Ok with the carried rotations; with `agent_rotations` cleared → `ChainMismatch("agent_device.signing_root")`.
- `registered_agent_uses_the_registry_root_not_the_carried_rotations`: registered agent (unrotated in the registry), chain carries a forged rotation to a new root and an agent device delegated by it → `ChainMismatch("device.signing_root")`.
- `daemon_hosted_rejections`: subject on another daemon → `NotVouched`; cert mode 0 → `ChainMismatch("session.mode")`; `agent_device.principal_genesis` of another principal → `ChainMismatch("agent_device.principal_genesis")`; host is a HUMAN principal → `WrongKind`; a HUMAN's genesis as the agent → `WrongKind`; frozen agent → `Frozen`; expired agent device delegation (`accepted(T0 + 31 * DAY)`) → `Expired("agent device delegation")` for unregistered, `Expired("device delegation")` for registered.
- `daemon_hosted_signed_message_verifies`: `verify_signed_message` on a message built from the chain (testkit `signed_message`) with grant true is Ok and `chain().principal() == agent.id()`.
- In the existing trusted-devices tests, add `daemon_hosted_chain_is_rejected` → `ChainMismatch("signer.daemon_hosted")`.

- [ ] **Step 2: Run to verify they fail**

Run: `$SLOT cargo test -p identity-crypto --lib`
Expected: the new tests FAIL (`ChainMismatch("signer.daemon_hosted")` from the Task 1 stub; `hosts_held_agents` method missing).

- [ ] **Step 3: Implement the registry rules and the `verify_chain` arm**

- [ ] **Step 4: Run**

Run: `$SLOT cargo test -p identity-crypto`
Expected: PASS.

- [ ] **Step 5: Commit** (`identity-crypto: daemon standing grant and DaemonHosted chain rules`; body states that explicit allowed_hosts decide alone, that unregistered agents need the grant and their carried rotations, and that the self-rooted-agent allowed_hosts rule is deleted).

---

### Task 5: `verify_carried_message` and `verify_root_device_delegation`

**Files:**
- Modify: `src/verify.rs`, `src/lib.rs` (re-exports)

**Interfaces:**
- Produces:

```rust
/// A message as a recipient sees it inside a Delivery: intact, with no
/// registry, revocation, freeze or clock check. Trust comes from the
/// Delivery signature over its transcript.
#[derive(Clone, Debug)]
pub struct CarriedMessage { /* private */ }
impl CarriedMessage {
    pub fn author(&self) -> &PrincipalId;
    pub fn session_key(&self) -> &PublicKey;
    pub fn nonce(&self) -> &[u8];
    pub fn issued_at(&self) -> i64;
    pub fn body_type(&self) -> &str;
    pub fn body(&self) -> &[u8];
}

pub fn verify_carried_message(msg: &pb::SignedMessage, expected_audience: &str) -> Result<CarriedMessage>;

/// A trusted principal's device, for a Delivery signer: the delegation is
/// from `principal`'s genesis root (a deliverer is trusted by principal id,
/// which is its root key; its root rotation means updating the trust list)
/// and current at `at`. Returns the device key.
pub fn verify_root_device_delegation(d: &pb::KeyDelegation, principal: &PrincipalId, at: i64) -> Result<PublicKey>;
```

  `verify_root_device_delegation` checks, in order: `principal_genesis` = `principal.genesis()` (`ChainMismatch("device.principal_genesis")`); `signing_root` = the same genesis (`ChainMismatch("device.signing_root")`); purpose DEVICE (`ChainMismatch("device.purpose")`); `not_after != 0` (`InvalidField { field: "device.not_after_unix_seconds", reason: "0 is not an expiry" }`); `check_unlisted_span("device.not_after_unix_seconds", ..)`; `issued_at > at + SKEW_SECONDS` → `NotYetValid("device delegation")`; `at > not_after` → `Expired("device delegation")`; signature under the genesis (its error). It shares the unlisted-window code with `device_current` and Task 4's `carried_device` through one `pub(crate) fn check_unlisted_window(d, at, what: &'static str)`, so the rule exists once. Decision: a deliverer always signs with a delegated device, multimatrix included (it already holds a device and its delegation in `ServiceKey`); there is no "signer is the root" case.

  Checks, in order: signature non-empty (`EmptySignature`); chain present. Per arm, integrity only:
  - `SelfRooted`: `device` required (`MissingField("self_rooted.device")`); `device.principal_genesis` = cert's (`ChainMismatch("device.principal_genesis")`); `device.delegated` = `cert.device` (`ChainMismatch("session.device")`); delegation signature under its own `signing_root`; cert mode 0; cert signature under `cert.device`.
  - `HostVouched`: `host_device.delegated` = `cert.device`; `cert.host_genesis` = `host_device.principal_genesis` (`ChainMismatch("session.host_genesis")`); delegation signature under its `signing_root`; mode 1; cert signature.
  - `DaemonHosted`: as `HostVouched` for `host_device`, plus `agent_device.principal_genesis` = cert's, `agent_device` signature under its `signing_root`, and `agent_signature` over `hosted_session_transcript` under `agent_device.delegated`.
  Then audience (`WrongAudience`) and the message signature under `cert.session`. No `not_before`/`not_after`/`issued_at` comparison anywhere. Cert-signature checks share a new `pub(crate) fn check_cert_signature(c, device) -> Result<PublicKey>` that `check_cert` also calls, so the signature rule exists once.

- [ ] **Step 1: Write the failing tests** (in `src/verify.rs` tests)

- `carried_self_rooted_message_verifies`: `daemon_chain`-style self-rooted chain for an agent principal; `author() == agent.id()`, `body() == [1, 2]`.
- `expired_session_still_verifies_when_carried`: cert window `(T0, T0 + 3600)` and delegation window `(T0, T0 + DAY)`: Ok (there is no clock parameter at all).
- `carried_daemon_hosted_message_verifies` and `carried_host_vouched_message_verifies`: author is the agent.
- `root_device_delegation_rules`: a fresh `Principal`'s `delegate_device(T0, T0 + DAY)` at `T0 + 60` → Ok(device); another principal → `ChainMismatch("device.principal_genesis")`; after `rotate(T0)` a delegation by the new root → `ChainMismatch("device.signing_root")`; at `T0 + DAY + 1` → `Expired("device delegation")`; issued at `T0 + 3600`, checked at `T0` → `NotYetValid("device delegation")`; tampered `not_after` → `BadSignature`.
- `carried_rejections`: wrong audience → `WrongAudience`; tampered body → `BadSignature`; missing `self_rooted.device` → `MissingField("self_rooted.device")`; delegation naming another genesis → `ChainMismatch("device.principal_genesis")`; cert device ≠ delegated → `ChainMismatch("session.device")`; DaemonHosted with a bad `agent_signature` → `BadSignature`; empty signature → `EmptySignature`.

- [ ] **Step 2: Run to verify they fail** (`$SLOT cargo test -p identity-crypto --lib verify`; expected compile failure).

- [ ] **Step 3: Implement** `verify_carried_message`, `CarriedMessage`, `check_cert_signature`, `verify_root_device_delegation`, `check_unlisted_window`; re-export `verify_carried_message, CarriedMessage, verify_root_device_delegation`.

- [ ] **Step 4: Run** `$SLOT cargo test -p identity-crypto` → PASS.

- [ ] **Step 5: Commit** (`identity-crypto: verify_carried_message and verify_root_device_delegation`).

---

### Task 6: identity-keyfile split layout

**Files:**
- Create: `identity-keyfile/src/layout.rs`, `identity-keyfile/tests/split.rs`
- Modify: `identity-keyfile/src/keys.rs`, `identity-keyfile/src/files.rs` (lock helpers take a layout), `identity-keyfile/src/error.rs`, `identity-keyfile/src/lib.rs`

**Interfaces:**
- Produces:

```rust
/// Where an identity's files live. `single(dir)` is the classic layout. In a
/// split layout `root_dir` holds only `root.jwk.json` (and its `.lock`);
/// every other file, `rotations.json` included, is in `device_dir`, the
/// folder an agent may be shown. One root_dir per identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityLayout { /* root_dir, device_dir */ }
impl IdentityLayout {
    pub fn single(dir: &Path) -> Self;
    /// Both paths absolute; root_dir neither equal to device_dir nor inside it.
    pub fn split(root_dir: &Path, device_dir: &Path) -> Result<Self, KeyfileError>;
    pub fn root_dir(&self) -> &Path;
    pub fn device_dir(&self) -> &Path;
    pub fn is_split(&self) -> bool;
}

// KeyfileError gains:
#[error("invalid identity layout: {0}")]
InvalidLayout(&'static str),   // "paths must be absolute" | "root_dir must not be device_dir or inside it"

impl IdentityKeys {
    pub fn init_at(layout: &IdentityLayout, now: i64, ttl_seconds: i64) -> Result<Self, KeyfileError>;
    pub fn save_at(&self, layout: &IdentityLayout) -> Result<(), KeyfileError>;
    pub fn load_at(layout: &IdentityLayout) -> Result<Self, KeyfileError>;
    pub fn load_verified_at(layout: &IdentityLayout) -> Result<Self, KeyfileError>;
    pub fn load_existing_at(layout: &IdentityLayout) -> Result<Option<Self>, KeyfileError>;
    pub fn exists_at(layout: &IdentityLayout) -> bool;   // agent_id in device_dir and root.jwk.json in root_dir
    pub fn create_or_load_at(layout: &IdentityLayout, now: i64, ttl_seconds: i64) -> Result<Self, KeyfileError>;
    pub fn renew_at(layout: &IdentityLayout, now: i64, ttl_seconds: i64, new_device: bool) -> Result<Self, KeyfileError>;
    pub fn rotate_device_at(layout: &IdentityLayout, now: i64, ttl_seconds: i64) -> Result<Self, KeyfileError>;
    pub fn rotate_root_at(layout: &IdentityLayout, now: i64) -> Result<pb::RootRotation, KeyfileError>;
    pub fn renew_if_due_at(&mut self, layout: Option<&IdentityLayout>, now: i64, ttl_seconds: i64, margin_seconds: i64) -> Result<bool, KeyfileError>;
}
```

  Every existing `dir: &Path` entry point (`init`, `save`, `load`, `load_verified`, `load_existing`, `exists`, `create_or_load`, `renew`, `rotate_device`, `rotate_root`, `renew_if_due`) keeps its signature and becomes a one-line call of its `_at` twin with `IdentityLayout::single(dir)`. `DeviceKeys::load(dir)` and `read_principal(dir)` are unchanged and work on a split `device_dir` (rotations live there). Re-export `IdentityLayout` from the crate root.

  Locks: an operation that reads or writes the root takes `root_dir/.lock` then `device_dir/.lock`, in that order; in a single layout the one lock is taken once (two `flock`s on one file from one process would self-deadlock). Device-only reads take only `device_dir/.lock`. `check_dir` (0700, not a symlink) applies to both directories.

  `create_or_load_at` on a split layout does not use the temp-dir rename (it cannot span two directories). Under both exclusive locks: if `device_dir/agent_id` exists, `load_verified_at`; otherwise write `root.jwk.json` to `root_dir`, then the device files, `rotations.json`, history, and `agent_id` last, overwriting any partial files left by a crashed earlier attempt (no `agent_id` means nothing was committed or registered). On a single layout it keeps today's rename-based algorithm. `init_at` keeps refusing (`AlreadyInitialised`) when any identity file exists in either directory.

- [ ] **Step 1: Write the failing tests in `identity-keyfile/tests/split.rs`**

Each test makes `root = tempdir()/root` and `dev = tempdir()/dev` (absolute) and `layout = IdentityLayout::split(&root, &dev).unwrap()`.
- `split_refuses_relative_paths_and_root_inside_device_dir`: `split("rel", abs)` and `split(abs, "rel")` → `InvalidLayout("paths must be absolute")`; `split(&dev, &dev)` and `split(&dev.join("r"), &dev)` → `InvalidLayout("root_dir must not be device_dir or inside it")`; `split(&root, &root.join("dev"))` is Ok.
- `split_init_keeps_the_root_out_of_the_device_dir`: after `init_at`, `root` contains exactly `{".lock", "root.jwk.json"}` and `dev` contains no `root.jwk.json`; `DeviceKeys::load(&dev)` gives the same `principal_id` and device public key as the returned `IdentityKeys`; `read_principal(&dev)` is `Ok(Some(id))`.
- `split_renew_and_rotate_device_work_with_the_root_outside`: `renew_at(.., false)` re-signs (delegation verifies under the root via `load_verified_at`); `rotate_device_at` retires the old device (history length 1) and `DeviceKeys::load(&dev)` returns the new device.
- `split_rotate_root_then_renew`: `rotate_root_at` writes `rotations.json` in `dev` and the new root in `root`; `load_verified_at` fails with `VerifyFailed(SigningRoot)` until `renew_at`, then passes; `read_principal(&dev)` is the unchanged id.
- `split_create_or_load_is_idempotent_and_recovers_an_uncommitted_attempt`: second call returns the same id; deleting `dev/agent_id` and calling again yields a new committed identity whose root file in `root` matches it.
- `split_create_or_load_races_to_one_identity`: 8 threads on one layout → one distinct `principal_id`.
- `split_renew_without_the_root_file_is_missing`: remove `root/root.jwk.json`; `renew_at` → `KeyfileError::Missing(path)` with `path == root.join("root.jwk.json")`.
- `exists_at_needs_both_halves`: false before init, true after, false after removing the root file.
- `single_layout_is_the_classic_folder`: `IdentityLayout::single(&d)` with `init_at` writes all six files into `d`, and `IdentityKeys::load(&d)` loads it.

- [ ] **Step 2: Run to verify they fail**

Run: `$SLOT cargo test -p identity-keyfile --test split`
Expected: FAIL to compile (`IdentityLayout` not found).

- [ ] **Step 3: Implement `layout.rs`, the `_at` functions and the wrappers**

- [ ] **Step 4: Run the whole crate, existing suites unchanged**

Run: `$SLOT cargo test -p identity-keyfile --all-features`
Expected: PASS, with no edits to `tests/keys.rs`, `tests/files.rs`, `tests/device.rs`, `tests/verified.rs`, `tests/testkit.rs` (that is the same-folder compatibility proof).

- [ ] **Step 5: Commit** (`identity-keyfile: IdentityLayout, root outside the device folder`).

---

### Task 7: Version 0.9.0, docs, full gate, push

**Files:**
- Modify: `Cargo.toml` (`version = "0.9.0"`), `identity-keyfile/Cargo.toml` (`version = "0.9.0"`, dependency `version = "0.9.0"`), `Cargo.lock`
- Modify: `README.md`, `identity-keyfile/README.md`, `metadata/metadata.yaml`

- [ ] **Step 1: Update the docs**

- `README.md`: delete the "Attestation (0.5.0)" bullets about `DeliveryAttestation`/`AttestedMessage` and their JSON; add a "Messages and ids (0.9.0)" section naming `Message`, `Delivery`, `Target`, `Targets`, `delivery.v1`, `hosted-session.v1`, `DaemonHosted`, `hosts_held_agents` and its precedence rule, `mint_hosted_session`, `verify_carried_message`, `verify_root_device_delegation`; fix the identity-keyfile version mention (`0.8.0` → `0.9.0`).
- `identity-keyfile/README.md`: a "Split layout" section: `IdentityLayout::split`, which file lives where, the lock order, and that the `dir` functions are the single layout.
- `metadata/metadata.yaml`: rewrite fact `pbjson-attestation-rejects-unknown-fields` as `pbjson-delivery-rejects-unknown-fields` (assertion about `Delivery`, evidence `tests/json.rs`); add facts `daemon-hosted-chain-needs-agent-cosignature` (evidence `src/verify.rs`, `src/session.rs`), `explicit-allowed-hosts-override-grant` (evidence `src/verify.rs`, `src/registry.rs`), `keyfile-split-layout-root-outside-device-dir` (evidence `identity-keyfile/src/layout.rs`, `identity-keyfile/tests/split.rs`).
- `grep -rn "DeliveryAttestation\|AttestedMessage\|delivery_attestation\|delivery-attestation\|never both" .  --exclude-dir=target --exclude-dir=.git` returns nothing outside this plan file.

- [ ] **Step 2: Full gate**

Run: `$SLOT --all cargo test --workspace --all-features 2>&1 | tee target/ic-gate.log; echo "exit=${PIPESTATUS[0]}"` (under `bash`), then `$SLOT --all cargo clippy --workspace --all-targets --all-features -- -D warnings`
Expected: `exit=0`; clippy clean. Then `cd vectors && .venv/bin/python gen.py && git diff --exit-code .` (vectors are reproducible).

- [ ] **Step 3: Commit** (`identity-crypto 0.9.0, identity-keyfile 0.9.0: messages and ids step 1`; body lists every removed public item from the Consumer impact section).

- [ ] **Step 4: Review, then push**

After the whole-branch review passes, push `main` (my-libs push rule: green and reviewed, no per-push approval). Record the pushed sha: the message-attestation plan's Task 1 pins it.

---

## Consumer impact

Removed (no replacement of the same name):
- `pb::DeliveryAttestation`, `pb::AttestedMessage` → use `pb::Delivery` and `pb::Message` (the message is the body of a `pb::SignedMessage` inside `Delivery.messages`; author = signer, `room_id` → `Message.to`).
- `transcripts::delivery_attestation_transcript`, `transcripts::DELIVERY_ATTESTATION_TAG` → `transcripts::delivery_transcript`, `transcripts::DELIVERY_TAG`.
- The registry rule refusing `allowed_hosts` on a self-rooted AGENT (registries that relied on that refusal now load).

Changed shape (struct literals and exhaustive matches break):
- `pb::SignerChain` oneof has a third arm `Chain::DaemonHosted(pb::DaemonHosted)`: every `match` on `pb::signer_chain::Chain` needs it.
- `pb::RegistryEntry` has a new field `hosts_held_agents: bool`: literals without `..Default::default()` need it.
- `transcripts::ALL_TAGS` is `[&str; 14]`.

Added:
- `pb::Message`, `pb::Delivery`, `pb::Target` (`pb::target::Target::{RoomId, RecipientId}`), `pb::Targets`, `pb::DaemonHosted`.
- `transcripts::{hosted_session_transcript, delivery_transcript, HOSTED_SESSION_TAG, DELIVERY_TAG}`.
- `mint_hosted_session`, `HostingDaemon`, `HostedAgent`, `HostedSessionCredential` (structmux's `mint_agent_session` for hosted agents).
- `verify_carried_message`, `CarriedMessage`, `verify_root_device_delegation` (used by message-attestation).
- `pb::Delivery` has no `key_id`: it carries `signer_device` (the deliverer's root→device delegation) and is signed by that device. Deliverers (multimatrix, structmuxd) sign with their device, never their root.
- `VerifiedEntry::hosts_held_agents()`.
- `testkit::hosted_chain`, `testkit::Fleet::daemon_grant`.
- identity-keyfile: `IdentityLayout`, `KeyfileError::InvalidLayout`, and `IdentityKeys::{init_at, save_at, load_at, load_verified_at, load_existing_at, exists_at, create_or_load_at, renew_at, rotate_device_at, rotate_root_at, renew_if_due_at}`. Every existing identity-keyfile function keeps its signature and behaviour (grorg's `agent ensure`/`renew` and structmux's daemon identity need no change).

Behaviour notes for consumers:
- `verify_chain` accepts `DaemonHosted` only from a DAEMON entry; a registered agent with `allowed_hosts` is governed by that list alone; an unregistered agent needs the daemon's `hosts_held_agents` and, if rotated, carried `agent_rotations` (structmux reads them with `identity_keyfile::read_rotations(device_dir)`).
- `verify_carried_message` requires `SelfRooted.device` (the root→device delegation). An author that signs with `device_delegation: None` is refused by recipients; multimatrix and the owner client must pass the delegation.
