# identity-crypto

P-256 key types, principal ids, canonical transcripts, the principal
registry and verification for the concordium/structmux identity design
(structmux `docs/superpowers/specs/2026-10-11-daemon-mesh-schema-design.md`;
verification: `2026-10-12-fleet-phase1b-identity-verification-design.md`).
Pure: no I/O, no clock, no key storage. Every primitive comes from
`rust_jwk_duo` (re-exported as [`jwk_duo`]); this crate owns byte layouts,
validation and verification.

The `identity-keyfile/` workspace member (0.7.0) stores a self-rooted principal's keys (an agent's or a daemon's) in a Unix directory, with the history and rotation chain; see its README.

## Attestation (0.5.0)

The delivery attestation has a JSON form, the one carried in `_meta`.
Breaking, pre-MVP.

- **JSON form.** `DeliveryAttestation`, `AttestedMessage` and the types they
  contain implement serde `Serialize` and `Deserialize` as proto3-JSON, via
  pbjson. Field names are camelCase (snake_case also parses). `attestedAt`
  is RFC 3339 and is emitted with `Z`; offset forms such as `+02:00` are
  accepted on parse. `bytes` fields are emitted as padded standard base64
  (parsing accepts either alphabet). Unknown fields are rejected.
- **Writer.** The supported writer of this JSON is the message-attestation
  crate's `attach` function. That function lives in message-attestation, not
  in this repo; this crate defines the form and the transcript only.
- **Layout.** `AttestedMessage.verification_outcome` is deleted, along with
  `VerificationOutcome` (its tag and name are reserved). Every attested
  message requires `author_genesis` and `delegation_cert`, and a
  `DeliveryAttestation` requires `attested_at`. The attestation transcript
  rejects a missing one.
- **`PublicKey::thumbprint()`** gives the RFC 7638 JWK thumbprint (43
  base64url characters, unpadded): the `key_id` for a `p256:` key.
- **`mint_session(device, principal_genesis, not_before, not_after)`**
  makes a fresh session key and a mode-0 cert signed by the device. The span
  must be in `(0, 24 h]`. It returns a `SessionCredential` (not `Clone`) with
  `cert()`, `session_public_key()` and `not_after_unix()`. Renewal is the
  caller's.
- **`SessionCredential::sign_message(device_delegation, audience, nonce,
  issued_at, in_reply_to_nonce, body_type, body)`** builds a `SelfRooted`
  `SignedMessage` and signs `signed-message.v1` with the session key. Pass
  `device_delegation: None` only in step 1, before a root exists to delegate
  the device.
- **`message_nonce(message_id)`** gives 16 bytes: the first half of SHA-256
  over the message id.
- **`verify_signed_message_trusted_devices`** (interim, step 1) checks a
  message against a caller-supplied `AuthorDevices { author_genesis, devices }`
  set of device keys, with no registry. It checks the mode-0 cert, its
  `principal_genesis`, device membership, the cert and its window, the
  audience, the message signature and, for `When::Live`, the 30 s skew. It
  does not read `SelfRooted.device` and does no revocation or freeze checks:
  removing a device from the set is the caller's revocation. `issued_at` is
  not tied to the cert window. This function is deleted, not kept, when the
  step-2 `Resolver` verifier lands.

## Request digests (0.4.0)

Two forms of `Approval.request_digest`, each under its own tag:

- `request_digest` (`request-digest.v1`): a requester that can carry a
  subject and always has a host daemon, an instance and an action.
- `client_request_digest` (`client-request-digest.v1`): a requester that
  connects with a self-rooted chain (no subject), with an optional host and an
  optional resource. An absent host covers both `Host::Hostless` and
  `Host::Unhosted`; the requester principal already fixes its kind.

0.4.0 is additive: `ALL_TAGS` is now `[&str; 13]` (its type changes, which is
why this is a minor bump). Nothing existing changes meaning.

## Verification (0.3.0)

History is checked once; messages are checked against it.

1. `verify_signed_document(doc, type, &accepted_chain)` checks the
   authority's signature and root chain. Its `id()` is the SHA-256 of the
   signed transcript, the same for every encoding.
2. `Resolver::from_document(&verified, registry_type)` checks the
   `PrincipalRegistry` inside (field 1 of the body) and builds the lookups.
   `resolver.check_successor(&accepted_chains)` rejects a version that forks
   or rewinds any principal's root chain; persist the returned set.
3. `verify_chain`, `verify_signed_message`, `verify_approval` and
   `verify_peer_revocation` check one input against a resolver at a time
   given as `When::Live { now }` (adds the ±30 s skew) or
   `When::Accepted(AcceptedAt::from_receiver_record(t))`.

Absence always means less access: fields added later may only grant, and
`0` is never "no expiry" (write `i64::MAX`). Nonce replay, document
versions, persistence and policy are the caller's.

## What it owns

- **Types:** `PublicKey` (SEC1 uncompressed P-256, validated),
  `PublicKeyDuo`, `PrincipalId` (`p256:<130 lowercase hex>`), `ShortId`
  (first 8 bytes of SHA-256 over the genesis key), and a typed `Error`.
  `PublicKey::thumbprint()` gives the RFC 7638 JWK thumbprint, the `key_id` for a `p256:` key.
- **Proto** (`proto/identitycrypto/v1/identity.proto`, reached as
  `identity_crypto::pb`): keys, delegations, signer chains, signed messages
  and documents, approvals, revocations, the delivery attestation.
- **Transcripts** (`identity_crypto::transcripts`): the exact bytes every
  signature covers, thirteen functions under `identitycrypto.*.v1` tags. Each
  validates while it encodes; signer and verifier call the same function.
- **`verify_p256`:** 64-byte `r‖s`, both S forms, returning a
  `VerifiedSignature` witness bound to the key and the message.
- **Key builders** (`keys`, see below): the delegation, proof, rotation and
  revocation signatures over those transcripts, with the device window cap.

Every primitive comes from [`rust_jwk_duo`](https://github.com/qtpi-bonding-org/rust_jwk_duo), re-exported as
`identity_crypto::jwk_duo`. Sign transcripts with the `keys` builders (below),
not with `jwk_duo` directly, so the window caps and transcript rules apply.

## Keys

Pure builders for a self-rooted principal's signatures (re-exported at the
root from `src/keys.rs`). No I/O, no clock (the caller passes `now`), no key
generation or storage.

- `signing_public`, `encryption_public`, `principal_id`: the public halves of a
  duo, and the principal id a genesis duo starts.
- `delegate_device(root, genesis, device, issued, not_after)`: a root-signed
  DEVICE delegation for an Agent or Daemon device. Capped at 31 days by the
  same rule the verifier applies (`check_unlisted_span`).
- `device_delegation` (unsigned) and `sign_key_delegation`: no cap. For a
  Human's device or an approval key, whose window may be longer.
- `renewal_due(d, now, margin)`: whether a delegation is inside its renewal
  margin.
- `challenge_proof`, `rename_proof`, `rotation`, `revocation`: the signed
  proofs over their transcripts.

Every builder returns `Error::InvalidKey` for a key pair with no private half,
never a panic.

## Testkit

The `testkit` feature (off by default) compiles `identity_crypto::testkit`:
real keys, real signatures and fixtures (`Signer`, `Principal`, `Fleet`,
signed messages, delegations). Enable it in `[dev-dependencies]` only:

```toml
[dev-dependencies]
identity-crypto = { git = "https://github.com/qtpi-bonding/identity-crypto.git", rev = "<rev>", features = ["testkit"] }
```

Its helpers call the same `keys` builders as the real API; they are test
conveniences, not a second implementation.

## Vectors

`vectors/gen.py` is an independent Python implementation of every
transcript. It writes `transcripts.json`, `principals.json`,
`signatures.json`, `thumbprints.json`, `nonces.json` and `messages.json`,
which `tests/vectors.rs` checks. To regenerate:

```
cd vectors
python3 -m venv .venv && .venv/bin/pip install --require-hashes -r requirements.txt
.venv/bin/python -I gen.py
```

Output must be byte-identical to the committed files.

## Using the proto from another crate

List `identity-crypto` under `[build-dependencies]` and pass
`identity_crypto::proto_include_dir()` to `compile_protos` to import
`identitycrypto/v1/identity.proto`.
