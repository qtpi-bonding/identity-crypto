# identity-crypto

Versions: identity-crypto **0.11.0**, identity-keyfile **0.11.0**,
identity-request-auth **0.2.0**. See `CHANGELOG.md` for every break.

P-256 key types, principal ids, canonical transcripts, the principal
registry and verification for the concordium/structmux identity design
(structmux `docs/superpowers/specs/2026-10-11-daemon-mesh-schema-design.md`;
verification: `2026-10-12-fleet-phase1b-identity-verification-design.md`).

Purity: this crate does no I/O (no filesystem, no tokio, no key storage).
The only wall-clock read in the crate is `src/clock.rs` (`now_timestamp` and
`now_unix`), as `lib.rs` documents. Every primitive comes from `rust_jwk_duo`
(re-exported as [`jwk_duo`]); this crate owns byte layouts, validation and
verification.

The `identity-keyfile/` workspace member (0.11.0) stores a self-rooted
principal's keys (an agent's or a daemon's) in a Unix directory, with the
history and rotation chain; see its README. The `identity-request-auth/`
member (0.2.0) signs and verifies one request at a time over this crate.

## Helpers (0.5.0)

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
- **`verify_signed_message_trusted_devices(msg, audience, AuthorDevices {
  author_genesis, devices }, when)`** checks a message against a
  caller-supplied set of device keys, with no registry. It is the check
  behind `identity-request-auth`'s `TrustedDeviceSet`, the request-auth core,
  and it stays in the crate. It checks the mode-0 cert, its
  `principal_genesis`, device membership, the cert and its window, the
  audience, the message signature and, for `When::Live`, the 30 s skew. It
  does not read `SelfRooted.device` and does no revocation or freeze checks:
  removing a device from the set is the caller's revocation, and it takes
  effect at the next call. `issued_at` is not tied to the cert window.

## Signer

The signing seam (`src/signer.rs`). Every builder and `sign_document` signs
through a `Signer`, so a backend can prompt, delegate to hardware, or refuse.

- **`Signer`** (`Send + Sync`) has `public_key()`, `sign(message)` and
  `sign_for(message, reason)`. `reason` is text a prompting backend may show;
  the default ignores it. `sign` returns `Result<Signature, SignerError>`.
- **`SignerError`** is `Cancelled`, `Unavailable` (no private half, or the key
  is not available) or `Backend(String)`. A builder that fails to sign returns
  `Error::Signer(SignerError)`, not `InvalidKey`.
- `Signer` is implemented for `jwk_duo::KeyDuo` and `SigningKeyPair`, and for
  `&S`, `Box<S>` and `Arc<S>` when `S: Signer`.
- **`Signature`** is the raw 64-byte `r || s`. **`verify_signature(&key,
  message, &signature)`** checks it by the key's own scheme (only ECDSA P-256
  is supported; any other scheme is `UnsupportedScheme`).
- **Unlock note:** `sign_document` builds the transcript from the draft and
  then calls `sign_for`. It does not unlock anything. Unlock a prompting signer
  before the caller chooses `issued_at`.

## Lifetimes

The constants are in `src/verify.rs` and re-exported at the root. Consumers
use these; they keep no TTL, margin or clock helpers of their own.

| Constant | Value | Meaning |
| --- | --- | --- |
| `DEFAULT_DELEGATION_SECONDS` | 30 d (2 592 000 s) | Lifetime of a new device delegation unless the caller says otherwise. |
| `MAX_DELEGATION_SECONDS` | 31 d (2 678 400 s) | Longest device delegation any signer or verifier accepts. |
| `DEFAULT_RENEW_MARGIN_SECONDS` | 7 d (604 800 s) | A delegation is renewed when less than this remains. |
| `MAX_SESSION_SECONDS` | 24 h | Longest span `mint_session` accepts. |
| `SKEW_SECONDS` | 30 s | Tolerance on `issued_at` for `When::Live`. |

`identity-request-auth` has its own `SESSION_SECONDS` (300 s, the session it
mints), which is separate from these.

Absence always means less access: fields added later may only grant, and
`0` is never "no expiry" (write `i64::MAX`). Nonce replay, document
versions, persistence and policy are the caller's.

## Messages and ids

- **`pb::Message`** is the body of an author's `SignedMessage` (`message_id`,
  `to: [Target]`, `reply_to`, `references`, `mentions`, `authored_at`, `body`).
  The author is the `SignedMessage` signer, never a field. `pb::Target` is a
  `RoomId` or a `RecipientId`; `pb::Targets` is one message's list.
- **`pb::Delivery`** is signed per recipient by the deliverer under
  `delivery.v2` (`delivery_transcript`). It carries the `SignedMessage`s
  verbatim, `via[i]` for `messages[i]`, and `signer_device`: the deliverer's
  root-to-device delegation. A deliverer signs with its device, never its root.
  `names` (sorted strictly ascending by `principal_id`, each canonical, each
  name non-empty) is signed with it: one display name per author principal.
  `verify_root_device_delegation(d, &principal, at)` checks that delegation
  against a trusted deliverer's principal id and returns the device key.
- **`DaemonHosted`** is a third `SignerChain` arm: an agent with its own keys
  that a daemon holds and runs. The daemon device signs the mode-1 session cert;
  the agent device co-signs it under `hosted-session.v1`
  (`hosted_session_transcript`). `mint_hosted_session(HostingDaemon,
  HostedAgent, subject, not_before, not_after)` builds one and returns a
  `HostedSessionCredential` whose `sign_message` produces the `SignedMessage`.
- **`hosts_held_agents`** on a DAEMON `RegistryEntry` lets that daemon host any
  agent whose device key it holds. Precedence: an agent with a non-empty
  `allowed_hosts` is governed by that list alone and the daemon's grant is
  ignored; an agent that names no host needs the grant. `verify_chain` accepts
  `DaemonHosted` only from a DAEMON entry.
- **`verify_carried_message(msg, audience)`** checks a message's chain for
  integrity with no registry and no clock and returns a `CarriedMessage`. It
  proves authorship only after the enclosing `Delivery` has been verified.
  Never call it on its own: it checks a self-rooted delegation only under its
  own `signing_root`, so on its own a fabricated chain passes.

A hosted agent with no registry entry cannot be revoked one device at a time:
each device delegation lasts at most 31 days, but whoever holds the agent's
root can keep issuing new ones. Registering it with `frozen` status blocks it.
Revoking the hosting daemon, or removing its `hosts_held_agents` grant, cuts
off all unregistered ones at once.

## Request digests (0.4.0)

Two forms of `Approval.request_digest`, each under its own tag:

- `request_digest` (`request-digest.v1`): a requester that can carry a
  subject and always has a host daemon, an instance and an action.
- `client_request_digest` (`client-request-digest.v1`): a requester that
  connects with a self-rooted chain (no subject), with an optional host and an
  optional resource. An absent host covers both `Host::Hostless` and
  `Host::Unhosted`; the requester principal already fixes its kind.

0.4.0 is additive: `ALL_TAGS` grew (its length is part of its type, which is
why this was a minor bump). Nothing existing changes meaning.

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

## What it owns

- **Types:** `PublicKey` (SEC1 uncompressed P-256, validated),
  `PublicKeyDuo`, `PrincipalId` (`p256:<130 lowercase hex>`), `ShortId`
  (first 8 bytes of SHA-256 over the genesis key), and a typed `Error`.
  `PublicKey::thumbprint()` gives the RFC 7638 JWK thumbprint, the `key_id` for a `p256:` key.
- **Proto** (`proto/identitycrypto/v1/identity.proto`, reached as
  `identity_crypto::pb`): keys, delegations, signer chains, signed messages
  and documents, approvals, revocations.
- **Transcripts** (`identity_crypto::transcripts`): the exact bytes every
  signature covers, fourteen functions under `identitycrypto.*.v1` tags. Each
  validates while it encodes; signer and verifier call the same function.
- **`verify_p256`:** 64-byte `r||s`, both S forms, returning a
  `VerifiedSignature` witness bound to the key and the message.
- **Key builders** (`keys`, see below): the delegation, proof, rotation and
  revocation signatures over those transcripts, with the device window cap.

Every primitive comes from [`rust_jwk_duo`](https://github.com/qtpi-bonding-org/rust_jwk_duo), re-exported as
`identity_crypto::jwk_duo`. Sign transcripts with the `keys` builders (below),
not with `jwk_duo` directly, so the window caps and transcript rules apply.

## Keys

Builders for a self-rooted principal's signatures, generic over `Signer` and
re-exported at the root from `src/keys.rs`. No I/O, no clock (the caller
passes `now`), no key generation or storage.

- `signing_public`, `encryption_public`, `principal_id`: the public halves of a
  duo, and the principal id a genesis duo starts.
- `delegate_device(root, genesis, &PublicKeyDuo, issued, not_after)`: a
  root-signed DEVICE delegation for an Agent, Daemon, or Service device. The span
  must be positive and at most `MAX_DELEGATION_SECONDS` (31 days), the cap the
  verifier applies to unlisted devices.
- `device_delegation` (unsigned) and `sign_key_delegation`: no cap. For a
  Human's device or an approval key, whose window may be longer.
- `renewal_due(d, now, margin)`: whether a delegation is inside its renewal
  margin.
- `challenge_proof`, `rename_proof`, `rotation`, `revocation`: the signed
  proofs over their transcripts.

A builder whose signer fails returns `Error::Signer(...)`; a key pair with no
private half is `Error::Signer(SignerError::Unavailable)`. Builders never panic.

## Testkit

The `testkit` feature (off by default) compiles `identity_crypto::testkit`:
real keys, real signatures and fixtures (`TestKey`, `Principal`, `Fleet`,
`sign_test_document`, signed messages, delegations). `TestKey` was called
`testkit::Signer` before 0.11.0. Enable it in `[dev-dependencies]` only:

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
