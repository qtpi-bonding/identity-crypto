# identity-crypto

P-256 key types, principal ids, canonical transcripts, the principal
registry and verification for the concordium/structmux identity design
(structmux `docs/superpowers/specs/2026-10-11-daemon-mesh-schema-design.md`;
verification: `2026-10-12-fleet-phase1b-identity-verification-design.md`).
Pure: no I/O, no clock, no key storage. Every primitive comes from
`rust_jwk_duo` (re-exported as [`jwk_duo`]); this crate owns byte layouts,
validation and verification.

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

Every primitive comes from [`rust_jwk_duo`](https://github.com/qtpi-bonding-org/rust_jwk_duo), re-exported as
`identity_crypto::jwk_duo`; sign with it directly over transcript bytes.

## Vectors

`vectors/gen.py` is an independent Python implementation of every
transcript. It writes `transcripts.json`, `principals.json` and
`signatures.json`, which `tests/vectors.rs` checks. To regenerate:

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
