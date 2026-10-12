# identity-crypto

P-256 key types, principal ids, canonical transcripts and the signature
check for the concordium/structmux identity design (structmux
`docs/superpowers/specs/2026-10-11-daemon-mesh-schema-design.md`). Pure: no
I/O, no runtime, no key storage. Product-agnostic.

## What it owns

- **Types:** `PublicKey` (SEC1 uncompressed P-256, validated),
  `PublicKeyDuo`, `PrincipalId` (`p256:<130 lowercase hex>`), `ShortId`
  (first 8 bytes of SHA-256 over the genesis key), and a typed `Error`.
- **Proto** (`proto/identitycrypto/v1/identity.proto`, reached as
  `identity_crypto::pb`): keys, delegations, signer chains, signed messages
  and documents, approvals, revocations, the delivery attestation.
- **Transcripts** (`identity_crypto::transcripts`): the exact bytes every
  signature covers, twelve functions under `identitycrypto.*.v1` tags. Each
  validates while it encodes; signer and verifier call the same function.
- **`verify_p256`:** 64-byte `r‖s`, both S forms, returning a
  `VerifiedSignature` witness bound to the key and the message.

Every primitive comes from [`rust_jwk_duo`](https://github.com/qtpi-bonding-org/rust_jwk_duo), re-exported as
`identity_crypto::jwk_duo`; sign with it directly over transcript bytes.
Chain verification (`verify_signed_message` and friends) arrives in 0.3.

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
