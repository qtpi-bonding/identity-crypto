# identity-crypto

Canonical transcript encoding and ed25519 verification shared by grorg,
gait, and multimatrix's agent-identity design (see
`concordat/2026-09-01-agent-identity-model-design.md` in the `concordium`
monorepo for the full design this implements).

## Scope

This crate is deliberately narrow:

- `transcripts::{self_proof_transcript, delegation_transcript, revocation_transcript, rotation_transcript, session_delegation_transcript}`
  — pure functions building the exact byte layout each signature covers.
- `verify_ed25519` / `hex_decode_32` — raw signature verification and a
  decode helper.

No RPC calls, no storage, no key generation or key storage. Each consumer
repo keeps that on its own side. This exists purely so there is exactly one
implementation of the byte-level transcript layout — three independent
copies of ~150 lines of bit-fiddling code, all required to agree
byte-for-byte, is a bug class review has to keep catching by hand; one
shared implementation removes it by construction.

## Status

Extracted from `grorg`'s implementation plan for the identity model
(2026-09-01) at the design's request, before any of grorg/gait/multimatrix
built their own independent copy. Currently consumed as a local path
dependency; a real git remote is forthcoming.
