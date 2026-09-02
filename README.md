# identity-crypto

Canonical transcript encoding and ed25519 verification shared by grorg,
gait, and multimatrix's agent-identity design (see
`concordat/2026-09-01-agent-identity-model-design.md` in the `concordium`
monorepo for the full design this implements).

## Scope

This crate is deliberately narrow — it owns exactly the pieces of the
design that no single one of grorg/gait/multimatrix actually owns:

- `transcripts::{self_proof_transcript, delegation_transcript, revocation_transcript, rotation_transcript, session_delegation_transcript}`
  — pure functions building the exact byte layout each signature covers.
- `verify_ed25519` / `hex_decode_32` — raw signature verification and a
  decode helper.
- `KeyScheme` / `DelegationCert` (generated from
  `proto/identitycrypto/v1/identity.proto`) — `KeyScheme` used to be
  independently (and only accidentally consistently) redefined in all
  three repos' own protos; `DelegationCert` is minted locally by whichever
  harness signs a session key and isn't stored by anyone, so it has no
  natural owner either. Import this package's proto directly rather than
  redefining these two.

Everything else stays with its one real owner: grorg's `Agent`/`AgentKey`
and its RPC surface, gait's `Event`/`Provenance` log format, multimatrix's
`RoomMessage`/`AuthoredMessage` — none of that moves here. No RPC calls, no
storage, no key generation/storage. The point of centralizing what's here
is that a single wrong byte in a transcript layout, or a numeric drift in
a discriminant embedded in one, breaks every cross-repo signature; one
shared implementation removes that whole class of bug by construction
instead of relying on review to catch independently-written copies
drifting apart.

## Status

Extracted from `grorg`'s implementation plan for the identity model
(2026-09-01) at the design's request, before any of grorg/gait/multimatrix
built their own independent copy. Currently consumed as a local path
dependency; a real git remote is forthcoming.
