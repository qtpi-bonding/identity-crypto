# identity-request-auth

Per-request signing and verification over `identity-crypto`. Each request
carries one `SignedMessage` (`signed-message.v1`), signed by a short-lived
session key. The signature covers the audience (`"<service>:<method>@<server id>"`),
the body type, the exact request bytes and a 16-byte nonce. A replay cache
refuses a nonce seen twice inside the skew window.

Two layers:

* **The core** (default features): synchronous, no `async`, no `Send`/`Sync`
  requirement, no lock, no tonic/tower/tokio. `open_signed_request` checks one
  request against any `SignerVerifier` (identity-crypto's `Resolver` for the full
  chain, or a `TrustedDeviceSet` for one author's device keys) and a
  caller-owned `NonceCache`. `RequestSigner` / `seal_request` is the sending side.
* **The `tonic` feature** (`grpc`): built only on the core. The async
  `TrustedDevices` source (with its TTL cache), `Verifier`, and the tower layers
  `SignRequests` (client) and `RequestAuthLayer` (server).

Nothing here names a service: audience and body-type strings come from the caller.

## Core constraints

A fleet wire that already has its own verifier must be able to switch to this
core with its own tests unchanged. These hold, and each has a test in
`src/tests/constraints.rs` that runs without the `tonic` feature:

* **C1. A plain sync verifier.** `open_signed_request` takes a `&impl
  SignerVerifier` (a `&Resolver` works as it is) and `now`, and uses
  identity-crypto's `When::Live { now }`. The async, TTL-cached
  `TrustedDevices` source lives only in the `tonic` layer. The core needs no
  async, no `Send`/`Sync` (the test uses an `Rc`-holding verifier) and no
  internal lock: `NonceCache::insert` is `&mut self`.
* **C2. The replay cache.** `NonceCache::insert(session_key, nonce, issued_at,
  now)` returns `Fresh | Replayed | Busy`, with caps of 256 per key and 4096 in
  total and identity-crypto's `SKEW_SECONDS` (30) and `PURGE_GRACE` (30). A
  replay at exactly `issued_at + 30` and `+ 60` is still `Replayed`; it is
  accepted again only after the grace. Keyed by session key and nonce.
* **C3. Opaque strings.** The audience and the body type are caller-supplied
  strings, compared for equality only: never formatted, parsed or constrained.
  (`audience_for` is a convenience for the gRPC layer; the core does not call it.)
* **C4. Distinguishable errors.** The cheap checks run before any chain work, each
  with its own `AuthError`, in this order: `Audience`, `BodyType`, `EmptySignature`,
  `NonceLength`; then the signer check (`NotSetUp` for `None`, `Verify(inner)` with
  the identity-crypto error kept, `UnknownAuthor`); then the tolerance (`Skew`),
  then `BodyMismatch` (the request that arrived is not the one that was signed).

`Skew` is only this crate's own tighter `ClockTolerance` (1 to 30 s; it can only
tighten). A message outside identity-crypto's own 30 s is `Verify(Error::Skew)`.

## The tonic layer

* A request is one message; the signature covers the message inside the gRPC
  length prefix.
* **Client-streaming and bidirectional methods are refused**, on both sides,
  before any of the body is read (`StreamingRequestUnsupported`, `UNIMPLEMENTED`).
  Say which methods stream with `method_kinds`: **a method not named there is
  `Unary`**, so an undeclared client-streaming method is not refused (it is read
  as one message and hangs or fails with a malformed frame). The streaming check
  runs before the body-type lookup on both sides, so a streaming method is refused
  as streaming even when it has no body type.
* A **server-streaming** response ends with `UNAUTHENTICATED` in its trailers at
  `VerifiedCaller::session_not_after`, including a stream that is idle then.
* A **pass-through** method (`allow_unsigned` on the server, `pass_through` on the
  client) is skipped entirely: checked before any buffering or hashing, so its
  body is not size-limited either.
* Every other body is buffered up to `MAX_BODY_BYTES` (4 MiB), on both sides.
* `RequestSigner` re-mints its session at 60% of its life, after expiry, or when
  the clock has gone back to before the held session's start.

### Restart replay (`reject_issued_before`)

The nonce cache is in memory, so a request captured before a server restart could
be replayed for up to 30 s after it. `RequestAuthLayer` therefore refuses a signed
request whose `issued_at` is earlier than `reject_issued_before`
(`AuthError::IssuedBeforeStart`, its own variant, separate from `Skew`; `UNAUTHENTICATED`
by default, with its own message). The default is the clock's time when the layer
was built, and the comparison is strict: a request issued in the same second as
construction is accepted. To opt out, set `reject_issued_before(0)` (the epoch).

Caveat: right after a restart, a client whose clock lags the server's by up to 30 s
is refused until its clock passes the layer's construction time.

### Throughput ceiling

`NonceCaps::total` (4096 by default) caps the replay cache for the whole service,
not per caller. A nonce is kept for about 60 s, so the service accepts at most
about 68 signed requests a second (4096 / 60) across all callers; past that,
requests are refused as `Busy` (`RESOURCE_EXHAUSTED`).

### Refusal to gRPC status (`default_reject`)

| refusal | status |
|---|---|
| `LookupUnavailable` | `UNAVAILABLE` |
| `BodyTooLarge`, `Busy` | `RESOURCE_EXHAUSTED` |
| `StreamingRequestUnsupported` | `UNIMPLEMENTED` |
| `Entropy`, `Credential` | `INTERNAL` |
| everything else (`IssuedBeforeStart` included) | `UNAUTHENTICATED` |

A service passes its own `on_reject` for coded errors.

### Implementing `TrustedDevices`

The lookup runs before the signature is checked, so an unauthenticated caller can
ask for any principal. Cache `Unknown` (negative lookups) so that costs one read;
**never cache `Unavailable`**, so an outage does not become cached rejections after
recovery; and you may rate-limit.

## CI

CI runs both `cargo test -p identity-request-auth` and
`cargo test -p identity-request-auth --features tonic`, and clippy with
`-D warnings` on both feature sets.
