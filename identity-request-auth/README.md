# identity-request-auth

Version 0.2.0. Per-request signing and verification over `identity-crypto`. Each
request carries one `SignedMessage` (`signed-message.v1`), signed by a
short-lived session key. The signature covers the audience (`"<service>:<method>@<server id>"`),
the body type, the exact request bytes and a 16-byte nonce. A replay cache
refuses a nonce seen twice inside the skew window.

Three feature sets:

* **The core** (default features): synchronous, no `async`, no `Send`/`Sync`
  requirement, no lock, no tonic/tower/tokio. `open_signed_request` checks one
  request against any `SignerVerifier` (identity-crypto's `Resolver` for the full
  chain, or a `TrustedDeviceSet` for one author's device keys) and a
  caller-owned `NonceCache`. `RequestSigner` / `seal_request` is the sending side.
* **The `tonic` feature** (`grpc`): built only on the core. The async
  `TrustedDevices` source (with its TTL cache), `Verifier`, and the tower layers
  `SignRequests` (client) and `RequestAuthLayer` (server).
* **The `client` feature**: `tonic`, plus `identity-keyfile`, for a signed gRPC
  channel built from an identity directory (see below).

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
* **C5. The chain, when there is one.** `VerifiedSigner` has `chain:
  Option<VerifiedChain>`, and `VerifiedCaller::chain()` returns it. It is `Some`
  when a `Resolver` verified the request (the chain from `verify_signed_message`:
  `kind()`, `principal()`, `host()`) and `None` for a `TrustedDeviceSet`, which
  checks one author's device keys and never builds a chain.
* **C6. No size limit of its own.** `precheck_request`, `check_request` and
  `open_signed_request` take `max_body: Option<usize>`: `Some(n)` refuses a body
  over `n` bytes with `BodyTooLarge`, `None` makes no size check. `MAX_BODY_BYTES`
  (4 MiB) is a public constant and the default only in the tonic layer.
* **C7. `check_request` has no side effect.** It never touches a replay cache, so
  it can run twice on one message; `Checked` exposes `caller()`, `nonce()`,
  `issued_at()` and `session_key()` for a caller with its own replay store.
  `Checked::accept(&mut NonceCache, now)` is the only call that consumes the
  nonce.

`Skew` is only this crate's own tighter `ClockTolerance` (1 to 30 s; it can only
tighten). A message outside identity-crypto's own 30 s is `Verify(Error::Skew)`.

## Clock

`Clock` (`identity_request_auth::Clock`) has one required method,
`fn now(&self) -> Timestamp`, to the nanosecond. There is no default and no
seconds-only form, so an `impl Clock` without `now` does not compile. Calls read
`clock.now().seconds` for seconds. `SystemClock` returns
`identity_crypto::now_timestamp()`.

## Liveness

A device key is live at `at` (a `Timestamp` with real nanoseconds, passed
through from the clock) when all of these hold, compared as `(seconds, nanos)`:

* scheme ECDSA P-256 and purpose Device;
* `issued_at <= at`;
* `at < not_after`, when `not_after` is set;
* `at < revoked_at`, when `revoked_at` is set. A revocation at exactly `at` is
  refused, and so is one earlier in the same second.

`live_devices(&[KeyRecord], at)` returns the live keys. An empty result is
`LookupError::Unknown`, which the layer answers as `UNAUTHENTICATED`. A retired
agent therefore gives an empty slice and is `Unknown`. `LookupError` is
`identity_request_auth::LookupError` (`Unknown` or `Unavailable`).

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
  `VerifiedCaller::session_not_after`, including a stream that is idle then
  (`SessionExpired`).
* A **pass-through** method (`allow_unsigned` on the server, `pass_through` on the
  client) is skipped entirely: checked before any buffering or hashing, so its
  body is not size-limited either.
* Every other body is buffered up to a limit, on both sides: `MAX_BODY_BYTES` (4 MiB) by default, or what `max_body(Option<usize>)` sets on `RequestAuthLayer` and `SignRequests` (`None` for no limit).
* `RequestSigner` mints a session that lasts 300 s (`SESSION_SECONDS`). It re-mints
  at 60% of that life, after expiry, or when the clock has gone back to before the
  held session's start.

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

### AuthError codes

Every refusal is an `AuthError` with a code in the `identity.request_auth`
namespace (`identity.request_auth.<code>`) and a gRPC status. `default_reject`
maps each one through `coded_error::grpc::to_status` (source
`identity-request-auth`). A service passes its own `on_reject` for its own codes.

| Variant | Code | Class | gRPC status |
|---|---|---|---|
| `Audience` | `audience` | Logical | `UNAUTHENTICATED` |
| `BodyType` | `body_type` | Logical | `UNAUTHENTICATED` |
| `UnknownMethod` | `unknown_method` | Logical | `UNAUTHENTICATED` |
| `StreamingRequestUnsupported` | `streaming_request` | Logical | `UNIMPLEMENTED` |
| `EmptySignature` | `empty_signature` | Logical | `UNAUTHENTICATED` |
| `NotSetUp` | `not_set_up` | Infrastructure | `UNAUTHENTICATED` |
| `NonceLength` | `nonce_length` | Logical | `UNAUTHENTICATED` |
| `BodyMismatch` | `body_mismatch` | Logical | `UNAUTHENTICATED` |
| `BodyTooLarge` | `body_too_large` | Logical | `RESOURCE_EXHAUSTED` |
| `Tolerance` | `tolerance` | Infrastructure | `UNAUTHENTICATED` |
| `Skew` | `skew` | Logical | `UNAUTHENTICATED` |
| `IssuedBeforeStart` | `issued_before_start` | Logical | `UNAUTHENTICATED` |
| `Replayed` | `replayed` | Logical | `UNAUTHENTICATED` |
| `Busy` | `busy` | Transient | `RESOURCE_EXHAUSTED` |
| `UnknownAuthor` | `unknown_author` | Logical | `UNAUTHENTICATED` |
| `LookupUnavailable` | `lookup_unavailable` | Transient | `UNAVAILABLE` |
| `Malformed` | `malformed` | Logical | `UNAUTHENTICATED` |
| `Verify` | `verify` | Logical | `UNAUTHENTICATED` |
| `Credential` | `credential` | Infrastructure | `INTERNAL` |
| `Entropy` | `entropy` | Infrastructure | `INTERNAL` |
| `SessionExpired` | `session_expired` | Transient | `UNAUTHENTICATED` |
| `NoCaller` | `no_caller` | Infrastructure | `UNAUTHENTICATED` |
| `UnsignableRequest` | `unsignable_request` | Logical | `INVALID_ARGUMENT` |

The table is the contract: a refusal keeps its variant, code and status.

### Implementing `TrustedDevices`

The lookup runs before the signature is checked, so an unauthenticated caller can
ask for any principal. Cache `Unknown` (negative lookups) so that costs one read;
**never cache `Unavailable`**, so an outage does not become cached rejections after
recovery; and you may rate-limit. Build the result with `live_devices` (see Liveness).

## The `client` feature

`identity_request_auth::grpc::client` (with `client` enabled) builds signed client
channels:

* `endpoint_defaults(url)` gives a tonic `Endpoint` with a 10 s connect timeout
  (`CONNECT_TIMEOUT`), HTTP/2 keepalive every 20 s with a 10 s timeout
  (`KEEPALIVE_INTERVAL`, `KEEPALIVE_TIMEOUT`), keepalive while idle, and TCP
  keepalive at 20 s.
* `SignedChannel::from_identity_dir(dir, endpoint, audience, clock, layer)` loads
  the device keys from `dir` with `DeviceKeys::load`, so a device-only directory
  is enough and the root is never read. It connects, resolves the server id from
  `AudienceSource::Fixed(id)` or `AudienceSource::Discover(f)` (discovery runs on
  the unsigned channel), and wraps the channel in `layer(Arc<RequestSigner>,
  server_id)`.
* `ChannelError` (`identity.request_auth.channel`): `Identity` (`INTERNAL`),
  `Connect` (`UNAVAILABLE`), `Audience` (`UNAVAILABLE`).

## CI

Feature sets tested: default, `tonic`, and `client`. Clippy runs with
`-D warnings` on each.
