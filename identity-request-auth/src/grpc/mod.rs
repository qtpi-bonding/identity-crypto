//! The tonic/tower layer, built only from the transport-free core.
//!
//! The client ([`SignRequests`]) buffers one unary or server-streaming request,
//! signs its message bytes and attaches the `SignedMessage` as the binary
//! metadata header [`REQUEST_HEADER`]. The server ([`RequestAuthLayer`]) reads
//! that header, buffers the request, checks it through [`Verifier`] and puts the
//! [`crate::VerifiedCaller`] in the request extensions.
//!
//! Both sides sign and check the message inside the gRPC length prefix: the
//! prefix is stripped, and the bytes after it are what the signature covers.
//!
//! # What is signed, and what is not
//!
//! * A request is one message. **Client-streaming and bidirectional methods
//!   cannot be signed** (a signature covers one message): both layers refuse
//!   them with [`AuthError::StreamingRequestUnsupported`] before reading any of
//!   the body. Say which methods stream with `method_kinds`.
//! * A **server-streaming** response ends with `UNAUTHENTICATED` in its
//!   trailers at [`crate::VerifiedCaller::session_not_after`]: a stream does not
//!   outlive the session that opened it.
//! * A **pass-through** method (the server's `allow_unsigned`, the client's
//!   `pass_through`) is skipped entirely: checked before anything is buffered or
//!   hashed, so its body is neither size-limited nor read by these layers.
//! * Any other body is buffered up to a limit, on both sides: [`MAX_BODY_BYTES`]
//!   by default, or what `max_body` sets (`None` for no limit). The core itself
//!   applies no limit; this layer passes its own to it.

mod client;
mod devices;
mod expiry;
mod verifier;

#[cfg(feature = "client")]
pub use client::{AudienceSource, ChannelError, DiscoverAudience, SignedChannel};
pub use client::{endpoint_defaults, CONNECT_TIMEOUT, KEEPALIVE_INTERVAL, KEEPALIVE_TIMEOUT};
pub use devices::TrustedDevices;
pub use verifier::Verifier;

use crate::MAX_BODY_BYTES;
use crate::{audience_for, seal_request, split_path, AuthError, Clock, RequestSigner, VerifiedCaller};
use expiry::ExpiringBody;
use http::{Request, Response};
use http_body_util::{BodyExt, Full, LengthLimitError, Limited};
use identity_crypto::pb;
use prost::Message;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tonic::body::Body;
use tonic::metadata::{MetadataMap, MetadataValue};
use tonic::Status;
use tower::{Layer, Service};

/// The binary metadata header that carries the signed message (`-bin`, so tonic
/// base64-encodes it).
pub const REQUEST_HEADER: &str = "x-request-bin";

/// Maps a gRPC path to the proto type URL of its request message.
pub type BodyTypeOf = Arc<dyn Fn(&str) -> Option<&'static str> + Send + Sync>;

/// How a method moves its messages.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum MethodKind {
    /// One request, one response. The default for every method.
    #[default]
    Unary,
    /// One request, a stream of responses: the stream ends at the session's end.
    ServerStreaming,
    /// A stream of requests. Cannot be signed: refused.
    ClientStreaming,
    /// Streams both ways. Cannot be signed: refused.
    Bidi,
}

impl MethodKind {
    fn streams_request(self) -> bool {
        matches!(self, Self::ClientStreaming | Self::Bidi)
    }
}

type KindOf = Arc<dyn Fn(&str) -> MethodKind + Send + Sync>;

fn all_unary() -> KindOf {
    Arc::new(|_| MethodKind::Unary)
}

type BoxFuture<T, E> = Pin<Box<dyn Future<Output = Result<T, E>> + Send>>;

/// The source label stamped on every coded refusal this crate sends.
pub const REJECT_SOURCE: &str = "identity-request-auth";

/// The default mapping from a refusal to a coded gRPC status: the status code
/// and the `x-error-code` metadata both come from the refusal's `CodedError`
/// table. A service that wants its own coded errors passes its own `on_reject`.
pub fn default_reject(err: AuthError) -> Status {
    coded_error::grpc::to_status(&err, REJECT_SOURCE)
}

/// Strips the gRPC length prefix from one uncompressed message.
fn unframe(bytes: &[u8]) -> Result<&[u8], AuthError> {
    if bytes.len() < 5 {
        return Err(AuthError::Malformed("gRPC frame header"));
    }
    if bytes[0] != 0 {
        return Err(AuthError::Malformed("compressed gRPC frame"));
    }
    let len = u32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as usize;
    let message = &bytes[5..];
    if message.len() != len {
        return Err(AuthError::Malformed("gRPC frame length"));
    }
    Ok(message)
}

/// Reads a whole framed request body (the 5-byte prefix plus the message), refusing
/// one whose message is over `max_body` (`None`: no limit). `max_body` counts the
/// message bytes only, so the buffer is cut at `max + 5`, and a longer message is
/// refused with its real length.
async fn buffer(body: Body, max_body: Option<usize>) -> Result<bytes::Bytes, AuthError> {
    let Some(max) = max_body else {
        return match body.collect().await {
            Ok(collected) => Ok(collected.to_bytes()),
            Err(_) => Err(AuthError::Malformed("request body")),
        };
    };
    match Limited::new(body, max.saturating_add(5)).collect().await {
        Ok(collected) => {
            let framed = collected.to_bytes();
            let message_len = framed.len().saturating_sub(5);
            if message_len > max {
                return Err(AuthError::BodyTooLarge {
                    len: message_len,
                    max,
                });
            }
            Ok(framed)
        }
        Err(e) if e.is::<LengthLimitError>() => Err(AuthError::BodyTooLarge {
            len: max.saturating_add(1), // the cut proves at least one byte over
            max,
        }),
        Err(_) => Err(AuthError::Malformed("request body")),
    }
}

/// Client layer: signs each unary or server-streaming request for `server_id`.
#[derive(Clone)]
pub struct SignRequests {
    signer: Arc<RequestSigner>,
    server_id: Arc<str>,
    body_type_of: BodyTypeOf,
    kind_of: KindOf,
    pass_through: Arc<dyn Fn(&str) -> bool + Send + Sync>,
    max_body: Option<usize>,
}

impl SignRequests {
    pub fn new(
        signer: Arc<RequestSigner>,
        server_id: impl Into<String>,
        body_type_of: impl Fn(&str) -> Option<&'static str> + Send + Sync + 'static,
    ) -> Self {
        Self {
            signer,
            server_id: Arc::from(server_id.into()),
            body_type_of: Arc::new(body_type_of),
            kind_of: all_unary(),
            pass_through: Arc::new(|_| false),
            max_body: Some(MAX_BODY_BYTES),
        }
    }

    /// The largest request body this layer buffers before signing it; `None`
    /// means no limit. The default is `Some(`[`MAX_BODY_BYTES`]`)`.
    pub fn max_body(mut self, limit: Option<usize>) -> Self {
        self.max_body = limit;
        self
    }

    /// Says which methods stream. A client-streaming or bidirectional method is
    /// refused with [`AuthError::StreamingRequestUnsupported`] before its body is
    /// read. Every method not named is [`MethodKind::Unary`].
    pub fn method_kinds(
        mut self,
        kind_of: impl Fn(&str) -> MethodKind + Send + Sync + 'static,
    ) -> Self {
        self.kind_of = Arc::new(kind_of);
        self
    }

    /// Methods to send as they are, never signed: the body is neither buffered nor
    /// hashed. Use it for the same methods the server allows unsigned.
    pub fn pass_through(mut self, skip: impl Fn(&str) -> bool + Send + Sync + 'static) -> Self {
        self.pass_through = Arc::new(skip);
        self
    }
}

impl<S> Layer<S> for SignRequests {
    type Service = SignedClient<S>;

    fn layer(&self, inner: S) -> Self::Service {
        SignedClient {
            inner,
            config: self.clone(),
        }
    }
}

/// The client service built by [`SignRequests`].
#[derive(Clone)]
pub struct SignedClient<S> {
    inner: S,
    config: SignRequests,
}

impl<S> Service<Request<Body>> for SignedClient<S>
where
    S: Service<Request<Body>, Response = Response<Body>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
{
    type Response = Response<Body>;
    type Error = S::Error;
    type Future = BoxFuture<Response<Body>, S::Error>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), S::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let config = self.config.clone();
        Box::pin(async move {
            let (mut parts, body) = req.into_parts();
            let path = parts.uri.path().to_owned();
            // A pass-through method is skipped before anything else: its body is
            // not touched.
            if (config.pass_through)(&path) {
                return inner.call(Request::from_parts(parts, body)).await;
            }
            // A streaming request cannot be signed whether or not its body type
            // is known: refused before anything else, and unread.
            if (config.kind_of)(&path).streams_request() {
                return Ok(default_reject(AuthError::StreamingRequestUnsupported(path)).into_http());
            }
            // A method with no known body type is not a signed method: it goes
            // out unsigned, and the server decides whether that is allowed.
            let (Some((service, method)), Some(body_type)) =
                (split_path(&path), (config.body_type_of)(&path))
            else {
                return inner.call(Request::from_parts(parts, body)).await;
            };

            let framed = match buffer(body, config.max_body).await {
                Ok(framed) => framed,
                Err(AuthError::Malformed(_)) => {
                    return Ok(default_reject(AuthError::UnsignableRequest("request body")).into_http())
                }
                Err(e) => return Ok(default_reject(e).into_http()),
            };
            let message = match unframe(&framed) {
                Ok(message) => message,
                Err(_) => {
                    return Ok(default_reject(AuthError::UnsignableRequest("gRPC frame header")).into_http())
                }
            };
            let audience = audience_for(service, method, &config.server_id);
            let signed = match seal_request(&config.signer, &audience, body_type, message) {
                Ok(signed) => signed,
                Err(e) => return Ok(default_reject(e).into_http()),
            };

            let mut metadata = MetadataMap::from_headers(std::mem::take(&mut parts.headers));
            metadata.insert_bin(
                REQUEST_HEADER,
                MetadataValue::from_bytes(&signed.encode_to_vec()),
            );
            parts.headers = metadata.into_headers();
            inner
                .call(Request::from_parts(parts, Body::new(Full::new(framed))))
                .await
        })
    }
}

/// What the server layer checks, shared by every clone of the service.
struct Config<K> {
    verifier: Arc<Verifier<K>>,
    clock: Arc<dyn Clock>,
    server_id: Arc<str>,
    body_type_of: BodyTypeOf,
    kind_of: KindOf,
    allow_unsigned: Arc<dyn Fn(&str) -> bool + Send + Sync>,
    on_reject: Arc<dyn Fn(AuthError) -> Status + Send + Sync>,
    reject_issued_before: i64,
    max_body: Option<usize>,
    caller_extension: Option<CallerExtension>,
}

impl<K> Clone for Config<K> {
    fn clone(&self) -> Self {
        Self {
            verifier: self.verifier.clone(),
            clock: self.clock.clone(),
            server_id: self.server_id.clone(),
            body_type_of: self.body_type_of.clone(),
            kind_of: self.kind_of.clone(),
            allow_unsigned: self.allow_unsigned.clone(),
            on_reject: self.on_reject.clone(),
            reject_issued_before: self.reject_issued_before,
            max_body: self.max_body,
            caller_extension: self.caller_extension.clone(),
        }
    }
}

/// Inserts a caller-derived extension into the request, given the verified caller.
type CallerExtension = Arc<dyn Fn(&VerifiedCaller, &mut http::Extensions) + Send + Sync>;

/// Server layer: refuses any request to a non-allow-listed method unless its
/// signed message verifies.
pub struct RequestAuthLayer<K> {
    config: Config<K>,
}

impl<K> Clone for RequestAuthLayer<K> {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
        }
    }
}

/// The verified caller of a request that passed the layer; a coded
/// `no_caller` refusal otherwise.
// `Status` is the error type of every tonic handler; the signature is part of the API.
#[allow(clippy::result_large_err)]
pub fn caller<T>(request: &tonic::Request<T>) -> Result<&VerifiedCaller, Status> {
    request
        .extensions()
        .get::<VerifiedCaller>()
        .ok_or_else(|| default_reject(AuthError::NoCaller))
}

impl<K: TrustedDevices> RequestAuthLayer<K> {
    pub fn new(
        verifier: Arc<Verifier<K>>,
        clock: Arc<dyn Clock>,
        server_id: impl Into<String>,
        body_type_of: impl Fn(&str) -> Option<&'static str> + Send + Sync + 'static,
        allow_unsigned: impl Fn(&str) -> bool + Send + Sync + 'static,
        on_reject: impl Fn(AuthError) -> Status + Send + Sync + 'static,
    ) -> Self {
        let reject_issued_before = clock.now().seconds;
        Self {
            config: Config {
                verifier,
                clock,
                server_id: Arc::from(server_id.into()),
                body_type_of: Arc::new(body_type_of),
                kind_of: all_unary(),
                allow_unsigned: Arc::new(allow_unsigned),
                on_reject: Arc::new(on_reject),
                reject_issued_before,
                max_body: Some(MAX_BODY_BYTES),
                caller_extension: None,
            },
        }
    }

    /// Refuses a signed request whose `issued_at` is earlier than
    /// `unix_seconds` ([`AuthError::IssuedBeforeStart`]); the comparison is
    /// strict, so a request issued at exactly that second is accepted.
    ///
    /// The default is the clock's time when this layer was built. The nonce
    /// cache lives in memory, so a request captured before a restart would
    /// otherwise be replayable until it ages out of the 30 s skew window; this
    /// closes that. Pass `0` (the epoch) to opt out.
    pub fn reject_issued_before(mut self, unix_seconds: i64) -> Self {
        self.config.reject_issued_before = unix_seconds;
        self
    }

    /// The largest request message, in bytes, this layer accepts. The limit counts
    /// the message only, not the 5-byte gRPC frame prefix, on the server and the
    /// client alike; `None` means no limit. The default is `Some(`[`MAX_BODY_BYTES`]`)`.
    pub fn max_body(mut self, limit: Option<usize>) -> Self {
        self.config.max_body = limit;
        self
    }

    /// Says which methods stream. A client-streaming or bidirectional method is
    /// refused with [`AuthError::StreamingRequestUnsupported`] before its body is
    /// read; the response of a server-streaming method ends when the caller's
    /// session does. Every method not named is [`MethodKind::Unary`].
    pub fn method_kinds(
        mut self,
        kind_of: impl Fn(&str) -> MethodKind + Send + Sync + 'static,
    ) -> Self {
        self.config.kind_of = Arc::new(kind_of);
        self
    }
}

impl<S, K> Layer<S> for RequestAuthLayer<K> {
    type Service = RequireSigned<S, K>;

    fn layer(&self, inner: S) -> Self::Service {
        RequireSigned {
            inner,
            config: Arc::new(self.config.clone()),
        }
    }
}

impl<K: TrustedDevices> RequestAuthLayer<K> {
    /// After a request verifies, inserts `f(&caller)` into its extensions next to
    /// the [`VerifiedCaller`], so a handler can read a type of its own choosing.
    pub fn caller_extension<X: Clone + Send + Sync + 'static>(
        mut self,
        f: impl Fn(&VerifiedCaller) -> X + Send + Sync + 'static,
    ) -> Self {
        self.config.caller_extension = Some(Arc::new(move |caller, extensions| {
            extensions.insert(f(caller));
        }));
        self
    }
}

/// The server service built by [`RequestAuthLayer`].
pub struct RequireSigned<S, K> {
    inner: S,
    config: Arc<Config<K>>,
}

impl<S: Clone, K> Clone for RequireSigned<S, K> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            config: self.config.clone(),
        }
    }
}

/// The response for a refused request: a gRPC error in the headers, HTTP 200.
fn refused<K>(config: &Config<K>, err: AuthError) -> Response<Body> {
    (config.on_reject)(err).into_http()
}

impl<S, K> Service<Request<Body>> for RequireSigned<S, K>
where
    S: Service<Request<Body>, Response = Response<Body>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
    K: TrustedDevices + 'static,
{
    type Response = Response<Body>;
    type Error = S::Error;
    type Future = BoxFuture<Response<Body>, S::Error>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), S::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let config = self.config.clone();
        Box::pin(async move {
            let (mut parts, body) = req.into_parts();
            // Nothing a request arrives with may pass for a verified caller.
            parts.extensions.remove::<VerifiedCaller>();
            let path = parts.uri.path().to_owned();
            // A pass-through method is skipped before anything else: no
            // buffering, no hashing, no size limit.
            if (config.allow_unsigned)(&path) {
                return inner.call(Request::from_parts(parts, body)).await;
            }

            // Streaming is refused first, registered or not: the body type of a
            // method that cannot be signed is beside the point.
            let kind = (config.kind_of)(&path);
            if kind.streams_request() {
                return Ok(refused(
                    &config,
                    AuthError::StreamingRequestUnsupported(path),
                ));
            }
            let Some((service, method)) = split_path(&path) else {
                return Ok(refused(&config, AuthError::UnknownMethod(path.clone())));
            };
            let Some(body_type) = (config.body_type_of)(&path) else {
                return Ok(refused(&config, AuthError::UnknownMethod(path.clone())));
            };

            let metadata = MetadataMap::from_headers(parts.headers.clone());
            let signed = match metadata.get_bin(REQUEST_HEADER).map(|v| v.to_bytes()) {
                Some(Ok(bytes)) => match pb::SignedMessage::decode(bytes) {
                    Ok(signed) => signed,
                    Err(_) => {
                        return Ok(refused(
                            &config,
                            AuthError::Malformed("signed request header"),
                        ))
                    }
                },
                Some(Err(_)) => {
                    return Ok(refused(
                        &config,
                        AuthError::Malformed("signed request header"),
                    ))
                }
                None => {
                    return Ok(refused(
                        &config,
                        AuthError::Malformed("missing signed request header"),
                    ))
                }
            };

            let collected = match buffer(body, config.max_body).await {
                Ok(collected) => collected,
                Err(e) => return Ok(refused(&config, e)),
            };
            let message = match unframe(&collected) {
                Ok(message) => message,
                Err(e) => return Ok(refused(&config, e)),
            };

            let audience = audience_for(service, method, &config.server_id);
            let caller = match config
                .verifier
                .open_signed_request(
                    &signed,
                    &audience,
                    body_type,
                    message,
                    config.max_body,
                    config.clock.now(),
                    config.reject_issued_before,
                )
                .await
            {
                Ok(caller) => caller,
                Err(e) => return Ok(refused(&config, e)),
            };

            let not_after = caller.session_not_after();
            if let Some(extend) = &config.caller_extension {
                extend(&caller, &mut parts.extensions);
            }
            parts.extensions.insert(caller);
            let response = inner
                .call(Request::from_parts(parts, Body::new(Full::new(collected))))
                .await?;
            Ok(match kind {
                MethodKind::ServerStreaming => response.map(|body| {
                    Body::new(ExpiringBody::new(body, config.clock.clone(), not_after))
                }),
                _ => response,
            })
        })
    }
}
