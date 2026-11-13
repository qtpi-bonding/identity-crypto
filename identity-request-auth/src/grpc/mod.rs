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
//! * Any other body is buffered up to [`MAX_BODY_BYTES`], on both sides.

mod devices;
mod expiry;
mod verifier;

pub use devices::{LookupError, TrustedDevices};
pub use verifier::Verifier;

use crate::MAX_BODY_BYTES;
use crate::{audience_for, seal_request, split_path, AuthError, Clock, RequestSigner};
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

/// The default mapping from a refusal to a gRPC status. A service that wants
/// its own coded errors passes its own `on_reject` instead.
///
/// | refusal | status |
/// |---|---|
/// | `LookupUnavailable` | `UNAVAILABLE` |
/// | `BodyTooLarge`, `Busy` | `RESOURCE_EXHAUSTED` |
/// | `StreamingRequestUnsupported` | `UNIMPLEMENTED` |
/// | `Entropy`, `Credential` | `INTERNAL` |
/// | everything else, `IssuedBeforeStart` included | `UNAUTHENTICATED` |
///
/// Every `UNAUTHENTICATED` status carries the refusal's own message, which is how
/// `IssuedBeforeStart` is told from `Skew` here; a service that needs a code for
/// it maps the variant in its own `on_reject`.
pub fn default_reject(err: AuthError) -> Status {
    let message = err.to_string();
    match err {
        AuthError::LookupUnavailable => Status::unavailable(message),
        AuthError::BodyTooLarge { .. } | AuthError::Busy => Status::resource_exhausted(message),
        AuthError::StreamingRequestUnsupported(_) => Status::unimplemented(message),
        AuthError::Entropy(_) | AuthError::Credential(_) => Status::internal(message),
        _ => Status::unauthenticated(message),
    }
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

/// Reads a whole request body, refusing one over [`MAX_BODY_BYTES`]. The body is
/// cut at the limit, so the reported length of an over-limit body is one byte
/// over it.
async fn buffer(body: Body) -> Result<bytes::Bytes, AuthError> {
    match Limited::new(body, MAX_BODY_BYTES).collect().await {
        Ok(collected) => Ok(collected.to_bytes()),
        Err(e) if e.is::<LengthLimitError>() => Err(AuthError::BodyTooLarge {
            len: MAX_BODY_BYTES + 1,
            max: MAX_BODY_BYTES,
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
        }
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

            let framed = match buffer(body).await {
                Ok(framed) => framed,
                Err(e @ AuthError::BodyTooLarge { .. }) => {
                    return Ok(Status::resource_exhausted(e.to_string()).into_http())
                }
                Err(e) => {
                    return Ok(Status::internal(format!("cannot read the request: {e}")).into_http())
                }
            };
            let message = match unframe(&framed) {
                Ok(message) => message,
                Err(e) => return Ok(Status::invalid_argument(e.to_string()).into_http()),
            };
            let audience = audience_for(service, method, &config.server_id);
            let signed = match seal_request(&config.signer, &audience, body_type, message) {
                Ok(signed) => signed,
                Err(e) => return Ok(Status::internal(e.to_string()).into_http()),
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
        }
    }
}

/// Server layer: refuses any request to a non-allow-listed method unless its
/// signed message verifies.
pub struct RequestAuthLayer<K> {
    config: Config<K>,
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
        let reject_issued_before = clock.now_unix();
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

            let collected = match buffer(body).await {
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
                    config.clock.now_unix(),
                )
                .await
            {
                Ok(caller) => caller,
                Err(e) => return Ok(refused(&config, e)),
            };

            if caller.issued_at() < config.reject_issued_before {
                return Ok(refused(&config, AuthError::IssuedBeforeStart));
            }

            let not_after = caller.session_not_after();
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
