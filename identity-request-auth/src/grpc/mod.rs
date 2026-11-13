//! The tonic/tower layer, built only from the transport-free core.
//!
//! The client ([`SignRequests`]) buffers one unary request, signs its message
//! bytes and attaches the `SignedMessage` as the binary metadata header
//! [`REQUEST_HEADER`]. The server ([`RequestAuthLayer`]) reads that header,
//! buffers the request, checks it through [`crate::Verifier`] and puts the
//! [`crate::VerifiedCaller`] in the request extensions.
//!
//! Both sides sign and check the message inside the gRPC length prefix: the
//! prefix is stripped, and the bytes after it are what the signature covers.

use crate::MAX_BODY_BYTES;
use crate::{
    audience_for, seal_request, split_path, AuthError, Clock, RequestSigner, TrustedDevices,
    Verifier,
};
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

type BoxFuture<T, E> = Pin<Box<dyn Future<Output = Result<T, E>> + Send>>;

/// The default mapping from a refusal to a gRPC status. A service that wants
/// its own coded errors passes its own `on_reject` instead.
pub fn default_reject(err: AuthError) -> Status {
    let message = err.to_string();
    match err {
        AuthError::LookupUnavailable => Status::unavailable(message),
        AuthError::BodyTooLarge { .. } | AuthError::Busy => Status::resource_exhausted(message),
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

/// Client layer: signs each unary request for `server_id`.
#[derive(Clone)]
pub struct SignRequests {
    signer: Arc<RequestSigner>,
    server_id: Arc<str>,
    body_type_of: BodyTypeOf,
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
        }
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
            // A method with no known body type is not a signed method: it goes
            // out unsigned, and the server decides whether that is allowed.
            let (Some((service, method)), Some(body_type)) =
                (split_path(&path), (config.body_type_of)(&path))
            else {
                return inner.call(Request::from_parts(parts, body)).await;
            };

            let framed = match body.collect().await {
                Ok(collected) => collected.to_bytes(),
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
    allow_unsigned: Arc<dyn Fn(&str) -> bool + Send + Sync>,
    on_reject: Arc<dyn Fn(AuthError) -> Status + Send + Sync>,
}

/// Server layer: refuses any request to a non-allow-listed method unless its
/// signed message verifies.
pub struct RequestAuthLayer<K> {
    config: Arc<Config<K>>,
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
        Self {
            config: Arc::new(Config {
                verifier,
                clock,
                server_id: Arc::from(server_id.into()),
                body_type_of: Arc::new(body_type_of),
                allow_unsigned: Arc::new(allow_unsigned),
                on_reject: Arc::new(on_reject),
            }),
        }
    }
}

impl<S, K> Layer<S> for RequestAuthLayer<K> {
    type Service = RequireSigned<S, K>;

    fn layer(&self, inner: S) -> Self::Service {
        RequireSigned {
            inner,
            config: self.config.clone(),
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
            if (config.allow_unsigned)(&path) {
                return inner.call(Request::from_parts(parts, body)).await;
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

            let collected = match Limited::new(body, MAX_BODY_BYTES).collect().await {
                Ok(collected) => collected.to_bytes(),
                // The body was cut at the limit, so its full length is unknown; it is
                // reported as one byte over the limit.
                Err(e) if e.is::<LengthLimitError>() => {
                    return Ok(refused(
                        &config,
                        AuthError::BodyTooLarge {
                            len: MAX_BODY_BYTES + 1,
                            max: MAX_BODY_BYTES,
                        },
                    ))
                }
                Err(_) => return Ok(refused(&config, AuthError::Malformed("request body"))),
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

            parts.extensions.insert(caller);
            inner
                .call(Request::from_parts(parts, Body::new(Full::new(collected))))
                .await
        })
    }
}
