/// Why a trusted-device lookup failed. The two cases map to different answers:
/// `Unknown` is an authentication failure, `Unavailable` is a service outage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum LookupError {
    #[error("no trusted devices for this principal")]
    Unknown,
    #[error("the trusted-device lookup is unavailable")]
    Unavailable,
}

/// Why a request was refused. Each variant is a distinct cause; a service maps
/// them to its own coded errors through `on_reject`.
#[derive(Debug, thiserror::Error, PartialEq, Eq, coded_error::CodedError)]
#[coded(namespace = "identity.request_auth")]
#[non_exhaustive]
pub enum AuthError {
    #[error("the audience does not match this method")]
    #[coded(code = "audience", class = Logical, grpc = Unauthenticated)]
    Audience,
    #[error("the body type does not match this method")]
    #[coded(code = "body_type", class = Logical, grpc = Unauthenticated)]
    BodyType,
    #[error("no body type is known for method {0}")]
    #[coded(code = "unknown_method", class = Logical, grpc = Unauthenticated)]
    UnknownMethod(String),
    #[error(
        "method {0} streams its request; only unary and server-streaming methods can be signed"
    )]
    #[coded(code = "streaming_request", class = Logical, grpc = Unimplemented)]
    StreamingRequestUnsupported(String),
    #[error("the signed message has no signature")]
    #[coded(code = "empty_signature", class = Logical, grpc = Unauthenticated)]
    EmptySignature,
    #[error("no signer authority is configured")]
    #[coded(code = "not_set_up", class = Infrastructure, grpc = Unauthenticated)]
    NotSetUp,
    #[error("the nonce must be 16 bytes, got {0}")]
    #[coded(code = "nonce_length", class = Logical, grpc = Unauthenticated)]
    NonceLength(usize),
    #[error("the request bytes differ from the signed body")]
    #[coded(code = "body_mismatch", class = Logical, grpc = Unauthenticated)]
    BodyMismatch,
    #[error("the request body is {len} bytes; the limit is {max}")]
    #[coded(code = "body_too_large", class = Logical, grpc = ResourceExhausted)]
    BodyTooLarge { len: usize, max: usize },
    #[error("the clock tolerance must be 1 to {max} seconds, got {seconds}")]
    #[coded(code = "tolerance", class = Infrastructure, grpc = Unauthenticated)]
    Tolerance { seconds: i64, max: i64 },
    #[error("the message is outside the clock tolerance")]
    #[coded(code = "skew", class = Logical, grpc = Unauthenticated)]
    Skew,
    #[error("the request was issued before this server started, so the replay cache cannot vouch for it")]
    #[coded(code = "issued_before_start", class = Logical, grpc = Unauthenticated)]
    IssuedBeforeStart,
    #[error("this nonce was already used")]
    #[coded(code = "replayed", class = Logical, grpc = Unauthenticated)]
    Replayed,
    #[error("the nonce cache is full")]
    #[coded(code = "busy", class = Transient, grpc = ResourceExhausted)]
    Busy,
    #[error("the author is not a trusted principal")]
    #[coded(code = "unknown_author", class = Logical, grpc = Unauthenticated)]
    UnknownAuthor,
    #[error("the trusted-device lookup is unavailable")]
    #[coded(code = "lookup_unavailable", class = Transient, grpc = Unavailable)]
    LookupUnavailable,
    #[error("malformed request: {0}")]
    #[coded(code = "malformed", class = Logical, grpc = Unauthenticated)]
    Malformed(&'static str),
    #[error("the signed message does not verify: {0}")]
    #[coded(code = "verify", class = Logical, grpc = Unauthenticated)]
    Verify(identity_crypto::Error),
    #[error("cannot mint a session credential: {0}")]
    #[coded(code = "credential", class = Infrastructure, grpc = Internal)]
    Credential(identity_crypto::Error),
    #[error("no entropy for a nonce: {0}")]
    #[coded(code = "entropy", class = Infrastructure, grpc = Internal)]
    Entropy(String),
    #[error("the session certificate has expired")]
    #[coded(code = "session_expired", class = Transient, grpc = Unauthenticated)]
    SessionExpired,
    #[error("no caller is attached to this request")]
    #[coded(code = "no_caller", class = Infrastructure, grpc = Unauthenticated)]
    NoCaller,
    #[error("the request cannot be signed: {0}")]
    #[coded(code = "unsignable_request", class = Logical, grpc = InvalidArgument)]
    UnsignableRequest(&'static str),
}
