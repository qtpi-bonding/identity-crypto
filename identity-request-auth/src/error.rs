/// Why a request was refused. Each variant is a distinct cause; a service maps
/// them to its own coded errors through `on_reject`.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthError {
    #[error("the audience does not match this method")]
    Audience,
    #[error("the body type does not match this method")]
    BodyType,
    #[error("no body type is known for method {0}")]
    UnknownMethod(String),
    #[error(
        "method {0} streams its request; only unary and server-streaming methods can be signed"
    )]
    StreamingRequestUnsupported(String),
    #[error("the signed message has no signature")]
    EmptySignature,
    #[error("no signer authority is configured")]
    NotSetUp,
    #[error("the nonce must be 16 bytes, got {0}")]
    NonceLength(usize),
    #[error("the request bytes differ from the signed body")]
    BodyMismatch,
    #[error("the request body is {len} bytes; the limit is {max}")]
    BodyTooLarge { len: usize, max: usize },
    #[error("the clock tolerance must be 1 to {max} seconds, got {seconds}")]
    Tolerance { seconds: i64, max: i64 },
    #[error("the message is outside the clock tolerance")]
    Skew,
    #[error("this nonce was already used")]
    Replayed,
    #[error("the nonce cache is full")]
    Busy,
    #[error("the author is not a trusted principal")]
    UnknownAuthor,
    #[error("the trusted-device lookup is unavailable")]
    LookupUnavailable,
    #[error("malformed request: {0}")]
    Malformed(&'static str),
    #[error("the signed message does not verify: {0}")]
    Verify(identity_crypto::Error),
    #[error("cannot mint a session credential: {0}")]
    Credential(identity_crypto::Error),
    #[error("no entropy for a nonce: {0}")]
    Entropy(String),
}
