//! Why the request signer refused.

#[derive(Debug, thiserror::Error, coded_error::CodedError)]
#[coded(namespace = "identity.request_signer")]
#[non_exhaustive]
pub enum SignerError {
    #[error("the configuration is invalid: {0}")]
    #[coded(code = "config_invalid", class = Logical)]
    ConfigInvalid(String),
    #[error("the server id must not be empty")]
    #[coded(code = "empty_server_id", class = Logical)]
    EmptyServerId,
    #[error("the device key is the principal's root key; refusing")]
    #[coded(code = "root_key", class = Logical)]
    RootKey,
    #[error("this identity is not the expected principal")]
    #[coded(code = "principal_mismatch", class = Logical)]
    PrincipalMismatch,
    #[error("this principal is refused by configuration")]
    #[coded(code = "principal_refused", class = Logical)]
    PrincipalRefused,
    #[error("the socket directory is not usable: {0}")]
    #[coded(code = "socket_dir", class = Infrastructure)]
    SocketDir(String),
    #[error("refusing to run as root")]
    #[coded(code = "running_as_root", class = Infrastructure)]
    RunningAsRoot,
    #[error("the request body is too large")]
    #[coded(code = "body_too_large", class = Logical)]
    BodyTooLarge,
    #[error("the request line is too long")]
    #[coded(code = "line_too_long", class = Logical)]
    LineTooLong,
    #[error("the client did not send a line in time")]
    #[coded(code = "read_timeout", class = Transient)]
    ReadTimeout,
    #[error("malformed request: {0}")]
    #[coded(code = "bad_request", class = Logical)]
    BadRequest(String),
    #[error("the device delegation has expired")]
    #[coded(code = "delegation_expired", class = Logical)]
    Expired,
    #[error("unknown op")]
    #[coded(code = "unknown_op", class = Logical)]
    UnknownOp,
    #[error("the device keys cannot be used: {0}")]
    #[coded(code = "keys", class = Infrastructure)]
    Keys(String),
    #[error("internal error: {0}")]
    #[coded(code = "internal", class = Infrastructure)]
    Internal(String),
}
