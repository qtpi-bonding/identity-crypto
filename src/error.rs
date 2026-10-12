//! The crate's one error type (non_exhaustive, so variants can be added).
//! `field` strings are the proto field path, or the Rust parameter name for
//! non-proto inputs.

use crate::PrincipalId;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    #[error("unsupported key scheme {0}")]
    UnsupportedScheme(i32),
    #[error("invalid public key: {0}")]
    InvalidKey(String),
    #[error("principal id is not canonical")]
    NonCanonicalPrincipal,
    #[error("malformed principal id: {0}")]
    MalformedPrincipal(String),
    #[error("malformed short id: {0}")]
    MalformedShortId(String),
    #[error("{field} must be {expected} bytes, got {actual}")]
    BadLength {
        field: &'static str,
        expected: usize,
        actual: usize,
    },
    #[error("{field} value {value} does not fit in one byte")]
    ScalarOutOfRange { field: &'static str, value: i64 },
    #[error("missing field {0}")]
    MissingField(&'static str),
    #[error("invalid {field}: {reason}")]
    InvalidField {
        field: &'static str,
        reason: &'static str,
    },
    #[error("keys must be distinct: {0}")]
    NotDistinct(&'static str),
    #[error("empty signature")]
    EmptySignature,
    #[error("signature does not verify")]
    BadSignature,
    #[error("document type is not the expected one")]
    WrongDocumentType,
    #[error("the signer is not the authority")]
    NotAuthority,
    #[error("signed by a retired root")]
    StaleRoot,
    #[error("root chain of {principal} forks from the accepted one")]
    RootFork { principal: PrincipalId },
    #[error("kind of {principal} changed")]
    KindChanged { principal: PrincipalId },
    #[error("a rotation chain repeats a key")]
    RotationCycle,
    #[error("signing key is not the current root")]
    NotCurrentRoot,
    #[error("invalid registry: {field}: {reason}")]
    InvalidRegistry { field: &'static str, reason: &'static str },
    #[error("unknown principal")]
    UnknownPrincipal,
    #[error("wrong principal kind")]
    WrongKind,
    #[error("principal is frozen")]
    Frozen,
    #[error("the device's host daemon is frozen")]
    HostFrozen,
    #[error("chain mismatch: {0}")]
    ChainMismatch(&'static str),
    #[error("key is revoked")]
    KeyRevoked,
    #[error("{0} has expired")]
    Expired(&'static str),
    #[error("{0} is not yet valid")]
    NotYetValid(&'static str),
    #[error("key is not bound to this principal's device")]
    NotBound,
    #[error("this host may not vouch for this agent")]
    NotVouched,
    #[error("wrong audience")]
    WrongAudience,
    #[error("issued_at is outside the 30-second window")]
    Skew,
    #[error("request id or digest does not match")]
    DigestMismatch,
    #[error("peer revocation is not allowed by the registry")]
    PeerRevocationDisabled,
    #[error("peer revocation is for another document")]
    StalePeerRevocation,
}

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_name_the_field() {
        let e = Error::BadLength { field: "nonce", expected: 16, actual: 15 };
        assert_eq!(e.to_string(), "nonce must be 16 bytes, got 15");
        assert_eq!(Error::MissingField("signer.chain").to_string(), "missing field signer.chain");
    }
}
