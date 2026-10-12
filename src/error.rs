//! The crate's one error type. 1b adds variants (hence `non_exhaustive`).
//! `field` strings are the proto field path, or the Rust parameter name for
//! non-proto inputs.

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
