use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum KeyfileError {
    #[error("I/O at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("cannot parse {path}: {msg}")]
    Parse { path: PathBuf, msg: String },
    #[error("cryptographic error: {0}")]
    Crypto(#[from] identity_crypto::Error),
    #[error("missing keyfile {0}")]
    Missing(PathBuf),
    #[error("device delegation does not match the device")]
    DelegationMismatch,
    #[error("insecure agent directory {0}")]
    InsecureDir(PathBuf),
    #[error("agent directory is already initialised: {0}")]
    AlreadyInitialised(PathBuf),
}

pub(crate) fn io(path: impl Into<PathBuf>, source: std::io::Error) -> KeyfileError {
    KeyfileError::Io {
        path: path.into(),
        source,
    }
}
