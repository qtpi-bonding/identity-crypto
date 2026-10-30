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
    #[error("identity check failed: {0:?}")]
    VerifyFailed(VerifyCheck),
}

/// Which load-time check of `IdentityKeys::load_verified` (or `read_principal`) failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyCheck {
    /// `agent_id` is not the principal derived from the root signing key.
    AgentId,
    /// `delegation.principal_genesis` is not the root signing key.
    PrincipalGenesis,
    /// `delegation.signing_root` is not the root signing key.
    SigningRoot,
    /// `delegation.delegated` is not the device signing key.
    Delegated,
    /// `delegation.delegated_encryption` is not the device encryption key.
    DelegatedEncryption,
    /// `delegation.purpose` is not Device.
    Purpose,
    /// The delegation signature does not verify under the root.
    Signature,
}

pub(crate) fn io(path: impl Into<PathBuf>, source: std::io::Error) -> KeyfileError {
    KeyfileError::Io {
        path: path.into(),
        source,
    }
}
