use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
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
    #[error("insecure identity directory {0}")]
    InsecureDir(PathBuf),
    #[error("insecure key file {0}")]
    InsecureFile(PathBuf),
    /// Holds the path only: library parse text can echo key fragments.
    #[error("not a private key set: {0}")]
    NotAKeySet(PathBuf),
    #[error("agent directory is already initialised: {0}")]
    AlreadyInitialised(PathBuf),
    #[error("identity check failed: {0:?}")]
    VerifyFailed(VerifyCheck),
    #[error("the root on disk is not the current root of the device folder's identity")]
    RootMismatch,
    #[error("invalid identity layout: {0}")]
    InvalidLayout(&'static str),
    #[error("cannot serialize {path}: {msg}")]
    Serialize { path: PathBuf, msg: String },
    #[error("{0} is owned by another user")]
    WrongOwner(PathBuf),
    #[error("{0} is not a regular file")]
    NotAFile(PathBuf),
    #[error("{path} is larger than {cap} bytes")]
    TooLarge { path: PathBuf, cap: usize },
    #[error("mode {0:o} is not a private file mode")]
    InvalidMode(u32),
    #[error("{0} holds a root but no identity; adopt it explicitly")]
    OrphanRoot(PathBuf),
    #[error("{0} is a device-only identity directory and is never written")]
    DeviceOnly(PathBuf),
    #[error("the root is the owner's; it cannot be adopted as a service or agent identity")]
    OwnerRoot,
    #[error("the root is not the owner's")]
    NotOwnerRoot,
    #[error("{0} is inside the machine identity directory")]
    InsideMachineDir(PathBuf),
    #[error("the machine identity directory {0} does not exist; create it (mode 0700) or set MACHINE_IDENTITY_DIR")]
    MachineDirMissing(PathBuf),
    #[error("the machine identity directory cannot be resolved (no MACHINE_IDENTITY_DIR, XDG_DATA_HOME or HOME)")]
    MachineDirUnresolved,
    #[error("enrolments.json version {0} is not supported")]
    IndexVersion(u64),
    #[error("invalid enrolment key {0:?}")]
    InvalidEnrolmentKey(String),
    #[error("enrolment {key}: {check:?}")]
    EnrolmentMismatch { key: String, check: EnrolmentCheck },
    #[error("the owner principal is never enrolled")]
    OwnerEnrolment,
}

/// Which load-time check of `IdentityKeys::load_verified` (or `read_principal`) failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
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

/// Which check of an enrolment failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EnrolmentCheck {
    /// The enrolment directory is missing.
    DirMissing,
    /// The enrolment directory is not private (mode or symlink).
    DirInsecure,
    /// The enrolment directory is owned by another user.
    DirOwner,
    /// The stored principal id does not match.
    PrincipalId,
    /// The stored device key id does not match.
    DeviceKeyId,
}

pub(crate) fn io(path: impl Into<PathBuf>, source: std::io::Error) -> KeyfileError {
    KeyfileError::Io {
        path: path.into(),
        source,
    }
}
