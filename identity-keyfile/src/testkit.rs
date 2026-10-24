use crate::{AgentKeys, KeyfileError};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

/// A temporary initialized agent directory for consumer tests. Dropping it
/// deletes the directory and its keys, unless [`TempAgentDir::keep`] is called.
#[must_use = "dropping a TempAgentDir deletes the agent directory immediately"]
pub struct TempAgentDir {
    directory: tempfile::TempDir,
}

impl TempAgentDir {
    /// Creates a private temp directory and runs `AgentKeys::init` in it.
    /// Panics on failure, which is correct for a test fixture.
    pub fn new(now: i64, ttl_seconds: i64) -> Self {
        let directory = tempfile::tempdir().expect("create temporary agent directory");
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .expect("make the temporary agent directory private");
        AgentKeys::init(directory.path(), now, ttl_seconds)
            .expect("initialize temporary agent directory");
        Self { directory }
    }

    pub fn path(&self) -> &Path {
        self.directory.path()
    }

    pub fn load(&self) -> Result<AgentKeys, KeyfileError> {
        AgentKeys::load(self.path())
    }

    /// Disables the cleanup and returns the directory path. The caller now owns
    /// the directory and must remove it.
    pub fn keep(self) -> std::path::PathBuf {
        self.directory.keep()
    }
}
