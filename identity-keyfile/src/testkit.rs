use crate::{IdentityKeys, KeyfileError};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

/// A temporary initialized agent directory for consumer tests. Dropping it
/// deletes the directory and its keys, unless [`TempIdentityDir::keep`] is called.
#[must_use = "dropping a TempIdentityDir deletes the agent directory immediately"]
pub struct TempIdentityDir {
    directory: tempfile::TempDir,
}

/// A temporary 0700 parent holding a machine identity directory at
/// `<parent>/machine`, created and checked. Dropping it deletes everything.
#[must_use = "dropping a TempMachineDir deletes the machine directory immediately"]
pub struct TempMachineDir {
    parent: tempfile::TempDir,
}

impl TempMachineDir {
    /// Creates the private parent and the `machine` subdirectory (mode 0700).
    /// Panics on failure, which is correct for a test fixture.
    pub fn new() -> Self {
        let parent = tempfile::tempdir().expect("create temporary machine parent");
        std::fs::set_permissions(parent.path(), std::fs::Permissions::from_mode(0o700))
            .expect("make the temporary machine parent private");
        crate::MachineDir::at(parent.path().join("machine"))
            .ensure()
            .expect("create temporary machine identity directory");
        Self { parent }
    }

    /// The machine identity directory.
    pub fn machine(&self) -> crate::MachineDir {
        crate::MachineDir::at(self.parent.path().join("machine"))
    }

    /// The machine identity directory path.
    pub fn path(&self) -> std::path::PathBuf {
        self.parent.path().join("machine")
    }
}

impl Default for TempMachineDir {
    fn default() -> Self {
        Self::new()
    }
}

impl TempIdentityDir {
    /// Creates a private temp directory and runs `IdentityKeys::init` in it.
    /// Panics on failure, which is correct for a test fixture.
    pub fn new(now: i64, ttl_seconds: i64) -> Self {
        let directory = tempfile::tempdir().expect("create temporary agent directory");
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .expect("make the temporary agent directory private");
        IdentityKeys::init(directory.path(), now, ttl_seconds)
            .expect("initialize temporary agent directory");
        Self { directory }
    }

    pub fn path(&self) -> &Path {
        self.directory.path()
    }

    pub fn load(&self) -> Result<IdentityKeys, KeyfileError> {
        IdentityKeys::load(self.path())
    }

    /// Disables the cleanup and returns the directory path. The caller now owns
    /// the directory and must remove it.
    pub fn keep(self) -> std::path::PathBuf {
        self.directory.keep()
    }
}
