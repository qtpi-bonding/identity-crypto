//! The machine identity directory: where the owner's own identity and the
//! machine-level index live. Its location comes from the environment.

use crate::error::KeyfileError;
use crate::private_fs;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// The environment variable that overrides the machine identity directory.
pub const MACHINE_IDENTITY_DIR_ENV: &str = "MACHINE_IDENTITY_DIR";

/// The machine identity directory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MachineDir {
    path: PathBuf,
}

impl MachineDir {
    /// `$MACHINE_IDENTITY_DIR`, else `$XDG_DATA_HOME/machine-identity`, else
    /// `$HOME/.local/share/machine-identity`. Empty values count as unset. A
    /// relative result is `InvalidLayout`.
    pub fn locate() -> Result<Self, KeyfileError> {
        Self::locate_with(|name| std::env::var_os(name))
    }

    /// [`MachineDir::locate`] with the environment supplied by `var`.
    pub fn locate_with(var: impl Fn(&str) -> Option<OsString>) -> Result<Self, KeyfileError> {
        let get = |name: &str| var(name).filter(|value| !value.is_empty());
        let path = if let Some(explicit) = get(MACHINE_IDENTITY_DIR_ENV) {
            PathBuf::from(explicit)
        } else if let Some(xdg) = get("XDG_DATA_HOME") {
            PathBuf::from(xdg).join("machine-identity")
        } else if let Some(home) = get("HOME") {
            PathBuf::from(home)
                .join(".local")
                .join("share")
                .join("machine-identity")
        } else {
            return Err(KeyfileError::MachineDirUnresolved);
        };
        if !path.is_absolute() {
            return Err(KeyfileError::InvalidLayout(
                "machine identity dir must be absolute",
            ));
        }
        Ok(Self { path })
    }

    /// A machine directory at `path`. Nothing is checked or created.
    pub fn at(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// The directory itself.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Creates the directory (mode 0700) when missing, then checks it.
    pub fn ensure(&self) -> Result<(), KeyfileError> {
        private_fs::create_private_dir(&self.path)
    }
}
