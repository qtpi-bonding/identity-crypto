use crate::error::KeyfileError;
use crate::files::ROOT_FILE;
use std::path::{Path, PathBuf};

/// Where an identity's files live. `single(dir)` is the classic layout. In a
/// split layout `root_dir` holds only `root.jwk.json` (and its `.lock`);
/// every other file, `rotations.json` included, is in `device_dir`, the
/// folder an agent may be shown. One root_dir per identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityLayout {
    root_dir: PathBuf,
    device_dir: PathBuf,
}

impl IdentityLayout {
    /// The classic layout: every file in `dir`.
    pub fn single(dir: &Path) -> Self {
        Self {
            root_dir: dir.to_path_buf(),
            device_dir: dir.to_path_buf(),
        }
    }

    /// Both paths absolute; root_dir neither equal to device_dir nor inside it.
    pub fn split(root_dir: &Path, device_dir: &Path) -> Result<Self, KeyfileError> {
        if !root_dir.is_absolute() || !device_dir.is_absolute() {
            return Err(KeyfileError::InvalidLayout("paths must be absolute"));
        }
        if root_dir.starts_with(device_dir) {
            return Err(KeyfileError::InvalidLayout(
                "root_dir must not be device_dir or inside it",
            ));
        }
        Ok(Self {
            root_dir: root_dir.to_path_buf(),
            device_dir: device_dir.to_path_buf(),
        })
    }

    pub fn root_dir(&self) -> &Path {
        &self.root_dir
    }

    pub fn device_dir(&self) -> &Path {
        &self.device_dir
    }

    pub fn is_split(&self) -> bool {
        self.root_dir != self.device_dir
    }

    /// The folder that holds the file called `name`.
    pub(crate) fn dir_of(&self, name: &str) -> &Path {
        if name == ROOT_FILE {
            &self.root_dir
        } else {
            &self.device_dir
        }
    }
}
