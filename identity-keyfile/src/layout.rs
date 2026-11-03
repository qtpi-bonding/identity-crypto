use crate::error::KeyfileError;
use crate::files::ROOT_FILE;
use std::io::ErrorKind;
use std::path::{Component, Path, PathBuf};

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

    /// Both paths absolute and free of `.` and `..` components. They are compared
    /// after resolving symlinks (a path that does not exist yet is resolved
    /// through its nearest existing ancestor): `root_dir` must not be
    /// `device_dir`, inside it, or contain it. The paths as given are kept.
    pub fn split(root_dir: &Path, device_dir: &Path) -> Result<Self, KeyfileError> {
        if !root_dir.is_absolute() || !device_dir.is_absolute() {
            return Err(KeyfileError::InvalidLayout("paths must be absolute"));
        }
        for path in [root_dir, device_dir] {
            if path
                .components()
                .any(|c| matches!(c, Component::CurDir | Component::ParentDir))
            {
                return Err(KeyfileError::InvalidLayout(
                    "paths must not contain . or .. components",
                ));
            }
        }
        let root = resolve(root_dir)?;
        let device = resolve(device_dir)?;
        if root.starts_with(&device) {
            return Err(KeyfileError::InvalidLayout(
                "root_dir must not be device_dir or inside it",
            ));
        }
        if device.starts_with(&root) {
            return Err(KeyfileError::InvalidLayout(
                "device_dir must not be inside root_dir",
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

/// `path` with symlinks resolved. The nearest existing ancestor is
/// canonicalised and the components that do not exist yet are appended.
fn resolve(path: &Path) -> Result<PathBuf, KeyfileError> {
    let mut missing = Vec::new();
    let mut ancestor = path;
    loop {
        match ancestor.canonicalize() {
            Ok(mut resolved) => {
                resolved.extend(missing.iter().rev());
                return Ok(resolved);
            }
            Err(e) if e.kind() == ErrorKind::NotFound => {
                let (Some(parent), Some(name)) = (ancestor.parent(), ancestor.file_name()) else {
                    return Err(crate::error::io(path, e));
                };
                missing.push(name);
                ancestor = parent;
            }
            Err(e) => return Err(crate::error::io(ancestor, e)),
        }
    }
}
