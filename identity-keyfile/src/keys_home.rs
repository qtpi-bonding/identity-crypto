//! The on-disk home for owner keys and device-only identities.

use crate::error::{io, KeyfileError};
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

/// A labelled home containing `root/` and `devices/<name>/`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeysHome {
    path: PathBuf,
}

impl KeysHome {
    /// Resolves `<config>/<dir_name>` using the XDG configuration rule.
    pub fn locate(dir_name: &str) -> Result<Self, KeyfileError> {
        Self::locate_with(dir_name, |name| std::env::var_os(name))
    }

    /// Resolves the home using an environment lookup supplied by the caller.
    pub fn locate_with(
        dir_name: &str,
        var: impl Fn(&str) -> Option<OsString>,
    ) -> Result<Self, KeyfileError> {
        if dir_name.is_empty() || dir_name.contains('/') || dir_name == "." || dir_name == ".." {
            return Err(KeyfileError::InvalidLayout(
                "invalid keys home directory name",
            ));
        }
        let get = |name: &str| var(name).filter(|value| !value.is_empty());
        let config = if let Some(xdg) = get("XDG_CONFIG_HOME") {
            PathBuf::from(xdg)
        } else if let Some(home) = get("HOME") {
            PathBuf::from(home).join(".config")
        } else {
            return Err(KeyfileError::KeysHomeUnresolved);
        };
        let path = config.join(dir_name);
        if !path.is_absolute() {
            return Err(KeyfileError::InvalidLayout("keys home must be absolute"));
        }
        Ok(Self { path })
    }

    /// Creates a handle at `path` without checking or creating anything.
    pub fn at(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// The home directory itself.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The root-key directory.
    pub fn root_dir(&self) -> PathBuf {
        self.path.join("root")
    }

    /// Lists the UTF-8 subdirectory names under `devices`, in sorted order.
    pub fn devices(&self) -> Result<Vec<String>, KeyfileError> {
        let dir = self.path.join("devices");
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(io(dir, error)),
        };
        let mut names = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|error| io(&dir, error))?;
            let file_type = entry.file_type().map_err(|error| io(entry.path(), error))?;
            if file_type.is_dir() {
                if let Some(name) = entry.file_name().to_str() {
                    names.push(name.to_owned());
                }
            }
        }
        names.sort();
        Ok(names)
    }

    /// Returns the path for a device name, refusing path-shaped names.
    pub fn device_dir(&self, name: &str) -> Result<PathBuf, KeyfileError> {
        if name.is_empty()
            || name.contains('/')
            || name.contains('\\')
            || name.contains('\0')
            || name == "."
            || name == ".."
        {
            return Err(KeyfileError::InvalidLayout("device name is invalid"));
        }
        Ok(self.path.join("devices").join(name))
    }
}
