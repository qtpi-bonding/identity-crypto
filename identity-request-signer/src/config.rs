//! Configuration: a private TOML file.

use crate::error::SignerError;
use serde::Deserialize;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

const MAX_CONFIG_BYTES: u64 = 1024 * 1024;
const DEFAULT_MAX_BODY: usize = 4_194_304;
const DEFAULT_MAX_LINE_BYTES: usize = 5_800_000;
const DEFAULT_READ_TIMEOUT_SECS: u64 = 5;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub identity_dir: PathBuf,
    pub expected_principal: String,
    #[serde(default)]
    pub refuse_principals: Vec<String>,
    pub socket: PathBuf,
    #[serde(default)]
    pub server_id: Option<String>,
    max_body: usize,
    max_line_bytes: usize,
    read_timeout_secs: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            identity_dir: PathBuf::new(),
            expected_principal: String::new(),
            refuse_principals: Vec::new(),
            socket: PathBuf::new(),
            server_id: None,
            max_body: DEFAULT_MAX_BODY,
            max_line_bytes: DEFAULT_MAX_LINE_BYTES,
            read_timeout_secs: DEFAULT_READ_TIMEOUT_SECS,
        }
    }
}

impl Config {
    pub fn parse(text: &str) -> Result<Config, SignerError> {
        toml::from_str(text).map_err(|_| SignerError::ConfigInvalid(String::from("invalid config")))
    }

    pub fn load(path: &Path) -> Result<Config, SignerError> {
        if std::fs::symlink_metadata(path)
            .map_err(|_| SignerError::ConfigInvalid(String::from("cannot read config")))?
            .file_type()
            .is_symlink()
        {
            return Err(SignerError::ConfigInvalid(String::from(
                "config must not be a symlink",
            )));
        }
        let mut file = std::fs::File::open(path)
            .map_err(|_| SignerError::ConfigInvalid(String::from("cannot read config")))?;
        let meta = file
            .metadata()
            .map_err(|_| SignerError::ConfigInvalid(String::from("cannot read config")))?;
        if meta.len() > MAX_CONFIG_BYTES {
            return Err(SignerError::ConfigInvalid(String::from(
                "config file is too large",
            )));
        }
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(SignerError::ConfigInvalid(String::from(
                "config file must be readable only by its owner",
            )));
        }
        let mut text = String::new();
        file.read_to_string(&mut text)
            .map_err(|_| SignerError::ConfigInvalid(String::from("config is not valid UTF-8")))?;
        Self::parse(&text)
    }

    pub fn validate(&self) -> Result<(), SignerError> {
        if self.server_id.as_deref() == Some("") {
            return Err(SignerError::EmptyServerId);
        }
        if self.max_body == 0 || self.max_line_bytes == 0 || self.read_timeout_secs == 0 {
            return Err(SignerError::ConfigInvalid(String::from(
                "limits must be positive",
            )));
        }
        if self.max_line_bytes < self.max_body * 4 / 3 {
            return Err(SignerError::ConfigInvalid(String::from(
                "the line limit must be at least 4/3 of the body limit",
            )));
        }
        Ok(())
    }

    pub fn max_body(&self) -> usize {
        self.max_body
    }

    pub fn max_line_bytes(&self) -> usize {
        self.max_line_bytes
    }

    pub fn read_timeout_secs(&self) -> u64 {
        self.read_timeout_secs
    }
}
