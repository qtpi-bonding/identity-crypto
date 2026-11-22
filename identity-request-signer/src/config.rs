//! Configuration: a private TOML file.

use crate::error::SignerError;
use serde::Deserialize;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

const MAX_CONFIG_BYTES: u64 = 1024 * 1024;
const DEFAULT_MAX_BODY: usize = 4_194_304;
const DEFAULT_MAX_LINE_BYTES: usize = 5_800_000;
const DEFAULT_READ_TIMEOUT_SECS: u64 = 5;

/// Reads a private TOML file: refuses a symlink, any group/other permission
/// bit, a file over 1 MiB, non-UTF-8 content and a TOML syntax error, always
/// with a fixed message that never echoes file content. Returns the parsed
/// table with any sections it contains.
pub fn read_private_toml(path: &Path) -> Result<toml::Table, SignerError> {
    if std::fs::symlink_metadata(path)
        .map_err(|_| SignerError::ConfigInvalid(String::from("cannot read config")))?
        .file_type()
        .is_symlink()
    {
        return Err(SignerError::ConfigInvalid(String::from(
            "config must not be a symlink",
        )));
    }
    let file = std::fs::File::open(path)
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
    let bytes = std::fs::read(path)
        .map_err(|_| SignerError::ConfigInvalid(String::from("cannot read config")))?;
    let text = String::from_utf8(bytes)
        .map_err(|_| SignerError::ConfigInvalid(String::from("config is not valid UTF-8")))?;
    toml::from_str(&text).map_err(|_| SignerError::ConfigInvalid(String::from("invalid config")))
}

fn default_max_body() -> usize {
    DEFAULT_MAX_BODY
}

fn default_max_line_bytes() -> usize {
    DEFAULT_MAX_LINE_BYTES
}

fn default_read_timeout_secs() -> u64 {
    DEFAULT_READ_TIMEOUT_SECS
}

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
    #[serde(default = "default_max_body")]
    max_body: usize,
    #[serde(default = "default_max_line_bytes")]
    max_line_bytes: usize,
    #[serde(default = "default_read_timeout_secs")]
    read_timeout_secs: u64,
}

impl Config {
    pub fn parse(text: &str) -> Result<Config, SignerError> {
        let table: toml::Table = toml::from_str(text)
            .map_err(|_| SignerError::ConfigInvalid(String::from("invalid config")))?;
        Self::from_table(table)
    }

    pub fn load(path: &Path) -> Result<Config, SignerError> {
        let table = read_private_toml(path)?;
        Self::from_table(table)
    }

    /// Builds a config from a parsed table, refusing unknown keys exactly as
    /// the direct deserializer did. Fixed message only: never echoes the table.
    pub fn from_table(table: toml::Table) -> Result<Config, SignerError> {
        toml::Value::Table(table)
            .try_into::<Config>()
            .map_err(|_| SignerError::ConfigInvalid(String::from("invalid config")))
    }

    pub fn validate(&self) -> Result<(), SignerError> {
        if self.server_id.as_deref() == Some("") {
            return Err(SignerError::EmptyServerId);
        }
        if self.expected_principal.is_empty() {
            return Err(SignerError::ConfigInvalid(String::from(
                "the expected principal must not be empty",
            )));
        }
        if self.identity_dir.as_os_str().is_empty() {
            return Err(SignerError::ConfigInvalid(String::from(
                "the identity directory must not be empty",
            )));
        }
        if self.socket.as_os_str().is_empty() {
            return Err(SignerError::ConfigInvalid(String::from(
                "the socket path must not be empty",
            )));
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
