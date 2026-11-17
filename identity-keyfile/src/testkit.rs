use crate::{IdentityKeys, IdentityLayout, KeyfileError, KeysHome};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

/// Returns lowercase hexadecimal, padded standard base64, and unpadded base64url forms.
pub fn secret_forms(bytes: &[u8]) -> Vec<String> {
    let hex = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    let standard = base64_encode(bytes, false, true);
    let url = base64_encode(bytes, true, false);
    vec![hex, standard, url]
}

fn base64_encode(bytes: &[u8], url: bool, padding: bool) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    for chunk in bytes.chunks(3) {
        let first = chunk[0] as usize;
        result.push(TABLE[first >> 2] as char);
        let second = if chunk.len() > 1 {
            chunk[1] as usize
        } else {
            0
        };
        result.push(TABLE[((first & 3) << 4) | (second >> 4)] as char);
        if chunk.len() > 1 {
            let third = if chunk.len() > 2 {
                chunk[2] as usize
            } else {
                0
            };
            result.push(TABLE[((second & 15) << 2) | (third >> 6)] as char);
            if chunk.len() > 2 {
                result.push(TABLE[third & 63] as char);
            } else if padding {
                result.push('=');
            }
        } else if padding {
            result.push_str("==");
        }
    }
    if url {
        result = result.replace('+', "-").replace('/', "_");
    }
    result
}

/// Extracts private JWK member values in document order, recursively.
pub fn jwk_private_values(document: &str) -> Vec<String> {
    let mut values = Vec::new();
    let mut deserializer = serde_json::Deserializer::from_str(document);
    serde::de::Deserializer::deserialize_any(
        &mut deserializer,
        PrivateValuesVisitor {
            values: &mut values,
        },
    )
    .unwrap_or_else(|error| panic!("invalid JSON: {error}"));
    deserializer
        .end()
        .unwrap_or_else(|error| panic!("invalid JSON: {error}"));
    values
}

struct PrivateValuesVisitor<'a> {
    values: &'a mut Vec<String>,
}

impl<'de, 'a> serde::de::Visitor<'de> for PrivateValuesVisitor<'a> {
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a JSON value")
    }

    fn visit_str<E>(self, _value: &str) -> Result<(), E>
    where
        E: serde::de::Error,
    {
        Ok(())
    }

    fn visit_string<E>(self, _value: String) -> Result<(), E>
    where
        E: serde::de::Error,
    {
        Ok(())
    }

    fn visit_bool<E>(self, _value: bool) -> Result<(), E>
    where
        E: serde::de::Error,
    {
        Ok(())
    }

    fn visit_i64<E>(self, _value: i64) -> Result<(), E>
    where
        E: serde::de::Error,
    {
        Ok(())
    }

    fn visit_u64<E>(self, _value: u64) -> Result<(), E>
    where
        E: serde::de::Error,
    {
        Ok(())
    }

    fn visit_f64<E>(self, _value: f64) -> Result<(), E>
    where
        E: serde::de::Error,
    {
        Ok(())
    }

    fn visit_none<E>(self) -> Result<(), E>
    where
        E: serde::de::Error,
    {
        Ok(())
    }

    fn visit_unit<E>(self) -> Result<(), E>
    where
        E: serde::de::Error,
    {
        Ok(())
    }

    fn visit_map<M>(self, mut map: M) -> Result<(), M::Error>
    where
        M: serde::de::MapAccess<'de>,
    {
        while let Some(name) = map.next_key::<String>()? {
            if matches!(name.as_str(), "d" | "p" | "q" | "dp" | "dq" | "qi" | "k") {
                let value = map.next_value::<serde_json::Value>()?;
                if let Some(value) = value.as_str() {
                    self.values.push(value.to_owned());
                }
            } else {
                map.next_value_seed(PrivateValuesSeed {
                    values: self.values,
                })?;
            }
        }
        Ok(())
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<(), A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        while sequence
            .next_element_seed(PrivateValuesSeed {
                values: self.values,
            })?
            .is_some()
        {}
        Ok(())
    }
}

struct PrivateValuesSeed<'a> {
    values: &'a mut Vec<String>,
}

impl<'de, 'a> serde::de::DeserializeSeed<'de> for PrivateValuesSeed<'a> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<(), D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        deserializer.deserialize_any(PrivateValuesVisitor {
            values: self.values,
        })
    }
}

/// Panics with the index if any non-empty secret occurs in `haystack`.
pub fn assert_no_secret(haystack: &str, secrets: &[String]) {
    for (index, secret) in secrets.iter().enumerate() {
        if !secret.is_empty() && haystack.contains(secret) {
            panic!("secret found at index {index}");
        }
    }
}

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

/// A temporary split-layout keys home exposing only one initialized device.
#[must_use = "dropping a DeviceOnlyHome deletes the temporary keys home"]
pub struct DeviceOnlyHome {
    parent: tempfile::TempDir,
    home: KeysHome,
    device: std::path::PathBuf,
}

impl DeviceOnlyHome {
    /// Creates a device-only fixture and locks its root directory.
    pub fn new(name: &str, now: i64, ttl_seconds: i64) -> Self {
        let parent = tempfile::tempdir().expect("create temporary keys home parent");
        std::fs::set_permissions(parent.path(), std::fs::Permissions::from_mode(0o700))
            .expect("make the temporary keys home parent private");
        let home = KeysHome::at(parent.path().join("keys"));
        let root = home.root_dir();
        let device = home
            .device_dir(name)
            .expect("validate temporary device name");
        std::fs::create_dir_all(&root).expect("create temporary keys root");
        std::fs::create_dir_all(&device).expect("create temporary device directory");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
            .expect("make temporary keys root private");
        std::fs::set_permissions(&device, std::fs::Permissions::from_mode(0o700))
            .expect("make temporary device directory private");
        let layout = IdentityLayout::split(&root, &device).expect("create split identity layout");
        IdentityKeys::init_at(&layout, now, ttl_seconds)
            .expect("initialize temporary device identity");
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o000))
            .expect("lock temporary keys root");
        Self {
            parent,
            home,
            device,
        }
    }

    /// The keys home handle.
    pub fn home(&self) -> KeysHome {
        self.home.clone()
    }

    /// The initialized device directory.
    pub fn device_dir(&self) -> std::path::PathBuf {
        self.device.clone()
    }

    /// The temporary parent directory.
    pub fn path(&self) -> std::path::PathBuf {
        self.parent.path().to_path_buf()
    }
}

impl Drop for DeviceOnlyHome {
    fn drop(&mut self) {
        let _ =
            std::fs::set_permissions(self.home.root_dir(), std::fs::Permissions::from_mode(0o700));
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
