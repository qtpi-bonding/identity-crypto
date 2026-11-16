//! The machine identity directory: where service and machine identities and
//! the machine-level index live, and never the owner's own key. Its location
//! comes from the environment.

use crate::error::{EnrolmentCheck, KeyfileError};
use crate::files;
use crate::private_fs;
use crate::private_fs::effective_uid;
use identity_crypto::{pb, PrincipalId, PublicKey};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

/// The environment variable that overrides the machine identity directory.
pub const MACHINE_IDENTITY_DIR_ENV: &str = "MACHINE_IDENTITY_DIR";

/// The machine-level index file, inside the machine identity directory.
pub const ENROLMENTS_FILE: &str = "enrolments.json";

const INDEX_VERSION: u64 = 1;
const SERVICES_DIR: &str = "services";

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

/// Where a service's identity directory came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DirSource {
    /// A per-service setting such as `<SERVICE>_IDENTITY_DIR`.
    Override,
    /// The checked index entry in `enrolments.json`.
    Index,
    /// `machine/services/<encoded key>`.
    Default,
}

/// The identity directory for a machine/service key.
///
/// Precedence: `service_override` (absolute) > the checked index entry for
/// `key` > `machine/services/<encoded key>`, where `/` becomes `%2F` and `:`
/// becomes `%3A`. Agent identities never use this.
pub fn service_identity_dir(
    service_override: Option<&Path>,
    machine: &MachineDir,
    key: &str,
) -> Result<(PathBuf, DirSource), KeyfileError> {
    check_key(key)?;
    if let Some(dir) = service_override {
        if !dir.is_absolute() {
            return Err(KeyfileError::InvalidLayout(
                "service identity dir override must be absolute",
            ));
        }
        return Ok((dir.to_path_buf(), DirSource::Override));
    }
    if let Some(entry) = EnrolmentIndex::read(machine)?.checked(key)? {
        return Ok((entry.dir.clone(), DirSource::Index));
    }
    let encoded = key.replace('/', "%2F").replace(':', "%3A");
    Ok((
        machine.path().join(SERVICES_DIR).join(encoded),
        DirSource::Default,
    ))
}

/// One enrolled identity: the principal it must hold and where it lives.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Enrolment {
    // Fields are declared in alphabetical order: the file's keys are sorted.
    /// `PublicKey::thumbprint` of the delegated device signing key.
    pub device_key_id: String,
    /// The identity directory (absolute).
    pub dir: PathBuf,
    /// An optional endpoint the service is reached at.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// The principal, serialized as its canonical `p256:…` string.
    #[serde(with = "principal_string")]
    pub principal_id: PrincipalId,
}

/// Serde support: a principal as its canonical string.
mod principal_string {
    use identity_crypto::PrincipalId;

    pub fn serialize<S: serde::Serializer>(id: &PrincipalId, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(id)
    }

    pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<PrincipalId, D::Error> {
        let text = <String as serde::Deserialize>::deserialize(d)?;
        PrincipalId::parse_canonical(&text).map_err(serde::de::Error::custom)
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct IndexFile {
    services: BTreeMap<String, Enrolment>,
    version: u64,
}

/// The `enrolments.json` index: service key to enrolment.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EnrolmentIndex {
    services: BTreeMap<String, Enrolment>,
}

/// The lock file that guards `enrolments.json`.
fn index_path(machine: &MachineDir) -> PathBuf {
    machine.path().join(ENROLMENTS_FILE)
}

/// A service key: lowercase, starts with a letter or digit, 1 to 128 characters
/// of `[a-z0-9._:/-]`, with no `..`.
fn check_key(key: &str) -> Result<(), KeyfileError> {
    let bytes = key.as_bytes();
    let ok_first = bytes
        .first()
        .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
    let ok_rest = bytes.iter().all(|b| {
        b.is_ascii_lowercase()
            || b.is_ascii_digit()
            || matches!(b, b'.' | b'_' | b':' | b'/' | b'-')
    });
    if !ok_first || !ok_rest || bytes.len() > 128 || key.contains("..") {
        return Err(KeyfileError::InvalidEnrolmentKey(key.to_string()));
    }
    Ok(())
}

fn mismatch(key: &str, check: EnrolmentCheck) -> KeyfileError {
    KeyfileError::EnrolmentMismatch {
        key: key.to_string(),
        check,
    }
}

impl EnrolmentIndex {
    /// Reads the index. A missing file is an empty index. Takes a shared lock.
    pub fn read(machine: &MachineDir) -> Result<Self, KeyfileError> {
        match fs::symlink_metadata(machine.path()) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => return Err(crate::error::io(machine.path(), e)),
        }
        let _lock = files::lock_shared(machine.path())?;
        Self::read_locked(machine)
    }

    fn read_locked(machine: &MachineDir) -> Result<Self, KeyfileError> {
        let path = index_path(machine);
        let bytes = match private_fs::read_private_file(&path, private_fs::MAX_PUBLIC_FILE_BYTES) {
            Ok(bytes) => bytes,
            Err(KeyfileError::Missing(_)) => return Ok(Self::default()),
            Err(error) => return Err(error),
        };
        let value: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|e| KeyfileError::Parse {
                path: path.clone(),
                msg: e.to_string(),
            })?;
        let version = value.get("version").and_then(serde_json::Value::as_u64);
        if let Some(version) = version {
            if version != INDEX_VERSION {
                return Err(KeyfileError::IndexVersion(version));
            }
        }
        let file: IndexFile = serde_json::from_value(value).map_err(|e| KeyfileError::Parse {
            path,
            msg: e.to_string(),
        })?;
        Ok(Self {
            services: file.services,
        })
    }

    /// The entry for `key`, unchecked. Crate-internal: consumers use [`EnrolmentIndex::checked`].
    pub(crate) fn get(&self, key: &str) -> Option<&Enrolment> {
        self.services.get(key)
    }

    /// Every entry, unchecked, in key order.
    pub fn services(&self) -> impl Iterator<Item = (&str, &Enrolment)> {
        self.services.iter().map(|(k, v)| (k.as_str(), v))
    }

    /// The entry for `key` after the read checks: the directory exists, is
    /// private, is not a symlink and is owned by the effective user; its
    /// `agent_id` equals `principal_id`; and the delegated device key's
    /// thumbprint equals `device_key_id`. Reads only `agent_id` and
    /// `delegation.json`, never a private key.
    pub fn checked(&self, key: &str) -> Result<Option<&Enrolment>, KeyfileError> {
        let Some(entry) = self.get(key) else {
            return Ok(None);
        };
        check_entry(key, entry)?;
        Ok(Some(entry))
    }

    /// Records `entry` under `key`, replacing any old entry. Takes the exclusive
    /// lock on `machine/.lock`. Refuses `owner`'s principal and any entry that
    /// fails the read checks. Writes nothing inside `entry.dir`.
    pub fn enrol(
        machine: &MachineDir,
        key: &str,
        entry: Enrolment,
        owner: &PrincipalId,
    ) -> Result<(), KeyfileError> {
        check_key(key)?;
        if &entry.principal_id == owner {
            return Err(KeyfileError::OwnerEnrolment);
        }
        if !entry.dir.is_absolute() {
            return Err(KeyfileError::InvalidLayout(
                "enrolment dir must be absolute",
            ));
        }
        machine.ensure()?;
        let _lock = files::lock_exclusive(machine.path())?;
        check_entry(key, &entry)?;
        let mut index = Self::read_locked(machine)?;
        index.services.insert(key.to_string(), entry);
        index.write_locked(machine)
    }

    /// Removes `key`. Returns whether it was present. Takes the exclusive lock.
    pub fn remove(machine: &MachineDir, key: &str) -> Result<bool, KeyfileError> {
        machine.ensure()?;
        let _lock = files::lock_exclusive(machine.path())?;
        let mut index = Self::read_locked(machine)?;
        let existed = index.services.remove(key).is_some();
        if existed {
            index.write_locked(machine)?;
        }
        Ok(existed)
    }

    /// Writes the index. The caller holds the exclusive lock.
    fn write_locked(&self, machine: &MachineDir) -> Result<(), KeyfileError> {
        let file = IndexFile {
            version: INDEX_VERSION,
            services: self.services.clone(),
        };
        let path = index_path(machine);
        let mut text =
            serde_json::to_string_pretty(&file).map_err(|e| KeyfileError::Serialize {
                path: path.clone(),
                msg: e.to_string(),
            })?;
        text.push('\n');
        private_fs::write_private_atomic(&path, text.as_bytes(), 0o600)
    }
}

/// The read checks for one entry (see [`EnrolmentIndex::checked`]).
fn check_entry(key: &str, entry: &Enrolment) -> Result<(), KeyfileError> {
    check_entry_with_uid(key, entry, effective_uid())
}

/// [`check_entry`] against an explicit owner uid (the seam the tests drive).
pub(crate) fn check_entry_with_uid(
    key: &str,
    entry: &Enrolment,
    uid: u32,
) -> Result<(), KeyfileError> {
    let dir = entry.dir.as_path();
    match fs::symlink_metadata(dir) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(mismatch(key, EnrolmentCheck::DirMissing));
        }
        Err(error) => return Err(crate::error::io(dir, error)),
        Ok(meta) => {
            if !meta.is_dir() || std::os::unix::fs::MetadataExt::mode(&meta) & 0o077 != 0 {
                return Err(mismatch(key, EnrolmentCheck::DirInsecure));
            }
            if !owned_by(std::os::unix::fs::MetadataExt::uid(&meta), uid) {
                return Err(mismatch(key, EnrolmentCheck::DirOwner));
            }
        }
    }
    let agent_id = files::read_principal_id(dir)?;
    if agent_id != entry.principal_id {
        return Err(mismatch(key, EnrolmentCheck::PrincipalId));
    }
    let delegation = crate::files::read_delegation(dir)?;
    if thumbprint_of(&delegation).as_deref() != Some(entry.device_key_id.as_str()) {
        return Err(mismatch(key, EnrolmentCheck::DeviceKeyId));
    }
    Ok(())
}

/// Whether a directory owned by `uid` is owned by `owner`. Crate seam for the
/// DirOwner check, so tests can exercise it without changing real owners.
pub(crate) fn owned_by(dir_uid: u32, owner: u32) -> bool {
    dir_uid == owner
}

/// The thumbprint of `delegation.delegated`, when it is a valid key.
fn thumbprint_of(delegation: &pb::KeyDelegation) -> Option<String> {
    let wire = delegation.delegated.as_ref()?;
    let key = PublicKey::try_from(wire).ok()?;
    Some(key.thumbprint())
}

/// Builds an entry from an existing identity dir (reads `agent_id` and
/// `delegation.json` only).
pub fn enrolment_for(dir: &Path, endpoint: Option<String>) -> Result<Enrolment, KeyfileError> {
    let dir = std::path::absolute(dir).map_err(|e| crate::error::io(dir, e))?;
    let dir = dir.as_path();
    private_fs::check_private_dir(dir)?;
    let principal_id = files::read_principal_id(dir)?;
    let delegation = crate::files::read_delegation(dir)?;
    let device_key_id = thumbprint_of(&delegation).ok_or(KeyfileError::DelegationMismatch)?;
    Ok(Enrolment {
        principal_id,
        device_key_id,
        dir: dir.to_path_buf(),
        endpoint,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_grammar_accepts_and_refuses() {
        assert!(check_key("grorg").is_ok());
        assert!(check_key("structmux/3b6a27bcceb6a42d").is_ok());
        assert!(check_key("Grorg").is_err());
        assert!(check_key("a/../b").is_err());
        assert!(check_key(&"a".repeat(129)).is_err());
    }

    #[test]
    fn dir_owner_seam_refuses_other_uid() {
        let uid = effective_uid();
        assert!(owned_by(uid, uid));
        assert!(!owned_by(uid, uid.wrapping_add(1)));
    }

    #[test]
    fn check_entry_refuses_a_dir_owned_by_another_uid() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let entry = Enrolment {
            principal_id: identity_crypto::principal_id(&crate::generate()),
            device_key_id: "x".into(),
            dir: dir.path().to_path_buf(),
            endpoint: None,
        };
        let err = check_entry_with_uid("k", &entry, effective_uid().wrapping_add(1)).unwrap_err();
        assert!(
            matches!(
                err,
                KeyfileError::EnrolmentMismatch {
                    check: EnrolmentCheck::DirOwner,
                    ..
                }
            ),
            "{err:?}"
        );
    }

    #[test]
    fn enrolment_keys_are_sorted_with_an_endpoint() {
        let entry = Enrolment {
            principal_id: identity_crypto::principal_id(&crate::generate()),
            device_key_id: "d".into(),
            dir: PathBuf::from("/x"),
            endpoint: Some("e".into()),
        };
        let text = serde_json::to_string(&entry).unwrap();
        let at = |k: &str| text.find(&format!("\"{k}\"")).unwrap();
        assert!(at("device_key_id") < at("dir"));
        assert!(at("dir") < at("endpoint"));
        assert!(at("endpoint") < at("principal_id"));
    }
}
