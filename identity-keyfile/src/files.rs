use crate::error::{io, KeyfileError};
use identity_crypto::jwk_duo::{KeyDuo, KeyDuoSerializer};
use identity_crypto::{pb, PrincipalId};
use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(test)]
use std::cell::RefCell;
#[cfg(test)]
use std::ffi::OsStr;

pub const ROOT_FILE: &str = "root.jwk.json";
pub const DEVICE_FILE: &str = "device.jwk.json";
pub const DELEGATION_FILE: &str = "delegation.json";
pub const AGENT_ID_FILE: &str = "agent_id";
pub const HISTORY_FILE: &str = "retired_devices.json";
pub const ROTATIONS_FILE: &str = "rotations.json";
pub const LOCK_FILE: &str = ".lock";

static COUNTER: AtomicU64 = AtomicU64::new(0);

#[cfg(test)]
thread_local! {
    /// Failpoint for crash-simulation unit tests: while set, every
    /// `write_private_at` whose target has this file name fails before it
    /// creates anything. Thread-local, so parallel tests cannot see each other.
    pub(crate) static FAIL_ON: RefCell<Option<&'static str>> = const { RefCell::new(None) };
}

/// Makes the next writes to `name` in this thread fail (`None` clears it).
#[cfg(test)]
pub(crate) fn fail_writes_to(name: Option<&'static str>) {
    FAIL_ON.with(|f| *f.borrow_mut() = name);
}

#[cfg(test)]
fn injected_failure(p: &Path) -> bool {
    let name = FAIL_ON.with(|f| *f.borrow());
    name.is_some_and(|name| p.file_name() == Some(OsStr::new(name)))
}

fn path(dir: &Path, name: &str) -> PathBuf {
    dir.join(name)
}

/// The directory a bare relative name lives in. `Path::parent` of `"x"` is
/// `Some("")`, which is not a usable directory, so it becomes `"."`.
fn parent_dir(p: &Path) -> &Path {
    match p.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    }
}

fn read_bytes(p: &Path) -> Result<Vec<u8>, KeyfileError> {
    let mut f = File::open(p).map_err(|e| {
        if e.kind() == ErrorKind::NotFound {
            KeyfileError::Missing(p.to_path_buf())
        } else {
            io(p, e)
        }
    })?;
    let mut b = Vec::new();
    f.read_to_end(&mut b).map_err(|e| io(p, e))?;
    Ok(b)
}

fn parse<T: serde::de::DeserializeOwned>(p: &Path) -> Result<T, KeyfileError> {
    serde_json::from_slice(&read_bytes(p)?).map_err(|e| KeyfileError::Parse {
        path: p.to_path_buf(),
        msg: e.to_string(),
    })
}

/// Writes `bytes` to `p` as a mode-0600 file, through a fresh temporary name
/// in the same directory (`.{name}.{pid}.{counter}.tmp`).
pub(crate) fn write_private(p: &Path, bytes: &[u8]) -> Result<(), KeyfileError> {
    let name = p
        .file_name()
        .ok_or_else(|| {
            io(
                p,
                std::io::Error::new(ErrorKind::InvalidInput, "no file name"),
            )
        })?
        .to_string_lossy()
        .into_owned();
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let tmp = parent_dir(p).join(format!(".{name}.{}.{n}.tmp", std::process::id()));
    write_private_at(p, bytes, &tmp)
}

/// Writes `bytes` to `p` through the caller-chosen temporary path `tmp`.
///
/// The temporary file is opened with `create_new` (O_EXCL), so an existing
/// entry at `tmp`, including a symlink (dangling or not), makes the open fail.
/// It is never followed, reused or removed by this call. Only a temporary this
/// call created is removed on error.
pub(crate) fn write_private_at(p: &Path, bytes: &[u8], tmp: &Path) -> Result<(), KeyfileError> {
    #[cfg(test)]
    if injected_failure(p) {
        return Err(io(p, std::io::Error::other("injected failure")));
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    // A failed open means the entry at `tmp` is not ours: return without
    // touching it.
    let mut file = options.open(tmp).map_err(|e| io(tmp, e))?;
    let staged = (|| -> Result<(), KeyfileError> {
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|e| io(tmp, e))?;
        file.write_all(bytes).map_err(|e| io(tmp, e))?;
        file.sync_all().map_err(|e| io(tmp, e))?;
        fs::rename(tmp, p).map_err(|e| io(p, e))
    })();
    if let Err(error) = staged {
        let _ = fs::remove_file(tmp);
        return Err(error);
    }
    // The rename has already happened, so the new file is in place. A failed
    // parent fsync is still reported as Err even though the file is written.
    let dir = parent_dir(p);
    File::open(dir)
        .and_then(|f| f.sync_all())
        .map_err(|e| io(dir, e))
}

pub fn write_duo(dir: &Path, name: &str, duo: &KeyDuo) -> Result<(), KeyfileError> {
    let p = path(dir, name);
    // An export failure is a failure to produce the bytes, not a parse error.
    let text = KeyDuoSerializer::export_key_duo_jwk(duo)
        .map_err(|e| io(&p, std::io::Error::other(e.to_string())))?;
    write_private(&p, text.as_bytes())
}

pub fn read_duo(dir: &Path, name: &str) -> Result<KeyDuo, KeyfileError> {
    let p = path(dir, name);
    let text = String::from_utf8(read_bytes(&p)?).map_err(|e| KeyfileError::Parse {
        path: p.clone(),
        msg: e.to_string(),
    })?;
    KeyDuoSerializer::import_key_duo_jwk(&text).map_err(|e| KeyfileError::Parse {
        path: p,
        msg: e.to_string(),
    })
}

pub fn write_delegation(dir: &Path, delegation: &pb::KeyDelegation) -> Result<(), KeyfileError> {
    write_json(dir, DELEGATION_FILE, delegation)
}

pub fn read_delegation(dir: &Path) -> Result<pb::KeyDelegation, KeyfileError> {
    parse(&path(dir, DELEGATION_FILE))
}

pub fn write_history(dir: &Path, history: &pb::DeviceHistory) -> Result<(), KeyfileError> {
    write_json(dir, HISTORY_FILE, history)
}

/// The retired-device history. A missing file is an empty history. A file that
/// exists but cannot be read or parsed is an error, never an empty history.
pub fn read_history(dir: &Path) -> Result<pb::DeviceHistory, KeyfileError> {
    read_optional(dir, HISTORY_FILE)
}

pub fn write_rotations(dir: &Path, rotations: &pb::RootRotations) -> Result<(), KeyfileError> {
    write_json(dir, ROTATIONS_FILE, rotations)
}

/// The root rotation chain. A missing file is an empty chain. A file that
/// exists but cannot be read or parsed is an error.
pub fn read_rotations(dir: &Path) -> Result<pb::RootRotations, KeyfileError> {
    read_optional(dir, ROTATIONS_FILE)
}

pub fn write_principal_id(dir: &Path, id: &PrincipalId) -> Result<(), KeyfileError> {
    write_private(&path(dir, AGENT_ID_FILE), id.to_string().as_bytes())
}

pub fn read_principal_id(dir: &Path) -> Result<PrincipalId, KeyfileError> {
    let p = path(dir, AGENT_ID_FILE);
    let text = String::from_utf8(read_bytes(&p)?).map_err(|e| KeyfileError::Parse {
        path: p.clone(),
        msg: e.to_string(),
    })?;
    PrincipalId::parse_canonical(text.trim()).map_err(|e| KeyfileError::Parse {
        path: p,
        msg: e.to_string(),
    })
}

fn write_json<T: serde::Serialize>(dir: &Path, name: &str, value: &T) -> Result<(), KeyfileError> {
    let p = path(dir, name);
    let text = serde_json::to_string_pretty(value).map_err(|e| KeyfileError::Parse {
        path: p.clone(),
        msg: e.to_string(),
    })?;
    write_private(&p, text.as_bytes())
}

/// Reads an optional file. Only `NotFound` means "absent" (an empty value).
/// A broken symlink, a permission error or a parse error is an error, so
/// retired keys are never dropped silently.
fn read_optional<T: serde::de::DeserializeOwned + Default>(
    dir: &Path,
    name: &str,
) -> Result<T, KeyfileError> {
    let p = path(dir, name);
    match fs::symlink_metadata(&p) {
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(T::default()),
        Err(e) => Err(io(&p, e)),
        Ok(_) => parse(&p),
    }
}

/// Creates the agent directory (mode 0700) when it is missing, then checks it.
/// Used by `init` and `save`, the operations that may create the directory.
pub(crate) fn ensure_dir(dir: &Path) -> Result<(), KeyfileError> {
    match fs::symlink_metadata(dir) {
        Ok(_) => {}
        Err(e) if e.kind() == ErrorKind::NotFound => {
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(dir)
                .map_err(|e| io(dir, e))?;
        }
        Err(e) => return Err(io(dir, e)),
    }
    check_dir(dir)
}

/// Requires an existing agent directory with no group or other access
/// (`mode & 0o077 == 0`). A symlink or a non-directory is refused. Writes
/// nothing.
pub(crate) fn check_dir(dir: &Path) -> Result<(), KeyfileError> {
    let meta = match fs::symlink_metadata(dir) {
        Ok(meta) => meta,
        Err(e) if e.kind() == ErrorKind::NotFound => {
            return Err(KeyfileError::Missing(dir.to_path_buf()))
        }
        Err(e) => return Err(io(dir, e)),
    };
    if !meta.is_dir() || meta.mode() & 0o077 != 0 {
        return Err(KeyfileError::InsecureDir(dir.to_path_buf()));
    }
    Ok(())
}

fn open_lock_file(dir: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(dir.join(LOCK_FILE))
}

/// The exclusive advisory lock for a mutation. It is held until the returned
/// `File` is dropped, so the caller keeps it alive for the whole operation.
pub(crate) fn lock_exclusive(dir: &Path) -> Result<File, KeyfileError> {
    let lock_path = path(dir, LOCK_FILE);
    let file = open_lock_file(dir).map_err(|e| io(&lock_path, e))?;
    file.lock().map_err(|e| io(&lock_path, e))?;
    Ok(file)
}

/// The shared advisory lock for a read. When `.lock` cannot be created because
/// the directory is read-only, returns `None` and the caller reads without a
/// lock. Any other failure is an error.
pub(crate) fn lock_shared(dir: &Path) -> Result<Option<File>, KeyfileError> {
    let lock_path = path(dir, LOCK_FILE);
    match open_lock_file(dir) {
        Ok(file) => {
            file.lock_shared().map_err(|e| io(&lock_path, e))?;
            Ok(Some(file))
        }
        Err(e)
            if matches!(
                e.kind(),
                ErrorKind::PermissionDenied | ErrorKind::ReadOnlyFilesystem
            ) =>
        {
            Ok(None)
        }
        Err(e) => Err(io(&lock_path, e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    fn private_dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }

    fn tmp_entries(dir: &Path) -> Vec<String> {
        fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name.ends_with(".tmp"))
            .collect()
    }

    #[test]
    fn planted_symlink_tmp_is_refused() {
        let dir = private_dir();
        let victim = dir.path().join("victim");
        fs::write(&victim, b"unchanged").unwrap();
        let target = dir.path().join(ROOT_FILE);
        let tmp = dir.path().join(".root.jwk.json.1.0.tmp");
        symlink(&victim, &tmp).unwrap();
        let result = write_private_at(&target, b"new key", &tmp);
        assert!(matches!(result, Err(KeyfileError::Io { .. })));
        assert_eq!(fs::read(&victim).unwrap(), b"unchanged");
        assert!(!target.exists());
        assert!(
            fs::symlink_metadata(&tmp).unwrap().file_type().is_symlink(),
            "the planted link is left alone"
        );
    }

    #[test]
    fn dangling_symlink_tmp_is_refused_and_its_target_is_not_created() {
        let dir = private_dir();
        let attacker_target = dir.path().join("created-by-attacker");
        let target = dir.path().join(ROOT_FILE);
        let tmp = dir.path().join(".root.jwk.json.2.0.tmp");
        symlink(&attacker_target, &tmp).unwrap();
        let result = write_private_at(&target, b"new key", &tmp);
        assert!(matches!(result, Err(KeyfileError::Io { .. })));
        assert!(
            !attacker_target.exists(),
            "O_EXCL does not follow a dangling link"
        );
        assert!(!target.exists());
    }

    #[test]
    fn existing_tmp_is_not_removed_when_the_exclusive_open_fails() {
        let dir = private_dir();
        let target = dir.path().join(ROOT_FILE);
        let tmp = dir.path().join(".root.jwk.json.3.0.tmp");
        fs::write(&tmp, b"someone else's file").unwrap();
        let result = write_private_at(&target, b"new key", &tmp);
        assert!(matches!(result, Err(KeyfileError::Io { .. })));
        assert_eq!(fs::read(&tmp).unwrap(), b"someone else's file");
        assert!(!target.exists());
    }

    #[test]
    fn failed_write_removes_its_tmp() {
        let dir = private_dir();
        let target = dir.path().join(ROOT_FILE);
        fs::create_dir(&target).unwrap();
        fs::write(target.join("child"), b"x").unwrap();
        let tmp = dir.path().join(".root.jwk.json.4.0.tmp");
        let result = write_private_at(&target, b"new key", &tmp);
        assert!(
            result.is_err(),
            "renaming a file onto a non-empty directory fails"
        );
        assert!(
            !tmp.exists(),
            "the temporary file this call created is removed"
        );
        assert!(tmp_entries(dir.path()).is_empty());
        assert!(target.join("child").is_file(), "the directory is untouched");
    }

    #[test]
    fn written_file_is_0600_even_over_a_loose_file() {
        let dir = private_dir();
        let target = dir.path().join(ROOT_FILE);
        fs::write(&target, b"old").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o644)).unwrap();
        write_private(&target, b"new").unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"new");
        assert_eq!(
            fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(tmp_entries(dir.path()).is_empty());
    }

    #[test]
    fn parent_of_a_bare_name_is_the_current_directory() {
        assert_eq!(parent_dir(Path::new("root.jwk.json")), Path::new("."));
        assert_eq!(parent_dir(Path::new("dir/root.jwk.json")), Path::new("dir"));
    }
}
