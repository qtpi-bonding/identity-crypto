//! Private-file primitives: atomic 0600 writes, 0700 directories and checked
//! reads. Every private key-set path goes through here.

use crate::error::{io, KeyfileError};
use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use zeroize::Zeroizing;

/// Maximum accepted size of a private key-set file.
pub const MAX_KEY_FILE_BYTES: usize = 16 * 1024;
/// Maximum accepted size of a public file inside a checked directory.
pub const MAX_PUBLIC_FILE_BYTES: usize = 1024 * 1024;

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// A process-unique suffix for temporary names. The only temp counter in the crate.
pub(crate) fn next_temp_suffix() -> u64 {
    TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// The directory a bare relative name lives in. `Path::parent` of `"x"` is
/// `Some("")`, which is not a usable directory, so it becomes `"."`.
fn parent_dir(p: &Path) -> &Path {
    match p.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    }
}

/// Writes `bytes` to `path` as a private file of `mode` (0600 or 0400), through
/// a unique temporary name in the same directory. The temporary is opened with
/// O_EXCL, fsynced, renamed over `path`, and the parent is fsynced. A temporary
/// this call created is removed on failure. The parent must exist.
pub fn write_private_atomic(path: &Path, bytes: &[u8], mode: u32) -> Result<(), KeyfileError> {
    let n = next_temp_suffix();
    let name = path
        .file_name()
        .ok_or_else(|| {
            io(
                path,
                std::io::Error::new(ErrorKind::InvalidInput, "no file name"),
            )
        })?
        .to_string_lossy()
        .into_owned();
    let tmp = parent_dir(path).join(format!(".{name}.{}.{n}.tmp", std::process::id()));
    write_private_via(path, bytes, mode, &tmp)
}

/// [`write_private_atomic`] through the caller-chosen temporary path `tmp`.
/// The temporary is opened with O_EXCL, so an existing entry at `tmp` (even a
/// dangling symlink) is refused and never touched.
pub(crate) fn write_private_via(
    path: &Path,
    bytes: &[u8],
    mode: u32,
    tmp: &Path,
) -> Result<(), KeyfileError> {
    #[cfg(test)]
    if crate::files::injected_failure(path) {
        return Err(io(path, std::io::Error::other("injected failure")));
    }
    if mode != 0o600 && mode != 0o400 {
        return Err(KeyfileError::InvalidMode(mode));
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut file = options.open(tmp).map_err(|e| io(tmp, e))?;
    let staged = (|| -> Result<(), KeyfileError> {
        file.set_permissions(fs::Permissions::from_mode(mode))
            .map_err(|e| io(tmp, e))?;
        file.write_all(bytes).map_err(|e| io(tmp, e))?;
        file.sync_all().map_err(|e| io(tmp, e))?;
        fs::rename(tmp, path).map_err(|e| io(path, e))
    })();
    if let Err(error) = staged {
        // Best effort: the temporary is ours; the original error is what matters.
        let _ = fs::remove_file(tmp);
        return Err(error);
    }
    let dir = parent_dir(path);
    File::open(dir)
        .and_then(|f| f.sync_all())
        .map_err(|e| io(dir, e))
}

/// Creates `path` and any missing ancestors with mode 0700, then checks it.
pub fn create_private_dir(path: &Path) -> Result<(), KeyfileError> {
    match fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(e) if e.kind() == ErrorKind::NotFound => {
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(path)
                .map_err(|e| io(path, e))?;
        }
        Err(e) => return Err(io(path, e)),
    }
    check_private_dir(path)
}

/// Requires an existing private directory: not a symlink, `mode & 0o077 == 0`,
/// owned by the effective user. Writes nothing.
pub fn check_private_dir(path: &Path) -> Result<(), KeyfileError> {
    // SAFETY: geteuid has no preconditions and cannot fail.
    let uid = unsafe { libc::geteuid() };
    check_private_dir_with_uid(path, uid)
}

/// [`check_private_dir`] against an explicit owner uid.
pub(crate) fn check_private_dir_with_uid(path: &Path, uid: u32) -> Result<(), KeyfileError> {
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == ErrorKind::NotFound => {
            return Err(KeyfileError::Missing(path.to_path_buf()))
        }
        Err(e) => return Err(io(path, e)),
    };
    if !meta.is_dir() || meta.mode() & 0o077 != 0 {
        return Err(KeyfileError::InsecureDir(path.to_path_buf()));
    }
    if meta.uid() != uid {
        return Err(KeyfileError::WrongOwner(path.to_path_buf()));
    }
    Ok(())
}

/// Opens `path` without following a symlink and without blocking on a FIFO.
fn open_no_follow(path: &Path) -> Result<File, KeyfileError> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|error| match error.kind() {
            ErrorKind::NotFound => KeyfileError::Missing(path.to_path_buf()),
            _ if error.raw_os_error() == Some(libc::ELOOP) => {
                KeyfileError::InsecureFile(path.to_path_buf())
            }
            _ => io(path, error),
        })
}

/// Reads at most `cap` bytes from an open regular file. Longer is `TooLarge`.
fn read_capped(
    file: &mut File,
    path: &Path,
    cap: usize,
) -> Result<Zeroizing<Vec<u8>>, KeyfileError> {
    // Capacity cap + 1 so the buffer never reallocates (no stray unzeroed copy).
    let mut bytes = Zeroizing::new(Vec::with_capacity(cap + 1));
    (&mut *file)
        .take(cap as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| io(path, error))?;
    if bytes.len() > cap {
        return Err(KeyfileError::TooLarge {
            path: path.to_path_buf(),
            cap,
        });
    }
    Ok(bytes)
}

/// Reads a private file: refuses a symlink, a non-regular file, a file with any
/// group or other access, a file owned by another user, and one over `cap`
/// bytes. The returned bytes are zeroized on drop.
pub fn read_private_file(path: &Path, cap: usize) -> Result<Zeroizing<Vec<u8>>, KeyfileError> {
    // SAFETY: geteuid has no preconditions and cannot fail.
    let uid = unsafe { libc::geteuid() };
    let mut file = open_no_follow(path)?;
    let meta = file.metadata().map_err(|error| io(path, error))?;
    if !meta.is_file() {
        return Err(KeyfileError::NotAFile(path.to_path_buf()));
    }
    if meta.mode() & 0o077 != 0 {
        return Err(KeyfileError::InsecureFile(path.to_path_buf()));
    }
    if meta.uid() != uid {
        return Err(KeyfileError::WrongOwner(path.to_path_buf()));
    }
    read_capped(&mut file, path, cap)
}

/// Checks an already-opened file handle: a regular file with
/// `mode & 0o077 == 0`, owned by the effective user. Used for lock files,
/// which are opened with O_NOFOLLOW|O_CREAT and then checked on the handle,
/// not the path, so the check cannot be raced.
pub(crate) fn check_private_file_handle(file: &File, path: &Path) -> Result<(), KeyfileError> {
    // SAFETY: geteuid has no preconditions and cannot fail.
    let uid = unsafe { libc::geteuid() };
    let meta = file.metadata().map_err(|error| io(path, error))?;
    if !meta.is_file() || meta.mode() & 0o077 != 0 {
        return Err(KeyfileError::InsecureFile(path.to_path_buf()));
    }
    if meta.uid() != uid {
        return Err(KeyfileError::WrongOwner(path.to_path_buf()));
    }
    Ok(())
}

/// Reads a public file inside an already-checked directory: no mode or owner
/// check, but still no symlink, no non-regular file and no more than `cap` bytes.
pub fn read_regular_file(path: &Path, cap: usize) -> Result<Vec<u8>, KeyfileError> {
    let mut file = open_no_follow(path)?;
    let meta = file.metadata().map_err(|error| io(path, error))?;
    if !meta.is_file() {
        return Err(KeyfileError::NotAFile(path.to_path_buf()));
    }
    let mut bytes = read_capped(&mut file, path, cap)?;
    Ok(std::mem::take(&mut *bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn check_private_dir_refuses_other_owner() {
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        // SAFETY: geteuid has no preconditions and cannot fail.
        let me = unsafe { libc::geteuid() };
        check_private_dir_with_uid(dir.path(), me).unwrap();
        let err = check_private_dir_with_uid(dir.path(), me + 1).unwrap_err();
        assert!(
            matches!(&err, KeyfileError::WrongOwner(p) if p == dir.path()),
            "{err:?}"
        );
    }
}
