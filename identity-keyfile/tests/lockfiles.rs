//! Lock files are refused when loose, symlinked or foreign: identity dirs and
//! the machine directory's `.lock`.

use identity_crypto::principal_id;
use identity_keyfile::*;
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::Path;

const DAY: i64 = 86_400;
const NOW: i64 = 1_000_000;
const TTL: i64 = 30 * DAY;

fn parent() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

fn identity(p: &Path) -> std::path::PathBuf {
    let dir = p.join("id");
    IdentityKeys::init(&dir, NOW, TTL).unwrap();
    assert!(dir.join(LOCK_FILE).is_file());
    dir
}

/// Every operation that needs the lock must refuse with InsecureFile.
fn all_refused(dir: &Path) {
    let insecure = |r: Result<IdentityKeys, KeyfileError>, what: &str| {
        assert!(
            matches!(r, Err(KeyfileError::InsecureFile(_))),
            "{what}: {:?}",
            r.err()
        );
    };
    insecure(IdentityKeys::load(dir), "load");
    insecure(
        IdentityKeys::create_or_load(dir, NOW + DAY, TTL),
        "create_or_load",
    );
    insecure(IdentityKeys::renew(dir, NOW + DAY, TTL, false), "renew");
}

#[test]
fn loose_lock_file_refused() {
    let p = parent();
    let dir = identity(p.path());
    for mode in [0o644, 0o640, 0o604, 0o666] {
        fs::set_permissions(dir.join(LOCK_FILE), fs::Permissions::from_mode(mode)).unwrap();
        all_refused(&dir);
    }
    // Tightened again, everything works.
    fs::set_permissions(dir.join(LOCK_FILE), fs::Permissions::from_mode(0o600)).unwrap();
    IdentityKeys::load(&dir).unwrap();
    IdentityKeys::create_or_load(&dir, NOW + DAY, TTL).unwrap();
}

#[test]
fn symlinked_lock_file_refused() {
    let p = parent();
    let dir = identity(p.path());
    let target = p.path().join("real.lock");
    fs::write(&target, b"").unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
    fs::remove_file(dir.join(LOCK_FILE)).unwrap();
    symlink(&target, dir.join(LOCK_FILE)).unwrap();
    all_refused(&dir);
}

#[test]
fn dangling_lock_symlink_target_is_not_created() {
    let p = parent();
    let dir = identity(p.path());
    let target = p.path().join("not-yet.lock");
    fs::remove_file(dir.join(LOCK_FILE)).unwrap();
    symlink(&target, dir.join(LOCK_FILE)).unwrap();
    all_refused(&dir);
    assert!(!target.exists(), "the dangling target was created");
    assert!(fs::symlink_metadata(dir.join(LOCK_FILE))
        .unwrap()
        .file_type()
        .is_symlink());
}

/// Needs root to chown; skipped (passes vacuously, says so) otherwise.
#[test]
fn foreign_owner_lock_file_refused() {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("SKIPPED foreign_owner_lock_file_refused: needs root to chown");
        return;
    }
    let p = parent();
    let dir = identity(p.path());
    let lock = std::ffi::CString::new(dir.join(LOCK_FILE).to_str().unwrap()).unwrap();
    assert_eq!(unsafe { libc::chown(lock.as_ptr(), 65534, u32::MAX) }, 0);
    assert!(matches!(
        IdentityKeys::load(&dir),
        Err(KeyfileError::WrongOwner(_))
    ));
}

fn machine(p: &Path) -> MachineDir {
    let machine = MachineDir::at(p.join("machine"));
    machine.ensure().unwrap();
    machine
}

fn index_ops_refused(machine: &MachineDir, dir: &Path) {
    assert!(
        matches!(
            EnrolmentIndex::read(machine),
            Err(KeyfileError::InsecureFile(_))
        ),
        "read"
    );
    let entry = enrolment_for(dir, None).unwrap();
    let owner = principal_id(&generate());
    assert!(
        matches!(
            EnrolmentIndex::enrol(machine, "grorg", entry, &owner),
            Err(KeyfileError::InsecureFile(_))
        ),
        "enrol"
    );
}

#[test]
fn loose_machine_lock_file_refused() {
    let p = parent();
    let dir = identity(p.path());
    let m = machine(p.path());
    let owner = principal_id(&generate());
    EnrolmentIndex::enrol(&m, "grorg", enrolment_for(&dir, None).unwrap(), &owner).unwrap();
    let lock = m.path().join(LOCK_FILE);
    assert!(lock.is_file());
    fs::set_permissions(&lock, fs::Permissions::from_mode(0o644)).unwrap();
    index_ops_refused(&m, &dir);
}

#[test]
fn symlinked_machine_lock_file_refused() {
    let p = parent();
    let dir = identity(p.path());
    let m = machine(p.path());
    let target = p.path().join("dangling-machine.lock");
    symlink(&target, m.path().join(LOCK_FILE)).unwrap();
    index_ops_refused(&m, &dir);
    assert!(!target.exists(), "the dangling target was created");
}
