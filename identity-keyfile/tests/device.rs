use identity_crypto::{encryption_public, signing_public};
use identity_keyfile::*;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::thread;
use std::time::Duration;

fn dir() -> tempfile::TempDir {
    let d = tempfile::tempdir().unwrap();
    fs::set_permissions(d.path(), fs::Permissions::from_mode(0o700)).unwrap();
    d
}

#[test]
fn device_load_works_without_root_file() {
    let d = dir();
    let a = IdentityKeys::init(d.path(), 1_000, 100).unwrap();
    fs::remove_file(d.path().join(ROOT_FILE)).unwrap();
    let k = DeviceKeys::load(d.path()).unwrap();
    assert_eq!(signing_public(&k.device), signing_public(&a.device));
    assert_eq!(k.delegation, a.delegation);
    assert_eq!(k.principal_id, a.principal_id);
    assert_eq!(k.retired, a.retired);
    assert!(matches!(
        IdentityKeys::load(d.path()),
        Err(KeyfileError::Missing(_))
    ));
}

#[test]
fn device_load_works_with_unreadable_root() {
    let d = dir();
    IdentityKeys::init(d.path(), 1_000, 100).unwrap();
    fs::set_permissions(d.path().join(ROOT_FILE), fs::Permissions::from_mode(0o000)).unwrap();
    let result = DeviceKeys::load(d.path());
    fs::set_permissions(d.path().join(ROOT_FILE), fs::Permissions::from_mode(0o600)).unwrap();
    result.unwrap();
}

#[test]
fn device_load_ignores_corrupt_root_and_rotations() {
    let d = dir();
    IdentityKeys::init(d.path(), 1_000, 100).unwrap();
    fs::write(d.path().join(ROOT_FILE), b"garbage").unwrap();
    fs::write(d.path().join(ROTATIONS_FILE), b"garbage").unwrap();
    DeviceKeys::load(d.path()).unwrap();
}

#[test]
fn device_load_reports_delegation_mismatch() {
    let d = dir();
    IdentityKeys::init(d.path(), 1_000, 100).unwrap();
    let other = identity_keyfile::generate();
    write_duo(d.path(), DEVICE_FILE, &other).unwrap();
    assert!(matches!(
        DeviceKeys::load(d.path()),
        Err(KeyfileError::DelegationMismatch)
    ));
}

#[test]
fn device_load_refuses_loose_dir() {
    let d = dir();
    IdentityKeys::init(d.path(), 1_000, 100).unwrap();
    fs::set_permissions(d.path(), fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(
        DeviceKeys::load(d.path()),
        Err(KeyfileError::InsecureDir(_))
    ));
}

#[test]
fn device_load_missing_files() {
    let d = dir();
    IdentityKeys::init(d.path(), 1_000, 100).unwrap();
    fs::remove_file(d.path().join(AGENT_ID_FILE)).unwrap();
    assert!(
        matches!(DeviceKeys::load(d.path()), Err(KeyfileError::Missing(p)) if p.ends_with(AGENT_ID_FILE))
    );
}

#[test]
fn device_load_missing_device_file() {
    let d = dir();
    IdentityKeys::init(d.path(), 1_000, 100).unwrap();
    fs::remove_file(d.path().join(DEVICE_FILE)).unwrap();
    assert!(
        matches!(DeviceKeys::load(d.path()), Err(KeyfileError::Missing(p)) if p.ends_with(DEVICE_FILE))
    );
}

#[test]
fn device_load_takes_shared_lock() {
    let d = dir();
    IdentityKeys::init(d.path(), 1_000, 100).unwrap();
    let held = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(d.path().join(LOCK_FILE))
        .unwrap();
    held.lock().unwrap();
    let path = d.path().to_owned();
    let reader = thread::spawn(move || DeviceKeys::load(&path).unwrap());
    thread::sleep(Duration::from_millis(300));
    assert!(
        !reader.is_finished(),
        "the load waits for the exclusive lock"
    );
    held.unlock().unwrap();
    reader.join().unwrap();
}

#[test]
fn device_load_does_not_block_on_a_shared_lock() {
    let d = dir();
    IdentityKeys::init(d.path(), 1_000, 100).unwrap();
    let held = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(d.path().join(LOCK_FILE))
        .unwrap();
    held.lock_shared().unwrap();
    let path = d.path().to_owned();
    thread::spawn(move || DeviceKeys::load(&path).unwrap())
        .join()
        .unwrap();
    held.unlock().unwrap();
}

#[test]
fn device_load_sees_renewed_device_and_history() {
    let d = dir();
    let first = IdentityKeys::init(d.path(), 1_000, 100).unwrap();
    let rotated = IdentityKeys::rotate_device(d.path(), 1_010, 100).unwrap();
    let dk = DeviceKeys::load(d.path()).unwrap();
    let ap = IdentityKeys::load(d.path()).unwrap().public();
    assert_eq!(signing_public(&dk.device), signing_public(&rotated.device));
    assert_eq!(dk.retired.len(), 1);
    assert_eq!(dk.public().device_keys_at(0), device_keys_at(&rotated, 0));
    assert_eq!(
        dk.public().device_keys_at(1_011),
        device_keys_at(&rotated, 1_011)
    );
    assert_ne!(signing_public(&first.device), ap.device_signing);
}

#[test]
fn public_snapshots_agree() {
    let d = dir();
    let a = IdentityKeys::init(d.path(), 1_000, 100).unwrap();
    let k = DeviceKeys::load(d.path()).unwrap();
    let x = k.public();
    let y = a.public();
    assert_eq!(x.principal_id, y.principal_id);
    assert_eq!(x.device_signing, y.device_signing);
    assert_eq!(x.device_encryption, y.device_encryption);
    assert_eq!(x.delegation, y.delegation);
    assert_eq!(x.retired, y.retired);
    assert_eq!(x.device_signing, signing_public(&k.device));
    assert_eq!(x.device_encryption, encryption_public(&k.device));
}
