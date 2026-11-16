//! Explicit root adoption: `create_or_load` never adopts, device-only folders are
//! never written, and `adopt_root` / `adopt_owner_root` are the only adopters.

use identity_crypto::{
    pb, principal_id, signing_public, PrincipalId, DEFAULT_DELEGATION_SECONDS,
    DEFAULT_RENEW_MARGIN_SECONDS, MAX_DELEGATION_SECONDS,
};
use identity_keyfile::*;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::SystemTime;

const DAY: i64 = 86_400;
const NOW: i64 = 1_000_000;
const TTL: i64 = 30 * DAY;

fn parent() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

fn private_dir(path: &Path) {
    fs::create_dir_all(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

/// A 0700 folder holding only a fresh root key. Returns the root and its principal.
fn root_only(dir: &Path) -> (identity_crypto::jwk_duo::KeyDuo, PrincipalId) {
    private_dir(dir);
    let root = generate();
    let id = principal_id(&root);
    write_duo(dir, ROOT_FILE, &root).unwrap();
    (root, id)
}

fn names(dir: &Path) -> BTreeSet<String> {
    fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect()
}

fn set(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|s| s.to_string()).collect()
}

type Snapshot = BTreeMap<String, (Vec<u8>, SystemTime)>;

/// Name to (bytes, mtime) of every entry of `dir`, the lock file included.
fn snapshot(dir: &Path) -> Snapshot {
    fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap())
        .map(|e| {
            let modified = fs::metadata(e.path()).unwrap().modified().unwrap();
            let bytes = if e.path().is_file() {
                fs::read(e.path()).unwrap()
            } else {
                Vec::new()
            };
            (
                e.file_name().to_string_lossy().into_owned(),
                (bytes, modified),
            )
        })
        .collect()
}

#[test]
fn create_or_load_never_adopts_single() {
    let p = parent();
    let dir = p.path().join("a");
    root_only(&dir);
    assert!(matches!(
        IdentityKeys::create_or_load(&dir, NOW, TTL),
        Err(KeyfileError::OrphanRoot(d)) if d == dir
    ));
    assert_eq!(names(&dir), set(&["root.jwk.json"]));
}

#[test]
fn create_or_load_never_adopts_split() {
    let p = parent();
    let root_dir = p.path().join("identity-root");
    let dev_dir = p.path().join("identity");
    root_only(&root_dir);
    private_dir(&dev_dir);
    let layout = IdentityLayout::split(&root_dir, &dev_dir).unwrap();
    assert!(matches!(
        IdentityKeys::create_or_load_at(&layout, NOW, TTL),
        Err(KeyfileError::OrphanRoot(d)) if d == root_dir
    ));
    assert!(names(&dev_dir).is_empty());
    assert_eq!(names(&root_dir), set(&["root.jwk.json"]));
}

#[test]
fn single_adopt_root_uses_root_as_genesis() {
    let p = parent();
    let dir = p.path().join("a");
    let (root, id) = root_only(&dir);
    let root_bytes = fs::read(dir.join(ROOT_FILE)).unwrap();
    let keys = IdentityKeys::adopt_root(&dir, NOW, TTL, None).unwrap();
    assert_eq!(keys.principal_id, id);
    assert_eq!(signing_public(&keys.root), signing_public(&root));
    assert_eq!(fs::read(dir.join(ROOT_FILE)).unwrap(), root_bytes);
    let loaded = IdentityKeys::load_verified(&dir).unwrap();
    assert_eq!(loaded.principal_id, id);
}

#[test]
fn adopt_root_recommits_partial_device() {
    let p = parent();
    let dir = p.path().join("a");
    let (_, id) = root_only(&dir);
    let stale = generate();
    write_duo(&dir, DEVICE_FILE, &stale).unwrap();
    let keys = IdentityKeys::adopt_root(&dir, NOW, TTL, None).unwrap();
    assert_eq!(keys.principal_id, id);
    assert_eq!(
        keys.delegation.delegated,
        Some(pb::PublicKey::from(&signing_public(&keys.device)))
    );
    let loaded = IdentityKeys::load_verified(&dir).unwrap();
    assert_eq!(signing_public(&loaded.device), signing_public(&keys.device));
    assert_eq!(
        loaded.delegation.delegated,
        Some(pb::PublicKey::from(&signing_public(&loaded.device)))
    );
}

#[test]
fn adopt_root_concurrent_agrees() {
    let p = parent();
    let dir = p.path().join("a");
    let (_, id) = root_only(&dir);
    let barrier = Arc::new(Barrier::new(8));
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let dir = dir.clone();
            let barrier = barrier.clone();
            thread::spawn(move || {
                barrier.wait();
                let keys = IdentityKeys::adopt_root(&dir, NOW, TTL, None).unwrap();
                (
                    keys.principal_id.to_string(),
                    format!("{:?}", signing_public(&keys.device)),
                )
            })
        })
        .collect();
    let results: BTreeSet<(String, String)> =
        handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert_eq!(results.len(), 1, "one principal and one device key");
    assert_eq!(results.iter().next().unwrap().0, id.to_string());
}

#[test]
fn adopt_root_refuses_owner_principal() {
    let p = parent();
    let dir = p.path().join("a");
    let (_, id) = root_only(&dir);
    let before = snapshot(&dir);
    assert!(matches!(
        IdentityKeys::adopt_root(&dir, NOW, TTL, Some(&id)),
        Err(KeyfileError::OwnerRoot)
    ));
    assert_eq!(names(&dir), set(&["root.jwk.json"]));
    assert_eq!(snapshot(&dir), before);
}

#[test]
fn adopt_root_with_none_refuses_nothing() {
    let p = parent();
    let dir = p.path().join("a");
    let (_, id) = root_only(&dir);
    let keys = IdentityKeys::adopt_root(&dir, NOW, TTL, None).unwrap();
    assert_eq!(keys.principal_id, id);
    assert!(dir.join(AGENT_ID_FILE).is_file());
    // A different principal to refuse does not refuse this root either.
    let other = principal_id(&generate());
    let dir2 = p.path().join("b");
    root_only(&dir2);
    assert!(IdentityKeys::adopt_root(&dir2, NOW, TTL, Some(&other)).is_ok());
}

#[test]
fn adopt_owner_root_missing_machine_dir_is_clear() {
    let p = parent();
    let dir = p.path().join("a");
    let (_, id) = root_only(&dir);
    let missing = p.path().join("no-such-machine-dir");
    let machine = MachineDir::at(&missing);
    let err = IdentityKeys::adopt_owner_root(&dir, NOW, TTL, &id, &machine)
        .err()
        .expect("must fail");
    match &err {
        KeyfileError::MachineDirMissing(path) => assert_eq!(*path, missing),
        other => panic!("expected MachineDirMissing, got {other:?}"),
    }
    let text = err.to_string();
    assert!(text.contains(missing.to_str().unwrap()), "{text}");
    assert!(text.contains("MACHINE_IDENTITY_DIR"), "{text}");
    assert_eq!(names(&dir), set(&["root.jwk.json"]));
    assert!(!missing.exists());
}

#[test]
fn adopt_owner_root_requires_owner() {
    let p = parent();
    let dir = p.path().join("a");
    root_only(&dir);
    let machine_path = p.path().join("machine");
    private_dir(&machine_path);
    let machine = MachineDir::at(&machine_path);
    let other = principal_id(&generate());
    assert!(matches!(
        IdentityKeys::adopt_owner_root(&dir, NOW, TTL, &other, &machine),
        Err(KeyfileError::NotOwnerRoot)
    ));
    assert_eq!(names(&dir), set(&["root.jwk.json"]));
}

#[test]
fn adopt_owner_root_refuses_machine_dir() {
    let p = parent();
    let machine_path = p.path().join("machine");
    private_dir(&machine_path);
    let machine = MachineDir::at(&machine_path);
    let inside = machine_path.join("x");
    let (_, id) = root_only(&inside);
    assert!(matches!(
        IdentityKeys::adopt_owner_root(&inside, NOW, TTL, &id, &machine),
        Err(KeyfileError::InsideMachineDir(_))
    ));
    // The machine directory itself.
    assert!(matches!(
        IdentityKeys::adopt_owner_root(&machine_path, NOW, TTL, &id, &machine),
        Err(KeyfileError::InsideMachineDir(_))
    ));
    // Through a symlink into it.
    let alias = p.path().join("alias");
    symlink(&inside, &alias).unwrap();
    assert!(matches!(
        IdentityKeys::adopt_owner_root(&alias, NOW, TTL, &id, &machine),
        Err(KeyfileError::InsideMachineDir(_))
    ));
    assert_eq!(names(&inside), set(&["root.jwk.json"]));
}

#[test]
fn has_root_and_is_device_only() {
    let p = parent();
    let single = p.path().join("s");
    let layout = IdentityLayout::single(&single);
    assert!(!layout.has_root());
    assert!(!is_device_only(&single));
    root_only(&single);
    assert!(layout.has_root());
    assert!(!is_device_only(&single));
    IdentityKeys::adopt_root(&single, NOW, TTL, None).unwrap();
    assert!(layout.has_root());
    assert!(!is_device_only(&single));
    fs::remove_file(single.join(ROOT_FILE)).unwrap();
    assert!(!layout.has_root());
    assert!(is_device_only(&single));
    // A directory named root.jwk.json is not a root.
    fs::create_dir(single.join(ROOT_FILE)).unwrap();
    assert!(!layout.has_root());
    fs::remove_dir(single.join(ROOT_FILE)).unwrap();
    // Missing delegation: no longer device-only.
    fs::remove_file(single.join(DELEGATION_FILE)).unwrap();
    assert!(!is_device_only(&single));
    // Split: root_dir decides has_root.
    let root_dir = p.path().join("r");
    let dev_dir = p.path().join("d");
    let split = IdentityLayout::split(&root_dir, &dev_dir).unwrap();
    IdentityKeys::init_at(&split, NOW, TTL).unwrap();
    assert!(split.has_root());
    fs::remove_file(root_dir.join(ROOT_FILE)).unwrap();
    assert!(!split.has_root());
    assert!(is_device_only(&dev_dir));
    assert!(!is_device_only(&p.path().join("nonexistent")));
}

#[test]
fn device_only_dirs_are_never_written() {
    let p = parent();
    let dir = p.path().join("d");
    IdentityKeys::init(&dir, NOW, TTL).unwrap();
    fs::remove_file(dir.join(ROOT_FILE)).unwrap();
    fs::remove_file(dir.join(LOCK_FILE)).unwrap();
    assert!(is_device_only(&dir));
    let before = snapshot(&dir);
    let is_dev = |e: KeyfileError| matches!(e, KeyfileError::DeviceOnly(ref d) if *d == dir);

    assert!(is_dev(
        IdentityKeys::create_or_load(&dir, NOW + DAY, TTL)
            .err()
            .unwrap()
    ));
    assert!(is_dev(
        IdentityKeys::adopt_root(&dir, NOW + DAY, TTL, None)
            .err()
            .unwrap()
    ));
    assert!(is_dev(
        IdentityKeys::renew(&dir, NOW + DAY, TTL, false)
            .err()
            .unwrap()
    ));
    assert!(is_dev(
        IdentityKeys::rotate_device(&dir, NOW + DAY, TTL)
            .err()
            .unwrap()
    ));
    assert!(is_dev(
        IdentityKeys::rotate_root(&dir, NOW + DAY).err().unwrap()
    ));
    // renew_if_due needs in-memory keys; take them from a separate full identity.
    let copy_parent = parent();
    let full = copy_parent.path().join("full");
    let mut keys = IdentityKeys::init(&full, NOW, TTL).unwrap();
    assert!(is_dev(
        keys.renew_if_due(
            Some(&dir),
            NOW + 40 * DAY,
            TTL,
            DEFAULT_RENEW_MARGIN_SECONDS
        )
        .err()
        .unwrap()
    ));

    assert_eq!(snapshot(&dir), before);
    assert!(!dir.join(LOCK_FILE).exists());
}

#[test]
fn create_or_load_loads_expired_31_day_dir_unmodified() {
    let p = parent();
    let dir = p.path().join("a");
    let first = IdentityKeys::init(&dir, NOW, MAX_DELEGATION_SECONDS).unwrap();
    let before = snapshot(&dir);
    let later = NOW + 40 * DAY;
    let mut loaded = IdentityKeys::create_or_load(&dir, later, DEFAULT_DELEGATION_SECONDS).unwrap();
    assert_eq!(snapshot(&dir), before);
    assert_eq!(loaded.principal_id, first.principal_id);

    let single = IdentityLayout::single(&dir);
    let renewed = loaded
        .renew_if_due_at(
            Some(&single),
            later,
            DEFAULT_DELEGATION_SECONDS,
            DEFAULT_RENEW_MARGIN_SECONDS,
        )
        .unwrap();
    assert!(renewed);
    assert_eq!(loaded.principal_id, first.principal_id);

    // A device-only copy of the identity.
    let copy: PathBuf = p.path().join("copy");
    private_dir(&copy);
    for name in [
        AGENT_ID_FILE,
        DELEGATION_FILE,
        DEVICE_FILE,
        HISTORY_FILE,
        ROTATIONS_FILE,
    ] {
        fs::copy(dir.join(name), copy.join(name)).unwrap();
        fs::set_permissions(copy.join(name), fs::Permissions::from_mode(0o600)).unwrap();
    }
    assert!(is_device_only(&copy));
    let mut stale = first;
    assert!(matches!(
        stale.renew_if_due(
            Some(&copy),
            later,
            DEFAULT_DELEGATION_SECONDS,
            DEFAULT_RENEW_MARGIN_SECONDS
        ),
        Err(KeyfileError::DeviceOnly(d)) if d == copy
    ));
}

#[test]
fn split_device_only_dirs_are_never_written() {
    let p = parent();
    let root_dir = p.path().join("r");
    let dev_dir = p.path().join("d");
    let split = IdentityLayout::split(&root_dir, &dev_dir).unwrap();
    let mut keys = IdentityKeys::init_at(&split, NOW, TTL).unwrap();
    fs::remove_file(root_dir.join(ROOT_FILE)).unwrap();
    let _ = fs::remove_file(dev_dir.join(LOCK_FILE));
    let _ = fs::remove_file(root_dir.join(LOCK_FILE));
    let before = (snapshot(&dev_dir), snapshot(&root_dir));
    let is_dev = |e: KeyfileError| matches!(e, KeyfileError::DeviceOnly(ref d) if *d == dev_dir);

    assert!(is_dev(
        IdentityKeys::create_or_load_at(&split, NOW + DAY, TTL)
            .err()
            .unwrap()
    ));
    assert!(is_dev(
        IdentityKeys::renew_at(&split, NOW + DAY, TTL, false)
            .err()
            .unwrap()
    ));
    assert!(is_dev(
        IdentityKeys::rotate_device_at(&split, NOW + DAY, TTL)
            .err()
            .unwrap()
    ));
    assert!(is_dev(
        IdentityKeys::rotate_root_at(&split, NOW + DAY)
            .err()
            .unwrap()
    ));
    // Not due, and due: both are refused before anything is decided.
    for at in [NOW + DAY, NOW + 40 * DAY] {
        assert!(is_dev(
            keys.renew_if_due_at(Some(&split), at, TTL, DEFAULT_RENEW_MARGIN_SECONDS)
                .err()
                .unwrap()
        ));
    }
    assert_eq!((snapshot(&dev_dir), snapshot(&root_dir)), before);
    assert!(!dev_dir.join(LOCK_FILE).exists());
    assert!(!root_dir.join(LOCK_FILE).exists());
}
