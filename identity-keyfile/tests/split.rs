//! The split layout: the root key in one folder, everything else in the device
//! folder an agent may be shown.

use identity_crypto::{principal_id, signing_public};
use identity_keyfile::*;
use std::collections::BTreeSet;
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Barrier};
use std::thread;

const DAY: i64 = 86_400;
const NOW: i64 = 1_000_000;
const TTL: i64 = 30 * DAY;

struct Split {
    _parent: tempfile::TempDir,
    root: PathBuf,
    dev: PathBuf,
    layout: IdentityLayout,
}

fn split() -> Split {
    let parent = tempfile::tempdir().unwrap();
    fs::set_permissions(parent.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let root = parent.path().join("root");
    let dev = parent.path().join("dev");
    let layout = IdentityLayout::split(&root, &dev).unwrap();
    Split {
        _parent: parent,
        root,
        dev,
        layout,
    }
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

#[test]
fn split_refuses_relative_paths_and_root_inside_device_dir() {
    let s = split();
    for result in [
        IdentityLayout::split(Path::new("rel"), &s.dev),
        IdentityLayout::split(&s.root, Path::new("rel")),
    ] {
        assert!(matches!(
            result,
            Err(KeyfileError::InvalidLayout("paths must be absolute"))
        ));
    }
    for result in [
        IdentityLayout::split(&s.dev, &s.dev),
        IdentityLayout::split(&s.dev.join("r"), &s.dev),
    ] {
        assert!(matches!(
            result,
            Err(KeyfileError::InvalidLayout(
                "root_dir must not be device_dir or inside it"
            ))
        ));
    }
    assert!(matches!(
        IdentityLayout::split(&s.root, &s.root.join("dev")),
        Err(KeyfileError::InvalidLayout(
            "device_dir must not be inside root_dir"
        ))
    ));
    assert!(IdentityLayout::split(&s.root, &s.dev).is_ok());
}

#[test]
fn split_init_keeps_the_root_out_of_the_device_dir() {
    let s = split();
    let keys = IdentityKeys::init_at(&s.layout, NOW, TTL).unwrap();
    assert!(s.layout.is_split());
    assert_eq!(names(&s.root), set(&[".lock", "root.jwk.json"]));
    assert!(!names(&s.dev).contains("root.jwk.json"));
    let device = DeviceKeys::load(&s.dev).unwrap();
    assert_eq!(device.principal_id, keys.principal_id);
    assert_eq!(signing_public(&device.device), signing_public(&keys.device));
    assert_eq!(read_principal(&s.dev).unwrap(), Some(keys.principal_id));
}

#[test]
fn split_init_refuses_when_either_folder_holds_identity_files() {
    let s = split();
    IdentityKeys::init_at(&s.layout, NOW, TTL).unwrap();
    assert!(matches!(
        IdentityKeys::init_at(&s.layout, NOW, TTL),
        Err(KeyfileError::AlreadyInitialised(_))
    ));
    // A root-only leftover.
    fs::remove_dir_all(&s.dev).unwrap();
    assert!(matches!(
        IdentityKeys::init_at(&s.layout, NOW, TTL),
        Err(KeyfileError::AlreadyInitialised(p)) if p == s.root
    ));
    // A device-only leftover.
    fs::remove_file(s.root.join("root.jwk.json")).unwrap();
    fs::write(s.dev.join("agent_id"), b"x").unwrap();
    assert!(matches!(
        IdentityKeys::init_at(&s.layout, NOW, TTL),
        Err(KeyfileError::AlreadyInitialised(p)) if p == s.dev
    ));
}

#[test]
fn split_resolves_dot_components_and_symlink_aliases() {
    let s = split();
    fs::create_dir(&s.dev).unwrap();
    let dotted = s.dev.parent().unwrap().join("x").join("..").join("dev");
    assert!(matches!(
        IdentityLayout::split(&s.root, &dotted),
        Err(KeyfileError::InvalidLayout(_))
    ));
    let alias = s.dev.parent().unwrap().join("alias");
    symlink(&s.dev, &alias).unwrap();
    // root inside the device folder, reached through the alias.
    assert!(matches!(
        IdentityLayout::split(&alias.join("r"), &s.dev),
        Err(KeyfileError::InvalidLayout(
            "root_dir must not be device_dir or inside it"
        ))
    ));
    // The same folder under two names.
    assert!(matches!(
        IdentityLayout::split(&alias, &s.dev),
        Err(KeyfileError::InvalidLayout(
            "root_dir must not be device_dir or inside it"
        ))
    ));
    // The device folder inside the root folder, through an alias.
    let outer = s.dev.parent().unwrap().join("outer");
    fs::create_dir(&outer).unwrap();
    let outer_alias = s.dev.parent().unwrap().join("outer_alias");
    symlink(&outer, &outer_alias).unwrap();
    assert!(matches!(
        IdentityLayout::split(&outer, &outer_alias.join("dev")),
        Err(KeyfileError::InvalidLayout(
            "device_dir must not be inside root_dir"
        ))
    ));
}

#[test]
fn split_renew_and_rotate_device_work_with_the_root_outside() {
    let s = split();
    let first = IdentityKeys::init_at(&s.layout, NOW, TTL).unwrap();
    let renewed = IdentityKeys::renew_at(&s.layout, NOW + DAY, TTL, false).unwrap();
    assert_eq!(renewed.principal_id, first.principal_id);
    let verified = IdentityKeys::load_verified_at(&s.layout).unwrap();
    assert_eq!(verified.delegation, renewed.delegation);
    let rotated = IdentityKeys::rotate_device_at(&s.layout, NOW + 2 * DAY, TTL).unwrap();
    assert_eq!(rotated.retired.len(), 1);
    let device = DeviceKeys::load(&s.dev).unwrap();
    assert_eq!(
        signing_public(&device.device),
        signing_public(&rotated.device)
    );
    assert_ne!(
        signing_public(&device.device),
        signing_public(&first.device)
    );
}

#[test]
fn split_rotate_root_then_renew() {
    let s = split();
    let first = IdentityKeys::init_at(&s.layout, NOW, TTL).unwrap();
    IdentityKeys::rotate_root_at(&s.layout, NOW + DAY).unwrap();
    assert!(s.dev.join("rotations.json").is_file());
    assert!(!s.root.join("rotations.json").exists());
    assert_eq!(names(&s.root), set(&[".lock", "root.jwk.json"]));
    assert!(matches!(
        IdentityKeys::load_verified_at(&s.layout),
        Err(KeyfileError::VerifyFailed(VerifyCheck::SigningRoot))
    ));
    IdentityKeys::renew_at(&s.layout, NOW + 2 * DAY, TTL, false).unwrap();
    let verified = IdentityKeys::load_verified_at(&s.layout).unwrap();
    assert_eq!(verified.principal_id, first.principal_id);
    assert_eq!(read_principal(&s.dev).unwrap(), Some(first.principal_id));
}

#[test]
fn split_create_or_load_is_idempotent_and_recommits_an_uncommitted_attempt() {
    let s = split();
    let first = IdentityKeys::create_or_load_at(&s.layout, NOW, TTL).unwrap();
    let again = IdentityKeys::create_or_load_at(&s.layout, NOW, TTL).unwrap();
    assert_eq!(first.principal_id, again.principal_id);
    fs::remove_file(s.dev.join("agent_id")).unwrap();
    let second = IdentityKeys::create_or_load_at(&s.layout, NOW, TTL).unwrap();
    assert_eq!(second.principal_id, first.principal_id);
    let loaded = IdentityKeys::load_verified_at(&s.layout).unwrap();
    assert_eq!(signing_public(&loaded.root), signing_public(&first.root));
}

#[test]
fn split_create_or_load_keeps_an_orphan_root_as_the_genesis() {
    let s = split();
    fs::create_dir(&s.root).unwrap();
    fs::set_permissions(&s.root, fs::Permissions::from_mode(0o700)).unwrap();
    let root = generate();
    let expected = principal_id(&root);
    write_duo(&s.root, ROOT_FILE, &root).unwrap();
    let keys = IdentityKeys::create_or_load_at(&s.layout, NOW, TTL).unwrap();
    assert_eq!(keys.principal_id, expected);
    assert_eq!(signing_public(&keys.root), signing_public(&root));
    let loaded = IdentityKeys::load_verified_at(&s.layout).unwrap();
    assert_eq!(loaded.principal_id, expected);
}

#[test]
fn split_create_or_load_races_to_one_identity() {
    let s = split();
    let barrier = Arc::new(Barrier::new(8));
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let layout = s.layout.clone();
            let barrier = barrier.clone();
            thread::spawn(move || {
                barrier.wait();
                IdentityKeys::create_or_load_at(&layout, NOW, TTL)
                    .unwrap()
                    .principal_id
            })
        })
        .collect();
    let ids: BTreeSet<String> = handles
        .into_iter()
        .map(|h| h.join().unwrap().to_string())
        .collect();
    assert_eq!(ids.len(), 1);
}

#[test]
fn split_renew_without_the_root_file_is_missing() {
    let s = split();
    IdentityKeys::init_at(&s.layout, NOW, TTL).unwrap();
    fs::remove_file(s.root.join("root.jwk.json")).unwrap();
    match IdentityKeys::renew_at(&s.layout, NOW + DAY, TTL, false) {
        Err(KeyfileError::Missing(path)) => assert_eq!(path, s.root.join("root.jwk.json")),
        other => panic!("expected Missing, got {:?}", other.err()),
    }
}

#[test]
fn exists_at_needs_both_halves() {
    let s = split();
    assert!(!IdentityKeys::exists_at(&s.layout));
    IdentityKeys::init_at(&s.layout, NOW, TTL).unwrap();
    assert!(IdentityKeys::exists_at(&s.layout));
    fs::remove_file(s.root.join("root.jwk.json")).unwrap();
    assert!(!IdentityKeys::exists_at(&s.layout));
}

#[test]
fn single_layout_is_the_classic_folder() {
    let parent = tempfile::tempdir().unwrap();
    let d = parent.path().join("agent");
    let layout = IdentityLayout::single(&d);
    assert!(!layout.is_split());
    let keys = IdentityKeys::init_at(&layout, NOW, TTL).unwrap();
    assert_eq!(
        names(&d),
        set(&[
            ".lock",
            "agent_id",
            "delegation.json",
            "device.jwk.json",
            "retired_devices.json",
            "root.jwk.json",
            "rotations.json",
        ])
    );
    assert_eq!(
        IdentityKeys::load(&d).unwrap().principal_id,
        keys.principal_id
    );
}

fn snapshot(dir: &Path) -> Vec<(String, Vec<u8>)> {
    let mut files: Vec<_> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap())
        .filter(|e| e.path().is_file())
        .map(|e| {
            (
                e.file_name().to_string_lossy().into_owned(),
                fs::read(e.path()).unwrap(),
            )
        })
        .collect();
    files.sort();
    files
}

#[test]
fn crossed_split_layout_never_touches_the_other_identitys_root() {
    let a = split();
    let b = split();
    IdentityKeys::init_at(&a.layout, NOW, TTL).unwrap();
    IdentityKeys::init_at(&b.layout, NOW, TTL).unwrap();
    // A's device folder with B's root.
    let crossed = IdentityLayout::split(&b.root, &a.dev).unwrap();
    let before = (
        snapshot(&a.root),
        snapshot(&a.dev),
        snapshot(&b.root),
        snapshot(&b.dev),
    );
    let mut loaded = IdentityKeys::load_at(&crossed).unwrap();
    let later = NOW + 40 * DAY;

    assert!(matches!(
        IdentityKeys::rotate_root_at(&crossed, later),
        Err(KeyfileError::RootMismatch)
    ));
    assert!(matches!(
        IdentityKeys::renew_at(&crossed, later, TTL, false),
        Err(KeyfileError::RootMismatch)
    ));
    assert!(matches!(
        IdentityKeys::rotate_device_at(&crossed, later, TTL),
        Err(KeyfileError::RootMismatch)
    ));
    assert!(matches!(
        loaded.renew_if_due_at(Some(&crossed), later, TTL, 0),
        Err(KeyfileError::RootMismatch)
    ));
    assert!(IdentityKeys::load_verified_at(&crossed).is_err());

    let after = (
        snapshot(&a.root),
        snapshot(&a.dev),
        snapshot(&b.root),
        snapshot(&b.dev),
    );
    assert_eq!(before, after);
}

#[test]
fn a_crash_pending_rotation_still_passes_the_root_check() {
    let s = split();
    IdentityKeys::init_at(&s.layout, NOW, TTL).unwrap();
    let root_before = fs::read(s.root.join("root.jwk.json")).unwrap();
    IdentityKeys::rotate_root_at(&s.layout, NOW + DAY).unwrap();
    // Put the old root back: the rotation is on file, the root was never installed.
    fs::write(s.root.join("root.jwk.json"), root_before).unwrap();
    IdentityKeys::rotate_root_at(&s.layout, NOW + 2 * DAY).unwrap();
}

#[test]
fn exists_on_a_device_only_folder_is_true_as_in_0_8_0() {
    let s = split();
    IdentityKeys::init_at(&s.layout, NOW, TTL).unwrap();
    assert!(IdentityKeys::exists(&s.dev));
    assert!(!IdentityKeys::exists(&s.root));
    fs::remove_file(s.root.join("root.jwk.json")).unwrap();
    assert!(IdentityKeys::exists(&s.dev));
    assert!(!IdentityKeys::exists_at(&s.layout));
}
