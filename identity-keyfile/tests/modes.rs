//! Task 7: key files are read checked (mode, owner, no symlink, capped);
//! public files are only capped; the identity dir must be private.

use identity_keyfile::private_fs::MAX_PUBLIC_FILE_BYTES;
use identity_keyfile::*;
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};

const NOW: i64 = 1_000_000;
const TTL: i64 = 30 * 86_400;

fn chmod(path: &Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

/// A private scratch parent and an identity made by `init` at `<parent>/daemon`.
fn made() -> (tempfile::TempDir, PathBuf) {
    let parent = tempfile::tempdir().unwrap();
    chmod(parent.path(), 0o700);
    let dir = parent.path().join("daemon");
    IdentityKeys::init(&dir, NOW, TTL).unwrap();
    (parent, dir)
}

fn insecure_file(result: Result<IdentityKeys, KeyfileError>, expected: &Path) {
    match result {
        Err(KeyfileError::InsecureFile(found)) => assert_eq!(found, expected),
        Err(other) => panic!("expected InsecureFile, got error {other}"),
        Ok(_) => panic!("expected InsecureFile({expected:?}), but the identity loaded"),
    }
}

#[test]
fn loose_key_file_in_private_dir_refused() {
    for name in [DEVICE_FILE, ROOT_FILE] {
        let (_parent, dir) = made();
        let file = dir.join(name);
        chmod(&file, 0o644);
        insecure_file(IdentityKeys::load(&dir), &file);
    }
}

#[test]
fn loose_public_file_in_private_dir_loads() {
    let (_parent, dir) = made();
    let before = read_principal_id(&dir).ok();
    // Create the optional public files when init did not write them.
    if !dir.join(ROTATIONS_FILE).exists() {
        write_rotations(&dir, &Default::default()).unwrap();
    }
    if !dir.join(HISTORY_FILE).exists() {
        write_history(&dir, &Default::default()).unwrap();
    }
    for name in [DELEGATION_FILE, ROTATIONS_FILE, HISTORY_FILE, AGENT_ID_FILE] {
        let file = dir.join(name);
        if file.exists() {
            chmod(&file, 0o644);
        }
    }
    let keys = IdentityKeys::load_verified(&dir).expect("loose public files must load");
    let _ = keys;
    assert_eq!(read_principal_id(&dir).ok(), before);
}

#[test]
fn loose_identity_dir_refused() {
    let (_parent, dir) = made();
    chmod(&dir, 0o755);
    match IdentityKeys::load(&dir) {
        Err(KeyfileError::InsecureDir(found)) => assert_eq!(found, dir),
        Err(other) => panic!("expected InsecureDir, got error {other}"),
        Ok(_) => panic!("expected InsecureDir, but the identity loaded"),
    }
}

#[test]
fn symlinked_key_file_refused() {
    let (parent, dir) = made();
    let file = dir.join(DEVICE_FILE);
    let real = parent.path().join("elsewhere.jwk.json");
    fs::rename(&file, &real).unwrap();
    symlink(&real, &file).unwrap();
    insecure_file(IdentityKeys::load(&dir), &file);
}

#[test]
fn oversize_delegation_refused() {
    let (_parent, dir) = made();
    let file = dir.join(DELEGATION_FILE);
    fs::write(&file, vec![b' '; MAX_PUBLIC_FILE_BYTES + 1]).unwrap();
    chmod(&file, 0o600);
    match IdentityKeys::load(&dir) {
        Err(KeyfileError::TooLarge { path, cap }) => {
            assert_eq!(path, file);
            assert_eq!(cap, MAX_PUBLIC_FILE_BYTES);
        }
        Err(other) => panic!("expected TooLarge, got error {other}"),
        Ok(_) => panic!("expected TooLarge, but the identity loaded"),
    }
}

#[test]
fn read_duo_now_refuses_loose_file() {
    let (_parent, dir) = made();
    chmod(&dir.join(DEVICE_FILE), 0o644);
    match read_duo(&dir, DEVICE_FILE) {
        Err(KeyfileError::InsecureFile(found)) => assert_eq!(found, dir.join(DEVICE_FILE)),
        Err(other) => panic!("expected InsecureFile, got error {other}"),
        Ok(_) => panic!("expected InsecureFile, but the file was read"),
    }
}
