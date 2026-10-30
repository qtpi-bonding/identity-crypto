use identity_crypto::{encryption_public, principal_id, signing_public};
use identity_keyfile::*;
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::Path;

/// `tempfile` creates 0755 directories on some platforms; agent dirs must be private.
fn tempdir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

fn mode(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

/// Every entry of `dir` as (name, bytes, mode), sorted by name.
fn snapshot(dir: &Path) -> Vec<(String, Vec<u8>, u32)> {
    let mut entries: Vec<_> = fs::read_dir(dir)
        .unwrap()
        .map(|entry| {
            let path = entry.unwrap().path();
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            (name, fs::read(&path).unwrap(), mode(&path))
        })
        .collect();
    entries.sort();
    entries
}

#[test]
fn duo_files_round_trip_and_are_private() {
    let dir = tempdir();
    let duo = generate();
    write_duo(dir.path(), ROOT_FILE, &duo).unwrap();
    let restored = read_duo(dir.path(), ROOT_FILE).unwrap();
    assert_eq!(
        signing_public(&restored),
        signing_public(&duo),
        "signing half"
    );
    assert_eq!(
        encryption_public(&restored),
        encryption_public(&duo),
        "encryption half"
    );
    assert_eq!(mode(&dir.path().join(ROOT_FILE)), 0o600);

    // A loose file left at the path is replaced by a 0600 file.
    fs::set_permissions(
        dir.path().join(ROOT_FILE),
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    write_duo(dir.path(), ROOT_FILE, &duo).unwrap();
    assert_eq!(mode(&dir.path().join(ROOT_FILE)), 0o600);
    assert_eq!(
        signing_public(&read_duo(dir.path(), ROOT_FILE).unwrap()),
        signing_public(&duo)
    );
}

#[test]
fn delegation_round_trips_through_json_and_verifies() {
    let root = generate();
    let device = generate();
    let id = principal_id(&root);
    let delegation = identity_crypto::delegate_device(&root, &id, &device, 10, 20).unwrap();
    let dir = tempdir();
    write_delegation(dir.path(), &delegation).unwrap();
    let loaded = read_delegation(dir.path()).unwrap();
    let transcript = identity_crypto::transcripts::key_delegation_transcript(&loaded).unwrap();
    assert_eq!(loaded, delegation);
    assert!(
        identity_crypto::verify_p256(&signing_public(&root), &transcript, &loaded.signature)
            .is_ok()
    );
}

#[test]
fn agent_id_round_trips() {
    let dir = tempdir();
    let id = principal_id(&generate());
    write_principal_id(dir.path(), &id).unwrap();
    assert_eq!(read_principal_id(dir.path()).unwrap(), id);
}

#[test]
fn files_have_no_tmp_leftover_and_dir_is_0700() {
    let dir = tempdir();
    let path = dir.path().join("agent");
    let agent = IdentityKeys::init(&path, 100, 50).unwrap();
    assert_eq!(mode(&path), 0o700);
    let mut names: Vec<String> = fs::read_dir(&path)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(
        names,
        [
            ".lock",
            "agent_id",
            "delegation.json",
            "device.jwk.json",
            "retired_devices.json",
            "root.jwk.json",
            "rotations.json",
        ]
    );
    for name in &names {
        assert_eq!(mode(&path.join(name)), 0o600, "{name} is private");
    }
    assert_eq!(read_principal_id(&path).unwrap(), agent.principal_id);
}

#[test]
fn stale_loose_tmp_file_is_not_inherited() {
    let dir = tempdir();
    let stale = dir.path().join(".root.jwk.json.old.tmp");
    fs::write(&stale, b"not a key").unwrap();
    fs::set_permissions(&stale, fs::Permissions::from_mode(0o644)).unwrap();
    IdentityKeys::init(dir.path(), 1, 20).unwrap();
    assert_eq!(
        fs::read(&stale).unwrap(),
        b"not a key",
        "the stale temporary is untouched"
    );
    assert_eq!(mode(&stale), 0o644, "its mode is untouched");
    let root = fs::read(dir.path().join(ROOT_FILE)).unwrap();
    assert_ne!(root, b"not a key");
    assert_eq!(mode(&dir.path().join(ROOT_FILE)), 0o600);
    assert!(IdentityKeys::load(dir.path()).is_ok());
}

#[test]
fn corrupt_history_is_an_error_not_empty() {
    let dir = tempdir();
    IdentityKeys::init(dir.path(), 1, 20).unwrap();

    fs::write(dir.path().join(HISTORY_FILE), b"{").unwrap();
    assert!(matches!(
        IdentityKeys::load(dir.path()),
        Err(KeyfileError::Parse { .. })
    ));
    fs::write(dir.path().join(HISTORY_FILE), b"{\"retired\":[]}").unwrap();
    assert!(IdentityKeys::load(dir.path()).is_ok());

    fs::write(dir.path().join(ROTATIONS_FILE), b"{").unwrap();
    assert!(matches!(
        IdentityKeys::load(dir.path()),
        Err(KeyfileError::Parse { .. })
    ));
    fs::write(dir.path().join(ROTATIONS_FILE), b"{\"rotations\":[]}").unwrap();
    assert!(IdentityKeys::load(dir.path()).is_ok());

    let history = dir.path().join(HISTORY_FILE);
    fs::set_permissions(&history, fs::Permissions::from_mode(0o000)).unwrap();
    let result = IdentityKeys::load(dir.path());
    fs::set_permissions(&history, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(
        matches!(result, Err(KeyfileError::Io { .. })),
        "an unreadable history fails closed"
    );
}

#[test]
fn dangling_history_symlink_is_an_error_not_empty() {
    let dir = tempdir();
    IdentityKeys::init(dir.path(), 1, 20).unwrap();
    let history = dir.path().join(HISTORY_FILE);
    fs::remove_file(&history).unwrap();
    symlink(dir.path().join("nowhere.json"), &history).unwrap();
    assert!(
        IdentityKeys::load(dir.path()).is_err(),
        "a broken link is not an empty history"
    );
}

#[test]
fn loose_existing_dir_is_refused() {
    let dir = tempdir();
    let path = dir.path().join("agent");
    IdentityKeys::init(&path, 1, 20).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    let before = snapshot(&path);

    assert!(matches!(
        IdentityKeys::load(&path),
        Err(KeyfileError::InsecureDir(_))
    ));
    assert!(matches!(
        IdentityKeys::renew(&path, 2, 20, false),
        Err(KeyfileError::InsecureDir(_))
    ));
    assert!(matches!(
        IdentityKeys::rotate_device(&path, 2, 20),
        Err(KeyfileError::InsecureDir(_))
    ));
    assert!(matches!(
        IdentityKeys::rotate_root(&path, 2),
        Err(KeyfileError::InsecureDir(_))
    ));
    assert_eq!(
        snapshot(&path),
        before,
        "a refused operation writes nothing"
    );

    let fresh = dir.path().join("loose-fresh");
    fs::create_dir(&fresh).unwrap();
    fs::set_permissions(&fresh, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(matches!(
        IdentityKeys::init(&fresh, 1, 20),
        Err(KeyfileError::InsecureDir(_))
    ));
    assert!(
        snapshot(&fresh).is_empty(),
        "init on a loose directory writes nothing"
    );
}
