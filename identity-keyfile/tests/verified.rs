//! Tests for the daemon-identity additions: `create_or_load`, `load_verified`,
//! `load_existing`, `exists`, `read_principal` and `renew_if_due`.

use identity_crypto::{encryption_public, pb, principal_id, signing_public, PrincipalId};
use identity_keyfile::*;
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

const DAY: i64 = 86_400;
const NOW: i64 = 1_000_000;
const TTL: i64 = 30 * DAY;
const CHILD_DIR_ENV: &str = "IDENTITY_KEYFILE_VERIFIED_CHILD_DIR";

/// A private (0700) scratch parent; `tempfile` may create 0755 directories.
fn parent() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

/// An identity made by `init` at `<parent>/daemon`.
fn made() -> (tempfile::TempDir, PathBuf, IdentityKeys) {
    let parent = parent();
    let dir = parent.path().join("daemon");
    let keys = IdentityKeys::init(&dir, NOW, TTL).unwrap();
    (parent, dir, keys)
}

fn mode(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

/// The `<name>.tmp-*` siblings of `dir`.
fn temp_siblings(dir: &Path) -> Vec<String> {
    let prefix = format!("{}.tmp-", dir.file_name().unwrap().to_string_lossy());
    fs::read_dir(dir.parent().unwrap())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with(&prefix))
        .collect()
}

/// File name to bytes of every entry of `dir` except the lock file.
fn files_of(dir: &Path) -> BTreeMap<String, Vec<u8>> {
    fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap())
        .filter(|entry| entry.file_name() != LOCK_FILE)
        .map(|entry| {
            (
                entry.file_name().to_string_lossy().into_owned(),
                fs::read(entry.path()).unwrap(),
            )
        })
        .collect()
}

fn change_delegation(dir: &Path, change: impl FnOnce(&mut pb::KeyDelegation)) {
    let mut delegation = read_delegation(dir).unwrap();
    change(&mut delegation);
    write_delegation(dir, &delegation).unwrap();
}

fn rejected_as(result: Result<IdentityKeys, KeyfileError>, check: VerifyCheck) {
    match result {
        Err(KeyfileError::VerifyFailed(found)) => assert_eq!(found, check),
        Err(other) => panic!("expected VerifyFailed({check:?}), got error {other}"),
        Ok(_) => panic!("expected VerifyFailed({check:?}), but the identity loaded"),
    }
}

// ---- create_or_load ----

#[test]
fn create_or_load_creates_then_reloads_the_same_principal() {
    let parent = parent();
    let dir = parent.path().join("daemon");
    assert!(!IdentityKeys::exists(&dir));

    let created = IdentityKeys::create_or_load(&dir, NOW, TTL).unwrap();
    assert!(IdentityKeys::exists(&dir));
    assert_eq!(mode(&dir), 0o700);
    for name in [
        ROOT_FILE,
        DEVICE_FILE,
        DELEGATION_FILE,
        AGENT_ID_FILE,
        HISTORY_FILE,
        ROTATIONS_FILE,
    ] {
        assert!(dir.join(name).is_file(), "{name} was written");
        assert_eq!(mode(&dir.join(name)), 0o600, "{name} is private");
    }
    assert!(
        temp_siblings(&dir).is_empty(),
        "the temporary directory was renamed away"
    );
    assert_eq!(created.delegation.not_after_unix_seconds, NOW + TTL);
    assert_eq!(
        IdentityKeys::load_verified(&dir).unwrap().principal_id,
        created.principal_id
    );

    let before = files_of(&dir);
    let again = IdentityKeys::create_or_load(&dir, NOW + 5 * DAY, TTL).unwrap();
    assert_eq!(again.principal_id, created.principal_id);
    assert_eq!(
        signing_public(&again.device),
        signing_public(&created.device)
    );
    assert_eq!(files_of(&dir), before, "the second call changed nothing");
    assert!(temp_siblings(&dir).is_empty());
}

#[test]
fn create_or_load_never_exposes_a_partial_directory() {
    // (a) and (b): stale and live temporary siblings.
    let parent = parent();
    let dir = parent.path().join("daemon");

    let mut done = Command::new("true").spawn().unwrap();
    let dead_pid = done.id();
    done.wait().unwrap();
    let stale = parent.path().join(format!("daemon.tmp-{dead_pid}-0"));
    fs::create_dir(&stale).unwrap();
    fs::write(stale.join("root.jwk.json"), b"junk from a crashed process").unwrap();

    let sleeper = Sleeper::start();
    let live = parent
        .path()
        .join(format!("daemon.tmp-{}-0", sleeper.pid()));
    fs::create_dir(&live).unwrap();
    fs::write(live.join("root.jwk.json"), b"another process is writing").unwrap();

    let keys = IdentityKeys::create_or_load(&dir, NOW, TTL).unwrap();
    assert_eq!(
        IdentityKeys::load_verified(&dir).unwrap().principal_id,
        keys.principal_id
    );
    assert!(
        !stale.exists(),
        "a dead process's temporary directory is removed"
    );
    assert_eq!(
        fs::read(live.join("root.jwk.json")).unwrap(),
        b"another process is writing",
        "a live process's temporary directory is left alone"
    );
    drop(sleeper);

    // (c): a half-written directory with data files and no agent_id.
    let (_source_parent, source, _keys) = made();
    let parent = self::parent();
    let half = parent.path().join("daemon");
    fs::create_dir(&half).unwrap();
    fs::set_permissions(&half, fs::Permissions::from_mode(0o700)).unwrap();
    for name in [ROOT_FILE, DEVICE_FILE, DELEGATION_FILE, HISTORY_FILE] {
        fs::copy(source.join(name), half.join(name)).unwrap();
    }
    let before = files_of(&half);
    assert!(!before.contains_key(AGENT_ID_FILE));

    assert!(!IdentityKeys::exists(&half));
    assert!(matches!(IdentityKeys::load_existing(&half), Ok(None)));
    assert!(matches!(read_principal(&half), Ok(None)));
    assert!(
        IdentityKeys::create_or_load(&half, NOW, TTL).is_err(),
        "create_or_load must not create over a half-written directory"
    );
    assert_eq!(
        files_of(&half),
        before,
        "the half-written files are untouched"
    );
    assert!(!IdentityKeys::exists(&half));
    assert!(
        temp_siblings(&half).is_empty(),
        "the failed attempt removed its own temporary directory"
    );
}

/// A `sleep 30` process that is killed when dropped.
struct Sleeper(Child);

impl Sleeper {
    fn start() -> Self {
        Sleeper(
            Command::new("sleep")
                .arg("30")
                .stdout(Stdio::null())
                .spawn()
                .unwrap(),
        )
    }

    fn pid(&self) -> u32 {
        self.0.id()
    }
}

impl Drop for Sleeper {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn create_or_load_on_an_empty_existing_directory_or_lock_only_directory_creates() {
    let parent = parent();
    let dir = parent.path().join("daemon");
    fs::create_dir(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(dir.join(LOCK_FILE), b"").unwrap();
    fs::set_permissions(dir.join(LOCK_FILE), fs::Permissions::from_mode(0o600)).unwrap();

    let keys = IdentityKeys::create_or_load(&dir, NOW, TTL).unwrap();
    assert!(IdentityKeys::exists(&dir));
    assert_eq!(
        IdentityKeys::load_verified(&dir).unwrap().principal_id,
        keys.principal_id
    );
    assert!(temp_siblings(&dir).is_empty());
}

/// Run by `concurrent_create_or_load_agrees_on_one_identity` in a child process.
/// Returns at once when the environment variable is absent.
#[test]
fn concurrent_child_helper() {
    let Some(dir) = std::env::var_os(CHILD_DIR_ENV) else {
        return;
    };
    let dir = PathBuf::from(dir);
    let go = dir.parent().unwrap().join("go");
    let deadline = Instant::now() + Duration::from_secs(30);
    while !go.exists() {
        assert!(
            Instant::now() < deadline,
            "the parent never released the child"
        );
        thread::sleep(Duration::from_millis(2));
    }
    let keys = IdentityKeys::create_or_load(&dir, NOW, TTL).unwrap();
    println!("CHILD_PRINCIPAL={}", keys.principal_id);
}

#[test]
fn concurrent_create_or_load_agrees_on_one_identity() {
    const THREADS: usize = 8;
    let parent = parent();
    let dir = parent.path().join("daemon");

    let child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "concurrent_child_helper", "--nocapture"])
        .env(CHILD_DIR_ENV, &dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let barrier = Arc::new(Barrier::new(THREADS + 1));
    let handles: Vec<_> = (0..THREADS)
        .map(|_| {
            let dir = dir.clone();
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                IdentityKeys::create_or_load(&dir, NOW, TTL)
                    .map(|keys| keys.principal_id.to_string())
                    .map_err(|error| error.to_string())
            })
        })
        .collect();
    barrier.wait();
    fs::write(parent.path().join("go"), b"").unwrap();

    let principals: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().expect("thread did not panic"))
        .collect();
    let output = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "the child failed: {stdout}{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let child_principal = stdout
        .lines()
        .find_map(|line| line.strip_prefix("CHILD_PRINCIPAL="))
        .unwrap_or_else(|| panic!("the child printed no principal: {stdout}"))
        .to_owned();

    let loaded = IdentityKeys::load_verified(&dir)
        .unwrap()
        .principal_id
        .to_string();
    for result in principals {
        assert_eq!(result.expect("no thread saw an error"), loaded);
    }
    assert_eq!(child_principal, loaded);
    assert!(IdentityKeys::exists(&dir));
    assert!(
        temp_siblings(&dir).is_empty(),
        "no temporary directory remains: {:?}",
        temp_siblings(&dir)
    );
}

// ---- load_verified ----

#[test]
fn load_verified_accepts_a_consistent_identity() {
    let (_parent, dir, keys) = made();
    let loaded = IdentityKeys::load_verified(&dir).unwrap();
    assert_eq!(loaded.principal_id, keys.principal_id);
    assert_eq!(loaded.delegation, keys.delegation);
}

#[test]
fn load_verified_rejects_wrong_agent_id() {
    let (_parent, dir, _keys) = made();
    let stranger = generate();
    write_principal_id(&dir, &principal_id(&stranger)).unwrap();
    rejected_as(IdentityKeys::load_verified(&dir), VerifyCheck::AgentId);
}

#[test]
fn load_verified_rejects_wrong_principal_genesis() {
    let (_parent, dir, _keys) = made();
    let stranger = pb::PublicKey::from(&signing_public(&generate()));
    change_delegation(&dir, |d| d.principal_genesis = Some(stranger));
    rejected_as(
        IdentityKeys::load_verified(&dir),
        VerifyCheck::PrincipalGenesis,
    );
}

#[test]
fn load_verified_rejects_wrong_signing_root() {
    let (_parent, dir, _keys) = made();
    let stranger = pb::PublicKey::from(&signing_public(&generate()));
    change_delegation(&dir, |d| d.signing_root = Some(stranger));
    rejected_as(IdentityKeys::load_verified(&dir), VerifyCheck::SigningRoot);
}

#[test]
fn load_verified_rejects_wrong_delegated() {
    let (_parent, dir, _keys) = made();
    let stranger = pb::PublicKey::from(&signing_public(&generate()));
    change_delegation(&dir, |d| d.delegated = Some(stranger));
    rejected_as(IdentityKeys::load_verified(&dir), VerifyCheck::Delegated);
}

#[test]
fn load_verified_rejects_wrong_delegated_encryption() {
    let (_parent, dir, _keys) = made();
    let stranger = pb::PublicKey::from(&encryption_public(&generate()));
    change_delegation(&dir, |d| d.delegated_encryption = Some(stranger));
    rejected_as(
        IdentityKeys::load_verified(&dir),
        VerifyCheck::DelegatedEncryption,
    );
}

#[test]
fn load_verified_rejects_wrong_purpose() {
    let (_parent, dir, _keys) = made();
    change_delegation(&dir, |d| d.purpose = pb::KeyPurpose::Approval as i32);
    rejected_as(IdentityKeys::load_verified(&dir), VerifyCheck::Purpose);
}

#[test]
fn load_verified_rejects_tampered_signature() {
    let (_parent, dir, _keys) = made();
    change_delegation(&dir, |d| d.signature[0] ^= 0x01);
    rejected_as(IdentityKeys::load_verified(&dir), VerifyCheck::Signature);
}

#[test]
fn plain_load_still_accepts_what_load_verified_rejects() {
    let (_parent, dir, _keys) = made();
    change_delegation(&dir, |d| d.signature[0] ^= 0x01);
    assert!(IdentityKeys::load(&dir).is_ok(), "load keeps its behaviour");
    assert!(IdentityKeys::load_verified(&dir).is_err());
}

// ---- load_existing and exists ----

#[test]
fn load_existing_and_exists_cover_missing_and_present() {
    let parent = parent();
    let dir = parent.path().join("daemon");
    assert!(!IdentityKeys::exists(&dir));
    assert!(matches!(IdentityKeys::load_existing(&dir), Ok(None)));

    let keys = IdentityKeys::init(&dir, NOW, TTL).unwrap();
    assert!(IdentityKeys::exists(&dir));
    let loaded = IdentityKeys::load_existing(&dir).unwrap().expect("present");
    assert_eq!(loaded.principal_id, keys.principal_id);

    change_delegation(&dir, |d| d.signature[0] ^= 0x01);
    assert!(
        IdentityKeys::exists(&dir),
        "exists only looks for the marker"
    );
    assert!(
        matches!(
            IdentityKeys::load_existing(&dir),
            Err(KeyfileError::VerifyFailed(VerifyCheck::Signature))
        ),
        "a present but inconsistent identity is verified, not skipped"
    );
}

// ---- read_principal ----

#[test]
fn read_principal_is_none_when_missing() {
    let parent = parent();
    assert!(matches!(
        read_principal(&parent.path().join("daemon")),
        Ok(None)
    ));
}

#[test]
fn read_principal_matches_the_identity_without_reading_private_keys() {
    let (_parent, dir, keys) = made();
    assert_eq!(
        read_principal(&dir).unwrap(),
        Some(keys.principal_id.clone())
    );

    for name in [ROOT_FILE, DEVICE_FILE] {
        fs::set_permissions(dir.join(name), fs::Permissions::from_mode(0o000)).unwrap();
    }
    assert_eq!(
        read_principal(&dir).unwrap(),
        Some(keys.principal_id.clone()),
        "unreadable private files are not needed"
    );
    for name in [ROOT_FILE, DEVICE_FILE] {
        fs::remove_file(dir.join(name)).unwrap();
    }
    assert_eq!(
        read_principal(&dir).unwrap(),
        Some(keys.principal_id.clone()),
        "absent private files are not needed"
    );
}

#[test]
fn read_principal_rejects_a_tampered_signature() {
    let (_parent, dir, _keys) = made();
    change_delegation(&dir, |d| d.signature[0] ^= 0x01);
    assert!(matches!(
        read_principal(&dir),
        Err(KeyfileError::VerifyFailed(VerifyCheck::Signature))
    ));
}

#[test]
fn read_principal_rejects_an_agent_id_that_differs_from_the_genesis() {
    let (_parent, dir, _keys) = made();
    let stranger: PrincipalId = principal_id(&generate());
    write_principal_id(&dir, &stranger).unwrap();
    assert!(read_principal(&dir).is_err());
}

#[test]
fn read_principal_rejects_a_genesis_that_differs_from_the_signing_root() {
    let (_parent, dir, _keys) = made();
    let stranger = pb::PublicKey::from(&signing_public(&generate()));
    change_delegation(&dir, |d| d.principal_genesis = Some(stranger));
    assert!(read_principal(&dir).is_err());
}

// ---- renew_if_due ----

#[test]
fn renew_if_due_renews_at_the_margin_and_not_before() {
    let parent = parent();
    let dir = parent.path().join("daemon");
    let margin = 15 * DAY;
    let mut keys = IdentityKeys::create_or_load(&dir, NOW, TTL).unwrap();
    let principal = keys.principal_id.clone();
    let device = signing_public(&keys.device);
    let file = dir.join(DELEGATION_FILE);
    let original = fs::read(&file).unwrap();
    let original_delegation = keys.delegation.clone();

    // 16 days left: not due.
    let early = NOW + 14 * DAY;
    assert!(!keys.renew_if_due(Some(&dir), early, TTL, margin).unwrap());
    assert_eq!(fs::read(&file).unwrap(), original);
    assert_eq!(keys.delegation, original_delegation);

    // 15 days left: due.
    let due = NOW + 15 * DAY;
    assert!(keys.renew_if_due(Some(&dir), due, TTL, margin).unwrap());
    assert_eq!(keys.delegation.issued_at_unix_seconds, due);
    assert_eq!(keys.delegation.not_after_unix_seconds, due + TTL);
    assert!(keys.delegation.not_after_unix_seconds > original_delegation.not_after_unix_seconds);
    assert_ne!(fs::read(&file).unwrap(), original, "written to disk");
    assert_eq!(mode(&file), 0o600);
    let reloaded = IdentityKeys::load_verified(&dir).unwrap();
    assert_eq!(reloaded.delegation, keys.delegation);
    assert_eq!(reloaded.principal_id, principal);
    assert_eq!(keys.principal_id, principal);
    assert_eq!(signing_public(&reloaded.device), device);
    assert_eq!(signing_public(&keys.device), device);

    // Without a directory the renewal stays in memory.
    let on_disk = fs::read(&file).unwrap();
    let again = due + TTL - margin;
    assert!(keys.renew_if_due(None, again, TTL, margin).unwrap());
    assert_eq!(keys.delegation.issued_at_unix_seconds, again);
    assert_eq!(fs::read(&file).unwrap(), on_disk, "no dir, no write");
}

// ---- insecure directories ----

/// A complete identity at `<parent>/daemon`, made world-readable.
fn loose_identity() -> (tempfile::TempDir, PathBuf) {
    let (parent, dir, _keys) = made();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
    (parent, dir)
}

/// A symlink `<parent>/link` to a complete identity directory.
fn linked_identity() -> (tempfile::TempDir, PathBuf) {
    let (parent, dir, _keys) = made();
    let link = parent.path().join("link");
    symlink(&dir, &link).unwrap();
    (parent, link)
}

fn insecure<T>(result: Result<T, KeyfileError>) -> bool {
    matches!(result, Err(KeyfileError::InsecureDir(_)))
}

#[test]
fn create_or_load_refuses_a_loose_directory() {
    let (_parent, dir) = loose_identity();
    assert!(insecure(IdentityKeys::create_or_load(&dir, NOW, TTL)));
    assert_eq!(mode(&dir), 0o755, "the mode is not repaired");
}

#[test]
fn create_or_load_refuses_a_symlinked_directory() {
    let (_parent, link) = linked_identity();
    assert!(insecure(IdentityKeys::create_or_load(&link, NOW, TTL)));
}

#[test]
fn load_verified_refuses_a_loose_directory() {
    let (_parent, dir) = loose_identity();
    assert!(insecure(IdentityKeys::load_verified(&dir)));
}

#[test]
fn load_verified_refuses_a_symlinked_directory() {
    let (_parent, link) = linked_identity();
    assert!(insecure(IdentityKeys::load_verified(&link)));
}

#[test]
fn load_existing_refuses_a_loose_directory() {
    let (_parent, dir) = loose_identity();
    assert!(insecure(IdentityKeys::load_existing(&dir)));
}

#[test]
fn load_existing_refuses_a_symlinked_directory() {
    let (_parent, link) = linked_identity();
    assert!(insecure(IdentityKeys::load_existing(&link)));
}
