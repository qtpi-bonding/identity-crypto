//! The machine identity directory, service directory precedence and the
//! checked `enrolments.json` index.
//!
//! Not covered here (needs a unit test next to the code): "directory owned by
//! another uid via the crate seam -> DirOwner".
//!
//! TempMachineDir (testkit) is not built yet: tests use a plain 0700 tempfile
//! dir and `MachineDir::at`.

use identity_crypto::{principal_id, signing_public, PrincipalId};
use identity_keyfile::*;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::SystemTime;

const DAY: i64 = 86_400;
const NOW: i64 = 1_000_000;
const TTL: i64 = 30 * DAY;

fn private_dir(path: &Path) {
    fs::create_dir_all(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

/// A 0700 temp parent, and a created machine dir `<parent>/machine`.
fn machine() -> (tempfile::TempDir, MachineDir) {
    let parent = tempfile::tempdir().unwrap();
    fs::set_permissions(parent.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let machine = MachineDir::at(parent.path().join("machine"));
    machine.ensure().unwrap();
    (parent, machine)
}

/// A fresh identity in `dir` (created 0700). Returns its principal and device key id.
fn identity(dir: &Path) -> (PrincipalId, String) {
    private_dir(dir);
    let keys = IdentityKeys::init(dir, NOW, TTL).unwrap();
    let device_id = signing_public(&keys.device).thumbprint();
    (keys.principal_id, device_id)
}

fn owner() -> PrincipalId {
    principal_id(&generate())
}

fn entry(dir: &Path) -> Enrolment {
    enrolment_for(dir, None).unwrap()
}

fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<OsString> {
    let map: HashMap<String, String> = pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    move |k: &str| map.get(k).map(OsString::from)
}

type Snapshot = BTreeMap<String, (Vec<u8>, SystemTime)>;

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

fn mismatch(result: Result<Option<&Enrolment>, KeyfileError>, key: &str, want: EnrolmentCheck) {
    match result {
        Err(KeyfileError::EnrolmentMismatch { key: k, check }) => {
            assert_eq!(k, key);
            assert_eq!(check, want);
        }
        Err(other) => panic!("expected EnrolmentMismatch({want:?}), got {other}"),
        Ok(_) => panic!("expected EnrolmentMismatch({want:?}), got Ok"),
    }
}

#[test]
fn machine_dir_precedence() {
    let dir = |pairs: &[(&str, &str)]| MachineDir::locate_with(env(pairs)).unwrap();
    assert_eq!(
        dir(&[
            ("MACHINE_IDENTITY_DIR", "/m"),
            ("XDG_DATA_HOME", "/x"),
            ("HOME", "/h")
        ])
        .path(),
        Path::new("/m")
    );
    assert_eq!(
        dir(&[
            ("MACHINE_IDENTITY_DIR", ""),
            ("XDG_DATA_HOME", "/x"),
            ("HOME", "/h")
        ])
        .path(),
        Path::new("/x/machine-identity")
    );
    assert_eq!(
        dir(&[("HOME", "/h")]).path(),
        Path::new("/h/.local/share/machine-identity")
    );
    assert!(matches!(
        MachineDir::locate_with(env(&[])),
        Err(KeyfileError::MachineDirUnresolved)
    ));
    assert!(matches!(
        MachineDir::locate_with(env(&[("MACHINE_IDENTITY_DIR", "rel")])),
        Err(KeyfileError::InvalidLayout(_))
    ));
}

#[test]
fn service_identity_dir_override_beats_index_beats_default() {
    let (parent, machine) = machine();
    let key = "structmux/3b6a";

    // Default: nothing enrolled, nothing created.
    let (dir, source) = service_identity_dir(None, &machine, key).unwrap();
    assert_eq!(
        dir,
        machine.path().join("services").join("structmux%2F3b6a")
    );
    assert_eq!(source, DirSource::Default);
    let (dir, _) = service_identity_dir(None, &machine, "a:b/c").unwrap();
    assert_eq!(dir, machine.path().join("services").join("a%3Ab%2Fc"));

    // Index beats default.
    let enrolled = parent.path().join("enrolled");
    identity(&enrolled);
    IdentityEnrol::enrol(&machine, key, &enrolled);
    let (dir, source) = service_identity_dir(None, &machine, key).unwrap();
    assert_eq!(dir, enrolled);
    assert_eq!(source, DirSource::Index);

    // Override beats index.
    let over = parent.path().join("override");
    let (dir, source) = service_identity_dir(Some(&over), &machine, key).unwrap();
    assert_eq!(dir, over);
    assert_eq!(source, DirSource::Override);
}

/// Small helper namespace so the enrol call reads the same everywhere.
struct IdentityEnrol;
impl IdentityEnrol {
    fn enrol(machine: &MachineDir, key: &str, dir: &Path) {
        EnrolmentIndex::enrol(machine, key, entry(dir), &owner()).unwrap();
    }
}

#[test]
fn index_golden_shape() {
    let (parent, machine) = machine();
    let grok = parent.path().join("grok");
    let smux = parent.path().join("smux");
    let (grok_p, grok_d) = identity(&grok);
    let (smux_p, smux_d) = identity(&smux);
    let o = owner();
    EnrolmentIndex::enrol(&machine, "grorg", entry(&grok), &o).unwrap();
    EnrolmentIndex::enrol(&machine, "structmux/3b6a27bcceb6a42d", entry(&smux), &o).unwrap();

    let golden = include_str!("fixtures/enrolments.golden.json")
        .replace("{{DIR_GROK}}", grok.to_str().unwrap())
        .replace("{{PRINCIPAL_GROK}}", &grok_p.to_string())
        .replace("{{DEVICE_GROK}}", &grok_d)
        .replace("{{DIR_STRUCTMUX}}", smux.to_str().unwrap())
        .replace("{{PRINCIPAL_STRUCTMUX}}", &smux_p.to_string())
        .replace("{{DEVICE_STRUCTMUX}}", &smux_d);
    let text = fs::read_to_string(machine.path().join(ENROLMENTS_FILE)).unwrap();
    assert_eq!(text, golden);
    assert!(text.ends_with("}\n"));

    let value: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(value["version"], 1);
    assert_eq!(value["services"]["grorg"]["dir"], grok.to_str().unwrap());
    assert!(value["services"]["grorg"].get("endpoint").is_none());

    let index = EnrolmentIndex::read(&machine).unwrap();
    assert_eq!(index.services().count(), 2);
}

#[test]
fn index_unknown_version_refused() {
    let (_p, machine) = machine();
    let path = machine.path().join(ENROLMENTS_FILE);
    fs::write(&path, "{\"version\":2,\"services\":{}}\n").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(matches!(
        EnrolmentIndex::read(&machine),
        Err(KeyfileError::IndexVersion(2))
    ));
}

#[test]
fn index_unknown_field_refused() {
    let (parent, machine) = machine();
    let dir = parent.path().join("a");
    let (p, d) = identity(&dir);
    let path = machine.path().join(ENROLMENTS_FILE);
    let body = serde_json::json!({
        "version": 1,
        "services": { "grorg": {
            "principal_id": p.to_string(),
            "device_key_id": d,
            "dir": dir.to_str().unwrap(),
            "delegation_not_after": 123
        }}
    });
    fs::write(&path, serde_json::to_string_pretty(&body).unwrap() + "\n").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(matches!(
        EnrolmentIndex::read(&machine),
        Err(KeyfileError::Parse { .. })
    ));

    // Top level too.
    fs::write(&path, "{\"version\":1,\"services\":{},\"extra\":1}\n").unwrap();
    assert!(matches!(
        EnrolmentIndex::read(&machine),
        Err(KeyfileError::Parse { .. })
    ));
}

#[test]
fn index_concurrent_enrol_keeps_all() {
    let (parent, machine) = machine();
    let o = owner();
    let barrier = Arc::new(Barrier::new(8));
    let mut jobs = Vec::new();
    for i in 0..8 {
        let dir = parent.path().join(format!("id{i}"));
        identity(&dir);
        jobs.push((format!("svc{i}"), entry(&dir)));
    }
    let handles: Vec<_> = jobs
        .into_iter()
        .map(|(key, e)| {
            let machine = machine.clone();
            let barrier = barrier.clone();
            let o = o.clone();
            thread::spawn(move || {
                barrier.wait();
                EnrolmentIndex::enrol(&machine, &key, e, &o).unwrap();
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
    let index = EnrolmentIndex::read(&machine).unwrap();
    assert_eq!(index.services().count(), 8);
    let mode = fs::metadata(machine.path().join(ENROLMENTS_FILE))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600);
    let names: BTreeSet<String> = fs::read_dir(machine.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert!(names.iter().all(|n| !n.ends_with(".tmp")), "{names:?}");
}

#[test]
fn index_entry_checks() {
    let (parent, machine) = machine();
    let o = owner();
    let enrol = |key: &str, dir: &Path| {
        EnrolmentIndex::enrol(&machine, key, entry(dir), &o).unwrap();
    };

    // Good entry passes.
    let good = parent.path().join("good");
    let (gp, _) = identity(&good);
    enrol("good", &good);
    let index = EnrolmentIndex::read(&machine).unwrap();
    assert_eq!(index.checked("good").unwrap().unwrap().principal_id, gp);
    assert!(index.checked("absent").unwrap().is_none());

    // Loose directory.
    let loose = parent.path().join("loose");
    identity(&loose);
    enrol("loose", &loose);
    fs::set_permissions(&loose, fs::Permissions::from_mode(0o755)).unwrap();
    let index = EnrolmentIndex::read(&machine).unwrap();
    mismatch(index.checked("loose"), "loose", EnrolmentCheck::DirInsecure);

    // Directory replaced by a symlink to a private directory.
    let linked = parent.path().join("linked");
    identity(&linked);
    enrol("linked", &linked);
    let moved = parent.path().join("linked-real");
    fs::rename(&linked, &moved).unwrap();
    symlink(&moved, &linked).unwrap();
    let index = EnrolmentIndex::read(&machine).unwrap();
    mismatch(
        index.checked("linked"),
        "linked",
        EnrolmentCheck::DirInsecure,
    );

    // Missing directory.
    let gone = parent.path().join("gone");
    identity(&gone);
    enrol("gone", &gone);
    fs::remove_dir_all(&gone).unwrap();
    let index = EnrolmentIndex::read(&machine).unwrap();
    mismatch(index.checked("gone"), "gone", EnrolmentCheck::DirMissing);

    // agent_id replaced by another identity's.
    let swapped = parent.path().join("swapped");
    identity(&swapped);
    enrol("swapped", &swapped);
    write_principal_id(&swapped, &owner()).unwrap();
    let index = EnrolmentIndex::read(&machine).unwrap();
    mismatch(
        index.checked("swapped"),
        "swapped",
        EnrolmentCheck::PrincipalId,
    );

    // Device rotated after enrolment.
    let rotated = parent.path().join("rotated");
    identity(&rotated);
    enrol("rotated", &rotated);
    IdentityKeys::rotate_device(&rotated, NOW + DAY, TTL).unwrap();
    let index = EnrolmentIndex::read(&machine).unwrap();
    mismatch(
        index.checked("rotated"),
        "rotated",
        EnrolmentCheck::DeviceKeyId,
    );
}

#[test]
fn index_refuses_owner_principal() {
    let (parent, machine) = machine();
    let dir = parent.path().join("a");
    let (p, _) = identity(&dir);
    assert!(matches!(
        EnrolmentIndex::enrol(&machine, "grorg", entry(&dir), &p),
        Err(KeyfileError::OwnerEnrolment)
    ));
    assert!(!machine.path().join(ENROLMENTS_FILE).exists());
}

#[test]
fn index_key_grammar() {
    let (parent, machine) = machine();
    let dir = parent.path().join("a");
    identity(&dir);
    let o = owner();
    let too_long = "a".repeat(129);
    for k in ["", "Grorg", "/x", "a/../b", too_long.as_str()] {
        assert!(
            matches!(
                EnrolmentIndex::enrol(&machine, k, entry(&dir), &o),
                Err(KeyfileError::InvalidEnrolmentKey(_))
            ),
            "key {k:?}"
        );
    }
    // service_identity_dir applies the same grammar, with the same error.
    for k in [
        "",
        ".",
        "..",
        "a/b/..",
        "a/../b",
        "Grorg",
        "/x",
        "a b",
        too_long.as_str(),
    ] {
        assert!(
            matches!(
                service_identity_dir(None, &machine, k),
                Err(KeyfileError::InvalidEnrolmentKey(ref bad)) if bad == k
            ),
            "service_identity_dir key {k:?}"
        );
        // An override does not bypass the grammar either.
        assert!(
            matches!(
                service_identity_dir(Some(&dir), &machine, k),
                Err(KeyfileError::InvalidEnrolmentKey(_))
            ),
            "service_identity_dir override key {k:?}"
        );
    }
    // Boundary keys are accepted.
    for k in ["a", "0x", "a.b_c", "a:b/c-d", "a".repeat(128).as_str()] {
        let k = k.replace('_', "-");
        EnrolmentIndex::enrol(&machine, &k, entry(&dir), &o).unwrap();
    }
}

#[test]
fn enrol_writes_nothing_in_enrolled_dir() {
    let (parent, machine) = machine();
    let dir = parent.path().join("a");
    let (p, _) = identity(&dir);
    let before = snapshot(&dir);
    EnrolmentIndex::enrol(&machine, "grorg", entry(&dir), &owner()).unwrap();
    let index = EnrolmentIndex::read(&machine).unwrap();
    index.checked("grorg").unwrap().unwrap();
    assert_eq!(snapshot(&dir), before);
    assert_eq!(read_principal(&dir).unwrap(), Some(p));
}

#[test]
fn index_entry_pointing_at_legacy_dir_loads() {
    let (parent, machine) = machine();
    // Outside the machine directory, as a pre-existing service identity.
    let legacy = parent.path().join("legacy-identity");
    let (p, _) = identity(&legacy);
    assert!(!legacy.starts_with(machine.path()));
    EnrolmentIndex::enrol(&machine, "grorg", entry(&legacy), &owner()).unwrap();
    let index = EnrolmentIndex::read(&machine).unwrap();
    let e = index.checked("grorg").unwrap().unwrap();
    assert_eq!(e.dir, legacy);
    assert_eq!(e.principal_id, p);
    let keys = IdentityKeys::load_verified(&legacy).unwrap();
    assert_eq!(keys.principal_id, e.principal_id);
}

#[test]
fn index_loose_file_refused() {
    let (parent, machine) = machine();
    let dir = parent.path().join("a");
    identity(&dir);
    EnrolmentIndex::enrol(&machine, "grorg", entry(&dir), &owner()).unwrap();
    let path: PathBuf = machine.path().join(ENROLMENTS_FILE);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(
        EnrolmentIndex::read(&machine),
        Err(KeyfileError::InsecureFile(_))
    ));
}

#[test]
fn fresh_host_default_dir_create_and_enrol() {
    let parent = tempfile::tempdir().unwrap();
    fs::set_permissions(parent.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let machine = MachineDir::at(parent.path().join("machine"));
    assert!(!machine.path().exists());
    let (dir, source) = service_identity_dir(None, &machine, "grorg").unwrap();
    assert_eq!(source, DirSource::Default);
    let keys = IdentityKeys::create_or_load(&dir, NOW, TTL).unwrap();
    EnrolmentIndex::enrol(&machine, "grorg", entry(&dir), &owner()).unwrap();
    let index = EnrolmentIndex::read(&machine).unwrap();
    assert_eq!(
        index.checked("grorg").unwrap().unwrap().principal_id,
        keys.principal_id
    );
    let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(machine.path()), 0o700, "machine dir");
    assert_eq!(mode(&machine.path().join("services")), 0o700, "services");
    assert_eq!(mode(&dir), 0o700, "service dir");
}
