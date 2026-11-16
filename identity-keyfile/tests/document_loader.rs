//! DocumentLoader: persisted high-water mark, hooks, expiry on every current().
//!
//! Assumptions: document_type is `identity_crypto::testkit::DOC_TYPE`; the
//! document id is `document_id(&pb)`; documents are issued at T0 and checked
//! at NOW = T0 + DAY unless a test says otherwise.

use identity_crypto::testkit::{Principal, DAY, DOC_TYPE, T0};
use identity_crypto::{document_id, pb, sign_document, AuthorityChain, DocumentDraft};
use identity_keyfile::{
    Accepted, DocumentError, DocumentLoader, KeyfileError, LoaderConfig, Reload, StateWrite,
    MAX_DOCUMENT_BYTES,
};
use prost::Message;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

const NOW: i64 = T0 + DAY;

struct Env {
    _tmp: tempfile::TempDir,
    doc_dir: PathBuf,
    state_dir: PathBuf,
    authority: Principal,
}

impl Env {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let doc_dir = tmp.path().join("doc");
        let state_dir = tmp.path().join("state");
        for d in [&doc_dir, &state_dir] {
            fs::create_dir(d).unwrap();
            fs::set_permissions(d, fs::Permissions::from_mode(0o700)).unwrap();
        }
        Env {
            _tmp: tmp,
            doc_dir,
            state_dir,
            authority: Principal::new(),
        }
    }
    fn doc_path(&self) -> PathBuf {
        self.doc_dir.join("doc.pb")
    }
    fn state_path(&self) -> PathBuf {
        self.state_dir.join("state.json")
    }
    fn chain(&self) -> AuthorityChain {
        AuthorityChain::from_rotations(self.authority.genesis(), &self.authority.rotations).unwrap()
    }
    fn config(&self) -> LoaderConfig {
        LoaderConfig {
            document_path: self.doc_path(),
            state_path: self.state_path(),
            authority: self.chain(),
            document_type: DOC_TYPE.to_string(),
        }
    }
    fn loader(&self) -> DocumentLoader<String> {
        DocumentLoader::new(self.config(), |b| {
            String::from_utf8(b.to_vec()).map_err(|e| e.to_string())
        })
    }
    fn signed(&self, version: u64, body: &str, issued: i64, expires: i64) -> pb::SignedDocument {
        sign_document(
            self.authority.root(),
            &self.chain(),
            DocumentDraft {
                document_type: DOC_TYPE,
                version,
                issued_at: issued,
                expires_at: expires,
                body: body.as_bytes(),
            },
        )
        .unwrap()
    }
    fn put_doc(&self, doc: &pb::SignedDocument) {
        let bytes = doc.encode_to_vec();
        assert!(bytes.len() < MAX_DOCUMENT_BYTES);
        let p = self.doc_path();
        let _ = fs::remove_file(&p);
        fs::write(&p, bytes).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o644)).unwrap();
    }
    fn put(&self, version: u64, body: &str) -> pb::SignedDocument {
        let d = self.signed(version, body, T0, T0 + 90 * DAY);
        self.put_doc(&d);
        d
    }
}

fn mode(p: &Path) -> u32 {
    fs::metadata(p).unwrap().permissions().mode() & 0o777
}

fn loaded(r: Reload) -> (Accepted, StateWrite) {
    match r {
        Reload::Loaded { accepted, state } => (accepted, state),
        other => panic!("expected Loaded, got {other:?}"),
    }
}

fn refused(r: Reload) -> DocumentError {
    match r {
        Reload::Refused(e) => e,
        other => panic!("expected Refused, got {other:?}"),
    }
}

#[test]
fn loader_state_missing_is_first_boot() {
    let env = Env::new();
    let doc = env.put(3, "hello");
    let l = env.loader();
    let (acc, state) = loaded(l.reload(NOW));
    assert_eq!(
        acc,
        Accepted {
            version: 3,
            id: document_id(&doc).unwrap()
        }
    );
    assert!(matches!(state, StateWrite::Written));
    assert_eq!(l.current(NOW).as_deref().map(String::as_str), Some("hello"));
    assert_eq!(l.accepted(), Some(acc));
    assert_eq!(mode(&env.state_path()), 0o600);
    let v: serde_json::Value =
        serde_json::from_slice(&fs::read(env.state_path()).unwrap()).unwrap();
    assert_eq!(v["highest_version"], 3);
    assert_eq!(v["version"], 1);
    assert_eq!(v["document_type"], DOC_TYPE);
    assert_eq!(v["document_id"], hex(&acc.id));
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn write_state(env: &Env, bytes: &[u8], m: u32) {
    fs::write(env.state_path(), bytes).unwrap();
    fs::set_permissions(env.state_path(), fs::Permissions::from_mode(m)).unwrap();
}

#[test]
fn loader_state_corrupt_refuses() {
    let env = Env::new();
    env.put(3, "x");
    write_state(&env, b"{", 0o600);
    let l = env.loader();
    assert!(matches!(
        refused(l.reload(NOW)),
        DocumentError::StateCorrupt { .. }
    ));
    assert!(l.current(NOW).is_none());
    // Every reload is refused until fixed.
    assert!(matches!(
        refused(l.reload(NOW)),
        DocumentError::StateCorrupt { .. }
    ));
}

#[test]
fn loader_state_loose_refuses() {
    let env = Env::new();
    let doc = env.put(3, "x");
    let good = format!(
        r#"{{"version":1,"document_type":"{}","highest_version":2,"document_id":"{}"}}"#,
        DOC_TYPE,
        hex(&document_id(&doc).unwrap())
    );
    write_state(&env, good.as_bytes(), 0o644);
    let l = env.loader();
    assert!(matches!(
        refused(l.reload(NOW)),
        DocumentError::StateCorrupt { .. }
    ));
    assert!(l.current(NOW).is_none());
}

#[test]
fn loader_state_unwritable_keeps_memory_protection() {
    let env = Env::new();
    env.put(3, "three");
    fs::set_permissions(&env.state_dir, fs::Permissions::from_mode(0o500)).unwrap();
    let l = env.loader();
    let (_, state) = loaded(l.reload(NOW));
    assert!(matches!(state, StateWrite::Failed(_)));
    assert!(l.current(NOW).is_some());
    env.put(2, "two");
    assert!(matches!(
        refused(l.reload(NOW)),
        DocumentError::Rollback {
            highest: 3,
            found: 2
        }
    ));
    assert!(l.current(NOW).is_none());
    fs::set_permissions(&env.state_dir, fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn loader_restart_with_older_file_yields_none() {
    let env = Env::new();
    env.put(3, "three");
    let a = env.loader();
    let _ = loaded(a.reload(NOW));
    env.put(2, "two");
    let b = env.loader();
    assert!(matches!(
        refused(b.reload(NOW)),
        DocumentError::Rollback {
            highest: 3,
            found: 2
        }
    ));
    assert!(b.current(NOW).is_none());
}

#[test]
fn loader_restart_same_document_loads() {
    let env = Env::new();
    let doc = env.put(3, "three");
    let a = env.loader();
    let (acc, _) = loaded(a.reload(NOW));
    let b = env.loader();
    let (acc_b, _) = loaded(b.reload(NOW));
    assert_eq!(acc, acc_b);
    assert_eq!(acc_b.id, document_id(&doc).unwrap());
    assert!(b.current(NOW).is_some());
}

#[test]
fn loader_same_version_other_id_refused() {
    let env = Env::new();
    env.put(3, "one");
    let l = env.loader();
    let _ = loaded(l.reload(NOW));
    env.put(3, "two");
    assert!(matches!(
        refused(l.reload(NOW)),
        DocumentError::Equivocation { version: 3 }
    ));
    assert!(l.current(NOW).is_none());
}

#[test]
fn loader_deleted_document_yields_none_keeps_high_water() {
    let env = Env::new();
    env.put(3, "three");
    let l = env.loader();
    let _ = loaded(l.reload(NOW));
    fs::remove_file(env.doc_path()).unwrap();
    assert!(matches!(
        refused(l.reload(NOW)),
        DocumentError::Read(KeyfileError::Missing(_))
    ));
    assert!(l.current(NOW).is_none());
    env.put(2, "two");
    assert!(matches!(
        refused(l.reload(NOW)),
        DocumentError::Rollback {
            highest: 3,
            found: 2
        }
    ));
}

#[test]
fn loader_expiry_checked_on_every_current() {
    let env = Env::new();
    let d = env.signed(1, "x", T0, T0 + 10);
    env.put_doc(&d);
    let l = env.loader();
    let _ = loaded(l.reload(T0 + 1));
    assert!(l.current(T0 + 9).is_some());
    assert!(l.current(T0 + 10).is_none());
}

#[test]
fn loader_successor_hook_refusal() {
    let env = Env::new();
    let d3 = env.put(3, "three");
    let seen: Arc<Mutex<Vec<Option<Accepted>>>> = Arc::default();
    let s = seen.clone();
    let l = env.loader().successor(move |prev, v| {
        s.lock().unwrap().push(prev);
        if v.version() == 4 {
            Err("x".to_string())
        } else {
            Ok(())
        }
    });
    let (acc3, _) = loaded(l.reload(NOW));
    assert_eq!(acc3.id, document_id(&d3).unwrap());
    env.put(4, "four");
    match refused(l.reload(NOW)) {
        DocumentError::Successor(m) => assert_eq!(m, "x"),
        e => panic!("expected Successor, got {e:?}"),
    }
    let seen = seen.lock().unwrap();
    assert_eq!(seen.last().unwrap(), &Some(acc3));
    drop(seen);
    // v3 stays protected: v2 is still a rollback.
    env.put(2, "two");
    assert!(matches!(
        refused(l.reload(NOW)),
        DocumentError::Rollback {
            highest: 3,
            found: 2
        }
    ));
}

#[test]
fn loader_lifetime_cap() {
    let env = Env::new();
    let l = env.loader().max_lifetime(30 * DAY);
    let d = env.signed(1, "x", T0, T0 + 31 * DAY);
    env.put_doc(&d);
    assert!(matches!(
        refused(l.reload(NOW)),
        DocumentError::LifetimeTooLong { .. }
    ));
    let d = env.signed(2, "x", T0, i64::MAX);
    env.put_doc(&d);
    assert!(matches!(
        refused(l.reload(NOW)),
        DocumentError::LifetimeTooLong { .. }
    ));
    let d = env.signed(3, "x", T0, T0 + 30 * DAY);
    env.put_doc(&d);
    let _ = loaded(l.reload(NOW));
}

#[test]
fn loader_structure_hook() {
    let env = Env::new();
    let l = env.loader().structure(|t: &String| {
        if t.contains("allow") {
            Err("no allow".to_string())
        } else {
            Ok(())
        }
    });
    env.put(1, "deny everything");
    let _ = loaded(l.reload(NOW));
    env.put(2, "allow everything");
    assert!(matches!(
        refused(l.reload(NOW)),
        DocumentError::Structure(_)
    ));
    assert!(l.current(NOW).is_none());
}

#[test]
fn loader_bad_signature_yields_none() {
    let env = Env::new();
    let mut d = env.signed(1, "x", T0, T0 + 90 * DAY);
    d.signature[0] ^= 0xff;
    env.put_doc(&d);
    let l = env.loader();
    assert!(matches!(refused(l.reload(NOW)), DocumentError::Verify(_)));
    assert!(l.current(NOW).is_none());
}

#[test]
fn loader_read_only_document_dir_with_separate_state() {
    let env = Env::new();
    env.put(3, "three");
    fs::set_permissions(&env.doc_dir, fs::Permissions::from_mode(0o555)).unwrap();
    let l = env.loader();
    let (_, state) = loaded(l.reload(NOW));
    assert!(matches!(state, StateWrite::Written));
    assert!(env.state_path().exists());
    fs::set_permissions(&env.doc_dir, fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn document_file_mode_is_not_checked() {
    let env = Env::new();
    env.put(1, "x");
    for m in [0o644, 0o666, 0o400] {
        fs::set_permissions(env.doc_path(), fs::Permissions::from_mode(m)).unwrap();
        let l = env.loader();
        let r = l.reload(NOW);
        assert!(matches!(r, Reload::Loaded { .. }), "mode {m:o}: {r:?}");
        let _ = fs::remove_file(env.state_path());
    }
}

fn good_state(version: u64, id: &str) -> String {
    format!(
        r#"{{"version":1,"document_type":"{DOC_TYPE}","highest_version":{version},"document_id":"{id}"}}"#
    )
}

#[test]
fn loader_reload_twice_is_unchanged() {
    let env = Env::new();
    env.put(3, "three");
    let l = env.loader();
    let _ = loaded(l.reload(NOW));
    assert!(matches!(l.reload(NOW), Reload::Unchanged));
    assert!(l.current(NOW).is_some());
}

#[test]
fn loader_current_refuses_not_yet_valid() {
    let env = Env::new();
    env.put(1, "x");
    let l = env.loader();
    let _ = loaded(l.reload(NOW));
    assert!(l.current(T0 - 10 * DAY).is_none());
    assert!(l.current(NOW).is_some());
}

#[test]
fn loader_state_refusals_and_recovery() {
    let env = Env::new();
    let doc = env.put(3, "x");
    let id = hex(&document_id(&doc).unwrap());
    let cases: Vec<(&str, Vec<u8>)> = vec![
        (
            "version 2",
            good_state(2, &id)
                .replace(r#""version":1"#, r#""version":2"#)
                .into_bytes(),
        ),
        (
            "wrong type",
            good_state(2, &id)
                .replace(DOC_TYPE, "other.type")
                .into_bytes(),
        ),
        ("uppercase", good_state(2, &id.to_uppercase()).into_bytes()),
        ("non-hex", good_state(2, &"z".repeat(64)).into_bytes()),
        ("oversize", {
            let mut v = good_state(2, &id).into_bytes();
            v.extend(std::iter::repeat_n(b' ', 4097));
            v
        }),
    ];
    for (name, bytes) in cases {
        write_state(&env, &bytes, 0o600);
        let l = env.loader();
        let r = l.reload(NOW);
        assert!(
            matches!(r, Reload::Refused(DocumentError::StateCorrupt { .. })),
            "{name}: {r:?}"
        );
        assert!(l.current(NOW).is_none(), "{name}");
        // Fixed: delete the state file and the next reload loads.
        fs::remove_file(env.state_path()).unwrap();
        let r = l.reload(NOW);
        assert!(matches!(r, Reload::Loaded { .. }), "{name} recovery: {r:?}");
        fs::remove_file(env.state_path()).unwrap();
    }
    // Fixing by rewriting a valid state also recovers.
    write_state(&env, b"{", 0o600);
    let l = env.loader();
    assert!(matches!(
        refused(l.reload(NOW)),
        DocumentError::StateCorrupt { .. }
    ));
    write_state(&env, good_state(2, &id).as_bytes(), 0o600);
    assert!(matches!(l.reload(NOW), Reload::Loaded { .. }));
}

#[test]
fn loader_state_symlink_refused() {
    let env = Env::new();
    let doc = env.put(3, "x");
    let target = env.state_dir.join("real.json");
    fs::write(&target, good_state(2, &hex(&document_id(&doc).unwrap()))).unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
    std::os::unix::fs::symlink(&target, env.state_path()).unwrap();
    let l = env.loader();
    let r = l.reload(NOW);
    assert!(
        matches!(r, Reload::Refused(DocumentError::StateCorrupt { .. })),
        "{r:?}"
    );
    fs::remove_file(env.state_path()).unwrap();
    assert!(matches!(l.reload(NOW), Reload::Loaded { .. }));
}

#[test]
fn loader_state_directory_refused() {
    let env = Env::new();
    env.put(3, "x");
    fs::create_dir(env.state_path()).unwrap();
    let l = env.loader();
    let r = l.reload(NOW);
    assert!(
        matches!(r, Reload::Refused(DocumentError::StateCorrupt { .. })),
        "{r:?}"
    );
    fs::remove_dir(env.state_path()).unwrap();
    assert!(matches!(l.reload(NOW), Reload::Loaded { .. }));
}

#[test]
fn loader_missing_state_parent_is_not_created() {
    let env = Env::new();
    env.put(3, "x");
    let missing = env.state_dir.join("nope");
    let mut config = env.config();
    config.state_path = missing.join("state.json");
    let l = DocumentLoader::new(config, |b| {
        String::from_utf8(b.to_vec()).map_err(|e| e.to_string())
    });
    let (_, state) = loaded(l.reload(NOW));
    assert!(matches!(state, StateWrite::Failed(_)));
    assert!(l.current(NOW).is_some());
    assert!(!missing.exists());
}

#[test]
fn loader_successor_previous_from_state_when_memory_empty() {
    let env = Env::new();
    env.put(3, "three");
    let a = env.loader();
    let (acc3, _) = loaded(a.reload(NOW));
    env.put(4, "four");
    let seen: Arc<Mutex<Vec<Option<Accepted>>>> = Arc::default();
    let s = seen.clone();
    let b = env.loader().successor(move |prev, _| {
        s.lock().unwrap().push(prev);
        Ok(())
    });
    let _ = loaded(b.reload(NOW));
    assert_eq!(*seen.lock().unwrap(), vec![Some(acc3)]);
}

#[test]
fn loader_successor_previous_prefers_memory_over_state() {
    let env = Env::new();
    env.put(3, "three");
    let seen: Arc<Mutex<Vec<Option<Accepted>>>> = Arc::default();
    let s = seen.clone();
    let l = env.loader().successor(move |prev, _| {
        s.lock().unwrap().push(prev);
        Ok(())
    });
    let (acc3, _) = loaded(l.reload(NOW));
    write_state(&env, good_state(5, &"ab".repeat(32)).as_bytes(), 0o600);
    env.put(6, "six");
    let _ = loaded(l.reload(NOW));
    let seen = seen.lock().unwrap();
    assert_eq!(seen.last().unwrap(), &Some(acc3));
}

#[allow(dead_code)]
fn assert_send_sync<T: Send + Sync>() {}
#[allow(dead_code)]
fn loader_is_send_sync() {
    assert_send_sync::<DocumentLoader<String>>();
}

#[test]
fn loader_max_expiry_with_cap_is_too_long() {
    let env = Env::new();
    let d = env.signed(1, "x", T0, i64::MAX);
    env.put_doc(&d);
    let l = env.loader().max_lifetime(30 * DAY);
    assert!(matches!(
        refused(l.reload(NOW)),
        DocumentError::LifetimeTooLong { .. }
    ));
}

#[test]
fn loader_oversize_document_refused() {
    let env = Env::new();
    fs::write(env.doc_path(), vec![0u8; MAX_DOCUMENT_BYTES + 1]).unwrap();
    let l = env.loader();
    let r = l.reload(NOW);
    assert!(
        matches!(
            r,
            Reload::Refused(DocumentError::Read(KeyfileError::TooLarge { .. }))
        ),
        "{r:?}"
    );
}

#[test]
fn loader_malformed_protobuf_refused() {
    let env = Env::new();
    fs::write(env.doc_path(), [0xffu8, 0xff, 0xff, 0xff, 0x0f, 0x01]).unwrap();
    let l = env.loader();
    assert!(matches!(
        refused(l.reload(NOW)),
        DocumentError::Malformed(_)
    ));
}
