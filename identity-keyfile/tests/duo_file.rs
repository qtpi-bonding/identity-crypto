use identity_crypto::jwk_duo::{KeyDuo, KeyDuoSerializer, ValidationService};
use identity_crypto::{encryption_public, signing_public, verify_p256};
use identity_keyfile::*;
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};

fn tempdir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

fn key_text(duo: &KeyDuo) -> String {
    KeyDuoSerializer::export_key_duo_jwk(duo).unwrap()
}

fn put(dir: &Path, name: &str, bytes: &[u8], mode: u32) -> PathBuf {
    let p = dir.join(name);
    fs::write(&p, bytes).unwrap();
    fs::set_permissions(&p, fs::Permissions::from_mode(mode)).unwrap();
    p
}

fn private_ds(text: &str) -> Vec<String> {
    let v: serde_json::Value = serde_json::from_str(text).unwrap();
    v["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k["d"].as_str().unwrap().to_string())
        .collect()
}

fn assert_accepted(duo: &KeyDuo, got: &KeyDuo) {
    assert_eq!(signing_public(got), signing_public(duo), "signing half");
    assert_eq!(
        encryption_public(got),
        encryption_public(duo),
        "encryption half"
    );
    let msg = b"duo file signing check";
    let sig = got.signing_key_pair().sign_bytes(msg).unwrap();
    assert!(verify_p256(&signing_public(duo), msg, &sig).is_ok());
}

/// Display and Debug of `err` must not contain the key text or any 8-byte
/// window of the file text or of the private `d` values.
fn assert_no_leak(err: &KeyfileError, text: &str, ds: &[String]) {
    for rendered in [err.to_string(), format!("{err:?}")] {
        assert!(!rendered.contains(text), "full key text leaked: {rendered}");
        for src in std::iter::once(text).chain(ds.iter().map(String::as_str)) {
            for w in src.as_bytes().windows(8) {
                let w = std::str::from_utf8(w).unwrap();
                assert!(
                    !rendered.contains(w),
                    "8-byte run {w:?} leaked in {rendered}"
                );
            }
        }
    }
}

#[test]
fn accepts_0600_and_signs() {
    let dir = tempdir();
    let duo = generate();
    let p = put(dir.path(), "k.json", key_text(&duo).as_bytes(), 0o600);
    assert_accepted(&duo, &read_duo_file(&p).unwrap());
}

#[test]
fn accepts_file_written_by_write_duo() {
    let dir = tempdir();
    let duo = generate();
    write_duo(dir.path(), "k.json", &duo).unwrap();
    assert_accepted(&duo, &read_duo_file(&dir.path().join("k.json")).unwrap());
}

#[test]
fn accepts_0400() {
    let dir = tempdir();
    let duo = generate();
    let p = put(dir.path(), "k.json", key_text(&duo).as_bytes(), 0o400);
    assert_accepted(&duo, &read_duo_file(&p).unwrap());
}

#[test]
fn refuses_0640_and_0644_as_insecure_file() {
    let dir = tempdir();
    let duo = generate();
    let text = key_text(&duo);
    let ds = private_ds(&text);
    for m in [0o640, 0o644] {
        let p = put(dir.path(), &format!("k{m:o}.json"), text.as_bytes(), m);
        let err = read_duo_file(&p).unwrap_err();
        assert!(
            matches!(&err, KeyfileError::InsecureFile(q) if q == &p),
            "{m:o}: {err:?}"
        );
        assert_eq!(
            err.to_string(),
            format!("insecure key file {}", p.display())
        );
        assert_no_leak(&err, &text, &ds);
    }
}

#[test]
fn refuses_a_directory_as_not_a_key_set() {
    let dir = tempdir();
    let sub = dir.path().join("sub");
    fs::create_dir(&sub).unwrap();
    fs::set_permissions(&sub, fs::Permissions::from_mode(0o700)).unwrap();
    let err = read_duo_file(&sub).unwrap_err();
    assert!(
        matches!(&err, KeyfileError::NotAKeySet(q) if q == &sub),
        "{err:?}"
    );
    assert_eq!(
        err.to_string(),
        format!("not a private key set: {}", sub.display())
    );
}

#[test]
fn refuses_a_missing_path_as_missing() {
    let dir = tempdir();
    let p = dir.path().join("nope.json");
    let err = read_duo_file(&p).unwrap_err();
    assert!(
        matches!(&err, KeyfileError::Missing(q) if q == &p),
        "{err:?}"
    );
}

#[test]
fn refuses_a_dangling_symlink_as_missing() {
    let dir = tempdir();
    let link = dir.path().join("link");
    symlink(dir.path().join("nowhere"), &link).unwrap();
    let err = read_duo_file(&link).unwrap_err();
    assert!(
        matches!(&err, KeyfileError::Missing(q) if q == &link),
        "{err:?}"
    );
}

#[test]
fn refuses_a_public_only_key_set() {
    let dir = tempdir();
    let duo = generate();
    // The crate's own public extraction: kty/crv/x/y/alg/use/kid, no `d`.
    let full: serde_json::Value = serde_json::from_str(&key_text(&duo)).unwrap();
    let public = ValidationService::extract_public_key_set(&full).unwrap();
    let public_text = public.to_string();
    assert!(!public_text.contains("\"d\""));
    let p = put(dir.path(), "pub.json", public_text.as_bytes(), 0o600);
    let err = read_duo_file(&p).unwrap_err();
    assert!(
        matches!(&err, KeyfileError::NotAKeySet(q) if q == &p),
        "{err:?}"
    );
    assert_eq!(
        err.to_string(),
        format!("not a private key set: {}", p.display())
    );
}

#[test]
fn refuses_garbage_empty_and_non_utf8_as_not_a_key_set() {
    let dir = tempdir();
    let cases: [(&str, &[u8]); 4] = [
        ("garbage", b"this is not json at all"),
        ("empty", b""),
        ("non-utf8", &[0xff, 0xfe, 0x00, 0xc3, 0x28, 0xa0, 0xa1]),
        ("json-not-keys", b"{\"keys\":[]}"),
    ];
    for (name, bytes) in cases {
        let p = put(dir.path(), name, bytes, 0o600);
        let err = read_duo_file(&p).unwrap_err();
        assert!(
            matches!(&err, KeyfileError::NotAKeySet(q) if q == &p),
            "{name}: {err:?}"
        );
        assert_eq!(
            err.to_string(),
            format!("not a private key set: {}", p.display())
        );
    }
}

#[test]
fn symlink_to_valid_0600_is_accepted() {
    let dir = tempdir();
    let duo = generate();
    let target = put(dir.path(), "real.json", key_text(&duo).as_bytes(), 0o600);
    let link = dir.path().join("link.json");
    symlink(&target, &link).unwrap();
    assert_accepted(&duo, &read_duo_file(&link).unwrap());
}

#[test]
fn symlink_to_0644_is_refused_as_insecure_file() {
    let dir = tempdir();
    let duo = generate();
    let text = key_text(&duo);
    let target = put(dir.path(), "real.json", text.as_bytes(), 0o644);
    let link = dir.path().join("link.json");
    symlink(&target, &link).unwrap();
    let err = read_duo_file(&link).unwrap_err();
    assert!(
        matches!(&err, KeyfileError::InsecureFile(q) if q == &link),
        "{err:?}"
    );
    assert_no_leak(&err, &text, &private_ds(&text));
}

#[test]
fn corrupted_key_sets_refuse_without_leaking_key_material() {
    let dir = tempdir();
    let duo = generate();
    let text = key_text(&duo);
    let ds = private_ds(&text);
    let variants: Vec<(&str, String)> = vec![
        ("truncated", text[..text.len() / 2].to_string()),
        ("trailing-garbage", format!("{text} garbage")),
        ("one-key-only", {
            let mut v: serde_json::Value = serde_json::from_str(&text).unwrap();
            v["keys"].as_array_mut().unwrap().truncate(1);
            v.to_string()
        }),
        ("bad-d", text.replace(&ds[0], &"A".repeat(ds[0].len()))),
        ("d-wrong-type", {
            let mut v: serde_json::Value = serde_json::from_str(&text).unwrap();
            v["keys"][0]["d"] = serde_json::json!(12345);
            v.to_string()
        }),
        ("mismatched-x", {
            let mut v: serde_json::Value = serde_json::from_str(&text).unwrap();
            v["keys"][0]["x"] = serde_json::json!("A".repeat(43));
            v.to_string()
        }),
    ];
    for (name, body) in variants {
        let p = put(dir.path(), name, body.as_bytes(), 0o600);
        let err = read_duo_file(&p).unwrap_err();
        assert!(
            matches!(&err, KeyfileError::NotAKeySet(q) if q == &p),
            "{name}: {err:?}"
        );
        assert_eq!(
            err.to_string(),
            format!("not a private key set: {}", p.display())
        );
        assert_no_leak(&err, &body, &ds);
        assert_no_leak(&err, &text, &ds);
    }
}

#[test]
fn refuses_a_fifo_promptly_as_not_a_key_set() {
    use std::os::unix::ffi::OsStrExt;
    use std::sync::mpsc;
    use std::time::Duration;

    let dir = tempdir();
    let p = dir.path().join("pipe.json");
    let c = std::ffi::CString::new(p.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0, "mkfifo");

    let (tx, rx) = mpsc::channel();
    let pp = p.clone();
    std::thread::spawn(move || {
        let _ = tx.send(read_duo_file(&pp));
    });
    let got = rx.recv_timeout(Duration::from_secs(5));
    if got.is_err() {
        // Unblock the stuck reader (open-for-read blocks until a writer appears).
        unsafe {
            let fd = libc::open(c.as_ptr(), libc::O_WRONLY | libc::O_NONBLOCK);
            if fd >= 0 {
                libc::close(fd);
            }
        }
        panic!("read_duo_file blocked on a FIFO for over 5s; it must refuse without blocking");
    }
    let err = got.unwrap().unwrap_err();
    assert!(
        matches!(&err, KeyfileError::NotAKeySet(q) if q == &p),
        "{err:?}"
    );
}

#[test]
fn refuses_an_oversized_17_kib_file_as_not_a_key_set() {
    let dir = tempdir();
    // A valid key set padded past the cap, so only the size cap can refuse it.
    let mut body = key_text(&generate()).into_bytes();
    body.resize(17 * 1024, b'\n');
    let p = put(dir.path(), "big.json", &body, 0o600);
    let err = read_duo_file(&p).unwrap_err();
    assert!(
        matches!(&err, KeyfileError::NotAKeySet(q) if q == &p),
        "{err:?}"
    );
}

#[test]
fn accepts_a_valid_key_set_padded_to_just_under_16_kib() {
    let dir = tempdir();
    let duo = generate();
    let mut body = key_text(&duo).into_bytes();
    assert!(body.len() < 16 * 1024 - 16);
    body.resize(16 * 1024 - 16, b'\n');
    let p = put(dir.path(), "padded.json", &body, 0o600);
    assert_accepted(&duo, &read_duo_file(&p).unwrap());
}

#[test]
fn cap_boundary_accepts_exactly_16_kib_and_refuses_one_byte_more() {
    let dir = tempdir();
    let duo = generate();
    let mut body = key_text(&duo).into_bytes();
    body.resize(16 * 1024, b'\n');
    let at = put(dir.path(), "at.json", &body, 0o600);
    assert_accepted(&duo, &read_duo_file(&at).unwrap());
    body.push(b'\n');
    let over = put(dir.path(), "over.json", &body, 0o600);
    let err = read_duo_file(&over).unwrap_err();
    assert!(
        matches!(&err, KeyfileError::NotAKeySet(q) if q == &over),
        "got {err:?}"
    );
}
