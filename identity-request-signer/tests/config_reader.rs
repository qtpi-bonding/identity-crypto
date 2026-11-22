//! Tests for the shared private-TOML reader and table-based config parsing.
//! Never reads real files.

use coded_error::CodedError;
use identity_request_signer::config::{read_private_toml, Config};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

const BASE: &str = "\
identity_dir = \"/tmp/identity\"\
\nexpected_principal = \"p256:abc\"\
\nsocket = \"/tmp/sock\"\
\nserver_id = \"example\"\
\n";

const EXTRA_SECTION: &str = "\n[extra]\nanswer = 42\n";

fn write_file(dir: &Path, name: &str, bytes: &[u8], mode: u32) -> std::path::PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, bytes).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
    path
}

fn base_bytes() -> Vec<u8> {
    format!("{BASE}max_body = 4194304\nmax_line_bytes = 5800000\nread_timeout_secs = 5\n{EXTRA_SECTION}").into_bytes()
}

#[test]
fn read_private_toml_refuses_symlink() {
    let dir = tempfile::tempdir().unwrap();
    let real = write_file(dir.path(), "real.toml", &base_bytes(), 0o600);
    let link = dir.path().join("link.toml");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    assert!(read_private_toml(&link).is_err());
}

#[test]
fn read_private_toml_refuses_group_or_other_readable() {
    let dir = tempfile::tempdir().unwrap();
    for mode in [0o644, 0o640, 0o604] {
        let path = write_file(dir.path(), &format!("w{mode}.toml"), &base_bytes(), mode);
        assert!(read_private_toml(&path).is_err(), "mode {mode:o}");
    }
}

#[test]
fn read_private_toml_refuses_oversize_file() {
    let dir = tempfile::tempdir().unwrap();
    let big = format!(
        "{BASE}[extra]\ntext = \"{}\"\n",
        "x".repeat(1024 * 1024 + 16)
    );
    let path = write_file(dir.path(), "big.toml", big.as_bytes(), 0o600);
    assert!(read_private_toml(&path).is_err());
}

#[test]
fn read_private_toml_refuses_non_utf8() {
    let dir = tempfile::tempdir().unwrap();
    let mut bytes = base_bytes();
    bytes.push(0xff);
    let path = write_file(dir.path(), "binary.toml", &bytes, 0o600);
    assert!(read_private_toml(&path).is_err());
}

#[test]
fn read_private_toml_refuses_bad_toml_and_never_echoes_content() {
    const MARKER: &str = "BAD-TOML-MARKER-do-not-leak-9c1d";
    let dir = tempfile::tempdir().unwrap();
    let path = write_file(
        dir.path(),
        "bad.toml",
        format!("{MARKER} = {{ broken").as_bytes(),
        0o600,
    );
    let err = read_private_toml(&path).unwrap_err();
    let disp = format!("{err}");
    let dbg = format!("{err:?}");
    assert!(!disp.contains(MARKER), "Display leaked: {disp}");
    assert!(!dbg.contains(MARKER), "Debug leaked: {dbg}");
    assert_eq!(
        CodedError::code(&err),
        "identity.request_signer.config_invalid"
    );
}

#[test]
fn read_private_toml_accepts_owner_only_and_keeps_extra_sections() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_file(dir.path(), "ok.toml", &base_bytes(), 0o600);
    let table = read_private_toml(&path).unwrap();
    let extra = table.get("extra").expect("the extra section is kept");
    assert_eq!(
        extra.get("answer").and_then(toml::Value::as_integer),
        Some(42)
    );
}

#[test]
fn from_table_accepts_the_table_without_the_extra_section() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_file(dir.path(), "ok.toml", &base_bytes(), 0o600);
    let mut table = read_private_toml(&path).unwrap();
    table.remove("extra");
    let cfg = Config::from_table(table).unwrap();
    cfg.validate().unwrap();
    assert_eq!(cfg.max_body(), 4_194_304);
}

#[test]
fn from_table_refuses_the_extra_section_as_an_unknown_key() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_file(dir.path(), "ok.toml", &base_bytes(), 0o600);
    let table = read_private_toml(&path).unwrap();
    let err = Config::from_table(table).unwrap_err();
    assert_eq!(
        CodedError::code(&err),
        "identity.request_signer.config_invalid"
    );
    let disp = format!("{err}");
    let dbg = format!("{err:?}");
    assert!(!disp.contains("answer"), "Display leaked a key: {disp}");
    assert!(!dbg.contains("answer"), "Debug leaked a key: {dbg}");
}
