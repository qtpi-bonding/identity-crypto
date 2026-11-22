//! Config loading and validation tests. Never reads real files.

use coded_error::CodedError;
use identity_request_signer::config::Config;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

const BASE: &str = "\
identity_dir = \"/tmp/identity\"\
\nexpected_principal = \"p256:abc\"\
\nsocket = \"/tmp/sock\"\
\nserver_id = \"example\"\
\n";

fn write_config(dir: &Path, name: &str, text: &str, mode: u32) -> std::path::PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, text).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
    path
}

fn base_with_limits() -> String {
    format!("{BASE}max_body = 4194304\nmax_line_bytes = 5800000\nread_timeout_secs = 5\n")
}

const BASE_NO_SERVER_ID: &str = "\
identity_dir = \"/tmp/identity\"\
\nexpected_principal = \"p256:abc\"\
\nsocket = \"/tmp/sock\"\
\n";

#[test]
fn defaults_apply_when_limit_keys_omitted() {
    let cfg = Config::parse(BASE).unwrap();
    assert_eq!(cfg.max_body(), 4_194_304);
    assert_eq!(cfg.max_line_bytes(), 5_800_000);
    assert_eq!(cfg.read_timeout_secs(), 5);
    cfg.validate().unwrap();
}

#[test]
fn explicit_limits_still_accepted() {
    let cfg = Config::parse(&base_with_limits()).unwrap();
    assert_eq!(cfg.max_body(), 4_194_304);
    cfg.validate().unwrap();
}

#[test]
fn unknown_key_refused() {
    let text = format!("{BASE}discover_url = \"https://example.invalid\"\n");
    let err = Config::parse(&text).unwrap_err();
    assert_eq!(
        CodedError::code(&err),
        "identity.request_signer.config_invalid"
    );
}

#[test]
fn empty_server_id_is_empty_server_id() {
    let cfg = Config::parse(&format!("{BASE_NO_SERVER_ID}server_id = \"\"\n")).unwrap();
    let err = cfg.validate().unwrap_err();
    assert_eq!(
        CodedError::code(&err),
        "identity.request_signer.empty_server_id"
    );
}

#[test]
fn absent_server_id_is_valid() {
    let text = "\
identity_dir = \"/tmp/identity\"\
\nexpected_principal = \"p256:abc\"\
\nsocket = \"/tmp/sock\"\
\n";
    let cfg = Config::parse(text).unwrap();
    cfg.validate().unwrap();
}

#[test]
fn zero_limits_refused() {
    for key in ["max_body", "max_line_bytes"] {
        let text = format!("{BASE}{key} = 0\n");
        let cfg = Config::parse(&text).unwrap();
        let err = cfg.validate().unwrap_err();
        assert_eq!(
            CodedError::code(&err),
            "identity.request_signer.config_invalid",
            "key {key}"
        );
    }
    let text = format!("{BASE}read_timeout_secs = 0\n");
    let cfg = Config::parse(&text).unwrap();
    assert_eq!(
        CodedError::code(&cfg.validate().unwrap_err()),
        "identity.request_signer.config_invalid"
    );
}

#[test]
fn line_limit_below_four_thirds_of_body_refused() {
    let text = format!("{BASE}max_body = 3000\nmax_line_bytes = 3999\nread_timeout_secs = 5\n");
    let cfg = Config::parse(&text).unwrap();
    assert_eq!(
        CodedError::code(&cfg.validate().unwrap_err()),
        "identity.request_signer.config_invalid"
    );
}

#[test]
fn empty_expected_principal_refused() {
    let text = "\
identity_dir = \"/tmp/identity\"\
\nexpected_principal = \"\"\
\nsocket = \"/tmp/sock\"\
\n";
    let cfg = Config::parse(text).unwrap();
    assert_eq!(
        CodedError::code(&cfg.validate().unwrap_err()),
        "identity.request_signer.config_invalid"
    );
}

#[test]
fn empty_identity_dir_refused() {
    let text = "\
identity_dir = \"\"\
\nexpected_principal = \"p256:abc\"\
\nsocket = \"/tmp/sock\"\
\n";
    let cfg = Config::parse(text).unwrap();
    assert_eq!(
        CodedError::code(&cfg.validate().unwrap_err()),
        "identity.request_signer.config_invalid"
    );
}

#[test]
fn empty_socket_refused() {
    let text = "\
identity_dir = \"/tmp/identity\"\
\nexpected_principal = \"p256:abc\"\
\nsocket = \"\"\
\n";
    let cfg = Config::parse(text).unwrap();
    assert_eq!(
        CodedError::code(&cfg.validate().unwrap_err()),
        "identity.request_signer.config_invalid"
    );
}

#[test]
fn load_refuses_symlink() {
    let dir = tempfile::tempdir().unwrap();
    let real = write_config(dir.path(), "real.toml", &base_with_limits(), 0o600);
    let link = dir.path().join("link.toml");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    assert_eq!(
        CodedError::code(&Config::load(&link).unwrap_err()),
        "identity.request_signer.config_invalid"
    );
}

#[test]
fn load_refuses_world_readable_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_config(dir.path(), "wide.toml", &base_with_limits(), 0o644);
    assert_eq!(
        CodedError::code(&Config::load(&path).unwrap_err()),
        "identity.request_signer.config_invalid"
    );
}

#[test]
fn load_refuses_oversize_file() {
    let dir = tempfile::tempdir().unwrap();
    let big = format!(
        "{BASE}refuse_principals = [\"{}\"]\n",
        "x".repeat(1024 * 1024)
    );
    let path = write_config(dir.path(), "big.toml", &big, 0o600);
    assert_eq!(
        CodedError::code(&Config::load(&path).unwrap_err()),
        "identity.request_signer.config_invalid"
    );
}

#[test]
fn load_accepts_owner_only_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_config(dir.path(), "ok.toml", &base_with_limits(), 0o600);
    Config::load(&path).unwrap();
}

#[test]
fn load_error_never_echoes_file_content() {
    const MARKER: &str = "SECRET-MARKER-p256-do-not-leak-7f3a";
    let dir = tempfile::tempdir().unwrap();
    // Bad TOML carrying a marker, and also a world-readable one.
    for mode in [0o600, 0o644] {
        let path = write_config(
            dir.path(),
            &format!("bad{mode}.toml"),
            &format!("{MARKER} = {{ broken"),
            mode,
        );
        let err = Config::load(&path).unwrap_err();
        let disp = format!("{err}");
        let dbg = format!("{err:?}");
        assert!(!disp.contains(MARKER), "Display leaked: {disp}");
        assert!(!dbg.contains(MARKER), "Debug leaked: {dbg}");
    }
    // And a valid-syntax but invalid-value file with a marker in the value.
    let path = write_config(
        dir.path(),
        "val.toml",
        &format!("{BASE}max_body = 0\nmax_line_bytes = 5800000\nread_timeout_secs = 5\n{MARKER} = true\n"),
        0o600,
    );
    let err = Config::load(&path).unwrap_err();
    assert!(!format!("{err}").contains(MARKER));
    assert!(!format!("{err:?}").contains(MARKER));
}
