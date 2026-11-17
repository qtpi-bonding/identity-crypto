//! `KeysHome`: `<config>/<dir_name>/{root/, devices/<name>/}`.
//! Tests use tempfile dirs and `locate_with` closures only.

use identity_keyfile::{KeyfileError, KeysHome};
use std::collections::HashMap;
use std::ffi::OsString;
use std::fs;
use std::path::PathBuf;

fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<OsString> {
    let map: HashMap<String, OsString> = pairs
        .iter()
        .map(|(k, v)| (k.to_string(), OsString::from(v)))
        .collect();
    move |name| map.get(name).cloned()
}

#[test]
fn device_dir_rejects_bad_names() {
    let tmp = tempfile::tempdir().unwrap();
    let home = KeysHome::at(tmp.path().join("keys"));
    for bad in ["", "..", ".", "a/b", "../x", "a\\b", "/abs", "a\0b"] {
        assert!(
            matches!(home.device_dir(bad), Err(KeyfileError::InvalidLayout(_))),
            "{bad:?} must be refused"
        );
    }
    let good = home.device_dir("laptop-1").unwrap();
    assert_eq!(
        good,
        tmp.path().join("keys").join("devices").join("laptop-1")
    );
    assert!(!good.exists(), "existence is not required");
}

#[test]
fn devices_lists_in_order() {
    let tmp = tempfile::tempdir().unwrap();
    let home = KeysHome::at(tmp.path());
    assert_eq!(home.devices().unwrap(), Vec::<String>::new());
    let devices = tmp.path().join("devices");
    for name in ["b", "a", "c"] {
        fs::create_dir_all(devices.join(name)).unwrap();
    }
    fs::write(devices.join("plain-file"), b"x").unwrap();
    assert_eq!(home.devices().unwrap(), vec!["a", "b", "c"]);
    assert_eq!(home.root_dir(), tmp.path().join("root"));
    assert_eq!(home.path(), tmp.path());
}

#[test]
fn locate_with_follows_the_xdg_rule() {
    let path = |h: Result<KeysHome, KeyfileError>| h.unwrap().path().to_path_buf();
    // XDG wins over HOME.
    assert_eq!(
        path(KeysHome::locate_with(
            "keys",
            env(&[("XDG_CONFIG_HOME", "/x/cfg"), ("HOME", "/h")])
        )),
        PathBuf::from("/x/cfg/keys")
    );
    // Empty XDG falls back to HOME/.config.
    assert_eq!(
        path(KeysHome::locate_with(
            "keys",
            env(&[("XDG_CONFIG_HOME", ""), ("HOME", "/h")])
        )),
        PathBuf::from("/h/.config/keys")
    );
    // Only HOME.
    assert_eq!(
        path(KeysHome::locate_with("keys", env(&[("HOME", "/h")]))),
        PathBuf::from("/h/.config/keys")
    );
    // Relative result.
    assert!(matches!(
        KeysHome::locate_with("keys", env(&[("XDG_CONFIG_HOME", "rel"), ("HOME", "/h")])),
        Err(KeyfileError::InvalidLayout(_))
    ));
    // Neither set (empty HOME counts as unset).
    assert!(matches!(
        KeysHome::locate_with("keys", env(&[])),
        Err(KeyfileError::KeysHomeUnresolved)
    ));
    assert!(matches!(
        KeysHome::locate_with("keys", env(&[("XDG_CONFIG_HOME", ""), ("HOME", "")])),
        Err(KeyfileError::KeysHomeUnresolved)
    ));
    // Bad dir_name.
    for bad in ["", "a/b", ".", ".."] {
        assert!(
            matches!(
                KeysHome::locate_with(bad, env(&[("HOME", "/h")])),
                Err(KeyfileError::InvalidLayout(_))
            ),
            "{bad:?}"
        );
    }
}
