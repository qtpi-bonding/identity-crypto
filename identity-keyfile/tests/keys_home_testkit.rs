#![cfg(feature = "testkit")]

use identity_keyfile::testkit::{
    assert_no_secret, jwk_private_values, secret_forms, DeviceOnlyHome,
};
use std::os::unix::fs::PermissionsExt;

#[test]
fn secret_forms_covers_each_encoding() {
    assert_eq!(
        secret_forms(&[0xfb, 0xff, 0xfe, 0x01]),
        vec!["fbfffe01", "+//+AQ==", "-__-AQ"]
    );
    assert_eq!(
        secret_forms(&[0x00, 0x10, 0xff]),
        vec!["0010ff", "ABD/", "ABD_"]
    );
}

#[test]
fn jwk_private_values_finds_nested_private_members() {
    let doc = r#"{
        "name": "x",
        "duo": {"signing": {"kty":"EC","crv":"P-256","x":"PX","y":"PY","d":"D1"}},
        "list": [{"kty":"OKP","crv":"Ed25519","x":"PX2","d":"D2"}],
        "rsa": {"kty":"RSA","n":"N","e":"E","p":"P","q":"Q","dp":"DP","dq":"DQ","qi":"QI"},
        "oct": {"kty":"oct","k":"K"}
    }"#;
    let values = jwk_private_values(doc);
    for public in ["PX", "PY", "PX2", "N", "E"] {
        assert!(!values.iter().any(|v| v == public), "{public} is public");
    }
    assert_eq!(values, vec!["D1", "D2", "P", "Q", "DP", "DQ", "QI", "K"]);
}

#[test]
#[should_panic]
fn jwk_private_values_panics_on_invalid_json() {
    jwk_private_values("{not json");
}

#[test]
fn assert_no_secret_passes_when_clean() {
    assert_no_secret(
        "nothing to see",
        &["hunter2".to_string(), String::new(), "abc123".to_string()],
    );
}

#[test]
#[should_panic]
fn assert_no_secret_panics_when_leaked() {
    assert_no_secret("a hunter2 b", &["other".to_string(), "hunter2".to_string()]);
}

#[test]
fn assert_no_secret_panics_without_echoing_the_secret() {
    let secret = "s3cr3t-value-xyz";
    let result = std::panic::catch_unwind(|| {
        assert_no_secret(
            &format!("leak {secret} here"),
            &["unrelated".to_string(), secret.to_string()],
        );
    });
    let payload = result.expect_err("must panic");
    let message = payload
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| payload.downcast_ref::<&str>().map(|s| s.to_string()))
        .expect("string panic message");
    assert!(
        !message.contains(secret),
        "message echoed the secret: {message}"
    );
    assert!(message.contains('1'), "message names the index: {message}");
}

#[test]
fn device_only_home_cleans_up() {
    let parent = {
        let fixture = DeviceOnlyHome::new("laptop", 100, 50);
        let parent = fixture.path();
        let home = fixture.home();
        assert_eq!(home.path(), parent.join("keys"));
        let mode = std::fs::metadata(home.root_dir())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0);
        assert_eq!(home.devices().unwrap(), vec!["laptop"]);
        assert!(fixture.device_dir().join("agent_id").is_file());
        parent
    };
    assert!(!parent.exists());
}

#[test]
fn device_only_home_names_the_device() {
    let fixture = DeviceOnlyHome::new("phone-2", 100, 50);
    assert_eq!(fixture.home().devices().unwrap(), vec!["phone-2"]);
    assert_eq!(
        fixture.device_dir(),
        fixture.home().device_dir("phone-2").unwrap()
    );
}
