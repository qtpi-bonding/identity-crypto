#![cfg(feature = "testkit")]

use identity_keyfile::enrol_cli::{run, EnrolCliError, Outcome};
use identity_keyfile::testkit::{TempIdentityDir, TempMachineDir};
use identity_keyfile::EnrolmentIndex;
use std::process::Command;

fn args(machine: &std::path::Path, key: Option<&str>, dir: &std::path::Path) -> Vec<String> {
    let mut v = vec![
        "enrol".to_string(),
        "--machine-dir".into(),
        machine.display().to_string(),
    ];
    if let Some(key) = key {
        v.push("--key".into());
        v.push(key.into());
    }
    v.push("--dir".into());
    v.push(dir.display().to_string());
    v
}

#[test]
fn enrol_then_reenrol_is_a_no_op() {
    let machine = TempMachineDir::new();
    let identity = TempIdentityDir::new(1_000_000, 3600);
    let a = args(&machine.path(), Some("svc/one"), identity.path());
    assert_eq!(run(&a, None).unwrap(), Outcome::Enrolled);
    let index_file = machine.path().join("enrolments.json");
    let before = std::fs::read(&index_file).unwrap();
    assert_eq!(run(&a, None).unwrap(), Outcome::Unchanged);
    assert_eq!(std::fs::read(&index_file).unwrap(), before, "no rewrite");
    let index = EnrolmentIndex::read(&machine.machine()).unwrap();
    assert_eq!(index.services().count(), 1);
}

#[test]
fn a_missing_key_is_a_coded_error() {
    let machine = TempMachineDir::new();
    let identity = TempIdentityDir::new(1_000_000, 3600);
    let err = run(&args(&machine.path(), None, identity.path()), None).unwrap_err();
    assert!(matches!(err, EnrolCliError::MissingKey));
    assert_eq!(err.code(), "identity.keyfile.enrol.missing_key");
    let bad = run(
        &args(&machine.path(), Some("Bad Key"), identity.path()),
        None,
    )
    .unwrap_err();
    assert_eq!(bad.code(), "identity.keyfile.enrol.invalid_key");
}

#[test]
fn the_binary_enrols_idempotently_and_prints_no_key_material() {
    let machine = TempMachineDir::new();
    let identity = TempIdentityDir::new(1_000_000, 3600);
    let run_bin = |key: Option<&str>| {
        Command::new(env!("CARGO_BIN_EXE_identity-enrol"))
            .args(args(&machine.path(), key, identity.path()))
            .output()
            .unwrap()
    };
    let first = run_bin(Some("svc/bin"));
    assert!(first.status.success(), "{first:?}");
    let second = run_bin(Some("svc/bin"));
    assert!(second.status.success(), "re-enrolling is exit 0");
    let missing = run_bin(None);
    assert_eq!(missing.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&missing.stderr);
    assert!(
        stderr.starts_with("identity.keyfile.enrol.missing_key: "),
        "{stderr}"
    );
    for out in [&first, &second, &missing] {
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(!text.contains("\"d\""), "no private key material: {text}");
    }
}
