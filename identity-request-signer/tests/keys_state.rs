//! DeviceState key-level tests: load ok, refusals, delegation tracking and
//! expiry. Keys are always generated in temp dirs; no real key files are read.

mod common;

use common::*;
use identity_request_auth::Clock;
use identity_request_signer::{DeviceState, SignerError, RENEWAL_MARGIN_DAYS};
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;

fn private_dir() -> tempfile::TempDir {
    let dir = tempfile::TempDir::new().expect("temp dir");
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
        .expect("make temp dir private");
    dir
}

fn device_only_dir(now: i64, ttl: i64) -> tempfile::TempDir {
    let dir = private_dir();
    identity_keyfile::IdentityKeys::init(dir.path(), now, ttl).expect("init identity");
    std::fs::remove_file(dir.path().join(identity_keyfile::ROOT_FILE))
        .expect("make the dir device-only");
    dir
}

/// A device-only dir plus a full sibling dir holding the SAME identity's root,
/// so the keyfile renew API can re-sign the delegation for the same device.
struct RenewableDir {
    device_only: tempfile::TempDir,
    full: tempfile::TempDir,
}

impl RenewableDir {
    fn new(now: i64, ttl: i64) -> Self {
        let full = private_dir();
        identity_keyfile::IdentityKeys::init(full.path(), now, ttl).expect("init identity");
        let device_only = private_dir();
        for name in [
            identity_keyfile::DEVICE_FILE,
            identity_keyfile::DELEGATION_FILE,
            identity_keyfile::AGENT_ID_FILE,
            identity_keyfile::HISTORY_FILE,
            identity_keyfile::ROTATIONS_FILE,
        ] {
            std::fs::copy(full.path().join(name), device_only.path().join(name))
                .expect("copy device file");
        }
        Self { device_only, full }
    }

    fn renew(&self, now: i64, ttl: i64) {
        identity_keyfile::IdentityKeys::renew(self.full.path(), now, ttl, false).expect("renew");
        std::fs::copy(
            self.full.path().join(identity_keyfile::DELEGATION_FILE),
            self.device_only
                .path()
                .join(identity_keyfile::DELEGATION_FILE),
        )
        .expect("copy the renewed delegation");
    }
}

fn load_at(dir: &std::path::Path, clock: Arc<dyn Clock>) -> Result<DeviceState, SignerError> {
    let principal = principal_string(dir);
    DeviceState::load(dir, &principal, &[], clock, LogSink::new().sink())
}

#[test]
fn load_ok_on_a_device_only_dir() {
    let dir = device_only_dir(T0, 86_400);
    let state = load_at(dir.path(), TestClock::new(T0)).expect("load");
    assert_eq!(state.principal(), principal_string(dir.path()));
}

#[test]
fn principal_mismatch_is_refused() {
    let dir = device_only_dir(T0, 86_400);
    let clock: Arc<dyn Clock> = TestClock::new(T0);
    let result = DeviceState::load(
        dir.path(),
        "p256:does-not-match",
        &[],
        clock,
        LogSink::new().sink(),
    );
    assert!(matches!(result, Err(SignerError::PrincipalMismatch)));
}

#[test]
fn refused_principal_is_refused() {
    let dir = device_only_dir(T0, 86_400);
    let principal = principal_string(dir.path());
    let clock: Arc<dyn Clock> = TestClock::new(T0);
    let result = DeviceState::load(
        dir.path(),
        &principal,
        std::slice::from_ref(&principal),
        clock,
        LogSink::new().sink(),
    );
    assert!(matches!(result, Err(SignerError::PrincipalRefused)));
}

#[test]
fn root_key_refused_by_key_comparison() {
    let dir = device_only_dir(T0, 86_400);
    let genesis = genesis_of(dir.path());
    let device = device_of(dir.path());
    assert!(matches!(
        DeviceState::refuse_root_key(&device, &device),
        Err(SignerError::RootKey)
    ));
    DeviceState::refuse_root_key(&device, &genesis).expect("a device key is not the root");
}

#[test]
fn status_days_left_and_renewal_due_follow_the_delegation() {
    let ttl = 91 * 86_400;
    let renewable = RenewableDir::new(T0, ttl);
    let dir = &renewable.device_only;
    let clock = TestClock::new(T0);
    let sink = LogSink::new();
    let principal = principal_string(dir.path());
    let state =
        DeviceState::load(dir.path(), &principal, &[], clock.clone(), sink.sink()).expect("load");

    let status = state.status();
    assert_eq!(status.not_after, T0 + ttl);
    assert_eq!(status.days_left, 91);
    assert!(!status.renewal_due);
    assert_eq!(RENEWAL_MARGIN_DAYS, 21);

    let ttl2 = 10 * 86_400;
    renewable.renew(T0, ttl2);

    let status = state.status();
    assert_eq!(status.not_after, T0 + ttl2, "the changed file is picked up");
    assert_eq!(status.days_left, 10);
    assert!(status.renewal_due, "10 days is within the 21-day margin");
}

#[test]
fn ensure_valid_is_expired_after_not_after() {
    let ttl = 100;
    let dir = device_only_dir(T0, ttl);
    let clock = TestClock::new(T0);
    let state = load_at(dir.path(), clock.clone()).expect("load");
    state.ensure_valid().expect("valid before expiry");
    clock.advance(ttl + 1);
    assert!(matches!(state.ensure_valid(), Err(SignerError::Expired)));
}

#[test]
fn no_key_file_text_in_any_error_or_log_line() {
    let dir = device_only_dir(T0, 86_400);
    let principal = principal_string(dir.path());
    let samples = key_text_samples(dir.path());
    assert!(!samples.is_empty(), "the device key file must have content");
    let mut texts: Vec<String> = Vec::new();
    for result in [
        load_at(dir.path(), TestClock::new(T0)).map(|_| ()),
        DeviceState::load(
            dir.path(),
            "p256:other",
            std::slice::from_ref(&principal),
            TestClock::new(T0),
            LogSink::new().sink(),
        )
        .map(|_| ()),
    ] {
        if let Err(e) = result {
            texts.push(format!("{e}"));
        }
    }
    let sink = LogSink::new();
    let _ = DeviceState::load(dir.path(), &principal, &[], TestClock::new(T0), sink.sink());
    texts.extend(sink.lines());
    for text in &texts {
        for sample in &samples {
            assert!(
                !text.contains(sample.as_str()),
                "a sample of the device key file leaked into: {text}"
            );
        }
    }
}
