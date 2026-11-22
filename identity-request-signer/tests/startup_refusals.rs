//! Start-up refusals: root key by key comparison, principal mismatch, refused
//! principal, empty server id — and no key text or request body anywhere.

mod common;

use common::*;
use identity_request_auth::Clock;
use identity_request_signer::{DeviceState, SignerError};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;

fn device(dir: &Path, refuse: &[String]) -> Result<DeviceState, SignerError> {
    let socket = dir.join("unused.sock");
    let config = config_for(dir, &socket, Some(SERVER));
    let clock: Arc<dyn Clock> = TestClock::new(T0);
    DeviceState::load(
        dir,
        &config.expected_principal,
        refuse,
        clock,
        LogSink::new().sink(),
    )
}

#[test]
fn start_up_refusals_and_no_secrets_in_any_text() {
    let dir = DeviceOnlyDir::new(T0, 3600);
    let principal = principal_string(dir.path());
    let genesis = genesis_of(dir.path());
    let device_key = device_of(dir.path());

    // Root key refused, by KEY comparison, directly.
    assert!(matches!(
        DeviceState::refuse_root_key(&device_key, &device_key),
        Err(SignerError::RootKey)
    ));
    DeviceState::refuse_root_key(&device_key, &device_key).expect_err("same key is refused");
    // A different key is fine.
    DeviceState::refuse_root_key(&device_key, &genesis).expect("a device key is not the root");

    // Root key refused through DeviceState::load when the device key equals the
    // genesis: a directory whose device file holds the root (genesis) signing
    // key and a delegation of that key, built with the keyfile/crypto APIs.
    let rooted = build_genesis_device_dir();
    let result = device(rooted.path(), &[]);
    assert!(
        matches!(result, Err(SignerError::RootKey)),
        "got {:?}",
        result.as_ref().map(|_| ())
    );

    // Principal mismatch.
    let result = {
        let socket = dir.path().join("unused.sock");
        let text = format!(
            "{}server_id = {:?}\n",
            config_text(dir.path(), &socket),
            SERVER
        );
        let mut config = identity_request_signer::Config::parse(&text).expect("parse");
        config.expected_principal = "p256:does-not-match".to_string();
        let clock: Arc<dyn Clock> = TestClock::new(T0);
        DeviceState::load(
            dir.path(),
            &config.expected_principal,
            &[],
            clock,
            LogSink::new().sink(),
        )
    };
    assert!(matches!(result, Err(SignerError::PrincipalMismatch)));

    // Refused principal.
    let result = device(dir.path(), std::slice::from_ref(&principal));
    assert!(matches!(result, Err(SignerError::PrincipalRefused)));

    // Empty server_id: Config::validate.
    let socket = dir.path().join("v.sock");
    let text = format!("{}server_id = \"\"\n", config_text(dir.path(), &socket));
    let config = identity_request_signer::Config::parse(&text).expect("parse");
    assert!(matches!(config.validate(), Err(SignerError::EmptyServerId)));

    // Empty server_id through Server::new.
    let clock: Arc<dyn Clock> = TestClock::new(T0);
    let result = identity_request_signer::Server::new(config, clock, LogSink::new().sink());
    assert!(matches!(result, Err(SignerError::EmptyServerId)));

    // No key bytes in any error, response or log line. Collect every error
    // Display and log line produced by the refusals above and check that none
    // contains a substring of the temp dir's own device key file text, nor the
    // body base64.
    let samples = key_text_samples(dir.path());
    assert!(!samples.is_empty(), "the device key file must have content");
    let mut texts: Vec<String> = Vec::new();
    for result in [
        device(dir.path(), &[]).map(|_| ()),
        device(dir.path(), &[principal]).map(|_| ()),
    ] {
        if let Err(e) = result {
            texts.push(format!("{e}"));
        }
    }
    let sink = LogSink::new();
    let clock: Arc<dyn Clock> = TestClock::new(T0);
    let _ = DeviceState::load(
        dir.path(),
        "p256:other",
        &[principal_string(dir.path())],
        clock,
        sink.sink(),
    );
    texts.extend(sink.lines());
    texts.push(
        identity_request_signer::Config::parse("socket = \"/x\"")
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default()
            .to_string(),
    );
    for text in &texts {
        for sample in &samples {
            assert!(
                !text.contains(sample.as_str()),
                "a sample of the device key file leaked into: {text}"
            );
        }
        assert!(
            !text.contains(&body_b64()),
            "the request body base64 leaked into: {text}"
        );
    }
}

/// Builds a private temp directory whose device file holds the identity's
/// root (genesis) key duo and whose delegation names that key, using only the
/// generated keys of a fresh `IdentityKeys::init` and the public keyfile and
/// crypto APIs. The TempDir handle is kept for the life of the test.
struct RootedDir {
    _temp: tempfile::TempDir,
}

impl RootedDir {
    fn path(&self) -> &Path {
        self._temp.path()
    }
}

fn build_genesis_device_dir() -> RootedDir {
    let temp = tempfile::TempDir::new().expect("temp identity dir");
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700))
        .expect("make the temp dir private");
    let keys = identity_keyfile::IdentityKeys::init(temp.path(), T0, 86_400)
        .expect("init a generated identity");
    let pid = keys.principal_id.clone();
    // The transcript rule refuses a delegation whose delegated key equals the
    // signing root, so the builder cannot sign one. `DeviceState::load` checks
    // only that the delegation names the device key (no signature check), so
    // the unsigned delegation bytes are enough to reach the key comparison.
    let delegation = identity_crypto::device_delegation(
        &pid,
        &identity_crypto::signing_public(&keys.root),
        &identity_crypto::signing_public(&keys.root),
        &identity_crypto::encryption_public(&keys.root),
        T0,
        T0 + 86_400,
    );
    identity_keyfile::write_duo(temp.path(), identity_keyfile::DEVICE_FILE, &keys.root)
        .expect("write the genesis duo as the device file");
    identity_keyfile::write_delegation(temp.path(), &delegation).expect("write the delegation");
    identity_keyfile::write_principal_id(temp.path(), &pid).expect("write the agent id");
    RootedDir { _temp: temp }
}

#[test]
fn server_new_as_root_is_refused_before_any_key_is_read() {
    // A config for a directory with no usable keys: if keys were read first,
    // the error would be Keys, not RunningAsRoot.
    let missing = tempfile::TempDir::new().expect("temp dir");
    let socket = missing.path().join("s.sock");
    // Hand-built: config_text would read the (absent) keys for the principal.
    let text = format!(
        "identity_dir = {:?}\nexpected_principal = \"p256:absent\"\nsocket = {:?}\nserver_id = {:?}\n",
        missing.path().join("absent"),
        socket,
        SERVER
    );
    let config = identity_request_signer::Config::parse(&text).expect("parse config");
    let clock: Arc<dyn Clock> = TestClock::new(T0);
    let result = identity_request_signer::Server::new_as(0, config, clock, LogSink::new().sink());
    assert!(
        matches!(result, Err(SignerError::RunningAsRoot)),
        "got {:?}",
        result.err()
    );
}
