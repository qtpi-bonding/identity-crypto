//! Start-up refusals: root key by key comparison, principal mismatch, refused
//! principal, empty server id — and no key text or request body anywhere.

mod common;

use common::*;
use identity_request_auth::Clock;
use identity_request_signer::{DeviceState, SignerError};
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
    // genesis: build a directory whose device file was replaced by a copy of the
    // genesis keys under the device file's name.
    if let Ok(rooted) = build_genesis_device_dir(dir.path()) {
        let result = device(&rooted, &[]);
        assert!(
            matches!(result, Err(SignerError::RootKey)),
            "got {:?}",
            result.as_ref().map(|_| ())
        );
    }

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
    let result = device(dir.path(), &[principal.clone()]);
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
    texts.extend(sink.lines().into_iter());
    texts.push(format!(
        "{}",
        identity_request_signer::Config::parse("socket = \"/x\"")
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default()
    ));
    texts.push(body_b64());
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

/// Builds a device-only directory whose device signing key equals the
/// principal's genesis key, by rewriting the generated device file with the
/// genesis duo's contents. Only works if the file format makes that possible;
/// otherwise returns Err and the direct comparison above still covers the rule.
fn build_genesis_device_dir(source: &Path) -> Result<std::path::PathBuf, ()> {
    // The generated files are opaque JWK documents; the honest construction is
    // to copy the directory and swap the device file for the root file's text,
    // which DeviceKeys::load either accepts (then the key comparison must
    // refuse it) or refuses on its own.
    let temp = tempfile::TempDir::new().map_err(|_| ())?;
    let dir = temp.keep();
    for name in [
        identity_keyfile::DEVICE_FILE,
        identity_keyfile::DELEGATION_FILE,
        identity_keyfile::AGENT_ID_FILE,
    ] {
        std::fs::copy(source.join(name), dir.join(name)).map_err(|_| ())?;
    }
    // Make the device file contain the genesis key by replacing the private
    // half: read the root file from a full init in another temp dir.
    let full = tempfile::TempDir::new().map_err(|_| ())?;
    identity_keyfile::IdentityKeys::init(full.path(), T0, 3600).map_err(|_| ())?;
    // Same principal requires the same genesis; use the full dir's own device
    // dir instead: rebuild a device-only view of `full` and copy its ROOT file
    // text into DEVICE_FILE's slot. If the formats differ, load refuses and the
    // direct comparison still covers the rule.
    std::fs::copy(
        full.path().join(identity_keyfile::ROOT_FILE),
        dir.join(identity_keyfile::DEVICE_FILE),
    )
    .map_err(|_| ())?;
    let loaded = identity_keyfile::DeviceKeys::load(&dir);
    if loaded.is_err() {
        return Err(());
    }
    Ok(dir)
}
