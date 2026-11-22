//! Renewal: status tracks the delegation file, refresh picks up changes, and
//! expiry is refused. Also: no IdentityKeys or renew calls in the crate src.

mod common;

use common::*;
use identity_request_auth::Clock;
use identity_request_signer::{DeviceState, SignParams, SignerError, Signing, RENEWAL_MARGIN_DAYS};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

struct Dir {
    _temp: tempfile::TempDir,
    path: PathBuf,
}

fn setup(now: i64, ttl: i64) -> (Dir, DeviceState, Arc<LogSink>, Arc<TestClock>) {
    let temp = tempfile::TempDir::new().expect("temp dir");
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700))
        .expect("make temp dir private");
    identity_keyfile::IdentityKeys::init(temp.path(), now, ttl).expect("init identity");
    std::fs::remove_file(temp.path().join(identity_keyfile::ROOT_FILE)).expect("make device-only");
    let dir = Dir {
        path: temp.path().to_path_buf(),
        _temp: temp,
    };
    let sink = LogSink::new();
    let clock = TestClock::new(now);
    let socket = dir.path.join("s.sock");
    let config = config_for(&dir.path, &socket, Some(SERVER));
    let dyn_clock: Arc<dyn Clock> = clock.clone();
    let device = DeviceState::load(
        &dir.path,
        &config.expected_principal,
        &[],
        dyn_clock,
        sink.sink(),
    )
    .expect("device state");
    (dir, device, sink, clock)
}

#[test]
fn renewal_status_tracks_the_delegation_file() {
    let ttl = 91 * 86400;
    let (dir, device, sink, clock) = setup(T0, ttl);

    // days_left and renewal_due with a fresh delegation.
    let status = device.status();
    assert_eq!(status.not_after, T0 + ttl);
    assert_eq!(status.days_left, 91);
    assert!(!status.renewal_due, "91 days left is not renewal-due");
    assert_eq!(RENEWAL_MARGIN_DAYS, 21);

    // The delegation file changed on disk: refresh picks it up without restart.
    let ttl2 = 10 * 86400;
    renew_delegation(&dir.path, T0, ttl2);
    let status = device.status();
    assert_eq!(status.not_after, T0 + ttl2, "the changed file is picked up");
    assert_eq!(status.days_left, 10);
    assert!(
        status.renewal_due,
        "10 days left is within the 21-day margin"
    );
    assert!(
        sink.contains("renewal_due"),
        "a coded warning line is logged when renewal is due"
    );

    // Expired: sign_request is refused with delegation_expired.
    clock.advance(ttl2 + 1);
    let socket = dir.path.join("s.sock");
    let config = config_for(&dir.path, &socket, Some(SERVER));
    let signing = Signing::new(&config, Arc::new(device)).expect("signing");
    let result = signing.sign_request(&SignParams {
        method_path: PATH,
        body_type: BODY_TYPE,
        body: BODY,
        audience: None,
    });
    assert!(matches!(result, Err(SignerError::Expired)));
}

/// Re-adds a root key file so the keyfile renew API can re-sign the delegation.
/// The signer itself never reads the root file; this is the test renewing the
/// delegation the way the real keyfile tool does.
fn renew_delegation(dir: &Path, now: i64, ttl: i64) {
    // The root file was removed to make the dir device-only. The keyfile renew
    // API needs a full layout, so rebuild the identity directory from scratch
    // with the same principal: we instead keep a full dir for renewal and copy
    // only the delegation into the device-only dir the signer reads.
    let full = tempfile::TempDir::new().expect("full temp dir");
    std::fs::set_permissions(full.path(), std::fs::Permissions::from_mode(0o700))
        .expect("make full dir private");
    identity_keyfile::IdentityKeys::init(full.path(), now, ttl).expect("full init");
    identity_keyfile::IdentityKeys::renew(full.path(), now, ttl, false).expect("renew");
    std::fs::copy(
        full.path().join(identity_keyfile::DELEGATION_FILE),
        dir.join(identity_keyfile::DELEGATION_FILE),
    )
    .expect("copy renewed delegation");
}

#[test]
fn the_signer_source_never_touches_identity_keys_or_renewal() {
    // Grep the crate src for IdentityKeys and renew calls: none.
    let mut hits = Vec::new();
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    for entry in walk(&src) {
        let text = std::fs::read_to_string(&entry).expect("read source");
        for (line_no, line) in text.lines().enumerate() {
            if line.contains("IdentityKeys") || regex_renew(line) {
                hits.push(format!("{}:{}: {line}", entry.display(), line_no + 1));
            }
        }
    }
    assert!(
        hits.is_empty(),
        "the signer must not use IdentityKeys or renew: {hits:?}"
    );
}

fn regex_renew(line: &str) -> bool {
    // "renew(" as a call (not in comments), the signer never renews.
    let stripped = line.split("//").next().unwrap_or(line);
    stripped.contains(".renew(") || stripped.contains("renew(") && !stripped.contains("RENEWAL")
}

fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).expect("read dir") {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        if path.is_dir() {
            out.extend(walk(&path));
        } else if path.extension().map(|e| e == "rs").unwrap_or(false) {
            out.push(path);
        }
    }
    out
}
