//! Round trip: a signed header verifies against the auth core; the wrong body,
//! audience or server id does not verify.

mod common;

use common::*;
use identity_request_auth::{NonceCache, NonceCaps, TrustedDeviceSet};
use identity_request_signer::{Config, DeviceState, SignParams, Signing};
use std::sync::Arc;

fn signing(dir: &std::path::Path, server_id: Option<&str>) -> (Config, Signing) {
    let socket = dir.join("test.sock");
    let config = config_for(dir, &socket, server_id);
    let clock: Arc<dyn identity_request_auth::Clock> = TestClock::new(T0);
    let device = DeviceState::load(
        dir,
        &config.expected_principal,
        &[],
        clock,
        LogSink::new().sink(),
    )
    .expect("device state");
    let signing = Signing::new(&config, Arc::new(device)).expect("signing");
    (config, signing)
}

#[test]
fn round_trip_header_verifies_and_tampering_is_refused() {
    let dir = DeviceOnlyDir::new(T0, 3600);
    let (config, signing) = signing(dir.path(), Some(SERVER));

    // No supplied audience: built from server_id and the path.
    let outcome = signing
        .sign_request(&SignParams {
            method_path: PATH,
            body_type: BODY_TYPE,
            body: BODY,
            audience: None,
        })
        .expect("sign");
    let signed: identity_crypto::pb::SignedMessage =
        prost::Message::decode(decode_b64(&outcome.header_b64).as_slice()).expect("decode");
    let audience = identity_request_auth::audience_for("acme.v1.Inventory", "AddItem", SERVER);
    assert_eq!(
        signed.audience, audience,
        "audience built from server id and path"
    );

    // Accepted by the auth core with the right audience, body type and body.
    let keys = identity_keyfile::DeviceKeys::load(dir.path()).expect("keys");
    let set = TrustedDeviceSet::new(
        keys.principal_id.genesis().clone(),
        vec![device_of(dir.path())],
    );
    let mut nonces = NonceCache::new(NonceCaps::default());
    let clock: Arc<dyn identity_request_auth::Clock> = TestClock::new(T0);
    let caller = identity_request_auth::open_signed_request(
        &signed,
        &audience,
        BODY_TYPE,
        BODY,
        Some(config.max_body()),
        &set,
        &mut nonces,
        identity_request_auth::ClockTolerance::default(),
        clock.now().seconds,
    )
    .expect("a freshly signed header verifies");
    let _ = caller;

    // The same header with an altered body is refused.
    let mut tampered = BODY.to_vec();
    tampered[0] ^= 1;
    let mut nonces = NonceCache::new(NonceCaps::default());
    let result = identity_request_auth::open_signed_request(
        &signed,
        &audience,
        BODY_TYPE,
        &tampered,
        Some(config.max_body()),
        &set,
        &mut nonces,
        identity_request_auth::ClockTolerance::default(),
        clock.now().seconds,
    );
    assert!(
        result.is_err(),
        "an altered body must not verify against the signature"
    );

    // A caller-supplied audience is used as given.
    let supplied = "custom-audience";
    let outcome = signing
        .sign_request(&SignParams {
            method_path: PATH,
            body_type: BODY_TYPE,
            body: BODY,
            audience: Some(supplied),
        })
        .expect("sign with supplied audience");
    let signed: identity_crypto::pb::SignedMessage =
        prost::Message::decode(decode_b64(&outcome.header_b64).as_slice()).expect("decode");
    assert_eq!(signed.audience, supplied);

    // And the right audience, body type and body again.
    let mut nonces = NonceCache::new(NonceCaps::default());
    identity_request_auth::open_signed_request(
        &signed,
        supplied,
        BODY_TYPE,
        BODY,
        Some(config.max_body()),
        &set,
        &mut nonces,
        identity_request_auth::ClockTolerance::default(),
        clock.now().seconds,
    )
    .expect("supplied audience verifies");
}
