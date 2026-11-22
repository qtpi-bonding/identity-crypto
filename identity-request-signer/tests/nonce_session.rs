//! Nonces differ per call; session renewal follows the auth signer's 60% rule.

mod common;

use common::*;
use identity_request_auth::Clock;
use identity_request_signer::{DeviceState, SignParams, Signing};
use std::sync::Arc;

fn make_signing(clock: Arc<dyn Clock>) -> (std::path::PathBuf, Signing) {
    let dir = DeviceOnlyDir::new(T0, 3600);
    let socket = dir.path().join("s.sock");
    let config = config_for(dir.path(), &socket, Some(SERVER));
    let device = DeviceState::load(
        dir.path(),
        &config.expected_principal,
        &[],
        clock,
        LogSink::new().sink(),
    )
    .expect("device state");
    let signing = Signing::new(&config, Arc::new(device)).expect("signing");
    (dir.path().to_path_buf(), signing)
}

fn sign(signing: &Signing) -> identity_crypto::pb::SignedMessage {
    let outcome = signing
        .sign_request(&SignParams {
            method_path: PATH,
            body_type: BODY_TYPE,
            body: BODY,
            audience: None,
        })
        .expect("sign");
    prost::Message::decode(decode_b64(&outcome.header_b64).as_slice()).expect("decode")
}

fn nonce_of(signed: &identity_crypto::pb::SignedMessage) -> Vec<u8> {
    signed.nonce.clone()
}

#[test]
fn nonce_differs_every_call_and_session_renews_at_sixty_percent() {
    let clock = TestClock::new(T0);
    let (_dir, signing) = make_signing(clock.clone());

    // Nonce differs on every call.
    let first = sign(&signing);
    let second = sign(&signing);
    assert!(!nonce_of(&first).is_empty(), "the message carries a nonce");
    assert_ne!(
        nonce_of(&first),
        nonce_of(&second),
        "a fresh nonce per call"
    );
    let third = sign(&signing);
    assert_ne!(nonce_of(&first), nonce_of(&third));
    assert_ne!(nonce_of(&second), nonce_of(&third));

    // Session renews at 60% of 300 s: same session at 179 s, new at 181 s.
    let auth = identity_request_auth::testkit::FakeClock::new(T0);
    let (_dir2, signing2) = make_signing(auth.clone());
    let a = sign(&signing2);
    auth.advance(179);
    let b = sign(&signing2);
    assert_eq!(
        session_key(&a),
        session_key(&b),
        "at 179 s the session is still the same"
    );
    auth.advance(2);
    let c = sign(&signing2);
    assert_ne!(
        session_key(&b),
        session_key(&c),
        "at 181 s the session has renewed"
    );
}

fn session_key(signed: &identity_crypto::pb::SignedMessage) -> Vec<u8> {
    use identity_crypto::pb::signer_chain::Chain;
    let key: identity_crypto::pb::PublicKey =
        match signed.signer.as_ref().and_then(|s| s.chain.as_ref()) {
            Some(Chain::SelfRooted(s)) => s
                .session
                .as_ref()
                .expect("session cert")
                .session
                .clone()
                .expect("session key"),
            other => panic!("expected a self-rooted chain, got {other:?}"),
        };
    identity_crypto::PublicKey::try_from(&key)
        .expect("a public key")
        .as_bytes()
        .to_vec()
}
