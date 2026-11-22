//! Refusals: coded errors, no signature, nothing of the request or key echoed.

mod common;

use common::*;
use identity_request_auth::{Clock, RequestSigner};
use identity_request_signer::{DeviceState, SignParams, SignerError, Signing};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::time::{Duration, Instant};

fn device(dir: &std::path::Path) -> DeviceState {
    let socket = dir.join("unused.sock");
    let config = config_for(dir, &socket, Some(SERVER));
    let clock: Arc<dyn Clock> = TestClock::new(T0);
    DeviceState::load(
        dir,
        &config.expected_principal,
        &[],
        clock,
        LogSink::new().sink(),
    )
    .expect("device state")
}

fn signing_with(dir: &std::path::Path, server_id: Option<&str>, overrides: &str) -> Signing {
    let socket = dir.join("test.sock");
    let mut text = format!(
        "{}{}\n",
        config_text(dir, &socket),
        match server_id {
            Some(s) => format!("server_id = {s:?}\n"),
            None => String::new(),
        }
    );
    // The defaults are omitted when the overrides supply their own limits,
    // so the TOML never carries a duplicate key.
    if !overrides.contains("max_body") {
        text.push_str("max_body = 4194304\nmax_line_bytes = 5800000\nread_timeout_secs = 5\n");
    }
    text.push_str(overrides);
    let config = identity_request_signer::Config::parse(&text).expect("parse config");
    Signing::new(&config, Arc::new(device(dir))).expect("signing")
}

fn assert_coded(result: Result<identity_request_signer::SignOutcome, SignerError>, code: &str) {
    let err = match result {
        Ok(_) => panic!("expected a coded refusal"),
        Err(e) => e,
    };
    assert_eq!(coded_error::CodedError::code(&err), code);
}

#[test]
fn bad_sign_requests_are_refused_with_coded_errors() {
    let dir = DeviceOnlyDir::new(T0, 3600);
    let signing = signing_with(dir.path(), Some(SERVER), "");

    // Empty method_path.
    assert_coded(
        signing.sign_request(&SignParams {
            method_path: "",
            body_type: BODY_TYPE,
            body: BODY,
            audience: None,
        }),
        "identity.request_signer.bad_request",
    );

    // Empty body_type.
    assert_coded(
        signing.sign_request(&SignParams {
            method_path: PATH,
            body_type: "",
            body: BODY,
            audience: None,
        }),
        "identity.request_signer.bad_request",
    );

    // Empty supplied audience.
    assert_coded(
        signing.sign_request(&SignParams {
            method_path: PATH,
            body_type: BODY_TYPE,
            body: BODY,
            audience: Some(""),
        }),
        "identity.request_signer.bad_request",
    );

    // No audience and no server_id.
    let no_server = signing_with(dir.path(), None, "");
    assert_coded(
        no_server.sign_request(&SignParams {
            method_path: PATH,
            body_type: BODY_TYPE,
            body: BODY,
            audience: None,
        }),
        "identity.request_signer.bad_request",
    );

    // Oversize body.
    let small = signing_with(
        dir.path(),
        Some(SERVER),
        "\nmax_body = 4\nmax_line_bytes = 100\n",
    );
    assert_coded(
        small.sign_request(&SignParams {
            method_path: PATH,
            body_type: BODY_TYPE,
            body: BODY,
            audience: None,
        }),
        "identity.request_signer.body_too_large",
    );
}

fn server_for(
    dir: &std::path::Path,
    max_line_bytes: usize,
    read_timeout_secs: u64,
) -> (identity_request_signer::Server, Arc<LogSink>) {
    let socket = dir.join("server.sock");
    let text = format!(
        "{}server_id = {:?}\nmax_body = 16\nmax_line_bytes = {max_line_bytes}\nread_timeout_secs = {read_timeout_secs}\n",
        config_text(dir, &socket),
        SERVER
    );
    let config = identity_request_signer::Config::parse(&text).expect("parse config");
    let sink = LogSink::new();
    let clock: Arc<dyn Clock> = TestClock::new(T0);
    let server = identity_request_signer::Server::new(config, clock, sink.sink()).expect("server");
    (server, sink)
}

#[test]
fn protocol_refusals_through_handle_line_and_socket() {
    let dir = DeviceOnlyDir::new(T0, 3600);

    // Over-long line through handle_line: small max_line_bytes.
    let (server, sink) = server_for(dir.path(), 64, 5);
    let long_line = format!(
        "{{\"op\":\"sign_request\",\"pad\":\"{}\"}}",
        "x".repeat(200)
    );
    let reply = server.handle_line(long_line.as_bytes());
    assert!(reply.contains("line_too_long"), "reply: {reply}");
    let _ = sink;

    // The same over-long line through a real socket.
    let bound = server.bind().expect("bind");
    let path = bound.socket_path().to_path_buf();
    let running = bound.spawn();
    let mut stream = UnixStream::connect(&path).expect("connect");
    stream
        .write_all(long_line.as_bytes())
        .expect("write long line");
    let mut buf = vec![0u8; 4096];
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set timeout");
    let n = stream.read(&mut buf).expect("read reply");
    let reply = String::from_utf8_lossy(&buf[..n]).to_string();
    assert!(reply.contains("line_too_long"), "reply: {reply}");
    drop(stream);
    running.stop();

    // Slow client: sends nothing; the server must answer read_timeout or close
    // within 3 s.
    let (server, _sink) = server_for(dir.path(), 5_800_000, 1);
    let bound = server.bind().expect("bind");
    let path = bound.socket_path().to_path_buf();
    let running = bound.spawn();
    let mut stream = UnixStream::connect(&path).expect("connect");
    let started = Instant::now();
    let mut buf = vec![0u8; 4096];
    let outcome = stream.read(&mut buf);
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(3),
        "server took {elapsed:?} for a slow client"
    );
    if let Ok(n) = outcome {
        if n > 0 {
            let reply = String::from_utf8_lossy(&buf[..n]).to_string();
            assert!(reply.contains("read_timeout"), "reply: {reply}");
        }
    }
    drop(stream);
    running.stop();

    // Bad base64 and malformed JSON through handle_line.
    let (server, _sink) = server_for(dir.path(), 5_800_000, 5);
    let bad_b64 = format!(
        "{{\"op\":\"sign_request\",\"method_path\":{PATH:?},\"body_type\":{BODY_TYPE:?},\"body_b64\":\"not!base64!\"}}"
    );
    let reply = server.handle_line(bad_b64.as_bytes());
    assert!(reply.contains("bad_request"), "reply: {reply}");
    assert!(!reply.contains("not!base64!"), "must not echo the value");

    let reply = server.handle_line(b"{not json");
    assert!(reply.contains("bad_request"), "reply: {reply}");
    let pair = identity_crypto::jwk_duo::SigningKeyPair::generate();
    let genesis = identity_crypto::PublicKey::from(&pair);
    let _ = RequestSigner::new(
        identity_request_auth::DeviceCredentials::new(pair, genesis),
        TestClock::new(T0) as Arc<dyn Clock>,
    );
}
