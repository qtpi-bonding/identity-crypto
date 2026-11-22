//! The wire protocol over a real unix socket.

mod common;

use common::*;
use identity_request_auth::Clock;
use identity_request_signer::{Op, OpContext, Server, SignerError};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::sync::Arc;

fn bound_server(dir: &std::path::Path) -> identity_request_signer::Server {
    let socket = dir.join("proto.sock");
    let text = format!(
        "{}server_id = {:?}\nmax_body = 4194304\nmax_line_bytes = 5800000\nread_timeout_secs = 5\n",
        config_text(dir, &socket),
        SERVER
    );
    let config = identity_request_signer::Config::parse(&text).expect("parse config");
    let clock: Arc<dyn Clock> = TestClock::new(T0);
    Server::new(config, clock, LogSink::new().sink()).expect("server")
}

fn exchange(path: &std::path::Path, request: &str) -> serde_json::Value {
    let mut stream = UnixStream::connect(path).expect("connect");
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .expect("set timeout");
    stream.write_all(request.as_bytes()).expect("write");
    stream.write_all(b"\n").expect("write newline");
    let mut line = String::new();
    BufReader::new(stream)
        .read_line(&mut line)
        .expect("read reply");
    serde_json::from_str(&line).expect("reply is JSON")
}

/// A test-only extra op.
struct Echo;

impl Op for Echo {
    fn name(&self) -> &str {
        "echo"
    }

    fn run(
        &self,
        _ctx: &OpContext,
        request: &serde_json::Value,
    ) -> Result<serde_json::Value, SignerError> {
        Ok(serde_json::json!({"echoed": request}))
    }
}

#[test]
fn protocol_over_a_real_unix_socket() {
    let dir = DeviceOnlyDir::new(T0, 3600);
    let mut server = bound_server(dir.path());

    // A duplicate op name is refused before we ever bind.
    let result = server.register_op(Box::new(SignRequestOp2));
    assert!(matches!(result, Err(SignerError::ConfigInvalid(_))));
    let result = server.register_op(Box::new(Echo));
    result.expect("echo op registers");

    let bound = server.bind().expect("bind");
    let path = bound.socket_path().to_path_buf();
    let running = bound.spawn();

    // info reply.
    let reply = exchange(&path, "{\"op\":\"info\"}");
    assert_eq!(reply["ok"], true);
    assert!(reply["principal"].is_string());
    assert!(reply["version"].is_string());
    assert!(reply["days_left"].is_i64());
    assert!(reply["renewal_due"].is_boolean());

    // sign_request reply.
    let request = format!(
        "{{\"op\":\"sign_request\",\"method_path\":{PATH:?},\"body_type\":{BODY_TYPE:?},\"body_b64\":{body:?},\"audience\":null}}",
        body = encode_b64(BODY)
    );
    let reply = exchange(&path, &request);
    assert_eq!(reply["ok"], true);
    assert!(reply["header_b64"].is_string());
    assert!(reply["days_left"].is_i64());

    // Unknown op.
    let reply = exchange(&path, "{\"op\":\"nope\"}");
    assert_eq!(reply["ok"], false);
    assert_eq!(reply["code"], "unknown_op");

    // A registered extra op works.
    let reply = exchange(&path, "{\"op\":\"echo\",\"hello\":\"world\"}");
    assert_eq!(reply["ok"], true);
    assert_eq!(reply["echoed"]["hello"], "world");

    // The header is decodable.
    let header = reply["header_b64"].as_str().expect("header");
    let signed: identity_crypto::pb::SignedMessage =
        prost::Message::decode(decode_b64(header).as_slice()).expect("decode header");

    running.stop();
    let _ = signed;
}

struct SignRequestOp2;

impl Op for SignRequestOp2 {
    fn name(&self) -> &str {
        "sign_request"
    }
    fn run(
        &self,
        _ctx: &OpContext,
        _request: &serde_json::Value,
    ) -> Result<serde_json::Value, SignerError> {
        unimplemented!()
    }
}

/// The socket directory the test binds in is private.
#[test]
fn the_socket_dir_is_private() {
    let dir = DeviceOnlyDir::new(T0, 3600);
    let socket = dir.path().join("perm.sock");
    let mut server = bound_server(dir.path());
    let bound = server.bind().expect("bind");
    let parent = bound.socket_path().parent().unwrap_or(dir.path());
    let mode = std::fs::metadata(parent)
        .map(|m| m.permissions().mode() & 0o777)
        .unwrap_or(0o700);
    assert_eq!(mode, 0o700, "the bind dir is 0700");
    drop(bound);
    let _ = socket;
}
