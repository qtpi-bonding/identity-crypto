//! The real binary starts from a 0600 config for a device-only temp dir and
//! serves both `info` and `sign_request` over its socket.

mod common;

use common::*;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::{Duration, Instant};

#[test]
fn the_binary_starts_and_serves_info_and_sign_request() {
    let dir = DeviceOnlyDir::new(T0, 91 * 86400);
    let socket = dir.path().join("run.sock");
    let config_dir = tempfile::TempDir::new().expect("config temp dir");
    let config_path: PathBuf = config_dir.path().join("signer.toml");
    let text = format!(
        "{}server_id = {:?}\n",
        config_text(dir.path(), &socket),
        SERVER
    );
    std::fs::write(&config_path, text).expect("write config");
    std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o600))
        .expect("make the config 0600");

    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_identity-request-signer"))
        .arg("--config")
        .arg(&config_path)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn the binary");

    // Wait up to 5 s for the socket to appear.
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut connected: Option<UnixStream> = None;
    while Instant::now() < deadline {
        match UnixStream::connect(&socket) {
            Ok(stream) => {
                connected = Some(stream);
                break;
            }
            Err(_) => {
                if matches!(child.try_wait(), Ok(Some(_))) {
                    panic!("the binary exited before its socket appeared");
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
    assert!(connected.is_some(), "the socket appeared within 5 s");
    let path = socket;
    let exchange = |request: &str| -> serde_json::Value {
        // The server handles one line per connection.
        let mut stream = UnixStream::connect(&path).expect("connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("set timeout");
        stream.write_all(request.as_bytes()).expect("write request");
        stream.write_all(b"\n").expect("write newline");
        let mut line = String::new();
        BufReader::new(stream.try_clone().expect("clone stream"))
            .read_line(&mut line)
            .expect("read reply");
        serde_json::from_str(&line).expect("the reply is JSON")
    };

    let info = exchange("{\"op\":\"info\"}");
    assert_eq!(info["ok"], true, "info reply: {info}");
    assert!(info["principal"].is_string());

    let sign = exchange(&format!(
        "{{\"op\":\"sign_request\",\"method_path\":{PATH:?},\"body_type\":{BODY_TYPE:?},\"body_b64\":{body:?},\"audience\":{SERVER:?}}}",
        body = encode_b64(BODY)
    ));
    assert_eq!(sign["ok"], true, "sign_request reply: {sign}");
    assert!(sign["header_b64"].is_string());

    // Never leave the child running.
    child.kill().expect("kill the child");
    let _ = child.wait();
}
