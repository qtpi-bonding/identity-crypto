//! Socket permissions: the socket dir is 0700, the socket 0600, and the
//! socket-path checks refuse everything else.

mod common;

use common::*;
use identity_request_auth::Clock;
use identity_request_signer::{check_not_root, prepare_socket_dir, SignerError};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::sync::Arc;

fn server(dir: &std::path::Path, socket: &std::path::Path) -> identity_request_signer::Server {
    let text = format!(
        "{}server_id = {:?}\nmax_body = 4194304\nmax_line_bytes = 5800000\nread_timeout_secs = 5\n",
        config_text(dir, socket),
        SERVER
    );
    let config = identity_request_signer::Config::parse(&text).expect("parse config");
    let clock: Arc<dyn Clock> = TestClock::new(T0);
    identity_request_signer::Server::new(config, clock, LogSink::new().sink()).expect("server")
}

#[test]
fn socket_permissions_and_refusals() {
    let dir = DeviceOnlyDir::new(T0, 3600);
    let uid = identity_keyfile::private_fs::effective_uid();

    // Parent dir 0700 and socket 0600 after bind.
    let socket = dir.path().join("run").join("signer.sock");
    std::fs::create_dir_all(socket.parent().unwrap()).expect("create socket dir");
    std::fs::set_permissions(
        socket.parent().unwrap(),
        std::fs::Permissions::from_mode(0o700),
    )
    .expect("make socket dir 0700");
    let bound = server(dir.path(), &socket).bind().expect("bind");
    let dir_meta = std::fs::metadata(socket.parent().unwrap()).expect("socket dir");
    assert_eq!(dir_meta.mode() & 0o777, 0o700, "socket dir must be 0700");
    let sock_meta = std::fs::metadata(bound.socket_path()).expect("socket file");
    assert_eq!(sock_meta.mode() & 0o777, 0o600, "socket must be 0600");

    // A stale socket at the path is removed and re-bound.
    drop(bound);
    let stale = dir.path().join("stale.sock");
    let _conn = UnixListener::bind(&stale).expect("create stale socket");
    prepare_socket_dir(&stale, uid).expect("a stale socket is removed");
    let bound2 = server(dir.path(), &stale).bind().expect("re-bind");
    assert_eq!(bound2.socket_path(), stale);
    drop(bound2);

    // A regular file at the socket path is refused.
    let regular = dir.path().join("regular.sock");
    std::fs::write(&regular, b"hello").expect("create regular file");
    let result = server(dir.path(), &regular).bind();
    assert!(matches!(result, Err(SignerError::SocketDir(_))));

    // prepare_socket_dir refuses a 0755 directory.
    let loose = dir.path().join("loose");
    std::fs::create_dir_all(&loose).expect("create loose dir");
    std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o755))
        .expect("make loose dir 0755");
    let result = prepare_socket_dir(&loose.join("s.sock"), uid);
    assert!(matches!(result, Err(SignerError::SocketDir(_))));

    // Refuses a directory not owned by the given uid.
    let owned = dir.path().join("owned");
    std::fs::create_dir_all(&owned).expect("create owned dir");
    std::fs::set_permissions(&owned, std::fs::Permissions::from_mode(0o700))
        .expect("make owned dir 0700");
    let other_uid = if uid == 0 { 1 } else { uid + 1 };
    let result = prepare_socket_dir(&owned.join("s.sock"), other_uid);
    assert!(matches!(result, Err(SignerError::SocketDir(_))));

    // check_not_root(0) is RunningAsRoot.
    assert!(matches!(check_not_root(0), Err(SignerError::RunningAsRoot)));
    check_not_root(1000).expect("a normal uid is fine");
}
