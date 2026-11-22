//! The unix-socket server: one JSON request line in, one JSON response line out.

use crate::config::Config;
use crate::error::SignerError;
use crate::keys::DeviceState;
use crate::signing::{Info, SignParams, Signing};
use identity_request_auth::Clock;
use serde_json::json;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc,
};
use std::time::Duration;

/// How many connections may be live at once; over this the extra connections
/// are closed at once.
const MAX_CONNECTIONS: usize = 32;
/// The accept-loop poll interval for the nonblocking accept.
const ACCEPT_POLL_MS: u64 = 20;

/// A coded refusal, logged with its code only (no message text, no values).
fn log_refusal(log: &dyn Fn(&str), err: &SignerError) {
    log(&format!("refused: {}", coded_error::CodedError::code(err)));
}

/// The JSON error line for a coded error.
fn error_json(err: &SignerError) -> String {
    json!({
        "ok": false,
        "code": coded_error::CodedError::code(err),
        "message": err.to_string(),
    })
    .to_string()
}

/// What an op needs to run.
pub struct OpContext<'a> {
    pub signing: &'a Signing,
    pub device: &'a DeviceState,
}

/// A named operation. The built-in `sign_request` and `info` are joined by
/// whatever a caller registers.
pub trait Op: Send + Sync {
    fn name(&self) -> &str;
    fn run(
        &self,
        ctx: &OpContext,
        request: &serde_json::Value,
    ) -> Result<serde_json::Value, SignerError>;
}

/// The built-in op: signs what the request says.
pub struct SignRequestOp;

impl SignRequestOp {
    pub fn new() -> SignRequestOp {
        SignRequestOp
    }
}

impl Default for SignRequestOp {
    fn default() -> Self {
        Self::new()
    }
}

impl Op for SignRequestOp {
    fn name(&self) -> &str {
        "sign_request"
    }

    fn run(
        &self,
        ctx: &OpContext,
        request: &serde_json::Value,
    ) -> Result<serde_json::Value, SignerError> {
        // One fixed message for every malformed request: values are never echoed.
        const MALFORMED: &str = "the request must carry method_path, body_type and body_b64 strings, and an optional audience";
        let method_path = request
            .get("method_path")
            .and_then(serde_json::Value::as_str)
            .ok_or(SignerError::BadRequest(String::from(MALFORMED)))?;
        let body_type = request
            .get("body_type")
            .and_then(serde_json::Value::as_str)
            .ok_or(SignerError::BadRequest(String::from(MALFORMED)))?;
        let body_b64 = request
            .get("body_b64")
            .and_then(serde_json::Value::as_str)
            .ok_or(SignerError::BadRequest(String::from(MALFORMED)))?;
        let audience = match request.get("audience") {
            None | Some(serde_json::Value::Null) => None,
            Some(value) => Some(
                value
                    .as_str()
                    .ok_or(SignerError::BadRequest(String::from(MALFORMED)))?,
            ),
        };
        use base64::Engine;
        let body = base64::engine::general_purpose::STANDARD
            .decode(body_b64)
            .map_err(|_| SignerError::BadRequest(String::from(MALFORMED)))?;
        let outcome = ctx.signing.sign_request(&SignParams {
            method_path,
            body_type,
            body: &body,
            audience,
        })?;
        Ok(json!({
            "header_b64": outcome.header_b64,
            "days_left": outcome.days_left,
        }))
    }
}

/// The shared request-handling core, usable from the owner and from
/// connection threads.
struct Core {
    max_line_bytes: usize,
    ops: Arc<RwLock<Vec<Box<dyn Op>>>>,
    signing: Arc<Signing>,
    device: Arc<DeviceState>,
    log: Arc<dyn Fn(&str) + Send + Sync>,
}

impl Core {
    /// One line in, one JSON line out. Any refusal is logged with its code.
    fn handle_line(&self, line: &[u8]) -> String {
        match self.handle_line_result(line) {
            Ok(reply) => reply,
            Err(err) => {
                log_refusal(self.log.as_ref(), &err);
                error_json(&err)
            }
        }
    }

    fn handle_line_result(&self, line: &[u8]) -> Result<String, SignerError> {
        // The line cap is enforced before any parsing.
        if line.len() > self.max_line_bytes {
            return Err(SignerError::LineTooLong);
        }
        let text = std::str::from_utf8(line)
            .map_err(|_| SignerError::BadRequest(String::from("malformed json")))?;
        let text = text.strip_suffix('\n').unwrap_or(text);
        let text = text.strip_suffix('\r').unwrap_or(text);
        let value: serde_json::Value = serde_json::from_str(text)
            .map_err(|_| SignerError::BadRequest(String::from("malformed json")))?;
        let op = value
            .get("op")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| SignerError::BadRequest(String::from("missing op")))?;
        if op == "info" {
            return Ok(info_json(&self.signing.info()).to_string());
        }
        let guard = self.ops.read().unwrap_or_else(|p| p.into_inner());
        let op_impl = guard
            .iter()
            .find(|candidate| candidate.name() == op)
            .ok_or(SignerError::UnknownOp)?;
        let ctx = OpContext {
            signing: &self.signing,
            device: &self.device,
        };
        let mut out = op_impl.run(&ctx, &value)?;
        if let serde_json::Value::Object(map) = &mut out {
            map.insert(String::from("ok"), serde_json::Value::Bool(true));
        }
        Ok(out.to_string())
    }
}

pub struct Server {
    config: Config,
    core: Core,
}

pub struct BoundServer {
    listener: std::os::unix::net::UnixListener,
    socket_path: PathBuf,
    max_line_bytes: usize,
    read_timeout_secs: u64,
    core: Arc<Core>,
}

pub struct Running {
    handle: Option<std::thread::JoinHandle<()>>,
    socket_path: PathBuf,
    stop: Arc<AtomicBool>,
}

impl Server {
    pub fn new(
        config: Config,
        clock: Arc<dyn Clock>,
        log: Arc<dyn Fn(&str) + Send + Sync>,
    ) -> Result<Server, SignerError> {
        Self::new_as(
            identity_keyfile::private_fs::effective_uid(),
            config,
            clock,
            log,
        )
    }

    /// [`Server::new`] with an explicit uid seam, so tests can prove the root
    /// check happens before any key is read.
    pub fn new_as(
        uid: u32,
        config: Config,
        clock: Arc<dyn Clock>,
        log: Arc<dyn Fn(&str) + Send + Sync>,
    ) -> Result<Server, SignerError> {
        check_not_root(uid)?;
        config.validate()?;
        let device = Arc::new(DeviceState::load(
            &config.identity_dir,
            &config.expected_principal,
            &config.refuse_principals,
            clock,
            log.clone(),
        )?);
        let signing = Signing::new(&config, Arc::clone(&device))?;
        let max_line_bytes = config.max_line_bytes();
        Ok(Server {
            config,
            core: Core {
                max_line_bytes,
                // The binary registers `sign_request`; the library starts empty.
                ops: Arc::new(RwLock::new(Vec::new())),
                signing: Arc::new(signing),
                device,
                log,
            },
        })
    }

    pub fn register_op(&mut self, op: Box<dyn Op>) -> Result<(), SignerError> {
        let mut ops = self.core.ops.write().unwrap_or_else(|p| p.into_inner());
        if op.name() == "info" || ops.iter().any(|existing| existing.name() == op.name()) {
            return Err(SignerError::ConfigInvalid(String::from(
                "an op with this name is already registered",
            )));
        }
        ops.push(op);
        Ok(())
    }

    pub fn handle_line(&self, line: &[u8]) -> String {
        self.core.handle_line(line)
    }

    pub fn bind(self) -> Result<BoundServer, SignerError> {
        let uid = identity_keyfile::private_fs::effective_uid();
        check_not_root(uid)?;
        prepare_socket_dir(&self.config.socket, uid)?;
        // The socket is created 0600 from the start via a restrictive umask,
        // so there is no window where it is readable by others.
        let old_mask = unsafe { libc::umask(0o177) };
        let bind_result = std::os::unix::net::UnixListener::bind(&self.config.socket);
        unsafe {
            libc::umask(old_mask);
        }
        let listener = bind_result
            .map_err(|_| SignerError::SocketDir(String::from("the socket could not be bound")))?;
        // The socket is made owner-only right after bind; the 0700 parent
        // directory owned by the running uid is the guard.
        std::fs::set_permissions(&self.config.socket, std::fs::Permissions::from_mode(0o600))
            .map_err(|_| {
                SignerError::SocketDir(String::from("the socket could not be made private"))
            })?;
        let meta = std::fs::metadata(&self.config.socket).map_err(|_| {
            SignerError::SocketDir(String::from("the socket could not be inspected"))
        })?;
        if std::os::unix::fs::MetadataExt::mode(&meta) & 0o777 != 0o600 {
            return Err(SignerError::SocketDir(String::from(
                "the socket is not 0600",
            )));
        }
        Ok(BoundServer {
            listener,
            socket_path: self.config.socket.clone(),
            max_line_bytes: self.config.max_line_bytes(),
            read_timeout_secs: self.config.read_timeout_secs(),
            core: Arc::new(self.core),
        })
    }
}

pub fn check_not_root(uid: u32) -> Result<(), SignerError> {
    if uid == 0 {
        Err(SignerError::RunningAsRoot)
    } else {
        Ok(())
    }
}

pub fn prepare_socket_dir(socket: &Path, uid: u32) -> Result<(), SignerError> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
    let refuse = || {
        SignerError::SocketDir(String::from(
            "the socket parent directory must exist, be a real directory, be owned by the running uid and be private (0700)",
        ))
    };
    let parent = socket.parent().ok_or_else(refuse)?;
    let meta = std::fs::symlink_metadata(parent).map_err(|_| {
        SignerError::SocketDir(String::from("the socket parent directory does not exist"))
    })?;
    if !meta.is_dir() || meta.uid() != uid || meta.permissions().mode() & 0o077 != 0 {
        return Err(refuse());
    }
    // A stale file at the socket path: a socket is removed, anything else refused.
    if let Ok(meta) = std::fs::symlink_metadata(socket) {
        if meta.file_type().is_socket() {
            std::fs::remove_file(socket).map_err(|_| {
                SignerError::SocketDir(String::from("the stale socket could not be removed"))
            })?;
        } else {
            return Err(refuse());
        }
    }
    Ok(())
}

impl BoundServer {
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    pub fn spawn(self) -> Running {
        let stop = Arc::new(AtomicBool::new(false));
        let listener = self.listener;
        listener
            .set_nonblocking(true)
            .expect("set the listener nonblocking");
        let socket_path = self.socket_path.clone();
        let flag = Arc::clone(&stop);
        let core = Arc::clone(&self.core);
        let max_line_bytes = self.max_line_bytes;
        let read_timeout_secs = self.read_timeout_secs;
        let handle = std::thread::spawn(move || {
            let live = Arc::new(AtomicUsize::new(0));
            while !flag.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _addr)) => {
                        if live.load(Ordering::SeqCst) >= MAX_CONNECTIONS {
                            drop(stream);
                            continue;
                        }
                        live.fetch_add(1, Ordering::SeqCst);
                        let live = Arc::clone(&live);
                        let core = Arc::clone(&core);
                        std::thread::spawn(move || {
                            let _guard = LiveGuard(&live);
                            // macOS accepts a nonblocking listener into a
                            // nonblocking stream; make it blocking again.
                            let _ = stream.set_nonblocking(false);
                            serve_connection(stream, max_line_bytes, read_timeout_secs, &core);
                        });
                    }
                    Err(_) => {
                        std::thread::sleep(Duration::from_millis(ACCEPT_POLL_MS));
                    }
                }
            }
        });
        Running {
            handle: Some(handle),
            socket_path,
            stop,
        }
    }
}

/// Decrements the live-connection counter on drop, even if the connection
/// thread panics.
struct LiveGuard<'a>(&'a AtomicUsize);

impl Drop for LiveGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// One line in, one line out, then close. Reads at most
/// `max_line_bytes + 1` bytes so an over-long line is detected without
/// buffering an unbounded line. One total deadline covers the whole read: a
/// slow-drip client gets the read_timeout refusal, not an open thread.
fn serve_connection(
    mut stream: std::os::unix::net::UnixStream,
    max_line_bytes: usize,
    read_timeout_secs: u64,
    core: &Core,
) {
    use std::io::{BufRead, BufReader, Read, Write};
    let deadline = std::time::Instant::now() + Duration::from_secs(read_timeout_secs);
    let remaining = || {
        deadline
            .saturating_duration_since(std::time::Instant::now())
            .max(Duration::from_millis(1))
    };
    if stream.set_read_timeout(Some(remaining())).is_err() {
        return;
    }
    let mut line = Vec::new();
    let reader = BufReader::new(match stream.try_clone() {
        Ok(clone) => clone,
        Err(_) => return,
    });
    let mut capped = reader.take((max_line_bytes + 1) as u64);
    let mut timed_out = false;
    loop {
        if let Err(err) = stream.set_read_timeout(Some(remaining())) {
            let _ = err;
            return;
        }
        match capped.fill_buf() {
            Ok([]) => break,
            Ok(available) => {
                if let Some(newline) = available.iter().position(|b| *b == b'\n') {
                    line.extend_from_slice(&available[..=newline]);
                    capped.consume(newline + 1);
                    break;
                }
                line.extend_from_slice(available);
                let len = available.len();
                capped.consume(len);
            }
            Err(ref e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                timed_out = true;
                break;
            }
            Err(_) => return,
        }
    }
    let outcome = if timed_out {
        Err(SignerError::ReadTimeout)
    } else if line.len() > max_line_bytes {
        Err(SignerError::LineTooLong)
    } else {
        Ok(core.handle_line(&line))
    };
    let reply = match outcome {
        Ok(reply) => reply,
        Err(err) => {
            log_refusal(core.log.as_ref(), &err);
            error_json(&err)
        }
    };
    let _ = stream.write_all(reply.as_bytes());
    let _ = stream.write_all(b"\n");
    let _ = stream.flush();
}

impl Running {
    pub fn stop(self) {
        self.stop.store(true, Ordering::SeqCst);
        // The accept loop polls with a 20 ms sleep, so it notices the flag
        // without a self-connect. Join the accept thread and clean up.
        if let Some(handle) = self.handle {
            let _ = handle.join();
        }
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

/// Serialises an `Info` reply as the server would.
pub(crate) fn info_json(info: &Info) -> serde_json::Value {
    json!({
        "ok": true,
        "principal": info.principal,
        "version": info.version,
        "days_left": info.days_left,
        "renewal_due": info.renewal_due,
    })
}
