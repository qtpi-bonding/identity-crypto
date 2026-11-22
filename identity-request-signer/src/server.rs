//! The unix-socket server: one JSON request line in, one JSON response line out.

use crate::config::Config;
use crate::error::SignerError;
use crate::keys::DeviceState;
use crate::signing::{Info, SignParams, Signing};
use identity_request_auth::Clock;
use serde_json::json;
use std::path::{Path, PathBuf};
use std::sync::Arc;

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
        let _ = (ctx, request);
        unimplemented!()
    }
}

pub struct Server {
    config: Config,
    _device: Arc<DeviceState>,
    _signing: Signing,
    ops: Vec<Box<dyn Op>>,
}

pub struct BoundServer {
    _listener: std::os::unix::net::UnixListener,
    _socket_path: PathBuf,
    _max_line_bytes: usize,
    _read_timeout_secs: u64,
    _log: Arc<dyn Fn(&str) + Send + Sync>,
}

pub struct Running {
    _handle: std::thread::JoinHandle<()>,
}

impl Server {
    pub fn new(
        config: Config,
        clock: Arc<dyn Clock>,
        log: Arc<dyn Fn(&str) + Send + Sync>,
    ) -> Result<Server, SignerError> {
        config.validate()?;
        let _ = (clock, log);
        Ok(Server {
            config,
            _device: unimplemented!(),
            _signing: unimplemented!(),
            ops: vec![Box::new(SignRequestOp::new())],
        })
    }

    pub fn register_op(&mut self, op: Box<dyn Op>) -> Result<(), SignerError> {
        if op.name() == "info" || self.ops.iter().any(|existing| existing.name() == op.name()) {
            return Err(SignerError::ConfigInvalid(String::from(
                "an op with this name is already registered",
            )));
        }
        self.ops.push(op);
        Ok(())
    }

    pub fn handle_line(&self, line: &[u8]) -> String {
        let _ = line;
        unimplemented!()
    }

    pub fn bind(self) -> Result<BoundServer, SignerError> {
        unimplemented!()
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
    let _ = (socket, uid);
    unimplemented!()
}

impl BoundServer {
    pub fn socket_path(&self) -> &Path {
        &self._socket_path
    }

    pub fn spawn(self) -> Running {
        Running {
            _handle: unimplemented!(),
        }
    }
}

impl Running {
    pub fn stop(self) {
        unimplemented!()
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
