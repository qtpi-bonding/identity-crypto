//! A local signing helper: holds a device key and signs requests over a unix
//! socket. A plain signer: the caller says what to sign; the signer signs it.

pub mod config;
pub mod error;
pub mod keys;
pub mod server;
pub mod signing;

pub use config::read_private_toml;
pub use config::Config;
pub use error::SignerError;
pub use keys::{DelegationStatus, DeviceState, RENEWAL_MARGIN_DAYS};
pub use server::{
    check_not_root, prepare_socket_dir, BoundServer, Op, OpContext, Running, Server, SignRequestOp,
};
pub use signing::{Info, SignOutcome, SignParams, Signing};
