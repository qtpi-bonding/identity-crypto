#[cfg(not(unix))]
compile_error!("identity-keyfile writes 0600 key files and needs a unix target");

mod keys;
mod error;
mod files;

pub use keys::{device_keys_at, IdentityKeys, DeviceKeys, DevicePublic};
pub use error::KeyfileError;
pub use files::{
    read_delegation, read_duo, read_history, read_principal_id, read_rotations, write_delegation,
    write_duo, write_history, write_principal_id, write_rotations, AGENT_ID_FILE, DELEGATION_FILE,
    DEVICE_FILE, HISTORY_FILE, LOCK_FILE, ROOT_FILE, ROTATIONS_FILE,
};

#[cfg(feature = "testkit")]
pub mod testkit;

use identity_crypto::jwk_duo::{GenerationService, KeyDuo};

/// Generates a fresh key duo (signing and encryption halves) with the
/// `rust_jwk_duo` generator. The result holds private keys: never log it, and
/// store it only through this crate's private-file writers.
pub fn generate() -> KeyDuo {
    GenerationService::generate_key_duo()
}
