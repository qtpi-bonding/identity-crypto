//! Device key state: load, principal checks, delegation freshness.

use crate::error::SignerError;
use identity_request_auth::{Clock, DeviceCredentials, RequestSigner};
use std::path::Path;
use std::sync::Arc;

/// Days before expiry at which renewal is considered due.
pub const RENEWAL_MARGIN_DAYS: i64 = 21;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegationStatus {
    pub not_after: i64,
    pub days_left: i64,
    pub renewal_due: bool,
}

/// The loaded device keys, a request signer built on them, and the delegation.
pub struct DeviceState {
    inner: DeviceStateInner,
}

struct DeviceStateInner {
    signer: RequestSigner,
    principal: String,
    delegation_not_after: i64,
}

impl DeviceState {
    pub fn load(
        dir: &Path,
        expected_principal: &str,
        refuse_principals: &[String],
        clock: Arc<dyn Clock>,
        log: Arc<dyn Fn(&str) + Send + Sync>,
    ) -> Result<DeviceState, SignerError> {
        let _ = (dir, expected_principal, refuse_principals, clock, log);
        unimplemented!()
    }

    /// Refuses a device key that is, by value, the principal's root (genesis) key.
    pub fn refuse_root_key(
        device: &identity_crypto::PublicKey,
        genesis: &identity_crypto::PublicKey,
    ) -> Result<(), SignerError> {
        if device == genesis {
            Err(SignerError::RootKey)
        } else {
            Ok(())
        }
    }

    pub fn principal(&self) -> String {
        self.inner.principal.clone()
    }

    pub fn refresh(&self) {
        unimplemented!()
    }

    pub fn status(&self) -> DelegationStatus {
        unimplemented!()
    }

    pub fn ensure_valid(&self) -> Result<(), SignerError> {
        unimplemented!()
    }

    pub fn request_signer(&self) -> &RequestSigner {
        &self.inner.signer
    }
}
