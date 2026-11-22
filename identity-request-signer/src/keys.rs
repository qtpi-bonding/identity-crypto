//! Device key state: load, principal checks, delegation freshness.

use crate::error::SignerError;
use identity_request_auth::{Clock, DeviceCredentials, RequestSigner};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

/// Days before expiry at which renewal is considered due.
pub const RENEWAL_MARGIN_DAYS: i64 = 21;

/// The only code the keys module ever logs; no paths, no file content.
const KEYS_CODE: &str = "identity.request_signer.keys";

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
    device_signing: identity_crypto::PublicKey,
    dir: PathBuf,
    clock: Arc<dyn Clock>,
    log: Arc<dyn Fn(&str) + Send + Sync>,
    delegation: RwLock<DelegationState>,
    /// The last (renewal_due, days_left) pair logged, so status() logs the
    /// warning again only when it changes.
    logged_renewal: RwLock<Option<(bool, i64)>>,
}

/// The tracked delegation and a fingerprint of the file it came from, so
/// `refresh` re-reads only when the file changed.
struct DelegationState {
    not_after: i64,
    delegation: identity_crypto::pb::KeyDelegation,
    fingerprint: Option<u64>,
}

/// A change fingerprint of the delegation file: a hash of its bytes. `None`
/// when the file cannot be read.
fn file_fingerprint(dir: &Path) -> Option<u64> {
    let bytes = std::fs::read(dir.join(identity_keyfile::DELEGATION_FILE)).ok()?;
    Some(hash_bytes(&bytes))
}

fn hash_bytes(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x1000_0000_01b3);
    }
    hash
}

/// One coded log line on a delegation read or parse failure: the code only.
fn delegation_unreadable(log: &dyn Fn(&str)) {
    log(&format!(
        "{KEYS_CODE}: the delegation file could not be read or parsed"
    ));
}

impl DeviceState {
    pub fn load(
        dir: &Path,
        expected_principal: &str,
        refuse_principals: &[String],
        clock: Arc<dyn Clock>,
        log: Arc<dyn Fn(&str) + Send + Sync>,
    ) -> Result<DeviceState, SignerError> {
        // Device-only keys: the root and rotation files are never opened.
        let keys = identity_keyfile::DeviceKeys::load(dir).map_err(|_| {
            // Fixed message only: the underlying error could echo paths.
            SignerError::Keys("the device keys could not be loaded".to_string())
        })?;
        let genesis = keys.principal_id.genesis().clone();
        let device_signing = identity_crypto::signing_public(&keys.device);
        Self::refuse_root_key(&device_signing, &genesis)?;
        let principal = keys.principal_id.to_string();
        if principal != expected_principal {
            return Err(SignerError::PrincipalMismatch);
        }
        if refuse_principals.contains(&principal) {
            return Err(SignerError::PrincipalRefused);
        }
        let credentials = DeviceCredentials::new(keys.device, genesis);
        let signer = RequestSigner::new(credentials, clock.clone());
        let fingerprint = file_fingerprint(dir);
        Ok(DeviceState {
            inner: DeviceStateInner {
                signer,
                principal,
                device_signing,
                dir: dir.to_path_buf(),
                clock,
                log,
                delegation: RwLock::new(DelegationState {
                    not_after: keys.delegation.not_after_unix_seconds,
                    delegation: keys.delegation.clone(),
                    fingerprint,
                }),
                logged_renewal: RwLock::new(None),
            },
        })
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

    /// Re-reads the delegation file when it changed. On any read or parse
    /// failure, or a delegation naming a different device, the old state is
    /// kept and one coded line is logged. The signer never renews.
    pub fn refresh(&self) {
        let Some(fingerprint) = file_fingerprint(&self.inner.dir) else {
            delegation_unreadable(self.inner.log.as_ref());
            return;
        };
        if Some(fingerprint)
            == self
                .inner
                .delegation
                .read()
                .unwrap_or_else(|p| p.into_inner())
                .fingerprint
        {
            return;
        }
        let delegation = match identity_keyfile::read_delegation(&self.inner.dir) {
            Ok(delegation) => delegation,
            Err(_) => {
                delegation_unreadable(self.inner.log.as_ref());
                return;
            }
        };
        let device = Some(identity_crypto::pb::PublicKey::from(
            &self.inner.device_signing,
        ));
        if delegation.delegated != device {
            delegation_unreadable(self.inner.log.as_ref());
            return;
        }
        let mut state = self
            .inner
            .delegation
            .write()
            .unwrap_or_else(|p| p.into_inner());
        state.not_after = delegation.not_after_unix_seconds;
        state.delegation = delegation.clone();
        state.fingerprint = Some(fingerprint);
    }

    /// The current delegation, re-reading the file first so a renewed
    /// delegation is returned without a restart.
    pub fn delegation(&self) -> identity_crypto::pb::KeyDelegation {
        self.refresh();
        self.inner
            .delegation
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .delegation
            .clone()
    }

    pub fn status(&self) -> DelegationStatus {
        self.refresh();
        let now = self.inner.clock.now().seconds;
        let not_after = self
            .inner
            .delegation
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .not_after;
        let days_left = (not_after - now).div_euclid(86400);
        let renewal_due = not_after - now <= RENEWAL_MARGIN_DAYS * 86400;
        let mut logged = self
            .inner
            .logged_renewal
            .write()
            .unwrap_or_else(|p| p.into_inner());
        if renewal_due && *logged != Some((renewal_due, days_left)) {
            (self.inner.log)(&format!("{KEYS_CODE}: renewal_due, days_left={days_left}"));
            *logged = Some((renewal_due, days_left));
        }
        DelegationStatus {
            not_after,
            days_left,
            renewal_due,
        }
    }

    pub fn ensure_valid(&self) -> Result<(), SignerError> {
        self.refresh();
        let now = self.inner.clock.now().seconds;
        let not_after = self
            .inner
            .delegation
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .not_after;
        if now > not_after {
            Err(SignerError::Expired)
        } else {
            Ok(())
        }
    }

    pub fn request_signer(&self) -> &RequestSigner {
        &self.inner.signer
    }
}
