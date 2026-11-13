//! Test fixtures: real P-256 keys, a fake clock and a static device table.
//! Compiled for this crate's tests, or for consumers that enable `testkit`.

use crate::{Clock, DeviceCredentials, LookupError, RequestSigner, TrustedDevices};
use identity_crypto::{jwk_duo::SigningKeyPair, PublicKey, Timestamp};
use std::collections::HashMap;
use std::future::Future;
use std::pin::pin;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

/// Drives a future that never waits on I/O (every test future here resolves
/// on its first poll). Avoids a runtime dependency in the core's tests.
pub fn block_on<F: Future>(future: F) -> F::Output {
    let mut cx = Context::from_waker(Waker::noop());
    let mut future = pin!(future);
    loop {
        if let Poll::Ready(value) = future.as_mut().poll(&mut cx) {
            return value;
        }
    }
}

/// A clock the test moves by hand.
#[derive(Debug)]
pub struct FakeClock(AtomicI64);

impl FakeClock {
    pub fn new(now: i64) -> Arc<Self> {
        Arc::new(Self(AtomicI64::new(now)))
    }

    pub fn set(&self, now: i64) {
        self.0.store(now, Ordering::SeqCst);
    }

    pub fn advance(&self, seconds: i64) {
        self.0.fetch_add(seconds, Ordering::SeqCst);
    }
}

impl Clock for FakeClock {
    fn now_unix(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
}

/// A device table the test edits between requests.
#[derive(Default)]
pub struct StaticDevices {
    table: Mutex<HashMap<PublicKey, Vec<PublicKey>>>,
    unavailable: AtomicBool,
}

impl StaticDevices {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn trust(&self, genesis: &PublicKey, device: &PublicKey) {
        let mut table = self.table.lock().unwrap_or_else(|p| p.into_inner());
        let devices = table.entry(genesis.clone()).or_default();
        if !devices.contains(device) {
            devices.push(device.clone());
        }
    }

    pub fn revoke(&self, genesis: &PublicKey, device: &PublicKey) {
        let mut table = self.table.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(devices) = table.get_mut(genesis) {
            devices.retain(|d| d != device);
        }
    }

    pub fn set_unavailable(&self, down: bool) {
        self.unavailable.store(down, Ordering::SeqCst);
    }
}

#[async_trait::async_trait]
impl TrustedDevices for StaticDevices {
    async fn devices_for(
        &self,
        genesis: &PublicKey,
        _at: Timestamp,
    ) -> Result<Vec<PublicKey>, LookupError> {
        if self.unavailable.load(Ordering::SeqCst) {
            return Err(LookupError::Unavailable);
        }
        let table = self.table.lock().unwrap_or_else(|p| p.into_inner());
        match table.get(genesis) {
            Some(devices) if !devices.is_empty() => Ok(devices.clone()),
            _ => Err(LookupError::Unknown),
        }
    }
}

/// A principal's genesis key and one device key.
pub struct TestPrincipal {
    pub genesis: PublicKey,
    device: SigningKeyPair,
}

impl TestPrincipal {
    pub fn new() -> Self {
        Self {
            genesis: PublicKey::from(&SigningKeyPair::generate()),
            device: SigningKeyPair::generate(),
        }
    }

    pub fn device_key(&self) -> PublicKey {
        PublicKey::from(&self.device)
    }

    /// A signer that mints its sessions under this principal's device.
    pub fn signer(self, clock: Arc<dyn Clock>) -> RequestSigner {
        RequestSigner::new(DeviceCredentials::new(self.device, self.genesis), clock)
    }
}

impl Default for TestPrincipal {
    fn default() -> Self {
        Self::new()
    }
}
