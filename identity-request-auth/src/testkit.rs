//! Test fixtures: real P-256 keys, a fake clock and a static device table.
//! Compiled for this crate's tests, or for consumers that enable `testkit`.

#[cfg(feature = "tonic")]
use crate::{live_devices, KeyRecord, LookupError};
use crate::{Clock, DeviceCredentials, RequestSigner};
use identity_crypto::{jwk_duo::SigningKeyPair, PublicKey, Timestamp};
#[cfg(feature = "tonic")]
use std::collections::HashMap;
use std::future::Future;
use std::pin::pin;
#[cfg(feature = "tonic")]
use std::sync::atomic::Ordering;
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
pub struct FakeClock(Mutex<Timestamp>);

impl FakeClock {
    pub fn new(now: i64) -> Arc<Self> {
        Arc::new(Self(Mutex::new(Timestamp {
            seconds: now,
            nanos: 0,
        })))
    }

    pub fn set(&self, now: i64) {
        self.set_at(Timestamp {
            seconds: now,
            nanos: 0,
        });
    }

    pub fn set_at(&self, at: Timestamp) {
        *self.0.lock().unwrap_or_else(|p| p.into_inner()) = at;
    }

    pub fn advance(&self, seconds: i64) {
        let mut now = self.0.lock().unwrap_or_else(|p| p.into_inner());
        *now = Timestamp {
            seconds: now.seconds + seconds,
            nanos: 0,
        };
    }
}

impl Clock for FakeClock {
    fn now(&self) -> Timestamp {
        *self.0.lock().unwrap_or_else(|p| p.into_inner())
    }
}

/// A device table the test edits between requests (needs the `tonic` feature,
/// where the async `TrustedDevices` lives).
#[cfg(feature = "tonic")]
#[derive(Default)]
pub struct StaticDevices {
    table: std::sync::Mutex<HashMap<PublicKey, Vec<PublicKey>>>,
    unavailable: std::sync::atomic::AtomicBool,
}

#[cfg(feature = "tonic")]
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

#[cfg(feature = "tonic")]
#[async_trait::async_trait]
impl crate::grpc::TrustedDevices for StaticDevices {
    async fn devices_for(
        &self,
        genesis: &PublicKey,
        _at: identity_crypto::Timestamp,
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

/// A registry of key records the test edits between requests, read through
/// [`live_devices`] so liveness is decided exactly as in production.
#[cfg(feature = "tonic")]
#[derive(Default)]
pub struct RecordDevices {
    table: Mutex<HashMap<PublicKey, Vec<KeyRecord>>>,
}

#[cfg(feature = "tonic")]
impl RecordDevices {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn put(&self, genesis: &PublicKey, records: Vec<KeyRecord>) {
        let mut table = self.table.lock().unwrap_or_else(|p| p.into_inner());
        table.insert(genesis.clone(), records);
    }
}

#[cfg(feature = "tonic")]
#[async_trait::async_trait]
impl crate::grpc::TrustedDevices for RecordDevices {
    async fn devices_for(
        &self,
        genesis: &PublicKey,
        at: Timestamp,
    ) -> Result<Vec<PublicKey>, LookupError> {
        let table = self.table.lock().unwrap_or_else(|p| p.into_inner());
        match table.get(genesis) {
            Some(records) => live_devices(records, at),
            None => Err(LookupError::Unknown),
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
