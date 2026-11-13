use super::devices::{LookupError, TrustedDevices};
use crate::{
    check_request, claimed_genesis, precheck_request, AuthError, ClockTolerance, NonceCache,
    NonceCaps, TrustedDeviceSet, VerifiedCaller,
};
use identity_crypto::{pb, Timestamp};
use std::sync::Mutex;

/// The async verifier the server layer uses: the [`TrustedDevices`] lookup in
/// front of the synchronous core, and the replay cache behind a lock that is
/// never held across an await.
///
/// The core itself ([`crate::open_signed_request`]) knows nothing of async or
/// locks; this type is where this transport pays for them.
pub struct Verifier<K> {
    keys: K,
    tolerance: ClockTolerance,
    nonces: Mutex<NonceCache>,
}

impl<K: TrustedDevices> Verifier<K> {
    pub fn new(keys: K, tolerance: ClockTolerance, caps: NonceCaps) -> Self {
        Self {
            keys,
            tolerance,
            nonces: Mutex::new(NonceCache::new(caps)),
        }
    }

    /// Accepts a request when the core accepts it ([`crate::open_signed_request`])
    /// for the device keys this verifier's [`TrustedDevices`] gives for the
    /// claimed principal. The cheap checks (size, audience, body type,
    /// signature present, nonce length, body equality) run before the lookup,
    /// so a malformed request never costs one.
    pub async fn open_signed_request(
        &self,
        signed: &pb::SignedMessage,
        expected_audience: &str,
        expected_body_type: &str,
        received_body: &[u8],
        now: i64,
    ) -> Result<VerifiedCaller, AuthError> {
        precheck_request(signed, expected_audience, expected_body_type, received_body)?;
        if signed.body != received_body {
            return Err(AuthError::BodyMismatch);
        }

        let genesis = claimed_genesis(signed)?;
        let devices = self
            .keys
            .devices_for(
                &genesis,
                Timestamp {
                    seconds: now,
                    nanos: 0,
                },
            )
            .await
            .map_err(|e| match e {
                LookupError::Unknown => AuthError::UnknownAuthor,
                LookupError::Unavailable => AuthError::LookupUnavailable,
            })?;
        let set = TrustedDeviceSet::new(genesis, devices);
        let checked = check_request(
            signed,
            expected_audience,
            expected_body_type,
            received_body,
            &set,
            self.tolerance,
            now,
        )?;

        // Only the cache is touched after the last await, so no guard is held across one.
        let mut nonces = self.nonces.lock().unwrap_or_else(|p| p.into_inner());
        checked.accept(&mut nonces, now)
    }
}
