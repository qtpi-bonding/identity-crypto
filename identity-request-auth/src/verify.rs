use crate::nonce::Insert;
use crate::{AuthError, ClockTolerance, LookupError, NonceCache, NonceCaps, TrustedDevices};
use identity_crypto::{
    pb, verify_signed_message_trusted_devices, AuthorDevices, PrincipalId, PublicKey, Timestamp,
    When,
};
use std::sync::Mutex;

/// The largest request body accepted, in bytes (4 MiB). Checked before any
/// signature work.
pub const MAX_BODY_BYTES: usize = 4 * 1024 * 1024;

/// The caller of an accepted request. Layers put it in request extensions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedCaller {
    principal: PrincipalId,
    device: PublicKey,
    session_not_after: i64,
}

impl VerifiedCaller {
    pub fn principal(&self) -> &PrincipalId {
        &self.principal
    }

    pub fn device(&self) -> &PublicKey {
        &self.device
    }

    /// The end of the session certificate's window. A long-lived stream may
    /// end here; the caller decides.
    pub fn session_not_after(&self) -> i64 {
        self.session_not_after
    }
}

/// Checks every signed request a service receives. Owns the trusted-device
/// lookup, the clock tolerance and the replay cache, so the cache is shared
/// by all requests handled through one verifier.
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

    /// Accepts a request when, in order: the body is within [`MAX_BODY_BYTES`];
    /// the audience and body type match; the nonce is 16 bytes; `received_body`
    /// equals the signed body; the signer is a trusted device of its principal
    /// (`Unknown` is refused, `Unavailable` is not); the signature verifies
    /// under identity-crypto's 30 s skew; `issued_at` is within this verifier's
    /// tolerance; and the nonce is fresh. `now` is the verifier's clock.
    pub async fn open_signed_request(
        &self,
        signed: &pb::SignedMessage,
        expected_audience: &str,
        expected_body_type: &str,
        received_body: &[u8],
        now: i64,
    ) -> Result<VerifiedCaller, AuthError> {
        if received_body.len() > MAX_BODY_BYTES {
            return Err(AuthError::BodyTooLarge {
                len: received_body.len(),
                max: MAX_BODY_BYTES,
            });
        }
        if signed.audience != expected_audience {
            return Err(AuthError::Audience);
        }
        if signed.body_type != expected_body_type {
            return Err(AuthError::BodyType);
        }
        if signed.nonce.len() != 16 {
            return Err(AuthError::NonceLength(signed.nonce.len()));
        }
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

        let verified = verify_signed_message_trusted_devices(
            signed,
            expected_audience,
            AuthorDevices {
                author_genesis: &genesis,
                devices: &devices,
            },
            When::Live { now },
        )
        .map_err(map_verify)?;

        if (now - verified.issued_at()).abs() > self.tolerance.seconds() {
            return Err(AuthError::Skew);
        }

        // Only the cache is touched after the last await, so no guard is held across one.
        let outcome = self
            .nonces
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(
                verified.session_key(),
                verified.nonce(),
                verified.issued_at(),
                now,
            );
        match outcome {
            Insert::Fresh => {}
            Insert::Replayed => return Err(AuthError::Replayed),
            Insert::Busy => return Err(AuthError::Busy),
        }

        Ok(VerifiedCaller {
            principal: PrincipalId::from_genesis(genesis),
            device: verified.device().clone(),
            session_not_after: verified.session_not_after(),
        })
    }
}

/// The principal a message claims, read before any check. The verifier then
/// requires it to match the session certificate it signs under.
fn claimed_genesis(signed: &pb::SignedMessage) -> Result<PublicKey, AuthError> {
    let chain = signed
        .signer
        .as_ref()
        .and_then(|s| s.chain.as_ref())
        .ok_or(AuthError::Malformed("signer chain"))?;
    let session = match chain {
        pb::signer_chain::Chain::SelfRooted(s) => s
            .session
            .as_ref()
            .ok_or(AuthError::Malformed("session certificate"))?,
        _ => return Err(AuthError::Malformed("signer chain is not self-rooted")),
    };
    let genesis = session
        .principal_genesis
        .as_ref()
        .ok_or(AuthError::Malformed("principal genesis"))?;
    PublicKey::try_from(genesis).map_err(|_| AuthError::Malformed("principal genesis"))
}

/// identity-crypto's skew failure is this crate's `Skew`; a device that is not
/// bound to the principal is an unknown author.
fn map_verify(err: identity_crypto::Error) -> AuthError {
    match err {
        identity_crypto::Error::Skew => AuthError::Skew,
        identity_crypto::Error::NotBound => AuthError::UnknownAuthor,
        other => AuthError::Verify(other),
    }
}
