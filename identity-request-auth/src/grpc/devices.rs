use identity_crypto::{PublicKey, Timestamp};

/// Why a trusted-device lookup failed. The two cases map to different answers:
/// `Unknown` is an authentication failure, `Unavailable` is a service outage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LookupError {
    #[error("no trusted devices for this principal")]
    Unknown,
    #[error("the trusted-device lookup is unavailable")]
    Unavailable,
}

/// The device keys the service trusts for a principal, read at each request.
///
/// # Implementing this
///
/// The lookup runs for every signed request, *before* the signature is
/// checked: the signer's principal is only a claim at that point. An
/// unauthenticated caller can therefore make the service look up any genesis
/// key it likes, so an implementation that goes to a database or a remote
/// registry must protect it:
///
/// * **Cache negative lookups.** Remember an [`LookupError::Unknown`] answer
///   (for a short time) so a flood of requests for unknown principals costs one
///   backing read, not one per request.
/// * **Never cache [`LookupError::Unavailable`].** It says the backing store
///   could not be reached, not that the principal has no devices. Caching it
///   would turn a short outage into rejections that outlive the recovery. Return
///   it every time the store fails, and let the next request try again.
/// * **May rate-limit** lookups (per caller or overall) and answer
///   [`LookupError::Unavailable`] when the limit is hit, which the layer reports
///   as a service error rather than an authentication failure.
///
/// Positive answers may be cached too; revocation then takes effect when the
/// cache entry expires, so keep the TTL short.
#[async_trait::async_trait]
pub trait TrustedDevices: Send + Sync {
    async fn devices_for(
        &self,
        genesis: &PublicKey,
        at: Timestamp,
    ) -> Result<Vec<PublicKey>, LookupError>;
}

/// A shared table is a table: lets a service keep one lookup and hand clones to
/// its verifiers.
#[async_trait::async_trait]
impl<T: TrustedDevices + ?Sized> TrustedDevices for std::sync::Arc<T> {
    async fn devices_for(
        &self,
        genesis: &PublicKey,
        at: Timestamp,
    ) -> Result<Vec<PublicKey>, LookupError> {
        (**self).devices_for(genesis, at).await
    }
}
