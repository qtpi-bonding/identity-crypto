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
/// Implementations may cache; revocation takes effect when the cache expires.
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
