//! Per-request signing and verification over `identity_crypto`.
//!
//! Each request carries one `identity_crypto` `SignedMessage` (`signed-message.v1`)
//! signed by a short-lived session key. The signature covers the audience
//! (`"<service>:<method>@<server id>"`), the body type, the exact request bytes
//! and a 16-byte nonce. A replay cache refuses a nonce seen twice inside the
//! skew window.
//!
//! The crate has two layers:
//!
//! * a transport-free core (this module and its submodules): [`NonceCache`],
//!   [`RequestSigner`] / [`seal_request`], and [`Verifier`]. No tonic, tower
//!   or tokio.
//! * the `tonic` feature ([`grpc`]), built only from the core.
//!
//! Nothing here names a service. Callers pass their audience strings and
//! their body types.

mod audience;
mod clock;
mod devices;
mod error;
mod nonce;
mod sign;
mod verify;

#[cfg(feature = "tonic")]
pub mod grpc;

#[cfg(any(test, feature = "testkit"))]
pub mod testkit;

#[cfg(test)]
mod tests;

pub use audience::{audience_for, split_path};
pub use clock::{Clock, ClockTolerance, SystemClock};
pub use devices::{LookupError, TrustedDevices};
pub use error::AuthError;
pub use nonce::{Insert, NonceCache, NonceCaps, PURGE_GRACE};
pub use sign::{seal_request, CredentialSource, DeviceCredentials, RequestSigner, SESSION_SECONDS};
pub use verify::{VerifiedCaller, Verifier, MAX_BODY_BYTES};
