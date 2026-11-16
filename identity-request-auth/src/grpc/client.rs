//! Client side of the `tonic` layer: endpoint defaults (`tonic` feature) and a
//! signed channel built from an identity directory (`client` feature).

#[cfg(feature = "client")]
use super::{SignRequests, SignedClient};
#[cfg(feature = "client")]
use crate::{Clock, DeviceCredentials, RequestSigner};
#[cfg(feature = "client")]
use identity_keyfile::DeviceKeys;
#[cfg(feature = "client")]
use std::future::Future;
#[cfg(feature = "client")]
use std::path::Path;
#[cfg(feature = "client")]
use std::pin::Pin;
#[cfg(feature = "client")]
use std::sync::Arc;
use std::time::Duration;
#[cfg(feature = "client")]
use tonic::transport::Channel;
use tonic::transport::Endpoint;
#[cfg(feature = "client")]
use tonic::Status;
#[cfg(feature = "client")]
use tower::Layer;

/// How long a connect may take before it fails.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// How often an idle HTTP/2 connection is pinged, and how often TCP keepalive probes are sent.
pub const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(20);

/// How long a keepalive ping may go unanswered before the connection is dropped.
pub const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);

/// An endpoint for `url` with this crate's connect and keepalive settings.
pub fn endpoint_defaults(url: impl Into<String>) -> Result<Endpoint, tonic::transport::Error> {
    let endpoint = Endpoint::from_shared(url.into())?;
    Ok(endpoint
        .connect_timeout(CONNECT_TIMEOUT)
        .http2_keep_alive_interval(KEEPALIVE_INTERVAL)
        .keep_alive_timeout(KEEPALIVE_TIMEOUT)
        .keep_alive_while_idle(true)
        .tcp_keepalive(Some(KEEPALIVE_INTERVAL)))
}

/// A signed client over a plain tonic channel.
#[cfg(feature = "client")]
pub type SignedChannel = SignedClient<Channel>;

/// Asks the server for its id (the audience), over the unsigned channel.
#[cfg(feature = "client")]
pub type DiscoverAudience = Arc<
    dyn Fn(Channel) -> Pin<Box<dyn Future<Output = Result<String, Status>> + Send>> + Send + Sync,
>;

/// Where the server id (the audience of every signed request) comes from.
#[cfg(feature = "client")]
#[derive(Clone)]
#[non_exhaustive]
pub enum AudienceSource {
    /// A server id the caller already knows.
    Fixed(String),
    /// The server's own id, asked for over the unsigned channel.
    Discover(DiscoverAudience),
}

/// Why a signed channel could not be built.
#[cfg(feature = "client")]
#[derive(Debug, thiserror::Error, coded_error::CodedError)]
#[coded(namespace = "identity.request_auth.channel")]
#[non_exhaustive]
pub enum ChannelError {
    #[error("identity directory: {0}")]
    #[coded(code = "identity", class = Infrastructure, grpc = Internal)]
    Identity(identity_keyfile::KeyfileError),
    #[error("connect: {0}")]
    #[coded(code = "connect", class = Transient, grpc = Unavailable)]
    Connect(tonic::transport::Error),
    #[error("audience discovery: {0}")]
    #[coded(code = "audience", class = Transient, grpc = Unavailable)]
    Audience(Status),
}

#[cfg(feature = "client")]
impl SignedClient<Channel> {
    /// Loads the device keys from `dir` (a device-only directory is fine), connects
    /// `endpoint`, resolves the server id from `audience` (discovery runs on the
    /// unsigned channel), then wraps the channel in `layer(signer, server_id)`.
    // `ChannelError::Audience(Status)` is part of the specified API.
    #[allow(clippy::result_large_err)]
    pub async fn from_identity_dir(
        dir: &Path,
        endpoint: Endpoint,
        audience: AudienceSource,
        clock: Arc<dyn Clock>,
        layer: impl FnOnce(Arc<RequestSigner>, String) -> SignRequests,
    ) -> Result<SignedChannel, ChannelError> {
        let keys = DeviceKeys::load(dir).map_err(ChannelError::Identity)?;
        let genesis = keys.principal_id.genesis().clone();
        let credentials = DeviceCredentials::new(keys.device, genesis);
        let signer = Arc::new(RequestSigner::new(credentials, clock));

        let channel = endpoint.connect().await.map_err(ChannelError::Connect)?;
        let server_id = match audience {
            AudienceSource::Fixed(server_id) => server_id,
            AudienceSource::Discover(discover) => discover(channel.clone())
                .await
                .map_err(ChannelError::Audience)?,
        };
        Ok(layer(signer, server_id).layer(channel))
    }
}
