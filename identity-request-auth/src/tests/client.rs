//! The `client` feature: `SignedClient::from_identity_dir` against an in-process
//! tonic server behind `RequestAuthLayer`, and `endpoint_defaults`.

use crate::grpc::{
    caller, endpoint_defaults, AudienceSource, ChannelError, RequestAuthLayer, SignRequests,
    SignedChannel, SignedClient, Verifier, CONNECT_TIMEOUT, KEEPALIVE_INTERVAL, KEEPALIVE_TIMEOUT,
};
use crate::testkit::{FakeClock, StaticDevices};
use crate::{Clock, ClockTolerance, NonceCaps};
use identity_crypto::{signing_public, PrincipalId};
use identity_keyfile::testkit::TempIdentityDir;
use identity_keyfile::ROOT_FILE;
use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::{mpsc, Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;
use tonic::body::Body;
use tonic::codec::ProstCodec;
use tonic::server::{Grpc, NamedService, UnaryService};
use tonic::transport::{Channel, Server};
use tonic::{Request, Response, Status};
use tower::Service;

const T0: i64 = 1_800_000_000;
const SERVER: &str = "srv-1";
const LIST: &str = "/acme.v1.Inventory/ListItems";
const DISCOVER: &str = "/acme.v1.Inventory/Discover";

#[derive(Clone, PartialEq, prost::Message)]
struct Msg {
    #[prost(string, tag = "1")]
    text: String,
}

fn body_type_of(path: &str) -> Option<&'static str> {
    match path {
        LIST => Some("type.googleapis.com/acme.v1.Msg"),
        _ => None,
    }
}

struct Echo {
    callers: Arc<Mutex<mpsc::Sender<PrincipalId>>>,
}

impl UnaryService<Msg> for Echo {
    type Response = Msg;
    type Future = std::future::Ready<Result<Response<Msg>, Status>>;
    fn call(&mut self, request: Request<Msg>) -> Self::Future {
        std::future::ready(caller(&request).map(|c| {
            let _ = self
                .callers
                .lock()
                .expect("lock")
                .send(c.principal().clone());
            Response::new(Msg { text: "ok".into() })
        }))
    }
}

struct Discover;

impl UnaryService<Msg> for Discover {
    type Response = Msg;
    type Future = std::future::Ready<Result<Response<Msg>, Status>>;
    fn call(&mut self, _request: Request<Msg>) -> Self::Future {
        std::future::ready(Ok(Response::new(Msg {
            text: SERVER.into(),
        })))
    }
}

#[derive(Clone)]
struct Inventory {
    callers: Arc<Mutex<mpsc::Sender<PrincipalId>>>,
}

impl NamedService for Inventory {
    const NAME: &'static str = "acme.v1.Inventory";
}

impl Service<http::Request<Body>> for Inventory {
    type Response = http::Response<Body>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Infallible>> + Send>>;
    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        Poll::Ready(Ok(()))
    }
    fn call(&mut self, req: http::Request<Body>) -> Self::Future {
        let callers = self.callers.clone();
        Box::pin(async move {
            let mut grpc = Grpc::new(ProstCodec::<Msg, Msg>::default());
            Ok(match req.uri().path() {
                DISCOVER => grpc.unary(Discover, req).await,
                _ => grpc.unary(Echo { callers }, req).await,
            })
        })
    }
}

/// A server on a local port; yields its address and the principals its handler saw.
async fn serve(
    devices: Arc<StaticDevices>,
    clock: Arc<dyn Clock>,
) -> (std::net::SocketAddr, mpsc::Receiver<PrincipalId>) {
    let verifier = Arc::new(Verifier::new(
        devices,
        ClockTolerance::default(),
        NonceCaps::default(),
    ));
    let layer = RequestAuthLayer::new(
        verifier,
        clock,
        SERVER,
        body_type_of,
        |path: &str| path == DISCOVER,
        crate::grpc::default_reject,
    );
    let (tx, rx) = mpsc::channel();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let svc = Inventory {
        callers: Arc::new(Mutex::new(tx)),
    };
    tokio::spawn(async move {
        Server::builder()
            .layer(layer)
            .add_service(svc)
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
    });
    (addr, rx)
}

fn sign_layer(signer: Arc<crate::RequestSigner>, id: String) -> SignRequests {
    SignRequests::new(signer, id, body_type_of).pass_through(|p| p == DISCOVER)
}

#[allow(clippy::result_large_err)]
async fn call(channel: &mut SignedChannel, path: &'static str) -> Result<Response<Msg>, Status> {
    let mut grpc = tonic::client::Grpc::new(channel.clone());
    grpc.ready()
        .await
        .map_err(|e| Status::unavailable(e.to_string()))?;
    grpc.unary(
        Request::new(Msg { text: "hi".into() }),
        http::uri::PathAndQuery::from_static(path),
        ProstCodec::<Msg, Msg>::default(),
    )
    .await
}

fn endpoint(addr: std::net::SocketAddr) -> tonic::transport::Endpoint {
    endpoint_defaults(format!("http://{addr}")).expect("endpoint")
}

#[tokio::test]
async fn signed_channel_audience_fixed_and_discover() {
    let clock = FakeClock::new(T0);
    let dir = TempIdentityDir::new(T0, 3600);
    // A device-only directory: the root key is gone.
    std::fs::remove_file(dir.path().join(ROOT_FILE)).expect("remove root");
    let keys = identity_keyfile::DeviceKeys::load(dir.path()).expect("device keys");
    let principal = keys.principal_id.clone();
    let devices = Arc::new(StaticDevices::new());
    devices.trust(principal.genesis(), &signing_public(&keys.device));
    let dyn_clock: Arc<dyn Clock> = clock.clone();
    let (addr, seen) = serve(devices, dyn_clock.clone()).await;

    // Fixed.
    let mut channel = SignedClient::<Channel>::from_identity_dir(
        dir.path(),
        endpoint(addr),
        AudienceSource::Fixed(SERVER.into()),
        dyn_clock.clone(),
        sign_layer,
    )
    .await
    .unwrap_or_else(|e| panic!("fixed: {e}"));
    call(&mut channel, LIST).await.expect("signed call");
    assert_eq!(
        seen.recv_timeout(Duration::from_secs(5)).expect("handler"),
        principal
    );
    assert_eq!(
        channel.principal(),
        Some(&principal),
        "the getter returns the identity directory's principal"
    );

    // Discover: runs on the unsigned channel.
    let discover: crate::grpc::DiscoverAudience = Arc::new(|channel: Channel| {
        Box::pin(async move {
            let mut grpc = tonic::client::Grpc::new(channel);
            grpc.ready()
                .await
                .map_err(|e| Status::unavailable(e.to_string()))?;
            let reply: Response<Msg> = grpc
                .unary(
                    Request::new(Msg::default()),
                    http::uri::PathAndQuery::from_static(DISCOVER),
                    ProstCodec::<Msg, Msg>::default(),
                )
                .await?;
            Ok(reply.into_inner().text)
        })
    });
    let mut channel = SignedClient::<Channel>::from_identity_dir(
        dir.path(),
        endpoint(addr),
        AudienceSource::Discover(discover),
        dyn_clock.clone(),
        sign_layer,
    )
    .await
    .unwrap_or_else(|e| panic!("discover: {e}"));
    call(&mut channel, LIST).await.expect("signed call");
    assert_eq!(
        seen.recv_timeout(Duration::from_secs(5)).expect("handler"),
        principal
    );

    // Discover failing.
    let failing: crate::grpc::DiscoverAudience =
        Arc::new(|_| Box::pin(async { Err(Status::unavailable("no discovery")) }));
    let result = SignedClient::<Channel>::from_identity_dir(
        dir.path(),
        endpoint(addr),
        AudienceSource::Discover(failing),
        dyn_clock.clone(),
        sign_layer,
    )
    .await;
    assert!(matches!(result, Err(ChannelError::Audience(_))));

    // Missing directory.
    let missing = dir.path().join("does-not-exist");
    let result = SignedClient::<Channel>::from_identity_dir(
        &missing,
        endpoint(addr),
        AudienceSource::Fixed(SERVER.into()),
        dyn_clock,
        sign_layer,
    )
    .await;
    assert!(matches!(result, Err(ChannelError::Identity(_))));
}

#[test]
fn endpoint_defaults_sets_timeouts() {
    assert_eq!(CONNECT_TIMEOUT, Duration::from_secs(10));
    assert_eq!(KEEPALIVE_INTERVAL, Duration::from_secs(20));
    assert_eq!(KEEPALIVE_TIMEOUT, Duration::from_secs(10));
    endpoint_defaults("http://127.0.0.1:1").expect("valid url");
    endpoint_defaults(String::from("http://127.0.0.1:1")).expect("owned string");
    assert!(endpoint_defaults("not a uri with spaces").is_err());
    // tonic exposes no getters for the timeouts on `Endpoint` and its Debug output is opaque;
    // the settings themselves are asserted by reading `endpoint_defaults` (Task 14 review).
}

#[tokio::test]
async fn a_client_from_the_plain_layer_has_no_principal() {
    use tower::Layer;
    let clock = FakeClock::new(T0);
    let dir = TempIdentityDir::new(T0, 3600);
    let keys = identity_keyfile::DeviceKeys::load(dir.path()).expect("device keys");
    let credentials =
        crate::DeviceCredentials::new(keys.device, keys.principal_id.genesis().clone());
    let dyn_clock: Arc<dyn Clock> = clock;
    let signer = Arc::new(crate::RequestSigner::new(credentials, dyn_clock));
    let client = sign_layer(signer, SERVER.into()).layer(());
    assert!(client.principal().is_none());
}
