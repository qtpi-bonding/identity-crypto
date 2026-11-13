//! The tonic layer, from the spec's Tests section: an allow-listed method passes
//! unsigned; a signed request reaches the handler with its caller; a body that
//! differs from the signed body is refused. Built with `--features tonic`.

use crate::grpc::{RequestAuthLayer, SignRequests, REQUEST_HEADER};
use crate::testkit::{block_on, FakeClock, StaticDevices, TestPrincipal};
use crate::{
    seal_request, AuthError, Clock, ClockTolerance, NonceCaps, RequestSigner, VerifiedCaller,
    Verifier, MAX_BODY_BYTES,
};
use bytes::Bytes;
use http::{Request, Response};
use http_body_util::Full;
use identity_crypto::{pb, PrincipalId, PublicKey};
use prost::Message;
use std::convert::Infallible;
use std::sync::{Arc, Mutex};
use tonic::body::Body;
use tonic::metadata::{MetadataMap, MetadataValue};
use tower::{service_fn, Layer, Service, ServiceExt};

const SERVER: &str = "server-1";
const PATH: &str = "/acme.v1.Inventory/ListItems";
const HEALTH: &str = "/acme.v1.Inventory/Health";
const BODY_TYPE: &str = "type.googleapis.com/acme.v1.ListItemsRequest";
const MESSAGE: &[u8] = b"\x0a\x03abc";
const T0: i64 = 1_800_000_000;

fn body_type_of(path: &str) -> Option<&'static str> {
    match path {
        PATH => Some(BODY_TYPE),
        HEALTH => Some("type.googleapis.com/acme.v1.HealthRequest"),
        _ => None,
    }
}

fn reject(err: AuthError) -> tonic::Status {
    crate::grpc::default_reject(err)
}

/// A gRPC length-prefixed frame around one uncompressed message.
fn framed(message: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8];
    out.extend((message.len() as u32).to_be_bytes());
    out.extend_from_slice(message);
    out
}

fn request(path: &str, body: Vec<u8>) -> Request<Body> {
    Request::builder()
        .uri(path)
        .body(Body::new(Full::new(Bytes::from(body))))
        .expect("a request")
}

fn with_header(req: &mut Request<Body>, signed: &pb::SignedMessage) {
    let mut metadata = MetadataMap::new();
    metadata.insert_bin(
        REQUEST_HEADER,
        MetadataValue::from_bytes(&signed.encode_to_vec()),
    );
    *req.headers_mut() = metadata.into_headers();
}

fn grpc_status(resp: &Response<Body>) -> Option<String> {
    resp.headers()
        .get("grpc-status")
        .map(|v| v.to_str().expect("ascii").to_owned())
}

/// The server side: a verifier over a shared device table, and the layer
/// wrapping a handler that records the verified caller it sees.
struct Server {
    clock: Arc<FakeClock>,
    devices: Arc<StaticDevices>,
    genesis: PublicKey,
    signer: Arc<RequestSigner>,
    seen: Arc<Mutex<Option<PrincipalId>>>,
}

fn server() -> Server {
    let clock = FakeClock::new(T0);
    let principal = TestPrincipal::new();
    let genesis = principal.genesis.clone();
    let devices = Arc::new(StaticDevices::new());
    devices.trust(&genesis, &principal.device_key());
    let signer = Arc::new(principal.signer(clock.clone()));
    Server {
        clock,
        devices,
        genesis,
        signer,
        seen: Arc::new(Mutex::new(None)),
    }
}

impl Server {
    fn layer(&self) -> RequestAuthLayer<Arc<StaticDevices>> {
        let verifier = Arc::new(Verifier::new(
            self.devices.clone(),
            ClockTolerance::default(),
            NonceCaps::default(),
        ));
        let clock: Arc<dyn Clock> = self.clock.clone();
        RequestAuthLayer::new(
            verifier,
            clock,
            SERVER,
            body_type_of,
            |path: &str| path == HEALTH,
            reject,
        )
    }

    /// The handler behind the layer: records the caller and answers OK.
    fn handler(
        &self,
    ) -> impl Service<Request<Body>, Response = Response<Body>, Error = Infallible, Future: Send>
           + Clone
           + Send {
        let seen = self.seen.clone();
        service_fn(move |req: Request<Body>| {
            let seen = seen.clone();
            async move {
                *seen.lock().expect("lock") = req
                    .extensions()
                    .get::<VerifiedCaller>()
                    .map(|c| c.principal().clone());
                Ok::<_, Infallible>(Response::new(Body::default()))
            }
        })
    }

    fn protected(
        &self,
    ) -> impl Service<Request<Body>, Response = Response<Body>, Error = Infallible, Future: Send>
           + Clone
           + Send {
        self.layer().layer(self.handler())
    }
}

#[test]
fn an_allow_listed_method_passes_without_a_signature() {
    let s = server();
    let svc = s.protected();
    let resp = block_on(svc.oneshot(request(HEALTH, framed(b"")))).expect("infallible");
    assert_eq!(resp.status(), 200);
    assert_eq!(grpc_status(&resp), None, "the handler answered");
    assert!(
        s.seen.lock().unwrap().is_none(),
        "an allow-listed call has no caller"
    );
}

#[test]
fn a_signed_request_reaches_the_handler_with_its_caller() {
    let s = server();
    let client = SignRequests::new(s.signer.clone(), SERVER, body_type_of).layer(s.protected());
    let resp = block_on(client.oneshot(request(PATH, framed(MESSAGE)))).expect("infallible");
    assert_eq!(grpc_status(&resp), None, "accepted");
    assert_eq!(
        s.seen.lock().unwrap().clone(),
        Some(PrincipalId::from_genesis(s.genesis.clone()))
    );
}

#[test]
fn an_unsigned_request_to_a_protected_method_is_unauthenticated() {
    let s = server();
    let resp = block_on(s.protected().oneshot(request(PATH, framed(MESSAGE)))).expect("infallible");
    assert_eq!(grpc_status(&resp).as_deref(), Some("16"), "UNAUTHENTICATED");
    assert!(s.seen.lock().unwrap().is_none());
}

#[test]
fn a_body_that_differs_from_the_signed_body_is_refused() {
    let s = server();
    let signed = seal_request(
        &s.signer,
        &crate::audience_for("acme.v1.Inventory", "ListItems", SERVER),
        BODY_TYPE,
        MESSAGE,
    )
    .expect("sealing");
    let mut req = request(PATH, framed(b"\x0a\x03abd"));
    with_header(&mut req, &signed);
    let resp = block_on(s.protected().oneshot(req)).expect("infallible");
    assert_eq!(
        grpc_status(&resp).as_deref(),
        Some("16"),
        "one byte differs: refused"
    );
    assert!(s.seen.lock().unwrap().is_none());
}

#[test]
fn a_lookup_outage_reaches_the_caller_as_unavailable() {
    let s = server();
    s.devices.set_unavailable(true);
    let client = SignRequests::new(s.signer.clone(), SERVER, body_type_of).layer(s.protected());
    let resp = block_on(client.oneshot(request(PATH, framed(MESSAGE)))).expect("infallible");
    assert_eq!(
        grpc_status(&resp).as_deref(),
        Some("14"),
        "UNAVAILABLE, not UNAUTHENTICATED"
    );
}

#[test]
fn a_body_over_the_limit_is_refused_before_it_is_verified() {
    let s = server();
    let big = vec![0u8; MAX_BODY_BYTES + 1];
    let audience = crate::audience_for("acme.v1.Inventory", "ListItems", SERVER);
    let signed = seal_request(&s.signer, &audience, BODY_TYPE, &big).expect("sealing");
    let mut req = request(PATH, framed(&big));
    with_header(&mut req, &signed);
    let resp = block_on(s.protected().oneshot(req)).expect("infallible");
    assert_eq!(
        grpc_status(&resp).as_deref(),
        Some("8"),
        "RESOURCE_EXHAUSTED"
    );
}
