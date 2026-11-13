//! The tonic layer, from the spec's Tests section: an allow-listed method passes
//! unsigned; a signed request reaches the handler with its caller; a body that
//! differs from the signed body is refused. Built with `--features tonic`.

use crate::grpc::{MethodKind, RequestAuthLayer, SignRequests, Verifier, REQUEST_HEADER};
use crate::testkit::{block_on, FakeClock, StaticDevices, TestPrincipal};
use crate::{
    audience_for, seal_request, Clock, ClockTolerance, NonceCaps, RequestSigner, VerifiedCaller,
    MAX_BODY_BYTES, SESSION_SECONDS,
};
use bytes::Bytes;
use http::{Request, Response};
use http_body::{Body as HttpBody, Frame};
use http_body_util::{BodyExt, Full};
use identity_crypto::{pb, PrincipalId, PublicKey};
use prost::Message;
use std::collections::VecDeque;
use std::convert::Infallible;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use tonic::body::Body;
use tonic::metadata::{MetadataMap, MetadataValue};
use tower::{service_fn, Layer, Service, ServiceExt};

const SERVER: &str = "server-1";
const PATH: &str = "/acme.v1.Inventory/ListItems";
const HEALTH: &str = "/acme.v1.Inventory/Health";
const DELETE: &str = "/acme.v1.Inventory/DeleteItem";
const WATCH: &str = "/acme.v1.Inventory/Watch";
const UPLOAD: &str = "/acme.v1.Inventory/Upload";
const CHAT: &str = "/acme.v1.Inventory/Chat";
const MYSTERY: &str = "/acme.v1.Inventory/Mystery";
/// Declared client-streaming, but with no body type: unregistered.
const GHOST: &str = "/acme.v1.Inventory/Ghost";
const BODY_TYPE: &str = "type.googleapis.com/acme.v1.ListItemsRequest";
const MESSAGE: &[u8] = b"\x0a\x03abc";
const T0: i64 = 1_800_000_000;

fn body_type_of(path: &str) -> Option<&'static str> {
    match path {
        PATH => Some(BODY_TYPE),
        HEALTH => Some("type.googleapis.com/acme.v1.HealthRequest"),
        DELETE => Some("type.googleapis.com/acme.v1.DeleteItemRequest"),
        WATCH => Some("type.googleapis.com/acme.v1.WatchRequest"),
        UPLOAD => Some("type.googleapis.com/acme.v1.UploadRequest"),
        CHAT => Some("type.googleapis.com/acme.v1.ChatRequest"),
        _ => None,
    }
}

fn kind_of(path: &str) -> MethodKind {
    match path {
        WATCH => MethodKind::ServerStreaming,
        UPLOAD => MethodKind::ClientStreaming,
        CHAT => MethodKind::Bidi,
        GHOST => MethodKind::ClientStreaming,
        _ => MethodKind::Unary,
    }
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
/// wrapping a handler that records what it sees.
struct Server {
    clock: Arc<FakeClock>,
    devices: Arc<StaticDevices>,
    genesis: PublicKey,
    signer: Arc<RequestSigner>,
    caps: NonceCaps,
    seen: Arc<Mutex<Option<PrincipalId>>>,
    /// How many requests reached the handler, and the byte length of the last body.
    reached: Arc<Mutex<(u32, usize)>>,
    /// The `Debug` of every refusal the layer made, in order.
    refusals: Arc<Mutex<Vec<String>>>,
    /// What a streaming response yields: the handler's body reads from here.
    stream: Arc<Mutex<VecDeque<Bytes>>>,
}

fn server() -> Server {
    server_with(NonceCaps::default())
}

fn server_with(caps: NonceCaps) -> Server {
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
        caps,
        seen: Arc::new(Mutex::new(None)),
        reached: Arc::new(Mutex::new((0, 0))),
        refusals: Arc::new(Mutex::new(Vec::new())),
        stream: Arc::new(Mutex::new(VecDeque::new())),
    }
}

impl Server {
    fn layer(&self) -> RequestAuthLayer<Arc<StaticDevices>> {
        let verifier = Arc::new(Verifier::new(
            self.devices.clone(),
            ClockTolerance::default(),
            self.caps,
        ));
        let clock: Arc<dyn Clock> = self.clock.clone();
        let refusals = self.refusals.clone();
        RequestAuthLayer::new(
            verifier,
            clock,
            SERVER,
            body_type_of,
            |path: &str| path == HEALTH,
            move |err| {
                refusals.lock().expect("lock").push(format!("{err:?}"));
                crate::grpc::default_reject(err)
            },
        )
        .method_kinds(kind_of)
    }

    fn refusals(&self) -> Vec<String> {
        self.refusals.lock().expect("lock").clone()
    }

    fn handler_calls(&self) -> u32 {
        self.reached.lock().expect("lock").0
    }

    /// The handler behind the layer: records the caller and the body it was
    /// given, and answers OK with the stream queue as the response body.
    fn handler(
        &self,
    ) -> impl Service<Request<Body>, Response = Response<Body>, Error = Infallible, Future: Send>
           + Clone
           + Send {
        let seen = self.seen.clone();
        let reached = self.reached.clone();
        let stream = self.stream.clone();
        service_fn(move |req: Request<Body>| {
            let seen = seen.clone();
            let reached = reached.clone();
            let stream = stream.clone();
            async move {
                *seen.lock().expect("lock") = req
                    .extensions()
                    .get::<VerifiedCaller>()
                    .map(|c| c.principal().clone());
                let body = req.into_body().collect().await.expect("a body").to_bytes();
                let mut reached = reached.lock().expect("lock");
                *reached = (reached.0 + 1, body.len());
                Ok::<_, Infallible>(Response::new(Body::new(Queue(stream))))
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

    /// The client layer over the protected server.
    fn client(
        &self,
    ) -> impl Service<Request<Body>, Response = Response<Body>, Error = Infallible, Future: Send>
           + Clone
           + Send {
        SignRequests::new(self.signer.clone(), SERVER, body_type_of)
            .method_kinds(kind_of)
            .pass_through(|path| path == HEALTH)
            .layer(self.protected())
    }
}

/// A response body that yields what is queued and, when the queue is empty,
/// waits (never ends by itself) until something wakes it.
struct Queue(Arc<Mutex<VecDeque<Bytes>>>);

impl HttpBody for Queue {
    type Data = Bytes;
    type Error = tonic::Status;

    fn poll_frame(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, tonic::Status>>> {
        match self.0.lock().expect("lock").pop_front() {
            Some(data) => Poll::Ready(Some(Ok(Frame::data(data)))),
            None => Poll::Pending,
        }
    }
}

/// A request body that must never be read.
struct Unread;

impl HttpBody for Unread {
    type Data = Bytes;
    type Error = tonic::Status;

    fn poll_frame(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, tonic::Status>>> {
        panic!("the layer read a body it should have refused unread");
    }
}

/// Polls a body once, without a runtime to wake it.
fn poll_once(body: &mut Body) -> Poll<Option<Result<Frame<Bytes>, tonic::Status>>> {
    let mut cx = Context::from_waker(Waker::noop());
    Pin::new(body).poll_frame(&mut cx)
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

// Item 5: the layer refuses what the core refuses, with the cause and the status.

fn sealed_for(s: &Server, path_service: &str, method: &str, server_id: &str) -> pb::SignedMessage {
    seal_request(
        &s.signer,
        &audience_for(path_service, method, server_id),
        BODY_TYPE,
        MESSAGE,
    )
    .expect("sealing")
}

#[test]
fn a_request_signed_for_another_server_is_refused_for_its_audience() {
    let s = server();
    let client = SignRequests::new(s.signer.clone(), "server-2", body_type_of).layer(s.protected());
    let resp = block_on(client.oneshot(request(PATH, framed(MESSAGE)))).expect("infallible");
    assert_eq!(grpc_status(&resp).as_deref(), Some("16"));
    assert_eq!(s.refusals(), ["Audience"]);
    assert_eq!(s.handler_calls(), 0);
}

#[test]
fn a_request_signed_for_another_method_is_refused_for_its_audience() {
    let s = server();
    // A valid signature for DeleteItem, presented on ListItems.
    let signed = sealed_for(&s, "acme.v1.Inventory", "DeleteItem", SERVER);
    let mut req = request(PATH, framed(MESSAGE));
    with_header(&mut req, &signed);
    let resp = block_on(s.protected().oneshot(req)).expect("infallible");
    assert_eq!(grpc_status(&resp).as_deref(), Some("16"));
    assert_eq!(s.refusals(), ["Audience"]);
    assert_eq!(s.handler_calls(), 0);
}

#[test]
fn a_replayed_request_is_refused_at_the_layer() {
    let s = server();
    let signed = sealed_for(&s, "acme.v1.Inventory", "ListItems", SERVER);
    let svc = s.protected();
    let mut first = request(PATH, framed(MESSAGE));
    with_header(&mut first, &signed);
    let resp = block_on(svc.clone().oneshot(first)).expect("infallible");
    assert_eq!(grpc_status(&resp), None, "the first is accepted");

    let mut again = request(PATH, framed(MESSAGE));
    with_header(&mut again, &signed);
    let resp = block_on(svc.oneshot(again)).expect("infallible");
    assert_eq!(grpc_status(&resp).as_deref(), Some("16"));
    assert_eq!(s.refusals(), ["Replayed"]);
    assert_eq!(s.handler_calls(), 1, "the replay never reached the handler");
}

#[test]
fn a_full_nonce_cache_is_resource_exhausted_at_the_layer() {
    let s = server_with(NonceCaps {
        per_key: 1,
        total: 16,
    });
    let svc = s.protected();
    for expected in [None, Some("8")] {
        let signed = sealed_for(&s, "acme.v1.Inventory", "ListItems", SERVER);
        let mut req = request(PATH, framed(MESSAGE));
        with_header(&mut req, &signed);
        let resp = block_on(svc.clone().oneshot(req)).expect("infallible");
        assert_eq!(grpc_status(&resp).as_deref(), expected);
    }
    assert_eq!(s.refusals(), ["Busy"]);
}

#[test]
fn a_method_with_no_body_type_is_refused_as_unknown() {
    let s = server();
    let resp =
        block_on(s.protected().oneshot(request(MYSTERY, framed(MESSAGE)))).expect("infallible");
    assert_eq!(grpc_status(&resp).as_deref(), Some("16"));
    assert_eq!(s.refusals(), [format!("UnknownMethod({MYSTERY:?})")]);
    assert_eq!(s.handler_calls(), 0);
}

// Item 2: the client layer against the server layer, and what the client sends.

/// A client over a service that records the request it is handed.
fn recording_client(
    s: &Server,
    seen: Arc<Mutex<Vec<(http::HeaderMap, Bytes)>>>,
) -> impl Service<Request<Body>, Response = Response<Body>, Error = Infallible, Future: Send>
       + Clone
       + Send {
    let inner = service_fn(move |req: Request<Body>| {
        let seen = seen.clone();
        async move {
            let (parts, body) = req.into_parts();
            let bytes = body.collect().await.expect("a body").to_bytes();
            seen.lock().expect("lock").push((parts.headers, bytes));
            Ok::<_, Infallible>(Response::new(Body::default()))
        }
    });
    SignRequests::new(s.signer.clone(), SERVER, body_type_of)
        .pass_through(|path| path == HEALTH)
        .layer(inner)
}

#[test]
fn the_client_attaches_the_header_and_signs_the_message_without_its_frame() {
    let s = server();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let client = recording_client(&s, seen.clone());
    block_on(client.oneshot(request(PATH, framed(MESSAGE)))).expect("infallible");

    let seen = seen.lock().unwrap();
    let (headers, body) = &seen[0];
    let metadata = MetadataMap::from_headers(headers.clone());
    let signed = pb::SignedMessage::decode(
        metadata
            .get_bin(REQUEST_HEADER)
            .expect("the header is attached")
            .to_bytes()
            .expect("valid binary metadata"),
    )
    .expect("a SignedMessage");
    assert_eq!(
        signed.body, MESSAGE,
        "the signature covers the message, not the 5-byte frame"
    );
    assert_eq!(signed.body_type, BODY_TYPE);
    assert_eq!(
        signed.audience,
        audience_for("acme.v1.Inventory", "ListItems", SERVER)
    );
    assert_eq!(
        body.as_ref(),
        framed(MESSAGE),
        "the request itself goes out unchanged"
    );
}

#[test]
fn a_method_with_no_body_type_goes_out_unsigned() {
    let s = server();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let client = recording_client(&s, seen.clone());
    block_on(client.oneshot(request(MYSTERY, framed(MESSAGE)))).expect("infallible");

    let seen = seen.lock().unwrap();
    let (headers, body) = &seen[0];
    assert!(
        headers.get(REQUEST_HEADER).is_none(),
        "no header: not signed"
    );
    assert_eq!(body.as_ref(), framed(MESSAGE));
}

#[test]
fn a_signed_request_authenticates_end_to_end_and_the_handler_gets_the_whole_frame() {
    let s = server();
    let resp = block_on(s.client().oneshot(request(PATH, framed(MESSAGE)))).expect("infallible");
    assert_eq!(grpc_status(&resp), None);
    assert!(s.refusals().is_empty());
    assert_eq!(
        *s.reached.lock().unwrap(),
        (1, framed(MESSAGE).len()),
        "the handler reads the same framed bytes the client sent"
    );
}

// Item 7 and 8: buffering is capped on both sides; pass-through is not buffered.

#[test]
fn the_client_refuses_a_request_body_over_the_limit_without_sending_it() {
    let s = server();
    let big = vec![0u8; MAX_BODY_BYTES + 1];
    let resp = block_on(s.client().oneshot(request(PATH, framed(&big)))).expect("infallible");
    assert_eq!(
        grpc_status(&resp).as_deref(),
        Some("8"),
        "RESOURCE_EXHAUSTED"
    );
    assert_eq!(s.handler_calls(), 0);
    assert!(s.refusals().is_empty(), "it never reached the server layer");
}

#[test]
fn a_pass_through_call_larger_than_the_buffering_cap_still_succeeds() {
    let s = server();
    let big = vec![7u8; MAX_BODY_BYTES + 1];
    let resp = block_on(s.client().oneshot(request(HEALTH, framed(&big)))).expect("infallible");
    assert_eq!(
        grpc_status(&resp),
        None,
        "neither side buffered or limited it"
    );
    assert_eq!(
        *s.reached.lock().unwrap(),
        (1, framed(&big).len()),
        "the handler got every byte"
    );
    assert!(s.seen.lock().unwrap().is_none(), "unsigned: no caller");
}

// Item 1: streaming.

#[test]
fn a_client_streaming_or_bidi_request_is_refused_unread() {
    let s = server();
    for path in [UPLOAD, CHAT] {
        let req = Request::builder()
            .uri(path)
            .body(Body::new(Unread))
            .expect("a request");
        let resp = block_on(s.protected().oneshot(req)).expect("infallible");
        assert_eq!(
            grpc_status(&resp).as_deref(),
            Some("12"),
            "{path}: UNIMPLEMENTED"
        );
    }
    assert_eq!(
        s.refusals(),
        [
            format!("StreamingRequestUnsupported({UPLOAD:?})"),
            format!("StreamingRequestUnsupported({CHAT:?})")
        ]
    );
    assert_eq!(s.handler_calls(), 0);
}

#[test]
fn the_client_refuses_a_streaming_request_unread() {
    let s = server();
    for path in [UPLOAD, CHAT] {
        let req = Request::builder()
            .uri(path)
            .body(Body::new(Unread))
            .expect("a request");
        let resp = block_on(s.client().oneshot(req)).expect("infallible");
        assert_eq!(
            grpc_status(&resp).as_deref(),
            Some("12"),
            "{path}: UNIMPLEMENTED"
        );
    }
    assert_eq!(s.handler_calls(), 0);
    assert!(
        s.refusals().is_empty(),
        "refused by the client, before the server"
    );
}

#[test]
fn an_unregistered_streaming_method_is_refused_as_streaming_by_the_server() {
    let s = server();
    let req = Request::builder()
        .uri(GHOST)
        .body(Body::new(Unread))
        .expect("a request");
    let resp = block_on(s.protected().oneshot(req)).expect("infallible");
    assert_eq!(
        grpc_status(&resp).as_deref(),
        Some("12"),
        "UNIMPLEMENTED, not UNAUTHENTICATED"
    );
    assert_eq!(
        s.refusals(),
        [format!("StreamingRequestUnsupported({GHOST:?})")]
    );
    assert_eq!(s.handler_calls(), 0);
}

#[test]
fn an_unregistered_streaming_method_is_refused_unread_by_the_client() {
    let s = server();
    let req = Request::builder()
        .uri(GHOST)
        .body(Body::new(Unread))
        .expect("a request");
    let resp = block_on(s.client().oneshot(req)).expect("infallible");
    assert_eq!(
        grpc_status(&resp).as_deref(),
        Some("12"),
        "refused by the client, not sent out unsigned"
    );
    assert_eq!(s.handler_calls(), 0);
    assert!(
        s.refusals().is_empty(),
        "the request never reached the server"
    );
}

// Restart replay: the nonce cache is in memory, so the layer refuses a request
// issued before it was built.

/// Signs and sends one ListItems request at the clock's current time.
fn send_at(
    s: &Server,
    svc: &(impl Service<Request<Body>, Response = Response<Body>, Error = Infallible, Future: Send>
          + Clone),
    at: i64,
) -> Option<String> {
    s.clock.set(at);
    let signed = sealed_for(s, "acme.v1.Inventory", "ListItems", SERVER);
    let mut req = request(PATH, framed(MESSAGE));
    with_header(&mut req, &signed);
    grpc_status(&block_on(svc.clone().oneshot(req)).expect("infallible"))
}

#[test]
fn a_request_signed_before_the_layer_was_built_is_refused() {
    let s = server();
    // Signed at T0 and captured; the server restarts five seconds later.
    s.clock.set(T0);
    let captured = sealed_for(&s, "acme.v1.Inventory", "ListItems", SERVER);
    s.clock.set(T0 + 5);
    let svc = s.protected();
    let mut req = request(PATH, framed(MESSAGE));
    with_header(&mut req, &captured);
    let resp = block_on(svc.clone().oneshot(req)).expect("infallible");
    assert_eq!(grpc_status(&resp).as_deref(), Some("16"));
    assert_eq!(
        s.refusals(),
        ["IssuedBeforeStart"],
        "its own refusal, not Skew"
    );
    assert_eq!(s.handler_calls(), 0);

    // One signed after the restart is accepted.
    assert_eq!(send_at(&s, &svc, T0 + 6), None);
    assert_eq!(s.handler_calls(), 1);
}

#[test]
fn the_issued_before_boundary_is_strict() {
    let s = server();
    let svc = s.protected(); // built at T0
    assert_eq!(
        send_at(&s, &svc, T0 - 1).as_deref(),
        Some("16"),
        "one second before"
    );
    assert_eq!(s.refusals(), ["IssuedBeforeStart"]);
    assert_eq!(send_at(&s, &svc, T0), None, "the same second");
    assert_eq!(send_at(&s, &svc, T0 + 1), None, "one second after");
    assert_eq!(s.handler_calls(), 2);
}

#[test]
fn reject_issued_before_can_be_opted_out_with_the_epoch() {
    let s = server();
    let svc = s.layer().reject_issued_before(0).layer(s.handler());
    assert_eq!(
        send_at(&s, &svc, T0 - 20),
        None,
        "issued before construction"
    );
    assert!(s.refusals().is_empty());
}

#[tokio::test(start_paused = true)]
async fn a_server_streaming_response_ends_with_an_error_status_at_the_session_end() {
    let s = server();
    s.stream
        .lock()
        .unwrap()
        .extend([Bytes::from("one"), Bytes::from("two")]);
    let resp = s
        .client()
        .oneshot(request(WATCH, framed(MESSAGE)))
        .await
        .expect("infallible");
    assert_eq!(grpc_status(&resp), None, "the stream opened");
    let mut body = resp.into_body();

    let Poll::Ready(Some(Ok(frame))) = poll_once(&mut body) else {
        panic!("the first frame is ready")
    };
    assert_eq!(frame.into_data().expect("data").as_ref(), b"one");

    // The session certificate ends here; the fake clock reaches it before the second frame.
    s.clock.set(T0 + SESSION_SECONDS);
    let Poll::Ready(Some(Ok(frame))) = poll_once(&mut body) else {
        panic!("the stream ends with a frame")
    };
    let trailers = frame
        .into_trailers()
        .expect("trailers, not the queued 'two'");
    assert_eq!(trailers.get("grpc-status").expect("a status"), "16");
    assert!(poll_once(&mut body).is_ready_none(), "and then it is over");
}

#[tokio::test(start_paused = true)]
async fn an_idle_server_stream_still_ends_when_the_session_does() {
    let s = server();
    let resp = s
        .client()
        .oneshot(request(WATCH, framed(MESSAGE)))
        .await
        .expect("infallible");
    let mut body = resp.into_body();
    assert!(poll_once(&mut body).is_pending(), "nothing to send yet");

    // Time passes with no frames: the timer, not a poll of data, ends the stream.
    s.clock.set(T0 + SESSION_SECONDS);
    tokio::time::advance(std::time::Duration::from_secs(SESSION_SECONDS as u64)).await;
    let frame = body
        .frame()
        .await
        .expect("a final frame")
        .expect("not an error");
    let trailers = frame.into_trailers().expect("trailers");
    assert_eq!(trailers.get("grpc-status").expect("a status"), "16");
}

#[tokio::test(start_paused = true)]
async fn a_unary_response_is_not_cut_at_the_session_end() {
    let s = server();
    s.stream.lock().unwrap().push_back(Bytes::from("late"));
    let resp = s
        .client()
        .oneshot(request(PATH, framed(MESSAGE)))
        .await
        .expect("infallible");
    let mut body = resp.into_body();
    s.clock.set(T0 + SESSION_SECONDS + 10);
    let Poll::Ready(Some(Ok(frame))) = poll_once(&mut body) else {
        panic!("a unary body is the handler's, untouched")
    };
    assert_eq!(frame.into_data().expect("data").as_ref(), b"late");
}

trait PollExt {
    fn is_ready_none(&self) -> bool;
}

impl<T> PollExt for Poll<Option<T>> {
    fn is_ready_none(&self) -> bool {
        matches!(self, Poll::Ready(None))
    }
}
