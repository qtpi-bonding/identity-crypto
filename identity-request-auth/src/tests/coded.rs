//! Task 12: `AuthError` is a `CodedError`; the gRPC status table is derived from
//! the codes; client refusals and the session-expiry trailer are coded.

use super::grpc::{framed, grpc_status, poll_once, request, server, MESSAGE, PATH, T0, WATCH};
use crate::grpc::{default_reject, REJECT_SOURCE};
use crate::{AuthError, MAX_BODY_BYTES, SESSION_SECONDS};
use coded_error::{CodedError, ErrorClass};
use std::task::Poll;
use tonic::Code;
use tower::ServiceExt;

fn crypto() -> identity_crypto::Error {
    identity_crypto::Error::NotCurrentRoot
}

/// Every variant with its code, class and gRPC code.
fn table() -> Vec<(AuthError, &'static str, ErrorClass, Code)> {
    use ErrorClass::{Infrastructure as I, Logical as L, Transient as T};
    vec![
        (AuthError::Audience, "audience", L, Code::Unauthenticated),
        (AuthError::BodyType, "body_type", L, Code::Unauthenticated),
        (
            AuthError::UnknownMethod("m".into()),
            "unknown_method",
            L,
            Code::Unauthenticated,
        ),
        (
            AuthError::StreamingRequestUnsupported("m".into()),
            "streaming_request",
            L,
            Code::Unimplemented,
        ),
        (
            AuthError::EmptySignature,
            "empty_signature",
            L,
            Code::Unauthenticated,
        ),
        (AuthError::NotSetUp, "not_set_up", I, Code::Unauthenticated),
        (
            AuthError::NonceLength(3),
            "nonce_length",
            L,
            Code::Unauthenticated,
        ),
        (
            AuthError::BodyMismatch,
            "body_mismatch",
            L,
            Code::Unauthenticated,
        ),
        (
            AuthError::BodyTooLarge { len: 2, max: 1 },
            "body_too_large",
            L,
            Code::ResourceExhausted,
        ),
        (
            AuthError::Tolerance { seconds: 0, max: 1 },
            "tolerance",
            I,
            Code::Unauthenticated,
        ),
        (AuthError::Skew, "skew", L, Code::Unauthenticated),
        (
            AuthError::IssuedBeforeStart,
            "issued_before_start",
            L,
            Code::Unauthenticated,
        ),
        (AuthError::Replayed, "replayed", L, Code::Unauthenticated),
        (AuthError::Busy, "busy", T, Code::ResourceExhausted),
        (
            AuthError::UnknownAuthor,
            "unknown_author",
            L,
            Code::Unauthenticated,
        ),
        (
            AuthError::LookupUnavailable,
            "lookup_unavailable",
            T,
            Code::Unavailable,
        ),
        (
            AuthError::Malformed("x"),
            "malformed",
            L,
            Code::Unauthenticated,
        ),
        (
            AuthError::Verify(crypto()),
            "verify",
            L,
            Code::Unauthenticated,
        ),
        (
            AuthError::Credential(crypto()),
            "credential",
            I,
            Code::Internal,
        ),
        (AuthError::Entropy("e".into()), "entropy", I, Code::Internal),
        (
            AuthError::SessionExpired,
            "session_expired",
            T,
            Code::Unauthenticated,
        ),
        (AuthError::NoCaller, "no_caller", I, Code::Unauthenticated),
        (
            AuthError::UnsignableRequest("request body"),
            "unsignable_request",
            L,
            Code::InvalidArgument,
        ),
    ]
}

#[test]
fn auth_error_codes_stable() {
    let mut seen = std::collections::HashSet::new();
    for (err, code, class, _) in table() {
        let full = format!("identity.request_auth.{code}");
        assert_eq!(CodedError::code(&err), full, "{err:?}");
        assert_eq!(CodedError::class(&err), class, "{err:?}");
        assert!(seen.insert(full), "duplicate code for {err:?}");
    }
    assert_eq!(seen.len(), 23);
}

#[test]
fn auth_error_status_table_unchanged() {
    for (err, _, _, grpc) in table() {
        let code = CodedError::code(&err);
        let status = default_reject(err);
        assert_eq!(status.code(), grpc, "{code}");
        assert_eq!(
            status
                .metadata()
                .get("x-error-code")
                .expect("coded")
                .to_str()
                .unwrap(),
            code
        );
    }
    let _ = REJECT_SOURCE;
}

/// An expired session is retryable once the client renews: class Transient on the wire and in
/// the trailer, with the code and the UNAUTHENTICATED status unchanged.
#[test]
fn session_expired_is_transient_with_its_code_and_status() {
    let err = AuthError::SessionExpired;
    assert_eq!(CodedError::class(&err), ErrorClass::Transient);
    assert_eq!(
        CodedError::code(&err),
        "identity.request_auth.session_expired"
    );
    let status = default_reject(err);
    assert_eq!(status.code(), Code::Unauthenticated);
    let meta = |key: &str| {
        status
            .metadata()
            .get(key)
            .unwrap_or_else(|| panic!("{key}"))
            .to_str()
            .unwrap()
            .to_owned()
    };
    assert_eq!(
        meta("x-error-code"),
        "identity.request_auth.session_expired"
    );
    assert_eq!(meta("x-error-class"), "transient");
}

fn code_of(resp: &http::Response<tonic::body::Body>) -> String {
    resp.headers()
        .get("x-error-code")
        .expect("x-error-code")
        .to_str()
        .unwrap()
        .to_owned()
}

#[tokio::test]
async fn client_errors_are_coded() {
    let s = server();
    let big = vec![0u8; MAX_BODY_BYTES + 1];
    let resp = s
        .client()
        .oneshot(request(PATH, framed(&big)))
        .await
        .expect("infallible");
    assert_eq!(grpc_status(&resp).as_deref(), Some("8"));
    assert_eq!(code_of(&resp), "identity.request_auth.body_too_large");

    // Three bytes: not even a gRPC frame header.
    let resp = s
        .client()
        .oneshot(request(PATH, vec![0u8, 0, 0]))
        .await
        .expect("infallible");
    assert_eq!(grpc_status(&resp).as_deref(), Some("3"), "INVALID_ARGUMENT");
    assert_eq!(code_of(&resp), "identity.request_auth.unsignable_request");
}

#[tokio::test(start_paused = true)]
async fn session_expiry_trailer_is_coded_unauthenticated() {
    let s = server();
    s.stream
        .lock()
        .unwrap()
        .push_back(bytes::Bytes::from("one"));
    let resp = s
        .client_with_reject(|_| tonic::Status::internal("x"))
        .oneshot(request(WATCH, framed(MESSAGE)))
        .await
        .expect("infallible");
    let mut body = resp.into_body();
    let Poll::Ready(Some(Ok(_))) = poll_once(&mut body) else {
        panic!("first frame")
    };
    s.clock.set(T0 + SESSION_SECONDS);
    let Poll::Ready(Some(Ok(frame))) = poll_once(&mut body) else {
        panic!("trailers")
    };
    let trailers = frame.into_trailers().expect("trailers");
    assert_eq!(trailers.get("grpc-status").expect("status"), "16");
    assert_eq!(
        trailers.get("x-error-code").expect("coded trailer"),
        "identity.request_auth.session_expired"
    );
}
