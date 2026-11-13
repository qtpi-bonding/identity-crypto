//! The transport-free core, from the spec's Tests section. These run without
//! the `tonic` feature.

use crate::testkit::{FakeClock, TestPrincipal};
use crate::{
    audience_for, open_signed_request, seal_request, split_path, AuthError, Clock, ClockTolerance,
    NonceCache, NonceCaps, RequestSigner, TrustedDeviceSet, VerifiedCaller, MAX_BODY_BYTES,
    SESSION_SECONDS,
};
use identity_crypto::{pb, PrincipalId, PublicKey};
use std::cell::RefCell;
use std::sync::Arc;

const T0: i64 = 1_800_000_000;
const SERVICE: &str = "acme.v1.Inventory";
const SERVER: &str = "server-1";
const AUD: &str = "acme.v1.Inventory:ListItems@server-1";
const BODY_TYPE: &str = "type.googleapis.com/acme.v1.ListItemsRequest";
const BODY: &[u8] = b"\x0a\x03abc";

/// One trusted principal, one device, a clock, and the verifier's own state:
/// the core takes the signer source and the replay cache as plain arguments.
struct Fixture {
    clock: Arc<FakeClock>,
    genesis: PublicKey,
    device: PublicKey,
    set: RefCell<TrustedDeviceSet>,
    nonces: RefCell<NonceCache>,
    tolerance: ClockTolerance,
    signer: RequestSigner,
}

fn fixture() -> Fixture {
    fixture_with(ClockTolerance::default(), NonceCaps::default())
}

fn fixture_with(tolerance: ClockTolerance, caps: NonceCaps) -> Fixture {
    let clock = FakeClock::new(T0);
    let principal = TestPrincipal::new();
    let genesis = principal.genesis.clone();
    let device = principal.device_key();
    let set = RefCell::new(TrustedDeviceSet::new(genesis.clone(), vec![device.clone()]));
    let signer = principal.signer(clock.clone());
    Fixture {
        clock,
        genesis,
        device,
        set,
        nonces: RefCell::new(NonceCache::new(caps)),
        tolerance,
        signer,
    }
}

impl Fixture {
    fn seal(&self, audience: &str, body_type: &str, body: &[u8]) -> pb::SignedMessage {
        seal_request(&self.signer, audience, body_type, body).expect("sealing a request")
    }

    fn open(
        &self,
        signed: &pb::SignedMessage,
        audience: &str,
        body_type: &str,
        body: &[u8],
    ) -> Result<VerifiedCaller, AuthError> {
        self.open_with(&self.set.borrow(), signed, audience, body_type, body)
    }

    fn open_with(
        &self,
        set: &TrustedDeviceSet,
        signed: &pb::SignedMessage,
        audience: &str,
        body_type: &str,
        body: &[u8],
    ) -> Result<VerifiedCaller, AuthError> {
        open_signed_request(
            signed,
            audience,
            body_type,
            body,
            Some(MAX_BODY_BYTES),
            set,
            &mut self.nonces.borrow_mut(),
            self.tolerance,
            self.clock.now_unix(),
        )
    }

    fn open_ok(&self, signed: &pb::SignedMessage) -> VerifiedCaller {
        self.open(signed, AUD, BODY_TYPE, BODY)
            .expect("a valid request is accepted")
    }
}

fn session_of(signed: &pb::SignedMessage) -> pb::PublicKey {
    match signed.signer.as_ref().and_then(|s| s.chain.as_ref()) {
        Some(pb::signer_chain::Chain::SelfRooted(s)) => {
            s.session.as_ref().expect("session cert").session.clone()
        }
        other => panic!("expected a self-rooted chain, got {other:?}"),
    }
    .expect("session key")
}

#[test]
fn a_well_formed_request_is_accepted_and_names_its_caller() {
    let f = fixture();
    let signed = f.seal(AUD, BODY_TYPE, BODY);
    let caller = f.open_ok(&signed);
    assert_eq!(
        caller.principal(),
        &PrincipalId::from_genesis(f.genesis.clone())
    );
    assert_eq!(caller.device(), &f.device);
    assert_eq!(caller.session_not_after(), T0 + SESSION_SECONDS);
}

#[test]
fn a_body_byte_changed_in_flight_is_refused() {
    let f = fixture();
    let signed = f.seal(AUD, BODY_TYPE, BODY);
    let mut tampered = BODY.to_vec();
    tampered[0] ^= 1;
    assert_eq!(
        f.open(&signed, AUD, BODY_TYPE, &tampered),
        Err(AuthError::BodyMismatch),
        "one byte of difference is refused"
    );
}

#[test]
fn a_body_altered_inside_the_signed_message_fails_the_signature() {
    let f = fixture();
    let mut signed = f.seal(AUD, BODY_TYPE, BODY);
    signed.body[0] ^= 1;
    let altered = signed.body.clone();
    assert!(matches!(
        f.open(&signed, AUD, BODY_TYPE, &altered),
        Err(AuthError::Verify(_))
    ));
}

#[test]
fn a_signature_is_refused_for_another_method_or_service() {
    let f = fixture();
    let signed = f.seal(AUD, BODY_TYPE, BODY);
    let delete = audience_for(SERVICE, "DeleteItem", SERVER);
    let other_service = audience_for("other.v1.Other", "ListItems", SERVER);
    let other_server = audience_for(SERVICE, "ListItems", "server-2");
    assert_eq!(
        f.open(&signed, &delete, BODY_TYPE, BODY),
        Err(AuthError::Audience)
    );
    assert_eq!(
        f.open(&signed, &other_service, BODY_TYPE, BODY),
        Err(AuthError::Audience)
    );
    assert_eq!(
        f.open(&signed, &other_server, BODY_TYPE, BODY),
        Err(AuthError::Audience)
    );
}

#[test]
fn the_audience_cannot_be_edited_to_another_method() {
    let f = fixture();
    let mut signed = f.seal(AUD, BODY_TYPE, BODY);
    let delete = audience_for(SERVICE, "DeleteItem", SERVER);
    signed.audience = delete.clone();
    assert!(matches!(
        f.open(&signed, &delete, BODY_TYPE, BODY),
        Err(AuthError::Verify(_))
    ));
}

#[test]
fn a_replayed_request_is_refused() {
    let f = fixture();
    let first = f.seal(AUD, BODY_TYPE, BODY);
    let second = f.seal(AUD, BODY_TYPE, BODY);
    assert_ne!(first.nonce, second.nonce, "each seal draws a fresh nonce");
    f.open_ok(&first);
    f.open_ok(&second);
    assert_eq!(
        f.open(&first, AUD, BODY_TYPE, BODY),
        Err(AuthError::Replayed)
    );
}

#[test]
fn a_full_nonce_cache_refuses_with_busy_and_evicts_nothing() {
    let f = fixture_with(
        ClockTolerance::default(),
        NonceCaps {
            per_key: 1,
            total: 16,
        },
    );
    let first = f.seal(AUD, BODY_TYPE, BODY);
    let second = f.seal(AUD, BODY_TYPE, BODY);
    f.open_ok(&first);
    assert_eq!(f.open(&second, AUD, BODY_TYPE, BODY), Err(AuthError::Busy));
    assert_eq!(
        f.open(&first, AUD, BODY_TYPE, BODY),
        Err(AuthError::Replayed),
        "nothing evicted"
    );
}

#[test]
fn a_stale_or_future_issued_at_is_refused() {
    let f = fixture();
    let signed = f.seal(AUD, BODY_TYPE, BODY);
    f.clock.advance(31);
    assert!(
        matches!(
            f.open(&signed, AUD, BODY_TYPE, BODY),
            Err(AuthError::Verify(identity_crypto::Error::Skew))
        ),
        "31 s late is identity-crypto's own skew failure, kept as it is"
    );

    // Early by more than 30 s: the session cert's own window refuses it first,
    // so the request is refused either way. The verifier is back at T0.
    f.clock.set(T0);
    let early = FakeClock::new(T0 + 31);
    let principal = TestPrincipal::new();
    let theirs = TrustedDeviceSet::new(principal.genesis.clone(), vec![principal.device_key()]);
    let early_signed =
        seal_request(&principal.signer(early), AUD, BODY_TYPE, BODY).expect("sealing");
    assert!(
        f.open_with(&theirs, &early_signed, AUD, BODY_TYPE, BODY)
            .is_err(),
        "31 s early is refused"
    );
}

#[test]
fn an_expired_certificate_is_refused() {
    let f = fixture();
    // A signer whose clock is long past: its session expired before `now`.
    let past = FakeClock::new(T0 - 1_000);
    let principal = TestPrincipal::new();
    let theirs = TrustedDeviceSet::new(principal.genesis.clone(), vec![principal.device_key()]);
    let stale = principal.signer(past);
    let signed = seal_request(&stale, AUD, BODY_TYPE, BODY).expect("sealing");
    assert!(matches!(
        f.open_with(&theirs, &signed, AUD, BODY_TYPE, BODY),
        Err(AuthError::Verify(identity_crypto::Error::Expired(_)))
    ));
}

#[test]
fn the_session_renews_at_sixty_percent_of_its_life_and_after_expiry() {
    let f = fixture();
    let first = f.seal(AUD, BODY_TYPE, BODY);
    let key = session_of(&first);

    f.clock.set(T0 + 179);
    assert_eq!(
        session_of(&f.seal(AUD, BODY_TYPE, BODY)),
        key,
        "still the same session at 179 s"
    );

    f.clock.set(T0 + 180);
    let renewed = f.seal(AUD, BODY_TYPE, BODY);
    assert_ne!(session_of(&renewed), key, "renewed at 60% of the life");
    f.clock.set(T0 + 180);
    f.open_ok(&renewed);

    f.clock.set(T0 + 1_000);
    let after_expiry = f.seal(AUD, BODY_TYPE, BODY);
    assert_ne!(
        session_of(&after_expiry),
        session_of(&renewed),
        "renewed after expiry"
    );
    f.open_ok(&after_expiry);
}

#[test]
fn a_revoked_device_is_refused_on_the_next_lookup() {
    let f = fixture();
    let before = f.seal(AUD, BODY_TYPE, BODY);
    f.open_ok(&before);

    // Revoking is the caller handing the core a set without the device.
    *f.set.borrow_mut() = TrustedDeviceSet::new(f.genesis.clone(), vec![]);
    let after = f.seal(AUD, BODY_TYPE, BODY);
    assert_eq!(
        f.open(&after, AUD, BODY_TYPE, BODY),
        Err(AuthError::UnknownAuthor),
        "the revoked device is refused at the next request"
    );
}

#[test]
fn a_message_for_another_principal_than_the_set_is_refused() {
    let f = fixture();
    let stranger = TestPrincipal::new().signer(f.clock.clone());
    let signed = seal_request(&stranger, AUD, BODY_TYPE, BODY).expect("sealing");
    // The caller picks the set by `claimed_genesis`; a set for another author
    // refuses a certificate that names a different principal. (An async layer
    // maps "no set for this genesis" to `UnknownAuthor` before it gets here.)
    assert!(matches!(
        f.open(&signed, AUD, BODY_TYPE, BODY),
        Err(AuthError::Verify(identity_crypto::Error::ChainMismatch(_)))
    ));
}

#[test]
fn an_oversize_body_is_refused_before_any_signature_work() {
    let f = fixture();
    let big = vec![0u8; MAX_BODY_BYTES + 1];
    let signed = f.seal(AUD, BODY_TYPE, &big);
    assert_eq!(
        f.open(&signed, AUD, BODY_TYPE, &big),
        Err(AuthError::BodyTooLarge {
            len: MAX_BODY_BYTES + 1,
            max: MAX_BODY_BYTES
        })
    );
}

#[test]
fn the_audience_string_is_pinned_by_a_golden_vector() {
    assert_eq!(
        audience_for("acme.v1.Inventory", "ListItems", "server-1"),
        "acme.v1.Inventory:ListItems@server-1"
    );
    assert_eq!(
        split_path("/acme.v1.Inventory/ListItems"),
        Some(("acme.v1.Inventory", "ListItems"))
    );
    assert_eq!(split_path("ListItems"), None);
    assert_eq!(split_path("/acme.v1.Inventory"), None);
}

#[test]
fn the_clock_tolerance_may_only_tighten_identity_crypto_skew() {
    assert_eq!(
        ClockTolerance::new(60),
        Err(AuthError::Tolerance {
            seconds: 60,
            max: 30
        }),
        "60 s would loosen the fixed 30 s"
    );
    assert!(ClockTolerance::new(0).is_err());
    assert!(ClockTolerance::new(-5).is_err());
    assert_eq!(ClockTolerance::new(30).unwrap().seconds(), 30);
    assert_eq!(ClockTolerance::new(1).unwrap().seconds(), 1);
    assert_eq!(ClockTolerance::default().seconds(), 30);
}

#[test]
fn a_tighter_tolerance_refuses_what_the_default_accepts() {
    let f = fixture_with(ClockTolerance::new(10).unwrap(), NonceCaps::default());
    let signed = f.seal(AUD, BODY_TYPE, BODY);
    f.clock.advance(11);
    assert_eq!(
        f.open(&signed, AUD, BODY_TYPE, BODY),
        Err(AuthError::Skew),
        "the tighter tolerance's own error"
    );
}

#[test]
fn a_nonce_of_the_wrong_length_is_refused() {
    let f = fixture();
    let mut signed = f.seal(AUD, BODY_TYPE, BODY);
    signed.nonce.pop();
    assert_eq!(
        f.open(&signed, AUD, BODY_TYPE, BODY),
        Err(AuthError::NonceLength(15))
    );
}

#[test]
fn a_body_type_other_than_the_method_expects_is_refused() {
    let f = fixture();
    let signed = f.seal(AUD, BODY_TYPE, BODY);
    assert_eq!(
        f.open(
            &signed,
            AUD,
            "type.googleapis.com/acme.v1.DeleteItemRequest",
            BODY
        ),
        Err(AuthError::BodyType)
    );
}

#[test]
fn a_clock_that_goes_backwards_mints_a_session_valid_now() {
    let f = fixture();
    let first = f.seal(AUD, BODY_TYPE, BODY);
    let key = session_of(&first);
    f.open_ok(&first);

    // The held session starts at T0. A clock stepped back past it must not keep
    // signing under a session that is not yet valid.
    f.clock.set(T0 - 100);
    let after = f.seal(AUD, BODY_TYPE, BODY);
    assert_ne!(
        session_of(&after),
        key,
        "a session not yet valid is replaced"
    );
    f.open_ok(&after);

    // And a clock that is merely a little behind (still inside the window of the
    // new session) keeps it.
    f.clock.set(T0 - 99);
    assert_eq!(
        session_of(&f.seal(AUD, BODY_TYPE, BODY)),
        session_of(&after)
    );
}
