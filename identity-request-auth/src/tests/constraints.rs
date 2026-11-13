//! The core's constraints from a fleet wire that has its own verifier (see the README, "Core constraints"):
//! each must hold so its fleet wire can switch to this core with its own tests
//! unchanged. Everything here runs without the `tonic` feature.

use crate::testkit::{FakeClock, TestPrincipal};
use crate::{
    check_request, open_signed_request, seal_request, AuthError, ClockTolerance, NonceCache,
    NonceCaps, SignerVerifier, TrustedDeviceSet, VerifiedSigner, MAX_BODY_BYTES, PURGE_GRACE,
};
use identity_crypto::testkit::{owner_chain, signed_message, Fleet};
use identity_crypto::{pb, PrincipalKind, PublicKey, When, SKEW_SECONDS};
use std::cell::Cell;
use std::rc::Rc;

const T0: i64 = 1_800_000_000;
const AUD: &str = "acme.v1.Inventory:ListItems@server-1";
const BODY_TYPE: &str = "type.googleapis.com/acme.v1.ListItemsRequest";
const BODY: &[u8] = b"\x0a\x03abc";

struct Rig {
    clock: Rc<FakeClockHandle>,
    signer: crate::RequestSigner,
    set: TrustedDeviceSet,
}

/// The fake clock is `Arc` in the crate's API; this keeps the rig's field list short.
struct FakeClockHandle(std::sync::Arc<FakeClock>);

fn rig() -> Rig {
    let clock = FakeClock::new(T0);
    let principal = TestPrincipal::new();
    let set = TrustedDeviceSet::new(principal.genesis.clone(), vec![principal.device_key()]);
    let signer = principal.signer(clock.clone());
    Rig {
        clock: Rc::new(FakeClockHandle(clock)),
        signer,
        set,
    }
}

fn open<V: SignerVerifier + ?Sized>(
    signed: &pb::SignedMessage,
    body: &[u8],
    signers: &V,
    cache: &mut NonceCache,
) -> Result<crate::VerifiedCaller, AuthError> {
    open_signed_request(
        signed,
        AUD,
        BODY_TYPE,
        body,
        None,
        signers,
        cache,
        ClockTolerance::default(),
        T0,
    )
}

// C1: a plain sync verifier, no Send/Sync, no lock; the cache is `&mut`.

/// `Rc` makes this verifier neither `Send` nor `Sync`: it only compiles if the
/// core asks for neither.
struct Counting {
    inner: TrustedDeviceSet,
    calls: Rc<Cell<u32>>,
}

impl SignerVerifier for Counting {
    fn verify(
        &self,
        msg: &pb::SignedMessage,
        aud: &str,
        when: When,
    ) -> Result<VerifiedSigner, AuthError> {
        self.calls.set(self.calls.get() + 1);
        self.inner.verify(msg, aud, when)
    }
}

#[test]
fn c1_the_core_verifies_with_a_sync_non_send_verifier_and_a_plain_mut_cache() {
    let r = rig();
    let calls = Rc::new(Cell::new(0));
    let signers = Counting {
        inner: r.set,
        calls: calls.clone(),
    };
    let signed = seal_request(&r.signer, AUD, BODY_TYPE, BODY).expect("sealing");
    let mut cache = NonceCache::new(NonceCaps::default());
    open(&signed, BODY, &signers, &mut cache).expect("accepted");
    assert_eq!(calls.get(), 1, "the caller's verifier was asked once");
    assert_eq!(cache.len(), 1, "the caller's cache holds the nonce");
    assert_eq!(
        open(&signed, BODY, &signers, &mut cache),
        Err(AuthError::Replayed)
    );
}

#[test]
fn c1_the_core_takes_a_full_chain_resolver_with_a_live_clock() {
    let f = Fleet::new();
    let resolver = f.resolver();
    let (session, chain) = owner_chain(&f, T0 - 10, T0 + 300);
    let msg = signed_message(&session, chain, AUD, T0);
    let mut cache = NonceCache::new(NonceCaps::default());
    let caller = open_signed_request(
        &msg,
        AUD,
        "type.googleapis.com/test.v1.Body",
        &[1, 2],
        None,
        &resolver,
        &mut cache,
        ClockTolerance::default(),
        T0,
    )
    .expect("a chain the resolver trusts is accepted");
    assert_eq!(caller.principal(), &f.owner.id());
    assert_eq!(caller.session_not_after(), T0 + 300);
}

// C2: the cache API and the constants.

#[test]
fn c2_the_cache_has_the_fixed_caps_and_constants() {
    let caps = NonceCaps::default();
    assert_eq!((caps.per_key, caps.total), (256, 4096));
    assert_eq!((SKEW_SECONDS, PURGE_GRACE), (30, 30));
}

#[test]
fn c2_a_replay_through_the_core_is_refused_until_the_grace_has_passed() {
    let r = rig();
    let signed = seal_request(&r.signer, AUD, BODY_TYPE, BODY).expect("sealing");
    let mut cache = NonceCache::new(NonceCaps::default());
    let at = |now| {
        open_signed_request(
            &signed,
            AUD,
            BODY_TYPE,
            BODY,
            None,
            &r.set,
            &mut NonceCache::new(NonceCaps::default()),
            ClockTolerance::default(),
            now,
        )
    };
    // The window itself: accepted once at issued_at (T0).
    assert!(at(T0).is_ok());
    assert!(open(&signed, BODY, &r.set, &mut cache).is_ok());
    // The cache refuses it at exactly issued_at + 30 and + 60, and purges after.
    let k = PublicKey::from(&identity_crypto::jwk_duo::SigningKeyPair::generate());
    assert_eq!(cache.insert(&k, b"n", T0, T0 + 30), crate::Insert::Fresh);
    assert_eq!(cache.insert(&k, b"n", T0, T0 + 30), crate::Insert::Replayed);
    assert_eq!(cache.insert(&k, b"n", T0, T0 + 60), crate::Insert::Replayed);
    assert_eq!(
        cache.insert(&k, b"n", T0, T0 + 61),
        crate::Insert::Fresh,
        "accepted again only after the grace"
    );
}

// C3: audience and body type are the caller's strings, compared for equality.

#[test]
fn c3_audience_and_body_type_are_compared_for_equality_only() {
    let r = rig();
    let odd_audience = "no format, at all: \u{2713}@@/\n";
    let odd_type = "x";
    let signed = seal_request(&r.signer, odd_audience, odd_type, BODY).expect("sealing");
    let mut cache = NonceCache::new(NonceCaps::default());
    open_signed_request(
        &signed,
        odd_audience,
        odd_type,
        BODY,
        None,
        &r.set,
        &mut cache,
        ClockTolerance::default(),
        T0,
    )
    .expect("any string the two sides agree on");
    let signed = seal_request(&r.signer, odd_audience, odd_type, BODY).expect("sealing");
    for wrong in [
        odd_audience.to_uppercase(),
        format!("{odd_audience} "),
        String::new(),
    ] {
        assert_eq!(
            open_signed_request(
                &signed,
                &wrong,
                odd_type,
                BODY,
                None,
                &r.set,
                &mut cache,
                ClockTolerance::default(),
                T0
            ),
            Err(AuthError::Audience),
            "{wrong:?}"
        );
    }
}

// C4: every refusal stays its own error, in the order the README gives.

#[test]
fn c4_cheap_checks_fail_with_their_own_error_before_any_signer_work() {
    let r = rig();
    let good = seal_request(&r.signer, AUD, BODY_TYPE, BODY).expect("sealing");
    let mut cache = NonceCache::new(NonceCaps::default());
    // No signer authority: if any signer work ran, `NotSetUp` would be the error.
    let none: Option<&TrustedDeviceSet> = None;
    let run = |m: &pb::SignedMessage, aud: &str, ty: &str, cache: &mut NonceCache| {
        open_signed_request(
            m,
            aud,
            ty,
            BODY,
            None,
            &none,
            cache,
            ClockTolerance::default(),
            T0,
        )
    };

    assert_eq!(
        run(&good, "elsewhere", BODY_TYPE, &mut cache),
        Err(AuthError::Audience)
    );
    assert_eq!(
        run(&good, AUD, "other.Type", &mut cache),
        Err(AuthError::BodyType)
    );
    let mut unsigned = good.clone();
    unsigned.signature.clear();
    assert_eq!(
        run(&unsigned, AUD, BODY_TYPE, &mut cache),
        Err(AuthError::EmptySignature)
    );
    let mut short = good.clone();
    short.nonce = vec![1; 15];
    assert_eq!(
        run(&short, AUD, BODY_TYPE, &mut cache),
        Err(AuthError::NonceLength(15))
    );
    assert_eq!(
        run(&good, AUD, BODY_TYPE, &mut cache),
        Err(AuthError::NotSetUp)
    );
    assert!(
        cache.is_empty(),
        "nothing was remembered for a refused request"
    );
}

#[test]
fn c4_a_verification_failure_keeps_the_inner_error() {
    let r = rig();
    let mut cache = NonceCache::new(NonceCaps::default());

    let mut altered = seal_request(&r.signer, AUD, BODY_TYPE, BODY).expect("sealing");
    altered.body[0] ^= 1;
    let body = altered.body.clone();
    assert!(matches!(
        open(&altered, &body, &r.set, &mut cache),
        Err(AuthError::Verify(identity_crypto::Error::BadSignature))
    ));

    let stale = seal_request(&r.signer, AUD, BODY_TYPE, BODY).expect("sealing");
    r.clock.0.advance(31);
    let late = open_signed_request(
        &stale,
        AUD,
        BODY_TYPE,
        BODY,
        None,
        &r.set,
        &mut cache,
        ClockTolerance::default(),
        T0 + 31,
    );
    assert!(
        matches!(late, Err(AuthError::Verify(identity_crypto::Error::Skew))),
        "identity-crypto's own skew error is preserved: {late:?}"
    );
}

#[test]
fn c4_the_request_that_arrived_must_be_the_request_that_was_signed() {
    let r = rig();
    let signed = seal_request(&r.signer, AUD, BODY_TYPE, BODY).expect("sealing");
    let mut cache = NonceCache::new(NonceCaps::default());
    assert_eq!(
        open(&signed, b"\x0a\x03abd", &r.set, &mut cache),
        Err(AuthError::BodyMismatch)
    );
    assert!(cache.is_empty());
}

// C5: the verified result carries the chain when a Resolver verified it.

fn resolver_message(f: &Fleet, issued_at: i64) -> pb::SignedMessage {
    let (session, chain) = owner_chain(f, T0 - 10, T0 + 300);
    signed_message(&session, chain, AUD, issued_at)
}

const RESOLVER_BODY_TYPE: &str = "type.googleapis.com/test.v1.Body";
const RESOLVER_BODY: &[u8] = &[1, 2];

#[test]
fn c5_the_resolver_form_returns_its_chain() {
    let f = Fleet::new();
    let resolver = f.resolver();
    let msg = resolver_message(&f, T0);
    let who = resolver
        .verify(&msg, AUD, When::Live { now: T0 })
        .expect("a chain the resolver trusts");
    let chain = who.chain.expect("the resolver verified a chain");
    assert_eq!(chain.kind(), PrincipalKind::Human);
    assert_eq!(chain.principal(), &f.owner.id());

    let checked = check_request(
        &msg,
        AUD,
        RESOLVER_BODY_TYPE,
        RESOLVER_BODY,
        None,
        &resolver,
        ClockTolerance::default(),
        T0,
    )
    .expect("checked");
    let chain = checked
        .caller()
        .chain()
        .expect("the caller carries the chain a Resolver verified");
    assert_eq!(chain.kind(), PrincipalKind::Human);
    assert_eq!(chain.principal(), &f.owner.id());
    assert_eq!(chain.principal(), checked.caller().principal());
    let mut cache = NonceCache::new(NonceCaps::default());
    let caller = checked.accept(&mut cache, T0).expect("fresh");
    assert_eq!(
        caller.chain().map(|c| c.kind()),
        Some(PrincipalKind::Human),
        "the chain survives accept"
    );
}

#[test]
fn c5_the_trusted_device_set_form_has_no_chain() {
    let r = rig();
    let signed = seal_request(&r.signer, AUD, BODY_TYPE, BODY).expect("sealing");
    let who = r
        .set
        .verify(&signed, AUD, When::Live { now: T0 })
        .expect("verifies");
    assert!(who.chain.is_none(), "a device set never builds a chain");
    let mut cache = NonceCache::new(NonceCaps::default());
    let caller = open(&signed, BODY, &r.set, &mut cache).expect("accepted");
    assert!(caller.chain().is_none());
}

// C6: the core applies no size limit of its own; the caller supplies one.

const EIGHT_MIB: usize = 8 * 1024 * 1024;

fn check_with_limit(
    r: &Rig,
    body: &[u8],
    max_body: Option<usize>,
) -> Result<crate::Checked, AuthError> {
    let signed = seal_request(&r.signer, AUD, BODY_TYPE, body).expect("sealing");
    check_request(
        &signed,
        AUD,
        BODY_TYPE,
        body,
        max_body,
        &r.set,
        ClockTolerance::default(),
        T0,
    )
}

#[test]
fn c6_a_body_over_a_given_limit_is_refused_and_one_at_the_limit_is_not() {
    let r = rig();
    let body = vec![3u8; 2048];
    assert!(matches!(
        check_with_limit(&r, &body, Some(2047)),
        Err(AuthError::BodyTooLarge {
            len: 2048,
            max: 2047
        })
    ));
    assert!(check_with_limit(&r, &body, Some(2048)).is_ok());
}

#[test]
fn c6_with_no_limit_an_8_mib_body_passes_the_core() {
    let r = rig();
    let body = vec![9u8; EIGHT_MIB];
    assert!(
        check_with_limit(&r, &body, None).is_ok(),
        "no limit given: no size check"
    );
    assert!(
        check_with_limit(&r, &body, Some(MAX_BODY_BYTES)).is_err(),
        "the same body is refused under the 4 MiB constant when it is asked for"
    );
}

#[test]
fn c6_the_frame_that_is_its_own_signed_body_over_4_mib_is_not_refused() {
    // The structmux case: the received bytes are the signed bytes (a frame, an
    // envelope or a response), larger than 4 MiB. With no limit given nothing
    // refuses on size, and the body cannot mismatch because it is the same value.
    let r = rig();
    let body = vec![5u8; MAX_BODY_BYTES + 1];
    let signed = seal_request(&r.signer, AUD, BODY_TYPE, &body).expect("sealing");
    assert_eq!(signed.body, body);
    let mut cache = NonceCache::new(NonceCaps::default());
    let caller = open_signed_request(
        &signed,
        AUD,
        BODY_TYPE,
        &signed.body,
        None,
        &r.set,
        &mut cache,
        ClockTolerance::default(),
        T0,
    );
    assert!(caller.is_ok(), "{caller:?}");
}

// C7: `check_request` has no side effect; `accept` alone consumes the nonce.

#[test]
fn c7_checked_exposes_the_nonce_issued_at_and_session_key_that_were_signed() {
    let r = rig();
    let signed = seal_request(&r.signer, AUD, BODY_TYPE, BODY).expect("sealing");
    let checked = check_with_limit(&r, BODY, None).expect("checked");
    let other = check_request(
        &signed,
        AUD,
        BODY_TYPE,
        BODY,
        None,
        &r.set,
        ClockTolerance::default(),
        T0,
    )
    .expect("checked");
    assert_eq!(other.nonce(), signed.nonce.as_slice());
    assert_eq!(other.issued_at(), signed.issued_at_unix_seconds);
    assert_eq!(other.issued_at(), other.caller().issued_at());
    let session = match signed.signer.as_ref().and_then(|s| s.chain.as_ref()) {
        Some(pb::signer_chain::Chain::SelfRooted(s)) => s
            .session
            .as_ref()
            .and_then(|c| c.session.as_ref())
            .expect("session key")
            .clone(),
        other => panic!("expected a self-rooted chain, got {other:?}"),
    };
    assert_eq!(
        other.session_key(),
        &PublicKey::try_from(&session).expect("a public key")
    );
    assert_eq!(other.nonce().len(), 16);
    assert_eq!(checked.nonce().len(), 16);
}

#[test]
fn c7_check_request_twice_succeeds_and_only_accept_consumes_the_nonce() {
    let r = rig();
    let signed = seal_request(&r.signer, AUD, BODY_TYPE, BODY).expect("sealing");
    let run = || {
        check_request(
            &signed,
            AUD,
            BODY_TYPE,
            BODY,
            None,
            &r.set,
            ClockTolerance::default(),
            T0,
        )
    };
    let first = run().expect("the first check");
    let second = run().expect("the second check: nothing was consumed");
    let mut cache = NonceCache::new(NonceCaps::default());
    assert!(cache.is_empty(), "check_request never touches a cache");
    first
        .accept(&mut cache, T0)
        .expect("a following accept is fresh");
    assert_eq!(cache.len(), 1);
    assert_eq!(
        second.accept(&mut cache, T0),
        Err(AuthError::Replayed),
        "a second accept of the same nonce is a replay"
    );
}

// Item 4: the verifier's own tolerance, either form.

#[test]
fn a_request_issued_31_seconds_ahead_is_refused_as_skew_with_tolerance_30() {
    let tolerance = ClockTolerance::new(30).expect("30 is allowed");
    let is_skew = |e: &AuthError| {
        matches!(
            e,
            AuthError::Skew | AuthError::Verify(identity_crypto::Error::Skew)
        )
    };

    // The device-set form: mint the session now, then issue 40 s later and
    // verify at 31 s before that issue time.
    let r = rig();
    let _ = seal_request(&r.signer, AUD, BODY_TYPE, BODY).expect("mints the session");
    r.clock.0.advance(40);
    let ahead = seal_request(&r.signer, AUD, BODY_TYPE, BODY).expect("sealing");
    assert_eq!(ahead.issued_at_unix_seconds, T0 + 40);
    let refused = check_request(
        &ahead,
        AUD,
        BODY_TYPE,
        BODY,
        None,
        &r.set,
        tolerance,
        T0 + 9,
    )
    .expect_err("31 s ahead");
    assert!(is_skew(&refused), "{refused:?}");

    // The Resolver form.
    let f = Fleet::new();
    let resolver = f.resolver();
    let msg = resolver_message(&f, T0 + 31);
    let refused = check_request(
        &msg,
        AUD,
        RESOLVER_BODY_TYPE,
        RESOLVER_BODY,
        None,
        &resolver,
        tolerance,
        T0,
    )
    .expect_err("31 s ahead");
    assert!(is_skew(&refused), "{refused:?}");

    // And 30 s ahead is still fine.
    let msg = resolver_message(&f, T0 + 30);
    assert!(check_request(
        &msg,
        AUD,
        RESOLVER_BODY_TYPE,
        RESOLVER_BODY,
        None,
        &resolver,
        tolerance,
        T0
    )
    .is_ok());
}
