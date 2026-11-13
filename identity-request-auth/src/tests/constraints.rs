//! The core's constraints from a fleet wire that has its own verifier (see the README, "Core constraints"):
//! each must hold so its fleet wire can switch to this core with its own tests
//! unchanged. Everything here runs without the `tonic` feature.

use crate::testkit::{FakeClock, TestPrincipal};
use crate::{
    open_signed_request, seal_request, AuthError, ClockTolerance, NonceCache, NonceCaps,
    SignerVerifier, TrustedDeviceSet, VerifiedSigner, PURGE_GRACE,
};
use identity_crypto::testkit::{owner_chain, signed_message, Fleet};
use identity_crypto::{pb, PublicKey, When, SKEW_SECONDS};
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
