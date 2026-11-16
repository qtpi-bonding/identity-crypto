//! Task 11: required `Clock::now()` and nanosecond-exact device liveness.

use crate::{live_devices, Clock, KeyRecord, LookupError, SystemClock};
use identity_crypto::{jwk_duo::SigningKeyPair, PublicKey, Timestamp};

const S: i64 = 1_800_000_000;

fn ts(seconds: i64, nanos: i32) -> Timestamp {
    Timestamp { seconds, nanos }
}

fn key() -> PublicKey {
    PublicKey::from(&SigningKeyPair::generate())
}

/// A live-looking device record (scheme 3, purpose 2, issued 10 s ago, no
/// expiry) with the given revocation.
fn rec(revoked: Option<(i64, i32)>) -> KeyRecord {
    KeyRecord {
        scheme: 3,
        purpose: 2,
        public_key: key(),
        issued_at: Some(ts(S - 10, 0)),
        not_after: None,
        revoked_at: revoked.map(|(s, n)| ts(s, n)),
    }
}

#[test]
fn live_devices_revoked_earlier_in_same_second_refused() {
    assert_eq!(
        live_devices(&[rec(Some((S, 500_000_000)))], ts(S, 700_000_000)),
        Err(LookupError::Unknown)
    );
}

#[test]
fn live_devices_revoked_later_in_same_second_accepted() {
    assert_eq!(
        live_devices(&[rec(Some((S, 500_000_000)))], ts(S, 300_000_000))
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn live_devices_revoked_at_exactly_refused() {
    assert_eq!(
        live_devices(&[rec(Some((S, 500_000_000)))], ts(S, 500_000_000)),
        Err(LookupError::Unknown)
    );
}

#[test]
fn live_devices_filters_scheme_purpose_issued_not_after() {
    let at = ts(S, 0);
    let mut wrong_scheme = rec(None);
    wrong_scheme.scheme = 0;
    let mut wrong_purpose = rec(None);
    wrong_purpose.purpose = 1;
    let mut no_issue = rec(None);
    no_issue.issued_at = None;
    let mut issued_later = rec(None);
    issued_later.issued_at = Some(ts(S, 1));
    let mut expired_exactly = rec(None);
    expired_exactly.not_after = Some(at);
    assert_eq!(
        live_devices(
            &[
                wrong_scheme,
                wrong_purpose,
                no_issue,
                issued_later,
                expired_exactly
            ],
            at
        ),
        Err(LookupError::Unknown),
        "every one is excluded"
    );

    let mut issued_now = rec(None);
    issued_now.issued_at = Some(at);
    let expected = issued_now.public_key.clone();
    assert_eq!(live_devices(&[issued_now], at), Ok(vec![expected]));
}

#[test]
fn live_devices_empty_is_unknown() {
    assert_eq!(live_devices(&[], ts(S, 0)), Err(LookupError::Unknown));
}

#[test]
fn system_clock_carries_nanoseconds() {
    assert!((0..1000).any(|_| SystemClock.now().nanos != 0));
}
