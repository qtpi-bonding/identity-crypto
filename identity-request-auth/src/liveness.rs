use crate::LookupError;
use identity_crypto::{PublicKey, Timestamp};

/// The `KeyScheme` value for ECDSA P-256 keys.
const SCHEME_ECDSA_P256: i32 = 3;
/// The `KeyPurpose` value for device keys.
const PURPOSE_DEVICE: i32 = 2;

/// One key record from a principal's registry, as the lookup reads it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyRecord {
    pub scheme: i32,
    pub purpose: i32,
    pub public_key: PublicKey,
    pub issued_at: Option<Timestamp>,
    pub not_after: Option<Timestamp>,
    pub revoked_at: Option<Timestamp>,
}

/// `a < b` for two timestamps, compared as (seconds, nanos).
fn before(a: &Timestamp, b: &Timestamp) -> bool {
    (a.seconds, a.nanos) < (b.seconds, b.nanos)
}

/// `a <= b` for two timestamps, compared as (seconds, nanos).
fn not_after_eq(a: &Timestamp, b: &Timestamp) -> bool {
    (a.seconds, a.nanos) <= (b.seconds, b.nanos)
}

fn is_live(record: &KeyRecord, at: &Timestamp) -> bool {
    record.scheme == SCHEME_ECDSA_P256
        && record.purpose == PURPOSE_DEVICE
        && record
            .issued_at
            .as_ref()
            .is_some_and(|issued| not_after_eq(issued, at))
        && record
            .not_after
            .as_ref()
            .is_none_or(|expiry| before(at, expiry))
        && record
            .revoked_at
            .as_ref()
            .is_none_or(|revoked| before(at, revoked))
}

/// The device keys live at `at`: scheme ECDSA P-256, purpose device, issued at
/// or before `at`, not expired (`at` before `not_after`) and not revoked (`at`
/// before `revoked_at`). All comparisons are on (seconds, nanos).
///
/// An empty result is [`LookupError::Unknown`]; the layer answers
/// `UNAUTHENTICATED` for it.
pub fn live_devices(records: &[KeyRecord], at: Timestamp) -> Result<Vec<PublicKey>, LookupError> {
    let live: Vec<PublicKey> = records
        .iter()
        .filter(|record| is_live(record, &at))
        .map(|record| record.public_key.clone())
        .collect();
    if live.is_empty() {
        Err(LookupError::Unknown)
    } else {
        Ok(live)
    }
}
