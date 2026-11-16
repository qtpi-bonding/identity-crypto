//! The one wall-clock read in this crate.

use crate::wkt::Timestamp;
use std::time::{SystemTime, UNIX_EPOCH};

/// The current wall-clock time as a `Timestamp`. A clock set before the
/// epoch reads as `Timestamp { seconds: 0, nanos: 0 }`.
pub fn now_timestamp() -> Timestamp {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => Timestamp {
            seconds: i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
            nanos: d.subsec_nanos() as i32,
        },
        Err(_) => Timestamp {
            seconds: 0,
            nanos: 0,
        },
    }
}

/// The current wall-clock time in unix seconds.
pub fn now_unix() -> i64 {
    now_timestamp().seconds
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn now_timestamp_is_after_2026_and_now_unix_agrees() {
        let t = now_timestamp();
        assert!(t.seconds > 1_780_000_000);
        assert!((now_unix() - t.seconds).abs() <= 1);
    }
}
