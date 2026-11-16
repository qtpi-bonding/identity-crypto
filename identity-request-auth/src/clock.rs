use crate::AuthError;
use identity_crypto::Timestamp;

/// The time, to the nanosecond. Injected everywhere the crate needs the time.
/// There is no default and no seconds-only form: `now` is required.
///
/// ```compile_fail,E0046
/// struct S;
/// impl identity_request_auth::Clock for S {}
/// ```
pub trait Clock: Send + Sync {
    fn now(&self) -> Timestamp;
}

/// The operating system's wall clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Timestamp {
        identity_crypto::now_timestamp()
    }
}

/// How far a message's `issued_at` may be from the verifier's clock. It can
/// only tighten identity-crypto's fixed 30 s (`SKEW_SECONDS`); a larger value
/// is refused, never accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClockTolerance(i64);

impl ClockTolerance {
    /// identity-crypto's fixed skew, the most a tolerance may allow.
    pub const MAX_SECONDS: i64 = identity_crypto::SKEW_SECONDS;

    /// Accepts `1..=30` seconds.
    pub fn new(seconds: i64) -> Result<Self, AuthError> {
        if (1..=Self::MAX_SECONDS).contains(&seconds) {
            Ok(Self(seconds))
        } else {
            Err(AuthError::Tolerance {
                seconds,
                max: Self::MAX_SECONDS,
            })
        }
    }

    pub fn seconds(self) -> i64 {
        self.0
    }
}

impl Default for ClockTolerance {
    fn default() -> Self {
        Self(identity_crypto::SKEW_SECONDS)
    }
}
