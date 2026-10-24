//! `google.protobuf.Timestamp` as the attestation carries it.
//!
//! prost-build and pbjson-build map `.google.protobuf` to this module (see
//! `build.rs`), so generated code uses this type instead of
//! `pbjson-types`. The only reason it exists: `pbjson-types` 0.7 writes
//! chrono's `to_rfc3339()`, which is `+00:00`, while proto3-JSON and the
//! concordat data-format rule want `Z`. Parsing is chrono's
//! `parse_from_rfc3339`, so every RFC 3339 spelling (offset or `Z`) is
//! accepted.

use chrono::{DateTime, SecondsFormat, Utc};
use serde::de::Error as _;
use serde::ser::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Seconds since the Unix epoch plus nanoseconds in `0..1_000_000_000`.
#[derive(Clone, Copy, PartialEq, Eq, prost::Message)]
pub struct Timestamp {
    #[prost(int64, tag = "1")]
    pub seconds: i64,
    #[prost(int32, tag = "2")]
    pub nanos: i32,
}

impl Serialize for Timestamp {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let nanos = u32::try_from(self.nanos)
            .ok()
            .filter(|n| *n < 1_000_000_000)
            .ok_or_else(|| S::Error::custom("attested_at.nanos out of range"))?;
        // RFC 3339 spans years 0001..=9999; wider values would not parse back.
        if !(-62_135_596_800..=253_402_300_799).contains(&self.seconds) {
            return Err(S::Error::custom("attested_at.seconds out of range"));
        }
        let at = DateTime::<Utc>::from_timestamp(self.seconds, nanos)
            .ok_or_else(|| S::Error::custom("attested_at.seconds out of range"))?;
        // AutoSi: 0, 3, 6 or 9 fractional digits, none when the nanos are zero.
        serializer.serialize_str(&at.to_rfc3339_opts(SecondsFormat::AutoSi, true))
    }
}

impl<'de> Deserialize<'de> for Timestamp {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        let at = DateTime::parse_from_rfc3339(&text)
            .map_err(D::Error::custom)?
            .with_timezone(&Utc);
        let nanos = at.timestamp_subsec_nanos();
        if nanos >= 1_000_000_000 {
            return Err(D::Error::custom("leap seconds are not representable"));
        }
        Ok(Timestamp { seconds: at.timestamp(), nanos: nanos as i32 })
    }
}
