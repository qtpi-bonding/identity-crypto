//! The canonical numeric mapping for the `scheme` byte every transcript in
//! [`crate::transcripts`] embeds. `KeyScheme` is independently redefined as
//! its own proto enum in grorg, gait, and multimatrix (each repo owns its
//! own piece of the design, so importing one shared proto enum was a
//! deliberate earlier call, not an oversight) -- but all three numeric
//! values must still agree, because a transcript encodes `scheme as u8`
//! directly into a byte a signature covers. If any one repo's proto enum
//! ever drifts from the others (a new scheme added to a different slot,
//! say), every signature crossing that repo boundary breaks silently, with
//! no compile error -- the exact bug class this crate exists to prevent for
//! the transcript bytes, showing up one level up in the discriminant that
//! feeds them.
//!
//! This type is NOT meant to replace each repo's own proto-generated enum
//! -- it's a canonical reference each repo's own enum should be tested
//! against (`assert_eq!(some_proto::KeyScheme::Ed25519 as i32,
//! identity_crypto::KeyScheme::Ed25519 as i32)`), turning silent drift into
//! a loud, local test failure in whichever repo caused it.

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyScheme {
    Unspecified = 0,
    Ed25519 = 1,
    Secp256k1Schnorr = 2,
}

impl TryFrom<i32> for KeyScheme {
    type Error = anyhow::Error;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(KeyScheme::Unspecified),
            1 => Ok(KeyScheme::Ed25519),
            2 => Ok(KeyScheme::Secp256k1Schnorr),
            other => Err(anyhow::anyhow!("unknown KeyScheme discriminant: {other}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discriminants_are_pinned() {
        // These exact values are load-bearing: every transcript in this
        // crate serializes a scheme as a raw byte. Changing any of these
        // numbers is a breaking change for every repo that depends on this
        // crate, not a routine edit.
        assert_eq!(KeyScheme::Unspecified as i32, 0);
        assert_eq!(KeyScheme::Ed25519 as i32, 1);
        assert_eq!(KeyScheme::Secp256k1Schnorr as i32, 2);
    }

    #[test]
    fn try_from_round_trips_every_known_value() {
        assert_eq!(KeyScheme::try_from(0).unwrap(), KeyScheme::Unspecified);
        assert_eq!(KeyScheme::try_from(1).unwrap(), KeyScheme::Ed25519);
        assert_eq!(KeyScheme::try_from(2).unwrap(), KeyScheme::Secp256k1Schnorr);
    }

    #[test]
    fn unknown_discriminant_errors_rather_than_silently_mapping() {
        assert!(KeyScheme::try_from(99).is_err());
    }
}
