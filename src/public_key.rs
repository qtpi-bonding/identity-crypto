//! Validated P-256 public keys (schema 2.1).

use crate::jwk_duo::{self, KeyPair as _};
use crate::{pb, Error, Result};

#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PublicKey {
    scheme: pb::KeyScheme,
    bytes: [u8; 65],
}

impl PublicKey {
    pub fn p256(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 65 {
            return Err(Error::BadLength { field: "key", expected: 65, actual: bytes.len() });
        }
        jwk_duo::Sec1PublicKey::import_p256(bytes)
            .map_err(|e| Error::InvalidKey(e.to_string()))?;
        let mut out = [0u8; 65];
        out.copy_from_slice(bytes);
        Ok(Self { scheme: pb::KeyScheme::EcdsaP256, bytes: out })
    }

    pub fn scheme(&self) -> pb::KeyScheme { self.scheme }
    pub fn as_bytes(&self) -> &[u8; 65] { &self.bytes }
    pub fn to_hex(&self) -> String { hex::encode(self.bytes) }

    /// RFC 7638 JWK thumbprint of `{crv, kty, x, y}` (SHA-256, base64url, unpadded, 43 chars):
    /// the `key_id` the jwk_duo convention derives for a `p256:` key.
    pub fn thumbprint(&self) -> String {
        jwk_duo::SigningKeyPair::import_public_key_raw(self.as_bytes())
            .and_then(|kp| kp.calculate_key_id())
            .expect("PublicKey is a validated SEC1 P-256 point, so jwk_duo import and thumbprint cannot fail")
    }

    pub fn from_hex(s: &str) -> Result<Self> {
        if s.len() != 130 || !s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
            return Err(Error::InvalidKey("expected 130 lowercase hex digits".into()));
        }
        let bytes = hex::decode(s).map_err(|e| Error::InvalidKey(e.to_string()))?;
        Self::p256(&bytes)
    }
}

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "p256:{}…", &self.to_hex()[..16])
    }
}

impl TryFrom<&pb::PublicKey> for PublicKey {
    type Error = Error;
    fn try_from(p: &pb::PublicKey) -> Result<Self> {
        match pb::KeyScheme::try_from(p.scheme) {
            Ok(pb::KeyScheme::EcdsaP256) => Self::p256(&p.key),
            _ => Err(Error::UnsupportedScheme(p.scheme)),
        }
    }
}

impl From<&PublicKey> for pb::PublicKey {
    fn from(k: &PublicKey) -> Self {
        pb::PublicKey { scheme: k.scheme as i32, key: k.bytes.to_vec() }
    }
}

impl From<&jwk_duo::SigningKeyPair> for PublicKey {
    fn from(k: &jwk_duo::SigningKeyPair) -> Self {
        Self { scheme: pb::KeyScheme::EcdsaP256, bytes: k.export_public_key_raw() }
    }
}

impl From<&jwk_duo::EncryptionKeyPair> for PublicKey {
    fn from(k: &jwk_duo::EncryptionKeyPair) -> Self {
        Self { scheme: pb::KeyScheme::EcdsaP256, bytes: k.export_public_key_raw() }
    }
}

impl serde::Serialize for PublicKey {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

impl<'de> serde::Deserialize<'de> for PublicKey {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PublicKeyDuo { signing: PublicKey, encryption: PublicKey }

impl PublicKeyDuo {
    pub fn new(signing: PublicKey, encryption: PublicKey) -> Result<Self> {
        if signing == encryption { return Err(Error::NotDistinct("duo halves")); }
        Ok(Self { signing, encryption })
    }
    pub fn signing(&self) -> &PublicKey { &self.signing }
    pub fn encryption(&self) -> &PublicKey { &self.encryption }
}

impl TryFrom<&pb::PublicKeyDuo> for PublicKeyDuo {
    type Error = Error;
    fn try_from(p: &pb::PublicKeyDuo) -> Result<Self> {
        let signing = p.signing.as_ref().ok_or(Error::MissingField("signing"))?;
        let encryption = p.encryption.as_ref().ok_or(Error::MissingField("encryption"))?;
        Self::new(PublicKey::try_from(signing)?, PublicKey::try_from(encryption)?)
    }
}

impl TryFrom<&jwk_duo::PublicKeyDuo> for PublicKeyDuo {
    type Error = Error;
    fn try_from(d: &jwk_duo::PublicKeyDuo) -> Result<Self> {
        let decode = |hex: &str| jwk_duo::Sec1PublicKey::decode_hex(hex)
            .map_err(|e| Error::InvalidKey(e.to_string()))
            .and_then(|raw| PublicKey::p256(&raw));
        Self::new(decode(d.signing.value())?, decode(d.encryption.value())?)
    }
}

impl From<&jwk_duo::KeyDuo> for PublicKeyDuo {
    fn from(d: &jwk_duo::KeyDuo) -> Self {
        Self { signing: PublicKey::from(d.signing_key_pair()), encryption: PublicKey::from(d.encryption_key_pair()) }
    }
}

impl From<&PublicKeyDuo> for pb::PublicKeyDuo {
    fn from(d: &PublicKeyDuo) -> Self {
        pb::PublicKeyDuo { signing: Some(pb::PublicKey::from(&d.signing)), encryption: Some(pb::PublicKey::from(&d.encryption)) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwk_duo::{GenerationService, SigningKeyPair};

    fn valid() -> PublicKey {
        PublicKey::from(&SigningKeyPair::generate())
    }

    #[test]
    fn accepts_a_generated_key_and_round_trips_hex() {
        let k = valid();
        assert_eq!(k.scheme(), pb::KeyScheme::EcdsaP256);
        assert_eq!(k.to_hex().len(), 130);
        assert_eq!(PublicKey::from_hex(&k.to_hex()).unwrap(), k);
        assert_eq!(PublicKey::p256(k.as_bytes()).unwrap(), k);
    }

    #[test]
    fn rejects_wrong_lengths() {
        let k = valid();
        for len in [0usize, 1, 33, 64, 66] {
            let mut b = k.as_bytes().to_vec();
            b.resize(len, 0);
            assert_eq!(
                PublicKey::p256(&b),
                Err(Error::BadLength { field: "key", expected: 65, actual: len }),
                "len {len}"
            );
        }
    }

    #[test]
    fn rejects_a_single_zero_byte() {
        assert_eq!(PublicKey::p256(&[0]), Err(Error::BadLength { field: "key", expected: 65, actual: 1 }));
    }

    #[test]
    fn rejects_off_curve_and_wrong_tag() {
        let mut off = [0u8; 65];
        off[0] = 0x04;
        assert!(matches!(PublicKey::p256(&off), Err(Error::InvalidKey(_))));
        let mut tag = *valid().as_bytes();
        tag[0] = 0x02;
        assert!(matches!(PublicKey::p256(&tag), Err(Error::InvalidKey(_))));
    }

    #[test]
    fn from_hex_is_strict_lowercase() {
        let k = valid();
        assert!(matches!(PublicKey::from_hex(&k.to_hex().to_uppercase()), Err(Error::InvalidKey(_))));
        assert!(matches!(PublicKey::from_hex(&k.to_hex()[..128]), Err(Error::InvalidKey(_))));
        assert!(matches!(PublicKey::from_hex("zz"), Err(Error::InvalidKey(_))));
    }

    #[test]
    fn proto_conversion_checks_the_scheme() {
        let k = valid();
        let p = pb::PublicKey::from(&k);
        assert_eq!(PublicKey::try_from(&p).unwrap(), k);
        for scheme in [1, pb::KeyScheme::Unspecified as i32, 2, 99] {
            let bad = pb::PublicKey { scheme, key: p.key.clone() };
            assert_eq!(PublicKey::try_from(&bad), Err(Error::UnsupportedScheme(scheme)));
        }
    }

    #[test]
    fn serde_is_the_hex_string_and_strict() {
        let k = valid();
        let json = serde_json::to_string(&k).unwrap();
        assert_eq!(json, format!("\"{}\"", k.to_hex()));
        assert_eq!(serde_json::from_str::<PublicKey>(&json).unwrap(), k);
        let upper = format!("\"{}\"", k.to_hex().to_uppercase());
        assert!(serde_json::from_str::<PublicKey>(&upper).is_err());
    }

    #[test]
    fn debug_is_short() {
        let k = valid();
        assert_eq!(format!("{k:?}"), format!("p256:{}…", &k.to_hex()[..16]));
    }

    #[test]
    fn duo_rejects_equal_halves_and_converts() {
        let a = valid();
        assert_eq!(PublicKeyDuo::new(a.clone(), a.clone()), Err(Error::NotDistinct("duo halves")));
        let duo = GenerationService::generate_key_duo();
        let d = PublicKeyDuo::from(&duo);
        assert_eq!(d.signing(), &PublicKey::from(duo.signing_key_pair()));
        assert_eq!(d.encryption(), &PublicKey::from(duo.encryption_key_pair()));
        let p = pb::PublicKeyDuo::from(&d);
        assert_eq!(PublicKeyDuo::try_from(&p).unwrap(), d);
        let jwk_public = duo.export_public_key_duo();
        assert_eq!(PublicKeyDuo::try_from(&jwk_public).unwrap(), d);
        let missing = pb::PublicKeyDuo { signing: None, encryption: p.encryption.clone() };
        assert_eq!(PublicKeyDuo::try_from(&missing), Err(Error::MissingField("signing")));
        let same = pb::PublicKeyDuo { signing: p.signing.clone(), encryption: p.signing.clone() };
        assert_eq!(PublicKeyDuo::try_from(&same), Err(Error::NotDistinct("duo halves")));
    }

    #[test]
    fn thumbprint_matches_jwk_duo_key_id() {
        use crate::jwk_duo::KeyPair as _;
        let kp = SigningKeyPair::generate();
        assert_eq!(PublicKey::from(&kp).thumbprint(), kp.calculate_key_id().unwrap());
    }

    #[test]
    fn thumbprint_is_43_chars_unpadded() {
        for _ in 0..16 {
            let t = valid().thumbprint();
            assert_eq!(t.len(), 43, "{t}");
            assert!(!t.contains('='), "{t}");
            assert!(t.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'), "{t}");
        }
    }

    #[test]
    fn distinct_keys_distinct_thumbprints() {
        let a = valid();
        let b = valid();
        assert_ne!(a, b);
        assert_ne!(a.thumbprint(), b.thumbprint());
        assert_eq!(a.thumbprint(), a.clone().thumbprint());
    }
}