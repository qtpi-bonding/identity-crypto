//! Principal ids `p256:<130 lowercase hex>` and their 8-byte short ids
//! (schema 2.1). Principal ids are never compared as strings.

use crate::{Error, PublicKey, Result};
use sha2::{Digest, Sha256};

const PREFIX: &str = "p256:";

#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PrincipalId {
    genesis: PublicKey,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ShortId([u8; 8]);

impl PrincipalId {
    pub fn from_genesis(genesis: PublicKey) -> Self { Self { genesis } }
    pub fn genesis(&self) -> &PublicKey { &self.genesis }

    /// Human input: the prefix and the hex are ASCII case-insensitive.
    pub fn parse(s: &str) -> Result<Self> {
        let malformed = |why: &str| Error::MalformedPrincipal(why.to_string());
        let prefix = s.get(..PREFIX.len()).ok_or_else(|| malformed("missing p256: prefix"))?;
        if !prefix.eq_ignore_ascii_case(PREFIX) {
            return Err(malformed("missing p256: prefix"));
        }
        let hex_part = &s[PREFIX.len()..];
        if hex_part.len() != 130 {
            return Err(malformed("expected 130 hex digits"));
        }
        let bytes = hex::decode(hex_part).map_err(|_| malformed("not hex"))?;
        Ok(Self { genesis: PublicKey::p256(&bytes)? })
    }

    pub fn parse_canonical(s: &str) -> Result<Self> {
        let id = Self::parse(s)?;
        if id.to_string() != s { return Err(Error::NonCanonicalPrincipal); }
        Ok(id)
    }

    pub fn short_id(&self) -> ShortId {
        let digest = Sha256::digest(self.genesis.as_bytes());
        let mut out = [0u8; 8];
        out.copy_from_slice(&digest[..8]);
        ShortId(out)
    }
}

impl std::fmt::Display for PrincipalId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{PREFIX}{}", self.genesis.to_hex())
    }
}

impl std::fmt::Debug for PrincipalId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "{:?}", self.genesis) }
}

impl ShortId {
    pub fn parse(s: &str) -> Result<Self> {
        if s.len() != 16 { return Err(Error::MalformedShortId("expected 16 hex digits".into())); }
        let bytes = hex::decode(s).map_err(|_| Error::MalformedShortId("not hex".into()))?;
        let mut out = [0u8; 8];
        out.copy_from_slice(&bytes);
        Ok(Self(out))
    }

    pub fn parse_canonical(s: &str) -> Result<Self> {
        if !s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
            return Err(Error::MalformedShortId("expected lowercase hex".into()));
        }
        Self::parse(s)
    }

    pub fn as_bytes(&self) -> &[u8; 8] { &self.0 }
}

impl std::fmt::Display for ShortId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str(&hex::encode(self.0)) }
}

impl std::fmt::Debug for ShortId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { std::fmt::Display::fmt(self, f) }
}

macro_rules! canonical_string_serde {
    ($t:ty) => {
        impl serde::Serialize for $t {
            fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> { s.collect_str(self) }
        }
        impl<'de> serde::Deserialize<'de> for $t {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
                let s = String::deserialize(d)?;
                <$t>::parse_canonical(&s).map_err(serde::de::Error::custom)
            }
        }
    };
}
canonical_string_serde!(PrincipalId);
canonical_string_serde!(ShortId);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwk_duo::SigningKeyPair;
    use sha2::{Digest, Sha256};

    fn id() -> PrincipalId {
        PrincipalId::from_genesis(PublicKey::from(&SigningKeyPair::generate()))
    }

    #[test]
    fn display_and_parse_round_trip() {
        let p = id();
        let s = p.to_string();
        assert_eq!(s.len(), 135);
        assert!(s.starts_with("p256:"));
        assert_eq!(PrincipalId::parse(&s).unwrap(), p);
        assert_eq!(PrincipalId::parse_canonical(&s).unwrap(), p);
    }

    #[test]
    fn parse_is_case_insensitive_and_canonical_is_not() {
        let p = id();
        let upper_hex = format!("p256:{}", p.genesis().to_hex().to_uppercase());
        let upper_prefix = format!("P256:{}", p.genesis().to_hex());
        assert_eq!(PrincipalId::parse(&upper_hex).unwrap(), p);
        assert_eq!(PrincipalId::parse(&upper_prefix).unwrap(), p);
        assert_eq!(PrincipalId::parse_canonical(&upper_hex), Err(Error::NonCanonicalPrincipal));
        assert_eq!(PrincipalId::parse_canonical(&upper_prefix), Err(Error::NonCanonicalPrincipal));
    }

    #[test]
    fn malformed_inputs() {
        let hex = id().genesis().to_hex();
        for bad in [
            format!("p384:{hex}"),
            format!("p256:{}", &hex[..129]),
            format!("p256:{hex}0"),
            "p256:00".to_string(),
            format!("p256:{}", &hex[2..]),
            "p256".to_string(),
            String::new(),
            format!("p256:{}zz", &hex[..128]),
        ] {
            assert!(matches!(PrincipalId::parse(&bad), Err(Error::MalformedPrincipal(_))), "{bad}");
        }
        let off_curve = format!("p256:04{}", "00".repeat(64));
        assert!(matches!(PrincipalId::parse(&off_curve), Err(Error::InvalidKey(_))));
    }

    #[test]
    fn non_ascii_never_panics() {
        for bad in ["p256é", "p25é:abc", "é", "p256:é"] {
            assert!(matches!(PrincipalId::parse(bad), Err(Error::MalformedPrincipal(_))), "{bad}");
        }
        let sixteen_bytes = "ééééééééb"; // 8 two-byte chars + 'b' = 17 bytes
        assert!(matches!(ShortId::parse(sixteen_bytes), Err(Error::MalformedShortId(_))));
        assert!(matches!(ShortId::parse("éééééééé"), Err(Error::MalformedShortId(_)))); // 16 bytes
    }

    #[test]
    fn short_id_is_sha256_of_key_bytes() {
        let p = id();
        let digest = Sha256::digest(p.genesis().as_bytes());
        assert_eq!(p.short_id().as_bytes(), &digest[..8]);
        assert_eq!(p.short_id().to_string(), hex::encode(&digest[..8]));
    }

    #[test]
    fn short_id_parsing() {
        // Fixed value with letters, so to_uppercase always changes it.
        let text = "0123456789abcdef".to_string();
        let s = ShortId::parse(&text).unwrap();
        assert_eq!(s.to_string(), text);
        assert_eq!(ShortId::parse(&text).unwrap(), s);
        assert_eq!(ShortId::parse(&text.to_uppercase()).unwrap(), s);
        assert_eq!(ShortId::parse_canonical(&text).unwrap(), s);
        assert!(matches!(ShortId::parse_canonical(&text.to_uppercase()), Err(Error::MalformedShortId(_))));
        assert!(matches!(ShortId::parse(&text[..15]), Err(Error::MalformedShortId(_))));
        assert!(matches!(ShortId::parse("zzzzzzzzzzzzzzzz"), Err(Error::MalformedShortId(_))));
    }

    #[test]
    fn serde_is_canonical_and_strict() {
        let p = id();
        let json = serde_json::to_string(&p).unwrap();
        assert_eq!(json, format!("\"{p}\""));
        assert_eq!(serde_json::from_str::<PrincipalId>(&json).unwrap(), p);
        assert!(serde_json::from_str::<PrincipalId>(&json.to_uppercase()).is_err());
        let s = ShortId::parse("0123456789abcdef").unwrap();
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(serde_json::from_str::<ShortId>(&json).unwrap(), s);
        assert!(serde_json::from_str::<ShortId>(&json.to_uppercase()).is_err());
    }

    #[test]
    fn usable_as_map_keys() {
        let (a, b) = (id(), id());
        let mut m = std::collections::BTreeMap::new();
        m.insert(a.clone(), 1);
        m.insert(b.clone(), 2);
        let mut h = std::collections::HashSet::new();
        h.insert(a.short_id());
        h.insert(b.short_id());
        assert_eq!((m.len(), h.len()), (2, 2));
    }
}
