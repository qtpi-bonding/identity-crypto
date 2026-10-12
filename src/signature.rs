//! The one P-256 signature check. Signers call `jwk_duo` directly over the
//! transcript bytes; there is no signing wrapper here.

use crate::{jwk_duo, Error, PublicKey, Result};
use sha2::{Digest, Sha256};

/// Proof that `verify_p256` succeeded for this key and message. It has no
/// public constructor, so code that requires one cannot skip the check:
///
/// ```compile_fail,E0451
/// use identity_crypto::{PublicKey, VerifiedSignature};
/// fn forge(k: PublicKey) -> VerifiedSignature {
///     VerifiedSignature { key: k, message_sha256: [0; 32] }
/// }
/// ```
#[derive(Debug, Clone)]
pub struct VerifiedSignature {
    key: PublicKey,
    message_sha256: [u8; 32],
}

impl VerifiedSignature {
    pub fn public_key(&self) -> &PublicKey {
        &self.key
    }

    /// Whether this witness is for exactly `message`.
    pub fn covers(&self, message: &[u8]) -> bool {
        Sha256::digest(message).as_slice() == self.message_sha256
    }
}

/// `signature` is 64-byte `r‖s`. Hardware callers convert DER first with
/// `jwk_duo::SigningKeyPair::signature_from_der`. Both S forms verify
/// (schema 2.1: signatures are never identifiers).
pub fn verify_p256(key: &PublicKey, message: &[u8], signature: &[u8]) -> Result<VerifiedSignature> {
    if signature.is_empty() {
        return Err(Error::EmptySignature);
    }
    if signature.len() != 64 {
        return Err(Error::BadLength { field: "signature", expected: 64, actual: signature.len() });
    }
    let verifier = jwk_duo::SigningKeyPair::import_public_key_raw(key.as_bytes())
        .map_err(|e| Error::InvalidKey(e.to_string()))?;
    if !verifier.verify_bytes(signature, message) {
        return Err(Error::BadSignature);
    }
    let mut message_sha256 = [0u8; 32];
    message_sha256.copy_from_slice(&Sha256::digest(message));
    Ok(VerifiedSignature { key: key.clone(), message_sha256 })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwk_duo::SigningKeyPair;

    const N: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
    ];

    /// n − s, big-endian, for the high-S twin.
    fn negate(s: &[u8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        let mut borrow = 0i16;
        for i in (0..32).rev() {
            let mut d = N[i] as i16 - s[i] as i16 - borrow;
            borrow = if d < 0 { d += 256; 1 } else { 0 };
            out[i] = d as u8;
        }
        out
    }

    fn signed(msg: &[u8]) -> (PublicKey, [u8; 64]) {
        let kp = SigningKeyPair::generate();
        (PublicKey::from(&kp), kp.sign_bytes(msg).unwrap())
    }

    #[test]
    fn good_signature_yields_a_witness_bound_to_key_and_message() {
        let (k, sig) = signed(b"hello");
        let v = verify_p256(&k, b"hello", &sig).unwrap();
        assert_eq!(v.public_key(), &k);
        assert!(v.covers(b"hello"));
        assert!(!v.covers(b"hellO"));
    }

    #[test]
    fn rejections() {
        let (k, sig) = signed(b"hello");
        assert_eq!(verify_p256(&k, b"hellO", &sig).unwrap_err(), Error::BadSignature);
        let (other, _) = signed(b"x");
        assert_eq!(verify_p256(&other, b"hello", &sig).unwrap_err(), Error::BadSignature);
        assert_eq!(verify_p256(&k, b"hello", &[]).unwrap_err(), Error::EmptySignature);
        for len in [63usize, 65] {
            let mut s = sig.to_vec();
            s.resize(len, 0);
            assert_eq!(
                verify_p256(&k, b"hello", &s).unwrap_err(),
                Error::BadLength { field: "signature", expected: 64, actual: len }
            );
        }
        let der = SigningKeyPair::signature_to_der(&sig).unwrap();
        assert!(matches!(verify_p256(&k, b"hello", &der), Err(Error::BadLength { .. })));
    }

    #[test]
    fn both_s_forms_verify() {
        let (k, sig) = signed(b"hello");
        let mut twin = sig;
        twin[32..].copy_from_slice(&negate(&sig[32..]));
        assert_ne!(twin, sig);
        // Exactly one of the pair is high-S (s > n/2), whichever the signer produced.
        let mut half_n = N;
        let mut carry = 0u8;
        for b in half_n.iter_mut() {
            let v = (carry << 7) | (*b >> 1);
            carry = *b & 1;
            *b = v;
        }
        let high = |s: &[u8]| s > &half_n[..];
        assert_ne!(high(&sig[32..]), high(&twin[32..]));
        assert!(verify_p256(&k, b"hello", &sig).is_ok());
        assert!(verify_p256(&k, b"hello", &twin).is_ok());
    }

    #[test]
    fn degenerate_scalars_are_bad_signatures_not_panics() {
        let (k, sig) = signed(b"hello");
        let mut zero_r = sig;
        zero_r[..32].fill(0);
        let mut zero_s = sig;
        zero_s[32..].fill(0);
        let mut s_is_n = sig;
        s_is_n[32..].copy_from_slice(&N);
        let ones = [0xffu8; 64];
        for bad in [zero_r, zero_s, s_is_n, ones] {
            assert_eq!(verify_p256(&k, b"hello", &bad).unwrap_err(), Error::BadSignature);
        }
    }
}
