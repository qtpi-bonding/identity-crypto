//! The signing seam. `Signer` is what a key holder implements; the crate's
//! builders sign through `sign_transcript`, so a backend can prompt, delegate
//! to hardware, or refuse. `verify_signature` checks a `Signature` by the
//! key's own scheme.

use crate::jwk_duo::{self, KeyPair as _};
use crate::{verify_p256, Error, PublicKey, Result, VerifiedSignature};
use std::sync::Arc;

/// Something that holds a signing key. The algorithm is carried in the key
/// (`PublicKey::scheme()`).
pub trait Signer: Send + Sync {
    fn public_key(&self) -> PublicKey;
    fn sign(&self, message: &[u8]) -> std::result::Result<Signature, SignerError>;
    /// `reason` is user-facing text a prompting backend may show; the default ignores it.
    fn sign_for(&self, message: &[u8], reason: &str) -> std::result::Result<Signature, SignerError> {
        let _ = reason;
        self.sign(message)
    }
}

/// A raw 64-byte P-256 signature (`r || s`).
#[derive(Clone, PartialEq, Eq)]
pub struct Signature(Vec<u8>);

impl Signature {
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl std::fmt::Debug for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Signature({} bytes)", self.0.len())
    }
}

/// Why a `Signer` could not produce a signature.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SignerError {
    #[error("signing was cancelled")]
    Cancelled,
    #[error("the signing key is unavailable")]
    Unavailable,
    #[error("the signing backend failed: {0}")]
    Backend(String),
}

fn sign_with_pair(pair: &jwk_duo::SigningKeyPair, message: &[u8]) -> std::result::Result<Signature, SignerError> {
    if !pair.has_private_key() {
        return Err(SignerError::Unavailable);
    }
    pair.sign_bytes(message)
        .map(|bytes| Signature::from_bytes(bytes.to_vec()))
        .map_err(|e| SignerError::Backend(e.to_string()))
}

impl Signer for jwk_duo::SigningKeyPair {
    fn public_key(&self) -> PublicKey {
        PublicKey::from(self)
    }

    fn sign(&self, message: &[u8]) -> std::result::Result<Signature, SignerError> {
        sign_with_pair(self, message)
    }
}

impl Signer for jwk_duo::KeyDuo {
    fn public_key(&self) -> PublicKey {
        PublicKey::from(self.signing_key_pair())
    }

    fn sign(&self, message: &[u8]) -> std::result::Result<Signature, SignerError> {
        sign_with_pair(self.signing_key_pair(), message)
    }
}

impl<S: Signer + ?Sized> Signer for &S {
    fn public_key(&self) -> PublicKey {
        (**self).public_key()
    }

    fn sign(&self, message: &[u8]) -> std::result::Result<Signature, SignerError> {
        (**self).sign(message)
    }

    fn sign_for(&self, message: &[u8], reason: &str) -> std::result::Result<Signature, SignerError> {
        (**self).sign_for(message, reason)
    }
}

impl<S: Signer + ?Sized> Signer for Box<S> {
    fn public_key(&self) -> PublicKey {
        (**self).public_key()
    }

    fn sign(&self, message: &[u8]) -> std::result::Result<Signature, SignerError> {
        (**self).sign(message)
    }

    fn sign_for(&self, message: &[u8], reason: &str) -> std::result::Result<Signature, SignerError> {
        (**self).sign_for(message, reason)
    }
}

impl<S: Signer + ?Sized> Signer for Arc<S> {
    fn public_key(&self) -> PublicKey {
        (**self).public_key()
    }

    fn sign(&self, message: &[u8]) -> std::result::Result<Signature, SignerError> {
        (**self).sign(message)
    }

    fn sign_for(&self, message: &[u8], reason: &str) -> std::result::Result<Signature, SignerError> {
        (**self).sign_for(message, reason)
    }
}

/// Verifies `signature` over `message` under `key`, by the key's own scheme.
pub fn verify_signature(key: &PublicKey, message: &[u8], signature: &Signature) -> Result<VerifiedSignature> {
    match key.scheme() {
        crate::pb::KeyScheme::EcdsaP256 => verify_p256(key, message, signature.as_bytes()),
        _ => Err(Error::UnsupportedScheme(key.scheme() as i32)),
    }
}

/// The one signing helper every builder uses: maps `SignerError` to `Error::Signer`.
pub(crate) fn sign_transcript<S: Signer + ?Sized>(signer: &S, transcript: &[u8]) -> Result<Vec<u8>> {
    signer
        .sign(transcript)
        .map(Signature::into_bytes)
        .map_err(Error::Signer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwk_duo::{GenerationService, KeyDuo, SigningKeyPair};
    use crate::{challenge_proof, signing_public, verify_p256, Error, PublicKey};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    fn duo() -> KeyDuo {
        GenerationService::generate_key_duo()
    }

    #[test]
    fn signer_keyduo_and_keypair_agree() {
        let duo = GenerationService::generate_key_duo();
        assert_eq!(
            Signer::public_key(&duo),
            Signer::public_key(duo.signing_key_pair())
        );
        let s = Signer::sign(&duo, b"m").unwrap();
        verify_p256(&Signer::public_key(&duo), b"m", s.as_bytes()).unwrap();
        verify_signature(&Signer::public_key(&duo), b"m", &s).unwrap();
    }

    #[test]
    fn public_only_signer_fails_with_signer_error() {
        let p = SigningKeyPair::import_public_key_raw(signing_public(&duo()).as_bytes()).unwrap();
        assert_eq!(Signer::sign(&p, b"m"), Err(SignerError::Unavailable));
        assert_eq!(
            sign_transcript(&p, b"m").unwrap_err(),
            Error::Signer(SignerError::Unavailable)
        );
    }

    struct Counting {
        calls: AtomicUsize,
        key: PublicKey,
    }

    impl Signer for Counting {
        fn public_key(&self) -> PublicKey {
            self.key.clone()
        }
        fn sign(&self, _message: &[u8]) -> std::result::Result<Signature, SignerError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(Signature::from_bytes(vec![1, 2, 3]))
        }
    }

    #[test]
    fn sign_for_defaults_to_sign() {
        let c = Counting {
            calls: AtomicUsize::new(0),
            key: signing_public(&duo()),
        };
        let s = c.sign_for(b"m", "approve this").unwrap();
        assert_eq!(s.as_bytes(), &[1, 2, 3]);
        assert_eq!(c.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn arc_and_box_and_ref_forward() {
        let d = duo();
        let expected = signing_public(&d);
        let arc: Arc<dyn Signer> = Arc::new(d);
        assert_eq!(arc.public_key(), expected);
        let s = arc.sign(b"m").unwrap();
        verify_signature(&expected, b"m", &s).unwrap();

        let boxed: Box<dyn Signer> = Box::new(duo());
        let boxed_key = boxed.public_key();
        let s = boxed.sign(b"m").unwrap();
        verify_signature(&boxed_key, b"m", &s).unwrap();

        let inner = duo();
        let inner_key = signing_public(&inner);
        let by_ref: &dyn Signer = &inner;
        assert_eq!(by_ref.public_key(), inner_key);
        let s = by_ref.sign(b"m").unwrap();
        verify_signature(&inner_key, b"m", &s).unwrap();

        // The blanket impls themselves, not just auto-deref.
        assert_eq!(Signer::public_key(&&inner), inner_key);
        let arc2 = Arc::new(duo());
        assert_eq!(Signer::public_key(&arc2), Signer::public_key(&*arc2));
        let boxed2 = Box::new(duo());
        assert_eq!(Signer::public_key(&boxed2), Signer::public_key(&*boxed2));
    }

    #[test]
    fn signature_debug_hides_bytes() {
        assert_eq!(
            format!("{:?}", Signature::from_bytes(vec![7; 64])),
            "Signature(64 bytes)"
        );
    }
}
