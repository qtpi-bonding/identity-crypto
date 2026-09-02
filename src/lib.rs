//! Cryptographic identity primitives for the grorg/gait/multimatrix
//! agent-identity design (`concordat/2026-09-01-agent-identity-model-design.md`
//! in the `concordium` monorepo). This crate is deliberately narrow: it
//! builds the canonical signed transcripts and verifies raw ed25519
//! signatures. It does not do RPC calls, storage, or key generation/storage
//! -- those stay in each consumer's own repo. The point of pulling this
//! specific ~150 lines out on its own is that a single wrong byte in a
//! transcript layout breaks every cross-repo signature; having exactly one
//! implementation removes that whole class of bug by construction instead
//! of relying on review to catch drift between independently-written
//! copies.

pub mod key_scheme;
pub mod transcripts;

pub use key_scheme::KeyScheme;

use anyhow::{anyhow, Context, Result};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

/// Decode a hex-encoded ed25519 public key (grorg's `AgentKey.public_key`
/// wire type) into its raw 32 bytes. Never hex-encode a value that's
/// already gone through this.
pub fn hex_decode_32(public_key_hex: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(public_key_hex).context("public_key is not valid hex")?;
    bytes
        .try_into()
        .map_err(|_| anyhow!("ed25519 public key must be 32 bytes"))
}

/// Verify a raw ed25519 signature against a hex-encoded public key.
pub fn verify_ed25519(public_key_hex: &str, message: &[u8], signature: &[u8]) -> Result<bool> {
    let public_bytes = hex_decode_32(public_key_hex)?;
    let verifying_key = VerifyingKey::from_bytes(&public_bytes)
        .map_err(|e| anyhow!("invalid ed25519 public key: {e}"))?;
    let sig_bytes: [u8; 64] = signature
        .try_into()
        .map_err(|_| anyhow!("ed25519 signature must be 64 bytes"))?;
    let signature = Signature::from_bytes(&sig_bytes);
    Ok(verifying_key.verify(message, &signature).is_ok())
}

#[cfg(test)]
mod verify_tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    #[test]
    fn genuine_signature_verifies() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let hex_pub = hex::encode(signing_key.verifying_key().to_bytes());
        let msg = b"hello";
        let sig = signing_key.sign(msg);
        assert!(verify_ed25519(&hex_pub, msg, &sig.to_bytes()).unwrap());
    }

    #[test]
    fn tampered_message_does_not_verify() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let hex_pub = hex::encode(signing_key.verifying_key().to_bytes());
        let sig = signing_key.sign(b"hello");
        assert!(!verify_ed25519(&hex_pub, b"goodbye", &sig.to_bytes()).unwrap());
    }

    #[test]
    fn malformed_hex_errors_rather_than_panics() {
        assert!(verify_ed25519("not-hex", b"msg", &[0u8; 64]).is_err());
    }
}
