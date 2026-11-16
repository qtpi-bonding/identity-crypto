//! Pure key builders for a self-rooted principal: the signatures the
//! transcripts define, over `jwk_duo` key pairs. No I/O, no clock (callers
//! pass `now`), no key storage. Key generation is not here; it belongs to the
//! caller (the `identity-keyfile` crate generates and stores agent keys).
//!
//! Signing failures (a public-only key pair) are `Error::InvalidKey`, as in
//! `session.rs`. Span rules are the verifier's own: `delegate_device` applies
//! the same 31-day cap as `verify_chain`; `device_delegation` and
//! `sign_key_delegation` do not cap, for the human and approval windows that
//! may be longer.

use crate::jwk_duo::KeyDuo;
use crate::signer::sign_transcript;
use crate::signer::Signer;
use crate::transcripts;
use crate::verify::check_unlisted_span;
use crate::{pb, PrincipalId, PublicKey, PublicKeyDuo, Result};

/// The signing half of a duo, as a validated public key.
pub fn signing_public(duo: &KeyDuo) -> PublicKey {
    PublicKey::from(duo.signing_key_pair())
}

/// The encryption half of a duo, as a validated public key.
pub fn encryption_public(duo: &KeyDuo) -> PublicKey {
    PublicKey::from(duo.encryption_key_pair())
}

/// The principal id a genesis duo starts: its signing key is the genesis key.
pub fn principal_id(genesis: &KeyDuo) -> PrincipalId {
    PrincipalId::from_genesis(signing_public(genesis))
}

/// An unsigned DEVICE `KeyDelegation` for the device's two halves over
/// `[issued, not_after]`. It carries no window cap: sign it with
/// [`sign_key_delegation`]. Use [`delegate_device`] for a capped, signed one.
pub fn device_delegation(
    genesis: &PrincipalId,
    root: &PublicKey,
    device_signing: &PublicKey,
    device_encryption: &PublicKey,
    issued: i64,
    not_after: i64,
) -> pb::KeyDelegation {
    pb::KeyDelegation {
        principal_genesis: Some(pb::PublicKey::from(genesis.genesis())),
        signing_root: Some(pb::PublicKey::from(root)),
        purpose: pb::KeyPurpose::Device as i32,
        delegated: Some(pb::PublicKey::from(device_signing)),
        delegated_encryption: Some(pb::PublicKey::from(device_encryption)),
        issued_at_unix_seconds: issued,
        not_after_unix_seconds: not_after,
        signature: vec![],
    }
}

/// Sets `d.signature` to `root`'s signature over `key_delegation_transcript(d)`.
/// No window cap: the caller owns the window.
pub fn sign_key_delegation<S: Signer + ?Sized>(root: &S, d: &mut pb::KeyDelegation) -> Result<()> {
    let transcript = transcripts::key_delegation_transcript(d)?;
    d.signature = sign_transcript(root, &transcript)?;
    Ok(())
}

/// A root-signed DEVICE delegation of `device` for `[issued_at, not_after]`
/// (unix seconds). For Agent, Daemon, and Service devices, the span must be positive
/// and at most `MAX_DELEGATION_SECONDS` (31 days), the cap the verifier applies to unlisted devices.
/// Humans may hold longer windows: build those with [`device_delegation`]
/// and [`sign_key_delegation`].
pub fn delegate_device<S: Signer + ?Sized>(
    root: &S,
    genesis: &PrincipalId,
    device: &PublicKeyDuo,
    issued_at: i64,
    not_after: i64,
) -> Result<pb::KeyDelegation> {
    check_unlisted_span("device.not_after_unix_seconds", issued_at, not_after)?;
    let mut d = device_delegation(
        genesis,
        &root.public_key(),
        device.signing(),
        device.encryption(),
        issued_at,
        not_after,
    );
    sign_key_delegation(root, &mut d)?;
    Ok(d)
}

/// True when the delegation expires within `margin_seconds` of `now`
/// (inclusive at the margin). An expired delegation is always due.
pub fn renewal_due(d: &pb::KeyDelegation, now: i64, margin_seconds: i64) -> bool {
    d.not_after_unix_seconds.saturating_sub(now) <= margin_seconds
}

/// Proof of possession for a key presented to a service: the 64-byte
/// signature of `key_challenge_transcript(audience, nonce, signing key)`.
pub fn challenge_proof<S: Signer + ?Sized>(
    signer: &S,
    audience: &str,
    nonce: &[u8],
) -> Result<Vec<u8>> {
    let transcript = transcripts::key_challenge_transcript(audience, nonce, &signer.public_key())?;
    sign_transcript(signer, &transcript)
}

/// The current root's 64-byte signature authorizing a rename.
pub fn rename_proof<S: Signer + ?Sized>(
    root: &S,
    nonce: &[u8],
    principal: &PrincipalId,
    new_name: &str,
) -> Result<Vec<u8>> {
    let transcript = transcripts::principal_rename_transcript(nonce, principal, new_name)?;
    sign_transcript(root, &transcript)
}

/// The old root's signed succession by `new_root`.
pub fn rotation<S: Signer + ?Sized>(
    old_root: &S,
    genesis: &PrincipalId,
    new_root: &PublicKey,
    issued_at: i64,
) -> Result<pb::RootRotation> {
    let mut r = pb::RootRotation {
        principal_genesis: Some(pb::PublicKey::from(genesis.genesis())),
        old_root: Some(pb::PublicKey::from(&old_root.public_key())),
        new_root: Some(pb::PublicKey::from(new_root)),
        issued_at_unix_seconds: issued_at,
        signature: vec![],
    };
    r.signature = sign_transcript(old_root, &transcripts::root_rotation_transcript(&r)?)?;
    Ok(r)
}

/// A revocation of `revoked` signed by `signer` (the revoked key itself, or
/// the principal's current root).
pub fn revocation<S: Signer + ?Sized>(
    signer: &S,
    genesis: &PrincipalId,
    revoked: &PublicKey,
    revoked_at: i64,
) -> Result<pb::KeyRevocation> {
    let mut r = pb::KeyRevocation {
        principal_genesis: Some(pb::PublicKey::from(genesis.genesis())),
        revoked: Some(pb::PublicKey::from(revoked)),
        revoked_by: Some(pb::PublicKey::from(&signer.public_key())),
        revoked_at_unix_seconds: revoked_at,
        signature: vec![],
    };
    r.signature = sign_transcript(signer, &transcripts::key_revocation_transcript(&r)?)?;
    Ok(r)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwk_duo::{EncryptionKeyPair, GenerationService, SigningKeyPair};
    use crate::SignerError;
    use crate::{verify_p256, Error};

    const DAY: i64 = 86_400;
    const T: i64 = 1_700_000_000;
    const MARGIN_ERR: &str = "must be within 31 days after issued_at";

    fn duo() -> KeyDuo {
        GenerationService::generate_key_duo()
    }

    fn genesis() -> (KeyDuo, PrincipalId) {
        let g = duo();
        let id = principal_id(&g);
        (g, id)
    }

    /// A duo whose halves are public only: the verifier-side view of a key.
    fn public_only(d: &KeyDuo) -> KeyDuo {
        let signing = SigningKeyPair::import_public_key_raw(signing_public(d).as_bytes()).unwrap();
        let encryption =
            EncryptionKeyPair::import_public_key_raw(encryption_public(d).as_bytes()).unwrap();
        KeyDuo::new(signing, encryption).unwrap()
    }

    fn verifies(key: &PublicKey, transcript: &[u8], signature: &[u8]) -> bool {
        verify_p256(key, transcript, signature).is_ok()
    }

    #[test]
    fn lifetime_constants() {
        use crate::verify::{
            DEFAULT_DELEGATION_SECONDS, DEFAULT_RENEW_MARGIN_SECONDS, MAX_DELEGATION_SECONDS,
        };
        assert_eq!(
            (
                DEFAULT_DELEGATION_SECONDS,
                MAX_DELEGATION_SECONDS,
                DEFAULT_RENEW_MARGIN_SECONDS
            ),
            (2_592_000, 2_678_400, 604_800)
        );
        let (root, id) = genesis();
        let d = PublicKeyDuo::from(&duo());
        assert!(delegate_device(&root, &id, &d, T, T + DEFAULT_DELEGATION_SECONDS).is_ok());
        assert!(delegate_device(&root, &id, &d, T, T + MAX_DELEGATION_SECONDS).is_ok());
        assert!(delegate_device(&root, &id, &d, T, T + MAX_DELEGATION_SECONDS + 1).is_err());
    }

    #[test]
    fn public_halves_are_the_duo_halves_and_the_principal_is_the_genesis_key() {
        let g = duo();
        assert_ne!(signing_public(&g), encryption_public(&g));
        assert_eq!(principal_id(&g).genesis(), &signing_public(&g));
        assert_eq!(signing_public(&public_only(&g)), signing_public(&g));
    }

    #[test]
    fn delegation_verifies_under_the_root() {
        let (root, id) = genesis();
        let device = duo();
        let d = delegate_device(&root, &id, &PublicKeyDuo::from(&device), T, T + DAY).unwrap();
        let transcript = transcripts::key_delegation_transcript(&d).unwrap();
        assert!(verifies(&signing_public(&root), &transcript, &d.signature));
        // Not under any other key.
        assert!(!verifies(
            &signing_public(&duo()),
            &transcript,
            &d.signature
        ));
    }

    #[test]
    fn delegation_window_is_capped_at_31_days() {
        let (root, id) = genesis();
        let device = duo();
        // Exactly 31 days is accepted.
        assert!(delegate_device(&root, &id, &PublicKeyDuo::from(&device), 0, 31 * DAY).is_ok());
        // One second more is rejected with the verifier's own field and text.
        assert_eq!(
            delegate_device(&root, &id, &PublicKeyDuo::from(&device), 0, 31 * DAY + 1).unwrap_err(),
            Error::InvalidField {
                field: "device.not_after_unix_seconds",
                reason: MARGIN_ERR
            }
        );
        // Zero and negative spans are rejected.
        assert!(delegate_device(&root, &id, &PublicKeyDuo::from(&device), 5, 5).is_err());
        assert!(delegate_device(&root, &id, &PublicKeyDuo::from(&device), 5, 4).is_err());
        // Bounds do not overflow: a span of i64::MAX is rejected, and so is a
        // full i64 range in either direction.
        assert!(delegate_device(&root, &id, &PublicKeyDuo::from(&device), 0, i64::MAX).is_err());
        assert!(
            delegate_device(&root, &id, &PublicKeyDuo::from(&device), i64::MIN, i64::MAX).is_err()
        );
        assert!(
            delegate_device(&root, &id, &PublicKeyDuo::from(&device), i64::MAX, i64::MIN).is_err()
        );
    }

    #[test]
    fn delegation_fields_bind_the_device_and_genesis() {
        let (root, id) = genesis();
        let device = duo();
        let d = delegate_device(&root, &id, &PublicKeyDuo::from(&device), T, T + DAY).unwrap();
        assert_eq!(d.principal_genesis, Some(pb::PublicKey::from(id.genesis())));
        assert_eq!(
            d.signing_root,
            Some(pb::PublicKey::from(&signing_public(&root)))
        );
        assert_eq!(d.purpose, pb::KeyPurpose::Device as i32);
        assert_eq!(
            d.delegated,
            Some(pb::PublicKey::from(&signing_public(&device)))
        );
        assert_eq!(
            d.delegated_encryption,
            Some(pb::PublicKey::from(&encryption_public(&device)))
        );
        assert_eq!(
            (d.issued_at_unix_seconds, d.not_after_unix_seconds),
            (T, T + DAY)
        );

        // Each bound field is under the signature: changing it breaks it.
        let root_key = signing_public(&root);
        // A transcript the rules refuse does not verify either.
        let ok = |d: &pb::KeyDelegation| match transcripts::key_delegation_transcript(d) {
            Ok(t) => verifies(&root_key, &t, &d.signature),
            Err(_) => false,
        };
        assert!(ok(&d));
        let mut other_genesis = d.clone();
        other_genesis.principal_genesis = Some(pb::PublicKey::from(principal_id(&duo()).genesis()));
        assert!(!ok(&other_genesis));
        let mut other_device = d.clone();
        other_device.delegated = Some(pb::PublicKey::from(&signing_public(&duo())));
        assert!(!ok(&other_device));
        let mut other_encryption = d.clone();
        other_encryption.delegated_encryption =
            Some(pb::PublicKey::from(&encryption_public(&duo())));
        assert!(!ok(&other_encryption));
        // An APPROVAL with the same halves is a different transcript (and
        // the rules forbid the encryption half on one, so drop it too).
        let mut other_purpose = d;
        other_purpose.purpose = pb::KeyPurpose::Approval as i32;
        other_purpose.delegated_encryption = None;
        assert!(!ok(&other_purpose));
    }

    #[test]
    fn renewal_is_due_inside_the_margin_only() {
        let (root, id) = genesis();
        let d = delegate_device(&root, &id, &PublicKeyDuo::from(&duo()), 0, 10 * DAY).unwrap();
        let margin = 7 * DAY;
        // 7 days before expiry is the boundary: due. One second earlier is not.
        assert!(renewal_due(&d, 3 * DAY, margin));
        assert!(!renewal_due(&d, 3 * DAY - 1, margin));
        assert!(!renewal_due(&d, 0, margin));
        // Past expiry is always due.
        assert!(renewal_due(&d, 11 * DAY, margin));
        // The arithmetic saturates at the i64 edges instead of panicking.
        let mut far = d.clone();
        far.not_after_unix_seconds = i64::MAX;
        assert!(!renewal_due(&far, i64::MIN, 0));
        far.not_after_unix_seconds = i64::MIN;
        assert!(renewal_due(&far, i64::MAX, i64::MAX));
    }

    #[test]
    fn proofs_verify_against_their_transcripts() {
        let (root, id) = genesis();
        let root_key = signing_public(&root);

        let proof = challenge_proof(&root, "grorg", b"nonce-1").unwrap();
        let t = transcripts::key_challenge_transcript("grorg", b"nonce-1", &root_key).unwrap();
        assert!(verifies(&root_key, &t, &proof));
        assert!(!verifies(
            &root_key,
            &transcripts::key_challenge_transcript("grorg", b"nonce-2", &root_key).unwrap(),
            &proof
        ));

        let rename = rename_proof(&root, b"n", &id, "new-name").unwrap();
        let t = transcripts::principal_rename_transcript(b"n", &id, "new-name").unwrap();
        assert!(verifies(&root_key, &t, &rename));
        assert!(!verifies(
            &root_key,
            &transcripts::principal_rename_transcript(b"n", &id, "other").unwrap(),
            &rename
        ));

        let new_root = duo();
        let rot = rotation(&root, &id, &signing_public(&new_root), 5).unwrap();
        assert!(verifies(
            &root_key,
            &transcripts::root_rotation_transcript(&rot).unwrap(),
            &rot.signature
        ));
        assert_eq!(
            rot.new_root,
            Some(pb::PublicKey::from(&signing_public(&new_root)))
        );

        let revoked = signing_public(&duo());
        let rev = revocation(&root, &id, &revoked, 9).unwrap();
        assert!(verifies(
            &root_key,
            &transcripts::key_revocation_transcript(&rev).unwrap(),
            &rev.signature
        ));
        assert_eq!(rev.revoked, Some(pb::PublicKey::from(&revoked)));
    }

    #[test]
    fn sign_key_delegation_has_no_cap() {
        let (root, id) = genesis();
        let root_key = signing_public(&root);
        let mut unbounded = device_delegation(
            &id,
            &root_key,
            &signing_public(&duo()),
            &encryption_public(&duo()),
            0,
            i64::MAX,
        );
        sign_key_delegation(&root, &mut unbounded).unwrap();
        assert!(verifies(
            &root_key,
            &transcripts::key_delegation_transcript(&unbounded).unwrap(),
            &unbounded.signature
        ));

        let mut full_range = device_delegation(
            &id,
            &root_key,
            &signing_public(&duo()),
            &encryption_public(&duo()),
            i64::MIN,
            i64::MAX,
        );
        assert!(sign_key_delegation(&root, &mut full_range).is_ok());
    }

    #[test]
    fn public_only_root_is_an_error_not_a_panic() {
        let (root, id) = genesis();
        let watcher = public_only(&root);
        let sig_err = |r: Result<()>| {
            assert!(
                matches!(r, Err(Error::Signer(SignerError::Unavailable))),
                "got {r:?}"
            )
        };

        let mut d = device_delegation(
            &id,
            &signing_public(&root),
            &signing_public(&duo()),
            &encryption_public(&duo()),
            T,
            T + DAY,
        );
        sig_err(sign_key_delegation(&watcher, &mut d));
        assert!(
            d.signature.is_empty(),
            "a failed signing must leave the signature unset"
        );

        assert!(matches!(
            delegate_device(&watcher, &id, &PublicKeyDuo::from(&duo()), T, T + DAY),
            Err(Error::Signer(SignerError::Unavailable))
        ));
        assert!(matches!(
            challenge_proof(&watcher, "grorg", b"n"),
            Err(Error::Signer(SignerError::Unavailable))
        ));
        assert!(matches!(
            rename_proof(&watcher, b"n", &id, "x"),
            Err(Error::Signer(SignerError::Unavailable))
        ));
        assert!(matches!(
            rotation(&watcher, &id, &signing_public(&duo()), T),
            Err(Error::Signer(SignerError::Unavailable))
        ));
        assert!(matches!(
            revocation(&watcher, &id, &signing_public(&duo()), T),
            Err(Error::Signer(SignerError::Unavailable))
        ));
    }

    #[test]
    fn delegate_device_accepts_dyn_signer() {
        let (root, id) = genesis();
        let dev = duo();
        let a = delegate_device(&root, &id, &crate::PublicKeyDuo::from(&dev), T, T + DAY).unwrap();
        let b = delegate_device(
            &root as &dyn crate::Signer,
            &id,
            &crate::PublicKeyDuo::from(&dev),
            T,
            T + DAY,
        )
        .unwrap();
        assert_eq!(
            transcripts::key_delegation_transcript(&a).unwrap(),
            transcripts::key_delegation_transcript(&b).unwrap()
        );
        assert_eq!(
            b.delegated,
            Some(pb::PublicKey::from(&signing_public(&dev)))
        );
        assert_eq!(
            b.delegated_encryption,
            Some(pb::PublicKey::from(&encryption_public(&dev)))
        );
        verify_p256(
            &signing_public(&root),
            &transcripts::key_delegation_transcript(&b).unwrap(),
            &b.signature,
        )
        .unwrap();
    }

    #[test]
    fn rotation_takes_the_new_root_public_key() {
        let (old, id) = genesis();
        let new = duo();
        let rot = rotation(&old, &id, &signing_public(&new), T).unwrap();
        assert_eq!(
            rot.new_root,
            Some(pb::PublicKey::from(&signing_public(&new)))
        );
        assert_eq!(
            rot.old_root,
            Some(pb::PublicKey::from(&signing_public(&old)))
        );
        verify_p256(
            &signing_public(&old),
            &transcripts::root_rotation_transcript(&rot).unwrap(),
            &rot.signature,
        )
        .unwrap();
        // The new root need not hold a private key here: only its public half is used.
        let watcher = public_only(&new);
        assert_eq!(
            rotation(&old, &id, &signing_public(&watcher), T)
                .unwrap()
                .new_root,
            rot.new_root
        );
    }
}
