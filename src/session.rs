//! Session minting and signed messages: the one place that builds a
//! self-rooted session certificate (mode 0) and signs a `signed-message.v1`
//! with the session key. Holds no clock; the caller chooses every window.

use crate::transcripts::{session_delegation_transcript, signed_message_transcript};
use crate::verify::check_session_span;
use crate::{jwk_duo, pb, Error, PublicKey, Result};

/// A minted session: a fresh P-256 session key and the mode-0 certificate
/// the device signed for it. It holds a private key, so it is not `Clone`,
/// and its `Debug` shows only the public half.
///
/// ```compile_fail
/// fn assert_clone<T: Clone>() {}
/// assert_clone::<identity_crypto::SessionCredential>();
/// ```
pub struct SessionCredential {
    cert: pb::DelegationCert,
    key: jwk_duo::SigningKeyPair,
}

impl std::fmt::Debug for SessionCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionCredential")
            .field("session", &self.session_public_key())
            .field("not_after_unix", &self.not_after_unix())
            .finish()
    }
}

/// Mints a session under `device` for `principal_genesis`, valid over
/// `[not_before_unix, not_after_unix]`. The span must be in `(0, 24 h]`.
pub fn mint_session(
    device: &jwk_duo::SigningKeyPair,
    principal_genesis: &PublicKey,
    not_before_unix: i64,
    not_after_unix: i64,
) -> Result<SessionCredential> {
    check_session_span(not_before_unix, not_after_unix)?;
    let key = jwk_duo::SigningKeyPair::generate();
    let mut cert = pb::DelegationCert {
        not_before_unix_seconds: not_before_unix,
        not_after_unix_seconds: not_after_unix,
        signature: vec![],
        principal_genesis: Some(pb::PublicKey::from(principal_genesis)),
        mode: 0,
        device: Some(pb::PublicKey::from(&PublicKey::from(device))),
        session: Some(pb::PublicKey::from(&PublicKey::from(&key))),
        host_genesis: None,
        subject: None,
    };
    cert.signature = sign(device, &session_delegation_transcript(&cert)?)?.to_vec();
    Ok(SessionCredential { cert, key })
}

fn sign(key: &jwk_duo::SigningKeyPair, message: &[u8]) -> Result<[u8; 64]> {
    key.sign_bytes(message)
        .map_err(|e| Error::InvalidKey(format!("cannot sign with this key pair: {e}")))
}

impl SessionCredential {
    pub fn cert(&self) -> &pb::DelegationCert {
        &self.cert
    }

    pub fn session_public_key(&self) -> PublicKey {
        PublicKey::from(&self.key)
    }

    /// The end of the window. Renewal is the caller's decision.
    pub fn not_after_unix(&self) -> i64 {
        self.cert.not_after_unix_seconds
    }

    /// Builds a `SelfRooted` message and signs `signed-message.v1` with the
    /// session key. `device_delegation` is `None` only in step 1, before any
    /// root exists to delegate the device. The step-2 verifier
    /// (`verify_signed_message`) rejects a `None` with
    /// `MissingField("self_rooted.device")`.
    #[allow(clippy::too_many_arguments)] // the wire fields, one per argument
    pub fn sign_message(
        &self,
        device_delegation: Option<pb::KeyDelegation>,
        audience: &str,
        nonce: [u8; 16],
        issued_at_unix: i64,
        in_reply_to_nonce: Option<[u8; 16]>,
        body_type: &str,
        body: &[u8],
    ) -> Result<pb::SignedMessage> {
        let mut message = pb::SignedMessage {
            signer: Some(pb::SignerChain {
                chain: Some(pb::signer_chain::Chain::SelfRooted(pb::SelfRooted {
                    device: device_delegation,
                    session: Some(self.cert.clone()),
                })),
            }),
            audience: audience.into(),
            nonce: nonce.to_vec(),
            issued_at_unix_seconds: issued_at_unix,
            in_reply_to_nonce: in_reply_to_nonce.map(|n| n.to_vec()),
            body_type: body_type.into(),
            body: body.to_vec(),
            signature: vec![],
        };
        message.signature = sign(&self.key, &signed_message_transcript(&message)?)?.to_vec();
        Ok(message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::{Fleet, Signer, LIVE, T0};
    use crate::transcripts::{message_nonce, signed_message_transcript};
    use crate::{verify_p256, verify_signed_message, MAX_SESSION_SECONDS};

    const AUD: &str = "structmux-fleet:3b6a27bcceb6a42d";
    const BODY_TYPE: &str = "type.googleapis.com/test.v1.Body";
    const SPAN_ERROR: Error = Error::InvalidField {
        field: "session.not_after_unix_seconds",
        reason: "must be within 24 hours after not_before",
    };

    fn mint(device: &Signer, not_before: i64, not_after: i64) -> Result<SessionCredential> {
        mint_session(device.key_pair(), &Signer::new().public(), not_before, not_after)
    }

    #[test]
    fn minted_cert_verifies_under_the_device_key() {
        let device = Signer::new();
        let principal = Signer::new().public();
        let cred = mint_session(device.key_pair(), &principal, T0, T0 + 3600).unwrap();
        let cert = cred.cert();
        assert_eq!(cert.mode, 0);
        assert_eq!(cert.host_genesis, None);
        assert_eq!(cert.subject, None);
        assert_eq!(cert.principal_genesis, Some(pb::PublicKey::from(&principal)));
        assert_eq!(cert.device, Some(pb::PublicKey::from(&device.public())));
        assert_eq!(cert.session, Some(pb::PublicKey::from(&cred.session_public_key())));
        assert_eq!(cert.not_before_unix_seconds, T0);
        assert_eq!(cred.not_after_unix(), T0 + 3600);
        let transcript = session_delegation_transcript(cert).unwrap();
        verify_p256(&device.public(), &transcript, &cert.signature).unwrap();
    }

    #[test]
    fn session_equal_to_device_is_impossible() {
        let device = Signer::new();
        for _ in 0..8 {
            let cred = mint(&device, T0, T0 + 60).unwrap();
            assert_ne!(cred.session_public_key(), device.public());
            let mut same = cred.cert().clone();
            same.session = same.device.clone();
            assert_eq!(
                session_delegation_transcript(&same),
                Err(Error::NotDistinct("device, session"))
            );
        }
    }

    #[test]
    fn span_over_24h_is_rejected() {
        let device = Signer::new();
        assert_eq!(mint(&device, T0, T0 + MAX_SESSION_SECONDS + 1).unwrap_err(), SPAN_ERROR);
        assert!(mint(&device, T0, T0 + MAX_SESSION_SECONDS).is_ok());
    }

    #[test]
    fn span_zero_or_negative_is_rejected() {
        let device = Signer::new();
        assert_eq!(mint(&device, T0, T0).unwrap_err(), SPAN_ERROR);
        assert_eq!(mint(&device, T0, T0 - 1).unwrap_err(), SPAN_ERROR);
        assert_eq!(mint(&device, T0, T0 - 86_400).unwrap_err(), SPAN_ERROR);
    }

    #[test]
    fn extreme_bounds_do_not_overflow() {
        let device = Signer::new();
        for (nb, na) in [
            (i64::MIN, i64::MAX),
            (i64::MAX, i64::MIN),
            (0, i64::MAX),
            (i64::MIN, 0),
        ] {
            assert_eq!(mint(&device, nb, na).unwrap_err(), SPAN_ERROR, "{nb}..{na}");
        }
    }

    #[test]
    fn empty_audience_or_body_type_is_an_error() {
        let cred = mint(&Signer::new(), T0, T0 + 3600).unwrap();
        assert_eq!(
            cred.sign_message(None, "", [1; 16], T0, None, BODY_TYPE, b"x").unwrap_err(),
            Error::InvalidField { field: "audience", reason: "empty" }
        );
        assert_eq!(
            cred.sign_message(None, AUD, [1; 16], T0, None, "", b"x").unwrap_err(),
            Error::InvalidField { field: "body_type", reason: "empty" }
        );
    }

    #[test]
    fn step_2_verifier_requires_the_device_delegation() {
        let f = Fleet::new();
        let cred = mint_session(f.laptop.key_pair(), &f.owner.genesis(), T0, T0 + 3600).unwrap();
        let r = f.resolver();
        let without = cred.sign_message(None, AUD, [7; 16], T0 + 60, None, BODY_TYPE, b"hi").unwrap();
        assert_eq!(
            verify_signed_message(&without, AUD, &r, LIVE).unwrap_err(),
            Error::MissingField("self_rooted.device")
        );
        let with = cred
            .sign_message(Some(f.laptop_deleg.clone()), AUD, [7; 16], T0 + 60, None, BODY_TYPE, b"hi")
            .unwrap();
        let verified = verify_signed_message(&with, AUD, &r, LIVE).unwrap();
        assert_eq!(verified.chain().principal(), &f.owner.id());
        assert_eq!(verified.chain().device(), &f.laptop.public());
        assert_eq!(verified.body(), b"hi");
    }

    #[test]
    fn signed_message_signature_verifies_under_the_session_key() {
        let device = Signer::new();
        let cred = mint(&device, T0, T0 + 3600).unwrap();
        let msg = cred.sign_message(None, AUD, [9; 16], T0, None, BODY_TYPE, b"hi").unwrap();
        assert_eq!(msg.signature.len(), 64);
        let transcript = signed_message_transcript(&msg).unwrap();
        verify_p256(&cred.session_public_key(), &transcript, &msg.signature).unwrap();
        assert!(verify_p256(&device.public(), &transcript, &msg.signature).is_err());
    }

    #[test]
    fn signed_message_carries_the_chain_and_fields() {
        let f = Fleet::new();
        let cred = mint_session(f.laptop.key_pair(), &f.owner.genesis(), T0, T0 + 3600).unwrap();
        let reply = message_nonce("m1");
        let nonce = message_nonce("m2");
        let msg = cred
            .sign_message(Some(f.laptop_deleg.clone()), AUD, nonce, T0 + 5, Some(reply), BODY_TYPE, &[1, 2, 3])
            .unwrap();
        let Some(pb::signer_chain::Chain::SelfRooted(s)) = msg.signer.as_ref().and_then(|c| c.chain.clone())
        else {
            panic!("expected a self-rooted chain");
        };
        assert_eq!(s.device, Some(f.laptop_deleg.clone()));
        assert_eq!(s.session.as_ref(), Some(cred.cert()));
        assert_eq!(msg.audience, AUD);
        assert_eq!(msg.nonce, nonce.to_vec());
        assert_eq!(msg.issued_at_unix_seconds, T0 + 5);
        assert_eq!(msg.in_reply_to_nonce, Some(reply.to_vec()));
        assert_eq!(msg.body_type, BODY_TYPE);
        assert_eq!(msg.body, vec![1, 2, 3]);
    }

    #[test]
    fn debug_shows_only_the_public_key() {
        let cred = mint(&Signer::new(), T0, T0 + 60).unwrap();
        let shown = format!("{cred:?}");
        assert!(shown.contains(&format!("{:?}", cred.session_public_key())), "{shown}");
        assert!(!shown.contains("SigningKeyPair") && !shown.contains("has_private_key"), "{shown}");
    }
}
