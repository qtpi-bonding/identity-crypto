//! Session minting and signed messages: the one place that builds a
//! self-rooted session certificate (mode 0) and signs a `signed-message.v1`
//! with the session key. Holds no clock; the caller chooses every window.

use crate::transcripts::{hosted_session_transcript, session_delegation_transcript, signed_message_transcript};
use crate::verify::check_session_span;
use crate::{jwk_duo, pb, Error, PrincipalId, PublicKey, Result};

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

/// The one signing-failure mapping: a public-only key pair becomes `InvalidKey`.
pub(crate) fn sign(key: &jwk_duo::SigningKeyPair, message: &[u8]) -> Result<[u8; 64]> {
    key.sign_bytes(message)
        .map_err(|e| Error::InvalidKey(format!("cannot sign with this key pair: {e}")))
}

/// Builds a `SignedMessage` carrying `chain` and signs `signed-message.v1`
/// with the session key; the one construction both credentials share.
#[allow(clippy::too_many_arguments)] // the wire fields, one per argument
fn sign_with_chain(
    key: &jwk_duo::SigningKeyPair,
    chain: pb::signer_chain::Chain,
    audience: &str,
    nonce: [u8; 16],
    issued_at_unix: i64,
    in_reply_to_nonce: Option<[u8; 16]>,
    body_type: &str,
    body: &[u8],
) -> Result<pb::SignedMessage> {
    let mut message = pb::SignedMessage {
        signer: Some(pb::SignerChain { chain: Some(chain) }),
        audience: audience.into(),
        nonce: nonce.to_vec(),
        issued_at_unix_seconds: issued_at_unix,
        in_reply_to_nonce: in_reply_to_nonce.map(|n| n.to_vec()),
        body_type: body_type.into(),
        body: body.to_vec(),
        signature: vec![],
    };
    message.signature = sign(key, &signed_message_transcript(&message)?)?.to_vec();
    Ok(message)
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
        sign_with_chain(
            &self.key,
            pb::signer_chain::Chain::SelfRooted(pb::SelfRooted {
                device: device_delegation,
                session: Some(self.cert.clone()),
            }),
            audience,
            nonce,
            issued_at_unix,
            in_reply_to_nonce,
            body_type,
            body,
        )
    }
}

/// The daemon side of a hosted session: its device key and that device's delegation from the daemon root.
pub struct HostingDaemon<'a> {
    pub device: &'a jwk_duo::SigningKeyPair,
    pub device_delegation: &'a pb::KeyDelegation,
}

/// The agent side: its device key, that device's delegation from the agent root, and the agent's root rotations (empty if never rotated).
pub struct HostedAgent<'a> {
    pub device: &'a jwk_duo::SigningKeyPair,
    pub device_delegation: &'a pb::KeyDelegation,
    pub rotations: &'a [pb::RootRotation],
}

/// A minted hosted session: a fresh P-256 session key, the mode-1 certificate
/// the daemon device signed for it, and the agent device's co-signature. It
/// holds a private key, so it is not `Clone`, and its `Debug` shows only the
/// public half.
///
/// ```compile_fail
/// fn assert_clone<T: Clone>() {}
/// assert_clone::<identity_crypto::HostedSessionCredential>();
/// ```
pub struct HostedSessionCredential {
    chain: pb::DaemonHosted,
    key: jwk_duo::SigningKeyPair,
}

impl std::fmt::Debug for HostedSessionCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostedSessionCredential")
            .field("session", &self.session_public_key())
            .field("not_after_unix", &self.not_after_unix())
            .finish()
    }
}

fn delegated_device(delegation: &pb::KeyDelegation, device: &jwk_duo::SigningKeyPair, field: &'static str) -> Result<PublicKey> {
    let public = PublicKey::from(device);
    let got = delegation.delegated.as_ref().map(PublicKey::try_from).transpose()?;
    if got.as_ref() != Some(&public) {
        return Err(Error::ChainMismatch(field));
    }
    Ok(public)
}

fn check_device_purpose(delegation: &pb::KeyDelegation, field: &'static str) -> Result<()> {
    if delegation.purpose != pb::KeyPurpose::Device as i32 {
        return Err(Error::ChainMismatch(field));
    }
    Ok(())
}

/// Mints a hosted session for the agent whose device is `agent.device`, run by
/// the daemon whose device is `daemon.device`, valid over
/// `[not_before_unix, not_after_unix]` (span in `(0, 24 h]`). `subject` must
/// start with the daemon's short id and `/`. Refuses before signing anything.
pub fn mint_hosted_session(
    daemon: HostingDaemon<'_>,
    agent: HostedAgent<'_>,
    subject: &str,
    not_before_unix: i64,
    not_after_unix: i64,
) -> Result<HostedSessionCredential> {
    check_session_span(not_before_unix, not_after_unix)?;
    let daemon_device = delegated_device(daemon.device_delegation, daemon.device, "host_device.delegated")?;
    delegated_device(agent.device_delegation, agent.device, "agent_device.delegated")?;
    check_device_purpose(daemon.device_delegation, "host_device.purpose")?;
    check_device_purpose(agent.device_delegation, "agent_device.purpose")?;
    let host_genesis = daemon.device_delegation.principal_genesis.clone().ok_or(Error::MissingField("host_device.principal_genesis"))?;
    let agent_genesis = agent.device_delegation.principal_genesis.clone().ok_or(Error::MissingField("agent_device.principal_genesis"))?;
    let host_id = PrincipalId::from_genesis(PublicKey::try_from(&host_genesis)?);
    if !subject.strip_prefix(&host_id.short_id().to_string()).is_some_and(|rest| rest.starts_with('/')) {
        return Err(Error::InvalidField { field: "subject", reason: "must start with the host daemon's short id and /" });
    }
    let key = jwk_duo::SigningKeyPair::generate();
    let mut cert = pb::DelegationCert {
        not_before_unix_seconds: not_before_unix,
        not_after_unix_seconds: not_after_unix,
        signature: vec![],
        principal_genesis: Some(agent_genesis),
        mode: 1,
        device: Some(pb::PublicKey::from(&daemon_device)),
        session: Some(pb::PublicKey::from(&PublicKey::from(&key))),
        host_genesis: Some(host_genesis),
        subject: Some(subject.to_string()),
    };
    cert.signature = sign(daemon.device, &session_delegation_transcript(&cert)?)?.to_vec();
    let agent_signature = sign(agent.device, &hosted_session_transcript(&cert)?)?.to_vec();
    Ok(HostedSessionCredential {
        chain: pb::DaemonHosted {
            host_device: Some(daemon.device_delegation.clone()),
            agent_device: Some(agent.device_delegation.clone()),
            session: Some(cert),
            agent_signature,
            agent_rotations: agent.rotations.to_vec(),
        },
        key,
    })
}

impl HostedSessionCredential {
    /// The mode-1 certificate the daemon device signed for the session key.
    pub fn cert(&self) -> &pb::DelegationCert {
        self.chain.session.as_ref().expect("minted with a session cert")
    }

    /// The public half of the session key.
    pub fn session_public_key(&self) -> PublicKey {
        PublicKey::from(&self.key)
    }

    /// The end of the window. Renewal is the caller's decision.
    pub fn not_after_unix(&self) -> i64 {
        self.cert().not_after_unix_seconds
    }

    /// Builds a `DaemonHosted` message and signs `signed-message.v1` with the
    /// session key.
    #[allow(clippy::too_many_arguments)] // the wire fields, one per argument
    pub fn sign_message(
        &self,
        audience: &str,
        nonce: [u8; 16],
        issued_at_unix: i64,
        in_reply_to_nonce: Option<[u8; 16]>,
        body_type: &str,
        body: &[u8],
    ) -> Result<pb::SignedMessage> {
        sign_with_chain(
            &self.key,
            pb::signer_chain::Chain::DaemonHosted(self.chain.clone()),
            audience,
            nonce,
            issued_at_unix,
            in_reply_to_nonce,
            body_type,
            body,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::{subject_on, Fleet, Principal, Signer, DAY, LIVE, T0};
    use crate::transcripts::{hosted_session_transcript, message_nonce, signed_message_transcript};
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

    fn hosted_fixture() -> (Principal, Principal, Signer, pb::KeyDelegation, Signer, pb::KeyDelegation) {
        let mut daemon = Principal::new();
        let mut agent = Principal::new();
        daemon.rotate(T0);
        agent.rotate(T0);
        let (dd, dd_deleg) = daemon.delegate_device(T0, T0 + DAY);
        let (ad, ad_deleg) = agent.delegate_device(T0, T0 + DAY);
        (daemon, agent, dd, dd_deleg, ad, ad_deleg)
    }

    fn mint_hosted(
        f: &(Principal, Principal, Signer, pb::KeyDelegation, Signer, pb::KeyDelegation),
        subject: &str,
    ) -> Result<HostedSessionCredential> {
        mint_hosted_session(
            HostingDaemon { device: f.2.key_pair(), device_delegation: &f.3 },
            HostedAgent { device: f.4.key_pair(), device_delegation: &f.5, rotations: &f.1.rotations },
            subject,
            T0,
            T0 + 3600,
        )
    }

    #[test]
    fn hosted_cert_is_signed_by_the_daemon_device_and_co_signed_by_the_agent_device() {
        let f = hosted_fixture();
        let cred = mint_hosted(&f, &subject_on(&f.0, "a1")).unwrap();
        let cert = cred.cert();
        verify_p256(&f.2.public(), &session_delegation_transcript(cert).unwrap(), &cert.signature).unwrap();
        let msg = cred.sign_message(AUD, [1; 16], T0, None, BODY_TYPE, b"x").unwrap();
        let Some(pb::signer_chain::Chain::DaemonHosted(h)) = msg.signer.and_then(|c| c.chain) else {
            panic!("expected a daemon-hosted chain");
        };
        verify_p256(&f.4.public(), &hosted_session_transcript(cert).unwrap(), &h.agent_signature).unwrap();
        assert_eq!(cert.mode, 1);
        assert_eq!(cert.host_genesis, Some(pb::PublicKey::from(&f.0.genesis())));
        assert_eq!(cert.principal_genesis, Some(pb::PublicKey::from(&f.1.genesis())));
        assert_eq!(h.agent_rotations, f.1.rotations);
    }

    #[test]
    fn hosted_message_verifies_under_the_session_key() {
        let f = hosted_fixture();
        let cred = mint_hosted(&f, &subject_on(&f.0, "a1")).unwrap();
        let m = cred.sign_message(AUD, [3; 16], T0 + 1, Some([4; 16]), BODY_TYPE, b"hi").unwrap();
        let Some(pb::signer_chain::Chain::DaemonHosted(h)) = m.signer.clone().and_then(|c| c.chain) else {
            panic!("expected a daemon-hosted chain");
        };
        assert_eq!(h.host_device.as_ref(), Some(&f.3));
        assert_eq!(h.agent_device.as_ref(), Some(&f.5));
        assert_eq!(h.session.as_ref(), Some(cred.cert()));
        verify_p256(&cred.session_public_key(), &signed_message_transcript(&m).unwrap(), &m.signature).unwrap();
    }

    #[test]
    fn mint_hosted_session_refusals() {
        let f = hosted_fixture();
        let good = subject_on(&f.0, "a1");
        let daemon = |deleg| HostingDaemon { device: f.2.key_pair(), device_delegation: deleg };
        let agent = |deleg| HostedAgent { device: f.4.key_pair(), device_delegation: deleg, rotations: &[] };
        let mint = |d: HostingDaemon<'_>, a: HostedAgent<'_>, subject: &str, na: i64| {
            mint_hosted_session(d, a, subject, T0, na).err()
        };
        assert_eq!(mint(daemon(&f.3), agent(&f.5), &good, T0 + MAX_SESSION_SECONDS + 1), Some(SPAN_ERROR));
        let other = Principal::new().delegate_device(T0, T0 + DAY).1;
        assert_eq!(mint(daemon(&other), agent(&f.5), &good, T0 + 60), Some(Error::ChainMismatch("host_device.delegated")));
        assert_eq!(mint(daemon(&f.3), agent(&other), &good, T0 + 60), Some(Error::ChainMismatch("agent_device.delegated")));
        let mut approval = f.3.clone();
        approval.purpose = pb::KeyPurpose::Approval as i32;
        assert_eq!(mint(daemon(&approval), agent(&f.5), &good, T0 + 60), Some(Error::ChainMismatch("host_device.purpose")));
        let mut approval = f.5.clone();
        approval.purpose = pb::KeyPurpose::Approval as i32;
        assert_eq!(mint(daemon(&f.3), agent(&approval), &good, T0 + 60), Some(Error::ChainMismatch("agent_device.purpose")));
        let bad = || Error::InvalidField { field: "subject", reason: "must start with the host daemon's short id and /" };
        let short = f.0.id().short_id().to_string();
        for subject in ["a1", "", &short, &format!("{short}x/a"), &format!("{}/a", f.1.id().short_id())] {
            assert_eq!(mint(daemon(&f.3), agent(&f.5), subject, T0 + 60), Some(bad()), "{subject}");
        }
    }
}
