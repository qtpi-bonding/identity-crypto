//! Per-message verification against a [`Resolver`] (1b spec sections 5–7).
//! Each function checks only what its input carries; history was checked
//! when the resolver was built.

use crate::registry::{AllowedHost, VerifiedEntry};
use crate::transcripts::{key_delegation_transcript, session_delegation_transcript, signed_message_transcript};
use crate::{pb, verify_p256, Error, PrincipalId, PrincipalKind, PublicKey, Resolver, Result};

pub const SKEW_SECONDS: i64 = 30;
pub const MAX_SESSION_SECONDS: i64 = 86_400;
/// A device delegation listed nowhere (daemons, self-rooted agents).
pub const MAX_UNLISTED_DELEGATION_SECONDS: i64 = 31 * 86_400;

/// A receiver's own recorded acceptance time; never a signer's timestamp.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AcceptedAt(i64);

impl AcceptedAt {
    pub fn from_receiver_record(unix_seconds: i64) -> Self { Self(unix_seconds) }
    pub fn unix_seconds(&self) -> i64 { self.0 }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum When {
    /// Also checks the ±30 s window on a message's own `issued_at`.
    Live { now: i64 },
    Accepted(AcceptedAt),
}

impl When {
    pub(crate) fn at(&self) -> i64 {
        match self {
            When::Live { now } => *now,
            When::Accepted(a) => a.0,
        }
    }

    pub(crate) fn check_skew(&self, issued_at: i64) -> Result<()> {
        if let When::Live { now } = self {
            if issued_at.abs_diff(*now) > SKEW_SECONDS as u64 {
                return Err(Error::Skew);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Host {
    /// The vouching daemon, the daemon itself, or a human binding's host.
    Daemon(PrincipalId),
    /// A human device bound with no host.
    Hostless,
    /// A self-rooted agent: no daemon stands behind it.
    Unhosted,
}

#[derive(Clone, Debug)]
pub struct VerifiedChain {
    principal: PrincipalId,
    kind: PrincipalKind,
    host: Host,
    subject: Option<String>,
    device: PublicKey,
    session_key: PublicKey,
    session_not_after: i64,
}

impl VerifiedChain {
    pub fn principal(&self) -> &PrincipalId { &self.principal }
    pub fn kind(&self) -> PrincipalKind { self.kind }
    pub fn host(&self) -> &Host { &self.host }
    pub fn subject(&self) -> Option<&str> { self.subject.as_deref() }
    pub fn device(&self) -> &PublicKey { &self.device }
    pub fn session_key(&self) -> &PublicKey { &self.session_key }
    pub fn session_not_after(&self) -> i64 { self.session_not_after }
}

pub(crate) fn key(k: &Option<pb::PublicKey>, field: &'static str) -> Result<PublicKey> {
    PublicKey::try_from(k.as_ref().ok_or(Error::MissingField(field))?)
}

/// Steps 2–4: the device delegation is the entry's, from its current root,
/// and current at `at`. Returns the device key.
fn device_current(d: &pb::KeyDelegation, entry: &VerifiedEntry, r: &Resolver, at: i64) -> Result<PublicKey> {
    let principal = entry.id();
    if &key(&d.principal_genesis, "device.principal_genesis")? != principal.genesis() {
        return Err(Error::ChainMismatch("device.principal_genesis"));
    }
    let root = key(&d.signing_root, "device.signing_root")?;
    if Some(&root) != entry.current_root().map(|c| c.signing()) {
        return Err(Error::ChainMismatch("device.signing_root"));
    }
    if r.is_revoked(principal, &root, at) {
        return Err(Error::KeyRevoked);
    }
    if d.purpose != pb::KeyPurpose::Device as i32 {
        return Err(Error::ChainMismatch("device.purpose"));
    }
    verify_p256(&root, &key_delegation_transcript(d)?, &d.signature)?;
    let device = key(&d.delegated, "device.delegated")?;
    if r.is_revoked(principal, &device, at) {
        return Err(Error::KeyRevoked);
    }
    if d.not_after_unix_seconds == 0 {
        return Err(Error::InvalidField { field: "device.not_after_unix_seconds", reason: "0 is not an expiry" });
    }
    match entry.kind() {
        PrincipalKind::Human => {
            let b = r.binding(principal, &device).ok_or(Error::NotBound)?;
            if b.device_delegation() != d {
                return Err(Error::ChainMismatch("device delegation differs from the bound one"));
            }
            if at > d.not_after_unix_seconds {
                return Err(Error::Expired("device delegation"));
            }
            if let Some(h) = b.host() {
                if r.is_frozen(h, at) {
                    return Err(Error::HostFrozen);
                }
            }
        }
        PrincipalKind::Daemon | PrincipalKind::Agent => {
            let span = i128::from(d.not_after_unix_seconds) - i128::from(d.issued_at_unix_seconds);
            if span <= 0 || span > i128::from(MAX_UNLISTED_DELEGATION_SECONDS) {
                return Err(Error::InvalidField { field: "device.not_after_unix_seconds", reason: "must be within 31 days after issued_at" });
            }
            if d.issued_at_unix_seconds > at.saturating_add(SKEW_SECONDS) {
                return Err(Error::NotYetValid("device delegation"));
            }
            if at > d.not_after_unix_seconds {
                return Err(Error::Expired("device delegation"));
            }
        }
    }
    Ok(device)
}

/// Step 5: the session cert under `device`. Returns `(session key, not_after)`.
fn check_cert(c: &pb::DelegationCert, device: &PublicKey, at: i64) -> Result<(PublicKey, i64)> {
    if &key(&c.device, "session.device")? != device {
        return Err(Error::ChainMismatch("session.device"));
    }
    verify_p256(device, &session_delegation_transcript(c)?, &c.signature)?;
    let (nb, na) = (c.not_before_unix_seconds, c.not_after_unix_seconds);
    let span = i128::from(na) - i128::from(nb);
    if span <= 0 || span > i128::from(MAX_SESSION_SECONDS) {
        return Err(Error::InvalidField { field: "session.not_after_unix_seconds", reason: "must be within 24 hours after not_before" });
    }
    if at < nb.saturating_sub(SKEW_SECONDS) {
        return Err(Error::NotYetValid("session cert"));
    }
    if at > na {
        return Err(Error::Expired("session cert"));
    }
    Ok((key(&c.session, "session.session")?, na))
}

pub fn verify_chain(signer: &pb::SignerChain, r: &Resolver, when: When) -> Result<VerifiedChain> {
    use pb::signer_chain::Chain;
    let at = when.at();
    match signer.chain.as_ref().ok_or(Error::MissingField("chain"))? {
        Chain::SelfRooted(s) => {
            let d = s.device.as_ref().ok_or(Error::MissingField("self_rooted.device"))?;
            let cert = s.session.as_ref().ok_or(Error::MissingField("self_rooted.session"))?;
            let principal = PrincipalId::from_genesis(key(&cert.principal_genesis, "session.principal_genesis")?);
            let entry = r.entry(&principal).ok_or(Error::UnknownPrincipal)?;
            if !entry.is_self_rooted() {
                return Err(Error::WrongKind);
            }
            if r.is_frozen(&principal, at) {
                return Err(Error::Frozen);
            }
            if cert.mode != 0 {
                return Err(Error::ChainMismatch("session.mode"));
            }
            let device = device_current(d, entry, r, at)?;
            let host = match entry.kind() {
                PrincipalKind::Human => match r.binding(&principal, &device).and_then(|b| b.host()) {
                    Some(h) => Host::Daemon(h.clone()),
                    None => Host::Hostless,
                },
                PrincipalKind::Daemon => Host::Daemon(principal.clone()),
                PrincipalKind::Agent => Host::Unhosted,
            };
            let (session_key, session_not_after) = check_cert(cert, &device, at)?;
            Ok(VerifiedChain { principal, kind: entry.kind(), host, subject: None, device, session_key, session_not_after })
        }
        Chain::HostVouched(h) => {
            let d = h.host_device.as_ref().ok_or(Error::MissingField("host_vouched.host_device"))?;
            let cert = h.session.as_ref().ok_or(Error::MissingField("host_vouched.session"))?;
            let daemon = PrincipalId::from_genesis(key(&d.principal_genesis, "host_device.principal_genesis")?);
            let daemon_entry = r.entry(&daemon).ok_or(Error::UnknownPrincipal)?;
            if daemon_entry.kind() != PrincipalKind::Daemon {
                return Err(Error::WrongKind);
            }
            if r.is_frozen(&daemon, at) {
                return Err(Error::Frozen);
            }
            if cert.mode != 1 {
                return Err(Error::ChainMismatch("session.mode"));
            }
            if &key(&cert.host_genesis, "session.host_genesis")? != daemon.genesis() {
                return Err(Error::ChainMismatch("session.host_genesis"));
            }
            let subject = cert.subject.clone().ok_or(Error::MissingField("session.subject"))?;
            if !subject.starts_with(&format!("{}/", daemon.short_id())) {
                return Err(Error::NotVouched);
            }
            let agent = PrincipalId::from_genesis(key(&cert.principal_genesis, "session.principal_genesis")?);
            let agent_entry = r.entry(&agent).ok_or(Error::UnknownPrincipal)?;
            if agent_entry.kind() != PrincipalKind::Agent || agent_entry.is_self_rooted() {
                return Err(Error::WrongKind);
            }
            if r.is_frozen(&agent, at) {
                return Err(Error::Frozen);
            }
            let allowed = agent_entry.allowed_hosts().iter().any(|h| match h {
                AllowedHost::Any => true,
                AllowedHost::Daemon(id) => id == &daemon,
            });
            if !allowed {
                return Err(Error::NotVouched);
            }
            let device = device_current(d, daemon_entry, r, at)?;
            let (session_key, session_not_after) = check_cert(cert, &device, at)?;
            Ok(VerifiedChain {
                principal: agent, kind: PrincipalKind::Agent, host: Host::Daemon(daemon), subject: Some(subject),
                device, session_key, session_not_after,
            })
        }
    }
}

#[derive(Clone, Debug)]
pub struct VerifiedMessage {
    chain: VerifiedChain,
    nonce: Vec<u8>,
    issued_at: i64,
    in_reply_to_nonce: Option<Vec<u8>>,
    body_type: String,
    body: Vec<u8>,
}

impl VerifiedMessage {
    pub fn chain(&self) -> &VerifiedChain { &self.chain }
    /// Replay checking is the caller's: it needs state.
    pub fn nonce(&self) -> &[u8] { &self.nonce }
    pub fn issued_at(&self) -> i64 { self.issued_at }
    pub fn in_reply_to_nonce(&self) -> Option<&[u8]> { self.in_reply_to_nonce.as_deref() }
    pub fn body_type(&self) -> &str { &self.body_type }
    pub fn body(&self) -> &[u8] { &self.body }
}

pub fn verify_signed_message(msg: &pb::SignedMessage, expected_audience: &str, r: &Resolver, when: When) -> Result<VerifiedMessage> {
    if msg.signature.is_empty() {
        return Err(Error::EmptySignature);
    }
    let chain = verify_chain(msg.signer.as_ref().ok_or(Error::MissingField("signer"))?, r, when)?;
    if msg.audience != expected_audience {
        return Err(Error::WrongAudience);
    }
    verify_p256(chain.session_key(), &signed_message_transcript(msg)?, &msg.signature)?;
    when.check_skew(msg.issued_at_unix_seconds)?;
    Ok(VerifiedMessage {
        chain, nonce: msg.nonce.clone(), issued_at: msg.issued_at_unix_seconds,
        in_reply_to_nonce: msg.in_reply_to_nonce.clone(), body_type: msg.body_type.clone(), body: msg.body.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::*;

    const AUD: &str = "structmux:3b6a27bcceb6a42d";

    #[test]
    fn owner_daemon_and_agent_chains_verify() {
        let f = Fleet::new();
        let r = f.resolver();
        let (_, c) = owner_chain(&f, T0, T0 + 3600);
        let v = verify_chain(&c, &r, LIVE).unwrap();
        assert_eq!((v.principal(), v.kind(), v.host()), (&f.owner.id(), PrincipalKind::Human, &Host::Daemon(f.daemon.id())));
        assert_eq!(v.device(), &f.laptop.public());
        let (_, c) = daemon_chain(&f.daemon, T0, T0 + 30 * DAY, T0, T0 + 3600);
        let v = verify_chain(&c, &r, LIVE).unwrap();
        assert_eq!((v.kind(), v.host()), (PrincipalKind::Daemon, &Host::Daemon(f.daemon.id())));
        let (_, c) = agent_chain(&f, &subject_on(&f.daemon, "i5"), T0, T0 + 3600);
        let v = verify_chain(&c, &r, LIVE).unwrap();
        assert_eq!((v.principal(), v.kind(), v.host()), (&f.agent_id(), PrincipalKind::Agent, &Host::Daemon(f.daemon.id())));
        assert_eq!(v.subject(), Some(subject_on(&f.daemon, "i5").as_str()));
    }

    #[test]
    fn hostless_human_and_unhosted_agent() {
        let mut f = Fleet::new();
        let mut reg = f.registry();
        reg.entries[0].devices[0].host_daemon_id = None;
        let r = resolver_for(&f.owner, reg).unwrap();
        let (_, c) = owner_chain(&f, T0, T0 + 3600);
        assert_eq!(verify_chain(&c, &r, LIVE).unwrap().host(), &Host::Hostless);
        let agent = Principal::new();
        f.extra.push(entry(&agent, pb::PrincipalKind::Agent));
        let (_, c) = daemon_chain(&agent, T0, T0 + DAY, T0, T0 + 3600);
        let v = verify_chain(&c, &f.resolver(), LIVE).unwrap();
        assert_eq!((v.kind(), v.host()), (PrincipalKind::Agent, &Host::Unhosted));
    }

    #[test]
    fn self_rooted_rejections() {
        let f = Fleet::new();
        let r = f.resolver();
        // unknown principal
        let stranger = Principal::new();
        let (_, c) = daemon_chain(&stranger, T0, T0 + DAY, T0, T0 + 3600);
        assert_eq!(verify_chain(&c, &r, LIVE).unwrap_err(), Error::UnknownPrincipal);
        // a host-vouched agent presenting a self-rooted chain
        let mut reg = f.registry();
        reg.entries[2].kind = pb::PrincipalKind::Agent as i32;
        let (_, mut c) = daemon_chain(&f.daemon, T0, T0 + DAY, T0, T0 + 3600);
        if let Some(pb::signer_chain::Chain::SelfRooted(s)) = c.chain.as_mut() {
            s.session.as_mut().unwrap().principal_genesis = pk(&f.agent.public());
        }
        assert_eq!(verify_chain(&c, &resolver_for(&f.owner, reg).unwrap(), LIVE).unwrap_err(), Error::WrongKind);
        // frozen
        let mut reg = f.registry();
        reg.entries[1].frozen = true;
        let (_, c) = daemon_chain(&f.daemon, T0, T0 + DAY, T0, T0 + 3600);
        assert_eq!(verify_chain(&c, &resolver_for(&f.owner, reg).unwrap(), LIVE).unwrap_err(), Error::Frozen);
        // a device delegation signed by a root that is not current
        let mut rotated = Fleet::new();
        let old = rotated.daemon.root_at(0).public();
        rotated.daemon.rotate(T0);
        let (dev, mut deleg) = rotated.daemon.delegate_device(T0, T0 + DAY);
        deleg.signing_root = pk(&old);
        deleg.signature = rotated.daemon.root_at(0).sign(&crate::transcripts::key_delegation_transcript(&deleg).unwrap());
        let (_, cert) = session_cert(&dev, &rotated.daemon.genesis(), None, None, T0, T0 + 3600);
        let c = pb::SignerChain { chain: Some(pb::signer_chain::Chain::SelfRooted(pb::SelfRooted { device: Some(deleg), session: Some(cert) })) };
        assert_eq!(verify_chain(&c, &rotated.resolver(), LIVE).unwrap_err(), Error::ChainMismatch("device.signing_root"));
    }

    #[test]
    fn human_must_present_the_bound_delegation() {
        let f = Fleet::new();
        let r = f.resolver();
        // an unbound device key
        let (dev, deleg) = f.owner.delegate_device(T0, i64::MAX);
        let (_, cert) = session_cert(&dev, &f.owner.genesis(), None, None, T0, T0 + 3600);
        let c = pb::SignerChain { chain: Some(pb::signer_chain::Chain::SelfRooted(pb::SelfRooted { device: Some(deleg), session: Some(cert) })) };
        assert_eq!(verify_chain(&c, &r, LIVE).unwrap_err(), Error::NotBound);
        // the bound key, re-delegated with a different expiry
        let mut resigned = f.laptop_deleg.clone();
        resigned.not_after_unix_seconds = T0 + 10 * DAY;
        f.owner.sign_delegation(&mut resigned);
        let (_, cert) = session_cert(&f.laptop, &f.owner.genesis(), None, None, T0, T0 + 3600);
        let c = pb::SignerChain { chain: Some(pb::signer_chain::Chain::SelfRooted(pb::SelfRooted { device: Some(resigned), session: Some(cert) })) };
        assert!(matches!(verify_chain(&c, &r, LIVE), Err(Error::ChainMismatch(_))));
    }

    #[test]
    fn a_second_human_verifies_and_cannot_rewrite_its_binding() {
        let mut f = Fleet::new();
        let alice = Principal::new();
        let (alice_dev, alice_deleg) = alice.delegate_device(T0, i64::MAX);
        let mut e = entry(&alice, pb::PrincipalKind::Human);
        e.devices = vec![pb::DeviceBinding {
            device: Some(alice_deleg.clone()),
            approval: None,
            host_daemon_id: None,
        }];
        f.extra.push(e);
        let r = f.resolver();
        let chain = |d: pb::KeyDelegation| {
            let (_, cert) = session_cert(
                &alice_dev,
                &alice.genesis(),
                None,
                None,
                T0,
                T0 + 3600,
            );
            pb::SignerChain {
                chain: Some(pb::signer_chain::Chain::SelfRooted(pb::SelfRooted {
                    device: Some(d),
                    session: Some(cert),
                })),
            }
        };
        let v = verify_chain(&chain(alice_deleg.clone()), &r, LIVE).unwrap();
        assert_eq!(
            (v.principal(), v.kind(), v.host()),
            (&alice.id(), PrincipalKind::Human, &Host::Hostless)
        );
        let mut resigned = alice_deleg;
        resigned.not_after_unix_seconds = T0 + 5 * DAY;
        alice.sign_delegation(&mut resigned);
        assert!(matches!(
            verify_chain(&chain(resigned), &r, LIVE),
            Err(Error::ChainMismatch(_))
        ));
    }

    #[test]
    fn chains_verify_after_an_authority_rotation() {
        let mut f = Fleet::new();
        f.owner.rotate(T0);
        let (laptop, d) = f.owner.delegate_device(T0, i64::MAX);
        let (presence, a) = f.owner.delegate_approval(T0, i64::MAX);
        (f.laptop, f.laptop_deleg, f.presence, f.presence_deleg) =
            (laptop, d, presence, a);
        let r = f.resolver();
        let (_, c) = owner_chain(&f, T0, T0 + 3600);
        assert_eq!(verify_chain(&c, &r, LIVE).unwrap().principal(), &f.owner.id());
    }

    #[test]
    fn registry_revoked_daemon_device_key_by_time() {
        let mut f = Fleet::new();
        let (dev, deleg) = f.daemon.delegate_device(T0, T0 + DAY);
        f.daemon_revocations = vec![f.daemon.revoke(&dev.public(), T0 + 100)];
        let r = f.resolver();
        let (_, cert) = session_cert(
            &dev,
            &f.daemon.genesis(),
            None,
            None,
            T0,
            T0 + 3600,
        );
        let c = pb::SignerChain {
            chain: Some(pb::signer_chain::Chain::SelfRooted(pb::SelfRooted {
                device: Some(deleg),
                session: Some(cert),
            })),
        };
        assert!(verify_chain(&c, &r, accepted(T0 + 99)).is_ok());
        assert_eq!(
            verify_chain(&c, &r, accepted(T0 + 100)).unwrap_err(),
            Error::KeyRevoked
        );
    }

    #[test]
    fn frozen_host_denies_its_bound_devices() {
        let f = Fleet::new();
        let mut reg = f.registry();
        reg.entries[1].frozen = true;
        let (_, c) = owner_chain(&f, T0, T0 + 3600);
        assert_eq!(verify_chain(&c, &resolver_for(&f.owner, reg).unwrap(), LIVE).unwrap_err(), Error::HostFrozen);
    }

    #[test]
    fn revoked_device_key_by_time() {
        let mut f = Fleet::new();
        f.owner_revocations = vec![f.owner.revoke(&f.laptop.public(), T0 + 100)];
        let r = f.resolver();
        let (_, c) = owner_chain(&f, T0, T0 + 3600);
        assert!(verify_chain(&c, &r, accepted(T0 + 99)).is_ok());
        assert_eq!(verify_chain(&c, &r, accepted(T0 + 100)).unwrap_err(), Error::KeyRevoked);
    }

    #[test]
    fn unlisted_delegation_time_rules() {
        let f = Fleet::new();
        let r = f.resolver();
        let now = T0 + 60;
        // dated 1 hour ahead: not yet valid; 10 s ahead: within skew
        let (_, c) = daemon_chain(&f.daemon, now + 3600, now + 3600 + DAY, now, now + 3600);
        assert_eq!(verify_chain(&c, &r, LIVE).unwrap_err(), Error::NotYetValid("device delegation"));
        let (_, c) = daemon_chain(&f.daemon, now + 10, now + 10 + DAY, now, now + 3600);
        assert!(verify_chain(&c, &r, LIVE).is_ok());
        // 31 days passes, 31 days + 1 s fails
        let (_, c) = daemon_chain(&f.daemon, T0, T0 + 31 * DAY, T0, T0 + 3600);
        assert!(verify_chain(&c, &r, LIVE).is_ok());
        let (_, c) = daemon_chain(&f.daemon, T0, T0 + 31 * DAY + 1, T0, T0 + 3600);
        assert!(matches!(verify_chain(&c, &r, LIVE), Err(Error::InvalidField { field: "device.not_after_unix_seconds", .. })));
        // expired
        let (_, c) = daemon_chain(&f.daemon, T0 - 2 * DAY, T0 - DAY, T0, T0 + 3600);
        assert_eq!(verify_chain(&c, &r, LIVE).unwrap_err(), Error::Expired("device delegation"));
    }

    #[test]
    fn session_cert_time_rules() {
        let f = Fleet::new();
        let r = f.resolver();
        let at = |t| accepted(t);
        let (_, c) = owner_chain(&f, T0, T0 + 86_400);
        assert!(verify_chain(&c, &r, at(T0 + 10)).is_ok());
        let (_, c) = owner_chain(&f, T0, T0 + 86_401);
        assert!(matches!(verify_chain(&c, &r, at(T0 + 10)), Err(Error::InvalidField { field: "session.not_after_unix_seconds", .. })));
        let (_, c) = owner_chain(&f, T0 + 10, T0 + 10);
        assert!(matches!(verify_chain(&c, &r, at(T0 + 10)), Err(Error::InvalidField { .. })));
        let (_, c) = owner_chain(&f, T0 + 100, T0 + 3600);
        assert!(verify_chain(&c, &r, at(T0 + 75)).is_ok(), "within the not_before tolerance");
        assert_eq!(verify_chain(&c, &r, at(T0 + 69)).unwrap_err(), Error::NotYetValid("session cert"));
        let (_, c) = owner_chain(&f, T0, T0 + 3600);
        assert_eq!(verify_chain(&c, &r, at(T0 + 3601)).unwrap_err(), Error::Expired("session cert"));
    }

    #[test]
    fn host_vouched_rejections() {
        let f = Fleet::new();
        // agent not allowed on this daemon
        let mut reg = f.registry();
        reg.entries[2].allowed_hosts = vec![Principal::new().id().to_string()];
        let (_, c) = agent_chain(&f, &subject_on(&f.daemon, "i5"), T0, T0 + 3600);
        assert_eq!(verify_chain(&c, &resolver_for(&f.owner, reg).unwrap(), LIVE).unwrap_err(), Error::NotVouched);
        // "*" allows any daemon
        let mut reg = f.registry();
        reg.entries[2].allowed_hosts = vec!["*".into()];
        assert!(verify_chain(&c, &resolver_for(&f.owner, reg).unwrap(), LIVE).is_ok());
        // frozen agent
        let mut reg = f.registry();
        reg.entries[2].frozen = true;
        assert_eq!(verify_chain(&c, &resolver_for(&f.owner, reg).unwrap(), LIVE).unwrap_err(), Error::Frozen);
    }

    #[test]
    fn subject_must_belong_to_the_vouching_daemon() {
        let mut f = Fleet::new();
        let other = Principal::new();
        f.extra.push(entry(&other, pb::PrincipalKind::Daemon));
        let r = f.resolver();
        let (_, c) = agent_chain(&f, &subject_on(&other, "i5"), T0, T0 + 3600);
        assert_eq!(verify_chain(&c, &r, LIVE).unwrap_err(), Error::NotVouched);
    }

    #[test]
    fn signed_messages() {
        let f = Fleet::new();
        let r = f.resolver();
        let (s, c) = owner_chain(&f, T0, T0 + 3600);
        let m = signed_message(&s, c, AUD, T0 + 60);
        let v = verify_signed_message(&m, AUD, &r, LIVE).unwrap();
        assert_eq!((v.body(), v.nonce(), v.chain().principal()), (&[1u8, 2][..], &[7u8; 16][..], &f.owner.id()));
        assert_eq!(verify_signed_message(&m, "structmux:other", &r, LIVE).unwrap_err(), Error::WrongAudience);
        let mut tampered = m.clone(); tampered.body.push(3);
        assert_eq!(verify_signed_message(&tampered, AUD, &r, LIVE).unwrap_err(), Error::BadSignature);
        let mut empty = m.clone(); empty.signature.clear();
        assert_eq!(verify_signed_message(&empty, AUD, &r, LIVE).unwrap_err(), Error::EmptySignature);
        // skew only when live
        let (s, c) = owner_chain(&f, T0, T0 + 3600);
        let late = signed_message(&s, c, AUD, T0 + 60 + 31);
        assert_eq!(verify_signed_message(&late, AUD, &r, LIVE).unwrap_err(), Error::Skew);
        assert!(verify_signed_message(&late, AUD, &r, accepted(T0 + 60)).is_ok());
    }
}
