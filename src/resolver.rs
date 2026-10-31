//! `Resolver`: a verified registry plus verified peer revocations, built
//! only from signed inputs (1b spec section 4).

use crate::registry::{check_registry, VerifiedBinding, VerifiedEntry};
use crate::{pb, Error, PrincipalId, PublicKey, Result, VerifiedDocument};
use prost::Message;
use std::collections::BTreeMap;

#[derive(Clone, Debug)]
pub struct VerifiedPeerRevocation {
    pub(crate) target: PrincipalId,
    pub(crate) revoked: Option<PublicKey>,
    pub(crate) accepted_at: i64,
    pub(crate) document_id: [u8; 32],
}

impl VerifiedPeerRevocation {
    pub fn target(&self) -> &PrincipalId { &self.target }
    /// `None` freezes the whole principal.
    pub fn revoked(&self) -> Option<&PublicKey> { self.revoked.as_ref() }
    /// The receiver's acceptance time, never the signer's `issued_at`.
    pub fn accepted_at(&self) -> i64 { self.accepted_at }
    pub fn document_id(&self) -> &[u8; 32] { &self.document_id }
}

#[derive(Clone, Debug)]
pub struct Resolver {
    authority: PrincipalId,
    document_version: u64,
    document_id: [u8; 32],
    allow_peer_revocation: bool,
    pub(crate) entries: BTreeMap<PrincipalId, VerifiedEntry>,
    peer: Vec<VerifiedPeerRevocation>,
}

/// Field 1 must occur exactly once: protobuf merges a repeated message
/// field instead of rejecting it.
fn decode_carrier(body: &[u8]) -> Result<pb::PrincipalRegistry> {
    use prost::encoding::{decode_key, skip_field, DecodeContext};
    let not_protobuf = || Error::InvalidRegistry { field: "body", reason: "not protobuf" };
    let mut buf = body;
    let mut count = 0;
    while !buf.is_empty() {
        let (tag, wire_type) = decode_key(&mut buf).map_err(|_| not_protobuf())?;
        if tag == 1 {
            count += 1;
        }
        skip_field(wire_type, tag, &mut buf, DecodeContext::default()).map_err(|_| not_protobuf())?;
    }
    if count != 1 {
        return Err(Error::InvalidRegistry { field: "body", reason: "the registry must be field 1, exactly once" });
    }
    pb::RegistryCarrier::decode(body).map_err(|_| not_protobuf())?
        .registry
        .ok_or(Error::InvalidRegistry { field: "body", reason: "registry missing" })
}

impl Resolver {
    pub fn from_document(doc: &VerifiedDocument, registry_type: &str) -> Result<Resolver> {
        if doc.document_type() != registry_type {
            return Err(Error::WrongDocumentType);
        }
        let checked = check_registry(&decode_carrier(doc.body())?, doc.authority_chain())?;
        Ok(Resolver {
            authority: doc.authority(), document_version: doc.version(), document_id: *doc.id(),
            allow_peer_revocation: checked.allow_peer_revocation, entries: checked.entries, peer: vec![],
        })
    }

    pub fn with_peer_revocation(&self, rev: VerifiedPeerRevocation) -> Result<Resolver> {
        if rev.document_id != self.document_id {
            return Err(Error::StalePeerRevocation);
        }
        let mut r = self.clone();
        r.peer.push(rev);
        Ok(r)
    }

    pub fn authority(&self) -> &PrincipalId { &self.authority }
    pub fn document_version(&self) -> u64 { self.document_version }
    pub fn document_id(&self) -> &[u8; 32] { &self.document_id }
    pub fn allow_peer_revocation(&self) -> bool { self.allow_peer_revocation }
    pub fn entry(&self, id: &PrincipalId) -> Option<&VerifiedEntry> { self.entries.get(id) }
    /// Entries with this name, not frozen at `at`. 0 or more than 1 is an
    /// error at the caller.
    pub fn resolve_name(&self, name: &str, at: i64) -> Vec<&PrincipalId> {
        self.entries.values()
            .filter(|e| e.name() == Some(name) && !self.is_frozen(e.id(), at))
            .map(|e| e.id())
            .collect()
    }

    pub fn binding(&self, principal: &PrincipalId, device: &PublicKey) -> Option<&VerifiedBinding> {
        self.entry(principal)?.bindings().iter().find(|b| b.device_key() == device)
    }

    /// False for a principal with no entry; callers look the entry up first.
    pub fn is_frozen(&self, principal: &PrincipalId, at: i64) -> bool {
        let Some(e) = self.entry(principal) else { return false };
        let current = e.current_root().map(|d| d.signing());
        e.frozen || self.peer.iter().any(|p| {
            &p.target == principal && p.accepted_at <= at && (p.revoked.is_none() || p.revoked.as_ref() == current)
        })
    }

    /// Revoked for this principal only.
    pub fn is_revoked(&self, principal: &PrincipalId, key: &PublicKey, at: i64) -> bool {
        let Some(e) = self.entry(principal) else { return false };
        e.revocations.iter().any(|(k, t)| k == key && *t <= at)
            || self.peer.iter().any(|p| &p.target == principal && p.revoked.as_ref() == Some(key) && p.accepted_at <= at)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AllowedHost, PrincipalKind};
    use crate::testkit::*;
    use prost::Message;
    use crate::{verify_signed_document, AuthorityChain};

    #[test]
    fn the_standard_fleet_resolves() {
        let f = Fleet::new();
        let r = f.resolver();
        assert_eq!(r.authority(), &f.owner.id());
        assert_eq!(r.document_version(), 1);
        assert!(r.allow_peer_revocation());
        let owner = r.entry(&f.owner.id()).unwrap();
        assert_eq!(owner.kind(), PrincipalKind::Human);
        let b = r.binding(&f.owner.id(), &f.laptop.public()).unwrap();
        assert_eq!(b.host(), Some(&f.daemon.id()));
        assert_eq!(b.approval_key(), Some(&f.presence.public()));
        assert_eq!(r.entry(&f.daemon.id()).unwrap().kind(), PrincipalKind::Daemon);
        assert_eq!(r.entry(&f.agent_id()).unwrap().allowed_hosts(), &[AllowedHost::Daemon(f.daemon.id())]);
        assert!(!r.is_frozen(&f.daemon.id(), T0));
    }

    #[test]
    fn carrier_decoding() {
        let f = Fleet::new();
        // a larger body with the registry at field 1 and unknown fields elsewhere
        let mut body = carrier_body(&f.registry());
        body.extend([0x10, 0x01]); // field 2, varint 1
        let doc = sign_document(&f.owner, 1, body);
        let v = verify_signed_document(&doc, DOC_TYPE, &AuthorityChain::genesis(f.owner.genesis())).unwrap();
        assert!(Resolver::from_document(&v, DOC_TYPE).is_ok());
        assert_eq!(Resolver::from_document(&v, "other").unwrap_err(), Error::WrongDocumentType);
        // field 1 twice
        let mut twice = carrier_body(&f.registry());
        twice.extend(carrier_body(&f.registry()));
        let v = verify_signed_document(&sign_document(&f.owner, 1, twice), DOC_TYPE, &AuthorityChain::genesis(f.owner.genesis())).unwrap();
        invalid(Resolver::from_document(&v, DOC_TYPE), "body");
        // no field 1
        let v = verify_signed_document(&sign_document(&f.owner, 1, vec![0x10, 0x01]), DOC_TYPE, &AuthorityChain::genesis(f.owner.genesis())).unwrap();
        invalid(Resolver::from_document(&v, DOC_TYPE), "body");
        let _ = pb::RegistryCarrier::default().encode_to_vec();
    }

    fn mutate(f: &Fleet, m: impl FnOnce(&mut pb::PrincipalRegistry)) -> Result<Resolver> {
        let mut reg = f.registry();
        m(&mut reg);
        resolver_for(&f.owner, reg)
    }

    #[test]
    fn every_entry_checks() {
        let f = Fleet::new();
        invalid(mutate(&f, |r| r.entries[1].principal_id = r.entries[1].principal_id.to_uppercase()), "entries.principal_id");
        invalid(mutate(&f, |r| { let d = r.entries[1].clone(); r.entries.push(d); }), "entries.principal_id");
        invalid(mutate(&f, |r| r.entries[1].kind = 0), "entries.kind");
        invalid(mutate(&f, |r| r.entries[1].name = Some(String::new())), "entries.name");
        invalid(mutate(&f, |r| r.entries[1].name = Some("0123456789ABCDEF".into())), "entries.name");
        invalid(mutate(&f, |r| { r.entries[1].name = Some("x".into()); r.entries[2].name = Some("x".into()); }), "entries.name");
        // a frozen entry does not block the name
        assert!(mutate(&f, |r| { r.entries[1].name = Some("x".into()); r.entries[2].name = Some("x".into()); r.entries[2].frozen = true; }).is_ok());
    }

    #[test]
    fn unknown_kind_is_skipped_but_counted() {
        let f = Fleet::new();
        let r = mutate(&f, |r| r.entries[2].kind = 99).unwrap();
        assert!(r.entry(&f.agent_id()).is_none());
        // a binding naming it as host is invalid
        invalid(mutate(&f, |r| r.entries[1].kind = 99), "devices.host_daemon_id");
        // its genesis still counts for distinctness
        let other = Principal::new();
        let mut skipped = entry(&other, pb::PrincipalKind::Daemon);
        skipped.kind = 99;
        let mut clash = entry(&Principal::new(), pb::PrincipalKind::Daemon);
        clash.current_root = Some(pb::PublicKeyDuo { signing: clash.current_root.unwrap().signing, encryption: pk(&other.genesis()) });
        invalid(mutate(&f, |r| { r.entries.push(skipped); r.entries.push(clash); }), "entries");
    }

    #[test]
    fn self_rooted_checks() {
        let f = Fleet::new();
        invalid(mutate(&f, |r| r.entries[1].current_root = None), "entries.current_root");
        invalid(mutate(&f, |r| { let s = r.entries[1].current_root.as_ref().unwrap().signing.clone(); r.entries[1].current_root.as_mut().unwrap().encryption = s; }), "entries.current_root");
        // current root is not the end of the (empty) rotation chain
        invalid(mutate(&f, |r| r.entries[1].current_root.as_mut().unwrap().signing = pk(&Signer::new().public())), "entries.current_root");
        // a rotated daemon verifies; a broken rotation does not
        let mut g = Fleet::new();
        g.daemon.rotate(T0);
        assert!(g.try_resolver().is_ok());
        invalid(mutate(&g, |r| r.entries[1].rotations[0].signature[0] ^= 1), "entries.rotations");
        invalid(mutate(&f, |r| r.entries[1].devices = r.entries[0].devices.clone()), "entries.devices");
        invalid(mutate(&f, |r| r.entries[1].allowed_hosts = vec!["*".into()]), "entries.allowed_hosts");
        invalid(mutate(&f, |r| r.entries[0].allowed_hosts = vec!["*".into()]), "entries.allowed_hosts");
    }

    #[test]
    fn authority_entry_checks() {
        let mut f = Fleet::new();
        invalid(mutate(&f, |r| { r.entries.remove(0); }), "entries");
        invalid(mutate(&f, |r| r.entries[0].kind = pb::PrincipalKind::Daemon as i32), "entries");
        invalid(mutate(&f, |r| r.entries[0].frozen = true), "entries.frozen");
        // after an authority rotation, its entry's current_root is the new head (B1)
        f.owner.rotate(T0);
        let (laptop, d) = f.owner.delegate_device(T0, i64::MAX);
        let (presence, a) = f.owner.delegate_approval(T0, i64::MAX);
        (f.laptop, f.laptop_deleg, f.presence, f.presence_deleg) = (laptop, d, presence, a);
        let r = resolver_for(&f.owner, f.registry()).map(|r| r.authority().clone());
        // resolver_for accepts from genesis; the document extends it
        assert_eq!(r.unwrap(), f.owner.id());
        invalid(mutate(&f, |r| r.entries[0].rotations = f.owner.rotations.clone()), "entries.rotations");
        let old_head = f.owner.root_at(0).public();
        invalid(mutate(&f, |r| r.entries[0].current_root.as_mut().unwrap().signing = pk(&old_head)), "entries.current_root");
    }

    #[test]
    fn binding_checks() {
        let f = Fleet::new();
        // a device delegation signed by another root
        let stranger = Principal::new();
        let (_, foreign) = stranger.delegate_device(T0, i64::MAX);
        invalid(mutate(&f, |r| r.entries[0].devices[0].device = Some(foreign.clone())), "devices.device");
        // purpose mismatch: the approval delegation in the device slot
        invalid(mutate(&f, |r| r.entries[0].devices[0].device = Some(f.presence_deleg.clone())), "devices.device");
        invalid(mutate(&f, |r| r.entries[0].devices[0].approval = Some(f.laptop_deleg.clone())), "devices.approval");
        // not_after 0
        let (_, mut zero) = f.owner.delegate_device(T0, 0);
        f.owner.sign_delegation(&mut zero);
        invalid(mutate(&f, |r| r.entries[0].devices[0].device = Some(zero.clone())), "devices.device");
        // tampered signature
        invalid(mutate(&f, |r| r.entries[0].devices[0].device.as_mut().unwrap().signature[0] ^= 1), "devices.device");
        // host names no DAEMON entry
        invalid(mutate(&f, |r| r.entries[0].devices[0].host_daemon_id = Some(f.agent_id().to_string())), "devices.host_daemon_id");
        invalid(mutate(&f, |r| r.entries[0].devices[0].host_daemon_id = Some(String::new())), "devices.host_daemon_id");
        // hostless is fine
        let r = mutate(&f, |r| r.entries[0].devices[0].host_daemon_id = None).unwrap();
        assert_eq!(r.binding(&f.owner.id(), &f.laptop.public()).unwrap().host(), None);
    }

    #[test]
    fn many_humans() {
        let mut f = Fleet::new();
        let alice = Principal::new();
        let (alice_dev, alice_deleg) = alice.delegate_device(T0, i64::MAX);
        let mut e = entry(&alice, pb::PrincipalKind::Human);
        e.devices = vec![pb::DeviceBinding { device: Some(alice_deleg), approval: None, host_daemon_id: None }];
        f.extra.push(e.clone());
        let r = f.resolver();
        assert!(r.binding(&alice.id(), &alice_dev.public()).is_some());
        // the authority signing alice's device instead of alice's own root
        let (_, mut by_owner) = f.owner.delegate_device(T0, i64::MAX);
        by_owner.principal_genesis = pk(&alice.genesis());
        f.owner.sign_delegation(&mut by_owner);
        e.devices[0].device = Some(by_owner);
        f.extra = vec![e];
        invalid(f.try_resolver(), "devices.device");
    }

    #[test]
    fn service_entry_loads_with_kind_service() {
        let mut f = Fleet::new();
        let service = Principal::new();
        f.extra.push(entry(&service, pb::PrincipalKind::Service));
        let resolver = f.resolver();
        let loaded = resolver.entry(&service.id()).unwrap();
        assert_eq!(loaded.kind(), PrincipalKind::Service);
        assert!(loaded.is_self_rooted());
    }

    #[test]
    fn service_cannot_be_the_authority() {
        let f = Fleet::new();
        invalid(mutate(&f, |registry| {
            registry.entries[0].kind = pb::PrincipalKind::Service as i32;
        }), "entries");
    }

    #[test]
    fn two_human_entries_are_allowed() {
        let mut f = Fleet::new();
        let second = Principal::new();
        f.extra.push(entry(&second, pb::PrincipalKind::Human));
        let resolver = f.resolver();
        assert_eq!(resolver.entry(&f.owner.id()).unwrap().kind(), PrincipalKind::Human);
        assert_eq!(resolver.entry(&second.id()).unwrap().kind(), PrincipalKind::Human);
    }

    #[test]
    fn service_with_registry_devices_is_invalid() {
        let f = Fleet::new();
        let service = Principal::new();
        let mut service_entry = entry(&service, pb::PrincipalKind::Service);
        service_entry.devices = f.registry().entries[0].devices.clone();
        invalid(mutate(&f, |registry| registry.entries.push(service_entry)), "entries.devices");
    }

    #[test]
    fn service_with_allowed_hosts_is_invalid() {
        let f = Fleet::new();
        let service = Principal::new();
        let mut service_entry = entry(&service, pb::PrincipalKind::Service);
        service_entry.allowed_hosts = vec!["*".into()];
        invalid(mutate(&f, |registry| registry.entries.push(service_entry)), "entries.allowed_hosts");
    }

    #[test]
    fn agent_checks() {
        let f = Fleet::new();
        invalid(mutate(&f, |r| r.entries[2].allowed_hosts.clear()), "entries.allowed_hosts");
        invalid(mutate(&f, |r| r.entries[2].allowed_hosts = vec!["laptop".into()]), "entries.allowed_hosts");
        // a host id that names no DAEMON is allowed
        assert!(mutate(&f, |r| r.entries[2].allowed_hosts = vec![Principal::new().id().to_string()]).is_ok());
        // self-rooted agent: current_root, no allowed_hosts
        let agent = Principal::new();
        let mut a = entry(&agent, pb::PrincipalKind::Agent);
        assert!(mutate(&f, |r| r.entries.push(a.clone())).is_ok());
        a.allowed_hosts = vec!["*".into()];
        invalid(mutate(&f, |r| r.entries.push(a.clone())), "entries.allowed_hosts");
        // a host-vouched agent with revocations
        invalid(mutate(&f, |r| r.entries[2].revocations = vec![f.daemon.revoke(&Signer::new().public(), T0)]), "entries.rotations");
    }

    #[test]
    fn revocation_checks() {
        let mut f = Fleet::new();
        // HUMAN: may revoke only its own keys
        f.owner_revocations = vec![f.owner.revoke(&Signer::new().public(), T0)];
        invalid(f.try_resolver(), "revocations.revoked");
        f.owner_revocations = vec![f.owner.revoke(&f.laptop.public(), T0 + 10)];
        let r = f.resolver();
        assert!(!r.is_revoked(&f.owner.id(), &f.laptop.public(), T0 + 9));
        assert!(r.is_revoked(&f.owner.id(), &f.laptop.public(), T0 + 10));
        // scoped to its principal: the same key under another principal is unaffected
        assert!(!r.is_revoked(&f.daemon.id(), &f.laptop.public(), T0 + 10));
        // DAEMON: any key, signed by its own root
        f.owner_revocations.clear();
        let unlisted = Signer::new().public();
        f.daemon_revocations = vec![f.daemon.revoke(&unlisted, T0)];
        assert!(f.resolver().is_revoked(&f.daemon.id(), &unlisted, T0));
        // signed by another principal's root
        f.daemon_revocations = vec![{ let mut r = f.owner.revoke(&unlisted, T0); r.principal_genesis = pk(&f.daemon.genesis()); r.signature = f.owner.root().sign(&crate::transcripts::key_revocation_transcript(&r).unwrap()); r }];
        invalid(f.try_resolver(), "revocations.revoked_by");
        // revoking the entry's own current root
        f.daemon_revocations = vec![f.daemon.revoke(&f.daemon.root().public(), T0)];
        invalid(f.try_resolver(), "revocations.revoked");
        f.daemon_revocations.clear();
        f.owner_revocations = vec![f.owner.revoke(&f.owner.root().public(), T0)];
        invalid(f.try_resolver(), "revocations.revoked");
        f.owner_revocations.clear();
        // a revocation naming another principal
        let mut other = f.daemon.revoke(&unlisted, T0);
        other.principal_genesis = pk(&f.owner.genesis());
        f.daemon_revocations = vec![other];
        invalid(f.try_resolver(), "revocations.principal_genesis");
        // a revocation whose signature is broken
        let mut broken = f.daemon.revoke(&unlisted, T0);
        broken.signature[0] ^= 1;
        f.daemon_revocations = vec![broken];
        invalid(f.try_resolver(), "revocations");
        f.daemon_revocations.clear();
        // survives a rotation: signed by the old root, still valid after
        let mut g = Fleet::new();
        let k = Signer::new().public();
        let rev = g.daemon.revoke(&k, T0);
        g.daemon.rotate(T0 + 1);
        g.daemon_revocations = vec![rev];
        assert!(g.resolver().is_revoked(&g.daemon.id(), &k, T0));
    }

    #[test]
    fn distinctness() {
        let f = Fleet::new();
        // the laptop key bound under the daemon's entry as its encryption half
        invalid(mutate(&f, |r| r.entries[1].current_root.as_mut().unwrap().encryption = pk(&f.laptop.public())), "entries");
        // approval key equal to a duo half in the same binding
        let mut dup = f.presence_deleg.clone();
        dup.delegated = f.laptop_deleg.delegated_encryption.clone();
        f.owner.sign_delegation(&mut dup);
        invalid(mutate(&f, |r| r.entries[0].devices[0].approval = Some(dup)), "entries");
        // root encryption half reused as another principal's genesis
        let enc = f.owner.current_root().encryption.unwrap();
        let mut a = pb::RegistryEntry { principal_id: PrincipalId::from_genesis(PublicKey::try_from(&enc).unwrap()).to_string(), kind: pb::PrincipalKind::Agent as i32, allowed_hosts: vec!["*".into()], ..Default::default() };
        a.name = None;
        invalid(mutate(&f, |r| r.entries.push(a)), "entries");
    }

    #[test]
    fn names_resolve_skipping_frozen() {
        let f = Fleet::new();
        let r = mutate(&f, |r| r.entries[1].name = Some("laptop".into())).unwrap();
        assert_eq!(r.resolve_name("laptop", T0), vec![&f.daemon.id()]);
        let r = mutate(&f, |r| { r.entries[1].name = Some("laptop".into()); r.entries[1].frozen = true; }).unwrap();
        assert!(r.resolve_name("laptop", T0).is_empty());
        assert!(r.is_frozen(&f.daemon.id(), T0));
    }
}
