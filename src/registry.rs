//! Registry body checks (1b spec 4.2) and the verified views a resolver
//! exposes. Nothing here has a public constructor.

use crate::authority::rotation_roots;
use crate::transcripts::{key_delegation_transcript, key_revocation_transcript};
use crate::{pb, verify_p256, AuthorityChain, Error, PrincipalId, PublicKey, PublicKeyDuo, Result};
use std::collections::{BTreeMap, HashSet};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PrincipalKind {
    Human,
    Agent,
    Daemon,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AllowedHost {
    Any,
    Daemon(PrincipalId),
}

#[derive(Clone, Debug)]
pub struct VerifiedBinding {
    pub(crate) device: pb::KeyDelegation,
    pub(crate) device_key: PublicKey,
    pub(crate) approval: Option<(pb::KeyDelegation, PublicKey)>,
    pub(crate) host: Option<PrincipalId>,
}

impl VerifiedBinding {
    pub fn device_delegation(&self) -> &pb::KeyDelegation { &self.device }
    pub fn device_key(&self) -> &PublicKey { &self.device_key }
    pub fn device_not_after(&self) -> i64 { self.device.not_after_unix_seconds }
    pub fn approval_delegation(&self) -> Option<&pb::KeyDelegation> { self.approval.as_ref().map(|(d, _)| d) }
    pub fn approval_key(&self) -> Option<&PublicKey> { self.approval.as_ref().map(|(_, k)| k) }
    /// `None` = hostless.
    pub fn host(&self) -> Option<&PrincipalId> { self.host.as_ref() }
}

#[derive(Clone, Debug)]
pub struct VerifiedEntry {
    pub(crate) id: PrincipalId,
    pub(crate) kind: PrincipalKind,
    pub(crate) name: Option<String>,
    pub(crate) frozen: bool,
    pub(crate) current_root: Option<PublicKeyDuo>,
    pub(crate) roots: Vec<PublicKey>,
    pub(crate) rotations: Vec<pb::RootRotation>,
    pub(crate) revocations: Vec<(PublicKey, i64)>,
    pub(crate) bindings: Vec<VerifiedBinding>,
    pub(crate) allowed_hosts: Vec<AllowedHost>,
}

impl VerifiedEntry {
    pub fn id(&self) -> &PrincipalId { &self.id }
    pub fn kind(&self) -> PrincipalKind { self.kind }
    pub fn name(&self) -> Option<&str> { self.name.as_deref() }
    pub fn is_self_rooted(&self) -> bool { self.current_root.is_some() }
    pub fn current_root(&self) -> Option<&PublicKeyDuo> { self.current_root.as_ref() }
    /// Genesis through current root; empty for a host-vouched agent.
    pub fn roots(&self) -> &[PublicKey] { &self.roots }
    pub fn rotations(&self) -> &[pb::RootRotation] { &self.rotations }
    pub fn bindings(&self) -> &[VerifiedBinding] { &self.bindings }
    pub fn allowed_hosts(&self) -> &[AllowedHost] { &self.allowed_hosts }
}

pub(crate) struct CheckedRegistry {
    pub entries: BTreeMap<PrincipalId, VerifiedEntry>,
    pub allow_peer_revocation: bool,
}

fn bad(field: &'static str, reason: &'static str) -> Error {
    Error::InvalidRegistry { field, reason }
}

fn key(k: &Option<pb::PublicKey>) -> Option<PublicKey> {
    k.as_ref().and_then(|k| PublicKey::try_from(k).ok())
}

/// Every key at most once in the registry (spec 4.2, distinctness).
#[derive(Default)]
struct KeySet(HashSet<PublicKey>);

impl KeySet {
    fn add(&mut self, k: &PublicKey) -> Result<()> {
        if !self.0.insert(k.clone()) {
            return Err(bad("entries", "a public key appears twice"));
        }
        Ok(())
    }
}

fn check_delegation(d: &pb::KeyDelegation, entry: &PrincipalId, root: &PublicKey, purpose: pb::KeyPurpose, field: &'static str) -> Result<PublicKey> {
    if key(&d.principal_genesis).as_ref() != Some(entry.genesis()) {
        return Err(bad(field, "principal_genesis is not this entry"));
    }
    if key(&d.signing_root).as_ref() != Some(root) {
        return Err(bad(field, "not signed by this entry's current root"));
    }
    if d.purpose != purpose as i32 {
        return Err(bad(field, "wrong purpose"));
    }
    if d.not_after_unix_seconds == 0 {
        return Err(bad(field, "not_after is 0; write i64::MAX for no expiry"));
    }
    let transcript = key_delegation_transcript(d).map_err(|_| bad(field, "malformed"))?;
    verify_p256(root, &transcript, &d.signature).map_err(|_| bad(field, "signature does not verify"))?;
    key(&d.delegated).ok_or_else(|| bad(field, "delegated missing"))
}

fn is_16_hex(s: &str) -> bool {
    s.len() == 16 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

pub(crate) fn check_registry(reg: &pb::PrincipalRegistry, chain: &AuthorityChain) -> Result<CheckedRegistry> {
    let authority = chain.principal();

    // Ids, kinds, short ids. An unknown non-zero kind is skipped (spec 2.2).
    let mut short_ids = HashSet::new();
    let mut parsed = Vec::with_capacity(reg.entries.len());
    for e in &reg.entries {
        let id = PrincipalId::parse_canonical(&e.principal_id).map_err(|_| bad("entries.principal_id", "not canonical"))?;
        if !short_ids.insert(id.short_id()) {
            return Err(bad("entries.principal_id", "short id repeated"));
        }
        let kind = match pb::PrincipalKind::try_from(e.kind) {
            Ok(pb::PrincipalKind::Unspecified) => return Err(bad("entries.kind", "unspecified")),
            Ok(pb::PrincipalKind::Human) => Some(PrincipalKind::Human),
            Ok(pb::PrincipalKind::Agent) => Some(PrincipalKind::Agent),
            Ok(pb::PrincipalKind::Daemon) => Some(PrincipalKind::Daemon),
            Err(_) => None,
        };
        parsed.push((e, id, kind));
    }

    let mut names = HashSet::new();
    for (e, _, kind) in &parsed {
        if let Some(n) = &e.name {
            if n.is_empty() {
                return Err(bad("entries.name", "empty"));
            }
            if is_16_hex(n) {
                return Err(bad("entries.name", "16 hex characters"));
            }
            if kind.is_some() && !e.frozen && !names.insert(n.as_str()) {
                return Err(bad("entries.name", "shared by two non-frozen entries"));
            }
        }
    }

    let daemons: HashSet<&PrincipalId> = parsed.iter()
        .filter(|(_, _, k)| *k == Some(PrincipalKind::Daemon))
        .map(|(_, id, _)| id)
        .collect();

    let mut keys = KeySet::default();
    let mut entries = BTreeMap::new();
    let mut authority_seen = false;
    for (e, id, kind) in &parsed {
        let Some(kind) = *kind else {
            keys.add(id.genesis())?;
            continue;
        };
        let is_authority = *id == authority;
        if is_authority {
            if kind != PrincipalKind::Human {
                return Err(bad("entries", "the authority's entry is not HUMAN"));
            }
            if e.frozen {
                return Err(bad("entries.frozen", "the authority cannot freeze itself in its own document"));
            }
            authority_seen = true;
        }
        let self_rooted = match kind {
            PrincipalKind::Human | PrincipalKind::Daemon => true,
            PrincipalKind::Agent => e.current_root.is_some(),
        };

        // Kind-specific field rules.
        match kind {
            PrincipalKind::Human if !e.allowed_hosts.is_empty() => return Err(bad("entries.allowed_hosts", "only for AGENT")),
            PrincipalKind::Daemon if !e.devices.is_empty() => return Err(bad("entries.devices", "only for HUMAN")),
            PrincipalKind::Daemon if !e.allowed_hosts.is_empty() => return Err(bad("entries.allowed_hosts", "only for AGENT")),
            PrincipalKind::Agent if !e.devices.is_empty() => return Err(bad("entries.devices", "only for HUMAN")),
            PrincipalKind::Agent if self_rooted && !e.allowed_hosts.is_empty() => {
                return Err(bad("entries.allowed_hosts", "an AGENT is self-rooted or host-vouched, never both"))
            }
            PrincipalKind::Agent if !self_rooted && e.allowed_hosts.is_empty() => {
                return Err(bad("entries.allowed_hosts", "a host-vouched AGENT needs at least one"))
            }
            _ => {}
        }

        // Roots.
        let (roots, current_root) = if self_rooted {
            let duo = e.current_root.as_ref()
                .ok_or_else(|| bad("entries.current_root", "missing"))
                .and_then(|d| PublicKeyDuo::try_from(d).map_err(|_| bad("entries.current_root", "invalid, or its halves are equal")))?;
            let roots = if is_authority {
                if !e.rotations.is_empty() {
                    return Err(bad("entries.rotations", "must be empty for the authority"));
                }
                chain.roots().to_vec()
            } else {
                rotation_roots(id.genesis(), &e.rotations).map_err(|_| bad("entries.rotations", "not a valid chain from the genesis key"))?
            };
            if Some(duo.signing()) != roots.last() {
                return Err(bad("entries.current_root", "is not the end of the root chain"));
            }
            for r in &roots {
                keys.add(r)?;
            }
            keys.add(duo.encryption())?;
            (roots, Some(duo))
        } else {
            if !e.rotations.is_empty() || !e.revocations.is_empty() {
                return Err(bad("entries.rotations", "rotations and revocations are only for self-rooted entries"));
            }
            keys.add(id.genesis())?;
            (vec![], None)
        };
        let current = roots.last();

        // Bindings (HUMAN). `own` collects the keys a HUMAN may revoke.
        let mut own: Vec<PublicKey> = roots.clone();
        let mut bindings = Vec::with_capacity(e.devices.len());
        for b in &e.devices {
            let root = current.expect("HUMAN entries are self-rooted");
            let d = b.device.as_ref().ok_or_else(|| bad("devices.device", "missing"))?;
            let device_key = check_delegation(d, id, root, pb::KeyPurpose::Device, "devices.device")?;
            let device_enc = key(&d.delegated_encryption).expect("a DEVICE transcript requires the encryption half");
            keys.add(&device_key)?;
            keys.add(&device_enc)?;
            own.extend([device_key.clone(), device_enc]);
            let approval = match &b.approval {
                Some(a) => {
                    let k = check_delegation(a, id, root, pb::KeyPurpose::Approval, "devices.approval")?;
                    keys.add(&k)?;
                    own.push(k.clone());
                    Some((a.clone(), k))
                }
                None => None,
            };
            let host = match &b.host_daemon_id {
                None => None,
                Some(h) => {
                    let h = PrincipalId::parse_canonical(h).map_err(|_| bad("devices.host_daemon_id", "not canonical"))?;
                    if !daemons.contains(&h) {
                        return Err(bad("devices.host_daemon_id", "names no DAEMON entry"));
                    }
                    Some(h)
                }
            };
            bindings.push(VerifiedBinding { device: d.clone(), device_key, approval, host });
        }

        // Revocations: scoped to this entry; signed by any root of its chain
        // (for the authority, the document's chain) or by the revoked key.
        let mut revocations = Vec::with_capacity(e.revocations.len());
        for r in &e.revocations {
            if key(&r.principal_genesis).as_ref() != Some(id.genesis()) {
                return Err(bad("revocations.principal_genesis", "is not this entry"));
            }
            let revoked = key(&r.revoked).ok_or_else(|| bad("revocations.revoked", "missing"))?;
            let by = key(&r.revoked_by).ok_or_else(|| bad("revocations.revoked_by", "missing"))?;
            if Some(&revoked) == current {
                return Err(bad("revocations.revoked", "revokes the current root; set frozen instead"));
            }
            if !(roots.contains(&by) || by == revoked) {
                return Err(bad("revocations.revoked_by", "not a root of this entry or the revoked key"));
            }
            if kind == PrincipalKind::Human && !own.contains(&revoked) {
                return Err(bad("revocations.revoked", "not one of this entry's keys"));
            }
            let transcript = key_revocation_transcript(r).map_err(|_| bad("revocations", "malformed"))?;
            verify_p256(&by, &transcript, &r.signature).map_err(|_| bad("revocations", "signature does not verify"))?;
            revocations.push((revoked, r.revoked_at_unix_seconds));
        }

        let allowed_hosts = e.allowed_hosts.iter().map(|h| {
            if h == "*" {
                Ok(AllowedHost::Any)
            } else {
                PrincipalId::parse_canonical(h).map(AllowedHost::Daemon).map_err(|_| bad("entries.allowed_hosts", "not \"*\" or a canonical principal id"))
            }
        }).collect::<Result<Vec<_>>>()?;

        entries.insert(id.clone(), VerifiedEntry {
            id: id.clone(), kind, name: e.name.clone(), frozen: e.frozen, current_root,
            roots, rotations: e.rotations.clone(), revocations, bindings, allowed_hosts,
        });
    }
    if !authority_seen {
        return Err(bad("entries", "no HUMAN entry for the authority"));
    }
    Ok(CheckedRegistry { entries, allow_peer_revocation: reg.allow_peer_revocation })
}
