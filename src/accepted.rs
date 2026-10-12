//! Every principal a receiver has ever accepted, so a fork or a return to a
//! retired root is caught across versions, including after a remove and
//! re-add (1b spec 4.5).

use crate::authority::rotation_roots;
use crate::{pb, Error, PrincipalId, PrincipalKind, PublicKey, Resolver, Result};
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq)]
struct Accepted {
    kind: PrincipalKind,
    roots: Vec<PublicKey>,
    rotations: Vec<pb::RootRotation>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct AcceptedChains(BTreeMap<PrincipalId, Accepted>);

fn kind_to_pb(kind: PrincipalKind) -> pb::PrincipalKind {
    match kind {
        PrincipalKind::Human => pb::PrincipalKind::Human,
        PrincipalKind::Agent => pb::PrincipalKind::Agent,
        PrincipalKind::Daemon => pb::PrincipalKind::Daemon,
    }
}

impl AcceptedChains {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Re-checks every rotation when loading persisted accepted chains.
    pub fn from_proto(proto: &pb::AcceptedChains) -> Result<Self> {
        let mut accepted = BTreeMap::new();
        for principal in &proto.principals {
            let id = PrincipalId::parse_canonical(&principal.principal_id)?;
            let kind = match pb::PrincipalKind::try_from(principal.kind) {
                Ok(pb::PrincipalKind::Human) => PrincipalKind::Human,
                Ok(pb::PrincipalKind::Agent) => PrincipalKind::Agent,
                Ok(pb::PrincipalKind::Daemon) => PrincipalKind::Daemon,
                _ => {
                    return Err(Error::InvalidField {
                        field: "principals.kind",
                        reason: "unknown or unspecified",
                    });
                }
            };
            let roots = rotation_roots(id.genesis(), &principal.rotations)?;
            if accepted
                .insert(
                    id,
                    Accepted {
                        kind,
                        roots,
                        rotations: principal.rotations.clone(),
                    },
                )
                .is_some()
            {
                return Err(Error::InvalidField {
                    field: "principals.principal_id",
                    reason: "repeated",
                });
            }
        }
        Ok(Self(accepted))
    }

    pub fn to_proto(&self) -> pb::AcceptedChains {
        pb::AcceptedChains {
            principals: self
                .0
                .iter()
                .map(|(id, accepted)| pb::AcceptedPrincipal {
                    principal_id: id.to_string(),
                    kind: kind_to_pb(accepted.kind) as i32,
                    rotations: accepted.rotations.clone(),
                })
                .collect(),
        }
    }
}

impl Resolver {
    /// Checks this version against every principal accepted before and returns
    /// the updated set. On an error the caller rejects this version and keeps
    /// the version it holds.
    pub fn check_successor(&self, accepted: &AcceptedChains) -> Result<AcceptedChains> {
        let mut updated = accepted.0.clone();
        for entry in self.entries.values() {
            if entry.id() == self.authority() {
                continue;
            }

            // A keyless agent's chain is its genesis key alone, which every
            // later self-rooted chain from the same genesis extends.
            let (roots, rotations) = if entry.is_self_rooted() {
                (entry.roots().to_vec(), entry.rotations().to_vec())
            } else {
                (vec![entry.id().genesis().clone()], vec![])
            };

            match updated.get(entry.id()) {
                Some(previous) => {
                    if previous.kind != entry.kind() {
                        return Err(Error::KindChanged {
                            principal: entry.id().clone(),
                        });
                    }
                    if entry.is_self_rooted() {
                        let extends = previous.roots.len() <= roots.len()
                            && previous.roots[..] == roots[..previous.roots.len()];
                        if !extends {
                            return Err(Error::RootFork {
                                principal: entry.id().clone(),
                            });
                        }
                        updated.insert(
                            entry.id().clone(),
                            Accepted {
                                kind: entry.kind(),
                                roots,
                                rotations,
                            },
                        );
                    }
                }
                None => {
                    updated.insert(
                        entry.id().clone(),
                        Accepted {
                            kind: entry.kind(),
                            roots,
                            rotations,
                        },
                    );
                }
            }
        }
        Ok(AcceptedChains(updated))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::*;

    #[test]
    fn first_version_records_everyone_but_the_authority() {
        let fleet = Fleet::new();
        let accepted = fleet
            .resolver()
            .check_successor(&AcceptedChains::empty())
            .unwrap();
        assert_eq!(accepted.len(), 2); // daemon and agent
        let back = AcceptedChains::from_proto(&accepted.to_proto()).unwrap();
        assert_eq!(back.to_proto(), accepted.to_proto());
    }

    #[test]
    fn rotations_must_equal_or_extend() {
        let mut fleet = Fleet::new();
        let first = fleet
            .resolver()
            .check_successor(&AcceptedChains::empty())
            .unwrap();
        assert!(fleet.resolver().check_successor(&first).is_ok());
        fleet.daemon.rotate(T0);
        let second = fleet.resolver().check_successor(&first).unwrap();

        // Return to the genesis root: a return to a retired root.
        let mut back = fleet.registry();
        back.entries[1].rotations.clear();
        back.entries[1]
            .current_root
            .as_mut()
            .unwrap()
            .signing = pk(&fleet.daemon.genesis());
        let resolver = resolver_for(&fleet.owner, back).unwrap();
        assert!(matches!(
            resolver.check_successor(&second),
            Err(Error::RootFork { .. })
        ));
    }

    #[test]
    fn forked_rotation_is_rejected() {
        let mut fleet = Fleet::new();
        fleet.daemon.rotate(T0);
        let accepted = fleet
            .resolver()
            .check_successor(&AcceptedChains::empty())
            .unwrap();

        // Presented: g -> B, a different rotation from the same genesis root.
        let mut fork = pb::RootRotation {
            principal_genesis: pk(&fleet.daemon.genesis()),
            old_root: pk(&fleet.daemon.genesis()),
            new_root: pk(&Signer::new().public()),
            issued_at_unix_seconds: T0,
            signature: vec![],
        };
        fork.signature = fleet.daemon.root_at(0).sign(
            &crate::transcripts::root_rotation_transcript(&fork).unwrap(),
        );
        let mut registry = fleet.registry();
        registry.entries[1]
            .current_root
            .as_mut()
            .unwrap()
            .signing = fork.new_root.clone();
        registry.entries[1].rotations = vec![fork];
        let resolver = resolver_for(&fleet.owner, registry).unwrap();
        assert!(matches!(
            resolver.check_successor(&accepted),
            Err(Error::RootFork { .. })
        ));
    }

    #[test]
    fn re_added_entry_is_checked_against_its_old_chain() {
        let mut fleet = Fleet::new();
        fleet.daemon.rotate(T0);
        let version_four = fleet
            .resolver()
            .check_successor(&AcceptedChains::empty())
            .unwrap();

        // The daemon (and the binding naming it) is removed.
        let mut version_five = fleet.registry();
        version_five.entries.remove(1);
        version_five.entries[0].devices[0].host_daemon_id = None;
        version_five.entries[1].allowed_hosts = vec!["*".into()];
        let version_five = resolver_for(&fleet.owner, version_five)
            .unwrap()
            .check_successor(&version_four)
            .unwrap();
        assert_eq!(version_five.len(), 2, "removed entries stay accepted");

        // Re-added at its genesis root, which is a retired root.
        let mut version_six = fleet.registry();
        version_six.entries[1].rotations.clear();
        version_six.entries[1]
            .current_root
            .as_mut()
            .unwrap()
            .signing = pk(&fleet.daemon.genesis());
        let resolver = resolver_for(&fleet.owner, version_six).unwrap();
        assert!(matches!(
            resolver.check_successor(&version_five),
            Err(Error::RootFork { .. })
        ));
    }

    #[test]
    fn kind_change_is_rejected() {
        let fleet = Fleet::new();
        let accepted = fleet
            .resolver()
            .check_successor(&AcceptedChains::empty())
            .unwrap();
        let mut registry = fleet.registry();
        registry.entries[1].kind = pb::PrincipalKind::Human as i32;
        registry.entries[0].devices[0].host_daemon_id = None;
        registry.entries[2].allowed_hosts = vec!["*".into()];
        let resolver = resolver_for(&fleet.owner, registry).unwrap();
        assert!(matches!(
            resolver.check_successor(&accepted),
            Err(Error::KindChanged { .. })
        ));
    }

    #[test]
    fn skipped_unknown_kinds_are_not_recorded() {
        let fleet = Fleet::new();
        let mut registry = fleet.registry();
        registry.entries[2].kind = 99;
        let accepted = resolver_for(&fleet.owner, registry)
            .unwrap()
            .check_successor(&AcceptedChains::empty())
            .unwrap();
        assert_eq!(accepted.len(), 1);
    }

    #[test]
    fn from_proto_rechecks_rotations() {
        let mut fleet = Fleet::new();
        fleet.daemon.rotate(T0);
        let mut proto = fleet
            .resolver()
            .check_successor(&AcceptedChains::empty())
            .unwrap()
            .to_proto();
        let daemon = proto
            .principals
            .iter_mut()
            .find(|principal| !principal.rotations.is_empty())
            .unwrap();
        daemon.rotations[0].signature[0] ^= 1;
        assert_eq!(
            AcceptedChains::from_proto(&proto).unwrap_err(),
            Error::BadSignature
        );
    }
}