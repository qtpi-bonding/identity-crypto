use crate::error::KeyfileError;
use crate::files::{
    self, read_delegation, read_duo, read_history, read_principal_id, read_rotations,
    write_delegation, write_duo, write_history, write_principal_id, write_rotations, AGENT_ID_FILE,
    DELEGATION_FILE, DEVICE_FILE, HISTORY_FILE, ROOT_FILE, ROTATIONS_FILE,
};
use crate::generate;
use identity_crypto::jwk_duo::KeyDuo;
use identity_crypto::{
    delegate_device, encryption_public, pb, principal_id, rotation, signing_public, PrincipalId,
    PublicKey,
};
use std::fs;
use std::path::Path;

/// The keys of one self-rooted agent, as stored in an agent directory.
///
/// The root signs the device delegation and root rotations. The device signs
/// for the agent day to day. `agent_id` is the principal id derived from the
/// first root and does not change when the root is rotated.
pub struct AgentKeys {
    /// The current root. Private: stored in `root.jwk.json`.
    pub root: KeyDuo,
    /// The current device. Private: stored in `device.jwk.json`.
    pub device: KeyDuo,
    /// The root's delegation of `device`. It is stale after `rotate_root` until
    /// `renew` re-signs it under the new root; see [`AgentKeys::delegation_is_current`].
    pub delegation: pb::KeyDelegation,
    /// The principal id, `p256:<genesis>`. Stored in `agent_id`, which is written last.
    pub agent_id: PrincipalId,
    /// Devices this agent used to have, public halves only, in the order they were
    /// retired. Each entry's `retired_at_unix_seconds` is a local, unsigned claim:
    /// it is not checked against any signature or clock. A compromised retired key
    /// can therefore sign claimed-earlier messages forever. Take the `at` passed to
    /// [`device_keys_at`] from a trusted clock or receipt time, never from a message.
    pub retired: Vec<pb::RetiredDevice>,
    /// The root rotation chain, oldest first, public data only. The last entry may
    /// be a pending rotation whose new root was never installed (see [`AgentKeys::rotate_root`]).
    pub rotations: Vec<pb::RootRotation>,
}

/// The device keys and public device metadata of an agent. Loading this type
/// never reads, checks, or opens the root or root-rotation files.
pub struct DeviceKeys {
    /// The current device. Private: stored in `device.jwk.json`.
    pub device: KeyDuo,
    /// The root's delegation of the current device.
    pub delegation: pb::KeyDelegation,
    /// The principal id of the agent.
    pub agent_id: PrincipalId,
    /// Devices this agent used to have, public halves only. `retired_at` is an
    /// unsigned local claim; see [`AgentKeys::retired`].
    pub retired: Vec<pb::RetiredDevice>,
}

/// Public device data suitable for handing to a verifier.
#[derive(Clone, PartialEq)]
pub struct DevicePublic {
    /// The principal id of the agent.
    pub agent_id: PrincipalId,
    /// The current device's signing key.
    pub device_signing: PublicKey,
    /// The current device's encryption key.
    pub device_encryption: PublicKey,
    /// The root's delegation of the current device.
    pub delegation: pb::KeyDelegation,
    /// Retired devices, public halves only; see [`AgentKeys::retired`] for the trust caveat.
    pub retired: Vec<pb::RetiredDevice>,
}

/// Every file an agent directory holds. `init` refuses when any of them exists.
const AGENT_FILES: [&str; 6] = [
    ROOT_FILE,
    DEVICE_FILE,
    DELEGATION_FILE,
    AGENT_ID_FILE,
    HISTORY_FILE,
    ROTATIONS_FILE,
];

/// Appends `device` to `retired` as retired at `now`. If its signing key is
/// already listed, keeps the EARLIER `retired_at`, so a retried renewal cannot
/// move a key's retirement later.
fn retire(retired: &mut Vec<pb::RetiredDevice>, device: &KeyDuo, now: i64) {
    let signing = pb::PublicKey::from(&signing_public(device));
    match retired
        .iter_mut()
        .find(|entry| entry.signing.as_ref() == Some(&signing))
    {
        Some(existing) => {
            existing.retired_at_unix_seconds = existing.retired_at_unix_seconds.min(now);
        }
        None => retired.push(pb::RetiredDevice {
            signing: Some(signing),
            encryption: Some(pb::PublicKey::from(&encryption_public(device))),
            retired_at_unix_seconds: now,
        }),
    }
}

/// `DelegationMismatch` unless `delegation` names `device`'s signing key.
fn check_delegation(device: &KeyDuo, delegation: &pb::KeyDelegation) -> Result<(), KeyfileError> {
    if delegation.delegated == Some(pb::PublicKey::from(&signing_public(device))) {
        Ok(())
    } else {
        Err(KeyfileError::DelegationMismatch)
    }
}

fn exists(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok()
}

impl AgentKeys {
    /// Returns public device data without exposing private keys.
    pub fn public(&self) -> DevicePublic {
        DevicePublic::new(
            &self.agent_id,
            &self.device,
            &self.delegation,
            &self.retired,
        )
    }

    /// Writes every file of `self` into `dir`, creating `dir` (mode 0700) if needed.
    /// Takes the exclusive lock. Refuses a group- or world-accessible existing `dir`.
    /// The files are overwritten, not checked: use [`AgentKeys::init`] to create a
    /// new agent. `agent_id` is written last.
    pub fn save(&self, dir: &Path) -> Result<(), KeyfileError> {
        files::ensure_dir(dir)?;
        let _lock = files::lock_exclusive(dir)?;
        write_duo(dir, ROOT_FILE, &self.root)?;
        write_duo(dir, DEVICE_FILE, &self.device)?;
        write_delegation(dir, &self.delegation)?;
        write_history(
            dir,
            &pb::DeviceHistory {
                retired: self.retired.clone(),
            },
        )?;
        write_rotations(
            dir,
            &pb::RootRotations {
                rotations: self.rotations.clone(),
            },
        )?;
        write_principal_id(dir, &self.agent_id)
    }

    /// Reads the agent directory `dir`. The directory must exist and must not be
    /// group- or world-accessible (`InsecureDir` otherwise). Takes a shared lock
    /// on `.lock`. If `.lock` cannot be created because the directory is read-only,
    /// the keys are read without a lock.
    ///
    /// Returns `DelegationMismatch` when the stored delegation names a different
    /// device key than `device.jwk.json`. A delegation that names an old root is
    /// accepted; [`AgentKeys::delegation_is_current`] reports it.
    pub fn load(dir: &Path) -> Result<Self, KeyfileError> {
        files::check_dir(dir)?;
        let _lock = files::lock_shared(dir)?;
        Self::load_locked(dir)
    }

    /// The body of `load`, for callers that already hold the lock. Public
    /// `load` must not be called while holding the exclusive lock, because the
    /// file lock would deadlock.
    fn load_locked(dir: &Path) -> Result<Self, KeyfileError> {
        files::check_dir(dir)?;
        let keys = Self::load_files(dir)?;
        check_delegation(&keys.device, &keys.delegation)?;
        Ok(keys)
    }

    /// Reads every file without checking the directory or the delegation.
    /// `renew` uses this to repair a device/delegation mismatch left by a crash.
    fn load_files(dir: &Path) -> Result<Self, KeyfileError> {
        let root = read_duo(dir, ROOT_FILE)?;
        let device = read_duo(dir, DEVICE_FILE)?;
        let delegation = read_delegation(dir)?;
        let agent_id = read_principal_id(dir)?;
        let retired = read_history(dir)?.retired;
        let rotations = read_rotations(dir)?.rotations;
        Ok(Self {
            root,
            device,
            delegation,
            agent_id,
            retired,
            rotations,
        })
    }

    /// Creates a new agent in `dir`: a fresh root and device, a root-signed
    /// delegation of the device over `[now, now + ttl_seconds]`, an empty history
    /// and an empty rotation chain.
    ///
    /// `ttl_seconds` must be in `(0, 31 days]`; anything else is `Crypto` and
    /// nothing is written. Refuses (`AlreadyInitialised`) when any agent file
    /// exists, and refuses a loose existing `dir` (`InsecureDir`) without writing.
    ///
    /// Writes are ordered so that `agent_id` is the commit marker: it is written
    /// last. If a crash happens before it, the directory is in a stuck state:
    /// `load` reports `Missing(agent_id)` and `init` reports `AlreadyInitialised`.
    /// Remove the directory and init again.
    pub fn init(dir: &Path, now: i64, ttl_seconds: i64) -> Result<Self, KeyfileError> {
        files::ensure_dir(dir)?;
        let root = generate();
        let device = generate();
        let agent_id = principal_id(&root);
        let delegation = delegate_device(
            &root,
            &agent_id,
            &device,
            now,
            now.saturating_add(ttl_seconds),
        )?;
        let _lock = files::lock_exclusive(dir)?;
        if AGENT_FILES.iter().any(|name| exists(&dir.join(name))) {
            return Err(KeyfileError::AlreadyInitialised(dir.to_path_buf()));
        }
        write_duo(dir, ROOT_FILE, &root)?;
        write_duo(dir, DEVICE_FILE, &device)?;
        write_delegation(dir, &delegation)?;
        write_history(
            dir,
            &pb::DeviceHistory {
                retired: Vec::new(),
            },
        )?;
        write_rotations(
            dir,
            &pb::RootRotations {
                rotations: Vec::new(),
            },
        )?;
        write_principal_id(dir, &agent_id)?;
        Ok(Self {
            root,
            device,
            delegation,
            agent_id,
            retired: Vec::new(),
            rotations: Vec::new(),
        })
    }

    /// Re-signs the device delegation over `[now, now + ttl_seconds]` under the
    /// current root. With `new_device = true` it first replaces the device, and
    /// records the old device's public keys in the history as retired at `now`.
    ///
    /// The new device and the delegation are built in memory before any file is
    /// written. A `ttl_seconds` outside `(0, 31 days]` returns `Crypto` with no
    /// file touched. Otherwise the writes are, in order: the history (when
    /// `new_device`), then `device.jwk.json` (when `new_device`), then
    /// `delegation.json`. A crash between two writes can leave a history entry for
    /// a key that is still current, which `device_keys_at` ignores. It can also
    /// leave a device that the stored delegation does not name, which `load`
    /// reports as `DelegationMismatch` and a later `renew(.., false)` repairs.
    /// Nothing is lost in either case.
    ///
    /// Takes the exclusive lock on `.lock`.
    pub fn renew(
        dir: &Path,
        now: i64,
        ttl_seconds: i64,
        new_device: bool,
    ) -> Result<Self, KeyfileError> {
        files::check_dir(dir)?;
        let _lock = files::lock_exclusive(dir)?;
        let mut keys = Self::load_files(dir)?;
        let replacement = if new_device { Some(generate()) } else { None };
        let device = replacement.as_ref().unwrap_or(&keys.device);
        let delegation = delegate_device(
            &keys.root,
            &keys.agent_id,
            device,
            now,
            now.saturating_add(ttl_seconds),
        )?;
        if let Some(new_device) = replacement {
            let mut retired = keys.retired.clone();
            retire(&mut retired, &keys.device, now);
            write_history(
                dir,
                &pb::DeviceHistory {
                    retired: retired.clone(),
                },
            )?;
            write_duo(dir, DEVICE_FILE, &new_device)?;
            keys.retired = retired;
            keys.device = new_device;
        }
        write_delegation(dir, &delegation)?;
        keys.delegation = delegation;
        Ok(keys)
    }

    /// Replaces the device with a new one and retires the old device's public
    /// keys. This is [`AgentKeys::renew`] with `new_device = true`.
    pub fn rotate_device(dir: &Path, now: i64, ttl_seconds: i64) -> Result<Self, KeyfileError> {
        Self::renew(dir, now, ttl_seconds, true)
    }

    /// Replaces the root with a new one. The rotation is signed by the old root
    /// and returned for the caller to submit. `agent_id` does not change.
    ///
    /// The delegation is not re-signed here: until [`AgentKeys::renew`] runs,
    /// `delegation_is_current` is false. Write order: the complete rotation chain
    /// first, then `root.jwk.json`. A crash between them leaves the old root on
    /// disk with a pending final rotation in the chain. The old root still works,
    /// and the next `rotate_root` replaces the pending entry instead of
    /// extending the chain past it.
    ///
    /// Takes the exclusive lock. The chain stores public data only.
    pub fn rotate_root(dir: &Path, now: i64) -> Result<pb::RootRotation, KeyfileError> {
        files::check_dir(dir)?;
        let _lock = files::lock_exclusive(dir)?;
        let keys = Self::load_locked(dir)?;
        let current = pb::PublicKey::from(&signing_public(&keys.root));
        let mut rotations = keys.rotations;
        // A last entry whose old root is the current root was written by a
        // crashed attempt that never installed its new root. It is replaced,
        // not extended, so a retry does not fork the chain.
        if rotations
            .last()
            .is_some_and(|last| last.old_root.as_ref() == Some(&current))
        {
            rotations.pop();
        }
        let new_root = generate();
        let signed = rotation(&keys.root, &keys.agent_id, &new_root, now)?;
        rotations.push(signed.clone());
        write_rotations(dir, &pb::RootRotations { rotations })?;
        write_duo(dir, ROOT_FILE, &new_root)?;
        Ok(signed)
    }

    /// True when the stored delegation is signed by the current root for the
    /// current device. This is false after `rotate_root` until `renew` runs.
    /// It checks the root and device keys, not the signature or the window.
    pub fn delegation_is_current(&self) -> bool {
        self.delegation.signing_root == Some(pb::PublicKey::from(&signing_public(&self.root)))
            && self.delegation.delegated == Some(pb::PublicKey::from(&signing_public(&self.device)))
    }
}

impl DeviceKeys {
    /// Reads only the device, delegation, principal id, and device history files.
    /// The root and rotation files are never opened or inspected.
    pub fn load(dir: &Path) -> Result<Self, KeyfileError> {
        files::check_dir(dir)?;
        let _lock = files::lock_shared(dir)?;
        let device = read_duo(dir, DEVICE_FILE)?;
        let delegation = read_delegation(dir)?;
        let agent_id = read_principal_id(dir)?;
        let retired = read_history(dir)?.retired;
        check_delegation(&device, &delegation)?;
        Ok(Self {
            device,
            delegation,
            agent_id,
            retired,
        })
    }

    /// Returns public device data without exposing the private device key.
    pub fn public(&self) -> DevicePublic {
        DevicePublic::new(
            &self.agent_id,
            &self.device,
            &self.delegation,
            &self.retired,
        )
    }
}

impl DevicePublic {
    fn new(
        agent_id: &PrincipalId,
        device: &KeyDuo,
        delegation: &pb::KeyDelegation,
        retired: &[pb::RetiredDevice],
    ) -> Self {
        Self {
            agent_id: agent_id.clone(),
            device_signing: signing_public(device),
            device_encryption: encryption_public(device),
            delegation: delegation.clone(),
            retired: retired.to_vec(),
        }
    }

    /// The device signing keys accepted at `at`, as [`device_keys_at`]. `at` must
    /// come from a trusted clock: `retired_at` is an unsigned local claim.
    pub fn device_keys_at(&self, at: i64) -> Vec<PublicKey> {
        device_keys_at_public(&self.device_signing, &self.retired, at)
    }
}

/// The device signing keys a verifier should accept as of `at`: the current
/// device first, then each retired device whose `retired_at_unix_seconds` is at
/// or after `at`, in history order. Duplicates are removed.
///
/// A retired entry with a missing or unparseable signing key is dropped (fail
/// closed). An entry equal to the current device is ignored.
///
/// `at` must come from a trusted clock or receipt time, never from a message's
/// own `issued_at`. `retired_at` is an unsigned local claim, so a compromised
/// retired key can sign claimed-earlier messages indefinitely.
pub fn device_keys_at(keys: &AgentKeys, at: i64) -> Vec<PublicKey> {
    device_keys_at_public(&signing_public(&keys.device), &keys.retired, at)
}

fn device_keys_at_public(
    current: &PublicKey,
    retired: &[pb::RetiredDevice],
    at: i64,
) -> Vec<PublicKey> {
    let mut result = vec![current.clone()];
    for retired in retired {
        if retired.retired_at_unix_seconds < at {
            continue;
        }
        let Some(wire) = &retired.signing else {
            continue;
        };
        let Ok(public) = PublicKey::try_from(wire) else {
            continue;
        };
        if &public == current || result.contains(&public) {
            continue;
        }
        result.push(public);
    }
    result
}

#[cfg(test)]
mod crash_tests {
    //! Crash-simulation tests. They arm the crate-private failpoint in `files`,
    //! which is thread-local, so they must live in the crate.

    use super::*;
    use crate::files::fail_writes_to;
    use identity_crypto::verify_p256;

    fn private_dir() -> tempfile::TempDir {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }

    /// Arms the failpoint for `name` until dropped.
    struct Failpoint;

    impl Failpoint {
        fn on(name: &'static str) -> Self {
            fail_writes_to(Some(name));
            Failpoint
        }
    }

    impl Drop for Failpoint {
        fn drop(&mut self) {
            fail_writes_to(None);
        }
    }

    #[test]
    fn crash_between_history_and_device_write_loses_no_key() {
        let dir = private_dir();
        let before = AgentKeys::init(dir.path(), 1_000, 100).unwrap();
        let old_signing = signing_public(&before.device);
        {
            let _armed = Failpoint::on(DEVICE_FILE);
            assert!(matches!(
                AgentKeys::renew(dir.path(), 1_010, 100, true),
                Err(KeyfileError::Io { .. })
            ));
        }
        let loaded = AgentKeys::load(dir.path()).unwrap();
        assert_eq!(
            signing_public(&loaded.device),
            old_signing,
            "the device file was never replaced"
        );
        assert_eq!(
            loaded.retired.len(),
            1,
            "the history was written before the device"
        );
        assert_eq!(
            loaded.retired[0].signing,
            Some(pb::PublicKey::from(&old_signing))
        );
        assert_eq!(loaded.retired[0].retired_at_unix_seconds, 1_010);
        assert_eq!(
            device_keys_at(&loaded, 0),
            vec![old_signing],
            "the early entry equal to the current device is ignored"
        );
    }

    #[test]
    fn crash_between_device_and_delegation_write_is_detected_and_repaired() {
        let dir = private_dir();
        let before = AgentKeys::init(dir.path(), 1_000, 100).unwrap();
        {
            let _armed = Failpoint::on(DELEGATION_FILE);
            assert!(matches!(
                AgentKeys::renew(dir.path(), 1_010, 100, true),
                Err(KeyfileError::Io { .. })
            ));
        }
        assert!(matches!(
            AgentKeys::load(dir.path()),
            Err(KeyfileError::DelegationMismatch)
        ));
        let written = signing_public(&read_duo(dir.path(), DEVICE_FILE).unwrap());
        assert_ne!(written, signing_public(&before.device));
        let repaired = AgentKeys::renew(dir.path(), 1_020, 100, false).unwrap();
        assert_eq!(signing_public(&repaired.device), written);
        assert!(repaired.delegation_is_current());
        let on_disk = read_delegation(dir.path()).unwrap();
        let transcript = identity_crypto::transcripts::key_delegation_transcript(&on_disk).unwrap();
        assert!(verify_p256(
            &signing_public(&repaired.root),
            &transcript,
            &on_disk.signature
        )
        .is_ok());
        assert_eq!(on_disk.issued_at_unix_seconds, 1_020);
        assert_eq!(
            read_history(dir.path()).unwrap().retired.len(),
            1,
            "the retired device is kept"
        );
    }

    #[test]
    fn init_writes_agent_id_last() {
        let dir = private_dir();
        let target = dir.path().join("agent");
        {
            let _armed = Failpoint::on(AGENT_ID_FILE);
            assert!(matches!(
                AgentKeys::init(&target, 1, 100),
                Err(KeyfileError::Io { .. })
            ));
        }
        for name in [
            ROOT_FILE,
            DEVICE_FILE,
            DELEGATION_FILE,
            HISTORY_FILE,
            ROTATIONS_FILE,
        ] {
            assert!(
                target.join(name).is_file(),
                "{name} is written before the commit marker"
            );
        }
        assert!(!target.join(AGENT_ID_FILE).exists());
        assert!(
            matches!(AgentKeys::load(&target), Err(KeyfileError::Missing(p)) if p.ends_with(AGENT_ID_FILE))
        );
        assert!(matches!(
            AgentKeys::init(&target, 1, 100),
            Err(KeyfileError::AlreadyInitialised(_))
        ));
    }

    #[test]
    fn rotate_root_writes_rotations_before_the_root() {
        let dir = private_dir();
        let before = AgentKeys::init(dir.path(), 1_000, 100).unwrap();
        let old_root = signing_public(&before.root);
        let root_bytes = fs::read(dir.path().join(ROOT_FILE)).unwrap();
        {
            let _armed = Failpoint::on(ROOT_FILE);
            assert!(matches!(
                AgentKeys::rotate_root(dir.path(), 50),
                Err(KeyfileError::Io { .. })
            ));
        }
        assert_eq!(
            fs::read(dir.path().join(ROOT_FILE)).unwrap(),
            root_bytes,
            "the root file is unchanged"
        );
        let chain = read_rotations(dir.path()).unwrap().rotations;
        assert_eq!(chain.len(), 1, "the chain was written before the root");
        assert_eq!(chain[0].old_root, Some(pb::PublicKey::from(&old_root)));
        assert_eq!(
            signing_public(&AgentKeys::load(dir.path()).unwrap().root),
            old_root
        );

        let other = private_dir();
        let other_keys = AgentKeys::init(other.path(), 1_000, 100).unwrap();
        {
            let _armed = Failpoint::on(ROTATIONS_FILE);
            assert!(matches!(
                AgentKeys::rotate_root(other.path(), 50),
                Err(KeyfileError::Io { .. })
            ));
        }
        assert_eq!(
            signing_public(&read_duo(other.path(), ROOT_FILE).unwrap()),
            signing_public(&other_keys.root)
        );
        assert!(
            read_rotations(other.path()).unwrap().rotations.is_empty(),
            "no rotation was recorded"
        );
    }

    #[test]
    fn crash_after_rotations_write_keeps_old_root_usable() {
        let dir = private_dir();
        let before = AgentKeys::init(dir.path(), 1_000, 100).unwrap();
        let old_root = signing_public(&before.root);
        {
            let _armed = Failpoint::on(ROOT_FILE);
            assert!(matches!(
                AgentKeys::rotate_root(dir.path(), 50),
                Err(KeyfileError::Io { .. })
            ));
        }
        let loaded = AgentKeys::load(dir.path()).unwrap();
        assert_eq!(
            signing_public(&loaded.root),
            old_root,
            "the old root is still installed"
        );
        assert_eq!(
            loaded.rotations.len(),
            1,
            "the pending final rotation remains in the chain"
        );
        assert_eq!(
            loaded.rotations[0].old_root,
            Some(pb::PublicKey::from(&old_root))
        );

        let retried = AgentKeys::rotate_root(dir.path(), 60).unwrap();
        let after = AgentKeys::load(dir.path()).unwrap();
        assert_eq!(
            after.rotations.len(),
            1,
            "the retry replaces the pending entry"
        );
        assert_eq!(
            after.rotations[0].new_root,
            Some(pb::PublicKey::from(&signing_public(&after.root)))
        );
        assert_eq!(after.rotations[0], retried);
        let renewed = AgentKeys::renew(dir.path(), 70, 100, false).unwrap();
        assert!(renewed.delegation_is_current());
    }

    #[test]
    fn rotate_root_retry_does_not_fork_the_chain() {
        let dir = private_dir();
        let before = AgentKeys::init(dir.path(), 1_000, 100).unwrap();
        let old_root = signing_public(&before.root);
        for _ in 0..2 {
            let _armed = Failpoint::on(ROOT_FILE);
            assert!(AgentKeys::rotate_root(dir.path(), 50).is_err());
        }
        let final_rotation = AgentKeys::rotate_root(dir.path(), 60).unwrap();
        let loaded = AgentKeys::load(dir.path()).unwrap();
        assert_eq!(
            loaded.rotations.len(),
            1,
            "two crashed attempts did not extend the chain"
        );
        assert_eq!(
            loaded.rotations[0].old_root,
            Some(pb::PublicKey::from(&old_root))
        );
        assert_eq!(
            loaded.rotations[0].new_root,
            Some(pb::PublicKey::from(&signing_public(&loaded.root)))
        );
        assert_eq!(loaded.rotations[0], final_rotation);
    }
}
