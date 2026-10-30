use crate::error::KeyfileError;
use crate::error::VerifyCheck;
use crate::files::{
    self, read_delegation, read_duo, read_history, read_principal_id, read_rotations,
    write_delegation, write_duo, write_history, write_principal_id, write_rotations, AGENT_ID_FILE,
    DELEGATION_FILE, DEVICE_FILE, HISTORY_FILE, ROOT_FILE, ROTATIONS_FILE,
};
use crate::generate;
use identity_crypto::jwk_duo::KeyDuo;
use identity_crypto::transcripts;
use identity_crypto::{
    delegate_device, encryption_public, pb, principal_id, renewal_due, rotation, signing_public,
    verify_p256, AuthorityChain, PrincipalId, PublicKey,
};
use std::fs;
use std::io::ErrorKind;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// The keys of one self-rooted agent, as stored in an agent directory.
///
/// The root signs the device delegation and root rotations. The device signs
/// for the principal day to day. `principal_id` (stored in the `agent_id` file)
/// is derived from the first root and does not change when the root is rotated.
pub struct IdentityKeys {
    /// The current root. Private: stored in `root.jwk.json`.
    pub root: KeyDuo,
    /// The current device. Private: stored in `device.jwk.json`.
    pub device: KeyDuo,
    /// The root's delegation of `device`. It is stale after `rotate_root` until
    /// `renew` re-signs it under the new root; see [`IdentityKeys::delegation_is_current`].
    pub delegation: pb::KeyDelegation,
    /// The principal id, `p256:<genesis>`. Stored in `agent_id`, which is written last.
    pub principal_id: PrincipalId,
    /// Devices this agent used to have, public halves only, in the order they were
    /// retired. Each entry's `retired_at_unix_seconds` is a local, unsigned claim:
    /// it is not checked against any signature or clock. A compromised retired key
    /// can therefore sign claimed-earlier messages forever. Take the `at` passed to
    /// [`device_keys_at`] from a trusted clock or receipt time, never from a message.
    pub retired: Vec<pb::RetiredDevice>,
    /// The root rotation chain, oldest first, public data only. The last entry may
    /// be a pending rotation whose new root was never installed (see [`IdentityKeys::rotate_root`]).
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
    pub principal_id: PrincipalId,
    /// Devices this agent used to have, public halves only. `retired_at` is an
    /// unsigned local claim; see [`IdentityKeys::retired`].
    pub retired: Vec<pb::RetiredDevice>,
}

/// Public device data suitable for handing to a verifier.
#[derive(Clone, PartialEq)]
pub struct DevicePublic {
    /// The principal id of the agent.
    pub principal_id: PrincipalId,
    /// The current device's signing key.
    pub device_signing: PublicKey,
    /// The current device's encryption key.
    pub device_encryption: PublicKey,
    /// The root's delegation of the current device.
    pub delegation: pb::KeyDelegation,
    /// Retired devices, public halves only; see [`IdentityKeys::retired`] for the trust caveat.
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

fn rename_collision(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        ErrorKind::AlreadyExists | ErrorKind::DirectoryNotEmpty
    )
}

struct TempDirGuard {
    path: std::path::PathBuf,
    armed: bool,
}

impl TempDirGuard {
    fn new(path: &Path) -> Self {
        Self {
            path: path.to_path_buf(),
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

fn clean_dead_temps(dir: &Path, parent: &Path) -> Result<(), KeyfileError> {
    let prefix = format!(
        "{}.tmp-",
        dir.file_name().unwrap_or_default().to_string_lossy()
    );
    let Ok(entries) = fs::read_dir(parent) else {
        return Ok(());
    };
    for entry in entries {
        let Ok(entry) = entry else {
            continue;
        };
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.starts_with(&prefix) {
            continue;
        }
        let Some(pid_text) = name.strip_prefix(&prefix).and_then(|s| s.split('-').next()) else {
            continue;
        };
        let Ok(pid) = pid_text.parse::<libc::pid_t>() else {
            continue;
        };
        // `kill(pid, 0)` probes process existence without sending a signal.
        let dead = unsafe {
            libc::kill(pid, 0) == -1
                && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
        };
        if dead {
            let _ = fs::remove_dir_all(entry.path());
        }
    }
    Ok(())
}

fn verify_identity(keys: &IdentityKeys) -> Result<(), KeyfileError> {
    let genesis = keys
        .delegation
        .principal_genesis
        .as_ref()
        .ok_or(KeyfileError::VerifyFailed(VerifyCheck::PrincipalGenesis))?;
    let genesis = PublicKey::try_from(genesis)
        .map_err(|_| KeyfileError::VerifyFailed(VerifyCheck::PrincipalGenesis))?;
    let chain = AuthorityChain::from_rotations(genesis, &keys.rotations)
        .map_err(|_| KeyfileError::VerifyFailed(VerifyCheck::PrincipalGenesis))?;
    // The chain must end at the root on disk before agent_id is compared
    // against it, so a foreign genesis is reported as such, not as agent_id.
    let root_signing = signing_public(&keys.root);
    if &root_signing != chain.head() {
        return Err(KeyfileError::VerifyFailed(VerifyCheck::PrincipalGenesis));
    }
    if keys.principal_id != chain.principal() {
        return Err(KeyfileError::VerifyFailed(VerifyCheck::AgentId));
    }
    let signing_root = keys
        .delegation
        .signing_root
        .as_ref()
        .ok_or(KeyfileError::VerifyFailed(VerifyCheck::SigningRoot))?;
    if signing_root != &pb::PublicKey::from(chain.head()) {
        return Err(KeyfileError::VerifyFailed(VerifyCheck::SigningRoot));
    }
    if keys.delegation.delegated.as_ref()
        != Some(&pb::PublicKey::from(&signing_public(&keys.device)))
    {
        return Err(KeyfileError::VerifyFailed(VerifyCheck::Delegated));
    }
    if keys.delegation.delegated_encryption.as_ref()
        != Some(&pb::PublicKey::from(&encryption_public(&keys.device)))
    {
        return Err(KeyfileError::VerifyFailed(VerifyCheck::DelegatedEncryption));
    }
    if keys.delegation.purpose != pb::KeyPurpose::Device as i32 {
        return Err(KeyfileError::VerifyFailed(VerifyCheck::Purpose));
    }
    let transcript = transcripts::key_delegation_transcript(&keys.delegation)
        .map_err(|_| KeyfileError::VerifyFailed(VerifyCheck::Signature))?;
    if verify_p256(chain.head(), &transcript, &keys.delegation.signature).is_err() {
        return Err(KeyfileError::VerifyFailed(VerifyCheck::Signature));
    }
    Ok(())
}

impl IdentityKeys {
    /// Returns public device data without exposing private keys.
    pub fn public(&self) -> DevicePublic {
        DevicePublic::new(
            &self.principal_id,
            &self.device,
            &self.delegation,
            &self.retired,
        )
    }

    /// Writes every file of `self` into `dir`, creating `dir` (mode 0700) if needed.
    /// Takes the exclusive lock. Refuses a group- or world-accessible existing `dir`.
    /// The files are overwritten, not checked: use [`IdentityKeys::init`] to create a
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
        write_principal_id(dir, &self.principal_id)
    }

    /// Reads the agent directory `dir`. The directory must exist and must not be
    /// group- or world-accessible (`InsecureDir` otherwise). Takes a shared lock
    /// on `.lock`. If `.lock` cannot be created because the directory is read-only,
    /// the keys are read without a lock.
    ///
    /// Returns `DelegationMismatch` when the stored delegation names a different
    /// device key than `device.jwk.json`. A delegation that names an old root is
    /// accepted; [`IdentityKeys::delegation_is_current`] reports it.
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
        let principal_id = read_principal_id(dir)?;
        let retired = read_history(dir)?.retired;
        let rotations = read_rotations(dir)?.rotations;
        Ok(Self {
            root,
            device,
            delegation,
            principal_id,
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
        let principal_id = principal_id(&root);
        let delegation = delegate_device(
            &root,
            &principal_id,
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
        write_principal_id(dir, &principal_id)?;
        Ok(Self {
            root,
            device,
            delegation,
            principal_id,
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
            &keys.principal_id,
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

    /// Creates the identity in `dir` atomically, or loads and verifies the one that
    /// is already there. See the daemon-identity spec.
    pub fn create_or_load(dir: &Path, now: i64, ttl_seconds: i64) -> Result<Self, KeyfileError> {
        if Self::exists(dir) {
            return Self::load_verified(dir);
        }
        // A symlink or a loose directory is refused, never renamed over.
        match fs::symlink_metadata(dir) {
            Ok(_) => files::check_dir(dir)?,
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => return Err(crate::error::io(dir, error)),
        }
        let parent = dir
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        fs::create_dir_all(parent).map_err(|e| crate::error::io(parent, e))?;
        clean_dead_temps(dir, parent)?;
        let mut temp = None;
        for _ in 0..8 {
            let n = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|duration| duration.as_nanos() as u64)
                .unwrap_or(0);
            let candidate = parent.join(format!(
                "{}.tmp-{}-{}-{:016x}",
                dir.file_name().unwrap_or_default().to_string_lossy(),
                std::process::id(),
                n,
                nanos ^ n
            ));
            match fs::DirBuilder::new().mode(0o700).create(&candidate) {
                Ok(()) => {
                    temp = Some(candidate);
                    break;
                }
                Err(error) if error.kind() == ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(crate::error::io(&candidate, error)),
            }
        }
        let temp = temp.ok_or_else(|| {
            crate::error::io(
                dir,
                std::io::Error::new(ErrorKind::AlreadyExists, "temporary directory collision"),
            )
        })?;
        let mut temp_guard = TempDirGuard::new(&temp);
        if dir.is_dir() {
            let only_lock = match fs::read_dir(dir) {
                Ok(mut entries) => {
                    let mut saw_lock = false;
                    let only_lock = entries.all(|entry| match entry {
                        Ok(entry) if entry.file_name().to_string_lossy() == files::LOCK_FILE => {
                            saw_lock = true;
                            true
                        }
                        Ok(_) => false,
                        Err(_) => false,
                    });
                    only_lock && saw_lock
                }
                Err(error) if error.kind() == ErrorKind::NotFound => false,
                Err(error) => return Err(crate::error::io(dir, error)),
            };
            if only_lock {
                let _ = fs::remove_file(dir.join(files::LOCK_FILE));
                match fs::remove_dir(dir) {
                    Ok(()) => {}
                    Err(error)
                        if matches!(
                            error.kind(),
                            ErrorKind::NotFound | ErrorKind::DirectoryNotEmpty
                        ) => {}
                    Err(error) => return Err(crate::error::io(dir, error)),
                }
            }
        }
        let keys = Self::init(&temp, now, ttl_seconds)?;
        fs::File::open(&temp)
            .and_then(|f| f.sync_all())
            .map_err(|e| crate::error::io(&temp, e))?;
        match fs::rename(&temp, dir) {
            Ok(()) => {
                temp_guard.disarm();
                fs::File::open(parent)
                    .and_then(|f| f.sync_all())
                    .map_err(|e| crate::error::io(parent, e))?;
                Ok(keys)
            }
            Err(error) if rename_collision(&error) => Self::load_verified(dir),
            Err(error) => Err(crate::error::io(dir, error)),
        }
    }

    /// `load`, plus every consistency check of [`VerifyCheck`]. After a root
    /// rotation, this fails with `SigningRoot` until `renew` re-signs the
    /// delegation under the installed root.
    pub fn load_verified(dir: &Path) -> Result<Self, KeyfileError> {
        files::check_dir(dir)?;
        let _lock = files::lock_shared(dir)?;
        let keys = Self::load_files(dir)?;
        verify_identity(&keys)?;
        Ok(keys)
    }

    /// `Ok(None)` when `dir` or its `agent_id` marker is absent; otherwise `load_verified`.
    pub fn load_existing(dir: &Path) -> Result<Option<Self>, KeyfileError> {
        match fs::symlink_metadata(dir) {
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(crate::error::io(dir, error)),
            Ok(_) => files::check_dir(dir)?,
        }
        if !exists(&dir.join(AGENT_ID_FILE)) {
            return Ok(None);
        }
        Self::load_verified(dir).map(Some)
    }

    /// True when `dir` exists and holds the `agent_id` marker.
    pub fn exists(dir: &Path) -> bool {
        fs::symlink_metadata(dir)
            .map(|meta| meta.is_dir() && meta.permissions().mode() & 0o077 == 0)
            .unwrap_or(false)
            && exists(&dir.join(AGENT_ID_FILE))
    }

    /// Re-signs the delegation with the in-memory root and device when it is due
    /// within `margin_seconds`; writes `delegation.json` when `dir` is given.
    /// Returns whether it renewed.
    pub fn renew_if_due(
        &mut self,
        dir: Option<&Path>,
        now: i64,
        ttl_seconds: i64,
        margin_seconds: i64,
    ) -> Result<bool, KeyfileError> {
        if !renewal_due(&self.delegation, now, margin_seconds) {
            return Ok(false);
        }
        let delegation = delegate_device(
            &self.root,
            &self.principal_id,
            &self.device,
            now,
            now.saturating_add(ttl_seconds),
        )?;
        if let Some(dir) = dir {
            files::check_dir(dir)?;
            let _lock = files::lock_exclusive(dir)?;
            let disk_root = read_duo(dir, ROOT_FILE)?;
            let disk_device = read_duo(dir, DEVICE_FILE)?;
            if signing_public(&disk_root) != signing_public(&self.root)
                || encryption_public(&disk_root) != encryption_public(&self.root)
                || signing_public(&disk_device) != signing_public(&self.device)
                || encryption_public(&disk_device) != encryption_public(&self.device)
            {
                return Err(KeyfileError::DelegationMismatch);
            }
            write_delegation(dir, &delegation)?;
        }
        self.delegation = delegation;
        Ok(true)
    }

    /// Replaces the device with a new one and retires the old device's public
    /// keys. This is [`IdentityKeys::renew`] with `new_device = true`.
    pub fn rotate_device(dir: &Path, now: i64, ttl_seconds: i64) -> Result<Self, KeyfileError> {
        Self::renew(dir, now, ttl_seconds, true)
    }

    /// Replaces the root with a new one. The rotation is signed by the old root
    /// and returned for the caller to submit. `agent_id` does not change.
    ///
    /// The delegation is not re-signed here: until [`IdentityKeys::renew`] runs,
    /// `delegation_is_current` is false. Write order: the complete rotation chain
    /// first, then `root.jwk.json`. A crash between them leaves the old root on
    /// disk with a pending final rotation in the chain. `load` and the old root
    /// still work (`load_verified` fails with `PrincipalGenesis` until a retry),
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
        let signed = rotation(&keys.root, &keys.principal_id, &new_root, now)?;
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

/// The principal stored in `dir`, read from `agent_id` and `delegation.json`
/// only (no private key). `Ok(None)` when missing; verified as in the spec.
pub fn read_principal(_dir: &Path) -> Result<Option<PrincipalId>, KeyfileError> {
    let dir = _dir;
    match fs::symlink_metadata(dir) {
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(crate::error::io(dir, error)),
        Ok(_) => files::check_dir(dir)?,
    }
    if !exists(&dir.join(AGENT_ID_FILE)) {
        return Ok(None);
    }
    let id = read_principal_id(dir)?;
    let delegation = read_delegation(dir)?;
    let genesis = delegation
        .principal_genesis
        .as_ref()
        .ok_or(KeyfileError::VerifyFailed(VerifyCheck::PrincipalGenesis))?;
    let genesis = PublicKey::try_from(genesis)
        .map_err(|_| KeyfileError::VerifyFailed(VerifyCheck::PrincipalGenesis))?;
    let rotations = read_rotations(dir)
        .map_err(|_| KeyfileError::VerifyFailed(VerifyCheck::PrincipalGenesis))?;
    let chain = AuthorityChain::from_rotations(genesis, &rotations.rotations)
        .map_err(|_| KeyfileError::VerifyFailed(VerifyCheck::PrincipalGenesis))?;
    if id != chain.principal() {
        return Err(KeyfileError::VerifyFailed(VerifyCheck::AgentId));
    }
    let signing_root = PublicKey::try_from(
        delegation
            .signing_root
            .as_ref()
            .ok_or(KeyfileError::VerifyFailed(VerifyCheck::SigningRoot))?,
    )
    .map_err(|_| KeyfileError::VerifyFailed(VerifyCheck::SigningRoot))?;
    if &signing_root != chain.head() {
        return Err(KeyfileError::VerifyFailed(VerifyCheck::SigningRoot));
    }
    if delegation.purpose != pb::KeyPurpose::Device as i32 {
        return Err(KeyfileError::VerifyFailed(VerifyCheck::Purpose));
    }
    let transcript = transcripts::key_delegation_transcript(&delegation)
        .map_err(|_| KeyfileError::VerifyFailed(VerifyCheck::Signature))?;
    if verify_p256(chain.head(), &transcript, &delegation.signature).is_err() {
        return Err(KeyfileError::VerifyFailed(VerifyCheck::Signature));
    }
    Ok(Some(id))
}

impl DeviceKeys {
    /// Reads only the device, delegation, principal id, and device history files.
    /// The root and rotation files are never opened or inspected.
    pub fn load(dir: &Path) -> Result<Self, KeyfileError> {
        files::check_dir(dir)?;
        let _lock = files::lock_shared(dir)?;
        let device = read_duo(dir, DEVICE_FILE)?;
        let delegation = read_delegation(dir)?;
        let principal_id = read_principal_id(dir)?;
        let retired = read_history(dir)?.retired;
        check_delegation(&device, &delegation)?;
        Ok(Self {
            device,
            delegation,
            principal_id,
            retired,
        })
    }

    /// Returns public device data without exposing the private device key.
    pub fn public(&self) -> DevicePublic {
        DevicePublic::new(
            &self.principal_id,
            &self.device,
            &self.delegation,
            &self.retired,
        )
    }
}

impl DevicePublic {
    fn new(
        principal_id: &PrincipalId,
        device: &KeyDuo,
        delegation: &pb::KeyDelegation,
        retired: &[pb::RetiredDevice],
    ) -> Self {
        Self {
            principal_id: principal_id.clone(),
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
pub fn device_keys_at(keys: &IdentityKeys, at: i64) -> Vec<PublicKey> {
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
        let before = IdentityKeys::init(dir.path(), 1_000, 100).unwrap();
        let old_signing = signing_public(&before.device);
        {
            let _armed = Failpoint::on(DEVICE_FILE);
            assert!(matches!(
                IdentityKeys::renew(dir.path(), 1_010, 100, true),
                Err(KeyfileError::Io { .. })
            ));
        }
        let loaded = IdentityKeys::load(dir.path()).unwrap();
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
        let before = IdentityKeys::init(dir.path(), 1_000, 100).unwrap();
        {
            let _armed = Failpoint::on(DELEGATION_FILE);
            assert!(matches!(
                IdentityKeys::renew(dir.path(), 1_010, 100, true),
                Err(KeyfileError::Io { .. })
            ));
        }
        assert!(matches!(
            IdentityKeys::load(dir.path()),
            Err(KeyfileError::DelegationMismatch)
        ));
        let written = signing_public(&read_duo(dir.path(), DEVICE_FILE).unwrap());
        assert_ne!(written, signing_public(&before.device));
        let repaired = IdentityKeys::renew(dir.path(), 1_020, 100, false).unwrap();
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
                IdentityKeys::init(&target, 1, 100),
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
            matches!(IdentityKeys::load(&target), Err(KeyfileError::Missing(p)) if p.ends_with(AGENT_ID_FILE))
        );
        assert!(matches!(
            IdentityKeys::init(&target, 1, 100),
            Err(KeyfileError::AlreadyInitialised(_))
        ));
    }

    #[test]
    fn rotate_root_writes_rotations_before_the_root() {
        let dir = private_dir();
        let before = IdentityKeys::init(dir.path(), 1_000, 100).unwrap();
        let old_root = signing_public(&before.root);
        let root_bytes = fs::read(dir.path().join(ROOT_FILE)).unwrap();
        {
            let _armed = Failpoint::on(ROOT_FILE);
            assert!(matches!(
                IdentityKeys::rotate_root(dir.path(), 50),
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
            signing_public(&IdentityKeys::load(dir.path()).unwrap().root),
            old_root
        );

        let other = private_dir();
        let other_keys = IdentityKeys::init(other.path(), 1_000, 100).unwrap();
        {
            let _armed = Failpoint::on(ROTATIONS_FILE);
            assert!(matches!(
                IdentityKeys::rotate_root(other.path(), 50),
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
        let before = IdentityKeys::init(dir.path(), 1_000, 100).unwrap();
        let old_root = signing_public(&before.root);
        {
            let _armed = Failpoint::on(ROOT_FILE);
            assert!(matches!(
                IdentityKeys::rotate_root(dir.path(), 50),
                Err(KeyfileError::Io { .. })
            ));
        }
        let loaded = IdentityKeys::load(dir.path()).unwrap();
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

        let retried = IdentityKeys::rotate_root(dir.path(), 60).unwrap();
        let after = IdentityKeys::load(dir.path()).unwrap();
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
        let renewed = IdentityKeys::renew(dir.path(), 70, 100, false).unwrap();
        assert!(renewed.delegation_is_current());
    }

    #[test]
    fn rotate_root_retry_does_not_fork_the_chain() {
        let dir = private_dir();
        let before = IdentityKeys::init(dir.path(), 1_000, 100).unwrap();
        let old_root = signing_public(&before.root);
        for _ in 0..2 {
            let _armed = Failpoint::on(ROOT_FILE);
            assert!(IdentityKeys::rotate_root(dir.path(), 50).is_err());
        }
        let final_rotation = IdentityKeys::rotate_root(dir.path(), 60).unwrap();
        let loaded = IdentityKeys::load(dir.path()).unwrap();
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
