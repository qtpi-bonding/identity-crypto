# identity-keyfile

Version 0.11.0. `identity-keyfile` keeps a self-rooted principal's keys (an
agent or a daemon) in a Unix directory. It creates them (`IdentityKeys::init`),
re-signs the device delegation (`renew`), replaces the device (`rotate_device`,
or `renew` with `new_device = true`), replaces the root (`rotate_root`), and
reads and writes them (`load`, `save`). A daemon that keeps one identity per
host uses the verified entry points instead (see below).

All file I/O for the identity workspace lives here; `identity-crypto` stays
I/O-free. The crate is Unix-only: key files are written mode `0600`, and other
targets fail to compile.

## Private files and the modes that are checked

`private_fs` is public:

- `create_private_dir(path)` makes missing ancestors and the directory at
  mode `0700`, then checks it.
- `check_private_dir(path)` requires an existing directory that is not a
  symlink, has no group or other bits (`mode & 0o077 == 0`) and is owned by the
  effective user (`InsecureDir`, `WrongOwner`). It writes nothing.
- `write_private_atomic(path, bytes, mode)` writes through a unique temp file
  and renames it into place. `mode` must be `0600` or `0400` (`InvalidMode`
  otherwise).
- `read_private_file(path, cap)` returns `Zeroizing<Vec<u8>>`. It refuses a
  symlink, a non-regular file (`NotAFile`, including FIFOs, which it never
  blocks on), any group or other bit (`InsecureFile`), another user's file
  (`WrongOwner`), and anything over `cap` (`TooLarge`).
- `read_regular_file(path, cap)` reads public data inside an already-checked
  directory: no mode or owner check, but still no symlink, no non-regular file
  and the same size cap.

Which files get which check:

- Key files (`root.jwk.json`, `device.jwk.json`) are read with
  `read_private_file`. A `0644` key file gives `InsecureFile`.
- Public files (`delegation.json`, `rotations.json`, `retired_devices.json`,
  `agent_id`) load at any mode inside a checked directory.
- Policy and other documents are not mode-checked (see DocumentLoader below).
- The directory itself must pass `check_private_dir`: a loose or symlinked
  identity dir is refused.

Size caps: `MAX_KEY_FILE_BYTES` (16 KiB) and `MAX_PUBLIC_FILE_BYTES` (1 MiB)
in `private_fs`; `MAX_DOCUMENT_BYTES` (1 MiB) for documents.

## Machine identity directory

The machine identity directory holds service and machine identities and the
machine-level index (`enrolments.json`), and never the owner's own key. `MachineDir` locates it:

- `MachineDir::locate()` (or `locate_with(env)` for tests) resolves, in order:
  `MACHINE_IDENTITY_DIR`, then `$XDG_DATA_HOME/machine-identity`, then
  `$HOME/.local/share/machine-identity`. Empty values count as unset. A relative
  result is `InvalidLayout`; with none of the three it is
  `MachineDirUnresolved`.
- `MachineDir::at(path)` names an explicit directory. `ensure()` creates it at
  `0700` if missing.
- `MACHINE_IDENTITY_DIR` is the only environment variable the library reads,
  and only in `machine.rs`.
- Agent identities never use the machine directory. They take an explicit dir.

Service identity directories come from `service_identity_dir(override, &machine,
key)`, which returns `(PathBuf, DirSource)`:

1. an absolute per-service `override` (`DirSource::Override`);
2. the checked index entry for `key` (`DirSource::Index`);
3. `machine/services/<key>`, with `/` as `%2F` and `:` as `%3A` (`DirSource::Default`).

## The enrolment index: `enrolments.json`

`EnrolmentIndex` is `machine/enrolments.json`, written at mode `0600` through a
temp file and rename, under the exclusive lock `machine/.lock` (reads take the
shared lock; a missing file is an empty index). Its shape, with keys sorted:

```json
{
  "services": {
    "grorg": {
      "device_key_id": "<RFC 7638 thumbprint of the delegated device key>",
      "dir": "/absolute/path/to/identity-dir",
      "principal_id": "p256:<130 lowercase hex>"
    },
    "structmux/3b6a27bcceb6a42d": {
      "device_key_id": "...",
      "dir": "...",
      "principal_id": "p256:..."
    }
  },
  "version": 1
}
```

Each entry may also carry `endpoint`, which is omitted when absent. Unknown
fields are refused, and so is any version other than `1` (`IndexVersion`).
Service keys are lowercase, start with a letter or digit, are 1 to 128
characters of `[a-z0-9._:/-]`, and contain no `..` (`InvalidEnrolmentKey`).

- `enrol(machine, key, entry, owner)` records an entry under the exclusive
  lock. It refuses the owner's principal (`OwnerEnrolment`) and any entry that
  fails the checks below. It writes nothing inside `entry.dir`.
- `remove(machine, key)` returns whether the key was present.
- `checked(key)` reads one entry and checks it against the directory:
  the directory exists, is private (`DirInsecure`, symlink included) and is
  owned by the effective user (`DirOwner`); its `agent_id` is the entry's
  principal (`PrincipalId`); and its delegation's device thumbprint is the
  entry's `device_key_id` (`DeviceKeyId`). Failures are
  `EnrolmentMismatch { key, check }`.
- `enrolment_for(dir, endpoint)` builds an entry from an existing identity
  directory, reading only `agent_id` and `delegation.json`.

## Adoption and device-only directories

- **Never adopted implicitly.** `create_or_load` (and `create_or_load_at`)
  never adopts a root. A directory holding `root.jwk.json` with no `agent_id`
  gives `OrphanRoot(dir)` and writes nothing. In a split layout the error names
  `root_dir`.
- **`IdentityKeys::adopt_root(dir, now, ttl, refuse)`** is the explicit opt-in.
  Under the lock, if `agent_id` exists it loads and verifies it (idempotent).
  Otherwise it creates the device files under the root found in `dir` and
  writes `agent_id` last. When the root's principal equals `refuse`, it returns
  `OwnerRoot` and writes nothing. `refuse: None` refuses nothing.
- **`IdentityKeys::adopt_owner_root(dir, now, ttl, owner, machine)`** is the
  owner's own registration. The machine directory must exist
  (`MachineDirMissing`); `dir` must not be inside it, after symlinks are
  resolved (`InsideMachineDir`); and the root's principal must be `owner`
  (`NotOwnerRoot`). Only then does it adopt the root.
- **Device-only folders** hold `agent_id`, `device.jwk.json` and
  `delegation.json` with no `root.jwk.json` (`is_device_only(dir)`). They are
  never written: `renew`, `rotate_device`, `rotate_root`, `renew_if_due`,
  `create_or_load` and `adopt_root` return `DeviceOnly` and change nothing.
- An expired 31-day directory loads unmodified. `renew_if_due_at` then renews
  it when the root is present, and returns `DeviceOnly` when it is not.
- `DeviceKeys::load(dir)` is the device-only loader: it reads what a signer
  needs (device key, delegation, `agent_id`, history) and never touches the root.

## Document loader

`DocumentLoader<T>` (`document_loader.rs`) loads one signed document from disk,
keeps the highest version it has ever accepted, and serves the decoded value.

- Configure with `LoaderConfig { document_path, state_path, authority,
  document_type }`, then `DocumentLoader::new(config, decode)`. Builders:
  `.successor(check)` runs for a version above the high-water mark (it receives
  the previous accepted document); `.max_lifetime(seconds)`; `.structure(check)`
  runs on the decoded body. `structure` may only tighten.
- `reload(now)` returns `Reload::Loaded { accepted, state }`, `Unchanged`, or
  `Refused(DocumentError)`. A refusal clears the document in force.
- `current(now)` returns the document in force, or `None` when none is loaded
  or it has expired at `now`. The time is checked on every call.
- Each reload checks: the file is at most `MAX_DOCUMENT_BYTES`; it decodes; the
  signature and authority verify; `now` is inside its validity window; the
  lifetime is within `max_lifetime`; the version is not below the high-water
  mark (`Rollback`); the same version has the same id (`Equivocation`); the
  successor check passes (only for a higher version); the body decodes and the
  structure check passes.
- The high-water mark lives in `state_path`, not in the document directory, so a
  read-only document directory works. The file is JSON,
  `{"version":1,"document_type":"…","highest_version":N,"document_id":"<64 hex>"}`,
  written mode `0600` and read with `read_private_file` (at most 4 KiB).

State cases:

- **Missing:** first boot. There is no high-water mark yet.
- **Corrupt, wrong version, wrong document type, bad hex id, loose mode, wrong
  owner, not a regular file, or too large:** `StateCorrupt`. Every reload is
  refused until the file is fixed, and nothing is in force.
- **Unwritable:** the document is installed, and the result is
  `StateWrite::Failed(error)`. The in-memory high-water mark is kept, so the
  rollback protection holds for this process. The caller must log it at error
  level.
- **Restart with an older file:** `Rollback`; nothing is in force.
- **Document deleted or unreadable:** `Refused(Read)`; nothing is in force;
  the in-memory high-water mark is kept.

Owner reset: delete the state file. That deliberately forgets the high-water
mark, so the next reload accepts whatever valid version is on disk.

## Split layout

`IdentityLayout::single(dir)` is the layout above. `IdentityLayout::split(root_dir,
device_dir)` puts the root where an agent cannot reach it:

- `root_dir` holds only `root.jwk.json` (and its `.lock`).
- `device_dir` holds everything else: `device.jwk.json`, `delegation.json`,
  `agent_id`, `retired_devices.json`, `rotations.json` and its own `.lock`. This
  is the folder an agent may be shown.

Both paths must be absolute with no `.` or `..` components. They are compared
after symlinks are resolved; `root_dir` may not be `device_dir`, inside it, or
contain it (`KeyfileError::InvalidLayout`). Use one `root_dir` per identity.

Every operation has an `_at(&IdentityLayout)` form: `init_at`, `save_at`,
`load_at`, `load_verified_at`, `load_existing_at`, `exists_at`,
`create_or_load_at`, `renew_at`, `rotate_device_at`, `rotate_root_at`,
`renew_if_due_at`. The `dir` functions (`init(dir, ..)` and the rest) call them
with `IdentityLayout::single(dir)`, so the `_at` functions are the single
layout implementation and the `dir` behaviour is unchanged.

Lock order: `root_dir/.lock` first, then `device_dir/.lock`, exclusive for
writes and shared for reads. A single layout has one lock, taken once.

`create_or_load_at` cannot rename across two folders, so it runs under both
exclusive locks. In a split layout an existing `root.jwk.json` is never
overwritten: if `root_dir` already holds a root but `device_dir` has no
identity, that root is still not adopted; the call returns `OrphanRoot`.

## Verified loading and atomic creation

For a long-lived identity (a daemon's), where a crash or two processes
starting together must never produce a second root:

- `IdentityKeys::create_or_load(dir, now, ttl)` loads and verifies `dir` if it
  holds an identity. Otherwise it runs `init` in a sibling temp directory
  (`<dir>.tmp-<pid>-<n>-<suffix>`), fsyncs it, and renames it into place, so a
  crash leaves nothing or a complete identity. A process that loses the rename
  race loads the winner's. Temp siblings are removed on failure, and stale ones
  only when their pid is dead. A directory holding only `.lock` is cleared with
  unlink and rmdir, never a recursive delete. A directory with key files but
  no `agent_id` is an error and is left untouched. The parent may be any mode
  and is created if missing.
- `IdentityKeys::load_verified(dir)` is `load` plus every consistency check:
  the rotation chain from `principal_genesis` ends at the root on disk,
  `agent_id` is that chain's principal, `signing_root` is the current root,
  `delegated` and `delegated_encryption` are the device's keys, the purpose is
  Device, and the signature verifies. A failure is `VerifyFailed(check)`.
  After `rotate_root` and before `renew` it fails with `VerifyFailed(SigningRoot)`.
- `IdentityKeys::load_existing(dir)` is `Ok(None)` when `dir` or `agent_id` is
  absent, else `load_verified`. `IdentityKeys::exists(dir)` is true for a
  secure directory holding `agent_id`.
- `read_principal(dir)` verifies the same chain, purpose and signature from
  `agent_id`, `delegation.json` and `rotations.json` without opening a private
  key file.
- `renew_if_due(&mut self, dir, now, ttl, margin)` re-signs when
  `renewal_due` says so and writes `delegation.json` under the exclusive lock.
  It refuses with `DelegationMismatch` when the root or device on disk no
  longer match memory (another process rotated). It does not re-read the
  delegation, so a concurrent renewal is overwritten.

## Refusals

- `InsecureDir`: the directory has any group or other permission bit set
  (`mode & 0o077 != 0`), or it is a symlink or not a directory.
- `WrongOwner`: the directory or a private file is owned by another user.
- `InsecureFile` and `NotAFile`, `TooLarge`: see Private files above.
- `AlreadyInitialised`: `init` found any agent file, including a partial one.
- `Missing`: `load` could not find a mandatory file (`root.jwk.json`,
  `device.jwk.json`, `delegation.json` or `agent_id`), or the directory itself.
- `DelegationMismatch`: `device.jwk.json` is not the device the delegation names.
- `VerifyFailed(check)`: a `load_verified` or `read_principal` check failed.
- `Crypto`: a `ttl_seconds` that is not in `(0, 31 days]`. The cap is the
  verifier's cap for unlisted devices, applied by `delegate_device`. Nothing
  is written.

Every operation checks the directory before writing anything, so a refused
call leaves the directory byte-identical.

## Locking

- `init`, `renew`, `rotate_device`, `rotate_root` and `save` take an exclusive
  `flock` on `.lock` for the whole operation.
- `load` takes a shared lock. If `.lock` cannot be created because the
  directory is read-only, `load` reads without a lock and creates nothing.
- The enrolment index takes `machine/.lock` the same way (exclusive for
  `enrol` and `remove`, shared for reads).

## Write order and crash states

- `init` writes the root, the device, the delegation, the empty history, the
  empty chain and then `agent_id`. `agent_id` is the commit marker. A crash
  before it leaves a stuck directory: `load` reports `Missing(agent_id)` and
  `init` reports `AlreadyInitialised`. Remove the directory and init again.
- `renew(.., true)` writes the history, then the device, then the delegation.
  A crash after the history leaves an entry for the still-current device,
  which `device_keys_at` ignores. A crash after the device leaves a
  mismatch: `load` returns `DelegationMismatch`, and `renew(.., false)`
  re-signs for the current device and repairs it.
- `rotate_root` writes the whole rotation chain, then the root. A crash between
  the two leaves the old root installed, with the unfinished rotation as the
  last chain entry. `load` and the old root still work, but `load_verified` and
  `read_principal` fail with `PrincipalGenesis` until `rotate_root` is run again.
  The next `rotate_root` replaces that pending entry instead of extending the
  chain past it.
- `rotate_root` does not re-sign the delegation. `delegation_is_current()` is
  false until `renew` runs under the new root. It compares the root and device
  keys only, not the signature or the window.
- When `retired_at` is already recorded for a signing key, a later retirement of
  that key keeps the earlier time.

## Device history and `device_keys_at`

`device_keys_at(keys, at)` returns the current device key, then each retired
signing key whose `retired_at_unix_seconds >= at`, in history order, without
duplicates. A retired entry with a missing or unparseable key is dropped, so
the result fails closed.

`retired_at_unix_seconds` is a local, unsigned claim. Nothing signs it and no
clock checks it. Pass `at` from a trusted clock or from receipt time, never
from the message's own `issued_at`. Otherwise a compromised retired key can
sign claimed-earlier messages indefinitely. The history file holds public
halves only.

## Testing

The `testkit` feature exports `TempIdentityDir`, a private temporary agent
directory that is removed on drop unless `keep()` is called, and
`TempMachineDir`, a temporary machine directory. Tests use `MachineDir::at` or
`MachineDir::locate_with` and never touch a real home or machine directory.
Crash simulations use a crate-private failpoint in `files.rs` and are unit tests
in `src/`.
