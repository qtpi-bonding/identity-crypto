# identity-keyfile

`identity-keyfile` keeps a self-rooted principal's keys (an agent or a daemon) in a Unix directory. It
creates them (`IdentityKeys::init`), re-signs the device delegation (`renew`),
replaces the device (`rotate_device`, or `renew` with `new_device = true`),
replaces the root (`rotate_root`), and reads and writes them (`load`, `save`).
The crate is Unix-only: key files are written mode `0600`, and other targets
fail to compile.

## Device-only loading

`DeviceKeys::load(dir)` reads the device key, delegation, agent id, and retired
device history while taking the same shared lock as `IdentityKeys::load`. It never
opens, stats, or checks `root.jwk.json` or `rotations.json`, so a device-only
signer can run without access to the root. Like `IdentityKeys::load`, it creates
`.lock`, and reads without a lock when the directory is read-only. `DeviceKeys::public()` (and
`IdentityKeys::public()`) returns the private-key-free `DevicePublic` snapshot.

## Layout

The key directory holds these files:

| File | Contents | Written by |
| --- | --- | --- |
| `root.jwk.json` | root key duo (private) | `init`, `rotate_root`, `save` |
| `device.jwk.json` | device key duo (private) | `init`, `renew(.., true)`, `save` |
| `delegation.json` | root-signed device delegation (proto3 JSON) | `init`, `renew`, `save` |
| `agent_id` | canonical `p256:<genesis>` principal id | `init` (last), `save` (last) |
| `retired_devices.json` | retired devices, public halves and `retiredAtUnixSeconds` (proto3 JSON `DeviceHistory`) | `renew(.., true)`, `save` |
| `rotations.json` | root rotation chain, public data only (proto3 JSON `RootRotations`) | `rotate_root`, `save` |
| `.lock` | empty advisory lock file | every locked operation |

The device-only loader needs `device.jwk.json`, `delegation.json`, `agent_id`,
and (optionally) `retired_devices.json`; the root and rotation files are not
part of its input.

The directory is `0700`. Each file is written as a `0600` temporary file in the
same directory, fsynced, renamed over the target, and then the directory is
fsynced. The temporary name is unique to the call. An existing entry at that
name, including a symlink, is never followed or reused. A failed parent fsync
after a successful rename returns `Err` even though the new file is in place.

Missing `retired_devices.json` or `rotations.json` reads as empty. A file that
exists but is unreadable, a broken symlink, or unparseable is an error, so
retired keys are never dropped silently.

## Refusals

- `InsecureDir`: the directory has any group or other permission bit set
  (`mode & 0o077 != 0`), or it is a symlink or not a directory. Every
  operation checks this before writing anything, so a refused call leaves
  the directory byte-identical. The owner of the directory is not checked.
- `AlreadyInitialised`: `init` found any agent file, including a partial one.
- `Missing`: `load` could not find a mandatory file (`root.jwk.json`,
  `device.jwk.json`, `delegation.json` or `agent_id`), or the directory itself.
- `DelegationMismatch`: `device.jwk.json` is not the device the delegation names.
- `Crypto`: a `ttl_seconds` that is not in `(0, 31 days]`. The cap is the
  verifier's cap for unlisted devices, applied by `delegate_device`. Nothing
  is written.

## Locking

- `init`, `renew`, `rotate_device`, `rotate_root` and `save` take an exclusive
  `flock` on `.lock` for the whole operation.
- `load` takes a shared lock. If `.lock` cannot be created because the
  directory is read-only, `load` reads without a lock and creates nothing.

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
  last chain entry. The old root still works. The next `rotate_root` replaces
  that pending entry instead of extending the chain past it.
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
directory that is removed on drop unless `keep()` is called. Crash
simulations use a crate-private failpoint in `files.rs` and are unit tests in
`src/`.
