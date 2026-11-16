# Changelog

## identity-crypto 0.11.0, identity-keyfile 0.11.0, identity-request-auth 0.2.0

This release changes the three crates together and has no backward
compatibility: there are no shims, no re-exports at old paths and no
deprecated aliases. Re-pin all three crates to the same pushed commit.

Breaking changes, grouped by consumer:

### Every consumer

- Re-pin `identity-crypto`, `identity-keyfile` and `identity-request-auth` to
  the pushed SHA.
- `MAX_UNLISTED_DELEGATION_SECONDS` is now `MAX_DELEGATION_SECONDS`.
- Delete your own TTL, margin and `now_unix`/`unix_now` helpers. Use
  `DEFAULT_DELEGATION_SECONDS`, `DEFAULT_RENEW_MARGIN_SECONDS` and
  `identity_crypto::now_unix`. This applies to new delegations only.
- `delegate_device(root, id, &PublicKeyDuo::from(&device), ..)`: the device is a
  `PublicKeyDuo`.
- `rotation(old, id, &signing_public(&new_root), at)`.
- Signing failures are `Error::Signer(SignerError)`, not `InvalidKey`.
- Add `_ =>` arms when matching `KeyfileError`, `VerifyCheck`, `LookupError`
  and `AuthError`. These enums are `#[non_exhaustive]`.
- `impl Clock` requires `fn now(&self) -> Timestamp`. Calls become
  `clock.now().seconds`.
- `LookupError` lives at `identity_request_auth::LookupError`.
- `AuthError::SessionExpired` is class `Transient` (was `Logical`). Its code
  `identity.request_auth.session_expired`, its trailers and its gRPC status
  `UNAUTHENTICATED` are unchanged. A watch that follows with `op-listen` now
  reconnects after the client renews its certificate instead of ending.
- Testkit renames: `testkit::Signer` becomes `TestKey`;
  `testkit::sign_document` becomes `sign_test_document`; `FakeClock` gains
  `set_at`.
- A `0644`, symlinked or other-uid key file or identity directory is now
  refused. Survey mode and owner uid before upgrading.

### grorg

- `agent_keys.rs`:
  - The local `adopt_root` and `only_root_present` become
    `IdentityKeys::adopt_root(dir, now, ttl, refuse)`. It is called only behind
    the new `agent key ensure --adopt-root` flag; without the flag a root-only
    directory is `OrphanRoot`. `refuse` comes from `GRORG_OWNER_PRINCIPAL` when
    set. The real guard is server-side: `agent register` refuses a root equal to
    the owner.
  - `is_device_only` and `only_root_present` keep their semantics
    (`device_only_client.rs` pins "device-only dir never written").
  - `register-gp.sh` (`agent ensure --name gp` on the owner key) calls
    `IdentityKeys::adopt_owner_root(dir, now, ttl, &owner, &MachineDir::locate()?)`.
    A missing machine directory is an error with a clear message.
  - The local `is_device_only` becomes the library's.
- `DEFAULT_VALIDITY_SECONDS` becomes 30 days.
- `grorg-server/src/signing.rs` `AgentKeyDevices` maps rows to `KeyRecord` and
  returns `live_devices(&records, at)`. A retired agent gives an empty slice,
  hence `Unknown`.
- Drop `CloneableAuth` (use `RequestAuthLayer: Clone`), `CallerLayer` (use
  `caller_extension` and `caller()`) and `reject_auth` (use codes; keep
  `on_reject` only for grorg's own codes).
- `grorg-client` `SigningChannel` becomes `SignedChannel::from_identity_dir`,
  with `AudienceSource::Discover` (or `Fixed` when an audience is configured)
  and `endpoint_defaults`.
- `device_only_client.rs` `FakeClock` becomes `now()`.
- `grorg-ops` takes the constant rename.
- Its identity directory comes from
  `service_identity_dir(GRORG_IDENTITY_DIR, &machine, "grorg")`, and it is
  enrolled as `grorg`.
- The signed policy goes through `DocumentLoader`, with the tighten-only
  `structure` hook and a configurable state path.

### multimatrix

- `PolicyLoader` becomes `DocumentLoader<Grants>`:
  - decode is `PolicyDocument::decode` plus `Grants::from_document`;
  - a new state path setting;
  - `ISSUED_SKEW_SECONDS` is deleted (use `check_document_time`);
  - `current(now)` replaces the `grants()` expiry logic.
- `key_source.rs` gets `KeyRecord`, `live_devices` and the `LookupError` path.
- `BodySizeGuard` is deleted (use the layer's `max_body`; the refusal code is
  `identity.request_auth.body_too_large`).
- `multimatrix-client` `CONNECT_TIMEOUT` and `KEEPALIVE_*` become
  `endpoint_defaults`.
- `signer.rs` uses `DeviceCredentials::new(keys.device, ..)`.
- The device renew margin moves from 1 day to 7 days.
- The service key is read via `private_fs::read_private_file`.
- `mint_session(&duo, ..)` may pass the duo directly.
- Use `RecordDevices` and `StaticDevices` with `FakeClock`.
- The service principal is unchanged (its existing directory is enrolled).

### structmux

- The `write_private` copies in `structmux-identity`, `structmux-approval-key`,
  `client-flows` and `client-state` are deleted. Use
  `private_fs::write_private_atomic(path, bytes, 0o600)`. Read with
  `read_private_file`, which zeroizes.
- The owner tool reads with `read_duo_file`.
- `ROOT_FILE` and `check_private_dir` are used as the library's.
- Document primitives: `sign_document`, `document_id`, `check_document_time`.
  Successor, lifetime and structure checks stay structmux's (as hooks or its own
  state machine). `SETTINGS_LIFETIME_SECONDS` stays separate.
- `HostingDaemon.device` and `HostedAgent.device` are `&dyn Signer`. Literals
  with `&SigningKeyPair` still coerce.
- `IdentityKeys` fields stay public.
- `DaemonIdentity::create_or_load` on a directory with an orphan root now
  returns `OrphanRoot`.
- Daemon directories are recorded with
  `enrol(machine, "structmux/<short_id>", enrolment_for(dir, None)?, &owner)`,
  without moving them. structmux passes its explicit daemon state directory as
  the service override (never the default under the machine directory) and
  checks short ids against the key grammar (lowercase `^[a-z0-9]...`).
- Loose daemon identity or replay directories or files are refused, not
  tightened. The Wave D migration fixes modes first; the survey covers the
  docker bind-mount uid question.
- The client device key and delegation go in the machine directory.
- The margin moves from 15 days to 7 days.

### gait

- `_` arm in `gait-identity`'s `from_keyfile`.
- `RENEW_MARGIN_SECS` (15 days) and `DELEGATION_TTL_SECS` are deleted. Use the
  library's 7-day margin and 30-day delegation.
- `unix_now` becomes `now_unix`.
- `mint_or_load`: `create_or_load_at` on a split layout no longer adopts an
  orphan `identity-root/root.jwk.json`. It returns `OrphanRoot(root_dir)`, which
  gait maps to a coded `IdentityError` with recovery text. Check fixtures that
  relied on adoption.
- The hand sandbox deny list adds `MachineDir::locate()?.path()`.
- Test fixtures with loose key files now fail.

### archegraph

- `DELEGATION_TTL_SECONDS` (31 days) becomes `DEFAULT_DELEGATION_SECONDS`
  (30 days).
- `load_or_init` becomes `IdentityKeys::create_or_load`. Existing expired
  31-day directories load unmodified. Then `renew_if_due_at` renews (root
  present), and a device-only directory fails loudly with `DeviceOnly`.
- An `OrphanRoot` from `init_daemon` is a loud error to the caller, while
  telemetry still starts (new test case).
- Loose old development directories are refused with a clear error (fixed by the
  Wave D migration where live).
- `service_identity_dir(Some(ARCHEGRAPH_IDENTITY_DIR), _, "archegraph")` keeps
  the environment override; the 30-day constant replaces 31 days.

### catuskoti

No identity API in use; nothing to absorb.

### message-attestation

Consumes exactly:

- `identity_crypto::{Signer, Signature, SignerError, verify_signature}`.
- `KeyDuo` and `SigningKeyPair` implement `Signer`.
- `identity_keyfile::private_fs::{create_private_dir, write_private_atomic(path,
  bytes, 0o600), read_private_file(path, cap) -> Zeroizing<Vec<u8>>}`.
- A missing file is `KeyfileError::Missing(path)`; a FIFO or non-file is
  `NotAFile`; an oversize file is `TooLarge`.
- `SignerError` is `Clone + PartialEq + Eq + 'static`, so
  `downcast_ref::<SignerError>() == Some(&SignerError::Cancelled)` works.
