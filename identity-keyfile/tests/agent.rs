use identity_crypto::jwk_duo::KeyDuoSerializer;
use identity_crypto::{
    encryption_public, pb, signing_public, transcripts, verify_p256,
    MAX_UNLISTED_DELEGATION_SECONDS,
};
use identity_keyfile::*;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;

const STANDARD_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const URL_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// The verifier's cap on an unlisted device window, in seconds.
const MAX_TTL: i64 = MAX_UNLISTED_DELEGATION_SECONDS;

/// Decodes unpadded or padded base64 in the given alphabet. Panics on a foreign character.
fn decode_base64(input: &str, alphabet: &[u8; 64]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buffer: u32 = 0;
    let mut bits = 0;
    for c in input.bytes().take_while(|&c| c != b'=') {
        let value = alphabet
            .iter()
            .position(|&a| a == c)
            .expect("base64 character") as u32;
        buffer = (buffer << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    out
}

/// Standard base64 with padding.
fn encode_standard_base64(bytes: &[u8]) -> String {
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0];
        let b1 = *chunk.get(1).unwrap_or(&0);
        let b2 = *chunk.get(2).unwrap_or(&0);
        let n = (u32::from(b0) << 16) | (u32::from(b1) << 8) | u32::from(b2);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(STANDARD_ALPHABET[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Collects every string value stored under a `d` member, at any depth.
fn collect_private_d(value: &serde_json::Value, out: &mut Vec<String>) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map {
                if key == "d" {
                    if let Some(text) = child.as_str() {
                        out.push(text.to_owned());
                    }
                }
                collect_private_d(child, out);
            }
        }
        serde_json::Value::Array(items) => {
            items.iter().for_each(|item| collect_private_d(item, out))
        }
        _ => {}
    }
}

/// `tempfile` creates 0755 directories on some platforms; agent dirs must be private.
fn tempdir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

/// Every entry of `dir` as (name, bytes, mode), sorted by name.
fn snapshot(dir: &Path) -> Vec<(String, Vec<u8>, u32)> {
    let mut entries: Vec<_> = fs::read_dir(dir)
        .unwrap()
        .map(|entry| {
            let path = entry.unwrap().path();
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            (
                name,
                fs::read(&path).unwrap(),
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            )
        })
        .collect();
    entries.sort();
    entries
}

fn fresh() -> (tempfile::TempDir, AgentKeys) {
    let dir = tempdir();
    let keys = AgentKeys::init(dir.path(), 1_000, 100).unwrap();
    (dir, keys)
}

#[test]
fn init_then_load_round_trips() {
    let (dir, keys) = fresh();
    let loaded = AgentKeys::load(dir.path()).unwrap();
    assert_eq!(loaded.agent_id, keys.agent_id);
    assert_eq!(loaded.delegation, keys.delegation);
    assert_eq!(
        signing_public(&loaded.root),
        signing_public(&keys.root),
        "root signing half"
    );
    assert_eq!(
        signing_public(&loaded.device),
        signing_public(&keys.device),
        "device signing half"
    );
    assert_eq!(
        encryption_public(&loaded.device),
        encryption_public(&keys.device),
        "device encryption half"
    );
    assert!(loaded.retired.is_empty());
    assert!(loaded.rotations.is_empty());
    assert!(loaded.delegation_is_current());
}

#[test]
fn init_refuses_to_overwrite() {
    let (dir, _) = fresh();
    let before = snapshot(dir.path());
    assert!(matches!(
        AgentKeys::init(dir.path(), 2, 100),
        Err(KeyfileError::AlreadyInitialised(_))
    ));
    assert_eq!(
        snapshot(dir.path()),
        before,
        "a refused init writes nothing"
    );

    let partial = tempdir();
    fs::write(partial.path().join(ROOT_FILE), b"partial").unwrap();
    assert!(matches!(
        AgentKeys::init(partial.path(), 1, 100),
        Err(KeyfileError::AlreadyInitialised(_))
    ));
    assert_eq!(
        fs::read(partial.path().join(ROOT_FILE)).unwrap(),
        b"partial"
    );
    assert!(!partial.path().join(AGENT_ID_FILE).exists());
}

#[test]
fn init_rejects_ttl_over_31_days_and_nonpositive() {
    let dir = tempdir();
    let path = dir.path().join("agent");
    for ttl in [0, -1, MAX_TTL + 1] {
        assert!(
            matches!(
                AgentKeys::init(&path, 1_000, ttl),
                Err(KeyfileError::Crypto(_))
            ),
            "ttl {ttl}"
        );
    }
    assert!(
        snapshot(&path).is_empty(),
        "a rejected init writes no agent file"
    );

    let keys = AgentKeys::init(&path, 1_000, MAX_TTL).unwrap();
    assert_eq!(
        keys.delegation.not_after_unix_seconds - keys.delegation.issued_at_unix_seconds,
        MAX_TTL
    );
}

#[test]
fn renew_rejects_bad_ttl_without_touching_files() {
    let (dir, _) = fresh();
    let before = snapshot(dir.path());
    for (ttl, new_device) in [
        (0, false),
        (MAX_TTL + 1, false),
        (0, true),
        (MAX_TTL + 1, true),
    ] {
        assert!(
            matches!(
                AgentKeys::renew(dir.path(), 1_010, ttl, new_device),
                Err(KeyfileError::Crypto(_))
            ),
            "ttl {ttl}, new_device {new_device}"
        );
    }
    assert_eq!(
        snapshot(dir.path()),
        before,
        "no file was written, not even the history"
    );
}

#[test]
fn renew_same_device_keeps_history_empty() {
    let (dir, before) = fresh();
    let history_before = fs::read(dir.path().join(HISTORY_FILE)).unwrap();
    let after = AgentKeys::renew(dir.path(), 1_010, 100, false).unwrap();
    assert_eq!(after.retired.len(), 0);
    assert_eq!(
        signing_public(&after.device),
        signing_public(&before.device)
    );
    assert!(after.delegation_is_current());

    let loaded = AgentKeys::load(dir.path()).unwrap();
    assert!(loaded.retired.is_empty());
    assert_eq!(
        fs::read(dir.path().join(HISTORY_FILE)).unwrap(),
        history_before,
        "history bytes unchanged"
    );
    assert_eq!(loaded.delegation.issued_at_unix_seconds, 1_010);
    assert_eq!(loaded.delegation.not_after_unix_seconds, 1_110);
    let transcript = transcripts::key_delegation_transcript(&loaded.delegation).unwrap();
    assert!(verify_p256(
        &signing_public(&loaded.root),
        &transcript,
        &loaded.delegation.signature
    )
    .is_ok());
}

#[test]
fn renew_new_device_appends_the_old_public_keys() {
    let (dir, before) = fresh();
    let after = AgentKeys::renew(dir.path(), 1_010, 100, true).unwrap();
    let loaded = AgentKeys::load(dir.path()).unwrap();
    for keys in [&after, &loaded] {
        assert_eq!(keys.retired.len(), 1);
        let entry = &keys.retired[0];
        assert_eq!(entry.retired_at_unix_seconds, 1_010);
        assert_eq!(
            entry.signing,
            Some(pb::PublicKey::from(&signing_public(&before.device))),
            "old signing half"
        );
        assert_eq!(
            entry.encryption,
            Some(pb::PublicKey::from(&encryption_public(&before.device))),
            "old encryption half"
        );
        assert_ne!(signing_public(&keys.device), signing_public(&before.device));
        assert_ne!(
            encryption_public(&keys.device),
            encryption_public(&before.device)
        );
        assert!(keys.delegation_is_current());
        assert_eq!(signing_public(&keys.root), signing_public(&before.root));
    }
    assert_eq!(
        signing_public(&loaded.device),
        signing_public(&after.device)
    );
}

#[test]
fn rotate_device_twice_keeps_both_retired_keys_in_order() {
    let (dir, first) = fresh();
    let second = AgentKeys::rotate_device(dir.path(), 10, 100).unwrap();
    let third = AgentKeys::rotate_device(dir.path(), 20, 100).unwrap();
    let loaded = AgentKeys::load(dir.path()).unwrap();
    assert_eq!(loaded.retired.len(), 2);
    assert_eq!(loaded.retired[0].retired_at_unix_seconds, 10);
    assert_eq!(loaded.retired[1].retired_at_unix_seconds, 20);
    assert_eq!(
        loaded.retired[0].signing,
        Some(pb::PublicKey::from(&signing_public(&first.device)))
    );
    assert_eq!(
        loaded.retired[0].encryption,
        Some(pb::PublicKey::from(&encryption_public(&first.device)))
    );
    assert_eq!(
        loaded.retired[1].signing,
        Some(pb::PublicKey::from(&signing_public(&second.device)))
    );
    assert_eq!(
        loaded.retired[1].encryption,
        Some(pb::PublicKey::from(&encryption_public(&second.device)))
    );
    assert_eq!(third.retired, loaded.retired);
}

#[test]
fn history_survives_load() {
    let (dir, _) = fresh();
    let rotated = AgentKeys::rotate_device(dir.path(), 8, 100).unwrap();
    let loaded = AgentKeys::load(dir.path()).unwrap();
    assert_eq!(loaded.retired, rotated.retired);
}

#[test]
fn retired_devices_file_holds_public_halves_only() {
    let (dir, old) = fresh();
    let _ = AgentKeys::rotate_device(dir.path(), 8, 100).unwrap();
    let text = fs::read_to_string(dir.path().join(HISTORY_FILE)).unwrap();
    let json: serde_json::Value = serde_json::from_str(&text).unwrap();
    let retired = json
        .get("retired")
        .and_then(serde_json::Value::as_array)
        .unwrap();
    let entry = retired.first().unwrap().as_object().unwrap();
    let mut keys: Vec<_> = entry.keys().cloned().collect();
    keys.sort();
    assert_eq!(
        keys,
        vec![
            "encryption".to_owned(),
            "retiredAtUnixSeconds".to_owned(),
            "signing".to_owned(),
        ]
    );
    let mut signing_keys: Vec<_> = entry["signing"]
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect();
    signing_keys.sort();
    assert_eq!(signing_keys, vec!["key", "scheme"]);
    let mut encryption_keys: Vec<_> = entry["encryption"]
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect();
    encryption_keys.sort();
    assert_eq!(encryption_keys, vec!["key", "scheme"]);
    assert!(!text.contains("\"d\""));
    for side in ["signing", "encryption"] {
        let key = entry[side]["key"].as_str().unwrap();
        let bytes = decode_base64(key, STANDARD_ALPHABET);
        assert_eq!(bytes.len(), 65, "{side} key is an uncompressed P-256 point");
        assert_eq!(bytes[0], 0x04, "{side} key starts with 0x04");
    }
    let exported = KeyDuoSerializer::export_key_duo_jwk(&old.device).unwrap();
    let private_jwk: serde_json::Value = serde_json::from_str(&exported).unwrap();
    let mut private_d = Vec::new();
    collect_private_d(&private_jwk, &mut private_d);
    assert_eq!(
        private_d.len(),
        2,
        "signing and encryption halves each carry a private d"
    );
    for d in &private_d {
        assert!(!d.is_empty());
        let raw = decode_base64(d, URL_ALPHABET);
        assert!(!raw.is_empty());
        assert!(
            !text.contains(d.as_str()),
            "raw private d leaked into history"
        );
        assert!(
            !text.contains(&encode_hex(&raw)),
            "private d bytes (hex) leaked into history"
        );
        assert!(
            !text.contains(&encode_standard_base64(&raw)),
            "private d bytes (base64) leaked into history"
        );
    }
}

#[test]
fn retry_after_history_first_crash_keeps_the_earliest_retired_at() {
    let (dir, before) = fresh();
    // Simulate a crash after the history write of an earlier attempt: the
    // current device is already recorded as retired at 1_500, but the device
    // file was never replaced.
    write_history(
        dir.path(),
        &pb::DeviceHistory {
            retired: vec![pb::RetiredDevice {
                signing: Some(pb::PublicKey::from(&signing_public(&before.device))),
                encryption: Some(pb::PublicKey::from(&encryption_public(&before.device))),
                retired_at_unix_seconds: 1_500,
            }],
        },
    )
    .unwrap();
    let retried = AgentKeys::rotate_device(dir.path(), 2_000, 100).unwrap();
    let loaded = AgentKeys::load(dir.path()).unwrap();
    let old_signing = pb::PublicKey::from(&signing_public(&before.device));
    assert_eq!(loaded.retired.len(), 1);
    let matching: Vec<_> = loaded
        .retired
        .iter()
        .filter(|r| r.signing.as_ref() == Some(&old_signing))
        .collect();
    assert_eq!(matching.len(), 1);
    assert_eq!(matching[0].retired_at_unix_seconds, 1_500);
    assert_ne!(
        signing_public(&retried.device),
        signing_public(&before.device)
    );
    assert_eq!(
        signing_public(&loaded.device),
        signing_public(&retried.device)
    );
    assert_eq!(
        loaded.delegation.issued_at_unix_seconds, 2_000,
        "the new device's window is the retried one"
    );
    assert_eq!(loaded.delegation.not_after_unix_seconds, 2_100);
}

#[test]
fn device_keys_at_includes_retired_until_retired_at() {
    let (dir, first) = fresh();
    let rotated = AgentKeys::rotate_device(dir.path(), 100, 100).unwrap();
    let current = signing_public(&rotated.device);
    let old = signing_public(&first.device);
    assert_eq!(
        device_keys_at(&rotated, 99),
        vec![current.clone(), old.clone()]
    );
    assert_eq!(
        device_keys_at(&rotated, 100),
        vec![current.clone(), old.clone()],
        "retired_at == at is included"
    );
    assert_eq!(device_keys_at(&rotated, 101), vec![current.clone()]);

    // Three keys: K0 retired at 100, K1 retired at 200, current K2.
    let (chain_dir, k0_keys) = fresh();
    let k1_keys = AgentKeys::rotate_device(chain_dir.path(), 100, 100).unwrap();
    let k2_keys = AgentKeys::rotate_device(chain_dir.path(), 200, 100).unwrap();
    let (k0, k1, k2) = (
        signing_public(&k0_keys.device),
        signing_public(&k1_keys.device),
        signing_public(&k2_keys.device),
    );
    assert_eq!(
        device_keys_at(&k2_keys, 100),
        vec![k2.clone(), k0.clone(), k1.clone()]
    );
    assert_eq!(
        device_keys_at(&k2_keys, 150),
        vec![k2.clone(), k1.clone()],
        "only the later retired key is in the window"
    );
    assert_eq!(device_keys_at(&k2_keys, 201), vec![k2]);
}

#[test]
fn current_device_is_always_included() {
    let (dir, first) = fresh();
    let rotated = AgentKeys::rotate_device(dir.path(), 5, 100).unwrap();
    let current = signing_public(&rotated.device);
    let old = signing_public(&first.device);
    assert_eq!(
        device_keys_at(&rotated, i64::MAX),
        vec![current.clone()],
        "the retired key is out of the window"
    );
    assert_eq!(
        device_keys_at(&rotated, i64::MIN),
        vec![current, old],
        "the current device comes first"
    );
}

#[test]
fn retired_equal_to_current_is_deduped() {
    let (_, mut keys) = fresh();
    let current = signing_public(&keys.device);
    keys.retired.push(pb::RetiredDevice {
        signing: Some(pb::PublicKey::from(&current)),
        encryption: None,
        retired_at_unix_seconds: i64::MAX,
    });
    assert_eq!(device_keys_at(&keys, 0), vec![current.clone()]);

    let other = signing_public(&identity_keyfile::generate());
    for _ in 0..2 {
        keys.retired.push(pb::RetiredDevice {
            signing: Some(pb::PublicKey::from(&other)),
            encryption: None,
            retired_at_unix_seconds: i64::MAX,
        });
    }
    assert_eq!(
        device_keys_at(&keys, 0),
        vec![current, other],
        "two identical retired entries count once"
    );
}

#[test]
fn device_keys_at_drops_unreadable_retired_entries() {
    let (_, mut keys) = fresh();
    let current = signing_public(&keys.device);
    let other = signing_public(&identity_keyfile::generate());
    let mut unreadable = pb::PublicKey::from(&other);
    unreadable.key = vec![1, 2, 3];
    keys.retired.push(pb::RetiredDevice {
        signing: None,
        encryption: None,
        retired_at_unix_seconds: i64::MAX,
    });
    keys.retired.push(pb::RetiredDevice {
        signing: Some(unreadable),
        encryption: None,
        retired_at_unix_seconds: i64::MAX,
    });
    assert_eq!(
        device_keys_at(&keys, 0),
        vec![current],
        "an entry with no readable key is dropped, fail closed"
    );
}

#[test]
fn rotate_root_keeps_agent_id_and_signs_with_the_old_root() {
    let (dir, before) = fresh();
    let rotation = AgentKeys::rotate_root(dir.path(), 50).unwrap();
    let transcript = transcripts::root_rotation_transcript(&rotation).unwrap();
    assert_eq!(
        rotation.principal_genesis,
        Some(pb::PublicKey::from(before.agent_id.genesis()))
    );
    assert_eq!(
        rotation.old_root,
        Some(pb::PublicKey::from(&signing_public(&before.root)))
    );
    assert!(verify_p256(
        &signing_public(&before.root),
        &transcript,
        &rotation.signature
    )
    .is_ok());
    assert_eq!(read_principal_id(dir.path()).unwrap(), before.agent_id);

    let loaded = AgentKeys::load(dir.path()).unwrap();
    assert_eq!(
        rotation.new_root,
        Some(pb::PublicKey::from(&signing_public(&loaded.root)))
    );
    assert!(
        !loaded.delegation_is_current(),
        "the delegation is stale until renew"
    );

    let renewed = AgentKeys::renew(dir.path(), 60, 100, false).unwrap();
    assert!(renewed.delegation_is_current());
    let delegation_transcript =
        transcripts::key_delegation_transcript(&renewed.delegation).unwrap();
    assert!(verify_p256(
        &signing_public(&renewed.root),
        &delegation_transcript,
        &renewed.delegation.signature
    )
    .is_ok());
    assert!(
        verify_p256(
            &signing_public(&before.root),
            &delegation_transcript,
            &renewed.delegation.signature
        )
        .is_err(),
        "the old root no longer verifies the renewed delegation"
    );
}

#[test]
fn rotation_chain_survives_load_and_grows_on_each_rotate() {
    let (dir, before) = fresh();
    let first = AgentKeys::rotate_root(dir.path(), 50).unwrap();
    let second = AgentKeys::rotate_root(dir.path(), 60).unwrap();
    let loaded = AgentKeys::load(dir.path()).unwrap();
    assert_eq!(loaded.rotations.len(), 2);
    assert_eq!(loaded.rotations[0], first);
    assert_eq!(loaded.rotations[1], second);
    assert_eq!(
        loaded.rotations[0].old_root,
        Some(pb::PublicKey::from(&signing_public(&before.root)))
    );
    assert_eq!(
        loaded.rotations[1].old_root, loaded.rotations[0].new_root,
        "the chain is continuous"
    );
    assert_eq!(
        loaded.rotations[1].new_root,
        Some(pb::PublicKey::from(&signing_public(&loaded.root)))
    );
    assert_eq!(loaded.rotations[0].issued_at_unix_seconds, 50);
    assert_eq!(loaded.rotations[1].issued_at_unix_seconds, 60);
}

#[test]
fn load_tolerates_a_history_entry_equal_to_the_current_device() {
    let (dir, before) = fresh();
    write_history(
        dir.path(),
        &pb::DeviceHistory {
            retired: vec![pb::RetiredDevice {
                signing: Some(pb::PublicKey::from(&signing_public(&before.device))),
                encryption: None,
                retired_at_unix_seconds: 7,
            }],
        },
    )
    .unwrap();
    let loaded = AgentKeys::load(dir.path()).unwrap();
    assert_eq!(loaded.retired.len(), 1);
    assert_eq!(
        signing_public(&loaded.device),
        signing_public(&before.device)
    );
    assert_eq!(device_keys_at(&loaded, 0).len(), 1);
}

#[test]
fn load_requires_agent_id() {
    let (dir, _) = fresh();
    fs::remove_file(dir.path().join(AGENT_ID_FILE)).unwrap();
    assert!(matches!(
        AgentKeys::load(dir.path()),
        Err(KeyfileError::Missing(_))
    ));
}

#[test]
fn load_in_read_only_dir_falls_back_to_unlocked_read() {
    let (dir, _) = fresh();
    fs::remove_file(dir.path().join(LOCK_FILE)).unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o500)).unwrap();
    let result = AgentKeys::load(dir.path());
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    assert!(
        result.is_ok(),
        "the keys are read when no lock file can be created"
    );
    assert!(
        !dir.path().join(LOCK_FILE).exists(),
        "the read did not create a lock file"
    );
}

#[test]
fn load_during_renew_never_sees_a_torn_state() {
    let (dir, _) = fresh();
    let path = dir.path();
    let done = AtomicBool::new(false);
    let renewals: Result<Vec<AgentKeys>, KeyfileError> = thread::scope(|scope| {
        let reader = scope.spawn(|| {
            let mut loads = 0u32;
            while !done.load(Ordering::SeqCst) {
                if let Err(error) = AgentKeys::load(path) {
                    panic!("load saw a torn state: {error}");
                }
                loads += 1;
            }
            loads
        });
        let renewals = (0..30i64)
            .map(|i| AgentKeys::renew(path, 1_010 + i, 100, true))
            .collect();
        done.store(true, Ordering::SeqCst);
        assert!(
            reader.join().unwrap() > 0,
            "the reader ran during the renewals"
        );
        renewals
    });
    renewals.unwrap();
    assert_eq!(AgentKeys::load(path).unwrap().retired.len(), 30);
}

#[test]
fn two_renewals_do_not_lose_history() {
    for _ in 0..5 {
        let dir = Arc::new(tempdir());
        AgentKeys::init(dir.path(), 1, 100).unwrap();
        let barrier = Arc::new(Barrier::new(8));
        let handles: Vec<_> = (0..8i64)
            .map(|i| {
                let dir = Arc::clone(&dir);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    AgentKeys::renew(dir.path(), 10 + i, 100, true).unwrap();
                })
            })
            .collect();
        for handle in handles {
            handle.join().unwrap();
        }
        let loaded = AgentKeys::load(dir.path()).unwrap();
        assert_eq!(
            loaded.retired.len(),
            8,
            "every concurrent renewal kept its retired device"
        );
        let current = pb::PublicKey::from(&signing_public(&loaded.device));
        for (index, entry) in loaded.retired.iter().enumerate() {
            let signing = entry.signing.as_ref().unwrap();
            assert_ne!(signing, &current, "no retired entry is the current device");
            assert!(
                !loaded.retired[index + 1..]
                    .iter()
                    .any(|other| other.signing.as_ref() == Some(signing)),
                "retired signing keys are distinct"
            );
        }
        assert!(loaded.delegation_is_current());
    }
}
