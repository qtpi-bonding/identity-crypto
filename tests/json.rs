//! proto3-JSON for `Delivery`: the carried form in `_meta`. Every test asserts
//! on exact output or on a specific rejection; nothing here only checks that
//! something parses.

use identity_crypto::jwk_duo::SigningKeyPair;
use identity_crypto::{pb, PublicKey, Timestamp};
use serde_json::{json, Value};

fn pk() -> pb::PublicKey {
    pb::PublicKey::from(&PublicKey::from(&SigningKeyPair::generate()))
}

fn cert(mode: u32) -> pb::DelegationCert {
    let device = Some(pk());
    pb::DelegationCert {
        principal_genesis: if mode == 0 { device.clone() } else { Some(pk()) },
        mode,
        device,
        session: Some(pk()),
        host_genesis: if mode == 1 { Some(pk()) } else { None },
        subject: if mode == 1 { Some("aaaaaaaaaaaaaaaa/i1".into()) } else { None },
        not_before_unix_seconds: 1_792_836_000,
        not_after_unix_seconds: 1_792_836_900,
        signature: vec![7; 64],
    }
}

fn target(room: bool) -> pb::Target {
    pb::Target {
        target: Some(if room {
            pb::target::Target::RoomId("design".into())
        } else {
            pb::target::Target::RecipientId("p256:04".into())
        }),
    }
}

fn signed_message(id: &str, mode: u32) -> pb::SignedMessage {
    let session = cert(mode);
    let signer = if mode == 0 {
        pb::signer_chain::Chain::SelfRooted(pb::SelfRooted { device: None, session: Some(session) })
    } else {
        pb::signer_chain::Chain::HostVouched(pb::HostVouched { host_device: None, session: Some(session) })
    };
    pb::SignedMessage {
        signer: Some(pb::SignerChain { chain: Some(signer) }),
        audience: "room-1".into(),
        nonce: vec![5; 16],
        issued_at_unix_seconds: 1_792_836_000,
        in_reply_to_nonce: None,
        body_type: "type.googleapis.com/identitycrypto.v1.Message".into(),
        body: format!("body of {id}").into_bytes(),
        signature: vec![0xfb; 64],
    }
}

fn full() -> pb::Delivery {
    pb::Delivery {
        delivery_id: "d-1".into(),
        recipient_id: "p256:04".into(),
        recipient_devices: vec![pk(), pk()],
        sequence: u64::MAX,
        attested_at: Some(Timestamp { seconds: 1_792_836_000, nanos: 0 }),
        messages: vec![signed_message("m1", 0), signed_message("m2", 1)],
        via: vec![
            pb::Targets { targets: vec![target(true)] },
            pb::Targets { targets: vec![target(false), target(true)] },
        ],
        signer_device: Some(pb::KeyDelegation {
            principal_genesis: Some(pk()),
            signing_root: Some(pk()),
            delegated: Some(pk()),
            issued_at_unix_seconds: 1,
            not_after_unix_seconds: 2,
            signature: vec![1; 64],
            ..Default::default()
        }),
        signature: vec![0xfb; 64],
        names: vec![pb::PrincipalName { principal_id: format!("p256:{}", "04".repeat(65)), name: "alice".into() }],
    }
}

fn to_json(d: &pb::Delivery) -> Value {
    serde_json::to_value(d).expect("serialize")
}

fn from_json(v: Value) -> Result<pb::Delivery, serde_json::Error> {
    serde_json::from_value(v)
}

#[test]
fn delivery_json_round_trip() {
    let d = full();
    let back = from_json(to_json(&d)).expect("decode");
    assert_eq!(back, d);
}

#[test]
fn delivery_json_field_names_are_camel_case() {
    let v = to_json(&full());
    let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        ["attestedAt", "deliveryId", "messages", "names", "recipientDevices", "recipientId", "sequence", "signature", "signerDevice", "via"]
    );
    assert_eq!(v["sequence"], json!("18446744073709551615"));
    assert!(v["attestedAt"].as_str().unwrap().ends_with('Z'));
}

#[test]
fn message_target_json_uses_the_oneof_field_name() {
    assert_eq!(serde_json::to_value(target(true)).unwrap(), json!({"roomId": "design"}));
    assert_eq!(serde_json::to_value(target(false)).unwrap(), json!({"recipientId": "p256:04"}));
}

#[test]
fn attested_at_serializes_as_rfc3339_with_z() {
    let mut a = full();
    a.attested_at = Some(Timestamp { seconds: 1_792_836_000, nanos: 0 });
    assert_eq!(to_json(&a)["attestedAt"], json!("2026-10-24T10:00:00Z"));

    a.attested_at = Some(Timestamp { seconds: 1_792_836_000, nanos: 120_000_000 });
    assert_eq!(to_json(&a)["attestedAt"], json!("2026-10-24T10:00:00.120Z"));

    a.attested_at = Some(Timestamp { seconds: 1_792_836_000, nanos: 1 });
    assert_eq!(to_json(&a)["attestedAt"], json!("2026-10-24T10:00:00.000000001Z"));
}

#[test]
fn attested_at_offset_form_is_accepted() {
    let mut v = to_json(&full());
    v["attestedAt"] = json!("2026-10-24T11:00:00+01:00");
    let a = from_json(v).expect("offset form parses");
    assert_eq!(a.attested_at, Some(Timestamp { seconds: 1_792_836_000, nanos: 0 }));
}

#[test]
fn attested_at_out_of_range_is_rejected() {
    for bad in ["not a time", "2026-13-24T10:00:00Z", "", "2026-10-24T10:00:00"] {
        let mut v = to_json(&full());
        v["attestedAt"] = json!(bad);
        assert!(from_json(v).is_err(), "{bad:?} must be rejected");
    }

    // A year past 9999 cannot be written as RFC 3339, so it must not parse.
    let mut v = to_json(&full());
    v["attestedAt"] = json!("+10000-01-01T00:00:00Z");
    assert!(from_json(v).is_err(), "year 10000 must be rejected");

    // Seconds outside chrono's range cannot be serialized at all.
    let mut a = full();
    a.attested_at = Some(Timestamp { seconds: i64::MAX, nanos: 0 });
    assert!(serde_json::to_value(&a).is_err(), "seconds out of range must not serialize");

    // The first second past year 9999 must not serialize either.
    let mut a = full();
    a.attested_at = Some(Timestamp { seconds: 253_402_300_800, nanos: 0 });
    assert!(serde_json::to_value(&a).is_err(), "year 10000 must not serialize");

    // Negative nanos cannot serialize; a leap second cannot parse.
    let mut a = full();
    a.attested_at = Some(Timestamp { seconds: 1, nanos: -1 });
    assert!(serde_json::to_value(&a).is_err(), "negative nanos must not serialize");
    let mut v = to_json(&full());
    v["attestedAt"] = json!("2016-12-31T23:59:60Z");
    assert!(from_json(v).is_err(), "leap second must be rejected");
}

#[test]
fn bytes_fields_are_emitted_as_padded_standard_base64() {
    let a = full();
    let v = to_json(&a);
    // 0xfb repeated 64 times, standard base64 with padding.
    let standard = "+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+w==";
    assert_eq!(v["signature"], json!(standard));
    assert_eq!(from_json(v.clone()).expect("standard decodes").signature, vec![0xfb; 64]);

    // Emission is padded standard base64. Decoding is pbjson's (alphabet- and
    // padding-indifferent): equivalent spellings give the same bytes, and the
    // signed transcript binds the parsed bytes, so leniency is not a hole.
    let lenient = standard.replace('+', "-").replace('/', "_");
    let mut w = v.clone();
    w["signature"] = json!(lenient.trim_end_matches('='));
    assert_eq!(from_json(w).expect("lenient spelling decodes").signature, vec![0xfb; 64]);
    let key = v["recipientDevices"][0]["key"].as_str().expect("key string");
    assert!(key.ends_with('='), "65-byte key is emitted padded");
}

#[test]
fn unknown_field_is_rejected() {
    let base = to_json(&full());

    let mut v = base.clone();
    v["extra"] = json!(1);
    assert!(from_json(v).is_err(), "unknown top-level field must reject");

    let mut v = base.clone();
    v["messages"][0]["extra"] = json!("x");
    assert!(from_json(v).is_err(), "unknown field inside a message must reject");

    let mut v = base.clone();
    v["recipientDevices"][0]["extra"] = json!("x");
    assert!(from_json(v).is_err(), "unknown field inside a key must reject");

    let mut v = base.clone();
    v["via"][0]["targets"][0]["extra"] = json!("x");
    assert!(from_json(v).is_err(), "unknown field inside a target must reject");

    let mut v = base;
    v["signerDevice"]["extra"] = json!("x");
    assert!(from_json(v).is_err(), "unknown field inside a delegation must reject");
}

#[test]
fn field_names_accept_camel_and_snake_case() {
    let base = to_json(&full());

    let mut snake = base.clone();
    let obj = snake.as_object_mut().unwrap();
    let v = obj.remove("deliveryId").unwrap();
    obj.insert("delivery_id".into(), v);
    let d = from_json(snake).expect("snake_case name accepted");
    assert_eq!(d, from_json(base.clone()).expect("camel decodes"));

    let mut dup = base;
    dup["delivery_id"] = json!("other");
    assert!(from_json(dup).is_err(), "camelCase and snake_case of one field together must error");
}

#[test]
fn duplicate_field_is_rejected() {
    let text = r#"{"deliveryId":"a","deliveryId":"b"}"#;
    assert!(serde_json::from_str::<pb::Delivery>(text).is_err(), "a duplicate field must error");
}

fn fixed_key(b: u8) -> pb::PublicKey {
    pb::PublicKey { scheme: pb::KeyScheme::EcdsaP256 as i32, key: vec![b; 65] }
}

fn device_history() -> pb::DeviceHistory {
    pb::DeviceHistory {
        retired: vec![pb::RetiredDevice {
            signing: Some(fixed_key(4)),
            encryption: Some(fixed_key(4)),
            retired_at_unix_seconds: 1_700_000_000,
        }],
    }
}

#[test]
fn device_history_json_round_trip() {
    let h = device_history();
    let v = serde_json::to_value(&h).expect("serialize");
    // Exact proto3-JSON: camelCase names, int64 as a string, bytes as padded
    // standard base64 of 65 bytes of 0x04, enums by their full proto name.
    let key = "BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ=";
    assert_eq!(
        v,
        json!({
            "retired": [{
                "signing": { "scheme": "KEY_SCHEME_ECDSA_P256", "key": key },
                "encryption": { "scheme": "KEY_SCHEME_ECDSA_P256", "key": key },
                "retiredAtUnixSeconds": "1700000000"
            }]
        })
    );
    let back: pb::DeviceHistory = serde_json::from_value(v).expect("decode");
    assert_eq!(back, h);
    // An empty history is the empty object, and the field may be absent.
    assert_eq!(serde_json::to_value(pb::DeviceHistory::default()).unwrap(), json!({}));
    assert_eq!(serde_json::from_str::<pb::DeviceHistory>("{}").unwrap(), pb::DeviceHistory::default());
}

#[test]
fn root_rotations_json_round_trip() {
    let rotation = pb::RootRotation {
        principal_genesis: Some(fixed_key(1)),
        old_root: Some(fixed_key(2)),
        new_root: Some(fixed_key(3)),
        issued_at_unix_seconds: 42,
        signature: vec![0xfb; 64],
    };
    let chain = pb::RootRotations { rotations: vec![rotation.clone()] };
    let v = serde_json::to_value(&chain).expect("serialize");
    let key = |b: u8| base64_std(&[b; 65]);
    assert_eq!(
        v,
        json!({
            "rotations": [{
                "principalGenesis": { "scheme": "KEY_SCHEME_ECDSA_P256", "key": key(1) },
                "oldRoot": { "scheme": "KEY_SCHEME_ECDSA_P256", "key": key(2) },
                "newRoot": { "scheme": "KEY_SCHEME_ECDSA_P256", "key": key(3) },
                "issuedAtUnixSeconds": "42",
                "signature": "+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+/v7+w=="
            }]
        })
    );
    let back: pb::RootRotations = serde_json::from_value(v).expect("decode");
    assert_eq!(back, chain);
    assert_eq!(back.rotations[0], rotation);
}

/// Standard padded base64, for the exact-JSON assertions above.
fn base64_std(raw: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in raw.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(A[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}
