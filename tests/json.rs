//! proto3-JSON for the attestation types (`DeliveryAttestation` and
//! `AttestedMessage`): the carried form in `_meta`. Every test asserts on
//! exact output or on a specific rejection; nothing here only checks that
//! something parses.

use identity_crypto::jwk_duo::SigningKeyPair;
use identity_crypto::transcripts::delivery_attestation_transcript;
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

fn message(id: &str, mode: u32) -> pb::AttestedMessage {
    pb::AttestedMessage {
        message_id: id.into(),
        room_id: "room-1".into(),
        body_text: format!("body of {id}"),
        author_genesis: Some(pk()),
        delegation_cert: Some(cert(mode)),
    }
}

fn full() -> pb::DeliveryAttestation {
    pb::DeliveryAttestation {
        key_id: "p256:thumb".into(),
        batch_sequence: 7,
        attested_at: Some(Timestamp { seconds: 1_792_836_000, nanos: 0 }),
        messages: vec![message("m1", 0), message("m2", 1)],
        signature: vec![0xfb; 64],
        recipient_devices: vec![pk(), pk()],
    }
}

fn to_json(a: &pb::DeliveryAttestation) -> Value {
    serde_json::to_value(a).expect("serialize")
}

fn from_json(v: Value) -> Result<pb::DeliveryAttestation, serde_json::Error> {
    serde_json::from_value(v)
}

fn transcript(a: &pb::DeliveryAttestation) -> Vec<u8> {
    delivery_attestation_transcript(a).expect("transcript")
}

#[test]
fn attestation_json_round_trip() {
    let a = full();
    let back = from_json(to_json(&a)).expect("decode");
    assert_eq!(back, a);
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

    // Nanos outside 0..1e9 are rejected by the signed transcript, which is
    // the only path that signs or verifies them.
    let mut a = full();
    a.attested_at = Some(Timestamp { seconds: 1, nanos: 1_000_000_000 });
    assert!(delivery_attestation_transcript(&a).is_err(), "nanos out of range must reject");

    // A missing attestedAt must reject in the transcript, not default to zero.
    let mut a = full();
    a.attested_at = None;
    assert!(delivery_attestation_transcript(&a).is_err(), "missing attestedAt must reject");
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
    // pbjson decodes either alphabet, padded or not, to the same bytes.
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

    let mut v = base;
    v["messages"][0]["delegationCert"]["extra"] = json!("x");
    assert!(from_json(v).is_err(), "unknown field inside a cert must reject");
}

#[test]
fn field_names_accept_camel_and_snake_case() {
    let base = to_json(&full());
    assert!(base.get("keyId").is_some(), "output uses the camelCase name");

    let mut snake = base.clone();
    let obj = snake.as_object_mut().unwrap();
    let v = obj.remove("keyId").unwrap();
    obj.insert("key_id".into(), v);
    let a = from_json(snake).expect("snake_case name accepted");
    assert_eq!(a, from_json(base.clone()).expect("camel decodes"));

    let mut dup = base.clone();
    dup["key_id"] = json!("other");
    assert!(from_json(dup).is_err(), "camelCase and snake_case of one field together must error");

    let text = r#"{"keyId":"a","keyId":"b"}"#;
    assert!(serde_json::from_str::<pb::DeliveryAttestation>(text).is_err(), "a duplicate field must error");
}

#[test]
fn old_verification_outcome_field_is_rejected() {
    let mut v = to_json(&full());
    v["messages"][0]["verificationOutcome"] = json!("DELEGATED_KEY");
    assert!(from_json(v).is_err(), "verificationOutcome is an unknown field after A1");
}

#[test]
fn json_round_trip_keeps_the_transcript() {
    let mut empty_messages = full();
    empty_messages.messages.clear();
    let mut seq_zero = full();
    seq_zero.batch_sequence = 0;
    let mut empty_key = full();
    empty_key.key_id = String::new();
    let mut empty_devices = full();
    empty_devices.recipient_devices.clear();

    let cases = [
        ("all fields set", full()),
        ("empty messages", empty_messages),
        ("batch_sequence 0", seq_zero),
        ("empty key_id", empty_key),
        ("no recipient devices", empty_devices),
    ];
    for (name, original) in cases {
        let decoded = from_json(to_json(&original)).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(decoded, original, "{name}: value round trip");
        assert_eq!(transcript(&decoded), transcript(&original), "{name}: transcript");
    }
}
