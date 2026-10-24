//! Checks the crate against vectors from an independent implementation
//! (`vectors/gen.py`). A mismatch is a bug in one of the two; decide it
//! against the schema, never by regenerating the file to match Rust.

use identity_crypto::transcripts::*;
use identity_crypto::{pb, verify_p256, Error, PrincipalId, PublicKey, Result, ShortId};
use serde_json::Value;

fn load(name: &str) -> Value {
    let path = format!("{}/vectors/{name}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap()
}

fn s(v: &Value) -> String {
    v.as_str().unwrap_or_else(|| panic!("expected string, got {v}")).to_string()
}
fn int<T: std::str::FromStr>(v: &Value) -> T
where
    T::Err: std::fmt::Debug,
{
    s(v).parse().unwrap()
}
fn bytes(v: &Value) -> Vec<u8> {
    hex::decode(s(v)).unwrap()
}
fn key(v: &Value) -> Option<pb::PublicKey> {
    (!v.is_null()).then(|| pb::PublicKey { scheme: int(&v["scheme"]), key: bytes(&v["key"]) })
}
fn opt_str(v: &Value) -> Option<String> {
    (!v.is_null()).then(|| s(v))
}
fn cert(v: &Value) -> Option<pb::DelegationCert> {
    (!v.is_null()).then(|| pb::DelegationCert {
        principal_genesis: key(&v["principal_genesis"]),
        mode: int(&v["mode"]),
        device: key(&v["device"]),
        session: key(&v["session"]),
        host_genesis: key(&v["host_genesis"]),
        subject: opt_str(&v["subject"]),
        not_before_unix_seconds: int(&v["not_before"]),
        not_after_unix_seconds: int(&v["not_after"]),
        signature: bytes(&v["signature"]),
    })
}

fn run(function: &str, i: &Value) -> Result<Vec<u8>> {
    match function {
        "key_challenge" => {
            let new = PublicKey::try_from(&key(&i["new"]).unwrap())?;
            key_challenge_transcript(&s(&i["audience"]), &bytes(&i["nonce"]), &new)
        }
        "principal_rename" => {
            let p = PrincipalId::from_genesis(PublicKey::try_from(&key(&i["principal_genesis"]).unwrap())?);
            principal_rename_transcript(&bytes(&i["nonce"]), &p, &s(&i["new_name"]))
        }
        "key_delegation" => key_delegation_transcript(&pb::KeyDelegation {
            principal_genesis: key(&i["principal_genesis"]),
            signing_root: key(&i["signing_root"]),
            purpose: int(&i["purpose"]),
            delegated: key(&i["delegated"]),
            delegated_encryption: key(&i["delegated_encryption"]),
            issued_at_unix_seconds: int(&i["issued_at"]),
            not_after_unix_seconds: int(&i["not_after"]),
            signature: vec![],
        }),
        "key_revocation" => key_revocation_transcript(&pb::KeyRevocation {
            principal_genesis: key(&i["principal_genesis"]),
            revoked: key(&i["revoked"]),
            revoked_by: key(&i["revoked_by"]),
            revoked_at_unix_seconds: int(&i["revoked_at"]),
            signature: vec![],
        }),
        "root_rotation" => root_rotation_transcript(&pb::RootRotation {
            principal_genesis: key(&i["principal_genesis"]),
            old_root: key(&i["old_root"]),
            new_root: key(&i["new_root"]),
            issued_at_unix_seconds: int(&i["issued_at"]),
            signature: vec![],
        }),
        "session_delegation" => session_delegation_transcript(&cert(i).unwrap()),
        "signed_message" => {
            let session = cert(&i["session"]);
            let chain = match i["chain"].as_str() {
                None => None,
                Some("self_rooted") => {
                    Some(pb::signer_chain::Chain::SelfRooted(pb::SelfRooted { device: None, session }))
                }
                Some("host_vouched") => {
                    Some(pb::signer_chain::Chain::HostVouched(pb::HostVouched { host_device: None, session }))
                }
                Some(other) => panic!("unknown chain {other}"),
            };
            signed_message_transcript(&pb::SignedMessage {
                signer: Some(pb::SignerChain { chain }),
                audience: s(&i["audience"]),
                nonce: bytes(&i["nonce"]),
                issued_at_unix_seconds: int(&i["issued_at"]),
                in_reply_to_nonce: (!i["in_reply_to_nonce"].is_null()).then(|| bytes(&i["in_reply_to_nonce"])),
                body_type: s(&i["body_type"]),
                body: bytes(&i["body"]),
                signature: vec![],
            })
        }
        "signed_document" => signed_document_transcript(&pb::SignedDocument {
            signer_genesis: key(&i["signer_genesis"]),
            signing: key(&i["signing"]),
            document_type: s(&i["document_type"]),
            version: int(&i["version"]),
            issued_at_unix_seconds: int(&i["issued_at"]),
            expires_at_unix_seconds: int(&i["expires_at"]),
            body: bytes(&i["body"]),
            signature: vec![],
            signer_rotations: vec![],
        }),
        "approval" => approval_transcript(&pb::Approval {
            principal_genesis: key(&i["principal_genesis"]),
            approval_key: key(&i["approval_key"]),
            device: key(&i["device"]),
            audience: s(&i["audience"]),
            request_id: s(&i["request_id"]),
            request_digest: bytes(&i["request_digest"]),
            accept: i["accept"].as_bool().unwrap(),
            issued_at_unix_seconds: int(&i["issued_at"]),
            signature: vec![],
        }),
        "peer_revocation" => peer_revocation_transcript(&pb::PeerRevocation {
            revoker_genesis: key(&i["revoker_genesis"]),
            approval_key: key(&i["approval_key"]),
            target_genesis: key(&i["target_genesis"]),
            revoked: key(&i["revoked"]),
            issued_at_unix_seconds: int(&i["issued_at"]),
            signature: vec![],
            document_id: bytes(&i["document_id"]),
        }),
        "delivery_attestation" => delivery_attestation_transcript(&pb::DeliveryAttestation {
            recipient_devices: i["recipient_devices"].as_array().unwrap().iter().map(|k| key(k).unwrap()).collect(),
            key_id: s(&i["key_id"]),
            batch_sequence: int(&i["batch_sequence"]),
            attested_at: (!i["attested_at"].is_null()).then(|| identity_crypto::Timestamp {
                seconds: int(&i["attested_at"]["seconds"]),
                nanos: int(&i["attested_at"]["nanos"]),
            }),
            messages: i["messages"]
                .as_array()
                .unwrap()
                .iter()
                .map(|m| pb::AttestedMessage {
                    message_id: s(&m["message_id"]),
                    room_id: s(&m["room_id"]),
                    body_text: s(&m["body_text"]),
                    delegation_cert: cert(&m["delegation_cert"]),
                    author_genesis: key(&m["author_genesis"]),
                })
                .collect(),
            signature: vec![],
        }),
        "request_digest" => {
            let pid = |f: &str| PublicKey::try_from(&key(&i[f]).unwrap()).map(PrincipalId::from_genesis);
            let (requester, host, target) = (pid("requester_genesis")?, pid("host_genesis")?, pid("target_genesis")?);
            let subject = opt_str(&i["subject"]);
            let (instance_id, action_id, request_id) = (s(&i["instance_id"]), s(&i["action_id"]), s(&i["request_id"]));
            let parameters = bytes(&i["parameters"]);
            request_digest_transcript(&RequestDigestInput {
                requester: &requester, host: &host, subject: subject.as_deref(), instance_id: &instance_id,
                action_id: &action_id, parameters: &parameters, request_id: &request_id, target: &target,
            })
        }
        "client_request_digest" => {
            let pid = |f: &str| PublicKey::try_from(&key(&i[f]).unwrap()).map(PrincipalId::from_genesis);
            let requester = pid("requester_genesis")?;
            let host = if i["host_genesis"].is_null() { None } else { Some(pid("host_genesis")?) };
            let target = pid("target_genesis")?;
            let resource = (!i["resource"].is_null()).then(|| (s(&i["resource"]["kind"]), s(&i["resource"]["id"])));
            let (message_kind, request_id) = (s(&i["message_kind"]), s(&i["request_id"]));
            let body = bytes(&i["body"]);
            client_request_digest_transcript(&ClientRequestDigestInput {
                requester: &requester, host: host.as_ref(),
                resource: resource.as_ref().map(|(k, id)| (k.as_str(), id.as_str())),
                message_kind: &message_kind, body: &body, request_id: &request_id, target: &target,
            })
        }
        other => panic!("unknown function {other}"),
    }
}

fn variant(e: &Error) -> (&'static str, Option<&'static str>) {
    match e {
        Error::UnsupportedScheme(_) => ("UnsupportedScheme", None),
        Error::InvalidKey(_) => ("InvalidKey", None),
        Error::NonCanonicalPrincipal => ("NonCanonicalPrincipal", None),
        Error::MalformedPrincipal(_) => ("MalformedPrincipal", None),
        Error::MalformedShortId(_) => ("MalformedShortId", None),
        Error::BadLength { field, .. } => ("BadLength", Some(*field)),
        Error::ScalarOutOfRange { field, .. } => ("ScalarOutOfRange", Some(*field)),
        Error::MissingField(f) => ("MissingField", Some(*f)),
        Error::InvalidField { field, .. } => ("InvalidField", Some(*field)),
        Error::NotDistinct(f) => ("NotDistinct", Some(*f)),
        Error::EmptySignature => ("EmptySignature", None),
        Error::BadSignature => ("BadSignature", None),
        _ => ("Unknown", None),
    }
}

#[test]
fn transcripts_match_the_independent_generator() {
    let cases = load("transcripts.json");
    let mut checked = 0;
    for case in cases["cases"].as_array().unwrap() {
        let name = s(&case["name"]);
        let got = run(&s(&case["function"]), &case["input"]);
        if let Some(want) = case.get("expected_hex") {
            assert_eq!(hex::encode(got.unwrap_or_else(|e| panic!("{name}: {e}"))), s(want), "{name}");
        } else {
            let err = got.expect_err(&name);
            let want = &case["error"];
            let (v, f) = variant(&err);
            assert_eq!(v, s(&want["variant"]), "{name}: {err}");
            assert_eq!(f.map(str::to_string), opt_str(&want["field"]), "{name}: {err}");
        }
        checked += 1;
    }
    assert_eq!(checked, 100, "transcripts.json case count changed");
}

#[test]
fn principals_match_the_independent_generator() {
    let p = load("principals.json");
    for v in p["valid"].as_array().unwrap() {
        let genesis = PublicKey::p256(&bytes(&v["genesis_hex"])).unwrap();
        let id = PrincipalId::from_genesis(genesis);
        assert_eq!(id.to_string(), s(&v["principal_id"]));
        assert_eq!(PrincipalId::parse_canonical(&s(&v["principal_id"])).unwrap(), id);
        assert_eq!(id.short_id().to_string(), s(&v["short_id"]));
        assert_eq!(ShortId::parse_canonical(&s(&v["short_id"])).unwrap(), id.short_id());
    }
    for v in p["invalid"].as_array().unwrap() {
        let input = s(&v["input"]);
        for (which, result) in [
            ("parse", PrincipalId::parse(&input)),
            ("parse_canonical", PrincipalId::parse_canonical(&input)),
        ] {
            let want = &v[which];
            match (want.get("ok"), result) {
                (Some(ok), Ok(id)) => assert_eq!(id.to_string(), s(ok), "{which} {input}"),
                (None, Err(e)) => assert_eq!(variant(&e).0, s(&want["error"]), "{which} {input}"),
                (w, r) => panic!("{which} {input}: want {w:?}, got {r:?}"),
            }
        }
    }
}

#[test]
fn signatures_from_an_independent_signer_verify_in_both_s_forms() {
    let sigs = load("signatures.json");
    for case in sigs["cases"].as_array().unwrap() {
        let name = s(&case["name"]);
        let k = PublicKey::p256(&bytes(&case["key_hex"])).unwrap();
        let msg = bytes(&case["message_hex"]);
        for field in ["signature_hex", "high_s_hex"] {
            let v = verify_p256(&k, &msg, &bytes(&case[field])).unwrap_or_else(|e| panic!("{name} {field}: {e}"));
            assert!(v.covers(&msg));
        }
        let mut tampered = msg.clone();
        tampered[0] ^= 1;
        assert_eq!(verify_p256(&k, &tampered, &bytes(&case["signature_hex"])).unwrap_err(), Error::BadSignature);
    }
}
