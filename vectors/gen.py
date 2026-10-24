#!/usr/bin/env python3
"""Independent generator for identity-crypto's transcript vectors.

Built from the schema's notation (structmux docs/superpowers/specs/
2026-10-11-daemon-mesh-schema-design.md section 3, and the phase 1a spec
section 5). Shares no code with the Rust crate. `cryptography` is used only
to derive public keys from fixed scalars, to validate points, and to sign.

Run from this directory:  .venv/bin/python gen.py
"""
import base64
import hashlib
import json
import struct
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

HERE = Path(__file__).resolve().parent
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
I64_MIN, I64_MAX, U64_MAX = -(2**63), 2**63 - 1, 2**64 - 1

TAGS = {
    "key_challenge": "identitycrypto.key-challenge.v1",
    "principal_rename": "identitycrypto.principal-rename.v1",
    "key_delegation": "identitycrypto.key-delegation.v1",
    "key_revocation": "identitycrypto.key-revocation.v1",
    "root_rotation": "identitycrypto.root-rotation.v1",
    "session_delegation": "identitycrypto.session-delegation.v1",
    "signed_message": "identitycrypto.signed-message.v1",
    "signed_document": "identitycrypto.signed-document.v1",
    "approval": "identitycrypto.approval.v1",
    "peer_revocation": "identitycrypto.peer-revocation.v1",
    "request_digest": "identitycrypto.request-digest.v1",
    "client_request_digest": "identitycrypto.client-request-digest.v1",
    "delivery_attestation": "identitycrypto.delivery-attestation.v1",
}


class VectorError(Exception):
    def __init__(self, variant, field=None):
        super().__init__(variant, field)
        self.variant, self.field = variant, field


def private(i):
    return ec.derive_private_key(i, ec.SECP256R1())


def raw_pub(i):
    return private(i).public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )


def K(i):
    return {"scheme": "3", "key": raw_pub(i).hex()}


OFF_CURVE = {"scheme": "3", "key": "04" + "00" * 64}
ED25519 = {"scheme": "1", "key": raw_pub(1).hex()}
SHORT_KEY = {"scheme": "3", "key": raw_pub(1).hex()[:128]}

# ---- encoding primitives (schema section 3 notation) ----


def tag(name):
    return TAGS[name].encode("ascii") + b"\x00"


def var(b):
    return struct.pack(">I", len(b)) + b


def text(s):
    return var(s.encode("utf-8"))


def i64(v):
    return struct.pack(">q", int(v))


def u64(v):
    return struct.pack(">Q", int(v))


def i32(v):
    return struct.pack(">i", int(v))


def u32(v):
    return struct.pack(">I", int(v))


def key(k, field):
    """KEY := scheme u8 ‖ len(bytes). Validates like the crate's PublicKey."""
    if k is None:
        raise VectorError("MissingField", field)
    scheme = int(k["scheme"])
    if scheme != 3:
        raise VectorError("UnsupportedScheme")
    raw = bytes.fromhex(k["key"])
    if len(raw) != 65:
        raise VectorError("BadLength", "key")
    try:
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw)
    except ValueError:
        raise VectorError("InvalidKey")
    if raw[0] != 4:
        raise VectorError("InvalidKey")
    return bytes([scheme]) + var(raw)


def non_empty(field, b):
    if len(b) == 0:
        raise VectorError("InvalidField", field)


def fixed(field, b, n):
    if len(b) != n:
        raise VectorError("BadLength", field)
    return b


# ---- transcripts ----


def key_challenge(i):
    # The key is converted first, as tests/vectors.rs does before the call.
    new = key(i["new"], "new")
    non_empty("audience", i["audience"].encode())
    nonce = bytes.fromhex(i["nonce"])
    non_empty("nonce", nonce)
    return tag("key_challenge") + text(i["audience"]) + var(nonce) + new


def principal_rename(i):
    p = key(i["principal_genesis"], "principal_genesis")
    nonce = bytes.fromhex(i["nonce"])
    non_empty("nonce", nonce)
    non_empty("new_name", i["new_name"].encode())
    return tag("principal_rename") + var(nonce) + p + text(i["new_name"])


def key_delegation(i):
    p = key(i["principal_genesis"], "principal_genesis")
    root = key(i["signing_root"], "signing_root")
    purpose = int(i["purpose"])
    if purpose not in (2, 3):
        raise VectorError("InvalidField", "purpose")
    delegated = key(i["delegated"], "delegated")
    enc_in = i["delegated_encryption"]
    if purpose == 2 and enc_in is None:
        raise VectorError("MissingField", "delegated_encryption")
    if purpose == 3 and enc_in is not None:
        raise VectorError("InvalidField", "delegated_encryption")
    enc = key(enc_in, "delegated_encryption") if enc_in is not None else None
    keys = [root, delegated] + ([enc] if enc is not None else [])
    if len(set(keys)) != len(keys):
        raise VectorError("NotDistinct", "signing_root, delegated, delegated_encryption")
    out = tag("key_delegation") + p + root + bytes([purpose]) + delegated
    out += b"\x00" if enc is None else b"\x01" + enc
    return out + i64(i["issued_at"]) + i64(i["not_after"])


def key_revocation(i):
    p = key(i["principal_genesis"], "principal_genesis")
    revoked = key(i["revoked"], "revoked")
    by = key(i["revoked_by"], "revoked_by")
    return tag("key_revocation") + p + revoked + by + i64(i["revoked_at"])


def root_rotation(i):
    p = key(i["principal_genesis"], "principal_genesis")
    old = key(i["old_root"], "old_root")
    new = key(i["new_root"], "new_root")
    if old == new:
        raise VectorError("NotDistinct", "old_root, new_root")
    return tag("root_rotation") + p + old + new + i64(i["issued_at"])


def cert_body(c):
    mode = int(c["mode"])
    if mode not in (0, 1):
        raise VectorError("InvalidField", "mode")
    p = key(c["principal_genesis"], "principal_genesis")
    host, subject = c["host_genesis"], c["subject"]
    if mode == 0:
        if host is not None:
            raise VectorError("InvalidField", "host_genesis")
        if subject is not None:
            raise VectorError("InvalidField", "subject")
        host_b, subject_b = b"\x00", b"\x00"
    else:
        host_b = b"\x01" + key(host, "host_genesis")
        if subject is None:
            raise VectorError("MissingField", "subject")
        non_empty("subject", subject.encode())
        subject_b = b"\x01" + text(subject)
    device = key(c["device"], "device")
    session = key(c["session"], "session")
    if device == session:
        raise VectorError("NotDistinct", "device, session")
    return bytes([mode]) + p + host_b + subject_b + device + session + i64(c["not_before"]) + i64(c["not_after"])


def session_delegation(i):
    return tag("session_delegation") + cert_body(i)


def signed_message(i):
    chain = i["chain"]
    if chain is None:
        raise VectorError("MissingField", "signer.chain")
    cert = i["session"]
    if cert is None:
        raise VectorError("MissingField", f"signer.{chain}.session")
    p = key(cert["principal_genesis"], f"signer.{chain}.session.principal_genesis")
    session = key(cert["session"], f"signer.{chain}.session.session")
    non_empty("audience", i["audience"].encode())
    non_empty("body_type", i["body_type"].encode())
    out = tag("signed_message") + p + session + text(i["audience"])
    out += fixed("nonce", bytes.fromhex(i["nonce"]), 16) + i64(i["issued_at"])
    reply = i["in_reply_to_nonce"]
    out += b"\x00" if reply is None else b"\x01" + fixed("in_reply_to_nonce", bytes.fromhex(reply), 16)
    return out + text(i["body_type"]) + var(bytes.fromhex(i["body"]))


def signed_document(i):
    p = key(i["signer_genesis"], "signer_genesis")
    signing = key(i["signing"], "signing")
    non_empty("document_type", i["document_type"].encode())
    return (
        tag("signed_document") + p + signing + text(i["document_type"]) + u64(i["version"])
        + i64(i["issued_at"]) + i64(i["expires_at"]) + var(bytes.fromhex(i["body"]))
    )


def approval(i):
    p = key(i["principal_genesis"], "principal_genesis")
    approval_key = key(i["approval_key"], "approval_key")
    device = key(i["device"], "device")
    if approval_key == device:
        raise VectorError("NotDistinct", "approval_key, device")
    non_empty("audience", i["audience"].encode())
    digest = fixed("request_digest", bytes.fromhex(i["request_digest"]), 32)
    return (
        tag("approval") + p + approval_key + device + text(i["audience"]) + text(i["request_id"])
        + digest + bytes([1 if i["accept"] else 0]) + i64(i["issued_at"])
    )


def peer_revocation(i):
    revoker = key(i["revoker_genesis"], "revoker_genesis")
    approval_key = key(i["approval_key"], "approval_key")
    target = key(i["target_genesis"], "target_genesis")
    revoked = i["revoked"]
    revoked_b = b"\x00" if revoked is None else b"\x01" + key(revoked, "revoked")
    document_id = fixed("document_id", bytes.fromhex(i["document_id"]), 32)
    return tag("peer_revocation") + revoker + approval_key + target + revoked_b + i64(i["issued_at"]) + document_id


def delivery_attestation(i):
    out = tag("delivery_attestation") + u32(len(i["recipient_devices"]))
    for r in i["recipient_devices"]:
        out += key(r, "recipient_devices")
    out += text(i["key_id"]) + u64(i["batch_sequence"])
    at = i["attested_at"]
    if at is None:
        raise VectorError("MissingField", "attested_at")
    nanos = int(at["nanos"])
    if not 0 <= nanos <= 999_999_999:
        raise VectorError("InvalidField", "attested_at.nanos")
    out += i64(at["seconds"]) + i32(nanos) + u32(len(i["messages"]))
    for m in i["messages"]:
        out += text(m["message_id"]) + text(m["room_id"])
        author, cert = m["author_genesis"], m["delegation_cert"]
        if author is None:
            raise VectorError("MissingField", "messages.author_genesis")
        author_bytes = key(author, "messages.author_genesis")
        if cert is None:
            raise VectorError("MissingField", "messages.delegation_cert")
        out += author_bytes + text(m["body_text"])
        out += cert_body(cert) + var(bytes.fromhex(cert["signature"]))
    return out


def request_digest(i):
    # Keys first, as tests/vectors.rs converts them before the call.
    requester = key(i["requester_genesis"], "requester")
    host = key(i["host_genesis"], "host")
    target = key(i["target_genesis"], "target")
    subject = i["subject"]
    if subject is not None:
        non_empty("subject", subject.encode())
    for field in ("instance_id", "action_id", "request_id"):
        non_empty(field, i[field].encode())
    out = tag("request_digest") + requester + host
    out += b"\x00" if subject is None else b"\x01" + text(subject)
    out += text(i["instance_id"]) + text(i["action_id"]) + var(bytes.fromhex(i["parameters"]))
    return out + text(i["request_id"]) + target


def client_request_digest(i):
    # Keys first (requester, host if present, target), as tests/vectors.rs converts them before the call.
    requester = key(i["requester_genesis"], "requester")
    host = None if i["host_genesis"] is None else key(i["host_genesis"], "host")
    target = key(i["target_genesis"], "target")
    resource = i["resource"]
    if resource is not None:
        non_empty("resource_kind", resource["kind"].encode())
        non_empty("resource_id", resource["id"].encode())
    non_empty("message_kind", i["message_kind"].encode())
    non_empty("request_id", i["request_id"].encode())
    out = tag("client_request_digest") + requester
    out += b"\x00" if host is None else b"\x01" + host
    out += b"\x00" if resource is None else b"\x01" + text(resource["kind"]) + text(resource["id"])
    out += text(i["message_kind"]) + var(bytes.fromhex(i["body"]))
    return out + text(i["request_id"]) + target


FUNCTIONS = {f.__name__: f for f in [
    key_challenge, principal_rename, key_delegation, key_revocation, root_rotation, session_delegation,
    signed_message, signed_document, approval, peer_revocation, delivery_attestation, request_digest,
    client_request_digest,
]}

# ---- cases ----


def cert(mode=0, principal=1, device=1, session=2, host=None, subject=None,
         not_before="1700000000", not_after="1700003600"):
    return {
        "principal_genesis": K(principal) if principal else None, "mode": str(mode),
        "device": K(device) if device else None, "session": K(session) if session else None,
        "host_genesis": K(host) if host else None, "subject": subject,
        "not_before": not_before, "not_after": not_after, "signature": "ab" * 64,
    }


CERT1 = cert(mode=1, principal=7, device=8, session=9, host=10, subject="3b6a27bcceb6a42d/i5")


def with_(base, **changes):
    out = dict(base)
    out.update(changes)
    return out


def cases():
    c = []

    def ok(name, function, inp):
        c.append({"name": name, "function": function, "input": inp})

    kc = {"audience": "structmux:3b6a27bcceb6a42d", "nonce": "00112233445566778899aabbccddeeff", "new": K(1)}
    ok("key_challenge", "key_challenge", kc)
    ok("key_challenge non-ascii audience", "key_challenge", with_(kc, audience="structmux:ünïcødé ✓"))
    ok("key_challenge empty audience", "key_challenge", with_(kc, audience=""))
    ok("key_challenge empty nonce", "key_challenge", with_(kc, nonce=""))
    ok("key_challenge ed25519 key", "key_challenge", with_(kc, new=ED25519))
    ok("key_challenge off-curve key", "key_challenge", with_(kc, new=OFF_CURVE))
    ok("key_challenge 64-byte key", "key_challenge", with_(kc, new=SHORT_KEY))

    pr = {"nonce": "0102", "principal_genesis": K(2), "new_name": "reviewer"}
    ok("principal_rename", "principal_rename", pr)
    ok("principal_rename non-ascii", "principal_rename", with_(pr, new_name="Grüße 👋"))
    ok("principal_rename empty name", "principal_rename", with_(pr, new_name=""))
    ok("principal_rename empty nonce", "principal_rename", with_(pr, nonce=""))

    kd = {"principal_genesis": K(1), "signing_root": K(5), "purpose": "2", "delegated": K(2),
          "delegated_encryption": K(3), "issued_at": "1700000000", "not_after": "1702592000"}
    ok("key_delegation device", "key_delegation", kd)
    ok("key_delegation approval", "key_delegation", with_(kd, purpose="3", delegated_encryption=None))
    ok("key_delegation zero not_after (rejected at verification)", "key_delegation", with_(kd, not_after="0"))
    ok("key_delegation extremes", "key_delegation", with_(kd, issued_at=str(I64_MIN), not_after=str(I64_MAX)))
    ok("key_delegation purpose root", "key_delegation", with_(kd, purpose="1"))
    ok("key_delegation purpose unspecified", "key_delegation", with_(kd, purpose="0"))
    ok("key_delegation device without encryption", "key_delegation", with_(kd, delegated_encryption=None))
    ok("key_delegation approval with encryption", "key_delegation", with_(kd, purpose="3"))
    ok("key_delegation genesis is root", "key_delegation", with_(kd, signing_root=K(1)))
    ok("key_delegation delegated is root", "key_delegation", with_(kd, delegated=K(5)))
    ok("key_delegation encryption is delegated", "key_delegation", with_(kd, delegated_encryption=K(2)))
    ok("key_delegation missing principal", "key_delegation", with_(kd, principal_genesis=None))

    kr = {"principal_genesis": K(1), "revoked": K(2), "revoked_by": K(5), "revoked_at": "1700000000"}
    ok("key_revocation", "key_revocation", kr)
    ok("key_revocation self", "key_revocation", with_(kr, revoked_by=K(2)))
    ok("key_revocation negative time", "key_revocation", with_(kr, revoked_at="-1"))
    ok("key_revocation missing revoked", "key_revocation", with_(kr, revoked=None))

    rr = {"principal_genesis": K(1), "old_root": K(5), "new_root": K(4), "issued_at": "1700000000"}
    ok("root_rotation", "root_rotation", rr)
    ok("root_rotation first", "root_rotation", with_(rr, old_root=K(1)))
    ok("root_rotation same root", "root_rotation", with_(rr, new_root=K(5)))

    ok("session_delegation mode 0 own device", "session_delegation", cert())
    ok("session_delegation mode 0", "session_delegation", cert(principal=5))
    ok("session_delegation mode 1", "session_delegation", CERT1)
    ok("session_delegation mode 1 non-ascii subject", "session_delegation", with_(CERT1, subject="sübject/ñ"))
    ok("session_delegation extremes", "session_delegation", cert(not_before=str(I64_MIN), not_after=str(I64_MAX)))
    ok("session_delegation mode 2", "session_delegation", with_(cert(), mode="2"))
    ok("session_delegation mode 0 with host", "session_delegation", with_(cert(), host_genesis=K(10)))
    ok("session_delegation mode 0 with subject", "session_delegation", with_(cert(), subject="x"))
    ok("session_delegation mode 0 with empty subject", "session_delegation", with_(cert(), subject=""))
    ok("session_delegation mode 1 without host", "session_delegation", with_(CERT1, host_genesis=None))
    ok("session_delegation mode 1 without subject", "session_delegation", with_(CERT1, subject=None))
    ok("session_delegation mode 1 empty subject", "session_delegation", with_(CERT1, subject=""))
    ok("session_delegation session is device", "session_delegation", cert(session=1))
    ok("session_delegation missing session", "session_delegation", with_(cert(), session=None))

    sm = {"chain": "self_rooted", "session": cert(), "audience": "structmux-fleet:3b6a27bcceb6a42d",
          "nonce": "0f" * 16, "issued_at": "1700000000", "in_reply_to_nonce": None,
          "body_type": "type.googleapis.com/structmux.v1.FleetRequest", "body": "0a0b0c"}
    ok("signed_message self-rooted", "signed_message", sm)
    ok("signed_message host-vouched", "signed_message", with_(sm, chain="host_vouched", session=CERT1))
    ok("signed_message reply", "signed_message", with_(sm, in_reply_to_nonce="1e" * 16))
    ok("signed_message empty body", "signed_message", with_(sm, body=""))
    ok("signed_message non-ascii audience", "signed_message", with_(sm, audience="aüd"))
    ok("signed_message extremes", "signed_message", with_(sm, issued_at=str(I64_MIN)))
    ok("signed_message no chain", "signed_message", with_(sm, chain=None))
    ok("signed_message no session", "signed_message", with_(sm, session=None))
    ok("signed_message 15-byte nonce", "signed_message", with_(sm, nonce="0f" * 15))
    ok("signed_message empty reply nonce", "signed_message", with_(sm, in_reply_to_nonce=""))
    ok("signed_message empty audience", "signed_message", with_(sm, audience=""))
    ok("signed_message empty body_type", "signed_message", with_(sm, body_type=""))

    sd = {"signer_genesis": K(1), "signing": K(4), "document_type": "type.googleapis.com/structmux.v1.OwnerDocument",
          "version": "3", "issued_at": "1700000000", "expires_at": "1707776000", "body": "0102"}
    ok("signed_document", "signed_document", sd)
    ok("signed_document max version zero expires_at (rejected at verification)", "signed_document", with_(sd, version=str(U64_MAX), expires_at="0"))
    ok("signed_document empty type", "signed_document", with_(sd, document_type=""))

    ap = {"principal_genesis": K(1), "approval_key": K(11), "device": K(12), "audience": "structmux:3b6a27bcceb6a42d",
          "request_id": "r4", "request_digest": "22" * 32, "accept": True, "issued_at": "1700000000"}
    ok("approval accept", "approval", ap)
    ok("approval reject", "approval", with_(ap, accept=False))
    ok("approval 31-byte digest", "approval", with_(ap, request_digest="22" * 31))
    ok("approval key is device", "approval", with_(ap, device=K(11)))
    ok("approval empty audience", "approval", with_(ap, audience=""))

    pv = {"revoker_genesis": K(1), "approval_key": K(11), "target_genesis": K(13), "revoked": None,
          "issued_at": "1700000000", "document_id": "33" * 32}
    ok("peer_revocation whole principal", "peer_revocation", pv)
    ok("peer_revocation one key", "peer_revocation", with_(pv, revoked=K(14)))
    ok("peer_revocation missing target", "peer_revocation", with_(pv, target_genesis=None))
    ok("peer_revocation 31-byte document id", "peer_revocation", with_(pv, document_id="33" * 31))

    def message(author=None, delegation=None, body="hi"):
        return {"message_id": "m1", "room_id": "!room", "author_genesis": author, "body_text": body,
                "delegation_cert": delegation}

    da = {"recipient_devices": [K(15), K(16)], "key_id": "mm-key-1", "batch_sequence": "7",
          "attested_at": {"seconds": "1700000000", "nanos": "123456789"},
          "messages": [message(author=K(2), delegation=CERT1), message(author=K(7), delegation=CERT1)]}
    ok("delivery_attestation empty", "delivery_attestation",
       {"recipient_devices": [], "key_id": "", "batch_sequence": "0",
        "attested_at": {"seconds": "0", "nanos": "0"}, "messages": []})
    ok("delivery_attestation full", "delivery_attestation", da)
    ok("delivery_attestation non-ascii body", "delivery_attestation",
       with_(da, messages=[message(author=K(2), delegation=CERT1, body="héllo wörld ✓")]))
    ok("delivery_attestation max sequence", "delivery_attestation",
       with_(da, batch_sequence=str(U64_MAX), attested_at={"seconds": str(I64_MIN), "nanos": "999999999"}))
    ok("delivery_attestation no timestamp", "delivery_attestation", with_(da, attested_at=None))
    ok("delivery_attestation nanos too big", "delivery_attestation",
       with_(da, attested_at={"seconds": "0", "nanos": "1000000000"}))
    ok("delivery_attestation negative nanos", "delivery_attestation",
       with_(da, attested_at={"seconds": "0", "nanos": "-1"}))
    ok("delivery_attestation author missing", "delivery_attestation",
       with_(da, messages=[message(delegation=CERT1)]))
    ok("delivery_attestation cert missing", "delivery_attestation",
       with_(da, messages=[message(author=K(7))]))
    ok("delivery_attestation author and cert missing", "delivery_attestation",
       with_(da, messages=[message()]))
    ok("delivery_attestation off-curve recipient", "delivery_attestation",
       with_(da, recipient_devices=[OFF_CURVE]))
    ok("delivery_attestation cert with empty signature", "delivery_attestation",
       with_(da, messages=[message(author=K(7), delegation=with_(CERT1, signature=""))]))
    ok("delivery_attestation cert with DER-length signature", "delivery_attestation",
       with_(da, messages=[message(author=K(7), delegation=with_(CERT1, signature="cd" * 71))]))

    rd = {"requester_genesis": K(7), "host_genesis": K(10), "subject": "3b6a27bcceb6a42d/i5",
          "instance_id": "3b6a27bcceb6a42d/i5", "action_id": "send_prompt", "parameters": "0a0568656c6c6f",
          "request_id": "r4", "target_genesis": K(10)}
    ok("request_digest agent", "request_digest", rd)
    ok("request_digest human, no subject", "request_digest", with_(rd, requester_genesis=K(1), subject=None))
    ok("request_digest empty parameters non-ascii action", "request_digest", with_(rd, parameters="", action_id="ação"))
    ok("request_digest empty subject", "request_digest", with_(rd, subject=""))
    ok("request_digest empty instance", "request_digest", with_(rd, instance_id=""))
    ok("request_digest empty action", "request_digest", with_(rd, action_id=""))
    ok("request_digest empty request id", "request_digest", with_(rd, request_id=""))
    ok("request_digest off-curve host", "request_digest", with_(rd, host_genesis=OFF_CURVE))

    crd = {"requester_genesis": K(1), "host_genesis": K(10), "resource": {"kind": "instance", "id": "3b6a27bcceb6a42d/i5"},
           "message_kind": "start_instance", "body": "0a0568656c6c6f", "request_id": "r7", "target_genesis": K(11)}
    ok("client_request_digest hosted client with resource", "client_request_digest", crd)
    ok("client_request_digest hostless client", "client_request_digest", with_(crd, host_genesis=None))
    ok("client_request_digest no resource", "client_request_digest", with_(crd, resource=None))
    ok("client_request_digest hostless and no resource", "client_request_digest",
       with_(crd, host_genesis=None, resource=None))
    ok("client_request_digest empty body", "client_request_digest", with_(crd, body=""))
    ok("client_request_digest long body", "client_request_digest", with_(crd, body="ab" * 300))
    ok("client_request_digest non-ascii message kind", "client_request_digest", with_(crd, message_kind="ação"))
    ok("client_request_digest empty resource kind", "client_request_digest",
       with_(crd, resource={"kind": "", "id": "x"}))
    ok("client_request_digest empty resource id", "client_request_digest",
       with_(crd, resource={"kind": "instance", "id": ""}))
    ok("client_request_digest empty message kind", "client_request_digest", with_(crd, message_kind=""))
    ok("client_request_digest empty request id", "client_request_digest", with_(crd, request_id=""))
    return c


def run_cases():
    out = []
    for case in cases():
        f = FUNCTIONS[case["function"]]
        try:
            case["expected_hex"] = f(case["input"]).hex()
        except VectorError as e:
            case["error"] = {"variant": e.variant, "field": e.field}
        out.append(case)
    functions_with_valid = {c["function"] for c in out if "expected_hex" in c}
    assert functions_with_valid == set(FUNCTIONS), set(FUNCTIONS) - functions_with_valid
    return out


def parse_principal(s, canonical):
    """Mirror of PrincipalId::parse / parse_canonical semantics."""
    if len(s) < 5 or not s[:5].isascii() or s[:5].lower() != "p256:":
        return {"error": "MalformedPrincipal"}
    rest = s[5:]
    if len(rest.encode()) != 130:
        return {"error": "MalformedPrincipal"}
    try:
        raw = bytes.fromhex(rest)
    except ValueError:
        return {"error": "MalformedPrincipal"}
    try:
        if raw[0] != 4:
            raise ValueError
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw)
    except ValueError:
        return {"error": "InvalidKey"}
    text_form = "p256:" + raw.hex()
    if canonical and text_form != s:
        return {"error": "NonCanonicalPrincipal"}
    return {"ok": text_form}


def principals():
    valid = []
    for i in (1, 2, 3):
        raw = raw_pub(i)
        valid.append({
            "genesis_hex": raw.hex(),
            "principal_id": "p256:" + raw.hex(),
            "short_id": hashlib.sha256(raw).digest()[:8].hex(),
        })
    h = raw_pub(1).hex()
    compressed = private(1).public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint
    ).hex()
    inputs = [
        "p256:" + h.upper(), "P256:" + h, "p384:" + h, "p256:" + h[:129], "p256:" + h + "0",
        "p256:04" + "00" * 64, "p256:" + compressed, "p256:00",
    ]
    invalid = [{"input": s, "parse": parse_principal(s, False), "parse_canonical": parse_principal(s, True)}
               for s in inputs]
    return {"valid": valid, "invalid": invalid}


def signatures(transcript_cases):
    wanted = ["key_challenge", "session_delegation mode 1", "signed_message self-rooted"]
    by_name = {c["name"]: c for c in transcript_cases}
    out = []
    for name in wanted:
        message = bytes.fromhex(by_name[name]["expected_hex"])
        der = private(1).sign(message, ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
        r, s = decode_dss_signature(der)
        out.append({
            "name": name,
            "key_hex": raw_pub(1).hex(),
            "message_hex": message.hex(),
            "signature_hex": (r.to_bytes(32, "big") + s.to_bytes(32, "big")).hex(),
            "high_s_hex": (r.to_bytes(32, "big") + (N - s).to_bytes(32, "big")).hex(),
        })
    return {"cases": out}


def b64url(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def thumbprint(raw):
    """RFC 7638 thumbprint of the EC JWK {crv, kty, x, y} for an uncompressed P-256 point."""
    assert len(raw) == 65 and raw[0] == 0x04
    canonical = '{"crv":"P-256","kty":"EC","x":"%s","y":"%s"}' % (b64url(raw[1:33]), b64url(raw[33:65]))
    return b64url(hashlib.sha256(canonical.encode("utf-8")).digest())


def thumbprints():
    # draft-ietf-jose-hpke-encrypt-22 Appendix A.13 (HPKE-7 key): a published known answer.
    a13_x = "z860carZ9CSxTjXo7MK65h_TaZX7ipi2iUh_Bh-VP54"
    a13_y = "i9X0v8PwcNgbsoMhAz-_W2OPaFU--BQAgWVzJVOfedo"
    a13_raw = b"\x04" + base64.urlsafe_b64decode(a13_x + "==") + base64.urlsafe_b64decode(a13_y + "==")
    a13 = {"name": "rfc draft a13 hpke-7 key", "key_hex": a13_raw.hex(),
           "thumbprint": thumbprint(a13_raw)}
    assert a13["thumbprint"] == "YGdLPiZno0vV3kJKu4kEMQEjK3_upFF2D_lFDf1FFwk"
    cases = [a13]
    for name, i in (("scalar 1", 1), ("scalar 2", 2), ("scalar 3", 3),
                    ("scalar large", 0x5EED5EED5EED5EED5EED5EED5EED5EED5EED5EED5EED5EED5EED5EED5EED5EED % N)):
        raw = raw_pub(i)
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw)  # on-curve check
        cases.append({"name": name, "key_hex": raw.hex(), "thumbprint": thumbprint(raw)})
    return {"cases": cases}


def write(name, data):
    (HERE / name).write_text(json.dumps(data, sort_keys=True, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def main():
    transcript_cases = run_cases()
    write("transcripts.json", {"cases": transcript_cases})
    write("principals.json", principals())
    write("signatures.json", signatures(transcript_cases))
    write("thumbprints.json", thumbprints())


if __name__ == "__main__":
    main()
