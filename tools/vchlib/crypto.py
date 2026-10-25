# SPDX-License-Identifier: Apache-2.0
"""Ed25519 detached signatures over canonical JSON (decisions D11).

Fingerprint format [H]: "ed25519:SHA256:" + unpadded standard base64 of sha256(raw
32-byte public key). It resembles, but is NOT byte-compatible with, OpenSSH
fingerprints (OpenSSH hashes the SSH wire encoding of the key).
"""
from __future__ import annotations

import base64
import hashlib
import pathlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .canonical import jcs, signing_payload

ALG = "ed25519"


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def unb64(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"), validate=True)


def fingerprint(raw_public_key: bytes) -> str:
    digest = hashlib.sha256(raw_public_key).digest()
    return "ed25519:SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def raw_public(key: Ed25519PrivateKey | Ed25519PublicKey) -> bytes:
    pub = key.public_key() if isinstance(key, Ed25519PrivateKey) else key
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def load_private_pem(path: pathlib.Path) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError(f"{path}: not an Ed25519 private key")
    return key


def new_private_pem() -> bytes:
    return Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def sign_bytes(key: Ed25519PrivateKey, data: bytes) -> str:
    return b64(key.sign(data))


def verify_bytes(raw_public_key_b64: str, data: bytes, signature_b64: str) -> bool:
    try:
        pub = Ed25519PublicKey.from_public_bytes(unb64(raw_public_key_b64))
        pub.verify(unb64(signature_b64), data)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def sign_document(doc: dict, signer: str, key: Ed25519PrivateKey) -> dict:
    """Return the signature object for `doc` (the `signatures` field is ignored)."""
    return {"signer": signer, "key_fingerprint": fingerprint(raw_public(key)), "alg": ALG,
            "value": sign_bytes(key, signing_payload(doc))}


def verify_document(doc: dict, sig: dict, raw_public_key_b64: str) -> bool:
    return sig.get("alg") == ALG and verify_bytes(raw_public_key_b64, signing_payload(doc), sig.get("value", ""))


def event_payload(event: dict) -> bytes:
    """Bytes covered by an audit event signature: JCS of the event without `signature`."""
    return jcs({k: v for k, v in event.items() if k != "signature"})


def sign_event(event: dict, signer: str, key: Ed25519PrivateKey) -> dict:
    return {"signer": signer, "key_fingerprint": fingerprint(raw_public(key)), "alg": ALG,
            "value": sign_bytes(key, event_payload(event))}


def verify_event(event: dict, raw_public_key_b64: str) -> bool:
    sig = event.get("signature") or {}
    return sig.get("alg") == ALG and verify_bytes(raw_public_key_b64, event_payload(event), sig.get("value", ""))


ANCHOR_SIGNER = "z3-executor"


ANCHOR_DOMAIN = "vibecheck/audit_anchor/v2"


def anchor_payload(event: dict) -> bytes:
    """Bytes the Z3 executor countersigns on an audit_anchor: JCS of {domain, run_id, seq, prev_hash, event_sha256}.

    prev_hash pins every earlier line, so rewriting the chain also needs the Z3 key (v0.4). v0.5 (review
    2026-10-25 T-9): event_sha256 = sha256(JCS(the anchor event without payload.z3_countersignature)) also pins
    the anchor's own ts, actor and payload, and the domain tag keeps an anchor signature from being replayed as
    one of the Z3 key's other signatures (ownership results, job ledger entries), which carry their own tags."""
    body = {k: v for k, v in event.items()}
    if isinstance(body.get("payload"), dict):
        body["payload"] = {k: v for k, v in body["payload"].items() if k != "z3_countersignature"}
    digest = "sha256:" + hashlib.sha256(jcs(body)).hexdigest()
    return jcs({"domain": ANCHOR_DOMAIN, "run_id": event.get("run_id"), "seq": event.get("seq"),
                "prev_hash": event.get("prev_hash"), "event_sha256": digest})


def countersign_anchor(event: dict, key: Ed25519PrivateKey) -> dict:
    return {"signer": ANCHOR_SIGNER, "key_fingerprint": fingerprint(raw_public(key)), "alg": ALG,
            "value": sign_bytes(key, anchor_payload(event))}
