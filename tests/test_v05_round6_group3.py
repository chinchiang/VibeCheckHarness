# SPDX-License-Identifier: Apache-2.0
"""v0.5 round 6, group 3 (docs/evidence/review-2026-10-25.md §4.2 T-2..T-9, V-7, V-10): trust anchors.
Positive and negative cases:

- T-2: opened_at is the receive time of the gate_opened event, not the signer's claim (E-GATE-OPENED);
- T-3: EXPIRED is unsigned (signatures [] , E-GATE-EXPIRED-SIG), with no E-SIG-MISSING;
- T-4: the z3_executor service key is not a person (initiator, actor, registry roles);
- T-5: engagement / ROE keys are judged at the first verification: expiry and issued_at after it;
- T-6: a G0 verification may name an older registry version, never a newer one;
- T-7: legal_review.attested_by may rotate its key after signing;
- T-9: the Z3 countersignature covers the anchor event itself, under a domain tag;
- V-7: unanchored tool output cannot back a verdict;
- V-10: a gate timeout the engagement leaves out falls back to the toolkit;
- every verdict version needs a verdict_changed event.
"""
import datetime as dt
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from conftest import codes, doc, rederive, resign_gate
from vchlib import checks, crypto
from vchlib.bundle import reload_json
from vchlib.checks import Ctx, run_all

AUDIT = "audit-event.run-2026-09-23-001.example.jsonl"
G1, G2, G4 = "gate-record.g1.example.json", "gate-record.g2.example.json", "gate-record.g4.example.json"
G0A = "gate-record.g0a.example.json"
FRANK = "ed25519:SHA256:jxVczmwwV1UVWwc1NkHUt22Xr+cvAoyjbxumX4TLJE0"


def errors(b, code, where=None):
    return [i for i in run_all(b).errors if i.code == code and (where is None or where in i.where)]


def write_events(b, name, events):
    d = doc(b, name)
    for i, e in enumerate(events, 1):
        e["seq"] = i
    reload_json(d, "".join(json.dumps(e, ensure_ascii=False, separators=(",", ":")) + "\n" for e in events))


def entry(b, fp):
    return next(e for e in doc(b, "key-registry.yaml").data["entries"] if e["fingerprint"] == fp)


# ================================================================ T-2 opened_at
def test_examples_have_their_gate_opened_events(b):
    assert not errors(b, "E-GATE-OPENED")


def test_forged_opened_at_is_rejected(b, keys):
    doc(b, G1).data["opened_at"] = "2026-09-24T10:00:00+08:00"       # the gate_opened event says 09-23 15:00
    resign_gate(b, G1, keys)
    assert errors(b, "E-GATE-OPENED", G1)


def test_missing_gate_opened_event(b, keys):
    events = [e for e in doc(b, AUDIT).data if not (e["event_type"] == "gate_opened" and e["payload"]["gate"] == "G1")]
    write_events(b, AUDIT, events)
    rederive(b, keys)
    assert any("no gate_opened event for G1" in i.msg for i in errors(b, "E-GATE-OPENED", G1))


def test_timeout_is_measured_from_the_receive_time(b, keys):
    """G2 was opened 09-25 12:00 and decided 09-28 10:00 (70 h). A later opened_at would hide a 48 h timeout."""
    doc(b, "engagement.yaml").data["gate_timeouts_hours"]["G2"] = 48
    doc(b, G2).data["opened_at"] = "2026-09-27T12:00:00+08:00"
    resign_gate(b, G2, keys)
    assert errors(b, "E-GATE-TIMEOUT", G2)


# ================================================================ T-3 EXPIRED
def _expire_g2(b, keys):
    doc(b, "engagement.yaml").data["gate_timeouts_hours"]["G2"] = 48       # 70 h > 48 h: really expired
    doc(b, G2).data["outcome"] = "EXPIRED"
    for e in doc(b, AUDIT).data:
        if e["event_type"] == "gate_decision" and e["payload"]["gate"] == "G2":
            e["payload"]["outcome"] = "EXPIRED"
    resign_gate(b, G2, keys)


def test_expired_record_is_unsigned(b, keys):
    _expire_g2(b, keys)
    assert doc(b, G2).data["signatures"] == []
    for code in ("E-SIG-MISSING", "E-GATE-EXPIRED-SIG", "E-GATE-EXPIRED-EARLY"):
        assert not errors(b, code, G2), code


def test_signed_expired_record_is_rejected(b, keys):
    _expire_g2(b, keys)
    rec = doc(b, G2).data
    rec["signatures"] = [crypto.sign_document(rec, a["person_id"], keys[a["person_id"]]) for a in rec["approvers"]]
    assert errors(b, "E-GATE-EXPIRED-SIG", G2)


# ================================================================ T-4 service identity
def test_z3_executor_is_not_a_person(b):
    c = Ctx(b)
    assert crypto.ANCHOR_SIGNER in c.services and crypto.ANCHOR_SIGNER not in c.persons


def test_z3_executor_cannot_initiate_a_gate(b, keys):
    doc(b, G1).data["initiator"] = crypto.ANCHOR_SIGNER
    resign_gate(b, G1, keys)
    assert errors(b, "E-GATE-INITIATOR", G1)
    assert errors(b, "E-PERSON-AUTOMATION", G1)


def test_z3_executor_cannot_claim_a_run(b, keys):
    ev = next(e for e in doc(b, AUDIT).data if e["event_type"] == "initiator_claim")
    ev["actor"]["id"] = ev["payload"]["person_id"] = crypto.ANCHOR_SIGNER
    ev["signature"] = crypto.sign_event(ev, crypto.ANCHOR_SIGNER, keys["z3_executor"])
    assert errors(b, "E-AUDIT-ACTOR", AUDIT)


def test_z3_executor_role_is_exclusive(b):
    z3 = next(e for e in doc(b, "key-registry.yaml").data["entries"] if e["person_id"] == crypto.ANCHOR_SIGNER)
    z3["roles"] = ["z3_executor", "test_lead"]
    assert errors(b, "E-KR-SERVICE")
    z3["roles"] = ["z3_executor"]
    assert not errors(b, "E-KR-SERVICE")


# ================================================================ T-5 first verification
def _first_g0a(b) -> dt.datetime:
    return Ctx(b).ix.decision_time(doc(b, G0A).data)


def test_key_expired_before_the_first_verification(b):
    """issued_at (09-18) is inside frank's validity, but the engagement was first seen after the key expired."""
    entry(b, FRANK)["not_after"] = (_first_g0a(b) - dt.timedelta(days=1)).isoformat()
    assert any("expired" in i.msg for i in errors(b, "E-SIG-BACKDATED", "engagement.yaml"))


def test_key_expiring_after_the_first_verification_is_fine(b):
    entry(b, FRANK)["not_after"] = (_first_g0a(b) + dt.timedelta(days=1)).isoformat()
    assert not errors(b, "E-SIG-BACKDATED", "engagement.yaml")


def test_issued_at_after_the_first_verification(b, keys):
    """A forward-dated engagement, honestly signed and verified by G0a: the claimed issued_at is later than the moment
    the Audit Writer first saw the signed bytes."""
    eng = doc(b, "engagement.yaml").data
    eng["issued_at"] = (_first_g0a(b) + dt.timedelta(days=1)).isoformat()
    eng["signatures"] = [crypto.sign_document(eng, s["signer"], keys[s["signer"]]) for s in eng["signatures"]]
    rederive(b, keys)                                       # G0a verification.document_ref follows the new bytes
    assert errors(b, "E-SIG-ISSUED-AT", "engagement.yaml")


def test_examples_issued_before_verification(b):
    assert "E-SIG-ISSUED-AT" not in codes(b)


# ================================================================ T-6 registry version
def test_newer_registry_keeps_old_verifications(b):
    doc(b, "key-registry.yaml").data["version"] = 5           # e.g. one revocation later
    assert not errors(b, "E-GATE-G0-VERIFY")


def test_verification_cannot_name_a_future_registry(b):
    doc(b, G0A).data["verification"]["key_registry_version"] = 5
    assert errors(b, "E-GATE-G0-VERIFY", G0A)


# ================================================================ T-7 attester key rotation
def test_legal_attester_may_rotate_after_signing(b):
    reg = doc(b, "key-registry.yaml").data
    grace = next(e for e in reg["entries"] if e["person_id"] == "grace" and not e["revoked_at"])
    first_g0b = Ctx(b).ix.decision_time(doc(b, "gate-record.g0b.example.json").data)
    rotated = (first_g0b + dt.timedelta(days=1)).isoformat()
    new = Ed25519PrivateKey.generate()
    pub = crypto.raw_public(new)
    reg["entries"].append(dict(grace, public_key=crypto.b64(pub), fingerprint=crypto.fingerprint(pub), not_before=rotated))
    grace["revoked_at"], grace["revocation_reason"] = rotated, "retired"
    got = {i.code for i in run_all(b).errors if i.where == "roe.yaml"}
    assert not got & {"E-SIG-EXTRA", "E-SIG-MISSING", "E-SIG-BACKDATED", "E-SIG-REVOKED"}, got


# ================================================================ T-9 anchor countersignature
def test_anchor_payload_has_a_domain_and_covers_the_event():
    ev = {"run_id": "r", "seq": 3, "prev_hash": "sha256:00", "ts": "2026-10-01T00:00:00+08:00",
          "payload": {"reason": "run_end", "z3_countersignature": {"value": "x"}}}
    body = json.loads(crypto.anchor_payload(ev))
    assert body["domain"] == crypto.ANCHOR_DOMAIN and body["event_sha256"].startswith("sha256:")
    other = dict(ev, ts="2026-10-02T00:00:00+08:00")
    assert crypto.anchor_payload(other) != crypto.anchor_payload(ev)
    resigned = dict(ev, payload=dict(ev["payload"], z3_countersignature={"value": "y"}))
    assert crypto.anchor_payload(resigned) == crypto.anchor_payload(ev)    # the signature itself is excluded


def test_edited_final_anchor_is_detected(b):
    """The last anchor has no later line whose prev_hash would pin it; its own countersignature now does."""
    last = [e for e in doc(b, AUDIT).data if e["event_type"] == "audit_anchor"][-1]
    last["ts"] = "2026-10-06T13:00:00+08:00"
    assert errors(b, "E-AUDIT-ANCHOR-SIG", AUDIT)


# ================================================================ V-7 unanchored evidence
def _k014(c):
    return c.ix.first("cluster", cluster_id="K-014").data


def test_anchored_sarif_resolves(b):
    c = Ctx(b)
    ref = _k014(c)["sarif_refs"][0]
    assert checks._resolving_event(c, _k014(c), ref)[0] is not None


def test_unanchored_sarif_does_not_resolve(b):
    d = doc(b, AUDIT)
    end = next(e["seq"] for e in d.data if e["event_type"] == "tool_invocation_end")
    d.data[:] = [e for e in d.data if not (e["event_type"] == "audit_anchor" and e["seq"] > end)]
    c = Ctx(b)
    ev, why = checks._resolving_event(c, _k014(c), _k014(c)["sarif_refs"][0])
    assert ev is None and "unanchored" in why


# ================================================================ V-10 timeout fallback
def test_missing_engagement_timeout_falls_back_to_the_toolkit(b):
    del doc(b, "engagement.yaml").data["gate_timeouts_hours"]["G4"]
    doc(b, "toolkit.yaml").data["gate_timeouts_hours"]["G4"] = 12     # G4 took 23 h
    assert errors(b, "E-GATE-TIMEOUT", G4)


# ================================================================ verdict_changed required
def test_every_example_verdict_has_its_event(b):
    assert "E-AUDIT-VERDICT" not in codes(b)


def test_verdict_without_event(b, keys):
    events = [e for e in doc(b, AUDIT).data if not (e["event_type"] == "verdict_changed" and e["payload"]["verdict_id"] == "V-014-1")]
    write_events(b, AUDIT, events)
    rederive(b, keys)
    assert errors(b, "E-AUDIT-VERDICT", "verdict.k-014-w3")
