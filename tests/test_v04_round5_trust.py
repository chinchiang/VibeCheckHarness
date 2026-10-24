# SPDX-License-Identifier: Apache-2.0
"""v0.4 round 5, trust anchors (docs/evidence/review-2026-10-24.md §9). Positive and negative cases:

- every audit_anchor carries a Z3 executor countersignature over {run_id, seq, prev_hash};
  rewriting the chain without the Z3 key breaks it;
- a signature by a key later revoked (not compromised) only counts if the document was first
  verified (G0a / G0b receive time) before revoked_at;
- ROE targets[].edge_ip_ranges are public CIDRs, and the Scope Proxy keeps resolved IPs inside them.
"""
import datetime as dt

from conftest import codes, doc, rederive
from vchlib import crypto, safety
from vchlib.checks import Ctx, run_all

AUDIT = "audit-event.run-2026-09-23-001.example.jsonl"
G0A = "gate-record.g0a.example.json"
FRANK = "ed25519:SHA256:jxVczmwwV1UVWwc1NkHUt22Xr+cvAoyjbxumX4TLJE0"


def errors(b, code):
    return [i for i in run_all(b).errors if i.code == code]


def anchors(b):
    return [e for e in doc(b, AUDIT).data if e["event_type"] == "audit_anchor"]


# ================================================================ Z3 countersigned anchors
def test_example_anchors_are_countersigned(b):
    assert anchors(b) and all(e["payload"]["z3_countersignature"]["signer"] == "z3-executor" for e in anchors(b))
    assert not errors(b, "E-AUDIT-ANCHOR-SIG")


def test_tampered_countersignature(b):
    cs = anchors(b)[0]["payload"]["z3_countersignature"]
    cs["value"] = cs["value"][:10] + ("A" if cs["value"][10] != "A" else "B") + cs["value"][11:]
    assert errors(b, "E-AUDIT-ANCHOR-SIG")


def test_missing_countersignature(b):
    del anchors(b)[0]["payload"]["z3_countersignature"]
    assert errors(b, "E-AUDIT-ANCHOR-SIG")


def test_countersignature_by_a_person_key(b, keys):
    """A Z1 operator signs the anchor with their own key under the Z3 signer name: wrong key, wrong role."""
    ev = anchors(b)[0]
    sig = crypto.countersign_anchor(ev, keys["alice"])
    ev["payload"]["z3_countersignature"] = sig
    assert errors(b, "E-AUDIT-ANCHOR-SIG")


def test_rewritten_chain_without_the_z3_key(b, keys):
    """Edit an early event, re-chain every prev_hash consistently, but keep the old countersignatures
    (the attacker controls Z1, not the Z3 key): every later anchor fails."""
    old = [e["payload"]["z3_countersignature"] for e in anchors(b)]
    doc(b, AUDIT).data[1]["payload"]["edited"] = True
    rederive(b, keys)
    assert not errors(b, "E-AUDIT-ANCHOR-SIG")          # the honest re-sign is consistent
    for e, cs in zip(anchors(b), old):
        e["payload"]["z3_countersignature"] = cs
    assert len(errors(b, "E-AUDIT-ANCHOR-SIG")) == len(old)


# ================================================================ back-dated issued_at
def _revoke_frank(b, at: dt.datetime, reason="retired"):
    for e in doc(b, "key-registry.yaml").data["entries"]:
        if e["fingerprint"] == FRANK:
            e["revoked_at"], e["revocation_reason"] = at.isoformat(), reason


def _first_g0a(b) -> dt.datetime:
    c = Ctx(b)
    return c.ix.decision_time(doc(b, G0A).data)


def test_revoked_after_first_verification_is_not_backdated(b):
    _revoke_frank(b, _first_g0a(b) + dt.timedelta(days=1))
    assert not errors(b, "E-SIG-BACKDATED")


def test_revoked_before_first_verification_is_backdated(b):
    """issued_at says the engagement was signed before the revocation, but nobody saw it until after."""
    _revoke_frank(b, _first_g0a(b) - dt.timedelta(minutes=1))
    assert [i.where for i in errors(b, "E-SIG-BACKDATED")] == ["engagement.yaml"]


def test_compromised_keys_are_reported_as_compromised_not_backdated(b):
    _revoke_frank(b, _first_g0a(b) - dt.timedelta(minutes=1), "compromised")
    found = codes(b)
    assert "E-SIG-COMPROMISED" in found and "E-SIG-BACKDATED" not in found


# ================================================================ CDN edge ranges (BL-15)
def test_edge_range_problem():
    assert safety.edge_range_problem("104.16.0.0/13") is None
    assert safety.edge_range_problem("2606:4700::/32") is None
    assert "host bits" in safety.edge_range_problem("104.16.0.1/13")
    assert "non-public" in safety.edge_range_problem("10.0.0.0/8")
    assert "non-public" in safety.edge_range_problem("100.0.0.0/7")     # spans 100.64.0.0/10 (CGNAT)
    assert safety.edge_range_problem("0.0.0.0/0") is not None          # overlaps every denied network


def test_ip_in_ranges():
    assert safety.ip_in_ranges("104.16.1.1", ["104.16.0.0/13"]) is None
    assert "outside" in safety.ip_in_ranges("8.8.8.8", ["104.16.0.0/13"])
    assert safety.ip_in_ranges("10.0.0.1", ["104.16.0.0/13"]) is not None   # ip_problem still applies
    assert safety.ip_in_ranges("8.8.8.8", None) is None                     # no ranges: U-18 default


def test_roe_edge_ranges(b):
    t = next(t for t in doc(b, "roe.yaml").data["targets"] if t["kind"] == "http")
    t["edge_ip_ranges"] = ["104.16.0.0/13"]
    assert not errors(b, "E-ROE-EDGE-RANGE")
    t["edge_ip_ranges"] = ["104.16.0.0/13", "192.168.0.0/16"]
    assert len(errors(b, "E-ROE-EDGE-RANGE")) == 1
