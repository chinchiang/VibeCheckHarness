# SPDX-License-Identifier: Apache-2.0
"""Signing policy: who signs which record, shared by the checker (checks.g_signatures, the feedback and withdrawal
checks) and by the TEST ONLY writers that re-seal a bundle (tools/sign_examples.py, tools/build_variants.py,
tests/conftest.py). See docs/adr/0002-reseal-module.md.

Architecture refactor PR-C1 (no behaviour change): the rules were written once in the checker and copied into each
writer; they now live here once. The writer helpers (current_key, sign_event_in_place) moved verbatim out of
tools/sign_examples.py.

TEST ONLY: sign_event_in_place signs with whatever private keys it is given; the writers pass the public test fixtures
in tests/fixtures/TEST_ONLY_private_keys. The checker only ever reads the policy, it never signs.
"""
from __future__ import annotations

from . import crypto, timeutil

# v0.5: ASI09 spot checks are a person's act
SIGNED_EVENTS = {"initiator_claim", "run_resume", "spot_check_result"}


def gate_unsigned(rec: dict) -> bool:
    """A gate record nobody signs: G0a / G0b are system verifications, an EXPIRED gate was decided by nobody.
    (The checker reports the two cases with their own codes, E-GATE-G0-SIG and E-GATE-EXPIRED-SIG.)"""
    return rec.get("gate") in ("G0a", "G0b") or rec.get("outcome") == "EXPIRED"


def required_signers(kind: str, data: dict) -> list:
    """The people who sign a record, in signature order (each entry has person_id and key_fingerprint).

    gate-record: its approvers (unless gate_unsigned); feedback: signed_by, then co_signed_by when it is set (v0.7, r8
    M4); report-withdrawal: its signers, in order (review r12, docs/06 §1.9 #4). Malformed input is passed through the
    way the checker reads it (a missing signed_by is {}, a co_signed_by that is not an object is ignored).
    """
    if kind == "gate-record":
        return data.get("approvers", [])
    if kind == "feedback":
        cs = data.get("co_signed_by")
        return [data.get("signed_by") or {}] + ([cs] if isinstance(cs, dict) else [])
    if kind == "report-withdrawal":
        return data.get("signers") or []
    raise ValueError(f"no signing policy for kind {kind!r}")


def event_is_signed(ev: dict) -> bool:
    """A human's SIGNED_EVENTS event carries the signature of its actor (actor.id); every other event has none."""
    return ev.get("event_type") in SIGNED_EVENTS and (ev.get("actor") or {}).get("kind") == "human"


def current_key(registry, person, at, by_fp):
    for e in registry["entries"]:
        if e["person_id"] != person or e.get("revoked_at"):
            continue
        if timeutil.parse_dt(e["not_before"]) <= at <= timeutil.parse_dt(e["not_after"]):
            return by_fp[e["fingerprint"]]
    raise SystemExit(f"no valid registry key for {person} at {at}")


def sign_event_in_place(ev: dict, registry, by_fp) -> None:
    """Re-sign one audit event whose prev_hash is already set: human SIGNED_EVENTS get the actor's
    signature; every audit_anchor gets the Z3 executor's countersignature (crypto.anchor_payload)."""
    ev["signature"] = None
    at = timeutil.parse_dt(ev["ts"])
    if ev["event_type"] == "audit_anchor" and isinstance(ev.get("payload"), dict):
        ev["payload"]["z3_countersignature"] = crypto.countersign_anchor(
            ev, current_key(registry, crypto.ANCHOR_SIGNER, at, by_fp))
    if event_is_signed(ev):
        ev["signature"] = crypto.sign_event(ev, ev["actor"]["id"], current_key(registry, ev["actor"]["id"], at, by_fp))
