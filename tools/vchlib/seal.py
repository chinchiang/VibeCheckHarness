# SPDX-License-Identifier: Apache-2.0
"""Signing policy: who signs which record, shared by the checker (checks.g_signatures, the feedback and withdrawal
checks) and by the TEST ONLY writers that re-seal a bundle (tools/sign_examples.py, tools/build_variants.py,
tests/conftest.py). See docs/adr/0002-reseal-module.md.

Architecture refactor PR-C1 (no behaviour change): the rules were written once in the checker and copied into each
writer; they now live here once. The writer helpers (current_key, sign_event_in_place) moved verbatim out of
tools/sign_examples.py. PR-C2: reseal, the one in-memory re-derive / re-sign / re-chain loop (moved verbatim out of
tools/build_variants.py, where it was `resign`).

TEST ONLY: sign_event_in_place and reseal sign with whatever private keys they are given; the writers pass the public
test fixtures in tests/fixtures/TEST_ONLY_private_keys. The checker only ever reads the policy, it never signs
(tests/test_seal.py keeps checks.py from using reseal).
"""
from __future__ import annotations

import hashlib
import json
import pathlib

from . import crypto, derive, expectations, timeutil
from .bundle import SIGNED_YAML, Bundle, dump_json, dump_jsonl, reload_json
from .canonical import content_hash

CFG = "docs/examples/"


class ResealError(Exception):
    """reseal could not bring the bundle back to a consistent state (no fixpoint, no valid TEST ONLY key)."""

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


def signing_key(by_fp, fingerprint, where):
    """The TEST ONLY private key with this fingerprint; ResealError (not KeyError) when the fixtures have none."""
    try:
        return by_fp[fingerprint]
    except KeyError:
        raise ResealError(f"{where}: no TEST ONLY key for {fingerprint}") from None


def current_key(registry, person, at, by_fp):
    for e in registry["entries"]:
        if e["person_id"] != person or e.get("revoked_at"):
            continue
        if timeutil.parse_dt(e["not_before"]) <= at <= timeutil.parse_dt(e["not_after"]):
            return signing_key(by_fp, e["fingerprint"], "key-registry.yaml")
    raise ResealError(f"no valid registry key for {person} at {at}")


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


def reseal(b: Bundle, keys, *, rounds: int = 30) -> None:
    """Bring an edited bundle back to a consistent state, in place: apply every writer derivation, refresh the
    engagement config_pins, re-sign the signed YAML, the gate records, feedback and report withdrawals, renumber and
    re-chain (re-sign) the audit logs, until nothing changes. keys: TEST ONLY key name -> private key.

    A test that wants an inconsistent bundle edits it after reseal. Raises ResealError without a fixpoint.
    """
    by_fp = {crypto.fingerprint(crypto.raw_public(k)): k for k in keys.values()}
    for d in b.docs:                       # edits may have inserted or dropped events: renumber and refresh the raw lines
        if d.kind == "audit-event" and d.data:
            for i, ev in enumerate(d.data):
                ev["seq"] = i + 1
            reload_json(d, dump_jsonl(d.data))
    for _ in range(rounds):
        changed = False
        docs = {d.path: d for d in b.docs}
        for e in expectations.expectations(b, for_writer=True):
            d = docs[e.file]
            if derive.get_path(d.data, e.path) != e.expected:
                derive.set_path(d.data, e.path, e.expected)
                changed = True
        eng = next((d for d in b.docs if d.kind == "engagement"), None)
        if eng is not None:
            for name, ref in (eng.data.get("config_pins") or {}).items():
                cfg = next((d for d in b.docs if d.path == f"{CFG}{name}.yaml"), None)
                if cfg is not None and ref != content_hash(cfg.data):
                    eng.data["config_pins"][name] = content_hash(cfg.data)
                    changed = True
        for d in b.docs:
            if pathlib.PurePosixPath(d.path).name in SIGNED_YAML:
                for sig in d.data.get("signatures") or []:
                    value = crypto.sign_document(d.data, sig["signer"], signing_key(by_fp, sig["key_fingerprint"], d.name))["value"]
                    if sig.get("value") != value:
                        sig["value"], changed = value, True
            if d.kind == "gate-record":
                rec = d.data
                sigs = [] if gate_unsigned(rec) else \
                    [crypto.sign_document(rec, a["person_id"], signing_key(by_fp, a["key_fingerprint"], d.name)) for a in required_signers(d.kind, rec)]
                if sigs != rec.get("signatures"):
                    rec["signatures"], changed = sigs, True
            if d.kind in ("feedback", "report-withdrawal"):
                rec = d.data
                sigs = [crypto.sign_document(rec, x["person_id"], signing_key(by_fp, x["key_fingerprint"], d.name)) for x in required_signers(d.kind, rec)]
                if sigs != rec.get("signatures"):
                    rec["signatures"], changed = sigs, True
        registry = next(d for d in b.docs if d.kind == "key-registry").data
        for d in b.docs:
            if d.kind == "audit-event" and d.data:
                prev = hashlib.sha256(d.data[0]["run_id"].encode()).hexdigest()
                for i, ev in enumerate(d.data):
                    ev["seq"] = i + 1
                    ev["prev_hash"] = "sha256:" + prev
                    sign_event_in_place(ev, registry, by_fp)
                    prev = hashlib.sha256(json.dumps(ev, ensure_ascii=False, separators=(",", ":")).encode("utf-8")).hexdigest()
                text = dump_jsonl(d.data)
                if text != d.text:
                    reload_json(d, text)
                    changed = True
        for d in b.docs:
            if not d.path.endswith(".jsonl") and d.path.endswith(".json"):
                d.text = dump_json(d.data)
        if not changed:
            return
    raise ResealError("no fixpoint")
