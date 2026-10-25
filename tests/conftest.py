# SPDX-License-Identifier: Apache-2.0
"""Shared fixtures: load the example bundle once, hand each test a deep copy."""
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from vchlib import crypto  # noqa: E402
from vchlib.bundle import load_bundle  # noqa: E402
from vchlib.checks import run_all  # noqa: E402

KEY_DIR = ROOT / "tests" / "fixtures" / "TEST_ONLY_private_keys"


@pytest.fixture(scope="session")
def base_bundle():
    return load_bundle(ROOT)


@pytest.fixture
def b(base_bundle):
    return base_bundle.clone()


@pytest.fixture(scope="session")
def keys():
    """TEST ONLY private keys by name (erin_old, erin, heidi, ...)."""
    return {p.name.split(".")[0]: crypto.load_private_pem(p) for p in KEY_DIR.glob("*.TEST_ONLY.pem")}


def doc(bundle, suffix):
    d = bundle.doc(suffix)
    assert d is not None, suffix
    return d


def codes(bundle):
    return run_all(bundle).codes()


def rederive(bundle, keys, rounds=20):
    """In-memory twin of tools/sign_examples.py: apply every writer derivation, re-sign the
    G1-G5/GB gate records and rebuild (re-chain, re-sign) the audit logs until nothing changes.
    Lets a test make a *consistent* change and then assert the exact error set."""
    import hashlib
    import json

    import sign_examples
    from vchlib import derive
    from vchlib.bundle import reload_json
    by_fp = {crypto.fingerprint(crypto.raw_public(k)): k for k in keys.values()}
    registry = doc(bundle, "key-registry.yaml").data
    for _ in range(rounds):
        changed = False
        docs = {d.path: d for d in bundle.docs}
        for e in derive.expectations(bundle, for_writer=True):
            d = docs[e.file]
            if derive.get_path(d.data, e.path) != e.expected:
                derive.set_path(d.data, e.path, e.expected)
                changed = True
        for d in bundle.docs:
            if d.kind == "gate-record" and isinstance(d.data, dict):
                rec = d.data
                sigs = [] if rec.get("gate") in ("G0a", "G0b") or rec.get("outcome") == "EXPIRED" else \
                    [crypto.sign_document(rec, a["person_id"], by_fp[a["key_fingerprint"]]) for a in rec["approvers"]]
                if sigs != rec.get("signatures"):
                    rec["signatures"] = sigs
                    changed = True
            if d.kind == "audit-event" and isinstance(d.data, list) and d.data:
                prev = hashlib.sha256(d.data[0]["run_id"].encode()).hexdigest()
                lines = []
                for ev in d.data:
                    ev["prev_hash"] = "sha256:" + prev
                    sign_examples.sign_event_in_place(ev, registry, by_fp)
                    line = json.dumps(ev, ensure_ascii=False, separators=(",", ":"))
                    prev = hashlib.sha256(line.encode("utf-8")).hexdigest()
                    lines.append(line)
                text = "".join(ln + "\n" for ln in lines)
                if text != d.text:
                    reload_json(d, text)
                    changed = True
        if not changed:
            return bundle
    raise AssertionError("rederive: no fixpoint")


def resign_gate(bundle, suffix, keys, key_for=None):
    """Re-sign a gate record after mutating it (key_for: person_id -> TEST ONLY key name)."""
    rec = doc(bundle, suffix).data
    key_for = key_for or {}
    rec["signatures"] = [] if rec.get("outcome") == "EXPIRED" else \
        [crypto.sign_document(rec, a["person_id"], keys[key_for.get(a["person_id"], a["person_id"])]) for a in rec["approvers"]]
    return rec
