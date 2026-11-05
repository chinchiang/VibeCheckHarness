# SPDX-License-Identifier: Apache-2.0
"""vchlib.seal (architecture refactor PR-C2, docs/adr/0002-reseal-module.md): reseal brings an edited bundle back to a
consistent state with the TEST ONLY keys, and the checker never uses it (it only reads the signing policy)."""
import ast
import copy

import pytest

from conftest import ROOT, codes, doc
from vchlib import seal

CHECKS = ROOT / "tools" / "vchlib" / "checks.py"


def test_the_checker_never_reseals():
    """checks.py reads the signing policy from seal but must not sign: no reseal / sign_event_in_place / current_key."""
    writers = {"reseal", "sign_event_in_place", "current_key"}
    tree = ast.parse(CHECKS.read_text(encoding="utf-8"))
    used = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name)
            and n.value.id == "seal"}
    imported = {a.name for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and (n.module or "").endswith("seal")
                for a in n.names}
    assert not (used | imported) & writers, sorted((used | imported) & writers)


def test_reseal_leaves_the_clean_bundle_unchanged(b, keys):
    """The example bundle is already sealed: reseal changes no document's data, nor the text of a JSON / JSONL one."""
    before = [(d.path, copy.deepcopy(d.data), d.text) for d in b.docs]
    seal.reseal(b, keys)
    after = [(d.path, d.data, d.text) for d in b.docs]
    assert [(p, data) for p, data, _ in after] == [(p, data) for p, data, _ in before]
    json_text = [(p, t) for p, _, t in after if p.endswith((".json", ".jsonl"))]
    assert json_text == [(p, t) for p, _, t in before if p.endswith((".json", ".jsonl"))]


def test_reseal_resigns_an_edited_feedback_record(b, keys):
    """conftest.rederive did not re-sign feedback before PR-C4; reseal does, and re-pins its recorded hash."""
    doc(b, "feedback.k-016.example.json").data["reason"] += "（補充）"
    assert {"E-SIG-BAD", "E-AUDIT-FEEDBACK"} <= codes(b)
    seal.reseal(b, keys)
    assert codes(b) == set()


def test_reseal_without_a_fixpoint_raises(b, keys):
    with pytest.raises(seal.ResealError, match="no fixpoint"):
        seal.reseal(b, keys, rounds=0)


def test_no_valid_key_raises():
    with pytest.raises(seal.ResealError, match="no valid registry key"):
        seal.current_key({"entries": []}, "alice", None, {})
