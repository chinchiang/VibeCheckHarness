# SPDX-License-Identifier: Apache-2.0
"""docs/05 §4.2 rule-order details: R12/R13 on every row, W4 phase annotation."""
import pytest

from conftest import codes, doc
from vchlib.adjudicate import Inputs, adjudicate
from vchlib.checks import Ctx, run_all, verdict_inputs

EARLY_ROWS = [
    (dict(lane_a=True, all_snippets_fail=True), 1, ["R9"]),
    (dict(lane_a=True), 2, ["R9"]),
    (dict(g2_rejected=True), 3, ["R10"]),
    (dict(all_snippets_fail=True), 4, ["R0"]),
    (dict(evidence={"E_proof"}), 5, ["R1"]),
]


@pytest.mark.parametrize("kw,row,rules", EARLY_ROWS)
def test_r12_r13_listed_on_early_rows(kw, row, rules):
    x = Inputs(**{**kw, "evidence": set(kw.get("evidence", set())) | {"E_inc"}}, g3_rejected=True)
    out = adjudicate(x)
    assert out.row == row
    assert out.rules == rules + ["R12", "R13"]
    assert {"test_inconclusive", "g3_rejected"} <= out.annotations


@pytest.mark.parametrize("kw,row,rules", EARLY_ROWS)
def test_early_rows_without_annotations_have_no_r12_r13(kw, row, rules):
    out = adjudicate(Inputs(**kw))
    assert out.rules == rules and "R12" not in out.rules and "R13" not in out.rules


def test_e_inc_on_g2_rejected_and_r0_rows_is_annotated():
    for kw in (dict(g2_rejected=True), dict(all_snippets_fail=True)):
        out = adjudicate(Inputs(**kw, evidence={"E_inc"}))
        assert out.status == "REJECTED" and "test_inconclusive" in out.annotations and out.rules[-1] == "R12"


def test_r1_with_e_pass_conflicting_results():
    out = adjudicate(Inputs(evidence={"E_proof", "E_pass"}))
    assert out.status == "CONFIRMED_EXECUTABLE"
    assert out.rules == ["R1", "R12"] and "conflicting_test_results" in out.annotations


def test_late_rows_rule_order():
    out = adjudicate(Inputs(evidence={"E_pass", "E_inc"}, independent_families=2, g3_rejected=True, pass_positive=True))
    assert out.status == "DISPUTED" and out.rules == ["R2", "R6", "R11", "R12", "R13"]


def test_w4_became_disputed_on_likely_to_disputed_in_w4():
    kw = dict(evidence={"E_pass"}, independent_families=2, pass_positive=True)   # LIKELY -> DISPUTED via R11
    out = adjudicate(Inputs(**kw, phase="W4", prev_status="LIKELY"))
    assert out.status == "DISPUTED" and "w4_became_disputed" in out.annotations


def test_w4_became_disputed_negative_cases():
    kw = dict(evidence={"E_pass"}, independent_families=2, pass_positive=True)
    assert "w4_became_disputed" not in adjudicate(Inputs(**kw, phase="W4", prev_status="DISPUTED")).annotations
    assert "w4_became_disputed" not in adjudicate(Inputs(**kw, phase="W4", prev_status=None)).annotations
    assert "w4_became_disputed" not in adjudicate(Inputs(**kw, phase="B5", prev_status="LIKELY")).annotations
    assert "w4_became_disputed" not in adjudicate(Inputs(**kw, phase="W3", prev_status="LIKELY")).annotations
    assert "w4_became_disputed" not in adjudicate(Inputs(independent_families=2, phase="W4", prev_status="LIKELY")).annotations


def test_prev_status_is_taken_from_the_superseded_verdict(b):
    c = Ctx(b)
    v = doc(b, "verdict.executable.example.json").data           # supersedes V-005-1 (LIKELY)
    cl = c.ix.first("cluster", cluster_id=v["cluster_id"]).data
    assert verdict_inputs(c, v, cl).prev_status == "LIKELY"
    v["readjudicated_by"] = "W4_readjudicate"
    assert verdict_inputs(c, v, cl).phase == "W4"
    assert verdict_inputs(c, doc(b, "verdict.example.json").data, cl).prev_status is None


def _derived_msgs(b):
    return [f"{i.where} {i.msg}" for i in run_all(b).errors if i.code == "E-DERIVED" and "disputed_after_g2" in i.msg]


def test_disputed_after_g2_must_match_w4_annotations(b):
    doc(b, "verdict.k-011-b5.example.json").data["annotations"].append({"kind": "w4_became_disputed", "reason": None})
    msgs = _derived_msgs(b)
    assert any("seed-threats" in m for m in msgs) and any("run.example" in m for m in msgs)
    doc(b, "seed-threats.example.json").data["seeds"][1]["disputed_after_g2"] = True
    doc(b, "examples/run.example.json").data["disputed_after_g2"] = ["K-011"]
    assert _derived_msgs(b) == []


def test_disputed_after_g2_flag_without_annotation_is_caught(b):
    doc(b, "seed-threats.example.json").data["seeds"][0]["disputed_after_g2"] = True
    assert _derived_msgs(b)


def test_rule_trace_missing_r12_is_caught(b):
    v = doc(b, "verdict.executable.example.json").data
    v["test_evidence"]["results"].append({"result_ref": "R-X", "class": "E_inc", "positive_control": None, "reason": "ERROR"})
    v["annotations"].append({"kind": "test_inconclusive", "reason": "R-X ERROR"})
    assert "E-VERDICT-TRACE" in codes(b)          # rule_trace still ends at R1


# ---------------------------------------------------------------- FAIL reproduction (docs/04 §4.4)
def _fail_class(b):
    from vchlib.derive import Index, classify_result
    ix = Index(b)
    tr = doc(b, "testresult.example.json").data                   # deterministic TC-012-01, FAIL, replays 2
    cl = ix.first("cluster", cluster_id=tr["cluster_ids"][0]).data
    return classify_result(ix, tr, cl)[0]


def test_deterministic_fail_fully_reproduced_is_proof_or_fail_u(b):
    assert _fail_class(b) in ("E_proof", "E_fail_u")


@pytest.mark.parametrize("replays,replay_k", [(2, 0), (2, 1), (0, 0)])
def test_fail_not_reproduced_is_e_inc(b, replays, replay_k):
    tr = doc(b, "testresult.example.json").data
    tr["replays"], tr["replay_k"] = replays, replay_k
    assert _fail_class(b) == "E_inc"


def test_fail_not_reproduced_cannot_confirm_executable(b):
    doc(b, "testresult.example.json").data["replay_k"] = 0
    msgs = [i.where for i in run_all(b).errors if i.code == "E-DERIVED"]
    assert any("verdict.executable" in w for w in msgs)              # class must now be E_inc, not E_proof


def test_probabilistic_fail_is_not_demoted_by_the_replay(b):
    """v0.5 (review 2026-10-25 M-3): the replay of a probabilistic test records reproducibility; k_r does not demote
    a FAIL that reached fail_k_min (a true 5% rate is silent in all 20 replays about 36% of the time)."""
    tc = doc(b, "testcase.idor.example.json").data
    tc["trials"]["n"], tc["trials"]["fail_k_min"], tc["trials"]["replay_n"] = 5, 2, 5
    tr = doc(b, "testresult.example.json").data
    tr["trials"] = {"n": 5, "k": 2}
    for k_r in (0, 1, 2):
        tr["replays"], tr["replay_k"] = 5, k_r
        assert _fail_class(b) in ("E_proof", "E_fail_u"), k_r
    tr["trials"] = {"n": 5, "k": 1}                                # below fail_k_min
    assert _fail_class(b) == "E_inc"
    tr["trials"], tr["replays"], tr["replay_k"] = {"n": 5, "k": 2}, 0, 0   # never replayed
    assert _fail_class(b) == "E_inc"


def test_replay_k_above_replays_is_rejected(b):
    doc(b, "testresult.example.json").data["replay_k"] = 3
    assert "E-RESULT-TRIALS" in codes(b)


# ---------------------------------------------------------------- R10 derived from the G2 records
def test_r10_cannot_be_bypassed_by_null_g2_ref(b, keys):
    from conftest import resign_gate
    rec = doc(b, "gate-record.g2.example.json").data
    next(x for x in rec["decisions"] if x["item_id"] == "K-011")["decision"] = "reject"
    resign_gate(b, "gate-record.g2.example.json", keys)
    v = doc(b, "verdict.k-011-b5.example.json").data
    c = Ctx(b)
    cl = c.ix.first("cluster", cluster_id="K-011").data
    assert verdict_inputs(c, v, cl).g2_rejected
    v["g2_decision_ref"] = None
    assert verdict_inputs(c, v, cl).g2_rejected                      # still rejected without the reference
    got = codes(b)
    assert "E-VERDICT-G2" in got and "E-VERDICT-STATUS" in got


def test_g2_ref_must_be_the_latest_g2_record(b):
    doc(b, "verdict.k-011-b5.example.json").data["g2_decision_ref"] = None
    assert "E-VERDICT-G2" in codes(b)                                # B5 verdict after G2 must reference it
