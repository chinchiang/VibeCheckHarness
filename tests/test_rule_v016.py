# SPDX-License-Identifier: Apache-2.0
"""rule_version 05-v0.16: three design changes decided by the user after the 2026-11-22 internal review
(docs/evidence/review-2026-11-22.md section 2, docs/05 section 4.2).

D2  A cluster whose rubric severity is critical / high is never rejected by rule: R0 and R4 row 8 give DISPUTED (a person
    decides at G2), Lane A (R9) gives UNCORROBORATED. The repository under test is attacker-controlled input.
D4  An eligible Result Analyst that disagrees no longer turns a pre-registered result into E_inc; the class stands and the
    verdict is annotated `analyst_disagrees`. Review r10 had made the disagreement win.
D6  A qualified PASS without a PASSed oracle_can_fail control is E_pass_weak; R11 only annotates on it, R14 (FIXED) does
    not accept it, and its annotation may not state a statistical bound.

Tests named `..._is_not_rejected`, `..._keeps_...`, `..._is_e_pass_weak`, `..._is_refused` failed before the change and pass
after it (tests/mutations/rule_v016.json); the others check that nothing else moved. See CONTRIBUTING.md."""
import itertools
import pathlib

import pytest

from conftest import doc
from vchlib import adjudicate as adj
from vchlib import derive, verdict
from vchlib.adjudicate import Inputs, adjudicate
from vchlib.checks import run_all
from vchlib.context import Ctx

V011B5 = "verdict.k-011-b5.example.json"


def errors(b, code):
    return [i for i in run_all(b).issues if i.code == code]


def test_the_rule_version_and_the_examples():
    assert adj.RULE_VERSION == "05-v0.17"
    assert adj.EVIDENCE_ORDER == ["E_proof", "E_fail_u", "E_pass", "E_pass_weak", "E_inc"]
    assert "pass_positive" not in Inputs.__dataclass_fields__


# ================================================================ D2: high severity is never rejected by rule
def test_r0_on_a_high_severity_cluster_is_not_rejected():
    out = adjudicate(Inputs(all_snippets_fail=True, high_severity=True))
    assert (out.status, out.row, out.rules) == ("DISPUTED", 17, ["R0"])
    low = adjudicate(Inputs(all_snippets_fail=True))
    assert (low.status, low.row, low.rules) == ("REJECTED", 4, ["R0"])


def test_r4_row_8_on_a_high_severity_cluster_is_not_rejected():
    kw = dict(weighted_refute=True, score=-3.0, theta_reject=2.0, independent_families=1)
    out = adjudicate(Inputs(**kw, high_severity=True))
    assert (out.status, out.row, out.rules) == ("DISPUTED", 9, ["R2", "R4"])
    low = adjudicate(Inputs(**kw))
    assert (low.status, low.row, low.rules) == ("REJECTED", 8, ["R2", "R4"])


def test_lane_a_reports_a_high_severity_cluster_instead_of_rejecting_it():
    out = adjudicate(Inputs(lane_a=True, all_snippets_fail=True, high_severity=True))
    assert (out.status, out.row, out.advisory, out.status_cap) == ("UNCORROBORATED", 2, True, "UNCORROBORATED")
    low = adjudicate(Inputs(lane_a=True, all_snippets_fail=True))
    assert (low.status, low.row) == ("REJECTED", 1)


def test_no_rule_rejects_a_high_severity_cluster_without_a_person():
    """Every combination of the inputs the deciding rules read: with high_severity the only REJECTED is the G2 rejection
    (R10), a person's decision."""
    seen = set()
    for lane, g2, fail, ev, sup, ref, score, strong, weak, fams in itertools.product(
            [False, True], [False, True], [False, True], [set(), {"E_pass"}, {"E_pass_weak"}, {"E_fail_u"}, {"E_inc"}],
            [False, True], [False, True], [-9.0, 0.0, 9.0], [False, True], [False, True], [0, 1, 2]):
        out = adjudicate(Inputs(lane_a=lane, g2_rejected=g2, all_snippets_fail=fail, evidence=ev, weighted_support=sup,
                                weighted_refute=ref, score=score, theta_confirm=2.0, theta_reject=2.0, strong_tool=strong,
                                weak_sarif=weak, independent_families=fams, high_severity=True))
        seen.add(out.status)
        if out.status == "REJECTED":
            assert g2 and not lane and out.rules[0] == "R10", (lane, g2, fail, ev, out.rules)
    assert "DISPUTED" in seen and "REJECTED" in seen


def test_high_severity_changes_nothing_else():
    """Outside R0 / R4 row 8 / R9 the flag is not read: every other outcome is the same with and without it."""
    for g2, ev, sup, ref, score, strong, weak, fams in itertools.product(
            [False, True], [set(), {"E_proof"}, {"E_pass"}, {"E_fail_u"}], [False, True], [False, True], [-9.0, 0.0, 9.0],
            [False, True], [False, True], [0, 1, 2]):
        kw = dict(g2_rejected=g2, evidence=ev, weighted_support=sup, weighted_refute=ref, score=score, theta_confirm=2.0,
                  theta_reject=2.0, strong_tool=strong, weak_sarif=weak, independent_families=fams)
        a, b_ = adjudicate(Inputs(**kw)), adjudicate(Inputs(**kw, high_severity=True))
        if a.row == 8:
            continue
        assert (a.status, a.row, a.rules, a.annotations) == (b_.status, b_.row, b_.rules, b_.annotations), kw


def test_the_severity_is_the_rubric_severity_of_the_cluster(b, monkeypatch):
    c = Ctx(b)
    v, cl = doc(b, "verdict.k-015-w3.example.json").data, c.ix.first("cluster", cluster_id="K-015").data
    assert derive.rubric_severity(c.ix, cl) == "critical" and verdict.verdict_inputs(c, v, cl).high_severity is True
    for sev, want in (("high", True), ("medium", False), ("low", False), ("info", False)):
        monkeypatch.setattr(derive, "rubric_severity", lambda ix, cluster, sev=sev: sev)
        assert verdict.verdict_inputs(c, v, cl).high_severity is want, sev


def test_row_17_is_not_provisional(b):
    """R0 on a high-severity cluster is decided by evidence, not by votes, so the verdict is not provisional."""
    doc(b, "finding.f-061.example.json").data["evidence"][0]["match"] = "NOT_FOUND"
    c = Ctx(b)
    v, cl = doc(b, "verdict.k-015-w3.example.json").data, c.ix.first("cluster", cluster_id="K-015").data
    assert adjudicate(verdict.verdict_inputs(c, v, cl)).row == 17
    v["calibration_version"] = None            # a vote-decided row would now be provisional (no calibration)
    assert verdict.derived_provisional(c, v, cl) is False
    doc(b, "finding.f-061.example.json").data["evidence"][0]["match"] = "MATCHED_SHIFTED"
    c = Ctx(b)
    assert adjudicate(verdict.verdict_inputs(c, v, cl)).row == 13 and verdict.derived_provisional(c, v, cl) is True


# ================================================================ D4: a disagreeing analyst marks, it does not veto
def _k015_with_an_eligible_analyst(b, agrees):
    ag = doc(b, "agents.yaml").data
    ag["test_gen"]["model"] = ag["test_critic"]["model"] = "gpt_flagship"
    tr = doc(b, "testresult.w4-k-015.example.json").data
    tr["interpreted_by"] = {"agent_id": "result_analyst_a", "family": "anthropic"}
    tr["interpretation"] = {"agrees": agrees, "rationale": "x"}
    ix = derive.Index(b)
    return ix, tr, ix.first("cluster", cluster_id="K-015").data


def test_a_disagreeing_analyst_keeps_a_preregistered_fail(b):
    ix, tr, cl = _k015_with_an_eligible_analyst(b, False)
    assert derive.preregistered(ix, ix.testcase_for(tr).data, tr, "oracle_can_pass", cl)
    cls, why = derive.classify_result(ix, tr, cl)
    assert cls == "E_proof" and derive.ANALYST_DISAGREES in why
    ix, tr, cl = _k015_with_an_eligible_analyst(b, True)
    cls, why = derive.classify_result(ix, tr, cl)
    assert cls == "E_proof" and derive.ANALYST_DISAGREES not in why


def test_a_disagreeing_analyst_still_makes_an_unregistered_result_inconclusive(b, monkeypatch):
    ix, tr, cl = _k015_with_an_eligible_analyst(b, False)
    monkeypatch.setattr(derive, "preregistered", lambda *a, **k: False)
    monkeypatch.setattr(derive, "result_oracle_unreviewed", lambda *a, **k: False)
    cls, why = derive.classify_result(ix, tr, cl)
    assert cls == "E_inc" and "does not agree" in why and derive.ANALYST_DISAGREES not in why
    # the PASS side: the example's B4 PASS has an eligible analyst; without a pre-registration its disagreement decides
    tr = doc(b, "testresult.llm-pass.example.json").data
    cl = ix.first("cluster", cluster_id="K-011").data
    tr["interpretation"]["agrees"] = False
    cls, why = derive.classify_result(ix, tr, cl)
    assert cls == "E_inc" and "does not agree" in why and derive.ANALYST_DISAGREES not in why


def test_the_verdict_is_annotated_analyst_disagrees(b):
    _k015_with_an_eligible_analyst(b, False)
    c = Ctx(b)
    v = doc(b, "verdict.k-015-w4.example.json").data
    cl = c.ix.first("cluster", cluster_id="K-015").data
    x = verdict.verdict_inputs(c, v, cl)
    assert x.analyst_disagrees is True
    out = adjudicate(x)
    assert out.status == "CONFIRMED_EXECUTABLE" and "analyst_disagrees" in out.annotations and out.rules[-1] == "R12"
    assert any("analyst_disagrees" in i.msg for i in errors(b, "E-VERDICT-ANNOTATIONS"))     # the stored verdict lacks it


def test_the_annotation_never_changes_the_status():
    for ev, sup, fams in itertools.product([{"E_proof"}, {"E_pass"}, {"E_pass_weak"}, {"E_fail_u"}, set()], [False, True], [0, 1, 2]):
        kw = dict(evidence=ev, weighted_support=sup, score=9.0 if sup else 0.0, theta_confirm=2.0, independent_families=fams)
        a, b_ = adjudicate(Inputs(**kw)), adjudicate(Inputs(**kw, analyst_disagrees=True))
        assert (a.status, a.row) == (b_.status, b_.row) and b_.annotations - a.annotations == {"analyst_disagrees"}
        assert "R12" in b_.rules


def test_the_schema_knows_the_new_annotation_and_class():
    s = (pathlib.Path(__file__).resolve().parents[1] / "docs/schemas/verdict.schema.json").read_text(encoding="utf-8")
    assert '"analyst_disagrees"' in s and s.count('"E_pass_weak"') == 2


# ================================================================ D6: a PASS without a positive control is E_pass_weak
def test_a_pass_without_a_positive_control_is_e_pass_weak(b):
    c = Ctx(b)
    tr = doc(b, "testresult.llm-pass.example.json").data
    cl = c.ix.first("cluster", cluster_id="K-011").data
    assert derive.positive_control_value(c.ix.testcase_for(tr).data, tr) is None
    assert derive.classify_result(c.ix, tr, cl)[0] == "E_pass_weak"
    assert doc(b, V011B5).data["test_evidence"]["class"] == "E_pass_weak"


def test_a_pass_with_a_positive_control_is_e_pass(b, monkeypatch):
    c = Ctx(b)
    tr = doc(b, "testresult.llm-pass.example.json").data
    cl = c.ix.first("cluster", cluster_id="K-011").data
    monkeypatch.setattr(derive, "positive_control_value", lambda tc, tr_: True)
    assert derive.classify_result(c.ix, tr, cl)[0] == "E_pass"
    monkeypatch.setattr(derive, "positive_control_value", lambda tc, tr_: False)      # a control exists and did not PASS
    assert derive.classify_result(c.ix, tr, cl)[0] == "E_pass_weak"


@pytest.mark.parametrize("kw, before", [(dict(independent_families=2), "LIKELY"),
                                        (dict(strong_tool=True, independent_families=1), "CONFIRMED_CORROBORATED")])
def test_r11_behaves_as_before_for_each_class(kw, before):
    strong = adjudicate(Inputs(evidence={"E_pass"}, **kw))
    assert (strong.status, strong.rules[-1]) == ("DISPUTED", "R11")
    weak = adjudicate(Inputs(evidence={"E_pass_weak"}, **kw))
    assert weak.status == before and weak.rules[-1] == "R11" and "test_not_reproduced" in weak.annotations
    both = adjudicate(Inputs(evidence={"E_pass", "E_pass_weak"}, **kw))
    assert both.status == "DISPUTED"


def test_a_weak_pass_next_to_a_proof_is_a_conflict():
    for ev in ({"E_proof", "E_pass"}, {"E_proof", "E_pass_weak"}):
        out = adjudicate(Inputs(evidence=ev))
        assert out.status == "CONFIRMED_EXECUTABLE" and "conflicting_test_results" in out.annotations


def test_a_weak_pass_does_not_make_a_regression_fixed(b):
    """R14 needs a PASS with a positive control; a result that only names the class E_pass does not count either."""
    from vchlib.canonical import content_hash
    c = Ctx(b)
    run = {"run_id": "run-2026-11-01-001", "run_kind": "regression", "parent_run_id": "run-2026-09-23-001"}
    cluster = {"cluster_id": "K-901", "run_id": run["run_id"],
               "carried_from": {"run_id": "run-2026-09-23-001", "cluster_id": "K-005", "fingerprint": "x"}}
    proof = content_hash(doc(b, "testresult.example.json").data)
    v = {"test_evidence": {"class": "E_pass", "results": [{"result_ref": proof, "class": "E_pass", "positive_control": True, "reason": "x"}]}}
    assert verdict.regression_fixed(c, v, cluster, run)
    v["test_evidence"]["results"][0]["class"] = "E_pass_weak"
    assert not verdict.regression_fixed(c, v, cluster, run)
    v["test_evidence"]["results"][0].update({"class": "E_pass", "positive_control": None})
    assert not verdict.regression_fixed(c, v, cluster, run)


@pytest.mark.parametrize("reason", ["TC-031-01：60 次都沒有重現（p_u≈0.049）", "違反率的單側 95% 上界 4.9%",
                                    "no violation; upper bound 4.9%", "95% 信賴界限以下"])
def test_a_stated_bound_on_a_weak_pass_is_refused(b, reason):
    v = doc(b, V011B5).data
    assert not errors(b, "E-VERDICT-ANNOTATIONS")
    next(a for a in v["annotations"] if a["kind"] == "test_not_reproduced")["reason"] = reason
    got = errors(b, "E-VERDICT-ANNOTATIONS")
    assert any("states a statistical bound" in i.msg and "k-011-b5" in i.where for i in got), [i.msg for i in got]


def test_a_plain_reason_on_a_weak_pass_is_accepted(b):
    v = doc(b, V011B5).data
    next(a for a in v["annotations"] if a["kind"] == "test_not_reproduced")["reason"] = "TC-031-01：60 次有效 trial 未觀察到違反；oracle 未經正對照驗證"
    assert not errors(b, "E-VERDICT-ANNOTATIONS")
