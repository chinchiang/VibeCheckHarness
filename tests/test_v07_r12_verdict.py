# SPDX-License-Identifier: Apache-2.0
"""Review r12 (docs/evidence/review-2026-10-28-r12.md), PR2: adjudication (rule_version 05-v0.11).

  R15        E-VERDICT-VOTE judged self-review against the cluster's CURRENT members while derive.vote_valid used the
             members at vote time (r11), so the bundle r11 was built for could satisfy neither check; and voted_after_round
             was taken as declared (now bounded by the CMD-2 plans anchored before the verdict version);
  policy     thresholds.high_precision_min is pinned (0.10 plus one rule at a lower bound of 0.13 turned a weak SARIF hit
             into an R8-immune, non-provisional confirmation);
  FIXED      a regression PASS no longer outranks a scanner rule that still fires or a weighted refutation (row 15,
             DISPUTED), and a source proved by an executable proof needs that proof re-run;
  floor      a carried-in confirmed cluster keeps its status when its regression test fails or never ran (R16, row 16);
             r11 let those collapse to UNCORROBORATED;
  R15 stance only refute votes get refute_by_later_member_family.
Each defect test failed on PR1 and passes with the fix (tests/mutations/r12_verdict.json); see CONTRIBUTING.md."""
import copy
import pathlib

import pytest

from conftest import doc, rederive
from test_v07_r11_verdict import REFUTE, nvidia_member, pin_calibration, settle
from vchlib import adjudicate as adj
from vchlib import checks, derive
from vchlib.canonical import content_hash
from vchlib.checks import Ctx, run_all

ROOT = pathlib.Path(__file__).resolve().parents[1]
RUN = "run-2026-09-23-001"
AUDIT = "audit-event.run-2026-09-23-001.example.jsonl"


def errors(b, code, where=None):
    return [i for i in run_all(b).errors if i.code == code and (where is None or where in i.where)]


def text(name):
    return (ROOT / "docs" / name).read_text(encoding="utf-8")


def test_the_examples_are_clean_and_the_rule_version_is_05_v0_11(b):
    assert adj.RULE_VERSION == "05-v0.15" and run_all(b).errors == []


# ================================================================ R15: one membership rule
def self_review(b):
    return [i for i in errors(b, "E-VERDICT-VOTE") if "self-review" in i.msg]


def test_the_r11_scenario_has_no_self_review_error(b, keys):
    """The review's probe A: the refute cast in round 1 stays valid (derive) and is no self-review (validator)."""
    v = doc(b, "verdict.example.json").data
    v["missing_votes"], v["votes"] = [], [copy.deepcopy(REFUTE)]
    nvidia_member(b, 2)
    rederive(b, keys)
    settle(b, keys)
    assert v["votes"][0]["valid"] is True and self_review(b) == []


def test_a_member_present_at_the_vote_is_still_a_self_review(b, keys):
    v = doc(b, "verdict.example.json").data
    v["missing_votes"], v["votes"] = [], [copy.deepcopy(REFUTE)]
    nvidia_member(b, 1)
    rederive(b, keys)
    settle(b, keys)
    v["votes"][0]["valid"] = True                              # the derivation says False; claim True
    assert self_review(b)


def test_voted_after_round_cannot_exceed_the_dispatched_rounds(b, keys):
    v = doc(b, "verdict.k-014-w3.example.json").data
    v["votes"][0]["voted_after_round"] = 2                     # no CMD-2 plan: only round 1 was ever dispatched
    rederive(b, keys)
    assert any("only rounds up to 1" in i.msg for i in errors(b, "E-VERDICT-VOTE"))


def test_an_anchored_cmd2_plan_raises_the_bound(b):
    plan = copy.deepcopy(doc(b, "commander-plan.example.json"))
    plan.path = plan.path.replace("commander-plan.example", "commander-plan.cmd2.example")
    plan.data.update(plan_id="plan-cmd2", decision_node="CMD-2", round=1)
    b.docs.append(plan)
    log = doc(b, AUDIT)
    at = next(i for i, e in enumerate(log.data) if e["event_type"] == "verdict_changed")
    ev = copy.deepcopy(next(e for e in log.data if e["event_type"] == "artifact_stored" and e["payload"].get("artifact") == "commander-plan"))
    ev["payload"] = {"artifact": "commander-plan", "plan_id": "plan-cmd2", "sha256": content_hash(plan.data)}
    log.data.insert(at, ev)
    c = Ctx(b)
    v = doc(b, "verdict.k-014-w3.example.json").data
    assert checks.max_vote_round(c, v, c.ix.first("cluster", cluster_id=v["cluster_id"]).data) == 2


def test_only_a_refute_is_a_refute_by_a_later_member(b):
    nvidia_member(b, 2)
    c = Ctx(b)
    cl = doc(b, "cluster.example.json").data
    assert derive.later_member_overlap(c.ix, copy.deepcopy(REFUTE), cl)
    assert not derive.later_member_overlap(c.ix, dict(copy.deepcopy(REFUTE), stance="SUPPORT"), cl)


# ================================================================ high_precision_min is policy
def test_high_precision_min_is_pinned(b, keys):
    doc(b, "calibration.yaml").data["result"]["thresholds"]["high_precision_min"]["value"] = 0.1
    pin_calibration(b, keys)
    assert any("high_precision_min.value 0.1 != 0.9" in i.msg for i in errors(b, "E-CAL-POLICY"))


def test_a_disabled_high_precision_min_is_allowed(b, keys):
    doc(b, "calibration.yaml").data["result"]["thresholds"]["high_precision_min"]["value"] = None
    pin_calibration(b, keys)
    assert not [i for i in errors(b, "E-CAL-POLICY") if "high_precision_min" in i.msg]


# ================================================================ FIXED needs an uncontradicted, complete re-test
@pytest.mark.parametrize("kw", [{"strong_tool": True}, {"weak_sarif": True},
                                {"strong_tool": True, "weighted_support": True, "weighted_refute": True}])    # r14: tools only
def test_a_contradicted_fix_is_disputed(kw):
    out = adj.adjudicate(adj.Inputs(regression_fixed=True, evidence={"E_pass"}, pass_positive=True, **kw))
    assert (out.status, out.row, out.rules) == ("DISPUTED", 15, ["R14"]) and "fix_contradicted" in out.annotations


def test_an_uncontradicted_fix_is_fixed():
    out = adj.adjudicate(adj.Inputs(regression_fixed=True, evidence={"E_pass"}, pass_positive=True, weighted_support=True))
    assert (out.status, out.row) == ("FIXED", 14)


def test_the_proof_of_the_source_must_be_rerun(b):
    c = Ctx(b)
    run = {"run_id": "run-2026-11-01-001", "run_kind": "regression", "parent_run_id": RUN}
    cluster = {"cluster_id": "K-901", "run_id": run["run_id"], "carried_from": {"run_id": RUN, "cluster_id": "K-005", "fingerprint": "x"}}
    other = content_hash(doc(b, "testresult.llm-pass.example.json").data)       # another testcase, not TC-012-01
    v = {"test_evidence": {"results": [{"result_ref": other, "class": "E_pass", "positive_control": True, "reason": "x"}]}}
    assert not checks.regression_fixed(c, v, cluster, run)
    v["test_evidence"]["results"].append({"result_ref": content_hash(doc(b, "testresult.example.json").data), "class": "E_pass",
                                          "positive_control": True, "reason": "x"})
    assert checks.regression_fixed(c, v, cluster, run)


# ================================================================ R16: a carried confirmed cluster keeps its status
@pytest.mark.parametrize("evidence,note", [({"E_fail_u"}, "regression_failed"), ({"E_inc"}, "fix_unverified"),
                                           (set(), "fix_unverified"), ({"E_pass"}, "fix_unverified")])
def test_a_carried_confirmed_cluster_keeps_its_status(evidence, note):
    out = adj.adjudicate(adj.Inputs(carried_status="CONFIRMED_EXECUTABLE", evidence=evidence))
    assert (out.status, out.row) == ("CONFIRMED_EXECUTABLE", 16) and "R16" in out.rules and note in out.annotations


@pytest.mark.parametrize("kw,status", [({"g2_rejected": True}, "REJECTED"), ({"lane_a": True}, "UNCORROBORATED"),
                                       ({"weighted_support": True, "weighted_refute": True}, "DISPUTED"),
                                       ({"regression_fixed": True, "evidence": {"E_pass"}}, "FIXED")])
def test_the_floor_leaves_people_lane_a_disputes_and_fixes_alone(kw, status):
    assert adj.adjudicate(adj.Inputs(carried_status="CONFIRMED_CORROBORATED", **kw)).status == status


def test_the_floor_needs_a_confirmed_source():
    out = adj.adjudicate(adj.Inputs(carried_status="LIKELY", evidence={"E_fail_u"}))
    assert out.row != 16 and "R16" not in out.rules


def test_the_floor_trace(b):
    out = adj.adjudicate(adj.Inputs(carried_status="CONFIRMED_EXECUTABLE", evidence={"E_fail_u"}))
    assert out.rules == ["R2", "R7", "R16"]
    assert adj.trace_statuses(out) == ["UNCORROBORATED", "UNCORROBORATED", "CONFIRMED_EXECUTABLE"]


def test_carried_status_comes_from_the_parent_head(b):
    c = Ctx(b)
    run = {"run_id": "run-2026-11-01-001", "run_kind": "followup", "parent_run_id": RUN}
    cluster = {"cluster_id": "K-901", "carried_from": {"run_id": RUN, "cluster_id": "K-005", "fingerprint": "x"}}
    assert checks.carried_status(c, cluster, run) == "CONFIRMED_EXECUTABLE"
    assert checks.carried_status(c, cluster, dict(run, parent_run_id="run-other")) is None


def test_rows_15_and_16_are_never_provisional(b, monkeypatch):
    c = Ctx(b)
    v = dict(doc(b, "verdict.k-014-w3.example.json").data, calibration_version=None)
    cl = c.ix.first("cluster", cluster_id=v["cluster_id"]).data
    for x in (adj.Inputs(carried_status="CONFIRMED_EXECUTABLE", evidence={"E_fail_u"}),
              adj.Inputs(regression_fixed=True, evidence={"E_pass"}, strong_tool=True)):
        monkeypatch.setattr(checks, "verdict_inputs", lambda *_a, _x=x: _x)
        assert checks.derived_provisional(c, v, cl) is False


# ================================================================ docs
def test_05_02_06_state_the_r12_rules():
    s = text("05-bias-calibration.md")
    assert "| F 下限 | R16 | 決定 |" in s and "| 15 | 否 | 否 |" in s and "| 16 | 否 | 否 |" in s
    assert "**獨立觀察的單位**（第十二輪第二次外部審查" in s        # the r12 limitation became a conservative default (05-v0.13)
    assert "`fix_contradicted`" in text("02-methodology.md") and "`regression_failed`" in text("02-methodology.md")
    assert "| 44 | **同家族的模型預設算一個觀察，可能低估獨立性**" in text("06-security-legal-limitations.md")


def test_a_carried_clusters_inputs_carry_the_source_status(b):
    """The follow-up run's K-301 is carried from K-005 (head V-005-2, CONFIRMED_EXECUTABLE)."""
    c = Ctx(b)
    cl = doc(b, "cluster.followup.k-301.example.json").data
    v = dict(copy.deepcopy(doc(b, "verdict.example.json").data), cluster_id=cl["cluster_id"], votes=[], missing_votes=[])
    assert checks.verdict_inputs(c, v, cl).carried_status == "CONFIRMED_EXECUTABLE"


def test_the_verdict_schema_knows_the_r12_annotations():
    import json
    s = json.loads((ROOT / "docs" / "schemas" / "verdict.schema.json").read_text(encoding="utf-8"))
    kinds = s["properties"]["annotations"]["items"]["properties"]["kind"]["enum"]
    assert {"fix_contradicted", "regression_failed", "fix_unverified"} <= set(kinds)
    assert "1[0-6]" in s["properties"]["rule_trace"]["items"]["pattern"]
