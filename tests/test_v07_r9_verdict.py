# SPDX-License-Identifier: Apache-2.0
"""Review round 9 (docs/evidence/review-2026-10-27-r9.md), PR2: independence of the votes and the calibration
(rule_version 05-v0.8). Each defect test failed on the PR1 head and passes with the fix; see CONTRIBUTING.md.

  roots     two weighted-valid votes of one base lineage are one observation: S counts each root once (the mean of its
            votes); v0.7 added them, so a claude_sonnet + claude_opus pair confirmed a cluster no other root supported;
  lineage   every model of a lineage declares the same derived_from (external review 2): v0.7 kept the last declaration
            in file order, so reordering models.yaml changed the root (E-MODEL-LINEAGE);
  probabil. the FAIL replay rule sees the same "probabilistic" as the rest of classify_result (external review 1), and a
            test with probabilistic signals declares trials.sampling sampled (E-TC-TRIALS);
  theta     the docs/05 §5.7 limits are recomputed from the split statistics, and theta_confirm is above any single
            vote's weight in its bucket (E-CAL-THETA);
  W4 author a W4 FAIL is pre-registered evidence only when the test's authors are outside the cluster's families and
            roots; otherwise it needs an eligible analyst (E_proof) or stays E_fail_u;
  abstain   a side that abstains on more than abstain_rate_max of its calibration cases is near zero (E-CAL-WEIGHT);
  FP        a false_positive suppression needs two people, one a security_reviewer who did not decide the cluster at G2.
"""
import copy

import pytest

from conftest import doc, rederive
from vchlib import adjudicate, checks, derive
from vchlib.checks import run_all

AUDIT = "audit-event.run-2026-09-23-001.example.jsonl"


def errors(b, code, where=None):
    return [i for i in run_all(b).errors if i.code == code and (where is None or where in i.where)]


def test_the_examples_are_clean(b):
    assert run_all(b).errors == []


def test_rule_version():
    assert adjudicate.RULE_VERSION == "05-v0.13"


# ================================================================ roots: one observation per base lineage
def test_root_score_counts_each_root_once():
    assert derive.root_score([("claude", 1.4425), ("claude", 1.4425)]) == pytest.approx(1.4425)
    assert derive.root_score([("claude", 1.4425), ("gpt", 1.0)]) == pytest.approx(2.4425)
    assert derive.root_score([("claude", 1.4425), ("claude", -1.5)]) == pytest.approx(-0.02875, abs=1e-4)
    assert derive.root_score([]) == 0


def add_second_claude_verifier(b):
    """Review r9 (adjudication) P5: claude_opus_48 joins as ver_4 with claude_sonnet's calibration, and votes SUPPORT on
    K-015 next to ver_2 (claude_sonnet). Both are lineage claude."""
    agents = doc(b, "agents.yaml").data
    agents["ver_4"] = {"model": "claude_opus_48", "role": "verifier", "tools": ["read_slice"]}
    cal = doc(b, "calibration.yaml").data
    cs = next(m for m in cal["config"]["models"] if m["model_key"] == "claude_sonnet")
    cal["config"]["models"].append({**cs, "model_key": "claude_opus_48", "version": "claude-opus-4-8"})
    for row in [r for r in cal["result"]["weights"] if r["model_key"] == "claude_sonnet"]:
        cal["result"]["weights"].append({**copy.deepcopy(row), "model_key": "claude_opus_48"})
    cal["result"]["valid_for_model_keys"].append("claude_opus_48")
    v = doc(b, "verdict.k-015-w3.example.json").data
    ver2 = next(x for x in v["votes"] if x["voter_agent_id"] == "ver_2")
    v4 = copy.deepcopy(ver2)
    v4.update({"voter_agent_id": "ver_4", "voter_model_key": "claude_opus_48"})
    v["votes"].append(v4)
    return v


def test_two_votes_of_one_root_are_one_observation(b, keys):
    v = add_second_claude_verifier(b)
    rederive(b, keys)
    ix = derive.Index(b)
    cl = ix.first("cluster", cluster_id="K-015").data
    one = derive.derived_score(ix, {**v, "votes": [x for x in v["votes"] if x["voter_agent_id"] != "ver_4"]}, cl)
    assert derive.derived_score(ix, v, cl) == pytest.approx(one)


# ================================================================ lineage: consistent derived_from (external review 2)
def contradict(b, first):
    m = doc(b, "models.yaml").data
    m["claude_sonnet"]["derived_from"] = "nemotron3"
    m["claude_opus_48"]["derived_from"] = "gpt"
    if first == "opus":
        items = list(m.items())
        keys_ = [k for k, _ in items]
        i, j = keys_.index("claude_sonnet"), keys_.index("claude_opus_48")
        items[i], items[j] = items[j], items[i]
        m.clear()
        m.update(dict(items))


@pytest.mark.parametrize("first", ["sonnet", "opus"])
def test_contradictory_derived_from_in_one_lineage_is_rejected(b, first):
    contradict(b, first)
    assert any("claude" in i.msg and "derived_from" in i.msg for i in errors(b, "E-MODEL-LINEAGE"))


def test_the_root_does_not_depend_on_the_order_of_models_yaml(b):
    contradict(b, "sonnet")
    a = derive.Index(b).lineage_root("claude")
    contradict(b, "opus")
    assert derive.Index(b).lineage_root("claude") == a


# ================================================================ probabilistic: one judgement (external review 1)
def llm_test_behind_an_http_adapter(b):
    """Review r9 external 1: an LLM test driven by playwright:api, single turn, no target_model record, sampling unset:
    probabilistic only through its LLM threat, which only an Index sees."""
    tc = doc(b, "testcase.llm.example.json").data
    tc["tool_binding"]["adapter"] = "playwright:api"
    tc["tool_binding"]["params"] = {}
    tc["trials"]["record"] = ["temperature"]
    tc["trials"]["sampling"] = None
    tc["multi_turn"] = False
    return tc


def test_a_probabilistic_fail_is_not_demoted_by_a_silent_replay(b, keys):
    tc = llm_test_behind_an_http_adapter(b)
    tr = doc(b, "testresult.llm-pass.example.json").data
    tr.update({"outcome": "FAIL", "trials": {"n": 60, "k": 3, "n_effective": 60}, "replays": 20, "replay_k": 2})
    tr["fail_oracles"] = sorted(derive.oracle_types(tc) & derive.DETERMINISTIC_ORACLES)
    for e in doc(b, AUDIT).data:
        if e["event_type"] == "sandbox_job_end" and e["payload"].get("job_id") == tr["job_id"]:
            e["payload"]["outcome"] = "FAIL"
    rederive(b, keys)
    ix = derive.Index(b)
    assert derive.is_probabilistic(tc, ix)
    cls, why = derive.classify_result(ix, tr, ix.first("cluster", cluster_id=tr["cluster_ids"][0]).data)
    assert why != "FAIL not reproduced by the replay job" and cls in ("E_proof", "E_fail_u"), (cls, why)


def test_a_test_with_probabilistic_signals_declares_sampled(b):
    llm_test_behind_an_http_adapter(b)
    assert any("sampling" in i.msg for i in errors(b, "E-TC-TRIALS", "testcase.llm"))


# ================================================================ theta: docs/05 §5.7 recomputed
def test_a_feasible_theta_meets_the_search_limits(b):
    """Review r9 (adjudication) P3: n 5, precision 0.5 and two self-declared booleans switched on the confirm branch."""
    th = doc(b, "calibration.yaml").data["result"]["thresholds"]["theta_confirm"]["by_bucket"]["authz"]
    th["calibration"] = {"precision": 0.5, "recall": 0.9, "ci_low": 0.3, "ci_high": 0.7, "n": 5}
    th["holdout"] = {"precision": 0.4, "recall": 0.9, "ci_low": 0.2, "ci_high": 0.6, "n": 3}
    msgs = [i.msg for i in errors(b, "E-CAL-THETA")]
    assert any("min_clusters" in m for m in msgs) and any("confirm_precision_floor" in m for m in msgs) \
        and any("holdout precision" in m for m in msgs)      # r10: not the holdout-size message


def test_a_feasible_reject_threshold_meets_the_reject_limits(b):
    """The rejected clusters hold true defects at 10 %, Wilson upper 15 %: above 0.02 and 0.08 (docs/05 §5.7)."""
    th = doc(b, "calibration.yaml").data["result"]["thresholds"]["theta_reject"]
    th["by_bucket"]["authz"] = {"value": 3.0, "feasible": True, "generalised": False,
                                "calibration": {"precision": 0.9, "recall": 0.5, "ci_low": 0.85, "ci_high": 0.95, "n": 50},
                                "holdout": {"precision": 0.9, "recall": 0.5, "ci_low": 0.8, "ci_high": 0.95, "n": 40}}
    msgs = [i.msg for i in errors(b, "E-CAL-THETA")]
    assert any("reject_true_defect_max" in m for m in msgs) and any("reject_wilson_upper_max" in m for m in msgs)


def test_theta_confirm_is_above_any_single_vote(b):
    cal = doc(b, "calibration.yaml").data
    cal["result"]["thresholds"]["theta_confirm"]["by_bucket"]["authz"]["value"] = 1.3                 # below 1.3179 (r10 weights)
    assert any("single" in i.msg for i in errors(b, "E-CAL-THETA"))


def test_the_example_thresholds_meet_the_limits(b):
    c = checks.Ctx(b)
    assert checks.theta_problems(c.calibration) == []


# ================================================================ W4 author independence
def test_a_w4_test_written_by_the_reporting_family_is_not_pre_registered_proof(b, keys):
    """Review r9 (adjudication) P6: the reporter's family wrote and critiqued the W4 test of K-015."""
    agents = doc(b, "agents.yaml").data
    agents["test_gen"]["model"] = "nemotron_self"
    agents["test_critic"]["model"] = "nemotron_self"
    rederive(b, keys)
    ix = derive.Index(b)
    tr = doc(b, "testresult.w4-k-015.example.json").data
    cls, why = derive.classify_result(ix, tr, ix.first("cluster", cluster_id="K-015").data)
    assert why != "reproduced FAIL, deterministic oracle, pre-registered interpretation", (cls, why)


def test_the_example_w4_proof_still_holds(b):
    ix = derive.Index(b)
    tr = doc(b, "testresult.w4-k-015.example.json").data
    assert derive.classify_result(ix, tr, ix.first("cluster", cluster_id="K-015").data)[0] == "E_proof"


# ================================================================ abstention
def test_a_side_that_abstains_too_often_is_near_zero(b):
    """Review r9 (adjudication) P2: answering only the easy cases kept the accuracy (and the weight) high."""
    row = next(r for r in doc(b, "calibration.yaml").data["result"]["weights"]
               if r["model_key"] == "nemotron_self" and r["cwe_bucket"] == "authz")
    row["support"]["n_abstain"] = 28
    assert any("abstain" in i.msg for i in errors(b, "E-CAL-WEIGHT", "nemotron_self/authz/support"))


def test_the_example_weights_record_abstentions(b):
    for r in doc(b, "calibration.yaml").data["result"]["weights"]:
        assert all(isinstance(r[s]["n_abstain"], int) for s in ("support", "refute"))


# ================================================================ FP suppression: two people
def fp(b, signer, role, co=None):
    f = copy.deepcopy(doc(b, "feedback.k-016.example.json").data)
    f["signed_by"] = {**f["signed_by"], "person_id": signer, "role": role}
    f["co_signed_by"] = None if co is None else {"person_id": co[0], "role": co[1], "key_fingerprint": "x"}
    return checks.feedback_suppression(checks.Ctx(b), f)


def test_a_single_security_reviewer_cannot_suppress_alone(b):
    assert fp(b, "heidi", "security_reviewer") == "underReview"      # heidi did not decide K-016: still one person
    assert fp(b, "erin", "security_reviewer") == "underReview"


def test_the_g2_approver_of_the_cluster_does_not_count_as_the_reviewer(b):
    assert fp(b, "frank", "app_owner", ("erin", "security_reviewer")) == "underReview"      # erin decided K-016 at G2


def test_two_people_with_an_independent_reviewer_suppress(b):
    assert fp(b, "frank", "app_owner", ("heidi", "security_reviewer")) == "accepted"
    assert fp(b, "erin", "security_reviewer", ("heidi", "security_reviewer")) == "accepted"
