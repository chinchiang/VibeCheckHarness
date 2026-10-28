# SPDX-License-Identifier: Apache-2.0
"""Review round 10 (docs/evidence/review-2026-10-27-r10.md), PR2: adjudication and calibration (rule_version 05-v0.10).
Each defect test failed on the PR1 head and passes with the fix; see CONTRIBUTING.md.

  theta_reject  a bucket's theta_reject is above every single refute weight of the bucket (E-CAL-THETA): one refuting
                vote did auto-reject a single-family cluster (row 8);
  sampled       `trials.sampling: sampled` is a declaration, not a signal: the replay leniency follows the target-side
                signals only, and a test that declares sampled without any of them is E-TC-TRIALS;
  root_score    each base lineage counts its strongest vote when its votes agree: a weaker SUPPORT of the same root no
                longer lowers S below theta;
  analyst       an eligible Result Analyst that disagrees makes a pre-registered result E_inc (fail closed);
  authors       a W4 test whose authors are unknown is not independent, and a bundle with W4 results registers a
                test_generator and a test_critic (E-AGENT-ROLES);
  contamination a reproduced canary zeroes the model's weights, sentinels are in the holdout split, nobody read the
                holdout before preregistration (E-CAL-CONTAMINATION); a flagged variant gap with weight warns;
  holdout       a threshold generalises only on a holdout of n >= 10 clusters;
  abstention    an abstention counts as a coin flip (half right, half wrong) in the rates and the Wilson bound, so
                abstaining on hard cases no longer keeps the weight;
  R8            with E-CAL-THETA, row 11 needs two base lineages, so R8 cannot fire (it stays as defence in depth).
"""
import copy
import itertools

from conftest import doc
from vchlib import adjudicate, checks, derive
from vchlib.checks import run_all


def errors(b, code, where=None):
    return [i for i in run_all(b).errors if i.code == code and (where is None or where in i.where)]


def test_the_examples_are_clean(b):
    assert run_all(b).errors == []


def test_the_rule_version_is_05_v0_9():
    assert adjudicate.RULE_VERSION == "05-v0.12"


# ================================================================ theta_reject guard
# r11: the split statistics come from the raw counts; for theta_reject `tp` counts the TRUE DEFECTS among the rejected clusters
# (docs/05 §5.7), so 0 of 60 and 0 of 45 give a true-defect share of 0 and Wilson uppers 0.0602 and 0.0787
GOOD = {"calibration": {"precision": 0.0, "recall": 0.3, "ci_low": 0.0, "ci_high": 0.0602, "n": 60, "tp": 0},
        "holdout": {"precision": 0.0, "recall": 0.3, "ci_low": 0.0, "ci_high": 0.0787, "n": 45, "tp": 0}, "generalised": True, "feasible": True}


def test_theta_reject_below_a_single_refute_weight_is_rejected(b):
    cal = doc(b, "calibration.yaml").data
    cal["result"]["thresholds"]["theta_reject"] = {"value": 1.0, **copy.deepcopy(GOOD),
                                                   "by_bucket": {"authz": {"value": 1.0, **copy.deepcopy(GOOD)}}}
    assert any(label == "theta_reject/authz" and "single" in msg for label, msg in checks.theta_problems(cal))


def test_theta_reject_above_every_refute_weight_is_accepted(b):
    cal = doc(b, "calibration.yaml").data
    cal["result"]["thresholds"]["theta_reject"] = {"value": 2.0, **copy.deepcopy(GOOD),
                                                   "by_bucket": {"authz": {"value": 2.0, **copy.deepcopy(GOOD)}}}
    assert not [p for p in checks.theta_problems(cal) if p[0].startswith("theta_reject")]


# ================================================================ sampled is not a signal
def test_a_self_declared_sampled_http_test_is_not_probabilistic(b):
    tc = doc(b, "testcase.idor.example.json").data
    tc["trials"]["sampling"] = "sampled"
    assert derive.probabilistic_signals(derive.Index(b), tc) == []


def test_declaring_sampled_without_a_target_signal_is_reported(b):
    doc(b, "testcase.idor.example.json").data["trials"]["sampling"] = "sampled"
    assert any("no target-side" in i.msg for i in errors(b, "E-TC-TRIALS", "testcase.idor"))


def test_a_silent_replay_of_a_declared_sampled_http_test_is_not_proof(b):
    tc, tr = doc(b, "testcase.idor.example.json").data, doc(b, "testresult.example.json").data
    tc["trials"]["sampling"] = "sampled"
    tr["replay_k"] = 0
    ix = derive.Index(b)
    assert derive.classify_result(ix, tr, ix.first("cluster", cluster_id=tr["cluster_ids"][0]).data)[0] == "E_inc"


# ================================================================ root_score: strongest vote per root
def test_a_weaker_vote_of_the_same_root_does_not_lower_s():
    assert derive.root_score([("nemotron3", 1.4633), ("claude", 1.4425), ("claude", 0.32)]) == round(1.4633 + 1.4425, 4)


def test_one_root_still_counts_once():
    assert derive.root_score([("claude", 1.44), ("claude", 1.44)]) == 1.44


def test_a_root_whose_votes_disagree_contributes_their_mean():
    assert derive.root_score([("claude", 1.2), ("claude", -0.8)]) == 0.2


# ================================================================ analyst disagreement fails closed
def test_a_disagreeing_eligible_analyst_makes_a_preregistered_fail_inconclusive(b):
    """The W4 FAIL of K-015 (nvidia) with openai test authors: claude_sonnet's analyst is eligible."""
    ag = doc(b, "agents.yaml").data
    ag["test_gen"]["model"] = ag["test_critic"]["model"] = "gpt_flagship"
    ix = derive.Index(b)
    tr = doc(b, "testresult.w4-k-015.example.json").data
    tr["interpreted_by"] = {"agent_id": "result_analyst_a", "family": "anthropic"}
    tr["interpretation"] = {"agrees": True, "rationale": "the FAIL is the violation the requirement names"}
    cl = ix.first("cluster", cluster_id="K-015").data
    assert derive.analyst_check(ix, tr, cl) == (True, None)
    assert derive.classify_result(ix, tr, cl)[0] == "E_proof"
    tr["interpretation"]["agrees"] = False
    assert derive.classify_result(ix, tr, cl)[0] == "E_inc"


def test_a_disagreeing_eligible_analyst_makes_a_preregistered_pass_inconclusive(b):
    ix = derive.Index(b)
    tr = doc(b, "testresult.llm-pass.example.json").data
    cl = ix.first("cluster", cluster_id=tr["cluster_ids"][0]).data
    assert derive.classify_result(ix, tr, cl)[0] == "E_pass"
    tr["interpretation"]["agrees"] = False
    assert derive.classify_result(ix, tr, cl)[0] == "E_inc"


# ================================================================ authors fail closed
def test_a_w4_test_with_unknown_authors_is_not_independent(b):
    ag = doc(b, "agents.yaml").data
    del ag["test_gen"], ag["test_critic"]
    ix = derive.Index(b)
    tr = doc(b, "testresult.w4-k-015.example.json").data
    cl = dict(ix.first("cluster", cluster_id="K-015").data, families=["openai"], lineages=["gpt"])
    assert derive.authors_independent(ix, tr, cl) is False


def test_w4_results_need_the_test_author_roles(b):
    ag = doc(b, "agents.yaml").data
    del ag["test_gen"], ag["test_critic"]
    msgs = [i.msg for i in errors(b, "E-AGENT-ROLES")]
    assert any("test_generator" in m for m in msgs) and any("test_critic" in m for m in msgs)


# ================================================================ contamination
def test_a_reproduced_canary_zeroes_the_models_weight(b):
    cal = doc(b, "calibration.yaml").data
    next(x for x in cal["result"]["contamination"]["canary_results"] if x["model_key"] == "nemotron_self")["reproduced"] = True
    assert derive.Index(b).weight("nemotron_self", "authz", cal["calibration_version"], "SUPPORT", "run-2026-09-23-001") == 0.0
    assert any("nemotron_self" in i.msg for i in errors(b, "E-CAL-CONTAMINATION"))


def test_a_sentinel_app_outside_the_holdout_is_reported(b):
    cal = doc(b, "calibration.yaml").data
    next(x for x in cal["config"]["corpus"] if x["sentinel"])["split"] = "calibration"
    assert any("sentinel" in i.msg for i in errors(b, "E-CAL-CONTAMINATION"))


def test_reading_the_holdout_before_preregistration_is_reported(b):
    cal = doc(b, "calibration.yaml").data
    cal["result"]["holdout_access_log"].append({"person_id": "alice", "at": "2026-07-01T09:00:00+08:00", "reason": "early"})
    assert any("registered_at" in i.msg for i in errors(b, "E-CAL-CONTAMINATION"))


def test_a_flagged_variant_gap_with_weight_warns(b):
    cal = doc(b, "calibration.yaml").data
    next(x for x in cal["result"]["contamination"]["variant_recall_gap"] if x["model_key"] == "nemotron_self")["flagged"] = True
    assert any(i.code == "W-CAL-CONTAMINATION" and "nemotron_self" in i.msg for i in run_all(b).warnings)


# ================================================================ holdout size
def test_a_threshold_does_not_generalise_on_a_tiny_holdout(b):
    cal = doc(b, "calibration.yaml").data
    # r11: consistent raw counts (1 of 1), so the ONLY problem is the size; with `tp` missing the split was reported as "not a
    # count", which passed this test without the holdout-size check
    cal["result"]["thresholds"]["theta_confirm"]["by_bucket"]["authz"]["holdout"] = \
        {"precision": 1.0, "recall": 1.0, "ci_low": round(checks.wilson_lower(1, 1), 4), "ci_high": round(checks.wilson_upper(1, 1), 4),
         "n": 1, "tp": 1}
    got = [(label, msg) for label, msg in checks.theta_problems(cal) if label == "theta_confirm/authz"]
    assert any("generalised on a holdout of 1 clusters" in msg for _, msg in got), got
    assert not any("not a count" in msg or "recomputed" in msg for _, msg in got), got


# ================================================================ abstention as a coin flip
def test_abstentions_count_as_coin_flips():
    assert checks.effective_counts({"n": 12, "correct": 12, "n_abstain": 5}) == (14.5, 17)
    assert checks.effective_counts({"n": 12, "correct": 12}) == (12, 12)


def test_abstaining_on_the_hard_cases_does_not_keep_the_weight(b):
    """Review r10 probe: 12 of 12 answered right and 5 abstentions (29 %, under abstain_rate_max) kept a = 0.9583."""
    cal = doc(b, "calibration.yaml").data
    rows = cal["result"]["weights"]
    row = next(r for r in rows if r["model_key"] == "nemotron_self" and r["cwe_bucket"] == "authz")
    for sk in ("support", "refute"):
        row[sk].update({"n": 12, "correct": 12, "n_abstain": 5})
    # what the 05-v0.8 rule computed: answered cases only
    k, a = cal["config"]["smoothing_k"], {}
    for sk in ("support", "refute"):
        mine = [r[sk] for r in rows if r["model_key"] == "nemotron_self"]
        abar = sum(x["correct"] for x in mine) / sum(x["n"] for x in mine)
        a[sk] = checks.smoothed_rate(12, 12, k, abar)
    lr = checks.lr_weights(a["support"], a["refute"])
    for sk in ("support", "refute"):
        row[sk].update({"a": round(a[sk], 4), "w": round(lr[sk], 4), "near_zero": False, "near_zero_reasons": []})
    assert any("nemotron_self/authz" in i.where for i in errors(b, "E-CAL-WEIGHT"))


# ================================================================ R8 is defence in depth
def test_row_11_needs_two_base_lineages_when_theta_is_above_every_single_weight():
    theta = 2.5
    grid = [0.5, 1.0, 1.5, 2.0, 2.49]
    for n in (1, 2, 3):
        for roots in itertools.product("ab", repeat=n):
            for ws in itertools.product(grid, repeat=n):
                s = derive.root_score(list(zip(roots, ws)))
                if s >= theta:
                    assert len(set(roots)) >= 2, (roots, ws, s)
