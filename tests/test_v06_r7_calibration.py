# SPDX-License-Identifier: Apache-2.0
"""v0.6 review r7, group 3b: calibration.

3.2 vote weights are log likelihood ratios of both calibrated rates (ln TPR/FPR for SUPPORT, ln TNR/FNR for REFUTE);
    an unreliable side zeroes both. v0.4-v0.5 weighted each side by its own accuracy, so an always-support verifier
    earned a high support weight.
3.5 theta_confirm / theta_reject are per CWE bucket (a missing bucket or generalised: false is +inf); the
    high_precision_rules rows are recomputed from raw counts (Clopper-Pearson, n >= 40, holdout).
3.6 a model weighs 0 unless its version and the run's w3-verify prompt are the calibrated ones; an empty
    valid_for_model_keys means no model is valid.
3.9 independence is judged on the base lineage (models.yaml derived_from).
"""
import math

import pytest

from conftest import doc
from vchlib import checks, derive
from vchlib.checks import Ctx, run_all

CAL, RUN = "calibration.yaml", "run.example.json"


def errors(b, code, where=None):
    return [i for i in run_all(b).errors if i.code == code and (where is None or where in i.where)]


def row(b, mk, bucket):
    return next(r for r in doc(b, CAL).data["result"]["weights"] if r["model_key"] == mk and r["cwe_bucket"] == bucket)


# ================================================================ 3.2 likelihood-ratio weights
def test_an_always_support_verifier_carries_no_information():
    """TPR 0.95 and TNR 0.05: it supports almost everything, so SUPPORT says nothing (v0.5: w = 2*0.95-1 = 0.9)."""
    w = checks.lr_weights(0.95, 0.05)
    assert w["support"] == pytest.approx(0.0, abs=1e-9) and w["refute"] == 0.0


def test_the_weights_use_both_sides():
    w = checks.lr_weights(0.8467, 0.8252)
    assert w["support"] == pytest.approx(math.log(0.8467 / 0.1748)) and w["refute"] == pytest.approx(math.log(0.8252 / 0.1533))


def test_the_example_weights_are_recomputed(b):
    assert not errors(b, "E-CAL-WEIGHT")
    assert row(b, "nemotron_self", "authz")["support"]["w"] == 1.3179           # r10 abstentions; r8 prior: 1.4633; was 1.5775


def test_the_old_accuracy_weight_is_rejected(b):
    row(b, "nemotron_self", "authz")["support"]["w"] = 0.6933                  # v0.5: 2a - 1
    assert any("nemotron_self/authz/support" in i.where for i in errors(b, "E-CAL-WEIGHT"))


def test_an_unreliable_side_zeroes_both(b):
    """nemotron_self/llm_specific: the refute side is near zero, so the support weight (v0.5: 0.6222) is 0 too."""
    r = row(b, "nemotron_self", "llm_specific")
    assert r["refute"]["near_zero"] and not r["support"]["near_zero"] and r["support"]["w"] == 0
    r["support"]["w"] = 1.2834
    assert any("llm_specific/support" in i.where for i in errors(b, "E-CAL-WEIGHT"))


# ================================================================ 3.5 thresholds per bucket
def test_thresholds_are_per_bucket(b):
    ix = derive.Index(b)
    assert ix.thresholds("authz") == (2.5, None)
    assert ix.thresholds("llm_specific") == (None, None)           # not feasible there
    assert ix.thresholds("injection") == (None, None)              # no threshold searched for the bucket


def test_a_threshold_that_did_not_generalise_is_disabled(b):
    doc(b, CAL).data["result"]["thresholds"]["theta_confirm"]["by_bucket"]["authz"]["generalised"] = False
    assert derive.Index(b).thresholds("authz") == (None, None)


def test_the_pooled_threshold_is_not_used(b):
    th = doc(b, CAL).data["result"]["thresholds"]["theta_confirm"]
    del th["by_bucket"]["authz"]
    assert th["value"] == 2.5 and derive.Index(b).thresholds("authz")[0] is None


def test_by_bucket_is_required(b):
    del doc(b, CAL).data["result"]["thresholds"]["theta_confirm"]["by_bucket"]
    assert any("by_bucket is required" in i.msg for i in errors(b, "E-CAL-THETA"))


def test_bucket_thresholds_are_checked(b):
    doc(b, CAL).data["result"]["thresholds"]["theta_confirm"]["by_bucket"]["llm_specific"]["value"] = 1.0   # feasible: false
    assert any("theta_confirm/llm_specific" in i.msg for i in errors(b, "E-CAL-THETA"))


HP = {"adapter": "opengrep:scan", "rule_id": "r", "tool_version": "1.6.0", "cwe_bucket": "authz",
      "n": 54, "tp": 53, "fp": 1, "precision_lower95": 0.9011, "holdout_n": 12, "holdout_tp": 12,
      "n_apps": 54, "holdout_n_apps": 12}                                # r13: one hit per application, so n_eff = n


def test_a_measured_rule_passes():
    assert checks.high_precision_problems(dict(HP), 0.9) == []
    assert checks.clopper_pearson_lower(40, 40) == pytest.approx(0.9119, abs=1e-4)      # docs/05 §5.10
    assert checks.clopper_pearson_lower(39, 40) == pytest.approx(0.8684, abs=1e-4)


@pytest.mark.parametrize("change, why", [
    ({"precision_lower95": 0.95}, "recomputed"),                     # a declared bound the counts do not give
    ({"n": 53, "n_apps": 53}, "tp + fp"),
    ({"n": 39, "tp": 39, "fp": 0, "precision_lower95": 0.9097, "n_apps": 39}, "< 40"),
    ({"tp": 52, "fp": 2, "precision_lower95": 0.8725}, "high_precision_min"),
    ({"holdout_n": 8, "holdout_tp": 8, "holdout_n_apps": 8}, "holdout"),
    ({"holdout_tp": 10}, "holdout"),                                 # 10/12 = 0.83 < 0.85
])
def test_a_rule_is_recomputed_from_its_counts(change, why):
    probs = checks.high_precision_problems(dict(HP, **change), 0.9)
    assert any(why in p for p in probs), probs


def test_a_bad_rule_is_reported(b):
    doc(b, CAL).data["result"]["high_precision_rules"] = [dict(HP, precision_lower95=0.97)]
    assert errors(b, "E-CAL-HIGH-PRECISION")


# ================================================================ 3.6 model and prompt changes
def test_an_empty_valid_for_list_means_none(b):
    ix = derive.Index(b)
    run_id = doc(b, RUN).data["run_id"]
    assert ix.weight("nemotron_self", "authz", 3, "SUPPORT", run_id) == 1.3179
    doc(b, CAL).data["result"]["valid_for_model_keys"] = []
    assert derive.Index(b).weight("nemotron_self", "authz", 3, "SUPPORT", run_id) == 0


def test_a_new_model_version_weighs_nothing(b):
    run_id = doc(b, RUN).data["run_id"]
    doc(b, "models.yaml").data["claude_sonnet"]["litellm"] = "anthropic/claude-sonnet-5-1"
    ix = derive.Index(b)
    assert "calibrated as version" in ix.calibrated_setup_problem("claude_sonnet", run_id)
    assert ix.weight("claude_sonnet", "authz", 3, "SUPPORT", run_id) == 0


def test_a_new_verifier_prompt_weighs_nothing(b):
    run = doc(b, RUN).data
    next(t for t in run["prompt_templates"] if t["template_id"] == "w3-verify")["sha256"] = "sha256:" + "9" * 64
    ix = derive.Index(b)
    assert "prompt" in ix.calibrated_setup_problem("nemotron_self", run["run_id"])
    assert ix.weight("nemotron_self", "authz", 3, "SUPPORT", run["run_id"]) == 0


def test_the_votes_follow(b):
    """V-014-1's nemotron vote loses its weight when the verifier prompt changes (E-DERIVED on the vote)."""
    run = doc(b, RUN).data
    next(t for t in run["prompt_templates"] if t["template_id"] == "w3-verify")["sha256"] = "sha256:" + "9" * 64
    assert any("verdict.k-014" in i.where and "weight" in i.msg for i in errors(b, "E-DERIVED"))


# ================================================================ 3.9 lineage roots
def test_a_derived_lineage_is_not_independent(b):
    k = derive.Index(b).first("cluster", cluster_id="K-015").data
    assert k["lineages"] == ["nemotron3"] and "claude_sonnet" in checks.eligible_verifier_models(Ctx(b), k)
    doc(b, "models.yaml").data["claude_sonnet"]["derived_from"] = "nemotron3"     # suppose it were distilled from Nemotron
    assert derive.Index(b).lineage_root("claude") == "nemotron3"
    assert "claude_sonnet" not in checks.eligible_verifier_models(Ctx(b), k)


def test_a_derived_voter_is_not_valid(b):
    """V-015-1: claude_sonnet's vote on K-015 (reported by nemotron3) is valid; derived from nemotron3, it is not."""
    ix = derive.Index(b)
    v = doc(b, "verdict.k-015-w3.example.json").data
    k = ix.first("cluster", cluster_id="K-015").data
    assert v["votes"][0]["voter_lineage"] == "claude" and derive.vote_valid(v["votes"][0], k, ix)
    doc(b, "models.yaml").data["claude_sonnet"]["derived_from"] = "nemotron3"
    assert not derive.vote_valid(v["votes"][0], k, derive.Index(b))


def test_a_lineage_cycle_terminates(b):
    models = doc(b, "models.yaml").data
    models["claude_sonnet"]["derived_from"] = "nemotron3"
    models["nemotron_self"]["derived_from"] = "claude"
    assert derive.Index(b).lineage_root("claude") in ("claude", "nemotron3")


# ================================================================ single sub-checks (mutation sweep)
def test_a_weak_likelihood_ratio_is_near_zero(b):
    """Support 90/100 but refute only 25/100: ln(TPR / FPR) is about 0.18 < w_min, so the support side lists
    w_below_min (its own Wilson bound and n are fine)."""
    rows = doc(b, CAL).data["result"]["weights"]
    rows.append({"model_key": "claude_sonnet", "cwe_bucket": "injection",
                 "support": {"n": 100, "correct": 90, "a": 0, "w": 0, "near_zero": True, "near_zero_reasons": ["wilson_lower_le_max"]},
                 "refute": {"n": 100, "correct": 25, "a": 0, "w": 0, "near_zero": True, "near_zero_reasons": ["wilson_lower_le_max"]}})
    assert any("injection/support" in i.where and "w_below_min" in i.msg for i in errors(b, "E-CAL-WEIGHT"))


K014_RULE = {"adapter": "opengrep:scan", "rule_id": "vc.authz.update-without-owner", "tool_version": "1.6.0", "cwe_bucket": "authz"}


def test_strong_tool_corroboration_uses_the_counts(b):
    c0 = Ctx(b)
    k = c0.ix.first("cluster", cluster_id="K-014").data
    ref = k["sarif_refs"][0]
    cal = doc(b, CAL).data["result"]
    cal["high_precision_rules"] = [dict(K014_RULE, n=120, tp=117, fp=3, precision_lower95=0.9287, holdout_n=30, holdout_tp=29, n_apps=120, holdout_n_apps=30)]
    assert checks.sarif_is_strong(Ctx(b), k, ref)
    cal["high_precision_rules"] = [dict(K014_RULE, n=40, tp=39, fp=1, precision_lower95=0.95, holdout_n=30, holdout_tp=29, n_apps=40, holdout_n_apps=30)]
    assert not checks.sarif_is_strong(Ctx(b), k, ref)                 # the declared 0.95 is not what 39/40 gives


def test_the_analyst_compares_base_lineages(b):
    """gpt_flagship (lineage gpt) analyses a cluster reported by gpt-oss; neither wrote the test. Derived from gpt-oss, it
    shares the reporter's base lineage and is not eligible."""
    ix = derive.Index(b)
    tr = next(d.data for d in b.docs if d.kind == "testresult" and d.data.get("result_id") == "R-TC-012-01-1")
    tr.update(interpreted_by={"agent_id": "result_analyst_b", "family": "openai"}, interpretation={"agrees": True, "rationale": "x"})
    k = dict(ix.first("cluster", cluster_id="K-005").data, families=["anthropic"], lineages=["gpt-oss"])
    assert derive.analyst_check(ix, tr, k) == (True, None)
    doc(b, "models.yaml").data["gpt_flagship"]["derived_from"] = "gpt-oss"
    assert derive.analyst_check(derive.Index(b), tr, k) == (False, None)


def test_a_verdict_takes_its_bucket_threshold(b):
    """V-011-1 is in llm_specific, where no threshold was feasible: its theta_confirm is null, not authz's 2.5."""
    v = doc(b, "verdict.k-011-w3.example.json").data
    assert v["theta_confirm"] is None and doc(b, "verdict.k-014-w3.example.json").data["theta_confirm"] == 2.5
    v["theta_confirm"] = 2.5
    assert any("verdict.k-011-w3" in i.where and "theta_confirm" in i.msg for i in errors(b, "E-DERIVED"))


def test_a_stored_valid_vote_from_a_derived_lineage_is_reported(b):
    doc(b, "models.yaml").data["claude_sonnet"]["derived_from"] = "nemotron3"
    assert any("base lineage" in i.msg for i in errors(b, "E-VERDICT-VOTE", "verdict.k-015-w3"))


def test_diversity_counts_base_lineages(b):
    models = doc(b, "models.yaml").data
    for k in ("gpt_flagship", "gpt_oss_self", "nemotron_self", "claude_opus_48"):
        models[k]["derived_from"] = "claude"                         # every verifier shares claude's base
    assert any("claude" in i.msg for i in errors(b, "E-DIVERSITY-VERIFIER"))
