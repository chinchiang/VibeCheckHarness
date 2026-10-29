# SPDX-License-Identifier: Apache-2.0
"""Review r11 (2026-10-28), group 2: adjudication parameters and independence (rule_version 05-v0.10).

Probes of the review:
  - calibration.yaml's policy constants (near-zero rules, smoothing prior, threshold-search limits) and the thresholds'
    split statistics were only checked for self-consistency: wilson_lower_max 0 plus theta 1.4, re-pinned and re-signed,
    turned two LIKELY / UNCORROBORATED clusters CONFIRMED_CORROBORATED (E-CAL-POLICY; split statistics from tp of n);
  - a same-family reporter added to a cluster after a weighted REFUTE was cast voided that vote: DISPUTED became a
    LIKELY nobody could check and no G2 saw (members_at_vote, R15, no_eligible_verifier clusters go to G2);
  - a model the canary check never covered kept its weight (E-CAL-CONTAMINATION);
  - a pre-registered PASS needed no independent authors while a pre-registered FAIL did (classify_result);
  - a regression run had no state for a fixed defect: the PASS landed on UNCORROBORATED (R14, FIXED).
Each test failed before the change and passes after it (tests/mutations/r11_verdict.json); see CONTRIBUTING.md."""
import copy

import pytest

from conftest import doc, rederive
from vchlib import adjudicate as adj
from vchlib import checks, crypto, derive
from vchlib.canonical import content_hash
from vchlib.checks import Ctx, run_all

RUN = "run-2026-09-23-001"


def errors(b, code, where=None):
    return [i for i in run_all(b).errors if i.code == code and (where is None or where in i.where)]


def pin_calibration(b, keys):
    e = doc(b, "engagement.yaml").data
    e["config_pins"]["calibration"] = content_hash(doc(b, "calibration.yaml").data)
    e["signatures"] = [crypto.sign_document(e, s["signer"], keys[s["signer"]]) for s in e["signatures"]]


def test_the_examples_are_clean_and_the_rule_version_is_05_v0_10(b):
    assert adj.RULE_VERSION == "05-v0.14" and run_all(b).errors == []


# ================================================================ calibration policy
@pytest.mark.parametrize("edit, text", [
    (lambda cfg: cfg["near_zero_rules"].__setitem__("wilson_lower_max", 0.0), "near_zero_rules.wilson_lower_max 0.0 != 0.5"),
    (lambda cfg: cfg["near_zero_rules"].__setitem__("n_min", 1), "near_zero_rules.n_min 1 != 10"),
    (lambda cfg: cfg.__setitem__("smoothing_k", 0), "smoothing_k 0 != 10"),
    (lambda cfg: cfg["threshold_search"].__setitem__("min_clusters", 1), "threshold_search.min_clusters 1 != 40"),
    (lambda cfg: cfg["threshold_search"].__setitem__("confirm_precision_floor", 0.0), "confirm_precision_floor 0.0 != 0.9"),
])
def test_a_policy_constant_that_differs_from_docs_05_is_an_error(b, keys, edit, text):
    edit(doc(b, "calibration.yaml").data["config"])
    pin_calibration(b, keys)
    assert any(text in i.msg for i in errors(b, "E-CAL-POLICY"))


def test_the_review_probe_no_longer_confirms_anything(b, keys):
    """The r11 probe: wilson_lower_max 0 and theta_confirm 1.4, re-pinned and re-signed, with every verdict settled by
    the validator itself. Now the policy error stands whatever the verdicts say."""
    cal = doc(b, "calibration.yaml").data
    cal["config"]["near_zero_rules"]["wilson_lower_max"] = 0.0
    cal["result"]["thresholds"]["theta_confirm"]["by_bucket"]["authz"]["value"] = 1.4
    pin_calibration(b, keys)
    assert errors(b, "E-CAL-POLICY")


def test_a_thresholds_split_statistics_come_from_its_raw_counts(b, keys):
    cs = doc(b, "calibration.yaml").data["result"]["thresholds"]["theta_confirm"]["by_bucket"]["authz"]["calibration"]
    cs["precision"] = 0.99                                       # tp 43 of n 46 is 0.9348
    pin_calibration(b, keys)
    assert any("calibration.precision 0.99 but recomputed 0.9348" in i.msg for i in errors(b, "E-CAL-THETA"))


def test_a_wilson_bound_that_does_not_match_the_counts_is_an_error(b, keys):
    ho = doc(b, "calibration.yaml").data["result"]["thresholds"]["theta_confirm"]["holdout"]
    ho["ci_low"] = 0.9                                           # tp 47 of n 52 from 13 applications gives 0.7839 (r13: n_eff)
    pin_calibration(b, keys)
    assert any("holdout.ci_low 0.9 but recomputed 0.7839" in i.msg for i in errors(b, "E-CAL-THETA"))


def test_tp_above_n_is_not_a_count(b, keys):
    cs = doc(b, "calibration.yaml").data["result"]["thresholds"]["theta_confirm"]["calibration"]
    cs["tp"] = 70
    pin_calibration(b, keys)
    assert any("is not a count" in i.msg for i in errors(b, "E-CAL-THETA"))


def test_wilson_upper_matches_the_known_value():
    assert round(checks.wilson_upper(0, 60), 4) == 0.0602          # docs/05 §5.7: 0 of 60 rejected -> upper about 0.060 and checks.wilson_upper(0, 0) == 0.0


def test_every_weighted_model_needs_a_canary_result(b, keys):
    cal = doc(b, "calibration.yaml").data
    cal["result"]["contamination"]["canary_results"] = [x for x in cal["result"]["contamination"]["canary_results"] if x["model_key"] != "nemotron_self"]
    pin_calibration(b, keys)
    assert any("nemotron_self has a non-zero weight but no canary_results entry" in i.msg for i in errors(b, "E-CAL-CONTAMINATION"))


# ================================================================ vote-time membership (R15) and G2 for no_eligible_verifier
REFUTE = {"voter_agent_id": "ver_1", "voter_model_key": "nemotron_self", "voter_family": "nvidia", "voter_lineage": "nemotron3",
          "stance": "REFUTE", "rationale": "tenant filter exists upstream", "cited_evidence": ["routes/invoices.ts:42"],
          "fallback_used": None, "anonymized": True, "order_randomized": True, "valid": True, "weight": 0, "weighted_valid": False,
          "voted_after_round": 1}


def nvidia_member(b, rnd):
    """F-900: a copy of F-017 reported by the nvidia reviewer in round `rnd`, added to K-005 (and the run)."""
    f17 = doc(b, "finding.example.json")
    new = copy.deepcopy(f17)
    new.path = f17.path.replace("finding.example.json", "finding.f-900.example.json")
    new.data.update(finding_id="F-900", title="F-017 duplicate by the nvidia reviewer",
                    reporter={"agent_id": "rev_c", "model_key": "nemotron_self", "family": "nvidia", "lineage": "nemotron3", "round": rnd})
    b.docs.append(new)
    doc(b, "run.example.json").data["findings"].append("F-900")
    cl = doc(b, "cluster.example.json").data
    cl["member_finding_ids"].append("F-900")
    cl["families"].append("nvidia"); cl["lineages"].append("nemotron3")       # checked, not derived (E-CLUSTER-FAMILIES)


def settle(b, keys, suffix="verdict.example.json"):
    c = Ctx(b)
    v = doc(b, suffix).data
    cl = c.ix.first("cluster", cluster_id=v["cluster_id"]).data
    x = checks.verdict_inputs(c, v, cl)
    out = adj.adjudicate(x)
    v.update(status=out.status, status_cap=out.status_cap, advisory=out.advisory,
             annotations=[{"kind": k, "reason": "probe"} for k in sorted(out.annotations)], rule_trace=list(out.rules))
    rederive(b, keys)
    return out, x


def test_a_refute_cast_before_a_same_family_member_joined_stays_valid(b, keys):
    v = doc(b, "verdict.example.json").data                      # V-005-1, K-005 (openai + anthropic), LIKELY
    v["missing_votes"], v["votes"] = [], [copy.deepcopy(REFUTE)]
    nvidia_member(b, 2)                                          # joins in round 2, after the round-1 vote
    rederive(b, keys)
    out, x = settle(b, keys)
    assert x.weighted_refute and out.status == "DISPUTED" and "refute_by_later_member_family" in out.annotations and "R15" in out.rules
    assert v["votes"][0]["weighted_valid"] is True


def test_a_member_present_at_the_vote_still_voids_it(b, keys):
    v = doc(b, "verdict.example.json").data
    v["missing_votes"], v["votes"] = [], [copy.deepcopy(REFUTE)]
    nvidia_member(b, 1)                                          # already a member when the vote was cast
    rederive(b, keys)
    out, x = settle(b, keys)
    assert not x.weighted_refute and "refute_by_later_member_family" not in out.annotations


def test_members_at_vote_follow_the_reporter_rounds(b):
    nvidia_member(b, 2)
    cl, ix = doc(b, "cluster.example.json").data, derive.Index(b)
    assert derive.members_at_vote(ix, {"voted_after_round": 1}, cl)[0] == ["anthropic", "openai"]
    assert derive.members_at_vote(ix, {"voted_after_round": 2}, cl)[0] == ["anthropic", "nvidia", "openai"]
    assert derive.members_at_vote(ix, {}, cl)[0] == cl["families"]       # no field: every member counts


def test_voted_after_round_is_required(b, keys):
    del doc(b, "verdict.k-014-w3.example.json").data["votes"][0]["voted_after_round"]
    rederive(b, keys)
    assert errors(b, "E-SCHEMA", "verdict.k-014-w3")


def test_a_cluster_with_no_eligible_verifier_needs_a_g2_decision(b, keys):
    nvidia_member(b, 1)                                          # K-005 now holds every verifier family
    rederive(b, keys)
    settle(b, keys)
    assert checks.derived_no_eligible_verifier(Ctx(b), doc(b, "cluster.example.json").data)
    assert any("K-005" in i.msg and "no eligible verifier" in i.msg and "no G2 decision" in i.msg for i in errors(b, "E-PIPELINE"))


# ================================================================ E_pass needs independent authors
def test_a_preregistered_pass_by_the_reporting_family_is_inconclusive(b, monkeypatch):
    """The qualified PASS of the example (pre-registered, no eligible analyst) with its test authors judged not
    independent, as a W4 test written and critiqued by the reporting family is: E_inc, as the FAIL side already was."""
    ix = derive.Index(b)
    tr, cl = doc(b, "testresult.llm-pass.example.json").data, doc(b, "cluster.k-011.example.json").data
    assert derive.classify_result(ix, tr, cl)[0] == "E_pass"
    monkeypatch.setattr(derive, "authors_independent", lambda ix_, tr_, cl_: False)
    monkeypatch.setattr(derive, "analyst_check", lambda ix_, tr_, cl_: (False, None))     # no eligible analyst either
    cls, why = derive.classify_result(ix, tr, cl)
    assert cls == "E_inc" and "independent authors" in why


# ================================================================ FIXED (R14)
def test_a_fixed_regression_cluster_is_decided_by_r14():
    out = adj.adjudicate(adj.Inputs(regression_fixed=True, evidence={"E_pass"}, weighted_support=True, score=5.0, theta_confirm=2.5))
    assert (out.status, out.row, out.rules) == ("FIXED", 14, ["R14"])
    assert adj.trace_statuses(out) == ["FIXED"]


def test_r14_yields_to_lane_a_and_g2_rejection():
    assert adj.adjudicate(adj.Inputs(regression_fixed=True, lane_a=True)).status == "UNCORROBORATED"
    assert adj.adjudicate(adj.Inputs(regression_fixed=True, g2_rejected=True)).status == "REJECTED"


def test_regression_fixed_is_derived_from_the_parent_verdict_and_the_pass(b):
    c = Ctx(b)
    run = {"run_id": "run-2026-11-01-001", "run_kind": "regression", "parent_run_id": RUN}
    cluster = {"cluster_id": "K-901", "run_id": run["run_id"], "carried_from": {"run_id": RUN, "cluster_id": "K-005", "fingerprint": "x"}}
    # r12: the PASS re-runs the testcase whose result proved the source (V-005-2's E_proof is R-TC-012-01-1, TC-012-01)
    proof = content_hash(doc(b, "testresult.example.json").data)
    v = {"test_evidence": {"class": "E_pass", "results": [{"result_ref": proof, "class": "E_pass", "positive_control": True, "reason": "x"}]}}
    assert checks.regression_fixed(c, v, cluster, run)                      # V-005-2 is CONFIRMED_EXECUTABLE
    assert not checks.regression_fixed(c, v, cluster, dict(run, run_kind="followup"))
    assert not checks.regression_fixed(c, v, dict(cluster, carried_from={"run_id": RUN, "cluster_id": "K-011", "fingerprint": "x"}), run)   # V-011-2 is UNCORROBORATED
    v["test_evidence"]["results"][0]["positive_control"] = None
    assert not checks.regression_fixed(c, v, cluster, run)
    v["test_evidence"]["results"][0]["positive_control"] = True
    v["test_evidence"]["results"].append({"result_ref": "sha256:" + "1" * 64, "class": "E_fail_u", "positive_control": None, "reason": "x"})
    assert not checks.regression_fixed(c, v, cluster, run)


def test_fixed_is_a_final_status_and_never_provisional():
    assert "FIXED" in checks.FINAL_STATUSES
    out = adj.adjudicate(adj.Inputs(regression_fixed=True))
    assert out.row in (1, 2, 3, 4, 5, 10, 14)


def test_r14_never_fires_without_regression_fixed():
    import itertools
    for ev, sup, ref, g2 in itertools.product([set(), {"E_pass"}, {"E_proof"}], [False, True], [False, True], [False, True]):
        out = adj.adjudicate(adj.Inputs(evidence=ev, weighted_support=sup, weighted_refute=ref, g2_rejected=g2, pass_positive=True))
        assert out.status != "FIXED" and "R14" not in out.rules
