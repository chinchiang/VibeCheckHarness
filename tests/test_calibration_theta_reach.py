# SPDX-License-Identifier: Apache-2.0
"""A bucket threshold must be reachable: theta <= S_max (2026-11-22 internal review; docs/05 section 5.7, E-CAL-THETA).

The example calibration declared theta_confirm 2.5 feasible in the authz bucket, with 46 clusters confirmed by the vote
branch, while the bucket's support weights add up to 2.1607 (nvidia 1.1055 + anthropic 1.0552 + openai 0). S takes one
vote per independent observation (verdict.root_score), so no set of votes reaches 2.5; the validator checked only that a
threshold is above every single vote. checks.bucket_score_max recomputes S_max and theta_problems compares.

`test_..._is_rejected` tests failed before the fix and pass after it (tests/mutations/calibration_theta_reach.json); the
`..._is_accepted` tests check the bound is not too tight. See CONTRIBUTING.md."""
import copy

import pytest

from conftest import codes, doc, split_stats
from vchlib import checks
from vchlib.checks import run_all

AUTHZ_SUPPORT_MAX = 2.1607      # nemotron_self 1.1055 + claude_sonnet 1.0552 + gpt_oss_self 0
AUTHZ_REFUTE_MAX = 2.1171       # nemotron_self 1.1384 + claude_sonnet 0.9787 + gpt_oss_self 0
GOOD_REJECT = {"calibration": split_stats(0, 60), "holdout": split_stats(0, 55, "holdout"), "generalised": True, "feasible": True}


def cal_of(b):
    return doc(b, "calibration.yaml").data


def reach(problems, label):
    return [msg for lab, msg in problems if lab == label and "largest score" in msg]


def observation(b):
    return checks.Ctx(b).ix.independence_key


def test_the_example_states_the_bucket_maxima_the_tests_assume(b):
    cal, obs = cal_of(b), observation(b)
    assert checks.bucket_score_max(cal["result"]["weights"], "authz", "support", obs) == AUTHZ_SUPPORT_MAX
    assert checks.bucket_score_max(cal["result"]["weights"], "authz", "refute", obs) == AUTHZ_REFUTE_MAX


def test_the_example_calibration_is_reachable_and_clean(b):
    cal = cal_of(b)
    assert cal["result"]["thresholds"]["theta_confirm"]["by_bucket"]["authz"]["value"] <= AUTHZ_SUPPORT_MAX
    assert checks.theta_problems(cal, observation(b)) == []
    assert "E-CAL-THETA" not in codes(b)


def test_theta_confirm_above_the_reachable_score_is_rejected(b):
    """The value the example used to declare: feasible at 2.5 where the weights reach 2.1607."""
    cal = cal_of(b)
    cal["result"]["thresholds"]["theta_confirm"]["by_bucket"]["authz"]["value"] = 2.5
    got = reach(checks.theta_problems(cal, observation(b)), "theta_confirm/authz")
    assert got and "2.5 > 2.1607" in got[0] and "support" in got[0], got
    issues = [i for i in run_all(b).issues if i.code == "E-CAL-THETA"]
    assert any("largest score" in i.msg and "theta_confirm/authz" in i.msg for i in issues), [i.msg for i in issues]


@pytest.mark.parametrize("value, bad", [(AUTHZ_SUPPORT_MAX, False), (2.1, False), (2.17, True), (2.2, True)])
def test_the_bound_is_the_reachable_score_itself(b, value, bad):
    cal = cal_of(b)
    cal["result"]["thresholds"]["theta_confirm"]["by_bucket"]["authz"]["value"] = value
    assert bool(reach(checks.theta_problems(cal, observation(b)), "theta_confirm/authz")) is bad


def test_theta_reject_above_the_reachable_refute_score_is_rejected(b):
    cal = cal_of(b)
    cal["result"]["thresholds"]["theta_reject"] = {"value": 2.2, **copy.deepcopy(GOOD_REJECT),
                                                   "by_bucket": {"authz": {"value": 2.2, **copy.deepcopy(GOOD_REJECT)}}}
    got = reach(checks.theta_problems(cal, observation(b)), "theta_reject/authz")
    assert got and "2.2 > 2.1171" in got[0] and "refute" in got[0], got


def test_theta_reject_within_the_reachable_refute_score_is_accepted(b):
    cal = cal_of(b)
    cal["result"]["thresholds"]["theta_reject"] = {"value": 2.1, **copy.deepcopy(GOOD_REJECT),
                                                   "by_bucket": {"authz": {"value": 2.1, **copy.deepcopy(GOOD_REJECT)}}}
    assert not [p for p in checks.theta_problems(cal, observation(b)) if p[0].startswith("theta_reject")]


def test_models_of_one_observation_count_once(b):
    """gpt_flagship is in gpt_oss_self's family (openai), one observation: giving both a weight adds only the larger."""
    weights = copy.deepcopy(cal_of(b)["result"]["weights"])
    for r in weights:
        if r["model_key"] == "gpt_oss_self" and r["cwe_bucket"] == "authz":
            r["support"]["w"] = 0.5
    twin = copy.deepcopy(next(r for r in weights if r["model_key"] == "gpt_oss_self" and r["cwe_bucket"] == "authz"))
    twin["model_key"], twin["support"]["w"] = "gpt_flagship", 0.9
    obs = observation(b)
    assert obs("gpt_flagship") == obs("gpt_oss_self") != obs("claude_sonnet")
    assert checks.bucket_score_max(weights + [twin], "authz", "support", obs) == round(AUTHZ_SUPPORT_MAX + 0.9, 4)
    # without the observation mapping every model is its own observation: a looser bound, never a tighter one
    assert checks.bucket_score_max(weights + [twin], "authz", "support") == round(AUTHZ_SUPPORT_MAX + 0.9 + 0.5, 4)


def test_other_buckets_and_malformed_weights_do_not_count(b):
    weights = copy.deepcopy(cal_of(b)["result"]["weights"])
    weights += [{"model_key": "claude_sonnet", "cwe_bucket": "injection", "support": {"w": 9.0}},
                {"model_key": "x", "cwe_bucket": "authz", "support": {"w": "9"}},
                {"model_key": "y", "cwe_bucket": "authz", "support": {"w": True}},
                {"model_key": "z", "cwe_bucket": "authz", "support": None}, "not a row"]
    assert checks.bucket_score_max(weights, "authz", "support", observation(b)) == AUTHZ_SUPPORT_MAX


def test_the_validator_groups_weights_by_observation(b):
    """A second anthropic model with claude_sonnet's weights adds nothing to S_max (one family, one observation): a
    threshold of 2.5 stays out of reach for the validator, although the per-model sum would be 3.2159."""
    cal = cal_of(b)
    twin = copy.deepcopy(next(r for r in cal["result"]["weights"] if r["model_key"] == "claude_sonnet" and r["cwe_bucket"] == "authz"))
    twin["model_key"] = "claude_opus_48"
    cal["result"]["weights"].append(twin)
    cal["result"]["thresholds"]["theta_confirm"]["by_bucket"]["authz"]["value"] = 2.5
    assert checks.bucket_score_max(cal["result"]["weights"], "authz", "support") == 3.2159
    issues = [i.msg for i in run_all(b).issues if i.code == "E-CAL-THETA"]
    assert any("theta_confirm/authz" in m and "2.5 > 2.1607" in m for m in issues), issues
