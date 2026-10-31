# SPDX-License-Identifier: Apache-2.0
"""External review of 2823823 (docs/evidence/review-2026-10-28-r11.md §9), PR5. Each defect test failed on the PR4 head
and passes with the fix; see CONTRIBUTING.md.

  calibration  the schema bounds every probability to 0..1 (differences and kappa to -1..1); for theta_reject the split
               statistics' `tp` counts the TRUE DEFECTS among the rejected clusters (docs/05 §5.7), so the true-defect
               share is precision and its Wilson upper bound is ci_high (r11 PR2 read 1 - precision, which made 60
               rejected clusters with no true defect infeasible and `tp = n` feasible); and 45 is the smallest n for
               which the 0.08 Wilson cap can be met;
  G4           one rule for "approved": an identical later accept does not move the approval, a later reject withdraws
               it for new dispatches but not for a result that ran under it, and adjudication agrees with the validator.
"""
import copy

import pytest

from conftest import doc, split_stats
from vchlib import checks
from vchlib.checks import run_all, wilson_lower, wilson_upper

ROOT_DOCS = __import__("pathlib").Path(__file__).resolve().parents[1] / "docs"


def errors(b, code, where=None):
    return [i for i in run_all(b).errors if i.code == code and (where is None or where in i.where)]


# ================================================================ calibration: schema bounds
def _set(d, path, value):
    for k in path[:-1]:
        d = d[k]
    d[path[-1]] = value


BOUNDED = [
    (("result", "thresholds", "theta_confirm", "calibration", "precision"), 1.2),
    (("result", "thresholds", "theta_confirm", "holdout", "ci_low"), -0.1),
    (("result", "thresholds", "theta_confirm", "calibration", "ci_high"), 1.0001),
    (("config", "threshold_search", "reject_wilson_upper_max"), 2),
    (("config", "near_zero_rules", "wilson_lower_max"), 1.5),
    (("result", "primary_hypothesis", "psi_observed"), 1.1),
    (("result", "primary_hypothesis", "delta"), 1.5),
    (("result", "exploratory", "precision"), 1.3),
    (("result", "exploratory", "recall_diff_vs_arm3"), -2),
    (("result", "annotator_agreement", 0, "kappa"), 2),
    (("result", "metrics", "M-11", "by_model", 0, "value"), 1.2),
]


@pytest.mark.parametrize("path,value", BOUNDED, ids=[".".join(map(str, p)) for p, _ in BOUNDED])
def test_a_probability_outside_its_range_is_a_schema_error(b, path, value):
    _set(doc(b, "calibration.yaml").data, path, value)
    assert any("calibration" in i.where for i in errors(b, "E-SCHEMA"))


def test_a_value_inside_its_range_stays_valid(b):
    assert run_all(b).errors == [] and errors(b, "E-SCHEMA") == []


# ================================================================ calibration: theta_reject counts true defects
def stats(tp, n, split="calibration"):
    return split_stats(tp, n, split)          # r14: the clusters are spread over the corpus applications of the split


def reject(cal_tp, cal_n, ho_tp=0, ho_n=45, generalised=True):
    return {"value": 2.0, "feasible": True, "generalised": generalised, "by_bucket": {},
            "calibration": stats(cal_tp, cal_n), "holdout": stats(ho_tp, ho_n, "holdout")}


def reject_problems(b, thr):
    cal = copy.deepcopy(doc(b, "calibration.yaml").data)
    cal["result"]["thresholds"]["theta_reject"] = thr
    return [p for p in checks.theta_problems(cal) if p[0].startswith("theta_reject")]


def test_sixty_rejected_clusters_without_a_true_defect_are_feasible(b):
    """The example of docs/05 §5.7: Wilson upper about 0.060 <= 0.08."""
    assert reject_problems(b, reject(0, 60)) == []


def test_a_rejected_set_made_only_of_true_defects_is_not_feasible(b):
    got = reject_problems(b, reject(60, 60))
    assert any("true-defect share 1.0" in m for _, m in got), got


# r14: on 16 applications with icc 0.06 the design effect pushes the smallest error-free set from 45 to 50 (n_eff 44.3,
# Wilson upper 0.0798); 49 clusters give n_eff 43.6 and 0.081
@pytest.mark.parametrize("n,feasible", [(40, False), (49, False), (50, True), (51, True)])
def test_the_smallest_error_free_rejection_set_is_50(b, n, feasible):
    got = reject_problems(b, reject(0, n))
    assert (got == []) is feasible, (n, got)
    if not feasible:
        assert any("Wilson upper" in m for _, m in got)


def test_the_wilson_upper_of_the_reject_branch_is_the_recomputed_one(b):
    thr = reject(0, 45)
    thr["calibration"]["ci_high"] = 0.01                      # a forged interval is a recomputation error
    assert any("ci_high" in m and "recomputed" in m for _, m in reject_problems(b, thr))


def test_a_holdout_with_a_high_true_defect_share_does_not_generalise(b):
    got = reject_problems(b, reject(0, 60, ho_tp=5, ho_n=45))
    assert any("generalised with holdout true-defect share" in m for _, m in got), got


def test_a_holdout_inside_the_five_point_margin_generalises(b):
    # r14: the holdout generalises on its Wilson upper too (<= 0.08 + 0.05); 1 of 120 over 13 applications: 0.008, upper 0.06
    assert reject_problems(b, reject(0, 60, ho_tp=1, ho_n=120)) == []
    got = reject_problems(b, reject(0, 60, ho_tp=2, ho_n=45))                # 2 of 45 = 0.044 <= 0.07, but the upper is 0.19
    assert any("holdout Wilson upper" in m for _, m in got), got


def test_05_states_the_minimum_feasible_n_and_the_tp_reading():
    s = (ROOT_DOCS / "05-bias-calibration.md").read_text(encoding="utf-8")
    assert "至少需要 45 個被駁回的叢集" in s
    assert "precision 本身就是真缺陷比例" in s


# ================================================================ G4: one rule for "approved"
from vchlib import derive                                          # noqa: E402
from vchlib.checks import Ctx                                       # noqa: E402

IDOR = "TC-012-01"           # job-idor-001 started 2026-10-05T20:30+08:00, G4 round 1 received 2026-10-03T11:00+08:00
ZAP = "TC-027-01"            # S2: job-zap-active-001, G5 opened 2026-10-05T21:00+08:00
AFTER_EXECUTION = "2026-10-05T23:00:00+08:00"
BEFORE_EXECUTION = "2026-10-04T09:00:00+08:00"


def g4_round(b, when, decisions, outcome="APPROVED", rid="GR-G4-0002", rnd=2):
    """A later G4 record (no gate_decision event: its time is its own timestamp)."""
    base = doc(b, "gate-record.g4.example.json")
    new = copy.deepcopy(base)
    new.path = new.path.replace("g4.example", f"g4-round{rnd}.example")
    new.data.update(gate_record_id=rid, round=rnd, timestamp=when, outcome=outcome,
                    decisions=[dict(base.data["decisions"][0], item_id=i, decision=d) for i, d in decisions])
    b.docs.append(new)
    return new


def result_of(b, testcase_id=IDOR):
    return next(d.data for d in b.docs if d.kind == "testresult" and d.data.get("testcase_id") == testcase_id)


def test_the_examples_agree_with_one_rule(b):
    st = derive.g4_state(Ctx(b).ix, "run-2026-09-23-001", IDOR)
    assert st.decision == "accept" and st.approved_since is not None and st.record_id == "GR-G4-0001"
    assert derive.g4_approved(Ctx(b).ix, result_of(b))


def test_an_identical_later_accept_does_not_move_the_approval(b):
    first = derive.g4_state(Ctx(b).ix, "run-2026-09-23-001", IDOR).approved_since
    g4_round(b, AFTER_EXECUTION, [(IDOR, "accept")])
    st = derive.g4_state(Ctx(b).ix, "run-2026-09-23-001", IDOR)
    assert st.decision == "accept" and st.approved_since == first and st.record_id == "GR-G4-0002"


def test_an_identical_later_accept_does_not_make_a_legitimate_execution_an_error(b):
    """The external review's reproduction: the job ran on 10-05 under the 10-03 approval; a round 2 that accepts it again
    used to move 'the G4 decision that approved the testcase' after the job start (two E-RESULT-G4)."""
    g4_round(b, AFTER_EXECUTION, [(IDOR, "accept"), (ZAP, "accept")])
    assert errors(b, "E-RESULT-G4") == []
    assert not [w for w in run_all(b).warnings if w.code == "W-RESULT-G4-WITHDRAWN"]


def test_a_reject_after_the_execution_withdraws_the_approval_for_new_dispatches_only(b):
    g4_round(b, AFTER_EXECUTION, [(IDOR, "reject")], outcome="PARTIALLY_APPROVED")
    ix = Ctx(b).ix
    now = derive.g4_state(ix, "run-2026-09-23-001", IDOR)
    assert now.decision == "reject" and now.approved_since is None                         # may not be dispatched again
    assert derive.g4_state(ix, "run-2026-09-23-001", IDOR, at=ix.decision_time(doc(b, "gate-record.g4.example.json").data)).decision == "accept"
    assert derive.g4_approved(ix, result_of(b))                                            # the result keeps its pre-registration


def test_a_withdrawn_approval_is_a_warning_not_an_error_for_a_result_that_ran_under_it(b):
    g4_round(b, AFTER_EXECUTION, [(IDOR, "reject")], outcome="PARTIALLY_APPROVED")
    run = doc(b, "run.example.json").data
    run["approved_testcase_ids"] = [t for t in run["approved_testcase_ids"] if t != IDOR]      # the end-of-log set
    assert errors(b, "E-RESULT-G4") == [] and errors(b, "E-RUN-G4") == []
    assert not [i for i in errors(b, "E-RUN-JOB") if "approved at G4" in i.msg]
    assert any(w.code == "W-RESULT-G4-WITHDRAWN" and "testresult.example" in w.where for w in run_all(b).warnings)


def test_a_reject_before_the_execution_means_the_job_ran_unapproved(b):
    """derive used to skip the whole REJECTED record and keep the result pre-registered (E_proof) while the validator
    honoured the reject; both now read the state when the job started."""
    g4_round(b, BEFORE_EXECUTION, [(IDOR, "reject")], outcome="PARTIALLY_APPROVED")
    assert not derive.g4_approved(Ctx(b).ix, result_of(b))
    assert any("executed while the G4 decision on the testcase was reject" in i.msg for i in errors(b, "E-RESULT-G4"))


def test_a_job_started_after_the_withdrawal_is_not_allowed(b):
    g4_round(b, "2026-10-05T19:00:00+08:00", [(IDOR, "reject")], outcome="PARTIALLY_APPROVED")
    run = doc(b, "run.example.json").data
    run["approved_testcase_ids"] = [t for t in run["approved_testcase_ids"] if t != IDOR]
    assert any("job for a testcase not approved at G4" in i.msg for i in errors(b, "E-RUN-JOB"))


def test_an_expired_g4_round_decides_nothing_for_the_g5_link(b):
    """g5_g4_link read EXPIRED records (unsigned, deciding nothing) that the other lookups skipped."""
    g4_round(b, "2026-10-05T10:00:00+08:00", [(ZAP, "needs_info")], outcome="EXPIRED")
    assert errors(b, "E-G5-G4") == []


def test_the_state_as_of_a_time_ignores_later_records(b):
    g4_round(b, AFTER_EXECUTION, [(IDOR, "needs_info")], outcome="PARTIALLY_APPROVED")
    ix = Ctx(b).ix
    t = lambda s: derive.timeutil.parse_dt(s)
    assert derive.g4_state(ix, "run-2026-09-23-001", IDOR, at=t("2026-10-04T00:00:00+08:00")).decision == "accept"
    assert derive.g4_state(ix, "run-2026-09-23-001", IDOR, at=t("2026-10-06T00:00:00+08:00")).decision == "needs_info"
    assert derive.g4_state(ix, "run-2026-09-23-001", IDOR, at=t("2026-10-01T00:00:00+08:00")).decision is None


def test_03_and_the_schemas_readme_state_the_approval_semantics():
    s = (ROOT_DOCS / "03-system-architecture.md").read_text(encoding="utf-8")
    assert "核准狀態的時間語意" in s and "執行當時是否已核准" in s and "目前是否可派送" in s
    r = (ROOT_DOCS / "schemas" / "README.md").read_text(encoding="utf-8")
    assert "W-RESULT-G4-WITHDRAWN" in r


def test_a_later_g4_round_does_not_undo_a_g5_already_decided(b):
    """E-G5-G4 judges the G4 decision in force when the G5 opened (2026-10-05T21:00), not the latest one."""
    g4_round(b, AFTER_EXECUTION, [(ZAP, "reject")], outcome="PARTIALLY_APPROVED")
    assert errors(b, "E-G5-G4") == []
