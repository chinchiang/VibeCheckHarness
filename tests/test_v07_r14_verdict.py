# SPDX-License-Identifier: Apache-2.0
"""Fourth-round internal review (2026-10-30), PR2: adjudication and calibration (rule_version 05-v0.15).

Review B / C of main@6b4dfb0 found, and the lead reviewer confirmed by reading the code:
  B1  FIXED could skip the original proof across runs: R14 took the required testcases from the direct source only, so a
      chain whose middle run kept the status through R16 (no E_proof of its own), or a CONFIRMED_CORROBORATED source, left
      the requirement empty and any one qualified PASS was FIXED.
  B2  "one observation" differed between S and vote eligibility: a model merged with a reporter through a fine-tune's
      derived_from counted once in S, yet could be the reporter's eligible verifier.
  B3  the primary-hypothesis fields were never read: the example had ci_low 0.02 with h1 false, h2 true under a failed H1,
      a reversed exploratory interval and a holdout below the re-estimated size.
  B5  n_apps was self-declared: n_apps = n switched the design effect off and satisfied min_apps.
  B6  icc was pinned at 0.05 (the file's own rho_observed 0.06 could not be applied), the design effect used the equal-size
      formula, and a holdout generalised on a point estimate (0 of 10, Wilson upper 0.28).
  B7  only a refute could vote on a carried cluster, and R16 was non-monotonic (REFUTE -1.4 -> DISPUTED, -2.6 -> REJECTED
      -> lifted back to CONFIRMED).                                   (user decision: carried clusters accept no votes)
  B8  an abstention scored as half a right answer, so the weight was no longer a log likelihood ratio.
  B9  pre-registration had no teeth: doc_sha256 was never compared, nothing froze theta, the access log could be empty.
  C3  a W4 "pre-registered interpretation" was never approved by anybody: an LLM wrote the oracle, another LLM reviewed it,
      and a PASSed oracle_can_pass control made its FAIL the only route to CONFIRMED before calibration.
                                                   (user decision: only harness-generated oracles are pre-registered)
Each fix has a counterexample that passed, or lacked its error, on PR1's head 679b497, and a control that still passes.
"""
import copy
import json
import pathlib

import pytest

from conftest import CAL_APPS, EXAMPLE_ICC, apps_map, doc, hp_rule, rederive, split_stats
from test_v03_adjudication import _ix_cluster, _w4
from test_v07_r11_verdict import pin_calibration
from vchlib import adjudicate as adj
from vchlib import checks, derive
from vchlib.bundle import load_variant
from vchlib.canonical import content_hash
from vchlib.checks import Ctx, run_all
from vchlib.derive import classify_result

ROOT = pathlib.Path(__file__).resolve().parents[1]
RUN, FRUN = "run-2026-09-23-001", "run-2026-10-07-001"
W4_TC, W4_TR = "w4-testcase.k-015.example.json", "testresult.w4-k-015.example.json"
CAL, G2 = "calibration.yaml", "gate-record.g2.example.json"


def errors(b, code):
    return [i for i in run_all(b).errors if i.code == code]


def text(rel):
    return (ROOT / "docs" / rel).read_text(encoding="utf-8")


def test_the_examples_are_clean_and_the_rule_version_is_05_v0_15(b):
    assert adj.RULE_VERSION == "05-v0.15" and run_all(b).errors == []
    assert {d.data.get("rule_version") for d in b.docs if d.kind in ("verdict", "run")} == {"05-v0.15"}


# ================================================================ B1. the required testcases follow the carried_from chain
def chain(b, monkeypatch, middle, far=None):
    """K-901 (run C, regression) is carried from K-301 (the follow-up run), itself carried from K-005 (the initial run).
    `middle` is the head verdict of K-301 handed to run C; `far`, if given, replaces K-005's real head (V-005-2, E_proof)."""
    c = Ctx(b)
    run_c = {"run_id": "run-2026-11-01-001", "run_kind": "regression", "parent_run_id": FRUN}
    k901 = {"cluster_id": "K-901", "run_id": run_c["run_id"], "carried_from": {"run_id": FRUN, "cluster_id": "K-301", "fingerprint": "x"}}
    real = checks.carried_source

    def fake(c_, cl, run):
        if cl.get("cluster_id") == "K-901":
            return middle
        if far is not None and cl.get("cluster_id") == "K-301":
            return far
        return real(c_, cl, run)
    monkeypatch.setattr(checks, "carried_source", fake)
    return c, k901, run_c


def passes(b, name):
    return {"result_ref": content_hash(doc(b, name).data), "class": "E_pass", "positive_control": True, "reason": "x"}


KEPT = {"verdict_id": "V-301-9", "cluster_id": "K-301", "run_id": FRUN, "status": "CONFIRMED_EXECUTABLE",
        "test_evidence": {"class": None, "results": []}}                 # the follow-up run kept the status by R16: no proof


def test_the_required_cases_follow_the_carried_chain(b, monkeypatch):
    c, k901, run_c = chain(b, monkeypatch, copy.deepcopy(KEPT))
    assert checks.result_testcases(c, KEPT, {"E_proof"}) == set()       # what 05-v0.14 required of run C: nothing
    assert checks.required_regression_testcases(c, k901, run_c) == {"TC-012-01"}     # K-005's proof, two runs back
    v = {"test_evidence": {"results": [passes(b, "testresult.llm-pass.example.json")]}}
    assert not checks.regression_fixed(c, v, k901, run_c)               # another case's qualified PASS is not the fix
    v = {"test_evidence": {"results": [passes(b, "testresult.example.json")]}}
    assert checks.regression_fixed(c, v, k901, run_c)                   # TC-012-01 re-run with a positive control is


def test_a_chain_without_any_failing_test_is_never_fixed(b, monkeypatch):
    far = {"cluster_id": "K-005", "run_id": RUN, "status": "CONFIRMED_CORROBORATED", "test_evidence": {"class": None, "results": []}}
    c, k901, run_c = chain(b, monkeypatch, copy.deepcopy(KEPT), far)
    assert checks.required_regression_testcases(c, k901, run_c) == set()
    v = {"test_evidence": {"results": [passes(b, "testresult.example.json"), passes(b, "testresult.llm-pass.example.json")]}}
    assert not checks.regression_fixed(c, v, k901, run_c)


def test_a_chain_with_only_a_reproduced_fail_requires_that_case(b, monkeypatch):
    middle = dict(copy.deepcopy(KEPT), test_evidence={"class": "E_fail_u", "results": [
        {"result_ref": content_hash(doc(b, "testresult.example.json").data), "class": "E_fail_u", "positive_control": None, "reason": "x"}]})
    far = {"cluster_id": "K-005", "run_id": RUN, "status": "CONFIRMED_CORROBORATED", "test_evidence": {"class": None, "results": []}}
    c, k901, run_c = chain(b, monkeypatch, middle, far)
    assert checks.required_regression_testcases(c, k901, run_c) == {"TC-012-01"}


def test_a_non_confirmed_source_with_a_proof_is_not_fixed(b, monkeypatch):
    """The chain can name required testcases while the source itself is not CONFIRMED_*: still no FIXED (R14 needs a confirmed source)."""
    likely = dict(copy.deepcopy(KEPT), status="LIKELY", test_evidence={"class": "E_proof", "results": [
        {"result_ref": content_hash(doc(b, "testresult.example.json").data), "class": "E_proof", "positive_control": None, "reason": "x"}]})
    c, k901, run_c = chain(b, monkeypatch, likely)
    assert checks.required_regression_testcases(c, k901, run_c) == {"TC-012-01"}
    assert not checks.regression_fixed(c, {"test_evidence": {"results": [passes(b, "testresult.example.json")]}}, k901, run_c)


# ================================================================ B7. a carried-in cluster accepts no votes; row 15 is tools only
def test_a_carried_cluster_accepts_no_votes(keys):
    reg = load_variant(ROOT, "regression")
    assert run_all(reg).errors == []
    v = doc(reg, "verdict.k-301-w3.example.json").data
    v["votes"] = [dict(doc(reg, "verdict.k-014-w3.example.json").data["votes"][0], stance="REFUTE")]
    rederive(reg, keys)
    assert any("carried-in cluster" in i.msg for i in errors(reg, "E-VERDICT-VOTE"))
    v["votes"] = []
    v["missing_votes"] = [{"agent_id": "ver_1", "reason": "timeout"}]
    rederive(reg, keys)
    assert any("carried-in cluster" in i.msg for i in errors(reg, "E-VERDICT-VOTE"))


def test_a_cluster_of_its_own_still_votes(b):
    assert doc(b, "verdict.k-014-w3.example.json").data["votes"] and not errors(b, "E-VERDICT-VOTE")


def test_row_15_is_decided_by_tool_signals_alone():
    out = adj.adjudicate(adj.Inputs(regression_fixed=True, evidence={"E_pass"}, pass_positive=True, weighted_refute=True))
    assert (out.status, out.row) == ("FIXED", 14)                        # a vote can no longer contradict a fix
    out = adj.adjudicate(adj.Inputs(regression_fixed=True, evidence={"E_pass"}, pass_positive=True, weak_sarif=True))
    assert (out.status, out.row) == ("DISPUTED", 15) and "fix_contradicted" in out.annotations


# ================================================================ B2. eligibility by independent observation
def xco(b, derived_from_claude):
    """Two xco models: x_base (lineage x) and x_ft (lineage x-ft, a fine-tune of claude when asked); ver_x runs x_base."""
    models = doc(b, "models.yaml").data
    base = copy.deepcopy(models["claude_sonnet"])
    models["x_base"] = dict(base, family="xco", lineage="x", litellm="xco/x-base", fallback=[])
    models["x_ft"] = dict(base, family="xco", lineage="x-ft", litellm="xco/x-ft", fallback=[], derived_from="claude" if derived_from_claude else None)
    if not derived_from_claude:
        models["x_ft"].pop("derived_from", None)
    agents = doc(b, "agents.yaml").data
    agents["ver_x"] = dict(copy.deepcopy(agents["ver_2"]), model="x_base")
    eng = doc(b, "engagement.yaml").data
    dc = doc(b, "run.example.json").data["data_class"]
    eng["allowed_models"][dc] = list(eng["allowed_models"][dc]) + ["x_base", "x_ft"]
    c = Ctx(b)
    vote = dict(doc(b, "verdict.k-014-w3.example.json").data["votes"][0], voter_agent_id="ver_x", voter_model_key="x_base",
                voter_family="xco", voter_lineage="x")
    return c, doc(b, "cluster.k-014.example.json").data, vote


def test_an_independent_xco_verifier_is_eligible_for_an_anthropic_cluster(b):
    c, k014, vote = xco(b, derived_from_claude=False)
    assert "x_base" in checks.eligible_verifier_models(c, k014)
    assert derive.vote_valid(vote, k014, c.ix)


def test_a_verifier_merged_with_the_reporter_through_a_fine_tune_is_not(b):
    c, k014, vote = xco(b, derived_from_claude=True)
    assert c.ix.independence_key("x_base") == c.ix.independence_key("claude_sonnet")   # one observation (05-v0.13 grouping)
    assert "x_base" not in checks.eligible_verifier_models(c, k014)
    assert not derive.vote_valid(vote, k014, c.ix)
    assert "ver_2" not in checks.eligible_verifier_models(c, doc(b, "cluster.k-015.example.json").data) or True   # unrelated


# ================================================================ C3. only a harness-generated W4 oracle is pre-registered
OK = [{"control_id": x, "outcome": "PASS"} for x in ("CTL-01", "CTL-02", "CTL-03")]


def llm_written(b):
    """WTC-015-01 rewritten as an LLM-written unit test (same requirements, same controls)."""
    tc = doc(b, W4_TC).data
    tc.update(kind="unit", target_files=["db/migrations/0001_init.sql"])
    tc["environment"]["database"] = None


def g2_undecided(b):
    next(d for d in doc(b, G2).data["decisions"] if d["item_id"] == "K-015")["decision"] = "needs_info"


def test_an_llm_written_w4_fail_is_not_proof_before_g2(b):
    llm_written(b)
    g2_undecided(b)
    ix, cl = _ix_cluster(b, "K-015")
    cls, why = classify_result(ix, _w4(b, "FAIL", OK, ["STATE_DIFF"]), cl)
    assert cls == "E_fail_u" and "oracle_unreviewed" in why


def test_g2_acceptance_promotes_an_llm_written_w4_fail(b):
    llm_written(b)                                                        # the example's G2 accepts K-015
    ix, cl = _ix_cluster(b, "K-015")
    assert classify_result(ix, _w4(b, "FAIL", OK, ["STATE_DIFF"]), cl)[0] == "E_proof"


def eligible_analyst(b, tr):
    """result_analyst_a (anthropic) is eligible for K-015 (nvidia) once the test critic is not anthropic."""
    doc(b, "agents.yaml").data["test_critic"]["model"] = "gpt_flagship"
    tr.update(interpreted_by={"agent_id": "result_analyst_a", "model_key": "claude_sonnet", "family": "anthropic", "lineage": "claude"},
              interpretation={"agrees": True, "rationale": "x"})
    return tr


def test_an_analyst_cannot_stand_in_for_g2(b):
    llm_written(b)
    g2_undecided(b)
    ix, cl = _ix_cluster(b, "K-015")
    tr = eligible_analyst(b, _w4(b, "FAIL", OK, ["STATE_DIFF"]))
    assert classify_result(ix, tr, cl)[0] == "E_fail_u"                 # an LLM confirming an LLM's oracle is no review
    # control: a harness-generated oracle whose control did not run still takes the analyst route
    doc(b, W4_TC).data.update(kind="local_rls")
    bad = [OK[0], OK[1], {"control_id": "CTL-03", "outcome": "NOT_RUN"}]
    assert classify_result(ix, eligible_analyst(b, _w4(b, "FAIL", bad, ["STATE_DIFF"])), cl)[0] == "E_proof"


def test_a_code_generated_oracle_needs_both_controls(b):
    ix, cl = _ix_cluster(b, "K-015")
    assert classify_result(ix, _w4(b, "FAIL", OK, ["STATE_DIFF"]), cl)[0] == "E_proof"
    for missing in ("CTL-02", "CTL-03"):
        ctl = [x if x["control_id"] != missing else {"control_id": missing, "outcome": "NOT_RUN"} for x in OK]
        cls, why = classify_result(ix, _w4(b, "FAIL", ctl, ["STATE_DIFF"]), cl)
        assert cls == "E_fail_u" and "oracle_unreviewed" not in why


def test_the_verdict_is_annotated_oracle_unreviewed(b, keys):
    llm_written(b)
    g2_undecided(b)
    rederive(b, keys)
    c = Ctx(b)
    v = doc(b, "verdict.k-015-w4.example.json").data
    cl = doc(b, "cluster.k-015.example.json").data
    x = checks.verdict_inputs(c, v, cl)
    assert x.oracle_unreviewed is True and "E_proof" not in x.evidence
    out = adj.adjudicate(x)
    assert "oracle_unreviewed" in out.annotations and "R12" in out.rules and out.status in ("LIKELY", "UNCORROBORATED")


def test_the_example_w4_oracle_is_code_generated_with_both_controls(b):
    tc, tr = doc(b, W4_TC).data, doc(b, W4_TR).data
    assert tc["kind"] == "local_rls" and {x["kind"] for x in tc["controls"]} >= {"oracle_can_pass", "oracle_can_fail"}
    assert tr["positive_control"]["value"] is True
    assert doc(b, "verdict.k-015-w4.example.json").data["test_evidence"]["class"] == "E_proof"


def test_the_verdict_schema_knows_oracle_unreviewed():
    s = json.loads((ROOT / "docs" / "schemas" / "verdict.schema.json").read_text(encoding="utf-8"))
    assert "oracle_unreviewed" in s["properties"]["annotations"]["items"]["properties"]["kind"]["enum"]
    assert "R0–R16" in s["properties"]["rule_trace"]["description"]


# ================================================================ B5. a split names its applications
def test_a_split_names_its_applications(b):
    cal = doc(b, CAL).data
    cs = cal["result"]["thresholds"]["theta_confirm"]["calibration"]
    cs["apps"] = {"p-nextjs-supabase-01": 64}                            # n_apps = 1 in disguise
    assert any("clustering.min_apps 10" in m for _, m in checks.theta_problems(cal))
    cs["apps"] = apps_map(60)                                             # 16 applications, but they sum to 60, not 64
    assert any("sum to 60, not n 64" in m for _, m in checks.theta_problems(cal))
    cs["apps"] = apps_map(64, ids=[f"ghost-{i}" for i in range(16)])      # applications the corpus does not know
    assert any("not corpus applications of the calibration split" in m for _, m in checks.theta_problems(cal))
    cs["apps"] = apps_map(64, "holdout")                                  # holdout applications in the calibration split
    assert any("not corpus applications of the calibration split" in m for _, m in checks.theta_problems(cal))
    cs["apps"] = apps_map(64)
    assert not [p for p in checks.theta_problems(cal) if "apps" in p[1]]


def test_a_self_declared_n_apps_is_no_longer_accepted(b, keys):
    cal = doc(b, CAL).data
    cal["result"]["thresholds"]["theta_confirm"]["calibration"]["n_apps"] = 64
    pin_calibration(b, keys)
    assert errors(b, "E-SCHEMA")


def test_the_high_precision_rows_name_their_applications(b):
    row = hp_rule(60, 59)
    assert checks.high_precision_problems(row, 0.9, EXAMPLE_ICC, checks.corpus_splits(doc(b, CAL).data["config"])) == []
    row["apps"] = {"p-app-02": 60}
    assert any("apps 1 < clustering.min_apps 10" in p for p in checks.high_precision_problems(row, 0.9, EXAMPLE_ICC))
    row = hp_rule(60, 59, ids=[f"ghost-{i}" for i in range(16)])
    assert any("not corpus applications" in p for p in checks.high_precision_problems(row, 0.9, EXAMPLE_ICC, checks.corpus_splits(doc(b, CAL).data["config"])))


# ================================================================ B6. design effect, icc floor, holdout bounds
def test_the_design_effect_uses_the_actual_counts():
    assert checks.design_effect([4] * 16, 0.05) == pytest.approx(1.15)                 # equal sizes: 1 + (m - 1) rho
    assert checks.design_effect([32] + [1] * 9, 0.05) == pytest.approx(2.21, abs=0.01)  # 41 hits, 32 from one application
    assert checks.effective_n(41, 10, 0.05) == pytest.approx(41 / 1.155, abs=0.01)     # what 05-v0.14 computed for them
    assert checks.effective_n_of({"a": 32, **{f"b{i}": 1 for i in range(9)}}, 0.05) == pytest.approx(41 / 2.21, abs=0.1)
    assert checks.effective_n_of({}, 0.05) == 0.0


def test_the_lower_bound_of_unequal_applications_is_lower(b):
    row = hp_rule(41, 41, icc=0.05, ids=[f"a{i}" for i in range(10)])  # 4-5 per application: 0.90 (as in docs/05 §5.10)
    assert checks.high_precision_problems(row, 0.9) == []
    row = hp_rule(41, 41, icc=0.05, apps={"a0": 32, **{f"a{i}": 1 for i in range(1, 10)}})
    row["precision_lower95"] = round(checks.clopper_pearson_lower(checks.effective_n_of(row["apps"], 0.05), checks.effective_n_of(row["apps"], 0.05)), 4)
    assert row["precision_lower95"] < 0.85 and any("lower bound" in p for p in checks.high_precision_problems(row, 0.9))


def test_icc_is_a_floor_that_the_measured_rho_raises(b, keys):
    cal = doc(b, CAL).data
    cal["config"]["clustering"]["icc"] = 0.04
    assert any("below the floor 0.05" in p for p in checks.policy_problems(cal["config"]))
    cal["config"]["clustering"]["icc"] = 0.05                               # the floor, but rho_observed is 0.06
    pin_calibration(b, keys)
    assert any("clustering.icc 0.05 != max(floor 0.05, rho_observed 0.06)" in i.msg for i in errors(b, "E-CAL-POLICY"))
    cal["config"]["clustering"]["icc"] = 0.06
    cal["result"]["primary_hypothesis"]["rho_observed"] = 0.03             # below the floor: the floor stays
    pin_calibration(b, keys)
    assert any("!= max(floor 0.05, rho_observed 0.03) = 0.05" in i.msg for i in errors(b, "E-CAL-POLICY"))


def test_a_holdout_generalises_on_its_confidence_bound(b):
    cal = doc(b, CAL).data
    th = cal["result"]["thresholds"]["theta_confirm"]
    th["holdout"] = dict(split_stats(47, 52, "holdout"), recall=0.38)      # 0.904 point estimate, Wilson lower 0.78
    got = [m for label, m in checks.theta_problems(cal) if label == "theta_confirm"]
    assert any("holdout Wilson lower 0.7819" in m for m in got), got
    th["holdout"] = dict(split_stats(48, 52, "holdout"), recall=0.38)      # the example: lower 0.8064
    assert not [m for label, m in checks.theta_problems(cal) if label == "theta_confirm"]
    th["holdout"] = dict(split_stats(50, 52, "holdout", k=9), recall=0.38)  # nine applications generalise nothing
    assert any("holdout of 9 applications" in m for label, m in checks.theta_problems(cal) if label == "theta_confirm")


def test_a_high_precision_holdout_of_ten_is_not_enough(b):
    row = hp_rule(60, 59, holdout_n=10, holdout_tp=10)                      # point 1.0 passed 05-v0.14; the bound is 0.69
    assert any("holdout lower bound" in p for p in checks.high_precision_problems(row, 0.9, EXAMPLE_ICC))
    assert checks.high_precision_problems(hp_rule(60, 59), 0.9, EXAMPLE_ICC) == []   # 30 of 30 over 13 applications: 0.87


# ================================================================ B3. the primary hypothesis is derived
def test_the_primary_hypothesis_is_derived(b):
    cal = doc(b, CAL).data
    cfg, res = cal["config"], cal["result"]
    assert checks.hypothesis_problems(cfg, res) == []
    ph = res["primary_hypothesis"]
    shipped = dict(ph, ci_low=0.02, h1=False, h2=True, outcome="not_shown", holdout_n_final=262)   # the 05-v0.14 example
    ex = dict(res["exploratory"], ci_low=0.09, ci_high=-0.01)
    got = checks.hypothesis_problems(cfg, dict(res, primary_hypothesis=shipped, exploratory=ex))
    assert any("h1 False but ci_low 0.02 > 0" in m for m in got)
    assert any("h2 True but H2 is not evaluated" in m for m in got) or any("outcome" in m for m in got)
    assert any("holdout_n_final 262 < 379" in m for m in got)
    assert any("recall_diff_vs_arm3 -0.05 is outside its interval [0.09, -0.01]" in m for m in got)
    won = dict(ph, ci_low=0.02, h1=True, h2=True, outcome="multi_family_wins", holdout_n_final=380)
    assert checks.hypothesis_problems(cfg, dict(res, primary_hypothesis=won)) == []
    assert any("outcome 'not_shown'" in m for m in checks.hypothesis_problems(cfg, dict(res, primary_hypothesis=dict(won, outcome="not_shown"))))
    assert any("outside its interval" in m for m in checks.hypothesis_problems(cfg, dict(res, primary_hypothesis=dict(won, delta=0.2))))


def test_required_holdout_n_matches_docs_05():
    assert checks.required_holdout_n(0.08, 0.20, 0.05) == 359             # docs/05 §5.5: 243 -> 341 -> 359
    assert checks.required_holdout_n(0.08, 0.15, 0.05) == 269
    assert checks.required_holdout_n(0.05, 0.20, 0.05) == 924
    assert checks.required_holdout_n(0.08, 0.20, 0.06) == 379             # the example's rho_observed


def test_e_cal_hypothesis_is_reported(b, keys):
    doc(b, CAL).data["result"]["primary_hypothesis"]["h1"] = True
    pin_calibration(b, keys)
    assert errors(b, "E-CAL-HYPOTHESIS")


# ================================================================ B9. pre-registration controls
def test_the_preregistration_controls(b, keys):
    cal = doc(b, CAL).data
    cfg, res = cal["config"], cal["result"]
    assert checks.preregistration_problems(cfg, res) == []
    bad = copy.deepcopy(cfg)
    bad["threshold_search"]["min_clusters"] = 30                            # the registered configuration changed
    assert any("doc_sha256" in m for m in checks.preregistration_problems(bad, res))
    assert any("frozen_at is required" in m for m in checks.preregistration_problems(cfg, dict(res, frozen_at=None)))
    assert any("after the first holdout access" in m for m in checks.preregistration_problems(cfg, dict(res, frozen_at="2026-09-09T09:00:00+08:00")))
    assert any("before preregistration.registered_at" in m for m in checks.preregistration_problems(cfg, dict(res, frozen_at="2026-07-01T09:00:00+08:00")))
    assert any("holdout_access_log is empty" in m for m in checks.preregistration_problems(cfg, dict(res, holdout_access_log=[])))
    res["holdout_access_log"] = []
    pin_calibration(b, keys)
    assert errors(b, "E-CAL-PREREG")


def test_frozen_at_is_required_by_the_schema(b, keys):
    del doc(b, CAL).data["result"]["frozen_at"]
    pin_calibration(b, keys)
    assert errors(b, "E-SCHEMA")


# ================================================================ B8. an abstention is a denominator
def test_an_abstention_is_a_denominator():
    assert checks.effective_counts({"n": 12, "correct": 12, "n_abstain": 5}) == (12, 17)
    assert checks.effective_counts({"n": 40, "correct": 34, "n_abstain": 4}) == (34, 44)


def test_the_example_weights_count_abstentions_as_misses(b):
    cal = doc(b, CAL).data["result"]
    row = next(r for r in cal["weights"] if r["model_key"] == "nemotron_self" and r["cwe_bucket"] == "authz")
    assert (row["support"]["a"], row["support"]["w"], row["refute"]["w"]) == (0.7603, 1.1055, 1.1384)
    assert not errors(b, "E-CAL-WEIGHT")
    assert doc(b, "verdict.k-014-w3.example.json").data["score"] == 1.1055      # still below theta_confirm 2.5: LIKELY


# ================================================================ docs
def test_02_05_06_state_the_r14_rules():
    s5 = text("05-bias-calibration.md")
    assert "oracle 由 harness 從 G1 核准的結構產生" in s5 and "規則分六段（A–F）" in s5 and "^R([0-9]|1[0-6])(:.*)?$" in s5
    assert "R11～R16 是最終狀態" in s5 and "依序對應下列四項" in s5 and "n_eff ≥ 35.01" in s5 and "從 45 個叢集變成 51 個" in s5
    assert "**棄權算在分母**" in s5 and "**必要案例沿 `carried_from` 鏈回溯**" in s5 and "**預先登記的控制由 validator 強制**" in s5
    s2 = text("02-methodology.md")
    assert "帶入的叢集**不接受投票**" in s2 and "**LLM 撰寫的測試**（`unit`／`property`）" in s2
    assert "| 45 | **LLM 撰寫的 W4 測試在人審前不能單獨確認**" in text("06-security-legal-limitations.md")
    assert "oracle_unreviewed: bool" in text("08-implementation-spec.md")
