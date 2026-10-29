# SPDX-License-Identifier: Apache-2.0
"""v0.3 adjudication: tool corroboration tiers (A1), deterministic proof without an LLM and black-box-origin
clusters (A2), controls / INVALID (B5), the diversity flag (A3), fallback weights (A4), provisional verdicts (E5),
the legal gate on SARIF refs (B12). Each rule has a positive and a negative case."""
import copy

import pytest

from conftest import codes, doc, rederive
from vchlib import adjudicate as adj
from vchlib.adjudicate import Inputs, adjudicate
from vchlib.checks import (Ctx, derived_diversity_degraded, derived_no_eligible_verifier, derived_provisional, run_all,
                           verdict_inputs)
from vchlib.derive import Index, classify_result

AUDIT = "audit-event.run-2026-09-23-001.example.jsonl"
V005, V011, V014 = "verdict.example.json", "verdict.k-011-w3.example.json", "verdict.k-014-w3.example.json"
V201, V202 = "verdict.k-201-b5.example.json", "verdict.k-202-b5.example.json"
TR_IDOR, TR_LLM, TR_ZAP, TR_LIST = ("testresult.example.json", "testresult.llm-pass.example.json",
                                   "testresult.zap-active.example.json", "testresult.bola-list.example.json")
TC_IDOR, TC_LIST = "testcase.idor.example.json", "testcase.bola-list.example.json"


def errs(bundle, code):
    return [i for i in run_all(bundle).errors if i.code == code]


# ================================================================ A1 tool tiers (pure rules)
def test_rule_version_is_bumped():
    assert adj.RULE_VERSION == "05-v0.13"           # bumped again by review r10 PR2


def test_weak_sarif_alone_never_confirms():
    out = adjudicate(Inputs(weak_sarif=True, independent_families=1))
    assert (out.status, out.row, out.rules, out.sources) == ("LIKELY", 12, ["R2", "R6"], 2)
    out = adjudicate(Inputs(weak_sarif=True, independent_families=0))
    assert (out.status, out.row) == ("UNCORROBORATED", 13)


def test_strong_tool_confirms_and_is_not_capped():
    out = adjudicate(Inputs(strong_tool=True, independent_families=1, diversity_degraded=True))
    assert (out.status, out.row, out.status_cap, out.rules) == ("CONFIRMED_CORROBORATED", 10, None, ["R2", "R5"])


def test_e_fail_u_is_a_signal_not_corroboration():
    # v0.7 (r8): only an independently authored E_fail_u is a source (fail_u_independent, derived by the validator)
    out = adjudicate(Inputs(evidence={"E_fail_u"}, fail_u_independent=True, independent_families=1))
    assert (out.status, out.row, out.sources) == ("LIKELY", 12, 2)
    out = adjudicate(Inputs(evidence={"E_fail_u"}, independent_families=1))
    assert (out.status, out.row, out.sources) == ("UNCORROBORATED", 13, 1)
    out = adjudicate(Inputs(evidence={"E_fail_u"}, fail_u_independent=True, independent_families=0))
    assert out.status == "UNCORROBORATED"


@pytest.mark.parametrize("kw", [dict(strong_tool=True), dict(weak_sarif=True), dict(evidence={"E_fail_u"})])
def test_refute_with_any_tool_signal_is_disputed(kw):
    out = adjudicate(Inputs(weighted_refute=True, score=-5.0, theta_reject=1.0, **kw))
    assert (out.status, out.row, out.rules) == ("DISPUTED", 7, ["R2", "R4"])


def test_refute_without_tool_signal_can_reject():
    out = adjudicate(Inputs(weighted_refute=True, score=-5.0, theta_reject=1.0))
    assert (out.status, out.row) == ("REJECTED", 8)


def test_vote_branch_still_capped_by_r8():
    out = adjudicate(Inputs(weighted_support=True, score=2.0, theta_confirm=1.2, diversity_degraded=True))
    assert (out.status, out.row, out.status_cap, out.rules) == ("LIKELY", 11, "LIKELY", ["R2", "R5", "R8"])


# ================================================================ A1 / B12 validator
def test_independent_sources_mismatch(b):
    doc(b, V014).data["independent_sources"] = 1
    assert codes(b) == {"E-VERDICT-SOURCES", "E-DERIVED", "E-AUDIT-VERDICT"}   # r7: the report pins V-014-1; r8 H4: so does its event


def test_sarif_from_legally_gated_adapter_is_rejected(b):
    """B12 (N-7): semgrep:scan is 法務閘門 in licenses.yaml, so its SARIF result is not tool evidence at all."""
    for e in doc(b, AUDIT).data:
        if (e.get("payload") or {}).get("adapter") == "opengrep:scan":
            e["payload"]["adapter"] = "semgrep:scan"
    R = run_all(b)
    hits = [i for i in R.errors if i.code == "E-SARIF-REF"]
    assert hits and "not legally cleared" in hits[0].msg and "法務閘門" in hits[0].msg
    assert {"E-VERDICT-TOOLSIGNAL", "E-VERDICT-SOURCES", "E-VERDICT-STATUS"} <= R.codes()


def test_cleared_license_status_resolves(b):
    comps = doc(b, "licenses.yaml").data["components"]
    semgrep = next(x for x in comps if x["component"] == "Semgrep CE")
    semgrep["status"] = "OK"                            # hypothetical: legal review cleared it
    for e in doc(b, AUDIT).data:
        if (e.get("payload") or {}).get("adapter") == "opengrep:scan":
            e["payload"]["adapter"] = "semgrep:scan"
    assert "E-SARIF-REF" not in codes(b)


# ================================================================ A2 classification
def _ix_cluster(b, cid):
    ix = Index(b)
    return ix, ix.first("cluster", cluster_id=cid).data


def test_black_box_fail_is_proof_without_llm(b):
    """K-201 / R-TC-033-01-1: deterministic FAIL of a G4-approved testcase, interpreted_by null -> E_proof (R1)."""
    tr = doc(b, TR_LIST).data
    assert tr["interpreted_by"] is None and tr["interpretation"] is None
    ix, cl = _ix_cluster(b, "K-201")
    assert classify_result(ix, tr, cl) == ("E_proof", "reproduced FAIL, deterministic oracle, pre-registered interpretation")
    v = doc(b, V201).data
    assert v["status"] == "CONFIRMED_EXECUTABLE" and v["executable_proof"]["interpretation_confirmed_by"] is None


def test_fail_without_g4_approval_needs_an_analyst(b, keys):
    """Without the accepting G4 decision the same FAIL is not pre-registered: no analyst -> E_fail_u."""
    rec = doc(b, "gate-record.g4.example.json").data
    next(x for x in rec["decisions"] if x["item_id"] == "TC-033-01")["decision"] = "reject"
    ix, cl = _ix_cluster(b, "K-201")
    assert classify_result(ix, doc(b, TR_LIST).data, cl)[0] == "E_fail_u"
    tr = doc(b, TR_LIST).data
    # v0.6 (review r7 3.1): nvidia modelled T-033, so the nvidia analyst would grade its own test; openai did not
    tr["interpreted_by"] = {"agent_id": "result_analyst_b", "family": "openai"}
    tr["interpretation"] = {"agrees": True, "rationale": "x"}
    assert classify_result(ix, tr, cl)[0] == "E_proof"                  # eligible analyst (cluster has no families)
    tr["interpretation"]["agrees"] = False
    assert classify_result(ix, tr, cl) == ("E_inc", "eligible analyst does not agree with the interpretation")


W4_TC, W4_TR = "w4-testcase.k-015.example.json", "testresult.w4-k-015.example.json"    # v0.5 (BL-27): W4 tests are w4-testcases


def _w4(b, outcome, controls, fail_oracles):
    tr = copy.deepcopy(doc(b, W4_TR).data)
    tr.update(outcome=outcome, controls=controls, fail_oracles=fail_oracles, interpreted_by=None, interpretation=None)
    for e in doc(b, "audit-event.run-2026-09-23-001.example.jsonl").data:   # v0.7 (r8 F2a): the executor's event agrees
        if e["event_type"] == "sandbox_job_end" and e["payload"].get("result_id") == tr["result_id"]:
            e["payload"]["outcome"] = outcome
    return tr


def test_w4_preregistration_needs_the_matching_control(b):
    """WTC-015-01: CTL-01 reachability, CTL-02 oracle_can_pass; CTL-03 (oracle_can_fail) added here."""
    tc = doc(b, W4_TC).data
    tc["controls"].append({"control_id": "CTL-03", "kind": "oracle_can_fail", "description": "known-bad variant",
                           "steps": ["run the oracle on the vulnerable schema"], "expected": "oracle fails"})
    ix, cl = _ix_cluster(b, "K-015")
    ok = [{"control_id": c, "outcome": "PASS"} for c in ("CTL-01", "CTL-02", "CTL-03")]
    assert classify_result(ix, _w4(b, "FAIL", ok, ["STATE_DIFF"]), cl)[0] == "E_proof"
    bad = [ok[0], {"control_id": "CTL-02", "outcome": "NOT_RUN"}, ok[2]]
    assert classify_result(ix, _w4(b, "FAIL", bad, ["STATE_DIFF"]), cl)[0] == "E_fail_u"
    # PASS needs the oracle_can_fail control (CTL-03) for a pre-registered W4 interpretation
    assert classify_result(ix, _w4(b, "PASS", ok, []), cl)[0] == "E_pass"
    tc["controls"] = [c for c in tc["controls"] if c["kind"] != "oracle_can_fail"]
    assert classify_result(ix, _w4(b, "PASS", ok[:2], []), cl) == ("E_inc", "no pre-registered interpretation, independent authors or eligible analyst")


def test_w4_preregistration_needs_g1_signed_requirements(b):
    inv = doc(b, "invariants.yaml").data
    ix, cl = _ix_cluster(b, "K-015")
    ok = [{"control_id": c, "outcome": "PASS"} for c in ("CTL-01", "CTL-02")]
    assert classify_result(ix, _w4(b, "FAIL", ok, ["STATE_DIFF"]), cl)[0] == "E_proof"
    next(i for i in inv["invariants"] if i["requirement_id"] == "INV-AC-007")["signoff"]["status"] = "REJECTED"
    assert classify_result(ix, _w4(b, "FAIL", ok, ["STATE_DIFF"]), cl)[0] == "E_fail_u"


def test_pass_needs_reachability_and_a_deterministic_oracle(b):
    ix, cl = _ix_cluster(b, "K-011")
    tr = doc(b, TR_LLM).data
    assert classify_result(ix, tr, cl)[0] == "E_pass"
    doc(b, "testcase.llm.example.json").data["oracle"]["types"] = ["LLM_GRADER"]
    assert classify_result(ix, tr, cl) == ("E_inc", "no deterministic oracle")


@pytest.mark.parametrize("outcome", ["INVALID", "ERROR", "SKIPPED", "STOPPED"])
def test_non_pass_fail_outcomes_are_inconclusive(b, outcome):
    ix, cl = _ix_cluster(b, "K-011")
    tr = doc(b, TR_LLM).data
    tr["outcome"] = outcome
    assert classify_result(ix, tr, cl) == ("E_inc", f"outcome {outcome}")


# ================================================================ B5 controls / INVALID
def test_failed_control_requires_invalid(b):
    tr = doc(b, TR_LLM).data
    tr["controls"][0]["outcome"] = "FAIL"
    got = codes(b)
    assert "E-RESULT-INVALID" in got and "E-RESULT-PRECONDITION" in got


def test_invalid_outcome_is_consistent_with_a_failed_control(b, keys):
    tr = doc(b, TR_LLM).data
    tr["controls"][0]["outcome"] = "ERROR"
    tr["outcome"] = "INVALID"
    rederive(b, keys)
    got = codes(b)
    assert not {"E-RESULT-INVALID", "E-RESULT-CONTROLS", "E-RESULT-PRECONDITION"} & got
    v = doc(b, "verdict.k-011-b5.example.json").data
    assert v["test_evidence"]["class"] == "E_inc"             # INVALID is never PASS / FAIL


def test_invalid_without_a_failed_control_is_rejected(b):
    doc(b, TR_LLM).data["outcome"] = "INVALID"
    assert "E-RESULT-INVALID" in codes(b)


def test_controls_must_cover_the_testcase_controls(b):
    doc(b, TR_IDOR).data["controls"].pop()
    assert "E-RESULT-CONTROLS" in codes(b)


def test_testcase_needs_a_reachability_control(b):
    tc = doc(b, TC_IDOR).data
    tc["controls"] = [c for c in tc["controls"] if c["kind"] != "reachability"]
    assert "E-TC-CONTROLS" in codes(b)


def test_precondition_reached_is_derived(b):
    doc(b, TR_ZAP).data["precondition_reached"]["value"] = False
    assert codes(b) >= {"E-RESULT-PRECONDITION"}


def test_positive_control_is_derived(b):
    doc(b, TR_IDOR).data["positive_control"]["value"] = None      # CTL-02 (oracle_can_fail) PASSed -> must be true
    assert "E-RESULT-CONTROLS" in codes(b)
    doc(b, TR_LLM).data["positive_control"]["value"] = True       # no oracle_can_fail control -> must be null
    assert len(errs(b, "E-RESULT-CONTROLS")) == 2


@pytest.mark.parametrize("fo,outcome", [([], "FAIL"), (["STATUS_AND_BODY"], "PASS"), (["TOOL_CALL_LOG"], "FAIL")])
def test_fail_oracles_rules(b, fo, outcome):
    tr = doc(b, TR_IDOR).data
    tr.update(fail_oracles=fo, outcome=outcome)
    assert "E-RESULT-ORACLE" in codes(b)


def test_report_metrics_recomputed(b):
    assert doc(b, "report-manifest.example.json").data["metrics"] == {"results_total": 5, "results_invalid": 0, "control_pass_rate": 1.0,
                                                                    "planned_access_matrix_coverage": 0.5714,
                                                                    "executed_access_matrix_coverage": 0.5714, "endpoint_slice_coverage": 0.8571,
                                                                    "planned_endpoint_test_coverage": 0.8571,
                                                                    "executed_endpoint_test_coverage": 0.8571}     # v0.5 BL-20, r7
    doc(b, "report-manifest.example.json").data["metrics"]["control_pass_rate"] = 0.9
    assert "E-REPORT-METRICS" in codes(b)


# ================================================================ A2 black-box-origin clusters
def test_black_box_cluster_needs_a_threat_without_source_cluster(b):
    doc(b, "cluster.k-201.example.json").data["threat_id"] = "T-012"      # T-012 has source cluster K-005
    assert "E-CLUSTER-ORIGIN" in codes(b)


def test_black_box_cluster_needs_an_endpoint(b):
    doc(b, "cluster.k-201.example.json").data["canonical_location"]["endpoint"] = None
    assert "E-CLUSTER-ORIGIN" in codes(b)


def test_white_box_cluster_needs_members(b):
    cl = doc(b, "cluster.example.json").data
    cl["threat_id"] = "T-012"
    assert "E-CLUSTER-ORIGIN" in codes(b)


def test_result_of_threat_without_source_cluster_is_recorded_on_a_black_box_cluster(b):
    doc(b, TR_ZAP).data["cluster_ids"] = []
    assert "E-CLUSTER-ORIGIN" in codes(b)
    doc(b, TR_ZAP).data["cluster_ids"] = ["K-201"]                # black_box, but of T-033, not T-027
    assert "E-CLUSTER-ORIGIN" in codes(b)


def test_pass_on_black_box_cluster_is_recorded(b):
    v = doc(b, V202).data
    assert v["test_evidence"]["class"] == "E_pass" and v["status"] == "UNCORROBORATED"
    assert [a["kind"] for a in v["annotations"]] == ["test_not_reproduced"]


def test_result_analyst_role_enforced(b):
    tr = doc(b, TR_IDOR).data
    tr["interpreted_by"] = {"agent_id": "rev_c", "family": "nvidia"}    # reviewer, same model as result_analyst
    assert "E-RESULT-ANALYST-ROLE" in codes(b)
    tr["interpreted_by"] = {"agent_id": "result_analyst_b", "family": "openai"}   # openai is in K-005: allowed role
    assert "E-RESULT-ANALYST-ROLE" not in codes(b)


def test_result_analyst_pool_has_one_per_family(b):
    agents = doc(b, "agents.yaml").data
    models = doc(b, "models.yaml").data
    fams = {models[a["model"]]["family"] for a in agents.values() if isinstance(a, dict) and a.get("role") == "result_analyst"}
    assert fams == {"anthropic", "openai", "nvidia"}


# ================================================================ A3 diversity / no eligible verifier
def _vote(agent, model, family, lineage, weight, stance="SUPPORT"):
    return {"voter_agent_id": agent, "voter_model_key": model, "voter_family": family, "voter_lineage": lineage, "stance": stance,
            "rationale": "r", "cited_evidence": ["routes/invoices.ts:42"], "fallback_used": None, "anonymized": True,
            "order_randomized": True, "valid": True, "weight": weight, "weighted_valid": weight > 0}


def test_two_family_cluster_with_third_family_vote_is_not_capped(b):
    """K-005 (openai + anthropic): E = {nvidia}; one weighted nvidia SUPPORT reaching theta -> CONFIRMED_CORROBORATED."""
    c = Ctx(b)
    v = copy.deepcopy(doc(b, V005).data)
    v.update(votes=[_vote("ver_1", "nemotron_self", "nvidia", "nemotron3", 0.6933)], theta_confirm=0.5, score=0.6933)
    cl = c.ix.first("cluster", cluster_id="K-005").data
    assert derived_diversity_degraded(c, v, cl) is False
    out = adjudicate(verdict_inputs(c, v, cl))
    assert (out.status, out.row, out.status_cap) == ("CONFIRMED_CORROBORATED", 11, None)


def test_one_family_cluster_with_one_of_two_eligible_families_is_capped(b):
    """K-011 (anthropic): E = {nvidia, openai}; only nvidia voted with weight -> degraded, R8 caps row 11 at LIKELY."""
    # v0.6 (review r7 3.2): nemotron's llm_specific refute side is near zero, which now zeroes both sides; make it
    # reliable so nvidia's vote carries weight again
    row = next(r for r in doc(b, "calibration.yaml").data["result"]["weights"]
               if r["model_key"] == "nemotron_self" and r["cwe_bucket"] == "llm_specific")
    row["support"]["w"], row["refute"]["near_zero"] = 1.2834, False
    c = Ctx(b)
    v = copy.deepcopy(doc(b, V011).data)
    v.update(theta_confirm=0.5)
    v["votes"][0].update(weight=1.2834, weighted_valid=True)
    cl = c.ix.first("cluster", cluster_id="K-011").data
    assert derived_diversity_degraded(c, v, cl) is True
    out = adjudicate(verdict_inputs(c, v, cl))
    assert (out.status, out.row, out.status_cap, out.rules) == ("LIKELY", 11, "LIKELY", ["R2", "R5", "R8"])


def test_no_eligible_verifier_is_derived(b):
    c = Ctx(b)
    cl = copy.deepcopy(c.ix.first("cluster", cluster_id="K-005").data)
    assert derived_no_eligible_verifier(c, cl) is False
    cl.update(families=["openai", "anthropic", "nvidia"], lineages=["gpt", "claude", "nemotron3"])
    assert derived_no_eligible_verifier(c, cl) is True
    assert derived_diversity_degraded(c, doc(b, V005).data, cl) is False         # nobody could vote: not "degraded"
    doc(b, V005).data["no_eligible_verifier"] = True
    assert "E-VERDICT-NOELIGIBLE" in codes(b)


# ================================================================ A4 fallback weight
def test_fallback_vote_uses_the_fallback_models_weight(b, keys):
    """claude_sonnet falls back to claude_opus_48, which has no calibration rows: w = 0, not weighted-valid.
    v0.4: on K-015 (white-box, authz); a black-box cluster has no location a vote could cite."""
    v = doc(b, "verdict.k-015-w3.example.json").data
    v["votes"] = [_vote("ver_2", "claude_opus_48", "anthropic", "claude", 0.5947)]
    v["votes"][0]["cited_evidence"] = ["inventory:/db/tables/0/rls_enabled"]
    v["votes"][0]["fallback_used"] = "claude_opus_48"
    rederive(b, keys)
    vt = v["votes"][0]
    assert vt["valid"] is True and vt["weight"] == 0.0 and vt["weighted_valid"] is False and v["score"] == 0.0
    assert "E-VERDICT-VOTE" not in codes(b)                  # a same-family fallback resolves through models.yaml
    vt.update(voter_model_key="claude_sonnet", fallback_used=None)
    rederive(b, keys)
    assert vt["weight"] == 1.2853 and vt["weighted_valid"] is True              # v0.7: likelihood-ratio weight, r8 prior, r10 abstentions


# ================================================================ E5 provisional
def test_provisional_examples(b):
    # v0.4: black-box clusters are never provisional (no votes possible), whatever the bucket's calibration
    assert doc(b, V202).data["provisional"] is False
    assert doc(b, V201).data["provisional"] is False


def test_provisional_is_derived(b, keys):
    doc(b, V202).data["provisional"] = True
    rederive(b, keys)                                    # the report manifest lists V-202-1 by hash
    assert codes(b) == {"E-VERDICT-PROVISIONAL"}


def test_provisional_without_theta(b):
    c = Ctx(b)
    v = copy.deepcopy(doc(b, V014).data)
    cl = c.ix.first("cluster", cluster_id="K-014").data
    assert derived_provisional(c, v, cl) is False
    v["theta_confirm"] = None
    assert derived_provisional(c, v, cl) is True
    v.update(theta_confirm=1.2, calibration_version=None)
    assert derived_provisional(c, v, cl) is True


def test_verdict_rule_version_must_match(b):
    doc(b, V014).data["rule_version"] = "05-v0.2"
    assert "E-VERDICT-RULE-VERSION" in codes(b)
