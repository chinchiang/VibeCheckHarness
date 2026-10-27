# SPDX-License-Identifier: Apache-2.0
"""BL-66 (review r10): agent, model, finding, trace, crosswalk, testcase, result and verdict checks — every error code below is triggered by at least one test.
Each test fails when its check is disabled (tests/mutations/bl66_pipeline.json); see CONTRIBUTING.md.

E-AGENT and E-MODEL guard a registry entry that is not a mapping. run_all never lets such an entry through: the
input-shape quarantine (D5) reports E-INPUT-SHAPE and hides the whole file first, so those two tests call g_models
directly on a context built from the unquarantined bundle (defence in depth behind E-INPUT-SHAPE).
"""
from conftest import codes, doc

from vchlib import crypto
from vchlib.checks import Ctx, Report, g_models, run_all


def warnings(bundle):
    return {i.code for i in run_all(bundle).warnings}


def agents(b):
    return doc(b, "agents.yaml").data


def models(b):
    return doc(b, "models.yaml").data


def g_models_codes(b):
    R = Report()
    g_models(R, Ctx(b))
    return R.codes()


# ---------------------------------------------------------------- agents.yaml / models.yaml
def test_e_agent_entry_that_is_not_a_mapping(b):
    agents(b)["bogus"] = "not an agent"
    assert "E-INPUT-SHAPE" in codes(b)            # run_all: the quarantine catches it first
    assert "E-AGENT" in g_models_codes(b)


def test_e_agent_data_class_model_not_allowed_for_the_engagement_class(b):
    agents(b)["test_critic"]["model"] = "nemotron_cloud"     # P-only model on a C engagement
    assert "E-AGENT-DATA-CLASS" in codes(b)


def test_e_agent_fallback_only_on_non_adjudicating_roles(b):
    agents(b)["test_critic"]["fallback_models"] = ["claude_opus_48"]
    assert "E-AGENT-FALLBACK" in codes(b)


def test_e_agent_fallback_model_must_be_allowed(b):
    agents(b)["reporter"]["fallback_models"] = ["nemotron_cloud"]   # reporter may fall back, but not to a P-only model
    assert "E-AGENT-FALLBACK" in codes(b)


def test_e_agent_lane_a_model_must_equal_the_engagement(b):
    agents(b)["lane_a"]["model"] = "claude_sonnet"
    assert "E-AGENT-LANE-A" in codes(b)


def test_e_agent_model_deterministic_role_has_no_model(b):
    agents(b)["aggregator"]["model"] = "claude_sonnet"
    assert "E-AGENT-MODEL" in codes(b)


def test_e_agent_model_llm_role_needs_a_model(b):
    agents(b)["test_critic"]["model"] = None
    assert "E-AGENT-MODEL" in codes(b)


def test_e_model_entry_that_is_not_a_mapping(b):
    models(b)["bogus"] = "not a model"
    assert "E-INPUT-SHAPE" in codes(b)
    assert "E-MODEL" in g_models_codes(b)


def test_e_model_fallback_is_same_family(b):
    models(b)["claude_sonnet"]["fallback"] = ["claude_opus_48", "gpt_flagship"]
    assert "E-MODEL-FALLBACK" in codes(b)


def test_e_model_nim_trial_endpoint_is_not_production(b):
    models(b)["nemotron_cloud"]["purpose"] = ["evaluation", "production"]
    assert "E-MODEL-NIM" in codes(b)


def test_w_diversity_reviewers_of_one_family(b):
    assert "W-DIVERSITY" not in warnings(b)
    agents(b)["rev_b"]["model"] = "claude_sonnet"
    agents(b)["rev_c"]["model"] = "claude_sonnet"
    assert "W-DIVERSITY" in warnings(b)


# ---------------------------------------------------------------- findings, votes, results, slices
def test_e_finding_reporter_lineage_disagrees_with_the_registry(b):
    doc(b, "finding.example.json").data["reporter"]["lineage"] = "gpt-oss"
    assert "E-FINDING-REPORTER" in codes(b)


def test_e_vote_model_voter_lineage_disagrees_with_the_registry(b):
    doc(b, "verdict.k-014-w3.example.json").data["votes"][0]["voter_lineage"] = "gpt-oss"
    assert "E-VOTE-MODEL" in codes(b)


def test_e_result_analyst_family_disagrees_with_the_agent(b):
    doc(b, "testresult.example.json").data["interpreted_by"]["family"] = "openai"
    assert "E-RESULT-ANALYST" in codes(b)


def test_e_result_analyst_interpretation_without_analyst(b):
    doc(b, "testresult.example.json").data["interpreted_by"] = None     # interpretation stays set
    assert "E-RESULT-ANALYST" in codes(b)


def test_e_slice_excluded_for_a_data_class_the_model_takes(b):
    doc(b, "slice.example.json").data["excluded_models"][0]["model_key"] = "gpt_oss_self"
    assert codes(b) == {"E-SLICE-EXCLUDED"}


def test_w_cluster_bucket_member_cwe_without_a_bucket(b):
    assert "W-CLUSTER-BUCKET" not in warnings(b)
    doc(b, "finding.f-052.example.json").data["cwe"] = ["CWE-99999"]       # sole member of K-014
    assert "W-CLUSTER-BUCKET" in warnings(b)


# ---------------------------------------------------------------- trace and crosswalk
def test_e_threat_llm_link_on_an_accepted_threat(b):
    x = doc(b, "threat.example.json").data["crosswalk"][0]
    x["provenance"], x["reviewed_by"] = "llm-suggested", None
    assert "E-THREAT-LLM-LINK" in codes(b)


def test_e_trace_invariant_signoff_disagrees_with_g1(b):
    doc(b, "invariants.yaml").data["invariants"][0]["signoff"]["status"] = "REJECTED"
    assert "E-TRACE-INVARIANT" in codes(b)


def test_e_trace_requirement_invariant_copy_differs(b):
    doc(b, "requirement.invariant.example.json").data["statement"] = "changed"
    assert "E-TRACE-REQUIREMENT" in codes(b)


def test_e_trace_requirement_baseline_ref_differs(b):
    doc(b, "requirement.asvs.example.json").data["ref"] = "v5.0.0-8.2.1"
    assert "E-TRACE-REQUIREMENT" in codes(b)


def test_e_xwalk_dup_duplicate_link(b):
    links = doc(b, "crosswalk.yaml").data["links"]
    links.append(dict(links[0]))
    assert "E-XWALK-DUP" in codes(b)


def test_e_xwalk_owasp_threat_taxonomy_version_differs_from_the_run(b):
    doc(b, "threat.example.json").data["taxonomy"].append({"scheme": "owasp-llm@2025", "id": "LLM01"})
    assert "E-XWALK-OWASP" in codes(b)


def test_e_xwalk_owasp_default_differs_from_the_toolkit(b):
    doc(b, "crosswalk.yaml").data["owasp_llm_default"] = "2025"
    assert "E-XWALK-OWASP" in codes(b)


def test_e_xwalk_owasp_unknown_version_in_a_link(b):
    doc(b, "crosswalk.yaml").data["links"][5]["from_scheme"] = "owasp-llm@2019"
    assert "E-XWALK-OWASP" in codes(b)


def test_e_xwalk_review_curated_threat_link_without_reviewer(b):
    doc(b, "threat.example.json").data["crosswalk"][0]["reviewed_by"] = None
    assert "E-XWALK-REVIEW" in codes(b)


def test_e_xwalk_review_curated_crosswalk_link_without_reviewer(b):
    doc(b, "crosswalk.yaml").data["links"][0]["reviewed_by"] = None
    assert "E-XWALK-REVIEW" in codes(b)


# ---------------------------------------------------------------- testcases
def test_e_tc_oracle_query_not_in_the_manifest(b):
    doc(b, "testcase.idor.example.json").data["oracle"]["oracle_query_id"] = "Q-nope"
    assert "E-TC-ORACLE" in codes(b)


def test_e_tc_oracle_requirement_ref_not_in_requirement_ids(b):
    doc(b, "testcase.idor.example.json").data["oracle"]["requirement_refs"].append("INV-NOPE")
    assert "E-TC-ORACLE" in codes(b)


def test_e_tc_roles_not_in_the_roe(b):
    doc(b, "testcase.idor.example.json").data["data_needed"]["roles"].append("ghost")
    assert "E-TC-ROLES" in codes(b)


def _multi_turn(b, max_turns):
    tc = doc(b, "testcase.llm.example.json").data
    tc["multi_turn"], tc["script_turns"] = True, ["hi"]
    tc["trials"]["multi_turn_max_turns"] = max_turns


def test_e_tc_relay_multi_turn_needs_a_roe_relay(b, keys):
    _multi_turn(b, 3)
    assert "E-TC-RELAY" not in codes(b)
    roe = doc(b, "roe.yaml").data
    roe["relay"]["models"] = []
    roe["signatures"] = [crypto.sign_document(roe, s["signer"], keys[s["signer"]]) for s in roe["signatures"]]
    assert "E-TC-RELAY" in codes(b)


def test_e_tc_relay_max_turns_over_the_roe(b):
    _multi_turn(b, 99)
    assert "E-TC-RELAY" in codes(b)


def test_e_tc_relay_max_turns_only_for_multi_turn(b):
    doc(b, "testcase.idor.example.json").data["trials"]["multi_turn_max_turns"] = 3
    assert "E-TC-RELAY" in codes(b)


# ---------------------------------------------------------------- results and verdicts
def test_e_result_job_b4_job_not_in_the_run(b):
    doc(b, "testresult.example.json").data["job_id"] = "job-nope"
    assert "E-RESULT-JOB" in codes(b)


def test_e_result_job_w4_result_has_no_job(b):
    doc(b, "testresult.w4-k-015.example.json").data["job_id"] = "job-idor-001"
    assert "E-RESULT-JOB" in codes(b)


def test_e_verdict_calibration_version_differs(b):
    doc(b, "verdict.example.json").data["calibration_version"] = 99
    assert "E-VERDICT-CALIBRATION" in codes(b)


def test_e_verdict_proof_interpretation_from_a_cluster_family(b):
    doc(b, "verdict.executable.example.json").data["executable_proof"]["interpretation_confirmed_by"]["family"] = "openai"
    assert "E-VERDICT-PROOF" in codes(b)

