# SPDX-License-Identifier: Apache-2.0
"""BL-66 (review r10): audit log, run, gate, L-level and ROE checks — every error code below is triggered by at least one test.
Each test fails when its check is disabled (tests/mutations/bl66_run_gates.json); see CONTRIBUTING.md.

  audit     E-AUDIT-RUN, E-AUDIT-TS, E-AUDIT-INITIATOR
  run       E-RUN, E-RUN-OWASP, E-RUN-DEADLINE, E-RUN-GATES, E-RUN-BUDGET, E-RUN-JOB
  gate      E-GATE-G0-SIG, E-GATE-TIME, E-GATE-ENGAGEMENT, E-GATE-ROLES, E-GATE-G0-APPROVERS, E-GB-APPROVER,
            E-G5-JOB, E-GATE-JOB
  ROE       E-ROE-ENGAGEMENT, E-ROE-VALIDITY, E-ROE-SIGNATORIES, E-ROE-S3, E-ROE-TOOLS, E-ROE-RELAY, E-ROE-DATA-CLASS
  legal     E-L1, E-L2, E-L3, W-L2-MANAGEMENT
A check with several branches gets one test per branch; where another branch of the same code would also fire on
the probe, the test pins the branch by its message.
"""
import pytest

from conftest import codes, doc, resign_gate
from vchlib import crypto
from vchlib.checks import run_all

RUN = "run.example.json"
FOLLOWUP = "run.followup.example.json"
AUDIT = "audit-event.run-2026-09-23-001.example.jsonl"


def msgs(bundle, code):
    return [i.msg for i in run_all(bundle).errors if i.code == code]


def resign(bundle, suffix, keys):
    """Re-sign a signed YAML document (engagement / ROE) with the TEST ONLY keys of its own signers."""
    d = doc(bundle, suffix).data
    d["signatures"] = [crypto.sign_document(d, s["signer"], keys[s["signer"]]) for s in d["signatures"]]
    return d


def event(bundle, event_type, n=0):
    return [e for e in doc(bundle, AUDIT).data if e["event_type"] == event_type][n]


def test_the_example_bundle_is_clean(b):
    assert codes(b) == set()


# ---------------------------------------------------------------- audit log

def test_e_audit_run_log_of_an_unknown_run(b):
    for ev in doc(b, AUDIT).data:
        ev["run_id"] = "run-does-not-exist"
    assert any("run-does-not-exist not found" in m for m in msgs(b, "E-AUDIT-RUN"))


def test_e_audit_run_event_of_another_engagement(b):
    doc(b, AUDIT).data[3]["engagement_id"] = "eng-other"
    assert "run/engagement mismatch" in msgs(b, "E-AUDIT-RUN")


def test_e_audit_run_event_data_class_differs_from_the_run(b):
    doc(b, AUDIT).data[3]["data_class"] = "P"
    assert "data_class differs from the run" in msgs(b, "E-AUDIT-RUN")


def test_e_audit_ts_timestamps_go_backwards(b):
    evs = doc(b, AUDIT).data
    evs[10]["ts"] = "2026-09-23T09:00:00+08:00"
    assert "E-AUDIT-TS" in codes(b)


def test_e_audit_initiator_claim_by_a_non_initiator(b):
    ev = event(b, "initiator_claim")
    ev["actor"]["id"] = "frank"                 # a registered person, but not in run.initiators
    assert "E-AUDIT-INITIATOR" in codes(b)


# ---------------------------------------------------------------- run

@pytest.mark.parametrize("field,value,msg", [
    ("engagement_id", "eng-other", "engagement_id mismatch"),
    ("data_class", "P", "data_class differs from the engagement"),
    ("calibration_version", 999, "calibration_version differs"),
])
def test_e_run_field_differs_from_the_engagement(b, field, value, msg):
    doc(b, RUN).data[field] = value
    assert msg in msgs(b, "E-RUN")


def test_e_run_owasp_wrong_version(b):
    doc(b, RUN).data["owasp_llm_version"] = "2019"
    assert "E-RUN-OWASP" in codes(b)


def test_e_run_deadline_not_opened_at_plus_timeout(b):
    run = doc(b, FOLLOWUP).data
    assert run["status"] == "WAITING_GATE"
    run["resume_deadline"] = "2026-10-11T10:30:00+08:00"   # G4 opened 10-07 10:30, timeout 72 h -> 10-10 10:30
    assert "E-RUN-DEADLINE" in codes(b)


def test_e_run_gates_out_of_opened_at_order(b):
    grs = doc(b, RUN).data["gate_records"]
    grs[1], grs[2] = grs[2], grs[1]
    assert "gate_records are not in opened_at order" in msgs(b, "E-RUN-GATES")


def test_e_run_gates_listed_record_not_found(b):
    doc(b, RUN).data["gate_records"][1]["gate_record_id"] = "GR-G1-9999"
    assert "gate record GR-G1-9999 not found" in msgs(b, "E-RUN-GATES")


def test_e_run_budget_does_not_carry_the_gb_new_caps(b):
    doc(b, RUN).data["budgets"]["W"]["max_cost_usd"] = 140
    assert "budgets.W must carry the GB new_caps" in msgs(b, "E-RUN-BUDGET")


def test_e_run_budget_spent_exceeds_the_cap(b):
    doc(b, RUN).data["budgets"]["B"]["spent_cost_usd"] = 51
    assert "budgets.B.spent_cost_usd exceeds max_cost_usd" in msgs(b, "E-RUN-BUDGET")


def test_e_run_job_id_differs_from_its_key(b):
    doc(b, RUN).data["jobs"]["job-idor-001"]["job_id"] = "job-other"
    assert "job_id != key" in msgs(b, "E-RUN-JOB")


def test_e_run_job_testcase_not_found(b):
    doc(b, RUN).data["jobs"]["job-idor-001"]["testcase_id"] = "TC-999-01"
    assert "testcase not found" in msgs(b, "E-RUN-JOB")


def test_e_run_job_testcase_not_approved_at_g4(b):
    run = doc(b, RUN).data
    run["approved_testcase_ids"].remove("TC-012-01")
    assert "job for a testcase not approved at G4" in msgs(b, "E-RUN-JOB")


# ---------------------------------------------------------------- gates

def test_e_gate_g0_sig_g0a_carries_a_signature(b, keys):
    rec = doc(b, "gate-record.g0a.example.json").data
    rec["signatures"] = [crypto.sign_document(rec, "frank", keys["frank"])]
    assert "E-GATE-G0-SIG" in codes(b)


def test_e_gate_time_opened_after_the_decision(b):
    doc(b, "gate-record.g0a.example.json").data["opened_at"] = "2026-09-23T10:02:00+08:00"
    assert "E-GATE-TIME" in codes(b)


def test_e_gate_engagement_decided_before_the_engagement_validity(b, keys):
    eng = doc(b, "engagement.yaml").data
    eng["validity"]["not_before"] = "2026-09-24T00:00:00+08:00"   # G0a was decided 09-23 10:01
    resign(b, "engagement.yaml", keys)
    assert "E-GATE-ENGAGEMENT" in codes(b)


def test_e_gate_roles_g3_without_an_app_owner(b, keys):
    rec = doc(b, "gate-record.g3.example.json").data
    rec["approvers"] = [a for a in rec["approvers"] if a["role"] != "app_owner"]
    resign_gate(b, "gate-record.g3.example.json", keys)
    assert "E-GATE-ROLES" in codes(b)


def test_e_gate_g0_approvers_g0a_not_the_engagement_signatories(b):
    rec = doc(b, "gate-record.g0a.example.json").data
    rec["approvers"] = rec["approvers"][:1]
    assert "G0a approvers must be the engagement signatories" in msgs(b, "E-GATE-G0-APPROVERS")


def test_e_gate_g0_approvers_g0b_not_the_roe_signatories(b):
    rec = doc(b, "gate-record.g0b.example.json").data
    rec["approvers"] = rec["approvers"][:-1]
    assert "G0b approvers must be the ROE signatories" in msgs(b, "E-GATE-G0-APPROVERS")


def test_e_gb_approver_neither_run_owner_nor_budget_approver(b, keys):
    rec = doc(b, "gate-record.gb.example.json").data
    frank = next(a for a in doc(b, "gate-record.g1.example.json").data["approvers"] if a["person_id"] == "frank")
    rec["approvers"] = [dict(frank)]
    resign_gate(b, "gate-record.gb.example.json", keys)
    assert "E-GB-APPROVER" in codes(b)


def test_e_g5_job_references_a_non_s2_job(b, keys):
    rec = doc(b, "gate-record.g5.example.json").data
    rec["job_id"] = "job-idor-001"                     # an S1 job of the run
    resign_gate(b, "gate-record.g5.example.json", keys)
    assert "E-G5-JOB" in codes(b)


def test_e_gate_job_on_a_gate_other_than_g5(b, keys):
    rec = doc(b, "gate-record.g4.example.json").data
    rec["job_id"] = "job-zap-active-001"
    resign_gate(b, "gate-record.g4.example.json", keys)
    assert "E-GATE-JOB" in codes(b)


# ---------------------------------------------------------------- ROE

def test_e_roe_engagement_wrong_version(b, keys):
    doc(b, "roe.yaml").data["engagement"]["version"] = 999
    resign(b, "roe.yaml", keys)
    assert "E-ROE-ENGAGEMENT" in codes(b)


def test_e_roe_validity_not_before_after_not_after(b, keys):
    v = doc(b, "roe.yaml").data["validity"]
    v["not_after"] = v["not_before"]
    resign(b, "roe.yaml", keys)
    assert "not_before must precede not_after" in msgs(b, "E-ROE-VALIDITY")


def test_e_roe_validity_outside_the_engagement_validity(b, keys):
    doc(b, "roe.yaml").data["validity"]["not_after"] = "2026-11-30T23:59:59+08:00"
    resign(b, "roe.yaml", keys)
    assert "ROE validity must lie inside the engagement validity" in msgs(b, "E-ROE-VALIDITY")


def test_e_roe_signatories_missing_a_required_role(b):
    r = doc(b, "roe.yaml").data
    r["signatories"] = [s for s in r["signatories"] if s["role"] != "infrastructure_owner"]
    assert "E-ROE-SIGNATORIES" in codes(b)


def test_e_roe_s3_allowed(b, keys):
    doc(b, "roe.yaml").data["activities"]["allowed_safety_classes"].append("S3")
    resign(b, "roe.yaml", keys)
    assert "E-ROE-S3" in codes(b)


def test_e_roe_tools_allowed_tool_not_b4_executable(b, keys):
    doc(b, "roe.yaml").data["activities"]["allowed_tools"].append("no-such-tool")
    resign(b, "roe.yaml", keys)
    assert any("no-such-tool" in m for m in msgs(b, "E-ROE-TOOLS"))


def test_e_roe_tools_denied_mode_not_registered(b, keys):
    doc(b, "roe.yaml").data["activities"]["denied_modes"].append("no-such-tool:scan")
    resign(b, "roe.yaml", keys)
    assert any("denied mode 'no-such-tool:scan' is not registered" in m for m in msgs(b, "E-ROE-TOOLS"))


def test_e_roe_relay_limit_above_the_toolkit(b, keys):
    doc(b, "roe.yaml").data["relay"]["max_turns"] = 10_000
    resign(b, "roe.yaml", keys)
    assert "relay.max_turns exceeds toolkit relay" in msgs(b, "E-ROE-RELAY")


def test_e_roe_relay_model_not_allowed_for_the_data_class(b, keys):
    doc(b, "roe.yaml").data["relay"]["models"] = ["nemotron_cloud"]    # allowed for P, not for C
    resign(b, "roe.yaml", keys)
    assert "relay model nemotron_cloud not allowed for the data class" in msgs(b, "E-ROE-RELAY")


def test_e_roe_data_class_differs_from_the_engagement(b, keys):
    doc(b, "roe.yaml").data["data_handling"]["data_class"] = "P"
    resign(b, "roe.yaml", keys)
    assert "E-ROE-DATA-CLASS" in codes(b)


# ---------------------------------------------------------------- legal review (L-1 .. L-3)

def test_e_l1_legal_review_missing(b, keys):
    del doc(b, "roe.yaml").data["legal_review"]
    resign(b, "roe.yaml", keys)
    assert any("legal_review is required" in m for m in msgs(b, "E-L1"))


def test_e_l1_scope_item_neither_true_nor_justified(b, keys):
    doc(b, "roe.yaml").data["legal_review"]["scope"]["privacy"] = False
    resign(b, "roe.yaml", keys)
    assert "legal_review.scope.privacy must be true or carry not_applicable_reason" in msgs(b, "E-L1")


def test_e_l2_attester_has_no_registry_key(b, keys):
    doc(b, "roe.yaml").data["legal_review"]["attested_by"] = "nobody"
    resign(b, "roe.yaml", keys)
    assert any("has no unrevoked registry key" in m for m in msgs(b, "E-L2"))


def test_e_l2_attester_has_neither_legal_nor_management_role(b, keys):
    doc(b, "roe.yaml").data["legal_review"]["attested_by"] = "alice"     # test_lead only
    resign(b, "roe.yaml", keys)
    assert any("neither the legal_reviewer nor the management role" in m for m in msgs(b, "E-L2"))


def test_w_l2_management_attests_the_legal_review(b, keys):
    doc(b, "roe.yaml").data["legal_review"]["attested_by"] = "carol"     # management, signs the ROE
    resign(b, "roe.yaml", keys)
    R = run_all(b)
    assert "W-L2-MANAGEMENT" in {w.code for w in R.warnings}
    assert "E-L2" not in R.codes()


def test_e_l3_attester_did_not_sign_the_roe(b, keys):
    r = doc(b, "roe.yaml").data
    att = r["legal_review"]["attested_by"]
    r["signatures"] = [s for s in r["signatures"] if s["signer"] != att]
    assert "E-L3" in codes(b)
