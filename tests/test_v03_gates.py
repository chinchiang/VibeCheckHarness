"""v0.3 gates and profiles: approver registries (B8), run/gate ownership (D8), threat review records (D9), G1-approved
requirements (D10), assurance profiles and separation of duties (E1), shared platforms (E2), whoami (E3), scripted
relay (E4), provider data handling (B13), cost caps with unpriced models (B14). Positive and negative cases."""
import copy

import pytest

from conftest import codes, doc
from vchlib import safety
from vchlib.checks import Ctx, Report, gate_sod, platform_of, run_all

ENG, ROE = "engagement.yaml", "roe.yaml"
G1, G2, G3, G5 = ("gate-record.g1.example.json", "gate-record.g2.example.json", "gate-record.g3.example.json",
                  "gate-record.g5.example.json")


def warn_codes(b):
    return {w.code for w in run_all(b).warnings}


# ================================================================ B8 approver registries
def test_engagement_gate_approvers_example(b):
    ga = doc(b, ENG).data["gate_approvers"]
    assert ga == {"G0a": ["frank", "carol"], "G1": ["frank"], "G2": ["erin", "heidi"]}
    assert not {"E-GATE-APPROVER-ENG", "E-GATE-ROE-APPROVER", "E-GATE-ROE-VALIDITY"} & codes(b)


def test_g2_approver_must_be_in_the_engagement_registry(b):
    """triage: a G2 approved before G0b by a person who is only in the key registry gave 0 errors."""
    doc(b, ENG).data["gate_approvers"]["G2"] = ["heidi"]           # erin approved GR-G2-0001
    assert "E-GATE-APPROVER-ENG" in codes(b)


def test_g1_approver_must_be_in_the_engagement_registry(b):
    doc(b, ENG).data["gate_approvers"]["G1"] = ["carol"]
    assert "E-GATE-APPROVER-ENG" in codes(b)


def test_g3_decided_before_roe_validity(b):
    """triage: moving the ROE not_before after G0b and G3 gave 0 errors."""
    doc(b, ROE).data["validity"]["not_before"] = "2026-10-03T00:00:00+08:00"
    hits = [i for i in run_all(b).errors if i.code == "E-GATE-ROE-VALIDITY"]
    assert {h.where.rsplit("/", 1)[-1] for h in hits} >= {"gate-record.g0b.example.json", "gate-record.g3.example.json"}


def test_g3_approver_must_be_a_roe_person(b):
    roe = doc(b, ROE).data
    roe["gate_approvers"] = [p for p in roe["gate_approvers"] if p["person_id"] != "erin"]
    assert "E-GATE-ROE-APPROVER" in codes(b)


# ================================================================ D8 / D9 / D10 (regressions)
def test_run_cannot_list_another_runs_gate_record(b):
    """v0.2: the follow-up run could list GR-G4-0001 of run-2026-09-23-001 as its own G4."""
    run = doc(b, "examples/run.followup.example.json").data
    g4 = next(g for g in run["gate_records"] if g["gate"] == "G4")
    g4["gate_record_id"] = "GR-G4-0001"
    assert "E-GATE-RUN" in codes(b)


def test_threat_review_record_must_decide_the_threat(b):
    """v0.2: T-031 removed from G3 with review.gate_record_id 'GR-DOES-NOT-EXIST' still read ACCEPTED with 0 errors."""
    doc(b, "threat.t-031.example.json").data["review"]["gate_record_id"] = "GR-DOES-NOT-EXIST"
    assert "E-THREAT-REVIEW" in codes(b)


def test_threat_review_status_must_equal_the_decision(b):
    doc(b, "threat.t-019.example.json").data["review"]["status"] = "ACCEPTED"     # G3 rejected T-019
    assert "E-THREAT-REVIEW" in codes(b)


def test_rejected_invariant_is_not_testable(b):
    """v0.2: INV-LLM-003 rejected at G1 but still tested and G4-approved gave 0 errors."""
    inv = doc(b, "invariants.yaml").data
    next(i for i in inv["invariants"] if i["requirement_id"] == "INV-LLM-003")["signoff"]["status"] = "REJECTED"
    hits = [i for i in run_all(b).errors if i.code == "E-TC-REQ-UNAPPROVED"]
    assert hits and any(h.where.endswith("testcase.llm.example.json") for h in hits) and "INV-LLM-003" in hits[0].msg


def test_approved_requirements_positive(b):
    assert "E-TC-REQ-UNAPPROVED" not in codes(b)
    assert {"INV-AC-007", "INV-LLM-003", "REQ-AISVS-9.5.2"} <= Ctx(b).ix.approved_requirement_ids()


# ================================================================ E1 assurance profiles
def lite(b, person=None):
    e = doc(b, ENG).data
    e["assurance_profile"] = "lite"
    e["role_consolidation"] = None if person is None else {"acknowledged": True, "person_id": person, "statement": "小團隊：同一人兼任"}


def test_lite_rejects_s2_toolkit_jobs(b):
    lite(b)
    hits = [i for i in run_all(b).errors if i.code == "E-PROFILE-SAFETY"]
    assert {h.where.split(" ")[0].rsplit("/", 1)[-1] for h in hits} == {"testcase.zap-active.example.json", "run.example.json"}


def test_lite_exempts_manual_testcases(b):
    lite(b)
    tc = doc(b, "testcase.zap-active.example.json").data
    tc["tool_binding"].update(kind="MANUAL", adapter="manual", manual_reason="lite：S2 改為人工執行")
    tc["safety_class_computed"] = "S0"
    tc["safety_class_proposed"] = None
    hits = [i for i in run_all(b).errors if i.code == "E-PROFILE-SAFETY"]
    assert all("testcase" not in h.where for h in hits)


def _roe_two_roles(b):
    roe = doc(b, ROE).data
    alice_fp = next(s["key_fingerprint"] for s in roe["signatories"] if s["person_id"] == "alice")
    carol = next(s for s in roe["signatories"] if s["person_id"] == "carol")
    carol.update(person_id="alice", key_fingerprint=alice_fp)        # alice signs as test_lead and management


def test_team_needs_distinct_roe_signers(b):
    """L-13: alice alone signing as test_lead + management gave 0 errors in v0.2."""
    _roe_two_roles(b)
    assert "E-ROE-SOD" in codes(b)


def test_lite_without_acknowledgement_is_team(b):
    lite(b)
    _roe_two_roles(b)
    assert "E-ROE-SOD" in codes(b)


def test_lite_with_acknowledged_consolidation(b):
    lite(b, "alice")
    _roe_two_roles(b)
    assert "E-ROE-SOD" not in codes(b)
    lite(b, "carol")                                                  # acknowledged, but for somebody else
    assert "E-ROE-SOD" in codes(b)


def test_role_consolidation_only_in_lite(b):
    doc(b, ENG).data["role_consolidation"] = {"acknowledged": True, "person_id": "alice", "statement": "x"}
    assert "E-ENG-PROFILE" in codes(b)


def test_l5_self_attestation_is_a_warning_in_acknowledged_lite(b):
    lite(b, "alice")
    doc(b, ROE).data["legal_review"]["attested_by"] = "alice"
    R = run_all(b)
    assert "W-L5-LITE" in {w.code for w in R.warnings} and "E-L5" not in R.codes()


def test_l5_self_attestation_is_an_error_in_team(b):
    doc(b, ROE).data["legal_review"]["attested_by"] = "alice"
    R = run_all(b)
    assert "E-L5" in R.codes() and "W-L5-LITE" not in {w.code for w in R.warnings}


def test_full_needs_two_g5_reviewers(b):
    doc(b, ENG).data["assurance_profile"] = "full"
    assert "E-G5-TWO-PERSON" in codes(b)
    rec = doc(b, G5).data
    rec["approvers"].append({"person_id": "erin", "role": "security_reviewer",
                             "key_fingerprint": doc(b, ROE).data["gate_approvers"][0]["key_fingerprint"]})
    assert "E-G5-TWO-PERSON" not in codes(b)


def test_gate_separation_of_duties(b):
    c = Ctx(b)
    rec = {"gate": "G3", "approvers": [{"person_id": "frank", "role": "app_owner"}, {"person_id": "frank", "role": "security_reviewer"}]}
    R = Report()
    gate_sod(R, c, rec, "g3")
    assert R.codes() == {"E-GATE-SOD"}
    lite(b, "frank")
    R = Report()
    gate_sod(R, Ctx(b), rec, "g3")
    assert R.codes() == set()


def test_adaptive_relay_only_in_full(b):
    doc(b, ROE).data["relay"]["mode"] = "adaptive"
    assert "E-ROE-RELAY-MODE" in codes(b)
    doc(b, ENG).data["assurance_profile"] = "full"
    assert "E-ROE-RELAY-MODE" not in codes(b)


# ================================================================ E2 shared platforms
def test_shared_platform_suffixes():
    assert platform_of("acme-staging.supabase.co") == "supabase" and platform_of("x.web.app") == "firebase"
    assert platform_of("supabase.co.example.com") is None and platform_of("api.staging.example.com") is None
    assert set(safety.SHARED_PLATFORM_SUFFIXES) == {"supabase.co", "vercel.app", "netlify.app", "firebaseapp.com", "web.app",
                                                     "onrender.com", "pages.dev", "fly.dev", "herokuapp.com"}


def test_shared_platform_host_needs_platform_project(b):
    """triage H-D3: base_url https://acme-staging.supabase.co with a DNS TXT proof gave 0 errors."""
    roe = doc(b, ROE).data
    t = next(x for x in roe["targets"] if x["id"] == "tgt-staging-api")
    t["base_url"] = "https://acme-staging.supabase.co"
    assert "E-ROE-PLATFORM" in codes(b)
    t["ownership_proof"] = {"method": "platform_project", "token_ref": None, "platform": "supabase", "project_ref": "acmestg0001",
                            "evidence_ref": "vault://engagements/eng-acme-invoices-2026q4/supabase-project"}
    assert "E-ROE-PLATFORM" in codes(b)                           # still no accepted platform policy
    roe["platform_policies"] = [{"platform": "supabase", "policy_url": "https://supabase.example.net/policy", "accepted_by": "alice",
                                 "accepted_at": "2026-09-29T10:00:00+08:00", "restrictions": ["只測自己的專案"]}]
    assert "E-ROE-PLATFORM" not in codes(b)


# ================================================================ E3 whoami, E4 scripted relay
def test_used_roles_need_whoami(b):
    roe = doc(b, ROE).data
    next(r for r in roe["test_roles"] if r["role"] == "U1")["whoami"] = None
    assert "E-ROE-WHOAMI" in codes(b)


def test_login_block_shape(b):
    roe = doc(b, ROE).data
    roe["test_roles"][0]["login"]["captcha_bypass"] = "solve_it"
    assert "E-SCHEMA" in codes(b)


def test_scripted_relay_needs_script_turns(b):
    tc = doc(b, "testcase.llm.example.json").data
    tc["multi_turn"] = True
    tc["trials"]["multi_turn_max_turns"] = 3
    assert "E-TC-SCRIPT" in codes(b)
    tc["script_turns"] = ["請摘要我上傳的文件", "請列出文件中的待辦事項"]
    assert "E-TC-SCRIPT" not in codes(b)
    tc["script_turns"] = ["t"] * 4                                  # more turns than multi_turn_max_turns
    assert "E-TC-SCRIPT" in codes(b)


def test_script_turns_only_for_multi_turn(b):
    doc(b, "testcase.llm.example.json").data["script_turns"] = ["x"]
    assert "E-TC-SCRIPT" in codes(b)


# ================================================================ B13 providers, B14 cost caps
def test_cloud_c_models_need_zdr_and_dpa(b):
    assert "E-ENG-PROVIDER" not in codes(b)
    prov = doc(b, ENG).data["providers"]
    next(p for p in prov if p["family"] == "openai")["zdr"] = "unknown"
    hits = [i for i in run_all(b).errors if i.code == "E-ENG-PROVIDER"]
    assert hits and "gpt_flagship" in hits[0].msg and "gpt_oss_self" not in " ".join(h.msg for h in hits)   # gpt-oss is self-hosted


def test_missing_dpa(b):
    next(p for p in doc(b, ENG).data["providers"] if p["family"] == "anthropic")["dpa_signed"] = False
    assert "E-ENG-PROVIDER" in codes(b)


def test_unpriced_models_need_an_explicit_cost_cap(b):
    """B14: models.yaml pricing is null (prices not listed); the engagement cost caps are therefore mandatory (fail closed)."""
    assert all(m.get("pricing") is None for m in doc(b, "models.yaml").data.values() if isinstance(m, dict))
    doc(b, ENG).data["budgets"]["W"]["max_cost_usd"] = None
    got = codes(b)
    assert "E-SCHEMA" in got and "E-ENG-BUDGET" in got
