"""Negative tests: each mutation of the (valid) example bundle must be caught with a specific code."""
import datetime as dt

import pytest
import rfc8785

from conftest import codes, doc, resign_gate
from vchlib import crypto, safety, timeutil
from vchlib.bundle import reload_yaml
from vchlib.canonical import jcs
from vchlib.checks import JCS_VECTORS, run_all

G1, G2, G4, G5 = ("gate-record.g1.example.json", "gate-record.g2.example.json",
                  "gate-record.g4.example.json", "gate-record.g5.example.json")
RUN = "examples/run.example.json"
TC_IDOR = "testcase.idor.example.json"
TC_ZAP = "testcase.zap-active.example.json"
TPE = dt.timezone(dt.timedelta(hours=8))


def fp_of(keys, name):
    return crypto.fingerprint(crypto.raw_public(keys[name]))


# ---------------------------------------------------------------- baseline
def test_examples_pass(b):
    R = run_all(b)
    assert not R.errors, [f"{i.code} {i.where} {i.msg}" for i in R.errors]
    assert {w.code for w in R.warnings} == {"W-MODEL-PLACEHOLDER"}


# ---------------------------------------------------------------- parsing
def test_duplicate_targets_key_in_roe(b):
    d = doc(b, "roe.yaml")
    assert "\ntargets:\n" in d.text
    reload_yaml(d, d.text.replace("\ntargets:\n", "\ntargets: []\ntargets:\n", 1))
    assert "E-YAML-STRICT" in codes(b)


def test_naive_datetime_rejected(b):
    doc(b, G1).data["timestamp"] = "2026-09-24T11:00:00"
    c = codes(b)
    assert "E-DATETIME" in c and "E-SCHEMA" in c
    assert "E-INTERNAL" not in c


def test_unknown_model_is_graceful(b):
    agents = doc(b, "agents.yaml").data
    name = next(k for k, a in agents.items() if isinstance(a, dict) and a.get("role") == "reviewer")
    agents[name]["model"] = "no_such_model"
    c = codes(b)
    assert "E-MODEL-UNKNOWN" in c and "E-INTERNAL" not in c


# ---------------------------------------------------------------- key registry / signatures
def test_signature_by_revoked_key_after_revocation(b, keys):
    rec = doc(b, G2).data                                   # decided 2026-09-28; erin_old revoked 09-15
    rec["approvers"][0]["key_fingerprint"] = fp_of(keys, "erin_old")
    resign_gate(b, G2, keys, {"erin": "erin_old"})
    assert "E-SIG-REVOKED" in codes(b)


def test_compromised_key_invalidates_all_signatures(b):
    reg = doc(b, "key-registry.yaml").data
    frank = next(e for e in reg["entries"] if e["person_id"] == "frank")
    frank["revoked_at"], frank["revocation_reason"] = "2026-12-01T00:00:00+08:00", "compromised"
    assert "E-SIG-COMPROMISED" in codes(b)


def test_bad_signature(b):
    sig = doc(b, G1).data["signatures"][0]
    sig["value"] = ("A" if sig["value"][0] != "A" else "B") + sig["value"][1:]
    assert "E-SIG-BAD" in codes(b)


def test_signing_key_of_another_person(b, keys):
    rec = doc(b, G1).data
    rec["approvers"][0]["key_fingerprint"] = fp_of(keys, "heidi")
    resign_gate(b, G1, keys, {"frank": "heidi"})
    c = codes(b)
    assert "E-SIG-SIGNER" in c and "E-GATE-APPROVER" in c


def test_registry_rollback(b):
    doc(b, "toolkit.yaml").data["key_registry"]["min_version"] = 99
    assert "E-KR-ROLLBACK" in codes(b)


def test_root_pin_mismatch(b, keys):
    doc(b, "toolkit.yaml").data["org_root_key"]["fingerprint"] = fp_of(keys, "alice")
    assert "E-KR-ROOT-PIN" in codes(b)


def test_registry_fingerprint_must_match_public_key(b):
    e = doc(b, "key-registry.yaml").data["entries"][0]
    e["fingerprint"] = "ed25519:SHA256:" + "A" * 43
    assert "E-KR-FP" in codes(b)


# ---------------------------------------------------------------- legal review
def test_l5_legal_attester_is_test_lead(b):
    doc(b, "roe.yaml").data["legal_review"]["attested_by"] = "alice"
    assert "E-L5" in codes(b)


def test_l6_component_licenses_required_for_legal_gate_tool(b):
    doc(b, "roe.yaml").data["legal_review"]["scope"]["component_licenses"] = False
    assert "E-L6" in codes(b)


def test_l4_attested_after_roe_start(b):
    doc(b, "roe.yaml").data["legal_review"]["attested_at"] = "2026-10-02T10:00:00+08:00"
    assert "E-L4" in codes(b)


# ---------------------------------------------------------------- gates
def test_g5_approver_is_initiator(b):
    doc(b, RUN).data["initiators"].append("heidi")
    assert "E-G5-INITIATOR" in codes(b)


def test_g5_decided_outside_window(b, keys):
    doc(b, G5).data["timestamp"] = "2026-10-05T23:10:00+08:00"   # Monday window ends 23:00
    resign_gate(b, G5, keys)
    assert "E-G5-WINDOW" in codes(b)


def test_g4_approver_not_initiator(b):
    doc(b, RUN).data["initiators"].remove("erin")
    assert "E-G4-INITIATOR" in codes(b)


def test_automation_account_as_initiator(b):
    doc(b, RUN).data["initiators"].append("ci-bot")
    assert "E-RUN-INITIATOR" in codes(b)


def outcome_errors(bundle):
    return [f"{i.where} {i.msg}" for i in run_all(bundle).errors if i.code == "E-GATE-OUTCOME"]


def test_partially_approved_allowed_at_g4(b, keys):
    rec = doc(b, G4).data
    rec["outcome"] = "PARTIALLY_APPROVED"
    rec["decisions"][0]["decision"] = "reject"                       # mixed per-testcase decisions (D2)
    resign_gate(b, G4, keys)
    assert outcome_errors(b) == []


def test_g4_outcome_derived_from_decisions(b, keys):
    doc(b, G4).data["outcome"] = "PARTIALLY_APPROVED"                # all decisions accept -> APPROVED
    resign_gate(b, G4, keys)
    assert "E-GATE-OUTCOME" in codes(b)


@pytest.mark.parametrize("gate", [G1, G5])
def test_partially_approved_rejected_outside_g3_g4(b, keys, gate):
    doc(b, gate).data["outcome"] = "PARTIALLY_APPROVED"
    resign_gate(b, gate, keys)
    assert any("only allowed at G3 and G4" in m for m in outcome_errors(b))


@pytest.mark.parametrize("outcome", ["REJECTED", "NEEDS_INFO", "PARTIALLY_APPROVED"])
def test_g2_whole_gate_outcome_is_approved_or_expired(b, keys, outcome):
    doc(b, G2).data["outcome"] = outcome
    resign_gate(b, G2, keys)
    assert any("G2 whole-gate outcome" in m for m in outcome_errors(b))


def test_g2_expired_outcome_is_allowed(b, keys):
    doc(b, G2).data["outcome"] = "EXPIRED"
    resign_gate(b, G2, keys)
    assert not any("G2 whole-gate outcome" in m for m in outcome_errors(b))


def test_engagement_timeout_above_toolkit(b):
    doc(b, "engagement.yaml").data["gate_timeouts_hours"]["G4"] = 500
    assert "E-ENG-TIMEOUT" in codes(b)


# ---------------------------------------------------------------- time windows (midnight)
def test_midnight_window():
    win = {"days": ["sat"], "start": "22:00", "end": "02:00", "tz": "Asia/Taipei"}
    sat = dt.datetime(2026, 10, 10, 23, 30, tzinfo=TPE)
    assert timeutil.in_window(sat, win)
    assert timeutil.in_window(sat + dt.timedelta(hours=2), win)            # Sunday 01:30
    assert not timeutil.in_window(sat + dt.timedelta(hours=3), win)        # Sunday 02:30
    assert not timeutil.in_window(sat - dt.timedelta(days=1), win)         # Friday 23:30
    assert timeutil.window_end(sat, [win]) == dt.datetime(2026, 10, 11, 2, 0, tzinfo=TPE)


def test_parse_dt_requires_offset():
    with pytest.raises(timeutil.TimeError):
        timeutil.parse_dt("2026-10-05T21:00:00")
    assert timeutil.parse_dt("2026-10-05T13:00:00Z") == dt.datetime(2026, 10, 5, 21, 0, tzinfo=TPE)


def test_impossible_date_is_a_time_error(b):
    with pytest.raises(timeutil.TimeError):
        timeutil.parse_dt("2026-02-30T10:00:00+08:00")
    doc(b, "gate-record.g2.example.json").data["timestamp"] = "2026-02-30T10:00:00+08:00"
    got = codes(b)
    assert "E-INTERNAL" not in got and got                           # reported as a schema/time error, not a crash


def test_gate_records_sorted_by_instant_not_text():
    assert timeutil.sort_key("2026-09-28T10:00:00+08:00") < timeutil.sort_key("2026-09-28T03:00:00Z")


# ---------------------------------------------------------------- testcases vs ROE
def test_s3_testcase_rejected(b):
    doc(b, TC_IDOR).data["tool_binding"]["adapter"] = "nuclei:code_protocol"
    c = codes(b)
    assert "E-TC-ADMISSIBLE" in c and "E-TC-SAFETY" in c


def test_delete_on_non_seed_is_s3(b):
    reqs = doc(b, TC_IDOR).data["request_allowlist"]
    next(r for r in reqs if r["method"] == "DELETE")["path"] = "/api/invoices/{id}"
    assert "E-TC-ADMISSIBLE" in codes(b)


def test_zap_delay_below_roe_minimum(b):
    doc(b, TC_ZAP).data["tool_binding"]["params"]["delayInMs"] = 50
    assert "E-TC-ZAP" in codes(b)


def test_zap_unlimited_scan_duration(b):
    doc(b, TC_ZAP).data["tool_binding"]["params"]["maxScanDurationInMins"] = 0
    assert "E-TC-ZAP" in codes(b)


def test_zap_threads_above_roe_max_concurrency(b):
    doc(b, TC_ZAP).data["tool_binding"]["params"]["threadPerHost"] = 3      # ROE max_concurrency 2
    assert "E-TC-ZAP-THREADS" in codes(b)


def test_zap_threads_at_roe_max_concurrency_ok(b):
    doc(b, TC_ZAP).data["tool_binding"]["params"]["threadPerHost"] = 2
    assert "E-TC-ZAP-THREADS" not in codes(b)


def test_db_table_outside_oracle_tables(b):
    doc(b, TC_IDOR).data["data_needed"]["db_tables"].append("users")
    assert "E-TC-DB" in codes(b)


def test_roe_denylist_weakened(b):
    doc(b, "roe.yaml").data["activities"]["denied_modes"] = ["restler:fuzz"]
    assert "E-ROE-DENYLIST" in codes(b)


def test_safety_algorithm_denylist_is_s3(b):
    tc = dict(doc(b, TC_IDOR).data)
    tc["tool_binding"] = dict(tc["tool_binding"], adapter="restler:fuzz")
    roe = doc(b, "roe.yaml").data
    level, _ = safety.compute_safety_class(tc, roe, doc(b, "tools.yaml").data, None)
    assert level == "S3" and not safety.admissible(level, roe)


# ---------------------------------------------------------------- models
def test_openai_c_model_needs_store_false(b):
    doc(b, "models.yaml").data["gpt_flagship"]["store"] = True
    assert "E-MODEL-STORE" in codes(b)


def test_model_retiring_during_engagement_warns(b):
    doc(b, "models.yaml").data["claude_opus_48"]["earliest_retirement"] = "2026-10-15"
    R = run_all(b)
    assert "W-MODEL-RETIREMENT" in {w.code for w in R.warnings}
    assert "E-MODEL-RETIRED" not in {e.code for e in R.errors}


def test_model_retired_before_engagement(b):
    doc(b, "models.yaml").data["claude_opus_48"]["earliest_retirement"] = "2026-09-01"
    assert "E-MODEL-RETIRED" in codes(b)


# ---------------------------------------------------------------- run / S2
def test_s2_job_without_verified_restore(b):
    doc(b, RUN).data["jobs"]["job-zap-active-001"]["restore_verified"] = False
    assert "E-RUN-S2" in codes(b)


# ---------------------------------------------------------------- derived values, audit, verdicts
def test_tampered_testcase_breaks_g4_hash(b):
    doc(b, TC_IDOR).data["rate_limit"]["max_requests"] += 1
    assert "E-DERIVED" in codes(b)


def test_calibration_weight_recomputed(b):
    doc(b, "calibration.yaml").data["result"]["weights"][0]["w"] = 0.9
    assert "E-CAL-WEIGHT" in codes(b)


def test_audit_chain_tampering(b):
    d = doc(b, "audit-event.run-2026-09-23-001.example.jsonl")
    lines = d.text.split("\n")
    assert '"seq":6,' in lines[5]
    lines[5] = lines[5].replace('"seq":6,', '"seq":6,"x":1,', 1)
    d.text = "\n".join(lines)
    assert "E-AUDIT-CHAIN" in codes(b)


def test_verdict_status_recomputed(b):
    doc(b, "verdict.example.json").data["status"] = "CONFIRMED_CORROBORATED"
    assert "E-VERDICT-STATUS" in codes(b)


def test_g3_rejected_derived_from_g3_gate_record(b, keys):
    rec = doc(b, "gate-record.g3.example.json").data
    next(x for x in rec["decisions"] if x["item_id"] == "T-031")["decision"] = "reject"   # K-011's seed threat
    resign_gate(b, "gate-record.g3.example.json", keys)
    errs = [i.where for i in run_all(b).errors if i.code == "E-VERDICT-ANNOTATIONS"]
    assert any("verdict.k-011-b5" in w for w in errs)                # B5 verdict now needs g3_rejected (R13)
    assert not any("verdict.k-011-w3" in w for w in errs)            # the pre-G3 W3 verdict does not


def test_g3_rejected_ignores_threat_review_alone(b):
    doc(b, "threat.t-031.example.json").data["review"]["status"] = "REJECTED"
    assert "E-VERDICT-ANNOTATIONS" not in codes(b)                   # R13 follows the G3 record, not the threat copy


def test_traceability_missing_threat(b):
    doc(b, TC_IDOR).data["threat_id"] = "T-999"
    assert "E-TRACE" in codes(b)


def test_selftest_m1_requires_st3(b):
    st = doc(b, "selftest-report.m1.example.json").data
    item = next(i for i in st["items"] if i["item"] == "ST-3")
    item.update(status="NOT_RUN", passed=None, value=None, runs=0)
    assert "E-SELFTEST-M1" in codes(b)


# ---------------------------------------------------------------- canonical JSON
@pytest.mark.parametrize("value,expected", JCS_VECTORS)
def test_jcs_rfc8785_vectors(value, expected):
    assert jcs(value) == expected == rfc8785.dumps(value)
