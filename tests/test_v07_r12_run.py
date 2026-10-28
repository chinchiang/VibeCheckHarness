# SPDX-License-Identifier: Apache-2.0
"""Review r12 (docs/evidence/review-2026-10-28-r12.md), PR1: what the run record says is derived or reconciled, not trusted.

  gaps      the untested list (docs/02 B6) is derived from the run's own records and must be in run.gaps (E-RUN-GAPS); r11
            derived the terminal status from gaps, but nobody checked gaps, so a skipped approved job still ended COMPLETED;
  S2        snapshot and restore follow the snapshot service's anchored events (E-RUN-S2); a log recording restore_failed
            coexisted with a run record saying RESTORED and a COMPLETED run;
  feedback  every anchored feedback_recorded names a feedback record of the bundle (E-AUDIT-FEEDBACK); deleting one passed;
  run_kind  run_created pins run_kind and trigger as it pins the commit (E-RUN-COMMIT);
  registry  a bundle whose key registry is older than one a run loaded is a rollback (E-KR-ROLLBACK, BL-43).
Each defect test failed on the r11 head and passes with the fix (tests/mutations/r12_run.json); see CONTRIBUTING.md."""
import copy
import pathlib

import pytest

from conftest import doc, rederive
from vchlib import checks
from vchlib.bundle import load_variant
from vchlib.canonical import content_hash
from vchlib.checks import Ctx, run_all

ROOT = pathlib.Path(__file__).resolve().parents[1]
AUDIT = "audit-event.run-2026-09-23-001.example.jsonl"
FAUDIT = "audit-event.run-2026-10-07-001.example.jsonl"
RID = "run-2026-09-23-001"
ZAP = "job-zap-active-001"


def errors(b, code, where=None):
    return [i for i in run_all(b).errors if i.code == code and (where is None or where in i.where)]


def renumber(log):
    for n, ev in enumerate(log.data, 1):
        ev["seq"] = n


def expected(b):
    c = Ctx(b)
    return checks.expected_gaps(c, RID, c.runs[RID])


@pytest.fixture(scope="module")
def edge_base():
    return load_variant(ROOT, "edge")


# ================================================================ gaps
def test_the_examples_list_their_derived_gaps(b):
    assert run_all(b).errors == []
    assert {"kind": "manual", "ref": "INV-LLM-003"}.items() <= doc(b, "run.example.json").data["gaps"][0].items()
    assert ("manual", "INV-LLM-003") in expected(b)


def test_a_missing_manual_gap_is_reported(b):
    for f in ("run.example.json", "report-manifest.example.json"):
        doc(b, f).data["gaps"] = []
    assert any("INV-LLM-003" in i.msg for i in errors(b, "E-RUN-GAPS"))


def test_a_skipped_job_must_be_on_the_untested_list(b):
    """The review's probe: an approved job SKIPPED (no session) and the run still COMPLETED with an empty list."""
    job = doc(b, "run.example.json").data["jobs"]["job-llm-001"]
    job.update(status="SKIPPED", skip_reason="session_unavailable")
    assert ("session_unavailable", job["testcase_id"]) in expected(b)
    assert any("session_unavailable" in i.msg and job["testcase_id"] in i.msg for i in errors(b, "E-RUN-GAPS"))


@pytest.mark.parametrize("reason,kind", [("g5_rejected", "g5_skipped"), ("g5_expired", "g5_skipped"),
                                         ("ownership_failed", "ownership_failed"), ("login_unavailable", "login_unavailable")])
def test_a_skip_reason_maps_to_its_gap_kind(b, reason, kind):
    job = doc(b, "run.example.json").data["jobs"]["job-llm-001"]
    job.update(status="SKIPPED", skip_reason=reason)
    assert (kind, job["testcase_id"]) in expected(b)


def test_a_g4_reject_at_the_end_of_the_log_is_a_gap(b):
    for x in doc(b, "gate-record.g4.example.json").data["decisions"]:
        if x["item_id"] == "TC-012-01":
            x["decision"] = "reject"
    assert ("g4_rejected", "TC-012-01") in expected(b)


def test_a_failed_ownership_check_is_a_gap(b):
    o = doc(b, "run.example.json").data["ownership_results"][0]
    o["ok"] = False
    assert ("ownership_failed", o["target_id"]) in expected(b)


def test_a_result_that_did_not_run_is_a_gap(b):
    tr = doc(b, "testresult.example.json").data
    tr["outcome"] = "ERROR"
    assert ("error", tr["testcase_id"]) in expected(b)


def test_a_gb_stop_is_a_gap(b):
    gb = doc(b, "gate-record.gb.example.json").data
    gb["gb"]["choice"] = "stop_phase"
    assert ("gb_stopped", gb["gate_record_id"]) in expected(b)


def test_a_g3_rejection_is_not_a_gap(b):
    assert any(x.get("decision") == "reject" for x in doc(b, "gate-record.g3.example.json").data["decisions"])
    assert not [k for k in expected(b) if k[0] == "g3_rejected"]


def test_the_skip_reasons_are_gap_kinds_in_the_schema(b):
    gaps = doc(b, "run.example.json").data["gaps"]
    gaps.append({"kind": "session_unavailable", "ref": "TC-031-01", "reason": "x"})
    assert not [i for i in errors(b, "E-SCHEMA") if "run.example" in i.where]


def test_the_lite_variant_lists_its_manual_testcase():
    lite = load_variant(ROOT, "lite")
    run = doc(lite, "run.example.json").data
    assert any(g["kind"] == "manual" and g["ref"] == "TC-027-01" for g in run["gaps"]) and run["status"] == "COMPLETED"
    c = Ctx(lite)
    assert ("manual", "TC-027-01") in checks.expected_gaps(c, RID, c.runs[RID])          # a MANUAL testcase is derived
    assert run_all(lite).errors == []


# ================================================================ S2 snapshot and restore
def test_a_restore_failed_event_contradicts_a_restored_job(b, keys):
    log = doc(b, AUDIT)
    for e in log.data:
        if e["event_type"] == "snapshot_restored":
            e["event_type"], e["payload"] = "restore_failed", {"job_id": ZAP, "verified": False, "reason": "restore timed out"}
            e["idempotency_key"] = e["idempotency_key"].replace("snapshot_restored", "restore_failed")
    rederive(b, keys)
    assert any("restore_failed" in i.msg for i in errors(b, "E-RUN-S2"))


def test_an_s2_job_needs_its_anchored_snapshot(b, keys):
    log = doc(b, AUDIT)
    log.data = [e for e in log.data if e["event_type"] != "snapshot_created"]
    renumber(log)
    rederive(b, keys)
    assert any("snapshot_created" in i.msg for i in errors(b, "E-RUN-S2"))


def test_the_snapshot_event_names_the_jobs_snapshot(b, keys):
    for e in doc(b, AUDIT).data:
        if e["event_type"] == "snapshot_created":
            e["payload"]["snapshot_ref"] = "snap-other"
    rederive(b, keys)
    assert any("snapshot_created" in i.msg for i in errors(b, "E-RUN-S2"))


def test_an_unverified_restore_is_not_a_restore(b, keys):
    for e in doc(b, AUDIT).data:
        if e["event_type"] == "snapshot_restored":
            e["payload"]["verified"] = False
    rederive(b, keys)
    assert any("snapshot_restored" in i.msg for i in errors(b, "E-RUN-S2"))


# ================================================================ feedback reverse check
def test_a_recorded_feedback_cannot_be_deleted(edge_base):
    be = edge_base.clone()
    fb = doc(be, "feedback.k-016.example.json")
    be.docs = [d for d in be.docs if d is not fb]
    assert any("no such feedback record" in i.msg for i in errors(be, "E-AUDIT-FEEDBACK"))


def test_the_edge_variant_is_clean(edge_base):
    assert run_all(edge_base).errors == []


# ================================================================ run_created pins run_kind and trigger
@pytest.mark.parametrize("field,value", [("run_kind", "regression"), ("trigger", "scheduled")])
def test_run_created_pins_the_run_kind_and_trigger(b, field, value):
    r = doc(b, "run.followup.example.json").data
    r[field] = value
    doc(b, "checkpoint-metadata.followup.example.json").data["state_sha256"] = content_hash(r)
    assert any(field in i.msg for i in errors(b, "E-RUN-COMMIT"))


# ================================================================ key registry rollback
def test_a_registry_older_than_a_run_loaded_is_a_rollback(b, keys):
    for e in doc(b, AUDIT).data:
        if e["event_type"] == "key_registry_loaded":
            e["payload"]["version"] = doc(b, "key-registry.yaml").data["version"] + 1
    rederive(b, keys)
    assert any("rollback" in i.msg for i in errors(b, "E-KR-ROLLBACK"))


def test_a_registry_newer_than_a_run_loaded_is_a_rotation(b, keys):
    for e in doc(b, AUDIT).data:
        if e["event_type"] == "key_registry_loaded":
            e["payload"]["version"] = doc(b, "key-registry.yaml").data["version"] - 1
    rederive(b, keys)
    assert errors(b, "E-KR-ROLLBACK") == []


# ================================================================ docs
def test_06_lists_the_w1_tool_results_and_the_derived_gaps():
    s = (ROOT / "docs" / "06-security-legal-limitations.md").read_text(encoding="utf-8")
    assert "| W1 工具結果（`tool_invocation_end` 的 `sarif_results`） |" in s
    assert "`gaps` 的最小集合由 run 的紀錄推導" in s and "`E-AUDIT-FEEDBACK`" in s
