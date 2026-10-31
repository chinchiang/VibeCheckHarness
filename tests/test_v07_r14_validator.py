# SPDX-License-Identifier: Apache-2.0
"""Review r14 (2026-10-30, internal, group A: validator bypasses of main@6b4dfb0), docs/evidence/review-2026-10-30-r14.md §A.

Nine ways to get a bundle past the validator while breaking docs/02 or docs/03, plus one honest record that could not be
written:
  A1  a Z3 job labelled W1 / G4 / END escaped every B4 rule (run.jobs, G0b, G4, G5, windows, ownership);
  A2  a job without a result (INTERRUPTED) skipped the G4-in-force and window checks, which lived in the testresult loop;
  A3  a G4-approved job that never ran (PENDING) left a COMPLETED run with no gap;
  A4  the ownership check, B0 / B1 and the restore drill ran outside the ROE time windows (the shipped example did);
  A5  a G0a / G0b VERIFY_FAILED did not make the run ABORTED, and an all-ok, reasonless VERIFY_FAILED was accepted;
  A6  a testcase whose final G4 decision is needs_info, or that no G4 decision covers, left no gap;
  A7  a resume needed no G0a re-verification, and a B-phase resume no new ownership check;
  A8  verdicts, drafts and report_published were written after the terminal status;
  A9  baseline_run_id pointed at a later run or the Lane A run and was not pinned;
  A10 a GB EXPIRED record could not be written (every choice mapped to APPROVED / REJECTED, null failed the schema).
Each test failed before the change and passes after it (tests/mutations/r14_validator.json); see CONTRIBUTING.md."""
import copy
import datetime as dt
import pathlib

import pytest

from conftest import doc, rederive
from test_v07_r11_anchor import FRUN, anchor, append, g0a_reverify, renumber, signed_resume
from test_v07_r13_external import first_index, insert
from vchlib import checks
from vchlib.bundle import Doc, load_variant
from vchlib.checks import run_all

ROOT = pathlib.Path(__file__).resolve().parents[1]
MRUN, MAUDIT = "run.example.json", "audit-event.run-2026-09-23-001.example.jsonl"
FAUDIT = "audit-event.run-2026-10-07-001.example.jsonl"
Z3 = {"kind": "system", "id": "z3-executor"}


def errors(b, code, where=None):
    return [i for i in run_all(b).errors if i.code == code and (where is None or where in i.where)]


def msgs(b, code):
    return [i.msg for i in errors(b, code)]


def codes(b):
    return sorted({i.code for i in run_all(b).errors})


def test_the_examples_are_clean(b):
    assert run_all(b).errors == []


# ================================================================ A1. the zone says where a job ran, not the node label
@pytest.mark.parametrize("node", ["W1", "G4", "END", "abort_handler"])
def test_a_z3_job_cannot_hide_behind_a_white_box_node(b, keys, node):
    log = doc(b, MAUDIT)
    i = first_index(log, event_type="sandbox_job_start", node="B4")
    insert(log, i, event_type="sandbox_job_start", node=node, ts=log.data[i]["ts"], zone="Z3", actor=Z3, payload={"job_id": "job-ghost-001"})
    insert(log, i + 1, event_type="sandbox_job_end", node=node, ts=log.data[i]["ts"], zone="Z3", actor=Z3,
           payload={"job_id": "job-ghost-001", "outcome": "FAIL", "testcase_sha256": None, "artifact_sha256": None})
    rederive(b, keys)
    assert any("zone Z3 at node" in m for m in msgs(b, "E-JOB-AUDIT"))
    assert any("job-ghost-001, which is not in run.jobs" in m for m in msgs(b, "E-JOB-AUDIT"))


def test_a_z3_job_labelled_w1_is_still_a_b_phase_event(b, keys):
    log = doc(b, MAUDIT)
    i = first_index(log, node="W1")                                       # 09-24, long before G0b
    insert(log, i, event_type="sandbox_job_start", node="W1", ts=log.data[i]["ts"], zone="Z3", actor=Z3, payload={"job_id": "job-ghost-001"})
    rederive(b, keys)
    assert any("without a VERIFIED G0b" in m for m in msgs(b, "E-GATE-ORDER"))


def test_a_b4_job_runs_in_z3(b, keys):
    log = doc(b, MAUDIT)
    i = first_index(log, event_type="sandbox_job_start", node="B4")
    log.data[i]["zone"] = "Z2"
    renumber(log)
    rederive(b, keys)
    assert any("runs in zone Z3, not 'Z2'" in m for m in msgs(b, "E-JOB-AUDIT"))


def test_a_w4_job_runs_in_z2(b, keys):
    log = doc(b, MAUDIT)
    i = first_index(log, event_type="sandbox_job_start", node="W4")
    log.data[i]["zone"] = "Z1"
    renumber(log)
    rederive(b, keys)
    assert any("white-box jobs run in Z2" in m for m in msgs(b, "E-JOB-AUDIT"))


# ================================================================ A2 / A3. a job is judged by its start, a run by every job
def interrupt_job(b, jid="job-llm-001", start_at=None):
    """Drop the job's end event and result; it started (at start_at if given) and was INTERRUPTED."""
    run, log = doc(b, MRUN).data, doc(b, MAUDIT)
    res = next(d for d in b.docs if d.kind == "testresult" and d.data.get("job_id") == jid)
    b.docs.remove(res)
    log.data = [e for e in log.data if not (e.get("event_type") == "sandbox_job_end" and (e.get("payload") or {}).get("job_id") == jid)]
    if start_at is not None:
        ev = log.data.pop(first_index(log, event_type="sandbox_job_start", p_job_id=jid))
        ev["ts"] = start_at
        pos = next(i for i, e in enumerate(log.data) if e["ts"] > start_at)
        log.data.insert(pos, ev)
    renumber(log)
    run["jobs"][jid].update({"status": "INTERRUPTED", "result_ref": None})
    run["executed_jobs"] = [j for j in run["executed_jobs"] if j != jid]
    run["testresults"] = [r for r in run.get("testresults", []) if r != res.data["result_id"]]
    rm = doc(b, "report-manifest.example.json").data
    rm["artifacts"] = [a for a in rm["artifacts"] if a.get("ref") != res.data["result_id"]]
    return res.data


def test_a_job_without_a_result_still_needs_its_g4_approval_first(b, keys):
    interrupt_job(b, start_at="2026-10-02T20:30:00+08:00")               # Friday 20:30, in the window, before the G4 decision (10-03 11:00)
    rederive(b, keys)
    assert any("while the G4 decision in force" in m for m in msgs(b, "E-JOB-G4"))


def test_a_job_without_a_result_still_keeps_the_window(b, keys):
    interrupt_job(b, start_at="2026-10-04T09:00:00+08:00")               # Sunday morning, after G4, outside every window
    rederive(b, keys)
    assert any("sandbox_job_start" in m and "outside the ROE validity" in m for m in msgs(b, "E-RUN-WINDOW"))


def test_an_interrupted_job_is_a_gap_of_the_completed_run(b, keys):
    interrupt_job(b)
    rederive(b, keys)
    assert any("stopped" in m and "TC-031-01" in m for m in msgs(b, "E-RUN-GAPS"))


def test_a_pending_approved_job_cannot_sit_in_a_completed_run(b, keys):
    run, log = doc(b, MRUN).data, doc(b, MAUDIT)
    jid = "job-llm-001"
    res = next(d for d in b.docs if d.kind == "testresult" and d.data.get("job_id") == jid)
    b.docs.remove(res)
    log.data = [e for e in log.data if (e.get("payload") or {}).get("job_id") != jid]
    renumber(log)
    run["jobs"][jid].update({"status": "PENDING", "result_ref": None})
    run["executed_jobs"] = [j for j in run["executed_jobs"] if j != jid]
    rederive(b, keys)
    assert any("is PENDING in a COMPLETED run" in m for m in msgs(b, "E-JOB-AUDIT"))


def test_a_started_job_needs_an_ownership_result_even_without_a_result(b, keys):
    interrupt_job(b)
    run = doc(b, MRUN).data
    tc = next(d.data for d in b.docs if d.kind == "testcase" and d.data["testcase_id"] == run["jobs"]["job-llm-001"]["testcase_id"])
    for o in run["ownership_results"]:
        if o["target_id"] in tc["target_ids"]:
            o["ok"] = False
    rederive(b, keys)
    assert any("has no ok ownership result" in m for m in msgs(b, "E-RUN-OWNERSHIP"))


# ================================================================ A4. target activity waits for the ROE window
def test_the_ownership_check_runs_inside_the_window(b, keys):
    log = doc(b, MAUDIT)
    i = first_index(log, event_type="ownership_check")
    log.data[i]["ts"] = "2026-10-01T09:30:00+08:00"                       # Thursday morning: the pre-r14 example
    # keep the log monotonic: G0b before it
    for j in range(i - 3, i):
        if log.data[j]["node"] == "G0b":
            log.data[j]["ts"] = "2026-10-01T09:00:00+08:00"
    renumber(log)
    for g in doc(b, MRUN).data["ownership_results"]:
        g["checked_at"] = "2026-10-01T09:30:00+08:00"
    rederive(b, keys)
    assert any("ownership_check at 2026-10-01T09:30:00+08:00" in m for m in msgs(b, "E-RUN-WINDOW"))


def test_the_restore_drill_runs_inside_the_window(b, keys):
    log = doc(b, MAUDIT)
    log.data[first_index(log, event_type="restore_drill")]["ts"] = "2026-10-02T14:00:00+08:00"
    renumber(log)
    rederive(b, keys)
    assert any("restore_drill" in m for m in msgs(b, "E-RUN-WINDOW"))


def test_target_activity_before_the_roe_is_valid_is_rejected(b, keys):
    log = doc(b, MAUDIT)
    ids = [i for i, e in enumerate(log.data) if e["node"] in ("G0b", "B0", "B1")]
    for k, i in enumerate(ids):                                            # 09-30 16:00..: before not_before (10-01)
        log.data[i]["ts"] = (dt.datetime.fromisoformat("2026-09-30T16:00:00+08:00") + dt.timedelta(minutes=10 * k)).isoformat()
    renumber(log)
    rederive(b, keys)
    assert errors(b, "E-RUN-WINDOW")


def test_the_regression_variant_checks_ownership_in_the_window():
    reg = load_variant(ROOT, "regression")
    log = doc(reg, FAUDIT)
    ev = log.data[first_index(log, event_type="ownership_check")]
    assert ev["ts"].startswith("2026-10-07T20:30") and run_all(reg).errors == []


# ================================================================ A5. a failed verification ends the run
def failed_g0b(b, reason=None, ok=True):
    """A VERIFY_FAILED G0b record and decision 10 minutes before the example's VERIFIED one."""
    src = doc(b, "gate-record.g0b.example.json")
    rec = copy.deepcopy(src.data)
    when = "2026-10-01T19:50:00+08:00"
    rec.update({"gate_record_id": "GR-G0b-0000", "outcome": "VERIFY_FAILED", "opened_at": when, "timestamp": when})
    for r in rec["verification"]["signer_results"]:
        r["ok"], r["reason"] = ok, reason
    b.docs.append(Doc(src.path.replace("g0b", "g0b-failed"), "gate-record", rec, ""))
    run = doc(b, MRUN).data
    run["gate_records"].insert(0, {"gate": "G0b", "gate_record_id": "GR-G0b-0000", "outcome": "VERIFY_FAILED", "round": 1,
                                   "subject_hash": rec["artifact"]["sha256"], "job_id": None, "opened_at": when, "decided_at": when})
    rm = doc(b, "report-manifest.example.json").data
    rm["artifacts"].append(dict(next(a for a in rm["artifacts"] if a.get("ref") == "GR-G0b-0001"), ref="GR-G0b-0000"))
    log = doc(b, MAUDIT)
    i = first_index(log, event_type="gate_decision", p_gate="G0b")
    insert(log, i, event_type="gate_decision", node="G0b", ts=when,
           payload={"gate": "G0b", "gate_record_id": "GR-G0b-0000", "outcome": "VERIFY_FAILED", "gate_record_sha256": None})
    insert(log, i + 1, event_type="audit_anchor", node="G0b", ts=when, payload={"reason": "gate_decision", "anchor_counter": 0, "z3_countersignature": None})


def test_a_verify_failed_g0b_must_abort_the_run(b, keys):
    failed_g0b(b, reason="legal_attester_is_test_lead")
    rederive(b, keys)
    assert any("VERIFY_FAILED must be followed by run_status_changed to ABORTED" in m for m in msgs(b, "E-GATE-ORDER"))


def test_a_verify_failed_record_names_what_failed(b, keys):
    failed_g0b(b, reason=None, ok=True)
    rederive(b, keys)
    assert any("although every signature verifies" in m for m in msgs(b, "E-GATE-G0-VERIFY"))


# ================================================================ A6. needs_info at the end of G4 is a gap
def test_a_final_needs_info_at_g4_is_a_gap(b, keys):
    g4 = doc(b, "gate-record.g4.example.json").data
    next(x for x in g4["decisions"] if x["item_id"] == "TC-031-01")["decision"] = "needs_info"
    g4["outcome"] = "PARTIALLY_APPROVED"
    rederive(b, keys)
    assert any("g4_rejected" in m and "TC-031-01" in m for m in msgs(b, "E-RUN-GAPS"))


def test_a_testcase_no_g4_decision_covers_is_a_gap(b, keys):
    g4 = doc(b, "gate-record.g4.example.json").data
    g4["decisions"] = [x for x in g4["decisions"] if x["item_id"] != "TC-031-01"]
    rederive(b, keys)
    assert any("g4_rejected" in m and "TC-031-01" in m for m in msgs(b, "E-RUN-GAPS"))


# ================================================================ A7. a resume re-verifies the engagement and the ownership
@pytest.fixture
def s():
    return load_variant(ROOT, "suspend").clone()


def test_a_resume_without_a_new_g0a_is_rejected(s, keys):
    signed_resume(s, keys, reverify=False)
    log = doc(s, FAUDIT)                                                  # the run goes on without re-verifying the engagement
    append(log, {"event_type": "policy_decision", "node": "B3", "ts": "2026-10-12T10:00:00+08:00", "payload": {"decision": "allow"}})
    anchor(log, "2026-10-12T10:00:00+08:00", node="B3")
    rederive(s, keys)
    assert any("without a new VERIFIED G0a first" in m for m in msgs(s, "E-RUN-RESUME"))


def test_a_resume_with_a_new_g0a_is_accepted(s, keys):
    signed_resume(s, keys)
    assert errors(s, "E-RUN-RESUME") == []


def test_a_failed_g0a_re_verification_is_an_error(s, keys):
    log = doc(s, FAUDIT)
    when = "2026-10-12T09:00:00+08:00"
    append(log, {"event_type": "run_resume", "node": "G4", "ts": when, "actor": {"kind": "human", "id": "alice"},
                 "payload": {"from_status": "SUSPENDED", "person_id": "alice", "reason": "x"}})
    from test_v07_r11_anchor import resume_line
    resume_line(s, when)
    g0a_reverify(s, when, outcome="VERIFY_FAILED")
    rec = next(d for d in s.docs if d.kind == "gate-record" and d.data.get("gate_record_id") == "GR-G0a-0003").data
    rec["verification"]["signer_results"][0]["reason"] = "key revoked"
    anchor(log, when)
    rederive(s, keys)
    assert any("re-verification after the resume" in m and "VERIFY_FAILED" in m for m in msgs(s, "E-RUN-RESUME"))


def test_a_b_phase_resume_re_checks_ownership_before_the_next_job(s, keys):
    signed_resume(s, keys)
    log, run = doc(s, FAUDIT), doc(s, FRUN).data
    when = "2026-10-12T20:30:00+08:00"
    main = doc(s, MRUN).data
    run["jobs"] = {"job-idor-002": dict(main["jobs"]["job-idor-001"], job_id="job-idor-002", status="EXECUTING", result_ref=None)}
    append(log, {"event_type": "gate_decision", "node": "G0b", "ts": "2026-10-12T09:30:00+08:00",
                 "payload": {"gate": "G0b", "gate_record_id": "GR-G0b-0002", "outcome": "VERIFIED", "gate_record_sha256": None}})
    append(log, {"event_type": "sandbox_job_start", "node": "B4", "ts": when, "actor": Z3, "zone": "Z3", "payload": {"job_id": "job-idor-002"}})
    anchor(log, when, node="B4")
    rederive(s, keys)
    assert any("runs after the resume" in m and "without a new ok ownership_check" in m for m in msgs(s, "E-RUN-OWNERSHIP"))


# ================================================================ A8. nothing follows the terminal status
def test_nothing_but_the_run_end_anchor_follows_a_terminal_status(b, keys):
    log = doc(b, MAUDIT)
    i = first_index(log, event_type="run_status_changed", p_to="COMPLETED")
    ev = log.data.pop(i)
    j = first_index(log, node="B5")
    ev["ts"] = log.data[j]["ts"]
    log.data.insert(j, ev)
    renumber(log)
    rederive(b, keys)
    assert any("after the run became COMPLETED" in m for m in msgs(b, "E-RUN-STATUS"))


# ================================================================ A9. the baseline is an earlier ancestor, pinned at creation
def test_an_initial_run_has_no_baseline(b, keys):
    doc(b, MRUN).data["baseline_run_id"] = "run-2026-10-07-001"
    doc(b, MAUDIT).data[0]["payload"]["baseline_run_id"] = "run-2026-10-07-001"
    rederive(b, keys)
    assert any("an initial run has no baseline" in m for m in msgs(b, "E-RUN-BASELINE"))


def test_the_baseline_is_an_ancestor(b, keys):
    doc(b, FRUN).data["baseline_run_id"] = "run-2026-09-25-pr-118"            # the Lane A run is not the follow-up's parent
    doc(b, FAUDIT).data[0]["payload"]["baseline_run_id"] = "run-2026-09-25-pr-118"
    rederive(b, keys)
    assert any("is not an ancestor" in m for m in msgs(b, "E-RUN-BASELINE"))


def test_the_baseline_is_pinned_by_run_created(b, keys):
    doc(b, FRUN).data["baseline_run_id"] = None
    rederive(b, keys)
    assert any("run.baseline_run_id" in m and "pinned by the anchored run_created" in m for m in msgs(b, "E-RUN-COMMIT"))


def test_the_run_created_payload_names_the_baseline(b):
    for d in b.docs:
        if d.kind == "audit-event":
            assert "baseline_run_id" in d.data[0]["payload"], d.path


def test_a_run_created_without_the_baseline_is_a_schema_error(b, keys):
    del doc(b, MAUDIT).data[0]["payload"]["baseline_run_id"]              # the initial run: None == None would pass the pin
    rederive(b, keys)
    assert errors(b, "E-SCHEMA")


# ================================================================ A10. a GB that nobody decided
def test_an_expired_gb_record_can_be_written(b, keys):
    gb = doc(b, "gate-record.gb.example.json").data
    gb.update({"outcome": "EXPIRED", "signatures": []})
    gb["gb"].update({"choice": None, "new_caps": None})
    for x in gb["decisions"]:
        x["decision"] = "needs_info"
    log = doc(b, MAUDIT)
    i = first_index(log, event_type="gate_decision", p_gate="GB")
    log.data[i]["payload"]["outcome"] = "EXPIRED"
    for e in log.data[i:i + 2]:
        e["ts"] = "2026-09-27T20:30:00+08:00"                              # 24 h 30 min after it opened (GB timeout 24 h)
    renumber(log)
    rederive(b, keys)
    assert not [i for i in run_all(b).errors if i.code in ("E-GATE-OUTCOME", "E-SCHEMA") and "gb" in i.where]


def test_an_expired_gb_record_carries_no_choice(b, keys):
    gb = doc(b, "gate-record.gb.example.json").data
    gb.update({"outcome": "EXPIRED", "signatures": []})
    for x in gb["decisions"]:
        x["decision"] = "needs_info"
    log = doc(b, MAUDIT)
    i = first_index(log, event_type="gate_decision", p_gate="GB")
    log.data[i]["payload"]["outcome"] = "EXPIRED"
    for e in log.data[i:i + 2]:
        e["ts"] = "2026-09-27T20:30:00+08:00"
    renumber(log)
    rederive(b, keys)
    assert any("an EXPIRED GB record carries no choice" in m for m in msgs(b, "E-GATE-OUTCOME"))


# ================================================================ the documents
def test_02_and_03_state_the_r14_rules():
    s2 = (ROOT / "docs/02-methodology.md").read_text(encoding="utf-8")
    s3 = (ROOT / "docs/03-system-architecture.md").read_text(encoding="utf-8")
    assert "都必須在 ROE 有效期間與時間窗內（`E-RUN-WINDOW`）" in s2 and "E-JOB-G4" in s2 and "E-RUN-BASELINE" in s2
    assert "每次 resume 都重驗 G0a" in s3 or "每次 resume 重驗 G0a" in s3
