# SPDX-License-Identifier: Apache-2.0
"""Review r12 (2026-10-28), group 3: three processes the docs describe could not be written as a valid bundle.

  - Expiry cleanup (docs/03 §5.2): a SUSPENDED / STOPPED run nobody resumed before the engagement validity ended is
    closed by the system as COMPLETED_WITH_GAPS. r11's E-RUN-RESUME demanded a signed run_resume received before
    not_after for every exit, so the cleanup was always an error; the system path is now an anchored resume_expired
    followed by the change to COMPLETED_WITH_GAPS, both after not_after, with an `expired` gap (E-RUN-GAPS).
  - run_resume.from_status is required (schema); a resume without it used to be judged as STOPPED.
  - Report withdrawal (docs/06 §1.9 #4, BL-54): a withdrawn run already ended with its run_end anchor, so "write a
    withdrawal event into the audit log" reopened it. A withdrawal is now an engagement-level document signed by the test
    lead and a security reviewer (E-REPORT-WITHDRAWAL); nothing checked a withdrawal before.
Each test failed before the change and passes after it (tests/mutations/r12_flow.json); see CONTRIBUTING.md."""
import copy
import pathlib

import pytest

from conftest import doc, rederive
from test_v07_r11_anchor import FAUDIT, FOLLOWUP, FRUN, append
from vchlib import crypto
from vchlib.bundle import Doc, load_variant
from vchlib.checks import run_all

ROOT = pathlib.Path(__file__).resolve().parents[1]
CK = "checkpoint-metadata.followup.example.json"
WD = "report-withdrawal.example.json"
AFTER = "2026-11-01T09:00:00+08:00"          # the engagement validity ends 2026-10-31
BEFORE = "2026-10-20T09:00:00+08:00"


def errors(b, code, where=None):
    return [i for i in run_all(b).errors if i.code == code and (where is None or where in i.where)]


def msgs(b, code):
    return [i.msg for i in errors(b, code)]


@pytest.fixture(scope="module")
def suspend_base():
    return load_variant(ROOT, "suspend")


@pytest.fixture
def s(suspend_base):
    return suspend_base.clone()


# ================================================================ expiry cleanup
def close_expired(s, keys, *, expired=True, when=AFTER, close_at=None, to="COMPLETED_WITH_GAPS", actor="system",
                  from_status="SUSPENDED", gap=True, end_anchor=True):
    log, run, ck = doc(s, FAUDIT), doc(s, FRUN).data, doc(s, CK).data
    if expired:
        ev = {"event_type": "resume_expired", "node": "resume", "ts": when, "payload": {"from_status": from_status}}
        if actor != "system":
            ev["actor"] = {"kind": "human", "id": actor}
        append(log, ev)
    append(log, {"event_type": "run_status_changed", "node": "B6", "ts": close_at or when,
                 "payload": {"from": "SUSPENDED", "to": to}})
    if end_anchor:
        append(log, {"event_type": "audit_anchor", "node": "B6", "ts": close_at or when,
                     "payload": {"reason": "run_end", "anchor_counter": 0, "z3_countersignature": None}})
    run.update({"status": to, "current_node": None})
    ck["run_status"] = to
    run["gaps"] = [{"kind": "expired", "ref": FOLLOWUP, "reason": "委任設定到期，沒有人續跑"}] if gap else []
    rederive(s, keys)


def test_the_suspend_variant_is_clean(suspend_base):
    assert run_all(suspend_base).errors == []


def test_an_expired_suspended_run_is_closed_by_the_system(s, keys):
    close_expired(s, keys)
    assert run_all(s).errors == []


def test_closing_without_resume_expired_still_needs_a_signed_resume(s, keys):
    close_expired(s, keys, expired=False)
    assert any("needs a human's signed run_resume" in m for m in msgs(s, "E-RUN-RESUME"))


def test_resume_expired_before_the_validity_ended_is_rejected(s, keys):
    close_expired(s, keys, when=BEFORE)
    assert any("only after its validity ended" in m and "resume_expired" in m for m in msgs(s, "E-RUN-RESUME"))


def test_the_status_change_must_also_come_after_the_validity_ended(s, keys):
    close_expired(s, keys, when=AFTER, close_at=BEFORE)
    assert any("only after its validity ended" in m and "run_status_changed" in m for m in msgs(s, "E-RUN-RESUME"))


def test_resume_expired_is_the_system_s_event_not_a_person_s(s, keys):
    close_expired(s, keys, actor="alice")
    assert any("needs a human's signed run_resume" in m for m in msgs(s, "E-RUN-RESUME"))


def test_resume_expired_names_the_state_it_closes(s, keys):
    close_expired(s, keys, from_status="STOPPED")                         # the run was SUSPENDED
    assert any("needs a human's signed run_resume" in m for m in msgs(s, "E-RUN-RESUME"))


def test_an_expired_run_cannot_end_completed_without_gaps(s, keys):
    close_expired(s, keys, to="COMPLETED", gap=False)
    assert any("needs a human's signed run_resume" in m for m in msgs(s, "E-RUN-RESUME"))


def test_resume_expired_must_be_anchored(s, keys):
    close_expired(s, keys, end_anchor=False)
    assert any("the resume_expired is not anchored" in m for m in msgs(s, "E-RUN-RESUME"))


def test_the_expired_gap_is_derived(s, keys):
    close_expired(s, keys, gap=False)
    assert any(f"{{kind: expired, ref: {FOLLOWUP}}}" in m for m in msgs(s, "E-RUN-GAPS"))


def test_run_resume_needs_from_status(s, keys):
    log = doc(s, FAUDIT)
    append(log, {"event_type": "run_resume", "node": "G4", "ts": "2026-10-12T09:00:00+08:00", "actor": {"kind": "human", "id": "alice"},
                 "payload": {"person_id": "alice", "reason": "ROE 重新簽署後恢復"}})
    rederive(s, keys)
    assert any("from_status must be SUSPENDED or STOPPED" in m for m in msgs(s, "E-AUDIT-ACTOR"))
    assert any("from_status" in i.msg for i in run_all(s).errors if i.code.startswith("E-SCHEMA"))


# ================================================================ report withdrawal
def resign(b, keys):
    w = doc(b, WD).data
    w["signatures"] = [crypto.sign_document(w, x["person_id"], keys[x["person_id"]]) for x in w["signers"]]
    return w


def report(b, report_id, run_id, generated_at):
    rm = copy.deepcopy(doc(b, "report-manifest.example.json").data)
    rm.update({"report_id": report_id, "run_id": run_id, "generated_at": generated_at})
    b.docs.append(Doc("docs/schemas/examples/report-manifest.extra.example.json", "report-manifest", rm, ""))


def test_the_bundle_withdraws_its_report(b):
    assert doc(b, WD).data["withdrawn_report_id"] == "RPT-2026-10-06-001" and errors(b, "E-REPORT-WITHDRAWAL") == []


def test_the_withdrawn_report_must_exist(b, keys):
    doc(b, WD).data["withdrawn_report_id"] = "RPT-2099-01-01-001"
    resign(b, keys)
    assert any("names no report of the bundle" in m for m in msgs(b, "E-REPORT-WITHDRAWAL"))


def test_the_withdrawn_run_is_the_report_s_run(b, keys):
    doc(b, WD).data["withdrawn_run_id"] = FOLLOWUP
    resign(b, keys)
    assert any("but report RPT-2026-10-06-001 is run" in m for m in msgs(b, "E-REPORT-WITHDRAWAL"))


def test_a_report_is_withdrawn_once(b, keys):
    w = copy.deepcopy(doc(b, WD).data)
    w["withdrawal_id"] = "WD-002"
    b.docs.append(Doc("docs/schemas/examples/report-withdrawal.second.example.json", "report-withdrawal", w, ""))
    assert any("is already withdrawn by" in m for m in msgs(b, "E-REPORT-WITHDRAWAL"))


def test_a_withdrawal_comes_after_the_report(b, keys):
    doc(b, WD).data["withdrawn_at"] = "2026-10-05T09:00:00+08:00"
    resign(b, keys)
    assert any("before report RPT-2026-10-06-001 was generated" in m for m in msgs(b, "E-REPORT-WITHDRAWAL"))


def test_the_customer_is_told_after_the_withdrawal(b, keys):
    doc(b, WD).data["customer_notified_at"] = "2026-10-07T08:00:00+08:00"
    resign(b, keys)
    assert any("customer_notified_at" in m for m in msgs(b, "E-REPORT-WITHDRAWAL"))


def test_the_engagement_is_this_one(b, keys):
    doc(b, WD).data["engagement_id"] = "eng-someone-else"
    resign(b, keys)
    assert any("is not this engagement's" in m for m in msgs(b, "E-REPORT-WITHDRAWAL"))


def test_the_signers_are_the_test_lead_then_a_security_reviewer(b, keys):
    w = doc(b, WD).data
    w["signers"] = list(reversed(w["signers"]))
    resign(b, keys)
    assert any("signers must be the test lead, then a security reviewer" in m for m in msgs(b, "E-REPORT-WITHDRAWAL"))


def test_two_people_sign_outside_lite(b, keys):
    w = doc(b, WD).data
    w["signers"][1] = dict(w["signers"][0], role="security_reviewer")
    resign(b, keys)
    assert any("are two people" in m for m in msgs(b, "E-REPORT-WITHDRAWAL"))


def test_lite_lets_the_consolidated_person_sign_both():
    lite = load_variant(ROOT, "lite")
    people = [x["person_id"] for x in doc(lite, WD).data["signers"]]
    assert people == ["alice", "alice"] and errors(lite, "E-REPORT-WITHDRAWAL") == [] and run_all(lite).errors == []


def test_each_signer_signs(b, keys):
    doc(b, WD).data["signatures"] = doc(b, WD).data["signatures"][:1]
    assert any("one signature per signer" in m for m in msgs(b, "E-REPORT-WITHDRAWAL"))


def test_a_changed_withdrawal_no_longer_verifies(b):
    doc(b, WD).data["reason"] = "other"
    assert errors(b, "E-SIG-BAD", WD)


def test_a_superseding_report_belongs_to_a_later_run(b, keys):
    report(b, "RPT-2026-10-20-001", FOLLOWUP, "2026-10-20T12:00:00+08:00")
    doc(b, WD).data["superseded_by_report_id"] = "RPT-2026-10-20-001"
    resign(b, keys)
    assert errors(b, "E-REPORT-WITHDRAWAL") == []


def test_a_report_cannot_supersede_itself(b, keys):
    doc(b, WD).data["superseded_by_report_id"] = "RPT-2026-10-06-001"
    resign(b, keys)
    assert any("must name the report of another run" in m for m in msgs(b, "E-REPORT-WITHDRAWAL"))


def test_a_superseding_report_is_newer(b, keys):
    report(b, "RPT-2026-10-01-001", FOLLOWUP, "2026-10-01T12:00:00+08:00")
    doc(b, WD).data["superseded_by_report_id"] = "RPT-2026-10-01-001"
    resign(b, keys)
    assert any("generated after the withdrawn report" in m for m in msgs(b, "E-REPORT-WITHDRAWAL"))
