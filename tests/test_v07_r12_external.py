# SPDX-License-Identifier: Apache-2.0
"""External review of main@48cadf9 (docs/evidence/review-2026-10-28-r12.md §9), four findings that held on re-run:

  1. R14 FIXED: a required regression testcase whose result was ERROR (E_inc) counted as "re-run", and a qualified PASS of
     any other testcase satisfied "a PASS with a positive control", so the defect was declared fixed although the test that
     proved it never passed again (rule_version 05-v0.12).
  2. E-RUN-S2 required every S2 job to be RESTORED with an APPROVED G5, so an honest RESTORE_FAILED job (run FAILED) and a
     job SKIPPED because G5 rejected it could not validate.
  3. tools/mutation_check.py counted any exception in a test body as CAUGHT (pytest's junit `failures` includes them).
  4. docs/08's AdjudicationInputs claimed to match vchlib.adjudicate.Inputs field for field and missed six fields.
Each test failed before the change and passes after it (tests/mutations/r12_external.json); see CONTRIBUTING.md."""
import copy
import dataclasses
import pathlib
import re
import subprocess
import sys

import pytest

from conftest import doc, rederive
from vchlib import adjudicate as adj
from vchlib import checks
from vchlib.bundle import load_variant
from vchlib.checks import content_hash, run_all

ROOT = pathlib.Path(__file__).resolve().parents[1]
FRUN = "run.followup.example.json"
RID = "run-2026-10-07-001"


def errors(b, code, where=None):
    return [i for i in run_all(b).errors if i.code == code and (where is None or where in i.where)]


# ================================================================ 1. FIXED needs a qualified PASS of every required case
@pytest.fixture(scope="module")
def reg():
    return load_variant(ROOT, "regression")


def entry(c, result_id, cls, control):
    tr = c.ix.first("testresult", result_id=result_id).data
    return {"result_ref": content_hash(tr), "class": cls, "positive_control": control, "reason": "x"}


def fixed(c, *entries):
    run, cl = c.runs[RID], c.ix.first("cluster", cluster_id="K-301").data
    return checks.regression_fixed(c, {"test_evidence": {"class": "E_pass", "results": list(entries)}}, cl, run)


def test_the_required_case_erroring_is_not_fixed_by_another_cases_pass(reg):
    c = checks.Ctx(reg)                                   # the review's probe: TC-012-01 (the source's proof) ERROR, TC-031-01 PASS
    assert not fixed(c, entry(c, "R-TC-012-01-2", "E_inc", None), entry(c, "R-TC-031-01-1", "E_pass", True))


def test_the_required_case_needs_its_own_positive_control(reg):
    c = checks.Ctx(reg)
    assert not fixed(c, entry(c, "R-TC-012-01-2", "E_pass", False), entry(c, "R-TC-031-01-1", "E_pass", True))


def test_a_required_case_with_a_pass_and_an_error_is_unclear(reg):
    c = checks.Ctx(reg)
    assert not fixed(c, entry(c, "R-TC-012-01-2", "E_pass", True), entry(c, "R-TC-012-01-1", "E_inc", None))


def test_a_qualified_pass_of_every_required_case_is_fixed(reg):
    c = checks.Ctx(reg)
    assert fixed(c, entry(c, "R-TC-012-01-2", "E_pass", True))
    assert fixed(c, entry(c, "R-TC-012-01-2", "E_pass", True), entry(c, "R-TC-031-01-1", "E_pass", True))


def test_a_source_without_an_executable_proof_needs_one_qualified_pass(reg, monkeypatch):
    c = checks.Ctx(reg)
    monkeypatch.setattr(checks, "carried_source", lambda c, cl, run: {"status": "CONFIRMED_CORROBORATED", "test_evidence": {"results": []}})
    assert fixed(c, entry(c, "R-TC-031-01-1", "E_pass", True))
    assert not fixed(c, entry(c, "R-TC-031-01-1", "E_pass", False))


def test_the_bundle_cannot_declare_fixed_while_the_proof_case_errors(reg):
    b = reg.clone()
    v = doc(b, "verdict.k-301-b5.example.json").data
    v["test_evidence"]["results"][0].update({"class": "E_inc", "positive_control": None})
    c = checks.Ctx(b)
    v["test_evidence"]["results"].append(entry(c, "R-TC-031-01-1", "E_pass", True))
    out = adj.adjudicate(checks.verdict_inputs(c, v, c.ix.first("cluster", cluster_id="K-301").data))
    assert out.status != "FIXED" and "R14" not in out.rules


def test_the_rule_version_is_05_v0_12(b):
    assert adj.RULE_VERSION == "05-v0.14"                     # bumped again by the second external review (05-v0.13)
    assert {d.data.get("rule_version") for d in b.docs if d.kind in ("verdict", "run")} == {"05-v0.14"}


# ================================================================ 2. S2 jobs are judged by their status
MRUN, MAUDIT = "run.example.json", "audit-event.run-2026-09-23-001.example.jsonl"


def s2_job(b):
    run = doc(b, MRUN).data
    jid = next(j for j, x in run["jobs"].items() if x["safety_class"] == "S2")
    return run, jid, run["jobs"][jid]


def fail_restore(b, keys, run_failed=True):
    run, jid, job = s2_job(b)
    log = doc(b, MAUDIT).data
    ev = next(e for e in log if e["event_type"] == "snapshot_restored" and e["payload"].get("job_id") == jid)
    ev["event_type"] = "restore_failed"
    ev["payload"] = {"job_id": jid, "snapshot_ref": job["snapshot_ref"], "reason": "checksum 不符，還原後的資料庫與快照不同"}
    job.update({"status": "RESTORE_FAILED", "restore_verified": False})
    if run_failed:                                       # docs/03 §5.6: a failed restore ends the run FAILED
        last = [e for e in log if e["event_type"] == "run_status_changed"][-1]
        last["payload"]["to"] = "FAILED"
        run.update({"status": "FAILED", "status_reason": "S2 還原失敗，staging 狀態未知"})
    rederive(b, keys)


def test_an_honest_restore_failure_validates(b, keys):
    fail_restore(b, keys)
    assert run_all(b).errors == []                       # the whole honest record validates, not only E-RUN-S2


def test_a_failed_restore_cannot_end_completed(b, keys):
    fail_restore(b, keys, run_failed=False)
    assert any("so the run is FAILED, not COMPLETED" in i.msg for i in errors(b, "E-RUN-S2"))


def test_restore_failed_claimed_restored_is_rejected(b, keys):
    run, jid, job = s2_job(b)
    log = doc(b, MAUDIT).data
    ev = next(e for e in log if e["event_type"] == "snapshot_restored" and e["payload"].get("job_id") == jid)
    ev["event_type"] = "restore_failed"
    ev["payload"] = {"job_id": jid, "snapshot_ref": job["snapshot_ref"], "reason": "x"}
    rederive(b, keys)
    assert any("restore_failed" in i.msg for i in errors(b, "E-RUN-S2"))


def test_restore_failed_needs_the_logged_failure(b, keys):
    run, jid, job = s2_job(b)
    job.update({"status": "RESTORE_FAILED", "restore_verified": False})
    rederive(b, keys)
    assert any("needs an anchored restore_failed" in i.msg for i in errors(b, "E-RUN-S2"))


def test_a_restore_failed_job_cannot_claim_verified(b, keys):
    run, jid, job = s2_job(b)
    log = doc(b, MAUDIT).data
    ev = next(e for e in log if e["event_type"] == "snapshot_restored" and e["payload"].get("job_id") == jid)
    ev["event_type"] = "restore_failed"
    ev["payload"] = {"job_id": jid, "snapshot_ref": job["snapshot_ref"], "reason": "x"}
    job.update({"status": "RESTORE_FAILED", "restore_verified": True})
    rederive(b, keys)
    assert any("the restore failed, so restore_verified is false" in i.msg for i in errors(b, "E-RUN-S2"))


def test_a_g5_rejected_s2_job_is_skipped_without_a_snapshot(b, keys):
    run, jid, job = s2_job(b)
    g5 = doc(b, "gate-record.g5.example.json").data
    g5["outcome"] = "REJECTED"
    log = doc(b, MAUDIT).data
    log[:] = [e for e in log if (e.get("payload") or {}).get("job_id") != jid]
    job.update({"status": "SKIPPED", "skip_reason": "g5_rejected", "snapshot_ref": None, "restore_verified": False, "result_ref": None})
    rederive(b, keys)
    # only E-RUN-S2 is under test: this probe leaves the job's result and gaps in place, which other rules report
    assert errors(b, "E-RUN-S2") == []


def test_a_skipped_s2_job_must_not_have_run(b, keys):
    run, jid, job = s2_job(b)
    job.update({"status": "SKIPPED", "skip_reason": "g5_rejected"})
    rederive(b, keys)
    assert any("so it never ran" in i.msg for i in errors(b, "E-RUN-S2"))


def test_a_restored_job_still_needs_its_approved_g5(b, keys):
    doc(b, "gate-record.g5.example.json").data["outcome"] = "REJECTED"
    rederive(b, keys)
    assert any("APPROVED G5" in i.msg for i in errors(b, "E-RUN-S2"))


# ================================================================ 3. the mutation runner wants an assertion
import mutation_check  # noqa: E402


def junit(tmp_path, body):
    (tmp_path / "test_m.py").write_text(body, encoding="utf-8")
    return mutation_check.run_tests(tmp_path, "test_m.py", "test_")


def test_an_assertion_failure_is_caught(tmp_path):
    assert mutation_check.classify(junit(tmp_path, "def test_a():\n    assert 1 == 2\n"))[0] == "CAUGHT"


def test_an_exception_in_the_test_body_is_not_caught(tmp_path):
    body = "def f():\n    raise RuntimeError('boom')\n\ndef test_a():\n    assert f() is None\n"
    verdict, detail = mutation_check.classify(junit(tmp_path, body))
    assert verdict == "VERIFY" and "RuntimeError" in detail


def test_an_exception_before_any_assertion_is_not_caught(tmp_path):
    # the runner stops at the first failure (-x): an exception there means no assertion of the list caught the mutation
    body = "def test_a():\n    raise KeyError('k')\n\ndef test_b():\n    assert 1 == 2\n"
    (tmp_path / "test_m.py").write_text(body, encoding="utf-8")
    r = mutation_check.run_tests(tmp_path, "test_m.py", "test_a or test_b")
    assert mutation_check.classify(r)[0] == "VERIFY"


# ================================================================ 4. docs/08 AdjudicationInputs mirrors adjudicate.Inputs
def spec_fields():
    s = (ROOT / "docs/08-implementation-spec.md").read_text(encoding="utf-8")
    block = s.split("class AdjudicationInputs(BaseModel):", 1)[1].split("\nclass ", 1)[0].split("\n\n", 1)[0]
    return [m.group(1) for m in re.finditer(r"^    ([a-z_][a-z0-9_]*)\s*:", block, re.M)]


def test_the_spec_lists_every_inputs_field_in_order():
    assert spec_fields() == [f.name for f in dataclasses.fields(adj.Inputs)]


def test_the_inputs_comments_name_the_right_rule_version():
    import inspect
    src = inspect.getsource(adj.Inputs)
    assert "r11 (05-v0.11)" not in src and "r11 (05-v0.10)" in src
