# SPDX-License-Identifier: Apache-2.0
"""Review round 10 (docs/evidence/review-2026-10-27-r10.md), PR1: three surfaces the anchor model did not cover yet,
plus robustness. Each defect test failed on 340b801 and passes with the fix; see CONTRIBUTING.md.

The bypasses need no key unless a test says so: they edit unsigned Z1 documents, re-derive the unsigned derived fields
(`refix_nokey`) and append to or re-chain only the unanchored tail of a log.

  reopen     nothing follows a run_end anchor: a completed run cannot be reopened by an unanchored
             run_status_changed and a run record marked RUNNING again (E-AUDIT-TAIL);
  manifest   a run has one report manifest, and it is the one an anchored report_published pins; a manifest without
             that event is not a report (E-ID-DUP, E-AUDIT-REPORT);
  gate       gate_decision pins the content of the gate record it decides (gate_record_sha256, signatures excluded), so
             the approvers cannot rewrite a decided record with their own keys (E-AUDIT-GATE);
  W4         once a run is COMPLETED every w4-testcase has a W4 result, and every W4 sandbox_job_end names a W4 result
             (E-W4-COVERAGE, E-W4-AUDIT): a test on paper does not cover an invariant;
  ownership  every run.ownership_results entry is backed by an anchored ownership_check event of the same batch that
             lists the target, method and outcome, received before the first B4 job against that target (E-RUN-OWNERSHIP);
  robust     the anchor-counter gap check does not enumerate the gap; a non-ASCII digit in an inventory reference is
             not an internal error.
"""
import copy
import json
import time

from conftest import doc, rederive, resign_gate
from test_v07_r9_anchor import AUDIT, FAUDIT, FRUN, RUN, rechain, refix_nokey, tail_event
from vchlib import checks, derive
from vchlib.bundle import Doc, reload_json
from vchlib.canonical import content_hash
from vchlib.checks import run_all


def errors(b, code, where=None):
    return [i for i in run_all(b).errors if i.code == code and (where is None or where in i.where)]


def test_the_examples_are_clean(b):
    assert run_all(b).errors == []


# ================================================================ reopen
def test_a_completed_run_cannot_be_reopened_after_its_run_end_anchor(b):
    tail_event(b, AUDIT, "run_status_changed", "B5", {"from": "COMPLETED", "to": "RUNNING", "reason": "reopen"}, "reopen")
    doc(b, "run.example.json").data["status"] = "RUNNING"
    refix_nokey(b)
    assert rechain(b, AUDIT)
    assert any("run_end" in i.msg for i in errors(b, "E-AUDIT-TAIL", "run-2026-09-23-001"))


def test_nothing_follows_a_run_end_anchor(b):
    run = doc(b, "run.example.json").data
    tail_event(b, AUDIT, "run_status_changed", "B5", {"from": "COMPLETED", "to": "RUNNING"}, "reopen", ts="2026-10-20T10:00:00+08:00")
    tail_event(b, AUDIT, "gate_opened", "G4", {"gate": "G4", "round": 2}, "g4-2", ts="2026-10-20T10:02:00+08:00")
    tail_event(b, AUDIT, "run_status_changed", "G4", {"from": "RUNNING", "to": "WAITING_GATE"}, "wait", ts="2026-10-20T10:03:00+08:00")
    run.update({"status": "WAITING_GATE", "current_node": "G4", "resume_deadline": "2026-10-23T10:02:00+08:00"})
    run["gate_records"].append({"gate": "G4", "gate_record_id": None, "round": 2, "opened_at": "2026-10-20T10:02:00+08:00",
                                "subject_hash": run["testplan_ref"], "outcome": None, "job_id": None, "decided_at": None})
    refix_nokey(b)
    assert rechain(b, AUDIT)
    errs = errors(b, "E-AUDIT-TAIL", "run-2026-09-23-001")
    assert len(errs) == 1 and "3 line(s) after the run_end anchor" in errs[0].msg


def test_a_completed_run_with_a_tail_reports_one_tail_error(b):
    tail_event(b, AUDIT, "restore_drill", "B4", {"ok": True, "snapshot_ref": "snap-x"}, "drill2")
    assert rechain(b, AUDIT)
    assert len(errors(b, "E-AUDIT-TAIL")) == 1


# ================================================================ report manifest
def follow_up_manifest(b):
    """A report manifest for the WAITING_GATE follow-up run, consistent in every derived value, with no event."""
    run = doc(b, "run.followup.example.json").data
    rm = copy.deepcopy(doc(b, "report-manifest.example.json").data)
    rm.update({"report_id": "RPT-2026-10-20-001", "run_id": FRUN, "generated_at": "2026-10-20T12:00:00+08:00",
               "gaps": run["gaps"], "manual_review_clusters": [], "over_cap_items": [], "report_only_clusters": [],
               "build_unverified_targets": [], "absent_fingerprints": []})
    c = checks.Ctx(b)
    heads = checks.verdict_heads(c, run["verdicts"])
    rm["verdict_counts"] = {s: sum(1 for v in heads if v.get("status") == s) for s in checks.FINAL_STATUSES}
    rm["metrics"] = checks.report_metrics(c, FRUN)
    base = run.get("baseline_run_id")
    cur = {derive.cluster_fingerprint(k.data) for k in c.docs("cluster") if k.data.get("run_id") == FRUN}
    old = {derive.cluster_fingerprint(k.data) for k in c.docs("cluster") if base is not None and k.data.get("run_id") == base}
    rm["absent_fingerprints"] = sorted(old - cur)
    grs = [g.data["gate_record_id"] for g in c.ix.gate_records(FRUN)]
    rm["artifacts"] = [{"kind": "whitebox_report", "ref": f"reports/{FRUN}/whitebox.md", "sha256": "sha256:" + "ab" * 32},
                       {"kind": "sarif", "ref": f"reports/{FRUN}/whitebox.sarif", "sha256": "sha256:" + "cd" * 32},
                       {"kind": "audit_log", "ref": f"docs/schemas/examples/{FAUDIT}", "sha256": "sha256:" + "ef" * 32}] \
        + [{"kind": "gate_record", "ref": g, "sha256": "sha256:" + "00" * 32} for g in grs] \
        + [{"kind": "verdict", "ref": v["verdict_id"], "sha256": "sha256:" + "00" * 32} for v in heads]
    b.docs.append(Doc("docs/schemas/examples/report-manifest.followup.example.json", "report-manifest", rm, json.dumps(rm)))
    return rm


def test_a_second_report_manifest_of_a_run_is_reported(b):
    fake = copy.deepcopy(doc(b, "report-manifest.example.json").data)
    fake.update(report_id="RPT-2026-10-06-002", generated_at="2026-10-20T12:00:00+08:00", report_only_clusters=[])
    for a in fake["artifacts"]:
        if a["kind"] in ("sarif", "whitebox_report"):
            a["sha256"] = "sha256:" + "ab" * 32
    b.docs.append(Doc("docs/schemas/examples/report-manifest.zz-second.example.json", "report-manifest", fake, json.dumps(fake)))
    refix_nokey(b)
    assert any("report-manifest" in i.msg for i in errors(b, "E-ID-DUP"))
    assert errors(b, "E-AUDIT-REPORT", "report-manifest.zz-second")


def test_a_manifest_without_a_report_published_event_is_not_a_report(b):
    follow_up_manifest(b)
    refix_nokey(b)
    assert any("report_published" in i.msg for i in errors(b, "E-AUDIT-REPORT", "report-manifest.followup"))


def test_a_report_published_event_in_the_unanchored_tail_publishes_nothing(b):
    rm = follow_up_manifest(b)
    refix_nokey(b)
    tail_event(b, FAUDIT, "report_published", "B6", {"report_id": rm["report_id"], "report_manifest_sha256": content_hash(rm)}, "pub")
    assert rechain(b, FAUDIT)
    refix_nokey(b)
    assert any("anchored" in i.msg for i in errors(b, "E-AUDIT-REPORT", "report-manifest.followup"))


# ================================================================ gate record content
def test_every_gate_decision_pins_its_gate_record(b):
    seen = 0
    for d in b.docs:
        if d.kind != "audit-event":
            continue
        for e in d.data:
            if e["event_type"] == "gate_decision":
                rec = next(g.data for g in b.docs if g.kind == "gate-record" and g.data["gate_record_id"] == e["payload"]["gate_record_id"])
                assert e["payload"]["gate_record_sha256"] == derive.gate_record_sha256(rec)
                seen += 1
    assert seen >= 10


def refix_gate(b, suffix):
    d = doc(b, suffix)
    for e in derive.expectations(b):
        if e.file == d.path and derive.get_path(d.data, e.path) != e.expected:
            derive.set_path(d.data, e.path, e.expected)


def test_rewriting_a_decided_gate_record_with_the_approvers_keys_is_reported(b, keys):
    """Review r10 probe: erin and frank add an accepted threat to the decided GR-G3-0002 and re-sign it."""
    t = copy.deepcopy(doc(b, "threat.t-019.example.json").data)
    t.update({"threat_id": "T-040", "title": "事後加進 G3 的威脅", "review": {"status": "ACCEPTED", "gate_record_id": "GR-G3-0002"},
              "source_cluster_id": None, "source_finding_ids": []})
    b.docs.append(Doc("docs/schemas/examples/threat.t-040.example.json", "threat", t, json.dumps(t)))
    g3 = doc(b, "gate-record.followup.g3.example.json")
    g3.data["decisions"].append({"item_id": "T-040", "item_sha256": "sha256:" + "0" * 64, "decision": "accept",
                                 "risk_override": None, "note": "added after the decision was anchored", "carried_from": None})
    refix_gate(b, "gate-record.followup.g3.example.json")
    resign_gate(b, "gate-record.followup.g3.example.json", keys)
    refix_nokey(b)
    assert any("GR-G3-0002" in i.msg for i in errors(b, "E-AUDIT-GATE"))


def test_re_signing_the_same_gate_record_content_is_not_a_change(b, keys):
    resign_gate(b, "gate-record.followup.g3.example.json", keys)
    assert run_all(b).errors == []


# ================================================================ W4 on paper
def test_a_w4_testcase_that_never_ran_does_not_cover_an_invariant(b):
    run = doc(b, "run.example.json").data
    run["w4_manual_requirements"] = []
    tc = copy.deepcopy(doc(b, "w4-testcase.k-015.example.json").data)
    tc.update({"testcase_id": "WTC-015-02", "requirement_ids": ["INV-LLM-003"], "kind": "unit", "target_files": ["db/migrations/0001_init.sql"],
               "environment": {"zone": "Z2", "network": "none", "dependencies_lock_sha256": tc["environment"]["dependencies_lock_sha256"],
                               "database": None},
               "test_file": "w4/run-2026-09-23-001/test_refund_tool.py"})
    tc["oracle"]["requirement_refs"] = ["INV-LLM-003"]
    b.docs.append(Doc("docs/schemas/examples/w4-testcase.k-015-02.example.json", "w4-testcase", tc, json.dumps(tc)))
    refix_nokey(b)
    assert any("WTC-015-02" in i.msg for i in errors(b, "E-W4-COVERAGE"))


def test_a_w4_sandbox_job_end_names_a_w4_result(b, keys):
    d = doc(b, AUDIT)
    i = next(i for i, e in enumerate(d.data) if e["event_type"] == "sandbox_job_end" and e["node"] == "W4")
    start = copy.deepcopy(next(e for e in d.data if e["event_type"] == "sandbox_job_start" and e["node"] == "W4"))
    end = copy.deepcopy(d.data[i])
    for e, k in ((start, "sandbox_job_start"), (end, "sandbox_job_end")):
        e["payload"]["job_id"] = "w4-WTC-015-01-2"
        e["idempotency_key"] = f"{RUN}:W4:{k}:w4-WTC-015-01-2"
    end["payload"]["result_id"] = "R-WTC-015-01-9"
    d.data[i + 1:i + 1] = [start, end]
    for n, e in enumerate(d.data, start=1):
        e["seq"] = n
    reload_json(d, "".join(json.dumps(e, ensure_ascii=False, separators=(",", ":")) + "\n" for e in d.data))
    rederive(b, keys)
    assert any("R-WTC-015-01-9" in x.msg for x in errors(b, "E-W4-AUDIT"))


# ================================================================ ownership results bound to Z3 events
def test_the_ownership_check_event_lists_each_target(b):
    run = doc(b, "run.example.json").data
    ev = next(e for e in doc(b, AUDIT).data if e["event_type"] == "ownership_check")
    listed = {(r["target_id"], r["method"], r["ok"]) for r in ev["payload"]["results"]}
    assert listed == {(o["target_id"], o["method"], o["ok"]) for o in run["ownership_results"]}


def test_ownership_results_without_an_ownership_check_event_are_reported(b):
    """Review r10 probe: the batch names no event, and the check is dated after every B4 job."""
    for o in doc(b, "run.example.json").data["ownership_results"]:
        o["batch_id"] = "own-9999-does-not-exist"
        o["checked_at"] = "2026-10-05T23:59:00+08:00"
    refix_nokey(b)
    assert len(errors(b, "E-RUN-OWNERSHIP")) >= 4


def test_an_ownership_result_checked_after_its_event_is_reported(b):
    o = next(o for o in doc(b, "run.example.json").data["ownership_results"] if o["target_id"] == "tgt-staging-api")
    o["checked_at"] = "2026-10-05T23:59:00+08:00"
    assert any("tgt-staging-api" in i.msg for i in errors(b, "E-RUN-OWNERSHIP"))


def test_an_ownership_result_the_event_does_not_list_is_reported(b, keys):
    ev = next(e for e in doc(b, AUDIT).data if e["event_type"] == "ownership_check")
    ev["payload"]["results"] = [r for r in ev["payload"]["results"] if r["target_id"] != "tgt-staging-db"]
    rederive(b, keys)
    assert any("tgt-staging-db" in i.msg for i in errors(b, "E-RUN-OWNERSHIP"))


# ================================================================ robustness
def test_the_anchor_counter_gap_is_not_enumerated():
    t = time.perf_counter()
    out = checks.anchor_counter_problems([(1, "2026-09-23T10:00:00Z", "a"), (10 ** 7, "2026-09-24T10:00:00Z", "b")])
    assert time.perf_counter() - t < 0.2
    assert any("9999998" in x for x in out)


def test_anchor_counter_problems_still_name_the_missing_counters():
    out = checks.anchor_counter_problems([(1, "2026-09-23T10:00:00Z", "a"), (4, "2026-09-24T10:00:00Z", "b"),
                                          (4, "2026-09-25T10:00:00Z", "c")])
    assert any("[2, 3]" in x for x in out) and any("twice" in x for x in out)


def test_a_non_ascii_digit_in_an_inventory_reference_is_not_an_internal_error(b):
    dfd = doc(b, "dfd.merged.example.json").data
    store = next(e for e in dfd["elements"] if e["type"] == "data_store")
    store["evidence_refs"] = list(store.get("evidence_refs") or []) + ["inventory:/db/tables/²"]
    assert not errors(b, "E-INTERNAL")
