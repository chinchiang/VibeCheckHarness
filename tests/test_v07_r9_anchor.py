# SPDX-License-Identifier: Apache-2.0
"""Review round 9 (docs/evidence/review-2026-10-27-r9.md), PR1: what the validator took as fact without an anchor.
Each bypass test reproduced its bypass on 87a5175 (it failed there) and passes with the fix; see CONTRIBUTING.md.

The bypasses need no key: they edit unsigned Z1 documents (run records, clusters, findings, seed threats, the report
manifest), re-derive the unsigned derived fields (`refix_nokey`) and re-chain only the unanchored tail of a log.

  rollback  a completed run cut back to an earlier anchor (B4 proofs, G5, B5 verdicts and the report deleted) leaves a
            gap in the engagement-wide anchor counter the Z3 executor countersigns (E-AUDIT-ANCHOR-GAP);
  status    run.status is the last run_status_changed of the log, so a completed run cannot be marked RUNNING again
            to reopen its tail (E-RUN-STATUS);
  verdict   a verdict_changed in the unanchored tail does not make a verdict (E-AUDIT-VERDICT);
  members   a verdict pins its cluster and the cluster pins its member findings (cluster_sha256,
            member_finding_sha256); a carried cluster has no members of its own (E-CLUSTER-CARRY);
  phase     the first version of a white-box cluster is W3_adjudicate; a G2_apply version names the G2 record that
            decided the cluster (E-VERDICT-PHASE, E-VERDICT-G2);
  seed      the seed threats are pinned by their anchored artifact_stored event, and every seed comes from a cluster of
            the seed document's run (E-AUDIT-ARTIFACT, E-TRACE-SEED);
  commit    the commit a run tests is pinned in its anchored run_created event (E-RUN-COMMIT);
  jobs      every sandbox_job event names a job of run.jobs, and a completed run has a job for every testcase G4
            approved (E-JOB-AUDIT).
"""
import copy
import hashlib
import json

import pytest

from conftest import doc, rederive
from vchlib import checks, derive
from vchlib.bundle import Doc, reload_json
from vchlib.canonical import content_hash
from vchlib.checks import run_all

RUN, FRUN, LRUN = "run-2026-09-23-001", "run-2026-10-07-001", "run-2026-09-25-pr-118"
AUDIT = "audit-event.run-2026-09-23-001.example.jsonl"
FAUDIT = "audit-event.run-2026-10-07-001.example.jsonl"


def errors(b, code, where=None):
    return [i for i in run_all(b).errors if i.code == code and (where is None or where in i.where)]


def refix_nokey(b, rounds=20):
    """Apply every derived value that sits in an unsigned, unanchored document (what Z1 write access alone can do).
    Audit-event payloads need a Z3 re-anchor and signed gate records need the approvers' keys: those are skipped."""
    for _ in range(rounds):
        docs, changed = {d.path: d for d in b.docs}, False
        for e in derive.expectations(b, for_writer=True):
            d = docs[e.file]
            if d.kind == "audit-event" or (d.kind == "gate-record" and d.data.get("signatures")):
                continue
            if derive.get_path(d.data, e.path) != e.expected:
                derive.set_path(d.data, e.path, e.expected)
                changed = True
        if not changed:
            return


def rechain(b, suffix):
    """Recompute seq and prev_hash of every line (ordinary lines carry no signature). Returns True iff the anchored
    prefix of the log is byte-for-byte unchanged, i.e. only the unanchored tail was touched."""
    d = doc(b, suffix)
    old = [ln for ln in (d.text or "").split("\n") if ln.strip()]
    prev, lines = hashlib.sha256(d.data[0]["run_id"].encode()).hexdigest(), []
    for i, ev in enumerate(d.data):
        ev["seq"], ev["prev_hash"] = i + 1, "sha256:" + prev
        line = json.dumps(ev, ensure_ascii=False, separators=(",", ":"))
        prev = hashlib.sha256(line.encode("utf-8")).hexdigest()
        lines.append(line)
    last = max(i for i, e in enumerate(d.data) if e["event_type"] == "audit_anchor")
    reload_json(d, "".join(ln + "\n" for ln in lines))
    return old[:last + 1] == lines[:last + 1]


def tail_event(b, suffix, event_type, node, payload, key, ts="2026-10-20T10:00:00+08:00"):
    """Append an unsigned event after the last anchor of a log (cloned from the log's first line)."""
    d = doc(b, suffix)
    ev = copy.deepcopy(d.data[0])
    ev.update({"event_type": event_type, "node": node, "payload": payload, "idempotency_key": f"{ev['run_id']}:{node}:{key}",
               "ts": ts, "signature": None, "payload_refs": []})
    d.data.append(ev)
    return ev


def add_doc(b, name, kind, data):
    b.docs.append(Doc(f"docs/schemas/examples/{name}", kind, data, json.dumps(data)))


def test_the_examples_are_clean(b):
    assert run_all(b).errors == []


# ================================================================ rollback: the anchor counter
def test_every_anchor_carries_the_engagement_counter(b):
    anchors = sorted(((e["payload"]["anchor_counter"], e["ts"]) for d in b.docs if d.kind == "audit-event"
                      for e in d.data if e["event_type"] == "audit_anchor"), key=lambda x: x[0])
    assert [n for n, _ in anchors] == list(range(1, len(anchors) + 1))
    assert [t for _, t in anchors] == sorted((t for _, t in anchors), key=derive.timeutil.sort_key)


def roll_back_to_g4(b):
    """Cut run 001 back to its G4 anchor (seq 42) and delete what came after it: what the review r9 probe did."""
    d = doc(b, AUDIT)
    lines = [ln for ln in d.text.split("\n") if ln.strip()]
    reload_json(d, "".join(ln + "\n" for ln in lines[:42]))
    run = doc(b, "run.example.json").data
    run.update({"status": "RUNNING", "current_node": "B4", "status_reason": None, "jobs": {}, "executed_jobs": []})
    gone_v, gone_k = {"V-005-2", "V-011-2", "V-201-1", "V-202-1"}, {"K-201", "K-202"}
    run["verdicts"] = [x for x in run["verdicts"] if x not in gone_v]
    run["cluster_ids"] = [x for x in run["cluster_ids"] if x not in gone_k]
    run["gate_records"] = [g for g in run["gate_records"] if g["gate"] != "G5"]
    for p in ("verdict.executable.example.json", "verdict.k-011-b5.example.json", "verdict.k-201-b5.example.json",
              "verdict.k-202-b5.example.json", "cluster.k-201.example.json", "cluster.k-202.example.json",
              "gate-record.g5.example.json", "testresult.example.json", "testresult.bola-list.example.json",
              "testresult.llm-pass.example.json", "testresult.zap-active.example.json"):
        b.docs.remove(doc(b, p))
    rm = doc(b, "report-manifest.example.json").data
    rm["artifacts"] = [a for a in rm["artifacts"] if not (a["ref"] in gone_v or a["ref"] == "GR-G5-0001" or a["ref"].startswith("R-TC-"))]
    refix_nokey(b)
    c = checks.Ctx(b)
    heads = checks.verdict_heads(c, run["verdicts"])
    rm["verdict_counts"] = {s: sum(1 for v in heads if v.get("status") == s) for s in checks.FINAL_STATUSES}
    rm["metrics"] = checks.report_metrics(c, RUN)
    refix_nokey(b)


def test_rolling_a_completed_run_back_to_an_earlier_anchor_leaves_a_counter_gap(b):
    roll_back_to_g4(b)
    # v0.7 (review r9 PR4): the follow-up run's anchored spot check of V-005-2 also outlives the deleted verdict
    assert {i.code for i in run_all(b).errors} == {"E-AUDIT-ANCHOR-GAP", "E-SPOT-CHECK"}


def test_anchor_counter_problems():
    assert checks.anchor_counter_problems([(1, "2026-09-23T10:00:00Z", "a"), (2, "2026-09-24T10:00:00Z", "b")]) == []
    assert checks.anchor_counter_problems([(1, "2026-09-23T10:00:00Z", "a"), (3, "2026-09-24T10:00:00Z", "b")])          # gap
    assert checks.anchor_counter_problems([(1, "2026-09-23T10:00:00Z", "a"), (1, "2026-09-24T10:00:00Z", "b")])          # twice
    assert checks.anchor_counter_problems([(2, "2026-09-23T10:00:00Z", "a"), (1, "2026-09-24T10:00:00Z", "b")])          # order
    assert checks.anchor_counter_problems([(1, "2026-09-23T10:00:00Z", "a"), ("2", "2026-09-24T10:00:00Z", "b")])        # type


def test_the_counter_is_inside_the_countersignature(b):
    ev = next(e for e in doc(b, AUDIT).data if e["event_type"] == "audit_anchor")
    ev["payload"]["anchor_counter"] += 100
    rechain(b, AUDIT)
    refix_nokey(b)
    assert errors(b, "E-AUDIT-ANCHOR-SIG")


# ================================================================ status: run.status follows the log
def test_a_run_with_a_run_end_anchor_is_terminal(b):
    """Review r9 P3: the completed run marked RUNNING again, so its tail accepted new unanchored lines."""
    doc(b, "run.example.json").data.update({"status": "RUNNING", "status_reason": None})
    tail_event(b, AUDIT, "restore_drill", "B3", {"target_id": "tgt-staging-db", "ok": True}, "drill-late")
    assert rechain(b, AUDIT)
    refix_nokey(b)
    assert errors(b, "E-RUN-STATUS", RUN)


def test_status_is_the_last_status_change_of_the_log(b):
    doc(b, "run.followup.example.json").data["status"] = "RUNNING"
    refix_nokey(b)
    assert any("WAITING_GATE" in i.msg for i in errors(b, "E-RUN-STATUS", FRUN))


# ================================================================ verdict: an unanchored verdict_changed is no verdict
def add_k301_verdict(b):
    """Review r9 P1: a W3 verdict for the carried cluster K-301 of the follow-up run (WAITING_GATE), whose
    verdict_changed is appended after the last anchor."""
    v = copy.deepcopy(doc(b, "verdict.example.json").data)
    v.update({"verdict_id": "V-301-1", "cluster_id": "K-301"})
    add_doc(b, "verdict.k-301-w3.example.json", "verdict", v)
    doc(b, "run.followup.example.json").data["verdicts"] = ["V-301-1"]
    ev = tail_event(b, FAUDIT, "verdict_changed", "W3", {"verdict_id": "V-301-1"}, "verdict-V-301-1")
    refix_nokey(b)
    c = checks.Ctx(checks.quarantine(checks.Report(), b))
    cl = c.ix.first("cluster", cluster_id="K-301").data
    out = checks.adj.adjudicate(checks.verdict_inputs(c, v, cl))
    v.update({"status": out.status, "status_cap": out.status_cap, "advisory": out.advisory,
              "annotations": [{"kind": k, "note": k} for k in sorted(out.annotations)],
              "rule_trace": [f"{r}: probe" for r in out.rules],
              "independent_sources": checks.derived_independent_sources(c, v, cl),
              "tool_corroboration": checks.derived_tool_corroboration(c, v, cl),
              "tool_signal": checks.derived_tool_signal(c, v, cl),
              "diversity_degraded": checks.derived_diversity_degraded(c, v, cl),
              "no_eligible_verifier": checks.derived_no_eligible_verifier(c, cl),
              "provisional": checks.derived_provisional(c, v, cl), "rule_version": checks.adj.RULE_VERSION})
    refix_nokey(b)
    ev["payload"].update({"status": v["status"], "verdict_sha256": content_hash(v)})
    assert rechain(b, FAUDIT)
    refix_nokey(b)
    return v


def test_a_verdict_changed_in_the_unanchored_tail_is_not_a_verdict(b):
    add_k301_verdict(b)
    assert {i.code for i in run_all(b).errors} == {"E-AUDIT-VERDICT"}
    assert any("after the last audit_anchor" in i.msg for i in errors(b, "E-AUDIT-VERDICT", "k-301"))


# ================================================================ members: the verdict pins the cluster and its findings
def test_the_examples_pin_clusters_and_findings(b):
    c = checks.Ctx(b)
    for d in b.docs:
        if d.kind == "verdict":
            assert d.data["cluster_sha256"] == content_hash(c.ix.first("cluster", cluster_id=d.data["cluster_id"]).data)
        if d.kind == "cluster":
            assert d.data["member_finding_sha256"] == [content_hash(c.ix.first("finding", finding_id=f).data)
                                                       for f in d.data["member_finding_ids"]]


def test_editing_a_member_finding_after_the_verdict_breaks_the_anchored_verdict(b):
    doc(b, "finding.example.json").data["reasoning"] += " (edited after W3)"
    refix_nokey(b)
    assert errors(b, "E-AUDIT-VERDICT", AUDIT)


def test_a_carried_cluster_has_no_members_of_its_own(b):
    """Review r9 P2: findings added to the carried cluster K-301 skipped the evidence binding (E-CLUSTER-BINDING)."""
    f = copy.deepcopy(doc(b, "finding.f-021.example.json").data)
    f.update({"finding_id": "F-300", "run_id": FRUN})
    add_doc(b, "finding.f-300.example.json", "finding", f)
    doc(b, "run.followup.example.json").data["findings"] = ["F-300"]
    doc(b, "cluster.followup.k-301.example.json").data["member_finding_ids"] = ["F-300"]
    refix_nokey(b)
    assert any("member" in i.msg for i in errors(b, "E-CLUSTER-CARRY", "k-301"))


# ================================================================ phase: the first version and the G2 link
def test_the_first_version_of_a_white_box_cluster_is_w3(b, keys):
    doc(b, "verdict.example.json").data["readjudicated_by"] = "W4_readjudicate"
    rederive(b, keys)
    assert any("first version" in i.msg for i in errors(b, "E-VERDICT-PHASE", "verdict.example"))


def test_a_g2_apply_version_names_the_g2_record_that_decided_the_cluster(b, keys):
    """Review r9 P4: a cluster's first version labelled G2_apply skipped the G2 routing check, and a G2_apply version
    with no G2 record for its cluster passed E-VERDICT-G2."""
    doc(b, "verdict.example.json").data["readjudicated_by"] = "G2_apply"
    rederive(b, keys)
    assert errors(b, "E-VERDICT-G2", "verdict.example")


# ================================================================ seed: the seed threats are pinned
def test_the_seed_artifact_event_pins_the_seed_threats(b):
    ev = next(e for e in doc(b, AUDIT).data if e["event_type"] == "artifact_stored")
    assert ev["payload"]["sha256"] == content_hash(doc(b, "seed-threats.example.json").data)


def test_moving_the_seed_threats_to_another_run_is_reported(b):
    """Review r9 P6: the seed document's run_id moved to the Lane A run switched off run 001's pipeline checks."""
    doc(b, "seed-threats.example.json").data["run_id"] = LRUN
    refix_nokey(b)
    assert errors(b, "E-AUDIT-ARTIFACT", AUDIT)              # run 001's event pins seed threats it no longer has
    assert errors(b, "E-AUDIT-ARTIFACT", "seed-threats")     # and the Lane A run has no event pinning them
    assert errors(b, "E-TRACE-SEED")


# ================================================================ commit: run_created pins the tested commit
def test_run_created_pins_the_commit(b):
    for d in b.docs:
        if d.kind == "run":
            ev = doc(b, f"audit-event.{d.data['run_id']}.example.jsonl").data[0]
            assert ev["event_type"] == "run_created" and ev["payload"]["repo_commit"] == d.data["repo_commit"]


def test_an_inventory_of_another_commit_is_reported(b):
    """Review r9 P5a: W0 inventoried another commit than the one the run tests."""
    doc(b, "inventory.example.json").data["repo_commit"] = "0" * 40
    refix_nokey(b)
    assert errors(b, "E-RUN-COMMIT", "inventory")


def test_rewriting_the_run_commit_is_reported(b):
    """Review r9 P5b: run and inventory rewritten to another commit with the same 12-character prefix."""
    new = doc(b, "run.example.json").data["repo_commit"][:12] + "f" * 28
    doc(b, "run.example.json").data["repo_commit"] = new
    doc(b, "inventory.example.json").data["repo_commit"] = new
    refix_nokey(b)
    assert errors(b, "E-RUN-COMMIT", RUN)


# ================================================================ jobs: no orphan job event, no missing job
def test_an_orphan_sandbox_job_event_is_reported(b):
    """Review r9 P15: job-list-001 dropped from run.jobs with its FAIL result; its anchored sandbox_job_end was ignored."""
    run = doc(b, "run.example.json").data
    del run["jobs"]["job-list-001"]
    run["executed_jobs"] = [j for j in run["executed_jobs"] if j != "job-list-001"]
    b.docs.remove(doc(b, "testresult.bola-list.example.json"))
    refix_nokey(b)
    assert any("job-list-001" in i.msg and "run.jobs" in i.msg for i in errors(b, "E-JOB-AUDIT", AUDIT))


def test_a_completed_run_has_a_job_for_every_approved_testcase(b, keys):
    run = doc(b, "run.example.json").data
    del run["jobs"]["job-list-001"]
    run["executed_jobs"] = [j for j in run["executed_jobs"] if j != "job-list-001"]
    b.docs.remove(doc(b, "testresult.bola-list.example.json"))
    a = doc(b, AUDIT)
    evs = [e for e in a.data if (e.get("payload") or {}).get("job_id") != "job-list-001"]
    for i, e in enumerate(evs):
        e["seq"] = i + 1
    reload_json(a, "".join(json.dumps(e, ensure_ascii=False, separators=(",", ":")) + "\n" for e in evs))
    rederive(b, keys)
    assert any("TC-033-01" in i.msg for i in errors(b, "E-JOB-AUDIT"))
