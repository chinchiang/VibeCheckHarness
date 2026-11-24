# SPDX-License-Identifier: Apache-2.0
"""Check group over the audit logs: the hash chain and its anchors, signatures of events, run transitions and the run's
structure, pinned artefacts, report and ownership events, job events, spot checks.

Split out of checks.py (architecture refactor PR-D7, docs/adr/0003-split-checks.md). The text is moved verbatim; no
rule, error code or message changed. checks.GROUPS still lists the group in the same place.
"""
from __future__ import annotations

from . import crypto, derive, timeutil
from .bundle import Doc, read_jsonl_lines
from .canonical import content_hash, sha256_hex
from .checks_engagement import profile
from .checks_runs import COMPLETED_RUN_STATES, JOB_RAN_STATES, target_activity_windows
from .checks_signatures import MAX_CLOCK_SKEW, verify_signature
from .context import Ctx
from .report import TERMINAL_RUN_STATES, Report, anchored_seqs, doc_guard, ts


# ============================================================== 15 audit log
def anchor_counter_problems(anchors) -> list[str]:
    """v0.7 (review r9 rollback): anchors = [(anchor_counter, ts, where)] of every audit_anchor of the engagement. The
    Z3 executor numbers the anchors it countersigns 1, 2, 3, ... in receive order, so the counters are unique integers
    without a gap and follow the receive time. Cutting a run back to an earlier anchor deletes counters that a later
    anchor (of the same or another run) already went past."""
    out, seen = [], {}  # type: ignore[var-annotated]  # an untyped local; its element types vary by branch
    for n, t, where in anchors:
        if type(n) is not int or n < 1:
            out.append(f"{where}: anchor_counter {n!r} is not a positive integer")
            continue
        if n in seen:
            out.append(f"{where}: anchor_counter {n} is used twice (also {seen[n]})")
        seen.setdefault(n, where)
    if seen:
        # v0.7 (review r10): one pass over the sorted counters; v0.7 r9 built set(range(1, max)), so one unsigned anchor
        # numbered 10**9 in an unanchored tail cost gigabytes
        missing, total, prev = [], 0, 0  # type: ignore[var-annotated]  # an untyped local; its element types vary by branch
        for n in sorted(seen):
            if n > prev + 1:
                total += n - prev - 1
                missing.extend(range(prev + 1, min(n, prev + 1 + 10 - len(missing))) if len(missing) < 10 else ())
            prev = n
        if total:
            out.append(f"anchor_counter {missing}{' ...' if total > len(missing) else ''} missing below {prev} ({total} in all): "
                       "anchors the Z3 executor countersigned are gone (a log was cut back to an earlier anchor or deleted)")
    ordered = sorted(((n, t, w) for n, t, w in anchors if type(n) is int), key=lambda x: x[0])
    for (n1, t1, w1), (n2, t2, w2) in zip(ordered, ordered[1:]):
        if timeutil.sort_key(t2) < timeutil.sort_key(t1):
            out.append(f"{w2}: anchor_counter {n2} was received at {t2}, before anchor_counter {n1} ({w1}, {t1})")
    return out


def g_audit(R: Report, c: Ctx):
    interval = (c.toolkit.get("audit") or {}).get("anchor_interval_events", 500)
    counters = []
    for d in c.ix.audit_docs():
        with doc_guard(R, d.path):
            evs, w = d.data, d.path
            rid = evs[0].get("run_id") if evs else None
            run = c.runs.get(rid)
            if not R.check(run is not None, "E-AUDIT-RUN", w, f"run {rid} not found"):
                continue
            prev_t, since, seen_keys = None, 0, set()
            for i, ev in enumerate(evs):
                where = f"{w} seq {ev.get('seq')}"
                # type(...) is int: a float literal such as 3e0 / 3.0 (or a bool) is not a seq
                R.check(type(ev.get("seq")) is int and ev.get("seq") == i + 1, "E-AUDIT-SEQ", where,
                        f"seq must be the integer {i + 1} (1, 2, 3, ...; float literals such as 3e0 are rejected), got {ev.get('seq')!r}")
                R.check(ev.get("run_id") == rid and ev.get("engagement_id") == c.engagement.get("engagement_id"), "E-AUDIT-RUN", where, "run/engagement mismatch")
                R.check(ev.get("data_class") == run.get("data_class"), "E-AUDIT-RUN", where, "data_class differs from the run")  # type: ignore[union-attr]  # a value an earlier check or lookup ruled out as None; mypy cannot follow it
                t = ts(R, ev.get("ts"), where)
                if t and prev_t:
                    R.check(t >= prev_t, "E-AUDIT-TS", where, "timestamps must not go backwards")
                prev_t = t or prev_t
                actor = ev.get("actor") or {}
                if actor.get("kind") == "human":
                    R.check(actor.get("id") in c.persons and actor.get("id") not in c.automation, "E-AUDIT-ACTOR", where, "human actor must be a registered person")
                et = ev.get("event_type")
                since = 0 if et == "audit_anchor" else since + 1
                R.check(since <= interval, "E-AUDIT-ANCHOR", where, f"more than {interval} events without an anchor")
                if et == "audit_anchor":
                    counters.append(((ev.get("payload") or {}).get("anchor_counter"), ev.get("ts"), where))
                    # v0.4: the Z3 executor countersigns {run_id, seq, prev_hash}; whoever controls both the
                    # audit log and the run record still cannot rewrite the chain without the Z3 key.
                    # v0.5 (T-9): plus a domain tag and the hash of the anchor event itself (crypto.anchor_payload)
                    cs = (ev.get("payload") or {}).get("z3_countersignature")
                    scratch = Report()
                    ok = isinstance(cs, dict) and cs.get("signer") == crypto.ANCHOR_SIGNER and verify_signature(
                        scratch, c, where, crypto.anchor_payload(ev), cs, t, need_role="z3_executor") is not None
                    R.check(ok, "E-AUDIT-ANCHOR-SIG", where, "audit_anchor needs a valid z3_countersignature by "
                            f"{crypto.ANCHOR_SIGNER} (role z3_executor) over {{domain, run_id, seq, prev_hash, event_sha256}}"
                            + (": " + "; ".join(f"{x.code} {x.msg}" for x in scratch.issues) if scratch.issues else ""))
                if et == "gate_decision":
                    nxt = evs[i + 1] if i + 1 < len(evs) else {}
                    R.check(nxt.get("event_type") == "audit_anchor", "E-AUDIT-ANCHOR", where, "every gate_decision must be followed by an audit_anchor")
                    p = ev.get("payload") or {}
                    rec = c.record(p.get("gate_record_id"))
                    signed_at = ts(R, rec.get("timestamp"), where) if rec is not None else None
                    R.check(rec is not None and rec.get("gate") == p.get("gate") and rec.get("outcome") == p.get("outcome")
                            and signed_at is not None and t is not None and abs(t - signed_at) <= MAX_CLOCK_SKEW, "E-AUDIT-GATE", where,
                            "gate_decision does not match its gate record (gate, outcome, or the signed timestamp differs from the "
                            f"Audit Writer's receive time by more than {MAX_CLOCK_SKEW})")
                    # v0.7 (review r10 gate): the event pins the decided record's content (signatures excluded); v0.7 r9 pinned
                    # gate and outcome only, so the record's own approvers could add or change decisions and re-sign it
                    R.check(rec is not None and p.get("gate_record_sha256") == derive.gate_record_sha256(rec), "E-AUDIT-GATE", where,
                            f"gate_decision pins gate_record_sha256 {p.get('gate_record_sha256')!r}, but {p.get('gate_record_id')} hashes to "
                            f"{derive.gate_record_sha256(rec) if rec is not None else None}: the record changed after it was decided")
                if et == "initiator_claim":
                    R.check(actor.get("id") in run.get("initiators", []), "E-AUDIT-INITIATOR", where, "claimed initiator not in run.initiators")  # type: ignore[union-attr]  # a value an earlier check or lookup ruled out as None; mypy cannot follow it
                if et == "spot_check_result":
                    spot_check(R, c, where, run, ev)  # type: ignore[arg-type]  # a value an earlier check or lookup ruled out as None; mypy cannot follow it
                # v0.4: idempotency keys are run_id:node:<key> and unique within the run (re-written events are deduplicated by it)
                ik = ev.get("idempotency_key")
                parts = ik.split(":", 2) if isinstance(ik, str) else []
                R.check(len(parts) == 3 and parts[0] == ev.get("run_id") and parts[1] == ev.get("node") and ik not in seen_keys,
                        "E-AUDIT-IDEMPOTENCY", where, f"idempotency_key {ik!r} must be '<run_id>:<node>:<key>' for this event and unique in the run")
                seen_keys.add(ik)
                if et == "verdict_changed":
                    p = ev.get("payload") or {}
                    v = c.ix.first("verdict", verdict_id=p.get("verdict_id"))
                    R.check(v is not None and v.data.get("status") == p.get("status"), "E-AUDIT-VERDICT", where, "verdict_changed does not match the verdict")
                    # v0.7 (review r8 H4): the event pins the whole verdict version, not only its status; v0.6 let anyone with
                    # Z1 write access rewrite a verdict's severity, rule_trace or evidence refs after the anchor
                    R.check(v is not None and p.get("verdict_sha256") == content_hash(v.data), "E-AUDIT-VERDICT", where,
                            f"verdict_changed pins verdict_sha256 {p.get('verdict_sha256')!r}, but {p.get('verdict_id')} hashes to "
                            f"{content_hash(v.data) if v is not None else None}: the verdict changed after it was recorded")
                if et == "report_published":
                    p = ev.get("payload") or {}
                    rm = c.ix.first("report-manifest", run_id=rid, report_id=p.get("report_id")) or c.ix.first("report-manifest", run_id=rid)
                    R.check(rm is not None and rm.data.get("report_id") == p.get("report_id"), "E-AUDIT-REPORT", where, "report id mismatch")
                    # v0.7 (review r8 H4): the manifest (whose artifacts pin the SARIF, HTML, verdicts and the audit log) is pinned too
                    R.check(rm is not None and p.get("report_manifest_sha256") == content_hash(rm.data), "E-AUDIT-REPORT", where,
                            f"report_published pins report_manifest_sha256 {p.get('report_manifest_sha256')!r}, but the manifest hashes to "
                            f"{content_hash(rm.data) if rm is not None else None}: the report changed after it was published")
            tail, last_anchor = audit_anchor_tail(R, w, run, d)  # type: ignore[arg-type]  # a value an earlier check or lookup ruled out as None; mypy cannot follow it
            # v0.7 (review r10 reopen): a run ends once. Whatever the (unsigned) run record says, no line follows the first
            # run_end anchor; v0.7 r9 decided "terminal" from run.status, which followed an unanchored run_status_changed
            # appended after the run_end anchor, so a completed run could be reopened without any key
            ended = next((i + 1 for i, e in enumerate(evs) if isinstance(e, dict) and e.get("event_type") == "audit_anchor"
                          and (e.get("payload") or {}).get("reason") == "run_end"), None)
            after_end = len(evs) - ended if ended is not None else 0
            if run.get("status") in TERMINAL_RUN_STATES or after_end:  # type: ignore[union-attr]  # a value an earlier check or lookup ruled out as None; mypy cannot follow it
                # at most one E-AUDIT-TAIL per run, listing every reason
                why = []
                if after_end:
                    why.append(f"{after_end} line(s) after the run_end anchor (seq {ended}): a run ends once and cannot be reopened")
                if tail > 0:
                    why.append(f"{tail} line(s) after the last audit_anchor (seq {last_anchor})")
                if not evs or evs[-1].get("event_type") != "audit_anchor":
                    why.append("the last event is not an audit_anchor")
                elif (evs[-1].get("payload") or {}).get("reason") != "run_end":
                    why.append("the final anchor is not a run_end anchor")
                R._checks += 1
                if why:
                    R.error("E-AUDIT-TAIL", w, f"{run.get('status')} run must end with a run_end audit_anchor covering the last line: "  # type: ignore[union-attr]  # a value an earlier check or lookup ruled out as None; mypy cannot follow it
                            + "; ".join(why))
            elif tail > 0:
                R.warn("W-AUDIT-UNANCHORED-TAIL", w, f"{tail} line(s) after the last audit_anchor (seq {last_anchor}) are not yet anchored")
            run_log_state(R, c, w, rid, run, evs)  # type: ignore[arg-type]  # a value an earlier check or lookup ruled out as None; mypy cannot follow it
            logged = {(e.get("payload") or {}).get("gate_record_id") for e in evs if e.get("event_type") == "gate_decision"}
            for g in c.ix.gate_records(rid):
                R.check(g.data.get("gate_record_id") in logged, "E-AUDIT-GATE", w, f"{g.data.get('gate_record_id')} has no gate_decision event")
            job_audit(R, c, w, rid, run, evs)  # type: ignore[arg-type]  # a value an earlier check or lookup ruled out as None; mypy cannot follow it
            run_structure(R, c, w, rid, run, evs)  # type: ignore[arg-type]  # a value an earlier check or lookup ruled out as None; mypy cannot follow it
            ownership_events(R, c, w, rid, run, evs)  # type: ignore[arg-type]  # a value an earlier check or lookup ruled out as None; mypy cannot follow it
            target_activity_windows(R, c, w, rid, evs)
            report_events(R, c, rid, evs)


    # a log the strict loader rejected has no anchors to count: its load error is the only report (no cascade)
    for p in ([] if c.broken_audit_runs else anchor_counter_problems(counters)):
        R.error("E-AUDIT-ANCHOR-GAP", "audit logs of the engagement", p)

    # v0.5 (review 2026-10-25, group 3): every verdict version has a verdict_changed event in its cluster's run log
    # (E-AUDIT-VERDICT above checks the events that exist; this makes the event itself required).
    # v0.7 (review r9 verdict): the event is in the anchored part of the log; an unanchored line is no evidence
    # (docs/03 §13.1), and v0.6 took a verdict_changed appended after the last anchor as the cluster's verdict
    for v in c.docs("verdict"):
        cl = c.ix.first("cluster", cluster_id=v.data.get("cluster_id"))
        rid = (cl.data if cl else {}).get("run_id")
        if rid in c.broken_audit_runs:
            continue
        audit = c.ix.audit_for(rid)
        evs = audit.data if audit is not None else []
        seqs = [i + 1 for i, e in enumerate(evs) if isinstance(e, dict) and e.get("event_type") == "verdict_changed"
                and (e.get("payload") or {}).get("verdict_id") == v.data.get("verdict_id")]
        if R.check(bool(seqs), "E-AUDIT-VERDICT", v.path,
                   f"verdict {v.data.get('verdict_id')} has no verdict_changed event in the audit log of run {rid}"):
            R.check(min(seqs) <= anchored_seqs(evs), "E-AUDIT-VERDICT", v.path,
                    f"verdict {v.data.get('verdict_id')}: its verdict_changed (seq {min(seqs)}) is after the last audit_anchor "
                    f"(seq {anchored_seqs(evs)}): an unanchored line is no evidence, so this is not yet a verdict")

    audited = {d.data[0].get("run_id") for d in c.ix.audit_docs() if d.data}
    for rid, run in c.runs.items():
        if rid in audited:
            continue
        if rid in c.broken_audit_runs:
            # the log exists but the strict loader rejected it: the load error (E-JSON-STRICT in
            # group 1) is the only report for this run's audit group; no cascade
            continue
        where = f"run {rid}"
        R.check(not run.get("audit_anchors"), "E-AUDIT-TRUNCATED", where, "run.audit_anchors names lines of an audit log that is missing")
        R.check(run.get("status") not in TERMINAL_RUN_STATES, "E-AUDIT-TAIL", where,
                f"{run.get('status')} run has no audit log, so no final anchor covers its last line")
        # v0.5 (review 2026-10-25 H-1): every gate decision needs the Audit Writer's receive time. Without a log the
        # receive-time rules (key validity and revocation, ROE validity, timeouts, EXPIRED-EARLY, G5 window) could only
        # fall back to the approver's self-declared timestamp, so a run with gate records must have its audit log
        for g in c.ix.gate_records(rid):
            R.check(False, "E-AUDIT-GATE", where,
                    f"{g.data.get('gate_record_id')} ({g.data.get('gate')}) has no gate_decision event: the run has no audit "
                    "log, so its receive time cannot be established")


def report_events(R: Report, c: Ctx, rid, evs: list):
    """v0.7 (review r10 manifest): a report manifest is a report only through the anchored report_published that pins
    it. v0.7 r9 checked the event against the first manifest of the run, so a second manifest (or one for a run that
    never published) with arbitrary SARIF / HTML hashes and a shorter report queue was accepted. With E-ID-DUP's one
    manifest per run, every manifest needs exactly one report_published naming its report_id, inside the anchored part
    of the log, whose report_manifest_sha256 is the manifest's content hash."""
    last = anchored_seqs(evs)
    for rm in c.docs("report-manifest"):
        if rm.data.get("run_id") != rid:
            continue
        rep = rm.data.get("report_id")
        pubs = [(i + 1, e.get("payload") or {}) for i, e in enumerate(evs) if isinstance(e, dict)
                and e.get("event_type") == "report_published" and (e.get("payload") or {}).get("report_id") == rep]
        if not R.check(len(pubs) == 1, "E-AUDIT-REPORT", rm.path,
                       f"report {rep}: the audit log of {rid} has {len(pubs)} report_published events naming it; a report "
                       "manifest is published by exactly one anchored report_published"):
            continue
        seq, p = pubs[0]
        R.check(seq <= last, "E-AUDIT-REPORT", rm.path,
                f"report {rep}: its report_published (seq {seq}) is after the last audit_anchor (seq {last}); "
                "an unanchored line is no evidence, so the report is not published yet")
        R.check(p.get("report_manifest_sha256") == content_hash(rm.data), "E-AUDIT-REPORT", rm.path,
                f"report {rep}: report_published (seq {seq}) pins {p.get('report_manifest_sha256')!r}, "
                f"but the manifest hashes to {content_hash(rm.data)}")


def ownership_events(R: Report, c: Ctx, w: str, rid, run: dict, evs: list):
    """v0.7 (review r10 ownership; docs/02 B0, 08 §11.9): every run.ownership_results entry is backed by the Z3
    executor's anchored ownership_check event of the same batch, which lists the target with the same method and
    outcome. checked_at is not later than the event's receive time, and the event is received before the first B4 job
    against that target starts. v0.7 r9 compared the results with the ROE only, so a batch no event names, dated after
    every job, passed."""
    last = anchored_seqs(evs)
    checks_ = [(i + 1, e) for i, e in enumerate(evs) if isinstance(e, dict) and e.get("event_type") == "ownership_check"]
    first_job: dict = {}
    jobs = run.get("jobs") or {}
    resumes = [i for i, e in enumerate(evs) if isinstance(e, dict) and e.get("event_type") == "run_resume"]
    for i, e in enumerate(evs):
        if isinstance(e, dict) and e.get("event_type") == "sandbox_job_start" and (e.get("node") in B_NODES or e.get("zone") == "Z3"):
            job = jobs.get((e.get("payload") or {}).get("job_id"))
            tc = c.ix.first("testcase", testcase_id=job.get("testcase_id")) if isinstance(job, dict) else None
            for tid in (tc.data if tc else {}).get("target_ids") or []:
                first_job.setdefault(tid, e)
                # r14 (internal review A7; docs/03 §5.6): a resume in the B phase re-checks ownership before the next job
                # against each target; r10-r13 only tied the FIRST job per target to a check
                since = max((r for r in resumes if r < i), default=None)
                if since is not None:
                    later = [x for k, x in checks_ if since < k - 1 < i and any(isinstance(r, dict) and r.get("target_id") == tid and r.get("ok") is True
                                                                                  for r in (x.get("payload") or {}).get("results") or [])]
                    R.check(bool(later), "E-RUN-OWNERSHIP", f"{w} seq {e.get('seq')}",
                            f"{tid}: job {(e.get('payload') or {}).get('job_id')} runs after the resume at seq {evs[since].get('seq')} "
                            "without a new ok ownership_check for the target (every B-phase resume re-verifies ownership, docs/03 §5.6)")
    for o in run.get("ownership_results") or []:
        if not isinstance(o, dict):
            continue
        tid = o.get("target_id")
        evs_ = [(seq, e) for seq, e in checks_ if (e.get("payload") or {}).get("batch_id") == o.get("batch_id")]
        if not R.check(len(evs_) == 1 and evs_[0][0] <= last, "E-RUN-OWNERSHIP", w,
                       f"{tid}: batch {o.get('batch_id')!r} needs exactly one anchored ownership_check event "
                       f"(the Z3 executor's record of the check); the log has {len(evs_)}"
                       + ("" if not evs_ or evs_[0][0] <= last else ", in the unanchored tail")):
            continue
        seq, ev = evs_[0]
        listed = [r for r in (ev.get("payload") or {}).get("results") or [] if isinstance(r, dict) and r.get("target_id") == tid]
        R.check(len(listed) == 1 and listed[0].get("method") == o.get("method") and listed[0].get("ok") is o.get("ok"),
                "E-RUN-OWNERSHIP", w, f"{tid}: the ownership_check event (seq {seq}) lists {listed}, but run.ownership_results "
                f"says method {o.get('method')!r}, ok {o.get('ok')!r}")
        at, recv = ts(R, o.get("checked_at"), w), ts(R, ev.get("ts"), w)
        R.check(at is not None and recv is not None and at <= recv + MAX_CLOCK_SKEW, "E-RUN-OWNERSHIP", w,
                f"{tid}: checked_at {o.get('checked_at')} is after the ownership_check event was received ({ev.get('ts')})")
        job = first_job.get(tid)
        if job is not None:
            start = ts(R, job.get("ts"), w)
            R.check(recv is not None and start is not None and recv <= start, "E-RUN-OWNERSHIP", w,
                    f"{tid}: ownership was checked at {ev.get('ts')}, after the first B4 job against it started "
                    f"(seq {job.get('seq')}, {job.get('ts')}); B4_preflight checks before the job")


def run_log_state(R: Report, c: Ctx, w: str, rid, run: dict, evs: list):
    """v0.7 (review r9): what the run record says about itself is checked against the log.

    E-RUN-STATUS: run.status is the `to` of the last run_status_changed (RUNNING before the first one); a completed run
    wrote its terminal status change before its run_end anchor, so it cannot be marked RUNNING again. v0.6 decided "terminal" from the unsigned run record alone, so a completed
    run marked RUNNING again accepted new unanchored lines after its run_end anchor.
    E-RUN-COMMIT: the anchored run_created event pins the commit the run tests; the run record and the run's W0
    inventory name the same commit (the build check, E-RESULT-BUILD, compares observed builds with it).
    E-AUDIT-ARTIFACT: the anchored artifact_stored event of the seed threats pins their content hash; v0.6 read the seed
    document's unsigned run_id, so moving it to another run switched off the run's pipeline checks."""
    changes = [(e.get("payload") or {}).get("to") for e in evs if isinstance(e, dict) and e.get("event_type") == "run_status_changed"]
    want = changes[-1] if changes else "RUNNING"
    R.check(run.get("status") == want, "E-RUN-STATUS", f"run {rid}",
            f"run.status {run.get('status')!r} but the last run_status_changed of the log moves the run to {want!r}")
    last = anchored_seqs(evs)
    created = [(i + 1, e) for i, e in enumerate(evs) if isinstance(e, dict) and e.get("event_type") == "run_created"]
    pinned = (created[0][1].get("payload") or {}).get("repo_commit") if created and created[0][0] <= last else None
    if R.check(len(created) == 1 and created[0][0] <= last, "E-RUN-COMMIT", f"run {rid}",
               "the log needs exactly one anchored run_created event (it pins the commit the run tests)"):
        R.check(run.get("repo_commit") == pinned, "E-RUN-COMMIT", f"run {rid}",
                f"run.repo_commit {run.get('repo_commit')!r} != {pinned!r} pinned by the anchored run_created event")
        for inv in c.docs("inventory"):
            if inv.data.get("run_id") == rid:
                R.check(inv.data.get("repo_commit") == pinned, "E-RUN-COMMIT", inv.path,
                        f"the W0 inventory names commit {inv.data.get('repo_commit')!r}, but the run tests {pinned!r}")
        # review r12: run_kind selects rule semantics (R14 FIXED only in a regression run, Lane A exemptions, reuse) and
        # trigger the Lane A / scheduled rules; the anchored run_created pins both, as it pins the commit
        payload = created[0][1].get("payload") or {}
        # r14 (internal review A9): baseline_run_id decides every cluster's baseline_state (SARIF baselineState), so it is
        # pinned by run_created too; run_manifest checks what it may point at (E-RUN-BASELINE)
        for k in ("run_kind", "trigger", "baseline_run_id"):
            R.check(run.get(k) == payload.get(k), "E-RUN-COMMIT", f"run {rid}",
                    f"run.{k} {run.get(k)!r} != {payload.get(k)!r} pinned by the anchored run_created event")
    # review r12 (BL-43): the key registry a run loaded is an anchored fact; a bundle carrying an older registry version
    # than any run loaded is a rollback (a registry revoking a key can be swapped for the root-signed one before it)
    reg_v = c.registry.get("version") if isinstance(c.registry, dict) else None
    for i, e in enumerate(evs):
        if isinstance(e, dict) and e.get("event_type") == "key_registry_loaded" and i + 1 <= last:
            v = (e.get("payload") or {}).get("version")
            R.check(type(v) is int and type(reg_v) is int and reg_v >= v, "E-KR-ROLLBACK", f"{w} seq {e.get('seq')}",
                    f"run {rid} loaded key registry version {v!r}, but the bundle's registry is version {reg_v!r} (older: a rollback)")
    artifact_pins(R, c, w, rid, run, evs, last)
    run_transitions(R, c, w, rid, run, evs, last)


PINNED_ARTIFACTS = ("seed-threats", "inventory", "redaction-map", "dfd-merged", "dfd-external", "commander-plan")


def pinned_documents(c: Ctx, rid, run: dict) -> list[tuple[str, str | None, Doc]]:
    """(artifact, plan_id, document) of every W / B-phase artefact of a run that an anchored artifact_stored event must
    pin (review r11): the seed threats (r9), the W0 inventory and redaction map, the merged and external DFD and every
    commander plan the run lists. Their content hashes also sit in the unsigned run record (derive), which only Z1
    write access could rewrite together with the documents; the anchored event is what a completed run cannot lose."""
    out = []
    for d in c.docs("seed-threats"):
        if d.data.get("run_id") == rid:
            out.append(("seed-threats", None, d))
    for kind, name in (("inventory", "inventory"), ("redaction-map", "redaction-map")):
        for d in c.docs(kind):
            if d.data.get("run_id") == rid:
                out.append((name, None, d))
    for d in c.docs("dfd"):
        if d.data.get("run_id") == rid and d.data.get("viewpoint") in ("merged", "external"):
            out.append((f"dfd-{d.data['viewpoint']}", None, d))
    for d in c.docs("commander-plan"):
        if d.data.get("plan_id") in (run.get("plan_ids") or []):
            out.append(("commander-plan", d.data.get("plan_id"), d))
    return out  # type: ignore[return-value]  # the list was built untyped above


def artifact_pins(R: Report, c: Ctx, w: str, rid, run: dict, evs: list, last: int):
    """E-AUDIT-ARTIFACT (r9 for the seed threats; r11 for the other W / B-phase artefacts): every pinned document of the
    run has exactly one anchored artifact_stored event whose sha256 is its content hash, and every artifact_stored event
    names a document of the run that hashes to what it says. v0.7 pinned only the seed threats, so a completed run's
    inventory (files, blind spots, env vars), DFD or commander plan could be rewritten with the report left intact."""
    docs = pinned_documents(c, rid, run)
    stored = [(i + 1, e) for i, e in enumerate(evs) if isinstance(e, dict) and e.get("event_type") == "artifact_stored"]
    for seq, e in stored:
        p = e.get("payload") or {}
        art, pid, sha = p.get("artifact"), p.get("plan_id"), p.get("sha256")
        if not R.check(art in PINNED_ARTIFACTS, "E-AUDIT-ARTIFACT", f"{w} seq {seq}",
                       f"artifact_stored names {art!r}; the pinned artefacts are {', '.join(PINNED_ARTIFACTS)}"):
            continue
        match = [d for a, q, d in docs if a == art and (art != "commander-plan" or q == pid)]
        R.check(seq <= last and len(match) == 1 and content_hash(match[0].data) == sha, "E-AUDIT-ARTIFACT", f"{w} seq {seq}",
                f"artifact_stored pins {art}{' ' + str(pid) if pid else ''} as {sha!r}, but run {rid} has {len(match)} such document(s)"
                + (f" hashing to {content_hash(match[0].data)}" if len(match) == 1 else "")
                + ("" if seq <= last else "; and the event is not anchored"))
    for art, pid, d in docs:
        pins = [seq for seq, e in stored if (e.get("payload") or {}).get("artifact") == art
                and (art != "commander-plan" or (e.get("payload") or {}).get("plan_id") == pid) and seq <= last]
        R.check(len(pins) == 1, "E-AUDIT-ARTIFACT", d.path,
                f"the {art}{' ' + str(pid) if pid else ''} of run {rid} needs exactly one anchored artifact_stored event pinning it, found {len(pins)}")


RESUMABLE_RUN_STATES = ("SUSPENDED", "STOPPED")
# Third external review (r13; docs/02 §1.4, docs/03 §5.2): the legal run status transitions. A terminal state has no
# exit; SUSPENDED / STOPPED leave only by a resume (E-RUN-RESUME) or the expiry cleanup; WAITING_GATE waits for a
# gate (it cannot complete by itself). r11 only checked that each `from` matched the previous `to`, so
# RUNNING -> ABORTED -> RUNNING followed by the rest of the B phase validated.
RUN_TRANSITIONS = {
    "RUNNING": ("WAITING_GATE", "SUSPENDED", "STOPPED", "ABORTED", "FAILED", "COMPLETED", "COMPLETED_WITH_GAPS"),
    "WAITING_GATE": ("RUNNING", "SUSPENDED", "STOPPED", "ABORTED", "FAILED"),
    "SUSPENDED": ("RUNNING", "COMPLETED_WITH_GAPS", "FAILED"),
    "STOPPED": ("RUNNING", "COMPLETED_WITH_GAPS", "FAILED"),
    "ABORTED": (), "FAILED": (), "COMPLETED": (), "COMPLETED_WITH_GAPS": (),
}
WORK_EVENTS = ("sandbox_job_start", "tool_invocation_start")        # work only happens while the run is RUNNING
GATE_STATES = ("RUNNING", "WAITING_GATE")                            # gates are decided while RUNNING or WAITING_GATE


def run_transitions(R: Report, c: Ctx, w: str, rid, run: dict, evs: list, last: int):
    """E-RUN-STATUS / E-RUN-RESUME (review r11): the run's status changes form a chain (each `from` is the previous
    `to`, RUNNING at first) along the legal transitions (RUN_TRANSITIONS, third external review: a terminal state is
    never left, and work events only happen while the run is RUNNING), and leaving SUSPENDED / STOPPED needs a human's
    anchored, signed run_resume after the status change that entered it (docs/03 §5.6: the run_owner or an initiator
    for SUSPENDED, the test lead for STOPPED; the signer's role is checked with the signature, E-SIG-ROLE /
    E-AUDIT-ACTOR), received before the engagement's validity ends (docs/02 §1.4), and the first B-phase event after it
    follows a fresh VERIFIED G0b decision (every resume re-verifies the ROE). Leaving WAITING_GATE for RUNNING needs a
    gate_decision in between. v0.7 accepted any run_status_changed line, so one unanchored system event resumed a
    suspended run with nobody's signature."""
    e_val = (c.engagement.get("validity") or {}).get("not_after") if isinstance(c.engagement, dict) else None
    not_after = ts(R, e_val, w) if isinstance(e_val, str) else None
    prev, prev_i = "RUNNING", 0
    rows = [(i + 1, e) for i, e in enumerate(evs) if isinstance(e, dict)]
    for i, e in rows:
        if prev in TERMINAL_RUN_STATES and e.get("event_type") != "audit_anchor":
            # r14 (internal review A8): after the terminal status only the run_end anchor follows; r13 stopped work events
            # and gate decisions, so verdicts, Commander drafts and report_published were still written after COMPLETED
            R.check(False, "E-RUN-STATUS", f"{w} seq {e.get('seq')}",
                    f"{e.get('event_type')} after the run became {prev}: a terminal status is followed only by the run_end anchor")
        if e.get("event_type") in WORK_EVENTS:
            R.check(prev == "RUNNING", "E-RUN-STATUS", f"{w} seq {e.get('seq')}",
                    f"{e.get('event_type')} while the run is {prev}: work only happens while the run is RUNNING (docs/02 §1.4)")
        if e.get("event_type") == "gate_decision":
            R.check(prev in GATE_STATES, "E-RUN-STATUS", f"{w} seq {e.get('seq')}",
                    f"gate_decision while the run is {prev}: a gate is decided while the run is RUNNING or WAITING_GATE (docs/02 §1.4)")
        if e.get("event_type") != "run_status_changed":
            continue
        p = e.get("payload") or {}
        where = f"{w} seq {e.get('seq')}"
        R.check(p.get("from") == prev, "E-RUN-STATUS", where,
                f"run_status_changed from {p.get('from')!r}, but the run was {prev!r} (the previous change or RUNNING)")
        R.check(p.get("to") in RUN_TRANSITIONS.get(prev, ()), "E-RUN-STATUS", where,
                f"run_status_changed {prev} -> {p.get('to')!r} is not a legal transition (docs/02 §1.4: {prev} may only go to "
                f"{list(RUN_TRANSITIONS.get(prev, ())) or 'nothing, it is terminal'})")
        between = [(j, x) for j, x in rows if prev_i < j < i]
        expired = [(j, x) for j, x in between if x.get("event_type") == "resume_expired"
                   and (x.get("actor") or {}).get("kind") == "system" and (x.get("payload") or {}).get("from_status") == prev]
        if prev in RESUMABLE_RUN_STATES and p.get("to") == "COMPLETED_WITH_GAPS" and expired:
            # review r12 (docs/03 §5.2): a SUSPENDED / STOPPED run nobody resumed before the engagement validity ended is
            # closed by the system: an anchored resume_expired, then the change to COMPLETED_WITH_GAPS (gap kind expired,
            # E-RUN-GAPS). r11 demanded a signed run_resume received before not_after for every exit, so the cleanup the
            # docs describe could not be written at all
            j, x = expired[-1]
            R.check(j <= last, "E-RUN-RESUME", f"{w} seq {x.get('seq')}", "the resume_expired is not anchored")
            for y in (x, e):
                at = ts(R, y.get("ts"), where)
                R.check(not_after is not None and at is not None and at > not_after, "E-RUN-RESUME", f"{w} seq {y.get('seq')}",
                        f"{y.get('event_type')} at {y.get('ts')}, but the engagement validity ends {e_val}: "
                        "a run is closed as expired only after its validity ended")
        elif prev in RESUMABLE_RUN_STATES:
            resumes = [(j, x) for j, x in between if x.get("event_type") == "run_resume" and (x.get("actor") or {}).get("kind") == "human"
                       and isinstance(x.get("signature"), dict) and (x.get("payload") or {}).get("from_status") == prev]
            if R.check(bool(resumes), "E-RUN-RESUME", where,
                       f"leaving {prev} needs a human's signed run_resume (from_status {prev}) after the change that entered it"):
                j, x = resumes[-1]
                R.check(j <= last, "E-RUN-RESUME", f"{w} seq {x.get('seq')}", "the run_resume is not anchored")
                at = ts(R, x.get("ts"), where)
                R.check(not_after is None or (at is not None and at <= not_after), "E-RUN-RESUME", f"{w} seq {x.get('seq')}",
                        f"run_resume received at {x.get('ts')}, after the engagement validity ended ({e_val})")
                after = [(k, y) for k, y in rows if k > j]
                # r14 (internal review A7; docs/02 §1.6, 03 §5.2 run_resume -> G0a_engagement_check): every resume re-verifies
                # the engagement before anything else happens; r11-r13 asked only for a fresh G0b before the B phase
                for k, y in after:
                    yp = y.get("payload") or {}
                    if y.get("event_type") == "gate_decision" and yp.get("gate") == "G0a":
                        R.check(yp.get("outcome") == "VERIFIED", "E-RUN-RESUME", f"{w} seq {y.get('seq')}",
                                f"the G0a re-verification after the resume at seq {x.get('seq')} is {yp.get('outcome')}")
                        break
                    if y.get("event_type") in WORK_EVENTS + ("gate_decision", "verdict_changed", "ownership_check") or y.get("node") in B_NODES:
                        R.check(False, "E-RUN-RESUME", f"{w} seq {y.get('seq')}",
                                f"{y.get('event_type')} after the resume at seq {x.get('seq')} without a new VERIFIED G0a first (every resume re-verifies the engagement)")
                        break
                for k, y in after:
                    yp = y.get("payload") or {}
                    if y.get("event_type") == "gate_decision" and yp.get("gate") == "G0b" and yp.get("outcome") == "VERIFIED":
                        break
                    if y.get("node") in B_NODES or (y.get("event_type") == "gate_decision" and yp.get("gate") in ("G3", "G4", "G5")) \
                            or y.get("event_type") in ("sandbox_job_start", "sandbox_job_end") and y.get("node") not in ("W0", "W1", "W4"):
                        R.check(False, "E-RUN-RESUME", f"{w} seq {y.get('seq')}",
                                f"B-phase event {y.get('event_type')} after the resume at seq {x.get('seq')} without a new VERIFIED G0b (every resume re-verifies the ROE)")
                        break
        if prev == "WAITING_GATE" and p.get("to") == "RUNNING":
            R.check(any(x.get("event_type") == "gate_decision" for _, x in between), "E-RUN-STATUS", where,
                    "WAITING_GATE -> RUNNING without a gate_decision in between: the gate the run waited for was never decided")
        prev, prev_i = p.get("to"), i  # type: ignore[assignment]  # the name is reused with another type earlier in the function


SPOT_CHECK_KINDS = ("g1", "g2", "g3", "g4", "g5")
# v0.7 (review r9): docs/06 §1.1's population also holds verdicts (CONFIRMED_*), clusters (auto-rejected, report-only,
# over-cap, G2-timed-out) and suppressed items (feedback records)
SPOT_CHECK_ITEMS = ("verdict", "cluster", "feedback")


def spot_check(R: Report, c: Ctx, where: str, run: dict, ev: dict):
    """v0.7 (review r8 M2; docs/06 §1.1 ASI09, 07 M2-X7): a spot_check_result is an independent re-review of a gate
    decision: its actor is a registered security_reviewer, its item is a gate record of the same engagement, and the
    reviewer neither approved that record nor initiated its run. v0.6 only required a human signature, so a G5 approver
    could 'confirm' their own approvals and the result still drove g5_escalation."""
    actor, p = ev.get("actor") or {}, ev.get("payload") or {}
    who = actor.get("id")
    R.check(actor.get("kind") == "human" and "security_reviewer" in c.roles_of(who), "E-SPOT-CHECK", where,
            f"spot_check_result actor {who!r} must be a registered security_reviewer")
    # v0.7 (review r9): Lite has one person, who approved everything; a spot check there would be self-review
    if not R.check(profile(c) != "lite", "E-SPOT-CHECK", where,
                   "a lite engagement records no spot check: its one person cannot re-review their own decisions (docs/06 §1.1)"):
        return
    kind = p.get("item_kind")
    if not R.check(kind in SPOT_CHECK_KINDS + SPOT_CHECK_ITEMS, "E-SPOT-CHECK", where,
                   f"item_kind {kind!r} must name a gate ({', '.join(SPOT_CHECK_KINDS)}) or an item ({', '.join(SPOT_CHECK_ITEMS)})"):
        return
    if kind in SPOT_CHECK_ITEMS:
        spot_check_item(R, c, where, run, who, kind, p.get("item_id"))
        return
    rec = c.record(p.get("item_id"))
    if not R.check(rec is not None and rec.get("gate", "").lower() == kind
                   and rec.get("engagement_id") == run.get("engagement_id"), "E-SPOT-CHECK", where,
                   f"item_id {p.get('item_id')!r} is not a {kind.upper()} gate record of this engagement"):  # type: ignore[union-attr]  # a value an earlier check or lookup ruled out as None; mypy cannot follow it
        return
    approvers = {a.get("person_id") for a in rec.get("approvers") or [] if isinstance(a, dict)}
    initiators = set((c.runs.get(rec.get("run_id")) or {}).get("initiators") or []) | {rec.get("initiator")}
    R.check(who not in approvers and who not in initiators, "E-SPOT-CHECK", where,
            f"{who} approved or initiated {p.get('item_id')}: the spot check must be independent (docs/06 §1.1)")


def spot_check_item(R: Report, c: Ctx, where: str, run: dict, who, kind: str, item_id):
    """v0.7 (review r9): a spot check of a verdict, cluster or feedback record. The item exists in this engagement, and the
    reviewer neither initiated its run, approved the G2 decision on its cluster, nor signed the feedback."""
    if kind == "verdict":
        v = c.ix.first("verdict", verdict_id=item_id)
        cid = v.data.get("cluster_id") if v else None
    elif kind == "feedback":
        f = c.ix.first("feedback", feedback_id=item_id)
        cid = f.data.get("cluster_id") if f else None
        signers = {(f.data.get(k) or {}).get("person_id") for k in ("signed_by", "co_signed_by")} if f else set()
    else:
        cid = item_id
    cl = c.ix.first("cluster", cluster_id=cid) if cid else None
    if not R.check(cl is not None and (c.runs.get(cl.data.get("run_id")) or {}).get("engagement_id") == run.get("engagement_id"),
                   "E-SPOT-CHECK", where, f"item_id {item_id!r} is not a {kind} of this engagement"):
        return
    involved = set((c.runs.get(cl.data.get("run_id")) or {}).get("initiators") or [])  # type: ignore[union-attr]  # a value an earlier check or lookup ruled out as None; mypy cannot follow it
    for g in c.ix.gate_records(cl.data.get("run_id"), "G2"):  # type: ignore[union-attr]  # a value an earlier check or lookup ruled out as None; mypy cannot follow it
        if any(x.get("item_id") == cid for x in g.data.get("decisions") or []):
            involved |= {a.get("person_id") for a in g.data.get("approvers") or [] if isinstance(a, dict)}
    if kind == "feedback":
        involved |= signers
    R.check(who not in involved, "E-SPOT-CHECK", where,
            f"{who} initiated, decided at G2 or signed {item_id}: the spot check must be independent (docs/06 §1.1)")


def job_audit(R: Report, c: Ctx, w: str, rid, run: dict, evs: list):
    """v0.5 (review 2026-10-25 V-9, E-JOB-AUDIT): the B4 jobs of run.jobs agree with the sandbox_job_* events of the log
    and with the testresults. v0.4 never reconciled them, so deleting a FAIL result and marking its job SKIPPED passed.
    W0 / W1 / W4 sandbox jobs are not in run.jobs and are not reconciled here."""
    jobs = run.get("jobs") or {}
    started = {(e.get("payload") or {}).get("job_id") for e in evs if isinstance(e, dict) and e.get("event_type") == "sandbox_job_start"}
    ended = {(e.get("payload") or {}).get("job_id"): (e.get("payload") or {}).get("outcome")
             for e in evs if isinstance(e, dict) and e.get("event_type") == "sandbox_job_end"}
    results: dict[str, list] = {}
    for r in c.docs("testresult"):
        if r.data.get("run_id") == rid and r.data.get("phase") == "B4":
            results.setdefault(r.data.get("job_id"), []).append(r.data)
    for jid, job in jobs.items():
        if not isinstance(job, dict):
            continue
        where = f"{w} (run.jobs {jid})"
        if job.get("status") == "SKIPPED":
            R.check(jid not in started and jid not in ended, "E-JOB-AUDIT", where,
                    f"job {jid} is SKIPPED but the audit log has sandbox_job events for it (it ran)")
        elif job.get("status") in JOB_RAN_STATES:
            R.check(jid in ended, "E-JOB-AUDIT", where, f"job {jid} is {job.get('status')} but the audit log has no sandbox_job_end for it")
            R.check(bool(results.get(jid)), "E-JOB-AUDIT", where, f"job {jid} is {job.get('status')} but no testresult names it")
        # v0.7 (review r8 F2a): a job in any other state (PENDING, EXECUTING, INTERRUPTED, STOPPED, ...) never finished; a
        # result naming it is rejected below ("never executed"). v0.6 reconciled only SKIPPED and the ran states.
        # r14 (internal review A3): a completed run has no job still waiting or executing (a job the run stopped is a gap,
        # expected_gaps); r12 let a G4-approved job sit PENDING with no events, no result and no gap in a COMPLETED run
        if run.get("status") in COMPLETED_RUN_STATES:
            R.check(job.get("status") not in ("PENDING", "SNAPSHOTTED", "EXECUTING"), "E-JOB-AUDIT", where,
                    f"job {jid} is {job.get('status')} in a {run.get('status')} run: a completed run has executed, stopped or "
                    "SKIPPED (with a reason) every job")
    for jid, trs in results.items():
        # v0.7 (review r8 F2a / F2b): every B4 result, not only the last one named for a job, is reconciled with the
        # executor's events: one result per job, a job that ran, and exactly one anchored sandbox_job_end whose
        # outcome and pins (testcase, artifact, result hashes) are this result's
        where = f"{w} (run.jobs {jid})"
        R.check(len(trs) == 1, "E-JOB-AUDIT", where,
                f"job {jid} has {len(trs)} testresults {[t.get('result_id') for t in trs]}: one job executes one result")
        job = jobs.get(jid)
        R.check(isinstance(job, dict) and job.get("status") in JOB_RAN_STATES, "E-JOB-AUDIT", where,
                f"testresult {[t.get('result_id') for t in trs]} names job {jid}, which is "
                f"{job.get('status') if isinstance(job, dict) else 'not in run.jobs'} (it never executed)")
        for tr in trs:
            end = derive.pinned_job_end(c.ix, tr)
            if end is not None:
                continue
            ends = [e for e in evs if derive.job_end_of(e, tr)]
            tc = c.ix.testcase_for(tr)
            if len(ends) == 1 and tc is not None:
                e, p = ends[0], ends[0].get("payload") or {}
                R.check(p.get("outcome") == tr.get("outcome"), "E-JOB-AUDIT", where,
                        f"testresult {tr.get('result_id')} outcome {tr.get('outcome')} != sandbox_job_end outcome {p.get('outcome')}")
                for key, want in derive.execution_pins(tc.data, tr).items():
                    R.check(p.get(key) == want, "E-JOB-AUDIT", where,
                            f"sandbox_job_end (seq {e.get('seq')}) pins {key} {p.get(key)!r}, but the bundle's "
                            f"testcase / result hash to {want!r}: changed after the run")
                R.check(False, "E-JOB-AUDIT", where,
                        f"testresult {tr.get('result_id')}: its sandbox_job_end (seq {e.get('seq')}) is not in the anchored part of the log")
            else:
                R.check(False, "E-JOB-AUDIT", where,
                        f"testresult {tr.get('result_id')} has {len(ends)} sandbox_job_end events for job {jid} (exactly one anchored event "
                        "must pin the testcase, artifact and result it executed)")
    for jid in ended:
        if jid in jobs:
            R.check(jid in results, "E-JOB-AUDIT", w, f"sandbox_job_end for job {jid} has no testresult")
    # v0.7 (review r9 jobs): every B-phase sandbox_job event names a job of run.jobs (W0 / W1 / W4 jobs are not in it), and a
    # completed run has a job, executed or SKIPPED with its reason, for every testcase G4 approved. v0.6 ignored an anchored
    # sandbox_job_end whose job had been dropped from run.jobs together with its FAIL result
    # r14 (internal review A1): the node label is the executor's claim; the zone says where the job ran. A Z3 job is a B4
    # job of run.jobs whatever its node says, and a W0 / W1 / W4 job runs in Z2. r9-r13 selected B-phase jobs by node
    # only, so a Z3 job labelled W1 (or G4, END, ...) escaped run.jobs, G0b / G4 / G5, the windows and the ownership rule
    for e in evs:
        if not (isinstance(e, dict) and e.get("event_type") in ("sandbox_job_start", "sandbox_job_end")):
            continue
        where = f"{w} seq {e.get('seq')}"
        jid = (e.get("payload") or {}).get("job_id")
        if e.get("zone") == "Z3":
            R.check(e.get("node") == "B4", "E-JOB-AUDIT", where,
                    f"{e.get('event_type')} in zone Z3 at node {e.get('node')!r}: a target-facing job is a B4 job (docs/03 §5.5)")
            R.check(jid in jobs, "E-JOB-AUDIT", where, f"{e.get('event_type')} names job {jid}, which is not in run.jobs")
        elif e.get("node") in B_NODES:
            R.check(False, "E-JOB-AUDIT", where, f"{e.get('event_type')} at node {e.get('node')} runs in zone Z3, not {e.get('zone')!r}")
        else:
            R.check(e.get("node") in ("W0", "W1", "W4") and e.get("zone") == "Z2", "E-JOB-AUDIT", where,
                    f"{e.get('event_type')} at node {e.get('node')!r} in zone {e.get('zone')!r}: white-box jobs run in Z2 at W0 / W1 / W4")
    # v0.7 (review r10 W4): a W4 / Z2 sandbox_job_end names a W4 result of this run for its testcase (a W4 job that
    # ended without a result was silently dropped), and a completed run has an end for every W4 job it started
    w4_results = {r.data.get("result_id"): r.data for r in c.docs("testresult") if r.data.get("run_id") == rid and r.data.get("phase") == "W4"}
    w4_ended = set()
    for e in evs:
        if isinstance(e, dict) and e.get("node") == "W4" and e.get("event_type") == "sandbox_job_end":
            p = e.get("payload") or {}
            w4_ended.add(p.get("job_id"))
            tr = w4_results.get(p.get("result_id"))
            R.check(tr is not None and tr.get("testcase_id") == p.get("testcase_id"), "E-W4-AUDIT", f"{w} seq {e.get('seq')}",
                    f"W4 sandbox_job_end names result {p.get('result_id')!r} of testcase {p.get('testcase_id')!r}, "
                    "which is not a W4 result of this run")
    if run.get("status") in COMPLETED_RUN_STATES:
        for e in evs:
            if isinstance(e, dict) and e.get("node") == "W4" and e.get("event_type") == "sandbox_job_start":
                R.check((e.get("payload") or {}).get("job_id") in w4_ended, "E-W4-AUDIT", f"{w} seq {e.get('seq')}",
                        f"W4 job {(e.get('payload') or {}).get('job_id')!r} started but has no sandbox_job_end in the completed run")
    if run.get("status") in COMPLETED_RUN_STATES:
        have = {j.get("testcase_id") for j in jobs.values() if isinstance(j, dict)}
        for g4 in c.ix.gate_records(rid, "G4"):
            if g4.data.get("outcome") == "EXPIRED":
                continue
            for x in g4.data.get("decisions") or []:
                # BL-60: a MANUAL testcase is carried out by a person, not by a toolkit job (it is listed in the report's
                # untested list, docs/02 B6); the r9 rule asked a job of it, which the examples never exercised
                tc = c.ix.first("testcase", testcase_id=x.get("item_id"))
                if ((tc.data if tc else {}).get("tool_binding") or {}).get("kind") == "MANUAL":
                    continue
                if x.get("decision") == "accept":
                    R.check(x.get("item_id") in have, "E-JOB-AUDIT", w,
                            f"G4 approved testcase {x.get('item_id')} ({g4.data.get('gate_record_id')}), but run.jobs has no job for it")


B_NODES = ("B0", "B1", "B2", "B3", "B4", "B5", "B6")
GATE_ORDER = ("G0a", "G1", "G2", "G0b", "G3", "G4", "G5")        # docs/02 §1.3: first decision of each gate in this order
W_GATED_NODES = ("W4",)                                          # nodes that need the G2 decisions and the human claim
# Third external review (r13; docs/02 §1.4 G1 "進入 W1", docs/03 §5.3): the white-box phase runs G1 -> W1 -> W2 / W3 -> (G2)
# -> W4 -> W5. Every event at these nodes needs an APPROVED G1 before it, and the nodes after W1 follow W1's first event
# (a re-dispatch back to W2 still follows W1). A Lane A run has no G1 (docs/02 §1.5). r8-r12 only ordered the gates
# among themselves and W4 after G2, so W1 scanned, or W3 adjudicated, before G1 approved the invariants.
G1_GATED_NODES = ("W1", "W2", "W3", "W4", "W5")
AFTER_W1_NODES = ("W2", "W3", "W4", "W5")


def run_structure(R: Report, c: Ctx, w: str, rid, run: dict, evs: list):
    """v0.7 (review r8 F1 / F3 / F4; docs/02 §1.3-§1.5): the shape of a run's audit log, judged by the Audit Writer's
    receive times (self-declared opened_at / timestamp values are not used):
    - the first decision of each gate follows the order G0a < G1 < G2 < G0b < G3 < G4 < G5 (E-GATE-ORDER);
    - every event after G0a's decision follows a VERIFIED G0a; every B-phase event (nodes B0-B6, the G3 / G4 / G5
      decisions, every job) follows a VERIFIED G0b with no later VERIFY_FAILED before it, so a run that reached the B
      phase has a VERIFIED G0b (E-GATE-ORDER; a job without events is E-JOB-AUDIT); W4 runs after the G2 decision and
      before G0b;
    - a Lane B run makes no G1 decision and enters W4 or the B phase only after a human's signed initiator_claim
      (E-RUN-CLAIM; docs/02 §1.5, docs/06 D7).
    v0.6 checked the order of a run's own gate_records by their self-declared opened_at and required nothing of G0b or the
    claim, so a log with no G0b, a VERIFY_FAILED G0b, G4 before G3, or no claim at all validated."""
    times = {}
    for e in evs:
        if isinstance(e, dict) and isinstance(e.get("ts"), str):
            try:
                times[id(e)] = timeutil.parse_dt(e["ts"])
            except (ValueError, TypeError):
                pass
    at = times.get
    decisions = {}  # type: ignore[var-annotated]  # gate -> [(time, outcome)] in log order
    for e in evs:
        p = (e.get("payload") or {}) if isinstance(e, dict) else {}
        if isinstance(e, dict) and e.get("event_type") == "gate_decision" and at(id(e)) is not None:
            decisions.setdefault(p.get("gate"), []).append((at(id(e)), p.get("outcome")))
    first = {g: min(t for t, _ in ds) for g, ds in decisions.items() if ds}
    prev = None
    for g in GATE_ORDER:
        if g in first:
            R.check(prev is None or first[g] > first[prev], "E-GATE-ORDER", w,
                    f"the first {g} decision ({first[g].isoformat()}) precedes the first {prev} decision ({first[prev].isoformat() if prev else None})")
            prev = g

    def last_before(gate, t):
        ds = [o for tt, o in decisions.get(gate, []) if tt < t]
        return ds[-1] if ds else None

    b_events, w4_events, g1_or_later = [], [], []
    lane_a = run.get("run_kind") == "lane_a"
    first_w1 = min((at(id(e)) for e in evs if isinstance(e, dict) and e.get("node") == "W1" and at(id(e)) is not None), default=None)  # type: ignore[type-var]  # the None values were filtered out above; mypy cannot follow it
    for e in evs:
        if not isinstance(e, dict) or at(id(e)) is None:
            continue
        t, node, et, p = at(id(e)), e.get("node"), e.get("event_type"), e.get("payload") or {}
        where = f"{w} seq {e.get('seq')}"
        if node in G1_GATED_NODES and not lane_a:
            R.check(last_before("G1", t) == "APPROVED", "E-GATE-ORDER", where,
                    f"event {et} at node {node} without an APPROVED G1 before it (last G1 decision: {last_before('G1', t)}): "
                    "the white-box phase starts after G1 approves the invariants (docs/02 §1.4)")
            if node in AFTER_W1_NODES:
                R.check(first_w1 is not None and first_w1 < t, "E-GATE-ORDER", where,  # type: ignore[operator]  # a value an earlier check or lookup ruled out as None; mypy cannot follow it
                        f"event {et} at node {node} before the first W1 event ({first_w1.isoformat() if first_w1 else None}): "
                        "W1 runs before W2-W5 (docs/03 §5.3)")
        if node in B_NODES or (et == "gate_decision" and p.get("gate") in ("G3", "G4", "G5")) or et in ("sandbox_job_start", "sandbox_job_end") \
                and (node not in ("W0", "W1", "W4") or e.get("zone") == "Z3"):          # r14 (A1): a Z3 job is B-phase whatever its label
            b_events.append(t)
            R.check(last_before("G0b", t) == "VERIFIED", "E-GATE-ORDER", where,
                    f"B-phase event {et} at node {node} without a VERIFIED G0b before it (last G0b decision: {last_before('G0b', t)})")
        if et == "gate_decision" and p.get("gate") in ("G0a", "G0b") and p.get("outcome") == "VERIFY_FAILED":
            # r14 (internal review A5; docs/02 §1.4): a failed verification ends the run (ABORTED; L-5 suspends it): the
            # next non-anchor line is the status change, nothing else happens first. r12 only asked that the LAST G0a /
            # G0b decision before an event was VERIFIED, so a VERIFY_FAILED followed by a VERIFIED one ran to COMPLETED
            later = [x for x in evs[evs.index(e) + 1:] if isinstance(x, dict) and x.get("event_type") not in
                     ("audit_anchor", "engagement_verify_failed", "roe_verify_failed", "signature_invalid")]
            nxt = later[0] if later else None
            R.check(nxt is not None and nxt.get("event_type") == "run_status_changed"
                    and (nxt.get("payload") or {}).get("to") in ("ABORTED", "SUSPENDED"), "E-GATE-ORDER", where,
                    f"{p.get('gate')} VERIFY_FAILED must be followed by run_status_changed to ABORTED (or SUSPENDED, docs/06 L-5), "
                    f"not by {nxt.get('event_type') if nxt else 'nothing'}")
        if node in W_GATED_NODES:
            w4_events.append(t)
        if node not in ("START", "G0a", "claim_run") and et not in ("run_created", "initiator_claim") and node is not None:
            R.check(last_before("G0a", t) == "VERIFIED", "E-GATE-ORDER", where,
                    f"event {et} at node {node} without a VERIFIED G0a before it (last G0a decision: {last_before('G0a', t)})")
        if et == "gate_decision" and p.get("gate") == "G1":
            g1_or_later.append(t)
    if w4_events:
        R.check("G2" not in first or min(w4_events) > first["G2"], "E-GATE-ORDER", w, "W4 ran before the G2 decision it depends on")  # type: ignore[type-var]  # the None values were filtered out above; mypy cannot follow it
        R.check("G0b" not in first or max(w4_events) < first["G0b"], "E-GATE-ORDER", w, "W4 ran after G0b: the white-box phase ends before the B phase")  # type: ignore[type-var]  # the None values were filtered out above; mypy cannot follow it
    if run.get("run_kind") != "lane_a":
        gated = g1_or_later + w4_events + b_events
        claims = [at(id(e)) for e in evs if isinstance(e, dict) and e.get("event_type") == "initiator_claim"
                  and (e.get("actor") or {}).get("kind") == "human" and at(id(e)) is not None]
        if gated:
            R.check(bool(claims) and min(claims) < min(gated), "E-RUN-CLAIM", w,  # type: ignore[operator,type-var]  # a value an earlier check or lookup ruled out as None; mypy cannot follow it
                    "no human initiator_claim before the first G1 decision / W4 / B-phase event: a person claims the run first (docs/02 §1.5)")
    # review r11: the other direction: run.initiators lists only people with an anchored, signed claim (v0.7 checked
    # that claimants are listed, so a G4 approver could be made an "initiator" without ever claiming the run)
    last = anchored_seqs(evs)
    claimed = {(e.get("actor") or {}).get("id") for i, e in enumerate(evs) if isinstance(e, dict) and e.get("event_type") == "initiator_claim"
               and (e.get("actor") or {}).get("kind") == "human" and isinstance(e.get("signature"), dict) and i + 1 <= last}
    for who in run.get("initiators") or []:
        R.check(who in claimed, "E-RUN-CLAIM", w, f"run.initiators lists {who!r}, who has no anchored signed initiator_claim in this run")


def audit_anchor_tail(R: Report, w: str, run: dict, d: Doc) -> tuple[int, int]:
    """Tail protection of the hash chain [H]. Returns (tail line count, seq of the last anchor event).

    run.audit_anchors = [{seq, line_sha256}] names audit_anchor lines by seq and by the sha256 of
    the raw line itself. It must name EVERY audit_anchor event of the log, in order (dropping an
    anchor from the run record is E-AUDIT-ANCHOR). The chain (prev_hash) protects every line up to
    the last anchor event; lines after it are the unanchored tail, reported by the caller
    (W-AUDIT-UNANCHORED-TAIL, or E-AUDIT-TAIL for a run in a terminal state, D2). Named seqs beyond
    the end of the log are E-AUDIT-TRUNCATED (and not compared again here).
    """
    lines = read_jsonl_lines(d.text or "")
    evs = d.data or []
    anchors = run.get("audit_anchors") or []
    prev = 0
    for j, a in enumerate(anchors):
        a = a if isinstance(a, dict) else {}
        s, h = a.get("seq"), a.get("line_sha256")
        where = f"{w} (run.audit_anchors[{j}])"
        if not R.check(type(s) is int and s > prev, "E-AUDIT-ANCHOR", where, f"anchor seq {s!r} must be an integer above {prev}"):
            continue
        prev = s  # type: ignore[assignment]  # the name is reused with another type earlier in the function
        if not R.check(s <= len(lines), "E-AUDIT-TRUNCATED", where,  # type: ignore[operator]  # a value an earlier check or lookup ruled out as None; mypy cannot follow it
                       f"anchor names seq {s} but the log has only {len(lines)} lines (truncated after the anchor)"):
            continue
        want = "sha256:" + sha256_hex(lines[s - 1].encode("utf-8"))  # type: ignore[operator]  # a value an earlier check or lookup ruled out as None; mypy cannot follow it
        R.check(h == want, "E-AUDIT-ANCHOR-MISMATCH", where, f"line_sha256 {h} != sha256 of line {s} ({want})")
        R.check(s - 1 < len(evs) and evs[s - 1].get("event_type") == "audit_anchor", "E-AUDIT-ANCHOR", where,  # type: ignore[operator]  # a value an earlier check or lookup ruled out as None; mypy cannot follow it
                f"line {s} is not an audit_anchor event")
    logged = [i + 1 for i, e in enumerate(evs) if isinstance(e, dict) and e.get("event_type") == "audit_anchor"]
    named = [a.get("seq") for a in anchors if isinstance(a, dict)]
    named_in_log = [s for s in named if type(s) is int and 0 < s <= len(lines)]
    R.check(named_in_log == logged, "E-AUDIT-ANCHOR", w,
            f"run.audit_anchors seqs {named_in_log} must name every audit_anchor event of the log, in order: {logged}"
            + (f" (missing {sorted(set(logged) - set(named_in_log))})" if set(logged) - set(named_in_log) else ""))
    last = logged[-1] if logged else 0
    return len(lines) - last, last
