# SPDX-License-Identifier: Apache-2.0
"""Check group over run records: state, jobs, ownership, builds, test results and their controls, the run manifest,
baselines and review plans; and the S2 job helpers (snapshot, restore, jobs that never ran).

Split out of checks.py (architecture refactor PR-D6, docs/adr/0003-split-checks.md). The text is moved verbatim; no
rule, error code or message changed. checks.GROUPS still lists the group in the same place.
"""
from __future__ import annotations

import datetime as dt
import re

from . import adjudicate as adj
from . import derive, safety, timeutil
from .bundle import Doc
from .canonical import content_hash
from .checks_engagement import profile
from .checks_gates import run_start
from .checks_roe import cname_platform_problems, expected_gaps, g4_latest_decisions, job_span
from .checks_signatures import decision_time
from .context import Ctx
from .report import TERMINAL_RUN_STATES, Report, anchored_seqs, doc_guard, roe_windows, ts


# ============================================================== 11 runs
def run_ownership(R: Report, c: Ctx, w: str, run: dict):
    """v0.7 (review r9, E-RUN-OWNERSHIP): run.ownership_results agree with the ROE. Each result names a ROE target and
    uses the method the ROE declares for it (a database proves control with db_comment, which a DNS record says
    nothing about), and every target a B4 job ran against has an ok result. v0.7 never read ownership_results, so the
    example's database target was 'verified' by dns_txt."""
    targets = {t.get("id"): t for t in c.roe.get("targets") or [] if isinstance(t, dict)}
    results = [o for o in run.get("ownership_results") or [] if isinstance(o, dict)]
    for o in results:
        t = targets.get(o.get("target_id"))
        if not R.check(t is not None, "E-RUN-OWNERSHIP", w, f"ownership result for {o.get('target_id')!r}, which is not a ROE target"):
            continue
        want = (t.get("ownership_proof") or {}).get("method")  # type: ignore[union-attr]  # a value an earlier check or lookup ruled out as None; mypy cannot follow it
        R.check(o.get("method") == want, "E-RUN-OWNERSHIP", w,
                f"{o.get('target_id')} was verified with {o.get('method')!r}, but the ROE declares {want!r} for it")
        for msg in cname_platform_problems(c, t, o):  # type: ignore[arg-type]  # a value an earlier check or lookup ruled out as None; mypy cannot follow it
            R.check(False, "E-ROE-PLATFORM", w, msg)
    ok = {o.get("target_id") for o in results if o.get("ok") is True}
    used = set()
    for jid, job in (run.get("jobs") or {}).items():
        # r14 (internal review A2): a job that started touched the target whether or not it finished with a result
        if isinstance(job, dict) and (job.get("status") in JOB_RAN_STATES or job_span(c, run.get("run_id"), jid)[0] is not None):
            tc = c.ix.first("testcase", testcase_id=job.get("testcase_id"))
            used |= set((tc.data if tc else {}).get("target_ids") or [])
    for tid in sorted(used - ok):
        R.error("E-RUN-OWNERSHIP", w, f"a B4 job ran against {tid}, which has no ok ownership result in this run (B4_preflight)")


def job_start_rules(R: Report, c: Ctx, rid, jid, job: dict, jw: str):
    """r14 (internal review A2; docs/02 §1.3-§1.4, 03 §5.5): a B4 job is judged by its own sandbox_job_start, whether or
    not a result exists. The approval in force when it started must be an accept (derive.g4_state at the start; E-JOB-G4),
    and the start must fall inside the ROE validity (E-RUN-WINDOW covers the time windows for every Z3 event). Until r14
    the G4 and window rules lived in the per-testresult loop, so an INTERRUPTED job with no result, started before G4
    and on a Saturday, validated."""
    start, _ = job_span(c, rid, jid)
    if start is None:
        return
    st = derive.g4_state(c.ix, rid, job.get("testcase_id"), at=start)
    R.check(st.decision == "accept" and st.approved_since is not None and start > st.approved_since, "E-JOB-G4", jw,
            f"job {jid} started at {start.isoformat()} while the G4 decision in force on {job.get('testcase_id')} was "
            f"{st.decision!r} (approved since {st.approved_since.isoformat() if st.approved_since else None})")


# r14 (internal review A4; docs/02 §1.4 G0b row, B0, 03 §5.4): every activity that touches the target runs inside the ROE
# validity and its time windows: the ownership check, every Z3 sandbox job, snapshots, restores and restore drills. Until
# r14 only a B4 result's executed_at was compared with the windows, so the shipped example verified ownership at 09:30
# against windows of 20:00-23:00 and a job without a result ran outside them.
TARGET_EVENTS = ("ownership_check", "snapshot_created", "snapshot_restored", "restore_failed", "restore_drill")


def target_activity_windows(R: Report, c: Ctx, w: str, rid, evs: list):
    if not c.roe:
        return
    rv = c.roe.get("validity") or {}
    rnb, rna = ts(R, rv.get("not_before"), "roe.yaml"), ts(R, rv.get("not_after"), "roe.yaml")
    windows = roe_windows(c)
    for e in evs:
        if not isinstance(e, dict):
            continue
        et = e.get("event_type")
        if not (et in TARGET_EVENTS or (et in ("sandbox_job_start", "sandbox_job_end") and e.get("zone") == "Z3")):
            continue
        at = ts(R, e.get("ts"), f"{w} seq {e.get('seq')}")
        R.check(at is not None and rnb is not None and rna is not None and rnb <= at <= rna and timeutil.in_any_window(at, windows),
                "E-RUN-WINDOW", f"{w} seq {e.get('seq')}",
                f"{et} at {e.get('ts')} touches the target outside the ROE validity ({rv.get('not_before')} .. {rv.get('not_after')}) "
                "or its time windows (docs/02 B0, §1.4: target activity waits for the window)")


def g_runs(R: Report, c: Ctx):
    tk, e = c.toolkit, c.engagement
    for d in c.docs("run"):
        with doc_guard(R, d.path):
            run, w = d.data, d.path
            rid = run.get("run_id")
            R.check(run.get("engagement_id") == e.get("engagement_id"), "E-RUN", w, "engagement_id mismatch")
            R.check(run.get("data_class") == e.get("data_class"), "E-RUN", w, "data_class differs from the engagement")
            R.check(run.get("calibration_version") == c.calibration.get("calibration_version"), "E-RUN", w, "calibration_version differs")
            want_owasp = e.get("owasp_llm_version") or tk.get("owasp_llm_default")
            R.check(run.get("owasp_llm_version") == want_owasp, "E-RUN-OWASP", w, f"owasp_llm_version must be {want_owasp}")
            R.check(run.get("run_owner") == e.get("run_owner"), "E-RUN", w, "run_owner differs from the engagement")
            for p in run.get("initiators", []):
                R.check(p in c.persons and p not in c.automation, "E-RUN-INITIATOR", w, f"initiator {p} must be a registered person")
            status = run.get("status")
            pending = [g for g in run.get("gate_records", []) if g.get("gate_record_id") is None]
            if status in TERMINAL_RUN_STATES:
                R.check(run.get("current_node") is None and not pending, "E-RUN-STATUS", w, f"{status} run has a current node or pending gate")
            if status in COMPLETED_RUN_STATES:
                # review r11: docs/02 §1.4 / B6: the terminal status follows the gaps (only MANUAL entries -> COMPLETED)
                kinds = sorted({g.get("kind") for g in run.get("gaps") or [] if isinstance(g, dict)} - {"manual"})  # type: ignore[type-var]  # the values are strings in a schema-valid document; mypy sees Any | None
                want_status = "COMPLETED_WITH_GAPS" if kinds else "COMPLETED"
                R.check(status == want_status, "E-RUN-STATUS", w,
                        f"status {status} but the gaps imply {want_status} (non-MANUAL gap kinds: {kinds})")
                # review r12: the gaps themselves are checked against what the run's records imply; r11 derived the status
                # from a list the run record could leave empty, so a skipped approved job still ended COMPLETED
                have = {(g.get("kind"), g.get("ref")) for g in run.get("gaps") or [] if isinstance(g, dict)}
                for (kind, ref), why in sorted(expected_gaps(c, rid, run).items(), key=lambda kv: (str(kv[0][0]), str(kv[0][1]))):
                    R.check((kind, ref) in have, "E-RUN-GAPS", w, f"gaps must list {{kind: {kind}, ref: {ref}}} ({why}; docs/02 B6)")
            if status == "WAITING_GATE":
                R.check(len(pending) == 1 and run.get("current_node") == pending[0].get("gate"), "E-RUN-STATUS", w,
                        "WAITING_GATE needs exactly one pending gate equal to current_node")
                if pending:
                    g = pending[0]
                    op, dl = ts(R, g.get("opened_at"), w), ts(R, run.get("resume_deadline"), w)
                    lim = (e.get("gate_timeouts_hours") or {}).get(g.get("gate"))
                    R.check(op and dl and lim is not None and dl == op + dt.timedelta(hours=lim), "E-RUN-DEADLINE", w,
                            f"resume_deadline must be opened_at + {lim} h")
            run_manifest(R, c, d)
            run_ownership(R, c, w, run)
            kind = run.get("run_kind")
            gates = [g.get("gate") for g in run.get("gate_records", [])]
            if kind == "lane_a":
                R.check(run.get("roe_ref") is None and "G0b" not in gates and not run.get("jobs"), "E-RUN-LANE-A", w,
                        "Lane A runs never pass G0b or run black-box jobs")
                for vid in run.get("verdicts", []):
                    v = c.ix.first("verdict", verdict_id=vid)
                    R.check(v is not None and v.data.get("advisory") is True, "E-RUN-LANE-A", w, f"Lane A verdict {vid} must be advisory")
                R.check(set(run.get("lane_a_advisories", [])) == set(run.get("cluster_ids", [])), "E-RUN-LANE-A", w, "lane_a_advisories must list the run's clusters")
            if kind in ("followup", "regression"):
                # v0.7 (review r8 H2): a regression run carries its parent's clusters the same way (docs/02 §1.6); v0.6 allowed
                # a parent / reuse for followup runs only, although the schema and the docs defined regression runs with both
                R.check(run.get("parent_run_id") in c.runs, "E-RUN-FOLLOWUP", w, "parent run not found")
                parent = c.runs.get(run.get("parent_run_id")) or {}
                R.check(any(fd in parent.get("followup_drafts", []) for p in c.docs("commander-plan") if p.data.get("plan_id") in run.get("plan_ids", [])
                            for fd in (x.get("draft_id") for x in p.data.get("followup_drafts", []))), "E-RUN-FOLLOWUP", w,
                        f"a {kind} run must come from a follow-up draft of its parent")
            else:
                R.check(run.get("parent_run_id") is None and run.get("reuse") == [], "E-RUN-FOLLOWUP", w, "only follow-up / regression runs have a parent / reuse")
            # v0.7 (review r8 M6, docs/03 §12): a Lane A run of a fork PR gets no LLM review and its results are untrusted
            if kind == "lane_a":
                R.check(run.get("pr_origin") in ("same_repo", "fork"), "E-RUN-LANE-A", w, "a Lane A run declares pr_origin (same_repo / fork)")
                if run.get("pr_origin") == "fork":
                    R.check(not run.get("verdicts") and not run.get("cluster_ids") and not run.get("lane_a_advisories"), "E-RUN-LANE-A", w,
                            "a fork PR gets no LLM review: no verdicts, clusters or advisories (untrusted input, docs/03 §12)")
            else:
                R.check(run.get("pr_origin") is None, "E-RUN-LANE-A", w, "pr_origin is a Lane A field")
                lane_a_clusters = {k.data.get("cluster_id") for k in c.docs("cluster")
                                   if (c.runs.get(k.data.get("run_id")) or {}).get("run_kind") == "lane_a"
                                   and (c.runs.get(k.data.get("run_id")) or {}).get("pr_origin") == "same_repo"}
                bad = sorted(set(run.get("lane_a_advisories") or []) - lane_a_clusters)
                R.check(not bad, "E-RUN-LANE-A", w, f"lane_a_advisories {bad} are not clusters of a same-repo Lane A run")
            # v0.7 (review r9; docs/02 §1.6): G1 and G3 are signed by the run itself (items may be carried from an ancestor);
            # a run whose G3 decides threats has an approved G1, so its threats rest on requirements this run approved
            if any(x.data.get("outcome") != "EXPIRED" for x in c.ix.gate_records(rid, "G3")):
                R.check(any(x.data.get("outcome") in ("APPROVED", "PARTIALLY_APPROVED") for x in c.ix.gate_records(rid, "G1")),
                        "E-RUN-G1", w, "the run's G3 decides threats, but the run has no approved G1 (decide it here or carry it "
                        "item by item with carried_from)")
            # v0.7 (review r8 H3; docs/02 §1.6): a testcase reaches G4 only after this run's G3 accepted its threat
            # (carried_from an ancestor is an accept of this run); v0.6 read the threat's global review.status
            if any(g.get("gate") == "G4" for g in run.get("gate_records", [])):
                accepted = {x.get("item_id") for rec in c.ix.gate_records(rid, "G3") if rec.data.get("outcome") != "EXPIRED"
                            for x in rec.data.get("decisions") or [] if isinstance(x, dict) and x.get("decision") == "accept"}
                for tcid in run.get("testcase_ids") or []:
                    tcd = c.ix.first("testcase", testcase_id=tcid)
                    th = tcd.data.get("threat_id") if tcd else None
                    R.check(th in accepted, "E-RUN-G3", w,
                            f"testcase {tcid} is at G4 but its threat {th} has no accept in this run's G3 (carry it with carried_from, or decide it here)")
            # gate record ordering
            times = [ts(R, g.get("opened_at"), w) for g in run.get("gate_records", [])]
            times = [t for t in times if t]
            R.check(times == sorted(times), "E-RUN-GATES", w, "gate_records are not in opened_at order")
            for g in run.get("gate_records", []):
                if g.get("gate_record_id"):
                    grec = c.record(g["gate_record_id"])
                    if R.check(grec is not None, "E-RUN-GATES", w, f"gate record {g['gate_record_id']} not found"):
                        # D8: a run may only list its own gate records
                        R.check(grec.get("run_id") == rid, "E-GATE-RUN", w,
                                f"gate record {g['gate_record_id']} belongs to run {grec.get('run_id')}, not {rid}")
            # G4 approved ids
            g4 = [x.data for x in c.ix.gate_records(rid, "G4")]
            g4_latest = g4_latest_decisions(c, rid)
            if g4:
                # v0.5 (review r7 1.2): the latest signed decision per testcase, over every G4 round
                acc = sorted(k for k, (dec, _) in g4_latest.items() if dec == "accept")
                R.check(sorted(run.get("approved_testcase_ids", [])) == acc, "E-RUN-G4", w,
                        f"approved_testcase_ids must be the testcases whose latest G4 decision is accept ({acc})")
            else:
                R.check(not run.get("approved_testcase_ids") and not run.get("jobs"), "E-RUN-G4", w, "no G4 record but approved tests / jobs exist")
            R.check(set(run.get("approved_testcase_ids", [])) <= set(run.get("testcase_ids", [])), "E-RUN-G4", w, "approved ids not in testcase_ids")
            # budgets after GB
            for gbr in c.ix.gate_records(rid, "GB"):
                gb = gbr.data.get("gb") or {}
                if gbr.data.get("outcome") == "APPROVED" and gb.get("choice") == "extend":
                    cur = (run.get("budgets") or {}).get(gb.get("phase")) or {}
                    R.check(all(cur.get(k) == v for k, v in (gb.get("new_caps") or {}).items()), "E-RUN-BUDGET", w,
                            f"budgets.{gb.get('phase')} must carry the GB new_caps")
            for ph, bud in (run.get("budgets") or {}).items():
                if isinstance(bud, dict) and "max_input_tokens" in bud:
                    for spent, cap in (("spent_input_tokens", "max_input_tokens"), ("spent_output_tokens", "max_output_tokens"),
                                       ("spent_cost_usd", "max_cost_usd"), ("compute_minutes", "max_compute_minutes")):
                        if bud.get(cap) is not None:
                            R.check(bud.get(spent, 0) <= bud[cap], "E-RUN-BUDGET", w, f"budgets.{ph}.{spent} exceeds {cap}")
            # jobs
            audit = c.ix.audit_for(rid)
            # review r11: a drill counts only when a system actor wrote it inside the anchored part of the log
            a_evs = [x for x in (audit.data if audit else []) if isinstance(x, dict)]
            a_last = anchored_seqs(a_evs)
            drills = [ts(R, x.get("ts"), w) for i, x in enumerate(a_evs) if x.get("event_type") == "restore_drill" and (x.get("payload") or {}).get("ok")
                      and (x.get("actor") or {}).get("kind") == "system" and i + 1 <= a_last]
            drill_days = tk.get("restore_drill_interval_days", 7)
            for jid, job in (run.get("jobs") or {}).items():
                with doc_guard(R, f"{w} jobs.{jid}"):
                    jw = f"{w} jobs.{jid}"
                    R.check(job.get("job_id") == jid, "E-RUN-JOB", jw, "job_id != key")
                    tc = c.ix.first("testcase", testcase_id=job.get("testcase_id"))
                    if not R.check(tc is not None, "E-RUN-JOB", jw, "testcase not found"):
                        continue
                    # approved now, or approved when the job started and withdrawn by a later G4 round (that does not undo a job
                    # that ran under it; a job started after the withdrawal is not allowed, review r11 external)
                    jstart, _jend = job_span(c, rid, jid)
                    withdrawn_later = jstart is not None \
                        and derive.g4_state(c.ix, rid, job.get("testcase_id"), at=jstart).decision == "accept" \
                        and derive.g4_state(c.ix, rid, job.get("testcase_id")).decision != "accept"
                    R.check(job.get("testcase_id") in run.get("approved_testcase_ids", []) or withdrawn_later,
                            "E-RUN-JOB", jw, "job for a testcase not approved at G4")
                    if profile(c) == "lite":
                        R.check(job.get("safety_class") in ("S0", "S1"), "E-PROFILE-SAFETY", jw,
                                f"assurance_profile lite allows only S0/S1 jobs, got {job.get('safety_class')}")
                    R.check(job.get("safety_class") == tc.data.get("safety_class_computed"), "E-RUN-JOB", jw, "safety_class != testcase computed class")  # type: ignore[union-attr]  # a value an earlier check or lookup ruled out as None; mypy cannot follow it
                    R.check(job.get("target_id") in tc.data.get("target_ids", []), "E-RUN-JOB", jw, "target not in the testcase")  # type: ignore[union-attr]  # a value an earlier check or lookup ruled out as None; mypy cannot follow it
                    tr = next((x.data for x in c.docs("testresult") if x.data.get("job_id") == jid and x.data.get("run_id") == rid), None)
                    if job.get("safety_class") == "S2" and job.get("status") not in S2_RAN_STATES:
                        # r12 external review: a job that never ran (SKIPPED after a G5 rejection or expiry, a failed snapshot,
                        # or still waiting) has no snapshot, no restore and no sandbox events; r12 judged every S2 job as RESTORED
                        g5 = c.record(job.get("g5_record_id"))
                        s2_not_run(R, c, rid, jid, job, g5, jw)
                    elif job.get("safety_class") == "S2":
                        g5 = c.record(job.get("g5_record_id"))
                        R.check(g5 is not None and g5.get("gate") == "G5" and g5.get("outcome") == "APPROVED" and g5.get("job_id") == jid,
                                "E-RUN-S2", jw, "S2 job needs an APPROVED G5 record for this job")
                        R.check(bool(job.get("snapshot_ref")), "E-RUN-S2", jw, f"S2 job {jid} ({job.get('status')}) ran, so it has a snapshot_ref")
                        R.check(job.get("status") in S2_END_STATES or run.get("status") not in TERMINAL_RUN_STATES, "E-RUN-S2", jw,
                                f"S2 job {jid} is {job.get('status')} in a {run.get('status')} run: an S2 job that ran ends RESTORED or "
                                "RESTORE_FAILED (docs/03 §5.6 abort_handler restores every snapshot)")
                        span_start, span_end = job_span(c, rid, jid)
                        restored = snapshot_audit(R, c, rid, jid, job, span_start, span_end, jw)
                        if restored is False and run.get("status") in TERMINAL_RUN_STATES:
                            R.check(run.get("status") == "FAILED", "E-RUN-S2", jw,
                                    f"the restore of {jid} failed, so the run is FAILED, not {run.get('status')} (docs/03 §5.6)")
                        start = span_start or (ts(R, tr.get("executed_at"), jw) if tr else (ts(R, g5.get("timestamp"), jw) if g5 else None))
                        ok = start is not None and any(dd and dd <= start and start - dd <= dt.timedelta(days=drill_days) for dd in drills)
                        # a log rejected by the strict loader is reported once (E-JSON-STRICT), not re-reported here
                        R.check(ok or rid in c.broken_audit_runs, "E-RUN-RESTORE-DRILL", jw,
                                f"no successful restore drill within {drill_days} days before the S2 job")
                        R.check(run.get("restore_drill_ref") is not None, "E-RUN-RESTORE-DRILL", jw, "restore_drill_ref missing")
                        if g5:
                            # v0.5 (review r7 1.2): the G5 decision and the job are both judged by receive time
                            # r14 (internal review A2): the job's own span is judged whether or not a result exists
                            g5_at = decision_time(c, g5) or ts(R, g5.get("timestamp"), jw)
                            end = timeutil.window_end(g5_at, roe_windows(c)) if g5_at else None
                            if tr:
                                ex = ts(R, tr.get("executed_at"), jw)
                                R.check(g5_at and ex and end and g5_at <= ex < end, "E-RESULT-G5", jw, "S2 job must start after its G5 and inside the same window")
                            if span_start is not None:
                                R.check(g5_at is not None and end is not None and g5_at <= span_start and (span_end is None or span_end < end),
                                        "E-RESULT-G5", jw, f"the sandbox_job_start ({span_start.isoformat()}) / end must lie between its G5 "
                                        f"decision ({g5_at.isoformat() if g5_at else None}) and the end of that window")
                    else:
                        R.check(job.get("g5_record_id") is None, "E-RUN-JOB", jw, "only S2 jobs have a G5 record")
                    if job.get("status") in ("EXECUTED", "RESTORED"):
                        R.check(tr is not None, "E-RUN-JOB", jw, "executed job without a testresult")
                        R.check(jid in run.get("executed_jobs", []), "E-RUN-JOB", jw, "executed job not listed in executed_jobs")
                    job_start_rules(R, c, rid, jid, job, jw)
            R.check(set(run.get("executed_jobs", [])) <= set((run.get("jobs") or {})), "E-RUN-JOB", w, "executed_jobs not in jobs")
            # testresults of this run
            rv = c.roe.get("validity") or {}
            rnb, rna = ts(R, rv.get("not_before"), "roe.yaml"), ts(R, rv.get("not_after"), "roe.yaml")
            for x in c.docs("testresult"):
                with doc_guard(R, x.path):
                    tr = x.data
                    if tr.get("run_id") != rid:
                        continue
                    ex = ts(R, tr.get("executed_at"), x.path)
                    tc = c.ix.testcase_for(tr)
                    black_box = tr.get("phase") == "B4"
                    if black_box:
                        job = (run.get("jobs") or {}).get(tr.get("job_id"))
                        R.check(job is not None and job.get("testcase_id") == tr.get("testcase_id"), "E-RESULT-JOB", x.path, "job not in the run or for another testcase")
                    else:                  # W4: Z2 sandbox test, no B4 job, no ROE window
                        R.check(tr.get("job_id") is None, "E-RESULT-JOB", x.path, "W4 results have no B4 job (job_id null)")
                    if ex and black_box:
                        # review r11 (external): the approval IN FORCE when the job started (derive.g4_state), not the latest G4 record
                        start, end = job_span(c, rid, tr.get("job_id"))
                        st = derive.g4_state(c.ix, rid, tr.get("testcase_id"), at=start or ex)
                        g4_at = st.approved_since
                        R.check(timeutil.in_any_window(ex, roe_windows(c)) and rnb and rna and rnb <= ex <= rna, "E-RESULT-WINDOW", x.path,
                                "executed outside the ROE validity / time windows")
                        R.check(st.decision == "accept" and g4_at is not None and ex > g4_at, "E-RESULT-G4", x.path,
                                "executed before G4 approval" if st.decision != "reject" and st.decision != "needs_info"
                                else f"executed while the G4 decision on the testcase was {st.decision}")
                        if st.decision == "accept" and g4_latest.get(tr.get("testcase_id"), (None, None))[0] != "accept":
                            R.warn("W-RESULT-G4-WITHDRAWN", x.path, "the G4 approval this result ran under was withdrawn by a later round: "
                                   "the result keeps its pre-registration, the testcase may not be dispatched again")
                        # v0.5 (review r7 1.2): executed_at is self-declared; the job's sandbox_job_* receive times decide
                        if start is not None and end is not None:
                            R.check(start <= ex <= end, "E-JOB-AUDIT", x.path,
                                    f"executed_at {tr.get('executed_at')} is outside its job ({start.isoformat()} .. {end.isoformat()})")
                            R.check(all(timeutil.in_any_window(t, roe_windows(c)) and rnb and rna and rnb <= t <= rna for t in (start, end)),
                                    "E-RESULT-WINDOW", x.path, "the sandbox_job_start / end lie outside the ROE validity / time windows")
                            R.check(g4_at is not None and start > g4_at, "E-RESULT-G4", x.path,
                                    f"the sandbox_job_start ({start.isoformat()}) precedes the G4 decision that approved the testcase")
                    if tc:
                        result_controls(R, c, x, tc.data)
                        R.check(tr.get("request_count", 0) <= (tc.data.get("rate_limit") or {}).get("max_requests", 0), "E-RESULT-REQUESTS", x.path,
                                "request_count exceeds the testcase max_requests")
                        n = (tc.data.get("trials") or {}).get("n")
                        R.check((tr.get("trials") or {}).get("n") == n, "E-RESULT-TRIALS", x.path, f"trials.n must equal the testcase n={n}")
                        # v0.5 (review 2026-10-25 M-3): a replay job runs the pre-registered replay_n times, not fewer
                        rn = (tc.data.get("trials") or {}).get("replay_n")
                        R.check(tr.get("replays", 0) in (0, rn), "E-RESULT-TRIALS", x.path,
                                f"replays (n_r) {tr.get('replays')} must be 0 (no replay job) or the testcase replay_n={rn}")
                        R.check(set(tr.get("target_ids", [])) <= set(tc.data.get("target_ids", [])), "E-RESULT-TARGETS", x.path, "targets outside the testcase")
                    # v0.5 (BL-27): a B4 result hit at least one ROE target; a W4 result ran in Z2 and has none
                    R.check(bool(tr.get("target_ids")) == black_box, "E-RESULT-TARGETS", x.path,
                            "B4 results name at least one ROE target" if black_box else "W4 results run in Z2 and name no ROE target")
                    if black_box:
                        result_build(R, c, x, run)
                        R.check(tr.get("request_log_sha256") is not None, "E-RESULT-REQUEST-LOG", x.path,
                                "black-box (B4) results need request_log_sha256 (the Scope Proxy request log)")
                    t = tr.get("trials") or {}
                    R.check(0 <= t.get("k", 0) <= t.get("n", 0), "E-RESULT-TRIALS", x.path, "k must be between 0 and n")
                    if tr.get("outcome") == "FAIL":
                        R.check(t.get("k", 0) >= 1, "E-RESULT-TRIALS", x.path, "FAIL needs k >= 1")
                        # v0.5 (review 2026-10-25 §4.3): the pre-registered threshold, not just k >= 1
                        kmin = ((tc.data if tc else {}).get("trials") or {}).get("fail_k_min", 1)
                        R.check(t.get("k", 0) >= kmin, "E-RESULT-TRIALS", x.path, f"FAIL needs k >= the testcase fail_k_min {kmin}")
                    R.check(0 <= tr.get("replay_k", 0) <= tr.get("replays", 0), "E-RESULT-TRIALS", x.path,
                            "replay_k (k_r) must be between 0 and replays (n_r)")
            rm = c.ix.first("report-manifest", run_id=rid)
            if rm is not None:
                want = unverified_build_targets(c, rid)
                R.check(sorted(rm.data.get("build_unverified_targets") or []) == want, "E-RESULT-BUILD", rm.path,
                        f"build_unverified_targets {rm.data.get('build_unverified_targets')} must list exactly the tested targets whose "
                        f"ROE build_identity.method is none: {want}")


def build_matches(observed, commit) -> bool:
    """B7: observed build id == run.repo_commit, or one is a prefix of the other and the shorter has >= 12 hex chars."""
    if not isinstance(observed, str) or not isinstance(commit, str):
        return False
    if observed == commit:
        return True
    short, long_ = sorted((observed, commit), key=len)
    return len(short) >= 12 and long_.startswith(short)


def roe_target(c: Ctx, tid) -> dict:
    return next((t for t in c.roe.get("targets") or [] if isinstance(t, dict) and t.get("id") == tid), {})


def unverified_build_targets(c: Ctx, run_id) -> list[str]:
    tids = {t for x in c.docs("testresult") if x.data.get("run_id") == run_id and x.data.get("phase") == "B4"
            for t in x.data.get("target_ids") or []}
    # Tester-controlled targets (e.g. the canary server) are not the system under test: no build to verify.
    return sorted(t for t in tids if (roe_target(c, t).get("build_identity") or {}).get("method") == "none"
                  and roe_target(c, t).get("environment") != "tester_controlled")


def result_build(R: Report, c: Ctx, x: Doc, run: dict):
    """B7 (H-B4): targets with a build identity must have served the run's repo_commit."""
    tr = x.data
    for t in tr.get("target_ids") or []:
        method = (roe_target(c, t).get("build_identity") or {}).get("method")
        if method in ("header", "endpoint"):
            R.check(build_matches(tr.get("observed_build_id"), run.get("repo_commit")), "E-RESULT-BUILD", x.path,
                    f"{t}: observed_build_id {tr.get('observed_build_id')!r} is not the run's repo_commit {run.get('repo_commit')!r} "
                    "(full, or a prefix of at least 12 characters)")


def result_controls(R: Report, c: Ctx, x: Doc, tc: dict):
    """B5 / A2: controls, INVALID, fail_oracles, derived precondition_reached / positive_control, analyst role."""
    tr, w = x.data, x.path
    ctl = derive.control_results(tc, tr)
    want_ids = [cid for cid, _, _ in ctl]
    got_ids = [y.get("control_id") for y in tr.get("controls") or [] if isinstance(y, dict)]
    R.check(sorted(got_ids) == sorted(want_ids) and len(set(got_ids)) == len(got_ids), "E-RESULT-CONTROLS", w,  # type: ignore[type-var]  # the values are strings in a schema-valid document; mypy sees Any | None
            f"controls {got_ids} must cover exactly the testcase controls {want_ids}")
    not_pass = [cid for cid, _, o in ctl if o != "PASS"]
    if not_pass:
        R.check(tr.get("outcome") == "INVALID", "E-RESULT-INVALID", w,
                f"controls {not_pass} did not PASS: the outcome must be INVALID (never PASS/FAIL), got {tr.get('outcome')}")
    else:
        R.check(tr.get("outcome") != "INVALID", "E-RESULT-INVALID", w, "INVALID needs at least one control that did not PASS")
    fo = tr.get("fail_oracles") or []
    R.check((tr.get("outcome") == "FAIL") == bool(fo), "E-RESULT-ORACLE", w, "fail_oracles must be non-empty iff the outcome is FAIL")
    trials = tr.get("trials") or {}
    ne, nn, kk = trials.get("n_effective"), trials.get("n"), trials.get("k")
    # v0.4: n' (trials whose precondition was reached) is recorded; it bounds k and is bounded by n
    R.check(isinstance(ne, int) and isinstance(nn, int) and isinstance(kk, int) and kk <= ne <= nn, "E-RESULT-TRIALS", w,
            f"trials must satisfy k <= n_effective <= n (got k={kk}, n_effective={ne}, n={nn})")
    R.check(set(fo) <= derive.oracle_types(tc), "E-RESULT-ORACLE", w,
            f"fail_oracles {sorted(set(fo) - derive.oracle_types(tc))} are not oracle.types of {tc.get('testcase_id')}")
    pr = (tr.get("precondition_reached") or {}).get("value")
    R.check(pr is derive.reachability_reached(tc, tr), "E-RESULT-PRECONDITION", w,
            f"precondition_reached {pr} != derived {derive.reachability_reached(tc, tr)} (every reachability control PASS)")
    pc = (tr.get("positive_control") or {}).get("value")
    R.check(pc is derive.positive_control_value(tc, tr), "E-RESULT-CONTROLS", w,
            f"positive_control {pc} != derived {derive.positive_control_value(tc, tr)} (an oracle_can_fail control exists and PASSed)")
    ib = tr.get("interpreted_by")
    R.check((ib is None) == (tr.get("interpretation") is None), "E-RESULT-ANALYST", w, "interpretation is set iff interpreted_by is set")
    if isinstance(ib, dict):
        a = c.agents.get(ib.get("agent_id")) if isinstance(ib.get("agent_id"), str) else None
        R.check(isinstance(a, dict) and a.get("role") == "result_analyst", "E-RESULT-ANALYST-ROLE", w,
                f"interpreted_by {ib.get('agent_id')!r} must be an agents.yaml agent with role result_analyst (got {(a or {}).get('role')!r})")


MAX_EXTRA_DISPATCH_ROUNDS = 2


RUN_INIT_CONFIGS = ("models", "agents", "tools", "calibration")
COMPLETED_RUN_STATES = ("COMPLETED", "COMPLETED_WITH_GAPS")
PRODUCING_NODE = {"invariants": "G1", "seed_manifest": "G0b"}   # invariants are approved at G1; G0b needs the seed manifest


def _run_reached(c: Ctx, run: dict) -> dict:
    """What the run's own records show it reached: G1 approved, G0b passed, any B-phase content, W2 started.
    An aborted or failed run is judged by the nodes it reached, like a running one."""
    rid = run.get("run_id")
    g1 = any(g.data.get("outcome") == "APPROVED" for g in c.ix.gate_records(rid, "G1"))
    g0b = bool(c.ix.gate_records(rid, "G0b"))
    black = g0b or bool(run.get("jobs")) or any(c.ix.gate_records(rid, g) for g in ("G3", "G4", "G5"))
    w2 = any(f.data.get("run_id") == rid for f in c.docs("finding")) or any(s.data.get("run_id") == rid for s in c.docs("slice"))
    return {"g1": g1, "g0b": g0b, "black": black, "w2": w2}


def artefact_state(R: Report, c: Ctx, run: dict, w: str, key: str, ref: dict):
    """v0.5 (BL-22 / BL-23, docs/08 §11.13): a run artefact that is not produced is pending (its producing node has not
    finished) or not_applicable (outside the run's phase plan); never a bare null. A pending artefact whose producing
    node has finished, or that a consumer already used, is "should exist but missing" (E-RUN-CONFIG)."""
    where = f"{w} config_refs.{key}"
    reached = _run_reached(c, run)
    if key in RUN_INIT_CONFIGS:
        R.check(False, "E-RUN-CONFIG", where, f"{key} is needed at run_init; it cannot be {ref.get('state')}")
        return
    if ref.get("state") == "pending":
        R.check(ref.get("expected_node") == PRODUCING_NODE[key], "E-RUN-CONFIG", where,
                f"pending {key} names expected_node {ref.get('expected_node')!r}; it is produced by {PRODUCING_NODE[key]}")
        done = (reached["g1"] or reached["w2"]) if key == "invariants" else (reached["g0b"] or reached["black"])
        # a run that stopped early (ABORTED, FAILED) before the producing node never had the artefact, so it stays
        # pending (docs/08 §11.13: missing = the producing node finished); a completed run has nothing left pending:
        # it produced the artefact or its plan did not need it (not_applicable)
        completed = run.get("status") in COMPLETED_RUN_STATES
        R.check(not done and not completed, "E-RUN-CONFIG", where,
                f"{key} is pending but its producing node already finished, a consumer used it or the run is "
                f"{run.get('status')}: should exist but missing")
    else:                                                   # not_applicable
        if key == "invariants":
            R.check(run.get("run_kind") == "lane_a", "E-RUN-CONFIG", where, "invariants are not_applicable only in a Lane A run (every other run has G1)")
        else:
            R.check(not reached["black"], "E-RUN-CONFIG", where,
                    "seed_manifest is not_applicable but the run has black-box content (G0b or later gate records, jobs)")


def run_manifest(R: Report, c: Ctx, d: Doc):
    """B11 (N-5, H-E13): config refs name the right files, tool versions are registered and agree with the audit
    log, the rule version is the adjudicator's; B10 CMD-2 round bound; B9 baseline run."""
    run, w = d.data, d.path
    rid = run.get("run_id")
    for key, kind in derive.CONFIG_KINDS.items():
        ref = (run.get("config_refs") or {}).get(key)
        if isinstance(ref, dict) and ref.get("state") is not None:
            artefact_state(R, c, run, w, key, ref)
            continue
        if ref is None:
            R.check(False, "E-RUN-CONFIG", w, f"config_refs.{key} is null; v0.5 writes {{state: pending | not_applicable}} instead")
            continue
        cd = next((x for x in c.b.docs if x.path == ref.get("path") and x.data is not None), None)
        R.check(cd is not None and cd.kind == kind, "E-RUN-CONFIG", w, f"config_refs.{key}.path {ref.get('path')!r} is not a {kind} file")
    versions = {}
    for tv in run.get("tool_versions") or []:
        R.check(safety.registry_entry(c.tools, tv.get("adapter")) is not None, "E-RUN-CONFIG", w,
                f"tool_versions: {tv.get('adapter')!r} is not a registered tools.yaml tool:mode")
        versions[tv.get("adapter")] = tv.get("version")
    audit = c.ix.audit_for(rid)
    for e in (audit.data if audit else []):
        p = e.get("payload") or {}
        if e.get("event_type") == "tool_invocation_end" and p.get("adapter"):
            R.check(versions.get(p.get("adapter")) is not None and versions.get(p.get("adapter")) == p.get("tool_version"), "E-RUN-CONFIG", w,
                    f"audit seq {e.get('seq')}: {p.get('adapter')} ran as version {p.get('tool_version')!r} but run.tool_versions says "
                    f"{versions.get(p.get('adapter'))!r}")
    R.check(run.get("rule_version") == adj.RULE_VERSION, "E-RUN-RULE-VERSION", w,
            f"rule_version {run.get('rule_version')!r} is not the adjudicator's {adj.RULE_VERSION!r}")
    for vid in run.get("verdicts") or []:
        v = c.ix.first("verdict", verdict_id=vid)
        if v is not None:
            R.check(v.data.get("rule_version") == run.get("rule_version"), "E-RUN-RULE-VERSION", w,
                    f"verdict {vid} rule_version {v.data.get('rule_version')!r} != run rule_version {run.get('rule_version')!r}")
    R.check((run.get("cmd2_rounds") or 0) <= MAX_EXTRA_DISPATCH_ROUNDS, "E-PLAN-ROUNDS", w,
            f"cmd2_rounds {run.get('cmd2_rounds')} exceeds max_extra_dispatch_rounds {MAX_EXTRA_DISPATCH_ROUNDS}")
    base = run.get("baseline_run_id")
    if base is not None:
        R.check(base in c.runs and base != rid, "E-CLUSTER-BASELINE", w, f"baseline_run_id {base!r} is not another run of the bundle")
    # r14 (internal review A9; docs/02 §1.6): an initial run has no baseline; a followup / regression run's baseline is an
    # ancestor (reachable over parent_run_id) that started earlier. r12 accepted a later run or the Lane A run, which
    # flipped the SARIF baselineState of every cluster
    if run.get("run_kind") == "initial":
        R.check(base is None, "E-RUN-BASELINE", w, f"an initial run has no baseline, got {base!r}")
    elif base is not None and base in c.runs:
        ancestors, p, hops = set(), run.get("parent_run_id"), 0
        while p is not None and p in c.runs and p not in ancestors and hops < 100:
            ancestors.add(p)
            p, hops = c.runs[p].get("parent_run_id"), hops + 1
        R.check(base in ancestors, "E-RUN-BASELINE", w, f"baseline_run_id {base!r} is not an ancestor of {rid} (parent chain {sorted(ancestors)})")
        mine, theirs = run_start(c, rid), run_start(c, base)
        R.check(mine is None or theirs is None or theirs < mine, "E-RUN-BASELINE", w,
                f"baseline_run_id {base!r} started at {theirs}, not before this run ({mine})")
    # E6: slices of this run use one of its prompt templates and its redaction map
    shas = {t.get("sha256") for t in run.get("prompt_templates") or []}
    for s in c.docs("slice"):
        if s.data.get("run_id") != rid:
            continue
        R.check(s.data.get("prompt_template_sha256") in shas, "E-SLICE-IDENTITY", s.path,
                "prompt_template_sha256 is not one of the run's prompt_templates")
        if run.get("redaction_map_ref") is not None:
            R.check(s.data.get("redaction_map_sha256") == run.get("redaction_map_ref"), "E-SLICE-IDENTITY", s.path,
                    "redaction_map_sha256 != run.redaction_map_ref")


def evidence_digest(c: Ctx, cluster: dict) -> list[str]:
    """B9: hashes of the member evidence (snippet hash, or JCS of the fact) used to tell unchanged from updated."""
    out = []
    for fid in cluster.get("member_finding_ids") or []:
        f = c.ix.finding(fid) or {}
        for e in f.get("evidence") or []:
            if not isinstance(e, dict):
                continue
            out.append(e.get("snippet_sha256") or content_hash({k: e.get(k) for k in ("kind", "file", "fact_ref", "key_path", "asserted")}))
    return sorted(out)


def derived_baseline_state(c: Ctx, cluster: dict) -> str | None:
    """B9 (SARIF 2.1.0 baselineState): None without a baseline run; new = fingerprint not in the baseline run;
    unchanged = same fingerprint and member evidence; updated = same fingerprint, evidence changed."""
    base = (c.runs.get(cluster.get("run_id")) or {}).get("baseline_run_id")
    if base is None:
        return None
    fp = derive.cluster_fingerprint(cluster)
    old = [k.data for k in c.docs("cluster") if k.data.get("run_id") == base and derive.cluster_fingerprint(k.data) == fp]
    if not old:
        return "new"
    return "unchanged" if any(evidence_digest(c, o) == evidence_digest(c, cluster) for o in old) else "updated"


def baseline_checks(R: Report, c: Ctx):
    for d in c.docs("cluster"):
        k = d.data
        want = derived_baseline_state(c, k)
        R.check(k.get("baseline_state") == want, "E-CLUSTER-BASELINE", d.path,
                f"baseline_state {k.get('baseline_state')!r} != derived {want!r} (run baseline_run_id / fingerprints)")
        R.check(not k.get("reopened") or k.get("baseline_state") == "new", "E-CLUSTER-BASELINE", d.path, "reopened only on a new cluster")
    for d in c.docs("report-manifest"):
        run = c.runs.get(d.data.get("run_id")) or {}
        base = run.get("baseline_run_id")
        cur = {derive.cluster_fingerprint(k.data) for k in c.docs("cluster") if k.data.get("run_id") == run.get("run_id")}
        old = {derive.cluster_fingerprint(k.data) for k in c.docs("cluster") if base is not None and k.data.get("run_id") == base}
        want = sorted(old - cur)  # type: ignore[assignment]  # the name is reused with another type earlier in the function
        R.check(sorted(d.data.get("absent_fingerprints") or []) == want, "E-CLUSTER-BASELINE", d.path,
                f"absent_fingerprints must be the baseline run's fingerprints missing from this run: {want}")


def plan_checks(R: Report, c: Ctx, d: Doc):
    """B10 / D16: typed extra-dispatch targets, round bound, agents with matching roles, budget within the run budget."""
    p, w = d.data, d.path
    patterns = {"cluster": r"^K-[0-9]{3,}$", "slice": r"^sha256:[0-9a-f]{64}$", "threat": r"^T-[0-9]{3,}$"}
    for i, x in enumerate(p.get("extra_dispatch") or []):
        t = x.get("target") or {}
        ok = isinstance(t, dict) and isinstance(t.get("id"), str) and re.match(patterns.get(t.get("kind"), r"(?!)"), t.get("id")) is not None  # type: ignore[arg-type]  # a value an earlier check or lookup ruled out as None; mypy cannot follow it
        found = ok and {"cluster": lambda i_: c.ix.first("cluster", cluster_id=i_), "slice": lambda i_: c.ix.first("slice", slice_id=i_),
                        "threat": lambda i_: c.ix.first("threat", threat_id=i_)}[t["kind"]](t["id"]) is not None
        R.check(ok and found, "E-PLAN-TARGET", w, f"extra_dispatch[{i}].target {t} is not an existing {t.get('kind') if isinstance(t, dict) else '?'}")
        for a in x.get("agents") or []:
            R.check((c.agents.get(a) or {}).get("role") in ("reviewer", "verifier"), "E-PLAN-AGENTS", w,
                    f"extra_dispatch[{i}] agent {a!r} is not an agents.yaml reviewer / verifier")
    R.check(isinstance(p.get("round"), int) and 1 <= p["round"] <= MAX_EXTRA_DISPATCH_ROUNDS, "E-PLAN-ROUNDS", w,
            f"round {p.get('round')} must be 1..{MAX_EXTRA_DISPATCH_ROUNDS} (max_extra_dispatch_rounds)")
    for i, s in enumerate(p.get("slices") or []):
        for a in s.get("agents") or []:
            R.check((c.agents.get(a) or {}).get("role") == "reviewer", "E-PLAN-AGENTS", w, f"slices[{i}] agent {a!r} is not an agents.yaml reviewer")
    phase = {"CMD-1": "W", "CMD-2": "W", "CMD-3": "B", "CMD-4": "B", "CMD-5": "run_total"}.get(p.get("decision_node"))
    for rid, run in c.runs.items():
        if p.get("plan_id") in run.get("plan_ids", []) and phase:
            cap = ((run.get("budgets") or {}).get(phase) or {}).get("max_input_tokens")
            R.check(cap is not None and (p.get("budget_tokens") or 0) <= cap, "E-PLAN-BUDGET", w,
                    f"budget_tokens {p.get('budget_tokens')} exceeds {rid} budgets.{phase}.max_input_tokens {cap}")


S2_RAN_STATES = ("SNAPSHOTTED", "EXECUTING", "EXECUTED", "INTERRUPTED", "RESTORED", "RESTORE_FAILED", "STOPPED")
S2_END_STATES = ("RESTORED", "RESTORE_FAILED")
G5_SKIP_OUTCOME = {"g5_rejected": "REJECTED", "g5_expired": "EXPIRED"}


def s2_not_run(R: Report, c: Ctx, rid, jid, job: dict, g5: dict | None, jw: str):
    """r12 external review: an S2 job that never ran (PENDING, AWAITING_G5, SKIPPED) has no sandbox, snapshot or restore
    event in the log, no snapshot_ref and no verified restore; one SKIPPED for its G5 names the G5 record of this job with
    the matching outcome (docs/03 §5.4: G5 REJECTED / NEEDS_INFO / EXPIRED -> skipped and recorded)."""
    audit = c.ix.audit_for(rid)
    evs = audit.data if audit and isinstance(audit.data, list) else []
    ran = [e.get("event_type") for e in evs if isinstance(e, dict) and (e.get("payload") or {}).get("job_id") == jid
           and e.get("event_type") in ("sandbox_job_start", "sandbox_job_end", "snapshot_created", "snapshot_restored", "restore_failed")]
    R.check(not ran and not job.get("snapshot_ref") and job.get("restore_verified") is not True, "E-RUN-S2", jw,
            f"S2 job {jid} is {job.get('status')}, so it never ran: no snapshot_ref, no verified restore and no sandbox or "
            f"snapshot events (the log has {ran})")
    want = G5_SKIP_OUTCOME.get(job.get("skip_reason"))  # type: ignore[arg-type]  # a value an earlier check or lookup ruled out as None; mypy cannot follow it
    if job.get("status") == "SKIPPED" and want:
        R.check(g5 is not None and g5.get("gate") == "G5" and g5.get("job_id") == jid and g5.get("outcome") == want, "E-RUN-S2", jw,
                f"S2 job {jid} was SKIPPED as {job.get('skip_reason')}, so its g5_record_id names this job's G5 record with outcome "
                f"{want} (got {(g5 or {}).get('outcome')})")


def snapshot_audit(R: Report, c: Ctx, rid, jid, job: dict, start, end, jw: str) -> bool | None:
    """E-RUN-S2 (review r12): the snapshot and the restore an S2 job claims are the snapshot service's anchored events, not
    the run record's word: exactly one snapshot_created naming the job's snapshot_ref, received before the job started.
    r11 read snapshot_ref / restore_verified / status from the run record only, so a run whose log says the restore failed was
    reported restored and COMPLETED (docs/02 B4: every snapshot restored; docs/03 §5: a failed restore -> FAILED).
    r12 external review: the restore is judged by the job's status. RESTORED: exactly one anchored snapshot_restored with
    verified true, after the job ended, no restore_failed, restore_verified true. RESTORE_FAILED: an anchored restore_failed,
    no verified snapshot_restored, restore_verified false (r12 rejected this honest record). Any other state that ran
    (INTERRUPTED, STOPPED, still executing): restore_verified follows the log. Returns True (restored), False (the restore
    failed) or None (not yet restored, or no log to judge)."""
    audit = c.ix.audit_for(rid)
    evs = audit.data if audit and isinstance(audit.data, list) else []
    if not evs or rid in c.broken_audit_runs:
        return None
    last = anchored_seqs(evs)
    mine = [(i + 1, e) for i, e in enumerate(evs) if isinstance(e, dict) and (e.get("payload") or {}).get("job_id") == jid]
    def of(kind):
        return [(i, e) for i, e in mine if e.get("event_type") == kind]
    snaps, restored, failed = of("snapshot_created"), of("snapshot_restored"), of("restore_failed")
    if R.check(len(snaps) == 1 and snaps[0][0] <= last and (snaps[0][1].get("payload") or {}).get("snapshot_ref") == job.get("snapshot_ref"),
               "E-RUN-S2", jw, f"{jid} needs exactly one anchored snapshot_created naming snapshot_ref {job.get('snapshot_ref')!r} "
               f"(the log has {len(snaps)})"):
        t = ts(R, snaps[0][1].get("ts"), jw)
        R.check(start is None or (t is not None and t <= start), "E-RUN-S2", jw, f"the snapshot of {jid} was taken after the job started")
    verified = [(i, e) for i, e in restored if (e.get("payload") or {}).get("verified") is True]
    status = job.get("status")
    if status == "RESTORE_FAILED" or (failed and status != "RESTORED"):
        R.check(bool(failed) and all(i <= last for i, _ in failed), "E-RUN-S2", jw,
                f"{jid} is {status}, so the log needs an anchored restore_failed (it has {len(failed)}); RESTORE_FAILED is the "
                "snapshot service's finding, not the run record's word")
        R.check(not verified, "E-RUN-S2", jw, f"{jid}: the log records both a verified snapshot_restored and restore_failed")
        R.check(job.get("restore_verified") is False, "E-RUN-S2", jw,
                f"{jid}: the restore failed, so restore_verified is false (got {job.get('restore_verified')!r})")
        return False
    if status == "RESTORED":
        R.check(not failed, "E-RUN-S2", jw, f"the audit log records restore_failed for {jid} (seq {[e.get('seq') for _, e in failed]}): "
                "the job is RESTORE_FAILED and the run FAILED, not restored")
        R.check(job.get("restore_verified") is True, "E-RUN-S2", jw, f"{jid} is RESTORED, so restore_verified is true")
        if R.check(len(restored) == 1 and len(verified) == 1 and restored[0][0] <= last, "E-RUN-S2", jw,
                   f"{jid} needs exactly one anchored snapshot_restored with verified true (the log has {len(restored)})"):
            t = ts(R, restored[0][1].get("ts"), jw)
            R.check(end is None or (t is not None and t >= end), "E-RUN-S2", jw, f"the restore of {jid} was recorded before the job ended")
        return True
    R.check(job.get("restore_verified") is (bool(verified) and verified[0][0] <= last), "E-RUN-S2", jw,
            f"{jid} is {status}: restore_verified {job.get('restore_verified')!r} does not match the log ({len(verified)} verified restore(s))")
    return True if verified else None


JOB_RAN_STATES = ("EXECUTED", "RESTORED", "RESTORE_FAILED")       # finished with a result (INTERRUPTED has none)
