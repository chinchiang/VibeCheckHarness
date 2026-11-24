# SPDX-License-Identifier: Apache-2.0
"""Check group over the W4 testcases (docs/02 W4): what a W4 test may be, its coverage of the approved requirements,
and where and when it ran.

Split out of checks.py (architecture refactor PR-D8, docs/adr/0003-split-checks.md). The text is moved verbatim; no
rule, error code or message changed. checks.GROUPS still lists the group in the same place.
"""
from __future__ import annotations

from . import derive
from .canonical import content_hash
from .checks_runs import COMPLETED_RUN_STATES
from .checks_testcases import access_cells_check
from .checks_trace import inventory_of_run
from .context import Ctx
from .report import Report, doc_guard, ts


# ============================================================== 12b W4 testcases
W4_CLUSTER_ORIGINS = ("white_box", "tool_only")


def g_w4_testcases(R: Report, c: Ctx):
    """v0.5 (BL-27, docs/02 W4, E-W4-TC): white-box tests run in Z2 against unit tests or a disposable local Postgres.
    - the run exists; every cluster is a white_box / tool_only cluster of that run;
    - requirement_ids and oracle.requirement_refs are approved at G1 (E-TC-REQ-UNAPPROVED); requirement_refs are
      requirement_ids; at least one reachability control (E-TC-CONTROLS); fail_k_min 1..n (E-TC-TRIALS);
    - local_rls has a database (disposable postgres, repo migrations of the run's inventory), other kinds none;
    - a W4 result runs a w4-testcase (not a black-box testcase) and names only the testcase's clusters."""
    approved = c.ix.approved_requirement_ids()
    for d in c.docs("w4-testcase"):
        with doc_guard(R, d.path):
            tc, w = d.data, d.path
            R.check(tc.get("run_id") in c.runs, "E-W4-TC", w, f"run {tc.get('run_id')!r} not found")
            for k in tc.get("cluster_ids") or []:
                cl = c.ix.first("cluster", cluster_id=k)
                R.check(cl is not None and cl.data.get("run_id") == tc.get("run_id") and cl.data.get("origin") in W4_CLUSTER_ORIGINS,
                        "E-W4-TC", w, f"{k} must be a {'/'.join(W4_CLUSTER_ORIGINS)} cluster of run {tc.get('run_id')}")
            o = tc.get("oracle") or {}
            reqs, refs = set(tc.get("requirement_ids") or []), set(o.get("requirement_refs") or [])
            R.check((reqs | refs) <= approved, "E-TC-REQ-UNAPPROVED", w,
                    f"requirements {sorted((reqs | refs) - approved)} are not approved at G1 (a W4 oracle cites only G1-approved items)")
            R.check(refs <= reqs, "E-W4-TC", w, f"oracle.requirement_refs {sorted(refs - reqs)} are not requirement_ids")
            ctls = [x for x in tc.get("controls") or [] if isinstance(x, dict)]
            R.check(any(x.get("kind") == "reachability" for x in ctls), "E-TC-CONTROLS", w,
                    "a W4 testcase needs at least one reachability control (the sink line is covered, the precondition reached)")
            ids = [x.get("control_id") for x in ctls]
            R.check(len(ids) == len(set(ids)), "E-TC-CONTROLS", w, f"duplicate control_id in {ids}")
            tr = tc.get("trials") or {}
            R.check(1 <= tr.get("fail_k_min", 1) <= tr.get("n", 1), "E-TC-TRIALS", w, "fail_k_min must be 1..n")
            access_cells_check(R, c, tc, w)
            db = (tc.get("environment") or {}).get("database")
            # v0.5 (review r7 1.3): a W4 test confirms only clusters in the files it exercises (as H-2 bound black-box
            # results to their threat's clusters); v0.5 BL-27 let an RLS test on a migration confirm a route cluster
            inv_files = {x.get("path") for x in (inventory_of_run(c, tc.get("run_id")) or {}).get("files") or [] if isinstance(x, dict)}
            targets = set(tc.get("target_files") or [])
            R.check(tc.get("kind") == "local_rls" or bool(targets), "E-W4-TC", w,
                    f"a {tc.get('kind')} test declares the files it exercises (target_files)")
            R.check(targets <= inv_files, "E-W4-TC", w, f"target_files {sorted(targets - inv_files)} are not files of the run's W0 inventory")
            covered = targets | set((db or {}).get("migrations") or [] if isinstance(db, dict) else [])
            for k in tc.get("cluster_ids") or []:
                cl = c.ix.first("cluster", cluster_id=k)
                f = ((cl.data.get("canonical_location") or {}) if cl else {}).get("file")
                R.check(cl is None or f in covered, "E-W4-TC", w,
                        f"{k} is in {f!r}, which this test does not exercise ({sorted(covered)})")
            if tc.get("kind") == "local_rls":
                files = {x.get("path") for x in (inventory_of_run(c, tc.get("run_id")) or {}).get("files") or [] if isinstance(x, dict)}
                if R.check(isinstance(db, dict), "E-W4-TC", w, "a local_rls test needs environment.database (a disposable local Postgres)"):
                    missing = [m for m in db.get("migrations") or [] if m not in files]  # type: ignore[union-attr]  # a value an earlier check or lookup ruled out as None; mypy cannot follow it
                    R.check(not missing, "E-W4-TC", w, f"migrations {missing} are not files of the run's W0 inventory")
            else:
                R.check(db is None, "E-W4-TC", w, f"only local_rls tests start a database (kind {tc.get('kind')})")
    for d in c.docs("run"):
        with doc_guard(R, d.path):
            w4_coverage(R, c, d.data, d.path, approved)
    for d in c.docs("testresult"):
        with doc_guard(R, d.path):
            tr, w = d.data, d.path
            if tr.get("phase") != "W4":
                continue
            borrowed = c.ix.first("testcase", testcase_id=tr.get("testcase_id"))
            R.check(borrowed is None, "E-W4-TC", w, f"W4 result runs black-box testcase {tr.get('testcase_id')}; W4 tests are w4-testcases")
            tc = c.ix.testcase_for(tr)
            if tc is not None:
                extra = sorted(set(tr.get("cluster_ids") or []) - set(tc.data.get("cluster_ids") or []))
                R.check(not extra, "E-W4-TC", w, f"cluster_ids {extra} are not clusters of {tc.data.get('testcase_id')}")
                R.check(tr.get("run_id") == tc.data.get("run_id"), "E-W4-TC", w, f"{tc.data.get('testcase_id')} belongs to run {tc.data.get('run_id')}")
            w4_execution(R, c, tr, w)
            # v0.7 (review r8, external review 6; docs/08 W4): the observations the oracle judged come from the harness process
            # (read-only DB connection, harness-side fake model, files read after the SUT exited), never from the SUT's own
            # output, which the SUT can forge; a sut-sourced result is declared as such and classifies as E_inc
            R.check(tr.get("observations_source") in ("harness", "sut"), "E-W4-OBSERVATION", w,
                    "a W4 result declares observations_source (harness / sut): where the oracle's observations were read from")


def w4_coverage(R: Report, c: Ctx, run: dict, w: str, approved: set):
    """v0.5 (BL-27, E-W4-COVERAGE; docs/02 W4 completion): once a non-Lane-A run has W4 output (a w4-testcase or a W4
    result) or seed threats (W5 ran), every G1-approved invariant of the run is cited by one of its w4-testcases or is
    marked MANUAL with a reason in run.w4_manual_requirements, not both; a MANUAL mark names a G1-approved invariant."""
    rid = run.get("run_id")
    manual = [m.get("requirement_id") for m in run.get("w4_manual_requirements") or [] if isinstance(m, dict)]
    inv = c.b.data("invariants") or {}
    invariants = {i.get("requirement_id") for i in inv.get("invariants") or [] if isinstance(i, dict)} & approved \
        if inv.get("run_id") == rid else set()
    for m in manual:
        R.check(m in invariants, "E-W4-COVERAGE", w, f"w4_manual_requirements names {m!r}, which is not a G1-approved invariant of {rid}")
    R.check(len(manual) == len(set(manual)), "E-W4-COVERAGE", w, f"w4_manual_requirements lists a requirement twice: {manual}")
    tcs = [t.data for t in c.docs("w4-testcase") if t.data.get("run_id") == rid]
    reached = bool(tcs) or any(r.data.get("run_id") == rid and r.data.get("phase") == "W4" for r in c.docs("testresult")) \
        or any(s.data.get("run_id") == rid for s in c.docs("seed-threats"))
    if run.get("run_kind") == "lane_a" or not reached:
        return
    if inv.get("run_id") != rid:
        # review r11: v0.7 took an empty invariant set for every run but the one invariants.yaml names, so a second
        # initial run was never checked; a follow-up / regression run reuses its parent's approved invariants (reuse[])
        parent = c.runs.get(run.get("parent_run_id")) or {}
        reused = inv.get("run_id") == parent.get("run_id") and content_hash(inv) in (run.get("reuse") or [])
        R.check(run.get("run_kind") in ("followup", "regression") and reused, "E-W4-COVERAGE", w,
                f"run {rid} reached W4 / W5 but has no G1 invariants of its own (invariants.yaml is run {inv.get('run_id')!r}) "
                "and does not reuse its parent's (reuse[] lacks the parent's invariants_ref)")
        return
    # v0.7 (review r10 W4): once the run is COMPLETED a w4-testcase covers its invariants only if it ran, i.e. it has a
    # W4 result (which E-W4-AUDIT backs with an anchored Z2 sandbox_job_end). v0.7 r9 counted a test written on paper
    if run.get("status") in COMPLETED_RUN_STATES:
        ran = {r.data.get("testcase_id") for r in c.docs("testresult") if r.data.get("run_id") == rid and r.data.get("phase") == "W4"}
        for t in tcs:
            R.check(t.get("testcase_id") in ran, "E-W4-COVERAGE", w,
                    f"w4-testcase {t.get('testcase_id')} never ran (no W4 result) in the completed run {rid}: it covers none of "
                    f"{t.get('requirement_ids')}; run it or mark them MANUAL with a reason")
    tested = {x for t in tcs for x in t.get("requirement_ids") or []}
    for x in sorted(invariants):  # type: ignore[type-var]  # the values are strings in a schema-valid document; mypy sees Any | None
        R.check((x in tested) != (x in manual), "E-W4-COVERAGE", w,
                f"G1 invariant {x}: " + ("both tested by a w4-testcase and marked MANUAL" if x in tested
                                         else "no w4-testcase cites it and it is not marked MANUAL (w4_manual_requirements)"))


def w4_execution(R: Report, c: Ctx, tr: dict, w: str):
    """v0.5 (BL-27, E-W4-AUDIT): a W4 result is backed by the Z2 sandbox run of its test, as a B4 result is by its job
    (E-JOB-AUDIT): exactly one W4 / Z2 sandbox_job_end names the result, for the same testcase and outcome, inside the
    anchored part of the log (an unanchored line is not yet countersigned, cf. V-7), and executed_at lies between that
    job's sandbox_job_start and sandbox_job_end. Without this a written W4 FAIL alone confirmed a cluster (R1)."""
    rid = tr.get("result_id")
    audit = c.ix.audit_for(tr.get("run_id"))
    evs = [e for e in (audit.data if audit else []) if isinstance(e, dict)]
    ends = [e for e in evs if e.get("event_type") == "sandbox_job_end" and (e.get("payload") or {}).get("result_id") == rid]
    if not R.check(len(ends) == 1, "E-W4-AUDIT", w,
                   f"{rid}: the audit log has {len(ends)} sandbox_job_end events naming it; a W4 result needs exactly one (its Z2 run)"):
        return
    e = ends[0]
    p = e.get("payload") or {}
    R.check(e.get("node") == "W4" and e.get("zone") == "Z2", "E-W4-AUDIT", w,
            f"{rid}: seq {e.get('seq')} is a {e.get('node')} / {e.get('zone')} event, not W4 / Z2")
    R.check(p.get("testcase_id") == tr.get("testcase_id"), "E-W4-AUDIT", w,
            f"{rid}: seq {e.get('seq')} names testcase {p.get('testcase_id')!r}, not {tr.get('testcase_id')!r}")
    R.check(p.get("outcome") == tr.get("outcome"), "E-W4-AUDIT", w,
            f"{rid}: outcome {tr.get('outcome')} != sandbox_job_end outcome {p.get('outcome')} (seq {e.get('seq')})")
    tc = c.ix.testcase_for(tr)
    for key, want in (derive.execution_pins(tc.data, tr) if tc else {}).items():
        R.check(p.get(key) == want, "E-W4-AUDIT", w, f"{rid}: sandbox_job_end (seq {e.get('seq')}) pins {key} {p.get(key)!r}, but what the "
                f"bundle holds hashes to {want!r}: the testcase, artifact or result changed after the run")
    anchored = max((i + 1 for i, x in enumerate(evs) if x.get("event_type") == "audit_anchor"), default=0)
    R.check(type(e.get("seq")) is int and e.get("seq") < anchored, "E-W4-AUDIT", w,  # type: ignore[operator]  # a value an earlier check or lookup ruled out as None; mypy cannot follow it
            f"{rid}: seq {e.get('seq')} is in the unanchored tail of the audit log; it cannot back a verdict yet")
    start = next((x for x in evs if x.get("event_type") == "sandbox_job_start"
                  and (x.get("payload") or {}).get("job_id") == p.get("job_id")), None)
    if R.check(start is not None, "E-W4-AUDIT", w, f"{rid}: no sandbox_job_start for job {p.get('job_id')!r}"):
        lo, hi, at = ts(R, start.get("ts"), w), ts(R, e.get("ts"), w), ts(R, tr.get("executed_at"), w)  # type: ignore[union-attr]  # a value an earlier check or lookup ruled out as None; mypy cannot follow it
        R.check(None not in (lo, hi, at) and lo <= at <= hi, "E-W4-AUDIT", w,
                f"{rid}: executed_at {tr.get('executed_at')} is outside its job {p.get('job_id')} ({start.get('ts')} .. {e.get('ts')})")  # type: ignore[union-attr]  # a value an earlier check or lookup ruled out as None; mypy cannot follow it
