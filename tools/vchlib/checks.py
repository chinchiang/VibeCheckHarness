# SPDX-License-Identifier: Apache-2.0
"""Semantic checks over the example bundle (v0.3).

Every check reports through `Report`: errors fail the run, warnings are printed only.
Each group is isolated: an unexpected exception in one group becomes E-INTERNAL instead of
crashing the validator (graceful handling of broken or unknown input).

Trust model [H]: the key registry (docs/examples/key-registry.yaml) is the ONLY source of
public keys. Its root signature is checked against the fingerprint pinned in toolkit.yaml.
Fingerprints and roles written anywhere else are claims that must agree with the registry.
Signatures are real Ed25519 over RFC 8785 JCS; the example keys are TEST ONLY fixtures.
"""
from __future__ import annotations

import re
import traceback


from . import adjudicate as adj
from . import derive, evidence, facets, llm_schema, safety, timeutil
from .bundle import Bundle, Doc
from .canonical import content_hash
from .checks_audit import g_audit
from .checks_calibration import BOUND_CLAIM_RE, g_calibration
from .checks_config import g_crosswalk, g_licenses, g_llm_schemas, g_toolkit
from .checks_engagement import (ANCHOR_LABEL, deployment, g_engagement,
                                profile)
from .checks_gates import g_gates
from .checks_integrity import g_derived, g_jcs, g_key_registry, g_persons, g_schemas
from .checks_models import g_models
from .checks_roe import g_roe, job_span, path_shape
from .checks_runs import COMPLETED_RUN_STATES, baseline_checks, g_runs, plan_checks
from .checks_signatures import g_signatures
from .checks_testcases import access_cells_check, access_matrix_cells, g_feedback, g_report_withdrawal, g_testcases
from .context import Ctx
from .report import (anchored_seqs, FINAL_STATUSES, M1_REQUIRED_SELFTESTS,
                     Report,
                     doc_guard, ts)
from .verdict import (derive_verdict, derived_no_eligible_verifier, eligible_verifier_families, g2_latest,
                      is_verifier_vote, members_at_vote, PHASE_ORDER, PRE_G3_PHASES, _resolving_event,
                      sarif_ref_problem, verdict_heads, verifier_template_controls, VERIFIER_TEMPLATE_ID, vote_model,
                      vote_terms)


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
                    missing = [m for m in db.get("migrations") or [] if m not in files]
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
    for x in sorted(invariants):
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
    R.check(type(e.get("seq")) is int and e.get("seq") < anchored, "E-W4-AUDIT", w,
            f"{rid}: seq {e.get('seq')} is in the unanchored tail of the audit log; it cannot back a verdict yet")
    start = next((x for x in evs if x.get("event_type") == "sandbox_job_start"
                  and (x.get("payload") or {}).get("job_id") == p.get("job_id")), None)
    if R.check(start is not None, "E-W4-AUDIT", w, f"{rid}: no sandbox_job_start for job {p.get('job_id')!r}"):
        lo, hi, at = ts(R, start.get("ts"), w), ts(R, e.get("ts"), w), ts(R, tr.get("executed_at"), w)
        R.check(None not in (lo, hi, at) and lo <= at <= hi, "E-W4-AUDIT", w,
                f"{rid}: executed_at {tr.get('executed_at')} is outside its job {p.get('job_id')} ({start.get('ts')} .. {e.get('ts')})")


def _tool_of(c: Ctx, cluster: dict, ref) -> str | None:
    """The tools.yaml tool (not the mode) whose W1 invocation produced a SARIF ref."""
    e, _ = _resolving_event(c, cluster, ref)
    entry = safety.registry_entry(c.tools, (e.get("payload") or {}).get("adapter")) if e else None
    return entry["tool"] if entry else None


def max_vote_round(c: Ctx, v: dict, cluster: dict) -> int | None:
    """r12: the highest round a vote of this verdict version can follow: 1 + the highest round of the run's CMD-2 plans
    whose artifact_stored event is anchored before the version's verdict_changed event (a member of round n + 1 needs a
    CMD-2 plan of round n, E-FINDING-ROUND). None when the version has no verdict_changed event (reported elsewhere).
    r11 read voted_after_round as declared, so a vote cast after a same-family member joined could claim an earlier round."""
    audit = c.ix.audit_for(cluster.get("run_id"))
    evs = audit.data if audit and isinstance(audit.data, list) else []
    last = anchored_seqs(evs)
    vseq = next((i + 1 for i, e in enumerate(evs) if isinstance(e, dict) and e.get("event_type") == "verdict_changed"
                 and (e.get("payload") or {}).get("verdict_id") == v.get("verdict_id")), None)
    if vseq is None:
        return None
    pinned = {(e.get("payload") or {}).get("plan_id"): i + 1 for i, e in enumerate(evs) if isinstance(e, dict)
              and e.get("event_type") == "artifact_stored" and (e.get("payload") or {}).get("artifact") == "commander-plan"
              and i + 1 <= last}
    rounds = [p.data.get("round") for p in c.docs("commander-plan") if p.data.get("decision_node") == "CMD-2"
              and p.data.get("plan_id") in pinned and pinned[p.data.get("plan_id")] < vseq and type(p.data.get("round")) is int]
    return 1 + max(rounds, default=0)


# review r11: the arrow may be ->, → or =>, the status is read case-insensitively, and only the LAST arrow of an item is
# the claim (an earlier one may sit inside "not ->X" or "would give ->X but"); a number may be written `S = 1.0`,
# `S: 1.0`, `S≈1.0`, `θ_confirm=…`, with a sign, and anything else after `=` (an exponent, a comma, a hex digit) is an error
TRACE_STATUS = re.compile(r"(?:->|→|=>)\s*(?:cap\s+)?([A-Za-z_]+)")
TRACE_STATUSES = ("REJECTED", "UNCORROBORATED", "LIKELY", "DISPUTED", "CONFIRMED_CORROBORATED", "CONFIRMED_EXECUTABLE", "FIXED")
TRACE_NUMBER = re.compile(r"(?<![A-Za-z0-9_])(score|S|theta_confirm|theta_reject|θ_confirm|θ_reject|independent_sources|independent_families|"
                          r"weighted_support|weighted_refute|valid_votes)\s*[=:≈]\s*([+\-−]?[0-9A-Za-z.]*)")
TRACE_PLAIN = re.compile(r"^[+\-−]?[0-9]+(?:\.[0-9]+)?$")


def weighted_vote_counts(c: Ctx, v: dict, cluster: dict) -> dict[str, int]:
    """Weighted-valid votes (recomputed, as verdict_inputs) by stance, for the counts a rule_trace text may state."""
    stances = [x.get("stance") for x in v.get("votes", []) if vote_terms(c.ix, x, cluster, v.get("calibration_version"))[2]]
    return {"weighted_support": stances.count("SUPPORT"), "weighted_refute": stances.count("REFUTE"), "valid_votes": len(stances)}


def trace_text_problems(items: list, out: adj.Outcome, x: adj.Inputs, counts: dict[str, int]) -> list[str]:
    """BL-01: the free text after `R<n>:` may explain, but what it states must be true. A `->STATUS` (or `->cap STATUS`)
    must be the status that rule leaves (adjudicate.trace_statuses), and a `name=number` for a derived quantity must
    equal the recomputed value (to the precision written). Other text is not interpreted."""
    actual = {"score": x.score, "S": x.score, "theta_confirm": x.theta_confirm, "theta_reject": x.theta_reject,
              "independent_sources": out.sources, "independent_families": x.independent_families, **counts}
    problems = []
    for item, status in zip(items, adj.trace_statuses(out)):
        rule, _, text = str(item).partition(":")
        arrows = [m.group(1) for m in TRACE_STATUS.finditer(text) if m.group(1).upper() in TRACE_STATUSES]
        if arrows and arrows[-1].upper() != status:
            problems.append(f"{rule} text says ->{arrows[-1]} but {rule} leaves {status}")
        for m in TRACE_NUMBER.finditer(text):
            name, raw = m.group(1).replace("θ_", "theta_"), m.group(2)
            if not TRACE_PLAIN.match(raw):
                problems.append(f"{rule} text says {name}={raw!r}, which is not a plain decimal")
                continue
            want = actual[name]
            val = float(raw.replace("−", "-"))
            tol = 0.5 * 10 ** -(len(raw.split(".")[1]) if "." in raw else 0) + 1e-9
            if want is None or abs(val - want) > tol:
                problems.append(f"{rule} text says {name}={raw} but the recomputed value is {want}")
    return problems


def g_verdicts(R: Report, c: Ctx):
    for d in c.docs("cluster"):
        for field in ("sarif_refs", "tool_report_refs"):
            for ref in d.data.get(field) or []:
                prob = sarif_ref_problem(c, d.data, ref)
                R.check(prob is None, "E-SARIF-REF", d.path, f"{d.data.get('cluster_id')} {field}: {prob}")
    for d in c.docs("verdict"):
        with doc_guard(R, d.path):
            v, w = d.data, d.path
            dv = derive_verdict(c, v)
            if not R.check(dv is not None, "E-TRACE", w, f"cluster {v.get('cluster_id')} not found"):
                continue
            # self-declared rule inputs are cross-checked against the derived values (docs/05 §4.2) [H]
            dd = dv.diversity_degraded
            R.check(v.get("diversity_degraded") is dd, "E-VERDICT-DIVERSITY", w,
                    f"diversity_degraded {v.get('diversity_degraded')} but the weighted-valid votes' registry families give {dd} "
                    f"(eligible verifier families {sorted(eligible_verifier_families(c, dv.cluster))})")
            ne = dv.no_eligible_verifier
            R.check(v.get("no_eligible_verifier") is ne, "E-VERDICT-NOELIGIBLE", w,
                    f"no_eligible_verifier {v.get('no_eligible_verifier')} but agents.yaml verifiers outside the cluster's families/lineages give {ne}")
            tcx = dv.tool_corroboration
            R.check(sorted(v.get("tool_corroboration") or []) == tcx, "E-VERDICT-TOOLCORR", w,
                    f"tool_corroboration {v.get('tool_corroboration')} != derived {tcx} (audit-backed SARIF refs of calibrated high-precision rules)")
            tsx = dv.tool_signal
            R.check(sorted(v.get("tool_signal") or []) == tsx, "E-VERDICT-TOOLSIGNAL", w,
                    f"tool_signal {v.get('tool_signal')} != derived {tsx} (other audit-backed SARIF refs + E_fail_u results)")
            srcx = dv.independent_sources
            R.check(v.get("independent_sources") == srcx, "E-VERDICT-SOURCES", w,
                    f"independent_sources {v.get('independent_sources')} != derived {srcx} (independent families + weak SARIF + independently authored E_fail_u)")
            pv = dv.provisional
            R.check(v.get("provisional") is pv, "E-VERDICT-PROVISIONAL", w,
                    f"provisional {v.get('provisional')} != derived {pv} (no calibration version, theta_confirm null, or every eligible "
                    "verifier model has weight 0 in the cluster's bucket)")
            R.check(v.get("rule_version") == adj.RULE_VERSION, "E-VERDICT-RULE-VERSION", w,
                    f"rule_version {v.get('rule_version')!r} is not the adjudicator's {adj.RULE_VERSION!r}")
            # r14 (05-v0.15, internal review B7, user decision): a carried-in cluster has no members of its own to verify;
            # its status is decided by regression evidence only (R14 / R16), never by votes (a lone REFUTE made it
            # DISPUTED, a stronger one REJECTED and then R16 lifted it back to the source status)
            if dv.cluster.get("carried_from"):
                R.check(not v.get("votes") and not v.get("missing_votes"), "E-VERDICT-VOTE", w,
                        f"{v.get('cluster_id')} is a carried-in cluster (carried_from): it accepts no votes and no missing_votes; "
                        "its status comes from the regression tests (docs/05 §4.2 R14 / R16)")
            out = dv.outcome
            R.check(v.get("status") == out.status, "E-VERDICT-STATUS", w, f"status {v.get('status')} but the rules give {out.status} (row {out.row})")
            R.check(v.get("status_cap") == out.status_cap, "E-VERDICT-STATUS", w, f"status_cap {v.get('status_cap')} != {out.status_cap}")
            R.check(v.get("advisory") is out.advisory, "E-VERDICT-STATUS", w, f"advisory {v.get('advisory')} != {out.advisory}")
            kinds = {a.get("kind") for a in v.get("annotations", [])}
            R.check(kinds == out.annotations, "E-VERDICT-ANNOTATIONS", w, f"annotations {sorted(kinds)} != {sorted(out.annotations)}")
            # D6 (05-v0.16, user decision): a PASS without a positive control (E_pass_weak) supports no statistical bound.
            # The oracle was never shown to fail, so "upper bound 4.9%" measures whether the target wrote its log, and a
            # reader takes it for a security guarantee. A pattern check: it stops the stated bound, not a paraphrase
            if "E_pass" not in dv.inputs.evidence:
                for a in v.get("annotations", []):
                    if isinstance(a, dict) and a.get("kind") == "test_not_reproduced" and BOUND_CLAIM_RE.search(str(a.get("reason") or "")):
                        R.check(False, "E-VERDICT-ANNOTATIONS", w,
                                f"test_not_reproduced reason {a.get('reason')!r} states a statistical bound, but no linked PASS has a "
                                "positive control (E_pass_weak): say that no violation was observed and the oracle was not verified")
            rules = [str(x).split(":", 1)[0] for x in v.get("rule_trace", [])]
            if R.check(rules == out.rules, "E-VERDICT-TRACE", w, f"rule_trace rules {rules} != {out.rules}"):
                x = dv.inputs
                for msg in trace_text_problems(v.get("rule_trace", []), out, x, weighted_vote_counts(c, v, dv.cluster)):
                    R.check(False, "E-VERDICT-TRACE", w, msg)
            if v.get("status") == "CONFIRMED_EXECUTABLE":
                p = v.get("executable_proof") or {}
                ib = p.get("interpretation_confirmed_by")
                # a pre-registered deterministic interpretation needs no analyst (v0.3); an analyst, if any, is cross-family
                R.check(ib is None or (isinstance(ib, dict) and ib.get("family") not in dv.cluster.get("families", [])), "E-VERDICT-PROOF", w,
                        "executable proof interpretation must come from another family")
            for vt in v.get("votes", []):
                a = c.agents.get(vt.get("voter_agent_id")) if isinstance(vt.get("voter_agent_id"), str) else None
                R.check(is_verifier_vote(c.ix, vt), "E-VERDICT-VOTER-ROLE", w,
                        f"vote by {vt.get('voter_agent_id')!r} (agents.yaml role {(a or {}).get('role')!r}): only verifier-role agents "
                        "may vote; the vote is ignored for weighted_valid, score, support/refute and diversity")
                m = vote_model(c, vt)
                if R.check(m is not None, "E-VERDICT-VOTE", w,
                           f"vote by {vt.get('voter_agent_id')!r} with model {vt.get('voter_model_key')!r} does not resolve through agents.yaml / models.yaml"):
                    R.check(vt.get("voter_family") == m.get("family") and vt.get("voter_lineage") == m.get("lineage"), "E-VERDICT-VOTE", w,
                            f"vote by {vt.get('voter_agent_id')}: voter_family/lineage {vt.get('voter_family')}/{vt.get('voter_lineage')} "
                            f"!= registry {m.get('family')}/{m.get('lineage')}")
                if vt.get("valid"):
                    # r12: as verdict.vote_valid, against the members when the vote was cast (r11 R15); r11 kept the current
                    # members here, so the bundle r11 was built for (a refute cast before a same-family member joined)
                    # could satisfy neither E-DERIVED (valid true) nor this check
                    fams_v, lins_v = members_at_vote(c.ix, vt, dv.cluster)
                    R.check(vt.get("voter_family") not in fams_v
                            and c.ix.lineage_root(vt.get("voter_lineage")) not in c.ix.lineage_roots(lins_v),
                            "E-VERDICT-VOTE", w, f"self-review vote by {vt.get('voter_agent_id')} counted as valid (same family or base lineage)")
                    bound = max_vote_round(c, v, dv.cluster)
                    R.check(bound is None or type(vt.get("voted_after_round")) is not int or vt["voted_after_round"] <= bound,
                            "E-VERDICT-VOTE", w,
                            f"vote by {vt.get('voter_agent_id')}: voted_after_round {vt.get('voted_after_round')!r} but only rounds up to "
                            f"{bound} were dispatched (anchored CMD-2 plans) before this verdict version was recorded")
                anon, rand = verifier_template_controls(c.ix, dv.cluster)
                R.check(vt.get("anonymized") is anon and vt.get("order_randomized") is rand, "E-VERDICT-VOTE", w,
                        f"vote by {vt.get('voter_agent_id')}: anonymized/order_randomized {vt.get('anonymized')}/{vt.get('order_randomized')} "
                        f"must equal the run's {VERIFIER_TEMPLATE_ID} template ({anon}/{rand}); a vote cannot declare them")
            if v.get("supersedes_verdict_id"):
                old = c.ix.first("verdict", verdict_id=v["supersedes_verdict_id"])
                R.check(old is not None and old.data.get("cluster_id") == v.get("cluster_id"), "E-TRACE", w, "supersedes a verdict of another cluster")
            R.check(v.get("calibration_version") == c.calibration.get("calibration_version"), "E-VERDICT-CALIBRATION", w, "calibration_version differs")
    verdict_chains(R, c)


def verdict_chains(R: Report, c: Ctx):
    """v0.5 (review 2026-10-25 V-4, V-12): the versions of a cluster form one linear chain in phase order.

    V-4 (E-VERDICT-CHAIN): no self-reference, no cycle, no fork (a version superseded twice), exactly one latest
    version, and a superseded version of the same run. A cycle used to drop the cluster from verdict_counts and the
    report queues without an error.
    V-12 (E-VERDICT-PHASE): readjudicated_by cannot be back-dated to switch off the test-evidence links:
    black-box clusters only have B5 versions; a W3 version supersedes nothing; phases never go backwards along the
    chain; and a version received (verdict_changed ts) after a W4 / B4 result of its cluster was executed is at
    least W4_readjudicate / B5_readjudicate."""
    by_cluster: dict = {}
    for d in c.docs("verdict"):
        by_cluster.setdefault(d.data.get("cluster_id"), []).append(d)
    for cid, docs in by_cluster.items():
        ids = {d.data.get("verdict_id"): d for d in docs}
        cl = c.ix.first("cluster", cluster_id=cid)
        cluster = cl.data if cl else {}
        superseded_by: dict = {}
        for d in docs:
            v, w = d.data, d.path
            s = v.get("supersedes_verdict_id")
            if s is None:
                continue
            R.check(s != v.get("verdict_id"), "E-VERDICT-CHAIN", w, f"{v.get('verdict_id')} supersedes itself")
            R.check(s not in superseded_by, "E-VERDICT-CHAIN", w,
                    f"{s} is superseded by both {superseded_by.get(s)} and {v.get('verdict_id')} (the chain forks)")
            superseded_by.setdefault(s, v.get("verdict_id"))
            old = ids.get(s)                                         # same cluster_id, so the same run (E-TRACE otherwise)
            if old is not None and s != v.get("verdict_id"):
                R.check(PHASE_ORDER.get(old.data.get("readjudicated_by"), -1) <= PHASE_ORDER.get(v.get("readjudicated_by"), -1),
                        "E-VERDICT-PHASE", w, f"{v.get('verdict_id')} ({v.get('readjudicated_by')}) supersedes the later-phase "
                        f"{s} ({old.data.get('readjudicated_by')}): phases go W3 -> G2_apply -> W4 -> B5")
        for d in docs:                                               # cycles of two or more versions
            seen, cur = [], d.data.get("verdict_id")
            while cur in ids and cur not in seen:
                seen.append(cur)
                cur = ids[cur].data.get("supersedes_verdict_id")
            if cur == d.data.get("verdict_id") and len(seen) > 1:
                R.error("E-VERDICT-CHAIN", d.path, f"{d.data.get('verdict_id')} is on a supersedes cycle {' -> '.join(seen + [cur])}")
        heads = [i for i in ids if i not in superseded_by]
        R.check(len(heads) == 1, "E-VERDICT-CHAIN", docs[0].path,
                f"cluster {cid} must have exactly one latest verdict version, got {sorted(map(str, heads))}")
        # BL-60: a G2 rejection is applied by a post-G2 version (G2_apply, or a later W4 / B5 one), which R10 decides.
        # v0.7 r10 accepted a rejected cluster whose latest version was still the W3 one, so the report showed it with
        # its pre-G2 status (found while building the `edge` variant bundle)
        if len(heads) == 1 and g2_latest(c, cluster)[1] == "reject":
            head = ids[heads[0]].data
            R.check(head.get("readjudicated_by") != "W3_adjudicate", "E-VERDICT-G2", ids[heads[0]].path,
                    f"G2 rejected {cid}, but its latest verdict {head.get('verdict_id')} is the W3 version: the rejection needs "
                    "a G2_apply version (docs/05 R10)")
        audit = c.ix.audit_for(cluster.get("run_id"))
        received = {(e.get("payload") or {}).get("verdict_id"): e.get("ts") for e in (audit.data if audit else [])
                    if isinstance(e, dict) and e.get("event_type") == "verdict_changed"}
        results = [r.data for r in c.docs("testresult") if r.data.get("run_id") == cluster.get("run_id")
                   and cid in (r.data.get("cluster_ids") or [])]
        for d in docs:
            v, w = d.data, d.path
            phase = v.get("readjudicated_by")
            if cluster.get("origin") == "black_box":
                R.check(phase == "B5_readjudicate", "E-VERDICT-PHASE", w,
                        f"{v.get('verdict_id')}: a black-box cluster only exists after B4, so its versions are B5_readjudicate, not {phase}")
            if phase == "W3_adjudicate":
                R.check(v.get("supersedes_verdict_id") is None, "E-VERDICT-PHASE", w,
                        f"{v.get('verdict_id')}: a W3_adjudicate version is the first version; it supersedes nothing")
            # v0.7 (review r9 phase): and the first version of a white-box or tool-only cluster is W3_adjudicate. v0.6 let it
            # be labelled G2_apply, which switched off the G2 routing check (E-PIPELINE reads the W3 version)
            if v.get("supersedes_verdict_id") is None and cluster.get("origin") != "black_box":
                R.check(phase == "W3_adjudicate", "E-VERDICT-PHASE", w,
                        f"{v.get('verdict_id')} is the first version of {cid}, so it is W3_adjudicate, not {phase}")
            at = received.get(v.get("verdict_id"))
            if at is None:
                continue
            for r in results:
                need = {"W4": "W4_readjudicate", "B4": "B5_readjudicate"}.get(r.get("phase"))
                if need and timeutil.sort_key(r.get("executed_at")) < timeutil.sort_key(at):
                    R.check(PHASE_ORDER.get(phase, -1) >= PHASE_ORDER[need], "E-VERDICT-PHASE", w,
                            f"{v.get('verdict_id')} was received at {at}, after {r.get('result_id')} ({r.get('phase')}) ran at "
                            f"{r.get('executed_at')}: it must be at least {need}, not {phase}")
                # v0.5 (review r7 1.2): a B5 version that counts a B4 result is received after that result's job ended
                if phase == "B5_readjudicate" and r.get("phase") == "B4" and r.get("job_id"):
                    _, end = job_span(c, cluster.get("run_id"), r.get("job_id"))
                    if end is not None:
                        R.check(end < timeutil.parse_dt(at), "E-VERDICT-PHASE", w,
                                f"{v.get('verdict_id')} was received at {at}, before job {r.get('job_id')} of {r.get('result_id')} "
                                f"ended at {end.isoformat()}")


# ============================================================== 14 traceability
def cluster_origin(R: Report, c: Ctx, d: Doc):
    """E-CLUSTER-ORIGIN (A2): white_box clusters need members, a source-code location and no threat_id;
    black_box clusters come from a threat without source cluster and use the endpoint as location."""
    k, w = d.data, d.path
    loc = k.get("canonical_location") or {}
    R.check(k.get("origin") == "tool_only" or not k.get("tool_report_refs"), "E-CLUSTER-ORIGIN", w,
            "tool_report_refs is only set on tool_only clusters")
    # v0.7 (review r8 F5): the rubric severity (docs/08 §11.17) is derived; it routes G2 and the report, the findings' own is advisory
    want = derive.rubric_severity(c.ix, k)
    R.check(k.get("severity") == want, "E-CLUSTER-SEVERITY", w,
            f"severity must be the rubric severity {want} (inputs {derive.rubric_inputs(c.ix, k)}), got {k.get('severity')!r}")
    if k.get("origin") == "black_box":
        t = c.ix.first("threat", threat_id=k.get("threat_id")) if k.get("threat_id") else None
        R.check(t is not None and t.data.get("source_cluster_id") is None, "E-CLUSTER-ORIGIN", w,
                f"black_box cluster needs a threat_id of a threat without source_cluster_id (got {k.get('threat_id')!r})")
        R.check(isinstance(loc.get("endpoint"), dict), "E-CLUSTER-ORIGIN", w, "black_box cluster needs canonical_location.endpoint")
        ep = loc.get("endpoint") or {}
        tc_ok = any(t2.data.get("threat_id") == k.get("threat_id") and any(
            r.get("target_id") == ep.get("target_id") and r.get("method") == ep.get("method") and r.get("path") == ep.get("path_template")
            for r in t2.data.get("request_allowlist") or []) for t2 in c.docs("testcase"))
        R.check(tc_ok, "E-CLUSTER-ORIGIN", w, "canonical_location.endpoint must be a request of a testcase of the cluster's threat")
    elif k.get("origin") == "tool_only":
        # v0.5 (BL-13): W3 clustered W1 tool results only. No LLM member may be listed (none may be invented to pass the
        # flow), and the location comes from the SARIF results, which sarif_location_problem binds to the cluster key
        R.check(not any(k.get(x) for x in ("member_finding_ids", "families", "lineages", "independent_families")),
                "E-CLUSTER-ORIGIN", w, "tool_only cluster has no member findings, families, lineages or independent families")
        R.check(k.get("threat_id") is None, "E-CLUSTER-ORIGIN", w, "threat_id is only set on black_box clusters")
        R.check(all(isinstance(loc.get(x), str) for x in ("file", "symbol")), "E-CLUSTER-ORIGIN", w,
                "tool_only cluster needs canonical_location file and symbol (from its tool results)")
        reports = [r for r in k.get("tool_report_refs") or [] if sarif_ref_problem(c, k, r) is None]
        R.check(bool(reports), "E-CLUSTER-ORIGIN", w,
                "tool_only cluster needs at least one tool_report_refs entry that resolves to a W1 tool result (E-SARIF-REF)")
        # the reporting result is the report, not corroboration (docs/08 §11.2): only another tool's result at the same
        # location may sit in sarif_refs and count as a signal
        reporters = {_tool_of(c, k, r) for r in reports}
        same = [r for r in k.get("sarif_refs") or [] if r in (k.get("tool_report_refs") or []) or _tool_of(c, k, r) in reporters]
        R.check(not same, "E-CLUSTER-ORIGIN", w,
                f"sarif_refs {same} come from the tool that reported the cluster ({sorted(map(str, reporters))}); a report is not its own corroboration")
    else:
        if k.get("carried_from") is None:               # v0.7: a carried cluster has no members of its own (E-CLUSTER-CARRY)
            R.check(bool(k.get("member_finding_ids")) and bool(k.get("families")) and bool(k.get("lineages")), "E-CLUSTER-ORIGIN", w,
                    "white_box cluster needs member findings, families and lineages")
        R.check(k.get("threat_id") is None, "E-CLUSTER-ORIGIN", w, "threat_id is only set on black_box clusters")
        R.check(all(isinstance(loc.get(x), (str, dict)) for x in ("file", "symbol", "sink")), "E-CLUSTER-ORIGIN", w,
                "white_box cluster needs canonical_location file, symbol and sink")
    # v0.7 (review r8, external review 5; docs/02 §1.6): a cluster a followup / regression run carries in is this run's own
    # instance (its own id, run_id this run) pointing at the parent's cluster by carried_from; the fingerprint is the
    # cross-run identity. v0.6 said "keep the original id", which a per-run cluster could not do
    cf = k.get("carried_from")
    run = c.runs.get(k.get("run_id")) or {}
    if isinstance(cf, dict):
        src = c.ix.first("cluster", cluster_id=cf.get("cluster_id"), run_id=cf.get("run_id"))
        R.check(run.get("run_kind") in ("followup", "regression") and cf.get("run_id") == run.get("parent_run_id"), "E-CLUSTER-CARRY", w,
                f"carried_from names run {cf.get('run_id')}, which is not the parent of this {run.get('run_kind')} run")
        R.check(src is not None and src.data.get("fingerprint") == cf.get("fingerprint") == k.get("fingerprint"), "E-CLUSTER-CARRY", w,
                f"carried_from must name a cluster of the parent run with this cluster's fingerprint {k.get('fingerprint')}")
        R.check(src is None or (k.get("cwe_bucket") == src.data.get("cwe_bucket") and k.get("families") == src.data.get("families")
                                and k.get("lineages") == src.data.get("lineages")), "E-CLUSTER-CARRY", w,
                "a carried cluster keeps the source's bucket, families and lineages")
        # v0.7 (review r9 members): a carried cluster skips the evidence binding (its evidence is the source's), so it has
        # no member findings of its own; v0.6 let findings be attached to it unchecked and counted their families
        R.check(not k.get("member_finding_ids"), "E-CLUSTER-CARRY", w,
                f"a carried cluster has no member findings of its own (got {k.get('member_finding_ids')}): its members are the "
                "source cluster's, and new findings of this run form a cluster of their own")
    elif run.get("run_kind") in ("followup", "regression"):
        twins = [x.data.get("cluster_id") for x in c.docs("cluster") if x.data.get("run_id") == run.get("parent_run_id")
                 and x.data.get("fingerprint") == k.get("fingerprint")]
        R.check(not twins, "E-CLUSTER-CARRY", w,
                f"the parent run has {twins} with the same fingerprint: carry it with carried_from instead of a new, unlinked cluster")


def _evidence_sites(c: Ctx, cluster: dict) -> tuple[list[tuple[str, int, int]], list[str]]:
    """(file, first line, last line) of every member's evidence, and the members' CWEs. code_snippet: its own range;
    inventory_fact: the source {file, line} of the nearest inventory object above fact_ref (e.g. /db/tables/0)."""
    inv = inventory_of_run(c, cluster.get("run_id")) or {}
    sites, cwes = [], []
    for fid in cluster.get("member_finding_ids") or []:
        f = c.ix.finding(fid) or {}
        cwes += [x for x in f.get("cwe") or [] if isinstance(x, str)]
        for e in f.get("evidence") or []:
            if not isinstance(e, dict):
                continue
            if e.get("kind") == "code_snippet" and isinstance(e.get("line_start"), int):
                end = e.get("line_end") if isinstance(e.get("line_end"), int) else e["line_start"]
                sites.append((e.get("file"), e["line_start"], end))
            elif e.get("kind") == "inventory_fact" and isinstance(e.get("fact_ref"), str):
                parts = e["fact_ref"].split("/")[1:]
                while parts:
                    node = evidence.resolve_pointer(inv, "/" + "/".join(parts))
                    src = node.get("source") if isinstance(node, dict) else None
                    if isinstance(src, dict) and isinstance(src.get("file"), str):
                        line = src.get("line") if isinstance(src.get("line"), int) else 0
                        sites.append((src["file"], line, line))
                        break
                    parts.pop()
    return sites, cwes


def cluster_binding(R: Report, c: Ctx, d: Doc):
    """v0.5 (review 2026-10-25 V-8): a white-box cluster's key is bound to its members' evidence, so a cluster cannot
    take another cluster's location (and with it the other cluster's SARIF refs, D1) or a bucket of its choosing.
    - canonical_location.file is a member evidence file; the sink lies in a member evidence range (same file);
      a symbol written file::name starts with that file;
    - cwe_bucket is the bucket (facets.CWE_BUCKETS) of a member CWE, when any member CWE is listed there;
    - no two clusters of a run share a fingerprint.
    tool_only clusters (BL-13) have no member evidence; their key is bound to the SARIF results instead."""
    k, w = d.data, d.path
    same = [x.path for x in c.docs("cluster") if x is not d and x.data.get("run_id") == k.get("run_id")
            and k.get("fingerprint") and x.data.get("fingerprint") == k.get("fingerprint")]
    R.check(not same, "E-CLUSTER-BINDING", w, f"{k.get('cluster_id')}: fingerprint shared with {same} in the same run")
    # v0.5 (review r7 1.6): a finding is a member of one cluster of its run, so its family is counted once
    for fid in k.get("member_finding_ids") or []:
        also = sorted(x.data.get("cluster_id") for x in c.docs("cluster") if x is not d and x.data.get("run_id") == k.get("run_id")
                      and fid in (x.data.get("member_finding_ids") or []))
        R.check(not also, "E-CLUSTER-BINDING", w, f"{k.get('cluster_id')}: member {fid} is also a member of {also}")
    if k.get("origin") in ("black_box", "tool_only"):         # tool_only: bound to its SARIF results (sarif_location_problem)
        return
    loc = k.get("canonical_location") or {}
    sites, cwes = _evidence_sites(c, k)
    files = {s[0] for s in sites}
    R.check(loc.get("file") in files, "E-CLUSTER-BINDING", w,
            f"{k.get('cluster_id')}: canonical_location.file {loc.get('file')!r} is not a member evidence file {sorted(files)}")
    sink = loc.get("sink")
    if isinstance(sink, dict):
        R.check(any(f == sink.get("file") and a <= (sink.get("line") or -1) <= b for f, a, b in sites), "E-CLUSTER-BINDING", w,
                f"{k.get('cluster_id')}: sink {sink.get('file')}:{sink.get('line')} is outside every member evidence range {sites}")
    sym = loc.get("symbol")
    if isinstance(sym, str) and "::" in sym:
        R.check(sym.split("::", 1)[0] == loc.get("file"), "E-CLUSTER-BINDING", w,
                f"{k.get('cluster_id')}: symbol {sym!r} does not belong to canonical_location.file {loc.get('file')!r}")
    buckets = {facets.CWE_BUCKETS[x] for x in cwes if x in facets.CWE_BUCKETS}
    if buckets:
        R.check(k.get("cwe_bucket") in buckets, "E-CLUSTER-BINDING", w,
                f"{k.get('cluster_id')}: cwe_bucket {k.get('cwe_bucket')!r} is not the bucket of any member CWE {sorted(set(cwes))} -> {sorted(buckets)}")
    else:
        R.warn("W-CLUSTER-BUCKET", w, f"{k.get('cluster_id')}: no member CWE {sorted(set(cwes))} is in facets.CWE_BUCKETS; cwe_bucket not checked")


def inventory_of_run(c: Ctx, run_id) -> dict | None:
    d = c.ix.first("inventory", run_id=run_id)
    return d.data if d else None


def finding_round(R: Report, c: Ctx, d: Doc):
    """v0.5 (review 2026-10-25 §4.3, E-FINDING-ROUND): reporter.round decides independence (only round-1 members count,
    derive.independent_families), so it is derived from the run's commander plans instead of trusted: round 1 = the
    CMD-1 plan dispatched this agent on this slice; round n > 1 = a CMD-2 plan of round n - 1 dispatched this agent
    (extra_dispatch). Lane A runs have no commander and are not checked."""
    f, w = d.data, d.path
    run = c.runs.get(f.get("run_id")) or {}
    if run.get("run_kind") == "lane_a":
        return
    rep = f.get("reporter") or {}
    agent, rnd = rep.get("agent_id"), rep.get("round")
    plans = [p.data for p in c.docs("commander-plan") if p.data.get("plan_id") in (run.get("plan_ids") or [])]
    if rnd == 1:
        ok = any(p.get("decision_node") == "CMD-1" and any(s.get("slice_id") == f.get("slice_id") and agent in (s.get("agents") or [])
                                                          for s in p.get("slices") or []) for p in plans)
        why = f"no CMD-1 plan of run {f.get('run_id')} dispatched {agent} on slice {f.get('slice_id')}"
    else:
        ok = isinstance(rnd, int) and any(p.get("decision_node") == "CMD-2" and p.get("round") == rnd - 1 and any(
            agent in (x.get("agents") or []) for x in p.get("extra_dispatch") or []) for p in plans)
        why = f"no CMD-2 plan of round {rnd - 1 if isinstance(rnd, int) else '?'} dispatched {agent}"
    R.check(ok, "E-FINDING-ROUND", w, f"{f.get('finding_id')}: reporter.round {rnd!r} is not derivable: {why}")


def finding_evidence(R: Report, c: Ctx, d: Doc):
    """B1: evidence kinds, inventory facts recomputed against the run's W0 inventory, status from matches."""
    f, w = d.data, d.path
    inv = inventory_of_run(c, f.get("run_id"))
    for i, ev in enumerate(f.get("evidence") or []):
        if not isinstance(ev, dict):
            continue
        probs = evidence.shape_problems(ev)
        R.check(not probs, "E-FINDING-EVIDENCE", w, f"evidence[{i}]: {'; '.join(probs)}")
        if ev.get("kind") == "inventory_fact":
            if not R.check(inv is not None and evidence.resolves(inv, ev.get("fact_ref")), "E-INVENTORY-REF", w,
                           f"evidence[{i}].fact_ref {ev.get('fact_ref')!r} does not resolve in the W0 inventory of {f.get('run_id')}"):
                continue
            want = evidence.match_fact(inv, ev)
            R.check(ev.get("match") == want, "E-FINDING-MATCH", w,
                    f"evidence[{i}].match {ev.get('match')} but the inventory fact gives {want}")
        if ev.get("kind") == "code_snippet":
            sl = c.ix.first("slice", slice_id=f.get("slice_id"))
            files = {x.get("path") for x in (sl.data.get("files") if sl else None) or [] if isinstance(x, dict)}
            R.check(sl is None or ev.get("file") in files, "E-FINDING-EVIDENCE", w,
                    f"evidence[{i}].file {ev.get('file')!r} is not a file of the finding's slice (v0.4: a snippet can only be "
                    "matched against the redacted slice the reviewer saw)")
        if ev.get("kind") == "config_fact" and inv is not None:
            R.check(ev.get("file") in {x.get("path") for x in inv.get("files") or []}, "E-INVENTORY-REF", w,
                    f"evidence[{i}].file {ev.get('file')!r} is not an inventory file")
    want = evidence.finding_status(f.get("evidence") or [])
    R.check(f.get("status") == want, "E-FINDING-STATUS", w, f"status {f.get('status')} but the evidence matches give {want}")
    for k in c.docs("cluster"):
        if f.get("finding_id") in (k.data.get("member_finding_ids") or []):
            allowed = facets.FACET_BUCKETS.get(f.get("facet"), frozenset())
            R.check(k.data.get("cwe_bucket") in allowed, "E-FINDING-FACET", w,
                    f"facet {f.get('facet')} may produce buckets {sorted(allowed)}, but cluster {k.data.get('cluster_id')} is {k.data.get('cwe_bucket')}")


def inventory_checks(R: Report, c: Ctx):
    """B2: internal references of every W0 inventory (middleware refs, source files)."""
    for d in c.docs("inventory"):
        with doc_guard(R, d.path):
            _inventory_doc(R, c, d)


def _inventory_doc(R: Report, c: Ctx, d: Doc):
    """B2 for one W0 inventory: middleware refs, source files, env vars (guarded per document by inventory_checks)."""
    inv, w = d.data, d.path
    paths = {x.get("path") for x in inv.get("files") or [] if isinstance(x, dict)}
    mws = {m.get("middleware_id") for m in (inv.get("auth") or {}).get("middleware") or [] if isinstance(m, dict)}
    for e in inv.get("endpoints") or []:
        bad = sorted(set(e.get("middleware_refs") or []) - mws)
        R.check(not bad, "E-INVENTORY", w, f"endpoint {e.get('method')} {e.get('path')}: unknown middleware_refs {bad}")
        # v0.5 (BL-19): a scheduled job / queue consumer has no HTTP request: no method, a schedule: / queue: path
        scheduled = e.get("kind") == "scheduled"
        R.check((e.get("method") is None) == scheduled, "E-INVENTORY", w,
                f"endpoint {e.get('method')} {e.get('path')}: " + ("a scheduled job has no HTTP method" if scheduled
                                                                     else f"kind {e.get('kind')} needs an HTTP method"))
        if scheduled:
            R.check(str(e.get("path", "")).startswith(("schedule:", "queue:")), "E-INVENTORY", w,
                    f"scheduled endpoint path {e.get('path')!r} must be schedule:<name> or queue:<name>")
    srcs = [("endpoint", e.get("file")) for e in inv.get("endpoints") or []]
    srcs += [("llm_integration", x.get("file")) for x in inv.get("llm_integrations") or []]
    srcs += [("middleware", m.get("file")) for m in (inv.get("auth") or {}).get("middleware") or []]
    db = inv.get("db") or {}
    for t in db.get("tables") or []:
        srcs.append((f"table {t.get('name')}", (t.get("source") or {}).get("file")))
        srcs += [(f"policy {p.get('name')}", (p.get("source") or {}).get("file")) for p in t.get("policies") or []]
    srcs += [(f"function {x.get('name')}", (x.get("source") or {}).get("file")) for x in db.get("functions") or []]
    srcs += [(f"bucket {x.get('name')}", (x.get("source") or {}).get("file")) for x in db.get("storage_buckets") or [] if x.get("source")]
    srcs += [(f"env {x.get('name')}", r.get("file")) for x in inv.get("env_vars") or [] for r in x.get("referenced_in") or []]
    for what, fpath in srcs:
        R.check(fpath in paths, "E-INVENTORY", w, f"{what}: source file {fpath!r} is not in files")
    ids = [t.get("table_id") for t in db.get("tables") or []]
    R.check(len(ids) == len(set(ids)), "E-INVENTORY", w, "duplicate table_id")
    for x in inv.get("env_vars") or []:
        want = str(x.get("name", "")).startswith(PUBLIC_ENV_PREFIXES)
        R.check(x.get("public_prefix") is want, "E-INVENTORY", w, f"env var {x.get('name')}: public_prefix must be {want}")


PUBLIC_ENV_PREFIXES = ("NEXT_PUBLIC_", "VITE_", "EXPO_PUBLIC_", "PUBLIC_")
LEVELS = {"L1": 1, "L2": 2, "L3": 3}


def requirement_level(c: Ctx, rid) -> tuple[str | None, str | None, int | None]:
    """(standard asvs|aisvs, number like 8.2.3, level) of a baseline ASVS/AISVS requirement, else (None, None, None)."""
    x = next((b for b in c.invariants.get("baseline") or [] if isinstance(b, dict) and b.get("requirement_id") == rid), None)
    if not x:
        return None, None, None
    std = {"asvs-5.0.0": "asvs", "aisvs-1.0": "aisvs"}.get(x.get("source"))
    return std, str(x.get("ref", "")).rsplit("-", 1)[-1], LEVELS.get(x.get("level"))


def level_covered(c: Ctx, std: str, number: str, level: int) -> bool:
    inv = c.invariants
    if ((inv.get("baseline_levels") or {}).get(std) or 0) >= level:
        return True
    for t in inv.get("level_triggers") or []:
        if not isinstance(t, dict) or t.get("standard") != std or (t.get("level") or 0) < level:
            continue
        if any(number == s or number.startswith(s + ".") for s in t.get("sections") or []):
            return True
    return False


def invariants_checks(R: Report, c: Ctx):
    """B3: level triggers cover every cited L2+ ASVS/AISVS requirement; llm_tools refer to data classes."""
    inv, w = c.invariants, "invariants.yaml"
    if not inv:
        return
    features = {f for i in inv.get("invariants") or [] for f in i.get("applies_to_features") or []}
    run_inv = inventory_of_run(c, inv.get("run_id")) or {}
    features |= set(run_inv.get("features") or [])
    for t in inv.get("level_triggers") or []:
        R.check(t.get("feature") in features, "E-INVARIANT-LEVEL", w,
                f"level trigger feature {t.get('feature')!r} is neither an invariant applies_to_features value nor a W0 inventory feature")
    cited = [(w, x.get("requirement_id")) for x in inv.get("baseline") or []]
    cited += [(d.path, r) for d in c.docs("testcase") + c.docs("w4-testcase") for r in set(d.data.get("requirement_ids") or [])
              | set((d.data.get("oracle") or {}).get("requirement_refs") or [])]
    for where, rid in cited:
        std, number, level = requirement_level(c, rid)
        if std and level and level >= 2:
            R.check(level_covered(c, std, number, level), "E-INVARIANT-LEVEL", where,
                    f"{rid} is {std.upper()} L{level} but neither baseline_levels.{std} nor a level trigger covers section {number}")
    dcs = {x.get("data_class_id") for x in inv.get("data_classification") or []}
    for t in inv.get("llm_tools") or []:
        bad = sorted(set(t.get("data_class_ids") or []) - dcs)
        R.check(not bad, "E-INVARIANT-REF", w, f"llm_tools {t.get('tool_name')}: unknown data_class_ids {bad}")
    for a in inv.get("access_matrix") or []:
        o = a.get("ownership") or {}
        R.check((o.get("kind") == "none") == (o.get("field") is None), "E-INVARIANT-REF", w,
                f"access_matrix {a.get('role')}/{a.get('resource')}: ownership.field is required unless kind is none")


def plan_facets(R: Report, c: Ctx, d: Doc):
    """E7: every slice of a commander plan covers the MANDATORY_FACETS of the W0 inventory of each run listing the plan."""
    for rid, run in c.runs.items():
        if d.data.get("plan_id") not in run.get("plan_ids", []):
            continue
        inv = inventory_of_run(c, rid)
        if inv is None:
            continue
        need = facets.mandatory_facets(inv)
        for i, s in enumerate(d.data.get("slices") or []):
            miss = sorted(need - set(s.get("facets") or []))
            R.check(not miss, "E-PLAN-FACETS", d.path, f"slices[{i}] misses mandatory facets {miss} (W0 inventory of {rid})")


def eligible_reviewer_families(c: Ctx, sl: dict) -> set[str]:
    """Registry families of agents.yaml reviewers whose model the engagement allows for its data class and
    that the slice does not exclude (slice.excluded_models: the model cannot fit the slice)."""
    e = c.engagement or {}
    allowed = set((e.get("allowed_models") or {}).get(e.get("data_class"), []))
    excluded = {x.get("model_key") for x in sl.get("excluded_models") or [] if isinstance(x, dict)}
    fams = set()
    for a in c.agents.values():
        if isinstance(a, dict) and a.get("role") == "reviewer" and a.get("model") in allowed and a.get("model") not in excluded:
            m = c.model(a.get("model"))
            if m and isinstance(m.get("family"), str):
                fams.add(m["family"])
    return fams


def plan_coverage(R: Report, c: Ctx, d: Doc):
    """v0.4 (D3): a CMD-1 plan is a superset of the coverage floor, not only for facets.

    - E-PLAN-COVERAGE: every slice of a (non-Lane-A) run that lists the plan is in plan.slices;
    - E-PLAN-FAMILIES: each planned slice is assigned reviewers of at least min(2, |eligible families|)
      distinct registry families (docs/02 W2: N reviewers of different families per slice).
    v0.3 checked only the facets of the slices the plan happened to list, so a plan could drop slices or
    send each slice to one family and still pass E-PLAN-FACETS."""
    p = d.data
    if p.get("decision_node") != "CMD-1":
        return
    planned = {s.get("slice_id"): s for s in p.get("slices") or [] if isinstance(s, dict)}
    for rid, run in c.runs.items():
        if p.get("plan_id") not in run.get("plan_ids", []) or run.get("run_kind") == "lane_a":
            continue
        for sd in c.docs("slice"):
            sl = sd.data
            if sl.get("run_id") != rid:
                continue
            ps = planned.get(sl.get("slice_id"))
            if not R.check(ps is not None, "E-PLAN-COVERAGE", d.path,
                           f"slice {sl.get('slice_id')} of {rid} is not in the CMD-1 plan (the plan must cover every slice)"):
                continue
            fams = set()
            for a in ps.get("agents") or []:
                m = c.model((c.agents.get(a) or {}).get("model"))
                if m and isinstance(m.get("family"), str):
                    fams.add(m["family"])
            need = min(2, len(eligible_reviewer_families(c, sl)))
            R.check(len(fams) >= need, "E-PLAN-FAMILIES", d.path,
                    f"slice {sl.get('slice_id')} of {rid} is assigned reviewer families {sorted(fams)}; "
                    f"at least {need} distinct families are required (eligible: {sorted(eligible_reviewer_families(c, sl))})")


def g_trace(R: Report, c: Ctx):
    ix = c.ix
    inv_ids = {i.get("requirement_id") for i in c.invariants.get("invariants", [])}
    req_ids = inv_ids | {x.get("requirement_id") for x in c.invariants.get("baseline", [])}
    # v0.5 (review r7, group 5): helpers run guarded, so one broken document does not end the traceability group
    with doc_guard(R, "inventory"):
        inventory_checks(R, c)
    with doc_guard(R, "invariants.yaml"):
        invariants_checks(R, c)
    for d in c.docs("finding"):
        with doc_guard(R, d.path):
            f, w = d.data, d.path
            run = c.runs.get(f.get("run_id")) or {}
            R.check(f.get("finding_id") in run.get("findings", []), "E-TRACE", w, "finding not listed by its run")
            R.check(ix.first("slice", slice_id=f.get("slice_id")) is not None, "E-TRACE", w, "slice not found")
            if run.get("run_kind") != "lane_a":
                R.check(set(f.get("invariant_refs", [])) <= inv_ids, "E-TRACE", w, "invariant_refs not in invariants.yaml")
            finding_evidence(R, c, d)
            finding_round(R, c, d)
    for d in c.docs("cluster"):
        with doc_guard(R, d.path):
            k, w = d.data, d.path
            run = c.runs.get(k.get("run_id")) or {}
            R.check(k.get("cluster_id") in run.get("cluster_ids", []), "E-TRACE", w, "cluster not listed by its run")
            cluster_origin(R, c, d)
            if k.get("carried_from") is None:
                cluster_binding(R, c, d)               # v0.7: a carried cluster is bound to its source (E-CLUSTER-CARRY), not to members
            members = [ix.first("finding", finding_id=f) for f in k.get("member_finding_ids", [])]
            if k.get("carried_from") is None and R.check(all(members), "E-TRACE", w, "member finding not found"):
                fams = {(m.data.get("reporter") or {}).get("family") for m in members}
                lins = {(m.data.get("reporter") or {}).get("lineage") for m in members}
                R.check(set(k.get("families", [])) == fams and set(k.get("lineages", [])) == lins, "E-CLUSTER-FAMILIES", w,
                        "families/lineages must be those of the member findings' reporters")
                R.check(all(m.data.get("run_id") == k.get("run_id") for m in members), "E-TRACE", w, "member finding from another run")
            indep = derive.independent_families(ix, k)
            R.check(sorted(k.get("independent_families", [])) == indep, "E-CLUSTER-FAMILIES", w,
                    f"independent_families {k.get('independent_families')} != {indep} (families of round-1 members reported by a reviewer)")
            fp = derive.cluster_fingerprint(k)
            R.check(k.get("fingerprint") == fp, "E-CLUSTER-FINGERPRINT", w, f"fingerprint {k.get('fingerprint')} != {fp} (sha256(JCS(fingerprint key)))")
    for d in c.docs("verdict"):
        with doc_guard(R, d.path):
            v = d.data
            cl = ix.first("cluster", cluster_id=v.get("cluster_id"))
            run = c.runs.get(cl.data.get("run_id")) if cl else None
            R.check(run is not None and v.get("verdict_id") in run.get("verdicts", []), "E-TRACE", d.path, "verdict not listed by its cluster's run")
            if v.get("g2_decision_ref"):
                g2 = c.record(v["g2_decision_ref"])
                R.check(g2 is not None and g2.get("gate") == "G2" and any(x.get("item_id") == v.get("cluster_id") for x in g2.get("decisions", [])),
                        "E-TRACE", d.path, "g2_decision_ref must be a G2 record deciding this cluster")
            if cl:
                # R10 is derived from the run's G2 records (g2_latest); the reference must agree with them.
                latest = g2_latest(c, cl.data)[0]
                lid = latest.get("gate_record_id") if latest else None
                if v.get("g2_decision_ref"):
                    R.check(v["g2_decision_ref"] == lid, "E-VERDICT-G2", d.path,
                            f"g2_decision_ref {v['g2_decision_ref']} is not the latest G2 record deciding this cluster ({lid})")
                elif v.get("readjudicated_by") != "W3_adjudicate":
                    R.check(lid is None, "E-VERDICT-G2", d.path,
                            f"verdict after G2 must reference the G2 record {lid} that decided this cluster")
                # v0.7 (review r9 phase): a G2_apply version applies a G2 decision; v0.6 accepted one with no G2 record at all
                if v.get("readjudicated_by") == "G2_apply":
                    R.check(lid is not None and v.get("g2_decision_ref") == lid, "E-VERDICT-G2", d.path,
                            f"a G2_apply version must reference the G2 record that decided {v.get('cluster_id')} (latest: {lid})")
    for d in c.docs("threat"):
        with doc_guard(R, d.path):
            t, w = d.data, d.path
            # D9: the review record must be a G3 record that decided this threat, and the status must be that decision
            rv = t.get("review") or {}
            if rv.get("gate_record_id") is not None:
                g3 = c.record(rv.get("gate_record_id"))
                dec = next((x.get("decision") for x in (g3 or {}).get("decisions") or [] if x.get("item_id") == t.get("threat_id")), None)
                want = {"accept": "ACCEPTED", "reject": "REJECTED", "needs_info": "NEEDS_INFO"}.get(dec)
                R.check(g3 is not None and g3.get("gate") == "G3" and dec is not None and rv.get("status") == want, "E-THREAT-REVIEW", w,
                        f"review {rv.get('status')} by {rv.get('gate_record_id')!r} must be the decision of a G3 record that decides "
                        f"{t.get('threat_id')} (found {dec!r})")
            else:
                R.check(rv.get("status") == "PENDING", "E-THREAT-REVIEW", w, "a threat without a G3 record must be PENDING")
            for ev in t.get("evidence") or []:
                kind, ref = ev.get("kind"), ev.get("ref")
                if kind == "cluster":
                    R.check(isinstance(ref, str) and ref.startswith("K-") and ix.first("cluster", cluster_id=ref) is not None, "E-TRACE", w,
                            f"evidence cluster {ref!r} not found")
                elif kind == "finding":
                    R.check(isinstance(ref, str) and ref.startswith("F-") and ix.first("finding", finding_id=ref) is not None, "E-TRACE", w,
                            f"evidence finding {ref!r} not found (cluster refs use kind cluster)")
                elif kind == "inventory":
                    invs = [x.data for x in c.docs("inventory")]
                    R.check(any(evidence.resolves(inv, ref) for inv in invs), "E-INVENTORY-REF", w,
                            f"inventory evidence {ref!r} is not a JSON Pointer that resolves in a W0 inventory")
            if t.get("source_cluster_id"):
                cl = ix.first("cluster", cluster_id=t["source_cluster_id"])
                if R.check(cl is not None, "E-TRACE", w, "source cluster not found"):
                    R.check(set(t.get("source_finding_ids", [])) <= set(cl.data.get("member_finding_ids", [])), "E-TRACE", w, "source findings not in the cluster")
            bad = [l.get("target_id") for l in t.get("crosswalk", []) if l.get("provenance") == "llm-suggested"]
            R.check((t.get("review") or {}).get("status") != "ACCEPTED" or not bad, "E-THREAT-LLM-LINK", w, f"accepted threat has llm-suggested links {bad}")
            for l in t.get("crosswalk", []):
                if l.get("target_scheme") == "invariant":
                    R.check(l.get("target_id") in inv_ids, "E-TRACE", w, f"invariant {l.get('target_id')} not in invariants.yaml")
                R.check((l.get("provenance") == "curated") == (l.get("reviewed_by") is not None), "E-XWALK-REVIEW", w,
                        f"{l.get('target_id')}: curated links need reviewed_by, llm-suggested links must not have it")
            for x in t.get("taxonomy", []):
                if str(x.get("scheme", "")).startswith("owasp-llm@"):
                    runs = [r for r in c.runs.values() if r.get("run_kind") == "initial"]
                    R.check(all(x["scheme"] == f"owasp-llm@{r.get('owasp_llm_version')}" for r in runs), "E-XWALK-OWASP", w,
                            f"{x['scheme']} differs from the run's owasp_llm_version")
            # v0.7 (review r9): the threat's own run (the run whose G3 reviewed it, else its source cluster's); v0.6 took
            # the first merged DFD of the bundle, whatever its run
            rv_rec = c.record((t.get("review") or {}).get("gate_record_id")) or {}
            src = ix.first("cluster", cluster_id=t.get("source_cluster_id")) if t.get("source_cluster_id") else None
            trun = rv_rec.get("run_id") or (src.data.get("run_id") if src else None)
            dfd = ix.first("dfd", run_id=trun, viewpoint="merged") if trun else None
            if dfd:
                els = {e.get("element_id"): e.get("type") for e in dfd.data.get("elements", [])}
                for el in t.get("dfd_elements", []):
                    R.check(els.get(el.get("element_id")) == el.get("type"), "E-TRACE-DFD", w, f"DFD element {el.get('element_id')} missing or of another type")
    for d in c.docs("testcase"):
        with doc_guard(R, d.path):
            tc, w = d.data, d.path
            th = ix.first("threat", threat_id=tc.get("threat_id"))
            if R.check(th is not None, "E-TRACE", w, f"threat {tc.get('threat_id')} not found"):
                R.check((th.data.get("review") or {}).get("status") == "ACCEPTED", "E-TRACE", w, "testcases only for threats accepted at G3")
            R.check(set(tc.get("requirement_ids", [])) <= req_ids, "E-TRACE", w, "requirement_ids not in invariants.yaml (invariants or baseline)")
            if tc.get("source_cluster_id"):
                R.check(ix.first("cluster", cluster_id=tc["source_cluster_id"]) is not None, "E-TRACE", w, "source cluster not found")
    for d in c.docs("testresult"):
        with doc_guard(R, d.path):
            tr, w = d.data, d.path
            tcd = ix.testcase_for(tr)
            R.check(tcd is not None, "E-TRACE", w, f"{'w4-testcase' if tr.get('phase') == 'W4' else 'testcase'} {tr.get('testcase_id')} not found")
            th = ix.first("threat", threat_id=tcd.data.get("threat_id")) if tcd else None
            if th is not None:
                src = th.data.get("source_cluster_id")
                if src is None:
                    # A2 (clarified): every result of a testcase whose threat has no source cluster is recorded on a
                    # black_box cluster of that threat (created at B5 for FAIL, PASS and INVALID alike)
                    bad = [k for k in tr.get("cluster_ids", []) if not ((ix.first("cluster", cluster_id=k) or Doc("", "", {})).data.get("origin") == "black_box"
                                                                       and (ix.first("cluster", cluster_id=k)).data.get("threat_id") == th.data.get("threat_id"))]
                    R.check(bool(tr.get("cluster_ids")) and not bad, "E-CLUSTER-ORIGIN", w,
                            f"result of {tcd.data.get('testcase_id')} (threat {th.data.get('threat_id')} has no source cluster) must be recorded "
                            f"on black_box clusters of that threat (cluster_ids {tr.get('cluster_ids')})")
                else:
                    # v0.5 (review 2026-10-25 H-2): a result counts as test evidence for every cluster it names, so it
                    # may name only clusters of its own threat (the source cluster and clusters the threat cites as
                    # evidence); v0.4 checked only that the source cluster was among them, so a PASS could be attached
                    # to an unrelated cluster and turn it DISPUTED through R11
                    # review r12: a carried-in cluster of the result's own run stands for the cluster it was carried from
                    # (docs/02 §1.6: a regression run re-runs the parent's testcases against its carried clusters). r11
                    # demanded the parent's cluster id, so a regression result could never reach the cluster R14 decides
                    def canon(k):
                        cl = (ix.first("cluster", cluster_id=k) or Doc("", "", {})).data
                        cf = cl.get("carried_from") if cl.get("run_id") == tr.get("run_id") else None
                        return cf.get("cluster_id") if isinstance(cf, dict) else k
                    own = {src} | {e.get("ref") for e in th.data.get("evidence") or [] if isinstance(e, dict) and e.get("kind") == "cluster"}
                    named = [canon(k) for k in tr.get("cluster_ids", [])]
                    extra = [k for k in named if k not in own]
                    R.check(src in named and not extra, "E-TRACE", w,
                            f"cluster_ids {tr.get('cluster_ids')} must include the threat's source cluster {src} and name only "
                            f"clusters of threat {th.data.get('threat_id')} ({sorted(own)}); not {extra}")
            for k in tr.get("cluster_ids", []):
                R.check(ix.first("cluster", cluster_id=k, run_id=tr.get("run_id")) is not None or
                        any(k in (r.get("cluster_ids") or []) for r in c.runs.values()), "E-TRACE", w, f"cluster {k} not found")
    for d in c.docs("requirement"):
        q = d.data
        if q.get("source") == "invariant":
            inv = next((i for i in c.invariants.get("invariants", []) if i.get("requirement_id") == q.get("requirement_id")), None)
            R.check(inv == q, "E-TRACE-REQUIREMENT", d.path, "must be identical to the invariants.yaml item")
        else:
            base = next((x for x in c.invariants.get("baseline", []) if x.get("requirement_id") == q.get("requirement_id")), None)
            R.check(base is not None and all(base.get(k) == q.get(k) for k in ("source", "ref", "level")), "E-TRACE-REQUIREMENT", d.path,
                    "must match the invariants.yaml baseline entry")
    for d in c.docs("seed-threats"):
        for s in d.data.get("seeds", []):
            cl = ix.first("cluster", cluster_id=s.get("source_cluster_id"))
            v = ix.first("verdict", verdict_id=s.get("verdict_id"))
            th = ix.first("threat", threat_id=s.get("threat_id")) if s.get("threat_id") else True
            ok = cl is not None and v is not None and th is not None and v.data.get("cluster_id") == s.get("source_cluster_id") \
                and v.data.get("status") == s.get("cluster_status") and cl.data.get("cwe_bucket") == s.get("cwe_bucket")
            R.check(ok, "E-TRACE-SEED", d.path, f"{s.get('seed_id')}: cluster/verdict/threat/status/bucket do not match")
            # v0.7 (review r9 seed): W5 seeds the run's own clusters
            R.check(cl is None or cl.data.get("run_id") == d.data.get("run_id"), "E-TRACE-SEED", d.path,
                    f"{s.get('seed_id')}: source cluster {s.get('source_cluster_id')} belongs to run {(cl.data if cl else {}).get('run_id')}, "
                    f"not to the seed document's run {d.data.get('run_id')}")
    with doc_guard(R, "invariants.yaml baseline"):
        baseline_checks(R, c)
    for d in c.docs("commander-plan"):
        with doc_guard(R, d.path):
            plan_facets(R, c, d)
            plan_coverage(R, c, d)
            plan_checks(R, c, d)
            for tid in d.data.get("testcase_ids", []):
                R.check(ix.first("testcase", testcase_id=tid) is not None, "E-TRACE", d.path, f"testcase {tid} not found")
            for fd in d.data.get("followup_drafts", []):
                for k in fd.get("cluster_ids", []):
                    R.check(ix.first("cluster", cluster_id=k) is not None, "E-TRACE", d.path, f"cluster {k} not found")
    drafts = {fd.get("draft_id") for p in c.docs("commander-plan") for fd in p.data.get("followup_drafts", [])}
    for rid, run in c.runs.items():
        for fd in run.get("followup_drafts", []):
            R.check(fd in drafts, "E-TRACE", rid, f"follow-up draft {fd} not found")
        for pid in run.get("plan_ids", []):
            R.check(c.ix.first("commander-plan", plan_id=pid) is not None, "E-TRACE", rid, f"plan {pid} not found")


def check_report_queues(R: Report, c: Ctx, w: str, rm: dict, status: dict):
    """v0.4 (BL-26, docs/02 W3 / W5): report_only_clusters and over_cap_items (E-REPORT-QUEUE).

    report_only: a white-box cluster, latest verdict UNCORROBORATED and no seed threat from it (the pruning rule; rubric severity
    and the high-risk conditions are the toolkit's to compute). over_cap G2: a cluster of the run that became
    a seed without a G2 decision, while the run's G2 queue was full (exactly g2_max_items decisions). over_cap
    G3: a seed threat of the run whose threat_id has a G3 decision over_cap (v0.5; v0.4: no G3 decision)."""
    rid = rm.get("run_id")
    caps = c.toolkit.get("gate_queues") or {}
    seeds = [sd for d in c.docs("seed-threats") if d.data.get("run_id") == rid for sd in d.data.get("seeds", [])]
    seed_clusters = {sd.get("source_cluster_id") for sd in seeds}
    for cid in rm.get("report_only_clusters") or []:
        cl = c.ix.first("cluster", cluster_id=cid)
        white = cl is not None and cl.data.get("origin") != "black_box"         # white_box or tool_only
        R.check(white and status.get(cid) == "UNCORROBORATED" and cid not in seed_clusters, "E-REPORT-QUEUE", w,
                f"report_only_clusters: {cid} must be a white-box cluster of the run whose latest verdict is UNCORROBORATED "
                f"(got {status.get(cid)}) and that is not a seed threat")
    decided = {g: {dec.get("item_id") for rec in c.ix.gate_records(rid, g) for dec in rec.data.get("decisions", [])}
               for g in ("G2", "G3")}
    over_cap_g3 = {dec.get("item_id") for rec in c.ix.gate_records(rid, "G3") for dec in rec.data.get("decisions", [])
                   if dec.get("decision") == "over_cap"}
    g2 = c.ix.gate_records(rid, "G2")
    g2_full = bool(g2) and len(g2[-1].data.get("decisions", [])) == caps.get("g2_max_items", 30)
    seen = set()
    for it in rm.get("over_cap_items") or []:
        g, iid = it.get("gate"), it.get("item_id")
        if g == "G2":
            ok = status.get(iid) in ("DISPUTED", "UNCORROBORATED") and iid in seed_clusters and iid not in decided["G2"] and g2_full
            why = "a DISPUTED / UNCORROBORATED seed cluster without a G2 decision, while the G2 queue held exactly g2_max_items"
        else:
            # v0.5 (review 2026-10-25 M-4b): the G3 record names it with decision over_cap, so D5 and R13 see it as rejected
            ok = any(sd.get("seed_id") == iid and sd.get("threat_id") in over_cap_g3 for sd in seeds)
            why = "a seed threat of the run whose threat has a G3 decision over_cap"
        R.check(ok and (g, iid) not in seen, "E-REPORT-QUEUE", w, f"over_cap_items: {g} {iid} must be {why}, listed once")
        seen.add((g, iid))
    # v0.6 (review r7 4.5): the list is recomputed, not only checked item by item: every seed whose threat G3 marked
    # over_cap is listed (the report is where an over-cap item is still visible to a person)
    for sd in seeds:
        if sd.get("threat_id") in over_cap_g3:
            R.check(("G3", sd.get("seed_id")) in seen, "E-REPORT-QUEUE", w,
                    f"over_cap_items: seed {sd.get('seed_id')} (threat {sd.get('threat_id')}) is over_cap at G3 but not listed")


HIGH_SEVERITIES = ("critical", "high")
EMPTY_DOC = Doc("", "", {}, None)


def manual_review_set(c: Ctx, rid) -> list[str]:
    """v0.5 (review r7, group 2; docs/02 B6): the clusters of a run whose latest verdict carries post_g2_conflict, or whose
    B5 version turned DISPUTED. Derived, so the run and the report cannot leave one out."""
    out = set()
    for v in verdict_heads(c, (c.runs.get(rid) or {}).get("verdicts", [])):
        kinds = {a.get("kind") for a in v.get("annotations") or [] if isinstance(a, dict)}
        if "post_g2_conflict" in kinds or (v.get("readjudicated_by") == "B5_readjudicate" and v.get("status") == "DISPUTED"):
            out.add(v.get("cluster_id"))
    return sorted(out)


def pipeline_checks(R: Report, c: Ctx):
    """v0.5 (review r7, group 2; E-PIPELINE): nothing leaves the pipeline silently. Per run (Lane A is advisory and stops at
    W3): once W3 adjudicated, every cluster has a verdict and every verified finding is in a cluster; once W5 produced the
    seed threats, every DISPUTED / high-severity UNCORROBORATED white-box cluster went through G2 (or over_cap), every
    white-box cluster not REJECTED is a seed or report-only, and no G2-rejected cluster is a seed; after G3 every seed has
    a threat; and the derived manual review list, the gaps and the artefacts reach the report."""
    for rid, run in c.runs.items():
        if run.get("run_kind") == "lane_a":
            continue
        w = f"run {rid}"
        clusters = {d.data.get("cluster_id"): d.data for d in c.docs("cluster") if d.data.get("run_id") == rid}
        heads = {v.get("cluster_id"): v for v in verdict_heads(c, run.get("verdicts", []))}
        if heads:
            for k in sorted(set(clusters) - set(heads)):
                R.error("E-PIPELINE", w, f"cluster {k} has no verdict: W3 adjudicates every cluster of the run")
            members = {f for k in clusters.values() for f in k.get("member_finding_ids") or []}
            for f in c.docs("finding"):
                if f.data.get("run_id") == rid and f.data.get("status") == "VERIFIED_SNIPPET":
                    R.check(f.data.get("finding_id") in members, "E-PIPELINE", w,
                            f"finding {f.data.get('finding_id')} is verified but in no cluster: it would never be adjudicated")
        seed_docs = [d for d in c.docs("seed-threats") if d.data.get("run_id") == rid]
        rms = [d.data for d in c.docs("report-manifest") if d.data.get("run_id") == rid]
        if seed_docs:
            seeds = [sd for d in seed_docs for sd in d.data.get("seeds") or [] if isinstance(sd, dict)]
            seeded = {sd.get("source_cluster_id") for sd in seeds}
            report_only = {x for rm in rms for x in rm.get("report_only_clusters") or []}
            over_cap_g2 = {it.get("item_id") for rm in rms for it in rm.get("over_cap_items") or [] if it.get("gate") == "G2"}
            pre_ids = [i for i in run.get("verdicts", []) if (c.ix.first("verdict", verdict_id=i) or EMPTY_DOC).data.get("readjudicated_by")
                       in PRE_G3_PHASES]
            w_status_of = {v.get("cluster_id"): v.get("status") for v in verdict_heads(c, pre_ids)}   # the state W5 saw
            # v0.7 (review r8 F5): G2 routing is decided on the W3 verdict (the state G2 saw), by the rubric severity
            # (docs/02 W3 step 6, docs/08 §11.17). v0.6 took the head over W4 too, so a W4 re-adjudication hid a cluster
            # that skipped G2, and read the reviewers' self-reported finding.severity, which the rubric replaced in v0.4
            w3_ids = [i for i in run.get("verdicts", []) if (c.ix.first("verdict", verdict_id=i) or EMPTY_DOC).data.get("readjudicated_by")
                      == "W3_adjudicate"]
            w3_status_of = {v.get("cluster_id"): v.get("status") for v in verdict_heads(c, w3_ids)}
            for k, cl in sorted(clusters.items()):
                if cl.get("origin") == "black_box":                     # B-phase clusters come after W5
                    continue
                w_status = w_status_of.get(k)
                w3_status, sev = w3_status_of.get(k), derive.rubric_severity(c.ix, cl)
                # r11: a cluster nobody outside its families can check (no_eligible_verifier) is decided by people too:
                # its LIKELY (R6) rests on reporters alone, and a same-family member can have voided a refute (R15)
                no_elig = w3_status not in (None, "REJECTED") and derived_no_eligible_verifier(c, cl)
                if w3_status == "DISPUTED" or (w3_status == "UNCORROBORATED" and sev in HIGH_SEVERITIES) or no_elig:
                    rec, _ = g2_latest(c, cl)
                    R.check(rec is not None or k in over_cap_g2, "E-PIPELINE", w,
                            f"{k} is {w3_status} after W3 (rubric severity {sev}{', no eligible verifier' if no_elig else ''}) "
                            "but has no G2 decision and is not over_cap")
                status = (heads.get(k) or {}).get("status")
                if status != "REJECTED":
                    R.check(k in seeded or k in report_only, "E-PIPELINE", w,
                            f"{k} ({status}) is neither a seed threat nor report_only: it left the pipeline without a decision")
                _, dec = g2_latest(c, cl)
                if dec == "reject":
                    R.check(k not in seeded, "E-PIPELINE", w, f"{k} was rejected at G2 but is a seed threat")
            if any(x.data.get("outcome") != "EXPIRED" for x in c.ix.gate_records(rid, "G3")):
                for sd in seeds:
                    R.check(sd.get("threat_id") is not None, "E-PIPELINE", w,
                            f"seed {sd.get('seed_id')} has no threat_id after G3: G3 decides threats, so every seed maps to one")
        want_review = manual_review_set(c, rid)
        R.check(sorted(run.get("manual_review_clusters") or []) == want_review, "E-PIPELINE", w,
                f"manual_review_clusters must be {want_review} (post_g2_conflict, or DISPUTED after B5)")
        for rm in rms:
            rw = f"report {rm.get('report_id')}"
            R.check(rm.get("gaps") == run.get("gaps"), "E-PIPELINE", rw, "gaps must be the run's gaps")
            listed = {(a.get("kind"), a.get("ref")) for a in rm.get("artifacts") or [] if isinstance(a, dict)}
            for v in sorted(heads.values(), key=lambda x: str(x.get("verdict_id"))):
                R.check(("verdict", v.get("verdict_id")) in listed, "E-PIPELINE", rw,
                        f"artifacts must list the latest verdict {v.get('verdict_id')} of {v.get('cluster_id')}")
            for t in c.docs("testresult"):
                if t.data.get("run_id") == rid:
                    R.check(("testresult", t.data.get("result_id")) in listed, "E-PIPELINE", rw,
                            f"artifacts must list testresult {t.data.get('result_id')}")


# ============================================================== 21 DFD, report, selftest, checkpoint
def _ratio(n, d):
    return round(n / d, 4) if d else None


def execution_backed(c: Ctx, tr: dict) -> bool:
    """v0.5 (review r7, external review 5): the result is effective evidence: outcome PASS or FAIL (not INVALID, ERROR,
    SKIPPED or STOPPED), every control PASSed, and exactly one sandbox_job_end in the anchored part of its run's audit log
    names it with the same outcome and the hashes of what ran (derive.execution_pins)."""
    controls = [y for y in tr.get("controls") or [] if isinstance(y, dict)]
    if tr.get("outcome") not in ("PASS", "FAIL") or not controls or any(y.get("outcome") != "PASS" for y in controls):
        return False
    tc = c.ix.testcase_for(tr)
    audit = c.ix.audit_for(tr.get("run_id"))
    evs = [e for e in (audit.data if audit else []) if isinstance(e, dict)]
    ends = [e for e in evs if derive.job_end_of(e, tr)]
    if tc is None or len(ends) != 1:
        return False
    e, p = ends[0], ends[0].get("payload") or {}
    anchored = max((i + 1 for i, x in enumerate(evs) if x.get("event_type") == "audit_anchor"), default=0)
    return (type(e.get("seq")) is int and e.get("seq") < anchored and p.get("outcome") == tr.get("outcome")
            and all(p.get(k) == v for k, v in derive.execution_pins(tc.data, tr).items()))


def report_metrics(c: Ctx, run_id) -> dict:
    """B5: results_total, results_invalid, control_pass_rate (PASS control outcomes / all control outcomes, 4 decimals).
    v0.5 (BL-20, docs/02 W5 coverage): planned_access_matrix_coverage = G1 matrix cells named by the access_cells of the
    run's testcases (run.testcase_ids) and w4-testcases / all cells; endpoint_slice_coverage = inventory endpoints whose
    handler file is in a slice of the run / all; planned_endpoint_test_coverage = endpoints hit by a request_allowlist
    entry of the run's testcases (same method and path shape) / all.
    v0.5 (review r7, external review 5): the planned figures stay 1.0 with every result removed, so the executed_*
    figures count only testcases with at least one execution_backed result of the run."""
    results = [x.data for x in c.docs("testresult") if x.data.get("run_id") == run_id]
    outs = [y.get("outcome") for r in results for y in r.get("controls") or [] if isinstance(y, dict)]
    run = c.runs.get(run_id) or {}
    tcs = [t.data for t in c.docs("testcase") if t.data.get("testcase_id") in (run.get("testcase_ids") or [])]
    w4 = [t.data for t in c.docs("w4-testcase") if t.data.get("run_id") == run_id]
    ran = {(r.get("phase") == "W4", r.get("testcase_id")) for r in results if execution_backed(c, r)}
    cells = access_matrix_cells(c)
    eps = [e for e in (inventory_of_run(c, run_id) or {}).get("endpoints") or [] if isinstance(e, dict)]

    def cell_cover(tests):
        covered = {(x.get("role"), x.get("resource"), x.get("action")) for t in tests for x in t.get("access_cells") or [] if isinstance(x, dict)}
        return _ratio(len(covered & cells), len(cells))

    def endpoint_cover(tests):
        hit = {(r.get("method"), path_shape(r.get("path"))) for t in tests for r in t.get("request_allowlist") or [] if isinstance(r, dict)}
        return _ratio(sum(1 for e in eps if (e.get("method"), path_shape(e.get("path"))) in hit), len(eps))

    tcs_ran = [t for t in tcs if (False, t.get("testcase_id")) in ran]
    w4_ran = [t for t in w4 if (True, t.get("testcase_id")) in ran]
    sliced = {f.get("path") for s in c.docs("slice") if s.data.get("run_id") == run_id for f in s.data.get("files") or [] if isinstance(f, dict)}
    return {"results_total": len(results), "results_invalid": sum(1 for r in results if r.get("outcome") == "INVALID"),
            "control_pass_rate": round(sum(1 for o in outs if o == "PASS") / len(outs), 4) if outs else None,
            "planned_access_matrix_coverage": cell_cover(tcs + w4),
            "executed_access_matrix_coverage": cell_cover(tcs_ran + w4_ran),
            "endpoint_slice_coverage": _ratio(sum(1 for e in eps if e.get("file") in sliced), len(eps)),
            "planned_endpoint_test_coverage": endpoint_cover(tcs),
            "executed_endpoint_test_coverage": endpoint_cover(tcs_ran)}


ID_KEYS = {"run": "run_id", "verdict": "verdict_id", "cluster": "cluster_id", "finding": "finding_id", "testcase": "testcase_id",
           "w4-testcase": "testcase_id", "feedback": "feedback_id",
           "testresult": "result_id", "threat": "threat_id", "gate-record": "gate_record_id", "report-manifest": "report_id",
           "slice": "slice_id", "commander-plan": "plan_id"}     # v0.7 (review r9): plans too
# v0.7 (review r9): documents a run has at most one of (per viewpoint for DFDs). Lookups take the first by file name, so a
# second inventory, seed-threats document or merged DFD of a run decided silently which one was checked
PER_RUN_SINGLETONS = {"inventory": None, "seed-threats": None, "redaction-map": None, "dfd": "viewpoint",
                      "report-manifest": None}     # v0.7 (review r10): one report per run; a second one decided nothing


def id_uniqueness(R: Report, c: Ctx):
    """v0.5 (review 2026-10-25 V-5): an ID names one document. With two documents of the same kind and ID, lookups
    disagreed (Ctx.runs took the last, Index.first the first), so a second copy could shadow the checked one."""
    for kind, key in ID_KEYS.items():
        seen: dict = {}
        for d in c.docs(kind):
            if isinstance(d.data, dict) and d.data.get(key) is not None:
                seen.setdefault(d.data.get(key), []).append(d.path)
        for i, paths in seen.items():
            R.check(len(paths) == 1, "E-ID-DUP", paths[-1], f"{kind} {key} {i!r} is used by {len(paths)} documents: {paths}")
    for kind, facet in PER_RUN_SINGLETONS.items():
        per: dict = {}
        for d in c.docs(kind):
            if isinstance(d.data, dict) and d.data.get("run_id") is not None:
                per.setdefault((d.data.get("run_id"), d.data.get(facet) if facet else None), []).append(d.path)
        for (rid, f), paths in per.items():
            R.check(len(paths) == 1, "E-ID-DUP", paths[-1],
                    f"run {rid} has {len(paths)} {kind} documents{f' ({facet} {f})' if facet else ''}: {paths}; a run has one")


def threat_coverage(R: Report, c: Ctx):
    """v0.5 (review 2026-10-25 §4.3), docs/04 §1.3 (D5) and docs/02 B2, enforced instead of only described:
    - E-THREAT-ATTACK-TREE: a threat rated likelihood high and impact high is high-risk and needs attack_tree_ref; a
      set attack_tree_ref names this threat's tree (…/<threat_id>.json);
    - E-COVERAGE-D5: once a run has a G4 record (B3 finished), every threat whose latest G3 decision is accept has at
      least one testcase (a MANUAL one counts); reject and over_cap need none."""
    for d in c.docs("threat"):
        t, w = d.data, d.path
        ref, risk = t.get("attack_tree_ref"), t.get("risk") or {}
        if risk.get("likelihood") == "high" and risk.get("impact") == "high":
            R.check(bool(ref), "E-THREAT-ATTACK-TREE", w, f"{t.get('threat_id')} is rated high/high (high-risk) and needs attack_tree_ref")
        if ref:
            R.check(isinstance(ref, str) and ref.rsplit("/", 1)[-1] == f"{t.get('threat_id')}.json", "E-THREAT-ATTACK-TREE", w,
                    f"attack_tree_ref {ref!r} must name this threat's tree (…/{t.get('threat_id')}.json)")
    tested = {x.data.get("threat_id") for x in c.docs("testcase")}
    for rid in c.runs:
        if not c.ix.gate_records(rid, "G4"):
            continue
        latest = {}
        for rec in c.ix.gate_records(rid, "G3"):
            for x in rec.data.get("decisions") or []:
                latest[x.get("item_id")] = x.get("decision")
        for tid, dec in latest.items():
            if dec == "accept":
                R.check(tid in tested, "E-COVERAGE-D5", f"run {rid}", f"threat {tid} was accepted at G3 but has no testcase (not even MANUAL)")


def g_misc(R: Report, c: Ctx):
    id_uniqueness(R, c)
    threat_coverage(R, c)
    with doc_guard(R, "pipeline"):
        pipeline_checks(R, c)
    for d in c.docs("dfd"):
        with doc_guard(R, d.path):
            els = d.data.get("elements", [])
            ids = [e.get("element_id") for e in els]
            R.check(len(ids) == len(set(ids)), "E-DFD", d.path, "duplicate element ids")
            inv = inventory_of_run(c, d.data.get("run_id"))
            for e in els:
                R.check((e.get("type") == "trust_boundary") == (e.get("kind") is not None), "E-DFD", d.path,
                        f"{e.get('element_id')}: kind is required on trust boundaries and null on other elements")
                for r in e.get("evidence_refs") or []:
                    if str(r).startswith("inventory:"):
                        R.check(inv is not None and evidence.resolves(inv, str(r)[len("inventory:"):]), "E-INVENTORY-REF", d.path,
                                f"{e.get('element_id')}: {r} does not resolve in the W0 inventory of {d.data.get('run_id')}")
                if e.get("type") == "data_flow":
                    R.check(e.get("from") in ids and e.get("to") in ids, "E-DFD", d.path, f"{e.get('element_id')}: flow endpoints missing")
                    R.check(all(x in ids for x in e.get("crosses", [])), "E-DFD", d.path, f"{e.get('element_id')}: unknown trust boundary")
    ext = {e.get("element_id") for d in c.ix.find("dfd", viewpoint="external") for e in d.data.get("elements", [])}
    mer = {e.get("element_id") for d in c.ix.find("dfd", viewpoint="merged") for e in d.data.get("elements", [])}
    for d in c.ix.find("dfd", viewpoint="merged"):
        for x in d.data.get("b1_diff") or []:
            eid = x.get("element_id")
            want = {"only_external": eid in ext and eid not in mer, "only_merged": eid in mer and eid not in ext,
                    "attribute_mismatch": eid in ext and eid in mer}.get(x.get("kind"), False)
            R.check(want, "E-DFD", d.path, f"b1_diff {eid}: kind {x.get('kind')} does not match the two views")
    for d in c.docs("report-manifest"):
        with doc_guard(R, d.path):
            rm, w = d.data, d.path
            run = c.runs.get(rm.get("run_id"))
            if not R.check(run is not None, "E-REPORT", w, "run not found"):
                continue
            R.check(rm.get("advisory") is (run.get("run_kind") == "lane_a"), "E-REPORT", w, "advisory iff Lane A")
            # review r11: a Lite engagement's one person holds every key and runs every zone, so its signatures, anchors
            # and receive times prove nothing to a third party (docs/06 §3 #26); the report says so in a field
            want_ev = "self_attested" if profile(c) == "lite" else "separated"
            R.check(rm.get("evidential") == want_ev, "E-REPORT", w,
                    f"evidential must be {want_ev!r} for assurance_profile {profile(c)} (Lite evidence is self-attested), not {rm.get('evidential')!r}")
            # BL-70 / D10: a single-host engagement's anchors are countersigned by the operator's own process; the report says so
            want_anchor = ANCHOR_LABEL.get(deployment(c), "countersigned")
            R.check(rm.get("audit_anchor") == want_anchor, "E-REPORT-ANCHOR", w,
                    f"audit_anchor must be {want_anchor!r} for deployment_profile {deployment(c)}, not {rm.get('audit_anchor')!r}")
            final = verdict_heads(c, run.get("verdicts", []))       # v0.5 (V-4): a broken chain is E-VERDICT-CHAIN
            counts = {s: sum(1 for v in final if v.get("status") == s) for s in FINAL_STATUSES}
            R.check(rm.get("verdict_counts") == counts, "E-REPORT", w, f"verdict_counts must be {counts} (latest verdict per cluster)")
            want_m = report_metrics(c, rm.get("run_id"))
            got_m = rm.get("metrics") or {}
            R.check(derive._equal(got_m, want_m), "E-REPORT-METRICS", w, f"metrics {got_m} != recomputed {want_m} (the run's testresults and controls)")
            R.check(sorted(rm.get("manual_review_clusters", [])) == sorted(run.get("manual_review_clusters", [])), "E-REPORT", w, "manual_review_clusters differ from the run")
            check_report_queues(R, c, w, rm, {v.get("cluster_id"): v.get("status") for v in final})
            for a in rm.get("artifacts", []):
                if a.get("kind") == "audit_log":
                    R.check(c.b.doc(a.get("ref", "")) is not None, "E-REPORT", w, f"audit log {a.get('ref')} not found")
            grs = {a.get("ref") for a in rm.get("artifacts", []) if a.get("kind") == "gate_record"}
            R.check(grs == {g.data.get("gate_record_id") for g in c.ix.gate_records(rm.get("run_id"))}, "E-REPORT", w, "report must list every gate record of the run")
    for d in c.docs("selftest-report"):
        with doc_guard(R, d.path):
            st, w = d.data, d.path
            items = {i.get("item"): i for i in st.get("items", [])}
            for i in items.values():
                if i.get("status") == "NOT_RUN":
                    R.check(i.get("passed") is None and i.get("value") is None and i.get("runs") == 0, "E-SELFTEST", w, f"{i.get('item')}: NOT_RUN has no result")
                else:
                    R.check(i.get("passed") is not None and i.get("runs", 0) >= 1, "E-SELFTEST", w, f"{i.get('item')}: RUN needs runs and passed")
            if st.get("milestone") == "M1":
                for need in M1_REQUIRED_SELFTESTS:
                    it = items.get(need) or {}
                    R.check(it.get("status") == "RUN" and it.get("passed") is True, "E-SELFTEST-M1", w, f"M1 requires {need} RUN and passed")
            ran = [i for i in items.values() if i.get("status") == "RUN"]
            R.check(st.get("overall_passed") is (bool(ran) and all(i.get("passed") for i in ran)), "E-SELFTEST", w, "overall_passed must be all RUN items passed")
            s, f = ts(R, st.get("started_at"), w), ts(R, st.get("finished_at"), w)
            R.check(s and f and s <= f, "E-SELFTEST", w, "finished_at before started_at")
            R.check(st.get("toolkit_version") == c.toolkit.get("toolkit_version"), "E-SELFTEST", w, "toolkit_version differs")
    for d in c.docs("checkpoint-metadata"):
        with doc_guard(R, d.path):
            run = c.runs.get(d.data.get("run_id"))
            if R.check(run is not None, "E-CHECKPOINT", d.path, "run not found"):
                R.check(d.data.get("run_status") == run.get("status") and d.data.get("thread_id") == run.get("run_id"), "E-CHECKPOINT", d.path,
                        "run_status / thread_id disagree with the run")
                R.check(d.data.get("encrypted") is True or run.get("data_class") == "P", "E-CHECKPOINT", d.path, "C-class checkpoints must be encrypted")


GROUPS = [
    ("schemas and examples", g_schemas),
    ("RFC 8785 canonical JSON", g_jcs),
    ("derived hashes, weights and audit chain", g_derived),
    ("key registry", g_key_registry),
    ("Ed25519 signatures", g_signatures),
    ("person references", g_persons),
    ("engagement", g_engagement),
    ("ROE and legal review L-1..L-6", g_roe),
    ("models, agents, family diversity", g_models),
    ("gates", g_gates),
    ("run state, jobs, test results", g_runs),
    ("testcases vs ROE (docs/04 §5)", g_testcases),
    ("W4 testcases (docs/02 W4)", g_w4_testcases),
    ("feedback records (docs/08 §11.16)", g_feedback),
    ("report withdrawals (docs/06 §1.9)", g_report_withdrawal),
    ("verdict recomputation (docs/05 §4.2)", g_verdicts),
    ("traceability", g_trace),
    ("audit log", g_audit),
    ("calibration", g_calibration),
    ("licenses and requirements", g_licenses),
    ("crosswalk", g_crosswalk),
    ("LLM-facing schemas (cross-vendor subset)", g_llm_schemas),
    ("toolkit, tools, retention", g_toolkit),
    ("DFD, report, self-test, checkpoint", g_misc),
]


def _json_type(value, t) -> bool:
    return {"object": isinstance(value, dict), "array": isinstance(value, list), "string": isinstance(value, str),
            "boolean": isinstance(value, bool), "null": value is None,
            # shape level: 3.0 in an integer field is left to E-SCHEMA (a strict-integer error), not quarantined
            "integer": isinstance(value, (int, float)) and not isinstance(value, bool),
            "number": isinstance(value, (int, float)) and not isinstance(value, bool)}.get(t, True)


def _shape_ok(value, schema, schemas, depth=0):
    """True / False when the JSON type of `value` is decidable from `schema` (type, $ref, anyOf); None otherwise."""
    if not isinstance(schema, dict) or depth > 10:
        return None
    if "$ref" in schema:
        target, _, frag = schema["$ref"].partition("#")
        doc = schemas.get(target.removesuffix(".schema.json")) if target else None
        try:
            node = llm_schema._pointer(doc if doc is not None else {}, frag) if target else None
        except (KeyError, IndexError, ValueError, TypeError):
            node = None
        return _shape_ok(value, node, schemas, depth + 1) if node is not None else None
    if "type" in schema:
        ts_ = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
        return any(_json_type(value, t) for t in ts_)
    if "anyOf" in schema:
        res = [_shape_ok(value, alt, schemas, depth + 1) for alt in schema["anyOf"]]
        if any(r is True for r in res):
            return True
        return False if res and all(r is False for r in res) else None
    return None


def input_shape_problems(d: Doc, schema: dict, schemas: dict) -> list[str]:
    """D5: the document's top level (and the JSON type of each top-level field) matches its schema."""
    if d.kind == "audit-event":
        if not isinstance(d.data, list) or not all(isinstance(x, dict) for x in d.data):
            return ["the audit log must be one JSON object per line"]
        return []
    if not isinstance(d.data, dict):
        return [f"top level is {type(d.data).__name__}, expected a mapping"]
    out = []
    props = schema.get("properties") or {}
    extra = schema.get("additionalProperties")
    for k, v in d.data.items():
        sub = props.get(k, extra if isinstance(extra, dict) else None)
        if sub is not None and _shape_ok(v, sub, schemas) is False:
            out.append(f"{k}: {type(v).__name__} does not have the schema's type")
    return out


def quarantine(R: Report, b: Bundle) -> Bundle:
    """D5: one E-INPUT-SHAPE per file whose shape is wrong; such documents are hidden (data None) from the semantic
    groups, so a wrong shape never crashes the validator. The schema group still sees the original document."""
    docs = []
    for d in b.docs:
        s = b.schemas.get(d.kind)
        probs = input_shape_problems(d, s, b.schemas) if (s is not None and d.data is not None) else []
        if probs:
            R.error("E-INPUT-SHAPE", d.path, "; ".join(probs[:5]) + " (the document is skipped by the semantic checks)")
            docs.append(Doc(d.path, d.kind, None, d.text, None))
        else:
            docs.append(d)
    return Bundle(root=b.root, schemas=b.schemas, docs=docs, requirements_txt=b.requirements_txt)


def run_all(b: Bundle, real_run: bool = False) -> Report:
    """Run every check group. real_run=True (CLI --real-run): placeholder models reachable from an
    agent are E-MODEL-PLACEHOLDER errors instead of W-MODEL-PLACEHOLDER warnings."""
    R = Report()
    view = quarantine(R, b)
    try:
        c = Ctx(view, real_run=real_run)              # D5: inside the guard
        c.original = b
    except Exception as exc:  # noqa: BLE001 - graceful: report, stop
        R.error("E-INTERNAL", "context", f"cannot build the check context: {type(exc).__name__}: {exc}")
        return R
    for name, fn in GROUPS:
        before_checks, before_err = R._checks, len(R.errors)
        try:
            fn(R, c)
        except Exception as exc:  # noqa: BLE001 - graceful: report, keep going
            R.error("E-INTERNAL", name, f"{type(exc).__name__}: {exc} | {traceback.format_exc(limit=3).splitlines()[-2].strip()}")
        R.groups.append((name, R._checks - before_checks, len(R.errors) - before_err))
    return R


__all__ = ["run_all", "GROUPS", "content_hash"]
