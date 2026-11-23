# SPDX-License-Identifier: Apache-2.0
"""Check group over the ROE and the legal review (L-1..L-6): targets, platforms, seed manifest, incident contacts, and
the run helpers derived from the ROE gates (job_span, g4_latest_decisions, expected_gaps).

Split out of checks.py (architecture refactor PR-D4, docs/adr/0003-split-checks.md). The text is moved verbatim; no
rule, error code or message changed. checks.GROUPS still lists the group in the same place.
"""
from __future__ import annotations

import datetime as dt

from . import derive, safety, timeutil
from .canonical import content_hash, signing_payload
from .checks_engagement import consolidation_person, cross_border_declared, missing_jurisdictions, profile
from .checks_signatures import silent_verify
from .context import Ctx
from .report import GATE_ROLES, LEGAL_GATE, ROE_GATES, Report, anchored_seqs, doc_guard, retention_max, ts, url_problem


# ============================================================== 8 ROE (+ L-1..L-6)
def job_span(c: Ctx, run_id, job_id) -> tuple[dt.datetime | None, dt.datetime | None]:
    """v0.5 (review r7 1.2): (receive time of the job's sandbox_job_start, of its sandbox_job_end) in the run's audit
    log, the Audit Writer's clock. A result's self-declared executed_at must lie inside it."""
    return derive.job_span(c.ix, run_id, job_id)


def g4_latest_decisions(c: Ctx, run_id) -> dict:
    """testcase_id -> (latest signed decision on it, receive time its current unbroken run of accepts began) at the end of
    the log: "currently allowed to dispatch". "Authorised when a job ran" is derive.g4_state(at=job start). Both come from
    the same rule (derive.g4_state); v0.4 read only the run's last G4 record, and r11 measured the approval from the latest
    record, not the one in force."""
    return {tc: (st.decision, st.approved_since) for tc, st in derive.g4_final_states(c.ix, run_id).items()}


# review r12: the run's "untested" list (docs/02 B6) is derived, not taken from the run record. A skipped job's gap kind
# follows its skip reason; reasons without a gap kind of their own keep their name.
SKIP_GAP_KIND: dict = {"g4_rejected": "g4_rejected", "g5_rejected": "g5_skipped", "g5_expired": "g5_skipped",
                       "ownership_failed": "ownership_failed", "seed_reset_failed": "seed_reset_failed",
                       "build_mismatch": "build_mismatch"}
UNRUN_OUTCOMES = ("ERROR", "SKIPPED", "STOPPED", "INVALID")


def expected_gaps(c: Ctx, rid, run: dict) -> dict:
    """(kind, ref) -> why, for every entry docs/02 B6 puts on the untested list that the run's own records imply: W4
    requirements and testcases marked MANUAL, testcases whose G4 decision at the end of the log is reject, SKIPPED jobs (by
    skip reason), failed ownership checks, results that did not run (ERROR / SKIPPED / STOPPED / INVALID) and GB decisions
    that stopped a phase, and the run itself when it was closed as expired. A G3 rejection is not a gap (the threat is reported as "未做黑箱驗證", docs/04 §3)."""
    out: dict = {}
    for x in run.get("w4_manual_requirements") or []:
        if isinstance(x, dict):
            out[("manual", x.get("requirement_id"))] = "W4 requirement marked MANUAL"
    for tcid in run.get("testcase_ids") or []:
        tc = c.ix.first("testcase", testcase_id=tcid)
        if tc and (tc.data.get("tool_binding") or {}).get("kind") == "MANUAL":
            out[("manual", tcid)] = "MANUAL testcase"
    g4_states = derive.g4_final_states(c.ix, rid)
    for tcid, st in g4_states.items():
        # r14 (internal review A6; docs/02 §1.4 G4 row): a final needs_info is a rejection after the second round, and
        # the testcase never ran; r12 counted only a final reject
        if st.decision in ("reject", "needs_info"):
            out[("g4_rejected", tcid)] = f"{st.decision} at G4"
    if any(g.data.get("outcome") != "EXPIRED" for g in c.ix.gate_records(rid, "G4")):
        # r14 (A6): a black-box testcase of the run that no signed G4 decision ever covered was never approved either
        for tcid in run.get("testcase_ids") or []:
            tc = c.ix.first("testcase", testcase_id=tcid)
            if tc and (tc.data.get("tool_binding") or {}).get("kind") != "MANUAL" and tcid not in g4_states:
                out[("g4_rejected", tcid)] = "no G4 decision covers the testcase"
    for jid, job in (run.get("jobs") or {}).items():
        if isinstance(job, dict) and job.get("status") == "SKIPPED":
            out[(SKIP_GAP_KIND.get(job.get("skip_reason"), job.get("skip_reason") or "error"), job.get("testcase_id"))] = \
                f"job {jid} SKIPPED ({job.get('skip_reason')})"
        elif isinstance(job, dict) and job.get("status") in ("INTERRUPTED", "STOPPED"):
            # r14 (internal review A3): a job the run stopped before it finished has no result; r12's list named only
            # SKIPPED jobs, so an approved job that never finished left a COMPLETED run with no gap
            out[("stopped", job.get("testcase_id"))] = f"job {jid} {job.get('status')} before it finished"
    for o in run.get("ownership_results") or []:
        if isinstance(o, dict) and o.get("ok") is False:
            out[("ownership_failed", o.get("target_id"))] = "ownership check failed"
    for x in c.docs("testresult"):
        if x.data.get("run_id") == rid and x.data.get("outcome") in UNRUN_OUTCOMES:
            out[("error", x.data.get("testcase_id"))] = f"result {x.data.get('result_id')} is {x.data.get('outcome')}"
    for gb in c.ix.gate_records(rid, "GB"):
        if (gb.data.get("gb") or {}).get("choice") == "stop_phase":
            out[("gb_stopped", gb.data.get("gate_record_id"))] = "GB stopped a phase"
    audit = c.ix.audit_for(rid)
    evs = audit.data if audit and isinstance(audit.data, list) else []
    if any(isinstance(e, dict) and e.get("event_type") == "resume_expired" for e in evs[:anchored_seqs(evs)]):
        out[("expired", rid)] = "the run was closed when the engagement validity ended (resume_expired)"
    return out


BLACK_BOX_KINDS = ("testcase", "testresult", "threat")          # B2-B4 artefacts (seed threats are W5 output)


def g_roe(R: Report, c: Ctx):
    r, e, tk, w = c.roe, c.engagement, c.toolkit, "roe.yaml"
    if not r:
        # v0.5 (review 2026-10-25 §4.3): the ROE is read from G0b on, so a white-box-only bundle (no black-box artefact,
        # no G0b-or-later gate record) is valid without one; anything of the B phase still needs it
        black = [k for k in BLACK_BOX_KINDS if c.docs(k)] + sorted(
            {g.data.get("gate") for g in c.docs("gate-record") if g.data.get("gate") in ROE_GATES})
        if black or any((run.get("jobs") or {}) for run in c.runs.values()):
            R.error("E-ROE-MISSING", w, f"no ROE, but the bundle has black-box content {black or ['run.jobs']}")
        return
    # v0.6 (review r7, group 5): each section is guarded on its own, so one malformed section (signatories: [None],
    # windows: "x", relay.max_turns: null, ...) yields one E-INTERNAL for that section instead of hiding the rest
    targets: dict = {}
    with doc_guard(R, "roe.yaml (engagement and validity)"):
        eng = r.get("engagement") or {}
        R.check(eng.get("id") == e.get("engagement_id") and eng.get("version") == e.get("version"), "E-ROE-ENGAGEMENT", w,
                "engagement.id/version must match engagement.yaml")
        v = r.get("validity") or {}
        nb, na = ts(R, v.get("not_before"), w), ts(R, v.get("not_after"), w)
        ev = e.get("validity") or {}
        enb, ena = ts(R, ev.get("not_before"), "engagement.yaml"), ts(R, ev.get("not_after"), "engagement.yaml")
        R.check(nb and na and nb < na, "E-ROE-VALIDITY", w, "not_before must precede not_after")
        R.check(nb and na and enb and ena and enb <= nb and na <= ena, "E-ROE-VALIDITY", w, "ROE validity must lie inside the engagement validity")
        for i, win in enumerate(v.get("windows") or []):
            try:
                timeutil.zone(win.get("tz"))
                s, en = timeutil.hhmm(win.get("start")), timeutil.hhmm(win.get("end"))
                R.check(s != en, "E-ROE-WINDOW", w, f"windows[{i}]: start == end")
                R.check(set(win.get("days", [])) <= set(timeutil.DAYS) and win.get("days"), "E-ROE-WINDOW", w, f"windows[{i}]: bad days")
            except timeutil.TimeError as exc:
                R.error("E-ROE-WINDOW", w, f"windows[{i}]: {exc}")
    with doc_guard(R, "roe.yaml (signatories)"):
        roles = {s.get("role") for s in r.get("signatories") or []}
        R.check(GATE_ROLES["G0b"] <= roles, "E-ROE-SIGNATORIES", w, f"signatories must include {sorted(GATE_ROLES['G0b'])}")
        # E1 / L-13: one person signs the ROE in at most one required role (lite + acknowledged consolidation excepted)
        holders: dict = {}
        for s in r.get("signatories") or []:
            if s.get("role") in GATE_ROLES["G0b"]:
                holders.setdefault(s.get("person_id"), set()).add(s.get("role"))
        for p, rs in holders.items():
            if len(rs) > 1:
                R.check(p == consolidation_person(c), "E-ROE-SOD", w,
                        f"{p} signs the ROE as {sorted(rs)}: required ROE roles need distinct persons (assurance_profile {profile(c)})")
    with doc_guard(R, "roe.yaml (platform)"):
        platform_rules(R, c)
    with doc_guard(R, "roe.yaml (test roles and relay mode)"):
        used_roles = {x for d in c.docs("testcase") for x in (d.data.get("data_needed") or {}).get("roles") or []}
        for tr_ in r.get("test_roles", []):
            if tr_.get("role") in used_roles:
                R.check(isinstance(tr_.get("whoami"), dict), "E-ROE-WHOAMI", w,
                        f"test role {tr_.get('role')} is used by testcases but has no whoami check (E3)")
        relay_ = r.get("relay") or {}
        if relay_.get("mode") == "adaptive":
            R.check(profile(c) == "full", "E-ROE-RELAY-MODE", w, f"relay mode adaptive is only allowed with assurance_profile full (got {profile(c)})")
    with doc_guard(R, "roe.yaml (targets)"):
        targets = {t.get("id"): t for t in r.get("targets", [])}
        R.check(len(targets) == len(r.get("targets", [])), "E-ROE-TARGETS", w, "duplicate target ids")
        for t in r.get("targets", []):
            if t.get("kind") == "http":
                R.check(t.get("base_url") and t.get("endpoint") is None, "E-ROE-TARGETS", w, f"{t.get('id')}: http target needs base_url only")
            elif t.get("kind") == "database":
                R.check(t.get("endpoint") and t.get("base_url") is None, "E-ROE-TARGETS", w, f"{t.get('id')}: database target needs endpoint only")
        # a target the ROE itself excludes is contradictory; for database targets the host comes from
        # the endpoint (base_url is null), so the exclusion list must be checked against it as well
        excl_hosts = (r.get("exclusions") or {}).get("hosts") or []
        for t in r.get("targets", []):
            if t.get("kind") == "database":
                h = safety.target_host(t)     # None: unparseable (bare host, '[::1', '::1:5432', trailing dot)
                R.check(h is not None, "E-ROE-DB-SCOPE", w,
                        f"{t.get('id')}: unparseable endpoint {t.get('endpoint')!r} (need host:port or [IPv6]:port)")
                R.check(h is None or not safety.host_excluded(h, excl_hosts), "E-ROE-DB-SCOPE", w,
                        f"{t.get('id')}: database host {h!r} is in exclusions.hosts (compared after trailing-dot/case/IDNA normalisation)")
            elif t.get("kind") == "http" and t.get("base_url"):
                prob = url_problem(t.get("base_url"))
                R.check(prob is None, "E-ROE-URL", w, f"{t.get('id')}: base_url {prob}")
                h = safety.host_of(t.get("base_url"))
                R.check(h is not None, "E-ROE-TARGETS", w, f"{t.get('id')}: unparseable base_url {t.get('base_url')!r} (no host)")
                R.check(h is None or not safety.host_excluded(h, excl_hosts), "E-ROE-TARGETS", w,
                        f"{t.get('id')}: base_url host {h!r} is in exclusions.hosts (compared after trailing-dot/case/IDNA normalisation)")
            # v0.4 (BL-15): CDN edge ranges are public CIDRs on http targets only; the Scope Proxy enforces them (safety.ip_in_ranges)
            for cidr in t.get("edge_ip_ranges") or []:
                prob = safety.edge_range_problem(cidr) if t.get("kind") == "http" else "only http targets have edge ranges"
                R.check(prob is None, "E-ROE-EDGE-RANGE", w, f"{t.get('id')}: edge_ip_ranges {prob}")
        for tr in r.get("test_roles", []):
            R.check((tr.get("login") or {}).get("target_id") in targets, "E-ROE-TARGETS", w, f"test role {tr.get('role')}: login target not in ROE")
    with doc_guard(R, "roe.yaml (db_access)"):
        db = r.get("db_access")
        if db:
            t = targets.get(db.get("target_id")) or {}
            R.check(t.get("kind") == "database" and t.get("endpoint") == db.get("endpoint"), "E-ROE-DB", w,
                    f"[binding rule] db_access.target_id {db.get('target_id')!r} must be a database target whose endpoint "
                    f"string equals db_access.endpoint {db.get('endpoint')!r}")
            # scope: the db_access host must be the host of an in-scope ROE database target and not excluded
            dbh = safety.endpoint_host(db.get("endpoint"))
            in_scope = {h for x in r.get("targets", []) if x.get("kind") == "database" and (h := safety.target_host(x))}
            if R.check(dbh is not None, "E-ROE-DB-SCOPE", w,
                       f"[scope rule] db_access: unparseable endpoint {db.get('endpoint')!r} (need host:port or [IPv6]:port)"):
                R.check(dbh in in_scope, "E-ROE-DB-SCOPE", w,
                        f"[scope rule] db_access endpoint host {dbh!r} is not the (normalised) host of any ROE database target (out of scope)")
                R.check(not safety.host_excluded(dbh, excl_hosts), "E-ROE-DB-SCOPE", w,
                        f"[exclusion rule] db_access endpoint host {dbh!r} is in exclusions.hosts (compared after trailing-dot/case/IDNA normalisation)")
            R.check(db.get("oracle_readonly_attested") is True, "E-ROE-DB", w, "oracle_readonly_attested must be true")
            R.check(db.get("seed_manifest_ref") == c.manifest.get("manifest_ref"), "E-ROE-DB", w, "seed_manifest_ref != seed manifest manifest_ref")
            R.check(c.manifest.get("db_target_id") == db.get("target_id"), "E-ROE-DB", "seed-manifest.yaml", "db_target_id != roe db_access.target_id")
            R.check(c.manifest.get("engagement_id") == e.get("engagement_id"), "E-ROE-DB", "seed-manifest.yaml", "engagement_id mismatch")
            oracle = set(db.get("oracle_tables", []))
            for qid, q in (c.manifest.get("oracle_queries") or {}).items():
                R.check(q.get("table") in oracle, "E-ROE-DB", "seed-manifest.yaml", f"oracle query {qid}: table {q.get('table')} not in ROE oracle_tables")
    with doc_guard(R, "roe.yaml (activities)"):
        acts = r.get("activities") or {}
        R.check("S3" not in acts.get("allowed_safety_classes", []), "E-ROE-S3", w, "S3 can never be allowed")
        R.check(safety.TOOLKIT_DENYLIST <= set(acts.get("denied_modes", [])), "E-ROE-DENYLIST", w, "denied_modes must include the toolkit deny-list")
        tools = (c.tools.get("tools") or {})
        denied_in_registry = {f"{t}:{m}" for t, spec in tools.items() for m, ms in (spec.get("modes") or {}).items() if ms.get("toolkit_denied")}
        R.check(denied_in_registry == set(safety.TOOLKIT_DENYLIST), "E-TOOLS-DENYLIST", "tools.yaml",
                f"toolkit_denied modes {sorted(denied_in_registry)} != safety.TOOLKIT_DENYLIST {sorted(safety.TOOLKIT_DENYLIST)}")
        for t in acts.get("allowed_tools", []):
            spec = tools.get(t)
            R.check(spec is not None and any(m.get("b4_executable") for m in (spec.get("modes") or {}).values()), "E-ROE-TOOLS", w,
                    f"allowed tool {t!r} is not a B4-executable tool in tools.yaml")
        for m in acts.get("denied_modes", []):
            R.check(safety.registry_entry(c.tools, m) is not None, "E-ROE-TOOLS", w, f"denied mode {m!r} is not registered")
    with doc_guard(R, "roe.yaml (stop_conditions)"):
        defaults = tk.get("stop_condition_defaults") or {}
        for k, val in (r.get("stop_conditions") or {}).items():
            if k in defaults and isinstance(val, (int, float)) and isinstance(defaults[k], (int, float)):
                stricter = val >= defaults[k] if k.startswith("min_") else val <= defaults[k]
                R.check(stricter, "E-ROE-STOP", w, f"stop_conditions.{k}={val} is looser than the toolkit default {defaults[k]}")
        R.check(bool((r.get("stop_conditions") or {}).get("contacts")), "E-ROE-STOP", w, "stop_conditions.contacts must not be empty")
        hu = (r.get("stop_conditions") or {}).get("health_url")
        if hu is not None:
            prob = url_problem(hu)
            R.check(prob is None, "E-ROE-URL", w, f"stop_conditions.health_url {prob}")
    with doc_guard(R, "roe.yaml (build_identity)"):
        for t in r.get("targets", []):
            bi = t.get("build_identity") or {}
            need = {"header": ("header_name",), "endpoint": ("path", "json_pointer"), "none": ()}.get(bi.get("method"), ())  # type: ignore[arg-type]  # an unknown method yields no required fields
            extra = [k for k in ("header_name", "path", "json_pointer") if k not in need and bi.get(k) is not None]
            missing = [k for k in need if bi.get(k) is None]
            R.check(not extra and not missing, "E-ROE-TARGETS", w,
                    f"{t.get('id')}: build_identity method {bi.get('method')!r} needs {list(need)} and null {extra or 'others'}")
    with doc_guard(R, "roe.yaml (seed manifest)"):
        seed_manifest_rules(R, c, targets)
        for ce in c.manifest.get("create_only_endpoints") or []:
            R.check(ce.get("target_id") in targets and (targets.get(ce.get("target_id")) or {}).get("kind") == "http", "E-SEED-MANIFEST",
                    "seed-manifest.yaml", f"create_only_endpoints: {ce.get('target_id')} is not an http target of the ROE")
            problem = safety.created_resource_problem(ce)       # v0.5
            R.check(problem is None, "E-SEED-MANIFEST", "seed-manifest.yaml",
                    f"create_only_endpoints {ce.get('method')} {ce.get('path_template')}: {problem}")
    with doc_guard(R, "roe.yaml (relay)"):
        relay, trelay = r.get("relay") or {}, tk.get("relay") or {}
        for k in ("max_turns", "max_spend_usd_per_job", "max_spend_usd_per_run"):
            if k in relay:
                R.check(trelay.get(k) is not None and relay[k] <= trelay[k], "E-ROE-RELAY", w, f"relay.{k} exceeds toolkit relay")
        for mk in relay.get("models", []):
            m = c.model(mk)
            if R.check(m is not None, "E-MODEL-UNKNOWN", w, f"relay model {mk!r} unknown"):
                R.check(mk in (e.get("allowed_models") or {}).get(e.get("data_class"), []), "E-ROE-RELAY", w, f"relay model {mk} not allowed for the data class")
    with doc_guard(R, "roe.yaml (data handling)"):
        dh = r.get("data_handling") or {}
        R.check(dh.get("data_class") == e.get("data_class"), "E-ROE-DATA-CLASS", w, "data_handling.data_class != engagement data_class")
        rrd = dh.get("retention_days")
        R.check(isinstance(rrd, int) and rrd <= e.get("retention_days", 0), "E-ROE-RETENTION", w,
                f"data_handling.retention_days {rrd} longer than the engagement retention_days {e.get('retention_days')} (ROE may only shorten)")
        lim = retention_max(tk, e.get("data_class"))
        R.check(lim is None or (isinstance(rrd, int) and rrd <= lim), "E-RETENTION", w,
                f"data_handling.retention_days {rrd} above the toolkit.yaml maximum {lim}")
        for u in r.get("upstream_llm_providers") or []:
            R.check(u.get("terms_confirmed_by") in c.persons, "E-PERSON-UNKNOWN", w, "upstream terms_confirmed_by must be a registry person")
    with doc_guard(R, "roe.yaml (incident response)"):
        incident_rules(R, c)
    with doc_guard(R, "roe.yaml (legal review)"):
        legal(R, c)


INCIDENT_COVERS = {"data_exposure", "third_party_side_effect", "shared_platform_impact", "staging_outage"}


def incident_rules(R: Report, c: Ctx):
    """v0.4 (C5): the ROE says who is told, how fast, under which procedure and liability terms, when a test leaks
    data, triggers a real third-party side effect, hits another tenant of a shared platform or takes staging down."""
    ir, w = c.roe.get("incident_response"), "roe.yaml"
    if not R.check(isinstance(ir, dict), "E-ROE-INCIDENT", w, "incident_response is required"):
        return
    for p in ir.get("contacts") or []:  # type: ignore[union-attr]  # R.check above returned when incident_response is not a dict
        R.check(p in c.persons, "E-ROE-INCIDENT", w, f"incident_response contact {p!r} is not a registry person")
    R.check(bool(ir.get("contacts")), "E-ROE-INCIDENT", w, "incident_response needs at least one contact")  # type: ignore[union-attr]  # R.check above returned when incident_response is not a dict
    miss = sorted(INCIDENT_COVERS - set(ir.get("covers") or []))  # type: ignore[union-attr]  # R.check above returned when incident_response is not a dict
    R.check(not miss, "E-ROE-INCIDENT", w, f"incident_response.covers misses {miss}")


def legal(R: Report, c: Ctx):
    r, w = c.roe, "roe.yaml"
    lr = r.get("legal_review")
    # L-1
    if not R.check(isinstance(lr, dict), "E-L1", w, "legal_review is required (docs/06 §2.1.1 L-1)"):
        return
    for k, val in (lr.get("scope") or {}).items():  # type: ignore[union-attr]  # R.check above returned when legal_review is not a dict
        ok = val is True or (isinstance(val, dict) and (val.get("value") is True or bool(val.get("not_applicable_reason"))))
        R.check(ok, "E-L1", w, f"legal_review.scope.{k} must be true or carry not_applicable_reason")
    # v0.4: the ROE cannot call cross-border "not applicable" when the signed engagement declares a cross-border transfer
    cb = (lr.get("scope") or {}).get("cross_border")  # type: ignore[union-attr]  # R.check above returned when legal_review is not a dict
    if cross_border_declared(c):
        R.check(cb is True or (isinstance(cb, dict) and cb.get("value") is True), "E-ROE-TRANSFER", w,
                "engagement data_transfer leaves the source jurisdiction, so legal_review.scope.cross_border must be true")
    # C3 (2026-11-22 review): the review names the jurisdictions it covers; the signed engagement names where the data
    # starts and where it goes. A review of "TW" for an engagement that sends code to US providers had not looked at
    # the destination, and nothing compared the two (the shipped example was exactly that)
    for j in missing_jurisdictions(c):
        R.check(False, "E-ROE-TRANSFER", w, f"legal_review.jurisdictions {lr.get('jurisdictions')!r} does not cover {j} "  # type: ignore[union-attr]  # R.check above returned when legal_review is not a dict
                "(the engagement's data_transfer names it as the source jurisdiction or a transfer region)")
    # L-2
    att = lr.get("attested_by")  # type: ignore[union-attr]  # R.check above returned when legal_review is not a dict
    live = [x for x in c.entries if x.get("person_id") == att and not x.get("revoked_at")]
    roles = {ro for x in live for ro in x.get("roles", [])}
    R.check(bool(live), "E-L2", w, f"legal_review.attested_by {att!r} has no unrevoked registry key")
    if live and "legal_reviewer" not in roles:
        if "management" in roles:
            R.warn("W-L2-MANAGEMENT", w, f"{att} attests as management (no legal_reviewer role): flag this in the report")
        else:
            R.error("E-L2", w, f"{att} has neither the legal_reviewer nor the management role")
    # L-3
    sig = next((s for s in r.get("signatures") or [] if s.get("signer") == att), None)
    ok3 = sig is not None and silent_verify(c, signing_payload(r), sig, ts(R, r.get("issued_at"), w))
    R.check(ok3, "E-L3", w, f"legal_review.attested_by {att} has no valid signature on this ROE")
    # L-4
    v = r.get("validity") or {}
    at, exp = ts(R, lr.get("attested_at"), w), ts(R, lr.get("expires_at"), w)  # type: ignore[union-attr]  # R.check above returned when legal_review is not a dict
    nb, na = ts(R, v.get("not_before"), w), ts(R, v.get("not_after"), w)
    R.check(at and nb and at <= nb, "E-L4", w, "legal_review.attested_at must be on or before ROE not_before")
    R.check(exp and na and exp >= na, "E-L4", w, "legal_review.expires_at must be on or after ROE not_after")
    # L-5
    leads = {s.get("person_id") for s in r.get("signatories") or [] if s.get("role") == "test_lead"}
    if att in leads and att is not None and att == consolidation_person(c):
        # lite + acknowledged role consolidation: allowed, but the report header must say the attestation is self-signed
        R.warn("W-L5-LITE", w, f"legal_review.attested_by {att} is also the test_lead (lite role_consolidation): "
               "the report header must state that the legal attestation was self-signed")
    else:
        R.check(att not in leads, "E-L5", w, f"legal_review.attested_by {att} must not be the ROE test_lead "
                "(G0b -> VERIFY_FAILED, reason legal_attester_is_test_lead; the run is SUSPENDED until the ROE is fixed)")
    # L-6
    tools = c.tools.get("tools") or {}
    status = {x.get("component"): x.get("status") for x in c.licenses.get("components", [])}
    gated = [t for t in (r.get("activities") or {}).get("allowed_tools", []) if status.get((tools.get(t) or {}).get("license_ref")) == LEGAL_GATE]
    if gated:
        R.check((lr.get("scope") or {}).get("component_licenses") is True, "E-L6", w,  # type: ignore[union-attr]  # R.check above returned when legal_review is not a dict
                f"enabled tools {gated} are 法務閘門 in licenses.yaml: legal_review.scope.component_licenses must be true")


path_shape = safety.path_shape      # a path template with every {variable} segment reduced to {}


def proven_reads(c: Ctx) -> set:
    """D5 (2026-11-22 review, user decision): the (method, path shape) of every W0 inventory GET / HEAD endpoint whose
    `writes` is false. safety.read_is_proven accepts these; an endpoint the inventory does not know, or one whose writes is
    true or null (the extractor could not tell), proves nothing and its GET is a write."""
    return {(ep.get("method"), path_shape(ep.get("path"))) for d in c.docs("inventory") for ep in d.data.get("endpoints") or []
            if isinstance(ep, dict) and ep.get("method") in safety.READ_PROOF_METHODS and ep.get("writes") is False}


def seed_manifest_rules(R: Report, c: Ctx, targets: dict):
    """v0.4 (write scope):
    - E-ROE-SEED-MANIFEST: ROE db_access.seed_manifest_sha256 is the content hash of the loaded seed manifest, so
      the infrastructure owner signs create_only_endpoints / state_changing_reads / read_only_endpoints;
    - E-SEED-SIDE-EFFECT: every W0 inventory GET / HEAD endpoint with writes true is declared in
      state_changing_reads (same method and path template, any target); declared endpoints are http targets."""
    w = "roe.yaml"
    db = c.roe.get("db_access") if isinstance(c.roe, dict) else None
    if isinstance(db, dict) and c.manifest:
        R.check(db.get("seed_manifest_sha256") == content_hash(c.manifest), "E-ROE-SEED-MANIFEST", w,
                f"db_access.seed_manifest_sha256 {db.get('seed_manifest_sha256')} != content hash of the seed manifest "
                f"{content_hash(c.manifest)}: the infrastructure owner must sign the manifest the run uses")
    # v0.5 (review 2026-10-25 §4.3): compare path shapes, not literal text: /api/x/{id} (W0) and /api/x/{invoice}
    # (manifest) are the same endpoint
    declared = {(e.get("method"), path_shape(e.get("path_template"))) for e in c.manifest.get("state_changing_reads") or [] if isinstance(e, dict)}
    for key in ("state_changing_reads", "read_only_endpoints"):
        for e in c.manifest.get(key) or []:
            if isinstance(e, dict):
                R.check((targets.get(e.get("target_id")) or {}).get("kind") == "http", "E-SEED-MANIFEST", "seed-manifest.yaml",
                        f"{key} target {e.get('target_id')!r} must be an http ROE target")
    # v0.5 (BL-40): registered sensitive fields are usable by the leakage oracle: digit kinds carry enough digits, and
    # no normalized value belongs to two seeds (a hit must name the leaked record)
    owners: dict = {}
    for name, seed in (c.manifest.get("seeds") or {}).items():
        for f in (seed or {}).get("sensitive_fields") or [] if isinstance(seed, dict) else []:
            v = str(f.get("value", ""))
            if f.get("kind") in safety.DIGIT_KINDS:
                R.check(len(safety.sensitive_digits(v)) >= safety.MIN_DIGITS, "E-SEED-SENSITIVE", "seed-manifest.yaml",
                        f"seeds.{name}.{f.get('field')}: a {f.get('kind')} needs at least {safety.MIN_DIGITS} digits to be matched as a digit sequence")
            owners.setdefault(safety.normalize_sensitive(v), set()).add(name)
    for v, names in owners.items():
        R.check(len(names) == 1, "E-SEED-SENSITIVE", "seed-manifest.yaml", f"sensitive value {v!r} is registered on several seeds {sorted(names)}")
    # v0.5 (review r7 1.5): a read_only_endpoints entry turns POST requests into reads (S0); W0's writes verdict wins
    read_only = {(e.get("method"), path_shape(e.get("path_template"))) for e in c.manifest.get("read_only_endpoints") or [] if isinstance(e, dict)}
    for d in c.docs("inventory"):
        for ep in d.data.get("endpoints") or []:
            if isinstance(ep, dict) and ep.get("writes") is True and (ep.get("method"), path_shape(ep.get("path"))) in read_only:
                R.check(False, "E-SEED-SIDE-EFFECT", d.path, f"{ep.get('method')} {ep.get('path')} writes (W0) but the seed manifest "
                        "lists it in read_only_endpoints: its requests would be classified as reads (S0)")
    for d in c.docs("inventory"):
        for ep in d.data.get("endpoints") or []:
            if isinstance(ep, dict) and ep.get("method") in ("GET", "HEAD") and ep.get("writes") is True:
                R.check((ep.get("method"), path_shape(ep.get("path"))) in declared, "E-SEED-SIDE-EFFECT", d.path,
                        f"{ep.get('method')} {ep.get('path')} writes (W0) but is not in the seed manifest's state_changing_reads: "
                        "requests to it would be classified as reads (S0)")


def platform_of(host: str | None) -> str | None:
    """E2: the shared-platform suffix a host is under (safety.SHARED_PLATFORM_SUFFIXES), or None."""
    h = safety.norm_host(host) if host else ""
    for suffix, plat in safety.SHARED_PLATFORM_SUFFIXES.items():
        if h == suffix or h.endswith("." + suffix):
            return plat
    return None


def chain_platforms(chain) -> dict[str, str]:
    """C4 (2026-11-22 review): {name: platform} for the names of a resolved CNAME chain that lie under a shared-platform
    suffix (safety.SHARED_PLATFORM_SUFFIXES)."""
    out = {}
    for name in chain if isinstance(chain, list) else []:
        plat = platform_of(name) if isinstance(name, str) else None
        if plat is not None:
            out[name] = plat
    return out


def cname_platform_problems(c: Ctx, t: dict, o: dict) -> list[str]:
    """C4: a custom domain that is a CNAME to a shared platform (app.example.com -> cname.vercel-dns.com is not caught;
    app.example.com -> acme.vercel.app is) belongs to the platform's infrastructure just like acme.vercel.app. The ROE
    check reads the host name only, so such a target passed with dns_txt and without the platform's testing policy.
    The executor records the names it resolved (ownership_results[].cname_chain); an ok result whose chain reaches a
    shared platform needs what a host on that platform needs: platform_project of that platform and its accepted
    platform_policies entry."""
    if o.get("ok") is not True:
        return []
    op, out = t.get("ownership_proof") or {}, []
    policies = {p.get("platform") for p in c.roe.get("platform_policies") or [] if isinstance(p, dict)}
    for name, plat in sorted(chain_platforms(o.get("cname_chain")).items()):
        if not (op.get("method") == "platform_project" and op.get("platform") == plat):
            out.append(f"{t.get('id')}: its host resolves through {name} (a shared {plat} domain), so ownership cannot be ok with "
                       f"{op.get('method')!r}: the ROE must declare platform_project with platform {plat}")
        elif plat not in policies:
            out.append(f"{t.get('id')}: its host resolves through {name} (a shared {plat} domain) but the ROE has no platform_policies entry for {plat}")
    return out


def platform_rules(R: Report, c: Ctx):
    """E2 (H-D3): a target on a shared-platform domain proves ownership with platform_project and has an accepted
    platform_policies entry of the same platform; dns_txt / well_known_path are not accepted there."""
    r, w = c.roe, "roe.yaml"
    policies = {p.get("platform"): p for p in r.get("platform_policies") or [] if isinstance(p, dict)}
    for p in policies.values():
        R.check(p.get("accepted_by") in c.persons, "E-ROE-PLATFORM", w, f"platform_policies {p.get('platform')}: accepted_by must be a registry person")
    for t in r.get("targets", []):
        op = t.get("ownership_proof") or {}
        if op.get("method") == "platform_project":
            R.check(all(op.get(k) for k in ("platform", "project_ref", "evidence_ref")), "E-ROE-PLATFORM", w,
                    f"{t.get('id')}: platform_project needs platform, project_ref and evidence_ref")
        else:
            R.check(bool(op.get("token_ref")), "E-ROE-TARGETS", w, f"{t.get('id')}: {op.get('method')} needs token_ref")
        # v0.5 (review 2026-10-25 M-1): a database has no DNS TXT record or web root of its own to prove control with;
        # db_comment (the engagement token in COMMENT ON DATABASE, read with the read-only oracle credential) or
        # platform_project does. db_comment proves nothing about an HTTP host
        if t.get("kind") == "database":
            R.check(op.get("method") in ("db_comment", "platform_project"), "E-ROE-TARGETS", w,
                    f"{t.get('id')}: a database target proves ownership with db_comment or platform_project, not {op.get('method')}")
        else:
            R.check(op.get("method") != "db_comment", "E-ROE-TARGETS", w, f"{t.get('id')}: db_comment is only for database targets")
        host = safety.host_of(t.get("base_url")) if t.get("kind") == "http" else safety.endpoint_host(t.get("endpoint"))
        plat = platform_of(host)
        if plat is None:
            continue
        R.check(op.get("method") == "platform_project" and op.get("platform") == plat, "E-ROE-PLATFORM", w,
                f"{t.get('id')}: {t.get('base_url') or t.get('endpoint')} is on a shared {plat} domain: ownership_proof must be platform_project "
                f"with platform {plat} (dns_txt / well_known_path prove nothing there)")
        R.check(plat in policies, "E-ROE-PLATFORM", w, f"{t.get('id')}: no platform_policies entry for {plat}")
        shared_platform_proof(R, c, t, op)


TECHNICAL_PROOFS = {"http": ("deployed_path", "response_header"), "database": ("db_comment",)}


def shared_platform_proof(R: Report, c: Ctx, t: dict, op: dict):
    """v0.6 (review r7 4.1): platform_project proves only that someone pointed at a project (evidence_ref is a screenshot
    or a claim). A technical_proof shows control of the deployment itself: the engagement token served by the project's
    own deployment (a path or a response header the app sets) or, for a database, in COMMENT ON DATABASE. Without it
    the target may only be tested at S0 (passive reads of what anyone can fetch)."""
    w, tp = "roe.yaml", op.get("technical_proof")
    if isinstance(tp, dict):
        R.check(tp.get("method") in TECHNICAL_PROOFS.get(t.get("kind"), ()) and bool(tp.get("token_ref")), "E-ROE-PLATFORM", w,  # type: ignore[arg-type]  # an unknown kind yields no methods
                f"{t.get('id')}: technical_proof needs a token_ref and a method for a {t.get('kind')} target "
                f"({list(TECHNICAL_PROOFS.get(t.get('kind'), ()))})")  # type: ignore[arg-type]  # an unknown kind yields no methods
        return
    for d in c.docs("testcase"):
        tc = d.data
        if t.get("id") in (tc.get("target_ids") or []) and tc.get("safety_class_computed") not in (None, "S0"):
            R.error("E-ROE-PLATFORM", d.path, f"{tc.get('testcase_id')} is {tc.get('safety_class_computed')} on shared-platform target "
                    f"{t.get('id')}, which has no technical_proof of ownership: only S0 is allowed there")
