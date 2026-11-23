# SPDX-License-Identifier: Apache-2.0
"""Check groups over black-box testcases against the ROE, feedback records and report withdrawals; and the access-matrix
cells other groups read.

Split out of checks.py (architecture refactor PR-D6, docs/adr/0003-split-checks.md). The text is moved verbatim; no
rule, error code or message changed. checks.GROUPS still lists the groups in the same places.
"""
from __future__ import annotations

from . import crypto, derive, safety, seal
from .canonical import content_hash
from .checks_engagement import consolidation_person, profile
from .checks_gates import run_start
from .checks_roe import proven_reads
from .checks_signatures import MAX_CLOCK_SKEW, verify_signature
from .context import Ctx
from .report import Report, anchored_seqs, doc_guard, ts


# ============================================================== 12 testcases vs ROE
def tool_binding_rules(R: Report, tc: dict, w: str):
    """v0.5 (review 2026-10-25 §4.3, E-TC-TOOL): limits of a mode that the safety class cannot see.
    - schemathesis:* run only GET / HEAD operations (tools.yaml): a write would hit non-seed objects;
    - zap:baseline runs zap-api-scan.py, which scans actively unless -S is given: params.safe_mode must be true
      (the adapter renders -S; B3_validate_artifacts rejects an artefact without it)."""
    tb = tc.get("tool_binding") or {}
    adapter = tb.get("adapter") or ""
    if adapter.startswith("schemathesis:"):
        bad = sorted({r.get("method") for r in tc.get("request_allowlist") or [] if r.get("method") not in ("GET", "HEAD")})
        R.check(not bad, "E-TC-TOOL", w, f"{adapter} only runs GET / HEAD operations; request_allowlist has {bad}")
    if adapter == "zap:baseline":
        R.check((tb.get("params") or {}).get("safe_mode") is True, "E-TC-TOOL", w,
                "zap:baseline needs params.safe_mode true (zap-api-scan.py -S); without it the scan is active (zap:active, S2)")


def g_testcases(R: Report, c: Ctx):
    r = c.roe
    if not r:
        return
    keys = set((c.manifest.get("seeds") or {}).keys())
    oq = c.manifest.get("oracle_queries") or {}
    roe_roles = {x.get("role") for x in r.get("test_roles", [])}
    oracle_tables = set((r.get("db_access") or {}).get("oracle_tables", []))
    rl = r.get("rate_limits") or {}
    proven = proven_reads(c)
    for d in c.docs("testcase"):
        with doc_guard(R, d.path):
            tc, w = d.data, d.path
            tool_binding_rules(R, tc, w)
            ref = tc.get("seed_manifest_ref")
            mk = c.manifest if ref and ref == c.manifest.get("manifest_ref") else None
            # v0.5 (review 2026-10-25 H-5): required. Without the manifest the safety class cannot see the seeds,
            # state_changing_reads or read_only_endpoints, so a null ref turned a state-changing GET from S3 into S0
            R.check(ref is not None and ref == (r.get("db_access") or {}).get("seed_manifest_ref"), "E-TC-SEEDS", w,
                    f"seed_manifest_ref {ref!r} must be the ROE's seed manifest (db_access.seed_manifest_ref); it is required")
            try:
                level, trace = safety.compute_safety_class(tc, r, c.tools, mk, proven)
            except (KeyError, TypeError) as exc:
                R.error("E-TC-SAFETY", w, f"cannot compute safety class: missing {exc}")
                continue
            R.check(tc.get("safety_class_computed") == level, "E-TC-SAFETY", w,
                    f"safety_class_computed {tc.get('safety_class_computed')} != algorithm {level} ({'; '.join(trace)})")
            prop = tc.get("safety_class_proposed") or "S0"
            R.check(safety.ORDER.index(level) >= safety.ORDER.index(prop), "E-TC-SAFETY", w, "computed class below the LLM proposal")
            R.check(safety.admissible(level, r), "E-TC-ADMISSIBLE", w, f"class {level} cannot enter G4 ({'; '.join(trace)})")
            scope = safety.mutation_scope_problems(tc, mk, r, proven)
            R.check(not scope, "E-TC-MUTATION-SCOPE", w, "every mutation must be seed-bound or a create in the run namespace (B6): "
                    + "; ".join(scope))
            dn = tc.get("data_needed") or {}
            R.check(set(dn.get("roles", [])) <= roe_roles, "E-TC-ROLES", w, f"roles not in ROE test_roles: {sorted(set(dn.get('roles', [])) - roe_roles)}")
            R.check(set(dn.get("db_tables", [])) <= oracle_tables, "E-TC-DB", w, f"db_tables not in ROE oracle_tables: {sorted(set(dn.get('db_tables', [])) - oracle_tables)}")
            R.check(set(dn.get("seed_data", [])) <= keys, "E-TC-SEEDS", w, f"seeds not in the manifest: {sorted(set(dn.get('seed_data', [])) - keys)}")
            for req in tc.get("request_allowlist", []):
                for k in safety.seed_keys(req.get("path", "")):
                    R.check(k in keys, "E-TC-SEEDS", w, f"{req.get('path')}: seed {k!r} not in the manifest")
            o = tc.get("oracle") or {}
            if o.get("oracle_query_id"):
                q = oq.get(o["oracle_query_id"])
                if R.check(q is not None, "E-TC-ORACLE", w, f"oracle query {o['oracle_query_id']} not in the seed manifest"):
                    R.check(q.get("table") in set(dn.get("db_tables", [])), "E-TC-DB", w, f"oracle query table {q.get('table')} not in data_needed.db_tables")  # type: ignore[union-attr]  # a value an earlier check or lookup ruled out as None; mypy cannot follow it
            R.check(set(o.get("requirement_refs", [])) <= set(tc.get("requirement_ids", [])), "E-TC-ORACLE", w, "oracle.requirement_refs not in requirement_ids")
            tb = tc.get("tool_binding") or {}
            if str(tb.get("adapter", "")).startswith("zap:"):
                p = tb.get("params") or {}
                R.check(isinstance(p.get("delayInMs"), int) and p["delayInMs"] >= rl.get("zap_delay_ms_min", 0), "E-TC-ZAP", w,
                        f"delayInMs must be >= ROE zap_delay_ms_min {rl.get('zap_delay_ms_min')}")
                th = p.get("threadPerHost")
                R.check(th is None or (isinstance(th, int) and 1 <= th <= rl.get("max_concurrency", 0)), "E-TC-ZAP-THREADS", w,
                        f"threadPerHost {th} must be 1..ROE rate_limits.max_concurrency {rl.get('max_concurrency')}")
                if tb.get("adapter") == "zap:active":
                    mx = p.get("maxScanDurationInMins")
                    R.check(isinstance(mx, int) and 0 < mx <= rl.get("zap_max_scan_minutes", 0), "E-TC-ZAP", w,
                            f"maxScanDurationInMins must be 1..{rl.get('zap_max_scan_minutes')} (0 = unlimited is not allowed)")
            tr = tc.get("trials") or {}
            if tc.get("multi_turn"):
                relay = r.get("relay") or {}
                R.check(bool(relay.get("models")), "E-TC-RELAY", w, "multi_turn needs a ROE relay")
                R.check(tr.get("multi_turn_max_turns") is not None and tr["multi_turn_max_turns"] <= relay.get("max_turns", 0), "E-TC-RELAY", w,
                        "multi_turn_max_turns exceeds ROE relay.max_turns")
                st = tc.get("script_turns")
                if relay.get("mode") == "scripted":
                    R.check(isinstance(st, list) and 1 <= len(st) <= min(tr.get("multi_turn_max_turns") or 0, relay.get("max_turns", 0)),
                            "E-TC-SCRIPT", w, "relay mode scripted: script_turns must list 1..multi_turn_max_turns (<= ROE relay.max_turns) fixed user turns")
            else:
                R.check(tr.get("multi_turn_max_turns") is None, "E-TC-RELAY", w, "multi_turn_max_turns only for multi_turn testcases")
                R.check(tc.get("script_turns") is None, "E-TC-SCRIPT", w, "script_turns only for multi_turn testcases")
            if profile(c) == "lite" and tb.get("kind") != "MANUAL":
                R.check(level in ("S0", "S1"), "E-PROFILE-SAFETY", w, f"assurance_profile lite allows only S0/S1 toolkit-executed testcases, got {level}")
            approved = c.ix.approved_requirement_ids()
            refs = set(tc.get("requirement_ids") or []) | set(o.get("requirement_refs") or [])
            R.check(refs <= approved, "E-TC-REQ-UNAPPROVED", w,
                    f"requirements {sorted(refs - approved)} are not approved at G1 (REJECTED / NEEDS_INFO requirements are not testable)")
            R.check(1 <= tr.get("fail_k_min", 1) <= tr.get("n", 1), "E-TC-TRIALS", w, "fail_k_min must be 1..n")
            bad = [x for x in tc.get("expected_error_statuses") or [] if not (x == 429 or (isinstance(x, int) and 500 <= x <= 599))]
            R.check(not bad, "E-TC-EXPECTED-STATUS", w,               # v0.6 (review r7 4.3)
                    f"expected_error_statuses {bad}: only 429 and 5xx are exempt from the run-level stop conditions")
            signals = derive.probabilistic_signals(c.ix, tc)    # v0.6 (review r7 3.3); v0.7 (review r8, external review 2): the target decides
            if signals:
                need = derive.pass_min_effective(c.ix, tc)
                R.check(isinstance(tr.get("n"), int) and tr.get("n") >= need, "E-TC-TRIALS", w,  # type: ignore[operator]  # the isinstance / type check on the same line rules out None; mypy cannot follow it
                        f"a probabilistic test ({'; '.join(signals)}) declares n {tr.get('n')}: it needs "
                        f"n >= {need}, the effective trials a PASS requires")
                # v0.7 (review r9, external review 1): and declares it; an unset sampling hid the contract from the reader
                R.check(tr.get("sampling") == "sampled", "E-TC-TRIALS", w,
                        f"trials.sampling {tr.get('sampling')!r} contradicts the target: a test with probabilistic signals "
                        f"({'; '.join(signals)}) declares sampling sampled (an LLM feature is sampled whatever tool drives it)")
            # v0.7 (review r10): sampled is a declaration about the target; without a target-side signal it only bought the
            # exemption from the deterministic replay rule
            R.check(tr.get("sampling") != "sampled" or bool(signals), "E-TC-TRIALS", w,
                    "trials.sampling sampled, but the test has no target-side probabilistic signal (LLM threat, LLM adapter, "
                    "multi_turn, target_model record): a deterministic target is replayed deterministically")
            # v0.7 (review r8, external review 1): the per-trial cap the Scope Proxy enforces, so the replay budget is a bound
            trl = tc.get("rate_limit") or {}
            per = trl.get("max_requests_per_trial")
            R.check(per is None or (type(per) is int and 1 <= per <= trl.get("max_requests", 0)), "E-TC-RATE", w,
                    f"rate_limit.max_requests_per_trial {per!r} must be between 1 and max_requests {trl.get('max_requests')}")
            R.check(not signals or per is not None, "E-TC-RATE", w,
                    "a probabilistic test declares rate_limit.max_requests_per_trial (replays re-run one trial; without the cap the budget "
                    "counts a whole job per replay)")
            ctls = [x for x in tc.get("controls") or [] if isinstance(x, dict)]
            R.check(any(x.get("kind") == "reachability" for x in ctls), "E-TC-CONTROLS", w,
                    "a testcase needs at least one reachability control (B5)")
            ids = [x.get("control_id") for x in ctls]
            R.check(len(ids) == len(set(ids)), "E-TC-CONTROLS", w, f"duplicate control_id in {ids}")
            access_cells_check(R, c, tc, w)
            R.check(tb.get("adapter") == "manual" or safety.registry_entry(c.tools, tb.get("adapter", "")) is not None, "E-TC-TOOL", w,
                    f"adapter {tb.get('adapter')} not registered")


def access_cells_check(R: Report, c: Ctx, tc: dict, w: str):
    """v0.5 (BL-20, E-TC-ACCESS-CELL): a testcase covers only cells that exist in the G1 access matrix."""
    cells = access_matrix_cells(c)
    for x in tc.get("access_cells") or []:
        key = (x.get("role"), x.get("resource"), x.get("action")) if isinstance(x, dict) else None
        R.check(key in cells, "E-TC-ACCESS-CELL", w, f"access_cells {key} is not a cell of the G1 access matrix")


FEEDBACK_SUPPRESSION = {"false_positive": "accepted", "needs_info": "underReview"}


def feedback_suppression(c: Ctx, f: dict) -> str | None:
    """v0.7 (review r8 M4; r9): the SARIF suppression a feedback record earns. false_positive -> accepted only when two
    people signed it (signer and co_signed_by), one a security_reviewer who did not approve the cluster's G2 decision: an app_owner is the party with the conflict of interest, so its own
    false_positive stays underReview until a reviewer co-signs (co_signed_by). The suppression also lapses (underReview)
    when the adopting run's cluster with the same fingerprint is baseline_state updated: the code changed, review again."""
    label = f.get("label")
    if label == "needs_info":
        return "underReview"
    if label != "false_positive":
        return None
    # v0.7 (review r9): two people, one of them a security_reviewer who did not decide this cluster at G2. v0.7 let a single
    # security_reviewer suppress alone, including the one whose G2 decision the false positive overturns
    people = [x for x in (f.get("signed_by"), f.get("co_signed_by")) if isinstance(x, dict)]
    if len({x.get("person_id") for x in people}) < 2:
        return "underReview"
    cl = c.ix.first("cluster", cluster_id=f.get("cluster_id"), run_id=f.get("run_id"))
    deciders = set()
    if cl is not None:
        for g in c.ix.gate_records(cl.data.get("run_id"), "G2"):
            if any(x.get("item_id") == f.get("cluster_id") for x in g.data.get("decisions") or []):
                deciders |= {a.get("person_id") for a in g.data.get("approvers") or []}
    if not any(x.get("role") == "security_reviewer" and x.get("person_id") not in deciders for x in people):
        return "underReview"
    rec = feedback_record_event(c, f)
    if not isinstance(rec, str):
        adopting = (rec[0].get("run_id") if isinstance(rec[0], dict) else None)
        for k in c.docs("cluster"):
            if k.data.get("run_id") == adopting and k.data.get("fingerprint") == f.get("fingerprint") and k.data.get("baseline_state") == "updated":
                return "underReview"
    return "accepted"


def g_feedback(R: Report, c: Ctx):
    """v0.5 (BL-18, docs/08 §11.16, E-FEEDBACK): a developer's PR comment is only a hint; a feedback record counts only when
    signed by a registered security_reviewer / app_owner. The fingerprint is the named cluster's (a cluster of a run of
    the same engagement); duplicate names another cluster's fingerprint of the engagement; sarif_suppression follows the
    label (false_positive -> accepted, needs_info -> underReview, else null)."""
    # review r12 (E-AUDIT-FEEDBACK): the reverse direction. Every anchored feedback_recorded names a feedback record of the
    # bundle with that content hash; r11 only checked records against events, so deleting a recorded feedback (and with
    # it a SARIF suppression and a member of the spot-check population) left a dangling event and no error
    for a in c.ix.audit_docs():
        evs = a.data if isinstance(a.data, list) else []
        last = anchored_seqs(evs)
        for i, e in enumerate(evs):
            if isinstance(e, dict) and e.get("event_type") == "feedback_recorded" and i + 1 <= last:
                pl = e.get("payload") or {}
                f = c.ix.first("feedback", feedback_id=pl.get("feedback_id"))
                R.check(f is not None and content_hash(f.data) == pl.get("feedback_sha256"), "E-AUDIT-FEEDBACK", f"{a.path} seq {e.get('seq')}",
                        f"the anchored feedback_recorded names {pl.get('feedback_id')!r} (sha {pl.get('feedback_sha256')!r}), "
                        + ("but no such feedback record is in the bundle" if f is None else "but the record's content hash differs"))
    for d in c.docs("feedback"):
        with doc_guard(R, d.path):
            f, w = d.data, d.path
            run = c.runs.get(f.get("run_id")) or {}
            R.check(run.get("engagement_id") == f.get("engagement_id"), "E-FEEDBACK", w,
                    f"run {f.get('run_id')!r} is not a run of engagement {f.get('engagement_id')!r}")
            cl = c.ix.first("cluster", cluster_id=f.get("cluster_id"), run_id=f.get("run_id"))
            R.check(cl is not None and cl.data.get("fingerprint") == f.get("fingerprint"), "E-FEEDBACK", w,
                    f"fingerprint must be the fingerprint of {f.get('cluster_id')} in {f.get('run_id')}")
            prints = {k.data.get("fingerprint") for k in c.docs("cluster")
                      if (c.runs.get(k.data.get("run_id")) or {}).get("engagement_id") == f.get("engagement_id")}
            if f.get("label") == "duplicate":
                R.check(f.get("duplicate_of") in prints - {f.get("fingerprint")}, "E-FEEDBACK", w,
                        "a duplicate names the fingerprint of another cluster of the engagement (duplicate_of)")
            else:
                R.check(f.get("duplicate_of") is None, "E-FEEDBACK", w, "duplicate_of is only set for label duplicate")
            # review r11 (docs/08 §11.16): false_positive always needs two people, which a Lite engagement does not
            # have; Lite suppresses with wont_fix / needs_info, which the report marks as self-suppressed
            R.check(not (profile(c) == "lite" and f.get("label") == "false_positive"), "E-FEEDBACK", w,
                    "assurance_profile lite cannot record a false_positive (two people are needed); use wont_fix or needs_info")
            want = feedback_suppression(c, f)                   # v0.7 (review r8 M4)
            R.check(f.get("sarif_suppression") == want, "E-FEEDBACK", w,
                    f"label {f.get('label')} by {(f.get('signed_by') or {}).get('role')} (co-signed by "
                    f"{(f.get('co_signed_by') or {}).get('role')}) gives SARIF suppression {want!r}, not {f.get('sarif_suppression')!r}")
            sb = f.get("signed_by") or {}
            cs = f.get("co_signed_by")
            if isinstance(cs, dict):
                R.check(cs.get("role") == "security_reviewer" and cs.get("person_id") != sb.get("person_id"), "E-FEEDBACK", w,
                        "co_signed_by is a security_reviewer other than the signer")
            sigs = f.get("signatures") or []
            # v0.5 (review r7 1.11, external review 3): signed_at is the signer's own claim, so a retired key could sign
            # with a back-dated time. The run that adopts the feedback records it (feedback_recorded, anchored, pinning
            # the record's hash); the key is judged at that receive time, which signed_at must agree with
            rec = feedback_record_event(c, f)
            at = None
            if isinstance(rec, str):
                R.check(False, "E-FEEDBACK", w, rec)
            else:
                event, anchored = rec
                at = ts(R, event.get("ts"), w)
                R.check((event.get("payload") or {}).get("feedback_sha256") == content_hash(f), "E-FEEDBACK", w,
                        f"the feedback_recorded event pins feedback_sha256 {(event.get('payload') or {}).get('feedback_sha256')!r}, "
                        "not this record's content hash: the record changed after it was recorded")
                R.check(anchored, "E-FEEDBACK", w, "the feedback_recorded event is in the unanchored tail of its audit log")
                claimed = ts(R, f.get("signed_at"), w)
                R.check(claimed is not None and at is not None and abs(claimed - at) <= MAX_CLOCK_SKEW, "E-FEEDBACK", w,
                        f"signed_at {f.get('signed_at')} differs from the receive time {event.get('ts')} by more than {MAX_CLOCK_SKEW}")
                start = run_start(c, f.get("run_id"))
                R.check(start is None or (at is not None and at >= start), "E-FEEDBACK", w,
                        f"recorded at {event.get('ts')}, before run {f.get('run_id')} started ({start})")
            signers = seal.required_signers("feedback", f)
            ok = len(sigs) == len(signers) and all(s.get("signer") == x.get("person_id") and s.get("key_fingerprint") == x.get("key_fingerprint")
                                                   for s, x in zip(sigs, signers))
            if R.check(ok, "E-FEEDBACK", w, "a feedback record carries one signature per signer (signed_by, then co_signed_by), by their keys"):
                for s, x in zip(sigs, signers):
                    verify_signature(R, c, w, crypto.signing_payload(f), s, at, x.get("role"))


WITHDRAWAL_ROLES = ("test_lead", "security_reviewer")


def g_report_withdrawal(R: Report, c: Ctx):
    """E-REPORT-WITHDRAWAL (review r12, docs/06 §1.9 #4, BL-54): a delivered report is withdrawn by an engagement-level
    document signed by the test lead and a security reviewer (two people unless lite consolidates them), not by a line in
    the withdrawn run's audit log (that run ended with its run_end anchor and cannot be reopened). The withdrawn report
    exists in the engagement and is withdrawn once; a superseding report belongs to another run of the engagement that
    started later and was generated after the withdrawn one."""
    seen: dict = {}
    for d in c.docs("report-withdrawal"):
        with doc_guard(R, d.path):
            x, w = d.data, d.path
            R.check(x.get("engagement_id") == c.engagement.get("engagement_id"), "E-REPORT-WITHDRAWAL", w,
                    f"engagement_id {x.get('engagement_id')!r} is not this engagement's")
            rid = x.get("withdrawn_report_id")
            R.check(rid not in seen, "E-REPORT-WITHDRAWAL", w, f"report {rid} is already withdrawn by {seen.get(rid)}")
            seen.setdefault(rid, w)
            old = c.ix.first("report-manifest", report_id=rid)
            at = ts(R, x.get("withdrawn_at"), w)
            if R.check(old is not None, "E-REPORT-WITHDRAWAL", w, f"withdrawn_report_id {rid!r} names no report of the bundle"):
                R.check(old.data.get("run_id") == x.get("withdrawn_run_id"), "E-REPORT-WITHDRAWAL", w,  # type: ignore[union-attr]  # a value an earlier check or lookup ruled out as None; mypy cannot follow it
                        f"withdrawn_run_id {x.get('withdrawn_run_id')!r}, but report {rid} is run {old.data.get('run_id')}'s")  # type: ignore[union-attr]  # a value an earlier check or lookup ruled out as None; mypy cannot follow it
                gen = ts(R, old.data.get("generated_at"), w)  # type: ignore[union-attr]  # a value an earlier check or lookup ruled out as None; mypy cannot follow it
                R.check(at is not None and gen is not None and at >= gen, "E-REPORT-WITHDRAWAL", w,
                        f"withdrawn_at {x.get('withdrawn_at')} is before report {rid} was generated ({old.data.get('generated_at')})")  # type: ignore[union-attr]  # a value an earlier check or lookup ruled out as None; mypy cannot follow it
                new_id = x.get("superseded_by_report_id")
                if new_id is not None:
                    new = c.ix.first("report-manifest", report_id=new_id)
                    ok = new is not None and new_id != rid and new.data.get("run_id") != old.data.get("run_id")  # type: ignore[union-attr]  # a value an earlier check or lookup ruled out as None; mypy cannot follow it
                    if R.check(ok, "E-REPORT-WITHDRAWAL", w,
                               f"superseded_by_report_id {new_id!r} must name the report of another run of the bundle"):
                        s_old, s_new = run_start(c, old.data.get("run_id")), run_start(c, new.data.get("run_id"))  # type: ignore[union-attr]  # a value an earlier check or lookup ruled out as None; mypy cannot follow it
                        g_old, g_new = gen, ts(R, new.data.get("generated_at"), w)  # type: ignore[union-attr]  # a value an earlier check or lookup ruled out as None; mypy cannot follow it
                        R.check(s_old is not None and s_new is not None and s_new > s_old and g_new is not None and g_old is not None
                                and g_new > g_old, "E-REPORT-WITHDRAWAL", w,
                                f"the superseding report {new_id} must come from a run that started after run {old.data.get('run_id')} "  # type: ignore[union-attr]  # a value an earlier check or lookup ruled out as None; mypy cannot follow it
                                "and be generated after the withdrawn report")
            told = x.get("customer_notified_at")
            if told is not None:
                t = ts(R, told, w)
                R.check(t is not None and at is not None and t >= at, "E-REPORT-WITHDRAWAL", w,
                        f"customer_notified_at {told} is before the withdrawal was signed ({x.get('withdrawn_at')})")
            signers, sigs = seal.required_signers("report-withdrawal", x), x.get("signatures") or []
            roles = [s.get("role") for s in signers if isinstance(s, dict)]
            people = [s.get("person_id") for s in signers if isinstance(s, dict)]
            R.check(roles == list(WITHDRAWAL_ROLES), "E-REPORT-WITHDRAWAL", w,
                    f"signers must be the test lead, then a security reviewer (got roles {roles})")
            R.check(len(set(people)) == len(people) or people[0] == consolidation_person(c), "E-REPORT-WITHDRAWAL", w,
                    f"the test lead and the security reviewer are two people (got {people}); only an acknowledged lite "
                    "role_consolidation lets one person sign both")
            ok = len(sigs) == len(signers) and all(isinstance(g, dict) and isinstance(s, dict) and g.get("signer") == s.get("person_id")
                                                   and g.get("key_fingerprint") == s.get("key_fingerprint") for g, s in zip(sigs, signers))
            if R.check(ok, "E-REPORT-WITHDRAWAL", w, "a withdrawal carries one signature per signer, in order, by their keys"):
                for g, s in zip(sigs, signers):
                    verify_signature(R, c, w, crypto.signing_payload(x), g, at, s.get("role"))


def feedback_record_event(c: Ctx, f: dict):
    """(the feedback_recorded event of this feedback, anchored?) or a problem string. It is in the audit log of a run of the
    same engagement other than the one the feedback is about (the run that adopts it), exactly once."""
    hits = []
    for a in c.ix.audit_docs():
        rid = a.data[0].get("run_id") if a.data and isinstance(a.data[0], dict) else None
        if rid == f.get("run_id") or (c.runs.get(rid) or {}).get("engagement_id") != f.get("engagement_id"):
            continue
        last_anchor = max((i + 1 for i, e in enumerate(a.data) if isinstance(e, dict) and e.get("event_type") == "audit_anchor"), default=0)
        for e in a.data:
            if isinstance(e, dict) and e.get("event_type") == "feedback_recorded" and (e.get("payload") or {}).get("feedback_id") == f.get("feedback_id"):
                hits.append((e, type(e.get("seq")) is int and e.get("seq") < last_anchor))  # type: ignore[operator]  # the isinstance / type check on the same line rules out None; mypy cannot follow it
    if len(hits) != 1:
        return (f"{f.get('feedback_id')} has {len(hits)} feedback_recorded events in the audit logs of the engagement's other runs; "
                "the run that adopts it records it exactly once")
    return hits[0]


def access_matrix_cells(c: Ctx) -> set:
    """(role, resource, action) of every cell of the G1 access matrix (each action of a row is one cell)."""
    inv = c.b.data("invariants") or {}
    return {(r.get("role"), r.get("resource"), a) for r in inv.get("access_matrix") or [] if isinstance(r, dict) for a in r.get("actions") or []}
