# SPDX-License-Identifier: Apache-2.0
"""Check group that recomputes every verdict (docs/05 section 4.2): votes and their rounds, the adjudication inputs and
outcome, the text of the decision trace, and the verdict chains.

Split out of checks.py (architecture refactor PR-D8, docs/adr/0003-split-checks.md). The text is moved verbatim; no
rule, error code or message changed. checks.GROUPS still lists the group in the same place.
"""
from __future__ import annotations

import re

from . import adjudicate as adj
from . import timeutil
from .checks_calibration import BOUND_CLAIM_RE
from .checks_roe import job_span
from .context import Ctx
from .report import Report, anchored_seqs, doc_guard
from .verdict import (PHASE_ORDER, VERIFIER_TEMPLATE_ID, derive_verdict, eligible_verifier_families, g2_latest,
                      is_verifier_vote, members_at_vote, sarif_ref_problem, verifier_template_controls, vote_model,
                      vote_terms)


# ============================================================== 13 verdict recomputation
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
            dd = dv.diversity_degraded  # type: ignore[union-attr]  # a value an earlier check or lookup ruled out as None; mypy cannot follow it
            R.check(v.get("diversity_degraded") is dd, "E-VERDICT-DIVERSITY", w,
                    f"diversity_degraded {v.get('diversity_degraded')} but the weighted-valid votes' registry families give {dd} "
                    f"(eligible verifier families {sorted(eligible_verifier_families(c, dv.cluster))})")  # type: ignore[union-attr]  # a value an earlier check or lookup ruled out as None; mypy cannot follow it
            ne = dv.no_eligible_verifier  # type: ignore[union-attr]  # a value an earlier check or lookup ruled out as None; mypy cannot follow it
            R.check(v.get("no_eligible_verifier") is ne, "E-VERDICT-NOELIGIBLE", w,
                    f"no_eligible_verifier {v.get('no_eligible_verifier')} but agents.yaml verifiers outside the cluster's families/lineages give {ne}")
            tcx = dv.tool_corroboration  # type: ignore[union-attr]  # a value an earlier check or lookup ruled out as None; mypy cannot follow it
            R.check(sorted(v.get("tool_corroboration") or []) == tcx, "E-VERDICT-TOOLCORR", w,
                    f"tool_corroboration {v.get('tool_corroboration')} != derived {tcx} (audit-backed SARIF refs of calibrated high-precision rules)")
            tsx = dv.tool_signal  # type: ignore[union-attr]  # a value an earlier check or lookup ruled out as None; mypy cannot follow it
            R.check(sorted(v.get("tool_signal") or []) == tsx, "E-VERDICT-TOOLSIGNAL", w,
                    f"tool_signal {v.get('tool_signal')} != derived {tsx} (other audit-backed SARIF refs + E_fail_u results)")
            srcx = dv.independent_sources  # type: ignore[union-attr]  # a value an earlier check or lookup ruled out as None; mypy cannot follow it
            R.check(v.get("independent_sources") == srcx, "E-VERDICT-SOURCES", w,
                    f"independent_sources {v.get('independent_sources')} != derived {srcx} (independent families + weak SARIF + independently authored E_fail_u)")
            pv = dv.provisional  # type: ignore[union-attr]  # a value an earlier check or lookup ruled out as None; mypy cannot follow it
            R.check(v.get("provisional") is pv, "E-VERDICT-PROVISIONAL", w,
                    f"provisional {v.get('provisional')} != derived {pv} (no calibration version, theta_confirm null, or every eligible "
                    "verifier model has weight 0 in the cluster's bucket)")
            R.check(v.get("rule_version") == adj.RULE_VERSION, "E-VERDICT-RULE-VERSION", w,
                    f"rule_version {v.get('rule_version')!r} is not the adjudicator's {adj.RULE_VERSION!r}")
            # r14 (05-v0.15, internal review B7, user decision): a carried-in cluster has no members of its own to verify;
            # its status is decided by regression evidence only (R14 / R16), never by votes (a lone REFUTE made it
            # DISPUTED, a stronger one REJECTED and then R16 lifted it back to the source status)
            if dv.cluster.get("carried_from"):  # type: ignore[union-attr]  # a value an earlier check or lookup ruled out as None; mypy cannot follow it
                R.check(not v.get("votes") and not v.get("missing_votes"), "E-VERDICT-VOTE", w,
                        f"{v.get('cluster_id')} is a carried-in cluster (carried_from): it accepts no votes and no missing_votes; "
                        "its status comes from the regression tests (docs/05 §4.2 R14 / R16)")
            out = dv.outcome  # type: ignore[union-attr]  # a value an earlier check or lookup ruled out as None; mypy cannot follow it
            R.check(v.get("status") == out.status, "E-VERDICT-STATUS", w, f"status {v.get('status')} but the rules give {out.status} (row {out.row})")
            R.check(v.get("status_cap") == out.status_cap, "E-VERDICT-STATUS", w, f"status_cap {v.get('status_cap')} != {out.status_cap}")
            R.check(v.get("advisory") is out.advisory, "E-VERDICT-STATUS", w, f"advisory {v.get('advisory')} != {out.advisory}")
            kinds = {a.get("kind") for a in v.get("annotations", [])}
            R.check(kinds == out.annotations, "E-VERDICT-ANNOTATIONS", w, f"annotations {sorted(kinds)} != {sorted(out.annotations)}")
            # D6 (05-v0.16, user decision): a PASS without a positive control (E_pass_weak) supports no statistical bound.
            # The oracle was never shown to fail, so "upper bound 4.9%" measures whether the target wrote its log, and a
            # reader takes it for a security guarantee. A pattern check: it stops the stated bound, not a paraphrase
            if "E_pass" not in dv.inputs.evidence:  # type: ignore[union-attr]  # a value an earlier check or lookup ruled out as None; mypy cannot follow it
                for a in v.get("annotations", []):
                    if isinstance(a, dict) and a.get("kind") == "test_not_reproduced" and BOUND_CLAIM_RE.search(str(a.get("reason") or "")):
                        R.check(False, "E-VERDICT-ANNOTATIONS", w,
                                f"test_not_reproduced reason {a.get('reason')!r} states a statistical bound, but no linked PASS has a "
                                "positive control (E_pass_weak): say that no violation was observed and the oracle was not verified")
            rules = [str(x).split(":", 1)[0] for x in v.get("rule_trace", [])]
            if R.check(rules == out.rules, "E-VERDICT-TRACE", w, f"rule_trace rules {rules} != {out.rules}"):
                x = dv.inputs  # type: ignore[union-attr]  # a value an earlier check or lookup ruled out as None; mypy cannot follow it
                for msg in trace_text_problems(v.get("rule_trace", []), out, x, weighted_vote_counts(c, v, dv.cluster)):  # type: ignore[union-attr]  # a value an earlier check or lookup ruled out as None; mypy cannot follow it
                    R.check(False, "E-VERDICT-TRACE", w, msg)
            if v.get("status") == "CONFIRMED_EXECUTABLE":
                p = v.get("executable_proof") or {}
                ib = p.get("interpretation_confirmed_by")
                # a pre-registered deterministic interpretation needs no analyst (v0.3); an analyst, if any, is cross-family
                R.check(ib is None or (isinstance(ib, dict) and ib.get("family") not in dv.cluster.get("families", [])), "E-VERDICT-PROOF", w,  # type: ignore[union-attr]  # a value an earlier check or lookup ruled out as None; mypy cannot follow it
                        "executable proof interpretation must come from another family")
            for vt in v.get("votes", []):
                a = c.agents.get(vt.get("voter_agent_id")) if isinstance(vt.get("voter_agent_id"), str) else None
                R.check(is_verifier_vote(c.ix, vt), "E-VERDICT-VOTER-ROLE", w,
                        f"vote by {vt.get('voter_agent_id')!r} (agents.yaml role {(a or {}).get('role')!r}): only verifier-role agents "
                        "may vote; the vote is ignored for weighted_valid, score, support/refute and diversity")
                m = vote_model(c, vt)
                if R.check(m is not None, "E-VERDICT-VOTE", w,
                           f"vote by {vt.get('voter_agent_id')!r} with model {vt.get('voter_model_key')!r} does not resolve through agents.yaml / models.yaml"):
                    R.check(vt.get("voter_family") == m.get("family") and vt.get("voter_lineage") == m.get("lineage"), "E-VERDICT-VOTE", w,  # type: ignore[union-attr]  # a value an earlier check or lookup ruled out as None; mypy cannot follow it
                            f"vote by {vt.get('voter_agent_id')}: voter_family/lineage {vt.get('voter_family')}/{vt.get('voter_lineage')} "
                            f"!= registry {m.get('family')}/{m.get('lineage')}")  # type: ignore[union-attr]  # a value an earlier check or lookup ruled out as None; mypy cannot follow it
                if vt.get("valid"):
                    # r12: as verdict.vote_valid, against the members when the vote was cast (r11 R15); r11 kept the current
                    # members here, so the bundle r11 was built for (a refute cast before a same-family member joined)
                    # could satisfy neither E-DERIVED (valid true) nor this check
                    fams_v, lins_v = members_at_vote(c.ix, vt, dv.cluster)  # type: ignore[union-attr]  # a value an earlier check or lookup ruled out as None; mypy cannot follow it
                    R.check(vt.get("voter_family") not in fams_v
                            and c.ix.lineage_root(vt.get("voter_lineage")) not in c.ix.lineage_roots(lins_v),
                            "E-VERDICT-VOTE", w, f"self-review vote by {vt.get('voter_agent_id')} counted as valid (same family or base lineage)")
                    bound = max_vote_round(c, v, dv.cluster)  # type: ignore[union-attr]  # a value an earlier check or lookup ruled out as None; mypy cannot follow it
                    R.check(bound is None or type(vt.get("voted_after_round")) is not int or vt["voted_after_round"] <= bound,
                            "E-VERDICT-VOTE", w,
                            f"vote by {vt.get('voter_agent_id')}: voted_after_round {vt.get('voted_after_round')!r} but only rounds up to "
                            f"{bound} were dispatched (anchored CMD-2 plans) before this verdict version was recorded")
                anon, rand = verifier_template_controls(c.ix, dv.cluster)  # type: ignore[union-attr]  # a value an earlier check or lookup ruled out as None; mypy cannot follow it
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
