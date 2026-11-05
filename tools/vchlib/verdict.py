# SPDX-License-Identifier: Apache-2.0
"""Verdict derivation (docs/05 §4.2): everything a verdict version's derived fields are computed from, in one module.

The checker (checks.g_verdicts), the derived values (expectations.py) and the variant writer (tools/build_variants.py)
all read a verdict version's derived fields from here (architecture refactor PR-B; ADR 0001).
"""
from __future__ import annotations

from . import adjudicate as adj
from . import derive, safety, timeutil
from .calibration import clustering_icc, corpus_splits, high_precision_min, high_precision_problems
from .canonical import content_hash
from .context import Ctx
from .derive import Index


STANCE = {"SUPPORT": 1, "REFUTE": -1, "ABSTAIN": 0}


def vote_terms(ix: "Index", vote: dict, cluster: dict, version) -> tuple[bool, float, bool]:
    """(valid, weight, weighted_valid) of one vote. A vote by an agent without the verifier role is ignored
    (E-VERDICT-VOTER-ROLE in checks); v0.5 (review 2026-10-25 A-3): an abstention takes a side neither way, so it is never
    weighted-valid (v0.4 counted it, and one abstaining family could lift the R8 cap through diversity)."""
    valid = vote_valid(vote, cluster, ix)
    wgt = ix.weight(vote.get("voter_model_key"), cluster.get("cwe_bucket"), version, vote.get("stance"), cluster.get("run_id"))
    counts = valid and wgt > 0 and is_verifier_vote(ix, vote) and vote.get("stance") in ("SUPPORT", "REFUTE")
    return valid, wgt, counts


def root_score(terms) -> float:
    """S from [(base lineage, w * stance)]: each root counts once (v0.7, review r9; v0.7 r10: its strongest vote). S adds
    log likelihood ratios, which is only valid for independent observations; two verifiers of one base lineage share
    its blind spots, so they are one observation. v0.7 added them, and a claude_sonnet + claude_opus pair (1.44 each)
    passed theta_confirm 2.5 that no single vote reaches."""
    by_root: dict = {}
    for root, x in terms:
        by_root.setdefault(root, []).append(x)
    total = 0.0
    for xs in by_root.values():
        # v0.7 (review r10, rule_version 05-v0.9): votes of one root that agree count as its strongest vote; the mean let a
        # weaker SUPPORT of the same root lower S below theta (adding evidence must never remove it). Votes of one root
        # that disagree count as their mean; a SUPPORT and a REFUTE together are R3 (DISPUTED) whatever S is.
        same = all(x >= 0 for x in xs) or all(x <= 0 for x in xs)
        total += max(xs, key=abs) if same else sum(xs) / len(xs)
    return round(total, 4)


def derived_score(ix: "Index", v: dict, cluster: dict) -> float:
    """S = sum over base lineages of the mean w * stance of their weighted-valid votes, recomputed (v0.5, review r7 1.7:
    the rules use this value, not the verdict's own score, which E-DERIVED compares only within rounding; v0.7, review
    r9: one observation per root, root_score)."""
    terms = []
    for vote in v.get("votes", []):
        _, wgt, counts = vote_terms(ix, vote, cluster, v.get("calibration_version"))
        if counts:
            root = ix.independence_key(vote.get("voter_model_key")) or vote.get("voter_model_key")   # 05-v0.13: per observation
            terms.append((root, wgt * STANCE.get(vote.get("stance"), 0)))
    return root_score(terms)


# v0.5 (review 2026-10-25 A-7): the test phases a verdict version may see. A W4 version is written before any
# black-box execution, so it cannot cite B4 results; v0.4 linked every result of the run to every version.
RESULT_PHASES = {"W3_adjudicate": (), "G2_apply": (), "W4_readjudicate": ("W4",), "B5_readjudicate": ("W4", "B4")}


def linked_results(ix: Index, cluster: dict, readjudicated_by: str | None = "B5_readjudicate") -> list[dict]:
    phases = RESULT_PHASES.get(readjudicated_by, ())
    rs = [d.data for d in ix.docs("testresult")
          if d.data.get("run_id") == cluster.get("run_id") and cluster.get("cluster_id") in d.data.get("cluster_ids", [])
          and d.data.get("phase") in phases]
    return sorted(rs, key=lambda r: (timeutil.sort_key(r.get("executed_at")), str(r.get("result_id"))))


VERIFIER_TEMPLATE_ID = "w3-verify"


def verifier_template_controls(ix: "Index", cluster: dict) -> tuple[bool, bool]:
    """v0.4: (anonymizes_candidates, randomizes_order) of the run's W3 verifier prompt template. These are
    properties of the harness template recorded in the run manifest, not of the vote."""
    run = ix.first("run", run_id=cluster.get("run_id"))
    for t in ((run.data if run else {}) or {}).get("prompt_templates") or []:
        if isinstance(t, dict) and t.get("template_id") == VERIFIER_TEMPLATE_ID:
            return t.get("anonymizes_candidates") is True, t.get("randomizes_order") is True
    return False, False


CITE_LINE_RE = __import__("re").compile(r"^(?P<file>.+):(?P<a>[1-9][0-9]*)(?:-(?P<b>[1-9][0-9]*))?$")


def _cite_lines(c: str) -> tuple[str, int, int] | None:
    """`file:line` or `file:start-end` -> (file, start, end); anything else (no line, bad range) -> None."""
    m = CITE_LINE_RE.match(c)
    if m is None:
        return None
    a = int(m.group("a"))
    b = int(m.group("b")) if m.group("b") else a
    return (m.group("file"), a, b) if b >= a else None


def cited_relevant(ix: "Index", v: dict, cluster: dict) -> bool:
    """v0.5 (review 2026-10-25 A-4, A-5): at least one cited item is about this cluster.

    - every vote: a `file:line[-line]` inside the line range of a member finding's code_snippet evidence (same
      file), or `inventory:<pointer>` equal to a member's inventory_fact fact_ref;
    - a REFUTE vote may also cite a line inside a member finding's slice (slice.files[] path and line range), or any
      `inventory:<pointer>` that resolves in the run's W0 inventory: a refutation usually rests on code elsewhere
      on the path (a middleware check, a policy) or on configuration.
    v0.4 compared the file name only, so `file:99999` or a bare file name counted."""
    from . import evidence
    members = [ix.finding(fid) or {} for fid in cluster.get("member_finding_ids") or []]
    ranges, facts = [], set()
    for f in members:
        for e in f.get("evidence") or []:
            if not isinstance(e, dict):
                continue
            if e.get("kind") == "code_snippet" and isinstance(e.get("line_start"), int) and isinstance(e.get("line_end"), int):
                ranges.append((e.get("file"), e["line_start"], e["line_end"]))
            elif e.get("kind") == "inventory_fact":
                facts.add(e.get("fact_ref"))
    refute = v.get("stance") == "REFUTE"
    if refute:
        sids = {f.get("slice_id") for f in members}
        for sl in ix.docs("slice"):
            if sl.data.get("slice_id") in sids and sl.data.get("run_id") == cluster.get("run_id"):
                ranges.extend((x.get("path"), x.get("line_start"), x.get("line_end"))
                              for x in sl.data.get("files") or [] if isinstance(x, dict))
        inv = ix.first("inventory", run_id=cluster.get("run_id"))
    for c in v.get("cited_evidence") or []:
        if not isinstance(c, str):
            continue
        if c.startswith("inventory:"):
            ptr = c[len("inventory:"):]
            if ptr in facts or (refute and inv is not None and evidence.resolves(inv.data, ptr)):
                return True
            continue
        loc = _cite_lines(c)
        if loc and any(loc[0] == f and isinstance(a, int) and isinstance(b, int) and a <= loc[1] and loc[2] <= b
                       for f, a, b in ranges):
            return True
    return False


def members_at_vote(ix: "Index", v: dict, cluster: dict) -> tuple[list, list]:
    """r11 (05-v0.10): the cluster's (families, lineages) as they stood when the vote was cast: the members whose reporter
    round is at most the vote's `voted_after_round`. Without the field (or without an index) every member counts, the
    stricter reading. v0.7 r10 judged every vote against the members present now, so a same-family reporter added to the
    cluster in a later round (CMD-2 extra dispatch, or a prompt injection that steers three reviewers to one spot)
    silently voided a weighted REFUTE already cast."""
    vr = v.get("voted_after_round")
    if ix is None or type(vr) is not int or not cluster.get("member_finding_ids"):
        return list(cluster.get("families") or []), list(cluster.get("lineages") or [])
    fams, lins = set(), set()
    for fid in cluster.get("member_finding_ids") or []:
        rep = (ix.finding(fid) or {}).get("reporter") or {}
        if type(rep.get("round")) is int and rep["round"] <= vr:
            fams.add(rep.get("family")); lins.add(rep.get("lineage"))
    return sorted(x for x in fams if x), sorted(x for x in lins if x)


def member_observation_keys(ix: "Index", cluster: dict, up_to_round=None) -> set:
    """r14 (05-v0.15, internal review B2): the independence keys (Index.independence_key) of the models that reported the
    cluster's members (those with reporter.round <= up_to_round when given). A verifier whose key is among them shares an
    observation with a reporter (same family, same base lineage, or merged through a fine-tune's derived_from), so it is
    not independent of the cluster even when its family and lineage differ from every member's. 05-v0.13 merged such
    models in S, the independent sources and diversity, but judged vote eligibility and the verifier pool on family and
    lineage alone, so a model merged with a reporter through a third model could still be its eligible verifier."""
    keys = set()
    for fid in cluster.get("member_finding_ids") or []:
        rep = (ix.finding(fid) or {}).get("reporter") or {}
        if up_to_round is not None and not (type(rep.get("round")) is int and rep["round"] <= up_to_round):
            continue
        a = ix.agents.get(rep.get("agent_id")) if isinstance(rep.get("agent_id"), str) else None
        for mk in (rep.get("model_key"), (a or {}).get("model") if isinstance(a, dict) else None):
            k = ix.independence_key(mk)
            if k is not None:
                keys.add(k)
    return keys


def shares_observation(ix: "Index", model_key, cluster: dict, up_to_round=None) -> bool:
    """r14 (05-v0.15): the model's independence key is one of the cluster's member observations."""
    k = ix.independence_key(model_key)
    return k is not None and k in member_observation_keys(ix, cluster, up_to_round)


def later_member_overlap(ix: "Index", v: dict, cluster: dict) -> bool:
    """r11: a weighted vote cast before a member of the voter's family or base lineage joined the cluster (R15 annotation).
    r12: a REFUTE only, as the annotation's name says (refute_by_later_member_family); a SUPPORT cast before a same-family
    member joined is not the case R15 shows."""
    if v.get("stance") != "REFUTE":
        return False
    fams, lins = members_at_vote(ix, v, cluster)
    now_f, now_l = cluster.get("families") or [], cluster.get("lineages") or []
    overlap_now = v.get("voter_family") in now_f or v.get("voter_lineage") in now_l \
        or ix.lineage_root(v.get("voter_lineage")) in ix.lineage_roots(now_l)
    overlap_then = v.get("voter_family") in fams or v.get("voter_lineage") in lins \
        or ix.lineage_root(v.get("voter_lineage")) in ix.lineage_roots(lins)
    return overlap_now and not overlap_then


def vote_valid(v: dict, cluster: dict, ix: "Index | None" = None) -> bool:
    """docs/05 §4.2: family / lineage not in the cluster (r11: as the cluster stood when the vote was cast, members_at_vote);
    candidates anonymised and order randomised (v0.4: by the run's verifier template, not by the vote's own flags); and
    (v0.4) a cited item relevant to the cluster."""
    fams, lins = members_at_vote(ix, v, cluster)
    if v.get("voter_family") in fams or v.get("voter_lineage") in lins:
        return False
    if ix is not None and ix.lineage_root(v.get("voter_lineage")) in ix.lineage_roots(lins):
        return False                                                    # v0.6 (review r7 3.9): same base lineage
    if ix is not None and shares_observation(ix, v.get("voter_model_key"), cluster,
                                             v.get("voted_after_round") if type(v.get("voted_after_round")) is int else None):
        return False                                                    # r14 (05-v0.15): same independent observation
    if ix is None:
        return bool(v.get("anonymized")) and bool(v.get("order_randomized"))
    anon, rand = verifier_template_controls(ix, cluster)
    return anon and rand and bool(v.get("anonymized")) and bool(v.get("order_randomized")) and cited_relevant(ix, v, cluster)


def is_verifier_vote(ix: "Index", v: dict) -> bool:
    """Only agents.yaml agents with role verifier may vote (docs/05 §3); other votes are ignored."""
    a = ix.agents.get(v.get("voter_agent_id")) if isinstance(v.get("voter_agent_id"), str) else None
    return isinstance(a, dict) and a.get("role") == "verifier"


# ============================================================== 13 verdicts
PRE_G3_PHASES = ("W3_adjudicate", "G2_apply", "W4_readjudicate")


def g3_rejected(c: Ctx, v: dict, cluster: dict) -> bool:
    """R13: the cluster's seed threat(s) were rejected in a G3 gate record of the cluster's run.

    Derived from the G3 GateRecord decisions (not from threat.review), for every verdict produced
    after G3, i.e. any verdict that is not a W-phase (pre-G3) verdict. For each threat the latest
    G3 record that decides it counts; the cluster is g3_rejected when all its threats are rejected.
    """
    if v.get("readjudicated_by") in PRE_G3_PHASES:
        return False
    k = cluster.get("cluster_id")
    tids = {t.data.get("threat_id") for t in c.docs("threat") if t.data.get("source_cluster_id") == k}
    tids |= {s.get("threat_id") for d in c.docs("seed-threats") for s in d.data.get("seeds", [])
             if s.get("source_cluster_id") == k and s.get("threat_id")}
    if not tids:
        return False
    # v0.5 (review r7 1.1): an EXPIRED record is unsigned; it decides nothing
    recs = [x.data for x in c.ix.gate_records(cluster.get("run_id"), "G3") if x.data.get("outcome") != "EXPIRED"]
    last = {}
    for rec in recs:
        for x in rec.get("decisions", []):
            if x.get("item_id") in tids:
                last[x.get("item_id")] = x.get("decision")
    return all(last.get(t) in ("reject", "over_cap") for t in tids)          # v0.5: over_cap is a rule-based rejection


def g2_latest(c: Ctx, cluster: dict) -> tuple[dict | None, str | None]:
    """R10: the latest G2 gate record of the cluster's run that decides the cluster, and its decision.

    Derived from all G2 GateRecords of the run (not from the verdict's own g2_decision_ref), so a
    verdict cannot escape R10 by omitting or pointing at an older G2 record.
    """
    k = cluster.get("cluster_id")
    rec = dec = None
    for x in c.ix.gate_records(cluster.get("run_id"), "G2"):  # timestamp order
        if x.data.get("outcome") == "EXPIRED":                   # v0.5 (review r7 1.1): unsigned, decides nothing
            continue
        for d in x.data.get("decisions", []):
            if d.get("item_id") == k:
                rec, dec = x.data, d.get("decision")
    return rec, dec


def vote_observation(c: Ctx, vt: dict, m: dict):
    """Second external review of r12 (05-v0.13): the independent observation a vote belongs to (derive.Index.independence_key:
    one family unless M-2 evidence splits it; a shared base lineage always merges)."""
    return c.ix.independence_key(vt.get("voter_model_key")) or c.ix.lineage_root(m.get("lineage"))


def vote_model(c: Ctx, vt: dict) -> dict | None:
    """models.yaml entry that cast a vote, resolved through the registries (never the vote's own
    voter_family): voter_agent_id -> agents.yaml model; voter_model_key must be that model, or,
    when fallback_used names it, one of that model's (same-family) models.yaml fallbacks.
    None when the vote does not resolve consistently."""
    a = c.agents.get(vt.get("voter_agent_id")) if isinstance(vt.get("voter_agent_id"), str) else None
    if not isinstance(a, dict) or not a.get("model") or c.model(a.get("model")) is None:
        return None
    key = vt.get("voter_model_key")
    if key == a["model"] and vt.get("fallback_used") in (None, key):
        return c.model(key)
    if vt.get("fallback_used") == key and key in (c.model(a["model"]).get("fallback") or []):
        return c.model(key)
    return None


def eligible_verifier_models(c: Ctx, cluster: dict) -> dict[str, dict]:
    """model key -> models.yaml entry of every agents.yaml `verifier` whose registry family is not in
    cluster.families, whose registry lineage is not in cluster.lineages (never self-declared) and whose independence key
    is none of the members' (r14, 05-v0.15)."""
    fams, lins = set(cluster.get("families") or []), c.ix.lineage_roots(cluster.get("lineages"))   # v0.6: base lineages
    # v0.5 (review 2026-10-25 §4.3): a verifier that may not receive the run's data class (engagement allowed_models)
    # can never vote on it; counting it inflated |E| and left C-class clusters diversity_degraded for good
    dc = (c.runs.get(cluster.get("run_id")) or {}).get("data_class")
    allowed = set(((c.engagement.get("allowed_models") or {}).get(dc)) or []) if dc else set()
    out = {}
    for a in (c.agents or {}).values():
        if not isinstance(a, dict) or a.get("role") != "verifier":
            continue
        if allowed and a.get("model") not in allowed:
            continue
        m = c.model(a.get("model"))
        # r14 (05-v0.15, internal review B2): nor a model that shares an independent observation with a reporter
        # (member_observation_keys): the same grouping S, the sources and diversity already use
        if m and m.get("family") not in fams and c.ix.lineage_root(m.get("lineage")) not in lins and isinstance(m.get("family"), str) \
                and not shares_observation(c.ix, a.get("model"), cluster):
            out[a.get("model")] = m
    return out


def eligible_verifier_families(c: Ctx, cluster: dict) -> set[str]:
    """E(cluster) (docs/05 §3, v0.3): the registry families of eligible_verifier_models."""
    return {m.get("family") for m in eligible_verifier_models(c, cluster).values()}


def derived_no_eligible_verifier(c: Ctx, cluster: dict) -> bool:
    return not eligible_verifier_families(c, cluster)


def derived_diversity_degraded(c: Ctx, v: dict, cluster: dict) -> bool:
    """docs/05 §3 rule 3 / §4.2 [H] (v0.3, N-1): derived, never taken from the verdict itself.

    diversity_degraded = not Lane A, and E(cluster) is non-empty, and the number of distinct families
    among the WEIGHTED-valid verifier votes is below min(2, |E|). A vote's family comes from the
    registries (vote_model: voter_agent_id -> agents.yaml model -> models.yaml family). A 2-family cluster
    has |E| = 1, so one weighted vote of the third family is full diversity (v0.2 capped every such
    cluster). No eligible verifier at all is `no_eligible_verifier`, not degraded diversity.
    """
    run = c.runs.get(cluster.get("run_id")) or {}
    if run.get("run_kind") == "lane_a":
        return False
    e = eligible_verifier_families(c, cluster)
    if not e:
        return False
    roots = set()
    for x in v.get("votes", []):
        m = vote_model(c, x)
        # only verifier-role votes count (others: E-VERDICT-VOTER-ROLE, ignored); v0.7 (review r8, external review 3):
        # weighted_valid is recomputed and diversity counts base lineages, as independent_families and E(cluster) do
        if m is not None and vote_terms(c.ix, x, cluster, v.get("calibration_version"))[2]:
            roots.add(vote_observation(c, x, m))
    # 05-v0.13: diversity counts independent observations (one family unless M-2 evidence splits it), as S does
    return len(roots) < min(2, len({c.ix.independence_key(k) or k for k in eligible_verifier_models(c, cluster)}))


def derived_provisional(c: Ctx, v: dict, cluster: dict) -> bool:
    """E5 (H-E11): calibration_version null, or theta_confirm null, or every eligible verifier model of the
    cluster (E(cluster), from the registries, not from the votes present) has calibration weight 0 (both sides)
    in the cluster's CWE bucket. v0.4: false for black-box clusters and for statuses decided by rows 1-5."""
    # v0.4: provisional marks only verdicts that votes could have decided. A status fixed by R9 / R10 / R0 / R1
    # (rows 1-5) does not depend on calibration, and a black-box cluster never has votes.
    # v0.5: row 10 (strong tool corroboration, R5) is not decided by votes either
    if cluster.get("origin") == "black_box" or adj.adjudicate(verdict_inputs(c, v, cluster)).row in (1, 2, 3, 4, 5, 10, 14, 15, 16):
        return False
    if v.get("calibration_version") is None or v.get("theta_confirm") is None:
        return True
    return all(c.ix.weight(k, cluster.get("cwe_bucket"), v.get("calibration_version"), st, cluster.get("run_id")) == 0
               for k in eligible_verifier_models(c, cluster) for st in ("SUPPORT", "REFUTE"))


LICENSE_CLEARED = ("OK", "注意")     # licenses.yaml statuses that may run; 法務閘門 / 不採用 / 待查 / 參考 may not (N-7)


def license_status(c: Ctx, tool: str) -> str | None:
    ref = ((c.tools.get("tools") or {}).get(tool) or {}).get("license_ref")
    return next((x.get("status") for x in c.licenses.get("components") or [] if isinstance(x, dict) and x.get("component") == ref), None)


def _resolving_event(c: Ctx, cluster: dict, ref) -> tuple[dict | None, str | None]:
    """(tool_invocation_end event that backs a cluster.sarif_refs entry, None) or (None, problem)."""
    rid = cluster.get("run_id")
    audit = c.ix.audit_for(rid)
    if audit is None:
        return None, f"run {rid!r} has no (loadable) audit log, so SARIF ref {ref} cannot be resolved"
    ends = [e for e in audit.data if isinstance(e, dict) and e.get("event_type") == "tool_invocation_end"
            and ref in (e.get("payload_refs") or [])]
    if not ends:
        return None, f"SARIF ref {ref} is not in payload_refs of any tool_invocation_end event of run {rid}"
    # v0.5 (review 2026-10-25 V-7): only anchored lines are evidence. A tool_invocation_end after the last audit_anchor
    # is not yet covered by a Z3 countersignature, so anyone with write access to Z1 could have appended it
    anchored = max((i + 1 for i, e in enumerate(audit.data) if isinstance(e, dict) and e.get("event_type") == "audit_anchor"), default=0)
    reasons = []
    for e in ends:
        if not (type(e.get("seq")) is int and e.get("seq") < anchored):
            reasons.append(f"seq {e.get('seq')}: the event is in the unanchored tail of the audit log (last audit_anchor at "
                           f"line {anchored}); unanchored lines cannot back a verdict")
            continue
        p = e.get("payload") or {}
        adapter = p.get("adapter")
        entry = safety.registry_entry(c.tools, adapter)
        tool_spec = ((c.tools.get("tools") or {}).get(entry["tool"]) or {}) if entry else {}
        status = license_status(c, entry["tool"]) if entry else None
        if entry is None:
            reasons.append(f"seq {e.get('seq')}: adapter {adapter!r} is not a registered tools.yaml tool:mode")
        elif tool_spec.get("zone") != "Z2" or entry.get("b4_executable") is not False:
            reasons.append(f"seq {e.get('seq')}: {adapter} is not a white-box/static tool (zone Z2, b4_executable false)")
        elif status not in LICENSE_CLEARED:
            reasons.append(f"seq {e.get('seq')}: {adapter} is not legally cleared (licenses.yaml {tool_spec.get('license_ref')!r} "
                           f"status {status!r}; only {'/'.join(LICENSE_CLEARED)} may run)")
        elif e.get("zone") != "Z2":
            reasons.append(f"seq {e.get('seq')}: event zone {e.get('zone')!r} is not Z2")
        elif e.get("node") != "W1":
            # v0.5 (BL-13, docs/08 §11.2): ToolResults are W1 output and run.tool_results_ref lists only W1 events
            reasons.append(f"seq {e.get('seq')}: the invocation is a {e.get('node')!r} event, not W1")
        elif p.get("ok") is not True:
            reasons.append(f"seq {e.get('seq')}: invocation of {adapter} failed (payload.ok is not true)")
        elif (why := sarif_location_problem(cluster, ref, p)) is not None:
            reasons.append(f"seq {e.get('seq')}: {why}")
        else:
            return e, None
    return None, f"SARIF ref {ref}: " + "; ".join(reasons)


def sarif_location_problem(cluster: dict, ref, payload: dict) -> str | None:
    """v0.4 (D1): a SARIF result supports only the cluster at its own location.

    The normaliser (docs/08 §11.2 steps 3-5) records the result's repo-relative `file`, innermost
    `symbol` and `cwe_bucket` in its payload.sarif_results[] entry; they must equal the cluster key
    (canonical_location.file / .symbol and cwe_bucket). Black-box clusters have no source location and
    take no SARIF. v0.3 checked only that the ref was in the audit log, so any one-family cluster could
    borrow an unrelated result as a weak signal and reach LIKELY (R6)."""
    if cluster.get("origin") == "black_box":
        return "black_box clusters take no SARIF (they have no source location)"
    entry = next((x for x in payload.get("sarif_results") or [] if isinstance(x, dict) and x.get("ref") == ref), None)
    if entry is None:
        return "no payload.sarif_results entry for the ref"
    loc = cluster.get("canonical_location") or {}
    want = {"file": loc.get("file"), "symbol": loc.get("symbol"), "cwe_bucket": cluster.get("cwe_bucket")}
    got = {k: entry.get(k) for k in want}
    if got != want:
        return f"result location {got} is not the cluster key {want}"
    return None


def sarif_ref_problem(c: Ctx, cluster: dict, ref) -> str | None:
    """E-SARIF-REF: why a cluster.sarif_refs entry is not backed by the audit log (None = resolved).

    A SARIF ref counts only when the audit log of the cluster's run has a `tool_invocation_end`
    event that lists the ref in payload_refs, whose payload.adapter is a tools.yaml tool:mode of a
    white-box tool (tool zone Z2, mode b4_executable false) whose licenses.yaml status is cleared
    (OK / 注意; not 法務閘門, N-7), with event zone Z2 and payload.ok true, and whose
    payload.sarif_results[] entry has the cluster's file, symbol and CWE bucket (v0.4,
    sarif_location_problem; black_box clusters take no SARIF).
    """
    return _resolving_event(c, cluster, ref)[1]


def resolved_sarif_refs(c: Ctx, cluster: dict) -> list[str]:
    return sorted({r for r in cluster.get("sarif_refs") or [] if sarif_ref_problem(c, cluster, r) is None})


def sarif_rule(c: Ctx, cluster: dict, ref) -> tuple[str | None, str | None]:
    """(adapter, rule_id) of a resolved SARIF ref: payload.adapter and the payload.sarif_results entry for the ref."""
    e, _ = _resolving_event(c, cluster, ref)
    if e is None:
        return None, None
    p = e.get("payload") or {}
    rule = next((x.get("rule_id") for x in p.get("sarif_results") or [] if isinstance(x, dict) and x.get("ref") == ref), None)
    return p.get("adapter"), rule


def sarif_is_strong(c: Ctx, cluster: dict, ref) -> bool:
    """H-A1: STRONG iff (adapter, rule_id, tool_version) of the resolving audit event is a calibration.yaml
    result.high_precision_rules entry for the cluster's CWE bucket with precision_lower95 >= high_precision_min.
    A scanner or rule-pack version other than the calibrated one is WEAK."""
    e, _ = _resolving_event(c, cluster, ref)
    adapter, rule = sarif_rule(c, cluster, ref)
    if e is None or adapter is None or rule is None:
        return False
    version = (e.get("payload") or {}).get("tool_version")
    lim = high_precision_min(c)
    cfg = c.calibration.get("config") or {}
    return any(isinstance(h, dict) and h.get("adapter") == adapter and h.get("rule_id") == rule and h.get("tool_version") == version
               and h.get("cwe_bucket") == cluster.get("cwe_bucket")
               and not high_precision_problems(h, lim, clustering_icc(cfg), corpus_splits(cfg))
               for h in (c.calibration.get("result") or {}).get("high_precision_rules") or [])


def strong_sarif_refs(c: Ctx, cluster: dict) -> list[str]:
    return [r for r in resolved_sarif_refs(c, cluster) if sarif_is_strong(c, cluster, r)]


def weak_sarif_refs(c: Ctx, cluster: dict) -> list[str]:
    return [r for r in resolved_sarif_refs(c, cluster) if not sarif_is_strong(c, cluster, r)]


def e_fail_u_refs(v: dict) -> set[str]:
    return {x.get("result_ref") for x in (v.get("test_evidence") or {}).get("results", [])
            if isinstance(x, dict) and x.get("class") == "E_fail_u" and x.get("result_ref")}


def derived_tool_corroboration(c: Ctx, v: dict, cluster: dict) -> list[str]:
    """R2 (v0.3): STRONG tool corroboration only = resolved cluster.sarif_refs (E-SARIF-REF) whose
    (adapter, rule_id) is a calibrated high-precision rule for the cluster's bucket. Sorted; compared
    as a sorted list with the verdict's own list."""
    return sorted(strong_sarif_refs(c, cluster))


def derived_tool_signal(c: Ctx, v: dict, cluster: dict) -> list[str]:
    """R2 (v0.3): WEAK tool signals = the other resolved SARIF refs + result_refs of E_fail_u results."""
    return sorted(set(weak_sarif_refs(c, cluster)) | e_fail_u_refs(v))


def fail_u_independent(c: Ctx, v: dict, cluster: dict) -> bool:
    """v0.7 (review r8, rule_version 05-v0.7): an E_fail_u result counts as an independent source (R6) only when the
    agents that wrote or shaped its test (derive.test_author_families) are outside the cluster's families and base
    lineages. v0.6 counted every E_fail_u, so a single-family report plus a W4 FAIL the same family wrote and read (no
    pre-registration, no eligible analyst) reached LIKELY. It stays a signal for R4 row 7 (a dispute is safer)."""
    fams, roots = set(cluster.get("families") or []), c.ix.lineage_roots(cluster.get("lineages"))
    for tr in linked_results(c.ix, cluster, v.get("readjudicated_by")):
        if derive.classify_result(c.ix, tr, cluster)[0] != "E_fail_u":
            continue
        afams, alins = derive.test_author_families(c.ix, tr)
        if not (afams & fams) and not (c.ix.lineage_roots(alins) & roots):
            return True
    return False


def derived_independent_sources(c: Ctx, v: dict, cluster: dict) -> int:
    return (len(derive.independent_families(c.ix, cluster)) + (1 if weak_sarif_refs(c, cluster) else 0)
            + (1 if fail_u_independent(c, v, cluster) else 0))


def all_evidence_not_found(c: Ctx, cluster: dict) -> bool:
    """R0 input: no evidence item of any member finding is grounded (MATCHED / MATCHED_SHIFTED) and at least one is
    NOT_FOUND; False when there are no members. v0.6 (review r7): v0.5 needed every item NOT_FOUND, so one NOT_CHECKED
    item kept an otherwise ungrounded cluster out of R0.
    (v0.4: R0 itself also needs no resolved SARIF and no FAIL-class test evidence, adjudicate.r0_applies.)"""
    members = [c.ix.finding(f) for f in cluster.get("member_finding_ids") or []]
    if not members or any(m is None for m in members):
        return False
    items = [e for m in members for e in m.get("evidence") or [] if isinstance(e, dict)]
    return (any(e.get("match") == "NOT_FOUND" for e in items)
            and not any(e.get("match") in ("MATCHED", "MATCHED_SHIFTED") for e in items))


def proof_overrides_g2(c: Ctx, v: dict) -> bool:
    """R10 (v0.6, review r7 3.1 / 3.4): an E_proof result of the verdict that is a G4-approved B4 result whose replay
    job reproduced the violation at least once (k_r >= 1). Only such a proof was fixed by a human before it ran and
    replayed outside the white-box pipeline that G2 overruled."""
    for x in (v.get("test_evidence") or {}).get("results") or []:
        if not isinstance(x, dict) or x.get("class") != "E_proof":
            continue
        tr = next((d.data for d in c.docs("testresult") if content_hash(d.data) == x.get("result_ref")), None)
        if tr and proof_can_override(c, tr):
            return True
    return False


def proof_can_override(c: Ctx, tr: dict) -> bool:
    """The result is a G4-approved B4 result with at least one replay hit (R10, v0.6)."""
    return tr.get("phase") == "B4" and derive.g4_approved(c.ix, tr) and (tr.get("replay_k") or 0) >= 1


def verdict_inputs(c: Ctx, v: dict, cluster: dict) -> adj.Inputs:
    run = c.runs.get(cluster.get("run_id")) or {}
    # v0.5 (review 2026-10-25 H-3): R10 applies only to versions produced after G2. The W3 version is decided before
    # G2 exists, so a later G2 reject must not make it invalid; G2_apply writes the post-G2 version (R10 -> REJECTED)
    g2_rej = v.get("readjudicated_by") != "W3_adjudicate" and g2_latest(c, cluster)[1] == "reject"
    all_fail = all_evidence_not_found(c, cluster)      # R0 (v0.6): nothing grounded, one NOT_FOUND; False without members
    # v0.7 (review r8): weighted_valid is recomputed (vote_terms), never read from the verdict (docs/05 §4.2 "derived")
    votes = [x for x in v.get("votes", []) if vote_terms(c.ix, x, cluster, v.get("calibration_version"))[2]]
    g3_rej = g3_rejected(c, v, cluster)
    prev = c.ix.first("verdict", verdict_id=v["supersedes_verdict_id"]) if v.get("supersedes_verdict_id") else None
    return adj.Inputs(
        lane_a=run.get("run_kind") == "lane_a",
        g2_rejected=g2_rej,
        proof_overrides_g2=proof_overrides_g2(c, v),
        all_snippets_fail=all_fail,
        evidence={x.get("class") for x in (v.get("test_evidence") or {}).get("results", [])},
        fail_u_independent=fail_u_independent(c, v, cluster),     # v0.7 (review r8): R6 counts an independently authored FAIL
        # R11 (v0.4): only a qualified PASS with a PASSed oracle_can_fail control may downgrade; the per-result
        # positive_control is recomputed from the testresult (E-RESULT-CONTROLS), not taken from the verdict
        pass_positive=any(x.get("class") == "E_pass" and x.get("positive_control") is True
                          for x in (v.get("test_evidence") or {}).get("results", []) if isinstance(x, dict)),
        weighted_support=any(x.get("stance") == "SUPPORT" for x in votes),
        weighted_refute=any(x.get("stance") == "REFUTE" for x in votes),
        score=derived_score(c.ix, v, cluster),           # v0.5 (review r7 1.7)
        # audit-backed refs only (E-SARIF-REF), tiered by calibration (H-A1); never v.tool_corroboration / v.tool_signal
        strong_tool=bool(strong_sarif_refs(c, cluster)),
        weak_sarif=bool(weak_sarif_refs(c, cluster)),
        theta_confirm=v.get("theta_confirm"),
        theta_reject=v.get("theta_reject"),
        independent_families=len(derive.independent_families(c.ix, cluster)),   # recomputed (D14), not cluster.independent_families
        diversity_degraded=derived_diversity_degraded(c, v, cluster),   # derived, not self-declared
        g3_rejected=g3_rej,
        phase={"W3_adjudicate": "W3", "G2_apply": "G2", "W4_readjudicate": "W4", "B5_readjudicate": "B5"}.get(v.get("readjudicated_by")),
        prev_status=prev.data.get("status") if prev else None,
        regression_fixed=regression_fixed(c, v, cluster, run),
        carried_status=carried_status(c, cluster, run),
        later_member_overlap=any(later_member_overlap(c.ix, x, cluster) for x in votes),
        oracle_unreviewed=oracle_unreviewed(c, v, cluster),
    )


def oracle_unreviewed(c: Ctx, v: dict, cluster: dict) -> bool:
    """r14 (05-v0.15, internal review C3, user decision): a linked W4 result classifies as E_fail_u only because an LLM wrote
    its oracle and G2 has not accepted the cluster (derive.classify_result); the verdict is annotated `oracle_unreviewed`."""
    for tr in linked_results(c.ix, cluster, v.get("readjudicated_by")):
        cls, why = derive.classify_result(c.ix, tr, cluster)
        if cls == "E_fail_u" and "oracle_unreviewed" in why:
            return True
    return False


def carried_source(c: Ctx, cluster: dict, run: dict) -> dict | None:
    """The head verdict of the parent-run cluster a carried-in cluster stands for (carried_from), or None."""
    cf = cluster.get("carried_from") or {}
    if not isinstance(cf, dict) or not cf.get("run_id") or cf.get("run_id") != run.get("parent_run_id"):
        return None
    parent = c.runs.get(cf.get("run_id")) or {}
    src = [h for h in verdict_heads(c, parent.get("verdicts") or []) if h.get("cluster_id") == cf.get("cluster_id")]
    return src[0] if src else None


def carried_status(c: Ctx, cluster: dict, run: dict) -> str | None:
    """R16 (r12, 05-v0.11): the status of the source a carried-in cluster stands for (the floor while no regression test
    shows it fixed)."""
    src = carried_source(c, cluster, run)
    return src.get("status") if src else None


def result_testcase(c: Ctx, result_ref) -> str | None:
    """The testcase id of the test result a verdict links by content hash, or None."""
    tr = next((d.data for d in c.docs("testresult") if content_hash(d.data) == result_ref), None)
    return tr.get("testcase_id") if tr else None


def result_testcases(c: Ctx, verdict: dict, classes) -> set:
    """Testcase ids of a verdict's linked results of the given evidence classes."""
    out = set()
    for x in (verdict.get("test_evidence") or {}).get("results", []):
        if isinstance(x, dict) and x.get("class") in classes:
            tc = result_testcase(c, x.get("result_ref"))
            if tc:
                out.add(tc)
    return out


def regression_fixed(c: Ctx, v: dict, cluster: dict, run: dict) -> bool:
    """R14 (r11, 05-v0.10; docs/02 §1.6, 05 §4.2): a regression run's carried-in cluster whose source verdict (the head
    verdict of the parent run's cluster) was CONFIRMED_* is FIXED when its test evidence has a qualified PASS with a
    positive control and no FAIL-class evidence. v0.7 had no state for "fixed": the PASS landed on UNCORROBORATED with
    test_not_reproduced and the SARIF result stayed open.
    r12 (05-v0.11): and every testcase whose result proved the source (its E_proof results) has a linked result here, so a
    W4 PASS cannot declare fixed a defect a B4 proof established before that proof was re-run (docs/02 §1.6 "B 階段只跑對應
    測試案例"); a contradiction by tools or votes is handled in adjudicate (row 15).
    r12 external review (05-v0.12): each of those testcases is re-run with a qualified PASS of its own (E_pass with a
    positive control) and nothing else. 05-v0.11 counted an ERROR (E_inc) of the proving testcase as "re-run" and let a
    PASS of any other testcase supply the positive control, so a defect whose proof never passed again was FIXED; an
    unclear required case now leaves the cluster at its source's status (R16, fix_unverified)."""
    if run.get("run_kind") != "regression":
        return False
    src = carried_source(c, cluster, run)
    if not src or src.get("status") not in adj.CONFIRMED:
        return False
    results = [x for x in (v.get("test_evidence") or {}).get("results", []) if isinstance(x, dict)]
    classes = {x.get("class") for x in results}

    def qualified(x):
        return x.get("class") == "E_pass" and x.get("positive_control") is True
    by_case: dict = {}
    for x in results:
        by_case.setdefault(result_testcase(c, x.get("result_ref")), []).append(x)
    required = required_regression_testcases(c, cluster, run)
    return bool(required) and bool(classes) and not (classes & {"E_proof", "E_fail_u"}) \
        and all(by_case.get(tc) and all(qualified(x) for x in by_case[tc]) for tc in required)


def required_regression_testcases(c: Ctx, cluster: dict, run: dict) -> set:
    """r14 (05-v0.15, internal review B1): the testcases a FIXED needs, found by following the carried_from chain back to the
    first head verdict that holds an E_proof (the proof that established the defect), or, when no verdict of the chain
    ever had one, the first that holds an E_fail_u (a test that was at least shown to fail). 05-v0.12-05-v0.14 read the
    proving testcases from the immediate source only: a chain whose middle run kept the status through R16 (no E_proof
    of its own) handed the next run an empty requirement, so any one qualified PASS was FIXED; a CONFIRMED_CORROBORATED
    source (votes or a scanner rule, no test) did the same. An empty set means the cluster can never be FIXED here (R16,
    fix_unverified): a fix nobody can show a failing test for is not a verified fix."""
    seen = set()
    cl, rn = cluster, run
    fallback: set = set()
    while True:
        src = carried_source(c, cl, rn)
        if not src or id(src) in seen:
            return fallback
        seen.add(id(src))
        proof = result_testcases(c, src, {"E_proof"})
        if proof:
            return proof
        if not fallback:
            fallback = result_testcases(c, src, {"E_fail_u"})
        cd = c.ix.first("cluster", cluster_id=src.get("cluster_id"))
        if cd is None:
            return fallback
        cl, rn = cd.data, c.runs.get(src.get("run_id")) or {}


PHASE_ORDER = {"W3_adjudicate": 0, "G2_apply": 1, "W4_readjudicate": 2, "B5_readjudicate": 3}


def verdict_heads(c: Ctx, verdict_ids) -> list[dict]:
    """The latest version of each cluster among `verdict_ids` (a run's verdicts): not superseded by another of them."""
    vs = [x.data for x in (c.ix.first("verdict", verdict_id=i) for i in verdict_ids) if x is not None]
    superseded = {v.get("supersedes_verdict_id") for v in vs if v.get("supersedes_verdict_id") != v.get("verdict_id")}
    return [v for v in vs if v.get("verdict_id") not in superseded]
