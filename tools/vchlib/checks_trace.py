# SPDX-License-Identifier: Apache-2.0
"""Check group over traceability: clusters and their origin and binding, findings and their evidence, the inventory,
invariants and requirement levels, review plans and their coverage, the report queues and the pipeline.

Split out of checks.py (architecture refactor PR-D8, docs/adr/0003-split-checks.md). The text is moved verbatim; no
rule, error code or message changed. checks.GROUPS still lists the group in the same place.
"""
from __future__ import annotations

from . import derive, evidence, facets, safety
from .bundle import Doc
from .checks_runs import baseline_checks, plan_checks
from .context import Ctx
from .report import Report, doc_guard
from .verdict import PRE_G3_PHASES, _resolving_event, derived_no_eligible_verifier, g2_latest, sarif_ref_problem, verdict_heads


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
    return sites, cwes  # type: ignore[return-value]  # the lists were built untyped above


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
            if not R.check(inv is not None and evidence.resolves(inv, ev.get("fact_ref")), "E-INVENTORY-REF", w,  # type: ignore[arg-type]  # a value an earlier check or lookup ruled out as None; mypy cannot follow it
                           f"evidence[{i}].fact_ref {ev.get('fact_ref')!r} does not resolve in the W0 inventory of {f.get('run_id')}"):
                continue
            want = evidence.match_fact(inv, ev)  # type: ignore[arg-type]  # a value an earlier check or lookup ruled out as None; mypy cannot follow it
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
    std = {"asvs-5.0.0": "asvs", "aisvs-1.0": "aisvs"}.get(x.get("source"))  # type: ignore[arg-type]  # a value an earlier check or lookup ruled out as None; mypy cannot follow it
    return std, str(x.get("ref", "")).rsplit("-", 1)[-1], LEVELS.get(x.get("level"))  # type: ignore[arg-type]  # a value an earlier check or lookup ruled out as None; mypy cannot follow it


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
            R.check(level_covered(c, std, number, level), "E-INVARIANT-LEVEL", where,  # type: ignore[arg-type]  # a value an earlier check or lookup ruled out as None; mypy cannot follow it
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
            for a in ps.get("agents") or []:  # type: ignore[union-attr]  # a value an earlier check or lookup ruled out as None; mypy cannot follow it
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
                fams = {(m.data.get("reporter") or {}).get("family") for m in members}  # type: ignore[union-attr]  # a value an earlier check or lookup ruled out as None; mypy cannot follow it
                lins = {(m.data.get("reporter") or {}).get("lineage") for m in members}  # type: ignore[union-attr]  # a value an earlier check or lookup ruled out as None; mypy cannot follow it
                R.check(set(k.get("families", [])) == fams and set(k.get("lineages", [])) == lins, "E-CLUSTER-FAMILIES", w,
                        "families/lineages must be those of the member findings' reporters")
                R.check(all(m.data.get("run_id") == k.get("run_id") for m in members), "E-TRACE", w, "member finding from another run")  # type: ignore[union-attr]  # a value an earlier check or lookup ruled out as None; mypy cannot follow it
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
                want = {"accept": "ACCEPTED", "reject": "REJECTED", "needs_info": "NEEDS_INFO"}.get(dec)  # type: ignore[arg-type]  # a value an earlier check or lookup ruled out as None; mypy cannot follow it
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
                    R.check(set(t.get("source_finding_ids", [])) <= set(cl.data.get("member_finding_ids", [])), "E-TRACE", w, "source findings not in the cluster")  # type: ignore[union-attr]  # a value an earlier check or lookup ruled out as None; mypy cannot follow it
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
                R.check((th.data.get("review") or {}).get("status") == "ACCEPTED", "E-TRACE", w, "testcases only for threats accepted at G3")  # type: ignore[union-attr]  # a value an earlier check or lookup ruled out as None; mypy cannot follow it
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
                                                                       and (ix.first("cluster", cluster_id=k)).data.get("threat_id") == th.data.get("threat_id"))]  # type: ignore[union-attr]  # a value an earlier check or lookup ruled out as None; mypy cannot follow it
                    R.check(bool(tr.get("cluster_ids")) and not bad, "E-CLUSTER-ORIGIN", w,
                            f"result of {tcd.data.get('testcase_id')} (threat {th.data.get('threat_id')} has no source cluster) must be recorded "  # type: ignore[union-attr]  # a value an earlier check or lookup ruled out as None; mypy cannot follow it
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
                            f"clusters of threat {th.data.get('threat_id')} ({sorted(own)}); not {extra}")  # type: ignore[type-var]  # the values are strings in a schema-valid document; mypy sees Any | None
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
            th = ix.first("threat", threat_id=s.get("threat_id")) if s.get("threat_id") else True  # type: ignore[assignment]  # the name is reused with another type earlier in the function
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
    return sorted(out)  # type: ignore[arg-type]  # a value an earlier check or lookup ruled out as None; mypy cannot follow it


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


def _tool_of(c: Ctx, cluster: dict, ref) -> str | None:
    """The tools.yaml tool (not the mode) whose W1 invocation produced a SARIF ref."""
    e, _ = _resolving_event(c, cluster, ref)
    entry = safety.registry_entry(c.tools, (e.get("payload") or {}).get("adapter")) if e else None  # type: ignore[arg-type]  # a value an earlier check or lookup ruled out as None; mypy cannot follow it
    return entry["tool"] if entry else None
