# SPDX-License-Identifier: Apache-2.0
"""Check group over models.yaml and agents.yaml: reachable models, agents, family diversity.

Split out of checks.py (architecture refactor PR-D3, docs/adr/0003-split-checks.md). The text is moved verbatim; no
rule, error code or message changed. checks.GROUPS still lists the group in the same place.
"""
from __future__ import annotations

import datetime as dt

from . import derive
from .context import Ctx
from .report import DETERMINISTIC_ROLES, NON_ADJUDICATING_ROLES, PLACEHOLDER_ID, Report, doc_guard, is_date, ts


# ============================================================== 9 models / agents
def reachable_models(c: Ctx) -> dict[str, set[str]]:
    """model key -> agents that can call it: agent model, agent fallback_models, and the
    models.yaml `fallback` chain of either (transitively)."""
    out: dict[str, set[str]] = {}
    for name, a in (c.agents or {}).items():
        if not isinstance(a, dict):
            continue
        todo = [a.get("model"), *(a.get("fallback_models") or [])]
        seen: set[str] = set()
        while todo:
            k = todo.pop()
            if not isinstance(k, str) or k in seen:
                continue
            seen.add(k)
            out.setdefault(k, set()).add(name)
            m = c.model(k)
            if m:
                todo.extend(m.get("fallback") or [])
    return out


def g_models(R: Report, c: Ctx):
    e, models, agents = c.engagement, c.models, c.agents
    dc = e.get("data_class")
    allowed = set((e.get("allowed_models") or {}).get(dc, []))
    ev = e.get("validity") or {}
    enb, ena = ts(R, ev.get("not_before"), "engagement.yaml"), ts(R, ev.get("not_after"), "engagement.yaml")
    used = set()
    # v0.7 (review r8, external review 3): derived_from is a tree; a cycle gave each member its own root (lineage_root
    # stops where the cycle closes), so two mutually derived lineages counted as independent and verified each other
    for cyc in c.ix.lineage_cycles():
        R.error("E-MODEL-LINEAGE", "models.yaml", f"derived_from cycle {' -> '.join(cyc + cyc[:1])}: a lineage cannot derive from itself")
    # v0.7 (review r9, external review 2): derived_from describes the lineage, so all its models declare the same parent;
    # v0.7 kept the last declaration in file order, and reordering models.yaml changed the root (and with it who may verify whom)
    for lin, decl in sorted(c.ix.lineage_declarations().items()):
        R.check(len(decl) == 1, "E-MODEL-LINEAGE", "models.yaml",
                f"lineage {lin!r}: its models declare different derived_from {sorted(decl, key=str)}; every model of a lineage declares the same one")
    lineages = {m.get("lineage") for m in models.values() if isinstance(m, dict)}
    for mk, m in models.items():
        if isinstance(m, dict) and isinstance(m.get("derived_from"), str):
            R.check(m["derived_from"] in lineages and m["derived_from"] != m.get("lineage"), "E-MODEL-LINEAGE", f"models.yaml {mk}",
                    f"derived_from {m['derived_from']!r} must be another lineage of the registry")
    for name, a in agents.items():
        with doc_guard(R, f"agents.yaml {name}"):
            where = f"agents.yaml {name}"
            if not isinstance(a, dict):
                R.error("E-AGENT", where, "not an object")
                continue
            mk = a.get("model")
            if a.get("role") in DETERMINISTIC_ROLES:
                R.check(mk is None, "E-AGENT-MODEL", where, f"deterministic role {a.get('role')} must have model null")
                continue
            if not R.check(mk is not None, "E-AGENT-MODEL", where, "LLM role needs a model"):
                continue
            if not R.check(mk in models, "E-MODEL-UNKNOWN", where, f"unknown model {mk!r} (not in models.yaml)"):
                continue
            used.add(mk)
            R.check(mk in allowed, "E-AGENT-DATA-CLASS", where, f"model {mk} not allowed for data class {dc}")
            if a.get("fallback_models"):
                R.check(a.get("role") in NON_ADJUDICATING_ROLES, "E-AGENT-FALLBACK", where, "cross-family fallback_models only on non-adjudicating roles")
                for fb in a["fallback_models"]:
                    R.check(fb in models and fb in allowed, "E-AGENT-FALLBACK", where, f"fallback model {fb!r} unknown or not allowed")
    # v0.7 (review r10): a W4 FAIL is independent proof only when its test's authors are known and outside the cluster
    # (derive.authors_independent); without the author roles in agents.yaml nobody can tell who wrote the tests
    if any(t.data.get("phase") == "W4" for t in c.docs("testresult")):
        roles = {a.get("role") for a in agents.values() if isinstance(a, dict)}
        for role in derive.TEST_AUTHOR_ROLES["W4"]:
            R.check(role in roles, "E-AGENT-ROLES", "agents.yaml",
                    f"the bundle has W4 results but agents.yaml registers no {role}: the authors of the W4 tests are unknown")
    lane = agents.get("lane_a") or {}
    R.check(lane.get("model") == e.get("lane_a_model"), "E-AGENT-LANE-A", "agents.yaml lane_a", "lane_a model must equal engagement lane_a_model")
    for name, a in agents.items():
        with doc_guard(R, f"agents.yaml {name}"):
            if not isinstance(a, dict):
                continue
            tools_ = set(a.get("tools") or [])
            role = a.get("role")  # type: ignore[assignment]  # role is rebound per agent; a missing role fails the checks below
            where = f"agents.yaml {name}"
            # B10 (H-C1, H-C2, N-6): reviewers / verifiers see only their slice; the commander gets a typed view built by
            # code (no tools); the invariant drafter reads the W0 inventory, never code slices
            if role in ("reviewer", "verifier"):
                R.check(tools_ <= {"read_slice"}, "E-AGENT-TOOLS", where, f"{role} may only use read_slice, has {sorted(tools_)}")
            elif role == "commander":
                R.check(not tools_, "E-AGENT-TOOLS", where, f"commander has no tools (typed input view), has {sorted(tools_)}")
            elif role == "invariant_drafter":
                R.check("read_slice" not in tools_, "E-AGENT-TOOLS", where, "invariant_drafter must not read code slices")
            # D15 (M-V1): every model reachable through fallback must take the engagement's data class and be allowed for it
            if a.get("model") and role not in DETERMINISTIC_ROLES:
                todo, seen = list((c.model(a.get("model")) or {}).get("fallback") or []) + list(a.get("fallback_models") or []), set()
                while todo:
                    k = todo.pop()
                    if k in seen or not isinstance(k, str):
                        continue
                    seen.add(k)
                    m = c.model(k)
                    R.check(m is not None and dc in (m.get("data_classes") or []) and k in allowed, "E-MODEL-FALLBACK-CLASS", where,
                            f"fallback model {k!r} (reachable from {a.get('model')}) cannot take {dc} data or is not in allowed_models.{dc}")
                    todo.extend((m or {}).get("fallback") or [])
    reach = reachable_models(c)
    for k, m in models.items():
        with doc_guard(R, f"models.yaml {k}"):
            where = f"models.yaml {k}"
            if not isinstance(m, dict):
                R.error("E-MODEL", where, "not an object")
                continue
            for fb in m.get("fallback", []):
                R.check(fb in models and models[fb].get("family") == m.get("family"), "E-MODEL-FALLBACK", where, f"fallback {fb!r} unknown or cross-family")
            lit = str(m.get("litellm", ""))
            # placeholder model IDs (e.g. nemotron_cloud): marked, never silent
            looks_placeholder = PLACEHOLDER_ID.search(lit) is not None
            if m.get("placeholder") is True or looks_placeholder:
                users = sorted(reach.get(k, ()))
                detail = (f"litellm {lit!r} is a placeholder model ID (replace before any real run)"
                          + (f"; reachable from agents {users}" if users else "") + ("; allowed by the engagement" if k in allowed else ""))
                if c.real_run and users:
                    # --real-run: a placeholder an agent can actually call (primary, agent fallback or
                    # models.yaml fallback chain) would send traffic to an unknown / wrong model
                    R.error("E-MODEL-PLACEHOLDER", where, detail + " [--real-run]")
                elif m.get("placeholder") is True:
                    R.warn("W-MODEL-PLACEHOLDER", where, detail)
            R.check(not looks_placeholder or m.get("placeholder") is True, "E-MODEL-PLACEHOLDER", where,
                    f"litellm {lit!r} looks like a placeholder (<...>, {{...}}, TBD, TODO, FIXME, 實作時確認) but placeholder: true is not set")
            if lit.startswith("nvidia_nim/"):
                R.check("C" not in m.get("data_classes", []) and "production" not in m.get("purpose", []), "E-MODEL-NIM", where,
                        "build.nvidia.com trial endpoint must be P-only and non-production")
            if "C" in m.get("data_classes", []) and lit.startswith("openai/"):
                R.check(m.get("store") is False, "E-MODEL-STORE", where, "OpenAI API models taking C data must set store: false")
            er = m.get("earliest_retirement")
            if er is not None and not is_date(er):
                R.error("E-MODEL-RETIREMENT-DATE", where, f"earliest_retirement {er!r} is not a valid date (YYYY-MM-DD)")
                er = None
            if er and (k in used or k in allowed) and enb and ena:
                d = dt.date.fromisoformat(er)
                if d < enb.date():
                    R.error("E-MODEL-RETIRED", where, f"earliest_retirement {er} is before the engagement starts")
                elif d <= ena.date():
                    R.warn("W-MODEL-RETIREMENT", where, f"earliest_retirement {er} falls inside the engagement validity")
    # family diversity
    def fam(a):
        m = c.model(a.get("model"))
        return (m.get("family"), m.get("lineage"), set(m.get("data_classes", []))) if m else None
    reviewers = [f for f in (fam(a) for a in agents.values() if isinstance(a, dict) and a.get("role") == "reviewer") if f]
    verifiers = [f for f in (fam(a) for a in agents.values() if isinstance(a, dict) and a.get("role") == "verifier") if f]
    fams = {f for f, _, d in reviewers if dc in d}
    if len(fams) < 2:
        R.warn("W-DIVERSITY", "agents.yaml", f"reviewers for {dc} span {len(fams)} family: diversity degraded (verdicts capped)")
    R._checks += 1
    for rf, rl, _ in reviewers:
        R.check(any(vf != rf and c.ix.lineage_root(vl) != c.ix.lineage_root(rl) and dc in vd for vf, vl, vd in verifiers),
                "E-DIVERSITY-VERIFIER", "agents.yaml",
                f"no verifier outside family {rf} / lineage {rl} for {dc}")
    # model claims in findings, votes, testresults
    for d in c.docs("finding"):
        rep = d.data.get("reporter") or {}
        a = agents.get(rep.get("agent_id")) or {}
        m = c.model(rep.get("model_key"))
        R.check(a.get("model") == rep.get("model_key") and m is not None and m.get("family") == rep.get("family")
                and m.get("lineage") == rep.get("lineage"), "E-FINDING-REPORTER", d.path, "reporter agent/model/family/lineage disagree with the registries")
    for d in c.docs("verdict"):
        for i, vt in enumerate(d.data.get("votes", [])):
            a = agents.get(vt.get("voter_agent_id")) or {}
            m = c.model(vt.get("voter_model_key"))
            # (the verifier-role requirement is E-VERDICT-VOTER-ROLE in g_verdicts)
            R.check(a.get("model") == vt.get("voter_model_key") and m is not None
                    and m.get("family") == vt.get("voter_family") and m.get("lineage") == vt.get("voter_lineage"),
                    "E-VOTE-MODEL", d.path, f"votes[{i}] voter agent/model/family/lineage disagree with the registries")
    for d in c.docs("testresult"):
        ib = d.data.get("interpreted_by")
        if ib:
            m = c.ix.model_of_agent(ib.get("agent_id"))
            R.check(m is not None and m.get("family") == ib.get("family"), "E-RESULT-ANALYST", d.path, "interpreted_by family disagrees with the agent's model")
    # D14 (H-A4): threat modellers and the invariant drafter resolve to registry agents of the right role and family
    for d in c.docs("threat"):
        for mb in d.data.get("modeled_by") or []:
            a = agents.get(mb.get("agent_id")) if isinstance(mb.get("agent_id"), str) else None
            m = c.ix.model_of_agent(mb.get("agent_id"))
            R.check(isinstance(a, dict) and a.get("role") in ("threat_modeler", "threat_merger") and m is not None
                    and m.get("family") == mb.get("family") and (a.get("viewpoint") in (None, mb.get("viewpoint"))),
                    "E-PROVENANCE", d.path, f"modeled_by {mb.get('agent_id')!r} / {mb.get('family')!r} / {mb.get('viewpoint')!r} does not "
                    "match an agents.yaml threat_modeler (role, registry family, viewpoint)")
    db_ = c.invariants.get("drafted_by") or {}
    if c.invariants:
        a = agents.get(db_.get("agent_id")) if isinstance(db_.get("agent_id"), str) else None
        m = c.ix.model_of_agent(db_.get("agent_id"))
        R.check(isinstance(a, dict) and a.get("role") == "invariant_drafter" and m is not None and m.get("family") == db_.get("family"),
                "E-PROVENANCE", "invariants.yaml", f"drafted_by {db_} does not match an agents.yaml invariant_drafter and its registry family")
    for d in c.docs("slice"):
        for x in d.data.get("excluded_models", []):
            R.check(x.get("model_key") in models, "E-MODEL-UNKNOWN", d.path, f"excluded model {x.get('model_key')!r} unknown")
            if x.get("reason") == "data_class":
                m = c.model(x.get("model_key")) or {}
                run = c.runs.get(d.data.get("run_id")) or {}
                R.check(run.get("data_class") not in m.get("data_classes", []), "E-SLICE-EXCLUDED", d.path, "excluded for data_class but the model may take it")
