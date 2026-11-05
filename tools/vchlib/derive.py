# SPDX-License-Identifier: Apache-2.0
"""Domain predicates of the example bundle: the bundle index (`Index`) and the pure functions the checks and the
derived values (expectations.py, error E-DERIVED) are computed from.
"""
from __future__ import annotations

import re

from dataclasses import dataclass
from typing import Any

from . import timeutil
from .bundle import Bundle, Doc
from .canonical import approval_hash, content_hash, jcs, set_digest, sha256_ref

ZERO = "sha256:" + "0" * 64


class _Missing:
    def __repr__(self):
        return "<missing>"


MISSING = _Missing()


def get_path(obj, path):
    for p in path:
        try:
            obj = obj[p]
        except (KeyError, IndexError, TypeError):
            return MISSING
    return obj


def set_path(obj, path, value):
    for p in path[:-1]:
        obj = obj[p]
    obj[path[-1]] = value


def fmt_path(path) -> str:
    out = "$"
    for p in path:
        out += f"[{p}]" if isinstance(p, int) else f".{p}"
    return out


# ---------------------------------------------------------------- lookups
class Index:
    """Convenience lookups over a bundle (all tolerant of missing documents)."""

    def __init__(self, b: Bundle):
        self.b = b
        self.models = b.data("model-registry") or {}
        self.agents = b.data("agent-registry") or {}
        self.calibration = b.data("calibration") or {}
        self.manifest = b.data("seed-manifest") or {}

    def docs(self, kind) -> list[Doc]:
        return [d for d in self.b.by_kind(kind) if isinstance(d.data, dict)]

    def find(self, kind, **match) -> list[Doc]:
        return [d for d in self.docs(kind) if all(d.data.get(k) == v for k, v in match.items())]

    def first(self, kind, **match) -> Doc | None:
        f = self.find(kind, **match)
        return f[0] if f else None

    def testcase_for(self, tr: dict) -> Doc | None:
        """The testcase a result ran: a W4 result runs a w4-testcase (v0.5, BL-27), a B4 result a black-box testcase.
        v0.4 looked every result up among black-box testcases, so a W4 result had to borrow one."""
        kind = "w4-testcase" if tr.get("phase") == "W4" else "testcase"
        return self.first(kind, testcase_id=tr.get("testcase_id"))

    def audit_docs(self) -> list[Doc]:
        return [d for d in self.b.by_kind("audit-event") if isinstance(d.data, list)]

    def audit_for(self, run_id) -> Doc | None:
        for d in self.audit_docs():
            if d.data and d.data[0].get("run_id") == run_id:
                return d
        return None

    def decision_time(self, rec: dict):
        """v0.4 (E4): ts of the gate_decision audit event of `rec` (the Audit Writer's receive clock), or None."""
        audit = self.audit_for(rec.get("run_id"))
        for ev in (audit.data if audit and isinstance(audit.data, list) else []):
            if isinstance(ev, dict) and ev.get("event_type") == "gate_decision" \
                    and (ev.get("payload") or {}).get("gate_record_id") == rec.get("gate_record_id"):
                try:
                    return timeutil.parse_dt(ev.get("ts"))
                except (timeutil.TimeError, TypeError, ValueError):
                    return None
        return None

    def gate_records(self, run_id, gate=None) -> list[Doc]:
        """Gate records of a run (optionally one gate), ordered by the Audit Writer's receive time (v0.4), falling
        back to the self-declared timestamp only for a record without a gate_decision event."""
        recs = [d for d in self.docs("gate-record") if d.data.get("run_id") == run_id and (gate is None or d.data.get("gate") == gate)]

        def key(d):
            t = self.decision_time(d.data)
            return timeutil.sort_key(t.isoformat()) if t is not None else timeutil.sort_key(d.data.get("timestamp"))
        return sorted(recs, key=key)

    def model_of_agent(self, agent_id) -> dict | None:
        a = self.agents.get(agent_id)
        if not isinstance(a, dict) or not a.get("model"):
            return None
        m = self.models.get(a["model"])
        return m if isinstance(m, dict) else None

    def lineage_declarations(self) -> dict:
        """v0.7 (review r9, external review 2): lineage -> the set of derived_from values its models declare (None for a
        model without one). Every model of a lineage must declare the same value (E-MODEL-LINEAGE)."""
        out: dict = {}
        for m in self.models.values():
            if isinstance(m, dict) and isinstance(m.get("lineage"), str):
                df = m.get("derived_from")
                out.setdefault(m["lineage"], set()).add(df if isinstance(df, str) else None)
        return out

    def lineage_parents(self) -> dict:
        """lineage -> derived_from, independent of the order of models.yaml. v0.7 built {lineage: derived_from} model by
        model, so of two contradicting models of one lineage the later one won and reordering the file changed the root;
        a contradiction is rejected (E-MODEL-LINEAGE), and until then the smallest declared parent is used."""
        return {lin: min(x for x in decl if x is not None) for lin, decl in self.lineage_declarations().items()
                if any(x is not None for x in decl)}

    def lineage_root(self, lineage):
        """v0.6 (review r7 3.9): the base lineage a lineage was derived from (models.yaml `derived_from`, followed to
        the end; a cycle stops where it closes). A fine-tune or distillation shares its base's blind spots, so
        independence is judged on the root: a verifier derived from the reporter's lineage is not independent."""
        parent = self.lineage_parents()
        seen = set()
        while lineage in parent and lineage not in seen:
            seen.add(lineage)
            lineage = parent[lineage]
        return lineage

    def lineage_roots(self, lineages) -> set:
        return {self.lineage_root(x) for x in lineages or []}

    def lineage_cycles(self) -> list[list[str]]:
        """v0.7 (review r8, external review 3): the derived_from cycles of models.yaml (A -> B -> A). lineage_root stops
        where a cycle closes, so two mutually derived lineages got two different roots and verified each other;
        E-MODEL-LINEAGE rejects the registry instead."""
        parent = self.lineage_parents()
        cycles, done = [], set()
        for start in parent:
            path, cur = [], start
            while cur in parent and cur not in path and cur not in done:
                path.append(cur)
                cur = parent[cur]
            if cur in path:
                cyc = path[path.index(cur):]
                cycles.append(cyc)
                done.update(cyc)
            done.update(path)
        return cycles

    def independence_split_families(self) -> set:
        """Second external review of r12 (05-v0.13): the families whose base lineages calibration.yaml shows to err
        independently: every pair of the family's lineage roots has an M-2 entry in config.independence.lineage_split
        with kappa_ci_upper below INDEPENDENCE_SPLIT["kappa_ci_upper_max"] on at least INDEPENDENCE_SPLIT["n_min"]
        clusters (docs/05 §4.3, §5.3 M-2). Every other family is one observation."""
        ind = ((self.calibration.get("config") or {}).get("independence") or {}) if isinstance(self.calibration, dict) else {}
        ok = set()
        for x in ind.get("lineage_split") or []:
            if isinstance(x, dict) and independence_evidence_ok(x):
                ok.add((x.get("family"), frozenset(self.lineage_roots(x.get("lineages")))))
        roots: dict = {}
        for m in self.models.values():
            if isinstance(m, dict) and isinstance(m.get("family"), str) and isinstance(m.get("lineage"), str):
                roots.setdefault(m["family"], set()).add(self.lineage_root(m["lineage"]))
        out = set()
        for fam, rs in roots.items():
            pairs = [frozenset((a, b)) for i, a in enumerate(sorted(rs)) for b in sorted(rs)[i + 1:]]
            if pairs and all((fam, p) in ok for p in pairs):
                out.add(fam)
        return out

    def independence_key(self, model_key):
        """Second external review of r12 (05-v0.13): the observation a model's vote or report belongs to. Models that share
        a base lineage are always one observation (a fine-tune inherits its base's blind spots, across families too);
        models of one family are one observation unless independence_split_families() lists the family. Votes and reports
        of one key count once in S, in the independent sources and in diversity. 05-v0.12 grouped by base lineage only,
        so openai's gpt and gpt-oss were two observations. None for an unknown model."""
        m = self.models.get(model_key) if isinstance(model_key, str) else None
        if not isinstance(m, dict) or not isinstance(m.get("lineage"), str):
            return None
        parent: dict = {}

        def find(x):
            while parent.get(x, x) != x:
                x = parent[x]
            return x

        def union(a, b):
            ra, rb = find(a), find(b)
            if ra != rb:
                parent[max(ra, rb)] = min(ra, rb)
        split = self.independence_split_families()
        for k, x in self.models.items():
            if isinstance(x, dict) and isinstance(x.get("lineage"), str):
                union(f"model:{k}", f"root:{self.lineage_root(x['lineage'])}")
                if isinstance(x.get("family"), str) and x["family"] not in split:
                    union(f"model:{k}", f"family:{x['family']}")
        return find(f"model:{model_key}")

    def root_of_agent(self, agent_id):
        """The base lineage of the model an agents.yaml entry runs (None when unresolved)."""
        m = self.model_of_agent(agent_id)
        return self.lineage_root(m.get("lineage")) if isinstance(m, dict) and isinstance(m.get("lineage"), str) else None

    def calibrated_setup_problem(self, model_key, run_id) -> str | None:
        """v0.6 (review r7 3.6, docs/05 §5.8): the weights hold only for the model version and verifier prompt they
        were measured with. The calibration's config.models entry must name the model's current version (the last
        segment of models.yaml litellm) and the w3-verify prompt template the run uses; otherwise the model weighs 0.
        v0.5 relied on someone listing the change in invalidated_by."""
        cm = next((m for m in (self.calibration.get("config") or {}).get("models") or []
                   if isinstance(m, dict) and m.get("model_key") == model_key), None)
        reg = self.models.get(model_key) if isinstance(model_key, str) else None
        if cm is None or not isinstance(reg, dict):
            return f"{model_key} is not a calibrated model"
        if str(reg.get("litellm") or "").rsplit("/", 1)[-1] != cm.get("version"):
            return f"{model_key} runs {reg.get('litellm')!r}, calibrated as version {cm.get('version')!r}"
        run = self.first("run", run_id=run_id) if run_id else None
        tpl = next((t for t in (run.data.get("prompt_templates") or []) if isinstance(t, dict)
                    and t.get("template_id") == "w3-verify"), None) if run else None
        if tpl is not None and tpl.get("sha256") != cm.get("prompt_template_sha256"):
            return f"{model_key} was calibrated with prompt {cm.get('prompt_template_sha256')}, the run verifies with {tpl.get('sha256')}"
        return None

    def weight(self, model_key, bucket, version, stance="SUPPORT", run_id=None) -> float:
        """v0.4: calibration weight of one side. REFUTE votes use the refute side (accuracy on known non-defects),
        every other stance the support side (accuracy on true defects); docs/05 §4.3. v0.6: 0 unless the model and
        the run's verifier prompt are the calibrated ones (calibrated_setup_problem)."""
        cal = self.calibration
        if not cal or version is None or cal.get("calibration_version") != version:
            return 0.0
        if self.calibrated_setup_problem(model_key, run_id) is not None:
            return 0.0
        side_key = "refute" if stance == "REFUTE" else "support"
        res = cal.get("result") or {}
        # v0.5 (review 2026-10-25 A-6, docs/05 §5.8): a model whose calibration is invalidated (model or version
        # changed) or that the result is not valid for weighs 0 until the minimal rerun
        # v0.6 (review r7 3.6): an empty list means no model is valid (v0.5 read it as "all")
        valid_for = res.get("valid_for_model_keys") or []
        # v0.7 (review r10): a model that reproduced a corpus canary has seen the corpus; its measured accuracy says nothing
        if any(isinstance(x, dict) and x.get("model_key") == model_key and x.get("reproduced") is not False
               for x in (res.get("contamination") or {}).get("canary_results") or []):
            return 0.0
        if model_key not in valid_for or any(
                isinstance(x, dict) and x.get("model_key") == model_key for x in res.get("invalidated_by") or []):
            return 0.0
        for row in res.get("weights", []):
            if row.get("model_key") == model_key and row.get("cwe_bucket") == bucket:
                side = row.get(side_key) or {}
                return 0.0 if side.get("near_zero") else float(side.get("w", 0))
        return 0.0

    def thresholds(self, bucket=None):
        """(theta_confirm, theta_reject) for a CWE bucket; None = +inf (disabled).
        v0.6 (review r7 3.5): the rules use the bucket's own threshold (`by_bucket`); a bucket without one is disabled,
        so a threshold searched on authz clusters does not confirm llm_specific ones. A threshold that did not
        generalise to the holdout split (`generalised: false`) is disabled too."""
        th = ((self.calibration.get("result") or {}).get("thresholds") or {})

        def value(name):
            t = ((th.get(name) or {}).get("by_bucket") or {}).get(bucket) or {}
            return t.get("value") if t.get("feasible") is True and t.get("generalised") is True else None
        return value("theta_confirm"), value("theta_reject")

    def approved_requirement_ids(self) -> set[str]:
        """Requirements approved at G1 (D10): invariants whose signoff is ACCEPTED by the G1 record named in
        invariants.yaml and whose decision there is accept; baseline items when that G1 record is APPROVED
        and the file-level signoff is ACCEPTED. REJECTED / NEEDS_INFO items are not testable."""
        inv = self.b.data("invariants") or {}
        so = inv.get("signoff") or {}
        rec = self.first("gate-record", gate_record_id=so.get("gate_record_id")) if so.get("gate_record_id") else None
        # v0.5 (review r7 1.1): an EXPIRED G1 is unsigned and approves nothing
        if rec is None or rec.data.get("gate") != "G1" or rec.data.get("outcome") == "EXPIRED":
            return set()
        accepted = {x.get("item_id") for x in rec.data.get("decisions") or [] if isinstance(x, dict) and x.get("decision") == "accept"}
        out = {i.get("requirement_id") for i in inv.get("invariants") or [] if isinstance(i, dict)
               and (i.get("signoff") or {}).get("status") == "ACCEPTED"
               and (i.get("signoff") or {}).get("gate_record_id") == rec.data.get("gate_record_id")
               and i.get("requirement_id") in accepted}
        if rec.data.get("outcome") == "APPROVED" and so.get("status") == "ACCEPTED":
            out |= {x.get("requirement_id") for x in inv.get("baseline") or [] if isinstance(x, dict)}
        return out

    def finding(self, fid) -> dict | None:
        d = self.first("finding", finding_id=fid)
        return d.data if d else None


GROUNDED_MATCHES = ("MATCHED", "MATCHED_SHIFTED")


def has_supporting_evidence(f: dict) -> bool:
    """At least one evidence item is grounded: MATCHED or MATCHED_SHIFTED (docs/05 §3 rule 5).

    v0.4: NOT_CHECKED (the harness could not check the item, e.g. an unparseable config file) is not
    grounded either. v0.3 counted every item that was not NOT_FOUND, so two families that each sent an
    uncheckable config_fact reached R6 LIKELY without any grounded evidence."""
    return any(isinstance(e, dict) and e.get("match") in GROUNDED_MATCHES for e in f.get("evidence") or [])


def independent_families(ix: Index, cluster: dict) -> list[str]:
    """docs/05 §4.1 (D14): families that contributed a member in the first round of this run, reported by an
    agents.yaml `reviewer` (Lane A advisories and CMD-2 extra rounds do not count), whose finding has at least
    one grounded evidence item (MATCHED / MATCHED_SHIFTED; UNVERIFIED and NOT_CHECKED-only findings do not count). Sorted.
    v0.7 (review r8, external review 3): two families whose models share a base lineage (models.yaml derived_from) are
    one source: a fine-tune of the reporter's base inherits its blind spots. Of each base lineage the first family in
    sorted order is kept, so len() is the number of independent base lineages; the verifier pool, the Result Analyst
    and diversity (R8) judge independence on the same roots."""
    fams = {}
    for fid in cluster.get("member_finding_ids") or []:
        f = ix.finding(fid)
        rep = (f or {}).get("reporter") or {}
        a = ix.agents.get(rep.get("agent_id")) if isinstance(rep.get("agent_id"), str) else None
        if (f and rep.get("round") == 1 and isinstance(a, dict) and a.get("role") == "reviewer"
                and f.get("run_id") == cluster.get("run_id") and has_supporting_evidence(f) and isinstance(rep.get("family"), str)):
            # 05-v0.13: one observation per independence key (one family unless M-2 evidence splits it)
            root = ix.independence_key((ix.agents.get(rep.get("agent_id")) or {}).get("model")) or ix.lineage_root(rep.get("lineage"))
            fams.setdefault(root, set()).add(rep.get("family"))
    return sorted(min(fs) for fs in fams.values())


RUBRIC_BASE = {"authz": 3, "authn": 3, "injection": 3, "secrets": 3, "llm_specific": 3, "deserialization": 3,
               "ssrf": 2, "path_traversal": 2, "crypto": 2, "config": 2, "other": 1}
RUBRIC_LEVELS = {4: "critical", 3: "high", 2: "medium", 1: "low", 0: "info"}


def rubric_inputs(ix: Index, cluster: dict) -> dict:
    """docs/08 §11.17: the four rubric inputs of a cluster, resolved from the run's inventory, merged DFD and G1
    data classification; never from a finding. An input the bundle cannot resolve is None (reachability "unknown",
    which the rubric treats as internet), and rubric_severity never lets an unresolved input lower the score.
    v0.7 (review r8 F5): v0.4-v0.6 documented the rubric but routed G2 on the reviewers' self-reported finding.severity."""
    rid, loc = cluster.get("run_id"), cluster.get("canonical_location") or {}
    inv = ix.first("inventory", run_id=rid)
    inv = inv.data if inv else {}
    dfd = ix.first("dfd", run_id=rid, viewpoint="merged")
    els = [e for e in (dfd.data.get("elements") if dfd else []) or [] if isinstance(e, dict)]
    by_id = {e.get("element_id"): e for e in els}
    # 1. the endpoints at the location (inventory), and the DFD processes they belong to
    eps = [e for e in inv.get("endpoints") or [] if isinstance(e, dict)]
    if cluster.get("origin") == "black_box":
        ep = loc.get("endpoint") or {}
        mine = [e for e in eps if e.get("method") == ep.get("method") and e.get("path") == ep.get("path_template")]
    else:
        mine = [e for e in eps if e.get("file") == loc.get("file")]
    refs = {f"endpoint:{e.get('method')} {e.get('path')}" for e in mine} | ({f"code:{loc.get('file')}"} if loc.get("file") else set())
    procs = {e.get("element_id") for e in els if e.get("type") == "process"
             and any(r in refs or any(r.startswith(x + ":") for x in refs) for r in e.get("evidence_refs") or [])}
    # 2. the data stores those processes read or write -> inventory tables -> G1 data classification
    tables = set()
    sym = str(loc.get("symbol") or "")
    if cluster.get("origin") != "black_box" and sym.startswith("public."):
        tables.add(sym.split(".", 1)[1])
    inv_tables = [t for t in (inv.get("db") or {}).get("tables") or [] if isinstance(t, dict)]
    for e in els:
        if e.get("type") == "data_flow" and (e.get("from") in procs or e.get("to") in procs):
            store = by_id.get(e.get("to") if e.get("from") in procs else e.get("from")) or {}
            for r in store.get("evidence_refs") or [] if store.get("type") == "data_store" else []:
                parts = str(r).split("/")
                if parts[:2] == ["inventory:", "db"] and parts[2:3] == ["tables"] and parts[3:4] and _INDEX.fullmatch(parts[3]) \
                        and int(parts[3]) < len(inv_tables):
                    tables.add(inv_tables[int(parts[3])].get("name"))
    levels, pii = [], False
    for dc in (ix.b.data("invariants") or {}).get("data_classification") or []:
        if isinstance(dc, dict) and any(str(f).split(".")[0] in tables for f in dc.get("fields") or []):
            levels.append(dc.get("level"))
            pii = pii or dc.get("pii") is True
    order = ["restricted", "confidential", "internal", "public"]
    data = next((lv for lv in order if lv in levels), None) if levels else None
    # 3. reachability: a flow into the process that crosses a network boundary from outside
    inbound = [e for e in els if e.get("type") == "data_flow" and e.get("to") in procs]
    if any(any((by_id.get(b) or {}).get("kind") == "network" for b in f.get("crosses") or []) for f in inbound):
        reach = "internet"
    elif procs and inbound:
        reach = "internal"
    else:
        reach = "unknown"
    # 4. authentication: any anonymous endpoint -> none; every endpoint authenticated -> any_user
    if not mine:
        auth = None
    elif any(e.get("auth_required") is not True for e in mine):
        auth = "none"
    else:
        auth = "any_user"
    return {"bucket": cluster.get("cwe_bucket"), "data": data, "pii": pii, "reachability": reach, "auth": auth}


def rubric_severity(ix: Index, cluster: dict) -> str:
    """docs/08 §11.17 severity rubric: base score by CWE bucket, +1 restricted / confidential / PII data (-1 public),
    -1 internal-only reachability (unknown counts as internet), +1 anonymous (-1 privileged), clamped to 0..4.
    An input the bundle cannot resolve never lowers the score: unknown data and a location without endpoints
    (no authentication requirement to read) add nothing; unknown reachability is internet."""
    x = rubric_inputs(ix, cluster)
    score = RUBRIC_BASE.get(x["bucket"], 1)
    if x["data"] in ("restricted", "confidential") or x["pii"]:
        score += 1
    elif x["data"] == "public":
        score -= 1
    if x["reachability"] == "internal":
        score -= 1
    if x["auth"] == "none":
        score += 1
    elif x["auth"] == "privileged":
        score -= 1
    return RUBRIC_LEVELS[max(0, min(4, score))]


def slice_identity(files, redaction_map_sha256, prompt_template_sha256) -> str:
    """E6 (H-E3): slice_id = sha256(JCS({files, redaction_map_sha256, prompt_template_sha256}))."""
    return sha256_ref(jcs({"files": files, "redaction_map_sha256": redaction_map_sha256,
                           "prompt_template_sha256": prompt_template_sha256}))


CONFIG_KINDS = {"models": "model-registry", "agents": "agent-registry", "tools": "tool-registry", "calibration": "calibration",
                "invariants": "invariants", "seed_manifest": "seed-manifest"}


def artifact_sha(rec: dict):
    """artifact.sha256 of a gate record; MISSING when the record has no artifact (reported as E-GATE-ARTIFACT, D6)."""
    a = rec.get("artifact") if isinstance(rec, dict) else None
    return a.get("sha256", MISSING) if isinstance(a, dict) else MISSING


def cluster_fingerprint(cluster: dict) -> str:
    """B9: stable cross-run fingerprint, no line numbers. white_box: {cwe_bucket, file, symbol};
    black_box: {cwe_bucket, target_id, method, path_template} of canonical_location.endpoint."""
    loc = cluster.get("canonical_location") or {}
    if cluster.get("origin") == "black_box":
        ep = loc.get("endpoint") or {}
        key = {"cwe_bucket": cluster.get("cwe_bucket"), "target_id": ep.get("target_id"), "method": ep.get("method"),
               "path_template": ep.get("path_template")}
    else:
        key = {"cwe_bucket": cluster.get("cwe_bucket"), "file": loc.get("file"), "symbol": loc.get("symbol")}
    return sha256_ref(jcs(key))


# ---------------------------------------------------------------- test evidence (docs/05 §4.2)
ORACLE_TYPES = ("STATUS_AND_BODY", "STATE_DIFF", "TOOL_CHECK", "TOOL_CALL_LOG", "CANARY", "THRESHOLD", "DOM_ASSERTION",
                "HUMAN", "LLM_GRADER")
NON_DETERMINISTIC_ORACLES = frozenset({"HUMAN", "LLM_GRADER"})
DETERMINISTIC_ORACLES = frozenset(ORACLE_TYPES) - NON_DETERMINISTIC_ORACLES


def oracle_types(tc: dict) -> set[str]:
    """testcase oracle.types (v0.3); a list-valued field that is missing or malformed gives the empty set."""
    types = (tc.get("oracle") or {}).get("types")
    return {t for t in types if isinstance(t, str)} if isinstance(types, list) else set()


def control_results(tc: dict, tr: dict) -> list[tuple[str, str, str | None]]:
    """[(control_id, kind, outcome or None)] for every control of the testcase, in testcase order."""
    got = {x.get("control_id"): x.get("outcome") for x in tr.get("controls") or [] if isinstance(x, dict)}
    return [(c.get("control_id"), c.get("kind"), got.get(c.get("control_id")))
            for c in tc.get("controls") or [] if isinstance(c, dict)]


def controls_of_kind_pass(tc: dict, tr: dict, kind: str) -> bool | None:
    """None when the testcase has no control of `kind`; else True iff every such control PASSed."""
    outs = [o for _, k, o in control_results(tc, tr) if k == kind]
    return None if not outs else all(o == "PASS" for o in outs)


def reachability_reached(tc: dict, tr: dict) -> bool:
    """The derived precondition_reached: at least one reachability control, and all of them PASS."""
    return controls_of_kind_pass(tc, tr, "reachability") is True


def positive_control_value(tc: dict, tr: dict) -> bool | None:
    """The derived positive_control.value: an oracle_can_fail control exists and PASSed (None: no such control)."""
    return controls_of_kind_pass(tc, tr, "oracle_can_fail")


PROBABILISTIC_TOOLS = ("promptfoo", "pyrit")                  # LLM test harnesses: a sampled target, not a fixed function
LLM_TAXONOMY_SCHEMES = ("owasp-llm", "owasp-asi")             # a threat in these taxonomies targets a sampled component


def llm_threat(ix: Index | None, tc: dict) -> bool:
    """v0.7 (review r8, external review 2): the testcase's threat targets an LLM component: its taxonomy is an LLM one
    (owasp-llm / owasp-asi, any version), or its source cluster is in the llm_specific bucket."""
    th = ix.first("threat", threat_id=tc.get("threat_id")) if ix is not None and isinstance(tc.get("threat_id"), str) else None
    if th is None:
        return False
    schemes = {str(x.get("scheme") or "").split("@")[0] for x in th.data.get("taxonomy") or [] if isinstance(x, dict)}
    if schemes & set(LLM_TAXONOMY_SCHEMES) or th.data.get("cwe_bucket") == "llm_specific":
        return True
    src = ix.first("cluster", cluster_id=th.data.get("source_cluster_id")) if isinstance(th.data.get("source_cluster_id"), str) else None
    return src is not None and src.data.get("cwe_bucket") == "llm_specific"


def probabilistic_signals(ix: Index | None, tc: dict) -> list[str]:
    """Why a testcase is probabilistic (empty: deterministic). v0.7 (review r8, external review 2): the target decides,
    not the tool: an HTTP adapter can drive an LLM feature as well as promptfoo can, so the threat's taxonomy / bucket
    and the declared sampling contract (`trials.sampling: sampled`) count too; v0.6 looked only at the adapter, multi_turn
    and the target_model record, and an LLM test re-bound to playwright:api with n = 1 passed as deterministic."""
    adapter = str((tc.get("tool_binding") or {}).get("adapter") or "")
    trials = tc.get("trials") or {}
    out = []
    if adapter.split(":")[0] in PROBABILISTIC_TOOLS:
        out.append(f"adapter {adapter}")
    if tc.get("multi_turn") is True:
        out.append("multi_turn")
    if "target_model" in (trials.get("record") or []):
        out.append("records target_model")
    # v0.7 (review r10): `trials.sampling: sampled` is the author's declaration, not a property of the target; v0.7 r9
    # counted it, so any HTTP test that declared it was exempt from the deterministic replay rule (E-TC-TRIALS checks it)
    if llm_threat(ix, tc):
        out.append("LLM threat (taxonomy / llm_specific bucket)")
    return out


def is_probabilistic(tc: dict, ix: Index | None = None) -> bool:
    """v0.6 (review r7 3.3): a test is probabilistic because of what it runs against, not because of the n it declares.
    v0.7 (review r8, external review 2): see probabilistic_signals; without an Index only the testcase's own signals are
    seen, so callers that have one pass it. Such a test must also declare n >= pass_min_effective (E-TC-TRIALS)."""
    return bool(probabilistic_signals(ix, tc))


def pass_min_effective(ix: "Index", tc: dict) -> int:
    """docs/04 §4.4: the effective trials a probabilistic PASS needs. 30 (one-sided 95% bound about 10%); v0.5 (review
    2026-10-25 §4.3): 60 (bound about 5%) for a high-risk threat, recognised by its attack tree (docs/02 B2: every
    high-risk threat has one), so a PASS cannot claim the high-risk target bound with only 30 valid trials."""
    t = ix.first("threat", threat_id=tc.get("threat_id")) if tc.get("threat_id") else None
    return 60 if t is not None and t.data.get("attack_tree_ref") else 30


def fail_reproduced(tc: dict, tr: dict, probabilistic: bool | None = None) -> tuple[bool, str]:
    """docs/04 §4.4: the first batch reaches fail_k_min and a separate replay job ran: a deterministic test fails on
    every replay (k_r = n_r). v0.5 (review 2026-10-25 M-3): for a probabilistic test the replay is a reproducibility
    record, not a second verdict: one confirmed violation already breaks the requirement, and a real 5% rate stays
    silent in all 20 replays about 36% of the time, so k_r is reported but does not demote the FAIL.
    v0.7 (review r9, external review 1): classify_result passes its own judgement (made with the Index, which sees the
    LLM threat); v0.7 re-judged here without it, so an LLM test behind an HTTP adapter was probabilistic for the PASS rule
    and deterministic for the replay rule, and one silent replay demoted a confirmed violation to E_inc."""
    trials = tc.get("trials") or {}
    if probabilistic is None:
        probabilistic = is_probabilistic(tc)
    k = (tr.get("trials") or {}).get("k", 0)
    fail_k_min = trials.get("fail_k_min", 1)
    n_r, k_r = tr.get("replays", 0), tr.get("replay_k", 0)
    if k < fail_k_min:
        return False, "FAIL below fail_k_min"
    if n_r < 1:
        return False, "FAIL not replayed"
    if not probabilistic and k_r != n_r:
        return False, "FAIL not reproduced by the replay job"
    return True, ""


@dataclass(frozen=True)
class G4State:
    """What the G4 decisions of a run say about one testcase as of a moment (docs/03 §6, review r11 external)."""
    decision: str | None = None         # the latest decision on the testcase (accept, reject, needs_info), None = never decided
    approved_since: Any = None          # receive time of the accept that began the current unbroken run of accepts, else None
    record_id: str | None = None        # the gate record carrying the latest decision


def record_time(ix: "Index", rec: dict):
    """The Audit Writer's receive time of a gate record's gate_decision, else its self-declared timestamp, else None."""
    t = ix.decision_time(rec)
    if t is None:
        try:
            t = timeutil.parse_dt(rec.get("timestamp"))
        except (timeutil.TimeError, TypeError, ValueError):
            t = None
    return t


def g4_state(ix: "Index", run_id, testcase_id, at=None) -> G4State:
    """The one rule for "is this testcase approved at G4": walk the run's signed G4 records (EXPIRED records are unsigned
    and decide nothing) in receive-time order, keep the latest decision on the testcase, and remember when the current
    unbroken run of accepts began. `at` restricts the walk to decisions received at or before it (a record whose time
    is unknown is then skipped): "authorised when the job started" is g4_state(at=start), "currently allowed to dispatch"
    is g4_state(at=None).

    A later, identical accept leaves approved_since where it was (it is not a new approval); a later reject or needs_info
    withdraws the approval for everything that starts after it, and does not reach back to a job that ran under it.
    Review r11 (external): derive.g4_approved skipped a whole REJECTED record while the validator honoured it, and the
    validator measured "executed before approval" from the LATEST record, so an identical second accept turned a legitimate
    execution into an error."""
    state = G4State()
    for rec in ix.gate_records(run_id, "G4"):                    # receive-time order
        if rec.data.get("outcome") == "EXPIRED":
            continue
        t = record_time(ix, rec.data)
        if at is not None and (t is None or t > at):
            continue
        for x in rec.data.get("decisions") or []:
            if isinstance(x, dict) and x.get("item_id") == testcase_id:
                since = state.approved_since if (x.get("decision") == "accept" and state.decision == "accept") else t
                state = G4State(x.get("decision"), since if x.get("decision") == "accept" else None, rec.data.get("gate_record_id"))
    return state


def g4_final_states(ix: "Index", run_id) -> dict[str, G4State]:
    """testcase_id -> its G4 state at the end of the log, for every testcase any signed G4 record decides."""
    ids = []
    for rec in ix.gate_records(run_id, "G4"):
        if rec.data.get("outcome") != "EXPIRED":
            ids += [x.get("item_id") for x in rec.data.get("decisions") or [] if isinstance(x, dict)]
    return {i: g4_state(ix, run_id, i) for i in dict.fromkeys(ids)}


def job_span(ix: "Index", run_id, job_id):
    """(receive time of the job's sandbox_job_start, of its sandbox_job_end) in the run's audit log, or None for each."""
    audit = ix.audit_for(run_id)
    evs = [e for e in (audit.data if audit and isinstance(audit.data, list) else [])
           if isinstance(e, dict) and (e.get("payload") or {}).get("job_id") == job_id]
    start = next((e.get("ts") for e in evs if e.get("event_type") == "sandbox_job_start"), None)
    end = next((e.get("ts") for e in reversed(evs) if e.get("event_type") == "sandbox_job_end"), None)
    return (timeutil.parse_dt(start) if isinstance(start, str) else None, timeutil.parse_dt(end) if isinstance(end, str) else None)


def g4_approved(ix: "Index", tr: dict) -> bool:
    """The testcase was approved at G4 when its job ran (black-box pre-registration): the state as of the job's
    sandbox_job_start, else of the result's executed_at, else (no time at all) at the end of the log. A reject that comes
    after the execution does not undo the pre-registration (the result keeps E_proof; the run may not dispatch the testcase
    again and the validator warns, W-RESULT-G4-WITHDRAWN).

    v0.5 (review 2026-10-25 §4.3): v0.4 read only the run's last G4 record, so a second-round G4 that covered other
    testcases turned an approved one into "not approved" (E_proof -> E_fail_u)."""
    start, _ = job_span(ix, tr.get("run_id"), tr.get("job_id"))
    at = start
    if at is None:
        try:
            at = timeutil.parse_dt(tr.get("executed_at"))
        except (timeutil.TimeError, TypeError, ValueError):
            at = None
    return g4_state(ix, tr.get("run_id"), tr.get("testcase_id"), at).decision == "accept"


# r14 (05-v0.15, internal review C3, user decision): the W4 test kinds whose oracle the harness generates from a G1-approved
# structure (access_matrix -> local_rls, llm_tools -> fake_model). Only these oracles are pre-registered by G1; a unit /
# property test is written by the W4_testgen LLM and only reviewed by another LLM, so nobody approved its oracle.
CODE_ORACLE_KINDS = ("local_rls", "fake_model")


def g2_accepted(ix: "Index", cluster: dict) -> bool:
    """The latest non-EXPIRED G2 record of the cluster's run that decides the cluster accepts it (verdict.g2_latest reads the
    same records); r14 (05-v0.15): the human review that lets an LLM-written W4 oracle count as pre-registered."""
    dec = None
    for x in ix.gate_records(cluster.get("run_id"), "G2"):
        if x.data.get("outcome") == "EXPIRED":
            continue
        for d in x.data.get("decisions") or []:
            if isinstance(d, dict) and d.get("item_id") == cluster.get("cluster_id"):
                dec = d.get("decision")
    return dec == "accept"


def oracle_preregistered_by_code(tc: dict) -> bool:
    """r14 (05-v0.15): the W4 oracle came from the harness, not from an LLM (CODE_ORACLE_KINDS)."""
    return tc.get("kind") in CODE_ORACLE_KINDS


def preregistered(ix: "Index", tc: dict, tr: dict, control_kind: str, cluster: dict | None = None) -> bool:
    """docs/05 §4.2 (v0.3): the oracle's interpretation was fixed before the test ran.
    B4: the testcase has an accepting G4 decision. W4: every requirement_id is approved at G1 and
    r14 (05-v0.15, internal review C3, user decision): the oracle was generated by the harness from the G1-approved
    structure (kind local_rls / fake_model) and BOTH oracle controls PASSed (oracle_can_pass and oracle_can_fail), or the
    oracle was written by an LLM, the cluster's latest G2 decision accepts it (a person reviewed the item) and the control
    of `control_kind` PASSed. 05-v0.3-05-v0.14 accepted any W4 test on G1-approved requirements with a PASSed
    oracle_can_pass control: G1 signs the requirement, not the test, so an LLM-written oracle confirmed a cluster with
    no human ever reading the oracle (the only route to CONFIRMED before calibration)."""
    if tr.get("phase") == "B4":
        return g4_approved(ix, tr)
    if tr.get("phase") == "W4":
        reqs = set(tc.get("requirement_ids") or [])
        if not reqs or not reqs <= ix.approved_requirement_ids():
            return False
        if oracle_preregistered_by_code(tc):
            return controls_of_kind_pass(tc, tr, "oracle_can_pass") is True and controls_of_kind_pass(tc, tr, "oracle_can_fail") is True
        return cluster is not None and g2_accepted(ix, cluster) and controls_of_kind_pass(tc, tr, control_kind) is True
    return False


def oracle_unreviewed(ix: "Index", tc: dict, tr: dict, cluster: dict) -> bool:
    """r14 (05-v0.15): a W4 result whose oracle an LLM wrote and no G2 decision has accepted; its FAIL stays E_fail_u and
    the verdict is annotated `oracle_unreviewed`."""
    return tr.get("phase") == "W4" and not oracle_preregistered_by_code(tc) and not g2_accepted(ix, cluster)


TEST_AUTHOR_ROLES = {"W4": ("test_generator", "test_critic"), "B4": ("test_designer", "test_implementer", "test_critic")}


def test_author_families(ix: "Index", tr: dict) -> tuple[set, set]:
    """v0.6 (review r7 3.1): (families, lineages) of the agents that wrote or shaped the test the result came from: the
    W4 test generator, or the B3 test designer and implementer and the threat modelers of the testcase's threat. A
    Result Analyst from one of them would grade its own test."""
    fams, lins = set(), set()
    for a in (ix.agents or {}).values():
        if isinstance(a, dict) and a.get("role") in TEST_AUTHOR_ROLES.get(tr.get("phase"), ()):
            m = ix.models.get(a.get("model")) if isinstance(a.get("model"), str) else None
            if isinstance(m, dict):
                fams.add(m.get("family"))
                lins.add(m.get("lineage"))
    if tr.get("phase") == "B4":
        tc = ix.testcase_for(tr)
        th = ix.first("threat", threat_id=tc.data.get("threat_id")) if tc and tc.data.get("threat_id") else None
        for mb in (th.data.get("modeled_by") or []) if th else []:
            m = ix.model_of_agent(mb.get("agent_id")) if isinstance(mb, dict) else None
            if isinstance(m, dict):
                fams.add(m.get("family"))
                lins.add(m.get("lineage"))
    return fams - {None}, lins - {None}


def authors_independent(ix: "Index", tr: dict, cluster: dict) -> bool:
    """v0.7 (review r9): a W4 FAIL is pre-registered proof only when the agents that wrote and critiqued the W4 test are
    outside the cluster's families and base lineages. G1 signs the requirement, not the test code, so a reporting family
    that writes and critiques its own test confirms its own finding; such a FAIL needs an eligible Result Analyst
    (E_proof) or stays E_fail_u. B4 tests are pre-registered by the humans at G4, who review the test and its oracle."""
    if tr.get("phase") != "W4":
        return True
    fams, lins = test_author_families(ix, tr)
    if not fams:
        return False         # v0.7 (review r10): unknown authors are not independent (v0.7 r9 read an empty set as "outside")
    return not (fams & set(cluster.get("families") or [])) and \
        not (ix.lineage_roots(lins) & ix.lineage_roots(cluster.get("lineages")))


def analyst_check(ix: "Index", tr: dict, cluster: dict) -> tuple[bool, str | None]:
    """(eligible, disagreement): the Result Analyst is an agents.yaml result_analyst whose registry
    family and lineage are not in the cluster; eligible only when its interpretation agrees.
    v0.6 (review r7 3.1): nor those of the test's authors (test_author_families)."""
    ib = tr.get("interpreted_by")
    if not isinstance(ib, dict):
        return False, None
    a = ix.agents.get(ib.get("agent_id")) if isinstance(ib.get("agent_id"), str) else None
    m = ix.model_of_agent(ib.get("agent_id"))
    if not isinstance(a, dict) or a.get("role") != "result_analyst" or m is None:
        return False, None
    if m.get("family") in set(cluster.get("families") or []) or ix.lineage_root(m.get("lineage")) in ix.lineage_roots(cluster.get("lineages")):
        return False, None
    author_fams, author_lins = test_author_families(ix, tr)
    if m.get("family") in author_fams or ix.lineage_root(m.get("lineage")) in ix.lineage_roots(author_lins):
        return False, None
    agrees = (tr.get("interpretation") or {}).get("agrees")
    if agrees is True:
        return True, None
    return False, "eligible analyst does not agree with the interpretation"


def classify_result(ix: Index, tr: dict, cluster: dict) -> tuple[str, str]:
    """Return (class, reason) for one testresult linked to `cluster` (docs/05 §4.2, v0.3).

    1. outcome not PASS / FAIL (ERROR, SKIPPED, STOPPED, INVALID) -> E_inc.
    2. FAIL: fail_k_min and the replay rules, else E_inc; a violation reported only by HUMAN /
       LLM_GRADER oracles is E_inc; a pre-registered interpretation (G4 for B4; G1-signed
       requirements and a PASSed oracle_can_pass control for W4) -> E_proof without any LLM;
       else an eligible cross-family Result Analyst that agrees -> E_proof; else E_fail_u.
    3. PASS: every reachability control PASSed, probabilistic k=0 and n' >= 30, a deterministic
       oracle, and a pre-registered interpretation (oracle_can_fail for W4) or an eligible analyst
       -> E_pass; else E_inc.
    """
    tc_doc = ix.testcase_for(tr)
    tc = tc_doc.data if tc_doc else {}
    probabilistic = is_probabilistic(tc, ix)
    got = tr.get("trials") or {}
    n, k = got.get("n", 0), got.get("k", 0)
    outcome = tr.get("outcome")
    if outcome not in ("FAIL", "PASS"):
        return "E_inc", f"outcome {outcome}"
    if not execution_anchored(ix, tr):                 # v0.7 (review r8 F2a): a result nothing executed is no evidence
        return "E_inc", "no anchored sandbox_job_end with this outcome names the result's job (it never ran)"
    if tr.get("phase") == "W4" and tr.get("observations_source") != "harness":   # v0.7 (review r8, external review 6)
        return "E_inc", "observations read from the SUT's own process can be forged; only harness-sourced observations are evidence"
    eligible, disagreement = analyst_check(ix, tr, cluster)
    if disagreement:
        # v0.7 (review r10): an eligible Result Analyst that disagrees with the interpretation makes the result
        # inconclusive, pre-registered or not (docs/05 §4.2); v0.7 r9 let the pre-registration win over it
        return "E_inc", disagreement
    if outcome == "FAIL":
        ok, why = fail_reproduced(tc, tr, probabilistic)
        if not ok:
            return "E_inc", why
        if not (set(tr.get("fail_oracles") or []) & DETERMINISTIC_ORACLES):
            return "E_inc", "violation judged only by a non-deterministic oracle"
        if preregistered(ix, tc, tr, "oracle_can_pass", cluster) and authors_independent(ix, tr, cluster):
            return "E_proof", "reproduced FAIL, deterministic oracle, pre-registered interpretation"
        # r14 (05-v0.15, C3): an LLM-written W4 oracle that G2 has not accepted is not proof, with or without an analyst
        # (an analyst LLM confirming an LLM's oracle is still no human review); it is a signal capped at LIKELY (R6)
        if oracle_unreviewed(ix, tc, tr, cluster):
            return "E_fail_u", "reproduced FAIL, LLM-written W4 oracle not yet accepted at G2 (oracle_unreviewed)"
        if eligible:
            return "E_proof", "reproduced FAIL, cross-family analyst"
        if disagreement:
            return "E_inc", disagreement
        return "E_fail_u", "reproduced FAIL, no pre-registered interpretation or eligible analyst"
    if not reachability_reached(tc, tr):
        return "E_inc", "reachability control not passed"
    n_eff = got.get("n_effective", n)          # v0.4: n' = trials whose precondition was reached (docs/04 §4.4)
    need = pass_min_effective(ix, tc)
    if probabilistic and not (k == 0 and isinstance(n_eff, int) and n_eff >= need):
        return "E_inc", f"probabilistic PASS needs k=0 and n'>={need}"
    if not (oracle_types(tc) & DETERMINISTIC_ORACLES):
        return "E_inc", "no deterministic oracle"
    # r11: a pre-registered PASS needs independent authors, as a pre-registered FAIL does (E_proof); v0.7 let the
    # reporting family's own test, written and interpreted by itself, downgrade another family's confirmation (R11)
    if preregistered(ix, tc, tr, "oracle_can_fail", cluster) and authors_independent(ix, tr, cluster):
        return "E_pass", "qualified PASS, pre-registered interpretation"
    if eligible:
        return "E_pass", "qualified PASS, cross-family analyst"
    return "E_inc", disagreement or "no pre-registered interpretation, independent authors or eligible analyst"


def pinned_job_end(ix: Index, tr: dict) -> dict | None:
    """v0.7 (review r8 F2a / F2b): the one sandbox_job_end that executed this result: in the anchored part of its run's
    audit log, same outcome, and the three execution_pins equal the bundle's testcase / artifact / result hashes.
    None when there is no such event, more than one, or the pins differ. v0.6 reconciled only the last result named
    for a job, and only for jobs whose status said they ran, so a result on a PENDING / INTERRUPTED job (or a second
    result for an executed job) was taken as evidence without any execution."""
    tc = ix.testcase_for(tr)
    audit = ix.audit_for(tr.get("run_id"))
    evs = [e for e in (audit.data if audit else []) if isinstance(e, dict)]
    ends = [e for e in evs if job_end_of(e, tr)]
    if tc is None or len(ends) != 1:
        return None
    e, p = ends[0], ends[0].get("payload") or {}
    anchored = max((i + 1 for i, x in enumerate(evs) if x.get("event_type") == "audit_anchor"), default=0)
    ok = (type(e.get("seq")) is int and e.get("seq") < anchored and p.get("outcome") == tr.get("outcome")
          and all(p.get(k) == v for k, v in execution_pins(tc.data, tr).items()))
    return e if ok else None


def execution_pinned(ix: Index, tr: dict) -> bool:
    return pinned_job_end(ix, tr) is not None


def execution_anchored(ix: Index, tr: dict) -> bool:
    """v0.7 (review r8 F2a): exactly one sandbox_job_end in the anchored part of the run's log names this result's job
    (B4) or result (W4) with the same outcome. The evidence class needs an execution; whether the executor ran this
    exact testcase / result is E-JOB-AUDIT's (pinned_job_end), which fails the bundle on a mismatch."""
    audit = ix.audit_for(tr.get("run_id"))
    evs = [e for e in (audit.data if audit else []) if isinstance(e, dict)]
    ends = [e for e in evs if job_end_of(e, tr)]
    if len(ends) != 1:
        return False
    e = ends[0]
    anchored = max((i + 1 for i, x in enumerate(evs) if x.get("event_type") == "audit_anchor"), default=0)
    return type(e.get("seq")) is int and e.get("seq") < anchored and (e.get("payload") or {}).get("outcome") == tr.get("outcome")


def job_end_of(e, tr: dict) -> bool:
    """The sandbox_job_end event of a result: by job_id for B4, by result_id for W4 (W4 jobs are not run.jobs)."""
    if not isinstance(e, dict) or e.get("event_type") != "sandbox_job_end":
        return False
    p = e.get("payload") or {}
    if tr.get("phase") == "W4":
        return p.get("result_id") == tr.get("result_id")
    return tr.get("job_id") is not None and p.get("job_id") == tr.get("job_id")


def execution_pins(tc: dict, tr: dict) -> dict:
    """v0.5 (review r7 1.10): hashes the executor records in sandbox_job_end: the testcase it ran, the artifact, and the
    result it returned."""
    return {"testcase_sha256": content_hash(tc), "artifact_sha256": tr.get("artifact_sha256"), "result_sha256": content_hash(tr)}


# Second external review of r12 (05-v0.13): the M-2 evidence that splits one family into independent observations (docs/05
# §4.3): kappa's upper confidence bound below the "diversity too low" bar of M-2 (κ ≥ 0.6, docs/05 §5.3), measured on at
# least as many clusters as a calibration threshold needs (threshold_search.min_clusters)
INDEPENDENCE_SPLIT = {"kappa_ci_upper_max": 0.6, "n_min": 40}


def independence_evidence_ok(x: dict) -> bool:
    upper, n, lins = x.get("kappa_ci_upper"), x.get("n"), x.get("lineages")
    return (isinstance(upper, (int, float)) and not isinstance(upper, bool) and upper < INDEPENDENCE_SPLIT["kappa_ci_upper_max"]
            and type(n) is int and n >= INDEPENDENCE_SPLIT["n_min"] and isinstance(lins, list) and len(set(lins)) == 2)


def strongest(classes) -> str | None:
    for c in ("E_proof", "E_fail_u", "E_pass", "E_inc"):
        if c in classes:
            return c
    return None


def w4_became_disputed_clusters(ix: Index) -> dict[str, Any]:
    """cluster_id -> run_id for clusters with a verdict annotated w4_became_disputed."""
    out = {}
    for v in ix.docs("verdict"):
        if any(a.get("kind") == "w4_became_disputed" for a in v.data.get("annotations", []) if isinstance(a, dict)):
            cl = ix.first("cluster", cluster_id=v.data.get("cluster_id"))
            out[v.data.get("cluster_id")] = cl.data.get("run_id") if cl else None
    return out


# ---------------------------------------------------------------- gate artifacts
def gate_items(ix: Index, rec: dict) -> dict[str, Any]:
    """item_id -> the object shown at the gate (None if unknown)."""
    gate, run_id = rec.get("gate"), rec.get("run_id")
    out = {}
    for dec in rec.get("decisions", []):
        iid = dec.get("item_id")
        obj = None
        if gate == "G1":
            inv = ix.b.data("invariants") or {}
            obj = next((i for i in inv.get("invariants", []) if i.get("requirement_id") == iid), None)
        elif gate == "G2":
            d = ix.first("cluster", cluster_id=iid, run_id=run_id)
            obj = d.data if d else None
        elif gate == "G3":
            d = ix.first("threat", threat_id=iid)
            obj = d.data if d else None
        elif gate in ("G4", "G5"):
            d = ix.first("testcase", testcase_id=iid)
            obj = d.data if d else None
        out[iid] = obj
    return out


def gate_artifact(ix: Index, rec: dict) -> str | None:
    gate = rec.get("gate")
    if gate == "G0a":
        e = ix.b.data("engagement")
        return content_hash(e) if e else None
    if gate == "G0b":
        r = ix.b.data("roe")
        return content_hash(r) if r else None
    if gate == "G1":
        inv = ix.b.data("invariants")
        return approval_hash(inv) if inv else None
    items = gate_items(ix, rec)
    if gate in ("G2", "G3", "G4"):
        if any(v is None for v in items.values()):
            return None
        return set_digest([{"id": k, "sha256": approval_hash(v)} for k, v in items.items()])
    if gate == "G5":
        run = ix.first("run", run_id=rec.get("run_id"))
        job = ((run.data.get("jobs") or {}).get(rec.get("job_id")) if run else None) or {}
        tc = ix.first("testcase", testcase_id=job.get("testcase_id"))
        if not tc:
            return None
        return content_hash({"job_id": rec.get("job_id"), "testcase_sha256": approval_hash(tc.data)})
    if gate == "GB":
        gb = rec.get("gb") or {}
        return content_hash({"run_id": rec.get("run_id"), "phase": gb.get("phase"), "new_caps": gb.get("new_caps")})
    return None


def item_hash(ix: Index, rec: dict, item_id: str):
    gate = rec.get("gate")
    if gate in ("G0a", "G0b"):
        return gate_artifact(ix, rec)
    if gate == "GB":
        return None
    obj = gate_items(ix, rec).get(item_id)
    return approval_hash(obj) if obj is not None else MISSING


# ---------------------------------------------------------------- shared with expectations.py
# v0.7 (review r10): str.isdigit() accepts "²", which int() rejects (an internal error that skipped documents)
_INDEX = re.compile(r"0|[1-9][0-9]*")


def gate_record_sha256(rec: dict) -> str:
    """v0.7 (review r10 gate): the content a gate_decision pins: content_hash, which excludes the signatures, so re-signing
    the same content is not a change and any edit of a decided record is (docs/06 §1.8)."""
    return content_hash(rec)


def tool_results_ref(ix: Index, rid) -> str | None:
    """v0.5 (BL-13): the run's ToolResult list, as the sorted unique payload_refs of its W1 / Z2 tool_invocation_end
    audit events; None when W1 recorded none."""
    audit = ix.audit_for(rid)
    refs = sorted({r for e in (audit.data if audit else []) if isinstance(e, dict) and e.get("event_type") == "tool_invocation_end"
                   and e.get("node") == "W1" and e.get("zone") == "Z2" for r in e.get("payload_refs") or [] if isinstance(r, str)})
    return sha256_ref(jcs(refs)) if refs else None


def _equal(a, b) -> bool:
    if isinstance(a, bool) or isinstance(b, bool):
        return a is b if isinstance(a, bool) and isinstance(b, bool) else False
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return abs(a - b) <= 5e-4
    if isinstance(a, dict) and isinstance(b, dict):
        return a.keys() == b.keys() and all(_equal(a[k], b[k]) for k in a)
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(_equal(x, y) for x, y in zip(a, b))
    return a == b


__all__ = ["Index", "classify_result", "strongest", "gate_artifact",
           "get_path", "set_path", "fmt_path", "MISSING", "ZERO", "timeutil"]
