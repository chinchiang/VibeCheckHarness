# SPDX-License-Identifier: Apache-2.0
"""Check groups over the toolkit's own configuration: licenses and requirements, the crosswalk, the LLM-facing schemas,
toolkit.yaml / tools.yaml / retention.

Split out of checks.py (architecture refactor PR-D0, docs/adr/0003-split-checks.md). The text is moved verbatim; no
rule, error code or message changed. checks.GROUPS still lists the four groups in the same order.
"""
from __future__ import annotations

import re

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError

from . import llm_schema, safety
from .context import REQUIRED_AUTOMATION, Ctx
from .report import B1_SKIP_BASELINE, GATE_ROLES, LEGAL_GATE, Report


# ============================================================== 17 licenses
def g_licenses(R: Report, c: Ctx):
    comps = {x.get("component"): x for x in c.licenses.get("components", [])}
    R.check(len(comps) == len(c.licenses.get("components", [])), "E-LIC-DUP", "licenses.yaml", "duplicate components")
    for t, spec in (c.tools.get("tools") or {}).items():
        R.check(spec.get("license_ref") in comps, "E-LIC-MISSING", "tools.yaml", f"{t}: license_ref {spec.get('license_ref')!r} not in licenses.yaml")
    for x in comps.values():
        if x.get("status") == LEGAL_GATE:
            R.check(x.get("gate_milestone") is not None, "E-LIC-GATE", "licenses.yaml", f"{x.get('component')}: 法務閘門 needs a gate_milestone")
    req = c.b.requirements_txt
    if R.check(req is not None, "E-REQ", "requirements.txt", "requirements.txt missing"):
        names = [re.split(r"[<>=!~\[; ]", ln.strip())[0].lower() for ln in req.splitlines() if ln.strip() and not ln.startswith("#")]  # type: ignore[union-attr]  # R.check above returned False for None
        lic = {k.lower(): v for k, v in comps.items()}
        for n in names:
            R.check(n in lic and str(lic[n].get("usage", "")).startswith("validator"), "E-LIC-MISSING", "requirements.txt",
                    f"{n} is not listed in licenses.yaml as a validator dependency")
        R.check("rfc8785==0.1.4" in req.replace(" ", ""), "E-REQ", "requirements.txt", "rfc8785 must be pinned to 0.1.4")  # type: ignore[union-attr]  # same guard


# ============================================================== 18 crosswalk
def g_crosswalk(R: Report, c: Ctx):
    x, w = c.crosswalk, "crosswalk.yaml"
    if not x:
        return
    R.check(x.get("owasp_llm_default") == c.toolkit.get("owasp_llm_default"), "E-XWALK-OWASP", w, "owasp_llm_default differs from toolkit.yaml")
    seen = set()
    for l in x.get("links", []):
        key = (l.get("from_scheme"), l.get("from_id"), l.get("target_scheme"), l.get("target_id"))
        R.check(key not in seen, "E-XWALK-DUP", w, f"duplicate link {key}")
        seen.add(key)
        R.check((l.get("provenance") == "curated") == (l.get("reviewed_by") is not None), "E-XWALK-REVIEW", w,
                f"{key}: curated links need reviewed_by; llm-suggested links must not have it")
        if l.get("target_scheme") == "invariant":
            R.check(l.get("target_id") in {i.get("requirement_id") for i in c.invariants.get("invariants", [])}, "E-TRACE", w, f"{key}: unknown invariant")
        fs = str(l.get("from_scheme"))
        if fs.startswith("owasp-llm@"):
            R.check(fs[len("owasp-llm@"):] in ("2025", "2026"), "E-XWALK-OWASP", w, f"{fs}: unknown OWASP LLM version")


# ============================================================== 19 LLM-facing schemas
def g_llm_schemas(R: Report, c: Ctx):
    """C / D7: for every LLM_OUTPUTS entry, project (harness-owned fields removed) and degrade the archival schema;
    the result uses only the cross-vendor subset, contains no harness-owned field, and every example's LLM part
    validates against it (round trip: the LLM part plus the harness fields is the archival example)."""
    schemas = c.b.schemas
    for out_name, spec in llm_schema.LLM_OUTPUTS.items():
        where = f"LLM output {out_name} ({spec['schema']}.schema.json)"
        s = schemas.get(spec["schema"])
        if not R.check(s is not None, "E-LLM-SCHEMA", where, "schema missing"):
            continue
        try:
            deg = llm_schema.degrade_for_llm(llm_schema.project(s, spec, schemas), schemas)  # type: ignore[arg-type]  # a missing schema raised above
        except llm_schema.DegradeError as exc:
            R.error("E-LLM-SCHEMA", where, f"cannot be degraded: {exc}")
            continue
        hits = llm_schema.find_forbidden(deg)
        R.check(not hits, "E-LLM-SCHEMA", where, f"outside the common subset: {hits[:5]}")
        owned = llm_schema.owned_paths_present(deg, spec)
        R.check(not owned, "E-LLM-SCHEMA", where, f"harness-owned fields are still in the LLM schema: {owned}")
        try:
            Draft202012Validator.check_schema(deg)
        except SchemaError as exc:
            R.error("E-LLM-SCHEMA", where, exc.message)
            continue
        v = Draft202012Validator(deg)
        for d in c.docs(spec["schema"]):
            for part in llm_schema.project_instance(d.data, spec):
                errs = list(v.iter_errors(part))
                R.check(not errs, "E-LLM-SCHEMA", d.path,
                        f"{out_name}: the LLM part does not validate against the degraded schema: {errs[0].message[:200] if errs else ''}")


# ============================================================== 20 toolkit
def g_toolkit(R: Report, c: Ctx):
    tk, w = c.toolkit, "toolkit.yaml"
    if not R.check(bool(tk), "E-TOOLKIT", w, "toolkit.yaml missing"):
        return
    R.check(re.match(r"^\d+\.\d+\.\d+$", str(tk.get("toolkit_version", ""))) is not None, "E-TOOLKIT", w, "toolkit_version must be semver")
    R.check(REQUIRED_AUTOMATION <= set(tk.get("automation_accounts", [])), "E-TOOLKIT", w, f"automation_accounts must include {sorted(REQUIRED_AUTOMATION)}")
    R.check(tk.get("owasp_llm_default") in ("2025", "2026"), "E-TOOLKIT", w, "owasp_llm_default must be 2025 or 2026")
    missing = B1_SKIP_BASELINE - {str(k).lower() for k in (tk.get("b1_crawl") or {}).get("skip_keywords") or []}
    R.check(not missing, "E-TOOLKIT-B1", w, f"b1_crawl.skip_keywords drops the baseline keywords {sorted(missing)} (docs/08 §11.7)")
    R.check((tk.get("gate_timeouts_hours") or {}).get("G5", 99) <= 24, "E-TOOLKIT", w, "G5 timeout must be <= 24 h")
    for key in ("g2_max_items", "g3_max_items", "g4_max_items"):          # v0.7 (review r8 M1): a cap of 0 sends every item to over_cap unreviewed
        val = (tk.get("gate_queues") or {}).get(key)
        R.check(type(val) is int and val >= 1, "E-TOOLKIT", w, f"gate_queues.{key} {val!r} must be an integer >= 1 (0 would skip the gate)")
    R.check(set(GATE_ROLES) - {"G0a", "G0b"} | {"claim_run", "GB"} <= set(tk.get("gate_timeouts_hours") or {}), "E-TOOLKIT", w, "missing gate timeouts")
    ref = tk.get("tool_registry_ref")
    R.check(ref is not None and (c.b.root / ref).exists(), "E-TOOLKIT", w, f"tool_registry_ref {ref} does not exist")
    ret = tk.get("retention") or {}
    for f in ("p_days", "c_days_after_run_end", "audit_days", "checkpoint_days_after_run_end", "checkpoint_keep_last"):
        R.check(isinstance(ret.get(f), int) and ret[f] >= (1 if f == "checkpoint_keep_last" else 0), "E-RETENTION", w, f"retention.{f} must be a non-negative integer")
    R.check(isinstance(ret.get("legal_hold"), list), "E-RETENTION", w, "retention.legal_hold must be a list")
    R.check(ret.get("audit_days", 0) >= max(ret.get("p_days", 0), ret.get("c_days_after_run_end", 0)), "E-RETENTION", w,
            "audit records must be kept at least as long as the content")
    for t, spec in (c.tools.get("tools") or {}).items():
        for m in (spec.get("modes") or {}):
            R.check(safety.ADAPTER_RE.match(f"{t}:{m}") is not None, "E-TOOLS-ID", "tools.yaml", f"{t}:{m} is not a D13 tool:mode id")
        for m, ms in (spec.get("modes") or {}).items():
            if ms.get("b4_executable") and not ms.get("toolkit_denied"):
                R.check(ms.get("base_class") in safety.ORDER, "E-TOOLS-CLASS", "tools.yaml", f"{t}:{m}: executable mode needs a base_class")
            R.check(not ms.get("b4_executable") or spec.get("zone") == "Z3", "E-TOOLS-ZONE", "tools.yaml", f"{t}:{m}: B4 modes run in Z3")
