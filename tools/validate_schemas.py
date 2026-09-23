#!/usr/bin/env python3
"""Validate the VibeCheck Harness data model and example configuration.

Checks:
  1. every schema in docs/schemas is a valid JSON Schema (2020-12);
  2. every example instance validates against its schema;
  3. docs/examples/{models,agents,roe,engagement}.yaml validate against their schemas;
  4. semantic rules the design depends on (see the numbered checks below);
  5. the LLM-facing "output schema" derived from the archival Finding schema
     uses only the cross-vendor common subset described in docs/03 §8.3.

Usage:  python3 -m pip install jsonschema pyyaml && python3 tools/validate_schemas.py
"""
from __future__ import annotations

import copy
import datetime as dt
import hashlib
import json
import pathlib
import sys
from zoneinfo import ZoneInfo

import yaml
from jsonschema import Draft202012Validator, FormatChecker

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCHEMAS = ROOT / "docs" / "schemas"
EXAMPLES = SCHEMAS / "examples"
CONFIG = ROOT / "docs" / "examples"
ORDER = ["S0", "S1", "S2", "S3"]
# Keywords outside the common subset of Claude / OpenAI strict structured outputs
# (docs/03 §8.3). `pattern`, `format`, `const` and `contains` are also stripped
# because their support was not verified for every provider; the archival schema
# re-checks them after the LLM answers.
FORBIDDEN_FOR_LLM = {
    "minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum", "minLength",
    "maxLength", "multipleOf", "pattern", "format", "$ref", "$defs", "contains",
}
# Roles that must approve each gate (docs/02 §1.3).
GATE_ROLES = {
    "G0a": {"app_owner"},
    "G0b": {"test_lead", "management", "infrastructure_owner"},
    "G1": {"app_owner"},
    "G2": {"security_reviewer"},
    "G3": {"security_reviewer", "app_owner"},
    "G4": {"security_reviewer"},
    "G5": {"security_reviewer"},
}
AUTOMATION_ACCOUNTS = {"run-controller", "commander", "system", "automation"}
NON_ADJUDICATING_ROLES = {"reporter"}

errors: list[str] = []


def fail(msg: str) -> None:
    errors.append(msg)
    print(f"  FAIL {msg}")


def check(cond: bool, ok_msg: str, fail_msg: str) -> bool:
    if cond:
        print(f"  ok   {ok_msg}")
    else:
        fail(fail_msg)
    return cond


def load_schemas() -> dict[str, dict]:
    out = {}
    for path in sorted(SCHEMAS.glob("*.schema.json")):
        schema = json.loads(path.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        out[path.name.removesuffix(".schema.json")] = schema
        print(f"  ok   schema {path.name}")
    return out


def validate(schema: dict, instance, label: str) -> bool:
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errs = sorted(validator.iter_errors(instance), key=lambda e: list(e.path))
    for e in errs:
        fail(f"{label}: {'/'.join(map(str, e.path)) or '<root>'}: {e.message}")
    if not errs:
        print(f"  ok   {label}")
    return not errs


def inline_refs(node, defs):
    if isinstance(node, dict):
        if "$ref" in node and node["$ref"].startswith("#/$defs/"):
            return inline_refs(copy.deepcopy(defs[node["$ref"].split("/")[-1]]), defs)
        return {k: inline_refs(v, defs) for k, v in node.items() if k != "$defs"}
    if isinstance(node, list):
        return [inline_refs(v, defs) for v in node]
    return node


def degrade_for_llm(schema: dict) -> dict:
    """Derive the LLM-facing output schema (cross-vendor common subset)."""
    s = inline_refs(schema, schema.get("$defs", {}))

    def walk(node):
        if isinstance(node, dict):
            node = {k: walk(v) for k, v in node.items() if k not in FORBIDDEN_FOR_LLM}
            if node.get("type") == "object" and "properties" in node:
                node["additionalProperties"] = False
                node["required"] = list(node["properties"].keys())
            if "minItems" in node:
                node["minItems"] = min(node["minItems"], 1)
            node.pop("$schema", None)
            node.pop("$id", None)
            return node
        if isinstance(node, list):
            return [walk(v) for v in node]
        return node

    return walk(s)


def find_forbidden(node, path="") -> list[str]:
    hits = []
    if isinstance(node, dict):
        for k, v in node.items():
            if k in FORBIDDEN_FOR_LLM:
                hits.append(f"{path}/{k}")
            if k == "minItems" and v > 1:
                hits.append(f"{path}/minItems={v}")
            hits += find_forbidden(v, f"{path}/{k}")
        if node.get("type") == "object" and "properties" in node:
            if node.get("additionalProperties") is not False:
                hits.append(f"{path}: additionalProperties must be false")
            if set(node.get("required", [])) != set(node["properties"]):
                hits.append(f"{path}: all properties must be required")
    elif isinstance(node, list):
        for i, v in enumerate(node):
            hits += find_forbidden(v, f"{path}[{i}]")
    return hits


def parse_ts(value: str) -> dt.datetime:
    return dt.datetime.fromisoformat(value)


def in_window(ts: dt.datetime, windows: list[dict]) -> bool:
    for w in windows:
        local = ts.astimezone(ZoneInfo(w["tz"]))
        day = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"][local.weekday()]
        if day in w["days"] and w["start"] <= local.strftime("%H:%M") <= w["end"]:
            return True
    return False


def main() -> int:
    print("1) schemas")
    schemas = load_schemas()

    print("2) example instances")
    inst: dict[str, list[dict]] = {}
    for path in sorted(EXAMPLES.glob("*.json")):
        name = path.name.split(".")[0]
        if name not in schemas:
            fail(f"{path.name}: no schema named {name}")
            continue
        obj = json.loads(path.read_text(encoding="utf-8"))
        validate(schemas[name], obj, f"examples/{path.name}")
        inst.setdefault(name, []).append(obj)

    print("3) configuration examples")
    cfg = {n: yaml.safe_load((CONFIG / f"{n}.yaml").read_text(encoding="utf-8"))
           for n in ("models", "agents", "roe", "engagement")}
    models, agents, roe, eng = cfg["models"], cfg["agents"], cfg["roe"], cfg["engagement"]
    validate(schemas["model-registry"], models, "examples/models.yaml")
    validate(schemas["agent-registry"], agents, "examples/agents.yaml")
    validate(schemas["roe"], roe, "examples/roe.yaml")
    validate(schemas["engagement"], eng, "examples/engagement.yaml")

    print("4) semantic rules")
    # 4.1 evidence snippet hashes
    for f in inst.get("finding", []):
        for ev in f["evidence"]:
            digest = "sha256:" + hashlib.sha256(ev["snippet"].encode()).hexdigest()
            check(digest == ev["snippet_sha256"], f"{f['finding_id']}: snippet hash matches",
                  f"{f['finding_id']}: snippet_sha256 does not match snippet")

    # 4.2 agents reference known models allowed for the engagement's data class
    allowed = set(eng["allowed_models"][eng["data_class"]])
    unknown = [n for n, a in agents.items() if a["model"] not in models]
    check(not unknown, "all agents reference known models", f"agents with unknown models: {unknown}")
    not_allowed = [n for n, a in agents.items() if a["model"] not in allowed]
    check(not not_allowed, f"all agent models are allowed for data class {eng['data_class']}",
          f"agents using models not allowed for {eng['data_class']}: {not_allowed}")
    class_mismatch = [k for k in allowed if eng["data_class"] not in models.get(k, {}).get("data_classes", [])]
    check(not class_mismatch, "engagement allow-list agrees with model data classes",
          f"engagement allows models that cannot take {eng['data_class']} data: {class_mismatch}")

    # 4.3 model fallback only within the same family; cross-family only for reporter
    bad = [f"{k}->{fb}" for k, m in models.items() for fb in m["fallback"]
           if fb not in models or models[fb]["family"] != m["family"]]
    check(not bad, "model fallbacks are same-family only", f"cross-family or unknown model fallback: {bad}")
    bad = [n for n, a in agents.items() if a.get("fallback_models") and a["role"] not in NON_ADJUDICATING_ROLES]
    check(not bad, "cross-family agent fallback only on non-adjudicating roles",
          f"agents with fallback_models in adjudicating roles: {bad}")

    # 4.4 cloud Nemotron (NVIDIA API trial) never gets C data or production use
    for key, m in models.items():
        if m["litellm"].startswith("nvidia_nim/"):
            check("C" not in m["data_classes"] and "production" not in m["purpose"],
                  f"model {key}: trial endpoint limited to P data, evaluation/prototyping",
                  f"model {key}: build.nvidia.com trial must be P-only and non-production")

    # 4.5 family diversity for the engagement's data class
    def fam(agent):
        m = models[agent["model"]]
        return m["family"], m["lineage"], set(m["data_classes"])

    dc = eng["data_class"]
    reviewers = [fam(a) for a in agents.values() if a["role"] == "reviewer"]
    verifiers = [fam(a) for a in agents.values() if a["role"] == "verifier"]
    rev_fams = {f for f, _, d in reviewers if dc in d}
    check(len(rev_fams) >= 2, f"reviewers for {dc} data span {len(rev_fams)} families: {sorted(rev_fams)}",
          f"reviewers for {dc} data span only {len(rev_fams)} family: diversity degraded")
    missing = [f"{rf}/{rl}" for rf, rl, _ in reviewers
               if not any(vf != rf and vl != rl and dc in vd for vf, vl, vd in verifiers)]
    check(not missing, "every reviewer family has a verifier from another family and lineage",
          f"no eligible verifier outside: {missing}")

    # 4.6 verdict votes come from outside the cluster's families and lineages
    clusters = {c["cluster_id"]: c for c in inst.get("cluster", [])}
    for v in inst.get("verdict", []):
        c = clusters.get(v["cluster_id"])
        if not c:
            fail(f"{v['verdict_id']}: unknown cluster {v['cluster_id']}")
            continue
        bad = [x["voter_agent_id"] for x in v["votes"] if x["valid"] and
               (x["voter_family"] in c["families"] or x["voter_lineage"] in c["lineages"])]
        check(not bad, f"{v['verdict_id']}: valid votes come from outside cluster families/lineages",
              f"{v['verdict_id']}: self-review votes counted as valid: {bad}")
        if v["status"] == "CONFIRMED_EXECUTABLE":
            p = v["executable_proof"]
            ok = p is not None and p["interpretation_confirmed_by"] is not None \
                and p["interpretation_confirmed_by"]["family"] not in c["families"]
            check(ok, f"{v['verdict_id']}: executable proof interpreted by another family",
                  f"{v['verdict_id']}: CONFIRMED_EXECUTABLE needs cross-family interpretation")

    # 4.7 gate records: registered approvers with required roles, validity, separation of duties
    registry = {(p["name"], p["key_fingerprint"]): p["role"] for p in roe["signatories"] + roe["gate_approvers"]}
    registry.update({(p["name"], p["key_fingerprint"]): p["role"] for p in eng["signatories"]})
    people = {name for name, _ in registry}
    e_from, e_to = parse_ts(eng["validity"]["not_before"]), parse_ts(eng["validity"]["not_after"])
    r_from, r_to = parse_ts(roe["validity"]["not_before"]), parse_ts(roe["validity"]["not_after"])
    for g in inst.get("gate-record", []):
        gid = g["gate_record_id"]
        unreg = [a["name"] for a in g["approvers"] if registry.get((a["name"], a["key_fingerprint"])) != a["role"]]
        check(not unreg, f"{gid}: approvers are registered with matching role and key",
              f"{gid}: unregistered approver/role/key: {unreg}")
        roles = {a["role"] for a in g["approvers"]}
        need = GATE_ROLES[g["gate"]]
        check(need <= roles, f"{gid}: required roles {sorted(need)} present",
              f"{gid}: missing required roles {sorted(need - roles)}")
        sig_keys = {s["key_fingerprint"] for s in g["signatures"]}
        check({a["key_fingerprint"] for a in g["approvers"]} <= sig_keys, f"{gid}: every approver signed",
              f"{gid}: approver without signature")
        ts = parse_ts(g["timestamp"])
        check(e_from <= ts <= e_to, f"{gid}: within engagement validity", f"{gid}: outside engagement validity")
        check(g["initiator"] not in AUTOMATION_ACCOUNTS and g["initiator"] in people,
              f"{gid}: initiator is a registered person", f"{gid}: initiator must be a registered person")
        if g["gate"] in {"G4", "G5"}:
            check(r_from <= ts <= r_to, f"{gid}: within ROE validity", f"{gid}: outside ROE validity")
        if g["gate"] == "G5":
            check(g["initiator"] not in {a["name"] for a in g["approvers"]},
                  f"{gid}: G5 approver differs from initiator", f"{gid}: G5 approver must differ from initiator")
            check(in_window(ts, roe["validity"]["windows"]), f"{gid}: inside an ROE time window",
                  f"{gid}: outside ROE time windows")

    # 4.8 ROE: signatories include infrastructure owner; each signatory signed; validity ordered
    roles = {p["role"] for p in roe["signatories"]}
    check({"test_lead", "management", "infrastructure_owner"} <= roles,
          "roe.yaml: signed by test lead, management and infrastructure owner",
          "roe.yaml: signatories must include test_lead, management, infrastructure_owner")
    check({p["key_fingerprint"] for p in roe["signatories"]} <= {s["key_fingerprint"] for s in roe["signatures"]},
          "roe.yaml: every signatory has a detached signature", "roe.yaml: signatory without signature")
    check(r_from < r_to, "roe.yaml: validity window is ordered", "roe.yaml: not_before must precede not_after")
    check(roe["validity"]["not_after"] <= eng["validity"]["not_after"],
          "roe.yaml: ROE ends within the engagement", "roe.yaml: ROE outlives the engagement")

    # 4.9 test cases: class, targets, rates, request allow-list, seed manifest for DELETE
    roe_targets = {t["id"] for t in roe["targets"]}
    roe_roles = {r["role"] for r in roe["test_roles"]}
    for tc in inst.get("testcase", []):
        tid = tc["testcase_id"]
        prop, comp = tc["safety_class_proposed"] or "S0", tc["safety_class_computed"]
        check(ORDER.index(comp) >= ORDER.index(prop), f"{tid}: computed class {comp} >= proposed {prop}",
              f"{tid}: computed class {comp} lower than proposed {prop}")
        check(comp != "S3" and comp in roe["activities"]["allowed_safety_classes"],
              f"{tid}: class {comp} allowed by ROE", f"{tid}: class {comp} not allowed")
        used = set(tc["target_ids"]) | {r["target_id"] for r in tc["request_allowlist"]}
        check(used <= roe_targets, f"{tid}: targets are ROE target IDs", f"{tid}: targets not in ROE: {sorted(used - roe_targets)}")
        check(tc["rate_limit"]["requests_per_second"] <= roe["rate_limits"]["per_host_rps"],
              f"{tid}: rate within ROE", f"{tid}: rate limit exceeds ROE per_host_rps")
        has_delete = any(r["method"] == "DELETE" for r in tc["request_allowlist"])
        seeded = all("{seed:" in r["path"] for r in tc["request_allowlist"] if r["method"] == "DELETE")
        check(not has_delete or (tc["seed_manifest_ref"] and seeded), f"{tid}: DELETE only on seeded IDs",
              f"{tid}: DELETE requires a seed manifest and seeded path templates")
        check(set(tc["data_needed"]["roles"]) <= roe_roles, f"{tid}: roles are ROE test roles",
              f"{tid}: roles not in ROE test_roles: {sorted(set(tc['data_needed']['roles']) - roe_roles)}")

    # 4.10 threats: accepted threats carry no llm-suggested crosswalk links
    for t in inst.get("threat", []):
        bad = [l["target_id"] for l in t["crosswalk"] if l["provenance"] == "llm-suggested"]
        check(t["review"]["status"] != "ACCEPTED" or not bad,
              f"{t['threat_id']}: no llm-suggested links in an accepted threat",
              f"{t['threat_id']}: accepted threat still has llm-suggested links {bad}")

    print("5) LLM-facing output schema (cross-vendor subset)")
    llm_finding = degrade_for_llm(schemas["finding"])
    hits = find_forbidden(llm_finding)
    for hit in hits:
        fail(f"degraded finding schema: {hit}")
    if not hits:
        print("  ok   degraded finding schema uses only the common subset")
    for f in inst.get("finding", []):
        validate(llm_finding, f, f"{f['finding_id']} against degraded schema")

    print()
    if errors:
        print(f"{len(errors)} check(s) failed")
        return 1
    print("all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
