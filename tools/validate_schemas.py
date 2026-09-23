#!/usr/bin/env python3
"""Validate the VibeCheck Harness data model and example configuration.

Checks:
  1. every schema in docs/schemas is a valid JSON Schema (2020-12);
  2. every example instance validates against its schema;
  3. docs/examples/{models,agents,roe}.yaml validate against their schemas;
  4. semantic rules the design depends on (family diversity, same-family
     fallback only, cloud Nemotron limited to P data, G5 separation of duties,
     computed safety class >= proposed, targets are ROE target IDs, ...);
  5. the LLM-facing "output schema" derived from the archival Finding schema
     uses only the cross-vendor common subset described in docs/03 §8.3.

Usage:  python3 -m pip install jsonschema pyyaml && python3 tools/validate_schemas.py
"""
from __future__ import annotations

import copy
import hashlib
import json
import pathlib
import sys

import yaml
from jsonschema import Draft202012Validator, FormatChecker

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCHEMAS = ROOT / "docs" / "schemas"
EXAMPLES = SCHEMAS / "examples"
CONFIG = ROOT / "docs" / "examples"
ORDER = ["S0", "S1", "S2", "S3"]
# Keywords outside the common subset of Claude / OpenAI strict structured outputs
# (docs/03 §8.3). `pattern` and `format` are also stripped because their support
# was not verified for every provider; the archival schema re-checks them.
FORBIDDEN_FOR_LLM = {
    "minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum", "minLength",
    "maxLength", "multipleOf", "pattern", "format", "$ref", "$defs",
}

errors: list[str] = []


def fail(msg: str) -> None:
    errors.append(msg)
    print(f"  FAIL {msg}")


def ok(msg: str) -> None:
    print(f"  ok   {msg}")


def load_schemas() -> dict[str, dict]:
    out = {}
    for path in sorted(SCHEMAS.glob("*.schema.json")):
        schema = json.loads(path.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        out[path.name.removesuffix(".schema.json")] = schema
        ok(f"schema {path.name}")
    return out


def validate(schema: dict, instance, label: str) -> bool:
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errs = sorted(validator.iter_errors(instance), key=lambda e: list(e.path))
    if errs:
        for e in errs:
            fail(f"{label}: {'/'.join(map(str, e.path)) or '<root>'}: {e.message}")
        return False
    ok(label)
    return True


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


def main() -> int:
    print("1) schemas")
    schemas = load_schemas()

    print("2) example instances")
    instances: dict[str, list[dict]] = {}
    for path in sorted(EXAMPLES.glob("*.json")):
        name = path.name.split(".")[0]
        if name not in schemas:
            fail(f"{path.name}: no schema named {name}")
            continue
        inst = json.loads(path.read_text(encoding="utf-8"))
        validate(schemas[name], inst, f"examples/{path.name}")
        instances.setdefault(name, []).append(inst)

    print("3) configuration examples")
    models = yaml.safe_load((CONFIG / "models.yaml").read_text(encoding="utf-8"))
    agents = yaml.safe_load((CONFIG / "agents.yaml").read_text(encoding="utf-8"))
    roe = yaml.safe_load((CONFIG / "roe.yaml").read_text(encoding="utf-8"))
    validate(schemas["model-registry"], models, "examples/models.yaml")
    validate(schemas["agent-registry"], agents, "examples/agents.yaml")
    validate(schemas["roe"], roe, "examples/roe.yaml")

    print("4) semantic rules")
    # 4.1 evidence snippet hashes
    for f in instances.get("finding", []):
        for ev in f["evidence"]:
            digest = "sha256:" + hashlib.sha256(ev["snippet"].encode()).hexdigest()
            if digest != ev["snippet_sha256"]:
                fail(f"{f['finding_id']}: snippet_sha256 does not match snippet")
            else:
                ok(f"{f['finding_id']}: snippet hash matches")

    # 4.2 agents reference existing models
    for name, a in agents.items():
        if a["model"] not in models:
            fail(f"agent {name}: unknown model {a['model']}")
    ok("all agents reference known models")

    # 4.3 fallback only within the same family
    for key, m in models.items():
        for fb in m["fallback"]:
            if fb not in models:
                fail(f"model {key}: fallback {fb} unknown")
            elif models[fb]["family"] != m["family"]:
                fail(f"model {key}: cross-family fallback to {fb} is not allowed")
    ok("fallbacks are same-family only")

    # 4.4 cloud Nemotron (NVIDIA API trial) never gets C data or production use
    for key, m in models.items():
        if m["litellm"].startswith("nvidia_nim/"):
            if "C" in m["data_classes"] or "production" in m["purpose"]:
                fail(f"model {key}: build.nvidia.com trial must be P-only and non-production")
            else:
                ok(f"model {key}: trial endpoint limited to P data, evaluation/prototyping")

    # 4.5 family diversity for confidential (C) code
    def fam(agent):
        m = models[agent["model"]]
        return m["family"], m["lineage"], set(m["data_classes"])

    reviewers = [fam(a) for a in agents.values() if a["role"] == "reviewer"]
    verifiers = [fam(a) for a in agents.values() if a["role"] == "verifier"]
    c_rev_fams = {f for f, _, dc in reviewers if "C" in dc}
    if len(c_rev_fams) < 2:
        fail(f"reviewers for C data span only {len(c_rev_fams)} family: diversity degraded")
    else:
        ok(f"reviewers for C data span {len(c_rev_fams)} families: {sorted(c_rev_fams)}")
    for rf, rl, _ in reviewers:
        if not any(vf != rf and vl != rl and "C" in vdc for vf, vl, vdc in verifiers):
            fail(f"no C-capable verifier outside family {rf}/{rl}")
    ok("every reviewer family has a C-capable verifier from another family and lineage")

    # 4.6 gate records: G5 separation of duties
    for g in instances.get("gate-record", []):
        if g["gate"] == "G5" and g["initiator"] == g["approver"]["name"]:
            fail(f"{g['gate_record_id']}: G5 approver must differ from initiator")
        elif g["gate"] == "G5":
            ok(f"{g['gate_record_id']}: G5 approver differs from initiator")

    # 4.7 test cases: computed class >= proposed; targets are ROE target IDs
    roe_targets = {t["id"] for t in roe["targets"]}
    for tc in instances.get("testcase", []):
        prop = tc["safety_class_proposed"] or "S0"
        comp = tc["safety_class_computed"]
        if ORDER.index(comp) < ORDER.index(prop):
            fail(f"{tc['testcase_id']}: computed class {comp} lower than proposed {prop}")
        if comp == "S3":
            fail(f"{tc['testcase_id']}: S3 tests must never be scheduled")
        if comp not in roe["activities"]["allowed_safety_classes"]:
            fail(f"{tc['testcase_id']}: {comp} not allowed by ROE")
        missing = set(tc["target_ids"]) - roe_targets
        if missing:
            fail(f"{tc['testcase_id']}: targets not in ROE: {sorted(missing)}")
        if tc["rate_limit"]["requests_per_second"] > roe["rate_limits"]["per_host_rps"]:
            fail(f"{tc['testcase_id']}: rate limit exceeds ROE per_host_rps")
        ok(f"{tc['testcase_id']}: safety class {comp}, targets and rate within ROE")

    # 4.8 ROE validity window
    if roe["validity"]["not_before"] >= roe["validity"]["not_after"]:
        fail("roe.yaml: not_before must be earlier than not_after")
    else:
        ok("roe.yaml: validity window is ordered")

    # 4.9 threats: llm-suggested crosswalk links need review before use
    for t in instances.get("threat", []):
        for link in t["crosswalk"]:
            if link["provenance"] == "llm-suggested" and t["review"]["status"] == "ACCEPTED" and not link["reviewed_by"]:
                fail(f"{t['threat_id']}: accepted threat has unreviewed llm-suggested link {link['target_id']}")
        ok(f"{t['threat_id']}: crosswalk provenance rules hold")

    print("5) LLM-facing output schema (cross-vendor subset)")
    llm_finding = degrade_for_llm(schemas["finding"])
    hits = find_forbidden(llm_finding)
    if hits:
        for h in hits:
            fail(f"degraded finding schema: {h}")
    else:
        ok("degraded finding schema uses only the common subset")
    for f in instances.get("finding", []):
        validate(llm_finding, f, f"{f['finding_id']} against degraded schema")

    print()
    if errors:
        print(f"{len(errors)} check(s) failed")
        return 1
    print("all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
