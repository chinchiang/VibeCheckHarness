# SPDX-License-Identifier: Apache-2.0
"""LLM-facing output schemas (docs/03 §8.3; v0.3: H-A4, M-V1, D7).

Every artifact an LLM produces is registered in LLM_OUTPUTS with its archival schema. The schema
sent to the model is built in two steps:

1. project(): resolve every $ref (internal $defs and cross-file refs such as
   common.schema.json#/$defs/..., requirement.schema.json), select the part the model writes
   (`pointer`), and remove the HARNESS-OWNED fields (IDs, hashes, run_id, families, statuses,
   safety class, approvals, match results...) or keep only the listed ones. The harness fills
   those fields itself; the model never sees or writes them.
2. degrade_for_llm(): reduce to the common subset of Claude / OpenAI strict structured outputs:
   - STRIPPED keywords are removed (numeric / length limits, pattern, format, contains,
     uniqueItems, ...): the archival schema re-checks them after the model answers;
   - `const` becomes a one-value `enum`; type arrays are kept;
   - a property that is not in the archival `required` becomes nullable before every property
     is made required, and every object gets additionalProperties: false;
   - minItems is clamped to 1;
   - REJECTED constructs (allOf / oneOf / not / if / then / else / patternProperties / ...), a
     free-form object (no properties, or additionalProperties true / a schema) and an
     unresolvable $ref raise DegradeError naming the path (fail closed: never `{}`).
"""
from __future__ import annotations

import copy

STRIPPED = frozenset({
    "minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum", "minLength", "maxLength", "multipleOf", "pattern", "format",
    "contains", "uniqueItems", "minProperties", "maxProperties", "propertyNames", "default",
})
REWRITTEN = frozenset({"const", "$ref", "$defs"})          # const -> enum; refs inlined; $defs dropped
REJECTED = frozenset({
    "allOf", "oneOf", "not", "if", "then", "else", "patternProperties", "dependentSchemas", "dependentRequired",
    "unevaluatedProperties", "unevaluatedItems", "prefixItems", "additionalItems",
})
# nothing in this set may appear in a degraded schema (find_forbidden; docs/schemas/README.md lists it)
FORBIDDEN_FOR_LLM = STRIPPED | REWRITTEN | REJECTED

# LLM-produced artifact -> archival schema, the part the model writes, and the harness-owned fields.
# Paths: "a.b" = nested property, "a[]" = the items of array a; `keep` lists the only properties the model writes.
LLM_OUTPUTS: dict[str, dict] = {
    "finding": {"schema": "finding", "pointer": "",
                "harness_owned": ["finding_id", "run_id", "slice_id", "reporter", "status", "evidence[].snippet_sha256", "evidence[].match"]},
    "vote": {"schema": "verdict", "pointer": "/properties/votes/items", "keep": ["stance", "rationale", "cited_evidence"]},
    "threat": {"schema": "threat", "pointer": "",
               "harness_owned": ["threat_id", "source_cluster_id", "source_finding_ids", "modeled_by", "review", "evidence[].match",
                                 "crosswalk[].provenance", "crosswalk[].source_ref", "crosswalk[].reviewed_by"]},
    "testcase": {"schema": "testcase", "pointer": "",
                 "harness_owned": ["testcase_id", "threat_id", "source_cluster_id", "safety_class_computed", "seed_manifest_ref",
                                   "oracle.oracle_query_sha256", "tool_binding.params", "strategy_template_sha256", "artifact_sha256"]},
    # v0.5 (BL-27): W4_testgen writes the test; the harness fixes its run, clusters, Z2 environment and artifact hash
    "w4-testcase": {"schema": "w4-testcase", "pointer": "",
                    "harness_owned": ["testcase_id", "run_id", "cluster_ids", "environment", "artifact_sha256"]},
    "commander-plan": {"schema": "commander-plan", "pointer": "",
                       "harness_owned": ["plan_id", "decision_node", "round", "followup_drafts[].draft_id"]},
    "invariants": {"schema": "invariants", "pointer": "",
                   "harness_owned": ["engagement_id", "run_id", "round", "drafted_by", "signoff", "invariants[].requirement_id",
                                     "invariants[].ref", "invariants[].signoff"]},
    "dfd": {"schema": "dfd", "pointer": "", "harness_owned": ["dfd_id", "run_id", "viewpoint", "elements[].provenance", "b1_diff"]},
    "result-interpretation": {"schema": "testresult", "pointer": "/properties/interpretation/anyOf/0", "keep": ["agrees", "rationale"]},
}


class DegradeError(ValueError):
    """The schema cannot be reduced to the LLM subset without losing a constraint silently."""


# ---------------------------------------------------------------- $ref resolution
def _pointer(doc, pointer: str):
    cur = doc
    for raw in [p for p in pointer.split("/") if p != ""]:
        tok = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(cur, list):
            cur = cur[int(tok)]
        else:
            cur = cur[tok]
    return cur


def resolve_refs(schema: dict, schemas: dict | None = None, name: str = "") -> dict:
    """Inline every $ref. `schemas` maps a schema name ("common") to its document for cross-file refs
    ("common.schema.json#/$defs/sha256"). An unresolvable ref raises DegradeError (never becomes {})."""
    schemas = schemas or {}

    def load(ref: str, base: dict, path: str):
        target, _, frag = ref.partition("#")
        doc = base
        if target:
            key = target.removesuffix(".schema.json")
            if key not in schemas:
                raise DegradeError(f"{path}: external $ref {ref!r} cannot be resolved")
            doc = schemas[key]
        try:
            return copy.deepcopy(_pointer(doc, frag)), doc
        except (KeyError, IndexError, ValueError, TypeError):
            raise DegradeError(f"{path}: $ref {ref!r} does not resolve") from None

    def walk(node, base, path, depth=0):
        if depth > 50:
            raise DegradeError(f"{path}: $ref nesting too deep (recursive schema)")
        if isinstance(node, dict):
            if "$ref" in node:
                target, doc = load(node["$ref"], base, path)
                rest = {k: v for k, v in node.items() if k != "$ref"}
                merged = {**walk(target, doc, path, depth + 1), **{k: walk(v, base, f"{path}/{k}", depth) for k, v in rest.items()}}
                return merged
            return {k: walk(v, base, f"{path}/{k}", depth) for k, v in node.items() if k != "$defs"}
        if isinstance(node, list):
            return [walk(v, base, f"{path}[{i}]", depth) for i, v in enumerate(node)]
        return node

    return walk(schema, schema, name or "#")


def inline_refs(node, defs):
    """Backwards-compatible helper: inline internal #/$defs refs only (external refs raise)."""
    return resolve_refs({**node, "$defs": defs} if isinstance(node, dict) else node, {})


# ---------------------------------------------------------------- projection
def _object_node(node: dict) -> dict:
    """The object alternative of a node (itself, or the object branch of an anyOf)."""
    if isinstance(node, dict) and ("properties" in node or node.get("type") == "object"):
        return node
    for alt in node.get("anyOf", []) if isinstance(node, dict) else []:
        if isinstance(alt, dict) and "properties" in alt:
            return alt
    raise DegradeError("path does not lead to an object")


def _array_items(node: dict) -> dict:
    if isinstance(node, dict) and "items" in node:
        return node["items"]
    for alt in node.get("anyOf", []) if isinstance(node, dict) else []:
        if isinstance(alt, dict) and "items" in alt:
            return alt["items"]
    raise DegradeError("path does not lead to an array")


def _drop_schema_path(schema: dict, path: str):
    parts = path.split(".")
    node = schema
    for i, part in enumerate(parts):
        arr = part.endswith("[]")
        name = part[:-2] if arr else part
        obj = _object_node(node)
        props = obj.get("properties") or {}
        if name not in props:
            raise DegradeError(f"harness-owned field {path!r}: {name!r} is not a property")
        if i == len(parts) - 1 and not arr:
            props.pop(name)
            if name in obj.get("required", []):
                obj["required"] = [r for r in obj["required"] if r != name]
            return
        node = _array_items(props[name]) if arr else props[name]
    raise DegradeError(f"harness-owned field {path!r} names an array, not a property")


def project(schema: dict, spec: dict, schemas: dict | None = None) -> dict:
    """The part of an archival schema the LLM writes (refs resolved, harness-owned fields removed)."""
    s = resolve_refs(schema, schemas, spec.get("schema", ""))
    if spec.get("pointer"):
        try:
            s = copy.deepcopy(_pointer(s, spec["pointer"]))
        except (KeyError, IndexError, ValueError, TypeError):
            raise DegradeError(f"pointer {spec['pointer']!r} does not resolve") from None
    if spec.get("keep") is not None:
        obj = _object_node(s)
        obj["properties"] = {k: v for k, v in obj.get("properties", {}).items() if k in spec["keep"]}
        obj["required"] = [r for r in obj.get("required", []) if r in spec["keep"]]
    for path in spec.get("harness_owned") or []:
        _drop_schema_path(s, path)
    return s


def project_instance(instance, spec: dict):
    """The model's part of an archival instance (for the example round trip); a list for pointer-into-array specs."""
    x = copy.deepcopy(instance)
    ptr = spec.get("pointer") or ""
    if ptr == "/properties/votes/items":
        items = x.get("votes") or []
    elif ptr == "/properties/interpretation/anyOf/0":
        items = [x.get("interpretation")] if isinstance(x.get("interpretation"), dict) else []
    else:
        items = [x]
    out = []
    for it in items:
        if spec.get("keep") is not None:
            it = {k: v for k, v in it.items() if k in spec["keep"]}
        for path in spec.get("harness_owned") or []:
            _drop_instance_path(it, path.split("."))
        out.append(it)
    return out


def _drop_instance_path(node, parts):
    if not isinstance(node, dict) or not parts:
        return
    part = parts[0]
    arr = part.endswith("[]")
    name = part[:-2] if arr else part
    if len(parts) == 1 and not arr:
        node.pop(name, None)
        return
    child = node.get(name)
    for c in (child if arr and isinstance(child, list) else [child]):
        _drop_instance_path(c, parts[1:])


def owned_paths_present(degraded: dict, spec: dict) -> list[str]:
    """Harness-owned paths that are still in the degraded schema (must be [])."""
    out = []
    for path in spec.get("harness_owned") or []:
        node = degraded
        try:
            for i, part in enumerate(path.split(".")):
                arr = part.endswith("[]")
                name = part[:-2] if arr else part
                props = _object_node(node).get("properties") or {}
                if name not in props:
                    raise KeyError(name)
                node = _array_items(props[name]) if arr else props[name]
            out.append(path)
        except (KeyError, DegradeError):
            continue
    return out


# ---------------------------------------------------------------- degrade
def _types(node: dict) -> list:
    t = node.get("type")
    return t if isinstance(t, list) else [t] if t is not None else []


def _is_object(node: dict) -> bool:
    return "object" in _types(node) or ("properties" in node and not node.get("anyOf"))


def nullable(node: dict) -> dict:
    """The same schema, also accepting null."""
    node = copy.deepcopy(node)
    if "type" in node:
        ts = _types(node)
        if "null" not in ts:
            node["type"] = ts + ["null"]
        if "enum" in node and None not in node["enum"]:
            node["enum"] = list(node["enum"]) + [None]
        return node
    if "anyOf" in node:
        if not any(isinstance(a, dict) and a.get("type") == "null" for a in node["anyOf"]):
            node["anyOf"] = list(node["anyOf"]) + [{"type": "null"}]
        return node
    if "enum" in node:
        if None not in node["enum"]:
            node["enum"] = list(node["enum"]) + [None]
        return node
    return {"anyOf": [node, {"type": "null"}]}


def degrade_for_llm(schema: dict, schemas: dict | None = None) -> dict:
    """Reduce a (projected) schema to the cross-vendor subset; raises DegradeError on constructs it cannot keep."""
    s = resolve_refs(schema, schemas)

    def walk(node, path):
        if isinstance(node, list):
            return [walk(v, f"{path}[{i}]") for i, v in enumerate(node)]
        if not isinstance(node, dict):
            return node
        bad = sorted(REJECTED & set(node))
        if bad:
            raise DegradeError(f"{path or '/'}: {bad} is outside the LLM subset (change the schema or remove it in the projection)")
        if _is_object(node):
            if not isinstance(node.get("properties"), dict):
                raise DegradeError(f"{path or '/'}: free-form object (no properties): remove it in the projection or give it properties")
            ap = node.get("additionalProperties", False)
            if ap is not False:
                raise DegradeError(f"{path or '/'}: additionalProperties {ap!r} (free-form): the LLM subset needs false")
        out = {}
        for k, v in node.items():
            if k in STRIPPED or k in ("$schema", "$id", "$defs"):
                continue
            if k == "const":
                out["enum"] = [v]
            elif k == "properties":
                out[k] = {pk: walk(pv, f"{path}/properties/{pk}") for pk, pv in v.items()}
            else:
                out[k] = walk(v, f"{path}/{k}")
        if _is_object(node):
            req = set(node.get("required") or [])
            out["properties"] = {pk: (pv if pk in req else nullable(pv)) for pk, pv in out["properties"].items()}
            out["additionalProperties"] = False
            out["required"] = list(out["properties"])
        if "minItems" in out:
            out["minItems"] = min(out["minItems"], 1)
        return out

    return walk(s, "")


def find_forbidden(node, path="") -> list[str]:
    hits = []
    if isinstance(node, dict):
        for k, v in node.items():
            if k in FORBIDDEN_FOR_LLM:
                hits.append(f"{path}/{k}")
            if k == "minItems" and isinstance(v, int) and v > 1:
                hits.append(f"{path}/minItems={v}")
            if k == "properties" and isinstance(v, dict):
                for pk, pv in v.items():
                    hits += find_forbidden(pv, f"{path}/properties/{pk}")
            else:
                hits += find_forbidden(v, f"{path}/{k}")
        if _is_object(node):
            if not isinstance(node.get("properties"), dict):
                hits.append(f"{path}: free-form object")
            elif node.get("additionalProperties") is not False:
                hits.append(f"{path}: additionalProperties must be false")
            elif set(node.get("required", [])) != set(node["properties"]):
                hits.append(f"{path}: all properties must be required")
    elif isinstance(node, list):
        for i, v in enumerate(node):
            hits += find_forbidden(v, f"{path}[{i}]")
    return hits


def llm_schema(name: str, schemas: dict) -> dict:
    """The degraded LLM schema of an LLM_OUTPUTS entry."""
    spec = LLM_OUTPUTS[name]
    return degrade_for_llm(project(schemas[spec["schema"]], spec, schemas), schemas)


__all__ = ["LLM_OUTPUTS", "FORBIDDEN_FOR_LLM", "STRIPPED", "REWRITTEN", "REJECTED", "DegradeError", "resolve_refs", "project",
           "project_instance", "degrade_for_llm", "find_forbidden", "owned_paths_present", "llm_schema", "nullable"]
