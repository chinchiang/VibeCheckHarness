"""Derive the LLM-facing output schema from an archival schema (docs/03 §8.3)."""
from __future__ import annotations

import copy

# Keywords outside the common subset of Claude / OpenAI strict structured outputs
# (docs/03 §8.3). `pattern`, `format`, `const` and `contains` are also stripped
# because their support was not verified for every provider; the archival schema
# re-checks them after the LLM answers.
FORBIDDEN_FOR_LLM = {
    "minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum", "minLength",
    "maxLength", "multipleOf", "pattern", "format", "$ref", "$defs", "contains",
}


def inline_refs(node, defs):
    if isinstance(node, dict):
        if "$ref" in node and node["$ref"].startswith("#/$defs/"):
            return inline_refs(copy.deepcopy(defs[node["$ref"].split("/")[-1]]), defs)
        return {k: inline_refs(v, defs) for k, v in node.items() if k != "$defs"}
    if isinstance(node, list):
        return [inline_refs(v, defs) for v in node]
    return node


def degrade_for_llm(schema: dict) -> dict:
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
