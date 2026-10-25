# SPDX-License-Identifier: Apache-2.0
"""v0.3 LLM-facing schemas (C, D7): projection of harness-owned fields, fail-closed degrading, round trip."""
import copy

import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from conftest import ROOT, codes, doc
from vchlib import llm_schema as L
from vchlib.checks import StrictValidator, format_checker


def schemas(b):
    return b.schemas


def archival_validator(b, name):
    reg = Registry().with_resources([(s.get("$id"), Resource.from_contents(s)) for s in b.schemas.values()])
    return StrictValidator(b.schemas[name], registry=reg, format_checker=format_checker())


# ================================================================ degrade rules (pure)
def test_const_becomes_enum_and_type_arrays_survive():
    d = L.degrade_for_llm({"type": "object", "properties": {"a": {"const": "x"}, "b": {"type": ["string", "number", "null"]}},
                           "required": ["a", "b"]})
    assert d["properties"]["a"] == {"enum": ["x"]} and d["properties"]["b"]["type"] == ["string", "number", "null"]
    assert not L.find_forbidden(d)


def test_optional_properties_become_nullable_before_required():
    d = L.degrade_for_llm({"type": "object", "properties": {"a": {"type": "string"}, "b": {"type": "integer", "enum": [2, 3]},
                                                            "c": {"anyOf": [{"type": "string"}]}}, "required": ["a"]})
    assert d["required"] == ["a", "b", "c"] and d["additionalProperties"] is False
    assert d["properties"]["a"] == {"type": "string"}
    assert d["properties"]["b"] == {"type": ["integer", "null"], "enum": [2, 3, None]}
    assert {"type": "null"} in d["properties"]["c"]["anyOf"]


@pytest.mark.parametrize("bad", [
    {"type": "object", "additionalProperties": True},                                     # free-form (tool_binding.params in v0.2)
    {"type": "object", "properties": {"a": {"type": "string"}}, "additionalProperties": {"type": "string"}},
    {"allOf": [{"type": "string"}]}, {"not": {"type": "string"}}, {"if": {"type": "string"}, "then": {}},
    {"type": "object", "properties": {}, "patternProperties": {"^x": {"type": "string"}}}, {"oneOf": [{"type": "string"}]},
])
def test_constructs_outside_the_subset_fail_closed(bad):
    with pytest.raises(L.DegradeError):
        L.degrade_for_llm({"type": "object", "properties": {"p": bad}, "required": ["p"]})


def test_external_ref_is_resolved_or_rejected_never_empty():
    common = {"$defs": {"sha": {"type": "string", "pattern": "^sha256:"}}}
    s = {"type": "object", "properties": {"h": {"$ref": "common.schema.json#/$defs/sha"}}, "required": ["h"]}
    assert L.degrade_for_llm(s, {"common": common})["properties"]["h"] == {"type": "string"}
    with pytest.raises(L.DegradeError, match="external"):
        L.degrade_for_llm(s)                                                # v0.2 silently replaced it by {}


def test_unique_items_is_stripped_and_nullable_objects_are_closed():
    d = L.degrade_for_llm({"type": "object", "required": ["o", "l"], "properties": {
        "o": {"type": ["object", "null"], "properties": {"x": {"type": "string"}}},
        "l": {"type": "array", "uniqueItems": True, "minItems": 3, "items": {"type": "string"}}}})
    assert d["properties"]["o"]["additionalProperties"] is False and d["properties"]["o"]["required"] == ["x"]
    assert "uniqueItems" not in d["properties"]["l"] and d["properties"]["l"]["minItems"] == 1


def test_find_forbidden_catches_what_v02_missed():
    """v0.2: const, allOf, not, if, patternProperties, uniqueItems and open ['object','null'] objects passed find_forbidden."""
    for node in ({"const": 1}, {"allOf": []}, {"not": {}}, {"if": {}}, {"patternProperties": {}}, {"uniqueItems": True},
                 {"type": ["object", "null"], "properties": {"a": {}}, "required": ["a"]}, {"type": "object"}):
        assert L.find_forbidden(node), node


# ================================================================ registry
def test_every_llm_output_is_clean(b):
    assert set(L.LLM_OUTPUTS) == {"finding", "vote", "threat", "testcase", "w4-testcase", "commander-plan", "invariants", "dfd",
                                  "result-interpretation"}
    for name, spec in L.LLM_OUTPUTS.items():
        deg = L.llm_schema(name, schemas(b))
        assert L.find_forbidden(deg) == [], name
        assert L.owned_paths_present(deg, spec) == [], name
        Draft202012Validator.check_schema(deg)


def test_harness_owned_fields_are_not_sent(b):
    f = L.llm_schema("finding", schemas(b))
    assert not {"finding_id", "run_id", "slice_id", "reporter", "status"} & set(f["properties"])
    ev = f["properties"]["evidence"]["items"]["properties"]
    assert "snippet_sha256" not in ev and "match" not in ev and "fact_ref" in ev
    vote = L.llm_schema("vote", schemas(b))
    assert set(vote["properties"]) == {"stance", "rationale", "cited_evidence"}
    tc = L.llm_schema("testcase", schemas(b))
    assert "safety_class_computed" not in tc["properties"] and "params" not in tc["properties"]["tool_binding"]["properties"]
    assert "safety_class_proposed" in tc["properties"]


def test_free_form_params_must_be_projected_away(b, monkeypatch):
    """D7 regression: testcase.tool_binding.params ({type: object, additionalProperties: true}) passed E-LLM-SCHEMA in v0.2."""
    spec = copy.deepcopy(L.LLM_OUTPUTS["testcase"])
    spec["harness_owned"].remove("tool_binding.params")
    monkeypatch.setitem(L.LLM_OUTPUTS, "testcase", spec)
    with pytest.raises(L.DegradeError, match="free-form"):
        L.llm_schema("testcase", schemas(b))
    assert "E-LLM-SCHEMA" in codes(b)


def test_harness_owned_path_must_exist(b, monkeypatch):
    spec = copy.deepcopy(L.LLM_OUTPUTS["finding"])
    spec["harness_owned"].append("evidence[].no_such_field")
    monkeypatch.setitem(L.LLM_OUTPUTS, "finding", spec)
    assert "E-LLM-SCHEMA" in codes(b)


# ================================================================ round trip
def fill(harness, answer):
    """Harness fill: start from the harness-owned values and overlay the LLM answer (objects merged key by key,
    arrays of objects index by index)."""
    if isinstance(harness, dict) and isinstance(answer, dict):
        out = copy.deepcopy(harness)
        for k, v in answer.items():
            out[k] = fill(harness.get(k), v)
        return out
    if isinstance(harness, list) and isinstance(answer, list) and len(harness) == len(answer):
        return [fill(h, a) for h, a in zip(harness, answer)]
    return copy.deepcopy(answer)


@pytest.mark.parametrize("name", sorted(L.LLM_OUTPUTS))
def test_round_trip(b, name):
    """An LLM answer valid under the degraded schema, plus the harness-filled fields, validates under the archival schema."""
    spec = L.LLM_OUTPUTS[name]
    deg = Draft202012Validator(L.llm_schema(name, schemas(b)))
    arch = archival_validator(b, spec["schema"])
    docs = [d for d in b.docs if d.kind == spec["schema"] and isinstance(d.data, dict)]
    assert docs, name
    n = 0
    for d in docs:
        parts = L.project_instance(d.data, spec)
        for part in parts:
            assert not list(deg.iter_errors(part)), (name, d.path)
            n += 1
        # harness fill: the harness-owned fields come from the harness, the rest from the LLM answer
        filled = copy.deepcopy(d.data)
        if spec.get("pointer") == "/properties/votes/items":
            filled["votes"] = [fill(v, part) for v, part in zip(filled.get("votes", []), parts)]
        elif spec.get("pointer") == "/properties/interpretation/anyOf/0":
            if parts:
                filled["interpretation"] = fill(filled["interpretation"], parts[0])
        else:
            filled = fill(filled, parts[0])
        assert filled == d.data                               # the fill reproduces the archival example exactly
        assert not list(arch.iter_errors(filled)), (name, d.path)
    assert n > 0


def test_llm_answer_with_harness_field_is_rejected(b):
    deg = Draft202012Validator(L.llm_schema("finding", schemas(b)))
    part = L.project_instance(doc(b, "finding.example.json").data, L.LLM_OUTPUTS["finding"])[0]
    part["status"] = "VERIFIED_SNIPPET"                       # the model tries to set a harness-owned field
    assert list(deg.iter_errors(part))


def test_readme_lists_the_forbidden_keywords():
    """L-18: docs/schemas/README.md lists exactly the keywords of FORBIDDEN_FOR_LLM (incl. contains, const)."""
    text = (ROOT / "docs" / "schemas" / "README.md").read_text(encoding="utf-8")
    missing = sorted(k for k in L.FORBIDDEN_FOR_LLM if f"`{k}`" not in text)
    assert missing == []
