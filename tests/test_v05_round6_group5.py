# SPDX-License-Identifier: Apache-2.0
"""v0.5 round 6, group 5 (docs/evidence/review-2026-10-25.md §4.2 C-1..C-13, §4.3): cross-document consistency.
These keep the fixed contradictions from drifting back:

- C-1: run.schema enums hold every skip reason / gap kind the docs use;
- C-9: gate_load_warning is an audit event type;
- C-7: the Z2 output cap is 200 MiB in toolkit.yaml and in the docs;
- licenses: test libraries are not W1 scanners;
- crosswalk: the CWE of T-031's clusters is mapped from its taxonomy;
- the shared-platform list in docs/02 and docs/08 names every safety.SHARED_PLATFORM_SUFFIXES entry;
- C-2 / C-3 / C-4 / C-12: the graph has the verifier node, nodes do not import graph, round-trips use
  exclude_unset, whoami has one signature.
"""
import json
import pathlib
import re

import pytest

from conftest import doc
from vchlib import safety

ROOT = pathlib.Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"


def text(name):
    return (DOCS / name).read_text(encoding="utf-8")


def schema(name):
    return json.loads((DOCS / "schemas" / name).read_text(encoding="utf-8"))


# ================================================================ C-1, C-9
def test_run_enums_cover_the_documented_values():
    s = schema("run.schema.json")
    kinds = set(s["properties"]["gaps"]["items"]["properties"]["kind"]["enum"])
    skips = set(s["$defs"]["job"]["properties"]["skip_reason"]["anyOf"][0]["enum"])
    assert {"build_mismatch", "teardown_failed", "no_lockfile"} <= kinds
    assert {"build_mismatch", "session_unavailable", "login_unavailable", "seed_setup_failed"} <= skips


def test_gate_load_warning_is_an_audit_event():
    s = schema("audit-event.schema.json")
    assert "gate_load_warning" in s["properties"]["event_type"]["enum"]
    assert "`gate_load_warning`" in text("03-system-architecture.md")


# ================================================================ C-7
def test_z2_output_cap_agrees(b):
    tk = doc(b, "toolkit.yaml").data
    caps = [v["max_output_mib"] for v in tk.values() if isinstance(v, dict) and "max_output_mib" in v]
    assert caps == [200]
    assert "200 MiB" in text("03-system-architecture.md") and "200 MiB" in text("08-implementation-spec.md")


# ================================================================ licenses, crosswalk
@pytest.mark.parametrize("component", ["Hypothesis", "fast-check"])
def test_test_libraries_are_not_w1_tools(b, component):
    c = next(x for x in doc(b, "licenses.yaml").data["components"] if x["component"] == component)
    assert c["usage"] == "w4_test"


def test_t031_cwe_is_mapped(b):
    links = doc(b, "crosswalk.yaml").data["links"]
    tax = {(t["scheme"], t["id"]) for t in doc(b, "threat.t-031.example.json").data["taxonomy"]}
    hits = {(l["from_scheme"], l["from_id"]) for l in links if l["target_id"] == "CWE-862"}
    assert tax & hits
    assert any(l["from_scheme"] == "owasp-asi@2026" for l in links)


# ================================================================ shared platforms
@pytest.mark.parametrize("name", ["02-methodology.md", "08-implementation-spec.md"])
def test_shared_platform_lists_name_every_suffix(name):
    body = text(name)
    missing = [s for s in safety.SHARED_PLATFORM_SUFFIXES if f"`{s}`" not in body]
    assert not missing, missing


# ================================================================ C-2, C-3, C-4, C-12
def test_w3_has_a_verifier_node():
    a = text("03-system-architecture.md")
    assert "W3_verify_fanout --> W3_verify" in a and "W3_verify --> W3_adjudicate" in a
    assert "`W3_verify`" in text("07-roadmap.md")


def test_nodes_do_not_import_graph():
    b = text("08-implementation-spec.md")
    assert re.search(r"^L3 .*\blgapi\b", b, re.M)
    assert "只有 `lgapi` 可以 import `langgraph`" in b


def test_round_trip_keeps_omitted_fields():
    b = text("08-implementation-spec.md")
    assert 'exclude_unset=True' in b and 'model_dump(mode="json", exclude_none=False)' not in b


def test_whoami_has_one_signature():
    sigs = {m.group(1).strip() for name in ("03-system-architecture.md", "08-implementation-spec.md")
            for m in re.finditer(r"def whoami\(self, ([^)]*)\)", text(name))}
    assert sigs == {"run_id: str, role: str, batch_id: str"}
