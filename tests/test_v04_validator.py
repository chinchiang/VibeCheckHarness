# SPDX-License-Identifier: Apache-2.0
"""v0.4 validator bypasses closed (docs/evidence/review v0.3 design review, first priority). Each has a
positive case (the example bundle still passes) and a negative case (the bypass is now an error):

- D1 E-SARIF-REF binds a SARIF result to the cluster key (file, symbol, CWE bucket); black-box clusters take none;
- D2 self-hosted (Z4) models are recognised by an exact toolkit.yaml host list, not a "z4-" prefix;
- D3 a CMD-1 plan covers every slice of the run with reviewers of >= min(2, eligible) families;
- D4 a code snippet needs content of its own and must be in the finding's slice;
- B1 graphql_operation counts as a read only on a ROE-declared GraphQL path.
"""
import copy

import pytest

from conftest import codes, doc
from vchlib import evidence, safety
from vchlib.checks import Ctx, resolved_sarif_refs, self_hosted

AUDIT = "audit-event.run-2026-09-23-001.example.jsonl"
K011, K014, K201 = "cluster.k-011.example.json", "cluster.k-014.example.json", "cluster.k-201.example.json"
PLAN, SLICE = "commander-plan.example.json", "slice.example.json"
F017 = "finding.example.json"
TC_LIST = "testcase.bola-list.example.json"


def errors(b, code):
    from vchlib.checks import run_all
    return [i for i in run_all(b).errors if i.code == code]


# ================================================================ D1 SARIF binding
def test_sarif_ref_resolves_on_its_own_cluster(b):
    k = doc(b, K014).data
    assert resolved_sarif_refs(Ctx(b), k) == k["sarif_refs"]
    assert not errors(b, "E-SARIF-REF")


@pytest.mark.parametrize("target", [K011, K201])
def test_sarif_ref_cannot_be_borrowed_by_another_cluster(b, target):
    ref = doc(b, K014).data["sarif_refs"][0]
    doc(b, target).data["sarif_refs"] = [ref]
    found = errors(b, "E-SARIF-REF")
    assert found and any(doc(b, target).data["cluster_id"] in i.msg for i in found)
    assert resolved_sarif_refs(Ctx(b), doc(b, target).data) == []


@pytest.mark.parametrize("field, value", [("file", "routes/other.ts"), ("symbol", "routes/invoices.ts::listInvoices"),
                                          ("cwe_bucket", "injection"), ("file", None)])
def test_sarif_entry_location_must_equal_the_cluster_key(b, field, value):
    for e in doc(b, AUDIT).data:
        for r in (e.get("payload") or {}).get("sarif_results") or []:
            r[field] = value
    assert errors(b, "E-SARIF-REF")


# ================================================================ D2 Z4 hosts
def test_self_hosted_needs_an_exact_toolkit_host(b):
    c = Ctx(b)
    assert self_hosted(c.model("nemotron_self"), c)
    for base in ("https://z4-evil.attacker.example/v1", "http://z4-nemotron.attacker.example:8000/v1", "http://z4-:8000"):
        assert not self_hosted({"api_base": base}, c), base
    assert not errors(b, "E-ENG-PROVIDER")


def test_prefix_spoofed_model_cannot_take_c_data(b):
    doc(b, "models.yaml").data["nemotron_self"]["api_base"] = "https://z4-evil.attacker.example/v1"
    assert any("nemotron_self" in i.msg for i in errors(b, "E-ENG-PROVIDER"))


def test_without_z4_hosts_nothing_is_self_hosted(b):
    del doc(b, "toolkit.yaml").data["z4_model_hosts"]
    assert any("nemotron_self" in i.msg for i in errors(b, "E-ENG-PROVIDER"))


# ================================================================ D3 plan coverage
def test_example_plan_covers_every_slice_with_three_families(b):
    assert not errors(b, "E-PLAN-COVERAGE") and not errors(b, "E-PLAN-FAMILIES")


def test_one_family_per_slice_is_rejected(b):
    doc(b, PLAN).data["slices"][0]["agents"] = ["rev_a"]
    assert errors(b, "E-PLAN-FAMILIES")
    assert "E-PLAN-FACETS" not in codes(b)          # v0.3 only checked facets, so this plan passed


def test_dropped_slice_is_rejected(b):
    doc(b, PLAN).data["slices"] = []
    assert errors(b, "E-PLAN-COVERAGE")


def test_family_floor_follows_the_slices_excluded_models(b):
    """A slice that only one family's reviewers can take needs one family, not two."""
    doc(b, PLAN).data["slices"][0]["agents"] = ["rev_a"]
    doc(b, SLICE).data["excluded_models"] += [{"model_key": "gpt_flagship", "reason": "context"},
                                              {"model_key": "nemotron_self", "reason": "context"}]
    assert not errors(b, "E-PLAN-FAMILIES")


# ================================================================ D4 snippet content and slice
@pytest.mark.parametrize("snippet", ["}", ");", "  }\n  );  ", "if (a) { b }"])
def test_trivial_snippets_are_not_grounded(snippet):
    text = "function f() {\n  if (a) { b }\n}\n);\n"
    assert evidence.snippet_content_problem(snippet) is not None
    assert evidence.match_snippet(text, {"snippet": snippet, "line_start": 1, "line_end": 1})[0] == "NOT_FOUND"


def test_real_snippet_still_matches():
    text = "x\nconst invoice = await db.invoice.findUnique({ where: { id } });\ny\n"
    ev = {"snippet": "const invoice = await db.invoice.findUnique({ where: { id } });", "line_start": 2, "line_end": 2}
    assert evidence.snippet_content_problem(ev["snippet"]) is None
    assert evidence.match_snippet(text, ev)[0] == "MATCHED"


def test_trivial_snippet_in_a_finding_is_an_error(b):
    doc(b, F017).data["evidence"][0]["snippet"] = "}"
    assert any("non-whitespace" in i.msg for i in errors(b, "E-FINDING-EVIDENCE"))


def test_snippet_file_must_be_in_the_slice(b):
    doc(b, F017).data["evidence"][0]["file"] = "routes/not-in-slice.ts"
    assert any("not a file of the finding's slice" in i.msg for i in errors(b, "E-FINDING-EVIDENCE"))


# ================================================================ B1 GraphQL label
def req(method, path, op):
    return {"target_id": "tgt-staging-api", "method": method, "path": path, "step_id": None, "graphql_operation": op}


def level(b, tc):
    return safety.compute_safety_class(tc, doc(b, "roe.yaml").data, doc(b, "tools.yaml").data, doc(b, "seed-manifest.yaml").data)


@pytest.mark.parametrize("op", ["query", "introspection"])
def test_graphql_read_label_on_an_undeclared_path_is_s3(b, op):
    tc = copy.deepcopy(doc(b, TC_LIST).data)
    tc["request_allowlist"] = [req("POST", "/api/admin/purge", op)]
    lv, trace = level(b, tc)
    assert lv == "S3" and "does not declare as GraphQL" in trace[0]


def test_graphql_read_label_with_a_non_graphql_method_is_s3(b):
    for t in doc(b, "roe.yaml").data["targets"]:
        t["graphql_paths"] = ["/graphql"]
    tc = copy.deepcopy(doc(b, TC_LIST).data)
    tc["request_allowlist"] = [req("DELETE", "/graphql", "query")]
    assert level(b, tc)[0] == "S3"
    tc["request_allowlist"] = [req("POST", "/graphql", "query")]
    assert level(b, tc)[0] == "S1"


def test_graphql_label_bypass_is_a_validator_error(b):
    doc(b, TC_LIST).data["request_allowlist"].append(req("POST", "/api/admin/purge", "query"))
    assert {"E-TC-MUTATION-SCOPE", "E-TC-ADMISSIBLE"} <= codes(b)
