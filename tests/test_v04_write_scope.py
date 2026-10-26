# SPDX-License-Identifier: Apache-2.0
"""v0.4 write scope, the remaining review items (docs/04 §5, docs/08 §11.7):

- object_refs bind writes whose path has no variable segment (Server Actions, GraphQL mutations, PostgREST);
- state_changing_reads (side-effecting GET) are writes; read_only_endpoints (POST RPC reads) are reads;
- create-only endpoints with uncontained external / llm_tools side effects are >= S2;
- the Scope Proxy binds body ids to the resolved refs (body_id_problem) and strips method overrides;
- the ROE signs the seed manifest hash (E-ROE-SEED-MANIFEST); W0 side-effecting GETs must be declared.
"""
import copy

import pytest

from conftest import codes, doc
from vchlib import safety
from vchlib.checks import run_all

TC = "testcase.bola-list.example.json"
TC_LLM = "testcase.llm.example.json"
API = "tgt-staging-api"


def errors(b, code):
    return [i for i in run_all(b).errors if i.code == code]


def req(method, path, refs=(), target=API, step=None):
    return {"target_id": target, "method": method, "path": path, "step_id": step, "graphql_operation": None,
            "object_refs": list(refs)}


def level(b, reqs, manifest=None):
    tc = copy.deepcopy(doc(b, TC).data)
    tc["request_allowlist"] = reqs
    man = manifest if manifest is not None else doc(b, "seed-manifest.yaml").data
    return safety.compute_safety_class(tc, doc(b, "roe.yaml").data, doc(b, "tools.yaml").data, man)


def manifest(b):
    return copy.deepcopy(doc(b, "seed-manifest.yaml").data)


# ================================================================ object_refs
@pytest.mark.parametrize("path", ["/dashboard/invoices", "/rest/v1/invoices"])   # Server Action page; PostgREST table
def test_pathless_write_is_in_scope_with_a_declared_seed_ref(b, path):
    man = manifest(b)
    man["seeds"]["tenant_a_invoice"]["path_templates"].append(path)
    lv, trace = level(b, [req("POST", path, ["{seed:tenant_a_invoice}"])], man)
    assert lv == "S1", trace


def test_pathless_write_without_refs_is_s3(b):
    assert level(b, [req("POST", "/dashboard/invoices")])[0] == "S3"


def test_seed_ref_not_declared_for_the_path_is_s3(b):
    lv, trace = level(b, [req("POST", "/dashboard/invoices", ["{seed:tenant_a_invoice}"])])
    assert lv == "S3" and "not declared for" in trace[0]


def test_unknown_or_malformed_refs_are_s3(b):
    assert level(b, [req("PATCH", "/rest/v1/invoices", ["{seed:nope}"])])[0] == "S3"
    assert level(b, [req("PATCH", "/rest/v1/invoices", ["{id}"])])[0] == "S3"


def test_created_ref_must_be_an_earlier_create(b):
    reqs = copy.deepcopy(doc(b, TC_LLM).data["request_allowlist"])
    # review r7 1.4: a {created:} object ref is bound to its create's path_templates, so the write stays on that resource
    reqs.append(req("POST", "/api/chat/sessions/{created:open_session}/messages", ["{created:open_session}"], target="tgt-staging-app"))
    tc = copy.deepcopy(doc(b, TC_LLM).data)
    tc["request_allowlist"] = reqs
    roe, tools = doc(b, "roe.yaml").data, doc(b, "tools.yaml").data
    assert safety.compute_safety_class(tc, roe, tools, doc(b, "seed-manifest.yaml").data)[0] == "S1"
    tc["request_allowlist"] = [reqs[-1]] + reqs[:-1]                      # used before the create
    assert safety.compute_safety_class(tc, roe, tools, doc(b, "seed-manifest.yaml").data)[0] == "S3"


# ================================================================ side-effecting GET, read-only POST
def test_state_changing_get_is_a_write(b):
    man = manifest(b)
    man["state_changing_reads"] = [{"target_id": API, "method": "GET", "path_template": "/api/cron/run"}]
    assert level(b, [req("GET", "/api/cron/run")])[0] == "S0"           # undeclared: classified as a read
    lv, trace = level(b, [req("GET", "/api/cron/run")], man)
    assert lv == "S3" and "non-seed object" in trace[0]


def test_read_only_post_is_a_read(b):
    man = manifest(b)
    assert level(b, [req("POST", "/rpc/search_invoices")], man)[0] == "S3"
    man["read_only_endpoints"] = [{"target_id": API, "method": "POST", "path_template": "/rpc/search_invoices"}]
    lv, trace = level(b, [req("POST", "/rpc/search_invoices")], man)
    assert lv == "S1" and "state-changing method -> >=S1" in trace


# ================================================================ invisible side effects
@pytest.mark.parametrize("effects, contained, want", [("llm_tools", True, "S1"), ("llm_tools", False, "S2"),
                                                     ("external", False, "S2"), ("none", False, "S1")])
def test_create_only_side_effects(b, effects, contained, want):
    man = manifest(b)
    man["create_only_endpoints"][1].update(side_effects=effects, contained=contained)
    tc = doc(b, TC_LLM).data
    lv, trace = safety.compute_safety_class(tc, doc(b, "roe.yaml").data, doc(b, "tools.yaml").data, man)
    assert lv == want, trace


# ================================================================ Scope Proxy reference rules
def test_body_ids_must_be_bound():
    ok = {"inv-a-0001", "42"}
    assert safety.body_id_problem({"invoice_id": "inv-a-0001", "amount": 5}, ok) is None
    assert safety.body_id_problem({"data": [{"orderId": 42}]}, ok) is None
    assert "invoice_id" in safety.body_id_problem({"invoice_id": "inv-b-0001"}, ok)
    assert safety.body_id_problem({"filter": {"user": {"id": "u-9"}}}, ok) is not None


def test_method_override_names():
    assert "x-http-method-override" in safety.METHOD_OVERRIDE_HEADERS and "_method" in safety.METHOD_OVERRIDE_PARAMS


# ================================================================ validator
def test_examples_pass(b):
    found = codes(b)
    assert "E-ROE-SEED-MANIFEST" not in found and "E-SEED-SIDE-EFFECT" not in found


def test_changed_seed_manifest_breaks_the_roe_signature_hash(b):
    doc(b, "seed-manifest.yaml").data["create_only_endpoints"][1]["contained"] = False
    assert errors(b, "E-ROE-SEED-MANIFEST")


def test_side_effecting_get_from_w0_must_be_declared(b):
    ep = next(e for e in doc(b, "inventory.example.json").data["endpoints"] if e["method"] == "GET")
    ep["writes"] = True
    assert errors(b, "E-SEED-SIDE-EFFECT")
