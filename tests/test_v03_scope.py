# SPDX-License-Identifier: Apache-2.0
"""v0.3 scope and safety: seed-bound mutations (B6), seed path binding (D11), seed lifecycle (E8), build identity (B7),
path / host / URL hardening (D1-D3), request log (D16). Positive and negative cases; bugs D1-D3/D11 are regressions."""
import copy

import pytest

from conftest import codes, doc
from vchlib import safety
from vchlib.checks import run_all

TC_IDOR, TC_LLM, TC_LIST = "testcase.idor.example.json", "testcase.llm.example.json", "testcase.bola-list.example.json"


def ctx(b):
    return doc(b, "roe.yaml").data, doc(b, "tools.yaml").data, doc(b, "seed-manifest.yaml").data


def level(b, tc):
    roe, tools, man = ctx(b)
    return safety.compute_safety_class(tc, roe, tools, man)


def req(target, method, path, step=None, op=None):
    # v0.6 (review r7 3.8): a GraphQL request pins its document
    return {"target_id": target, "method": method, "path": path, "step_id": step, "graphql_operation": op,
            "graphql_document_sha256": "sha256:" + "d" * 64 if op else None}


# ================================================================ B6 mutation scope
def test_examples_are_in_scope(b):
    for s in (TC_IDOR, TC_LLM, TC_LIST, "testcase.zap-active.example.json"):
        assert safety.mutation_scope_problems(doc(b, s).data, doc(b, "seed-manifest.yaml").data) == [], s
    assert "E-TC-MUTATION-SCOPE" not in codes(b)


def test_patch_on_a_non_seed_id_is_s3(b):
    tc = copy.deepcopy(doc(b, TC_IDOR).data)
    tc["request_allowlist"].append(req("tgt-staging-api", "PATCH", "/api/invoices/{id}"))
    lv, trace = level(b, tc)
    assert lv == "S3" and trace[0].startswith(safety.MUTATION_SCOPE)
    doc(b, TC_IDOR).data["request_allowlist"].append(req("tgt-staging-api", "PATCH", "/api/invoices/{id}"))
    got = codes(b)
    assert {"E-TC-MUTATION-SCOPE", "E-TC-ADMISSIBLE"} <= got


def test_collection_level_post_is_s3(b):
    tc = copy.deepcopy(doc(b, TC_LLM).data)
    tc["request_allowlist"].insert(0, req("tgt-staging-app", "POST", "/api/uploads"))
    assert level(b, tc)[0] == "S3"


def test_post_to_create_only_endpoint_is_allowed(b):
    lv, trace = level(b, doc(b, TC_LLM).data)            # POST /api/chat/sessions is a create_only_endpoints entry
    assert lv == "S1" and "state-changing method -> >=S1" in trace


def test_put_on_created_object_is_allowed(b):
    tc = copy.deepcopy(doc(b, TC_LLM).data)
    tc["request_allowlist"].append(req("tgt-staging-app", "PUT", "/api/chat/sessions/{created:open_session}"))
    assert level(b, tc)[0] == "S1"
    tc["request_allowlist"].append(req("tgt-staging-app", "DELETE", "/api/chat/sessions/{created:open_session}"))
    assert level(b, tc)[0] == "S1"


def test_created_placeholder_must_name_an_earlier_create(b):
    tc = copy.deepcopy(doc(b, TC_LLM).data)
    tc["request_allowlist"][1]["path"] = "/api/chat/sessions/{created:nope}/messages"
    probs = safety.mutation_scope_problems(tc, doc(b, "seed-manifest.yaml").data)
    assert probs and "not an earlier create request" in probs[0]
    tc = copy.deepcopy(doc(b, TC_LLM).data)
    tc["request_allowlist"].insert(0, tc["request_allowlist"].pop(1))     # use before the create
    assert level(b, tc)[0] == "S3"


def test_unbound_variable_in_a_mutation_is_s3(b):
    tc = copy.deepcopy(doc(b, TC_LLM).data)
    tc["request_allowlist"][1]["path"] = "/api/chat/sessions/{session}/messages"     # the v0.2 form
    assert level(b, tc)[0] == "S3"


def declare_graphql(b, target="tgt-staging-api", path="/graphql"):
    """v0.4: GraphQL reads need the path declared in the signed ROE (targets[].graphql_paths)."""
    for t in doc(b, "roe.yaml").data["targets"]:
        if t["id"] == target:
            t["graphql_paths"] = [path]


def test_graphql_introspection_over_post_is_s1(b):
    """A GraphQL introspection (read) sent as POST to a ROE-declared GraphQL path is not a mutation:
    S1 via the POST floor, not S3."""
    declare_graphql(b)
    tc = copy.deepcopy(doc(b, TC_LIST).data)
    tc["request_allowlist"] = [req("tgt-staging-api", "POST", "/graphql", op="introspection")]
    lv, trace = level(b, tc)
    assert lv == "S1" and "state-changing method -> >=S1" in trace
    tc["request_allowlist"] = [req("tgt-staging-api", "POST", "/graphql", op="query")]
    assert level(b, tc)[0] == "S1"
    tc["request_allowlist"] = [req("tgt-staging-api", "POST", "/graphql", op="mutation")]       # not seed-bound
    assert level(b, tc)[0] == "S3"
    tc["request_allowlist"] = [req("tgt-staging-api", "POST", "/graphql")]                      # unknown operation: fail closed
    assert level(b, tc)[0] == "S3"


# ================================================================ D11 seed path binding (regression)
def test_delete_with_seed_of_another_resource_is_s3(b):
    """v0.2: DELETE /api/users/{seed:tenant_b_invoice} (an invoices seed) was S1."""
    tc = copy.deepcopy(doc(b, TC_IDOR).data)
    next(r for r in tc["request_allowlist"] if r["method"] == "DELETE")["path"] = "/api/users/{seed:tenant_b_invoice}"
    lv, trace = level(b, tc)
    assert lv == "S3" and "not declared for /api/users/{seed:tenant_b_invoice}" in trace[0]


def test_seed_on_a_read_is_bound_too(b):
    tc = copy.deepcopy(doc(b, TC_IDOR).data)
    tc["request_allowlist"][0]["path"] = "/api/orders/{seed:tenant_a_invoice}"
    assert level(b, tc)[0] == "S3"
    doc(b, TC_IDOR).data["request_allowlist"][0]["path"] = "/api/orders/{seed:tenant_a_invoice}"
    assert "E-TC-MUTATION-SCOPE" in codes(b)


def test_seed_path_template_positive(b):
    man = doc(b, "seed-manifest.yaml").data
    assert safety.seed_path_problem("/api/invoices/{seed:tenant_b_invoice}", man) is None
    assert safety.seed_path_problem("/api/invoices/{seed:tenant_b_invoice}/lines", man) is not None


# ================================================================ E8 seed lifecycle
def test_seed_namespace_must_be_run_scoped(b):
    doc(b, "seed-manifest.yaml").data["namespace"] = "vc-shared-"
    assert "E-SCHEMA" in codes(b)


def test_seeding_job_is_s1_and_idempotent(b):
    doc(b, "seed-manifest.yaml").data["seeding"]["idempotent"] = False
    assert "E-SCHEMA" in codes(b)


def test_create_only_endpoint_must_be_an_http_target(b):
    doc(b, "seed-manifest.yaml").data["create_only_endpoints"][0]["target_id"] = "tgt-staging-db"
    assert "E-SEED-MANIFEST" in codes(b)


# ================================================================ D1 path exclusions (regression)
@pytest.mark.parametrize("path", ["/Admin/billing/x", "/admin;jsessionid=1/billing/x", "/admin/%62illing/x", "/ADMIN/BILLING"])
def test_excluded_path_variants_are_s3(b, path):
    tc = copy.deepcopy(doc(b, TC_LIST).data)
    tc["request_allowlist"] = [req("tgt-staging-api", "GET", path)]
    assert level(b, tc)[0] == "S3"


def test_path_normalisation():
    assert safety.normalize_for_match("/admin;x=1/./billing//x/../y") == "/admin/billing/y"
    assert safety.path_may_match("/Admin/billing/x", "/admin/billing/*")
    assert not safety.path_may_match("/api/invoices", "/admin/billing/*")


# ================================================================ D2 wildcard hosts (regression)
def test_wildcard_host_exclusion(b):
    """v0.2: exclusions.hosts ['*.staging.example.com'] matched nothing."""
    roe = doc(b, "roe.yaml").data
    roe["exclusions"]["hosts"] = ["*.staging.example.com"]
    assert level(b, doc(b, TC_LIST).data) == ("S3", ["tgt-staging-api: excluded host"])
    got = codes(b)
    assert "E-ROE-TARGETS" in got and "E-ROE-DB-SCOPE" in got


def test_wildcard_host_semantics():
    assert safety.host_matches("api.staging.example.com", "*.example.com")
    assert safety.host_matches("API.Staging.Example.com.", "*.EXAMPLE.com")
    assert not safety.host_matches("example.com", "*.example.com")          # not the apex
    assert not safety.host_matches("evilexample.com", "*.example.com")
    assert safety.host_matches("example.com", "example.com")


def test_host_exclusion_pattern(b):
    doc(b, "roe.yaml").data["exclusions"]["hosts"] = ["https://legacy.example.com/"]
    assert "E-SCHEMA" in codes(b)


# ================================================================ D3 URLs (regression)
def test_non_https_base_url(b):
    """v0.2: base_url ftp://... passed."""
    roe = doc(b, "roe.yaml").data
    next(t for t in roe["targets"] if t["id"] == "tgt-staging-api")["base_url"] = "ftp://api.staging.example.com"
    assert "E-ROE-URL" in codes(b)
    assert level(b, doc(b, TC_LIST).data) == ("S3", ["tgt-staging-api: unparseable target host"])


def test_health_url_must_be_a_uri(b):
    """v0.2: health_url 'this is not a uri' passed (the uri format was never checked)."""
    doc(b, "roe.yaml").data["stop_conditions"]["health_url"] = "this is not a uri"
    got = codes(b)
    assert "E-SCHEMA" in got and "E-ROE-URL" in got


@pytest.mark.parametrize("url,ok", [("http://localhost:3000", True), ("http://127.0.0.1:8080", True), ("http://[::1]:8080", True),
                                    ("http://api.staging.example.com", False), ("https://api.staging.example.com", True)])
def test_http_only_for_local_targets(b, url, ok):
    roe = doc(b, "roe.yaml").data
    next(t for t in roe["targets"] if t["id"] == "tgt-staging-api")["base_url"] = url
    assert ("E-ROE-URL" not in codes(b)) is ok


def test_unknown_format_fails_at_start_up(b):
    b.schemas["testcase"]["properties"]["testcase_id"]["format"] = "email"
    assert "E-SCHEMA-FORMAT" in codes(b)


# ================================================================ B7 build identity
TR = "testresult.example.json"


def test_observed_build_must_be_the_run_commit(b):
    doc(b, TR).data["observed_build_id"] = "0123456789ab"
    assert "E-RESULT-BUILD" in codes(b)


@pytest.mark.parametrize("obs,ok", [("4f2a9c1e8b3d", True), ("4f2a9c1e8b3d5f7a9c1e2d4b6f8a0c2e4d6b8f0a", True), ("4f2a9c1", False), (None, False)])
def test_build_prefix_rule(b, obs, ok):
    doc(b, TR).data["observed_build_id"] = obs
    assert ("E-RESULT-BUILD" not in codes(b)) is ok


def test_tester_controlled_targets_are_not_build_unverified(b):
    rm = doc(b, "report-manifest.example.json").data
    assert rm["build_unverified_targets"] == []          # tgt-canary is tester_controlled
    rm["build_unverified_targets"] = ["tgt-canary"]
    assert "E-RESULT-BUILD" in codes(b)


def test_unverified_staging_targets_are_listed(b):
    roe = doc(b, "roe.yaml").data
    next(t for t in roe["targets"] if t["id"] == "tgt-canary")["environment"] = "staging"
    assert "E-RESULT-BUILD" in codes(b)                  # now it must be listed
    doc(b, "report-manifest.example.json").data["build_unverified_targets"] = ["tgt-canary"]
    assert "E-RESULT-BUILD" not in codes(b)


def test_build_identity_shape(b):
    roe = doc(b, "roe.yaml").data
    next(t for t in roe["targets"] if t["id"] == "tgt-staging-api")["build_identity"]["header_name"] = None
    assert "E-ROE-TARGETS" in codes(b)


# ================================================================ D16 request log
def test_black_box_result_needs_a_request_log(b):
    doc(b, TR).data["request_log_sha256"] = None
    assert "E-RESULT-REQUEST-LOG" in codes(b)
