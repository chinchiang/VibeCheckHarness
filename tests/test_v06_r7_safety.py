# SPDX-License-Identifier: Apache-2.0
"""v0.6 review r7, group 3c (3.8): the safety class sees side effects, replays and GraphQL documents.

- a write to a seed with uncontained side effects is at least S2, like a create-only endpoint; a seed that declares
  nothing is assumed to reach the application's integrations when the ROE lists one that is not disabled;
- the request budget counts the replay jobs (replay_n re-runs of one trial), which max_requests leaves out;
- until the proxy parses GraphQL (BL-35), a GraphQL request is POST only and pins its document hash.
"""
import copy

import pytest

from conftest import doc
from vchlib import safety

IDOR, LIST, LLM = "testcase.idor.example.json", "testcase.bola-list.example.json", "testcase.llm.example.json"
DOC = "sha256:" + "d" * 64


def level(b, tc):
    return safety.compute_safety_class(tc, doc(b, "roe.yaml").data, doc(b, "tools.yaml").data, doc(b, "seed-manifest.yaml").data)


def test_the_examples_keep_their_class(b):
    for name in (IDOR, LIST, LLM, "testcase.zap-active.example.json"):
        tc = doc(b, name).data
        assert level(b, tc)[0] == tc["safety_class_computed"], name


# ================================================================ seed side effects
def test_a_seed_with_external_side_effects_is_s2(b):
    """TC-012-01 PUTs tenant_b_invoice; if updating an invoice mails the customer, that is S2 (G5 + snapshot)."""
    doc(b, "seed-manifest.yaml").data["seeds"]["tenant_b_invoice"].update(side_effects="external", contained=False)
    lv, trace = level(b, copy.deepcopy(doc(b, IDOR).data))
    assert lv == "S2" and any("tenant_b_invoice" in t for t in trace)


def test_contained_side_effects_stay_s1(b):
    doc(b, "seed-manifest.yaml").data["seeds"]["tenant_b_invoice"].update(side_effects="external", contained=True)
    assert level(b, copy.deepcopy(doc(b, IDOR).data))[0] == "S1"


def test_an_undeclared_seed_fails_closed_while_an_integration_is_live(b):
    seed = doc(b, "seed-manifest.yaml").data["seeds"]["tenant_b_invoice"]
    del seed["side_effects"], seed["contained"]
    assert level(b, copy.deepcopy(doc(b, IDOR).data))[0] == "S2"            # email is in sandbox mode, not disabled
    for i in doc(b, "roe.yaml").data["integrations"]:
        i["mode"] = "disabled"
    assert level(b, copy.deepcopy(doc(b, IDOR).data))[0] == "S1"


def test_reading_a_seed_is_not_a_write(b):
    """A GET of the seed's own resource reads it; the side effects of writing it do not raise the read."""
    doc(b, "seed-manifest.yaml").data["seeds"]["tenant_b_invoice"].update(side_effects="external", contained=False)
    tc = copy.deepcopy(doc(b, IDOR).data)
    tc["request_allowlist"] = [r for r in tc["request_allowlist"] if r["method"] == "GET" and "{seed:tenant_b_invoice}" in r["path"]]
    assert tc["request_allowlist"]
    lv, trace = level(b, tc)
    assert lv == "S1" and not any("side effects" in t for t in trace)      # S1 is the proposal floor, not the seed


# ================================================================ replays in the budget
def test_the_budget_counts_replays(b):
    assert safety.request_budget(doc(b, LLM).data) == 250 + 20 * 5           # 20 replays of one 5-request trial
    assert safety.request_budget(doc(b, IDOR).data) == 10 + 2 * 10


def test_replays_can_raise_the_class(b):
    """400 requests fit the S1 cap of 500; with two full replays (n = 1) the job may send 1200."""
    tc = copy.deepcopy(doc(b, IDOR).data)
    tc["rate_limit"]["max_requests"] = 400
    lv, trace = level(b, tc)
    assert lv == "S2" and any("replays = 1200" in t for t in trace)
    tc["trials"]["replay_n"] = 0
    assert level(b, tc)[0] == "S1"


# ================================================================ GraphQL
def _graphql(b, method, doc_sha=DOC, op="query"):
    for t in doc(b, "roe.yaml").data["targets"]:
        t["graphql_paths"] = ["/graphql"]
    tc = copy.deepcopy(doc(b, LIST).data)
    tc["request_allowlist"] = [{"target_id": "tgt-staging-api", "method": method, "path": "/graphql", "step_id": None,
                                "graphql_operation": op, "graphql_document_sha256": doc_sha, "object_refs": [], "server_action": None}]
    return tc


def test_graphql_over_get_is_s3(b):
    """v0.5 accepted a GET query on a declared GraphQL path as a read (S0): the document rides the query string,
    where the proxy cannot tell a query from a mutation."""
    lv, trace = level(b, _graphql(b, "GET"))
    assert lv == "S3" and "only over POST" in trace[0]
    assert level(b, _graphql(b, "GET", op=None))[0] == "S3"                  # unlabelled GET to the GraphQL path


def test_graphql_pins_its_document(b):
    lv, trace = level(b, _graphql(b, "POST", doc_sha=None))
    assert lv == "S3" and "graphql_document_sha256" in trace[0]
    assert level(b, _graphql(b, "POST"))[0] == "S1"


def test_a_pathless_write_bound_by_object_refs_counts_the_seed(b):
    """A Server-Action-style POST names its seed in object_refs, not in the path."""
    man = doc(b, "seed-manifest.yaml").data
    man["seeds"]["tenant_a_invoice"]["path_templates"].append("/dashboard/invoices")
    tc = copy.deepcopy(doc(b, IDOR).data)
    tc["request_allowlist"] = [{"target_id": "tgt-staging-api", "method": "POST", "path": "/dashboard/invoices", "step_id": None,
                                "graphql_operation": None, "graphql_document_sha256": None,
                                "object_refs": ["{seed:tenant_a_invoice}"], "server_action": None}]
    assert level(b, tc)[0] == "S1"
    man["seeds"]["tenant_a_invoice"].update(side_effects="external", contained=False)
    assert level(b, tc)[0] == "S2"
