# SPDX-License-Identifier: Apache-2.0
"""D5 of the 2026-11-22 review (user decision): a GET / HEAD is a read only when that is proven (docs/04 section 5).

Until this change a GET was a read (S0, no seed binding, no G5) unless the seed manifest declared it a state-changing read.
AI-generated applications are the ones that least respect HTTP semantics (GET /api/x/delete?id=, GET /logout), so the
safety class depended on how complete that declaration was. Now a GET / HEAD is a read only when the W0 inventory has the
endpoint with writes false (checks.proven_reads) or the signed seed manifest lists it in read_only_endpoints; any other
GET / HEAD is a write: it needs a seed binding and is at least S1, and without a binding it is S3.

`..._is_a_write` / `..._is_refused` tests failed before the change and pass after it
(tests/mutations/get_read_proof.json); the others check that proven reads still work. See CONTRIBUTING.md."""
import copy

import pytest

from conftest import codes, doc, proven_reads
from vchlib import checks, safety
from vchlib.checks import run_all

API = "tgt-staging-api"
LIST = "testcase.bola-list.example.json"


def req(method, path, target=API, refs=()):
    return {"target_id": target, "method": method, "path": path, "step_id": None, "graphql_operation": None, "object_refs": list(refs)}


def level(b, reqs, proven=None, manifest=None):
    tc = copy.deepcopy(doc(b, LIST).data)
    tc["request_allowlist"] = reqs
    return safety.compute_safety_class(tc, doc(b, "roe.yaml").data, doc(b, "tools.yaml").data,
                                       doc(b, "seed-manifest.yaml").data if manifest is None else manifest, proven)


# ================================================================ the rule
@pytest.mark.parametrize("method", ["GET", "HEAD"])
def test_an_unproven_get_is_a_write(method):
    assert safety.is_mutation(req(method, "/api/x/delete")) is True
    assert safety.is_mutation(req(method, "/api/x/delete"), None, {}, set()) is True
    assert safety.is_mutation(req(method, "/api/x/delete"), None, None, {("GET", "/api/other")}) is True


def test_a_get_the_inventory_proves_read_only_is_a_read():
    proven = {("GET", "/api/invoices/{}")}
    assert safety.is_mutation(req("GET", "/api/invoices/{id}"), None, None, proven) is False
    assert safety.is_mutation(req("GET", "/api/invoices/{seed:tenant_a_invoice}"), None, None, proven) is False   # same shape
    assert safety.is_mutation(req("HEAD", "/api/invoices/{id}"), None, None, proven) is False                     # HEAD by its GET
    assert safety.is_mutation(req("GET", "/api/invoices"), None, None, proven) is True                            # another endpoint


def test_a_head_proof_does_not_prove_the_get():
    assert safety.is_mutation(req("GET", "/api/x"), None, None, {("HEAD", "/api/x")}) is True


def test_a_get_the_manifest_declares_read_only_is_a_read():
    man = {"read_only_endpoints": [{"target_id": API, "method": "GET", "path_template": "/api/reports/{id}"}]}
    assert safety.is_mutation(req("GET", "/api/reports/{r}"), None, man) is False
    assert safety.is_mutation(req("GET", "/api/reports/{r}", target="tgt-other"), None, man) is True       # another target
    assert safety.is_mutation(req("HEAD", "/api/reports/{r}"), None, man) is True                          # another method


def test_a_declared_state_changing_read_stays_a_write_even_when_proven():
    man = {"state_changing_reads": [{"target_id": API, "method": "GET", "path_template": "/api/cron/run"}]}
    assert safety.is_mutation(req("GET", "/api/cron/run"), None, man, {("GET", "/api/cron/run")}) is True


def test_options_needs_no_proof():
    assert safety.is_mutation(req("OPTIONS", "/api/x")) is False


# ================================================================ the safety class
def test_an_unproven_get_without_a_seed_is_refused(b):
    lv, trace = level(b, [req("GET", "/api/admin/export")], proven_reads(b))
    assert lv == "S3" and safety.MUTATION_SCOPE in trace[0]


def test_an_unproven_get_of_a_seed_is_at_least_s1(b):
    # the seed is declared for /api/invoices/{}: on its own resource the unproven GET is a seed-bound write (S1) ...
    lv, trace = level(b, [req("GET", "/api/orders/{seed:tenant_a_invoice}")], set())
    assert lv == "S3"                                                   # ... and on another resource it is out of scope
    lv, trace = level(b, [req("GET", "/api/invoices/{seed:tenant_a_invoice}")], set())
    assert lv == "S1" and any("not proven read-only" in t for t in trace), trace


def test_a_proven_get_is_still_s0(b):
    lv, trace = level(b, [req("GET", "/api/invoices"), req("GET", "/api/invoices/{seed:tenant_a_invoice}")], proven_reads(b))
    assert lv == "S0", trace


def test_the_bundle_proof_comes_from_the_inventory_writes_flag(b):
    assert proven_reads(b) == {("GET", "/api/invoices/{}"), ("GET", "/api/invoices")}
    inv = doc(b, "inventory.example.json").data
    ep = next(e for e in inv["endpoints"] if e["method"] == "GET" and e["path"] == "/api/invoices")
    for writes in (None, True):
        ep["writes"] = writes
        assert ("GET", "/api/invoices") not in proven_reads(b), writes


def test_the_validator_uses_the_inventory_proof(b):
    """The list testcase reads GET /api/invoices (S0). When W0 can no longer tell whether the endpoint writes, the same
    request is a write without a seed: the validator recomputes S3."""
    assert "E-TC-SAFETY" not in codes(b) and "E-TC-MUTATION-SCOPE" not in codes(b)
    inv = doc(b, "inventory.example.json").data
    next(e for e in inv["endpoints"] if e["method"] == "GET" and e["path"] == "/api/invoices")["writes"] = None
    got = {i.code for i in run_all(b).issues if "bola-list" in i.where}
    assert {"E-TC-SAFETY", "E-TC-MUTATION-SCOPE"} <= got, got


def test_the_example_manifest_declares_the_gets_the_inventory_does_not_know(b):
    man = doc(b, "seed-manifest.yaml").data
    declared = {(e["target_id"], e["method"], e["path_template"]) for e in man["read_only_endpoints"]}
    assert ("tgt-canary", "GET", "/log/{job}") in declared
    assert ("tgt-staging-app", "GET", "/api/chat/sessions/{session}/messages") in declared
    man["read_only_endpoints"] = [e for e in man["read_only_endpoints"] if e["target_id"] != "tgt-canary"]
    tc = doc(b, "testcase.llm.example.json").data
    lv, trace = safety.compute_safety_class(tc, doc(b, "roe.yaml").data, doc(b, "tools.yaml").data, man, proven_reads(b))
    assert lv == "S3" and "/log/{job}" in trace[0]


def test_a_declared_read_only_get_that_w0_says_writes_is_refused(b):
    man = doc(b, "seed-manifest.yaml").data
    man["read_only_endpoints"].append({"target_id": API, "method": "GET", "path_template": "/api/invoices/{id}"})
    inv = doc(b, "inventory.example.json").data
    next(e for e in inv["endpoints"] if e["method"] == "GET" and e["path"] == "/api/invoices/{id}")["writes"] = True
    got = [i.msg for i in run_all(b).issues if i.code == "E-SEED-SIDE-EFFECT"]
    assert any("read_only_endpoints" in m and "/api/invoices/{id}" in m for m in got), got


def test_the_schema_accepts_get_and_head_in_read_only_endpoints(b):
    man = doc(b, "seed-manifest.yaml").data
    man["read_only_endpoints"].append({"target_id": API, "method": "HEAD", "path_template": "/api/invoices"})
    assert not [i for i in run_all(b).issues if i.code == "E-SCHEMA" and "seed-manifest" in i.where]
    man["read_only_endpoints"].append({"target_id": API, "method": "DELETE", "path_template": "/api/invoices"})
    assert [i for i in run_all(b).issues if i.code == "E-SCHEMA" and "seed-manifest" in i.where]


# ================================================================ the Scope Proxy rule
def test_a_plain_placeholder_matches_only_a_proven_read():
    allowlist = [req("GET", "/api/invoices/{id}", target="t")]
    assert safety.allowlist_match("t", "GET", "/api/invoices/x", allowlist, {}) is None
    assert safety.allowlist_match("t", "GET", "/api/invoices/x", allowlist, {}, proven_reads={("GET", "/api/invoices/{}")}) is not None


def test_checks_and_safety_share_one_path_shape():
    assert checks.path_shape is safety.path_shape
    assert safety.path_shape("/a/{x}/b/{seed:y}") == "/a/{}/b/{}" and safety.path_shape(None) is None
