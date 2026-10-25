# SPDX-License-Identifier: Apache-2.0
"""v0.5 round 6, group 4 (docs/evidence/review-2026-10-25.md §4.1 H-6, §4.2 M-1..M-7): methodology.
Positive and negative cases:

- H-6: the Scope Proxy binding rule covers the query string (PostgREST eq. only), lists / objects under id keys,
  plural id keys and unfiltered writes; Server Actions are bound by action_id and exact args;
- M-1: database targets prove ownership with db_comment or platform_project (also on shared platforms);
- M-2: example A's oracle treats non-2xx / non-403/404 responses as inconclusive;
- M-3: a replay runs replay_n times; a probabilistic FAIL is not demoted by k_r;
- M-4: G3 over_cap is a recorded, rule-based rejection (D5, R13, E-REPORT-QUEUE);
- M-6: gate_queues.g4_max_items.
"""
import copy

import pytest

from conftest import codes, doc, rederive, resign_gate
from vchlib import checks, safety
from vchlib.checks import Ctx, run_all

API = "tgt-staging-api"
G3, G4 = "gate-record.g3.example.json", "gate-record.g4.example.json"
OK = {"inv-a-0001", "42"}


def errors(b, code, where=None):
    return [i for i in run_all(b).errors if i.code == code and (where is None or where in i.where)]


# ================================================================ H-6 request binding
@pytest.mark.parametrize("query, body, need", [
    ({"id": "eq.inv-a-0001"}, None, True),                 # PostgREST filter on the bound row
    ({"invoice_id": "inv-a-0001"}, None, True),
    (None, {"invoice_id": "inv-a-0001", "amount": 5}, True),
    (None, {"data": [{"orderId": 42}]}, False),
    (None, {"status": "paid"}, False),                     # a path-bound write needs no body id
])
def test_bound_requests_pass(query, body, need):
    assert safety.request_binding_problem(query, body, OK, need) is None


@pytest.mark.parametrize("query, body, need, why", [
    ({"id": "in.(inv-a-0001,inv-b-0001)"}, None, True, "eq. operator"),
    ({"id": "neq.inv-a-0001"}, None, True, "eq. operator"),
    ({"or": "(id.eq.inv-a-0001,id.eq.inv-b-0001)"}, None, False, "logical operator"),
    ({"and": "(status.eq.paid)"}, None, False, "logical operator"),
    ({"id": "eq.inv-b-0001"}, None, True, "not a seed"),
    (None, {"status": "paid"}, True, "unfiltered"),         # PATCH /rest/v1/orders without a filter
    (None, {"invoice_id": [999]}, False, "holds a list"),
    (None, {"where": {"id": {"eq": "inv-b-0001"}}}, False, "holds a dict"),
    (None, {"ids": ["inv-a-0001"]}, False, "several objects"),
    (None, {"order_ids": ["42"]}, False, "several objects"),
    ({"ids": "42"}, None, False, "several objects"),
    (None, ["inv-b-0001", 5], False, "positional"),
])
def test_unbound_requests_are_rejected(query, body, need, why):
    got = safety.request_binding_problem(query, body, OK, need)
    assert got is not None and why in got, got


def test_body_id_problem_keeps_its_v04_meaning():
    assert safety.body_id_problem({"invoice_id": "inv-a-0001"}, OK) is None
    assert "invoice_id" in safety.body_id_problem({"invoice_id": "inv-b-0001"}, OK)


SPEC = {"action_id": "7f3a9c01d2e4", "args": ["{seed:tenant_a_invoice}", {"amount": 5}]}
RESOLVE = {"{seed:tenant_a_invoice}": "inv-a-0001"}


def test_server_action_exact_match():
    assert safety.server_action_problem({"Next-Action": "7f3a9c01d2e4"}, ["inv-a-0001", {"amount": 5}], SPEC, RESOLVE) is None


@pytest.mark.parametrize("headers, body", [
    ({"Next-Action": "other"}, ["inv-a-0001", {"amount": 5}]),
    ({}, ["inv-a-0001", {"amount": 5}]),
    ({"Next-Action": "7f3a9c01d2e4"}, ["inv-b-0001", {"amount": 5}]),
    ({"Next-Action": "7f3a9c01d2e4"}, ["inv-a-0001", {"amount": 5}, "extra"]),
])
def test_server_action_mismatch(headers, body):
    assert safety.server_action_problem(headers, body, SPEC, RESOLVE) is not None


def _level(b, r, path="/dashboard/invoices"):
    man = copy.deepcopy(doc(b, "seed-manifest.yaml").data)
    man["seeds"]["tenant_a_invoice"]["path_templates"].append(path)
    tc = copy.deepcopy(doc(b, "testcase.bola-list.example.json").data)
    tc["request_allowlist"] = [r]
    return safety.compute_safety_class(tc, doc(b, "roe.yaml").data, doc(b, "tools.yaml").data, man)


def _action(method="POST", path="/dashboard/invoices", refs=("{seed:tenant_a_invoice}",), spec=SPEC):
    return dict(target_id=API, method=method, path=path, step_id=None, graphql_operation=None,
                object_refs=list(refs), server_action=spec)


def test_declared_server_action_is_s1(b):
    lv, trace = _level(b, _action())
    assert lv == "S1", trace


@pytest.mark.parametrize("kw, why", [
    (dict(method="PUT"), "POST to a path without variable"),
    (dict(refs=()), "not in object_refs"),
])
def test_bad_server_action_is_s3(b, kw, why):
    lv, trace = _level(b, _action(**kw))
    assert lv == "S3" and any(why in t for t in trace), trace


# ================================================================ M-1 database ownership
def _db(b):
    return next(t for t in doc(b, "roe.yaml").data["targets"] if t["kind"] == "database")


def test_example_database_uses_db_comment(b):
    assert _db(b)["ownership_proof"]["method"] == "db_comment"
    assert "E-ROE-TARGETS" not in codes(b) and "E-ROE-PLATFORM" not in codes(b)


@pytest.mark.parametrize("method", ["dns_txt", "well_known_path"])
def test_database_cannot_use_http_proofs(b, method):
    _db(b)["ownership_proof"]["method"] = method
    assert any("database target" in i.msg for i in errors(b, "E-ROE-TARGETS"))


def test_db_comment_is_only_for_databases(b):
    t = next(t for t in doc(b, "roe.yaml").data["targets"] if t["kind"] == "http")
    t["ownership_proof"]["method"] = "db_comment"
    assert any("only for database" in i.msg for i in errors(b, "E-ROE-TARGETS"))


def test_supabase_database_needs_platform_project(b):
    db = _db(b)
    db["endpoint"] = "db.abcdefghijklmnop.supabase.co:5432"
    assert any(db["id"] in i.msg for i in errors(b, "E-ROE-PLATFORM"))


# ================================================================ M-2 example A oracle
def test_example_a_oracle_has_an_inconclusive_branch(b):
    o = doc(b, "testcase.idor.example.json").data["oracle"]["conditions"]
    assert any(c.startswith("PASS") for c in o) and any(c.startswith("FAIL") and "2xx" in c for c in o)
    assert any("INCONCLUSIVE" in c and "405" in c for c in o)


# ================================================================ M-3 replays
def test_example_replays_match_replay_n(b):
    assert not errors(b, "E-RESULT-TRIALS")


def test_short_replay_is_rejected(b):
    tr = doc(b, "testresult.example.json").data                  # TC-012-01 replay_n = 2
    tr["replays"], tr["replay_k"] = 1, 1
    assert any("replay_n" in i.msg for i in errors(b, "E-RESULT-TRIALS", "testresult.example"))


# ================================================================ M-4 G3 over_cap
def _over_cap(b, keys, tid, impact=None):
    if impact:
        doc(b, f"threat.{tid.lower()}.example.json").data["risk"]["impact"] = impact
    rec = doc(b, G3).data
    next(x for x in rec["decisions"] if x["item_id"] == tid)["decision"] = "over_cap"
    resign_gate(b, G3, keys)


def test_low_risk_threat_may_be_over_cap(b, keys):
    _over_cap(b, keys, "T-027", impact="medium")
    doc(b, "threat.t-027.example.json").data["review"]["status"] = "REJECTED"
    assert not errors(b, "E-GATE-OVER-CAP")
    assert not [i for i in errors(b, "E-TRACE-THREAT-REVIEW") if "t-027" in i.where]


def test_high_risk_threat_is_never_over_cap(b, keys):
    _over_cap(b, keys, "T-031")                                   # attack tree, impact high
    assert any("T-031" in i.msg for i in errors(b, "E-GATE-OVER-CAP"))


def test_over_cap_only_at_g3(b, keys):
    rec = doc(b, G4).data
    rec["decisions"][0]["decision"] = "over_cap"
    resign_gate(b, G4, keys)
    assert any("only used at G3" in i.msg for i in errors(b, "E-GATE-OUTCOME", G4))


def test_over_cap_counts_as_rejected_for_r13(b, keys):
    _over_cap(b, keys, "T-031")
    c = Ctx(b)
    cl = c.ix.first("cluster", cluster_id="K-011").data
    assert checks.g3_rejected(c, doc(b, "verdict.k-011-b5.example.json").data, cl)


def test_over_cap_items_name_the_over_cap_decisions(b, keys):
    rm = doc(b, "report-manifest.example.json").data
    rm["over_cap_items"] = [{"gate": "G3", "item_id": "ST-002"}]          # ST-002 -> T-031 (accepted)
    assert any("over_cap" in i.msg for i in errors(b, "E-REPORT-QUEUE"))
    _over_cap(b, keys, "T-031")
    assert not errors(b, "E-REPORT-QUEUE")


def test_over_cap_outcome_is_a_rejection(b, keys):
    rec = doc(b, G3).data
    for x in rec["decisions"]:
        x["decision"] = "reject" if x["item_id"] != "T-027" else "over_cap"
    doc(b, "threat.t-027.example.json").data["risk"]["impact"] = "medium"
    rec["outcome"] = "REJECTED"
    resign_gate(b, G3, keys)
    assert not [i for i in errors(b, "E-GATE-OUTCOME", G3) if "decisions imply" in i.msg]


# ================================================================ M-6 G4 queue
def test_g4_queue_cap_is_configurable(b):
    assert doc(b, "toolkit.yaml").data["gate_queues"]["g4_max_items"] == 40
    doc(b, "toolkit.yaml").data["gate_queues"]["g4_max_items"] = 0
    assert "E-SCHEMA" in codes(b)
