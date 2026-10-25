# SPDX-License-Identifier: Apache-2.0
"""v0.5 round 6, group 0 (docs/evidence/review-2026-10-25.md §3): the parts of the v0.5 branch carried onto
v0.4. Positive and negative cases:

- create_only_endpoints declare created_resource; {created:step_id} is used only on the declared paths,
  with the other variables bound to the creation request (no moving a created ID to another resource);
- creation step_ids are unique;
- a GraphQL mutation is sent only over POST (on top of v0.4's ROE-declared graphql_paths).
"""
import pytest

from conftest import codes, doc, rederive
from vchlib import safety

TC = "testcase.llm.example.json"


def context(b):
    return doc(b, TC).data, doc(b, "roe.yaml").data, doc(b, "tools.yaml").data, doc(b, "seed-manifest.yaml").data


def request(method, path, op=None, target="tgt-staging-app", step=None):
    return dict(target_id=target, method=method, path=path, step_id=step, graphql_operation=op, object_refs=[])


def klass(b):
    tc, roe, tools, manifest = context(b)
    return safety.compute_safety_class(tc, roe, tools, manifest)[0]


def test_example_is_in_scope(b):
    assert klass(b) == "S1"
    assert "E-TC-MUTATION-SCOPE" not in codes(b) and "E-SEED-MANIFEST" not in codes(b)


@pytest.mark.parametrize("method", ["GET", "DELETE"])
def test_created_id_cannot_move_to_another_resource(b, method):
    tc, *_ = context(b)
    tc["request_allowlist"].append(request(method, "/api/users/{created:open_session}"))
    assert klass(b) == "S3"
    assert "E-TC-MUTATION-SCOPE" in codes(b)


def test_declared_created_path_is_allowed(b):
    tc, *_ = context(b)
    tc["request_allowlist"].append(request("DELETE", "/api/chat/sessions/{created:open_session}"))
    assert klass(b) == "S1"


def test_parent_binding_comes_from_the_creation_request(b):
    tc, *_ = context(b)
    # the message was created under {created:open_session}; it cannot be addressed under another session
    tc["request_allowlist"].append(request("DELETE", "/api/chat/sessions/{seed:u1_doc}/messages/{created:send_message}"))
    assert klass(b) == "S3"
    tc["request_allowlist"][-1]["path"] = "/api/chat/sessions/{created:open_session}/messages/{created:send_message}"
    assert klass(b) == "S1"


def test_created_path_allowed_unit():
    endpoint = dict(path_template="/sessions/{session}/messages", created_resource=dict(
        type="message", id_pointer="/id", path_templates=["/sessions/{session}/messages/{created_id}"]))
    source = dict(path="/sessions/{created:open}/messages")
    assert safety.created_path_allowed("/sessions/{created:open}/messages/{created:send}", "send", source, endpoint)
    assert not safety.created_path_allowed("/sessions/other/messages/{created:send}", "send", source, endpoint)
    assert not safety.created_path_allowed("/messages/{created:send}", "send", source, endpoint)


def test_created_resource_is_required(b):
    doc(b, "seed-manifest.yaml").data["create_only_endpoints"][0].pop("created_resource")
    assert klass(b) == "S3"
    assert {"E-SCHEMA", "E-SEED-MANIFEST"} <= codes(b)


@pytest.mark.parametrize("bad", ["/api/users/{unknown}", "/api/chat/sessions/{created_id}/../users",
                                 "/api/users/{id}", "/api/chat/sessions"])
def test_invalid_created_resource_paths(b, bad):
    doc(b, "seed-manifest.yaml").data["create_only_endpoints"][0]["created_resource"]["path_templates"] = [bad]
    assert klass(b) == "S3"
    assert "E-SEED-MANIFEST" in codes(b)


@pytest.mark.parametrize("pointer", ["", "/", "id", "/id//x"])
def test_invalid_id_pointer(pointer):
    endpoint = dict(path_template="/s", created_resource=dict(type="s", id_pointer=pointer, path_templates=["/s/{created_id}"]))
    assert safety.created_resource_problem(endpoint) is not None


def test_creation_step_ids_are_unique(b):
    tc, *_ = context(b)
    tc["request_allowlist"].append(request("POST", "/api/chat/sessions", step="open_session"))
    assert klass(b) == "S3"


def test_created_on_another_target_or_later(b):
    tc, *_ = context(b)
    tc["request_allowlist"].insert(0, request("DELETE", "/api/chat/sessions/{created:open_session}"))
    assert klass(b) == "S3"                                  # refers to a creation that comes later


@pytest.mark.parametrize("method", ["GET", "PUT", "DELETE"])
def test_graphql_mutation_only_over_post(b, method):
    tc, roe, *_ = context(b)
    roe["targets"][1]["graphql_paths"] = ["/graphql"]
    target = roe["targets"][1]["id"]
    tc["target_ids"].append(target)
    tc["request_allowlist"].append(request(method, "/graphql", "mutation", target=target))
    problems = safety.mutation_scope_problems(tc, doc(b, "seed-manifest.yaml").data, roe)
    # GET: the v0.5 rule; PUT / DELETE: already outside v0.4's declared GraphQL methods
    assert any(("only over POST" if method == "GET" else "not over GET/POST") in p for p in problems)


def test_consistently_rederived_wrong_scope_is_still_rejected(b, keys):
    tc, *_ = context(b)
    tc["request_allowlist"].append(request("DELETE", "/api/users/{created:open_session}"))
    rederive(b, keys)
    got = codes(b)
    assert "E-DERIVED" not in got and "E-TC-MUTATION-SCOPE" in got
