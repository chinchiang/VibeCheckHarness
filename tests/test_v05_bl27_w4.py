# SPDX-License-Identifier: Apache-2.0
"""v0.5 BL-27: white-box (W4) testcases have their own schema (w4-testcase.schema.json, E-W4-TC). Positive and negative
cases: the K-015 example (local RLS test -> R1 CONFIRMED_EXECUTABLE), G1-approved requirements, clusters of the run,
reachability controls, the local database, and W4 results that borrow a black-box testcase.
"""
import copy

import pytest

from conftest import codes, doc
from vchlib.bundle import Doc
from vchlib.checks import run_all
from vchlib.derive import Index, classify_result

W4_TC, W4_TR, W4_V = "w4-testcase.k-015.example.json", "testresult.w4-k-015.example.json", "verdict.k-015-w4.example.json"


def errors(b, code, where=None):
    return [i for i in run_all(b).errors if i.code == code and (where is None or where in i.where)]


def test_the_example_confirms_k015_without_an_llm(b):
    """docs/02 W4: a deterministic FAIL with every control PASSed and a G1-pre-registered interpretation is E_proof."""
    assert not errors(b, "E-W4-TC") and "E-TC-REQ-UNAPPROVED" not in codes(b)
    v = doc(b, W4_V).data
    assert v["readjudicated_by"] == "W4_readjudicate" and v["supersedes_verdict_id"] == "V-015-1"
    assert v["status"] == "CONFIRMED_EXECUTABLE" and v["test_evidence"]["class"] == "E_proof"
    assert v["executable_proof"]["testcase_id"] == "WTC-015-01"
    ix = Index(b)
    assert ix.testcase_for(doc(b, W4_TR).data).path.endswith(W4_TC)
    assert classify_result(ix, doc(b, W4_TR).data, ix.first("cluster", cluster_id="K-015").data)[0] == "E_proof"


def test_requirements_must_be_approved_at_g1(b):
    doc(b, W4_TC).data["requirement_ids"].append("INV-XX-999")
    assert errors(b, "E-TC-REQ-UNAPPROVED", "w4-testcase")


def test_oracle_cites_only_the_testcase_requirements(b):
    doc(b, W4_TC).data["oracle"]["requirement_refs"].append("INV-LLM-003")    # approved, but not a requirement_id
    assert any("not requirement_ids" in i.msg for i in errors(b, "E-W4-TC", "w4-testcase"))


@pytest.mark.parametrize("cid", ["K-201", "K-999"])                     # a black-box cluster; no such cluster
def test_clusters_are_white_box_clusters_of_the_run(b, cid):
    doc(b, W4_TC).data["cluster_ids"] = [cid]
    assert any(cid in i.msg for i in errors(b, "E-W4-TC", "w4-testcase"))


def test_a_cluster_of_another_run(b):
    doc(b, W4_TC).data["run_id"] = "run-2026-10-07-001"
    assert any("K-015" in i.msg for i in errors(b, "E-W4-TC", "w4-testcase"))


def test_needs_a_reachability_control(b):
    tc = doc(b, W4_TC).data
    tc["controls"] = [x for x in tc["controls"] if x["kind"] != "reachability"]
    assert errors(b, "E-TC-CONTROLS", "w4-testcase")


def test_local_rls_needs_a_database(b):
    doc(b, W4_TC).data["environment"]["database"] = None
    assert any("needs environment.database" in i.msg for i in errors(b, "E-W4-TC", "w4-testcase"))


def test_migrations_are_inventory_files(b):
    doc(b, W4_TC).data["environment"]["database"]["migrations"].append("db/migrations/9999_made_up.sql")
    assert any("9999_made_up" in i.msg for i in errors(b, "E-W4-TC", "w4-testcase"))


def test_only_local_rls_starts_a_database(b):
    doc(b, W4_TC).data["kind"] = "unit"
    assert any("only local_rls" in i.msg for i in errors(b, "E-W4-TC", "w4-testcase"))


def test_the_test_never_leaves_z2(b):
    doc(b, W4_TC).data["environment"]["network"] = "staging"
    assert any("w4-testcase" in i.where for i in errors(b, "E-SCHEMA"))


def test_a_w4_result_cannot_borrow_a_black_box_testcase(b):
    """v0.4 looked every result up among black-box testcases, so a W4 result ran 'TC-012-01'."""
    tr = doc(b, W4_TR).data
    tr["testcase_id"] = "TC-012-01"
    assert any("black-box testcase" in i.msg for i in errors(b, "E-W4-TC", "testresult.w4"))
    assert any("w4-testcase TC-012-01 not found" in i.msg for i in errors(b, "E-TRACE", "testresult.w4"))


def test_a_b4_result_cannot_run_a_w4_testcase(b):
    doc(b, "testresult.example.json").data["testcase_id"] = "WTC-015-01"
    assert any("testcase WTC-015-01 not found" in i.msg for i in errors(b, "E-TRACE", "testresult.example"))


def test_a_w4_result_names_only_the_testcase_clusters(b):
    doc(b, W4_TR).data["cluster_ids"].append("K-014")
    assert any("K-014" in i.msg for i in errors(b, "E-W4-TC", "testresult.w4"))


@pytest.mark.parametrize("phase, targets, ok", [("W4", [], True), ("W4", ["tgt-staging-api"], False)])
def test_w4_results_name_no_roe_target(b, phase, targets, ok):
    doc(b, W4_TR).data["target_ids"] = targets
    assert (not errors(b, "E-RESULT-TARGETS", "testresult.w4")) is ok


def test_b4_results_still_need_a_target(b):
    doc(b, "testresult.example.json").data["target_ids"] = []
    assert any("at least one ROE target" in i.msg for i in errors(b, "E-RESULT-TARGETS", "testresult.example"))


def test_ids_are_unique_across_copies(b):
    d = copy.deepcopy(doc(b, W4_TC))
    b.docs.append(Doc(d.path.replace("k-015", "k-015-copy"), "w4-testcase", d.data, None))
    assert errors(b, "E-ID-DUP")
