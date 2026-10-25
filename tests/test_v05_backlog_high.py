# SPDX-License-Identifier: Apache-2.0
"""v0.5 high-priority backlog items (docs/09-backlog.md BL-04, BL-13, BL-21, BL-22, BL-23). Positive and negative cases:

- BL-04: a G5 names the G4 that approved its testcase in this run (g4_gate_record_id, E-G5-G4);
- BL-21: an unchanged G1 / G3 item may carry an ancestor run's approval (decisions[].carried_from, E-GATE-CARRY);
- BL-22 / BL-23: run artefacts are produced, pending or not_applicable, never a bare null (E-RUN-CONFIG);
- BL-13: a tool-only cluster (origin tool_only) and the run's derived tool_results_ref.
"""
import copy

import pytest

from conftest import codes, doc, rederive
from vchlib import derive
from vchlib.checks import run_all

PARENT, FOLLOWUP = "run-2026-09-23-001", "run-2026-10-07-001"
AUDIT = "audit-event.run-2026-09-23-001.example.jsonl"


def errors(b, code, where=None):
    return [i for i in run_all(b).errors if i.code == code and (where is None or where in i.where)]


def add_copy(b, suffix, new_name, **fields):
    d = copy.deepcopy(doc(b, suffix))
    d.path = d.path.replace(suffix, new_name)
    d.data.update(fields)
    b.docs.append(d)
    return d


# ================================================================ BL-04 G5 -> G4
def test_examples_have_no_g5_g4_or_carry_errors(b):
    found = codes(b)
    for code in ("E-G5-G4", "E-GATE-CARRY", "E-RUN-CONFIG", "E-CLUSTER-ORIGIN"):
        assert code not in found, code


@pytest.mark.parametrize("ref", [None, "GR-G1-0001", "GR-G4-9999"])
def test_g5_needs_a_g4_of_its_run(b, ref):
    doc(b, "gate-record.g5.example.json").data["g4_gate_record_id"] = ref
    assert errors(b, "E-G5-G4", "g5.example")


def test_g4_record_id_is_only_for_g5(b):
    doc(b, "gate-record.g3.example.json").data["g4_gate_record_id"] = "GR-G4-0001"
    assert any("only used by G5" in i.msg for i in errors(b, "E-G5-G4", "g3.example"))


def test_g5_approver_must_not_have_approved_the_g4(b):
    g4 = doc(b, "gate-record.g4.example.json").data
    g4["approvers"].append(copy.deepcopy(doc(b, "gate-record.g5.example.json").data["approvers"][0]))
    assert any("approved both" in i.msg for i in errors(b, "E-G5-G4", "g5.example"))


def test_g5_names_the_latest_g4_decision(b):
    """A later G4 round rejected the testcase: the G5 still pointing at the first G4 is stale."""
    g4 = doc(b, "gate-record.g4.example.json").data
    tc = doc(b, "gate-record.g5.example.json").data["decisions"][0]["item_id"]
    later = add_copy(b, "gate-record.g4.example.json", "gate-record.g4-round2.example.json",
                     gate_record_id="GR-G4-0002", round=2, timestamp=g4["timestamp"])
    later.data["decisions"] = [dict(x, decision="reject") for x in later.data["decisions"] if x["item_id"] == tc]
    assert any("latest G4 decision" in i.msg for i in errors(b, "E-G5-G4", "g5.example"))


def test_a_g4_round_after_the_g5_does_not_undo_it(b):
    """The G5 is judged by the G4 decisions known when it opened; a later round rejecting the testcase is not E-G5-G4."""
    tc = doc(b, "gate-record.g5.example.json").data["decisions"][0]["item_id"]
    later = add_copy(b, "gate-record.g4.example.json", "gate-record.g4-round2.example.json",
                     gate_record_id="GR-G4-0002", round=2, timestamp="2026-10-06T09:00:00+08:00")   # after the G5 opened
    later.data["decisions"] = [dict(x, decision="reject") for x in later.data["decisions"] if x["item_id"] == tc]
    assert not errors(b, "E-G5-G4", "g5.example")


# ================================================================ BL-21 carried G1 / G3 approvals
def carried_g1(b, **cf):
    """A G1 record of the followup run that carries the parent's G1 decisions."""
    src = doc(b, "gate-record.g1.example.json").data
    d = add_copy(b, "gate-record.g1.example.json", "gate-record.followup.g1.example.json",
                 run_id=FOLLOWUP, gate_record_id="GR-G1-0002")
    for x in d.data["decisions"]:
        x["carried_from"] = dict(dict(run_id=PARENT, gate_record_id=src["gate_record_id"], item_sha256=x["item_sha256"]), **cf)
    return d


def test_unchanged_g1_item_carries_the_parent_approval(b):
    carried_g1(b)
    assert not errors(b, "E-GATE-CARRY")


def test_changed_item_does_not_carry(b):
    d = carried_g1(b)
    d.data["decisions"][0]["item_sha256"] = "sha256:" + "0" * 64
    assert any("same item_sha256" in i.msg for i in errors(b, "E-GATE-CARRY", "followup.g1"))


def test_carry_only_from_an_ancestor_run(b):
    carried_g1(b, run_id=FOLLOWUP)
    assert any("ancestor run" in i.msg for i in errors(b, "E-GATE-CARRY", "followup.g1"))


def test_carry_needs_a_record_that_still_verifies(b):
    carried_g1(b)
    doc(b, "gate-record.g1.example.json").data["signatures"][0]["value"] = "A" * 86 + "=="
    assert any("no longer verifies" in i.msg for i in errors(b, "E-GATE-CARRY", "followup.g1"))


def test_g4_never_carries(b):
    g4 = doc(b, "gate-record.g4.example.json").data
    g4["decisions"][0]["carried_from"] = dict(run_id=PARENT, gate_record_id="GR-G4-0001", item_sha256=g4["decisions"][0].get("item_sha256"))
    assert any("only G1 / G3" in i.msg for i in errors(b, "E-GATE-CARRY", "g4.example"))


def carried_g3(b):
    src = doc(b, "gate-record.g3.example.json").data
    d = add_copy(b, "gate-record.g3.example.json", "gate-record.followup.g3.example.json",
                 run_id=FOLLOWUP, gate_record_id="GR-G3-0002")
    d.data["decisions"] = [x for x in d.data["decisions"] if x["decision"] == "accept"]
    for x in d.data["decisions"]:
        x["carried_from"] = dict(run_id=PARENT, gate_record_id=src["gate_record_id"], item_sha256=x["item_sha256"])
    return d


def test_g3_carries_under_the_same_roe(b):
    carried_g3(b)
    assert not errors(b, "E-GATE-CARRY")


def test_g3_does_not_carry_under_another_roe(b):
    carried_g3(b)
    doc(b, "gate-record.followup.g0b.example.json").data["verification"]["document_ref"] = "sha256:" + "1" * 64
    assert any("same ROE" in i.msg for i in errors(b, "E-GATE-CARRY", "followup.g3"))


# ================================================================ BL-22 / BL-23 run artefact states
def cfg(b, suffix="run.followup.example.json"):
    return doc(b, suffix).data["config_refs"]


def run_config_errors(b, suffix="run.followup.example.json"):
    return [i for i in errors(b, "E-RUN-CONFIG") if suffix in i.where]


def test_lane_a_seed_manifest_is_not_applicable(b):
    assert cfg(b, "run.lane-a.example.json")["seed_manifest"]["state"] == "not_applicable"
    assert not run_config_errors(b, "run.lane-a.example.json")


def test_a_bare_null_is_an_error(b):
    cfg(b, "run.lane-a.example.json")["seed_manifest"] = None
    assert any("is null" in i.msg for i in run_config_errors(b, "run.lane-a.example.json"))


def test_invariants_pending_before_g1(b):
    """The followup run has not reached G1 nor W2: its invariants may be pending."""
    cfg(b)["invariants"] = {"state": "pending", "expected_node": "G1"}
    assert not run_config_errors(b)


@pytest.mark.parametrize("status", ["ABORTED", "FAILED"])
def test_a_run_that_ended_before_g1_keeps_its_invariants_pending(b, status):
    """docs/08 §11.13: missing = the producing node finished. A run that ended before G1 never had invariants."""
    doc(b, "run.followup.example.json").data["status"] = status
    cfg(b)["invariants"] = {"state": "pending", "expected_node": "G1"}
    assert not [i for i in run_config_errors(b) if "invariants" in i.where]


def test_a_completed_run_has_nothing_pending(b):
    cfg(b, "run.lane-a.example.json")["seed_manifest"] = {"state": "pending", "expected_node": "G0b"}
    assert doc(b, "run.lane-a.example.json").data["status"] in ("COMPLETED", "COMPLETED_WITH_GAPS")
    assert any("should exist but missing" in i.msg for i in run_config_errors(b, "run.lane-a.example.json"))


def test_pending_names_the_producing_node(b):
    cfg(b)["invariants"] = {"state": "pending", "expected_node": "W0"}
    assert any("produced by G1" in i.msg for i in run_config_errors(b))


def test_invariants_pending_after_g1_is_missing(b):
    cfg(b, "run.example.json")["invariants"] = {"state": "pending", "expected_node": "G1"}
    assert any("should exist but missing" in i.msg for i in run_config_errors(b, "run.example.json"))


def test_seed_manifest_pending_after_g0b_is_missing(b):
    cfg(b)["seed_manifest"] = {"state": "pending", "expected_node": "G0b"}
    assert any("should exist but missing" in i.msg for i in run_config_errors(b))


def test_seed_manifest_not_applicable_with_black_box_content(b):
    cfg(b)["seed_manifest"] = {"state": "not_applicable", "reason": "test"}
    assert any("black-box content" in i.msg for i in run_config_errors(b))


def test_white_box_only_run_may_skip_the_seed_manifest(b):
    """BL-23: a non-Lane-A run without any B phase (no G0b, jobs or G3-G5) marks the seed manifest not_applicable."""
    run = doc(b, "run.followup.example.json").data
    b.docs[:] = [d for d in b.docs if "followup.g0b" not in d.path]
    run["gate_records"] = [g for g in run["gate_records"] if g["gate"] not in ("G0b", "G4")]
    cfg(b)["seed_manifest"] = {"state": "not_applicable", "reason": "純白箱 run，沒有 B 階段"}
    assert not [i for i in run_config_errors(b) if "seed_manifest" in i.where]


def test_invariants_not_applicable_only_in_lane_a(b):
    cfg(b)["invariants"] = {"state": "not_applicable", "reason": "test"}
    assert any("Lane A" in i.msg for i in run_config_errors(b))


def test_run_init_configs_cannot_be_pending(b):
    cfg(b)["models"] = {"state": "pending", "expected_node": "run_init"}
    assert "E-SCHEMA" in codes(b) or run_config_errors(b)


# ================================================================ BL-13 tool-only clusters
def tool_only(b):
    k = doc(b, "cluster.k-014.example.json").data
    k["origin"] = "tool_only"
    for x in ("member_finding_ids", "families", "lineages", "independent_families"):
        k[x] = []
    k["tool_report_refs"], k["sarif_refs"] = k["sarif_refs"], []      # the opengrep result reported the cluster
    return k


def test_tool_only_example_reaches_the_report(b):
    """K-016: opengrep's delete-without-owner result, no LLM finding at that location. Its own result is the report
    (tool_report_refs), so it has no signal: UNCORROBORATED (R7), listed in the report as report-only."""
    k = doc(b, "cluster.k-016.example.json").data
    v = doc(b, "verdict.k-016-w3.example.json").data
    assert k["origin"] == "tool_only" and not k["member_finding_ids"] and k["tool_report_refs"] and not k["sarif_refs"]
    assert v["status"] == "UNCORROBORATED" and v["independent_sources"] == 0 and v["tool_signal"] == []
    assert "K-016" in doc(b, "report-manifest.example.json").data["report_only_clusters"]
    assert k["tool_report_refs"][0] in doc(b, AUDIT).data[12]["payload_refs"]


def test_tool_only_cluster_is_accepted(b, keys):
    tool_only(b)
    rederive(b, keys)
    found = codes(b)
    for code in ("E-CLUSTER-ORIGIN", "E-CLUSTER-BINDING", "E-SARIF-REF"):
        assert code not in found, code


def test_the_reporting_tool_result_is_not_corroboration(b, keys):
    """docs/08 §11.2: the result that reported the cluster is not its own signal; no member or vote is invented,
    so before calibration the cluster is UNCORROBORATED (R7) with zero independent sources."""
    tool_only(b)
    rederive(b, keys)
    assert any("UNCORROBORATED" in i.msg for i in errors(b, "E-VERDICT-STATUS", "k-014"))
    assert any("derived 0" in i.msg for i in errors(b, "E-VERDICT-SOURCES", "k-014"))
    assert any("derived []" in i.msg for i in errors(b, "E-VERDICT-TOOLSIGNAL", "k-014"))


def test_the_report_cannot_also_be_a_signal(b):
    k = tool_only(b)
    k["sarif_refs"] = list(k["tool_report_refs"])
    assert any("not its own corroboration" in i.msg for i in errors(b, "E-CLUSTER-ORIGIN", "k-014"))


def test_report_refs_only_on_tool_only_clusters(b):
    k = doc(b, "cluster.k-014.example.json").data
    k["tool_report_refs"] = list(k["sarif_refs"])
    assert any("only set on tool_only" in i.msg for i in errors(b, "E-CLUSTER-ORIGIN", "k-014"))


def test_tool_only_cluster_has_no_llm_members(b):
    tool_only(b)["member_finding_ids"] = ["F-052"]
    assert any("no member findings" in i.msg for i in errors(b, "E-CLUSTER-ORIGIN", "k-014"))


def test_tool_only_cluster_needs_a_resolved_tool_result(b):
    tool_only(b)["tool_report_refs"] = []
    assert any("at least one tool_report_refs" in i.msg for i in errors(b, "E-CLUSTER-ORIGIN", "k-014"))


def test_tool_only_location_comes_from_the_tool_result(b):
    tool_only(b)["canonical_location"]["symbol"] = "routes/invoices.ts::deleteInvoice"
    assert errors(b, "E-SARIF-REF", "k-014")
    assert errors(b, "E-CLUSTER-ORIGIN", "k-014")


def test_tool_results_ref_is_derived(b):
    run = doc(b, "run.example.json").data
    assert run["tool_results_ref"] == derive.tool_results_ref(derive.Index(b), PARENT) is not None
    assert doc(b, "run.followup.example.json").data["tool_results_ref"] is None      # no W1 tool events
    run["tool_results_ref"] = None
    assert errors(b, "E-DERIVED", "run.example")
