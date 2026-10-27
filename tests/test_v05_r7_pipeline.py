# SPDX-License-Identifier: Apache-2.0
"""v0.5 review r7, group 2: pipeline completeness (E-PIPELINE) and planned vs executed coverage (external review 5).

v0.5 checked each artefact on its own, so a cluster or finding could leave the pipeline without a decision: the K-014
example (LIKELY) was neither a seed threat nor report-only, and the report omitted three latest verdicts and the W4
result. The coverage metrics counted what the testcases planned, so they stayed 1.0 / 0.8571 with every result removed.
"""
import copy

import pytest

from conftest import doc, rederive
from vchlib import checks
from vchlib.checks import Ctx, report_metrics, run_all

RUN_ID = "run-2026-09-23-001"
RUN, RM, SEEDS, G2 = "run.example.json", "report-manifest.example.json", "seed-threats.example.json", "gate-record.g2.example.json"
AUDIT = "audit-event.run-2026-09-23-001.example.jsonl"


def errors(b, code="E-PIPELINE", where=None):
    return [i for i in run_all(b).errors if i.code == code and (where is None or where in i.where)]


def msgs(b):
    return [i.msg for i in errors(b)]


def test_the_examples_complete_the_pipeline(b):
    assert not errors(b)
    assert any(s["source_cluster_id"] == "K-014" for s in doc(b, SEEDS).data["seeds"])


# ================================================================ W3: every cluster and verified finding is adjudicated
def test_every_cluster_has_a_verdict(b):
    k = copy.deepcopy(doc(b, "cluster.k-014.example.json"))
    k.path = k.path.replace("k-014", "k-099")
    k.data.update(cluster_id="K-099", member_finding_ids=[])
    b.docs.append(k)
    assert any("K-099 has no verdict" in m for m in msgs(b))


def test_a_verified_finding_is_in_a_cluster(b):
    doc(b, "cluster.k-014.example.json").data["member_finding_ids"] = []
    assert any("F-052" in m and "in no cluster" in m for m in msgs(b))


# ================================================================ W5: seeds, report-only and G2
def test_a_likely_cluster_cannot_vanish(b):
    """The K-014 example bug: LIKELY, no seed threat, not report-only."""
    seeds = doc(b, SEEDS).data["seeds"]
    seeds[:] = [s for s in seeds if s["source_cluster_id"] != "K-014"]
    assert any("K-014" in m and "neither a seed threat nor report_only" in m for m in msgs(b))


def test_report_only_counts_as_a_decision(b):
    seeds = doc(b, SEEDS).data["seeds"]
    seeds[:] = [s for s in seeds if s["source_cluster_id"] != "K-014"]
    doc(b, RM).data["report_only_clusters"].append("K-014")
    assert not [m for m in msgs(b) if "neither a seed" in m]


def test_a_high_uncorroborated_cluster_goes_through_g2(b):
    doc(b, G2).data["decisions"][0]["item_id"] = "K-999"                 # K-011 (high, UNCORROBORATED) undecided
    assert any("K-011" in m and "no G2 decision" in m for m in msgs(b))


def test_over_cap_also_counts(b):
    doc(b, G2).data["decisions"][0]["item_id"] = "K-999"
    doc(b, RM).data["over_cap_items"].append({"gate": "G2", "item_id": "K-011", "reason": "queue full"})
    assert not [m for m in msgs(b) if "no G2 decision" in m]


def test_a_disputed_cluster_goes_through_g2(b):
    doc(b, "verdict.k-014-w3.example.json").data["status"] = "DISPUTED"
    assert any("K-014 is DISPUTED" in m for m in msgs(b))


def test_a_g2_rejected_cluster_is_not_a_seed(b):
    doc(b, G2).data["decisions"][0]["decision"] = "reject"
    assert any("K-011 was rejected at G2" in m for m in msgs(b))


def test_seeds_have_threats_after_g3(b):
    doc(b, SEEDS).data["seeds"][0]["threat_id"] = None
    assert any("ST-001" in m and "no threat_id" in m for m in msgs(b))


# ================================================================ report
def test_manual_review_is_derived(b):
    doc(b, "verdict.executable.example.json").data["annotations"] = [{"kind": "post_g2_conflict", "reason": None}]
    assert any("manual_review_clusters must be ['K-005']" in m for m in msgs(b))
    doc(b, RUN).data["manual_review_clusters"] = ["K-005"]
    doc(b, RM).data["manual_review_clusters"] = ["K-005"]
    assert not [m for m in msgs(b) if "manual_review_clusters" in m]


def test_the_report_carries_the_run_gaps(b):
    doc(b, RUN).data["gaps"] = [{"kind": "manual", "ref": "TC-019-01", "reason": "需要人工測試"}]
    assert any("gaps must be the run's gaps" in m for m in msgs(b))


@pytest.mark.parametrize("kind, ref", [("verdict", "V-014-1"), ("verdict", "V-015-2"), ("testresult", "R-WTC-015-01-1")])
def test_the_report_lists_latest_verdicts_and_results(b, kind, ref):
    arts = doc(b, RM).data["artifacts"]
    arts[:] = [a for a in arts if a["ref"] != ref]
    assert any(ref in m for m in msgs(b))


def test_lane_a_stops_at_w3(b):
    assert not errors(b, where="run-2026-09-25-pr-118")


# ================================================================ planned vs executed coverage (external review 5)
def test_executed_coverage_drops_without_results(b):
    b.docs[:] = [d for d in b.docs if not (d.kind == "testresult" and d.data.get("run_id") == RUN_ID)]
    m = report_metrics(Ctx(b), RUN_ID)
    assert (m["planned_access_matrix_coverage"], m["planned_endpoint_test_coverage"]) == (0.5714, 0.8571)
    assert (m["executed_access_matrix_coverage"], m["executed_endpoint_test_coverage"]) == (0.0, 0.0)


def _result(b, rid):
    return next(d.data for d in b.docs if d.kind == "testresult" and d.data.get("result_id") == rid)


def test_the_example_results_are_backed(b):
    c = Ctx(b)
    assert all(checks.execution_backed(c, d.data) for d in c.docs("testresult") if d.data.get("run_id") == RUN_ID)


def _end_of(b, tr):
    return next(e for e in doc(b, AUDIT).data if e["event_type"] == "sandbox_job_end" and e["payload"].get("job_id") == tr["job_id"])


@pytest.mark.parametrize("outcome", ["INVALID", "ERROR", "SKIPPED", "STOPPED"])
def test_an_ineffective_outcome_does_not_count(b, keys, outcome):
    """The audit event agrees and the pins are re-derived: only the outcome rule rejects it."""
    tr = _result(b, "R-TC-012-01-1")
    tr["outcome"] = outcome
    _end_of(b, tr)["payload"]["outcome"] = outcome
    rederive(b, keys)
    tr = _result(b, "R-TC-012-01-1")
    assert not checks.execution_backed(Ctx(b), tr)


def test_a_failed_control_does_not_count(b, keys):
    _result(b, "R-TC-012-01-1")["controls"][0]["outcome"] = "FAIL"
    rederive(b, keys)
    assert not checks.execution_backed(Ctx(b), _result(b, "R-TC-012-01-1"))


def test_a_result_needs_exactly_one_execution(b):
    tr = _result(b, "R-TC-012-01-1")
    doc(b, AUDIT).data.append(copy.deepcopy(_end_of(b, tr)))
    assert not checks.execution_backed(Ctx(b), tr)


def test_unbacked_results_do_not_raise_executed_coverage(b):
    for d in b.docs:
        if d.kind == "testresult" and d.data.get("run_id") == RUN_ID:
            d.data["artifact_sha256"] = "sha256:" + "1" * 64            # none matches its sandbox_job_end any more
    m = report_metrics(Ctx(b), RUN_ID)
    assert (m["planned_access_matrix_coverage"], m["executed_access_matrix_coverage"], m["executed_endpoint_test_coverage"]) == (0.5714, 0.0, 0.0)


def test_a_result_without_matching_pins_does_not_count(b):
    tr = _result(b, "R-TC-012-01-1")
    tr["artifact_sha256"] = "sha256:" + "1" * 64
    assert not checks.execution_backed(Ctx(b), tr)


def test_an_unanchored_execution_does_not_count(b):
    tr = _result(b, "R-TC-012-01-1")
    evs = doc(b, AUDIT).data
    end = next(n for n, e in enumerate(evs) if e["event_type"] == "sandbox_job_end" and e["payload"].get("job_id") == tr["job_id"])
    evs[:] = evs[:end] + [e for e in evs[end:] if e["event_type"] != "audit_anchor"]     # no anchor after the job
    assert not checks.execution_backed(Ctx(b), tr)


def test_executed_metrics_are_recomputed(b):
    doc(b, RM).data["metrics"]["executed_endpoint_test_coverage"] = 1.0
    assert errors(b, "E-REPORT-METRICS")
