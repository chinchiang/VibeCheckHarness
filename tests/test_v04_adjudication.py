# SPDX-License-Identifier: Apache-2.0
"""v0.4 adjudication edges (docs/05 §4.2, rule_version 05-v0.4). Each fix has a positive and a negative case:

- R0 needs that nothing else points at the cluster (no resolved SARIF, no FAIL-class test evidence);
- R10: an executable proof is not overridden by a G2 rejection;
- R11 downgrades only when the qualified PASS has a positive control;
- NOT_CHECKED evidence is not grounded and does not count as an independent family.
"""
import pytest

from conftest import doc
from vchlib import derive
from vchlib.adjudicate import Inputs, adjudicate
from vchlib.checks import Ctx, verdict_inputs, run_all

V005, V011B5 = "verdict.example.json", "verdict.k-011-b5.example.json"
F017, F021 = "finding.example.json", "finding.f-021.example.json"


# ================================================================ R0
def test_r0_rejects_when_nothing_else_points_at_the_cluster():
    out = adjudicate(Inputs(all_snippets_fail=True, independent_families=0))
    assert (out.status, out.rules) == ("REJECTED", ["R0"])


@pytest.mark.parametrize("kw, status", [
    (dict(weak_sarif=True), "UNCORROBORATED"),                    # 1 source (weak SARIF) -> R7, becomes a seed threat
    (dict(strong_tool=True), "CONFIRMED_CORROBORATED"),           # strong tool -> R5 row 10
    (dict(evidence={"E_fail_u"}), "UNCORROBORATED"),              # 1 source (E_fail_u) -> R7
    (dict(evidence={"E_proof"}), "CONFIRMED_EXECUTABLE"),         # R1
])
def test_r0_does_not_reject_with_tool_or_fail_evidence(kw, status):
    out = adjudicate(Inputs(all_snippets_fail=True, independent_families=0, **kw))
    assert out.status == status and "R0" not in out.rules


def test_r0_lane_a_still_rejects_without_other_evidence_and_not_with_sarif():
    assert adjudicate(Inputs(lane_a=True, all_snippets_fail=True)).status == "REJECTED"
    assert adjudicate(Inputs(lane_a=True, all_snippets_fail=True, weak_sarif=True)).status == "UNCORROBORATED"


def test_r0_pass_evidence_alone_does_not_save_the_cluster():
    # a PASS is not evidence that the defect exists: R0 still applies
    out = adjudicate(Inputs(all_snippets_fail=True, evidence={"E_pass"}, pass_positive=True))
    assert (out.status, out.rules) == ("REJECTED", ["R0"])


# ================================================================ R10 vs R1
def test_g2_rejection_is_final_against_votes_sarif_and_e_fail_u():
    for kw in (dict(weighted_support=True, score=9.0, theta_confirm=1.0), dict(strong_tool=True), dict(evidence={"E_fail_u"})):
        out = adjudicate(Inputs(g2_rejected=True, independent_families=2, **kw))
        assert (out.status, out.rules) == ("REJECTED", ["R10"])
    assert "post_g2_conflict" in adjudicate(Inputs(g2_rejected=True, evidence={"E_fail_u"})).annotations


def test_executable_proof_overrides_g2_rejection_with_annotation():
    out = adjudicate(Inputs(g2_rejected=True, evidence={"E_proof"}, proof_overrides_g2=True))   # v0.6: a G4-approved, replayed B4 proof
    assert (out.status, out.row, out.rules) == ("CONFIRMED_EXECUTABLE", 5, ["R10", "R1"])
    assert "post_g2_conflict" in out.annotations


# ================================================================ R11 positive control
@pytest.mark.parametrize("kw, before", [
    (dict(independent_families=2), "LIKELY"),
    (dict(strong_tool=True, independent_families=1), "CONFIRMED_CORROBORATED"),
])
def test_r11_downgrades_only_with_a_positive_control(kw, before):
    with_pc = adjudicate(Inputs(evidence={"E_pass"}, pass_positive=True, **kw))
    assert (with_pc.status, with_pc.rules[-1]) == ("DISPUTED", "R11")
    without = adjudicate(Inputs(evidence={"E_pass"}, pass_positive=False, **kw))
    assert without.status == before and without.rules[-1] == "R11"
    assert "test_not_reproduced" in without.annotations


def test_r11_on_uncorroborated_unchanged():
    out = adjudicate(Inputs(evidence={"E_pass"}, independent_families=1))
    assert out.status == "UNCORROBORATED" and "test_not_reproduced" in out.annotations


def test_verdict_inputs_reads_positive_control_per_result(b):
    """K-011's B5 PASS (TC-031-01, no oracle_can_fail control) gives pass_positive False."""
    c = Ctx(b)
    v = doc(b, V011B5).data
    cl = c.ix.first("cluster", cluster_id=v["cluster_id"]).data
    assert verdict_inputs(c, v, cl).pass_positive is False
    v["test_evidence"]["results"][0]["positive_control"] = True
    assert verdict_inputs(c, v, cl).pass_positive is True


# ================================================================ NOT_CHECKED
@pytest.mark.parametrize("match, counts", [("MATCHED", True), ("MATCHED_SHIFTED", True),
                                           ("NOT_CHECKED", False), ("NOT_FOUND", False)])
def test_only_grounded_evidence_supports(match, counts):
    assert derive.has_supporting_evidence({"evidence": [{"match": match}]}) is counts


def test_not_checked_findings_do_not_make_an_independent_family(b):
    """K-005 has two families (F-017 openai, F-021 anthropic). With F-021's only evidence NOT_CHECKED, the
    recomputed independent families drop to one and the LIKELY verdict V-005 no longer follows from the rules."""
    for e in doc(b, F021).data["evidence"]:
        e["match"] = "NOT_CHECKED"
    c = Ctx(b)
    cl = c.ix.first("cluster", cluster_id="K-005").data
    assert derive.independent_families(c.ix, cl) == ["openai"]
    found = {i.code for i in run_all(b).errors}
    assert "E-VERDICT-STATUS" in found or "E-CLUSTER-FAMILIES" in found
