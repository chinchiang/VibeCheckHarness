# SPDX-License-Identifier: Apache-2.0
"""v0.5 round 6, group 2 (docs/evidence/review-2026-10-25.md §4.1 H-4, §4.2 A-3..A-8, T-10). Positive and negative:

- R4 rejects automatically only a single-family report; two or more independent families -> DISPUTED (G2);
- an abstention is never weighted-valid;
- a citation must hit the member evidence lines (support) or the members' slices / inventory (refute);
- invalidated calibration rows weigh 0;
- a W4 version sees only W4 results;
- calibration.yaml and crosswalk.yaml are pinned by the engagement;
- row 10 (strong tool) is not provisional.
"""
import pytest

from conftest import codes, doc
from vchlib import adjudicate as adj
from vchlib import derive
from vchlib.adjudicate import Inputs, adjudicate
from vchlib.checks import Ctx

V014 = "verdict.k-014-w3.example.json"


def test_rule_version():
    assert adj.RULE_VERSION == "05-v0.10"           # bumped again by review r10 PR2


# ================================================================ R4 diversity floor
def test_single_family_report_can_be_rejected():
    out = adjudicate(Inputs(weighted_refute=True, score=-5.0, theta_reject=1.0, independent_families=1))
    assert (out.status, out.row, out.rules) == ("REJECTED", 8, ["R2", "R4"])


@pytest.mark.parametrize("fams", [2, 3])
def test_multi_family_report_is_disputed_not_rejected(fams):
    out = adjudicate(Inputs(weighted_refute=True, score=-5.0, theta_reject=1.0, independent_families=fams))
    assert (out.status, out.row, out.rules) == ("DISPUTED", 9, ["R2", "R4"])


# ================================================================ abstentions
def test_abstention_is_not_weighted_valid(b):
    vote = doc(b, V014).data["votes"][0]
    vote["stance"] = "ABSTAIN"
    exp = {e.path: e.expected for e in derive.expectations(b) if e.file.endswith(V014)}
    assert exp[("votes", 0, "weighted_valid")] is False
    assert exp[("votes", 0, "weight")] > 0                     # the weight is still recorded


# ================================================================ citation relevance
def _relevant(b, citation, stance="SUPPORT"):
    ix = Ctx(b).ix
    cl = ix.first("cluster", cluster_id="K-014").data
    return derive.cited_relevant(ix, {"stance": stance, "cited_evidence": [citation]}, cl)


@pytest.mark.parametrize("cite", ["routes/invoices.ts:88", "routes/invoices.ts:88-88"])
def test_support_citation_on_the_member_lines(b, cite):
    assert _relevant(b, cite)


@pytest.mark.parametrize("cite", ["routes/invoices.ts:99999", "routes/invoices.ts", "routes/invoices.ts:40",
                                  "routes/invoices.ts:90-80", "inventory:/db/tables/0/rls_enabled"])
def test_support_citation_elsewhere_is_not_relevant(b, cite):
    assert not _relevant(b, cite)


@pytest.mark.parametrize("cite", ["routes/invoices.ts:40", "db/schema.prisma:12", "inventory:/db/tables/0/rls_enabled"])
def test_refute_citation_may_use_the_slice_or_inventory(b, cite):
    assert _relevant(b, cite, "REFUTE")


@pytest.mark.parametrize("cite", ["routes/invoices.ts:500", "routes/other.ts:3", "inventory:/no/such/path"])
def test_refute_citation_outside_slice_or_inventory(b, cite):
    assert not _relevant(b, cite, "REFUTE")


def test_irrelevant_citation_makes_the_vote_invalid(b):
    doc(b, V014).data["votes"][0]["cited_evidence"] = ["routes/invoices.ts:99999"]
    exp = {e.path: e.expected for e in derive.expectations(b) if e.file.endswith(V014)}
    assert exp[("votes", 0, "valid")] is False


# ================================================================ invalidated calibration
def test_invalidated_model_weighs_zero(b):
    cal = doc(b, "calibration.yaml").data
    ix = Ctx(b).ix
    v = cal["calibration_version"]
    assert ix.weight("nemotron_self", "authz", v) > 0
    cal["result"]["invalidated_by"] = [{"model_key": "nemotron_self", "change": "version", "at": "2026-10-01T00:00:00+08:00"}]
    assert Ctx(b).ix.weight("nemotron_self", "authz", v) == 0


def test_model_outside_valid_for_weighs_zero(b):
    cal = doc(b, "calibration.yaml").data
    cal["result"]["valid_for_model_keys"] = ["claude_sonnet"]
    assert Ctx(b).ix.weight("nemotron_self", "authz", cal["calibration_version"]) == 0


# ================================================================ phase-scoped test results
def test_w4_version_does_not_see_b4_results(b):
    ix = Ctx(b).ix
    cl = ix.first("cluster", cluster_id="K-005").data
    assert derive.linked_results(ix, cl, "B5_readjudicate")              # the B4 result of TC-012-01
    assert derive.linked_results(ix, cl, "W4_readjudicate") == []
    assert derive.linked_results(ix, cl, "W3_adjudicate") == []


# ================================================================ config pins
@pytest.mark.parametrize("name", ["calibration.yaml", "crosswalk.yaml"])
def test_calibration_and_crosswalk_are_pinned(b, name):
    assert "E-ENG-CONFIG-PIN" not in codes(b)
    d = doc(b, name).data
    d["_tampered"] = True
    assert "E-ENG-CONFIG-PIN" in codes(b)


# ================================================================ provisional
def test_strong_tool_row_is_not_provisional(b, monkeypatch):
    from vchlib import checks
    c = Ctx(b)
    v = dict(doc(b, V014).data, calibration_version=None, theta_confirm=None)   # uncalibrated: provisional by default
    cl = c.ix.first("cluster", cluster_id="K-014").data
    assert checks.derived_provisional(c, v, cl) is True
    real = checks.adj.adjudicate
    monkeypatch.setattr(checks.adj, "adjudicate", lambda x: real(adj.Inputs(strong_tool=True, independent_families=1)))
    assert checks.derived_provisional(c, v, cl) is False                         # row 10 is not decided by votes
