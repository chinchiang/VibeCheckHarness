# SPDX-License-Identifier: Apache-2.0
"""v0.4 round 5, adjudication and validator gaps (docs/evidence/review-2026-10-24.md §9). Positive and negative cases:

- support / refute weights are separate (a supporter that is always right on defects gets no refute weight);
- provisional marks only verdicts that votes could decide;
- a vote's citation must be about the cluster; anonymized / order_randomized come from the verifier template;
- gate records are ordered by the Audit Writer's receive time;
- initiator_claim / run_resume are human acts; run_resume needs test_lead;
- an unsigned EXPIRED cannot come before the timeout; idempotency keys are required and unique.
"""
import copy

import pytest

from conftest import codes, doc
from vchlib import derive
from vchlib.checks import Ctx, derived_provisional, run_all

V014, V202, V201 = "verdict.k-014-w3.example.json", "verdict.k-202-b5.example.json", "verdict.k-201-b5.example.json"
AUDIT = "audit-event.run-2026-09-23-001.example.jsonl"


def errors(b, code):
    return [i for i in run_all(b).errors if i.code == code]


# ================================================================ split weights
def test_weight_sides(b):
    ix = Ctx(b).ix
    v = doc(b, "calibration.yaml").data["calibration_version"]
    # v0.6 (review r7 3.2): log likelihood ratios of both sides
    assert ix.weight("nemotron_self", "authz", v, "SUPPORT") == pytest.approx(1.3179)   # v0.7 prior (r8), abstentions (r10)
    assert ix.weight("nemotron_self", "authz", v, "REFUTE") == pytest.approx(1.3878)
    assert ix.weight("nemotron_self", "llm_specific", v, "REFUTE") == 0.0      # refute side near_zero


def test_refute_side_is_recomputed(b):
    row = doc(b, "calibration.yaml").data["result"]["weights"][0]
    row["refute"]["w"] = 0.9
    assert any("refute" in i.where for i in errors(b, "E-CAL-WEIGHT"))


def test_refute_vote_uses_the_refute_weight(b):
    """K-014's nemotron vote turned into a REFUTE: its expected weight becomes refute.w, not support.w."""
    vote = doc(b, V014).data["votes"][0]
    vote["stance"] = "REFUTE"
    exp = [e for e in derive.expectations(b) if e.file.endswith(V014) and e.path == ("votes", 0, "weight")]
    assert exp and exp[0].expected == pytest.approx(1.3878)                    # v0.6: refute-side likelihood; v0.7 prior ratio; r10 abstentions


# ================================================================ provisional
def test_black_box_and_proof_verdicts_are_not_provisional(b):
    c = Ctx(b)
    for name in (V202, V201):
        v = doc(b, name).data
        cl = c.ix.first("cluster", cluster_id=v["cluster_id"]).data
        assert derived_provisional(c, v, cl) is False


def test_vote_dependent_verdict_without_calibration_is_provisional(b):
    c = Ctx(b)
    v = copy.deepcopy(doc(b, V014).data)
    v["calibration_version"] = None
    cl = c.ix.first("cluster", cluster_id=v["cluster_id"]).data
    assert derived_provisional(c, v, cl) is True


# ================================================================ votes
def test_irrelevant_citation_makes_the_vote_invalid(b):
    c = Ctx(b)
    vote = copy.deepcopy(doc(b, V014).data["votes"][0])
    cl = c.ix.first("cluster", cluster_id="K-014").data
    assert derive.vote_valid(vote, cl, c.ix) is True
    vote["cited_evidence"] = ["app/support/agent.py:57"]          # a real line, but in another cluster's file
    assert derive.vote_valid(vote, cl, c.ix) is False


def test_inventory_citation_is_relevant_only_for_a_member_fact(b):
    c = Ctx(b)
    cl = c.ix.first("cluster", cluster_id="K-015").data
    vote = copy.deepcopy(doc(b, "verdict.k-015-w3.example.json").data["votes"][0])
    assert derive.cited_relevant(c.ix, vote, cl)
    vote["cited_evidence"] = ["inventory:/db/tables/1/rls_enabled"]
    assert not derive.cited_relevant(c.ix, vote, cl)


def test_vote_flags_come_from_the_verifier_template(b):
    for t in doc(b, "run.example.json").data["prompt_templates"]:
        if t["template_id"] == "w3-verify":
            t["randomizes_order"] = False
    assert any("must equal the run's w3-verify template" in i.msg for i in errors(b, "E-VERDICT-VOTE"))


# ================================================================ audit actors, EXPIRED, idempotency
def test_claim_by_a_system_actor_is_an_error(b):
    ev = next(e for e in doc(b, AUDIT).data if e["event_type"] == "initiator_claim")
    ev["actor"] = {"kind": "system", "id": "run-controller"}
    assert any("must have actor.kind human" in i.msg for i in errors(b, "E-AUDIT-ACTOR"))


def test_early_expired_is_an_error(b):
    rec = doc(b, "gate-record.g1.example.json").data
    rec["outcome"] = "EXPIRED"
    assert errors(b, "E-GATE-EXPIRED-EARLY")


@pytest.mark.parametrize("bad", [None, "run-other:W0:x", "nocolons"])
def test_bad_idempotency_keys(b, bad):
    doc(b, AUDIT).data[3]["idempotency_key"] = bad
    assert errors(b, "E-AUDIT-IDEMPOTENCY")


def test_duplicate_idempotency_key(b):
    evs = doc(b, AUDIT).data
    i, j = next((i, j) for i in range(len(evs)) for j in range(i + 1, len(evs)) if evs[i]["node"] == evs[j]["node"])
    evs[j]["idempotency_key"] = evs[i]["idempotency_key"]
    assert any("unique in the run" in x.msg for x in errors(b, "E-AUDIT-IDEMPOTENCY"))


def test_examples_pass(b):
    found = codes(b)
    for code in ("E-AUDIT-IDEMPOTENCY", "E-GATE-EXPIRED-EARLY", "E-VERDICT-PROVISIONAL", "E-CAL-WEIGHT", "E-VERDICT-VOTE"):
        assert code not in found, code
