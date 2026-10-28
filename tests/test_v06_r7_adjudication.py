# SPDX-License-Identifier: Apache-2.0
"""v0.6 review r7, group 3a (rule_version 05-v0.7): adjudication edges.

3.1 / 3.4 R10: only a G4-approved B4 proof that the replay reproduced (k_r >= 1) overrides a G2 rejection; a W4 proof
    only adds post_g2_conflict. The Result Analyst may not come from the families that wrote the test.
3.3 probabilistic tests are recognised by what they run against (LLM harness, multi-turn, a recorded target model),
    not by the n they declare, and must declare n >= pass_min_effective (E-TC-TRIALS).
3.9 R0: no grounded member evidence and at least one NOT_FOUND (one NOT_CHECKED item no longer escapes it).
"""
import copy

import pytest

from conftest import doc
from vchlib import adjudicate as adj
from vchlib import checks, derive
from vchlib.checks import Ctx, run_all


def errors(b, code, where=None):
    return [i for i in run_all(b).errors if i.code == code and (where is None or where in i.where)]


def result(b, rid):
    return next(d.data for d in b.docs if d.kind == "testresult" and d.data.get("result_id") == rid)


def test_rule_version():
    assert adj.RULE_VERSION == "05-v0.10"                     # review r9 PR2, r10 PR2
    assert all(d.data.get("rule_version") == "05-v0.10" for d in b_docs("verdict"))


def b_docs(kind):
    from conftest import ROOT
    from vchlib.bundle import load_bundle
    return [d for d in load_bundle(ROOT).docs if d.kind == kind]


# ================================================================ R10
@pytest.mark.parametrize("overrides, status, row", [(True, "CONFIRMED_EXECUTABLE", 5), (False, "REJECTED", 3)])
def test_only_a_replayed_g4_proof_overrides_g2(overrides, status, row):
    out = adj.adjudicate(adj.Inputs(g2_rejected=True, evidence={"E_proof"}, proof_overrides_g2=overrides))
    assert (out.status, out.row) == (status, row) and "post_g2_conflict" in out.annotations


def test_the_b4_proof_of_k005_overrides(b):
    v = doc(b, "verdict.executable.example.json").data
    assert checks.proof_overrides_g2(Ctx(b), v)


def test_a_proof_without_a_replay_hit_does_not(b):
    tr = result(b, "R-TC-012-01-1")
    assert checks.proof_can_override(Ctx(b), tr)
    tr["replay_k"] = 0
    assert not checks.proof_can_override(Ctx(b), tr)


def test_a_w4_result_never_overrides_even_if_named_at_g4(b):
    g4 = doc(b, "gate-record.g4.example.json").data
    g4["decisions"].append(dict(g4["decisions"][0], item_id="WTC-015-01", decision="accept"))
    tr = result(b, "R-WTC-015-01-1")
    assert derive.g4_approved(derive.Index(b), tr) and tr["replay_k"] >= 1
    assert not checks.proof_can_override(Ctx(b), tr)


def test_a_w4_proof_does_not_override(b):
    """V-015-2's proof is the W4 local RLS test WTC-015-01."""
    assert not checks.proof_overrides_g2(Ctx(b), doc(b, "verdict.k-015-w4.example.json").data)


def test_a_proof_without_g4_does_not_override(b):
    doc(b, "gate-record.g4.example.json").data["decisions"] = [
        dict(x, decision="reject") if x["item_id"] == "TC-012-01" else x for x in doc(b, "gate-record.g4.example.json").data["decisions"]]
    assert not checks.proof_overrides_g2(Ctx(b), doc(b, "verdict.executable.example.json").data)


# ================================================================ Result Analyst independence
def test_the_analyst_is_not_a_test_author(b):
    """R-TC-012-01-1 (T-012, modelled by tm_a anthropic and tm_c nvidia) was interpreted by the nvidia analyst; nvidia is
    not in K-005, so v0.5 accepted it although nvidia modelled the threat the test was written from."""
    tr = result(b, "R-TC-012-01-1")
    tr["interpretation"] = {"agrees": True, "rationale": "x"}
    ix = derive.Index(b)
    k005 = ix.first("cluster", cluster_id="K-005").data
    assert tr["interpreted_by"]["agent_id"] == "result_analyst" and "nvidia" not in k005["families"]
    assert derive.analyst_check(ix, tr, k005) == (False, None)


def test_an_analyst_outside_the_authors_is_eligible(b):
    tr = result(b, "R-TC-012-01-1")
    tr["interpreted_by"] = {"agent_id": "result_analyst_b", "family": "openai"}
    tr["interpretation"] = {"agrees": True, "rationale": "x"}
    ix = derive.Index(b)
    k = copy.deepcopy(ix.first("cluster", cluster_id="K-005").data)
    k.update(families=["anthropic"], lineages=["claude"])               # openai neither reported nor wrote the test
    assert derive.analyst_check(ix, tr, k) == (True, None)


def test_w4_authors_are_the_test_generator(b):
    fams, _ = derive.test_author_families(derive.Index(b), result(b, "R-WTC-015-01-1"))
    assert fams == {"openai", "anthropic"}                             # test_gen gpt_flagship, test_critic claude_sonnet


# ================================================================ probabilistic tests
LLM = "testcase.llm.example.json"


def test_an_llm_test_is_probabilistic_whatever_its_n(b):
    tc = doc(b, LLM).data
    assert derive.is_probabilistic(tc)
    tc["trials"]["n"] = 1
    assert derive.is_probabilistic(tc)
    assert not derive.is_probabilistic(doc(b, "testcase.idor.example.json").data)


def test_an_llm_test_declares_enough_trials(b):
    doc(b, LLM).data["trials"]["n"] = 1
    assert any("probabilistic" in i.msg for i in errors(b, "E-TC-TRIALS", "testcase.llm"))


def test_one_clean_llm_trial_is_not_a_qualified_pass(b):
    """v0.5: n = 1 made the LLM test deterministic, so one trial with k = 0 was E_pass."""
    ix = derive.Index(b)
    doc(b, LLM).data["trials"]["n"] = 1
    tr = result(b, "R-TC-031-01-1")
    tr["trials"].update(n=1, k=0, n_effective=1)
    cls, why = derive.classify_result(ix, tr, ix.first("cluster", cluster_id="K-011").data)
    assert cls == "E_inc" and "probabilistic" in why


def test_an_llm_harness_adapter_is_probabilistic(b):
    tc = copy.deepcopy(doc(b, "testcase.idor.example.json").data)
    tc["tool_binding"]["adapter"] = "pyrit:orchestrator"
    assert derive.is_probabilistic(tc)


@pytest.mark.parametrize("change", [{"multi_turn": True}, {"trials_record": ["target_model"]}])
def test_multi_turn_and_recorded_models_are_probabilistic(b, change):
    tc = copy.deepcopy(doc(b, "testcase.idor.example.json").data)
    if "multi_turn" in change:
        tc["multi_turn"] = True
    else:
        tc["trials"]["record"] = change["trials_record"]
    assert derive.is_probabilistic(tc)


def test_a_probabilistic_fail_is_not_demoted_by_quiet_replays(b):
    """docs/04 §4.4 (M-3): for a probabilistic test the replay only records reproducibility. v0.5 judged an LLM test
    declaring n = 1 deterministic, so 3 hits in 20 replays demoted its FAIL."""
    tc = copy.deepcopy(doc(b, LLM).data)
    tc["trials"]["n"] = 1
    tr = {"trials": {"n": 1, "k": 1}, "replays": 20, "replay_k": 3}
    assert derive.fail_reproduced(tc, tr) == (True, "")


# ================================================================ R0
def _k014_evidence(b):
    return doc(b, "finding.f-052.example.json").data["evidence"]


def test_not_checked_does_not_escape_r0(b):
    ev = _k014_evidence(b)
    ev[:] = [dict(ev[0], match="NOT_FOUND"), dict(ev[0], match="NOT_CHECKED")]
    c = Ctx(b)
    assert checks.all_evidence_not_found(c, c.ix.first("cluster", cluster_id="K-014").data)


def test_grounded_evidence_keeps_the_cluster(b):
    ev = _k014_evidence(b)
    ev[:] = [dict(ev[0], match="NOT_FOUND"), dict(ev[0], match="MATCHED_SHIFTED")]
    c = Ctx(b)
    assert not checks.all_evidence_not_found(c, c.ix.first("cluster", cluster_id="K-014").data)


def test_only_unchecked_evidence_is_not_r0(b):
    ev = _k014_evidence(b)
    ev[:] = [dict(ev[0], match="NOT_CHECKED")]
    c = Ctx(b)
    assert not checks.all_evidence_not_found(c, c.ix.first("cluster", cluster_id="K-014").data)
