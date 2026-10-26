# SPDX-License-Identifier: Apache-2.0
"""Review round 8 (docs/evidence/review-2026-10-26-r8.md), groups 1-2: validator bypasses and the structure of a run.
Each bypass test reproduced its bypass on e5fa57d (it failed there) and passes with the fix; see CONTRIBUTING.md.

Group 1 (no key needed):
  F2a  a B4 result on a job that never ran (PENDING / EXECUTING / INTERRUPTED / STOPPED) is no evidence (E-JOB-AUDIT; E_inc);
  F2b  one job executes one result, and every result is pin-checked, not only the last one named (E-JOB-AUDIT);
  F5   G2 routing is judged on the W3 verdict by the rubric severity, not on the W4 head / self-reported severity
       (E-PIPELINE, E-CLUSTER-SEVERITY);
  F7   a probabilistic E_proof copies {n, k} only and is recognised by is_probabilistic (E-SCHEMA regression);
  ext1 the replay budget uses the per-trial cap the Scope Proxy enforces (E-TC-RATE, safety.request_budget);
  ext2 a test of an LLM threat is probabilistic whatever adapter drives it (E-TC-TRIALS, derive.probabilistic_signals);
  ext3 independence counts base lineages; a derived_from cycle is rejected (E-MODEL-LINEAGE);
  ext4 calibration counts are consistent (E-CAL-COUNT); theta values are positive finite (E-CAL-THETA);
       weighted_valid is recomputed, never read from the verdict.
Group 2 (structure; a Z3 key holder could also forge these, docs/03 §13 limit 16, but the validator now sees them):
  F1   the B phase needs a VERIFIED G0b before it (E-GATE-ORDER);
  F3   gate decisions follow G0a < G1 < G2 < G0b < G3 < G4 < G5 by receive time (E-GATE-ORDER);
  F4   a Lane B run is claimed by a human before G1 / W4 / B (E-RUN-CLAIM);
  H3   a testcase at G4 has a G3 accept of its threat in the same run (E-RUN-G3);
  H2   regression runs carry a parent and reuse like followup runs (E-RUN-FOLLOWUP);
  M2   a spot check is independent of the decision it re-reviews (E-SPOT-CHECK);
  M6   a fork-PR Lane A run gets no LLM review (E-RUN-LANE-A).
"""
import copy
import json

import pytest

from conftest import doc, rederive
from vchlib import checks, derive, safety
from vchlib.bundle import Doc, reload_json
from vchlib.checks import Ctx, report_metrics, run_all

RUN = "run-2026-09-23-001"
FRUN = "run-2026-10-07-001"
AUDIT = "audit-event.run-2026-09-23-001.example.jsonl"
FAUDIT = "audit-event.run-2026-10-07-001.example.jsonl"
G2, G3 = "gate-record.g2.example.json", "gate-record.g3.example.json"


def errors(b, code, where=None):
    return [i for i in run_all(b).errors if i.code == code and (where is None or where in i.where)]


def msgs(b, code):
    return [i.msg for i in errors(b, code)]


def rewrite(b, evs, audit=AUDIT):
    for i, e in enumerate(evs):
        e["seq"] = i + 1
    reload_json(doc(b, audit), "".join(json.dumps(e, ensure_ascii=False, separators=(",", ":")) + "\n" for e in evs))


def refix(b):
    """Re-derive every non-audit derived field (what a writer without any key can do)."""
    for _ in range(10):
        docs, changed = {d.path: d for d in b.docs}, 0
        for e in derive.expectations(b, for_writer=True):
            if e.file.endswith(".jsonl"):
                continue
            if derive.get_path(docs[e.file].data, e.path) != e.expected:
                derive.set_path(docs[e.file].data, e.path, e.expected)
                changed += 1
        if not changed:
            return


def result(b, rid):
    return next(d.data for d in b.docs if d.kind == "testresult" and d.data.get("result_id") == rid)


def test_the_examples_are_clean(b):
    assert run_all(b).errors == []


# ================================================================ F2a / F2b: a result needs the execution that produced it
def add_result_on_job(b, status):
    run = doc(b, "run.example.json").data
    j = copy.deepcopy(run["jobs"]["job-llm-001"])
    j.update(job_id="job-llm-002", status=status, result_ref=None)
    run["jobs"]["job-llm-002"] = j
    nd = copy.deepcopy(doc(b, "testresult.llm-pass.example.json").data)
    nd.update(result_id="R-TC-031-01-2", job_id="job-llm-002")
    b.docs.append(Doc("docs/schemas/examples/testresult.zz.example.json", "testresult", nd, None))
    rm = doc(b, "report-manifest.example.json").data
    rm["artifacts"].append({"kind": "testresult", "ref": nd["result_id"], "sha256": "sha256:" + "00" * 32})
    refix(b)
    rm["metrics"].update(report_metrics(Ctx(b), RUN))
    refix(b)
    return nd


@pytest.mark.parametrize("status", ["PENDING", "EXECUTING", "INTERRUPTED", "STOPPED"])
def test_a_result_on_a_job_that_never_ran_is_rejected(b, status):
    """F2a: no key needed. v0.6 reconciled only SKIPPED and the ran states."""
    add_result_on_job(b, status)
    assert any("never executed" in m for m in msgs(b, "E-JOB-AUDIT"))


def test_a_result_without_an_execution_is_inconclusive(b):
    nd = add_result_on_job(b, "INTERRUPTED")
    cl = Ctx(b).ix.first("cluster", cluster_id="K-011").data
    assert derive.classify_result(Ctx(b).ix, nd, cl)[0] == "E_inc"


def test_the_example_results_are_pinned(b):
    c = Ctx(b)
    for d in c.docs("testresult"):
        assert derive.execution_pinned(c.ix, d.data), d.data["result_id"]


def test_a_second_result_for_an_executed_job_is_rejected(b):
    """F2b: the forged copy sits before the original, so v0.6 pin-checked only the original."""
    orig = doc(b, "testresult.example.json")
    nd = copy.deepcopy(orig.data)
    nd.update(result_id="R-TC-012-01-2", request_log_sha256="sha256:" + "cd" * 32, oracle_observations=["forged: never ran"])
    b.docs.insert(b.docs.index(orig), Doc("docs/schemas/examples/testresult.aaa.example.json", "testresult", nd, None))
    rm = doc(b, "report-manifest.example.json").data
    rm["artifacts"].append({"kind": "testresult", "ref": "R-TC-012-01-2", "sha256": "sha256:" + "00" * 32})
    refix(b)
    rm["metrics"].update(report_metrics(Ctx(b), RUN))
    refix(b)
    assert any("one job executes one result" in m for m in msgs(b, "E-JOB-AUDIT"))


def test_an_unanchored_job_end_is_rejected(b, keys):
    tr = result(b, "R-TC-012-01-1")
    evs = doc(b, AUDIT).data
    end = next(n for n, e in enumerate(evs) if derive.job_end_of(e, tr))
    evs[:] = evs[:end] + [e for e in evs[end:] if e["event_type"] != "audit_anchor"]
    rewrite(b, evs)
    rederive(b, keys)
    assert any("not in the anchored part" in m for m in msgs(b, "E-JOB-AUDIT"))


# ================================================================ F5: G2 routing on the W3 verdict and the rubric severity
def test_cluster_severity_is_the_rubric(b):
    k = doc(b, "cluster.k-014.example.json").data
    assert k["severity"] == derive.rubric_severity(Ctx(b).ix, k) == "critical"
    k["severity"] = "low"
    assert errors(b, "E-CLUSTER-SEVERITY", "k-014")


def test_rubric_inputs_come_from_the_bundle(b):
    ix = Ctx(b).ix
    k = doc(b, "cluster.k-014.example.json").data
    assert derive.rubric_inputs(ix, k) == {"bucket": "authz", "data": "confidential", "pii": True, "reachability": "internet", "auth": "any_user"}
    doc(b, "inventory.example.json").data["endpoints"][1]["auth_required"] = False            # PUT /api/invoices/{id} anonymous
    assert derive.rubric_inputs(Ctx(b).ix, k)["auth"] == "none"
    k["cwe_bucket"] = "other"
    assert derive.rubric_severity(Ctx(b).ix, k) == "high"                                  # 1 + data 1 + anonymous 1


def test_a_cluster_that_w4_readjudicated_still_needs_its_g2(b, keys):
    """F5: K-015 is UNCORROBORATED (critical) after W3; W4 later confirmed it. v0.6 looked at the W4 head only."""
    g2 = doc(b, G2).data
    g2["decisions"] = [x for x in g2["decisions"] if x["item_id"] != "K-015"]
    doc(b, "verdict.k-015-w4.example.json").data["g2_decision_ref"] = None
    rederive(b, keys)
    assert any("K-015 is UNCORROBORATED after W3" in m for m in msgs(b, "E-PIPELINE"))


def test_self_reported_severity_does_not_route(b, keys):
    """The reviewer writes low on every member of K-015: the rubric still sends it to G2."""
    g2 = doc(b, G2).data
    g2["decisions"] = [x for x in g2["decisions"] if x["item_id"] != "K-015"]
    doc(b, "verdict.k-015-w4.example.json").data["g2_decision_ref"] = None
    for d in b.docs:
        if d.kind == "finding" and d.data.get("finding_id") in doc(b, "cluster.k-015.example.json").data["member_finding_ids"]:
            d.data["severity"] = "low"
    rederive(b, keys)
    assert any("K-015 is UNCORROBORATED after W3" in m for m in msgs(b, "E-PIPELINE"))


# ================================================================ F7: the probabilistic executable proof
def test_probabilistic_proof_carries_n_and_k_only(b, keys):
    """A FAIL on the LLM test becomes an E_proof whose trials must validate against the verdict schema."""
    tr = result(b, "R-TC-031-01-1")
    tr.update(outcome="FAIL", fail_oracles=["CANARY"], replays=20, replay_k=3)
    tr["trials"]["k"] = 7
    for e in doc(b, AUDIT).data:
        if derive.job_end_of(e, tr):
            e["payload"]["outcome"] = "FAIL"
    rederive(b, keys)
    v = doc(b, "verdict.k-011-b5.example.json").data
    assert v["executable_proof"]["trials"] == {"n": 60, "k": 7}
    assert not errors(b, "E-SCHEMA", "k-011-b5")


# ================================================================ external 1: the replay budget
def test_replay_budget_uses_the_per_trial_cap():
    tc = {"rate_limit": {"max_requests": 400, "max_requests_per_trial": 4}, "trials": {"n": 100, "replay_n": 2}}
    assert safety.request_budget(tc) == 408
    tc["rate_limit"].pop("max_requests_per_trial")                     # no enforceable cap: a replay may cost a whole job
    assert safety.request_budget(tc) == 1200


def test_a_probabilistic_test_declares_its_per_trial_cap(b):
    tc = doc(b, "testcase.llm.example.json").data
    tc["rate_limit"].pop("max_requests_per_trial")
    assert errors(b, "E-TC-RATE", "testcase.llm")


def test_the_per_trial_cap_is_within_the_job_cap(b):
    tc = doc(b, "testcase.llm.example.json").data
    tc["rate_limit"]["max_requests_per_trial"] = 251
    assert errors(b, "E-TC-RATE", "testcase.llm")


# ================================================================ external 2: what is probabilistic
def disguise(tc):
    """The v0.6 bypass: an LLM test re-bound to an HTTP adapter, single turn, no target_model record, one trial."""
    tc["tool_binding"]["adapter"] = "playwright:api"
    tc["multi_turn"] = False
    tc["trials"]["record"] = [x for x in tc["trials"]["record"] if x != "target_model"]
    tc["trials"]["n"] = 1
    tc["trials"]["replay_n"] = 0


def test_an_llm_threat_is_probabilistic_whatever_the_adapter(b):
    tc = doc(b, "testcase.llm.example.json").data
    disguise(tc)
    assert derive.is_probabilistic(tc, Ctx(b).ix)
    assert any("LLM threat" in m for m in msgs(b, "E-TC-TRIALS"))


def test_a_disguised_llm_pass_is_not_qualified(b, keys):
    tc = doc(b, "testcase.llm.example.json").data
    disguise(tc)
    tr = result(b, "R-TC-031-01-1")
    tr["trials"].update(n=1, k=0, n_effective=1)
    tr.update(replays=0, replay_k=0)
    rederive(b, keys)
    cl = Ctx(b).ix.first("cluster", cluster_id="K-011").data
    assert derive.classify_result(Ctx(b).ix, result(b, "R-TC-031-01-1"), cl)[0] == "E_inc"


def test_sampling_sampled_is_a_signal(b):
    tc = doc(b, "testcase.idor.example.json").data
    tc["trials"]["sampling"] = "sampled"
    assert derive.probabilistic_signals(Ctx(b).ix, tc) == ["trials.sampling sampled"]


def test_deterministic_cannot_be_declared_on_an_llm_target(b):
    doc(b, "testcase.llm.example.json").data["trials"]["sampling"] = "deterministic"
    assert any("contradicts the target" in m for m in msgs(b, "E-TC-TRIALS"))


def test_a_deterministic_test_stays_deterministic(b):
    assert not derive.probabilistic_signals(Ctx(b).ix, doc(b, "testcase.idor.example.json").data)


# ================================================================ external 3: base lineages
def test_independent_families_count_base_lineages(b):
    ix = Ctx(b).ix
    k = doc(b, "cluster.example.json").data                                # K-005: anthropic + openai
    assert derive.independent_families(ix, k) == ["anthropic", "openai"]
    doc(b, "models.yaml").data["gpt_flagship"]["derived_from"] = "claude"
    assert derive.independent_families(Ctx(b).ix, k) == ["anthropic"]


def test_diversity_counts_the_base_lineages_of_the_pool(b):
    """K-014 (anthropic) has one weighted vote (nemotron3) and a pool E of two base lineages: degraded. When every
    verifier lineage derives from nemotron3 the pool is one base lineage and one vote is full diversity; v0.6 counted
    three families in E and kept the R8 cap."""
    v = doc(b, "verdict.k-014-w3.example.json").data
    cl = doc(b, "cluster.k-014.example.json").data
    assert checks.derived_diversity_degraded(Ctx(b), v, cl)
    models = doc(b, "models.yaml").data
    for mk in ("gpt_flagship", "gpt_oss_self"):
        models[mk]["derived_from"] = "nemotron3"
    assert not checks.derived_diversity_degraded(Ctx(b), v, cl)


def test_a_lineage_cycle_is_rejected(b):
    models = doc(b, "models.yaml").data
    models["claude_sonnet"]["derived_from"] = "nemotron3"
    models["nemotron_self"]["derived_from"] = "claude"
    assert any("cycle" in m for m in msgs(b, "E-MODEL-LINEAGE"))


def test_derived_from_names_a_registry_lineage(b):
    doc(b, "models.yaml").data["claude_sonnet"]["derived_from"] = "no-such-lineage"
    assert errors(b, "E-MODEL-LINEAGE")


# ================================================================ external 4: calibration counts and thresholds
HP_RULE = {"adapter": "semgrep", "rule_id": "python.lang.security.audit.sqli", "tool_version": "1.0.0", "cwe_bucket": "injection",
           "tp": 48, "fp": 2, "n": 50, "precision_lower95": 0.8684, "holdout_n": 12, "holdout_tp": 12}


def test_a_consistent_high_precision_rule_is_accepted(b):
    doc(b, "calibration.yaml").data["result"]["high_precision_rules"].append(dict(HP_RULE))
    assert not errors(b, "E-CAL-COUNT")
def test_holdout_tp_cannot_exceed_holdout_n(b):
    doc(b, "calibration.yaml").data["result"]["high_precision_rules"].append(HP_RULE | {"holdout_tp": 11, "holdout_n": 10})
    assert errors(b, "E-CAL-COUNT")
    assert not errors(b, "E-CAL-HIGH-PRECISION")
    assert not errors(b, "E-INTERNAL")


def test_correct_cannot_exceed_n(b):
    w = doc(b, "calibration.yaml").data["result"]["weights"][0]
    w["support"]["correct"] = w["support"]["n"] + 1
    assert errors(b, "E-CAL-COUNT")
    assert not errors(b, "E-INTERNAL")


@pytest.mark.parametrize("value", [-1.0, 0.0, 0.05, float("inf"), float("nan")])
def test_a_threshold_is_a_positive_finite_score(b, value):
    th = doc(b, "calibration.yaml").data["result"]["thresholds"]["theta_confirm"]
    th["by_bucket"]["authz"]["value"] = value
    assert errors(b, "E-CAL-THETA")


def test_weighted_valid_is_recomputed(b):
    """A verdict flags an unweighted vote as a weighted REFUTE: the rules ignore the flag (E-DERIVED still reports it)."""
    v = doc(b, "verdict.k-014-w3.example.json").data
    cl = doc(b, "cluster.k-014.example.json").data
    vote = next(x for x in v["votes"] if not x.get("weighted_valid"))
    vote["weighted_valid"], vote["stance"] = True, "REFUTE"
    c = Ctx(b)
    assert not derive.vote_terms(c.ix, vote, cl, v["calibration_version"])[2]
    assert checks.verdict_inputs(c, v, cl).weighted_refute is False
    assert errors(b, "E-DERIVED", "k-014-w3")


# ================================================================ group 2: the structure of a run (receive times)
def test_b_phase_needs_a_verified_g0b(b, keys):
    """F1 variant A: the G0b events and record removed."""
    evs = [e for e in doc(b, AUDIT).data if e["node"] != "G0b"]
    rewrite(b, evs)
    b.docs.remove(doc(b, "gate-record.g0b.example.json"))
    run = doc(b, "run.example.json").data
    run["gate_records"] = [g for g in run["gate_records"] if g["gate"] != "G0b"]
    rm = doc(b, "report-manifest.example.json").data
    rm["artifacts"] = [a for a in rm["artifacts"] if a.get("ref") != "GR-G0b-0001"]
    rederive(b, keys)
    assert any("without a VERIFIED G0b" in m for m in msgs(b, "E-GATE-ORDER"))


def test_a_failed_g0b_stops_the_b_phase(b, keys):
    """F1 variant B: the G0b decision is VERIFY_FAILED but G3 / G4 / jobs follow."""
    doc(b, "gate-record.g0b.example.json").data["outcome"] = "VERIFY_FAILED"
    for e in doc(b, AUDIT).data:
        if e["event_type"] == "gate_decision" and e["payload"].get("gate") == "G0b":
            e["payload"]["outcome"] = "VERIFY_FAILED"
    rederive(b, keys)
    assert any("without a VERIFIED G0b" in m for m in msgs(b, "E-GATE-ORDER"))


def test_a_later_failed_g0b_stops_the_b_phase(b, keys):
    """A VERIFIED G0b, then (re-verification at resume) VERIFY_FAILED before B0: the B events that follow are rejected."""
    evs = doc(b, AUDIT).data
    i = next(n for n, e in enumerate(evs) if e["node"] == "B0")
    dec = copy.deepcopy(next(e for e in evs if e["event_type"] == "gate_decision" and e["payload"].get("gate") == "G0b"))
    dec.update(ts=evs[i]["ts"], idempotency_key=f"{RUN}:G0b:GR-G0b-0001:2")
    dec["payload"]["outcome"] = "VERIFY_FAILED"
    rewrite(b, evs[:i] + [dec] + evs[i:])
    rederive(b, keys)
    assert any("last G0b decision: VERIFY_FAILED" in m for m in msgs(b, "E-GATE-ORDER"))


def move_block(b, node, new_ts, before_node):
    """Move every event of `node` to new_ts, placed before the first event of before_node (seq renumbered)."""
    evs = doc(b, AUDIT).data
    block = [e for e in evs if e["node"] == node]
    for e in block:
        e["ts"] = new_ts
    rest = [e for e in evs if e["node"] != node]
    i = next(n for n, e in enumerate(rest) if e["node"] == before_node)
    rewrite(b, rest[:i] + block + rest[i:])


def test_g0b_cannot_come_after_g3(b, keys):
    """F3: the G0b block moved between G3 and G4 (self-declared opened_at values re-sorted to match)."""
    move_block(b, "G0b", "2026-10-03T08:00:00+08:00", "G4")
    g = doc(b, "gate-record.g0b.example.json").data
    g.update(opened_at="2026-10-03T07:59:00+08:00", timestamp="2026-10-03T08:00:00+08:00")
    run = doc(b, "run.example.json").data
    for x in run["gate_records"]:
        if x["gate"] == "G0b":
            x["opened_at"], x["decided_at"] = g["opened_at"], g["timestamp"]
    run["gate_records"].sort(key=lambda x: x["opened_at"])
    rederive(b, keys)
    assert any("first G0b decision" in m or "without a VERIFIED G0b" in m for m in msgs(b, "E-GATE-ORDER"))


def test_g4_cannot_precede_g3(b, keys):
    move_block(b, "G4", "2026-10-01T12:00:00+08:00", "G3")
    g = doc(b, "gate-record.g4.example.json").data
    g.update(opened_at="2026-10-01T11:00:00+08:00", timestamp="2026-10-01T12:00:00+08:00")
    run = doc(b, "run.example.json").data
    for x in run["gate_records"]:
        if x["gate"] == "G4":
            x["opened_at"], x["decided_at"] = g["opened_at"], g["timestamp"]
    run["gate_records"].sort(key=lambda x: x["opened_at"])
    rederive(b, keys)
    assert any("first G4 decision" in m for m in msgs(b, "E-GATE-ORDER"))


def test_w4_runs_after_g2_and_before_g0b(b, keys):
    move_block(b, "W4", "2026-09-25T13:00:00+08:00", "G2")          # before the G2 decision (09-28)
    rederive(b, keys)
    assert any("W4 ran before the G2 decision" in m for m in msgs(b, "E-GATE-ORDER"))


@pytest.mark.parametrize("audit", [AUDIT, FAUDIT])
def test_a_lane_b_run_is_claimed_by_a_human(b, keys, audit):
    """F4: the signed initiator_claim removed from both Lane B logs."""
    rewrite(b, [e for e in doc(b, audit).data if e["event_type"] != "initiator_claim"], audit)
    rederive(b, keys)
    assert errors(b, "E-RUN-CLAIM", audit)


def test_the_claim_precedes_the_first_gate(b, keys):
    evs = doc(b, AUDIT).data
    claim = next(e for e in evs if e["event_type"] == "initiator_claim")
    claim["ts"] = "2026-09-24T12:30:00+08:00"                         # after the G1 decision (09-24 11:00)
    rest = [e for e in evs if e is not claim]
    i = next(n for n, e in enumerate(rest) if e["node"] == "W1")
    rewrite(b, rest[:i + 1] + [claim] + rest[i + 1:])
    rederive(b, keys)
    assert errors(b, "E-RUN-CLAIM")


def test_lane_a_needs_no_claim(b):
    assert not errors(b, "E-RUN-CLAIM", "pr-118")


# ================================================================ H3 / H2: run kinds and the same-run G3
def test_a_testcase_at_g4_needs_this_runs_g3(b, keys):
    """H3: the follow-up run's G3 (carrying T-012) removed; the parent's G3 accept is not this run's."""
    b.docs.remove(doc(b, "gate-record.followup.g3.example.json"))
    run = doc(b, "run.followup.example.json").data
    run["gate_records"] = [g for g in run["gate_records"] if g["gate"] != "G3"]
    rewrite(b, [e for e in doc(b, FAUDIT).data if e["node"] != "G3"], FAUDIT)
    rederive(b, keys)
    assert any("TC-012-01 is at G4" in m for m in msgs(b, "E-RUN-G3"))


def test_the_carried_g3_keeps_the_threat_review_on_its_source(b):
    assert not errors(b, "E-TRACE-THREAT-REVIEW")
    doc(b, "threat.example.json").data["review"]["gate_record_id"] = "GR-G3-0002"
    assert errors(b, "E-TRACE-THREAT-REVIEW")


def test_a_regression_run_carries_a_parent(b, keys):
    """H2: the follow-up example re-labelled regression validates; v0.6 rejected any parent / reuse on it."""
    doc(b, "run.followup.example.json").data["run_kind"] = "regression"
    rederive(b, keys)
    assert not errors(b, "E-RUN-FOLLOWUP")


def test_an_initial_run_has_no_parent(b, keys):
    run = doc(b, "run.followup.example.json").data
    run["run_kind"] = "initial"
    rederive(b, keys)
    assert errors(b, "E-RUN-FOLLOWUP")


# ================================================================ M2: spot checks
def spot_check(b, keys, who, item="GR-G5-0001", kind="g5"):
    evs = doc(b, AUDIT).data
    i = next(n for n, e in enumerate(evs) if e["event_type"] == "report_published")
    ev = copy.deepcopy(evs[1])                                           # the signed initiator_claim as a template
    ev.update(event_type="spot_check_result", ts=evs[i]["ts"], node="B6", actor={"kind": "human", "id": who},
              idempotency_key=f"{RUN}:B6:spot_check:{item}", payload={"item_kind": kind, "item_id": item, "outcome": "confirmed", "note": None})
    rewrite(b, evs[:i] + [ev] + evs[i:])
    rederive(b, keys)


def test_an_independent_spot_check_is_accepted(b, keys):
    spot_check(b, keys, "heidi", item="GR-G4-0001", kind="g4")          # security_reviewer; erin approved G4, alice initiated
    assert not errors(b, "E-SPOT-CHECK")


def test_an_approver_cannot_spot_check_their_own_decision(b, keys):
    spot_check(b, keys, "heidi")                                         # heidi approved GR-G5-0001
    assert any("independent" in m for m in msgs(b, "E-SPOT-CHECK"))


def test_the_initiator_cannot_spot_check(b, keys):
    spot_check(b, keys, "alice", item="GR-G4-0001", kind="g4")
    assert any("independent" in m for m in msgs(b, "E-SPOT-CHECK"))


def test_only_a_security_reviewer_spot_checks(b, keys):
    spot_check(b, keys, "frank", item="GR-G4-0001", kind="g4")       # app_owner: neither approver nor initiator of G4
    assert any("security_reviewer" in m for m in msgs(b, "E-SPOT-CHECK"))


def test_a_spot_check_names_a_gate_record(b, keys):
    spot_check(b, keys, "heidi", item="GR-NOPE")
    assert any("gate record" in m for m in msgs(b, "E-SPOT-CHECK"))


# ================================================================ M6: fork PRs
def test_a_fork_pr_gets_no_llm_review(b, keys):
    run = doc(b, "run.lane-a.example.json").data
    run["pr_origin"] = "fork"
    rederive(b, keys)
    assert any("fork PR" in m for m in msgs(b, "E-RUN-LANE-A"))


def test_lane_a_declares_its_origin(b, keys):
    doc(b, "run.lane-a.example.json").data["pr_origin"] = None
    rederive(b, keys)
    assert any("pr_origin" in m for m in msgs(b, "E-RUN-LANE-A"))


def test_advisories_come_from_same_repo_lane_a_runs(b, keys):
    run = doc(b, "run.example.json").data
    run["lane_a_advisories"] = ["K-101"]
    rederive(b, keys)
    assert not errors(b, "E-RUN-LANE-A", "run.example")
    doc(b, "run.lane-a.example.json").data["pr_origin"] = "fork"
    rederive(b, keys)
    assert any("not clusters of a same-repo" in m for m in msgs(b, "E-RUN-LANE-A"))
