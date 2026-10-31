# SPDX-License-Identifier: Apache-2.0
"""Review round 8, group 3 (rule_version 05-v0.7): the calibration prior and the sources of R6.
Each test reproduced its defect on e5fa57d (it failed there) and passes with the fix; see CONTRIBUTING.md.

1. the smoothed rate has a non-degenerate prior: a verifier perfect on one side keeps a weight (E-CAL-WEIGHT);
2. an E_fail_u is an independent source for R6 only when its test's authors are outside the cluster;
3. the decision table rows 3 / 5 agree with the code (R10 needs proof_overrides_g2);
4. rule_version 05-v0.7.
"""
import copy

from conftest import doc, rederive
from vchlib import adjudicate as adj
from vchlib import checks, derive
from vchlib.bundle import Doc, reload_json
from vchlib.checks import Ctx, run_all

AUDIT = "audit-event.run-2026-09-23-001.example.jsonl"


def errors(b, code, where=None):
    return [i for i in run_all(b).errors if i.code == code and (where is None or where in i.where)]


def test_rule_version(b):
    assert adj.RULE_VERSION == "05-v0.15"                     # bumped again by review r10 PR2
    assert all(d.data.get("rule_version") == "05-v0.15" for d in b.docs if d.kind == "verdict")
    assert not errors(b, "E-VERDICT-RULE-VERSION") and not errors(b, "E-RUN-RULE-VERSION")


# ================================================================ 1. the prior
def test_smoothed_rate_is_strictly_inside_the_unit_interval():
    assert 0 < checks.smoothed_rate(0, 0, 0, 0) < 1
    assert 0 < checks.smoothed_rate(40, 40, 10, 1.0) < 1
    assert checks.smoothed_rate(34, 40, 10, 50 / 60) == (34 + 10 * 50 / 60 + 1) / 52


def test_a_verifier_perfect_on_one_side_keeps_its_weight(b):
    """claude_sonnet refutes correctly on every known non-defect (20/20, 6/6): v0.6 smoothed to a = 1 and zeroed both
    weights (near_zero w_below_min); v0.7 keeps a finite log likelihood ratio."""
    rows = doc(b, "calibration.yaml").data["result"]["weights"]
    for r in rows:
        if r["model_key"] == "claude_sonnet":
            r["refute"]["correct"] = r["refute"]["n"]
    import re
    msgs = [i.msg for i in errors(b, "E-CAL-WEIGHT", "claude_sonnet/authz/support")]
    want_w = next(float(re.search(r"recomputed (\S+)", m).group(1)) for m in msgs if m.startswith("w="))
    assert want_w > 1.0, msgs                                                    # v0.6 recomputed 0 (near_zero w_below_min)
    assert not any("near_zero/near_zero_reasons must be True" in m for m in msgs), msgs


def test_lr_weights_never_divides_by_zero():
    assert checks.lr_weights(0.9, 1.0) == {"support": 0.0, "refute": checks.lr_weights(0.9, 1.0)["refute"]}
    assert checks.lr_weights(checks.smoothed_rate(36, 40, 10, 0.9), checks.smoothed_rate(40, 40, 10, 1.0))["support"] > 0


def test_the_example_weights_are_recomputed(b):
    assert not errors(b, "E-CAL-WEIGHT")
    w = doc(b, "calibration.yaml").data["result"]["weights"][0]
    assert (w["support"]["a"], w["support"]["w"]) == (0.7603, 1.1055)        # r14: abstentions in the denominator (r10 coin flips gave 0.8041, 1.3179)
    w["support"]["w"] = 1.5775                                                   # the v0.6 value
    assert errors(b, "E-CAL-WEIGHT")


# ================================================================ 2. the sources of R6
def _w4_fail_u(b, keys, analyst_family):
    """An E_fail_u on K-011 from a W4 fake-model test (no oracle_can_pass control) read by an analyst of
    `analyst_family`; the W4 test generator is anthropic (K-011's family) in agents.yaml."""
    wtc = copy.deepcopy(doc(b, "w4-testcase.k-015.example.json").data)
    wtc.update(testcase_id="WTC-011-01", cluster_ids=["K-011"], requirement_ids=["INV-LLM-003"], kind="fake_model",
               oracle={"types": ["TOOL_CALL_LOG"], "conditions": ["refund called without confirmation"], "requirement_refs": ["INV-LLM-003"]})
    wtc["environment"]["database"] = None
    wtc["controls"] = [x for x in wtc["controls"] if x["kind"] == "reachability"]
    b.docs.append(Doc("docs/schemas/examples/w4-testcase.k-011.example.json", "w4-testcase", wtc, None))
    w4 = copy.deepcopy(doc(b, "testresult.w4-k-015.example.json").data)
    w4.update(result_id="R-WTC-011-01-1", testcase_id="WTC-011-01", cluster_ids=["K-011"], fail_oracles=["TOOL_CALL_LOG"],
              controls=[{"control_id": "CTL-01", "outcome": "PASS"}],
              interpreted_by={"agent_id": "result_analyst_a", "family": analyst_family},
              interpretation={"agrees": True, "rationale": "same-family analyst (not eligible)"})
    b.docs.append(Doc("docs/schemas/examples/testresult.w4.example.json", "testresult", w4, None))
    evs = doc(b, AUDIT).data
    i = next(n for n, e in enumerate(evs) if e["event_type"] == "sandbox_job_end" and e["payload"].get("result_id") == "R-WTC-015-01-1")
    end = copy.deepcopy(evs[i])
    end["idempotency_key"] = end["idempotency_key"].replace("WTC-015-01", "WTC-011-01")
    end["payload"].update(job_id="w4-WTC-011-01-1", testcase_id="WTC-011-01", result_id="R-WTC-011-01-1", outcome="FAIL")
    evs.insert(i + 1, end)
    for n, e in enumerate(evs):
        e["seq"] = n + 1
    import json
    reload_json(doc(b, AUDIT), "".join(json.dumps(e, ensure_ascii=False, separators=(",", ":")) + "\n" for e in evs))
    rederive(b, keys)
    c = Ctx(b)
    v = doc(b, "verdict.k-011-b5.example.json").data
    cl = c.ix.first("cluster", cluster_id="K-011").data
    return c, v, cl


def test_a_fail_u_written_by_the_reporting_family_is_not_a_source(b, keys):
    c, v, cl = _w4_fail_u(b, keys, "anthropic")
    x = checks.verdict_inputs(c, v, cl)
    assert "E_fail_u" in x.evidence and not x.fail_u_independent
    assert adj.independent_sources(x) == 1 and adj.adjudicate(x).status == "UNCORROBORATED"


def test_an_independently_written_fail_u_is_a_source(b, keys):
    """The same FAIL with the W4 test authors moved outside the cluster's family / lineage."""
    agents = doc(b, "agents.yaml").data
    for a in agents.values():
        if isinstance(a, dict) and a.get("role") in derive.TEST_AUTHOR_ROLES.get("W4", ()):
            a["model"] = "nemotron_self"
    c, v, cl = _w4_fail_u(b, keys, "anthropic")
    x = checks.verdict_inputs(c, v, cl)
    assert x.fail_u_independent and adj.independent_sources(x) == 2
    assert adj.adjudicate(x).status == "LIKELY"


def test_a_fail_u_still_turns_a_refutation_into_a_dispute():
    x = adj.Inputs(evidence={"E_fail_u"}, weighted_refute=True, score=-3.0, theta_reject=1.0, independent_families=1)
    out = adj.adjudicate(x)
    assert (out.status, out.row) == ("DISPUTED", 7)


# ================================================================ 3. the decision table vs the code
def test_row_3_rejects_a_proof_that_cannot_override_g2():
    x = adj.Inputs(g2_rejected=True, evidence={"E_proof"}, proof_overrides_g2=False)
    out = adj.adjudicate(x)
    assert (out.status, out.row, "post_g2_conflict" in out.annotations) == ("REJECTED", 3, True)
    x.proof_overrides_g2 = True
    assert adj.adjudicate(x).row == 5


def test_the_documented_rows_3_and_5_name_the_override(b):
    text = (b.root / "docs" / "05-bias-calibration.md").read_text(encoding="utf-8")
    row3 = next(line for line in text.splitlines() if line.startswith("| 3 |"))
    row5 = next(line for line in text.splitlines() if line.startswith("| 5 |"))
    assert "proof_overrides_g2" in row3 and "proof_overrides_g2" in row5
