# SPDX-License-Identifier: Apache-2.0
"""BL-01 (review 2026-09-26 L-14): what a rule_trace item's text states must be true.

Before, only the `R<n>` prefix of each item was compared with the recomputed rule sequence; the text after the colon
could say anything. Now a `->STATUS` claim must be the status that rule leaves (adjudicate.trace_statuses), and a
`name=number` for a derived quantity (score, theta_confirm, theta_reject, independent_sources, independent_families,
weighted_support, weighted_refute, valid_votes) must equal the recomputed value to the precision written. The check
found five example verdicts whose R2 text still carried pre-r10 weights and thresholds. Each test failed before this
change and passes after it (tests/mutations/bl01_trace_text.json); see CONTRIBUTING.md."""
import pytest

from conftest import doc, rederive
from vchlib import adjudicate as adj
from vchlib.checks import run_all, trace_text_problems

K014 = "verdict.k-014-w3.example.json"


def trace_errors(b):
    return [e for e in run_all(b).errors if e.code == "E-VERDICT-TRACE"]


def set_trace(b, keys, suffix, i, text):
    doc(b, suffix).data["rule_trace"][i] = text
    rederive(b, keys)


def test_the_examples_state_only_true_things(base_bundle):
    assert trace_errors(base_bundle) == []


def test_a_wrong_status_claim_is_an_error(b, keys):
    set_trace(b, keys, K014, 1, "R6:independent_sources=2 (anthropic + weak SARIF signal)->CONFIRMED_CORROBORATED")
    errs = trace_errors(b)
    assert [e.where for e in errs] == ["docs/schemas/examples/" + K014]
    assert "->CONFIRMED_CORROBORATED but R6 leaves LIKELY" in errs[0].msg
    assert run_all(b).codes() == {"E-VERDICT-TRACE"}


def test_a_wrong_score_is_an_error(b, keys):
    text = doc(b, K014).data["rule_trace"][0]
    set_trace(b, keys, K014, 0, text.replace("score=1.3179", "score=1.4633"))
    errs = trace_errors(b)
    assert len(errs) == 1 and "score=1.4633 but the recomputed value is 1.3179" in errs[0].msg


@pytest.mark.parametrize("written, ok", [("1.3179", True), ("1.32", True), ("1.3", True), ("1.33", False), ("1", True), ("2", False)])
def test_a_number_is_compared_to_the_precision_written(b, keys, written, ok):
    text = doc(b, K014).data["rule_trace"][0]
    set_trace(b, keys, K014, 0, text.replace("score=1.3179", "score=" + written))
    assert (trace_errors(b) == []) is ok


def test_a_count_is_checked(b, keys):
    text = doc(b, K014).data["rule_trace"][0]
    set_trace(b, keys, K014, 0, text.replace("weighted_support=1", "weighted_support=2"))
    assert "weighted_support=2 but the recomputed value is 1" in trace_errors(b)[0].msg


def test_a_threshold_that_is_null_cannot_be_stated(b, keys):
    suffix = "verdict.k-011-w3.example.json"
    set_trace(b, keys, suffix, 0, "R2:weighted_support=0,score=0<theta_confirm=1.2")
    assert "theta_confirm=1.2 but the recomputed value is None" in trace_errors(b)[0].msg


def test_explanations_without_claims_are_not_interpreted(b, keys):
    set_trace(b, keys, K014, 0, "R2:one family and one uncalibrated scanner rule; see 05 §4.2")
    set_trace(b, keys, K014, 1, "R6")
    assert trace_errors(b) == []


def test_a_wrong_rule_sequence_is_reported_once(b, keys):
    set_trace(b, keys, K014, 1, "R7:independent_sources=2->UNCORROBORATED")
    errs = trace_errors(b)
    assert len(errs) == 1 and "rule_trace rules" in errs[0].msg


# ---------------------------------------------------------------- the status each rule leaves
def outcome(rules, status, decided):
    return adj.Outcome(status, 11, rules, None, False, set(), decided=decided)


def test_r8_leaves_likely_and_the_deciding_rule_its_own_status():
    out = outcome(["R2", "R5", "R8"], "LIKELY", "CONFIRMED_CORROBORATED")
    assert adj.trace_statuses(out) == ["CONFIRMED_CORROBORATED", "CONFIRMED_CORROBORATED", "LIKELY"]
    x = adj.Inputs()
    ok = ["R2:", "R5:vote branch->CONFIRMED_CORROBORATED", "R8:diversity_degraded->cap LIKELY"]
    assert trace_text_problems(ok, out, x, {}) == []
    bad = ["R2:", "R5:vote branch->LIKELY", "R8:->CONFIRMED_CORROBORATED"]
    assert len(trace_text_problems(bad, out, x, {})) == 2


def test_r11_leaves_the_final_status():
    out = outcome(["R2", "R6", "R11"], "DISPUTED", "LIKELY")
    assert adj.trace_statuses(out) == ["LIKELY", "LIKELY", "DISPUTED"]
    assert trace_text_problems(["R2:", "R6:->LIKELY", "R11:qualified E_pass->DISPUTED"], out, adj.Inputs(), {}) == []


def test_adjudicate_records_the_deciding_status():
    x = adj.Inputs(weighted_support=True, score=3.0, theta_confirm=2.5, independent_families=1, diversity_degraded=True)
    out = adj.adjudicate(x)
    assert (out.status, out.decided, out.rules) == ("LIKELY", "CONFIRMED_CORROBORATED", ["R2", "R5", "R8"])
