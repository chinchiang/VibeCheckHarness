# SPDX-License-Identifier: Apache-2.0
"""Review r11 (2026-10-28), group 3: method and contracts.

  - a Lite engagement's one person holds every key and runs every zone, so its signatures, anchors and receive times
    prove nothing to a third party; the report now says so (`evidential: self_attested`, E-REPORT);
  - Lite cannot record a false_positive (two people are needed): wont_fix / needs_info are its suppressions (E-FEEDBACK);
  - the BL-01 rule_trace text check missed `->rejected`, `→REJECTED`, `S = 1.0`, `S=+1.0`, `θ_confirm=`, and read
    `score=1.3179e3` as 1.3179; a negated earlier arrow was a false positive;
  - docs: a pure white-box run's terminal status (02 §1.4 vs 03 §5.2), what E-REPORT-QUEUE checks of report_only,
    and the Lite statements in 02 §1.7 / 06 §3 #26 / 08 §11.16.
Each test failed before the change and passes after it (tests/mutations/r11_contracts.json); see CONTRIBUTING.md."""
import copy
import pathlib

import pytest

from conftest import doc, rederive
from vchlib import adjudicate as adj
from vchlib.bundle import load_variant
from vchlib.checks import run_all, trace_text_problems

ROOT = pathlib.Path(__file__).resolve().parents[1]


def errors(b, code, where=None):
    return [i for i in run_all(b).errors if i.code == code and (where is None or where in i.where)]


def text(name):
    return (ROOT / "docs" / name).read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def lite_base():
    return load_variant(ROOT, "lite")


@pytest.fixture
def lite(lite_base):
    return lite_base.clone()


# ================================================================ evidential
def test_the_examples_state_their_evidential_value(b, lite_base):
    assert doc(b, "report-manifest.example.json").data["evidential"] == "separated"
    assert doc(lite_base, "report-manifest.example.json").data["evidential"] == "self_attested"
    assert run_all(b).errors == [] and run_all(lite_base).errors == []


def test_a_lite_report_cannot_claim_separated_evidence(lite):
    doc(lite, "report-manifest.example.json").data["evidential"] = "separated"
    assert any("must be 'self_attested'" in i.msg for i in errors(lite, "E-REPORT"))


def test_a_team_report_cannot_claim_self_attested_evidence(b):
    doc(b, "report-manifest.example.json").data["evidential"] = "self_attested"
    assert any("must be 'separated'" in i.msg for i in errors(b, "E-REPORT"))


def test_evidential_is_required(b):
    del doc(b, "report-manifest.example.json").data["evidential"]
    assert errors(b, "E-SCHEMA", "report-manifest")


# ================================================================ Lite suppression
def test_lite_cannot_record_a_false_positive(lite, b):
    fb = copy.deepcopy(doc(b, "feedback.k-016.example.json"))
    fb.data["label"] = "false_positive"
    lite.docs.append(fb)
    assert any("lite cannot record a false_positive" in i.msg for i in errors(lite, "E-FEEDBACK"))


def test_lite_may_record_wont_fix(lite, b):
    fb = copy.deepcopy(doc(b, "feedback.k-016.example.json"))
    fb.data["label"] = "wont_fix"
    lite.docs.append(fb)
    assert not any("lite cannot record" in i.msg for i in errors(lite, "E-FEEDBACK"))


# ================================================================ BL-01 regex
OUT = adj.Outcome("LIKELY", 12, ["R2", "R6"], decided="LIKELY")
X = adj.Inputs(score=1.3179, theta_confirm=2.5, independent_families=1)
COUNTS = {"weighted_support": 1, "weighted_refute": 0, "valid_votes": 1}


def problems(items):
    OUT.sources = 2
    return trace_text_problems(items, OUT, X, COUNTS)


@pytest.mark.parametrize("item", ["R6:->rejected", "R6:→REJECTED", "R6:=> Rejected", "R6:->cap REJECTED"])
def test_every_arrow_form_and_case_is_a_status_claim(item):
    assert any("but R6 leaves LIKELY" in p for p in problems(["R2:", item]))


def test_only_the_last_arrow_of_an_item_is_the_claim():
    assert problems(["R2:", "R6:not ->REJECTED (one family); ->LIKELY"]) == []
    assert problems(["R2:", "R6:would give ->LIKELY but ->REJECTED"])


@pytest.mark.parametrize("item", ["R2:S = 1.3179", "R2:S: 1.3179", "R2:S≈1.32", "R2:θ_confirm=2.5", "R2:S=+1.3179"])
def test_a_correct_number_in_any_form_is_accepted(item):
    assert problems([item, "R6:"]) == []


@pytest.mark.parametrize("item", ["R2:S = 9.9", "R2:S: 9.9", "R2:S≈9.9", "R2:θ_confirm=9.9", "R2:S=+9.9", "R2:score=0<theta_confirm=2.5"])
def test_a_wrong_number_in_any_form_is_an_error(item):
    assert any("but the recomputed value is" in p for p in problems([item, "R6:"])), item


@pytest.mark.parametrize("item", ["R2:score=1.3179e3", "R2:S=0x1", "R2:S=1.3179abc"])
def test_a_value_that_is_not_a_plain_decimal_is_an_error(item):
    assert any("not a plain decimal" in p for p in problems([item, "R6:"]))


def test_a_unicode_minus_is_read_as_a_sign():
    assert any("S=−1.3179 but the recomputed value is 1.3179" in p for p in problems(["R2:S=−1.3179", "R6:"]))


def test_the_regex_rework_holds_on_the_examples(b, keys):
    v = doc(b, "verdict.k-014-w3.example.json").data
    v["rule_trace"][1] = "R6:independent_sources=2 (anthropic + weak SARIF signal) → likely"
    rederive(b, keys)
    assert errors(b, "E-VERDICT-TRACE") == []
    v["rule_trace"][1] = "R6:independent_sources=2 → Confirmed_Corroborated"
    rederive(b, keys)
    assert errors(b, "E-VERDICT-TRACE")


# ================================================================ docs
def test_a_pure_white_box_run_completes_without_gaps():
    assert "純白箱 run → B6 → `COMPLETED_WITH_GAPS`" not in text("02-methodology.md")
    assert "沒有黑箱階段的 run 以 `COMPLETED` 結束" in text("02-methodology.md")


def test_02_says_what_the_validator_checks_of_report_only():
    assert "嚴重度與風險由工具包計算，validator 不檢查" in text("02-methodology.md")


def test_the_lite_statements_are_in_02_06_and_08():
    assert "evidential: self_attested" in text("02-methodology.md")
    assert "只供自查，不可作為對外證據" in text("06-security-legal-limitations.md")
    assert "Lite 不能記錄 `false_positive`" in text("08-implementation-spec.md")
