# SPDX-License-Identifier: Apache-2.0
"""BL-60 (review r9): variant example bundles walk the documented paths the main bundle does not, on real signed data.

  lite   one person under a signed role_consolidation, S0/S1 only (the S2 test is MANUAL, so no G5), no spot checks;
  edge   G2 rejects K-016 and G2_apply records the R10 verdict; the engagement is `full`, so G5 has two security
         reviewers; the follow-up run hits a stop condition and is aborted (ABORTED, run_end anchor).

Building them found two validator gaps, fixed here with regression tests: a G4-approved MANUAL testcase was required to
have a toolkit job (E-JOB-AUDIT), and a G2-rejected cluster could keep its W3 verdict as the latest (E-VERDICT-G2).
Each test failed before this change and passes after it; see CONTRIBUTING.md."""
import copy
import pathlib
import sys

import pytest

from conftest import doc, rederive
from vchlib.bundle import load_bundle, load_variant, variant_names
from vchlib.checks import Ctx, run_all, verdict_heads

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import build_variants  # noqa: E402

EXPECTED_WARNINGS = {"lite": {"W-L5-LITE", "W-MODEL-PLACEHOLDER"}, "edge": {"W-MODEL-PLACEHOLDER"}, "suspend": {"W-MODEL-PLACEHOLDER"},
                     "regression": {"W-MODEL-PLACEHOLDER"}}


@pytest.fixture(scope="module")
def variants():
    return {n: load_variant(ROOT, n) for n in variant_names(ROOT)}


def test_both_variants_exist(variants):
    assert set(variants) == {"lite", "edge", "suspend", "regression"}          # r12 added regression


@pytest.mark.parametrize("name", ["lite", "edge", "suspend", "regression"])
def test_a_variant_validates_cleanly(variants, name):
    R = run_all(variants[name])
    assert R.errors == []
    assert {w.code for w in R.warnings} == EXPECTED_WARNINGS[name]


def test_the_overlays_are_what_the_builder_writes():
    assert build_variants.main(["--check"]) == 0


def test_an_unknown_variant_is_an_error():
    with pytest.raises(ValueError):
        load_variant(ROOT, "no-such-variant")


def test_an_overlay_replaces_adds_and_removes_documents(variants):
    lite, main = variants["lite"], load_bundle(ROOT)
    paths = {d.path for d in lite.docs}
    assert "docs/schemas/examples/run.followup.example.json" not in paths                     # removed.txt
    assert doc(lite, "engagement.yaml").data["assurance_profile"] == "lite"                     # replaced
    assert doc(main, "engagement.yaml").data["assurance_profile"] == "team"
    assert any(d.path.endswith("verdict.k-016-g2.example.json") for d in variants["edge"].docs)  # added


# ================================================================ lite
def test_lite_is_one_person(variants):
    b = variants["lite"]
    e = doc(b, "engagement.yaml").data
    assert e["role_consolidation"]["acknowledged"] is True and e["role_consolidation"]["person_id"] == "alice"
    approvers = {a["person_id"] for d in b.docs if d.kind == "gate-record" for a in d.data["approvers"]}
    assert approvers == {"alice"}


def test_lite_runs_no_s2_job_and_has_no_g5(variants):
    b = variants["lite"]
    run = doc(b, "run.example.json").data
    assert {j["safety_class"] for j in run["jobs"].values()} <= {"S0", "S1"}
    assert not [d for d in b.docs if d.kind == "gate-record" and d.data["gate"] == "G5"]
    assert doc(b, "testcase.zap-active.example.json").data["tool_binding"]["kind"] == "MANUAL"


def test_lite_records_no_spot_check(variants):
    b = variants["lite"]
    assert not [e for d in b.docs if d.kind == "audit-event" for e in d.data if e["event_type"] == "spot_check_result"]


# ================================================================ edge
def test_edge_g5_has_two_security_reviewers(variants):
    b = variants["edge"]
    assert doc(b, "engagement.yaml").data["assurance_profile"] == "full"
    g5 = doc(b, "gate-record.g5.example.json").data
    assert len({a["person_id"] for a in g5["approvers"]}) == 2


def test_edge_g2_rejection_is_applied_by_r10(variants):
    b = variants["edge"]
    c = Ctx(b)
    head = next(v for v in verdict_heads(c, c.runs["run-2026-09-23-001"]["verdicts"]) if v["cluster_id"] == "K-016")
    assert head["readjudicated_by"] == "G2_apply" and head["status"] == "REJECTED" and head["rule_trace"][0].startswith("R10")


def test_edge_follow_up_run_is_stopped_then_aborted(variants):
    b = variants["edge"]
    run = doc(b, "run.followup.example.json").data
    evs = doc(b, "audit-event.run-2026-10-07-001.example.jsonl").data
    kinds = [e["event_type"] for e in evs]
    assert run["status"] == "ABORTED" and "stop_condition" in kinds
    assert evs[-1]["event_type"] == "audit_anchor" and evs[-1]["payload"]["reason"] == "run_end"


# ================================================================ the two validator gaps
def test_a_g2_rejected_cluster_needs_a_post_g2_verdict(b, keys):
    """On the main bundle: G2 rejects K-016, whose only verdict is the W3 version."""
    g2 = doc(b, "gate-record.g2.example.json").data
    next(x for x in g2["decisions"] if x["item_id"] == "K-016")["decision"] = "reject"
    rederive(b, keys)
    assert any("K-016" in i.msg for i in run_all(b).errors if i.code == "E-VERDICT-G2")


def test_a_manual_testcase_needs_no_toolkit_job(variants):
    lite = variants["lite"]
    assert not [i for i in run_all(lite).errors if i.code == "E-JOB-AUDIT"]


def test_an_automated_g4_testcase_still_needs_a_job(variants):
    b = copy.deepcopy(variants["lite"])
    tc = doc(b, "testcase.zap-active.example.json").data
    tc["tool_binding"]["kind"] = "BUILTIN_CHECK"
    assert any("TC-027-01" in i.msg for i in run_all(b).errors if i.code == "E-JOB-AUDIT")


def test_schema_coverage_is_checked_on_the_main_bundle_only(variants):
    assert not [i for i in run_all(variants["lite"]).errors if i.code == "E-SCHEMA-NO-EXAMPLE"]
    main = load_bundle(ROOT)
    main.docs = [d for d in main.docs if d.kind != "feedback"]
    assert any("feedback" in i.where for i in run_all(main).errors if i.code == "E-SCHEMA-NO-EXAMPLE")


def test_ci_checks_the_variants():
    ci = (ROOT / ".github" / "workflows" / "validate.yml").read_text(encoding="utf-8")
    assert "tools/build_variants.py --check" in ci
