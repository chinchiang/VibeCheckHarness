# SPDX-License-Identifier: Apache-2.0
"""Review r12 (2026-10-28), group 4: examples, estimates and stale text.

  - The `regression` path (R14 FIXED, R16's floor) had no signed example. Building the `regression` variant found a
    validator gap: E-TRACE made a regression result name the parent run's cluster (K-005), never the carried cluster
    K-301 that R14 decides, so the path docs/02 §1.6 describes could not be written. A carried cluster of the result's
    own run now stands for the cluster it was carried from.
  - run.initiators had no uniqueItems; the lite variant listed alice twice.
  - Estimates: Lite's claim / G1 / G2 targets (2 days each) exceeded its 1-day report target; MVP-1 left out M3 although it
    runs B0-B6; the G3 hours of the app_owner (a G3 approver) were not counted; 02's G0b row ended a white-box-only run
    COMPLETED_WITH_GAPS against §1.4.
  - Stale text: the 02-08 status lines still said round 10; the glossary lacked the r11 / r12 terms and said the suspend
    variant walks the resume path (it does not).
Each test failed before the change and passes after it (tests/mutations/r12_examples.json); see CONTRIBUTING.md."""
import copy
import pathlib

import pytest

import build_variants
from conftest import doc
from vchlib.bundle import load_variant
from vchlib.checks import run_all

ROOT = pathlib.Path(__file__).resolve().parents[1]
FRUN = "run.followup.example.json"


def text(rel):
    return (ROOT / rel).read_text(encoding="utf-8")


def errors(b, code, where=None):
    return [i for i in run_all(b).errors if i.code == code and (where is None or where in i.where)]


@pytest.fixture(scope="module")
def reg_base():
    return load_variant(ROOT, "regression")


@pytest.fixture
def r(reg_base):
    return reg_base.clone()


# ================================================================ the regression variant
def test_the_regression_variant_is_clean(reg_base):
    assert run_all(reg_base).errors == []
    assert doc(reg_base, FRUN).data["run_kind"] == "regression"


def test_the_carried_cluster_keeps_its_source_status_until_the_regression_test_runs(reg_base):
    v = doc(reg_base, "verdict.k-301-w3.example.json").data
    assert v["status"] == "CONFIRMED_EXECUTABLE" and v["rule_trace"][-1].startswith("R16")
    assert [a["kind"] for a in v["annotations"]] == ["fix_unverified"]


def test_the_passing_regression_test_makes_it_fixed(reg_base):
    v = doc(reg_base, "verdict.k-301-b5.example.json").data
    assert (v["status"], v["readjudicated_by"], v["provisional"]) == ("FIXED", "B5_readjudicate", False)
    assert [t.split(":")[0] for t in v["rule_trace"]] == ["R14"]


def test_a_regression_result_names_the_carried_cluster(reg_base):
    res = doc(reg_base, "testresult.regression.example.json").data
    assert res["cluster_ids"] == ["K-301"] and errors(reg_base, "E-TRACE") == []


def test_a_carried_cluster_stands_only_for_its_own_runs_results(r):
    res = doc(r, "testresult.example.json").data                        # the initial run's result
    res["cluster_ids"] = ["K-301"]
    assert any("must include the threat's source cluster K-005" in i.msg for i in errors(r, "E-TRACE", "testresult.example.json"))


def test_a_carried_cluster_stands_only_for_its_own_source(r):
    cl = doc(r, "cluster.followup.k-301.example.json").data
    cl["carried_from"] = dict(cl["carried_from"], cluster_id="K-011")
    assert any("must include the threat's source cluster K-005" in i.msg
               for i in errors(r, "E-TRACE", "testresult.regression.example.json"))


def test_the_builder_writes_the_regression_and_lite_variants():
    assert "regression" in build_variants.VARIANTS
    assert build_variants.main(["--check", "regression", "lite"]) == 0


def test_the_variant_has_a_readme():
    s = text("docs/examples/variants/regression/README.md")
    assert "FIXED" in s and "R16" in s and "E-TRACE" in s


# ================================================================ initiators
def test_initiators_are_unique(b):
    run = doc(b, "run.example.json").data
    run["initiators"] = run["initiators"] + run["initiators"][:1]
    assert any("non-unique" in i.msg for i in run_all(b).errors if i.code == "E-SCHEMA")


def test_the_lite_variant_lists_alice_once():
    lite = load_variant(ROOT, "lite")
    assert doc(lite, "run.example.json").data["initiators"] == ["alice"]


# ================================================================ estimates
def test_lite_targets_fit_its_one_day_report():
    s = text("docs/03-system-architecture.md")
    assert "| 3.5（70 × 3 ÷ 60） | 同日／2 天／3 天 |" in s and "| `g2_max_items` × 5 ÷ 60 | 同日／2 天／3 天 |" in s
    assert "| 0.1 | 同日／1 天／1 天 |" in s and "—／2 天／3 天" not in s and "—／1 天／2 天" not in s


def test_the_app_owner_hours_count_g3():
    s = text("docs/03-system-architecture.md")
    assert "2（security_reviewer＋app_owner" in s and "app_owner 6～10 人時" in s


def test_mvp1_includes_m3():
    assert "M3（B1、B2、G3；MVP-1 跑完整的 B0–B6" in text("docs/07-roadmap.md")


def test_a_white_box_only_run_without_roe_ends_completed():
    s = text("docs/02-methodology.md")
    assert "**未提供** → B6 → `COMPLETED`（純白箱 run" in s and "**未提供** → B6 → `COMPLETED_WITH_GAPS`" not in s


# ================================================================ stale text
@pytest.mark.parametrize("name", ["02-methodology", "03-system-architecture", "04-threat-to-testcase", "05-bias-calibration",
                                  "06-security-legal-limitations", "07-roadmap", "08-implementation-spec"])
def test_status_lines_name_round_twelve(name):
    status = text(f"docs/{name}.md").split("## 現況", 1)[1].split("\n## ", 1)[0]
    assert "第十四輪審查（2026-10-30）後的設計" in status             # r13 moved the status lines on


def test_the_glossary_has_the_r11_and_r12_terms():
    gl = text("README.md").split("## 術語表", 1)[1].split("\n## ", 1)[0]
    for term in ("voted_after_round", "refute_by_later_member_family", "CAL_POLICY", "g4_state", "W-RESULT-G4-WITHDRAWN",
                 "fix_contradicted", "report-withdrawal"):
        assert f"`{term}" in gl, term
    assert "`suspend` 變體走這條路）" not in gl and "resume_expired" in gl


def test_02_w3_names_the_current_rules():
    s = text("docs/02-methodology.md")
    assert "第八輪審查改變了 R6 的來源計算與權重的先驗；第七輪審查）" not in s and "有序規則 R0–R16" in s


def test_the_unwalked_paths_table_lists_the_r12_paths():
    readme = text("docs/schemas/README.md")
    section = readme.split("### 範例沒有走過的路徑", 1)[1].split("\n## ", 1)[0]
    for rule in ("E-RUN-RESUME", "E-GATE-ROUND", "W-RESULT-G4-WITHDRAWN", "E-REPORT-WITHDRAWAL", "`regression` 變體"):
        assert rule in section, rule
