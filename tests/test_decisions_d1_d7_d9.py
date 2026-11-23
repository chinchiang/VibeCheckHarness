# SPDX-License-Identifier: Apache-2.0
"""Design decisions D1, D7 and D9 of the 2026-11-22 review (docs/evidence/design-decisions-2026-11-22.md, user decisions).

D1  The vote branch (R5 row 11, R4 row 8, theta, the weights) stays in the rules but is marked "not enabled until
    calibration shows it feasible"; docs/05 section 5.1 carries a feasibility table computed from its own corpus targets.
D7  A Lite report calls a CONFIRMED_EXECUTABLE verdict a self-approved executable proof (docs/02 section 1.7, docs/08).
D9  The pre-registered primary hypothesis compares the full pipeline (arm 4) with the single best model resampled three
    times behind the same back end (arm 4s), not the ">= 2 agree" rule of arms 3 and 2 that the pipeline does not use.
    calibration.yaml registers the comparison; the validator checks it (E-CAL-ARMS, E-CAL-HYPOTHESIS).

Each test failed before the change and passes after it (tests/mutations/decisions_d1_d7_d9.json); see CONTRIBUTING.md."""
import copy
import pathlib
import re

import pytest

from conftest import codes, doc
from vchlib import checks_calibration
from vchlib.checks import run_all

ROOT = pathlib.Path(__file__).resolve().parents[1]


def text(name):
    return (ROOT / "docs" / name).read_text(encoding="utf-8")


def cal_of(b):
    return doc(b, "calibration.yaml").data


def issues(b, code):
    return [i.msg for i in run_all(b).issues if i.code == code]


# ================================================================ D1: the feasibility table of docs/05 section 5.1
def target_table():
    s = text("05-bias-calibration.md").split("**各 CWE 桶的目標數**", 1)[1]
    rows = [[c.strip() for c in ln.strip().strip("|").split("|")] for ln in s.split("\n\n", 2)[1].splitlines()
            if ln.startswith("|") and not ln.startswith("|---")][1:]
    return {r[0]: int(r[1].strip("*")) for r in rows}


def feasibility_table():
    s = text("05-bias-calibration.md").split("**投票分支的可行性與啟用狀態**", 1)[1]
    block = next(part for part in s.split("\n\n") if part.lstrip().startswith("| 桶 |"))
    return [[c.strip() for c in ln.strip().strip("|").split("|")] for ln in block.splitlines() if not ln.startswith("|---")][1:]


def test_the_feasibility_table_is_computed_from_the_corpus_targets(b):
    targets = target_table()
    total = targets.pop("**合計**")
    assert total == sum(targets.values()) == 610
    cfg = cal_of(b)["config"]
    need = cfg["threshold_search"]["min_clusters"]
    rows = feasibility_table()
    assert [r[0] for r in rows] == list(targets)                       # every bucket, in the same order
    for bucket, target, expected, needed, feasible in rows:
        assert int(target) == targets[bucket], bucket
        assert int(expected) == round(targets[bucket] * 250 / total), bucket
        assert int(needed) == need, bucket
        assert feasible == ("是" if int(expected) >= need else "否"), bucket
    assert all(r[4] == "否" for r in rows)                             # the claim the section makes


def test_the_vote_branch_is_marked_not_enabled():
    s = text("05-bias-calibration.md")
    section = s.split("**投票分支的可行性與啟用狀態**", 1)[1].split("\n### ", 1)[0]
    assert "投票分支視為**未啟用**" in section and "規則與程式保留，不刪除" in section
    assert "只在投票分支啟用時才有影響，隨同暫緩" in section               # D8 is deferred with it
    weights = s.split("### 4.3 投票加權", 1)[1].split("\n### ", 1)[0]
    assert weights.lstrip().startswith("**啟用狀態**") and "視為未啟用" in weights.split("\n\n", 2)[0] + weights.split("\n\n", 2)[1]


# ================================================================ D7: a Lite report labels its confirmations
def test_lite_reports_call_a_confirmation_self_approved():
    row = next(ln for ln in text("02-methodology.md").splitlines() if ln.startswith("| 報告首頁 |"))
    assert "自我核准的可執行證明" in row and "存取矩陣（G1）與測試的 oracle（G4）都由同一個人核准" in row
    assert "Team／Full 不加這個字樣" in row
    home = next(ln for ln in text("08-implementation-spec.md").splitlines() if ln.startswith("1. **首頁**"))
    assert "自我核准的可執行證明" in home and "evidential: self_attested" in home


# ================================================================ D9: the registered primary comparison
def test_the_example_registers_pipeline_against_resampled_single_best(b):
    cal = cal_of(b)
    assert cal["config"]["preregistration"]["primary_comparison"] == {"treatment": "4", "comparator": "4s"}
    arms = {a["arm"]: a for a in cal["config"]["arms"]}
    assert arms["4s"]["model_keys"] == arms["1"]["model_keys"] and arms["4s"]["n_samples"] == 3
    assert arms["4s"]["acceptance_rule"] == arms["4"]["acceptance_rule"]
    assert cal["result"]["primary_hypothesis"]["comparator"] == "4s"
    assert checks_calibration.primary_comparison_problems(cal["config"]) == []
    assert not issues(b, "E-CAL-ARMS") and not issues(b, "E-CAL-HYPOTHESIS")


def test_a_result_for_another_comparator_is_refused(b):
    cal = cal_of(b)
    cal["result"]["primary_hypothesis"]["comparator"] = "2a"
    got = checks_calibration.hypothesis_problems(cal["config"], cal["result"])
    assert any("comparator '2a' is not the registered" in m for m in got), got
    assert {"E-CAL-HYPOTHESIS", "E-SCHEMA"} <= set(codes(b))           # the schema no longer lists 2a either


def test_a_missing_registration_is_refused(b):
    cal = cal_of(b)
    del cal["config"]["preregistration"]["primary_comparison"]
    assert checks_calibration.primary_comparison_problems(cal["config"]) == ["preregistration.primary_comparison is required (treatment and comparator arms)"]
    assert any("primary_comparison is required" in m for m in issues(b, "E-CAL-ARMS"))


@pytest.mark.parametrize("field, value, needle", [
    ("model_keys", ["gpt_oss_self"], "must be those of arm 1"),
    ("model_keys", ["claude_sonnet", "gpt_oss_self", "nemotron_self"], "must be those of arm 1"),
    ("n_samples", 1, "n_samples 1 must be 3"),
    ("acceptance_rule", ">=2_of_3", "must equal that of arm 4"),
    ("exploratory", True, "are not exploratory"),
])
def test_the_comparator_arm_is_the_single_best_model_behind_the_same_back_end(b, field, value, needle):
    cfg = copy.deepcopy(cal_of(b)["config"])
    next(a for a in cfg["arms"] if a["arm"] == "4s")[field] = value
    got = checks_calibration.primary_comparison_problems(cfg)
    assert any(needle in m for m in got), got


@pytest.mark.parametrize("key", ["treatment", "comparator"])
def test_the_registered_arms_must_exist(b, key):
    cfg = copy.deepcopy(cal_of(b)["config"])
    drop = cfg["preregistration"]["primary_comparison"][key]
    cfg["arms"] = [a for a in cfg["arms"] if a["arm"] != drop]
    got = checks_calibration.primary_comparison_problems(cfg)
    assert got == [f"preregistration.primary_comparison.{key} {drop!r} is not an arm of config.arms"], got


def test_docs05_states_the_same_comparison():
    s = text("05-bias-calibration.md")
    assert "### 5.6 預先登記的主要假設：④ 是否勝過 ④′" in s
    section = s.split("### 5.6 預先登記的主要假設", 1)[1].split("\n### ", 1)[0]
    assert "Δ＝recall(④) − recall(④′)" in section and '`{treatment: "4", comparator: "4s"}`' in section
    assert "管線實際上不用「≥ 2 個家族都回報才接受」這條規則" in section
    assert not re.search(r"主要指標\*\*：[^\n]*recall\(③\)", section)        # ③ vs ② is the secondary analysis now
    assert "- **次要分析**（不切換預設）：recall(③) − recall(②)" in section
    arms = s.split("### 5.2 對照組（必要）", 1)[1].split("\n### ", 1)[0]
    assert "| ④′ 單一最佳模型取樣 N 次＋與 ④ 相同的工具佐證與可執行驗證 |" in arms
