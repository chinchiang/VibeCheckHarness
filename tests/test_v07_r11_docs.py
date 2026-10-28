# SPDX-License-Identifier: Apache-2.0
"""Review r11 (docs/evidence/review-2026-10-28-r11.md), PR4: the documents agree with each other and with the code.
Each test failed on the PR3 head and passes with this PR (tests/mutations/r11_docs.json); see CONTRIBUTING.md.

  08 §11.18 says SKIPPED (not MANUAL) for a missing whoami / CAPTCHA bypass, as 02 B4 and 06 #41 do;
  the schemas README lists every signed event and all 23 check groups of the validator;
  the G1 estimate in 03 §6.5 uses the ASVS L1 baseline of 02 W0.5 (70 items), the MVP0-X8 threshold excludes G1,
  07 §1.5 and 08 §9.2 assume the same two engineers; the README status, record list and glossary are current."""
import pathlib
import re

from vchlib import checks

ROOT = pathlib.Path(__file__).resolve().parents[1]


def text(rel):
    return (ROOT / rel).read_text(encoding="utf-8")


def test_08_1118_skips_instead_of_manual():
    section = text("docs/08-implementation-spec.md").split("### 11.18")[1].split("\n### ")[0]
    assert "MANUAL |" not in section
    assert section.count("`SKIPPED`") >= 2


def test_the_schemas_readme_lists_every_signed_event():
    s = text("docs/schemas/README.md")
    assert "只有人為的 `initiator_claim`、`run_resume` 與 `spot_check_result` 帶簽章" in s
    assert "人為的 `initiator_claim`／`run_resume`／`spot_check_result` 事件" in s


def test_the_schemas_readme_lists_all_check_groups():
    s = text("docs/schemas/README.md")
    section = s.split("### 檢查項目（23 組）")[1].split("\n### ")[0]
    items = re.findall(r"^(\d+)\. \*\*", section, re.M)
    assert items == [str(i) for i in range(1, 24)]
    assert len(checks.GROUPS) == 23
    assert "`g_feedback`" in section and "`g_w4_testcases`" in section


def test_03_estimates_g1_from_the_asvs_l1_baseline():
    s = text("docs/03-system-architecture.md")
    assert "不變量約 10～30 條" not in s
    assert "最多 70 條" in s and "3.5（70 × 3 ÷ 60）" in s


def test_03_cites_g4_max_items():
    s = text("docs/03-system-architecture.md")
    assert "| G4 | `g4_max_items`（預設 40） | 4 |" in s


def test_mvp0_x8_excludes_g1_from_the_two_hour_threshold():
    row = [ln for ln in text("docs/07-roadmap.md").splitlines() if ln.startswith("| MVP0-X8 |")][0]
    assert "**G1 另計**" in row and "G1 問卷與簽核、**G2" not in row


def test_07_and_08_assume_the_same_engineers():
    assert "以 3–4 位工程師為前提" not in text("docs/08-implementation-spec.md")
    assert "兩位全職工程師 [H]" in text("docs/08-implementation-spec.md")
    assert "表中的人週是**下限**" in text("docs/07-roadmap.md")


def test_readme_and_overview_point_at_the_r11_record():
    assert "第十一輪審查（2026-10-28）後" in text("README.md")
    assert "review-2026-10-28-r11.md" in text("README.md")
    assert "review-2026-10-28-r11.md" in text("docs/00-overview.md")
    assert (ROOT / "docs/evidence/review-2026-10-28-r11.md").is_file()


def test_the_glossary_has_the_r11_terms():
    s = text("README.md").split("## 術語表")[1]
    for term in ("| 變體 bundle |", "| `rule_trace` |", "| `over_cap` |", "| `report_only` |", "| `post_g2_conflict`／`w4_became_disputed` |",
                 "| `gate_load_warning` |", "| `role_consolidation` |", "| `g5_escalation` |", "| `SUSPENDED` 與 resume |", "| `evidential` |"):
        assert term in s, term


def test_the_glossary_lists_every_final_status():
    row = [ln for ln in text("README.md").splitlines() if ln.startswith("| 裁決狀態 |")][0]
    for status in checks.FINAL_STATUSES:
        assert f"`{status}`" in row, status


def test_the_record_lists_the_four_prs():
    s = text("docs/evidence/review-2026-10-28-r11.md")
    assert all(f"chinchiang/VibeCheckHarness#{n}" in s for n in (34, 35, 36, 37))
    assert "`rule_version 05-v0.9` → `05-v0.10`" in s


def test_the_changelog_has_the_pr4_section():
    assert "### 文件矛盾、估算與審查紀錄（PR4）" in text("CHANGELOG.md")
