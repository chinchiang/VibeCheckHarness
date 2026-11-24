# SPDX-License-Identifier: Apache-2.0
"""The effort estimate says what it leaves out (2026-11-22 review, finding A6; re-verified 2026-11-24).

A6 called the schedule optimistic: 48 person-weeks for two engineers, twelve tickets in the first two weeks of M1, and
no measured speed (docs/09 BL-63). The three facts hold. Speed cannot be fixed in a document, but three things could be
checked and were wrong or missing:

  - the calendar weeks did not follow the table's own formula (person-weeks / 2 / 0.8): the rows were rounded down and
    the total said 29 where the formula gives 30;
  - five pieces of scope were specified after the estimate was last changed (2026-10-31) and are in no row;
  - the LangGraph spike was placed in week 1 of M1, where six tickets already fill two people, with no ticket and no
    time limit.

docs/07 section 1.5 now lists the unestimated scope without inventing numbers for it; the conflict is docs/08 U-25.

Each test failed before the change and passes after it (tests/mutations/effort_estimate.json); see CONTRIBUTING.md."""
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]
UNESTIMATED = ("BL-70", "oracle_approvals", "BL-78", "BL-75", "BL-79")


def text(rel):
    return (ROOT / rel).read_text(encoding="utf-8")


def section():
    return text("docs/07-roadmap.md").split("### 1.5 人力與時程估算", 1)[1].split("\n## ", 1)[0].split("\n### ", 1)[0]


def rows():
    out = {}
    for ln in section().splitlines():
        if ln.startswith("| M") or ln.startswith("| **合計**"):
            cells = [c.strip().strip("*") for c in ln.strip().strip("|").split("|")]
            out[cells[0][:2]] = (float(cells[1]), float(cells[2]))
    return out


def row(rel, start):
    hits = [ln for ln in text(rel).splitlines() if ln.startswith(start)]
    assert len(hits) == 1, (rel, start, len(hits))
    return hits[0]


def test_the_calendar_weeks_follow_the_formula_the_section_states():
    sec, r = section(), rows()
    assert "「人週 ÷ 2 ÷ 0.8」" in sec and "不進位" in sec
    assert list(r) == ["M1", "M2", "M3", "M4", "M5", "合計"]
    for name, (pw, cw) in r.items():
        assert cw == pw / 2 / 0.8, (name, pw, cw)
    assert r["合計"] == (48.0, 30.0)
    assert sum(pw for n, (pw, _) in r.items() if n != "合計") == 48
    assert sum(cw for n, (_, cw) in r.items() if n != "合計") == 30


def test_the_scope_added_after_the_estimate_is_listed_as_unestimated():
    sec = section()
    part = sec.split("**估算定稿之後才加入、沒有計入這 48 人週的範圍**", 1)[1].split("- **關鍵路徑**", 1)[0]
    items = [ln for ln in part.splitlines() if ln.startswith("  - ")]
    assert len(items) == len(UNESTIMATED)
    for item, key in zip(items, UNESTIMATED):
        assert key in item and "未估" in item, key
        assert not re.search(r"\d+(\.\d+)? ?人週", item), item          # no invented number
    assert "2026-10-31" in part and "不替它們填數字" in part and "BL-63 重估時必須逐項補上" in part


def test_every_unestimated_item_is_really_in_the_specification():
    spec = text("docs/08-implementation-spec.md")
    assert "### 11.20 Lite 的單機部署 profile" in spec and "### 11.21 LangGraph 相容性 spike" in spec
    assert "class JobLedger" in spec
    assert "oracle_approvals" in text("docs/02-methodology.md")
    backlog = text("docs/09-backlog.md")
    for bl in ("BL-70", "BL-75", "BL-78", "BL-79"):
        assert f"| {bl} |" in backlog, bl


def test_the_week_one_conflict_is_an_open_decision_with_a_default_that_does_not_squeeze():
    u25 = row("docs/08-implementation-spec.md", "| U-25 |")
    assert "§11.21" in u25 and "T-01–T-06" in u25 and "時間上限" in u25
    assert "不壓縮" in u25 and "順延" in u25 and "BL-63" in u25 and u25.rstrip().endswith("| M1 |")
    intro = text("docs/08-implementation-spec.md").split("### 9.2 M1 前兩週的工單", 1)[1].split("\n| # |", 1)[0]
    assert "沒有餘裕" in intro and "U-25" in intro
    tickets = re.findall(r"^\| (T-\d\d) \| ([12]) \|", text("docs/08-implementation-spec.md"), re.M)
    assert [w for _, w in tickets] == ["1"] * 6 + ["2"] * 6                 # what "twelve tickets in two weeks" means
    assert "U-25" in section() and "第一週原本已排 6 張工單" in section()


def test_the_backlog_and_the_findings_say_measured_speed_is_still_missing():
    bl = row("docs/09-backlog.md", "| BL-63 |")
    assert "待量測" in bl and "五項範圍沒有計入" in bl and "已完成" not in bl
    a6 = row("docs/evidence/findings-2026-11-22.md", "| A6 |")
    assert "⚠️ 部分處理" in a6 and "✅" not in a6
    assert "仍只能由 BL-63 量測" in a6 and "U-25" in a6 and "30，不是 29" in a6
    assert "[代理]" not in a6 and "已對原文核對" in a6
