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
U-25 was decided by the user on 2026-11-24: one engineer on the spike, at most five person-days, the week-one tickets
slip by at most that much, and reaching the limit means stop and report -- never fewer cases or a weaker pass rule.
On 2026-11-25 the Scope Proxy prototype gate (BL-32) joined the list: no row of the estimate mentions it, its first
stage moved in front of the black-box work of MVP-1 (finding D5), and neither stage has a time limit.

Each test failed before the change and passes after it (tests/mutations/effort_estimate.json); see CONTRIBUTING.md."""
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]
UNESTIMATED = ("BL-70", "oracle_approvals", "BL-78", "BL-75", "BL-79", "BL-32")


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
    gate = items[-1]
    assert "SP-01–SP-16" in gate and "上表沒有任何一列提到它" in gate and "兩段都沒有時間上限" in gate
    assert "第一段（SP-01–SP-08）提前到 MVP-1 的 B4 開工之前（MVP1-X5）" in gate


def test_every_unestimated_item_is_really_in_the_specification():
    spec = text("docs/08-implementation-spec.md")
    assert "### 11.20 Lite 的單機部署 profile" in spec and "### 11.21 LangGraph 相容性 spike" in spec
    assert "class JobLedger" in spec
    assert "oracle_approvals" in text("docs/02-methodology.md")
    backlog = text("docs/09-backlog.md")
    assert "| SP-16 |" in spec and "| MVP1-X5 |" in text("docs/07-roadmap.md")
    for bl in ("BL-32", "BL-70", "BL-75", "BL-78", "BL-79"):
        assert f"| {bl} |" in backlog, bl


def test_the_week_one_conflict_is_decided_with_a_limit_that_does_not_squeeze():
    u25 = row("docs/08-implementation-spec.md", "| U-25 |")
    assert "**已決定（2026-11-24，使用者）**" in u25 and "§11.21" in u25 and "T-01–T-06" in u25
    assert "時間上限是 5 人日" in u25 and "一位工程師專做" in u25 and "最多順延 5 人日" in u25
    assert "停止並回報" in u25 and "由使用者決定延長或改為自寫的狀態機" in u25
    assert "不得以減少案例或放寬通過條件來趕上限" in u25
    assert "不壓縮" in u25 and "BL-63" in u25 and u25.rstrip().endswith("| M1 |")
    spec = text("docs/08-implementation-spec.md")
    intro = spec.split("### 9.2 M1 前兩週的工單", 1)[1].split("\n| # |", 1)[0]
    assert "沒有餘裕" in intro and "U-25" in intro and "上限 5 人日" in intro and "最多順延 5 人日" in intro
    tickets = re.findall(r"^\| (T-\d\d) \| ([12]) \|", spec, re.M)
    assert [w for _, w in tickets] == ["1"] * 6 + ["2"] * 6                 # what "twelve tickets in two weeks" means
    sec = section()
    assert "U-25 已決定（2026-11-24）" in sec and "第一週原本已排 6 張工單" in sec
    assert "這是上限，不是估算" in sec and "實際用量由 BL-63 回填" in sec


def test_the_spike_section_states_the_limit_and_what_it_may_not_change():
    spike = text("docs/08-implementation-spec.md").split("### 11.21 LangGraph 相容性 spike", 1)[1].split("\n### ", 1)[0]
    how = spike.split("**做法**", 1)[1].split("**必要案例**", 1)[0]
    limit = [ln for ln in how.splitlines() if ln.startswith("- 時間上限：")]
    assert len(limit) == 1
    assert "5 人日" in limit[0] and "一位工程師專做" in limit[0] and "§10 U-25" in limit[0]
    assert "停止" in limit[0] and "由使用者決定延長或改為自寫的狀態機" in limit[0] and "T-09 仍不開工" in limit[0]
    assert "上限不改變必要案例的數目、通過條件與決策規則" in limit[0]
    assert len(re.findall(r"^\| LG-\d\d \|", spike, re.M)) == 15         # the limit did not shrink the case list


def test_the_backlog_and_the_findings_say_measured_speed_is_still_missing():
    bl = row("docs/09-backlog.md", "| BL-63 |")
    assert "待量測" in bl and "五項範圍沒有計入" in bl and "已完成" not in bl
    assert "BL-32 的 Scope Proxy 原型關卡，共六項" in bl
    a6 = row("docs/evidence/findings-2026-11-22.md", "| A6 |")
    assert "⚠️ 部分處理" in a6 and "✅" not in a6
    assert "仍只能由 BL-63 量測" in a6 and "U-25" in a6 and "30，不是 29" in a6
    assert "上限 5 人日" in a6 and "待決定" not in a6
    assert "[代理]" not in a6 and "已對原文核對" in a6
