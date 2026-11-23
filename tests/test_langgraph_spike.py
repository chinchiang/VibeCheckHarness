# SPDX-License-Identifier: Apache-2.0
"""The LangGraph compatibility spike is specified, not run (2026-11-22 review, finding D3; docs/09 BL-79).

The design keeps every authority outside the graph (job ledger, gate records, kill switch, run lock, audit de-duplication)
and marks those rules [H]: nobody has run LangGraph against them. BL-79 asked for a spike but did not say what it must
answer. docs/08 section 11.21 does now: required cases LG-01..LG-15, a pass condition and a consequence for each, a
decision rule (keep LangGraph or write a state machine; docs/08 U-24), and where it sits in the plan (before T-09;
docs/07 M1-X11 and section 1.4).

These tests hold the specification together. They do not and cannot show that any case passes: no product code exists and
the spike has not been run. One contradiction found while re-verifying is fixed and held here: SqliteSaver was called a
test-only dependency although the single-host profile uses it in production.

Each test failed before the change and passes after it (tests/mutations/langgraph_spike.json); see CONTRIBUTING.md."""
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]
HEADING = "### 11.21 LangGraph 相容性 spike（原型關卡）[H]"
ANCHOR = "08-implementation-spec.md#1121-langgraph-相容性-spike原型關卡h"
DECISIVE = ["LG-02", "LG-03", "LG-05", "LG-06", "LG-07", "LG-09", "LG-13", "LG-15"]


def text(rel):
    return (ROOT / rel).read_text(encoding="utf-8")


def section():
    s = text("docs/08-implementation-spec.md")
    assert s.count(HEADING) == 1
    return re.split(r"\n### |\n## ", s.split(HEADING, 1)[1])[0]


def cases():
    out = {}
    for ln in section().splitlines():
        if ln.startswith("| LG-"):
            cells = [c.strip() for c in ln.strip().strip("|").split("|")]
            assert len(cells) == 5, ln[:40]
            assert cells[0] not in out, cells[0]
            out[cells[0]] = cells
    return out


def row(rel, start):
    rows = [ln for ln in text(rel).splitlines() if ln.startswith(start)]
    assert len(rows) == 1, (rel, start, len(rows))
    return rows[0]


def test_every_required_case_has_a_pass_condition_and_a_consequence():
    c = cases()
    assert list(c) == [f"LG-{i:02d}" for i in range(1, 16)]
    for cid, (_, question, passes, fails, decisive) in c.items():
        assert len(question) > 20 and len(passes) > 15 and len(fails) >= 4, cid
        assert decisive in ("是", "否"), cid
    assert [cid for cid, cells in c.items() if cells[4] == "是"] == DECISIVE


def test_a_decisive_case_that_fails_leads_to_the_decision_rule_or_a_named_change():
    for cid in DECISIVE:
        fails = cases()[cid][3]
        assert "決策規則" in fails, cid


def test_the_cases_cover_the_three_questions_of_bl79_and_the_ones_it_missed():
    c = cases()
    blob = {cid: " ".join(cells[1:4]) for cid, cells in c.items()}
    for cid, needles in {
        "LG-02": ("子圖", "只前進一次"),
        "LG-03": ("唯讀", "gate_opened"),
        "LG-04": ("同一個交易",),
        "LG-05": ("N-15", "signature_invalid"),
        "LG-06": ("advisory lock", "run abort", "§11.20 的目錄檔案鎖是否涵蓋"),
        "LG-07": ("durability", "kill"),
        "LG-08": ("BudgetExceeded", "GB_budget_gate"),
        "LG-09": ("state_sha256", "IntegrityError", "vchlib.expectations"),
        "LG-10": ("encrypted: true", "E-CHECKPOINT"),
        "LG-11": ("checkpoint_keep_last", "不修改"),
        "LG-12": ("Send", "缺票"),
        "LG-13": ("帳本", "idempotency_key", "恢復流程"),
        "LG-14": ("schema_version", "migrations"),
        "LG-15": ("每個節點邊界", "hash"),
    }.items():
        for n in needles:
            assert n in blob[cid], (cid, n)


def test_both_savers_run_every_case():
    sec = section()
    assert "**每個案例在 PostgresSaver 與 SqliteSaver 上各跑一次**" in sec and "InMemorySaver 不算數" in sec
    for pin in ("langgraph 1.2.12", "langgraph-checkpoint-postgres 3.1.2", "langgraph-checkpoint-sqlite 3.1.1"):
        assert pin in sec, pin
    s71 = text("docs/08-implementation-spec.md").split("### 7.1 LangGraph checkpointer", 1)[1].split("### 7.2", 1)[0]
    for pin in ("1.2.12", "3.1.2", "3.1.1"):
        assert pin in s71, pin


def test_the_decision_rule_names_every_decisive_case_and_both_outcomes():
    sec = section()
    rule = sec.split("**決策規則**", 1)[1].split("**產出**", 1)[0]
    listed = re.findall(r"LG-\d\d", rule.split("\n2.", 1)[0])
    assert listed == DECISIVE
    assert "保留 LangGraph" in rule and "自寫的狀態機" in rule
    assert "只在 SqliteSaver 上不通過" in rule and "單機 profile" in rule
    # no passing a case by switching a safeguard off
    for n in ("不得為了通過而讓 checkpoint 成為授權依據", "取消 run 鎖", "自動重送結果不明的 job"):
        assert n in rule, n


def test_the_recovery_direction_never_lets_a_checkpoint_overwrite_the_records():
    sec = section()
    rec = sec.split("**恢復流程的方向**", 1)[1].split("**決策規則**", 1)[0]
    assert "**圖外紀錄為準**" in rec
    for n in ("Z3 job 帳本", "GateRecord", "稽核檔"):
        assert n in rec, n
    assert "不能反過來覆寫" in rec and "`FAILED`" in rec


def test_the_section_does_not_claim_the_spike_was_run():
    sec = section()
    assert "**本輪沒有執行 spike，也不宣稱任何一個案例已通過**" in sec
    assert "不對 LangGraph 的行為做新的斷言" in sec
    assert "spike 的結果不能代替它" in sec
    # the section adds no verified-evidence tag of its own
    assert "[V]" not in sec and "[E:" not in sec
    assert not list((ROOT / "docs" / "evidence").glob("*langgraph*")), "a spike report exists; update the statuses"


def test_the_plan_puts_the_spike_before_the_first_checkpointer_ticket():
    u24 = row("docs/08-implementation-spec.md", "| U-24 |")
    assert "保留 LangGraph" in u24 and "自寫的狀態機" in u24 and "§11.21" in u24 and "T-09 不開工" in u24
    assert u24.rstrip().endswith("| M1 |")
    t09 = row("docs/08-implementation-spec.md", "| T-09 |")
    assert "U-24 結案（§11.21 的 spike）" in t09 and "PostgresSaver 與 SqliteSaver" in t09
    x11 = row("docs/07-roadmap.md", "| M1-X11 |")
    assert ANCHOR in x11 and "U-24" in x11 and "沒有報告就開始 T-09" in x11
    assert "有決定性案例不通過仍保留 LangGraph" in x11
    order = row("docs/07-roadmap.md", "| M1 第一週，T-09 開工之前 |")
    assert "BL-79" in order and "M1-X11" in order and "08 §11.21" in order


def test_the_backlog_and_the_findings_say_specified_not_run():
    bl = row("docs/09-backlog.md", "| BL-79 |")
    assert ANCHOR in bl and "M1-X11" in bl and "U-24" in bl
    assert "T-09 開工之前" in bl and bl.rstrip().endswith("| 規格已訂；spike 未執行，相容性假設仍未經驗證 |")
    assert "不是同日設計決定的 D3" in bl      # the same day's design decision D3 is a different thing
    d3 = row("docs/evidence/findings-2026-11-22.md", "| D3 |")
    assert "規格已訂、spike 未執行" in d3 and "08 §11.21" in d3 and "沒有執行過 LangGraph" in d3
    assert "15 個必要案例" in d3 and len(cases()) == 15


def test_sqlitesaver_is_not_called_test_only_while_the_single_host_profile_ships_it():
    s = text("docs/08-implementation-spec.md")
    s71 = s.split("### 7.1 LangGraph checkpointer", 1)[1].split("### 7.2", 1)[0]
    assert "只是測試依賴。" not in s71 and "**單機 profile 的正式 checkpointer**" in s71
    lic = row("docs/06-security-legal-limitations.md", "| langgraph-checkpoint-sqlite 3.1.1 |")
    assert "| 只用於測試 |" not in lic and "單機 profile" in lic and "隨工具包散布" in lic
    # the profile itself still names it
    prof = row("docs/08-implementation-spec.md", "| checkpointer | SqliteSaver")
    assert "三區部署用 PostgresSaver" in prof
