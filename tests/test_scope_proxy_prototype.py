# SPDX-License-Identifier: Apache-2.0
"""The Scope Proxy prototype gate is a numbered case table in two stages (2026-11-22 review, finding D5; re-verified
2026-11-25).

D5 said the Scope Proxy is a safety-critical component whose intercepting proxy has not been chosen (docs/08 U-13) and
whose prototype gate sits before MVP-2 (docs/09 BL-32). The three facts hold. Re-verification found two things a
document can fix:

  - an ordering conflict: the MVP-1 exit criterion is example A, whose adapter is `playwright:api`, but the gate that
    checks Playwright through the proxy was scheduled before MVP-2, and section 11.7 says an adapter is enabled only
    after its cases pass;
  - the required cases were one paragraph, so "every required case" (docs/07 MVP2-X5) had nothing to be checked against.

The gate is now sixteen numbered cases in two stages with a decision rule. Nothing was run: the section still says no
product is chosen and no case has passed, and it asserts nothing new about any proxy or tool.

Each test failed before the change and passes after it (tests/mutations/scope_proxy_prototype.json); see
CONTRIBUTING.md."""
import json
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]
STAGE_ONE = [f"SP-{i:02d}" for i in range(1, 9)]
STAGE_TWO = [f"SP-{i:02d}" for i in range(9, 17)]
# every kind of case the paragraph this table replaced named, and the case that now carries it
FROM_THE_OLD_PARAGRAPH = {
    "SP-01": "Executor", "SP-02": "playwright:api", "SP-15": "ZAP", "SP-09": "信任根",
    "SP-10": "SNI、`Host`、`:authority`", "SP-04": "路徑編碼與正規化差異", "SP-05": "重複或衝突的長度標頭",
    "SP-06": "越界轉址", "SP-11": "DNS 答案改變", "SP-12": "HTTP/2 多 stream 的預算",
    "SP-13": "WebSocket 的核准腳本與上限", "SP-14": "SSE 上限", "SP-07": "租約失效", "SP-08": "繞過出口",
}


def text(rel):
    return (ROOT / rel).read_text(encoding="utf-8")


def gate():
    s = text("docs/08-implementation-spec.md")
    sec = s.split("### 11.7 Scope Proxy 實作", 1)[1].split("\n### ", 1)[0]
    assert sec.count("**選型前的原型關卡**[H]：") == 1
    return sec.split("**選型前的原型關卡**[H]：", 1)[1]


def cases():
    out = {}
    for ln in gate().splitlines():
        if ln.startswith("| SP-"):
            cells = [c.strip() for c in ln.strip().strip("|").split("|")]
            assert len(cells) == 5, ln[:40]
            assert cells[0] not in out, cells[0]
            out[cells[0]] = cells
    return out


def row(rel, start):
    rows = [ln for ln in text(rel).splitlines() if ln.startswith(start)]
    assert len(rows) == 1, (rel, start, len(rows))
    return rows[0]


def test_every_required_case_is_numbered_with_a_pass_condition_and_a_consequence():
    c = cases()
    assert list(c) == STAGE_ONE + STAGE_TWO
    for cid, (_, question, passes, fails, stage) in c.items():
        assert len(question) > 12 and len(passes) > 12 and len(fails) >= 5, cid
        assert stage in ("一", "二"), cid
    assert [cid for cid, cells in c.items() if cells[4] == "一"] == STAGE_ONE


def test_nothing_the_old_paragraph_required_was_dropped():
    c = cases()
    for cid, phrase in FROM_THE_OLD_PARAGRAPH.items():
        assert phrase in c[cid][1], (cid, phrase)
    g = gate()
    assert "每個允許的案例要收到預期回應；每個禁止的案例要有拒絕紀錄，且越界接收器零命中" in g
    forbidden = [cid for cid, cells in c.items() if "越界接收器零命中" in cells[2]]
    assert forbidden == ["SP-03", "SP-06", "SP-08", "SP-10", "SP-11"]


def test_stage_one_is_what_a_local_plain_http_target_needs_and_no_more():
    c = cases()
    for cid in STAGE_ONE:
        joined = " ".join(c[cid][1:4])
        for later in ("TLS", "SNI", "HTTP/2", "WebSocket", "SSE", "ZAP", "DNS"):
            assert later not in joined, (cid, later)
    assert "playwright:api" in c["SP-02"][1] and "`playwright:api` 不啟用（決策規則 1）" == c["SP-02"][3]
    assert "借用另一個 job 的白名單被拒絕" in c["SP-02"][2]
    assert "SP-01–SP-08" in c["SP-16"][1] and "HTTPS" in c["SP-16"][1] and c["SP-16"][4] == "二"
    g = gate()
    assert "MVP-1 的 B4 開工之前" in g and "MVP1-X5" in g and "MVP-2 staging 之前" in g and "MVP2-X5" in g
    assert "它的 adapter 是 `playwright:api`" in g and "不能等到 MVP-2" in g
    example = json.loads(text("docs/schemas/examples/testcase.idor.example.json"))
    assert example["tool_binding"]["adapter"] == "playwright:api"          # why stage one exists


def test_the_decision_rule_keeps_every_existing_requirement():
    rule = gate().split("**決策規則**（U-13 依此結案）：", 1)[1].split("**產出**", 1)[0]
    items = [ln for ln in rule.splitlines() if re.match(r"\d\. ", ln)]
    assert [ln[0] for ln in items] == ["1", "2", "3", "4", "5"]
    assert "第一段（SP-01–SP-08）全部通過，MVP-1 才能啟用 `playwright:api`" in items[0]
    assert "只能使用 Executor 自己的 HTTP 用戶端" in items[0] and "MVP1-X1 不算通過" in items[0]
    assert "Executor 的必要 HTTP 工作流" in items[1] and "沒有通過就不能進 MVP-2" in items[1]
    assert "標為不支援或 `MANUAL`" in items[2] and "**禁止改用直連或關閉 TLS 驗證**" in items[2]
    assert "只在它的案例通過後啟用" in items[2]
    assert "U-13 不結案" in items[3] and "回報使用者" in items[3] and "不預先設計" in items[3]
    assert "不允許以放寬本節的規則通過任何案例" in items[4]
    for kept in ("per-job 身分", "路徑正規化", "越界轉址", "重新解析 DNS"):
        assert kept in items[4], kept
    for cid, cells in cases().items():                                     # no case may be passed by going direct
        assert "直連" not in cells[3] or "不得" in cells[3] or "不會" in cells[3], cid


def test_the_section_claims_no_result_and_no_choice():
    g = gate()
    assert "**本輪不選定產品，也不宣稱原型已通過，下表沒有任何一個案例執行過**" in g
    assert "不對任何代理或工具的行為做新的斷言" in g
    assert "U-13 依這份證據結案，之後才能宣稱實際的相容範圍" in g
    assert "原型的結果不能代替它們" in g and "N-17、N-18、N-32、N-33" in g
    spec = text("docs/08-implementation-spec.md")
    assert "**攔截式 proxy 的選型**仍未決定（§10 U-13）" in spec and "**尚未選定**" in spec
    for cells in cases().values():
        assert "已通過" not in " ".join(cells) and "✅" not in " ".join(cells)


def test_the_plan_puts_stage_one_before_the_black_box_work_of_mvp_1():
    x5 = row("docs/07-roadmap.md", "| MVP1-X5 |")
    assert "SP-01–SP-08" in x5 and "才啟用 `playwright:api`" in x5 and "MVP1-X1" in x5
    assert "第一段有案例未通過仍啟用 `playwright:api`" in x5 and "直連" in x5
    x25 = row("docs/07-roadmap.md", "| MVP2-X5 |")
    assert "第二段" in x25 and "SP-09–SP-16" in x25 and "MVP1-X5" in x25
    assert "有必要案例未通過仍進 MVP-2" in x25 and "改用直連或關閉 TLS 驗證" in x25
    before_mvp1 = row("docs/07-roadmap.md", "| MVP-1 黑箱執行之前 |")
    assert "BL-32 Scope Proxy 原型關卡第一段（MVP1-X5）" in before_mvp1 and "SP-01–SP-08" in before_mvp1
    before_mvp2 = row("docs/07-roadmap.md", "| MVP-2 staging 之前 |")
    assert "原型關卡第二段（MVP2-X5）" in before_mvp2 and "SP-09–SP-16" in before_mvp2
    criteria = re.findall(r"^\| (MVP[12]-X\d+) \|", text("docs/07-roadmap.md"), re.M)
    assert criteria == [f"MVP1-X{i}" for i in range(1, 6)] + [f"MVP2-X{i}" for i in range(1, 6)]


def test_u13_the_backlog_and_the_findings_agree_and_none_says_done():
    u13 = row("docs/08-implementation-spec.md", "| U-13 |")
    assert "已決定" not in u13 and "依 §11.7 的原型報告" in u13
    assert "只服務 Executor 自己的 HTTP 用戶端" in u13
    assert "`playwright:api` 只在 §11.7 原型關卡第一段（SP-01–SP-08）通過後啟用" in u13
    bl = row("docs/09-backlog.md", "| BL-32 |")
    assert "SP-01–SP-16" in bl and "MVP1-X5、MVP2-X5" in bl and "原型未執行" in bl
    assert "第一段在 MVP-1 的 B4 之前；第二段在 MVP-2 之前" in bl
    d5 = row("docs/evidence/findings-2026-11-22.md", "| D5 |")
    assert "⚠️ 規格已訂、原型未執行" in d5 and "✅" not in d5 and "❌" not in d5
    assert "[代理]" not in d5 and "已對原文核對" in d5 and "沒有執行過任何代理或工具" in d5
    assert "選型仍未決定（U-13）" in d5 and "`playwright:api`" in d5 and "MVP1-X5" in d5
    assert "SP-01–SP-08" in d5 and "SP-09–SP-16" in d5
