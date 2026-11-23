# SPDX-License-Identifier: Apache-2.0
"""Documentation and calibration fixes of the 2026-11-22 review that are not rule changes (findings B8, B9, C7, C8, C9, D2).

B9  The holdout is used once. M-6 asked for a threshold adjustment when the holdout result was out of range ("then it
    passes"), which is tuning on the holdout. A calibration registers how often its holdout was unblinded before
    (preregistration.holdout_prior_unblindings); with a count above 0 the primary result is exploratory
    (primary_hypothesis.confirmatory false, outcome not_shown). The validator derives both (E-CAL-HYPOTHESIS).
B8  Precision depends on the corpus's defect density; docs/05 says what may and may not be claimed.
C8  The injection self-test's thresholds: docs/06 states what n = 3 per vector can show (numbers recomputed here).
C9  docs/06 section 3 gains three limitations about what a report is not (#49-#51).
C7  docs/04 lists the attack surfaces the Binding table has no row for (BL-75).
D2  LiteLLM is used as a library inside the Gateway, not as a proxy; its version is not chosen yet.

Each test failed before the change and passes after it (tests/mutations/docs_review_2026_11_22.json); see CONTRIBUTING.md."""
import copy
import pathlib
import re

import pytest

from conftest import doc
from vchlib import checks
from vchlib.checks import run_all

ROOT = pathlib.Path(__file__).resolve().parents[1]


def text(rel):
    return (ROOT / rel).read_text(encoding="utf-8")


def cal(b):
    return doc(b, "calibration.yaml").data


def hyp(b):
    c = cal(b)
    return checks.hypothesis_problems(c["config"], c["result"])


# ================================================================ B9: the holdout is used once
def test_the_example_uses_its_holdout_for_the_first_time(b):
    c = cal(b)
    assert c["config"]["preregistration"]["holdout_prior_unblindings"] == 0
    assert c["result"]["primary_hypothesis"]["confirmatory"] is True
    assert hyp(b) == [] and "E-CAL-HYPOTHESIS" not in run_all(b).codes()


def test_a_result_on_a_reused_holdout_cannot_be_confirmatory(b):
    cal(b)["config"]["preregistration"]["holdout_prior_unblindings"] = 1
    got = hyp(b)
    assert any("confirmatory True but preregistration.holdout_prior_unblindings 1 gives False" in m for m in got), got
    cal(b)["result"]["primary_hypothesis"]["confirmatory"] = False
    assert hyp(b) == []                                       # the example's outcome is already not_shown


@pytest.mark.parametrize("lo, hi, h1, h2, outcome", [
    (0.03, 0.12, True, True, "multi_family_wins"),
    (0.03, 0.12, True, False, "recall_only"),
    (-0.2, -0.05, False, None, "single_best_wins"),
])
def test_nothing_is_shown_on_a_reused_holdout(b, lo, hi, h1, h2, outcome):
    c = cal(b)
    ph = c["result"]["primary_hypothesis"]
    ph.update(ci_low=lo, ci_high=hi, delta=(lo + hi) / 2, h1=h1, h2=h2, outcome=outcome)
    assert not any("outcome" in m for m in hyp(b))            # first use: the interval decides
    c["config"]["preregistration"]["holdout_prior_unblindings"] = 2
    ph["confirmatory"] = False
    got = hyp(b)
    assert any(f"outcome {outcome!r}" in m and "give 'not_shown'" in m for m in got), got
    ph["outcome"] = "not_shown"
    assert not any("outcome" in m for m in hyp(b))


def test_a_first_use_cannot_call_itself_exploratory_or_omit_the_count(b):
    cal(b)["result"]["primary_hypothesis"]["confirmatory"] = False
    assert any("confirmatory False" in m and "gives True" in m for m in hyp(b))
    b2 = copy.deepcopy(cal(b))
    del b2["config"]["preregistration"]["holdout_prior_unblindings"]
    b2["result"]["primary_hypothesis"]["confirmatory"] = True
    assert any("holdout_prior_unblindings None gives False" in m for m in checks.hypothesis_problems(b2["config"], b2["result"]))
    del cal(b)["config"]["preregistration"]["holdout_prior_unblindings"]
    assert "E-SCHEMA" in run_all(b).codes()


def test_docs05_m6_no_longer_tunes_on_the_holdout():
    s = text("docs/05-bias-calibration.md")
    row = next(ln for ln in s.splitlines() if ln.startswith("| M-6 |"))
    assert "超出範圍時要有記錄在案的門檻調整，才算通過" not in row
    assert "這一版 M-6 **不通過**" in row and "只能在校準切分上、以新的 `calibration_version` 進行" in row
    assert "**保留切分只用一次**" in s and "`preregistration.holdout_prior_unblindings`" in s
    assert "validator 無法查證登記的次數是否屬實" in s          # what the check cannot do


# ================================================================ B8: precision depends on prevalence
def test_docs05_says_precision_does_not_transfer():
    s = text("docs/05-bias-calibration.md")
    sec = s.split("**precision 型指標依賴盛行率**", 1)[1].split("每個指標都在**保留切分**上報告", 1)[0]
    assert "只對**這份語料的缺陷密度**成立" in sec and "每個應用（與每千行）的誤報數" in sec and "沒有排入任何里程碑 [A]" in sec


# ================================================================ C8: what the injection self-test can show
def test_docs06_states_the_power_of_the_self_test_with_the_right_numbers():
    s = text("docs/06-security-legal-limitations.md")
    sec = s.split("**這些門檻能證明什麼**", 1)[1].split("**執行時機**", 1)[0]
    vectors = len(re.findall(r"^\| INJ-[A-Z]+ \|", s, re.M))
    per_vector = int(re.search(r"每個向量至少 (\d+) 個樣本", s).group(1))
    bound = lambda n: 1 - 0.05 ** (1 / n)
    assert (vectors, per_vector) == (8, 3)
    assert f"上界 **{round(bound(per_vector) * 100)}%**" in sec
    assert f"{vectors} 個向量合計 {vectors * per_vector} 個樣本 → **{bound(vectors * per_vector) * 100:.1f}%**" in sec
    need = next(n for n in range(1, 500) if bound(n) <= 0.05)
    assert need == 59 and f"需要 **{need}** 個樣本都沒有失敗" in sec
    assert "**這個設計偵測不到它要偵測的差距**" in sec and "沒有針對本工具包的 prompt 與裁決規則調整過的適應性攻擊者" in sec
    assert "**回歸用的煙霧測試**" in sec and "通過不等於「能抵抗 prompt injection」" in sec


# ================================================================ C9: what a report is not
def test_docs06_lists_the_three_outward_limitations():
    s = text("docs/06-security-legal-limitations.md")
    rows = {int(m.group(1)): m.group(0) for m in re.finditer(r"^\| (\d+) \| [^\n]*", s.split("## 3. 做不到／不承諾的事", 1)[1], re.M)}
    assert max(rows) == 51
    assert "**報告不是滲透測試報告，也不是合規證明**" in rows[49] and "PCI DSS" in rows[49]
    assert "**不偵測蓄意植入的後門與惡意開發者**" in rows[50] and "校準語料沒有對抗樣本" in rows[50]
    assert "**無法驗證 staging 等同正式環境**" in rows[51]
    cats = {ln[2]: ln for ln in s.splitlines() if re.match(r"^\| [A-D]\. ", ln)}
    assert "#49" in cats["C"] and "#50" in cats["D"] and "#51" in cats["B"]


# ================================================================ C7: what the Binding table does not cover
def test_docs04_lists_the_uncovered_attack_surfaces():
    s = text("docs/04-threat-to-testcase.md")
    sec = s.split("**這張表沒有涵蓋的類別**", 1)[1].split("這兩個 inventory 旗標", 1)[0]
    rows = [ln.split("|")[1].strip() for ln in sec.splitlines() if ln.startswith("| ") and not ln.startswith("| 類別")]
    assert rows == ["WebSocket／SSE 與自建即時通道", "OAuth／OIDC 流程", "JWT 驗證細節", "LLM 輸出的渲染外洩", "黑箱注入（Lite）"]
    assert "只能是 `MANUAL`" in sec and "不能讓「Binding 表每一列都測了」被讀成「常見攻擊面都測了」" in sec
    # 2026-11-23 (BL-75): the rows were added or extended; the list now says what is STILL not covered and names the rows
    # that exist (tests/test_binding_table.py). The first version said none of the five had a row, which was wrong
    for cited in ("「Realtime 訂閱隔離」", "「OAuth／OIDC 流程」", "「JWT 處理」", "「非 LLM 的 XSS」"):
        assert cited in sec and cited.strip("「」") in s.split("**這張表沒有涵蓋的類別**", 1)[0], cited    # the rows it points at exist
    bl = next(ln for ln in text("docs/09-backlog.md").splitlines() if ln.startswith("| BL-75 |"))
    assert "PKCE" in bl and "| 已補列；全部未實作" in bl and "| 待辦" not in bl


# ================================================================ D2: LiteLLM is a library in the Gateway
def test_docs03_and_08_agree_on_how_litellm_is_used():
    a03, a08 = text("docs/03-system-architecture.md"), text("docs/08-implementation-spec.md")
    assert "**只有 `gateway` 可以 import `litellm`**" in a08
    assert "token 預算由 LiteLLM proxy 追蹤" not in a03
    assert "**LiteLLM 以函式庫方式在 Gateway 行程內使用，不另起 LiteLLM proxy 行程**" in a03
    assert "**版本尚未選定**" in a03 and "選定前不能宣稱「已鎖版本」" in a03
    lic = next(ln for ln in text("docs/examples/licenses.yaml").splitlines() if "component: LiteLLM" in ln)
    assert "usage: reference" in lic                          # the statement in 03 about this row is true


# ================================================================ later additions of the same review (B3, A4, D1, D3)
def test_docs05_lists_the_adversarial_subset_as_not_built():
    s = text("docs/05-bias-calibration.md")
    row = next(ln for ln in s.splitlines() if ln.startswith("| A：對抗子集"))
    assert "**尚未建立**" in row and "宣稱已檢查權限的註解" in row and "09 BL-77" in row
    cells = [c.strip() for c in row.strip().strip("|").split("|")]
    assert len(cells) == 4 and cells[3].startswith("否")        # not part of the primary hypothesis n


def test_the_single_host_profile_does_not_downgrade_the_data_class_for_the_user():
    s = text("docs/08-implementation-spec.md")
    row = next(ln for ln in s.splitlines() if ln.startswith("| 資料等級與可用模型 |"))
    assert "未標記的 repo 仍是 C 級" in row and "**預設情況下沒有雲端模型可用**" in row
    assert "`vibecheck init` 不替使用者降級" in row and "都不選就不產生委任設定" in row
    for choice in ("資料等級宣告為 P", "使用自架模型", "只跑確定性最小切片"):
        assert choice in row, choice


def test_the_open_design_items_are_on_the_backlog():
    s = text("docs/09-backlog.md")
    for bl, needle in (("BL-77", "對抗子集"), ("BL-79", "LangGraph checkpoint 的 spike")):
        row = next(ln for ln in s.splitlines() if ln.startswith(f"| {bl} |"))
        assert needle in row and "| 待辦" in row, bl
    # BL-78 was specified on 2026-11-23 (tests/test_interface_contracts.py); it stays on the backlog as not implemented
    row = next(ln for ln in s.splitlines() if ln.startswith("| BL-78 |"))
    assert "fencing token" in row and "| 介面已訂；未實作，數值待實測 |" in row and "已完成" not in row
