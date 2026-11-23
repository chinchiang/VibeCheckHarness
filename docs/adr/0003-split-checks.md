---
status: accepted
---

# checks.py 拆成平面模組，一次搬一塊

`tools/vchlib/checks.py` 有 5,841 行，24 個檢查群組與全部 331 個錯誤碼都在這一個檔案（[2026-11-22 審查](../evidence/findings-2026-11-22.md) 的發現 E8）。當時的判斷是不拆：純重構、沒有行為收益，而且將近一半的突變錨點指向這個檔案。使用者之後決定處理，做法如下。

- **`checks.py` 留作門面**：`GROUPS`、`quarantine`、`run_all` 與還沒搬走的群組留在原處；群組的數量（24）與順序不變，因為回報 issue 的順序由它決定。
- **搬出去的是 `tools/vchlib/` 下的平面模組，不是 `checks/` 子套件。** `tools/build_error_table.py` 與型別棘輪測試都以 `glob("*.py")` 掃這個目錄，不遞迴；放進子套件的錯誤碼會從錯誤碼表消失。
- **共用基礎在 `report.py`**：`Issue`、`Report`、`doc_guard`、`ts`、格式檢查器與多個群組共用的常數。檢查群組的模組命名為 `checks_<主題>.py`。
- **依賴方向**沿用 [ADR 0001](0001-verdict-derivation-module.md)：`derive ← context ← calibration ← verdict ← expectations ← checks`。`report` 只依賴 `context` 與 `timeutil`；`checks_*` 只被 `checks`（或彼此）匯入，不被上述任何模組匯入。
- **原文搬移，不留 re-export。** 呼叫端改用新路徑（`report.Report`、`report.FINAL_STATUSES`）；`run_all` 仍在 `checks`。
- **新模組必須通過 mypy。** 型別棘輪（`tests/test_typing_ratchet.py`）不允許豁免清單變長，所以搬出去的程式要先修掉型別錯誤；只改型別標註或加有理由的 `type: ignore`，不改行為。

## 每次搬移都要處理的五件事

1. **突變清單**：`file` 指向 `checks.py` 的突變，函式搬走後要改 `file`；`old` 在新檔中必須仍然只出現一次；`new` 若引用新模組看不到的名稱會變成 NameError（判為 VERIFY 而不是 CAUGHT）。
2. **Monkeypatch**：測試 patch `checks_integrity.JCS_VECTORS`、`checks_integrity.jcs`（PR-D2 之前在 `checks`）、`checks.run_start`、`checks.result_controls`。使用這些名稱的函式搬走時，patch 的目標要跟著改，並確認拿掉 patch 後該測試會失敗——否則 patch 失效而測試照樣通過。
3. **`tests/test_seal.py`** 以 AST 確認 checker 不使用重新簽章的函式；它掃 `checks*.py` 與 `report.py`，新模組照這個命名就會被涵蓋。
4. **ruff 的 `per-file-ignores`** 掛在檔名上：`pipeline_checks` 的 F841 搬走時，ignore 要跟著搬。
5. **文件中的程式名稱**只同步引用，不動規則文字；歷史審查紀錄不改。

## 驗收（純重構的等價證據，CONTRIBUTING「規格凍結」）

- `run_all` 對主範例、四個變體與一份刻意弄壞的 bundle 回報的 issue（等級、錯誤碼、位置、訊息、順序）、各群組的檢查數，搬移前後逐筆相同。
- `sign_examples.py` 重算後 `docs/` 沒有差異；`build_variants.py --check`、`build_error_table.py --check` 通過（錯誤碼仍是 331 個）。
- 完整 pytest 通過；搬移所涉及的突變清單在搬移前後各完整執行一次，逐項結果相同。

## Consequences

- **PR-D0**（2026-11-23）：`report.py`（共用基礎）與 `checks_config.py`（licenses、crosswalk、LLM-facing schemas、toolkit 四個群組，約 100 行、14 個突變）。`checks.py` 由 5,841 行減為約 5,560 行。簽章 helpers 這次沒搬：它們依賴定義在 ROE 段的 `MAX_CLOCK_SKEW` 與 `decision_time`。
- **PR-D1**（2026-11-23）：`checks_calibration.py`（`g_calibration` 與它的 21 個函式、常數，544 行、75 個突變）。`checks.py` 減為約 5,020 行。為通過 mypy：`calibration.CAL_POLICY` 標註為 `dict[str, Any]`，另在 14 行加 `type: ignore`（都是上方已用 `num(...)` 或 schema 驗過、mypy 追不到的比較與呼叫）；其中 3 行原本是多行突變錨點的結尾，錨點改為不含行尾。`g_verdicts` 用到的 `BOUND_CLAIM_RE` 由 `checks` 匯入。
- **PR-D2**（2026-11-23）：`checks_integrity.py`（schemas、JCS、derived、key registry、persons 五個群組與 `JCS_VECTORS`、`person_refs`，243 行、30 個突變）。`checks.py` 減為約 4,790 行。搬走的程式不依賴 `checks` 中任何其他名稱。`g_signatures` 沒有搬：它與簽章 helpers 一起留到 ROE 那一步。為通過 mypy 在 `g_jcs` 的兩行加 `type: ignore`（選用的 `rfc8785` 模組設為 `None`、把向量傳給 `rfc8785.dumps`）；其中一行是突變錨點的結尾，錨點改為不含行尾。三個測試檔的 patch 目標由 `checks` 改為 `checks_integrity`。
- **PR-D3**（2026-11-23）：`checks_engagement.py`（`g_engagement` 與它的 12 個函式、常數，加上委任設定的存取函式 `profile`、`deployment`、`deployment_problems`、`consolidation_person`、`SINGLE_HOST`、`ANCHOR_LABEL`，314 行）與 `checks_models.py`（`reachable_models`、`g_models`，209 行）；60 個突變。`checks.py` 減為約 4,290 行。這一步有雙向相依：`g_engagement` 需要原本定義在 gates 段的 `deployment_problems`，而留下的群組用到 `profile`（11 處）、`consolidation_person`、`deployment`、`missing_jurisdictions`、`cross_border_declared`——所以存取函式跟著 engagement 搬，`checks` 從新模組匯入它實際使用的名稱（不是 re-export）。`ENGAGEMENT_GATES`、`ROE_GATES` 移到 `report.py`。`checks_engagement` 從 `checks_models` 匯入 `reachable_models`；兩者都不匯入 `checks`。為通過 mypy 加了 10 行 `type: ignore`（都是上方 `R.check(...)` 已經擋掉 `None`、mypy 追不到的 `.get`），沒有突變錨點受影響。
- 之後的順序（由易到難，每個另開 PR）：ROE 與簽章 helpers、gates、runs 與 testcases、W4／verdicts、trace、audit。越後面耦合越深、型別錯誤越多（audit 有 38 個）。
- 沒有排定完成時間；每一步都可以停在那裡，`checks.py` 仍然完整可用。
