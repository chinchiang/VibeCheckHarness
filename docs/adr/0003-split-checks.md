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
2. **Monkeypatch**：測試 patch `checks_integrity.JCS_VECTORS`、`checks_integrity.jcs`（PR-D2 之前在 `checks`）、`checks_gates.run_start`（PR-D5 之前在 `checks`）、`checks_runs.result_controls`（PR-D6 之前在 `checks`）。使用這些名稱的函式搬走時，patch 的目標要跟著改，並確認拿掉 patch 後該測試會失敗——否則 patch 失效而測試照樣通過。
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
- **PR-D4**（2026-11-23）：`checks_signatures.py`（簽章 helpers、`g_signatures`，加上 `MAX_CLOCK_SKEW`、`decision_time`，231 行）與 `checks_roe.py`（`g_roe`、`legal`、平台與種子清單規則、`job_span`、`g4_latest_decisions`、`expected_gaps`、`proven_reads`、`path_shape` 等，493 行）；43 個突變。`anchored_seqs` 移到 `report.py`。`checks.py` 減為約 3,600 行。`path_shape` 原計畫放 `report.py`，但它是 `safety.path_shape` 的別名，而 `report` 只能依賴 `context` 與 `timeutil`，所以留在 `checks_roe`。`checks_roe` 匯入 `checks_engagement`（存取函式）與 `checks_signatures`（`silent_verify`）；`checks_signatures` 不匯入任何檢查模組。為通過 mypy：13 行 `type: ignore`，另有兩處只加型別標註（`SKIP_GAP_KIND: dict`、`expected_gaps` 的 `out: dict`——那一行以反斜線續行，放不下註解）。
- **PR-D5**（2026-11-23）：`checks_gates.py`（`g_gates` 與 `oracle_approval_problems`、`gate_sod`、`g5_g4_link`、`carried_decisions`、`opened_time`、兩個常數，加上 `g5_escalation` 與 `run_start`，365 行）；28 個突變。`checks.py` 減為約 3,250 行。`g_gates` 需要 `g5_escalation`，它又需要 `run_start`，所以兩者一起搬；`run_manifest`、`g_feedback`、`g_report_withdrawal` 仍用 `run_start`，由 `checks` 從新模組匯入。測試 patch 的 `checks.run_start` 改為 `checks_gates.run_start`（被 patch 的是 `g5_escalation` 看到的那個名稱；該測試斷言 patch 之後才會升級，patch 失效就會失敗）。為通過 mypy 加了 21 行 `type: ignore`，沒有突變錨點受影響。
- **PR-D6**（2026-11-23）：`checks_runs.py`（`g_runs` 與 runs 段全部，加上只有它使用的 `s2_not_run`、`snapshot_audit`、`S2_RAN_STATES`、`S2_END_STATES`、`G5_SKIP_OUTCOME` 與 audit 段的 `JOB_RAN_STATES`，682 行）與 `checks_testcases.py`（`g_testcases`、`g_feedback`、`g_report_withdrawal`、`tool_binding_rules`、`access_cells_check`、`feedback_suppression`、`feedback_record_event`，加上 misc 段的 `access_matrix_cells`，348 行）；79 個突變。`checks.py` 減為約 2,260 行。兩個新模組互不匯入；各自匯入 `checks_engagement`、`checks_gates`、`checks_roe`、`checks_signatures`。`checks` 不再使用的匯入（`decision_time`、`expected_gaps`、`run_start`、`consolidation_person` 等）隨之移除，所以拆分測試改為斷言「搬走的名稱只定義一次、門面不重新定義」，不再要求門面一定匯入它們。測試 patch 的 `checks.result_controls` 改為 `checks_runs.result_controls`。為通過 mypy 加了 20 行 `type: ignore`；其中一行是 `zdr_and_cname.json` 一個兩行錨點的第一行，錨點改為含該註解。
- **PR-D7**（2026-11-23）：`checks_audit.py`（`g_audit` 與 audit 段的 12 個函式、12 個常數，812 行）；76 個突變。`checks.py` 減為約 1,470 行。這一段不需要 `checks` 中其他段的名稱，其他段也不用它，所以原訂順序（W4／verdicts 在前）改為先搬它。它匯入 `checks_engagement`、`checks_runs`、`checks_signatures`；沒有任何檢查模組匯入它。為通過 mypy 加了 27 行 `type: ignore`（原先估計 38 個錯誤，實際 30 個、分布在 27 行），沒有突變錨點受影響。文件中的 `checks.RUN_TRANSITIONS`、`checks.G1_GATED_NODES` 改為 `checks_audit.…`，`r13_external.json` 一個錨定該文件字串的突變同步。
- **PR-D8**（2026-11-24）：`checks_w4.py`（`g_w4_testcases`、`w4_coverage`、`w4_execution`，169 行）、`checks_verdicts.py`（`g_verdicts`、`verdict_chains`、`trace_text_problems`、`max_vote_round`、`weighted_vote_counts` 與 4 個 `TRACE_*` 常數，272 行）、`checks_trace.py`（`g_trace` 與追溯段全部，加上 `_tool_of`，718 行）；47 個突變。`checks.py` 減為 355 行。W4 與裁決互不相依，所以各自一個模組。兩段原本互相依賴的只有兩個小函式：`_tool_of` 跟著唯一的使用者 `cluster_origin` 搬到 `checks_trace`，`checks_w4` 再從 `checks_trace` 匯入 `inventory_of_run`，相依只剩一個方向。`pyproject.toml` 的 F841 豁免跟著 `pipeline_checks` 從 `checks.py` 改掛到 `checks_trace.py`。測試 patch 的 `checks.adj.adjudicate` 改為 `checks_verdicts.adj.adjudicate`（門面不再匯入 `adjudicate`）。為通過 mypy 加了 42 行 `type: ignore`；其中兩行是突變錨點的第一行（`r14_verdict.json`、`rule_v016.json` 各一個），錨點改為含該註解。另外補上 PR-D5 漏掉的文件名稱：`docs/02`、`docs/schemas/README.md`、suspend 變體的 README 中的 `checks.g5_escalation` 改為 `checks_gates.g5_escalation`。
- **拆分到此為止**：24 個群組已搬出 23 個。`checks.py` 留下門面（`GROUPS`、`quarantine`、`run_all`、輸入形狀檢查）與 `g_misc`（DFD、報告、自測、checkpoint；它彙整其他群組的結果，與 `run_all` 放在一起）。`g_misc` 要不要另外搬出去沒有排定；不搬也不影響任何一條規則。
- 每一步都可以停在那裡，`checks.py` 始終完整可用；這九步（PR-D0–D8）各自有等價證據，紀錄在上面與 CHANGELOG。
