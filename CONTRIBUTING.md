# 貢獻指南

本 repo 的測試、建置與驗證一律直接用 `python` 執行；指令見 [README「快速驗證本 repo 的資料模型」](README.md#快速驗證本-repo-的資料模型)。

## 規格凍結（第十二輪第二次外部審查起）

設計規格（`docs/00`～`09`、schema、validator 的規則）在第十二輪第二次外部審查的 PR 合併後**凍結**，接下來進入 MVP-0 的實作。之後的規格修改只接受兩種：

1. **實作中發現的矛盾或缺口**：寫明是哪個實作步驟發現的；
2. **外部審查或內部審查核實成立的缺陷**：附重現方式；
3. **審查核實成立、經使用者決定的設計變更**（第十四輪起明列；例如第十三輪的 `hosting` 必填欄位與 `n_apps`、第十四輪的 W4 事先登記與帶入叢集不投票）：審查紀錄記下決定的選項與理由，CHANGELOG 標「使用者決定」。

三種都照下一節的規則附回歸測試。新的設計想法記入 [09 待辦清單](docs/09-backlog.md)，不直接改規格。

## 修正錯誤一定要有回歸測試

所有宣稱「修好」的錯誤，都必須經過回歸測試的驗證：

1. **先寫測試，重現錯誤**：在修正前的程式碼上執行，測試必須失敗，而且失敗的原因就是要修的那個錯誤。
2. **再修正**：同一個測試在修正後必須通過。
3. **證明測試抓得到這個錯誤**：一次只把一項修正換回舊程式碼，重跑測試，確認只有對應的測試失敗；換回修正版後全部通過。一次修多個錯誤時，每一項都要各自驗證。把每項突變寫進 `tests/mutations/<name>.json`（檔案、原文、換回的文字、對應測試的 `-k`），以 `python tools/mutation_check.py tests/mutations/<name>.json` 執行；清單留在 repo 裡，之後 `--anchors-only` 能檢查它是否過期（v0.7，審查 r8 M8）。工具只在**選到的測試在原始碼上全部通過、突變後至少一個斷言失敗且沒有收集或匯入錯誤**時才算 `CAUGHT`。「斷言失敗」是 junit 報告中 `<failure>` 的訊息以 `assert `、`AssertionError` 或 `Failed:`（`pytest.fail`／`pytest.raises`）開頭；測試本體中其他例外（`RuntimeError`、`KeyError`…）pytest 也計入 `failures`，但不是斷言抓到的，算 `VERIFY`（第十二輪外部審查）；`-k` 選不到測試、用法錯誤、收集錯誤、基準本來就失敗都是 `VERIFY`（結束碼 1），不是成功（外部審查，`tests/test_mutation_check.py`）。
4. **寫進 PR 說明**：列出每個錯誤與對應的測試名稱，並說明驗證方式（例如「拿掉第 N 行的條件，`test_x` 失敗；恢復後通過」）。
5. 放寬限制的修正（讓原本被誤判的資料通過），另外要有一個測試確認沒有放寬過頭：原本該報錯的情況仍然報錯。

沒有回歸測試的修正，只能說「已修改」，不能說「已修好」。

## 提交前

- `python tools/sign_examples.py`：改了範例或推導規則時，重算到穩定為止（TEST ONLY 簽章）；接著 `python tools/build_variants.py` 重建變體 bundle。
- `python tools/validate_schemas.py`、`python -m pytest tests`、`python tools/check_doc_links.py`，以及四個 generator（證據帳本、參考文獻、錯誤碼表、變體 bundle）的 `--check`，全部通過才推送。相依套件以 `requirements.lock`（CI 用的精確版本）安裝；升級套件時重產 lock（檔頭有指令）。PR 說明依 `.github/pull_request_template.md` 的檢查表填寫。
- 改變 validator 行為時，同步更新 `docs/schemas/README.md` 的錯誤碼表、相關設計文件與 `CHANGELOG.md`。
