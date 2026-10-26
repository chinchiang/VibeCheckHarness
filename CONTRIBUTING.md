# 貢獻指南

本 repo 的測試、建置與驗證一律直接用 `python` 執行；指令見 [README「快速驗證本 repo 的資料模型」](README.md#快速驗證本-repo-的資料模型)。

## 修正錯誤一定要有回歸測試

所有宣稱「修好」的錯誤，都必須經過回歸測試的驗證：

1. **先寫測試，重現錯誤**：在修正前的程式碼上執行，測試必須失敗，而且失敗的原因就是要修的那個錯誤。
2. **再修正**：同一個測試在修正後必須通過。
3. **證明測試抓得到這個錯誤**：一次只把一項修正換回舊程式碼，重跑測試，確認只有對應的測試失敗；換回修正版後全部通過。一次修多個錯誤時，每一項都要各自驗證。把每項突變寫進 `tests/mutations/<name>.json`（檔案、原文、換回的文字、對應測試的 `-k`），以 `python tools/mutation_check.py tests/mutations/<name>.json` 執行；清單留在 repo 裡，之後 `--anchors-only` 能檢查它是否過期（v0.7，審查 r8 M8）。
4. **寫進 PR 說明**：列出每個錯誤與對應的測試名稱，並說明驗證方式（例如「拿掉第 N 行的條件，`test_x` 失敗；恢復後通過」）。
5. 放寬限制的修正（讓原本被誤判的資料通過），另外要有一個測試確認沒有放寬過頭：原本該報錯的情況仍然報錯。

沒有回歸測試的修正，只能說「已修改」，不能說「已修好」。

## 提交前

- `python tools/sign_examples.py`：改了範例或推導規則時，重算到穩定為止（TEST ONLY 簽章）。
- `python tools/validate_schemas.py`、`python -m pytest tests`、`python tools/check_doc_links.py`，以及兩個 generator 的 `--check`，全部通過才推送。相依套件以 `requirements.lock`（CI 用的精確版本）安裝；升級套件時重產 lock（檔頭有指令）。PR 說明依 `.github/pull_request_template.md` 的檢查表填寫。
- 改變 validator 行為時，同步更新 `docs/schemas/README.md` 的錯誤碼表、相關設計文件與 `CHANGELOG.md`。
