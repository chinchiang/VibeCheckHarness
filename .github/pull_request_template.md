<!-- 依 CONTRIBUTING.md：宣稱「修好」的錯誤都要有回歸測試。沒有回歸測試的修正只能寫「已修改」。 -->

## 變更

<!-- 修了什麼、為什麼；對應的審查發現或待辦編號 -->

## 回歸測試驗證

- [ ] **先失敗**：新測試在修正前的 commit `<sha>` 上失敗，失敗的原因就是要修的錯誤（列出測試名稱與 commit）。
- [ ] **後通過**：同一批測試在本 PR 上通過。
- [ ] **突變驗證**：每項修正逐一換回舊行為，只有對應的測試失敗。突變清單放在 `tests/mutations/<name>.json`，以 `python tools/mutation_check.py tests/mutations/<name>.json` 執行；貼上結果（`CAUGHT n/n`）。
- [ ] **放寬限制的修正**另有一個測試確認沒有放寬過頭。
- [ ] 受新語意影響而更新的既有測試：列出檔名與原因（沒有放寬斷言）。

## 完整檢查

- [ ] `python tools/sign_examples.py`（改了範例或推導規則時，重算到穩定）
- [ ] `python tools/validate_schemas.py`
- [ ] `python -m pytest tests`（寫出通過的數量）
- [ ] `python tools/check_doc_links.py`、`python tools/build_evidence_ledger.py --check`、`python tools/build_references.py --check`
- [ ] 改變 validator 行為時：`docs/schemas/README.md` 的錯誤碼表、相關設計文件與 `CHANGELOG.md` 已更新
