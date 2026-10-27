# 變體 bundle：`suspend`（BL-60 後續）

跟進 run 的兩條路徑，主範例與 `lite`、`edge` 都沒有走過。這個目錄是一層覆蓋：這裡的檔案取代或新增主範例中同路徑的檔案。檔案由 `python tools/build_variants.py` 產生並以 TEST ONLY 金鑰簽署，不要手改。

- **G4 逾時 → `SUSPENDED`**：G4 開啟 72 小時內沒有人決定。Gate Service 寫入沒有簽章的 `EXPIRED` 紀錄 GR-G4-0002（每個項目都是 `needs_info`），run 轉為 `SUSPENDED`，檢查點保留；沒有 `run_end` 錨點，因為 run 沒有結束，之後由 run_owner 或發起者在委任到期前 resume，resume 時 G0b 重驗（02 §1.4）。G4 的審查者 erin 在 G4 開啟前認領 run（`E-G4-INITIATOR`）。
- **抽查推翻 G5**：跟進 run 記錄的 ASI09 抽查改為檢查第一個 run 的 G5（GR-G5-0001），結果是 `overturned`。抽查人必須獨立：heidi 核准了那個 G5、erin 發起了那個 run，所以由 grace 抽查（grace 在金鑰登錄加上資安審查者角色，並列為 ROE 的關卡核准者）。之後開始的每個 run，G5 都需要兩位資安審查者（`checks.g5_escalation`）；這個範例沒有更晚、帶 G5 的 run，所以這個後果仍由記憶體中的測試檢查。
- 建置時發現一個 validator 缺口並修正：`EXPIRED` 的 G3／G4 紀錄只能有 `needs_info`，但「結果與決定一致」的檢查又要求 `PARTIALLY_APPROVED`，所以任何逾時的 G3／G4 紀錄都會被拒絕（`E-GATE-OUTCOME`）。
- **預期警告**：與主範例相同的 `W-MODEL-PLACEHOLDER`。

```bash
python tools/validate_schemas.py --variant suspend
```
