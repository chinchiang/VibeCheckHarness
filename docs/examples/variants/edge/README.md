# 變體 bundle：`edge`（BL-60）

主範例沒有走過的團隊規模路徑，用同樣的三個 run。這個目錄是一層覆蓋：這裡的檔案取代或新增主範例中同路徑的檔案。檔案由 `python tools/build_variants.py` 產生並以 TEST ONLY 金鑰簽署，不要手改。

- **G2 駁回（R10）**：G2 駁回 K-016（不是種子威脅）。G2_apply 寫入第二版裁決 V-016-2，由 R10 決定為 REJECTED，並有已錨定的 `verdict_changed` 事件；K-016 不再列在「只列報告」的叢集中。
- **G5 兩人核准**：委任改為 `full`，S2 job 的 G5 由兩位資安審查者（heidi 與 grace）核准。grace 在金鑰登錄中加上資安審查者角色，並列為 ROE 的關卡核准者。
- **停止條件與中止**：跟進 run 在等待 G4 時記下 `stop_condition`（staging 停機），測試負責人中止 run：`ABORTED`，最後一行是 `run_end` 錨點，檢查點也記錄中止。
- **預期警告**：與主範例相同的 `W-MODEL-PLACEHOLDER`。

```bash
python tools/validate_schemas.py --variant edge
```
