# 變體 bundle：`regression`（審查 r12）

`regression` run 的路徑：主範例與 `lite`、`edge`、`suspend` 都沒有走過，`FIXED`（05 §4.2 R14）與帶入叢集的下限（R16）之前只在記憶體中的測試出現。這個目錄是一層覆蓋：這裡的檔案取代或新增主範例中同路徑的檔案。檔案由 `python tools/build_variants.py` 產生並以 TEST ONLY 金鑰簽署，不要手改。

- **跟進 run 改為 `regression`**：`run_created` 釘住 `run_kind`（`E-RUN-COMMIT`），帶入的叢集 K-301 指回第一個 run 的 K-005（`CONFIRMED_EXECUTABLE`）。
- **W3：R16 維持來源的確認狀態**：K-301 在本 run 沒有成員、也還沒有回歸測試結果，V-301-1 由 R16 維持 `CONFIRMED_EXECUTABLE` 並加註 `fix_unverified`（審查 r12 之前會降成 UNCORROBORATED）。
- **G4 與 B4**：erin 在 G4 開啟前認領 run（G4 核准者計入發起者，`E-G4-INITIATOR`、`E-RUN-CLAIM`），本 run 的 B0 所有權檢查後，G4 核准重跑來源的可執行證明 TC-012-01；B4 job 在 ROE 時間窗內執行，對照都 PASS、正對照成立，結果 PASS。
- **B5：R14 → `FIXED`**：V-301-2 有合格 PASS 與正對照、來源的可執行證明已在本 run 重跑、沒有工具訊號或計權反駁票，所以是 `FIXED`（不是暫定）。run 仍是 `RUNNING`（B6 還沒開始），所以沒有報告。
- 建置時發現一個 validator 缺口並修正：`E-TRACE` 要求結果的 `cluster_ids` 包含威脅的來源叢集（第一個 run 的 K-005），所以回歸結果永遠無法指向 R14 要裁決的帶入叢集 K-301；現在本 run 的帶入叢集代表它的來源叢集。
- **預期警告**：與主範例相同的 `W-MODEL-PLACEHOLDER`。

```bash
python tools/validate_schemas.py --variant regression
```
