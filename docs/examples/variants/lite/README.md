# 變體 bundle：`lite`（BL-60）

主範例的單人版本。這個目錄是一層覆蓋：這裡的檔案取代或新增主範例中同路徑的檔案，`removed.txt` 列出拿掉的主範例檔案。檔案由 `python tools/build_variants.py` 產生並以 TEST ONLY 金鑰簽署，不要手改。

- **委任**：`assurance_profile: lite`，`role_consolidation` 由 alice 簽署；金鑰登錄給 alice 所有角色（測試負責人、管理者、基礎設施擁有者、資安審查者、應用程式擁有者、法務聲明者）。所有關卡、ROE 與委任簽署都是她。
- **只有 S0／S1**：主範例 S2 的 ZAP 主動掃描（TC-027-01）改為 MANUAL，所以沒有 S2 job、沒有 G5，也沒有它的結果、叢集 K-202 與裁決 V-202-1。G4 仍核准這個測試案例；它由人執行，列在報告的未能測試清單。
- **沒有抽查**：Lite 只有一個人，重看自己的決定不提供獨立性。
- **只有首次 run**：跟進 run、Lane A run 與它們的文件，以及誤報回饋（需要兩個人）都拿掉。
- **預期警告**：`W-L5-LITE`（法務聲明由兼任測試負責人的同一人簽署）與主範例相同的 `W-MODEL-PLACEHOLDER`。

```bash
python tools/validate_schemas.py --variant lite
```
