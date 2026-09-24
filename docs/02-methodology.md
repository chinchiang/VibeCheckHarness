# 02 方法論：先白箱、後黑箱（威脅建模強制在前）

> 標記說明見 [README](../README.md#標記說明)。證據 ID 對應 [evidence/ledger.md](evidence/ledger.md)。

## v0.2 變更摘要

- **Secrets 先於任何 LLM**：W0 改為完全確定性（盤點＋secrets 掃描＋路徑黑名單＋`secrets-redaction-map`）；W1 不再負責 secrets；W0.5 以後所有 LLM 只收遮罩後內容；沒有 `redaction_map_ref` 的 run，Model Gateway 一律拒絕 [H]。
- **關卡結果與終止狀態**：每個人工關卡回傳 `APPROVED`／`PARTIALLY_APPROVED`（只 G3、G4）／`REJECTED`／`NEEDS_INFO`／`EXPIRED`，各有處理路徑；run 狀態 enum 固定為 8 種（[§1.4](#14-關卡結果與-run-狀態)）。
- **新節點**：`B0_ownership_verify`（Z3）、`B4_preflight`（每批重驗）、`W4_exec`／`W4_readjudicate`、`GB_budget_gate`（預算關卡）、`abort_handler`（補償）、`claim_run`（自動觸發的人工認領）。
- **執行種類**：`run_kind` = `initial`／`followup`／`regression`／`lane_a`，附 `parent_run_id` 與 `reuse`（[§1.6](#16-執行種類與後續執行)）。
- **種子威脅與 G3**：規則改為「每個非 REJECTED 叢集都有 ≥1 個 B3 測試案例，**或**有 G3 駁回紀錄（附理由）」。
- **G2 路由**：只有 DISPUTED 與高嚴重度的 UNCORROBORATED 進 G2；佇列為空就略過 G2。
- **B1 差異清單**成為 B2 的正式輸入，B2 critic 必須逐項處置。
- 定義「**高風險威脅**」（[B2](#b2-威脅建模g3-強制簽核)）。
- Lane A 的單一家族 diff 審查只有**參考性**，結果最高 `UNCORROBORATED`（05 R9），且在下一個 Lane B run 中不計入 `independent_families`。
- **G2 之後才出現的爭議**：由 `W4_readjudicate` 產生的 `DISPUTED` 不重開 G2，而是在 G3 的種子威脅清單標為「W4 後轉為爭議」；由 `B5_readjudicate` 產生者列入 B6 的人工複核清單 [H]。裁決規則對齊 05 的 R0–R13。
- 儀表板移出範圍；報告為靜態 HTML＋SARIF＋JSON。
- 新增 [§5 階段與關卡規格總表](#5-階段與關卡規格總表)：每個階段與關卡的輸入、輸出、執行區、是否用 LLM、失敗處理、完成條件、schema、里程碑。
- 模型命名統一為 GPT-6 Astra／Sol（[P][E:providers-31]）。
- **W0 預設 secrets 掃描器**改為 Betterleaks／gitleaks（MIT）；TruffleHog（AGPL-3.0）改為選用，須通過授權登錄的法務閘門。
- **G0b 加入法務審查聲明檢查**（`legal_review`，規則 L-1～L-6，見 [06 §2.1.1](06-security-legal-limitations.md#211-roe-的法務審查聲明legal_reviewg0b-檢查h)）。

## 1. 總覽

### 1.1 流程

```mermaid
flowchart TD
  G0a{{"G0a 委任設定驗章（程式碼所有權、資料等級、允許模型）"}} --> W0
  subgraph W["Phase W 白箱"]
    W0["W0 盤點＋secrets 遮罩（確定性，無 LLM）"] --> W05["W0.5 安全不變量規格（LLM 只見遮罩後內容）"]
    W05 --> G1{{"G1 人工簽核"}}
    G1 -- "REJECTED／NEEDS_INFO（≤3 輪）" --> W05
    G1 --> W1["W1 確定性掃描（SARIF）"]
    W1 --> W2["W2 多家族獨立審查"]
    W2 --> W3["W3 交叉驗證與裁決"]
    W3 --> G2{{"G2 爭議項人審（佇列為空就略過）"}}
    G2 --> W4["W4 白箱測試：產生 → Z2 執行 → 重新裁決"]
    W3 -. "無待審項" .-> W4
    W4 --> W5["W5 白箱報告＋DFD＋種子威脅"]
  end
  subgraph B["Phase B 灰箱威脅建模＋黑箱執行"]
    G0b{{"G0b ROE 驗章（離線）"}} --> B0["B0 目標所有權驗證（Z3 經 Scope Proxy）"]
    B0 --> B1["B1 系統建模（外部視角 ∥ 合併視角＋差異清單）"]
    B1 --> B2["B2 威脅建模（處置差異清單）"]
    B2 --> G3{{"G3 威脅模型強制簽核"}}
    G3 --> B3["B3 威脅→需求→測試案例"]
    B3 --> G4{{"G4 測試計畫＋產物核准"}}
    G4 --> B4["B4 執行（每批 preflight；S0/S1 自動，S2 逐次 G5）"]
    B4 --> B5["B5 結果驗證"]
    B5 --> B6["B6 報告＋追溯矩陣"]
  end
  W5 --> G0b
  GB{{"GB 預算關卡"}} -. "任何消耗預算的節點觸頂時" .- W
  GB -. .- B
  B4 -. "停止條件／kill switch" .-> AH["abort_handler：還原快照＋稽核＋報告"]
  B2 -. "followup run：威脅衍生的新需求回寫 W0.5 → G1 → W4" .-> W05
  B5 -. "regression run：黑箱確認項→白箱根因＋回歸測試" .-> W4
```

完整狀態機（含失敗、駁回、逾時、終止狀態與 resume）見 [03 §5](03-system-architecture.md#5-run-controllerlanggraph-狀態機)。

### 1.2 為什麼先白箱、後黑箱
- NIST SP 800-115 附錄 C：白箱技術對自製應用的缺陷**較有效率、成本較低**；黑箱技術用於元件之間、與使用者、其他系統、環境的互動；兩者合用稱為 gray-box [V][E:blackbox-31]。
- NIST SSDF SP 800-218 v1.1（目前的正式版；v1.2 仍是草案 [V][E:threat_modeling-48]）的三項實務剛好對應三個階段 [V][E:threat_modeling-49]：
  - PW.1.1 風險建模 → B2
  - PW.7 審查程式碼 → W1–W3
  - PW.8 測試可執行碼 → W4、B4
- 白箱產物（DFD、發現項、安全不變量）讓黑箱的威脅建模有具體依據。所以 **B 階段的威脅建模是灰箱**，**測試執行只經外部介面，是黑箱**。另外保留一組**只看外部視角**的威脅建模 agent，維持純黑箱觀點（見 [B1](#b1-系統建模兩個獨立視角)）。

### 1.3 人工關卡一覽

| 關卡 | 位置 | 核准內容 | 必要核准角色 | 可能結果 | 為何必要 |
|---|---|---|---|---|---|
| G0a | W0 之前（每次 run 開始都重驗） | 委任設定（[schemas/engagement.schema.json](schemas/engagement.schema.json)）：程式碼所有權聲明、資料等級、每個等級允許的模型 | 應用擁有者（另可加管理層） | 離線驗章：通過／失敗 | 程式碼要送往 LLM、在 Z2 執行之前，必須先有授權 |
| G0b | B 階段入口（每次 run 與每次 resume 都重驗） | ROE（範圍、時間窗、停止條件、目標所有權、測試角色、法務審查聲明 `legal_review`） | 測試負責人＋管理層＋**基礎設施擁有者**（NIST SP 800-115 的簽核頁至少要測試負責人與管理層 [V][E:blackbox-29]） | 離線驗章：通過／失敗／未生效／已過期 | 沒有授權就不能碰網路 |
| G1 | W0.5 | 安全不變量規格（ASVS 基準＋存取控制矩陣＋資料分級＋LLM 工具權限） | 應用擁有者 | APPROVED／REJECTED／NEEDS_INFO／EXPIRED | vibe-coded 應用通常沒有安全需求，oracle 必須有人確認的來源 |
| G2 | W3 | DISPUTED 叢集與高嚴重度 UNCORROBORATED 叢集（逐項） | 資安審查者 | 逐項 accept／reject／needs_info；整體 APPROVED／EXPIRED | 跨家族衝突無法自動判定 |
| G3 | B2 | 威脅模型（可部分核准） | 資安審查者＋應用擁有者 | APPROVED／PARTIALLY_APPROVED／REJECTED／NEEDS_INFO／EXPIRED | LLM 威脅建模準確度有限 [V][E:threat_modeling-20][E:threat_modeling-21] |
| G4 | B3 | 測試計畫與每個產生的可執行產物（綁定 hash） | 資安審查者 | APPROVED／PARTIALLY_APPROVED（逐測試案例）／REJECTED／NEEDS_INFO／EXPIRED | 產物可能被受測 repo 的內容影響 |
| G5 | B4 | 每一次 S2 侵入性執行 | 資安審查者，且**不得是發起者** | APPROVED／REJECTED／NEEDS_INFO／EXPIRED（逐 job） | 可能影響 staging 可用性 |
| GB | 任何節點觸及預算上限時 | 延長（新上限）／停止本階段／中止 | run_owner 或委任設定指定的預算核准者 [H] | APPROVED（附選項）／REJECTED（＝停止本階段）／EXPIRED | 預算用盡時不能靜默刪減覆蓋 |

- 核准者必須登錄在組織的**金鑰登錄**（`key-registry.yaml`，由組織根金鑰簽署；見 [03 §6](03-system-architecture.md#6-人工關卡服務)）中，G0b 以後的核准者也必須列在 ROE 的 `signatories` 或 `gate_approvers`。ROE 與委任設定**不能**引入新的金鑰。
- **發起者（initiator）**：啟動該次執行、認領自動觸發的執行（`initiator_claim`），或核准 G4 的**人**；不能是自動化帳號（`toolkit.yaml` 的 `automation_accounts`，例如 `run-controller`、`scheduler`、`ci-bot`；這些帳號也不能當任何關卡的核准者，驗證器會強制檢查。見 [§1.5](#15-自動觸發與發起者)）。

核准記錄是**簽章紀錄**（核准者身分、角色、時間、產物 hash、逐項決定），由 Policy Engine 驗證；詳見 [03 §6](03-system-architecture.md#6-人工關卡服務)。

### 1.4 關卡結果與 run 狀態

**run 狀態 enum**（`run.schema.json` 的 `status`）：

| 狀態 | 意思 | 是否終止 |
|---|---|---|
| `RUNNING` | 正在執行節點 | 否 |
| `WAITING_GATE` | 停在人工關卡或 `claim_run` 的 interrupt | 否 |
| `SUSPENDED` | 關卡逾時、時間窗外或預算關卡逾時；checkpoint 保留，可在委任／ROE 到期前 resume | 否（可續跑） |
| `STOPPED` | 停止條件或 kill switch 觸發；已執行補償 | 否（需測試負責人簽署 resume） |
| `ABORTED` | 授權不成立（驗章失敗）、G1 三輪未通過、GB 選擇中止、ROE 在執行中失效 | 是 |
| `FAILED` | 無法恢復的技術錯誤（例如 W0 失敗、快照還原失敗） | 是 |
| `COMPLETED` | 全部完成，未能測試清單中只有設計上的 `MANUAL` 項 | 是 |
| `COMPLETED_WITH_GAPS` | 完成，但有計畫中的覆蓋沒做到（例如 G3 全部駁回、目標所有權失敗、G5 駁回、執行錯誤、GB 停止階段） | 是 |

**各關卡結果的處理**（[H]，依共同設計決定 D2）：

| 關卡 | APPROVED／PARTIALLY_APPROVED | REJECTED | NEEDS_INFO | EXPIRED |
|---|---|---|---|---|
| G0a／G0b | —（離線驗章，結果只有 `VERIFIED`／`VERIFY_FAILED`／`EXPIRED`；`VERIFIED` 即繼續） | `VERIFY_FAILED`（驗章失敗）→ `ABORTED`（例外：06 L-5 → `SUSPENDED` 等 ROE 修正） | — | G0b：ROE 未生效或在時間窗外 → `SUSPENDED`；ROE 已過期或未提供 → 跳到 B6 → `COMPLETED_WITH_GAPS` |
| G1 | 進入 W1 | 附審查意見回到 W0.5 重擬，最多 3 輪；第 3 輪仍未通過 → `ABORTED` | 同 REJECTED（共用 3 輪上限） | `SUSPENDED` |
| G2 | 逐項：accept → 維持狀態，成為種子威脅。整關結果只有 `APPROVED` 或 `EXPIRED` | 只能逐項（不接受整關 `REJECTED`）：該叢集 → `REJECTED`（附理由；為最終決定，之後的證據只註記 `post_g2_conflict`，05 R10） | 逐項：維持 `DISPUTED`／`UNCORROBORATED`，成為種子威脅並在報告列出 | 未決項視同 NEEDS_INFO，run 繼續 [H] |
| G3 | 已接受的威脅進入 B3；被駁回的種子威脅在 B6 列為「未做黑箱驗證（G3 駁回：理由）」 | 全部駁回 → 跳到 B6（只含白箱結果）→ `COMPLETED_WITH_GAPS` | 回到 `B2_merge_critic` 補充，最多 3 輪；之後仍 NEEDS_INFO 的項目視同駁回 [H] | `SUSPENDED` |
| G4 | 已核准的測試案例進入 B4 | 全部駁回 → 跳到 B6 → `COMPLETED_WITH_GAPS`；部分駁回的測試案例不執行，列入 B6 | 該測試案例回到 `B3_derive` 重做，最多 2 輪；之後視同駁回 [H] | `SUSPENDED` [H] |
| G5 | 執行該 S2 job | 該 job 略過並記錄 | 該 job 略過並記錄（可在後續執行重提）[H] | 該 job 略過並記錄 |
| GB | 延長：以新上限回到觸頂的節點 | 停止本階段：W → 以現有結果直接到 W5；B → 直接到 B6；run 以 `COMPLETED_WITH_GAPS` 結束 | — | `SUSPENDED` [H] |
| GB（中止） | 選擇中止：B4 中 → `abort_handler`；其他 → `ABORTED` | | | |

各關卡的逾時預設值見 [03 §6](03-system-architecture.md#6-人工關卡服務)。

### 1.5 自動觸發與發起者
- 排程或合併到主幹觸發的 Lane B run，只能自動執行 **W0–W3**：沒有網路出站（Z2 只到鏡像）、不執行受測程式（W4 執行屬於「執行」）。紀錄上的發起者是委任設定指定的人類 **`run_owner`** [H]。
- 在做任何 **G1 決定**、進入 **W4** 或任何 **B 階段節點**之前，必須有一位人類以 `vibecheck run claim` **認領**該 run（稽核事件 `initiator_claim`，附簽章）。狀態機中是 `claim_run` 節點（interrupt）。
- 若 G1 可沿用上一版已簽核規格（[§1.6](#16-執行種類與後續執行)），自動觸發的 run 可以一路跑到 W3 後才停在 `claim_run`。
- 認領者成為發起者；**G5 核准者 ≠ 發起者**，G4 核准者也計入發起者集合。

### 1.6 執行種類與後續執行

| `run_kind` | 用途 | 從哪裡開始 | 關卡重簽規則 |
|---|---|---|---|
| `initial` | 第一次完整評估 | W0 | 全部 |
| `followup` | B2 衍生的新需求回寫、CMD-5 追加的測試 | W0（新 commit 時重算）→ W0.5 帶入「威脅衍生需求」草稿 | G1 只在不變量有變時重簽；G3 只簽新增或變更的威脅；G4／G5 每次 run 都要 |
| `regression` | 修正後重跑已確認問題的白箱回歸測試與對應黑箱測試 | W0 → W1 → W4（只跑回歸集）→ B 階段只跑對應測試案例 | 同上；通常沿用 G1 與 G3 |
| `lane_a` | 每個 PR 的同步檢查 | W0 → W1 →（可選）單一家族 diff 審查 → 結束 | 只需 G0a；不進 B 階段 |

- 每個 run 有 `parent_run_id`（`initial` 可為空）與 `reuse` 清單：以 content hash 引用上一個 run 的產物。只有當產物的**所有輸入 hash**（repo commit 或切片 `slice_id`、設定、模型 ID 與版本）都相同時才能沿用，否則重算 [H]。
- **G0a／G0b 簽章每次 run 開始（與每次 resume）都重新驗證**，不能沿用。
- 回饋不在同一張圖內迴圈：CMD-5 只**建立**後續 run 的草稿（`followup` 或 `regression`），由人啟動或認領。

## 2. 白箱階段（W0–W5）

### W0 盤點與 secrets 遮罩（確定性，無 LLM）
- **前提**：G0a 委任設定已驗章（[03 §6](03-system-architecture.md#6-人工關卡服務)）；未標記資料等級的 repo 視為 C。
- **輸入**：repo（唯讀，固定 commit SHA）、`toolkit.yaml` 的路徑黑名單。執行位置：Z2。
- **做法**（全部是確定性工具與解析器，**不用 LLM**）：
  1. **Secrets 掃描最先跑**：**預設**用 Betterleaks [P][E:whitebox-09] 或 gitleaks（已宣布只修安全問題），兩者都是 MIT 授權。TruffleHog（AGPL-3.0）[V][E:whitebox-10] 是**選用**：[06 §2.3](06-security-legal-limitations.md#23-授權登錄表) 把它列為法務閘門，ROE 的 `legal_review.scope.component_licenses` 為 `true` 才能啟用 [H]。TruffleHog 的驗證會把找到的憑證送到供應商 API → 啟用時**預設 `--no-verification`**；若要驗證，必須寫進 ROE 並從 Z3 發出、留紀錄，否則建議直接輪替。
  2. **路徑黑名單**（`.env*`、金鑰與憑證檔、auth-state 目錄、CI secrets 檔）**完全不進任何後續產物**。
  3. **遮罩對照表 `secrets-redaction-map`**（`redaction-map.schema.json`，run 以 `redaction_map_ref` 參照）：`hash_alg`、`hmac_key_ref` 與 `entries[]`；每筆只存位置、類型、值的 **HMAC** 與遮罩代號，**不存值**；再以 pattern＋entropy 作第二層遮罩規則（掃描器 recall 不完美，Betterleaks 的 98.6% recall 只是廠商宣稱 [P][E:whitebox-09]）。
  4. 以遮罩後的檔案建立下列清單：
     - 路由表與 entry points（REST、GraphQL resolver、webhook、排程工作）
     - auth middleware 與角色定義
     - DB schema、RLS policy（Supabase／PostgreSQL 類）
     - 設定檔與環境變數名稱（**只取名稱，不取值**）
     - LLM 呼叫點、prompt 組裝位置、agent 工具清單與權限
     - 相依清單；Syft 產生 SBOM（CycloneDX／SPDX）[V][E:whitebox-14]
- **輸出**：`inventory.json`（結構化）、SBOM、`secrets-redaction-map`、secrets 發現清單（只含位置與 hash）。
- **強制點**：`redaction_map_ref` 寫入 run 紀錄之後，Model Gateway 才接受該 run 的任何請求；沒有就拒絕（fail-closed）[H]。所有之後送往 LLM 的內容（切片、inventory 摘要、Z2 輸出、測試日誌）都先套用遮罩。
- **重點**：指揮官的規劃輸入**只用這些確定性產物**，不用 LLM 對程式碼的自由文字摘要。原因：受測 repo 可能含有影響 LLM 的文字，已有預印本顯示經 LLM 最佳化的 PR metadata 框架攻擊能讓 LLM 安全審查漏判 33 個 CVE 中的 32 個（範本式攻擊無效）[V：預印本][E:whitebox-29]。
- **完成條件**：每個 entry point 都有對應的 handler 位置；每個 DB table 都有 RLS 狀態（有／無／不適用）；遮罩對照表已寫入。W0 任何子步驟失敗 → run `FAILED`（沒有遮罩就不能繼續）。

### W0.5 安全不變量規格（Security Invariants Spec）＋ G1
- **問題**：LLM 產生的測試傾向記錄程式「實際行為」而非「預期行為」[V][E:whitebox-43]。vibe coding 的原始定義就是「忘了程式碼的存在」、不讀 diff [V][E:vibe_risks-01]，因此通常也不會有書面安全需求 [H]，oracle 沒有可靠來源。
- **做法**：
  1. **基準需求**：依 W0 偵測到的功能（登入、檔案上傳、OAuth、LLM 呼叫…）篩選 **OWASP ASVS 5.0 Level 1**。L1 共 70 條，約佔全部需求的 20% [V][E:threat_modeling-43]，需求 ID 格式如 `v5.0.0-8.2.2` [V][E:threat_modeling-40]。
  2. **應用專屬不變量**：
     - 存取控制矩陣：角色 × 資源 × 動作 → 允許／拒絕
     - 資料分級：每個 store／欄位是否含個資、機密
     - LLM 工具權限矩陣：每個工具可被哪些角色觸發、哪些動作必須先經人確認（OWASP 對 Excessive Agency 的建議是最小權限＋高影響動作需人核准 [V][E:blackbox-32]）
  3. 由 Invariant Drafter agent 根據（**已遮罩的**）路由、schema、RLS **起草**；`followup` run 另帶入 B2 衍生的需求草稿。再由人在 **G1** 逐條確認、修改或刪除。
  4. G1 `REJECTED`／`NEEDS_INFO` 時，審查意見連同上一版草稿回到 Drafter 重擬，最多 3 輪；之後 run `ABORTED`。`EXPIRED` → `SUSPENDED`。
- **輸出**：`invariants.yaml`（每條有 ID、來源〔ASVS／應用專屬／威脅衍生〕、簽核狀態；依 `invariants.schema.json`）。
- **完成條件**：已簽核；W4 與 B3 的 oracle **只能引用已簽核條目**。

### W1 確定性掃描（建立基準，不用 LLM）
- **輸入**：repo、SBOM、`secrets-redaction-map`。執行位置：Z2 程式執行沙箱（見 [03 §2](03-system-architecture.md#2-部署與信任區)）。
- **工具**（輸出一律轉為 **SARIF 2.1.0** [V][E:whitebox-17]；SARIF 內的程式片段也套用遮罩）：

| 類別 | 工具 | 注意 |
|---|---|---|
| SAST | Opengrep（LGPL-2.1，Semgrep CE 1.100.0 的 fork，含檔內跨函式 taint，需啟用 `--taint-intrafile`）[V][E:whitebox-06] 或 Semgrep CE | Semgrep 引擎是 LGPL，但官方規則自 2024-12 改用非開源的 Semgrep Rules License；CE 只做單檔、單函式分析 [V][E:whitebox-04] |
| SAST（Python） | Bandit（Apache-2.0，有 SARIF formatter）[V][E:whitebox-08] | — |
| SAST（選用） | CodeQL | CLI 授權只允許開源專案與學術研究免費使用，私有商業碼需付費 [V][E:whitebox-07] |
| 相依漏洞 | OSV-Scanner（Apache-2.0）[V][E:whitebox-11]、Grype（EPSS／KEV 排序）[V][E:whitebox-14] | OSV-Scanner 的可達性判斷（call analysis）是選配功能，且不是每個生態系都支援 [V][E:whitebox-11] |
| 套件存在性 | 自建檢查：每個相依到 registry（經 Z2 的鏡像或 metadata 代理）查存在性、首次發布時間、下載量 | 對應套件幻覺：19.7% 的套件引用是幻覺名稱；43% 的幻覺名稱在 10 次重複查詢中每次都出現 [V][E:vibe_risks-13][E:vibe_risks-15] |

- Secrets 掃描已移到 W0（v0.2）。
- **輸出**：`w1.sarif`、`deps-check.json`。
- **完成條件**：所有工具以鎖定版本執行完畢；任何工具失敗都要在報告中列出，不能靜默略過。

### W2 多家族獨立審查
- **輸入**：inventory、G1 規格、W1 SARIF、切片（全部已遮罩）。
- **切片器（Slicer，確定性）**：
  1. 以每個 entry point 為錨，依靜態呼叫圖納入 handler、被呼叫函式、相關 model／schema／RLS policy、auth middleware，直到 token 預算上限。
  2. **共同輸入上限（同等性單位）**：取所有參與模型中**最小的可用 context**。例如自架 Nemotron 3 Nano 的 Hugging Face 設定預設 256K [V][E:providers-05]，Claude 約 1M [V][E:providers-23]、OpenAI GPT-6 Astra／Sol 為 1,050,000 tokens [P][E:providers-31]。這樣可以確保各家族看到**相同輸入**。重新命名函式或變數就可能改變 LLM 的安全判斷 [P][E:multi_llm_bias-26]，所以輸入必須一致，比較才有意義。
  3. 流程超過上限時，以重疊方式切割並記錄；若某模型放不下某切片，就把該模型排除在此切片之外，並標記 `diversity_degraded`。**不允許靜默截斷**。
  4. 每個切片有 `slice_id`＝各檔案範圍的 sha256（依 `slice.schema.json`）。
- **審查方式**：
  - 同一切片平行交給 N 個不同家族的 reviewer。**第一輪彼此看不到對方結果**。多輪辯論中模型常由對轉錯，原因未定，作者列出從眾、諂媚等可能因素 [P][E:multi_llm_bias-21]；多數決本身就拿到辯論的大部分效益 [V][E:multi_llm_bias-16]。
  - 審查面向（facet）：
    - 授權與 IDOR
    - 輸入處理與注入
    - 資料存取與 RLS
    - secrets 與設定
    - 商業邏輯（對照 G1 規格）
    - LLM 整合：prompt 組裝、工具權限、輸出處理
  - reviewer 沒有 shell、沒有網路，只讀切片。系統提示明確區分「指令」與「待審資料」。
- **發現項要求**：每個發現項必須附：
  - `file:line` 範圍
  - 逐字程式片段
  - CWE（可多個）、嚴重度、推理
  - 引用的 G1 條目（若有）

  Harness 以程式碼比對片段是否真的在該位置；對不到就標 `UNVERIFIED`，但不刪除（STRIDE-GPT 的證據比對做法）[V][E:threat_modeling-15]。
- **輸出**：`findings[]`（依 [schemas/finding.schema.json](schemas/finding.schema.json)）。
- **完成條件**：覆蓋下限（每個切片 × 每個必要面向）都有結果，或有記錄在案的缺票原因。

### W3 交叉驗證與裁決（＋G2）
- **輸入**：W2 發現項、W1 SARIF。
- **做法**（詳見 [05 §4](05-bias-calibration.md#4-叢集與裁決)）：
  1. **叢集**：以確定性叢集鍵合併不同模型描述的同一問題。
  2. **跨家族反駁式驗證**：驗證者的 `family` 與 `lineage` 都不能出現在叢集的回報者中；驗證時去除來源模型資訊、隨機排列候選順序；驗證者被要求「嘗試反駁」。
  3. **與 SARIF 相互佐證**。
  4. **規則式裁決**（Aggregator 是程式碼，不是 LLM），依 [05 §4.2](05-bias-calibration.md#42-裁決狀態與有序規則) 的有序規則 R0–R13：`CONFIRMED_CORROBORATED`／`LIKELY`／`UNCORROBORATED`／`DISPUTED`／`REJECTED`。
  5. **CMD-2 加派**：對 `DISPUTED` 與 `UNCORROBORATED` 叢集加派審查者或驗證者，最多 2 輪 [H]。
  6. **G2 佇列**（加派結束後，由程式碼計算）[H]：
     - 所有 `DISPUTED` 叢集；
     - 成員最高嚴重度為 `critical` 或 `high` 的 `UNCORROBORATED` 叢集。
     - 其他 `UNCORROBORATED` 叢集不進 G2，直接成為種子威脅並在報告中列出。
     - **佇列為空就略過 G2**（稽核事件 `gate_skipped`，附原因）。
  7. G2 逐項：accept → 維持狀態；reject → `REJECTED`（附理由）；needs_info 或逾時 → 維持狀態並在報告列出。三者除 `REJECTED` 外都成為種子威脅。
- **輸出**：`clusters[]`、`verdicts[]`、G2 GateRecord（若有）。
- **完成條件**：每個叢集都有裁決與 `rule_trace`；缺票與多樣性降低都已註記；G2 佇列中每項都有決定或已標逾時。

### W4 白箱測試（oracle 只取自 G1 規格）
- **輸入**：G1 規格、裁決為 LIKELY 以上的叢集、程式碼（已遮罩）。
- **節點**：`W4_testgen`（Z1，LLM）→ `W4_exec`（Z2，無網路）→ `W4_readjudicate`（Z1，程式碼）。
- **做法**：
  - 對每條安全不變量產生單元測試或性質測試：Python 用 Hypothesis，JS／TS 用 fast-check [V][E:whitebox-40]。可參考 agentic PBT 的做法，由 agent 推論性質並寫 Hypothesis 測試 [V][E:whitebox-41]。
  - 用覆蓋率回饋補測試（CoverUp 式迭代）[V][E:whitebox-36]：Z1 產生測試 → Z2 執行並回傳覆蓋率與失敗日誌（套用遮罩後）→ Z1 依未覆蓋行補測試。**最多 3 輪**，或覆蓋率連續一輪沒有增加就停止 [H]。Z1 與 Z2 之間只透過 Blackboard 交換產物，不直接連線。
  - 用 mutmut（Python）或 Stryker（JS／TS）評估測試強度 [V][E:whitebox-45]。
  - **TestGen-LLM 濾網**：只保留能 build、重複執行都通過、且有增加覆蓋的測試 [V][E:whitebox-34]。例外：**斷言安全不變量而失敗**的測試不丟棄，它就是發現。
  - A 家族生成、B 家族審查（Test Critic）。
  - **oracle 只能引用 G1 已簽核條目**。程式本身可能已有 bug 時，覆蓋率與變異分數不再是可靠指標 [V][E:whitebox-44]，所以只能當輔助訊號。
  - 測試只能 import 鎖定、預先核准的相依套件；在 Z2 執行（無憑證、無 LLM 出站、無網路）。Pynguin 的文件也警告，執行受測模組可能傷害主機 [V][E:whitebox-38]。
  - `W4_readjudicate`：測試結果寫回相關叢集，由 Aggregator 重新裁決（例如不變量測試失敗且重播相同 → 依 R1 需另一家族確認解讀）。
    - G2 已 `REJECTED` 的叢集維持 `REJECTED`；之後出現的可執行證明只註記 `post_g2_conflict`（05 R10），列入 W5 報告。
    - 重新裁決後才轉為 `DISPUTED` 的叢集**不重開 G2**；它們照常成為種子威脅，並在種子清單中標為「W4 後轉為爭議」，由人在 G3 處理 [H]。
    - 合格的測試 PASS 不會自動使叢集變成 `REJECTED`（05 R11）。
- **輸出**：測試檔、執行結果（`testresult.schema.json`，`phase: W4`）、覆蓋率、mutation score、新版裁決。
- **完成條件**：每條 G1 不變量都有至少一個測試，或被標記 `MANUAL`（附原因）；所有結果已回寫並重新裁決。

### W5 白箱報告＋DFD＋種子威脅
- **DFD 骨幹由確定性方法產生**：
  - 路由與 handler → process
  - DB schema 與 RLS → data store
  - 外部 API 呼叫與 LLM 工具點 → external entity
  - 認證邊界、網路邊界、租戶邊界 → trust boundary

  LLM 只**提議**標籤與邊界，由人在 G3 確認。pytm 也是從明確的模型產生 DFD，不是推論出來的 [V：該條只有日期與數字被更正，此部分成立][E:threat_modeling-11]。
- **種子威脅**：除了 `REJECTED` 以外的叢集（`CONFIRMED_CORROBORATED`、`LIKELY`、`UNCORROBORATED`、`DISPUTED`，以及 W4 已升級的 `CONFIRMED_EXECUTABLE`）都轉成 B2 的種子威脅，帶 `source_cluster_id` 與 `source_finding_ids`。
  - **規則（v0.2）**：每個種子威脅**必須出現在 B2 威脅模型中**；之後要嘛有 ≥1 個 B3 測試案例，要嘛有 **G3 駁回紀錄（理由必填）**。被 G3 駁回的叢集保留其白箱狀態，B6 列為「未做黑箱驗證（G3 駁回：理由）」。
  - `W4_readjudicate` 時才轉為 `DISPUTED` 的叢集（前一版裁決不是 `DISPUTED`，例如 `LIKELY` 經 R11 → `DISPUTED`；與 G2 是否已決定無關）在裁決上加註 `w4_became_disputed`；種子威脅與 run 的 `disputed_after_g2` 由這些註記推導，G3 呈現時標為「W4 後轉為爭議」[H]（[05 §4.2](05-bias-calibration.md#42-裁決狀態與有序規則)）。
  - 這樣動態測試可以把確認升級為 `CONFIRMED_EXECUTABLE`、化解跨家族爭議，並替已確認的問題留下回歸測試。
- **輸出**：`whitebox-report.md`、`w.sarif`、`dfd.json`（`dfd.schema.json`）、`seed-threats.json`（`seed-threats.schema.json`）、報告清單（`report-manifest.schema.json`）。

## 3. 黑箱階段（B0–B6）

### B0 ROE 與範圍（G0b，機器可驗證）
- **節點**：`G0b_roe_check`（Z1，離線驗章）→ `B0_ownership_verify`（Z3，經 Scope Proxy）。
- **輸入**：已簽章的 `roe.yaml`、金鑰登錄（`key-registry.yaml`）、G0a 委任設定。**輸出**：ROE 驗章結果、每個目標的所有權驗證結果（由 Z3 取得並簽署回傳）、出站白名單。
- **內容**：依 NIST SP 800-115 附錄 B 的 ROE 樣板 [V][E:blackbox-29]：
  - 範圍、目標清單與排除清單
  - 允許與禁止的活動、授權工具
  - 測試時間窗
  - 停止條件（criteria for halting）、事件處理
  - 資料處理
  - 簽核頁
- **程式碼強制**（詳見 [04 §7](04-threat-to-testcase.md#7-roe-樣板) 與 [schemas/roe.schema.json](schemas/roe.schema.json)）：
  1. ROE 是 YAML，驗章前先轉為標準形式（canonical form）；每位簽署人（至少測試負責人、管理層、基礎設施擁有者）在 `signatures[]` 中各有一筆**數位簽章**（`signer`、`key_fingerprint`、`alg`、`value`；簽署對象是移除 `signatures` 後的文件），金鑰必須在金鑰登錄中、角色相符且未撤銷；ROE 有 `not_before`／`not_after` 與時間窗，且不得超過委任設定的有效期間。標準形式與簽章演算法見 [03 §6](03-system-architecture.md#6-人工關卡服務)（方案是 [H] 提案；所依據的外部事實見 [01 §7](01-research-survey.md#7-v02-補充研究2026-09-24)，已經獨立查核 [V][E:orchestration-43][E:orchestration-44]）。簽署的 YAML 必須通過嚴格載入（拒絕重複鍵等），違反就視為簽章無效。
  1a. **法務審查聲明**（`legal_review`，[06 §2.1.1](06-security-legal-limitations.md#211-roe-的法務審查聲明legal_reviewg0b-檢查h)）[H]：G0b 同時檢查 L-1～L-6：聲明存在且每個 `scope` 項目為 `true` 或附 `not_applicable_reason`；`attested_by` 在金鑰登錄中、未撤銷、角色含 `legal_reviewer`（沒有法務人員時可用 `management`，報告首頁標示「未經法務人員審查」）；簽章有效；`attested_at` ≤ ROE `not_before` 且 `expires_at` ≥ ROE `not_after`；`attested_by` 不是 `test_lead`（否則 NEEDS_INFO）；法務閘門元件在 `component_licenses` 不為 `true` 時從允許清單移除並列入 B6。L-1～L-4 失敗 → G0b 不通過（稽核 `roe_verify_failed`，理由如 `legal_review_missing`）；run 執行中聲明到期 → `SUSPENDED`。
  2. **目標所有權驗證**（`B0_ownership_verify`）：每個目標主機要在 DNS TXT 或 well-known path 放置本次委任的 token。檢查**由 Z3 經 Scope Proxy 執行**（Z1 不能連目標），結果由 Z3 Executor 簽署後回傳給 Policy Engine。我方控制的設施（例如 canary 伺服器）標為 `tester_controlled`。**每個 B4 批次開始時（`B4_preflight`）重新檢查**。
     - 某個目標驗證失敗 → 該目標從出站白名單移除，其測試不執行並列入 B6；全部目標失敗 → 跳到 B6 → `COMPLETED_WITH_GAPS`。
  3. **預設拒絕**：出站白名單只由通過所有權驗證的 ROE 目標 ID 產生。
  4. **範圍變更需重新簽署**。SP 800-115：偏離 ROE 需原簽署人許可，通常要書面 [V][E:blackbox-30]。
- **其他前提**（寫在 ROE 裡、由核准者聲明）：
  - staging 資料為合成資料。SP 800-115 建議可能暴露個資的測試使用非正式系統與測試資料 [V][E:blackbox-30]。
  - staging 的外部整合（email、SMS、金流、LLM API）都在 sandbox／test 模式並列入 ROE，否則在出站層阻擋。
  - staging 與正式環境的憑證、DB 分離。Replit 的 agent 在 code freeze 期間刪除了正式資料庫 [P][E:vibe_risks-27]，事後 Replit 才宣布開始推出自動 dev／prod 資料庫分離 [V][E:vibe_risks-28]。
- **適用範圍**：**所有接觸網路的步驟**（從 B1 爬行開始，包括 TruffleHog 驗證）都必須先通過 G0b 與所有權驗證。

### B1 系統建模（兩個獨立視角）
- **節點**：`B1_crawl`（Z3，S0 爬行）→ `B1_model`（Z1）。
- **輸入**：OpenAPI／GraphQL schema、W5 DFD、種子威脅、ROE 測試角色。**輸出**：外部視角模型、合併視角模型、**兩者差異清單**（`b1_diff`）。
- **(a) 外部視角（純黑箱）**：
  - 匯入 OpenAPI／GraphQL schema。
  - ZAP spider／ajax spider：由 ROE 產生 context，設定 `includePaths`／`excludePaths` [V][E:blackbox-05]。
  - Playwright 以多個角色錄製流程（每個角色一個 BrowserContext／storageState）[V][E:blackbox-21]。
- **(b) 合併視角（灰箱）**：W5 DFD＋種子威脅＋(a) 的結果。
- **差異清單**：兩個視角在元件、端點、資料流、信任邊界上的差異，每項有 ID。差異代表「文件或介面與實作不一致」，或其中一方的盲點；這是覆蓋訊號，不是用來驗證 DFD。
- 爬行受 Scope Proxy 限制：擋掉越界 redirect；Playwright MCP 的 allowed-origins 不是安全邊界，也不管 redirect [V][E:blackbox-24]。
- 爬行觸發停止條件時，外部視角退回「只用 schema」，並標記為缺口。

### B2 威脅建模（G3 強制簽核）
- **框架**：Threat Modeling Manifesto 的四個問題 [V][E:threat_modeling-01]：
  1. 我們在做什麼？
  2. 會出什麼錯？
  3. 要怎麼處理？
  4. 做得夠好嗎？

  OWASP Threat Modeling Cheat Sheet 的四階段：系統建模、威脅識別、緩解、審查驗證；緩解措施以 ASVS 與 CWE 寫成需求 [V][E:threat_modeling-02]。
- **輸入**：外部視角模型、合併視角模型、`b1_diff`、種子威脅、CMD-3 的分類計畫。
- **方法組合**：

| 條件 | 方法 | 備註 |
|---|---|---|
| 一律 | STRIDE-per-element | 資料存放的 R（否認）只在存放稽核紀錄時適用；Microsoft 2006 圖表只給資料存放 T、I、D [P][E:threat_modeling-04] |
| 處理個資 | LINDDUN（7 類）[V][E:threat_modeling-07] | Threat Dragon 支援 LINDDUN [V][E:threat_modeling-09] |
| 有 LLM 功能 | OWASP Top 10 for LLM Applications | 版本見下方 |
| 有 Agent／工具呼叫 | OWASP Top 10 for Agentic Applications 2026（ASI01–ASI10）[V][E:threat_modeling-32]、CSA MAESTRO 七層 [V][E:threat_modeling-35] | — |
| 高風險威脅（定義見下） | Attack tree：OR 節點取最便宜的子節點、AND 節點取總和 [V][E:threat_modeling-08] | 必須有 attack tree（`attack_tree_ref`） |

- **高風險威脅的定義**（由程式碼從威脅欄位計算；任一條件成立即是）[H]：
  1. `risk.impact = high`，且 `risk.likelihood ∈ {high, medium}`；
  2. 威脅的 DFD 元素跨越**租戶邊界或認證邊界**，且涉及資料分級為機密或個資的 data store（依 G1 資料分級）；
  3. 涉及 G1 LLM 工具權限矩陣中標為「需人確認」的高影響動作；
  4. 來自種子威脅，其來源叢集為 `CONFIRMED_*` 或 `LIKELY`，且成員最高嚴重度為 `critical` 或 `high`。

  LLM 給的 likelihood／impact 只當**下限**：程式碼計算的結果與 LLM 提議取較高者；人在 G3 可以提高，降低時必須附理由（寫入 GateRecord）。
- **OWASP LLM Top 10 的版本**：
  - 2025 版（LLM01–LLM10）已完整查證 [V][E:threat_modeling-31]。
  - 2026 版已於 2026-08-03 發布 [S-01]。兩個獨立的二手來源列出一致的十項，Help Net Security 也報導了相同的變動：
    - Excessive Agency 升到 LLM03
    - Improper Output Handling 降到 LLM10
    - System Prompt Leakage 擴大並改名為 Hidden Context Exposure

    v0.1 時官方 PDF 未直接讀取，S-01 標 [P]。
  - v0.2：官方 PDF（122 頁）已讀取，列出的 LLM01:2026–LLM10:2026 與上述一致 [V][E:threat_modeling-73]；S-01 已升級為 [V]（發布日的一天差異見 [01 §4](01-research-survey.md#4-撰寫文件時補做的查證)）。
  - → 每筆威脅都存 `taxonomy: "owasp-llm@2025"` 或 `"owasp-llm@2026"`；**新的委任預設 `owasp-llm@2026`**；既有委任可沿用 2025 版，以 2025↔2026 對照表轉換（[04 §2.3](04-threat-to-testcase.md#23-owasp-llm-top-10-20252026-對照)）。
- **多模型流程**：
  1. 2–3 個不同家族的 Threat Modeler 各自產出（`B2_threat_fanout`）；一組只看外部視角。
  2. Merger 去重（`B2_merge_critic`）。
  3. Critic（另一家族）找遺漏，並**逐項處置 `b1_diff`**：納入模型（連到威脅 ID）或駁回（附理由）；未處置的差異項會擋住 G3 [H]。
  4. **每個種子威脅都必須出現在模型中**（缺少就由程式碼補上一筆 `seed-only` 威脅，並在 G3 標示）[H]。
  5. 每個威脅必須有證據（端點、資料流、程式位置）；證據對不到就標「未驗證」。
- **正本格式**：工具包自有 JSON schema（[schemas/threat.schema.json](schemas/threat.schema.json)）。pytm 的威脅是對元件屬性的條件式規則（引用 CAPEC／CWE），另有 LLM 元素的 LLM01–09；114 條威脅中 98 條引用 CAPEC、75 條引用 CWE [C][E:threat_modeling-11]。所以 pytm 匯出只算部分匯出，ASI、MAESTRO、LINDDUN 只存在自有 schema。
- **為何強制人簽核（G3）**：
  - 一項只分類 6 個 5G 威脅的研究：STRIDE 分類的平均準確度從 63%（zero-shot）到 71%（few-shot＋網路），最佳單一結果 72% [V][E:threat_modeling-20]。
  - 同一研究群的後續研究（兩篇並非彼此獨立）：更大或經領域調適的模型都沒有穩定改善 [V][E:threat_modeling-21]。
  - G3 允許**逐項**接受、拒絕、要求補充；被拒絕的威脅不產生測試，但保留在紀錄中。**駁回種子威脅時理由必填**；駁回會在叢集上註記（05 R13）。標為「W4 後轉為爭議」的種子威脅在 G3 另列一區，審查者要明確處理（接受並測試，或駁回附理由）[H]。處理路徑見 [§1.4](#14-關卡結果與-run-狀態)。
- **輸出**：`threat-model.json`（已簽核版本附 hash）、`b1_diff` 處置紀錄。

### B3 威脅 → 需求 → 測試案例
- **輸入**：G3 已簽核的威脅、G1 規格、crosswalk、ROE、工具登錄（`tools.yaml`）、seed manifest。**輸出**：測試案例（含 `request_allowlist`）、產生的腳本與設定（附 hash）、測試計畫。

詳見 [04](04-threat-to-testcase.md)。重點：
- 追溯鏈的每條連結都標 `official`／`curated`／`llm-suggested`。
- `tool_binding` 三選一：`BUILTIN_CHECK`／`GENERATED_SCRIPT`／`MANUAL`；`adapter` 是 `tool:mode` 格式的工具 ID（例如 `zap:active`、`playwright:api`）。
- `safety_class` 由程式碼計算。
- 產物驗證（`B3_validate_artifacts`）失敗 → 回到 `B3_derive` 修復，最多 2 次；仍失敗 → 該測試案例改為 `MANUAL`（附原因）[H]。
- 測試計畫與每個產物都要在 **G4** 綁定 hash 核准；G4 可逐測試案例部分核准。
- **覆蓋規則**：每個已接受的威脅有測試案例或 `MANUAL`；每個非 `REJECTED` 的種子威脅有 ≥1 個測試案例，或有 G3 駁回紀錄。

### B4 執行
- **輸入**：G4 核准的測試計畫與產物、G5 核准紀錄（S2）、Session Provider 的角色憑證、seed manifest。**輸出**：測試結果（[schemas/testresult.schema.json](schemas/testresult.schema.json)）、請求紀錄、停止事件。
- 執行位置：Z3，經 Scope Proxy 出站；Scope Proxy 依每個測試案例的 `request_allowlist` 逐一放行，DELETE 只允許 seed manifest 中的 ID。
- **每個批次開始前 `B4_preflight`**：ROE 仍有效且在時間窗內、金鑰未撤銷、所有權重驗、kill switch 未觸發、預算足夠、（每個 S2 job 前）`toolkit.restore_drill_interval_days`（預設 7）天內有成功的 `restore_drill` 稽核事件。時間窗外 → `SUSPENDED`；其他失敗 → `abort_handler`。
- 安全等級：
  - S0（被動）與 S1（良性主動）：ROE 允許就自動執行。
  - S2（侵入）：每次都要 **G5**；沒有成功的快照就不執行。
  - S3：一律拒絕。
- 停止條件或 kill switch 觸發時，進入 `abort_handler`：對每個「有快照但尚未成功還原」的 job 執行還原，再寫入稽核與中止報告，run → `STOPPED`。
- 限速、停止條件門檻、kill switch、DB 快照、LangGraph 節點邊界等細節，見 [03 §7](03-system-architecture.md#7-黑箱執行安全) 與 [06 §1](06-security-legal-limitations.md#1-工具包自身的安全)。

### B5 結果驗證
- **輸入**：測試結果、需求 oracle、相關叢集。**輸出**：判定、重新裁決後的叢集（例如 `LIKELY` → `CONFIRMED_EXECUTABLE`）。
- **確定性判定**：通過或失敗由 oracle 決定；LLM 只負責解讀與撰寫說明。
- **重播**：確認為漏洞前必須能重播（同條件再跑一次得到相同結果）。重播是新的 job，同樣受 ROE、`B4_preflight` 與（S2 時）G5 約束。
- **LLM 功能類採機率規則**：固定設定跑 n 次，記錄目標模型、版本與 temperature，報告成功率與信賴區間。只有確定性 oracle（工具呼叫紀錄、canary、狀態差異）成立才算 `CONFIRMED_EXECUTABLE`；只有 LLM 評分支持時，該測試結果列為 `E_inc`（[05 §4.2](05-bias-calibration.md#42-裁決狀態與有序規則)），不提升裁決；裁決仍只看投票與其他證據（因此最高 `LIKELY`）。promptfoo 以 LLM-as-a-judge 評分 [V][E:reference_systems-23]；PyRIT 的 scorer 可以是生成式 AI [V][E:reference_systems-19]；garak 的 detector 表現不穩定 [V][E:reference_systems-22]。
- **跨家族驗證**：由不在該叢集家族中的 Result Analyst 驗證解讀；這是 `CONFIRMED_EXECUTABLE` 的必要條件（[05 §4.2](05-bias-calibration.md#42-裁決狀態與有序規則) R1）。沒有合格的 Result Analyst → 不升級為 `CONFIRMED_EXECUTABLE`，註記 `no_eligible_verifier`；但可重播的 FAIL 仍可作工具佐證（05 R5，最高 `CONFIRMED_CORROBORATED`）。
- **PASS 與不確定結果**：合格的 PASS 會把 `CONFIRMED_CORROBORATED`／`LIKELY` 降為 `DISPUTED`、在 `UNCORROBORATED` 上加註記，但**永遠不會自動變成 `REJECTED`**（05 R11）；不確定的結果只註記（05 R12）。
- **重新裁決**（`B5_readjudicate`）：結果寫回相關叢集，由 Aggregator 重新裁決，保留每一版。此時才轉為 `DISPUTED` 的叢集不回到 G2 或 G3，而是列入 B6 的人工複核清單 [H]。
- **PII**：若在回應中偵測到個資，觸發停止條件，B5 的解讀改成只用自架模型。

### B6 報告
- 輸出（M4 起 JSON＋SARIF＋追溯矩陣；M5 起加靜態 HTML；**不提供儀表板**）：
  - SARIF
  - 人讀報告（Markdown／靜態 HTML）
  - 機器可讀 JSON 與報告清單（`report-manifest.schema.json`：列出每個產物的 hash）
  - **追溯矩陣**：威脅 → 需求 → 測試 → 結果 → 回連白箱發現項
  - **威脅覆蓋率**：已簽核威脅中至少有一個已執行測試的比例
  - **未能測試清單**：`MANUAL`、G4 駁回的測試案例、G5 駁回或逾時的 S2 job、所有權驗證失敗的目標、ERROR／SKIPPED／STOPPED 的執行、GB 停止的階段
  - 每個種子威脅的結果；G3 駁回者列為「未做黑箱驗證（G3 駁回：理由）」
  - Lane A 帶入的參考性發現項及其在本次的結果
  - **人工複核清單**：`B5_readjudicate` 後轉為 `DISPUTED` 的叢集、帶 `post_g2_conflict` 註記的叢集 [H]
  - 回饋任務草稿：確認項 → `regression` run（白箱根因定位＋W4 回歸測試）；威脅衍生需求 → `followup` run
- 報告由 Reporter 撰寫敘事，**不改裁決**；Reporter 失敗時仍輸出確定性部分，敘事欄標示缺漏。
- run 最終狀態：未能測試清單中只有 `MANUAL` → `COMPLETED`；否則 `COMPLETED_WITH_GAPS`。

## 4. 階段之間的交接與回饋

| 從 | 到 | 產物 | 規則 |
|---|---|---|---|
| W0 | 所有 LLM 節點 | `secrets-redaction-map` | 沒有遮罩對照表，Gateway 拒絕該 run 的所有請求 |
| W0.5（G1） | W4、B3 | `invariants.yaml` | oracle 只能引用已簽核條目 |
| W5 | B1、B2 | `dfd.json`、`seed-threats.json` | 除 `REJECTED` 外的叢集都成為種子威脅；每個都要在 B2 模型中，且有 ≥1 個 B3 測試或 G3 駁回紀錄 |
| B1 | B2 | `b1_diff` | B2 critic 逐項處置（納入或駁回附理由） |
| B2（G3 之後） | W0.5 | 威脅衍生的新需求 | 由 CMD-5 建立 **`followup` run** 草稿 → W0.5 帶入草稿 → 重新走 G1 → 重跑 W4 |
| B5 | W4 | 已確認的黑箱問題 | 由 CMD-5 建立 **`regression` run** 草稿 → 定位到 file:line → 產生回歸測試（X 家族寫、Y 家族審） |
| W3 | B5 | 非 `REJECTED` 的叢集 | 黑箱結果寫回叢集並重新裁決 |
| Lane A | 下一個 Lane B run | 參考性發現項（最高 `UNCORROBORATED`） | 作為額外輸入；不能直接進 `CONFIRMED_*`；不計入 `independent_families`（05 R9） |

## 5. 階段與關卡規格總表

欄位說明：**區**＝執行區（Z1 控制平面、Z2 程式執行沙箱、Z3 黑箱執行區，見 [03 §2](03-system-architecture.md#2-部署與信任區)）；**schema**＝`docs/schemas/` 下的檔名（含 v0.2 新增者）；**里程碑**＝[07](07-roadmap.md) 的 M1–M5。以下分配都是設計假設 [H]。

### 5.1 白箱階段與關卡

| 步驟 | 輸入 | 輸出 | 區 | LLM | 失敗處理 | 完成條件 | schema | 里程碑 |
|---|---|---|---|---|---|---|---|---|
| G0a | `engagement.yaml`（含 `signatures[]`）、`key-registry.yaml`、`toolkit.yaml`（根金鑰指紋） | G0a GateRecord（`signatures: []`＋`verification` 區塊）、run 紀錄 | Z1 | 否 | 驗章失敗、金鑰撤銷、過期、模型不在允許清單 → `ABORTED` | 簽章有效、角色相符、在有效期間內、每個 agent 的模型都在該資料等級的允許清單中 | engagement、key-registry、toolkit-config、gate-record、run | M1 |
| W0 | repo（commit SHA）、路徑黑名單 | `inventory.json`、SBOM、`secrets-redaction-map`、secrets 發現（位置＋hash；預設 Betterleaks／gitleaks） | Z2 | 否 | 任何子步驟失敗 → `FAILED` | entry point 都有 handler；table 都有 RLS 狀態；遮罩對照表已登錄 | run（`inventory_ref`、`redaction_map_ref`）、inventory、redaction-map | M1 |
| W0.5 | 遮罩後 inventory、ASVS 5.0 L1、（followup）威脅衍生需求 | `invariants.yaml` 草稿 | Z1 | 是（Invariant Drafter） | schema 修復 ≤2 次；仍失敗 → 只交 ASVS 基準＋空白矩陣給 G1，由人補齊 | 草稿通過 schema | invariants、requirement | M2 |
| G1 | 不變量草稿＋與上一版的差異 | GateRecord（G1）、已簽核 `invariants.yaml` | Z1 | 否 | REJECTED／NEEDS_INFO → W0.5，≤3 輪 → `ABORTED`；EXPIRED → `SUSPENDED` | APPROVED 且簽章、hash 綁定有效 | gate-record、invariants | M2 |
| W1 | repo、SBOM、遮罩對照表 | `w1.sarif`、`deps-check.json` | Z2 | 否 | 單一工具失敗 → 列為缺口、其他繼續；全部失敗 → `FAILED` | 全部工具以鎖定版本跑完；失敗已列出 | tool-registry（工具版本）；SARIF 2.1.0 | M1 |
| W2 | inventory、已簽核不變量、`w1.sarif`、遮罩後切片、CMD-1 計畫 | `findings[]`、缺票、多樣性旗標 | Z1（Slicer 為程式碼） | 是（多家族 reviewer；Commander） | 重試上限用盡 → 缺票；低於 quorum → R8 封頂；計畫不合規 → 修復 ≤2 次後改用覆蓋下限計畫；預算觸頂 → GB | 每個切片 × 必要面向都有結果或缺票紀錄 | slice、commander-plan、finding | M2 |
| W3 | findings、`w1.sarif` | clusters、verdicts（含 `rule_trace`）、G2 佇列 | Z1 | 是（verifier、Commander）；裁決為程式碼 | 無合格驗證者 → `no_eligible_verifier`（R6／R7）；CMD-2 加派 ≤2 輪 | 每個叢集都有裁決與 `rule_trace` | cluster、verdict、commander-plan | M2 |
| G2 | G2 佇列（DISPUTED＋高嚴重度 UNCORROBORATED） | GateRecord（G2）、逐項決定 | Z1 | 否 | 佇列為空 → 略過；見 [§1.4](#14-關卡結果與-run-狀態) | 每項有決定或已標逾時 | gate-record、verdict | M2 |
| W4 | 已簽核不變量、LIKELY 以上叢集、遮罩後程式碼 | 測試檔、測試結果、覆蓋率、mutation score、新版裁決 | Z1（產生）＋Z2（執行） | 是（Test Generator／Test Critic，不同家族） | 生成失敗 → 修復 ≤2 次；沙箱失敗 → 重試 1 次後記 `ERROR`；CoverUp 迭代 ≤3 輪 | 每條不變量有測試或 `MANUAL`；結果已回寫並重新裁決 | testresult（`phase: W4`）、verdict、requirement | M2 |
| W5 | inventory、clusters／verdicts、不變量 | `whitebox-report.md`、`w.sarif`、`dfd.json`、`seed-threats.json` | Z1 | 部分（DFD 標籤提議、報告敘事） | LLM 失敗 → 只輸出確定性 DFD 骨幹與報告的確定性部分 | 每個非 REJECTED 叢集都有種子威脅 | dfd、seed-threats、report-manifest | M2 |
| GB | 預算狀態與下一步的預估消耗 | GateRecord（GB）：延長（新上限）／停止本階段／中止 | Z1 | 否 | EXPIRED → `SUSPENDED` | 有簽章決定 | gate-record、run（budgets） | M2 |
| Lane A | PR diff、W0／W1 結果 | 參考性發現項 | Z2＋Z1 | 可選（單一家族，須在 G0a 允許清單中） | 任何失敗 → PR 檢查標示失敗，不阻擋 Lane B | W0、W1 完成；diff 審查（若啟用）有結果或缺票 | run（`run_kind: lane_a`）、finding | M1（W0／W1）、M2（diff 審查） |

### 5.2 黑箱階段與關卡

| 步驟 | 輸入 | 輸出 | 區 | LLM | 失敗處理 | 完成條件 | schema | 里程碑 |
|---|---|---|---|---|---|---|---|---|
| G0b | `roe.yaml`（含 `signatures[]`）、`key-registry.yaml`、委任設定 | G0b GateRecord（`signatures: []`＋`verification` 區塊）、出站白名單草稿 | Z1 | 否 | 驗章失敗 → `ABORTED`；未生效／時間窗外 → `SUSPENDED`；已過期或未提供 → B6 → `COMPLETED_WITH_GAPS` | 簽章有效、三個必要角色齊全、在委任期間內；`legal_review` 通過 L-1～L-6 | roe、key-registry、engagement、gate-record | M1 |
| B0 | ROE 目標與 token 參照 | 每個目標的簽署驗證結果、最終出站白名單 | Z3（經 Scope Proxy） | 否 | 單一目標失敗 → 排除並列為缺口；全部失敗 → B6 → `COMPLETED_WITH_GAPS`；Z3 無法連線，重試 3 次後 → `SUSPENDED` | 每個目標都有簽署結果 | run（`ownership_results`）、audit-event | M1（最小 Z3 出站執行器） |
| B1 | OpenAPI／GraphQL schema、DFD、種子威脅、ROE 測試角色 | 外部視角模型、合併視角模型、`b1_diff` | Z3（爬行）＋Z1（建模） | 部分（System Modeler 標籤） | 爬行觸發停止條件 → 外部視角只用 schema，列為缺口 | 兩個模型與差異清單都已產出 | dfd（含 viewpoint 與差異清單） | M3 |
| B2 | 兩個模型、`b1_diff`、種子威脅、CMD-3 分類計畫 | 威脅模型草稿、`b1_diff` 處置、高風險威脅的 attack tree | Z1 | 是（Threat Modeler ×N、Merger、Critic；Commander） | modeler 低於 quorum → 標記多樣性降低；critic 失敗 → 重試後在 G3 標示「未經 critic」 | 每個種子威脅都在模型中；每個差異項已處置；每個高風險威脅有 attack tree | threat、seed-threats、commander-plan | M3 |
| G3 | 威脅模型草稿 | GateRecord（G3）、已簽核威脅模型 | Z1 | 否 | 見 [§1.4](#14-關卡結果與-run-狀態) | 每個威脅有決定；駁回種子威脅都有理由 | gate-record、threat | M3 |
| B3 | 已接受的威脅、不變量、crosswalk、ROE、工具登錄、seed manifest、CMD-4 計畫 | 測試案例、產物（附 hash）、測試計畫 | Z1 | 是（Test Designer；Commander）；安全等級與產物驗證為程式碼 | 產物驗證失敗 → 修復 ≤2 次 → `MANUAL` | 每個已接受威脅有測試或 `MANUAL`；每個非 REJECTED 種子威脅有測試或 G3 駁回 | testcase、requirement、crosswalk、tool-registry、seed-manifest | M4 |
| G4 | 測試計畫、產物 hash、計算後的安全等級 | GateRecord（G4），逐測試案例決定 | Z1 | 否 | 見 [§1.4](#14-關卡結果與-run-狀態) | 每個測試案例有決定；hash 綁定有效 | gate-record、testcase | M4 |
| B4 | 已核准測試案例與產物、G5 紀錄、角色 session、seed manifest、快照設定 | 測試結果、請求紀錄、停止事件、快照／還原紀錄 | Z3 | 否（多輪 LLM 測試經 Z1 relay 呼叫） | 停止條件／kill switch → `abort_handler` → `STOPPED`；還原失敗 → `FAILED`；時間窗外 → `SUSPENDED` | 所有核准的測試已執行或記錄原因；所有快照都已還原 | testresult、seed-manifest、audit-event | M4（S0／S1／S2）、M5（LLM 多輪） |
| G5 | 單一 S2 job（產物 hash、目標、快照計畫） | GateRecord（G5） | Z1 | 否 | REJECTED／NEEDS_INFO／EXPIRED → 該 job 略過並記錄 | 核准者 ≠ 發起者、在 ROE 時間窗內 | gate-record | M4 |
| B5 | 測試結果、需求 oracle、相關叢集 | 判定、新版裁決 | Z1 | 是（Result Analyst，跨家族；PII 時只用自架） | 無合格 Result Analyst → 不升級並註記；重播需新 job | 每個結果有判定；機率類有 n、k、信賴區間 | verdict、testresult | M4（確定性）、M5（機率類） |
| B6 | 以上全部 | SARIF、JSON、追溯矩陣、報告清單、（M5）靜態 HTML、後續 run 草稿 | Z1 | 是（Reporter 敘事） | Reporter 失敗 → 只出確定性部分 | 追溯矩陣完整；每個種子威脅都有結果或駁回理由；最終狀態已判定 | report-manifest、run | M4（JSON／SARIF／矩陣）、M5（HTML） |
