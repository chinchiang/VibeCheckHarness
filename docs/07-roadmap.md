# 07 實作路線圖

> 本文件列出文件核准之後的實作計畫：每個元件與節點在哪個里程碑完成，以及每個里程碑的出口準則。每一條出口準則都可以量測，也都可能不通過。
>
> 安全控制放在最前面（M1）：ROE 驗章與 Scope Proxy 完成之前，不寫任何會連網的功能。
>
> 以下內容本文件不重複：
> - 模組配置、介面、CLI、測試清單與前兩週工單：見 [08 實作規格](08-implementation-spec.md)；
> - 出口準則中的 `N-xx`：見 [08 §8.2](08-implementation-spec.md#82-m1-必須拒絕清單負面安全測試)；
> - 範例應用：見 [08 §8.3](08-implementation-spec.md#83-範例應用整合測試的目標)。
>
> 里程碑的切分與出口準則都是設計選擇 [H]。

## 現況

第十輪審查（2026-10-27）後的設計，裁決規則版本 `05-v0.10`。本文件描述現在的規則；正文中「審查 rN」「v0.x」等字樣只出現在說明「為什麼這樣規定」的句子。各版的變更摘要移到 [evidence/doc-history.md](evidence/doc-history.md#07-實作路線圖)，逐版的完整變更見 [CHANGELOG](../CHANGELOG.md)，審查紀錄見 [evidence/](evidence/)。

## 1. 總覽

| 里程碑 | 主題 | 可以交付什麼 |
|---|---|---|
| **M1** | 基礎與安全控制 | 驗章、稽核、Gateway（fail-closed）、Z2 沙箱、W0／W1、最小的 Z3（所有權驗證）、CI Lane A。**還沒有任何 LLM 審查** |
| **M2** | 白箱多家族審查 | W 子圖全部、Gate Service（G1、G2、GB）、Calibration Lab、白箱報告 |
| **M3** | 威脅建模 | B1、B2、G3 |
| **M4** | 黑箱執行 | B3–B6、G4、G5、Z3 完整版、S2 快照與還原、CI Lane B 完整版 |
| **M5** | LLM 功能測試與報告 | LLM Relay、機率判定、靜態 HTML 報告 |

- 進入每個里程碑之前，§3 的入口閘門都要結案；
- 離開之前，§4 的出口準則全部通過，而且達到 [08 §9.1](08-implementation-spec.md#91-各里程碑) 的完成定義。

### 1.1 分段 MVP

里程碑 M1–M5 是依元件分層切的；只完成 M1 時，使用者還拿不到任何可用的結果。因此 v0.3 把**開發與交付的順序**改成下列四段縱向切片 [H]：
- 每一段都能獨立交付，並有自己的出場條件（`MVPn-Xk`）。
- 每一段也沿用部分 M 準則。一個 M 里程碑的全部準則，要等它的元件都完成後才整體驗收。
- 已經寫在 M 準則裡的，不在這裡重複。

| 階段 | 交付什麼 | 不包含 | 可用的模式 | 沿用的 M 準則 |
|---|---|---|---|---|
| **MVP-0 白箱、不連網** | 依序為：<br>• G0a、W0（secrets 掃描與遮罩；inventory 先支援 Next.js＋Supabase：路由、server action、middleware、migrations 與 RLS policy、環境變數名稱，[08 §11.1](08-implementation-spec.md#111-w0-盤點抽取器與支援矩陣)）<br>• W0.5／認領與 G1（G1 在 W1 之前，由本 run 核准）<br>• W1：SCA、經鏡像的套件存在性、前端 bundle 的公開環境變數（`public_prefix`：`NEXT_PUBLIC_`、`VITE_`、`EXPO_PUBLIC_`、`PUBLIC_`）<br>• W2／W3：1–3 個家族，裁決標 `provisional`<br>• W4：Z2 內的本地測試，包含拋棄式 PostgreSQL 上的 RLS 測試，以及用腳本式假模型輸出驗證工具防護<br>• W5：報告、SARIF、指紋 | Z3、G0b、任何對目標的網路請求；Calibration Lab 的門檻 | Lite、Team、Full | M1-X4～X7；M2-X4、X6、X10、X11；§3 中 MVP-0 用到的元件的入口閘門（MVP0-X7） |
| **MVP-1 本地拋棄式目標** | 在隔離環境中啟動範例應用（`http://localhost`；ROE 只對 `localhost`、`127.0.0.1`、`[::1]` 允許 `http://`，其他一律 `https://`，`E-ROE-URL`），跑 B0–B6：<br>• G0b 與 `legal_review`<br>• 所有權用 well-known path 證明，由範例應用提供<br>• S0／S1<br>• S2 只在本地 DB 可快照還原時執行<br>• 範例 A 端到端 | staging、共享平台網域、LLM 功能測試 | Team、Full（Lite 只能跑 S0／S1） | M1-X1～X3；M3-X1、X5；M4-X2～X5、X7 |
| **MVP-2 staging（S0／S1）** | 真實 staging，包括：<br>• `legal_review` 涵蓋 staging 的範圍與條款（G0b 已在 MVP-1 交付）<br>• 所有權證明，包含 `platform_project`<br>• Scope Proxy 與 TLS 終結<br>• Session Provider 與 whoami<br>• `build_identity` 檢查 | S2、G5、relay | Lite、Team、Full | M1-X8、X9；M4-X3、X8 |
| **MVP-3 以後** | 依序加入：<br>• staging 的 S2＋G5（Full 模式需兩人核准）<br>• LLM 功能測試，先做 G4 核准的腳本式多輪（M5）<br>• Calibration Lab 與 `high_precision_rules`（M2-X1）<br>• CI Lane B 完整版<br>• 靜態 HTML 報告<br>• adaptive relay（只限 Full，[09 BL-10](09-backlog.md)） | — | 依功能而定 | M2-X1～X3、X5、X7～X9、X12；M4 其餘；M5 全部 |

**出場條件**：

| # | 準則 | 如何量測 | 不通過的判斷 |
|---|---|---|---|
| MVP0-X1 | 在 `notes-rls-app`（Next.js＋Supabase 型的範例，[08 §8.3](08-implementation-spec.md#83-範例應用整合測試的目標)）上找出下列三個植入問題：<br>• 沒有 RLS 的資料表：以 `inventory_fact` 證據支撐（寫法同範例 F-061：`fact_ref` `/db/tables/0/rls_enabled`、`asserted: false`）<br>• bundle 中的公開前綴金鑰<br>• 幻覺套件名稱 | 整合測試（CI 用錄製的 LLM 回應） | 任一個沒有找到，或 RLS 問題因為交不出程式片段而被判 `REJECTED` |
| MVP0-X2 | 遮罩之前沒有任何 LLM 呼叫；除了 Model Gateway 與套件鏡像，沒有任何出站連線 | 稽核檔＋Z2 出站紀錄 | 有任何一例 |
| MVP0-X3 | SARIF 通過 SARIF 2.1.0 schema 驗證，並符合 §3.27.9–3.27.10 的 `kind`／`level` 規則（`kind` 不是 `fail` 的 result，`level` 為 `none`）[V][E:whitebox-59]；在同一個 commit 上重跑時，所有叢集的 `baseline_state` 都是 `unchanged` | `fast` 線＋整合測試 | 驗證失敗，或指紋不穩定 |
| MVP0-X4 | 沒有校準資料時，每個可能由投票決定的裁決（決定表第 6–9、11–13 列、非黑箱叢集）都是 `provisional`；R0／R1／R9／R10 決定的裁決（第 1–5 列）、強工具佐證決定的裁決（第 10 列）與黑箱叢集不是；沒有可執行證明的叢集不會是 `CONFIRMED_*` | 性質測試 | 有任何一例 |
| MVP0-X5 | 單人使用（Lite）時，engagement 有 `role_consolidation` 聲明，報告首頁標示「單人模式，未經職責分離」 | validator（`E-ENG-PROFILE`、`E-GATE-SOD`）＋報告測試 | 缺少聲明卻通過（一人在同一份關卡紀錄中兼任兩個角色而沒有 `E-GATE-SOD`），或報告沒有標示 |
| MVP0-X6 | **前導實驗**（§1.2）已依預先登記執行，決定已寫入 `calibration.yaml` 的 `recommended_defaults`（MVP-1 起的 `w2_review.strategy`）與報告 | 前導實驗報告：預先登記的 hash、每個應用的原始結果、決定 | 沒有預先登記就解盲；應用中有工具包團隊撰寫的；報告缺少決定，或 MVP-1 的預設值與決定不符 |
| MVP0-X7 | MVP-0 會用到的元件，其 §3 入口閘門都已結案：「M1 前」的 Anthropic API 條款、Semgrep／CodeQL（不啟用則免）、psycopg 的散布形式（MVP-0 就用 Z1 的 Postgres checkpointer）、G-11 的 runsc／Firecracker 版本固定與 CVE 訂閱（MVP-0 的 W0、W1、W4 都在 Z2）；「M2 前」的 OpenAI API 條款（G-13）、GPT-6 的 ZDR 書面確認（G-06）、NIM 用途（使用 `nemotron_self` 時）。v0.3 的 MVP-0 只沿用 M1-X4～X7，雲端模型的條款還沒確認就能出貨 | 驗收包中的法務紀錄，或證明該元件已停用的設定檔（engagement 的 `allowed_models`、`config_pins`） | 有未結案的項目，而對應的模型或工具仍然啟用 |
| MVP0-X8 | **Lite 使用者 pilot**（§1.3）：≥8 位不屬於工具包團隊的單人開發者，各自以自己的應用跑 Lite 的 MVP-0。門檻 [H]：從開始安裝到拿到第一份白箱報告的中位數 ≤ 1 個工作天；每個 run 的人工關卡總耗時（`claim_run`、G0a 簽署、G1 問卷與簽核、**G2 逐項決定**、GB）中位數 ≤ 2 小時，G2 另記每項的耗時與 `needs_info` 的比例；沒有人因為金鑰與簽章設定而放棄 | pilot 紀錄（各步驟時間戳記、放棄原因）；也記錄 [03 §6.5](03-system-architecture.md#65-人力負擔與周轉時間h) 每個關卡的實際人時，與設計假設比較 | 任一門檻沒有達到，且沒有啟用 §1.3 的降階路徑 |
| MVP1-X1 | 範例 A 在本地目標上：<br>• 植入版的 TC-012-01 FAIL，並且**不經 LLM 分析者**就裁決為 `CONFIRMED_EXECUTABLE`（G4 已事先登記解讀）<br>• 修正版 PASS，且所有 control 都通過 | 整合測試 | 任一步不符 |
| MVP1-X2 | run 中每一個寫入請求都綁定 `{seed:}`、`{created:}` 或 create-only 端點（沒有綁定的測試案例算出 S3，`E-TC-MUTATION-SCOPE`） | Scope Proxy 紀錄 | 有任何一個沒有綁定的寫入 |
| MVP1-X3 | 故障注入（session 過期、路徑錯誤、種子遺失）時，結果是 `INVALID`，不是 PASS；報告列出 control 通過率 | 整合測試 | 有任何一例被當成 PASS |
| MVP1-X4 | 沒有來源叢集的黑箱威脅，每一筆結果（FAIL、PASS、INVALID 都一樣）都寫進該威脅 `origin: black_box` 的叢集並有裁決（`E-CLUSTER-ORIGIN`；範例 K-201、K-202） | 整合測試 | 結果沒有裁決路徑 |
| MVP2-X1 | 部署的版本與 `repo_commit` 不一致時，job 不執行，並列入 B6；`build_identity.method: none` 的目標在報告中列為「版本未驗證」（`build_unverified_targets[]`；`tester_controlled` 的目標如 canary 除外；`E-RESULT-BUILD`） | 整合測試 | 不一致仍執行，或報告沒有列出 |
| MVP2-X2 | 共享平台網域的目標沒有 `platform_project` 證明與同一平台的 `platform_policies` 時，G0b 拒絕（`E-ROE-PLATFORM`） | `security` 線 | 被接受 |
| MVP2-X3 | 每一批測試前，每個角色都先通過 whoami；需要 CAPTCHA 或第三方 IdP、卻沒有 staging 旁路的角色，其測試標 `SKIPPED` 並列入 B6 | 整合測試 | 未驗證身分就執行，或沒有列出略過的測試 |
| MVP2-X4 | ST-1＝0：canary-server 的「ROE 以外」接收器沒有任何命中 | `selftest-report.json` | 大於 0 |
| MVP2-X5 | **Scope Proxy 原型關卡**：必要案例全部符合預期；Executor 的必要 HTTP 工作流通過；未通過的 adapter 不啟用 | 原型報告（實際版本、支援與拒絕情況、越界接收器紀錄） | 有必要案例未通過仍進 MVP-2；有 adapter 改用直連或關閉 TLS 驗證 |

### 1.2 前導實驗：MVP-1 之前的預設值決策 [H]

05 §5.6 的正式檢定需要約 40 個應用的保留切分（M2-X1），要到校準語料完成才能做（09 BL-11，依 U-10）。在那之前，MVP-0～2 若一律假設多家族比較好，就是在未經檢驗的前提上花三倍的供應商成本。所以 MVP-0 結束前先做一次小型、預先登記的前導實驗，只用來決定**預設值**，不當成科學證明。

- **應用**：≥10 個**不是工具包團隊撰寫**的 vibe-coded 應用，例如請外部開發者以 vibe coding 工具生成、或 git 歷史中有已修正安全問題的公開 repo（以修正前的 commit 當受測版本）。每個應用都有人工確認的已知缺陷清單；生成工具的家族盡量平衡（05 §5.1）。
- **兩組**：③ 多家族（3 個家族各 1 次，≥2 個家族回報才接受）對照 ②a 單一最佳模型取樣 3 次（≥2 次回報才接受）。M\* 在另外 3 個應用上選出，不在這 10 個應用上選。
- **預先登記的決策規則**（解盲前寫入 `calibration.yaml` 的 `preregistration`，含本節版本的 hash）：
  - Δrecall＝recall(③) − recall(②a) 的點估計 ≥ +5 個百分點，**而且** precision(③) − precision(②a) ≥ −5 個百分點 → MVP-1 起維持 `w2_review.strategy: multi_family`；
  - 否則 → MVP-1 起預設 `single_best_resampled`（05 §5.6 的定義），多家族降為選用；跨家族 verifier 保留（它的價值另由 M-4 判斷）。
  - 不論結果如何，M2 的正式檢定（05 §5.6）照常進行，並依它的結果再切換一次（M2-X13）。
- **對照一次外包滲透測試**[H]：至少 3 個應用另外委託一次人工滲透測試（同一 commit、同一 staging、同樣的時間窗），比較兩者確認的問題、各自獨有的問題、人時與費用。目的是回答「先制」相對於傳統做法到底多了什麼：沒有這個對照，對外不宣稱工具包比 DAST 或滲透測試更好。結果寫入 MVP-1 的出口報告。
- **報告另外列出**：每個已確認缺陷是由 W0／W1 的確定性規則、還是只由 W2 的 LLM 審查找到。只有 LLM 找到的比例，是 W2 值不值得花費的第一個實測訊號（MVP0-X1 的三個植入問題都能由確定性規則找到）。
- **誠實說明**：10 個應用（約 50–100 個缺陷）偵測不到小於約 10 個百分點的差距，點估計的誤差也大；這個規則只保證「沒有看到明顯效益時，不預設花三倍的錢」。
- **比較的公平性**[H]：
  - 另外比較**純工具**（W0／W1，不用 LLM）這一組，三組（純工具、②a、③）用同一個工具基線、同樣的可見輸入、工具版本與時間窗；LLM 組的模型與 prompt 版本固定。
  - 事先固定每組相同的總費用上限、重複次數與停止規則，按實際費用與人工分鐘分別報告（純工具不必用完上限）；指揮官的加派另列有效發現與邊際成本。
  - 真值由沒有參與開發與調參的標註人先固定（範圍與評分規則一併固定）；以應用為單位報告差異與區間，記錄 INVALID／未執行、人工複核時間、延遲與費用的不確定部分。
  - 開始後不能因為看到結果而調整 prompt 或挑選最佳組合；要調整就保留這一輪的結果，改用新的保留資料。
  - 錄製的 LLM 回應（CI）只驗證流程、序列化與裁決，**不能**證明模型的召回率或多家族的加值；在有對應實測之前，不對外宣稱「更準」「更省」或「已校準」。

### 1.3 Lite 的使用者 pilot 與降階路徑 [H]

Lite 號稱「一個人就能用」，但目前的設計要求單人開發者自建組織根金鑰與金鑰登錄、以 Ed25519 簽署委任設定、回答 G1 問卷，B 階段還要三角色 ROE、法務聲明、seed manifest、whoami 端點與 `build_identity` 標頭。這些對目標使用者（不讀程式碼的 vibe coder）可能是放棄的理由，必須實測（MVP0-X8）。

**pilot 未達門檻時的降階路徑**（擇一或並用，選擇記入 08 §10 的待決事項）：
- **Lite 白箱快速模式**：只跑 MVP-0（白箱、不連網、沒有 G0b 與 B 階段）。`vibecheck init` 在本機產生一把金鑰，建立只有一個人的金鑰登錄與委任設定，使用者只需確認一次；報告首頁標示「單人、自行簽署、只有白箱」。安全底線（先遮罩再送 LLM、跨境聲明、設定檔釘選）不變。
- **精簡 Lite 流程（候選，v0.6 審查 r7；本輪不實作）**：只做 S0（被動讀取，不需要 seed manifest、whoami 與 G5）、使用本機產生的單一金鑰、ROE 由範本自動填入目標與時段，使用者只確認一次並簽署。代價是黑箱只剩被動檢查；是否採用涉及產品範圍，留待 pilot（§1.3）的結果決定。
- **G1 問卷精簡**：只問存取控制矩陣的核心題（每個角色 × 有個資的資源），其他條目用 ASVS L1 基準與預設值，在報告中標示「未經使用者確認」。
- **託管控制面**：由可信的第三方代管 Z1／Z2 與金鑰登錄，使用者只用硬體金鑰或 passkey 簽署。這改變信任模型（託管方看得到遮罩後的程式碼），需要另外的法務與威脅模型審查，不在 v0.4 範圍。

### 1.4 實作前置工作與驗收順序 [H]

下列項目是設計契約，尚未實作或驗收；元件的里程碑歸屬（§2）不變，交付時點以這張表為準，不能因為原本列為低優先就跳過。

| 時點 | 必須完成 | 驗收 |
|---|---|---|
| MVP-0 開始派送 job 之前 | BL-22／23 產物生命週期與 BL-13 純工具路徑（v0.5 的 schema 與 validator 已完成，執行期待實作）、BL-31 job 原子領取與結果不明的處置 | 08 §11.13 的生命週期案例；雙 worker 同時搶領、舊 worker 復活、意圖記錄後／外部成功後／結果提交前後逐點當機、租約或代理中斷時有在途請求（03 §5.8） |
| MVP-0 交付之前 | BL-34 G2 駁回後新證據的報告與去重；純工具結果可以交付 | 沒有任何 LLM 發現項時，工具發現仍可追溯到報告；新證據只列一次並醒目呈現 |
| MVP-1 黑箱執行之前 | BL-31 在 Z3 出口強制 fencing；BL-28 還原範圍排他權（任何 `snapshot_restore` 之前）；BL-35 `{created:}` 的執行期 ID 擷取與 GraphQL 解析；S2 另需 BL-04 | 舊 worker、結果不明時不重送；兩個 run 爭用同一還原範圍時只有一方開始、目標別名不能繞過、背景寫入未停時拒絕；本 run 的 G4／G5 與職責分離 |
| MVP-2 staging 之前 | BL-32 Scope Proxy 原型關卡（MVP2-X5） | 08 §11.7 的全部必要案例 |
| CAS 實作之前 | BL-29 委任隔離與多參照保留（08 §7.3、§7.5） | 相同內容不同期限、不同資料等級、legal hold、多 run 共用、刪除後稽核 |
| 機率報告啟用之前 | BL-30 取樣獨立性與重播分離（04 §4.4） | 固定 seed 重播、快取重用、重置失敗、模型版本變更、有相關性的 trial 都不虛增 n′ |
| 啟用跨 run G1／G3 沿用之前 | BL-21 來源鏈驗證（v0.5 validator 已完成，`E-GATE-CARRY`；執行期的沿用畫面待實作） | hash 改變、過期、撤銷、來源缺漏都拒絕沿用 |
| 對外宣稱模型或指揮官有效益之前 | BL-33 比較的公平性（§1.2） | 依 §1.2 報告品質、人工成本、費用與不確定性；沒有勝出不阻擋功能性的 MVP |

### 1.5 人力與時程估算 [H]

這一節是契約：估算的假設與數字，pilot 要量測實際值並回填（[09 BL-63](09-backlog.md#41-第七輪2026-10-25-r7-審查起留下的實作項目)）。數字是設計假設，沒有外部證據；目的是讓「做得完嗎」可以被檢查，而不是承諾日期。

- **假設**：兩位全職工程師（一位熟悉 LangGraph 與 LLM 供應商，一位熟悉資安工具與沙箱），一位兼職的資安審查者（每週約 1 天，負責關卡與校準標註）；`tools/vchlib` 的 validator 與 schema 已可重用；不含法務閘門的等待時間（§3）。
- **人週**是兩位工程師合計的工作量；**日曆週**假設兩人並行、扣掉 20% 的整合與修正。校準語料的人工標註（[05 §5.1](05-bias-calibration.md#51-語料)）另計，不在下表。

| 里程碑 | 人週 | 日曆週 | 主要工作 | 風險最高的部分 |
|---|---|---|---|---|
| M1 基礎與安全控制 | 10 | 6 | ROE 與委任驗章、Scope Proxy、Audit Writer 與 Z3 副簽、kill switch、Run Controller 骨架 | Scope Proxy 的負面測試（[08 §8.2](08-implementation-spec.md#82-m1-必須拒絕清單負面安全測試)） |
| M2 白箱多家族審查 | 12 | 7 | W0 抽取器、Slicer、多家族審查與驗證、Model Gateway、裁決、校準流程 | 校準語料與標註（另需約 6 人週的標註） |
| M3 威脅建模 | 6 | 4 | B1 系統建模、B2 威脅建模、G3、對照表 | DFD 與 W0 inventory 的比對 |
| M4 黑箱執行 | 12 | 7 | B3 測試設計、B4 沙箱執行、快照還原、Session Provider、G4／G5 | 共享平台的所有權證明與快照 |
| M5 LLM 功能測試與報告 | 8 | 5 | 機率型測試、relay、B5 結果分析、B6 報告、SARIF | 機率型測試的次數與預算 |
| **合計** | **48** | **29** | | |

- **關鍵路徑**：M1 → M2 → M3 → M4 → M5 大致是序列的（M3 依賴 M2 的種子威脅，M4 依賴 M3 的 G3）；M5 的報告部分可以與 M4 並行，約省 2 週。
- **與分段 MVP 的對應**（§1.1）：MVP-0 約需 M1 的一半與 M2 的大部分（約 16 人週）；MVP-1 再加 M1 其餘與 M4 的本地執行部分（約 12 人週）。
- **什麼時候要重估**：任一里程碑的實際人週超過估算 50%，或校準語料不足以讓任何桶的 θ 可行時，重估後面的里程碑並回報委任的簽署人。

## 2. 元件與節點的歸屬

### 2.1 元件（[03 §1](03-system-architecture.md#1-元件總覽)）

| 元件 | M1 | M2 | M3 | M4 | M5 |
|---|---|---|---|---|---|
| Run Controller（LangGraph） | 骨架、checkpoint、resume、kill switch | W 子圖 | B1–B2、G3 | B3–B6、`abort_handler` | — |
| Policy Engine | 資料等級、端點與參數白名單、G0a、G0b、目標解析 | 計畫驗證（CMD） | — | 安全等級計算、產物驗證 | Relay 的上限 |
| Registries（模型、agent、工具、金鑰） | 全部 | `calibration.yaml` | — | — | — |
| Blackboard／CAS | ✓ | — | — | — | — |
| Model Gateway | fail-closed 的前置檢查、快取、修復、重試（M1 正式版沒有會呼叫 LLM 的節點） | 真實供應商、fallback、`earliest_retirement` 警告 | — | — | — |
| Audit Log | ✓ | — | — | — | — |
| Scope Proxy | 所有權驗證與 M1 的 GET | — | B1 的 S0 爬行 | 黑箱工具的攔截式 proxy（[08 §10](08-implementation-spec.md#10-尚未決定需使用者決定) U-13） | — |
| Sandbox Runner（Z2） | W0、W1 | W4（`hypothesis:property`、`fast_check:property`） | — | — | — |
| Z3 Executor | 最小版（`verify_ownership`、`http_get`） | — | B1 | 完整版（`run_job`、停止條件） | Relay 用戶端 |
| Commander | — | CMD-1、CMD-2 | CMD-3 | CMD-4、CMD-5 | — |
| ToolResult 正規化（[08 §11.2](08-implementation-spec.md#112-工具結果正規化與合併)） | W1 各工具輸出轉 SARIF | 轉成 ToolResult、區段對應函式、強／弱工具證據 | — | 黑箱證據的 ToolResult | — |
| Slicer、Clusterer、Aggregator | — | ✓ | — | 黑箱證據（[05 §4.2](05-bias-calibration.md#42-裁決狀態與有序規則)：`E_proof`→R1、`E_fail_u`→R2 的弱工具訊號（1 個獨立來源）→R4／R6、`E_pass`→R11、`E_inc` 與證據衝突→R12；黑箱起源叢集；B5 重新裁決） | 機率判定 |
| Gate Service | 只有 G0a／G0b 的離線驗章 | G1、G2、GB、`claim_run`、ASI09 抽查 | G3 | G4、G5 | — |
| Calibration Lab | — | ✓ | — | — | — |
| Budget Tracker | — | ✓ | — | — | Relay 的花費上限 |
| Session Provider | — | — | — | ✓ | — |
| Snapshot Service | — | — | — | ✓（S2、還原演練、oracle） | — |
| LLM Relay | — | — | — | — | ✓ |
| Reporter | — | 白箱（W5） | — | B6：JSON、SARIF、追溯矩陣 | 靜態 HTML |
| 自測（06 §1.2.1） | ST-1、ST-3、ST-7 | ST-2、ST-4、ST-5 | INJ-DOC | ST-6、INJ-HTTP | INJ-LLMAPP |

### 2.2 節點（[03 §5.7](03-system-architecture.md#57-節點規格表)）

| 里程碑 | 節點 |
|---|---|
| **M1** | `run_init`、`G0a_engagement_check`、`W0_inventory`、`LA_static`、`W1_static`、`G0b_roe_check`、`B0_ownership_verify`、`run_resume`、`suspended_wait`、`m1_finish`（M1 暫時的結束節點，M2 起由 `W5_report` 取代，M4 起由 `B6_report` 取代，[08 §9.2](08-implementation-spec.md#92-m1-前兩週的工單)） |
| **M2** | `W05_draft_invariants`、`claim_run`、`G1_gate`、`W2_slice`、`CMD1_plan`、`W2_fanout`、`W2_review`、`W2_fanin`、`W3_cluster`、`W3_verify_fanout`、`W3_verify`、`W3_adjudicate`、`CMD2_redispatch`、`G2_gate`、`W4_testgen`、`W4_exec`、`W4_readjudicate`、`W5_report`、`GB_budget_gate`、`LA_diff_review` |
| **M3** | `B1_crawl`、`B1_model`、`CMD3_taxonomy`、`B2_threat_fanout`、`B2_merge_critic`、`G3_gate` |
| **M4** | `CMD4_testplan`、`B3_derive`、`B3_validate_artifacts`、`G4_gate`、`B4_preflight`、`B4_s0s1_exec`、`B4_s2_queue`、`G5_gate`、`B4_s2_snapshot`、`B4_s2_exec`、`B4_s2_restore`、`abort_handler`（`ah_cancel`、`ah_restore`、`ah_escalate`、`ah_revoke`、`ah_report`）、`B5_verify`、`B5_readjudicate`、`CMD5_followup`、`B6_report`、`stopped_wait` |
| **M5** | `B5_verify` 的機率判定分支；Relay 的多回合測試（在 `B4_s0s1_exec` 內） |

## 3. 入口閘門（法務與查證）

- 每個里程碑開始之前，下表中該里程碑的項目都要結案，結果有兩種：
  - **已確認**：寫進 [06 §2.3](06-security-legal-limitations.md#23-授權登錄表) 與 `licenses.yaml`；
  - **未確認**：該元件在這個里程碑停用，並以設定檔證明它已停用（`tools.yaml`、`models.yaml` 或 engagement 的允許清單）。
- 項目與負責人取自 [06 §4](06-security-legal-limitations.md#4-開放的法務與查證項目)；研究缺口取自 [01 §5](01-research-survey.md#5-研究缺口未搜尋或未能確認)。

| 閘門 | 項目 | 負責 | 未確認則 |
|---|---|---|---|
| **M1 前** | Anthropic API 條款 [V][E:providers-43][E:providers-44] | legal_reviewer | M1 不受影響；M2 的 `claude_*` 別名不啟用 |
| | TruffleHog（AGPL，`trufflehog:scan`）[V][E:whitebox-51]～[E:blackbox-61] | legal_reviewer | `trufflehog:scan` 不註冊；W0 只用 `betterleaks:scan`／`gitleaks:scan` |
| | psycopg（LGPL-3.0）的散布形式 [V][E:orchestration-42] | legal_reviewer | 只做內部部署，不對外散布 `vibecheck-z1` 映像 |
| | Semgrep 官方規則（`semgrep:scan`）、CodeQL CLI（`codeql:analyze`）用於私有碼（閘門未結案時，這兩個 adapter 的 SARIF 也不算佐證：validator 回報 `E-SARIF-REF`）。CodeQL 條款允許在 GitHub.com 上託管與維護的開源碼庫做 CI／CD 的資料庫產生，限制只及於其他情境 [P][E:whitebox-04][E:whitebox-07][E:whitebox-53] | legal_reviewer | 兩者不註冊（`tools.yaml` 已登錄、受 `licenses.yaml` 法務閘門控制）；W1 只用 Opengrep＋自有規則。CodeQL 只可用於符合上述條件的開源 repo |
| | nftables 授權（未查） | toolkit_maintainer | 補查完成前，Z2／Z3 的出站規則由容器執行環境的網路政策負責 |
| | E2B 的授權依據 [V][E:blackbox-57] | toolkit_maintainer | 寫進 `licenses.yaml`（不阻擋） |
| | G-11：固定 runsc／Firecracker 的版本、訂閱 CVE；逃逸測試列入 ST-7 | toolkit_maintainer | 不啟用 Z2 |
| **M2 前** | NIM 是否屬於開發／測試用途 [V][E:providers-40] | legal_reviewer | 不使用 NIM；`nemotron_self` 改用其他推論伺服器 |
| | OpenAI API 條款，由人工直接讀原文（G-13）[V][E:providers-45] | legal_reviewer | `gpt_flagship` 不啟用 |
| | GPT-6 的 ZDR 書面確認（G-06）[V][E:providers-48][V][E:providers-35] | app_owner | `gpt_flagship` 不收 C 級資料 |
| | Nemotron 雲端路徑的 DPA（G-04）[V][E:providers-42] | toolkit_maintainer＋legal_reviewer | C 級資料只送自架的 Nemotron；`nemotron_cloud` 只收 P 級 |
| | Nemotron 託管端點的 json_schema 支援（G-05） | toolkit_maintainer | 改用用戶端 Pydantic 驗證＋修復（M2 的整合測試實測） |
| | PrimeVul 樣本的重製：repo 標示 MIT，但資料集沒有另外的授權聲明；README 描述為取自 real-world C/C++ 專案的函式（未明寫開源）[P][E:vibe_risks-35] | legal_reviewer | 只作內部評估，不進對外報告 |
| | OpenRouter 條款 | toolkit_maintainer | 不使用 OpenRouter |
| **M3 前** | MAESTRO、LINDDUN 的授權（未查） | toolkit_maintainer | 只在分類欄位引用 ID，不重製內容 |
| | OWASP LLM Top 10 預設版本：**已結案**。官方 PDF 的十項 ID 已查證 [V][E:threat_modeling-73]，新委任預設已切到 `owasp-llm@2026`（[04 §2.3](04-threat-to-testcase.md#23-owasp-llm-top-10-20252026-對照)）；資源頁標題為「OWASP GenAI LLM Top 10 2026」、PDF 封面為「OWASP Top 10 for LLM Applications 2026」[P][E:threat_modeling-72] | toolkit_maintainer | 不適用（已結案）；既有委任仍可沿用 2025 版並以對照表轉換 |
| **M4 前** | k6（AGPL）[V][E:blackbox-25][E:blackbox-59] | legal_reviewer | 限流驗證改用其他工具；`k6:threshold` 不註冊 |
| **M5 前** | promptfoo 部分策略繞過本地生成 [S-09] | toolkit_maintainer | 以出站紀錄實測之前，`promptfoo:*` 不能在真實 run 啟用。範例 `tools.yaml` 已登錄 `promptfoo:eval`／`redteam_local`、範例 ROE 也允許，是為了示範範例 B；實測結果是 M5 驗收的前提，實測前真實的 ROE 不得把 `promptfoo` 列入 `allowed_tools` |
| | OWASP 內容（CC BY-SA 4.0；網站頁尾如此聲明，repo 的 LICENSE.md 只是 CC BY-SA 4.0 的摘要頁，不是完整授權條文）在報告中的引用 [P][E:threat_modeling-67][E:threat_modeling-68][E:threat_modeling-78] | legal_reviewer | 報告只列 ID 與連結 |

## 4. 各里程碑

### M1 基礎與安全控制

**範圍**：
- §2 中 M1 的元件與節點。
- CI Lane A（W0、W1、secrets、套件存在性）。
- 開發順序：[08 §9.2](08-implementation-spec.md#92-m1-前兩週的工單) 的 T-01–T-18。

**出口準則**：

| # | 準則 | 如何量測 | 不通過的判斷 |
|---|---|---|---|
| M1-X1 | [範例 A](04-threat-to-testcase.md#61-範例-awebapi-的-idorbola) 的前半段端到端：在 `invoices-app` 上跑 `run_init → G0a → W0 → W1 → G0b → B0 → m1_finish`（只是 M1 的元件測試 fixture，不是交付給使用者的 run；MVP 與 Lane B 的 run 仍要經過 W0.5、認領與 G1） | 整合測試 | inventory 的 `endpoints[]` 沒有 `GET /api/invoices/{id}`（`file` 為 `routes/invoices.ts`、`kind` 為 `http`；`line` 是 handler 的位置，範例 inventory 為第 40 行，第 42 行是 K-005 的 sink），或 `db.tables[]` 中 `name` 為 `invoices` 的項目 `rls_enabled` 不是 `false`；任一個固定工具沒有產出 SARIF（且沒有列為缺口）；`tgt-staging-api`（DNS TXT）或 `tgt-staging-app`（well-known path）的所有權驗證沒有通過 |
| M1-X2 | 必須拒絕清單 N-01–N-43 全部通過（N-32–N-43 為 v0.3 新增，見 [08 §8.2](08-implementation-spec.md#82-m1-必須拒絕清單負面安全測試)） | `security` 線 | 任一項沒有拒絕，或沒有對應的稽核事件 |
| M1-X3 | ST-1＝0、ST-3＝0、ST-7＝0（[06 §1.2.1](06-security-legal-limitations.md#121-工具包自測計畫植入注入的-repo-h)）；M1 的每個注入向量 ≥3 個樣本；每個 twin ≥10 個已知漏洞 | [selftest-report](schemas/selftest-report.schema.json)：三項都是 `status: RUN`、`passed: true` | 任一個大於 0，或任一項為 `NOT_RUN` |
| M1-X4 | 在每個 M1 節點的邊界 kill 行程後 resume | 整合測試 | 最終產物的 hash 與不中斷的 run 不同；Sandbox job 被重跑；稽核去重後有重複事件 |
| M1-X5 | 稽核與 CAS 的竄改偵測 | 性質測試 ≥1,000 例 | 偵測率 < 100% |
| M1-X6 | `docs/schemas/examples/` 全部通過契約往返（`exclude_unset=True`，[08 §3](08-implementation-spec.md#3-資料模型從-json-schema-產生-pydantic)） | `fast` 線 | 任一個範例不是逐位元組相同 |
| M1-X7 | 供應鏈：鎖檔含 hash；LiteLLM 鎖版本，並排除 1.82.7、1.82.8 [V][E:orchestration-31]；每個依賴在 `licenses.yaml` 都有一列；Actions 鎖 SHA；有 SBOM | `licenses check`＋N-29 | 任一項缺少 |
| M1-X8 | Z2 維運（[06 §1.4](06-security-legal-limitations.md#14-沙箱與網路)）：runsc 的版本寫進 SBOM、CVE 訂閱、不同 engagement 不共用主機、不掛 Docker socket | 檢查清單＋ST-7 | 任一項缺少 |
| M1-X9 | §3「M1 前」的每一項都已結案 | 驗收包中的法務紀錄或設定檔證明 | 有未結案的項目，而該元件仍然啟用 |
| M1-X10 | Lane A 在 `invoices-app` 上的耗時 | 連續 10 次的中位數與最大值，寫回 [03 §11](03-system-architecture.md#11-成本與延遲模型) | 沒有量測紀錄（只量測、不設門檻） |

### M2 白箱多家族審查

**範圍**：
- §2 中 M2 的元件與節點；
- W4 的 adapter：`hypothesis:property`、`fast_check:property`（[tools.yaml](examples/tools.yaml)）；
- Calibration Lab 第一版（05 §5 的語料、對照組、預先登記）；
- CI Lane B 的白箱部分。

**出口準則**：

| # | 準則 | 如何量測 | 不通過的判斷 |
|---|---|---|---|
| M2-X1 | （依 09 BL-11：校準語料需要 U-10 決定標註人力與預算；在那之前 M2 只能部分驗收，M2-X1 以外的準則照常驗收）在**保留切分**上，[05 §5.3](05-bias-calibration.md#53-指標) 的 M-1–M-11 全部達到該表的門檻：每個模型×桶 ≥20 票，否則標 `near_zero`；`CONFIRMED_*` 的 precision ≥0.90 且 Wilson 下界 ≥0.80；CONFIRMED∪LIKELY 的 recall ≥0.60；M-4 的家族排除 100%；M-5 的翻轉率 ≤0.10；M-6 ≥30 個 DISPUTED；M-7 缺票率 ≤0.05。<br>預先登記在解盲前完成；主要假設（③ 優於 ②）**不論結果如何都要報告**，但它不是出口條件 | `calibrate report` | 任一個有門檻的指標沒有達標；解盲前沒有預先登記；`holdout_access_log` 有預先登記前的存取 |
| M2-X2 | [範例 A](04-threat-to-testcase.md#61-範例-awebapi-的-idorbola) 的白箱部分：`invoices-app` 的 IDOR（K-005）裁決為 ≥`LIKELY`；W5 產出對應的種子威脅 | 整合測試（真實供應商跑在 manual 線；CI 用錄製的回應） | K-005 沒有達到 `LIKELY`，或沒有種子威脅 |
| M2-X3 | ST-2＝0；ST-4：`CONFIRMED_*` 為 0、`LIKELY` ≤5%；ST-5 ≤10 個百分點（≥3 次 run） | `selftest-report.json` | 任一項沒有達標 |
| M2-X4 | Lane A 的結果永遠不會是 `CONFIRMED_*`（R9） | 性質測試＋ST | 出現任何一例 |
| M2-X5 | 關卡行為：[03 §6.2](03-system-architecture.md#62-關卡逾時預設值) 的逾時；G2 未決定的項目視為 `NEEDS_INFO`；職責分離；偽造或重送的 GateRecord 被拒絕 | `security` 線 | 任一項不符 |
| M2-X6 | 預算：80% 發出事件；用盡時進 GB；沒有費用上限時 fail-closed（[03 §11](03-system-architecture.md#11-成本與延遲模型)） | 整合測試 | 超出上限仍繼續呼叫 |
| M2-X7 | ASI09 抽查（[06 §1.1](06-security-legal-limitations.md#11-以-owasp-agentic-top-10-檢視工具包)）：每個 run 抽所有 `CONFIRMED_*` 裁決的 10%（最少 3 項）與 G2 決定的 10%（最少 2 項）；複核者不是原核准者或發起者；5 個工作天內完成 | 抽查紀錄 | 抽樣率不足、複核者是原核准者，或逾期 |
| M2-X8 | §3「M2 前」全部結案；研究缺口 G-02、G-03、G-04、G-05、G-06、G-09、G-13 都完成 01 §5 列出的動作（例如 G-02：找到 Lacrosse 的資料，或在 Calibration 報告中註明找不到） | 驗收包 | 有缺口沒有完成動作 |
| M2-X9 | 模型退役：`models.yaml` 的每個別名都有 `earliest_retirement`；`claude_haiku`（Claude Haiku 4.5，最早 2026-10-15 [V][E:providers-49]）已換成 `claude_opus_48`（U-11 已決定 [V][單源][E:providers-52]），且替代模型已完成 05 §5.8 的最小重跑 | `config validate`＋Gateway 的警告測試 | 缺少欄位，或退役後仍被呼叫 |
| M2-X10 | [05 §5.8](05-bias-calibration.md#58-模型版本變更時的最小重跑集) 的最小重跑：`model_key` 改變後，完成重跑之前該模型的權重 w＝0 | 整合測試 | 重跑前 w≠0 |
| M2-X11 | 每個 LLM 輸出都通過 schema 驗證，或有記錄在案的修復或缺票 | 稽核查核 | 有未驗證的輸出進入 Blackboard |
| M2-X13 | **預設值照 §5.6 的結果切換**：主要假設的結果（不論哪一方勝出）寫入 `calibration.yaml` 的 `recommended_defaults`，組態載入時套用；使用者覆寫時報告標示「未採用校準建議」（05 §5.6） | `config validate`＋報告 | 預設值與 §5.6 的結果不符，且沒有標示覆寫 |
| M2-X12 | 指揮官的加值：每份計畫都包含確定性的覆蓋下限（必要面向，`E-PLAN-FACETS`）；報告列出指揮官在下限之外加派的切片、面向與 CMD-2 輪次，以及其中產生有效叢集（`LIKELY` 以上）的比例 | 計畫檔＋報告 | 有計畫少於覆蓋下限；沒有報告加派結果（只量測、不設門檻） |

### M3 威脅建模

**範圍**：§2 中 M3 的元件與節點；分類版本欄位與 2025↔2026 對照；pytm 部分匯出。

**出口準則**：

| # | 準則 | 如何量測 | 不通過的判斷 |
|---|---|---|---|
| M3-X1 | 範例 A 與[範例 B](04-threat-to-testcase.md#62-範例-bllm-功能的-prompt-injection-與工具濫用confused-deputy) 的威脅模型都通過 G3。每個種子威脅都要在模型中，或在 G3 以理由駁回；每個 `b1_diff` 項目都已處置 | 整合測試 | 有種子威脅沒有處置；有 `b1_diff` 項目沒有處置，G3 卻已開啟 |
| M3-X2 | G-08：在範例應用上以人工標註的威脅清單比較 B2 與 pytm 規則輸出的 recall（只供 B2 設計參考，不設門檻） | 報告附原始資料 | 沒有報告 |
| M3-X3 | INJ-DOC 對 B1／B2 的影響：植入 twin 的威脅模型漏列種子威脅 → 失敗 | `selftest-report.json` | 有任何一例 |
| M3-X4 | OWASP LLM Top 10 的預設版本為 `owasp-llm@2026`（§3 已結案）；toolkit.yaml 與 crosswalk.yaml 的 `owasp_llm_default` 一致，2025 版委任可經對照表轉換 | 設定檔＋validator | 設定檔不一致，或 2025 版委任無法轉換 |
| M3-X5 | B1 只使用 S0 請求；ST-1＝0 | `selftest-report.json`＋Scope Proxy 統計 | B1 有任何一個非 S0 的請求 |
| M3-X6 | §3「M3 前」全部結案 | 驗收包 | 有未結案的項目 |

### M4 黑箱執行

**範圍**：§2 中 M4 的元件與節點；04 §4.3 的 tool_binding adapter（Schemathesis、ZAP AF、Playwright、Nuclei 自簽章模板）；停止條件自動化；CI Lane B 完整版。

**出口準則**：

| # | 準則 | 如何量測 | 不通過的判斷 |
|---|---|---|---|
| M4-X1 | 範例 A 端到端：`invoices-app` 植入版的 TC-012-01 → FAIL → 依 R1 裁決 `CONFIRMED_EXECUTABLE` → 產生回歸測試；修正版 → PASS | 整合測試 | 任一步不符 |
| M4-X2 | S2 在 resume 或重試時不重跑；`EXECUTING` 但沒有結果的 job 被標為 `INTERRUPTED`，需要新的 G5；還原演練 ≤7 天；還原失敗 → `FAILED` 並通知聯絡人 | 整合測試 | 任一項不符 |
| M4-X3 | [03 §7.3](03-system-architecture.md#73-限速與停止條件) 停止條件表的每一列，都有故障注入的整合測試，而且觸發 `abort_handler` | 整合測試 | 有任何一列沒有測試，或觸發後沒有停止 |
| M4-X4 | ST-6＝0；INJ-HTTP 不改變裁決或計畫 | `selftest-report.json` | 大於 0 |
| M4-X5 | S3 永遠不進 G4；安全等級依 04 §5 的虛擬碼計算（每個分支都有測試） | `security` 線 | 有任何一例 |
| M4-X6 | G-07 pilot：在 ≥3 個含已知漏洞的 vibe-coded 範例應用（`invoices-app`、`support-agent-app`、`notes-rls-app`）上，量測 ZAP、Nuclei、Schemathesis 對種子漏洞的檢出率與誤報，報告附原始結果 | 報告 | 缺少任何一個工具或應用 |
| M4-X7 | B6 的 JSON 報告通過 schema 驗證、SARIF 通過 SARIF 2.1.0 schema 驗證，並符合 §3.27.9–3.27.10 的 `kind`／`level` 規則 [V][E:whitebox-59]；追溯矩陣中每一列都能從發現項追到測試案例與結果 | `fast`＋`integration` 線 | 驗證失敗，或有斷鏈 |
| M4-X8 | ASI09 抽查：G3／G4 各抽 10%（最少 2 項）；G5 全部抽查，2 個工作天內完成 | 抽查紀錄 | 不符 |
| M4-X9 | §3「M4 前」全部結案 | 驗收包 | 有未結案的項目 |

### M5 LLM 功能測試與報告

**範圍**：§2 中 M5 的元件與節點；PyRIT、promptfoo 的 adapter（關閉遠端生成、封鎖出站）；canary 與工具呼叫紀錄 oracle；受測應用上游 LLM 的花費上限；靜態 HTML 報告。

**出口準則**：

| # | 準則 | 如何量測 | 不通過的判斷 |
|---|---|---|---|
| M5-X1 | 範例 B 端到端：`support-agent-app` 植入版的 TC-031-01 在 n＝60 下判定 FAIL；修正版在 n＝60、k＝0 時依 04 §4.4 的上界公式報告殘餘率上界，報告中不得寫成「沒有漏洞」（`outcome` 仍是 `PASS`，但殘餘率上界必須並列）。受測應用的上游模型固定為驗收包指定的模型與版本，並記入測試結果；植入版是否 FAIL 取決於上游模型會不會被注入，與工具包無關，所以另以腳本式假模型（W4 的工具防護測試）確認工具包的判定路徑 | 整合測試 | 判定或上界不符；沒有記錄上游模型與版本 |
| M5-X2 | Relay 的回合數與花費上限生效（`relay.max_turns`、`max_spend_usd_per_job`、`max_spend_usd_per_run`）；INJ-LLMAPP 不改變裁決 | `security` 線＋ST | 超過上限仍繼續；INJ-LLMAPP 改變了裁決 |
| M5-X3 | promptfoo 沒有任何雲端出站 | 出站紀錄 | 有任何一筆 |
| M5-X4 | HTML 報告是靜態檔案，不需要伺服器或外部資源；內容與 JSON 報告一致 | 測試 | 有外部請求，或與 JSON 不一致 |
| M5-X5 | ST-1–ST-7 與全部 INJ 向量都通過 | `selftest-report.json` | 任一項失敗 |
| M5-X6 | §3「M5 前」全部結案 | 驗收包 | 有未結案的項目 |

## 5. 自測排程

依 [06 §1.2.1](06-security-legal-limitations.md#121-工具包自測計畫植入注入的-repo-h)：

| 里程碑 | 新增的自測 |
|---|---|
| M1 | ST-1、ST-3、ST-7 |
| M2 | ST-2、ST-4、ST-5 |
| M3 | INJ-DOC 對 B1／B2 的影響 |
| M4 | ST-6、INJ-HTTP |
| M5 | INJ-LLMAPP |

- 自測是**累加**的：每個里程碑都要重跑之前的全部項目。
- 更換任何模型、prompt 或 Commander 規則時，全部重跑。
- 任一個 0 門檻失敗 → 阻擋發布（[08 §8.4](08-implementation-spec.md#84-ci-線)）。

## 6. CI 線

### 6.1 產品的兩條線

這兩條線與 [03 §12](03-system-architecture.md#12-ci-整合兩條線) 一致：

| 線 | 從哪個里程碑開始 | 內容 |
|---|---|---|
| Lane A（同步、每個 PR） | M1 | W0、W1、secrets、套件存在性；M2 起可選用單一家族只審 diff（`LA_diff_review`），結果最高只到 `UNCORROBORATED`（05 R9） |
| Lane B（非同步） | M2 起白箱部分；M4 起完整 | 完整多家族白箱、所有人工關卡、黑箱；checkpoint 續跑；結果回貼 PR |

### 6.2 工具包自己的 CI

工具包自己的 CI 線（`fast`、`security`、`integration`、`selftest`、`manual`）見 [08 §8.4](08-implementation-spec.md#84-ci-線)。

## 7. 每個里程碑都要做的事

- **模型**：重新查證模型 ID、版本與退役日期。
  - 旗艦模型「GPT-6 Astra／Sol」[P][E:providers-31] 以別名 `gpt_flagship` 引用；程式與設定檔只使用別名，不寫死模型 ID（模型 ID 只寫在 `models.yaml`：U-12 已決定綁 `gpt-6-sol` [V][E:providers-46]）。
  - `models.yaml` 的每個別名都有 `earliest_retirement`；Gateway 在退役前 30 天發出警告 [H]。
  - `claude_haiku`（Claude Haiku 4.5）的最早退役日 2026-10-15 已過 [V][E:providers-49]。使用者已決定改用 Claude Opus 4.8（`claude_opus_48`，最早 2027-05-28 退役 [V][單源][E:providers-52]；[08 §10](08-implementation-spec.md#10-尚未決定需使用者決定) U-11），範例已更新；M2 仍要完成替代模型的最小重跑。
  - 模型改變時，依 05 §5.8 重跑，並重跑全部自測。
- **授權**：更新授權登錄表（[06 §2.3](06-security-legal-limitations.md#23-授權登錄表)）與 `licenses.yaml`，並結案下一個里程碑的入口閘門（§3）。
- **威脅模型**：更新工具包自己的威脅模型（[06 §1.1](06-security-legal-limitations.md#11-以-owasp-agentic-top-10-檢視工具包)）。
- **Z2**：每個里程碑都重跑 ST-7；每週檢查 CVE，High 以上 7 天內升級（[06 §1.4](06-security-legal-limitations.md#14-沙箱與網路)）。
- **範例與 schema**：修改 `docs/examples/` 或 schema 之後，重跑 `python tools/sign_examples.py`（只供測試的金鑰）與 `python tools/validate_schemas.py`（[08 §3](08-implementation-spec.md#3-資料模型從-json-schema-產生-pydantic)）。
- **人工關卡**：在 pilot 中量測人工關卡的實際耗時，並回寫到 [03 §11](03-system-architecture.md#11-成本與延遲模型)。

## 8. 暫不規劃

- 行動 App（iOS／Android）的黑箱測試。
- 正式環境測試、效能與容量測試。
- 自動修補（autofix）後直接合併；修補建議一律走人工審查。
- **儀表板與任何常駐的 Web UI**（D14）：關卡以 CLI 操作，報告是靜態檔案。
