# 各文件的變更摘要（第十輪整併前）

> 第十輪審查把 02～08 開頭逐版累積的變更摘要移到這裡，原文照錄、只把標題降一級並改寫相對連結；各文件開頭改成一段「現況」。逐版的完整變更見 [CHANGELOG](../../CHANGELOG.md)。文中的「本版」「v0.x」指當時的版本，不是現況。

## 02 方法論：先白箱、後黑箱（威脅建模強制在前）

### v0.4 變更摘要

依 [2026-10-24 設計審查](review-2026-10-24.md) 的第一優先項目修正裁決規則與 validator（規則細節見 [05 v0.4 變更摘要](#05-降低模型偏誤證據規則裁決校準)；`rule_version` 為 `05-v0.4`）：
- **R0** 在叢集另有 SARIF 或 FAIL 類測試證據時不成立；**R10**：G2 駁回後出現 `E_proof` → `CONFIRMED_EXECUTABLE`（加註 `post_g2_conflict`）；**R11** 只有在 PASS 有正對照（`oracle_can_fail`）時才降級。
- 只有 `NOT_CHECKED` 證據的發現項不計入獨立家族；程式片段至少 12 個非空白字元並含識別字，且必須在發現項的切片中。
- SARIF 只佐證自己位置（檔案、符號、桶）的叢集；黑箱叢集不收 SARIF。
- CMD-1 計畫必須涵蓋 run 的**每個**切片，且每個切片的 reviewer 至少 min(2, 合格家族數) 個家族（`E-PLAN-COVERAGE`、`E-PLAN-FAMILIES`）。
- 自架（Z4）模型改由 `toolkit.yaml` 的 `z4_model_hosts` 確切主機名稱判定，不再看 `z4-` 前綴。
- `graphql_operation: query／introspection` 只在 ROE 為該目標宣告的 GraphQL 路徑（`targets[].graphql_paths`）、方法為 GET／POST 時才算讀取；其他帶這個標籤的請求一律 S3。
- **第二優先**（v0.4 第二輪）：G0a 增加跨境聲明（`data_transfer`，`E-ENG-TRANSFER`）與設定檔釘選（`config_pins`，`E-ENG-CONFIG-PIN`）；W0 增加個資掃描（遮罩表 `kind: pii`）；ROE 增加事故應變（`incident_response`，`E-ROE-INCIDENT`）；關卡時間以 Audit Writer 收件時間為準。架構面的修正見 [03 v0.4](#03-系統架構)。

### v0.3 變更摘要

- **保證等級**：新增 [§1.7](../02-methodology.md#17-保證等級liteteamfull)，定義 `lite`／`team`／`full` 三種等級：
  - `lite`：一人可以兼任多個角色，但必須有 `role_consolidation` 聲明；只允許 S0／S1，所以沒有 G5。兼任的 `test_lead` 可以自己做法務審查聲明（警告 `W-L5-LITE`，報告首頁標示為自行簽署）。
  - `team`：ROE 的每個簽署角色都由不同的人擔任。
  - `full`：G5 需要兩位資安審查者；只有 `full` 可以用 adaptive relay。
  - 三種等級的安全底線相同 [H]。
  - （M-G3、L-13、N-11）
- **簡化**：
  - G2 維持不阻擋。
  - `lite`，或測試計畫只有 S0／S1 job 時，G3 與 G4 可以在同一次審查中處理，但仍是兩份簽章紀錄。
  - B3 優先用樣板 adapter。
  - Commander 保留，但它的計畫必須是覆蓋下限計畫的超集合，並且要量測它的額外價值。
  - （M-G4）
- **W0 是 G0a 之後的第一步**：
  - secrets 掃描與遮罩在任何 LLM 呼叫之前完成。
  - 程式碼只能經 Slicer（已套用遮罩）送往 LLM。
  - W0.5 的 Invariant Drafter 只收 W0 inventory（名稱與事實，不含程式碼）與 G1 問卷答案，工具只有 `read_inventory`。
  - （H-C1）
- **W0 inventory 欄位**：新增 `frameworks[]`（支援程度）、endpoint 的 `kind`、`db.tables[]` 的 RLS 狀態與 policy、`auth`、`env_vars[]`（只有名稱）、`blind_spots[]`、`features[]`；完成條件改用這些欄位。（H-E1、A-1）
- **W0.5／G1**：
  - 不變量新增資料分級、LLM 工具、`limits`、`policies` 與結構化的 `ownership`。
  - 基準是 ASVS 5.0 L1，依功能觸發 L2／L3（`level_triggers`）。
  - G1 改用白話問卷。
  - （H-E4、A-2）
- **工具輸出只給程式碼**：W1 的 SARIF 只交給確定性的 Clusterer／Aggregator；W2 與 W3 的 LLM 輸入不再含 SARIF。（H-A1）
- **W1** 新增兩項檢查：前端 bundle 的公開前綴環境變數、以 migration 分析 RLS。CodeQL 的授權說法改成與 07 一致。（M-G5、A-10）
- **W2 審查面向**：
  - 由 6 個增為 12 個，分成 3 組，每組一次呼叫。
  - 新增面向與 CWE 桶的對照表。
  - 必要面向由 W0 `features[]` 決定（`E-PLAN-FACETS`）。
  - （H-F1、L-22）
- **W2 證據種類**：分成 `code_snippet`／`inventory_fact`／`config_fact`。片段比對的對象是遮罩後的文字，容許空白差異與 ±3 行位移。（H-A5、L-16）
- **Commander**：
  - 沒有任何工具，只收程式碼建立的型別化視圖。
  - `extra_dispatch.target` 有型別。
  - CMD-2 至多 2 輪。
  - 輸出不合規 → 修復 ≤2 次 → 改用程式碼的預設（覆蓋下限計畫）。
  - （H-C2、N-6）
- **W4**：
  - 輸入加入 `DISPUTED`，以及成員最高嚴重度為 critical／high 的 `UNCORROBORATED` 叢集。
  - 解讀已事先登記的確定性 FAIL 直接是 `E_proof`；Result Analyst 池只在解讀無法事先登記時使用。
  - 新增兩種測試：以腳本式假模型輸出測試工具防護；在 Z2 以拋棄式本地 Postgres 測試 RLS。
  - （A-4、H-A3、M-G5）
- **W5**：
  - 叢集有跨 run 的指紋與 `baseline_state`（new／unchanged／updated／absent）。
  - 核准綁定逐項 hash，下一個 run 只重審變更的項目；G5 永遠不沿用。
  - 報告加入覆蓋指標。
  - （H-B5、M-G5）
- **關卡核准者的來源**：G0a／G1／G2 取自委任設定的 `gate_approvers`；G0b／G3／G4／G5 取自 ROE；G3／G4／G5 必須在 ROE 有效期間內決定，G0b 除外（它本身就是發現 ROE 未生效並讓 run 暫停的檢查；[§1.3](../02-methodology.md#13-人工關卡一覽)）。（H-D2）
- **G0b 結果的寫法統一**：ROE 尚未生效或不在時間窗內 → `VERIFIED`，run → `SUSPENDED`；`EXPIRED` 只用於 ROE 已過期。（A-9）
- **B0**：
  - 共享平台網域改用 `platform_project` 證明，並在 ROE 記錄 `platform_policies[]`。
  - B0 與 `B4_preflight` 檢查 staging 的版本識別。
  - 每批開始前，對每個測試角色做 whoami。
  - （H-D3、H-B4、H-E8）
- **B1**：
  - 爬行只用 GET／HEAD／OPTIONS，過濾登出與刪除連結，有請求上限與 allowlist。
  - 沒有 OpenAPI 的應用，由 W0 inventory 起草 spec，在 G4 審查。
  - （H-E7、L-17、H-E10）
- **B2**：merger 改為確定性（合併鍵＝DFD 元素＋STRIDE 類別＋CWE 桶），另由 LLM critic 找遺漏；呼叫數的寫法與流程一致。（M-G5、L-03）
- **B3／B4**：
  - 測試案例必須有 `controls[]`；任一對照未通過 → `INVALID`。
  - 所有寫入都要綁種子或 create-only 端點（`{seed:}`、`{created:}`）。
  - （H-B1、H-B3）
- **B5**：黑箱起源的叢集（`origin: black_box`）也走同一套裁決；Result Analyst 改為每個家族一位的池。（H-A3）
- **B6**：新增 SARIF 匯出規格、對照通過率、`build_unverified_targets`、暫定（`provisional`）標記。（M-G6、H-E11）
- **流程圖**：補上 G3／G4／B0 → B6，以及 abort_handler → `STOPPED`／`ABORTED` 的邊。（L-10）
- [§4](../02-methodology.md#4-階段之間的交接與回饋) 交接表與 [§5](../02-methodology.md#5-階段與關卡規格總表) 規格總表已同步更新。

### v0.2 變更摘要

- **Secrets 先於任何 LLM**：W0 改為完全確定性（盤點＋secrets 掃描＋路徑黑名單＋`secrets-redaction-map`）；W1 不再負責 secrets；W0.5 以後所有 LLM 只收遮罩後內容；沒有 `redaction_map_ref` 的 run，Model Gateway 一律拒絕 [H]。
- **關卡結果與終止狀態**：每個人工關卡回傳 `APPROVED`／`PARTIALLY_APPROVED`（只 G3、G4）／`REJECTED`／`NEEDS_INFO`／`EXPIRED`，各有處理路徑；run 狀態 enum 固定為 8 種（[§1.4](../02-methodology.md#14-關卡結果與-run-狀態)）。
- **新節點**：`B0_ownership_verify`（Z3）、`B4_preflight`（每批重驗）、`W4_exec`／`W4_readjudicate`、`GB_budget_gate`（預算關卡）、`abort_handler`（補償）、`claim_run`（自動觸發的人工認領）。
- **執行種類**：`run_kind` = `initial`／`followup`／`regression`／`lane_a`，附 `parent_run_id` 與 `reuse`（[§1.6](../02-methodology.md#16-執行種類與後續執行)）。
- **種子威脅與 G3**：規則改為「每個非 REJECTED 叢集都有 ≥1 個 B3 測試案例，**或**有 G3 駁回紀錄（附理由）」。
- **G2 路由**：只有 DISPUTED 與高嚴重度的 UNCORROBORATED 進 G2；佇列為空就略過 G2。
- **B1 差異清單**成為 B2 的正式輸入，B2 critic 必須逐項處置。
- 定義「**高風險威脅**」（[B2](../02-methodology.md#b2-威脅建模g3-強制簽核)）。
- Lane A 的單一家族 diff 審查只有**參考性**，結果最高 `UNCORROBORATED`（05 R9），且在下一個 Lane B run 中不計入 `independent_families`。
- **G2 之後才出現的爭議**：由 `W4_readjudicate` 產生的 `DISPUTED` 不重開 G2，而是在 G3 的種子威脅清單標為「W4 後轉為爭議」；由 `B5_readjudicate` 產生者列入 B6 的人工複核清單 [H]。裁決規則對齊 05 的 R0–R13。
- 儀表板移出範圍；報告為靜態 HTML＋SARIF＋JSON。
- 新增 [§5 階段與關卡規格總表](../02-methodology.md#5-階段與關卡規格總表)：每個階段與關卡的輸入、輸出、執行區、是否用 LLM、失敗處理、完成條件、schema、里程碑。
- 模型命名統一為 GPT-6 Astra／Sol（[P][E:providers-31]）。
- **W0 預設 secrets 掃描器**改為 Betterleaks／gitleaks（MIT）；TruffleHog（AGPL-3.0）改為選用，須通過授權登錄的法務閘門。
- **G0b 加入法務審查聲明檢查**（`legal_review`，規則 L-1～L-6，見 [06 §2.1.1](../06-security-legal-limitations.md#211-roe-的法務審查聲明legal_reviewg0b-檢查h)）。
- **G0b 之前不讀 ROE**：W0 只用 G0a 已驗章的委任設定與工具包設定；W0 能不能用 TruffleHog，只看工具包層級的法務閘門是否已結案，不看 ROE 的 `legal_review`。依 `component_licenses` 過濾元件（L-6）在 G0b 進行，結果記入 G0b GateRecord，供 B 階段使用 [H]。
- **ROE 或 `legal_review` 在執行中到期** → `SUSPENDED`（保留 checkpoint；resume 需要一份新的有效 ROE，由 `B4_preflight` 強制）。只有驗章失效（金鑰撤銷、簽章無效、文件被改）才 `ABORTED` [H]。

## 03 系統架構

### v0.4 變更摘要

依 [2026-10-24 設計審查](review-2026-10-24.md) 修正（第一優先見 [02 v0.4](#02-方法論先白箱後黑箱威脅建模強制在前)；以下是第二優先的架構項目）：
- **Z3 工具容器需求**（§2）：比照 Z2 的沙箱表；每個 job 一個 gVisor／microVM、只能連 Scope Proxy、沒有 DNS 解析器、只解密本 job 角色的 storageState、沒有 Relay 憑證。
- **Scope Proxy 的位址與協定**（§2、[08 §11.7](../08-implementation-spec.md#117-scope-proxy-實作)）：解析到的位址以參考實作 `safety.ip_problem` 判定（擋 NAT64、IPv4-mapped、6to4、Teredo、ULA、site-local、multicast 與一切非公開位址）；封鎖 `Upgrade: h2c`、HTTP/3（QUIC、`Alt-Svc`）與 CONNECT 後的非 TLS 流量；路徑的 `\` 視為 `/`。
- **執行期狀態不放在 checkpoint**（§5.8）：S2 與所有 B4 job 的冪等帳本放在 Z3 的 job 帳本（append-only），時間旅行重播或 checkpoint 回溯不會讓已執行的 job 再執行；每個 run 一把資料庫 advisory lock；kill switch 走圖外通道；有副作用的節點用同步 checkpoint。
- **LLM 快取鍵**（§5.8）加入 `engagement_id`、資料等級與取樣序號：不跨委任重用回應，重複取樣不會被壓成同一個答案。
- **設定檔釘選**（§6.1）：委任設定以 `config_pins` 釘選 `models.yaml`、`agents.yaml`、`tools.yaml`、`licenses.yaml` 的內容 hash（`E-ENG-CONFIG-PIN`）。
- **關卡時間以 Audit Writer 的收件時間為準**（§6.1、§13.1）：GateRecord 的 `timestamp` 只需與 `gate_decision` 事件的 `ts` 相差不超過 5 分鐘（`E-AUDIT-GATE`）；金鑰效期、ROE 有效期、逾時與時間窗都以收件時間判定。
- **跨境聲明在 G0a**（§8.4）：委任設定的 `data_transfer`（`E-ENG-TRANSFER`）；HMAC 遮罩金鑰改為每個 run 一把、只在 W0 job 內存在的臨時金鑰。

### v0.3 變更摘要

依 [2026-09-26 深度審查紀錄](review-2026-09-26.md) 修正。新元件的細部規格放在 [08 §11](../08-implementation-spec.md#11-元件規格補充)，本文件只保留架構層級的說明與連結。

- **Commander 沒有工具，只看型別化視圖**（§4）：每個 CMD 節點的輸入由程式碼組成，只有 ID、狀態、CWE 桶、嚴重度、家族與計數，不含 LLM 輸出或 repo 的自由文字；`extra_dispatch[].target` 改為 `{kind, id}`；CMD-2 至多 2 輪並由 validator 檢查（`E-PLAN-ROUNDS`）；輸出不合規 → 修復 ≤2 次 → 程式碼的保底計畫；Commander 的計畫必須是覆蓋下限計畫的超集合（必要面向，`E-PLAN-FACETS`）。內嵌的計畫 JSON 改為標明「節錄」並連到範例檔（H-C2、N-6、L-04）。
- **W1 工具輸出不給 reviewer 與 verifier**（§5.3、§5.7、§9）：W1 結果只經 ToolResult 正規化器交給 Clusterer 與 Aggregator；SARIF 分為強佐證（`high_precision_rules`）與弱訊號（§5.9，規則見 05 §4.2）（H-A1）。
- **ToolResult 正規化器**（§1、§15）：W1 工具與 Clusterer 之間的新元件；`Clusterer.cluster(findings, tool_results)`（H-E2）。
- **Result Analyst 池**（§5.5、§9、§14.3）：`result_analyst_a`（`claude_sonnet`）、`result_analyst_b`（`gpt_flagship`）、`result_analyst`（`nemotron_self`）；有 PII 時只用自架模型；事先登記解讀的確定性 FAIL 不需要 LLM；B5 為黑箱起源的問題建立 `origin: black_box` 叢集（H-A3）。
- **遮罩是通往 LLM 的唯一路徑**（§1、§8.4、§9）：Inventory 不用 LLM；Invariant Drafter 的工具改為 `read_inventory`、`write_blackboard`（H-C1）。
- **run manifest**（§5.1）：RunState 與 run 紀錄加入 `config_refs`、`prompt_templates`、`tool_versions`、`rule_version`、`baseline_run_id`（N-5、H-E13）。
- **核准者來源、逐項核准與保證等級**（§6、新增 §6.3、§6.4）：G0a／G1／G2 看委任設定的 `gate_approvers`，G0b／G3／G4／G5 看 ROE；G3／G4／G5 須在 ROE 有效期內決定（v0.3 起 G3 也檢查，`E-GATE-ROE-VALIDITY`；G0b 是發現 ROE 尚未生效的系統驗證，不受此限）；核准綁逐項 approval hash（validator 重算 `item_sha256`），G1／G3 未變項目以 `carried_from` 逐項沿用（v0.5 由 validator 檢查，`E-GATE-CARRY`，§6.3）、G5 永不沿用，取代「產物有任何變動，核准就失效」；叢集以 `fingerprint` 與 `baseline_state` 跨 run 對應；Lite 兼任需明示聲明、Team 的 ROE 角色須不同人（`E-ROE-SOD`）、Full 的 G5 需兩位資安審查者（`E-G5-TWO-PERSON`）（H-D2、H-B5、M-G3、N-11）。
- **寫入範圍與排除清單**（§2、§7.1）：所有寫入都要綁種子或 create-only 端點（`E-TC-MUTATION-SCOPE`）；路徑先正規化再不分大小寫比對；主機排除支援 `*.` 萬用字元；目標 URL 只接受 `https://`（localhost 例外）（H-B3、C-1、C-2、C-3）。
- **build 識別**（§5.5、§7、§15）：`B4_preflight` 依 ROE `build_identity.method`（`header`／`endpoint`／`none`）確認受測版本；`none` 的目標列入 `build_unverified_targets`（H-B4）。
- **Scope Proxy、Session、種子、共享平台網域**（§2、§7.4、§7.6）：TLS 以 Z3 本地 CA 終結、HTTP/2／WebSocket／SSE、DNS 固定與 CDN（08 §11.7）；MFA、CAPTCHA staging 略過、第三方 IdP、每批 whoami、加密 storageState（08 §11.8）；種子命名空間、建立與 teardown（08 §11.6）；共享平台網域改用 `platform_project` 證明（08 §11.9）（H-E7、H-E8、H-E6、H-D3）。
- **結構化輸出先投影、再降級**（§8.3）：送給 LLM 的 schema 移除 harness 欄位；選填 → 可為 null、`const` → 單值 `enum`；`$ref` 在投影時展開，開放物件、`allOf`／`not`／`if`／`patternProperties`、無法解析的 `$ref` 一律拒絕；`uniqueItems`／`pattern`／`format` 移除後由存檔 schema 重新驗證；8 種 LLM 產物登錄在 `LLM_OUTPUTS`（H-A4、C-7）。
- **Opus 4.8 的說法更正**（§8.1）：它是 `claude_sonnet` 的同家族 fallback，fallback 時可能投票，但使用自己的校準權重（§5.8 重跑前為 0），只記錄不計權（N-2）。
- **C 級路由依供應商宣告**（§8.4）：委任設定的 `providers[]`（ZDR、DPA、保留、區域）決定哪些家族能收 C 級資料（H-E14）。
- **成本模型**（§11）：W2 呼叫數改為 S × V × G（G＝面向組數，12 個面向分 3 組）；B2 為 V_tm＋1（確定性 merger；另設 LLM merger 時 V_tm＋2，與 02 B2 一致）；加入輸出與推理 token、W0.5、W4、B3、B5、relay、加派與校準；價格取自 `models.yaml` 的 `pricing`（null＝未知；委任設定的 `max_cost_usd` 一律必填）；費用上限只能來自委任設定（H-E12、L-03、L-22、N-11）。
- **CI**（§12）：本 repo 自己的 CI 也以 SHA 鎖定 Actions（M-R1、A-11）。
- **序列圖**（§14）：回應一律經 Model Gateway 回到 Run Controller；Aggregator 不呼叫 Gateway；新增 §14.3 B5 結果解讀（L-10）。
- **一致性對齊**：`diversity_degraded` 改用合格驗證家族 E 的新定義（§5.9，N-1）；`E-SARIF-REF` 也要求該工具在 `licenses.yaml` 的狀態為 `OK` 或 `注意`（§5.9，N-7）；relay 預設為腳本式多輪、adaptive 只限 `full`（§7.5，H-E15）；§9 名冊與 §10 資料模型反映本輪的新欄位與 agent。

### v0.2 變更摘要

- **狀態機完整化**（§5）：拆成主圖＋W 子圖＋B 子圖＋B4 執行迴圈＋中止／補償／resume 圖；每個關卡都有各自允許結果的邊（`PARTIALLY_APPROVED` 只限 G3／G4；G2 整關只有 `APPROVED`／`EXPIRED`；G0a／G0b 為 `VERIFIED`／`VERIFY_FAILED`／`EXPIRED`）；加上終止狀態與可續跑狀態。
- **新節點**：`run_init`、`claim_run`、`LA_static`、`LA_diff_review`、`W4_exec`、`W4_readjudicate`、`B0_ownership_verify`、`B1_crawl`、`B4_preflight`、`GB_budget_gate`、`abort_handler`、`run_resume`、`suspended_wait`、`stopped_wait`。
- **完整 RunState**（§5.1）：W 與 B 欄位、關卡紀錄、預算、`run_kind`、`parent_run_id`、狀態 enum。
- **節點規格表**（§5.7）：每個節點的執行區、是否用 LLM、冪等鍵、副作用、失敗邊；節點邊界規則延伸到新節點。
- **Secrets 先於 LLM**：W0 完全確定性；Model Gateway 對沒有 `redaction_map_ref` 的 run 一律拒絕（§8.4）。
- **金鑰登錄與驗章流程**（§6.1）、**關卡逾時預設值**（§6.2）、**稽核事件格式與類型**（§13）。
- **停止條件預設門檻**（§7.3）、**DB 快照與 oracle 唯讀存取路徑**（§7.6）、**Session Provider 介面**（§7.4）、**Z3→Z1 relay**（§7.5）、**Z2 沙箱需求**（§2）。
- **Blackboard、content-addressed store** 與其他元件的介面（§15）；每個元件標出負責的里程碑（§1）。
- 預算觸頂改由 `GB_budget_gate` 決定（§11）；Lane A 的單一家族審查只有參考性（§12）。
- 儀表板移出範圍：M5 只交付靜態 HTML＋SARIF＋JSON 報告。
- **v0.2 後續對齊（04／05）**：裁決規則改為 05 的 R0–R13；G2 之後才出現的 `DISPUTED` 不重開 G2（§5.3）；Snapshot Service 新增 `oracle_capture` 與 G4 核准的 `oracle_count`、種子重置失敗規則（§7.6、§15）；§7.1 無法分類工具的等級規則對齊 04 §5。
- **v0.2 後續對齊（06）**：§6.1 引用 [01 §7](../01-research-survey.md#7-v02-補充研究2026-09-24) 的證據（已獨立查核），並加入嚴格 YAML 規則與 `legal_reviewer` 角色；G0b 加入 `legal_review` 檢查（§5.4）；Z2 加入版本鎖定與 CVE 更新要求（§2）；§8 補上 GPT-6 Luna 與模型退役提醒；§13.1 引用稽核鏈文獻；Executor 的 TruffleHog 驗證為選用。
- **v0.2 後續對齊（一致性）**：G0b 之前的節點不讀任何 ROE 欄位（W0 只用 G0a 已驗章的委任設定；元件授權過濾在 G0b，§5.4）；ROE 或 `legal_review` 在執行中**到期** → `SUSPENDED`，只有**驗章失效**（金鑰撤銷、簽章無效）才 `ABORTED`（§5.2、§5.5、§5.6）；保留期限的優先順序（§2）；稽核鏈尾端保護（§13.1）；簽署 JSON 文件拒絕重複鍵（§6.1）；DB 目標也對照 ROE 排除清單（§7.6）；`models.yaml` 佔位 ID 警告 `W-MODEL-PLACEHOLDER`（§8.1）。
- **v0.2 強化第二輪（與 validator 對齊）** [H]：保留期限錯誤碼分為 ROE > engagement → `E-ROE-RETENTION`、超過工具包上限 → `E-RETENTION`（§2）；gate 逾時在 G0b 之前只以委任設定的 `not_after` 為上限（§6.2）；嚴格 JSON 擴及溢位浮點數、超過 2^53 的整數與整數欄位的浮點數字面值（§6.1）；家族多樣性只計 verifier 的票（§5.9）；`sarif_refs` 必須對應同一 run 的工具稽核事件（§5.9、`E-SARIF-REF`）；DB endpoint 主機正規化（§7.6）；真實 run 的佔位模型 → `E-MODEL-PLACEHOLDER`（§8.1）；`audit_anchors` 與錨點事件一一對應、JSONL 只以 `\n` 分行（§13.1）。
- 模型命名統一：OpenAI 旗艦寫作 GPT-6 Astra／Sol（[P][E:providers-31]），設定檔中的代號為 `gpt_flagship`（§8.1）。

## 04 威脅 → 需求 → 測試案例

### v0.4 變更摘要

依 [2026-10-24 設計審查](review-2026-10-24.md) 的第三優先項目修正對照表與範例：
- **`zap:baseline` 與 `zap-api-scan.py`**：已查證的證據 E:blackbox-07 寫明 `zap-api-scan.py` 預設會跑主動掃描、`-S` 才是 safe mode。以它執行 `zap:baseline`（S0）時必須帶 `-S`，否則就是把主動掃描標成被動。
- **Open redirect**：`WSTG-v42-CLNT-04` 是用戶端（DOM）轉址；這一列的 oracle 檢查的是伺服器回應的 `Location`，WSTG v4.2 沒有對應的伺服器端 ID，改為「—」。
- **CSRF**：`playwright:api` 不會模擬瀏覽器的跨站 cookie 行為，驗不了 SameSite；只靠 SameSite 防護的應用會被誤判 FAIL。改為只驗 token 檢查，SameSite 的驗證列為 `MANUAL`。
- **認證控制**：這一列的 oracle 只涵蓋 401／403；登入限流與 session 逾時沒有 oracle，改寫清楚並指向對應的列或 `MANUAL`。
- **範例 B 的標籤**：注入文件由 U1 自己上傳，實際測到的是工具端授權（confused deputy），不是第三方內容的間接注入；標題、分類與 B 表都改寫，第三方來源的情境列為缺口。
- **ASI04／05／08 列**：oracle 寫成「請 agent ……」，看起來像直接 prompt；改寫為「以注入內容觸發，違反以工具端效果判定」，與 §4.3 的直接注入範圍聲明一致。
- **範例的 oracle**：計數查詢偵測不到 PUT 就地修改，seed manifest 的 oracle 查詢新增 `returns: row_hash`；範例 B 新增 `Q-unconfirmed-refunds`，涵蓋對 U1 自己訂單的未確認退款；測試結果新增 `trials.n_effective`（n′，`E-RESULT-TRIALS`）。
- **範例 B′**（第五輪，§6.3）：第三方（U2）文件的間接注入；seed manifest 新增 `u2_doc`。
- **框架與平台的新列**（第五輪，§4.3 F 表）：Next.js 只靠 middleware 授權、Server Actions 授權、Supabase RLS 寫入政策與 `WITH CHECK`、MCP 工具描述投毒、受測應用的 CI／CD 與 IaC；inventory 新增 `ci_workflows`、`iac` 旗標與 `cicd_iac` 面向。
- **K-015**：API 層的黑箱測試無法證實「沒有 RLS」，K-015 的確認要靠 W4 的本地 RLS 測試；範例 A 的說明改寫。
- **寫入範圍的其餘部分**（§5）：
  - 會改變狀態的 GET（seed manifest `state_changing_reads`）算寫入；W0 inventory 判定會寫入的 GET 都必須列入（`E-SEED-SIDE-EFFECT`）。
  - 以 POST 送出的唯讀端點（`read_only_endpoints`，BL-25）算讀取。
  - 路徑沒有變數段的寫入（Next.js Server Actions、GraphQL mutation、PostgREST 過濾條件）以 `object_refs` 綁定種子（BL-24）；Scope Proxy 把 body 與 query 中的物件 ID 綁到解析後的值，並移除 method override。v0.5（審查 2026-10-25 H-6）：綁定規則補上 query 字串（只接受 PostgREST `eq.`）、ID 鍵下的陣列與物件、複數 ID 鍵、沒有任何綁定 ID 的整表寫入；Server Action 改以 `server_action {action_id, args}` 逐字比對（[08 §11.7](../08-implementation-spec.md#117-scope-proxy-實作)）。審查 r7：沒有路徑變數的 PATCH／PUT／DELETE 只能以 query 的 `eq.` 選取已綁定的物件，body 中的 ID 不算選取條件（只有 POST 可以由 body 綁定）；Server Action 的參照全部要能解析，引數依 JSON 型別比對；`object_refs` 中的 `{created:x}` 只用在 x 的 `created_resource.path_templates` 宣告的路徑上。
  - create-only 端點宣告看不到的副作用（`side_effects: external／llm_tools`）；沒有宣告 `contained` 就至少 S2。
  - v0.6（審查 r7 3.8）：
    - 種子也宣告 `side_effects`／`contained`。寫入（不是讀取）一個副作用沒有被圍住的種子 → 至少 S2。種子沒有宣告時，只要 ROE `integrations` 有任何一項不是 `disabled`，就視為 `external`（fail closed；更新訂單和建立訂單一樣可能寄信）（`safety.seed_side_effects`）。
    - 請求預算包含重播：v0.7（審查 r8 外部 1）改為 `max_requests ＋ replay_n × max_requests_per_trial`，`max_requests_per_trial` 是 Scope Proxy 逐 trial 強制的上限（機率型測試必填，`E-TC-RATE`），沒有宣告時每次重播以整個 job 計。v0.6 用 `⌈max_requests ／ n⌉`——一個沒有任何規則強制的平均值：一個 301 個請求的 trial 重播兩次就是 1,002，預算卻算成 408。超過 `s1_request_cap` → 至少 S2（`safety.request_budget`）。v0.5 只比較 `max_requests`，但重播「不計入 max_requests」。
    - GraphQL：在 Scope Proxy 能解析 document 之前（[09 BL-35](../09-backlog.md)），GraphQL 請求只能以 POST 送出，並在白名單以 `graphql_document_sha256` 釘住 document；以 GET 送出，或 `graphql_operation` 不是 null 卻沒有釘住 document → S3。GET 的 document 放在 query string 中，Proxy 無法分辨 query 與 mutation。
  - seed manifest 的內容 hash 由基礎設施擁有者在 ROE 簽署（`E-ROE-SEED-MANIFEST`）。
  - Schemathesis 的 S1 模式只跑 GET／HEAD 操作；寫入操作改用綁種子的 GENERATED_SCRIPT。v0.5 起 validator 檢查：`schemathesis:*` 測試案例的 `request_allowlist` 只能有 GET／HEAD；`zap:baseline` 測試案例必須帶 `params.safe_mode: true`（adapter 以 `-S` 執行，`E-TC-TOOL`）。

### v0.3 變更摘要

- **§2.3 補上 2026 版界線與 CWE 對照**：加入官方 PDF 的「模型當元件 → LLM 清單；模型當行動者（工具、記憶、下游後果）→ Agentic 清單，模型會行動時兩張清單並用」界線規則 [V][E:threat_modeling-79]，以及附錄 A 的 CWE 對照範例（LLM01→CWE-1427；LLM04→CWE-494、CWE-829；LLM05→CWE-349、CWE-829；LLM10→CWE-1426、CWE-116、CWE-79）[V][E:threat_modeling-80]。所有 LLMxx 引用一律帶版本（§2.3、§4.3、§6）（§2.3、L-07）。
- **Binding 表（§4.3）大幅擴充並引用 OWASP API Security Top 10 2023**：新增 BFLA、mass assignment／excessive data exposure（BOPLA）、列表端點的租戶隔離、認證控制、OAuth／OIDC、CSRF、CORS、open redirect、非 LLM XSS、檔案上傳、入站 webhook 簽章、外洩檔案與頁面（source map／`.git`／`.env`／除錯／API 文件）、Supabase／BaaS（寬鬆 RLS、SECURITY DEFINER RPC、view、edge function、realtime、storage bucket）、私有回應快取、商業流程競態、盤點漂移（W0 vs B1）、供應鏈 CSP／SRI、GraphQL 額外項（batching／alias／欄位建議）、工具端物件層級授權，以及直接 prompt injection 的範圍聲明；Web／API 與 BaaS 列補上能對到的 API Top 10 2023 編號，對不到的列寫「—」。條目 ID 與名稱已查證 [V][E:blackbox-65]，逐列對映是 curated 判斷 [H]（H-F2、M-R2）。
- **§4.3 修正既有列的安全等級與 §5 一致**：GraphQL introspection 以 POST 送出 → S1；Schemathesis `use_after_free` 期望成功 DELETE 後回 404，只在 stateful 階段觸發、單次 `call_and_validate()` 不會觸發 [V][E:blackbox-66]；stateful 階段 DELETE 的目標不限於工具自己建立的物件 [H]，所以執行這個 check 為 S3、一律不跑，「刪除後不可存取」改以綁種子的 GENERATED_SCRIPT 驗證（L-11）。
- **§4.2 標明 Schemathesis `ignored_auth` 的前提**：只作用在 schema 有宣告認證（OpenAPI 的 `security`）的操作（401 或 403 都算強制）[V][E:blackbox-66]；GraphQL SDL 沒有這類宣告 [H]；沒有正確 OpenAPI 的應用須先由 W0 起草規格（連 [08 §11.10](../08-implementation-spec.md#1110-沒有-openapi-的應用)）（H-E10）。
- **良性 canary 政策（§4.3 末）**：明訂 canary 可含的內容、可放置的位置與偵測方式，以及 promptfoo／PyRIT 允許的策略「類別」（不逐一列外掛 ID）（M-G5）。
- **§3 測試案例欄位**：新增 `controls[]`（reachability／oracle_can_pass／oracle_can_fail，至少一個 reachability）、`oracle.types[]`（陣列，含 `LLM_GRADER`）、腳本式多輪的 `script_turns[]`；allow-list 項目新增 `step_id`、`graphql_operation`；結果側新增 `fail_oracles`、`INVALID` 結果、`observed_build_id`、`request_log_sha256`、`interpretation`，`precondition_reached`／`positive_control` 改為由 `controls[]` 推導（H-B1、H-A3、H-E15、H-B4、L-15、L-21）。
- **§5 安全等級演算法**（與 `tools/vchlib/safety.py` 同步）：每個寫入（POST／PUT／PATCH／DELETE、GraphQL mutation）都必須用種子 `path_templates` 相符的 `{seed:<key>}`，或用 create-only 端點＋`{created:<step_id>}`，否則 S3（`mutation_scope_problems`，`E-TC-MUTATION-SCOPE`）；allow-list 項目新增 `step_id` 與 `graphql_operation`；排除比對前先正規化路徑（`normalize_for_match`：百分號解碼一次、去 `;params`、收合 `//`、解析 dot segment、不分大小寫）；主機排除支援 `*.` 萬用字元（`host_matches`）；`host_of` 只接受 http／https，https 規則（localhost 除外）由 ROE 檢查 `E-ROE-URL` 強制；lite profile 只允許 S0／S1（`E-PROFILE-SAFETY`，MANUAL 除外）（H-B3、C-1、C-2、C-3、M-G3）。
- **§6 範例對齊 JSON**：正對照／reachability 請求與 canary 紀錄讀取都列入 allowlist；重播是獨立 job，不計入本 job 的 `max_requests`（範例 A 為 10、範例 B 為 250）（A-5）；範例 B 的對照改為在有漏洞版本上可成立的 `reachability` 控制，FAIL 定義為「未經確認即對他人訂單執行退款工具」，沒有 `oracle_can_fail` 對照所以 PASS 的 `positive_control` 為 null，待確認項目的請求也移除（A-6）；範例 B 的 FAIL 由確定性 oracle（TOOL_CALL_LOG／CANARY／STATE_DIFF）在 G4 核准測試上判定，屬 `E_proof`，不需 LLM 分析者（A-7、H-A3）；修正 `data_class`／attack tree 的混淆句（A-8）；範例 B 程式路徑改為 FastAPI 應用的 Python 檔（`app/support/agent.py`）（A-12）；K- 參照的威脅證據 kind 用 `cluster`（L-05）；「W2 叢集」改為「W3」（L-06）；WSTG ID 一律用 `WSTG-v42-…` 形式（L-08）。§3 另附一條黑箱起源的範例鏈（T-033 → TC-033-01 → K-201）。
- **§7 ROE 樣板**：新增 `build_identity`（H-B4）、共享平台網域的 `ownership_proof.platform_project` 與 `platform_policies`（H-D3）、login 的 `mfa`／`captcha_bypass`／`idp`／`whoami`（H-E8）、`relay.mode`（scripted｜adaptive，H-E15）。

### v0.2 變更摘要

- **工具詞彙改用 D13 格式**：`adapter` 一律是 `tool:mode`（例如 `playwright:api`、`zap:active`）；ROE `allowed_tools` 列工具 ID、`denied_modes` 列 `tool:mode`（§3、§4、§5、§7）。
- **§5 安全等級演算法重寫**：可直接實作的虛擬碼，每個 helper 都有定義；`TOOLKIT_DENYLIST` 與 ROE `denied_modes` 用同一套 ID；未登錄的模式一律 S3；超過 ROE 速率改為 S3（v0.1 未檢查）。新版虛擬碼已實作於 validator（`tools/vchlib/safety.py` 的 `compute_safety_class`）。
- **Binding 表擴充**（§4.3）：新增 LLM02@2025、LLM04@2025、LLM08@2025、LLM09@2025、ASI04–ASI10、LINDDUN 七類、SSRF、路徑穿越、不安全反序列化、session／JWT；新增 WSTG／AITG 欄，只填已在 OWASP 官方檔案核對過的 ID。
- **兩個範例補齊端到端**（§6）：「需求未滿足」與「需求成立」兩種結果都寫出；範例 A 補上 DB 唯讀 oracle（ROE `db_access`）與 DELETE 後的種子重置；範例 B 補上對照表、`request_allowlist`、`rate_limit`、計算後的安全等級、另一家族 Result Analyst 的確認步驟，以及 0／n 的單側 95% 上界。
- **機率型測試的統計規則**（§4.4）：0 次失敗時的上界（rule of three）與所需 n。
- **措辭修正**：依據已被推翻的 E:threat_modeling-52 的「沒有官方對照」改為「未找到官方對照」（§1.1）。
- **對齊其他文件**：D5 種子威脅覆蓋規則（§1.3）、高風險威脅定義引用 [02 B2](../02-methodology.md#b2-威脅建模g3-強制簽核)、停止條件門檻引用 [03 §7.3](../03-system-architecture.md#73-限速與停止條件)、節點名稱（`B3_derive`、`B3_validate_artifacts`、`B5_verify`、`B5_readjudicate`）、PASS／FAIL 對叢集裁決的影響依 [05 §4.2](../05-bias-calibration.md#42-裁決狀態與有序規則)。
- **OWASP LLM Top 10 版本**：官方 2026 PDF 已讀取且條目與 S-01 一致 → 新 engagement **預設改為 2026 版**（查證已通過；理由與回退條件見 §2.3）；新增版本欄位說明；Binding 表同時列兩版編號。
- **ASI 名稱**依官方 PDF 更正（ASI02、ASI03、ASI05）；WSTG v4.2 的引用網址改用 `wstg.owasp.org/v4.2/`（§4.3）。
- **與實作對齊**（`tools/vchlib`）：§5 的函式與參數名稱改成與 `safety.py` 相同；testcase 欄位 `seed_manifest_ref`（`docs/examples/seed-manifest.yaml`）、`{seed:<key>}` 整段規則、`data_needed.db_tables`、`multi_turn`、`trials.{n, fail_k_min, replay_n, multi_turn_max_turns}`、`oracle.{oracle_query_id, requirement_refs}`；ZAP 參數 `delayInMs`、`maxScanDurationInMins`、`threadPerHost` 的 ROE 界限（§3、§4.2、§4.4、§6）。OWASP 2026 資源頁標題更正為「OWASP GenAI LLM Top 10 2026」、授權說明補上 `LICENSE.md` 只是 deed 摘要（§2.3）。

## 05 降低模型偏誤：證據、規則、裁決、校準

### 第十輪審查的變更（`rule_version 05-v0.9`）

- **S 每個根取最強的一票**（§4.3）：同一個根的票立場一致時，取 |w| 最大的那一票；立場不一致時取平均（同時有支持與反駁本來就是 R3）。第九輪取平均，同根多一張較弱的支持票反而把 S 拉到 θ 以下：增加證據不應該讓確認消失。
- **棄權當作擲硬幣**（§4.3）：一張棄權票以「半對半錯」計入該邊的正確率與 Wilson 下界（`checks.effective_counts`）。第九輪只算表態的票，棄權率在 `abstain_rate_max`（0.3，仍保留為硬上限）以下時，只回答容易案例的模型權重不受影響。範例的權重因此下降（nemotron_self authz support 1.4633 → 1.3179，claude_sonnet 1.4425 → 1.2853），兩個根的支持仍跨過 θ_confirm 2.5，所有範例裁決的狀態不變、分數改變。
- **θ_reject 的守衛**（§5.7）：每個桶的 θ_reject 必須高於該桶任何一張反駁票的權重；否則一張反駁票就能讓單一家族回報的叢集被第 8 列自動駁回（`E-CAL-THETA`）。`generalised: true` 的保留切分至少 10 個叢集。
- **合格分析者不同意 → `E_inc`**（§4.2）：事先登記的解讀遇到合格 Result Analyst `agrees: false` 時，結果是 `E_inc`（本文件一直這樣寫，第九輪的程式讓事先登記優先）。
- **作者不明不算獨立**：W4 測試的作者集合是空的（agents.yaml 沒有 test_generator／test_critic）→ 不獨立；有 W4 結果的 bundle 必須登錄這兩個角色（`E-AGENT-ROLES`）。
- **`trials.sampling: sampled` 是宣告，不是訊號**：重播放寬只看目標側訊號（LLM 威脅、LLM 測試工具、multi_turn、`target_model` 紀錄）；只宣告 sampled 而沒有任何目標側訊號 → `E-TC-TRIALS`。
- **校準汙染欄位生效**（§5.4）：canary 重現的模型權重為 0；哨兵 app 必須在保留切分；`holdout_access_log` 不能早於預先登記時間（`E-CAL-CONTAMINATION`）；有權重的模型被標示變體召回落差 → `W-CAL-CONTAMINATION`。
- **R8 是防禦縱深**：θ_confirm 高於任何單張支持票（`E-CAL-THETA`）而且每個根只算一票時，第 11 列一定需要兩個根的支持票，`diversity_degraded` 不會成立，R8 不會觸發；保留它，防的是校準檔或 θ 規則將來改變。

### 第九輪審查的變更（`rule_version 05-v0.8`）

- **S 以基底血統計**（§4.3）：同一個根的計權合格票是一個觀察，S 取該根各票 w × 立場的平均（`derive.root_score`）。對數概似比只有在觀察互相獨立時才能相加；v0.7 把 claude_sonnet 與 claude_opus 兩張 1.44 的支持票加成 2.885，跨過了 θ_confirm 2.5，而沒有任何其他血統支持。
- **W4 的事先登記證明要求作者獨立**（§4.2 R1）：寫與審 W4 測試的代理（test_generator、test_critic）都在叢集的家族與基底血統之外，FAIL 才是 `E_proof`；否則要有合格的 Result Analyst，不然是 `E_fail_u`。G1 簽的是需求，不是測試程式；v0.7 讓回報家族自己寫、自己審的測試直接確認自己的發現。
- **機率型只判定一次**：FAIL 的重播規則用分類時同一個判定（看得到 LLM 威脅）；v0.7 在重播規則裡重判一次，看不到威脅分類，於是一次沉默的重播就把已確認的違反降成 `E_inc`（外部審查 1）。有機率型訊號的測試必須宣告 `trials.sampling: sampled`（`E-TC-TRIALS`）。
- **血統宣告一致**：同一血統的模型宣告相同的 `derived_from`，矛盾即 `E-MODEL-LINEAGE`；根不再依 models.yaml 的排列順序而變（外部審查 2）。
- **校準**：棄權率超過 `abstain_rate_max`（預設 0.3）的一邊 near_zero（§4.3）；§5.7 的 θ 限制由分割統計重算，θ_confirm 必須高於該桶任何單張支持票的權重（`E-CAL-THETA`）。
- **誤報抑制要兩個人**（§5.10、[08 §11.16](../08-implementation-spec.md#1116-sarif-輸出與報告回饋)）：簽署者與副簽者是不同的人，其中一位是沒有在 G2 決定該叢集的 security_reviewer。

### v0.7 變更摘要（第八輪審查 第 3 組）

`rule_version` 改為 `05-v0.7`：
- **平滑的先驗**（§4.3）：a ＝ (C ＋ k·ā ＋ 1) ／ (n ＋ k ＋ 2)。v0.6 的 a ＝ (C ＋ k·ā) ／ (n ＋ k) 只往模型自己的跨桶正確率 ā 收縮：一個在每個桶都單邊全對的模型 ā＝1，a 也是 1，ln(a／(1−a)) 除以零而權重被歸零——最準的驗證者反而沒有發言權。範例的權重與分數因此重算（K-014 的 S 由 1.5775 變為 1.4633，θ_confirm 2.5 不變，裁決狀態都不變）。
- **R6 的來源**：`E_fail_u` 只有在寫或塑造那個測試的代理（`derive.test_author_families`：W4 的 test_generator／test_critic、黑箱的 test_designer／test_implementer／test_critic 與威脅建模者）都在叢集的家族與基底血統之外時，才算一個獨立來源（`Inputs.fail_u_independent`，由 validator 推導）。v0.6 算每一個 `E_fail_u`，所以單一家族回報缺陷、自己寫 W4 測試、自己解讀 FAIL，就能靠 R6 到 `LIKELY`。`E_fail_u` 仍是第 7 列的訊號：單一反駁票遇上它會變 `DISPUTED`，交給人。
- **決定表**：第 3、5 列與「G2 駁回後才出現 FAIL 證明」的邊界列改寫，與 v0.6 的 R10（只有 `proof_overrides_g2` 的證明能推翻駁回）一致；v0.6 的表仍寫著任何 `E_proof` 都是 R10＋R1，與程式不符（2,304 個輸入組合）。
- **`provisional` 的例外**補上第 10 列（強工具佐證，v0.5 起程式已如此）。
- 機率型測試的預算不足不再降低 n（[04 §4.4](../04-threat-to-testcase.md#44-機率型測試的次數與上界)）。

### v0.6 變更摘要（第七輪審查 第 3 組）

`rule_version` 改為 `05-v0.6`：
- **R10**：只有 G4 核准、重播至少命中一次（k_r ≥ 1）的 B4 證明能推翻 G2 駁回。W4 證明由白箱流程自己產生與解讀，而人剛剛否決的就是這個流程；它仍能讓沒有被駁回的叢集經 R1 升為 `CONFIRMED_EXECUTABLE`，但對已駁回的叢集只加註 `post_g2_conflict`，送 B6 人工複核。
- **Result Analyst**：除了叢集的家族與血統，也排除寫測試的家族——W4 的 test_generator／test_critic，黑箱的 test_designer、test_implementer、test_critic 與該威脅的 threat_modeler。否則分析者是在評自己的測試。
- **機率型測試**：依測試的對象判定（LLM 測試 adapter `promptfoo`／`pyrit`、`multi_turn`，或 `trials.record` 記錄目標模型），不看宣告的 n；這類測試的 n 必須 ≥ PASS 所需的有效次數（`E-TC-TRIALS`）。v0.5 以 n ＞ 1 判定，宣告 n＝1 的 LLM 測試只跑一次乾淨的 trial 就算合格 PASS。
- **R0**：成員證據沒有任何一項接地（MATCHED／MATCHED_SHIFTED），而且至少一項 NOT_FOUND。v0.5 要求全部 NOT_FOUND，所以一項 NOT_CHECKED 就能讓沒有任何接地證據的叢集逃過 R0。
- **一致決**：R3／R4 的「任一計權合格反駁票 → 不能確認」是刻意的一致決設計：單一家族的反駁就足以把叢集送 G2 由人判斷（R4 第 9 列），只有單一家族回報的叢集才可能被反駁自動駁回（第 8 列）。

### v0.4 變更摘要

依 2026-10-24 設計審查（[review-2026-10-24](review-2026-10-24.md)）修正會讓真漏洞在沒有人看到時被駁回或降級的規則邊界；`rule_version` 改為 `05-v0.4`。

- **R0 只在叢集沒有任何其他證據時成立**（§4.2）：除了「所有成員的所有證據都是 `NOT_FOUND`」，還要沒有已解析的 SARIF（強或弱），也沒有 FAIL 類測試證據（`E_proof`／`E_fail_u`）。v0.3 中，LLM 片段的行號偏移超過 ±3，就能讓掃描器或可重現 FAIL 也指向的叢集被駁回，而且不進 G2、不成為種子威脅。（審查 A1）
- **可執行證明不被 G2 駁回覆蓋**（R10）：G2 駁回對投票、SARIF 與 `E_fail_u` 仍是最終決定；但 `E_proof` 出現時，叢集改為 `CONFIRMED_EXECUTABLE`（`rule_trace` 為 R10、R1），加註 `post_g2_conflict`，列入 B6 人工複核清單。理由：事先登記、重播成立的確定性 FAIL，比測試出現之前的人工判斷更有力；v0.3 會讓它在 SARIF 中維持 `REJECTED` 而被壓掉。G2 的 accept 仍不是規則輸入。（審查 A4）
- **R11 降級需要正對照**（§4.2）：合格 PASS 只有在有 `oracle_can_fail` 對照且為 PASS（`positive_control: true`）時，才把 `CONFIRMED_CORROBORATED`／`LIKELY` 降為 `DISPUTED`；沒有正對照的 PASS 只加註 `test_not_reproduced`。沒有證明過自己能失敗的測試，不能用來反駁。W4 的 `E_pass` 本來就要求 `oracle_can_fail` 對照；受影響的是 G4 核准但沒有正對照的黑箱 PASS（例如 ZAP 通用掃描）。（審查 A3）
- **`NOT_CHECKED` 不計入獨立家族**（§4.1）：計入獨立家族的發現項必須至少有一項**已接地**的證據（`MATCHED`／`MATCHED_SHIFTED`）。v0.3 只排除「全部 `NOT_FOUND`」，兩個家族各交一份無法檢查的 `config_fact` 就能到 `LIKELY`。（審查 A2）
- **SARIF 只佐證自己位置的叢集**（§4.2）：稽核事件 `payload.sarif_results[]` 的每一項加上 `file`、`symbol`、`cwe_bucket`（正規化器的輸出），必須等於叢集的正規位置與桶；黑箱叢集不收 SARIF。v0.3 只檢查 ref 在稽核檔中，任何單一家族叢集都能借一筆無關的結果當弱訊號而到 `LIKELY`。（審查 D1）
- **程式片段要有實質內容**（§3 規則 5）：遮罩後片段至少 12 個非空白字元，且含一個 3 字元以上的識別字；片段的檔案必須在該發現項的切片中。單獨一個 `}` 在任何視窗內都找得到，v0.3 會把它當成已接地。（審查 D4）
- **quorum 的定義**（§3 規則 3）與 **`single_best_resampled` 下的裁決**（§5.6）補上定義。（審查 A8、A9）
- **第五輪**（[review-2026-10-24 §9](review-2026-10-24.md#9-第五輪剩餘項目)）：
  - **支持與反駁權重分開**（§4.3）：支持票的權重取自真缺陷上的票、反駁票的權重取自已知非缺陷上的票，各自平滑與套用「接近 0」判準。v0.3 的單一正確率會讓永遠投支持的驗證者也拿到正權重。（審查 A10）
  - **`provisional` 只標在投票可能決定的裁決**（§4.2）：R0、R1、R9、R10 決定的裁決與黑箱叢集一律不是暫定。範例 K-202 改為 false。
  - **合格票的引用必須與叢集相關**（§4.2），`anonymized`／`order_randomized` 由 run 的 verifier 範本推導。（審查 A6、D5）

### v0.3 變更摘要

- **reviewer 與 verifier 看不到工具輸出**（§3 規則 5）：工具結果只經由確定性的 Clusterer／Aggregator 進入裁決，因為一個家族重複掃描器的命中不是獨立證據。（H-A1）
- **工具佐證分強／弱**（§3 規則 5、§4.2）：只有 (adapter, rule_id, tool_version) 列在該桶 `high_precision_rules`、且 `precision_lower95` ≥ `high_precision_min`（0.90）的 SARIF 算強佐證；校準前名單為空。其他 SARIF 與 `E_fail_u` 是弱工具訊號，各只算 1 個獨立來源。R2 計算獨立來源數；R4 遇到任何工具佐證或訊號都是 `DISPUTED`；R5 只接受強佐證或投票分支；R6 改為「獨立來源 ≥ 2 → `LIKELY`」；R8 不變。裁決新增 `tool_signal`、`independent_sources`；`tool_corroboration` 只含強佐證。決定表仍是 13 列，欄位改為「強工具佐證」「弱工具訊號／`E_fail_u`」「獨立來源 ≥ 2」。範例 K-014 由 `CONFIRMED_CORROBORATED` 改為 `LIKELY`（它的 SARIF 改由 `opengrep:scan` 產生，見 §4.2）。`rule_version` 改為 `05-v0.3`。（H-A1、N-7）
- **新增 §5.10**：掃描器規則列入高精準名單的程序（Clopper-Pearson 下界、n ≥ 40、保留切分檢查、移除與暫停）。（H-A1）
- **確定性證明不必經 LLM**（§4.2 測試證據分類）：確定性 oracle 判定的 FAIL，重播成立、所有對照 PASS、解讀事先登記（G4 核准的黑箱測試；或需求全部經 G1 簽核、有 `oracle_can_pass` 對照的 W4 測試）→ 直接 `E_proof`。否則由分析者池（每家族一位；有 PII 時只用自架模型）中合格的 Result Analyst 確認。`oracle.types` 改為陣列並新增 `LLM_GRADER`；測試結果新增 `fail_oracles`；違反只由 `LLM_GRADER`／`HUMAN` 判定 → `E_inc`。（H-A3、N-8、L-15）
- **對照與 `INVALID`**（§4.2）：測試案例的 `controls[]`（`reachability`／`oracle_can_pass`／`oracle_can_fail`）；任一對照不是 PASS → `INVALID` → `E_inc`，永遠不算 PASS。`E_pass` 改以 `reachability` 對照取代「前置條件已到達」；`positive_control`＝`oracle_can_fail` 對照為 PASS。（H-B1、H-A3）
- **黑箱起源叢集**（§4.1）：`origin: white_box | black_box`、`threat_id`、以端點為叢集鍵、沒有成員；R0 不適用，實際會觸發的是 R1 或 R7。（H-A3）
- **跨 run 指紋與基準狀態**（§4.1）：`fingerprint`、`baseline_state`（SARIF `baselineState` 的四個值）、`reopened`；不是裁決輸入。（H-B5）
- **多樣性旗標不再倒置**（§3 規則 3）：以合格驗證家族 E(叢集) 定義 `no_eligible_verifier`（|E|＝0）與 `diversity_degraded`（計權合格票的家族數 ＜ min(2, |E|)），只計 verifier 角色的票。（N-1、N-11）
- **`no_eligible_verifier` 的去向**（§3 規則 2）：這類叢集是 `LIKELY`，不進 G2；改由 W4 與黑箱測試確認。（N-4）
- **fallback 的票**（§3 規則 3、§4.3）：同家族 fallback 可以投票，但權重取 fallback 模型自己的值，完成 §5.8 重跑前為 0。（N-2）
- **證據接地**（§3 規則 5、§4.2）：證據種類 `code_snippet`／`inventory_fact`／`config_fact`；對遮罩後的文字做容錯比對（空白正規化、±3 行，`MATCHED`／`MATCHED_SHIFTED`／`NOT_FOUND`／`NOT_CHECKED`）；R0 改為「所有成員的所有證據都 `NOT_FOUND`」；合格票要引用已接地的程式位置或 inventory／設定事實，不能引用工具輸出。（H-A5、L-16）
- **暫定裁決與 reviewer 權重**（§4.2、§4.3、§5.3 M-1）：裁決新增 `provisional`（校準前），報告標示；reviewer 不投票、沒有權重，各家族 reviewer 的 recall／precision 只當指標。（H-E11）
- **自我宣告的欄位不採信**擴大（§4.2）：validator 另外推導 `tool_corroboration`（強）、`tool_signal`、`independent_sources`、`no_eligible_verifier`、`provisional`。（H-A1、N-1、H-E11）

### v0.2 變更摘要

- **裁決規則補齊為全函數**（§4.2）：新增測試證據分類（`E_proof`／`E_fail_u`／`E_pass`／`E_inc`）、R9（Lane A 上限，D8）、R10（G2 人工駁回）、R11（合格 PASS 修正）、R12（不確定測試結果只記錄）、R13（G3 駁回種子威脅只註記，D5），並附**決定表**，使每種輸入組合恰好對應一個狀態。機率型 LLM 測試的 k 門檻、重播（n_r＝20）與有效次數下限（n′ ≥ 30）對齊 04 §4.4；只有 LLM grader 判定的違反列 `E_inc`。
- **修正 v0.1 的兩個漏洞**：R4「只有合格反駁」但有工具佐證時一律 `DISPUTED`，不再自動 `REJECTED`；R6 改為「≥ 2 個家族獨立回報、沒有計權反駁、未達 R5」即 `LIKELY`（v0.1 中「2 家族＋支持但 S 未達門檻」會掉到 `UNCORROBORATED`）。
- **G2 路由對齊 02 W3**：G2 佇列＝所有 `DISPUTED`＋最高嚴重度為 critical／high 的 `UNCORROBORATED`；其他 `UNCORROBORATED` 直接成為種子威脅；佇列為空就略過 G2（`gate_skipped`）。
- **重新裁決節點**：`W4_readjudicate`、`B5_readjudicate`；每次產生新版裁決（append-only）。
- **權重公式明確化**（§4.3）：平滑後投票正確率 a → w＝max(0, 2a−1)，並定義「接近 0」的判準。
- **校準語料**（§5.1）：組成、各 CWE 桶目標數、按應用切分的校準／保留集、汙染控制、雙標註者＋κ 門檻＋仲裁。
- **預先登記的主要假設**（§5.6）：③ 多家族 vs ② 單一最佳模型重複取樣，含檢定、α、最小效果量、逐步樣本數計算，以及 ③ 未勝出時的預設設定切換。
- **次要／探索性分析**：驗證者真陰性率分開報告（M-11）；少數否決組 ⑤ 只作探索，不改主要假設。
- **門檻調整**（§5.7）、**模型版本變更的最小重跑集**（§5.8）、**M2 出場門檻**（§5.3）、**校準設定／結果欄位**（§5.9，schema 見 [schemas/calibration.schema.json](../schemas/calibration.schema.json)）。
- **validator 推導旗標**（§3 第 3 條、§4.2）：`diversity_degraded`＝有效且投票者角色為 `verifier` 的票中不同家族少於 2（家族由 `voter_agent_id` 經 agents／models 登錄解析），`tool_corroboration`＝叢集已解析（對應到稽核檔中白箱工具輸出，否則 `E-SARIF-REF`）的 `sarif_refs` ∪ `E_fail_u` 測試結果的 `result_ref`；都與裁決自己宣告的值比對，不採信自我宣告，規則以推導值重算。
- **§2 證據補充**：新增 preference leakage、身分驅動的自我偏好、反證（可驗證修訂任務無自我偏好）、同質辯論、異質驗證、評審的「好好先生」偏誤、Cursor Bugbot 的同模型多次審查；§5.1 補上資料集授權。只改證據敘述，不改規則。

## 06 工具包自身的安全、法遵與授權、做不到的事

### v0.4 變更摘要

依 [2026-10-24 設計審查](review-2026-10-24.md)：
- **跨境聲明移到 G0a**（§2.2）：委任設定的 `data_transfer` 逐家族宣告處理區域與傳輸機制（`E-ENG-TRANSFER`）。v0.3 只在 ROE 的 `legal_review` 有一個布林 `cross_border`，而 G0b 之前的節點不讀 ROE，W2 卻已經把 C 級程式碼送到雲端模型。範例 ROE 的 `cross_border` 改為 true（委任設定宣告了 TW→US），不一致時 `E-ROE-TRANSFER`。
- **事故應變**（§2.2）：ROE 新增 `incident_response`（聯絡人、通報時限、四種事故、處理程序與責任條款，`E-ROE-INCIDENT`）。
- **W0 個資掃描**（§1.3）：repo 中的 fixture、種子 dump 與日誌也可能有真實個資；W0 以確定性偵測器掃描並像 secrets 一樣遮罩（遮罩表 `kind: pii`）。
- **設定檔釘選與關卡時間**（§1.6）：`models.yaml`、`agents.yaml`、`tools.yaml`、`licenses.yaml` 由委任設定的 `config_pins` 釘選；關卡決定的時間以 Audit Writer 的收件時間為準。§3 #25 的限制因此縮小。

### v0.3 變更摘要

- **§3 做不到**：
  - 補上 #26–#41，共 16 條。內容包括：單人無法職責分離、staging 不等於正式環境、PASS 不代表沒有漏洞、平台後台設定、W0 完整度、目標內部的 LLM 設定、0/n 的上界、目標回應中的注入、靜態抽取與 WebSocket／SSE、kill switch、快照依平台、共享網域、校準前暫定、簽章不代表仔細審、成本與重現性、CAPTCHA 與第三方 IdP。
  - 全部 41 條分成四類，並附索引（v0.5 增為 43 條）。
  - 既有編號不變。
  - （M-G1）
- **指揮官的輸入**（§1.1 ASI01）：指揮官沒有任何工具，只收到程式碼產生的型別化視圖，與 agents.yaml 一致。（N-6）
- **ASI09 抽查**（§1.1）：
  - 抽查母體改為所有 `CONFIRMED_*` 裁決。G2 佇列只有爭議與高嚴重度未佐證的叢集，原本的母體永遠是空的。
  - G2 的決定另外抽查。
  - G5 的升級方式改為「下一個 run 起改用 Full 模式」，由 validator 強制兩人核准。（v0.7 後續：改為只改 G5 規則，不切換為 Full，見 02 §1.7。）
  - （N-3、N-11）
- **保證等級**（§1.6）：職責分離依 Lite／Team／Full 而不同，定義見 [02 §1.7](../02-methodology.md#17-保證等級liteteamfull)；安全底線不變。（M-G3）
- **共享平台網域**（§2.1）：`*.supabase.co`、`*.vercel.app` 這類主機改用平台專案證明與 `platform_policies`。（H-D3）
- **授權登錄表**（§2.3）：
  - 新增候選工具：tree-sitter、Presidio、mitmproxy。
  - 新增 OWASP API Security Top 10 2023，授權待查。
  - BaxBench 的用途與 05 §5.1 一致，只作輔助資料。
  - （M-R2、N-11）
- **本 repo 自己的 CI** 也改為鎖 commit SHA（§1.5）。（M-R1）

### v0.2 變更摘要

- **自測計畫**（§1.2.1）：以植入 prompt injection 的 repo 語料，在 M1–M5 每個里程碑，以及每次換模型或換 prompt 時，量測工具包本身；有可量測的通過條件。
- **定期抽查**（§1.1 ASI09）：訂出頻率與樣本數。
- **Secrets 先於 LLM**（§1.3）：依 D1，secrets 掃描與遮罩移到確定性的 W0；Gateway 對沒有 `redaction_map_ref` 的 run 一律拒絕。
- **沙箱**（§1.4）：以 CVE 與獨立學術研究取代「只找到廠商自述」；補上側通道與主機端元件的限制。
- **簽章與稽核鏈**（§1.6、§1.7）：補上 D11、D12 的外部事實、`signatures[]` 格式、指紋格式、金鑰登錄與撤銷語意，並說明 YAML 解析的陷阱。
- **資料分級**：改為 P（公開或合成）與 C（機密）兩級，與 schema 一致。
- **法遵**（§2.1）：ROE 新增 `legal_review` 聲明，由 G0b 檢查（L-1～L-6；`management` 代理時為警告 `W-L2-MANAGEMENT`）。G0b 之前的節點（含 W0）不讀 `legal_review`；ROE 或聲明在執行中到期 → `SUSPENDED`（§2.1.1）。
- **保留期限**（§2.2.1）：`toolkit.yaml` 是上限與預設值，engagement 的 `retention_days` 是實際值，只能收緊。
- **授權登錄表**（§2.3）：
  - 涵蓋 docs 02–05 與 examples 中的每個工具、模型、資料集與標準，每列都有授權、義務與狀態
  - 需要法務判斷的項目有負責角色與里程碑閘門
  - pytm 標記更正為 [C]
  - E2B 的衝突改寫為「兩者皆寬鬆，記錄依據」
- **§3 做不到**：新增 #16–#25（稽核鏈、DB 還原、DB 所有權、工具端限制、沙箱稽核、側通道、模型退役、NVIDIA 試用條款、法務判斷、自我宣告的簽署時間）。
- **§4 開放項目**：每項都對應里程碑與負責角色。
- v0.2 新的外部事實都已經獨立查核並併入證據帳本，依查核結果標 V／P／C（見 [01 §7](../01-research-survey.md#7-v02-補充研究2026-09-24)）。

## 07 實作路線圖

### v0.4 變更摘要

依 [2026-10-24 設計審查](review-2026-10-24.md) 的第三優先項目：
- **核心假設在 MVP-1 之前先做一次決策**（§1.2、MVP0-X6）：v0.3 明文不把「多家族勝過單一最佳模型多次取樣」當成出口條件，校準又排在 MVP-3 之後，所以 MVP-0～2 期間整套多家族機制都在未經檢驗的假設上運作。v0.4 在 MVP-0 結束前加入預先登記的**前導實驗**：在不是工具包團隊寫的應用上比較兩種設定，依預先寫好的規則決定 MVP-1 起的預設值。它的樣本小、不是統計證明；正式檢定仍是 05 §5.6（M2-X1）。
- **M2 的預設值必須照 §5.6 的結果切換**（M2-X13）：主要假設的結果仍不擋出場，但「照結果切換預設值」是出口條件。
- **法務閘門綁到 MVP 切片**（MVP0-X7）：MVP-0 已經用雲端模型跑 W2，所以它用到的供應商條款與 ZDR（§3 的 M1 前、M2 前中相關項目）必須在 MVP-0 出貨前結案。
- **Lite 使用者 pilot**（§1.3、MVP0-X8）：至少 8 位（v0.7，審查 r8 M3）不屬於工具包團隊的單人開發者，以各自的應用跑 Lite 的 MVP-0，量測「拿到第一份報告的時間」與「人工關卡總耗時」；未達門檻就啟用降階路徑。
- **W2 的加值要在外部應用上量**（MVP0-X6 的報告項目）：MVP0-X1 的三個植入問題都能由 W0／W1 確定性找到，沒有測到 LLM 審查本身。

### v0.3 變更摘要

- **分段 MVP**（§1.1）：
  - 開發與交付的順序改為四個可用的縱向切片：
    - **MVP-0**：白箱、不連網，先支援 Next.js＋Supabase
    - **MVP-1**：本地拋棄式目標
    - **MVP-2**：staging，只跑 S0／S1
    - **MVP-3 以後**：S2＋G5、LLM 功能測試、校準等
  - 每段都有可量測的出場條件，並列出沿用哪些 M 準則。
  - 里程碑 M1–M5 保留，作為元件的歸屬與出口準則。
  - （M-G2）
- **保證等級**：每個 MVP 標示可用的模式（Lite／Team／Full，[02 §1.7](../02-methodology.md#17-保證等級liteteamfull)）。（M-G3）
- **指揮官的加值要量測**（M2-X12）：指揮官維持為核心元件，但它的計畫必須包含確定性的覆蓋下限；它額外加派的內容是否產生有效叢集，要記錄並報告。（M-G4）
- **ASI09 抽查**（M2-X7）：抽查對象改為所有 `CONFIRMED_*` 裁決與 G2 的決定。（N-3）
- **法務閘門與工具佐證**（§3）：`licenses.yaml` 狀態不是 `OK`／`注意` 的 adapter（例如法務閘門未結案的 `semgrep:scan`）產生的 SARIF，validator 回報 `E-SARIF-REF`，既不算強佐證也不算弱訊號。範例 K-014 的 SARIF 因此改由 `opengrep:scan` 產生（[05 §4.2](../05-bias-calibration.md#42-裁決狀態與有序規則)）。（N-7）

### v0.2 變更摘要

- **歸屬**：[03 §1](../03-system-architecture.md#1-元件總覽) 的每個元件、[03 §5.7](../03-system-architecture.md#57-節點規格表) 的每個節點，都指定了里程碑（§2）。
- **出口準則**：
  - 改為編號、可以量測的準則（`M1-X1` 等，§4）；
  - 直接引用 05 的 M-1–M-11、04 的範例 A／B、06 的 ST-1–ST-7。
  - v0.1 的「多家族 vs Self-MoA 比較」改為依 05 §5.3 報告，**不作為出口條件**。
- **閘門**：法務項目與研究缺口改為各里程碑的入口閘門（§3），內容取自 [06 §4](../06-security-legal-limitations.md#4-開放的法務與查證項目) 與 [01 §5](../01-research-survey.md#5-研究缺口未搜尋或未能確認)。
- **儀表板移除**（D14）：M5 只有靜態 HTML 報告。
- **模型名稱**：旗艦模型改寫為「GPT-6 Astra／Sol」[P][E:providers-31]，別名 `gpt_flagship`。v0.1 只寫 GPT-6 Sol。
- **新增**：
  - 自測排程（§5）；
  - 模型退役追蹤（§7）；
  - 連到 [08](../08-implementation-spec.md) 的完成定義。

## 08 實作規格

### v0.3 變更摘要

- **新增 [§11 元件規格補充](../08-implementation-spec.md#11-元件規格補充)**，共 17 小節；小節標題固定，其他文件直接連到它們：
  - W0 抽取器外掛與支援矩陣、瀏覽器直連 BaaS 的入口、只在平台後台的設定、W0 與 B1 的端點差異（§11.1）（H-E1）
  - `ToolResult`、正規化與合併、tool-only 叢集、SCA／secrets／套件存在性的去向、強與弱工具佐證（§11.2）（H-E2）
  - Slicer 的呼叫圖來源與限制、錨點、focus 與 context、monorepo、多語言、token 預算、新的 `slice_id`（§11.3）（H-E3）
  - G1 的白話問卷、invariants 新欄位、依功能提高 ASVS／AISVS 等級（§11.4）（H-E4）
  - DFD 元素的出處、邊界種類、browser → BaaS 資料流（§11.5）（H-E5）
  - 種子資料的建立、解析、重置與清理，以及 STATE_DIFF 怎麼觀察狀態（§11.6）（H-E6）
  - Scope Proxy 的 per-job 身分、TLS 終結、HTTP/2／WebSocket／SSE、DNS 固定與 CDN、路徑正規化、萬用字元主機、只允許 HTTPS、B1 爬行的預設規則（§11.7）（H-E7、L-17、C-1、C-2、C-3）
  - Session Provider 的登入方式、第三方 IdP、MFA、CAPTCHA、每批 whoami、加密的 storageState（§11.8）（H-E8）
  - 共享平台網域的 `platform_project` 證明與 `platform_policies`（§11.9）（H-D3）
  - 沒有 OpenAPI 時由 inventory 起草、`security` 取自 G1、在 G4 審（§11.10）（H-E10）
  - 校準前的預設值與 `provisional`（§11.11）（H-E11）
  - 成本模型涵蓋全部節點、價格欄位、執行前估算、錯誤預算、超支處理（§11.12）（H-E12）
  - run manifest 與 prompt 範本登錄（§11.13）（H-E13、N-5）
  - 供應商的 ZDR／DPA 宣告與 C 級路由（§11.14）（H-E14）
  - 預設為 G4 核准的腳本式多輪，adaptive 只限 Full（§11.15）（H-E15）
  - SARIF 對應表、指紋與基準狀態、追溯矩陣樣板、PR／issue 回饋、誤報回饋、修正說明、發布權杖的權限（§11.16）（M-G6、H-B5）
  - 確定性輔助規則：嚴重度 rubric、敘事 linter、B2 merger 鍵、W4 防護測試、Z2 本地 RLS 測試、Z2 建置政策、公開前綴 secret、具名 PII 偵測器、覆蓋指標（§11.17）（M-G5）
- **開頭的說明改正**：§10 只列需要使用者決定的事項，§11 補元件規格，其他未定的細節列在 [09 待辦清單](../09-backlog.md)（N-10）。
- **§2.3 介面**：
  - `AdjudicationInputs` 以 `strong_tool`／`weak_sarif` 取代 `sarif_corroboration`，與參考實作一致；`E_fail_u` 留在 `evidence`，是弱訊號（N-11、H-A1）。
  - `diversity_degraded` 改用合格驗證家族 E 的定義，並加上 `no_eligible_verifier`（N-1）。
  - `Clusterer.cluster(findings, tool_results)`；`Slicer.slice` 不再接收任何工具結果（H-E2、H-E3、H-A1）。
  - `ResolvedTarget` 加入 `platform_project`（H-D3）；`JobAllowlist` 加入協定、per-job 身分與 CDN 範圍（H-E7）。
- **§1 模組**：新增 `toolresult`、`apispec`、`pii`；publisher 是 Z1 中另一個可以對外連線的元件，只連程式碼託管平台（§1.2 規則 5）；說明「同等性單位」（H-E2、H-E10、M-G5、M-G6、L-06）。
- **§4.2 CLI**：新增 `run estimate`、`report publish`、`feedback add`（H-E12、M-G6）。
- **§5 設定**：新增 §5.4，列出 v0.3 的設定與產物欄位；§5.2 加入保證等級；§5.3 加入 publisher 權杖、Z3 CA 私鑰與 session 加密金鑰的參照（M-G3、H-D2、H-B4、H-D3、H-E8、H-E14、H-E15、N-5）。
- **§6.1 錯誤**：新增 `BuildMismatch`、`SessionUnavailable`、`SeedSetupFailed`、`TeardownFailed`（H-B4、H-E8、H-E6）。
- **§8.2 必須拒絕清單**：新增 N-32–N-43：路徑正規化繞過、萬用字元主機、非 HTTPS 的 base URL、沒有綁定種子的寫入、build 不一致、共享平台網域、Lite＋S2、Team 中一人簽兩個 ROE 角色、Full 的 G5 只有一人、角色不對的分析者、借用別的 run 的關卡紀錄、測試 G1 駁回的需求（C-1、C-2、C-3、H-B3、C-11、H-B4、H-D3、M-G3、L-13、N-11、C-12、C-8、C-10）。
- **§8.3 範例應用**：`notes-rls-app` 明定為 Next.js＋Supabase 型，植入沒有 RLS 的資料表、bundle 中的公開前綴 secret 與幻覺套件，是 MVP-0 的目標（M-G2、M-G5）。
- **§7.2、§8.5、§9**：run 紀錄改存 run manifest；列出 v0.3 追加的測試；§9.2 的 T-08、T-13–T-15 同步更新；完成定義加上分段 MVP（N-5、M-G2）。
- **§10**：U-01–U-14 不變；新增 U-15–U-23，都是 §11 帶出的新事項，各附預設做法（N-10）。

### v0.2 變更摘要

- **新文件**（D16）：
  - 套件配置與依賴方向；
  - 03 §15 的介面，以及 8 個擴充介面；
  - 從 JSON Schema 產生 Pydantic 模型的做法；
  - CLI 與結束碼；
  - 設定檔的優先順序；
  - 錯誤分類、重試與冪等；
  - 持久化；
  - 各里程碑的測試與完成定義；
  - M1 前兩週的工單；
  - 待決事項。
- 里程碑的出口準則寫在 [07](../07-roadmap.md)。本文件 §8 與 §9 的測試項目，以 07 的準則編號（例如 `M1-X2`）互相對應。
- **後續對齊（一致性）** [H]：
  - 保留期限的優先順序（§5.2、§7.5）：`toolkit.yaml` 是上限與預設值，engagement 是實際值，只能收緊；
  - ROE 或 `legal_review` 執行中到期 → `SUSPENDED`（§6.1 `OutsideWindow`、N-25），驗章失效才 `ABORTED`；
  - L-6 過濾後的允許工具清單寫入 G0b GateRecord（§2 `RoeCheck`）；
  - validator 強制的規則（§5.1、§7.4）：推導 `diversity_degraded` 與工具佐證、JSON 簽署文件拒絕重複鍵、稽核尾端保護、DB 目標對照 ROE 排除清單、`W-MODEL-PLACEHOLDER`。
  - 與 validator 實作對齊：錨點改為 `{seq, line_sha256}`（§7.4、N-22）；保留期限的錯誤碼 `E-RETENTION`／`E-ROE-RETENTION`（§7.5）；`E-ROE-DB-SCOPE`、`E-JSON-STRICT`、`E-MODEL-PLACEHOLDER`（§5.1）；`tests/test_v02_hardening.py`（§8.1）。
  - **v0.2 強化第二輪（2026-09-25）**：保留期限錯誤碼更正為 ROE > engagement → `E-ROE-RETENTION`、ROE 或 engagement 超過工具包上限 → `E-RETENTION`（§5.2、§7.5）；錯誤表新增 `StrictJSONError`（`E-JSON-STRICT`：重複鍵、NaN／Infinity、溢位浮點數、|n| > 2^53、整數欄位的浮點數字面值；簽署文件視為簽章無效）（§5.1、§6.1）；關卡逾時在 G0b 之前只受 engagement `not_after` 限制（§5.2、[03 §6.2](../03-system-architecture.md#62-關卡逾時預設值)）；`B4_preflight` 全部目標失去所有權 → `abort_handler` → `STOPPED`（§6.1）；`sarif_refs` 必須對應同一 run 的 `tool_invocation_end` 事件（`E-SARIF-REF`）、`sarif_refs`／`tool_corroboration` 不得重複；家族多樣性只計 verifier 的票（§2.3）；佔位模型的啟發式擴大，真實 run（`--real-run`、G0a）中可達的佔位模型 → `E-MODEL-PLACEHOLDER`（§5.1）；DB endpoint 主機正規化、無法解析 → `E-ROE-DB-SCOPE`（§5.1）；`audit_anchors` 與錨點事件一一對應、未錨定尾端只看最後一個錨點事件之後、JSONL 只以 `\n` 分行（§7.4）。
