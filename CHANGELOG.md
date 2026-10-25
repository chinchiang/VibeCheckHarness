# 變更紀錄

格式參考 [Keep a Changelog](https://keepachangelog.com/)；版本是設計文件的版本，不是軟體發行版本。

## v0.5（2026-10-25）

依 [2026-10-25 設計審查](docs/evidence/review-2026-10-25.md)。v0.5 分支（`07658d7`）是從 v0.3 分出的，直接合併會還原 v0.4；本版把它的內容在 v0.4 上重做（審查紀錄 §3、§7）。工具包本體仍未實作；新增的契約大多只有規格，交付時點見 [07 §1.4](docs/07-roadmap.md#14-v05-的前置工作與驗收順序-h)。第 2 組改變了 R4 與合格票的語意，`rule_version` 升為 `05-v0.5`；R10 保留 v0.4 的語意（使用者確認）。

### 寫入範圍（schema 與 validator，不相容的收緊）
- `create_only_endpoints[]` 必填 `created_resource`（`type`、`id_pointer`、`path_templates`）；`{created:step_id}` 只能用在宣告的路徑，其他變數段綁定那次建立請求的值，巢狀資源由內層的建立端點宣告；建立的 `step_id` 不能重複（`E-SEED-MANIFEST`、`E-TC-MUTATION-SCOPE`；`safety.created_resource_problem`、`created_path_allowed`）。缺少宣告的舊 manifest 一律 S3，要由基礎設施擁有者補齊並重新簽署。
- GraphQL mutation 只能以 POST 送出（v0.4 的 ROE `graphql_paths` 規則保留）。

### validator 漏洞（第 1 組）
- 有關卡紀錄的 run 必須有稽核紀錄，關卡決定一定要有收件時間（`E-AUDIT-GATE`）；範例後續 run 補上稽核紀錄。
- 測試結果只能掛到自己威脅的叢集（`E-TRACE`）。
- R10 只套用到 G2 之後的裁決版本；新增 `readjudicated_by: G2_apply`。
- `testcase.seed_manifest_ref` 必填（`E-TC-SEEDS`）。
- 新增 `tests/test_v05_round6_group1.py`。

### 裁決設計（第 2 組；`rule_version` 改為 `05-v0.5`）
- R4：只有單一獨立家族回報的叢集會被反駁票自動駁回；兩個以上獨立家族回報 → `DISPUTED`，送 G2（使用者決定）。
- 棄權票不算計權合格票。
- 引用相關性比對到行號；反駁票另可引用成員切片或 inventory 中的位置（使用者決定）。
- 校準結果中 `invalidated_by` 列出、或不在 `valid_for_model_keys` 的模型，權重為 0。
- 裁決版本只看自己階段的測試結果（W4 版看不到 B4 結果）。
- 強工具佐證（第 10 列）不標 `provisional`。
- `calibration.yaml`、`crosswalk.yaml` 加入 `config_pins`。
- 新增 `tests/test_v05_round6_group2.py`。

### 信任錨（第 3 組）
- 關卡的開啟時間改用 `gate_opened` 事件的收件時間；`opened_at` 與它不符或沒有事件 → `E-GATE-OPENED`。
- EXPIRED 紀錄不簽章（`signatures: []`，`E-GATE-EXPIRED-SIG`），也不再報 `E-SIG-MISSING`。
- `z3-executor` 是服務身分：不能當發起者、核准者或人為事件的行為者；`z3_executor` 角色不得兼任（`E-KR-SERVICE`）。
- 委任設定／ROE 的金鑰撤銷與到期都以首次驗章的收件時間判斷；`issued_at` 晚於首次驗章 → `E-SIG-ISSUED-AT`。
- G0 驗章記錄的登錄版本可以比目前舊；法務聲明者簽完 ROE 後可以輪替金鑰。
- 稽核事件改為寫入端去重（文件與 validator 一致）。
- Z3 副簽改蓋 `{domain, run_id, seq, prev_hash, event_sha256}`；Z3 簽之前重算鏈並核對自己產生的事件（規格）。
- 未錨定尾端的工具輸出不能當裁決證據。
- 委任設定沒有列的關卡逾時沿用 toolkit 上限。
- 每個裁決版本都必須有 `verdict_changed` 事件。
- 範例重簽；新增 `tests/test_v05_round6_group3.py`。

### 方法論（第 4 組）
- Scope Proxy 的物件綁定規則（`safety.request_binding_problem`）補上 query 字串（PostgREST 只接受 `eq.`，擋 `or=`／`and=` 與其他運算子）、ID 鍵下的陣列或物件、複數 ID 鍵，以及沒有任何綁定 ID 的整表寫入。
- Server Action 以 `request_allowlist[].server_action {action_id, args}` 逐字綁定（`safety.server_action_problem`）；testcase schema 新增必填欄位 `server_action`（不是 Server Action 時為 null）。
- DB 目標的所有權改以 `db_comment`（token 放在資料庫註解，Z3 以唯讀 oracle 憑證讀出）或 `platform_project` 證明；共享平台上的 DB 主機也要 `platform_project`。範例 ROE 已改並重簽。
- 範例 A 的 oracle：只有 2xx 且洩漏或改動才是 FAIL，405／422／5xx 為 INCONCLUSIVE；CTL-02 涵蓋狀態碼。
- 機率型測試的重播只記錄重現率，不再把達到 `fail_k_min` 的 FAIL 降成 `E_inc`；重播次數必須等於 `replay_n`。
- G3 超出上限的項目以 `decision: over_cap` 記錄（只限 G3、不能是高風險項目），視同駁回（D5、R13、`over_cap_items`）。
- G4 佇列上限 `gate_queues.g4_max_items`（預設 40），超出的測試案例改 `MANUAL`。
- LLM02／08／09、ASI06 的 oracle 另比對種子紀錄的結構化欄位值；04 補上帳號復原、Supabase Auth 設定、API10 三列，並寫明 Lite 沒有黑箱注入測試。
- 新增 `tests/test_v05_round6_group4.py`。

### 執行期契約（只有規格）
- job 的原子領取、租約與 fencing token（在出口強制），結果不明時不自動重送（03 §5.8，BL-31）。
- 整庫還原前取得資料庫層級的排他租約；外部寫入停不下來就不還原（03 §5.8、§7.6，BL-28）。
- CAS 依委任隔離、hash 不是授權、每個 run 一筆生命週期參照（08 §7.3、§7.5，BL-29）。
- 取樣與重播分開；無法支持獨立同分布時不給二項上界（04 §4.4，BL-30）。
- run 產物的四種狀態（08 §11.13，BL-22／23）、純工具路徑（08 §11.2，BL-13）、Scope Proxy 選型前的原型關卡（08 §11.7、07 MVP2-X5，BL-32）。

### 流程與報告
- 跨 run 的 G1／G3 沿用停用，直到 BL-21 完成；W0 → W0.5／認領與 G1 → W1，自動觸發的 run 在 G1 前停在 `claim_run`。
- G2 駁回後的新證據：裁決依 R10，報告醒目呈現、去重、不覆寫歷史（02 B6，BL-34）。
- 前導實驗加入純工具組、等費用比較與盲測紀律（07 §1.2，BL-33）；07 §1.4 列出各項前置工作的交付時點。
- 06 §3 增為 43 條（#42 共用 staging 無法安全整庫還原、#43 二項上界的前提）。

### 文件
- `rule_version` 的「目前版本」陳述在 03、08、schemas README 改為 `05-v0.4`；08 §11.6 的範例說明改為 `delete_namespace`；08 §11.7 的 `edge_ip_ranges` 說明更新。
- 新增 [docs/evidence/review-2026-10-25.md](docs/evidence/review-2026-10-25.md)、`tests/test_v05_round6_group0.py`。

## v0.4（2026-10-24）

依 [2026-10-24 設計審查](docs/evidence/review-2026-10-24.md) 的第一到第三優先項目：修正裁決規則的邊界與 validator 的繞過；把跨境聲明移到 G0a、補上事故應變、釘選設定檔、修正信任錨與 Scope Proxy；在 MVP-1 前加入核心假設的前導實驗、降低人工關卡負擔、修正對照表與範例。其餘審查項目與理由見該紀錄 §5。

### 裁決規則（語意改變，`rule_version` 改為 `05-v0.4`）
- **R0** 只在叢集沒有任何其他證據時成立：除了成員證據全部 `NOT_FOUND`，還要沒有已解析的 SARIF、沒有 `E_proof`／`E_fail_u`。（A1）
- **R10**：G2 駁回後出現 `E_proof` → `CONFIRMED_EXECUTABLE`（R10、R1），加註 `post_g2_conflict` 並列入 B6 人工複核；對投票、SARIF 與 `E_fail_u` 仍是最終決定。（A4）
- **R11** 只有在合格 PASS 有正對照（`oracle_can_fail` PASS）時才把 `CONFIRMED_CORROBORATED`／`LIKELY` 降為 `DISPUTED`；否則只加註 `test_not_reproduced`。（A3）
- 只有 `NOT_CHECKED` 證據的發現項不計入獨立家族。（A2）
- 補上 quorum 與 `single_best_resampled` 下的裁決定義。（A8、A9）

### validator
- `E-SARIF-REF`：`payload.sarif_results[]` 新增 `file`、`symbol`、`cwe_bucket`，必須等於叢集鍵；黑箱叢集不收 SARIF。（D1）
- 自架（Z4）模型改由 `toolkit.yaml` 新增的 `z4_model_hosts` 確切主機名稱判定，不再看 `z4-` 前綴。（D2）
- 新增 `E-PLAN-COVERAGE`、`E-PLAN-FAMILIES`：CMD-1 計畫涵蓋 run 的每個切片，每個切片的 reviewer 至少 min(2, 合格家族數) 個家族。（D3）
- `E-FINDING-EVIDENCE`：程式片段至少 12 個非空白字元並含識別字，檔案必須在發現項的切片中。（D4）
- `graphql_operation: query／introspection` 只在 ROE 新增的 `targets[].graphql_paths` 宣告的路徑、GET／POST 上算讀取；其他帶這個標籤的請求一律 S3。（B1）
- 新增 `tests/test_v04_adjudication.py`、`tests/test_v04_validator.py`（每項修正都有正反向案例）；測試由 454 個增加到 576 個。

### 第二優先：資料出境、法務與信任錨
- **跨境聲明移到 G0a**：委任設定新增 `data_transfer`（來源法域、聲明者、逐家族的區域與傳輸機制）；能收 C 級資料的雲端家族 `providers[].region` 不得為 null（`E-ENG-TRANSFER`）。委任設定宣告跨境時，ROE 的 `cross_border` 不能寫不適用（`E-ROE-TRANSFER`）；範例 ROE 改為 true。（C1）
- **ROE 事故應變**：新增 `incident_response`（聯絡人、1–72 小時內通報、四種事故、處理程序與責任條款，`E-ROE-INCIDENT`）。（C5）
- **W0 個資掃描**：secrets 之後以確定性偵測器掃描 repo，命中的值遮罩並記入遮罩表（`kind: pii`）。（C3）
- **設定檔釘選**：委任設定新增 `config_pins`，釘選 `models.yaml`、`agents.yaml`、`tools.yaml`、`licenses.yaml` 的內容 hash（`E-ENG-CONFIG-PIN`）。（E1）
- **關卡時間以 Audit Writer 收件時間為準**：GateRecord 的自填 `timestamp` 與 `gate_decision` 事件 `ts` 相差不超過 5 分鐘（`E-AUDIT-GATE`）；金鑰效期、ROE 有效期、逾時與 G5 時間窗都以收件時間判定。（E4）
- **執行期狀態**（03 §5.8、08 §6–§7）：B4 job 的權威帳本在 Z3、不受 checkpoint 回溯影響；每個 run 一把 advisory lock；kill switch 走圖外通道；有副作用的節點用同步 checkpoint；LLM 快取鍵加入 `engagement_id`、資料等級與取樣序號。（E3、E7、E9）
- **HMAC 遮罩金鑰**改為每個 run 一把、只存在 W0 job 內的臨時金鑰，解決「金鑰在 Z1、遮罩在 Z2」的矛盾。（E6）
- **Z3 工具容器需求表**（03 §2）：每個 job 一個 gVisor／microVM、只能連 Scope Proxy、沒有 DNS、只解密本角色的 storageState、沒有 Relay 憑證。（E2）
- **Scope Proxy**：參考實作 `safety.ip_problem`（擋 NAT64、IPv4-mapped、6to4、Teredo、ULA、`fec0::/10`、multicast 與一切非公開位址）；封鎖 h2c、QUIC 與 CONNECT 後的非 TLS 流量；路徑的 `\`／`%5C` 視為 `/`；共享平台網域加入 `lovable.app`、`replit.app`、`workers.dev`、`github.io` 等 12 個，實作版以 Public Suffix List 為來源。（B8、B9）
- 新增 `tests/test_v04_legal_trust.py`、`tests/test_v04_scope_proxy.py`；`test_validator.py` 的 G5 時間窗測試改以收件時間為準。

### 第三優先：路線圖、人工關卡負擔、對照表與範例
- **前導實驗**（07 §1.2、MVP0-X6）：MVP-1 之前，在 ≥10 個不是工具包團隊撰寫的應用上，比較多家族與單一最佳模型取樣 3 次；依預先登記的規則決定 MVP-1 起的 `w2_review.strategy`，並報告只有 LLM 找到的缺陷比例。正式檢定仍是 05 §5.6；M2 的預設值必須照它的結果切換（M2-X13）。
- **法務閘門綁到 MVP-0**（MVP0-X7）：MVP-0 用到的雲端模型條款與 ZDR 必須先結案。
- **Lite 使用者 pilot**（07 §1.3、MVP0-X8）：≥3 位外部單人開發者；第一份報告中位數 ≤ 1 個工作天、人工關卡總耗時中位數 ≤ 2 小時；未達門檻時的降階路徑（白箱快速模式、精簡問卷、託管控制面）。
- **路由改用 rubric 嚴重度**：G2 佇列、W4 輸入、B2 高風險條件 4 不再採信 reviewer 自報的嚴重度（08 §11.17）。
- **人工關卡負擔**：G2 每個 run 預設最多 30 項、G3 50 項（高風險與 critical／high 不受限），依嚴重度排序；G2 逾時比例超過 50% 時告警；低嚴重度、單一來源的 `UNCORROBORATED` 叢集只列報告、不轉成種子威脅（G3 可拉回）。設定欄位尚未進 schema（09 BL-26）。
- **ASI09 抽查**納入沒有人看過的項目：R0／R4 的自動駁回、只列報告的叢集、超出 G2 上限與 G2 逾時的項目；Lite 改為自行延後抽查。
- **對照表**：`zap-api-scan.py` 用於 `zap:baseline` 時必須帶 `-S`（依 E:blackbox-07，否則是主動掃描）；open redirect 不再誤對 `WSTG-v42-CLNT-04`；CSRF 的 SameSite 驗證改為 `MANUAL`；認證控制列寫清楚 oracle 的範圍；ASI04／05／08 列改以注入內容觸發、以工具端效果判定。
- **範例**：範例 B 更正為工具端授權（confused deputy），不是第三方內容的間接注入；oracle 查詢新增 `returns: row_hash`（偵測 PUT 就地修改）與 `Q-unconfirmed-refunds`；測試結果新增 `trials.n_effective`（`E-RESULT-TRIALS`）；K-015 改由 W4 本地 RLS 測試確認。
- 新增 `tests/test_v04_examples.py`。

### 寫入範圍的其餘項目
- **路徑沒有變數段的寫入**（BL-24 延伸）：`request_allowlist[].object_refs` 指出請求在 body、query、GraphQL variables、Server Action 參數或 PostgREST 過濾條件中碰的種子；有效時就在寫入範圍內，Next.js Server Actions 與 PostgREST 不再一律 S3。
- **Scope Proxy 的內容綁定**：寫入請求 body 與 query 中的 ID 類欄位必須是本請求綁定的種子或建立物件（參考實作 `safety.body_id_problem`）；移除 method override 標頭、擋下 `_method`。
- **會改變狀態的 GET**：seed manifest 新增 `state_changing_reads`，算寫入；W0 inventory 新增 `endpoints[].writes`，會寫入的 GET 都必須列入（`E-SEED-SIDE-EFFECT`）。B1 爬行的跳過關鍵字擴充。
- **唯讀的 POST**（BL-25）：seed manifest 新增 `read_only_endpoints`，算讀取。
- **看不到的副作用**：`create_only_endpoints[]` 新增 `side_effects`（`none`／`external`／`llm_tools`）與 `contained`；沒有聲明 contained 就至少 S2。範例的聊天端點宣告 `llm_tools`、`contained: true`。
- **seed manifest 由基礎設施擁有者簽署**：ROE `db_access.seed_manifest_sha256`（`E-ROE-SEED-MANIFEST`）。
- **種子重置**改為只處理本 run 命名空間的種子腳本，`teardown: delete_namespace`；整庫快照還原只用於 S2。
- **Schemathesis** 的 S1 模式只跑 GET／HEAD 操作。
- 新增 `tests/test_v04_write_scope.py`。

### 第五輪：審查紀錄 §5 的剩餘項目
- **支持／反駁權重分開**：`calibration.yaml` 的每列改為 `support` 與 `refute` 兩側，各自 n、correct、a、w、near_zero；SUPPORT 票用 `support.w`，REFUTE 票用 `refute.w`。
- **`provisional` 只標在受投票影響的裁決**：R0、R1、R9、R10 決定的裁決與黑箱叢集一律 false；範例 K-202 改為 false。
- **合格票的引用必須與叢集相關**：至少一項落在叢集的 canonical 檔案或等於成員的 inventory 事實，否則視為棄權。
- **旗標與排序**：`anonymized`／`order_randomized` 由 run 的 verifier prompt 範本推導（`run.prompt_templates[].anonymizes_candidates`／`randomizes_order`）；G4「最新紀錄」以 Audit Writer 收件時間排序；`initiator_claim`、`run_resume` 必須是 `human`，`run_resume` 要 `test_lead`。
- **`E-GATE-EXPIRED-EARLY`**：無簽章的 EXPIRED 不能早於 `opened_at`＋逾時。**`E-AUDIT-IDEMPOTENCY`**：`idempotency_key` 必填、格式 `run_id:node:<鍵>`、同 run 不重複。
- **稽核錨點由 Z3 副簽**：`audit_anchor` 的 `payload.z3_countersignature`（`E-AUDIT-ANCHOR-SIG`）。
- **`E-SIG-BACKDATED`**：以非 compromised 原因撤銷的金鑰，文件第一次被驗章必須早於撤銷時間。
- **CDN 邊緣 IP 範圍**（BL-15）：ROE `targets[].edge_ip_ranges`（`E-ROE-EDGE-RANGE`）、`safety.ip_in_ranges`。
- **Public Suffix List 比對**：`tools/check_platform_suffixes.py`（選用，不在 CI 執行）；`safety.PSL_EXCEPTIONS`。
- **G2／G3 佇列欄位**（BL-26）：`toolkit.yaml` `gate_queues`；report-manifest `over_cap_items`、`report_only_clusters`（`E-REPORT-QUEUE`）。
- **框架與平台的威脅列**（04 §4.3 F 表）：Next.js 只靠 middleware 授權、Server Actions、Supabase RLS 寫入與 `WITH CHECK`、MCP 工具描述投毒、受測應用的 CI／CD 與 IaC。inventory `features` 新增 `ci_workflows`、`iac`；新面向 `cicd_iac`（共 13 個）；G1 `llm_tools[]` 新增 `mcp_server`、`description_sha256`；W4 本地 RLS 測試加入寫入。
- **範例 B′**（04 §6.3）：第三方文件的間接注入；seed manifest 新增 `u2_doc`。
- **BL-27**：W4 測試案例的 schema（K-015 的 W4 確認範例等它）。
- 新增 `tests/test_v04_round5_adjudication.py`、`tests/test_v04_round5_trust.py`、`tests/test_v04_round5_examples.py`。

### 文件
- README 新增系統架構圖（`docs/architecture.svg`：四個信任區、元件、資料流與人／LLM／程式碼的分界）與 v0.4 的術語。
- docs/00、02、03、04、05、06、07、08、09 與 schemas README 依上述修改；新增 [docs/evidence/review-2026-10-24.md](docs/evidence/review-2026-10-24.md)。

## v0.3（2026-09-26）

依 [2026-09-26 深度審查](docs/evidence/review-2026-09-26.md) 修正 v0.2。高、中優先項目本輪處理；低優先與延後項目見 [docs/09-backlog.md](docs/09-backlog.md)。

### 裁決規則（語意改變）
- **審查者與驗證者不再收到掃描器結果**。SARIF 只有在校準證實為高精準規則（`high_precision_rules`）時才算強佐證；其他 SARIF 與 `E_fail_u` 只算一個「獨立來源」，最多到 `LIKELY`（R6 改為「獨立來源 ≥ 2」）。範例 K-014 因此由 `CONFIRMED_CORROBORATED` 改為 `LIKELY`。（H-A1）
- **確定性的測試失敗不需要 LLM 就能成為可執行證明**：oracle 是確定性的、重播一致、對照都通過，而且解讀事先登記過（黑箱在 G4 核准；W4 綁定 G1 已簽核需求並有 `oracle_can_pass` 對照）。Result Analyst 改為每個家族各一位。黑箱起源的問題另建 `origin: black_box` 叢集。（H-A3、N-8）
- **修正多樣性旗標倒置**：`diversity_degraded` 改以「可投票的合格家族」計算，多家族回報的叢集不再被永遠封頂。（N-1）
- 新增 `tool_signal`、`independent_sources`、`provisional`、`votes[].cited_evidence`；`rule_version` 為 `05-v0.3`。

### 資料模型與 validator
- 發現項證據新增 `inventory_fact`、`config_fact`，片段比對改為對遮罩後文字容錯比對。（H-A5）
- 測試案例必須宣告 `controls[]`；任一對照沒通過，結果就是 `INVALID`，不算 PASS；報告列出對照通過率。（H-B1）
- 所有寫入請求都要綁 `{seed:}`、`{created:}` 或 create-only 端點，否則為 S3；路徑排除先正規化再比對；主機排除支援 `*.`；base URL 必須是 https（localhost 除外）。（H-B3、C-1～C-3）
- ROE `build_identity` 與結果的 `observed_build_id`；共享平台網域改用 `platform_project` 證明與 `platform_policies`；登入的 MFA／CAPTCHA／IdP 與每個角色的 whoami。（H-B4、H-D3、H-E8）
- 保證等級 `assurance_profile`（Lite／Team／Full）、engagement `gate_approvers`、`providers[]`（ZDR／DPA）。（M-G3、H-D2、H-E14）
- inventory、invariants、DFD、seed manifest、run manifest、叢集指紋與 `baseline_state` 的新欄位；面向擴充為 12 個並依 W0 強制必要面向；指揮官沒有工具、計畫的加派目標型別化。（H-E1～H-E6、H-E13、H-B5、H-F1、H-C1、H-C2）
- 送給 LLM 的 schema 先移除 harness 欄位再降級，不支援的結構一律拒絕。（H-A4、C-7）
- validator 的強韌性：輸入形狀錯誤不再崩潰、單一錯誤不再讓整組檢查被略過、gate record 不能跨 run 借用、G1 駁回的需求不能測試、分析者角色與來源欄位都會檢查。（C-4～C-13）
- 測試由 175 個增加到 454 個。

### 文件
- 新增 [docs/00-overview.md](docs/00-overview.md)（總覽與依角色的閱讀路徑）、[docs/09-backlog.md](docs/09-backlog.md)（待辦）。
- docs/02：保證等級（§1.7）、W0 先遮罩、W1 結果只給確定性規則、12 個面向、對照與寫入範圍、黑箱起源叢集。
- docs/03：指揮官的型別化視圖、核准者來源與逐項核准、保證等級對簽署的影響、LLM 輸出投影、成本模型。
- docs/04：binding 表補約 30 類並加上 OWASP API Security Top 10 2023 編號；安全等級演算法；範例與 JSON 一致。
- docs/05：強／弱工具佐證、可執行證明、多樣性、暫定裁決、高精準規則名單的程序（§5.10）。
- docs/06：「做不到」增為 41 條並分成四類；ASI09 抽查母體修正。
- docs/07：分段 MVP（MVP-0～3）與出場條件。
- docs/08：§11 共 17 節元件規格；必須拒絕清單 N-32～N-43；待決事項 U-15～U-23。
- 證據帳本新增 10 條已查證事實（共 456 條），其中 2 條（SARIF 的 kind／level 規則、8 個 WSTG v4.2 ID）是獨立事實查核時補查的。

### 工具與 repo
- 帳本與參考文獻產生器：跳脫 `< > &`、穩定錨點、`--check` 模式；連結檢查支援 `~~~` fence、inline code、reference-style link 與 GitHub 的錨點規則；新增手動執行的外部連結檢查。
- CI：Actions 鎖 commit SHA、token 只有 `contents: read`、檢查產生的檔案是否最新。
- 授權：工具與測試 Apache-2.0（`LICENSE`），文件 CC BY-SA 4.0（`LICENSE-docs`）；Python 檔加上 SPDX 標頭；`.gitignore` 補上 secrets 與 session 檔。

## v0.2（2026-09-24～25）

- 新增實作規格 `docs/08-implementation-spec.md`、33 個 JSON Schema、`tools/vchlib` 驗證程式與參考演算法、175 個測試與 CI。
- U-11（Claude Opus 4.8 取代 Haiku 4.5）、U-12（GPT-6 Sol）已決定。

## v0.1（2026-09-23）

- 初版方法論與系統架構文件（docs/01–07）、證據帳本與參考資料。
