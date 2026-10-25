# 09 待辦清單（低優先與延後項目）

> **2026-10-24 設計審查**中工具包本身做不到的項目（實驗結果、元件本體、託管控制面），列在該審查紀錄的 [§5](evidence/review-2026-10-24.md#5-本輪沒有處理的項目)；其餘已在 v0.4 處理或編入下表。
>
> 本清單收錄 [2026-09-26 深度審查](evidence/review-2026-09-26.md) 中**本輪沒有修正**的項目：低優先（L）項目，以及刻意延後、需要更多資訊才能處理的部分。高、中優先項目本輪都已處理，或在此寫明延後的理由。
>
> [2026-10-25 設計審查](evidence/review-2026-10-25.md)（第六輪）的發現已全部處理（該審查紀錄 §7～§14）。其中只寫成規格、或 validator 只做靜態檢查的部分，連同處理時記下的限制，列在下方 §4（BL-36 起）。已處理的舊項目移到 §5，編號保留供追溯。
>
> - **需要使用者決定的事項**（金鑰、GPU、法務關卡、保留期限等）不在這裡，見 [08 §10](08-implementation-spec.md#10-尚未決定需使用者決定)。
> - **狀態**：`待辦`＝尚未處理；`延後`＝有意留到之後的里程碑。

## 0. v0.5 的實作前置項目

v0.5（[2026-10-25 審查](evidence/review-2026-10-25.md) §3）把 v0.5 分支的設計契約併入 v0.4。下列項目只有規格（或只有靜態檢查），執行期尚未實作；交付時點見 [07 §1.4](07-roadmap.md#14-v05-的前置工作與驗收順序-h)。「設計已補齊」不等於功能完成。v0.5 提升為高優先的既有項目 BL-04、BL-13、BL-21、BL-22、BL-23 已完成（§5）。

| 編號 | 工作 | 規格 | 時點 | 狀態 |
|---|---|---|---|---|
| BL-28 | 還原範圍的排他租約（資料庫層級、跨 job／run、目標別名共用一把鎖、外部寫入隔離） | [03 §5.8](03-system-architecture.md#58-節點邊界規則)、§7.6 | 任何 `snapshot_restore` 之前 | 設計已補齊；未實作 |
| BL-29 | CAS 依委任隔離、hash 不是授權、每個 run 一筆生命週期參照 | [08 §7.3](08-implementation-spec.md#73-cas-配置)、§7.5 | CAS 實作之前 | 設計已補齊；未實作 |
| BL-30 | 取樣與重播分開、每個 trial 的實際呼叫證據與快取紀錄、無法支持獨立同分布時不給上界 | [04 §4.4](04-threat-to-testcase.md#44-機率型測試的次數與上界) | 機率報告啟用之前 | 設計已補齊；trial 紀錄欄位與統計執行器未實作 |
| BL-31 | job 原子領取、租約與 fencing token（在 Z3、Sandbox、Gateway 出口強制）、結果不明時不自動重送 | [03 §5.8](03-system-architecture.md#58-節點邊界規則) | MVP-0 派送之前；Z3 出口在 MVP-1 之前 | 設計已補齊；未實作 |
| BL-32 | Scope Proxy 選型前的原型關卡（U-13） | [08 §11.7](08-implementation-spec.md#117-scope-proxy-實作)、07 MVP2-X5 | MVP-2 之前 | 設計已補齊；原型未執行 |
| BL-33 | 前導實驗加入純工具組、等費用比較、獨立標註與盲測紀律 | [07 §1.2](07-roadmap.md#12-前導實驗mvp-1-之前的預設值決策-h) | 對外宣稱效益之前 | 設計已補齊；語料與人力未定 |
| BL-34 | G2 駁回後新證據的報告契約（醒目呈現、去重、不覆寫歷史、已結束 run 建 followup 草稿）；裁決仍依 R10 | [02 B6](02-methodology.md#b6-報告) | MVP-0 報告交付之前 | 設計已補齊；報告欄位與去重未實作 |
| BL-35 | `{created:}` 的執行期 ID 擷取（`id_pointer`、ID 格式限制、綁定 run／job／步驟／目標／宣告 hash）與 GraphQL document 解析 | [04 §5](04-threat-to-testcase.md#5-安全等級計算規則) | MVP-1 黑箱執行之前 | 靜態檢查已實作（`safety.created_resource_problem`、`created_path_allowed`）；執行期未實作 |

## 1. 低優先項目

| 編號 | 來源 | 檔案 | 問題 | 建議修法 | 狀態 |
|---|---|---|---|---|---|
| BL-01 | L-14 | `tools/vchlib/checks.py`、`docs/05` §4.2 | `rule_trace` 每一項的說明文字（`R2:S=0.73` 冒號後的部分）不會被檢查；說明與裁決矛盾時 validator 不報錯 | 為每條規則定義說明格式（例如 R2 必須是 `S=<分數>`），由 `adjudicate.py` 產生後比對整個字串 | 待辦 |
| BL-02 | L-19 | `docs/examples/serving/README.md`、`docs/examples/models.yaml` | gpt-oss 段落沒有 `vllm serve` 啟動指令；`usable_ctx: 128000` 仍是假設 | 依模型卡查證 context 長度並補上啟動範例；查證前維持「假設值」標記 | 待辦 |
| BL-03 | L-20 | `docs/evidence/link-check-2026-09-23.md` | 外部連結檢查只做到 2026-09-23；v0.2／v0.3 新增的 URL 尚未重查；403 的來源未逐一人工確認 | 用本輪加入的 `tools/check_external_links.py` 重跑，並把結果存成新的日期檔；403 以瀏覽器人工抽查 | 待辦 |
| BL-05 | M-G7 延伸 | docs 02／03／04／06／07／08 | 保留期限（03、06 §2.2、08 §7.5）、簽章（03 §6.1、06 §1.6）、稽核 tail（03 §13、06 §1.7、08 §7.4）、OWASP LLM Top 10 版本（02 B2 與 04 §2.3）、promptfoo 的用法與限制（03 §7.5、04、06 §2.3、07 §3）仍在多處描述 | 各主題指定一個主頁，其他地方改為一句話加連結 | 待辦 |
| BL-06 | H-E9 限制 | `docs/03` §6.1、`docs/06` §3 | 簽署時間由簽署者自填，沒有可信的時間來源 | 評估 RFC 3161 時間戳記服務或以 WORM 稽核錨點的時間為準；需要先決定 U-04 | 延後（依 U-04） |

## 2. 延後的設計項目

| 編號 | 來源 | 內容 | 延後理由 | 狀態 |
|---|---|---|---|---|
| BL-10 | H-E15 | adaptive（LLM 產生下一輪）的多輪 relay | 本輪改以 G4 核准的腳本式多輪為預設，adaptive 只在 Full 模式允許；adaptive 的評估方法與上限需要 M5 的實測資料 | 延後（M5 之後） |
| BL-11 | H-E11 | 校準語料的實際建立與標註 | 需要 U-10（標註人員與預算）；在那之前所有裁決標示 `provisional` | 延後（依 U-10） |
| BL-12 | H-A1 | `high_precision_rules` 的實際內容 | 需要校準語料；在那之前白名單為空，SARIF 只算弱訊號 | 延後（依 BL-11） |

## 3. 規格已寫、schema 尚未涵蓋的欄位

[08 §11](08-implementation-spec.md#11-元件規格補充v03) 的元件規格提到、但 schema 原本沒有的欄位，v0.5 已全部補上（BL-13～BL-20、BL-27，見 §5）。之後若再發現，依同樣方式列在這裡。

## 4. 第六輪（2026-10-25 審查）留下的實作項目

第 0～5 組、追加組與 §4.3 處理時，validator 能檢查的部分都已實作；下列是只有規格、參考實作或文件說明的部分，以及處理時記下的限制。

| 編號 | 來源 | 工作 | 規格 | 時點 | 狀態 |
|---|---|---|---|---|---|
| BL-36 | T-9 | Z3 副簽前重算上一個錨點後的鏈，並核對 Z3 自己產生的事件（`tool_invocation_*`、`sandbox_job_*`、所有權結果）與 job 帳本；三種 z3 簽章各自的 domain tag（錨點已定為 `vibecheck/audit_anchor/v2`，所有權結果與 job 帳本另訂） | [03 §13.1](03-system-architecture.md#131-稽核事件格式audit-eventschemajsonh) | Z3 Executor 實作時（MVP-0 派送之前） | validator 已驗 v2 副簽；Z3 端未實作 |
| BL-37 | T-8 | Audit Writer 寫入端去重：重複的 `idempotency_key` 不寫新行，回傳原本那一行的 `seq` | [03 §5.8](03-system-architecture.md#58-節點邊界規則)、[08 §6.3](08-implementation-spec.md#63-冪等鍵) | Audit Writer 實作時 | validator 已把重複當錯誤；寫入端未實作 |
| BL-38 | H-6、§4.3 | Scope Proxy 實作物件綁定與白名單比對，並與參考實作做 parity 測試：`safety.request_binding_problem`、`server_action_problem`、`allowlist_match` | [08 §11.7](08-implementation-spec.md#117-scope-proxy-實作) | MVP-1 黑箱執行之前（與 BL-32 同時） | 參考實作與單元測試已有；Proxy 未實作 |
| BL-39 | M-1 | DB 目標的 `db_comment` 所有權驗證：Z3 以唯讀 oracle 憑證讀出 `COMMENT ON DATABASE` 中的 token，結果由 z3_executor 簽署 | [02 B0](02-methodology.md#b0-roe-與範圍g0b機器可驗證)、[06 §3 #18](06-security-legal-limitations.md#3-做不到不承諾的事) | MVP-1 之前 | validator 已檢查方法；Z3 端未實作 |
| BL-41 | M-6 | G4 佇列上限的排序與「超出 G4 上限 → `MANUAL`」：B3 依序裁切，報告列出被裁掉的測試案例 | [02 B3](02-methodology.md#b3-威脅--需求--測試案例) | M4 之前 | `gate_queues.g4_max_items` 已加；裁切與報告欄位未實作，validator 未檢查 |
| BL-42 | V-8 | `facets.CWE_BUCKETS`（CWE→桶的 curated 對照）與校準的桶定義對齊；對不到時目前只發 `W-CLUSTER-BUCKET` | [05 §3](05-bias-calibration.md#3-設計規則)、`tools/vchlib/facets.py` | 校準語料建立時（依 BL-11） | 最小對照表已有 |
| BL-43 | §4.3 | 撤銷金鑰時自動調高 `key_registry.min_version`（`vibecheck keys rotate`），避免撤銷前的舊登錄仍被接受 | [03 §6.1](03-system-architecture.md#61-金鑰登錄與驗章流程) | M1 | 限制已寫入文件；未實作 |
| BL-44 | §4.3 | W2 quorum 的執行期紀錄：目前沒有欄位，只能由 `missing_vote` 事件推得哪些切片 quorum 不足 | [05 §3](05-bias-calibration.md#3-設計規則) | M2 | 文件已寫明；未實作 |
| BL-45 | §4.3 | `report_only` 叢集拉回 G3 的紀錄方式：拉回時新增的種子威脅沒有欄位標示「由 G3 審查者拉回」 | [02 W5](02-methodology.md#w5-白箱報告dfd種子威脅) | M3 | 機制已寫入文件；schema 未加欄位 |
| BL-46 | 第 5 組 | 以網路執行 `tools/check_platform_suffixes.py`（比對 Public Suffix List），與 BL-03 的外部連結檢查一起定期重跑 | [08 §11.9](08-implementation-spec.md#119-共享平台網域的所有權證明) | 每個版本發佈前 | 未執行（需要網路） |
| BL-47 | §4.3 | 範例 `invariants.yaml` 補上範例 B′ 需要的存取矩陣列（工作區文件：同工作區成員可讀、只有上傳者可改），並重新簽核 G1 範例 | [04 §6.3](04-threat-to-testcase.md#63-範例-b第三方文件的間接注入v04-第五輪) | 下次調整範例時 | 範例已註明缺這一列 |

## 5. 已完成（保留編號供追溯）

| 編號 | 原本的問題 | 處理 |
|---|---|---|
| BL-14 | engagement 沒有每家族的 USD 上限 | v0.5 已處理：engagement `budgets.families`（`E-ENG-BUDGET`；[08 §11.12](08-implementation-spec.md#1112-成本模型與價格)） |
| BL-16 | toolkit 沒有 B1 爬行預設區塊 | v0.5 已處理：toolkit `b1_crawl`（schema 限定 S0 方法、不送表單、同 origin、上限；`E-TOOLKIT-B1` 基本關鍵字；[08 §11.7](08-implementation-spec.md#117-scope-proxy-實作)） |
| BL-17 | engagement 沒有 PR／issue 發布的開關與權杖範圍 | v0.5 已處理：engagement `publishing`（預設關閉；開啟需平台與最小權限範圍，`E-ENG-PUBLISH`；[08 §11.16](08-implementation-spec.md#1116-sarif-輸出與報告回饋)） |
| BL-18 | 誤報回饋紀錄沒有 schema | v0.5 已處理：`feedback.schema.json`（簽署、指紋、標籤與 SARIF suppression，`E-FEEDBACK`；範例 FB-001） |
| BL-19 | inventory 沒有排程工作的 kind | v0.5 已處理：inventory `kind: scheduled`（method null、`schedule:`／`queue:` 路徑，`E-INVENTORY`；範例的排程工作） |
| BL-20 | report-manifest 沒有存取矩陣與 entry point 的覆蓋率 | v0.5 已處理：testcase／w4-testcase 的 `access_cells`（`E-TC-ACCESS-CELL`）與 metrics 的三個覆蓋率（`E-REPORT-METRICS`） |
| BL-40 | seed manifest 不能登記外洩類 oracle 要比對的結構化欄位 | v0.5 已處理：seed `sensitive_fields` 與參考比對 `safety.sensitive_leaks`（NFKC、摺疊、去分隔、數字序列；`E-SEED-SENSITIVE`；[04 §4.3](04-threat-to-testcase.md#43-binding-表)） |
| BL-27 | `testcase.schema.json` 只描述黑箱測試；W4 測試案例只記在 run manifest 與 CAS，W4 結果只能借用黑箱測試案例 | v0.5 已處理：`w4-testcase.schema.json`（unit／property／local_rls／fake_model、Z2 環境、對照、oracle 引用的 G1 條目；`E-W4-TC`）；W4 結果以 `testcase_id` 指向它、`target_ids` 為空（`E-RESULT-TARGETS`）。範例：K-015 的本地 RLS 測試 WTC-015-01 → V-015-2（R1 `CONFIRMED_EXECUTABLE`；[02 W4](02-methodology.md#w4-白箱測試oracle-只取自-g1-規格)） |
| BL-04 | G4／G5 的職責分離只在同一個 run 內檢查；G5 沒有指回核准它的 G4 | v0.5 已處理：G5 的 `g4_gate_record_id` 指向本 run 中該測試案例最新且 accept 的 G4，G4 與 G5 的實際核准者不能重疊（`E-G5-G4`；[03 §6.3](03-system-architecture.md#63-核准者來源與逐項核准)）；G4／G5 每個 run 重新核准 |
| BL-13 | `cluster.schema` 無法表示純工具叢集；`run.schema` 沒有 ToolResult 清單的參照 | v0.5 已處理：叢集 `origin: tool_only` 與 `tool_report_refs`（回報不算佐證，`E-CLUSTER-ORIGIN`、`E-SARIF-REF`）；run 的 `tool_results_ref` 由 W1 稽核事件導出（`E-DERIVED`；[08 §11.2](08-implementation-spec.md#112-工具結果正規化與合併)） |
| BL-21 | 跨 run 沿用 G1／G3 核准沒有記錄來源，validator 不檢查 | v0.5 已處理並重新啟用：`decisions[].carried_from`；validator 核對祖先 run、同項目同 hash、來源簽章與角色、G3 的 ROE（`E-GATE-CARRY`；[02 §1.6](02-methodology.md#16-執行種類與後續執行)） |
| BL-22 | `config_refs` 無法表示「尚未產生」 | v0.5 已處理：`{state: pending, expected_node}` 與 `{state: not_applicable, reason}`，validator 依 run 已到達的節點檢查（`E-RUN-CONFIG`；[08 §11.13](08-implementation-spec.md#1113-run-manifest-與-prompt-範本登錄)） |
| BL-23 | 只做白箱的 Lane B run 也必須參照 `seed_manifest` | v0.5 已處理：沒有 B 階段內容的 run 可以把 `seed_manifest` 標為 not_applicable（同 BL-22） |
| BL-15 | ROE `targets[]` 的 CDN 邊緣 IP 範圍欄位 | v0.4 已處理：ROE `targets[].edge_ip_ranges`（`E-ROE-EDGE-RANGE`）、`safety.ip_in_ranges`（[08 §11.7](08-implementation-spec.md#117-scope-proxy-實作)） |
| BL-24 | 種子綁定只看路徑；GraphQL mutation 的物件 ID 在 variables 裡，無法綁定 | v0.4 已處理：見 [04 §5](04-threat-to-testcase.md#5-安全等級計算規則)（`object_refs`＋Scope Proxy 的 body ID 綁定）；v0.5 補強 query 字串、ID 鍵下的陣列與物件、整表寫入與 Server Action（審查 2026-10-25 H-6；執行期見 BL-38） |
| BL-25 | 沒有方式宣告「唯讀的 POST 端點」（例如 Supabase RPC 的查詢函式） | v0.4 已處理：見 [04 §5](04-threat-to-testcase.md#5-安全等級計算規則)（seed manifest `read_only_endpoints`） |
| BL-26 | `toolkit.yaml` 沒有 G2／G3 佇列上限與逾時比例告警門檻的欄位；run／report-manifest 沒有「超出上限」「只列報告」清單的欄位 | v0.4 已處理：`toolkit.yaml` `gate_queues`；report-manifest `over_cap_items`、`report_only_clusters`（`E-REPORT-QUEUE`）；v0.5 另加 G4 上限（`g4_max_items`，見 BL-41）與 G3 的 `over_cap` 決定 |
