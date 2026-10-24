# 09 待辦清單（低優先與延後項目）

> **2026-10-24 設計審查**中本輪（v0.4）沒有處理的項目，列在該審查紀錄的 [§5](evidence/review-2026-10-24.md#5-本輪沒有處理的項目)，尚未編入下表。
>
> 本清單收錄 [2026-09-26 深度審查](evidence/review-2026-09-26.md) 中**本輪沒有修正**的項目：低優先（L）項目，以及刻意延後、需要更多資訊才能處理的部分。高、中優先項目本輪都已處理，或在此寫明延後的理由。
>
> - **需要使用者決定的事項**（金鑰、GPU、法務關卡、保留期限等）不在這裡，見 [08 §10](08-implementation-spec.md#10-尚未決定需使用者決定)。
> - **狀態**：`待辦`＝尚未處理；`延後`＝有意留到之後的里程碑。

## 1. 低優先項目

| 編號 | 來源 | 檔案 | 問題 | 建議修法 | 狀態 |
|---|---|---|---|---|---|
| BL-01 | L-14 | `tools/vchlib/checks.py`、`docs/05` §4.2 | `rule_trace` 每一項的說明文字（`R2:S=0.73` 冒號後的部分）不會被檢查；說明與裁決矛盾時 validator 不報錯 | 為每條規則定義說明格式（例如 R2 必須是 `S=<分數>`），由 `adjudicate.py` 產生後比對整個字串 | 待辦 |
| BL-02 | L-19 | `docs/examples/serving/README.md`、`docs/examples/models.yaml` | gpt-oss 段落沒有 `vllm serve` 啟動指令；`usable_ctx: 128000` 仍是假設 | 依模型卡查證 context 長度並補上啟動範例；查證前維持「假設值」標記 | 待辦 |
| BL-03 | L-20 | `docs/evidence/link-check-2026-09-23.md` | 外部連結檢查只做到 2026-09-23；v0.2／v0.3 新增的 URL 尚未重查；403 的來源未逐一人工確認 | 用本輪加入的 `tools/check_external_links.py` 重跑，並把結果存成新的日期檔；403 以瀏覽器人工抽查 | 待辦 |
| BL-04 | H-D1 延伸 | `tools/vchlib/checks.py`、`gate-record.schema.json` | G4／G5 的職責分離只在同一個 run 內檢查；跟進 run 沿用前一個 run 的 G4 時，沒有 `g4_gate_record_id` 的跨 run 連結 | G5 紀錄加上 `g4_gate_record_id`，validator 跨 run 解析 | 待辦 |
| BL-05 | M-G7 延伸 | docs 02／03／04／06／07／08 | 保留期限（03、06 §2.2、08 §7.5）、簽章（03 §6.1、06 §1.6）、稽核 tail（03 §13、06 §1.7、08 §7.4）、OWASP LLM Top 10 版本（02 B2 與 04 §2.3）、promptfoo 的用法與限制（03 §7.5、04、06 §2.3、07 §3）仍在多處描述 | 各主題指定一個主頁，其他地方改為一句話加連結 | 待辦 |
| BL-06 | H-E9 限制 | `docs/03` §6.1、`docs/06` §3 | 簽署時間由簽署者自填，沒有可信的時間來源 | 評估 RFC 3161 時間戳記服務或以 WORM 稽核錨點的時間為準；需要先決定 U-04 | 延後（依 U-04） |
| BL-21 | H-B5 延伸 | `gate-record.schema.json`、`tools/vchlib/checks.py` | 跨 run 沿用 G1／G3 核准（未變更的項目）只是設計規則：`decisions[]` 沒有欄位標示「沿用自哪一份紀錄」，validator 也不檢查跨 run 的沿用 | `decisions[]` 加上 `carried_from`（前一個 run 的 gate record ID 與項目 hash），validator 核對 hash 相同、ROE 相同且在效期內；G4／G5 永遠不沿用 | 待辦 |
| BL-22 | N-5 延伸 | `run.schema.json` | run manifest 的 `config_refs` 六個鍵都必填；G1 之前（還沒有 `invariants`）或 G0b 之前（還沒有 `seed_manifest`）的 run 紀錄無法表示「尚未產生」 | 允許 `null` 並記錄產生的節點；validator 依 run 已到達的節點檢查 | 待辦 |
| BL-23 | N-5 延伸 | `tools/vchlib/checks.py` | 只做白箱的 Lane B run 也必須有 `seed_manifest` 參照（目前只有 Lane A 可為 `null`） | 沒有 B 階段的 run 允許 `seed_manifest: null` | 待辦 |

## 2. 延後的設計項目

| 編號 | 來源 | 內容 | 延後理由 | 狀態 |
|---|---|---|---|---|
| BL-10 | H-E15 | adaptive（LLM 產生下一輪）的多輪 relay | 本輪改以 G4 核准的腳本式多輪為預設，adaptive 只在 Full 模式允許；adaptive 的評估方法與上限需要 M5 的實測資料 | 延後（M5 之後） |
| BL-11 | H-E11 | 校準語料的實際建立與標註 | 需要 U-10（標註人員與預算）；在那之前所有裁決標示 `provisional` | 延後（依 U-10） |
| BL-12 | H-A1 | `high_precision_rules` 的實際內容 | 需要校準語料；在那之前白名單為空，SARIF 只算弱訊號 | 延後（依 BL-11） |

## 3. 規格已寫、schema 尚未涵蓋的欄位

[08 §11](08-implementation-spec.md#11-元件規格補充v03) 的元件規格提到下列欄位，但 v0.3 的 schema 與 validator 還沒有對應；實作對應元件時一併補上 schema、範例與正反向測試。

| 編號 | 用在 | 缺少的欄位或檔案 | 暫行做法 | 狀態 |
|---|---|---|---|---|
| BL-13 | [08 §11.2](08-implementation-spec.md#112-工具結果正規化與合併) 純工具叢集 | `cluster.schema` 沒有表示「只有工具結果、沒有 LLM 成員」的方式（例如新的 `origin` 值）；`run.schema` 也沒有 ToolResult 清單的參照（`tool_results_ref`） | 純工具叢集只在設計中描述；範例不含 | 待辦 |
| BL-14 | [08 §11.12](08-implementation-spec.md#1112-成本模型與價格) 各家族上限 | engagement 的每家族 USD 上限欄位 | 只用現有的每 run／階段上限 | 待辦 |
| BL-15 | [08 §11.7](08-implementation-spec.md#117-scope-proxy-實作) CDN | ROE `targets[]` 的 CDN 邊緣 IP 範圍欄位 | 目標若經 CDN，DNS 固定到第一次解析的位址；解析結果改變就停止該 job | 待辦 |
| BL-16 | [08 §11.7](08-implementation-spec.md#117-scope-proxy-實作) B1 爬行預設 | `toolkit.yaml` 的 B1 爬行預設區塊（方法、排除樣式、請求上限） | 規則寫在程式碼常數，並記入 run manifest | 待辦 |
| BL-17 | [08 §11.16](08-implementation-spec.md#1116-sarif-輸出與報告回饋) 回貼 PR／issue | engagement 啟用發佈的欄位與權杖範圍宣告 | 預設不發佈；報告只輸出檔案 | 待辦 |
| BL-18 | [08 §11.16](08-implementation-spec.md#1116-sarif-輸出與報告回饋) 誤報回饋 | 回饋紀錄的 schema | 回饋先以人工整理進校準語料 | 待辦 |
| BL-19 | [08 §11.1](08-implementation-spec.md#111-w0-盤點抽取器與支援矩陣) 排程工作 | inventory `endpoints[].kind` 沒有排程工作（cron／job）的值 | 排程工作記為 `blind_spots`（`other`） | 待辦 |
| BL-20 | [02 W5](02-methodology.md#w5-白箱報告dfd種子威脅) 覆蓋指標 | report-manifest `metrics` 只有結果數、INVALID 數與對照通過率；沒有存取矩陣格與 entry point 的覆蓋率 | 覆蓋率先寫在報告正文 | 待辦 |
| BL-24 | [04 §5](04-threat-to-testcase.md#5-安全等級計算規則) GraphQL mutation | 種子綁定只看路徑；GraphQL mutation 的物件 ID 在 variables 裡，無法綁定 | 送到固定 `/graphql` 端點的 mutation 一律 S3，除非該端點列為 create-only（保守，會漏測） | 待辦 |
| BL-25 | [04 §4.3](04-threat-to-testcase.md#43-binding-表) BaaS RPC | 沒有方式宣告「唯讀的 POST 端點」（例如 Supabase RPC 的查詢函式） | 非 GraphQL 的 POST 一律視為寫入：未列為 create-only 就是 S3（保守，會漏測） | 待辦 |
