# 09 待辦清單（實作前置、低優先與延後項目）

> v0.4（2026-10-24）重新評估優先級。下列契約已在文件補齊，但 schema、validator、範例與執行期尚未實作；不得把「設計已補齊」視為功能完成。原始項目追溯至 [2026-09-26 審查](evidence/review-2026-09-26.md)，使用者待決事項仍見 [08 §10](08-implementation-spec.md#10-尚未決定需使用者決定)。

## v0.5 狀態與門檻

| 編號 | 工作 | 狀態與時點 |
|---|---|---|
| BL-30 | GraphQL 方法相容性、created_resource 宣告與資源路徑綁定 | 最小分類器／validator／回歸測試已補；真實 GraphQL 內容解析與 ID 擷取仍未實作，黑箱啟用前須完成 |
| BL-31 | 還原範圍跨 job／run 排他權與外部寫入隔離 | 設計已補，尚未實作；任何快照還原工作流啟用前 |
| BL-32 | CAS 委任隔離與多參照保留政策 | 設計已補，尚未實作；CAS 實作前 |
| BL-33 | 取樣與重播分離、實際呼叫證據、快取／無效樣本排除 | 設計已補，尚未實作；機率報告啟用前 |
| BL-34 | W0 → W0.5／認領與 G1 → W1 的順序統一 | 文件已同步；Lane A 保留獨立流程 |

完整契約見 [08 §13](08-implementation-spec.md#13-v05-安全分類與執行邊界)。下方 v0.4 前置工作仍未因本輪完成；`05-v0.3` 裁決規則版本不變。

## 0. 實作前置項目

| 編號 | 優先級與時點 | 修正契約與驗收 | 狀態 |
|---|---|---|---|
| BL-22／BL-23 | 高；MVP-0 前 | Run 區分尚未產生、不適用、已產生及遺失；純白箱不要求種子清單；按完成節點拒絕缺產物 resume，見 08 §12.1 | 設計已補齊；schema／validator 待實作 |
| BL-13 | 高；MVP-0 前 | ToolResult 參照、零 LLM 成員叢集及工具至報告的完整路徑，見 08 §12.3 | 設計已補齊；schema／validator／報告待實作 |
| BL-21 | 高；啟用跨 run 沿用前 | G1／G3 沿用目前停用；來源鏈、hash、簽章、範圍、效期及撤銷驗證完成後才啟用，見 03 §6.3 | 設計已補齊；來源欄位與驗證待實作 |
| BL-04 | 高；S2 前 | 取消「沿用上次 G4」前提；G4／G5 每次重新核准，G5 明確連至本 run 當前有效 G4 並驗證職責分離，見 03 §6.3 | 設計已釐清；明確關聯與測試待實作 |
| BL-26 | 高；MVP-0 派送前，黑箱出口在 MVP-1 前 | 原子領取、租約與 fencing、結果不明及費用核對，逐點崩潰與雙 worker 驗收，見 08 §12.2、§12.5 | 設計已補齊；執行期待實作 |
| BL-27 | 高；staging MVP-2 前 | Scope Proxy 相容性原型與異常請求、出口繞過、在途請求驗收，見 08 §12.4 | 設計已補齊；原型未執行、U-13 待選型 |
| BL-28 | 高；MVP-0 報告交付前 | G2 駁回後的新 E_proof 重新送審、去重與醒目報告，見 05 §4.2 | 設計已補齊；現有 R10／報告待實作 |
| BL-29 | 中；效果宣稱前 | 盲測的純工具、單模型、多家族等成本比較，見 05 §7 | 設計已補齊；語料、人力及實驗待完成 |

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

[08 §11](08-implementation-spec.md#11-元件規格補充v03) 的元件規格提到下列欄位，但 v0.3 的 schema 與 validator 還沒有對應；實作對應元件時一併補上 schema、範例與正反向測試。

| 編號 | 用在 | 缺少的欄位或檔案 | 暫行做法 | 狀態 |
|---|---|---|---|---|
| BL-14 | [08 §11.12](08-implementation-spec.md#1112-成本模型與價格) 各家族上限 | engagement 的每家族 USD 上限欄位 | 只用現有的每 run／階段上限 | 待辦 |
| BL-15 | [08 §11.7](08-implementation-spec.md#117-scope-proxy-實作) CDN | ROE `targets[]` 的 CDN 邊緣 IP 範圍欄位 | 目標若經 CDN，DNS 固定到第一次解析的位址；解析結果改變就停止該 job | 待辦 |
| BL-16 | [08 §11.7](08-implementation-spec.md#117-scope-proxy-實作) B1 爬行預設 | `toolkit.yaml` 的 B1 爬行預設區塊（方法、排除樣式、請求上限） | 規則寫在程式碼常數，並記入 run manifest | 待辦 |
| BL-17 | [08 §11.16](08-implementation-spec.md#1116-sarif-輸出與報告回饋) 回貼 PR／issue | engagement 啟用發佈的欄位與權杖範圍宣告 | 預設不發佈；報告只輸出檔案 | 待辦 |
| BL-18 | [08 §11.16](08-implementation-spec.md#1116-sarif-輸出與報告回饋) 誤報回饋 | 回饋紀錄的 schema | 回饋先以人工整理進校準語料 | 待辦 |
| BL-19 | [08 §11.1](08-implementation-spec.md#111-w0-盤點抽取器與支援矩陣) 排程工作 | inventory `endpoints[].kind` 沒有排程工作（cron／job）的值 | 排程工作記為 `blind_spots`（`other`） | 待辦 |
| BL-20 | [02 W5](02-methodology.md#w5-白箱報告dfd種子威脅) 覆蓋指標 | report-manifest `metrics` 只有結果數、INVALID 數與對照通過率；沒有存取矩陣格與 entry point 的覆蓋率 | 覆蓋率先寫在報告正文 | 待辦 |
| BL-24 | [04 §5](04-threat-to-testcase.md#5-安全等級計算規則) GraphQL mutation | 種子綁定只看路徑；GraphQL mutation 的物件 ID 在 variables 裡，無法綁定 | 送到固定 `/graphql` 端點的 mutation 一律 S3，除非該端點列為 create-only（保守，會漏測） | 待辦 |
| BL-25 | [04 §4.3](04-threat-to-testcase.md#43-binding-表) BaaS RPC | 沒有方式宣告「唯讀的 POST 端點」（例如 Supabase RPC 的查詢函式） | 非 GraphQL 的 POST 一律視為寫入：未列為 create-only 就是 S3（保守，會漏測） | 待辦 |
