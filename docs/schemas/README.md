# 資料模型（JSON Schema 2020-12，v0.2）

這裡的 schema 是**存檔與交換用**的完整版本。送給 LLM 的「輸出用 schema」由程式自動**降級**為跨廠商的最小公約數：去除數值與長度限制、`pattern`、`format`、`multipleOf`、`$ref`；所有物件設 `additionalProperties: false` 並把所有欄位列為 required；`minItems` 最大為 1。LLM 輸出取得後，再以這裡的完整 schema 驗證（見 [03 §8.3](../03-system-architecture.md#83-結構化輸出跨廠商最小公約數)）。降級程式在 [tools/vchlib/llm_schema.py](../../tools/vchlib/llm_schema.py)，目前套用在 finding、threat、testcase、commander-plan。

每個 schema 的 `$id` 等於檔名；跨檔引用只用 `common.schema.json#/$defs/...`。

## Schema 與範例

| Schema | 用途 | 範例 |
|---|---|---|
| [common](common.schema.json) | 共用定義（sha256、datetime、person_ref、signature、data_class、tool_mode、window…） | （只被引用） |
| [toolkit-config](toolkit-config.schema.json) | 工具包設定：根金鑰釘選、逾時上限、保存期限、自動化帳號 | [toolkit.yaml](../examples/toolkit.yaml) |
| [key-registry](key-registry.schema.json) | 金鑰登錄（唯一的公鑰來源） | [key-registry.yaml](../examples/key-registry.yaml) |
| [tool-registry](tool-registry.schema.json) | 工具與 `tool:mode`（D13） | [tools.yaml](../examples/tools.yaml) |
| [licenses](licenses.schema.json) | 元件授權登錄 | [licenses.yaml](../examples/licenses.yaml) |
| [engagement](engagement.schema.json) | 委任設定（G0a） | [engagement.yaml](../examples/engagement.yaml) |
| [roe](roe.schema.json) | 交戰規則（G0b），含 legal_review | [roe.yaml](../examples/roe.yaml) |
| [model-registry](model-registry.schema.json) | 模型登錄 | [models.yaml](../examples/models.yaml) |
| [agent-registry](agent-registry.schema.json) | 代理登錄 | [agents.yaml](../examples/agents.yaml) |
| [seed-manifest](seed-manifest.schema.json) | 種子資料與 oracle 查詢 | [seed-manifest.yaml](../examples/seed-manifest.yaml) |
| [invariants](invariants.schema.json) | G1 安全不變量與基準需求 | [invariants.yaml](../examples/invariants.yaml) |
| [crosswalk](crosswalk.schema.json) | 分類對照表 | [crosswalk.yaml](../examples/crosswalk.yaml) |
| [calibration](calibration.schema.json) | 校準設定與結果（D15） | [calibration.yaml](../examples/calibration.yaml) |
| [run](run.schema.json) | run 狀態、jobs、關卡清單 | [主 run](examples/run.example.json)、[後續 run](examples/run.followup.example.json)、[Lane A](examples/run.lane-a.example.json) |
| [gate-record](gate-record.schema.json) | 關卡紀錄 | [G0a](examples/gate-record.g0a.example.json)、[G0b](examples/gate-record.g0b.example.json)、[G1](examples/gate-record.g1.example.json)、[G2](examples/gate-record.g2.example.json)、[G3](examples/gate-record.g3.example.json)、[G4](examples/gate-record.g4.example.json)、[G5](examples/gate-record.g5.example.json)、[GB](examples/gate-record.gb.example.json)、[後續 G0a](examples/gate-record.followup.g0a.example.json)、[後續 G0b](examples/gate-record.followup.g0b.example.json)、[Lane A G0a](examples/gate-record.lane-a.g0a.example.json) |
| [audit-event](audit-event.schema.json) | 稽核事件（JSONL，一行一筆） | [audit-event.run-2026-09-23-001.example.jsonl](examples/audit-event.run-2026-09-23-001.example.jsonl)、[audit-event.run-2026-09-25-pr-118.example.jsonl](examples/audit-event.run-2026-09-25-pr-118.example.jsonl)（Lane A） |
| [inventory](inventory.schema.json) | W0 盤點 | [inventory.example.json](examples/inventory.example.json) |
| [redaction-map](redaction-map.schema.json) | secrets 遮罩對照 | [redaction-map.example.json](examples/redaction-map.example.json) |
| [slice](slice.schema.json) | 切片 | [slice.example.json](examples/slice.example.json)、[Lane A](examples/slice.lane-a.example.json) |
| [finding](finding.schema.json) | 發現項（含程式證據） | [F-001](examples/finding.example.json)、[F-021](examples/finding.f-021.example.json)、[F-044](examples/finding.f-044.example.json)、[F-052](examples/finding.f-052.example.json)、[F-101](examples/finding.f-101.example.json) |
| [cluster](cluster.schema.json) | 叢集鍵、成員、家族 | [K-005](examples/cluster.example.json)、[K-011](examples/cluster.k-011.example.json)、[K-014](examples/cluster.k-014.example.json)（SARIF 佐證）、[K-101](examples/cluster.k-101.example.json) |
| [verdict](verdict.schema.json) | 驗證票、裁決狀態、rule_trace | [V-005-1](examples/verdict.example.json)、[V-005-2](examples/verdict.executable.example.json)、[V-011-1](examples/verdict.k-011-w3.example.json)、[V-011-2](examples/verdict.k-011-b5.example.json)、[V-014-1](examples/verdict.k-014-w3.example.json)（CONFIRMED_CORROBORATED）、[V-101-1](examples/verdict.lane-a.example.json) |
| [dfd](dfd.schema.json) | 資料流程圖（外部觀點／合併觀點） | [external](examples/dfd.external.example.json)、[merged](examples/dfd.merged.example.json) |
| [threat](threat.schema.json) | 威脅、分類版本、簽核、對照連結 | [T-005](examples/threat.example.json)、[T-019](examples/threat.t-019.example.json)、[T-027](examples/threat.t-027.example.json)、[T-031](examples/threat.t-031.example.json) |
| [seed-threats](seed-threats.schema.json) | W3→B1 種子威脅 | [seed-threats.example.json](examples/seed-threats.example.json) |
| [requirement](requirement.schema.json) | ASVS／AISVS 需求與 G1 安全不變量 | [asvs](examples/requirement.asvs.example.json)、[invariant](examples/requirement.invariant.example.json)、[invariant-llm](examples/requirement.invariant-llm.example.json) |
| [commander-plan](commander-plan.schema.json) | 指揮官計畫與後續草稿 | [CMD-4](examples/commander-plan.example.json)、[CMD-5](examples/commander-plan.cmd5.example.json) |
| [testcase](testcase.schema.json) | 測試案例 | [IDOR（S1）](examples/testcase.idor.example.json)、[LLM（S1）](examples/testcase.llm.example.json)、[ZAP active（S2）](examples/testcase.zap-active.example.json) |
| [testresult](testresult.schema.json) | 測試結果 | [IDOR](examples/testresult.example.json)、[LLM](examples/testresult.llm-pass.example.json)、[ZAP](examples/testresult.zap-active.example.json) |
| [report-manifest](report-manifest.schema.json) | 報告清單與雜湊 | [report-manifest.example.json](examples/report-manifest.example.json) |
| [selftest-report](selftest-report.schema.json) | 工具包自測結果 | [selftest-report.m1.example.json](examples/selftest-report.m1.example.json) |
| [checkpoint-metadata](checkpoint-metadata.schema.json) | checkpoint 中繼資料 | [checkpoint-metadata.followup.example.json](examples/checkpoint-metadata.followup.example.json) |

## 驗證

```bash
python -m pip install -r requirements.txt      # 或 python -m pip install --user -r requirements.txt
python tools/validate_schemas.py               # 最後一行應為 "all checks passed (...)"
python -m pytest -q tests                      # 負向測試：每個竄改都要被對應的錯誤碼抓到
python tools/validate_schemas.py --real-run    # 正式執行前：可達的佔位模型 ID 變成錯誤（目前範例會失敗：gpt_flagship）
```

`tools/validate_schemas.py` 只是入口；檢查都在 [tools/vchlib](../../tools/vchlib/)。CI（`.github/workflows/validate.yml`）在 ubuntu 與 windows 上跑上面兩個命令與 `tools/check_doc_links.py`。

**Windows 注意事項**
- 需要 `tzdata` 套件：Windows 沒有系統時區資料庫，`zoneinfo.ZoneInfo("Asia/Taipei")` 會失敗（已列在 requirements.txt）。
- 主控台是 cp950 時，中文輸出可能亂碼或 `UnicodeEncodeError`。驗證程式會把 stdout 改成 UTF-8；其他工具請設 `PYTHONUTF8=1`（或 `PYTHONIOENCODING=utf-8`）。
- 所有檔案以 UTF-8 讀寫；repo 的 `.gitattributes`（`* text=auto eol=lf`）讓簽出一律是 LF。若仍遇到 CRLF 的 `.jsonl`，雜湊鏈以去掉行尾 `\r` 的行計算（`bundle.read_jsonl_lines`）。
- JSON／JSONL 以嚴格模式載入（`vchlib/jsonstrict.py`）：重複鍵、NaN／Infinity、溢位成無限大的浮點數（如 `1e400`）、絕對值超過 2^53 的整數一律拒絕（`E-JSON-STRICT`），該文件連同其上的簽章或雜湊鏈都不採信，語意與嚴格 YAML 相同。`3e0` 之類的浮點數不會被當成整數：schema 的 `integer` 只接受真正的整數（布林值與 `3.0` 都不算），`seq` 等欄位寫成浮點數 → `E-SCHEMA`（稽核 seq 另有 `E-AUDIT-SEQ`）。
- 稽核日誌被嚴格載入器拒絕時，只回報那一個 `E-JSON-STRICT`：該 run 的稽核檢查（`E-AUDIT-*`）與依賴稽核日誌的 `E-RUN-RESTORE-DRILL` 都不再連帶報錯。

### 檢查項目（21 組）

1. **schema 與範例**：每個 schema 是合法 2020-12、`$id`＝檔名；每個範例（含 `docs/examples/*.yaml`）通過 schema，`date-time` 必須帶時區；除 `common` 外每個 schema 都有範例；YAML 以嚴格載入器讀取（重複鍵、anchor、tag → `E-YAML-STRICT`）；無對應 schema 的 YAML → `E-KIND`。
2. **RFC 8785 JCS**：自寫的 `canonical.jcs` 對 RFC 8785 測試向量，並對每份文件與參考套件 `rfc8785==0.1.4` 比對。
3. **衍生值**：片段 hash、關卡項目 hash、artifact hash、報告清單 hash、票權重、分數、合格票等由 `vchlib.derive` 重算；稽核雜湊鏈由原始行重算。
4. **金鑰登錄**：根公鑰指紋＝toolkit 釘選值、根簽章有效、`version ≥ min_version`（防回滾）、`registry_id`＝toolkit `location`＝engagement／ROE `key_registry_ref`、指紋＝公鑰計算值、撤銷欄位一致、自動化帳號不得持有金鑰。
5. **Ed25519 簽章**：engagement、ROE（含 legal_review.attested_by）、G1–G5／GB 關卡紀錄、人為的 `initiator_claim`／`run_resume` 事件。公鑰只從金鑰登錄取得；`compromised` → 該金鑰全部簽章無效；其他撤銷原因 → 撤銷時間之前的簽章仍有效。G0a／G0b 是系統驗證：`signatures: []`，`verification.signer_results` 必須等於實際驗證結果。
6. **人員參照**：所有 person_id 都已登錄、不是自動化帳號，角色與金鑰相符（校準標註者是外部標註人員，不列入）。
7. **委任**：有效期間、允許模型與資料等級、逾時不超過工具包、成本上限都有值且階段 ≤ 總額、保存期限（`retention_days` 必須在 1..工具包上限之內，否則 `E-RETENTION`，是錯誤不是警告）、Lane A 模型、程式碼擁有權聲明、OWASP LLM 版本。
8. **ROE 與 L-1..L-6**：在委任期間內、時間窗與時區、目標與 db_access、拒絕清單（`tools.yaml` 的 `toolkit_denied`＝程式內建清單 ⊆ ROE `denied_modes`）、允許的工具已登錄、停止條件只能更嚴、relay 不超過工具包、資料等級與保存期限（toolkit.yaml `retention` 是組織上限；engagement `retention_days` 是有效值且不得超過上限，ROE 只能再縮短：`E-RETENTION`／`E-ROE-RETENTION`）、資料庫目標與 `db_access` 的主機不得在 `exclusions.hosts` 且必須是 ROE 的資料庫目標（`E-ROE-DB-SCOPE`；訊息以 `[binding rule]`／`[scope rule]`／`[exclusion rule]` 標出是哪一條）、http 目標的 `base_url` 必須可解析且主機不得在 `exclusions.hosts`（`E-ROE-TARGETS`）、endpoint 只接受 `host:port` 或 `[IPv6]:port`（schema pattern；無法解析 → `E-ROE-DB-SCOPE` "unparseable endpoint"，不會 `E-INTERNAL`）；比對主機前兩邊都先正規化（小寫、去掉結尾的 `.`、IDNA），`DB.X.` 與 `db.x` 視為同一主機、seed manifest，以及 docs/06 §2.1.1 的 L-1..L-6。
9. **模型與代理**：未知模型回報 `E-MODEL-UNKNOWN`（不當掉）、確定性角色 `model: null`、fallback 同家族、雲端 Nemotron 只收 P、OpenAI 模型收 C 時 `store: false`、`earliest_retirement`（委任開始前 → 錯誤，期間內 → 警告）、佔位模型 ID（`placeholder: true` → `W-MODEL-PLACEHOLDER`；litellm 含 `<...>`、`{...}`、獨立的 `TBD`／`TODO`／`FIXME`（不分大小寫）或「實作時確認」卻沒標 → `E-MODEL-PLACEHOLDER`；加 `--real-run` 時，任何代理經 `model`、`fallback_models` 或 models.yaml fallback 鏈可達的佔位模型 → `E-MODEL-PLACEHOLDER`）、reviewer 家族多樣性與跨家族 verifier、finding／票／解讀者的家族與登錄一致。
10. **關卡**：每關必要角色、登錄一致、G0b 之後的核准者來自 ROE、發起者、逾時、有效期間、G4 核准者 ∈ run.initiators、G5 核准者 ∉ run.initiators 且在同一 ROE 時間窗內決定、GB 核准者、outcome 與 decisions 一致、G3 決定寫回威脅、G1 決定寫回不變量。
11. **run**：狀態／current_node／resume_deadline、jobs、S2 需要 G5＋快照＋還原驗證＋7 天內的還原演練（稽核日誌無法載入時不重複回報 `E-RUN-RESTORE-DRILL`）、測試結果在時間窗內且在 G4／G5 之後、請求數 ≤ 上限、k ≤ n、GB 延長後的預算、Lane A 與後續 run 規則。
12. **測試案例 vs ROE**：以 docs/04 §5 演算法（`vchlib.safety`）重算安全等級、可否進入 G4、db_tables ⊆ oracle_tables、種子都在 manifest、ZAP `delayInMs`／`maxScanDurationInMins` 限制、多輪對話需要 relay、角色。
13. **裁決重算**：以 docs/05 §4.2 規則（`vchlib.adjudicate`）重算 status、status_cap、advisory、annotations 與 `rule_trace` 規則序列；`diversity_degraded` 由合格票在 agents.yaml／models.yaml 的家族推導（少於 2 個家族 → true；Lane A 為 false），`tool_corroboration` ＝ 已解析的 cluster.sarif_refs ∪ E_fail_u 測試結果（排序後以清單比對，重複項目也算不符；schema 另以 `uniqueItems` 拒絕重複），與裁決宣告值不符 → `E-VERDICT-DIVERSITY`／`E-VERDICT-TOOLCORR`，重算時只用推導值。每個 `sarif_refs` 項目必須對應到該 run 稽核日誌中一個 `tool_invocation_end` 事件的 `payload_refs`，且該事件 `payload.adapter` 是 tools.yaml 中白箱工具的 `tool:mode`（工具 zone Z2、`b4_executable: false`）、事件 zone Z2、`payload.ok: true`；否則 → `E-SARIF-REF`，該 ref 不算工具佐證（不能用自己宣稱的 ref 繞過 R8）。只有 agents.yaml 中 role 為 `verifier` 的代理可以投票；其他角色的票 → `E-VERDICT-VOTER-ROLE`，且不計入 weighted_valid、score、支持／反對與家族多樣性。
14. **追溯鏈**：finding → cluster → verdict → threat → testcase → testresult → report；requirement 範例與 invariants.yaml 一致；種子威脅、DFD 元件、G2 參照。
15. **稽核紀錄結構**：seq 是整數且連號（`3e0` 之類 → `E-AUDIT-SEQ`）、時間不倒退、每個 gate_decision 後緊接 audit_anchor、`run.audit_anchors` 的 `{seq, line_sha256}` 與日誌行一致（`E-AUDIT-ANCHOR`／`-MISMATCH`／`-TRUNCATED`），而且必須依序列出日誌中**每一個** audit_anchor 事件（漏列任何一個，包括最後一個 → `E-AUDIT-ANCHOR`，不論 run 狀態）、最後錨點之後的尾段（非終止 → `W-AUDIT-UNANCHORED-TAIL`；終止狀態的 run 必須以 `run_end` anchor 結尾，所有原因合併成**一個** `E-AUDIT-TAIL`）、每份關卡紀錄都有事件。
16. **校準**：重算 a、w、near_zero 與原因（±0.0005）、θ 可行性、arms（只有 ⑤ 探索性）、M-11 flag、κ。
17. **授權**：`tools.yaml` 的 license_ref 與 requirements.txt 的套件都在 licenses.yaml。
18. **對照表**：curated 必須有 reviewed_by、llm-suggested 不得有；OWASP 預設版本＝toolkit。
19. **LLM 輸出 schema**：降級後只用共通子集，且範例仍通過降級 schema。
20. **工具包**：自動化帳號、逾時、保存期限欄位、`tool:mode` 命名、B4 模式在 Z3。
21. **其他**：DFD 連線與 b1_diff、報告 verdict_counts（每叢集最新裁決）、自測（M1 需 ST-1／ST-3／ST-7 已執行且通過）、checkpoint。

目前範例的預期警告只有一個：`nemotron_cloud` 的 litellm 是佔位模型 ID（`W-MODEL-PLACEHOLDER`；沒有 agent 會用到，`--real-run` 也不報錯）。U-11 已把 `claude_haiku` 換成 `claude_opus_48`（最早 2027-05-28 退役，不在委任期間內 [V][E:providers-52]）；U-12 已把 `gpt_flagship` 換成 `gpt-6-sol` [V][E:providers-46]。

## 簽章與測試金鑰

- 簽章是**真的 Ed25519**，簽在 RFC 8785 JCS（去掉 `signatures`）上；稽核事件簽在去掉 `signature` 的事件上。指紋＝`ed25519:SHA256:` ＋ base64（無 padding）的 SHA-256（原始 32 位元組公鑰）[H]。
- 範例用的私鑰在 `tests/fixtures/TEST_ONLY_private_keys/*.TEST_ONLY.pem`，**是公開的測試資料，只證明驗證程式的邏輯，不代表任何真實核准**。正式部署必須用各人自己的金鑰，絕不可沿用這些檔案。
- 修改任何範例後執行 `python tools/sign_examples.py`：取代 `FP:<名稱>`／`PK:<名稱>` 佔位字串，重算所有衍生值、重簽 YAML 與關卡紀錄、重建稽核雜湊鏈，直到不再變動。

## 設計決定（其他文件參照用）

- 稽核雜湊鏈：`prev_hash` ＝ 前一行原始 UTF-8 位元組（去掉行尾）的 SHA-256；第一筆＝`sha256(run_id)`。只有人為的 `initiator_claim` 與 `run_resume` 帶簽章，其他事件 `signature: null`。`run.audit_anchors` 依序列出每個 `audit_anchor` 事件的 `{seq, line_sha256}`（該錨點那一行本身的 SHA-256，所以錨點涵蓋到自己那一行）；它是寫入端推導的值，必須與日誌中的錨點事件完全一致，漏列 → `E-AUDIT-ANCHOR`（所以「從 run 紀錄刪掉最後一個錨點」不會降級成警告）。日誌中最後一個錨點事件之後的行是未錨定尾段：非終止狀態 → `W-AUDIT-UNANCHORED-TAIL`；終止狀態（COMPLETED、COMPLETED_WITH_GAPS、ABORTED、FAILED）→ 一個 `E-AUDIT-TAIL`（列出所有原因：尾段行數、最後一筆不是 audit_anchor、最後錨點不是 run_end）；日誌比錨定的 seq 短 → `E-AUDIT-TRUNCATED`；雜湊不符 → `E-AUDIT-ANCHOR-MISMATCH`。
- 報告清單中 `audit_log` 的 sha256 ＝ `report_published` 事件的 `prev_hash`，也就是「發布報告當下之前全部紀錄」的雜湊；之後追加的事件（如 run_end anchor）不影響報告清單。
- 關卡項目 hash 用「核准視圖」：去掉 `signatures`、`review`、`signoff` 後的 JCS，讓寫回決定不會改變被核准的 hash。
- G0a／G0b 沒有人為簽章；它們記錄系統對 engagement／ROE 簽章的驗證結果。

## 限制（誠實說明）

- 這是**設計庫的範例驗證器**，不是執行期元件：它證明範例彼此一致、規則可機械檢查，不證明實作正確。
- `canonical.jcs` 只涵蓋本庫用到的 JSON 子集，只與 3 組 RFC 8785 向量及 `rfc8785` 套件在本庫資料上比對過 [H]。
- 金鑰登錄的信任根是 `toolkit.yaml` 的釘選指紋；範例中根私鑰同樣是 TEST ONLY 檔案。沒有實作線上撤銷查詢或時間戳服務，簽章時間取自文件的 `issued_at`、關卡紀錄的 `timestamp` 或事件的 `ts`，也就是簽署者自己宣稱的時間。
- 安全等級與裁決規則各有一份 Python 實作（`vchlib.safety`、`vchlib.adjudicate`），依 docs/04 §5 與 docs/05 §4.2 逐條轉寫；文件若改動，程式與範例必須一起更新。
- 範例中的網域（example.com／example.net）、雜湊佔位與校準數字都是虛構的。
