# 資料模型（JSON Schema 2020-12，v0.5）

這裡的 schema 是**存檔與交換用**的完整版本。送給 LLM 的「輸出用 schema」由程式自動產生（見 [03 §8.3](../03-system-architecture.md#83-結構化輸出跨廠商最小公約數)；程式在 [tools/vchlib/llm_schema.py](../../tools/vchlib/llm_schema.py)），分兩步：

1. **投影**（`project`）：解析所有 `$ref`（含跨檔的 `common.schema.json#/$defs/...`、`requirement.schema.json`），取出 LLM 要寫的部分，並**移除 Harness 自己填的欄位**（ID、hash、run_id、家族、狀態、比對結果、安全等級、核准）。登錄表 `LLM_OUTPUTS`：
   - `finding`：移除 `finding_id`、`run_id`、`slice_id`、`reporter`、`status`、`evidence[].snippet_sha256`、`evidence[].match`
   - `vote`（verdict 的 `votes[]`）：只留 `stance`、`rationale`、`cited_evidence`
   - `threat`：移除 `threat_id`、`source_cluster_id`、`source_finding_ids`、`modeled_by`、`review`、`evidence[].match`、`crosswalk[].provenance／source_ref／reviewed_by`
   - `testcase`：移除 `testcase_id`、`threat_id`、`source_cluster_id`、`safety_class_computed`、`seed_manifest_ref`、`oracle.oracle_query_sha256`、`tool_binding.params`（自由格式，由 adapter 範本填）、`strategy_template_sha256`、`artifact_sha256`
   - `commander-plan`：移除 `plan_id`、`decision_node`、`round`、`followup_drafts[].draft_id`
   - `invariants`：移除 `engagement_id`、`run_id`、`round`、`drafted_by`、`signoff`、`invariants[].requirement_id／ref／signoff`
   - `dfd`：移除 `dfd_id`、`run_id`、`viewpoint`、`elements[].provenance`、`b1_diff`
   - `result-interpretation`（testresult 的 `interpretation`）：只留 `agrees`、`rationale`
2. **降級**（`degrade_for_llm`）成 Claude／OpenAI strict 的共通子集：
   - 直接移除（完整 schema 事後再驗）：`contains` `default` `exclusiveMaximum` `exclusiveMinimum` `format` `maxLength` `maxProperties` `maximum` `minLength` `minProperties` `minimum` `multipleOf` `pattern` `propertyNames` `uniqueItems`
   - 改寫：`const` → 單值 `enum`；`$ref` 內嵌、`$defs` 移除；無法解析的 `$ref` 是錯誤（不會變成 `{}`）
   - 拒絕（`DegradeError`，列出路徑；必須在投影中移除或改 schema）：`additionalItems` `allOf` `dependentRequired` `dependentSchemas` `else` `if` `not` `oneOf` `patternProperties` `prefixItems` `then` `unevaluatedItems` `unevaluatedProperties`，以及自由格式物件（沒有 `properties`，或 `additionalProperties` 為 true／schema）
   - 不在完整 schema `required` 中的欄位先改成可為 null，再把所有欄位列為 required；每個物件（含 `type: ["object","null"]`）設 `additionalProperties: false`；型別陣列保留；`minItems` 最大為 1
   - 降級結果不得含 `FORBIDDEN_FOR_LLM`（上面三組的聯集）中的任何關鍵字，也不得含 Harness 欄位（`E-LLM-SCHEMA`）。LLM 輸出取得後，Harness 填回自己的欄位，再以這裡的完整 schema 驗證。

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
| [finding](finding.schema.json) | 發現項（證據 kind：code_snippet／inventory_fact／config_fact） | [F-017](examples/finding.example.json)、[F-021](examples/finding.f-021.example.json)、[F-044](examples/finding.f-044.example.json)、[F-052](examples/finding.f-052.example.json)、[F-061](examples/finding.f-061.example.json)（inventory_fact：invoices 沒有 RLS）、[F-101](examples/finding.f-101.example.json) |
| [cluster](cluster.schema.json) | 叢集鍵、來源（white_box／black_box／tool_only）、成員、家族、指紋、baseline_state | [K-005](examples/cluster.example.json)、[K-011](examples/cluster.k-011.example.json)、[K-014](examples/cluster.k-014.example.json)（弱 SARIF 訊號）、[K-015](examples/cluster.k-015.example.json)、[K-016](examples/cluster.k-016.example.json)（tool_only，只有工具結果）、[K-101](examples/cluster.k-101.example.json)、[K-201](examples/cluster.k-201.example.json)（black_box，T-033）、[K-202](examples/cluster.k-202.example.json)（black_box，T-027） |
| [verdict](verdict.schema.json) | 驗證票、裁決狀態、rule_trace、工具佐證／訊號、provisional | [V-005-1](examples/verdict.example.json)、[V-005-2](examples/verdict.executable.example.json)、[V-011-1](examples/verdict.k-011-w3.example.json)、[V-011-2](examples/verdict.k-011-b5.example.json)、[V-014-1](examples/verdict.k-014-w3.example.json)（LIKELY，R6）、[V-016-1](examples/verdict.k-016-w3.example.json)（tool_only，UNCORROBORATED，R7）、[V-015-1](examples/verdict.k-015-w3.example.json)、[V-015-2](examples/verdict.k-015-w4.example.json)（W4，R1 CONFIRMED_EXECUTABLE）、[V-101-1](examples/verdict.lane-a.example.json)、[V-201-1](examples/verdict.k-201-b5.example.json)（CONFIRMED_EXECUTABLE，不需 LLM 分析者）、[V-202-1](examples/verdict.k-202-b5.example.json) |
| [dfd](dfd.schema.json) | 資料流程圖（外部觀點／合併觀點；元件來源與邊界種類） | [external](examples/dfd.external.example.json)、[merged](examples/dfd.merged.example.json) |
| [threat](threat.schema.json) | 威脅、分類版本、簽核、對照連結 | [T-012](examples/threat.example.json)、[T-019](examples/threat.t-019.example.json)、[T-027](examples/threat.t-027.example.json)、[T-031](examples/threat.t-031.example.json)、[T-033](examples/threat.t-033.example.json)（外部視角，沒有來源叢集） |
| [seed-threats](seed-threats.schema.json) | W3→B1 種子威脅 | [seed-threats.example.json](examples/seed-threats.example.json) |
| [requirement](requirement.schema.json) | ASVS／AISVS 需求與 G1 安全不變量 | [asvs](examples/requirement.asvs.example.json)、[invariant](examples/requirement.invariant.example.json)、[invariant-llm](examples/requirement.invariant-llm.example.json) |
| [commander-plan](commander-plan.schema.json) | 指揮官計畫與後續草稿 | [CMD-1](examples/commander-plan.example.json)、[CMD-5](examples/commander-plan.cmd5.example.json) |
| [testcase](testcase.schema.json) | 測試案例（oracle.types、controls） | [IDOR（S1）](examples/testcase.idor.example.json)、[LLM（S1）](examples/testcase.llm.example.json)、[ZAP active（S2）](examples/testcase.zap-active.example.json)、[發票列表 BOLA（S0）](examples/testcase.bola-list.example.json) |
| [w4-testcase](w4-testcase.schema.json) | v0.5（BL-27）：W4 白箱測試案例（unit／property／local_rls／fake_model、Z2 環境、對照、oracle 引用的 G1 條目） | [WTC-015-01](examples/w4-testcase.k-015.example.json)（K-015 的本地 RLS 測試） |
| [feedback](feedback.schema.json) | v0.5（BL-18）：簽署的誤報／確認回饋（指紋、標籤、SARIF suppression、單一簽章） | [FB-001](examples/feedback.k-016.example.json)（app_owner 把 K-016 標為誤報） |
| [testresult](testresult.schema.json) | 測試結果（fail_oracles、controls、observed_build_id） | [IDOR](examples/testresult.example.json)、[W4 本地 RLS](examples/testresult.w4-k-015.example.json)、[LLM](examples/testresult.llm-pass.example.json)、[ZAP](examples/testresult.zap-active.example.json)、[發票列表](examples/testresult.bola-list.example.json) |
| [report-manifest](report-manifest.schema.json) | 報告清單與雜湊、metrics、build_unverified_targets、absent_fingerprints | [report-manifest.example.json](examples/report-manifest.example.json) |
| [selftest-report](selftest-report.schema.json) | 工具包自測結果 | [selftest-report.m1.example.json](examples/selftest-report.m1.example.json) |
| [checkpoint-metadata](checkpoint-metadata.schema.json) | checkpoint 中繼資料 | [checkpoint-metadata.followup.example.json](examples/checkpoint-metadata.followup.example.json) |

## 驗證

```bash
python -m pip install -r requirements.txt      # 或 python -m pip install --user -r requirements.txt
python tools/validate_schemas.py               # 最後一行應為 "all checks passed (...)"
python -m pytest -q tests                      # 負向測試：每個竄改都要被對應的錯誤碼抓到
python tools/validate_schemas.py --real-run    # 正式執行前：代理可達的佔位模型 ID 變成錯誤（目前範例通過：唯一的佔位模型 nemotron_cloud 沒有代理可達）
```

`tools/validate_schemas.py` 只是入口；檢查都在 [tools/vchlib](../../tools/vchlib/)。CI（`.github/workflows/validate.yml`）在 ubuntu 與 windows 上跑上面兩個命令與 `tools/check_doc_links.py`。

**Windows 注意事項**
- 需要 `tzdata` 套件：Windows 沒有系統時區資料庫，`zoneinfo.ZoneInfo("Asia/Taipei")` 會失敗（已列在 requirements.txt）。
- 主控台是 cp950 時，中文輸出可能亂碼或 `UnicodeEncodeError`。驗證程式會把 stdout 改成 UTF-8；其他工具請設 `PYTHONUTF8=1`（或 `PYTHONIOENCODING=utf-8`）。
- 所有檔案以 UTF-8 讀寫；repo 的 `.gitattributes`（`* text=auto eol=lf`）讓簽出一律是 LF。若仍遇到 CRLF 的 `.jsonl`，雜湊鏈以去掉行尾 `\r` 的行計算（`bundle.read_jsonl_lines`）。
- JSON／JSONL 以嚴格模式載入（`vchlib/jsonstrict.py`）：重複鍵、NaN／Infinity、溢位成無限大的浮點數（如 `1e400`）、絕對值超過 2^53 的整數，以及（v0.5）巢狀超過 64 層、字串或鍵含孤立的 UTF-16 surrogate 一律拒絕（`E-JSON-STRICT`；v0.4 前者讓 validator 直接 `RecursionError`，後者讓整組檢查變成 `E-INTERNAL`；嚴格 YAML 同樣處理），該文件連同其上的簽章或雜湊鏈都不採信，語意與嚴格 YAML 相同。`3e0` 之類的浮點數不會被當成整數：schema 的 `integer` 只接受真正的整數（布林值與 `3.0` 都不算），`seq` 等欄位寫成浮點數 → `E-SCHEMA`（稽核 seq 另有 `E-AUDIT-SEQ`）。
- 稽核日誌被嚴格載入器拒絕時，只回報那一個 `E-JSON-STRICT`：該 run 的稽核檢查（`E-AUDIT-*`）與依賴稽核日誌的 `E-RUN-RESTORE-DRILL` 都不再連帶報錯。

### 檢查項目（21 組）

1. **schema 與範例**：每個 schema 是合法 2020-12、`$id`＝檔名；每個範例（含 `docs/examples/*.yaml`）通過 schema，`date-time` 必須帶時區、`uri` 必須是有 scheme 與主機的絕對 URI；schema 用到沒有檢查器的 `format` → `E-SCHEMA-FORMAT`（啟動即失敗，不會默默略過）；除 `common` 外每個 schema 都有範例；YAML 以嚴格載入器讀取（重複鍵、anchor、tag → `E-YAML-STRICT`）；無對應 schema 的 YAML → `E-KIND`；頂層形狀錯誤（該是 mapping 卻是 list、該是 list 卻是整數…）→ 每個檔案一個 `E-INPUT-SHAPE`，該文件不進語意檢查，驗證程式不會丟出 traceback。
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
13. **裁決重算**（rule_version `05-v0.5`）：以 docs/05 §4.2 規則（`vchlib.adjudicate`）重算 status、status_cap、advisory、annotations 與 `rule_trace` 規則序列；自我宣告的輸入一律由 validator 推導、重算時只用推導值：
    - `tool_corroboration`＝**強**工具佐證：已解析的 SARIF ref 中，(adapter, rule_id, tool_version) 列在 calibration.yaml `result.high_precision_rules`（同 CWE 桶、`precision_lower95` ≥ `result.thresholds.high_precision_min.value`，預設 0.90）者 → R5 row 10（不受 R8 限制）；`E-VERDICT-TOOLCORR`
    - `tool_signal`＝**弱**工具訊號：其他已解析的 SARIF ref ∪ E_fail_u 結果；不能單獨確認；`E-VERDICT-TOOLSIGNAL`
    - `independent_sources`＝len(叢集 independent_families) ＋（有弱 SARIF 訊號 ? 1 : 0）＋（有 E_fail_u ? 1 : 0）；R6 需 ≥ 2；`E-VERDICT-SOURCES`
    - E(cluster)＝agents.yaml 中 role verifier、家族與血統都不在叢集中的家族；`no_eligible_verifier`＝E 為空（`E-VERDICT-NOELIGIBLE`）；`diversity_degraded`＝非 Lane A、E 非空、且**計權合格票**的不同家族數 ＜ min(2, |E|)（`E-VERDICT-DIVERSITY`）
    - `provisional`＝calibration_version 為 null，或 theta_confirm 為 null，或 E(cluster) 每個模型在該叢集 CWE 桶的權重都是 0（`E-VERDICT-PROVISIONAL`）
    - 每個 `sarif_refs` 項目必須對應到該 run 稽核日誌中一個 W1 節點（v0.5）`tool_invocation_end` 事件的 `payload_refs`（`tool_report_refs` 同），該事件 `payload.adapter` 是 tools.yaml 中白箱工具的 `tool:mode`（工具 zone Z2、`b4_executable: false`）、其 licenses.yaml 狀態已放行（`OK`／`注意`；`法務閘門` 不算）、事件 zone Z2、`payload.ok: true`，且該 ref 的 `payload.sarif_results[]` 項目的 `file`、`symbol`、`cwe_bucket` 等於叢集的 `canonical_location.file`／`.symbol` 與 `cwe_bucket`（v0.4；`origin: black_box` 的叢集不收 SARIF）；否則 → `E-SARIF-REF`，該 ref 不算任何工具證據。rule_id 取自 `payload.sarif_results[]`
    - 只有 agents.yaml 中 role 為 `verifier` 的代理可以投票；其他角色的票 → `E-VERDICT-VOTER-ROLE`，且不計入 weighted_valid、score、支持／反對與家族多樣性
    - R0＝每個成員的每一項證據都是 NOT_FOUND（沒有成員時不成立）；independent_families＝第一輪、reviewer 角色、至少一項證據不是 NOT_FOUND 的成員家族（`E-CLUSTER-FAMILIES`）
    - 測試證據分類（`derive.classify_result`）：非 PASS／FAIL（ERROR、SKIPPED、STOPPED、INVALID）→ E_inc；重現的 FAIL 若只有 HUMAN／LLM_GRADER oracle 判定違反 → E_inc；解讀已預先登記（B4：G4 核准；W4：需求都經 G1 核准且 oracle_can_pass 對照 PASS）→ E_proof，不需要 LLM；否則由家族與血統都不在叢集中、且同意解讀的 Result Analyst → E_proof；否則 E_fail_u。PASS 需要所有 reachability 對照 PASS、機率型 k＝0 且 n′ ≥ 30、有確定性 oracle，以及預先登記（W4 用 oracle_can_fail）或合格分析者 → E_pass
14. **追溯鏈**：finding → cluster → verdict → threat → testcase → testresult → report；requirement 範例與 invariants.yaml 一致；種子威脅、DFD 元件、G2 參照。
15. **稽核紀錄結構**：v0.5：有關卡紀錄的 run 必須有稽核紀錄，每份關卡紀錄都要有 `gate_decision` 事件（收件時間），沒有 → `E-AUDIT-GATE`（不退回核准者自填的時間）；seq 是整數且連號（`3e0` 之類 → `E-AUDIT-SEQ`）、時間不倒退、每個 gate_decision 後緊接 audit_anchor、`run.audit_anchors` 的 `{seq, line_sha256}` 與日誌行一致（`E-AUDIT-ANCHOR`／`-MISMATCH`／`-TRUNCATED`），而且必須依序列出日誌中**每一個** audit_anchor 事件（漏列任何一個，包括最後一個 → `E-AUDIT-ANCHOR`，不論 run 狀態）、最後錨點之後的尾段（非終止 → `W-AUDIT-UNANCHORED-TAIL`；終止狀態的 run 必須以 `run_end` anchor 結尾，所有原因合併成**一個** `E-AUDIT-TAIL`）、每份關卡紀錄都有事件；gate_decision 事件的 `ts`（Audit Writer 的收件時間）與關卡紀錄自填的 `timestamp` 相差不超過 5 分鐘（v0.4，`E-AUDIT-GATE`），而關卡的金鑰效期、ROE 有效期、逾時與 G5 時間窗都以收件時間判定。
16. **校準**：重算 a、w、near_zero 與原因（±0.0005）、θ 可行性、arms（只有 ⑤ 探索性）、M-11 flag、κ。
17. **授權**：`tools.yaml` 的 license_ref 與 requirements.txt 的套件都在 licenses.yaml。
18. **對照表**：curated 必須有 reviewed_by、llm-suggested 不得有；OWASP 預設版本＝toolkit。
19. **LLM 輸出 schema**：`LLM_OUTPUTS` 每一項投影並降級後只用共通子集、不含 Harness 欄位，且每個範例的 LLM 部分通過降級 schema（`E-LLM-SCHEMA`；見本頁開頭）。
20. **工具包**：自動化帳號、逾時、保存期限欄位、`tool:mode` 命名、B4 模式在 Z3。
21. **其他**：DFD 連線與 b1_diff、報告 verdict_counts（每叢集最新裁決）、自測（M1 需 ST-1／ST-3／ST-7 已執行且通過）、checkpoint。

### v0.3 新增的錯誤碼

| 錯誤碼 | 規則 |
|---|---|
| `E-VERDICT-TOOLSIGNAL`、`E-VERDICT-SOURCES`、`E-VERDICT-NOELIGIBLE`、`E-VERDICT-PROVISIONAL`、`E-VERDICT-RULE-VERSION` | 裁決的推導欄位（第 13 組） |
| `E-RESULT-ORACLE` | `fail_oracles` 非空 ⇔ outcome FAIL，且 ⊆ testcase `oracle.types` |
| `E-GATE-EXPIRED-EARLY` | v0.4：EXPIRED 關卡紀錄的收件時間必須在開啟時間加上該關卡逾時之後（v0.5：開啟時間是 `gate_opened` 事件的收件時間） |
| `E-GATE-EXPIRED-SIG` | v0.5：EXPIRED 是唯一沒有簽章的結果，`signatures` 必須是 `[]`；不要求核准者簽章；審查 r7 1.1：EXPIRED 紀錄只能帶 needs_info 決定（`E-GATE-OUTCOME`），也不計入 G1 核准的需求、G2／G3 的決定與 G4 核准的測試案例 |
| `E-GATE-OPENED` | v0.5：G0a／G0b 以外的關卡紀錄，其 `gate_decision` 之前必須有同一關卡（G5 另加同一個 `job_id`）的 `gate_opened` 事件，`opened_at` 與它的收件時間相差不超過時鐘容差 |
| `E-KR-SERVICE` | v0.5：`z3_executor` 角色只能由服務身分 `z3-executor` 單獨持有；服務身分不是人員，不能出現在任何人員欄位 |
| `E-SIG-ISSUED-AT` | v0.5：委任設定／ROE 的 `issued_at` 不能晚於首次驗章（G0a／G0b 收件時間）超過時鐘容差 |
| `E-AUDIT-IDEMPOTENCY` | v0.4：`idempotency_key` 必填，格式 `<run_id>:<node>:<鍵>`，前兩段等於事件的 run_id 與 node，同一 run 內不重複 |
| `E-TRACE`（v0.5 補充） | 測試結果的 `cluster_ids` 必須含威脅的來源叢集，而且只能列該威脅的叢集（來源叢集與威脅以 `evidence.kind: cluster` 引用的叢集）；不能掛到無關的叢集改寫它的裁決 |
| `E-TC-SEEDS`（v0.5 補充） | `seed_manifest_ref` 必填，且等於 ROE 的 `db_access.seed_manifest_ref`；沒有 manifest，安全等級計算看不到種子、`state_changing_reads` 與 `read_only_endpoints` |
| `E-AUDIT-ANCHOR-SIG` | v0.4：每個 `audit_anchor` 的 `payload.z3_countersignature` 必須是金鑰登錄中 `z3-executor`（角色 `z3_executor`）對 JCS(`{run_id, seq, prev_hash}`) 的有效簽章；v0.5 改為 JCS(`{domain, run_id, seq, prev_hash, event_sha256}`)，`domain` 為 `vibecheck/audit_anchor/v2`，`event_sha256` 蓋住錨點事件本身（去掉副簽） |
| `E-SIG-BACKDATED` | v0.4：委任設定或 ROE 的簽章金鑰後來以非 `compromised` 原因撤銷時，該文件第一次被驗章（G0a／G0b 紀錄的收件時間）必須早於 `revoked_at`；v0.5 對 `not_after` 也一樣（首次驗章時金鑰已到期，或從未驗章而登錄顯示已到期） |
| `E-AUDIT-VERDICT` | `verdict_changed` 必須與裁決相符；v0.5：每一版裁決在其叢集所屬 run 的稽核檔中都必須有一筆 `verdict_changed` |
| `E-VERDICT-CHAIN` | v0.5：同一叢集的裁決版本以 `supersedes_verdict_id` 形成單一線性鏈（不自我取代、不循環、不分岔、恰好一個最新版） |
| `E-VERDICT-PHASE` | v0.5：`readjudicated_by` 不能倒填：黑箱叢集只有 B5 版本；W3 版本不取代任何版本；階段只能往後；收件時間晚於 W4／B4 測試結果的版本至少是 W4／B5；審查 r7 1.2：B5 版本的收件時間晚於所連 B4 job 的 `sandbox_job_end` |
| `E-ID-DUP` | v0.5：同一種文件（run、verdict、cluster、finding、testcase、testresult、threat、gate-record、report-manifest、slice）的 ID 不能重複 |
| `E-CLUSTER-BINDING` | v0.5：白箱叢集的 `canonical_location.file` 是成員證據的檔案、sink 落在成員證據的行範圍內、`file::name` 形式的 symbol 屬於該檔案、`cwe_bucket` 是某個成員 CWE 的桶（`facets.CWE_BUCKETS`）；同一 run 的叢集指紋不重複；審查 r7 1.6：同一個 run 內，一個發現項只能是一個叢集的成員 |
| `W-CLUSTER-BUCKET` | v0.5（警告）：成員的 CWE 都不在 `facets.CWE_BUCKETS`，`cwe_bucket` 無法檢查 |
| `E-JOB-AUDIT` | v0.5：`run.jobs`、`sandbox_job_*` 稽核事件與測試結果一致（有事件的 job 不是 SKIPPED；已執行的 job 有 `sandbox_job_end` 與 outcome 相同的測試結果）；審查 r7：B4 結果的 `executed_at` 落在該 job 的 `sandbox_job_start`／`end` 收件時間之間（1.2），`sandbox_job_end` 的 payload 釘住 `testcase_sha256`、`artifact_sha256`、`result_sha256`（1.10） |
| `E-RESULT-G4`、`E-RESULT-G5`、`E-RESULT-WINDOW`、`E-RUN-G4` | 審查 r7 1.2：以稽核事件的收件時間判斷：B4 job 的 `sandbox_job_start` 晚於核准該測試案例的 G4 決定（每個測試案例看最新的決定），job 的開始與結束都在 ROE 的有效期間與時段內；S2 job 的開始與結束落在 G5 決定與該時段結束之間；`approved_testcase_ids` 是最新 G4 決定為 accept 的測試案例 |
| `E-REPORT-QUEUE` | v0.4（BL-26）：`report_only_clusters` 每項是白箱叢集、最新裁決 `UNCORROBORATED`、不是種子威脅；`over_cap_items` 的 G2 項是沒有 G2 決定的 DISPUTED／UNCORROBORATED 種子叢集，且 G2 紀錄恰好有 `gate_queues.g2_max_items` 項決定；G3 項是 threat_id 沒有 G3 決定的種子威脅（seed_id） |
| `E-ROE-EDGE-RANGE` | v0.4（BL-15）：`targets[].edge_ip_ranges` 只用於 http 目標，每項是主機位元為 0 的 CIDR，且不與任何非公開網段重疊 |
| `E-RESULT-TRIALS` | v0.4：`trials` 滿足 k ≤ `n_effective` ≤ n；機率型 PASS 以 `n_effective`（n′）≥ 30 判定 `E_pass` |
| `E-FINDING-ROUND` | v0.5：發現項的 `reporter.round` 由 run 的指揮官計畫推導（round 1＝CMD-1 派給該 agent 與切片；round n＞1＝round n−1 的 CMD-2 加派）；Lane A 不檢查 |
| `E-TC-TOOL` | v0.5：`schemathesis:*` 的 `request_allowlist` 只有 GET／HEAD；`zap:baseline` 需要 `params.safe_mode: true`（`-S`） |
| `E-THREAT-ATTACK-TREE` | v0.5：likelihood high＋impact high 的威脅必須有 `attack_tree_ref`；`attack_tree_ref` 指向該威脅自己的 `…/<threat_id>.json` |
| `E-COVERAGE-D5` | v0.5：run 有 G4 紀錄後，每個最新 G3 決定為 accept 的威脅都有測試案例（含 MANUAL） |
| `E-ROE-MISSING` | 沒有 ROE；v0.5 起只在 bundle 含黑箱內容（測試案例、測試結果、威脅、G0b 以後的關卡紀錄或 `run.jobs`）時才是錯誤，純白箱 bundle 可以沒有 ROE |
| `E-TC-CONTROLS`、`E-RESULT-CONTROLS`、`E-RESULT-INVALID`、`E-RESULT-PRECONDITION` | testcase 至少一個 reachability 對照；結果恰好涵蓋所有對照；任何對照沒有 PASS → outcome 必須是 INVALID；`precondition_reached`＝所有 reachability 對照 PASS；`positive_control`＝oracle_can_fail 對照 PASS（沒有時為 null） |
| `E-W4-TC` | v0.5（BL-27）：W4 測試案例的 run 存在、叢集是同 run 的 white_box／tool_only 叢集、oracle 只引用 requirement_ids、local_rls 有拋棄式 Postgres 與 inventory 中的 migration；W4 結果不借用黑箱測試案例、只掛在測試案例的叢集上；審查 r7 1.3：local_rls 以外的種類要宣告 `target_files`（inventory 中的檔案），每個叢集的 `canonical_location.file` 必須在 target_files（local_rls 另加 migration）之內 |
| `E-W4-AUDIT` | v0.5（BL-27）：W4 結果恰好對應一筆已錨定的 W4／Z2 `sandbox_job_end`（同 result_id、testcase_id、outcome），`executed_at` 在該 job 的開始與結束之間；審查 r7 1.10：該事件另釘住 testcase、artifact 與結果的 hash |
| `E-W4-COVERAGE` | v0.5（BL-27）：run 有 W4 產物或種子威脅後，每條 G1 核准的不變量有 W4 測試案例或列在 `w4_manual_requirements`（不能兩者都有）；MANUAL 只能列 G1 核准的不變量 |
| `E-REPORT-METRICS` | report-manifest `metrics`（results_total、results_invalid、control_pass_rate；v0.5 BL-20：access_matrix_coverage、endpoint_slice_coverage、endpoint_test_coverage）由 run 的測試結果、testcase 的 access_cells、切片與 request_allowlist 重算；審查 r7（外部審查 5）：覆蓋率分成 `planned_*`（測試案例宣告的計畫）與 `executed_*`（只算有有效執行結果的測試案例：outcome PASS／FAIL、對照全部 PASS、有已錨定且 hash 相符的 `sandbox_job_end`），兩者都重算 |
| `E-PIPELINE` | v0.5（審查 r7 第 2 組）：流程完整性，Lane A 除外。W3 之後，run 的每個叢集都有裁決，每個 VERIFIED_SNIPPET 發現項都屬於某個叢集。W5 之後，W 階段最新狀態為 DISPUTED 或成員嚴重度 high 以上的 UNCORROBORATED 白箱叢集，必須有 G2 決定或列為 over_cap；沒有被 REJECTED 的白箱叢集是種子威脅或 report_only；G2 駁回的叢集不是種子。G3 之後每個種子都有 `threat_id`。`manual_review_clusters` 等於推導值（`post_g2_conflict`，或 B5 後 DISPUTED）。報告的 `gaps` 等於 run 的 gaps，artifacts 列出每個叢集的最新裁決與 run 的每個測試結果 |
| `E-TC-TRIALS`（v0.6 補充） | `fail_k_min` 在 1..n 之間；審查 r7 3.3：機率型測試（LLM 測試 adapter、`multi_turn`，或 `trials.record` 含 `target_model`）的 `trials.n` ≥ PASS 所需的有效次數（30；高風險威脅 60） |
| `E-CAL-WEIGHT`、`E-CAL-THETA`、`E-CAL-HIGH-PRECISION`（v0.6） | 審查 r7：`weights[]` 的 a、w、near_zero 由計數重算，w 是兩邊的對數概似比（SUPPORT＝ln(TPR／(1−TNR))、REFUTE＝ln(TNR／(1−TPR))），任一邊 near_zero → 兩邊 w＝0（3.2）；`theta_confirm`／`theta_reject` 必須有 `by_bucket`，每一項 value 與 feasible 一致，`high_precision_min` 沒有 `by_bucket`（3.5）；`high_precision_rules` 每列 n＝tp＋fp ≥ 40、`precision_lower95` 等於 Clopper-Pearson 雙尾 95% 下界且 ≥ `high_precision_min`、保留切分 n ≥ 10 且點估計 ≥ 下限 − 0.05（3.5） |
| `E-CLUSTER-ORIGIN` | white_box 叢集要有成員與程式位置；tool_only 叢集（v0.5，BL-13）沒有成員、`tool_report_refs` 至少一筆能解析，`sarif_refs` 不能含回報或同一工具的結果，其他 origin 的 `tool_report_refs` 為空；black_box 叢集要有 threat_id（該威脅沒有 source_cluster_id）與 `canonical_location.endpoint`；沒有來源叢集的威脅，其測試結果（FAIL、PASS、INVALID 都一樣）記在該威脅的 black_box 叢集 |
| `E-CLUSTER-FINGERPRINT`、`E-CLUSTER-BASELINE` | 指紋＝sha256(JCS({cwe_bucket, file, symbol}))（black_box：{cwe_bucket, target_id, method, path_template}）；`baseline_state` 依 run `baseline_run_id` 推導；report `absent_fingerprints` |
| `E-FINDING-EVIDENCE`、`E-FINDING-MATCH`、`E-FINDING-STATUS`、`E-FINDING-FACET` | 證據 kind 的欄位；code_snippet 至少 12 個非空白字元並含 3 字元以上的識別字，`file` 在發現項的切片中（v0.4）；inventory_fact 由 inventory 重算 match；status 由 match 推導；facet 與叢集 CWE 桶（`FACET_BUCKETS`） |
| `E-INVENTORY`、`E-INVENTORY-REF` | inventory 內部參照（middleware、來源檔、public_prefix；v0.5 BL-19：`kind: scheduled` 沒有 method、path 為 `schedule:`／`queue:`，其他 kind 必須有 method）；finding／threat／DFD 的 inventory JSON Pointer 必須可解析 |
| `E-ENG-BUDGET` | 每一層 `max_cost_usd` 等上限必填、階段上限不超過 run_total；v0.5（BL-14）：`budgets.families` 的家族是 models.yaml 的家族、上限不超過 run_total |
| `E-ENG-PUBLISH` | v0.5（BL-17）：`publishing` 關閉時 platform 為 null、token_scopes 為空；開啟時平台為 github、權杖範圍只能是 metadata:read／issues:write／pull_requests:write |
| `E-TOOLKIT-B1` | v0.5（BL-16）：toolkit `b1_crawl.skip_keywords` 包含 08 §11.7 的基本清單（方法、表單、origin、上限由 schema 限制） |
| `E-FEEDBACK` | v0.5（BL-18）：回饋的 run 屬於同一委任、指紋是所指叢集的指紋、duplicate 指向另一個叢集、sarif_suppression 依標籤、恰好一個 signed_by 的簽章（簽章與角色另由 E-SIG-* 檢查）；審查 r7 1.11：採用回饋的 run（同委任的另一個 run）在稽核紀錄中恰好有一筆已錨定的 `feedback_recorded`，payload 的 `feedback_sha256` 等於回饋的內容 hash；簽章以該事件的收件時間驗證，`signed_at` 與收件時間相差不超過時鐘容差，收件時間不早於所指 run 的開始 |
| `E-TC-ACCESS-CELL` | v0.5（BL-20）：testcase／w4-testcase 的 `access_cells` 每格都在 G1 存取矩陣中 |
| `E-SEED-SENSITIVE` | v0.5（BL-40）：seed `sensitive_fields` 的 phone／account 至少 6 位數字；同一正規化值不登記在兩個種子 |
| `E-INVARIANT-LEVEL`、`E-INVARIANT-REF` | L2 以上的 ASVS／AISVS 需求由 baseline_levels 或 level_triggers 涵蓋；llm_tools 的資料分級、access_matrix.ownership |
| `E-PLAN-COVERAGE`、`E-PLAN-FAMILIES` | v0.4：CMD-1 計畫涵蓋 run 的每個切片；每個切片的 reviewer 至少 min(2, 合格 reviewer 家族數) 個家族（合格＝reviewer 角色、模型在 engagement 該資料等級的 `allowed_models`、不在切片 `excluded_models`） |
| `E-PLAN-FACETS`、`E-PLAN-TARGET`、`E-PLAN-ROUNDS`、`E-PLAN-AGENTS`、`E-PLAN-BUDGET` | 計畫每個切片涵蓋 `MANDATORY_FACETS`；型別化目標；輪次 ≤ 2；代理角色；token 預算 ≤ run 階段預算 |
| `E-AGENT-TOOLS` | reviewer／verifier 只能 read_slice；commander 沒有工具；invariant_drafter 不能 read_slice |
| `E-TC-MUTATION-SCOPE` | 變更請求只能經 `{seed:key}`（種子的 path_templates）或 create_only_endpoints＋`{created:step_id}`（同時 S3）；帶 `graphql_operation` 的請求必須送到 ROE `targets[].graphql_paths` 宣告的路徑、方法為 GET／POST（v0.4，同時 S3）；`object_refs` 的每一項是為這條路徑宣告的種子或較早的建立請求，路徑沒有變數段的寫入有有效的 `object_refs` 才在範圍內；`state_changing_reads` 的 GET 算寫入、`read_only_endpoints` 的 POST 算讀取（v0.4）；v0.5：`{created:}` 只能用在建立端點 `created_resource.path_templates` 宣告的路徑（其他變數段等於建立請求的值）、建立的 `step_id` 不重複、GraphQL mutation 只用 POST；審查 r7：`object_refs` 中的 `{created:x}` 只用於 x 的 `created_resource.path_templates`（1.4）；沒有路徑變數的 PATCH／PUT／DELETE 必須以 query 的 `<id>=eq.<已綁定值>` 選取列，body 中的 ID 不算選取條件，只有 POST 可以由 body 綁定（1.8）；Server Action 的參照全部要能解析，引數以區分 JSON 型別的方式比對（`true` ≠ `1`，1.9） |
| `E-SEED-MANIFEST` | create_only_endpoints、state_changing_reads、read_only_endpoints 的目標必須是 ROE 的 http 目標；v0.5：create_only_endpoints 的 `created_resource` 必填且合法（`id_pointer` 是 token 非空的 JSON Pointer；每條 `path_templates` 恰有一段 `{created_id}`，其他變數段來自建立路徑） |
| `E-ROE-SEED-MANIFEST`、`E-SEED-SIDE-EFFECT` | v0.4：ROE `db_access.seed_manifest_sha256` 等於 seed manifest 的內容 hash；W0 inventory 中 `writes: true` 的 GET／HEAD 端點都列在 `state_changing_reads`；審查 r7 1.5：W0 標為 `writes: true` 的端點不能列在 `read_only_endpoints` |
| `E-RESULT-BUILD`、`E-RESULT-REQUEST-LOG` | observed_build_id＝run.repo_commit（完整或 ≥12 字元前綴）；build_identity none 的目標列入 build_unverified_targets；B4 結果需要請求紀錄 hash |
| `E-ROE-URL`、`E-ROE-PLATFORM`、`E-ROE-WHOAMI`、`E-ROE-RELAY-MODE`、`E-ROE-SOD` | https（http 只限 localhost）；共用平台網域需 platform_project＋platform_policies；用到的角色需 whoami；adaptive relay 只在 full；ROE 簽署角色由不同人擔任 |
| `E-GATE-APPROVER-ENG`、`E-GATE-SOD`、`E-GATE-RUN`、`E-GATE-ARTIFACT`、`E-G5-TWO-PERSON` | G0a／G1／G2 核准者來自 engagement gate_approvers（G0b／G3／G4／G5 來自 ROE：`E-GATE-ROE-APPROVER`；G3／G4／G5 必須在 ROE 有效期間內決定：`E-GATE-ROE-VALIDITY`；G0b 不受此限，它本身就是發現 ROE 未生效並讓 run 暫停的檢查）；同一人不兼兩個關卡角色；run 只能列自己的關卡紀錄；關卡紀錄必須有 artifact；full 的 G5 需兩位 security_reviewer |
| `E-ENG-TRANSFER`、`E-ROE-TRANSFER` | v0.4：data_class C 時，每個能收 C 級資料的雲端（非 Z4）家族有 `providers[].region` 與同區域的 `data_transfer.transfers[]`；跨出 `source_jurisdiction` 需要 `same_jurisdiction` 以外的機制與 reference；聲明者是委任設定簽署人。委任設定宣告跨境傳輸時，ROE `legal_review.scope.cross_border` 必須為 true |
| `E-ENG-CONFIG-PIN` | v0.4：engagement `config_pins` 等於 models／agents／tools／licenses 的內容 hash（sha256(JCS)）；v0.5 加入 calibration、crosswalk（決定裁決與威脅連結） |
| `E-ROE-INCIDENT` | v0.4：ROE `incident_response` 的聯絡人在金鑰登錄中，`covers` 含 data_exposure、third_party_side_effect、shared_platform_impact、staging_outage |
| `E-ENG-PROVIDER`、`E-ENG-PROFILE`、`E-PROFILE-SAFETY` | 能收 C 級資料的雲端模型需 ZDR confirmed＋DPA（自架＝`api_base` 主機完全等於 toolkit.yaml `z4_model_hosts` 的一項，v0.4）；role_consolidation 只在 lite；lite 只允許 S0／S1（MANUAL 除外）；`W-L5-LITE`：lite 且 acknowledged 時法務自證只是警告 |
| `E-THREAT-REVIEW`、`E-TC-REQ-UNAPPROVED`、`E-TC-SCRIPT` | 威脅的 review 必須是決定它的 G3 紀錄；testcase 只能引用 G1 核准的需求；scripted relay 需要 script_turns |
| `E-RUN-CONFIG`、`E-RUN-RULE-VERSION`、`E-SLICE-IDENTITY` | run config_refs 指向正確種類的檔案；v0.5（BL-22／23）：不能是 null，`invariants`／`seed_manifest` 可為 pending（`expected_node` 是產生節點 G1／G0b，且 run 尚未到達）或 not_applicable（invariants 只限 Lane A；seed_manifest 只限沒有 B 階段內容的 run）；tool_versions 已登錄且與稽核一致；rule_version＝`05-v0.5`；切片的 prompt 範本與 redaction map 屬於本 run |
| `E-G5-G4` | v0.5（BL-04）：G5 的 `g4_gate_record_id` 是同一 run 的 G4、在 G5 開啟前決定、是該測試案例最新且 accept 的 G4 決定，G4 與 G5 的核准者不重疊；其他關卡為 null |
| `E-GATE-CARRY` | v0.5（BL-21）：`decisions[].carried_from` 只限 G1／G3 的 accept；來源是祖先 run（同一委任）的同一關卡紀錄、同項目 accept 且 `item_sha256` 相同；來源簽章以現行金鑰登錄重新驗證；G3 另要求兩個 run 的 G0b 驗證同一份 ROE |
| `E-PROVENANCE`、`E-MODEL-FALLBACK-CLASS`、`E-MODEL-RETIREMENT-DATE`、`E-RESULT-ANALYST-ROLE` | threat.modeled_by／invariants.drafted_by 對應登錄；fallback 鏈上的模型都能收該資料等級且在允許清單；退役日期格式；Result Analyst 必須是 result_analyst 角色 |
| `E-SCHEMA-FORMAT`、`E-INPUT-SHAPE` | 見第 1 組；每份文件各自受保護：一份文件的意外錯誤只產生一個 `E-INTERNAL`，同組其他文件照常檢查；審查 r7 第 5 組：推導值（`E-DERIVED`）與 inventory／invariants／baseline 的追溯檢查也逐份文件保護 |

目前範例的預期警告只有一個：`nemotron_cloud` 的 litellm 是佔位模型 ID（`W-MODEL-PLACEHOLDER`；沒有 agent 會用到，`--real-run` 也不報錯）。U-11 已把 `claude_haiku` 換成 `claude_opus_48`（最早 2027-05-28 退役，不在委任期間內 [V][E:providers-52]）；U-12 已把 `gpt_flagship` 換成 `gpt-6-sol` [V][E:providers-46]。

## 簽章與測試金鑰

- 簽章是**真的 Ed25519**，簽在 RFC 8785 JCS（去掉 `signatures`）上；稽核事件簽在去掉 `signature` 的事件上。指紋＝`ed25519:SHA256:` ＋ base64（無 padding）的 SHA-256（原始 32 位元組公鑰）[H]。
- 範例用的私鑰在 `tests/fixtures/TEST_ONLY_private_keys/*.TEST_ONLY.pem`，**是公開的測試資料，只證明驗證程式的邏輯，不代表任何真實核准**。正式部署必須用各人自己的金鑰，絕不可沿用這些檔案。
- 修改任何範例後執行 `python tools/sign_examples.py`：取代 `FP:<名稱>`／`PK:<名稱>` 佔位字串，重算所有衍生值、重簽 YAML 與關卡紀錄、重建稽核雜湊鏈，直到不再變動。

## 設計決定（其他文件參照用）

- 稽核雜湊鏈：`prev_hash` ＝ 前一行原始 UTF-8 位元組（去掉行尾）的 SHA-256；第一筆＝`sha256(run_id)`。只有人為的 `initiator_claim` 與 `run_resume` 帶簽章，其他事件 `signature: null`；`audit_anchor` 另在 `payload.z3_countersignature` 帶 Z3 副簽（v0.4）。`run.audit_anchors` 依序列出每個 `audit_anchor` 事件的 `{seq, line_sha256}`（該錨點那一行本身的 SHA-256，所以錨點涵蓋到自己那一行）；它是寫入端推導的值，必須與日誌中的錨點事件完全一致，漏列 → `E-AUDIT-ANCHOR`（所以「從 run 紀錄刪掉最後一個錨點」不會降級成警告）。日誌中最後一個錨點事件之後的行是未錨定尾段：非終止狀態 → `W-AUDIT-UNANCHORED-TAIL`；終止狀態（COMPLETED、COMPLETED_WITH_GAPS、ABORTED、FAILED）→ 一個 `E-AUDIT-TAIL`（列出所有原因：尾段行數、最後一筆不是 audit_anchor、最後錨點不是 run_end）；日誌比錨定的 seq 短 → `E-AUDIT-TRUNCATED`；雜湊不符 → `E-AUDIT-ANCHOR-MISMATCH`。
- 報告清單中 `audit_log` 的 sha256 ＝ `report_published` 事件的 `prev_hash`，也就是「發布報告當下之前全部紀錄」的雜湊；之後追加的事件（如 run_end anchor）不影響報告清單。
- 關卡項目 hash 用「核准視圖」：去掉 `signatures`、`review`、`signoff` 後的 JCS，讓寫回決定不會改變被核准的 hash。
- G0a／G0b 沒有人為簽章；它們記錄系統對 engagement／ROE 簽章的驗證結果。

## 限制（誠實說明）

- 這是**設計庫的範例驗證器**，不是執行期元件：它證明範例彼此一致、規則可機械檢查，不證明實作正確。
- `canonical.jcs` 只涵蓋本庫用到的 JSON 子集，只與 3 組 RFC 8785 向量及 `rfc8785` 套件在本庫資料上比對過 [H]。
- 金鑰登錄的信任根是 `toolkit.yaml` 的釘選指紋；範例中根私鑰同樣是 TEST ONLY 檔案。沒有實作線上撤銷查詢或時間戳服務，簽章時間取自文件的 `issued_at`、關卡紀錄的 `timestamp` 或事件的 `ts`，也就是簽署者自己宣稱的時間。
- 安全等級與裁決規則各有一份 Python 實作（`vchlib.safety`、`vchlib.adjudicate`），依 docs/04 §5 與 docs/05 §4.2 逐條轉寫；文件若改動，程式與範例必須一起更新。
- 範例中的網域（example.com／example.net）、雜湊佔位與校準數字都是虛構的。
