# 資料模型（JSON Schema 2020-12）

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
| [w4-testcase](w4-testcase.schema.json) | W4 白箱測試案例（unit／property／local_rls／fake_model、Z2 環境、對照、oracle 引用的 G1 條目） | [WTC-015-01](examples/w4-testcase.k-015.example.json)（K-015 的本地 RLS 測試） |
| [feedback](feedback.schema.json) | 簽署的誤報／確認回饋（指紋、標籤、SARIF suppression、單一簽章） | [FB-001](examples/feedback.k-016.example.json)（app_owner 把 K-016 標為誤報） |
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
- JSON／JSONL 以嚴格模式載入（`vchlib/jsonstrict.py`）：重複鍵、NaN／Infinity、溢位成無限大的浮點數（如 `1e400`）、絕對值超過 2^53 的整數，以及巢狀超過 64 層、字串或鍵含孤立的 UTF-16 surrogate 一律拒絕（`E-JSON-STRICT`；v0.4 前者讓 validator 直接 `RecursionError`，後者讓整組檢查變成 `E-INTERNAL`；嚴格 YAML 同樣處理），該文件連同其上的簽章或雜湊鏈都不採信，語意與嚴格 YAML 相同。`3e0` 之類的浮點數不會被當成整數：schema 的 `integer` 只接受真正的整數（布林值與 `3.0` 都不算），`seq` 等欄位寫成浮點數 → `E-SCHEMA`（稽核 seq 另有 `E-AUDIT-SEQ`）。
- 稽核日誌被嚴格載入器拒絕時，只回報那一個 `E-JSON-STRICT`：該 run 的稽核檢查（`E-AUDIT-*`）與依賴稽核日誌的 `E-RUN-RESTORE-DRILL` 都不再連帶報錯。

### 檢查項目（24 組）

1. **schema 與範例**：每個 schema 是合法 2020-12、`$id`＝檔名；每個範例（含 `docs/examples/*.yaml`）通過 schema，`date-time` 必須帶時區、`uri` 必須是有 scheme 與主機的絕對 URI；schema 用到沒有檢查器的 `format` → `E-SCHEMA-FORMAT`（啟動即失敗，不會默默略過）；除 `common` 外每個 schema 都有範例；YAML 以嚴格載入器讀取（重複鍵、anchor、tag → `E-YAML-STRICT`）；無對應 schema 的 YAML → `E-KIND`；頂層形狀錯誤（該是 mapping 卻是 list、該是 list 卻是整數…）→ 每個檔案一個 `E-INPUT-SHAPE`，該文件不進語意檢查，驗證程式不會丟出 traceback。
2. **RFC 8785 JCS**：自寫的 `canonical.jcs` 對 RFC 8785 測試向量，並對每份文件與參考套件 `rfc8785==0.1.4` 比對。
3. **衍生值**：片段 hash、關卡項目 hash、artifact hash、報告清單 hash、票權重、分數、合格票等由 `vchlib.derive` 重算；稽核雜湊鏈由原始行重算。
4. **金鑰登錄**：根公鑰指紋＝toolkit 釘選值、根簽章有效、`version ≥ min_version`（防回滾）、`registry_id`＝toolkit `location`＝engagement／ROE `key_registry_ref`、指紋＝公鑰計算值、撤銷欄位一致、自動化帳號不得持有金鑰。
5. **Ed25519 簽章**：engagement、ROE（含 legal_review.attested_by）、G1–G5／GB 關卡紀錄、人為的 `initiator_claim`／`run_resume`／`spot_check_result` 事件。公鑰只從金鑰登錄取得；`compromised` → 該金鑰全部簽章無效；其他撤銷原因 → 撤銷時間之前的簽章仍有效。G0a／G0b 是系統驗證：`signatures: []`，`verification.signer_results` 必須等於實際驗證結果。
6. **人員參照**：所有 person_id 都已登錄、不是自動化帳號，角色與金鑰相符（校準標註者是外部標註人員，不列入）。
7. **委任**：有效期間、允許模型與資料等級、逾時不超過工具包、成本上限都有值且階段 ≤ 總額、保存期限（`retention_days` 必須在 1..工具包上限之內，否則 `E-RETENTION`，是錯誤不是警告）、Lane A 模型、程式碼擁有權聲明、OWASP LLM 版本。
8. **ROE 與 L-1..L-6**：在委任期間內、時間窗與時區、目標與 db_access、拒絕清單（`tools.yaml` 的 `toolkit_denied`＝程式內建清單 ⊆ ROE `denied_modes`）、允許的工具已登錄、停止條件只能更嚴、relay 不超過工具包、資料等級與保存期限（toolkit.yaml `retention` 是組織上限；engagement `retention_days` 是有效值且不得超過上限，ROE 只能再縮短：`E-RETENTION`／`E-ROE-RETENTION`）、資料庫目標與 `db_access` 的主機不得在 `exclusions.hosts` 且必須是 ROE 的資料庫目標（`E-ROE-DB-SCOPE`；訊息以 `[binding rule]`／`[scope rule]`／`[exclusion rule]` 標出是哪一條）、http 目標的 `base_url` 必須可解析且主機不得在 `exclusions.hosts`（`E-ROE-TARGETS`）、endpoint 只接受 `host:port` 或 `[IPv6]:port`（schema pattern；無法解析 → `E-ROE-DB-SCOPE` "unparseable endpoint"，不會 `E-INTERNAL`）；比對主機前兩邊都先正規化（小寫、去掉結尾的 `.`、IDNA），`DB.X.` 與 `db.x` 視為同一主機、seed manifest，以及 docs/06 §2.1.1 的 L-1..L-6。
9. **模型與代理**：未知模型回報 `E-MODEL-UNKNOWN`（不當掉）、確定性角色 `model: null`、fallback 同家族、雲端 Nemotron 只收 P、OpenAI 模型收 C 時 `store: false`、`earliest_retirement`（委任開始前 → 錯誤，期間內 → 警告）、佔位模型 ID（`placeholder: true` → `W-MODEL-PLACEHOLDER`；litellm 含 `<...>`、`{...}`、獨立的 `TBD`／`TODO`／`FIXME`（不分大小寫）或「實作時確認」卻沒標 → `E-MODEL-PLACEHOLDER`；加 `--real-run` 時，任何代理經 `model`、`fallback_models` 或 models.yaml fallback 鏈可達的佔位模型 → `E-MODEL-PLACEHOLDER`）、reviewer 家族多樣性與跨家族 verifier、finding／票／解讀者的家族與登錄一致。
10. **關卡**：每關必要角色、登錄一致、G0b 之後的核准者來自 ROE、發起者、逾時、有效期間、G4 核准者 ∈ run.initiators、G5 核准者 ∉ run.initiators 且在同一 ROE 時間窗內決定、GB 核准者、outcome 與 decisions 一致、G3 決定寫回威脅、G1 決定寫回不變量。
11. **run**：狀態／current_node／resume_deadline、jobs、S2 需要 G5＋快照＋還原驗證＋7 天內的還原演練（稽核日誌無法載入時不重複回報 `E-RUN-RESTORE-DRILL`）、測試結果在時間窗內且在 G4／G5 之後、請求數 ≤ 上限、k ≤ n、GB 延長後的預算、Lane A 與後續 run 規則。
12. **測試案例 vs ROE**：以 docs/04 §5 演算法（`vchlib.safety`）重算安全等級、可否進入 G4、db_tables ⊆ oracle_tables、種子都在 manifest、ZAP `delayInMs`／`maxScanDurationInMins` 限制、多輪對話需要 relay、角色。
13. **裁決重算**（rule_version `05-v0.15`）：以 docs/05 §4.2 規則（`vchlib.adjudicate`）重算 status、status_cap、advisory、annotations 與 `rule_trace` 規則序列；自我宣告的輸入一律由 validator 推導、重算時只用推導值：
    - `tool_corroboration`＝**強**工具佐證：已解析的 SARIF ref 中，(adapter, rule_id, tool_version) 列在 calibration.yaml `result.high_precision_rules`（同 CWE 桶、`precision_lower95` ≥ `result.thresholds.high_precision_min.value`，預設 0.90）者 → R5 row 10（不受 R8 限制）；`E-VERDICT-TOOLCORR`
    - `tool_signal`＝**弱**工具訊號：其他已解析的 SARIF ref ∪ E_fail_u 結果；不能單獨確認；`E-VERDICT-TOOLSIGNAL`
    - `independent_sources`＝len(叢集 independent_families) ＋（有弱 SARIF 訊號 ? 1 : 0）＋（有 E_fail_u ? 1 : 0）；R6 需 ≥ 2；`E-VERDICT-SOURCES`
    - E(cluster)＝agents.yaml 中 role verifier、模型在該 run 資料等級的 `allowed_models` 中、家族與血統（血統的根，`derived_from`）都不在叢集中的家族；`no_eligible_verifier`＝E 為空（`E-VERDICT-NOELIGIBLE`）；`diversity_degraded`＝非 Lane A、E 非空、且**計權合格票**的不同家族數 ＜ min(2, |E|)（`E-VERDICT-DIVERSITY`）
    - `provisional`＝calibration_version 為 null，或 theta_confirm 為 null，或 E(cluster) 每個模型在該叢集 CWE 桶的權重都是 0（`E-VERDICT-PROVISIONAL`）
    - 每個 `sarif_refs` 項目必須對應到該 run 稽核日誌中一個 W1 節點`tool_invocation_end` 事件的 `payload_refs`（`tool_report_refs` 同），該事件 `payload.adapter` 是 tools.yaml 中白箱工具的 `tool:mode`（工具 zone Z2、`b4_executable: false`）、其 licenses.yaml 狀態已放行（`OK`／`注意`；`法務閘門` 不算）、事件 zone Z2、`payload.ok: true`，且該 ref 的 `payload.sarif_results[]` 項目的 `file`、`symbol`、`cwe_bucket` 等於叢集的 `canonical_location.file`／`.symbol` 與 `cwe_bucket`（v0.4；`origin: black_box` 的叢集不收 SARIF）；否則 → `E-SARIF-REF`，該 ref 不算任何工具證據。rule_id 取自 `payload.sarif_results[]`
    - 只有 agents.yaml 中 role 為 `verifier` 的代理可以投票；其他角色的票 → `E-VERDICT-VOTER-ROLE`，且不計入 weighted_valid、score、支持／反對與家族多樣性
    - R0＝每個成員的每一項證據都是 NOT_FOUND（沒有成員時不成立）；independent_families＝第一輪、reviewer 角色、至少一項證據不是 NOT_FOUND 的成員家族（`E-CLUSTER-FAMILIES`）
    - 測試證據分類（`derive.classify_result`）：非 PASS／FAIL（ERROR、SKIPPED、STOPPED、INVALID）→ E_inc；重現的 FAIL 若只有 HUMAN／LLM_GRADER oracle 判定違反 → E_inc；解讀已預先登記（B4：G4 核准；W4：需求都經 G1 核准、oracle 由程式從 G1 結構產生（kind local_rls／fake_model）且 oracle_can_pass 與 oracle_can_fail 對照都 PASS；LLM 撰寫的 W4 測試要 G2 已接受該叢集）→ E_proof，不需要 LLM；LLM 撰寫、G2 未接受的 W4 FAIL → E_fail_u（裁決加註 oracle_unreviewed）；否則由家族與血統都不在叢集中、且同意解讀的 Result Analyst → E_proof；否則 E_fail_u。PASS 需要所有 reachability 對照 PASS、機率型 k＝0 且 n′ ≥ 30、有確定性 oracle，以及預先登記（W4 用 oracle_can_fail）或合格分析者 → E_pass
14. **追溯鏈**：finding → cluster → verdict → threat → testcase → testresult → report；requirement 範例與 invariants.yaml 一致；種子威脅、DFD 元件、G2 參照。
15. **稽核紀錄結構**：有關卡紀錄的 run 必須有稽核紀錄，每份關卡紀錄都要有 `gate_decision` 事件（收件時間），沒有 → `E-AUDIT-GATE`（不退回核准者自填的時間）；seq 是整數且連號（`3e0` 之類 → `E-AUDIT-SEQ`）、時間不倒退、每個 gate_decision 後緊接 audit_anchor、`run.audit_anchors` 的 `{seq, line_sha256}` 與日誌行一致（`E-AUDIT-ANCHOR`／`-MISMATCH`／`-TRUNCATED`），而且必須依序列出日誌中**每一個** audit_anchor 事件（漏列任何一個，包括最後一個 → `E-AUDIT-ANCHOR`，不論 run 狀態）、最後錨點之後的尾段（非終止 → `W-AUDIT-UNANCHORED-TAIL`；終止狀態的 run 必須以 `run_end` anchor 結尾，所有原因合併成**一個** `E-AUDIT-TAIL`）、每份關卡紀錄都有事件；gate_decision 事件的 `ts`（Audit Writer 的收件時間）與關卡紀錄自填的 `timestamp` 相差不超過 5 分鐘，而關卡的金鑰效期、ROE 有效期、逾時與 G5 時間窗都以收件時間判定。
16. **校準**：重算 a、w、near_zero 與原因（±0.0005）、θ 可行性、arms（只有 ⑤ 探索性）、M-11 flag、κ。
17. **授權**：`tools.yaml` 的 license_ref 與 requirements.txt 的套件都在 licenses.yaml。
18. **對照表**：curated 必須有 reviewed_by、llm-suggested 不得有；OWASP 預設版本＝toolkit。
19. **LLM 輸出 schema**：`LLM_OUTPUTS` 每一項投影並降級後只用共通子集、不含 Harness 欄位，且每個範例的 LLM 部分通過降級 schema（`E-LLM-SCHEMA`；見本頁開頭）。
20. **工具包**：自動化帳號、逾時、保存期限欄位、`tool:mode` 命名、B4 模式在 Z3。
21. **回饋**（`g_feedback`）：`feedback` 的簽署者角色、`false_positive` 的副簽與 SARIF 抑制狀態、`duplicate_of`、叢集更新後抑制失效、Lite 不能記錄 `false_positive`（`E-FEEDBACK`）。
22. **報告撤回**（`g_report_withdrawal`，審查 r12）：`report-withdrawal` 指向本委任存在的報告、每份報告只撤回一次、取代的報告來自較晚開始的另一個 run、簽署者依序是測試負責人與資安審查者且是兩個人（`E-REPORT-WITHDRAWAL`）。
23. **W4 測試案例**（`g_w4_testcases`）：W4 需求來自已核准的 G1 不變量、對照步驟、`MANUAL` 標記、完成的 run 每份 w4-testcase 都有結果（`E-W4-COVERAGE`）、觀察來源（`E-W4-OBSERVATION`）。
24. **其他**：DFD 連線與 b1_diff、報告 verdict_counts（每叢集最新裁決）、自測（M1 需 ST-1／ST-3／ST-7 已執行且通過）、checkpoint。

### 錯誤碼

下表由 [`tools/build_error_table.py`](../../tools/build_error_table.py) 維護：每個 validator 會回報的錯誤碼與警告碼恰好一列（`tools/vchlib` 中所有 `E-…`／`W-…` 字串），依家族分組、組內依字母排序；「守住的測試」欄由 `tests/` 中提到該碼的測試檔自動產生（最多列 3 份）。規則欄是手寫的說明；新增錯誤碼時先在表中補上規則，再執行 `python tools/build_error_table.py`。CI 以 `--check` 確認表格與程式一致。標「—」的錯誤碼目前沒有測試直接引用它。

目前範例的預期警告只有一個：`nemotron_cloud` 的 litellm 是佔位模型 ID（`W-MODEL-PLACEHOLDER`；沒有 agent 會用到，`--real-run` 也不報錯）。U-11 已把 `claude_haiku` 換成 `claude_opus_48`（最早 2027-05-28 退役，不在委任期間內 [V][E:providers-52]）；U-12 已把 `gpt_flagship` 換成 `gpt-6-sol` [V][E:providers-46]。

<!-- error-table:start -->

**稽核紀錄**

| 錯誤碼 | 規則 | 守住的測試 |
|---|---|---|
| `E-AUDIT-ACTOR` | `initiator_claim`／`run_resume`／`spot_check_result` 事件的 `actor.kind` 必須是 human；`actor.kind: human` 的 `actor.id` 必須是已登錄、非自動化帳號的人員；從 SUSPENDED 恢復的 `run_resume` 只能由該 run 的 `run_owner` 或發起者執行；審查 r12：`run_resume` 的 `payload.from_status` 必須是 `SUSPENDED` 或 `STOPPED`（之前缺了就當成 STOPPED） | `test_v04_round5_adjudication`、`test_v05_round6_group3`、`test_v05_round6_lowprio` 等 4 份 |
| `E-AUDIT-ANCHOR` | 每個 `gate_decision` 之後緊接一個 `audit_anchor`；兩個錨點之間的事件數不超過 `toolkit.yaml` 的 `audit.anchor_interval_events`；`run.audit_anchors` 的每一項指名一個 `audit_anchor` 事件，且與稽核檔的錨點事件一一對應 | `test_v02_hardening` |
| `E-AUDIT-ANCHOR-GAP` | Z3 對每個副簽的錨點編上本委任的遞增編號 `payload.anchor_counter`（在副簽範圍內）：所有 run 的錨點編號必須是 1、2、3…不重複、不缺號，而且依收件時間排序。只控制 Z1 的人把一個 run 截回較早的錨點（刪掉 B4 證據、G5、B5 裁決與報告）時，之後的錨點已經用過被刪掉的編號，所以會留下缺號 | `test_v07_r9_anchor` |
| `E-AUDIT-ANCHOR-MISMATCH` | `run.audit_anchors[].line_sha256` 必須等於稽核檔中該 `seq` 那一行原始位元組的 sha256，而且那一行是 `audit_anchor` 事件 | `test_v02_hardening` |
| `E-AUDIT-ANCHOR-SIG` | 每個 `audit_anchor` 的 `payload.z3_countersignature` 必須是金鑰登錄中 `z3-executor`（角色 `z3_executor`）對 JCS(`{run_id, seq, prev_hash}`) 的有效簽章；v0.5 改為 JCS(`{domain, run_id, seq, prev_hash, event_sha256}`)，`domain` 為 `vibecheck/audit_anchor/v2`，`event_sha256` 蓋住錨點事件本身（去掉副簽） | `test_v04_round5_trust`、`test_v05_round6_group3`、`test_v07_r9_anchor` |
| `E-AUDIT-ARTIFACT` | 已錨定的 `artifact_stored` 以 `payload.sha256` 釘住 run 的 W／B 階段產物：種子威脅（W5）、W0 inventory 與 redaction map、合併與外部 DFD（B1）、run 列出的每份 Commander 計畫（`plan_id`）。每份產物恰有一筆已錨定的事件，每筆事件指名本 run 一份 hash 相符的文件。審查 r9 只釘種子威脅（改種子文件的 `run_id` 就關掉了管線檢查）；審查 r11 補上其餘：已完成的 run 原本可以刪掉 inventory 的檔案、盲點與環境變數，報告與 run 紀錄仍自洽 | `test_v07_r11_anchor`、`test_v07_r9_anchor` |
| `E-AUDIT-CHAIN` | 每筆事件的 `prev_hash` 必須是 sha256(run_id)（第一筆）或前一筆原始行的 sha256 | `test_v02_hardening`、`test_validator` |
| `E-AUDIT-FEEDBACK` | 審查 r12：每筆已錨定的 `feedback_recorded` 都要對應 bundle 中同 `feedback_id`、內容 hash 相符的回饋紀錄（反向檢查；之前刪掉回饋紀錄——連同 SARIF 抑制與 ASI09 抽查母體——不會報錯） | `test_v07_r12_run` |
| `E-AUDIT-GATE` | `gate_decision` 的 `payload.gate_record_sha256` 釘住所決定的關卡紀錄（去掉 `signatures` 的 content hash）。審查 r9 只釘關卡、結果與時間，核准者用自己的金鑰就能在決定被錨定之後增刪決定項目再重簽；只重簽相同內容不算變更 | `test_v05_round6_group1`、`test_v04_legal_trust`、`test_v05_round6_lowprio` 等 6 份 |
| `E-AUDIT-IDEMPOTENCY` | `idempotency_key` 必填，格式 `<run_id>:<node>:<鍵>`，前兩段等於事件的 run_id 與 node，同一 run 內不重複 | `test_v04_round5_adjudication` |
| `E-AUDIT-INITIATOR` | `initiator_claim` 事件的 actor 必須列在 `run.initiators` | `test_bl66_run_gates` |
| `E-AUDIT-REPORT` | （同一條規則也涵蓋 `E-AUDIT-VERDICT`）`verdict_changed` 的 payload 釘住 `verdict_sha256`（該版裁決的內容 hash），`report_published` 釘住 `report_manifest_sha256`（manifest 的 artifacts 再釘住 SARIF、HTML、裁決與稽核紀錄）；錨點之後改裁決的任何欄位或報告都會被發現<br>每個 run 只有一份報告 manifest（`E-ID-DUP`），而且它必須恰有一筆**已錨定**的 `report_published` 指名它的 `report_id`、`report_manifest_sha256` 等於 manifest 的 content hash。審查 r9 只拿事件比對該 run 的第一份 manifest，第二份 manifest、或從未發布的 run 的 manifest 都不受檢查；manifest 的 `audit_log` 產物改對照同一 `report_id` 的事件<br>`report_published` 事件的 `payload.report_id` 必須等於該 run 的 report-manifest 的 `report_id`（report-manifest 必須存在） | `test_v07_r10_anchor`、`test_v07_r8_integrity`、`test_v07_r9_anchor` |
| `E-AUDIT-RUN` | 稽核檔所屬的 run 必須存在；每筆事件的 `run_id`、`engagement_id` 與該 run 及委任一致，`data_class` 與 run 相同 | `test_bl66_run_gates` |
| `E-AUDIT-SEQ` | `seq` 是整數 1、2、3…連號（`3e0`、`3.0` 這類浮點寫法也拒絕） | `test_review_fixes` |
| `E-AUDIT-SIG` | 人員發出的 `initiator_claim`／`run_resume`／`spot_check_result` 事件必須帶簽章；其他事件的 `signature` 必須是 null | `test_v05_round6_lowprio` |
| `E-AUDIT-TAIL` | `run_end` 錨點之後不能再有任何行，不論 run 紀錄自填什麼狀態：一個 run 只結束一次。審查 r9 的 `E-RUN-STATUS` 讓 run 狀態跟著最後一筆 `run_status_changed`，但那一筆本身可以是 `run_end` 之後附加的未錨定行，所以「改回 RUNNING 重新打開」仍然成立 | `test_v02_hardening`、`test_v07_r10_anchor`、`test_v07_r10_contracts` |
| `E-AUDIT-TRUNCATED` | `run.audit_anchors` 指名的行必須存在於稽核檔中；稽核檔不存在時 `run.audit_anchors` 必須是空的（檔案被截到錨點之前） | `test_v02_hardening` |
| `E-AUDIT-TS` | 事件的 `ts` 不能倒退（不早於前一筆事件） | `test_bl66_run_gates` |
| `E-AUDIT-VERDICT` | `verdict_changed` 必須與裁決相符；每一版裁決在其叢集所屬 run 的稽核檔中都必須有一筆 `verdict_changed`；那一筆必須在最後一個 `audit_anchor` 之前（未錨定的行不是證據，所以還不是裁決）；裁決以 `cluster_sha256` 釘住叢集、叢集以 `member_finding_sha256` 釘住成員發現項，裁決之後改寫發現項也會讓這個比對失敗<br>（同一條規則也涵蓋 `E-AUDIT-REPORT`）`verdict_changed` 的 payload 釘住 `verdict_sha256`（該版裁決的內容 hash），`report_published` 釘住 `report_manifest_sha256`（manifest 的 artifacts 再釘住 SARIF、HTML、裁決與稽核紀錄）；錨點之後改裁決的任何欄位或報告都會被發現 | `test_v07_r9_anchor`、`test_v02_hardening`、`test_v05_round6_group3` 等 5 份 |
| `W-AUDIT-UNANCHORED-TAIL` | 非終態 run 的稽核檔中，最後一個 `audit_anchor` 之後的行尚未錨定（警告；它們還不能當作證據） | `test_v02_hardening` |

**run 與 job**

| 錯誤碼 | 規則 | 守住的測試 |
|---|---|---|
| `E-JOB-AUDIT` | `run.jobs`、`sandbox_job_*` 稽核事件與測試結果一致（有事件的 job 不是 SKIPPED；已執行的 job 有 `sandbox_job_end` 與 outcome 相同的測試結果）；審查 r7：B4 結果的 `executed_at` 落在該 job 的 `sandbox_job_start`／`end` 收件時間之間（1.2），`sandbox_job_end` 的 payload 釘住 `testcase_sha256`、`artifact_sha256`、`result_sha256`（1.10）；審查 r8 F2a／F2b：每個 B4 結果的 job 必須在已執行的狀態（PENDING、EXECUTING、INTERRUPTED、STOPPED 的 job 不能有結果），每個 job 恰有一份結果，而且每一份結果都要有恰一筆已錨定、outcome 與三個 hash 都相符的 `sandbox_job_end`（不只是同一 job 的最後一份）；`derive.classify_result` 對沒有已錨定執行事件的結果一律給 `E_inc`；審查 r9：B 階段的每個 `sandbox_job_*` 事件都要對應 `run.jobs` 的 job（拿掉 job 與它的 FAIL 結果，已錨定的 `sandbox_job_end` 不再被忽略），完成的 run 對 G4 核准的每個測試案例都有 job（已執行或 SKIPPED）<br>BL-60：G4 核准的 MANUAL 測試案例不需要工具包的 job（由人執行，列在報告的未能測試清單）；第十四輪內部審查：zone Z3 的 `sandbox_job_*` 事件不論 `node` 標成什麼都是 B4 job——必須 node B4、在 `run.jobs` 裡；W0／W1／W4 的 job 必須 zone Z2（之前只依 node 挑 B 階段 job，標成 W1 的 Z3 job 逃過全部規則）；完成的 run 不得有 PENDING／SNAPSHOTTED／EXECUTING 的 job | `test_v07_r14_validator`、`test_v05_round6_group6`、`test_v07_r8_validator` 等 6 份 |
| `E-JOB-G4` | 第十四輪內部審查：B4 job 的 `sandbox_job_start` 當下，對該測試案例有效的 G4 決定必須是 accept（`derive.g4_state`），不論 job 有沒有結果；之前這條檢查只在測試結果的迴圈內，INTERRUPTED 的 job 不受約束 | `test_v07_r14_validator` |
| `E-PIPELINE` | 流程完整性，Lane A 除外。審查 r11：`no_eligible_verifier` 的叢集（W3 狀態不是 REJECTED）也必須有 G2 決定或 over_cap。W3 之後，run 的每個叢集都有裁決，每個 VERIFIED_SNIPPET 發現項都屬於某個叢集。W5 之後，**W3 裁決**為 DISPUTED 或 rubric 嚴重度 high 以上的 UNCORROBORATED 白箱叢集，必須有 G2 決定或列為 over_cap（審查 r8 F5：以 G2 當時看到的 W3 版本與 `cluster.severity` 判斷，不看 W4 重新裁決後的版本，也不看成員自報的 `finding.severity`）；沒有被 REJECTED 的白箱叢集是種子威脅或 report_only；G2 駁回的叢集不是種子。G3 之後每個種子都有 `threat_id`。`manual_review_clusters` 等於推導值（`post_g2_conflict`，或 B5 後 DISPUTED）。報告的 `gaps` 等於 run 的 gaps，artifacts 列出每個叢集的最新裁決與 run 的每個測試結果 | `test_v07_r8_validator`、`test_v05_r7_pipeline`、`test_v07_r11_verdict` |
| `E-RUN` | run 的 `engagement_id`、`data_class`、`run_owner` 必須與委任相同，`calibration_version` 與 calibration.yaml 相同 | `test_bl66_run_gates` |
| `E-RUN-BASELINE` | 第十四輪內部審查：`initial` run 的 `baseline_run_id` 必須是 null；其餘必須是沿 `parent_run_id` 可達、而且更早開始的祖先 run（02 §1.6）；之前只要求是 bundle 中另一個 run | `test_v07_r14_validator` |
| `E-RUN-BUDGET` | GB 以 extend 核准後，`budgets.<phase>` 必須帶 GB 的 `new_caps`；各階段已用的 token、成本與運算分鐘不能超過對應上限 | `test_bl66_run_gates` |
| `E-RUN-CLAIM` | Lane B run 在第一個 G1 決定、W4 或 B 階段事件之前，必須有人簽署的 `initiator_claim`（[02 §1.5](../02-methodology.md#15-自動觸發與發起者)、06 D7）；審查 r11：反向也成立，`run.initiators` 列出的每個人都要有本 run 已錨定、簽章有效的 `initiator_claim`（否則 G4 核准者可以被列成從未認領的「發起者」） | `test_v07_r8_validator`、`test_v07_r11_anchor` |
| `E-RUN-COMMIT` | 已錨定的 `run_created` 事件以 `payload.repo_commit` 釘住 run 測試的 commit；run 紀錄與本 run 的 W0 inventory 必須是同一個 commit（`E-RESULT-BUILD` 再拿它比對觀察到的 build）；審查 r12：`run_kind` 與 `trigger` 也由它釘住（`run_kind` 決定 R14 `FIXED`、Lane A 豁免與 `reuse` 規則）；第十四輪內部審查：也釘住 `baseline_run_id` | `test_v07_r9_anchor`、`test_v07_r12_run`、`test_v07_r14_validator` |
| `E-RUN-CONFIG` | （同一條規則也涵蓋 `E-RUN-RULE-VERSION`、`E-SLICE-IDENTITY`）run config_refs 指向正確種類的檔案；不能是 null，`invariants`／`seed_manifest` 可為 pending（`expected_node` 是產生節點 G1／G0b，且 run 尚未到達）或 not_applicable（invariants 只限 Lane A；seed_manifest 只限沒有 B 階段內容的 run）；tool_versions 已登錄且與稽核一致；rule_version＝`05-v0.5`；切片的 prompt 範本與 redaction map 屬於本 run | `test_v03_manifest`、`test_v05_backlog_high` |
| `E-RUN-DEADLINE` | WAITING_GATE 時，`resume_deadline` 必須等於待決關卡的 `opened_at` 加上委任對該關卡的逾時 | `test_bl66_run_gates` |
| `E-RUN-FOLLOWUP` | followup／regression run 的 `parent_run_id` 必須存在，且來自父 run 的某個 follow-up 草稿；其他 run 不能有 `parent_run_id`，`reuse` 必須是 `[]` | `test_v07_r8_validator` |
| `E-RUN-G1` | 有 G3 決定（非 EXPIRED）的 run 必須有核准的 G1（本 run 決定，或以 `carried_from` 逐項沿用祖先 run 的 G1）；沿用的 G1 決定，其不變量的 `signoff` 指向來源紀錄（`E-TRACE-INVARIANT`） | `test_v07_r9_contracts` |
| `E-RUN-G3` | 到 G4 的 run，其 `testcase_ids` 每個測試案例的威脅都在**本 run** 的 G3 有 accept（可用 `carried_from` 沿用祖先 run 的核准，但仍由本 run 簽署） | `test_v07_r8_validator` |
| `E-RUN-G4` | （同一條規則也涵蓋 `E-RESULT-G4`、`E-RESULT-G5`、`E-RESULT-WINDOW`）審查 r7 1.2：以稽核事件的收件時間判斷：B4 job 的 `sandbox_job_start` 晚於**開始那一刻仍有效的**核准（`derive.g4_state`：最新決定是 accept，從哪一次 accept 起連續核准；之後相同內容的再次 accept 不移動它；外部審查），job 的開始與結束都在 ROE 的有效期間與時段內；S2 job 的開始與結束落在 G5 決定與該時段結束之間；`approved_testcase_ids` 是日誌末端最新 G4 決定為 accept 的測試案例（目前可派送）；執行後才被撤銷的核准不使已執行的結果失效，改報 `W-RESULT-G4-WITHDRAWN` | `test_v05_r7_bypasses`、`test_v07_r11_external` |
| `E-RUN-GAPS` | 審查 r12：完成的 run，`gaps` 必須包含由 run 的紀錄推導出的每一項（kind＋ref）：MANUAL 的 W4 需求（`w4_manual_requirements`）與 MANUAL 測試案例 → `manual`；日誌末端 G4 決定為 reject 的測試案例 → `g4_rejected`；SKIPPED job → 依 `skip_reason`（G5 駁回／逾時 → `g5_skipped`，其餘沿用原因名稱）；所有權驗證失敗 → `ownership_failed`；ERROR／SKIPPED／STOPPED／INVALID 的結果 → `error`；GB `stop_phase` → `gb_stopped`；已錨定的 `resume_expired`（到期未續跑）→ `{kind: expired, ref: <run_id>}`。G3 駁回不是 gap（報告另列「未做黑箱驗證」）。r11 由 `gaps` 推導終態，但 `gaps` 本身沒人檢查，跳過已核准的 job 仍能 COMPLETED；第十四輪內部審查：G4 最終 `needs_info`、run 有 G4 紀錄卻沒有任何 G4 決定涵蓋的測試案例 → `g4_rejected`；INTERRUPTED／STOPPED 的 job → `stopped` | `test_v07_r14_validator`、`test_v07_r12_run`、`test_v07_r12_flow` |
| `E-RUN-GATES` | `gate_records` 必須依 `opened_at` 排序，列出的關卡紀錄都必須存在 | `test_bl66_run_gates` |
| `E-RUN-INITIATOR` | `initiators` 每一位都必須是已登錄、非自動化帳號的人員 | `test_validator` |
| `E-RUN-JOB` | `run.jobs` 的鍵等於 `job_id`；測試案例存在且經 G4 核准（列在 `approved_testcase_ids`，或在 job 開始時有效、事後才被撤銷）；`safety_class` 等於測試案例的計算等級；目標屬於該測試案例；只有 S2 job 有 `g5_record_id`；已執行的 job 有測試結果且列在 `executed_jobs`；`executed_jobs` ⊆ `jobs` | `test_bl66_run_gates`、`test_v07_r11_external` |
| `E-RUN-LANE-A` | Lane A run 沒有 `roe_ref`、不經過 G0b、沒有 jobs；它的裁決都是 advisory；`lane_a_advisories` 等於該 run 的叢集；Lane A run 宣告 `pr_origin`（same_repo／fork），fork 的 PR 沒有裁決、叢集與 advisories；其他 run 的 `pr_origin` 為 null，其 `lane_a_advisories` 只能引用 same_repo Lane A run 的叢集 | `test_v07_r8_validator` |
| `E-RUN-OWASP` | run 的 `owasp_llm_version` 必須等於委任的設定（委任為 null 時用工具包的 `owasp_llm_default`） | `test_bl66_run_gates` |
| `E-RUN-OWNERSHIP` | `run.ownership_results` 的每一筆對應 ROE 的目標，方法等於 ROE 為該目標宣告的 `ownership_proof.method`（DB 目標是 `db_comment`）；B4 job 跑過的每個目標都有 `ok: true` 的結果。v0.7 第八輪從不讀這個欄位，範例的 DB 目標以 `dns_txt`「通過」<br>`run.ownership_results` 的每一筆都要有同一 `batch_id`、已錨定的 `ownership_check` 事件（Z3 Executor 的紀錄），事件的 `payload.results` 列出該目標、相同的方法與結果；`checked_at` 不晚於事件收件時間，事件收件早於對該目標的第一個 B4 `sandbox_job_start`。審查 r9 只比對 ROE，一個沒有任何事件、日期在所有 job 之後的批次也能通過；第十四輪內部審查：有 `sandbox_job_start` 的 job 不論有無結果都算碰過目標；`run_resume` 之後對每個目標在下一個 Z3 job 前要有新的 ok `ownership_check`（03 §5.6） | `test_v07_r9_contracts`、`test_v07_r10_anchor`、`test_v07_r14_validator` |
| `E-RUN-RESTORE-DRILL` | S2 job 開始前 `restore_drill_days` 天內必須有一次成功的還原演練（`restore_drill` 事件），且 job 帶 `restore_drill_ref`；審查 r11：只採計系統帳號寫在已錨定部分的事件 | `test_v07_r11_anchor`、`test_review_fixes` |
| `E-RUN-RESUME` | 審查 r11：`run_status_changed` 離開 `SUSPENDED`／`STOPPED` 時，進入暫停之後必須有一筆已錨定、人簽署的 `run_resume`（`from_status` 相符；簽署人的角色由 `E-AUDIT-ACTOR`／`E-SIG-ROLE` 檢查：SUSPENDED 由 run_owner 或發起者、STOPPED 由測試負責人），收件時間不晚於委任設定的 `validity.not_after`；resume 之後第一個 B 階段事件之前必須有新的 G0b `VERIFIED` 決定（每次 resume 重驗 ROE，[03 §5.6](../03-system-architecture.md#56-中止補償與-resume)）。之前一行未錨定的系統事件就能把暫停的 run 接回去。審查 r12：唯一的例外是到期清理——轉到 `COMPLETED_WITH_GAPS`、之前有一筆已錨定的系統 `resume_expired`（`from_status` 相符），且兩筆事件都晚於 `not_after`（[03 §5.2](../03-system-architecture.md#52-主狀態圖)）；第十四輪內部審查：`run_resume` 之後、下一個工作或關卡事件之前要有新的 `VERIFIED` G0a（03 §5.2 run_resume → G0a_engagement_check） | `test_v07_r12_flow`、`test_v07_r11_anchor`、`test_v07_r14_validator` 等 4 份 |
| `E-RUN-RULE-VERSION` | （同一條規則也涵蓋 `E-RUN-CONFIG`、`E-SLICE-IDENTITY`）run config_refs 指向正確種類的檔案；不能是 null，`invariants`／`seed_manifest` 可為 pending（`expected_node` 是產生節點 G1／G0b，且 run 尚未到達）或 not_applicable（invariants 只限 Lane A；seed_manifest 只限沒有 B 階段內容的 run）；tool_versions 已登錄且與稽核一致；rule_version＝`05-v0.5`；切片的 prompt 範本與 redaction map 屬於本 run | `test_v03_manifest`、`test_v07_r8_calibration` |
| `E-RUN-S2` | 已執行的 S2 job（SNAPSHOTTED、EXECUTING、EXECUTED、INTERRUPTED、RESTORED、RESTORE_FAILED、STOPPED）需要該 job 的 APPROVED G5 紀錄與 `snapshot_ref`；審查 r12：快照與還原以稽核事件為準——恰一筆已錨定、`snapshot_ref` 相符、早於 `sandbox_job_start` 的 `snapshot_created`。第十二輪外部審查起依 job 狀態判斷（之前一律要求 RESTORED，誠實的還原失敗與 G5 駁回的略過都過不了）：**RESTORED**＝恰一筆已錨定、`verified: true`、晚於 `sandbox_job_end` 的 `snapshot_restored`、沒有 `restore_failed`、`restore_verified: true`；**RESTORE_FAILED**＝有已錨定的 `restore_failed`、沒有 verified 的 `snapshot_restored`、`restore_verified: false`，終止的 run 必須是 `FAILED`（[03 §5.6](../03-system-architecture.md#56-中止補償與-resume)）；INTERRUPTED／STOPPED 的 `restore_verified` 必須與日誌相符；終止的 run 中，已執行的 S2 job 只能是 RESTORED 或 RESTORE_FAILED。**沒有執行**的 S2 job（PENDING、AWAITING_G5、SKIPPED）沒有快照、還原或沙箱事件，`snapshot_ref` 為空；因 G5 駁回或逾時而 SKIPPED 的，`g5_record_id` 指向本 job 的 G5 紀錄且結果是 REJECTED／EXPIRED | `test_v07_r12_external`、`test_v07_r12_run`、`test_validator` |
| `E-RUN-STATUS` | `run.status` 必須是稽核檔最後一筆 `run_status_changed` 的 `to`（第一筆之前是 `RUNNING`）；稽核檔有 `run_end` 錨點的 run 一定是終止狀態。v0.7 第八輪只看 run 紀錄自填的狀態，把已完成的 run 改回 RUNNING 就能在 `run_end` 錨點之後繼續附加未錨定的行<br>終止狀態的 run 不能有 `current_node` 或待決關卡；WAITING_GATE 必須恰好有一個待決關卡且等於 `current_node`<br>審查 r11：每筆 `run_status_changed` 的 `from` 必須是上一筆的 `to`（第一筆之前是 `RUNNING`）；`WAITING_GATE → RUNNING` 之間必須有 `gate_decision`；完成的 run 的狀態由 `gaps` 推導（只有 `manual` → `COMPLETED`，否則 `COMPLETED_WITH_GAPS`，[02 §1.4](../02-methodology.md#14-關卡結果與-run-狀態)）<br>第十三輪外部審查：每筆 `from → to` 必須在 [02 §1.4](../02-methodology.md#14-關卡結果與-run-狀態) 的合法轉移表中（`checks.RUN_TRANSITIONS`；終止狀態沒有出口，之前 `RUNNING → ABORTED → RUNNING` 再接著跑黑箱也過）；`sandbox_job_start`／`tool_invocation_start` 只能在 `RUNNING` 時發生，`gate_decision` 只能在 `RUNNING`／`WAITING_GATE`<br>第十四輪內部審查：終止狀態之後只允許 `run_end` 錨點，裁決、草稿與 `report_published` 都不能再寫 | `test_v07_r11_anchor`、`test_v07_r13_external`、`test_v07_r9_anchor` 等 5 份 |
| `E-RUN-WINDOW` | 第十四輪內部審查（02 §1.4 G0b 列、B0）：碰到目標的事件——`ownership_check`、zone Z3 的 `sandbox_job_*`、`snapshot_created`／`snapshot_restored`／`restore_failed`、`restore_drill`——都要在 ROE 有效期間與時間窗內；之前只檢查 B4 結果的 `executed_at`，範例的所有權驗證與還原演練都在時間窗外 | `test_v07_r14_validator` |

**關卡與抽查**

| 錯誤碼 | 規則 | 守住的測試 |
|---|---|---|
| `E-G4-INITIATOR` | G4 核准者必須列在 `run.initiators` | `test_validator` |
| `E-G5-G4` | G5 的 `g4_gate_record_id` 是同一 run 的 G4、在 G5 開啟前決定、是 G5 開啟時該測試案例最新且 accept 的 G4 決定（過期的 G4 round 不算，與其他查詢一致），G4 與 G5 的核准者不重疊；其他關卡為 null | `test_v05_backlog_high`、`test_v07_r11_external` |
| `E-G5-INITIATOR` | G5 核准者不能是 run 的發起者，也不能是該關卡紀錄的 `initiator` | `test_validator` |
| `E-G5-JOB` | G5 的 `job_id` 必須是該 run 中 `safety_class` 為 S2 的 job | `test_bl66_run_gates` |
| `E-G5-TWO-PERSON` | （同一條規則也涵蓋 `E-GATE-APPROVER-ENG`、`E-GATE-SOD`、`E-GATE-RUN`、`E-GATE-ARTIFACT`）G0a／G1／G2 核准者來自 engagement gate_approvers（G0b／G3／G4／G5 來自 ROE：`E-GATE-ROE-APPROVER`；G3／G4／G5 必須在 ROE 有效期間內決定：`E-GATE-ROE-VALIDITY`；G0b 不受此限，它本身就是發現 ROE 未生效並讓 run 暫停的檢查）；同一人不兼兩個關卡角色；run 只能列自己的關卡紀錄；關卡紀錄必須有 artifact；full 的 G5 需兩位 security_reviewer；同一委任另一個 run 中，已錨定且早於本 run 開始的 `spot_check_result`（`item_kind: g5`、`outcome: overturned`）也要求兩位資安審查者（`checks.g5_escalation`） | `test_v03_gates`、`test_v06_r7_methodology` |
| `E-G5-WINDOW` | G5 必須在某個 ROE 時間窗內開啟與決定，且決定時間早於該時間窗結束與「開啟時間加逾時（未設定時 24 小時）」兩者中較早者 | `test_validator` |
| `E-GATE-APPROVER` | 每個核准者的 `key_fingerprint` 必須是金鑰登錄中該 `person_id` 的金鑰，且該金鑰具有所列的角色 | `test_validator` |
| `E-GATE-APPROVER-ENG` | （同一條規則也涵蓋 `E-GATE-SOD`、`E-GATE-RUN`、`E-GATE-ARTIFACT`、`E-G5-TWO-PERSON`）G0a／G1／G2 核准者來自 engagement gate_approvers（G0b／G3／G4／G5 來自 ROE：`E-GATE-ROE-APPROVER`；G3／G4／G5 必須在 ROE 有效期間內決定：`E-GATE-ROE-VALIDITY`；G0b 不受此限，它本身就是發現 ROE 未生效並讓 run 暫停的檢查）；同一人不兼兩個關卡角色；run 只能列自己的關卡紀錄；關卡紀錄必須有 artifact；full 的 G5 需兩位 security_reviewer；同一委任另一個 run 中，已錨定且早於本 run 開始的 `spot_check_result`（`item_kind: g5`、`outcome: overturned`）也要求兩位資安審查者（`checks.g5_escalation`） | `test_v03_gates` |
| `E-GATE-ARTIFACT` | （同一條規則也涵蓋 `E-GATE-APPROVER-ENG`、`E-GATE-SOD`、`E-GATE-RUN`、`E-G5-TWO-PERSON`）G0a／G1／G2 核准者來自 engagement gate_approvers（G0b／G3／G4／G5 來自 ROE：`E-GATE-ROE-APPROVER`；G3／G4／G5 必須在 ROE 有效期間內決定：`E-GATE-ROE-VALIDITY`；G0b 不受此限，它本身就是發現 ROE 未生效並讓 run 暫停的檢查）；同一人不兼兩個關卡角色；run 只能列自己的關卡紀錄；關卡紀錄必須有 artifact；full 的 G5 需兩位 security_reviewer；同一委任另一個 run 中，已錨定且早於本 run 開始的 `spot_check_result`（`item_kind: g5`、`outcome: overturned`）也要求兩位資安審查者（`checks.g5_escalation`） | `test_v03_robustness` |
| `E-GATE-CARRY` | `decisions[].carried_from` 只限 G1／G3 的 accept；來源是祖先 run（同一委任）的同一關卡紀錄、同項目 accept 且 `item_sha256` 相同；來源簽章以現行金鑰登錄重新驗證；G3 另要求兩個 run 的 G0b 驗證同一份 ROE | `test_v05_backlog_high` |
| `E-GATE-ENGAGEMENT` | 關卡的決定時間（收件時間）必須在委任有效期間內 | `test_bl66_run_gates` |
| `E-GATE-EXPIRED-EARLY` | EXPIRED 關卡紀錄的收件時間必須在開啟時間加上該關卡逾時之後（開啟時間是 `gate_opened` 事件的收件時間） | `test_v04_round5_adjudication`、`test_bl60_suspend`、`test_v05_round6_group3` 等 4 份 |
| `E-GATE-EXPIRED-SIG` | EXPIRED 是唯一沒有簽章的結果，`signatures` 必須是 `[]`；不要求核准者簽章；審查 r7 1.1：EXPIRED 紀錄只能帶 needs_info 決定（`E-GATE-OUTCOME`），也不計入 G1 核准的需求、G2／G3 的決定與 G4 核准的測試案例 | `test_v05_round6_group3` |
| `E-GATE-G0-APPROVERS` | G0a 核准者必須恰好是委任設定的簽署人，G0b 核准者恰好是 ROE 的簽署人（person_id、角色與金鑰指紋都相同） | `test_bl66_run_gates` |
| `E-GATE-G0-SIG` | G0a／G0b 是系統驗章，`signatures` 必須是 `[]` | `test_bl66_run_gates` |
| `E-GATE-G0-VERIFY` | G0a／G0b 的 `verification.signer_results` 必須等於以已載入金鑰登錄重新驗章的結果；`key_registry_version` 是 1 到已載入登錄版本之間的整數；outcome 為 VERIFIED 時至少有一個簽章且全部有效；第十四輪內部審查：`VERIFY_FAILED` 的紀錄至少一個 `signer_results[].ok` 為 false 或有 `reason` | `test_v05_round6_group3`、`test_v07_r14_validator` |
| `E-GATE-INITIATOR` | 關卡紀錄的 `initiator` 必須是已登錄、非自動化帳號的人員，且列在 `run.initiators`；只有自動觸發的 Lane A run 可以是 null（沒有人認領它） | `test_v05_round6_group3`、`test_v07_r11_anchor` |
| `E-GATE-JOB` | 只有 G5 使用 `job_id`，其他關卡必須是 null | `test_bl66_run_gates` |
| `E-GATE-OPENED` | G0a／G0b 以外的關卡紀錄，其 `gate_decision` 之前必須有同一關卡（G5 另加同一個 `job_id`）的 `gate_opened` 事件，`opened_at` 與它的收件時間相差不超過時鐘容差 | `test_v05_round6_group3` |
| `E-GATE-ORDER` | 以稽核事件的收件時間檢查 run 的結構：各關卡第一次決定依 G0a < G1 < G2 < G0b < G3 < G4 < G5；G0a 之後的事件都在 VERIFIED 的 G0a 之後；B 階段事件（B0～B6 節點、G3／G4／G5 決定、B4 的 job）都在 VERIFIED 的 G0b 之後、而且中間沒有 VERIFY_FAILED；有 G3／G4／G5 紀錄或 job 的 run 一定有 VERIFIED 的 G0b；W4 在 G2 決定之後、G0b 之前；第十三輪外部審查：`W1`～`W5` 的每個事件之前要有 APPROVED 的 G1，`W2`～`W5` 的事件晚於第一個 W1 事件（`run_kind: lane_a` 沒有 G1，不適用；之前 W1 在 G1 前掃描、W3 在 G1 前裁決都過）；第十四輪內部審查：zone Z3 的 job 事件是 B 階段事件（需 VERIFIED 的 G0b）；G0a／G0b `VERIFY_FAILED` 之後的下一筆非錨點事件必須是 `run_status_changed` → ABORTED／SUSPENDED | `test_v07_r8_validator`、`test_v07_r13_external`、`test_v07_r14_validator` |
| `E-GATE-OUTCOME` | `assurance_profile: lite` 的 G2 決定只能是 accept／needs_info；第十四輪內部審查：GB `EXPIRED` 時 `gb.choice` 與 `new_caps` 必須是 null（沒有人決定；之前每個 choice 都映射成 APPROVED／REJECTED，GB EXPIRED → SUSPENDED 的路徑寫不出來） | `test_bl60_suspend`、`test_v05_round6_group4`、`test_v07_r14_validator` 等 6 份 |
| `E-GATE-OVER-CAP` | G3 的 `over_cap` 決定不能用在有 `attack_tree_ref` 或 impact 為 high 的威脅（這類威脅永遠不受 G3 佇列上限影響） | `test_v05_round6_group4` |
| `E-GATE-ROE-APPROVER` | G3～G5 的核准者必須是 ROE 的簽署人或 ROE 列出的 `gate_approvers` | `test_v03_gates` |
| `E-GATE-ROE-VALIDITY` | G3～G5 的決定（收件時間）必須在 ROE 的有效期間內 | `test_v03_gates` |
| `E-GATE-ROLES` | 核准者的角色必須涵蓋該關卡的必要角色（`GATE_ROLES`，例如 G3 需要 security_reviewer 與 app_owner） | `test_bl66_run_gates` |
| `E-GATE-ROUND` | 審查 r11：關卡紀錄的 `round` 不超過 [02 §1.4](../02-methodology.md#14-關卡結果與-run-狀態) 的重擬上限：G1、G3 最多 3 輪，G4 最多 2 輪，其他關卡 1 輪（schema 另以 `maximum: 3` 擋下）。之前上限只是文字 | `test_v07_r11_anchor`、`test_v07_r12_examples` |
| `E-GATE-RUN` | （同一條規則也涵蓋 `E-GATE-APPROVER-ENG`、`E-GATE-SOD`、`E-GATE-ARTIFACT`、`E-G5-TWO-PERSON`）G0a／G1／G2 核准者來自 engagement gate_approvers（G0b／G3／G4／G5 來自 ROE：`E-GATE-ROE-APPROVER`；G3／G4／G5 必須在 ROE 有效期間內決定：`E-GATE-ROE-VALIDITY`；G0b 不受此限，它本身就是發現 ROE 未生效並讓 run 暫停的檢查）；同一人不兼兩個關卡角色；run 只能列自己的關卡紀錄；關卡紀錄必須有 artifact；full 的 G5 需兩位 security_reviewer；同一委任另一個 run 中，已錨定且早於本 run 開始的 `spot_check_result`（`item_kind: g5`、`outcome: overturned`）也要求兩位資安審查者（`checks.g5_escalation`） | `test_v03_gates` |
| `E-GATE-SOD` | （同一條規則也涵蓋 `E-GATE-APPROVER-ENG`、`E-GATE-RUN`、`E-GATE-ARTIFACT`、`E-G5-TWO-PERSON`）G0a／G1／G2 核准者來自 engagement gate_approvers（G0b／G3／G4／G5 來自 ROE：`E-GATE-ROE-APPROVER`；G3／G4／G5 必須在 ROE 有效期間內決定：`E-GATE-ROE-VALIDITY`；G0b 不受此限，它本身就是發現 ROE 未生效並讓 run 暫停的檢查）；同一人不兼兩個關卡角色；run 只能列自己的關卡紀錄；關卡紀錄必須有 artifact；full 的 G5 需兩位 security_reviewer；同一委任另一個 run 中，已錨定且早於本 run 開始的 `spot_check_result`（`item_kind: g5`、`outcome: overturned`）也要求兩位資安審查者（`checks.g5_escalation`） | `test_v03_gates` |
| `E-GATE-TIME` | 關卡的開啟時間不能晚於決定時間（收件時間） | `test_bl66_run_gates` |
| `E-GATE-TIMEOUT` | G5 以外的關卡，決定時間與開啟時間的間隔不能超過逾時（委任 `gate_timeouts_hours`，未設定時用工具包上限）；第十三輪外部審查：只約束人工結果（APPROVED／REJECTED／NEEDS_INFO），EXPIRED 由系統寫入、只需不早於期限（`E-GATE-EXPIRED-EARLY`），之前兩條同時套在 EXPIRED 上，逾時紀錄只能剛好寫在期限那一刻 | `test_v05_round6_group3`、`test_v07_r13_external` |
| `E-GB-APPROVER` | GB 核准者只能是委任的 `run_owner` 或 `budget_approver` | `test_bl66_run_gates` |
| `E-SPOT-CHECK` | `spot_check_result` 的 actor 是登錄的 `security_reviewer`，`item_kind` 是 g1～g5，`item_id` 是同一委任的該關卡紀錄，而且 actor 不是該紀錄的核准者、發起者或其 run 的發起者（06 §1.1 ASI09 的獨立複核）；審查 r9：`item_kind` 也可以是 `verdict`、`cluster`、`feedback`（06 §1.1 的母體），項目屬於本委任，抽查人不是該 run 的發起者、該叢集 G2 的核准者或回饋的簽署者；Lite 委任不記錄抽查（一個人無法獨立重看自己的決定） | `test_v07_r8_validator`、`test_bl60_suspend`、`test_v07_r9_anchor` 等 4 份 |

**ROE 與法務聲明**

| 錯誤碼 | 規則 | 守住的測試 |
|---|---|---|
| `E-L1` | ROE 必須有 `legal_review`（L-1）；`legal_review.scope` 每一項必須是 true，或帶 `not_applicable_reason` | `test_bl66_run_gates` |
| `E-L2` | `legal_review.attested_by` 必須有未撤銷的登錄金鑰（L-2），且具有 legal_reviewer 或 management 角色（只有 management 時改報 `W-L2-MANAGEMENT`） | `test_bl66_run_gates` |
| `E-L3` | `legal_review.attested_by` 必須在這份 ROE 上有有效簽章（L-3） | `test_bl66_run_gates` |
| `E-L4` | `legal_review.attested_at` 不晚於 ROE `not_before`，`expires_at` 不早於 ROE `not_after`（L-4） | `test_validator` |
| `E-L5` | `legal_review.attested_by` 不能是 ROE 的 test_lead（L-5；lite＋已確認的角色合併例外，改報 `W-L5-LITE`） | `test_v03_gates`、`test_validator` |
| `E-L6` | 允許的工具中有 licenses.yaml 狀態為「法務閘門」的元件時，`legal_review.scope.component_licenses` 必須是 true（L-6） | `test_validator` |
| `E-ROE-DATA-CLASS` | `data_handling.data_class` 必須等於委任的 `data_class` | `test_bl66_run_gates` |
| `E-ROE-DB` | `db_access.target_id` 必須是 database 目標且 endpoint 字串與 `db_access.endpoint` 相同；`oracle_readonly_attested` 為 true；`seed_manifest_ref` 等於 seed manifest 的 `manifest_ref`；manifest 的 `db_target_id`、`engagement_id` 一致；每個 oracle query 的資料表都在 ROE `oracle_tables` | `test_review_fixes` |
| `E-ROE-DB-SCOPE` | DB 目標的 `endpoint` 必須是可解析的 `host:port` 或 `[IPv6]:port`，主機不在 `exclusions.hosts` 中（比較前做結尾點、大小寫與 IDNA 正規化） | `test_review_fixes`、`test_v02_hardening`、`test_v03_scope` |
| `E-ROE-DENYLIST` | `activities.denied_modes` 必須包含工具包內建的拒絕清單（`safety.TOOLKIT_DENYLIST`） | `test_validator` |
| `E-ROE-EDGE-RANGE` | `targets[].edge_ip_ranges` 只用於 http 目標，每項是主機位元為 0 的 CIDR，且不與任何非公開網段重疊 | `test_v04_round5_trust` |
| `E-ROE-ENGAGEMENT` | ROE 的 `engagement.id`／`version` 必須等於 engagement.yaml 的 `engagement_id`／`version` | `test_bl66_run_gates` |
| `E-ROE-INCIDENT` | ROE `incident_response` 的聯絡人在金鑰登錄中，`covers` 含 data_exposure、third_party_side_effect、shared_platform_impact、staging_outage | `test_v04_legal_trust` |
| `E-ROE-MISSING` | 沒有 ROE；v0.5 起只在 bundle 含黑箱內容（測試案例、測試結果、威脅、G0b 以後的關卡紀錄或 `run.jobs`）時才是錯誤，純白箱 bundle 可以沒有 ROE | `test_v05_round6_lowprio` |
| `E-ROE-PLATFORM` | （同一條規則也涵蓋 `E-ROE-URL`、`E-ROE-WHOAMI`、`E-ROE-RELAY-MODE`、`E-ROE-SOD`）https（http 只限 localhost）；共用平台網域需 platform_project＋platform_policies；用到的角色需 whoami；adaptive relay 只在 full；ROE 簽署角色由不同人擔任；沒有 `technical_proof`（部署提供的 token 或回應標頭；資料庫用 `COMMENT ON DATABASE`）的共享平台目標只允許 S0 測試案例 | `test_v03_gates`、`test_v06_r7_methodology`、`test_v05_round6_group4` 等 4 份 |
| `E-ROE-RELAY` | `relay` 的 `max_turns`、`max_spend_usd_per_job`、`max_spend_usd_per_run` 不能超過工具包的 relay 上限；relay 模型必須在委任該資料等級的 `allowed_models` | `test_bl66_run_gates` |
| `E-ROE-RELAY-MODE` | （同一條規則也涵蓋 `E-ROE-URL`、`E-ROE-PLATFORM`、`E-ROE-WHOAMI`、`E-ROE-SOD`）https（http 只限 localhost）；共用平台網域需 platform_project＋platform_policies；用到的角色需 whoami；adaptive relay 只在 full；ROE 簽署角色由不同人擔任；沒有 `technical_proof`（部署提供的 token 或回應標頭；資料庫用 `COMMENT ON DATABASE`）的共享平台目標只允許 S0 測試案例 | `test_v03_gates` |
| `E-ROE-RETENTION` | ROE `data_handling.retention_days` 不得長於委任的 `retention_days`（ROE 只能縮短） | `test_v02_hardening`、`test_review_fixes` |
| `E-ROE-S3` | `activities.allowed_safety_classes` 永遠不能含 S3 | `test_bl66_run_gates` |
| `E-ROE-SEED-MANIFEST` | （同一條規則也涵蓋 `E-SEED-SIDE-EFFECT`）ROE `db_access.seed_manifest_sha256` 等於 seed manifest 的內容 hash；W0 inventory 中 `writes: true` 的 GET／HEAD 端點都列在 `state_changing_reads`；審查 r7 1.5：W0 標為 `writes: true` 的端點不能列在 `read_only_endpoints` | `test_v04_round5_examples`、`test_v04_write_scope` |
| `E-ROE-SIGNATORIES` | ROE 簽署人的角色必須涵蓋 G0b 的必要角色（test_lead、management、infrastructure_owner） | `test_bl66_run_gates` |
| `E-ROE-SOD` | （同一條規則也涵蓋 `E-ROE-URL`、`E-ROE-PLATFORM`、`E-ROE-WHOAMI`、`E-ROE-RELAY-MODE`）https（http 只限 localhost）；共用平台網域需 platform_project＋platform_policies；用到的角色需 whoami；adaptive relay 只在 full；ROE 簽署角色由不同人擔任；沒有 `technical_proof`（部署提供的 token 或回應標頭；資料庫用 `COMMENT ON DATABASE`）的共享平台目標只允許 S0 測試案例 | `test_v03_gates` |
| `E-ROE-STOP` | `stop_conditions` 中與工具包預設同名的數值只能更嚴（`min_*` 不低於預設，其他不高於預設）；`contacts` 不能是空的 | `test_v06_r7_methodology` |
| `E-ROE-TARGETS` | ROE 目標的 ID 不重複；HTTP 目標只有 `base_url`、DB 目標只有 `endpoint`；所有權證明的方法與目標種類相符（DB 用 `db_comment`／`platform_project`） | `test_v05_round6_group4`、`test_v03_scope`、`test_review_fixes` |
| `E-ROE-TOOLS` | `allowed_tools` 每一項都必須是 tools.yaml 中有 B4 可執行模式的工具；`denied_modes` 每一項都必須已登錄 | `test_bl66_run_gates` |
| `E-ROE-TRANSFER` | （同一條規則也涵蓋 `E-ENG-TRANSFER`）data_class C 時，每個能收 C 級資料的雲端（非 Z4）家族有 `providers[].region` 與同區域的 `data_transfer.transfers[]`；跨出 `source_jurisdiction` 需要 `same_jurisdiction` 以外的機制與 reference；聲明者是委任設定簽署人。委任設定宣告跨境傳輸時，ROE `legal_review.scope.cross_border` 必須為 true | `test_v04_legal_trust` |
| `E-ROE-URL` | （同一條規則也涵蓋 `E-ROE-PLATFORM`、`E-ROE-WHOAMI`、`E-ROE-RELAY-MODE`、`E-ROE-SOD`）https（http 只限 localhost）；共用平台網域需 platform_project＋platform_policies；用到的角色需 whoami；adaptive relay 只在 full；ROE 簽署角色由不同人擔任；沒有 `technical_proof`（部署提供的 token 或回應標頭；資料庫用 `COMMENT ON DATABASE`）的共享平台目標只允許 S0 測試案例 | `test_v03_scope` |
| `E-ROE-VALIDITY` | ROE 的 `not_before` 必須早於 `not_after`，且有效期間落在委任有效期間內 | `test_bl66_run_gates` |
| `E-ROE-WHOAMI` | （同一條規則也涵蓋 `E-ROE-URL`、`E-ROE-PLATFORM`、`E-ROE-RELAY-MODE`、`E-ROE-SOD`）https（http 只限 localhost）；共用平台網域需 platform_project＋platform_policies；用到的角色需 whoami；adaptive relay 只在 full；ROE 簽署角色由不同人擔任；沒有 `technical_proof`（部署提供的 token 或回應標頭；資料庫用 `COMMENT ON DATABASE`）的共享平台目標只允許 S0 測試案例 | `test_v03_gates` |
| `E-ROE-WINDOW` | 每個 `windows[]` 的時區與 HH:MM 時間必須可解析，start 不等於 end，`days` 非空且都是合法的星期 | `test_v03_robustness` |
| `W-L2-MANAGEMENT` | `legal_review.attested_by` 沒有 legal_reviewer 角色而以 management 身分證明：報告中必須標示 | `test_bl66_run_gates` |
| `W-L5-LITE` | Lite 委任中法務審查聲明由兼任測試負責人的同一人簽署（警告）；報告首頁必須寫明聲明為自行簽署 | `test_v03_gates`、`test_bl60_variants` |

**委任**

| 錯誤碼 | 規則 | 守住的測試 |
|---|---|---|
| `E-ENG-BUDGET` | 每一層 `max_cost_usd` 等上限必填、階段上限不超過 run_total；`budgets.families` 的家族是 models.yaml 的家族、上限不超過 run_total | `test_v05_schema_backlog`、`test_v03_gates` |
| `E-ENG-CONFIG-PIN` | `config_pins` 另釘 `toolkit`（toolkit.yaml）；`E-TOOLKIT`：`gate_queues.g2/g3/g4_max_items` ≥ 1<br>engagement `config_pins` 等於 models／agents／tools／licenses 的內容 hash（sha256(JCS)）；v0.5 加入 calibration、crosswalk（決定裁決與威脅連結） | `test_v04_legal_trust`、`test_v05_round6_group2`、`test_v07_r8_integrity` |
| `E-ENG-DATA-CLASS` | `data_class` 必須是 P 或 C | `test_bl66_trust` |
| `E-ENG-LANE-A` | `lane_a_model` 必須在該資料等級的 `allowed_models` | `test_bl66_trust` |
| `E-ENG-MISSING` | bundle 沒有 engagement.yaml | `test_bl66_trust` |
| `E-ENG-MODEL-CLASS` | `allowed_models.<等級>` 列出的模型必須能收該等級的資料（models.yaml `data_classes`） | `test_bl66_trust` |
| `E-ENG-OWASP` | `owasp_llm_version` 只能是 null、2025 或 2026 | `test_bl66_trust` |
| `E-ENG-OWNERSHIP` | `code_ownership.attested_by` 必須是 app_owner、同時是委任的簽署人，且 `attestation` 為 true | `test_bl66_trust` |
| `E-ENG-PRICING` | 第十三輪外部審查（[08 §11.12](../08-implementation-spec.md#1112-成本模型與價格)）：`agents.yaml` 用到的模型（含 `fallback_models` 與 `models.yaml` 的 `fallback` 鏈）若 `hosting: cloud` 且 `pricing: null`，委任設定必須有 `budgets.price_assumptions.<model_key>`（兩個單價都 > 0、鍵是 models.yaml 的模型），否則 USD 上限無法強制，run 拒絕；之前文件稱 fail-closed，但價格未知的模型照跑、只在報告寫「費用不完整」 | `test_v07_r13_external` |
| `E-ENG-PROFILE` | （同一條規則也涵蓋 `E-ENG-PROVIDER`、`E-PROFILE-SAFETY`）能收 C 級資料的雲端模型需 ZDR confirmed＋DPA（自架＝`api_base` 主機完全等於 toolkit.yaml `z4_model_hosts` 的一項，v0.4）；role_consolidation 只在 lite；lite 只允許 S0／S1（MANUAL 除外）；`W-L5-LITE`：lite 且 acknowledged 時法務自證只是警告 | `test_v03_gates` |
| `E-ENG-PROVIDER` | （同一條規則也涵蓋 `E-ENG-PROFILE`、`E-PROFILE-SAFETY`）能收 C 級資料的雲端模型需 ZDR confirmed＋DPA（自架＝`api_base` 主機完全等於 toolkit.yaml `z4_model_hosts` 的一項，v0.4）；role_consolidation 只在 lite；lite 只允許 S0／S1（MANUAL 除外）；`W-L5-LITE`：lite 且 acknowledged 時法務自證只是警告 | `test_v03_gates`、`test_v04_validator` |
| `E-ENG-PUBLISH` | `publishing` 關閉時 platform 為 null、token_scopes 為空；開啟時平台為 github、權杖範圍只能是 metadata:read／issues:write／pull_requests:write | `test_v05_schema_backlog` |
| `E-ENG-SIGNATORIES` | 簽署人的角色必須涵蓋 G0a 的必要角色（app_owner、management） | `test_bl66_trust` |
| `E-ENG-TELEMETRY` | `telemetry_disabled` 必須是 true | `test_bl66_trust` |
| `E-ENG-TIMEOUT` | `gate_timeouts_hours` 每一關都不能超過 toolkit.yaml 的上限 | `test_validator` |
| `E-ENG-TRANSFER` | （同一條規則也涵蓋 `E-ROE-TRANSFER`）data_class C 時，每個能收 C 級資料的雲端（非 Z4）家族有 `providers[].region` 與同區域的 `data_transfer.transfers[]`；跨出 `source_jurisdiction` 需要 `same_jurisdiction` 以外的機制與 reference；聲明者是委任設定簽署人。委任設定宣告跨境傳輸時，ROE `legal_review.scope.cross_border` 必須為 true | `test_v04_legal_trust` |
| `E-ENG-VALIDITY` | `validity.not_before` 必須早於 `not_after`，且 `issued_at` 不晚於有效期間結束 | `test_bl66_trust` |
| `E-PROFILE-SAFETY` | （同一條規則也涵蓋 `E-ENG-PROVIDER`、`E-ENG-PROFILE`）能收 C 級資料的雲端模型需 ZDR confirmed＋DPA（自架＝`api_base` 主機完全等於 toolkit.yaml `z4_model_hosts` 的一項，v0.4）；role_consolidation 只在 lite；lite 只允許 S0／S1（MANUAL 除外）；`W-L5-LITE`：lite 且 acknowledged 時法務自證只是警告 | `test_v03_gates` |
| `E-RETENTION` | 委任的 `retention_days` 在 1 到 `toolkit.yaml` 該資料等級的保留上限之間（委任只能縮短）；工具包必須為每個資料等級定義上限 | `test_v02_hardening` |

**簽章與金鑰登錄**

| 錯誤碼 | 規則 | 守住的測試 |
|---|---|---|
| `E-KR-ALG` | 登錄項目的 `alg` 必須是 ed25519 | `test_bl66_trust` |
| `E-KR-AUTOMATION` | 自動化帳號不能持有人員金鑰 | `test_bl66_trust` |
| `E-KR-DUP` | 登錄中的金鑰指紋不能重複 | `test_bl66_trust` |
| `E-KR-FP` | `fingerprint` 必須等於由 `public_key` 計算出的指紋 | `test_validator` |
| `E-KR-LOCATION` | 登錄的 `registry_id` 與 engagement／ROE 的 `key_registry_ref` 必須等於 toolkit `key_registry.location`，且該檔案存在 | `test_bl66_trust` |
| `E-KR-MISSING` | bundle 沒有金鑰登錄 | `test_bl66_trust` |
| `E-KR-REVOCATION` | `revoked_at` 與 `revocation_reason` 必須同時設定或同時為 null；`revoked_at` 不能晚於登錄的 `issued_at` | `test_bl66_trust` |
| `E-KR-ROLLBACK` | 登錄的 `version` 必須是整數且 ≥ toolkit `key_registry.min_version`（防回滾）；審查 r12：也必須 ≥ 每個 run 已錨定的 `key_registry_loaded.version`——bundle 帶的登錄比 run 當時載入的舊，就是回滾（BL-43 不再只靠人記得調高 `min_version`） | `test_v07_r12_run`、`test_validator` |
| `E-KR-ROOT-PIN` | `org_root_public_key` 的指紋必須等於 toolkit `org_root_key.fingerprint` 的釘選值 | `test_validator` |
| `E-KR-ROOT-SIG` | 登錄必須恰好有一個由釘選根金鑰（`org_root`）做的簽章，且驗證通過 | `test_bl66_trust` |
| `E-KR-SERVICE` | `z3_executor` 角色只能由服務身分 `z3-executor` 單獨持有；服務身分不是人員，不能出現在任何人員欄位 | `test_v05_round6_group3` |
| `E-KR-VALIDITY` | 登錄項目的 `not_before` 必須早於 `not_after` | `test_bl66_trust` |
| `E-SIG-BACKDATED` | 委任設定或 ROE 的簽章金鑰後來以非 `compromised` 原因撤銷時，該文件第一次被驗章（G0a／G0b 紀錄的收件時間）必須早於 `revoked_at`；v0.5 對 `not_after` 也一樣（首次驗章時金鑰已到期，或從未驗章而登錄顯示已到期） | `test_v04_round5_trust`、`test_v05_round6_group3` |
| `E-SIG-BAD` | `alg` 不是 ed25519，或 Ed25519 簽章驗證失敗 | `test_v05_schema_backlog`、`test_v07_r12_flow`、`test_validator` |
| `E-SIG-COMPROMISED` | 簽章金鑰以 `compromised` 撤銷：該金鑰的所有簽章一律無效 | `test_v04_round5_trust`、`test_validator` |
| `E-SIG-EXPIRED` | 沒有有效的簽章時間，或簽章時間落在金鑰的 `not_before`..`not_after` 之外 | `test_bl66_trust` |
| `E-SIG-EXTRA` | 簽章者不是文件預期的簽署人，或不是關卡紀錄的核准者 | `test_v05_round6_group3` |
| `E-SIG-ISSUED-AT` | 委任設定／ROE 的 `issued_at` 不能晚於首次驗章（G0a／G0b 收件時間）超過時鐘容差 | `test_v05_round6_group3` |
| `E-SIG-MISSING` | 預期的簽署人或關卡核准者沒有簽章 | `test_v05_round6_group3` |
| `E-SIG-REVOKED` | 金鑰以 `compromised` 以外的原因撤銷，且簽章時間不早於 `revoked_at` | `test_v05_r7_bypasses`、`test_v05_round6_group3`、`test_validator` |
| `E-SIG-ROLE` | 簽章金鑰在登錄中沒有所需的角色 | `test_v05_round6_lowprio`、`test_v05_schema_backlog` |
| `E-SIG-SIGNER` | 簽章的金鑰屬於 `signer` 以外的人員；稽核事件簽章的 `signer` 不等於 `actor.id` | `test_validator` |
| `E-SIG-UNKNOWN-KEY` | 簽章的 `key_fingerprint` 不在金鑰登錄中 | `test_bl66_trust` |

**人員參照**

| 錯誤碼 | 規則 | 守住的測試 |
|---|---|---|
| `E-PERSON-AUTOMATION` | 人員欄位不能是服務身分（z3_executor）或自動化帳號 | `test_v05_round6_group3` |
| `E-PERSON-KEY` | 人員參照所帶的金鑰指紋必須是該人員的登錄金鑰 | `test_bl66_trust` |
| `E-PERSON-ROLE` | 人員參照的角色必須是金鑰登錄授予該人員的角色 | `test_bl66_trust` |
| `E-PERSON-UNKNOWN` | person_id 必須在金鑰登錄中；ROE `upstream_llm_providers[].terms_confirmed_by` 也必須是登錄人員 | `test_bl66_trust` |

**代理與模型**

| 錯誤碼 | 規則 | 守住的測試 |
|---|---|---|
| `E-AGENT` | agents.yaml 的每個項目必須是物件 | `test_bl66_pipeline` |
| `E-AGENT-DATA-CLASS` | 代理的模型必須在委任該資料等級的 `allowed_models` | `test_bl66_pipeline` |
| `E-AGENT-FALLBACK` | 跨家族的 `fallback_models` 只能用在非裁決角色（reporter），每個 fallback 模型都必須已登錄且在允許清單 | `test_bl66_pipeline` |
| `E-AGENT-LANE-A` | agents.yaml `lane_a` 的模型必須等於委任的 `lane_a_model` | `test_bl66_pipeline` |
| `E-AGENT-MODEL` | 確定性角色（aggregator、scope_proxy、executor）的 `model` 必須是 null；LLM 角色必須有模型 | `test_bl66_pipeline` |
| `E-AGENT-ROLES` | bundle 有 W4 結果時，agents.yaml 必須登錄 `test_generator` 與 `test_critic`；作者不明的 W4 測試不算獨立（`derive.authors_independent`），審查 r9 把空的作者集合當成「在叢集之外」 | `test_v07_r10_contracts`、`test_v07_r10_verdict` |
| `E-AGENT-TOOLS` | reviewer／verifier 只能 read_slice；commander 沒有工具；invariant_drafter 不能 read_slice | `test_v03_manifest` |
| `E-DIVERSITY-VERIFIER` | 每個 reviewer 都必須有一個能收該資料等級、家族不同且基礎血統不同的 verifier | `test_v06_r7_calibration` |
| `E-LLM-SCHEMA` | 每個 LLM 輸出（`llm_schema.LLM_OUTPUTS`）的 schema 去掉 harness 擁有的欄位並降級後，只使用跨廠商共同支援的關鍵字 | `test_v03_llm_schema` |
| `E-MODEL` | models.yaml 的每個項目必須是物件 | `test_bl66_pipeline` |
| `E-MODEL-FALLBACK` | models.yaml `fallback` 的每個模型都必須已登錄，且與本模型同家族 | `test_bl66_pipeline` |
| `E-MODEL-FALLBACK-CLASS` | （同一條規則也涵蓋 `E-PROVENANCE`、`E-MODEL-RETIREMENT-DATE`、`E-RESULT-ANALYST-ROLE`）threat.modeled_by／invariants.drafted_by 對應登錄；fallback 鏈上的模型都能收該資料等級且在允許清單；退役日期格式；Result Analyst 必須是 result_analyst 角色 | `test_v03_manifest` |
| `E-MODEL-LINEAGE` | models.yaml 的 `derived_from` 必須是登錄中的另一個血統，而且不能形成循環（A → B → A 會讓兩者各自成為根、互相驗證）；審查 r9 外部 2：同一血統的所有模型宣告相同的 `derived_from`（v0.7 取檔案中最後一筆，調換 models.yaml 的順序就改變根） | `test_v07_r8_validator`、`test_v07_r9_verdict` |
| `E-MODEL-NIM` | `nvidia_nim/` 開頭的模型（build.nvidia.com 試用端點）只能收 P 級資料，且不能用於 production | `test_bl66_pipeline` |
| `E-MODEL-PLACEHOLDER` | models.yaml 的 `litellm` 看起來是佔位值（`<...>`、`{...}`、TBD、TODO、FIXME、實作時確認）時必須標 `placeholder: true`；真實 run（`--real-run`）中任何 agent 可達的佔位模型（主要或 fallback）是錯誤 | `test_review_fixes`、`test_v02_hardening` |
| `E-MODEL-RETIRED` | 被代理使用或在允許清單中的模型，其 `earliest_retirement` 早於委任開始 | `test_validator` |
| `E-MODEL-RETIREMENT-DATE` | （同一條規則也涵蓋 `E-PROVENANCE`、`E-MODEL-FALLBACK-CLASS`、`E-RESULT-ANALYST-ROLE`）threat.modeled_by／invariants.drafted_by 對應登錄；fallback 鏈上的模型都能收該資料等級且在允許清單；退役日期格式；Result Analyst 必須是 result_analyst 角色 | `test_v03_robustness` |
| `E-MODEL-STORE` | 能收 C 級資料的 `openai/` 模型必須設 `store: false` | `test_validator` |
| `E-MODEL-UNKNOWN` | 委任設定 `allowed_models` 與 agents.yaml 引用的模型必須在 models.yaml 中，而且能接收該資料等級 | `test_validator` |
| `E-PROVENANCE` | （同一條規則也涵蓋 `E-MODEL-FALLBACK-CLASS`、`E-MODEL-RETIREMENT-DATE`、`E-RESULT-ANALYST-ROLE`）threat.modeled_by／invariants.drafted_by 對應登錄；fallback 鏈上的模型都能收該資料等級且在允許清單；退役日期格式；Result Analyst 必須是 result_analyst 角色 | `test_v03_manifest` |
| `W-DIVERSITY` | 能收該資料等級的 reviewer 家族少於 2 個：多樣性降級（裁決受上限限制） | `test_bl66_pipeline` |
| `W-MODEL-PLACEHOLDER` | models.yaml 有標示 `placeholder: true` 的模型 ID（警告）；真實 run 前必須換成真實 ID | `test_bl60_variants`、`test_v02_hardening`、`test_bl60_suspend` 等 6 份 |
| `W-MODEL-RETIREMENT` | 被代理使用或在允許清單中的模型，其 `earliest_retirement` 落在委任有效期間內 | `test_validator` |

**白箱產物：盤點、計畫、發現項、切片、叢集、W4、種子**

| 錯誤碼 | 規則 | 守住的測試 |
|---|---|---|
| `E-CLUSTER-BASELINE` | （同一條規則也涵蓋 `E-CLUSTER-FINGERPRINT`）指紋＝sha256(JCS({cwe_bucket, file, symbol}))（black_box：{cwe_bucket, target_id, method, path_template}）；`baseline_state` 依 run `baseline_run_id` 推導；report `absent_fingerprints` | `test_v03_manifest` |
| `E-CLUSTER-BINDING` | 白箱叢集的 `canonical_location.file` 是成員證據的檔案、sink 落在成員證據的行範圍內、`file::name` 形式的 symbol 屬於該檔案、`cwe_bucket` 是某個成員 CWE 的桶（`facets.CWE_BUCKETS`）；同一 run 的叢集指紋不重複；審查 r7 1.6：同一個 run 內，一個發現項只能是一個叢集的成員 | `test_v05_round6_group6`、`test_v05_backlog_high`、`test_v05_r7_bypasses` |
| `E-CLUSTER-CARRY` | `carried_from` 只在 followup／regression run 中、指向 parent run 的叢集，fingerprint、桶、家族、血統相同；parent 有同指紋叢集而本 run 的叢集沒有 `carried_from` → 報錯。帶入的叢集沒有本 run 的成員，不做成員綁定與家族檢查；有成員 → 報錯（v0.7 第八輪允許掛成員卻不檢查證據綁定） | `test_v07_r8_integrity`、`test_v07_r9_anchor` |
| `E-CLUSTER-FAMILIES` | 叢集的 `families`／`lineages` 必須等於成員發現項回報者的家族與血統（由 agents.yaml 與 models.yaml 推導） | `test_v03_datamodel`、`test_v04_adjudication` |
| `E-CLUSTER-FINGERPRINT` | （同一條規則也涵蓋 `E-CLUSTER-BASELINE`）指紋＝sha256(JCS({cwe_bucket, file, symbol}))（black_box：{cwe_bucket, target_id, method, path_template}）；`baseline_state` 依 run `baseline_run_id` 推導；report `absent_fingerprints` | `test_v03_manifest` |
| `E-CLUSTER-ORIGIN` | white_box 叢集要有成員與程式位置；tool_only 叢集沒有成員、`tool_report_refs` 至少一筆能解析，`sarif_refs` 不能含回報或同一工具的結果，其他 origin 的 `tool_report_refs` 為空；black_box 叢集要有 threat_id（該威脅沒有 source_cluster_id）與 `canonical_location.endpoint`；沒有來源叢集的威脅，其測試結果（FAIL、PASS、INVALID 都一樣）記在該威脅的 black_box 叢集 | `test_v05_backlog_high`、`test_v03_adjudication`、`test_v07_r8_integrity` |
| `E-CLUSTER-SEVERITY` | `cluster.severity` 等於 validator 依 [08 §11.17](../08-implementation-spec.md#1117-確定性輔助規則) 推導的 rubric 嚴重度（`derive.rubric_severity`：桶的基本分、G1 資料分級與 PII、DFD 的網路邊界可達性、inventory 端點的認證需求；無法解析的輸入不降低分數）；G2 路由與 report_only 用它 | `test_v07_r8_validator` |
| `E-DFD` | DFD 元素 ID 不重複；只有 trust_boundary 有 `kind`；data_flow 的 from／to 與 `crosses` 都指向存在的元素；merged DFD 的 `b1_diff` 每項 kind 必須與 external／merged 兩個視角相符 | `test_v03_datamodel` |
| `E-FINDING-EVIDENCE` | （同一條規則也涵蓋 `E-FINDING-MATCH`、`E-FINDING-STATUS`、`E-FINDING-FACET`）證據 kind 的欄位；code_snippet 至少 12 個非空白字元並含 3 字元以上的識別字，`file` 在發現項的切片中；inventory_fact 由 inventory 重算 match；status 由 match 推導；facet 與叢集 CWE 桶（`FACET_BUCKETS`） | `test_v03_datamodel`、`test_v04_validator` |
| `E-FINDING-FACET` | （同一條規則也涵蓋 `E-FINDING-EVIDENCE`、`E-FINDING-MATCH`、`E-FINDING-STATUS`）證據 kind 的欄位；code_snippet 至少 12 個非空白字元並含 3 字元以上的識別字，`file` 在發現項的切片中；inventory_fact 由 inventory 重算 match；status 由 match 推導；facet 與叢集 CWE 桶（`FACET_BUCKETS`） | `test_v03_datamodel` |
| `E-FINDING-MATCH` | （同一條規則也涵蓋 `E-FINDING-EVIDENCE`、`E-FINDING-STATUS`、`E-FINDING-FACET`）證據 kind 的欄位；code_snippet 至少 12 個非空白字元並含 3 字元以上的識別字，`file` 在發現項的切片中；inventory_fact 由 inventory 重算 match；status 由 match 推導；facet 與叢集 CWE 桶（`FACET_BUCKETS`） | `test_v03_datamodel` |
| `E-FINDING-REPORTER` | `reporter` 的代理、`model_key`、家族與血統必須與 agents.yaml／models.yaml 相符 | `test_bl66_pipeline` |
| `E-FINDING-ROUND` | 發現項的 `reporter.round` 由 run 的指揮官計畫推導（round 1＝CMD-1 派給該 agent 與切片；round n＞1＝round n−1 的 CMD-2 加派）；Lane A 不檢查 | `test_v05_round6_lowprio` |
| `E-FINDING-STATUS` | （同一條規則也涵蓋 `E-FINDING-EVIDENCE`、`E-FINDING-MATCH`、`E-FINDING-FACET`）證據 kind 的欄位；code_snippet 至少 12 個非空白字元並含 3 字元以上的識別字，`file` 在發現項的切片中；inventory_fact 由 inventory 重算 match；status 由 match 推導；facet 與叢集 CWE 桶（`FACET_BUCKETS`） | `test_v03_datamodel` |
| `E-INVARIANT-LEVEL` | （同一條規則也涵蓋 `E-INVARIANT-REF`）L2 以上的 ASVS／AISVS 需求由 baseline_levels 或 level_triggers 涵蓋；llm_tools 的資料分級、access_matrix.ownership | `test_v03_datamodel` |
| `E-INVARIANT-REF` | （同一條規則也涵蓋 `E-INVARIANT-LEVEL`）L2 以上的 ASVS／AISVS 需求由 baseline_levels 或 level_triggers 涵蓋；llm_tools 的資料分級、access_matrix.ownership | `test_v03_datamodel` |
| `E-INVENTORY` | （同一條規則也涵蓋 `E-INVENTORY-REF`）inventory 內部參照（middleware、來源檔、public_prefix；v0.5 BL-19：`kind: scheduled` 沒有 method、path 為 `schedule:`／`queue:`，其他 kind 必須有 method）；finding／threat／DFD 的 inventory JSON Pointer 必須可解析 | `test_v05_schema_backlog`、`test_v03_datamodel`、`test_v05_r7_bypasses` |
| `E-INVENTORY-REF` | （同一條規則也涵蓋 `E-INVENTORY`）inventory 內部參照（middleware、來源檔、public_prefix；v0.5 BL-19：`kind: scheduled` 沒有 method、path 為 `schedule:`／`queue:`，其他 kind 必須有 method）；finding／threat／DFD 的 inventory JSON Pointer 必須可解析 | `test_v03_datamodel` |
| `E-PLAN-AGENTS` | （同一條規則也涵蓋 `E-PLAN-FACETS`、`E-PLAN-TARGET`、`E-PLAN-ROUNDS`、`E-PLAN-BUDGET`）計畫每個切片涵蓋 `MANDATORY_FACETS`；型別化目標；輪次 ≤ 2；代理角色；token 預算 ≤ run 階段預算 | `test_v03_manifest` |
| `E-PLAN-BUDGET` | （同一條規則也涵蓋 `E-PLAN-FACETS`、`E-PLAN-TARGET`、`E-PLAN-ROUNDS`、`E-PLAN-AGENTS`）計畫每個切片涵蓋 `MANDATORY_FACETS`；型別化目標；輪次 ≤ 2；代理角色；token 預算 ≤ run 階段預算 | `test_v03_manifest` |
| `E-PLAN-COVERAGE` | （同一條規則也涵蓋 `E-PLAN-FAMILIES`）CMD-1 計畫涵蓋 run 的每個切片；每個切片的 reviewer 至少 min(2, 合格 reviewer 家族數) 個家族（合格＝reviewer 角色、模型在 engagement 該資料等級的 `allowed_models`、不在切片 `excluded_models`） | `test_v04_validator` |
| `E-PLAN-FACETS` | （同一條規則也涵蓋 `E-PLAN-TARGET`、`E-PLAN-ROUNDS`、`E-PLAN-AGENTS`、`E-PLAN-BUDGET`）計畫每個切片涵蓋 `MANDATORY_FACETS`；型別化目標；輪次 ≤ 2；代理角色；token 預算 ≤ run 階段預算 | `test_v03_datamodel`、`test_v04_round5_examples`、`test_v04_validator` |
| `E-PLAN-FAMILIES` | （同一條規則也涵蓋 `E-PLAN-COVERAGE`）CMD-1 計畫涵蓋 run 的每個切片；每個切片的 reviewer 至少 min(2, 合格 reviewer 家族數) 個家族（合格＝reviewer 角色、模型在 engagement 該資料等級的 `allowed_models`、不在切片 `excluded_models`） | `test_v04_validator` |
| `E-PLAN-ROUNDS` | （同一條規則也涵蓋 `E-PLAN-FACETS`、`E-PLAN-TARGET`、`E-PLAN-AGENTS`、`E-PLAN-BUDGET`）計畫每個切片涵蓋 `MANDATORY_FACETS`；型別化目標；輪次 ≤ 2；代理角色；token 預算 ≤ run 階段預算 | `test_v03_manifest` |
| `E-PLAN-TARGET` | （同一條規則也涵蓋 `E-PLAN-FACETS`、`E-PLAN-ROUNDS`、`E-PLAN-AGENTS`、`E-PLAN-BUDGET`）計畫每個切片涵蓋 `MANDATORY_FACETS`；型別化目標；輪次 ≤ 2；代理角色；token 預算 ≤ run 階段預算 | `test_v03_manifest` |
| `E-SARIF-REF` | 叢集的 `sarif_refs`／`tool_report_refs` 必須解析到 W1 已錨定的工具輸出中存在的結果 | `test_v05_backlog_high`、`test_v04_validator`、`test_review_fixes` 等 5 份 |
| `E-SEED-MANIFEST` | create_only_endpoints、state_changing_reads、read_only_endpoints 的目標必須是 ROE 的 http 目標；create_only_endpoints 的 `created_resource` 必填且合法（`id_pointer` 是 token 非空的 JSON Pointer；每條 `path_templates` 恰有一段 `{created_id}`，其他變數段來自建立路徑） | `test_v05_round6_group0`、`test_v03_scope` |
| `E-SEED-SENSITIVE` | seed `sensitive_fields` 的 phone／account 至少 6 位數字；同一正規化值不登記在兩個種子 | `test_v05_schema_backlog` |
| `E-SEED-SIDE-EFFECT` | （同一條規則也涵蓋 `E-ROE-SEED-MANIFEST`）ROE `db_access.seed_manifest_sha256` 等於 seed manifest 的內容 hash；W0 inventory 中 `writes: true` 的 GET／HEAD 端點都列在 `state_changing_reads`；審查 r7 1.5：W0 標為 `writes: true` 的端點不能列在 `read_only_endpoints` | `test_v04_write_scope`、`test_v05_r7_bypasses`、`test_v05_round6_lowprio` |
| `E-SLICE-EXCLUDED` | 切片以 data_class 理由排除的模型，必須確實不能收該 run 的資料等級 | `test_bl66_pipeline` |
| `E-SLICE-IDENTITY` | （同一條規則也涵蓋 `E-RUN-CONFIG`、`E-RUN-RULE-VERSION`）run config_refs 指向正確種類的檔案；不能是 null，`invariants`／`seed_manifest` 可為 pending（`expected_node` 是產生節點 G1／G0b，且 run 尚未到達）或 not_applicable（invariants 只限 Lane A；seed_manifest 只限沒有 B 階段內容的 run）；tool_versions 已登錄且與稽核一致；rule_version＝`05-v0.5`；切片的 prompt 範本與 redaction map 屬於本 run | `test_v03_manifest` |
| `E-W4-AUDIT` | W4 結果恰好對應一筆已錨定的 W4／Z2 `sandbox_job_end`（同 result_id、testcase_id、outcome），`executed_at` 在該 job 的開始與結束之間；審查 r7 1.10：該事件另釘住 testcase、artifact 與結果的 hash<br>（同一條規則也涵蓋 `E-W4-COVERAGE`）run 完成（`COMPLETED`／`COMPLETED_WITH_GAPS`）後，每份 w4-testcase 都要有 W4 結果（結果再由 `E-W4-AUDIT` 綁到已錨定的 Z2 `sandbox_job_end`），否則它引用的不變量沒有被測過、必須列為 MANUAL；每筆 W4 `sandbox_job_end` 指名本 run 的 W4 結果，完成的 run 中每個開始的 W4 job 都有結束事件 | `test_v05_bl27_w4`、`test_v05_r7_bypasses`、`test_v07_r10_anchor` |
| `E-W4-COVERAGE` | run 有 W4 產物或種子威脅後，每條 G1 核准的不變量有 W4 測試案例或列在 `w4_manual_requirements`（不能兩者都有）；MANUAL 只能列 G1 核准的不變量；審查 r11：到達 W4／W5 的 initial run 必須有自己的 G1 不變量（`invariants.yaml` 的 `run_id`），followup／regression run 以 `reuse[]` 帶入父 run 的 `invariants_ref` 才免檢<br>（同一條規則也涵蓋 `E-W4-AUDIT`）run 完成（`COMPLETED`／`COMPLETED_WITH_GAPS`）後，每份 w4-testcase 都要有 W4 結果（結果再由 `E-W4-AUDIT` 綁到已錨定的 Z2 `sandbox_job_end`），否則它引用的不變量沒有被測過、必須列為 MANUAL；每筆 W4 `sandbox_job_end` 指名本 run 的 W4 結果，完成的 run 中每個開始的 W4 job 都有結束事件 | `test_v05_bl27_w4`、`test_v07_r10_anchor`、`test_v07_r11_anchor` |
| `E-W4-OBSERVATION` | W4 結果宣告 `observations_source`（harness／sut）；`sut` 的結果在 `classify_result` 只能是 `E_inc` | `test_v07_r8_integrity` |
| `E-W4-TC` | W4 測試案例的 run 存在、叢集是同 run 的 white_box／tool_only 叢集、oracle 只引用 requirement_ids、local_rls 有拋棄式 Postgres 與 inventory 中的 migration；W4 結果不借用黑箱測試案例、只掛在測試案例的叢集上；審查 r7 1.3：local_rls 以外的種類要宣告 `target_files`（inventory 中的檔案），每個叢集的 `canonical_location.file` 必須在 target_files（local_rls 另加 migration）之內 | `test_v05_bl27_w4`、`test_v05_r7_bypasses` |
| `W-CLUSTER-BUCKET` | 成員的 CWE 都不在 `facets.CWE_BUCKETS`，`cwe_bucket` 無法檢查 | `test_bl66_pipeline` |

**威脅、追溯與對照表**

| 錯誤碼 | 規則 | 守住的測試 |
|---|---|---|
| `E-COVERAGE-D5` | run 有 G4 紀錄後，每個最新 G3 決定為 accept 的威脅都有測試案例（含 MANUAL） | `test_v05_round6_lowprio` |
| `E-THREAT-ATTACK-TREE` | likelihood high＋impact high 的威脅必須有 `attack_tree_ref`；`attack_tree_ref` 指向該威脅自己的 `…/<threat_id>.json` | `test_v05_round6_lowprio` |
| `E-THREAT-LLM-LINK` | ACCEPTED 的威脅不能有 llm-suggested 的對照連結 | `test_bl66_pipeline` |
| `E-THREAT-REVIEW` | （同一條規則也涵蓋 `E-TC-REQ-UNAPPROVED`、`E-TC-SCRIPT`）威脅的 review 必須是決定它的 G3 紀錄；testcase 只能引用 G1 核准的需求；scripted relay 需要 script_turns | `test_v03_gates` |
| `E-TRACE` | 測試結果的 `cluster_ids` 必須含威脅的來源叢集，而且只能列該威脅的叢集（來源叢集與威脅以 `evidence.kind: cluster` 引用的叢集）；不能掛到無關的叢集改寫它的裁決 | `test_v07_r12_examples`、`test_v05_bl27_w4`、`test_v05_round6_group1` 等 6 份 |
| `E-TRACE-DFD` | 威脅的 `dfd_elements` 必須存在於 merged DFD，且型別相同 | `test_v07_r9_examples` |
| `E-TRACE-INVARIANT` | invariants.yaml 每條不變量的 `signoff`（`gate_record_id` 與狀態）必須與 G1 紀錄的決定相符；以 `carried_from` 沿用的決定，`signoff` 指向來源紀錄 | `test_bl66_pipeline` |
| `E-TRACE-REQUIREMENT` | `source: invariant` 的 requirement 必須與 invariants.yaml 的項目完全相同；其他 requirement 的 source、ref、level 必須與 baseline 項目相符 | `test_bl66_pipeline` |
| `E-TRACE-SEED` | seed-threats 每個種子的叢集、裁決、威脅、狀態與 CWE 桶必須互相相符；來源叢集屬於種子文件的 run | `test_v07_r9_anchor` |
| `E-TRACE-THREAT-REVIEW` | 威脅的 `review.status` 與 `gate_record_id` 必須與決定它的 G3 紀錄相符（accept → ACCEPTED，reject／over_cap → REJECTED，其他 → NEEDS_INFO）；以 `carried_from` 沿用的決定指向來源紀錄 | `test_v07_r8_validator`、`test_v05_round6_group4` |
| `E-XWALK-DUP` | crosswalk.yaml 的連結（from_scheme、from_id、target_scheme、target_id）不能重複 | `test_bl66_pipeline` |
| `E-XWALK-OWASP` | crosswalk 的 `owasp_llm_default` 必須等於 toolkit；`owasp-llm@` 的版本只能是 2025 或 2026；威脅的 `owasp-llm@` 分類版本必須等於 initial run 的 `owasp_llm_version` | `test_bl66_pipeline` |
| `E-XWALK-REVIEW` | crosswalk 與威脅的對照連結：curated 必須有 `reviewed_by`，llm-suggested 不得有 | `test_bl66_pipeline` |

**測試案例**

| 錯誤碼 | 規則 | 守住的測試 |
|---|---|---|
| `E-TC-ACCESS-CELL` | testcase／w4-testcase 的 `access_cells` 每格都在 G1 存取矩陣中 | `test_v05_schema_backlog`、`test_bl47_access_matrix` |
| `E-TC-ADMISSIBLE` | 重算的安全等級必須是 ROE 允許進入 G4 的等級（`safety.admissible`） | `test_validator`、`test_v03_scope`、`test_v04_validator` |
| `E-TC-CONTROLS` | （同一條規則也涵蓋 `E-RESULT-CONTROLS`、`E-RESULT-INVALID`、`E-RESULT-PRECONDITION`）testcase 至少一個 reachability 對照；結果恰好涵蓋所有對照；任何對照沒有 PASS → outcome 必須是 INVALID；`precondition_reached`＝所有 reachability 對照 PASS；`positive_control`＝oracle_can_fail 對照 PASS（沒有時為 null） | `test_v03_adjudication`、`test_v05_bl27_w4` |
| `E-TC-DB` | `data_needed.db_tables` ⊆ ROE `db_access.oracle_tables`；oracle query 的資料表必須列在 `data_needed.db_tables` | `test_validator` |
| `E-TC-EXPECTED-STATUS` | `expected_error_statuses` 只能列 429 與 5xx（只有這些狀態碼可以不觸發 run 層級的停止條件） | `test_v06_r7_methodology` |
| `E-TC-MUTATION-SCOPE` | 變更請求只能經 `{seed:key}`（種子的 path_templates）或 create_only_endpoints＋`{created:step_id}`（同時 S3）；帶 `graphql_operation` 的請求必須送到 ROE `targets[].graphql_paths` 宣告的路徑、方法為 GET／POST；`object_refs` 的每一項是為這條路徑宣告的種子或較早的建立請求，路徑沒有變數段的寫入有有效的 `object_refs` 才在範圍內；`state_changing_reads` 的 GET 算寫入、`read_only_endpoints` 的 POST 算讀取；`{created:}` 只能用在建立端點 `created_resource.path_templates` 宣告的路徑（其他變數段等於建立請求的值）、建立的 `step_id` 不重複、GraphQL mutation 只用 POST；審查 r7：`object_refs` 中的 `{created:x}` 只用於 x 的 `created_resource.path_templates`（1.4）；沒有路徑變數的 PATCH／PUT／DELETE 必須以 query 的 `<id>=eq.<已綁定值>` 選取列，body 中的 ID 不算選取條件，只有 POST 可以由 body 綁定（1.8）；Server Action 的參照全部要能解析，引數以區分 JSON 型別的方式比對（`true` ≠ `1`，1.9） | `test_v03_scope`、`test_v05_round6_group0`、`test_v04_validator` |
| `E-TC-ORACLE` | `oracle.oracle_query_id` 必須在 seed manifest 的 `oracle_queries` 中；`oracle.requirement_refs` ⊆ 測試案例的 `requirement_ids` | `test_bl66_pipeline` |
| `E-TC-RATE` | `rate_limit.max_requests_per_trial` 在 1..`max_requests` 之間，機率型測試必填；重播預算＝`max_requests ＋ replay_n × max_requests_per_trial`（`safety.request_budget`），沒有宣告時每次重播以整個 job 計 | `test_v07_r8_validator` |
| `E-TC-RELAY` | `multi_turn` 測試案例需要 ROE relay 有模型，且 `trials.multi_turn_max_turns` 不超過 ROE `relay.max_turns`；非 `multi_turn` 的測試案例不能設 `multi_turn_max_turns` | `test_bl66_pipeline` |
| `E-TC-REQ-UNAPPROVED` | （同一條規則也涵蓋 `E-THREAT-REVIEW`、`E-TC-SCRIPT`）威脅的 review 必須是決定它的 G3 紀錄；testcase 只能引用 G1 核准的需求；scripted relay 需要 script_turns | `test_v03_gates`、`test_v05_bl27_w4` |
| `E-TC-ROLES` | `data_needed.roles` ⊆ ROE `test_roles` 的角色 | `test_bl66_pipeline` |
| `E-TC-SAFETY` | 安全等級重算寫入副作用沒有被圍住的種子 → ≥ S2（種子沒有宣告且 ROE 有未停用的 integration 時視為 external）；請求預算 `max_requests ＋ replay_n × ⌈max_requests／n⌉` 超過 `s1_request_cap` → ≥ S2；GraphQL 請求不是 POST，或沒有 `graphql_document_sha256` → S3 | `test_validator` |
| `E-TC-SCRIPT` | （同一條規則也涵蓋 `E-THREAT-REVIEW`、`E-TC-REQ-UNAPPROVED`）威脅的 review 必須是決定它的 G3 紀錄；testcase 只能引用 G1 核准的需求；scripted relay 需要 script_turns | `test_v03_gates` |
| `E-TC-SEEDS` | `seed_manifest_ref` 必填，且等於 ROE 的 `db_access.seed_manifest_ref`；沒有 manifest，安全等級計算看不到種子、`state_changing_reads` 與 `read_only_endpoints` | `test_v05_round6_group1` |
| `E-TC-TOOL` | `schemathesis:*` 的 `request_allowlist` 只有 GET／HEAD；`zap:baseline` 需要 `params.safe_mode: true`（`-S`） | `test_v05_round6_lowprio` |
| `E-TC-TRIALS` | `fail_k_min` 在 1..n 之間；審查 r7 3.3：機率型測試的 `trials.n` ≥ PASS 所需的有效次數（30；高風險威脅 60）；審查 r8 外部 2：機率型由受測功能判定（`derive.probabilistic_signals`：LLM 威脅——taxonomy 為 owasp-llm／owasp-asi 或來源叢集在 `llm_specific` 桶、LLM 測試 adapter、`multi_turn`、`trials.record` 含 `target_model`、`trials.sampling: sampled`），有任何訊號時 `trials.sampling: deterministic` 即報錯；審查 r9 外部 1：有訊號時 `trials.sampling` 必須是 `sampled`（未宣告也報錯）<br>（同一條規則也涵蓋 `E-CAL-THETA`、`E-CAL-WEIGHT`）每個桶的 θ_reject 高於該桶任何一張反駁票的權重；`generalised: true` 的保留切分 n ≥ 10。權重與 Wilson 下界以有效計數計算：一張棄權票算半對半錯（`checks.effective_counts`）。`trials.sampling: sampled` 不是機率型訊號，只宣告它而沒有目標側訊號（LLM 威脅、LLM 測試工具、multi_turn、`target_model` 紀錄）→ `E-TC-TRIALS` | `test_v07_r8_validator`、`test_v06_r7_adjudication`、`test_v07_r10_verdict` 等 4 份 |
| `E-TC-ZAP` | `zap:*` adapter 的 `params.delayInMs` 必須是整數且 ≥ ROE `rate_limits.zap_delay_ms_min`；`zap:active` 的 `maxScanDurationInMins` 必須在 1..`zap_max_scan_minutes`（不允許 0＝無上限） | `test_validator` |
| `E-TC-ZAP-THREADS` | `zap:*` 的 `threadPerHost` 有設定時必須在 1..ROE `rate_limits.max_concurrency` | `test_validator` |

**測試結果**

| 錯誤碼 | 規則 | 守住的測試 |
|---|---|---|
| `E-RESULT-ANALYST` | `interpreted_by` 的家族必須等於該代理模型的家族；`interpretation` 與 `interpreted_by` 必須同時有或同時沒有 | `test_bl66_pipeline` |
| `E-RESULT-ANALYST-ROLE` | （同一條規則也涵蓋 `E-PROVENANCE`、`E-MODEL-FALLBACK-CLASS`、`E-MODEL-RETIREMENT-DATE`）threat.modeled_by／invariants.drafted_by 對應登錄；fallback 鏈上的模型都能收該資料等級且在允許清單；退役日期格式；Result Analyst 必須是 result_analyst 角色 | `test_v03_adjudication` |
| `E-RESULT-BUILD` | （同一條規則也涵蓋 `E-RESULT-REQUEST-LOG`）observed_build_id＝run.repo_commit（完整或 ≥12 字元前綴）；build_identity none 的目標列入 build_unverified_targets；B4 結果需要請求紀錄 hash | `test_v03_scope` |
| `E-RESULT-CONTROLS` | （同一條規則也涵蓋 `E-TC-CONTROLS`、`E-RESULT-INVALID`、`E-RESULT-PRECONDITION`）testcase 至少一個 reachability 對照；結果恰好涵蓋所有對照；任何對照沒有 PASS → outcome 必須是 INVALID；`precondition_reached`＝所有 reachability 對照 PASS；`positive_control`＝oracle_can_fail 對照 PASS（沒有時為 null） | `test_v03_adjudication` |
| `E-RESULT-G4` | （同一條規則也涵蓋 `E-RESULT-G5`、`E-RESULT-WINDOW`、`E-RUN-G4`）審查 r7 1.2：以稽核事件的收件時間判斷：B4 job 的 `sandbox_job_start` 晚於**開始那一刻仍有效的**核准（`derive.g4_state`：最新決定是 accept，從哪一次 accept 起連續核准；之後相同內容的再次 accept 不移動它；外部審查），job 的開始與結束都在 ROE 的有效期間與時段內；S2 job 的開始與結束落在 G5 決定與該時段結束之間；`approved_testcase_ids` 是日誌末端最新 G4 決定為 accept 的測試案例（目前可派送）；執行後才被撤銷的核准不使已執行的結果失效，改報 `W-RESULT-G4-WITHDRAWN` | `test_v07_r11_external`、`test_v05_r7_bypasses` |
| `E-RESULT-G5` | （同一條規則也涵蓋 `E-RESULT-G4`、`E-RESULT-WINDOW`、`E-RUN-G4`）審查 r7 1.2：以稽核事件的收件時間判斷：B4 job 的 `sandbox_job_start` 晚於**開始那一刻仍有效的**核准（`derive.g4_state`：最新決定是 accept，從哪一次 accept 起連續核准；之後相同內容的再次 accept 不移動它；外部審查），job 的開始與結束都在 ROE 的有效期間與時段內；S2 job 的開始與結束落在 G5 決定與該時段結束之間；`approved_testcase_ids` 是日誌末端最新 G4 決定為 accept 的測試案例（目前可派送）；執行後才被撤銷的核准不使已執行的結果失效，改報 `W-RESULT-G4-WITHDRAWN` | `test_v05_r7_bypasses` |
| `E-RESULT-INVALID` | （同一條規則也涵蓋 `E-TC-CONTROLS`、`E-RESULT-CONTROLS`、`E-RESULT-PRECONDITION`）testcase 至少一個 reachability 對照；結果恰好涵蓋所有對照；任何對照沒有 PASS → outcome 必須是 INVALID；`precondition_reached`＝所有 reachability 對照 PASS；`positive_control`＝oracle_can_fail 對照 PASS（沒有時為 null） | `test_v03_adjudication` |
| `E-RESULT-JOB` | B4 結果的 `job_id` 必須是該 run 中同一測試案例的 job；W4 結果的 `job_id` 必須是 null | `test_bl66_pipeline` |
| `E-RESULT-ORACLE` | `fail_oracles` 非空 ⇔ outcome FAIL，且 ⊆ testcase `oracle.types` | `test_v03_adjudication` |
| `E-RESULT-PRECONDITION` | （同一條規則也涵蓋 `E-TC-CONTROLS`、`E-RESULT-CONTROLS`、`E-RESULT-INVALID`）testcase 至少一個 reachability 對照；結果恰好涵蓋所有對照；任何對照沒有 PASS → outcome 必須是 INVALID；`precondition_reached`＝所有 reachability 對照 PASS；`positive_control`＝oracle_can_fail 對照 PASS（沒有時為 null） | `test_v03_adjudication` |
| `E-RESULT-REQUEST-LOG` | （同一條規則也涵蓋 `E-RESULT-BUILD`）observed_build_id＝run.repo_commit（完整或 ≥12 字元前綴）；build_identity none 的目標列入 build_unverified_targets；B4 結果需要請求紀錄 hash | `test_v03_scope` |
| `E-RESULT-REQUESTS` | `request_count` 不能超過測試案例的 `rate_limit.max_requests` | `test_v03_robustness` |
| `E-RESULT-TARGETS` | `target_ids` ⊆ 測試案例的 `target_ids`；B4 結果至少有一個 ROE 目標，W4 結果（在 Z2 執行）不能有目標 | `test_v05_bl27_w4` |
| `E-RESULT-TRIALS` | `trials` 滿足 k ≤ `n_effective` ≤ n；機率型 PASS 以 `n_effective`（n′）≥ 30 判定 `E_pass`；高風險威脅（有 attack tree）≥ 60；v0.6 起機率型由測試對象判定（`derive.is_probabilistic`） | `test_v04_examples`、`test_v05_round6_group4`、`test_adjudicate` 等 4 份 |
| `E-RESULT-WINDOW` | （同一條規則也涵蓋 `E-RESULT-G4`、`E-RESULT-G5`、`E-RUN-G4`）審查 r7 1.2：以稽核事件的收件時間判斷：B4 job 的 `sandbox_job_start` 晚於**開始那一刻仍有效的**核准（`derive.g4_state`：最新決定是 accept，從哪一次 accept 起連續核准；之後相同內容的再次 accept 不移動它；外部審查），job 的開始與結束都在 ROE 的有效期間與時段內；S2 job 的開始與結束落在 G5 決定與該時段結束之間；`approved_testcase_ids` 是日誌末端最新 G4 決定為 accept 的測試案例（目前可派送）；執行後才被撤銷的核准不使已執行的結果失效，改報 `W-RESULT-G4-WITHDRAWN` | `test_v05_r7_bypasses` |

**裁決與回饋**

| 錯誤碼 | 規則 | 守住的測試 |
|---|---|---|
| `E-FEEDBACK` | 審查 r11：`assurance_profile: lite` 不能記錄 `false_positive`（兩人副簽在單人模式永遠不成立），只能用 `wont_fix`／`needs_info`；`sarif_suppression` 由 `checks.feedback_suppression` 推導：`false_positive` 只有在 `signed_by` 或 `co_signed_by` 是 `security_reviewer` 時才是 `accepted`，否則 `underReview`；審查 r9：一律兩個不同的人，其中一位是沒有核准該叢集 G2 決定的 `security_reviewer`；採用 run 中同指紋叢集 `baseline_state: updated` 時回到 `underReview`；副簽者是 `security_reviewer` 且不是簽署者本人；signatures 依序對應 signed_by、co_signed_by<br>回饋的 run 屬於同一委任、指紋是所指叢集的指紋、duplicate 指向另一個叢集、sarif_suppression 依標籤、恰好一個 signed_by 的簽章（簽章與角色另由 E-SIG-* 檢查）；審查 r7 1.11：採用回饋的 run（同委任的另一個 run）在稽核紀錄中恰好有一筆已錨定的 `feedback_recorded`，payload 的 `feedback_sha256` 等於回饋的內容 hash；簽章以該事件的收件時間驗證，`signed_at` 與收件時間相差不超過時鐘容差，收件時間不早於所指 run 的開始 | `test_v05_r7_bypasses`、`test_v05_schema_backlog`、`test_v07_r8_integrity` 等 4 份 |
| `E-VERDICT-ANNOTATIONS` | `annotations` 的 kind 集合必須等於裁決規則重算的結果 | `test_validator` |
| `E-VERDICT-CALIBRATION` | 裁決的 `calibration_version` 必須等於 calibration.yaml 的 `calibration_version` | `test_bl66_pipeline` |
| `E-VERDICT-CHAIN` | 同一叢集的裁決版本以 `supersedes_verdict_id` 形成單一線性鏈（不自我取代、不循環、不分岔、恰好一個最新版） | `test_v05_round6_group6` |
| `E-VERDICT-DIVERSITY` | 裁決的 `diversity_degraded` 必須等於由計權合格票的登錄家族與血統根推導的值，不採自填 | `test_v02_hardening` |
| `E-VERDICT-G2` | 有 `g2_decision_ref` 時必須是決定該叢集的最新 G2 紀錄；沒有時（且不是 `W3_adjudicate` 的版本），該叢集不能已有 G2 紀錄；`G2_apply` 版本一定要引用決定該叢集的 G2 紀錄<br>BL-60：G2 最新的決定是駁回時，該叢集最新的裁決版本必須在 G2 之後（`G2_apply` 或更晚的版本），不能還是 W3 版本 | `test_adjudicate`、`test_bl60_variants`、`test_v07_r9_anchor` |
| `E-VERDICT-NOELIGIBLE` | （同一條規則也涵蓋 `E-VERDICT-TOOLSIGNAL`、`E-VERDICT-SOURCES`、`E-VERDICT-PROVISIONAL`、`E-VERDICT-RULE-VERSION`）裁決的推導欄位（第 13 組） | `test_v03_adjudication` |
| `E-VERDICT-PHASE` | `readjudicated_by` 不能倒填：黑箱叢集只有 B5 版本；W3 版本不取代任何版本；白箱與 tool_only 叢集的第一版一定是 `W3_adjudicate`（標成 `G2_apply` 會跳過 G2 路由檢查）；階段只能往後；收件時間晚於 W4／B4 測試結果的版本至少是 W4／B5；審查 r7 1.2：B5 版本的收件時間晚於所連 B4 job 的 `sandbox_job_end` | `test_v05_round6_group6`、`test_v05_r7_bypasses`、`test_v07_r9_anchor` |
| `E-VERDICT-PROOF` | CONFIRMED_EXECUTABLE 的 `executable_proof.interpretation_confirmed_by` 有值時，其家族不能是叢集的家族之一 | `test_bl66_pipeline` |
| `E-VERDICT-PROVISIONAL` | （同一條規則也涵蓋 `E-VERDICT-TOOLSIGNAL`、`E-VERDICT-SOURCES`、`E-VERDICT-NOELIGIBLE`、`E-VERDICT-RULE-VERSION`）裁決的推導欄位（第 13 組） | `test_v03_adjudication`、`test_v04_round5_adjudication` |
| `E-VERDICT-RULE-VERSION` | （同一條規則也涵蓋 `E-VERDICT-TOOLSIGNAL`、`E-VERDICT-SOURCES`、`E-VERDICT-NOELIGIBLE`、`E-VERDICT-PROVISIONAL`）裁決的推導欄位（第 13 組） | `test_v03_adjudication`、`test_v03_manifest`、`test_v07_r8_calibration` |
| `E-VERDICT-SOURCES` | （同一條規則也涵蓋 `E-VERDICT-TOOLSIGNAL`、`E-VERDICT-NOELIGIBLE`、`E-VERDICT-PROVISIONAL`、`E-VERDICT-RULE-VERSION`）裁決的推導欄位（第 13 組） | `test_v02_hardening`、`test_v03_adjudication`、`test_review_fixes` 等 4 份 |
| `E-VERDICT-STATUS` | `status`、`status_cap`、`advisory` 必須等於 docs/05 §4.2 規則（`vchlib.adjudicate`）重算的結果；審查 r11（`05-v0.10`）：`FIXED`（R14，regression run 帶入的 `CONFIRMED_*` 叢集回歸測試合格 PASS）與 `refute_by_later_member_family` 註記（R15）也由重算得出；審查 r12（`05-v0.11`）：`FIXED` 只在沒有強／弱工具訊號與計權反駁票、且來源的可執行證明已在本 run 重跑時成立，否則 `DISPUTED`（`fix_contradicted`，第 15 列）；帶入叢集的來源為 `CONFIRMED_*` 時以來源狀態為下限（R16，第 16 列，`regression_failed`／`fix_unverified`） | `test_v02_hardening`、`test_adjudicate`、`test_review_fixes` 等 7 份 |
| `E-VERDICT-TOOLCORR` | 裁決的 `tool_corroboration` 必須等於推導值：已錨定的 SARIF 結果中，屬於該桶校準過的高精準規則者 | `test_v02_hardening`、`test_review_fixes` |
| `E-VERDICT-TOOLSIGNAL` | （同一條規則也涵蓋 `E-VERDICT-SOURCES`、`E-VERDICT-NOELIGIBLE`、`E-VERDICT-PROVISIONAL`、`E-VERDICT-RULE-VERSION`）裁決的推導欄位（第 13 組） | `test_v02_hardening`、`test_review_fixes`、`test_v03_adjudication` 等 4 份 |
| `E-VERDICT-TRACE` | `rule_trace` 的規則序列必須等於重算的規則序列；說明文字裡的 `->狀態`（`->`、`→`、`=>`，不分大小寫，每項只看最後一個箭頭）必須是該規則留下的狀態，`名稱=數字`（score、θ、獨立來源與家族數、計權票數；`=`、`:`、`≈` 與正負號都可以，`θ_` 等同 `theta_`）必須在寫出的位數內等於重算值，`=` 後面不是純十進位數（指數、十六進位）就是錯誤（BL-01；審查 r11 收緊） | `test_bl01_trace_text`、`test_v07_r11_contracts`、`test_adjudicate` 等 4 份 |
| `E-VERDICT-VOTE` | 每張票的代理與模型都能經 agents.yaml／models.yaml 解析，`voter_family`／`voter_lineage` 與登錄相符；計為有效的票不能來自叢集的家族或相同的基礎血統（自我審查）；`anonymized`／`order_randomized` 必須等於該 run 驗證者範本的設定，不能由票自行宣告；審查 r12：自我審查以投票當時的成員判定（`derive.members_at_vote`，與 `vote_valid` 同一條規則；r11 這裡仍用目前的成員，兩個檢查無法同時滿足），而且 `voted_after_round` 不能超過該版裁決的 `verdict_changed` 之前已錨定的 CMD-2 計畫的最高輪次＋1；第十四輪內部審查（`05-v0.15`）：帶入叢集（`carried_from`）的裁決不得有 `votes` 或 `missing_votes`——它的狀態只由回歸測試證據決定（R14／R16）；合格票的投票模型不得與任一成員回報者共用獨立觀察（`independence_key`，`derive.member_observation_keys`） | `test_v07_r14_verdict`、`test_v02_hardening`、`test_v04_round5_adjudication` 等 6 份 |
| `E-VERDICT-VOTER-ROLE` | 只有 agents.yaml 中 `verifier` 角色的代理可以投票；其他角色的票被忽略（不算計權合格、分數、支持／反駁或多樣性） | `test_review_fixes` |
| `E-VOTE-MODEL` | 票的 `voter_agent_id` 在 agents.yaml 的模型及其在 models.yaml 的家族、血統，必須與票上的 `voter_model_key`、`voter_family`、`voter_lineage` 相符 | `test_bl66_pipeline` |

**校準**

| 錯誤碼 | 規則 | 守住的測試 |
|---|---|---|
| `E-CAL-ARMS` | 只有 arm 5 是 exploratory；每個 arm 的 `model_keys` 都在 `config.models`；`result.exploratory.arm` 必須是 5 | `test_bl66_config` |
| `E-CAL-CONTAMINATION` | 校準的汙染欄位：`canary_results` 中 `reproduced` 不是 false 的模型，所有桶的 w 必須是 0（`Index.weight` 也回傳 0）；審查 r11：每個有權重的模型都要有 `canary_results` 一列（沒有檢查過不等於乾淨）；`sentinel: true` 的語料 app 在 `split: holdout`；`holdout_access_log` 每一筆都不早於 `preregistration.registered_at`。審查 r9 只記錄這些欄位、不使用它們。有權重的模型被標示 `variant_recall_gap.flagged` → `W-CAL-CONTAMINATION` | `test_v07_r10_verdict`、`test_v07_r10_contracts`、`test_v07_r11_verdict` |
| `E-CAL-COUNT` | 校準檔的每一組計數 0 ≤ correct ≤ n、0 ≤ tp／fp ≤ n、0 ≤ holdout_tp ≤ holdout_n；不一致時不再計算界限（v0.6 接受 holdout 10 筆答對 11 筆，correct > n 則以 `E-INTERNAL` 崩潰） | `test_v07_r8_validator` |
| `E-CAL-HIGH-PRECISION` | （同一條規則也涵蓋 `E-CAL-WEIGHT`、`E-CAL-THETA`）審查 r7：`weights[]` 的 a、w、near_zero 由計數重算，w 是兩邊的對數概似比（SUPPORT＝ln(TPR／(1−TNR))、REFUTE＝ln(TNR／(1−TPR))），任一邊 near_zero → 兩邊 w＝0（3.2）；`theta_confirm`／`theta_reject` 必須有 `by_bucket`，每一項 value 與 feasible 一致，`high_precision_min` 沒有 `by_bucket`（3.5）；審查 r8：每個門檻的 value 必須是 ≥ 0.1 的有限數（§5.7 的格點下限；負的 θ_reject 會讓單一弱反駁票自動駁回）；`high_precision_rules` 每列 n＝tp＋fp ≥ 40、`precision_lower95` 等於 Clopper-Pearson 雙尾 95% 下界且 ≥ `high_precision_min`、保留切分 n ≥ 10 且點估計 ≥ 下限 − 0.05（3.5）；審查 r9：每一邊記 `n_abstain`，棄權率 ＞ `abstain_rate_max` → near_zero（`abstain_rate_gt_max`）；`feasible: true` 的 θ 由分割統計重算 docs/05 §5.7 的限制（`checks.theta_problems`：n ≥ `min_clusters`、確認分支 precision 與 Wilson 下界、駁回分支的真缺陷比例與 Wilson 上界、`generalised` 的保留切分），每個桶的 θ_confirm 高於該桶任何單張支持票的權重；第十三輪外部審查（`05-v0.14`）：每列另記 `n_apps`、`holdout_n_apps`，`n_apps` ≥ `clustering.min_apps`，`precision_lower95` 以 n_eff 重算；第十四輪內部審查（`05-v0.15`）：每列以 `apps`／`holdout_apps` 列出應用，下界以不等大小的設計效果計算；保留切分在 n_eff 上的 Clopper-Pearson 下界也要 ≥ `high_precision_min` − 0.05 | `test_v06_r7_calibration`、`test_v07_r8_validator` |
| `E-CAL-HYPOTHESIS` | 第十四輪內部審查（`05-v0.15`，docs/05 §5.6）：`primary_hypothesis` 的欄位由區間推導——`h1`＝ci_low ＞ 0；`h2` 只在 H1 成立時是布林、否則必須是 null（固定順序程序）；`outcome` 由 h1／h2／ci_high 推導（multi_family_wins／recall_only／single_best_wins／not_shown）；ci_low ≤ delta ≤ ci_high；`holdout_n_final` ≥ 以 max(ψ_assumed, ψ_observed)、max(ρ_assumed, ρ_observed) 依 §5.5 重算的樣本數（`checks.required_holdout_n`）；`exploratory` 的區間有序且含 `recall_diff_vs_arm3` | `test_v07_r14_verdict` |
| `E-CAL-KAPPA` | `annotator_agreement[].accepted` 必須等於 kappa ≥ `annotation.kappa_min` | `test_bl66_config` |
| `E-CAL-M11` | M-11 `by_model` 的 `flag`：值 ＜ 0.5 時必須是 support_leaning，否則必須是 null | `test_bl66_config` |
| `E-CAL-MODEL` | `config.models` 的家族／血統必須與 models.yaml 相符；`weights[]` 與 `valid_for_model_keys` 的模型都必須在 `config.models` | `test_bl66_config` |
| `E-CAL-POLICY` | 審查 r11：`calibration.yaml` 的政策常數必須等於 `checks.CAL_POLICY`（docs/05 §4.3 的 `smoothing_k`、`near_zero_rules`；§5.7 的 `threshold_search` 限制）。之前 validator 只檢查檔案自我一致，`wilson_lower_max: 0.0` 加上較低的 θ 就把 LIKELY 推成 CONFIRMED；審查 r12：`result.thresholds.high_precision_min.value` 也釘住（0.9，或 null 停用強佐證）——0.1 加一列下界 0.13 的規則，弱 SARIF 訊號就變成不受 R8 限制、非暫定的確認；第十二輪第二次外部審查（`05-v0.13`）：`config.independence.unit` 必須是 `family`（同家族算一個觀察），`lineage_split` 每一項都要是 M-2 證據（兩個血統、`kappa_ci_upper` ＜ 0.6、`n` ≥ 40），否則不能拿來拆分家族；第十三輪外部審查（`05-v0.14`）：`config.clustering`（`min_apps` 10、`icc` 0.05）也釘住；第十四輪內部審查（`05-v0.15`）：`clustering.icc` 是下限 0.05，必須等於 max(0.05, `result.primary_hypothesis.rho_observed`) | `test_v07_r11_verdict`、`test_v07_r12_verdict`、`test_v07_r14_verdict` |
| `E-CAL-PREREG` | 第十四輪內部審查（`05-v0.15`，docs/05 §5.6）：`preregistration.doc_sha256` 等於 config 本身（該欄為 null 時）的 content hash；`result.frozen_at` 必填，不早於 `registered_at`、不晚於第一筆 `holdout_access_log`；任何保留切分統計 n ＞ 0 時 `holdout_access_log` 至少一筆 | `test_v07_r14_verdict` |
| `E-CAL-THETA` | （同一條規則也涵蓋 `E-CAL-WEIGHT`、`E-CAL-HIGH-PRECISION`）審查 r11：`theta_confirm`／`theta_reject` 的 `calibration`／`holdout` 以 `tp`／`n` 重算 precision 與 Wilson 95% 界限，tp 必須是 0～n 的計數；審查 r7：`weights[]` 的 a、w、near_zero 由計數重算，w 是兩邊的對數概似比（SUPPORT＝ln(TPR／(1−TNR))、REFUTE＝ln(TNR／(1−TPR))），任一邊 near_zero → 兩邊 w＝0（3.2）；`theta_confirm`／`theta_reject` 必須有 `by_bucket`，每一項 value 與 feasible 一致，`high_precision_min` 沒有 `by_bucket`（3.5）；審查 r8：每個門檻的 value 必須是 ≥ 0.1 的有限數（§5.7 的格點下限；負的 θ_reject 會讓單一弱反駁票自動駁回）；`high_precision_rules` 每列 n＝tp＋fp ≥ 40、`precision_lower95` 等於 Clopper-Pearson 雙尾 95% 下界且 ≥ `high_precision_min`、保留切分 n ≥ 10 且點估計 ≥ 下限 − 0.05（3.5）；審查 r9：每一邊記 `n_abstain`，棄權率 ＞ `abstain_rate_max` → near_zero（`abstain_rate_gt_max`）；`feasible: true` 的 θ 由分割統計重算 docs/05 §5.7 的限制（`checks.theta_problems`：n ≥ `min_clusters`、確認分支 precision 與 Wilson 下界、駁回分支的真缺陷比例與 Wilson 上界、`generalised` 的保留切分），每個桶的 θ_confirm 高於該桶任何單張支持票的權重<br>（同一條規則也涵蓋 `E-CAL-WEIGHT`、`E-TC-TRIALS`）每個桶的 θ_reject 高於該桶任何一張反駁票的權重；`generalised: true` 的保留切分 n ≥ 10。權重與 Wilson 下界以有效計數計算：一張棄權票算半對半錯（`checks.effective_counts`）。`trials.sampling: sampled` 不是機率型訊號，只宣告它而沒有目標側訊號（LLM 威脅、LLM 測試工具、multi_turn、`target_model` 紀錄）→ `E-TC-TRIALS`；第十三輪外部審查（`05-v0.14`）：每個切分另記 `n_apps`（不同應用數，1～n），Wilson 界限以 n_eff＝n／(1＋(n／n_apps−1)·icc) 重算，可行的門檻另需 `n_apps` ≥ `clustering.min_apps`；第十四輪內部審查（`05-v0.15`）：每個切分統計以 `apps`＝{app_id: 叢集數} 列出應用（n＝總和、app_id 在 corpus 的同一切分；取代自填的 `n_apps`），設計效果用各應用筆數 DE＝1＋(Σm_i²／n − 1)·icc；`generalised: true` 的保留切分至少 10 個應用，確認分支的保留切分 Wilson 下界 ≥ `confirm_wilson_lower_floor`、駁回分支的 Wilson 上界 ≤ `reject_wilson_upper_max`＋0.05 | `test_v07_r11_verdict`、`test_v07_r9_verdict`、`test_v06_r7_calibration` 等 4 份 |
| `E-CAL-WEIGHT` | （同一條規則也涵蓋 `E-CAL-THETA`、`E-CAL-HIGH-PRECISION`）審查 r7：`weights[]` 的 a、w、near_zero 由計數重算，w 是兩邊的對數概似比（SUPPORT＝ln(TPR／(1−TNR))、REFUTE＝ln(TNR／(1−TPR))），任一邊 near_zero → 兩邊 w＝0（3.2）；`theta_confirm`／`theta_reject` 必須有 `by_bucket`，每一項 value 與 feasible 一致，`high_precision_min` 沒有 `by_bucket`（3.5）；審查 r8：每個門檻的 value 必須是 ≥ 0.1 的有限數（§5.7 的格點下限；負的 θ_reject 會讓單一弱反駁票自動駁回）；`high_precision_rules` 每列 n＝tp＋fp ≥ 40、`precision_lower95` 等於 Clopper-Pearson 雙尾 95% 下界且 ≥ `high_precision_min`、保留切分 n ≥ 10 且點估計 ≥ 下限 − 0.05（3.5）；審查 r9：每一邊記 `n_abstain`，棄權率 ＞ `abstain_rate_max` → near_zero（`abstain_rate_gt_max`）；`feasible: true` 的 θ 由分割統計重算 docs/05 §5.7 的限制（`checks.theta_problems`：n ≥ `min_clusters`、確認分支 precision 與 Wilson 下界、駁回分支的真缺陷比例與 Wilson 上界、`generalised` 的保留切分），每個桶的 θ_confirm 高於該桶任何單張支持票的權重<br>（同一條規則也涵蓋 `E-CAL-THETA`、`E-TC-TRIALS`）每個桶的 θ_reject 高於該桶任何一張反駁票的權重；`generalised: true` 的保留切分 n ≥ 10。權重與 Wilson 下界以有效計數計算：一張棄權票算半對半錯（`checks.effective_counts`）。`trials.sampling: sampled` 不是機率型訊號，只宣告它而沒有目標側訊號（LLM 威脅、LLM 測試工具、multi_turn、`target_model` 紀錄）→ `E-TC-TRIALS`；第十四輪內部審查（`05-v0.15`）：棄權算在分母、不算半對（C′＝C、n′＝n＋n_abstain），權重才是對數概似比 | `test_v06_r7_calibration`、`test_v07_r8_calibration`、`test_v04_round5_adjudication` 等 7 份 |
| `W-CAL-CONTAMINATION` | 有非零權重的模型，其變體召回落差被標示（`flagged: true`）：可能記住了語料，依賴它的票之前要人判斷 | `test_v07_r10_verdict` |

**報告、自測與檢查點**

| 錯誤碼 | 規則 | 守住的測試 |
|---|---|---|
| `E-CHECKPOINT` | checkpoint 的 run 必須存在，`run_status`／`thread_id` 與 run 相符；C 級資料的 checkpoint 必須加密 | `test_bl66_config` |
| `E-REPORT` | report-manifest 的 run 必須存在；`advisory` 只在 Lane A 為 true；審查 r11：`evidential` 在 `assurance_profile: lite` 必須是 `self_attested`，其他為 `separated`；`verdict_counts` 等於每叢集最新裁決的計數；`manual_review_clusters` 與 run 相同；audit_log artifact 必須存在；gate_record artifact 必須恰好是該 run 的所有關卡紀錄 | `test_bl66_config`、`test_v07_r11_contracts` |
| `E-REPORT-METRICS` | report-manifest `metrics`（results_total、results_invalid、control_pass_rate；v0.5 BL-20：access_matrix_coverage、endpoint_slice_coverage、endpoint_test_coverage）由 run 的測試結果、testcase 的 access_cells、切片與 request_allowlist 重算；審查 r7（外部審查 5）：覆蓋率分成 `planned_*`（測試案例宣告的計畫）與 `executed_*`（只算有有效執行結果的測試案例：outcome PASS／FAIL、對照全部 PASS、有已錨定且 hash 相符的 `sandbox_job_end`），兩者都重算 | `test_v05_schema_backlog`、`test_v03_adjudication`、`test_v05_r7_pipeline` |
| `E-REPORT-QUEUE` | `report_only_clusters` 每項是白箱叢集、最新裁決 `UNCORROBORATED`、不是種子威脅；`over_cap_items` 的 G2 項是沒有 G2 決定的 DISPUTED／UNCORROBORATED 種子叢集，且 G2 紀錄恰好有 `gate_queues.g2_max_items` 項決定；G3 項是 threat_id 沒有 G3 決定的種子威脅（seed_id）；清單也重算完整性：每個威脅被 G3 判為 over_cap 的種子都要列出 | `test_v04_round5_examples`、`test_v05_round6_group4`、`test_v06_r7_methodology` |
| `E-REPORT-WITHDRAWAL` | 審查 r12（[06 §1.9](../06-security-legal-limitations.md#19-營運手冊金鑰外洩備份與報告撤回h) 第 4 點、BL-54）：報告撤回是委任層級的簽署文件，不寫進被撤回 run 的稽核檔（那個 run 已經以 `run_end` 錨點結束）。`engagement_id` 是本委任；`withdrawn_report_id` 指向 bundle 中的報告、`withdrawn_run_id` 是它的 run，同一份報告只撤回一次；`withdrawn_at` 不早於報告的 `generated_at`，`customer_notified_at` 不早於 `withdrawn_at`；`superseded_by_report_id` 不為 null 時指向另一個較晚開始的 run 的報告，且產生時間較晚；`signers` 依序是 `test_lead`、`security_reviewer`，兩個不同的人（lite 已確認的 `role_consolidation` 除外），每人一筆簽章（以 `withdrawn_at` 驗證，角色由 `E-SIG-ROLE` 檢查） | `test_v07_r12_flow`、`test_v07_r12_examples` |
| `E-SELFTEST` | NOT_RUN 項目沒有結果（`passed`、`value` 為 null、`runs` 為 0），RUN 項目有 `runs` 與 `passed`；`overall_passed` 等於所有 RUN 項目都通過；`finished_at` 不早於 `started_at`；`toolkit_version` 等於 toolkit | `test_bl66_config` |
| `E-SELFTEST-M1` | milestone 為 M1 時，ST-1、ST-3、ST-7 都必須已執行且通過 | `test_validator` |

**載入、格式與推導**

| 錯誤碼 | 規則 | 守住的測試 |
|---|---|---|
| `E-DATETIME` | 時間欄位不是可解析的 RFC 3339 時間戳記 | `test_validator` |
| `E-DERIVED` | 所有由 validator 推導的欄位（hash、分數、計數、鏡像欄位等，`derive.expectations`）必須等於推導值；訊息列出欄位路徑、實際值、預期值與推導依據 | `test_v03_manifest`、`test_adjudicate`、`test_v06_r7_calibration` 等 12 份 |
| `E-ID-DUP` | 同一種文件（run、verdict、cluster、finding、testcase、testresult、threat、gate-record、report-manifest、slice）的 ID 不能重複；commander-plan 的 `plan_id` 也是；一個 run 只有一份 inventory、seed-threats、redaction-map、report-manifest（report-manifest 為審查 r10 補上），每個 viewpoint 一份 DFD（查找取檔名排序的第一份，第二份會默默決定哪一份被檢查） | `test_v07_r9_examples`、`test_v05_round6_group6`、`test_v05_bl27_w4` 等 4 份 |
| `E-INPUT-SHAPE` | （同一條規則也涵蓋 `E-SCHEMA-FORMAT`）見第 1 組；每份文件各自受保護：一份文件的意外錯誤只產生一個 `E-INTERNAL`，同組其他文件照常檢查；審查 r7 第 5 組：推導值（`E-DERIVED`）與 inventory／invariants／baseline 的追溯檢查也逐份文件保護 | `test_bl66_pipeline`、`test_v03_robustness` |
| `E-INTERNAL` | 檢查時發生意外例外；只影響那一份文件（記下例外類型與位置，該文件其餘的推導與檢查略過），同組其他文件照常檢查 | `test_v03_robustness`、`test_validator`、`test_review_fixes` 等 7 份 |
| `E-JCS` | `canonical.jcs` 與參考套件都必須符合 RFC 8785 測試向量；每份文件都要能被兩者正規化，且結果相同 | `test_bl66_config`、`test_v07_r12_external2` |
| `E-JSON-STRICT` | JSON／JSONL 以嚴格模式載入：重複鍵、非有限數字、超出範圍的整數等一律拒絕；被拒的稽核檔不再做後續的鏈與錨點檢查（不連鎖報錯） | `test_review_fixes`、`test_v02_hardening`、`test_v05_round6_lowprio` |
| `E-KIND` | 每份文件的種類必須有對應的 schema | `test_bl66_config` |
| `E-LOAD` | 已知種類的文件因嚴格 YAML／JSON 以外的原因無法載入 | `test_bl66_config` |
| `E-SCHEMA` | 文件不符合其 JSON Schema（訊息列出位置與 schema 的錯誤說明） | `test_review_fixes`、`test_v03_manifest`、`test_v03_scope` 等 26 份 |
| `E-SCHEMA-FORMAT` | （同一條規則也涵蓋 `E-INPUT-SHAPE`）見第 1 組；每份文件各自受保護：一份文件的意外錯誤只產生一個 `E-INTERNAL`，同組其他文件照常檢查；審查 r7 第 5 組：推導值（`E-DERIVED`）與 inventory／invariants／baseline 的追溯檢查也逐份文件保護 | `test_v03_scope` |
| `E-SCHEMA-ID` | schema 的 `$id` 必須等於檔名 | `test_bl66_config` |
| `E-SCHEMA-META` | schema 必須通過 2020-12 meta-schema 檢查，且 `$schema` 是 2020-12 | `test_bl66_config` |
| `E-SCHEMA-NO-EXAMPLE` | 每個 schema（`common` 除外）至少要有一個通過驗證的範例 | `test_bl60_variants` |
| `E-YAML-STRICT` | YAML 以嚴格模式載入：重複鍵、錨點與別名、非標準標籤等一律拒絕 | `test_validator` |

**授權與工具包設定**

| 錯誤碼 | 規則 | 守住的測試 |
|---|---|---|
| `E-LIC-DUP` | licenses.yaml 的 component 不能重複 | `test_bl66_config` |
| `E-LIC-GATE` | 狀態為「法務閘門」的元件必須有 `gate_milestone` | `test_bl66_config` |
| `E-LIC-MISSING` | tools.yaml 的 `license_ref` 都必須在 licenses.yaml；requirements.txt 的每個套件都必須列在 licenses.yaml，且 usage 是 validator 依賴 | `test_bl66_config` |
| `E-REQ` | requirements.txt 必須存在，且 `rfc8785` 釘選為 0.1.4 | `test_bl66_config` |
| `E-TOOLKIT` | toolkit.yaml 必須存在；`toolkit_version` 是 semver；`automation_accounts` 含 run-controller、scheduler、ci-bot；`owasp_llm_default` 是 2025 或 2026；G5 逾時 ≤ 24 小時；G0a／G0b 以外的每關及 claim_run、GB 都有逾時；`tool_registry_ref` 指向存在的檔案 | `test_v07_r8_integrity` |
| `E-TOOLKIT-B1` | toolkit `b1_crawl.skip_keywords` 包含 08 §11.7 的基本清單（方法、表單、origin、上限由 schema 限制） | `test_v05_schema_backlog` |
| `E-TOOLS-CLASS` | B4 可執行且未被工具包拒絕的模式必須有合法的 `base_class` | `test_bl66_config` |
| `E-TOOLS-DENYLIST` | tools.yaml 中 `toolkit_denied` 的模式集合必須等於 `safety.TOOLKIT_DENYLIST` | `test_bl66_config` |
| `E-TOOLS-ID` | 每個工具模式的 ID 必須符合 D13 的 `tool:mode` 格式（`safety.ADAPTER_RE`） | `test_bl66_config` |
| `E-TOOLS-ZONE` | 有 B4 可執行模式的工具必須在 Z3 | `test_bl66_config` |

**其他**

| 錯誤碼 | 規則 | 守住的測試 |
|---|---|---|
| `W-JCS-REFERENCE-MISSING` | 第十二輪第二次外部審查：沒有安裝參考套件 `rfc8785` 時，`canonical.jcs` 只對 RFC 8785 測試向量檢查，不與參考套件逐份比對（警告）；之前 `checks.py` 在模組層級載入它，缺套件時整個 validator 直接崩潰。CI 安裝 `requirements.lock`，比對一定執行（測試確認主範例沒有這個警告）。`cryptography`、`jsonschema`、`referencing`、`yaml` 是驗章與 schema 的核心，缺少時 CLI 以結束碼 2 指名缺少的套件 | `test_v07_r12_external2` |
| `W-RESULT-G4-WITHDRAWN` | 外部審查：B4 結果在有效的 G4 核准下執行，之後的 G4 round 以 reject／needs_info 撤銷了這個核准。結果保留事先登記（仍可為 E_proof），該測試案例不再列在 `approved_testcase_ids`、不得再派送（警告；規則見 03 §6.6） | `test_v07_r11_external`、`test_v07_r12_examples` |

<!-- error-table:end -->

### 變體 bundle（BL-60）

變體是主範例 bundle 加上一層覆蓋：`docs/examples/variants/<名稱>/` 依 repo 的相對路徑放「取代或新增」的檔案，`removed.txt` 列出拿掉的主範例檔案；`vchlib.bundle.load_variant` 套用它，文件保留主範例的路徑。覆蓋由 [`tools/build_variants.py`](../../tools/build_variants.py) 從主範例以腳本修改後，重算衍生值並以 TEST ONLY 金鑰重簽到穩定而產生（Ed25519 簽章是確定性的，所以重建結果逐位元組相同）；不要手改覆蓋裡的檔案。

| 變體 | 走過的路徑 |
|---|---|
| [`lite`](../examples/variants/lite/README.md) | 單人委任：alice 以簽署的 `role_consolidation` 兼任所有角色；只有 S0／S1 job，S2 的主動掃描改為 MANUAL，所以沒有 G5；沒有抽查；只保留主範例的首次 run。預期警告 `W-L5-LITE`（法務聲明自行簽署） |
| [`edge`](../examples/variants/edge/README.md) | G2 駁回 K-016，G2_apply 版本由 R10 決定為 REJECTED；委任為 `full`，S2 job 的 G5 由兩位資安審查者核准；跟進 run 在等 G4 時觸發停止條件，由測試負責人中止（`ABORTED`，以 `run_end` 錨點收尾） |
| [`suspend`](../examples/variants/suspend/README.md) | 跟進 run 的 G4 開啟 72 小時沒有人決定：Gate Service 寫入沒有簽章、只有 `needs_info` 的 `EXPIRED` 紀錄，run 轉為 `SUSPENDED`（沒有 `run_end`，可 resume）；同一個 run 記錄的 ASI09 抽查推翻第一個 run 的 G5，抽查人 grace 與該 G5 的核准者、發起者都不同 |
| [`regression`](../examples/variants/regression/README.md) | 跟進 run 改為 `regression`：帶入的叢集 K-301 在 W3 由 R16 維持來源的 `CONFIRMED_EXECUTABLE`（`fix_unverified`）；erin 認領 run、G4 核准重跑來源的可執行證明 TC-012-01，B4 PASS 且正對照成立，B5 由 R14 判為 `FIXED`；run 仍在 `RUNNING`（審查 r12） |

```bash
python tools/validate_schemas.py --variant lite   # 驗證一個變體
python tools/build_variants.py                    # 改了主範例或推導規則後重建所有變體
python tools/build_variants.py --check            # CI：覆蓋是最新的，而且每個變體零錯誤
```

建置變體時找到兩個 validator 缺口，已修正：G4 核准的 MANUAL 測試案例不需要工具包的 job（它由人執行，列在報告的未能測試清單）；G2 駁回的叢集，最新的裁決版本必須在 G2 之後（`E-VERDICT-G2`），否則報告會顯示它在 G2 之前的狀態。`regression` 變體也找到一個：`E-TRACE` 要求回歸結果指向第一個 run 的來源叢集，所以結果永遠無法指向 R14 要裁決的帶入叢集，現在本 run 的帶入叢集代表它的來源叢集（審查 r12）。`suspend` 變體另外找到一個：逾時的 G3／G4 紀錄只能有 `needs_info`，「結果與決定一致」的檢查卻要求 `PARTIALLY_APPROVED`，所以任何逾時的 G3／G4 都會被拒絕（`E-GATE-OUTCOME`）；現在 `EXPIRED` 不由決定推導結果。「每個 schema 都有範例」（`E-SCHEMA-NO-EXAMPLE`）只檢查主範例。

### 範例沒有走過的路徑

主範例 bundle 只有一個委任（`team`）、三個 run。四個**變體 bundle**（見上一節）在真實簽署的資料上走過其中幾條路徑，標「`lite` 變體」「`edge` 變體」「`suspend` 變體」「`regression` 變體」；其餘路徑由記憶體中的測試在範例上修改後檢查。每一列都由 `tests/test_v07_r9_examples.py` 確認所列的測試存在。

| 路徑 | 規則 | 測試 |
|---|---|---|
| `lite` 委任的安全等級與抽查（`lite` 變體） | `E-PROFILE-SAFETY`、`E-SPOT-CHECK` | `tests/test_v03_gates.py::test_lite_rejects_s2_toolkit_jobs`、`tests/test_v07_r9_contracts.py::test_a_lite_engagement_records_no_spot_check`、`tests/test_bl60_variants.py::test_lite_runs_no_s2_job_and_has_no_g5`、`tests/test_bl60_variants.py::test_lite_records_no_spot_check` |
| G2 駁回之後的證據（R10；`edge` 變體以 G2_apply 版本走過） | `E-VERDICT-G2`、R10 | `tests/test_adjudicate.py::test_r10_cannot_be_bypassed_by_null_g2_ref`、`tests/test_bl60_variants.py::test_edge_g2_rejection_is_applied_by_r10` |
| `ABORTED`／`FAILED` 的 run（`edge` 變體的跟進 run 被中止） | `E-RUN-CONFIG`、`E-AUDIT-TAIL` | `tests/test_v05_backlog_high.py::test_a_run_that_ended_before_g1_keeps_its_invariants_pending`、`tests/test_bl60_variants.py::test_edge_follow_up_run_is_stopped_then_aborted` |
| G0b `VERIFY_FAILED` 擋住 B 階段 | `E-GATE-ORDER` | `tests/test_v07_r8_validator.py::test_a_failed_g0b_stops_the_b_phase` |
| `STOPPED` 之後的 resume | `E-SIG-ROLE` | `tests/test_v05_round6_lowprio.py::test_stopped_resume_needs_a_test_lead` |
| PII 停止條件 | `safety.pii_stop_hits` | `tests/test_v06_r7_methodology.py::test_unregistered_pii_still_stops` |
| G5 兩人核准（`edge` 變體以 `full` 等級走過；`suspend` 變體記錄推翻 G5 的抽查，但範例沒有更晚、帶 G5 的 run，所以升級的後果仍只在記憶體中） | `E-G5-TWO-PERSON`、`E-SPOT-CHECK` | `tests/test_v06_r7_methodology.py::test_an_overturned_g5_spot_check_requires_two_reviewers_later`、`tests/test_bl60_variants.py::test_edge_g5_has_two_security_reviewers`、`tests/test_bl60_suspend.py::test_the_overturn_escalates_later_runs_only` |
| 關卡逾時 → `SUSPENDED`（`suspend` 變體的跟進 run，G4 `EXPIRED`） | `E-GATE-EXPIRED-EARLY`、`E-GATE-OUTCOME`、`E-RUN-STATUS` | `tests/test_bl60_suspend.py::test_the_run_is_suspended_not_ended`、`tests/test_bl60_suspend.py::test_an_expired_g3_or_g4_implies_no_outcome_from_its_decisions` |
| `regression` run 與 `FIXED`（`regression` 變體：W3 由 R16 維持確認，B5 由 R14 判為 FIXED） | `E-RUN-FOLLOWUP`、R14、R16、`E-TRACE` | `tests/test_v07_r8_validator.py::test_a_regression_run_carries_a_parent`、`tests/test_v07_r12_examples.py::test_the_passing_regression_test_makes_it_fixed`、`tests/test_v07_r12_verdict.py::test_a_contradicted_fix_is_disputed` |
| `SUSPENDED` 之後 resume（已錨定、人簽署的 `run_resume`＋新的 G0b） | `E-RUN-RESUME` | `tests/test_v07_r11_anchor.py::test_a_signed_anchored_run_resume_by_the_run_owner_resumes_it`、`tests/test_v07_r11_anchor.py::test_a_b_phase_event_after_the_resume_needs_a_fresh_g0b` |
| 委任到期未續跑 → `COMPLETED_WITH_GAPS`（gap `expired`） | `E-RUN-RESUME`、`E-RUN-GAPS` | `tests/test_v07_r12_flow.py::test_an_expired_suspended_run_is_closed_by_the_system`、`tests/test_v07_r12_flow.py::test_the_expired_gap_is_derived` |
| `COMPLETED_WITH_GAPS` 與推導的 gaps | `E-RUN-STATUS`、`E-RUN-GAPS` | `tests/test_v07_r11_anchor.py::test_completed_with_a_non_manual_gap_is_completed_with_gaps`、`tests/test_v07_r12_run.py::test_a_gb_stop_is_a_gap` |
| 關卡 `round` > 1 與輪數上限 | `E-GATE-ROUND` | `tests/test_v07_r11_anchor.py::test_a_gate_beyond_its_round_limit_is_rejected`、`tests/test_v07_r11_anchor.py::test_the_g4_round_limit_fires_the_validator_rule` |
| G3 `over_cap` | `E-GATE-OVER-CAP`、`E-REPORT-QUEUE` | `tests/test_v04_round5_examples.py::test_over_cap_g3`、`tests/test_v05_round6_group4.py::test_over_cap_outcome_is_a_rejection` |
| G4 核准事後被撤回 | `W-RESULT-G4-WITHDRAWN` | `tests/test_v07_r11_external.py::test_a_withdrawn_approval_is_a_warning_not_an_error_for_a_result_that_ran_under_it` |
| 報告撤回（主範例撤回 `RPT-2026-10-06-001`；取代的報告只在記憶體中） | `E-REPORT-WITHDRAWAL` | `tests/test_v07_r12_flow.py::test_the_bundle_withdraws_its_report`、`tests/test_v07_r12_flow.py::test_a_superseding_report_belongs_to_a_later_run` |
| 逾時的關卡（EXPIRED 不核准任何項目） | `Index.approved_requirement_ids` | `tests/test_v05_r7_bypasses.py::test_an_expired_g1_approves_nothing` |
| 已完成的 run 被截回較早的錨點 | `E-AUDIT-ANCHOR-GAP` | `tests/test_v07_r9_anchor.py::test_rolling_a_completed_run_back_to_an_earlier_anchor_leaves_a_counter_gap` |
| 停止條件（`stop_condition`）之後中止 run（`edge` 變體） | `E-AUDIT-TAIL`、`E-RUN-STATUS` | `tests/test_bl60_variants.py::test_edge_follow_up_run_is_stopped_then_aborted` |

## 簽章與測試金鑰

- 簽章是**真的 Ed25519**，簽在 RFC 8785 JCS（去掉 `signatures`）上；稽核事件簽在去掉 `signature` 的事件上。指紋＝`ed25519:SHA256:` ＋ base64（無 padding）的 SHA-256（原始 32 位元組公鑰）[H]。
- 範例用的私鑰在 `tests/fixtures/TEST_ONLY_private_keys/*.TEST_ONLY.pem`，**是公開的測試資料，只證明驗證程式的邏輯，不代表任何真實核准**。正式部署必須用各人自己的金鑰，絕不可沿用這些檔案。
- 修改任何範例後執行 `python tools/sign_examples.py`：取代 `FP:<名稱>`／`PK:<名稱>` 佔位字串，重算所有衍生值、重簽 YAML 與關卡紀錄、重建稽核雜湊鏈，直到不再變動；接著執行 `python tools/build_variants.py` 重建變體 bundle。

## 設計決定（其他文件參照用）

- 稽核雜湊鏈：`prev_hash` ＝ 前一行原始 UTF-8 位元組（去掉行尾）的 SHA-256；第一筆＝`sha256(run_id)`。只有人為的 `initiator_claim`、`run_resume` 與 `spot_check_result` 帶簽章（`E-AUDIT-SIG`），其他事件 `signature: null`；`audit_anchor` 另在 `payload.z3_countersignature` 帶 Z3 副簽。`run.audit_anchors` 依序列出每個 `audit_anchor` 事件的 `{seq, line_sha256}`（該錨點那一行本身的 SHA-256，所以錨點涵蓋到自己那一行）；它是寫入端推導的值，必須與日誌中的錨點事件完全一致，漏列 → `E-AUDIT-ANCHOR`（所以「從 run 紀錄刪掉最後一個錨點」不會降級成警告）。日誌中最後一個錨點事件之後的行是未錨定尾段：非終止狀態 → `W-AUDIT-UNANCHORED-TAIL`；終止狀態（COMPLETED、COMPLETED_WITH_GAPS、ABORTED、FAILED）→ 一個 `E-AUDIT-TAIL`（列出所有原因：尾段行數、最後一筆不是 audit_anchor、最後錨點不是 run_end）；日誌比錨定的 seq 短 → `E-AUDIT-TRUNCATED`；雜湊不符 → `E-AUDIT-ANCHOR-MISMATCH`。
- 報告清單中 `audit_log` 的 sha256 ＝ `report_published` 事件的 `prev_hash`，也就是「發布報告當下之前全部紀錄」的雜湊；之後追加的事件（如 run_end anchor）不影響報告清單。
- 關卡項目 hash 用「核准視圖」：去掉 `signatures`、`review`、`signoff` 後的 JCS，讓寫回決定不會改變被核准的 hash。
- G0a／G0b 沒有人為簽章；它們記錄系統對 engagement／ROE 簽章的驗證結果。

## 限制（誠實說明）

- 這是**設計庫的範例驗證器**，不是執行期元件：它證明範例彼此一致、規則可機械檢查，不證明實作正確。
- `canonical.jcs` 只涵蓋本庫用到的 JSON 子集，只與 3 組 RFC 8785 向量及 `rfc8785` 套件在本庫資料上比對過 [H]。
- 金鑰登錄的信任根是 `toolkit.yaml` 的釘選指紋；範例中根私鑰同樣是 TEST ONLY 檔案。沒有實作線上撤銷查詢或時間戳服務，簽章時間取自文件的 `issued_at`、關卡紀錄的 `timestamp` 或事件的 `ts`，也就是簽署者自己宣稱的時間。
- 安全等級與裁決規則各有一份 Python 實作（`vchlib.safety`、`vchlib.adjudicate`），依 docs/04 §5 與 docs/05 §4.2 逐條轉寫；文件若改動，程式與範例必須一起更新。
- 範例中的網域（example.com／example.net）、雜湊佔位與校準數字都是虛構的。
