# 變更紀錄

格式參考 [Keep a Changelog](https://keepachangelog.com/)；版本是設計文件的版本，不是軟體發行版本。

**版本規則**（v0.7 補，審查 r8）：設計文件版本（v0.x）只在整套文件重寫或合併分支時升；裁決規則版本（`rule_version 05-v0.x`，`vchlib.adjudicate.RULE_VERSION`）在任何改變裁決語意的變更時升，與文件版本無關；程式與 schema 註解中的「v0.7」指第八、九輪審查這一批變更（第九輪的註解另標 review r9）。目前：設計文件 v0.5，`rule_version 05-v0.8`，`toolkit_version` 與 `pyproject` 版本 0.5.0。歷程：`05-v0.4`（v0.4）→ `05-v0.5`（v0.5 第 2 組）→ `05-v0.6`（第七輪第 3 組）→ `05-v0.7`（第八輪第 3 組）→ `05-v0.8`（第九輪 PR2）。

## 第九輪審查（2026-10-27）

依第九輪設計審查：三個獨立審查（validator 繞過、裁決與校準、方法論與文件）加上使用者提供的外部審查（2 項，都重現）。審查紀錄在本輪最後一個 PR 加入。

### 投票的獨立性與校準（PR2；`rule_version` 改為 `05-v0.8`）
- **S 以基底血統計**：同一個根的計權合格票取平均（`derive.root_score`）；v0.7 讓 claude_sonnet＋claude_opus 兩張同根支持票相加跨過 θ_confirm，單一血統就能確認。
- **血統宣告一致**（外部審查 2）：同一血統的模型宣告相同的 `derived_from`（`E-MODEL-LINEAGE`）；根不再依 models.yaml 的順序而變。
- **機率型只判定一次**（外部審查 1）：FAIL 的重播規則用分類時的判定；有機率型訊號的測試必須宣告 `trials.sampling: sampled`（`E-TC-TRIALS`）。
- **W4 事先登記證明要求作者獨立**：回報家族自己寫、自己審的 W4 測試，FAIL 需要合格的 Result Analyst，否則是 `E_fail_u`。
- **θ 的 §5.7 限制重算**（`checks.theta_problems`，`E-CAL-THETA`）；θ_confirm 高於該桶任何單張支持票的權重。
- **棄權率**：校準的每一邊記 `n_abstain`，棄權率 ＞ `abstain_rate_max`（0.3）→ near_zero（`E-CAL-WEIGHT`）。範例每邊約 9% 棄權，權重不變；engagement 的 `config_pins.calibration` 重算。
- **誤報抑制要兩個人**：其中一位是沒有在 G2 決定該叢集的 security_reviewer。
- 文件：00、03、04 §4.4、05（摘要、§4.3、§5.7、§5.10、R2 說明與舊的平滑公式）、08、schemas README、verdict schema。
- 新增 `tests/test_v07_r9_verdict.py`（20 個）與 `tests/mutations/r9_verdict.json`；斷言目前規則版本的四個既有測試改為 `05-v0.8`；第八輪兩份突變清單的錨點跟著改（`ext2` 改指新的 sampling 檢查，`M4` 由本輪的兩個 FP 突變取代）。

### 錨定的根因（PR1）
- **回捲已完成的 run**（致命，不需金鑰）：Z3 對每個副簽的錨點編上本委任的遞增編號 `payload.anchor_counter`（在副簽範圍內）；所有 run 的編號必須連續、依收件時間遞增（`E-AUDIT-ANCHOR-GAP`）。v0.7 第八輪的錨點清單是從稽核檔推回 run 紀錄的，只控制 Z1 的人能把已完成的 run 截回較早的錨點、刪掉 B4 證據、G5、B5 裁決與報告，validator 零錯誤。06 §3 #16「尾端截斷只能截到最後一個錨點」的說法更正。
- **run 紀錄跟著稽核檔**：`run.status` 是最後一筆 `run_status_changed` 的 `to`（`E-RUN-STATUS`）；已錨定的 `run_created` 釘住 `repo_commit`，run 與 W0 inventory 必須相同（`E-RUN-COMMIT`）。
- **未錨定的 `verdict_changed` 不是裁決**（`E-AUDIT-VERDICT`）。
- **裁決釘住叢集、叢集釘住發現項**：verdict 新增 `cluster_sha256`、cluster 新增 `member_finding_sha256`（推導）；v0.7 第八輪在裁決之後改寫成員發現項不會被發現。帶入的叢集不能有自己的成員（`E-CLUSTER-CARRY`）。
- **裁決鏈**：白箱與 tool_only 叢集的第一版一定是 `W3_adjudicate`（`E-VERDICT-PHASE`）；`G2_apply` 版本一定引用決定該叢集的 G2 紀錄（`E-VERDICT-G2`）。
- **種子威脅**：W5 的 `artifact_stored` 釘住 seed-threats 的 content hash（`E-AUDIT-ARTIFACT`）；種子的來源叢集屬於種子文件的 run（`E-TRACE-SEED`）。
- **job**：B 階段的 `sandbox_job_*` 都要對應 `run.jobs`，完成的 run 對 G4 核准的每個測試案例都有 job（`E-JOB-AUDIT`）。
- 文件：02 §1.6、03 §5.4 `run_init` 與 §13.1、06 §1.8 完整性矩陣與 §3 #16、schemas README 錯誤碼表。
- 新增 `tests/test_v07_r9_anchor.py`（20 個）與 `tests/mutations/r9_anchor.json`（15 個突變）；`test_v02_hardening` 的兩個「進行中 run」測試改用真正未完成的跟進 run（把已完成的 run 標成 RUNNING 現在是 `E-RUN-STATUS`）。

## 第八輪審查（2026-10-26）

依 [2026-10-26 設計審查（第八輪）](docs/evidence/review-2026-10-26-r8.md)：三個獨立審查（validator 繞過、裁決與校準、方法論與文件）加上使用者提供的外部審查（6 項，全部重現）。設計文件仍為 v0.5 的版本號；程式與 schema 的註解以 v0.7 標示本輪變更。

### 範例、流程與過時文字（第 5 組）與審查紀錄
- 稽核事件的 `node` 改為列舉（W0～W5、B0～B6、關卡、`claim_run`、`feedback`、`abort_handler`、`resume`、START／END、`CMD-n`）；範例的 `W6` 改為 W5，`budget_exhausted` 移到 W3（它發生在 G2 之前）。
- `run.w4_results` 由 validator 推導（W4 結果的內容 hash）；`repo_commit` 一律 40 字元；checkpoint 的 `schema_version` 對齊。
- 流程證據進 repo（M8）：`.github/pull_request_template.md` 的檢查表；`tools/mutation_check.py` 與 `tests/mutations/*.json`（第八輪三份清單共 54 個突變）；`--anchors-only` 檢查清單是否過期，並有測試守住。
- 相依套件（M9）：`requirements.lock` 釘精確版本，CI 改用它；hash 鎖定列為 BL-57。`pyproject` 與 `toolkit_version` 對齊為 0.5.0。
- 過時文字：schemas README、verdict schema、08 的 `rule_version`；README 的狀態與 `config_pins` 清單；`validate_schemas.py` 的 docstring；09 的 BL-07～09 說明與 BL-51／52 順序、錨點；本 CHANGELOG 的第七輪小節與版本規則；r7 審查紀錄的「本 PR」改為 #19。
- 審查紀錄 `docs/evidence/review-2026-10-26-r8.md`；新增 `tests/test_v07_r8_process.py`。

### 完整性模型與方法論（第 4 組）
- **交付物綁進錨定鏈**（H4）：`verdict_changed` 釘 `verdict_sha256`、`report_published` 釘 `report_manifest_sha256`（`E-AUDIT-VERDICT`／`E-AUDIT-REPORT`）；v0.6 只釘 id 與狀態，錨點之後改裁決的嚴重度、`rule_trace`、證據引用或報告都不會被發現。06 §1.8 新增工件完整性矩陣。
- **`toolkit.yaml` 納入 `config_pins`**（M1）；`gate_queues.*_max_items` ≥ 1（`E-TOOLKIT`）。
- **回饋的抑制要兩個人**（M4）：app_owner 單獨簽署的 `false_positive` 是 `underReview`，security_reviewer 以 `co_signed_by` 副簽才 `accepted`；叢集 `updated` 時抑制失效；被抑制項目列入 ASI09 抽查；只有已裁決的誤報才暫停 high-precision 規則（05 §5.10）。範例 FB-001 改為 `underReview`。
- **ROE 失效的結果統一**（H1）：到期 → `SUSPENDED`，撤銷或驗章失效 → `ABORTED`，不論在 B 階段入口或進行中（02 §1.4 為唯一來源；§1.6、03 §5.6、BL-48 引用）。
- **Lite 的 G2 只能 accept／needs_info**（M3；`E-GATE-OUTCOME`）；MVP0-X8 的 pilot 改為 ≥8 人並計入 `claim_run` 與 G2。
- **人數需求改寫為資安審查者人數**（M7）；升級後只有 G5 規則改變，只有 2 位審查者的委任不能再執行 S2。
- **帶入的叢集是新實例**（外部 5）：cluster 新增 `carried_from`（`E-CLUSTER-CARRY`）；範例跟進 run 以 `K-301` 帶入 `K-005`。
- **W4 觀察資料的可信來源契約**（外部 6）：testresult 新增 `observations_source`（harness／sut），`sut` 只能 `E_inc`（`E-W4-OBSERVATION`）；08 W4 寫明可信觀察者、取得通道與寫入權限。
- **營運手冊**（M5）：06 §1.9（金鑰外洩、根金鑰輪替、Audit Writer／Z3 外洩、報告撤回、備份、通報），待辦 BL-53～56。
- 新增 `tests/test_v07_r8_integrity.py`。

### 裁決與校準設計（第 3 組；`rule_version` 改為 `05-v0.7`）
- **平滑的先驗**：a ＝ (C ＋ k·ā ＋ 1) ／ (n ＋ k ＋ 2)（`checks.smoothed_rate`）。v0.6 只往模型自己的跨桶正確率收縮，單邊全對的模型 a＝1、權重被 `lr_weights` 歸零——最準的驗證者沒有發言權。範例的 a、w 與裁決分數重算（K-014 的 S 由 1.5775 變為 1.4633），θ_confirm 2.5 與所有裁決狀態不變；engagement 的 `config_pins.calibration` 重算。
- **R6 的來源**：`E_fail_u` 只有在測試的作者（`derive.test_author_families`）都在叢集的家族與基底血統之外時才算獨立來源（`Inputs.fail_u_independent`，`checks.fail_u_independent` 推導）；v0.6 讓單一家族回報、自己寫 W4 測試、自己解讀 FAIL 就到 `LIKELY`。它仍是第 7 列的訊號（反駁票遇上它 → `DISPUTED`）。
- **決定表**：第 3、5 列與「G2 駁回後才出現 FAIL 證明」改寫，與 v0.6 的 R10 一致（審查 r8 第 3 項：文件與程式在 2,304 個輸入組合上不符）。
- `provisional` 的例外補上第 10 列（05 §4.2、07 MVP0-X4、08 §11.x）；05 的 K-014 範例數字與 R0 說明更新。
- 04 §4.4：預算不足不再降低 n——測試案例標 `MANUAL`（`budget`）並列入 gaps；v0.6 的文字與 `E-TC-TRIALS` 矛盾。
- 文件：00、02、03、05、07、08 的 `rule_version` 與說明。
- 新增 `tests/test_v07_r8_calibration.py`；既有測試依新數值與語意更新（`test_v03_adjudication`、`test_v04_round5_adjudication`、`test_v06_r7_calibration`、`test_v02_hardening`）。

### validator 繞過與 run 的結構（第 1、2 組，含外部審查 1～4）
- **不需要金鑰的繞過**：
  - 每個 B4 結果的 job 必須在已執行的狀態，每個 job 恰有一份結果，每份結果都要有恰一筆已錨定、outcome 與三個 hash 相符的 `sandbox_job_end`；`classify_result` 對沒有已錨定執行事件的結果一律 `E_inc`（`E-JOB-AUDIT`；審查 r8 F2a／F2b：v0.6 只核對 SKIPPED 與已執行狀態的 job，而且同一 job 只看最後一份結果，所以掛在 PENDING job 上的結果能把 K-011 從 UNCORROBORATED 變成 CONFIRMED_EXECUTABLE）。
  - G2 路由改以 W3 裁決與 validator 推導的 rubric 嚴重度判斷；新增 `cluster.severity`（必填，`E-CLUSTER-SEVERITY`，`derive.rubric_severity` 依 08 §11.17）；範例的 K-015、K-016 因此補上 G2 決定（F5）。
  - 機率型 `E_proof` 的 `trials` 只複製 `{n, k}`，並改用 `is_probabilistic`（F7；v0.6 複製 `n_effective`，每個 LLM 測試的 CONFIRMED_EXECUTABLE 都會是 `E-SCHEMA`）。
  - 重播預算改用 `rate_limit.max_requests_per_trial`（機率型測試必填，`E-TC-RATE`）：`max_requests ＋ replay_n × max_requests_per_trial`，沒有宣告時每次重播以整個 job 計（外部 1）。
  - 機率型由受測功能判定：LLM 威脅（taxonomy owasp-llm／owasp-asi，或來源叢集在 `llm_specific` 桶）、`trials.sampling: sampled`，加上原本的 adapter／`multi_turn`／`target_model` 訊號；有訊號時不能宣告 `deterministic`（`E-TC-TRIALS`、`derive.probabilistic_signals`；外部 2：改綁 `playwright:api`、n＝1 的 LLM 測試原本被當成確定性測試）。
  - 獨立性以血統的根計算：`independent_families` 與 R8 的多樣性都用 `lineage_root`，`derived_from` 的循環與指向不存在血統的宣告由 `E-MODEL-LINEAGE` 拒絕（外部 3）。
  - 校準檔的計數 0 ≤ k ≤ n（`E-CAL-COUNT`；外部 4），θ 必須是 ≥ 0.1 的有限數（`E-CAL-THETA`）；規則輸入的 `weighted_valid` 改為重算（`derive.vote_terms`），不讀裁決自填的旗標。
- **run 的結構（需要 Z3 金鑰才能偽造，但流程錯誤也抓得到）**：
  - `E-GATE-ORDER`：各關卡第一次決定的收件時間依 G0a < G1 < G2 < G0b < G3 < G4 < G5；B 階段事件都在 VERIFIED 的 G0b 之後且中間沒有 VERIFY_FAILED；W4 在 G2 之後、G0b 之前（F1、F3）。
  - `E-RUN-CLAIM`：Lane B run 的第一個 G1 決定、W4 或 B 階段事件之前必須有人簽署的 `initiator_claim`（F4）。
  - `E-RUN-G3`：到 G4 的 run，其測試案例的威脅都在本 run 的 G3 有 accept（可 `carried_from`）；威脅的 `review` 指向來源紀錄（H3）。範例的跟進 run 補上 `GR-G3-0002`。
  - `regression` run 比照 `followup` 允許 `parent_run_id`／`reuse`（`E-RUN-FOLLOWUP`；H2）。
  - `E-SPOT-CHECK`：抽查者是 `security_reviewer`、不是該紀錄的核准者或發起者，`item_id` 是同一委任的關卡紀錄（M2）。
  - Lane A run 必填 `pr_origin`；fork 的 PR 沒有裁決、叢集與 advisories，其他 run 的 `lane_a_advisories` 只能引用 same_repo 的 Lane A 叢集（`E-RUN-LANE-A`；M6）。
- schema：testcase `rate_limit.max_requests_per_trial`、`trials.sampling`；cluster `severity`；run `pr_origin`。
- 文件：02 §1.5、§1.6、W3；03 §12；04 §5；05 §4；06 §1.1；08 §11.7、§11.17；schemas README 的錯誤碼表。
- 新增 `tests/test_v07_r8_validator.py`（55 個測試，48 個在 `e5fa57d` 上失敗）。

## 第七輪審查（2026-10-25）

依 [2026-10-25 設計審查（第七輪）](docs/evidence/review-2026-10-25-r7.md)；v0.6 之前這些小節列在 v0.5 之下，設計文件版本沒有升（版本規則見開頭），`rule_version` 升為 `05-v0.6`。

### 第七輪審查：validator 繞過（第 1 組，含外部審查 1～4）
- EXPIRED（沒有簽章）的關卡紀錄只能帶 needs_info 決定（`E-GATE-OUTCOME`），不再算 G1 核准的需求、G2／G3 的決定或 G4 核准的測試案例。
- B4／S2 的執行時間以 `sandbox_job_start`／`end` 的收件時間判斷：`executed_at` 在 job 之內（`E-JOB-AUDIT`）；job 開始晚於核准它的最新 G4 決定（`E-RESULT-G4`）與 G5 決定（`E-RESULT-G5`），並在 ROE 時段內（`E-RESULT-WINDOW`）；B5 裁決晚於 job 結束才收件（`E-VERDICT-PHASE`）；`approved_testcase_ids` 看每個測試案例最新的 G4 決定。
- W4 測試案例新增必填的 `target_files`；每個叢集的位置必須在測試涵蓋的檔案內（`E-W4-TC`）。
- `sandbox_job_end` 釘住 `testcase_sha256`、`artifact_sha256`、`result_sha256`（W4：`E-W4-AUDIT`；B4：`E-JOB-AUDIT`）。
- 誤報回饋由採用它的 run 以已錨定的 `feedback_recorded` 事件記錄，以收件時間驗章（`E-FEEDBACK`）；`audit-event` 新增此事件種類。
- Scope Proxy：沒有路徑變數的 PATCH／PUT／DELETE 只能以 query 選取已綁定的列（body ID 不算）；`object_refs` 的 `{created:x}` 綁定 x 的 path_templates；Server Action 拒絕解析不到的參照，並以區分 JSON 型別的方式比對。
- `read_only_endpoints` 不能是 W0 標為會寫入的端點（`E-SEED-SIDE-EFFECT`）；一個發現項只屬於一個叢集（`E-CLUSTER-BINDING`）；裁決規則改用推導出的 score。
- 穩健性：推導值與 inventory／invariants／baseline 檢查逐份文件保護，一份壞文件不再遮蔽其他文件的錯誤。
- 新增 `tests/test_v05_r7_bypasses.py`。

### 第七輪審查：方法論與架構（第 4 組）與審查紀錄
- 共享平台目標新增 `ownership_proof.technical_proof`；沒有技術證明只允許 S0（`E-ROE-PLATFORM`）。
- PII 停止條件排除登記的合成值與 canary（`safety.pii_stop_hits`）；測試案例可宣告 `expected_error_statuses`（只限 429／5xx，`E-TC-EXPECTED-STATUS`），不計入 run 層級停止條件（`safety.counts_for_run_stop`）。
- ASI09 抽查推翻 G5 後，同一委任之後的 run 一律需要兩位資安審查者（`checks.g5_escalation`，`E-G5-TWO-PERSON`）；over_cap 清單重算 G3 的完整性（`E-REPORT-QUEUE`）。
- `g_roe` 分成 14 個區段各自保護（第 5 組）。
- 文件：W4 以乾淨設定執行並在行程外判定結果、自動觸發只跑 W0／W0.5、各保證等級的最少人數、`regression` 帶入叢集、ROE 在 B 階段入口失效、fork PR、本機目標的 loopback 例外、07 的精簡 Lite 候選；修正多處過時文字；schemas README 補上 154 個錯誤碼。
- 審查紀錄 [docs/evidence/review-2026-10-25-r7.md](docs/evidence/review-2026-10-25-r7.md)；09 新增 BL-48～BL-52。
- 新增 `tests/test_v06_r7_methodology.py`。

### 第七輪審查：安全等級（第 3 組之三）
- 種子新增 `side_effects`／`contained`；寫入副作用沒有被圍住的種子 → 至少 S2，沒有宣告時依 ROE integrations 採 fail closed。範例的種子都宣告 `none`／`contained`，ROE 的 seed manifest hash 已更新。
- 請求預算包含重播（`max_requests ＋ replay_n × ⌈max_requests／n⌉`）。計畫原本寫 `max_requests ×（1＋replay_n）`，但重播只重跑一個 trial，那樣會高估：LLM 範例會從 350 變成 5250。
- GraphQL 只能 POST，並以 `graphql_document_sha256` 釘住 document（testcase `request_allowlist` 新欄位）；否則 S3。
- 新增 `tests/test_v06_r7_safety.py`。

### 第七輪審查：校準（第 3 組之二）
- 權重改為兩邊比率的對數概似比（SUPPORT＝ln(TPR／(1−TNR))、REFUTE＝ln(TNR／(1−TPR))），任一邊 near_zero → 兩邊都是 0；範例的權重、θ_confirm（2.5，新尺度）與 K-011 的 provisional 隨之更新。
- θ_confirm／θ_reject 依 CWE 桶分開（`by_bucket`）；沒有列出的桶、不可行或未能類推（`generalised: false`）的門檻都視為 +∞。
- `high_precision_rules` 記錄 tp／fp 與保留切分計數，由 validator 重算 Clopper-Pearson 下界與列入條件（新錯誤碼 `E-CAL-HIGH-PRECISION`）。
- 模型版本或驗證 prompt 與校準時不同 → 權重 0（`Index.calibrated_setup_problem`）；`valid_for_model_keys` 空清單代表沒有任何模型有效。
- models.yaml 新增 `derived_from`；家族與血統的獨立性以血統的根判定。
- 新增 `tests/test_v06_r7_calibration.py`。

### 第七輪審查：裁決規則（第 3 組之一；`rule_version` 改為 `05-v0.6`）
- R10：只有 G4 核准、重播至少命中一次的 B4 證明能推翻 G2 駁回；W4 證明只加註 `post_g2_conflict`（`checks.proof_overrides_g2`）。
- Result Analyst 排除寫測試的家族（W4 的 test_generator／test_critic；黑箱的 test_designer、test_implementer、test_critic 與威脅的 threat_modeler）。
- 機率型測試依 adapter、`multi_turn` 與 `trials.record` 判定，n 必須達到 PASS 所需的有效次數（`E-TC-TRIALS`）。
- R0：沒有任何接地證據、至少一項 NOT_FOUND（NOT_CHECKED 不再能逃過）。
- 05 寫明反駁票的一致決設計。
- 不採納：審查 3.7（CMD-2 加入的家族不併入 `cluster.families`）。那會讓加派回報的家族也能驗證自己的回報，重新引入自我偏好；保留排除只會讓驗證者池變小，這已由 `no_eligible_verifier` 顯示出來。
- 新增 `tests/test_v06_r7_adjudication.py`。

### 第七輪審查：流程完整性與有效覆蓋率（第 2 組，含外部審查 5）
- 新增 `E-PIPELINE`：叢集都有裁決、已驗證的發現項都在叢集中；DISPUTED／高嚴重度 UNCORROBORATED 叢集經過 G2 或列為 over_cap；沒有被駁回的白箱叢集是種子或 report_only；G2 駁回的不是種子；G3 後種子都有威脅；`manual_review_clusters` 由裁決推導；報告的 gaps 與 artifacts 完整。
- 範例修正：K-014（LIKELY）原本既不是種子也不是 report_only，補上種子 ST-004（T-012）；報告 artifacts 補上 V-014-1、V-015-2、V-016-1 與 W4 結果 R-WTC-015-01-1。
- report `metrics`：`access_matrix_coverage`／`endpoint_test_coverage` 改名為 `planned_*`，新增 `executed_access_matrix_coverage`、`executed_endpoint_test_coverage`（只算有有效執行結果的測試案例，`checks.execution_backed`）。
- 新增 `tests/test_v05_r7_pipeline.py`。

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

### 一致性（第 5 組）
- run.schema 的 `skip_reason`、`gaps[].kind` 補齊文件要求的值；audit-event enum 加入 `gate_load_warning`。
- Z2 單一 job 輸出上限統一為 200 MiB；Hypothesis／fast-check 的授權用途改為 `w4_test`；crosswalk 補 T-031 用到的 CWE-862 與 ASI 對照（engagement 重新釘選、重簽）。
- 03 的 W3 補上驗證者節點 `W3_verify`；08 的分層以 L3 `lgapi` 解開 `nodes`／`graph` 的循環；契約往返改用 `exclude_unset=True`。
- G0b 與 `legal_review` 移到 MVP-1；M2-X9、M2-X13 加上 U-10 前的部分驗收；W0 的規則式 PII 偵測器提前到 M2（MVP-0）。
- `whoami` 簽名、ROE `edge_ip_ranges`、`executed_jobs`（job 帳本才是權威）、成本模型（B3、W4、W3 的 M）在 03 與 08 之間對齊。
- 架構圖：雲端 LLM 與 Z4 的資料等級、W1 方塊不含 secrets、補上 Calibration Lab。
- 其他：MVP0-X7 補 psycopg 與 G-11、promptfoo 的條件、00 的三個範例、共享平台清單（21 個）、範例 B 的請求數、08 的測試清單。
- 新增 `tests/test_v05_round6_group5.py`。

### 其餘的 validator 繞過（追加組）
- 裁決版本必須形成單一線性鏈（`E-VERDICT-CHAIN`），`verdict_counts` 取每條鏈的最新版。
- 同一種文件的 ID 不能重複（`E-ID-DUP`）；`Ctx.runs` 與 `Index.first` 都取第一個文件。
- 白箱叢集的位置、sink、symbol 與 CWE 桶綁定成員證據，指紋不重複（`E-CLUSTER-BINDING`；新增 `facets.CWE_BUCKETS`）。
- B4 job、`sandbox_job_*` 事件與測試結果對帳（`E-JOB-AUDIT`）。
- `readjudicated_by` 不能倒填（`E-VERDICT-PHASE`）。
- 新增 `tests/test_v05_round6_group6.py`。

### 低優先項目（審查 §4.3）
- 嚴格載入器拒絕巢狀超過 64 層與孤立 surrogate（原本是 `RecursionError`／整組 `E-INTERNAL`）；`Bundle.doc("")` 不再對到第一個文件。
- `reporter.round` 由指揮官計畫推導（`E-FINDING-ROUND`）。
- E(cluster) 只算可以收該資料等級的驗證者；`g4_approved` 看最後一份對該測試案例做決定的 G4；高風險威脅的機率型 PASS 需要 n′ ≥ 60。
- Scope Proxy 白名單比對的參考實作 `safety.allowlist_match`；SUSPENDED 的 resume 由 run_owner 或發起者簽；ASI09 抽查改用簽章事件 `spot_check_result`。
- 安全等級的 S1 下限改看 `is_mutation`；純白箱 bundle 可以沒有 ROE；FAIL 必須 k ≥ `fail_k_min`；`E-TC-TOOL`（Schemathesis 只讀、zap baseline 要 `-S`）、`E-THREAT-ATTACK-TREE`、`E-COVERAGE-D5`；`E-SEED-SIDE-EFFECT` 以路徑形狀比對。
- 文件：quorum 的檢查範圍、`min_version` 的限制、`report_only` 拉回 G3 的方式、範例 B′ 需要的 G1 列。
- 新增 `tests/test_v05_round6_lowprio.py`。

### 待辦清單整理
- `docs/09-backlog.md` 新增 §4：第六輪只寫成規格或參考實作的部分，以及處理時記下的限制（BL-36～BL-47）；已處理的 BL-15、BL-24、BL-25、BL-26 移到 §5，編號保留。

### schema 待辦（BL-14、16～20、40）
- 每家族的 USD 上限：engagement `budgets.families`（家族必須存在於 models.yaml，上限不超過 run_total；`E-ENG-BUDGET`）。
- B1 爬行預設：toolkit `b1_crawl`（只允許 GET／HEAD／OPTIONS、不送表單、同 origin、每目標 ≤ 200 個請求、深度 ≤ 5；跳過關鍵字只能加不能刪，`E-TOOLKIT-B1`）。
- PR／issue 發布：engagement `publishing`，預設關閉；開啟時必須宣告平台與最小權限的權杖範圍（`E-ENG-PUBLISH`）。
- 誤報回饋：新增 `feedback.schema.json`。回饋紀錄要簽章、指紋必須是所指叢集的、SARIF suppression 依標籤決定（`E-FEEDBACK`）；`sign_examples.py` 會簽回饋範例 FB-001。
- 排程工作：inventory 的 `kind: scheduled`（`method` 為 null、路徑寫成 `schedule:`／`queue:`；`E-INVENTORY`）；範例加上一個排程工作。
- 覆蓋指標：testcase 與 w4-testcase 新增 `access_cells`（`E-TC-ACCESS-CELL`）；report `metrics` 新增 `access_matrix_coverage`、`endpoint_slice_coverage`、`endpoint_test_coverage`，由 validator 重算（`E-REPORT-METRICS`）。
- 外洩比對：seed `sensitive_fields` 與參考實作 `safety.sensitive_leaks`（`E-SEED-SENSITIVE`）。seed manifest 內容改變，ROE 的 `seed_manifest_sha256` 隨之更新並重簽。
- 新增 `tests/test_v05_schema_backlog.py`。每個新檢查都做過驗證：單獨停用時，只有它自己的測試失敗。

### 白箱測試案例（BL-27）
- 新增 `w4-testcase.schema.json`：W4 在 Z2 執行的單元、性質、本地 RLS 與假模型測試，與黑箱 testcase 分開。validator 檢查 run 與叢集、oracle 只引用 G1 已核准的 `requirement_ids`、reachability 對照、`local_rls` 的拋棄式 Postgres 與 migration（`E-W4-TC`、`E-TC-REQ-UNAPPROVED`、`E-TC-CONTROLS`）。
- 修正：W4 的測試結果原本只能在黑箱測試案例中查找，等於借用黑箱測試案例的對照與 oracle。現在 `phase: W4` 的結果以 `testcase_id` 指向 W4 測試案例，借用黑箱測試案例是錯誤；W4 結果的 `target_ids` 為空，B4 結果至少一個目標（`E-RESULT-TARGETS`）。
- 範例：K-015 的本地 RLS 測試 WTC-015-01、結果 R-WTC-015-01-1、裁決 V-015-2（`W4_readjudicate`，R1 `CONFIRMED_EXECUTABLE`）；種子 ST-003 改指這一版，報告的裁決統計與結果數隨之更新，稽核紀錄在 G2 之後插入一筆 `verdict_changed`，之後的序號順延一號。
- 修正：W4 結果原本不需要任何執行證據，寫一份 W4 FAIL 就能讓叢集成為 `CONFIRMED_EXECUTABLE`。現在每個 W4 結果要對應一筆已錨定的 W4／Z2 `sandbox_job_end`（`E-W4-AUDIT`）；範例補上 WTC-015-01 的執行事件。
- W4 完成條件：每條 G1 核准的不變量都有 W4 測試案例，或列在 run 新增的 `w4_manual_requirements`（`E-W4-COVERAGE`）；範例的 INV-LLM-003 標為 MANUAL。
- `W4_testgen` 的輸出加入跨廠商 LLM schema 子集（`LLM_OUTPUTS` 的 `w4-testcase`）。
- 新增 `CONTRIBUTING.md`：每個宣稱修好的錯誤都要有回歸測試，並證明拿掉修正時測試會失敗。
- 新增 `tests/test_v05_bl27_w4.py`；既有測試中借用黑箱測試案例的 W4 結果改用 W4 測試案例。

### 提升為高優先的待辦（BL-04、BL-13、BL-21、BL-22、BL-23；schema 與 validator）
- G5 紀錄新增 `g4_gate_record_id`：指向本 run 中該測試案例最新且 accept 的 G4，在 G5 開啟前決定，G4 與 G5 的核准者不重疊（`E-G5-G4`，BL-04）。
- 逐項決定新增必填的 `carried_from`，重新啟用跨 run 的 G1／G3 沿用：只限 accept、來源是祖先 run 的同一關卡、同項目同 hash，來源簽章以現行金鑰登錄重新驗證，G3 另要求同一份 ROE；G4／G5 不沿用（`E-GATE-CARRY`，BL-21）。
- run 的 `config_refs.invariants`／`seed_manifest` 可以是 `{state: pending, expected_node}` 或 `{state: not_applicable, reason}`；validator 依 run 已到達的節點判斷「應存在但遺失」，沒有說明的 null 一律是錯誤（`E-RUN-CONFIG`，BL-22）。沒有 B 階段內容的 run 可以把 `seed_manifest` 標為不適用（BL-23）；範例的 Lane A run 改用這個寫法。
- 叢集新增 `origin: tool_only` 與必填的 `tool_report_refs`：沒有 LLM 成員，引發叢集的工具結果是回報、不算佐證（`E-CLUSTER-ORIGIN`、`E-SARIF-REF`）；run 新增 writer 導出的 `tool_results_ref`（BL-13）。
- 範例新增純工具叢集 K-016 與裁決 V-016-1（`UNCORROBORATED`，列在報告的 `report_only_clusters`）；W1 稽核事件加一筆 opengrep 結果，其後的稽核序號順延一號。
- 修正：中途結束（ABORTED、FAILED）、沒有走到產生節點的 run，產物仍可以是「尚未產生」（正常完成的 run 不能留下「尚未產生」），不再誤報「應存在但遺失」；G5 只看它開啟時最新的 G4 決定，之後的 G4 重審不會讓已核准的 G5 變成錯誤。
- 修正：SARIF 參照（`sarif_refs`、`tool_report_refs`）只能由 W1 的 `tool_invocation_end` 事件支持（`E-SARIF-REF`）；之前同一筆工具結果記成其他節點的事件時，run 的 `tool_results_ref` 是 null，叢集卻仍可引用它。
- 本節之前的「跨 run 的 G1／G3 沿用停用，直到 BL-21 完成」由上面的 `carried_from` 取代。
- 新增 `tests/test_v05_backlog_high.py`；09 待辦清單把這五項移到 §5。

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

依 [2026-10-24 設計審查](docs/evidence/review-2026-10-24.md) 的第一到第三優先項目，以及寫入範圍的其餘項目與第五輪（見下方各節）：修正裁決規則的邊界與 validator 的繞過；把跨境聲明移到 G0a、補上事故應變、釘選設定檔、修正信任錨與 Scope Proxy；在 MVP-1 前加入核心假設的前導實驗、降低人工關卡負擔、修正對照表與範例。其餘審查項目與理由見該紀錄 §5。

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
