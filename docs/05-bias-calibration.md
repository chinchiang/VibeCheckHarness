# 05 降低模型偏誤：證據、規則、裁決、校準

> 你的需求：白箱每個 agent 可以接不同 LLM，以減少模型差異造成的偏誤。本文件說明：證據支持到什麼程度、工具包怎麼設計、以及**必須自己量測**的部分。標記說明見 [README](../README.md#標記說明)。

## v0.4 變更摘要

依 2026-10-24 設計審查（[review-2026-10-24](evidence/review-2026-10-24.md)）修正會讓真漏洞在沒有人看到時被駁回或降級的規則邊界；`rule_version` 改為 `05-v0.4`。

- **R0 只在叢集沒有任何其他證據時成立**（§4.2）：除了「所有成員的所有證據都是 `NOT_FOUND`」，還要沒有已解析的 SARIF（強或弱），也沒有 FAIL 類測試證據（`E_proof`／`E_fail_u`）。v0.3 中，LLM 片段的行號偏移超過 ±3，就能讓掃描器或可重現 FAIL 也指向的叢集被駁回，而且不進 G2、不成為種子威脅。（審查 A1）
- **可執行證明不被 G2 駁回覆蓋**（R10）：G2 駁回對投票、SARIF 與 `E_fail_u` 仍是最終決定；但 `E_proof` 出現時，叢集改為 `CONFIRMED_EXECUTABLE`（`rule_trace` 為 R10、R1），加註 `post_g2_conflict`，列入 B6 人工複核清單。理由：事先登記、重播成立的確定性 FAIL，比測試出現之前的人工判斷更有力；v0.3 會讓它在 SARIF 中維持 `REJECTED` 而被壓掉。G2 的 accept 仍不是規則輸入。（審查 A4）
- **R11 降級需要正對照**（§4.2）：合格 PASS 只有在有 `oracle_can_fail` 對照且為 PASS（`positive_control: true`）時，才把 `CONFIRMED_CORROBORATED`／`LIKELY` 降為 `DISPUTED`；沒有正對照的 PASS 只加註 `test_not_reproduced`。沒有證明過自己能失敗的測試，不能用來反駁。W4 的 `E_pass` 本來就要求 `oracle_can_fail` 對照；受影響的是 G4 核准但沒有正對照的黑箱 PASS（例如 ZAP 通用掃描）。（審查 A3）
- **`NOT_CHECKED` 不計入獨立家族**（§4.1）：計入獨立家族的發現項必須至少有一項**已接地**的證據（`MATCHED`／`MATCHED_SHIFTED`）。v0.3 只排除「全部 `NOT_FOUND`」，兩個家族各交一份無法檢查的 `config_fact` 就能到 `LIKELY`。（審查 A2）
- **SARIF 只佐證自己位置的叢集**（§4.2）：稽核事件 `payload.sarif_results[]` 的每一項加上 `file`、`symbol`、`cwe_bucket`（正規化器的輸出），必須等於叢集的正規位置與桶；黑箱叢集不收 SARIF。v0.3 只檢查 ref 在稽核檔中，任何單一家族叢集都能借一筆無關的結果當弱訊號而到 `LIKELY`。（審查 D1）
- **程式片段要有實質內容**（§3 規則 5）：遮罩後片段至少 12 個非空白字元，且含一個 3 字元以上的識別字；片段的檔案必須在該發現項的切片中。單獨一個 `}` 在任何視窗內都找得到，v0.3 會把它當成已接地。（審查 D4）
- **quorum 的定義**（§3 規則 3）與 **`single_best_resampled` 下的裁決**（§5.6）補上定義。（審查 A8、A9）
- **第五輪**（[review-2026-10-24 §9](evidence/review-2026-10-24.md#9-第五輪剩餘項目)）：
  - **支持與反駁權重分開**（§4.3）：支持票的權重取自真缺陷上的票、反駁票的權重取自已知非缺陷上的票，各自平滑與套用「接近 0」判準。v0.3 的單一正確率會讓永遠投支持的驗證者也拿到正權重。（審查 A10）
  - **`provisional` 只標在投票可能決定的裁決**（§4.2）：R0、R1、R9、R10 決定的裁決與黑箱叢集一律不是暫定。範例 K-202 改為 false。
  - **合格票的引用必須與叢集相關**（§4.2），`anonymized`／`order_randomized` 由 run 的 verifier 範本推導。（審查 A6、D5）

## v0.3 變更摘要

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

## v0.2 變更摘要

- **裁決規則補齊為全函數**（§4.2）：新增測試證據分類（`E_proof`／`E_fail_u`／`E_pass`／`E_inc`）、R9（Lane A 上限，D8）、R10（G2 人工駁回）、R11（合格 PASS 修正）、R12（不確定測試結果只記錄）、R13（G3 駁回種子威脅只註記，D5），並附**決定表**，使每種輸入組合恰好對應一個狀態。機率型 LLM 測試的 k 門檻、重播（n_r＝20）與有效次數下限（n′ ≥ 30）對齊 04 §4.4；只有 LLM grader 判定的違反列 `E_inc`。
- **修正 v0.1 的兩個漏洞**：R4「只有合格反駁」但有工具佐證時一律 `DISPUTED`，不再自動 `REJECTED`；R6 改為「≥ 2 個家族獨立回報、沒有計權反駁、未達 R5」即 `LIKELY`（v0.1 中「2 家族＋支持但 S 未達門檻」會掉到 `UNCORROBORATED`）。
- **G2 路由對齊 02 W3**：G2 佇列＝所有 `DISPUTED`＋最高嚴重度為 critical／high 的 `UNCORROBORATED`；其他 `UNCORROBORATED` 直接成為種子威脅；佇列為空就略過 G2（`gate_skipped`）。
- **重新裁決節點**：`W4_readjudicate`、`B5_readjudicate`；每次產生新版裁決（append-only）。
- **權重公式明確化**（§4.3）：平滑後投票正確率 a → w＝max(0, 2a−1)，並定義「接近 0」的判準。
- **校準語料**（§5.1）：組成、各 CWE 桶目標數、按應用切分的校準／保留集、汙染控制、雙標註者＋κ 門檻＋仲裁。
- **預先登記的主要假設**（§5.6）：③ 多家族 vs ② 單一最佳模型重複取樣，含檢定、α、最小效果量、逐步樣本數計算，以及 ③ 未勝出時的預設設定切換。
- **次要／探索性分析**：驗證者真陰性率分開報告（M-11）；少數否決組 ⑤ 只作探索，不改主要假設。
- **門檻調整**（§5.7）、**模型版本變更的最小重跑集**（§5.8）、**M2 出場門檻**（§5.3）、**校準設定／結果欄位**（§5.9，schema 見 [schemas/calibration.schema.json](schemas/calibration.schema.json)）。
- **validator 推導旗標**（§3 第 3 條、§4.2）：`diversity_degraded`＝有效且投票者角色為 `verifier` 的票中不同家族少於 2（家族由 `voter_agent_id` 經 agents／models 登錄解析），`tool_corroboration`＝叢集已解析（對應到稽核檔中白箱工具輸出，否則 `E-SARIF-REF`）的 `sarif_refs` ∪ `E_fail_u` 測試結果的 `result_ref`；都與裁決自己宣告的值比對，不採信自我宣告，規則以推導值重算。
- **§2 證據補充**：新增 preference leakage、身分驅動的自我偏好、反證（可驗證修訂任務無自我偏好）、同質辯論、異質驗證、評審的「好好先生」偏誤、Cursor Bugbot 的同模型多次審查；§5.1 補上資料集授權。只改證據敘述，不改規則。

## 1. 「偏誤」指什麼

研究文獻裡的 bias 指的是**評審偏誤**與**錯誤相關性**，不是公平性偏誤 [V：研究限制，見 ledger multi_llm_bias 主題]。本工具包處理下列三類：

| 偏誤類型 | 意思 | 機制 | 量測指標（§5） |
|---|---|---|---|
| 共同盲點／錯誤相關 | 不同模型在同樣的地方犯錯 | 多家族獨立審查、校準加權 | 兩兩錯誤相關（Cohen's κ、CAPA）、recall 差異 |
| 評審自我偏好 | 模型評審時偏好自己（或同家族）的輸出 | 驗證者與報告者不同家族與血統、匿名化 | 評自己 vs 評他人的分數差 |
| 位置／表面特徵偏誤 | 候選順序、變數名稱、註解、格式影響判斷 | 隨機順序、證據接地、輸入一致 | 交換順序後的翻轉率 |

## 2. 證據

> 注意：下列研究大多使用一般 NLP 或 MMLU 任務、以及較舊的模型。**能否轉移到「AI 生成應用的安全審查」是假設**，要靠 §5 的實驗驗證。

### 2.1 支持「多家族＋獨立＋驗證」的證據
- **錯誤相關**：Kim et al.（ICML 2025）測了 350 多個 LLM，發現錯誤高度相關。在某個 leaderboard 資料集上，兩個模型同時答錯時，有 60% 的機率答成同一個錯誤答案；越大、越準的模型錯誤越相關，**即使架構與供應商不同** [V][E:multi_llm_bias-01]。同一篇論文也發現（MMLU 資料），LLM 評審會高估**比自己弱**的模型，尤其是同供應商或同家族的模型，並低估比自己強的模型 [V][E:multi_llm_bias-02]。
  - → 多家族可能有幫助，但幫助**有限**。
- **自我偏好**：
  - GPT-4 與 Llama 2 能辨認自己的輸出；自我辨識能力與自我偏好強度呈線性相關（Panickssery et al.，NeurIPS 2024）[V][E:multi_llm_bias-05]。
  - 在可客觀驗證的 rubric（IFEval、LiveCodeBench）上，對於生成者沒做到的 rubric 項目，評審在評自己的輸出時，錯判為「已滿足」的機率高出 50% 以上；集成多個評審可以減緩，但不能消除（Pombal et al.，2026）[V][E:multi_llm_bias-08]。
  - 評審會偏好與自己相關的學生模型（同一模型、繼承關係或同家族），而且這種偏誤比已知的評審偏誤更難察覺（Preference Leakage，Li et al.，列為 ICLR 2026 接受）[V][E:multi_llm_bias-45]。
  - 在 8 個 LLM、約 41,000 次查詢的 72 個實驗中，模型一致偏好「自己的身分」，而且偏好跟著**被指定的**身分走，不是真實身分（預印本）[V][E:multi_llm_bias-46]。→ 支持驗證時去除來源模型資訊（§3 規則 2）。
  - → 驗證者不能與報告者同家族。
- **位置偏誤**：以 ChatGPT 當評審時，只要交換候選順序，Vicuna-13B 在 80 題中就有 66 題「勝過」ChatGPT（Wang et al.，ACL 2024）[V][E:multi_llm_bias-12]。→ 隨機順序。
- **程式表面特徵偏誤**：程式碼評審會受變數名稱、註解、格式等表面變化影響，所有受測評審都出現分數高估與低估（Moon et al.，EACL 2026 Findings）[V][E:multi_llm_bias-10]。另外，SecLLMHolmes 發現，重新命名函式或變數、加入函式庫函式，會讓 LLM 的安全判斷出錯；這類擾動造成最多 26%／17% 的錯誤答案 [P][E:multi_llm_bias-26]。→ 各家族看到一致的輸入。
- **跨家族評審團**：由不同家族的小模型組成的評審團，在 3 種評審設定、6 個資料集上，比單一 GPT-4 評審更貼近人類判斷，偏誤較少、成本低 7 倍以上（PoLL）[V][E:multi_llm_bias-09]。
- **異質性有助於辯論**：Zhang et al. 的立場論文（未獲 NeurIPS 2025 Position Paper Track 接受）表示，讓參與辯論的模型異質化能「穩定」改善辯論框架（作者用語）[V][E:multi_llm_bias-17]。ReConcile 的作者也說，來自不同模型的多樣性對效能很關鍵 [P][E:multi_llm_bias-18]。
- **漏洞偵測的互補性**：較弱的 LLM 仍會提供其他模型沒有的正確預測；投票比 GPT-3.5 好 10% 以上，但相對最佳單一模型只好約 4%（cross-validation）；未找到發表場所（Widyasari et al.，2024）[V][E:multi_llm_bias-28]。
- **異質驗證抗操縱**：一篇預印本（兩個資料集合計 47,807 次互動）發現，worker 能力越強，平均攻擊成功率反而從 18.4% 升到 63.9%；改用異質集成驗證後，攻擊成功率從 52.8% 降到 2.0% [P][E:multi_llm_bias-41]。論文中 74% 的中介效果只在較大的 Worker-Only 設定成立，Full-MAS 設定只有方向一致的效果。研究對象是多代理系統的安全，不是程式審查。
- **跨模型 critic 可以大量淘汰錯誤候選**：Refute-or-Promote（預印本）以對抗式 kill agent＋跨模型 critic 合併運作，淘汰 171 個 LLM 候選漏洞中的約 79%；作者也說「沒有任何漏洞是自主發現的」，流程中有人參與 [V][E:whitebox-32]。

### 2.2 限制或反對「多家族」的證據
- **混用多家族不一定更好**：「Rethinking Mixture-of-Agents」發現，混用不同 LLM 常會**拉低**平均品質；只用單一最佳模型的多次輸出做彙整（Self-MoA），在 AlpacaEval 2.0 上勝過混合 MoA 6.6%，在 MMLU、CRUX、MATH 平均勝 3.8% [V][E:multi_llm_bias-19]。
  - **這直接挑戰本工具包的前提**，所以 §5 一定要有 Self-MoA 對照組。
- **辯論的效益大多來自多數決**：Choi et al.（NeurIPS 2025，7 個 NLP benchmark）證明，單純辯論是 martingale，不會提高期望正確率 [V][E:multi_llm_bias-16]；但這只是一篇論文、NLP 任務，未在安全審查上驗證 [P][E:multi_llm_bias-37]。辯論常常打不贏 self-consistency [V][E:multi_llm_bias-15][E:multi_llm_bias-17]。→ 不做多輪辯論。
- **辯論中由對轉錯**：模型常在讀了同儕推理後從對的答案轉成錯的；原因未定（作者列出諂媚、從眾、模型與任務類型等可能因素；ICML 2025 workshop）[P][E:multi_llm_bias-21]。→ 第一輪互不可見。
- **同家族互審會「回音」**：一篇 2026 單一作者預印本的兩個實驗中，由 Claude 模型審查 Claude 生成的程式碼，錯誤會互相呼應而非抵銷；另有一個 4 個模型、3 個家族的跨家族實驗；作者主張以可執行規格當品質關卡，AI 審查只處理規格之外的殘餘問題 [單源][S-02]。→ 這與本工具包的 W0.5 規格＋可執行測試相符。
- **自我偏好不一定存在**（反證）：一篇 7 頁預印本在 IFEval 的可驗證修訂任務上，以 4 個中階模型家族做 85 組比較，**沒有**測到自我偏好（差距 −5.1 個百分點，95% CI [−12.9, +2.7]）[V][E:multi_llm_bias-47]。→ 自我偏好的大小要在 §5 量測，不能假設。
- **同質辯論不划算**：10 個相同的 7–8B 模型辯論，表現不如各自獨立的自我修正；出現諂媚式從眾（最高 85.5% 採用多數答案），且多用 2.1–3.4 倍 token（預印本）[V][E:multi_llm_bias-42]。→ 與「不做多輪辯論」（§3 規則 1）一致。
- **評審的「好好先生」偏誤**：在 366 個 Python 程式、14 個 LLM 的程式回饋任務上，LLM 評審的真陽性率約 96%，真陰性率卻低於 25%；作者先提出少數否決（minority-veto）作為一種緩解做法，另外再提出以迴歸為基礎的偏誤修正框架；1.2% 的最大絕對誤差來自**迴歸框架本身**，約為 14 個前沿 LLM 中**表現最好的集成**的一半（預印本）[P][E:multi_llm_bias-43]。→ 驗證票可能系統性偏向「支持」。本文件因此把驗證者的真陰性率分開報告（§5.3 M-11），並把少數否決列為**探索性**對照組 ⑤（§5.2）；兩者都不改變 §5.6 預先登記的主要假設。
- **業界的同模型多次審查**：Cursor 的〈Building a better Bugbot〉一文說明：Bugbot 上線時（v1）的流程是 8 次平行審查（每次隨機化 diff 順序）加多數決，只在一次中出現的 bug 會被濾掉，之後再由驗證模型剔除誤報；Cursor 自述解決率從 52% 升到 70% 以上，未公開模型名稱；同文也說 Bugbot 之後已改為 agentic 架構 [P][E:reference_systems-45]。→ 上線版流程是 §5.2 ②（單一最佳模型多次取樣）在實務上的對應做法；現行版本已不同。
- **沒有外部回饋時，自我修正常失敗**（Huang et al.，ICLR 2024）[V][E:multi_llm_bias-24]。→ 以工具、測試、跨家族驗證作為外部回饋。

### 2.3 LLM＋工具／執行
- **LLM 推 spec，工具追蹤**：IRIS 讓 LLM 推論 taint spec 再交給 CodeQL，找到 55 個漏洞，CodeQL 單獨只找到 27 個；**比較對象是 CodeQL 單獨，不是純 LLM** [P][E:multi_llm_bias-37][V][E:whitebox-18]。
- **混合管線優於純 LLM**：只有一篇 2026 預印本（Multi-LLMSecCodeEval，研究對象是安全**程式生成**）直接證明 [單源：未經同儕審查的預印本][E:multi_llm_bias-32]。
- **agent 框架大幅降低 SAST 誤報**（預印本，結果只限該 benchmark）：在 OWASP Benchmark 上，SAST 誤報率從 92% 以上降到最低 6.3%；但效果很依賴底層模型，較弱的模型效益有限，而且過度壓低誤報可能壓掉真的漏洞 [V][E:whitebox-33]。
- **benchmark 高估效能**：常見漏洞 benchmark 因標註錯誤、重複與資料洩漏而高估效能。同一個 7B 模型在 BigVul 上 F1 為 68.26%，在 PrimeVul 上只有 3.09% [V][E:multi_llm_bias-25]。

### 2.4 沒有找到的證據
本研究**未找到**（搜尋未窮盡）任何研究量測過「Claude、GPT、Nemotron 在『AI 生成應用的安全審查』上的錯誤相關性」，也沒有找到以跨廠商分歧作為安全審查分流訊號的同儕審查研究 [P][E:multi_llm_bias-38]。

## 3. 設計規則

1. **獨立優先**：第一輪平行、互不可見；用加權多數決，不做多輪辯論。
2. **不自評**：一張票只有在投票者的 `family` **不在**叢集的 `families` 中、`lineage` **不在**叢集的 `lineages` 中時才有效（叢集可能由多個家族回報，所以是「不屬於任何回報者的家族」，不只是「不同於某一個報告者」）；驗證時去除來源模型資訊；候選順序隨機化。karpathy/llm-council 也把互評匿名化，以免模型「偏袒」[V][E:reference_systems-31]。
   - **沒有合格的驗證者**：合格驗證家族 E（定義見規則 3）為空時，設 `no_eligible_verifier`，例如 3 個家族都回報了同一叢集。這種叢集沒有票；它由多個家族獨立回報，依 R6 為 `LIKELY`，所以**不進 G2**（G2 只收 `DISPUTED` 與高嚴重度的 `UNCORROBORATED`，規則 7）。確認改由可執行測試：W4 白箱測試，以及轉成種子威脅後的黑箱測試（B3–B5）[H]。
   - 確定性 oracle 判定的 FAIL，若解讀已事先登記，不需要 Result Analyst 就是 `E_proof`（§4.2）。所以這種叢集仍能升到 `CONFIRMED_EXECUTABLE`。
   - 例外：其他家族只在 CMD-2 加派時才回報（不算獨立回報，§4.1），獨立來源可能只有 1 個 → R7 `UNCORROBORATED`，照一般的 G2 路由（規則 7）。
3. **不跨家族 fallback**：reviewer 與 verifier 只允許同家族 fallback，且要記錄；失敗就記為缺票。
   - **fallback 的票** [H]：同家族 fallback 模型可以投票。票照樣保存，`valid` 照定義判斷；但權重取 **fallback 模型自己**的校準權重（依票上的 `voter_model_key` 查，§4.3）。fallback 模型在完成 §5.8 的重跑前所有桶 w＝0，所以它的票有紀錄、但不是計權合格票。例如 `claude_opus_48` 代替 `claude_sonnet` 擔任 `ver_2` 時就是這樣。
   - **quorum**（v0.4 定義）[H]：W2 的 quorum 是「每個切片 × 必要面向，取得結果的 reviewer 家族數 ≥ min(2, 該切片的合格 reviewer 家族數)」；合格 reviewer 家族＝`agents.yaml` 中角色為 `reviewer`、模型在委任設定該資料等級的 `allowed_models` 中、且不在切片 `excluded_models` 中的家族（CMD-1 計畫必須達到它，`E-PLAN-FAMILIES`）。W2 缺票造成 quorum 不足時**不是** R8：它直接表現為獨立家族數較少（例如 `LIKELY` 變成 `UNCORROBORATED`），報告列出缺票與 quorum 不足的切片。R8 只看 verifier 的計權合格票（下一條）。
   - **驗證家族不足**時照常執行並照常裁決，但**只靠投票**得到的確認最高只到 `LIKELY`（R8）；報告標示 `diversity_degraded` 並列出缺少的家族。可執行證明（R1）或**強**工具佐證（R5 第 10 列）的確認不受此上限影響。
   - **判定方式（validator 強制）** [H]：
     - **合格驗證家族** E(叢集)：`agents.yaml` 中角色為 `verifier` 的 agent，家族不在叢集的 `families`、血統也不在叢集的 `lineages`；E 是這些 agent 的家族集合。家族與血統由 agent → `agents.yaml` 的模型 → `models.yaml` 解析，不看自寫的值。
     - `no_eligible_verifier` ＝ |E| ＝ 0。
     - `diversity_degraded` ＝ 非 Lane A，|E| ＞ 0，且**計權合格票**（§4.2）中不同家族的數目 ＜ min(2, |E|)。只計角色為 `verifier` 的 agent 所投的票。Lane A 一律為 false（Lane A 另有 R9 上限）。
     - **為什麼這樣定義**：v0.2 用「有效票中不同家族少於 2」。3 個家族時，被 2 個家族回報的叢集只剩 1 個合格驗證家族，旗標永遠為真、永遠被 R8 封頂；回報的家族越多，上限反而越低。新定義只和「這個叢集最多能有幾個合格驗證家族」比較，所以不再倒置。
     - 校準前所有 w＝0，所以每個 |E| ＞ 0 的叢集都會標 `diversity_degraded`。這如實反映「沒有任何經校準的票」；這些裁決同時標 `provisional`（§4.2）。
4. **輸入一致**：所有家族看同一個切片（共同輸入上限＝所有參與模型中最小的可用 context，見 [02 W2](02-methodology.md#w2-多家族獨立審查)）。
5. **證據接地**：證據一律由 harness 以程式碼比對，不靠 LLM 判斷 [H]。
   - **證據種類**（`kind`）：
     - `code_snippet`：`file`、`line_start`、`line_end`、`snippet`（遮罩後的程式片段）。
     - `inventory_fact`：`fact_ref`（指向本 run W0 inventory 的 JSON Pointer，例如 `/db/tables/0/rls_enabled`）＋`asserted`（主張的值，例如 `false`）。
     - `config_fact`：`file`＋`key_path`（指向已解析、已遮罩設定檔的 JSON Pointer）＋`asserted`（主張的值；字串 `"<absent>"` 表示主張該鍵不存在）。
     - 後兩種用在「缺少某物」類問題，例如沒有 RLS、沒有認證 middleware、沒有限流設定。這類問題交不出一段程式碼；v0.2 只收逐字片段，所以它們一定比對失敗，並被 R0 駁回。
   - **一律比對遮罩後的文字**：片段與比對對象都是 W0 遮罩之後的切片，不是原始碼。
   - **容錯比對**（`code_snippet`）：先正規化空白（去掉每一行頭尾的空白、連續的空白與 tab 合併為一個、統一換行字元、片段前後的空白行不計），再在第 line_start − 3 行到第 line_end + 3 行之間尋找：
     - 在所寫的行號找到 → `MATCHED`；
     - 在範圍內其他行找到 → `MATCHED_SHIFTED`，harness 改寫 `line_start`／`line_end`；
     - 範圍內找不到 → `NOT_FOUND`。
   - `inventory_fact`：指標能解析、且值等於 `asserted` → `MATCHED`，否則 `NOT_FOUND`。`config_fact` 相同；`asserted` 為 `"<absent>"` 時，該鍵不存在才是 `MATCHED`。
   - 任何種類，harness 無法檢查時（例如設定檔無法解析）→ `NOT_CHECKED`。它不算接地，也不算 `NOT_FOUND`：不會觸發 R0，也不讓發現項計入獨立家族（v0.4，§4.1）。
   - 只有 `MATCHED`／`MATCHED_SHIFTED` 的證據算**已接地**。叢集所有成員的所有證據都是 `NOT_FOUND`，**而且**叢集沒有已解析的 SARIF、也沒有 FAIL 類測試證據 → R0 `REJECTED`（v0.4）。
   - **片段要有實質內容**（v0.4）[H]：`code_snippet` 正規化後至少 12 個非空白字元，且含一個 3 字元以上的識別字（`vchlib.evidence.snippet_content_problem`）；不符 → 比對結果為 `NOT_FOUND`，validator 報 `E-FINDING-EVIDENCE`。片段的 `file` 必須是該發現項切片 `files[]` 中的檔案（`E-FINDING-EVIDENCE`）。門檻是設計假設，用來擋掉 `}`、`);` 這類在任何視窗內都找得到的片段。
   - **reviewer 與 verifier 看不到工具輸出**：W2 reviewer（含 CMD-2 加派的輪次）與 W3 verifier 都**不會**收到 W1 的工具輸出（SARIF 等）。工具結果只經由確定性的 Clusterer／Aggregator 進入裁決（§4.1、§4.2 R2）。原因：reviewer 若先看到掃描器命中、再回報同一位置，只是把掃描器的同一次命中重複一遍。一個家族重複掃描器的結果不是獨立證據，卻會被算成「家族回報＋工具佐證」兩個來源 [H]。
   - **強／弱工具佐證** [H]：
     - **強**：已解析的 SARIF 結果，其 (adapter, rule_id, tool_version) 列在 `calibration.yaml` 的 `result.high_precision_rules`，桶等於叢集的 CWE 桶，且 `precision_lower95` ≥ `result.thresholds.high_precision_min.value`（預設 0.90）。`adapter`、`rule_id`、`tool_version` 取自該結果所屬稽核事件（`tool_invocation_end`）的 `payload.adapter`、`payload.sarif_results[]`（v0.4：`{ref, rule_id, file, symbol, cwe_bucket}`，後三欄必須等於叢集的 `canonical_location.file`／`.symbol` 與 `cwe_bucket`，否則 `E-SARIF-REF`）與 `payload.tool_version`。名單怎麼產生見 [§5.10](#510-掃描器規則的高精準名單high_precision_rules)。**校準前名單是空的**，所以所有 SARIF 都是弱的。
     - **弱**（工具訊號）：其他所有已解析的 SARIF 結果，以及 `E_fail_u` 測試結果（§4.2）。弱 SARIF（不論幾筆）只算 **1 個獨立來源**，`E_fail_u`（不論幾筆）也只算 1 個（R2、R6）；弱訊號本身不能確認。
     - 為什麼要分級：SAST 整體的誤報率很高。§2.3 引用的研究中，SAST 在 OWASP Benchmark 上的誤報率超過 92%（預印本）[V][E:whitebox-33]。該研究只給整體數字；「各規則之間的精準度差很多」是本設計的假設 [H]。所以只有實測精準度夠高的規則，才能單獨讓叢集確認。
6. **校準加權**：投票權重取自各模型在校準語料上、分 CWE 桶的實測投票正確率（公式見 §4.3），不是等權。只有驗證者有權重；reviewer 不投票（§4.3）。
7. **分歧→人工（G2）**：這是 **[H] 設計假設**，需要量測 DISPUTED 佇列的精準度（§5.3 M-6）。G2 佇列＝所有 `DISPUTED` 叢集＋rubric 嚴重度（[08 §11.17](08-implementation-spec.md#1117-確定性輔助規則)；v0.4 起取代成員自報的最高嚴重度）為 critical／high 的 `UNCORROBORATED` 叢集，每個 run 預設最多 30 項（[02 W3](02-methodology.md#w3-交叉驗證與裁決g2)）；其他 `UNCORROBORATED` 不進 G2（見 [02 W3](02-methodology.md#w3-交叉驗證與裁決g2)）。`LIKELY`（含 `no_eligible_verifier` 的多家族叢集）也不進 G2（規則 2）。Trust or Escalate（ICLR 2025）支持「信心不足就不自動判定」，但它是升級給**更強的 LLM 評審**並選擇棄權，**不是交給人**，而且用的是單一評審的校準信心，不是跨廠商分歧 [P][E:multi_llm_bias-34]。
8. **防注入**：受測 repo 一律視為不可信資料（[06 §1](06-security-legal-limitations.md#1-工具包自身的安全)）。

## 4. 叢集與裁決

### 4.1 叢集鍵（Clusterer，確定性）
- **正規位置**：優先用漏洞 sink 所在的函式或 AST 節點（`file`＋完整限定符號名）；有 source→sink 資料流時，用這一對。
- **CWE 家族桶**：在 repo 裡維護 CWE → 桶的對照，例如：
  - 注入
  - 授權
  - 認證
  - 加密
  - secrets
  - 設定
  - 反序列化
  - SSRF
  - 路徑穿越
  - LLM 專屬（prompt injection、工具濫用、輸出處理）
  - 其他
- **同一叢集的條件**：
  - 同一個正規位置，或同一函式內的行範圍重疊
  - **且**屬於同一個桶
- 同一桶內若 CWE 不一致，保留清單；不同桶則分成不同叢集，但互相連結。
- **「獨立報告」的定義**：不同家族在**本次 run 的第一輪**各自貢獻了同一叢集的成員。Lane A 帶入的參考性發現項（D8）與 CMD-2 加派的結果**不計入**獨立家族數 [H]。validator 重算 `independent_families`，不採信叢集自己寫的值（不一致 → `E-CLUSTER-FAMILIES`）。只計同時符合下列條件的成員的家族：
  - 發現項屬於本 run，`reporter.round`＝1；
  - 回報的 agent 在 `agents.yaml` 的角色是 `reviewer`；
  - 發現項至少有一項**已接地**的證據（`MATCHED`／`MATCHED_SHIFTED`）。證據全部 `NOT_FOUND` 的發現項（`UNVERIFIED`），以及只有 `NOT_CHECKED` 證據的發現項，都不算支持，所以不計入（v0.4；v0.3 只排除全部 `NOT_FOUND`）。
- **工具結果怎麼進叢集**：W1 工具結果先正規化，再由 Clusterer 以同一組叢集鍵附到叢集的 `sarif_refs`（正規化與合併規則見 [08 §11.2](08-implementation-spec.md#112-工具結果正規化與合併)）。這是工具結果進入裁決的唯一路徑（§3 規則 5）。
- 叢集結果依 [schemas/cluster.schema.json](schemas/cluster.schema.json) 保存，含 `member_finding_ids`、`families`、`lineages`、`independent_families`、`sarif_refs`；v0.3 另有 `origin`、`threat_id`、`fingerprint`、`baseline_state`、`reopened`（見下）。

**叢集來源（`origin`）** [H]
- `white_box`：由 W2 發現項形成，使用上面的叢集鍵。`threat_id` 為 null。
- `black_box`：黑箱階段發現、沒有對應白箱叢集的問題。也就是威脅沒有 `source_cluster_id`（例如只有 B1 外部視角看得到的威脅）。這種威脅的測試案例，**每一筆** B5 測試結果（FAIL、PASS、INVALID 等都一樣，不只 FAIL）都寫到該威脅的黑箱叢集，由 B5 以程式碼建立，`threat_id` 必填。validator 檢查：這類結果的 `cluster_ids` 不能是空的，而且只能指向 `origin: black_box`、`threat_id` 相同的叢集（`E-CLUSTER-ORIGIN`）。所以 PASS 也有裁決紀錄（例如 R7＋R11 的 `test_not_reproduced`）。
  - **叢集鍵**：(`target_id`, HTTP 方法, `path_template`)＋桶，記在 `canonical_location.endpoint`（`file`、`symbol`、`source`、`sink` 為 null）。端點必須是該威脅某個測試案例 `request_allowlist` 中的請求（`E-CLUSTER-ORIGIN`）。
  - **沒有成員**：`member_finding_ids`、`families`、`lineages`、`independent_families`、`sarif_refs` 可以是空的；只有 `black_box` 能這樣（validator `E-CLUSTER-ORIGIN`）。
  - **會觸發的規則**：
    - R1：`E_proof` → `CONFIRMED_EXECUTABLE`。黑箱測試都經 G4 核准，所以解讀算事先登記（§4.2）。
    - R7：沒有 `E_proof` → `UNCORROBORATED`。單一個 `E_fail_u` 只算 1 個獨立來源，到不了 R6。
    - R11、R12 的註記照常。
  - **不會觸發的規則**：R0 不適用（沒有成員，「全部證據 `NOT_FOUND`」恆為否）；沒有投票與 SARIF，所以 R3–R5 不成立；R9、R10 不會出現（Lane A 不跑黑箱；G2 在黑箱之前）。
  - 叢集的 `families` 是空的，所以分析者池中每一位 Result Analyst 都合格（§4.2）。
  - 黑箱叢集在 B5 才建立，已經過了 CMD-2 與 G2，所以結果直接列入 B6 報告。
  - 範例（`schemas/examples/`）：
    - `cluster.k-201.example.json`：K-201，威脅 T-033（沒有 `source_cluster_id`），端點 `tgt-staging-api` `GET /api/invoices`，桶 `authz`。G4 核准的 TC-033-01（S0，`testcase.bola-list.example.json`）得到確定性 FAIL（R-TC-033-01-1：`fail_oracles` 為 `STATUS_AND_BODY`，兩個對照都 PASS，重播 2 次都相同）→ `verdict.k-201-b5.example.json`（V-201-1）經 R1 為 `CONFIRMED_EXECUTABLE`，**沒有** Result Analyst（`interpretation_confirmed_by` 為 null）。
    - `cluster.k-202.example.json`：K-202，威脅 T-027（同樣沒有來源叢集），桶 `injection`。TC-027-01（ZAP 主動掃描）的結果 R-TC-027-01-1 是 PASS → `verdict.k-202-b5.example.json`（V-202-1）經 R7 為 `UNCORROBORATED`，R11 加註 `test_not_reproduced`。v0.3 時它是範例中唯一 `provisional` 為 true 的裁決；v0.4 起黑箱叢集一律不是暫定（見 §4.2）。

**跨 run 指紋與基準狀態** [H]：每個叢集有 `fingerprint`＝sha256(JCS({cwe_bucket, file, symbol}))；黑箱叢集用 {cwe_bucket, target_id, method, path_template}。指紋不含行號，所以程式移動幾行，指紋不變；validator 會重算（`E-CLUSTER-FINGERPRINT`）。`baseline_state` 是與 `run.baseline_run_id` 那次 run 比較的結果，沿用 SARIF 2.1.0 `baselineState` 的四個值 `new`／`unchanged`／`updated`／`absent` [V][E:whitebox-56]。本工具包的用法：`new`＝基準 run 沒有這個指紋；`unchanged`＝指紋相同、成員證據的 hash 也相同；`updated`＝指紋相同、證據改變；`absent` 只出現在報告中（基準 run 有、本次沒有的指紋，列在 report-manifest 的 `absent_fingerprints[]`）；沒有基準 run 時為 null。`reopened`（本次為 `new`，但更早的 run 曾是 `absent`）只是資訊。這些欄位**不是**裁決規則的輸入，只讓報告、PR 回饋與 G3 的差異審查能跨 run 對上同一個問題。SARIF 輸出的欄位對應見 [08 §11.16](08-implementation-spec.md#1116-sarif-輸出與報告回饋)。

### 4.2 裁決狀態與有序規則

**狀態**

| 狀態 | 意思 |
|---|---|
| `CONFIRMED_EXECUTABLE` | 有可重播的測試證明；解讀已事先登記（確定性 oracle），或經另一家族的 Result Analyst 確認 |
| `CONFIRMED_CORROBORATED` | 有強工具佐證（高精準規則），或計權合格支持票達門檻；沒有計權合格的反駁 |
| `LIKELY` | 至少 2 個獨立來源（第一輪獨立回報的家族、弱工具訊號各算 1 個），沒有計權合格反駁，但未達確認；或因多樣性降低而封頂 |
| `UNCORROBORATED` | 最多 1 個獨立來源，沒有強工具佐證，支持也未達門檻；或 Lane A 參考性結果；或沒有可執行證明的黑箱起源叢集 |
| `DISPUTED` | 同時有計權合格的支持與反駁；或反駁遇上任何工具佐證或訊號；或反駁未達門檻；或確認後被合格 PASS 反證 → 人審 |
| `REJECTED` | 所有成員的所有證據都是 `NOT_FOUND`；或計權合格反駁達到門檻，且沒有任何工具佐證或訊號；或 G2 人工駁回 |

`UNVERIFIED` 只是**發現項層級**的暫時狀態（證據全部 `NOT_FOUND`），不是叢集裁決。

**合格票（valid vote）的操作定義**：
- 投票者的家族與血統都不在叢集中（§3 規則 2）；
- 候選已匿名化、順序已隨機化；
- 理由**引用了具體證據**，而且引用的證據通過同樣的接地比對（§3 規則 5）：程式位置（例如「第 57 行已有 `tenant_id` 條件」），或 inventory／設定事實（例如「`/db/tables/0/rls_enabled` 為 `true`」）。**工具輸出不能當引用**，因為驗證者看不到它。沒有可比對證據的票一律視為棄權。引用逐項記在票的 `votes[].cited_evidence`（v0.3 新增、必填；例如 K-014 的兩張票都引用 `routes/invoices.ts:88`）；它也是驗證者 LLM 輸出中僅有的三個欄位之一（另兩個是 `stance`、`rationale`）。
- 「理由成立」因此不需要主觀判斷：Aggregator 只檢查引用的證據能否被程式碼或 inventory 比對。
- **引用必須與叢集相關**（v0.4，v0.5 收緊）[H]：至少一項引用必須落在下列位置，否則視為棄權（`derive.cited_relevant`）。引用寫成 `file:line` 或 `file:起-迄`，**不帶行號的引用不算**。
  - 每一種票：落在某個成員發現項 `code_snippet` 證據的行範圍內（同一檔案），或等於某個成員 `inventory_fact` 的 `inventory:<pointer>`。
  - 反駁票另外可以引用成員發現項所屬切片（`slice.files[]` 的檔案與行範圍）中的任何位置，或該 run 的 W0 inventory 中任何可解析的 `inventory:<pointer>`：反駁的根據通常在路徑上的別處（例如中介層的授權檢查）或設定中。
  - v0.4 只比對檔名，`routes/invoices.ts:99999`、甚至沒有行號的引用都算有效。validator 沒有切片內容，以「落在切片宣告的檔案與行範圍」近似「能在遮罩後的程式中找到」；實際的文字比對由 Aggregator 在執行期做。v0.3 只檢查引用能被比對，受測碼裡的註解可以同時誘導反駁並提供一個「真實存在」但無關的行號。
- **`anonymized`、`order_randomized` 不採信票上的值**（v0.4）：它們是 harness 的性質，由 run manifest 中 W3 verifier 範本（`w3-verify`）的 `anonymizes_candidates`、`randomizes_order` 推導；票上的值必須相同（`E-VERDICT-VOTE`）。

**計權合格票**＝合格票，立場是支持或反駁（v0.5：棄權票一律不算，以免一張棄權票就讓 `diversity_degraded` 解除、繞過 R8 的上限），且投票模型在該叢集的 CWE 桶、對應票的立場那一邊的權重 w > 0（§4.3；v0.4 起支持票看 support、反駁票看 refute）[H]。權重為 0 的模型（含「接近 0」者，§4.3；以及尚未重跑 §5.8 的 fallback 模型，§3 規則 3）的票照樣保存（`valid` 依上面定義），但不參與 R3–R5 的條件判斷，也不影響 S。這避免一個近乎隨機的投票者單獨把叢集推進 `DISPUTED`。

#### 測試證據分類

與叢集相連的每一筆測試結果（W4 的 Z2 沙箱單元／性質測試，或 B5 的黑箱測試；依 [schemas/testresult.schema.json](schemas/testresult.schema.json)）先由程式碼分成四類 [H]。黑箱起源叢集以 `threat_id` 與測試結果相連（§4.1）。叢集的測試證據取**最強的一類**，強弱順序為 `E_proof` ＞ `E_fail_u` ＞ `E_pass` ＞ `E_inc` ＞ 無；同時存在 FAIL 類與 `E_pass` 時兩者都保留（R11 與 R12 會處理衝突）。

分類用到下列定義 [H]：
- **確定性 oracle 類型**：測試案例的 `oracle.types` 是陣列，一個測試可以同時用多種 oracle（例如 [04 §6.2](04-threat-to-testcase.md#62-範例-bllm-功能的-prompt-injection-與工具濫用confused-deputy) 的範例 B 用 `TOOL_CALL_LOG`、`CANARY`、`STATE_DIFF`）。除了 `HUMAN` 與 `LLM_GRADER` 以外的類型都是確定性的。測試結果的 `fail_oracles` 列出回報違反的 oracle 類型：`FAIL` 時非空、其他結果為空，且必須是 `oracle.types` 的子集（validator `E-RESULT-ORACLE`）。
- **對照（controls）**：每個測試案例都有 `controls[]`（寫法見 [04 §3](04-threat-to-testcase.md#3-測試案例欄位)），種類有三：
  - `reachability`：證明測試真的到達要測的地方。W4：sink 行被覆蓋；B5：請求帶著有效 session 到達目標端點，並通過認證／授權前置步驟。每個測試案例至少一個（`E-TC-CONTROLS`）。
  - `oracle_can_pass`：在已知正常的條件下，oracle 判 PASS。證明測試不是「怎樣都失敗」。
  - `oracle_can_fail`：在已知有缺陷的條件下，oracle 判 FAIL。W4 用 mutmut／Stryker 的變異體或植入缺陷版本；B5 用 oracle 自我檢查 fixture。證明測試不是「怎樣都通過」。
  - 測試結果的 `controls[]` 記錄每個對照的結果。**任一對照不是 PASS**（FAIL、ERROR、NOT_RUN）→ 結果的 `outcome` 必須是 `INVALID`（`E-RESULT-INVALID`）。`INVALID` 表示測試沒有證明自己能測到東西，所以它**永遠不算 PASS**，也不算 FAIL，一律列 `E_inc`。報告清單的 `metrics` 列出 `results_total`、`results_invalid` 與 `control_pass_rate`（PASS 的對照數 ÷ 所有結果的對照總數；validator 重算，`E-REPORT-METRICS`）。範例 run 為 4 筆結果、0 筆 `INVALID`、1.0。
- **事先登記的解讀**：下列兩種情況，FAIL 的意思在測試執行**之前**就已由人核准，所以不需要 LLM 解讀：
  - (a) 經 G4 核准的黑箱測試案例（B4 結果；該 run 最新的 G4 紀錄為 `APPROVED`／`PARTIALLY_APPROVED`，且對這個測試案例的決定是 `accept`）：G4 核准的就是測試步驟與 oracle；
  - (b) W4 測試：它的 `requirement_ids` 不是空的、全部經 G1 核准，而且有 `oracle_can_pass` 對照、全部 PASS（判定 PASS 時改為 `oracle_can_fail` 對照）。
  - Result Analyst 原本只負責確認「這個 FAIL 真的代表所述問題」。意思已事先固定、又由確定性 oracle 判定時，這一步沒有增加資訊，只會讓證明依賴 LLM，而且在分析者都與叢集同家族時根本無法成立。
- **Result Analyst 分析者池**：`agents.yaml` 中每個家族一位，角色都是 `result_analyst`（`result_analyst_a`＝`claude_sonnet`、`result_analyst_b`＝`gpt_flagship`、`result_analyst`＝`nemotron_self`）。harness 挑一位家族與血統都不在叢集 `families`／`lineages` 中的分析者（家族與血統由 `agents.yaml` → `models.yaml` 解析）。黑箱回應中偵測到 PII 時，只能用自架模型（`result_analyst`）。沒有符合條件的分析者，就是「沒有合格的 Result Analyst」。
  - 分析者記在測試結果的 `interpreted_by`，它的 LLM 輸出記在 `interpretation`（`{agrees, rationale}`；兩者同時有或同時為 null，`E-RESULT-ANALYST`）。`interpreted_by` 不是 `result_analyst` 角色的 agent → `E-RESULT-ANALYST-ROLE`。
  - 合格分析者只有在 `agrees` 為 true 時才算「確認」；`agrees` 為 false → `E_inc`。

| 類別 | 條件（全部成立） | 用在 |
|---|---|---|
| `E_proof` 可執行證明 | ① `outcome: FAIL`（所以所有對照都是 PASS）；② k ≥ `trials.fail_k_min`（安全需求預設 1）且至少有一次重播（`replays`＝n_r ≥ 1，重播中違反次數記在 `replay_k`＝k_r）；確定性測試：每次重播都失敗（k_r＝n_r）；機率型 LLM 測試：確定性 oracle 在有效次數 n′ 中違反 k 次，**且**另開的重播 job（n_r＝`trials.replay_n`，預設 20）中 k_r ≥ `fail_k_min`（定義見 [04 §4.4](04-threat-to-testcase.md#44-機率型測試的次數與上界)）；③ `fail_oracles` 至少有一個確定性類型；④ 解讀**事先登記**，或由**合格的 Result Analyst** 確認 | R1 |
| `E_fail_u` 未經確認的重現失敗 | ①–③ 成立，但解讀沒有事先登記，也**沒有合格的 Result Analyst**。若有合格分析者但**不同意**解讀 → 改列 `E_inc` | R2（弱工具訊號，算 1 個獨立來源）、R4 |
| `E_pass` 合格 PASS | `outcome: PASS`；測試案例綁定此叢集（`source_cluster_id`、種子威脅追溯，或黑箱叢集的 `threat_id`）；所有 `reachability` 對照都是 PASS（取代 v0.2 的「前置條件已到達」；`precondition_reached` 欄位保留，但必須等於推導值，`E-RESULT-PRECONDITION`）；測試案例的 `oracle.types` 有確定性類型；機率型 LLM 測試另需 k＝0 且有效次數 n′ ≥ 30，並報告單側 95% 上界 p_u＝1 − 0.05^(1/n′)（04 §4.4）；解讀**事先登記**（W4 用 `oracle_can_fail` 對照），或由合格的 Result Analyst 確認「此 PASS 代表所述問題在測試條件下未重現」 | R11 |
| `E_inc` 不確定 | 其他所有情況：`ERROR`、`SKIPPED`、`STOPPED`、**`INVALID`**（任一對照不是 PASS）、沒有重播或重播不一致的 FAIL（`replays`＝0；確定性測試 k_r ＜ n_r；機率型測試 k_r ＜ `fail_k_min`，例如 k_r＝0）、k 未達 `trials.fail_k_min`、機率型 PASS 的有效次數 n′ ＜ 30（前置條件未到達的次數不計；n′ ≥ 30 是 `E_pass` 的條件）、**違反只由 `LLM_GRADER`／`HUMAN` 判定**（`fail_oracles` 沒有確定性類型）、沒有確定性 oracle 的 PASS、解讀沒有事先登記也沒有合格分析者的 PASS、分析者不同意或缺票 | R12（只記錄） |

- **機率型測試的次數、門檻與重播**以 [04 §4.4](04-threat-to-testcase.md#44-機率型測試的次數與上界) 為準（`trials.fail_k_min`、n＝30／60、n_r＝`trials.replay_n`＝20、k_r＝`replay_k`、PASS 的 n′ ＜ 30 ⇒ `E_inc`；`trials.pass_rule` 只是文字說明）；本節只負責把結果分類。重播 job k_r＝0 不代表第一批是誤判（真實違反率 5% 時約 36% 會全部沒重現），所以列 `E_inc` 並保留第一批紀錄給人看，而不是反證 [H]。
- `positive_control.value`（測試結果欄位）＝「有 `oracle_can_fail` 對照，而且全部 PASS」；沒有這種對照時為 null（例如範例 B 的 PASS 與 TC-027-01 的 ZAP PASS）。由 validator 推導比對（`E-RESULT-CONTROLS`）[H]。沒有正對照的 PASS 仍可能是 `E_pass`（黑箱測試經 G4 核准，或經分析者確認），但報告標示；§5.3 M-9 會分開量測兩者的「測試漏報率」。
- **PASS 永遠不會單獨把叢集變成 `REJECTED`**：測試只覆蓋有限條件，「沒有失敗」不等於「沒有漏洞」[H]。若校準顯示測試漏報率夠低（§5.3 M-9），未來的 `rule_version` 才可能放寬。

#### 有序規則

規則分五段（A–E），依序評估；每段的「決定規則」採**第一條成立者決定**，「修正規則」依序套用於前段結果，「註記規則」不改狀態。每條被觸發的規則都寫入 `rule_trace` [H]。每項格式為 `R<n>:<說明>`（pattern `^R([0-9]|1[0-3])(:.*)?$`），R 前綴的順序必須等於規則實際觸發的順序，例如 `["R2:S=0.73", "R5:vote branch", "R8:diversity_degraded"]`；validator 會以 `tools/vchlib/adjudicate.py` 重算並比對。R11 只在改變狀態或加註時寫入。

| 段 | 規則 | 種類 | 條件 | 結果 |
|---|---|---|---|---|
| A 前置 | R9 | 決定 | `run_kind: lane_a`（D8） | 若 R0 條件成立 → `REJECTED`；否則 → `UNCORROBORATED`。兩種情況都設 `advisory: true`、`status_cap: UNCORROBORATED`。**結束**（不再評估 B–D 段；Lane A 不跑測試） |
| A 前置 | R10 | 決定 | 此叢集最新的 G2 決定為 `REJECTED` | 測試證據有 `E_proof` → `CONFIRMED_EXECUTABLE`（`rule_trace` 為 R10、R1），加註 `post_g2_conflict`，列入 B6 人工複核清單（v0.4）。否則 → `REJECTED`（原因：人工駁回，附理由）；有 `E_fail_u` 時加註 `post_g2_conflict`。**結束** |
| B 證據 | R0 | 決定 | 叢集有成員，所有成員的所有證據都是 `NOT_FOUND`（§3 規則 5），**而且**沒有已解析的 SARIF（強或弱）、測試證據沒有 `E_proof`／`E_fail_u`（v0.4）。黑箱起源叢集沒有成員，R0 不適用 | `REJECTED`（原因：無證據）。**結束** |
| B 證據 | R1 | 決定 | 測試證據為 `E_proof` | `CONFIRMED_EXECUTABLE`。**結束**（若同時有 `E_pass`，R12 加註 `conflicting_test_results`） |
| C 投票 | R2 | 計算 | ① 計權合格票，以及 S＝Σ w × 立場（支持＋1、反駁−1、棄權 0；w 見 §4.3）；② **強工具佐證**：叢集有強的 SARIF 結果（§3 規則 5）；③ **弱 SARIF**：叢集有其他已解析的 SARIF 結果；④ **獨立來源數**＝第一輪獨立回報的家族數＋（有弱 SARIF 時 1）＋（測試證據含 `E_fail_u` 時 1） | — |
| C 投票 | R3 | 決定 | 同時有計權合格支持與計權合格反駁 | `DISPUTED` |
| C 投票 | R4 | 決定 | 只有計權合格反駁 | 有強工具佐證、弱 SARIF 或 `E_fail_u` → `DISPUTED`；否則 S ≤ −θ_reject **而且只有一個獨立家族回報**（v0.5）→ `REJECTED`；否則 → `DISPUTED`（兩個以上獨立家族回報的叢集不會被反駁票自動駁回，送 G2 由人判斷） |
| C 投票 | R5 | 決定 | 有強工具佐證（決定表第 10 列）；或只有計權合格支持且 S ≥ θ_confirm（第 11 列，投票分支） | `CONFIRMED_CORROBORATED` |
| C 投票 | R6 | 決定 | 獨立來源 ≥ 2（此時已知沒有計權反駁，也未達 R5）。例：2 個家族獨立回報；1 個家族＋弱 SARIF；1 個家族＋`E_fail_u`；`no_eligible_verifier` 的多家族叢集 | `LIKELY` |
| C 投票 | R7 | 決定 | 其他（獨立來源 ≤ 1、沒有計權反駁、沒有強工具佐證、支持未達門檻或沒有票） | `UNCORROBORATED`（→ CMD-2 加派；之後若最高嚴重度為 critical／high 進 G2 佇列，否則直接成為種子威脅） |
| D 修正 | R8 | 修正 | `diversity_degraded`，且 C 段結果來自 R5 的投票分支（第 11 列） | 降為 `LIKELY`（`status_cap: LIKELY`）。R1 與強工具佐證的 R5（第 10 列）**不受**此上限影響 |
| D 修正 | R11 | 修正 | 測試證據含 `E_pass`，且 C 段（經 R8）結果為下列之一 | 有正對照（某個 `E_pass` 結果的 `positive_control` 為 true，即 `oracle_can_fail` 對照 PASS）：`CONFIRMED_CORROBORATED` → `DISPUTED`；`LIKELY` → `DISPUTED`。沒有正對照：`CONFIRMED_CORROBORATED`、`LIKELY` 維持，加註 `test_not_reproduced`（v0.4）。`UNCORROBORATED` → 維持，加註 `test_not_reproduced`；`DISPUTED`、`REJECTED` → 維持 |
| E 註記 | R12 | 註記 | 有任何 `E_inc` 結果，或 R1 與 `E_pass` 並存 | 不改狀態；加註 `test_inconclusive`（附測試 ID 與原因）或 `conflicting_test_results` |
| E 註記 | R13 | 註記 | 此叢集對應的種子威脅被 G3 駁回（D5）；依 G3 GateRecord 計算，G3 之後任何階段（例如 `B5_readjudicate`）的新版裁決都適用 | 不改狀態（保留白箱狀態）；加註 `g3_rejected`（理由必填）；B6 列為「未做黑箱驗證（G3 駁回：理由）」 |

- θ_reject、θ_confirm 由 §5.7 的程序決定；若該程序判定「不可行」，對應門檻設為 +∞（該分支永遠不成立）。
- **重新裁決**：`W4_readjudicate`（W4 的 Z2 測試結果）與 `B5_readjudicate`（黑箱測試結果）把新結果寫回相關叢集，由 Aggregator **從 A 段重新評估全部規則**（例如從 `LIKELY` 經 R1 升為 `CONFIRMED_EXECUTABLE`，或經 R11 由 `CONFIRMED_CORROBORATED` 降為 `DISPUTED`），並以 append-only 方式產生新版裁決，保留每一版。
- **G2 之後才出現的 `DISPUTED`**（W4 或 B5 的 R11）：G2 不會重開 [H]。
  - W4：`W4_readjudicate` 的新版裁決若為 `DISPUTED`、而被取代的前一版不是 `DISPUTED`（例如 `LIKELY` 經 R11 → `DISPUTED`），加註 `w4_became_disputed`；這與 G2 是否已決定無關。run 與種子威脅的 `disputed_after_g2` 是由這些註記推導的清單，G3 的種子威脅清單標示「W4 後轉為爭議」。
  - B5：`B5_readjudicate` 產生的 `DISPUTED` 不加 `w4_became_disputed`，列入 B6 的人工複核清單。
- G2 的 accept 與 NEEDS_INFO／逾時都**不是規則輸入**：狀態照規則計算，G2 紀錄只附在報告中。
- **暫定裁決（`provisional`）** [H]：下列任一成立，裁決的 `provisional` 為 true：
  - `calibration_version` 為 null；
  - `theta_confirm` 為 null；
  - 合格驗證家族 E(叢集)（§3 規則 3）中的**每一個**驗證模型，在該叢集 CWE 桶的校準權重（支持與反駁兩邊）都是 0。
  - **例外**（v0.4）：決定規則是 R9、R10、R0 或 R1（決定表第 1–5 列），或叢集是 `black_box`，一律不是暫定。這些狀態不取決於投票，標暫定沒有意義；v0.3 會讓同為黑箱、同樣沒有票的 K-201 與 K-202 只因桶不同而一個暫定、一個不是。這一條由 `calibration.yaml` 與 `agents.yaml`／`models.yaml` 計算，**不看**本裁決實際有哪些票：合格的驗證者都沒有校準權重，才算沒有校準支撐。E 為空（`no_eligible_verifier`）時也成立。
  - v0.3 的例子（已由上面的例外取代）：黑箱叢集 K-201 的 V-201-1 沒有票，因為合格的 `nemotron_self` 在 `authz` 桶有權重而不是暫定；K-202 在 `injection` 桶，沒有任何模型有權重，V-202-1 曾是 true。v0.4 起兩者都是 false。
  - 它不改規則的計算（w＝0 時投票分支本來就不會成立，θ＝null 視為 +∞），只表示這個狀態沒有經過校準的投票支撐。報告（W5、B6）把暫定裁決標為「暫定（校準前）」，並在摘要列出暫定裁決的比例。校準前的其他預設見 [08 §11.11](08-implementation-spec.md#1111-校準前的預設)。
- **規則版本**：v0.5 改變了 R4（多家族回報不自動駁回）、計權合格票（不含棄權）與引用相關性，裁決的 `rule_version` 為 **`05-v0.5`**（v0.4 改變了 R0、R10、R11 與獨立家族的語意，為 `05-v0.4`；v0.3 改變了 R0、R2、R4–R6 與測試證據分類的語意，由 `05-v0.2` 改為 `05-v0.3`）（`tools/vchlib/adjudicate.py` 的 `RULE_VERSION`）。validator 檢查每個裁決與 run 的 `rule_version` 都等於它（`E-VERDICT-RULE-VERSION`、`E-RUN-RULE-VERSION`）。
- 每張票與每次裁決依 [schemas/verdict.schema.json](schemas/verdict.schema.json) 保存，含 `voter_family`、`voter_lineage`、`valid`、`fallback_used`、`anonymized`、`order_randomized`、`rule_trace`；v0.2 另有每票的 `votes[].weight`、`votes[].weighted_valid`（＝計權合格票），以及 `status_cap`、`advisory`、`test_evidence{class, results[]}`、`annotations[]{kind, reason}`（kind：`test_not_reproduced`、`test_inconclusive`、`conflicting_test_results`、`g3_rejected`、`post_g2_conflict`、`w4_became_disputed`）、`g2_decision_ref`、`calibration_version`（整數）、`theta_confirm`、`theta_reject`、`readjudicated_by`（產生該版裁決的節點：`W3_adjudicate`、`G2_apply`（v0.5，G2 逐項套用駁回時寫的新版）、`W4_readjudicate` 或 `B5_readjudicate`；R10 只看 G2 之後產生的版本）、`supersedes_verdict_id`。v0.3 的 `tool_corroboration` 只含**強**工具佐證，另新增 `tool_signal`（弱工具訊號）、`independent_sources`（整數）、`provisional`，以及每票必填的 `votes[].cited_evidence`。
- **自我宣告的欄位不採信**（validator 強制）[H]：裁決中影響規則的欄位由 validator 自行推導，再與裁決記錄的值比對，不一致就是錯誤；重算規則時用推導值，不用裁決自己寫的值。
  - `diversity_degraded`：依 §3 第 3 條（|E| ＞ 0 且計權合格票的家族數 ＜ min(2, |E|)；Lane A 一律 false）。家族依 `voter_agent_id` → `agents.yaml` 的模型 → `models.yaml` 的 `family` 解析。每張票的 `voter_model_key` 必須是該 agent 的模型；`fallback_used` 時可以是同家族的 fallback 模型，權重取 fallback 模型自己的值；否則 → `E-VERDICT-VOTE`。與宣告值不一致 → `E-VERDICT-DIVERSITY`。
  - `no_eligible_verifier`：＝ |E(叢集)| ＝ 0（§3 第 3 條）；不一致 → `E-VERDICT-NOELIGIBLE`。
  - 只有 `agents.yaml` 角色為 `verifier` 的 agent 能投票；其他角色的票 → `E-VERDICT-VOTER-ROLE`，且不計入計權合格票、分數與家族多樣性。
  - `tool_corroboration`：＝ 叢集**已解析且為強**的 `sarif_refs`（§3 規則 5）；不一致 → `E-VERDICT-TOOLCORR`。
  - `tool_signal`：＝ 已解析但為弱的 `sarif_refs` ∪ 每個 `E_fail_u` 測試結果的 `result_ref`（不可重複）；不一致 → `E-VERDICT-TOOLSIGNAL`。
  - `independent_sources`：＝ 叢集的獨立家族數＋（有弱 SARIF 時 1）＋（有 `E_fail_u` 時 1）；不一致 → `E-VERDICT-SOURCES`。
  - `provisional`：依上面的定義；不一致 → `E-VERDICT-PROVISIONAL`。
  - `sarif_refs` 也不採信叢集自我宣告：每一項都必須出現在同一個 run 稽核檔中某個 `tool_invocation_end` 事件的 `payload_refs`，且該事件在 Z2、`payload.ok` 為 true、`payload.adapter` 是 `tools.yaml` 登錄的白箱工具模式（工具在 Z2、`b4_executable: false`），該工具在 `licenses.yaml` 的狀態是 `OK` 或 `注意`（`法務閘門` 等其他狀態都不行，N-7）；否則 → `E-SARIF-REF`，該項既不算強佐證，也不算弱訊號。**位置綁定**（v0.4）：同一事件 `payload.sarif_results[]` 中這個 ref 的 `file`、`symbol`、`cwe_bucket` 必須等於叢集的 `canonical_location.file`、`canonical_location.symbol` 與 `cwe_bucket`；`origin: black_box` 的叢集不收任何 SARIF。這三欄是正規化器（[08 §11.2](08-implementation-spec.md#112-工具結果正規化與合併) 步驟 3–5）算出的叢集鍵，所以 SARIF 只能佐證它自己位置的叢集。強弱的判斷另外需要同一事件的 `payload.sarif_results[]` 有這個 ref 的 `rule_id`，以及 `payload.tool_version`；validator 另檢查 `payload.tool_version` 等於 `run.tool_versions` 中該 adapter 的版本（`E-RUN-CONFIG`）。
  - 這樣裁決無法靠自行宣告「有工具佐證」或把弱訊號寫成強佐證來繞過 R6／R8，也無法靠漏寫 `diversity_degraded` 避開 `LIKELY` 上限。

#### 決定表

下表把 A–C 段所有輸入組合對應到**恰好一個**基本狀態。每列由上而下第一個符合者勝出；「·」表示不論該欄取值。最後一列沒有任何條件，所以每種組合都至少符合一列；由上而下取第一列，所以恰好一列 [H]。

欄位說明：「強工具佐證」＝`tool_corroboration` 非空；「弱工具訊號／`E_fail_u`」＝`tool_signal` 非空（弱 SARIF 或 `E_fail_u`）；「獨立來源」＝第一輪獨立回報的家族數＋（有弱 SARIF 時 1）＋（有 `E_fail_u` 時 1）；「R0 條件」＝全部證據 `NOT_FOUND`、沒有已解析的 SARIF、沒有 `E_proof`／`E_fail_u`（v0.4），在叢集沒有成員時（黑箱起源）恆為「否」。第 7 列的「任一」表示這兩欄至少一欄為「有」。

| # | lane_a | G2 駁回 | R0 條件 | 測試證據 | 計權支持 | 計權反駁 | 強工具佐證 | 弱工具訊號／`E_fail_u` | S 對門檻 | 獨立來源 ≥ 2 | 基本狀態（規則） |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 是 | · | 是 | · | · | · | · | · | · | · | `REJECTED`（R9） |
| 2 | 是 | · | 否 | · | · | · | · | · | · | · | `UNCORROBORATED`（R9） |
| 3 | 否 | 是 | · | 非 proof | · | · | · | · | · | · | `REJECTED`（R10） |
| 4 | 否 | 否 | 是 | · | · | · | · | · | · | · | `REJECTED`（R0） |
| 5 | 否 | · | 否 | `E_proof` | · | · | · | · | · | · | `CONFIRMED_EXECUTABLE`（R1；G2 駁回時為 R10、R1，加註 `post_g2_conflict`） |
| 6 | 否 | 否 | 否 | 非 proof | 有 | 有 | · | · | · | · | `DISPUTED`（R3） |
| 7 | 否 | 否 | 否 | 非 proof | 無 | 有 | 任一 | 任一 | · | · | `DISPUTED`（R4） |
| 8 | 否 | 否 | 否 | 非 proof | 無 | 有 | 無 | 無 | S ≤ −θ_reject | · | `REJECTED`（R4）；v0.5 起只在獨立家族 ≤ 1 時，否則同第 9 列 |
| 9 | 否 | 否 | 否 | 非 proof | 無 | 有 | 無 | 無 | S ＞ −θ_reject，或獨立家族 ≥ 2（v0.5） | · | `DISPUTED`（R4） |
| 10 | 否 | 否 | 否 | 非 proof | · | 無 | 有 | · | · | · | `CONFIRMED_CORROBORATED`（R5，強工具佐證） |
| 11 | 否 | 否 | 否 | 非 proof | 有 | 無 | 無 | · | S ≥ θ_confirm | · | `CONFIRMED_CORROBORATED`（R5，投票分支） |
| 12 | 否 | 否 | 否 | 非 proof | · | 無 | 無 | · | 未達 | 是 | `LIKELY`（R6） |
| 13 | · | · | · | · | · | · | · | · | · | · | `UNCORROBORATED`（R7） |

**修正矩陣**（只套用在第 6–13 列的結果；第 1–5 列不修正）：

| 基本狀態 | R8：`diversity_degraded` 且來自第 11 列 | R11：另有 `E_pass`，有正對照 | R11：另有 `E_pass`，沒有正對照（v0.4） |
|---|---|---|---|
| `CONFIRMED_CORROBORATED`（第 10 列，強工具佐證） | 不變 | → `DISPUTED` | 不變，加註 `test_not_reproduced` |
| `CONFIRMED_CORROBORATED`（第 11 列，投票分支） | → `LIKELY` | → `DISPUTED`（不論是否先經 R8） | 不變（經 R8 則為 `LIKELY`），加註 `test_not_reproduced` |
| `LIKELY`（第 12 列，含 1 個家族＋弱工具訊號） | 不變 | → `DISPUTED` | 不變，加註 `test_not_reproduced` |
| `UNCORROBORATED`（第 13 列） | 不變 | 不變，加註 `test_not_reproduced` | 不變，加註 `test_not_reproduced` |
| `DISPUTED`（第 6、7、9 列） | 不變 | 不變 | 不變 |
| `REJECTED`（第 8 列） | 不變 | 不變 | 不變 |

「正對照」＝某個 `E_pass` 結果的 `positive_control` 為 true（`oracle_can_fail` 對照存在且 PASS；由 validator 從測試結果推導，`E-RESULT-CONTROLS`）。

R8 與 R11 都是「6 個狀態 → 6 個狀態」的全函數，依序套用後仍恰好得到一個狀態；R12、R13 不改狀態。因此任意輸入組合都對應到恰好一個最終狀態。

**題目中列出的邊界情況**：

| 情況 | 結果 |
|---|---|
| W4 沙箱或 B5 測試 PASS（合格、有正對照）落在 `LIKELY` | `DISPUTED`（R6 → R11）；W4 發生時在 G3 標示，B5 發生時列入 B6 人工複核 |
| B5 測試 PASS（合格、沒有正對照，例如 ZAP 通用掃描）落在 `LIKELY` 或 `CONFIRMED_CORROBORATED` | 狀態不變，加註 `test_not_reproduced`（R11，v0.4）；報告列為「測試未重現（無正對照）」 |
| 合格 PASS 落在 `UNCORROBORATED` | 維持 `UNCORROBORATED`，加註 `test_not_reproduced`；報告列為「測試未重現」 |
| 合格 PASS（有正對照）落在 `CONFIRMED_CORROBORATED` | `DISPUTED`（R5 → R11），不論佐證來自強工具佐證或投票 |
| 合格 PASS 與另一測試的 `E_proof` 並存 | `CONFIRMED_EXECUTABLE`（R1），加註 `conflicting_test_results` |
| 不合格 PASS、`INVALID`（任一對照不是 PASS）、`ERROR`／`SKIPPED`／`STOPPED`、重播不一致、違反只由 `LLM_GRADER`／`HUMAN` 判定 | `E_inc`：狀態不變，加註 `test_inconclusive`（R12）；`INVALID` 永遠不算 PASS |
| 可重現、由確定性 oracle 判定的 FAIL，解讀已事先登記（G4 核准的黑箱測試；或需求全部經 G1 簽核、`oracle_can_pass` 對照為 PASS 的 W4 測試） | `E_proof` → `CONFIRMED_EXECUTABLE`（R1），不需要 Result Analyst |
| 可重現的確定性 FAIL，解讀沒有事先登記，也沒有合格的 Result Analyst | `E_fail_u`：弱工具訊號，算 1 個獨立來源。單一家族回報、投票未達 R5 時 → `LIKELY`（R6）；它不會單獨造成 `CONFIRMED_*`；若同時有計權反駁 → `DISPUTED`（R4） |
| 單一家族回報＋SARIF 命中，規則不在 `high_precision_rules`（校準前一律如此） | 弱工具訊號；獨立來源＝2 → 投票未達 R5 時為 `LIKELY`（R6）。例：K-014（見下） |
| 單一家族回報＋SARIF 命中，規則在該桶的 `high_precision_rules` | 強工具佐證 → `CONFIRMED_CORROBORATED`（R5 第 10 列），不受 R8 上限 |
| 3 個家族都在第一輪回報（`no_eligible_verifier`） | 沒有票；獨立來源 ≥ 3 → `LIKELY`（R6）；不進 G2，改由 W4 與黑箱測試確認（§3 規則 2） |
| 黑箱起源叢集（`origin: black_box`） | 確定性 FAIL（G4 核准即事先登記）→ `E_proof` → `CONFIRMED_EXECUTABLE`（R1）；沒有 `E_proof` → `UNCORROBORATED`（R7） |
| G3 駁回種子威脅（D5） | 狀態不變，加註 `g3_rejected`（R13）；不產生 B3 測試案例；B6 列為「未做黑箱驗證（G3 駁回：理由）」 |
| G2 駁回後才出現 FAIL 證明 | `E_proof` → `CONFIRMED_EXECUTABLE`（R10、R1，v0.4；v0.5 保留這個語意）；`E_fail_u` → 維持 `REJECTED`（R10）。報告的呈現、去重與複核流程見 [02 B6](02-methodology.md#b6-報告) 的「G2 駁回後的新證據」。兩者都加註 `post_g2_conflict` 並列入 B6 人工複核清單 |
| 成員片段全部 `NOT_FOUND`，但同一位置有 SARIF 或可重現的 FAIL | R0 不成立（v0.4）：照 R2–R7 裁決，例如只有一筆弱 SARIF → `UNCORROBORATED`（R7），成為種子威脅 |
| Lane A 參考性發現項 | `UNCORROBORATED`（R9），`advisory: true`；帶入下一個 Lane B run 作為額外輸入，在那次 run 中重新從頭裁決，但不計入獨立家族數（§4.1） |

**範例：K-014（單一家族＋一筆 SARIF）**：範例 bundle 的 `cluster.k-014` 只由 anthropic 家族回報（F-052），另有一筆 W1 掃描器的 SARIF 結果在同一位置。這正是審查發現 H-A1 的情況。

| 項目 | v0.2 | v0.3（`verdict.k-014-w3.example.json`，V-014-1） |
|---|---|---|
| 第一輪獨立回報的家族 | anthropic | anthropic（`routes/invoices.ts::updateInvoice`，桶 `authz`） |
| SARIF | 1 筆已解析的 ref，來自 `semgrep:scan`，算工具佐證 | 同一個 ref，改由 `opengrep:scan` 1.6.0 產生（稽核 seq 13，`inv-w1-opengrep-001`；規則 `vc.authz.update-without-owner`）。`semgrep:scan` 在 `licenses.yaml` 是法務閘門，v0.3 的 `E-SARIF-REF` 不接受它（N-7）；Opengrep 的狀態是「注意」，可以執行。規則不在 `high_precision_rules`（校準前為空）→ 弱工具訊號 |
| 票 | `ver_1`（nvidia，`nemotron_self`）支持，w＝0.6933；`ver_3`（openai，`gpt_oss_self`）支持，w＝0 | 相同，兩票的 `cited_evidence` 都是 `routes/invoices.ts:88`；只有 `ver_1` 是計權合格票；S＝0.6933 ＜ θ_confirm＝1.2（`calibration_version` 3，θ_reject 為 null） |
| 合格驗證家族 E | —（v0.2 沒有這個定義） | {nvidia, openai}；`ver_2`（`claude_sonnet`）屬 anthropic，排除 |
| `diversity_degraded` | false（有效票有 2 個家族） | true（計權合格票只有 1 個家族 ＜ min(2, 2)）；不影響結果，因為 R8 只作用在第 11 列 |
| 裁決欄位 | `tool_corroboration`＝[該 ref] | `tool_corroboration`＝[]、`tool_signal`＝[該 ref]、`independent_sources`＝2、`no_eligible_verifier`＝false、`provisional`＝false（E 中的 `nemotron_self` 在 `authz` 桶 w＞0） |
| 規則與狀態 | R2 → R5（工具佐證）→ `CONFIRMED_CORROBORATED`；`rule_version` `05-v0.2` | R2 → R6（獨立來源＝2）→ `LIKELY`；`rule_version` `05-v0.3` |

範例的 `rule_trace`：

```text
R2:weak_sarif=opengrep:scan rule vc.authz.update-without-owner (audit seq 13; not a calibrated high-precision rule),weighted_support=1 (nvidia),score=0.6933<theta_confirm=1.2,independent_sources=2
R6:independent_sources=2 (anthropic + weak SARIF signal)->LIKELY
```

一個家族加一條未經校準的掃描器規則，v0.2 就能「確認」；v0.3 只到 `LIKELY`。它仍會送 W4 測試並成為種子威脅；要確認，需要可執行證明、強工具佐證，或達門檻的跨家族計權票。

### 4.3 投票加權

- **v0.4：兩邊分開計算**（審查 A10）[H]。v0.3 把兩種答對混成一個正確率；真缺陷佔多數的語料上，永遠投支持的驗證者正確率很高，卻從來沒有正確地反駁過。現在每個（m, b）有兩組統計，下面的公式與「接近 0」判準在每一邊各自套用：
  - **support 邊**：只看**真實缺陷**上的非棄權合格票；答對＝投支持。用於 SUPPORT 票的權重。
  - **refute 邊**：只看**已知非缺陷**（誤報叢集與 §5.1 誘餌）上的票；答對＝投反駁。用於 REFUTE 票的權重。這也就是 §5.3 M-11 的真陰性率。
  - `calibration.yaml` 的 `result.weights[]` 每列有 `support`、`refute` 兩組 `{n, correct, a, w, near_zero, near_zero_reasons}`；validator 逐邊重算（`E-CAL-WEIGHT`）。
- 以下以單一邊說明（原 v0.3 的定義）。對每個模型 m 與 CWE 桶 b，在**校準切分**上統計該模型作為驗證者的**非棄權合格票**：n(m,b)＝票數，C(m,b)＝與真值一致的票數（真實缺陷投支持、非缺陷投反駁）[H]。
- **平滑**（收縮到該模型跨桶的整體正確率 ā(m)）[H]：

  a(m,b) ＝ (C(m,b) ＋ k · ā(m)) ／ (n(m,b) ＋ k)，其中 k ＝ 10（相當於 10 張虛擬票）

  ā(m) ＝ Σ_b C(m,b) ／ Σ_b n(m,b)

- **權重** [H]：w(m,b) ＝ max(0, 2 · a(m,b) − 1)。正確率 0.5（等於擲硬幣）時權重為 0，正確率 1 時權重為 1。
  - 例：C＝18、n＝20、ā＝0.8 → a＝(18＋8)／30＝0.867 → w＝0.733。
- **「權重接近 0」的判準** [H]：下列任一成立，就把 w(m,b) 設為 0，並在報告與 `calibration.yaml` 標示 `near_zero: true`，原因寫入 `near_zero_reasons`（依序對應下列三項：`w_below_min`、`wilson_lower_le_max`、`n_below_min`）：
  1. w(m,b) ＜ 0.2（即 a ＜ 0.6）；
  2. 原始正確率 C／n 的 Wilson 95% 下界 ≤ 0.5（和隨機分不開）；
  3. n(m,b) ＜ 10（資料不足）。
- 加權分數 S 用於 §4.2 的 R4、R5；w＝0 的票不算「計權合格票」。
- 權重為 0 的模型**仍保留在報告中並註明**，不偷偷移除；它在該桶提出的新叢集仍會進入驗證（補充召回），只是不參與確認或否決（§5.5）。
- **新模型或新版本**在完成 §5.8 的最小重跑前，所有桶 w＝0 [H]（fail-safe：只能補充召回）。v0.5 起由 validator 強制：`result.invalidated_by` 列出的模型，以及 `valid_for_model_keys` 不為空時不在其中的模型，權重一律為 0（`Index.weight`）。
- **fallback 的票**以投票時實際使用的模型（票上的 `voter_model_key`）查權重，不沿用被取代模型的權重 [H]。fallback 模型也適用上一條：完成 §5.8 重跑前 w＝0，所以票有紀錄、`valid` 照判，但不是計權合格票（§3 規則 3）。
- **只有驗證者有權重** [H]：reviewer 只提出發現項、不投票，所以沒有 w。各家族 reviewer 的 recall／precision 在 §5.3 M-1 量測，只當指標，不轉成權重、不影響裁決。理由：發現項本來就要經過證據接地（§3 規則 5）與跨家族驗證；reviewer 的偏誤由驗證者與可執行測試處理。
- **門檻由 §5.7 的程序決定**，不是事先憑直覺設定。

## 5. Calibration & Bias Lab

### 5.1 語料

**組成** [H]

| 部分 | 內容 | 用途 | 是否計入主要假設的 n |
|---|---|---|---|
| P：自建植入缺陷應用 | 以至少 3 種 vibe coding 工具生成的應用（例如 Next.js＋Supabase、FastAPI、Express 等常見組合），每個應用植入約 9 個已知缺陷；生成時自然產生的問題由人標註後加入真值 | 主要語料：權重、門檻、主要假設 | 是 |
| V：變形版本 | 每個 P 應用各 1 個語意不變的變形：重新命名識別字與路由、刪註解、重新格式化、打散檔案順序 | 表面特徵偏誤與記憶（汙染）檢查 | 否（與原版高度相關） |
| D：誘餌 | 看起來像漏洞但其實安全的程式位置（例如有 `tenant_id` 條件的查詢、已參數化的 SQL） | 量測誤報與錯誤確認 | 否（用於 precision） |
| B：公開 benchmark | BaxBench 情境（392 個後端任務，每個情境對應 CWE，並有黑箱與白箱安全檢查）[V][E:vibe_risks-20][E:vibe_risks-21]；OWASP Benchmark（只用於 SAST 分流） | 對外可比較的輔助報告 | 否；**不用於**權重、門檻或主要假設 |

- 重點類別參考真實事件：RLS 設定錯誤、前端 bundle 內含金鑰、缺少認證 [P][E:vibe_risks-26]、IDOR、套件幻覺。
- **生成工具的家族要平衡**：每個 P 應用記錄 `generator_family`（生成它的模型家族）。評審可能偏好自己家族生成的程式（§2.1 自我偏好），所以各生成家族的應用數要大致相等，並依 `generator_family` 分層報告 [H]。
- **每個植入缺陷附一支利用測試**（正對照）：在植入版 FAIL、在修正版 PASS。真值因此可被程式驗證，也順便提供 §4.2 `E_pass` 的正對照與 §5.3 M-9 的測試漏報率量測 [H]。
- **資料集授權**：BaxBench 的程式碼與 Hugging Face 資料集都是 MIT [V][E:vibe_risks-34]；OWASP BenchmarkJava 是 GPL-2.0 [V][E:whitebox-50]，只當作獨立的受測目標執行，不重新散布；PrimeVul（取自真實 C/C++ 專案的函式）的 repo 是 MIT，但以 Google Drive 發布的資料集沒有另外標示授權 [P][E:vibe_risks-35]，只用於內部評估。
- **注意 PrimeVul 的教訓**：公開集可能有標註錯誤、重複與資料洩漏，會高估效能 [V][E:multi_llm_bias-25]；BaxBench 同樣是公開集，所以只作輔助。

**各 CWE 桶的目標數**（P 部分植入缺陷，兩個切分合計）[H]

| 桶 | 目標正例 | 誘餌（約 0.3×） |
|---|---|---|
| 授權（含 IDOR、RLS） | 90 | 27 |
| 注入 | 80 | 24 |
| 認證 | 70 | 21 |
| secrets | 60 | 18 |
| 設定 | 60 | 18 |
| LLM 專屬 | 60 | 18 |
| 加密 | 40 | 12 |
| SSRF | 40 | 12 |
| 路徑穿越 | 40 | 12 |
| 反序列化 | 30 | 9 |
| 其他（含套件幻覺） | 40 | 12 |
| **合計** | **610** | **183** |

- 合計 610 個正例 ÷ 每應用約 9 個 ≈ 68 個 P 應用（另加 68 個 V 變形）[H]。
- 權重與門檻按桶估計；主要假設以**合併所有桶**的正例檢定（§5.6），各桶結果只作描述性報告（附 CI），不做各桶的假設檢定。

**切分** [H]
- **以應用為單位**分層切分（依桶分布與 `generator_family` 分層），同一應用的 P、V、D 一律在同一切分，避免洩漏。
- **校準切分**：≥ 28 個應用、≥ 250 個正例 → 用來開發 prompt、估計 w(m,b)、調整 θ、挑選 ② 的最佳模型。
- **保留切分**：≥ 40 個應用、≥ 360 個正例（數字由 §5.6 的樣本數計算決定）→ 只用來檢定主要假設與報告最終指標。保留切分的結果在主要分析前**不得查看**；任何人看過就記錄在 `calibration.yaml` 的 `holdout_access_log`。
- 另從保留切分固定抽出 20% 應用作為 **哨兵子集**，供 §5.8 的版本回歸檢查使用（只報告、不調參）。

**汙染控制** [H]
- **截止日後的應用**：P 應用在所有受測模型公布的訓練截止日**之後**才生成，並記錄生成日期；語料存放在私有 repo，不公開。若要公開，公開後該批應用就只能當 B 類（公開 benchmark）使用。
- **變形版本**：比較同一模型在原版與變形版的 recall。差距 ＞ 5 個百分點就標示該模型「可能有記憶或表面特徵敏感」，並在報告列出 [H]。SecLLMHolmes 也發現重新命名會讓 LLM 的安全判斷出錯 [P][E:multi_llm_bias-26]。
- **Canary 字串**：語料 repo 的每個 metadata 檔（不在切片內，避免干擾審查）含一組唯一 GUID canary。BIG-bench 也在所有任務檔放 canary 字串，目的是**防止**任務流入網路爬取的訓練資料 [P][E:multi_llm_bias-39]。canary 的主要作用是讓遵守它的資料蒐集流程**排除**本語料；它不是汙染檢測工具。
  - 另外做一個粗略的探測 [H]：每次校準前，要求每個受測模型補完 canary 前綴；若能補出 → 該模型視為已接觸語料，改用新一批應用。
  - **做不到**：補不出 canary **不能證明**沒有汙染（訓練流程可能剔除了 canary 行、只收了程式碼，或模型看過改寫版本）。汙染控制主要靠截止日後生成、私有存放與變形版本比較，canary 只是輔助。
- **公開 benchmark**（B 類）結果一律標示「可能已汙染」，分開報告。

**標註流程** [H]
1. **植入缺陷驗證**：每個植入缺陷的利用測試必須在植入版 FAIL、修正版 PASS；不符者修正或移除。
2. **雙標註**：兩位標註者**獨立**標註每個「對不上植入缺陷」的叢集（真實自然缺陷／誤報／範圍外），並標註桶與 CWE。標註者看不到叢集來自哪一組（§5.2）或哪個模型。
3. **一致性門檻**：以每批（約 10 個應用）計算 Cohen's κ（二元：真實缺陷 vs 誤報）；**κ ≥ 0.70** 才接受該批。未達門檻 → 修訂標註指引並重標該批，最多 2 輪；仍未達 → 該批不進入保留切分的主要分析，並在報告列出。
4. **仲裁**：兩人不一致的項目由第三位資深標註者裁定，記錄理由；仲裁結果即為真值。
5. 自然缺陷確認後加入真值，並補上利用測試（能做到時）。

### 5.2 對照組（必要）

| 組別 | 內容 |
|---|---|
| ① 單一最佳模型、單次 | 基準；用來在校準切分挑選「最佳模型」M* |
| ② 單一最佳模型、N 次取樣彙整（Self-MoA／self-consistency） | **多家族效益的比較基準** |
| ③ 多家族（N 個家族各一次，或各多次） | 本工具包的預設 |
| ④ 多家族＋工具佐證（強／弱，§4.2）＋可執行驗證 | 完整管線 |
| ⑤ 少數否決（**探索性**，不屬於預先登記的假設） | 與 ③ 相同的輸出；接受規則改為「≥ 2 個家族回報，**且**沒有任何一張計權合格反駁票」——任一合格驗證者提出有證據的反駁就不接受 |

**⑤ 的定位** [H]：少數否決是該研究在程式回饋評分任務上提出的一種緩解做法（主要的誤差改善來自另一個迴歸框架）[P][E:multi_llm_bias-43]；那是評分任務、不是漏洞審查，所以 ⑤ 只作探索。本工具包的 R3／R4 其實已經讓單一計權合格反駁把叢集送去 `DISPUTED`（人審）而不是自動確認，所以 ⑤ 回答的是「若把這種反駁改成直接否決、不經人審，precision 與 recall 會怎樣」。⑤ 在保留切分上只報告 precision、recall 與相對 ③ 的差值（bootstrap CI），**不做**假設檢定、不影響 §5.6 的判定與預設設定；若結果顯示值得採用，要在下一輪校準預先登記後才能成為規則。

**多家族的效益只以 ② 為基準報告**。「混用多家族不一定勝過單一最佳模型多次取樣」是已知的反證 [V][E:multi_llm_bias-19]。②、③ 的精確定義與勝負判準見 §5.6；③ 未勝出時的預設設定切換見 §5.6「誠實的後備方案」。

### 5.3 指標

每個指標都在**保留切分**上報告（附 95% CI）；「M2 出場門檻」是 M2 里程碑的驗收條件，全部是 **[H]**。注意：**「③ 勝過 ②」不是出場條件**，那是實驗結果，不論哪一方勝出都照實報告（§5.6）。

| 編號 | 指標 | 定義 | M2 出場門檻 [H] |
|---|---|---|---|
| M-1 | 各模型、各 CWE 桶的 precision／recall | 以 §5.6 的比對規則計算；附 Wilson 95% CI。分兩種角色報告 [H]：verifier（投票的正確率，對應 §4.3 的權重）；reviewer（各家族第一輪發現項的 precision 與 recall，**只當指標**，不轉成權重、不影響裁決，§4.3） | 每個（模型，桶）組合都有 ≥ 20 張非棄權合格票，或已依 §4.3 標示 `near_zero`；④ 預設設定下 `CONFIRMED_*` 的 precision ≥ 0.90（Wilson 下界 ≥ 0.80），`CONFIRMED_*`∪`LIKELY` 的 recall ≥ 0.60 |
| M-2 | 兩兩錯誤相關 | Cohen's κ 與 CAPA（以錯誤重疊為基礎、經機率校正的相似度）[V][E:multi_llm_bias-03] | 所有家族兩兩都有值與 bootstrap CI；κ ≥ 0.6 的一對在報告標示「多樣性不足」 |
| M-3 | 標註者一致性 | §5.1 的 Cohen's κ | 保留切分每批 κ ≥ 0.70 |
| M-4 | 自我偏好差 | 同一模型判斷**已知為假**的候選時，候選來自自己家族 vs 其他家族的錯判率（判為真）之差 | 每個模型每種條件 ≥ 100 題；差值的 95% CI 下界 ＞ 0.05 的模型，報告標示並維持「不自評」規則（§3 規則 2）；另外稽核：100% 的計權合格票都滿足家族／血統排除 |
| M-5 | 位置翻轉率 | 同一組候選交換順序後判定改變的比例 | 每個驗證者 ≥ 100 對；翻轉率 ≤ 0.10 才可擔任驗證者，否則該模型改為「兩種順序各評一次，不一致則棄權」，或其權重設為 0 |
| M-6 | DISPUTED 佇列精準度 | `DISPUTED` 叢集中真實缺陷的比例（驗證設計規則 7） | 保留切分 ≥ 30 個 `DISPUTED`；精準度落在 0.25–0.80 之間。＜ 0.25 表示佇列多半在浪費人工 → 提高 θ_reject 的可行性檢查或收緊 R4；＞ 0.80 表示可自動確認的太多 → 重新檢查 θ_confirm。超出範圍時要有記錄在案的門檻調整，才算通過 |
| M-7 | 缺票率 | 缺票數 ÷ 預期票數（依 `missing_votes.reason` 分類） | 每個供應商 ≤ 0.05；`diversity_degraded` 叢集比例 ≤ 0.05 |
| M-8 | 每個確認發現項的成本 | 該組總成本（USD 與 tokens）÷ 保留切分中真陽性的 `CONFIRMED_*` 數 | ①–④ 都有值；③／④ 超過 ② 的 3 倍時在報告中列為取捨，不擋出場 |
| M-9 | 測試漏報率 | 真實缺陷（有正對照的植入缺陷）上出現 `E_pass` 的比例，分「有／無正對照」 | 有值與 CI；供未來決定是否允許 PASS 自動降級（§4.2） |
| M-10 | 其他 | 延遲、schema 修復次數、原版 vs 變形版 recall 差（§5.1） | 有值 |
| M-11 | 驗證者真陰性率（次要分析） | 每個驗證模型、每個桶：對**已知非缺陷**（誤報叢集與 §5.1 誘餌）投反駁的比例，與真陽性率（對真實缺陷投支持）**分開**報告，不只報合併的正確率 a(m,b)。動機：程式回饋任務上 LLM 評審真陽性率約 96%、真陰性率低於 25% [P][E:multi_llm_bias-43] | 每個驗證模型有值與 Wilson CI（每桶 ≥ 20 個非缺陷，否則合併桶報告）；真陰性率 ＜ 0.5 的模型在報告標示「傾向支持」（`by_model[].flag: support_leaning`，若且唯若值 ＜ 0.5）。§4.3 的權重公式本輪不改，若 M-11 顯示支持票與反駁票的可靠度差很大，下一版再考慮分開加權 [H] |

### 5.4 實驗步驟
1. 固定語料與切片；記錄每個模型的 ID、版本、參數；把 §5.6 的預先登記內容（含本檔版本的 hash）寫入 `calibration.yaml` 的 `preregistration`，之後才執行保留切分。
2. 各組獨立執行；每組重複 R＝3 次，以估計變異。CodeJudgeBench 發現所有評審都有明顯的隨機性 [V][E:multi_llm_bias-11]。
3. 由人標註真值（§5.1：兩位標註者、κ ≥ 0.70、仲裁）。
4. 在校準切分估計 w(m,b)（§4.3）與掃描器規則的 `precision_lower95`（§5.10），再調整 θ（§5.7），並以 ① 選出 M*。θ 放在最後，因為哪些叢集走到 R5 投票分支取決於 `high_precision_rules`（強工具佐證的叢集在第 10 列就已確認）[H]。
5. 在校準切分上以 ②、③ 的前導結果估計 §5.6 的干擾參數 ψ 與 ρ（**不看**保留切分），必要時上修保留切分樣本數。
6. 解盲保留切分：檢定主要假設（§5.6），計算 §5.3 指標，並做 §5.10 的保留切分檢查。
7. 以結果產出 `calibration.yaml`（權重、門檻、高精準規則名單、建議的 N、主要假設結果、預設設定），欄位見 §5.9。

### 5.5 決策規則
- 最佳 N 的起點可以參考 Team Atlanta 2026 的 patch ensemble 研究：N＝3 是甜蜜點 [P][E:reference_systems-15]。但它是 blog、不是同儕審查論文，**任務是從已通過測試的 patch 中挑選**，與發現項審查不同，所以只能當起點。
- 自架 Nemotron（Nano 或 Lightning，約 3–3.5B active）與前沿模型差距可能很大。若它在某 CWE 桶的權重接近 0（§4.3 判準），就在該桶只保留作「補充召回」用途（它提出的新叢集仍會進入驗證），不參與否決。

### 5.6 預先登記的主要假設：③ 是否勝過 ②

以下內容在解盲保留切分前寫定，之後不得更改；任何偏離都要在報告中逐條列出 [H]。

**兩組的精確定義** [H]
- **M\***：在校準切分上，① 單次 recall 最高的模型（同分取成本較低者）。
- **②a（主要比較組）**：M\* 對每個切片取樣 3 次（各供應商預設溫度），叢集後「≥ 2 次取樣都回報」的叢集才算**接受**（self-consistency）。
- **②b（次要）**：M\* 取樣 3 次，再由 M\* 彙整（Self-MoA 式）。若在校準切分上 ②b 的 recall 高於 ②a，就改用 ②b 當主要比較組——**在解盲前決定並記錄**。
- **③**：3 個家族各取樣 1 次，同一 prompt 範本、同一切片、同一輸出上限；「≥ 2 個家族都回報」的叢集才算接受。
- 兩組的模型呼叫次數相同（每切片 3 次）；成本另外以 M-8 報告。
- **比對**：接受的叢集若與真值缺陷有相同正規位置與桶（§4.1 的叢集鍵），就算命中；對不上的由 §5.1 的雙標註判定為自然缺陷或誤報。
- 每個缺陷在每組的**結果**＝3 次重複中 ≥ 2 次被命中（1）或否（0）。

**假設與檢定** [H]
- **主要指標**：保留切分正例上的 recall 差 Δ＝recall(③) − recall(②)。
- **H1（優越性）**：Δ ＞ 0。檢定：以**應用為重抽單位**的配對 bootstrap（10,000 次），取 Δ 的雙尾 95% percentile CI；**CI 下界 ＞ 0** 即成立（α＝0.05，雙尾）。敏感度分析：精確 McNemar 檢定（忽略應用內相關）。
- **H2（精準度不劣性）**：precision(③) − precision(②) 的單尾 95% 下界 ＞ −0.05（不劣性邊界 5 個百分點），同樣以應用為單位 bootstrap。
- **多重比較**：固定順序程序，先檢 H1，H1 成立才檢 H2，各用 α＝0.05，整體錯誤率控制在 0.05。
- **「③ 勝出」＝ H1 與 H2 都成立**。
- **最小效果量**：Δ＝8 個百分點。理由：投票相對最佳單一模型只好約 4% [V][E:multi_llm_bias-28]，Self-MoA 反過來勝過混合 MoA 3.8–6.6% [V][E:multi_llm_bias-19]；接入並維護 3 個供應商的成本，需要比這些文獻差距更大的效益才值得 [H]。

**樣本數計算（逐步）** [H]

配對二元結果的 McNemar 常態近似。符號：p₁₀＝③ 命中、② 未命中的比例；p₀₁＝相反；ψ＝p₁₀＋p₀₁（不一致比例）；Δ＝p₁₀ − p₀₁。

n ＝ [ z₁₋α/₂ · √ψ ＋ z₁₋β · √(ψ − Δ²) ]² ／ Δ²

1. 設定：α＝0.05（雙尾）→ z₁₋α/₂＝1.960；檢定力 0.80 → z₁₋β＝0.842；Δ＝0.08；ψ＝0.20（假設值，由步驟 5 的前導資料更新）。
2. √ψ＝√0.20＝0.4472 → 1.960 × 0.4472＝0.8765。
3. ψ − Δ²＝0.20 − 0.0064＝0.1936 → √0.1936＝0.4400 → 0.842 × 0.4400＝0.3703。
4. 相加 0.8765＋0.3703＝1.2468 → 平方 1.5546 → ÷ Δ²（0.0064）＝242.9 → **n₀＝243 個缺陷**。
5. **應用內相關的設計效果**：每應用 m＝9 個缺陷，假設組內相關 ρ＝0.05 → DE＝1＋(m − 1)ρ＝1＋8 × 0.05＝1.40 → 243 × 1.40＝340.2 → **341**。
6. **標註損耗 5%**（κ 未達門檻而剔除的批次等）→ 341 ÷ 0.95＝358.9 → **359**，取整為 **360 個正例 ≈ 40 個應用**（這就是 §5.1 保留切分的下限）。

敏感度（同一公式）：

| 情境 | n₀ | ×DE 1.40 | ÷0.95 |
|---|---|---|---|
| Δ＝0.08，ψ＝0.15 | 182 | 255 | 269 |
| **Δ＝0.08，ψ＝0.20（登記值）** | **243** | **341** | **359** |
| Δ＝0.08，ψ＝0.30 | 366 | 513 | 540 |
| Δ＝0.05，ψ＝0.20 | 626 | 877 | 924 |

- **樣本數重估**：若步驟 5 在校準切分估得 ψ ＞ 0.20 或 ρ ＞ 0.05，就用估計值重算並擴充保留切分；只用干擾參數、不看保留切分的效果，所以不影響型一錯誤 [H]。
- **誠實說明**：要偵測 5 個百分點的差距需要約 924 個正例（約 103 個應用），超出 M2 的標註預算；所以本實驗**無法**排除「③ 有小於 8 個百分點的真實效益」。H2 的檢定力也沒有保證：若每組約 250 個接受的叢集、precision 約 0.85，未配對的差值標準誤約 √(2 × 0.85 × 0.15 ／ 250)＝0.032，單尾 1.645 × 0.032＝0.053，已超過 0.05 的邊界；只有兩組的誤報高度重疊（配對相關為正）時，H2 才有合理的檢定力 [H]。

**誠實的後備方案（預先登記）** [H]

| 結果 | 預設設定切換 | 報告用語 |
|---|---|---|
| ③ 勝出（H1、H2 成立） | 維持 `w2_review.strategy: multi_family` | 「在本語料上，多家族的 recall 高於單一最佳模型重複取樣 Δ（CI）」 |
| H1 成立、H2 不成立 | 預設改為 ④；若 ④ 相對 ② 的 precision 也不劣，才維持多家族；否則 `strategy: single_best_resampled`，多家族降為選用的「補充召回」 | 「多家族多找到問題，但誤報較多」 |
| H1 不成立（CI 含 0） | 預設改為 `strategy: single_best_resampled`（② 的設定、N＝3）；多家族保留為選用 | 「在本語料上，**未證明**多家族勝過單一最佳模型重複取樣」 |
| ② 顯著勝出（CI 上界 ＜ 0） | 同上，並把此結果提給 README 與 [06 §3](06-security-legal-limitations.md#3-做不到不承諾的事) 的維護者更新說法 | 「在本語料上，多家族**不如**單一最佳模型重複取樣」 |

- 不論結果如何，**跨家族驗證者**（§3 規則 2）是否保留，另由 M-4 決定：若所有模型的自我偏好差 CI 都含 0，跨家族驗證改為建議而非必要；否則維持必要。
- 這些切換寫入 `calibration.yaml` 的 `recommended_defaults`，由組態載入時套用；使用者可以覆寫，但報告會標示「未採用校準建議」。
- **`single_best_resampled` 下的裁決**（v0.4 定義）[H]：R0–R13 不變。同一模型的多次取樣**不是**獨立家族，所以「≥ 2 次取樣都回報」只決定該叢集是否進入裁決（② 的接受規則），算作 **1 個**獨立來源；R6 的 `LIKELY` 需要另一個來源（弱 SARIF 或 `E_fail_u`）。因此這個策略下多數叢集是 `UNCORROBORATED`（R7）並成為種子威脅，確認主要靠 W4／B5 的可執行證明（R1）。跨家族 verifier 是否保留另由 M-4 決定（上一條）；保留時，它的計權合格票照常進 R3–R5。報告首頁標示「單一模型重複取樣（未證明多家族效益）」。

### 5.7 門檻調整（θ_confirm、θ_reject）

**在校準切分上選定，在保留切分上報告**；兩者都以 §4.2 的完整規則在 ④ 預設設定下模擬 [H]。

- **格點**：θ ∈ {0.1, 0.2, …, S_max}，S_max＝該設定下可能的最大 |S|。
- **θ_confirm**：目標＝**最大化** R5 投票分支的 recall，**限制**：經 R5 投票分支確認的叢集 precision ≥ 0.90，且其 Wilson 95% 下界 ≥ 0.80，且該分支至少有 40 個叢集。在可行的 θ 中取**最小者**（recall 最高）。
- **θ_reject**：目標＝**最大化**被 R4 自動 `REJECTED` 的誤報數，**限制**：被自動駁回的叢集中真實缺陷的比例 ≤ 0.02，且其 Wilson 95% 上界 ≤ 0.08，且至少 40 個被駁回的叢集。在可行的 θ 中取**最小者**。駁回的限制比確認嚴，因為被駁回的叢集不會成為種子威脅，漏報無法在黑箱階段補回。
  - 例：60 個被駁回的叢集中 0 個是真缺陷 → Wilson 上界約 0.060 ≤ 0.08，可行。
- **不可行時**：沒有任何 θ 滿足限制 → 該門檻設為 +∞（R5 投票分支或 R4 自動駁回停用，相關叢集改落在 `LIKELY`／`DISPUTED`／`UNCORROBORATED`），並在報告中說明。
- **保留切分檢查**：保留切分上的 precision 比限制低 0.05 以上（確認分支 ＜ 0.85，或駁回分支真缺陷比例 ＞ 0.07）→ 標示「門檻未能類推」，改用 +∞，下一輪校準再調。
- θ 只調一次；不得在看過保留切分後重選。

### 5.8 模型版本變更時的最小重跑集

**觸發條件** [H]：任何參與模型的 `model_key` 改變，包括供應商、模型 ID、版本或快照日期、自架模型的量化方式、system prompt 範本 hash、解碼參數。

**最小重跑集** [H]：
1. **校準切分，只重跑改變的模型**擔任的角色（reviewer、verifier），R＝3；其他模型的輸出以內容 hash 重用。
2. 重新估計該模型的 w(m,b)，並依 §5.7 重選 θ（S 的分布會變）。
3. 該模型的 M-4 自我偏好（≥ 100 題／條件）、M-5 位置翻轉（≥ 100 對）、canary 檢查（§5.1）。
4. **哨兵子集**（§5.1，保留切分的固定 20%）上重算 M-1 與 M-7，只報告、不調參。

完成前，該模型所有桶 w＝0（§4.3）。任一桶 |Δw| ＞ 0.15 或 θ 改變 → `calibration_version`（整數）加一，新 run 記錄所用版本。

**需要重跑完整 Lab（含 §5.6 主要假設）** [H]：家族組成改變、M\* 改變、或自上次完整校準後已有 ≥ 2 個模型改變。

### 5.9 校準設定與結果的欄位

`calibration.yaml` 分成**設定**（事先寫定）與**結果**（實驗產出）兩部分，schema 見 [schemas/calibration.schema.json](schemas/calibration.schema.json)。本節列出本文件需要的欄位 [H]：

- **設定**：`calibration_id`、`calibration_version`（整數）、`preregistration`（本檔版本 hash、主要指標、檢定、α、Δ_min、ψ、ρ、不劣性邊界、登記時間）、`corpus`（每個應用的 ID、內容 hash、部分 P／V／D／B、`generator_family`、生成日期、切分、是否在哨兵子集）、`models`（`model_key`、家族、血統、版本、參數、prompt 範本 hash、訓練截止日）、`arms`（`"1"`、`"2a"`、`"2b"`、`"3"`、`"4"`、`"5"` 的定義、N、接受規則；`"5"` 即 ⑤ 少數否決，標示 `exploratory: true`）、`repetitions`、`random_seed`、`threshold_search`（格點、precision 下限、駁回真缺陷上限、最小叢集數）、`smoothing_k`、`near_zero_rules`、`annotation`（標註者 ID、κ 門檻、仲裁者）。
- **結果**：`weights[]`（模型、桶、n、C、a、w、`near_zero`、`near_zero_reasons`）、`thresholds`（`theta_confirm`、`theta_reject`、`high_precision_min` 三項，結構相同：`value`、`feasible`、校準與保留切分上的 precision／recall 與 CI、`generalised`）、`high_precision_rules[]`（`adapter`、`rule_id`、`tool_version`、`cwe_bucket`、`n`、`precision_lower95`；§5.10；校準前為空陣列）、`primary_hypothesis`（實際比較組 ②a／②b、Δ、CI、McNemar p 值、H1／H2 結果、決定、套用的後備方案）、`metrics`（M-1–M-11 的值與 CI）、`exploratory`（⑤ 的 precision、recall、相對 ③ 的差值與 CI）、`annotator_agreement[]`（批次、κ、是否接受）、`contamination`（canary 探測結果（只作輔助）、原版 vs 變形版差距）、`holdout_access_log`、`recommended_defaults`、`valid_for_model_keys`、`invalidated_by`（觸發 §5.8 的變更）。
- **`high_precision_min` 放在結果的 `thresholds` 裡**（`result.thresholds.high_precision_min`），不在設定，也不在 `toolkit.yaml`。它是政策下限、不是 §5.7 搜尋出來的，所以範例是 `value: 0.9`、`feasible: true`，兩個切分的統計都填 0（n＝0）、`generalised: false`。schema 要求這一項；validator 讀它的 `value`，`value` 為 null 時停用強佐證（沒有任何 SARIF 算強）。

### 5.10 掃描器規則的高精準名單（`high_precision_rules`）

**目的**：決定哪些 W1 掃描器規則的命中可以當**強**工具佐證（§3 規則 5），單獨讓叢集到 `CONFIRMED_CORROBORATED`（§4.2 R5 第 10 列）。其他規則的命中都只是弱訊號。名單以 (adapter, rule_id, tool_version, cwe_bucket) 為單位：同一條規則在不同桶分開量測，只在量測過的桶算強；掃描器換版就是另一列，要重新量測 [H]。

**為什麼要量測**：reviewer 看不到工具輸出，所以掃描器命中與家族回報是兩個獨立來源（§3 規則 5）。但要讓工具**單獨**確認一個叢集，就要先證明這條規則的命中很少是誤報；SAST 整體的誤報率很高 [V][E:whitebox-33]，而且本設計假設各規則的精準度差異很大 [H]。

**候選規則** [H]：`tools.yaml` 登錄的 W1 白箱工具模式（工具在 Z2、`b4_executable: false`），且 `licenses.yaml` 狀態為 `OK` 或 `注意`（與 `E-SARIF-REF` 的條件相同，§4.2）；在校準切分上至少命中一次的規則。

**量測**（校準切分）[H]：
1. 在校準切分的 P 與 D 應用上執行候選掃描器，版本固定，並寫入該列的 `tool_version`。V 變形版與 B 公開 benchmark 不計入：V 與原版高度相關，B 不用於任何門檻（§5.1）。
2. 每筆 SARIF 結果依 §4.1 的叢集鍵對到正規位置與桶；同一條規則在同一位置的重複結果只算一筆。
3. 對到真值缺陷（植入缺陷，或經 §5.1 雙標註確認的自然缺陷）＝真陽性；對到誘餌或被標為誤報＝偽陽性；範圍外的不計。對不上植入缺陷的結果，照 §5.1 的雙標註流程判定。n＝真陽性＋偽陽性。
4. `precision_lower95`＝真陽性／n 的 **Clopper-Pearson 雙尾 95% 區間下界**。選精確法，是因為它與 [04 §4.4](04-threat-to-testcase.md#44-機率型測試的次數與上界) 報告 k／n 的方法相同。

**列入條件**（全部成立）[H]：
- n ≥ 40（與 §5.7 的最小叢集數相同）；
- 校準切分上的 `precision_lower95` ≥ `high_precision_min`（預設 0.90）；
- 通過下面的保留切分檢查。

門檻的實際意思：n＝40 時要 40 筆全對（下界 0.912）；39／40 的下界只有 0.868，不列入。有 1 筆誤報時需要 n ≥ 54，有 2 筆時需要 n ≥ 70。

**保留切分檢查**（§5.4 第 6 步解盲後；只檢查、不調參）[H]：
- 在保留切分以同樣方法計數。該規則在保留切分的 n ≥ 10，且 precision 點估計 ≥ `high_precision_min` − 0.05（預設 0.85），才列入名單。
- n ＜ 10 或點估計太低 → 不列入，報告分別標示「保留切分樣本不足」或「未能類推」。這與 §5.7 保留切分檢查的邏輯相同：寧可少列，也不讓未經驗證的規則單獨確認。

**移除與暫停** [H]：
- 之後任何一次校準（含新加入的語料）重算的 `precision_lower95` ＜ `high_precision_min` → 移除。
- **版本綁定**：每一列記錄量測時的掃描器版本（`tool_version`）。執行時，只有該 SARIF 結果所屬稽核事件的 `payload.tool_version` 等於這一列的 `tool_version`，才算強佐證；而 validator 另外要求稽核事件的版本等於 `run.tool_versions` 中該 adapter 的版本（`E-RUN-CONFIG`）。所以掃描器換版後，舊的一列自動不再適用，結果只算弱訊號（等於暫停），直到在校準切分以新版本重新量測、加入新的一列。validator 只比對版本字串：規則內容改變但版本字串不變時（例如自有規則檔更新），它看不出差別，所以規則內容也要反映在所記錄的版本上 [H]。
- 實際使用中經人確認的誤報（該規則佐證的叢集被 G2 駁回，或在報告回饋中被標為誤報，見 [08 §11.16](08-implementation-spec.md#1116-sarif-輸出與報告回饋)）：去識別化後加入校準切分（§6），與原本的計數一起重算下界；低於 `high_precision_min` 就立刻暫停，下一版校準正式移除。
- 名單有任何增減 → `calibration_version` 加一，新 run 記錄所用的版本。

**校準前**：名單是空陣列，所有 SARIF 都是弱訊號。因此沒有達門檻的投票時，單一家族＋SARIF 最多到 `LIKELY`（§4.2 的 K-014 範例）。

## 6. 已知風險
- 模型版本更新可能讓校準失效 → 每次更換模型或版本都要重跑 §5.8 的最小集；完成前該模型權重為 0。
- 校準語料可能不代表真實應用 → 定期把真實專案中人工確認的案例加入語料（去識別化）；新增案例只進校準切分，保留切分維持固定。
- 語料汙染無法完全排除 → 截止日後生成、私有存放、變形版本比較只能降低風險；canary 只幫助排除，補不出也不能證明沒有汙染（§5.1）。
- 樣本數只能偵測 8 個百分點以上的差距 → 較小的真實差距可能被判為「未證明」（§5.6）。
- 高精準規則名單可能過度擬合校準語料 → 保留切分檢查、掃描器版本綁定、實際誤報回饋時暫停（§5.10）；名單為空時所有 SARIF 都只是弱訊號，單靠 SARIF 最多讓叢集到 `LIKELY`。
- 評審本身的偏誤無法完全消除 → 最終判定保留人工關卡（G2、G3）。
