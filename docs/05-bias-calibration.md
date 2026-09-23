# 05 降低模型偏誤：證據、規則、裁決、校準

> 你的需求：白箱每個 agent 可以接不同 LLM，以減少模型差異造成的偏誤。本文件說明：證據支持到什麼程度、工具包怎麼設計、以及**必須自己量測**的部分。標記說明見 [README](../README.md#標記說明)。

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
  - → 驗證者不能與報告者同家族。
- **位置偏誤**：以 ChatGPT 當評審時，只要交換候選順序，Vicuna-13B 在 80 題中就有 66 題「勝過」ChatGPT（Wang et al.，ACL 2024）[V][E:multi_llm_bias-12]。→ 隨機順序。
- **程式表面特徵偏誤**：程式碼評審會受變數名稱、註解、格式等表面變化影響，所有受測評審都出現分數高估與低估（Moon et al.，EACL 2026 Findings）[V][E:multi_llm_bias-10]。另外，SecLLMHolmes 發現，重新命名函式或變數、加入函式庫函式，會讓 LLM 的安全判斷出錯；這類擾動造成最多 26%／17% 的錯誤答案 [P][E:multi_llm_bias-26]。→ 各家族看到一致的輸入。
- **跨家族評審團**：由不同家族的小模型組成的評審團，在 3 種評審設定、6 個資料集上，比單一 GPT-4 評審更貼近人類判斷，偏誤較少、成本低 7 倍以上（PoLL）[V][E:multi_llm_bias-09]。
- **異質性有助於辯論**：Zhang et al. 的立場論文（未獲 NeurIPS 2025 Position Paper Track 接受）表示，讓參與辯論的模型異質化能「穩定」改善辯論框架（作者用語）[V][E:multi_llm_bias-17]。ReConcile 的作者也說，來自不同模型的多樣性對效能很關鍵 [P][E:multi_llm_bias-18]。
- **漏洞偵測的互補性**：較弱的 LLM 仍會提供其他模型沒有的正確預測；投票比 GPT-3.5 好 10% 以上，但相對最佳單一模型只好約 4%（cross-validation）；未找到發表場所（Widyasari et al.，2024）[V][E:multi_llm_bias-28]。
- **跨模型 critic 可以大量淘汰錯誤候選**：Refute-or-Promote（預印本）以對抗式 kill agent＋跨模型 critic 合併運作，淘汰 171 個 LLM 候選漏洞中的約 79%；作者也說「沒有任何漏洞是自主發現的」，流程中有人參與 [V][E:whitebox-32]。

### 2.2 限制或反對「多家族」的證據
- **混用多家族不一定更好**：「Rethinking Mixture-of-Agents」發現，混用不同 LLM 常會**拉低**平均品質；只用單一最佳模型的多次輸出做彙整（Self-MoA），在 AlpacaEval 2.0 上勝過混合 MoA 6.6%，在 MMLU、CRUX、MATH 平均勝 3.8% [V][E:multi_llm_bias-19]。
  - **這直接挑戰本工具包的前提**，所以 §5 一定要有 Self-MoA 對照組。
- **辯論的效益大多來自多數決**：Choi et al.（NeurIPS 2025，7 個 NLP benchmark）證明，單純辯論是 martingale，不會提高期望正確率 [V][E:multi_llm_bias-16]；但這只是一篇論文、NLP 任務，未在安全審查上驗證 [P][E:multi_llm_bias-37]。辯論常常打不贏 self-consistency [V][E:multi_llm_bias-15][E:multi_llm_bias-17]。→ 不做多輪辯論。
- **辯論中由對轉錯**：模型常在讀了同儕推理後從對的答案轉成錯的；原因未定（作者列出諂媚、從眾、模型與任務類型等可能因素；ICML 2025 workshop）[P][E:multi_llm_bias-21]。→ 第一輪互不可見。
- **同家族互審會「回音」**：一篇 2026 單一作者預印本的兩個實驗中，由 Claude 模型審查 Claude 生成的程式碼，錯誤會互相呼應而非抵銷；另有一個 4 個模型、3 個家族的跨家族實驗；作者主張以可執行規格當品質關卡，AI 審查只處理規格之外的殘餘問題 [單源][S-02]。→ 這與本工具包的 W0.5 規格＋可執行測試相符。
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
2. **不自評**：驗證者的 `family` 與 `lineage` 都必須與報告者不同；驗證時去除來源模型資訊；候選順序隨機化。karpathy/llm-council 也把互評匿名化，以免模型「偏袒」[V][E:reference_systems-31]。
3. **不跨家族 fallback**：reviewer 與 verifier 只允許同家族 fallback，且要記錄；失敗就記為缺票。
   - 可用家族少於 2 時照常執行，但裁決最高只到 `LIKELY`，報告標示 `diversity_degraded` 並列出缺少的家族。
4. **輸入一致**：所有家族看同一個切片（同等性單位＝最小可用 context，見 [02 W2](02-methodology.md#w2-多家族獨立審查)）。
5. **證據接地**：每個發現項都要通過逐字片段比對；優先以 SARIF 或可執行測試佐證。
6. **校準加權**：投票權重取自各模型在校準語料上、分 CWE 家族的實測精準度，不是等權。
7. **分歧→人工（G2）**：這是 **[H] 設計假設**，需要量測 DISPUTED 佇列的精準度。Trust or Escalate（ICLR 2025）支持「信心不足就不自動判定」，但它是升級給**更強的 LLM 評審**並選擇棄權，**不是交給人**，而且用的是單一評審的校準信心，不是跨廠商分歧 [P][E:multi_llm_bias-34]。
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
- **「獨立報告」的定義**：不同家族在**第一輪**各自貢獻了同一叢集的成員。
- 叢集結果依 [schemas/cluster.schema.json](schemas/cluster.schema.json) 保存，含 `member_finding_ids` 與 `families`。

### 4.2 裁決狀態

| 狀態 | 條件（Aggregator 以程式碼判定） |
|---|---|
| `CONFIRMED_EXECUTABLE` | 有可重播的測試證明（W4 或 B4）。**LLM 功能類**：固定設定跑 n 次、記錄目標模型與版本，k/n 次違反，且有確定性 oracle（工具呼叫紀錄、canary、狀態差異） |
| `CONFIRMED_CORROBORATED` | 片段比對通過，**且**（有 SARIF 佐證**或**至少 1 個不同家族驗證者同意） |
| `LIKELY` | 至少 2 個家族獨立報告，且沒有成立的反駁；或只有 LLM 評分支持（例如 promptfoo、PyRIT 的 LLM 評分）；或因多樣性降低而被封頂 |
| `DISPUTED` | 家族之間衝突（有報告、也有成立的反駁）→ G2 |
| `REJECTED` | 片段比對失敗，或多數跨家族驗證者反駁且理由成立 |
| `UNVERIFIED` | 片段比對失敗但尚未處理（暫時狀態，不刪除） |

每張票依 [schemas/verdict.schema.json](schemas/verdict.schema.json) 保存，含 `voter_family`、`voter_lineage`、`fallback_used`、`anonymized`、`order_randomized`。

### 4.3 投票加權
- 權重 w(model, cwe_bucket)＝該模型在校準語料上、該桶的精準度，並做平滑。
- 叢集分數＝Σ w × 票（同意＋1、反駁−1、棄權 0）。
- **門檻由 §5 的實驗決定**，不是事先拍腦袋。
- 權重低到接近 0 的模型，仍保留在報告中並註明，不偷偷移除。

## 5. Calibration & Bias Lab

### 5.1 語料
- **主要**：自建的「植入已知 CWE 的 vibe-coded 範例應用」。用 vibe coding 工具生成應用，再植入已知問題；也保留生成時自然產生的問題，由人標註。
  - 重點類別參考真實事件：RLS 設定錯誤、前端 bundle 內含金鑰、缺少認證 [P][E:vibe_risks-26]、IDOR、套件幻覺。
- **輔助**：
  - BaxBench 情境：392 個後端任務，每個情境都對應 CWE，並有黑箱與白箱安全檢查 [V][E:vibe_risks-20][E:vibe_risks-21]
  - OWASP Benchmark（SAST 分流）
- **注意 PrimeVul 的教訓**：避免使用有標註錯誤或資料洩漏的公開集；以自建語料為主 [V][E:multi_llm_bias-25]。

### 5.2 對照組（必要）

| 組別 | 內容 |
|---|---|
| ① 單一最佳模型、單次 | 基準 |
| ② 單一最佳模型、N 次取樣彙整（Self-MoA／self-consistency） | **多家族效益的比較基準** |
| ③ 多家族（N 個家族各一次，或各多次） | 本工具包的預設 |
| ④ 多家族＋工具佐證＋可執行驗證 | 完整管線 |

**多家族的效益只以 ② 為基準報告**。若 ③ 沒有勝過 ②，工具包仍支援多家族，但報告要誠實指出，並建議使用 ② 或 ④。

### 5.3 指標
- 各模型、各 CWE 桶的 precision、recall
- 兩兩錯誤相關：Cohen's κ、CAPA。CAPA 是以錯誤重疊為基礎、經機率校正的相似度 [V][E:multi_llm_bias-03]
- 自我偏好差：同一模型評自己的答案 vs 評其他家族的答案，在已知真值上的錯判率差
- 位置翻轉率：交換候選順序後判定改變的比例
- DISPUTED 佇列的精準度（驗證設計規則 7）
- 成本（tokens）、延遲、schema 修復次數、缺票率

### 5.4 實驗步驟
1. 固定語料與切片；記錄每個模型的 ID、版本、參數。
2. 各組獨立執行；每組至少重複 3 次，以估計變異。CodeJudgeBench 發現所有評審都有明顯的隨機性 [V][E:multi_llm_bias-11]。
3. 由人標註真值（兩位標註者＋仲裁）。
4. 計算 §5.3 指標；對 ②、③、④ 做配對比較，報告信賴區間。
5. 以結果產出 `calibration.yaml`（權重、門檻、建議的 N）。

### 5.5 決策規則
- 最佳 N 的起點可以參考 Team Atlanta 2026 的 patch ensemble 研究：N＝3 是甜蜜點 [P][E:reference_systems-15]。但它是 blog、不是同儕審查論文，**任務是從已通過測試的 patch 中挑選**，與發現項審查不同，所以只能當起點。
- 自架 Nemotron（Nano 或 Lightning，約 3–3.5B active）與前沿模型差距可能很大。若它在某 CWE 桶的權重接近 0，就在該桶只保留作「補充召回」用途（它提出的新叢集仍會進入驗證），不參與否決。

## 6. 已知風險
- 模型版本更新可能讓校準失效 → 每次更換模型或版本都要重跑 §5 的最小集。
- 校準語料可能不代表真實應用 → 定期把真實專案中人工確認的案例加入語料（去識別化）。
- 評審本身的偏誤無法完全消除 → 最終判定保留人工關卡（G2、G3）。
