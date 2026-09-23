# 01 研究調查：查證方法、參考專案與文獻

> 研究日期：2026-09-23。範圍限定在**防禦性**的程式審查、測試生成、威脅建模與驗證測試；**刻意不研究**攻擊技術細節（例如 CAPEC／ATLAS 的執行流程）。標記說明見 [README](../README.md#標記說明)。

## 1. 查證方法

### 1.1 流程
1. **研究**：8 個主題各由一個研究代理以網路搜尋撰寫發現，每條都附來源與信心程度。
2. **獨立查核**：每個主題再由另一個查核代理，嘗試用**不同發布者**的來源確認每條發現；無法確認就標「未查證」，與證據衝突就標「推翻」並給出更正。
3. **計畫審查**：初版計畫交給 4 個審查代理，從證據忠實度、架構可行性、安全與範圍、需求符合度四個角度做對抗式審查，再依結果修訂（§6）。
4. **補做查證**：審查代理新帶入的事實，以及撰寫文件時需要的細節，另外上網查證（§4）。
5. **撰寫後查核**：文件完成後，再由獨立代理把每個事實陳述逐條比對證據帳本的**查核結果與更正**（不是原始主張）。

### 1.2 結果統計
- 共 **321** 條發現：
  - 已查證 273 條
  - 部分查證 43 條
  - 被推翻、已更正 5 條
- 完整內容見 [evidence/ledger.md](evidence/ledger.md)（英文原文＋查核意見＋來源），機器可讀版見 [evidence/research-findings.json](evidence/research-findings.json)。
- **獨立性的限制**：不少條目只能以原始或廠商來源確認，例如「只查了 CrewAI 自己的文件」「只有 SoK 能確認」。審查代理以關鍵字比對估計，至少有 55 條屬於這類 [單源：審查代理估計]。文件中這類陳述另標 **[單源]**。
- **連結檢查**：2026-09-23 以 curl 檢查約 670 個外部 URL，結果見 [evidence/link-check-2026-09-23.md](evidence/link-check-2026-09-23.md)。
- **工具限制**：GitHub API 在研究環境中被擋；部分 PDF 與網站無法直接讀取（openai.com、Springer、ACM 回傳 403；X 回傳 402）；WebFetch 以摘要模型轉述，引文可能被改寫；部分主題用完了 WebSearch 額度（見 ledger 各主題的「研究限制」）。

### 1.3 5 條被推翻的主張與更正

| 證據 ID | 原主張 | 更正 |
|---|---|---|
| E:providers-22 | LiteLLM `hosted_vllm/` 會原樣傳遞 tools 與 response_format | tools 的 `strict` 與 `additionalProperties` 會被移除；response_format 看起來會傳遞 |
| E:whitebox-39 | EvoSuite v1.2.0 發布於 2024 | 實為 2021-09-16，且只支援到 Java 11；視為 2021 年後未維護 |
| E:threat_modeling-11 | pytm v1.4.0 發布於 2025-07 | 實為 2026-07-06；114 條威脅中 98 條引用 CAPEC、75 條引用 CWE |
| E:threat_modeling-52 | 威脅→CAPEC→CWE→ASVS→WSTG 每一環都能取自官方資料 | 多段沒有官方對照（見 [04 §1.1](04-threat-to-testcase.md#11-官方與非官方連結)） |
| E:reference_systems-37 | 所有參考系統都不只依賴 LLM 共識確認發現項 | 過度概括：Claude Code Security 的公告只提到 LLM 自我驗證＋人工核准；部分 AIxCC 隊伍只用 LLM 評審 SARIF |

## 2. 主題摘要

### 2.1 多代理編排與模型閘道（[ledger](evidence/ledger.md#orchestration)）

| 框架 | 狀態 | 每個 agent 用不同廠商模型？ | 人工關卡／持久化 | 結論 |
|---|---|---|---|---|
| LangGraph 1.x | MIT，1.2.12（2026-09-21）[V][E:orchestration-01] | 可 [V][E:orchestration-02] | `interrupt()`＋checkpointer [V][E:orchestration-04][E:orchestration-05] | **採用** |
| Microsoft Agent Framework 1.0 | MIT，GA 2026-04-03 [V][E:orchestration-07] | 可，每個 Agent 有自己的 chat client [V][E:orchestration-08] | checkpoint＋request/response [V][E:orchestration-09] | 備案 |
| CrewAI | MIT，1.15.22 [V][E:orchestration-11] | 可，其他供應商走 LiteLLM [V][E:orchestration-12] | Flows `@persist`、`@human_feedback` [V][E:orchestration-14] | 不採用（hierarchical 模式由 manager LLM 派工、預設開 telemetry）[V][E:orchestration-13][E:orchestration-15] |
| OpenAI Agents SDK | MIT，0.22.3（仍是 0.x）[V][E:orchestration-16] | 可；但追蹤預設上傳到 OpenAI，沒有 OpenAI key 時上傳失敗（可關閉或改用其他 trace processor），託管工具只限 OpenAI Responses 模型 [V][E:orchestration-17] | `needs_approval`＋RunState [V][E:orchestration-18] | 不採用 |
| Claude Agent SDK | MIT 套件＋Commercial Terms [V][E:orchestration-19] | **不可**：不支援路由到非 Claude 模型 [V][E:orchestration-21] | hooks、權限、sessions [V][E:orchestration-22][E:orchestration-23] | 不作核心 |
| AutoGen | 維護模式 [V][E:orchestration-06] | — | — | 不採用 |
| Google ADK 2.x | Apache-2.0 [V][E:orchestration-24] | 可，經 wrapper [V][E:orchestration-25] | tool confirmation（部分 session service 不支援）[V][E:orchestration-27] | 未深入評估 |

- **閘道**：LiteLLM 支援 100 多個供應商，有預算與 fallback [V][E:orchestration-29]；但 2026-03-24 發生 PyPI 供應鏈事件 [V][E:orchestration-31]。OpenRouter 是 SaaS（查核者推論為封閉原始碼：其 GitHub 組織只有 SDK 與範例，沒有路由平台本身），另有 ZDR 路由選項 [V][E:orchestration-32][E:orchestration-33]。
- **協定**：
  - MCP 已捐給 Linux Foundation 旗下的 Agentic AI Foundation [V][E:orchestration-34]；最新規格 2026-07-28 [V][E:orchestration-35]；有安全最佳實務文件 [V][E:orchestration-36]。
  - A2A 於 2026-03-12 發布 v1.0.0 [V][E:orchestration-37]。

### 2.2 LLM 供應商（[ledger](evidence/ledger.md#providers)）
- **Nemotron**：
  - Nemotron 3 Nano（2025-12）、Super（2026-03）、Ultra（2026-06）[V][E:providers-01][E:providers-02]；3.5 Lightning（2026-08）[V][E:providers-03]。
  - 授權：Nemotron Open Model License 或 OpenMDW-1.1 [V][E:providers-06][E:providers-07]。
  - 雲端 build.nvidia.com 是試用服務，條款禁止機密資訊與正式用途 [V][E:providers-10]。
  - 自架用 vLLM／SGLang／NIM [P][E:providers-11][E:providers-12]；硬體需求見 [V][E:providers-13]。
- **Claude**：
  - Fable 5.1、Opus 5.5、Sonnet 5 有 1M context，Haiku 4.5 為 200K [V][E:providers-23]。
  - structured outputs 已 GA，schema 有限制 [V][E:providers-24][E:providers-25]。
  - Opus 5.5 拒絕強制 tool_choice [V][E:providers-26]。
  - 資料保留與 ZDR [V][E:providers-27][E:providers-28][E:providers-29]。
- **OpenAI**：
  - GPT-6 Astra、Sol、Luna（2026-09）[P][E:providers-31]；structured outputs [V][E:providers-32]。
  - 資料保留、`store`、ZDR 例外 [V][E:providers-33][E:providers-34][E:providers-35]；schema 被視為 system data [V][E:providers-36]。
  - 開放權重的 gpt-oss-120b [V][E:providers-37]。

### 2.3 多模型與偏誤（[ledger](evidence/ledger.md#multi_llm_bias)）
摘要見 [05 §2](05-bias-calibration.md#2-證據)。一句話：**跨家族能降低、不能消除偏誤** [V][E:multi_llm_bias-08][E:multi_llm_bias-09]；**混用多家族不一定勝過單一最佳模型多次取樣** [V][E:multi_llm_bias-19]；**辯論的效益大多來自多數決**（單一篇論文、7 個 NLP benchmark，未在安全審查上驗證）[V][E:multi_llm_bias-16][P][E:multi_llm_bias-37]；**所以必須自己量測**。

### 2.4 白箱工具與研究（[ledger](evidence/ledger.md#whitebox)）
- **確定性工具**：Opengrep、Semgrep、CodeQL、Bandit、Betterleaks、gitleaks、TruffleHog、OSV-Scanner、Trivy、Syft、Grype、SonarQube [V][E:whitebox-04]～[E:whitebox-16]（其中 Betterleaks 為 [P][E:whitebox-09]）；SARIF 2.1.0 [V][E:whitebox-17]。
- **LLM 輔助**：
  - IRIS [V][E:whitebox-18]、Vulnhuntr [V][E:whitebox-19]
  - Claude Code security-review [V][E:whitebox-20]、Claude Security [P][E:whitebox-21]
  - Copilot Autofix [V][E:whitebox-22]
  - Aardvark／Codex Security：數字為 OpenAI 自報（官方頁＋媒體），未經獨立稽核 [V][E:whitebox-23][E:whitebox-24]
  - CodeMender [V][E:whitebox-26]
  - Semgrep AI triage [P][E:whitebox-27]
- **測試生成**：TestGen-LLM [V][E:whitebox-34]、ACH [V][E:whitebox-35]、CoverUp [V][E:whitebox-36]、Pynguin [V][E:whitebox-38]、Agentic PBT [V][E:whitebox-41]；oracle 的限制 [V][E:whitebox-43][E:whitebox-44]。

### 2.5 威脅建模（[ledger](evidence/ledger.md#threat_modeling)）
- **方法**：Manifesto、OWASP Cheat Sheet、STRIDE、PASTA、LINDDUN、attack tree [V][E:threat_modeling-01]～[E:threat_modeling-08]（其中 STRIDE-per-element 的資料存放對應為 [P][E:threat_modeling-04]）。
- **工具**：Threat Dragon、pytm、Threagile、OTM、STRIDE-GPT [V][E:threat_modeling-09]～[E:threat_modeling-18]（pytm 為 [C][E:threat_modeling-11]；STRIDE-GPT 的 ID 對照與驗證器 PR 為 [P][E:threat_modeling-16][E:threat_modeling-17]）。
- **LLM 威脅建模的準確度研究**：[V][P][E:threat_modeling-20]～[E:threat_modeling-30]。多數在特定領域（5G、銀行、AWS、Kubernetes），**不能直接套用到 vibe-coded 應用**。
- **AI／Agent 分類**：OWASP LLM Top 10 2025、Agentic Top 10 2026、Agentic Threats、MAESTRO、ATLAS、AI Testing Guide、AISVS [V][E:threat_modeling-31]～[E:threat_modeling-39]（MAESTRO 的 CI 範例為 [P][E:threat_modeling-36]，其工具 TITO 由該 blog 的共同作者撰寫，不是第三方工具）。
- **需求與測試標準**：ASVS 5.0、OpenCRE、WSTG、CAPEC、CWE、SSDF [V][E:threat_modeling-40]～[E:threat_modeling-49]；abuse case [V][E:threat_modeling-51]。

### 2.6 黑箱驗證工具與安全實務（[ledger](evidence/ledger.md#blackbox)）
- **工具**：ZAP、Nuclei、Schemathesis、RESTler、EvoMaster、Playwright、k6 [V][E:blackbox-01]～[E:blackbox-28]（其中 Nuclei 簽章與 `-dut`、REST 工具比較研究、k6 2.0 新指令為 [P][E:blackbox-11][E:blackbox-20][E:blackbox-26]）。
- **ROE**：NIST SP 800-115 [V][E:blackbox-29]～[E:blackbox-31]。
- **沙箱**：gVisor、Firecracker、E2B、Docker、Docker Sandboxes、sandbox-runtime [V][E:blackbox-34]～[E:blackbox-40]。

### 2.7 Vibe coding 風險（[ledger](evidence/ledger.md#vibe_risks)）

| 主題 | 發現 |
|---|---|
| 名詞 | 由 Karpathy 在 2025-02-02 提出 [V][E:vibe_risks-01]；Collins 2025 年度詞彙 [V][E:vibe_risks-02] |
| Pearce et al.（Copilot） | 約 40% 程式有漏洞 [V][E:whitebox-02]（場景並非全部取自 CWE Top 25 [P][E:vibe_risks-04]） |
| Perry et al. | 使用 AI 助手者寫出較不安全的程式，卻更相信自己的程式安全 [V][E:vibe_risks-06] |
| Veracode | 2025：45% 樣本未通過 [V][E:vibe_risks-07]；2026：平均約 56% 通過 [P][E:vibe_risks-11] |
| 常見誤引 | 「AI 程式碼的漏洞多 2.74 倍」其實出自 CodeRabbit，不是 Veracode；而且 2.74 倍只是 XSS 這一類的數字，CodeRabbit 整體約為 1.7 倍問題數 [V][E:vibe_risks-12] |
| 套件幻覺 | [V][E:vibe_risks-13]～[E:vibe_risks-16] |
| Benchmark | CyberSecEval [V][E:vibe_risks-18]、BaxBench [V][E:vibe_risks-20]、SeCodePLT [V][E:vibe_risks-22] |
| 事件 | Lovable CVE-2025-48757 [V][E:vibe_risks-23][E:vibe_risks-24]；Base44 [P][E:vibe_risks-25]；Escape.tech 掃描 [P][E:vibe_risks-26]；Replit [P][E:vibe_risks-27][V][E:vibe_risks-28] |
| **反例** | 沒有一手來源顯示 Tea（第一次）外洩由 vibe coding 造成；Tea 歸因於未遷移的舊系統（此為否定性主張，只對已查來源成立）[V][E:vibe_risks-30][E:vibe_risks-31] |

### 2.8 參考系統架構（[ledger](evidence/ledger.md#reference_systems)）
見 §3。

## 3. 參考專案一覽

| 專案 | 類別 | 本設計借鏡的部分 | 證據 |
|---|---|---|---|
| DARPA AIxCC 決賽系統（Atlantis、Buttercup、RoboDuck 等） | 程式分析與修補 CRS | ・Atlantis 以 ensemble 為先<br>・Buttercup 用確定性流程，只在工具不足處用 LLM<br>・準確度乘數懲罰錯誤提報（準確率 50% 時乘數 0.9375、40% 時 0.8704；錯誤的關聯會讓獎勵變成懲罰；公式只見於 SoK）<br>・SoK 的基準 agent：自動驗證通過後仍有語意錯誤 → 人審 | [V][E:reference_systems-02][單源][E:reference_systems-05][V][E:reference_systems-07] |
| Buttercup | CRS | 修補拆成專門 agent（根因、撰寫、脈絡、反思）；多供應商 | [V][E:reference_systems-03][E:reference_systems-04] |
| RoboDuck（Theori） | CRS | 兩階段誤報過濾；delta 模式 | [V][E:reference_systems-10][E:reference_systems-12] |
| OSS-CRS | CRS 執行平台 | 每個系統有 USD 預算（proxy 強制）；只透過檔案協作 | [V][E:reference_systems-13][E:reference_systems-14] |
| Team Atlanta patch ensemble（2026） | 研究（blog） | 從不同 agent／模型組合的 patch 中挑選，N＝3 | [P][E:reference_systems-15] |
| OSS-Fuzz-gen | fuzz harness 生成 | agent 管線化 | [V][E:reference_systems-16] |
| Microsoft PyRIT | LLM 紅隊框架 | Targets、Converters、Scorers 等元件 | [V][E:reference_systems-19][E:reference_systems-20] |
| NVIDIA garak | LLM 弱點掃描 | 設計上作為人工評估的一部分；不涵蓋系統層問題 | [V][E:reference_systems-21][E:reference_systems-22] |
| promptfoo | LLM 評測與紅隊 | plugins × strategies；誤報需校準 grader | [V][E:reference_systems-23][E:reference_systems-24] |
| OpenAI Codex Security（前 Aardvark） | 廠商 AI 安全審查 | 先建立 repo 威脅模型，只對 high-signal 的問題在沙箱中驗證，再建議修補 | [V][E:reference_systems-26] |
| Claude Code Security | 廠商 AI 安全審查 | 多階段自我驗證、信心分數、人工核准 | [V][E:reference_systems-27] |
| claude-code-security-review | GitHub Action | 分開的誤報過濾步驟；未針對 prompt injection 強化 | [V][E:reference_systems-28] |
| Google CodeMender | AI 修補 | critique agent＋多種程式分析；人審後才送上游 | [V][E:reference_systems-29] |
| Project Naptime | LLM 漏洞研究框架 | 獨立的 Controller 檢查成功條件；偏好可自動驗證的任務 | [V][E:reference_systems-30] |
| karpathy/llm-council | 多模型 | 匿名互評＋chairman 彙整 | [V][E:reference_systems-31] |
| PAL MCP Server | 多模型 MCP | consensus、codereview、secaudit 工具 | [V][E:reference_systems-32] |
| CodeAgent（EMNLP 2024） | 多 agent 程式審查 | 監督型 QA-Checker agent | [V][E:reference_systems-33] |
| VulTrial | 多 agent 漏洞偵測 | 法庭式角色 | [V][E:multi_llm_bias-30] |
| Refute-or-Promote | 對抗式驗證 | kill agent＋跨模型 critic | [V][E:whitebox-32] |
| IRIS | LLM＋CodeQL | LLM 推 taint spec | [V][E:whitebox-18] |
| STRIDE-GPT | LLM 威脅建模 | LiteLLM 多供應商；證據對到 file:line | [V][E:threat_modeling-14][E:threat_modeling-15] |
| pytm、Threagile、Threat Dragon、OTM | threat-model-as-code 與工具 | 格式與規則引擎 | [C][V][E:threat_modeling-09]～[E:threat_modeling-13] |
| Meta TestGen-LLM、ACH | LLM 測試生成 | 可執行濾網、mutation 導向 | [V][E:whitebox-34][E:whitebox-35] |
| BaxBench | 安全 benchmark | 黑箱＋白箱安全檢查、CWE 對應 | [V][E:vibe_risks-20][E:vibe_risks-21] |

> **研究範圍說明**：本次**沒有**把自主滲透測試 agent 框架列為參考，因為工具包的範圍是防禦性驗證，不是自主攻擊。

## 4. 撰寫文件時補做的查證

| ID | 內容 | 來源 | 狀態 |
|---|---|---|---|
| S-01 | OWASP Top 10 for LLM Applications 2026 發布日為 2026-08-03；十項依序為：<br>LLM01 Prompt Injection、LLM02 Sensitive Information Disclosure、LLM03 Excessive Agency、LLM04 Supply Chain、LLM05 Data and Model Poisoning、LLM06 Unbounded Consumption、LLM07 Misinformation、LLM08 Hidden Context Exposure、LLM09 Vector and Embedding Weaknesses、LLM10 Improper Output Handling | 發布日：OWASP 官方頁 <https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/><br>變動：Help Net Security <https://www.helpnetsecurity.com/2026/08/06/owasp-2026-llm-top-10-released/><br>完整清單：Aembit <https://aembit.io/blog/the-owasp-top-10-for-llm-applications-2026-what-changed-and-why-it-matters/>、BMSP <https://www.bmsp.tech/en/knowledge/owasp-top-10-llm-applications-2026/> | **[P]**：兩個獨立的二手來源一致，但官方 PDF 未直接讀取；另有搜尋摘要寫 8 月 4 日，以官方頁為準 |
| S-02 | arXiv 2603.25773：C. Zietsman，“The Specification as Quality Gate: Three Hypotheses on AI-Assisted Code Review”（2026-03-26，預印本）。同家族互審的錯誤會互相呼應；另有 4 個模型、3 個家族的跨家族實驗；主張先有規格與確定性驗證 | <https://arxiv.org/abs/2603.25773> | **[單源]**：單一作者、未經同儕審查 |
| S-03 | LangGraph 從條件邊回傳 `Send` 物件可以動態 fan-out；每個 state key 有獨立的 reducer，平行更新以 reducer 合併 | <https://docs.langchain.com/oss/python/langgraph/graph-api> | [V]（官方文件） |
| S-04 | CWE-639 的名稱：Authorization Bypass Through User-Controlled Key | <https://cwe.mitre.org/data/definitions/639.html> | [V] |
| S-05 | ASVS 5.0：8.2.1 功能層級存取（L1）、8.2.2 資料層級存取以緩解 IDOR／BOLA（L1）、8.2.3 欄位層級存取以緩解 BOPLA（L2） | <https://github.com/OWASP/ASVS/blob/master/5.0/en/0x17-V8-Authorization.md> | [V] |
| S-06 | WSTG-ATHZ-04：Testing for Insecure Direct Object References（v4.2）；建議以多個不同權限的測試使用者，檢查修改物件參照後授權是否仍被正確執行 | <https://github.com/OWASP/www-project-web-security-testing-guide/blob/master/v42/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References.md>（v4.2 原始檔，直接讀取）；owasp.org 上對應的 v42 頁面在 2026-09-23 的連結檢查中回傳 404（網站改版），搜尋結果仍列出該頁 | [V] |
| S-07 | 讀取時 CWE-639 頁面沒有列出 Related Attack Patterns；CAPEC-1 的 Related Weaknesses 也沒有 CWE-639 → 範例 A 不硬配 CAPEC | <https://cwe.mitre.org/data/definitions/639.html>、<https://capec.mitre.org/data/definitions/1.html> | **[P]**：網頁摘要工具可能漏讀，實作時用 CWE／CAPEC 的 XML 資料再確認 |
| S-08 | promptfoo 的遠端服務與關閉方式：<br>・`PROMPTFOO_DISABLE_REDTEAM_REMOTE_GENERATION=true`：改用本地生成，但**保留** SimulatedUser 的遠端生成；官方提醒品質可能下降<br>・`PROMPTFOO_DISABLE_REMOTE_GENERATION=true`：停用紅隊生成路徑中支援的遠端生成 fallback；但**不會**停用 telemetry、帳號或授權檢查、分享、Cloud 同步<br>・`PROMPTFOO_DISABLE_TELEMETRY=1`：關閉 telemetry<br>・沒有 API key 時，會把應用的 `purpose`、plugin 設定、送給目標的 prompt 與目標的回應（評分用）、使用者 email 送到 `api.promptfoo.app` | <https://www.promptfoo.dev/docs/red-team/configuration/><br><https://www.promptfoo.dev/docs/red-team/troubleshooting/data-handling/> | [V]（官方文件） |
| S-09 | GitHub issue #10970：iterative／crescendo 策略即使明確設定了 redteam provider，仍會使用遠端生成（觸發條件：未設 `OPENAI_API_KEY` 且未登入 cloud）；issue 中的暫行解法是 `PROMPTFOO_DISABLE_REMOTE_GENERATION` | <https://github.com/promptfoo/promptfoo/issues/10970> | **[單源]**：issue 存在且內容相符（事實查核代理確認）；仍只是使用者回報 |
| S-10 | 審查代理以 Hugging Face API 確認，自架模型 ID 應為 `nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B-BF16`（或 `-FP8`），不帶後綴的名稱不存在 | <https://huggingface.co/nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B-BF16> | [V]（與 E:providers-01 的來源一致） |

## 5. 研究缺口（未搜尋或未能確認）
- **多模型程式審查產品**：CodeRabbit、Qodo 等商用產品的多模型設計未查（WebSearch 額度用完）[E:reference_systems 研究限制]。
- **更多 AIxCC 隊伍的原始文件**：Shellphish、FuzzingBrain、42-b3yond-6ug、Lacrosse 未查。
- **2026 年更新的多 agent 漏洞偵測論文**：未完整搜尋。
- **Nemotron**：研究時查過，沒有找到 NVIDIA 託管端點的 ZDR 或 DPA；第三方託管（OpenRouter、Together、Fireworks 等）的條款未審；託管端點的 json_schema 支援未確認。
- **GPT-6**：是否有模型特定的 ZDR 限制，未確認。
- **獨立 benchmark**：沒有找到 STRIDE-GPT、Threat Dragon、pytm、Threagile 在真實 Web 應用上的人工標註比較；也沒有找到 ZAP、Nuclei、Schemathesis 在 vibe-coded 應用上的獨立評測。
- **廠商準確率**：Semgrep、Claude Security、Codex Security、CodeMender、Copilot Autofix 的數字都是廠商自報。
- **授權**：Hypothesis、fast-check、PyRIT、garak 的授權本次未查（promptfoo 為 MIT [V][E:reference_systems-25]）。

## 6. 計畫審查的修訂紀錄

初版計畫經 4 個審查代理審查後，主要修訂如下：

| 類別 | 修訂 |
|---|---|
| 證據忠實度 | ・AIxCC 的 37.7%／45.6% 是 SoK 的 Claude 3.7 基準 agent，不是決賽隊伍；SoK 列出的決賽隊 patch 準確度：Atlantis 83.8%、Buttercup 79.2%、Shellphish 100% [V][單源][E:reference_systems-07]<br>・SoK 關鍵發現改用原文措辭<br>・5G 威脅建模研究只分類了 6 個威脅<br>・「43% 會重複」改為「43% 在 10 次查詢中每次都出現」<br>・PR metadata 攻擊標明是預印本、且範本式攻擊無效<br>・IRIS 的比較對象是 CodeQL 單獨<br>・「找不到」改為「未找到（搜尋未窮盡）」<br>・補上所有 [P] 標記 |
| 前提挑戰 | 加入 Self-MoA 對照組（混用多家族不一定勝過單一最佳模型多次取樣） |
| 架構 | ・加入 W0.5 安全不變量規格＋G1（解決「oracle 沒有來源」）<br>・確定性叢集鍵<br>・切片同等性單位<br>・禁止跨家族 fallback 並處理缺票<br>・`tool_binding` 列舉<br>・LangGraph 節點冪等邊界<br>・Credential／Session Provider<br>・閘道背壓<br>・成本模型<br>・CI 兩條線<br>・人工關卡的簽章紀錄<br>・Commander 決策節點與覆蓋下限 |
| 安全 | ・ROE 改為機器可驗證（簽章、到期、目標所有權 token），並在第一個接觸網路的步驟就檢查<br>・產物驗證<br>・信任區分離（Z1–Z4）<br>・安全等級由程式碼計算<br>・每主機限速與自動停止條件<br>・資料等級 fail-closed<br>・promptfoo 雲端生成<br>・PII 偵測<br>・供應鏈延伸到受測應用與產生的測試<br>・法遵段落與授權登錄表 |
| 需求符合度 | ・加入需求對照表<br>・兩個完整範例（IDOR、LLM 工具濫用）<br>・LLM 功能的機率型判定<br>・白箱→黑箱的種子威脅交接<br>・「灰箱威脅建模＋黑箱執行」的名詞說明<br>・Nemotron 雲端只限評估與原型<br>・OWASP LLM Top 10 版本管理 |
