# 01 研究調查：查證方法、參考專案與文獻

> 研究日期：2026-09-23（v0.1）；2026-09-24（v0.2 補充研究，見 [§7](#7-v02-補充研究2026-09-24)）；2026-09-26（v0.3 補充查證，見 [§8](#8-v03-補充查證2026-09-26)）。範圍限定在**防禦性**的程式審查、測試生成、威脅建模與驗證測試；**刻意不研究**攻擊技術細節（例如 CAPEC／ATLAS 的執行流程）。標記說明見 [README](../README.md#標記說明)。

## v0.3 變更摘要

- **新增 §8 補充查證**（2026-09-26）：深度審查（[review-2026-09-26](evidence/review-2026-09-26.md)）需要的 10 條事實，逐條對照一手來源查證後併入帳本（全部已查證；帳本欄位 `merged_from` 為 `review-2026-09-26-NN`；其中 2 條是獨立事實查核時補查的）。帳本合計 **456** 條。（M-R2）
- **標記一致**（§1.2）：providers-52 同時標 [V] 與 [單源]：已查證，但來源只有 Anthropic 官方頁面。（N-11）

## v0.2 變更摘要

- **新增 §7 補充研究**（2026-09-24）：103 條新發現，已由獨立查核者逐條複查並併入證據帳本（已查證 86、部分查證 15、被推翻 2；帳本欄位 `merged_from` 保留暫存編號），文中依查核結果標 V／P／C。涵蓋：
  - 多模型程式審查產品（CodeRabbit、PR-Agent／Qodo、Copilot code review、Cursor Bugbot）
  - 其餘 AIxCC 隊伍（Shellphish、FuzzingBrain、42-b3yond-6ug），以及 SoK 已標為 USENIX Security 2026 接受
  - 2025–26 的 ensemble／辯論與評審偏誤論文，**包括反證**
  - 沙箱的 CVE 與獨立評估，取代 v0.1「只找到廠商自述」的說法
  - 授權事實，補齊 [06 §2.3](06-security-legal-limitations.md#23-授權登錄表)
  - D11 簽章與 D12 稽核鏈的密碼學與實務事實
- **時效性事實更新**（§2.2、§4）：
  - GPT-6 Luna 與 Sol 有相同的 Chat Completions 工具呼叫限制
  - Claude Haiku 4.5 最早可能在 2026-10-15 退役
  - OWASP LLM Top 10 2026 官方 PDF 已讀並經查核，S-01 升級為 [V]
  - WSTG v4.2 的可用網址
  - ATLAS 2026.09
- **§5 研究缺口**：每一項都列出負責的里程碑與具體行動；v0.1 的缺口中，已補的標為「已補」。
- **§3 參考專案**：新增 AIxCC 其他隊伍與商用多模型審查產品。

## 1. 查證方法

### 1.1 流程
1. **研究**：8 個主題各由一個研究代理以網路搜尋撰寫發現，每條都附來源與信心程度。
2. **獨立查核**：每個主題再由另一個查核代理，嘗試用**不同發布者**的來源確認每條發現；無法確認就標「未查證」，與證據衝突就標「推翻」並給出更正。
3. **計畫審查**：初版計畫交給 4 個審查代理，從證據忠實度、架構可行性、安全與範圍、需求符合度四個角度做對抗式審查，再依結果修訂（§6）。
4. **補做查證**：審查代理新帶入的事實，以及撰寫文件時需要的細節，另外上網查證（§4）。
5. **撰寫後查核**：文件完成後，再由獨立代理把每個事實陳述逐條比對證據帳本的**查核結果與更正**（不是原始主張）。

### 1.2 結果統計
- 證據帳本共 **456** 條發現（v0.1 的 321 條、v0.2 的 125 條、v0.3 的 10 條）：
  - 已查證 389 條（v0.1 273、v0.2 106、v0.3 10）
  - 部分查證 60 條（v0.1 43、v0.2 17）
  - 被推翻、已更正 7 條（v0.1 5、v0.2 2）
  - v0.2 的第 125 條是 providers-52（Claude Opus 4.8，U-11 的替代模型，2026-09-25 加入）；只以三個 Anthropic 官方頁面互相核對：已查證，但屬廠商來源，因此標 [V][單源]。
- 完整內容見 [evidence/ledger.md](evidence/ledger.md)（英文原文＋查核意見＋來源），機器可讀版見 [evidence/research-findings.json](evidence/research-findings.json)。
- **獨立性的限制**：不少條目只能以原始或廠商來源確認，例如「只查了 CrewAI 自己的文件」「只有 SoK 能確認」。審查代理以關鍵字比對估計，至少有 55 條屬於這類 [單源：審查代理估計]。文件中這類陳述另標 **[單源]**。
- **連結檢查**：2026-09-23 以 curl 檢查約 670 個外部 URL，結果見 [evidence/link-check-2026-09-23.md](evidence/link-check-2026-09-23.md)。
- **v0.2 新增**：v0.2 撰寫期間共 124 條新發現（本文件 §7 的 103 條，加上 04／05／08 與範例檔引用的 21 條），全部經獨立查核後併入帳本：已查證 105、部分查證 17、被推翻 2（reference_systems-51 FuzzingBrain 投票對象、reference_systems-54 Atlantis 授權，文中已依更正改寫）。帳本合計 **445** 條；之後因 U-11 再加入 providers-52，共 **446** 條（見上）。另重查既有的 reference_systems-04（不是新發現，不計入 124 條）：5／7 隊使用 LiteLLM 屬實，但該表在 arXiv HTML 版為 Table 1、PDF 版為 Table 2。
- **工具限制**：GitHub API 在 v0.1 研究環境中被擋（v0.2 時已可用 license API）；部分 PDF 與網站無法直接讀取（openai.com、Springer、ACM 回傳 403；X 回傳 402）；WebFetch 以摘要模型轉述，引文可能被改寫；部分主題用完了 WebSearch 額度（見 ledger 各主題的「研究限制」）。

### 1.3 7 條被推翻的主張與更正

| 證據 ID | 原主張 | 更正 |
|---|---|---|
| E:providers-22 | LiteLLM `hosted_vllm/` 會原樣傳遞 tools 與 response_format | tools 的 `strict` 與 `additionalProperties` 會被移除；response_format 看起來會傳遞 |
| E:whitebox-39 | EvoSuite v1.2.0 發布於 2024 | 實為 2021-09-16，且只支援到 Java 11；視為 2021 年後未維護 |
| E:threat_modeling-11 | pytm v1.4.0 發布於 2025-07 | 實為 2026-07-06；114 條威脅中 98 條引用 CAPEC、75 條引用 CWE |
| E:threat_modeling-52 | 威脅→CAPEC→CWE→ASVS→WSTG 每一環都能取自官方資料 | 多段沒有官方對照（見 [04 §1.1](04-threat-to-testcase.md#11-官方與非官方連結)） |
| E:reference_systems-37 | 所有參考系統都不只依賴 LLM 共識確認發現項 | 過度概括：Claude Code Security 的公告只提到 LLM 自我驗證＋人工核准；部分 AIxCC 隊伍只用 LLM 評審 SARIF |
| E:reference_systems-51（v0.2） | FuzzingBrain 以三家 LLM 中 2 家同意的投票做 patch 去重 | 該投票用於 **POV（crash 報告）**去重，不是 patch；其餘數字（第 4 名、28 個漏洞、修補 14 個）屬實（見 §7） |
| E:reference_systems-54（v0.2） | Atlantis 儲存庫為 MIT | LICENSE 檔寫 GPL-3.0，README 寫 MIT，兩者不一致；以 LICENSE 檔（GPL-3.0）為準 |

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
  - 2026-09-24 託管端點的模型 ID [V][E:providers-50]：
    - `nvidia/nemotron-nano-3-30b-a3b`（注意字序和其他 ID 不同）
    - `nvidia/nemotron-3-super-120b-a12b`
    - `nvidia/nemotron-3-ultra-550b-a55b`
    - `nvidia/nemotron-3.5-lightning-30b-a3b`
- **Claude**：
  - Fable 5.1、Opus 5.5、Sonnet 5 有 1M context，Haiku 4.5 為 200K [V][E:providers-23]。
  - 模型 ID 與最早退役日（2026-09-24 查詢）[V][E:providers-49]：
    - `claude-fable-5-1`：2027-09-01
    - `claude-opus-5-5`：2027-09-22
    - `claude-sonnet-5`：2027-06-30
    - `claude-haiku-4-5-20251001`：**2026-10-15**。範例設定已依使用者決定換成 Claude Opus 4.8（見 [06 §3](06-security-legal-limitations.md#3-做不到不承諾的事)、[08 §10](08-implementation-spec.md#10-尚未決定需使用者決定) U-11）。
    - `claude-opus-4-8`（legacy，仍為 Active）：2027-05-28；1M context，每百萬 token $5／$25（2026-09-25 查詢）[V][單源][E:providers-52]
  - structured outputs 已 GA，schema 有限制 [V][E:providers-24][E:providers-25]。
  - Opus 5.5 拒絕強制 tool_choice [V][E:providers-26]。
  - 資料保留與 ZDR [V][E:providers-27][E:providers-28][E:providers-29]。
- **OpenAI**：
  - GPT-6 Astra、Sol、Luna（2026-09）[P][E:providers-31]；structured outputs [V][E:providers-32]。
  - v0.2 重新查詢（2026-09-24）：
    - API ID 為 `gpt-6-astra`、`gpt-6-sol`、`gpt-6-luna`，changelog 日期與 providers-31 一致 [V][E:providers-46]。
    - **Luna 與 Sol 一樣**：Chat Completions 只有在 `reasoning_effort` 為 `none` 時才支援 function calling [P][E:providers-47]。
    - providers-31 的更正內容（Astra 的工具呼叫需要 Responses API）仍成立，狀態維持 [P]。
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
- **沙箱**：gVisor、Firecracker、E2B、Docker、Docker Sandboxes、sandbox-runtime [V][E:blackbox-34]～[E:blackbox-40]。v0.2 補上 CVE 紀錄與獨立的學術評估（見 §7.4）。

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
| 事件 | Lovable CVE-2025-48757（CVE 標為 disputed）[V][E:vibe_risks-23][E:vibe_risks-24]；Base44 [P][E:vibe_risks-25]；Escape.tech 掃描 [P][E:vibe_risks-26]；Replit [P][E:vibe_risks-27][V][E:vibe_risks-28] |
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
| **v0.2 新增** | | | |
| Shellphish ARTIPHISHELL（AIxCC 第 5） | CRS（MIT） | 53 個元件；以多個工具與 LLM 的加權投票排序候選；修補後再 fuzz 驗證 | [V][E:reference_systems-49][E:reference_systems-50] |
| FuzzingBrain（AIxCC 第 4） | CRS（Apache-2.0） | 跨三家 LLM 的階梯式 fallback；**POV（crash 報告）**去重採三家 LLM 中 2 家同意（patch 去重則用較保守的規則）；PoV 必須觸發 sanitizer | [C][E:reference_systems-51][E:reference_systems-52] |
| 42-b3yond-6ug BugBuster | CRS（GPL-3.0） | 釋出不完整，只作參考 | [V][E:reference_systems-53] |
| PR-Agent（Qodo 舊專案，捐給基金會中） | 開源 PR 審查（MIT） | 經 LiteLLM 支援多家廠商；多模型只用於 fallback、成本路由、自我反思 | [V][E:reference_systems-41][E:reference_systems-42] |
| Qodo code review | 商用 | 平行的專門 agent，再由 judge agent 合併、去重、過濾 | [V][E:reference_systems-43] |
| CodeRabbit | 商用 | 驗證 agent 與審查 agent 分開；自述採「production model mix」；新模型抓到**不同**的 bug，不是舊模型的超集 | [P][E:reference_systems-39][E:reference_systems-40] |
| GitHub Copilot code review | 商用 | 模型組合由廠商決定、使用者不能切換，可能用到組織未啟用的模型 | [V][E:reference_systems-44] |
| Cursor Bugbot | 商用 | 上線版：同一模型跑 8 次、打亂 diff 順序、多數決，再由驗證模型過濾（後改為 agentic 架構） | [P][E:reference_systems-45] |

> **研究範圍說明**：本次**沒有**把自主滲透測試 agent 框架列為參考，因為工具包的範圍是防禦性驗證，不是自主攻擊。

## 4. 撰寫文件時補做的查證

| ID | 內容 | 來源 | 狀態 |
|---|---|---|---|
| S-01 | OWASP Top 10 for LLM Applications 2026 發布日為 2026-08-03；十項依序為：<br>LLM01 Prompt Injection、LLM02 Sensitive Information Disclosure、LLM03 Excessive Agency、LLM04 Supply Chain、LLM05 Data and Model Poisoning、LLM06 Unbounded Consumption、LLM07 Misinformation、LLM08 Hidden Context Exposure、LLM09 Vector and Embedding Weaknesses、LLM10 Improper Output Handling | 發布日：OWASP 官方頁 <https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/><br>變動：Help Net Security <https://www.helpnetsecurity.com/2026/08/06/owasp-2026-llm-top-10-released/><br>完整清單：Aembit <https://aembit.io/blog/the-owasp-top-10-for-llm-applications-2026-what-changed-and-why-it-matters/>、BMSP <https://www.bmsp.tech/en/knowledge/owasp-top-10-llm-applications-2026/> | **[V]**（v0.2 升級）。<br>v0.1 為 [P]：兩個獨立的二手來源一致，但官方 PDF 未直接讀取；另有搜尋摘要寫 8 月 4 日，以官方頁為準。<br>**v0.2**：官方 PDF 已讀，十項 ID 與名稱完全一致 [V][E:threat_modeling-73]；官方資源頁的標題是「OWASP GenAI LLM Top 10 2026」[P][E:threat_modeling-72]；官方頁畫面顯示 8 月 3 日，但頁面 schema 的 datePublished 為 2026-08-04 [P][E:threat_modeling-72]。<br>PDF 封面寫「[Publication date to be set] August 4th, 2026」，官方頁寫 2026-08-03 [V][E:threat_modeling-74]。<br>`/llm-top-10/` 頁面仍顯示 2025 版 [V][E:threat_modeling-75]。<br>發布日以官方頁顯示的 2026-08-03 為準，並註記頁面 schema 的 datePublished 與 PDF 封面寫 8 月 4 日。 |
| S-02 | arXiv 2603.25773：C. Zietsman，“The Specification as Quality Gate: Three Hypotheses on AI-Assisted Code Review”（2026-03-26，預印本）。其中兩個實驗由 Claude 模型審查 Claude 生成的程式碼，錯誤會互相呼應而非抵銷；另有 4 個模型、3 個家族的跨家族實驗；主張先有規格與確定性驗證 | <https://arxiv.org/abs/2603.25773> | **[單源]**：單一作者、未經同儕審查 |
| S-03 | LangGraph 從條件邊回傳 `Send` 物件可以動態 fan-out；每個 state key 有獨立的 reducer，平行更新以 reducer 合併 | <https://docs.langchain.com/oss/python/langgraph/graph-api> | [V]（官方文件） |
| S-04 | CWE-639 的名稱：Authorization Bypass Through User-Controlled Key | <https://cwe.mitre.org/data/definitions/639.html> | [V] |
| S-05 | ASVS 5.0：8.2.1 功能層級存取（L1）、8.2.2 資料層級存取以緩解 IDOR／BOLA（L1）、8.2.3 欄位層級存取以緩解 BOPLA（L2） | <https://github.com/OWASP/ASVS/blob/master/5.0/en/0x17-V8-Authorization.md> | [V] |
| S-06 | WSTG-v42-ATHZ-04：Testing for Insecure Direct Object References（v4.2）；建議以多個不同權限的測試使用者，檢查修改物件參照後授權是否仍被正確執行 | <https://github.com/OWASP/www-project-web-security-testing-guide/blob/master/v42/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References.md>（v4.2 原始檔，直接讀取）；owasp.org 上對應的 v42 頁面在 2026-09-23 的連結檢查中回傳 404（網站改版），搜尋結果仍列出該頁。<br>**v0.2**：可用的網址格式為 `https://wstg.owasp.org/v4.2/…`；v5.0 仍在開發中 [V][E:threat_modeling-77] | [V] |
| S-07 | 讀取時 CWE-639 頁面沒有列出 Related Attack Patterns；CAPEC-1 的 Related Weaknesses 也沒有 CWE-639 → 範例 A 不硬配 CAPEC | <https://cwe.mitre.org/data/definitions/639.html>、<https://capec.mitre.org/data/definitions/1.html> | **[P]**：網頁摘要工具可能漏讀，實作時用 CWE／CAPEC 的 XML 資料再確認 |
| S-08 | promptfoo 的遠端服務與關閉方式：<br>・`PROMPTFOO_DISABLE_REDTEAM_REMOTE_GENERATION=true`：改用本地生成，但**保留** SimulatedUser 的遠端生成；官方提醒品質可能下降<br>・`PROMPTFOO_DISABLE_REMOTE_GENERATION=true`：停用紅隊生成路徑中支援的遠端生成 fallback；但**不會**停用 telemetry、帳號或授權檢查、分享、Cloud 同步<br>・`PROMPTFOO_DISABLE_TELEMETRY=1`：關閉 telemetry<br>・沒有 API key 時，會把應用的 `purpose`、plugin 設定、送給目標的 prompt 與目標的回應（評分用）、使用者 email 送到 `api.promptfoo.app` | <https://www.promptfoo.dev/docs/red-team/configuration/><br><https://www.promptfoo.dev/docs/red-team/troubleshooting/data-handling/> | [V]（官方文件） |
| S-09 | GitHub issue #10970：iterative／crescendo 策略即使明確設定了 redteam provider，仍會使用遠端生成（觸發條件：未設 `OPENAI_API_KEY` 且未登入 cloud）；issue 中的暫行解法是 `PROMPTFOO_DISABLE_REMOTE_GENERATION` | <https://github.com/promptfoo/promptfoo/issues/10970> | **[單源]**：issue 存在且內容相符（事實查核代理確認）；仍只是使用者回報 |
| S-10 | 審查代理以 Hugging Face API 確認，自架模型 ID 應為 `nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B-BF16`（或 `-FP8`），不帶後綴的名稱不存在 | <https://huggingface.co/nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B-BF16> | [V]（與 E:providers-01 的來源一致） |

## 5. 研究缺口（未搜尋或未能確認）

v0.2 為每個缺口指定負責里程碑與具體行動（[H]）。里程碑定義見 [07](07-roadmap.md)。「已補」表示 v0.2 已有新發現，並已經獨立查核併入證據帳本（狀態依各條標記）。

| # | 缺口 | v0.2 狀態 | 負責里程碑 | 具體行動與完成條件 |
|---|---|---|---|---|
| G-01 | 多模型程式審查產品的設計 | **已補**（部分）：CodeRabbit、Qodo、Copilot 都**不公開**各 agent 用哪家模型 [P][E:reference_systems-40][E:reference_systems-43][E:reference_systems-44] | —（研究結案） | 不再追查；廠商未公開的設計不作為設計依據 |
| G-02 | 其他 AIxCC 隊伍的原始文件 | **已補**：Shellphish、FuzzingBrain、42-b3yond-6ug（§7.2）。**仍缺 Lacrosse**（只有 SoK 描述它用 DSPy） | M2 | Lacrosse 的 repo／論文找到後補一條 finding；找不到就在 M2 的 Calibration 報告中註明 |
| G-03 | 2026 年的多 agent 漏洞偵測與評審偏誤論文 | **已補**（§7.3），多數為預印本 | M2 | Calibration Lab 第一版要量測自我偏好、同意偏誤（TNR）、提示敏感度（見 [05](05-bias-calibration.md)）；以實測結果取代文獻推論 |
| G-04 | Nemotron 可用於正式環境的託管路徑 | **仍缺**：v0.2 讀了 Trial Terms，確認沒有 ZDR，而且資料條款互相矛盾 [V][E:providers-42]；第三方託管條款未審 | M2（Z4 上線前） | C 級資料**只用自架**。若要用第三方託管，M2 前逐家審 DPA 與保留條款，結果寫進 `models.yaml` 的 `data_classes`；未審完的端點只給 P 級（公開或合成資料） |
| G-05 | Nemotron 託管端點的 json_schema 支援 | 仍缺 | M2 | M2 的 Gateway 整合測試對每個 Nemotron 端點跑 structured-output 測試集；不支援就走用戶端 Pydantic 驗證＋修復 |
| G-06 | GPT-6 是否有模型特定的 ZDR 例外 | **部分**：公開文件沒有找到 GPT-6 的 ZDR 排除 [V][E:providers-48]，但 OpenAI 保留對特定模型排除的權利 [V][E:providers-35] | M2（C 級資料送 OpenAI 前） | 由 engagement 的 app owner 向 OpenAI 取得書面確認，記在 `models.yaml`；確認前 GPT-6 只給 P 級 |
| G-07 | 黑箱工具（ZAP、Nuclei、Schemathesis）在 vibe-coded 應用上的獨立評測 | 仍缺 | M4 | M4 pilot：在 ≥3 個含已知漏洞的 vibe-coded 範例應用上，量測每個工具對 seed 漏洞的檢出率與誤報，報告附原始結果 |
| G-08 | 威脅建模工具（STRIDE-GPT、Threat Dragon、pytm、Threagile）的人工標註比較 | 仍缺 | M3 | M3 以範例應用建立人工標註的威脅清單，比較 B2 輸出與 pytm 規則輸出的 recall；不作工具排名，只用於 B2 設計 |
| G-09 | 廠商宣稱的準確率 | 仍缺；v0.2 新增的 CodeRabbit、Cursor 數字也是自報 [P][E:reference_systems-39][E:reference_systems-45] | M2 | 不引用為設計依據；Calibration Lab 以自建語料量測 |
| G-10 | Hypothesis、fast-check、PyRIT、garak 的授權 | **已補** [V][E:whitebox-47]～[E:reference_systems-56] | — | 見 [06 §2.3](06-security-legal-limitations.md#23-授權登錄表) |
| G-11 | 沙箱逃逸抵抗力的獨立評估 | **部分**：找到 CVE 紀錄與學術研究（§7.4），但**沒有找到 gVisor、Firecracker、Kata 的第三方安全稽核報告** | M1 | Z2 上線前固定 runsc／Firecracker 版本，訂閱 CVE；把 Z2 的逃逸測試列入 M1 自測（見 [06 §1.2](06-security-legal-limitations.md#12-受測程式碼造成的注入)） |
| G-12 | 法律問題（AGPL、NIM 用途、CodeQL CLI、上游 LLM 條款） | 事實已查，**解讀需法務** | M1–M5（依元件） | 見 [06 §2.3](06-security-legal-limitations.md#23-授權登錄表) 的法務閘門 |
| G-13 | 部分 OpenAI 條款只能經代理讀取（openai.com 回傳 403） | 仍缺 | M2 | 由人工以瀏覽器直接核對 Services Agreement 與 Usage Policies [V][E:providers-45] |

## 6. 修訂紀錄

### 6.1 計畫審查

初版計畫經 4 個審查代理審查後，主要修訂如下：

| 類別 | 修訂 |
|---|---|
| 證據忠實度 | ・AIxCC 的 37.7%／45.6% 是 SoK 的 Claude 3.7 基準 agent，不是決賽隊伍；SoK 列出的決賽隊 patch 準確度：Atlantis 83.8%、Buttercup 79.2%、Shellphish 100% [V][單源][E:reference_systems-07]<br>・SoK 關鍵發現改用原文措辭<br>・5G 威脅建模研究只分類了 6 個威脅<br>・「43% 會重複」改為「43% 在 10 次查詢中每次都出現」<br>・PR metadata 攻擊標明是預印本、且範本式攻擊無效<br>・IRIS 的比較對象是 CodeQL 單獨<br>・「找不到」改為「未找到（搜尋未窮盡）」<br>・補上所有 [P] 標記 |
| 前提挑戰 | 加入 Self-MoA 對照組（混用多家族不一定勝過單一最佳模型多次取樣） |
| 架構 | ・加入 W0.5 安全不變量規格＋G1（解決「oracle 沒有來源」）<br>・確定性叢集鍵<br>・切片同等性單位<br>・禁止跨家族 fallback 並處理缺票<br>・`tool_binding` 列舉<br>・LangGraph 節點冪等邊界<br>・Credential／Session Provider<br>・閘道背壓<br>・成本模型<br>・CI 兩條線<br>・人工關卡的簽章紀錄<br>・Commander 決策節點與覆蓋下限 |
| 安全 | ・ROE 改為機器可驗證（簽章、到期、目標所有權 token），並在第一個接觸網路的步驟就檢查<br>・產物驗證<br>・信任區分離（Z1–Z4）<br>・安全等級由程式碼計算<br>・每主機限速與自動停止條件<br>・資料等級 fail-closed<br>・promptfoo 雲端生成<br>・PII 偵測<br>・供應鏈延伸到受測應用與產生的測試<br>・法遵段落與授權登錄表 |
| 需求符合度 | ・加入需求對照表<br>・兩個完整範例（IDOR、LLM 工具濫用）<br>・LLM 功能的機率型判定<br>・白箱→黑箱的種子威脅交接<br>・「灰箱威脅建模＋黑箱執行」的名詞說明<br>・Nemotron 雲端只限評估與原型<br>・OWASP LLM Top 10 版本管理 |

### 6.2 文件審查

文件完成後，4 個獨立代理逐條比對證據帳本並檢查一致性（約 590 個事實陳述），主要修訂如下：

| 類別 | 修訂 |
|---|---|
| 事實 | ・ZAP 的 exit code 對應（FAIL、只有 WARN、執行失敗三種分開）<br>・promptfoo 的遠端服務與關閉方式（S-08、S-09）<br>・Anthropic／OpenAI 資料保留的細節<br>・vLLM 與 SGLang 參數的差異<br>・OWASP LLM06:2025 對應 2026 版的 LLM03<br>・WSTG 頁面改用 GitHub v4.2 原始檔<br>・對齊 V／P／C 標記、預印本與立場論文的限定詞 |
| 一致性 | ・裁決改為有序規則 R0–R8，新增 `UNCORROBORATED`；定義「合格票」<br>・驗證者家族不得出現在叢集的回報者中<br>・種子威脅改用叢集 ID，並納入已確認叢集<br>・CONFIRMED_EXECUTABLE 需另一家族確認解讀<br>・狀態機補上 G0a、切片節點、加派回圈、多個 S2 job、重新裁決；回饋改為後續執行 |
| 安全 | ・新增白箱前的委任設定驗章（G0a）<br>・所有權驗證改由 Z3 經 Scope Proxy<br>・Z3 以受限 relay 取得多輪 LLM 輸入<br>・TruffleHog 驗證使用第三方接觸白名單<br>・每個 job 的請求白名單由 Scope Proxy 強制（DELETE 只限 seed manifest）<br>・核准者金鑰改由 out-of-band 金鑰登錄管理<br>・發起者不得是自動化帳號 |
| 資料模型 | ・新增 engagement、testresult schema<br>・GateRecord 支援多位核准者<br>・ROE 新增 signatories、gate_approvers、test_roles、`tester_controlled` 目標<br>・驗證程式新增上述規則的檢查 |
| 範圍 | Binding 表補上 GraphQL（輸入驗證、欄位層級授權、查詢深度、introspection）；README 需求表補上追問的回答 |


### 6.3 v0.2 補充研究（2026-09-24）

- 依 v0.1 審查指出的缺口補做研究（§7）。
- 新發現先以暫存編號記錄，由獨立查核者確認後才併入帳本並標 V／P／C（v0.2 已全部完成；帳本欄位 `merged_from` 保留暫存編號）。
- 本輪沒有 WebSearch，只用 WebFetch、GitHub license API、PyPI／npm JSON API、arXiv 與 CVE API 讀取已知 URL，所以**搜尋並未窮盡**。

## 7. v0.2 補充研究（2026-09-24）

> 本節的發現都已經獨立查核，標記依查核結果為 V／P／C（P 與 C 的內文已依查核更正改寫）；原文、查核意見與來源見 [evidence/ledger.md](evidence/ledger.md)。本節只陳述事實；對設計的影響另標 [H]。

### 7.1 多模型程式審查產品

- **CodeRabbit**：
  - 自述在「production model mix」中測試 Opus 5.5。其 80 題 OSS benchmark 上 Standard 51/80、基準 49/80；Standard 多抓到 11 個、同時漏掉 9 個基準抓到的問題 [P][E:reference_systems-39]。
  - 架構文件列出 Review、Verification、Chat、Pre-Merge Checks、Finishing Touches 五種平行 agent，但沒有寫出任何模型或廠商 [P][E:reference_systems-40]。
- **PR-Agent**（Qodo 的舊專案，MIT，正捐給開源基金會）：
  - 經 LiteLLM 支援多家廠商 [V][E:reference_systems-41]。
  - 多模型的用途是 fallback、`model_weak` 成本路由、`model_reasoning` 自我反思；`[model_routing]` 預設關閉 [V][E:reference_systems-42]。
- **Qodo code review**：平行的專門 agent，之後由 judge agent 合併、去重、過濾低信心項；未寫出模型 [V][E:reference_systems-43]。
- **GitHub Copilot code review**：使用「carefully tuned mix of models」；不支援切換模型；可能使用組織未啟用的模型 [V][E:reference_systems-44]。
- **Cursor Bugbot**（blog〈Building a better Bugbot〉）：上線時（v1）的流程是 8 次平行審查、打亂 diff 順序、多數決，再由驗證模型過濾；自報 resolution rate 從 52% 升到 70% 以上；文中說之後已改為 agentic 架構 [P][E:reference_systems-45]。
- **對本設計的意義 [H]**：
  - 已公開的產品都用多模型或多次取樣，但**沒有一家公開以跨廠商來降低偏誤並量測效果**；這與 v0.1 的結論一致 [P][E:reference_systems-38]。
  - Bugbot 的「同模型多次＋順序擾動」正是 [05](05-bias-calibration.md) 的 Self-MoA 對照組該比的對象。
  - Copilot 的「可能用到未啟用的模型」提醒我們：若把商用審查服務當作 reviewer，無法保證資料只送往 engagement 允許的模型。所以這類服務不納入 Z1 的 reviewer 名冊。

### 7.2 AIxCC 其他隊伍

- **官方名次**（DARPA，2025-08-08）：Team Atlanta 第 1（400 萬美元）、Trail of Bits 第 2（300 萬美元）、Theori 第 3（150 萬美元）；7 個 CRS 都承諾以 OSI 授權釋出 [V][E:reference_systems-46]。
- **SoK 現況**：arXiv 2602.07666 v5 標示為 USENIX Security 2026 接受。完整分數：Atlanta 392.8、ToB 219.4、Theori 210.7、FuzzingBrain 153.7、Shellphish 135.9、42-b3yond-6ug 105.0、Lacrosse 9.6 [V][E:reference_systems-47]。
  - v0.1 標 [單源：SoK] 的條目，其來源已是經同儕審查的論文；**是否因此調整 [單源] 標記，由整合者決定**。
- **LLM 花費**：約 94% 花在 Anthropic 與 OpenAI；花費排名與最終分數高度相關 [V][E:reference_systems-48]。
- **Shellphish**：53 個元件；以多工具、多 LLM 的加權投票**排序**候選；以修補後 fuzz 驗證 patch [V][E:reference_systems-49]。repo 為 MIT，設定需要 OpenAI、Anthropic、Gemini 三家金鑰 [V][E:reference_systems-50]。
- **FuzzingBrain**：
  - 28 個漏洞（6 個 zero-day）、修補 14 個 [C][E:reference_systems-51]。
  - 跨 Claude、GPT、Gemini 的階梯式 fallback。
  - **POV（crash 報告）**去重由三家 LLM 各自判斷，2 家同意即視為重複；patch 的去重不用這個投票，而是較保守的規則式判斷 [C][E:reference_systems-51]。
  - PoV 必須觸發 sanitizer。
  - repo 為 Apache-2.0 [V][E:reference_systems-52]。
- **42-b3yond-6ug**：GPL-3.0，釋出的程式碼不完整 [V][E:reference_systems-53]。
- **授權**：Buttercup 為 AGPL-3.0；Atlantis 的 LICENSE 檔寫 GPL-3.0，但 README 寫 MIT，兩者不一致，以 LICENSE 檔（GPL-3.0）為準 [C][E:reference_systems-54]。借用程式碼前要看授權（[06 §2.3](06-security-legal-limitations.md#23-授權登錄表)）。
- **SoK Table 1 的 LiteLLM 標記**：研究代理讀取時對註腳的解讀不確定，可能與 v0.1「7 隊中 5 隊用 LiteLLM」[V][E:reference_systems-04] 的說法有出入。本輪**不作新主張**，由查核者對照原表。
- **對本設計的意義 [H]**：跨廠商投票在決賽隊伍中只用於**排序**（Shellphish）與 **POV 去重**（FuzzingBrain），發現項的確認仍靠可執行證據（sanitizer、PoV、fuzz）。這支持 [05](05-bias-calibration.md) 的原則：CONFIRMED_EXECUTABLE 高於任何 LLM 共識。

### 7.3 2025–26 的 ensemble、辯論與評審偏誤論文

| 論文 | 主要結果 | 狀態 | 證據 |
|---|---|---|---|
| ReasonVul（arXiv 2605.18153） | 三種推理模式的 agent 各自分析，再以結構化辯論解決衝突；PrimeVul pair-wise accuracy 40.00%、F1 72.52% | 預印本；單一模型家族 | [V][E:multi_llm_bias-40] |
| The Capability Paradox（arXiv 2605.17480） | 能力越強的 worker 越容易被操弄（ASR 18.4%→63.9%）；**異質 ensemble 驗證**把 ASR 從 52.8% 降到 2.0% | 預印本 | [P][E:multi_llm_bias-41] |
| The Cost of Consensus（arXiv 2605.00914） | 同質的 7–8B 模型辯論不如各自自我修正；從眾比例最高 85.5%；token 多用 2.1–3.4 倍 | 預印本；只有小模型 | [V][E:multi_llm_bias-42] |
| Beyond Consensus（arXiv 2510.11822） | 程式回饋評審的 TPR 約 96%、TNR 低於 25%（同意偏誤）；提出 minority-veto 作為緩解，另以迴歸式校正框架把最大絕對誤差降到 1.2%（約為 14 個 LLM 最佳 ensemble 的一半） | 預印本 | [P][E:multi_llm_bias-43] |
| Bias in the Loop（arXiv 2604.16790） | SE 任務的 LLM 評審對提示偏誤高度敏感，足以改變模型排名 | 預印本；摘要無數字 | [V][E:multi_llm_bias-44] |
| Preference Leakage（arXiv 2502.01534） | 評審偏好與自己相關（同模型、同家族、繼承關係）的學生模型 | ICLR 2026 | [V][E:multi_llm_bias-45] |
| Extreme Self-Preference（arXiv 2509.26464） | 模型偏好「被指定」的身分，而不是真實身分 | 預印本 | [V][E:multi_llm_bias-46] |
| **反證**：Self-Preference Is Weak or Absent（arXiv 2606.20093） | 在可驗證的指令遵循修改任務上，**未偵測到**自我偏好（−5.1 pp，95% CI [−12.9, +2.7]） | 預印本；7 頁、樣本小 | [V][E:multi_llm_bias-47] |

**對本設計的意義 [H]**：
- 支持的設計：驗證者用與回報者不同的家族（preference leakage）；匿名化、移除模型身分（extreme self-preference）；異質驗證者（capability paradox）。
- 需要修正的設計：
  - 簡單多數決會繼承評審的同意偏誤，所以校準時要單獨量測 TNR，並評估 minority-veto 規則（Beyond Consensus）。
  - 同質辯論不划算，不應作為預設（Cost of Consensus）。
- **反證的意義**：在可客觀驗證的任務上，自我偏好可能很小。所以 [05](05-bias-calibration.md) 不應**假設**偏誤存在，而要**量測**（G-03）。
- 以上除 ICLR 2026 一篇外都是預印本，**任何一篇都不能當作定論**。

### 7.4 沙箱：CVE 與獨立評估

v0.1 寫「只找到廠商自述」；v0.2 找到下列非廠商來源，但**仍沒有找到第三方安全稽核報告**。

| 沙箱 | 紀錄 | 證據 |
|---|---|---|
| gVisor | CVE-2018-19333：沙箱內記憶體覆寫，但紀錄寫明「not escape the sandbox」 | [V][E:blackbox-41] |
| gVisor | CVE-2025-2713：runsc 本地提權；CVE 紀錄只把 release-20250319.0 列為不受影響（修正 commit 的日期更早） | [P][E:blackbox-42] |
| gVisor | GitHub 沒有 security advisory，漏洞只能從 CVE／NVD 追蹤 | [V][E:blackbox-43] |
| gVisor、Firecracker | VEE '20 獨立研究：兩者執行的 host kernel 程式碼都明顯多於原生 Linux | [V][E:blackbox-44] |
| Firecracker | CVE-2019-18960：vsock 緩衝區溢位 | [V][E:blackbox-45] |
| Firecracker | CVE-2026-5747：guest 端可造成 virtio queue 以外的越界寫入（仍在 guest 記憶體內；要影響 host 程序記憶體需額外前提），**只在 `--enable-pci` 時**；1.14.4／1.15.1 修正 | [P][E:blackbox-46] |
| Firecracker | CVE-2026-1386：Jailer 跟隨 symlink，可覆寫 host 檔案；1.13.2／1.14.1 修正 | [V][E:blackbox-47] |
| Firecracker | 學術研究（arXiv 2311.15999）：對 Spectre、MDS 類攻擊「offers little protection」 | [V][E:blackbox-48] |
| Kata | CVE-2020-2023、CVE-2020-2026：可串成 guest→host 程式碼執行 | [P][E:blackbox-49][E:blackbox-50] |
| Kata | 2026 年 1–8 月有 10 個 advisory，其中 5 個 Critical，包括 VM 逃逸 | [V][E:blackbox-51][E:blackbox-52] |
| Kata | GHSA-fgm4-mv68-h344：Dragonball virtio-blk 的 guest→host 逃逸，4.0.0 修正；GitHub advisory 頁面列出 CVE-2026-93417；此編號截至 2026-09-24 尚未出現在 NVD，只見於 GitHub advisory | [V][E:blackbox-53] |
| runc（Docker 預設） | CVE-2019-5736、CVE-2024-21626、CVE-2025-31133：容器逃逸 | [V][E:blackbox-54]～[E:blackbox-56] |

**對本設計的意義 [H]**：
- microVM 與 gVisor 都有逃逸或越界寫入的歷史，而且多半在**主機端元件**（Jailer、virtiofsd、runtime）或**非預設設定**（`--enable-pci`）上。
- 所以 Z2 要：
  - 固定版本並追蹤 CVE
  - 使用預設的最小裝置設定
  - 主機端輔助程式也要沙箱化
  - 單一主機不混放不同 engagement 的工作（側通道）
- 詳見 [06 §1.4](06-security-legal-limitations.md#14-沙箱與網路)。

### 7.5 授權事實

逐項結果已寫進 [06 §2.3](06-security-legal-limitations.md#23-授權登錄表)。本輪新發現：
- **psycopg**：LangGraph 的 Postgres checkpointer 依賴 psycopg 3，而 psycopg 3.3.6 為 **LGPL-3.0-only** [V][E:orchestration-42]。
- **E2B**：repo 為 Apache-2.0，套件 metadata 為 MIT，兩者至今仍不一致；但**兩者都是寬鬆授權** [V][E:blackbox-57]。
- **CodeQL CLI**：CI／CD 中的自動分析只允許用於託管在 GitHub.com 的開源程式碼；其他情境（例如私有碼）需要 GitHub Advanced Security 授權 [P][E:whitebox-53]。
- **NVIDIA API Trial Terms**：資料條款前後矛盾，且沒有 ZDR [V][E:providers-41][E:providers-42]。

### 7.6 D11 簽章與 D12 稽核鏈的事實

**D11（簽章）**：

| 事實 | 證據 |
|---|---|
| Ed25519：公鑰 32 bytes、簽章 64 bytes、簽章是確定性的；RFC 8032 是 IRTF 的 Informational 文件 | [V][E:orchestration-43] |
| RFC 8785 JCS 是 Independent Submission 的 Informational RFC，**不是 IETF 標準**。規則：<br>・輸入限 I-JSON（不可重複鍵）<br>・數字限 IEEE 754 double<br>・鍵依 UTF-16 code unit 排序<br>・大整數建議改用字串 | [V][E:orchestration-44] |
| Python 實作：`rfc8785` 0.1.4（Trail of Bits，Apache-2.0，2024）；`jcs` 0.2.1（2022） | [V][E:orchestration-45] |
| `cryptography` 50.0.1 的 Ed25519 API：驗證失敗時丟出 `InvalidSignature` | [V][E:orchestration-46] |
| YAML 1.2 以成為 JSON 的嚴格超集為主要目標；其 JSON schema 在 failsafe schema（map、seq、str）之外加上 null、bool、int、float；mapping 的鍵必須唯一 | [P][E:orchestration-52] |
| **但 PyYAML 是 YAML 1.1 parser**，而且 issue #41（至今未關）指出 libyaml／PyYAML **會默默接受重複鍵** | [P][E:orchestration-53][E:orchestration-54] |
| 替代方案：<br>・OpenSSH `ssh-keygen -Y sign/verify`（8.1 起）有 namespace、`valid-after`／`valid-before`、撤銷檔<br>・minisign 沒有撤銷或到期機制<br>・cosign keyless 依賴線上的 Fulcio／Rekor | [V][E:orchestration-47]～[E:orchestration-49] |

**對 D11 的意義 [H]**：
- Ed25519＋JCS 的方案可行，但 YAML 的「JSON 相容子集」必須由**嚴格 loader** 強制：
  - 拒絕重複鍵、anchor／alias、自訂 tag
  - 關閉 YAML 1.1 的隱式型別（例如 `yes`／`no`、時間戳）
  - 整數限在 ±2^53 內
- 否則兩個 parser 可能對同一份 ROE 算出不同的 canonical bytes（或同一份 bytes 在不同 parser 中代表不同內容）。
- 已納入 [03 §6.1](03-system-architecture.md#61-金鑰登錄與驗章流程) 的嚴格 YAML 載入規則與 [08 §5.1](08-implementation-spec.md#51-檔案擁有者與驗證點)（`keys/yamlstrict.py`）。

**D12（稽核鏈）**：

| 事實 | 證據 |
|---|---|
| RFC 9162（CT v2，Experimental）：Merkle tree＋inclusion／consistency proof；明言 log 可能對不同客戶端呈現不一致的視圖 | [V][E:orchestration-50] |
| Crosby & Wallach（USENIX Security 2009）：tamper-evident log 依靠外部稽核者持有的先前承諾；hash chain 的證明大小與 log 長度成正比 | [V][E:orchestration-51] |

**對 D12 的意義 [H]**：
- 每個 run 一條 hash chain 的規模不大，線性驗證可以接受。
- 防竄改的關鍵在「錨點由誰保管」：寫進同一個 Postgres 只能防**意外**，不能防管理者（見 [06 §3](06-security-legal-limitations.md#3-做不到不承諾的事)）。

### 7.7 時效性事實（2026-09-24 重新查詢）

| 項目 | 結果 | 證據 |
|---|---|---|
| LangGraph | 1.2.12（2026-09-21）仍是最新版 | [V][E:orchestration-01] |
| GPT-6 | ID 與日期見 §2.2；Luna 的 Chat Completions 工具呼叫限制同 Sol | [P][E:providers-46][E:providers-47] |
| Claude | Haiku 4.5 最早 2026-10-15 退役 | [V][E:providers-49] |
| Nemotron | 託管 ID 見 §2.2；build.nvidia.com 頁面的授權與日期與 v0.1 一致 | [V][E:providers-50][E:providers-51] |
| OWASP LLM Top 10 2026 | 官方 PDF 已讀，十項 ID 一致，S-01 升級為 [V]；頁面標題與日期細節見 S-01 | [V][E:threat_modeling-73]～[E:threat_modeling-75]；[P][E:threat_modeling-72] |
| OWASP Agentic Top 10 2026 | 官方 PDF 的正式名稱：ASI02 為「Tool Misuse and Exploitation」、ASI05 為「Unexpected Code Execution (RCE)」 | [V][E:threat_modeling-76] |
| WSTG | v4.2 為穩定版、v5.0 開發中；網址見 S-06 | [V][E:threat_modeling-77] |
| MITRE ATLAS | 2026.09（2026-09-14）仍是最新版 | [V][E:threat_modeling-37] |

## 8. v0.3 補充查證（2026-09-26）

2026-09-26 的深度審查（[review-2026-09-26](evidence/review-2026-09-26.md)）指出，修正內容需要下列事實；最後兩條是修正完成後的獨立事實查核補查的。每一條都直接讀一手來源查證（官方專案頁、官方 schema 檔、官方文件、官方 PDF、PyPI metadata），全部標 [V]。

| 證據 ID | 內容 | 用在 |
|---|---|---|
| [E:blackbox-65] | OWASP API Security Top 10 2023 的 10 個條目；API3:2023 合併了 2019 年的 Excessive Data Exposure 與 Mass Assignment | [04 §4.3](04-threat-to-testcase.md#43-binding-表) 的分類 |
| [E:blackbox-66] | Schemathesis `ignored_auth` 只對 schema 宣告了認證的操作執行（401 或 403 算有強制）；`use_after_free` 在成功 DELETE 之後預期 404 | 04 binding 表、[08 §11.10](08-implementation-spec.md#1110-沒有-openapi-的應用) |
| [E:blackbox-67] | mitmproxy 12.2.3 在 PyPI 的授權 classifier 為 MIT | U-13 的候選（未選定） |
| [E:whitebox-56] | SARIF 2.1.0 官方 schema 中，`baselineState`、`kind`、`level`、`suppressions` 的列舉值，以及 `webRequest`、`partialFingerprints`、`logicalLocations` 等欄位 | [08 §11.16](08-implementation-spec.md#1116-sarif-輸出與報告回饋) |
| [E:whitebox-57] | presidio-analyzer 2.2.364 在 PyPI 的授權為 MIT；首頁連結指向 `data-privacy-stack/presidio` | PII 偵測器的候選（未選定） |
| [E:whitebox-58] | tree-sitter 的 Python binding 0.26.0 在 PyPI 的授權 classifier 為 MIT（各語言 grammar 另計） | W0 抽取器與 Slicer 的候選（未選定） |
| [E:threat_modeling-79] | OWASP LLM Top 10 2026 PDF 的版本界線：模型是應用中的元件時用 LLM 清單；模型成為能呼叫工具、帶記憶、造成下游後果的行動者時，改用 Agentic Top 10，並建議兩者搭配 | [04 §2.3](04-threat-to-testcase.md#23-owasp-llm-top-10-20252026-對照) |
| [E:threat_modeling-80] | 同一份 PDF 的附錄 A 把每個條目對應到 CWE 4.20（分主要與輔助），例如 LLM01→CWE-1427、LLM10→CWE-1426、CWE-116、CWE-79 | 叢集的 CWE 桶、威脅紀錄 |
| [E:whitebox-59] | SARIF 2.1.0 規格 §3.27.9–3.27.10：`level` 不是 `none` 時 `kind` 必須是 `fail`；`kind` 不是 `fail` 時 `level` 必須是 `none` | [08 §11.16](08-implementation-spec.md#1116-sarif-輸出與報告回饋) 的對應規則 |
| [E:threat_modeling-81] | WSTG v4.2 checklist 中 CLNT-04、CLNT-07、INPV-01、INPV-02、BUSL-08、BUSL-09、CONF-04、CONF-05 的名稱 | 04 binding 表新增的列 |

**限制**：
- PyPI 的授權欄位是發布者自填的 metadata。三個候選工具都要在採用前讀 repo 的 LICENSE（[06 §4](06-security-legal-limitations.md#4-開放的法務與查證項目)）。
- 本環境的 GitHub API 只對已附加的 repo 開放，所以這次沒有使用 GitHub license API。
- 附錄 A 是多欄表格，這次只讀了表中列出的幾列，沒有完整轉錄。
