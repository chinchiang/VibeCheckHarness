# 06 工具包自身的安全、法遵與授權、做不到的事

> 一個會讀不可信程式碼、呼叫多家 LLM、還會對網路送出測試請求的工具包，本身就是高風險的 agentic 系統。本文件把威脅建模套用在工具包自己身上，並列出法遵事項與做不到的事。標記說明見 [README](../README.md#標記說明)。

## 1. 工具包自身的安全

### 1.1 以 OWASP Agentic Top 10 檢視工具包

分類依 OWASP Top 10 for Agentic Applications 2026 [V][E:threat_modeling-32]。

| ID | 對工具包的威脅 | 緩解措施（程式碼強制） |
|---|---|---|
| ASI01 Agent Goal Hijack | 受測 repo 的註解、README、PR metadata 內嵌文字，影響 reviewer、Commander、Test Designer 的判斷 | 指揮官只讀確定性 inventory；覆蓋下限不可減；reviewer 系統提示區分指令與資料；發現項必須通過片段比對；跨家族驗證 |
| ASI02 Tool Misuse | 產生的 ZAP、Playwright、promptfoo 設定被引導去打 ROE 以外的主機，或開啟危險模式 | 目標只能寫 ROE 目標 ID；執行前以確定性方法抽取所有 host、URL、method、旗標並比對；安全等級由程式碼計算；G4 綁定 hash |
| ASI03 Identity & Privilege Abuse | agent 持有過多憑證；工具包在沒有授權的情況下處理程式碼 | LLM 金鑰只在 Gateway；測試帳號只在 Z3 secret store、永不進 LLM context；reviewer 無 shell、無網路；G0a 委任設定驗章前，任何程式碼都不送往 LLM、不在 Z2 執行 |
| ASI04 Agentic Supply Chain | 工具包依賴的套件或掃描器被植入惡意程式 | 鎖版本＋hash；Actions 鎖 SHA；cosign 驗證；掃描器在沒有 CI secrets 的環境執行（見 §1.5） |
| ASI05 Unexpected Code Execution | 建置目標應用、安裝其相依、執行 LLM 產生的測試時，執行了不可信程式碼 | 一律在 Z2（gVisor 或 microVM）；沒有金鑰、沒有 LLM 出站、沒有目標出站；預設關閉 lifecycle scripts |
| ASI06 Memory & Context Poisoning | 被污染的中間產物（例如 LLM 摘要）在後續步驟被當成事實 | Blackboard 只存型別化 artifact，並附來源（哪個 agent、哪個模型、哪個輸入 hash）；LLM 摘要不作為規劃輸入 |
| ASI07 Insecure Inter-Agent Communication | agent 之間互相傳遞指令 | agent 不直接對話；只透過 Blackboard，且每個 artifact 都經 schema 驗證 |
| ASI08 Cascading Failures | 一個錯誤裁決連鎖影響下游測試與報告 | quorum；多樣性降低時封頂；人工關卡；每個階段的完成條件 |
| ASI09 Human-Agent Trust Exploitation | 人在關卡上「照單全收」LLM 的敘事 | 關卡顯示證據（file:line、片段、工具結果），不只是敘事；可部分核准；Reporter 不能改裁決；定期抽查已核准項目 |
| ASI10 Rogue Agents | 某個 agent 行為超出角色 | Policy Engine 白名單；最小權限；所有呼叫都寫入 audit |

### 1.2 受測程式碼造成的注入
- Anthropic 的 claude-code-security-review README 明言：該工具**未針對 prompt injection 強化**，只應審查可信的 PR [V][E:whitebox-20]。
- 一篇 2026 預印本：經 LLM 最佳化的 PR metadata 框架攻擊，讓 Claude Code 與 CodeRabbit 的安全審查管線在 33 個 CVE 中漏判 32 個；範本式攻擊無效 [V：預印本][E:whitebox-29]。
- **結論**：無法完全防止，只能隔離與降低（[§3](#3-做不到不承諾的事) 第 11 條）。

### 1.3 秘密與資料
- **路徑黑名單**：`.env*`、金鑰與憑證檔、auth-state 目錄（例如 Playwright 的 `playwright/.auth`）、CI secrets 檔，一律不進切片。Playwright 提醒 state 檔含敏感 cookie 與 header [V][E:blackbox-21]。
- **雙層遮罩**：先用掃描結果遮罩，再以 pattern＋entropy 遮罩。
- **TruffleHog 驗證**：有 700 多個 detector 會拿找到的憑證去供應商 API 驗證（數量只見於廠商 README）[V][單源][E:whitebox-10]，等於和使用者不擁有的系統互動。→ 預設關閉；要開就寫進 ROE，列出供應商，從 Z3 發出並記錄。建議直接輪替外洩的憑證。
- **資料等級採 fail-closed**，送往 LLM 的端點與參數受白名單限制（[03 §8.4](03-system-architecture.md#84-資料治理)）。
- **PII**：B4 前抽樣檢查 staging 回應；一旦偵測到個資就觸發停止條件，B5 改用自架模型。
- **Audit Log 與 DB 快照**：加密、與原始碼同等級、設保留期限、限制存取、遮罩 secrets。
- **重現證據**：只保存「對 ROE 目標 ID 的失敗安全斷言」；不建立通用 payload 庫；以 C 級權限保存。

### 1.4 沙箱與網路
- 信任區 Z1–Z4 與 Scope Proxy：見 [03 §2](03-system-architecture.md#2-部署與信任區)。
- Z3 沒有 LLM 金鑰；多輪 LLM 測試經 Z1 的受限 relay 產生下一輪輸入（只允許 ROE 指定的模型、有花費上限、全程稽核）。
- 所有權驗證由 Z3 經 Scope Proxy 發出，Z1 不直接連目標。
- TruffleHog 驗證使用另一份「第三方接觸」白名單，只含 ROE 列出的供應商，預設為空。
- **最低隔離要求**：不可信程式碼至少要 gVisor 或 microVM；絕不掛載 Docker socket [V][E:blackbox-38]。
- gVisor 的限制：相容性降低、每次 syscall 的額外負擔較高，而且不是每個 syscall 或 `/proc`、`/sys` 檔都有實作 [V][E:blackbox-34]。
- Firecracker 的整體安全仍取決於妥善設定的 Linux 主機 [V][E:blackbox-35]。
- E2B 的自架包 E2B Embed 自稱是「評估用，不是正式部署模式」[V][E:blackbox-37]。
- **各沙箱的逃逸抵抗力，本研究只找到廠商自述，未找到獨立評估（搜尋未窮盡）**。

### 1.5 供應鏈
- **工具包自己**：
  - 所有依賴鎖版本＋hash，並產出 SBOM。
  - GitHub Actions 鎖 commit SHA；binary 用 cosign 驗證。
  - Trivy 在 2026-03-19 發布管道遭入侵（CVE-2026-33634）：v0.69.4 binary、以及 v0.69.5／v0.69.6 Docker image、trivy-action < 0.35.0、setup-trivy < 0.2.6 帶有竊密程式 [V][E:whitebox-13]。
  - LiteLLM 1.82.7／1.82.8 同樣遭入侵 [V][E:orchestration-31]。
- **受測應用**：
  - 相依套件在 Z2 經鏡像安裝，預設關閉 lifecycle scripts，且要先通過 W1 的存在性與發布時間檢查（對應套件幻覺 [V][E:vibe_risks-13][E:vibe_risks-15] 與 slopsquatting [V][E:vibe_risks-16]）。
- **產生的測試**：只能 import 鎖定、預先核准的相依；執行時不允許從網路安裝套件。

### 1.6 人工關卡的完整性
- 核准是**簽章紀錄**，綁定產物 hash；Policy Engine 驗的是紀錄，不是 checkpoint（[03 §6](03-system-architecture.md#6-人工關卡服務)）。
- **金鑰信任根**：核准者公鑰登錄在組織的金鑰登錄中（out-of-band，含登錄、輪替、撤銷）；ROE 與委任設定只能引用登錄中的指紋，不能自行宣告可信金鑰。
- G5 的核准者不能是發起者；發起者必須記錄為啟動執行或核准 G4 的人，不能是自動化帳號。
- 限制 checkpoint 與 audit 儲存庫的存取權。Microsoft Agent Framework 也警告不要從不可信來源載入 checkpoint [V][E:orchestration-09]。

## 2. 法遵與授權

### 2.1 授權範圍
- **擁有程式碼≠擁有基礎設施**。vibe-coded 應用常架在第三方平台（BaaS、PaaS、託管 DB、CDN）上。需要基礎設施擁有者的書面授權，並確認平台的安全測試政策。
  - CVE-2025-48757 被標記為 disputed，Lovable 主張資料保護是客戶的責任 [V][E:vibe_risks-23]，可見平台與使用者的責任劃分並不單純。
- **staging 也會碰到第三方**：email、SMS、金流、LLM API 等整合必須在 sandbox／test 模式，並列入 ROE，否則在出站層封鎖。
- **LLM 供應商條款可能限制測試**。例如 NVIDIA API Trial Terms 第 4.10 條禁止未經書面授權測試其 API 服務本身的安全性 [V][E:providers-10]。受測應用的上游 LLM 供應商條款要由使用者確認。
- **ZAP 官方文件**：主動掃描只應該用在你有權限測試的應用上 [V][E:blackbox-06]。

### 2.2 資料、個資與跨境
- 把原始碼與測試資料送到境外的 LLM 供應商，可能涉及資料保護與跨境傳輸義務。
- 使用前，應由法律顧問檢視當地的電腦濫用法規、個資法規、跨境傳輸規定。
- **本工具包不會讓任何使用行為變得合法**。本文件只提供一般性提醒，不是法律意見。

### 2.3 授權登錄表

實作時放在 repo 中，並以 CI 檢查。下表列出本次研究查得的授權；「待查」表示本次未查證。

| 元件 | 授權 | 義務／風險 | 本設計的用法 |
|---|---|---|---|
| LangGraph | MIT [V][E:orchestration-01] | — | 核心 |
| LiteLLM | MIT core；企業功能另有商業授權 [V][E:orchestration-29] | 供應鏈事件，需鎖版本 | 核心 |
| Opengrep | LGPL-2.1 [V][E:whitebox-06] | 修改並散布時的 LGPL 義務 | W1 |
| Semgrep CE | 引擎 LGPL-2.1；官方規則採 Semgrep Rules License v1.0（非開源）[V][E:whitebox-04] | 規則使用限制 | W1（選用） |
| CodeQL CLI | 僅開源專案與學術研究可免費使用 [V][E:whitebox-07] | 私有商業碼需購買 GitHub Code Security | 選用 |
| Bandit | Apache-2.0 [V][E:whitebox-08] | — | W1 |
| Betterleaks | MIT [P][E:whitebox-09] | — | W1 |
| TruffleHog | AGPL-3.0 [V][E:whitebox-10] | AGPL（網路服務提供時的義務） | W1 |
| OSV-Scanner | Apache-2.0 [V][E:whitebox-11] | — | W1 |
| Syft、Grype | Apache-2.0 [V][E:whitebox-14] | — | W0、W1 |
| Trivy | Apache-2.0 [V][E:whitebox-13] | 供應鏈事件，需鎖版本 | 選用 |
| mutmut／Stryker | BSD-3／Apache-2.0 [V][E:whitebox-45] | mutmut 需要 fork()，Windows 要用 WSL | W4 |
| Pynguin | MIT（v0.30.0 起）[V][E:whitebox-38] | 會執行受測模組 | 選用（Z2） |
| Qodo Cover | AGPL-3.0，已停止維護 [V][E:whitebox-37] | — | **不採用** |
| Vulnhuntr | AGPL-3.0，僅 Python [V][E:whitebox-19] | — | 參考 |
| ZAP | Apache-2.0 [V][E:blackbox-01] | — | B1、B4 |
| Nuclei、nuclei-templates | MIT [V][E:blackbox-09][E:blackbox-12] | — | B4（只跑自簽章模板） |
| Schemathesis | MIT [V][E:blackbox-13] | — | B4 |
| RESTler | MIT [V][E:blackbox-16] | fuzz 模式可能造成中斷；維護活躍度低 [V][E:blackbox-17] | 選用（S2／拋棄式環境） |
| EvoMaster | LGPL-3.0 [V][E:blackbox-18] | LGPL 義務 | 選用 |
| Playwright、@playwright/mcp | Apache-2.0 [V][E:blackbox-21][E:blackbox-24] | — | B1、B4 |
| k6 | AGPL-3.0 [V][E:blackbox-25] | AGPL | B4（限流驗證） |
| pytm | MIT [V：該條只有日期與數字被更正][E:threat_modeling-11] | — | B2 匯出 |
| Threagile | MIT [V][E:threat_modeling-12] | — | 參考 |
| OWASP Threat Dragon | Apache-2.0 [V][E:threat_modeling-09] | — | 視覺化（選用） |
| STRIDE-GPT | MIT [V][E:threat_modeling-14] | — | 參考 |
| gVisor、Firecracker | Apache-2.0 [V][E:blackbox-34][E:blackbox-35] | — | Z2、Z3 |
| E2B | repo 的 LICENSE 為 Apache-2.0，SDK metadata 寫 MIT，**不一致** [V][E:blackbox-36] | 需釐清 | 選用 |
| sandbox-runtime | Apache-2.0（research preview）[V][E:blackbox-40] | — | 選用 |
| Claude Agent SDK | 套件為 MIT，但使用受 Anthropic Commercial Terms 規範 [V][E:orchestration-19] | — | 不作核心 |
| Nemotron 3 Nano／Super | NVIDIA Nemotron Open Model License（可商用、需標示來源；提起專利或著作權訴訟即終止授權）[V][E:providers-06] | 標示來源 | Z4 |
| Nemotron 3 Ultra、3.5 Lightning | OpenMDW-1.1 [V][E:providers-07] | 提起專利訴訟者的專利權利終止；對輸出不設限制 | Z4 |
| Nemotron Nano 2、Llama-Nemotron | 舊版 NVIDIA Open Model License：**繞過或規避安全護欄會自動終止權利**；Llama-Nemotron 另受 Llama 社群授權約束 [V][E:providers-08] | **工具包絕不移除或繞過模型護欄** | 不優先 |
| NIM 容器 | NVIDIA Software License Agreement＋Product-Specific Terms [P][E:providers-11]；免費授權限研究、開發、測試（≤16 GPU），正式用途需 NVIDIA AI Enterprise（依用途而非 GPU 數定義）[P][E:providers-12] | **需法務確認**本工具包的使用是否屬於「測試」用途 | 選用 |
| NVIDIA API（build.nvidia.com） | Trial Terms：僅供試用、禁止機密資訊、禁止正式用途 [V][E:providers-10] | 第 4.10 條：未經書面授權不得測試其 API 服務本身的安全性；NVIDIA 會以使用者與生成內容改善其產品與 AI 模型 | 只用於評估與原型 |
| gpt-oss-120b | Apache-2.0 [V][E:providers-37] | 另有 usage policy 檔適用 | Z4（選用；MXFP4 可放入單張 80GB GPU） |
| Docker Sandboxes | sbx CLI 可免費商用；集中管理的網路、檔案系統、MCP 政策需付費訂閱 [V][單源：Docker 自家來源][E:blackbox-39] | — | Z2（選用） |
| promptfoo | MIT（已被 OpenAI 收購，宣稱維持開源）[V][E:reference_systems-25] | 預設會把部分資料送到其雲端（[03 §7.5](03-system-architecture.md#75-llm-功能測試的額外控制)） | B4（LLM 功能測試，關閉遠端生成） |
| Hypothesis、fast-check、PyRIT、garak | 待查 | — | 實作前補查 |

## 3. 做不到／不承諾的事

| # | 做不到的事 | 原因（證據） | 替代做法 |
|---|---|---|---|
| 1 | **無法消除模型偏誤**，只能降低與量測；也可能打不贏「單一最佳模型多次取樣」 | 錯誤相關跨供應商存在 [V][E:multi_llm_bias-01]；Self-MoA 勝過混合 MoA [V][E:multi_llm_bias-19]；沒有研究量測過 Claude／GPT／Nemotron 在此任務的錯誤相關 [P][E:multi_llm_bias-38] | Calibration Lab 用 Self-MoA 對照組實測（[05 §5](05-bias-calibration.md#5-calibration--bias-lab)） |
| 2 | **無法保證找到所有漏洞** | LLM 威脅建模準確度有限（兩篇同一研究群的論文，其中一篇只分類 6 個威脅）[V][E:threat_modeling-20][E:threat_modeling-21]；LLM 程式審查的效果高度依賴底層模型，常見 benchmark 又會高估效能 [V][E:whitebox-33][E:multi_llm_bias-25]；SoK 基準 agent 通過自動檢查的 patch 仍有 37.7%／45.6% 語意錯誤 [V][單源：SoK][E:reference_systems-07] | 多層：確定性工具＋多家族＋可執行測試＋人工關卡 |
| 3 | **雲端 Nemotron（build.nvidia.com）不能處理機密碼或用於正式用途** | Trial Terms [V][E:providers-10]；未找到 ZDR 或 DPA；本次沒有研究到可用於正式環境的 Nemotron 雲端路徑 | 機密碼用自架 Nemotron；雲端只用於評估、原型、公開碼 |
| 4 | **私有碼的三家族多樣性有代價** | 自架多半只跑得動 Nano 或 Lightning（約 3–3.5B active；Super 需要 8×H100）[V][E:providers-13]；校準後權重可能很低；沒有 GPU 時只剩兩家族 | C 級資料不能送到 OpenAI API 時，以自架 gpt-oss-120b 保住 openai 家族（它與 GPT 同家族，不會增加家族數；需要單張 80GB GPU）[V][E:providers-37]；多樣性不足時裁決封頂 `LIKELY` |
| 5 | **不能只用 Claude Agent SDK 當多廠商指揮框架** | 不支援路由到非 Claude 模型 [V][E:orchestration-21] | LangGraph＋LiteLLM |
| 6 | **威脅→CAPEC→CWE→ASVS 5.0→WSTG 無法全自動、全官方對照** | 多段沒有官方對照 [C][E:threat_modeling-52]；ASVS 5.0 已移除 CWE 對照 [V][E:threat_modeling-42] | 人審對照表，每條連結標 provenance |
| 7 | **沒有人確認的安全不變量規格（G1），就無法判斷商業邏輯與授權意圖** | LLM 測試傾向記錄實際行為 [V][E:whitebox-43] | W0.5＋G1 |
| 8 | **LLM 產生的 oracle 不可信**；程式本身有 bug 時，覆蓋率與變異分數不可靠 | [V][E:whitebox-43][E:whitebox-44] | oracle 只引用 G1 已簽核條目 |
| 9 | **LLM 功能的漏洞只能以機率陳述**（n 次中 k 次），無法「重播一次就確認」 | LLM 輸出不確定 [P][E:multi_llm_bias-26]；LLM 評審有明顯隨機性 [V][E:multi_llm_bias-11]；garak 的 detector 表現不穩定 [V][E:reference_systems-22] | n 次試驗＋確定性 oracle＋信賴區間 |
| 10 | **不做 exploit 開發、不測正式環境或第三方系統、不做 S3 破壞性測試**；staging **不做效能容量評估** | 範圍界線；Grafana：QA 環境不適合評估效能與擴充性 [V][E:blackbox-28] | 只做限流與資源上限的驗證 |
| 11 | **無法完全防止受測程式碼對 agent 的 prompt injection** | [V][E:whitebox-20][V：預印本][E:whitebox-29] | 隔離、最小權限、證據接地、覆蓋下限、產物驗證 |
| 12 | **不是全自動**：G0a、G0b 的事先簽署，加上 G1–G5 五種人工關卡與對照表審查 | LLM 準確度限制；SoK 人工審 patch 花兩人週 [V][單源：SoK][E:reference_systems-07] | 人力成本在 pilot 中量測；CI 分兩條線 |
| 13 | Nemotron 託管端點的結構化輸出**未確認**；NIM 2.x **只有部分查證** | [P][E:providers-18] | 一律用 Pydantic 在用戶端驗證 |
| 14 | **廠商宣稱的準確率，本研究都沒有找到獨立驗證**（Semgrep AI triage、Claude Security、Codex Security、Copilot Autofix 等） | 研究限制（ledger whitebox 主題） | 以 Calibration Lab 自測；文件中一律標「廠商宣稱」 |
| 15 | **行動 App 不在本版範圍**；模型 ID 與版本變動快（例如 GPT-6 Sol 2026-09-22 才發布 [P][E:providers-31]）；OWASP LLM Top 10 2026 的官方 PDF 尚未核對 [P][S-01] | — | 實作時重新查證；分類版本寫在每筆威脅裡 |

## 4. 開放的法務與查證項目

| 項目 | 狀態 | 下一步 |
|---|---|---|
| NIM 在本工具包中的使用是否屬於「開發／測試」用途 | 未確認 | 法務確認 |
| AGPL 元件（TruffleHog、k6）以服務形式提供時的義務 | 未分析 | 法務確認 |
| Semgrep 官方規則授權、CodeQL 授權 | 已查得條款 | 依使用情境決定是否採用 |
| E2B 授權不一致 | 未解決 | 詢問上游或不採用 |
| 可用於正式環境的 Nemotron 雲端路徑 | 查過但沒有找到 NVIDIA 託管端點的 ZDR 或 DPA；第三方託管的條款未審 | 補做研究 |
| Nemotron 託管端點的 json_schema 支援 | 未確認 | 實測 |
| OWASP LLM Top 10 2026 官方 PDF | 未直接讀取 | 下載核對後切換預設版本 |
| promptfoo 部分策略會繞過本地生成的使用者回報 | 單源：issue 存在且內容相符 [S-09] | 上線前以出站紀錄實測 |
| Hypothesis、fast-check、PyRIT、garak 的授權 | 未查 | 實作前補查 |
| GPT-6 系列在 ZDR 下是否有模型特定限制 | 未確認；OpenAI 只保留可對特定客戶讓特定模型不適用 ZDR 的權利 [V][E:providers-35] | 洽 OpenAI |
