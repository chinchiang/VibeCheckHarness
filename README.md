# VibeCheck Harness（暫定名）— Multi-Agent Vibe Coding 測試工具包：方法論與系統架構

> **狀態**：設計文件（v0.1，2026-09-23）。尚未實作。
> **目的**：替 vibe-coded（由 AI 生成、開發者未必逐行讀過）的 Web／API 應用與含 LLM／Agent 功能的應用，建立一套**防禦性**、**先白箱後黑箱**的多代理測試方法與系統架構。
> **語言**：正體中文；證據原文保留英文（見 [`docs/evidence/ledger.md`](docs/evidence/ledger.md)）。

## 一句話說明

一個 **Harness**（程式碼寫成的流程控制器）加上一個 **指揮官 Agent**（LLM）調度多個子代理：
- **白箱階段**：每個子代理可以綁不同廠商的 LLM（Claude／ChatGPT／Nemotron…），彼此獨立審查程式碼，再由**不同家族**的模型交叉驗證，以降低單一模型的偏誤；
- **黑箱階段**：**一定先做威脅建模**，人工簽核後，才依威脅模型推導測試案例，再在隔離環境中對 **staging** 執行。

## 範圍與界線

| 會做 | 不會做 |
|---|---|
| 測試**使用者自己擁有**、且基礎設施擁有者**書面授權**的程式碼與 staging 環境 | 測試正式環境、第三方系統、或無法證明所有權的主機 |
| 以測試案例證明「安全需求沒有被滿足」（失敗的安全斷言） | exploit 開發、通用攻擊 payload 庫、破壞性測試（S3） |
| 以程式碼強制 ROE（交戰規則）、範圍白名單、限速、人工關卡 | 只靠文件宣示的「請勿濫用」 |

## 需求對照表

| 需求 | 做法 | 文件位置 | 誠實的限制 |
|---|---|---|---|
| 一個主 AI agent 當 harness／指揮官，負責調度其他 agents | Harness＝Run Controller（程式碼：順序、並行、重試、限速、checkpoint）＋ Commander Agent（LLM，在 5 個決策節點規劃與加派）；Policy Engine 以程式碼強制範圍與關卡 | [03 §4](docs/03-system-architecture.md#4-harness指揮官如何滿足需求) | 指揮官刻意不能判定漏洞真偽、不能擴大範圍、不能跳過關卡 |
| 白箱每個 agent 可接不同 LLM（Claude、Nemotron、ChatGPT 等）以減少模型偏誤 | `agents.yaml` 逐一綁模型；LiteLLM 接 Anthropic／OpenAI／NVIDIA（雲端＋自架）；規則：驗證者必須不同家族、不跨家族 fallback、第一輪互不可見 | [02 §2](docs/02-methodology.md#2-白箱階段w0w5)、[05](docs/05-bias-calibration.md)、[examples](docs/examples/) | 多家族**只能降低、不能消除**偏誤；是否勝過「單一最佳模型多次取樣」必須自己量 |
| 黑箱階段一定先做威脅建模，再依結果設計 test cases | B2 威脅建模是強制關卡（G3 人工簽核）；B3 以「威脅→需求→測試」可追溯鏈產生案例；附兩個完整範例 | [02 §3](docs/02-methodology.md#3-黑箱階段b0b6)、[04](docs/04-threat-to-testcase.md) | 追溯鏈並非每一環都有官方對照，需人審對照表 |
| 先上網搜尋可參考的專案與資料 | 8 個主題、321 條發現，逐條查核 | [01](docs/01-research-survey.md)、[ledger](docs/evidence/ledger.md) | 搜尋未窮盡（部分產品與論文未查） |
| 完整的方法論 | 白箱 W0–W5、黑箱 B0–B6、關卡 G0–G5、偏誤控制、校準實驗 | [02](docs/02-methodology.md)、[05](docs/05-bias-calibration.md) | — |
| 詳細的系統架構 | 元件、信任區部署、LangGraph 狀態機、資料模型（JSON Schema）、設定範例、成本模型、CI 兩條線 | [03](docs/03-system-architecture.md)、[schemas](docs/schemas/) | 尚未實作，數字皆為設計假設 |
| 做不到的事就說做不到 | 15 條明列 | [06 §3](docs/06-security-legal-limitations.md#3-做不到不承諾的事) | — |
| 所有內容經交叉比對核實 | 每個事實陳述帶狀態標記與證據 ID；計畫與文件都經獨立代理對抗式審查 | [01 §1](docs/01-research-survey.md#1-查證方法)、全文 | 部分條目只有單一或廠商來源（已標示） |

## 文件導覽

| 文件 | 內容 |
|---|---|
| [docs/01-research-survey.md](docs/01-research-survey.md) | 查證方法、參考專案與文獻調查、研究缺口 |
| [docs/02-methodology.md](docs/02-methodology.md) | 方法論：白箱 W0–W5、黑箱 B0–B6、人工關卡、完成條件 |
| [docs/03-system-architecture.md](docs/03-system-architecture.md) | 系統架構：元件、信任區、狀態機、指揮官、閘道、成本、CI |
| [docs/04-threat-to-testcase.md](docs/04-threat-to-testcase.md) | 威脅→需求→測試案例：追溯鏈、對照表規則、工具綁定、安全等級、完整範例、ROE 樣板 |
| [docs/05-bias-calibration.md](docs/05-bias-calibration.md) | 降低模型偏誤：偏誤定義、證據、規則、叢集與裁決、校準實驗 |
| [docs/06-security-legal-limitations.md](docs/06-security-legal-limitations.md) | 工具包自身安全、法遵與授權、做不到的事 |
| [docs/07-roadmap.md](docs/07-roadmap.md) | 實作里程碑 M1–M5 |
| [docs/references.md](docs/references.md) | 參考文獻 |
| [docs/schemas/](docs/schemas/) | 資料模型 JSON Schema＋範例實例（`python3 tools/validate_schemas.py` 驗證） |
| [docs/examples/](docs/examples/) | `models.yaml`、`agents.yaml`、`roe.yaml`、自架模型啟動範例 |
| [docs/evidence/](docs/evidence/) | 研究證據（JSON）與自動產生的證據帳本 |

## 標記說明

文件中的事實陳述帶有下列標記：

| 標記 | 意義 |
|---|---|
| **[V]** | 已查證：獨立查核代理確認 |
| **[P]** | 部分查證：部分細節未能確認，或查核者提出限定條件 |
| **[C]** | 已依查核更正：原主張有誤，文件採用更正後的說法 |
| **[單源]** | 只能以原始、廠商或單一來源確認 |
| **[H]** | 設計假設：沒有研究直接證實，工具包必須自己量測 |
| `[E:xxx-NN]` | 證據 ID，對應 [`docs/evidence/ledger.md`](docs/evidence/ledger.md) |
| `[S-NN]` | 撰寫文件時補做的查證，見 [01 §4](docs/01-research-survey.md#4-撰寫文件時補做的查證) |

## 術語表

| 英文 | 本文用語 | 說明 |
|---|---|---|
| harness | 測試控制框架 | 以程式碼控制流程、權限、關卡的外殼 |
| commander agent | 指揮官 | 負責規劃與派工的 LLM agent |
| finding | 發現項 | 審查者回報的疑似問題 |
| oracle | 測試判定準則 | 判斷測試通過或失敗的依據 |
| crosswalk | 對照表 | 不同分類體系之間的對應關係 |
| ROE (Rules of Engagement) | 交戰規則 | 授權範圍、禁止事項、停止條件、簽核 |
| PoV (Proof of Vulnerability) | 漏洞觸發證明 | 能重現問題的輸入或測試 |
| DFD (Data Flow Diagram) | 資料流程圖 | 元件、資料存放、資料流、信任邊界 |
| family / lineage | 模型家族／血統 | 同一廠商或同一基礎模型衍生的模型歸為同家族 |
| staging | 預備環境 | 與正式環境分離的測試環境 |
| SARIF | — | OASIS 靜態分析結果交換格式 2.1.0 |

## 快速驗證本 repo 的資料模型

```bash
python3 -m pip install jsonschema pyyaml
python3 tools/validate_schemas.py
```

## 授權

本 repo 目前只含設計文件。工具包實作時使用的第三方工具與模型各有授權義務，見 [06 §2](docs/06-security-legal-limitations.md#2-法遵與授權)。
