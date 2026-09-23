# 07 實作路線圖

> 以下里程碑是在文件核准後才開始的實作計畫。**安全控制放在最前面（M1）**：ROE 驗章與 Scope Proxy 完成之前，不寫任何會接觸網路的功能。

## 里程碑

| 里程碑 | 內容 | 完成條件 |
|---|---|---|
| **M1 基礎與安全控制** | ・專案骨架（Python）、Pydantic 資料模型（對應 [schemas/](schemas/)）<br>・Model Gateway（LiteLLM 鎖版本＋hash）與 `models.yaml`（family、lineage、資料等級、同家族 fallback）<br>・Policy Engine：資料等級 fail-closed、端點與參數白名單<br>・金鑰登錄整合（登錄、撤銷）與**委任設定驗章（G0a）**：驗章前不送任何程式碼到 LLM<br>・**ROE 驗章（G0b）、目標所有權驗證（由 Z3 經 Scope Proxy）、Scope Proxy**（白名單、每 job 請求白名單、每主機預算、redirect 與內網阻擋、第三方接觸白名單、kill switch）<br>・W0 inventory、W1 確定性掃描（SARIF 匯整）、secrets 遮罩、套件存在性檢查<br>・Audit Log<br>・CI Lane A | ・未簽章或過期的委任設定與 ROE、未登錄或已撤銷的金鑰、所有權驗證失敗、ROE 以外的主機、不在 job 白名單內的請求，全部被拒絕（有測試）<br>・C 級資料無法送到 `data_classes` 不含 C 的模型（有測試）<br>・W1 在範例應用上產出 SARIF |
| **M2 白箱多家族審查** | ・W0.5 不變量起草＋G1<br>・Slicer（同等性單位、`slice_id`、多樣性降低標記）<br>・W2 fan-out／fan-in（`Send`、quorum、缺票）<br>・發現項片段比對<br>・Clusterer、Aggregator、跨家族驗證（匿名、隨機順序）<br>・Gate Service（CLI、簽章紀錄）＋G2<br>・Calibration Lab 第一版（自建語料、四個對照組）<br>・W4 測試生成（Hypothesis／fast-check、TestGen-LLM 濾網、mutation）<br>・W5 DFD＋種子威脅 | ・校準報告：各家族 precision／recall、κ／CAPA，以及「多家族 vs Self-MoA」比較<br>・所有 LLM 輸出都通過 Pydantic 驗證，或有記錄在案的修復／缺票 |
| **M3 威脅建模** | ・B1 兩個視角的系統建模<br>・B2 多家族威脅建模、merger、critic；STRIDE-per-element、LINDDUN、OWASP LLM、ASI、MAESTRO<br>・分類版本欄位與 2025↔2026 對照<br>・G3（可部分核准）<br>・pytm 部分匯出 | ・範例應用的威脅模型通過 G3<br>・每個種子威脅都在模型中 |
| **M4 黑箱執行** | ・B3 推導、crosswalk（含 provenance）、tool_binding adapters（Schemathesis、ZAP AF、Playwright、Nuclei 自簽章）<br>・安全等級計算、產物驗證、G4／G5<br>・Z3 Executor、停止條件自動化、S2 快照、還原（補償步驟）<br>・B5 判定、B6 追溯矩陣<br>・CI Lane B | ・範例 A（IDOR）端到端：FAIL → CONFIRMED_EXECUTABLE → 回歸測試 → 修正後 PASS<br>・S2 在 resume 或重試時不會重跑（有測試） |
| **M5 LLM 功能測試與報告** | ・PyRIT／promptfoo adapter（關閉遠端生成、出站封鎖）<br>・機率判定（n、k、信賴區間）、canary 與工具呼叫紀錄 oracle<br>・受測應用上游 LLM 的花費上限<br>・報告（SARIF、HTML）與儀表板 | ・範例 B 端到端<br>・promptfoo 沒有任何雲端出站（以出站紀錄證明） |

## CI 兩條線（與 [03 §12](03-system-architecture.md#12-ci-整合兩條線) 一致）

| 線 | 從哪個里程碑開始 | 內容 |
|---|---|---|
| Lane A（同步、每個 PR） | M1 | W0、W1、secrets、套件存在性；M2 起可選單一家族只審 diff |
| Lane B（非同步） | M2 起部分、M4 起完整 | 完整多家族白箱、所有人工關卡、黑箱；checkpoint 續跑；結果回貼 PR |

## 每個里程碑都要做的事
- 重新查證模型 ID 與版本（變動很快，例如 GPT-6 Sol 在 2026-09-22 才發布 [P][E:providers-31]）。
- 更新授權登錄表（[06 §2.3](06-security-legal-limitations.md#23-授權登錄表)）。
- 更新工具包自己的威脅模型（[06 §1.1](06-security-legal-limitations.md#11-以-owasp-agentic-top-10-檢視工具包)）。
- 在 pilot 中量測人工關卡的實際耗時，並回寫到 [03 §11](03-system-architecture.md#11-成本與延遲模型)。

## 暫不規劃
- 行動 App（iOS／Android）的黑箱測試。
- 正式環境測試、效能容量測試。
- 自動修補（autofix）後直接合併；修補建議一律走人工審查。
