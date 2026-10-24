# 變更紀錄

格式參考 [Keep a Changelog](https://keepachangelog.com/)；版本是設計文件的版本，不是軟體發行版本。

## v0.5（2026-10-25）

仍屬設計階段；只新增驗證設計必要的程式碼。

- 修正 GraphQL 標記讓 DELETE／PUT／PATCH 免除寫入限制的問題；不相容的方法與操作組合直接拒絕。
- `create_only_endpoints` 必填 `created_resource`（資源種類、回應 ID JSON Pointer、允許路徑）；`{created:step_id}` 檢查目標與資源路徑，缺漏不自動遷移。這是資料格式的不相容收緊，舊清單須人審補齊並重新核准。
- 同步範例 manifest 及其衍生 hash，增加回歸測試；裁決演算法未變，`05-v0.3` 規則版本保留。
- 補上還原範圍排他租約、CAS 委任隔離與多參照保留、獨立取樣與重播分離的契約及驗收；沒有建置新服務。
- 統一路線圖為 W0 → W0.5／認領與 G1 → W1；Lane A 維持獨立流程。

## v0.4（2026-10-24）

本版只修正設計文件；schema、validator、範例、測試與 `05-v0.3` 規則版本均未變更。

- 明定 run 產物生命週期、job 原子領取、租約與 fencing、外部結果不明時的恢復契約。
- 跨 run G1／G3 沿用在可驗證來源鏈完成前停用；G4／G5 每次重新核准，修正原本互相矛盾的描述。
- G2 駁回後的新可執行證據必須重新送審；保留歷史決定，報告不得只呈現已駁回。現有 R10 尚未變更。
- BL-13、BL-22、BL-23 提升為 MVP-0 前置工作；新增故障注入、純工具結果、效果盲測與代理原型驗收。
- 每項新增契約的實作差距與優先級見 [待辦](docs/09-backlog.md)；本次不新增外部事實查證結論。

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
