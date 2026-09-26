# 變更紀錄

格式參考 [Keep a Changelog](https://keepachangelog.com/)；版本是設計文件的版本，不是軟體發行版本。

## v0.3（進行中，2026-09-26）

依 [2026-09-26 深度審查](docs/evidence/review-2026-09-26.md) 修正 v0.2。高、中優先項目本輪處理；低優先與延後項目見 [docs/09-backlog.md](docs/09-backlog.md)。

### 新增
- 深度審查紀錄 `docs/evidence/review-2026-09-26.md`：原有約 100 項發現在 v0.2 上的逐項判定，以及 v0.2 的新問題。
- 證據帳本新增 8 條已查證事實（OWASP API Security Top 10 2023、SARIF 2.1.0 列舉值、Schemathesis `ignored_auth` 的適用範圍、OWASP LLM Top 10 2026 的版本界線與 CWE 對應、候選工具授權）。
- 待辦清單 `docs/09-backlog.md`。

## v0.2（2026-09-24～25）

- 新增實作規格 `docs/08-implementation-spec.md`、33 個 JSON Schema、`tools/vchlib` 驗證程式與參考演算法、175 個測試與 CI。
- U-11（Claude Opus 4.8 取代 Haiku 4.5）、U-12（GPT-6 Sol）已決定。

## v0.1（2026-09-23）

- 初版方法論與系統架構文件（docs/01–07）、證據帳本與參考資料。
