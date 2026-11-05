---
status: accepted
---

# 裁決版本的推導欄位只由一個模組產出，且逐欄延遲計算

一個裁決版本（verdict version）的推導欄位（derived field）原本分散在 `checks.py`、`derive.py` 和 `adjudicate.py`。checker（`g_verdicts`）、推導值（E-DERIVED）與 variant 寫入端（`build_variants`）各自呼叫一組輔助函式；寫入端甚至得穿過 `checks` 的內部，才組得出同樣的值。2026-11-04 的架構審查決定（候選 #1，設計逐項經使用者決定）：所有推導欄位只由 `tools/vchlib/verdict.py` 的 `derive_verdict(ctx, version) -> DerivedVerdict | None` 產出，三個呼叫端都從這裡讀。依賴方向固定為 `derive` ← `context` ← `calibration` ← `verdict` ← `expectations` ← `checks`。為此，`Ctx` 與推導值先從 `checks`／`derive` 拆出（PR-A），校準統計拆成 `calibration.py`（PR-B0），否則會形成 derive → verdict → derive 的循環依賴。

`DerivedVerdict` 的欄位刻意用 `functools.cached_property` 在第一次讀取時才計算，逐票的值也一票一票算（`vote(i)`）。每個呼叫端都以文件為單位攔截例外：checker 的 `doc_guard` 轉成 E-INTERNAL，推導值的 `guard` 記進 `problems`。拆成獨立函式時，壞掉的輸入只會讓「讀到那一欄的地方」拋例外，前面已報的錯誤碼與已產生的期望值都會保留。一次算完全部欄位（eager 的 frozen dataclass）看起來比較簡單，卻會讓一個欄位的例外把同一份文件其他欄位的結果一起吞掉，悄悄改變 E-INTERNAL 與 E-DERIVED 的行為。**不要把它「簡化」成 eager 計算。**

## Consequences

- 測試只對 bundle 裡的裁決版本做裁決層級的斷言（inputs、outcome、推導欄位），而且一律經過 `derive_verdict`。純函式與內部接縫（internal seam），例如 `root_score`、`vote_valid`、`eligible_verifier_models`、`regression_fixed`，仍可在測試中直接以 `verdict.X` 呼叫，因為這些測試常用 bundle 以外的合成叢集（使用者決定，2026-11-05）。
- `g2_latest` 與 `PRE_G3_PHASES` 是關卡帳本（gate ledger，架構審查候選 #4）的概念，暫時放在 `verdict.py`，等候選 #4 再移。
