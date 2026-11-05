---
status: accepted
---

# 簽章政策只寫一次，重新封存只有一份記憶體內實作

「誰簽什麼」原本寫了五次：checker（`checks.g_signatures`、`g_feedback`、`g_report_withdrawal`）寫一次，三個 TEST ONLY 寫入端（`tools/sign_examples.py`、`tests/conftest.py` 的 `rederive`／`resign_gate`、`build_variants.resign`）又各寫一次，連 `SIGNED_EVENTS` 都是從 `checks` 複製過去的。三份重新封存（reseal）實作也已經漂移：`rederive` 不簽 YAML、feedback 與 withdrawal，也不更新 `config_pins`；只有 `build_variants.resign` 會重編 `seq`。2026-11-05 依架構審查候選 #2 決定（設計逐項經使用者決定）：

- **簽章政策（signing policy）** 只放在 `tools/vchlib/seal.py`：`SIGNED_EVENTS`、`gate_unsigned(rec)`、`required_signers(kind, data)`、`event_is_signed(ev)`。checker 與寫入端都從這裡讀。
  - checker 的錯誤碼分支保持不變：G0a/G0b 與 EXPIRED 各自回報 E-GATE-G0-SIG、E-GATE-EXPIRED-SIG，所以 `gate_unsigned` 只有寫入端使用。
  - 政策函式對格式錯誤的輸入，照 checker 原本的讀法處理（例如 `co_signed_by` 不是物件就忽略）。`event_is_signed` 刻意是布林值，不是「回傳簽章人」：checker 的分支條件與 `actor.id` 是否存在無關，改成回傳簽章人會讓「human 但缺 `actor.id`」的事件換一個錯誤碼。
  - YAML（engagement、roe、key-registry）不在 `required_signers` 內：checker 比對的是 `signatories`，寫入端則是原地重簽既有的 `signatures`，兩者不是同一個概念。
- **重新封存（reseal）** 只有一份記憶體內實作：`seal.reseal(bundle, keys, *, rounds=30) -> None`，直接修改 bundle，不收斂時拋 `ResealError`。它是三份實作的聯集：推導值 → `config_pins` → YAML 簽章 → gate → feedback／withdrawal → 稽核串鏈與簽章，外加 `seq` 重編，重複到收斂。
  - `sign_examples` 改成 placeholder → `load_bundle` → `reseal` → 寫回。YAML 仍以「替換第 n 個 `value:` 行」寫回，保留註解與排版；但這只是序列化，簽章值來自記憶體。
  - `conftest.rederive` 只做轉接（`ResealError` → `AssertionError`）。`resign_gate` 是「只重簽一份 gate、可指定金鑰」的負面測試工具，保留，但改讀政策。
  - 想留下「不一致」狀態的測試，要在 reseal **之後**才竄改。
- `seal` 簽的是傳進來的私鑰，寫入端傳的都是 `tests/fixtures/TEST_ONLY_private_keys`。不加執行期防護（reseal 拿到的是記憶體中的金鑰物件，判斷不了來源）；界線是 checker 只讀政策、從不簽章，由測試鎖住 `checks` 不 import `reseal`。

## Consequences

- 分四步做，每步一個 PR，都有逐位元組的驗收：C1 抽出政策與 helper（`sign_event_in_place`、`current_key` → `seal`；`dump_json`、`dump_jsonl`、`load_events` → `bundle`），不留轉出口；C2 `reseal` 取代 `build_variants.resign`（`build_variants --check`）；C3 `sign_examples` 改用 `reseal`（`docs/` 無 diff）；C4 `rederive` 改用 `reseal`（完整 pytest）。
- 實測（2026-11-05，獨立 worktree）：把 `rederive` 換成 `build_variants.resign` 這個聯集之後，呼叫 `rederive` 的 36 個測試檔仍是 981 passed，結果完全相同；聯集多做的五件事在範例 bundle 上都是 no-op。
- 新增一種簽章文件時，只改 `seal.py`。
