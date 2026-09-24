# 08 實作規格

> 本文件的讀者是要動手寫程式的工程師。讀完之後，應該不需要再做任何設計決定就能開始 M1。不在本文件、也不在 [03](03-system-architecture.md) 的設計，就是還沒決定，列在 [§10](#10-尚未決定需使用者決定)。
>
> - 本文件的內容幾乎全部是設計選擇，標為 **[H]**。
> - 引用的外部事實沿用 01–06 的證據 ID。本文件新增的外部事實只有套件的授權與版本，已獨立查核並併入證據帳本（依查核結果標 V／P）。
> - 元件名稱與介面沿用 [03 §15](03-system-architecture.md#15-元件介面h)。03 §15 沒有的介面，本文件標為「**擴充**」。
> - 依 03 §15 的約定，**模組配置、錯誤分類與 CLI 細節以本文件為準**。兩份文件不一致時，應改 03。

## v0.2 變更摘要

- **新文件**（D16）：
  - 套件配置與依賴方向；
  - 03 §15 的介面，以及 8 個擴充介面；
  - 從 JSON Schema 產生 Pydantic 模型的做法；
  - CLI 與結束碼；
  - 設定檔的優先順序；
  - 錯誤分類、重試與冪等；
  - 持久化；
  - 各里程碑的測試與完成定義；
  - M1 前兩週的工單；
  - 待決事項。
- 里程碑的出口準則寫在 [07](07-roadmap.md)。本文件 §8 與 §9 的測試項目，以 07 的準則編號（例如 `M1-X2`）互相對應。

## 1. 套件配置

### 1.1 模組

原始碼放在 `src/vibecheck/`。Python 版本定為 3.12 [H]；本文件提到的每個依賴套件都支援 3.10 以上（證據見各套件引用處的 [E:id]）。

「區」指該模組的程式碼**執行**在哪個信任區（[03 §2](03-system-architecture.md#2-部署與信任區)）。

| 模組 | 責任 | 區 | 里程碑 |
|---|---|---|---|
| `errors` | 例外類別、`error_class` 字串、CLI 結束碼（§6.1） | 全部 | M1 |
| `models` | 由 schema 產生的 Pydantic 模型（`models/_generated/`），加上少量手寫的行為包裝（§3） | 全部 | M1 |
| `keys` | JCS 正規化、嚴格 YAML 載入、Ed25519、`KeyRegistry`、`SignatureVerifier`（[03 §6.1](03-system-architecture.md#61-金鑰登錄與驗章流程)） | Z1、Z3、簽署人裝置 | M1 |
| `config` | 載入並驗證 7 種設定檔，套用優先順序（§5） | Z1、Z3 | M1 |
| `store`（擴充） | `ContentStore`（CAS）、`Blackboard`、Postgres 的 run 與關卡紀錄、資料表遷移 | Z1 | M1 |
| `audit` | `AuditWriter`：hash chain、錨定、驗證（[03 §13.1](03-system-architecture.md#131-稽核事件格式audit-eventschemajsonh)） | Z1 | M1 |
| `policy` | `PolicyEngine`（擴充）：G0a、G0b、資料等級、白名單、計畫驗證、目標解析；`SafetyClassifier`（擴充，[04 §5](04-threat-to-testcase.md#5-安全等級計算規則)）；產物驗證 | Z1 | M1；M2 加計畫驗證；M4 加安全等級與產物驗證 |
| `gateway` | `ModelGateway`，唯一的 LLM 出口；`BudgetTracker`；`LlmRelay` 的 Z1 端點 | Z1 | M1；M2 加 Budget；M5 加 Relay |
| `sandbox`（擴充） | `SandboxRunner`（Z2 job 的建立、限制、收集輸出、遮罩） | Z1 端控制、Z2 執行 | M1（W0／W1）、M2（W4） |
| `scope_proxy` | `ScopeProxy`（擴充）：Z3 唯一出口；DNS 固定；每個 job 的白名單；速率、指標與 kill switch | Z3 | M1 |
| `executor`（擴充） | `Executor`（Z3 服務，只接受 Z1 以 mTLS 發來的指令）；`SessionProvider`（M4）；`LlmRelay` 的 Z3 用戶端（M5） | Z3 | M1（最小版）、M4（完整版） |
| `snapshot` | `SnapshotService`（快照、還原、演練、種子資料、oracle 唯讀查詢） | Z3 | M4 |
| `adapters` | `ToolAdapter` 基底類別（擴充），加上每個 `tool:mode` 一個實作（D13） | Z2、Z3 | M1（W0／W1 工具）、M2（W4）、M4（黑箱工具）、M5（LLM 測試工具） |
| `slicer` | `Slicer`（擴充）：同等性單位、`slice_id`、多樣性降低標記 | Z1 | M2 |
| `cluster` | `Clusterer`（擴充）：確定性叢集鍵（[05 §4.1](05-bias-calibration.md#41-叢集鍵clusterer確定性)） | Z1 | M2 |
| `aggregator` | `Aggregator`（擴充）：R0–R13 有序規則（[05 §4.2](05-bias-calibration.md#42-裁決狀態與有序規則)） | Z1 | M2 |
| `agents` | 每個 agent 的 prompt 範本、輸出 schema 與角色（`agents.yaml`）；Commander（CMD-1–CMD-5） | Z1 | M2（W）、M3–M4（B） |
| `nodes` | LangGraph 節點函式，一個節點一個函式（[03 §5.7](03-system-architecture.md#57-節點規格表)） | Z1 | M1–M5（依節點，見 [07 §2](07-roadmap.md#2-元件與節點的歸屬)） |
| `graph` | `RunState`、StateGraph 的組裝、checkpointer、`Send` fan-out、interrupt 與 resume | Z1 | M1（骨架）、M2（W 圖）、M3–M4（B 圖） |
| `gates` | `GateService`（擴充）：開關卡、列表與顯示、提交簽章紀錄、逾時、ASI09 抽查 | Z1 | M2（M1 只有 G0a／G0b 的離線驗章，放在 `policy`） |
| `reporter` | 確定性報告骨架＋Reporter agent 的敘事；JSON、SARIF、靜態 HTML | Z1 | M2（白箱）、M4（B6 JSON／SARIF）、M5（HTML） |
| `calibration` | Calibration Lab：語料載入、對照組、M-1–M-11、θ 搜尋、§5.8 最小重跑 | Z1＋Z2 | M2 |
| `selftest`（擴充） | 06 §1.2.1 的自測：ST-1–ST-7，產出 `selftest-report.json` | Z1＋Z2＋Z3 | M1 起逐步擴充 |
| `cli` | `vibecheck` 指令（§4）；只做參數解析，再呼叫其他模組 | Z1、簽署人裝置 | M1 起 |

**擴充說明**：D16 列出的 18 個模組都保留，名稱也不變。另外新增 `errors`、`config`、`store`、`sandbox`、`executor`、`selftest`，原因是 03 §15 的 `ContentStore`、`Blackboard`、`SandboxRunner`、`Executor`、`SessionProvider` 在 D16 的清單裡沒有對應的模組 [H]。

### 1.2 依賴方向

分層（上層可以 import 下層，反過來不行）[H]：

```text
L7  cli
L6  graph, gates, reporter, calibration, selftest
L5  nodes
L4  agents, slicer, cluster, aggregator
L3  policy, gateway, sandbox, scope_proxy, executor, snapshot
L2  adapters
L1  keys, config, store, audit
L0  errors, models
```

- `adapters` 放在 L2（`executor`、`sandbox` 之下），因為 Z2／Z3 的執行器要呼叫 adapter 的 `render()`／`parse()`；`adapters` 本身只 import L0–L1（`errors`、`models`、`config`、`keys`），不 import 任何 L3 以上的模組，所以規則 4 不需要例外 [H]。

**強制規則**（`tests/arch/test_imports.py` 以標準函式庫 `ast` 掃描 import，違反就讓 CI 失敗）[H]：

1. **只有 `gateway` 可以 import `litellm`**。只有 `gateway` 可以讀取 LLM API 金鑰的環境變數（§5.3）。
2. **`nodes` 不可以直接呼叫供應商或目標**。`nodes` 不 import `litellm`、`httpx`、`dns`、`socket`、`subprocess`，只透過注入的 Protocol 物件（`ModelGateway`、`SandboxRunner`、`Executor` 用戶端等）做事。
3. **`slicer`、`cluster`、`aggregator` 是純函式**：
   - 不 import `store`、`gateway`、`audit` 或任何 I/O 模組；
   - 輸入與輸出都是 `models` 的物件，由 `nodes` 負責讀寫 Blackboard。
4. **Z3 的模組不 import Z1 的模組**：
   - `scope_proxy`、`executor`、`snapshot` 不 import `gateway`、`store`、`graph`、`gates`；
   - 它們可以 import `errors`、`models`、`keys`、`config`、`adapters`；
   - Z3 映像不包含 Z1 的模組（§1.3），這一條由映像內容測試再檢查一次。
5. **網路出站只允許**：`gateway` 連 LLM 端點；`executor` 經 `scope_proxy` 連目標；`sandbox` 只連 Z2 的鏡像（`mirror_only`）。其他模組開 socket 一律視為違規。
6. **`agents` 只依賴 `ModelGateway` 這個 Protocol**，不依賴 `gateway` 的實作。
7. **只有 `graph` 可以 import `langgraph`**。`nodes` 內只使用 `graph` 重新匯出的 `interrupt`、`Send`、`Command`，方便以假物件測試。
8. `keys` 不依賴 `policy`；`policy` 使用 `keys`。

### 1.3 部署單位

三個映像，都鎖 digest [H]：

| 映像 | 內容 | 區 | 限制 |
|---|---|---|---|
| `vibecheck-z1` | 除 `scope_proxy`、`executor`、`snapshot` 以外的全部模組 | Z1 | 出站只允許 LLM 端點、Z4 與 Z3 的指令埠。**不能連目標** |
| `vibecheck-z3` | `errors`、`models`、`keys`、`config`、`adapters`（只含 Z3 模式）、`scope_proxy`、`executor`、`snapshot` | Z3 | 不含 LLM 金鑰；出站只經 Scope Proxy |
| 工具映像（每個工具一個） | W0／W1／W4 工具，以及 M4 起的黑箱工具 | Z2 或 Z3 | digest 登錄在 `tools.yaml` 與 SBOM |

- 開發機可以用單一行程執行 Z1 與 Z3 的模組，方便除錯；但整合測試線與安全測試線一律使用分開的映像與網路（§8.4）。
- **Z1 與 Z3 的通道** [H]：
  - Z1 以 mTLS 呼叫 Z3 Executor 的 HTTP JSON API。Z3 只接受 Z1 控制平面憑證，Z3 本身不主動連 Z1（例外是 M5 的 Relay 端點）。
  - **Z3 不盲目相信 Z1**。每個指令都附上：已驗章的 ROE 原文與簽章；需要時再附 G4／G5 的 GateRecord。Executor 以自己的 `keys` 模組重新驗章，並比對 job 的 hash。
  - 這樣一來，即使 Z1 被入侵，也無法讓 Z3 對 ROE 以外的目標發出請求 [H]。

## 2. 介面

### 2.1 名稱對照

設計決策（D1–D16）用了幾個簡稱。下表把簡稱對應到 03 的正式名稱；**以 03 的名稱為準**。

| 需求中的名稱 | 實際介面 | 來源 |
|---|---|---|
| `ModelGateway.complete` | `ModelGateway.complete` | 03 §15 |
| `AuditLog.append` | `AuditWriter.append` | 03 §15（元件名稱是 Audit Log，介面名稱是 AuditWriter） |
| `KeyRegistry.verify` | `SignatureVerifier.verify_document`，底層呼叫 `KeyRegistry.verify_signature` | 03 §15 只把 `KeyRegistry` 當成前向參照；它的方法是**擴充** |
| `SnapshotService`（含 `oracle_capture`、`oracle_count`） | `SnapshotService` | 03 §15 |
| `PolicyEngine.check`、`ScopeProxy`、`GateService`、`Slicer`、`Clusterer`、`Aggregator.adjudicate`、`SafetyClassifier`、`ToolAdapter` | 本節 §2.3 | **擴充** |

### 2.2 沿用 03 §15 的介面

以下介面的簽名**原樣沿用** [03 §15](03-system-architecture.md#15-元件介面h)，本文件不重寫：

- `Provenance`、`ContentStore`、`Blackboard`、`SignatureVerifier`、`AuditWriter`、`ModelGateway`
- `SandboxJobSpec`、`SandboxResult`、`SandboxRunner`
- `Executor`、`SessionHandle`、`SessionProvider`、`SnapshotService`
- `RelayRequest`、`LlmRelay`、`BudgetTracker`

本文件只補上它們**丟出哪些例外**（名稱見 §6.1）[H]：

| 方法 | 例外 |
|---|---|
| `ContentStore.get` | 重算的 hash 不符 → `IntegrityError`；不存在 → `NotFound` |
| `Blackboard.publish` | schema 驗證失敗 → `SchemaInvalid`（不寫入任何東西） |
| `SignatureVerifier.load_registry` | 根簽章無效 → `SignatureInvalid`；版本回滾 → `RegistryRollback` |
| `SignatureVerifier.verify_document` | **不丟例外**，一律回傳 `VerifyResult`；由呼叫者決定後果 |
| `AuditWriter.append` | 寫入失敗 → `AuditUnavailable`。這是 fail-closed：該節點失敗 |
| `ModelGateway.complete` | 依序檢查，任一項不通過就在**送出請求之前**丟出：`RedactionMissing`、`ModelNotAllowed`、`DataClassDenied`、`EndpointDenied`、`BudgetExceeded`。之後才可能出現：`ProviderRateLimited`、`ProviderUnavailable`、`ProviderRefused`、`SchemaRepairExhausted` |
| `SandboxRunner.run` | 基礎設施失敗 → `SandboxInfraError`。工具本身的非零結束碼**不是**例外，而是寫在 `SandboxResult` |
| `Executor.*` | `ScopeViolation`、`OwnershipFailed`、`Z3Unavailable`、`StopConditionTriggered` |
| `SnapshotService.restore` | 回傳 `False`，不丟例外；重試由呼叫的節點處理 |
| `SnapshotService.oracle_count` | `query_id` 不在 G4 核准清單中 → `PolicyDenied` |

### 2.3 擴充介面

```python
from abc import ABC, abstractmethod
from typing import ClassVar, Literal, Protocol
from pydantic import BaseModel
from vibecheck.models import (ArtifactRef, Provenance, TestCase, Roe, Engagement,
                              ToolRegistry, SeedManifest, CommanderPlan, GateRecord)

# --- KeyRegistry（keys；M1）：03 §15 只有前向參照，下列方法是擴充 ---
class SignerCheck(BaseModel):
    fingerprint: str
    person_id: str | None
    roles: list[str]
    ok: bool
    reason: str | None       # not_registered / revoked_compromised / revoked_after / not_yet_valid /
                             # expired / role_mismatch / bad_signature

class VerifyResult(BaseModel):       # SignatureVerifier.verify_document 的回傳值
    ok: bool                          # 所有 required_roles 都至少有一位 ok 的簽署人
    doc_hash: str                     # "sha256:" + JCS(移除 signatures 的文件)
    signers: list[SignerCheck]
    failures: list[str]

class KeyRegistry:
    registry_id: str
    version: int
    issued_at: str
    def lookup(self, fingerprint: str) -> "KeyEntry | None": ...
    def verify_signature(self, payload: bytes, signature_b64: str, fingerprint: str,
                         required_roles: set[str], at: str) -> SignerCheck: ...
    # 撤銷規則依 03 §6.1 第 5 步：compromised → 全部無效；其他原因 → 以 revoked_at 為界

# --- PolicyEngine（policy；M1）---
class PolicyAction(BaseModel):
    kind: Literal["llm_call", "tool_invocation", "egress", "resume", "plan", "artifact"]
    run_id: str
    subject: dict             # 依 kind 而定，例如 {agent_id, model_alias, data_class, endpoint, params}

class PolicyDecision(BaseModel):
    allow: bool
    rule_id: str              # 例如 "GW-003 data_class"；每次呼叫都寫 policy_decision 稽核事件
    reason: str

class EngagementCheck(BaseModel):
    ok: bool
    verify: VerifyResult
    engagement_ref: ArtifactRef
    failures: list[str]

class RoeCheck(BaseModel):
    ok: bool
    verify: VerifyResult
    roe_ref: ArtifactRef
    in_window: bool
    legal_review: dict        # L-1–L-6 的結果（06 §2.1.1）
    failures: list[str]

class ResolvedTarget(BaseModel):
    target_id: str
    base_url: str
    host: str
    ownership_method: Literal["dns_txt", "well_known_path"]

class PolicyEngine(Protocol):
    def check(self, action: PolicyAction) -> PolicyDecision: ...     # 純判斷，不做 I/O；deny 由呼叫者轉成 PolicyDenied
    def verify_engagement(self, doc_bytes: bytes, detached: list[bytes], at: str) -> EngagementCheck: ...  # G0a
    def verify_roe(self, run_id: str, doc_bytes: bytes, detached: list[bytes], at: str) -> RoeCheck: ...  # G0b
    def verify_gate_record(self, run_id: str, record_bytes: bytes, detached: list[bytes]) -> VerifyResult: ...
    def validate_plan(self, run_id: str, plan: CommanderPlan) -> PolicyDecision: ...  # CMD-1–CMD-5；M2
    def resolve_target(self, run_id: str, target_id: str) -> ResolvedTarget: ...  # 目標 ID → 主機，不經 LLM

# --- SafetyClassifier（policy.safety；M4，M1 起用於 roe verify 的預檢）---
class SafetyResult(BaseModel):
    level: Literal["S0", "S1", "S2", "S3"]
    reasons: list[str]

class SafetyClassifier(Protocol):
    def classify(self, tc: TestCase, roe: Roe, registry: ToolRegistry,
                 manifest: SeedManifest | None) -> SafetyResult: ...
    # 包裝 04 §5 的 compute_safety_class。參考實作 vchlib/safety.py 的簽名是
    # compute_safety_class(tc: dict, roe: dict, tools: dict, manifest_keys: set[str] | None)
    #   -> tuple[str, list[str]]；classify 以 model_dump(mode="json") 與 manifest 的種子鍵集合呼叫同一演算法，
    # (level, reasons) ＝ 參考實作的 (class, trace)
    def admissible(self, level: str, roe: Roe) -> bool: ...            # 04 §5 的 admissible

# --- ScopeProxy（scope_proxy；Z3；M1）---
class JobAllowlist(BaseModel):
    run_id: str
    job_id: str
    target_id: str
    hosts: list[str]
    pinned_ips: dict[str, list[str]]   # 第一次解析就固定，之後不再解析
    methods: list[str]                 # M1 只有 ["GET"]
    path_patterns: list[str]           # 已扣除 ROE 的 exclusions
    max_requests: int
    rate_per_s: float
    third_party: list[str]             # 預設為空
    expires_at: str

class TargetMetrics(BaseModel):        # 60 秒滑動視窗（03 §7.3）
    target_id: str
    n: int
    ratio_5xx: float
    consecutive_5xx: int
    p95_ms: float
    error_ratio: float
    count_429: int

class ScopeProxy(Protocol):
    def open_job(self, allowlist: JobAllowlist) -> str: ...    # 回傳這個 job 專用的 proxy 端點
    def close_job(self, run_id: str, job_id: str) -> dict: ...  # 回傳統計：請求數、被擋數、停止原因
    def close_all(self, run_id: str) -> None: ...               # ah_cancel 與 kill switch 使用
    def metrics(self, run_id: str, target_id: str) -> TargetMetrics: ...
    def resolve_txt(self, run_id: str, name: str) -> list[str]: ...  # 所有權驗證用的 DNS TXT 查詢

# --- GateService（gates；M2）---
class GateSummary(BaseModel):
    gate_id: str
    run_id: str
    gate: str
    round: int
    status: Literal["OPEN", "DECIDED", "EXPIRED"]
    opened_at: str
    due_at: str

class GateService(Protocol):
    def open_pending(self, run_id: str) -> list[GateSummary]: ...
    # 觀察 checkpoint 中待處理的 interrupt → 寫 gate_opened；以 (run_id, gate, round) 為冪等鍵
    def list(self, run_id: str | None = None, status: str | None = None) -> list[GateSummary]: ...
    def show(self, gate_id: str) -> ArtifactRef: ...   # 呈現用的包：叢集、排序、證據
    def submit(self, gate_id: str, record_bytes: bytes, detached: list[bytes]) -> str: ...
    # 以 PolicyEngine.verify_gate_record 驗章 → 存 GateRecord → 回傳 gate_record_id
    # → graph.resume(run_id, Command(resume=gate_record_id))
    def expire_due(self, now: str) -> list[str]: ...
    # 寫一份由系統產生的 EXPIRED 紀錄（沒有人員簽章；Policy 只接受 EXPIRED 這一種無簽章紀錄）
    def spot_check_sample(self, run_id: str) -> list[str]: ...  # ASI09 抽查（07 M2）

# --- Slicer / Clusterer / Aggregator（純函式；M2）---
class Slicer(Protocol):
    def slice(self, inventory: BaseModel, sarif: list[BaseModel],
              plan: CommanderPlan | None) -> list[BaseModel]: ...
    # 回傳 slice.schema.json 的物件；slice_id = 內容 hash；相同輸入 → 相同輸出

class Clusterer(Protocol):
    def cluster(self, findings: list[BaseModel], sarif: list[BaseModel]) -> list[BaseModel]: ...
    # 回傳 cluster.schema.json 的物件；使用 05 §4.1 的叢集鍵

class AdjudicationInputs(BaseModel):   # 欄位與 tools/vchlib/adjudicate.py 的 Inputs 一一相同（§2.4）
    lane_a: bool
    g2_rejected: bool
    all_snippets_fail: bool
    evidence: set[str]                 # E_proof / E_fail_u / E_pass / E_inc（EVIDENCE_ORDER）
    weighted_support: bool
    weighted_refute: bool
    score: float                       # S = Σ w(m,b)·stance；w=0 的票不計入
    sarif_corroboration: bool
    theta_confirm: float | None        # None = +∞
    theta_reject: float | None
    independent_families: int
    diversity_degraded: bool
    g3_rejected: bool                  # R13：由 G3 GateRecord 計算；G3 之後任何階段的裁決都適用
    phase: str | None                  # 呼叫情境："W3"、"W4"、"B5"…（對應 readjudicated_by）
    prev_status: str | None            # 被取代那一版裁決的狀態；第一版為 None
    # w4_became_disputed：phase == "W4"、prev_status 不是 None 也不是 DISPUTED、新狀態為 DISPUTED
    # （例如 LIKELY 經 R11 → DISPUTED）；與 G2 是否已決定無關（05 §4.2）
# 由 nodes 從投票、證據與 calibration.yaml 組成；純核心回傳 Outcome(status, row, rules,
# status_cap, advisory, annotations)，與 vchlib 相同

class Aggregator(Protocol):
    def adjudicate(self, cluster: BaseModel, x: AdjudicationInputs,
                   previous: BaseModel | None) -> BaseModel: ...
    # 回傳 verdict.schema.json 的新一版裁決（append-only）；rule_trace 記錄每條被觸發的規則
    # 規則順序：R9、R10、R0、R1、R2–R7、R8、R11、R12、R13（05 §4.2）；每次都從 A 段重新評估
```

**`ToolAdapter` 基底類別**（adapters；擴充）：

```python
class AdapterContext(BaseModel):
    run_id: str
    job_id: str
    zone: Literal["Z2", "Z3"]
    target: ResolvedTarget | None
    proxy_endpoint: str | None          # Z3 才有
    session_handles: list[str]          # SessionHandle.handle_id；不含任何憑證值
    rate_per_s: float | None
    max_requests: int | None
    timeout_s: int

class AdapterPlan(BaseModel):
    image_digest: str
    argv: list[str]
    env: dict[str, str]                 # 只允許非機密值；含 secret 樣式的值 → 拒絕
    inputs: list[ArtifactRef]
    network: Literal["none", "mirror_only", "scope_proxy"]
    output_dirs: list[str]

class ToolAdapter(ABC):
    tool: ClassVar[str]                 # 例如 "playwright"
    mode: ClassVar[str]                 # 例如 "api"
    zone: ClassVar[Literal["Z2", "Z3"]]

    @classmethod
    def adapter_id(cls) -> str:
        return f"{cls.tool}:{cls.mode}"                                   # D13

    @abstractmethod
    def validate_binding(self, binding: BaseModel) -> list[str]: ...       # 回傳錯誤清單；空清單表示通過
    @abstractmethod
    def render(self, tc: TestCase | None, ctx: AdapterContext) -> AdapterPlan: ...  # 純函式；不連網
    @abstractmethod
    def parse(self, outputs: list[ArtifactRef], ctx: AdapterContext) -> list[BaseModel]: ...
    # 回傳 testresult（含 04 §4.2 的 oracle 判定）或 SARIF 結果
```

**adapter 的註冊規則** [H]（啟動時檢查，由 `tests/contract/test_adapters.py` 測試）：
- 每個已實作的 adapter，在 `tools.yaml` 都必須有同名的 `tool:mode`，而且 `zone` 一致。
- **必須有實作**：`tools.yaml` 中同時滿足下列三項的模式，在它所屬的里程碑都必須有實作：
  - (a) `b4_executable: true`；
  - (b) 不在 `TOOLKIT_DENYLIST`，且 `toolkit_denied` 不是 `true`；
  - (c) 沒有被法務閘門擋下：該工具的 `license_ref` 在 `licenses.yaml` 不是 `status: 法務閘門`，或該閘門已依 [07 §3](07-roadmap.md#3-入口閘門法務與查證) 結案為「已確認」。
- **不得有實作**：`TOOLKIT_DENYLIST`（`nuclei:code_protocol`、`restler:fuzz`）以及 `toolkit_denied: true` 的模式。`tools.yaml` 雖把這兩個模式標為 `b4_executable: true`（描述工具本身的能力），但 (b) 優先，所以它們不在「必須有實作」之列。
- **法務閘門未結案**（例如 `k6:threshold`，`licenses.yaml` 的 k6 為 `法務閘門`、`gate_milestone: M4`）：adapter 程式可以存在，但啟動時**不註冊**（見下方白箱清單的同一規則）；不算違反「必須有實作」。
- `render()` 必須遵守：ROE 的速率下限，以及 [03 §7.3](03-system-architecture.md#73-限速與停止條件) 的工具設定規則（例如 ZAP 的 `maxScanDurationInMins` > 0）。

**白箱 adapter 清單**（ID 取自 [docs/examples/tools.yaml](examples/tools.yaml)；兩者不同時以 `tools.yaml` 為準）[H]：
- M1 W0：`betterleaks:scan`、`gitleaks:scan`、`syft:sbom`、`inventory:fastapi`、`inventory:express`、`inventory:sql_rls`
- M1 W1：`opengrep:scan`、`bandit:scan`、`osv_scanner:scan`、`grype:scan`、`pkgcheck:exists`
- **已登錄但受法務閘門控制**：`trufflehog:scan`（W0）、`semgrep:scan`、`codeql:analyze`（W1）。`licenses.yaml` 標為「法務閘門」且 [07 §3](07-roadmap.md#3-入口閘門法務與查證) 未確認之前，adapter 程式可以存在，但**啟動時不註冊**，engagement 或 ROE 也不能啟用；由 `tests/contract/test_adapters.py` 檢查。
- M2 W4：`hypothesis:property`、`fast_check:property`（Z2，`b4_executable: false`；出現在 B4 → S3）。

### 2.4 參考實作

`tools/vchlib/`（validator 使用）是下列演算法的**參考實作**。本文件 §2.3 的正式介面只規定型別與注入方式；**演算法本身以 vchlib 為準，移植而不重寫**。防止兩者悄悄分歧的規則 [H]：
- `tests/contract/test_vchlib_parity.py` 對同一組輸入同時呼叫兩邊，結果不同 → CI 失敗。輸入包含：`tests/fixtures/`、`docs/examples/` 的全部文件、RFC 8785 測試向量，以及 Hypothesis 產生的隨機輸入。
- 任何一邊的演算法修改，都要在同一個 PR 同步修改另一邊，並更新 05 §4.2 或 04 §5（文件 → 參考實作 → 正式實作）。
- 等 `tools/` 改為直接 import `vibecheck` 之後，才刪除 vchlib 中的重複程式；在那之前兩份並存。

| 參考實作（函式） | 移植位置 | 正式介面 |
|---|---|---|
| `canonical.py`：`jcs`、`signing_payload`、`content_hash`、`approval_hash`、`set_digest`、`text_hash`、`sha256_ref` | `keys/canonical.py` | `SignatureVerifier`、`ContentStore`、GateRecord 的冪等鍵（§6.3） |
| `crypto.py`：`fingerprint`、`sign_document`、`verify_document`、`sign_event`、`verify_event` | `keys/crypto.py` | `KeyRegistry.verify_signature`、`vibecheck sign`、`AuditWriter` |
| `yamlstrict.py`：`load`、`StrictYAMLError` | `keys/yamlstrict.py` | 所有 YAML 的載入（§5.1） |
| `timeutil.py`：`in_window`、`in_any_window`、`window_end` | `policy/timeutil.py` | `PolicyEngine.verify_roe`、`B4_preflight` |
| `safety.py`：`compute_safety_class`、`admissible` | `policy/safety.py` | `SafetyClassifier.classify`、`admissible` |
| `adjudicate.py`：`Inputs`、`Outcome`、`adjudicate`、`EVIDENCE_ORDER` | `aggregator/rules.py` | `Aggregator.adjudicate` 的純核心 |
| `llm_schema.py`：`degrade_for_llm`、`find_forbidden` | `gateway/schema_degrade.py` | `ModelGateway.complete` 的輸出 schema |

## 3. 資料模型：從 JSON Schema 產生 Pydantic

**單一真實來源（single source of truth）規則** [H]：
1. **`docs/schemas/*.schema.json` 是唯一真實來源**。Pydantic 模型一律由它產生，不手寫欄位。
2. 產生器使用 datamodel-code-generator。它支援從 JSON Schema 與 OpenAPI 3 產生 Pydantic v2 模型，授權 MIT，需要 Python 3.10 以上 [P][E:orchestration-55]。
   - **不假設**它支援 docs/schemas 用到的每個 2020-12 關鍵字。這一點由第 5 條的契約測試證明，不支援的部分由第 4 條補上。
3. 輸出放在 `src/vibecheck/models/_generated/`，**檔案進版控**。
   - CI 會重新產生一次再做 diff；有差異 → CI 失敗。
   - 產生器的版本與參數寫在 `pyproject.toml`，並加上 hash 鎖定。
4. **手寫程式只能放在** `src/vibecheck/models/`（不能放在 `_generated/`）。允許兩種：
   - **行為**：例如 `Verdict.latest()`；
   - **跨欄位檢查**：以 Pydantic validator 實作，而且 validator 必須與 `tools/validate_schemas.py` 的檢查一一對應（在測試中列出對照）。
5. **契約測試**（`tests/contract/`）：
   - (a) `docs/schemas/examples/` 的每個範例，都要能「解析 → Pydantic → `model_dump(mode="json", exclude_none=False)` → 以 jsonschema 驗證 → JCS」，並且與原檔的 JCS **逐位元組相同**。
   - (b) 以 Hypothesis 從 schema 產生隨機實例（Hypothesis 6.168.1，MPL-2.0 [V][E:orchestration-56][V][E:whitebox-47]），做同樣的往返檢查。
   - (c) 每個 schema 都要有至少一個應該被拒絕的反例。
6. **送給 LLM 的 schema**：
   - 由 `gateway/schema_degrade.py`（移植自 `degrade_for_llm`）從同一份 schema 降階，產生各廠商都能接受的子集（[03 §8.3](03-system-architecture.md#83-結構化輸出跨廠商最小公約數)）。
   - 回應先以完整 schema 驗證，才寫入 Blackboard。
7. **schema 的變更流程**：
   - 修改 schema → 重新產生模型 → 修正契約測試 → 更新 `docs/schemas/examples/` 或 `docs/examples/`。
   - **修改任何範例之後**，依序執行 `python tools/sign_examples.py`（重新產生衍生 hash、簽章與稽核鏈；使用的是**只供測試的金鑰**，不得用於正式環境）與 `python tools/validate_schemas.py`，兩者都通過才能合併。
   - 如果變更不向後相容，`$id` 的版本要遞增，而且 checkpoint 中舊版的 `RunState` 必須有遷移函式（§7.1）。

## 4. CLI

### 4.1 共用選項與結束碼

- 共用選項：
  - `--toolkit PATH`：預設讀環境變數 `VIBECHECK_TOOLKIT`，再退到 `/etc/vibecheck/toolkit.yaml`；
  - `--json`：機器可讀的輸出；
  - `--at ISO8601`：只給離線驗證使用，以指定時間判斷效期；
  - `-v`。
- **CLI 不能放寬任何安全設定**。旗標只用來選擇輸入檔、輸出格式與動作 [H]。
- 每個會改變狀態的指令都寫稽核事件；`--json` 的輸出包含對應的稽核行 hash。

| 結束碼 | 意義 |
|---|---|
| 0 | 成功（包含冪等重送：同一份已記錄的簽章紀錄再送一次） |
| 1 | 未預期的內部錯誤（`InternalError`） |
| 2 | 參數錯誤 |
| 3 | 設定或 schema 不合法：`ConfigInvalid`、`SchemaInvalid`；**未簽署**設定檔（`toolkit.yaml`、`models.yaml`、`agents.yaml`、`tools.yaml` 等）的 `StrictYAMLError` |
| 4 | 驗章失敗：`SignatureInvalid`、`RegistryRollback`、金鑰撤銷、角色不符、效期外；**簽署文件**（engagement、ROE、`key-registry.yaml`、GateRecord）的 `StrictYAMLError`（記為 `signature_invalid`） |
| 5 | 政策拒絕：`PolicyDenied`、職責分離違規、時間窗外、ROE 的法務聲明未通過 |
| 6 | 找不到：run、關卡或產物 |
| 7 | 狀態衝突：run 不在可執行該動作的狀態，或關卡已有不同的決定 |
| 8 | 完整性失敗：稽核鏈斷裂、錨點不符、CAS hash 不符 |
| 9 | 相依服務無法使用：Postgres、Z3、Z2 執行環境 |
| 10 | 門檻未達：`selftest run`、`calibrate check`、`licenses check` |
| 11–15 | 只用於 `run status --exit-code`：11 `COMPLETED_WITH_GAPS`、12 `RUNNING`／`WAITING_GATE`／`SUSPENDED`、13 `STOPPED`、14 `ABORTED`、15 `FAILED`（`COMPLETED` 為 0） |

### 4.2 指令

| 指令 | 參數 | 做什麼 | 結束碼 | 里程碑 |
|---|---|---|---|---|
| `vibecheck config validate` | `[--dir DIR]` | 驗證 §5 的 7 種設定檔（schema＋跨檔規則，例如 fallback 必須同家族） | 0/3/4 | M1 |
| `vibecheck keys verify` | `REGISTRY [--accept]` | 驗根簽章與版本；`--accept` 把該版本寫成「上次接受的版本」（需要 `toolkit_maintainer` 身分簽章） | 0/3/4 | M1 |
| `vibecheck keys show` | `[--person ID] [--fingerprint FP]` | 列出登錄項、角色、效期、撤銷狀態 | 0/6 | M1 |
| `vibecheck keys fingerprint` | `PUBKEY_FILE` | 計算指紋（與 `key-registry` 的格式一致） | 0/3 | M1 |
| `vibecheck sign` | `DOC --signer PERSON_ID --key PATH [--out SIG]` | 在**簽署人自己的裝置上**：嚴格解析 → 移除 `signatures` → JCS → Ed25519 分離式簽章。私鑰是加密的 PEM 檔，密碼以互動方式輸入；工具包伺服器不持有任何私鑰 | 0/2/3 | M1 |
| `vibecheck engagement verify` | `ENGAGEMENT --sig SIG... [--at]` | 離線執行 G0a 的全部檢查 | 0/3/4/5 | M1 |
| `vibecheck roe verify` | `ROE --sig SIG... --engagement E [--at]` | 離線執行 G0b 的全部檢查，包含 L-1–L-6、`TOOLKIT_DENYLIST`、時間窗 | 0/3/4/5 | M1 |
| `vibecheck run start` | `--engagement E --engagement-sig S... [--roe R --roe-sig S...] --repo PATH --commit SHA [--kind initial\|followup\|regression\|lane_a] [--sign --signer ID --key PATH] [--wait]` | 建立 run。除了 `lane_a` 以外，一律要 `--sign`：寫入 `initiator_claim`，發起者必須是登錄中的**人**（D7） | 0/3/4/5/9；`--wait` 時依最終狀態回傳 11–15 | M1 |
| `vibecheck run status` | `RUN_ID [--json] [--exit-code]` | 狀態、目前節點、待處理關卡、缺口、預算 | 0/6；`--exit-code` 時 11–15 | M1 |
| `vibecheck run resume` | `RUN_ID [--sign --signer ID --key PATH]` | `SUSPENDED`：run_owner 或發起者即可；`STOPPED`：必須由 ROE 的 `test_lead` 簽署（[03 §5.6](03-system-architecture.md#56-中止補償與-resume)） | 0/4/5/7 | M1 |
| `vibecheck run abort` | `RUN_ID --reason TEXT --sign ...` | 設 kill switch。M1：停止圖並設為 `ABORTED`；M4 起走完整的 `abort_handler` | 0/4/7 | M1 |
| `vibecheck run claim` | `RUN_ID --sign ...` | 認領自動觸發的 run（`claim_run`，D7） | 0/4/5/7 | M2 |
| `vibecheck gate list` | `[--run RUN_ID] [--status open\|decided\|expired]` | 列出關卡 | 0 | M2 |
| `vibecheck gate show` | `GATE_ID [--out DIR]` | 輸出呈現包：已叢集、排序，附 file:line、片段、CWE、殘餘風險 | 0/6 | M2 |
| `vibecheck gate approve` | `GATE_ID --decisions decisions.yaml --sign ...` | 逐項 `accept`／`reject`／`needs_info` → 產生 GateRecord 並簽章 → `GateService.submit` | 0/3/4/5/7 | M2 |
| `vibecheck gate reject` | `GATE_ID --reason TEXT --sign ...` | 整個關卡 `REJECTED`（等於全部項目 reject）；理由必填。**G2 不允許整關 reject**（G2 的整關結果只有 `APPROVED` 或 `EXPIRED`；要駁回請用 `gate approve` 逐項 `reject`／`needs_info`），對 G2 執行 → 結束碼 5 | 0/4/5/7 | M2 |
| `vibecheck audit verify` | `RUN_ID \| --engagement ID` | 重算 hash chain，並與錨點比對 | 0/8 | M1 |
| `vibecheck calibrate run` | `--config calibration.yaml [--split calibration\|holdout]` | 執行 Calibration Lab。讀取保留切分時寫入 `holdout_access_log` | 0/3/10 | M2 |
| `vibecheck calibrate rerun-minimal` | `--model-key KEY` | 05 §5.8 的最小重跑集；完成前該模型 w＝0 | 0/10 | M2 |
| `vibecheck calibrate check` | `[--models models.yaml]` | 檢查每個 `model_key` 都在 `valid_for_model_keys` 內，否則列出受影響的桶 | 0/10 | M2 |
| `vibecheck calibrate report` | `CALIBRATION_ID [--format json\|md]` | 輸出 M-1–M-11 與主要假設的結果 | 0/6 | M2 |
| `vibecheck report show` | `RUN_ID` | 摘要 | 0/6 | M2 |
| `vibecheck report export` | `RUN_ID --format json\|sarif\|html --out DIR` | `json`（M2 白箱、M4 完整）、`sarif`（M4）、`html`（M5，靜態檔案） | 0/6/7 | M2/M4/M5 |
| `vibecheck selftest run` | `[--items ST-1,ST-3,...] --out selftest-report.json` | 06 §1.2.1 的自測；任一個 0 門檻失敗 → 10 | 0/10 | M1 |
| `vibecheck licenses check` | `[--lock FILE]` | 鎖檔中每個依賴在 `licenses.yaml` 都要有一列，否則失敗（[06 §2.3](06-security-legal-limitations.md#23-授權登錄表)） | 0/10 | M1 |
| `vibecheck db migrate` | — | 套用 `store/migrations/` 的 SQL | 0/9 | M1 |

- **冪等**：`gate approve` 以 `approval_hash`（決定內容＋被核准產物的 hash）判斷。同一份紀錄再送一次 → 0；關卡已有**不同**的決定 → 7。
- **`--key` 的簽章方式**：M1 只支援本地的加密 Ed25519 PEM（與 `tools/vchlib/crypto.py` 相同的格式）。改用 OpenSSH `ssh-keygen -Y` 或硬體金鑰，列在 §10。原因是 SSH 簽章格式不是「直接對 JCS 位元組做 Ed25519」，要新增一種 `alg`，會改動 D11 [H]。

## 5. 設定檔

### 5.1 檔案、擁有者與驗證點

| 檔案 | schema | 擁有者 | 是否簽署 | 在哪裡驗證 |
|---|---|---|---|---|
| `toolkit.yaml` | [toolkit-config](schemas/toolkit-config.schema.json) | `toolkit_maintainer`；隨部署管理，**不是 run 的輸入** | 否（檔案權限＋部署管線） | 每個行程啟動時；驗證失敗 → 行程拒絕啟動（CLI 結束碼 3） |
| `key-registry.yaml` | [key-registry](schemas/key-registry.schema.json) | 資安團隊，以組織根金鑰簽署 | 是（根金鑰） | `run_init`、G0a、G0b、`run_resume`、`gate approve`、`keys verify`；Z3 收到每個指令時也驗 |
| `engagement.yaml` | [engagement](schemas/engagement.schema.json) | `app_owner` 等（[02 §1.3](02-methodology.md#13-人工關卡一覽)） | 是 | `engagement verify`、`G0a_engagement_check`、每次 resume |
| `roe.yaml` | [roe](schemas/roe.schema.json) | ROE 簽署人 | 是 | `roe verify`、`G0b_roe_check`、`B4_preflight`、Z3 的每個指令 |
| `models.yaml` | [model-registry](schemas/model-registry.schema.json) | `toolkit_maintainer` | 否；它的 hash 寫入 run 紀錄 | 啟動時與 `run_init`；允許清單由已簽署的 engagement 決定 |
| `agents.yaml` | [agent-registry](schemas/agent-registry.schema.json) | `toolkit_maintainer` | 否；hash 寫入 run 紀錄 | `run_init`；家族與血統規則由 `config` 驗證 |
| `tools.yaml` | [tool-registry](schemas/tool-registry.schema.json) | `toolkit_maintainer` | 否；hash 寫入 run 紀錄 | 啟動時（含 adapter 註冊檢查，§2.3）與 `run_init` |

另外還有兩個檔案：
- `calibration.yaml`（M2，`calibration.schema.json`，D15）：在 `run_init` 載入，以 `valid_for_model_keys` 比對。
- `licenses.yaml`（M1）：只在 CI 使用。

**規則** [H]：
- 所有 YAML 一律以 `keys/yamlstrict.py` 載入，**不只是**簽署文件。這樣同一個解析器不會有兩種行為。
- 一個 run 使用的每個設定檔，都把 hash 寫入 run 紀錄與 `config_loaded` 稽核事件。
- run 執行中，設定檔改變**不影響**該 run。resume 時如果發現 hash 不同，run 維持原狀態，結束碼 7，並提示需要開新的 run。
- `models.yaml` 的每個別名要有 `earliest_retirement` 欄位（[model-registry](schemas/model-registry.schema.json)；尚無公告日期時為 `null`）。Gateway 在日期前 30 天內，每次呼叫都寫警告事件；日期已過 → `ModelNotAllowed` [H]。

### 5.2 優先順序

從低到高：`toolkit.yaml` 的預設值 → `engagement.yaml` → `roe.yaml`。後面的只能**收緊**，不能放寬。唯一的例外是 ROE 的 `stop_conditions`：它由 ROE 簽署人簽署，可以覆寫預設值（[03 §7.3](03-system-architecture.md#73-限速與停止條件)）[H]。

| 設定 | 規則 |
|---|---|
| 關卡逾時 | `toolkit.yaml` 的 `gate_timeouts_hours` → engagement 可以縮短；上限是 `resume_deadline`（[03 §6.2](03-system-architecture.md#62-關卡逾時預設值)） |
| 預算 | `toolkit.yaml` 的 `budget_defaults` → engagement 可以設定。**沒有預設的費用上限**：engagement 沒寫 → 需要花費的節點 fail-closed（[03 §11](03-system-architecture.md#11-成本與延遲模型)） |
| 允許的模型 | engagement 的允許清單 ∩ `models.yaml` ∩ `agents.yaml` 的綁定；交集為空的角色 → `run_init` 失敗（`ConfigInvalid`） |
| 停止條件 | ROE 有寫的鍵用 ROE 的值，沒寫的用 `toolkit.yaml` 的預設值 |
| 允許的工具與模式 | `tools.yaml` − `TOOLKIT_DENYLIST` − ROE 的 `denied_modes`，再 ∩ ROE 的 `allowed_tools` |
| 沙箱資源 | 只看 `toolkit.yaml` 的 `sandbox`；run 不能改 |
| CLI 旗標、環境變數 | 不能改上面任何一項 |

### 5.3 環境變數與 secrets

環境變數只放**路徑、參照與 secrets**，不放任何會影響安全行為的設定 [H]。

| 變數 | 行程 | 內容 |
|---|---|---|
| `VIBECHECK_TOOLKIT` | 全部 | `toolkit.yaml` 的路徑 |
| `VIBECHECK_PG_DSN` | Z1 | Postgres 連線字串（secret） |
| `VIBECHECK_CAS_ROOT`、`VIBECHECK_AUDIT_ROOT` | Z1 | CAS 與稽核檔的根目錄 |
| `VIBECHECK_CAS_KEK_REF` | Z1 | CAS 加密金鑰在 KMS 中的參照（KMS 的選型見 §10） |
| `VIBECHECK_LLM_SECRET_<PROVIDER>` | 只有 Gateway | 各供應商的 API 金鑰，例如 `_ANTHROPIC`、`_OPENAI`、`_NVIDIA`、`_Z4`。Gateway 讀取後，以明確參數傳給 LiteLLM；參數名稱以釘選版本的文件為準 |
| `VIBECHECK_Z3_CLIENT_CERT`、`VIBECHECK_Z3_CLIENT_KEY` | Z1 | 連 Z3 的 mTLS 憑證 |
| `VIBECHECK_Z3_SERVER_CERT`、`VIBECHECK_Z3_SERVER_KEY`、`VIBECHECK_Z3_SERVICE_KEY` | Z3 | mTLS 憑證，以及 `z3_executor` 簽署所有權結果用的私鑰（路徑） |
| `VIBECHECK_Z3_SECRET_STORE` | Z3 | 測試帳號與 DB 憑證的 secret store 參照。這些憑證**永遠不離開 Z3** |

- `config_loaded` 事件只記錄變數**名稱**與是否存在，不記錄值。
- 例外訊息與 log 一律經過遮罩函式，遮罩範圍包含上表所有值。
- **Z2 的 job 不繼承任何環境變數**。`AdapterPlan.env` 中含有 secret 樣式的值 → 拒絕。

## 6. 錯誤、重試與冪等

### 6.1 錯誤分類

所有例外都繼承 `VibeCheckError`，並帶有三個屬性：
- `error_class`：寫入 `RunState.errors[].error_class`（[03 §5.1](03-system-architecture.md#51-statepydantic示意)）；
- `retryable`；
- `exit_code`。

節點依下表決定 run 的後果 [H]：

| 例外（`error_class`） | 典型來源 | 可重試 | run 的後果 | 稽核事件 | 結束碼 |
|---|---|---|---|---|---|
| `ConfigInvalid` | `run_init`、行程啟動 | 否 | `FAILED` | `config_loaded`（失敗） | 3 |
| `SchemaInvalid` | Blackboard、設定檔 | 否 | 看節點：LLM 輸出 → 修復 ≤2 次；其他 → `FAILED` | `schema_repair`／`artifact_validation` | 3 |
| `StrictYAMLError` | 簽署文件、設定檔 | 否 | **簽署文件**（engagement、ROE、`key-registry.yaml`、GateRecord）→ 由 `SignatureVerifier` 轉為 `SignatureInvalid`，後果同下一列；**未簽署設定檔** → 同 `ConfigInvalid` | 簽署文件：`signature_invalid`；設定檔：`config_loaded`（失敗） | 簽署文件 4；設定檔 3 |
| `SignatureInvalid`、`RegistryRollback` | G0a、G0b、resume、gate、Z3 | 否 | G0a／G0b → `ABORTED`；resume 或 gate → 維持原狀態 | `signature_invalid`、`engagement_verify_failed`／`roe_verify_failed` | 4 |
| `PolicyDenied` | Policy Engine | 否 | 看動作：CMD 計畫 → 該計畫作廢；工具呼叫 → 該 job `SKIPPED`；resume → 維持原狀態 | `policy_decision`（deny） | 5 |
| `LegalReviewPending` | G0b 的 L-5 | 否 | `SUSPENDED`（`suspended_wait`） | `roe_verify_failed` | 5 |
| `OutsideWindow` | G0b、`B4_preflight` | 否 | `SUSPENDED` | `run_status_changed` | 5 |
| `RedactionMissing` | Gateway | 否 | 該節點失敗 → `FAILED`（這是程式錯誤，正常流程不會發生） | `llm_refused_policy` | 5 |
| `ModelNotAllowed`、`DataClassDenied`、`EndpointDenied` | Gateway | 否 | 該票記為缺票（`missing_votes.reason = policy`）；另寫 `policy_violation` | `llm_refused_policy`、`policy_violation` | 5 |
| `BudgetExceeded` | Gateway、BudgetTracker | 否 | 進 `GB_budget_gate`（`WAITING_GATE`） | `budget_exhausted` | — |
| `ProviderRateLimited` | Gateway | 是（§6.2） | 用盡 → 缺票 | `retry`、`missing_vote` | — |
| `ProviderUnavailable` | Gateway | 是（§6.2） | 用盡 → 同家族 fallback → 缺票 | `retry`、`fallback_used`、`missing_vote` | — |
| `ProviderRefused` | Gateway | 否 | 缺票（`reason = refused`） | `missing_vote` | — |
| `SchemaRepairExhausted` | Gateway | 否 | 看節點（[03 §5.7](03-system-architecture.md#57-節點規格表)）：缺票、空白矩陣或 `MANUAL` | `schema_repair`、`missing_vote` | — |
| `SandboxInfraError` | SandboxRunner | 是（1 次） | 單一工具 → 缺口；W0 或全部 W1 工具 → `FAILED` | `sandbox_job_end` | 9 |
| `SandboxLimitExceeded` | timeout、OOM、輸出超過上限 | 否 | 缺口（`killed_reason`） | `sandbox_job_end` | — |
| `EgressBlocked` | Z2 或 Z3 的網路政策 | 否 | 該 job 的結果丟棄並列為可疑；ST-1／ST-7 計數 | `egress_blocked` | — |
| `ScopeViolation` | Scope Proxy | 否 | 依 03 §7.3：job 停止；指向 ROE 以外主機 → 另寫 `policy_violation` | `egress_blocked`、`policy_violation` | 5 |
| `OwnershipFailed` | B0、`B4_preflight` | 否 | 該目標 `SKIPPED`；全部目標失敗 → `B6_report`（M1 是 `m1_finish`） | `ownership_check` | — |
| `Z3Unavailable` | Executor 用戶端 | 是（§6.2） | 用盡 → `SUSPENDED` | `run_status_changed` | 9 |
| `StopConditionTriggered` | Executor | 否 | `abort_handler` → `STOPPED` | `stop_condition` | — |
| `RestoreFailed` | Snapshot | 是（2 次） | `abort_handler` → `FAILED`，並通知聯絡人 | `restore_failed` | — |
| `IntegrityError` | CAS、稽核、checkpoint 反序列化 | 否 | `FAILED` | `policy_violation` | 8 |
| `AuditUnavailable` | AuditWriter | 立即重試最多 3 次 | 仍失敗 → 該節點失敗 → `FAILED`（沒有稽核就不繼續） | —（寫入行程 log，並發出告警） | 9 |
| `StoreUnavailable` | Postgres | 是（§6.2） | 用盡 → 行程結束；重啟後從 checkpoint 續跑 | — | 9 |
| `InternalError` | 其他 | 否 | `FAILED` | `run_status_changed` | 1 |

- 每筆 `ErrorRecord` 寫入 `node`、`error_class`、`attempt`，以及 `detail_ref`（詳細內容放在 CAS，已遮罩）。
- 例外訊息不含 secrets、prompt 本體或目標回應本體，只含 hash 與位置。

### 6.2 重試與退避

| 情況 | 策略 [H] | 上限 | 用盡後 |
|---|---|---|---|
| LLM 429 | 依 `Retry-After`（最多等 60 秒）；沒有這個標頭就指數退避 2、4、8 秒＋full jitter | 3 次（[03 §5.9](03-system-architecture.md#59-fan-outfan-in重試缺票)） | 缺票 |
| LLM 5xx、逾時、連線錯誤 | 指數退避 2、4、8 秒＋jitter | 3 次 | `models.yaml` 的同家族 fallback（各自再算 3 次）→ 缺票 |
| LLM 輸出不符 schema | 把驗證錯誤送回同一模型修復 | 2 次 | 看節點（§6.1） |
| Z2 基礎設施失敗 | 立即重試 | 1 次 | 缺口或 `FAILED` |
| `W4_exec` | 重試 | 1 次 | `ERROR` |
| Z3 無法連線 | 5、15、45 秒 | 3 次（[03 §5.4](03-system-architecture.md#54-b-子圖g0b-到-g4)） | `SUSPENDED` |
| `B4_s2_restore` | 立即重試 | 2 次 | `abort_handler` |
| Postgres 暫時性錯誤 | 0.5、1、2、4、8 秒 | 5 次 | 行程結束 |
| **絕不重試** | 驗章失敗、政策拒絕、範圍違規、停止條件、`BudgetExceeded`、完整性失敗、黑箱測試請求本身（避免超出 `max_requests`；工具自己的重試也要關閉） | — | — |

- 每次重試都寫 `retry` 事件，內容包含次數與原因。
- 退避時間計入節點的時限，但不計入 LLM 預算。

### 6.3 冪等鍵

| 對象 | 冪等鍵 [H] | 已存在時 |
|---|---|---|
| run | `run_id`（UUIDv7） | `run_init` 略過建立 |
| CAS 物件 | `sha256`（明文內容） | 直接回傳同一個 ref |
| Blackboard 發布 | 物件 JCS 的 sha256 | 回傳同一個 ref（append-only） |
| LLM 請求 | sha256（模型 ID＋版本＋參數＋prompt hash＋schema hash）（[03 §5.8](03-system-architecture.md#58-節點邊界規則)） | 從 CAS 讀回應，不重新呼叫、不重複計費 |
| Sandbox job | sha256（image digest＋argv＋輸入 hash）（[03 §2](03-system-architecture.md#2-部署與信任區)） | 讀已存在的結果 |
| 所有權驗證 | `(run_id, target_id, batch_id)` | 讀已簽署的結果 |
| S2 快照 | `run_id + job_id` | 略過 |
| B4 job | `executed_jobs` 與 `JobStatus` | `EXECUTED` 不重跑；`EXECUTING` 但沒有結果 → `INTERRUPTED`（[03 §5.6](03-system-architecture.md#56-中止補償與-resume)） |
| 開關卡 | `(run_id, gate, round)` | 不重複開啟、不重複通知 |
| GateRecord | `approval_hash` | 同一份 → 成功；不同 → 7 |
| 稽核事件 | `idempotency_key` ＝ `run_id:node:<上列鍵>` | 仍然寫入（append-only）；讀取與驗證時去重 |

## 7. 持久化

### 7.1 LangGraph checkpointer

- **正式環境**使用 PostgresSaver，以 `thread_id` 為鍵 [V][E:orchestration-05]，套件是 langgraph-checkpoint-postgres 3.1.2，依賴 psycopg [V][E:orchestration-42]。
  - psycopg 是 LGPL-3.0，屬於 **M1 前的法務閘門**：未確認前只做內部部署、不散布映像（[07 §3](07-roadmap.md#3-入口閘門法務與查證)）。
- **測試**使用 InMemorySaver 與 SqliteSaver [V][E:orchestration-05]。SqliteSaver 來自 langgraph-checkpoint-sqlite 3.1.1（MIT）[V][E:orchestration-59]，只是測試依賴。
- LangGraph 本身鎖定 1.2.12（MIT）[V][E:orchestration-01]。
- **設計規則** [H]：
  - `thread_id = run_id`；子圖使用 LangGraph 預設的 namespace。
  - **state 只放 ref 與小型結構**（`RunState`，[03 §5.1](03-system-architecture.md#51-statepydantic示意)），不放程式碼、prompt、回應或測試日誌。C 級內容只存在 CAS（加密）。
  - **checkpoint 不能當作授權依據**。resume 值（`gate_record_id`）一律回到 Postgres 讀 GateRecord 並重新驗章（[03 §6](03-system-architecture.md#6-人工關卡服務)）。
  - interrupt 前沒有副作用，因為 resume 會從節點開頭重新執行 [V][E:orchestration-04]。
  - 每個 checkpoint 另寫一筆 metadata，格式是 [checkpoint-metadata.schema.json](schemas/checkpoint-metadata.schema.json)：`checkpoint_id`、`run_id`、`thread_id`、`parent_checkpoint_id`、`node`、`created_at`、`state_sha256`（`RunState` 的 JCS hash）、`schema_version`、`run_status`、`pending_interrupt`、`encrypted`、`authoritative`（一律 `false`，表示 checkpoint 不是授權依據）。反序列化時重算 `state_sha256`，不符 → `IntegrityError`。
  - `RunState` 的 schema 不向後相容時，要在 `graph/migrations.py` 提供 `vN → vN+1` 的純函式，並附測試。
  - 限制 checkpoint 資料表的存取：只有 Z1 的服務帳號可以寫；Gate Service 只能讀（[06 §1.6](06-security-legal-limitations.md#16-人工關卡的完整性與簽章d11)）。

### 7.2 Postgres 資料表（Z1）

由 `store/migrations/NNNN_*.sql` 建立 [H]：

| 資料表 | 內容 |
|---|---|
| `runs` | run 紀錄：狀態、run_kind、發起者、各設定檔的 hash、`redaction_map_ref`、`key_registry_ref`、`resume_deadline` |
| `run_audit_anchors` | `run_id`、`seq`、行 hash、時間 |
| `gate_records` | GateRecord 本體（JCS）、分離式簽章、`approval_hash`、驗章結果 |
| `gate_spot_checks` | ASI09 抽查：抽中的關卡、複核者、期限、結果 |
| `blackboard_index` | `run_id`、`kind`、`ref`、schema `$id`、provenance、建立時間 |
| `llm_cache` | 快取鍵 → 回應 ref、token 數、費用 |
| `sandbox_jobs` | job ID → `SandboxResult` ref |
| `budget_ledger` | 每次 reserve 與 record（M2） |
| `key_registry_state` | 上次接受的版本與 hash（防回滾） |
| LangGraph 的資料表 | 由 checkpointer 自己建立；本工具包的遷移**不修改**這些資料表 |

### 7.3 CAS 配置

```text
$VIBECHECK_CAS_ROOT/
  sha256/ab/cd/abcd…ef          # 密文（AEAD；演算法與 KMS 見 §10）
  sha256/ab/cd/abcd…ef.meta.json
      # {media_type, data_class, retention_days, created_at, legal_hold, kek_id, size}
```

- ref ＝ 明文的 sha256。`get()` 先解密，再重算 hash。
- 寫入的方式：先寫暫存檔，再原子性地 rename。已存在 → 不覆寫。
- **Z3 有自己的儲存區**，不同步到 Z1：`oracle_capture` 的 before 內容、session 狀態。Z1 只收到 hash 與比對結果（[03 §7.6](03-system-architecture.md#76-db-快照種子資料與-oracle-唯讀存取)）。

### 7.4 稽核檔配置

```text
$VIBECHECK_AUDIT_ROOT/<engagement_id>/
  engagement.jsonl              # 跨 run 事件
  runs/<run_id>.jsonl           # 每個 run 一個檔
  runs/<run_id>.lock            # Audit Writer 的檔案鎖
```

- 欄位、hash chain、每 500 個事件錨定：見 [03 §13.1](03-system-architecture.md#131-稽核事件格式audit-eventschemajsonh)。
- 事件類型的 enum 以 03 §13.2 為準，程式中放在 `models` 的產生碼中（`audit-event.schema.json`）。
- 一個 run 的檔案不輪替。run 結束時寫最後一個錨點。
- 可選擇另外寫到 WORM 儲存或外部系統；是否需要，由 engagement 決定（§10）。

### 7.5 保留與刪除

- 保留期限設定在 `toolkit.yaml` 的 `retention` 區塊（[toolkit-config](schemas/toolkit-config.schema.json)），寫入 CAS 物件時記在 meta。預設值 [H] 如下，**實際值需要法務決定（§10）**：
  - `p_days: 365`（P 級）；
  - `c_days_after_run_end: 90`（C 級）；
  - `audit_days: 1095`（稽核檔與 GateRecord；必須 ≥ 兩個內容期限）；
  - `checkpoint_days_after_run_end: 30`、`checkpoint_keep_last: 1`；
  - `legal_hold: []`（列入的範圍一律不刪）。
- `ContentStore.gc(now)` 只刪除「超過保留期限、而且沒有 `legal_hold`」的物件。每次刪除都寫稽核事件。
- 刪除 C 級內容之後，稽核檔中的 hash 仍然保留，所以 `audit verify` 不受影響。

## 8. 測試

### 8.1 測試層級與目錄

| 層級 | 目錄 | 內容 | CI 線（§8.4） |
|---|---|---|---|
| 既有：文件驗證 | `tests/test_validator.py`、`tests/test_adjudicate.py`、`tests/fixtures/`、`tests/conftest.py`（pytest） | `test_validator.py`：validator 的負面案例、基準、denylist 檢查、RFC 8785 測試向量；`test_adjudicate.py`：05 §4.2 的 R0–R13 決定表與註記（`annotations`） | 既有的 `.github/workflows/validate.yml`（ubuntu、windows × Python 3.11、3.13）；併入 `fast` |
| 單元 | `tests/unit/` | 每個模組各自測試；外部相依以 Protocol 的假物件取代 | `fast` |
| 性質 | `tests/property/` | Hypothesis：JCS 的穩定性、嚴格 YAML、稽核竄改偵測、Clusterer 與順序無關、Aggregator 的規則性質（例如 Lane A 的結果永遠不會是 `CONFIRMED_*`；R1 一定勝過投票） | `fast` |
| 契約 | `tests/contract/` | schema 往返（§3）、adapter 註冊（§2.3）、`vchlib` 與 `vibecheck` 同一組測試向量的結果相同、RFC 8785 附錄的測試向量 | `fast` |
| 架構 | `tests/arch/` | import 規則（§1.2）、映像內容（§1.3） | `fast` |
| 負面安全 | `tests/security/` | §8.2 的必須拒絕清單 | `security` |
| 整合 | `tests/integration/` | 以真的 Postgres、gVisor、分開的 Z1／Z3 網路，對 §8.3 的範例應用端到端執行 | `integration` |
| 自測 | `selftest/` | 06 §1.2.1 的 ST-1–ST-7 | `selftest` |

- **LLM 的假供應商**：Gateway 內有一個 `ProviderTransport` 接縫：
  - 正式環境：`LiteLLMTransport`；
  - 測試：`RecordedTransport`，以 §6.3 的 LLM 快取鍵讀取錄好的回應，並**計數**收到的請求數（用來證明 fail-closed 時送出 0 個請求）。
- CI 只用 `RecordedTransport`。對真實供應商的冒煙測試放在 `manual` 線，需要金鑰（§10）。
- `tests/` 目前只有上表「既有」一列的測試（`test_validator.py`、`test_adjudicate.py`）。上表其他目錄是 M1 起新增的；既有測試留在原位。
- 正式程式使用 Python 3.12（§1.1），`fast` 線另跑 3.11 與 3.13，與 `validate.yml` 的矩陣一致。

### 8.2 M1 必須拒絕清單（負面安全測試）

每一項都是 `tests/security/test_n<NN>_*.py`，而且要**斷言**稽核事件與結束碼。第三欄對應 [07 §4](07-roadmap.md#4-各里程碑) 的出口準則。

| # | 輸入 | 預期結果 | 07 準則 |
|---|---|---|---|
| N-01 | W0 完成前，也就是沒有 `redaction_map_ref` 時呼叫 `ModelGateway.complete` | `RedactionMissing`；假供應商收到 0 個請求 | M1-X2 |
| N-02 | 模型不在 engagement 的允許清單中 | `ModelNotAllowed`；0 個請求 | M1-X2 |
| N-03 | 把 C 級切片送給 `data_classes` 不含 C 的模型（例如 `nemotron_cloud`） | `DataClassDenied`；0 個請求 | M1-X2 |
| N-04 | 改動 `api_base`、對 `gpt_flagship` 設 `store: true`、傳入白名單以外的參數 | `EndpointDenied` | M1-X2 |
| N-05 | repo 含 canary secret（放在程式、註解、設定檔、git 歷史中） | 任何 LLM 請求本體中都沒有 canary（對 CAS 全文搜尋）；`secret_detected` 只含位置與 hash | M1-X3（ST-3） |
| N-06 | 路徑黑名單中的檔案（`.env*`、金鑰檔、auth-state） | W0 之後的任何產物、SARIF、切片中都沒有這些檔案的內容 | M1-X2 |
| N-07 | ROE 有兩個 `targets:` 鍵 | `StrictYAMLError` → `signature_invalid`；結束碼 4 | M1-X2 |
| N-08 | anchor／alias、自訂 tag、NaN、超過 2^53 的整數、未加引號的 `yes`／時間 | 同 N-07 | M1-X2 |
| N-09 | 用未登錄的金鑰簽署；或簽署人不在 ROE 的 `signatories` 中 | 驗章失敗；結束碼 4 | M1-X2 |
| N-10 | 金鑰以 `compromised` 撤銷：撤銷前後的簽章各一份 | 兩份都無效；若撤銷原因是 `role_change`，撤銷前的有效、之後的無效 | M1-X2 |
| N-11 | `key-registry` 的版本比上次接受的小；或根簽章不是 `toolkit.yaml` 釘選的根金鑰 | `RegistryRollback`／`SignatureInvalid` | M1-X2 |
| N-12 | 簽署人的角色不符合該文件的要求 | `role_mismatch` | M1-X2 |
| N-13 | 簽署時間在 `not_before` 之前或 `not_after` 之後 | 無效 | M1-X2 |
| N-14 | 簽署後改動一個值（例如 `max_rps`） | 無效。對照組：只調整鍵的順序或 YAML 格式 → **仍然有效**（JCS） | M1-X2 |
| N-15 | 直接寫 checkpoint DB，放入偽造的 resume 值；或以不存在、未簽章的 `gate_record_id` 呼叫 `Command(resume=…)` | run 不前進；`signature_invalid` | M1-X2 |
| N-16 | 目標沒有 DNS TXT 或 well-known token；token 屬於另一個 engagement；檢查後 DNS 改指向別的 IP | 該目標 `OwnershipFailed`；對新 IP 的連線被 Scope Proxy 擋下（IP 已固定） | M1-X2 |
| N-17 | `http_get` 的目標主機不在 ROE 中；目標回應 30x，導向 ROE 以外的主機、`169.254.169.254` 或內網位址 | `ScopeViolation`；外部封包紀錄中 0 筆出站 | M1-X3（ST-1） |
| N-18 | M1 的 `http_get` 使用 GET 以外的方法；路徑在 ROE 的 `exclusions` 中（例如 `/api/payments/x`） | 拒絕 | M1-X2 |
| N-19 | Z2 job 內嘗試：DNS 查詢、HTTP 連外、raw socket、讀 host 路徑、連 metadata 端點、掛載 Docker socket | 全部失敗，且有 `egress_blocked` 紀錄 | M1-X3（ST-7） |
| N-20 | Z2 job 的輸出超過 200 MiB、執行逾時、記憶體不足 | `killed_reason` 依序為 `output_too_large`／`timeout`／`oom`；列為缺口 | M1-X2 |
| N-21 | 從 Z1 映像直接連目標 | 網路層拒絕（整合測試線） | M1-X3（ST-1） |
| N-22 | 稽核檔被修改一行、刪除一行、插入、交換順序、截斷尾端；錨點被改 | `audit verify` 結束碼 8。性質測試 ≥1,000 個隨機竄改，偵測率 100% | M1-X5 |
| N-23 | 改動 CAS 物件的一個位元組 | `IntegrityError` | M1-X5 |
| N-24 | 非 `lane_a` 的 `run start` 沒有簽章，或簽署人是自動化帳號 | 拒絕（D7）；結束碼 5 | M1-X2 |
| N-25 | ROE 的 `allowed_tools` 含 `TOOLKIT_DENYLIST` 的模式；ROE 在時間窗外；ROE 已過期 | 依序：`roe verify` 拒絕；`SUSPENDED`；跳過 B 階段並記為缺口 | M1-X2 |
| N-26 | ROE 的 `legal_review` 不符 L-1–L-4；L-5（聲明者就是 `test_lead`） | `roe_verify_failed`；L-5 → `SUSPENDED` | M1-X2 |
| N-27 | engagement 允許的模型不在 `models.yaml` 中；fallback 跨家族 | `ConfigInvalid` | M1-X2 |
| N-28 | `toolkit.yaml` 的根金鑰指紋與登錄不符 | 行程拒絕啟動 | M1-X2 |
| N-29 | 鎖檔新增一個依賴，但 `licenses.yaml` 沒有對應的列；鎖檔的 hash 被改；鎖檔含 LiteLLM 1.82.7 或 1.82.8 [V][E:orchestration-31] | `licenses check`／安裝失敗 | M1-X7 |
| N-30 | 送給 Z3 的指令附的 ROE 被竄改，或換成另一份 ROE | Z3 重新驗章後拒絕（§1.3） | M1-X2 |
| N-31 | Z3 映像中出現 `gateway`、`litellm` 或 LLM 金鑰變數 | 映像內容測試失敗 | M1-X2 |

### 8.3 範例應用（整合測試的目標）

放在 `tests/targets/`。每個應用都有「植入版」與「修正版」，並附真值檔 `truth.yaml`（位置、桶、CWE，以及利用測試）[H]。

| 應用 | 內容 | 對應 | 首次使用 |
|---|---|---|---|
| `invoices-app` | Express（TypeScript）＋PostgreSQL 的多租戶發票 API。`routes/invoices.ts:42` 的 `GET /api/invoices/{id}` 沒有檢查租戶（IDOR）；`invoices` 資料表沒有 RLS；角色 `tenantA_user`、`tenantB_user`。另外植入的漏洞讓總數 ≥10，以符合 ST 的語料要求 | [04 §6.1](04-threat-to-testcase.md#61-範例-awebapi-的-idorbola) 範例 A（TC-012-01、K-005） | M1（W0／W1／B0）、M2（W2–W5）、M4（B3–B5） |
| `support-agent-app` | FastAPI 的客服 agent：`refund(order_id)` 工具、可上傳 PDF、`agent_tool_calls` 資料表。它的上游 LLM 在 CI 中是**我方的腳本式假模型**：植入版以固定種子、固定機率遵循 PDF 內的指令；修正版在呼叫 `refund` 前要求人確認 | [04 §6.2](04-threat-to-testcase.md#62-範例-bllm-功能的間接-prompt-injection-與工具濫用) 範例 B（TC-031-01、K-011，n＝60、k＝0 規則） | M1（W0／W1）、M2（白箱）、M5（完整） |
| `notes-rls-app` | 類似 Next.js＋Supabase 的組合：PostgreSQL 的 RLS 政策錯誤、前端 bundle 內含金鑰、`package.json` 中有一個幻覺套件名稱 | 05 §5.1 的重點類別；G-07 需要的第 3 個應用 | M1（W0／W1 的套件存在性）、M4（G-07） |
| `canary-server` | 對應 ROE 的 `tgt-canary`：記錄所有請求；另有一個「ROE 以外」的接收器，**任何一次**命中都算 ST-1 失敗 | [docs/examples/roe.yaml](examples/roe.yaml) | M1 |
| 故障注入代理 | 放在目標前面，可以注入 5xx、延遲、429、健康檢查失敗、PII 回應 | 03 §7.3 停止條件表的每一列 | M4 |

- **自測的 twin**：`selftest/injected/<app>-clean` 與 `<app>-injected`。
  - 以 `invoices-app` 與 `support-agent-app` 為底。
  - 每個 twin ≥10 個已知漏洞（`selftest-report` 的 `corpus.twins[].known_vulns`），≥1 個 canary secret。
  - 每個注入向量至少 3 個樣本；M1 使用 INJ-CMT、INJ-PR、INJ-FN、INJ-SARIF、INJ-DEP（[06 §1.2.1](06-security-legal-limitations.md#121-工具包自測計畫植入注入的-repo-h)）。
- **與 05 語料的關係**：這些應用是**開發者已知的**。它們最多只能放進校準切分，**不得**放進保留切分或哨兵子集，以避免汙染（[05 §5.1](05-bias-calibration.md#51-語料)）。
- 所有權驗證：
  - `invoices-app` 以 DNS TXT 驗證（`tgt-staging-api`），由測試環境內的權威 DNS 提供；
  - `notes-rls-app` 以 well-known path 驗證（`tgt-staging-app`）。

### 8.4 CI 線

| 線 | 觸發 | 執行環境 | 內容 | 阻擋合併 |
|---|---|---|---|---|
| `fast` | 每個 commit | 一般 runner | lint、型別檢查、單元、性質（每個性質 200 例）、契約、架構、`licenses check`、模型產生碼的 diff | 是 |
| `security` | 每個 PR | 自架 runner，具備 gVisor 與分開的網路 [H] | §8.2 全部、性質測試加量（N-22 ≥1,000 例） | 是 |
| `integration` | 合併到主幹、每晚 | 同上＋Postgres＋Z3 映像＋§8.3 的應用 | 端到端（07 各里程碑的範例 A／B 準則）、kill 與 resume 測試 | 主幹失敗 → 停止發布 |
| `selftest` | 每晚；每次更換模型、prompt 或 Commander 規則；發布前 | 同上 | ST-1–ST-7（依里程碑）；產出 `selftest-report.json` | **任一個 0 門檻失敗 → 阻擋發布** |
| `manual` | 手動 | 有供應商金鑰的環境 | 真實供應商的冒煙測試；Nemotron 端點的 structured output 測試集（G-05） | 否 |

- GitHub Actions 一律鎖 commit SHA；binary 以 cosign 驗證（[06 §1.5](06-security-legal-limitations.md#15-供應鏈)）。
- 掃描器在沒有 CI secrets 的環境中執行。
- 本工具包的 CI 線（上表）與 03 §12 的 Lane A／Lane B 不同：Lane A／B 是**產品功能**，也就是對受測 repo 執行的線。

### 8.5 各里程碑的測試重點

| 里程碑 | 新增的單元／性質／契約測試 | 新增的負面安全測試 | 新增的整合與自測 |
|---|---|---|---|
| M1 | keys、config、store、audit、policy（G0a／G0b）、gateway 的前置檢查、sandbox、scope_proxy | N-01–N-31 | `invoices-app` 的 W0→W1→G0b→B0；每個節點邊界 kill＋resume；ST-1、ST-3、ST-7 |
| M2 | slicer、cluster、aggregator（決定表每一列至少一個案例，以及 05 §4.2 的所有例子）、budget、gates、calibration 的統計函式（Wilson、bootstrap、McNemar，以已知數值驗證） | 偽造或重送 GateRecord；職責分離；G2 逾時；Lane A 的結果進入 `CONFIRMED_*`（必須為 0）；缺少 `calibration.yaml` 時 w＝0 | 範例 A 白箱；ST-2、ST-4、ST-5；Calibration Lab 端到端（小型語料） |
| M3 | B1 的 diff、B2 merger 的確定性部分、crosswalk 驗證 | G3 駁回種子威脅時沒有理由 → 拒絕；未處置的 `b1_diff` 項目 → 不開 G3 | 範例 A／B 的威脅模型；INJ-DOC |
| M4 | SafetyClassifier（04 §5 虛擬碼的每個分支）、產物驗證、每個 adapter 的 `render`／`parse` | S3 不進 G4；S2 沒有 G5 或還原演練 → 不執行；`EXECUTING` 的 job 不自動重跑；ST-6 | 範例 A 的 TC-012-01；03 §7.3 的每個停止條件；S2 快照→執行→還原；還原失敗；INJ-HTTP；G-07 pilot |
| M5 | 機率判定（04 §4.4 的上界公式，以已知數值驗證）、Relay 的回合與花費上限 | Relay 使用 ROE 以外的模型、超過回合或花費上限 → 拒絕 | 範例 B 的 TC-031-01；INJ-LLMAPP；promptfoo 出站測試 |

## 9. 完成定義（Definition of Done）

### 9.1 各里程碑

每個里程碑都要滿足以下全部條件，才算完成 [H]：
1. [07 §4](07-roadmap.md#4-各里程碑) 的出口準則，每一條都有自動化測試或附在驗收包中的報告。「有值」類的準則，要附原始資料。
2. §8.5 的測試全部通過。[selftest-report.json](schemas/selftest-report.schema.json) 中，當期的每個 ST 項目都是 `status: RUN` 且 `passed: true`，`overall_passed: true`（M1：ST-1、ST-3、ST-7）。`NOT_RUN` 視為不通過。
3. 若修改了任何範例：`python tools/sign_examples.py` 與 `python tools/validate_schemas.py` 都已重跑並通過（§3 第 7 條）。
4. 該里程碑的入口法務閘門都已結案：確認，或以設定證明該元件已停用（[07 §3](07-roadmap.md#3-入口閘門法務與查證)）。
5. `licenses.yaml`、SBOM、鎖檔已更新；新依賴已在 [06 §2.3](06-security-legal-limitations.md#23-授權登錄表) 有對應的列（由該文件的維護者更新）。
6. 已依 06 §1.1 更新工具包自己的威脅模型。
7. 03 與本文件中，對應的介面沒有未記錄的偏離。有偏離時，先更新文件再合併。
8. 驗收包（CAS ref 清單）包含：測試報告、自測報告、稽核驗證結果、該里程碑的範例 run 的 `run_id`。

### 9.2 M1 前兩週的工單

以 3–4 位工程師為前提 [H]。依序排列；同一週內，前置條件相同的工單可以並行。

| # | 週 | 工單 | 前置 | 驗收測試 |
|---|---|---|---|---|
| T-01 | 1 | 專案骨架：`pyproject.toml`、`src/` 配置、含 hash 的鎖檔、`licenses.yaml`、`vibecheck licenses check`、CI 的 `fast` 線 | — | N-29：新增一個沒有登錄的依賴 → CI 失敗；竄改一個 hash → 安裝失敗；鎖檔含 LiteLLM 1.82.7 → 失敗 |
| T-02 | 1 | `errors` 模組：例外、`error_class`、結束碼；§6.1 的表格改寫成測試資料 | T-01 | 對表格驅動的測試：每個例外的結束碼與 run 後果都和 §6.1 一致 |
| T-03 | 1 | `models`：以 datamodel-code-generator 產生 `_generated/`；重新產生後做 diff 的 CI 步驟；契約往返測試 | T-01 | `docs/schemas/examples/` 全部往返後逐位元組相同；只改 schema、不重新產生 → CI 失敗 |
| T-04 | 1 | `keys`：移植 canonical、yamlstrict、crypto；`KeyRegistry`、`SignatureVerifier` | T-03 | RFC 8785 附錄的測試向量；與 `rfc8785` 套件交叉比對 [V][E:orchestration-45]；N-07、N-08、N-10–N-14 |
| T-05 | 1 | `audit`：`AuditWriter`（檔案鎖、seq、prev_hash、錨定）＋`vibecheck audit verify` | T-03 | N-22（≥1,000 個隨機竄改，100% 偵測）；兩個行程同時寫入 → seq 連續、沒有交錯 |
| T-06 | 1 | `store`：`ContentStore`（檔案系統＋meta；加密先以 `KekProvider` 介面加上測試用實作）、Postgres 遷移、`Blackboard`、`vibecheck db migrate` | T-03 | N-23；同一內容 put 兩次 → 同一個 ref；schema 不合法的物件 → `SchemaInvalid`，而且沒有寫入任何東西 |
| T-07 | 2 | `config`：7 種設定檔的載入、跨檔規則、優先順序、環境變數；`vibecheck config validate`、`keys verify`、`keys show`、`keys fingerprint` | T-04 | `docs/examples/` 全部通過；N-11、N-27、N-28；CLI 不能放寬設定（以旗標嘗試 → 結束碼 2） |
| T-08 | 2 | `policy`：`verify_engagement`、`verify_roe`（含 L-1–L-6、`TOOLKIT_DENYLIST`、時間窗）、`check`、`resolve_target`；`vibecheck sign`、`engagement verify`、`roe verify` | T-04、T-07 | 以測試金鑰簽署 `docs/examples/` 的 engagement 與 ROE → 通過；N-09、N-12、N-25、N-26 |
| T-09 | 2 | `graph` 骨架：`RunState`、`run_init`、`G0a_engagement_check`、暫時的 `m1_finish` 節點；PostgresSaver 與 SqliteSaver；`vibecheck run start`、`run status`、`run abort`、`run resume` | T-05、T-06、T-08 | N-15、N-24；在每個節點邊界 kill 行程再 resume → 最終產物的 hash 與不中斷的 run 相同，稽核去重後沒有重複事件 |
| T-10 | 2 | `sandbox`：以 gVisor（runsc，版本寫進 SBOM）執行、`network: none`、資源上限、job ID、輸出收集與遮罩 | T-06 | N-19、N-20；同一個 spec 執行兩次 → 只跑一次；runsc 的版本出現在 SBOM 中 |
| T-11 | 2 | `gateway`：`ModelGateway.complete` 的前置檢查、`RecordedTransport`、LLM 快取、schema 降階與修復、重試策略 | T-06、T-07 | N-01–N-04（假供應商收到 0 個請求）；429 會遵守 `Retry-After`；修復 2 次後 → `SchemaRepairExhausted` |
| T-12 | 2 | `selftest` 骨架＋`selftest/injected/invoices-app-{clean,injected}` 的初版（先只有 canary secret 與 INJ-CMT） | T-10 | `vibecheck selftest run --items ST-7` 產出通過 schema 驗證的 `selftest-report.json`，其中 ST-7 為 `status: RUN`、`passed: true` |

**M1 其餘的工單**（第 3 週起，依序）：
- T-13 `W0_inventory`：secrets 掃描 adapter、路徑黑名單、遮罩對照表、`inventory:*`、SBOM、`redaction_map_ref` 寫入 run 紀錄。
  - 驗收：`invoices-app` 的 inventory 列出 `routes/invoices.ts:42`，而且 `invoices` 的 RLS 為「無」；N-05、N-06。
- T-14 `W1_static` 與 `LA_static`：W1 的 adapter、合併 SARIF 並遮罩、套件存在性（經 Z2 的 metadata 鏡像）。
  - 驗收：每個工具都產出 SARIF；單一工具失敗會列為缺口；`notes-rls-app` 的幻覺套件被標出。
  - `inventory:express` 所依賴的 SAST 引擎輸出格式，也在這張工單以測試確認。
- T-15 `scope_proxy`＋`executor`（最小版）＋mTLS 通道：`verify_ownership`、`http_get`、以 `z3_executor` 金鑰簽署結果。
  - 驗收：N-16–N-18、N-21、N-30、N-31。
- T-16 `G0b_roe_check`、`B0_ownership_verify`、`suspended_wait`、`run_resume` 的完整流程。
  - 驗收：`invoices-app` 與 `notes-rls-app` 的所有權驗證通過；時間窗外 → `SUSPENDED`，時間窗內 resume 成功。
- T-17 自測擴充到 ST-1、ST-3，並加入其餘的 M1 注入向量。
- T-18 Z2 維運：CVE 訂閱、升級流程文件、同一台主機不混用不同 engagement 的 job（G-11）。

## 10. 尚未決定／需使用者決定

以下事項本文件**沒有替使用者決定**。未決定之前，各項的預設做法寫在「未決定時」欄 [H]。

| # | 事項 | 需要誰決定 | 未決定時 | 影響的里程碑 |
|---|---|---|---|---|
| U-01 | 雲端 LLM 供應商、帳號與 API 金鑰（Anthropic、OpenAI、NVIDIA），以及是否簽 ZDR | 使用者、`app_owner` | CI 只用 `RecordedTransport`；M2 的多家族審查無法在真實模型上執行 | M2 |
| U-02 | 自架 Nemotron 與 gpt-oss 的 GPU 與主機（Z4）：數量、型號、機房 | 使用者 | C 級資料只能送到已簽 ZDR 的雲端模型；若都沒有，C 級 repo 無法做多家族審查 | M2 |
| U-03 | 法務閘門（[07 §3](07-roadmap.md#3-入口閘門法務與查證)）：Anthropic 條款、TruffleHog、psycopg 的散布形式、Semgrep 規則與 CodeQL、NIM 用途、OpenAI 條款、PrimeVul、k6、OWASP CC BY-SA | `legal_reviewer` | 對應的元件停用（該表的「未確認則」欄） | M1–M5 |
| U-04 | 保留期限（§7.5）與是否需要外部 WORM 錨點 | 法務、engagement | 使用 §7.5 的預設值；錨點只寫在 Postgres（只能偵測意外損壞與單點竄改，[06 §3](06-security-legal-limitations.md#3-做不到不承諾的事) 第 16 條） | M1 |
| U-05 | CAS 加密所用的 KMS 與 AEAD 演算法 | 使用者的資安團隊 | 測試用的 KEK 實作只允許在 `fast` 線與 `security` 線使用；**正式部署不得在沒有 KMS 的情況下啟動** | M1 |
| U-06 | 核准者的簽章方式：本地 PEM（M1 預設）、OpenSSH `ssh-keygen -Y`、硬體金鑰 | 資安團隊 | 只支援本地加密 PEM；改用其他方式需要修改 D11 與 `key-registry` 的 `alg` | M1–M2 |
| U-07 | 組織根金鑰的產生與保管、金鑰登錄的發行流程 | 資安團隊 | 只有測試用的根金鑰；正式 engagement 無法啟動 | M1 |
| U-08 | Z2 使用 gVisor 還是 Firecracker；Z1／Z2／Z3 的主機與網路配置 | 使用者、維運 | M1 以 gVisor（runsc）實作與測試；Firecracker 延後 | M1 |
| U-09 | 關卡通知的管道（Email、聊天工具） | 使用者 | 只有 `gate list` 輪詢；逾時仍照 03 §6.2 計算 | M2 |
| U-10 | Calibration 語料的標註人力（兩位標註者＋仲裁者）與預算（05 §5.1） | 使用者 | M2 的出口準則 M2-X1 無法完成 | M2 |
| U-11 | `claude_haiku`（Claude Haiku 4.5，最早 2026-10-15 退役 [V][E:providers-49]）的替代模型 | `toolkit_maintainer`＋使用者 | 退役前 30 天起 Gateway 發出警告；退役後該別名停用，`claude_sonnet` 沒有 fallback；替代模型要先完成 05 §5.8 的最小重跑 | M2 |
| U-12 | GPT-6 Astra／Sol 由哪一個擔任 `gpt_flagship` [P][E:providers-31] | 使用者 | 別名先保留、不指定模型 ID；M2 的 manual 線確認後才填入 | M2 |
| U-13 | M4 黑箱工具使用的 HTTP 攔截式 proxy 實作（ZAP、Playwright 等工具要經 Scope Proxy） | `toolkit_maintainer` | M1 的 Scope Proxy 只服務 Executor 自己的 HTTP 用戶端（httpx 0.28.1，BSD-3-Clause [V][E:orchestration-57]；DNS 使用 dnspython 2.8.0，ISC [V][E:orchestration-58]） | M4 |
| U-14 | 鎖檔工具（pip 的 hash 檢查模式、或其他工具） | `toolkit_maintainer` | 以 pip 的 hash 檢查模式實作；它的行為以 T-01 的驗收測試證明，不另外引用文件 | M1 |
