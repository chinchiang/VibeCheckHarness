# 08 實作規格

> 本文件的讀者是要動手寫程式的工程師。讀完之後，應該不需要再做任何設計決定就能開始 M1。
>
> - [§10](#10-尚未決定需使用者決定) 只列**需要使用者決定**的事項，各附未決定時的預設做法。
> - [§11](#11-元件規格補充) 補上 v0.3 的元件規格（W0 抽取器、工具結果合併、Slicer、Scope Proxy、Session Provider、SARIF 等）。
> - 其他還沒寫到的細節（不需要使用者決定，但本版尚未規定的部分）列在 [09 待辦清單](09-backlog.md)。不在本文件、03 或 09 的設計，視為遺漏，請回報。
> - 本文件的內容幾乎全部是設計選擇，標為 **[H]**。
> - 引用的外部事實沿用 01–06 的證據 ID。本文件新增的外部事實只有套件的授權與版本，以及 §11 引用的 SARIF 2.1.0 列舉值與 `kind`／`level` 規則、Schemathesis 的行為；都已獨立查核並併入證據帳本（依查核結果標 V／P）。
> - 元件名稱與介面沿用 [03 §15](03-system-architecture.md#15-元件介面h)。03 §15 沒有的介面，本文件標為「**擴充**」。
> - 依 03 §15 的約定，**模組配置、錯誤分類與 CLI 細節以本文件為準**。兩份文件不一致時，應改 03。

## 現況

第十輪審查（2026-10-27）後的設計，裁決規則版本 `05-v0.10`。本文件描述現在的規則；正文中「審查 rN」「v0.x」等字樣只出現在說明「為什麼這樣規定」的句子。各版的變更摘要移到 [evidence/doc-history.md](evidence/doc-history.md#08-實作規格)，逐版的完整變更見 [CHANGELOG](../CHANGELOG.md)，審查紀錄見 [evidence/](evidence/)。

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
| `scope_proxy` | `ScopeProxy`（擴充）：Z3 唯一出口；DNS 固定；每個 job 的白名單與身分；路徑正規化；速率、指標與 kill switch；TLS 終結與長連線協定（§11.7） | Z3 | M1；M3 加 B1 爬行規則；M4 加 TLS 終結 |
| `executor`（擴充） | `Executor`（Z3 服務，只接受 Z1 以 mTLS 發來的指令）；`SessionProvider`（M4，含每批 whoami，§11.8）；`SeedService`（M4，§11.6）；`LlmRelay` 的 Z3 用戶端（M5） | Z3 | M1（最小版）、M4（完整版） |
| `snapshot` | `SnapshotService`（快照、還原、演練、種子資料、oracle 唯讀查詢） | Z3 | M4 |
| `adapters` | `ToolAdapter` 基底類別（擴充），加上每個 `tool:mode` 一個實作（D13）；W0 抽取器 `inventory:*`（§11.1） | Z2、Z3 | M1（W0／W1 工具）、M2（W4）、M4（黑箱工具）、M5（LLM 測試工具） |
| `slicer` | `Slicer`（擴充）：切片與 `slice_id`；同等性單位（所有家族收到完全相同的切片，上限是參與模型中最小的可用 context）；多樣性降低標記（§11.3） | Z1 | M2 |
| `toolresult`（擴充） | W1 輸出 → `ToolResult`：區段對應到函式、合併、去重（§11.2） | Z1 | M2 |
| `cluster` | `Clusterer`（擴充）：確定性叢集鍵（[05 §4.1](05-bias-calibration.md#41-叢集鍵clusterer確定性)）、tool-only 叢集（§11.2；`origin: tool_only`，v0.5，[09 BL-13](09-backlog.md)）、`fingerprint`（§11.16）；B2 的確定性 merger 鍵（§11.17） | Z1 | M2；M3 加 merger 鍵 |
| `aggregator` | `Aggregator`（擴充）：R0–R13 有序規則（[05 §4.2](05-bias-calibration.md#42-裁決狀態與有序規則)）；嚴重度 rubric（§11.17） | Z1 | M2 |
| `apispec`（擴充） | 沒有 OpenAPI 時，由 inventory 與 G1 起草 OpenAPI（§11.10） | Z1 | M4 |
| `agents` | 每個 agent 的 prompt 範本、輸出 schema 與角色（`agents.yaml`）；Commander（CMD-1–CMD-5） | Z1 | M2（W）、M3–M4（B） |
| `nodes` | LangGraph 節點函式，一個節點一個函式（[03 §5.7](03-system-architecture.md#57-節點規格表)） | Z1 | M1–M5（依節點，見 [07 §2](07-roadmap.md#2-元件與節點的歸屬)） |
| `graph` | `RunState`、StateGraph 的組裝、checkpointer、`Send` fan-out、interrupt 與 resume | Z1 | M1（骨架）、M2（W 圖）、M3–M4（B 圖） |
| `gates` | `GateService`（擴充）：開關卡、列表與顯示、提交簽章紀錄、逾時、ASI09 抽查；G1 問卷（§11.4） | Z1 | M2（M1 只有 G0a／G0b 的離線驗章，放在 `policy`） |
| `reporter` | 確定性報告骨架＋Reporter agent 的敘事；JSON、SARIF（對應表見 §11.16）、靜態 HTML；敘事 linter（§11.17）；publisher（PR／issue 回饋，§11.16） | Z1 | M2（白箱）、M4（B6 JSON／SARIF、publisher）、M5（HTML） |
| `calibration` | Calibration Lab：語料載入、對照組、M-1–M-11、θ 搜尋、§5.8 最小重跑 | Z1＋Z2 | M2 |
| `selftest`（擴充） | 06 §1.2.1 的自測：ST-1–ST-7，產出 `selftest-report.json` | Z1＋Z2＋Z3 | M1 起逐步擴充 |
| `pii`（擴充） | 具名 PII 偵測器的包裝（§11.17）；Z1、Z2（W0 個資掃描）與 Z3 共用 | Z1、Z2、Z3 | M2（MVP-0：W0 用的規則式偵測器）；M4（黑箱停止條件與發布前掃描） |
| `cli` | `vibecheck` 指令（§4）；只做參數解析，再呼叫其他模組 | Z1、簽署人裝置 | M1 起 |

**擴充說明**：D16 列出的 18 個模組都保留，名稱也不變。另外新增 `errors`、`config`、`store`、`sandbox`、`executor`、`selftest`，原因是 03 §15 的 `ContentStore`、`Blackboard`、`SandboxRunner`、`Executor`、`SessionProvider` 在 D16 的清單裡沒有對應的模組 [H]。v0.3 再新增 `toolresult`、`apispec`、`pii`（§11.2、§11.10、§11.17）。

### 1.2 依賴方向

分層（上層可以 import 下層，反過來不行）[H]：

```text
L7  cli
L6  graph, gates, reporter, calibration, selftest
L5  nodes
L4  agents, slicer, toolresult, cluster, aggregator, apispec
L3  policy, gateway, sandbox, scope_proxy, executor, snapshot, lgapi
L2  adapters, pii
L1  keys, config, store, audit
L0  errors, models
```

- `lgapi`：唯一 import `langgraph` 的模組，只重新匯出 `interrupt`、`Send`、`Command` 與 checkpointer 的型別。v0.4 讓 `nodes`（L5）從 `graph`（L6）匯入這三個名字，違反「上層 import 下層」的方向；現在 `nodes` 與 `graph` 都從 L3 的 `lgapi` 匯入。

- `adapters` 放在 L2（`executor`、`sandbox` 之下），因為 Z2／Z3 的執行器要呼叫 adapter 的 `render()`／`parse()`；`adapters` 本身只 import L0–L1（`errors`、`models`、`config`、`keys`），不 import 任何 L3 以上的模組，所以規則 4 不需要例外 [H]。
- `pii` 也放在 L2：Z2（W0 的個資掃描，v0.5）、Z1（報告與發布前的掃描）與 Z3（回應的 PII 停止條件）都要用它，它只 import L0–L1 [H]。

**強制規則**（`tests/arch/test_imports.py` 以標準函式庫 `ast` 掃描 import，違反就讓 CI 失敗）[H]：

1. **只有 `gateway` 可以 import `litellm`**。只有 `gateway` 可以讀取 LLM API 金鑰的環境變數（§5.3）；只有 `reporter` 的 publisher 可以讀取 `VIBECHECK_PUBLISHER_TOKEN`。
2. **`nodes` 不可以直接呼叫供應商或目標**。`nodes` 不 import `litellm`、`httpx`、`dns`、`socket`、`subprocess`，只透過注入的 Protocol 物件（`ModelGateway`、`SandboxRunner`、`Executor` 用戶端等）做事。
3. **`slicer`、`toolresult`、`cluster`、`aggregator`、`apispec` 是純函式**：
   - 不 import `store`、`gateway`、`audit` 或任何 I/O 模組；
   - 輸入與輸出都是 `models` 的物件，由 `nodes` 負責讀寫 Blackboard。
4. **Z3 的模組不 import Z1 的模組**：
   - `scope_proxy`、`executor`、`snapshot` 不 import `gateway`、`store`、`graph`、`gates`；
   - 它們可以 import `errors`、`models`、`keys`、`config`、`adapters`、`pii`；
   - Z3 映像不包含 Z1 的模組（§1.3），這一條由映像內容測試再檢查一次。
5. **網路出站只允許**：`gateway` 連 LLM 端點；`executor` 經 `scope_proxy` 連目標；`sandbox` 只連 Z2 的鏡像（`mirror_only`）；`reporter` 的 publisher 只連設定的程式碼託管平台 API，而且只在委任設定開啟時（§11.16）。其他模組開 socket 一律視為違規。
6. **`agents` 只依賴 `ModelGateway` 這個 Protocol**，不依賴 `gateway` 的實作。
7. **只有 `lgapi` 可以 import `langgraph`**（v0.5；v0.4 是 `graph`）。`nodes` 與 `graph` 都只使用 `lgapi` 重新匯出的 `interrupt`、`Send`、`Command`，測試時可以換成假物件。
8. `keys` 不依賴 `policy`；`policy` 使用 `keys`。

### 1.3 部署單位

三個映像，都鎖 digest [H]：

| 映像 | 內容 | 區 | 限制 |
|---|---|---|---|
| `vibecheck-z1` | 除 `scope_proxy`、`executor`、`snapshot` 以外的全部模組 | Z1 | 出站只允許 LLM 端點、Z4、Z3 的指令埠，以及（publisher 開啟時）程式碼託管平台 API。**不能連目標** |
| `vibecheck-z3` | `errors`、`models`、`keys`、`config`、`adapters`（只含 Z3 模式）、`pii`、`scope_proxy`、`executor`、`snapshot` | Z3 | 不含 LLM 金鑰；出站只經 Scope Proxy；本地 CA 私鑰只在 Z3 的 secret store（§11.7） |
| 工具映像（每個工具一個） | W0／W1／W4 工具（W0 的映像含 `pii` 的規則式偵測器，v0.5），以及 M4 起的黑箱工具 | Z2 或 Z3 | digest 登錄在 `tools.yaml` 與 SBOM |

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
| `SessionProvider.whoami`（擴充，§11.8） | **不丟例外**，回傳 `WhoamiResult`；`ok` 為 false 時由 `B4_preflight` 轉成 `SessionUnavailable` |

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
    allowed_tools_effective: list[str]  # 經 L-6 元件授權過濾後的 allowed_tools；寫入 G0b GateRecord，只供 B 階段使用 [H]
    failures: list[str]

class ResolvedTarget(BaseModel):
    target_id: str
    base_url: str
    host: str
    ownership_method: Literal["dns_txt", "well_known_path", "platform_project"]  # 共享平台網域只接受 platform_project（§11.9）

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
    # compute_safety_class(tc: dict, roe: dict, tools: dict, manifest: dict | None)
    #   -> tuple[str, list[str]]；manifest 是 tc.seed_manifest_ref 指到的整份 seed manifest（dict），
    # 寫入範圍規則要用它的 seeds[].path_templates 與 create_only_endpoints（§11.6）。classify 以
    # model_dump(mode="json") 把 tc、roe、registry、manifest 轉成 dict 後呼叫同一演算法，
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
    max_requests_per_trial: int | None  # v0.7（審查 r8 外部 1）：逐 trial 的上限，trial 邊界由 harness 以 trial_id 標頭標示；機率型測試必填
    rate_per_s: float
    third_party: list[str]             # 預設為空
    expires_at: str
    protocols: list[Literal["http1", "h2", "ws", "sse"]]  # M1 只有 ["http1"]；ws、sse 的限制見 §11.7
    job_token_id: str                  # per-job proxy 認證權杖的 ID；權杖本身只在 Z3（§11.7）
    edge_ip_ranges: list[str]          # 取自 ROE targets[].edge_ip_ranges（v0.4 起 ROE schema 已有，E-ROE-EDGE-RANGE）；省略時為空（§11.7）
                                       # 這個欄位（09 BL-15），補上之前一律為空

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
    # 寫一份由系統產生的 EXPIRED 紀錄（signatures: []；Policy 只接受 EXPIRED 這一種無簽章紀錄，
    # 證明是 gate_opened 與 gate_decision 兩個收件時間之間已經逾時，03 §6.2）
    def spot_check_sample(self, run_id: str) -> list[str]: ...  # ASI09 抽查（07 M2）

# --- Slicer / Clusterer / Aggregator（純函式；M2）---
class Slicer(Protocol):
    def slice(self, inventory: BaseModel, symbols: "SymbolIndex",
              extra_anchors: list["CodeLocation"], budget: "SliceBudget") -> list[BaseModel]: ...
    # 回傳 slice.schema.json 的物件；slice_id = sha256(JCS({files, redaction_map_sha256,
    # prompt_template_sha256}))；相同輸入 → 相同輸出。不接收任何工具結果（05 §3 規則 5）；
    # extra_anchors 只有位置（檔案＋符號），給 tool-only 叢集的驗證用（§11.3）

class Clusterer(Protocol):
    def cluster(self, findings: list[BaseModel], tool_results: list["ToolResult"]) -> list[BaseModel]: ...
    # 回傳 cluster.schema.json 的物件；使用 05 §4.1 的叢集鍵並計算 fingerprint（§11.16）。
    # 只有 kind == "sast" 的 ToolResult（§11.2）進叢集：同叢集鍵 → 附到 sarif_refs；
    # 對不到任何發現項 → tool-only 叢集（origin: tool_only；引發它的結果記在 tool_report_refs，
    # 是回報，不算佐證；09 BL-13）

class AdjudicationInputs(BaseModel):   # 欄位與 tools/vchlib/adjudicate.py 的 Inputs 一一相同（§2.4）
    lane_a: bool
    g2_rejected: bool
    all_snippets_fail: bool            # R0：叢集有成員，且每個成員的每個證據都是 NOT_FOUND（05 §3 規則 5）；黑箱叢集沒有成員 → false
    evidence: set[str]                 # E_proof / E_fail_u / E_pass / E_inc（EVIDENCE_ORDER）
    weighted_support: bool
    weighted_refute: bool
    score: float                       # S = Σ w(m,b)·stance；w=0 的票不計入
    strong_tool: bool                  # 叢集有「強」SARIF 結果：解析該 ref 的稽核事件之 (payload.adapter、
                                       # payload.sarif_results[] 中該 ref 的 rule_id、payload.tool_version) 與 calibration.yaml
                                       # result.high_precision_rules 的一列相同、cwe_bucket 等於叢集的桶，且 precision_lower95 ≥
                                       # result.thresholds.high_precision_min.value（預設 0.90）；強 refs ＝ 裁決的
                                       # tool_corroboration，不符 → E-VERDICT-TOOLCORR（05 §3 規則 5、§4.2；§11.2）
    weak_sarif: bool                   # 叢集有其他已解析的 SARIF 結果（弱工具訊號，算 1 個獨立來源）；
                                       # 弱 SARIF refs ∪ 每個 E_fail_u 測試結果的 result_ref ＝ 裁決的 tool_signal，
                                       # 不符 → E-VERDICT-TOOLSIGNAL。E_fail_u 本身只放在 evidence，不併入這兩個欄位
    # 每個 sarif_refs 項目都必須對應同一 run、已登錄、未失敗（payload.ok true）、licenses.yaml 狀態為
    # OK 或「注意」的白箱工具（zone Z2、b4_executable false）之 tool_invocation_end 事件的 payload_refs，
    # 否則 → E-SARIF-REF（該項不算）；
    # sarif_refs、tool_corroboration、tool_signal 都不得重複
    theta_confirm: float | None        # None = +∞
    theta_reject: float | None
    independent_families: int          # validator 重算：只計同一 run、reporter.round＝1、reporter 在 agents.yaml 的角色是
                                       # reviewer、而且至少有一個證據不是 NOT_FOUND 的成員之家族；R2 的獨立來源數＝此值＋
                                       # weak_sarif＋（evidence 含 E_fail_u）＝ Outcome.sources ＝ 裁決的 independent_sources
                                       # （E-VERDICT-SOURCES）
    diversity_degraded: bool           # validator 推導（05 §3 規則 3）：E＝agents.yaml 中角色為 verifier、家族與血統都不在
                                       # 叢集中的 agent 家族；非 Lane A、|E| > 0，且計權合格票的家族數 < min(2, |E|) → true；
                                       # |E| ＝ 0 → no_eligible_verifier（E-VERDICT-NOELIGIBLE）；只計 verifier 的票，其他
                                       # → E-VERDICT-VOTER-ROLE；家族由 voter_agent_id → agents.yaml → models.yaml；
                                       # 不符 → E-VERDICT-DIVERSITY
    g3_rejected: bool                  # R13：由 G3 GateRecord 計算；G3 之後任何階段的裁決都適用
    phase: str | None                  # 呼叫情境："W3"、"W4"、"B5"…（對應 readjudicated_by）
    prev_status: str | None            # 被取代那一版裁決的狀態；第一版為 None
    # w4_became_disputed：phase == "W4"、prev_status 不是 None 也不是 DISPUTED、新狀態為 DISPUTED
    # （例如 LIKELY 經 R11 → DISPUTED）；與 G2 是否已決定無關（05 §4.2）
# 由 nodes 從投票、證據與 calibration.yaml 組成；純核心回傳 Outcome(status, row, rules,
# status_cap, advisory, annotations, sources)，與 vchlib 相同。裁決的 provisional 推導為：calibration_version
# 為 null、theta_confirm 為 null，或叢集的每個合格驗證者模型（E 的模型，由登錄推得，不看出席的票）在該桶的
# 權重都是 0（E-VERDICT-PROVISIONAL，§11.11）。裁決與 run 的 rule_version 都必須等於 vchlib 的
# RULE_VERSION（目前 "05-v0.10"；E-VERDICT-RULE-VERSION、E-RUN-RULE-VERSION）

class Aggregator(Protocol):
    def adjudicate(self, cluster: BaseModel, x: AdjudicationInputs,
                   previous: BaseModel | None) -> BaseModel: ...
    # 回傳 verdict.schema.json 的新一版裁決（append-only）；rule_trace 記錄每條被觸發的規則
    # 規則順序：R9、R10、R0、R1、R2–R7、R8、R11、R12、R13（05 §4.2）；每次都從 A 段重新評估
```

**v0.3 的擴充介面**寫在 §11，與規格放在一起：
- `ToolResult`、`ToolLocation`、`PackageRef`（`toolresult`；Clusterer 的輸入）：§11.2。
- `InventoryExtractor`、`FrameworkHit`、`InventoryPart`（adapters；W0 抽取器）：§11.1。
- `SeedService`（executor；種子的建立、解析、清理）：§11.6。
- `SessionProvider.whoami`、`WhoamiResult`（executor；每批身分確認）：§11.8。

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
    # 回傳 testresult（含 04 §4.2 的 oracle 判定），或 W1 的單一結果 SARIF 物件（之後由 toolresult
    # 正規化成 ToolResult，§11.2）；W0 抽取器回傳 InventoryPart（§11.1）
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
- M1 W0：`betterleaks:scan`、`gitleaks:scan`、`syft:sbom`、`inventory:fastapi`、`inventory:express`、`inventory:sql_rls`；MVP-0 另需 `inventory:nextjs`、`inventory:baas_client`（§11.1 的支援矩陣）。這兩個是**規劃中的 adapter**，目前的 `tools.yaml` 還沒有登錄（`inventory` 只登錄了 `fastapi`、`express`、`sql_rls` 三個模式）；實作時先在 `tools.yaml` 登錄，才適用上面的註冊規則。
- M2 W0（候選，同樣都還沒有登錄在 `tools.yaml`）：`inventory:llm_sdk`（MVP-0 需要）、`inventory:hono`、`inventory:flask`、`inventory:django`、`inventory:graphql`、`inventory:firebase_rules`、`inventory:prisma`
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
| `safety.py`：`compute_safety_class`、`admissible`；路徑正規化 `normalize_for_match`、萬用字元主機 `host_matches`（§11.7）；寫入範圍 `is_mutation`、`mutation_scope_problems`、`seed_path_problem`（§11.6）；`SHARED_PLATFORM_SUFFIXES`（§11.9） | `policy/safety.py` | `SafetyClassifier.classify`、`admissible`；Scope Proxy 使用同一個正規化函式 |
| `evidence.py`：`match_snippet`、`match_fact`、`match_config`、`finding_status` | `cluster/evidence.py` | 發現項的證據比對（05 §3 規則 5）；Clusterer 的 R0 輸入 |
| `adjudicate.py`：`Inputs`、`Outcome`、`adjudicate`、`independent_sources`、`EVIDENCE_ORDER`、`RULE_VERSION` | `aggregator/rules.py` | `Aggregator.adjudicate` 的純核心 |
| `llm_schema.py`：`project`、`degrade_for_llm`、`find_forbidden`、`FORBIDDEN_FOR_LLM`、`LLM_OUTPUTS` | `gateway/schema_degrade.py` | `ModelGateway.complete` 的輸出 schema |

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
   - (a) `docs/schemas/examples/` 的每個範例，都要能「解析 → Pydantic → `model_dump(mode="json", exclude_unset=True)` → 以 jsonschema 驗證 → JCS」，並且與原檔的 JCS **逐位元組相同**。v0.4 寫的 `exclude_none=False` 會替範例中省略的選填欄位補出 `null`（目前有 8 個範例省略選填欄位，例如叢集的 `canonical_location.endpoint`），`exclude_none=True` 又會刪掉範例中明寫的 `null`，兩者都做不到逐位元組相同；`exclude_unset=True` 只輸出原檔有的欄位，省略的與明寫 `null` 的都保留原樣。
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
| `vibecheck run estimate` | `--engagement E --repo PATH --commit SHA [--json]` | 先跑 W0（不用 LLM），再依 §11.12 估算每個階段與家族的呼叫數、token 與費用，與委任設定的上限比較；`run start` 也自動執行同樣的估算 | 0/3/10 | M2 |
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
| `vibecheck report export` | `RUN_ID --format json\|sarif\|html --out DIR [--include-rejected] [--include-pass]` | `json`（M2 白箱、M4 完整）、`sarif`（M2 白箱、M4 完整；對應表見 §11.16）、`html`（M5，靜態檔案） | 0/6/7 | M2/M4/M5 |
| `vibecheck report publish` | `RUN_ID [--dry-run]` | publisher：把摘要留言、以指紋去重的 issue 與修正說明發布到程式碼託管平台（§11.16）。委任設定沒有開啟 → 結束碼 5（開啟用的欄位是 engagement 的 `publishing`，v0.5，[09 BL-17](09-backlog.md)）；`--dry-run` 只輸出將要發布的內容 | 0/5/6/9 | M4 |
| `vibecheck feedback add` | `--fingerprint FP --label LABEL --reason TEXT --sign ...` | 登錄中的人（`security_reviewer` 或 `app_owner`）簽署的誤報／確認回饋；標籤與去向見 §11.16（回饋紀錄：`feedback.schema.json`，v0.5，[09 BL-18](09-backlog.md)） | 0/3/4/5 | M4 |
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
- 一個 run 使用的每個設定檔，都把路徑與 hash 寫入 run 紀錄的 `config_refs`（§11.13）與 `config_loaded` 稽核事件；validator 以參照的檔案重算。
- run 執行中，設定檔改變**不影響**該 run。resume 時如果發現 hash 不同，run 維持原狀態，結束碼 7，並提示需要開新的 run。
- 以 JSON 格式儲存的文件（例如 GateRecord、稽核事件）同樣嚴格解析：重複鍵、NaN／Infinity、溢位的浮點數（例如 `1e400`）、絕對值超過 2^53 的整數、或需要整數處出現浮點數字面值 → `E-JSON-STRICT`（與 `E-YAML-STRICT` 對應；例外類別 `StrictJSONError`，§6.1）；該文件連同它的簽章與 hash chain 一律拒絕，簽署文件記為 `signature_invalid`（validator 強制）[H]。
- `models.yaml` 中 `litellm` 仍是未確認模型 ID 的別名以 `placeholder: true` 標記（目前只剩 `nemotron_cloud`；`gpt_flagship` 已依 §10 U-12 換成 `gpt-6-sol`），佔位的啟發式判斷涵蓋 `<...>`、`{...}`、`TBD`、`TODO`、`FIXME`、`實作時確認`；`litellm` 符合卻沒有標記 → `E-MODEL-PLACEHOLDER` [H]。已標記的佔位模型**只在 repo 範例**得到警告 `W-MODEL-PLACEHOLDER`；**真實 run**（validator `--real-run` 與 G0a）中，任何 agent 可達的佔位模型（主要模型或 fallback）都是 `E-MODEL-PLACEHOLDER` → G0a `VERIFY_FAILED` [H]。目前範例的預期警告只有一個：`nemotron_cloud` 的 `W-MODEL-PLACEHOLDER`（沒有 agent 會用到，所以 `--real-run` 也不報錯）。U-11、U-12 已決定，不再有 `W-MODEL-RETIREMENT` 與 `gpt_flagship` 的佔位警告。
- DB 目標的主機（`endpoint` 的 host 部分；`endpoint` 必須是 `host:port` 或 `[IPv6]:port`，無法解析 → `E-ROE-DB-SCOPE`）先正規化（去掉結尾的 `.`、大小寫摺疊、IDNA 轉換），再與同樣正規化的 ROE `exclusions.hosts` 精確比對，不能在其中；`db_access.endpoint` 的主機必須是某個 ROE DB 目標的主機且未被排除；違反 → validator 拒絕該 ROE（`E-ROE-DB-SCOPE`；[03 §7.6](03-system-architecture.md#76-db-快照種子資料與-oracle-唯讀存取)）[H]。
- `models.yaml` 的每個別名要有 `earliest_retirement` 欄位（[model-registry](schemas/model-registry.schema.json)；尚無公告日期時為 `null`）。Gateway 在日期前 30 天內，每次呼叫都寫警告事件；日期已過 → `ModelNotAllowed` [H]。

### 5.2 優先順序

從低到高：`toolkit.yaml` 的預設值 → `engagement.yaml` → `roe.yaml`。後面的只能**收緊**，不能放寬。唯一的例外是 ROE 的 `stop_conditions`：它由 ROE 簽署人簽署，可以覆寫預設值（[03 §7.3](03-system-architecture.md#73-限速與停止條件)）[H]。

| 設定 | 規則 |
|---|---|
| 關卡逾時 | `toolkit.yaml` 的 `gate_timeouts_hours` → engagement 可以縮短；上限是 `resume_deadline`，G0b 之前的關卡只受 engagement 的 `not_after` 限制，G0b 起也受 ROE 的 `not_after` 限制（[03 §6.2](03-system-architecture.md#62-關卡逾時預設值)） |
| 預算 | `toolkit.yaml` 的 `budget_defaults` → engagement 可以設定。**沒有預設的費用上限**：engagement 沒寫 → 需要花費的節點 fail-closed（[03 §11](03-system-architecture.md#11-成本與延遲模型)） |
| 允許的模型 | engagement 的允許清單 ∩ `models.yaml` ∩ `agents.yaml` 的綁定；交集為空的角色 → `run_init` 失敗（`ConfigInvalid`） |
| 停止條件 | ROE 有寫的鍵用 ROE 的值，沒寫的用 `toolkit.yaml` 的預設值 |
| 允許的工具與模式 | `tools.yaml` − `TOOLKIT_DENYLIST` − ROE 的 `denied_modes`，再 ∩ ROE 的 `allowed_tools` |
| 保證等級 | 只由 engagement 的 `assurance_profile` 決定（G0a 驗章），ROE 不能改。`lite` → 實際可用的安全等級＝ROE `allowed_safety_classes` ∩ {S0, S1}（`E-PROFILE-SAFETY`）；ROE `relay.mode: adaptive` 只在 `full` 有效（[02 §1.7](02-methodology.md#17-保證等級liteteamfull)、§11.15） |
| 沙箱資源 | 只看 `toolkit.yaml` 的 `sandbox`；run 不能改 |
| 保留期限 | `toolkit.yaml` 的上限 → engagement 的實際值 → ROE，後者只能更短；規則與錯誤碼見 [06 §2.2.1](06-security-legal-limitations.md#221-保留期限的優先順序-h)、§7.5 [H] |
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
| `VIBECHECK_Z3_CA_KEY_REF` | Z3（只有 `scope_proxy`） | Scope Proxy 本地 CA 私鑰在 Z3 secret store 中的參照（§11.7）；私鑰不離開 Z3 |
| `VIBECHECK_Z3_SESSION_KEK_REF` | Z3（只有 Session Provider） | 加密 storageState 的金鑰參照（§11.8） |
| `VIBECHECK_PUBLISHER_TOKEN` | Z1（只有 `reporter` 的 publisher） | 程式碼託管平台的權杖，權限見 §11.16；預設不設定（publisher 關閉） |

- `config_loaded` 事件只記錄變數**名稱**與是否存在，不記錄值。
- 例外訊息與 log 一律經過遮罩函式，遮罩範圍包含上表所有值。
- **Z2 的 job 不繼承任何環境變數**。`AdapterPlan.env` 中含有 secret 樣式的值 → 拒絕。

### 5.4 其他設定與產物欄位

欄位的完整語意在各自連到的小節；這裡只列出在哪個檔案、由什麼檢查 [H]。欄位名稱以 [docs/schemas/](schemas/) 為準，錯誤碼以 `tools/vchlib/checks.py` 為準。

| 檔案 | 欄位 | 用途 | 檢查 | 細節 |
|---|---|---|---|---|
| `engagement.yaml` | `assurance_profile`（`lite`、`team`、`full`） | 保證等級 | `E-PROFILE-SAFETY`（`lite` 只允許 S0／S1；`MANUAL` 測試案例除外）、`E-ROE-SOD`、`E-GATE-SOD`、`E-G5-TWO-PERSON`（`full`）、`E-ROE-RELAY-MODE`（`adaptive` 只在 `full`） | [02 §1.7](02-methodology.md#17-保證等級liteteamfull)、[03 §6.4](03-system-architecture.md#64-保證等級對簽署的影響) |
| `engagement.yaml` | `role_consolidation`（`acknowledged`、`person_id`、`statement`；可以是 null） | Lite 模式一人兼多角色的明示聲明 | 只在 `lite` 使用，`person_id` 必須是登錄中的人、`statement` 不可空（`E-ENG-PROFILE`）；沒有聲明卻一人兼多角色 → `E-ROE-SOD`（ROE 簽署）、`E-GATE-SOD`（同一份 GateRecord）；聲明的這個人同時是法務聲明者與 `test_lead` → 警告 `W-L5-LITE`（取代 `E-L5`，報告首頁註明法務聲明是自簽） | 同上 |
| `engagement.yaml` | `gate_approvers`（`G0a`、`G1`、`G2`） | G0b 之前各關卡的核准者 | `E-GATE-APPROVER-ENG`；G0b／G3／G4／G5 的核准者來自 ROE（`E-GATE-ROE-APPROVER`）；G3／G4／G5 的決定時間必須在 ROE 效期內（`E-GATE-ROE-VALIDITY`；G0b 本身就是檢查 ROE 效期的關卡，ROE 尚未生效時是讓 run 暫停，不適用這個錯誤碼） | [03 §6.3](03-system-architecture.md#63-核准者來源與逐項核准) |
| `engagement.yaml` | `providers[]`（`family`、`zdr`、`zdr_evidence_ref`、`dpa_signed`、`retention_days`、`region`） | 供應商的 ZDR／DPA 宣告 | `E-ENG-PROVIDER` | §11.14 |
| `roe.yaml` | `targets[].build_identity`（`method`：`header`、`endpoint`、`none`；`header_name`、`path`、`json_pointer`） | 確認 staging 跑的是被審查的 commit | `E-RESULT-BUILD`；`method` 與其他三個欄位的搭配 → `E-ROE-TARGETS` | §11.7 |
| `roe.yaml` | `targets[].ownership_proof.method: platform_project`（`platform`、`project_ref`、`evidence_ref`；`token_ref` 改為可以是 null）；頂層的 `platform_policies[]` | 共享平台網域的所有權 | `E-ROE-PLATFORM` | §11.9 |
| `roe.yaml` | `test_roles[].login` 的 `mfa`、`captcha_bypass`、`idp`；`test_roles[]` 的 `whoami` 與 `storage_state_encrypted: true` | 登入方式與每批的身分確認 | schema；測試案例用到的角色都要有 `whoami`（`E-ROE-WHOAMI`） | §11.8 |
| `roe.yaml` | `relay.mode`（`scripted`、`adaptive`） | 多輪對話的產生方式 | `adaptive` 只限 `full`（`E-ROE-RELAY-MODE`）；`scripted` 時多輪測試案例要有 `script_turns`（`E-TC-SCRIPT`） | §11.15 |
| `roe.yaml` | `exclusions.hosts` 的 `*.` 萬用字元；`targets[].base_url` 與 `stop_conditions.health_url` 只允許 `https://`（`http://` 只限 `localhost`、`127.0.0.1`、`[::1]`） | 範圍 | 測試案例的主機被排除 → S3（`E-TC-ADMISSIBLE`）；ROE 自己的目標落在排除清單內 → `E-ROE-TARGETS`（DB 目標 `E-ROE-DB-SCOPE`）；URL → `E-ROE-URL` | §11.7 |
| `models.yaml` | `pricing`（`input_usd_per_mtok`、`output_usd_per_mtok`、`as_of`、`source`；null＝價格未知）、`rate_limits`（`rpm`、`tpm`）、`tokenizer` | 成本估算與 token 計算 | 形狀由 schema 檢查；engagement `budgets` 每一層的 `max_cost_usd` 一律必填（schema＋`E-ENG-BUDGET`），所以價格未知時同樣 fail-closed | §11.12、§11.3 |
| `calibration.yaml` | `result.high_precision_rules[]`（`adapter`、`rule_id`、`tool_version`、`cwe_bucket`、`n`、`precision_lower95`）；`result.thresholds.high_precision_min`（`value` 預設 0.90） | 強工具佐證 | `E-VERDICT-TOOLCORR`、`E-VERDICT-TOOLSIGNAL`、`E-VERDICT-SOURCES` | [05 §5.10](05-bias-calibration.md#510-掃描器規則的高精準名單high_precision_rules)、§11.2 |
| `seed-manifest.yaml` | `namespace`（必須含 `{run_id}`，例如 `vc-{run_id}-`）、`seeding`、`teardown`、`reseed_per_trial`、頂層的 `create_only_endpoints[]`、每個種子的 `path_templates[]` | 種子生命週期與寫入範圍 | `E-TC-MUTATION-SCOPE`（該測試案例同時成為 S3）；`create_only_endpoints` 的目標必須是 ROE 的 http 目標（`E-SEED-MANIFEST`） | §11.6 |
| `agents.yaml` | 分析者池 `result_analyst_a`、`result_analyst_b`、`result_analyst`；reviewer 與 verifier 只能用 `read_slice`；`invariant_drafter` 的工具是 `read_inventory`、`write_blackboard`（不能有 `read_slice`）；`commander` 沒有工具 | 解讀的跨家族確認；最小權限 | `E-RESULT-ANALYST-ROLE`、`E-AGENT-TOOLS` | [05 §4.2](05-bias-calibration.md#42-裁決狀態與有序規則) |
| run 紀錄 | `config_refs`（`models`、`agents`、`tools`、`calibration`、`invariants`、`seed_manifest`）、`prompt_templates[]`、`tool_versions[]`、`rule_version`、`baseline_run_id` | run manifest | `config_refs.*.sha256` 重算（`E-DERIVED`）；路徑的檔案種類、`tool_versions` 與稽核事件一致（`E-RUN-CONFIG`）；`rule_version`（`E-RUN-RULE-VERSION`）；`baseline_run_id`（`E-CLUSTER-BASELINE`） | §11.13 |
| `invariants.yaml` | `data_classification[]`、`llm_tools[]`、`limits[]`、`policies[]`、`access_matrix[].ownership`；頂層的 `level_triggers[]` 與 `baseline_levels`（`asvs`、`aisvs`） | G1 規格 | `E-INVARIANT-LEVEL`、`E-INVARIANT-REF` | §11.4 |
| `inventory.json` | `frameworks[]`；`endpoints[]` 的 `kind`、`auth_required`、`middleware_refs`；`db`、`auth`、`env_vars[]`、`blind_spots[]`、`features[]` | W0 的產出 | `E-INVENTORY`、`E-INVENTORY-REF`、`E-PLAN-FACETS` | §11.1 |
| 發現項（finding） | 證據的 `kind`（`code_snippet`、`inventory_fact`、`config_fact`）、`fact_ref`、`key_path`、`asserted`；`match` 新增 `MATCHED_SHIFTED`；`facet`（13 個面向） | 不是程式片段的證據；審查面向 | `E-FINDING-EVIDENCE`、`E-FINDING-MATCH`、`E-FINDING-STATUS`、`E-INVENTORY-REF`；所屬叢集的桶必須在 `FACET_BUCKETS[facet]` 中（`E-FINDING-FACET`） | §11.1、[05 §3](05-bias-calibration.md#3-設計規則) |
| 切片（slice） | `redaction_map_sha256`、`prompt_template_sha256` | 新的 `slice_id` | `slice_id` 重算（`E-DERIVED`）；範本不是 run 的 `prompt_templates` 之一，或遮罩表不是 run 的 `redaction_map_ref` → `E-SLICE-IDENTITY` | §11.3 |
| 叢集（cluster） | `origin`（`white_box`、`black_box`；v0.5 加 `tool_only` 與 `tool_report_refs`）、`threat_id`、`canonical_location.endpoint`、`fingerprint`、`baseline_state`、`reopened` | 黑箱起源的叢集；跨 run 的指紋 | `E-CLUSTER-ORIGIN`、`E-CLUSTER-FINGERPRINT`、`E-CLUSTER-BASELINE` | §11.16 |
| 裁決（verdict） | `tool_signal`、`independent_sources`、`provisional`、`no_eligible_verifier`、`votes[].cited_evidence`；`rule_version` 固定為目前的 `RULE_VERSION`（目前 `05-v0.10`；v0.5 起 `05-v0.5`） | 強弱工具訊號、校準前的標示 | `E-VERDICT-TOOLSIGNAL`、`E-VERDICT-SOURCES`、`E-VERDICT-PROVISIONAL`、`E-VERDICT-NOELIGIBLE`、`E-VERDICT-RULE-VERSION`；`cited_evidence` 由 schema 檢查 | §2.3、§11.2、§11.11 |
| 測試案例（testcase） | `oracle.types[]`、`controls[]`、`script_turns`、`request_allowlist[].step_id`、`request_allowlist[].graphql_operation` | 對照組、多輪腳本、寫入範圍 | `E-TC-CONTROLS`、`E-TC-SCRIPT`、`E-TC-MUTATION-SCOPE`、`E-TC-REQ-UNAPPROVED` | §11.6、§11.15 |
| 測試結果（testresult） | `controls[]`、`fail_oracles[]`、`outcome: INVALID`、`observed_build_id`、`request_log_sha256`、`interpretation` | 對照結果、build 識別、解讀 | `E-RESULT-CONTROLS`、`E-RESULT-INVALID`、`E-RESULT-ORACLE`、`E-RESULT-BUILD`、`E-RESULT-REQUEST-LOG`、`E-RESULT-ANALYST`、`E-RESULT-ANALYST-ROLE` | §11.7、[05 §4.2](05-bias-calibration.md#42-裁決狀態與有序規則) |
| report-manifest | `metrics`（`results_total`、`results_invalid`、`control_pass_rate`）、`build_unverified_targets[]`、`absent_fingerprints[]` | 報告的確定性計數 | `E-REPORT-METRICS`、`E-RESULT-BUILD`、`E-CLUSTER-BASELINE` | §11.16、§11.17 |
| Commander 計畫 | `round`（1–2）、`extra_dispatch[].target`（`{kind, id}`） | CMD-2 加派 | `E-PLAN-ROUNDS`、`E-PLAN-TARGET`；每個切片的 `facets` 必須涵蓋必要面向（`E-PLAN-FACETS`） | §11.1 |
| DFD | 每個元素的 `provenance`；trust boundary 的 `kind` | 元素出處、邊界種類 | schema；只有 trust boundary 的 `kind` 不是 null（`E-DFD`） | §11.5 |

- 優先順序照 §5.2：`assurance_profile` 只寫在委任設定（G0a 驗章），ROE 不能改。
- 「run 紀錄」以下各列是 run 產生的紀錄或產物，不是部署時的設定檔；列在這裡，是因為它們的新欄位是其他元件的輸入，或由 validator 交叉檢查。
- v0.3 的 validator 另有兩個不屬於單一欄位的錯誤碼：`E-INPUT-SHAPE`（檔案的整體形狀不對，例如應該是物件卻是陣列：該檔只報一次，並從語意檢查中隔離，其他檔案照常檢查）；`E-SCHEMA-FORMAT`（schema 用到 validator 沒有檢查器的 `format`；目前只有 `date-time`、`date`、`uri` 有檢查器）。

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
| `StrictJSONError`（`E-JSON-STRICT`） | JSON 格式的文件（GateRecord、稽核事件、JSON 範例實例） | 否 | 觸發條件：重複鍵、NaN／Infinity、溢位的浮點數（例如 `1e400`）、絕對值超過 2^53 的整數、需要整數處卻是浮點數字面值。**簽署文件**（GateRecord 等）→ 視為簽章無效，後果同下一列（與 §5.1 一致）；**未簽署文件** → 同 `ConfigInvalid` | 簽署文件：`signature_invalid`；其他：`config_loaded`（失敗）或 `artifact_validation` | 簽署文件 4；其他 3 |
| `SignatureInvalid`、`RegistryRollback` | G0a、G0b、resume、gate、Z3 | 否 | G0a／G0b → `ABORTED`；B 階段執行中（`B4_preflight`、Z3）驗章失效（金鑰撤銷、簽章無效、文件被改）→ `abort_handler` → `ABORTED`；resume 或 gate → 維持原狀態。**到期不屬於這一列**，見 `OutsideWindow` | `signature_invalid`、`engagement_verify_failed`／`roe_verify_failed` | 4 |
| `PolicyDenied` | Policy Engine | 否 | 看動作：CMD 計畫 → 該計畫作廢；工具呼叫 → 該 job `SKIPPED`；resume → 維持原狀態 | `policy_decision`（deny） | 5 |
| `LegalReviewPending` | G0b 的 L-5 | 否 | `SUSPENDED`（`suspended_wait`） | `roe_verify_failed` | 5 |
| `OutsideWindow` | G0b、`B4_preflight`、resume | 否 | `SUSPENDED`；包含執行中 ROE 的 `not_after` 或 `legal_review.expires_at` 已過：保留 checkpoint，resume 需要一份新的有效 ROE（重跑 G0b），`B4_preflight` 再檢查一次（[03 §5.6](03-system-architecture.md#56-中止補償與-resume)）[H] | `run_status_changed` | 5 |
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
| `OwnershipFailed` | B0、`B4_preflight` | 否 | 該目標 `SKIPPED`；全部目標失敗：B0 → `B6_report`（M1 是 `m1_finish`），`B4_preflight` → `abort_handler` → `STOPPED`（[03 §5.5](03-system-architecture.md#55-b4-執行迴圈)） | `ownership_check` | — |
| `Z3Unavailable` | Executor 用戶端 | 是（§6.2） | 用盡 → `SUSPENDED` | `run_status_changed` | 9 |
| `StopConditionTriggered` | Executor | 否 | `abort_handler` → `STOPPED` | `stop_condition` | — |
| `BuildMismatch` | `B4_preflight`、Executor（§11.7） | 否 | 該目標本批的 job `SKIPPED`（`build_mismatch`），列入 B6；其他目標繼續 | `policy_decision`（deny） | — |
| `SessionUnavailable` | `B4_preflight` 的 whoami、Session Provider（§11.8） | 重新登入 1 次 | 該角色本批的 job `SKIPPED`（`session_unavailable`；登入方式無法自動化時為 `login_unavailable`），列入 B6 | `session_login`（失敗） | — |
| `SeedSetupFailed` | 種子 job（§11.6） | 否 | 依賴該種子的 job `SKIPPED`（`seed_setup_failed`），列入 B6 | `tool_invocation_end`（`ok: false`） | — |
| `TeardownFailed` | 種子清理（§11.6） | 1 次 | 缺口 `teardown_failed`，報告列出殘留物件；run 最終為 `COMPLETED_WITH_GAPS` | `tool_invocation_end`（`ok: false`） | — |
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
| LLM 請求 | sha256（`engagement_id`＋資料等級＋模型 ID＋版本＋參數＋prompt hash＋schema hash＋取樣序號）（v0.4；[03 §5.8](03-system-architecture.md#58-節點邊界規則)） | 從 CAS 讀回應，不重新呼叫、不重複計費；不跨委任重用；刻意的重複取樣各有自己的序號 |
| Sandbox job | sha256（image digest＋argv＋輸入 hash）（[03 §2](03-system-architecture.md#2-部署與信任區)） | 讀已存在的結果 |
| 所有權驗證 | `(run_id, target_id, batch_id)` | 讀已簽署的結果 |
| S2 快照 | `run_id + job_id` | 略過 |
| B4 job | Z3 的 job 帳本（權威，v0.4）；`executed_jobs` 與 `JobStatus` 只是快取 | 帳本已有紀錄 → Executor 拒絕執行並回傳原結果，即使 checkpoint 回溯過；`EXECUTING` 但沒有結果 → `INTERRUPTED`（[03 §5.6](03-system-architecture.md#56-中止補償與-resume)） |
| 開關卡 | `(run_id, gate, round)` | 不重複開啟、不重複通知 |
| GateRecord | `approval_hash` | 同一份 → 成功；不同 → 7 |
| 稽核事件 | `idempotency_key` ＝ `run_id:node:<上列鍵>` | Audit Writer 寫入端去重，不寫新行，回傳原本那一行的 `seq`；稽核檔中同一 run 的鍵唯一（`E-AUDIT-IDEMPOTENCY`，[03 §5.8](03-system-architecture.md#58-節點邊界規則)） |

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
| `runs` | run 紀錄：狀態、run_kind、發起者、run manifest（`config_refs`、`prompt_templates`、`tool_versions`、`rule_version`、`baseline_run_id`，§11.13）、`redaction_map_ref`、`key_registry_ref`、`resume_deadline` |
| `run_audit_anchors` | `run_id`、`seq`、`line_sha256`（錨點事件自己那一行的 sha256）、時間 |
| `gate_records` | GateRecord 本體（JCS）、分離式簽章、`approval_hash`、驗章結果 |
| `gate_spot_checks` | ASI09 抽查：抽中的關卡、複核者、期限、結果 |
| `blackboard_index` | `run_id`、`kind`、`ref`、schema `$id`、provenance、建立時間 |
| `llm_cache` | 快取鍵 → 回應 ref、token 數、費用 |
| `sandbox_jobs` | job ID → `SandboxResult` ref |
| `budget_ledger` | 每次 reserve 與 record（M2） |
| `key_registry_state` | 上次接受的版本與 hash（防回滾） |
| `run_locks` | 不是資料表，而是以 `run_id` 為鍵的 PostgreSQL advisory lock；Run Controller、Gate Service、`run abort` 修改 run 之前取得（[03 §5.8](03-system-architecture.md#58-節點邊界規則)） |
| Z3 `job_ledger` | 在 Z3（不在 Z1 的資料庫），append-only：`run_id`、`job_id`、`g5_gate_record_id`、開始與結束時間、結果 ref；每筆以 z3_executor 金鑰簽署。不受 checkpoint 回溯影響 |
| LangGraph 的資料表 | 由 checkpointer 自己建立；本工具包的遷移**不修改**這些資料表 |

### 7.3 CAS 配置

```text
$VIBECHECK_CAS_ROOT/<engagement_id>/            # v0.5：每個委任一個儲存根，不跨委任共用內容或快取
  sha256/ab/cd/abcd…ef          # 密文（AEAD；演算法與 KMS 見 §10）
  refs/ab/cd/abcd…ef/<run_id>.<ref_id>.json
      # v0.5：生命週期參照 {run_id, producer_node, media_type, data_class, retention_starts_at,
      #        retention_days, legal_hold, created_at}；同一內容可以有多筆參照
```

- ref ＝ 明文的 sha256。`get()` 先解密，再重算 hash。
- **hash 不是授權**[H]：讀取要檢查呼叫者、委任與一筆仍有效的生命週期參照；知道 hash 不代表有權讀。儲存根依委任隔離，金鑰（KEK）也依委任分開；跨委任去重要先完成授權與金鑰隔離設計，MVP 不啟用。LLM 快取（03 §5.8）的鍵已含 `engagement_id`，與此一致。
- 寫入的方式：先寫暫存檔，再原子性地 rename。內容已存在 → 不覆寫內容，但**新增一筆自己的生命週期參照**；同 hash 的第二次寫入不能沿用第一筆的資料等級、起算點或保留期限。
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
- **分行**：`AuditWriter` 與所有讀取端（`audit verify`、validator）都只以 `\n` 分行，不使用 `str.splitlines()` 之類會把 `\r`、U+2028 等也當成行界的函式 [H]。
- **錨點格式**：`run.audit_anchors` 的每一項是 `{seq, line_sha256}`，`line_sha256` ＝ 該 `audit_anchor` 事件自己那一行原始位元組的 sha256（取代舊版的「錨點的 prev_hash」）。
- **尾端保護（validator 強制）** [H]：規則與錯誤碼的主頁是 [03 §13.1](03-system-architecture.md#131-稽核事件格式audit-eventschemajsonh)；hash chain 只能偵測竄改，不能防止（[06 §3](06-security-legal-limitations.md#3-做不到不承諾的事) #16）。
- 可選擇另外寫到 WORM 儲存或外部系統；是否需要，由 engagement 決定（§10）。

### 7.5 保留與刪除

- 優先順序 [H]：規則與錯誤碼見 [06 §2.2.1](06-security-legal-limitations.md#221-保留期限的優先順序-h)。寫入 CAS 物件時，meta 記的是生效值。
- 保留期限設定在 `toolkit.yaml` 的 `retention` 區塊（[toolkit-config](schemas/toolkit-config.schema.json)）。工具包的預設值 [H] 如下，**實際值需要法務決定（§10）**：
  - `p_days: 365`（P 級）；
  - `c_days_after_run_end: 90`（C 級）；
  - `audit_days: 1095`（稽核檔與 GateRecord；必須 ≥ 兩個內容期限）；
  - `checkpoint_days_after_run_end: 30`、`checkpoint_keep_last: 1`；
  - `legal_hold: []`（列入的範圍一律不刪）。
- `ContentStore.gc(now)`：每筆生命週期參照各自到期，到期即撤銷**該參照**的讀取權；實體內容只有在**所有**參照都到期、而且都沒有 `legal_hold` 時才刪除。較晚的新參照不能替已到期的舊參照延長存取；legal hold 期間的讀取權限由獨立政策決定。每次撤銷與刪除都寫稽核事件。驗收：相同內容的不同期限、不同資料等級、legal hold、多 run 共用、刪除後的稽核驗證。
- 刪除 C 級內容之後，稽核檔中的 hash 仍然保留，所以 `audit verify` 不受影響。

## 8. 測試

### 8.1 測試層級與目錄

| 層級 | 目錄 | 內容 | CI 線（§8.4） |
|---|---|---|---|
| 既有：文件驗證 | `tests/test_validator.py`、`tests/test_adjudicate.py`、`tests/test_review_fixes.py`、`tests/test_doc_tools.py`，以及各輪審查的回歸測試 `tests/test_v0<版本>_*.py`、`tests/fixtures/`、`tests/conftest.py`（pytest） | `test_validator.py`：validator 的負面案例、基準、denylist 檢查、RFC 8785 測試向量；`test_adjudicate.py`：05 §4.2 的 R0–R13 決定表與註記（`annotations`）；`test_v02_hardening.py`：v0.2 強化規則（推導 `diversity_degraded`／工具訊號、稽核錨點與尾端、保留期限、DB 範圍、佔位模型 ID、嚴格 JSON）；`test_review_fixes.py`：v0.2.1 的審查修正；`test_v03_adjudication.py`、`test_v03_datamodel.py`、`test_v03_scope.py`、`test_v03_gates.py`、`test_v03_manifest.py`、`test_v03_llm_schema.py`、`test_v03_robustness.py`：v0.3 的規則，每條都有正反案例；`test_doc_tools.py`：文件工具（兩個產生器、連結檢查、外部連結檢查） | 既有的 `.github/workflows/validate.yml`（ubuntu、windows × Python 3.11、3.13）；併入 `fast` |
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
- `tests/` 目前只有上表「既有」一列的測試。上表其他目錄是 M1 起新增的；既有測試留在原位。
- 正式程式使用 Python 3.12（§1.1），`fast` 線另跑 3.11 與 3.13，與 `validate.yml` 的矩陣一致。

### 8.2 M1 必須拒絕清單（負面安全測試）

每一項都是 `tests/security/test_n<NN>_*.py`，而且要**斷言**稽核事件與結束碼。第三欄對應 [07](07-roadmap.md) 的出口準則（[§4](07-roadmap.md#4-各里程碑) 的 M 準則與分段 MVP 的 `MVPn-Xk`）。

- N-32 起是 v0.3 新增的項目（§11），[07 的 M1-X2](07-roadmap.md#m1-基礎與安全控制) 的範圍是 N-01–N-43。它們在 M1 先測 validator 與 `PolicyEngine` 的判定（斷言錯誤碼與 CLI 結束碼）；需要 Z3 執行期的部分（例如 build 不一致時不執行），在該功能的里程碑另有整合測試（§8.5）。
- 預期結果欄的錯誤碼是參考 validator（`tools/vchlib/checks.py`）實際報出的碼；括號中的測試名稱是 `tests/test_v0*_*.py` 中對應的回歸測試，`tests/security/` 的測試以它們為藍本。

| # | 輸入 | 預期結果 | 07 準則 |
|---|---|---|---|
| N-01 | W0 完成前，也就是沒有 `redaction_map_ref` 時呼叫 `ModelGateway.complete` | `RedactionMissing`；假供應商收到 0 個請求 | M1-X2 |
| N-02 | 模型不在 engagement 的允許清單中 | `ModelNotAllowed`；0 個請求 | M1-X2 |
| N-03 | 把 C 級切片送給 `data_classes` 不含 C 的模型（例如 `nemotron_cloud`） | `DataClassDenied`；0 個請求 | M1-X2 |
| N-04 | 改動 `api_base`、對 `gpt_flagship` 設 `store: true`、傳入白名單以外的參數 | `EndpointDenied` | M1-X2 |
| N-05 | repo 含 canary secret（放在程式、註解、設定檔、git 歷史中） | 任何 LLM 請求本體中都沒有 canary（對 CAS 全文搜尋）；`secret_detected` 只含位置與 hash | M1-X3（ST-3） |
| N-06 | 路徑黑名單中的檔案（`.env*`、金鑰檔、auth-state） | W0 之後的任何產物、SARIF、切片中都沒有這些檔案的內容 | M1-X2 |
| N-07 | ROE 有兩個 `targets:` 鍵 | `StrictYAMLError` → `signature_invalid`；結束碼 4 | M1-X2 |
| N-08 | anchor／alias、自訂 tag、NaN、超過 2^53 的整數、未加引號的 `yes`／時間；JSON 文件的重複鍵或 NaN／Infinity（`E-JSON-STRICT`） | 同 N-07 | M1-X2 |
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
| N-22 | 稽核檔被修改一行、刪除一行、插入、交換順序；錨點被改；檔案被截到錨點之前（`E-AUDIT-TRUNCATED`）；錨點行 hash 不符（`E-AUDIT-ANCHOR-MISMATCH`）；錨點指向非錨點行或跳過錨點（`E-AUDIT-ANCHOR`）；終態 run 沒有以 `run_end` 錨點結尾（`E-AUDIT-TAIL`） | `audit verify` 結束碼 8。性質測試 ≥1,000 個隨機竄改（錨定範圍內），偵測率 100%。最後一個錨點之後的截斷**只能偵測到錨點為止**：非終態 run 的未錨定尾端 → `W-AUDIT-UNANCHORED-TAIL`（§7.4）| M1-X5 |
| N-23 | 改動 CAS 物件的一個位元組 | `IntegrityError` | M1-X5 |
| N-24 | 非 `lane_a` 的 `run start` 沒有簽章，或簽署人是自動化帳號 | 拒絕（D7）；結束碼 5 | M1-X2 |
| N-25 | ROE 的 `allowed_tools` 含 `TOOLKIT_DENYLIST` 的模式；ROE 在時間窗外；進入 B 階段時 ROE 已過期；B 階段執行中 ROE 或 `legal_review` 到期；以已過期的 ROE resume | 依序：`roe verify` 拒絕；`SUSPENDED`；跳過 B 階段並記為缺口（`COMPLETED_WITH_GAPS`）；`SUSPENDED`（checkpoint 保留）；resume 被拒、維持 `SUSPENDED` | M1-X2 |
| N-26 | ROE 的 `legal_review` 不符 L-1–L-4；L-5（聲明者就是 `test_lead`） | `roe_verify_failed`；L-5 → `SUSPENDED` | M1-X2 |
| N-27 | engagement 允許的模型不在 `models.yaml` 中；fallback 跨家族 | `ConfigInvalid` | M1-X2 |
| N-28 | `toolkit.yaml` 的根金鑰指紋與登錄不符 | 行程拒絕啟動 | M1-X2 |
| N-29 | 鎖檔新增一個依賴，但 `licenses.yaml` 沒有對應的列；鎖檔的 hash 被改；鎖檔含 LiteLLM 1.82.7 或 1.82.8 [V][E:orchestration-31] | `licenses check`／安裝失敗 | M1-X7 |
| N-30 | 送給 Z3 的指令附的 ROE 被竄改，或換成另一份 ROE | Z3 重新驗章後拒絕（§1.3） | M1-X2 |
| N-31 | Z3 映像中出現 `gateway`、`litellm` 或 LLM 金鑰變數 | 映像內容測試失敗 | M1-X2 |
| N-32 | ROE 排除 `/admin/billing/*`；請求路徑為 `/Admin/billing/x`、`/admin;jsessionid=1/billing/x`、`/admin/%62illing/x`，以及雙重編碼的 `/admin/%2562illing/x`（C-1） | 安全等級 S3 → `E-TC-ADMISSIBLE`（測試案例自填的等級不是 S3 時另有 `E-TC-SAFETY`）；路徑樣板含 `%` 就視為未正規化，所以雙重編碼也是 S3；Scope Proxy 擋下，目標收到 0 個請求（§11.7）（`test_excluded_path_variants_are_s3`、`test_path_normalisation`） | M1-X2 |
| N-33 | ROE `exclusions.hosts: ["*.staging.example.com"]`；測試案例的目標主機是 `api.staging.example.com`（C-2） | S3 → `E-TC-ADMISSIBLE`；ROE 自己的目標主機落在樣板內 → `E-ROE-TARGETS`（DB 目標 `E-ROE-DB-SCOPE`）；Scope Proxy 擋下。對照組：`staging.example.com` 本身不被這個樣板排除（`test_wildcard_host_exclusion`、`test_wildcard_host_semantics`） | M1-X2 |
| N-34 | ROE 目標的 `base_url` 是 `ftp://…`、`http://api.staging.example.com` 或 `"this is not a uri"`（C-3） | `E-ROE-URL`（`"this is not a uri"` 另有 schema `uri` 格式的 `E-SCHEMA`）；`roe verify` 拒絕，結束碼 3。對照組：`http://localhost:3000`、`http://127.0.0.1:8080`、`http://[::1]:8080` 通過（`test_non_https_base_url`、`test_http_only_for_local_targets`） | M1-X2 |
| N-35 | 對非種子 ID 的 PUT、PATCH、POST、DELETE；`{seed:tenant_b_invoice}` 用在別的資源的路徑，例如 `/api/users/{seed:tenant_b_invoice}`（H-B3、C-11） | S3：`E-TC-MUTATION-SCOPE`＋`E-TC-ADMISSIBLE`（路徑樣板不是該種子的 `path_templates` 之一）。對照組：POST 到 `create_only_endpoints`、PUT 到 `{created:<step_id>}` → S1（`test_patch_on_a_non_seed_id_is_s3`、`test_delete_with_seed_of_another_resource_is_s3`、`test_post_to_create_only_endpoint_is_allowed`、`test_put_on_created_object_is_allowed`） | M1-X2、MVP1-X2 |
| N-36 | 測試結果的 `observed_build_id` 與 run 的 `repo_commit` 不同（相等，或較短的一方 ≥12 個十六進位字元且是另一方的前綴，才算相同）；或 `build_identity.method: none` 的受測目標沒有列在報告的 `build_unverified_targets`（H-B4） | `E-RESULT-BUILD`（`test_observed_build_must_be_the_run_commit`、`test_build_prefix_rule`、`test_unverified_staging_targets_are_listed`）。對照組：`environment: tester_controlled` 的目標（例如 `tgt-canary`）不是受測系統，不列入（`test_tester_controlled_targets_are_not_build_unverified`）。執行期「不一致就不執行」（`BuildMismatch`）在 M4 測 | M1-X2、MVP2-X1 |
| N-37 | 目標是 `https://acme-staging.supabase.co`，所有權方法為 `dns_txt`；或用了 `platform_project`，ROE 卻沒有對應的 `platform_policies`（H-D3） | `E-ROE-PLATFORM`；`roe verify` 結束碼 5（`test_shared_platform_host_needs_platform_project`） | M1-X2、MVP2-X2 |
| N-38 | `assurance_profile: lite`，而測試案例的安全等級是 S2（M-G3） | `E-PROFILE-SAFETY`；該測試案例不能進 G4（`test_lite_rejects_s2_toolkit_jobs`）。對照組：`MANUAL` 測試案例不受限（`test_lite_exempts_manual_testcases`） | M1-X2 |
| N-39 | `assurance_profile: team`，同一人以 `test_lead` 與 `management` 兩個角色簽署 ROE（L-13） | `E-ROE-SOD`；`roe verify` 結束碼 5（`test_team_needs_distinct_roe_signers`）。同一人在同一份 GateRecord 兼兩個角色 → `E-GATE-SOD`（`test_gate_separation_of_duties`）。對照組：`lite`，且 `role_consolidation.acknowledged: true`、`person_id` 就是此人 → 通過（`test_lite_with_acknowledged_consolidation`） | M1-X2、MVP0-X5 |
| N-40 | `assurance_profile: full`，G5 只有一位 `security_reviewer` 核准 | `E-G5-TWO-PERSON`；該 S2 job 不執行（`test_full_needs_two_g5_reviewers`） | M1-X2 |
| N-41 | 以 reviewer（例如 `rev_c`）擔任 Result Analyst（C-12） | `E-RESULT-ANALYST-ROLE`；該解讀不計入。若結果本來就事先登記解讀（例如 G4 核准的黑箱測試），分類仍依確定性 oracle 決定；否則因沒有合格分析者而不會成為 `E_proof`（`tests/test_v03_adjudication.py` 的 `test_result_analyst_role_enforced`） | M1-X2 |
| N-42 | 跟進 run 在自己的紀錄中列出前一個 run 的 GateRecord（例如 `GR-G4-0001`）（C-8） | `E-GATE-RUN`；該紀錄不被採用，依賴它的 resume 被拒（`test_run_cannot_list_another_runs_gate_record`） | M1-X2 |
| N-43 | 測試案例的 oracle 引用 G1 駁回（`REJECTED`）的需求（C-10） | `E-TC-REQ-UNAPPROVED`；該測試案例不能進 G4（`test_rejected_invariant_is_not_testable`） | M1-X2 |

### 8.3 範例應用（整合測試的目標）

放在 `tests/targets/`。每個應用都有「植入版」與「修正版」，並附真值檔 `truth.yaml`（位置、桶、CWE，以及利用測試）[H]。

| 應用 | 內容 | 對應 | 首次使用 |
|---|---|---|---|
| `invoices-app` | Express（TypeScript）＋PostgreSQL 的多租戶發票 API。`GET /api/invoices/{id}`（handler 在 `routes/invoices.ts:40`）在第 42 行讀取發票時沒有檢查租戶（IDOR；K-005 的 sink）；`invoices` 資料表沒有 RLS；角色 `tenantA_user`、`tenantB_user`。另外植入的漏洞讓總數 ≥10，以符合 ST 的語料要求 | [04 §6.1](04-threat-to-testcase.md#61-範例-awebapi-的-idorbola) 範例 A（TC-012-01、K-005） | M1（W0／W1／B0）、M2（W2–W5）、M4（B3–B5） |
| `support-agent-app` | FastAPI 的客服 agent：`refund(order_id)` 工具、可上傳 PDF、`agent_tool_calls` 資料表。它的上游 LLM 在 CI 中是**我方的腳本式假模型**：植入版以固定種子、固定機率遵循 PDF 內的指令；修正版在呼叫 `refund` 前要求人確認。也是 W4 工具防護測試（假模型輸出，§11.17）的範例 | [04 §6.2](04-threat-to-testcase.md#62-範例-bllm-功能的-prompt-injection-與工具濫用confused-deputy) 範例 B（TC-031-01、K-011，n＝60、k＝0 規則） | M1（W0／W1）、M2（白箱，含 W4 防護測試）、M5（完整） |
| `notes-rls-app` | **Next.js（App Router）＋Supabase 型**的筆記應用：`supabase/migrations/*.sql` 定義資料表與 RLS policy，前端以 BaaS 用戶端直接讀寫資料表（`baas_direct`，§11.1）。植入：<br>① 一張**沒有啟用 RLS** 的資料表 `shared_notes`，只能以 `inventory_fact` 證據回報；<br>② 一條 RLS policy 錯誤（條件漏了擁有者欄位）；<br>③ 前端 bundle 中一個**公開前綴**的 secret 樣式變數（`NEXT_PUBLIC_` 開頭，值是 canary）；<br>④ `package.json` 中一個**幻覺套件**名稱。<br>CI 以本地的 PostgreSQL 與認證函式替身執行，不連任何雲端平台 | 05 §5.1 的重點類別；G-07 需要的第 3 個應用；07 分段 MVP 的 MVP0-X1 | MVP-0（W0–W5、Z2 本地 RLS 測試、套件存在性）、MVP-1（本地目標）、M4（G-07） |
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
  - MVP-1 的本地目標（`http://localhost`）也以 well-known path 驗證，token 由範例應用自己提供。

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
| M1 | keys、config、store、audit、policy（G0a／G0b）、gateway 的前置檢查、sandbox、scope_proxy | N-01–N-43 | `invoices-app` 的 W0→W1→G0b→B0；每個節點邊界 kill＋resume；ST-1、ST-3、ST-7 |
| M2 | slicer、cluster、aggregator（決定表每一列至少一個案例，以及 05 §4.2 的所有例子）、budget、gates、calibration 的統計函式（Wilson、bootstrap、McNemar，以已知數值驗證） | 偽造或重送 GateRecord；職責分離；G2 逾時；Lane A 的結果進入 `CONFIRMED_*`（必須為 0）；缺少 `calibration.yaml` 時 w＝0 | 範例 A 白箱；ST-2、ST-4、ST-5；Calibration Lab 端到端（小型語料） |
| M3 | B1 的 diff、B2 merger 的確定性部分、crosswalk 驗證 | G3 駁回種子威脅時沒有理由 → 拒絕；未處置的 `b1_diff` 項目 → 不開 G3 | 範例 A／B 的威脅模型；INJ-DOC |
| M4 | SafetyClassifier（04 §5 虛擬碼的每個分支）、產物驗證、每個 adapter 的 `render`／`parse` | S3 不進 G4；S2 沒有 G5 或還原演練 → 不執行；`EXECUTING` 的 job 不自動重跑；ST-6 | 範例 A 的 TC-012-01；03 §7.3 的每個停止條件；S2 快照→執行→還原；還原失敗；INJ-HTTP；G-07 pilot |
| M5 | 機率判定（04 §4.4 的上界公式，以已知數值驗證）、Relay 的回合與花費上限 | Relay 使用 ROE 以外的模型、超過回合或花費上限 → 拒絕 | 範例 B 的 TC-031-01；INJ-LLMAPP；promptfoo 出站測試 |

**v0.3 追加的測試**（§11）[H]：
- **M1**：N-32–N-43；`inventory:nextjs`、`inventory:baas_client` 與擴充後的 `inventory:sql_rls` 在 `notes-rls-app` 上的抽取結果（支援等級、`blind_spots`、`features[]`）；run manifest 的 `config_refs` 重算；路徑正規化與 `vchlib` 的 parity。
- **M2**：ToolResult 正規化（區段 → 函式、去重、只收 `kind: fail`、不採用受測 repo 的抑制註解）；tool-only 叢集的回報不算佐證；強與弱佐證（`high_precision_rules` 為空時全部是弱的）；`slice_id` 隨遮罩表與範本改變；所有裁決在校準前都是 `provisional`（MVP0-X4）；嚴重度 rubric 的每個分支；敘事 linter 擋下禁用說法與不存在的 ID；W4 的假模型防護測試；Z2 的本地 RLS 測試；沒有鎖檔時 W4 為 `MANUAL`；`run estimate` 超過上限 → 結束碼 10；指紋在同一 commit 上重跑不變（MVP0-X3）。
- **M3**：B1 爬行只送 GET、HEAD、OPTIONS，並跳過登出與刪除類連結；W0 與 B1 的端點差異進 `b1_diff`；B2 merger 鍵的確定性；`llm_proposed` 的 DFD 元素在 G3 接受前不影響高風險計算。
- **M4**：TLS 終結（CA 私鑰不在任何映像、CAS 或 Z1 中）；HTTP/2 每個 stream 算一個請求；WebSocket 只允許訂閱或 `script_turns`；CDN 目標每個 job 固定一次解析；`platform_project` 與 `platform_policies`；每批 whoami 不符 → `SKIPPED`；build 不一致 → 不執行（MVP2-X1）；種子的建立、解析、重置、清理與冪等；OpenAPI 草稿的 `security`；SARIF 對應表與 schema 驗證；publisher 以指紋去重、權杖權限不足時不發布；fix brief 不含 secrets 與個資。
- **M5**：scripted 多輪只送 `script_turns`、不呼叫 LLM；`adaptive` 在 `full` 以外被拒；PII 偵測器的命中觸發停止條件。

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
9. 依 [07 的分段 MVP](07-roadmap.md) 交付時，每個 MVP 階段的出場條件（`MVPn-Xk`）也都有自動化測試或驗收報告；各元件規格屬於哪個階段，見 §11 開頭的表。

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
| T-08 | 2 | `policy`：`verify_engagement`、`verify_roe`（含 L-1–L-6、`TOOLKIT_DENYLIST`、時間窗、保證等級、共享平台網域、URL 規則）、`check`、`resolve_target`；`vibecheck sign`、`engagement verify`、`roe verify` | T-04、T-07 | 以測試金鑰簽署 `docs/examples/` 的 engagement 與 ROE → 通過；N-09、N-12、N-25、N-26、N-34、N-37、N-39 |
| T-09 | 2 | `graph` 骨架：`RunState`、`run_init`、`G0a_engagement_check`、暫時的 `m1_finish` 節點；PostgresSaver 與 SqliteSaver；`vibecheck run start`、`run status`、`run abort`、`run resume` | T-05、T-06、T-08 | N-15、N-24；在每個節點邊界 kill 行程再 resume → 最終產物的 hash 與不中斷的 run 相同，稽核去重後沒有重複事件 |
| T-10 | 2 | `sandbox`：以 gVisor（runsc，版本寫進 SBOM）執行、`network: none`、資源上限、job ID、輸出收集與遮罩 | T-06 | N-19、N-20；同一個 spec 執行兩次 → 只跑一次；runsc 的版本出現在 SBOM 中 |
| T-11 | 2 | `gateway`：`ModelGateway.complete` 的前置檢查、`RecordedTransport`、LLM 快取、schema 降階與修復、重試策略 | T-06、T-07 | N-01–N-04（假供應商收到 0 個請求）；429 會遵守 `Retry-After`；修復 2 次後 → `SchemaRepairExhausted` |
| T-12 | 2 | `selftest` 骨架＋`selftest/injected/invoices-app-{clean,injected}` 的初版（先只有 canary secret 與 INJ-CMT） | T-10 | `vibecheck selftest run --items ST-7` 產出通過 schema 驗證的 `selftest-report.json`，其中 ST-7 為 `status: RUN`、`passed: true` |

**M1 其餘的工單**（第 3 週起，依序）：
- T-13 `W0_inventory`：secrets 掃描 adapter、路徑黑名單、遮罩對照表、`inventory:*`（含 §11.1 的合併步驟、`features[]` 與 `blind_spots`）、SBOM、`redaction_map_ref` 寫入 run 紀錄。
  - 驗收：`invoices-app` 的 inventory 在 `endpoints[]` 列出 `GET /api/invoices/{id}`（`routes/invoices.ts` 第 40 行；第 42 行是 K-005 的 sink，不是端點），而且 `db.tables[]` 中 `name: invoices` 的 `rls_enabled` 為 `false`（與 [inventory 範例](schemas/examples/inventory.example.json) 相同）；N-05、N-06。
  - MVP-0 另需 `inventory:nextjs` 與 `inventory:baas_client`：`notes-rls-app` 的 `shared_notes` 為 `rls_enabled: false`，公開前綴的變數有 `public_prefix: true`。
- T-14 `W1_static` 與 `LA_static`：W1 的 adapter、遮罩、每個 SARIF result 拆成獨立的 CAS 物件（§11.2 第 1 步）、套件存在性（經 Z2 的 metadata 鏡像）。ToolResult 的正規化與合併屬於 M2（§11.2）。
  - 驗收：每個工具都產出 SARIF；單一工具失敗會列為缺口；`notes-rls-app` 的幻覺套件被標出。
  - `inventory:express` 所依賴的 SAST 引擎輸出格式，也在這張工單以測試確認。
- T-15 `scope_proxy`＋`executor`（最小版）＋mTLS 通道：`verify_ownership`、`http_get`、以 `z3_executor` 金鑰簽署結果。
  - 驗收：N-16–N-18、N-21、N-30、N-31、N-32、N-33。
- T-16 `G0b_roe_check`、`B0_ownership_verify`、`suspended_wait`、`run_resume` 的完整流程。
  - 驗收：`invoices-app` 與 `notes-rls-app` 的所有權驗證通過；時間窗外 → `SUSPENDED`，時間窗內 resume 成功。
- T-17 自測擴充到 ST-1、ST-3，並加入其餘的 M1 注入向量。
- T-18 Z2 維運：CVE 訂閱、升級流程文件、同一台主機不混用不同 engagement 的 job（G-11）。

## 10. 尚未決定／需使用者決定

以下事項本文件**沒有替使用者決定**。未決定之前，各項的預設做法寫在「未決定時」欄 [H]。

- U-01–U-14 沿用 v0.2（U-11、U-12 已決定）。
- U-15 起是 v0.3 的元件規格（§11）帶出的新事項。
- 不需要使用者決定、但本版還沒規定的細節，列在 [09 待辦清單](09-backlog.md)。

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
| U-11 | **已決定（2026-09-25，使用者）**：`claude_haiku`（Claude Haiku 4.5，最早 2026-10-15 退役 [V][E:providers-49]）換成 `claude_opus_48`（`claude-opus-4-8`，legacy 但仍為 Active，最早 2027-05-28 退役，1M context，每百萬 token $5／$25 [V][單源][E:providers-52]）；reporter、Lane A 與 `claude_sonnet` 的 fallback 改用它 | `toolkit_maintainer`＋使用者 | 單價是 Haiku 4.5 的 5 倍，reporter 與 Lane A 的成本上升 [V][單源][E:providers-52]；替代模型仍要先完成 05 §5.8 的最小重跑；Opus 4.8 已是 legacy，2027-05-28 前要再選後繼版本 | M2 |
| U-12 | **已決定（2026-09-25，使用者）**：`gpt_flagship` 綁 GPT-6 Sol（`openai/gpt-6-sol` [V][E:providers-46]；1,050,000 context [V][E:providers-46]）；走 Responses API，因為 Chat Completions 只有 `reasoning_effort=none` 時才能 function calling [P][E:providers-47] | 使用者 | OpenAI 模型頁目前沒有列退役日；C 級使用前仍需確認 GPT-6 的 ZDR 資格 [V][E:providers-48]；M2 的 manual 線仍要驗證 structured outputs 與工具呼叫 | M2 |
| U-13 | M4 黑箱工具使用的 HTTP 攔截式 proxy 實作（ZAP、Playwright 等工具要經 Scope Proxy） | `toolkit_maintainer` | M1 的 Scope Proxy 只服務 Executor 自己的 HTTP 用戶端（httpx 0.28.1，BSD-3-Clause [V][E:orchestration-57]；DNS 使用 dnspython 2.8.0，ISC [V][E:orchestration-58]） | M4 |
| U-14 | 鎖檔工具（pip 的 hash 檢查模式、或其他工具） | `toolkit_maintainer` | 以 pip 的 hash 檢查模式實作；它的行為以 T-01 的驗收測試證明，不另外引用文件 | M1 |
| U-15 | `high_precision_min` 的值：掃描器規則要多準，才能單獨當強工具佐證（[05 §5.10](05-bias-calibration.md#510-掃描器規則的高精準名單high_precision_rules)、§11.2） | `toolkit_maintainer`＋校準負責人 | 0.90。校準前名單是空的，所以暫時不影響任何裁決 | M2 |
| U-16 | 具名的 PII 偵測器：Presidio（presidio-analyzer 2.2.364 在 PyPI 標 MIT [V][E:whitebox-57]；相依的語言模型另有授權，未查證）或其他 | `toolkit_maintainer`、`legal_reviewer` | 工具包自己的規則式偵測器：email、電話、信用卡號（Luhn）、常見身分證號格式（檢查碼）（§11.17） | M4 |
| U-17 | JS／TS 解析器是否採用 tree-sitter（Python binding 0.26.0，MIT [V][E:whitebox-58]；各 grammar 另有授權） | `toolkit_maintainer`、`legal_reviewer` | MVP-0 以 tree-sitter 做暫定實作，只使用已在 `licenses.yaml` 登錄的 grammar；決定不採用時換解析器，並重跑抽取器與 Slicer 的契約測試（§11.1、§11.3） | M1–M2 |
| U-18 | **已處理**：ROE 的 `targets[].edge_ip_ranges` 為選填；宣告時每個解析出的 IP 都必須在範圍內（§11.7、`safety.ip_in_ranges`）。原問題：CDN 目標是否必須在 ROE 宣告邊緣 IP 範圍 | `toolkit_maintainer`、ROE 簽署人 | 選填：未宣告時每個 job 固定一次解析結果，並擋下非公開位址（§11.7） | M4 |
| U-19 | 是否開啟 PR／issue 回饋；使用哪個程式碼託管平台與哪種權杖（engagement 的 `publishing`，見 [09 BL-17](09-backlog.md)） | 使用者、`app_owner` | 關閉：只產出報告檔與 SARIF（§11.16） | M4 |
| U-20 | 每個家族的 USD 上限是否成為委任設定的欄位（engagement 的 `budgets.families`，見 [09 BL-14](09-backlog.md)） | 使用者 | 家族上限等於所在階段的上限（§11.12） | M2 |
| U-21 | Z2 本地 RLS 測試用的 PostgreSQL 版本，以及 BaaS 認證函式的替身 | `toolkit_maintainer` | 與 migrations 相容的 PostgreSQL 主版本，鎖 digest；替身只實作「取得目前使用者 ID」一類的函式（§11.17） | M2 |
| U-22 | 校準前 W3 每個叢集派幾位驗證者（M） | 使用者（成本）、`toolkit_maintainer` | M＝1；票只當參考意見（§11.11） | M2 |
| U-23 | staging 使用自簽憑證時，Scope Proxy 如何信任目標（例如 ROE 宣告目標的 CA） | 資安團隊、ROE 簽署人 | 不支援：TLS 驗證失敗 → 該目標的 job `ERROR` 並列入缺口；不提供略過驗證的選項（§11.7） | M4 |

## 11. 元件規格補充

§1–§9 定了模組、介面與測試。2026-09-26 的[深度審查](evidence/review-2026-09-26.md)找出一批「元件存在，但沒寫怎麼做」的缺口。本節逐一補上，寫法與前面各節相同：輸入、輸出、規則、失敗時怎麼辦、設定欄位、由哪個 validator 錯誤碼強制、屬於哪個里程碑與 MVP 階段。

- 除非另外標示，本節全部是設計選擇 [H]。
- 欄位名稱與錯誤碼以 v0.3 的 schema 與 `tools/vchlib` 為準，本節已逐一對照。設計中提到、但 schema 還沒有涵蓋的欄位原本列在 [09 待辦清單](09-backlog.md) 第 3 節；BL-13～BL-20 已在 v0.5 補上（09 §5）。
- 分段 MVP 的定義見 [07](07-roadmap.md)。下表的「MVP」欄是該元件第一次被需要的階段。

| 小節 | 審查 ID | 主要介面或設定 | validator 錯誤碼 | 里程碑 | MVP |
|---|---|---|---|---|---|
| [11.1 W0 盤點抽取器與支援矩陣](#111-w0-盤點抽取器與支援矩陣) | H-E1 | `InventoryExtractor`、inventory 新欄位 | `E-INVENTORY`、`E-INVENTORY-REF`、`E-PLAN-FACETS` | M1（M2 起擴充框架） | MVP-0 |
| [11.2 工具結果正規化與合併](#112-工具結果正規化與合併) | H-E2 | `ToolResult`、`Clusterer.cluster(findings, tool_results)` | `E-SARIF-REF`、`E-VERDICT-TOOLCORR`、`E-VERDICT-TOOLSIGNAL`、`E-VERDICT-SOURCES` | M2 | MVP-0 |
| [11.3 Slicer](#113-slicer) | H-E3 | `Slicer.slice`、`slice_id` | `slice_id` 重算（`E-DERIVED`）、`E-SLICE-IDENTITY` | M2 | MVP-0 |
| [11.4 G1 問卷與 invariants 格式](#114-g1-問卷與-invariants-格式) | H-E4 | G1 問卷、invariants 新欄位 | `E-INVARIANT-LEVEL`、`E-INVARIANT-REF`、`E-TC-REQ-UNAPPROVED` | M2 | MVP-0 |
| [11.5 DFD 元素出處](#115-dfd-元素出處) | H-E5 | DFD 的 `provenance`、邊界的 `kind` | schema、`E-DFD` | M2（W5）、M3（B1、B2） | MVP-0 |
| [11.6 種子資料生命週期](#116-種子資料生命週期) | H-E6 | seed manifest 新欄位、`SeedService` | `E-TC-MUTATION-SCOPE`、`E-SEED-MANIFEST` | M4 | MVP-1 |
| [11.7 Scope Proxy 實作](#117-scope-proxy-實作) | H-E7、L-17 | `JobAllowlist` 新欄位、TLS 終結、B1 爬行規則 | 安全等級 S3（`E-TC-ADMISSIBLE`）、`E-ROE-URL`、`E-RESULT-BUILD` | M1（GET）、M3（爬行）、M4（TLS 終結） | MVP-1（本地）、MVP-2（TLS） |
| [11.8 Session Provider](#118-session-provider) | H-E8 | ROE 的登入宣告、`whoami` | schema、`E-ROE-WHOAMI` | M4 | MVP-2 |
| [11.9 共享平台網域的所有權證明](#119-共享平台網域的所有權證明) | H-D3 | `platform_project`、`platform_policies[]` | `E-ROE-PLATFORM` | M1（validator）、M4 | MVP-2 |
| [11.10 沒有 OpenAPI 的應用](#1110-沒有-openapi-的應用) | H-E10 | OpenAPI 草稿產生器 | G4 的產物 hash | M4 | MVP-1 |
| [11.11 校準前的預設](#1111-校準前的預設) | H-E11 | `provisional` | `E-VERDICT-PROVISIONAL` | M2 | MVP-0 |
| [11.12 成本模型與價格](#1112-成本模型與價格) | H-E12 | `models.yaml` 的 `pricing`、`vibecheck run estimate` | 費用上限 fail-closed（`E-ENG-BUDGET`） | M2 | MVP-0 |
| [11.13 Run manifest 與 prompt 範本登錄](#1113-run-manifest-與-prompt-範本登錄) | H-E13、N-5 | run 的 `config_refs` 等欄位、範本登錄檔 | 設定 hash 重算（`E-DERIVED`）、`E-RUN-CONFIG`、`E-RUN-RULE-VERSION`、`E-VERDICT-RULE-VERSION` | M1（M2 加範本登錄） | MVP-0 |
| [11.14 供應商資料處理宣告](#1114-供應商資料處理宣告) | H-E14 | engagement 的 `providers[]` | `E-ENG-PROVIDER` | M1（validator）、M2 | MVP-0 |
| [11.15 多輪對話測試](#1115-多輪對話測試) | H-E15 | ROE 的 `relay.mode`、`script_turns[]` | `E-TC-SCRIPT`、`E-ROE-RELAY-MODE` | M5 | MVP-3 |
| [11.16 SARIF 輸出與報告回饋](#1116-sarif-輸出與報告回饋) | M-G6、H-B5 | SARIF 對應、`fingerprint`、publisher | `E-CLUSTER-FINGERPRINT`、`E-CLUSTER-BASELINE` | M2（白箱 SARIF）、M4 | MVP-0 |
| [11.17 確定性輔助規則](#1117-確定性輔助規則) | M-G5 | 嚴重度 rubric、敘事 linter、B2 merger 鍵、W4 防護測試、本地 RLS 測試、Z2 建置政策、PII 偵測器 | `E-REPORT-METRICS` | M2–M4 | MVP-0 起 |

- 「MVP」欄已與 [07 §1.1](07-roadmap.md#11-分段-mvp) 的分段 MVP 對照：MVP-0 是白箱、不連網（W0–W5、SARIF、`provisional`）；MVP-1 是本地拋棄式目標（寫入範圍、種子、本地 Scope Proxy）；MVP-2 是 staging 的 S0／S1（TLS 終結、`platform_project`、whoami、`build_identity`）；MVP-3 以後才有多輪 LLM 測試。

### 11.1 W0 盤點抽取器與支援矩陣

**目的**：W0 的 inventory 是下列項目唯一的確定性來源：指揮官的規劃、必要面向、切片錨點、DFD 骨幹、G1 問卷（[02 W0](02-methodology.md#w0-盤點與-secrets-遮罩確定性無-llm)）。v0.2 只有 FastAPI、Express、SQL RLS 三個抽取器，也沒說其他框架怎麼辦。本節定義抽取器外掛、支援矩陣，以及看不到的部分怎麼記錄。

**輸入**：遮罩後的 repo 檔案（W0 第 1–3 步之後）、`tools.yaml` 中已註冊的 `inventory:*` 模式（目前只有 `fastapi`、`express`、`sql_rls`；見下方支援矩陣）。執行位置 Z2，`network: none`。
**輸出**：`inventory.json`（`inventory.schema.json` v0.3）。

**抽取器介面**（adapters；擴充）：抽取器是工具包自有的程式碼，在 W0 的 Z2 映像內執行；對外以 `inventory:<name>` 登錄為 adapter，§2.3 的註冊規則照樣適用。

```python
class FrameworkHit(BaseModel):
    name: str                      # 例如 "nextjs"
    version: str | None            # 取自鎖檔；沒有鎖檔 → None
    root: str                      # monorepo 中的單元根目錄（§11.3）
    evidence: list[str]            # 判定依據：manifest 中的相依、特徵檔案

class InventoryPart(BaseModel):    # inventory.schema.json 的子集；由合併步驟組成完整的 inventory
    frameworks: list[dict]
    endpoints: list[dict]
    db: dict
    auth: dict
    env_vars: list[dict]
    llm_integrations: list[dict]
    blind_spots: list[dict]
    features: list[str]

class InventoryExtractor(ABC):
    name: ClassVar[str]            # adapter ID ＝ "inventory:" + name
    languages: ClassVar[list[str]]
    @abstractmethod
    def detect(self, tree: "RepoTree") -> list[FrameworkHit]: ...
    @abstractmethod
    def extract(self, tree: "RepoTree", hits: list[FrameworkHit]) -> InventoryPart: ...
    # 純函式：只讀遮罩後的檔案；不執行受測程式碼、不安裝套件、不連網
```

**規則**：
1. **偵測**：依相依清單（`package.json`、`pyproject.toml`、`requirements*.txt`）與特徵檔案判定框架；版本取自鎖檔。偵測到框架、卻沒有對應的抽取器 → `frameworks[].support: unsupported`，並加一筆 `blind_spots`（`unsupported_framework`）。
2. **支援等級由本次 run 決定**。支援矩陣列的是該抽取器**最多**能到的等級；實際寫入 `frameworks[].support` 的值是：
   - `full`：抽取器找到的每個註冊點（路由、handler、policy）都解析成功；
   - `partial`：有任何一個註冊點無法解析，例如路徑在執行時才組出來。每一個都記一筆 `blind_spots`（`kind` 為 `dynamic_route`、`generated_code` 或 `other`；`blind_spots` 只有 `kind` 與 `description` 兩個欄位，檔案與行號寫在 `description` 中）；
   - `unsupported`：見第 1 條。
3. **合併**：各抽取器的輸出依 (kind, method, path_template, handler 的檔案與行號) 去重，再依穩定鍵排序。路徑樣板統一寫成 `{name}`：Next.js 的 `[id]`、Express 的 `:id`、Django 的 `<int:id>` 都寫成 `{id}`。
4. **環境變數**：所有抽取器共用一個步驟。它從程式碼的參照（例如 `process.env.X`、`import.meta.env.X`、`os.environ["X"]`）取出**名稱**，不讀值；`.env*` 在路徑黑名單中，本來就不會被讀到。名稱以 `NEXT_PUBLIC_`、`VITE_`、`EXPO_PUBLIC_`、`PUBLIC_` 開頭時，`public_prefix: true`。
5. **`features[]`**：由下表的固定規則產生，規則隨抽取器版本發布，不由 LLM 判斷。它決定必要面向（[02 W2](02-methodology.md#w2-多家族獨立審查)，`E-PLAN-FACETS`）與 G1 問卷的題目（§11.4）。

| feature | 偵測規則（任一成立） |
|---|---|
| `file_upload` | 處理 multipart 表單的 handler；對 storage bucket 的寫入呼叫 |
| `outbound_http` | 伺服器端程式以非常數的 URL 呼叫 HTTP 用戶端 |
| `webhook_inbound` | 路徑含 `webhook` 或 `callback` 的端點；使用 webhook 簽章驗證的函式庫 |
| `payments` | 引用金流 SDK |
| `oauth` | `auth.providers` 含第三方登入 |
| `llm_tools` | `llm_integrations` 中有工具定義 |
| `frontend_bundle` | 有會送到瀏覽器的程式碼（例如 Next.js 的 client component、Vite 專案） |
| `crypto` | 直接使用加解密或簽章 API（TLS 用戶端不算） |

6. **失敗**：
   - 單一檔案解析失敗 → 該檔記一筆 `blind_spots`（`other`），該框架降為 `partial`，W0 繼續。
   - 抽取器本身崩潰或逾時 → W0 `FAILED`，與 02 W0 的「任何子步驟失敗 → `FAILED`」一致。原因：inventory 不完整會讓必要面向與切片錨點少算，而且沒有任何訊號告訴人少了什麼。

**支援矩陣**（各框架的慣例是設計假設 [H]，見表後說明）：目前 [`tools.yaml`](examples/tools.yaml) 的 `inventory` 只登錄了 `fastapi`、`express`、`sql_rls` 三個模式。下表標為「規劃中」的 adapter（`nextjs`、`baas_client`、`hono`、`flask`、`django`、`graphql`、`firebase_rules`、`prisma`、`llm_sdk`）**還沒有登錄**，是提案；在 `tools.yaml` 登錄之後才生效，inventory 的 `frameworks[].extractor` 也才能填這些 ID。

| 框架或元件 | adapter | 抽取內容（寫到 inventory 的哪裡） | 最高支援等級 | 已知盲點 | 里程碑／MVP |
|---|---|---|---|---|---|
| Next.js App Router | `inventory:nextjs`（規劃中） | `app/**/route.*` 的 route handler，依匯出的 HTTP 方法 → `endpoints`（`kind: http`）；`"use server"` 的函式 → `kind: server_action`；`middleware.*` 與它的 `matcher` → `auth.middleware`、`endpoints[].middleware_refs` | `full`；有 rewrites 或動態 `matcher` 時為 `partial` | 執行時才決定的 `matcher` → `dynamic_route`；`next.config.*` 的 rewrites、redirects 只記錄、不展開 | M1／MVP-0 |
| Next.js Pages Router | `inventory:nextjs`（規劃中） | `pages/api/**` → `kind: http`；方法由 handler 內對方法的判斷推得，推不出時記為全部方法，並加一筆 `dynamic_route` | `partial` | 同上 | M1／MVP-0 |
| Express | `inventory:express`（已登錄） | `app.<method>()`、`router.<method>()`；`app.use()` 的掛載前綴與中介層鏈 | `full` | 以變數或迴圈組出的路徑 → `dynamic_route` | M1 |
| Hono | `inventory:hono`（規劃中） | `app.<method>()`、`app.route()` 的前綴、`app.use()` 的中介層 | `full` | 同 Express | M2（候選） |
| FastAPI | `inventory:fastapi`（已登錄） | 路徑裝飾器、`APIRouter` 前綴、`Depends()` 的認證依賴 | `full` | 執行時才加入的路由 | M1 |
| Flask | `inventory:flask`（規劃中） | `@app.route`、blueprint 前綴、`before_request` | `full` | 同上 | M2（候選） |
| Django | `inventory:django`（規劃中） | `urls.py` 的 `path()`、`re_path()`、`include()`；view；`MIDDLEWARE` 設定；view 上的權限裝飾器 | `partial` | `re_path` 只能近似成路徑樣板；DRF router 產生的路由 | M2（候選） |
| GraphQL | `inventory:graphql`（規劃中） | SDL 檔中每個 Query 與 Mutation 欄位 → `kind: graphql`（方法 POST，路徑是 GraphQL 端點）；依命名慣例對到 resolver | `partial` | code-first 的 schema；resolver 只依慣例對應 | M2（候選） |
| Supabase 型 migrations | `inventory:sql_rls`（已登錄；本表的擴充是規劃中） | `supabase/migrations/*.sql` 等 SQL 檔：資料表 → `db.tables`；`ENABLE ROW LEVEL SECURITY` → `rls_enabled`；`CREATE POLICY` → `policies[]`（command、roles、來源行）；`SECURITY DEFINER` 函式 → `db.functions[].security_definer`；SQL 中宣告的 storage bucket → `db.storage_buckets` | `full`（只限 SQL 中寫到的部分） | 在平台後台設定、沒進 migration 的 RLS 與 bucket 公開設定 → `dashboard_only_setting` | M1／MVP-0 |
| 瀏覽器直連 BaaS | `inventory:baas_client`（規劃中） | 會送到瀏覽器的程式碼中，BaaS 用戶端對資料表、RPC、storage 的呼叫 → `kind: baas_direct`，路徑樣板寫成 `table:<名稱>`、`rpc:<函式>`、`storage:<bucket>`，並連到 `db` 中的同名項目 | `partial` | 名稱以變數傳入 → `dynamic_route`；SDK 的方法名稱以釘選的 SDK 版本為準（候選，未查證） | M1／MVP-0 |
| Firebase 規則 | `inventory:firebase_rules`（規劃中） | `firestore.rules`、`storage.rules` 等規則檔的 `match` 路徑 → `db.tables`（`schema` 記為規則檔種類）；`allow` 的動作 → `policies[].command`：read → `SELECT`、create → `INSERT`、update → `UPDATE`、delete → `DELETE`、write（＝create＋update＋delete）→ `INSERT`、`UPDATE`、`DELETE` 各一筆（不用 `ALL`：PostgreSQL policy 的 `ALL` 也包含 `SELECT`） | `partial` | 條件運算式只記位置，不求值；主控台上的設定 → `dashboard_only_setting` | M2（候選） |
| Prisma | `inventory:prisma`（規劃中） | `schema.prisma` 的 model → `db.tables`（`rls_enabled: null`）；關聯欄位當作 G1 問卷「資料屬於誰」的候選答案（§11.4） | `full`（只限 schema） | Prisma 本身不表達 RLS | M2（候選） |
| LLM SDK | `inventory:llm_sdk`（規劃中） | 已知 LLM SDK 的呼叫點、字面值的模型參數、工具定義（名稱與 handler 位置）、prompt 組裝位置 → `llm_integrations`；有工具時 `features` 加 `llm_tools` | `partial` | 使用者輸入是否流入 prompt，只在同一函式內近似判斷 | M2／MVP-0 |

- 表中各框架的檔案與語法慣例都是**設計假設 [H]**，證據帳本沒有對應條目：Next.js 的 `app/**/route.*`、`"use server"`、`middleware.*` 與 `matcher`、`pages/api/**`；Supabase 的 `supabase/migrations/*.sql` 路徑；PostgreSQL 的 `ENABLE ROW LEVEL SECURITY`、`CREATE POLICY`、`SECURITY DEFINER` 語法與 policy 指令的涵蓋範圍（例如 `ALL` 也包含 `SELECT`）；Firebase 規則檔的 `match`／`allow` 與各動作的涵蓋範圍（例如 `write` 包含 create、update、delete）。每個抽取器實作前，都要對照所釘選框架版本的官方文件確認，並把確認結果寫進抽取器的測試資料。

**瀏覽器直連 BaaS 的入口**（`kind: baas_direct`）[H]：
- 這類入口中間沒有伺服器端的 handler，授權完全靠資料庫端的 policy（例如 RLS）。
- 抽取器把每個 `baas_direct` 端點連到 `db.tables` 中的同名資料表。資料表的 `rls_enabled` 是 `false` 或 `null` 時，reviewer 可以用 `inventory_fact` 證據直接引用 `/db/tables/<i>/rls_enabled`（[05 §3](05-bias-calibration.md#3-設計規則) 規則 5），不必交出程式片段。
- 在 DFD 中，這是一條從 browser 直接到 data store 的資料流（§11.5）。
- `baas_direct` 端點的 `auth_required` 一律是 `null`：要不要登入取決於 policy，不取決於程式碼。

**只在平台後台的設定**：W0 只讀 repo，看不到平台主控台上的設定（[06 §3](06-security-legal-limitations.md#3-做不到不承諾的事) 第 29 條）。處理方式：
- 偵測到 BaaS 或託管平台（Supabase 型 migrations、Firebase 規則檔、平台設定檔）時，W0 為每一類可能只在後台設定的項目各寫一筆 `blind_spots`（`dashboard_only_setting`）：認證方式、storage 是否公開、沒進 migration 的 policy、CORS。
- G1 問卷把這些盲點轉成問題（§11.4 第 10 題）：
  - 回答了 → 成為 invariants 的 `policies[]` 項目，對應 DFD 元素的出處是 `g1_declared`（§11.5）；盲點仍保留，報告標示「已宣告、未驗證」。
  - 沒回答 → 盲點原樣列入報告。
- 黑箱階段只能驗證看得到的效果，例如匿名讀取某張資料表是否被拒。

**W0 與 B1 的端點差異（inventory drift）**：B1 外部視角（爬行＋匯入的 schema）的端點與 W0 的端點比對。比對鍵是 (HTTP 方法, 路徑樣板)，路徑樣板先依第 3 條統一 [H]。
- 只在 B1 出現 → `b1_diff` 的 `only_external`。可能是 repo 以外的部署、舊版殘留或動態路由；另外檢查 build 識別（§11.7）。
- 只在 W0 出現 → `only_merged`。可能需要登入、沒有部署，或爬行沒有走到。
- 每一項都由 B2 critic 處置（[02 B2](02-methodology.md#b2-威脅建模g3-強制簽核)）。這對應 OWASP API Security Top 10 2023 的 API9 Improper Inventory Management（條目 [V][E:blackbox-65]；對映本身是 curated 判斷 [H]）；binding 見 [04 §4.3](04-threat-to-testcase.md#43-binding-表)。

**解析器**：
- Python 抽取器使用標準函式庫 `ast`。
- JS／TS 需要另外的解析器。tree-sitter 的 Python binding 0.26.0 是 MIT [V][E:whitebox-58]，但它只是**候選**：各語言的 grammar 另有授權，採用前要逐一登錄在 `licenses.yaml`（[06 §2.3](06-security-legal-limitations.md#23-授權登錄表)）。是否採用見 §10 U-17。

**validator**：
- threat 與 finding 引用的 inventory 事實必須能解析（`E-INVENTORY-REF`）。
- inventory 內部的一致性（`E-INVENTORY`）：`middleware_refs` 要對到 `auth.middleware[].middleware_id`；每個來源檔都要在 `files` 中；`table_id` 不重複；`public_prefix` 必須等於「名稱以 `NEXT_PUBLIC_`、`VITE_`、`EXPO_PUBLIC_`、`PUBLIC_` 開頭」。
- 必要面向（`E-PLAN-FACETS`）由 `vchlib/facets.py` 的 `mandatory_facets` 計算：固定的 6 個（`authz`、`authn_session`、`injection`、`data_access`、`secrets_config`、`business_logic`）；`llm_integrations` 不是空的 → 加 `llm_integration`；`file_upload` → `file_handling`、`outbound_http` → `ssrf_outbound`、`webhook_inbound` → `webhooks_integrations`、`frontend_bundle` 或任何 `public_prefix: true` 的變數 → `frontend_client`、`crypto` → `crypto`、`ci_workflows` 或 `iac` → `cicd_iac`。`payments`、`oauth`、`llm_tools` 不增加面向，只影響 G1 問卷與 `level_triggers`（§11.4）。

### 11.2 工具結果正規化與合併

**目的**：W1 有多個工具（SAST、相依漏洞、套件存在性），W0 還有 secrets 掃描。v0.2 只說「輸出一律轉為 SARIF」，沒規定怎麼合併、怎麼對到叢集，也沒處理不是程式位置的結果。本節定義內部的 `ToolResult`、正規化步驟與合併規則。

**最重要的一條**：W2 reviewer（含 CMD-2 加派的輪次）與 W3 verifier **都不會收到** `ToolResult`、SARIF 或它們的摘要。工具結果只經由確定性的 Clusterer 與 Aggregator 進入裁決（[05 §3](05-bias-calibration.md#3-設計規則) 規則 5）[H]。

**輸入**：W1 各 adapter 的輸出（CAS ref）、對應的 `tool_invocation_end` 稽核事件、W0 的符號索引（§11.3）、CWE → 桶的對照表。
**輸出**：ToolResult 清單，RunState 以 `tool_results_ref` 參照（[03 §5.1](03-system-architecture.md#51-statepydantic示意)）；保存用的 run 紀錄也有 `tool_results_ref`＝sha256(JCS(本 run 中 W1、Z2 的 `tool_invocation_end` 事件之 `payload_refs`，去重排序))，沒有工具結果時為 null，由 writer 導出（`E-DERIVED`）；只交給 `W3_cluster` 與 `W3_adjudicate`。

```python
class ToolLocation(BaseModel):
    file: str                        # repo 相對路徑，POSIX 分隔
    line_start: int                  # 從 1 起算
    line_end: int
    symbol: str | None               # 區段 → 函式的對應結果；模組層級為 "<module>"
    source_symbol: str | None        # 有 source→sink 資料流時的 source

class PackageRef(BaseModel):
    ecosystem: str                   # npm、PyPI…
    name: str
    version: str | None

class ToolResult(BaseModel):
    tool_result_id: str              # sha256(JCS({adapter, rule_id, location 或 package, 工具指紋}))
    run_id: str
    adapter: str                     # 例如 "opengrep:scan"
    tool_version: str
    kind: Literal["sast", "sca", "secret", "package_existence"]
    rule_id: str | None              # SARIF 的 ruleId；SCA 為 advisory ID
    cwe: list[str]
    cwe_bucket: str | None           # common.schema 的 cwe_bucket
    level: Literal["none", "note", "warning", "error"]
    location: ToolLocation | None    # sast、secret
    package: PackageRef | None       # sca、package_existence
    sarif_ref: ArtifactRef | None    # 只含這一個 result 的 SARIF 物件；就是叢集 sarif_refs 的一項
    message_ref: ArtifactRef | None  # 工具的原始訊息（已遮罩）；只進報告的確定性部分，不進任何 LLM 輸入
    suppressed_in_source: bool       # 受測 repo 內的抑制註解；只記錄，不採用
```

**正規化步驟**（`toolresult` 模組，純函式）[H]：
1. **拆成單一結果**：adapter 的 `parse()` 把每個 SARIF result 存成獨立的 CAS 物件（只含一個 result 的 SARIF log），全部列在該次 `tool_invocation_end` 的 `payload_refs`。同一個事件的 `payload` 帶 `adapter`、`tool_version`，以及 `sarif_results[]`（每一項是 `{ref, rule_id, file, symbol, cwe_bucket}`，`ref` 就是 `payload_refs` 中的那個物件；`file`、`symbol`、`cwe_bucket` 是步驟 3–5 的結果，v0.4 起必填，用來把結果綁到叢集鍵）。這樣叢集的每個 `sarif_refs` 項目都能對到一組 (adapter, rule_id, tool_version)（`E-SARIF-REF`；範例：稽核 seq 13 的 `opengrep:scan` 1.6.0，規則 `vc.authz.update-without-owner`）。
2. **只收 `kind: fail`**：SARIF result 的 `kind` 預設是 `fail` [V][E:whitebox-56]。`level` 在 schema 中的預設值是 `warning` [V][E:whitebox-56]，但依規格 §3.27.9–3.27.10，這只適用於 `kind: fail` 且規則沒有設定（組態覆寫或 `defaultConfiguration`）的情況：`kind: fail` 而沒有 `level` 時，`level` 取自規則設定；`kind` 不是 `fail` 時，`level` 預設為 `none`，有值也必須是 `none` [V][E:whitebox-59]。`kind` 為其他值（`pass`、`notApplicable`、`informational`、`review`、`open`）的結果只留在工具紀錄，不成為 ToolResult。
3. **路徑與行號**：路徑轉成 repo 相對的 POSIX 路徑。指到 repo 以外、或路徑黑名單中的檔案 → 丟棄並記錄。欄（column）不使用。
4. **區段 → 函式**：以 W0 的符號索引，找出**包含 `region.startLine` 的最內層函式或方法**，得到完整限定符號名；不在任何函式內 → `"<module>"`。有 `codeFlows` 時，正規位置用最後一個位置（sink），第一個位置記為 `source_symbol`（[05 §4.1](05-bias-calibration.md#41-叢集鍵clusterer確定性)）。
5. **CWE 與桶**：CWE 取自規則的 metadata（SARIF 的 taxonomy 關聯或 tag）。規則沒有 CWE → 查工具包維護的 `rule_bucket_map`（adapter, rule_id → 桶）；兩者都沒有 → `other`。
6. **不採用受測 repo 的抑制註解**：受測程式碼中的抑制註解（例如行內的忽略標記）由受測 repo 的作者控制，可能被用來藏問題（[06 §1.2](06-security-legal-limitations.md#12-受測程式碼造成的注入)）。這類結果照樣正規化，只加記 `suppressed_in_source: true`，並在報告列出 [H]。
7. **去重**：(adapter, rule_id, file, symbol, 工具提供的 `partialFingerprints`) 相同的只留一筆。

**四種結果的去向**：

| kind | 來源 | 進叢集嗎 | 去向 |
|---|---|---|---|
| `sast` | Opengrep、Bandit 等 | 是 | 依叢集鍵附到叢集的 `sarif_refs`，或成為 tool-only 叢集（見下） |
| `sca` | OSV-Scanner、Grype | 否 | 依 (ecosystem, name, version, advisory ID) 合併，不同工具的 advisory 別名合成一筆；列入報告的「相依弱點」與 SARIF。位置種類不同，所以**不是**任何叢集的佐證 |
| `secret` | W0 的 secrets 掃描 | 否 | 只有位置與 HMAC，永遠沒有值（[02 W0](02-methodology.md#w0-盤點與-secrets-遮罩確定性無-llm)）；列入報告與 SARIF。前端 bundle 中的公開前綴變數見 §11.17 |
| `package_existence` | `pkgcheck:exists` | 否 | 找不到套件、首次發布很新或下載量很低 → 報告的「供應鏈」一節與 SARIF。找不到套件是確定性事實，不經投票 |

**合併規則**（只有 `sast`）[H]：
- **叢集鍵相同**：ToolResult 的 (正規位置, 桶) 與某個發現項叢集相同，或同一函式內行範圍重疊且同桶（05 §4.1）→ 附到該叢集的 `sarif_refs`。多個工具命中同一叢集時全部附上，強或弱逐項判定（見下）。
- **沒有對應的叢集** → 成為 **tool-only 叢集**（`origin: tool_only`，v0.5，[09 BL-13](09-backlog.md)）：
  - Clusterer 以同一組叢集鍵建立叢集，成員是空的。
  - 它和其他叢集一樣送 W3 驗證。驗證者收到的是正規位置、桶，以及工具包規則目錄中這條規則的**固定說明句**（以 (adapter, rule_id) 查表，不是工具的原始訊息；目錄中沒有這條規則時，用該桶的通用說明句）。驗證者不知道候選來自工具，看不到工具名稱、規則 ID 或訊息 [H]。
  - 驗證用的切片：沿用涵蓋該位置的既有切片；沒有的話，由 Slicer 以該位置為錨建立一個（§11.3）。切片只含程式碼。
  - **引發這個叢集的工具結果是「回報」，不是佐證**：它不計入 `tool_corroboration`、`tool_signal` 或 `independent_sources`。否則同一次命中會同時算成「回報」與「佐證」。同一位置上**其他**工具的結果照常算佐證或訊號。
  - 結果：校準前，tool-only 叢集最多是 `UNCORROBORATED`（R7），照一般的 CMD-2 與 G2 路由；有了校準權重之後，可以經投票確認。
  - **schema**：`origin: tool_only`；`member_finding_ids`、`families`、`lineages`、`independent_families` 都是空的，`threat_id` 為 null，`canonical_location` 有 `file` 與 `symbol`。引發叢集的工具結果記在 `tool_report_refs`（至少一筆，解析規則同 `sarif_refs`，所以位置與桶必須等於這些結果，`E-SARIF-REF`）；`sarif_refs` 只能放**其他工具**在同一位置的結果。validator（`E-CLUSTER-ORIGIN`）檢查以上各點，並拒絕把回報再放進 `sarif_refs`、或在其他 origin 的叢集填 `tool_report_refs`。成員證據的位置綁定（`E-CLUSTER-BINDING`）不適用，因為沒有成員；同一 run 指紋不得重複仍然適用。
  - 範例：K-016 是 opengrep `vc.authz.delete-without-owner` 在 `routes/invoices.ts::deleteInvoice` 的結果，該位置沒有 LLM 發現項。它的 `tool_report_refs` 是 W1 稽核事件（seq 13）中的那筆結果，`sarif_refs` 是空的，所以獨立來源是 0、裁決 V-016-1 是 `UNCORROBORATED`（R7），沒有捏造的成員或投票；報告清單把它列在 `report_only_clusters`，工具發現因此追溯得到報告。測試（`tests/test_v05_backlog_high.py`）另把 K-014 改成 tool-only，驗證回報不能再放進 `sarif_refs`。
  - 尚未涵蓋：「沒有任何發現」的 run 範例；validator 也還不檢查 tool-only 叢集是否出現在 W5 的 SARIF 輸出（範例沒有 SARIF 輸出檔）。
- **強與弱**：`sarif_refs` 的每一項，以稽核事件的 (adapter, rule_id, tool_version) 加上叢集的桶，查 `calibration.yaml` 的 `result.high_precision_rules`：
  - 有相同的一列，而且 `precision_lower95` ≥ `result.thresholds.high_precision_min.value`（預設 0.90）→ **強**，進 `tool_corroboration`。掃描器或規則包的版本與校準時不同 → 弱；
  - 其他 → **弱**，進 `tool_signal`，算 1 個獨立來源。
  - 裁決規則與決定表見 [05 §4.2](05-bias-calibration.md#42-裁決狀態與有序規則)；名單怎麼產生見 [05 §5.10](05-bias-calibration.md#510-掃描器規則的高精準名單high_precision_rules)。校準前名單是空的，所以全部是弱的（§11.11）。
  - 範例：K-014 的 `opengrep:scan` 結果不在名單中（範例的 `high_precision_rules` 是空的），所以是弱訊號：裁決 V-014-1 的 `tool_signal` 列出它、`tool_corroboration` 是空的、`independent_sources` 是 2（anthropic＋弱 SARIF），經 R6 為 `LIKELY`。

**validator**：
- `E-SARIF-REF`：每個 `sarif_refs` 與 `tool_report_refs` 項目都要對到同一 run 的 `tool_invocation_end` 事件（`payload_refs` 含這個 ref、事件是 W1 節點（ToolResult 是 W1 的輸出，與 run 的 `tool_results_ref` 一致）、`zone` 為 Z2、`payload.ok` 為 true），它的 adapter 是 `tools.yaml` 中已登錄的白箱模式（工具 zone Z2、`b4_executable: false`），而且 `licenses.yaml` 的狀態是 `OK` 或「注意」（法務閘門未結案的工具不算，N-7）。該 ref 的 `sarif_results[]` 項目的 `file`、`symbol`、`cwe_bucket` 必須等於叢集的 `canonical_location.file`、`canonical_location.symbol` 與 `cwe_bucket`；`origin: black_box` 的叢集不收 SARIF。v0.3 沒有這條，任何叢集都能借用同一 run 中無關的 SARIF 結果當弱訊號。
- `E-VERDICT-TOOLCORR`：裁決的 `tool_corroboration` 必須等於推導出的強佐證。
- `E-VERDICT-TOOLSIGNAL`：`tool_signal` 必須等於「弱 SARIF ∪ `E_fail_u` 測試結果的 `result_ref`」。
- `E-VERDICT-SOURCES`：`independent_sources` 必須等於推導值。

**沒有 LLM 發現項的路徑**[H]：MVP-0 必須有 `W1 → ToolResult 正規化 → 純工具叢集 → 裁決 → W5 報告／SARIF` 的完整路徑。run 要能參照 ToolResult 清單，叢集要能表示零個 LLM 成員，並追溯工具版本、規則、位置與證據（v0.5 的 schema 以 run 的 `tool_results_ref` 與 `origin: tool_only` 叢集的 `tool_report_refs` 表示，見上）。沿用本節的去重與裁決規則：工具自己的回報不能再算成自己的獨立佐證；校準前不能因為沒有 LLM 成員就套用「所有成員都沒有證據」的 R0，也不能憑空產生合格票；強弱證據、暫定標示與報告覆蓋限制都保留。驗收要包含「只有工具發現」「工具與 LLM 合併」「沒有任何發現」三種輸入，不能靠捏造 LLM 發現項讓流程通過。

**失敗**：單一工具失敗 → 列為缺口，其他工具繼續；全部 W1 工具失敗 → `FAILED`（[02 W1](02-methodology.md#w1-確定性掃描建立基準不用-llm)）。正規化本身失敗（例如 SARIF 不合 schema）→ 該工具視同失敗。

### 11.3 Slicer

**目的**：把 repo 切成 W2 的審查單位，讓每個家族看到**完全相同**的輸入（同等性單位，[02 W2](02-methodology.md#w2-多家族獨立審查)）。v0.2 只寫了「以 entry point 為錨、依靜態呼叫圖納入」，沒說呼叫圖從哪來、上限在哪、monorepo 與多語言怎麼處理。

**介面**：見 §2.3 的 `Slicer.slice`。它**不接收任何工具結果**；`extra_anchors` 只有位置（檔案＋符號），用於 tool-only 叢集需要的切片（§11.2）。

**輸入**：inventory、W0 的符號索引與呼叫圖、遮罩後的檔案、參與本 run W2 的模型（決定 token 上限）、W2 reviewer 範本的 sha256、遮罩對照表的 sha256。
**輸出**：`slice.schema.json` 的物件清單。

**錨點**（每一種都至少產生一個切片）：

| 錨點 | 來源 |
|---|---|
| 路由與 route handler | inventory `endpoints`（`kind: http`、`graphql`、`rpc`） |
| server action | `endpoints`（`kind: server_action`） |
| webhook | `endpoints`（`kind: webhook`） |
| 排程與背景工作 | 排程設定中宣告的函式、queue consumer。v0.3 inventory 的 `endpoints[].kind`（`http`、`server_action`、`graphql`、`rpc`、`baas_direct`、`webhook`）原本沒有排程工作的值；v0.5 加上 `kind: scheduled`（`method` 為 null，`path` 為 `schedule:<名稱>`／`queue:<名稱>`，`E-INVENTORY`，[09 BL-19](09-backlog.md)） |
| LLM 工具 handler | `llm_integrations` 的工具定義 |
| 資料庫 policy | 每張有 policy、RLS 設定或 `SECURITY DEFINER` 函式的資料表：migration 中的相關敘述，加上所有存取這張表的程式碼（包括 `baas_direct` 呼叫點） |
| 位置錨點 | `extra_anchors`（只給 W3 的 tool-only 叢集） |

**呼叫圖的來源與限制** [H]：

| 語言 | 來源 | 解析得到 | 解析不到（記為未解析的呼叫） |
|---|---|---|---|
| Python | 標準函式庫 `ast`，加上 repo 內的 import 解析 | 直接呼叫、模組限定呼叫、`self.` 方法呼叫、繼承鏈上的方法 | `getattr` 等動態分派；裝飾器在執行時註冊的函式（路由由抽取器處理）；第三方套件內部 |
| JS／TS | tree-sitter（候選，§11.1），加上 ES module／CommonJS 的 import 解析（含 `tsconfig` 的路徑別名） | 以識別字綁定解析的呼叫、字面值的動態 `import()`、client component 引用的 server action | 計算出的屬性呼叫、非字面值的 `import()`、事件驅動的呼叫 |
| SQL | migration 檔 | 資料表、policy、函式之間以名稱連結 | 動態 SQL 字串 |

- **深度**：從錨點起最多 4 層呼叫；每個函式最多納入 20 個被呼叫者（依出現順序）[H]。超過的部分記為未解析，不靜默丟棄。
- **不追進**：`node_modules`、`site-packages`、vendored 目錄、建置輸出（例如 `.next/`、`dist/`、`build/`）。
- 未解析的呼叫寫入 Slicer 的診斷輸出（CAS），並計入報告的覆蓋指標。「呼叫圖一定不完整」列在 [06 §3](06-security-legal-limitations.md#3-做不到不承諾的事) 第 34 條。

**focus 與 context**：
- **focus**：錨點的 handler，以及它往下 2 層的被呼叫者。這裡是預期會有發現項的地方；覆蓋下限（每個切片 × 每個必要面向）以 focus 計算。
- **context**：其餘納入的程式碼（middleware、model、schema、policy、更深的被呼叫者），只供理解。
- 兩者在同一個切片裡，prompt 以兩個區塊呈現。focus 可以由 `entry_points` 與呼叫深度重算，所以不另存欄位。
- 證據的位置必須在切片的檔案範圍內；在切片以外 → `NOT_FOUND`（比對只對遮罩後的切片文字進行，05 §3 規則 5）。

**monorepo**：依 workspace 設定（例如 `package.json` 的 workspaces、多個 `pyproject.toml`）把 repo 分成單元。切片不跨單元；唯一的例外是經 workspace 對應解析得到的 import。路徑一律從 repo 根目錄寫起，所以單元名稱就在路徑中。

**多語言切片**：只有下列明確的連結才跨語言：
- 程式碼 → 它讀寫的資料表的 SQL policy 與函式（依 ORM model 或 BaaS 呼叫中的資料表名稱）；
- 前端 client component → 它呼叫的 server action；
- 前端的 `baas_direct` 呼叫 → 對應資料表的 policy。
- 經 HTTP 呼叫另一個內部服務 → 不追，記為未解析。

**排除**：路徑黑名單的檔案在 W0 已經移除。另外排除 [H]：測試檔、lockfile、壓縮過的程式（例如 `*.min.js`）、產生的程式碼（記一筆 `blind_spots` 的 `generated_code`）、二進位檔、超過 1 MiB 的檔案。

**token 預算與 tokenizer**：
- 共同上限＝參與模型中最小的可用 context，減去 prompt 範本與輸出的保留量（依 `models.yaml` 的輸出上限）。
- 每個參與模型的 token 數，以它在 `models.yaml` 的 `tokenizer` 計算。`tokenizer` 為 null 時，用參考 tokenizer 計算，再乘以 1.25 的安全係數 [H]。切片的 `token_count` 取所有參與模型中的最大值，`tokenizer` 記錄是哪一個。
- 超過共同上限 → 依被呼叫者的子樹切成多個切片；每個都保留錨點 handler 作為重疊的 context，並記錄切法。某個模型怎麼切都放不下 → 記在該切片的 `excluded_models`（`context_exceeded`）。**不允許靜默截斷**。

**`slice_id`**＝sha256(JCS({files, redaction_map_sha256, prompt_template_sha256}))：
- `files` 依路徑排序；同一檔案重疊或相鄰的範圍先合併。
- `prompt_template_sha256` 是 W2 reviewer 的範本。所有面向共用同一個範本，面向只是範本的參數（§11.13）。
- 效果：程式碼、遮罩、範本都相同 → ID 相同，跨 run 可以沿用 LLM 輸出（[02 §1.6](02-methodology.md#16-執行種類與後續執行)）。遮罩表變了（例如找到新的 secret），或範本換版 → 新的 ID，不會沿用舊的輸出。
- validator 重算 `slice_id` 與 `redaction_map_sha256`（取自本 run 的遮罩對照表），不符 → `E-DERIVED`；`prompt_template_sha256` 不是 run `prompt_templates[]` 中的一個，或 `redaction_map_sha256` 不等於 run 的 `redaction_map_ref` → `E-SLICE-IDENTITY`。

**確定性**：相同的輸入 → 位元組相同的輸出，由契約測試以 JCS 比對。

### 11.4 G1 問卷與 invariants 格式

**目的**：vibe coding 通常沒有書面的安全需求（[02 W0.5](02-methodology.md#w05-安全不變量規格security-invariants-spec-g1)），G1 的核准者也多半不是資安人員。v0.2 讓 Invariant Drafter 起草整份規格再請人逐條確認，但沒給人一份看得懂的問題清單，也沒有地方寫資料分級、LLM 工具權限與限制。

**流程**：
1. W0 之後，`gates` 模組依 inventory 的 `features[]`、`blind_spots[]`、`auth`、`db`，**以程式碼**選出要問的題目（下表的「觸發」欄）。題目範本有版本，版本記在 run manifest（§11.13）。
2. Invariant Drafter 讀遮罩後的 inventory，為每一題**提議**答案。它的工具只有 `read_inventory` 與 `write_blackboard`，沒有 `read_slice`（H-C1）。提議的答案在 G1 畫面上標為「模型提議」。
3. 人在 G1 逐題確認、修改，或回答「不知道」。確認後寫入 `invariants.yaml`。逐項核准時，G1 GateRecord 的每一筆決定以 `item_sha256` 綁定該條目（該條目的 approval hash，由 validator 重算；`invariants.yaml` 的條目本身不帶 hash 欄位）（[03 §6.3](03-system-architecture.md#63-核准者來源與逐項核准)）。
4. 必答題（第 1–3 題）不能留空：核准者回答「不知道」時，G1 只能判 `NEEDS_INFO`（回到 W0.5 重擬，最多 3 輪，02 W0.5），不能 `APPROVED`。其他題回答「不知道」→ 該欄位留空，報告列出。

**問卷**：

| # | 問題（白話） | 觸發 | 寫入的 invariants 欄位 |
|---|---|---|---|
| 1 | 你的應用有哪些使用者角色？每個角色可以對哪些資料做什麼？ | 一律 | `access_matrix[]`（角色 × 資源 × 動作 → 允許或拒絕） |
| 2 | 每一筆資料屬於誰？（某個使用者、某個團隊或租戶、所有人都能看） | 一律 | `access_matrix[].ownership`：`kind` 為 `owner_field`、`tenant_field`、`membership` 或 `none`；`field` 是欄位名稱；`membership` 時 `via` 是成員關係表 |
| 3 | 哪些資料是個資或機密？ | 一律 | `data_classification[]`（`level`：`public`、`internal`、`confidential`、`restricted`；`pii`；`fields[]`） |
| 4 | AI 助理可以替使用者做哪些事？哪些事一定要先經使用者確認？ | `llm_tools` | `llm_tools[]`（`side_effect`、`requires_human_confirmation`、`allowed_roles[]`、`data_class_ids[]`） |
| 5 | 有沒有次數、頻率或金額的限制？（例如每人每天最多幾次、退款上限） | 一律 | `limits[]`（`subject`、`metric`、`value`、`scope`） |
| 6 | 哪些網站可以從瀏覽器呼叫你的 API？登入後可以導向哪些網址？ | `frontend_bundle` 或 `oauth` | `policies[]`：`cors_allowlist`、`redirect_allowlist` |
| 7 | 使用者可以上傳哪些檔案？ | `file_upload` | `policies[]`：`upload_types` |
| 8 | 你的伺服器會主動連哪些外部網站？ | `outbound_http` | `policies[]`：`outbound_hosts` |
| 9 | 哪些外部服務會用 webhook 打進來？怎麼確認真的是它們？ | `webhook_inbound` | `policies[]`：`webhook_signature` |
| 10 | 有沒有只在平台後台設定、沒寫在程式碼裡的東西？（登入方式、檔案空間是否公開、資料表的存取規則） | 有 `dashboard_only_setting` 盲點 | `policies[]`（`kind: other`）；對應 DFD 元素的出處為 `g1_declared`（§11.5） |
| 11 | 應用有沒有付款、第三方登入或 AI 工具？（確認 W0 的偵測結果） | `payments`、`oauth`、`llm_tools` | `level_triggers[]`（頂層；見下） |
| 12 | staging 與正式環境有哪些已知的差異？ | 有黑箱階段時 | `policies[]`（`kind: other`）；報告引用（[06 §3](06-security-legal-limitations.md#3-做不到不承諾的事) 第 27 條） |

**invariants 的新欄位**（`invariants.schema.json` v0.3；陣列可以是空的）：
- `data_classification[]`：`data_class_id`、`name`、`level`、`fields[]`、`pii`。這是**應用自己的**資料分級；工具包的 `data_class`（P／C，決定程式碼可以送給哪些模型）是另一回事。
- `llm_tools[]`：`tool_name`、`side_effect`（`none`、`read`、`write`、`external`）、`requires_human_confirmation`、`allowed_roles[]`、`data_class_ids[]`。
- `limits[]`：`limit_id`、`subject`、`metric`、`value`（數字）、`scope`（`per_user`、`per_tenant`、`global`）。
- `policies[]`：`policy_id`、`kind`（`cors_allowlist`、`redirect_allowlist`、`upload_types`、`outbound_hosts`、`webhook_signature`、`csp`、`other`）、`values[]`。
- `access_matrix[].ownership`：`{kind, field, via}`。原本的自由文字 `condition` 保留給人看，程式碼只用 `ownership`。
- `level_triggers[]`：放在**頂層**，與 `baseline[]` 同一層（`baseline` 是需求條目的陣列，放不進觸發）。每一項是 `{feature, standard, level, sections[]}`；`standard` 為 `asvs` 或 `aisvs`，`level` 為 2 或 3，`sections` 是章節前綴（例如 `8.2` 涵蓋 8.2.3）；`feature` 必須是 invariants 的 `applies_to_features` 值或 W0 inventory 的 `features`（否則 `E-INVARIANT-LEVEL`）。
- `baseline_levels`：`{asvs, aisvs}`，整體採用的等級（1–3）。
- 參照檢查（`E-INVARIANT-REF`）：`llm_tools[].data_class_ids` 必須是 `data_classification` 的 ID；`access_matrix[].ownership.kind` 不是 `none` 時必須有 `field`。

**為什麼要結構化** [H]：
- `ownership` 讓程式碼直接產生跨租戶、跨使用者的測試（04 範例 A 就是 `tenant_field`），也讓 Z2 的本地 RLS 測試知道每張表該怎麼隔離（§11.17）。
- `data_classification` 與 DFD 的邊界一起決定 B2 的高風險威脅（[02 B2](02-methodology.md#b2-威脅建模g3-強制簽核) 的第 2 條）。
- `llm_tools[].requires_human_confirmation` 是 W4 防護測試（§11.17）與 B2 高風險第 3 條的輸入。

**ASVS 與 AISVS 的等級**：
- **基準**一律是 ASVS 5.0 Level 1。L1 共 70 條，約佔全部需求的 20% [V][E:threat_modeling-43]；ID 格式如 `v5.0.0-8.2.2` [V][E:threat_modeling-40]。
- **依功能提高等級**：程式碼依 `features[]` 加入頂層的 `level_triggers`；G1 可以再加，不能刪。預設的觸發 [H]：

| feature | 標準與等級 | 章節 |
|---|---|---|
| `oauth` | ASVS L2 | V10 OAuth and OIDC（ASVS 5.0 的章節之一 [V][E:threat_modeling-40]） |
| `llm_tools` | AISVS L2 | C9 Orchestration & Agentic Security。AISVS 1.0 分 L1–L3，C9 是其中一章 [V][E:threat_modeling-39]；例如 9.5.2 是 L2 [V][E:threat_modeling-63] |
| `payments` | ASVS L2 | 與商業邏輯相關的章節，實作時依 ASVS 5.0 的官方資料檔選定（未查證章節編號） |
| 其他 | — | 預設不提高；G1 可以手動加入 |

- **範例**（[docs/examples/invariants.yaml](examples/invariants.yaml)）：`baseline_levels: {asvs: 1, aisvs: 1}`；兩條 `level_triggers` 涵蓋 L2 的條目：`{feature: invoices, standard: asvs, level: 2, sections: ["8.2"]}` 涵蓋 ASVS `v5.0.0-8.2.3`，`{feature: support_agent, standard: aisvs, level: 2, sections: ["9.5"]}` 涵蓋 AISVS `v1.0-9.5.2` 與 `v1.0-9.5.3`（AISVS 的條文編號是 9.5.2、9.5.3 [V][E:threat_modeling-63]；前面加 `v1.0-` 是本工具包仿照 ASVS 格式自訂的 ID 慣例；AISVS 是否有官方的版本前綴格式未查證 [H]）。這兩個 `feature` 取自 invariants 的 `applies_to_features`；上表依 inventory `features[]` 自動加入的預設觸發，範例沒有示範。

- **`E-INVARIANT-LEVEL`**：`baseline[]` 中、或測試案例（`requirement_ids`、`oracle.requirement_refs`）引用的 ASVS 或 AISVS L2 以上條目，都必須被涵蓋：`baseline_levels` 中該標準的等級 ≥ 條目的等級，或有一條同標準、`level` ≥ 條目等級、`sections` 前綴符合條目編號的 `level_triggers`。這避免「只選了 L1，卻在測試中引用 L2」（A-2）。
- **`E-TC-REQ-UNAPPROVED`**：oracle 引用的需求必須是 G1 已核准的；G1 駁回的條目不能被測試（C-10）。

### 11.5 DFD 元素出處

**目的**：W5 的 DFD 骨幹由程式碼產生，LLM 只提議（[02 W5](02-methodology.md#w5-白箱報告dfd種子威脅)）。但 v0.2 的 DFD 沒記錄每個元素是怎麼來的，程式碼也無法判斷「跨越租戶或認證邊界」。

**每個元素都有 `provenance`**：

| 值 | 意思 | 例子 | 能不能用在程式碼的判斷 |
|---|---|---|---|
| `deterministic` | 由 W0 inventory 以固定規則產生 | route 與 handler → process；資料表 → data store；外部 API 與 LLM 呼叫 → external entity；auth middleware → `auth` 邊界 | 可以 |
| `g1_declared` | 由 G1 的回答產生 | 第 2 題的 `ownership` → `tenant` 邊界；第 10 題的後台設定；第 8 題的外部主機 | 可以（標示「已宣告、未驗證」） |
| `llm_proposed` | 由 W5 或 B1 的 LLM 提議 | 標籤、額外的邊界、遺漏的元素 | G3 接受之前**不可以** |

- **G3 接受**：`llm_proposed` 元素要在 G3 被逐項接受（GateRecord 的 `item_sha256` 綁定該元素），才用於 B2 的高風險計算。出處欄位不改，保留「這是模型提的」這個事實 [H]。
- 程式碼計算「跨越租戶或認證邊界」（02 B2 高風險第 2 條）時，只看 `deterministic`、`g1_declared`，以及 G3 已接受的 `llm_proposed` 元素。

**邊界的種類**（trust boundary 的 `kind`）：

| kind | 什麼時候產生（deterministic 規則） |
|---|---|
| `auth` | 匿名可達的入口與需要登入的 handler 之間（`endpoints[].auth_required`、`middleware_refs`） |
| `tenant` | `ownership` 為 `tenant_field` 或 `membership` 的資料（`g1_declared`） |
| `network` | 網際網路與伺服器之間；伺服器與 DB 主機之間；伺服器與外部服務之間 |
| `process` | 不同的部署單元之間（monorepo 的單元、edge function 與主伺服器） |
| `third_party` | 外部服務：LLM 供應商、金流、email、BaaS 平台 |
| `browser` | 使用者的瀏覽器。會送到瀏覽器的程式碼都在這個邊界內，視為不可信 |

**browser → BaaS 資料流** [H]：
- inventory 的每個 `baas_direct` 端點，產生一條從瀏覽器端直接到 data store 的資料流；中間**沒有**伺服器的 process。依 `dfd.schema.json`，這條流以 `external_entity` → `data_store` 表示，而且至少跨越一個 `kind: third_party` 的邊界。範例 `flow-browser-uploads`（使用者的瀏覽器以簽名 URL 直接上傳到 `store-support-uploads`）跨越 `tb-internet`（`network`）與 `tb-baas`（`third_party`）。
- 這條流上唯一的授權控制是資料表的 policy，所以 DFD 把流連到 `db.tables[].policies`。
- B2 critic 的檢查清單包含每一條這類資料流：`rls_enabled` 為 `false` 或 `null` 的資料表，要有對應的威脅，或附理由駁回。這正是 vibe-coded 應用常見的問題類別，例如 Lovable 因 RLS 不足而被登錄的 CVE-2025-48757（CVE 標為 disputed）[V][E:vibe_risks-23]。

**validator**：`kind` 與 `provenance` 由 schema 強制（必填、列舉）；只有 trust boundary 的 `kind` 不是 null，資料流的兩端與跨越的邊界都要是存在的元素（`E-DFD`）。G3 是否接受，在 B2 → B3 之間由 Policy Engine 檢查（M3）。

### 11.6 種子資料生命週期

**目的**：v0.2 的 seed manifest 只有固定的 ID 與重置方式。建立種子本身、每個 run 的命名空間、LLM 試驗之間的重建、run 結束後的清理都沒有規定。另外，v0.3 要求**每個寫入請求**都綁定種子或本 job 新建的物件（H-B3，[04 §5](04-threat-to-testcase.md#5-安全等級計算規則)）。

**seed manifest 的新欄位**（`seed-manifest.schema.json` v0.3）：
- `namespace`：run 範圍的前綴樣板，必須含 `{run_id}`（schema pattern），例如 `vc-{run_id}-`。
- `seeding`：`{job_kind: "S1_seed", idempotent: true}`（兩個值都是固定的）。
- `teardown`：`{method}`，值為 `delete_namespace`、`restore_snapshot` 或 `manual`。
- `reseed_per_trial`：LLM 試驗之間是否重建種子。
- `create_only_endpoints[]`（manifest **頂層**）：`{target_id, method, path_template, side_effects, contained, created_resource}`，`method` 只能是 `POST` 或 `PUT`；可以在 run 命名空間中建立新物件的端點。`target_id` 必須是 ROE 的 http 目標（`E-SEED-MANIFEST`）。v0.5 的 `created_resource`（`type`、`id_pointer`、`path_templates`）宣告 `{created:<step_id>}` 可以用在哪些路徑，規則與例子見 [04 §5](04-threat-to-testcase.md#5-安全等級計算規則)；參考實作 `safety.created_resource_problem`、`safety.created_path_allowed`。
- `seeds.<key>.path_templates[]`（每個種子各自一份，必填，至少一項）：這個種子屬於哪些資源路徑（D11）；請求中 `{seed:key}` 所在的位置必須是其中一個樣板的變數段。
- 範例（[docs/examples/seed-manifest.yaml](examples/seed-manifest.yaml)）：`namespace: "vc-{run_id}-"`、`teardown: {method: delete_namespace}`、`reseed_per_trial: true`；`create_only_endpoints` 是 `tgt-staging-app` 的 `POST /api/chat/sessions`（建立 `chat_session`）與 `POST /api/chat/sessions/{session}/messages`（建立 `chat_message`，只能在同一個對話底下引用）；`tenant_a_invoice`、`tenant_b_invoice` 的 `path_templates` 都是 `["/api/invoices/{id}"]`。

**生命週期** [H]：

| 步驟 | 何時 | 誰做 | 做什麼 | 失敗時 |
|---|---|---|---|---|
| 1 計畫 | B3 | Test Designer＋程式碼 | 測試案例以 `{seed:<key>}` 指既有物件，以 `{created:<step_id>}` 指同一 job 前面步驟建立的物件；`data_needed.seed_data` 列出需要的種子 | 不符合寫入範圍規則 → S3（`E-TC-MUTATION-SCOPE`） |
| 2 核准 | G4 | 人 | seed manifest 的 hash 隨測試案例一起綁定 | — |
| 3 建立 | 每個目標的第一批 B4 之前 | Executor（Z3）；由 harness 產生的 S1 job，不經 LLM | manifest 已給 ID 的種子是預先準備好的，只以 GET 確認存在；沒給 ID 的種子，以擁有它的測試角色經 `create_only_endpoints` 建立，名稱帶 `namespace` 前綴。key → 實際 ID 的對照表存在 Z3 | 任一種子建立失敗 → 依賴它的 job `SKIPPED`（`seed_setup_failed`），列入 B6 |
| 4 解析 | 每個請求送出前 | Executor（Z3） | `{seed:key}` 換成對照表中的 ID，前提是請求的路徑樣板屬於該種子；`{created:step_id}` 換成該步驟回應中新物件的 ID | 路徑樣板不屬於該種子 → 不送出（S3，D11）；取不到新物件的 ID → 後續步驟不送出，結果 `ERROR` |
| 5 重置 | 有狀態改變的 S1 job 之後；S2 還原之後；`reseed_per_trial: true` 時每次試驗之前 | Snapshot Service | 依 manifest 的 `reset` 方式重置 | `seed_reset_failed`（[03 §7.6](03-system-architecture.md#76-db-快照種子資料與-oracle-唯讀存取)）：之後使用同一份 manifest 的 job `SKIPPED` |
| 6 清理 | B6 之前；`abort_handler` 還原之後 | Executor 或 Snapshot Service | `delete_namespace`：以 DELETE 刪除 namespace 內的物件，只經 `{seed:}`／`{created:}`，同樣受寫入範圍規則限制；`restore_snapshot`：還原 run 開始前的快照（`snapshot_method` 不能是 `none`）；`manual`：報告列出殘留物件的 namespace 與 key，由擁有者處理 | 缺口 `teardown_failed`，報告列出殘留物件；run 為 `COMPLETED_WITH_GAPS` |

- **ID 對照只在 Z3**：Z1 與任何 LLM 只看到 key，看不到實際 ID [H]。
- **種子 job 的請求不計入測試的上限**：建立、確認、重置、清理的請求屬於 harness 的種子 job，不計入測試案例的 `max_requests`。它們有自己的上限（每個種子最多 3 個請求），同樣經 Scope Proxy、受停止條件限制 [H]。
- **冪等**：建立步驟以 (run_id, target_id, manifest 的 hash) 為鍵；重跑時先以 namespace 與 key 找既有物件，不重複建立。

**介面**（executor；擴充）：

```python
class SeedReport(BaseModel):
    keys_ok: list[str]
    keys_failed: list[str]          # 只有 key；實際 ID 永遠不離開 Z3

class SeedService(Protocol):
    def seed(self, run_id: str, target_id: str, manifest_ref: ArtifactRef) -> SeedReport: ...
    def resolve(self, run_id: str, placeholder: str, path_template: str) -> str: ...
    # 只在 Z3 內使用；路徑樣板不屬於該種子 → ScopeViolation
    def teardown(self, run_id: str, method: str) -> SeedReport: ...
```

**STATE_DIFF 怎麼觀察狀態**：
- job 前：Snapshot Service 以 oracle 唯讀憑證，對 `oracle_tables` 中**以種子 ID 或 namespace 找到的資料列**計算 hash（`oracle_capture`）。
- job 後：再算一次並比對（`oracle_diff`）。只回傳哪些列改變、改變的欄位名稱與列數，**不回傳值**（03 §7.6）。
- ID 在 Z3 內解析，所以 Z1 不需要知道實際 ID。
- 計數型 oracle（`oracle_count`）的參數仍只能是 `seed:` 或 `const:`（seed manifest 的 `oracle_queries`）。

**validator**：寫入範圍規則（`E-TC-MUTATION-SCOPE`，該測試案例同時成為 S3 → `E-TC-ADMISSIBLE`）；`{seed:}` 的路徑樣板必須屬於該種子（D11，同樣是 `E-TC-MUTATION-SCOPE`）；`create_only_endpoints` 的目標與 `created_resource` 宣告（`E-SEED-MANIFEST`）；`{created:}` 必須用在宣告的路徑、建立的 `step_id` 不重複、GraphQL mutation 只用 POST；其他新欄位由 schema 檢查形狀（例如 `namespace` 不含 `{run_id}`、`seeding.idempotent` 不是 true → `E-SCHEMA`）。

### 11.7 Scope Proxy 實作

**目的**：Scope Proxy 是 Z3 唯一的出口，也是請求白名單真正的強制點（[03 §2](03-system-architecture.md#2-部署與信任區)）。v0.2 只寫了 DNS 固定與擋 redirect。要逐一檢查 HTTPS 請求的方法與路徑，需要 TLS 終結；長連線協定、CDN、B1 爬行也都還沒有規則。

**白名單比對的參考實作**：`safety.allowlist_match(target_id, method, path, allowlist, resolve)` 回傳具體請求對應的白名單項目，對不到就擋。路徑必須已是正規形式（含 `%` 編碼或 `.`／`..` 段的請求一律擋，不做解碼後再比對）；逐段比對同一目標、同一方法的項目：字面段要相等；`{seed:k}`／`{created:s}` 段要等於代換後的值（`resolve` 來自 seed manifest 與本 run 的建立回應）；一般 `{name}` 段只在讀取請求上可對到任一非空段，寫入請求一律不行。body 與 query 的物件綁定見下方 `request_binding_problem`。parity 測試以這個函式為準。

**per-job 身分** [H]：
- `open_job` 為每個 job 產生一個隨機的 proxy 認證權杖（256 位元），只在該 job 期間有效；回傳的 proxy 端點只接受帶這個權杖的連線。
- 工具程序只拿到自己 job 的權杖。所以每個請求都能歸屬到一個 job，一個 job 也無法借用另一個 job 的白名單。
- 無法設定 proxy 認證的工具，改為每個 job 一個監聽埠，只在該 job 的網路命名空間內可見。

**TLS 終結** [H]：
- **Z3 本地 CA**：私鑰在 Z3 產生，存在 Z3 的 secret store（或 HSM），**永遠不離開 Z3**：不進映像、不進 CAS、不進 Z1、不進任何工具容器。參照見 §5.3 的 `VIBECHECK_Z3_CA_KEY_REF`。
- **葉憑證**依目標主機簽發，效期不超過該 job，最長 24 小時。
- **工具容器**只掛載 CA 的**公開憑證**作為信任根。
- **面向目標**：以一般的 TLS 驗證連線（系統信任庫；SNI＝ROE 目標主機）。**不提供略過憑證驗證的選項**；staging 用自簽憑證時怎麼辦，見 §10 U-23。
- **終結之後**逐一解析請求：方法、正規化後的路徑（見下）、主機。`Host` 或 `:authority` 必須等於 SNI 的主機，也必須是該 job 的主機；不一致 → 擋下。

**協定**：

| 協定 | 處理方式 | 檢查什麼 | 限制 |
|---|---|---|---|
| HTTP/1.1 | 逐一解析請求 | 方法、路徑、主機、寫入範圍規則 | 不支援 pipelining；`Transfer-Encoding` 與 `Content-Length` 同時出現 → 擋下 |
| HTTP/2 | 兩端都以 ALPN 協商；做不到時降為 HTTP/1.1 | 每個 stream 算一個請求，檢查 `:method`、`:path`、`:authority` | 關閉 server push；同時的 stream 數 ≤ ROE 的 `max_concurrency` |
| WebSocket | 只接受 HTTP/1.1 的升級請求；升級請求本身要在白名單中，而且 job 的 `protocols` 含 `ws` | 訊息數與大小；伺服器傳來的文字訊息做 PII 掃描 | 每則客戶端訊息算一個請求，計入 `max_requests`；每條連線有訊息數、位元組數與時間上限 |
| SSE | 視為一個長時間的 GET | 事件的位元組數；PII 掃描 | 預設最長 120 秒，並有位元組上限；算一個請求 |

- **長連線的內容無法套用逐請求的安全等級計算** [H]。所以 WebSocket 只允許兩種用途：(a) 只接收的訂閱；(b) 逐字送出 G4 核准的 `script_turns`（§11.15）。其他用途一律 `MANUAL`。
- 經 WebSocket 或 SSE 的測試限 S0／S1，結果列入人工複核（[06 §3](06-security-legal-limitations.md#3-做不到不承諾的事) 第 34 條）。

**DNS 固定與 CDN** [H]：
- 每個 job 開始時（`open_job`）解析一次主機（dnspython [V][E:orchestration-58]），答案固定在該 job 的 `pinned_ips`。job 期間不再解析，也不理會 TTL；連不上固定的 IP → 該請求失敗，不重新解析。
- 下一個 job 重新解析。這樣 CDN 輪替 IP 時，每個 job 仍有一組固定、可以稽核的位址。
- 解析到的每個 IP 都必須是公開位址；私有、loopback、link-local 與雲端 metadata 位址一律擋下。判定以參考實作 `vchlib.safety.ip_problem` 為準（Scope Proxy 以 parity 測試對齊），除了 `not is_global` 之外，另外擋下 `DENIED_NETWORKS`：NAT64（`64:ff9b::/96`、`64:ff9b:1::/48`）、IPv4-mapped（`::ffff:0:0/96`，改以 IPv4 連線才套用 IPv4 規則）、6to4（`2002::/16`）、Teredo（`2001::/32`）、`fec0::/10`、`fc00::/7` 與 multicast。Python 的 `is_global` 對 `64:ff9b::a9fe:a9fe`（經 NAT64 到達 169.254.169.254）與 `fec0::1` 都回傳 True，所以不能只用它。
- **DNS 解析器**[H]：Scope Proxy 使用 Z3 自己的遞迴解析器，不使用目標或工具容器提供的解析器；工具容器沒有 DNS。DNSSEC 驗證在可用時開啟；解析結果與 TTL 記入請求紀錄。唯一的例外是 MVP-1 的本地目標（`localhost`、`127.0.0.1`、`[::1]`），而且只限 Z3 與目標在同一台隔離主機上。
- ROE 為目標宣告了 CDN 邊緣 IP 範圍（`targets[].edge_ip_ranges`，v0.4）時，每個解析出的 IP 都必須在範圍內，否則該 job 不開始（參考實作 `safety.ip_in_ranges`；範圍本身必須是公開位址空間的 CIDR，`E-ROE-EDGE-RANGE`）。沒有宣告時照 §10 U-18 的預設：只套用上面的規則（每個 job 固定一次解析結果，並擋下非公開位址）。
- 每批開始時的所有權重驗（`B4_preflight`）照舊。

**路徑正規化**（比對排除清單與白名單之前；C-1）：
1. percent-decode 一次；
2. 移除每一段的 `;參數`；
3. 合併連續的 `/`；
4. 解析 `.` 與 `..`；
5. 轉成小寫，再與同樣轉成小寫的樣板比對。
- 正規化後符合任何排除樣板 → 擋下（fail-closed）。例如排除 `/admin/billing/*` 時，`/Admin/billing/x`、`/admin;jsessionid=1/billing/x`、`/admin/%62illing/x` 都會被擋下。
- 解碼一次之後仍含「`%`＋兩個十六進位字元」（雙重編碼）→ 擋下 [H]。
- **反斜線**：解碼後的 `\` 一律視為 `/`（部分伺服器把 `\` 當成路徑分隔，例如 IIS 與部分 Node 路由器）；`/admin%5Cbilling/x` 正規化為 `/admin/billing/x`，會被 `/admin/billing/*` 擋下。
- **method override**[H]：請求中的 `X-HTTP-Method-Override`、`X-HTTP-Method`、`X-Method-Override` 標頭一律移除並記錄，query 或表單 body 中的 `_method` 參數 → 擋下（`safety.METHOD_OVERRIDE_HEADERS`／`METHOD_OVERRIDE_PARAMS`）。否則一個核准為 GET 或 POST 的請求可以在伺服器端變成 DELETE。
- **body 與 query 的物件 ID 綁定**[H]：白名單只約束目標、方法與路徑；寫入請求的 body 或 query 若含 ID 類欄位（鍵名為 `id`、`*_id`、`*Id`、`*ID`，任何巢狀層級），值必須是本請求路徑上的 `{seed:}`／`{created:}` 或 `object_refs` 解析後的值之一，否則擋下（參考實作 `safety.body_id_problem`，parity 測試對齊）。v0.4 宣稱這也涵蓋 Server Action 參數與 PostgREST 過濾條件，實際上擋不住（審查 2026-10-25 H-6）：參考實作沒有看 query，`id=eq.X` 反而因為值帶運算子前綴被擋；沒有過濾條件的整表 `PATCH`、`or=(...)`、`ids: [...]`、`{"invoice_id": [999]}`、`where: {id: {eq: ...}}` 與 Server Action 的位置參數全部放行。
  - **v0.5 規則**（參考實作 `safety.request_binding_problem`，parity 測試對齊）：
    - query：ID 類參數只接受原值或 PostgREST 的 `eq.<值>`；其他運算子（`in.`、`neq.`、`gt.`、`like.`、`is.`、`not.` 等）與邏輯參數 `or=`／`and=` 一律擋下，因為它們能選到綁定物件以外的資料列。
    - body：ID 類鍵下的陣列或物件、複數 ID 鍵（`ids`、`*_ids`、`*Ids`、`*IDs`）一律擋下；頂層是陣列的 body（位置參數）不以鍵名綁定，見下一點。
    - 路徑沒有變數段的寫入，query 或 body 中至少要有一個已綁定的 ID，否則擋下（整表 `PATCH`／`DELETE`）。
    - 區分「選哪些列」與「寫什麼值」。PostgREST 的 `PATCH`／`PUT`／`DELETE` 會作用於 query 選到的每一列，body 是新的內容，不是篩選條件，所以 `PATCH /rest/v1/invoices` 加上 body `{"invoice_id": <已綁定值>}` 仍是整表寫入。路徑沒有變數段的這三種方法，選取條件只能來自 query 的 `<id>=eq.<已綁定值>`；body 中 ID 類鍵的值仍必須是已綁定的值（不能把資料寫到別人名下）。只有 POST（RPC、action 呼叫、建立）可以由 body 綁定。Scope Proxy 必須把請求方法傳給參考實作；沒有方法時視為會選取列的寫入（fail closed）。
  - **Server Action**：位置參數沒有鍵名可比對。測試案例的 `request_allowlist[].server_action` 宣告 `{action_id, args}`；Scope Proxy 只在 `Next-Action` 標頭等於 `action_id`、body 等於把 `{seed:}`／`{created:}` 代換成解析值後的 `args` 時放行（`safety.server_action_problem`）。任何參照解析不到就拒絕（不再代換成 null 後拿去比對）；比對區分 JSON 型別，遞迴比較型別與值（`true` ≠ `1`，`1` ≠ `1.0`）。validator 檢查：只能用在 POST、沒有變數段的路徑，`args` 用到的參照都要列在 `object_refs`（`E-TC-MUTATION-SCOPE`）。
  - **GraphQL document**：Scope Proxy 只放行 POST，且 body 中 `query` 文字的 sha256 必須等於白名單的 `graphql_document_sha256`；GET 一律拒絕（[04 §5](04-threat-to-testcase.md#5-安全等級計算規則)，BL-35 完成解析前）。
  - 限制：不是 ID 類鍵名的欄位（例如 `invoice` 物件裡的 `ref`）仍無法用鍵名辨識，靠 G4 審查產物 [H]。
- **協定**[H]：請求帶 `Upgrade: h2c` → 拒絕（h2c smuggling）；回應的 `Alt-Svc` 標頭被移除，UDP 443 在 job 的網路命名空間中封鎖（HTTP/3／QUIC 不經 TCP proxy）；CONNECT 之後的第一個位元組不是 TLS ClientHello → 斷線。
- Scope Proxy 與 `policy/safety.py`（移植自 `vchlib/safety.py`）使用**同一個**正規化函式，由 parity 測試比對（§2.4）。

**主機**：
- `exclusions.hosts` 支援開頭的萬用字元：`*.example.com` 符合任何子網域，但不符合 `example.com` 本身（C-2）。比較前先正規化主機：去掉結尾的 `.`、大小寫摺疊、IDNA 轉換，與 DB 主機相同（§5.1）。
- **只允許 HTTPS**（C-3）：ROE 的 `targets[].base_url` 與 `stop_conditions.health_url` 必須是 `https://`；`http://` 只允許 `localhost`、`127.0.0.1`、`[::1]`（MVP-1）。這個例外同時是 IP 規則的例外——Scope Proxy 對 loopback 位址的封鎖（`safety.ip_problem`）只在目標 `environment: local`、主機正是 ROE 宣告的 loopback 名稱、且 job 在同一台主機上執行時放行；其他目標解析到 loopback 一律擋下（DNS rebinding 到 127.0.0.1 不會因此變成合法目標）。不符，或根本不是絕對 URI → `E-ROE-URL`。Scope Proxy 也不會以明文連到其他主機。

**build 識別**（H-B4）：
- `build_identity.method: header`：Scope Proxy 從回應讀取 ROE 指定的標頭，記入請求紀錄；Executor 以它填 testresult 的 `observed_build_id`。
- `method: endpoint`：`B4_preflight` 以一次 S0 GET 讀取，用 `json_pointer` 取值。
- 與 run 的 `repo_commit` 不符 → 該目標本批的 job 不執行（`BuildMismatch`，§6.1）；validator 以 `E-RESULT-BUILD` 檢查結果：`observed_build_id` 必須等於 `repo_commit`（run 的 `repo_commit` 是完整的 40 字元 commit），或較短的一方至少 12 個十六進位字元且是另一方的前綴（範例 `4f2a9c1e8b3d`）。
- `method: none` → 報告把該目標列在 `build_unverified_targets`（同樣由 `E-RESULT-BUILD` 檢查）。`environment: tester_controlled` 的目標（例如 `tgt-canary`）是我方的設施、不是受測系統，不列入；所以範例報告的 `build_unverified_targets` 是空的。

**B1 爬行的預設規則**（L-17）[H]：B1 爬行 job 的白名單由 harness 以程式碼產生，不經 LLM；它只有 S0 請求，所以不需要 G4。白名單的 hash 記入 run 與稽核事件。

| 規則 | 預設 |
|---|---|
| 方法 | 只有 GET、HEAD、OPTIONS；其他方法一律擋下，包括頁面自己發出的背景請求 |
| 路徑 | 目標的所有路徑，扣掉 ROE 的排除清單 |
| 跳過的連結 | 正規化後的路徑、查詢字串或連結文字含 `logout`、`log-out`、`signout`、`sign-out`、`delete`、`remove`、`unsubscribe`（不分大小寫），或中文介面的「登出」「刪除」「移除」「取消訂閱」。v0.4 加上 `approve`、`confirm`、`reset`、`cron`、`send`、`pay`、`toggle`、`activate`、`publish`（「核准」「確認」「重設」「送出」「付款」「發布」），以及 seed manifest `state_changing_reads` 中的每個端點；關鍵字清單只是第二道防線，W0 判定會寫入的 GET 才是主要依據 |
| 表單 | 不送出 |
| 範圍 | 只限同一個 origin，不跟到第三方 |
| 請求上限 | 每個目標 200 個請求、深度 5；ROE 可以再調低 |
| 速率 | ≤ ROE 的 `per_host_rps` |

- 被擋下的請求照 [03 §7.3](03-system-architecture.md#73-限速與停止條件) 計數。觸發停止條件時，外部視角退回「只用 schema」，並列為缺口（[02 B1](02-methodology.md#b1-系統建模兩個獨立視角)）。
- 預設值放在 `toolkit.yaml` 的 `b1_crawl`：schema 只允許 GET／HEAD／OPTIONS、`submit_forms: false`、`same_origin_only: true`、每個目標最多 200 個請求、深度最多 5；`skip_keywords` 必須包含上表的基本清單，可以再加不能刪（`E-TOOLKIT-B1`）。

**攔截式 proxy 的選型**仍未決定（§10 U-13）。mitmproxy 12.2.3 的 PyPI classifier 為 MIT [V][E:blackbox-67]，是候選之一，**尚未選定**。不論選哪一個，本節的規則都由工具包自己的程式碼強制，並以 §8.2 的 N-17、N-18、N-32、N-33 驗證。

**`JobAllowlist` 的擴充欄位**（§2.3）：`protocols`、`job_token_id`、`fencing_token`、`edge_ip_ranges`（取自 ROE `targets[].edge_ip_ranges`）。

**選型前的原型關卡**[H]：以本地拋棄式 HTTPS 目標與「越界接收器」驗證候選代理；本輪不選定產品，也不宣稱原型已通過。依上面的協定矩陣測試 Executor、ZAP、Playwright 的代理認證與信任根配置，記錄實際版本、支援與拒絕情況。必要案例：SNI／Host／`:authority` 不一致、路徑編碼與正規化差異、重複或衝突的長度標頭、越界轉址、DNS 改變、HTTP/2 多 stream 的預算、WebSocket 的核准腳本與上限、SSE 上限、租約失效與代理中斷。每個允許的案例要收到預期回應；每個禁止的案例要有拒絕紀錄，且越界接收器零命中；直接繞過出口也必須失敗。代理不支援的工具或協定標為不支援或 `MANUAL`，禁止改用直連或關閉 TLS 驗證。Executor 的必要 HTTP 工作流沒有通過就不能進 MVP-2；選用的 adapter 只在通過後啟用。U-13 依這份證據結案，之後才能宣稱實際的相容範圍。

### 11.8 Session Provider

**目的**：多角色授權測試要以正確的身分登入。v0.2 只有 `materialize`、`refresh`、`revoke_run`；沒處理第三方 IdP、MFA、CAPTCHA，也沒在測試前確認「現在的 session 真的是這個角色」。

**ROE 的登入宣告**（每個 `test_roles[]` 項目；`method`、`idp`、`mfa`、`captcha_bypass` 在 `test_roles[].login` 之內，`whoami` 與 `storage_state_encrypted` 直接在 `test_roles[]` 項目上；v0.3）：

| 欄位 | 值 | 工具包怎麼做 |
|---|---|---|
| `login.method` | 既有的 `form`、`api_token`、`oauth_password`、`browser_recipe` | `api_token`：直接以標頭送出；`form`：以 Playwright 在 `login_path` 登入；非標準的流程用 `recipe_ref`（ROE 簽署時綁定的腳本 hash） |
| `login.idp` | `local` | 應用自己的帳號 |
|  | `oauth_third_party`、`saml`、`other` | 需要 ROE 宣告的 **staging 測試用 IdP 或測試租戶**；IdP 的主機只在登入 job 中加入白名單。沒有 → 該角色的 job `SKIPPED`。**絕不**用真實使用者的第三方帳號登入 |
| `login.mfa` | `none` | — |
|  | `totp` | TOTP 種子只給**測試帳號**，存在 Z3 的 secret store；登入時由 Z3 產生驗證碼。ZAP 的 Browser Based Authentication 也支援 TOTP [V][E:blackbox-05] |
|  | `other` | 簡訊、推播等無法自動化 → 該角色的 job `SKIPPED` |
| `login.captcha_bypass` | `not_needed` | — |
|  | `staging_bypass_token` | staging 專用的略過權杖，存在 Z3 的 secret store，只送往該目標 |
|  | `blocked` | 該角色的 job `SKIPPED`。工具包**不**嘗試破解 CAPTCHA |
| `whoami` | `{path, expect_json_pointer, expect_value_from_role}` 或 null | 見下方「每批 whoami」；測試案例用到的角色不可以是 null |

- `login` 另有既有的 `target_id`、`login_path`、`recipe_ref`；它們與上表的欄位都必填（不用的填 null），不含任何憑證值。範例 ROE 的每個角色都有 `whoami` 與 `storage_state_encrypted: true`。

- 因為登入方式而 `SKIPPED` 的 job，`skip_reason` 為 `login_unavailable`，列入 B6 的未能測試清單（[06 §3](06-security-legal-limitations.md#3-做不到不承諾的事) 第 41 條）。

**每批 whoami** [H]：
- `B4_preflight` 對本批用到的每個角色，以該角色的 session 送一次 whoami 請求（S0 GET，在 preflight job 的白名單中）。
- 回應中 `expect_json_pointer` 指到的值，必須等於 ROE 為該角色宣告的值（`expect_value_from_role`，例如該角色的使用者 ID 或租戶 ID）。
- 不符或 401 → 重新登入一次再試。仍不符 → 該角色本批的 job 標 `SKIPPED`（`session_unavailable`，[03 §7.4](03-system-architecture.md#74-測試帳號與-session-providerz3)），並寫 `session_login`（失敗）稽核事件。
- whoami 與測試案例的 `reachability` 對照互補：身分錯了，該角色的 job 根本不執行；執行中 session 才失效時，`reachability` 對照會失敗，結果是 `INVALID`，不會被當成 PASS（[05 §4.2](05-bias-calibration.md#42-裁決狀態與有序規則)）。
- validator：測試案例 `data_needed.roles` 用到的每個角色都必須有 `whoami`（`E-ROE-WHOAMI`）；`login` 的列舉值由 schema 檢查。

**refresh 與撤銷** [H]：
- 401 或到期 → 自動重新登入。每個角色每小時最多登入 6 次；超過，或目標回應帳號被鎖的狀態 → 該角色停止並列入缺口，避免把測試帳號鎖住。
- `revoke_run`（run 結束或 `abort_handler`）：ROE 宣告了登出路徑時呼叫一次；一律刪除 Z3 中的 session 狀態。目標不支援伺服器端撤銷時，報告註明「session 在到期前仍有效」。

**加密的 storageState**：
- Playwright 的 storageState 含敏感的 cookie [V][E:blackbox-21]。ROE 的每個 `test_roles[]` 項目都必須宣告 `storage_state_encrypted: true`（schema 只接受 true）。
- **存放**：只在 Z3，以 AEAD 加密；金鑰在 Z3 的 secret store（參照 `VIBECHECK_Z3_SESSION_KEK_REF`，§5.3；KMS 的選型同 §10 U-05）。
- **使用**：只在 job 期間解密到工具容器的 tmpfs，job 結束就刪除。
- **不進** repo、Z1 的 CAS、Blackboard、稽核事件或任何 LLM 輸入；`SessionHandle` 只有 handle ID。
- 工具包自己的 repo 與產生的測試專案，`.gitignore` 都要包含 `playwright/.auth/`、`*.storageState.json`、`storageState*.json`、`.env`、`.env.*`、`*.pem`、`*.key`（與本 repo 的 [.gitignore](../.gitignore) 相同）。

**介面擴充**（`SessionProvider`；03 §15 的三個方法之外）：

```python
class WhoamiResult(BaseModel):
    role: str
    ok: bool
    reason: str | None           # mismatch / unauthorized / login_unavailable / locked_out
    checked_at: str

class SessionProvider(Protocol):
    def whoami(self, run_id: str, role: str, batch_id: str) -> WhoamiResult: ...
    # 不丟例外；ok 為 false 時由 B4_preflight 轉成 SessionUnavailable（§6.1）
```

### 11.9 共享平台網域的所有權證明

**目的**：vibe-coded 應用常部署在共享平台的子網域上。租用者無法在這些網域放 DNS TXT；即使能放 well-known 檔案，也只證明「能部署內容」，不證明平台允許這類測試 [H]。v0.2 對 `https://acme-staging.supabase.co` 也照樣接受 DNS TXT（H-D3）。

**共享平台網域清單**（`tools/vchlib/safety.py` 的 `SHARED_PLATFORM_SUFFIXES`；主機正規化後等於其中一項，或是它的子網域）[H]：`supabase.co`（`supabase`）、`vercel.app`（`vercel`）、`netlify.app`（`netlify`）、`firebaseapp.com` 與 `web.app`（`firebase`）、`onrender.com`（`render`）、`pages.dev`、`fly.dev`、`herokuapp.com`（這三個對應 `other`）。括號中是該網域對應的 `platform` 值。
- v0.4 加入 vibe coding 與其他託管平台（都對應 `other`）：`lovable.app`、`replit.app`、`repl.co`、`workers.dev`、`github.io`、`gitlab.io`、`amplifyapp.com`、`azurewebsites.net`、`azurestaticapps.net`、`railway.app`、`glitch.me`、`deno.dev`。
- 手寫清單一定會漏。實作版以 Public Suffix List 的 private 區段為來源（版本與 hash 記入 run manifest），這份表只負責對應 `platform` 值，並作為 validator 強制的最小集合 [H]。`tools/check_platform_suffixes.py`（選用，需要網路或本地 PSL 檔，不在 CI 執行）檢查手寫清單的每一項都在 PSL private 區段中（或是其中某條規則的上層網域）；不在其中的必須列入 `safety.PSL_EXCEPTIONS` 並寫明理由。2026-10-24 對 PSL 版本 2026-10-22 執行：`railway.app` 在 PSL 只有 `up.railway.app`、`glitch.me` 不在 PSL，兩者都保留（比 PSL 嚴格只會拒絕 DNS TXT／well-known 證明，不會放寬）。
- 清單由 `toolkit_maintainer` 以 PR 維護，每次變更都附測試。

**`ownership_proof.method: platform_project`**：
- `platform`：`supabase`、`vercel`、`netlify`、`firebase`、`render`、`other`。
- `project_ref`：平台上的專案 ID。
- `evidence_ref`：證明委任方控制該專案的文件參照，例如平台專案設定頁的匯出，存在 engagement 的證據區。由簽署 ROE 的 `infrastructure_owner` 審閱。

**`platform_policies[]`**（ROE 頂層）：`{platform, policy_url, accepted_by, accepted_at, restrictions[]}`。
- `policy_url` 是平台的安全測試政策；`accepted_by` 是登錄中的人。
- `restrictions[]` 是給人看的文字，工具包**讀不懂**。ROE 簽署人必須把其中的限制轉成機器強制的欄位：`rate_limits`、`denied_modes`、`allowed_safety_classes`、`exclusions` [H]。

**validator**（`E-ROE-PLATFORM`）：主機在清單中的目標必須用 `platform_project`，`platform` 必須等於該網域對應的值，而且 ROE 有同一個 `platform` 的 `platform_policies` 項目；這類主機一律不接受 `dns_txt`、`well_known_path`。`platform_project` 必須填齊 `platform`、`project_ref`、`evidence_ref`；`platform_policies[].accepted_by` 必須是登錄中的人。所有保證等級都適用，Lite 也一樣。

**執行時**：
- `B0_ownership_verify` 對 `platform_project` 目標不做 DNS 或 well-known 檢查。結果記為「以平台專案宣告」（`OwnershipCheck.method: platform_project`），由 Z3 簽署，並附一次 S0 的可達性 GET。
- `B4_preflight` 每批重驗 ROE 的簽章、效期，以及 `platform_policies` 仍然存在。
- 報告標示「所有權以平台專案證明，未以 DNS 驗證」（[06 §3](06-security-legal-limitations.md#3-做不到不承諾的事) 第 37 條）。
- **建議**：共享平台上的目標只允許 S0／S1，除非平台政策明文允許更侵入的測試。validator 讀不懂政策文字，所以不強制這一條 [H]。

**工具包無法驗證**：`project_ref` 是否真的屬於簽署人；政策是否仍是最新版；平台是否允許這次的特定測試；共享的基礎設施是否只服務這個租用者。這些都是簽署人的聲明（06 §3）。

### 11.10 沒有 OpenAPI 的應用

**為什麼需要**：
- Schemathesis 從 OpenAPI 或 GraphQL schema 產生測試 [V][E:blackbox-13]。它的 `ignored_auth` 只對 schema **宣告了認證**的操作執行（401 或 403 都算有強制；每個操作多送 2 個請求）[V][E:blackbox-66]。
- vibe-coded 應用常沒有 OpenAPI [H]。沒有 spec，或 spec 沒寫 `security`，這個 check 就**不執行** [V][E:blackbox-66]，而且可能不會有任何提示（靜默略過）[H]。
- `use_after_free` 在成功的 DELETE 之後預期 404，只在 Schemathesis 的 stateful 階段觸發，單次 `call_and_validate()` 不會觸發 [V][E:blackbox-66]。stateful 階段 DELETE 的目標可能取自其他回應或由工具產生，不限於工具自己建立的物件 [H]；依寫入範圍規則是 S3（§11.6），不跑。「刪除後不可存取」改以綁種子的 GENERATED_SCRIPT 驗證（[04 §4.3](04-threat-to-testcase.md#43-binding-表)）。

**輸入**：W0 inventory（`endpoints`、框架能抽出的請求 model）、G1 的 `access_matrix`、ROE 的登入方式；選用：B1 爬行錄到的 S0 流量。
**輸出**：`openapi.draft.json`（OpenAPI 3.1 草稿），附 hash。它是**測試產物**，不是應用的文件。

**產生規則**（`apispec` 模組，純函式）[H]：
1. **paths**：`endpoints` 中每個 `kind: http` 與 `webhook`，各產生一個 operation；路徑參數取自路徑樣板。`webhook` 的 operation 加註 `x-vibecheck-webhook: true`（多半需要簽章，測試常為 `MANUAL`）。
2. **不放進草稿**：`server_action`（以 Playwright 測）、`graphql`（直接用 SDL）、`baas_direct`（BaaS 自己的 API，以腳本測）。
3. **request body**：框架能抽出 model 時照抄，例如 FastAPI 的 Pydantic model；抽不出 → 空的 schema，加註 `x-vibecheck-body: unknown`。
4. **responses**：只寫 `default`。
5. **`security`**，依 G1 的 `access_matrix`：
   - 端點對應的資源與動作，有角色被允許、匿名不被允許 → 需要認證。`securitySchemes` 依 ROE 的登入方式：bearer、cookie 或 API key 標頭。
   - 存取矩陣明確允許匿名 → `security: []`。
   - 對不到存取矩陣 → 預設需要認證，並標記給 G4 審（fail-closed：寧可多測認證）。
6. **流量**（選用）：B1 的 S0 流量只用來補 W0 已有的端點，例如觀察到的查詢參數、回應的 content type。只在流量中出現的端點不加入草稿，改列 `b1_diff`（§11.1）。流量只取結構，不取值。
7. 每個 operation 帶 `x-vibecheck-provenance`：`inventory`、`traffic` 或 `g1`。

**G4 審查**：草稿是 Schemathesis 測試案例的產物，G4 以 hash 綁定核准（[03 §7.2](03-system-architecture.md#72-產物驗證g4-之前)）。人要確認路徑與 `security` 合理；草稿改了就要重新走 G4。

**其他規則**：
- 草稿不當作應用真實 API 的說明，也不參與 `b1_diff`：它由 W0 產生，拿來比對 W0 沒有意義。
- 沒有任何 `http` 端點 → 不產生草稿；需要 spec 的測試改用 Playwright 腳本，或標 `MANUAL`。

### 11.11 校準前的預設

**情況**：Calibration Lab 需要標註好的語料（[05 §5.1](05-bias-calibration.md#51-語料)；人力見 §10 U-10）。在那之前，`calibration.yaml` 不存在，或 `calibration_version` 是 null。

**預設值** [H]：

| 項目 | 校準前 | 效果 |
|---|---|---|
| 投票權重 w(m,b) | 所有模型、所有桶都是 0 | 沒有計權合格票，S＝0；R3、R4 與 R5 的投票分支都不會成立 |
| θ_confirm、θ_reject | null（視為 +∞） | 沒有靠投票得到的 `CONFIRMED_CORROBORATED`，也沒有靠權重得到的 `REJECTED` |
| `high_precision_rules` | 空陣列 | 沒有強工具佐證，所有 SARIF 都是弱訊號 |
| `provisional` | 每個可能由投票決定的裁決都是 true；R0／R1／R9／R10 決定的裁決（第 1–5 列）、強工具佐證決定的裁決（第 10 列，v0.5）與黑箱叢集是 false | 報告標示「暫定（校準前）」（`E-VERDICT-PROVISIONAL`） |
| reviewer | 不加權 | reviewer 的貢獻只經由獨立來源數（R6）。Calibration Lab 另外量測 reviewer 的精準度，但 v0.3 不把它變成權重 |

**校準前仍然會產出**：
- W0 inventory、W1 的 ToolResult。相依弱點、secrets、套件存在性都是確定性事實，不需要校準。
- 發現項、叢集與裁決。可能的狀態只有：
  - `CONFIRMED_EXECUTABLE`：事先登記解讀的確定性 FAIL 不需要校準（R1，[05 §4.2](05-bias-calibration.md#42-裁決狀態與有序規則)）；
  - `LIKELY`：獨立來源 ≥ 2，例如 2 個家族，或 1 個家族＋弱 SARIF（R6）；
  - `UNCORROBORATED`（R7）；
  - `REJECTED`：只來自 R0（沒有證據）、R10（G2 駁回）、R9（Lane A）；
  - `DISPUTED`：只來自 R11（合格 PASS 反證）。
- G2 佇列：此時只會有高嚴重度的 `UNCORROBORATED`。`DISPUTED` 只會在 W4 之後由 R11 產生，那時已經過了 G2。
- W4 與黑箱測試、種子威脅、報告、SARIF（`properties.vc_provisional: true`）。

**W3 的驗證者**：校準前的票不影響狀態，但仍保存，並在 G2 與報告中作為參考意見（例如驗證者指出的反證位置）。為了控制成本，校準前每個叢集只派 1 位合格驗證者（M＝1），成本估算以此為準（§11.12、§10 U-22）[H]。

**`high_precision_min`**：預設 0.90（[05 §5.10](05-bias-calibration.md#510-掃描器規則的高精準名單high_precision_rules)）；這個值是否合適見 §10 U-15。

**轉換**：`calibration.yaml` 存在、`calibration_version` 不是 null，而且 run 用到的每個 `model_key` 都在 `valid_for_model_keys` 中（`calibrate check`），新的裁決才可能是 `provisional: false`。validator 的推導（`E-VERDICT-PROVISIONAL`）：裁決的 `calibration_version` 或 `theta_confirm` 是 null，或叢集的每個合格驗證者模型在該桶的權重都是 0 → `provisional: true`（§2.3）。已產生的裁決不改寫；下一次重新裁決時才用新的權重。

### 11.12 成本模型與價格

**起點**：[03 §11](03-system-architecture.md#11-成本與延遲模型) 只算了 W2 與 W3 的輸入 token。本節補上其他節點、輸出與推理 token、價格欄位、執行前估算，以及超支時怎麼辦。

**要估算的呼叫**（每一列都分輸入 token 與輸出 token）[H]：

| 節點 | 呼叫數 | 說明 |
|---|---|---|
| W0.5 | 1–3 次（G1 的重擬輪數） | 輸入是遮罩後 inventory 的摘要 |
| CMD-1–CMD-5 | 每個決策點 1 次，修復 ≤2 次 | 輸入是型別化視圖，很小 |
| W2 | S × V × G | 03 §11；G＝每個切片要審的面向組數（13 個面向分成 3 組） |
| CMD-2 加派 | ≤2 輪 × 加派數 | 依 `UNCORROBORATED` 與 `DISPUTED` 叢集數估計 |
| W3 | K × M | 校準前 M＝1（§11.11） |
| W4 | 每條不變量 × ≤3 輪 × 2（生成＋critic） | — |
| W5 | DFD 標籤＋報告敘事 | — |
| B1 | System Modeler 的標籤 | — |
| B2 | V_tm＋1（每個家族建模 1 次，加上 critic；merger 預設是確定性程式碼）；另設 LLM merger 時 V_tm＋2 | L-03；與 [02 B2](02-methodology.md#b2-威脅建模g3-強制簽核)、[03 §11](03-system-architecture.md#11-成本與延遲模型) 相同 |
| B3 | 每個已接受的威脅 1 次，修復 ≤2 次 | 另外登錄 `test_implementer` 時每個威脅再加 1 次（03 §11） |
| B5 | 每個需要解讀的結果 1 次 | 事先登記的確定性 FAIL 不需要（05 §4.2） |
| B6 | 報告敘事，linter 修復 ≤2 次（§11.17） | — |
| relay | 回合數 × job 數 | 只有 adaptive 模式（§11.15）；上限見 ROE |
| Calibration Lab | 語料大小 × 模型數 × 重複次數 | 不算在 run 的預算內，另外編列 |

- **推理 token**：有推理模式的模型，推理 token 依該模型 `pricing.source` 所寫的計價方式計入；估算時另外預留一份與輸出上限相同的量 [H]。

**`models.yaml` 的價格欄位**：
- `pricing`：`{input_usd_per_mtok, output_usd_per_mtok, as_of, source}`，可以是 null。**null＝價格未知**，不是免費。
- `rate_limits`：`{rpm, tpm}`，各自可以是 null。
- `tokenizer`：字串或 null（§11.3）。
- 範例檔的 `pricing` 都是 null：價格會變，實作時查證後填入，並寫上 `as_of` 與 `source`。例如 §10 U-11 記錄的 Claude Opus 4.8 單價是每百萬 token $5／$25 [V][單源][E:providers-52]。
- 自架模型（Z4）的 API 費用記為 0，但運算時間照常計入 `max_compute_minutes`。

**執行前估算**（`vibecheck run estimate`，§4.2）[H]：
1. 先跑 W0（確定性，不用 LLM），得到實際的切片數 S、端點數、G1 題目數等。
2. 依上表與 `agents.yaml` 的綁定，算出每個階段、每個家族的呼叫數與 token 數；有價格的模型換算成 USD。
3. 與委任設定的 `budgets` 比較。任何一項預估超過上限 → 結束碼 10，並列出超過的項目。價格未知的模型列為「費用未知」。
4. `run start` 時自動做同樣的估算，結果存入 CAS，並寫進 `run_created` 稽核事件。預估超過任一上限 → `run start` 拒絕（結束碼 5）；要執行，就先提高委任設定的上限（重新簽署）。

**上限** [H]：

| 層級 | 欄位 | 來源 |
|---|---|---|
| run 總額 | `budgets.run_total.max_cost_usd` 等 | 委任設定；必填，沒有就 fail-closed |
| 階段 | `budgets.W`、`budgets.B` | 委任設定 |
| 家族 | 每個家族的 USD 上限 | engagement 的 `budgets.families`：家族名稱必須是 `models.yaml` 的家族，上限不能超過 `run_total.max_cost_usd`（`E-ENG-BUDGET`）；沒有列出的家族，上限等於所在階段的上限 |
| relay | ROE 的 `relay.max_spend_usd_per_job`、`relay.max_spend_usd_per_run` | ROE |
| 受測應用的上游 LLM | ROE 的 `upstream_llm_providers[].spend_cap_usd` | ROE |

- **價格未知的模型**：token 上限照常強制；USD 上限只能對有價格的模型強制。run 用到任何價格未知的雲端模型時，委任設定仍必須有明確的 `max_cost_usd`（fail-closed），報告註明「費用不完整」。
  - validator 不另外檢查 `pricing` 是否為 null：engagement `budgets` 的 `run_total`、`W`、`B` 每一層的 `max_cost_usd` **一律**必填（schema 要求是數字；缺值 → `E-ENG-BUDGET`），而且階段上限不能超過 `run_total`（`E-ENG-BUDGET`）。所以不論價格是否已知，都不會有沒有費用上限的 run。範例 `models.yaml` 的 `pricing` 全部是 null（`tests/test_v03_gates.py` 的 `test_unpriced_models_need_an_explicit_cost_cap`）。

**錯誤預算** [H]：重試、schema 修復與 fallback 也要花錢。每個階段最多把該階段預算的 20% 花在這些「錯誤處理」呼叫上。超過之後，該階段不再重試或修復：失敗直接記為缺票或 `MANUAL`，並寫稽核事件。這不進 GB：它不是覆蓋範圍的取捨，而是停止在壞掉的呼叫上花錢；缺票照常列入報告。

**超支時**（沿用 03 §11）：
- 達 80% → `budget_threshold` 事件，並通知 run_owner。
- 達 100%，或下一個 fan-out 的預估會超過剩餘額度 → `GB_budget_gate`。
- 家族上限先到（欄位補上之後）→ 同樣進 GB，多一個選項「移除這個家族」；多樣性降低會被記錄。
- 絕不靜默刪減覆蓋。

### 11.13 Run manifest 與 prompt 範本登錄

**目的**：一次 run 的結果要能說清楚：用了哪些設定、哪些 prompt、哪些工具版本、哪一版的裁決規則。v0.2 說「每個設定檔的 hash 都寫入 run 紀錄」，但 run.schema 沒有對應的欄位（N-5）；`rule_version` 也可以隨便填（H-E13）。

**run 紀錄的新欄位**（`run.schema.json` v0.3；RunState 見 [03 §5.1](03-system-architecture.md#51-statepydantic示意)）：

| 欄位 | 內容 | 何時寫入 |
|---|---|---|
| `config_refs` | `models`、`agents`、`tools`、`calibration`、`invariants`、`seed_manifest`；已產生的是 `{path, sha256}`，`invariants` 與 `seed_manifest` 另可以是 `{state: pending, expected_node}` 或 `{state: not_applicable, reason}` | `run_init`（`invariants` 在 G1 核准後、`seed_manifest` 在 G0b 之前才有內容） |
| `prompt_templates[]` | `{template_id, version, sha256}` | `run_init`：列出本 run 的 agent 會用到的全部範本 |
| `tool_versions[]` | `{adapter, version, image_digest}`；工具包自有程式碼的 adapter 填 Z2 映像的 digest | 每個工具第一次執行時 |
| `rule_version` | 裁決規則的版本（05 §4.2）；必須等於工具包程式中的 `RULE_VERSION` 常數（目前 `05-v0.10`），也必須等於本 run 每個裁決的 `rule_version` | `run_init` |
| `baseline_run_id` | 計算 `baseline_state` 用的基準 run（§11.16）；null＝沒有基準 | `run start` 的選項；`followup`、`regression` 預設為 `parent_run_id`（範例跟進 run 的基準是 `run-2026-09-23-001`） |

**schema 與 validator**：`config_refs` 的六個鍵都必填，不能是沒有說明的 null（`E-RUN-CONFIG`）。
- `models`、`agents`、`tools`、`calibration` 在 `run_init` 就必須是 `{path, sha256}`。`calibration` 也一樣：校準前仍要有一份 `calibration.yaml`，`calibration.schema.json` 允許它的 `result` 是 null（Calibration Lab 還沒有結果）。
- 尚未產生＝`{state: pending, expected_node}`：`expected_node` 必須是產生節點（`invariants` → `G1`，`seed_manifest` → `G0b`）。run 已經到達該節點或下游（`invariants`：G1 已核准或已有 W2 的切片／發現項；`seed_manifest`：已有 G0b、job 或 G3–G5 紀錄），或 run 已正常完成（`COMPLETED`、`COMPLETED_WITH_GAPS`），卻仍是 pending → 「應存在但遺失」（`E-RUN-CONFIG`）。中途結束（`ABORTED`、`FAILED`）的 run 只看它到達的節點：G1 前就中止的 run，`invariants` 可以維持 pending。
- 不適用＝`{state: not_applicable, reason}`：`invariants` 只有 Lane A run 可以不適用；`seed_manifest` 只要 run 沒有任何 B 階段內容（G0b、job、G3–G5）就可以不適用，Lane A 與純白箱的 Lane B run 都一樣（範例的 Lane A run 就是這樣填）。
- 已產生的項目照舊重算 hash（`E-DERIVED`）並檢查檔案種類（`E-RUN-CONFIG`）。

**run 產物的生命週期**[H]：每個預期產物都要能區分四種狀態，不能用一個沒有說明的 null 混合表示：

| 狀態 | 要求 | 消費端 |
|---|---|---|
| 尚未產生 | 記錄預期的產生節點，而且該節點尚未完成 | 可以保存中間狀態；禁止進入依賴它的節點 |
| 不適用 | 記錄省略原因與本 run 的階段計畫 | 只能略過不在計畫內的消費節點 |
| 已產生 | 有內容 hash、參照與產生節點；可讀且 hash 相符 | 通過授權與完整性檢查後才能使用 |
| 應存在但遺失 | 產生節點已完成卻沒有產物，或參照讀不到、hash 不符 | 阻止消費與 resume；不能降級成「尚未產生」或「不適用」 |

- `run_init` 必須有委任設定、toolkit、models、agents、tools、calibration（校準結果可以還沒有，但設定檔要有）。
- W0.5 完成後要有不變量草稿，G1 之後要有它的核准紀錄；兩者是不同的產物狀態，W2 等消費端同時檢查內容與授權。
- 純白箱的 run（含非 Lane A）把 `seed_manifest` 標為「不適用」；計畫含 B 階段時可以先標「尚未產生」，但 G0b 驗證 ROE 的引用前必須備齊，B4 前另外驗證種子與目標已就緒。
- resume 依已完成的節點重新檢查必要產物；擴大階段計畫時重新驗證前置條件，不能沿用「不適用」跳過檢查。
- 驗收：G1 前保存、純白箱完成、缺必要產物時 resume——前兩者可以表示，最後一個被阻擋且不偽造空產物。

**validator**：
- 依 `config_refs` 的路徑讀取檔案、重算 sha256，不符 → `E-DERIVED`（做法與既有的 toolkit、engagement 參照相同）；路徑指到的不是該種類的檔案，或不該是 null 的項目是 null → `E-RUN-CONFIG`。
- `tool_versions[].adapter` 必須是 `tools.yaml` 中已登錄的 `tool:mode`，而且每個 `tool_invocation_end` 稽核事件的 `payload.tool_version` 必須等於這裡的版本（`E-RUN-CONFIG`）。
- `rule_version` 不等於 `RULE_VERSION`，或與本 run 某個裁決的 `rule_version` 不同 → `E-RUN-RULE-VERSION`；裁決自己的 `rule_version` 不等於 `RULE_VERSION` → `E-VERDICT-RULE-VERSION`。
- 切片的 `prompt_template_sha256` 必須是本 run `prompt_templates[]` 之一（`E-SLICE-IDENTITY`，§11.3）；`baseline_run_id` 必須是另一個 run（`E-CLUSTER-BASELINE`）。

**prompt 範本登錄** [H]：
- **存放**：範本是工具包的程式碼，放在 `src/vibecheck/agents/prompts/<template_id>/<version>.md`，隨 Z1 映像發布。登錄檔 `src/vibecheck/agents/prompts/registry.yaml` 列出每個範本的 `template_id`、`version`、`sha256`、可以使用的 agent 角色、輸出 schema 的 `$id`。
- **hash**：範本檔 UTF-8 位元組（換行統一為 `\n`）的 sha256。
- **啟動檢查**：Gateway 在行程啟動與 `run_init` 時重算每個範本的 hash；與登錄檔不符 → `ConfigInvalid`，行程拒絕啟動。
- **使用**：每個 LLM 請求的快取鍵含範本的 sha256（[03 §5.8](03-system-architecture.md#58-節點邊界規則)）；W2 reviewer 範本的 sha256 也進 `slice_id`（§11.3）。
- **改版**：任何修改都是新的 `version`；舊版保留，讓舊的 run 能重現。
- **與校準的關係**：`calibration.yaml` 的 `models[]` 記錄校準時的範本 hash（[05 §5.9](05-bias-calibration.md#59-校準設定與結果的欄位)）。run 中 verifier 的範本 hash 與校準時不同 → `calibrate check` 列出受影響的桶（結束碼 10），該 agent 在這個 run 的權重為 0。這等同 [05 §5.8](05-bias-calibration.md#58-模型版本變更時的最小重跑集) 的「system prompt 範本 hash 改變」。目前由 `calibrate check` 強制，validator 還沒檢查。

**稽核**：`config_loaded` 事件列出每個設定檔的路徑與 hash；每次 LLM 呼叫的稽核紀錄含範本 ID 與版本（[03 §13](03-system-architecture.md#13-可觀測性與稽核)）。

### 11.14 供應商資料處理宣告

**目的**：C 級資料只能送到不會保留它的端點。v0.2 只在 `models.yaml` 寫了註解，程式碼無法依此判斷（H-E14）。

**engagement 的 `providers[]`**（由 `app_owner` 等人在委任設定上簽署）：

| 欄位 | 值 | 意思 |
|---|---|---|
| `family` | 例如 `anthropic`、`openai`、`nvidia` | 對應 `models.yaml` 的 `family` |
| `zdr` | `confirmed`、`not_available`、`unknown` | 組織是否已取得該供應商的零資料保留（ZDR） |
| `zdr_evidence_ref` | 文件參照或 null | 例如合約或供應商確認信的內部參照 |
| `dpa_signed` | true 或 false | 是否已簽資料處理協議 |
| `retention_days` | 整數或 null | 宣告的保留天數 |
| `region` | 字串或 null | 資料處理的區域（ISO 3166-1 alpha-2）。能收 C 級資料的雲端家族不得為 null，且要有同區域的 `data_transfer.transfers[]`（`E-ENG-TRANSFER`，[03 §8.4](03-system-architecture.md#84-資料治理)） |

**C 級路由規則**（`E-ENG-PROVIDER`）[H]：可能收到 C 級資料的 agent，它的模型必須符合下列其一：
- 自架：`api_base` 的主機**完全等於** `toolkit.yaml` 的 `z4_model_hosts` 中的一項（v0.4；v0.3 只看主機名稱是否以 `z4-` 開頭，`https://z4-evil.attacker.example` 也會被當成自架）；或
- 該家族在 `providers[]` 中是 `zdr: confirmed`，**而且** `dpa_signed: true`。

同一規則也套用到 fallback 鏈上的每個模型（`E-MODEL-FALLBACK-CLASS`）。Gateway 在執行時再檢查一次；不符 → `DataClassDenied`（§6.1），請求不送出。端點限制照舊：C 級不使用 Batch、Files 等不在 ZDR 範圍內的端點 [V][E:providers-28][E:providers-35]；OpenAI 一律 `store=false`（[03 §8.4](03-system-architecture.md#84-資料治理)）。

**工具包無法驗證**：ZDR 是否真的生效、DPA 的內容是否涵蓋這種用途、宣告的保留天數與區域是否正確。工具包只比對宣告值（03 §8.4、[06 §3](06-security-legal-limitations.md#3-做不到不承諾的事)）。`zdr_evidence_ref` 只是指向文件的參照，由簽署委任設定的人審閱。取得 ZDR 本身屬於 §10 U-01。

### 11.15 多輪對話測試

**目的**：v0.2 的多輪 LLM 測試走 adaptive relay：每一輪都由工具包的 LLM 依目標的回應產生下一句。這讓測試內容在執行時才決定，G4 核准的只是策略範本（H-E15）。

**ROE 的 `relay.mode`**：

| 模式 | 預設 | 下一輪從哪來 | 允許的保證等級 | 里程碑 |
|---|---|---|---|---|
| `scripted` | 是 | 測試案例的 `script_turns[]`：固定的使用者輪次，1 句到 `trials.multi_turn_max_turns` 句（≤ ROE `relay.max_turns`），G4 以產物 hash 核准 | 全部 | M5（MVP-3） |
| `adaptive` | 否 | Z3 → Z1 relay 依 G4 核准的策略範本產生（[03 §7.5](03-system-architecture.md#75-llm-功能測試的額外控制)） | 只有 `full` | M5 之後（[09 待辦清單](09-backlog.md) BL-10） |

**scripted 怎麼執行** [H]：
- Executor 依序送出每一句，等目標的回應完成才送下一句；不呼叫任何 LLM 產生內容。
- 每則目標回應存入 CAS（遮罩後），並做 PII 掃描（§11.17）；命中 → 停止條件，改用自架模型解讀（[03 §7.3](03-system-architecture.md#73-限速與停止條件)）。
- oracle 仍以確定性訊號為準：工具呼叫紀錄、canary、狀態差異。任何一輪 oracle 已經判定違反，可以提早結束該次試驗。
- 機率型測試的每次試驗都跑完整個腳本；`reseed_per_trial: true` 時，每次試驗前重置種子（§11.6）。
- 經 WebSocket 的聊天介面只能逐字送出 `script_turns`（§11.7）。

**adaptive 的額外條件**：委任設定是 `assurance_profile: full`。它仍受 ROE `relay` 的限制：模型清單、`max_turns`、每 job 與每 run 的花費上限，以及 03 §7.5 的輸出檢查（不得含 URL 或主機名稱、不得含遮罩對照表的內容）。

**validator**：
- `multi_turn: true` 且 ROE `relay.mode: scripted` 時，測試案例必須有 `script_turns[]`，句數在 1 與 min(`trials.multi_turn_max_turns`, ROE `relay.max_turns`) 之間；`multi_turn: false` 的測試案例 `script_turns` 必須是 null。違反 → `E-TC-SCRIPT`（`test_scripted_relay_needs_script_turns`、`test_script_turns_only_for_multi_turn`）。
- ROE `relay.mode: adaptive` 只允許在 `assurance_profile: full` → 否則 `E-ROE-RELAY-MODE`（`test_adaptive_relay_only_in_full`）。
- 範例 ROE 是 `relay.mode: scripted`；範例的測試案例都不是多輪，`script_turns` 都是 null。

### 11.16 SARIF 輸出與報告回饋

**目的**：v0.2 只說「輸出 SARIF」與「結果回貼 PR」。本節規定 SARIF 欄位怎麼對應、跨 run 怎麼對上同一個問題、追溯矩陣有哪些欄，以及怎麼把結果安全地回饋給開發者。SARIF 2.1.0 是 OASIS 標準 [V][E:whitebox-17]；下文用到的欄位與列舉值都出自它的官方 JSON schema [V][E:whitebox-56]，`kind` 與 `level` 的搭配規則出自規格正文 §3.27.9–3.27.10 [V][E:whitebox-59]。

**對應表**：一個叢集，或一筆確定性的工具結果 → 一個 SARIF `result` [H]。

| SARIF 欄位 | 來源 | 規則 |
|---|---|---|
| `ruleId` | 叢集的桶與主要 CWE | `vibecheck/<cwe_bucket>/<CWE-n>`；主要 CWE＝成員中出現最多者，同數時取編號最小者。工具結果另用 `vibecheck-tool/<adapter>/<rule_id>` |
| `level` | 嚴重度 rubric（§11.17）＋`kind` | 只有 `kind: fail` 的 result 依嚴重度給值：critical、high → `error`；medium → `warning`；low → `note`；info → `none`。`kind` 不是 `fail`（`review`、`open`、`pass`，以及 `informational`、`notApplicable`）的 result 一律寫 `level: none`：SARIF 2.1.0 規定 `level` 不是 `none` 時 `kind` 必須是 `fail`，`kind` 不是 `fail` 時 `level` 必須是 `none` [V][E:whitebox-59]。這些 result 的嚴重度只放在 `properties.vc_severity` |
| `kind` | 裁決狀態 | `CONFIRMED_*`、`LIKELY` → `fail`；`DISPUTED` → `review`；`UNCORROBORATED` → `open`；`REJECTED` 預設不輸出（`--include-rejected` 時以 suppression 輸出）；黑箱的 PASS 結果只在 `--include-pass` 時以 `pass` 輸出。`kind` 不是 `fail` 的 result，`level` 一律 `none`（見上一列） |
| `message.text` | 確定性範本 | 由桶、CWE、位置、狀態組成；**不放** LLM 的敘事 |
| `locations[].physicalLocation` | 成員證據中 `MATCHED` 或 `MATCHED_SHIFTED` 的位置 | repo 相對路徑與行範圍；不放程式片段 |
| `locations[].logicalLocations` | 叢集的正規位置 | 完整限定符號名 |
| `partialFingerprints` | 叢集的 `fingerprint` | 鍵為 `vibecheck/v1`。不含行號，所以程式移動幾行也不變 |
| `baselineState` | 叢集的 `baseline_state`；裁決為 `FIXED`（審查 r11）的叢集一律輸出 `absent`，並以 `suppressions[]`（`status: accepted`，`justification` 指向回歸測試結果）標示 | `new`、`unchanged`、`updated`、`absent`；沒有基準 run 時省略 |
| `suppressions` | G2 駁回、回饋 | G2 駁回 → `kind: external`、`status: accepted`，理由指向 GateRecord；開發者回報誤報但尚未判定 → `status: underReview`；判定是誤報 → `accepted`；判定不是誤報 → `rejected`（見下方「誤報回饋」） |
| `webRequest`、`webResponse` | 黑箱測試結果 | 方法、目標 URL、狀態碼；標頭去掉 `Authorization`、`Cookie` 等認證資訊；**不放** request 與 response 的本體，只放 hash |
| `rank` | 不使用 | —（嚴重度放在 `properties.vc_severity`） |
| `properties` | 工具包自己的欄位 | `vc_cluster_id`、`vc_status`、`vc_provisional`、`vc_origin`、`vc_families`、`vc_independent_sources`、`vc_test_evidence`、`vc_threat_ids`、`vc_requirement_ids`、`vc_severity`（rubric 結果，每個 result 都有，不論 `kind`）、`vc_severity_inputs`、`vc_reopened`、`vc_rule_trace_ref` |

- 匯出的 SARIF 以 SARIF 2.1.0 的官方 schema 驗證（07 的 M4-X7、MVP0-X3），**並**由匯出器另外檢查 §3.27.9–3.27.10 的 `kind`／`level` 規則：每個 `level` 不是 `none` 的 result，`kind` 都是 `fail`（或省略）；每個 `kind` 不是 `fail` 的 result，`level` 都是 `none` [V][E:whitebox-59]。schema 驗證抓不到這條規則，違反時匯出失敗 [H]。
- 相依弱點、secrets、套件存在性（§11.2）以 `vibecheck-tool/...` 的 `ruleId` 輸出，`properties.vc_origin: tool`，不帶裁決狀態。

**指紋與基準狀態**（H-B5）：
- 叢集的 `fingerprint`＝sha256(JCS({cwe_bucket, file, symbol}))；黑箱起源的叢集用 {cwe_bucket, target_id, method, path_template}。validator 重算（`E-CLUSTER-FINGERPRINT`）。
- `baseline_state` 對 `run.baseline_run_id` 計算（[05 §4.1](05-bias-calibration.md#41-叢集鍵clusterer確定性)）：
  - `new`：基準 run 沒有這個指紋；
  - `unchanged`：指紋相同，成員證據的 hash 也相同；
  - `updated`：指紋相同，證據改變；
  - `absent`：基準 run 有、本次沒有；只列在 report-manifest 的 `absent_fingerprints[]`，並以 `baselineState: absent` 輸出；
  - 另外，叢集有布林欄位 `reopened`（只是資訊，不是 `baseline_state` 的值）：本 run 是 `new`，但在更早的 run 曾是 `absent`；只能出現在 `new` 的叢集上（`E-CLUSTER-BASELINE`）。
  - `baseline_state`、`absent_fingerprints` 由 validator 對基準 run 重算（`E-CLUSTER-BASELINE`）；範例的叢集都是 `baseline_state: null`。
- **已知的限制**：函式改名或檔案搬移 → 舊指紋 `absent`、新指紋 `new`，不會被當成同一個問題 [H]。

**追溯矩陣樣板**（B6 的 `traceability.json` 與報告中的表格；每一列是「一個威脅 × 一個需求 × 一個測試案例」）[H]：

| 欄 | 來源 | 空值規則 |
|---|---|---|
| `threat_id` | 威脅模型 | 必填 |
| `taxonomy` | 威脅的分類與版本，例如 `owasp-llm@2026:LLM01`、`owasp-api@2023:API1` | 必填 |
| `dfd_element_ids` | DFD（含出處） | 只有種子威脅時可以是空的 |
| `source_cluster_id`、`cluster_fingerprint` | 種子威脅；黑箱起源時為黑箱叢集 | — |
| `source_finding_ids` | 叢集成員 | 可以是空的 |
| `requirement_id`、`requirement_source`、`asvs_level` | invariants 與需求 | 必填 |
| `testcase_id`、`adapter`、`safety_class` | 測試案例 | 沒有測試時為空，改填 `gap_kind` |
| `g4_decision` | G4 GateRecord | 沒有測試時為空 |
| `result_ids` | 測試結果（含重播） | 同上 |
| `outcome` | `PASS`、`FAIL`、`INVALID`、`ERROR`、`SKIPPED`、`STOPPED` | 同上 |
| `controls_passed` | 例如 `2/2` | 同上 |
| `fail_oracles` | 測試結果 | 不是 FAIL 時為空 |
| `evidence_class` | `E_proof`、`E_fail_u`、`E_pass`、`E_inc` | 沒有測試時為空 |
| `verdict_status`、`provisional` | 最新一版裁決 | 必填 |
| `baseline_state` | 叢集 | 沒有基準 run 時為空 |
| `severity` | 嚴重度 rubric | 必填 |
| `observed_build_id`、`build_verified` | 測試結果、ROE 的 `build_identity` | `method: none` 時 `build_verified: false` |
| `gap_kind`、`gap_reason` | 未能測試清單 | 有測試結果時為空 |

**PR 與 issue 回饋** [H]：
- **只由程式碼發布**：`reporter` 的 publisher 在 W5（白箱）或 B6 之後執行。預設**關閉**，由委任設定開啟（§10 U-19）。開關是 engagement 的 `publishing`：`enabled: false` 時 `platform` 必須是 null、`token_scopes` 必須是空的；開啟時必須宣告平台（目前只有 `github`）與最小權限的權杖範圍，只能是 `metadata:read`、`issues:write`、`pull_requests:write`，不能有程式碼存取權（`E-ENG-PUBLISH`）。範例是關閉的。
- **每個 run 一則摘要留言**：放在 PR 上；以隱藏標記找到同一系列 run 的舊留言並更新，不重複張貼。
- **每個問題一個 issue 或逐行留言，以指紋去重**：同一 repo 已有相同 `fingerprint` 的未關閉 issue → 更新它（加上本次 run ID 與 `baseline_state`），不開新的。`absent` → 在 issue 留言「本次未出現」，但**不自動關閉**，由人關閉。
- **只發布**：`CONFIRMED_*`、`LIKELY`，以及嚴重度 high 以上的 `UNCORROBORATED`；其他只出現在摘要與報告中。每一則都標示是否為暫定裁決。
- 發布的內容只有確定性欄位與修正說明（見下）。Reporter 的敘事只放在報告檔，不發布到 PR。

**誤報回饋** [H]：
- 開發者在 PR 或 issue 上的留言**只是提示**，工具包不自動採用：留言者的身分與內容都不可信，可能是任何人，也可能含有注入。
- 由登錄中的人（`security_reviewer` 或 `app_owner`）以 CLI 簽署回饋紀錄：`vibecheck feedback add --fingerprint FP --label LABEL --reason TEXT --sign ...`（§4.2）。
- 標籤：`false_positive`、`true_positive`、`wont_fix`（接受風險）、`duplicate`、`needs_info`。
- 去向：
  - 下一個 run 的 SARIF `suppressions`：`false_positive` → `accepted`；`needs_info` → `underReview`；
  - Calibration Lab 的**候選**語料，來源標為 `developer_feedback`。它不是真值，要照 [05 §5.1](05-bias-calibration.md#51-語料) 的雙標註流程確認後才能使用；確認為誤報的，也用來重新檢查 `high_precision_rules`（[05 §5.10](05-bias-calibration.md#510-掃描器規則的高精準名單high_precision_rules)）。
- `app_owner` 是利益衝突方，所以它單獨簽署的 `false_positive` 的 `sarif_suppression` 是 `underReview`，直到一位 `security_reviewer` 以 `co_signed_by` 副簽才是 `accepted`；叢集在採用回饋的 run 中 `baseline_state: updated`（程式碼改了）時抑制失效，回到 `underReview`；被抑制的項目列入 ASI09 抽查（[06 §1.1](06-security-legal-limitations.md#11-以-owasp-agentic-top-10-檢視工具包)）。範例 FB-001 因此是 `underReview`。
- `false_positive` 一律要兩個人（`signed_by` 與 `co_signed_by` 不同人），其中一位是**沒有**核准該叢集 G2 決定的 `security_reviewer`；單獨一位資安審查者、或推翻自己 G2 決定的審查者，都不能單獨抑制。
- 回饋紀錄是 `feedback.schema.json`：指紋必須是所指叢集的指紋，該叢集要屬於同一委任的 run；`duplicate` 必須指向同一委任另一個叢集的指紋；`sarif_suppression` 依標籤決定（`false_positive` → `accepted`、`needs_info` → `underReview`、其他 null）；紀錄恰好有一個簽章，由 `signed_by` 的人以登錄金鑰簽署，而且這個人要有 `security_reviewer` 或 `app_owner` 角色。範例 FB-001：app_owner 把純工具叢集 K-016 標為誤報。採用回饋的 run 以一筆已錨定的 `feedback_recorded` 稽核事件記錄它（payload 釘住 `feedback_id` 與 `feedback_sha256`），簽章以該事件的收件時間驗證；範例 FB-001 由跟進 run `run-2026-10-07-001` 記錄。

**給開發者 AI 助手的修正說明**（fix brief）[H]：每個發布的問題附一份，以確定性範本產生。
- **內容**：桶與 CWE；位置（檔案、行、符號）；違反的 G1 不變量（原文）；證據（測試 ID、oracle 類型、請求摘要）；預期行為（取自不變量）；驗收方式（必須通過的 W4 或黑箱測試 ID）；限制（不得刪除或停用該測試，要保留回歸測試）。
- **不得包含**：secrets（只寫位置與 hash）、目標回應的本體、個資、測試帳號或 staging 憑證、攻擊輸入的本體（只寫測試 ID）、LLM 的自由文字。
- 發布前以遮罩函式與 PII 偵測器（§11.17）掃描一次；命中 → 不發布該則，報告列出。
- 長度上限 1,500 字。

**publisher 權杖的權限**（最小權限）[H]：
- 只對**受測的那一個 repo** 有效；
- 只允許：讀取 repo 的 metadata、寫 issue、寫 PR 留言；
- 不允許：寫程式碼內容、改 workflow、管理設定、讀 secrets、存取其他 repo；
- 盡量用短效權杖（具體做法依託管平台而定，實作時確認，未查證）；
- 存在 Z1 的 secret store，以 `VIBECHECK_PUBLISHER_TOKEN` 注入，只有 publisher 讀取（§5.3）。publisher 是 Z1 中除了 Gateway 以外唯一能對外連線的元件，而且只能連設定的託管平台 API（§1.2 規則 5）。

### 11.17 確定性輔助規則

**目的**：審查指出幾個原本交給 LLM、其實可以由程式碼決定的地方（M-G5）。規則越確定，結果越能重現，也越不受受測內容的注入影響 [H]。

#### 嚴重度 rubric

報告、SARIF 的 `level`（只用於 `kind: fail` 的 result；其他 result 的 `level` 是 `none`，嚴重度放在 `properties.vc_severity`，見 §11.16）與 issue 的排序所用的嚴重度，由下列四個輸入以程式碼計算 [H]：

| 輸入 | 取值 | 來源 |
|---|---|---|
| 桶 | 叢集的 `cwe_bucket` | 叢集 |
| 資料等級 | 受影響資料的最高 G1 等級（`restricted`、`confidential`、`internal`、`public`），另看 `pii` | invariants＋DFD（位置所在的 process 讀寫的 data store） |
| 可達性 | `internet`、`internal`、`unknown` | inventory＋DFD 的 `network` 邊界 |
| 認證需求 | `none`（匿名）、`any_user`、`privileged` | `endpoints[].auth_required`、存取矩陣 |

計算：
1. **基本分**：`authz`、`authn`、`injection`、`secrets`、`llm_specific`、`deserialization` → 3；`ssrf`、`path_traversal`、`crypto`、`config` → 2；`other` → 1。
2. **資料**：`restricted` 或 `confidential`，或 `pii` 為 true → ＋1；`public` → −1。
3. **可達性**：`internal` → −1；`unknown` 視同 `internet`（fail-safe），不加減。
4. **認證需求**：`none` → ＋1；`privileged` → −1。
5. 結果夾在 0 到 4 之間：4＝`critical`、3＝`high`、2＝`medium`、1＝`low`、0＝`info`。
6. **無法解析的輸入**：可達性未知視同 `internet`；資料等級無法對應（位置所在的 process 沒有流向任何能對應到 inventory 資料表的 data store）不加減；位置沒有對應的端點（例如 migration 檔）認證需求不加減。無法解析的輸入永遠不會降低分數。

- reviewer 提議的嚴重度照樣保存，報告同時列出兩者。人在 G2 或 G3 可以改，調低要附理由。
- rubric 不改變裁決，但 v0.4 起**決定路由**：G2 佇列、W4 輸入、B2 高風險條件 4 與「只列報告的叢集」都用 rubric 嚴重度（[02 W3](02-methodology.md#w3-交叉驗證與裁決g2)、[02 W5](02-methodology.md#w5-白箱報告dfd種子威脅)）。v0.3 用成員自報的最高嚴重度，等於讓單一家族的 LLM 決定哪些項目給人看。W3 時 DFD 只有確定性骨幹，可達性無法判定就視同 `internet`。validator 以同一套規則推導每個叢集的 `severity`（`derive.rubric_severity`：端點由 inventory 依 `canonical_location.file` 或黑箱端點對應，process 由 DFD 的 `evidence_refs`（`endpoint:`／`code:`）對應，data store 經 `inventory:/db/tables/<i>` 對應到資料表再對應 G1 `data_classification` 的欄位前綴；`E-CLUSTER-SEVERITY`），G2 路由檢查用它（`E-PIPELINE`）。

#### 報告敘事 linter

Reporter 的敘事（LLM 寫的）寫入報告前，由程式碼檢查 [H]：
1. **每個主張都要有 ID**：敘事中每一段只要提到發現、狀態或結果，就要引用至少一個本 run 中存在的 ID：叢集 `K-`、裁決 `V-`、測試結果 `R-`、威脅 `T-`、需求 ID。引用不存在的 ID → 失敗。
2. **狀態用語要對得上**：寫「已確認」只能引用 `CONFIRMED_*` 的裁決；寫「可能」只能引用 `LIKELY`；暫定裁決必須寫出「暫定」。
3. **禁用的說法**：「沒有漏洞」「安全無虞」「已完全測試」「100% 覆蓋」，以及英文的同義說法（例如 no vulnerabilities、fully secure）。結果是 PASS 時一律寫「在測試條件下未重現」（[06 §3](06-security-legal-limitations.md#3-做不到不承諾的事) 第 28 條）。
4. **數字要一致**：敘事中的數字必須等於 report-manifest 的 `metrics` 與矩陣的計數。
5. **不得包含**：URL（repo 內的相對路徑除外）、主機名稱（ROE 目標 ID 除外）、遮罩對照表中的任何內容。
- 失敗 → 把錯誤清單送回 Reporter 修復，最多 2 次；仍失敗 → 丟棄敘事，只輸出確定性部分，敘事欄標示缺漏（[02 B6](02-methodology.md#b6-報告)）。

#### B2 的確定性 merger 鍵

- 各 Threat Modeler 產生的威脅，先以程式碼合併。鍵＝sha256(JCS({dfd_element_id, taxonomy, category, source_cluster_id}))；`taxonomy` 含版本（例如 `stride`、`owasp-llm@2026`）；沒有 `source_cluster_id` 時為 null [H]。
- 鍵相同 → 合成一筆，`modeled_by` 列出所有提出的家族。
- 鍵不同但可能重複 → Merger（LLM）只能**提議**合併；提議在 G3 顯示，由人決定。Merger 不能自行刪除任何一筆。
- 種子威脅一律保留自己的一筆，不會被合併掉（[02 B2](02-methodology.md#b2-威脅建模g3-強制簽核) 的多模型流程第 4 步）。

#### W4 的工具防護測試（假模型輸出）

- 對 `llm_integrations` 中有工具的功能，W4 產生以**腳本式假模型**取代 LLM 用戶端的測試。假模型回傳固定的工具呼叫，例如「為另一位使用者的訂單呼叫 refund」；測試斷言應用的防護會擋下它：工具的 handler 沒有被執行，或進入「等待使用者確認」的狀態 [H]。
- 替換點是 inventory 記錄的 SDK 呼叫點：Python 以 mock 替換用戶端，JS／TS 以模組 mock 替換。
- 在 Z2 執行，沒有網路，不呼叫真的 LLM。假模型的輸出只是工具呼叫的 JSON，不含攻擊文字。
- oracle 取自 G1 的 `llm_tools[].requires_human_confirmation` 與 `allowed_roles`。需求都經 G1 簽核，又有一個通過的 `oracle_can_pass` 對照（正常使用者對自己的訂單呼叫 → 允許）時，FAIL 就是事先登記的 `E_proof`（[05 §4.2](05-bias-calibration.md#42-裁決狀態與有序規則)）。
- 範例：`support-agent-app`（§8.3）。

#### Z2 內的本地 RLS 測試

- 依 inventory 中的 migrations，在 Z2 job 內啟動一個**拋棄式 PostgreSQL**（鎖 digest 的映像，沒有網路），依序套用 migrations [H]。
- 依 G1 的 `ownership` 建立合成的使用者與租戶，以各角色的身分執行固定的查詢：租戶 A 讀不到、也改不到租戶 B 的資料；`ownership` 不是 `none` 的資料表若 `rls_enabled: false` → FAIL。
- BaaS 特有的認證函式（例如取得目前使用者 ID 的函式）以本地替身模擬；替身與平台是否相容，要在實作時確認（候選，未查證；§10 U-21）。
- 結果是 W4 的 testresult，oracle 類型為 `TOOL_CHECK`，對應 G1 的需求。
- 範例：`notes-rls-app`（§8.3）。

#### Z2 建置政策

W4 需要安裝相依並建置受測程式 [H]：
- **網路**：只允許 Z2 的套件鏡像（`mirror_only`），沒有其他出站。
- **鎖檔必填**：例如 `package-lock.json`、`pnpm-lock.yaml`、`yarn.lock`、`poetry.lock`、`uv.lock`，或帶 hash 的 requirements。沒有鎖檔 → 該單元的 W4 標 `MANUAL`（`no_lockfile`），列入缺口。
- **只安裝鎖檔中的套件**，加上預先核准的測試相依（例如 Hypothesis、fast-check、pytest）。鏡像只提供通過套件存在性檢查的套件，所以幻覺套件裝不起來。
- **停用安裝腳本**：以各套件管理器的對應選項關閉，與 [03 §2](03-system-architecture.md#2-部署與信任區) 的「預設關閉 lifecycle scripts」一致。
- 資源上限與輸出遮罩照 Z2 的規則。
- **測試與受測程式隔離**[H]：受測 repo 可以帶自己的 `conftest.py`、pytest 外掛、`vitest.config`／`setupFiles` 或 `sitecustomize`，在測試行程內改寫 assertion 或結果。所以：
  - 以乾淨的設定執行：pytest 用 `-p no:cacheprovider --noconftest`、`PYTEST_DISABLE_PLUGIN_AUTOLOAD=1` 與 harness 自己的 `-c` 設定檔；vitest／jest 以 harness 的設定檔執行，忽略 repo 的 setup 檔；`PYTHONNOUSERSITE=1`，不載入 repo 的 `sitecustomize`。
  - outcome 與對照的結果**不在**受測程式的行程中判定：測試只輸出結構化的觀察結果（例如本地 Postgres 的資料列 hash、假模型的工具呼叫紀錄），由 Z2 的另一個行程依 w4-testcase 的 oracle 計算 PASS／FAIL，再寫入 `sandbox_job_end`（連同 PR1 的三個 hash）。
  - **觀察資料的可信來源**[H]：受測行程輸出的觀察資料仍可能被受測程式偽造，所以 oracle 只能用 harness 行程**自己取得**的觀察：本地 Postgres 由 harness 以唯讀連線直接讀（不是測試回傳的列）；假模型的工具呼叫紀錄由 harness 端的假模型伺服器寫入（受測行程只持有用戶端）；檔案系統觀察在受測行程**結束後**由 harness 讀取；受測行程對觀察資料目錄沒有寫入權限（只讀掛載）。測試結果以 `observations_source: harness | sut` 宣告來源；`sut` 的觀察只能支持 `E_inc`，不能成為 `E_proof`／`E_pass`（`derive.classify_result`），W4 結果必填（`E-W4-OBSERVATION`）。執行器的實作列在 [09 BL-50](09-backlog.md)。
  - 受測程式寫入結果目錄以外的檔案一律丟棄。

#### 前端 bundle 中的公開前綴 secret

- W0 `env_vars` 中 `public_prefix: true` 的變數，若名稱符合 secret 樣式（含 `SECRET`、`PRIVATE`、`SERVICE_ROLE`、`PASSWORD`，或以 `_KEY`、`_TOKEN` 結尾）→ 確定性的發現，以 `inventory_fact` 證據（`/env_vars/<i>/public_prefix`）回報 [H]。
- 工具包假設公開前綴的變數會被打包進前端（這是這類前綴的用途），所以不論值是什麼都當作已公開 [H]。W0 的 secrets 掃描在這些檔案找到的結果（只有位置與 hash）一併列出。
- 範例：`notes-rls-app` 的植入問題（§8.3）。

#### 具名的 PII 偵測器

- **用在**：W0 的個資掃描、黑箱回應的 PII 停止條件（[03 §7.3](03-system-architecture.md#73-限速與停止條件)）、relay 與 scripted 多輪的目標回應、fix brief 與 PR 發布前的掃描、報告輸出前的掃描。
- **候選**：Presidio（presidio-analyzer 2.2.364 在 PyPI 標 MIT [V][E:whitebox-57]）。它依賴的語言模型等套件另有授權，採用前要逐一登錄（未查證）。**尚未選定**（§10 U-16）。
- **未決定前的預設** [H]：工具包自己的規則式偵測器，涵蓋 email、電話號碼、信用卡號（加 Luhn 檢查）、常見的身分證號格式（加檢查碼）。「高信心命中」＝樣式符合，而且檢查碼正確。
- 偵測器在 Z1 與 Z3 都要能用，所以放在 `pii` 模組（L2，不依賴 Z1 的模組；§1.2）。偵測器本身不連網。

#### 覆蓋指標

- report-manifest 的 `metrics` 由 validator 以本 run 的測試結果重算：`results_total`、`results_invalid`、`control_pass_rate`（PASS 的對照結果數 ÷ 全部對照結果數，四捨五入到小數 4 位；沒有對照時為 null）（`E-REPORT-METRICS`）。範例報告是 5 個結果（含 W4 的 R-WTC-015-01-1）、0 個 `INVALID`、`control_pass_rate` 1.0。
- v0.5（[09 BL-20](09-backlog.md)）另有三個指標，也由 validator 重算：`access_matrix_coverage`（本 run 的 testcase 與 w4-testcase 以 `access_cells` 宣告涵蓋的 G1 矩陣格子 ÷ 總格數，每格必須在矩陣中，`E-TC-ACCESS-CELL`）、`endpoint_slice_coverage`（handler 檔案在本 run 切片中的端點 ÷ 總數）、`endpoint_test_coverage`（被黑箱 testcase 的 `request_allowlist` 打到的端點，方法與路徑樣板都相同 ÷ 總數）。範例是 0.5714、0.8571、0.8571：矩陣 7 格中，範例 B′ 的工作區文件 3 格（BL-47）沒有 testcase；新增的排程工作沒有切片也沒有測試。
- 上面兩個測試覆蓋率只代表**計畫**，所以拿掉全部測試結果仍是 0.5714 與 0.8571。改名為 `planned_access_matrix_coverage`、`planned_endpoint_test_coverage`，並新增 `executed_access_matrix_coverage`、`executed_endpoint_test_coverage`：只算至少有一個有效執行結果的測試案例（outcome 為 PASS 或 FAIL，INVALID／ERROR／SKIPPED／STOPPED 不算；對照全部 PASS；本 run 稽核紀錄中恰好一筆已錨定的 `sandbox_job_end`，outcome 與三個 hash 相符，`checks.execution_backed`）。報告正文必須把 planned 與 executed 並列；只寫其中一個不符合報告契約。`endpoint_slice_coverage` 量的是 W3 實際審查的切片，名稱不變。

**里程碑**：嚴重度 rubric、敘事 linter、W4 防護測試、本地 RLS 測試、Z2 建置政策、公開前綴 secret → M2（MVP-0）；B2 merger 鍵 → M3；W0 用的規則式 PII 偵測器 → M2（MVP-0，v0.5）；具名 PII 偵測器的其餘用途與 fix brief 的掃描 → M4（MVP-2）。

### 11.18 受測系統的準備檢核表[H]

新的受測系統在第一次 B 階段之前，逐項確認下面各點；任一項沒有，B 階段只做 S0 或不開始，原因寫入 `gaps`。散在 ROE 樣板（[04 §7](04-threat-to-testcase.md)）、[03 §7](03-system-architecture.md#7-黑箱執行安全) 與本章的要求集中在這裡：

| 項目 | 用途 | 沒有時 |
|---|---|---|
| staging 環境，與正式環境分離 | 只測 staging（06 §2.1） | 不開始 B 階段 |
| `build_identity` 標頭或端點 | B4 結果綁定 commit（`E-RESULT-BUILD`） | 列入 `build_unverified_targets` |
| 每個測試角色的 `whoami` 端點 | 可達性對照 | 該角色的測試案例 MANUAL |
| 所有權 token 放置（DNS TXT、well-known、DB `COMMENT ON DATABASE`、共享平台的 `technical_proof`） | B0 所有權驗證（`E-RUN-OWNERSHIP`） | 該目標排除 |
| seed manifest 與種子帳號 | 寫入範圍綁定種子 | 只做唯讀測試 |
| CAPTCHA／MFA 的測試繞過 | Session Provider | 該流程 MANUAL |
| 外部整合（金流、郵件）的 sandbox | 不打到真實第三方 | 該端點列入排除 |
| 快照與還原能力（S2） | `restore_drill` | 不核准 S2 |
| 支援的框架與平台（§11.1 支援矩陣） | W0 盤點與切片 | 列入 `blind_spots`；主要框架不支援時不建議使用本工具包 |

- **W4 的 MANUAL 需求**：`run.w4_manual_requirements` 會免除 W4 測試，所以列入的每一條要在 G4 由 `security_reviewer` 逐項核准，未核准的 MANUAL 視同沒有 W4 測試；schema 欄位與 validator 檢查尚未實作（BL-59）。
- **執行時釘住的結果 hash**：`sandbox_job_end` 的 `result_sha256` 在 job 結束時計算，那時還沒有 B5 Result Analyst 的 `interpreted_by`／`interpretation`；實作時釘的是去掉這兩個欄位的測試結果 hash，解讀另由 `verdict_changed` 錨定。範例是事後一起簽的，所以目前兩者相同（BL-59）。
