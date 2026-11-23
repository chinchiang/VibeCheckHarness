# SPDX-License-Identifier: Apache-2.0
"""Interface signatures of four mechanisms that existed only as prose (2026-11-22 review D1, docs/09 BL-78).

The finding was reported by a review agent and re-verified on 2026-11-23. Three parts held, one partly:

  - fencing: one paragraph in docs/03; docs/08 said JobAllowlist has a `fencing_token` field and the class had none;
  - job ledger (in Z3, the backlog said Z2): docs/03 listed `outcome`, docs/08 "結果 ref", and no interface existed;
  - CAS lifecycle: docs/08 section 7.3 defines the reference record, but ContentStore.put took no run_id / producer_node /
    legal_hold, get took no caller, nothing revoked a reference, and deletion had no audit event type;
  - countersign RPC: retry and idempotency were specified; a typed rejection, its reasons, a per-call timeout and the
    transport were not.

docs/08 section 2.3 now carries the signatures. The tests parse that code block, so a field or method that prose claims
must exist in it. This is specification text: no product code exists that could be run against it.

Each test failed before the change and passes after it (tests/mutations/interface_contracts.json); see CONTRIBUTING.md."""
import ast
import json
import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]


def text(rel):
    return (ROOT / rel).read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def spec():
    return text("docs/08-implementation-spec.md")


@pytest.fixture(scope="module")
def classes(spec):
    """{class name: {"fields": {name: annotation}, "methods": {name: [parameter names]}}} of docs/08 section 2.3."""
    sec = spec.split("### 2.3 擴充介面", 1)[1].split("\n### ", 1)[0]
    out = {}
    for block in re.findall(r"```python\n(.*?)```", sec, re.S):
        for node in ast.parse(block).body:
            if isinstance(node, ast.ClassDef):
                fields = {s.target.id: ast.unparse(s.annotation) for s in node.body if isinstance(s, ast.AnnAssign)}
                methods = {s.name: [a.arg for a in s.args.args if a.arg != "self"] for s in node.body if isinstance(s, ast.FunctionDef)}
                out[node.name] = {"fields": fields, "methods": methods, "returns": {
                    s.name: ast.unparse(s.returns) for s in node.body if isinstance(s, ast.FunctionDef) and s.returns}}
    return out


def errors_table(spec):
    sec = spec.split("### 6.1 ", 1)[1].split("\n### ", 1)[0]
    rows = [[c.strip() for c in ln.strip().strip("|").split("|")] for ln in sec.splitlines() if ln.startswith("| `")]
    return {r[0].strip("`"): r for r in rows}


# ================================================================ fencing and the job ledger
def test_every_job_allowlist_field_the_prose_names_is_in_the_class(spec, classes):
    line = next(ln for ln in spec.splitlines() if ln.startswith("**`JobAllowlist` 的擴充欄位**"))
    named = re.findall(r"`([a-z_]+)`", line.split("：", 1)[1])
    assert "fencing_token" in named
    missing = [f for f in named if f not in classes["JobAllowlist"]["fields"]]
    assert not missing, missing                               # 08 said the class had fencing_token; it did not
    assert classes["JobAllowlist"]["fields"]["fencing_token"] == "int"


def test_the_job_ledger_can_claim_renew_complete_and_look_up(classes):
    led = classes["JobLedger"]
    assert led["methods"] == {"claim": ["run_id", "job_id", "holder", "g5_gate_record_id"], "renew": ["lease"],
                              "complete": ["lease", "result_ref"], "lookup": ["run_id", "job_id"]}
    assert led["returns"] == {"claim": "JobLease", "renew": "JobLease", "complete": "JobLedgerEntry", "lookup": "JobLedgerEntry | None"}
    assert set(classes["JobLease"]["fields"]) == {"run_id", "job_id", "holder", "fencing_token", "lease_expires_at"}
    assert classes["JobLease"]["fields"]["fencing_token"] == "int"


def test_docs03_and_docs08_list_the_same_ledger_fields(spec, classes):
    entry = list(classes["JobLedgerEntry"]["fields"])
    a03 = next(ln for ln in text("docs/03-system-architecture.md").splitlines() if ln.startswith("- **job 帳本在 checkpoint 之外**"))
    in03 = [x.strip() for x in re.search(r"每筆 `\{([^}]*)\}`", a03).group(1).split(",")]
    row = next(ln for ln in spec.splitlines() if ln.startswith("| Z3 `job_ledger` |"))
    in08 = re.findall(r"`([a-z0-9_]+)`", row.split("append-only：", 1)[1].split("（§2.3", 1)[0])
    assert in03 == entry == in08, (in03, entry, in08)
    assert "outcome" not in in03 and "result_ref" in entry    # 03 said outcome, 08 said "結果 ref"
    assert "在 Z3（不在 Z1 的資料庫）" in row


def test_a_stale_lease_stops_the_request_and_an_executed_job_is_not_rerun(spec):
    sec = spec.split("### 2.3 擴充介面", 1)[1].split("\n### ", 1)[0]
    assert "已完成 → JobAlreadyExecuted（帶原本的 result_ref，不重跑）" in sec
    assert "帳本連不上、租約過期、kill switch 已觸發或 token 過期 → StaleLease，請求不送出" in sec
    assert "本文件不寫死數字（待 M1 實測）[H]" in sec           # no invented lease length
    t = errors_table(spec)
    assert t["StaleLease"][2] == "否" and "不覆寫結果" in t["StaleLease"][3]
    assert "不重跑" in t["JobAlreadyExecuted"][3] and t["JobAlreadyExecuted"][4] == "`job_skipped`"


# ================================================================ CAS lifecycle
def test_the_content_store_can_create_the_reference_record_of_section_7_3(spec, classes):
    store = classes["ContentStore"]
    layout = re.sub(r"\n\s*#\s*", " ", spec.split("### 7.3 ", 1)[1].split("\n### ", 1)[0])
    wanted = {x.strip() for x in re.search(r"生命週期參照 \{([^}]*)\}", layout).group(1).split(",")}
    assert wanted == {"run_id", "producer_node", "media_type", "data_class", "retention_starts_at", "retention_days", "legal_hold", "created_at"}
    # retention_starts_at and created_at are set by the store; every other field of the record must be an argument of put
    for field in sorted(wanted - {"retention_starts_at", "created_at"}):
        assert field in store["methods"]["put"], field
    assert store["methods"]["get"] == ["ref", "run_id"]       # a hash is not an authorisation
    assert store["methods"].get("revoke") == ["ref", "run_id"] and store["methods"].get("set_legal_hold") == ["ref", "run_id", "on"]
    assert store["returns"]["gc"] == "GcReport"
    assert set(classes["GcReport"]["fields"]) == {"references_deleted", "contents_deleted", "skipped_legal_hold"}
    assert set(classes["KekProvider"]["methods"]) == {"wrap", "unwrap"}


def test_docs08_no_longer_adopts_the_minimal_content_store_unchanged(spec):
    adopted = next(ln for ln in spec.splitlines() if ln.startswith("- `Provenance`、"))
    assert "`ContentStore` 不在此列" in adopted and not adopted.startswith("- `Provenance`、`ContentStore`")
    assert "以那一版為準\nclass ContentStore(Protocol):" in text("docs/03-system-architecture.md")
    assert "這個 run 沒有仍有效的參照 → `ReferenceExpired`" in spec and "ReferenceExpired" in errors_table(spec)


def test_revoking_and_deleting_have_audit_event_types(spec):
    enum = json.loads(text("docs/schemas/audit-event.schema.json"))["properties"]["event_type"]["enum"]
    assert {"artifact_stored", "artifact_revoked", "artifact_deleted"} <= set(enum) and len(enum) == len(set(enum))
    row = next(ln for ln in text("docs/03-system-architecture.md").splitlines() if ln.startswith("| 產物與裁決 |"))
    assert "`artifact_revoked`" in row and "`artifact_deleted`" in row
    assert "每次撤銷與刪除都寫稽核事件" in spec                  # the requirement the two types were missing for


def test_every_event_type_of_docs03_is_in_the_schema_and_back():
    a03 = text("docs/03-system-architecture.md").split("### 13.2 事件類型（enum）", 1)[1].split("\n## ", 1)[0]
    in_doc = set()
    for ln in a03.splitlines():
        if ln.startswith("| ") and not ln.startswith("| 類別") and not ln.startswith("|---"):
            in_doc |= set(re.findall(r"`([a-z0-9_]+)`", re.sub(r"（[^）]*）", "", ln.split("|", 2)[2])))
    enum = set(json.loads(text("docs/schemas/audit-event.schema.json"))["properties"]["event_type"]["enum"])
    assert enum == in_doc, (sorted(enum - in_doc), sorted(in_doc - enum))     # feedback_recorded was missing from the table
    assert {"artifact_revoked", "artifact_deleted"} <= in_doc & enum


# ================================================================ the countersign RPC
def test_the_countersigner_has_a_typed_request_response_and_rejection(spec, classes):
    assert classes["AnchorCountersigner"]["methods"] == {"countersign": ["request", "timeout_s"]}
    assert classes["AnchorCountersigner"]["returns"] == {"countersign": "CountersignResponse"}
    row = next(ln for ln in spec.splitlines() if ln.startswith("| 介面 | RPC `countersign(request) → response`"))
    req = re.findall(r"[a-z_]+", re.search(r"request＝`\{([^}]*)\}`", row).group(1))
    res = re.findall(r"[a-z_]+", re.search(r"response＝`\{([^}]*)\}`", row).group(1))
    assert list(classes["CountersignRequest"]["fields"]) == req and list(classes["CountersignResponse"]["fields"]) == res
    reasons = ["chain_mismatch", "counter_regression", "unknown_run", "malformed_request"]
    assert "／".join(f"`{r}`" for r in reasons) in row
    sec = spec.split("### 2.3 擴充介面", 1)[1].split("\n### ", 1)[0]
    assert "、".join(reasons) in sec and "兩者不可混用：拒簽重試也不會成功" in sec


def test_a_rejection_is_not_retried_and_a_timeout_is(spec):
    t = errors_table(spec)
    assert t["AnchorRejected"][2].startswith("否") and "`SUSPENDED`" in t["AnchorRejected"][3] and "`anchor_rejected`" in t["AnchorRejected"][4]
    assert t["Z3Unavailable"][2].startswith("是")
    retry = next((ln for ln in spec.splitlines() if ln.startswith("| 錨點副簽（`countersign`）單次呼叫逾時 |")), "")
    assert "10 秒 [H]" in retry and "算 Z3 無法連線" in retry
    row = next(ln for ln in spec.splitlines() if ln.startswith("| 介面 | RPC `countersign(request) → response`"))
    assert "mTLS HTTP JSON API" in row and "`single_host` 由 CLI 啟動子行程，以 stdin／stdout" in row


def test_every_exception_the_new_interfaces_name_is_in_the_error_table(spec):
    sec = spec.split("# --- 介面補齊", 1)[1].split("```", 1)[0]
    named = set(re.findall(r"\b(StaleLease|JobAlreadyExecuted|AnchorRejected|Z3Unavailable|ReferenceExpired|IntegrityError|NotFound)\b", sec))
    assert named == {"StaleLease", "JobAlreadyExecuted", "AnchorRejected", "Z3Unavailable", "ReferenceExpired", "IntegrityError", "NotFound"}
    t = errors_table(spec)
    assert not (named - set(t)), named - set(t)
    assert all(len(r) == 6 for r in t.values())               # every row has the six columns of the header


def test_the_backlog_says_specified_not_implemented_and_names_z3():
    row = next(ln for ln in text("docs/09-backlog.md").splitlines() if ln.startswith("| BL-78 |"))
    assert "Z3 的 job 帳本（這一列原本誤寫成 Z2）" in row and "| 介面已訂；未實作，數值待實測 |" in row
