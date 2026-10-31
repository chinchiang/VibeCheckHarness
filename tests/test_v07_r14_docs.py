# SPDX-License-Identifier: Apache-2.0
"""Fourth-round internal review (2026-10-30), PR3: methodology, documents and process (C1, C2, C4-C12, D).

Review C of main@6b4dfb0 found the specification could not be implemented as written in several places; the lead reviewer
confirmed each by reading the documents. This file pins the corrected text and configuration so it cannot drift back:
  C1  the Lite single-host profile is deferred (user decision): 07 says so, BL-70 exists, `vibecheck init` is listed as
      unspecified, README / 00 no longer promise "one local key, confirm once";
  C2  the three MVP-0 signature detections have a non-LLM output path: ToolResult kinds rule_rls / rule_public_env, the
      rules tool and the Next.js / BaaS extractors registered in tools.yaml, MVP0-X1 reworded;
  C4  one public-env secret rule with an allowlist for known public keys;
  C5  the countersign RPC is idempotent, anchor_rejected is an audit event, the config key is audit.anchor_interval_events,
      Z3 unavailability has one rule;
  C6  the G1 questionnaire flow follows 08 and decisions.yaml has a schema;
  C7  the Lite G2 cap (g2_max_items_lite) makes the MVP0-X8 threshold arithmetically possible;
  C8  report export has a markdown format and E-ENG-PRICING exits 5 from run start;
  C9/C10  milestone ownership, pilot effort and the labelling budget;
  C11 stale text (R0-R16, 45 limitations, ci_workflows / iac detection rules);
  C12/D CI runs the anchor check, the PR template names every generator, CONTRIBUTING has the third freeze exception,
      rfc8785 is an optional extra.
Each test fails on PR2's head (the text before these edits) and passes after.
"""
import json
import pathlib

import pytest
import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]


def text(rel):
    return (ROOT / rel).read_text(encoding="utf-8")


def doc(name):
    return text(f"docs/{name}")


# ================================================================ C1. the Lite single-host profile is deferred
def test_07_defers_the_lite_single_host_profile():
    s = doc("07-roadmap.md")
    assert "**Lite 的單機部署 profile 待訂**" in s and "BL-70" in s and "`vibecheck init` 還沒有規格" in s
    assert "KMS" in s and "U-07" in s and "gVisor 實作，只有 Linux" in s


def test_bl70_exists_and_08_lists_init_as_unspecified():
    assert "| BL-70 | r14 C1 | **Lite 的單機部署 profile 與 `vibecheck init` 規格**" in doc("09-backlog.md")
    s = doc("08-implementation-spec.md")
    assert "| `vibecheck init` | `[--dir DIR]` | **規格待訂**" in s
    assert "除了 [§10](#10-尚未決定需使用者決定) 列出的使用者決定與 [09 BL-70]" in s


def test_readme_and_00_no_longer_promise_one_key_confirm_once():
    for s in (text("README.md"), doc("00-overview.md")):
        assert "確認一次就能跑" not in s and "本機一把金鑰、確認一次" not in s
        assert "單機部署 profile 待訂" in s


# ================================================================ C2. non-LLM output paths for the MVP-0 detections
def test_tool_result_has_the_rule_kinds_and_tools_yaml_registers_them():
    s = doc("08-implementation-spec.md")
    assert 'kind: Literal["sast", "sca", "secret", "package_existence", "rule_rls", "rule_public_env"]' in s
    assert "| `rule_rls` | `rules:rls`" in s and "| `rule_public_env` | `rules:public_env`" in s
    tools = yaml.safe_load(text("docs/examples/tools.yaml"))["tools"]
    assert "rules" in tools and tools["rules"]["zone"] == "Z2" and set(tools["rules"]["modes"]) == {"rls", "public_env"}
    assert all(not m["b4_executable"] for m in tools["rules"]["modes"].values())
    assert {"nextjs", "baas_client"} <= set(tools["inventory"]["modes"])


def test_mvp0_x1_needs_a_path_without_an_llm():
    s = doc("07-roadmap.md")
    assert "**每一個都要有不靠 LLM 的輸出路徑**" in s and "沒有 LLM 的 run 少了任何一個" in s
    assert "`rules:rls` 的 ToolResult（`kind: rule_rls`" in s


# ================================================================ C4. one public-env rule with an allowlist
def test_the_public_env_rule_has_one_home_and_an_allowlist():
    s8 = doc("08-implementation-spec.md")
    assert "**公開前綴 secret 規則**（W1 的 `rules:public_env`" in s8
    assert "`_SUPABASE_ANON_KEY`、`_FIREBASE_API_KEY`、`_PUBLISHABLE_KEY`" in s8 and "`service_role` 一律命中" in s8
    s2 = doc("02-methodology.md")
    assert "名稱含 `SECRET`、`SERVICE_ROLE`、`PRIVATE_KEY` 等字樣的公開變數 → 發現項" not in s2
    assert "[08 §11.17](08-implementation-spec.md#1117-確定性輔助規則) 的名稱規則（含已知公開金鑰的允許清單）" in s2


# ================================================================ C5. the countersign service
def test_the_countersign_rpc_is_idempotent_and_anchor_rejected_is_an_event():
    s8 = doc("08-implementation-spec.md")
    assert "RPC `countersign(request) → response`" in s8 and "以 `(run_id, seq, event_sha256)` 為冪等鍵" in s8
    assert "response＝`{anchor_counter, countersignature}`" in s8
    assert "`audit_anchor_interval`" not in s8 and "`audit.anchor_interval_events`" in s8
    assert "依 §6.1 的 `Z3Unavailable` 處理（唯一的一版" in s8
    enum = json.loads(text("docs/schemas/audit-event.schema.json"))["properties"]["event_type"]["enum"]
    assert "anchor_rejected" in enum
    assert "`audit_anchor`、`anchor_rejected`" in doc("03-system-architecture.md")


# ================================================================ C6. the G1 questionnaire and decisions.yaml
def test_02_follows_08s_questionnaire_flow():
    s = doc("02-methodology.md")
    assert "由應用擁有者在 W0.5 起草之前回答" not in s
    assert "Invariant Drafter 為每一題**提議**答案（標為「模型提議」）；應用擁有者在 **G1** 逐題確認" in s


def test_decisions_yaml_has_a_schema_and_an_example():
    s = json.loads(text("docs/schemas/decisions.schema.json"))
    assert s["$id"] == "decisions.schema.json" and set(s["required"]) == {"gate", "run_id", "gate_id", "decisions", "answers"}
    item = s["properties"]["decisions"]["items"]
    assert set(item["required"]) == {"item_id", "decision", "note", "risk_override", "carried_from", "edited_item"}
    ex = json.loads(text("docs/schemas/examples/decisions.g1.example.json"))
    assert ex["gate"] == "G1" and any(a["answer"] is None for a in ex["answers"])
    assert "[decisions.schema.json](schemas/decisions.schema.json)" in doc("08-implementation-spec.md")
    assert "| [decisions](decisions.schema.json) |" in doc("schemas/README.md")


# ================================================================ C7. the Lite G2 cap
def test_the_lite_g2_cap_is_configured_and_documented():
    tk = yaml.safe_load(text("docs/examples/toolkit.yaml"))
    assert tk["gate_queues"]["g2_max_items_lite"] == 15 and tk["gate_queues"]["g2_max_items"] == 30
    sc = json.loads(text("docs/schemas/toolkit-config.schema.json"))
    assert "g2_max_items_lite" in sc["properties"]["gate_queues"]["properties"]
    assert "Lite 用 `g2_max_items_lite`，預設 15" in doc("03-system-architecture.md")
    assert "`gate_queues.g2_max_items_lite` 預設 15 項，15 × 5 分鐘＝1.25 小時" in doc("07-roadmap.md")
    assert "**Lite pilot（MVP0-X8）之前**" in doc("07-roadmap.md")


# ================================================================ C8. report format and exit codes
def test_report_export_has_markdown_and_run_start_exits_5_on_pricing():
    s = doc("08-implementation-spec.md")
    assert "`RUN_ID --format json\\|sarif\\|markdown\\|html --out DIR" in s
    assert "**白箱報告（`whitebox-report.md`，`report export --format markdown`）的區段**" in s
    assert "`run estimate` 結束碼 10、`run start` 結束碼 5" in s and "`run estimate`／`run start` 結束碼 10" not in s


# ================================================================ C9 / C10. milestones, pilot effort, labelling budget
def test_w0_extractors_and_pii_belong_to_m1_and_the_pilot_effort_is_listed():
    s7 = doc("07-roadmap.md")
    assert "| M1 基礎與安全控制 | 12 | 7 |" in s7 and "**W0 抽取器**（含 `inventory:nextjs`、`inventory:baas_client`）" in s7
    assert "**MVP-0 的出場另需 pilot 人力，不在這 16 人週內**" in s7
    assert "同一 commit、同一目標環境、同樣的時間窗；MVP-1 的目標是本地拋棄式環境" in s7
    s8 = doc("08-implementation-spec.md")
    assert "| `pii`（擴充） | 具名 PII 偵測器的包裝（§11.17）；Z1、Z2（W0 個資掃描）與 Z3 共用 | Z1、Z2、Z3 | M1（MVP-0" in s8
    assert "登錄了 `fastapi`、`express`、`sql_rls`、`nextjs`、`baas_client` 五個模式" in s8


def test_the_labelling_budget_is_thirty_person_weeks():
    s5 = doc("05-bias-calibration.md")
    assert "≈ **30 人週**" in s5 and "**模型更換時的語料刷新**" in s5 and "每一批至少 30 個標註題" in s5
    assert "另需約 30 人週的標註" in doc("07-roadmap.md") and "| BL-73 | r14 C10 |" in doc("09-backlog.md")


# ================================================================ C11. stale text
@pytest.mark.parametrize("rel", ["docs/00-overview.md", "docs/03-system-architecture.md", "docs/05-bias-calibration.md", "docs/08-implementation-spec.md"])
def test_no_document_still_says_r0_to_r13(rel):
    assert "R0–R13" not in text(rel) and "R0-R13" not in text(rel)


def test_the_limitation_count_and_the_feature_flag_rules():
    assert "45 條明列" in text("README.md") and "完整的 45 條見" in doc("00-overview.md")
    s8 = doc("08-implementation-spec.md")
    assert "`ci_workflows`＝repo 有 CI／CD 設定檔（`.github/workflows/*.yml`" in s8 and "`iac`＝repo 有 IaC 或平台設定檔" in s8
    assert "R14／R16 決定的裁決（第 14–16 列，審查 r12）與黑箱叢集是 false" in s8


# ================================================================ C12 / D. governance
def test_ci_runs_the_anchor_check_and_the_pr_template_names_every_generator():
    ci = text(".github/workflows/validate.yml")
    assert "python tools/mutation_check.py --anchors-only tests/mutations/*.json" in ci
    tpl = text(".github/pull_request_template.md")
    assert "build_error_table.py --check" in tpl and "build_variants.py --check" in tpl and "--anchors-only" in tpl


def test_contributing_has_the_third_freeze_exception():
    s = text("CONTRIBUTING.md")
    assert "3. **審查核實成立、經使用者決定的設計變更**" in s and "三種都照下一節的規則附回歸測試" in s


def test_readme_no_longer_claims_everything_is_cross_checked():
    s = text("README.md")
    assert "| 所有內容經交叉比對核實 |" not in s and "| 設計文件與驗證器互相驗證 |" in s and "**工具包本身尚未實作**" in s


def test_rfc8785_is_an_optional_extra():
    s = text("pyproject.toml")
    assert 'reference = ["rfc8785==0.1.4"]' in s
    deps = s[s.index("dependencies = ["):s.index("]", s.index("dependencies = ["))]
    assert "rfc8785" not in deps
    assert "rfc8785==0.1.4" in text("requirements.lock")


def test_the_backlog_lists_the_r14_leftovers():
    s = doc("09-backlog.md")
    for bl, src in (("BL-70", "C1"), ("BL-71", "B10"), ("BL-72", "D"), ("BL-73", "C10")):
        assert f"| {bl} | r14 {src} |" in s
