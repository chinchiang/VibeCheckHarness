# SPDX-License-Identifier: Apache-2.0
"""The Lite single-host deployment profile (docs/09 BL-70, design decision D10 of the 2026-11-22 review).

Review r14 found that Lite, the default entry of MVP-0, could not start on one development machine under the rules written
for the three-zone deployment (KMS, a production root key, a countersigner under another OS user, gVisor, Postgres, a
package mirror) and left the profile "to be specified". It is specified now (docs/08 section 11.20):

  - engagement.deployment_profile: three_zone (default) or single_host; single_host only with assurance_profile lite and an
    acknowledged role_consolidation, and white-box only (E-ENG-DEPLOYMENT);
  - a single-host run's anchors are countersigned by the operator's own process (a local anchor), so the report manifest
    says audit_anchor: local; every other report says countersigned (E-REPORT-ANCHOR). team / full keep the Z3 countersign;
  - `vibecheck init` and the six deployment decisions are written down in docs/07 section 1.3 and docs/08 section 11.20.

Each test failed before the change and passes after it (tests/mutations/lite_single_host.json); see CONTRIBUTING.md.
There is no complete signed single-host example bundle: the tests rewrite the lite variant and assert the two rules."""
import json
import pathlib

import pytest

from conftest import doc
from vchlib import checks
from vchlib.bundle import load_variant
from vchlib.checks import run_all
from vchlib.context import Ctx

ROOT = pathlib.Path(__file__).resolve().parents[1]
RM = "report-manifest.example.json"


def text(rel):
    return (ROOT / rel).read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def lite_base():
    return load_variant(ROOT, "lite")


@pytest.fixture
def lite(lite_base):
    return lite_base.clone()


def msgs(b, code):
    return [i.msg for i in run_all(b).errors if i.code == code]


def single_host(bundle, white_box_only=True):
    """The bundle as a single-host engagement; with white_box_only its black-box gate records are removed."""
    doc(bundle, "engagement.yaml").data["deployment_profile"] = "single_host"
    doc(bundle, RM).data["audit_anchor"] = "local"
    if white_box_only:
        bundle.docs[:] = [d for d in bundle.docs if not (d.kind == "gate-record" and d.data.get("gate") in checks.ROE_GATES)]
    return bundle


# ================================================================ the examples
def test_the_examples_are_three_zone_and_countersigned(b, lite_base):
    for bundle in (b, lite_base):
        assert "deployment_profile" not in doc(bundle, "engagement.yaml").data
        assert checks.deployment(Ctx(bundle)) == "three_zone"
        assert doc(bundle, RM).data["audit_anchor"] == "countersigned"
        assert checks.deployment_problems(Ctx(bundle)) == []
    assert run_all(b).errors == [] and run_all(lite_base).errors == []


# ================================================================ E-ENG-DEPLOYMENT
def test_a_white_box_lite_engagement_may_be_single_host(lite):
    single_host(lite)
    assert checks.deployment(Ctx(lite)) == "single_host"
    assert checks.deployment_problems(Ctx(lite)) == []
    assert msgs(lite, "E-ENG-DEPLOYMENT") == [] and msgs(lite, "E-REPORT-ANCHOR") == []
    assert "E-SCHEMA" not in {i.code for i in run_all(lite).errors if "engagement.yaml" in i.where or RM in i.where}


@pytest.mark.parametrize("profile", ["team", "full"])
def test_single_host_is_refused_outside_lite(b, profile):
    doc(b, "engagement.yaml").data["assurance_profile"] = profile
    single_host(b)
    assert any(f"only allowed with assurance_profile lite (got {profile})" in m for m in msgs(b, "E-ENG-DEPLOYMENT"))


def test_single_host_needs_the_acknowledged_role_consolidation(lite):
    single_host(lite)
    doc(lite, "engagement.yaml").data["role_consolidation"]["acknowledged"] = False
    assert any("needs an acknowledged role_consolidation" in m for m in msgs(lite, "E-ENG-DEPLOYMENT"))


def test_single_host_is_white_box_only(lite):
    single_host(lite, white_box_only=False)
    got = msgs(lite, "E-ENG-DEPLOYMENT")
    assert any("white-box only, but the bundle has G0b, G3, G4 records" in m for m in got), got
    # one black-box gate is enough, and the white-box gates are not counted
    single_host(lite)
    assert msgs(lite, "E-ENG-DEPLOYMENT") == []
    assert {d.data["gate"] for d in lite.docs if d.kind == "gate-record"} >= {"G0a", "G1", "G2"}


def test_the_schema_knows_the_two_profiles(lite):
    s = json.loads(text("docs/schemas/engagement.schema.json"))
    assert s["properties"]["deployment_profile"]["enum"] == ["three_zone", "single_host"]
    assert "deployment_profile" not in s["required"]
    doc(lite, "engagement.yaml").data["deployment_profile"] = "laptop"
    assert "E-SCHEMA" in run_all(lite).codes()


# ================================================================ E-REPORT-ANCHOR
def test_a_single_host_report_says_local_anchor(lite):
    single_host(lite)
    doc(lite, RM).data["audit_anchor"] = "countersigned"
    assert msgs(lite, "E-REPORT-ANCHOR") == ["audit_anchor must be 'local' for deployment_profile single_host, not 'countersigned'"]


@pytest.mark.parametrize("which", ["main", "lite"])
def test_a_three_zone_report_cannot_say_local(b, lite, which):
    bundle = b if which == "main" else lite
    doc(bundle, RM).data["audit_anchor"] = "local"
    assert msgs(bundle, "E-REPORT-ANCHOR") == ["audit_anchor must be 'countersigned' for deployment_profile three_zone, not 'local'"]


def test_audit_anchor_is_required(b):
    del doc(b, RM).data["audit_anchor"]
    assert "E-SCHEMA" in run_all(b).codes() and msgs(b, "E-REPORT-ANCHOR")
    s = json.loads(text("docs/schemas/report-manifest.schema.json"))
    assert "audit_anchor" in s["required"] and s["properties"]["audit_anchor"]["enum"] == ["countersigned", "local"]


def test_the_three_zone_anchor_still_needs_the_z3_countersignature(b):
    """D10 moves nothing for team / full: an anchor without a valid z3-executor countersignature is still an error."""
    log = doc(b, "audit-event.run-2026-09-23-001.example.jsonl").data
    anchor = next(e for e in log if e["event_type"] == "audit_anchor")
    anchor["payload"]["z3_countersignature"]["signer"] = "alice"
    assert "E-AUDIT-ANCHOR-SIG" in run_all(b).codes()


def test_a_single_host_anchor_keeps_the_same_format(lite):
    """The local anchor is the same event with the same countersignature format; only who runs the signer differs."""
    single_host(lite)
    assert "E-AUDIT-ANCHOR-SIG" not in run_all(lite).codes()
    log = next(d for d in lite.docs if d.kind == "audit-event").data
    next(e for e in log if e["event_type"] == "audit_anchor")["payload"]["z3_countersignature"] = None
    assert "E-AUDIT-ANCHOR-SIG" in run_all(lite).codes()


# ================================================================ the specification
def test_08_specifies_the_profile_and_init():
    s = text("docs/08-implementation-spec.md")
    assert "### 11.20 Lite 的單機部署 profile 與 `vibecheck init`[H]" in s
    sec = s.split("### 11.20 Lite 的單機部署 profile", 1)[1]
    rows = {ln.split("|")[1].strip() for ln in sec.splitlines() if ln.startswith("| ")}
    assert {"金鑰數量", "金鑰存放", "錨點副簽", "報告標示", "Z2 沙箱", "checkpointer", "套件存在性", "模型呼叫"} <= rows
    for needle in ("`deployment_profile: single_host`", "`E-ENG-DEPLOYMENT`", "`E-REPORT-ANCHOR`", "`audit_anchor: \"local\"`",
                   "**本機錨點**", "擋不住本人重寫整條鏈", "SqliteSaver", "不覆寫既有的 `DIR`", "**確定性最小切片**",
                   "沒有任何 LLM 呼叫", "只適用 `three_zone`"):
        assert needle in sec, needle
    steps = [ln for ln in sec.splitlines() if ln[:2] in ("1.", "2.", "3.", "4.", "5.", "6.")]
    assert len(steps) == 6
    init = next(ln for ln in s.splitlines() if ln.startswith("| `vibecheck init` |"))
    assert "§11.20" in init and "規格待訂" not in init and "不覆寫既有目錄" in init
    assert "獨立行程與使用者。例外：`deployment_profile: single_host` 的 Lite 用本機錨點" in s
    for u in ("U-05", "U-07"):
        row = next(ln for ln in s.splitlines() if ln.startswith(f"| {u} |"))
        assert "`single_host` 的 Lite 除外" in row, u
    home = next(ln for ln in s.splitlines() if ln.startswith("1. **首頁**"))
    assert "稽核鏈為本機錨點，不能作為對外證據" in home


def test_07_states_the_six_decisions_and_the_first_slice():
    s = text("docs/07-roadmap.md")
    sec = s.split("**Lite 的單機部署 profile**", 1)[1].split("**人工操作的契約**", 1)[0]
    rows = [ln.split("|")[1].strip() for ln in sec.splitlines() if ln.startswith("| ") and not ln.startswith("| 要決定的事")]
    assert rows == ["根金鑰與人員金鑰是否同一把", "KMS 的本機替代", "副簽行程的隔離", "macOS／Windows 的 Z2", "checkpointer", "套件 registry"]
    assert "**確定性最小切片（MVP-0a）**" in sec and "W0＋W1＋SARIF" in sec and "沒有任何 LLM 呼叫" in sec
    assert "尚未實作" in sec and "沒有實測過 [A]" in sec           # a specification, not a claim that it runs


def test_the_other_documents_point_at_the_specification():
    assert "單機 profile（`deployment_profile: single_host`" in text("docs/02-methodology.md")
    row = next(ln for ln in text("docs/09-backlog.md").splitlines() if ln.startswith("| BL-70 |"))
    assert "08 §11.20" in row and "規格已訂" in row and "未實作" in row and "| 待辦 |" not in row
    a03 = text("docs/03-system-architecture.md")
    assert "`deployment_profile`（選用" in a03 and "`audit_anchor`（`E-REPORT-ANCHOR`）" in a03
    table = text("docs/schemas/README.md")
    assert "| `E-ENG-DEPLOYMENT` | 2026-11-22 內部審查（BL-70、D10）" in table and "| `E-REPORT-ANCHOR` | 2026-11-22 內部審查（BL-70、D10）" in table
