# SPDX-License-Identifier: Apache-2.0
"""Two more places where a declaration was not compared with anything (2026-11-22 review, findings C3 and C5).

C3  legal_review.jurisdictions said which jurisdictions the legal review covers; the signed engagement said where the data
    starts and where it is sent. The shipped example reviewed ["TW"] while sending code to US providers, and no rule
    compared the two. The ROE's list must now cover the engagement's source jurisdiction and every transfer region
    (checks_engagement.missing_jurisdictions, E-ROE-TRANSFER). docs/06 also gains a question list for the reviewer (not legal advice).
C5  The evidence ledger had no date: nothing said when a claim about a licence or a provider's terms was last read. The
    findings file carries `checked_at_default`, an entry may carry its own `checked_at`, and the generator reports the
    entries past the recheck age (tools/build_evidence_ledger.py --age-report). docs/07 states the 180-day rule.

Each test failed before the change and passes after it (tests/mutations/jurisdictions_and_evidence_age.json)."""
import importlib.util
import json
import pathlib

import pytest

from conftest import doc
from vchlib import checks_engagement
from vchlib.checks import run_all
from vchlib.context import Ctx

ROOT = pathlib.Path(__file__).resolve().parents[1]


def text(rel):
    return (ROOT / rel).read_text(encoding="utf-8")


def msgs(b, code):
    return [i.msg for i in run_all(b).errors if i.code == code]


# ================================================================ C3
def test_the_example_review_covers_where_the_data_goes(b):
    assert doc(b, "roe.yaml").data["legal_review"]["jurisdictions"] == ["TW", "US"]
    dt = doc(b, "engagement.yaml").data["data_transfer"]
    assert dt["source_jurisdiction"] == "TW" and {t["region"] for t in dt["transfers"]} == {"US"}
    assert checks_engagement.missing_jurisdictions(Ctx(b)) == [] and msgs(b, "E-ROE-TRANSFER") == []


def test_a_review_that_leaves_out_the_destination_is_refused(b):
    doc(b, "roe.yaml").data["legal_review"]["jurisdictions"] = ["TW"]           # what the example said before
    assert checks_engagement.missing_jurisdictions(Ctx(b)) == ["US"]
    assert any("does not cover US" in m for m in msgs(b, "E-ROE-TRANSFER"))


def test_a_review_that_leaves_out_the_source_is_refused(b):
    doc(b, "roe.yaml").data["legal_review"]["jurisdictions"] = ["US"]
    assert any("does not cover TW" in m for m in msgs(b, "E-ROE-TRANSFER"))


def test_every_transfer_region_counts(b):
    doc(b, "engagement.yaml").data["data_transfer"]["transfers"].append(
        {"family": "nvidia", "region": "DE", "mechanism": "contract", "reference": "doc:x"})
    assert checks_engagement.missing_jurisdictions(Ctx(b)) == ["DE"]


def test_extra_jurisdictions_and_a_domestic_engagement_still_pass(b):
    doc(b, "roe.yaml").data["legal_review"]["jurisdictions"] = ["JP", "TW", "US"]
    assert checks_engagement.missing_jurisdictions(Ctx(b)) == []
    doc(b, "engagement.yaml").data["data_transfer"]["transfers"] = []
    doc(b, "roe.yaml").data["legal_review"]["jurisdictions"] = ["TW"]
    assert checks_engagement.missing_jurisdictions(Ctx(b)) == []


def test_docs06_states_the_comparison_and_the_question_list():
    s = text("docs/06-security-legal-limitations.md")
    assert 'jurisdictions: ["TW", "US"]' in s and 'jurisdictions: ["TW"] ' not in s
    assert "`jurisdictions` 必須涵蓋委任設定 `data_transfer` 的 `source_jurisdiction` 與每個 `transfers[].region`（`E-ROE-TRANSFER`）" in s
    sec = s.split("**法務審查至少要看什麼**", 1)[1].split("\n- **G0b 之前不使用", 1)[0]
    assert "**提問清單，不是法律意見**" in sec and "沒有經過律師審閱" in sec
    rows = [ln.split("|")[1].strip() for ln in sec.splitlines() if ln.strip().startswith("| `") and "項目" not in ln.split("|")[1]]
    scope = json.loads(text("docs/schemas/roe.schema.json"))["properties"]["legal_review"]["properties"]["scope"]
    assert rows == [f"`{k}`" for k in scope["required"]], (rows, scope["required"])      # one row per scope item, same order


# ================================================================ C5
@pytest.fixture(scope="module")
def ledger():
    spec = importlib.util.spec_from_file_location("build_evidence_ledger", ROOT / "tools" / "build_evidence_ledger.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def data(**top):
    f = lambda i, **kw: dict({"id": f"t-{i:02d}", "claim": "c", "sources": [], "independent_sources": [], "correction": "",
                              "verification_status": "verified"}, **kw)
    return dict({"generated_from": "test", "topics": [{"topic": "t", "limitations": [],
                 "findings": [f(1), f(2, checked_at="2026-11-01")]}]}, **top)


def test_the_findings_file_records_when_it_was_checked(ledger):
    d = json.loads(text("docs/evidence/research-findings.json"))
    assert d.get("checked_at_default") == "2026-09-23"
    head = text("docs/evidence/ledger.md").split("總計", 1)[0]
    assert "**查核日期**：未另標示的條目最後一次查核不早於 2026-09-23" in head and f"超過 {ledger.RECHECK_AFTER_DAYS} 天" in head
    assert ledger.RECHECK_AFTER_DAYS == 180


def test_an_entry_can_carry_its_own_date(ledger):
    d = data(checked_at_default="2026-09-23")
    assert ledger.checked_at(d, d["topics"][0]["findings"][0]) == "2026-09-23"
    assert ledger.checked_at(d, d["topics"][0]["findings"][1]) == "2026-11-01"
    out = ledger.render(d)
    assert out.count("- **查核日期**：2026-11-01") == 1 and "- **查核日期**：2026-09-23" not in out


def test_stale_entries_are_reported_by_age(ledger):
    d = data(checked_at_default="2026-09-23")
    assert ledger.stale(d, "2026-11-23") == []
    assert ledger.stale(d, "2027-03-22") == []                               # exactly 180 days: not yet past the limit
    assert ledger.stale(d, "2027-03-23") == [("t-01", "2026-09-23", 181)]
    assert [x[0] for x in ledger.stale(d, "2027-06-01")] == ["t-01", "t-02"]
    assert ledger.stale(d, "2026-11-23", max_age_days=30) == [("t-01", "2026-09-23", 61)]


def test_an_entry_without_any_date_is_stale(ledger):
    assert ledger.stale(data(), "2026-11-23") == [("t-01", None, None)]      # no default: only the dated entry is fresh
    assert "查核日期**：未另標示" not in ledger.render(data())                   # and the header does not invent a date


def test_the_age_report_never_fails_the_build(ledger, capsys):
    assert ledger.main(["--age-report", "--as-of", "2030-01-01"]) == 0
    out = capsys.readouterr().out
    assert "456 of 456 findings were last checked more than 180 days ago" in out


def test_docs07_states_the_recheck_rule():
    s = text("docs/07-roadmap.md")
    para = next(ln for ln in s.splitlines() if ln.startswith("- **證據會過期**"))
    assert "不得超過 180 天" in para and "`python tools/build_evidence_ledger.py --age-report`" in para
    assert "目前沒有人排定定期重查" in para and "136 個連結當時就無法確認" in para
