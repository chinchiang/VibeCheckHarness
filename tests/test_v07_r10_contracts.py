# SPDX-License-Identifier: Apache-2.0
"""Review round 10 (docs/evidence/review-2026-10-27-r10.md), PR4: contracts the design lacked, and the round's record.
Each test failed on the PR3 head and passes with this PR; see CONTRIBUTING.md.

  observability  06 §1.11: health checks, metrics, alerts and on-call for the harness itself, including the signals
                 the validator cannot see (anchor lag, countersignature failures, gate waits over the target);
  reviewers      06 §1.12: who may approve gates or spot-check, how that is measured and renewed;
  effort         07 §1.5: person-weeks and calendar weeks for every milestone M1-M5;
  record         docs/evidence/review-2026-10-27-r10.md lists the round's PRs; the backlog carries BL-61 onward in order.
"""
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]


def text(rel):
    return (ROOT / rel).read_text(encoding="utf-8")


def section(rel, heading):
    s = text(rel)
    assert heading in s, heading
    body = s.split(heading, 1)[1]
    return re.split(r"\n#{2,3} ", body, maxsplit=1)[0]


def test_06_has_an_observability_and_on_call_contract():
    s = section("docs/06-security-legal-limitations.md", "### 1.11 harness 的可觀測性與值班")
    for must in ("健康檢查", "指標", "告警", "值班", "Audit Writer", "anchor", "z3_countersignature", "fail closed", "BL-61"):
        assert must in s, must


def test_06_has_reviewer_qualifications():
    s = section("docs/06-security-legal-limitations.md", "### 1.12 審查者與抽查人的資格")
    for must in ("security_reviewer", "app_owner", "抽查", "利益衝突", "κ", "重新認證", "BL-62"):
        assert must in s, must


def test_07_estimates_every_milestone():
    s = section("docs/07-roadmap.md", "### 1.5 人力與時程估算")
    rows = [ln for ln in s.split("\n") if ln.startswith("| M")]
    assert [r.split("|")[1].strip()[:2] for r in rows] == ["M1", "M2", "M3", "M4", "M5"]
    for r in rows:
        cells = [c.strip() for c in r.split("|")[1:-1]]
        assert re.search(r"\d", cells[1]) and re.search(r"\d", cells[2]), r
    assert "[H]" in s and "BL-63" in s


def test_the_r10_record_lists_its_prs():
    s = text("docs/evidence/review-2026-10-27-r10.md")
    for n in (28, 29, 30, 31):
        assert f"chinchiang/VibeCheckHarness#{n}" in s, n
    for code in ("E-AUDIT-TAIL", "E-AUDIT-GATE", "E-CAL-CONTAMINATION", "E-AGENT-ROLES"):
        assert code in s, code


def test_the_backlog_carries_the_r10_items():
    s = text("docs/09-backlog.md")
    for n in range(61, 66):
        assert re.search(rf"^\| BL-{n} \| r10 ", s, flags=re.M), n
