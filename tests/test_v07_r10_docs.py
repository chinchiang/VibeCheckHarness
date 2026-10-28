# SPDX-License-Identifier: Apache-2.0
"""Review round 10 (docs/evidence/review-2026-10-27-r10.md), PR3: the documents state the current design.
Each test failed on the PR2 head and passes with the consolidation; see CONTRIBUTING.md.

  preambles  02-08 open with a short current-state section, not nine rounds of change summaries (moved verbatim to
             docs/evidence/doc-history.md), and name the current rule_version;
  tags       normative headings and clause prefixes carry no version tags (v0.x, review rN); the sentences that
             explain why a rule exists may still name the version that had the old behaviour;
  status     the README status line names the current rule_version, and the glossary has the r8-r10 terms;
  fixes      scattered stale text: G2 staffing in 03 §6.5 vs 02 §1.7, Lite without spot checks, RunStatus comment,
             U-18 handled, whoami SKIPPED vs MANUAL, the anchor counter in 03 §13.1's tail protection, the r8 test count.
"""
import pathlib
import re

from vchlib import adjudicate

ROOT = pathlib.Path(__file__).resolve().parents[1]
DOCS = ["02-methodology.md", "03-system-architecture.md", "04-threat-to-testcase.md", "05-bias-calibration.md",
        "06-security-legal-limitations.md", "07-roadmap.md", "08-implementation-spec.md"]
NORMATIVE = [f"docs/{d}" for d in DOCS] + ["docs/schemas/README.md"]


def text(rel):
    return (ROOT / rel).read_text(encoding="utf-8")


def prose(rel):
    """The text outside fenced code blocks and inline code."""
    out, fence = [], False
    for ln in text(rel).split("\n"):
        if ln.strip().startswith("```"):
            fence = not fence
            continue
        if not fence:
            out.append(re.sub(r"`[^`]*`", "", ln))
    return out


def test_no_document_opens_with_change_summaries():
    for d in DOCS:
        heads = [ln for ln in text(f"docs/{d}").split("\n") if ln.startswith("## ")]
        assert not [h for h in heads if "變更摘要" in h or re.match(r"## 第.+輪審查", h)], d
        assert heads[0] == "## 現況", d


def test_each_current_state_section_names_the_rule_version():
    for d in DOCS:
        now = text(f"docs/{d}").split("## 現況", 1)[1].split("\n## ", 1)[0]
        assert adjudicate.RULE_VERSION in now, d


def test_the_change_summaries_are_kept_in_the_archive():
    archive = text("docs/evidence/doc-history.md")
    for d in DOCS:
        title = text(f"docs/{d}").split("\n", 1)[0].lstrip("# ")
        assert f"## {title}" in archive, d
    assert "### v0.4 變更摘要" in archive and "### 第九輪審查的變更" in archive


def test_normative_headings_carry_no_version_tags():
    for f in NORMATIVE:
        for ln in prose(f):
            if ln.startswith("#"):
                assert not re.search(r"v0\.\d|審查 r\d", ln), (f, ln)


def test_no_clause_starts_with_a_version_tag():
    pat = re.compile(r"(^|[：；。、（|\s])\**v0\.\d(（[^）]*）)?\**[：:]")
    for f in NORMATIVE:
        hits = [ln for ln in prose(f) if pat.search(ln)]
        assert not hits, (f, hits[:3])


def test_no_bare_version_parentheticals():
    pat = re.compile(r"（v0\.\d(、v0\.\d)?(，[^）]*)?）|（v0\.\d (補充|註記|定義|起|新增)[^）]*）")
    for f in NORMATIVE:
        hits = [ln for ln in prose(f) if pat.search(ln)]
        assert not hits, (f, hits[:3])


def test_the_readme_status_names_the_rule_version():
    status = next(ln for ln in text("README.md").split("\n") if ln.startswith("> **狀態**"))
    assert adjudicate.RULE_VERSION in status and "第十二輪" in status   # r11 / r12: the status line names the latest round


def test_the_glossary_has_the_recent_terms():
    gl = text("README.md").split("## 術語表", 1)[1].split("\n## ", 1)[0]
    for term in ("anchor_counter", "run_end", "root_score", "carried_from", "observations_source", "pr_origin",
                 "Audit Writer", "Calibration Lab", "technical_proof", "db_comment", "infrastructure_owner", "gate_record_sha256"):
        assert term in gl, term


def test_03_g2_staffing_matches_02():
    row = next(ln for ln in text("docs/03-system-architecture.md").split("\n") if ln.startswith("| G2 | `g2_max_items`"))
    assert "Full 2" not in row


def test_lite_reports_no_spot_checks():
    assert "未經獨立抽查" in text("docs/00-overview.md")
    assert "未經獨立抽查" in text("docs/02-methodology.md")


def test_runstatus_suspended_covers_roe_expiry():
    line = next(ln for ln in text("docs/03-system-architecture.md").split("\n") if 'SUSPENDED = "SUSPENDED"' in ln)
    assert "ROE" in line


def test_u18_is_marked_handled():
    row = next(ln for ln in text("docs/08-implementation-spec.md").split("\n") if ln.startswith("| U-18 "))
    assert "已處理" in row


def test_whoami_failures_are_skipped_not_manual():
    assert "它的 job 是 `SKIPPED`，不是 `MANUAL`" in text("docs/02-methodology.md")


def test_03_tail_protection_names_the_anchor_counter_and_run_end():
    tail = text("docs/03-system-architecture.md").split("- **尾端保護**", 1)[1].split("- **限制", 1)[0]
    assert "anchor_counter" in tail and "run_end` 錨點之後不能再有任何行" in tail


def test_the_changelog_counts_the_r8_validator_tests():
    assert "test_v07_r8_validator.py`（57 個測試" in text("CHANGELOG.md")
