# SPDX-License-Identifier: Apache-2.0
"""BL-05 (review 2026-09-26 M-G7): each repeated topic has one home page; other documents say it in a sentence and link.

Retention precedence, the audit tail protection, the key registry and signature rules, the OWASP LLM Top 10 version
and the promptfoo egress controls were each described in full in two to four of docs 02-08, and the copies drifted.
Each topic now has a home section; a marker phrase that only the full statement uses may appear only there, and the
documents that touch the topic link to it. Each test failed before this change and passes after it
(tests/mutations/bl05_home_pages.json); see CONTRIBUTING.md."""
import pathlib

import pytest

DOCS = pathlib.Path(__file__).resolve().parents[1] / "docs"
NORMATIVE = sorted(p for p in DOCS.glob("0[2-8]-*.md"))

TOPICS = {
    "retention": ("06-security-legal-limitations.md", "06-security-legal-limitations.md#221-保留期限的優先順序-h",
                  ["必須在 1 到工具包"], ["03-system-architecture.md", "08-implementation-spec.md"]),
    "audit tail": ("03-system-architecture.md", "03-system-architecture.md#131-稽核事件格式audit-eventschemajsonh",
                   ["以稽核檔本身的錨點事件為準"], ["06-security-legal-limitations.md", "08-implementation-spec.md"]),
    "signatures": ("03-system-architecture.md", "03-system-architecture.md#61-金鑰登錄與驗章流程",
                   ["`revocation_reason = compromised`", "PyYAML 是 YAML 1.1"], ["06-security-legal-limitations.md"]),
    "owasp version": ("04-threat-to-testcase.md", "04-threat-to-testcase.md#23-owasp-llm-top-10-20252026-對照",
                      ["122 頁", "OWASP 自己的 Top 10 入口頁"], ["02-methodology.md"]),
    "promptfoo": ("03-system-architecture.md", "03-system-architecture.md#75-llm-功能測試的額外控制",
                  ["PROMPTFOO_DISABLE"], ["04-threat-to-testcase.md"]),
}


def text(name):
    return (DOCS / name).read_text(encoding="utf-8")


@pytest.mark.parametrize("topic", sorted(TOPICS))
def test_the_full_statement_lives_only_on_its_home_page(topic):
    home, _, markers, _ = TOPICS[topic]
    for m in markers:
        where = [p.name for p in NORMATIVE if m in p.read_text(encoding="utf-8")]
        assert where == [home], (topic, m, where)


@pytest.mark.parametrize("topic", sorted(TOPICS))
def test_the_other_pages_link_to_the_home(topic):
    home, link, _, others = TOPICS[topic]
    for name in others:
        assert link.split("#", 1)[1] in text(name), (topic, name)


def test_the_06_licence_row_points_at_the_new_pyyaml_home():
    row = next(ln for ln in text("06-security-legal-limitations.md").splitlines() if ln.startswith("| jsonschema、PyYAML"))
    assert "#61-金鑰登錄與驗章流程" in row


@pytest.mark.parametrize("name", ["06-security-legal-limitations.md", "08-implementation-spec.md"])
def test_the_tail_protection_copies_no_longer_restate_the_error_codes(name):
    (line,) = [ln for ln in text(name).splitlines() if "尾端保護" in ln and ln.lstrip().startswith("-")]
    assert "`E-AUDIT-" not in line and "#131-" in line
