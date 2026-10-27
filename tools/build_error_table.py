#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Keep the error-code table of docs/schemas/README.md in step with the validator (BL-64, review r10).

The rule text of each code is written by hand inside the table; this tool owns everything else:
  - one row per code the validator can report (every "E-..." / "W-..." string literal in tools/vchlib), no other rows;
  - codes grouped by family (FAMILIES) and sorted inside a family;
  - the "守住的測試" column: the test files under tests/ that name the code, most mentions first (at most 3, then a count).

    python tools/build_error_table.py          # rewrite the table in place
    python tools/build_error_table.py --check  # exit 1 if the table is not what this tool would write

The table lives between the markers <!-- error-table:start --> and <!-- error-table:end -->.
"""
from __future__ import annotations

import argparse
import pathlib
import re
import sys
from collections import Counter

ROOT = pathlib.Path(__file__).resolve().parents[1]
README = ROOT / "docs" / "schemas" / "README.md"
START, END = "<!-- error-table:start -->", "<!-- error-table:end -->"
CODE_RE = re.compile(r"[EW]-[A-Z0-9]+(?:-[A-Z0-9]+)*")
MISSING_RULE = "（待補說明）"
SELF_TEST = "test_bl64_error_table"        # this tool's own test names codes as fixtures, not as checks it guards

# (title, family keys); a code's key is its first two segments ("E-AUDIT" for "E-AUDIT-TAIL"); "E-L" stands for E-L1..E-L6
FAMILIES = [
    ("稽核紀錄", ["E-AUDIT", "W-AUDIT"]),
    ("run 與 job", ["E-RUN", "E-JOB", "E-PIPELINE"]),
    ("關卡與抽查", ["E-GATE", "E-G4", "E-G5", "E-GB", "E-SPOT"]),
    ("ROE 與法務聲明", ["E-ROE", "E-L", "W-L"]),
    ("委任", ["E-ENG", "E-RETENTION", "E-PROFILE"]),
    ("簽章與金鑰登錄", ["E-SIG", "E-KR"]),
    ("人員參照", ["E-PERSON"]),
    ("代理與模型", ["E-AGENT", "E-MODEL", "W-MODEL", "E-DIVERSITY", "W-DIVERSITY", "E-PROVENANCE", "E-LLM"]),
    ("白箱產物：盤點、計畫、發現項、切片、叢集、W4、種子", ["E-INVENTORY", "E-INVARIANT", "E-PLAN", "E-FINDING", "E-SLICE",
                                              "E-CLUSTER", "W-CLUSTER", "E-SARIF", "E-W4", "E-SEED", "E-DFD"]),
    ("威脅、追溯與對照表", ["E-TRACE", "E-THREAT", "E-XWALK", "E-COVERAGE"]),
    ("測試案例", ["E-TC"]),
    ("測試結果", ["E-RESULT"]),
    ("裁決與回饋", ["E-VERDICT", "E-VOTE", "E-FEEDBACK"]),
    ("校準", ["E-CAL", "W-CAL"]),
    ("報告、自測與檢查點", ["E-REPORT", "E-SELFTEST", "E-CHECKPOINT"]),
    ("載入、格式與推導", ["E-SCHEMA", "E-LOAD", "E-JSON", "E-YAML", "E-KIND", "E-DATETIME", "E-JCS", "E-INPUT",
                     "E-INTERNAL", "E-DERIVED", "E-ID"]),
    ("授權與工具包設定", ["E-LIC", "E-REQ", "E-TOOLKIT", "E-TOOLS"]),
]


def family_key(code: str) -> str:
    head, second = code.split("-")[:2]
    return f"{head}-L" if re.fullmatch(r"L\d", second) else f"{head}-{second}"


def family_of(code: str) -> int:
    key = family_key(code)
    for i, (_, keys) in enumerate(FAMILIES):
        if key in keys:
            return i
    return len(FAMILIES)                                     # 其他


def validator_codes(root: pathlib.Path = ROOT) -> set[str]:
    src = "".join(p.read_text(encoding="utf-8") for p in sorted((root / "tools" / "vchlib").glob("*.py")))
    return {c for c in re.findall(r"[\"']([EW]-[A-Z0-9-]+)[\"']", src) if CODE_RE.fullmatch(c)}


def guarding_tests(root: pathlib.Path = ROOT) -> dict[str, list[str]]:
    """code -> test file stems naming it as a string literal, most mentions first, then by name."""
    counts: dict[str, Counter] = {}
    for p in sorted((root / "tests").glob("test_*.py")):
        if p.stem == SELF_TEST:
            continue
        for c in re.findall(r"[\"']([EW]-[A-Z0-9-]+)[\"']", p.read_text(encoding="utf-8")):
            counts.setdefault(c, Counter())[p.stem] += 1
    return {c: [n for n, _ in sorted(cnt.items(), key=lambda x: (-x[1], x[0]))] for c, cnt in counts.items()}


def tests_cell(names: list[str]) -> str:
    if not names:
        return "—"
    shown = "、".join(f"`{n}`" for n in names[:3])
    return shown + (f" 等 {len(names)} 份" if len(names) > 3 else "")


def parse_rules(section: str) -> dict[str, str]:
    """code -> rule text from the rows of an existing generated table."""
    rules = {}
    for ln in section.split("\n"):
        cells = [c.strip() for c in ln.split("|")[1:-1]] if ln.startswith("| `") else []
        if len(cells) >= 2:
            m = CODE_RE.fullmatch(cells[0].strip("`"))
            if m:
                rules[m.group(0)] = cells[1]
    return rules


def render(rules: dict[str, str], codes: set[str], tests: dict[str, list[str]]) -> str:
    out = [START, ""]
    titles = [t for t, _ in FAMILIES] + ["其他"]
    for i, title in enumerate(titles):
        fam = sorted(c for c in codes if family_of(c) == i)
        if not fam:
            continue
        out += [f"**{title}**", "", "| 錯誤碼 | 規則 | 守住的測試 |", "|---|---|---|"]
        out += [f"| `{c}` | {rules.get(c) or MISSING_RULE} | {tests_cell(tests.get(c, []))} |" for c in fam]
        out.append("")
    out.append(END)
    return "\n".join(out)


def build(text: str, root: pathlib.Path = ROOT) -> tuple[str, list[str]]:
    """(new README text, problems). Problems: codes without a rule, rows for codes the validator never reports."""
    if START not in text or END not in text:
        return text, [f"markers {START} / {END} not found"]
    head, rest = text.split(START, 1)
    section, tail = rest.split(END, 1)
    rules, codes = parse_rules(section), validator_codes(root)
    problems = [f"{c}: no rule text (write it in the table)" for c in sorted(codes) if not rules.get(c) or rules[c] == MISSING_RULE]
    problems += [f"{c}: row for a code the validator never reports" for c in sorted(set(rules) - codes)]
    return head + render(rules, codes, guarding_tests(root)) + tail, problems


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--check", action="store_true", help="exit 1 if the table is stale or incomplete")
    args = ap.parse_args(argv)
    text = README.read_text(encoding="utf-8")
    new, problems = build(text)
    for p in problems:
        print(f"error-table: {p}")
    if args.check:
        if new != text:
            print("docs/schemas/README.md: error table is stale; run python tools/build_error_table.py")
            return 1
        if problems:
            return 1
        print("docs/schemas/README.md: error table up to date")
        return 0
    if new != text:
        README.write_text(new, encoding="utf-8")
        print("docs/schemas/README.md: error table rewritten")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
