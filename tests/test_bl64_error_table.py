# SPDX-License-Identifier: Apache-2.0
"""BL-64 (review r10): the error-code table of docs/schemas/README.md has one row per code the validator reports,
grouped by family and sorted, with a generated "guarding tests" column; tools/build_error_table.py --check keeps it so.
Each test failed before the consolidation (the table had 250 rows over two sections, 11 codes in several rows and 28 codes
without a row of their own) and passes after it; see CONTRIBUTING.md."""
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import build_error_table as B  # noqa: E402


def readme():
    return (ROOT / "docs" / "schemas" / "README.md").read_text(encoding="utf-8")


def table_rows():
    text = readme()
    assert B.START in text and B.END in text
    section = text.split(B.START, 1)[1].split(B.END, 1)[0]
    return [ln for ln in section.split("\n") if ln.startswith("| `")]


def test_the_table_is_what_the_tool_writes():
    new, problems = B.build(readme())
    assert problems == [] and new == readme()


def test_every_validator_code_has_exactly_one_row():
    firsts = [r.split("|")[1].strip().strip("`") for r in table_rows()]
    assert sorted(firsts) == sorted(B.validator_codes()) and len(firsts) == len(set(firsts))


def test_no_row_lists_more_than_one_code():
    for r in table_rows():
        assert len(re.findall(r"`[EW]-[A-Z0-9-]+`", r.split("|")[1])) == 1, r


def test_codes_are_grouped_by_family_and_sorted():
    codes = [r.split("|")[1].strip().strip("`") for r in table_rows()]
    keys = [(B.family_of(c), c) for c in codes]
    assert keys == sorted(keys)


def test_the_guarding_tests_column_names_real_tests():
    rows = {r.split("|")[1].strip().strip("`"): r.split("|")[3] for r in table_rows()}
    assert "test_v07_r10_anchor" in rows["E-AUDIT-TAIL"]
    for code, cell in rows.items():
        for stem in re.findall(r"`(test_[a-z0-9_]+)`", cell):
            assert f'"{code}"' in (ROOT / "tests" / f"{stem}.py").read_text(encoding="utf-8") or \
                f"'{code}'" in (ROOT / "tests" / f"{stem}.py").read_text(encoding="utf-8"), (code, stem)


def test_every_row_has_a_rule():
    for r in table_rows():
        assert B.MISSING_RULE not in r and r.split("|")[2].strip(), r


def test_a_new_code_without_a_rule_is_reported(tmp_path):
    text = readme()
    section = text.split(B.START, 1)[1].split(B.END, 1)[0]
    rules = B.parse_rules(section)
    rendered = B.render(rules, set(rules) | {"E-NEW-CODE"}, {})
    assert f"| `E-NEW-CODE` | {B.MISSING_RULE} | — |" in rendered


def test_a_row_for_a_code_the_validator_never_reports_is_a_problem(monkeypatch):
    real = B.validator_codes()
    monkeypatch.setattr(B, "validator_codes", lambda root=B.ROOT: real - {"E-AUDIT-TAIL"})
    _, problems = B.build(readme())
    assert any(p.startswith("E-AUDIT-TAIL:") and "never reports" in p for p in problems)


def test_ci_runs_the_check():
    ci = "".join(p.read_text(encoding="utf-8") for p in (ROOT / ".github" / "workflows").glob("*.yml"))
    assert "tools/build_error_table.py --check" in ci


def test_a_new_validator_code_without_a_rule_is_a_problem(monkeypatch):
    real = B.validator_codes()
    monkeypatch.setattr(B, "validator_codes", lambda root=B.ROOT: real | {"E-NEW-CODE"})
    _, problems = B.build(readme())
    assert any(p.startswith("E-NEW-CODE:") and "no rule" in p for p in problems)


def test_this_tests_own_fixtures_do_not_count_as_guarding_tests():
    assert all("test_bl64_error_table" not in r for r in table_rows())
