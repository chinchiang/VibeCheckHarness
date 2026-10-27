# SPDX-License-Identifier: Apache-2.0
"""BL-66 (review r10): every validator error code is named by at least one test.

BL-64's error table found 97 codes whose 守住的測試 column was "—". The tests/test_bl66_*.py files trigger each of
them, and the mutation lists tests/mutations/bl66_*.json show each test fails when its check is disabled. This file
keeps the table from regressing: a new code without a test fails here. See CONTRIBUTING.md."""
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import build_error_table  # noqa: E402


def test_every_validator_code_is_named_by_a_test():
    tested = build_error_table.guarding_tests(ROOT)
    untested = sorted(c for c in build_error_table.validator_codes(ROOT) if not tested.get(c))
    assert untested == []


def test_the_error_table_has_no_untested_row():
    text = build_error_table.README.read_text(encoding="utf-8")
    rows = [ln for ln in text.splitlines() if ln.startswith("| `E-") or ln.startswith("| `W-")]
    assert rows and not [ln for ln in rows if ln.rstrip().endswith("| — |")]
