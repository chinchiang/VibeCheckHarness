# SPDX-License-Identifier: Apache-2.0
"""Type checking as a ratchet (2026-11-22 review E7).

`mypy tools/vchlib` reported 226 errors and nothing ran it. Ten of them were in five small modules and are fixed; the
other 216 are in five modules listed under `ignore_errors` in pyproject.toml. `python -m mypy` must pass (CI job lint),
so the checked modules stay clean, and the exempt list may only shrink. On 2026-11-26 `vchlib.checks` left the list:
four modules were exempt and thirty-one checked. On 2026-11-28 `vchlib.calibration` and `vchlib.expectations` followed:
two modules were exempt. Later the same day `vchlib.verdict` and `vchlib.derive` left as well: no module is exempt, all
thirty-five are checked, an `ignore_errors` override may not come back, and the findings record (E7) says so too.

Each test failed before the change and passes after it (tests/mutations/typing_ratchet.json); see CONTRIBUTING.md."""
import pathlib
import re
import subprocess
import sys

import pytest

try:
    import tomllib
except ModuleNotFoundError:                                    # Python 3.10 is not supported (pyproject: >= 3.11)
    tomllib = None

ROOT = pathlib.Path(__file__).resolve().parents[1]
# The modules that did not pass on 2026-11-22. Remove a name here when its module is clean; never add one.
# 2026-11-26: vchlib.checks left the list (7 errors remained after the split of checks.py, finding E8).
# 2026-11-28: vchlib.calibration and vchlib.expectations left it too (7 errors each), then vchlib.verdict (10) and
# vchlib.derive (14). The list is empty and stays empty.
EXEMPT_AT_MOST: set[str] = set()


def config():
    return tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["tool"]["mypy"]


def test_the_exempt_list_does_not_grow():
    cfg = config()
    assert cfg["files"] == ["tools/vchlib"]
    overrides = cfg.get("overrides", [])
    exempt = {m for o in overrides if o.get("ignore_errors") for m in o.get("module", [])}
    assert exempt <= EXEMPT_AT_MOST, exempt - EXEMPT_AT_MOST                 # the list is empty: any name here is new
    assert not any(o.get("ignore_errors") or o.get("disable_error_code") or o.get("follow_imports") == "skip"
                   for o in overrides), overrides
    assert not any(k in cfg for k in ("exclude", "disable_error_code", "ignore_errors"))
    assert cfg.get("warn_unused_ignores") is True
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert "ignore_errors = true" not in text and "Do not add an ignore_errors override" in text
    assert len(list((ROOT / "tools" / "vchlib").glob("*.py"))) >= 35


def test_the_checked_modules_pass():
    pytest.importorskip("mypy")
    r = subprocess.run([sys.executable, "-m", "mypy"], cwd=ROOT, capture_output=True, text=True)
    assert r.returncode == 0, r.stdout[-2000:]
    n = len(list((ROOT / "tools" / "vchlib").glob("*.py")))        # report.py and checks_config.py were split out of checks (PR-D0)
    assert n >= 22 and f"no issues found in {n} source files" in r.stdout


def test_ci_runs_the_type_check_and_pins_the_tool():
    import yaml
    lint = yaml.safe_load((ROOT / ".github" / "workflows" / "validate.yml").read_text(encoding="utf-8"))["jobs"]["lint"]
    assert any(s.get("run") == "python -m mypy" for s in lint["steps"])
    dev = (ROOT / "requirements-dev.txt").read_text(encoding="utf-8")
    assert "\nmypy==" in dev


def findings():
    return (ROOT / "docs" / "evidence" / "findings-2026-11-22.md").read_text(encoding="utf-8")


def test_the_findings_record_says_what_the_configuration_says():
    (e7,) = [ln for ln in findings().splitlines() if ln.startswith("| E7 |")]
    overrides = config().get("overrides", [])
    assert not [o for o in overrides if o.get("ignore_errors")]
    update = e7.split("**2026-11-28 更新**", 1)[1]
    assert "豁免清單已清空" in update and "仍豁免" not in update
    for name in ("checks", "calibration", "expectations", "verdict", "derive"):
        assert f"`{name}`" in update, name                     # each of the five, and when it left
    checked = len(list((ROOT / "tools" / "vchlib").glob("*.py")))
    assert f"現在全部 {checked} 個模組都必須通過" in update
    assert "⚠️" in e7 and "✅" not in e7                       # still partly handled: the per-line ignores remain
    ignores = sum(p.read_text(encoding="utf-8").count("# type: ignore")
                  for p in (ROOT / "tools" / "vchlib").glob("*.py"))
    assert 150 <= ignores <= 170 and "約 160 行逐行 `type: ignore`" in update and "不是已修正" in update, ignores
    assert "沒有新增任何 `type: ignore`" in update


def test_the_findings_preamble_describes_the_statuses_the_rows_use():
    text = findings()
    rows = [ln for ln in text.splitlines() if re.match(r"\| [A-G]\d+ \|", ln)]
    marks = [ln.strip().strip("|").split("|")[-1].strip()[0] for ln in rows]
    count = {m: marks.count(m) for m in set(marks)}
    assert len(rows) == 41 and set(count) == {"✅", "⚠", "⏸", "❌"}
    (legend,) = [ln for ln in text.splitlines() if ln.startswith("狀態欄：")]
    for mark in ("✅", "⚠️", "⏸", "❌"):
        assert mark in legend, mark
    assert f"✅ {count['✅']}、⚠️ {count['⚠']}、⏸ {count['⏸']}、❌ {count['❌']}" in legend
    assert "❌ 不處理（設計取捨）" in legend and "❌ 未處理" not in legend
    assert "⏸ 暫緩；" in legend and "⚠️ 部分處理，或規格已訂但還沒有執行；" in legend      # every mark is explained
    for ln in rows:                                            # the one row marked with a cross is a decision, not a gap
        if ln.strip().strip("|").split("|")[-1].strip().startswith("❌"):
            assert "不處理（設計取捨）" in ln, ln[:20]
    assert "全部未處理" not in text and "### 2.1 範圍與可交付性（影響最大；都只部分處理）" in text
    a_rows = [m for ln, m in zip(rows, marks) if ln.startswith("| A")]
    assert a_rows == ["⚠"] * 6
    assert "狀態欄更新到 2026-11-28" in text and "狀態欄更新到 2026-11-23" not in text
