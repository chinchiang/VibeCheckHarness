# SPDX-License-Identifier: Apache-2.0
"""Type checking as a ratchet (2026-11-22 review E7).

`mypy tools/vchlib` reported 226 errors and nothing ran it. Ten of them were in five small modules and are fixed; the
other 216 are in five modules listed under `ignore_errors` in pyproject.toml. `python -m mypy` must pass (CI job lint),
so the checked modules stay clean, and the exempt list may only shrink. On 2026-11-26 `vchlib.checks` left the list:
four modules were exempt and thirty-one checked. On 2026-11-28 `vchlib.calibration` and `vchlib.expectations` followed:
two modules are exempt, thirty-three are checked, and the findings record (E7) says the same thing as pyproject.toml.

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
# 2026-11-28: vchlib.calibration and vchlib.expectations left it too (7 errors each).
EXEMPT_AT_MOST = {"vchlib.derive", "vchlib.verdict"}


def config():
    return tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["tool"]["mypy"]


def test_the_exempt_list_does_not_grow():
    cfg = config()
    assert cfg["files"] == ["tools/vchlib"]
    exempt = [o for o in cfg["overrides"] if o.get("ignore_errors")]
    assert len(exempt) == 1 and set(exempt[0]["module"]) <= EXEMPT_AT_MOST, set(exempt[0]["module"]) - EXEMPT_AT_MOST
    assert not any(o.get("ignore_errors") is None and o.get("disable_error_code") for o in cfg["overrides"])
    assert "exclude" not in cfg and cfg.get("warn_unused_ignores") is True
    modules = {f"vchlib.{p.stem}" for p in (ROOT / "tools" / "vchlib").glob("*.py")}
    assert set(exempt[0]["module"]) <= modules and len(modules - set(exempt[0]["module"])) >= 33


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


def test_the_findings_record_names_the_same_exempt_modules_as_the_configuration():
    (e7,) = [ln for ln in findings().splitlines() if ln.startswith("| E7 |")]
    exempt = [o for o in config()["overrides"] if o.get("ignore_errors")][0]["module"]
    update = e7.split("**2026-11-28 更新**", 1)[1]
    listed = update.split("仍豁免的是", 1)[1].split("）", 1)[0]
    assert sorted(f"vchlib.{name}" for name in re.findall(r"`(\w+)` \d+", listed)) == sorted(exempt)
    assert f"仍豁免的是 {len(exempt)} 個模組" in update and "已處理並移出豁免清單" in update
    counts = [int(n) for n in re.findall(r"`\w+` (\d+)", listed)]
    assert f"共 {sum(counts)} 個錯誤" in update
    checked = len(list((ROOT / "tools" / "vchlib").glob("*.py"))) - len(exempt)
    assert f"現在 {checked} 個模組必須通過" in update
    assert "⚠️" in e7 and "✅" not in e7                       # still partly handled: exempt modules and ignores remain
    ignores = sum(p.read_text(encoding="utf-8").count("# type: ignore")
                  for p in (ROOT / "tools" / "vchlib").glob("*.py"))
    assert 150 <= ignores <= 170 and "約 160 行逐行 `type: ignore`" in update and "`calibration` 與 `expectations`" in update and "不是已修正" in update, ignores


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
