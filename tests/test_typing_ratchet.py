# SPDX-License-Identifier: Apache-2.0
"""Type checking as a ratchet (2026-11-22 review E7).

`mypy tools/vchlib` reported 226 errors and nothing ran it. Ten of them were in five small modules and are fixed; the
other 216 are in five modules listed under `ignore_errors` in pyproject.toml. `python -m mypy` must pass (CI job lint),
so the fifteen checked modules stay clean, and the exempt list may only shrink.

Each test failed before the change and passes after it (tests/mutations/typing_ratchet.json); see CONTRIBUTING.md."""
import pathlib
import subprocess
import sys

import pytest

try:
    import tomllib
except ModuleNotFoundError:                                    # Python 3.10 is not supported (pyproject: >= 3.11)
    tomllib = None

ROOT = pathlib.Path(__file__).resolve().parents[1]
# The modules that did not pass on 2026-11-22. Remove a name here when its module is clean; never add one.
EXEMPT_AT_MOST = {"vchlib.checks", "vchlib.derive", "vchlib.verdict", "vchlib.calibration", "vchlib.expectations"}


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
    assert set(exempt[0]["module"]) <= modules and len(modules - set(exempt[0]["module"])) >= 15


def test_the_checked_modules_pass():
    pytest.importorskip("mypy")
    r = subprocess.run([sys.executable, "-m", "mypy"], cwd=ROOT, capture_output=True, text=True)
    assert r.returncode == 0, r.stdout[-2000:]
    assert "no issues found in 20 source files" in r.stdout


def test_ci_runs_the_type_check_and_pins_the_tool():
    import yaml
    lint = yaml.safe_load((ROOT / ".github" / "workflows" / "validate.yml").read_text(encoding="utf-8"))["jobs"]["lint"]
    assert any(s.get("run") == "python -m mypy" for s in lint["steps"])
    dev = (ROOT / "requirements-dev.txt").read_text(encoding="utf-8")
    assert "\nmypy==" in dev
