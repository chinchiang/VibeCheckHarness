# SPDX-License-Identifier: Apache-2.0
"""v0.3 validator robustness (triage c): D4 result order, D5 input shapes and the context guard, D6 per-document
guards / bad dates / gate records without artifact, D13 stale README. Each reproduces the original failure."""
import shutil

import pytest

from conftest import ROOT, codes, doc, rederive
from vchlib import checks, cli, timeutil
from vchlib.canonical import content_hash
from vchlib.checks import run_all

RUN = "examples/run.example.json"


def group_errors(R, code):
    return [i for i in R.errors if i.code == code]


# ================================================================ D4
def test_testresults_are_ordered_by_instant_not_text(b, keys):
    """v0.2: rewriting R-TC-031-01-1 to the same instant in UTC ('...T12:45:00Z') moved it first in run.testresults,
    and writing the true chronological order was rejected with E-DERIVED."""
    llm = doc(b, "testresult.llm-pass.example.json").data
    llm["executed_at"] = "2026-10-05T12:45:00Z"                     # = 20:45 +08:00
    rederive(b, keys)
    order = doc(b, RUN).data["testresults"]
    by_id = {d.data["result_id"]: content_hash(d.data) for d in b.docs if d.kind == "testresult"}
    assert order == [by_id[r] for r in ("R-WTC-015-01-1", "R-TC-012-01-1", "R-TC-033-01-1", "R-TC-031-01-1", "R-TC-027-01-1")]
    assert codes(b) == set()


# ================================================================ D5
@pytest.mark.parametrize("suffix,mutate", [
    ("toolkit.yaml", lambda d: setattr(d, "data", [d.data])),                           # a list instead of a mapping
    ("toolkit.yaml", lambda d: d.data.update(automation_accounts=5)),                   # an int instead of a list
    ("key-registry.yaml", lambda d: d.data.update(entries=7)),
    ("examples/run.example.json", lambda d: d.data.update(jobs=[])),                    # a list instead of a mapping
])
def test_wrong_shapes_are_reported_not_crashing(b, suffix, mutate):
    """v0.2: these produced an uncaught AttributeError / TypeError before any check ran."""
    mutate(doc(b, suffix))
    R = run_all(b)
    shape = group_errors(R, "E-INPUT-SHAPE")
    assert len(shape) == 1 and shape[0].where.endswith(suffix)
    assert R.errors and len(R.groups) == len(checks.GROUPS)


def test_cli_exits_non_zero_without_traceback(tmp_path, capsys):
    for sub in ("docs/schemas", "docs/examples"):
        shutil.copytree(ROOT / sub, tmp_path / sub)
    shutil.copy(ROOT / "requirements.txt", tmp_path / "requirements.txt")
    tk = tmp_path / "docs/examples/toolkit.yaml"
    tk.write_text("- " + tk.read_text(encoding="utf-8").replace("\n", "\n  "), encoding="utf-8")   # top level becomes a list
    assert cli.main(["--root", str(tmp_path), "--quiet"]) == 1
    out = capsys.readouterr()
    assert "E-INPUT-SHAPE" in out.out and "Traceback" not in out.out + out.err


# ================================================================ D6
def test_bad_window_is_reported_once(b):
    """v0.2: a bad window tz gave E-ROE-WINDOW plus E-INTERNAL in the gates and run-state groups."""
    doc(b, "roe.yaml").data["validity"]["windows"][0]["tz"] = "Mars/Olympus"
    R = run_all(b)
    assert len(group_errors(R, "E-ROE-WINDOW")) == 1 and "E-INTERNAL" not in R.codes()


def test_bad_hhmm_is_reported_once(b):
    doc(b, "roe.yaml").data["validity"]["windows"][1]["end"] = "29:59"
    R = run_all(b)
    assert len(group_errors(R, "E-ROE-WINDOW")) == 1 and "E-INTERNAL" not in R.codes()


def test_valid_window_helper():
    assert timeutil.valid_window({"days": ["mon"], "start": "20:00", "end": "23:00", "tz": "Asia/Taipei"})
    assert not timeutil.valid_window({"days": ["mon"], "start": "20:00", "end": "24:00", "tz": "Asia/Taipei"})


def test_bad_retirement_date_does_not_abort_the_models_group(b):
    """v0.2: earliest_retirement '2026-02-30' aborted the models group (E-INTERNAL)."""
    doc(b, "models.yaml").data["claude_sonnet"]["earliest_retirement"] = "2026-02-30"
    R = run_all(b)
    assert "E-MODEL-RETIREMENT-DATE" in R.codes() and "E-INTERNAL" not in R.codes()
    assert "W-MODEL-PLACEHOLDER" in {w.code for w in R.warnings}          # the rest of the group still ran


def test_gate_record_without_artifact(b):
    """v0.2: a gate record without `artifact` aborted the whole derived-values group."""
    del doc(b, "gate-record.g3.example.json").data["artifact"]
    R = run_all(b)
    assert "E-GATE-ARTIFACT" in R.codes() and "E-INTERNAL" not in R.codes()
    derived = next(g for g in R.groups if g[0].startswith("derived"))
    assert derived[1] > 100                                             # the group ran


def test_one_bad_document_does_not_skip_the_group(b, monkeypatch):
    """Guard per document: an unexpected exception for one testresult is one E-INTERNAL; the other results are still checked."""
    real = checks.result_controls

    def boom(R, c, x, tc):
        if x.data.get("result_id") == "R-TC-012-01-1":
            raise RuntimeError("synthetic failure")
        return real(R, c, x, tc)

    monkeypatch.setattr(checks, "result_controls", boom)
    doc(b, "testresult.zap-active.example.json").data["request_count"] = 99999
    R = run_all(b)
    internal = group_errors(R, "E-INTERNAL")
    assert len(internal) == 1 and internal[0].where.endswith("testresult.example.json") and "synthetic failure" in internal[0].msg
    assert any(i.where.endswith("testresult.zap-active.example.json") for i in group_errors(R, "E-RESULT-REQUESTS"))


# ================================================================ D13
def test_readme_real_run_statement_is_current():
    """D13: docs/schemas/README.md said --real-run currently fails on gpt_flagship; it passes."""
    text = (ROOT / "docs" / "schemas" / "README.md").read_text(encoding="utf-8")
    assert "目前範例會失敗" not in text
    assert cli.main(["--quiet", "--real-run"]) == 0
