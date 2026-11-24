# SPDX-License-Identifier: Apache-2.0
"""The shape the split of checks.py must keep (architecture refactor PR-D0, docs/adr/0003-split-checks.md).

checks.py held every check group and all 331 error codes in 5,841 lines. It is being split one piece at a time into flat
modules next to it. These tests hold the rules that make each move safe; the moves themselves change no rule, code or
message (the equivalence evidence is in CHANGELOG.md).

tests/mutations/split_checks.json; see CONTRIBUTING.md."""
import ast
import importlib.util
import pathlib

from vchlib import (checks, checks_audit, checks_config, checks_engagement, checks_gates, checks_integrity, checks_models, checks_roe,
                    checks_runs, checks_signatures, checks_testcases, checks_trace, checks_verdicts, checks_w4,
                    report)

ROOT = pathlib.Path(__file__).resolve().parents[1]
PKG = ROOT / "tools" / "vchlib"
# ADR 0001: derive <- context <- calibration <- verdict <- expectations <- checks. Nothing on the left imports the checker.
BELOW_THE_CHECKER = ("derive", "context", "calibration", "verdict", "expectations", "seal", "adjudicate", "canonical", "crypto")


def imports_of(name):
    tree = ast.parse((PKG / f"{name}.py").read_text(encoding="utf-8"))
    out = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.ImportFrom) and n.level == 1:
            out |= {n.module} if n.module else {a.name for a in n.names}
    return out


def test_the_checker_is_flat_modules_not_a_sub_package():
    """build_error_table.py and the typing ratchet scan tools/vchlib/*.py without recursing: a sub-package would drop its
    error codes from the table."""
    assert not [p for p in PKG.iterdir() if p.is_dir() and p.name != "__pycache__"]
    spec = importlib.util.spec_from_file_location("build_error_table", ROOT / "tools" / "build_error_table.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert len(mod.validator_codes()) == 331                  # every code is still found after the move


def test_the_group_list_and_its_order_are_unchanged():
    names = [fn.__name__ for _, fn in checks.GROUPS]
    assert len(names) == 24 and names[:3] == ["g_schemas", "g_jcs", "g_derived"]
    assert names[19:23] == ["g_licenses", "g_crosswalk", "g_llm_schemas", "g_toolkit"] and names[23] == "g_misc"
    for fn in checks.GROUPS[19:23]:
        assert fn[1].__module__ == "vchlib.checks_config"     # the four groups PR-D0 moved
    assert names[18] == "g_calibration" and checks.GROUPS[18][1].__module__ == "vchlib.checks_calibration"   # PR-D1
    assert names[:6] == ["g_schemas", "g_jcs", "g_derived", "g_key_registry", "g_signatures", "g_persons"]
    for i in (0, 1, 2, 3, 5):
        assert checks.GROUPS[i][1].__module__ == "vchlib.checks_integrity", names[i]      # the five groups PR-D2 moved
    assert checks.GROUPS[4][1].__module__ == "vchlib.checks_signatures"      # PR-D4: with the signature helpers
    assert checks.GROUPS[7][1].__module__ == "vchlib.checks_roe"             # PR-D4
    assert names[9] == "g_gates" and checks.GROUPS[9][1].__module__ == "vchlib.checks_gates"     # PR-D5
    assert names[10:12] == ["g_runs", "g_testcases"] and names[13:15] == ["g_feedback", "g_report_withdrawal"]
    assert checks.GROUPS[10][1].__module__ == "vchlib.checks_runs"                             # PR-D6
    for i in (11, 13, 14):
        assert checks.GROUPS[i][1].__module__ == "vchlib.checks_testcases", names[i]           # PR-D6
    assert names[12] == "g_w4_testcases" and checks.GROUPS[12][1].__module__ == "vchlib.checks_w4"    # PR-D8
    assert names[15:18] == ["g_verdicts", "g_trace", "g_audit"]
    assert checks.GROUPS[17][1].__module__ == "vchlib.checks_audit"                            # PR-D7
    assert checks.GROUPS[15][1].__module__ == "vchlib.checks_verdicts"                         # PR-D8
    assert checks.GROUPS[16][1].__module__ == "vchlib.checks_trace"                            # PR-D8
    # only g_misc is still defined in the facade
    assert [fn.__name__ for _, fn in checks.GROUPS if fn.__module__ == "vchlib.checks"] == ["g_misc"]
    assert names[6:9] == ["g_engagement", "g_roe", "g_models"]
    assert checks.GROUPS[6][1].__module__ == "vchlib.checks_engagement" and checks.GROUPS[8][1].__module__ == "vchlib.checks_models"   # PR-D3


def test_the_shared_base_imports_no_check_group():
    assert imports_of("report") <= {"timeutil", "context"}
    assert not {m for m in imports_of("checks_config") if m.startswith("checks")}
    assert not {m for m in imports_of("checks_calibration") if m.startswith("checks")}
    assert not {m for m in imports_of("checks_integrity") if m.startswith("checks")}
    # PR-D3: the engagement group reads reachable_models from the models module; neither imports the facade
    assert not {m for m in imports_of("checks_models") if m.startswith("checks")}
    assert {m for m in imports_of("checks_engagement") if m.startswith("checks")} == {"checks_models"}
    # PR-D4: signatures import no check group; the ROE group reads the engagement accessors and silent_verify
    assert not {m for m in imports_of("checks_signatures") if m.startswith("checks")}
    assert {m for m in imports_of("checks_roe") if m.startswith("checks")} == {"checks_engagement", "checks_signatures"}
    # PR-D5: the gates group reads the engagement accessors and the signature helpers
    assert {m for m in imports_of("checks_gates") if m.startswith("checks")} == {"checks_engagement", "checks_signatures"}
    # PR-D6: runs and testcases read the groups before them and not each other
    lower = {"checks_engagement", "checks_gates", "checks_roe", "checks_signatures"}
    assert {m for m in imports_of("checks_runs") if m.startswith("checks")} == lower
    assert {m for m in imports_of("checks_testcases") if m.startswith("checks")} == lower
    assert report.anchored_seqs([{"event_type": "x"}, {"event_type": "audit_anchor"}, {"event_type": "y"}]) == 2
    # PR-D7: the audit group reads the engagement, signature and run modules; nothing reads it but the facade
    assert {m for m in imports_of("checks_audit") if m.startswith("checks")} == {"checks_engagement", "checks_runs", "checks_signatures"}
    for other in PKG.glob("checks_*.py"):
        assert "checks_audit" not in imports_of(other.stem), other.name
    # PR-D8: verdicts read no later group; trace reads the run module; W4 reads trace (inventory_of_run). No cycle.
    assert {m for m in imports_of("checks_verdicts") if m.startswith("checks")} == {"checks_calibration", "checks_roe"}
    assert {m for m in imports_of("checks_trace") if m.startswith("checks")} == {"checks_runs"}
    assert {m for m in imports_of("checks_w4") if m.startswith("checks")} == {"checks_runs", "checks_testcases", "checks_trace"}
    # a moved name lives once: the facade may import it (when it still uses it) but never redefines it
    facade = (PKG / "checks.py").read_text(encoding="utf-8")
    for home, names in ((checks_signatures, ("decision_time", "verify_signature", "MAX_CLOCK_SKEW")),
                        (checks_roe, ("job_span", "expected_gaps", "path_shape")), (report, ("anchored_seqs",)),
                        (checks_gates, ("run_start", "g5_escalation")), (checks_engagement, ("profile", "deployment", "consolidation_person")),
                        (checks_runs, ("result_controls", "baseline_checks", "JOB_RAN_STATES")),
                        (checks_testcases, ("access_matrix_cells", "feedback_suppression")),
                        (checks_audit, ("anchor_counter_problems", "spot_check", "RUN_TRANSITIONS", "run_structure")),
                        (checks_verdicts, ("trace_text_problems", "max_vote_round", "verdict_chains")),
                        (checks_trace, ("inventory_of_run", "pipeline_checks", "_tool_of", "cluster_origin")),
                        (checks_w4, ("w4_coverage", "W4_CLUSTER_ORIGINS"))):
        for name in names:
            assert hasattr(home, name), name
            assert getattr(checks, name, getattr(home, name)) is getattr(home, name), name
            assert f"\ndef {name}(" not in facade and f"\n{name} = " not in facade, name
    assert report.ROE_GATES == ("G0b", "G3", "G4", "G5") and report.ENGAGEMENT_GATES == ("G0a", "G1", "G2")
    for name in ("Issue", "Report", "doc_guard", "ts", "format_checker"):
        assert getattr(report, name).__module__ == "vchlib.report", name
    for name in ("GATE_ROLES", "FINAL_STATUSES", "TERMINAL_RUN_STATES", "LEGAL_GATE", "StrictValidator", "FORMATS"):
        assert hasattr(report, name), name
    assert checks_config.Report is report.Report and checks.Report is report.Report      # one Report class, not copies
    assert checks_integrity.Report is report.Report and checks_engagement.Report is report.Report
    assert checks_models.Report is report.Report and checks_roe.Report is report.Report
    assert checks_signatures.Report is report.Report and checks_gates.Report is report.Report
    assert checks_runs.Report is report.Report and checks_testcases.Report is report.Report
    assert checks_audit.Report is report.Report
    assert checks_trace.Report is report.Report and checks_verdicts.Report is report.Report and checks_w4.Report is report.Report


def test_nothing_below_the_checker_imports_it():
    for name in BELOW_THE_CHECKER:
        bad = {m for m in imports_of(name) if m == "report" or m.startswith("checks")}
        assert not bad, (name, bad)


def test_checks_keeps_no_re_exports_of_moved_names():
    assert checks.__all__ == ["run_all", "GROUPS", "content_hash"]
    src = (PKG / "checks.py").read_text(encoding="utf-8")
    for moved in ("class Report", "class Issue", "class doc_guard", "def ts(", "GATE_ROLES = {", "def g_licenses(", "def g_toolkit(",
                  "def g_calibration(", "def theta_problems(", "def wilson_lower("):
        assert moved not in src, moved
    tests_and_tools = [p for p in (ROOT / "tests").glob("*.py") if p.name != "test_split_checks.py"] + [ROOT / "tools" / "build_variants.py"]
    for p in tests_and_tools:
        text = p.read_text(encoding="utf-8")
        for stale in ("checks.Report", "checks.Issue", "checks.FINAL_STATUSES", "checks.TERMINAL_RUN_STATES", "checks.LEGAL_GATE",
                      "checks.theta_problems", "checks.hypothesis_problems", "checks.wilson_lower", "checks.wilson_upper",
                      "checks.lr_weights", "checks.effective_counts", "checks.policy_problems"):
            assert stale not in text, (p.name, stale)


def test_the_findings_file_records_the_split_as_done_with_the_numbers_the_code_has():
    """Finding E8 (2026-11-22 review): the row is closed only while what it says is still true of the package."""
    row = next(ln for ln in (ROOT / "docs" / "evidence" / "findings-2026-11-22.md").read_text(encoding="utf-8").splitlines()
               if ln.startswith("| E8 |"))
    assert "✅ 已處理" in row and "進行中" not in row and "adr/0003-split-checks.md" in row
    moved = [fn for _, fn in checks.GROUPS if fn.__module__ != "vchlib.checks"]
    modules = sorted(p.name for p in PKG.glob("checks_*.py"))
    assert len(moved) == 23 and "搬出 23 個" in row
    assert len(modules) == 14 and "14 個 `checks_*.py` 模組" in row
    assert {fn.__module__.split(".")[1] + ".py" for fn in moved} == set(modules)       # every module holds a group
    lines = len((PKG / "checks.py").read_text(encoding="utf-8").splitlines())
    assert lines == 355 and "減為 355 行" in row
    ignores = sum(p.read_text(encoding="utf-8").count("# type: ignore") for p in PKG.glob("checks_*.py"))
    assert 140 <= ignores <= 165 and "約 150 行 `type: ignore`" in row, ignores

