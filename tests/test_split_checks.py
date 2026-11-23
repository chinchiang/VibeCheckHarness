# SPDX-License-Identifier: Apache-2.0
"""The shape the split of checks.py must keep (architecture refactor PR-D0, docs/adr/0003-split-checks.md).

checks.py held every check group and all 331 error codes in 5,841 lines. It is being split one piece at a time into flat
modules next to it. These tests hold the rules that make each move safe; the moves themselves change no rule, code or
message (the equivalence evidence is in CHANGELOG.md).

tests/mutations/split_checks.json; see CONTRIBUTING.md."""
import ast
import importlib.util
import pathlib

from vchlib import (checks, checks_config, checks_engagement, checks_gates, checks_integrity, checks_models, checks_roe,
                    checks_signatures, report)

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
    assert names[10] == "g_runs" and checks.GROUPS[10][1].__module__ == "vchlib.checks"       # not moved yet
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
    assert checks.run_start is checks_gates.run_start and "\ndef run_start(" not in (PKG / "checks.py").read_text(encoding="utf-8")
    assert report.anchored_seqs([{"event_type": "x"}, {"event_type": "audit_anchor"}, {"event_type": "y"}]) == 2
    # the facade uses these, it does not redefine them
    for home, names in ((checks_signatures, ("decision_time", "verify_signature", "MAX_CLOCK_SKEW")),
                        (checks_roe, ("job_span", "expected_gaps", "path_shape")), (report, ("anchored_seqs",))):
        for name in names:
            assert getattr(checks, name) is getattr(home, name), name
            assert f"\ndef {name}(" not in (PKG / "checks.py").read_text(encoding="utf-8"), name
    assert report.ROE_GATES == ("G0b", "G3", "G4", "G5") and report.ENGAGEMENT_GATES == ("G0a", "G1", "G2")
    # the engagement accessors live once, in the engagement module; the facade uses them, it does not redefine them
    for name in ("profile", "deployment", "consolidation_person"):
        assert getattr(checks, name) is getattr(checks_engagement, name), name
    for name in ("Issue", "Report", "doc_guard", "ts", "format_checker"):
        assert getattr(report, name).__module__ == "vchlib.report", name
    for name in ("GATE_ROLES", "FINAL_STATUSES", "TERMINAL_RUN_STATES", "LEGAL_GATE", "StrictValidator", "FORMATS"):
        assert hasattr(report, name), name
    assert checks_config.Report is report.Report and checks.Report is report.Report      # one Report class, not copies
    assert checks_integrity.Report is report.Report and checks_engagement.Report is report.Report
    assert checks_models.Report is report.Report and checks_roe.Report is report.Report
    assert checks_signatures.Report is report.Report and checks_gates.Report is report.Report


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
