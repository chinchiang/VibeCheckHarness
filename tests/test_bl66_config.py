# SPDX-License-Identifier: Apache-2.0
"""BL-66 (review r10): calibration, checkpoint, report, self-test, loader, schema, license and toolkit config checks — every error code below is triggered by at least one test.
Each test fails when its check is disabled (tests/mutations/bl66_config.json); see CONTRIBUTING.md."""
import shutil

import pytest

from conftest import ROOT, codes, doc
from vchlib import checks
from vchlib.bundle import Doc, load_bundle, reload_json
from vchlib.checks import run_all


def hits(bundle, code):
    """(where, message) of every error with this code."""
    return [(i.where, i.msg) for i in run_all(bundle).errors if i.code == code]


def has(bundle, code, where=None, msg=None):
    return any((where is None or w == where) and (msg is None or msg in m) for w, m in hits(bundle, code))


def cal(b):
    return doc(b, "calibration.yaml").data


# ------------------------------------------------------------------ calibration
def test_e_cal_model_config_model_disagrees_with_models_yaml(b):
    cal(b)["config"]["models"][0]["family"] = "someone-else"
    assert has(b, "E-CAL-MODEL", "calibration.yaml", "family/lineage disagree with models.yaml")


def test_e_cal_model_weight_row_model_not_in_config(b):
    cal(b)["result"]["weights"][0]["model_key"] = "ghost_model"
    assert has(b, "E-CAL-MODEL", msg="model not in config.models")


def test_e_cal_model_valid_for_unknown_model(b):
    cal(b)["result"]["valid_for_model_keys"].append("ghost_model")
    assert has(b, "E-CAL-MODEL", "calibration.yaml", "valid_for_model_keys not in config.models")


def test_e_cal_arms_only_arm_5_is_exploratory(b):
    cal(b)["config"]["arms"][0]["exploratory"] = True
    assert has(b, "E-CAL-ARMS", "calibration.yaml", "only arm 5 is exploratory")


def test_e_cal_arms_unknown_model_key(b):
    cal(b)["config"]["arms"][0]["model_keys"].append("ghost_model")
    assert has(b, "E-CAL-ARMS", "calibration.yaml", "unknown model keys")


def test_e_cal_arms_result_exploratory_arm_must_be_5(b):
    cal(b)["result"]["exploratory"]["arm"] = "4"
    assert has(b, "E-CAL-ARMS", "calibration.yaml", "result.exploratory.arm must be 5")


def test_e_cal_m11_flag_follows_value(b):
    rows = cal(b)["result"]["metrics"]["M-11"]["by_model"]
    row = next(r for r in rows if r["value"] is not None and r["value"] < 0.5)
    row["flag"] = None
    assert has(b, "E-CAL-M11", "calibration.yaml", "flag must be support_leaning")


def test_e_cal_kappa_accepted_must_follow_kappa_min(b):
    cal(b)["result"]["annotator_agreement"][0]["accepted"] = False
    assert has(b, "E-CAL-KAPPA", "calibration.yaml", "accepted must equal kappa >= kappa_min")


# ------------------------------------------------------------------ checkpoint
CKPT = "checkpoint-metadata.followup.example.json"


def test_e_checkpoint_run_not_found(b):
    doc(b, CKPT).data["run_id"] = "run-ghost"
    assert has(b, "E-CHECKPOINT", msg="run not found")


def test_e_checkpoint_status_disagrees_with_run(b):
    doc(b, CKPT).data["run_status"] = "COMPLETED"
    assert has(b, "E-CHECKPOINT", msg="run_status / thread_id disagree with the run")


def test_e_checkpoint_c_class_must_be_encrypted(b):
    doc(b, CKPT).data["encrypted"] = False
    assert has(b, "E-CHECKPOINT", msg="C-class checkpoints must be encrypted")


# ------------------------------------------------------------------ report manifest
REPORT = "report-manifest.example.json"


def test_e_report_run_not_found(b):
    doc(b, REPORT).data["run_id"] = "run-ghost"
    assert has(b, "E-REPORT", msg="run not found")


def test_e_report_advisory_iff_lane_a(b):
    doc(b, REPORT).data["advisory"] = True
    assert has(b, "E-REPORT", msg="advisory iff Lane A")


def test_e_report_verdict_counts_recomputed(b):
    doc(b, REPORT).data["verdict_counts"]["LIKELY"] += 1
    assert has(b, "E-REPORT", msg="verdict_counts must be")


# ------------------------------------------------------------------ self-test report
SELFTEST = "selftest-report.m1.example.json"


def item(b, status):
    return next(i for i in doc(b, SELFTEST).data["items"] if i["status"] == status)


def test_e_selftest_not_run_has_no_result(b):
    item(b, "NOT_RUN")["runs"] = 1
    assert has(b, "E-SELFTEST", msg="NOT_RUN has no result")


def test_e_selftest_run_needs_runs_and_passed(b):
    item(b, "RUN")["runs"] = 0
    assert has(b, "E-SELFTEST", msg="RUN needs runs and passed")


def test_e_selftest_overall_passed_must_be_derived(b):
    st = doc(b, SELFTEST).data
    st["overall_passed"] = not st["overall_passed"]
    assert has(b, "E-SELFTEST", msg="overall_passed must be all RUN items passed")


# ------------------------------------------------------------------ JCS
def test_e_jcs_vector_mismatch_in_canonical_py(b, monkeypatch):
    monkeypatch.setattr(checks, "JCS_VECTORS", [({"a": 1}, '{"a":2}')])
    assert has(b, "E-JCS", "canonical.py", "RFC 8785 vector mismatch")


def test_e_jcs_vector_mismatch_in_reference_library(b, monkeypatch):
    monkeypatch.setattr(checks, "JCS_VECTORS", [({"a": 1}, '{"a":2}')])
    assert has(b, "E-JCS", "rfc8785", "reference library disagrees")
    assert codes(b) == {"E-JCS"}


def test_e_jcs_document_not_canonicalisable(b):
    # unreachable from disk (the strict loaders reject NaN), so the value is put in memory
    doc(b, REPORT).data["x_nan"] = float("nan")
    assert has(b, "E-JCS", "docs/schemas/examples/" + REPORT, "not canonicalisable")


def test_e_jcs_canonical_differs_from_rfc8785(b, monkeypatch):
    target = doc(b, REPORT)
    real = checks.jcs
    monkeypatch.setattr(checks, "jcs", lambda x: real(x) + (b" " if x is target.data else b""))
    assert has(b, "E-JCS", target.path, "canonical.jcs differs from rfc8785")
    assert codes(b) == {"E-JCS"}


# ------------------------------------------------------------------ loader (files on disk)
@pytest.fixture
def disk(tmp_path):
    """A copy of the bundle's files on disk, for faults only the loader can produce."""
    shutil.copytree(ROOT / "docs", tmp_path / "docs")
    shutil.copy2(ROOT / "requirements.txt", tmp_path / "requirements.txt")
    return tmp_path


def test_e_kind_yaml_file_without_schema_mapping(disk):
    (disk / "docs" / "examples" / "extra.yaml").write_text("a: 1\n", encoding="utf-8")
    bb = load_bundle(disk)
    assert has(bb, "E-KIND", "docs/examples/extra.yaml", "no schema mapping")


def test_e_kind_example_with_no_schema(disk):
    (disk / "docs" / "schemas" / "examples" / "nosuch.x.example.json").write_text("{}", encoding="utf-8")
    bb = load_bundle(disk)
    assert has(bb, "E-KIND", "docs/schemas/examples/nosuch.x.example.json", "no schema named 'nosuch'")


def test_e_load_malformed_json_example(disk):
    p = disk / "docs" / "schemas" / "examples" / REPORT
    p.write_text(p.read_text(encoding="utf-8")[:-5], encoding="utf-8")
    bb = load_bundle(disk)
    assert has(bb, "E-LOAD", "docs/schemas/examples/" + REPORT, "JSON:")


def test_e_load_in_memory_reload(b):
    reload_json(doc(b, SELFTEST), "{")
    assert "E-LOAD" in codes(b)


# ------------------------------------------------------------------ schemas
def test_e_schema_meta_invalid_schema(b):
    b.schemas["checkpoint-metadata"]["minLength"] = -1
    assert has(b, "E-SCHEMA-META", "checkpoint-metadata.schema.json")


def test_e_schema_meta_draft_must_be_2020_12(b):
    b.schemas["checkpoint-metadata"]["$schema"] = "http://json-schema.org/draft-07/schema#"
    assert has(b, "E-SCHEMA-META", "checkpoint-metadata.schema.json", "$schema must be 2020-12")


def test_e_schema_id_must_equal_file_name(b):
    b.schemas["checkpoint-metadata"]["$id"] = "checkpoint.schema.json"
    assert has(b, "E-SCHEMA-ID", "checkpoint-metadata.schema.json", "must equal the file name")


# ------------------------------------------------------------------ licenses and requirements
def lic(b):
    return doc(b, "licenses.yaml").data["components"]


def test_e_lic_dup_duplicate_component(b):
    lic(b).append(dict(lic(b)[0]))
    assert has(b, "E-LIC-DUP", "licenses.yaml", "duplicate components")


def test_e_lic_missing_tool_license_ref(b):
    doc(b, "tools.yaml").data["tools"]["zap"]["license_ref"] = "Ghost"
    assert has(b, "E-LIC-MISSING", "tools.yaml", "license_ref 'Ghost' not in licenses.yaml")


def test_e_lic_missing_requirement_not_listed(b):
    b.requirements_txt += "requests>=2\n"
    assert has(b, "E-LIC-MISSING", "requirements.txt", "requests is not listed")


def test_e_lic_gate_needs_gate_milestone(b):
    x = next(x for x in lic(b) if x["status"] == checks.LEGAL_GATE)
    x["gate_milestone"] = None
    assert has(b, "E-LIC-GATE", "licenses.yaml", "needs a gate_milestone")


def test_e_req_requirements_missing(b):
    b.requirements_txt = None
    assert has(b, "E-REQ", "requirements.txt", "requirements.txt missing")


def test_e_req_rfc8785_must_be_pinned(b):
    b.requirements_txt = b.requirements_txt.replace("rfc8785==0.1.4", "rfc8785>=0.1.4")
    assert codes(b) == {"E-REQ"}
    assert has(b, "E-REQ", "requirements.txt", "rfc8785 must be pinned to 0.1.4")


# ------------------------------------------------------------------ tool registry
def tools(b):
    return doc(b, "tools.yaml").data["tools"]


def test_e_tools_id_mode_is_not_a_tool_mode_id(b):
    tools(b)["zap"]["modes"]["Bad Mode"] = dict(tools(b)["zap"]["modes"]["baseline"])
    assert has(b, "E-TOOLS-ID", "tools.yaml", "zap:Bad Mode is not a D13 tool:mode id")


def test_e_tools_class_executable_mode_needs_base_class(b):
    tools(b)["zap"]["modes"]["baseline"]["base_class"] = None
    assert has(b, "E-TOOLS-CLASS", "tools.yaml", "zap:baseline: executable mode needs a base_class")


def test_e_tools_zone_b4_modes_run_in_z3(b):
    tools(b)["zap"]["zone"] = "Z2"
    assert has(b, "E-TOOLS-ZONE", "tools.yaml", "zap:baseline: B4 modes run in Z3")


def test_e_tools_denylist_registry_matches_toolkit_denylist(b):
    tools(b)["restler"]["modes"]["fuzz"]["toolkit_denied"] = False
    assert has(b, "E-TOOLS-DENYLIST", "tools.yaml", "toolkit_denied modes")
