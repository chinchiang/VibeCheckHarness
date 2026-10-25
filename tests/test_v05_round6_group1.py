# SPDX-License-Identifier: Apache-2.0
"""v0.5 round 6, group 1 (docs/evidence/review-2026-10-25.md §4.1 H-1, H-2, H-3, H-5). Positive and negative cases:

- H-1: a run with gate records must have an audit log (receive time), otherwise E-AUDIT-GATE;
- H-2: a test result names only clusters of its own threat (E-TRACE);
- H-3: R10 applies only to verdict versions produced after G2; G2_apply writes the post-G2 version;
- H-5: testcase.seed_manifest_ref is required (E-TC-SEEDS).
"""
import json

from conftest import codes, doc, rederive, resign_gate
from vchlib.bundle import reload_json
from vchlib.checks import Ctx, run_all, verdict_inputs

FOLLOWUP_LOG = "audit-event.run-2026-10-07-001.example.jsonl"
G2 = "gate-record.g2.example.json"


def errors(b, code):
    return [i for i in run_all(b).errors if i.code == code]


# ================================================================ H-1
def test_followup_example_has_an_audit_log(b):
    c = Ctx(b)
    assert c.ix.audit_for("run-2026-10-07-001") is not None
    assert not errors(b, "E-AUDIT-GATE")


def test_gate_records_without_an_audit_log_are_rejected(b):
    b.docs[:] = [d for d in b.docs if not d.path.endswith(FOLLOWUP_LOG)]
    got = [i for i in errors(b, "E-AUDIT-GATE") if "run-2026-10-07-001" in i.where]
    assert {g for i in got for g in ("GR-G0a-0002", "GR-G0b-0002") if g in i.msg} == {"GR-G0a-0002", "GR-G0b-0002"}


def test_a_missing_gate_decision_event_is_still_reported(b, keys):
    d = doc(b, FOLLOWUP_LOG)
    events = [e for e in d.data if not (e["event_type"] == "gate_decision" and e["payload"]["gate"] == "G0b")]
    for i, e in enumerate(events, 1):
        e["seq"] = i
    reload_json(d, "".join(json.dumps(e, ensure_ascii=False, separators=(",", ":")) + "\n" for e in events))
    rederive(b, keys)
    assert any("GR-G0b-0002" in i.msg for i in errors(b, "E-AUDIT-GATE"))


# ================================================================ H-2
def test_result_cannot_be_attached_to_an_unrelated_cluster(b):
    doc(b, "testresult.llm-pass.example.json").data["cluster_ids"] = ["K-011", "K-014"]
    assert any("K-014" in i.msg for i in errors(b, "E-TRACE"))


def test_result_may_name_clusters_its_threat_cites(b):
    tr = doc(b, "testresult.example.json").data            # TC-012-01, threat T-012 cites K-005 and K-015
    tr["cluster_ids"] = ["K-005", "K-015"]
    assert not [i for i in errors(b, "E-TRACE") if "testresult.example" in i.where]


# ================================================================ H-3
def _reject_k011(b, keys):
    rec = doc(b, G2).data
    next(x for x in rec["decisions"] if x["item_id"] == "K-011")["decision"] = "reject"
    resign_gate(b, G2, keys)


def test_g2_reject_does_not_invalidate_the_w3_version(b, keys):
    _reject_k011(b, keys)
    c = Ctx(b)
    cl = c.ix.first("cluster", cluster_id="K-011").data
    assert not verdict_inputs(c, doc(b, "verdict.k-011-w3.example.json").data, cl).g2_rejected
    assert verdict_inputs(c, doc(b, "verdict.k-011-b5.example.json").data, cl).g2_rejected
    assert not [i for i in run_all(b).errors if "verdict.k-011-w3" in i.where and i.code.startswith("E-VERDICT")]


def test_g2_apply_is_a_post_g2_phase(b, keys):
    _reject_k011(b, keys)
    v = doc(b, "verdict.k-011-b5.example.json").data
    v["readjudicated_by"] = "G2_apply"
    c = Ctx(b)
    cl = c.ix.first("cluster", cluster_id="K-011").data
    assert verdict_inputs(c, v, cl).g2_rejected
    assert "E-SCHEMA" not in {i.code for i in run_all(b).errors if "verdict.k-011-b5" in i.where}


# ================================================================ H-5
def test_seed_manifest_ref_is_required(b):
    doc(b, "testcase.llm.example.json").data["seed_manifest_ref"] = None
    assert any("testcase.llm" in i.where for i in errors(b, "E-TC-SEEDS"))


def test_example_testcases_name_the_roe_manifest(b):
    assert "E-TC-SEEDS" not in codes(b)
