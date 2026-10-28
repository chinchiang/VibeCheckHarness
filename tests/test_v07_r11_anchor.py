# SPDX-License-Identifier: Apache-2.0
"""Review r11 (2026-10-28), group 1: the run lifecycle and the W / B-phase artefacts join the anchoring model.

Probes of the review, each of which validated with zero errors on 2823823 without any key:
  - a SUSPENDED / STOPPED run went back to RUNNING on one unanchored system run_status_changed line, with no signed
    run_resume and no fresh G0b (E-RUN-RESUME); a WAITING_GATE run went RUNNING with its gate never decided;
  - the W0 inventory (files, blind spots, env vars), the redaction map, both DFDs and the commander plans of a completed
    run could be rewritten: only the seed threats had an anchored artifact_stored (E-AUDIT-ARTIFACT);
  - a run wrote COMPLETED with an ownership_failed gap (docs/02 §1.4 derives the terminal status from the gaps);
  - a G1 record in round 7 (docs/02 §1.4 allows 3) validated (E-GATE-ROUND);
  - run.initiators listed a person who never claimed the run (E-RUN-CLAIM, the reverse direction);
  - E-W4-COVERAGE held only for the run invariants.yaml names; a restore drill counted whoever wrote it, anchored or not.
Each test failed before the change and passes after it (tests/mutations/r11_anchor.json); see CONTRIBUTING.md."""
import copy
import pathlib

import pytest

from conftest import doc, rederive
from test_v07_r9_anchor import AUDIT, FAUDIT, refix_nokey
import sign_examples
from vchlib.bundle import load_variant, reload_json
from vchlib.checks import run_all

ROOT = pathlib.Path(__file__).resolve().parents[1]
RUN, FRUN = "run.example.json", "run.followup.example.json"
FOLLOWUP = "run-2026-10-07-001"


def errors(b, code, where=None):
    return [i for i in run_all(b).errors if i.code == code and (where is None or where in i.where)]


def codes(b):
    return {i.code for i in run_all(b).errors}


@pytest.fixture(scope="module")
def suspend_base():
    return load_variant(ROOT, "suspend")


@pytest.fixture
def s(suspend_base):
    return suspend_base.clone()


def append(log, *events, after=None):
    """Append events cloned from the log's last line (seq and hashes are rebuilt by rederive / refix_nokey)."""
    base = log.data[-1] if after is None else log.data[after - 1]
    for e in events:
        ev = copy.deepcopy(base)
        ev.update({"payload_refs": [], "signature": None, "actor": {"kind": "system", "id": "run-controller"}, "zone": "Z1"})
        ev.update(e)
        ev["idempotency_key"] = f"{ev['run_id']}:{ev['node']}:{ev['event_type']}:{len(log.data)}"
        log.data.append(ev)
    renumber(log)


def renumber(log):
    for n, ev in enumerate(log.data, 1):
        ev["seq"] = n
    reload_json(log, sign_examples.dump_jsonl(log.data))        # keep the raw text in step with the events


def test_the_examples_are_clean(b, suspend_base):
    assert run_all(b).errors == [] and run_all(suspend_base).errors == []


# ================================================================ resume
def resume_line(s, when="2026-10-12T09:00:00+08:00"):
    run, ck = doc(s, FRUN).data, doc(s, "checkpoint-metadata.followup.example.json").data
    append(doc(s, FAUDIT), {"event_type": "run_status_changed", "node": "G4", "ts": when, "payload": {"from": "SUSPENDED", "to": "RUNNING"}})
    run["status"], ck["run_status"] = "RUNNING", "RUNNING"


def test_a_suspended_run_cannot_resume_on_an_unsigned_line(s):
    resume_line(s)
    refix_nokey(s)
    assert any("needs a human's signed run_resume" in i.msg for i in errors(s, "E-RUN-RESUME"))


def anchor(log, when, node="G4"):
    append(log, {"event_type": "audit_anchor", "node": node, "ts": when,
                 "payload": {"reason": "phase_end", "anchor_counter": 0, "z3_countersignature": None}})


def signed_resume(s, keys, who="alice", when="2026-10-12T09:00:00+08:00", from_status="SUSPENDED"):
    log = doc(s, FAUDIT)
    append(log, {"event_type": "run_resume", "node": "G4", "ts": when, "actor": {"kind": "human", "id": who},
                 "payload": {"from_status": from_status, "person_id": who, "reason": "ROE 重新簽署後恢復"}})
    resume_line(s, when)
    anchor(log, when)
    rederive(s, keys)


def test_a_signed_anchored_run_resume_by_the_run_owner_resumes_it(s, keys):
    signed_resume(s, keys)
    assert errors(s, "E-RUN-RESUME") == [] and errors(s, "E-RUN-STATUS") == []


def test_the_resume_must_be_anchored(s, keys):
    log = doc(s, FAUDIT)
    append(log, {"event_type": "run_resume", "node": "G4", "ts": "2026-10-12T09:00:00+08:00", "actor": {"kind": "human", "id": "alice"},
                 "payload": {"from_status": "SUSPENDED", "person_id": "alice", "reason": "x"}})
    resume_line(s, "2026-10-12T09:00:00+08:00")
    rederive(s, keys)
    assert any("not anchored" in i.msg for i in errors(s, "E-RUN-RESUME"))


def test_a_resume_after_the_engagement_validity_is_rejected(s, keys):
    signed_resume(s, keys, when="2026-11-15T09:00:00+08:00")               # engagement validity ends 2026-10-31
    assert any("after the engagement validity ended" in i.msg for i in errors(s, "E-RUN-RESUME"))


def test_a_b_phase_event_after_the_resume_needs_a_fresh_g0b(s, keys):
    signed_resume(s, keys)
    log = doc(s, FAUDIT)
    append(log, {"event_type": "policy_decision", "node": "B3", "ts": "2026-10-12T10:00:00+08:00", "payload": {"decision": "allow"}})
    anchor(log, "2026-10-12T10:00:00+08:00", node="B3")
    rederive(s, keys)
    assert any("without a new VERIFIED G0b" in i.msg for i in errors(s, "E-RUN-RESUME"))


def test_the_status_chain_links_each_from_to_the_previous_to(s):
    ev = next(e for e in doc(s, FAUDIT).data if e["event_type"] == "run_status_changed" and e["payload"]["to"] == "SUSPENDED")
    ev["payload"]["from"] = "RUNNING"                                       # the run was WAITING_GATE
    refix_nokey(s)
    assert any("but the run was 'WAITING_GATE'" in i.msg for i in errors(s, "E-RUN-STATUS"))


def test_waiting_gate_cannot_go_running_without_a_decision(b):
    run, ck = doc(b, FRUN).data, doc(b, "checkpoint-metadata.followup.example.json").data
    append(doc(b, FAUDIT), {"event_type": "run_status_changed", "node": "G4", "ts": "2026-10-08T09:00:00+08:00",
                            "payload": {"from": "WAITING_GATE", "to": "RUNNING"}})
    run["status"], ck["run_status"], ck["pending_interrupt"] = "RUNNING", "RUNNING", None
    refix_nokey(b)
    assert any("without a gate_decision in between" in i.msg for i in errors(b, "E-RUN-STATUS"))


# ================================================================ W / B-phase artefacts
@pytest.mark.parametrize("name, change", [
    ("inventory.example.json", lambda d: d["files"].pop()),
    ("inventory.example.json", lambda d: d.__setitem__("blind_spots", [])),
    ("redaction-map.example.json", lambda d: d["entries"].pop()),
    ("dfd.merged.example.json", lambda d: d["elements"].pop()),
    ("dfd.external.example.json", lambda d: d["elements"].pop()),
    ("commander-plan.example.json", lambda d: d.__setitem__("rationale", "rewritten after the run")),
    ("commander-plan.cmd5.example.json", lambda d: d.__setitem__("rationale", "rewritten after the run")),
])
def test_a_completed_runs_artefact_cannot_be_rewritten(b, name, change):
    change(doc(b, name).data)
    refix_nokey(b)
    assert errors(b, "E-AUDIT-ARTIFACT")


def test_every_pinned_artefact_needs_its_anchored_event(b, keys):
    log = doc(b, AUDIT)
    log.data[:] = [e for e in log.data if not (e["event_type"] == "artifact_stored" and e["payload"]["artifact"] == "inventory")]
    renumber(log)
    rederive(b, keys)
    assert any("needs exactly one anchored artifact_stored" in i.msg for i in errors(b, "E-AUDIT-ARTIFACT", "inventory.example.json"))


def test_an_artifact_stored_must_name_a_pinned_artefact(b, keys):
    ev = next(e for e in doc(b, AUDIT).data if e["event_type"] == "artifact_stored" and e["payload"]["artifact"] == "dfd-merged")
    ev["payload"]["artifact"] = "slice"
    rederive(b, keys)
    assert "E-SCHEMA" in codes(b) or any("the pinned artefacts are" in i.msg for i in errors(b, "E-AUDIT-ARTIFACT"))


def test_the_seed_threats_are_still_pinned(b):
    doc(b, "seed-threats.example.json").data["seeds"].pop()
    refix_nokey(b)
    assert errors(b, "E-AUDIT-ARTIFACT")


# ================================================================ terminal status from the gaps
def test_completed_with_a_non_manual_gap_is_completed_with_gaps(b, keys):
    gap = {"kind": "ownership_failed", "ref": "tgt-staging-api", "reason": "probe"}
    doc(b, RUN).data["gaps"] = [gap]
    doc(b, "report-manifest.example.json").data["gaps"] = [copy.deepcopy(gap)]
    rederive(b, keys)
    assert any("imply COMPLETED_WITH_GAPS" in i.msg for i in errors(b, "E-RUN-STATUS"))


def test_completed_with_gaps_needs_a_non_manual_gap(b, keys):
    run = doc(b, RUN).data
    run["status"] = "COMPLETED_WITH_GAPS"
    ev = next(e for e in doc(b, AUDIT).data if e["event_type"] == "run_status_changed")
    ev["payload"]["to"] = "COMPLETED_WITH_GAPS"
    rederive(b, keys)
    assert any("imply COMPLETED" in i.msg for i in errors(b, "E-RUN-STATUS"))


def test_a_manual_gap_keeps_completed(b, keys):
    gap = {"kind": "manual", "ref": "TC-027-01", "reason": "probe"}
    doc(b, RUN).data["gaps"] = [gap]
    doc(b, "report-manifest.example.json").data["gaps"] = [copy.deepcopy(gap)]
    rederive(b, keys)
    assert errors(b, "E-RUN-STATUS") == []


# ================================================================ gate rounds
@pytest.mark.parametrize("suffix, rnd", [("gate-record.g1.example.json", 4), ("gate-record.g4.example.json", 3), ("gate-record.g2.example.json", 2)])
def test_a_gate_beyond_its_round_limit_is_rejected(b, keys, suffix, rnd):
    rec = doc(b, suffix).data
    rec["round"] = rnd
    for g in doc(b, RUN).data["gate_records"]:
        if g["gate_record_id"] == rec["gate_record_id"]:
            g["round"] = rnd
    rederive(b, keys)
    assert "E-GATE-ROUND" in codes(b) or "E-SCHEMA" in codes(b)


def test_the_g4_round_limit_fires_the_validator_rule(b, keys):
    rec = doc(b, "gate-record.g4.example.json").data
    rec["round"] = 3
    for g in doc(b, RUN).data["gate_records"]:
        if g["gate_record_id"] == rec["gate_record_id"]:
            g["round"] = 3
    rederive(b, keys)
    assert any("exceeds the 2-round limit" in i.msg for i in errors(b, "E-GATE-ROUND"))


# ================================================================ initiators, W4 coverage, restore drill
def test_an_initiator_without_a_claim_is_rejected(b):
    doc(b, RUN).data["initiators"].append("frank")
    refix_nokey(b)
    assert any("frank" in i.msg and "no anchored signed initiator_claim" in i.msg for i in errors(b, "E-RUN-CLAIM"))


def test_a_lane_a_run_has_no_initiator(b):
    rec = doc(b, "gate-record.lane-a.g0a.example.json").data
    assert rec["initiator"] is None and doc(b, "run.lane-a.example.json").data["initiators"] == []
    doc(b, "gate-record.g0a.example.json").data["initiator"] = None
    refix_nokey(b)
    assert any("only allowed on a Lane A run" in i.msg for i in errors(b, "E-GATE-INITIATOR"))


def test_an_initial_run_without_its_own_invariants_is_not_covered(b, keys):
    inv = doc(b, "invariants.yaml").data
    inv["run_id"] = FOLLOWUP                                    # the initial run now has no G1 invariants of its own
    rederive(b, keys)
    assert any("has no G1 invariants of its own" in i.msg for i in errors(b, "E-W4-COVERAGE"))


def test_a_restore_drill_counts_only_from_a_system_actor_in_the_anchored_log(b, keys):
    log = doc(b, AUDIT)
    drill = next(e for e in log.data if e["event_type"] == "restore_drill")
    drill["actor"] = {"kind": "human", "id": "dave"}
    rederive(b, keys)
    assert errors(b, "E-RUN-RESTORE-DRILL")
    b2 = b.clone()
    log2 = doc(b2, AUDIT)
    d2 = next(e for e in log2.data if e["event_type"] == "restore_drill")
    d2["actor"] = {"kind": "system", "id": "snapshot-service"}
    log2.data.remove(d2)
    log2.data.append(d2)                                        # after the run_end anchor: unanchored (and E-AUDIT-TAIL)
    renumber(log2)
    rederive(b2, keys)
    assert errors(b2, "E-RUN-RESTORE-DRILL")


def test_the_schema_caps_the_round():
    import json
    schema = json.loads((ROOT / "docs" / "schemas" / "gate-record.schema.json").read_text(encoding="utf-8"))
    assert schema["properties"]["round"]["maximum"] == 3
