# SPDX-License-Identifier: Apache-2.0
"""BL-60 follow-up: the `suspend` variant walks a G4 timeout to SUSPENDED and an ASI09 spot check that overturns a G5.

Building it found a validator gap, fixed here: an EXPIRED G3 / G4 record may carry only needs_info decisions, but the
outcome-vs-decisions check then demanded PARTIALLY_APPROVED, so no timed-out G3 / G4 could ever validate
(E-GATE-OUTCOME). Each test failed before this change and passes after it (tests/mutations/bl60_suspend.json)."""
import copy
import pathlib

import pytest

from conftest import doc
from vchlib import checks, timeutil
from vchlib.bundle import load_variant
from vchlib.checks import Ctx, g5_escalation, run_all

ROOT = pathlib.Path(__file__).resolve().parents[1]
FOLLOWUP = "run-2026-10-07-001"
LOG = "audit-event.run-2026-10-07-001.example.jsonl"


@pytest.fixture(scope="module")
def base_suspend():
    return load_variant(ROOT, "suspend")


@pytest.fixture
def s(base_suspend):
    return base_suspend.clone()


def events(b):
    return doc(b, LOG).data


def test_the_variant_validates_cleanly(s):
    R = run_all(s)
    assert R.errors == [] and {w.code for w in R.warnings} == {"W-MODEL-PLACEHOLDER"}


def test_g4_expires_unsigned_with_only_needs_info(s):
    g4 = doc(s, "gate-record.followup.g4.example.json").data
    assert (g4["outcome"], g4["signatures"]) == ("EXPIRED", [])
    assert {d["decision"] for d in g4["decisions"]} == {"needs_info"}


def test_the_run_is_suspended_not_ended(s):
    run = doc(s, "run.followup.example.json").data
    ck = doc(s, "checkpoint-metadata.followup.example.json").data
    assert run["status"] == ck["run_status"] == "SUSPENDED"
    evs = events(s)
    changed = [e for e in evs if e["event_type"] == "run_status_changed"]
    assert changed[-1]["payload"]["to"] == "SUSPENDED"
    assert not [e for e in evs if (e.get("payload") or {}).get("reason") == "run_end"]          # resumable: no run_end


def test_a_suspended_run_cannot_claim_to_be_ended(s):
    doc(s, "run.followup.example.json").data["status"] = "ABORTED"
    assert "E-RUN-STATUS" in run_all(s).codes()


def test_g4_expired_before_its_timeout_is_rejected(s):
    evs = events(s)
    dec = next(e for e in evs if e["event_type"] == "gate_decision" and e["payload"]["gate"] == "G4")
    dec["ts"] = "2026-10-08T10:30:00+08:00"
    assert "E-GATE-EXPIRED-EARLY" in run_all(s).codes()


def test_an_expired_g4_may_not_accept_anything(s):
    g4 = doc(s, "gate-record.followup.g4.example.json").data
    g4["decisions"][0]["decision"] = "accept"
    assert any("may only carry needs_info" in i.msg for i in run_all(s).errors if i.code == "E-GATE-OUTCOME")


def test_an_expired_g3_or_g4_implies_no_outcome_from_its_decisions(s):
    """The regression: before the fix this record was always E-GATE-OUTCOME ("decisions imply PARTIALLY_APPROVED")."""
    assert not [i for i in run_all(s).errors if i.code == "E-GATE-OUTCOME"]


def test_the_spot_check_overturns_the_initial_g5(s):
    sc = next(e for e in events(s) if e["event_type"] == "spot_check_result")
    assert sc["actor"]["id"] == "grace"
    assert (sc["payload"]["item_kind"], sc["payload"]["item_id"], sc["payload"]["outcome"]) == ("g5", "GR-G5-0001", "overturned")


def test_the_g5_approver_may_not_spot_check_it(s, keys):
    sc = next(e for e in events(s) if e["event_type"] == "spot_check_result")
    sc["actor"] = {"kind": "human", "id": "heidi"}
    assert any("must be independent" in i.msg for i in run_all(s).errors if i.code == "E-SPOT-CHECK")


def test_the_overturn_escalates_later_runs_only(s, monkeypatch):
    """The example has no run that starts after the spot check, so a later run of the engagement is stood in for by
    its start time (checks.run_start reads it from that run's own audit log)."""
    c = Ctx(s)
    assert g5_escalation(c, FOLLOWUP) is None                    # the follow-up run started before the spot check
    later = copy.deepcopy(c.runs[FOLLOWUP])
    later["run_id"] = "run-2026-11-01-001"
    c.runs["run-2026-11-01-001"] = later
    real = checks.run_start
    monkeypatch.setattr(checks, "run_start", lambda c_, rid: timeutil.parse_dt("2026-11-01T09:00:00+08:00")
                        if rid == "run-2026-11-01-001" else real(c_, rid))
    assert g5_escalation(c, "run-2026-11-01-001")
