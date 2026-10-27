# SPDX-License-Identifier: Apache-2.0
"""Review round 9 (docs/evidence/review-2026-10-27-r9.md), PR3: design contracts the validator now holds the bundle to.
Each defect test failed on the PR2 head and passes with the fix; see CONTRIBUTING.md.

  ownership  a run's ownership result uses the method the ROE declares for that target (a database proves control with
             db_comment, not a DNS record), and every target a B4 job ran against has an ok result (E-RUN-OWNERSHIP);
  spot check the ASI09 population is the gate decisions and the verdicts, clusters and suppressions (docs/06 §1.1), and a
             Lite engagement records no spot check: its one person cannot re-review their own decisions (E-SPOT-CHECK);
  G1         a run whose G3 decides threats has an approved G1 of its own (carried item by item from an ancestor or decided
             here), before G0b; the follow-up example now carries GR-G1-0001 (E-RUN-G1).
"""
import copy
import json

from conftest import doc, rederive
from vchlib import checks
from vchlib.bundle import reload_json
from vchlib.checks import run_all

RUN, FRUN = "run-2026-09-23-001", "run-2026-10-07-001"
FAUDIT = "audit-event.run-2026-10-07-001.example.jsonl"


def errors(b, code, where=None):
    return [i for i in run_all(b).errors if i.code == code and (where is None or where in i.where)]


def test_the_examples_are_clean(b):
    assert run_all(b).errors == []


# ================================================================ ownership: the ROE's method, every target used
def own(b, target):
    return next(o for o in doc(b, "run.example.json").data["ownership_results"] if o["target_id"] == target)


def test_the_database_target_is_verified_with_db_comment(b):
    """Review r9 (methodology) #1: the ROE declares db_comment for tgt-staging-db, the run said dns_txt."""
    assert own(b, "tgt-staging-db")["method"] == "db_comment"


def test_a_result_with_another_method_than_the_roe_is_reported(b):
    own(b, "tgt-staging-db")["method"] = "dns_txt"
    assert any("tgt-staging-db" in i.msg and "db_comment" in i.msg for i in errors(b, "E-RUN-OWNERSHIP", "run.example"))


def test_a_target_a_job_ran_against_needs_an_ok_result(b):
    run = doc(b, "run.example.json").data
    run["ownership_results"] = [o for o in run["ownership_results"] if o["target_id"] != "tgt-staging-api"]
    assert any("tgt-staging-api" in i.msg for i in errors(b, "E-RUN-OWNERSHIP", "run.example"))


def test_a_failed_result_does_not_cover_a_target(b):
    own(b, "tgt-staging-api")["ok"] = False
    assert any("tgt-staging-api" in i.msg for i in errors(b, "E-RUN-OWNERSHIP", "run.example"))


def test_a_result_for_a_target_outside_the_roe_is_reported(b):
    extra = copy.deepcopy(own(b, "tgt-canary"))
    extra["target_id"] = "tgt-nowhere"
    doc(b, "run.example.json").data["ownership_results"].append(extra)
    assert any("tgt-nowhere" in i.msg for i in errors(b, "E-RUN-OWNERSHIP", "run.example"))


# ================================================================ spot check: the ASI09 population, and Lite
def spot(b, kind, item, who="heidi", profile=None):
    c = checks.Ctx(b)
    if profile:
        c.engagement = {**c.engagement, "assurance_profile": profile}
    R = checks.Report()
    ev = {"actor": {"kind": "human", "id": who}, "payload": {"item_kind": kind, "item_id": item, "agrees": True}}
    checks.spot_check(R, c, "probe", c.runs[RUN], ev)
    return [i for i in R.errors if i.code == "E-SPOT-CHECK"]


def test_a_verdict_cluster_or_suppression_can_be_spot_checked(b):
    """docs/06 §1.1: the population includes every CONFIRMED_* verdict, auto-rejected and report-only clusters and
    suppressed items; v0.7 only accepted gate records, so none of them could be recorded."""
    assert spot(b, "verdict", "V-005-2") == []
    assert spot(b, "cluster", "K-014") == []
    assert spot(b, "feedback", "FB-001") == []


def test_an_unknown_item_is_reported(b):
    assert spot(b, "verdict", "V-999-1")
    assert spot(b, "cluster", "K-999")


def test_the_g2_approver_cannot_spot_check_the_cluster_they_decided(b):
    assert spot(b, "cluster", "K-016", who="erin")                       # erin approved GR-G2-0001, which decided K-016
    assert spot(b, "verdict", "V-011-2", who="erin")


def test_a_lite_engagement_records_no_spot_check(b):
    """docs/06 §1.1: Lite has one person, who approved everything; a 'spot check' would be self-review."""
    assert any("lite" in i.msg for i in spot(b, "g4", "GR-G4-0001", profile="lite"))


# ================================================================ G1: the follow-up run's own G1
def test_the_follow_up_run_has_its_own_g1_carried_from_the_parent(b):
    run = doc(b, "run.followup.example.json").data
    g1 = [g for g in run["gate_records"] if g["gate"] == "G1"]
    assert len(g1) == 1 and g1[0]["outcome"] == "APPROVED"
    rec = doc(b, "gate-record.followup.g1.example.json").data
    assert rec["run_id"] == FRUN and all(x["carried_from"]["gate_record_id"] == "GR-G1-0001" for x in rec["decisions"])


def test_a_run_whose_g3_decides_threats_needs_a_g1(b, keys):
    """Review r9 (methodology) #4: the follow-up run had G0a, G0b, G3 and a G4 but no G1; docs/02 §1.6 says G1 and G3 are
    signed by the run itself."""
    b.docs.remove(doc(b, "gate-record.followup.g1.example.json"))
    run = doc(b, "run.followup.example.json").data
    run["gate_records"] = [g for g in run["gate_records"] if g["gate"] != "G1"]
    a = doc(b, FAUDIT)
    # drop the anchor that followed the G1 decision
    keep, skip = [], False
    for e in a.data:
        if (e.get("payload") or {}).get("gate") == "G1":
            skip = e["event_type"] == "gate_decision"
            continue
        if skip and e["event_type"] == "audit_anchor":
            skip = False
            continue
        keep.append(e)
    for i, e in enumerate(keep):
        e["seq"] = i + 1
    reload_json(a, "".join(json.dumps(e, ensure_ascii=False, separators=(",", ":")) + "\n" for e in keep))
    rederive(b, keys)
    assert errors(b, "E-RUN-G1", "run.followup")
