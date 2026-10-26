# SPDX-License-Identifier: Apache-2.0
"""v0.6 review r7, groups 4 and 5 (the parts the validator or the reference functions enforce).

4.1 a shared-platform target without a technical proof of ownership (a token its own deployment serves) is S0 only;
4.2 PII stop condition: registered synthetic seed values and canaries do not stop a job;
4.3 expected 5xx / 429 declared by a testcase count only toward its own job, not the run-level stop conditions;
4.5 an overturned G5 spot check escalates the engagement's later G5s to two security reviewers; over_cap_items is
    recomputed for G3;
5   one malformed ROE section does not hide the errors of the others.
"""
import copy

import pytest

from conftest import doc
from vchlib import checks, safety
from vchlib.checks import Ctx, run_all

ROE = "roe.yaml"


def errors(b, code, where=None):
    return [i for i in run_all(b).errors if i.code == code and (where is None or where in i.where)]


# ================================================================ 5: g_roe sections
@pytest.mark.parametrize("path, value, section", [
    (("validity", "windows"), "x", "engagement and validity"),
    (("signatories",), [None], "signatories"),
    (("relay", "max_turns"), None, "relay"),                      # fuzz: relay.max_turns=None
])
def test_a_malformed_roe_section_does_not_hide_the_others(b, path, value, section):
    roe = doc(b, ROE).data
    node = roe
    for k in path[:-1]:
        node = node[k]
    node[path[-1]] = value
    roe["stop_conditions"]["contacts"] = []                       # an error in a later section
    found = run_all(b).errors
    assert any(i.code == "E-INTERNAL" and section in i.where for i in found), [(i.code, i.where) for i in found if i.code == "E-INTERNAL"]
    assert any(i.code == "E-ROE-STOP" and "contacts" in i.msg for i in found)


# ================================================================ 4.1 technical ownership proof
def _on_vercel(b):
    roe = doc(b, ROE).data
    t = next(x for x in roe["targets"] if x["id"] == "tgt-staging-app")
    t["base_url"] = "https://acme-staging.vercel.app"
    t["ownership_proof"] = {"method": "platform_project", "token_ref": None, "platform": "vercel", "project_ref": "acme-staging",
                            "evidence_ref": "vault://engagements/eng-acme-invoices-2026q4/vercel-project"}
    roe["platform_policies"] = [{"platform": "vercel", "policy_url": "https://vercel.example.net/policy", "accepted_by": "alice",
                                 "accepted_at": "2026-09-29T10:00:00+08:00", "restrictions": ["只測自己的專案"]}]
    return t


def test_a_shared_platform_target_without_technical_proof_is_s0_only(b):
    """TC-031-01 (S1) targets tgt-staging-app; a project page screenshot alone no longer authorises it."""
    _on_vercel(b)
    assert any("TC-031-01" in i.msg and "technical_proof" in i.msg for i in errors(b, "E-ROE-PLATFORM"))


def test_a_technical_proof_allows_s1(b):
    t = _on_vercel(b)
    t["ownership_proof"]["technical_proof"] = {"method": "deployed_path", "token_ref": "vault://x/token",
                                               "location": "/.well-known/vibecheck-eng-acme-invoices-2026q4.txt"}
    assert not errors(b, "E-ROE-PLATFORM")


def test_a_technical_proof_fits_the_target_kind(b):
    t = _on_vercel(b)
    t["ownership_proof"]["technical_proof"] = {"method": "db_comment", "token_ref": "vault://x/token", "location": "COMMENT ON DATABASE"}
    assert any("technical_proof needs" in i.msg for i in errors(b, "E-ROE-PLATFORM"))


# ================================================================ 4.2 PII stop condition
def test_registered_seed_values_and_canaries_do_not_stop_a_job(b):
    man = doc(b, "seed-manifest.yaml").data
    hits = ["0912-345-678", "林雅婷", "822 5501 7788 21", "vc-canary-7f3a", "0987-654-321", "王小明"]
    assert safety.pii_stop_hits(hits, man, canaries=["vc-canary-7f3a"]) == ["0987-654-321", "王小明"]


def test_unregistered_pii_still_stops(b):
    assert safety.pii_stop_hits(["0912-345-678"], {"seeds": {}}) == ["0912-345-678"]


# ================================================================ 4.3 expected 5xx / 429
def test_expected_errors_do_not_count_toward_the_run(b):
    tc = {"expected_error_statuses": [500, 429]}
    assert not safety.counts_for_run_stop(500, tc) and not safety.counts_for_run_stop(429, tc)
    assert safety.counts_for_run_stop(502, tc) and safety.counts_for_run_stop(500, {})
    assert not safety.counts_for_run_stop(404, {})


def test_only_429_and_5xx_can_be_expected(b):
    doc(b, "testcase.idor.example.json").data["expected_error_statuses"] = [404]
    assert any("404" in i.msg for i in errors(b, "E-TC-EXPECTED-STATUS"))
    doc(b, "testcase.idor.example.json").data["expected_error_statuses"] = [503]
    assert not errors(b, "E-TC-EXPECTED-STATUS")


# ================================================================ 4.5 spot-check escalation, over_cap
LANE_A_AUDIT = "audit-event.run-2026-09-25-pr-118.example.jsonl"


def _overturned_g5(b, ts):
    evs = doc(b, LANE_A_AUDIT).data
    i = max(n for n, e in enumerate(evs) if e["event_type"] == "audit_anchor")
    ev = copy.deepcopy(evs[i - 1])
    ev.update(event_type="spot_check_result", ts=ts, payload={"item_kind": "g5", "item_id": "GR-G5-0001", "outcome": "overturned", "note": "x"})
    evs.insert(i, ev)
    for n, e in enumerate(evs, 1):
        e["seq"] = n


def test_an_overturned_g5_spot_check_requires_two_reviewers_later(b):
    """The Lane A run is of the same engagement; an overturned G5 recorded there before the initial run started
    makes that run's G5 a two-reviewer gate (the example G5 has one security reviewer)."""
    _overturned_g5(b, "2026-09-20T09:00:00+08:00")
    c = Ctx(b)
    assert checks.g5_escalation(c, "run-2026-09-23-001")
    assert any("overturned" in i.msg for i in errors(b, "E-G5-TWO-PERSON"))


def test_a_later_spot_check_does_not_reach_back(b):
    _overturned_g5(b, "2026-12-01T09:00:00+08:00")
    assert checks.g5_escalation(Ctx(b), "run-2026-09-23-001") is None


def test_g3_over_cap_seeds_are_listed(b):
    g3 = doc(b, "gate-record.g3.example.json").data
    d = next(x for x in g3["decisions"] if x["item_id"] == "T-031")
    d["decision"] = "over_cap"
    assert any("ST-002" in i.msg and "not listed" in i.msg for i in errors(b, "E-REPORT-QUEUE"))
    doc(b, "report-manifest.example.json").data["over_cap_items"].append({"gate": "G3", "item_id": "ST-002", "reason": "x"})
    assert not [i for i in errors(b, "E-REPORT-QUEUE") if "not listed" in i.msg]


def test_only_an_overturned_g5_escalates(b):
    _overturned_g5(b, "2026-09-20T09:00:00+08:00")
    ev = next(e for e in doc(b, LANE_A_AUDIT).data if e["event_type"] == "spot_check_result")
    ev["payload"]["item_kind"] = "g2"
    assert checks.g5_escalation(Ctx(b), "run-2026-09-23-001") is None
    ev["payload"].update(item_kind="g5", outcome="upheld")
    assert checks.g5_escalation(Ctx(b), "run-2026-09-23-001") is None


def test_an_unanchored_spot_check_does_not_escalate(b):
    evs = doc(b, LANE_A_AUDIT).data
    ev = copy.deepcopy(evs[-1])
    ev.update(event_type="spot_check_result", ts="2026-09-20T09:00:00+08:00",
              payload={"item_kind": "g5", "item_id": "GR-G5-0001", "outcome": "overturned", "note": "x"})
    evs.append(ev)
    for n, e in enumerate(evs, 1):
        e["seq"] = n
    assert checks.g5_escalation(Ctx(b), "run-2026-09-23-001") is None
