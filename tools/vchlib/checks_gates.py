# SPDX-License-Identifier: Apache-2.0
"""Check group over the gate records: approvers and separation of duties, the G5/G4 link, carried decisions, opening
times and redraft limits, the G3 oracle approvals; and the G5 escalation after an overturned spot check.

Split out of checks.py (architecture refactor PR-D5, docs/adr/0003-split-checks.md). The text is moved verbatim; no
rule, error code or message changed. checks.GROUPS still lists the group in the same place.
"""
from __future__ import annotations

import datetime as dt

from . import derive, timeutil
from .canonical import signing_payload
from .checks_engagement import consolidation_person, profile
from .checks_signatures import MAX_CLOCK_SKEW, decision_time, verify_signature
from .context import Ctx
from .report import ENGAGEMENT_GATES, GATE_ROLES, ROE_GATES, Report, doc_guard, roe_windows, ts


# ============================================================== 10 gates
def oracle_approval_problems(R, c, rec: dict, w) -> None:
    """D3 (2026-11-22 review, 05-v0.17, user decision): `oracle_approvals` of a gate record. After W4 a person reads the
    oracle of each LLM-written W4 test and approves it item by item; the approval is what makes its interpretation
    pre-registered (derive.w4_oracle_approved). It is recorded in the G3 record, signed with it, and pins the testcase:
      - only a G3 record carries it;
      - each item names a w4-testcase of the record's run, once;
      - not one whose oracle the harness generated (derive.CODE_ORACLE_KINDS): nothing to approve there;
      - an `accept` pins the testcase as it is in the bundle (testcase_sha256 = its approval hash)."""
    oa = rec.get("oracle_approvals")
    if oa is None:
        return
    R.check(rec.get("gate") == "G3", "E-GATE-ORACLE", w,
            f"oracle_approvals belongs to a G3 record, not {rec.get('gate')} (the W4 oracles are reviewed with the seed threats)")
    seen = set()
    for d in oa if isinstance(oa, list) else []:
        if not isinstance(d, dict):
            continue
        tid = d.get("testcase_id")
        R.check(tid not in seen, "E-GATE-ORACLE", w, f"oracle_approvals names {tid} twice")
        seen.add(tid)
        tc = next((t.data for t in c.docs("w4-testcase") if t.data.get("testcase_id") == tid and t.data.get("run_id") == rec.get("run_id")), None)
        if not R.check(tc is not None, "E-GATE-ORACLE", w, f"oracle_approvals names {tid}, which is not a W4 testcase of run {rec.get('run_id')}"):
            continue
        R.check(not derive.oracle_preregistered_by_code(tc), "E-GATE-ORACLE", w,  # type: ignore[arg-type]  # a value an earlier check or lookup ruled out as None; mypy cannot follow it
                f"{tid} is a {tc.get('kind')} test: the harness generated its oracle, there is nothing for a person to approve")  # type: ignore[union-attr]  # a value an earlier check or lookup ruled out as None; mypy cannot follow it
        if d.get("decision") == "accept":
            R.check(d.get("testcase_sha256") == derive.approval_hash(tc), "E-GATE-ORACLE", w,  # type: ignore[arg-type]  # a value an earlier check or lookup ruled out as None; mypy cannot follow it
                    f"the approval of {tid} pins {d.get('testcase_sha256')}, the testcase is {derive.approval_hash(tc)} (it changed: review it again)")  # type: ignore[arg-type]  # a value an earlier check or lookup ruled out as None; mypy cannot follow it


def gate_sod(R: Report, c: Ctx, rec: dict, w: str):
    """E1: a person approves a gate in at most one of its required roles (lite + acknowledged consolidation excepted)."""
    by_person: dict = {}
    for a in rec.get("approvers", []):
        by_person.setdefault(a.get("person_id"), set()).add(a.get("role"))
    for p, roles in by_person.items():
        if len(roles) > 1:
            R.check(p == consolidation_person(c), "E-GATE-SOD", w,
                    f"{p} approves {rec.get('gate')} in several roles {sorted(roles)} (only an acknowledged lite role_consolidation allows this)")


def g5_g4_link(R: Report, c: Ctx, rec: dict, w: str, job: dict | None, opened: dt.datetime):
    """v0.5 (BL-04, E-G5-G4): a G5 names the G4 that approved its job's testcase in this run: a G4 record of the same
    run, decided before the G5 opened, whose decision on that testcase is the latest one when the G5 opened and is accept; no person approves both
    (the separation of duties is checked against the actual G4 approvers, not only against run.initiators)."""
    ref = rec.get("g4_gate_record_id")
    g4 = c.record(ref) if ref else None
    if not R.check(g4 is not None and g4.get("gate") == "G4" and g4.get("run_id") == rec.get("run_id"), "E-G5-G4", w,
                   f"g4_gate_record_id {ref!r} must be a G4 record of run {rec.get('run_id')}"):
        return
    tcid = (job or {}).get("testcase_id")
    at = decision_time(c, g4) or ts(R, g4.get("timestamp"), w)  # type: ignore[arg-type,union-attr]  # a value an earlier check or lookup ruled out as None; mypy cannot follow it
    R.check(at is not None and at <= opened, "E-G5-G4", w, f"{ref} was decided after this G5 opened")
    # the latest G4 decision on the testcase when this G5 opened: a later G4 round does not undo a G5 already decided
    st = derive.g4_state(c.ix, rec.get("run_id"), tcid, at=opened)
    latest = (st.record_id, st.decision) if st.decision is not None else None
    R.check(latest == (ref, "accept"), "E-G5-G4", w,
            f"{ref} is not the latest G4 decision on {tcid} when this G5 opened, or does not accept it (latest: {latest})")
    both = {a.get("person_id") for a in rec.get("approvers", [])} & {a.get("person_id") for a in g4.get("approvers", [])}  # type: ignore[union-attr]  # a value an earlier check or lookup ruled out as None; mypy cannot follow it
    R.check(not both, "E-G5-G4", w, f"{sorted(both)} approved both the G4 {ref} and this G5")


CARRY_GATES = ("G1", "G3")


def carried_decisions(R: Report, c: Ctx, rec: dict, w: str):
    """v0.5 (BL-21, E-GATE-CARRY): an unchanged G1 / G3 item may carry an ancestor run's approval (decisions[].carried_from).
    Re-enabled with these checks, so "the hash is the same" is verified instead of assumed:
    - only G1 / G3, only an accept, only from an ancestor of this run (parent_run_id chain), same engagement;
    - the source record is a gate record of that run and gate, its decision on the same item is accept with the same
      item_sha256, which equals this decision's item_sha256;
    - the source record's signatures still verify with the loaded registry (no key revoked as compromised, still
      within validity at its decision time) and its approvers still hold the gate's roles;
    - G3: the source run's G0b verified the same ROE (document_ref) as this run's G0b.
    The carrying record itself is still signed by this run's approvers."""
    ancestors, cur = [], (c.runs.get(rec.get("run_id")) or {}).get("parent_run_id")
    while cur and cur not in ancestors:
        ancestors.append(cur)
        cur = (c.runs.get(cur) or {}).get("parent_run_id")
    for i, x in enumerate(rec.get("decisions") or []):
        cf = x.get("carried_from")
        if cf is None:
            continue
        where = f"{w} decisions[{i}] {x.get('item_id')}"
        if not R.check(rec.get("gate") in CARRY_GATES and x.get("decision") == "accept", "E-GATE-CARRY", where,
                       f"only G1 / G3 accept decisions carry an earlier approval (gate {rec.get('gate')}, decision {x.get('decision')})"):
            continue
        src = c.record(cf.get("gate_record_id"))
        ok = (src is not None and src.get("gate") == rec.get("gate") and src.get("run_id") == cf.get("run_id")
              and cf.get("run_id") in ancestors and src.get("engagement_id") == rec.get("engagement_id"))
        if not R.check(ok, "E-GATE-CARRY", where, f"carried_from {cf} must be a {rec.get('gate')} record of an ancestor run "
                       f"{ancestors} of the same engagement"):
            continue
        sx = next((y for y in src.get("decisions") or [] if y.get("item_id") == x.get("item_id")), None)
        R.check(sx is not None and sx.get("decision") == "accept" and sx.get("item_sha256") == cf.get("item_sha256") == x.get("item_sha256"),
                "E-GATE-CARRY", where, "the source decision must accept the same item with the same item_sha256 (the item changed: review it again)")
        at = decision_time(c, src) or ts(R, src.get("timestamp"), where)
        payload = signing_payload(src)
        approvers = {(a.get("person_id"), a.get("key_fingerprint")): a for a in src.get("approvers", [])}
        good = bool(src.get("signatures")) and all(
            (s.get("signer"), s.get("key_fingerprint")) in approvers and verify_signature(
                Report(), c, where, payload, s, at, approvers[(s.get("signer"), s.get("key_fingerprint"))].get("role")) is not None
            for s in src.get("signatures") or [])
        R.check(good, "E-GATE-CARRY", where, f"the source record {cf.get('gate_record_id')} no longer verifies (revoked or invalid signature, role lost)")
        if rec.get("gate") == "G3":
            def roe_ref(rid):
                g0b = [g.data for g in c.ix.gate_records(rid, "G0b")]
                return (g0b[-1].get("verification") or {}).get("document_ref") if g0b else None
            R.check(roe_ref(cf.get("run_id")) is not None and roe_ref(cf.get("run_id")) == roe_ref(rec.get("run_id")), "E-GATE-CARRY", where,
                    "a G3 approval carries only under the same ROE (the source run's G0b verified another document)")


def opened_time(R: Report, c: Ctx, rec: dict, w: str, declared: dt.datetime) -> dt.datetime:
    """v0.5 (review 2026-10-25 T-2): the receive time of the gate_opened event that opened `rec`: the last
    gate_opened of the same gate (and, for G5, the same job) before its gate_decision. The record's own opened_at
    must agree with it within MAX_CLOCK_SKEW (E-GATE-OPENED). G0a / G0b are system verifications with no opening
    event; a record without a gate_decision event is already E-AUDIT-GATE and keeps its declared time."""
    if rec.get("gate") in ("G0a", "G0b"):
        return declared
    audit = c.ix.audit_for(rec.get("run_id"))
    evs = [e for e in (audit.data if audit else []) if isinstance(e, dict)]
    pos = next((i for i, e in enumerate(evs) if e.get("event_type") == "gate_decision"
                and (e.get("payload") or {}).get("gate_record_id") == rec.get("gate_record_id")), None)
    if pos is None:
        return declared
    opens = [e for e in evs[:pos] if e.get("event_type") == "gate_opened" and (e.get("payload") or {}).get("gate") == rec.get("gate")
             and (rec.get("gate") != "G5" or (e.get("payload") or {}).get("job_id") == rec.get("job_id"))]
    got = ts(R, opens[-1].get("ts"), w, "gate_opened ts") if opens else None
    if not R.check(got is not None, "E-GATE-OPENED", w,
                   f"{rec.get('gate_record_id')}: no gate_opened event for {rec.get('gate')} before its gate_decision; "
                   "opened_at cannot be established by the Audit Writer"):
        return declared
    R.check(abs(declared - got) <= MAX_CLOCK_SKEW, "E-GATE-OPENED", w,  # type: ignore[operator]  # a value an earlier check or lookup ruled out as None; mypy cannot follow it
            f"opened_at {rec.get('opened_at')} differs from the gate_opened receive time {got.isoformat()} by more than {MAX_CLOCK_SKEW}")  # type: ignore[union-attr]  # a value an earlier check or lookup ruled out as None; mypy cannot follow it
    return got  # type: ignore[return-value]  # None was ruled out by the R.check above


GATE_MAX_ROUNDS = {"G1": 3, "G3": 3, "G4": 2}      # docs/02 §1.4; every other gate decides once


def g_gates(R: Report, c: Ctx):
    e, r = c.engagement, c.roe
    tmo = e.get("gate_timeouts_hours") or {}
    ev = e.get("validity") or {}
    enb, ena = ts(R, ev.get("not_before"), "engagement.yaml"), ts(R, ev.get("not_after"), "engagement.yaml")
    rv = r.get("validity") or {}
    rnb, rna = ts(R, rv.get("not_before"), "roe.yaml"), ts(R, rv.get("not_after"), "roe.yaml")
    roe_people = {(p.get("person_id"), p.get("key_fingerprint")) for p in (r.get("signatories") or []) + (r.get("gate_approvers") or [])}
    for d in c.docs("gate-record"):
        with doc_guard(R, d.path):
            rec, w = d.data, d.path
            gate = rec.get("gate")
            run = c.runs.get(rec.get("run_id"))
            if not R.check(run is not None, "E-GATE-RUN", w, f"run {rec.get('run_id')} not found"):
                continue
            R.check(isinstance(rec.get("artifact"), dict) and isinstance((rec.get("artifact") or {}).get("sha256"), str), "E-GATE-ARTIFACT", w,
                    "gate record needs artifact {kind, sha256} (what was approved)")
            R.check(rec.get("engagement_id") == e.get("engagement_id"), "E-GATE-RUN", w, "engagement_id mismatch")
            opened, at = ts(R, rec.get("opened_at"), w), ts(R, rec.get("timestamp"), w)
            if not (opened and at):
                continue
            # v0.5 (review 2026-10-25 T-2): opened_at sits inside the approver-signed record; the authority is the
            # Audit Writer's gate_opened event (timeouts, EXPIRED-EARLY and the G5 window are measured from it)
            opened = opened_time(R, c, rec, w, opened)
            # v0.4 (E4): the Audit Writer's receive time is the authority for every time rule of a decision;
            # the signer's own timestamp only has to agree with it within MAX_CLOCK_SKEW (E-AUDIT-GATE)
            at = decision_time(c, rec) or at
            R.check(opened <= at, "E-GATE-TIME", w, "opened_at after timestamp")
            R.check(enb and ena and enb <= at <= ena, "E-GATE-ENGAGEMENT", w, "decided outside the engagement validity")
            roles = {a.get("role") for a in rec.get("approvers", [])}
            if gate in GATE_ROLES:
                R.check(GATE_ROLES[gate] <= roles, "E-GATE-ROLES", w, f"missing roles {sorted(GATE_ROLES[gate] - roles)}")
            for a in rec.get("approvers", []):
                ent = c.by_fp.get(a.get("key_fingerprint"))
                R.check(ent is not None and ent.get("person_id") == a.get("person_id") and a.get("role") in ent.get("roles", []),
                        "E-GATE-APPROVER", w, f"approver {a.get('person_id')} / {a.get('role')} / key not registered together")
            if rec.get("initiator") is None:
                # review r11: only an automatic Lane A run has no initiator (nobody claims it, docs/02 §1.5)
                R.check(run.get("run_kind") == "lane_a", "E-GATE-INITIATOR", w, "initiator null is only allowed on a Lane A run")  # type: ignore[union-attr]  # a value an earlier check or lookup ruled out as None; mypy cannot follow it
            else:
                R.check(rec.get("initiator") in c.persons and rec.get("initiator") not in c.automation, "E-GATE-INITIATOR", w,
                        "initiator must be a registered person, not an automation account")
                R.check(rec.get("initiator") in run.get("initiators", []), "E-GATE-INITIATOR", w, "initiator is not a run initiator")  # type: ignore[union-attr]  # a value an earlier check or lookup ruled out as None; mypy cannot follow it
            if gate == "G0a":
                want = {(s.get("person_id"), s.get("role"), s.get("key_fingerprint")) for s in e.get("signatories") or []}
                got = {(a.get("person_id"), a.get("role"), a.get("key_fingerprint")) for a in rec.get("approvers", [])}
                R.check(want == got, "E-GATE-G0-APPROVERS", w, "G0a approvers must be the engagement signatories")
            if gate == "G0b":
                want = {(s.get("person_id"), s.get("role"), s.get("key_fingerprint")) for s in r.get("signatories") or []}
                got = {(a.get("person_id"), a.get("role"), a.get("key_fingerprint")) for a in rec.get("approvers", [])}
                R.check(want == got, "E-GATE-G0-APPROVERS", w, "G0b approvers must be the ROE signatories")
            # B8 (H-D2): white-box gates are approved from the engagement registry, black-box gates from the ROE
            if gate in ENGAGEMENT_GATES:
                allowed_eng = set(((e.get("gate_approvers") or {}).get(gate)) or [])
                for a in rec.get("approvers", []):
                    R.check(a.get("person_id") in allowed_eng, "E-GATE-APPROVER-ENG", w,
                            f"{gate} approver {a.get('person_id')} is not in engagement.yaml gate_approvers.{gate} {sorted(allowed_eng)}")
            if gate in ROE_GATES:
                for a in rec.get("approvers", []):
                    R.check((a.get("person_id"), a.get("key_fingerprint")) in roe_people, "E-GATE-ROE-APPROVER", w,
                            f"{gate} approver {a.get('person_id')} is not a ROE signatory or gate_approver")
                # G0b is the check that finds a not-yet-valid ROE and suspends the run (docs/02 §1.4), so its own
                # record may precede not_before; the gates decided by people (G3-G5) must fall inside the validity.
                if gate != "G0b":
                    R.check(rnb and rna and rnb <= at <= rna, "E-GATE-ROE-VALIDITY", w, f"{gate} decided outside the ROE validity")
            gate_sod(R, c, rec, w)
            # timeouts
            # v0.5 (review 2026-10-25 V-10): a key the engagement leaves out falls back to the toolkit maximum
            limit = tmo.get(gate) if tmo.get(gate) is not None else (c.toolkit.get("gate_timeouts_hours") or {}).get(gate)
            if limit is not None and gate != "G5":
                # third external review (r13): the timeout is the deadline of a HUMAN decision; the system's EXPIRED
                # record is written at or after it (below), and writing it late is a scheduling delay, not a forgery.
                # v0.5-r12 applied the deadline to EXPIRED too, so an honest EXPIRED one second after it was an error
                R.check(rec.get("outcome") == "EXPIRED" or at - opened <= dt.timedelta(hours=limit), "E-GATE-TIMEOUT", w,
                        f"decided {at - opened} after opening; timeout {limit} h")
                # v0.4: EXPIRED is the one unsigned outcome; it is only valid once the timeout has really elapsed by the
                # Audit Writer's clock. Otherwise a forged EXPIRED could skip G2 (the run continues past a timed-out G2).
                # v0.5: both ends of that interval are receive times (gate_opened and gate_decision events)
                if rec.get("outcome") == "EXPIRED":
                    R.check(at - opened >= dt.timedelta(hours=limit), "E-GATE-EXPIRED-EARLY", w,
                            f"EXPIRED {at - opened} after opening, before the {limit} h timeout elapsed")
            # outcome vs decisions
            decs = [x.get("decision") for x in rec.get("decisions", [])]
            # v0.5 (review r7 1.1): EXPIRED is the one unsigned outcome, so it may record only that nobody decided;
            # an accept / reject / over_cap in it would approve or reject without any signature
            if rec.get("outcome") == "EXPIRED":
                R.check(all(x == "needs_info" for x in decs), "E-GATE-OUTCOME", w,
                        f"an EXPIRED (unsigned) record may only carry needs_info decisions, not {sorted(set(decs) - {'needs_info'})}")
            if rec.get("outcome") == "PARTIALLY_APPROVED":
                R.check(gate in ("G3", "G4"), "E-GATE-OUTCOME", w, "PARTIALLY_APPROVED is only allowed at G3 and G4 (D2)")
            # v0.5 (review 2026-10-25 M-4): over_cap is a G3-only, rule-based rejection written by the Gate Service
            R.check(gate == "G3" or "over_cap" not in decs, "E-GATE-OUTCOME", w, "decision over_cap is only used at G3")
            # BL-60 (suspend variant): an EXPIRED G3 / G4 record carries only needs_info (above), so it implies no outcome
            if gate in ("G3", "G4") and decs and rec.get("outcome") != "EXPIRED":
                rej = [x for x in decs if x in ("reject", "over_cap")]
                want = "APPROVED" if all(x == "accept" for x in decs) else ("REJECTED" if len(rej) == len(decs) else "PARTIALLY_APPROVED")  # type: ignore[assignment]  # the name is reused with another type earlier in the function
                R.check(rec.get("outcome") == want, "E-GATE-OUTCOME", w, f"{gate} outcome {rec.get('outcome')} but decisions imply {want}")
            if gate == "G2":
                R.check(rec.get("outcome") in ("APPROVED", "EXPIRED"), "E-GATE-OUTCOME", w,
                        f"G2 whole-gate outcome must be APPROVED or EXPIRED (per-item REJECTED/NEEDS_INFO live in decisions), not {rec.get('outcome')}")
                # v0.7 (review r8 M3): in Lite the one person is not equipped to make a final rejection (R10 makes it final
                # against votes and SARIF, and Lite has no S2 proof to overturn it): a dispute stays visible in the report
                if profile(c) == "lite":
                    R.check("reject" not in decs, "E-GATE-OUTCOME", w,
                            "assurance_profile lite: G2 decides accept / needs_info only; a reject is final and needs a security reviewer (docs/02 §1.7)")
            if gate in ("G1", "G5") and rec.get("outcome") == "APPROVED":
                R.check(all(x == "accept" for x in decs), "E-GATE-OUTCOME", w, "APPROVED with non-accept decisions")
            if gate == "GB":
                gb = rec.get("gb") or {}
                if rec.get("outcome") == "EXPIRED":
                    # r14 (internal review A10; docs/02 §1.3, 03 §5.2 GB EXPIRED -> SUSPENDED): nobody chose, so the record
                    # carries no choice and no new caps; r12 mapped every choice to APPROVED / REJECTED, so the documented
                    # expiry path could not be written at all
                    R.check(gb.get("choice") is None and gb.get("new_caps") is None, "E-GATE-OUTCOME", w,
                            f"an EXPIRED GB record carries no choice and no new_caps (got {gb.get('choice')!r}): nobody decided")
                else:
                    ok_outcome = {"extend": "APPROVED", "stop_phase": "REJECTED", "abort": "APPROVED"}.get(gb.get("choice"))  # type: ignore[arg-type]  # a value an earlier check or lookup ruled out as None; mypy cannot follow it
                    R.check(rec.get("outcome") == ok_outcome, "E-GATE-OUTCOME", w, f"GB choice {gb.get('choice')} needs outcome {ok_outcome}")
                allowed = {e.get("budget_approver") or e.get("run_owner"), e.get("run_owner")}
                for a in rec.get("approvers", []):
                    R.check(a.get("person_id") in allowed, "E-GB-APPROVER", w, f"GB approver {a.get('person_id')} is neither run_owner nor budget_approver")
            # review r11: the redraft limits of docs/02 §1.4 were text only (G1 at most 3 rounds, G4 at most 2, the rest 1)
            lim_r = GATE_MAX_ROUNDS.get(gate, 1)
            R.check(isinstance(rec.get("round"), int) and 1 <= rec.get("round") <= lim_r, "E-GATE-ROUND", w,
                    f"{gate} round {rec.get('round')!r} exceeds the {lim_r}-round limit of docs/02 §1.4 (the run is ABORTED / the item rejected after it)")
            oracle_approval_problems(R, c, rec, w)
            if gate == "G4":
                for a in rec.get("approvers", []):
                    R.check(a.get("person_id") in run.get("initiators", []), "E-G4-INITIATOR", w,  # type: ignore[union-attr]  # a value an earlier check or lookup ruled out as None; mypy cannot follow it
                            f"G4 approver {a.get('person_id')} must be recorded as a run initiator")
            if gate == "G5":
                for a in rec.get("approvers", []):
                    R.check(a.get("person_id") not in run.get("initiators", []) and a.get("person_id") != rec.get("initiator"),  # type: ignore[union-attr]  # a value an earlier check or lookup ruled out as None; mypy cannot follow it
                            "E-G5-INITIATOR", w, f"G5 approver {a.get('person_id')} must not be a run initiator")
                escalated = g5_escalation(c, rec.get("run_id"))
                if profile(c) == "full" or escalated:
                    revs = {a.get("person_id") for a in rec.get("approvers", []) if a.get("role") == "security_reviewer"}
                    why = f"spot check {escalated} overturned a G5 decision of an earlier run" if escalated else "assurance_profile full"
                    R.check(len(revs) >= 2, "E-G5-TWO-PERSON", w, f"{why}: G5 needs two distinct security_reviewer approvers, got {sorted(revs)}")
                win_end = timeutil.window_end(opened, roe_windows(c))
                R.check(win_end is not None, "E-G5-WINDOW", w, "G5 opened outside every ROE time window")
                R.check(timeutil.in_any_window(at, roe_windows(c)), "E-G5-WINDOW", w, "G5 decided outside every ROE time window")
                if win_end is not None:
                    lim = min(win_end, opened + dt.timedelta(hours=limit if limit is not None else 24))
                    R.check(at < lim, "E-G5-WINDOW", w, f"G5 decided at/after the window end {win_end.isoformat()}")
                job = (run.get("jobs") or {}).get(rec.get("job_id"))  # type: ignore[union-attr]  # a value an earlier check or lookup ruled out as None; mypy cannot follow it
                R.check(job is not None and job.get("safety_class") == "S2", "E-G5-JOB", w, "G5 must reference an S2 job of the run")
                g5_g4_link(R, c, rec, w, job, opened)
            else:
                R.check(rec.get("job_id") is None, "E-GATE-JOB", w, "job_id is only used by G5")
                R.check(rec.get("g4_gate_record_id") is None, "E-G5-G4", w, "g4_gate_record_id is only used by G5")
            carried_decisions(R, c, rec, w)
            # threats vs G3 decisions
            if gate == "G3":
                for x in rec.get("decisions", []):
                    t = c.ix.first("threat", threat_id=x.get("item_id"))
                    if R.check(t is not None, "E-TRACE", w, f"threat {x.get('item_id')} not found"):
                        want = {"accept": "ACCEPTED", "reject": "REJECTED", "over_cap": "REJECTED"}.get(x.get("decision"), "NEEDS_INFO")  # type: ignore[assignment]  # the name is reused with another type earlier in the function
                        if x.get("decision") == "over_cap":
                            # the queue cap never applies to high-risk threats (attack tree) or impact high (docs/02 B2)
                            R.check(not t.data.get("attack_tree_ref") and (t.data.get("risk") or {}).get("impact") != "high",  # type: ignore[union-attr]  # a value an earlier check or lookup ruled out as None; mypy cannot follow it
                                    "E-GATE-OVER-CAP", w, f"{x.get('item_id')} is high-risk or impact high: it is never over the G3 cap")
                        rv_ = t.data.get("review") or {}  # type: ignore[union-attr]  # a value an earlier check or lookup ruled out as None; mypy cannot follow it
                        # v0.7 (review r8 H3): a carried accept re-signs an ancestor's review; the threat's review names the
                        # record that reviewed it (the carried_from source), not the carrying record
                        owner = (x.get("carried_from") or {}).get("gate_record_id") or rec.get("gate_record_id")
                        R.check(rv_.get("status") == want and rv_.get("gate_record_id") == owner, "E-TRACE-THREAT-REVIEW",
                                t.path, f"review must be {want} by {owner}")  # type: ignore[union-attr]  # a value an earlier check or lookup ruled out as None; mypy cannot follow it
            if gate == "G1":
                for inv in c.invariants.get("invariants", []):
                    so = inv.get("signoff") or {}
                    dec = next((x for x in rec.get("decisions", []) if x.get("item_id") == inv.get("requirement_id")), None)
                    # v0.7 (review r9): a carried G1 accept re-signs an ancestor's signoff, which names the source record
                    owner = ((dec or {}).get("carried_from") or {}).get("gate_record_id") or rec.get("gate_record_id")
                    R.check(dec is not None and so.get("gate_record_id") == owner
                            and so.get("status") == {"accept": "ACCEPTED", "reject": "REJECTED"}.get(dec.get("decision")),
                            "E-TRACE-INVARIANT", "invariants.yaml", f"{inv.get('requirement_id')}: signoff does not match {owner}")


def g5_escalation(c: Ctx, run_id) -> str | None:
    """v0.6 (review r7 4.5, docs/06 §1.1 ASI09): the seq of an anchored spot_check_result that overturned a G5 decision
    (payload item_kind g5, outcome overturned) in another run of the same engagement, received before this run started,
    or None. From then on the engagement runs G5 as in Full: two distinct security reviewers. v0.5 only wrote the rule."""
    run = c.runs.get(run_id) or {}
    start = run_start(c, run_id)
    for a in c.ix.audit_docs():
        rid = a.data[0].get("run_id") if a.data and isinstance(a.data[0], dict) else None
        if rid == run_id or (c.runs.get(rid) or {}).get("engagement_id") != run.get("engagement_id"):
            continue
        last_anchor = max((i + 1 for i, e in enumerate(a.data) if isinstance(e, dict) and e.get("event_type") == "audit_anchor"), default=0)
        for e in a.data:
            p = (e.get("payload") or {}) if isinstance(e, dict) else {}
            if isinstance(e, dict) and e.get("event_type") == "spot_check_result" and p.get("item_kind") == "g5" \
                    and p.get("outcome") == "overturned" and type(e.get("seq")) is int and e.get("seq") < last_anchor:  # type: ignore[operator]  # a value an earlier check or lookup ruled out as None; mypy cannot follow it
                at = timeutil.parse_dt(e["ts"]) if isinstance(e.get("ts"), str) else None
                if start is not None and at is not None and at < start:
                    return f"{rid}#{e.get('seq')}"
    return None


def run_start(c: Ctx, run_id) -> dt.datetime | None:
    """The receive time of the first event of a run's audit log (run_created)."""
    a = c.ix.audit_for(run_id)
    first = a.data[0] if a and a.data and isinstance(a.data[0], dict) else None
    return timeutil.parse_dt(first["ts"]) if first and isinstance(first.get("ts"), str) else None
