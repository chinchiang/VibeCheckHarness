# SPDX-License-Identifier: Apache-2.0
"""Review round 7 (docs/evidence/review-2026-10-25-r7.md), group 1: validator bypasses. Each test reproduced its
bypass on cec8fb8 (it failed there) and passes with the fix; see CONTRIBUTING.md.

1.1  an EXPIRED (unsigned) gate record carries only needs_info, and approves / rejects nothing;
1.2  B4 / S2 execution times come from the Audit Writer's sandbox_job_* receive times;
1.3  a W4 testcase covers only clusters in the files it tests;
1.4  {created:x} in object_refs is bound to x's created_resource paths;
1.5  read_only_endpoints may not name an endpoint W0 found writing;
1.6  a finding is a member of one cluster per run;
1.7  the rules use the score the validator derives, not the verdict's own;
1.8  a collection PATCH / PUT / DELETE selects rows by the query only (external review 1);
1.9  Server Action refs must resolve and arguments compare with JSON types (external review 4);
1.10 sandbox_job_end pins the testcase, artifact and result hashes (external review 2);
1.11 feedback is verified at the Audit Writer's receive time of its feedback_recorded event (external review 3);
5    one malformed document does not hide another document's errors in the same check group.
"""
import copy

import pytest

from conftest import doc, rederive
from vchlib import checks, crypto, derive, safety
from vchlib.bundle import Doc
from vchlib.checks import Ctx, run_all

RUN = "run-2026-09-23-001"
AUDIT = "audit-event.run-2026-09-23-001.example.jsonl"
FAUDIT = "audit-event.run-2026-10-07-001.example.jsonl"


def errors(b, code, where=None):
    return [i for i in run_all(b).errors if i.code == code and (where is None or where in i.where)]


def move_event(b, pred, ts, audit=AUDIT):
    """Give the matching audit event a new receive time and keep the log in time order (seq renumbered)."""
    evs = doc(b, audit).data
    e = next(x for x in evs if pred(x))
    e["ts"] = ts
    evs.sort(key=lambda x: derive.timeutil.sort_key(x["ts"]))
    for n, x in enumerate(evs, 1):
        x["seq"] = n
    return e


def job_event(kind, job):
    return lambda e: e["event_type"] == kind and (e.get("payload") or {}).get("job_id") == job


# ================================================================ 1.1 EXPIRED records
def test_an_expired_record_carries_no_decision_but_needs_info(b):
    doc(b, "gate-record.g1.example.json").data["outcome"] = "EXPIRED"
    assert any("EXPIRED" in i.msg and "needs_info" in i.msg for i in errors(b, "E-GATE-OUTCOME", "g1.example"))


def test_an_expired_g1_approves_nothing(b):
    doc(b, "gate-record.g1.example.json").data["outcome"] = "EXPIRED"
    assert derive.Index(b).approved_requirement_ids() == set()


def test_an_expired_g2_rejects_nothing(b):
    g2 = doc(b, "gate-record.g2.example.json").data
    g2["outcome"] = "EXPIRED"
    g2["decisions"][0]["decision"] = "reject"
    c = Ctx(b)
    assert checks.g2_latest(c, c.ix.first("cluster", cluster_id="K-011").data) == (None, None)


def test_an_expired_g4_approves_no_testcase(b):
    doc(b, "gate-record.g4.example.json").data["outcome"] = "EXPIRED"
    assert not derive.g4_approved(derive.Index(b), doc(b, "testresult.example.json").data)


# ================================================================ 1.2 B4 / S2 times from the audit log
def test_executed_at_lies_inside_its_job(b):
    doc(b, "testresult.example.json").data["executed_at"] = "2026-10-05T20:50:00+08:00"   # job-idor-001 ended 20:40
    assert any("outside its job" in i.msg for i in errors(b, "E-JOB-AUDIT"))


def test_a_b4_job_starts_after_its_g4_decision(b, keys):
    move_event(b, job_event("sandbox_job_start", "job-idor-001"), "2026-10-03T10:30:00+08:00")   # G4 decided 10-03 11:00
    rederive(b, keys)
    assert any("sandbox_job_start" in i.msg for i in errors(b, "E-RESULT-G4"))


def test_an_s2_job_starts_after_its_g5_decision(b, keys):
    move_event(b, job_event("sandbox_job_start", "job-zap-active-001"), "2026-10-05T21:40:00+08:00")   # G5 decided 21:50
    rederive(b, keys)
    assert any("sandbox_job_start" in i.msg for i in errors(b, "E-RESULT-G5"))


def test_a_job_ends_inside_the_roe_window(b, keys):
    move_event(b, job_event("sandbox_job_end", "job-zap-active-001"), "2026-10-05T23:30:00+08:00")
    rederive(b, keys)
    assert any("sandbox_job" in i.msg for i in errors(b, "E-RESULT-WINDOW"))


def test_a_b5_verdict_is_received_after_the_job_ends(b, keys):
    move_event(b, job_event("sandbox_job_end", "job-idor-001"), "2026-10-06T10:30:00+08:00")   # V-005-2 received 10:00
    rederive(b, keys)
    assert any("before" in i.msg and "job-idor-001" in i.msg for i in errors(b, "E-VERDICT-PHASE"))


def test_approved_testcase_ids_follow_the_latest_decision_per_testcase(b):
    g4 = doc(b, "gate-record.g4.example.json")
    second = copy.deepcopy(g4)
    second.path = second.path.replace("g4.example", "g4-round2.example")
    second.data.update(gate_record_id="GR-G4-0002", round=2)
    second.data["decisions"] = [dict(second.data["decisions"][0], item_id="TC-012-01")]   # re-decides one testcase
    b.docs.append(second)
    assert not [i for i in errors(b, "E-RUN-G4") if "approved_testcase_ids" in i.msg]


def test_a_later_reject_withdraws_the_approval(b):
    g4 = doc(b, "gate-record.g4.example.json")
    second = copy.deepcopy(g4)
    second.path = second.path.replace("g4.example", "g4-round2.example")
    second.data.update(gate_record_id="GR-G4-0002", round=2)
    second.data["decisions"] = [dict(second.data["decisions"][0], item_id="TC-012-01", decision="reject")]
    b.docs.append(second)
    assert any("approved_testcase_ids" in i.msg for i in errors(b, "E-RUN-G4"))


# ================================================================ 1.3 W4 cluster binding
def test_a_w4_test_covers_only_clusters_in_its_files(b):
    doc(b, "w4-testcase.k-015.example.json").data["cluster_ids"].append("K-016")     # routes/invoices.ts, not a migration
    assert any("K-016" in i.msg and "routes/invoices.ts" in i.msg for i in errors(b, "E-W4-TC", "w4-testcase"))


def test_non_rls_w4_tests_declare_their_target_files(b):
    tc = doc(b, "w4-testcase.k-015.example.json").data
    tc.update(kind="unit", target_files=[])
    tc["environment"]["database"] = None
    assert any("target_files" in i.msg for i in errors(b, "E-W4-TC", "w4-testcase"))


# ================================================================ 1.4 {created:} in object_refs
def test_a_created_ref_in_object_refs_is_bound_to_its_paths(b):
    tc = doc(b, "testcase.llm.example.json").data
    tc["request_allowlist"].append({"target_id": "tgt-staging-app", "method": "PATCH", "path": "/api/admin/settings",
                                    "object_refs": ["{created:open_session}"]})
    probs = safety.object_ref_problems(tc["request_allowlist"][-1], doc(b, "seed-manifest.yaml").data,
                                       {"open_session": tc["request_allowlist"][0]})
    assert any("created_resource" in p for p in probs), probs


# ================================================================ 1.5 read_only_endpoints vs W0 writes
def test_a_writing_endpoint_is_not_read_only(b):
    doc(b, "seed-manifest.yaml").data["read_only_endpoints"].append(
        {"target_id": "tgt-staging-api", "method": "POST", "path_template": "/api/chat/sessions/{session}/messages"})
    assert any("read_only_endpoints" in i.msg for i in errors(b, "E-SEED-SIDE-EFFECT"))


# ================================================================ 1.6 one cluster per finding
def test_a_finding_belongs_to_one_cluster(b):
    doc(b, "cluster.k-015.example.json").data["member_finding_ids"].append("F-017")    # a member of K-005
    assert any("F-017" in i.msg for i in errors(b, "E-CLUSTER-BINDING"))


# ================================================================ 1.7 derived score
def test_the_rules_use_the_derived_score(b):
    v = doc(b, "verdict.k-014-w3.example.json").data
    c = Ctx(b)
    cl = c.ix.first("cluster", cluster_id="K-014").data
    derived = checks.verdict_inputs(c, v, cl).score
    v["score"] = round(derived + 0.0004, 4)                       # inside the 5e-4 tolerance of E-DERIVED
    assert checks.verdict_inputs(Ctx(b), v, cl).score == derived


# ================================================================ 1.8 PostgREST collection writes (external 1)
OK = {"inv-a-0001"}


@pytest.mark.parametrize("method", ["PATCH", "PUT", "DELETE"])
def test_a_collection_write_selects_by_query_only(method):
    got = safety.request_binding_problem({}, {"invoice_id": "inv-a-0001", "amount": 0}, OK, True, method=method)
    assert got is not None and "selects" in got, got


def test_a_collection_write_with_a_bound_filter_passes():
    assert safety.request_binding_problem({"id": "eq.inv-a-0001"}, {"amount": 0}, OK, True, method="PATCH") is None


def test_body_ids_must_still_be_bound_values():
    got = safety.request_binding_problem({"id": "eq.inv-a-0001"}, {"tenant_id": "t-b"}, OK, True, method="PATCH")
    assert got is not None and "tenant_id" in got


def test_an_rpc_post_may_bind_by_body():
    assert safety.request_binding_problem({}, {"invoice_id": "inv-a-0001"}, OK, True, method="POST") is None


# ================================================================ 1.9 Server Actions (external 4)
SPEC = {"action_id": "a1", "args": ["{seed:u2_order}", True, 1.0]}


def test_an_unresolved_ref_is_rejected():
    got = safety.server_action_problem({"Next-Action": "a1"}, [None, True, 1.0], SPEC, {})
    assert got is not None and "unresolved" in got


@pytest.mark.parametrize("body", [["ord-u2", 1, 1.0], ["ord-u2", True, 1], ["ord-u2", True, True]])
def test_arguments_compare_with_json_types(body):
    assert safety.server_action_problem({"Next-Action": "a1"}, body, SPEC, {"{seed:u2_order}": "ord-u2"}) is not None


def test_exact_arguments_still_pass():
    assert safety.server_action_problem({"Next-Action": "a1"}, ["ord-u2", True, 1.0], SPEC, {"{seed:u2_order}": "ord-u2"}) is None


# ================================================================ 1.10 execution content pinned (external 2)
def _derive_without_audit(b, keys):
    """A forger without the Z3 key: re-derive every unsigned document, but leave the audit log as Z3 anchored it."""
    saved = {d.path: copy.deepcopy(d.data) for d in b.docs if d.kind == "audit-event"}
    rederive(b, keys)
    for d in b.docs:
        if d.path in saved:
            d.data[:] = saved[d.path]


def test_a_swapped_w4_artifact_breaks_the_pin(b, keys):
    doc(b, "w4-testcase.k-015.example.json").data["artifact_sha256"] = "sha256:" + "ab" * 32
    _derive_without_audit(b, keys)
    assert any("artifact_sha256" in i.msg for i in errors(b, "E-W4-AUDIT"))


def test_a_swapped_b4_result_breaks_the_pin(b, keys):
    doc(b, "testresult.example.json").data["oracle_observations"].append("edited after the run")
    _derive_without_audit(b, keys)
    assert any("result_sha256" in i.msg for i in errors(b, "E-JOB-AUDIT"))


def test_the_pins_are_in_the_example_log(b):
    end = next(e for e in doc(b, AUDIT).data if job_event("sandbox_job_end", "job-idor-001")(e))
    assert {"testcase_sha256", "artifact_sha256", "result_sha256"} <= set(end["payload"])


# ================================================================ 1.11 feedback time (external 3)
FB = "feedback.k-016.example.json"


def test_feedback_is_recorded_by_the_adopting_run(b):
    evs = doc(b, FAUDIT).data
    assert any(e["event_type"] == "feedback_recorded" and e["payload"]["feedback_id"] == "FB-001" for e in evs)
    assert not errors(b, "E-FEEDBACK")
    evs[:] = [e for e in evs if e["event_type"] != "feedback_recorded"]
    assert any("feedback_recorded" in i.msg for i in errors(b, "E-FEEDBACK"))


def test_a_backdated_signature_with_a_retired_key_fails(b, keys):
    """erin's old key was retired 2026-09-15; back-dating signed_at before that no longer helps."""
    reg = doc(b, "key-registry.yaml").data
    old = next(e for e in reg["entries"] if e["person_id"] == "erin" and e.get("revoked_at"))
    f = doc(b, FB).data
    f["signed_by"] = {"person_id": "erin", "role": "security_reviewer", "key_fingerprint": old["fingerprint"]}
    f["signed_at"] = "2026-09-01T09:00:00+08:00"
    f["signatures"] = [crypto.sign_document(f, "erin", keys["erin_old"])]
    found = {i.code for i in run_all(b).errors if "feedback" in i.where}
    assert {"E-SIG-REVOKED", "E-FEEDBACK"} & found, found


def test_the_recorded_hash_binds_the_feedback(b):
    doc(b, FB).data["reason"] += "（改過）"                    # signature and record now disagree
    assert any("feedback_sha256" in i.msg for i in errors(b, "E-FEEDBACK"))


# ================================================================ 5 robustness
def test_one_bad_document_does_not_hide_another_in_derivations(b):
    doc(b, "testcase.idor.example.json").data["trials"]["n"] = "x"
    doc(b, "verdict.k-014-w3.example.json").data["score"] = 0.9
    assert any("verdict.k-014" in i.where for i in errors(b, "E-DERIVED"))


def test_one_bad_document_does_not_hide_another_in_traceability(b):
    doc(b, "inventory.example.json").data["endpoints"].append(None)
    doc(b, "testresult.example.json").data["cluster_ids"].append("K-999")
    assert errors(b, "E-TRACE", "testresult.example")


# ================================================================ guards for single sub-checks (mutation sweep)
def test_a_result_executes_after_the_latest_g4_decision(b):
    move_event(b, lambda e: e["event_type"] == "gate_decision" and e["node"] == "G4", "2026-10-05T20:31:00+08:00")
    assert any("executed before G4 approval" in i.msg for i in errors(b, "E-RESULT-G4", "testresult.example"))


def test_the_feedback_event_must_be_anchored(b):
    move_event(b, lambda e: e["event_type"] == "feedback_recorded", "2026-10-07T23:00:00+08:00", FAUDIT)
    assert any("unanchored" in i.msg for i in errors(b, "E-FEEDBACK"))


def test_signed_at_stays_near_the_receive_time(b):
    doc(b, FB).data["signed_at"] = "2026-10-07T10:20:00+08:00"
    assert any("differs from the receive time" in i.msg for i in errors(b, "E-FEEDBACK"))


def test_feedback_is_not_recorded_before_its_run_started(b):
    doc(b, AUDIT).data[0]["ts"] = "2026-10-08T00:00:00+08:00"          # the run now 'starts' after the record
    assert any("before run" in i.msg for i in errors(b, "E-FEEDBACK"))


def test_target_files_are_inventory_files(b):
    doc(b, "w4-testcase.k-015.example.json").data["target_files"] = ["src/made_up.ts"]
    assert any("made_up" in i.msg for i in errors(b, "E-W4-TC", "w4-testcase"))


def test_one_bad_inventory_does_not_hide_another(b):
    good = doc(b, "inventory.example.json")
    bad = copy.deepcopy(good)
    bad.path = bad.path.replace("inventory.example", "inventory.broken.example")
    bad.data["endpoints"] = [None]
    b.docs.insert(b.docs.index(good), bad)                                # checked first
    good.data["endpoints"][0]["middleware_refs"] = ["mw-made-up"]
    assert any("mw-made-up" in i.msg for i in errors(b, "E-INVENTORY", "inventory.example"))
