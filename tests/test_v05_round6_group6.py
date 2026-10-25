# SPDX-License-Identifier: Apache-2.0
"""v0.5 round 6, extra group (docs/evidence/review-2026-10-25.md §4.2 V-4, V-5, V-8, V-9, V-12): the validator
bypasses no earlier group took. Positive and negative cases:

- V-4: the versions of a cluster form one linear chain (E-VERDICT-CHAIN);
- V-5: an ID names one document (E-ID-DUP);
- V-8: a white-box cluster's location and bucket are bound to its members' evidence (E-CLUSTER-BINDING);
- V-9: B4 jobs, sandbox_job_* events and testresults agree (E-JOB-AUDIT);
- V-12: readjudicated_by cannot be back-dated (E-VERDICT-PHASE).
"""
import copy

from conftest import codes, doc
from vchlib.checks import run_all

AUDIT = "audit-event.run-2026-09-23-001.example.jsonl"


def errors(b, code, where=None):
    return [i for i in run_all(b).errors if i.code == code and (where is None or where in i.where)]


def clone(b, suffix, new_name):
    d = copy.deepcopy(doc(b, suffix))
    d.path = d.path.replace(suffix, new_name)
    b.docs.append(d)
    return d


def test_examples_pass(b):
    found = codes(b)
    for code in ("E-VERDICT-CHAIN", "E-ID-DUP", "E-CLUSTER-BINDING", "E-JOB-AUDIT", "E-VERDICT-PHASE"):
        assert code not in found, code


# ================================================================ V-4 version chain
def test_self_supersede(b):
    v = doc(b, "verdict.k-011-b5.example.json").data
    v["supersedes_verdict_id"] = v["verdict_id"]
    assert any("supersedes itself" in i.msg for i in errors(b, "E-VERDICT-CHAIN"))


def test_supersede_cycle(b):
    doc(b, "verdict.k-011-w3.example.json").data["supersedes_verdict_id"] = "V-011-2"
    got = errors(b, "E-VERDICT-CHAIN")
    assert any("cycle" in i.msg for i in got) and any("exactly one latest" in i.msg for i in got)


def test_supersede_fork(b):
    d = clone(b, "verdict.k-011-b5.example.json", "verdict.k-011-b5-fork.example.json")
    d.data["verdict_id"] = "V-011-3"                               # also supersedes V-011-1
    got = errors(b, "E-VERDICT-CHAIN")
    assert any("forks" in i.msg for i in got) and any("exactly one latest" in i.msg for i in got)


# ================================================================ V-5 IDs
def test_duplicate_run_id(b):
    clone(b, "run.example.json", "run.copy.example.json")
    assert any("run_id" in i.msg for i in errors(b, "E-ID-DUP"))


def test_duplicate_verdict_id(b):
    clone(b, "verdict.k-014-w3.example.json", "verdict.k-014-copy.example.json")
    assert any("V-014-1" in i.msg for i in errors(b, "E-ID-DUP"))


def test_runs_lookup_takes_the_first_document(b):
    from vchlib.checks import Ctx
    d = clone(b, "run.example.json", "run.copy.example.json")
    d.data["status"] = "FAILED"
    c = Ctx(b)
    assert c.runs["run-2026-09-23-001"] is c.ix.first("run", run_id="run-2026-09-23-001").data


# ================================================================ V-8 cluster binding
def test_borrowed_location_is_rejected(b):
    k014 = doc(b, "cluster.k-014.example.json").data
    doc(b, "cluster.k-011.example.json").data["canonical_location"] = copy.deepcopy(k014["canonical_location"])
    assert any("K-011" in i.msg and "member evidence file" in i.msg for i in errors(b, "E-CLUSTER-BINDING"))


def test_sink_outside_the_evidence(b):
    doc(b, "cluster.k-014.example.json").data["canonical_location"]["sink"]["line"] = 99
    assert any("outside every member evidence range" in i.msg for i in errors(b, "E-CLUSTER-BINDING"))


def test_symbol_of_another_file(b):
    doc(b, "cluster.k-014.example.json").data["canonical_location"]["symbol"] = "routes/exports.ts::getExport"
    assert any("symbol" in i.msg for i in errors(b, "E-CLUSTER-BINDING"))


def test_bucket_not_of_a_member_cwe(b):
    doc(b, "cluster.k-014.example.json").data["cwe_bucket"] = "llm_specific"
    assert any("cwe_bucket" in i.msg for i in errors(b, "E-CLUSTER-BINDING"))


def test_member_with_two_buckets_may_use_either(b):
    # K-011's member F-044 carries CWE-1427 (llm_specific) and CWE-862 (authz)
    assert not [i for i in errors(b, "E-CLUSTER-BINDING") if "K-011" in i.msg]


def test_inventory_fact_cluster_is_bound_through_the_inventory_source(b):
    assert not [i for i in errors(b, "E-CLUSTER-BINDING") if "K-015" in i.msg]
    doc(b, "cluster.k-015.example.json").data["canonical_location"]["sink"]["line"] = 40
    assert any("K-015" in i.msg for i in errors(b, "E-CLUSTER-BINDING"))


def test_shared_fingerprint(b):
    fp = doc(b, "cluster.k-014.example.json").data["fingerprint"]
    doc(b, "cluster.k-011.example.json").data["fingerprint"] = fp
    assert any("fingerprint shared" in i.msg for i in errors(b, "E-CLUSTER-BINDING"))


# ================================================================ V-9 jobs vs audit
def test_deleted_fail_result_with_skipped_job(b):
    b.docs[:] = [d for d in b.docs if not d.path.endswith("testresult.example.json")]
    job = doc(b, "run.example.json").data["jobs"]["job-idor-001"]
    job["status"], job["skip_reason"] = "SKIPPED", "stopped"
    assert any("job-idor-001" in i.msg and "SKIPPED" in i.msg for i in errors(b, "E-JOB-AUDIT"))


def test_deleted_result_of_an_executed_job(b):
    b.docs[:] = [d for d in b.docs if not d.path.endswith("testresult.example.json")]
    assert any("no testresult" in i.msg for i in errors(b, "E-JOB-AUDIT"))


def test_outcome_differs_from_the_job_end_event(b):
    ev = next(e for e in doc(b, AUDIT).data if e["event_type"] == "sandbox_job_end" and e["payload"]["job_id"] == "job-idor-001")
    ev["payload"]["outcome"] = "PASS"
    assert any("outcome" in i.msg for i in errors(b, "E-JOB-AUDIT"))


# ================================================================ V-12 verdict phase
def test_black_box_verdict_cannot_be_w3(b):
    doc(b, "verdict.k-201-b5.example.json").data["readjudicated_by"] = "W3_adjudicate"
    assert any("black-box" in i.msg for i in errors(b, "E-VERDICT-PHASE"))


def test_b5_version_cannot_be_relabelled_w3(b):
    doc(b, "verdict.k-011-b5.example.json").data["readjudicated_by"] = "W3_adjudicate"
    got = [i.msg for i in errors(b, "E-VERDICT-PHASE")]
    assert any("supersedes nothing" in m for m in got) and any("must be at least B5_readjudicate" in m for m in got)


def test_version_after_b4_results_cannot_be_w4(b):
    doc(b, "verdict.executable.example.json").data["readjudicated_by"] = "W4_readjudicate"
    assert any("must be at least B5_readjudicate" in i.msg for i in errors(b, "E-VERDICT-PHASE"))


def test_phase_cannot_go_backwards(b):
    doc(b, "verdict.k-011-w3.example.json").data["readjudicated_by"] = "B5_readjudicate"
    doc(b, "verdict.k-011-b5.example.json").data["readjudicated_by"] = "W4_readjudicate"
    assert any("later-phase" in i.msg for i in errors(b, "E-VERDICT-PHASE"))
