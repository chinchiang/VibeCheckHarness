# SPDX-License-Identifier: Apache-2.0
"""Derived values of the example bundle (moved out of derive.py; architecture refactor PR-A, no behaviour change).

Every hash, weight or copied field that is a pure function of other files is listed here as
an Expectation (file, json path, expected value, why). The validator compares each one with
the file (error E-DERIVED); tools/sign_examples.py writes them back until nothing changes.
Signatures and the audit hash chain are handled by checks.py / sign_examples.py, because
they need keys or raw lines. The domain predicates these values are computed from stay in derive.py.
"""
from __future__ import annotations

import contextlib
from dataclasses import dataclass
from typing import Any

from . import timeutil
from .bundle import Bundle, Doc, read_jsonl_lines
from .canonical import approval_hash, content_hash, jcs, set_digest, sha256_hex, sha256_ref, text_hash
from .derive import (CONFIG_KINDS, Index, MISSING, _equal, artifact_sha, classify_result, cluster_fingerprint,
    derived_score, execution_pins, gate_artifact, gate_record_sha256, get_path, is_probabilistic, item_hash,
    job_end_of, linked_results, positive_control_value, reachability_reached, rubric_severity, slice_identity,
    strongest, tool_results_ref, vote_terms, w4_became_disputed_clusters)


@dataclass
class Expectation:
    file: str
    path: tuple
    expected: Any
    why: str


def expectations(b: Bundle, for_writer: bool = False, problems: list | None = None) -> list[Expectation]:
    """Derived values. for_writer=True adds values that only the writer (sign_examples) fills in
    and that the reader checks with dedicated rules instead (run.audit_anchors).
    v0.5 (review r7, group 5): each document is derived on its own; a document whose values break a derivation is
    appended to `problems` as (path, exception) and the other documents are still derived."""
    ix = Index(b)
    out: list[Expectation] = []

    @contextlib.contextmanager
    def guard(d):
        try:
            yield
        except Exception as exc:  # noqa: BLE001 - reported as E-INTERNAL for this document by checks.g_derived
            if problems is None:
                raise
            problems.append((d.path, exc))

    def exp(doc: Doc, path, value, why):
        if value is MISSING:
            return
        out.append(Expectation(doc.path, tuple(path), value, why))

    # slices (E6: the identity covers the files, the redaction map and the prompt template)
    slice_by_run: dict[str, list[str]] = {}
    for d in ix.docs("slice"):
        with guard(d):
            rm = ix.first("redaction-map", run_id=d.data.get("run_id"))
            if rm:
                exp(d, ["redaction_map_sha256"], content_hash(rm.data), "content hash of the run's redaction map")
            rm_sha = content_hash(rm.data) if rm else d.data.get("redaction_map_sha256")
            sid = slice_identity(d.data.get("files", []), rm_sha, d.data.get("prompt_template_sha256"))
            exp(d, ["slice_id"], sid, "sha256(JCS({files, redaction_map_sha256, prompt_template_sha256}))")
            slice_by_run.setdefault(d.data.get("run_id"), []).append(sid)

    # findings
    for d in ix.docs("finding"):
        with guard(d):
            for i, e in enumerate(d.data.get("evidence", [])):
                if isinstance(e.get("snippet"), str):
                    exp(d, ["evidence", i, "snippet_sha256"], text_hash(e["snippet"]), "sha256(snippet UTF-8)")
            sl = slice_by_run.get(d.data.get("run_id"), [])
            if len(sl) == 1:
                exp(d, ["slice_id"], sl[0], "the slice of the same run")

    # v0.7 (review r9 members): a cluster pins its member findings and a verdict pins its cluster, so the anchored
    # verdict_changed (verdict_sha256) covers the findings it adjudicated. v0.6 let anyone with Z1 write access edit a
    # member finding after the verdict and re-derive the unsigned fields without any error
    for d in ix.docs("cluster"):
        with guard(d):
            shas = []
            for fid in d.data.get("member_finding_ids") or []:
                f = ix.first("finding", finding_id=fid)
                shas.append(content_hash(f.data) if f else None)
            exp(d, ["member_finding_sha256"], shas, "content hash of each member finding (member_finding_ids order)")
    for d in ix.docs("verdict"):
        with guard(d):
            cl = ix.first("cluster", cluster_id=d.data.get("cluster_id"))
            if cl:
                exp(d, ["cluster_sha256"], content_hash(cl.data), "content hash of the cluster the verdict adjudicates")

    if for_writer:
        # v0.7 (review r9 rollback, seed, commit): values only the writer fills in; the reader checks them with dedicated
        # codes (E-AUDIT-ANCHOR-GAP, E-AUDIT-ARTIFACT, E-RUN-COMMIT). The Z3 executor numbers every anchor it
        # countersigns, engagement-wide and in receive order, so a run cut back to an earlier anchor leaves a gap
        anchors = sorted(((timeutil.sort_key(e.get("ts")), str(e.get("run_id")), i, a) for a in ix.audit_docs()
                          for i, e in enumerate(a.data) if isinstance(e, dict) and e.get("event_type") == "audit_anchor"),
                         key=lambda x: x[:3])
        for n, (_, _, i, a) in enumerate(anchors, start=1):
            exp(a, [i, "payload", "anchor_counter"], n, "engagement-wide anchor counter of the Z3 executor (receive order)")
        for a in ix.audit_docs():
            for i, e in enumerate(a.data):
                if not isinstance(e, dict):
                    continue
                rid, p = e.get("run_id"), e.get("payload") or {}
                if e.get("event_type") == "run_created":
                    r = ix.first("run", run_id=rid)
                    if r is not None:
                        exp(a, [i, "payload", "repo_commit"], r.data.get("repo_commit"), "the commit the run tests (E-RUN-COMMIT)")
                if e.get("event_type") == "artifact_stored" and p.get("artifact") == "seed-threats":
                    sd = ix.first("seed-threats", run_id=rid)
                    if sd is not None:
                        exp(a, [i, "payload", "sha256"], content_hash(sd.data), "content hash of the run's seed threats (E-AUDIT-ARTIFACT)")
        # writer-only: the reader checks these with dedicated codes (E-CLUSTER-FINGERPRINT,
        # E-RESULT-PRECONDITION, E-RESULT-CONTROLS) so a tampered value is reported by its rule
        for d in ix.docs("cluster"):
            with guard(d):
                exp(d, ["fingerprint"], cluster_fingerprint(d.data), "sha256(JCS(fingerprint key))")
                exp(d, ["severity"], rubric_severity(ix, d.data), "docs/08 §11.17 severity rubric (E-CLUSTER-SEVERITY)")
        for d in ix.docs("testresult"):
            with guard(d):
                tc = ix.testcase_for(d.data)
                if tc:
                    exp(d, ["precondition_reached", "value"], reachability_reached(tc.data, d.data), "all reachability controls PASS")
                    exp(d, ["positive_control", "value"], positive_control_value(tc.data, d.data), "oracle_can_fail control PASSed")
        # v0.5 (review r7 1.11): the adopting run's feedback_recorded event pins the feedback record (E-FEEDBACK reads it)
        for f in ix.docs("feedback"):
            for a in ix.audit_docs():
                for i, e in enumerate(a.data):
                    if isinstance(e, dict) and e.get("event_type") == "feedback_recorded" and \
                            (e.get("payload") or {}).get("feedback_id") == f.data.get("feedback_id"):
                        exp(a, [i, "payload", "feedback_sha256"], content_hash(f.data), "content hash of the recorded feedback")
        # v0.7 (review r8 H4): the deliverables are bound to the anchored chain: verdict_changed pins the verdict's content
        # hash, report_published the report manifest's (whose artifacts pin the SARIF, HTML, verdicts and audit log)
        for a in ix.audit_docs():
            for i, e in enumerate(a.data):
                if not isinstance(e, dict):
                    continue
                p = e.get("payload") or {}
                if e.get("event_type") == "verdict_changed":
                    v = ix.first("verdict", verdict_id=p.get("verdict_id"))
                    if v is not None:
                        exp(a, [i, "payload", "verdict_sha256"], content_hash(v.data), "content hash of the verdict version (E-AUDIT-VERDICT)")
                if e.get("event_type") == "gate_decision":
                    rec = ix.first("gate-record", gate_record_id=p.get("gate_record_id"))
                    if rec is not None:
                        exp(a, [i, "payload", "gate_record_sha256"], gate_record_sha256(rec.data),
                            "content hash of the decided gate record, signatures excluded (E-AUDIT-GATE)")
                if e.get("event_type") == "report_published":
                    rm = ix.first("report-manifest", report_id=p.get("report_id"))
                    if rm is not None:
                        exp(a, [i, "payload", "report_manifest_sha256"], content_hash(rm.data), "content hash of the report manifest (E-AUDIT-REPORT)")
        # v0.5 (review r7 1.10, external review 2): the executor's sandbox_job_end pins what ran and what it produced; the
        # reader compares them with dedicated codes (E-W4-AUDIT / E-JOB-AUDIT)
        for d in ix.docs("testresult"):
            with guard(d):
                tc = ix.testcase_for(d.data)
                audit = ix.audit_for(d.data.get("run_id"))
                if tc is None or audit is None:
                    continue
                for i, e in enumerate(audit.data):
                    if job_end_of(e, d.data):
                        for key, val in execution_pins(tc.data, d.data).items():
                            exp(audit, [i, "payload", key], val, f"{key} of what the job ran")

    # inventory -> redaction map
    for d in ix.docs("inventory"):
        with guard(d):
            rm = ix.first("redaction-map", run_id=d.data.get("run_id"))
            if rm:
                exp(d, ["redaction_map_ref"], content_hash(rm.data), "content hash of the run's redaction map")

    # testcases -> seed manifest oracle queries
    oq = ix.manifest.get("oracle_queries") or {}
    for d in ix.docs("testcase"):
        with guard(d):
            qid = (d.data.get("oracle") or {}).get("oracle_query_id")
            if qid and qid in oq:
                exp(d, ["oracle", "oracle_query_sha256"], oq[qid].get("sql_sha256"), f"seed-manifest oracle_queries.{qid}.sql_sha256")

    # testresults -> testcase artifact
    for d in ix.docs("testresult"):
        with guard(d):
            tc = ix.testcase_for(d.data)
            if tc:
                exp(d, ["artifact_sha256"], tc.data.get("artifact_sha256"), "testcase.artifact_sha256")

    # verdicts
    for d in ix.docs("verdict"):
        with guard(d):
            v = d.data
            cl = ix.first("cluster", cluster_id=v.get("cluster_id"))
            t_conf, t_rej = ix.thresholds((cl.data if cl else {}).get("cwe_bucket"))
            if not cl:
                continue
            cluster = cl.data
            version = v.get("calibration_version")
            for i, vote in enumerate(v.get("votes", [])):
                valid, wgt, counts = vote_terms(ix, vote, cluster, version)
                exp(d, ["votes", i, "valid"], valid, "family/lineage not in cluster, anonymized, order randomized")
                exp(d, ["votes", i, "weight"], wgt, "calibration.yaml w(model, cwe_bucket, side of the stance)")
                exp(d, ["votes", i, "weighted_valid"], counts, "valid, w > 0, a verifier-role voter, stance SUPPORT or REFUTE")
            exp(d, ["score"], derived_score(ix, v, cluster), "sum over base lineages of the mean w * stance of their weighted-valid votes")
            if version is not None and ix.calibration.get("calibration_version") == version:
                exp(d, ["theta_confirm"], t_conf, "calibration theta_confirm")
                exp(d, ["theta_reject"], t_rej, "calibration theta_reject")
            results = linked_results(ix, cluster, v.get("readjudicated_by"))
            classes = []
            exp(d, ["test_evidence", "results"], _merge_results(v, ix, results, cluster, classes), "linked testresults (docs/05 §4.2)")
            cls = strongest(classes)
            exp(d, ["test_evidence", "class"], cls, "strongest linked class")
            proof = None
            if cls == "E_proof":
                tr = next(r for r, c in zip(results, classes) if c == "E_proof")
                tc = ix.testcase_for(tr)
                # v0.7 (review r8 F7): is_probabilistic, not n > 1, and only {n, k} (the verdict schema has no n_effective)
                probabilistic = tc is not None and is_probabilistic(tc.data, ix)
                got = tr.get("trials") or {}
                proof = {"testcase_id": tr.get("testcase_id"), "result_ref": content_hash(tr),
                         "trials": {"n": got.get("n"), "k": got.get("k")} if probabilistic else None,
                         "interpretation_confirmed_by": tr.get("interpreted_by")}
            exp(d, ["executable_proof"], proof, "from the E_proof testresult")

    # disputed_after_g2: derived from verdicts carrying the w4_became_disputed annotation (docs/05 §4.2)
    became = w4_became_disputed_clusters(ix)
    for d in ix.docs("seed-threats"):
        with guard(d):
            for i, sd in enumerate(d.data.get("seeds", [])):
                exp(d, ["seeds", i, "disputed_after_g2"], sd.get("source_cluster_id") in became,
                    "a verdict of the source cluster carries w4_became_disputed")

    # gate records
    for d in ix.docs("gate-record"):
        with guard(d):
            rec = d.data
            art = gate_artifact(ix, rec)
            if art is not None:
                exp(d, ["artifact", "sha256"], art, f"{rec.get('gate')} artifact hash")
            for i, dec in enumerate(rec.get("decisions", [])):
                exp(d, ["decisions", i, "item_sha256"], item_hash(ix, rec, dec.get("item_id")), "approval hash of the item")
            if rec.get("gate") in ("G0a", "G0b") and art is not None and rec.get("verification"):
                exp(d, ["verification", "document_ref"], art, "hash of the verified document")

    # runs
    for d in ix.docs("run"):
        with guard(d):
            _run_expectations(ix, d, exp, slice_by_run, for_writer)

    # report manifest
    for d in ix.docs("report-manifest"):
        with guard(d):
            _report_expectations(ix, d, exp)

    # checkpoint
    for d in ix.docs("checkpoint-metadata"):
        with guard(d):
            run = ix.first("run", run_id=d.data.get("run_id"))
            if run:
                exp(d, ["state_sha256"], content_hash(run.data), "content hash of the run state")
                pi = d.data.get("pending_interrupt")
                pend = [g for g in run.data.get("gate_records", []) if g.get("gate_record_id") is None]
                if pi and pend:
                    exp(d, ["pending_interrupt", "gate"], pend[-1].get("gate"), "the run's pending gate")
                    exp(d, ["pending_interrupt", "subject_hash"], pend[-1].get("subject_hash"), "the run's pending gate subject")
                    exp(d, ["pending_interrupt", "deadline"], run.data.get("resume_deadline"), "run.resume_deadline")

    # commander plans: slice ids of the run that lists the plan
    for d in ix.docs("commander-plan"):
        with guard(d):
            runs = [r.data for r in ix.docs("run") if d.data.get("plan_id") in r.data.get("plan_ids", [])]
            if len(runs) == 1:
                sl = slice_by_run.get(runs[0].get("run_id"), [])
                if len(sl) == 1:
                    for i, _ in enumerate(d.data.get("slices", [])):
                        exp(d, ["slices", i, "slice_id"], sl[0], "the slice of the run that lists this plan")

    # (the audit hash chain is checked from raw lines in checks.py, E-AUDIT-CHAIN)
    return out


def _merge_results(v, ix, results, cluster, classes):
    old = (v.get("test_evidence") or {}).get("results", [])
    merged = []
    for i, tr in enumerate(results):
        cls, why = classify_result(ix, tr, cluster)
        classes.append(cls)
        reason = old[i].get("reason") if i < len(old) and isinstance(old[i], dict) else why
        merged.append({"result_ref": content_hash(tr), "class": cls,
                       "positive_control": (tr.get("positive_control") or {}).get("value"), "reason": reason})
    return merged


def _run_expectations(ix: Index, d: Doc, exp, slice_by_run, for_writer=False):
    r = d.data
    rid = r.get("run_id")
    b = ix.b
    for field, kind in (("toolkit_config_ref", "toolkit-config"), ("key_registry_ref", "key-registry"), ("engagement_ref", "engagement")):
        if b.data(kind) is not None:
            exp(d, [field], content_hash(b.data(kind)), f"content hash of {kind}")
    # B11: configuration files named by the run manifest (the kind is checked in checks.g_runs, E-RUN-CONFIG)
    for key in CONFIG_KINDS:
        ref = (r.get("config_refs") or {}).get(key)
        if isinstance(ref, dict) and isinstance(ref.get("path"), str):
            cd = next((x for x in b.docs if x.path == ref["path"] and x.data is not None), None)
            if cd is not None:
                exp(d, ["config_refs", key, "sha256"], content_hash(cd.data), f"content hash of {ref['path']}")
    has_g0b = any(g.get("gate") == "G0b" for g in r.get("gate_records", []))
    if b.data("roe") is not None:
        exp(d, ["roe_ref"], content_hash(b.data("roe")) if has_g0b else None, "content hash of roe.yaml when the run passed G0b")

    def by_run(kind, field, fn=content_hash, **extra):
        doc = ix.first(kind, run_id=rid, **extra)
        exp(d, [field], fn(doc.data) if doc else None, f"{kind} of this run")
        return doc

    inv = by_run("inventory", "inventory_ref")
    exp(d, ["sbom_ref"], inv.data.get("sbom_ref") if inv else None, "inventory.sbom_ref")
    exp(d, ["tool_results_ref"], tool_results_ref(ix, rid), "sha256(JCS(sorted payload_refs of the run's W1 Z2 tool_invocation_end events))")
    by_run("redaction-map", "redaction_map_ref")
    by_run("seed-threats", "seed_threats_ref")
    merged = by_run("dfd", "dfd_ref", viewpoint="merged")
    by_run("dfd", "b1_merged_ref", viewpoint="merged")
    by_run("dfd", "b1_external_ref", viewpoint="external")
    exp(d, ["b1_diff_ref"], sha256_ref(jcs(merged.data.get("b1_diff"))) if merged else None, "sha256(JCS(merged.b1_diff))")
    by_run("report-manifest", "report_manifest_ref")
    invariants = b.data("invariants")
    exp(d, ["invariants_ref"], content_hash(invariants) if invariants and invariants.get("run_id") == rid else None,
        "invariants.yaml of this run")
    exp(d, ["slice_refs"], slice_by_run.get(rid, []), "slices of this run")

    g3 = ix.gate_records(rid, "G3")
    exp(d, ["threat_model_ref"], artifact_sha(g3[-1].data) if g3 else None, "G3 artifact")
    tcs = {tid: ix.first("testcase", testcase_id=tid) for tid in r.get("testcase_ids", [])}
    if all(tcs.values()):
        exp(d, ["artifact_hashes"], {k: approval_hash(v.data) for k, v in tcs.items()}, "approval hash of each testcase")
        exp(d, ["testplan_ref"], set_digest([{"id": k, "sha256": approval_hash(v.data)} for k, v in tcs.items()]) if tcs else None,
            "set digest of the run's testcases (= G4 artifact)")
    trs = sorted((x.data for x in ix.docs("testresult") if x.data.get("run_id") == rid),
                 key=lambda t: (timeutil.sort_key(t.get("executed_at")), str(t.get("result_id"))))   # D4: by instant, not by text
    exp(d, ["testresults"], [content_hash(t) for t in trs], "content hash of each testresult (execution order)")
    # v0.7 (review r8): the W4 subset is derived too; v0.6 left run.w4_results unchecked (the example had [] with a W4 result)
    exp(d, ["w4_results"], [content_hash(t) for t in trs if t.get("phase") == "W4"], "content hash of each W4 testresult (execution order)")
    for jid in (r.get("jobs") or {}):
        tr = next((t for t in trs if t.get("job_id") == jid), None)
        exp(d, ["jobs", jid, "result_ref"], content_hash(tr) if tr else None, "testresult of this job")
    recs = {x.data.get("gate_record_id"): x.data for x in ix.gate_records(rid)}
    for i, g in enumerate(r.get("gate_records", [])):
        rec = recs.get(g.get("gate_record_id"))
        if rec is None:
            if g.get("gate") == "G4" and g.get("gate_record_id") is None and r.get("testplan_ref") is not None:
                exp(d, ["gate_records", i, "subject_hash"], get_path(r, ["testplan_ref"]), "pending G4 subject = testplan_ref")
            continue
        for field, val in (("gate", rec.get("gate")), ("outcome", rec.get("outcome")), ("round", rec.get("round")),
                           ("subject_hash", artifact_sha(rec)), ("job_id", rec.get("job_id")),
                           ("opened_at", rec.get("opened_at")), ("decided_at", rec.get("timestamp"))):
            exp(d, ["gate_records", i, field], val, f"mirror of {rec.get('gate_record_id')}")
    parent = ix.first("run", run_id=r.get("parent_run_id")) if r.get("parent_run_id") else None
    if parent and r.get("run_kind") == "followup":
        exp(d, ["reuse"], [parent.data.get("invariants_ref"), parent.data.get("threat_model_ref")],
            "follow-up reuses the parent's approved invariants and threat model")
    exp(d, ["disputed_after_g2"], sorted(k for k, run_id in w4_became_disputed_clusters(ix).items() if run_id == rid),
        "clusters of this run with a verdict carrying w4_became_disputed")
    audit = ix.audit_for(rid)
    if audit and for_writer:
        # writer-only: the reader side checks the anchors against the raw lines in checks.g_audit
        # (E-AUDIT-ANCHOR / -MISMATCH / -TRUNCATED / -TAIL), so a tampered log is reported as such
        lines = read_jsonl_lines(audit.text or "")
        exp(d, ["audit_anchors"],
            [{"seq": i + 1, "line_sha256": "sha256:" + sha256_hex(lines[i].encode("utf-8"))}
             for i, e in enumerate(audit.data) if e.get("event_type") == "audit_anchor"],
            "one {seq, line_sha256} per audit_anchor event (sha256 of the anchor's own raw line)")


def _report_expectations(ix: Index, d: Doc, exp):
    rid = d.data.get("run_id")
    audit = ix.audit_for(rid)
    for i, a in enumerate(d.data.get("artifacts", [])):
        kind, ref = a.get("kind"), a.get("ref")
        val = MISSING
        if kind in ("threat_model", "test_plan", "gate_record"):
            rec = ix.first("gate-record", gate_record_id=ref)
            if rec:
                val = artifact_sha(rec.data) if kind != "gate_record" else content_hash(rec.data)
        elif kind == "testresult":
            x = ix.first("testresult", result_id=ref)
            val = content_hash(x.data) if x else MISSING
        elif kind == "verdict":
            x = ix.first("verdict", verdict_id=ref)
            val = content_hash(x.data) if x else MISSING
        elif kind == "audit_log":
            # v0.7 (review r10 manifest): the report_published of this manifest's report_id (v0.7 r9 took the first event of
            # the run). A manifest without its event is E-AUDIT-REPORT (checks.report_events), not a derivation
            pub = [e for e in (audit.data if audit else []) if isinstance(e, dict) and e.get("event_type") == "report_published"
                   and (e.get("payload") or {}).get("report_id") == d.data.get("report_id")]
            val = pub[0].get("prev_hash") if pub else MISSING
        elif kind == "followup_draft":
            x = next((p for p in ix.docs("commander-plan") if any(f.get("draft_id") == ref for f in p.data.get("followup_drafts", []))), None)
            val = content_hash(x.data) if x else MISSING
        exp(d, ["artifacts", i, "sha256"], val, f"{kind} {ref}")


def compare(b: Bundle, problems: list | None = None) -> list[tuple[Expectation, Any]]:
    """Mismatches: [(expectation, actual)]."""
    docs = {d.path: d for d in b.docs}
    bad = []
    for e in expectations(b, problems=problems):
        doc = docs.get(e.file)
        actual = get_path(doc.data, e.path) if doc and doc.data is not None else MISSING
        if not _equal(actual, e.expected):
            bad.append((e, actual))
    return bad


__all__ = ["Expectation", "expectations", "compare"]
