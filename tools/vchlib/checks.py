# SPDX-License-Identifier: Apache-2.0
"""Semantic checks over the example bundle (v0.3).

Every check reports through `Report`: errors fail the run, warnings are printed only.
Each group is isolated: an unexpected exception in one group becomes E-INTERNAL instead of
crashing the validator (graceful handling of broken or unknown input).

Trust model [H]: the key registry (docs/examples/key-registry.yaml) is the ONLY source of
public keys. Its root signature is checked against the fingerprint pinned in toolkit.yaml.
Fingerprints and roles written anywhere else are claims that must agree with the registry.
Signatures are real Ed25519 over RFC 8785 JCS; the example keys are TEST ONLY fixtures.
"""
from __future__ import annotations

import traceback

from . import derive, evidence, llm_schema
from .bundle import Bundle, Doc
from .canonical import content_hash
from .checks_audit import g_audit
from .checks_calibration import g_calibration
from .checks_config import g_crosswalk, g_licenses, g_llm_schemas, g_toolkit
from .checks_engagement import ANCHOR_LABEL, deployment, g_engagement, profile
from .checks_gates import g_gates
from .checks_integrity import g_derived, g_jcs, g_key_registry, g_persons, g_schemas
from .checks_models import g_models
from .checks_roe import g_roe, path_shape
from .checks_runs import g_runs
from .checks_signatures import g_signatures
from .checks_testcases import access_matrix_cells, g_feedback, g_report_withdrawal, g_testcases
from .checks_trace import check_report_queues, g_trace, inventory_of_run, pipeline_checks
from .checks_verdicts import g_verdicts
from .checks_w4 import g_w4_testcases
from .context import Ctx
from .report import FINAL_STATUSES, M1_REQUIRED_SELFTESTS, Report, doc_guard, ts
from .verdict import verdict_heads


# ============================================================== 21 DFD, report, selftest, checkpoint
def _ratio(n, d):
    return round(n / d, 4) if d else None


def execution_backed(c: Ctx, tr: dict) -> bool:
    """v0.5 (review r7, external review 5): the result is effective evidence: outcome PASS or FAIL (not INVALID, ERROR,
    SKIPPED or STOPPED), every control PASSed, and exactly one sandbox_job_end in the anchored part of its run's audit log
    names it with the same outcome and the hashes of what ran (derive.execution_pins)."""
    controls = [y for y in tr.get("controls") or [] if isinstance(y, dict)]
    if tr.get("outcome") not in ("PASS", "FAIL") or not controls or any(y.get("outcome") != "PASS" for y in controls):
        return False
    tc = c.ix.testcase_for(tr)
    audit = c.ix.audit_for(tr.get("run_id"))
    evs = [e for e in (audit.data if audit else []) if isinstance(e, dict)]
    ends = [e for e in evs if derive.job_end_of(e, tr)]
    if tc is None or len(ends) != 1:
        return False
    e, p = ends[0], ends[0].get("payload") or {}
    anchored = max((i + 1 for i, x in enumerate(evs) if x.get("event_type") == "audit_anchor"), default=0)
    return (type(e.get("seq")) is int and e.get("seq") < anchored and p.get("outcome") == tr.get("outcome")  # type: ignore[operator]
            and all(p.get(k) == v for k, v in derive.execution_pins(tc.data, tr).items()))


def report_metrics(c: Ctx, run_id) -> dict:
    """B5: results_total, results_invalid, control_pass_rate (PASS control outcomes / all control outcomes, 4 decimals).
    v0.5 (BL-20, docs/02 W5 coverage): planned_access_matrix_coverage = G1 matrix cells named by the access_cells of the
    run's testcases (run.testcase_ids) and w4-testcases / all cells; endpoint_slice_coverage = inventory endpoints whose
    handler file is in a slice of the run / all; planned_endpoint_test_coverage = endpoints hit by a request_allowlist
    entry of the run's testcases (same method and path shape) / all.
    v0.5 (review r7, external review 5): the planned figures stay 1.0 with every result removed, so the executed_*
    figures count only testcases with at least one execution_backed result of the run."""
    results = [x.data for x in c.docs("testresult") if x.data.get("run_id") == run_id]
    outs = [y.get("outcome") for r in results for y in r.get("controls") or [] if isinstance(y, dict)]
    run = c.runs.get(run_id) or {}
    tcs = [t.data for t in c.docs("testcase") if t.data.get("testcase_id") in (run.get("testcase_ids") or [])]
    w4 = [t.data for t in c.docs("w4-testcase") if t.data.get("run_id") == run_id]
    ran = {(r.get("phase") == "W4", r.get("testcase_id")) for r in results if execution_backed(c, r)}
    cells = access_matrix_cells(c)
    eps = [e for e in (inventory_of_run(c, run_id) or {}).get("endpoints") or [] if isinstance(e, dict)]

    def cell_cover(tests):
        covered = {(x.get("role"), x.get("resource"), x.get("action")) for t in tests for x in t.get("access_cells") or [] if isinstance(x, dict)}
        return _ratio(len(covered & cells), len(cells))

    def endpoint_cover(tests):
        hit = {(r.get("method"), path_shape(r.get("path"))) for t in tests for r in t.get("request_allowlist") or [] if isinstance(r, dict)}
        return _ratio(sum(1 for e in eps if (e.get("method"), path_shape(e.get("path"))) in hit), len(eps))

    tcs_ran = [t for t in tcs if (False, t.get("testcase_id")) in ran]
    w4_ran = [t for t in w4 if (True, t.get("testcase_id")) in ran]
    sliced = {f.get("path") for s in c.docs("slice") if s.data.get("run_id") == run_id for f in s.data.get("files") or [] if isinstance(f, dict)}
    return {"results_total": len(results), "results_invalid": sum(1 for r in results if r.get("outcome") == "INVALID"),
            "control_pass_rate": round(sum(1 for o in outs if o == "PASS") / len(outs), 4) if outs else None,
            "planned_access_matrix_coverage": cell_cover(tcs + w4),
            "executed_access_matrix_coverage": cell_cover(tcs_ran + w4_ran),
            "endpoint_slice_coverage": _ratio(sum(1 for e in eps if e.get("file") in sliced), len(eps)),
            "planned_endpoint_test_coverage": endpoint_cover(tcs),
            "executed_endpoint_test_coverage": endpoint_cover(tcs_ran)}


ID_KEYS = {"run": "run_id", "verdict": "verdict_id", "cluster": "cluster_id", "finding": "finding_id", "testcase": "testcase_id",
           "w4-testcase": "testcase_id", "feedback": "feedback_id",
           "testresult": "result_id", "threat": "threat_id", "gate-record": "gate_record_id", "report-manifest": "report_id",
           "slice": "slice_id", "commander-plan": "plan_id"}     # v0.7 (review r9): plans too
# v0.7 (review r9): documents a run has at most one of (per viewpoint for DFDs). Lookups take the first by file name, so a
# second inventory, seed-threats document or merged DFD of a run decided silently which one was checked
PER_RUN_SINGLETONS = {"inventory": None, "seed-threats": None, "redaction-map": None, "dfd": "viewpoint",
                      "report-manifest": None}     # v0.7 (review r10): one report per run; a second one decided nothing


def id_uniqueness(R: Report, c: Ctx):
    """v0.5 (review 2026-10-25 V-5): an ID names one document. With two documents of the same kind and ID, lookups
    disagreed (Ctx.runs took the last, Index.first the first), so a second copy could shadow the checked one."""
    for kind, key in ID_KEYS.items():
        seen: dict = {}
        for d in c.docs(kind):
            if isinstance(d.data, dict) and d.data.get(key) is not None:
                seen.setdefault(d.data.get(key), []).append(d.path)
        for i, paths in seen.items():
            R.check(len(paths) == 1, "E-ID-DUP", paths[-1], f"{kind} {key} {i!r} is used by {len(paths)} documents: {paths}")
    for kind, facet in PER_RUN_SINGLETONS.items():
        per: dict = {}
        for d in c.docs(kind):
            if isinstance(d.data, dict) and d.data.get("run_id") is not None:
                per.setdefault((d.data.get("run_id"), d.data.get(facet) if facet else None), []).append(d.path)
        for (rid, f), paths in per.items():
            R.check(len(paths) == 1, "E-ID-DUP", paths[-1],
                    f"run {rid} has {len(paths)} {kind} documents{f' ({facet} {f})' if facet else ''}: {paths}; a run has one")


def threat_coverage(R: Report, c: Ctx):
    """v0.5 (review 2026-10-25 §4.3), docs/04 §1.3 (D5) and docs/02 B2, enforced instead of only described:
    - E-THREAT-ATTACK-TREE: a threat rated likelihood high and impact high is high-risk and needs attack_tree_ref; a
      set attack_tree_ref names this threat's tree (…/<threat_id>.json);
    - E-COVERAGE-D5: once a run has a G4 record (B3 finished), every threat whose latest G3 decision is accept has at
      least one testcase (a MANUAL one counts); reject and over_cap need none."""
    for d in c.docs("threat"):
        t, w = d.data, d.path
        ref, risk = t.get("attack_tree_ref"), t.get("risk") or {}
        if risk.get("likelihood") == "high" and risk.get("impact") == "high":
            R.check(bool(ref), "E-THREAT-ATTACK-TREE", w, f"{t.get('threat_id')} is rated high/high (high-risk) and needs attack_tree_ref")
        if ref:
            R.check(isinstance(ref, str) and ref.rsplit("/", 1)[-1] == f"{t.get('threat_id')}.json", "E-THREAT-ATTACK-TREE", w,
                    f"attack_tree_ref {ref!r} must name this threat's tree (…/{t.get('threat_id')}.json)")
    tested = {x.data.get("threat_id") for x in c.docs("testcase")}
    for rid in c.runs:
        if not c.ix.gate_records(rid, "G4"):
            continue
        latest = {}
        for rec in c.ix.gate_records(rid, "G3"):
            for x in rec.data.get("decisions") or []:
                latest[x.get("item_id")] = x.get("decision")
        for tid, dec in latest.items():
            if dec == "accept":
                R.check(tid in tested, "E-COVERAGE-D5", f"run {rid}", f"threat {tid} was accepted at G3 but has no testcase (not even MANUAL)")


def g_misc(R: Report, c: Ctx):
    id_uniqueness(R, c)
    threat_coverage(R, c)
    with doc_guard(R, "pipeline"):
        pipeline_checks(R, c)
    for d in c.docs("dfd"):
        with doc_guard(R, d.path):
            els = d.data.get("elements", [])
            ids = [e.get("element_id") for e in els]
            R.check(len(ids) == len(set(ids)), "E-DFD", d.path, "duplicate element ids")
            inv = inventory_of_run(c, d.data.get("run_id"))
            for e in els:
                R.check((e.get("type") == "trust_boundary") == (e.get("kind") is not None), "E-DFD", d.path,
                        f"{e.get('element_id')}: kind is required on trust boundaries and null on other elements")
                for r in e.get("evidence_refs") or []:
                    if str(r).startswith("inventory:"):
                        R.check(inv is not None and evidence.resolves(inv, str(r)[len("inventory:"):]), "E-INVENTORY-REF", d.path,
                                f"{e.get('element_id')}: {r} does not resolve in the W0 inventory of {d.data.get('run_id')}")
                if e.get("type") == "data_flow":
                    R.check(e.get("from") in ids and e.get("to") in ids, "E-DFD", d.path, f"{e.get('element_id')}: flow endpoints missing")
                    R.check(all(x in ids for x in e.get("crosses", [])), "E-DFD", d.path, f"{e.get('element_id')}: unknown trust boundary")
    ext = {e.get("element_id") for d in c.ix.find("dfd", viewpoint="external") for e in d.data.get("elements", [])}
    mer = {e.get("element_id") for d in c.ix.find("dfd", viewpoint="merged") for e in d.data.get("elements", [])}
    for d in c.ix.find("dfd", viewpoint="merged"):
        for x in d.data.get("b1_diff") or []:
            eid = x.get("element_id")
            want = {"only_external": eid in ext and eid not in mer, "only_merged": eid in mer and eid not in ext,
                    "attribute_mismatch": eid in ext and eid in mer}.get(x.get("kind"), False)
            R.check(want, "E-DFD", d.path, f"b1_diff {eid}: kind {x.get('kind')} does not match the two views")
    for d in c.docs("report-manifest"):
        with doc_guard(R, d.path):
            rm, w = d.data, d.path
            run = c.runs.get(rm.get("run_id"))
            if not R.check(run is not None, "E-REPORT", w, "run not found"):
                continue
            R.check(rm.get("advisory") is (run.get("run_kind") == "lane_a"), "E-REPORT", w, "advisory iff Lane A")  # type: ignore[union-attr]
            # review r11: a Lite engagement's one person holds every key and runs every zone, so its signatures, anchors
            # and receive times prove nothing to a third party (docs/06 §3 #26); the report says so in a field
            want_ev = "self_attested" if profile(c) == "lite" else "separated"
            R.check(rm.get("evidential") == want_ev, "E-REPORT", w,
                    f"evidential must be {want_ev!r} for assurance_profile {profile(c)} (Lite evidence is self-attested), not {rm.get('evidential')!r}")
            # BL-70 / D10: a single-host engagement's anchors are countersigned by the operator's own process; the report says so
            want_anchor = ANCHOR_LABEL.get(deployment(c), "countersigned")
            R.check(rm.get("audit_anchor") == want_anchor, "E-REPORT-ANCHOR", w,
                    f"audit_anchor must be {want_anchor!r} for deployment_profile {deployment(c)}, not {rm.get('audit_anchor')!r}")
            final = verdict_heads(c, run.get("verdicts", []))  # type: ignore[union-attr]  # v0.5 (V-4): a broken chain is E-VERDICT-CHAIN
            counts = {s: sum(1 for v in final if v.get("status") == s) for s in FINAL_STATUSES}
            R.check(rm.get("verdict_counts") == counts, "E-REPORT", w, f"verdict_counts must be {counts} (latest verdict per cluster)")
            want_m = report_metrics(c, rm.get("run_id"))
            got_m = rm.get("metrics") or {}
            R.check(derive._equal(got_m, want_m), "E-REPORT-METRICS", w, f"metrics {got_m} != recomputed {want_m} (the run's testresults and controls)")
            R.check(sorted(rm.get("manual_review_clusters", [])) == sorted(run.get("manual_review_clusters", [])), "E-REPORT", w, "manual_review_clusters differ from the run")  # type: ignore[union-attr]
            check_report_queues(R, c, w, rm, {v.get("cluster_id"): v.get("status") for v in final})
            for a in rm.get("artifacts", []):
                if a.get("kind") == "audit_log":
                    R.check(c.b.doc(a.get("ref", "")) is not None, "E-REPORT", w, f"audit log {a.get('ref')} not found")
            grs = {a.get("ref") for a in rm.get("artifacts", []) if a.get("kind") == "gate_record"}
            R.check(grs == {g.data.get("gate_record_id") for g in c.ix.gate_records(rm.get("run_id"))}, "E-REPORT", w, "report must list every gate record of the run")
    for d in c.docs("selftest-report"):
        with doc_guard(R, d.path):
            st, w = d.data, d.path
            items = {i.get("item"): i for i in st.get("items", [])}
            for i in items.values():
                if i.get("status") == "NOT_RUN":
                    R.check(i.get("passed") is None and i.get("value") is None and i.get("runs") == 0, "E-SELFTEST", w, f"{i.get('item')}: NOT_RUN has no result")
                else:
                    R.check(i.get("passed") is not None and i.get("runs", 0) >= 1, "E-SELFTEST", w, f"{i.get('item')}: RUN needs runs and passed")
            if st.get("milestone") == "M1":
                for need in M1_REQUIRED_SELFTESTS:
                    it = items.get(need) or {}
                    R.check(it.get("status") == "RUN" and it.get("passed") is True, "E-SELFTEST-M1", w, f"M1 requires {need} RUN and passed")
            ran = [i for i in items.values() if i.get("status") == "RUN"]
            R.check(st.get("overall_passed") is (bool(ran) and all(i.get("passed") for i in ran)), "E-SELFTEST", w, "overall_passed must be all RUN items passed")
            s, f = ts(R, st.get("started_at"), w), ts(R, st.get("finished_at"), w)
            R.check(s and f and s <= f, "E-SELFTEST", w, "finished_at before started_at")
            R.check(st.get("toolkit_version") == c.toolkit.get("toolkit_version"), "E-SELFTEST", w, "toolkit_version differs")
    for d in c.docs("checkpoint-metadata"):
        with doc_guard(R, d.path):
            run = c.runs.get(d.data.get("run_id"))
            if R.check(run is not None, "E-CHECKPOINT", d.path, "run not found"):
                R.check(d.data.get("run_status") == run.get("status") and d.data.get("thread_id") == run.get("run_id"), "E-CHECKPOINT", d.path,  # type: ignore[union-attr]
                        "run_status / thread_id disagree with the run")
                R.check(d.data.get("encrypted") is True or run.get("data_class") == "P", "E-CHECKPOINT", d.path, "C-class checkpoints must be encrypted")  # type: ignore[union-attr]


GROUPS = [
    ("schemas and examples", g_schemas),
    ("RFC 8785 canonical JSON", g_jcs),
    ("derived hashes, weights and audit chain", g_derived),
    ("key registry", g_key_registry),
    ("Ed25519 signatures", g_signatures),
    ("person references", g_persons),
    ("engagement", g_engagement),
    ("ROE and legal review L-1..L-6", g_roe),
    ("models, agents, family diversity", g_models),
    ("gates", g_gates),
    ("run state, jobs, test results", g_runs),
    ("testcases vs ROE (docs/04 §5)", g_testcases),
    ("W4 testcases (docs/02 W4)", g_w4_testcases),
    ("feedback records (docs/08 §11.16)", g_feedback),
    ("report withdrawals (docs/06 §1.9)", g_report_withdrawal),
    ("verdict recomputation (docs/05 §4.2)", g_verdicts),
    ("traceability", g_trace),
    ("audit log", g_audit),
    ("calibration", g_calibration),
    ("licenses and requirements", g_licenses),
    ("crosswalk", g_crosswalk),
    ("LLM-facing schemas (cross-vendor subset)", g_llm_schemas),
    ("toolkit, tools, retention", g_toolkit),
    ("DFD, report, self-test, checkpoint", g_misc),
]


def _json_type(value, t) -> bool:
    return {"object": isinstance(value, dict), "array": isinstance(value, list), "string": isinstance(value, str),
            "boolean": isinstance(value, bool), "null": value is None,
            # shape level: 3.0 in an integer field is left to E-SCHEMA (a strict-integer error), not quarantined
            "integer": isinstance(value, (int, float)) and not isinstance(value, bool),
            "number": isinstance(value, (int, float)) and not isinstance(value, bool)}.get(t, True)


def _shape_ok(value, schema, schemas, depth=0):
    """True / False when the JSON type of `value` is decidable from `schema` (type, $ref, anyOf); None otherwise."""
    if not isinstance(schema, dict) or depth > 10:
        return None
    if "$ref" in schema:
        target, _, frag = schema["$ref"].partition("#")
        doc = schemas.get(target.removesuffix(".schema.json")) if target else None
        try:
            node = llm_schema._pointer(doc if doc is not None else {}, frag) if target else None
        except (KeyError, IndexError, ValueError, TypeError):
            node = None
        return _shape_ok(value, node, schemas, depth + 1) if node is not None else None
    if "type" in schema:
        ts_ = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
        return any(_json_type(value, t) for t in ts_)
    if "anyOf" in schema:
        res = [_shape_ok(value, alt, schemas, depth + 1) for alt in schema["anyOf"]]
        if any(r is True for r in res):
            return True
        return False if res and all(r is False for r in res) else None
    return None


def input_shape_problems(d: Doc, schema: dict, schemas: dict) -> list[str]:
    """D5: the document's top level (and the JSON type of each top-level field) matches its schema."""
    if d.kind == "audit-event":
        if not isinstance(d.data, list) or not all(isinstance(x, dict) for x in d.data):
            return ["the audit log must be one JSON object per line"]
        return []
    if not isinstance(d.data, dict):
        return [f"top level is {type(d.data).__name__}, expected a mapping"]
    out = []
    props = schema.get("properties") or {}
    extra = schema.get("additionalProperties")
    for k, v in d.data.items():
        sub = props.get(k, extra if isinstance(extra, dict) else None)
        if sub is not None and _shape_ok(v, sub, schemas) is False:
            out.append(f"{k}: {type(v).__name__} does not have the schema's type")
    return out


def quarantine(R: Report, b: Bundle) -> Bundle:
    """D5: one E-INPUT-SHAPE per file whose shape is wrong; such documents are hidden (data None) from the semantic
    groups, so a wrong shape never crashes the validator. The schema group still sees the original document."""
    docs = []
    for d in b.docs:
        s = b.schemas.get(d.kind)
        probs = input_shape_problems(d, s, b.schemas) if (s is not None and d.data is not None) else []
        if probs:
            R.error("E-INPUT-SHAPE", d.path, "; ".join(probs[:5]) + " (the document is skipped by the semantic checks)")
            docs.append(Doc(d.path, d.kind, None, d.text, None))
        else:
            docs.append(d)
    return Bundle(root=b.root, schemas=b.schemas, docs=docs, requirements_txt=b.requirements_txt)


def run_all(b: Bundle, real_run: bool = False) -> Report:
    """Run every check group. real_run=True (CLI --real-run): placeholder models reachable from an
    agent are E-MODEL-PLACEHOLDER errors instead of W-MODEL-PLACEHOLDER warnings."""
    R = Report()
    view = quarantine(R, b)
    try:
        c = Ctx(view, real_run=real_run)              # D5: inside the guard
        c.original = b
    except Exception as exc:  # noqa: BLE001 - graceful: report, stop
        R.error("E-INTERNAL", "context", f"cannot build the check context: {type(exc).__name__}: {exc}")
        return R
    for name, fn in GROUPS:
        before_checks, before_err = R._checks, len(R.errors)
        try:
            fn(R, c)
        except Exception as exc:  # noqa: BLE001 - graceful: report, keep going
            R.error("E-INTERNAL", name, f"{type(exc).__name__}: {exc} | {traceback.format_exc(limit=3).splitlines()[-2].strip()}")
        R.groups.append((name, R._checks - before_checks, len(R.errors) - before_err))
    return R


__all__ = ["run_all", "GROUPS", "content_hash"]
