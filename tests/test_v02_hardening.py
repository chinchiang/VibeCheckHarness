# SPDX-License-Identifier: Apache-2.0
"""v0.2 hardening: derived verdict flags, strict JSON, audit tail anchors, retention precedence,
DB target scope, placeholder model IDs. Each rule has a positive and a negative case."""
import copy
import hashlib
import json

import pytest

from conftest import codes, doc, rederive
from vchlib import crypto, jsonstrict, safety
from vchlib.bundle import read_jsonl_lines, reload_json
from vchlib.checks import run_all

AUDIT = "audit-event.run-2026-09-23-001.example.jsonl"
AUDIT_A = "audit-event.run-2026-09-25-pr-118.example.jsonl"
RUN = "examples/run.example.json"
RUN_A = "examples/run.lane-a.example.json"
V_W3 = "verdict.example.json"                  # K-005, no valid votes -> degraded
V_K011 = "verdict.k-011-w3.example.json"       # K-011, one valid nvidia vote -> degraded
V_LANE_A = "verdict.lane-a.example.json"
G1 = "gate-record.g1.example.json"
TC_IDOR = "testcase.idor.example.json"


def warn_codes(bundle):
    return {w.code for w in run_all(bundle).warnings}


def dump_line(ev):
    return json.dumps(ev, ensure_ascii=False, separators=(",", ":"))


def rechain(events):
    """JSONL text with a correct prev_hash chain (what an attacker able to rewrite the log produces)."""
    prev = hashlib.sha256(events[0]["run_id"].encode()).hexdigest()
    out = []
    for ev in events:
        ev["prev_hash"] = "sha256:" + prev
        line = dump_line(ev)
        prev = hashlib.sha256(line.encode("utf-8")).hexdigest()
        out.append(line)
    return "".join(ln + "\n" for ln in out)


def line_sha(text, seq):
    return "sha256:" + hashlib.sha256(read_jsonl_lines(text)[seq - 1].encode("utf-8")).hexdigest()


# ================================================================ 1 derived verdict flags
def test_diversity_degraded_examples_are_derived(b):
    # v0.3 (A3): only WEIGHTED-valid votes count; K-014's openai vote has weight 0 -> degraded
    for suffix, want in ((V_W3, True), (V_K011, True), ("verdict.executable.example.json", True), (V_LANE_A, False),
                         ("verdict.k-014-w3.example.json", True)):
        assert doc(b, suffix).data["diversity_degraded"] is want, suffix
    assert "E-VERDICT-DIVERSITY" not in codes(b)


def test_diversity_degraded_understated_is_rejected(b):
    doc(b, V_W3).data["diversity_degraded"] = False
    assert "E-VERDICT-DIVERSITY" in codes(b)


def test_diversity_degraded_on_lane_a_is_rejected(b):
    doc(b, V_LANE_A).data["diversity_degraded"] = True
    assert "E-VERDICT-DIVERSITY" in codes(b)


def _add_gpt_oss_vote(v):
    vt = copy.deepcopy(v["votes"][0])
    vt.update(voter_agent_id="ver_3", voter_model_key="gpt_oss_self", voter_family="openai", voter_lineage="gpt-oss",
              weighted_valid=False, weight=0.0)
    v["votes"].append(vt)


def test_weight_zero_vote_does_not_add_diversity(b, keys):
    """v0.3 (A3): a valid vote with calibration weight 0 (gpt_oss_self / llm_specific) is not weighted-valid,
    so it adds no family: V-011-1 stays diversity_degraded (the v0.2 rule counted every valid vote)."""
    v = doc(b, V_K011).data
    _add_gpt_oss_vote(v)
    rederive(b, keys)                                  # G2 item hash / signatures follow the new vote
    assert v["votes"][1]["valid"] is True and v["votes"][1]["weighted_valid"] is False
    assert codes(b) == set()                           # still degraded, as declared
    v["diversity_degraded"] = False
    rederive(b, keys)
    assert codes(b) == {"E-VERDICT-DIVERSITY"}


def test_vote_family_is_taken_from_the_registry(b):
    """A vote claiming another family does not create diversity: family comes from agents/models."""
    v = doc(b, V_K011).data
    _add_gpt_oss_vote(v)
    v["votes"][1].update(voter_agent_id="ver_1", voter_model_key="nemotron_self")  # really nvidia again
    v["diversity_degraded"] = False
    c = codes(b)
    assert "E-VERDICT-DIVERSITY" in c and "E-VERDICT-VOTE" in c


def test_vote_model_must_match_the_agent(b):
    doc(b, V_K011).data["votes"][0]["voter_model_key"] = "claude_sonnet"
    assert "E-VERDICT-VOTE" in codes(b)


def test_tool_corroboration_self_declared_is_rejected(b):
    doc(b, V_W3).data["tool_corroboration"] = ["sha256:" + "a" * 64]
    assert "E-VERDICT-TOOLCORR" in codes(b)


def test_tool_signal_from_sarif_refs(b):
    """The K-014 example (v0.3, H-A1): its SARIF ref is backed by a successful, legally cleared opengrep:scan
    tool_invocation_end, but opengrep's rule is not a calibrated high-precision rule, so it is a WEAK signal:
    tool_signal, one extra independent source, LIKELY via R6 (was CONFIRMED_CORROBORATED in v0.2)."""
    cl = doc(b, "cluster.k-014.example.json").data
    v = doc(b, "verdict.k-014-w3.example.json").data
    assert cl["sarif_refs"] and v["tool_signal"] == cl["sarif_refs"] and v["tool_corroboration"] == []
    assert v["independent_sources"] == 2 and v["status"] == "LIKELY" and v["rule_trace"][-1].startswith("R6:")
    ends = [e for e in doc(b, AUDIT).data if e["event_type"] == "tool_invocation_end"]
    assert any(cl["sarif_refs"][0] in e["payload_refs"] and e["payload"]["adapter"] == "opengrep:scan" for e in ends)
    assert codes(b) == set()
    v["tool_signal"] = []                              # omitting the derived SARIF ref
    # review r7 group 2: the report now lists V-014-1, so its pinned hash no longer matches either
    assert codes(b) == {"E-VERDICT-TOOLSIGNAL", "E-DERIVED", "E-AUDIT-VERDICT"}   # r8 H4: verdict_changed pins the verdict


def _repin_calibration(b, keys):
    """Re-pin calibration.yaml in the engagement and re-sign it, as the signatories would after a calibration change."""
    from vchlib.canonical import content_hash
    eng = doc(b, "engagement.yaml").data
    eng["config_pins"]["calibration"] = content_hash(doc(b, "calibration.yaml").data)
    eng["signatures"] = [crypto.sign_document(eng, s["signer"], keys[s["signer"]]) for s in eng["signatures"]]


def test_high_precision_rule_is_strong_tool_corroboration(b, keys):
    """Positive case of H-A1: once calibration lists (opengrep:scan, rule, authz) with precision_lower95 >=
    high_precision_min, the same SARIF ref is STRONG: tool_corroboration, row 10 CONFIRMED_CORROBORATED (never
    capped by R8, although V-014-1 is diversity_degraded)."""
    # v0.6 (review r7 3.5): the row carries its raw counts; 117/120 has a Clopper-Pearson lower bound of 0.9287
    rule = {"adapter": "opengrep:scan", "rule_id": "vc.authz.update-without-owner", "tool_version": "1.6.0", "cwe_bucket": "authz",
            "n": 120, "tp": 117, "fp": 3, "precision_lower95": 0.9287, "holdout_n": 30, "holdout_tp": 29}
    doc(b, "calibration.yaml").data["result"]["high_precision_rules"] = [rule]
    _repin_calibration(b, keys)                        # v0.5: calibration.yaml is pinned by the engagement
    rederive(b, keys)                                  # run.config_refs hashes calibration.yaml (v0.3, B11)
    v = doc(b, "verdict.k-014-w3.example.json").data
    ref = v["tool_signal"][0]
    assert codes(b) == {"E-VERDICT-TOOLCORR", "E-VERDICT-TOOLSIGNAL", "E-VERDICT-SOURCES", "E-VERDICT-STATUS", "E-VERDICT-TRACE"}
    v.update(tool_corroboration=[ref], tool_signal=[], independent_sources=1, status="CONFIRMED_CORROBORATED",
             rule_trace=["R2:strong_tool=opengrep:scan", "R5:strong tool corroboration (row 10)"])
    counts = doc(b, "report-manifest.example.json").data["verdict_counts"]
    counts["LIKELY"] -= 1
    counts["CONFIRMED_CORROBORATED"] += 1
    # review r7 group 2: K-014 is a seed threat (ST-004), which records the status W5 saw
    next(s for s in doc(b, "seed-threats.example.json").data["seeds"] if s["source_cluster_id"] == "K-014")["cluster_status"] = \
        "CONFIRMED_CORROBORATED"
    rederive(b, keys)
    assert codes(b) == {"E-AUDIT-VERDICT"}            # the audit verdict_changed event still says LIKELY
    next(e for e in doc(b, AUDIT).data if (e["payload"] or {}).get("verdict_id") == "V-014-1")["payload"]["status"] = "CONFIRMED_CORROBORATED"
    rederive(b, keys)
    assert codes(b) == set()
    rule.update(tp=108, fp=12, precision_lower95=0.8318)   # below high_precision_min 0.90 -> weak again
    assert "E-VERDICT-TOOLCORR" in codes(b)
    rule.update(tp=117, fp=3, precision_lower95=0.9287, tool_version="1.5.2")   # measured on another scanner version -> weak
    assert "E-VERDICT-TOOLCORR" in codes(b)
    rule["tool_version"] = "1.6.0"
    rederive(b, keys)
    assert codes(b) == set()
    doc(b, "calibration.yaml").data["result"]["thresholds"]["high_precision_min"]["value"] = 0.95   # stricter policy
    assert "E-VERDICT-TOOLCORR" in codes(b)


def test_fabricated_sarif_ref_is_rejected(b):
    """A ref no audited tool invocation produced: E-SARIF-REF, and it does not corroborate (no R8 bypass)."""
    ref = "sha256:" + "b" * 64
    doc(b, "cluster.k-011.example.json").data["sarif_refs"] = [ref]
    for s in (V_K011, "verdict.k-011-b5.example.json"):
        doc(b, s).data["tool_corroboration"] = [ref]
    R = run_all(b)
    c = R.codes()
    assert "E-SARIF-REF" in c and "E-VERDICT-TOOLCORR" in c
    # the verdict stays UNCORROBORATED: a fabricated ref never reaches row 10 (R5) past R8
    assert "E-VERDICT-STATUS" not in c
    assert any("not in payload_refs of any tool_invocation_end" in i.msg for i in R.errors if i.code == "E-SARIF-REF")


def test_reproduced_black_box_fail_is_proof_without_an_eligible_analyst(b, keys):
    """v0.3 (A2, H-A3): a reproduced deterministic FAIL of a G4-approved black-box testcase has a pre-registered
    interpretation, so it is E_proof even when the analyst is of the cluster's family (v0.2: E_fail_u)."""
    from vchlib.derive import Index, classify_result
    tr = doc(b, "testresult.llm-pass.example.json").data
    tr.update(outcome="FAIL", fail_oracles=["TOOL_CALL_LOG"], trials={"n": 60, "k": 3}, replays=20, replay_k=2,
              interpreted_by={"agent_id": "result_analyst_a", "family": "anthropic"})    # K-011 is anthropic: not eligible
    for e in doc(b, "audit-event.run-2026-09-23-001.example.jsonl").data:                 # v0.7 (r8 F2a): the executor saw the FAIL
        if e["event_type"] == "sandbox_job_end" and e["payload"].get("job_id") == tr["job_id"]:
            e["payload"]["outcome"] = "FAIL"
    ix = Index(b)
    assert classify_result(ix, tr, ix.first("cluster", cluster_id="K-011").data)[0] == "E_proof"
    tr["fail_oracles"] = ["LLM_GRADER"]                 # only a non-deterministic oracle saw the violation
    assert classify_result(ix, tr, ix.first("cluster", cluster_id="K-011").data) ==         ("E_inc", "violation judged only by a non-deterministic oracle")


def test_tool_signal_from_e_fail_u(b, keys):
    """E_fail_u (a reproduced W4 FAIL without pre-registration or an eligible analyst) is a WEAK tool signal
    (v0.3): it goes to tool_signal and counts as one independent source; it never confirms on its own."""
    from vchlib.checks import Ctx, derived_independent_sources, derived_tool_signal, verdict_inputs
    from vchlib.adjudicate import adjudicate
    from vchlib.bundle import Doc
    # v0.5 (BL-27): the W4 test is a w4-testcase (a scripted fake model), without an oracle_can_pass control,
    # so the FAIL is not pre-registered; its analyst shares K-011's family (not eligible)
    # v0.7 (r8, 05-v0.7): an E_fail_u is a source only when the test's authors are outside the cluster, so the W4
    # test generator / critic (anthropic in agents.yaml, K-011's family) are moved to nvidia for this test
    for a in doc(b, "agents.yaml").data.values():
        if isinstance(a, dict) and a.get("role") in ("test_generator", "test_critic"):
            a["model"] = "nemotron_self"
    wtc = copy.deepcopy(doc(b, "w4-testcase.k-015.example.json").data)
    wtc.update(testcase_id="WTC-011-01", cluster_ids=["K-011"], requirement_ids=["INV-LLM-003"], kind="fake_model",
               oracle={"types": ["TOOL_CALL_LOG"], "conditions": ["refund called without confirmation"], "requirement_refs": ["INV-LLM-003"]})
    wtc["environment"]["database"] = None
    wtc["controls"] = [x for x in wtc["controls"] if x["kind"] == "reachability"]
    b.docs.append(Doc("docs/schemas/examples/w4-testcase.k-011.example.json", "w4-testcase", wtc, None))
    w4 = copy.deepcopy(doc(b, "testresult.w4-k-015.example.json").data)
    w4.update(result_id="R-WTC-011-01-1", testcase_id="WTC-011-01", cluster_ids=["K-011"], fail_oracles=["TOOL_CALL_LOG"],
              controls=[{"control_id": "CTL-01", "outcome": "PASS"}],
              interpreted_by={"agent_id": "result_analyst_a", "family": "anthropic"},
              interpretation={"agrees": True, "rationale": "同家族分析者（不合格）"})
    b.docs.append(Doc("docs/schemas/examples/testresult.w4.example.json", "testresult", w4, None))
    # v0.7 (r8 F2a): a W4 result is evidence only with its anchored sandbox_job_end (pins re-derived by rederive)
    evs = doc(b, "audit-event.run-2026-09-23-001.example.jsonl").data
    i = next(n for n, e in enumerate(evs) if e["event_type"] == "sandbox_job_end" and e["payload"].get("result_id") == "R-WTC-015-01-1")
    end = copy.deepcopy(evs[i])
    end["idempotency_key"] = end["idempotency_key"].replace("WTC-015-01", "WTC-011-01")
    end["payload"].update(job_id="w4-WTC-011-01-1", testcase_id="WTC-011-01", result_id="R-WTC-011-01-1", outcome="FAIL")
    evs.insert(i + 1, end)
    for n, e in enumerate(evs):
        e["seq"] = n + 1
    reload_json(doc(b, "audit-event.run-2026-09-23-001.example.jsonl"),
                "".join(json.dumps(e, ensure_ascii=False, separators=(",", ":")) + "\n" for e in evs))
    rederive(b, keys)
    c = Ctx(b)
    v = doc(b, "verdict.k-011-b5.example.json").data
    cl = c.ix.first("cluster", cluster_id="K-011").data
    classes = [r["class"] for r in v["test_evidence"]["results"]]
    assert "E_fail_u" in classes and v["test_evidence"]["class"] == "E_fail_u"
    ref = next(r["result_ref"] for r in v["test_evidence"]["results"] if r["class"] == "E_fail_u")
    assert derived_tool_signal(c, v, cl) == [ref] and derived_independent_sources(c, v, cl) == 2
    out = adjudicate(verdict_inputs(c, v, cl))
    assert out.row == 12 and out.rules[:2] == ["R2", "R6"]     # LIKELY via the extra source
    # v0.4: the B5 PASS (TC-031-01) has no oracle_can_fail control, so R11 only annotates (no downgrade to DISPUTED)
    assert out.status == "LIKELY" and out.rules[-1] == "R11" and "test_not_reproduced" in out.annotations
    assert {"E-VERDICT-TOOLSIGNAL", "E-VERDICT-SOURCES", "E-VERDICT-STATUS"} <= run_all(b).codes()


# ================================================================ 2 strict JSON
def test_jsonstrict_rejects_duplicates_and_nan():
    assert jsonstrict.loads('{"a": {"b": 1}}') == {"a": {"b": 1}}
    with pytest.raises(jsonstrict.StrictJSONError, match="duplicate key 'b'"):
        jsonstrict.loads('{"a": {"b": 1, "b": 2}}')
    with pytest.raises(jsonstrict.StrictJSONError):
        jsonstrict.loads('{"a": NaN}')


def test_duplicate_key_in_signed_gate_record(b):
    d = doc(b, G1)
    assert '"outcome": "APPROVED",' in d.text
    reload_json(d, d.text.replace('"outcome": "APPROVED",', '"outcome": "REJECTED",\n  "outcome": "APPROVED",', 1))
    R = run_all(b)
    hits = [i for i in R.errors if i.code == "E-JSON-STRICT"]
    assert hits and "duplicate key 'outcome'" in hits[0].msg and "signatures" in hits[0].msg


def test_duplicate_key_in_audit_line(b):
    d = doc(b, AUDIT)
    lines = read_jsonl_lines(d.text)
    lines[5] = lines[5].replace('"zone":"Z1",', '"zone":"Z3","zone":"Z1",', 1)
    reload_json(d, "".join(ln + "\n" for ln in lines))
    assert "E-JSON-STRICT" in codes(b)


def test_reload_json_roundtrip_is_clean(b):
    d = doc(b, G1)
    reload_json(d, d.text)
    assert "E-JSON-STRICT" not in codes(b)


# ================================================================ 3 audit tail anchors
def test_run_anchors_name_anchor_lines(b):
    d, run = doc(b, AUDIT), doc(b, RUN).data
    last = run["audit_anchors"][-1]
    assert last == {"seq": len(d.data), "line_sha256": line_sha(d.text, len(d.data))}
    R = run_all(b)
    assert not [i for i in R.errors if i.code.startswith("E-AUDIT")]


def test_truncated_log_is_detected(b):
    d = doc(b, AUDIT)
    evs = copy.deepcopy(d.data)[:-2]                  # drop status change + final anchor, chain intact
    reload_json(d, rechain(evs))
    c = codes(b)
    assert "E-AUDIT-TRUNCATED" in c and "E-AUDIT-CHAIN" not in c


def test_rewritten_final_anchor_line_is_detected(b):
    d = doc(b, AUDIT)
    evs = copy.deepcopy(d.data)
    evs[-1]["ts"] = "2026-10-06T12:02:00+08:00"
    reload_json(d, rechain(evs))
    c = codes(b)
    assert "E-AUDIT-ANCHOR-MISMATCH" in c and "E-AUDIT-CHAIN" not in c


def test_line_after_final_anchor_on_terminal_run(b):
    d = doc(b, AUDIT)
    evs = copy.deepcopy(d.data)
    extra = copy.deepcopy(evs[-2])
    extra.update(seq=len(evs) + 1, event_type="artifact_stored", payload={"artifact": "late"})
    reload_json(d, rechain(evs + [extra]))
    c = codes(b)
    assert "E-AUDIT-TAIL" in c and "E-AUDIT-CHAIN" not in c


def test_missing_final_anchor_in_run_record(b):
    """Dropping an anchor from the run record is E-AUDIT-ANCHOR (the log's anchor event is still there,
    so the log itself has no unanchored tail)."""
    doc(b, RUN).data["audit_anchors"].pop()
    assert codes(b) == {"E-AUDIT-ANCHOR"}


def test_dropped_middle_anchor_in_run_record(b):
    del doc(b, RUN).data["audit_anchors"][2]
    R = run_all(b)
    assert R.codes() == {"E-AUDIT-ANCHOR"}
    assert any("missing" in i.msg for i in R.errors)


def test_terminal_tail_is_reported_once(b):
    d = doc(b, AUDIT)
    evs = copy.deepcopy(d.data)
    extra = copy.deepcopy(evs[-2])
    extra.update(seq=len(evs) + 1, event_type="artifact_stored", payload={"artifact": "late"})
    reload_json(d, rechain(evs + [extra]))
    tails = [i for i in run_all(b).errors if i.code == "E-AUDIT-TAIL"]
    assert len(tails) == 1
    assert "1 line(s) after the last audit_anchor" in tails[0].msg and "not an audit_anchor" in tails[0].msg


def test_anchor_must_name_an_anchor_event(b):
    d, run = doc(b, AUDIT), doc(b, RUN).data
    run["audit_anchors"][0] = {"seq": 6, "line_sha256": line_sha(d.text, 6)}   # seq 6 is a gate_decision
    assert "E-AUDIT-ANCHOR" in codes(b)


def test_dropped_anchor_on_running_run_is_an_error(b):
    """Previously a warning: dropping the last run.audit_anchors entry now fails E-AUDIT-ANCHOR."""
    run = doc(b, RUN_A).data
    run["audit_anchors"].pop()
    run["status"] = "RUNNING"
    run["current_node"] = "W3"
    R = run_all(b)
    assert R.codes() == {"E-AUDIT-ANCHOR"}
    assert "W-AUDIT-UNANCHORED-TAIL" not in {w.code for w in R.warnings}


def test_unanchored_tail_on_running_run_is_a_warning(b):
    """Genuine tail: events appended after the log's last audit_anchor, run still RUNNING."""
    d, run = doc(b, AUDIT_A), doc(b, RUN_A).data
    evs = copy.deepcopy(d.data)
    extra = copy.deepcopy(next(e for e in reversed(evs) if e["event_type"] != "audit_anchor"))
    extra.update(seq=len(evs) + 1, ts=evs[-1]["ts"], event_type="artifact_stored",
                 payload={"artifact": "late"}, payload_refs=[], signature=None,
                 idempotency_key=f"{extra['run_id']}:{extra['node']}:artifact_stored:late-1",
                 actor={"kind": "system", "id": "run-controller"})
    extra2 = dict(copy.deepcopy(extra), seq=len(evs) + 2, idempotency_key=f"{extra['run_id']}:{extra['node']}:artifact_stored:late-2")
    reload_json(d, rechain(evs + [extra, extra2]))
    run["status"] = "RUNNING"
    run["current_node"] = "W3"
    R = run_all(b)
    tails = [w for w in R.warnings if w.code == "W-AUDIT-UNANCHORED-TAIL"]
    assert len(tails) == 1 and "2 line(s)" in tails[0].msg
    assert R.codes() == set()


def test_fully_anchored_running_run_has_no_tail_warning(b):
    run = doc(b, RUN_A).data
    run["status"] = "RUNNING"
    run["current_node"] = "W3"
    assert "W-AUDIT-UNANCHORED-TAIL" not in warn_codes(b)


def test_terminal_run_without_audit_log(b):
    b.docs = [d for d in b.docs if not d.path.endswith(AUDIT_A)]
    doc(b, RUN_A).data["audit_anchors"] = []
    assert "E-AUDIT-TAIL" in codes(b)


# ================================================================ 4 retention precedence
def test_engagement_retention_at_the_toolkit_maximum_is_ok(b):
    lim = doc(b, "toolkit.yaml").data["retention"]["c_days_after_run_end"]
    doc(b, "engagement.yaml").data["retention_days"] = lim
    assert "E-RETENTION" not in codes(b)


def test_engagement_retention_above_the_toolkit_maximum(b):
    lim = doc(b, "toolkit.yaml").data["retention"]["c_days_after_run_end"]
    doc(b, "engagement.yaml").data["retention_days"] = lim + 1
    assert "E-RETENTION" in codes(b)


def test_roe_may_only_shorten_retention(b):
    doc(b, "roe.yaml").data["data_handling"]["retention_days"] = 10
    assert not {"E-RETENTION", "E-ROE-RETENTION"} & codes(b)
    doc(b, "roe.yaml").data["data_handling"]["retention_days"] = 31
    assert "E-ROE-RETENTION" in codes(b)


def test_lower_toolkit_maximum_binds_engagement_and_roe(b):
    doc(b, "toolkit.yaml").data["retention"]["c_days_after_run_end"] = 20
    errs = [i for i in run_all(b).errors if i.code == "E-RETENTION"]
    assert {i.where for i in errs} == {"engagement.yaml", "roe.yaml"}


# ================================================================ 5 DB target scope
def test_endpoint_host_parsing():
    assert safety.endpoint_host("db.staging.example.com:5432") == "db.staging.example.com"
    assert safety.endpoint_host("[2001:db8::1]:5432") == "2001:db8::1"
    assert safety.target_host({"kind": "database", "endpoint": "DB.x:1", "base_url": None}) == "db.x"
    assert not safety.host_excluded("", [""])
    # roe.schema.json endpoint forms only: bare host, trailing dot, unclosed / unbracketed IPv6 -> None
    for bad in ("db.x", "db.x.:5432", "[::1", "::1:5432", "a..b:1", "", None, 5432):
        assert safety.endpoint_host(bad) is None, bad


def test_db_target_in_exclusions(b):
    doc(b, "roe.yaml").data["exclusions"]["hosts"] = ["DB.Staging.Example.com"]
    errs = [i for i in run_all(b).errors if i.code == "E-ROE-DB-SCOPE"]
    assert len(errs) == 2                            # the database target and db_access


def test_unrelated_host_exclusion_is_fine(b):
    doc(b, "roe.yaml").data["exclusions"]["hosts"] = ["legacy.example.com"]
    assert "E-ROE-DB-SCOPE" not in codes(b)


def test_db_access_outside_scope(b):
    doc(b, "roe.yaml").data["db_access"]["endpoint"] = "prod-db.example.com:5432"
    assert "E-ROE-DB-SCOPE" in codes(b)


def test_safety_class_excludes_db_host(b):
    roe = doc(b, "roe.yaml").data
    tools = doc(b, "tools.yaml").data
    tc = dict(doc(b, TC_IDOR).data, target_ids=["tgt-staging-api", "tgt-staging-db"])
    _, before = safety.compute_safety_class(tc, roe, tools, None)
    assert not any("excluded host" in x for x in before)
    roe["exclusions"]["hosts"] = ["db.staging.example.com"]
    level, trace = safety.compute_safety_class(tc, roe, tools, None)
    assert level == "S3" and trace == ["tgt-staging-db: excluded host"]


# ================================================================ 6 placeholder model IDs
def test_placeholder_marked_model_warns(b):
    m = doc(b, "models.yaml").data["gpt_flagship"]
    m.update(litellm="openai/<GPT-6 model ID>", placeholder=True)
    R = run_all(b)
    hits = [w for w in R.warnings if w.code == "W-MODEL-PLACEHOLDER"]
    assert any("gpt_flagship" in f"{w.where} {w.msg}" for w in hits)
    assert "E-MODEL-PLACEHOLDER" not in R.codes()


def test_unmarked_placeholder_is_an_error(b):
    doc(b, "models.yaml").data["gpt_flagship"]["litellm"] = "openai/<GPT-6 model ID>"
    assert "E-MODEL-PLACEHOLDER" in codes(b)


def test_confirmed_model_id_drops_the_warning(b):
    m = doc(b, "models.yaml").data
    for k in ("gpt_flagship", "nemotron_cloud"):
        m[k]["litellm"] = m[k]["litellm"].split("/")[0] + "/confirmed-id"
        m[k]["placeholder"] = False
    assert "W-MODEL-PLACEHOLDER" not in warn_codes(b)
