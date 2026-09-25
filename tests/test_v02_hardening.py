"""v0.2 hardening: derived verdict flags, strict JSON, audit tail anchors, retention precedence,
DB target scope, placeholder model IDs. Each rule has a positive and a negative case."""
import copy
import hashlib
import json

import pytest

from conftest import codes, doc, rederive
from vchlib import jsonstrict, safety
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
    for suffix, want in ((V_W3, True), (V_K011, True), ("verdict.executable.example.json", True), (V_LANE_A, False),
                         ("verdict.k-014-w3.example.json", False)):         # nvidia + openai valid votes
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


def test_two_valid_families_are_not_degraded(b, keys):
    v = doc(b, V_K011).data
    _add_gpt_oss_vote(v)
    rederive(b, keys)                                  # G2 item hash / signatures follow the new vote
    assert codes(b) == {"E-VERDICT-DIVERSITY"}         # still declared true: the only error
    v["diversity_degraded"] = False
    rederive(b, keys)
    assert codes(b) == set()


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


def test_tool_corroboration_from_sarif_refs(b):
    """The K-014 example: its SARIF ref is backed by a successful semgrep:scan tool_invocation_end."""
    cl = doc(b, "cluster.k-014.example.json").data
    v = doc(b, "verdict.k-014-w3.example.json").data
    assert cl["sarif_refs"] and v["tool_corroboration"] == cl["sarif_refs"]
    assert v["diversity_degraded"] is False and v["status"] == "CONFIRMED_CORROBORATED"
    ends = [e for e in doc(b, AUDIT).data if e["event_type"] == "tool_invocation_end"]
    assert any(cl["sarif_refs"][0] in e["payload_refs"] for e in ends)
    assert codes(b) == set()
    v["tool_corroboration"] = []                       # omitting the derived SARIF ref
    assert codes(b) == {"E-VERDICT-TOOLCORR"}


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


def test_tool_corroboration_from_e_fail_u(b, keys):
    """A reproduced FAIL interpreted by an ineligible (same-family) analyst is E_fail_u, which is
    tool corroboration (R2) -> row 10 CONFIRMED_CORROBORATED. Consistent change, exact error set."""
    tr = doc(b, "testresult.llm-pass.example.json").data
    tr.update(outcome="FAIL", trials={"n": 60, "k": 3}, replays=20, replay_k=2,
              interpreted_by={"agent_id": "rev_a", "family": "anthropic"})     # K-011 is anthropic: not eligible
    v = doc(b, "verdict.k-011-b5.example.json").data
    v.update(status="CONFIRMED_CORROBORATED", annotations=[],
             rule_trace=["R2:E_fail_u (TC-031-01 reproduced, analyst not eligible)", "R5:tool_corroboration->CONFIRMED_CORROBORATED"])
    for ev in doc(b, AUDIT).data:
        if (ev.get("payload") or {}).get("verdict_id") == "V-011-2":
            ev["payload"]["status"] = "CONFIRMED_CORROBORATED"
        if (ev.get("payload") or {}).get("job_id") == "job-llm-001" and ev["event_type"] == "sandbox_job_end":
            ev["payload"]["outcome"] = "FAIL"
    counts = doc(b, "report-manifest.example.json").data["verdict_counts"]
    counts["UNCORROBORATED"] -= 1
    counts["CONFIRMED_CORROBORATED"] += 1
    rederive(b, keys)
    assert v["test_evidence"]["class"] == "E_fail_u"
    ref = v["test_evidence"]["results"][0]["result_ref"]
    assert codes(b) == {"E-VERDICT-TOOLCORR"}          # declared [] but E_fail_u is derived corroboration
    v["tool_corroboration"] = [ref]
    rederive(b, keys)
    assert codes(b) == set()


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
                 payload={"artifact": "late"}, payload_refs=[], signature=None, idempotency_key=None,
                 actor={"kind": "system", "id": "run-controller"})
    reload_json(d, rechain(evs + [extra, dict(copy.deepcopy(extra), seq=len(evs) + 2)]))
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
