"""Review fixes (v0.2.1): audit-backed SARIF refs, strict JSON numbers, audit anchor completeness,
host normalisation, unparseable endpoints, placeholder models / --real-run, JSONL line splitting,
verifier-only votes. Each rule has a positive and a negative case."""
import copy
import json

import pytest

import sign_examples
from conftest import codes, doc, rederive
from vchlib import checks, cli, jsonstrict, safety
from vchlib.bundle import read_jsonl_lines, reload_json
from vchlib.checks import run_all

AUDIT = "audit-event.run-2026-09-23-001.example.jsonl"
RUN = "examples/run.example.json"
K014 = "cluster.k-014.example.json"
V014 = "verdict.k-014-w3.example.json"
TC_IDOR = "testcase.idor.example.json"


def tool_end(b):
    return next(e for e in doc(b, AUDIT).data if e["event_type"] == "tool_invocation_end")


# ================================================================ 1 E-SARIF-REF
def test_rederive_is_a_noop_on_the_examples(b, keys):
    before = {d.path: d.text for d in b.docs}
    rederive(b, keys)
    assert codes(b) == set()
    assert {d.path: d.text for d in b.docs if d.path.endswith(".jsonl")} == {p: t for p, t in before.items() if p.endswith(".jsonl")}


@pytest.mark.parametrize("mutate, why", [
    (lambda e: e["payload"].update(ok=False), "failed"),
    (lambda e: e["payload"].pop("ok"), "failed"),
    (lambda e: e["payload"].update(adapter="zap:active"), "not a white-box/static tool"),
    (lambda e: e["payload"].update(adapter="semgrep:nope"), "not a registered"),
    (lambda e: e.update(zone="Z3"), "not Z2"),
    (lambda e: e.update(event_type="tool_invocation_start"), "not in payload_refs of any tool_invocation_end"),
    (lambda e: e.update(payload_refs=[]), "not in payload_refs of any tool_invocation_end"),
])
def test_sarif_ref_needs_a_successful_whitebox_invocation(b, mutate, why):
    mutate(tool_end(b))
    R = run_all(b)
    hits = [i for i in R.errors if i.code == "E-SARIF-REF"]
    assert hits and why in hits[0].msg and hits[0].where.endswith(K014)
    # the unresolved ref no longer corroborates: V-014-1 is re-derived as UNCORROBORATED (R7)
    assert {"E-VERDICT-TOOLCORR", "E-VERDICT-STATUS"} <= R.codes()


def test_sarif_ref_without_audit_log(b):
    b.docs = [d for d in b.docs if not d.path.endswith(AUDIT)]
    hits = [i for i in run_all(b).errors if i.code == "E-SARIF-REF"]
    assert hits and "no (loadable) audit log" in hits[0].msg


def test_sarif_refs_and_tool_corroboration_are_unique(b):
    cl, v = doc(b, K014).data, doc(b, V014).data
    cl["sarif_refs"] = cl["sarif_refs"] * 2
    v["tool_corroboration"] = v["tool_corroboration"] * 2
    errs = [i for i in run_all(b).errors if i.code == "E-SCHEMA"]
    assert {i.where.rsplit("/", 1)[-1] for i in errs} >= {K014, V014}
    assert all("non-unique" in i.msg for i in errs)


def test_tool_corroboration_is_compared_as_a_list(b):
    v = doc(b, V014).data
    v["tool_corroboration"] = v["tool_corroboration"] * 2      # a set compare would accept this
    assert "E-VERDICT-TOOLCORR" in codes(b)


# ================================================================ 2 strict JSON numbers
@pytest.mark.parametrize("text", ["1e400", "-1e400", "[1e400]", '{"a": -1E+999}', str(2 ** 53 + 1), str(-(2 ** 53 + 1)), "1" * 5000])
def test_jsonstrict_rejects_non_finite_and_unsafe_numbers(text):
    with pytest.raises(jsonstrict.StrictJSONError):
        jsonstrict.loads(text)


def test_jsonstrict_accepts_the_safe_range():
    assert jsonstrict.loads(str(2 ** 53)) == 2 ** 53
    assert jsonstrict.loads(str(-(2 ** 53))) == -(2 ** 53)
    assert jsonstrict.loads("1.7976931348623157e308") == 1.7976931348623157e308
    v = jsonstrict.loads("3e0")
    assert v == 3 and type(v) is float                        # stays a float: never silently an integer


def test_overflowing_number_in_audit_line_rejects_the_log(b):
    d = doc(b, AUDIT)
    lines = read_jsonl_lines(d.text)
    lines[0] = lines[0].replace('"seq":1,', '"seq":1e400,', 1)
    reload_json(d, "".join(ln + "\n" for ln in lines))
    assert d.load_error and "non-finite" in d.load_error
    assert "E-JSON-STRICT" in codes(b)


def test_float_seq_is_rejected(b):
    d = doc(b, AUDIT)
    lines = read_jsonl_lines(d.text)
    assert '"seq":3,' in lines[2]
    lines[2] = lines[2].replace('"seq":3,', '"seq":3e0,', 1)
    reload_json(d, "".join(ln + "\n" for ln in lines))
    assert d.load_error is None and type(d.data[2]["seq"]) is float
    R = run_all(b)
    seq = [i for i in R.errors if i.code == "E-AUDIT-SEQ"]
    assert seq and "3.0" in seq[0].msg
    assert any("seq" in i.msg and "integer" in i.msg for i in R.errors if i.code == "E-SCHEMA")


def test_float_in_integer_schema_field_is_rejected(b):
    d = doc(b, "testresult.llm-pass.example.json")
    reload_json(d, d.text.replace('"n": 60,', '"n": 60.0,', 1))
    errs = [i for i in run_all(b).errors if i.code == "E-SCHEMA"]
    assert any("trials.n" in i.msg and "integer" in i.msg for i in errs)


def test_bool_is_not_an_integer():
    assert checks._strict_integer(None, 3) and not checks._strict_integer(None, 3.0) and not checks._strict_integer(None, True)


# ================================================================ 3 broken audit log short-circuit
def test_broken_audit_log_reports_only_the_load_error_in_the_audit_group(b):
    d = doc(b, AUDIT)
    lines = read_jsonl_lines(d.text)
    lines[5] = lines[5].replace('"zone":"Z1",', '"zone":"Z3","zone":"Z1",', 1)
    reload_json(d, "".join(ln + "\n" for ln in lines))
    R = run_all(b)
    c = R.codes()
    assert "E-JSON-STRICT" in c
    audit_codes = {x for x in c if x.startswith("E-AUDIT")}
    assert audit_codes == set(), audit_codes
    assert "E-RUN-RESTORE-DRILL" not in c
    assert len([i for i in R.errors if i.code == "E-JSON-STRICT"]) == 1


# ================================================================ 4 host normalisation
def test_norm_host():
    assert safety.norm_host("API.Example.com.") == "api.example.com"
    assert safety.norm_host("Bücher.example") == "xn--bcher-kva.example"
    assert safety.host_excluded("db.x.", ["DB.X"]) and safety.host_excluded("db.x", ["db.x."])
    assert safety.host_of("https://API.staging.example.com./v1") == "api.staging.example.com"
    assert safety.host_of("http://[::1") is None and safety.host_of("") is None


@pytest.mark.parametrize("excl", ["db.staging.example.com.", "DB.STAGING.EXAMPLE.COM", "db.staging.example.com.."])
def test_db_exclusion_trailing_dot_bypass(b, excl):
    doc(b, "roe.yaml").data["exclusions"]["hosts"] = [excl]
    errs = [i for i in run_all(b).errors if i.code == "E-ROE-DB-SCOPE"]
    assert len(errs) == 2                                   # the database target and db_access
    assert any("[exclusion rule]" in i.msg for i in errs)


def test_base_url_exclusion_trailing_dot_bypass(b):
    roe = doc(b, "roe.yaml").data
    tools = doc(b, "tools.yaml").data
    tc = doc(b, TC_IDOR).data
    roe["exclusions"]["hosts"] = ["api.staging.example.com."]
    level, trace = safety.compute_safety_class(tc, roe, tools, None)
    assert level == "S3" and trace == ["tgt-staging-api: excluded host"]
    assert "E-ROE-TARGETS" in codes(b)
    # and the other way round: trailing dot on the target, plain name in the exclusions
    roe["exclusions"]["hosts"] = ["api.staging.example.com"]
    t = next(x for x in roe["targets"] if x["id"] == "tgt-staging-api")
    t["base_url"] = "https://API.staging.example.com./"
    level, trace = safety.compute_safety_class(tc, roe, tools, None)
    assert level == "S3" and trace == ["tgt-staging-api: excluded host"]


# ================================================================ 5 unparseable endpoints
@pytest.mark.parametrize("endpoint", ["[::1", "::1:5432", "db.staging.example.com", "db.staging.example.com.:5432"])
def test_unparseable_endpoint_is_reported_not_internal(b, endpoint):
    roe = doc(b, "roe.yaml").data
    next(t for t in roe["targets"] if t["kind"] == "database")["endpoint"] = endpoint
    roe["db_access"]["endpoint"] = endpoint
    roe["data_handling"]["retention_days"] = 31             # the rest of the ROE group still runs
    R = run_all(b)
    c = R.codes()
    assert "E-INTERNAL" not in c
    scope = [i for i in R.errors if i.code == "E-ROE-DB-SCOPE"]
    assert len([i for i in scope if "unparseable endpoint" in i.msg]) == 2
    assert "E-ROE-RETENTION" in c and "E-SCHEMA" in c        # pattern rejects it as well


def test_ipv6_endpoint_is_accepted(b):
    roe = doc(b, "roe.yaml").data
    next(t for t in roe["targets"] if t["kind"] == "database")["endpoint"] = "[2001:db8::1]:5432"
    roe["db_access"]["endpoint"] = "[2001:db8::1]:5432"
    c = codes(b)
    assert not {"E-SCHEMA", "E-ROE-DB-SCOPE", "E-ROE-DB", "E-INTERNAL"} & {x for x in c if x != "E-DERIVED" and not x.startswith("E-SIG")}


def test_unparseable_target_host_is_s3(b):
    roe = doc(b, "roe.yaml").data
    tools = doc(b, "tools.yaml").data
    next(t for t in roe["targets"] if t["id"] == "tgt-staging-api")["base_url"] = "https://[::1"
    level, trace = safety.compute_safety_class(doc(b, TC_IDOR).data, roe, tools, None)
    assert level == "S3" and trace == ["tgt-staging-api: unparseable target host"]


# ================================================================ 9 placeholder models / --real-run
@pytest.mark.parametrize("lit", ["openai/TBD", "openai/{model-id}", "openai/<id>", "nvidia_nim/todo", "x/FIXME-later", "x/模型（實作時確認）"])
def test_placeholder_pattern_matches(lit):
    assert checks.PLACEHOLDER_ID.search(lit)


@pytest.mark.parametrize("lit", ["openai/gpt-5", "anthropic/claude-sonnet-4-5", "x/tbdx", "x/stodo"])
def test_placeholder_pattern_ignores_real_ids(lit):
    assert not checks.PLACEHOLDER_ID.search(lit)


@pytest.mark.parametrize("lit", ["openai/TBD", "openai/{model-id}"])
def test_unmarked_widened_placeholder_is_an_error(b, lit):
    m = doc(b, "models.yaml").data["gpt_flagship"]
    m["litellm"] = lit
    m.pop("placeholder")
    assert "E-MODEL-PLACEHOLDER" in codes(b)
    m["placeholder"] = True
    assert "E-MODEL-PLACEHOLDER" not in codes(b)


def test_real_run_escalates_reachable_placeholders(b):
    R = run_all(b, real_run=True)
    errs = [i for i in R.errors if i.code == "E-MODEL-PLACEHOLDER"]
    assert [i.where for i in errs] == ["models.yaml gpt_flagship"]          # rev_b, reporter fallback, ...
    assert "[--real-run]" in errs[0].msg
    # nemotron_cloud is not reachable from any agent: still only a warning
    assert [w.where for w in R.warnings if w.code == "W-MODEL-PLACEHOLDER"] == ["models.yaml nemotron_cloud"]


def test_real_run_follows_fallback_chains(b):
    models, agents = doc(b, "models.yaml").data, doc(b, "agents.yaml").data
    models["gpt_flagship"].update(litellm="openai/gpt-confirmed", placeholder=False)
    assert "E-MODEL-PLACEHOLDER" not in run_all(b, real_run=True).codes()
    agents["reporter"]["fallback_models"] = ["nemotron_cloud"]           # now reachable (agent fallback)
    errs = [i for i in run_all(b, real_run=True).errors if i.code == "E-MODEL-PLACEHOLDER"]
    assert any(i.where == "models.yaml nemotron_cloud" for i in errs)


def test_cli_real_run_flag(capsys):
    assert cli.main(["--quiet"]) == 0
    assert cli.main(["--quiet", "--real-run"]) == 1
    assert "E-MODEL-PLACEHOLDER models.yaml gpt_flagship" in capsys.readouterr().out


# ================================================================ 14 JSONL line splitting
def test_sign_examples_splits_on_newline_only():
    ev = {"seq": 1, "payload": {"note": "a\u2028b\u2029c\x85d\x0be"}}
    text = sign_examples.dump_jsonl([ev, dict(ev, seq=2)])
    assert "\u2028" in text and len(text.splitlines()) > 2        # what the old code would have split
    events = sign_examples.load_events(text)
    assert [e["seq"] for e in events] == [1, 2] and events[0]["payload"]["note"] == ev["payload"]["note"]
    assert len(read_jsonl_lines(text)) == 2


def test_u2028_in_audit_payload_keeps_the_chain(b, keys):
    d = doc(b, AUDIT)
    tool_end(b)["payload"]["note"] = "line\u2028separator"
    rederive(b, keys)
    assert "\u2028" in d.text
    assert codes(b) == set()


# ================================================================ 19 verifier-only votes
def test_non_verifier_vote_is_ignored_and_reported(b, keys):
    v = doc(b, V014).data
    v["votes"][0].update(voter_agent_id="rev_c")           # reviewer role, same model nemotron_self
    rederive(b, keys)
    assert v["votes"][0]["weighted_valid"] is False and v["score"] == 0.0
    R = run_all(b)
    assert R.codes() == {"E-VERDICT-VOTER-ROLE", "E-VERDICT-DIVERSITY"}   # only openai left -> degraded
    assert any("rev_c" in i.msg and "'reviewer'" in i.msg for i in R.errors if i.code == "E-VERDICT-VOTER-ROLE")
    v["diversity_degraded"] = True
    assert codes(b) == {"E-VERDICT-VOTER-ROLE"}


def test_verifier_votes_have_no_role_error(b):
    assert "E-VERDICT-VOTER-ROLE" not in codes(b)
