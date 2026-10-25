# SPDX-License-Identifier: Apache-2.0
"""v0.5 round 6, low-priority items (docs/evidence/review-2026-10-25.md §4.3). Positive and negative cases:

- validator robustness: deep nesting and lone surrogates are strict-load errors; Bundle.doc("") matches nothing;
  reporter.round is derived from the commander plans (E-FINDING-ROUND);
- adjudication: E(cluster) only counts verifiers allowed for the run's data class; g4_approved reads the latest G4
  decision of the testcase; a high-risk probabilistic PASS needs n' >= 60;
- trust anchors: the allow-list reference matcher; SUSPENDED resumes by the run owner / an initiator; spot checks
  are their own signed event;
- methodology: the S1 floor follows is_mutation; a white-box-only bundle needs no ROE; FAIL needs k >= fail_k_min;
  tool limits (E-TC-TOOL); attack trees (E-THREAT-ATTACK-TREE); D5 coverage (E-COVERAGE-D5); side-effect GETs
  are matched by path shape.
"""
import copy

import pytest

from conftest import codes, doc
from vchlib import checks, crypto, derive, jsonstrict, safety, yamlstrict
from vchlib.bundle import reload_json
from vchlib.checks import Ctx, run_all

AUDIT = "audit-event.run-2026-09-23-001.example.jsonl"


def errors(b, code, where=None):
    return [i for i in run_all(b).errors if i.code == code and (where is None or where in i.where)]


# ================================================================ robustness
# short ids: a 200 000-character test id overflows PYTEST_CURRENT_TEST on Windows (32 767-character environment limit)
@pytest.mark.parametrize("text", ["[" * 100000 + "]" * 100000, "[" * 70 + "]" * 70, '{"a": "\\ud800"}', '{"\\udc00": 1}'],
                         ids=["deep-100000", "deep-70", "surrogate-value", "surrogate-key"])
def test_strict_json_rejects_deep_nesting_and_lone_surrogates(text):
    with pytest.raises(jsonstrict.StrictJSONError):
        jsonstrict.loads(text)


@pytest.mark.parametrize("text", ['a: "\\ud800"', "a: " + "[" * 80 + "]" * 80], ids=["surrogate", "deep-80"])
def test_strict_yaml_rejects_deep_nesting_and_lone_surrogates(text):
    with pytest.raises(yamlstrict.StrictYAMLError):
        yamlstrict.load(text)


def test_ordinary_nesting_still_loads():
    assert jsonstrict.loads('{"a": [1, {"b": "ok"}]}') == {"a": [1, {"b": "ok"}]}


def test_a_lone_surrogate_in_an_example_is_a_load_error_not_internal(b):
    d = doc(b, "finding.f-052.example.json")
    reload_json(d, d.text.replace('"title": "', '"title": "\\ud800', 1))
    found = codes(b)
    assert "E-JSON-STRICT" in found and "E-INTERNAL" not in found


@pytest.mark.parametrize("ref", ["", "/", None, "example.json"])
def test_bundle_doc_needs_a_real_reference(b, ref):
    assert b.doc(ref) is None


def test_bundle_doc_still_finds_by_file_name(b):
    assert b.doc("roe.yaml").path.endswith("docs/examples/roe.yaml")


def test_reporter_round_is_derived(b):
    assert "E-FINDING-ROUND" not in codes(b)
    doc(b, "finding.f-052.example.json").data["reporter"]["round"] = 2      # no CMD-2 plan dispatched rev_a
    assert errors(b, "E-FINDING-ROUND", "f-052")


def test_round_one_needs_the_cmd1_dispatch(b):
    doc(b, "finding.f-052.example.json").data["reporter"]["agent_id"] = "rev_z"
    assert errors(b, "E-FINDING-ROUND", "f-052")


# ================================================================ adjudication
def test_eligible_verifiers_follow_the_data_class(b):
    c = Ctx(b)
    cl = c.ix.first("cluster", cluster_id="K-014").data
    before = set(checks.eligible_verifier_models(c, cl))
    assert before
    dc = c.runs[cl["run_id"]]["data_class"]
    allowed = doc(b, "engagement.yaml").data["allowed_models"][dc]
    drop = sorted(before)[0]
    allowed.remove(drop)
    assert drop not in checks.eligible_verifier_models(Ctx(b), cl)


def test_second_g4_round_keeps_earlier_approvals(b):
    g4 = doc(b, "gate-record.g4.example.json")
    second = copy.deepcopy(g4)
    second.path = second.path.replace("g4.example", "g4-round2.example")
    second.data.update(gate_record_id="GR-G4-0002", round=2, timestamp="2026-10-04T11:00:00+08:00")
    second.data["decisions"] = [dict(second.data["decisions"][0], item_id="TC-999-01")]
    b.docs.append(second)
    tr = doc(b, "testresult.example.json").data
    assert derive.g4_approved(Ctx(b).ix, tr)


def test_high_risk_pass_needs_sixty_effective_trials(b):
    tr = doc(b, "testresult.llm-pass.example.json").data
    ix = Ctx(b).ix
    cl = ix.first("cluster", cluster_id="K-011").data
    assert derive.classify_result(ix, tr, cl)[0] == "E_pass"
    tr["trials"]["n_effective"] = 45
    cls, why = derive.classify_result(Ctx(b).ix, tr, cl)
    assert cls == "E_inc" and "60" in why


# ================================================================ trust anchors
AL = [dict(target_id="t", method="DELETE", path="/api/invoices/{seed:b}"), dict(target_id="t", method="GET", path="/api/invoices/{id}")]
RES = {"{seed:b}": "inv-b-1"}


@pytest.mark.parametrize("method, path, ok", [
    ("DELETE", "/api/invoices/inv-b-1", True), ("DELETE", "/api/invoices/inv-a-1", False),
    ("GET", "/api/invoices/x", True), ("GET", "/api/invoices/%2e%2e", False), ("GET", "/api/invoices/../users", False),
    ("GET", "/api/invoices/", False), ("PUT", "/api/invoices/inv-b-1", False), ("DELETE", "/api/invoices/inv-b-1/x", False)])
def test_allowlist_match(method, path, ok):
    assert (safety.allowlist_match("t", method, path, AL, RES) is not None) is ok


def _resume(b, keys, who, from_status):
    evs = doc(b, AUDIT).data
    ev = dict(copy.deepcopy(evs[-1]), event_type="run_resume", actor={"kind": "human", "id": who}, signature=None,
              payload={"from_status": from_status, "reason": "test"}, seq=len(evs) + 1)
    ev["signature"] = crypto.sign_event(ev, who, keys[who])
    evs.append(ev)


def test_suspended_resume_by_a_non_initiator(b, keys):
    _resume(b, keys, "frank", "SUSPENDED")
    assert any("SUSPENDED run is resumed" in i.msg for i in errors(b, "E-AUDIT-ACTOR"))


def test_stopped_resume_needs_a_test_lead(b, keys):
    _resume(b, keys, "frank", "STOPPED")
    assert any("test_lead" in i.msg for i in errors(b, "E-SIG-ROLE"))


def test_spot_check_is_a_signed_human_event(b):
    evs = doc(b, AUDIT).data
    evs.append(dict(copy.deepcopy(evs[-1]), event_type="spot_check_result", actor={"kind": "human", "id": "erin"}, signature=None,
                    payload={"item_kind": "verdict", "item_id": "V-014-1", "outcome": "upheld", "note": None}, seq=len(evs) + 1))
    assert errors(b, "E-AUDIT-SIG")
    assert not errors(b, "E-AUDIT-GATE", AUDIT)


# ================================================================ methodology
def test_s1_floor_follows_is_mutation(b):
    """A seed-bound GET declared state-changing: no write method, so the S1 floor comes from is_mutation."""
    tc = copy.deepcopy(doc(b, "testcase.idor.example.json").data)
    tc["request_allowlist"] = [x for x in tc["request_allowlist"] if x["method"] == "GET"]   # seed-bound reads only
    man = copy.deepcopy(doc(b, "seed-manifest.yaml").data)
    r = tc["request_allowlist"][0]
    man["state_changing_reads"] = [dict(target_id=r["target_id"], method="GET", path_template=r["path"])]
    lv, trace = safety.compute_safety_class(tc, doc(b, "roe.yaml").data, doc(b, "tools.yaml").data, man)
    assert lv == "S1" and any("mutation on a read method" in t for t in trace), trace


def test_white_box_only_bundle_needs_no_roe(b):
    black = ("roe.yaml", "testcase.", "testresult.", "threat.", "gate-record.g0b", "gate-record.followup.g0b",
             "gate-record.g3", "gate-record.g4", "gate-record.g5")
    b.docs[:] = [d for d in b.docs if not any(x in d.path for x in black)]
    for d in b.docs:
        if d.kind == "run":
            d.data["jobs"] = {}
    assert "E-ROE-MISSING" not in codes(b)


def test_black_box_bundle_still_needs_the_roe(b):
    b.docs[:] = [d for d in b.docs if not d.path.endswith("roe.yaml")]
    assert "E-ROE-MISSING" in codes(b)


def test_fail_below_fail_k_min(b):
    doc(b, "testcase.idor.example.json").data["trials"]["fail_k_min"] = 2      # the FAIL result has k = 1
    assert any("fail_k_min" in i.msg for i in errors(b, "E-RESULT-TRIALS"))


def test_schemathesis_only_reads(b):
    tc = doc(b, "testcase.idor.example.json").data
    tc["tool_binding"]["adapter"] = "schemathesis:check"
    assert any("GET / HEAD" in i.msg for i in errors(b, "E-TC-TOOL"))


def test_zap_baseline_needs_safe_mode(b):
    tb = doc(b, "testcase.zap-active.example.json").data["tool_binding"]
    tb["adapter"] = "zap:baseline"
    assert any("safe_mode" in i.msg for i in errors(b, "E-TC-TOOL"))
    tb["params"]["safe_mode"] = True
    assert not errors(b, "E-TC-TOOL")


def test_high_risk_threat_needs_its_attack_tree(b):
    t = doc(b, "threat.example.json").data                                  # T-012, high / high
    t["attack_tree_ref"] = None
    assert errors(b, "E-THREAT-ATTACK-TREE", "threat.example")
    t["attack_tree_ref"] = "attack-trees/T-031.json"
    assert any("this threat's tree" in i.msg for i in errors(b, "E-THREAT-ATTACK-TREE"))


def test_accepted_threat_without_a_testcase(b):
    b.docs[:] = [d for d in b.docs if not d.path.endswith("testcase.zap-active.example.json")]
    assert any("T-027" in i.msg for i in errors(b, "E-COVERAGE-D5"))


def test_examples_have_full_coverage(b):
    found = codes(b)
    for code in ("E-COVERAGE-D5", "E-THREAT-ATTACK-TREE", "E-TC-TOOL", "E-FINDING-ROUND", "E-ROE-MISSING"):
        assert code not in found, code


def test_side_effect_get_is_matched_by_path_shape(b):
    inv = doc(b, "inventory.example.json").data
    ep = next(e for e in inv["endpoints"] if e["method"] == "GET")
    ep["writes"] = True
    man = doc(b, "seed-manifest.yaml").data
    man["state_changing_reads"] = [dict(target_id="tgt-staging-api", method="GET",
                                        path_template=checks.path_shape(ep["path"]).replace("{}", "{renamed}"))]
    assert not [i for i in errors(b, "E-SEED-SIDE-EFFECT") if ep["path"] in i.msg]
