# SPDX-License-Identifier: Apache-2.0
"""D3 of the 2026-11-22 review (rule_version 05-v0.17, user decision): a person approves the oracle of an LLM-written W4
test after W4, item by item, in the G3 record (`oracle_approvals`).

05-v0.15 / 05-v0.16 took the cluster's G2 `accept` as the pre-registration of such a test. G2 comes before W4: the test
did not exist when the person accepted the cluster, so nobody had read the oracle whose FAIL then confirmed it
(CONFIRMED_EXECUTABLE). Now:

  - the G2 decision no longer changes the class of any test result (derive.g2_accepted is gone);
  - the approval is an `oracle_approvals` item of the run's latest non-EXPIRED G3 record that names the testcase, with
    decision `accept` and testcase_sha256 equal to the testcase's approval hash now (derive.w4_oracle_approved);
  - a verdict version written before G3 (W3_adjudicate, G2_apply, W4_readjudicate) cannot use it;
  - a harness-generated oracle (local_rls, fake_model) needs no approval and gets no stricter;
  - the validator checks the list (E-GATE-ORACLE).

Each test of the new rule failed before the change and passes after it (tests/mutations/w4_oracle_approval.json); the
`..._still_...` tests check that nothing else moved. See CONTRIBUTING.md."""
import copy
import json
import pathlib

import pytest

from conftest import doc, rederive
from test_v03_adjudication import _ix_cluster, _w4
from vchlib import adjudicate as adj
from vchlib import derive, verdict
from vchlib.checks import run_all
from vchlib.context import Ctx

ROOT = pathlib.Path(__file__).resolve().parents[1]
W4_TC, W4_TR = "w4-testcase.k-015.example.json", "testresult.w4-k-015.example.json"
G2, G3 = "gate-record.g2.example.json", "gate-record.g3.example.json"
OK = [{"control_id": x, "outcome": "PASS"} for x in ("CTL-01", "CTL-02", "CTL-03")]


def text(rel):
    return (ROOT / "docs" / rel).read_text(encoding="utf-8")


def llm_written(b):
    """WTC-015-01 rewritten as an LLM-written unit test (same requirements, same controls)."""
    tc = doc(b, W4_TC).data
    tc.update(kind="unit", target_files=["db/migrations/0001_init.sql"])
    tc["environment"]["database"] = None
    return tc


def approve(b, decision="accept", record=G3, sha=None):
    tc = doc(b, W4_TC).data
    item = {"testcase_id": tc["testcase_id"], "testcase_sha256": sha or derive.approval_hash(tc), "decision": decision}
    doc(b, record).data["oracle_approvals"] = [item]
    return item


def fail(b):
    return _w4(b, "FAIL", OK, ["STATE_DIFF"])


def gate_errors(b):
    return [i.msg for i in run_all(b).errors if i.code == "E-GATE-ORACLE"]


# ================================================================ the rule
def test_the_rule_version_is_05_v0_17_and_the_examples_are_clean(b):
    assert adj.RULE_VERSION == "05-v0.17"
    assert run_all(b).errors == []
    assert {d.data.get("rule_version") for d in b.docs if d.kind in ("verdict", "run")} == {"05-v0.17"}


def test_g2_acceptance_alone_does_not_make_an_llm_written_w4_fail_proof(b):
    llm_written(b)
    assert next(d for d in doc(b, G2).data["decisions"] if d["item_id"] == "K-015")["decision"] == "accept"
    ix, cl = _ix_cluster(b, "K-015")
    cls, why = derive.classify_result(ix, fail(b), cl)
    assert cls == "E_fail_u" and "oracle_unreviewed" in why
    assert not hasattr(derive, "g2_accepted")


def test_a_g3_oracle_approval_makes_it_proof(b):
    llm_written(b)
    approve(b)
    ix, cl = _ix_cluster(b, "K-015")
    assert derive.classify_result(ix, fail(b), cl)[0] == "E_proof"
    assert derive.classify_result(ix, fail(b), cl, "B5_readjudicate")[0] == "E_proof"


def test_the_approval_does_not_depend_on_the_g2_decision(b):
    llm_written(b)
    approve(b)
    next(d for d in doc(b, G2).data["decisions"] if d["item_id"] == "K-015")["decision"] = "needs_info"
    ix, cl = _ix_cluster(b, "K-015")
    assert derive.classify_result(ix, fail(b), cl)[0] == "E_proof"


@pytest.mark.parametrize("phase", ["W3_adjudicate", "G2_apply", "W4_readjudicate"])
def test_a_version_written_before_g3_cannot_use_the_approval(b, phase):
    llm_written(b)
    approve(b)
    ix, cl = _ix_cluster(b, "K-015")
    cls, why = derive.classify_result(ix, fail(b), cl, phase)
    assert cls == "E_fail_u" and "oracle_unreviewed" in why
    assert phase in verdict.PRE_G3_PHASES and verdict.PRE_G3_PHASES is derive.PRE_ORACLE_REVIEW_PHASES


def test_the_w4_verdict_version_stays_unreviewed_after_the_approval(b):
    """V-015-2 is the W4_readjudicate version: the G3 approval comes later, so its inputs still carry oracle_unreviewed."""
    llm_written(b)
    approve(b)
    c = Ctx(b)
    v = doc(b, "verdict.k-015-w4.example.json").data
    cl = doc(b, "cluster.k-015.example.json").data
    assert verdict.oracle_unreviewed(c, v, cl) is True
    later = dict(v, readjudicated_by="B5_readjudicate")
    assert verdict.oracle_unreviewed(c, later, cl) is False


def test_an_approval_of_an_earlier_text_of_the_test_does_not_count(b):
    tc = llm_written(b)
    approve(b)
    ix, cl = _ix_cluster(b, "K-015")
    assert derive.classify_result(ix, fail(b), cl)[0] == "E_proof"
    tc["oracle"] = dict(copy.deepcopy(tc["oracle"]), note="edited after the review")
    assert derive.classify_result(ix, fail(b), cl)[0] == "E_fail_u"


def test_a_rejected_oracle_is_not_approved(b):
    llm_written(b)
    approve(b, "reject")
    ix, cl = _ix_cluster(b, "K-015")
    assert derive.classify_result(ix, fail(b), cl)[0] == "E_fail_u"


def test_an_approval_in_another_gate_or_for_another_test_does_not_count(b):
    llm_written(b)
    approve(b, record=G2)
    ix, cl = _ix_cluster(b, "K-015")
    assert derive.classify_result(ix, fail(b), cl)[0] == "E_fail_u"
    doc(b, G2).data.pop("oracle_approvals")
    approve(b)["testcase_id"] = "WTC-999-01"
    assert derive.classify_result(ix, fail(b), cl)[0] == "E_fail_u"


def test_the_latest_g3_record_that_names_the_test_decides(b):
    llm_written(b)
    tc = doc(b, W4_TC).data
    ix, cl = _ix_cluster(b, "K-015")
    first = {"run_id": tc["run_id"], "outcome": "PARTIALLY_APPROVED",
             "oracle_approvals": [{"testcase_id": tc["testcase_id"], "testcase_sha256": derive.approval_hash(tc), "decision": "accept"}]}
    second = copy.deepcopy(first)
    second["oracle_approvals"][0]["decision"] = "reject"
    silent = {"run_id": tc["run_id"], "outcome": "APPROVED"}
    expired = dict(copy.deepcopy(second), outcome="EXPIRED")

    class D:
        def __init__(self, data):
            self.data = data

    def records(recs):
        ix.gate_records = lambda run_id, gate=None: [D(r) for r in recs] if gate == "G3" and run_id == tc["run_id"] else []
        return derive.w4_oracle_approved(ix, tc, fail(b))

    assert records([first]) is True
    assert records([first, second]) is False              # the later decision wins
    assert records([second, first]) is True
    assert records([first, silent]) is True               # a later record that does not name the test changes nothing
    assert records([first, expired]) is True              # nobody decided in an EXPIRED record
    assert records([]) is False


def test_the_control_must_still_pass(b):
    llm_written(b)
    approve(b)
    ix, cl = _ix_cluster(b, "K-015")
    ctl = [OK[0], {"control_id": "CTL-02", "outcome": "NOT_RUN"}, OK[2]]
    cls, why = derive.classify_result(ix, _w4(b, "FAIL", ctl, ["STATE_DIFF"]), cl)
    assert cls == "E_fail_u" and "oracle_unreviewed" not in why     # the oracle was reviewed; it was never shown to pass


def test_a_harness_generated_oracle_still_needs_no_approval(b):
    assert doc(b, W4_TC).data["kind"] in derive.CODE_ORACLE_KINDS
    assert "oracle_approvals" not in doc(b, G3).data
    ix, cl = _ix_cluster(b, "K-015")
    for phase in (None, "W4_readjudicate", "B5_readjudicate"):
        assert derive.classify_result(ix, fail(b), cl, phase)[0] == "E_proof", phase
    assert doc(b, "verdict.k-015-w4.example.json").data["status"] == "CONFIRMED_EXECUTABLE"


def test_a_harness_generated_oracle_still_needs_both_controls(b):
    ix, cl = _ix_cluster(b, "K-015")
    approve(b)                                              # an approval cannot stand in for a control
    for missing in ("CTL-02", "CTL-03"):
        ctl = [x if x["control_id"] != missing else {"control_id": missing, "outcome": "NOT_RUN"} for x in OK]
        assert derive.classify_result(ix, _w4(b, "FAIL", ctl, ["STATE_DIFF"]), cl)[0] == "E_fail_u"


# ================================================================ the validator (E-GATE-ORACLE)
def test_a_signed_approval_of_an_llm_written_test_validates(b, keys):
    llm_written(b)
    approve(b)
    rederive(b, keys)
    assert gate_errors(b) == []
    assert "E-SCHEMA" not in run_all(b).codes() and "E-SIG" not in {i.code[:5] for i in run_all(b).errors}


def test_the_approval_is_signed_with_the_record(b, keys):
    llm_written(b)
    approve(b)
    rederive(b, keys)
    before = {i.code for i in run_all(b).errors}
    doc(b, G3).data["oracle_approvals"][0]["decision"] = "reject"
    after = {i.code for i in run_all(b).errors} - before
    assert any(code.startswith("E-SIG") for code in after), after


def test_only_a_g3_record_carries_oracle_approvals(b):
    llm_written(b)
    approve(b, record=G2)
    assert any("belongs to a G3 record, not G2" in m for m in gate_errors(b))


def test_an_approval_must_name_a_w4_testcase_of_the_run(b):
    llm_written(b)
    approve(b)["testcase_id"] = "WTC-999-01"
    assert any("WTC-999-01, which is not a W4 testcase of run" in m for m in gate_errors(b))
    doc(b, W4_TC).data["run_id"] = "run-2026-10-07-001"
    approve(b)
    assert any("is not a W4 testcase of run run-2026-09-23-001" in m for m in gate_errors(b))


def test_a_harness_generated_oracle_is_not_an_approval_item(b):
    approve(b)
    assert any("the harness generated its oracle" in m for m in gate_errors(b))


def test_an_accept_must_pin_the_testcase_as_it_is(b):
    llm_written(b)
    approve(b, sha="sha256:" + "0" * 64)
    assert any("it changed: review it again" in m for m in gate_errors(b))
    approve(b, "reject", sha="sha256:" + "0" * 64)          # a rejection of an earlier text is history, not an error
    assert not any("it changed" in m for m in gate_errors(b))


def test_a_testcase_is_named_once(b):
    llm_written(b)
    item = approve(b)
    doc(b, G3).data["oracle_approvals"].append(dict(item))
    assert any("names WTC-015-01 twice" in m for m in gate_errors(b))


def test_the_schema_knows_the_field_and_its_shape(b):
    s = json.loads(text("schemas/gate-record.schema.json"))
    item = s["properties"]["oracle_approvals"]["items"]
    assert item["required"] == ["testcase_id", "testcase_sha256", "decision"] and item["additionalProperties"] is False
    assert item["properties"]["decision"]["enum"] == ["accept", "reject"]
    assert "oracle_approvals" not in s["required"]
    llm_written(b)
    approve(b)["decision"] = "needs_info"
    assert "E-SCHEMA" in run_all(b).codes()


# ================================================================ the documents say the same
def test_the_documents_name_g3_not_g2_as_the_entry():
    d05 = text("05-bias-calibration.md")
    assert "`derive.w4_oracle_approved`" in d05 and "`derive.g2_accepted`" not in d05
    line = next(ln for ln in d05.splitlines() if "G2 的 accept 與 NEEDS_INFO" in ln)
    assert "沒有例外" in line and "`oracle_approvals`" in line
    b_item = next(ln for ln in d05.splitlines() if ln.lstrip().startswith("- (b) W4 測試"))
    assert "G3 紀錄的 `oracle_approvals`" in b_item and "只對 G3 之後的裁決版本" in b_item and "G2 在 W4 之前" in b_item
    assert "叢集經 G2 逐項 `accept`（人看過這一項）之後" not in d05
    d02 = next(ln for ln in text("02-methodology.md").splitlines() if ln.lstrip().startswith("- **LLM 撰寫的測試**"))
    assert "`oracle_approvals`" in d02 and "`E-GATE-ORACLE`" in d02 and "沒有 G3 的 run" in d02
    assert "LLM 自己寫的測試要先由人在 G3 逐項核准它的 oracle" in text("00-overview.md")
    assert "要先經 G2 接受" not in text("08-implementation-spec.md")
    row = next(ln for ln in text("06-security-legal-limitations.md").splitlines() if ln.startswith("| 45 |"))
    assert "`oracle_approvals`" in row and "G2 逐項接受該叢集之後才算事先登記" not in row
    assert "oracle_approvals[]" in text("03-system-architecture.md")
