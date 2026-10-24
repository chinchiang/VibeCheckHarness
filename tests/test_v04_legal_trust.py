# SPDX-License-Identifier: Apache-2.0
"""v0.4 second priority: data-egress legal checks at G0a, ROE incident response, pinned configuration.

- C1 E-ENG-TRANSFER: every cloud family that can receive C data has a region and a transfer entry, checked at G0a;
- E-ROE-TRANSFER: the ROE cannot call cross-border not applicable when the engagement declares a transfer;
- C5 E-ROE-INCIDENT: contacts, notification time, the four covered incident kinds, procedure and liability refs;
- E1 E-ENG-CONFIG-PIN: models / agents / tools / licenses equal the hashes pinned in the signed engagement.
"""
import pytest

from conftest import codes, doc
from vchlib.checks import run_all


def errors(b, code):
    return [i for i in run_all(b).errors if i.code == code]


def test_examples_pass_the_new_rules(b):
    found = codes(b)
    for code in ("E-ENG-TRANSFER", "E-ROE-TRANSFER", "E-ROE-INCIDENT", "E-ENG-CONFIG-PIN"):
        assert code not in found, code


# ================================================================ C1 data transfer at G0a
def provider(b, fam):
    return next(p for p in doc(b, "engagement.yaml").data["providers"] if p["family"] == fam)


def test_null_region_for_a_c_capable_cloud_family_is_an_error(b):
    provider(b, "openai")["region"] = None
    assert any("providers.openai.region is null" in i.msg for i in errors(b, "E-ENG-TRANSFER"))


def test_missing_transfer_entry_is_an_error(b):
    dt = doc(b, "engagement.yaml").data["data_transfer"]
    dt["transfers"] = [t for t in dt["transfers"] if t["family"] != "anthropic"]
    assert any("anthropic" in i.msg for i in errors(b, "E-ENG-TRANSFER"))


def test_region_mismatch_is_an_error(b):
    provider(b, "anthropic")["region"] = "JP"
    assert errors(b, "E-ENG-TRANSFER")


def test_cross_border_needs_a_real_mechanism_and_reference(b):
    t = doc(b, "engagement.yaml").data["data_transfer"]["transfers"][0]
    t["mechanism"] = "same_jurisdiction"
    assert errors(b, "E-ENG-TRANSFER")
    t["mechanism"], t["reference"] = "contract", None
    assert errors(b, "E-ENG-TRANSFER")


def test_same_jurisdiction_transfer(b):
    eng = doc(b, "engagement.yaml").data
    for fam in ("anthropic", "openai"):
        provider(b, fam)["region"] = "TW"
    eng["data_transfer"]["transfers"] = [{"family": f, "region": "TW", "mechanism": "same_jurisdiction", "reference": None}
                                         for f in ("anthropic", "openai")]
    assert not errors(b, "E-ENG-TRANSFER")
    eng["data_transfer"]["transfers"][0]["mechanism"] = "contract"       # same region but declared as a transfer
    assert errors(b, "E-ENG-TRANSFER")


def test_attester_must_be_an_engagement_signatory(b):
    doc(b, "engagement.yaml").data["data_transfer"]["attested_by"] = "grace"
    assert any("signatory" in i.msg for i in errors(b, "E-ENG-TRANSFER"))


def test_p_class_engagement_needs_no_transfer_entries(b):
    eng = doc(b, "engagement.yaml").data
    eng["data_class"] = "P"
    eng["data_transfer"]["transfers"] = []
    assert not errors(b, "E-ENG-TRANSFER")


def test_roe_cannot_call_cross_border_not_applicable(b):
    doc(b, "roe.yaml").data["legal_review"]["scope"]["cross_border"] = {"value": False, "not_applicable_reason": "same jurisdiction"}
    assert errors(b, "E-ROE-TRANSFER")


# ================================================================ C5 incident response
@pytest.mark.parametrize("mutate, needle", [
    (lambda ir: ir.update(contacts=["nobody"]), "not a registry person"),
    (lambda ir: ir.update(covers=["data_exposure"]), "misses"),
])
def test_incident_response_rules(b, mutate, needle):
    mutate(doc(b, "roe.yaml").data["incident_response"])
    assert any(needle in i.msg for i in errors(b, "E-ROE-INCIDENT"))


def test_incident_response_is_required(b):
    del doc(b, "roe.yaml").data["incident_response"]
    assert errors(b, "E-ROE-INCIDENT")


# ================================================================ E1 config pins
@pytest.mark.parametrize("name, mutate", [
    ("models.yaml", lambda d: d["gpt_flagship"].update(data_classes=["P", "C"], family="openai_alt")),
    ("agents.yaml", lambda d: d["rev_b"].update(model="claude_sonnet")),
    ("tools.yaml", lambda d: next(iter(d["tools"].values())).update(zone="Z9-changed")),
    ("licenses.yaml", lambda d: d["components"][0].update(status=d["components"][0]["status"] + "-changed")),
])
def test_changed_config_breaks_the_pin(b, name, mutate):
    data = doc(b, name).data
    mutate(data)
    key = name.split(".")[0]
    assert any(f"config_pins.{key}" in i.msg for i in errors(b, "E-ENG-CONFIG-PIN"))


def test_missing_pins_are_an_error(b):
    del doc(b, "engagement.yaml").data["config_pins"]
    assert errors(b, "E-ENG-CONFIG-PIN")


# ================================================================ E4 decision time authority
G1 = "gate-record.g1.example.json"
AUDIT = "audit-event.run-2026-09-23-001.example.jsonl"


def gate_event(b, rec_id):
    return next(e for e in doc(b, AUDIT).data if e["event_type"] == "gate_decision"
                and e["payload"]["gate_record_id"] == rec_id)


def test_decision_time_is_the_audit_writer_receive_time(b):
    from vchlib.checks import Ctx, decision_time
    from vchlib import timeutil
    rec = doc(b, G1).data
    assert decision_time(Ctx(b), rec) == timeutil.parse_dt(gate_event(b, rec["gate_record_id"])["ts"])


def test_backdated_gate_timestamp_is_an_error(b):
    """The approver writes a timestamp an hour before the Audit Writer received the decision."""
    import datetime as dt
    from vchlib import timeutil
    rec = doc(b, G1).data
    t = timeutil.parse_dt(gate_event(b, rec["gate_record_id"])["ts"])
    rec["timestamp"] = (t - dt.timedelta(hours=1)).isoformat()
    assert any("receive time" in i.msg for i in errors(b, "E-AUDIT-GATE"))


def test_small_clock_skew_is_tolerated(b):
    import datetime as dt
    from vchlib import timeutil
    rec = doc(b, G1).data
    t = timeutil.parse_dt(gate_event(b, rec["gate_record_id"])["ts"])
    rec["timestamp"] = (t - dt.timedelta(minutes=2)).isoformat()
    assert not any("receive time" in i.msg for i in errors(b, "E-AUDIT-GATE"))
