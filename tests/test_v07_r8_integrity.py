# SPDX-License-Identifier: Apache-2.0
"""Review round 8, group 4: the integrity model and the methodology contracts the validator can enforce.
Each test reproduced its gap on the PR2 head (it failed there) and passes with the fix; see CONTRIBUTING.md.

H4   verdict_changed pins the verdict's content, report_published the report manifest (E-AUDIT-VERDICT / E-AUDIT-REPORT);
M1   toolkit.yaml is pinned by the engagement (E-ENG-CONFIG-PIN); queue caps are >= 1 (E-TOOLKIT);
M4   an app_owner's false_positive stays underReview until a security_reviewer co-signs; the suppression lapses when the
     cluster is updated (E-FEEDBACK);
M3   Lite G2 decides accept / needs_info only (E-GATE-OUTCOME);
ext5 a carried cluster is a new instance pointing at the parent's cluster (E-CLUSTER-CARRY);
ext6 a W4 result declares where its observations came from; SUT-sourced observations are E_inc (E-W4-OBSERVATION).
"""
import copy

from conftest import doc, rederive
from vchlib import checks, crypto, derive
from vchlib.bundle import Doc
from vchlib.checks import Ctx, run_all

AUDIT = "audit-event.run-2026-09-23-001.example.jsonl"
FB = "feedback.k-016.example.json"


def errors(b, code, where=None):
    return [i for i in run_all(b).errors if i.code == code and (where is None or where in i.where)]


def msgs(b, code):
    return [i.msg for i in errors(b, code)]


def test_the_examples_are_clean(b):
    assert run_all(b).errors == []


# ================================================================ H4: the deliverables are bound to the chain
def test_a_verdict_edited_after_its_event_is_detected(b):
    """A consistent edit (rule_trace text) that v0.6 never compared: the event pinned only the status."""
    v = doc(b, "verdict.k-014-w3.example.json").data
    v["rule_trace"][0] = v["rule_trace"][0] + " (edited after the anchor)"
    assert any("verdict_sha256" in m for m in msgs(b, "E-AUDIT-VERDICT"))


def test_a_report_edited_after_publication_is_detected(b):
    rm = doc(b, "report-manifest.example.json").data
    rm["artifacts"][0]["sha256"] = "sha256:" + "ab" * 32          # the manifest's own content changed
    assert any("report_manifest_sha256" in m for m in msgs(b, "E-AUDIT-REPORT"))


def test_the_events_pin_the_current_examples(b):
    assert not errors(b, "E-AUDIT-VERDICT") and not errors(b, "E-AUDIT-REPORT")
    evs = doc(b, AUDIT).data
    assert all("verdict_sha256" in e["payload"] for e in evs if e["event_type"] == "verdict_changed")
    assert all("report_manifest_sha256" in e["payload"] for e in evs if e["event_type"] == "report_published")


# ================================================================ M1: toolkit.yaml is a pinned trust root
def test_toolkit_is_pinned(b):
    doc(b, "toolkit.yaml").data["gate_queues"]["g2_max_items"] = 5
    assert any("config_pins.toolkit" in m for m in msgs(b, "E-ENG-CONFIG-PIN"))


def test_a_zero_queue_cap_is_rejected(b):
    doc(b, "toolkit.yaml").data["gate_queues"]["g2_max_items"] = 0
    assert any("g2_max_items" in m for m in msgs(b, "E-TOOLKIT"))


# ================================================================ M4: feedback needs a reviewer
def cosign(b, keys, person="heidi"):
    f = doc(b, FB).data
    reg = next(e for e in doc(b, "key-registry.yaml").data["entries"] if e["person_id"] == person and not e.get("revoked_at"))
    f["co_signed_by"] = {"person_id": person, "role": reg["roles"][0], "key_fingerprint": reg["fingerprint"]}
    f["signatures"] = [crypto.sign_document(f, "frank", keys["frank"]), crypto.sign_document(f, person, keys[person])]
    return f


def test_an_owners_false_positive_is_under_review(b, keys):
    assert doc(b, FB).data["sarif_suppression"] == "underReview" and not errors(b, "E-FEEDBACK")
    f = doc(b, FB).data
    f["sarif_suppression"] = "accepted"
    f["signatures"] = [crypto.sign_document(f, "frank", keys["frank"])]
    rederive(b, keys)
    assert any("gives SARIF suppression 'underReview'" in m for m in msgs(b, "E-FEEDBACK"))


def test_a_reviewer_cosign_accepts_the_suppression(b, keys):
    f = cosign(b, keys)
    f["sarif_suppression"] = "accepted"
    f["signatures"] = [crypto.sign_document(f, "frank", keys["frank"]), crypto.sign_document(f, "heidi", keys["heidi"])]
    rederive(b, keys)
    assert not errors(b, "E-FEEDBACK")


def test_the_cosigner_is_a_reviewer_other_than_the_signer(b, keys):
    f = cosign(b, keys, "carol")                                     # management, not a security_reviewer
    f["signatures"] = [crypto.sign_document(f, "frank", keys["frank"]), crypto.sign_document(f, "carol", keys["carol"])]
    rederive(b, keys)
    assert any("co_signed_by is a security_reviewer" in m for m in msgs(b, "E-FEEDBACK"))


def test_the_suppression_lapses_when_the_cluster_is_updated(b, keys):
    """The adopting run (the follow-up) carries a cluster with FB-001's fingerprint whose code changed."""
    f = cosign(b, keys)
    f["sarif_suppression"] = "accepted"
    f["signatures"] = [crypto.sign_document(f, "frank", keys["frank"]), crypto.sign_document(f, "heidi", keys["heidi"])]
    k = copy.deepcopy(doc(b, "cluster.k-016.example.json").data)
    k.update(cluster_id="K-316", run_id="run-2026-10-07-001", baseline_state="updated", member_finding_ids=[], independent_families=[],
             carried_from={"run_id": "run-2026-09-23-001", "cluster_id": "K-016", "fingerprint": k["fingerprint"]})
    b.docs.append(Doc("docs/schemas/examples/cluster.followup.k-316.example.json", "cluster", k, None))
    doc(b, "run.followup.example.json").data["cluster_ids"].append("K-316")
    rederive(b, keys)
    assert any("gives SARIF suppression 'underReview'" in m for m in msgs(b, "E-FEEDBACK"))


# ================================================================ M3: Lite G2
def make_lite(b):
    e = doc(b, "engagement.yaml").data
    e["assurance_profile"] = "lite"
    e["role_consolidation"] = {"acknowledged": True, "person_id": "erin", "statement": "single-user test"}


def test_lite_g2_cannot_reject(b, keys):
    make_lite(b)
    doc(b, "gate-record.g2.example.json").data["decisions"][0]["decision"] = "reject"
    rederive(b, keys)
    assert any("lite: G2 decides accept / needs_info only" in m for m in msgs(b, "E-GATE-OUTCOME"))


def test_team_g2_can_reject(b, keys):
    doc(b, "gate-record.g2.example.json").data["decisions"][0]["decision"] = "reject"
    rederive(b, keys)
    assert not [m for m in msgs(b, "E-GATE-OUTCOME") if "lite" in m]


# ================================================================ external 5: carried clusters
def test_the_followup_carries_k005_as_a_new_instance(b):
    k = doc(b, "cluster.followup.k-301.example.json").data
    assert k["carried_from"] == {"run_id": "run-2026-09-23-001", "cluster_id": "K-005", "fingerprint": k["fingerprint"]}
    assert not errors(b, "E-CLUSTER-CARRY") and not errors(b, "E-CLUSTER-ORIGIN", "k-301")


def test_a_carried_cluster_keeps_the_fingerprint(b):
    k = doc(b, "cluster.followup.k-301.example.json").data
    k["carried_from"]["cluster_id"] = "K-014"
    assert any("parent run with this cluster's fingerprint" in m for m in msgs(b, "E-CLUSTER-CARRY"))


def test_a_twin_without_carried_from_is_rejected(b):
    k = doc(b, "cluster.followup.k-301.example.json").data
    k["carried_from"] = None
    k["member_finding_ids"] = doc(b, "cluster.example.json").data["member_finding_ids"]
    assert any("carry it with carried_from" in m for m in msgs(b, "E-CLUSTER-CARRY"))


def test_an_initial_run_cannot_carry(b):
    k = doc(b, "cluster.k-014.example.json").data
    k["carried_from"] = {"run_id": "run-2026-09-23-001", "cluster_id": "K-014", "fingerprint": k["fingerprint"]}
    assert any("not the parent" in m for m in msgs(b, "E-CLUSTER-CARRY"))


# ================================================================ external 6: trusted observations
def test_a_w4_result_declares_its_observation_source(b, keys):
    doc(b, "testresult.w4-k-015.example.json").data["observations_source"] = None
    rederive(b, keys)
    assert errors(b, "E-W4-OBSERVATION")


def test_sut_sourced_observations_are_inconclusive(b, keys):
    tr = doc(b, "testresult.w4-k-015.example.json").data
    tr["observations_source"] = "sut"
    rederive(b, keys)
    c = Ctx(b)
    cl = c.ix.first("cluster", cluster_id="K-015").data
    cls, why = derive.classify_result(c.ix, doc(b, "testresult.w4-k-015.example.json").data, cl)
    assert cls == "E_inc" and "SUT" in why
    v = doc(b, "verdict.k-015-w4.example.json").data
    assert v["test_evidence"]["class"] == "E_inc"                          # re-derived by rederive
    assert checks.adj.adjudicate(checks.verdict_inputs(c, v, cl)).status != "CONFIRMED_EXECUTABLE"
