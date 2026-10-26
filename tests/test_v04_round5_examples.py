# SPDX-License-Identifier: Apache-2.0
"""v0.4 round 5, roadmap fields, threat rows and examples (docs/evidence/review-2026-10-24.md §9).
Positive and negative cases:

- toolkit gate_queues and report-manifest over_cap_items / report_only_clusters (BL-26, E-REPORT-QUEUE);
- the cicd_iac facet is mandatory when the inventory has ci_workflows or iac;
- G1 llm_tools may pin MCP tool descriptions.
"""
from conftest import codes, doc, resign_gate
from vchlib import facets
from vchlib.checks import run_all

RM = "report-manifest.example.json"
SEEDS = "seed-threats.example.json"


def errors(b, code):
    return [i for i in run_all(b).errors if i.code == code]


# ================================================================ BL-26
def test_example_queue_fields(b):
    assert doc(b, "toolkit.yaml").data["gate_queues"] == {"g2_max_items": 30, "g3_max_items": 50, "g4_max_items": 40,
                                                         "g2_timeout_warn_ratio": 0.5}
    rm = doc(b, RM).data
    assert rm["over_cap_items"] == [] and rm["report_only_clusters"] == ["K-016"]      # v0.5: the tool-only cluster (BL-13)
    assert not errors(b, "E-REPORT-QUEUE")


def test_gate_queue_ratio_must_be_positive(b):
    doc(b, "toolkit.yaml").data["gate_queues"]["g2_timeout_warn_ratio"] = 0
    assert any("toolkit" in i.where for i in errors(b, "E-SCHEMA"))


def test_report_only_needs_an_unseeded_white_box_uncorroborated_cluster(b):
    rm = doc(b, RM).data
    rm["report_only_clusters"] = ["K-015", "K-202", "K-014", "K-999"]
    # K-015 is a seed threat; K-202 is black-box; K-014 is LIKELY; K-999 does not exist
    assert len(errors(b, "E-REPORT-QUEUE")) == 4


def _k015_before_w4(b):
    """K-015 as it stood before its W4 test and before G2 decided it: UNCORROBORATED (V-015-1), a seed candidate
    (v0.7, r8 F5: the example's G2 now decides K-015 too, so that decision is removed here)."""
    b.docs[:] = [d for d in b.docs if not d.path.endswith("verdict.k-015-w4.example.json")]
    g2 = doc(b, "gate-record.g2.example.json").data
    g2["decisions"] = [x for x in g2["decisions"] if x["item_id"] != "K-015"]


def test_report_only_accepts_a_pruned_cluster(b):
    _k015_before_w4(b)
    seeds = doc(b, SEEDS).data["seeds"]
    seeds[:] = [s for s in seeds if s["source_cluster_id"] != "K-015"]
    doc(b, RM).data["report_only_clusters"] = ["K-015"]
    assert not errors(b, "E-REPORT-QUEUE")


def test_over_cap_g2_only_when_the_queue_was_full(b):
    _k015_before_w4(b)
    rm = doc(b, RM).data
    rm["over_cap_items"] = [{"gate": "G2", "item_id": "K-015"}]
    assert errors(b, "E-REPORT-QUEUE")                     # G2 holds 2 decisions (K-011, K-016), the cap is 30
    doc(b, "toolkit.yaml").data["gate_queues"]["g2_max_items"] = 2
    assert not errors(b, "E-REPORT-QUEUE")


def test_over_cap_g2_rejects_decided_and_unseeded_clusters(b):
    doc(b, "toolkit.yaml").data["gate_queues"]["g2_max_items"] = 3
    rm = doc(b, RM).data
    rm["over_cap_items"] = [{"gate": "G2", "item_id": "K-011"},     # decided at G2
                            {"gate": "G2", "item_id": "K-014"}]     # LIKELY, not a G2 candidate
    assert len(errors(b, "E-REPORT-QUEUE")) == 2


def test_over_cap_g3(b, keys):
    rm = doc(b, RM).data
    rm["over_cap_items"] = [{"gate": "G3", "item_id": "ST-001"}]   # T-012 was accepted at G3
    assert errors(b, "E-REPORT-QUEUE")
    doc(b, SEEDS).data["seeds"][0]["threat_id"] = "T-999"          # v0.5: undecided is not over_cap either
    assert errors(b, "E-REPORT-QUEUE")
    # v0.5 (review 2026-10-25 M-4b): the G3 record names the item with decision over_cap
    doc(b, SEEDS).data["seeds"][0]["threat_id"] = "T-027"
    rec = doc(b, "gate-record.g3.example.json").data
    next(x for x in rec["decisions"] if x["item_id"] == "T-027")["decision"] = "over_cap"
    resign_gate(b, "gate-record.g3.example.json", keys)
    assert not errors(b, "E-REPORT-QUEUE")
    rm["over_cap_items"].append({"gate": "G3", "item_id": "ST-001"})
    assert len(errors(b, "E-REPORT-QUEUE")) == 1                  # listed twice


# ================================================================ cicd_iac facet
def test_cicd_iac_facet_rule():
    base = set(facets.BASE_FACETS)
    assert facets.mandatory_facets({"features": ["ci_workflows"]}) == base | {"cicd_iac"}
    assert facets.mandatory_facets({"features": ["iac"]}) == base | {"cicd_iac"}
    assert facets.FACET_BUCKETS["cicd_iac"] >= {"injection", "secrets", "config"}


def test_plan_must_cover_cicd_iac_when_the_repo_has_workflows(b):
    inv = doc(b, "inventory.example.json").data
    inv["features"].append("ci_workflows")
    assert "E-PLAN-FACETS" in codes(b)
    for s in doc(b, "commander-plan.example.json").data["slices"]:
        s["facets"].append("cicd_iac")
    assert "E-PLAN-FACETS" not in codes(b)


def test_reviewers_list_the_new_facet(b):
    reviewers = [a for a in doc(b, "agents.yaml").data.values() if isinstance(a, dict) and a.get("role") == "reviewer"]
    assert reviewers and all("cicd_iac" in a["facets"] for a in reviewers)


# ================================================================ MCP tool descriptions
def test_llm_tools_can_pin_an_mcp_description(b):
    tool = doc(b, "invariants.yaml").data["llm_tools"][0]
    tool["mcp_server"] = "mcp://support-tools"
    tool["description_sha256"] = "sha256:" + "a" * 64
    assert not [i for i in errors(b, "E-SCHEMA") if "invariants" in i.where]
    tool["description_sha256"] = "not-a-hash"
    assert [i for i in errors(b, "E-SCHEMA") if "invariants" in i.where]


# ================================================================ example B′ (third-party indirect injection)
def test_third_party_document_seed(b):
    seed = doc(b, "seed-manifest.yaml").data["seeds"]["u2_doc"]
    assert seed["owner_role"] == "U2" and seed["table"] == "documents"
    assert "E-ROE-SEED-MANIFEST" not in codes(b)          # the ROE re-signs the manifest with the new seed


def test_unsigned_seed_change_is_caught(b):
    doc(b, "seed-manifest.yaml").data["seeds"]["u2_doc"]["owner_role"] = "U1"
    assert "E-ROE-SEED-MANIFEST" in codes(b)
