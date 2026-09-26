"""v0.3 data model: evidence kinds and tolerant matching (B1), inventory (B2), invariants and level triggers (B3),
DFD provenance / boundary kinds (B4), threat evidence kinds (L-05), facets (E7). Positive and negative cases."""
import copy

import pytest

from conftest import codes, doc, rederive
from vchlib import evidence, facets
from vchlib.adjudicate import adjudicate
from vchlib.checks import Ctx, run_all, verdict_inputs
from vchlib.derive import Index, independent_families

F061 = "finding.f-061.example.json"
INV = "inventory.example.json"


def errs(bundle, code):
    return [i for i in run_all(bundle).errors if i.code == code]


# ================================================================ B1 tolerant matching (pure)
SLICE = "\n".join([
    "import { db } from '../db';",                                        # 1
    "",                                                                   # 2
    "export async function getInvoice(req, res) {",                        # 3
    "  const invoice = await db.invoice.findUnique({ where: { id: req.params.id } });",   # 4
    "  return res.json(invoice);",                                        # 5
    "}",                                                                  # 6
    "const key = '<REDACTED:STRIPE_KEY_1>';",                              # 7
    "", "", "", "", "",                                                   # 8-12
    "// far away",                                                        # 13
    "const invoice = await db.invoice.findUnique({ where: { id: req.params.id } });",     # 14
])
SNIP = "const invoice = await db.invoice.findUnique({ where: { id: req.params.id } });"


def ev(ls, le, snippet=SNIP):
    return {"kind": "code_snippet", "line_start": ls, "line_end": le, "snippet": snippet}


def test_match_snippet_exact_with_whitespace_normalisation():
    assert evidence.match_snippet(SLICE, ev(4, 4, "  const invoice =  await\tdb.invoice.findUnique({ where: { id: req.params.id } });  ")) \
        == ("MATCHED", 4, 4)
    assert evidence.match_snippet(SLICE.replace("\n", "\r\n"), ev(4, 4)) == ("MATCHED", 4, 4)      # CRLF checkout


def test_match_snippet_shift_within_window():
    assert evidence.match_snippet(SLICE, ev(6, 6)) == ("MATCHED_SHIFTED", 4, 4)       # claimed 6, found at 4 (|shift| = 2)
    assert evidence.match_snippet(SLICE, ev(1, 1)) == ("MATCHED_SHIFTED", 4, 4)       # shift +3 is still inside the window


def test_match_snippet_shift_beyond_window():
    assert evidence.match_snippet(SLICE, ev(9, 9))[0] == "NOT_FOUND"                  # 4 and 14 are both > 3 lines away
    assert evidence.match_snippet(SLICE, ev(12, 12)) == ("MATCHED_SHIFTED", 14, 14)   # the later copy is within +2


def test_match_snippet_multiline_and_redacted_text():
    two = "export async function getInvoice(req, res) {\n  const invoice = await db.invoice.findUnique({ where: { id: req.params.id } });"
    assert evidence.match_snippet(SLICE, ev(3, 4, two)) == ("MATCHED", 3, 4)
    assert evidence.match_snippet(SLICE, ev(5, 6, two)) == ("MATCHED_SHIFTED", 3, 4)
    assert evidence.match_snippet(SLICE, ev(7, 7, "const key = '<REDACTED:STRIPE_KEY_1>';")) == ("MATCHED", 7, 7)
    # the unredacted secret never matches the redacted slice text
    assert evidence.match_snippet(SLICE, ev(7, 7, "const key = 'sk_test_123';"))[0] == "NOT_FOUND"


def test_match_fact_and_config():
    inv = {"db": {"tables": [{"name": "invoices", "rls_enabled": False}]}}
    assert evidence.match_fact(inv, {"fact_ref": "/db/tables/0/rls_enabled", "asserted": False}) == "MATCHED"
    assert evidence.match_fact(inv, {"fact_ref": "/db/tables/0/rls_enabled", "asserted": 0}) == "NOT_FOUND"     # false is not 0
    assert evidence.match_fact(inv, {"fact_ref": "/db/tables/1/rls_enabled", "asserted": False}) == "NOT_FOUND"
    cfg = {"cors": {"origin": "*"}}
    assert evidence.match_config(cfg, {"key_path": "/cors/origin", "asserted": "*"}) == "MATCHED"
    assert evidence.match_config(cfg, {"key_path": "/csp", "asserted": evidence.ABSENT}) == "MATCHED"
    assert evidence.match_config(cfg, {"key_path": "/cors", "asserted": evidence.ABSENT}) == "NOT_FOUND"
    assert evidence.resolve_pointer({"a/b": {"~": 1}}, "/a~1b/~0") == 1


# ================================================================ B1 validator
def test_inventory_fact_finding_example(b):
    f = doc(b, F061).data
    assert f["evidence"][0]["kind"] == "inventory_fact" and f["evidence"][0]["fact_ref"] == "/db/tables/0/rls_enabled"
    assert "E-FINDING-MATCH" not in codes(b)


def test_inventory_fact_match_is_recomputed(b):
    doc(b, F061).data["evidence"][0]["asserted"] = True          # the inventory says false
    assert "E-FINDING-MATCH" in codes(b)


def test_inventory_fact_ref_must_resolve(b):
    doc(b, F061).data["evidence"][0]["fact_ref"] = "/db/tables/9/rls_enabled"
    assert "E-INVENTORY-REF" in codes(b)


def test_evidence_kind_fields(b):
    doc(b, F061).data["evidence"][0]["snippet"] = "ALTER TABLE invoices"
    assert "E-FINDING-EVIDENCE" in codes(b)
    doc(b, "finding.example.json").data["evidence"][0]["fact_ref"] = "/db"
    assert len(errs(b, "E-FINDING-EVIDENCE")) == 2


def test_finding_status_follows_matches(b):
    doc(b, "finding.example.json").data["evidence"][0]["match"] = "NOT_FOUND"
    assert "E-FINDING-STATUS" in codes(b)                      # all NOT_FOUND -> UNVERIFIED
    doc(b, "finding.example.json").data["status"] = "UNVERIFIED"
    assert "E-FINDING-STATUS" not in codes(b)


def test_r0_all_evidence_not_found(b):
    f = doc(b, F061).data
    f["evidence"][0]["match"] = "NOT_FOUND"
    c = Ctx(b)
    v, cl = doc(b, "verdict.k-015-w3.example.json").data, c.ix.first("cluster", cluster_id="K-015").data
    out = adjudicate(verdict_inputs(c, v, cl))
    assert (out.status, out.rules) == ("REJECTED", ["R0"])
    f["evidence"][0]["match"] = "MATCHED_SHIFTED"
    assert adjudicate(verdict_inputs(Ctx(b), v, cl)).status == "UNCORROBORATED"


def test_independent_families_ignore_unverified_members(b):
    ix = Index(b)
    assert independent_families(ix, ix.first("cluster", cluster_id="K-005").data) == ["anthropic", "openai"]
    doc(b, "finding.f-021.example.json").data["evidence"][0]["match"] = "NOT_FOUND"
    ix = Index(b)
    assert independent_families(ix, ix.first("cluster", cluster_id="K-005").data) == ["openai"]
    assert "E-CLUSTER-FAMILIES" in codes(b)


def test_independent_families_are_recomputed(b):
    """D14: marking F-017 as a round-2 finding drops openai from the independent families (v0.2 only checked subset)."""
    doc(b, "finding.example.json").data["reporter"]["round"] = 2
    assert "E-CLUSTER-FAMILIES" in codes(b)


# ================================================================ B2 inventory
def test_threat_inventory_evidence_is_a_resolvable_pointer(b):
    t = doc(b, "threat.example.json").data
    ref = next(e for e in t["evidence"] if e["kind"] == "inventory")
    assert ref["ref"] == "/db/tables/0/rls_enabled"
    ref["ref"] = "rls:invoices=none"                              # the v0.2 free-text form
    assert "E-INVENTORY-REF" in codes(b)


def test_dfd_inventory_refs_resolve(b):
    d = doc(b, "dfd.merged.example.json").data
    e = next(x for x in d["elements"] if x["element_id"] == "store-invoices")
    e["evidence_refs"] = ["inventory:/db/tables/7"]
    assert "E-INVENTORY-REF" in codes(b)


@pytest.mark.parametrize("mutate", [
    lambda inv: inv["endpoints"][0].update(middleware_refs=["MW-999"]),
    lambda inv: inv["db"]["tables"][0]["source"].update(file="db/unknown.sql"),
    lambda inv: inv["env_vars"][0].update(name="NEXT_PUBLIC_API_URL"),          # public prefix but public_prefix false
])
def test_inventory_internal_references(b, mutate):
    mutate(doc(b, INV).data)
    assert "E-INVENTORY" in codes(b)


# ================================================================ B3 invariants
def test_level_triggers_cover_l2_citations(b):
    inv = doc(b, "invariants.yaml").data
    assert "E-INVARIANT-LEVEL" not in codes(b)
    inv["level_triggers"] = [t for t in inv["level_triggers"] if t["standard"] != "aisvs"]
    hits = errs(b, "E-INVARIANT-LEVEL")
    assert {"REQ-AISVS-9.5.2", "REQ-AISVS-9.5.3"} <= {w for i in hits for w in ("REQ-AISVS-9.5.2", "REQ-AISVS-9.5.3") if w in i.msg}
    assert any(i.where.endswith("testcase.llm.example.json") for i in hits)          # the testcase cites 9.5.2
    inv["baseline_levels"]["aisvs"] = 2                                              # adopting AISVS L2 overall also covers it
    assert "E-INVARIANT-LEVEL" not in codes(b)


def test_level_trigger_feature_must_be_declared(b):
    doc(b, "invariants.yaml").data["level_triggers"][0]["feature"] = "no_such_feature"
    assert "E-INVARIANT-LEVEL" in codes(b)


def test_llm_tool_data_classes_resolve(b):
    doc(b, "invariants.yaml").data["llm_tools"][0]["data_class_ids"] = ["DC-NOPE"]
    assert "E-INVARIANT-REF" in codes(b)


# ================================================================ B4 DFD
def test_trust_boundary_needs_a_kind(b):
    d = doc(b, "dfd.merged.example.json").data
    next(x for x in d["elements"] if x["type"] == "trust_boundary")["kind"] = None
    assert "E-DFD" in codes(b)
    next(x for x in d["elements"] if x["type"] == "process")["kind"] = "network"
    assert len(errs(b, "E-DFD")) == 2


def test_browser_to_baas_flow_example(b):
    d = doc(b, "dfd.merged.example.json").data
    flow = next(x for x in d["elements"] if x["element_id"] == "flow-browser-uploads")
    assert flow["from"] == "ext-tenant-user" and flow["to"] == "store-support-uploads" and "tb-baas" in flow["crosses"]
    assert next(x for x in d["elements"] if x["element_id"] == "tb-baas")["kind"] == "third_party"
    assert {x["provenance"] for x in d["elements"]} == {"deterministic", "g1_declared", "llm_proposed"}


def test_provenance_is_required(b):
    del doc(b, "dfd.external.example.json").data["elements"][0]["provenance"]
    assert "E-SCHEMA" in codes(b)


# ================================================================ L-05 threat evidence kinds
def test_cluster_refs_use_kind_cluster(b):
    t = doc(b, "threat.t-031.example.json").data
    e = next(x for x in t["evidence"] if x["kind"] == "cluster")
    assert e["ref"] == "K-011"
    e["kind"] = "finding"                                          # a K- id under kind finding (the v0.2 bug)
    assert "E-TRACE" in codes(b)


def test_threat_t031_uses_the_python_path(b):
    t = doc(b, "threat.t-031.example.json").data
    assert any(x["ref"] == "app/support/agent.py:57" for x in t["evidence"])


# ================================================================ E7 facets
def test_mandatory_facets_rule():
    base = set(facets.BASE_FACETS)
    assert facets.mandatory_facets({}) == base
    assert facets.mandatory_facets({"llm_integrations": [{}], "features": ["file_upload"]}) == base | {"llm_integration", "file_handling"}
    assert facets.mandatory_facets({"features": ["outbound_http", "webhook_inbound", "crypto"]}) == \
        base | {"ssrf_outbound", "webhooks_integrations", "crypto"}
    assert "frontend_client" in facets.mandatory_facets({"env_vars": [{"name": "NEXT_PUBLIC_X", "public_prefix": True}]})
    assert "frontend_client" in facets.mandatory_facets({"features": ["frontend_bundle"]})
    assert set(facets.FACET_BUCKETS) == set(facets.FACETS) and len(facets.FACETS) == 12


def test_plan_must_cover_mandatory_facets(b):
    p = doc(b, "commander-plan.example.json").data
    assert "E-PLAN-FACETS" not in codes(b)
    p["slices"][0]["facets"].remove("file_handling")
    assert "E-PLAN-FACETS" in codes(b)


def test_new_inventory_feature_raises_the_floor(b):
    doc(b, INV).data["features"].append("outbound_http")
    hits = errs(b, "E-PLAN-FACETS")
    assert hits and "ssrf_outbound" in hits[0].msg


def test_finding_facet_must_fit_the_cluster_bucket(b):
    doc(b, "finding.f-044.example.json").data["facet"] = "crypto"      # K-011 is llm_specific
    assert "E-FINDING-FACET" in codes(b)


def test_reviewers_list_all_twelve_facets(b):
    agents = doc(b, "agents.yaml").data
    for a in agents.values():
        if isinstance(a, dict) and a.get("role") == "reviewer":
            assert tuple(a["facets"]) == facets.FACETS
