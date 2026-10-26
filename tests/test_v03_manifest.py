# SPDX-License-Identifier: Apache-2.0
"""v0.3 run manifest and provenance: baseline state (B9), agent tools and commander plans (B10, D16), run manifest
(B11), model pricing fields (B14), slice identity (E6), provenance (D14), fallback data class (D15)."""
import copy

import pytest

from conftest import codes, doc, rederive
from vchlib import adjudicate as adj
from vchlib import derive
from vchlib.bundle import Doc
from vchlib.checks import Ctx, derived_baseline_state, run_all

RUN, RUN_F, RUN_A = "examples/run.example.json", "examples/run.followup.example.json", "examples/run.lane-a.example.json"
PLAN = "commander-plan.example.json"


def errs(b, code):
    return [i for i in run_all(b).errors if i.code == code]


# ================================================================ B9 fingerprints and baseline state
def test_fingerprint_has_no_line_numbers(b):
    k = copy.deepcopy(doc(b, "cluster.example.json").data)
    fp = derive.cluster_fingerprint(k)
    k["canonical_location"]["sink"]["line"] += 30                # code moved: same fingerprint
    assert derive.cluster_fingerprint(k) == fp
    k["canonical_location"]["symbol"] = "routes/invoices.ts::listInvoices"
    assert derive.cluster_fingerprint(k) != fp


def test_fingerprint_is_recomputed(b):
    doc(b, "cluster.k-014.example.json").data["fingerprint"] = doc(b, "cluster.example.json").data["fingerprint"]
    assert "E-CLUSTER-FINGERPRINT" in codes(b)


def test_black_box_fingerprint_uses_the_endpoint(b):
    k = doc(b, "cluster.k-201.example.json").data
    assert k["fingerprint"] == derive.sha256_ref(derive.jcs({"cwe_bucket": "authz", "target_id": "tgt-staging-api", "method": "GET",
                                                             "path_template": "/api/invoices"}))


def test_baseline_state_without_baseline_is_null(b):
    assert all(d.data["baseline_state"] is None for d in b.docs if d.kind == "cluster" and d.data.get("carried_from") is None)
    assert doc(b, "cluster.followup.k-301.example.json").data["baseline_state"] == "updated"   # r8: carried into the follow-up run
    doc(b, "cluster.example.json").data["baseline_state"] = "new"
    assert "E-CLUSTER-BASELINE" in codes(b)


def test_baseline_states(b):
    """A follow-up run (baseline = the first run) re-finds K-005: unchanged; with other evidence: updated; elsewhere: new."""
    run_f = doc(b, RUN_F).data
    assert run_f["baseline_run_id"] == "run-2026-09-23-001"
    f = copy.deepcopy(doc(b, "finding.f-021.example.json").data)
    f.update(finding_id="F-321", run_id=run_f["run_id"])
    b.docs.append(Doc("docs/schemas/examples/finding.f-321.example.json", "finding", f, None))
    k = copy.deepcopy(doc(b, "cluster.example.json").data)
    k.update(cluster_id="K-301", run_id=run_f["run_id"], member_finding_ids=["F-017", "F-321"])
    assert derived_baseline_state(Ctx(b), k) == "unchanged"          # same fingerprint, same member evidence
    f["evidence"][0]["snippet_sha256"] = "sha256:" + "1" * 64       # the code at the sink changed
    assert derived_baseline_state(Ctx(b), k) == "updated"
    k["canonical_location"]["symbol"] = "routes/invoices.ts::listInvoices"
    assert derived_baseline_state(Ctx(b), k) == "new"


def test_absent_fingerprints(b, keys):
    doc(b, RUN).data["baseline_run_id"] = "run-2026-09-25-pr-118"        # hypothetical baseline: the Lane A run
    hits = errs(b, "E-CLUSTER-BASELINE")
    assert any("absent_fingerprints" in h.msg for h in hits) and any("baseline_state" in h.msg for h in hits)
    for d in b.docs:
        if d.kind == "cluster" and d.data["run_id"] == "run-2026-09-23-001":
            d.data["baseline_state"] = "new"
    k101 = doc(b, "cluster.k-101.example.json").data
    doc(b, "report-manifest.example.json").data["absent_fingerprints"] = [k101["fingerprint"]]
    rederive(b, keys)
    assert "E-CLUSTER-BASELINE" not in codes(b)


# ================================================================ B10 agent tools, commander plans (and D16)
@pytest.mark.parametrize("agent,tools", [("commander", ["read_blackboard"]), ("invariant_drafter", ["read_slice", "write_blackboard"]),
                                         ("rev_a", ["read_slice", "write_blackboard"]), ("ver_1", ["read_blackboard"])])
def test_agent_tool_grants(b, agent, tools):
    doc(b, "agents.yaml").data[agent]["tools"] = tools
    assert "E-AGENT-TOOLS" in codes(b)


def test_agent_tool_grants_example(b):
    a = doc(b, "agents.yaml").data
    assert a["commander"]["tools"] == [] and a["invariant_drafter"]["tools"] == ["read_inventory", "write_blackboard"]
    assert "E-AGENT-TOOLS" not in codes(b)


def test_typed_extra_dispatch_target(b):
    p = doc(b, PLAN).data
    p["extra_dispatch"] = [{"target": {"kind": "cluster", "id": "K-011"}, "agents": ["ver_3"], "reason": "second verifier round"}]
    assert not {"E-PLAN-TARGET", "E-PLAN-AGENTS"} & codes(b)
    p["extra_dispatch"][0]["target"] = {"kind": "cluster", "id": "T-031"}          # a threat id under kind cluster
    assert "E-PLAN-TARGET" in codes(b)
    p["extra_dispatch"][0]["target"] = "K-011"                                     # the v0.2 plain string
    assert "E-SCHEMA" in codes(b)


def test_plan_round_bound(b):
    doc(b, PLAN).data["round"] = 3
    got = codes(b)
    assert "E-PLAN-ROUNDS" in got and "E-SCHEMA" in got
    doc(b, PLAN).data["round"] = 2
    doc(b, RUN).data["cmd2_rounds"] = 3
    assert "E-PLAN-ROUNDS" in codes(b)


def test_plan_agents_must_have_the_right_role(b):
    """D16: v0.2 never checked commander-plan agents."""
    doc(b, PLAN).data["slices"][0]["agents"] = ["rev_a", "ver_1"]
    assert "E-PLAN-AGENTS" in codes(b)
    doc(b, PLAN).data["slices"][0]["agents"] = ["rev_a", "ghost"]
    assert "E-PLAN-AGENTS" in codes(b)


def test_plan_budget_within_the_run_budget(b):
    """D16: budget_tokens was unchecked in v0.2."""
    doc(b, PLAN).data["budget_tokens"] = 25_000_000                # W phase cap is 20M after GB
    assert "E-PLAN-BUDGET" in codes(b)


# ================================================================ B11 run manifest
def test_config_refs_are_hashed(b):
    doc(b, "agents.yaml").data["rev_a"]["facets"] = ["authz"]
    hits = [i for i in errs(b, "E-DERIVED") if "config_refs" in i.msg]
    assert hits and all("agents" in h.msg for h in hits)


def test_config_ref_path_must_be_the_right_kind(b):
    doc(b, RUN).data["config_refs"]["models"]["path"] = "docs/examples/agents.yaml"
    assert "E-RUN-CONFIG" in codes(b)


def test_tool_versions_agree_with_the_audit_log(b):
    tv = next(t for t in doc(b, RUN).data["tool_versions"] if t["adapter"] == "opengrep:scan")
    tv["version"] = "1.5.0"
    assert "E-RUN-CONFIG" in codes(b)
    doc(b, RUN).data["tool_versions"].append({"adapter": "nope:x", "version": "1", "image_digest": None})
    assert len(errs(b, "E-RUN-CONFIG")) == 2


def test_rule_version_is_checked(b):
    """triage H-E13: rule_version 'totally-made-up' gave 0 errors."""
    doc(b, RUN).data["rule_version"] = "totally-made-up"
    assert "E-RUN-RULE-VERSION" in codes(b)
    doc(b, RUN).data["rule_version"] = adj.RULE_VERSION
    doc(b, "verdict.k-014-w3.example.json").data["rule_version"] = "totally-made-up"
    got = codes(b)
    assert {"E-RUN-RULE-VERSION", "E-VERDICT-RULE-VERSION"} <= got


# ================================================================ E6 slice identity
def test_slice_id_covers_prompt_template_and_redaction_map(b):
    s = doc(b, "slice.example.json").data
    old = s["slice_id"]
    assert old == derive.slice_identity(s["files"], s["redaction_map_sha256"], s["prompt_template_sha256"])
    assert old != derive.sha256_ref(derive.jcs(s["files"]))                       # the v0.2 identity
    s["prompt_template_sha256"] = "sha256:" + "2" * 64
    got = codes(b)
    assert "E-SLICE-IDENTITY" in got and "E-DERIVED" in got                      # not a run template; slice_id changes


def test_slice_redaction_map_must_be_the_runs(b):
    doc(b, "slice.example.json").data["redaction_map_sha256"] = "sha256:" + "3" * 64
    assert "E-DERIVED" in codes(b)


# ================================================================ D14 provenance
def test_threat_modeller_family_is_from_the_registry(b):
    """v0.2: threat.modeled_by could be fabricated with 0 errors."""
    doc(b, "threat.example.json").data["modeled_by"][0]["family"] = "openai"     # tm_a is claude_sonnet
    assert "E-PROVENANCE" in codes(b)


def test_threat_modeller_role(b):
    doc(b, "threat.example.json").data["modeled_by"][0]["agent_id"] = "rev_a"
    assert "E-PROVENANCE" in codes(b)


def test_invariant_drafter_provenance(b):
    doc(b, "invariants.yaml").data["drafted_by"] = {"agent_id": "rev_b", "family": "openai"}
    assert "E-PROVENANCE" in codes(b)
    doc(b, "invariants.yaml").data["drafted_by"] = {"agent_id": "invariant_drafter", "family": "anthropic"}
    assert "E-PROVENANCE" in codes(b)


# ================================================================ D15 fallback chain data class
def test_fallback_to_a_p_only_model_is_rejected(b):
    """triage M-V1: claude_sonnet (C data) falling back to a P-only model outside allowed_models.C gave 0 errors."""
    m = doc(b, "models.yaml").data
    m["claude_haiku_p"] = dict(copy.deepcopy(m["claude_opus_48"]), data_classes=["P"], litellm="anthropic/claude-haiku-p")
    m["claude_sonnet"]["fallback"] = ["claude_haiku_p"]
    hits = errs(b, "E-MODEL-FALLBACK-CLASS")
    assert hits and all("claude_haiku_p" in h.msg for h in hits)
    assert {"commander", "rev_a", "ver_2"} <= {h.where.split(" ")[-1] for h in hits}


def test_fallback_chain_positive(b):
    assert "E-MODEL-FALLBACK-CLASS" not in codes(b)          # claude_sonnet -> claude_opus_48 takes C and is allowed


# ================================================================ B14 pricing fields
def test_pricing_shape(b):
    m = doc(b, "models.yaml").data["claude_sonnet"]
    m["pricing"] = {"input_usd_per_mtok": 3.0, "output_usd_per_mtok": 15.0, "as_of": "2026-09-01", "source": "vendor price page"}
    m["rate_limits"] = {"rpm": 50, "tpm": None}
    m["tokenizer"] = "claude"
    assert "E-SCHEMA" not in codes(b)
    m["pricing"] = {"input_usd_per_mtok": 3.0}
    assert "E-SCHEMA" in codes(b)
