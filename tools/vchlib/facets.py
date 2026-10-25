# SPDX-License-Identifier: Apache-2.0
"""Review facets (E7, H-F1): the 13 facets (12 + cicd_iac in v0.4), the CWE buckets each facet may produce, and the facets every
commander plan must cover, derived deterministically from the W0 inventory."""
from __future__ import annotations

FACETS = ("authz", "authn_session", "injection", "data_access", "secrets_config", "business_logic", "llm_integration",
          "file_handling", "ssrf_outbound", "frontend_client", "webhooks_integrations", "crypto", "cicd_iac")

# facet -> CWE buckets (common.schema.json cwe_bucket) a finding of that facet may be clustered into
FACET_BUCKETS: dict[str, frozenset[str]] = {
    "authz": frozenset({"authz"}),
    "authn_session": frozenset({"authn", "crypto", "config"}),
    "injection": frozenset({"injection", "deserialization", "path_traversal"}),
    "data_access": frozenset({"authz", "injection", "config"}),
    "secrets_config": frozenset({"secrets", "config", "crypto"}),
    "business_logic": frozenset({"authz", "other"}),
    "llm_integration": frozenset({"llm_specific", "authz", "injection"}),
    "file_handling": frozenset({"path_traversal", "deserialization", "injection", "config"}),
    "ssrf_outbound": frozenset({"ssrf"}),
    "frontend_client": frozenset({"secrets", "config", "injection", "authn"}),
    "webhooks_integrations": frozenset({"authn", "crypto", "ssrf", "config"}),
    "crypto": frozenset({"crypto", "secrets"}),
    # v0.4: the app's own CI/CD workflows and IaC / platform config (pull_request_target, expression injection
    # into run:, vercel.json / supabase/config.toml)
    "cicd_iac": frozenset({"injection", "secrets", "config", "authz"}),
}

# v0.5 (review 2026-10-25 V-8): the bucket of common CWEs. A white-box cluster's cwe_bucket must be the bucket of one of
# its members' CWEs whenever any of them is listed here (E-CLUSTER-BINDING); clusters whose members carry only unlisted
# CWEs get W-CLUSTER-BUCKET. Curated [H]; extend it with the calibration buckets.
CWE_BUCKETS: dict[str, str] = {
    **{c: "authz" for c in ("CWE-284", "CWE-285", "CWE-639", "CWE-862", "CWE-863", "CWE-915", "CWE-269")},
    **{c: "authn" for c in ("CWE-287", "CWE-288", "CWE-306", "CWE-307", "CWE-384", "CWE-613", "CWE-640")},
    **{c: "injection" for c in ("CWE-74", "CWE-77", "CWE-78", "CWE-79", "CWE-89", "CWE-90", "CWE-94", "CWE-917", "CWE-943")},
    **{c: "path_traversal" for c in ("CWE-22", "CWE-23", "CWE-73")},
    **{c: "deserialization" for c in ("CWE-502",)},
    **{c: "ssrf" for c in ("CWE-918",)},
    **{c: "secrets" for c in ("CWE-798", "CWE-312", "CWE-200", "CWE-522")},
    **{c: "crypto" for c in ("CWE-327", "CWE-328", "CWE-330", "CWE-347")},
    **{c: "config" for c in ("CWE-16", "CWE-942", "CWE-1021", "CWE-693")},
    **{c: "llm_specific" for c in ("CWE-1427", "CWE-1426")},
}

BASE_FACETS = frozenset({"authz", "authn_session", "injection", "data_access", "secrets_config", "business_logic"})
FEATURE_FACETS = {                     # inventory.features value -> facet it makes mandatory
    "file_upload": "file_handling",
    "outbound_http": "ssrf_outbound",
    "webhook_inbound": "webhooks_integrations",
    "frontend_bundle": "frontend_client",
    "crypto": "crypto",
    "ci_workflows": "cicd_iac",          # v0.4
    "iac": "cicd_iac",                   # v0.4
}


def mandatory_facets(inventory: dict | None) -> set[str]:
    """MANDATORY_FACETS rule: the 6 base facets; + llm_integration when inventory.llm_integrations is non-empty;
    + file_handling (file_upload), ssrf_outbound (outbound_http), webhooks_integrations (webhook_inbound),
    frontend_client (frontend_bundle, or any env var with a public prefix), crypto (crypto),
    cicd_iac (ci_workflows or iac, v0.4)."""
    inv = inventory or {}
    out = set(BASE_FACETS)
    if inv.get("llm_integrations"):
        out.add("llm_integration")
    feats = set(inv.get("features") or [])
    out |= {f for feat, f in FEATURE_FACETS.items() if feat in feats}
    if any(isinstance(e, dict) and e.get("public_prefix") for e in inv.get("env_vars") or []):
        out.add("frontend_client")
    return out


MANDATORY_FACETS = mandatory_facets      # the rule, under the name used in the docs

__all__ = ["FACETS", "FACET_BUCKETS", "CWE_BUCKETS", "BASE_FACETS", "FEATURE_FACETS", "mandatory_facets", "MANDATORY_FACETS"]
