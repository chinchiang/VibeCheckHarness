# SPDX-License-Identifier: Apache-2.0
"""Check group over the engagement (providers, cross-border transfers, config pins, deployment profile), and the
engagement accessors other groups use: profile, deployment, consolidation_person.

Split out of checks.py (architecture refactor PR-D3, docs/adr/0003-split-checks.md). The text is moved verbatim; no
rule, error code or message changed. checks.GROUPS still lists the group in the same place.
"""
from __future__ import annotations

from urllib.parse import urlsplit

from . import safety
from .canonical import content_hash
from .checks_models import reachable_models
from .context import Ctx
from .report import GATE_ROLES, PUBLISH_SCOPES, ROE_GATES, Report, retention_max, ts


# ============================================================== engagement accessors (used by several groups)
def profile(c: Ctx) -> str:
    return c.engagement.get("assurance_profile") or "team"


SINGLE_HOST = "single_host"
ANCHOR_LABEL = {SINGLE_HOST: "local"}          # report-manifest.audit_anchor by deployment profile; otherwise "countersigned"


def deployment(c: Ctx) -> str:
    """BL-70 / D10 (2026-11-22 review): the engagement's deployment profile; an engagement that names none is three_zone."""
    return c.engagement.get("deployment_profile") or "three_zone"


def deployment_problems(c: Ctx) -> list[str]:
    """The single-host profile (docs/08 section 11.20) is the one-person, white-box deployment: one OS user holds every key
    and runs the anchor countersigner. It is only for assurance_profile lite with an acknowledged role_consolidation, and
    it has no black-box phase (the Scope Proxy and the executor zone are safety controls, not evidence; it has neither)."""
    if deployment(c) != SINGLE_HOST:
        return []
    out = []
    if profile(c) != "lite":
        out.append(f"deployment_profile single_host is only allowed with assurance_profile lite (got {profile(c)})")
    elif consolidation_person(c) is None:
        out.append("deployment_profile single_host needs an acknowledged role_consolidation (one person holds every key)")
    gates = sorted({d.data.get("gate") for d in c.docs("gate-record") if d.data.get("gate") in ROE_GATES})
    if gates:
        out.append(f"deployment_profile single_host is white-box only, but the bundle has {', '.join(gates)} records "
                   "(the black-box phase needs the three_zone deployment)")
    return out


def consolidation_person(c: Ctx) -> str | None:
    """The one person allowed to hold several ROE / gate roles: only in lite, only when acknowledged."""
    rc = c.engagement.get("role_consolidation") or {}
    if profile(c) == "lite" and rc.get("acknowledged") is True:
        return rc.get("person_id")
    return None


# ============================================================== 7 engagement
def models_in_use(c: Ctx) -> set:
    """The models agents.yaml can call: each agent's model, its cross-family fallback_models, and the models.yaml
    fallback chain of each of them."""
    out, todo = set(), []
    for a in (c.agents or {}).values():
        if isinstance(a, dict):
            todo += [a.get("model")] + list(a.get("fallback_models") or [])
    while todo:
        k = todo.pop()
        if isinstance(k, str) and k not in out:
            out.add(k)
            todo += list((c.model(k) or {}).get("fallback") or [])
    return out


def pricing_rules(R: Report, c: Ctx, w: str, bud: dict):
    """E-ENG-PRICING (third external review, r13; docs/08 §11.12): a USD cap can only be enforced on a model whose unit
    prices are known. A cloud model with pricing null may run only when the engagement states a conservative upper
    bound for it (budgets.price_assumptions[model_key], signed with the engagement); the estimate and the caps then use
    that bound. Until r13 the docs called the cap "fail-closed" while an unknown-priced model ran against a cap nobody
    could enforce (the report only said "費用不完整"). Self-hosted models (hosting: self) bill no API fee."""
    assumed = bud.get("price_assumptions") or {}
    for k, px in assumed.items():
        if not R.check(c.model(k) is not None, "E-ENG-PRICING", w, f"budgets.price_assumptions.{k}: unknown model"):
            continue
        for f in ("input_usd_per_mtok", "output_usd_per_mtok"):
            v = (px or {}).get(f)
            R.check(isinstance(v, (int, float)) and not isinstance(v, bool) and v > 0, "E-ENG-PRICING", w,
                    f"budgets.price_assumptions.{k}.{f} must be a positive unit price (an upper bound the signer stands behind)")
    for k in sorted(models_in_use(c)):
        m = c.model(k)
        if m is None:                                                        # E-MODEL-UNKNOWN elsewhere
            continue
        if m.get("hosting") == "cloud" and m.get("pricing") is None:
            R.check(k in assumed, "E-ENG-PRICING", w,
                    f"model {k} is a cloud model with pricing null and no budgets.price_assumptions.{k}: the USD cap cannot be "
                    "enforced on it, so the run is refused (docs/08 §11.12; state a conservative price bound or price the model)")


def g_engagement(R: Report, c: Ctx):
    e, tk, w = c.engagement, c.toolkit, "engagement.yaml"
    if not e:
        R.error("E-ENG-MISSING", w, "no engagement")
        return
    v = e.get("validity") or {}
    nb, na = ts(R, v.get("not_before"), w), ts(R, v.get("not_after"), w)
    iss = ts(R, e.get("issued_at"), w)
    R.check(nb and na and nb < na, "E-ENG-VALIDITY", w, "validity.not_before must precede not_after")
    R.check(iss and na and iss <= na, "E-ENG-VALIDITY", w, "issued_at after the end of validity")
    dc = e.get("data_class")
    R.check(dc in ("P", "C"), "E-ENG-DATA-CLASS", w, f"data_class {dc!r} must be P or C")
    for cls, keys in (e.get("allowed_models") or {}).items():
        for k in keys:
            m = c.model(k)
            if not R.check(m is not None, "E-MODEL-UNKNOWN", w, f"allowed_models.{cls}: unknown model {k!r}"):
                continue
            R.check(cls in m.get("data_classes", []), "E-ENG-MODEL-CLASS", w, f"allowed_models.{cls} lists {k}, which cannot take {cls} data")
    allowed = set((e.get("allowed_models") or {}).get(dc, []))
    R.check(e.get("lane_a_model") in allowed, "E-ENG-LANE-A", w, f"lane_a_model {e.get('lane_a_model')} not allowed for {dc}")
    for g, h in (e.get("gate_timeouts_hours") or {}).items():
        lim = (tk.get("gate_timeouts_hours") or {}).get(g)
        R.check(lim is not None and h <= lim, "E-ENG-TIMEOUT", w, f"gate_timeouts_hours.{g}={h} exceeds toolkit {lim}")
    bud = e.get("budgets") or {}
    total = bud.get("run_total") or {}
    for ph, caps in bud.items():
        if ph == "families":
            continue
        for k, val in caps.items():
            R.check(val is not None, "E-ENG-BUDGET", w, f"budgets.{ph}.{k} must be set (no default for cost caps)")
            if ph != "run_total" and val is not None and total.get(k) is not None:
                R.check(val <= total[k], "E-ENG-BUDGET", w, f"budgets.{ph}.{k} exceeds run_total")
    # v0.5 (BL-14, docs/08 §11.12): per-family USD caps name a models.yaml family and stay within run_total
    families = {m.get("family") for m in c.models.values() if isinstance(m, dict)}
    for fam, cap in (bud.get("families") or {}).items():
        R.check(fam in families, "E-ENG-BUDGET", w, f"budgets.families.{fam}: not a models.yaml family {sorted(map(str, families))}")
        mx = (cap or {}).get("max_cost_usd")
        R.check(not isinstance(total.get("max_cost_usd"), (int, float)) or not isinstance(mx, (int, float)) or mx <= total["max_cost_usd"],
                "E-ENG-BUDGET", w, f"budgets.families.{fam}.max_cost_usd {mx} exceeds run_total.max_cost_usd {total.get('max_cost_usd')}")
    pricing_rules(R, c, w, bud)
    # v0.5 (BL-17, docs/08 §11.16): publishing is off unless the engagement names a platform and least-privilege scopes
    pub = e.get("publishing") or {}
    if pub.get("enabled") is True:
        allowed = PUBLISH_SCOPES.get(pub.get("platform"), frozenset())  # type: ignore[assignment,arg-type]  # an unknown platform has no scopes; allowed is only read
        scopes = set(pub.get("token_scopes") or [])
        R.check(bool(allowed) and bool(scopes) and scopes <= allowed, "E-ENG-PUBLISH", w,
                f"publishing.enabled needs a platform and token_scopes within {sorted(allowed)} (got {pub.get('platform')!r}, {sorted(scopes)})")
    else:
        R.check(pub.get("platform") is None and not pub.get("token_scopes"), "E-ENG-PUBLISH", w,
                "publishing is disabled: platform must be null and token_scopes empty")
    # retention: toolkit.yaml retention = org maximum (and default); engagement retention_days =
    # effective value, tighten-only (toolkit < engagement < ROE precedence, docs/08 §7.5) [H]
    lim = retention_max(tk, dc)
    rd = e.get("retention_days")
    R.check(lim is not None, "E-RETENTION", w, f"toolkit.yaml has no retention maximum for data class {dc}")
    if lim is not None:
        R.check(isinstance(rd, int) and 1 <= rd <= lim, "E-RETENTION", w,
                f"retention_days {rd} must be 1..{lim} (toolkit.yaml retention maximum for {dc}; engagements may only shorten it)")
    att = (e.get("code_ownership") or {}).get("attested_by") or {}
    R.check(att.get("role") == "app_owner", "E-ENG-OWNERSHIP", w, "code_ownership.attested_by must be the app_owner")
    R.check(any(s.get("person_id") == att.get("person_id") and s.get("key_fingerprint") == att.get("key_fingerprint")
                for s in e.get("signatories") or []), "E-ENG-OWNERSHIP", w, "code_ownership.attested_by must also sign the engagement")
    R.check((e.get("code_ownership") or {}).get("attestation") is True, "E-ENG-OWNERSHIP", w, "attestation must be true")
    roles = {s.get("role") for s in e.get("signatories") or []}
    R.check(GATE_ROLES["G0a"] <= roles, "E-ENG-SIGNATORIES", w, f"signatories must include {sorted(GATE_ROLES['G0a'])}")
    R.check(e.get("owasp_llm_version") in (None, "2025", "2026"), "E-ENG-OWASP", w, "owasp_llm_version must be null, 2025 or 2026")
    rc = e.get("role_consolidation")
    if e.get("assurance_profile") != "lite":
        R.check(rc is None or rc.get("acknowledged") is not True, "E-ENG-PROFILE", w, "role_consolidation is only used with assurance_profile lite")
    elif isinstance(rc, dict) and rc.get("acknowledged") is True:
        R.check(rc.get("person_id") in c.persons and bool(rc.get("statement")), "E-ENG-PROFILE", w,
                "an acknowledged role_consolidation needs a registry person_id and a statement")
    for m in deployment_problems(c):
        R.check(False, "E-ENG-DEPLOYMENT", w, m)
    provider_rules(R, c)
    transfer_rules(R, c)
    config_pin_rules(R, c)
    R.check(e.get("telemetry_disabled") is True, "E-ENG-TELEMETRY", w, "telemetry_disabled must be true")


def z4_hosts(c: Ctx) -> set[str]:
    """toolkit.yaml z4_model_hosts: the exact host names of the Z4 self-hosted model servers."""
    hosts = c.toolkit.get("z4_model_hosts") if isinstance(c.toolkit, dict) else None
    return {safety.norm_host(h) for h in hosts if isinstance(h, str)} if isinstance(hosts, list) else set()


def self_hosted(m: dict, c: Ctx) -> bool:
    """v0.4 (D2): a model is self-hosted in Z4 iff its api_base host equals a toolkit.yaml z4_model_hosts entry.

    v0.3 accepted any host that started with "z4-", so https://z4-evil.attacker.example could take C data."""
    try:
        host = urlsplit(m.get("api_base") or "").hostname or ""
    except ValueError:
        return False
    return bool(host) and safety.norm_host(host) in z4_hosts(c)


def provider_rules(R: Report, c: Ctx):
    """B13 (H-E14): every model an agent can reach that may receive C data (engagement data class C and the model
    takes C) is self-hosted in Z4, or its family has zdr confirmed and a signed DPA."""
    e, w = c.engagement, "engagement.yaml"
    if e.get("data_class") != "C":
        return
    prov = {p.get("family"): p for p in e.get("providers") or [] if isinstance(p, dict)}
    for k, users in sorted(reachable_models(c).items()):
        m = c.model(k)
        if not m or "C" not in (m.get("data_classes") or []) or self_hosted(m, c):
            continue
        p = prov.get(m.get("family")) or {}
        if not R.check(p.get("zdr") == "confirmed" and p.get("dpa_signed") is True, "E-ENG-PROVIDER", w,
                       f"{k} ({m.get('family')}) can receive C data (agents {sorted(users)}) but providers.{m.get('family')} is not "
                       f"zdr confirmed with a signed DPA (and the model is not self-hosted in Z4)"):
            continue
        for msg in zdr_problems(R, e, p, k):
            R.check(False, "E-ENG-PROVIDER", w, f"{k} ({m.get('family')}) can receive C data but {msg}")


def zdr_problems(R: Report, e: dict, p: dict, model_key: str) -> list[str]:
    """C6 (2026-11-22 review): what a `zdr: confirmed` line must also say before a cloud model receives C data. One word
    in a signed file was the whole control; a provider may exclude single models from ZDR and a confirmation ends with
    its contract. So the confirmation names its evidence, the models it covers and the period it holds for, and that
    period covers the engagement: confirmed no later than issued_at, expiring no earlier than validity.not_after."""
    fam, out, w = p.get("family"), [], "engagement.yaml"
    if not p.get("zdr_evidence_ref"):
        out.append(f"providers.{fam}.zdr_evidence_ref is empty (a confirmation without a reference cannot be reviewed)")
    if model_key not in (p.get("zdr_models") or []):
        out.append(f"providers.{fam}.zdr_models does not list it (the confirmation is per model)")
    got, exp = ts(R, p.get("zdr_confirmed_at"), w, "zdr_confirmed_at"), ts(R, p.get("zdr_expires_at"), w, "zdr_expires_at")
    issued, until = ts(R, e.get("issued_at"), w, "issued_at"), ts(R, (e.get("validity") or {}).get("not_after"), w, "validity.not_after")
    if got is None or (issued is not None and got > issued):
        out.append(f"providers.{fam}.zdr_confirmed_at {p.get('zdr_confirmed_at')!r} must be set and not later than issued_at {e.get('issued_at')!r}")
    if exp is None or (until is not None and exp < until):
        out.append(f"providers.{fam}.zdr_expires_at {p.get('zdr_expires_at')!r} must be set and not earlier than validity.not_after "
                   f"{(e.get('validity') or {}).get('not_after')!r} (the confirmation must hold for the whole engagement)")
    return out


def c_cloud_families(c: Ctx) -> dict[str, list[str]]:
    """family -> model keys of the models agents can reach that may receive C data and are not self-hosted in Z4."""
    out: dict[str, list[str]] = {}
    if (c.engagement or {}).get("data_class") != "C":
        return out
    for k in sorted(reachable_models(c)):
        m = c.model(k)
        if m and "C" in (m.get("data_classes") or []) and not self_hosted(m, c) and isinstance(m.get("family"), str):
            out.setdefault(m["family"], []).append(k)
    return out


def transfer_rules(R: Report, c: Ctx):
    """v0.4 (C1): the cross-border declaration is verified at G0a, before W2 sends code to any cloud model.

    Every cloud family that can receive C data has a providers[].region (not null) and a data_transfer.transfers
    entry with the same region; a region other than source_jurisdiction needs a mechanism other than
    same_jurisdiction and a reference. The declarer is an engagement signatory, so the G0a signature covers it.
    v0.3 only had legal_review.scope.cross_border in the ROE, which no node before G0b reads."""
    e, w = c.engagement, "engagement.yaml"
    dt = e.get("data_transfer")
    if not R.check(isinstance(dt, dict), "E-ENG-TRANSFER", w, "data_transfer is required (checked at G0a)"):
        return
    R.check(dt.get("attested_by") in {s.get("person_id") for s in e.get("signatories") or [] if isinstance(s, dict)},  # type: ignore[union-attr]  # R.check above returned when it is not a dict
            "E-ENG-TRANSFER", w, f"data_transfer.attested_by {dt.get('attested_by')!r} must be an engagement signatory")  # type: ignore[union-attr]  # R.check above returned when it is not a dict
    src = dt.get("source_jurisdiction")  # type: ignore[union-attr]  # R.check above returned when it is not a dict
    prov = {p.get("family"): p for p in e.get("providers") or [] if isinstance(p, dict)}
    transfers = [t for t in dt.get("transfers") or [] if isinstance(t, dict)]  # type: ignore[union-attr]  # R.check above returned when it is not a dict
    for fam, keys in sorted(c_cloud_families(c).items()):
        region = (prov.get(fam) or {}).get("region")
        if not R.check(isinstance(region, str), "E-ENG-TRANSFER", w,
                       f"providers.{fam}.region is null, but {keys} can receive C data: the processing region must be declared"):
            continue
        t = next((t for t in transfers if t.get("family") == fam and t.get("region") == region), None)
        if not R.check(t is not None, "E-ENG-TRANSFER", w,
                       f"no data_transfer.transfers entry for {fam} in {region} ({keys} can receive C data)"):
            continue
        if region == src:
            R.check(t.get("mechanism") == "same_jurisdiction", "E-ENG-TRANSFER", w,  # type: ignore[union-attr]  # R.check above continued when t is None
                    f"{fam}: region {region} equals source_jurisdiction, so mechanism must be same_jurisdiction")
        else:
            R.check(t.get("mechanism") != "same_jurisdiction" and bool(t.get("reference")), "E-ENG-TRANSFER", w,  # type: ignore[union-attr]  # R.check above continued when t is None
                    f"{fam}: {src} -> {region} is a cross-border transfer; it needs a mechanism other than same_jurisdiction and a reference")


def missing_jurisdictions(c: Ctx) -> list[str]:
    """The jurisdictions of the engagement's data_transfer (source and every transfer region) that the ROE's
    legal_review.jurisdictions does not list."""
    dt = (c.engagement or {}).get("data_transfer") or {}
    named = [dt.get("source_jurisdiction")] + [t.get("region") for t in dt.get("transfers") or [] if isinstance(t, dict)]
    covered = set(((c.roe or {}).get("legal_review") or {}).get("jurisdictions") or [])
    return sorted({j for j in named if isinstance(j, str) and j and j not in covered})


def cross_border_declared(c: Ctx) -> bool:
    """Some engagement transfer leaves the source jurisdiction."""
    dt = (c.engagement or {}).get("data_transfer") or {}
    return any(isinstance(t, dict) and t.get("region") != dt.get("source_jurisdiction") for t in dt.get("transfers") or [])


# v0.5 (review 2026-10-25 T-10 / V-6): calibration and crosswalk decide verdicts and threat links, so they are pinned too
# v0.7 (review r8 M1): toolkit.yaml carries security policy (root-key fingerprint, automation accounts, gate timeouts and
# queue caps, stop-condition defaults, retention caps), so it is pinned too
CONFIG_PIN_KINDS = {"models": "model-registry", "agents": "agent-registry", "tools": "tool-registry", "licenses": "licenses", "toolkit": "toolkit-config",
                    "calibration": "calibration", "crosswalk": "crosswalk"}


def config_pin_rules(R: Report, c: Ctx):
    """v0.4 (E1): models / agents / tools / licenses are pinned by content hash in the signed engagement.
    v0.3 did not sign them, although they decide C-data routing, family diversity, S0/S2 and the legal gate."""
    pins = (c.engagement or {}).get("config_pins")
    if not R.check(isinstance(pins, dict), "E-ENG-CONFIG-PIN", "engagement.yaml", "config_pins is required"):
        return
    for key, kind in CONFIG_PIN_KINDS.items():
        data = c.b.data(kind)
        got = content_hash(data) if data is not None else None
        R.check(pins.get(key) == got, "E-ENG-CONFIG-PIN", "engagement.yaml",  # type: ignore[union-attr]  # R.check above returned when pins is not a dict
                f"config_pins.{key} {pins.get(key)} != content hash of the loaded {kind} {got}: "  # type: ignore[union-attr]  # R.check above returned when pins is not a dict
                "the configuration changed after the engagement was signed")
