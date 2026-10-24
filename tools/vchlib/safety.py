# SPDX-License-Identifier: Apache-2.0
"""Safety-class computation: the docs/04 §5 pseudo-code (v0.3, D13 tool IDs), verbatim in
logic, plus a trace so the validator can explain its result.

Differences from v0.1: unregistered or malformed adapter -> S3; registered mode with base_class
null -> >= S2; white-box-only mode (b4_executable false) -> S3; excluded host (compared after
norm_host: trailing dot, case, IDNA; `*.example.com` covers every subdomain but not the apex),
unparseable target host (also any scheme other than http/https), non-normalised path template,
rps above the ROE, empty allow-list, request target outside tc.target_ids, MANUAL kind/adapter
mismatch -> S3. `admissible()` is a separate check against allowed_safety_classes.

v0.3 (H-B3, L-11, D1, D11):
  - exclusion paths are matched after normalisation (percent-decode once, strip `;params` from
    every segment, collapse `//`, resolve `.` / `..`, lower-case on both sides), fail closed;
  - every mutation (POST / PUT / PATCH / DELETE and GraphQL mutations; a GET / POST whose
    graphql_operation is query / introspection is a declared read (runtime parsing still required)) must address an existing object only
    through {seed:<key>} of the seed manifest, or be a request to a seed-manifest
    create_only_endpoints entry; objects created that way are addressed only through
    {created:<step_id>} of an earlier create request in the same allow-list; otherwise S3
    ("mutation scope", E-TC-MUTATION-SCOPE);
  - a {seed:<key>} segment is only valid at a variable position of one of the seed's declared
    path_templates (a DELETE on an invoices seed under /api/users/... is S3).
"""
from __future__ import annotations

import fnmatch
import posixpath
import re
from urllib.parse import unquote, urlsplit

ORDER = ("S0", "S1", "S2", "S3")
STATE_CHANGING = frozenset({"POST", "PUT", "PATCH", "DELETE"})
READ_ONLY_GRAPHQL = frozenset({"query", "introspection"})

# Modes the toolkit never runs. ROE denied_modes can only add to this set.
TOOLKIT_DENYLIST = frozenset({"nuclei:code_protocol", "restler:fuzz"})

ADAPTER_RE = re.compile(r"^[a-z][a-z0-9_]*:[a-z][a-z0-9_]*$")   # D13: tool:mode
SEED_SEG_RE = re.compile(r"^\{seed:([a-z0-9_]+)\}$")            # whole segment is {seed:key}
CREATED_SEG_RE = re.compile(r"^\{created:([a-z][a-z0-9_]*)\}$")  # whole segment is {created:step_id}
MUTATION_SCOPE = "mutation scope"                                # trace prefix -> E-TC-MUTATION-SCOPE


def hi(a: str, b: str) -> str:
    return a if ORDER.index(a) >= ORDER.index(b) else b


def split_adapter(adapter: str) -> tuple[str, str] | None:
    if not isinstance(adapter, str) or not ADAPTER_RE.match(adapter):
        return None
    tool, mode = adapter.split(":", 1)
    return tool, mode


def segments(path: str) -> list[str]:
    return [s for s in path.split("/") if s != ""]


def is_normalized(path: str) -> bool:
    if not path.startswith("/") or "//" in path:
        return False
    if any(c in path for c in "%\\?#"):
        return False
    return all(s not in (".", "..") for s in segments(path))


def is_placeholder(seg: str) -> bool:
    return "{" in seg


def normalize_for_match(path: str) -> str:
    """D1: the form an exclusion is compared against: percent-decode once, strip `;params` from every
    segment, collapse `//`, resolve `.` / `..`, lower-case. Placeholder segments are kept."""
    p = unquote(path or "")
    segs = [s.split(";", 1)[0] if not is_placeholder(s) else s for s in p.split("/")]
    p = "/".join(segs)
    p = re.sub(r"/{2,}", "/", p)
    p = posixpath.normpath("/" + p.lstrip("/")) if p else "/"
    return p.lower()


def path_may_match(template: str, pattern: str) -> bool:
    """Conservative: True if the template *may* expand to a path matching `pattern` (both normalised,
    case-insensitive: case-insensitive routers and servlet `;params` cannot bypass an exclusion)."""
    t, p = segments(normalize_for_match(template)), segments(normalize_for_match(pattern))
    open_tail = bool(p) and p[-1] == "*"
    if open_tail:
        p = p[:-1]
        if len(t) < len(p):
            return False
    elif len(t) != len(p):
        return False
    for ts, ps in zip(t, p):
        if is_placeholder(ts):
            continue
        if not fnmatch.fnmatchcase(ts, ps):
            return False
    return True


def seed_keys(template: str) -> list[str]:
    return [m.group(1) for s in segments(template) if (m := SEED_SEG_RE.match(s))]


def created_refs(template: str) -> list[str]:
    return [m.group(1) for s in segments(template) if (m := CREATED_SEG_RE.match(s))]


def _manifest_seeds(manifest) -> dict:
    return ((manifest or {}).get("seeds") or {}) if isinstance(manifest, dict) else {}


def is_seed_path(template: str, manifest) -> bool:
    """Every variable segment is {seed:key} with key in the manifest (at least one variable segment)."""
    seeds = _manifest_seeds(manifest)
    if not seeds:
        return False
    var_segs = [s for s in segments(template) if is_placeholder(s)]
    if not var_segs:
        return False
    for s in var_segs:
        m = SEED_SEG_RE.match(s)
        if m is None or m.group(1) not in seeds:
            return False
    return True


def _shape_matches(request_segs: list[str], template: str) -> bool:
    """Same length; literal segments equal; every variable segment of the request is a variable segment of the template."""
    t = segments(template)
    if len(t) != len(request_segs):
        return False
    for rs, ts in zip(request_segs, t):
        if is_placeholder(rs):
            if not is_placeholder(ts):
                return False
        elif is_placeholder(ts) or rs != ts:
            return False
    return True


def seed_path_problem(path: str, manifest) -> str | None:
    """D11: each {seed:key} must be a manifest seed whose path_templates contain this request path shape."""
    seeds = _manifest_seeds(manifest)
    segs = segments(path)
    for k in seed_keys(path):
        spec = seeds.get(k)
        if not isinstance(spec, dict):
            return f"{{seed:{k}}} is not a seed-manifest key"
        if not any(_shape_matches(segs, t) for t in spec.get("path_templates") or [] if isinstance(t, str)):
            return f"{{seed:{k}}} is not declared for {path} (seed path_templates {spec.get('path_templates')})"
    return None


def is_mutation(r: dict) -> bool:
    """Only GET / POST may use a declared GraphQL read exception; no runtime parsing here."""
    op = r.get("graphql_operation")
    if op == "mutation":
        return True
    if op in READ_ONLY_GRAPHQL and r.get("method") in {"GET", "POST"}:
        return False
    return r.get("method") in STATE_CHANGING


def _create_endpoint(manifest, r: dict) -> dict | None:
    segs = segments(r.get("path", ""))
    for e in (manifest or {}).get("create_only_endpoints") or [] if isinstance(manifest, dict) else []:
        if isinstance(e, dict) and e.get("target_id") == r.get("target_id") and e.get("method") == r.get("method") \
                and _shape_matches(segs, e.get("path_template", "")):
            return e
    return None


def created_resource_problem(endpoint: dict) -> str | None:
    """Validate the minimal declarative resource contract; no response execution here."""
    resource = endpoint.get("created_resource")
    if not isinstance(resource, dict):
        return "missing created_resource"
    if not isinstance(resource.get("type"), str) or not re.fullmatch(r"[a-z][a-z0-9_]*", resource["type"]):
        return "invalid created_resource type"
    pointer = resource.get("id_pointer")
    if not isinstance(pointer, str) or not re.fullmatch(r"(?:/(?:[^~/]|~[01])*)+", pointer):
        return "invalid created_resource id_pointer"
    parent = segments(endpoint.get("path_template", ""))
    if not is_normalized(endpoint.get("path_template", "")):
        return "invalid creation path"
    names = [x for x in parent if is_placeholder(x)]
    if len(names) != len(set(names)) or "{created_id}" in names:
        return "ambiguous creation variables"
    paths = resource.get("path_templates")
    if not isinstance(paths, list) or not paths:
        return "missing created_resource path_templates"
    for path in paths:
        if not isinstance(path, str) or not is_normalized(path):
            return "invalid created_resource path"
        parts = segments(path)
        if parts.count("{created_id}") != 1 or any(
            is_placeholder(x) and x != "{created_id}" and x not in names for x in parts
        ):
            return "unbound created_resource variable"
    return None


def created_path_allowed(path: str, step: str, source: dict, endpoint: dict) -> bool:
    """Bind parent variables to the exact creation request, not arbitrary resource IDs."""
    if created_resource_problem(endpoint):
        return False
    bindings = {key: value for key, value in zip(segments(endpoint["path_template"]), segments(source["path"]))
                if is_placeholder(key)}
    bindings["{created_id}"] = "{created:" + step + "}"
    return any(segments(path) == [bindings.get(x, x) for x in segments(template)]
               for template in endpoint["created_resource"]["path_templates"])


def mutation_scope_problems(tc: dict, manifest) -> list[str]:
    """B6 (H-B3, L-11): why requests of the allow-list are outside the seed-bound mutation scope ([] = in scope)."""
    out = []
    creates: dict[str, dict] = {}                   # step_id -> earlier create request
    for i, r in enumerate(tc.get("request_allowlist") or []):
        if not isinstance(r, dict):
            continue
        path = r.get("path", "")
        where = f"{r.get('method')} {path}"
        if r.get("graphql_operation") is not None and (
            r.get("method") not in {"GET", "POST"}
            or (r.get("graphql_operation") == "mutation" and r.get("method") != "POST")
        ):
            out.append(f"{where}: incompatible GraphQL method/operation")
        for s in created_refs(path):
            src = creates.get(s)
            if src is None:
                out.append(f"{where}: {{created:{s}}} is not an earlier create request of this allow-list")
            elif src.get("target_id") != r.get("target_id"):
                out.append(f"{where}: {{created:{s}}} was created on another target")
            elif not created_path_allowed(path, s, src, _create_endpoint(manifest, src) or {}):
                out.append(f"{where}: {{created:{s}}} is not declared for this resource path")
        prob = seed_path_problem(path, manifest)
        if prob:
            out.append(f"{where}: {prob}")
        if is_mutation(r):
            var = [s for s in segments(path) if is_placeholder(s)]
            unbound = [s for s in var if not (SEED_SEG_RE.match(s) or CREATED_SEG_RE.match(s))]
            create = _create_endpoint(manifest, r)
            if unbound:
                out.append(f"{where}: mutation addresses {unbound} that are neither {{seed:key}} nor {{created:step_id}}")
            elif create is None and not var:
                out.append(f"{where}: mutation of a non-seed object (not a seed-manifest create_only_endpoints entry)")
            if create is not None:
                problem = created_resource_problem(create)
                if problem:
                    out.append(f"{where}: {problem}")
                elif r.get("step_id"):
                    if r["step_id"] in creates:
                        out.append(f"{where}: duplicate creation step_id")
                    else:
                        creates[r["step_id"]] = r
    return out


# E2 (H-D3): shared-platform domains. A host under one of these suffixes belongs to the platform, not to the
# customer: DNS TXT / well-known-path proofs do not show ownership of the project; platform_project does.
SHARED_PLATFORM_SUFFIXES = {
    "supabase.co": "supabase",
    "vercel.app": "vercel",
    "netlify.app": "netlify",
    "firebaseapp.com": "firebase",
    "web.app": "firebase",
    "onrender.com": "render",
    "pages.dev": "other",
    "fly.dev": "other",
    "herokuapp.com": "other",
}


# roe.schema.json targets[].endpoint / db_access.endpoint: 'host:port' or '[v6]:port'; no bare
# host, no trailing dot, no empty label
ENDPOINT_RE = re.compile(r"^(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*):[0-9]{1,5}$")


def norm_host(host) -> str:
    """Comparable host name: trailing dot(s) removed, lower-cased, IDNA (punycode) encoded.

    'API.Example.com.' and 'api.example.com' are the same DNS name, so an exclusion must not be
    bypassable by a trailing dot, case or a Unicode spelling. When IDNA encoding fails (IPv6
    literal edge cases, empty label, over-long label) the lower-cased form is used.
    """
    h = str(host or "").strip().rstrip(".").lower()
    try:
        return h.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return h


def host_of(base_url: str | None) -> str | None:
    """Normalised host of an http(s) base_url; None when the URL is unparseable, has no host or is not http(s)."""
    try:
        u = urlsplit(base_url or "")
        h = u.hostname
    except ValueError:            # e.g. 'http://[::1' (invalid IPv6 literal)
        return None
    if u.scheme.lower() not in ("http", "https"):
        return None
    return (norm_host(h) or None) if h else None


def endpoint_host(endpoint: str | None) -> str | None:
    """Normalised host of a database endpoint 'host:port' or '[v6]:port' (IPv6 without brackets).

    Only the roe.schema.json endpoint forms are accepted: a bare host without port, '[::1'
    (unclosed bracket), '::1:5432' (unbracketed IPv6) or a trailing dot give None (unparseable),
    which callers report as E-ROE-DB-SCOPE instead of crashing.
    """
    if not isinstance(endpoint, str) or not ENDPOINT_RE.match(endpoint):
        return None
    try:
        h = urlsplit("//" + endpoint).hostname
    except ValueError:
        return None
    return (norm_host(h) or None) if h else None


def target_host(target: dict) -> str | None:
    """Host a ROE target resolves to: base_url host (http) or endpoint host (database); None if unparseable."""
    if target.get("kind") == "database":
        return endpoint_host(target.get("endpoint"))
    return host_of(target.get("base_url"))


def host_matches(host: str | None, pattern) -> bool:
    """D2: exact match after norm_host, or a leading-wildcard pattern `*.example.com` that matches every
    subdomain of example.com (at any depth) but not example.com itself."""
    h = norm_host(host) if host else ""
    if not h or not isinstance(pattern, str):
        return False
    p = pattern.strip()
    if p.startswith("*."):
        base = norm_host(p[2:])
        return bool(base) and h.endswith("." + base)
    return bool(norm_host(p)) and h == norm_host(p)


def host_excluded(host: str | None, excluded_hosts) -> bool:
    """ROE exclusions.hosts match (an empty host never matches)."""
    return any(host_matches(host, x) for x in excluded_hosts or [])


def registry_entry(tools: dict, adapter: str) -> dict | None:
    """tools.yaml lookup: {tool, mode, base_class, b4_executable, ...} or None."""
    parsed = split_adapter(adapter)
    if parsed is None:
        return None
    tool, mode = parsed
    spec = (tools or {}).get("tools", {}).get(tool, {}).get("modes", {}).get(mode)
    return None if spec is None else {"tool": tool, "mode": mode, **spec}


def compute_safety_class(tc: dict, roe: dict, tools: dict, manifest: dict | None) -> tuple[str, list[str]]:
    """Return (class, trace). `manifest` = the seed manifest named by tc.seed_manifest_ref (dict), or None."""
    tb = tc["tool_binding"]
    acts = roe["activities"]

    # 1. MANUAL: never sent to B4. kind/adapter mismatch -> S3.
    if tb["kind"] == "MANUAL" or tb["adapter"] == "manual":
        if tb["kind"] == "MANUAL" and tb["adapter"] == "manual":
            return "S0", ["MANUAL: not executed"]
        return "S3", ["MANUAL kind/adapter mismatch"]

    # 2. adapter format and registration
    parsed = split_adapter(tb["adapter"])
    if parsed is None:
        return "S3", [f"{tb['adapter']!r}: not tool:mode"]
    tool, _ = parsed
    entry = registry_entry(tools, tb["adapter"])
    if entry is None:
        return "S3", [f"{tb['adapter']}: not registered in tools.yaml"]
    if not entry.get("b4_executable"):
        return "S3", [f"{tb['adapter']}: white-box only (b4_executable false)"]

    # 3. deny-lists and ROE authorisation (exact tool:mode match)
    if tb["adapter"] in TOOLKIT_DENYLIST:
        return "S3", [f"{tb['adapter']}: toolkit deny-list"]
    if tb["adapter"] in set(acts["denied_modes"]):
        return "S3", [f"{tb['adapter']}: ROE denied_modes"]
    if tool not in set(acts["allowed_tools"]):
        return "S3", [f"{tool}: not in ROE allowed_tools"]

    # 4. targets
    roe_targets = {t["id"]: t for t in roe["targets"]}
    if not tc["target_ids"] or any(t not in roe_targets for t in tc["target_ids"]):
        return "S3", ["target not in ROE"]
    for t in tc["target_ids"]:
        h = target_host(roe_targets[t])
        if h is None:
            return "S3", [f"{t}: unparseable target host"]
        if host_excluded(h, roe["exclusions"]["hosts"]):
            return "S3", [f"{t}: excluded host"]

    # 5. request allow-list
    reqs = tc["request_allowlist"]
    if not reqs:
        return "S3", ["empty request_allowlist"]
    for r in reqs:
        if r["target_id"] not in tc["target_ids"]:
            return "S3", [f"{r['target_id']}: request target not in testcase target_ids"]
        if not is_normalized(r["path"]):
            return "S3", [f"{r['path']!r}: path template not normalised"]
        hits = [p for p in roe["exclusions"]["paths"] if path_may_match(r["path"], p)]
        if hits:
            return "S3", [f"{r['method']} {r['path']}: may match ROE exclusion {hits}"]
    # every mutation is seed-bound or a create in the run namespace; seeds only on their own resources
    scope = mutation_scope_problems(tc, manifest)
    if scope:
        return "S3", [f"{MUTATION_SCOPE}: {p}" for p in scope]

    # 6. rate above the ROE is a rejection, not an upgrade
    if tc["rate_limit"]["requests_per_second"] > roe["rate_limits"]["per_host_rps"]:
        return "S3", ["requests_per_second > ROE per_host_rps"]

    # 7. level
    trace = []
    level = entry.get("base_class") or "S2"
    trace.append(f"{tb['adapter']}: base_class {entry.get('base_class')} -> {level}")
    if any(r["method"] in STATE_CHANGING for r in reqs):
        level = hi(level, "S1")
        trace.append("state-changing method -> >=S1")
    if tc["rate_limit"]["max_requests"] > roe["rate_limits"]["s1_request_cap"]:
        level = hi(level, "S2")
        trace.append("max_requests > s1_request_cap -> >=S2")

    # 8. the LLM proposal is only a floor
    proposed = tc.get("safety_class_proposed") or "S0"
    result = hi(level, proposed)
    if result != level:
        trace.append(f"LLM proposal {proposed} used as floor")
    return result, trace


def admissible(level: str, roe: dict) -> bool:
    """Can the computed class enter G4? (S2 also needs a G5 per job and a restore drill.)"""
    return level != "S3" and level in set(roe["activities"]["allowed_safety_classes"])
