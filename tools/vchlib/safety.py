"""Safety-class computation: the docs/04 §5 pseudo-code (v0.2, D13 tool IDs), verbatim in
logic, plus a trace so the validator can explain its result.

Source: requests/c2-to-b.md (pkg c2). Differences from v0.1: unregistered or malformed
adapter -> S3; registered mode with base_class null -> >= S2; white-box-only mode
(b4_executable false) -> S3; excluded host, non-normalised path template, rps above the
ROE, empty allow-list, request target outside tc.target_ids, MANUAL kind/adapter
mismatch -> S3. `admissible()` is a separate check against allowed_safety_classes.
"""
from __future__ import annotations

import fnmatch
import re
from urllib.parse import urlsplit

ORDER = ("S0", "S1", "S2", "S3")
STATE_CHANGING = frozenset({"POST", "PUT", "PATCH", "DELETE"})

# Modes the toolkit never runs. ROE denied_modes can only add to this set.
TOOLKIT_DENYLIST = frozenset({"nuclei:code_protocol", "restler:fuzz"})

ADAPTER_RE = re.compile(r"^[a-z][a-z0-9_]*:[a-z][a-z0-9_]*$")   # D13: tool:mode
SEED_SEG_RE = re.compile(r"^\{seed:([a-z0-9_]+)\}$")            # whole segment is {seed:key}


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


def path_may_match(template: str, pattern: str) -> bool:
    """Conservative: True if the template *may* expand to a path matching `pattern`."""
    t, p = segments(template), segments(pattern)
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


def is_seed_path(template: str, manifest_keys: set[str] | None) -> bool:
    """Every variable segment of a DELETE template must be {seed:key} with key in the manifest."""
    if manifest_keys is None:
        return False
    var_segs = [s for s in segments(template) if is_placeholder(s)]
    if not var_segs:
        return False
    for s in var_segs:
        m = SEED_SEG_RE.match(s)
        if m is None or m.group(1) not in manifest_keys:
            return False
    return True


def host_of(base_url: str | None) -> str:
    return (urlsplit(base_url or "").hostname or "").lower()


def registry_entry(tools: dict, adapter: str) -> dict | None:
    """tools.yaml lookup: {tool, mode, base_class, b4_executable, ...} or None."""
    parsed = split_adapter(adapter)
    if parsed is None:
        return None
    tool, mode = parsed
    spec = (tools or {}).get("tools", {}).get(tool, {}).get("modes", {}).get(mode)
    return None if spec is None else {"tool": tool, "mode": mode, **spec}


def compute_safety_class(tc: dict, roe: dict, tools: dict, manifest_keys: set[str] | None) -> tuple[str, list[str]]:
    """Return (class, trace). `manifest_keys` = seed keys of tc.seed_manifest_ref, or None."""
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
    excluded = {h.lower() for h in roe["exclusions"]["hosts"]}
    for t in tc["target_ids"]:
        if host_of(roe_targets[t].get("base_url")) in excluded:
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
        if r["method"] == "DELETE" and not is_seed_path(r["path"], manifest_keys):
            return "S3", [f"DELETE {r['path']}: not a seed-manifest object"]

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
