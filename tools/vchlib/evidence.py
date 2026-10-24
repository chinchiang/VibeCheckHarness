# SPDX-License-Identifier: Apache-2.0
"""Evidence matching for findings (B1; docs/05 §4.2, H-A5 / L-16). Pure functions, no I/O.

  match_snippet(slice_text, ev) -> (match, line_start, line_end)   code_snippet evidence
  match_fact(inventory, ev)     -> match                            inventory_fact evidence
  match_config(config, ev)      -> match                            config_fact evidence

Code snippets are compared with the REDACTED slice text (secrets already replaced by the
redaction-map placeholders, e.g. <REDACTED:STRIPE_KEY_1>), after whitespace normalisation:
line endings unified, every line stripped at both ends, runs of spaces / tabs collapsed to one
space, blank lines around the snippet ignored. The snippet is searched in the window
[line_start - 3, line_end + 3]: found at the claimed lines -> MATCHED; found at shifted lines ->
MATCHED_SHIFTED and the harness rewrites line_start / line_end; otherwise NOT_FOUND.

v0.4 (D4): a snippet must carry content of its own (snippet_content_problem): at least
MIN_SNIPPET_CHARS non-whitespace characters and one identifier-like token. A lone "}" or ");"
occurs in almost every window, so v0.3 accepted it as grounded evidence. Too-short snippets are
NOT_FOUND in match_snippet and an E-FINDING-EVIDENCE shape problem in the validator.
"""
from __future__ import annotations

import re

SHIFT_WINDOW = 3
ABSENT = "<absent>"
MIN_SNIPPET_CHARS = 12
_WS = re.compile(r"[ \t]+")
_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]{2,}")
_MISSING = object()


def normalize_lines(text: str) -> list[str]:
    """Whitespace-normalised lines of `text` (\\r\\n and \\r become \\n)."""
    text = (text or "").replace("\r\n", "\n").replace("\r", "\n")
    return [_WS.sub(" ", ln).strip() for ln in text.split("\n")]


def _snippet_lines(snippet: str) -> list[str]:
    lines = normalize_lines(snippet)
    while lines and lines[0] == "":
        lines.pop(0)
    while lines and lines[-1] == "":
        lines.pop()
    return lines


def snippet_content_problem(snippet) -> str | None:
    """None when the snippet has enough content to ground a claim (v0.4, D4), else the reason."""
    text = "".join(_snippet_lines(snippet if isinstance(snippet, str) else ""))
    chars = len(re.sub(r"\s", "", text))
    if chars < MIN_SNIPPET_CHARS:
        return f"snippet has {chars} non-whitespace characters (minimum {MIN_SNIPPET_CHARS})"
    if not _IDENT.search(text):
        return "snippet has no identifier of 3 or more characters"
    return None


def match_snippet(slice_text: str, ev: dict) -> tuple[str, int | None, int | None]:
    """Tolerant code match of a code_snippet evidence item against the redacted file text."""
    ls, le = ev.get("line_start"), ev.get("line_end")
    snip = _snippet_lines(ev.get("snippet") or "")
    if (not snip or not isinstance(ls, int) or not isinstance(le, int) or le < ls
            or snippet_content_problem(ev.get("snippet")) is not None):
        return "NOT_FOUND", ls, le
    lines = normalize_lines(slice_text)
    n = len(snip)

    def at(start: int) -> bool:          # 1-based start line
        return start >= 1 and start - 1 + n <= len(lines) and lines[start - 1:start - 1 + n] == snip

    if le - ls + 1 == n and at(ls):
        return "MATCHED", ls, le
    lo, hi = max(1, ls - SHIFT_WINDOW), le + SHIFT_WINDOW
    starts = [s for s in range(lo, hi - n + 2) if at(s)]
    if starts:
        s = min(starts, key=lambda x: (abs(x - ls), x))   # the closest shift wins
        return "MATCHED_SHIFTED", s, s + n - 1
    return "NOT_FOUND", ls, le


def resolve_pointer(doc, pointer: str):
    """RFC 6901 JSON Pointer; returns the sentinel MISSING (module-private) when it does not resolve."""
    if not isinstance(pointer, str) or (pointer and not pointer.startswith("/")):
        return _MISSING
    cur = doc
    for raw in pointer.split("/")[1:] if pointer else []:
        tok = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(cur, dict):
            if tok not in cur:
                return _MISSING
            cur = cur[tok]
        elif isinstance(cur, list):
            if not re.fullmatch(r"0|[1-9][0-9]*", tok) or int(tok) >= len(cur):
                return _MISSING
            cur = cur[int(tok)]
        else:
            return _MISSING
    return cur


def resolves(doc, pointer: str) -> bool:
    return resolve_pointer(doc, pointer) is not _MISSING


def same_value(a, b) -> bool:
    """JSON equality that does not confuse false with 0 or 1 with true."""
    if isinstance(a, bool) or isinstance(b, bool):
        return type(a) is type(b) and a == b
    return a == b


def match_fact(inventory: dict, ev: dict) -> str:
    """inventory_fact: MATCHED iff fact_ref resolves in the run's W0 inventory and equals `asserted`."""
    val = resolve_pointer(inventory, ev.get("fact_ref"))
    return "MATCHED" if val is not _MISSING and same_value(val, ev.get("asserted")) else "NOT_FOUND"


def match_config(config: dict, ev: dict) -> str:
    """config_fact: key_path into the parsed, redacted config; asserted "<absent>" means the key must be missing."""
    val = resolve_pointer(config, ev.get("key_path"))
    if ev.get("asserted") == ABSENT:
        return "MATCHED" if val is _MISSING else "NOT_FOUND"
    return "MATCHED" if val is not _MISSING and same_value(val, ev.get("asserted")) else "NOT_FOUND"


KIND_FIELDS = {
    # kind -> (fields that must be non-null, fields that must be null)
    "code_snippet": (("file", "line_start", "line_end", "snippet", "snippet_sha256"), ("fact_ref", "key_path", "asserted")),
    "inventory_fact": (("fact_ref",), ("file", "line_start", "line_end", "snippet", "snippet_sha256", "key_path")),
    "config_fact": (("file", "key_path"), ("line_start", "line_end", "snippet", "snippet_sha256", "fact_ref")),
}


def shape_problems(ev: dict) -> list[str]:
    """E-FINDING-EVIDENCE: kind-specific fields present / null."""
    kind = ev.get("kind")
    if kind not in KIND_FIELDS:
        return [f"unknown evidence kind {kind!r}"]
    need, forbid = KIND_FIELDS[kind]
    out = [f"{kind} needs {f}" for f in need if ev.get(f) is None]
    out += [f"{kind} must have {f} null" for f in forbid if ev.get(f) is not None]
    ls, le = ev.get("line_start"), ev.get("line_end")
    if isinstance(ls, int) and isinstance(le, int) and le < ls:
        out.append("line_end before line_start")
    if kind == "code_snippet" and isinstance(ev.get("snippet"), str):
        why = snippet_content_problem(ev["snippet"])
        if why:
            out.append(why)
    return out


def finding_status(evidence: list[dict]) -> str:
    """Finding status from its evidence: any MATCHED / MATCHED_SHIFTED -> VERIFIED_SNIPPET; all NOT_FOUND ->
    UNVERIFIED; otherwise (something NOT_CHECKED) PENDING."""
    ms = [e.get("match") for e in evidence if isinstance(e, dict)]
    if any(m in ("MATCHED", "MATCHED_SHIFTED") for m in ms):
        return "VERIFIED_SNIPPET"
    if ms and all(m == "NOT_FOUND" for m in ms):
        return "UNVERIFIED"
    return "PENDING"


__all__ = ["match_snippet", "match_fact", "match_config", "resolve_pointer", "resolves", "normalize_lines", "shape_problems",
           "finding_status", "snippet_content_problem", "SHIFT_WINDOW", "ABSENT", "MIN_SNIPPET_CHARS"]
