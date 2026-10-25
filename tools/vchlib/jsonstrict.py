# SPDX-License-Identifier: Apache-2.0
"""Strict JSON loading for signed / hash-chained documents (the JSON twin of yamlstrict).

Python's json module silently keeps the LAST value of a duplicated key, so two parsers can
disagree about what a signed gate record or audit event says. Every JSON / JSONL document of
the bundle is therefore loaded with this loader. A violation means the document (and every
signature or hash-chain link over it) is rejected, exactly like a strict-YAML violation.
Rejected (same number rules as yamlstrict._check_numbers):
  - duplicate object keys (at any depth)
  - NaN, Infinity, -Infinity (not JSON; not representable in RFC 8785 JCS)
  - number literals that overflow to a non-finite float (1e400, -1e400)
  - integer literals beyond +-2^53 (not exactly representable in I-JSON / RFC 8785)
  - v0.5 (review 2026-10-25 §4.3): nesting deeper than MAX_DEPTH (the parser's RecursionError used to escape as an
    internal error) and lone UTF-16 surrogates in keys or strings (not representable in UTF-8 or RFC 8785 JCS, so
    every hash and signature over the document failed later as E-INTERNAL for the whole group)
Float literals such as 3e0 or 3.0 stay floats (never silently integers); integer-typed fields
reject them in the schema check (checks.format_checker type checker) and in the audit seq check.
"""
from __future__ import annotations

import json
import math

MAX_SAFE_INT = 2 ** 53
MAX_DEPTH = 64          # the deepest example is far below; a signed document has no reason to nest deeper


class StrictJSONError(ValueError):
    pass


def _pairs(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise StrictJSONError(f"duplicate key {k!r}")
        out[k] = v
    return out


def _constant(name):
    raise StrictJSONError(f"non-finite number {name} is not JSON")


def _float(text: str) -> float:
    value = float(text)
    if not math.isfinite(value):
        raise StrictJSONError(f"number {text} overflows to a non-finite float")
    return value


def _int(text: str) -> int:
    try:
        value = int(text)
    except ValueError as exc:      # e.g. beyond sys.get_int_max_str_digits()
        raise StrictJSONError(f"integer literal of {len(text)} digits beyond +-2^53") from exc
    if abs(value) > MAX_SAFE_INT:
        raise StrictJSONError(f"integer {text} beyond +-2^53")
    return value


def _lone_surrogate(s: str) -> bool:
    return any(0xD800 <= ord(ch) <= 0xDFFF for ch in s)


def check_tree(value, error=StrictJSONError, max_depth: int = MAX_DEPTH):
    """Iteratively reject nesting deeper than max_depth and lone surrogates in strings and keys."""
    stack = [(value, 1, "$")]
    while stack:
        cur, depth, path = stack.pop()
        if isinstance(cur, str):
            if _lone_surrogate(cur):
                raise error(f"{path}: lone UTF-16 surrogate in a string")
            continue
        if not isinstance(cur, (dict, list)):
            continue
        if depth > max_depth:
            raise error(f"{path}: nesting deeper than {max_depth}")
        if isinstance(cur, dict):
            for k, v in cur.items():
                if isinstance(k, str) and _lone_surrogate(k):
                    raise error(f"{path}: lone UTF-16 surrogate in a key")
                stack.append((v, depth + 1, f"{path}.{k}"))
        else:
            stack.extend((v, depth + 1, f"{path}[{i}]") for i, v in enumerate(cur))


def loads(text: str):
    """Parse JSON; raises StrictJSONError (strict violation) or json.JSONDecodeError (syntax)."""
    try:
        data = json.loads(text, object_pairs_hook=_pairs, parse_constant=_constant,
                          parse_float=_float, parse_int=_int)
    except RecursionError as exc:
        raise StrictJSONError(f"nesting deeper than the parser can follow (limit {MAX_DEPTH})") from exc
    check_tree(data)
    return data
