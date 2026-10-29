# SPDX-License-Identifier: Apache-2.0
"""Canonical JSON (RFC 8785 JCS) for the JSON subset used by this repo, and content hashes.

[H] This is a from-scratch implementation of the parts of RFC 8785 that the design
documents need: objects with string keys (sorted by UTF-16 code units), arrays,
strings (minimal JSON escaping, UTF-8 output), booleans, null, integers and finite
IEEE-754 doubles serialised like ECMAScript Number.prototype.toString. The validator
(checks.g_jcs) compares it with three RFC 8785 vectors (number serialisation, UTF-16 key
order, -0/1e21/1e-7 edge cases) and with the reference package rfc8785==0.1.4 on every
example document; that is agreement on this repo's data, not a proof of full conformance.
Non-JSON values (datetime, bytes, sets, NaN, Infinity) are rejected.
"""
from __future__ import annotations

import hashlib
import math
from typing import Any, Iterable

SIGNATURE_FIELDS = ("signatures",)
# Fields that record the *outcome* of a gate on an item; they are excluded from the
# "approval view" so that writing the decision back does not change the approved hash.
APPROVAL_EXCLUDED = ("signatures", "review", "signoff")


class CanonicalizationError(ValueError):
    pass


def _escape_string(s: str) -> str:
    out = ['"']
    for ch in s:
        o = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif o < 0x20:
            out.append({0x08: "\\b", 0x09: "\\t", 0x0A: "\\n", 0x0C: "\\f", 0x0D: "\\r"}.get(o, f"\\u{o:04x}"))
        elif 0xD800 <= o <= 0xDFFF:
            raise CanonicalizationError("lone surrogate in string")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _number(v: float) -> str:
    """ECMAScript Number.prototype.toString for finite doubles (RFC 8785 §3.2.2.3)."""
    if math.isnan(v) or math.isinf(v):
        raise CanonicalizationError("NaN/Infinity are not JSON")
    if v == 0:
        return "0"
    if v < 0:
        return "-" + _number(-v)
    # repr() gives the shortest round-tripping digits, like ECMAScript.
    r = repr(v)
    if "e" in r or "E" in r:
        mant, exp = r.lower().split("e")
        exp_i = int(exp)
    else:
        mant, exp_i = r, 0
    if "." in mant:
        int_part, frac = mant.split(".")
    else:
        int_part, frac = mant, ""
    digits = (int_part + frac).lstrip("0")
    # decimal exponent n such that value = 0.d1d2... * 10^n
    lead_zeros = len(int_part + frac) - len((int_part + frac).lstrip("0"))
    n = len(int_part) + exp_i - lead_zeros
    digits = digits.rstrip("0") or "0"
    k = len(digits)
    if k <= n <= 21:
        return digits + "0" * (n - k)
    if 0 < n <= 21:
        return digits[:n] + "." + digits[n:]
    if -6 < n <= 0:
        return "0." + "0" * (-n) + digits
    e = n - 1
    sign = "+" if e >= 0 else "-"
    m = digits[0] + ("." + digits[1:] if k > 1 else "")
    return f"{m}e{sign}{abs(e)}"


def _utf16_key(s: str) -> list[int]:
    return list(s.encode("utf-16-be"))


def _canon(v: Any, out: list[str]) -> None:
    if v is None:
        out.append("null")
    elif v is True:
        out.append("true")
    elif v is False:
        out.append("false")
    elif isinstance(v, int):
        out.append(str(v))
    elif isinstance(v, float):
        # Below 2^53 every integer-valued double is exact, so its integer digits are its shortest representation.
        # From 2^53 up the double no longer holds every integer: ECMAScript prints the shortest digits that round-trip
        # (1000000000000000100.0 -> "1000000000000000100"), while str(int(v)) prints the exact binary value
        # ("1000000000000000128"), which the RFC 8785 reference and JavaScript do not (third external review, r13).
        if v.is_integer() and abs(v) < 2 ** 53:
            out.append(str(int(v)))
        else:
            out.append(_number(v))
    elif isinstance(v, str):
        out.append(_escape_string(v))
    elif isinstance(v, (list, tuple)):
        out.append("[")
        for i, item in enumerate(v):
            if i:
                out.append(",")
            _canon(item, out)
        out.append("]")
    elif isinstance(v, dict):
        for k in v:
            if not isinstance(k, str):
                raise CanonicalizationError(f"non-string object key: {k!r}")
        out.append("{")
        for i, k in enumerate(sorted(v, key=_utf16_key)):
            if i:
                out.append(",")
            out.append(_escape_string(k))
            out.append(":")
            _canon(v[k], out)
        out.append("}")
    else:
        raise CanonicalizationError(f"value of type {type(v).__name__} is not JSON")


def jcs(value: Any) -> bytes:
    out: list[str] = []
    _canon(value, out)
    return "".join(out).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_ref(data: bytes) -> str:
    return "sha256:" + sha256_hex(data)


def strip(obj: dict, fields: Iterable[str]) -> dict:
    return {k: v for k, v in obj.items() if k not in set(fields)}


def signing_payload(doc: dict) -> bytes:
    """Bytes covered by detached signatures: JCS of the parsed document without `signatures`."""
    return jcs(strip(doc, SIGNATURE_FIELDS))


def content_hash(obj: Any) -> str:
    """sha256 of the canonical form; for signed documents the signatures are excluded."""
    if isinstance(obj, dict):
        obj = strip(obj, SIGNATURE_FIELDS)
    return sha256_ref(jcs(obj))


def approval_hash(obj: dict) -> str:
    """Hash of an item as shown at a gate (review/signoff/signatures excluded)."""
    return sha256_ref(jcs(strip(obj, APPROVAL_EXCLUDED)))


def set_digest(items: Iterable[dict]) -> str:
    """Digest of a multi-item gate artifact: sha256(JCS(sorted [{id, sha256}]))."""
    norm = sorted(({"id": i["id"], "sha256": i["sha256"]} for i in items), key=lambda x: x["id"])
    return sha256_ref(jcs(norm))


def text_hash(s: str) -> str:
    return sha256_ref(s.encode("utf-8"))
