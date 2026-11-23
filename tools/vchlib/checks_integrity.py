# SPDX-License-Identifier: Apache-2.0
"""Check groups over the bundle's own integrity: schemas and examples, RFC 8785 canonical JSON, derived hashes and
weights, the key registry, person references.

Split out of checks.py (architecture refactor PR-D2, docs/adr/0003-split-checks.md). The text is moved verbatim; no
rule, error code or message changed. checks.GROUPS still lists the five groups in the same places.
"""
from __future__ import annotations

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError
from referencing import Registry, Resource

from . import crypto, derive, expectations
from .bundle import read_jsonl_lines
from .canonical import CanonicalizationError, jcs, sha256_hex, signing_payload
from .context import Ctx
from .report import FORMATS, Report, StrictValidator, format_checker, schema_formats, ts

# RFC 8785 §3.2.2.3 / Appendix B number vectors and §3.2.3 key-order vector
JCS_VECTORS = [
    ([333333333.33333329, 1e30, 4.50, 2e-3, 0.000000000000000000000000001], b"[333333333.3333333,1e+30,4.5,0.002,1e-27]"),
    ({"€": "Euro Sign", "\r": "Carriage Return", "דּ": "Hebrew Letter Dalet With Dagesh", "1": "One",
      "\U0001f600": "Emoji: Grinning Face", "\u0080": "Control", "ö": "Latin Small Letter O With Diaeresis"},
     '{"\\r":"Carriage Return","1":"One","\u0080":"Control","ö":"Latin Small Letter O With Diaeresis",'
     '"€":"Euro Sign","\U0001f600":"Emoji: Grinning Face","דּ":"Hebrew Letter Dalet With Dagesh"}'.encode("utf-8")),
    ([-0.0, 1e21, 1e-7, 9007199254740991, 0.1, 100], b"[0,1e+21,1e-7,9007199254740991,0.1,100]"),
    # third external review (r13): integer-valued doubles at and above 2^53 print their shortest round-trip digits padded
    # with zeros (ECMAScript Number::toString, RFC 8785 §3.2.2.3), not the exact binary value (1000000000000000128)
    ([1000000000000000100.0, -1000000000000000100.0, 9007199254740993.0, 1.2345678901234568e+20, 1234567890123456789.0, 1e20, 123456789012345680000.0],
     b"[1000000000000000100,-1000000000000000100,9007199254740992,123456789012345680000,1234567890123456800,100000000000000000000,123456789012345680000]"),
]


# ============================================================== 1 schemas
def g_schemas(R: Report, c: Ctx):
    b = getattr(c, "original", c.b)            # the schema group sees every document as loaded (D5)
    resources = []
    for name, s in b.schemas.items():
        try:
            Draft202012Validator.check_schema(s)
        except SchemaError as exc:
            R.error("E-SCHEMA-META", f"{name}.schema.json", exc.message)
        R.check(s.get("$id") == f"{name}.schema.json", "E-SCHEMA-ID", f"{name}.schema.json", f"$id {s.get('$id')!r} must equal the file name")
        R.check(s.get("$schema") == "https://json-schema.org/draft/2020-12/schema", "E-SCHEMA-META", f"{name}.schema.json", "$schema must be 2020-12")
        resources.append((s.get("$id") or f"{name}.schema.json", Resource.from_contents(s)))
    registry = Registry().with_resources(resources)
    for name, s in b.schemas.items():
        for where, fmt in schema_formats(s):
            R.check(fmt in FORMATS, "E-SCHEMA-FORMAT", f"{name}.schema.json", f"{where}: format {fmt!r} has no checker (known: {sorted(FORMATS)})")
    fc = format_checker()
    seen = set()
    for d in b.docs:
        if d.load_error:
            if d.load_error.startswith("strict YAML"):
                code, msg = "E-YAML-STRICT", d.load_error
            elif d.load_error.startswith("strict JSON"):
                # same semantics as strict YAML: the document and every signature / hash-chain
                # link over it are rejected (signature_invalid), never "last duplicate wins"
                code, msg = "E-JSON-STRICT", d.load_error + " (document rejected: its signatures / hash chain are invalid)"
            else:
                code, msg = ("E-KIND" if d.kind == "unknown" else "E-LOAD"), d.load_error
            R.error(code, d.path, msg)
            continue
        if d.kind not in b.schemas:
            R.error("E-KIND", d.path, f"no schema named {d.kind!r}")
            continue
        seen.add(d.kind)
        v = StrictValidator(b.schemas[d.kind], registry=registry, format_checker=fc)
        items = d.data if isinstance(d.data, list) else [d.data]
        for i, inst in enumerate(items):
            R._checks += 1
            for e in sorted(v.iter_errors(inst), key=lambda e: list(e.absolute_path)):
                loc = derive.fmt_path(([i] if isinstance(d.data, list) else []) + list(e.absolute_path))
                R.error("E-SCHEMA", d.path, f"{loc}: {e.message[:300]}")
    for name in b.schemas:
        if name != "common":
            # BL-60: a variant bundle is an overlay on the main bundle; schema coverage is the main bundle's job
            if getattr(b, "variant", None) is None:
                R.check(name in seen, "E-SCHEMA-NO-EXAMPLE", f"{name}.schema.json", "no valid example instance")


# ============================================================== 2 JCS
def g_jcs(R: Report, c: Ctx):
    docs = getattr(c, "original", c.b).docs
    # second external review of r12: the reference library is only needed for this parity check (canonical.jcs is the
    # repo's own RFC 8785 implementation), so a validator without it warns and still checks its own JCS against the RFC
    # vectors; it was imported at module level and the whole validator crashed. CI installs requirements.lock, so the
    # parity check always runs there (tests/test_v07_r12_external2.py).
    try:
        import rfc8785
    except ImportError:
        rfc8785 = None  # type: ignore[assignment]  # the module is optional; None means the parity check is skipped
        R.warn("W-JCS-REFERENCE-MISSING", "requirements.txt", "rfc8785 is not installed: canonical.jcs is checked against the "
               "RFC 8785 vectors only, not against the reference library (pip install -r requirements.lock)")
    for value, expected in JCS_VECTORS:
        R.check(jcs(value) == expected, "E-JCS", "canonical.py", f"RFC 8785 vector mismatch: {jcs(value)!r} != {expected!r}")
        if rfc8785 is not None:
            R.check(rfc8785.dumps(value) == expected, "E-JCS", "rfc8785", "reference library disagrees with the RFC 8785 vector")  # type: ignore[arg-type]  # the vectors are JSON values
    if rfc8785 is None:
        return
    for d in docs:
        if d.data is None:
            continue
        for i, x in enumerate(d.data if isinstance(d.data, list) else [d.data]):
            try:
                mine = jcs(x)
            except CanonicalizationError as exc:
                R.error("E-JCS", d.path, f"[{i}] not canonicalisable: {exc}")
                continue
            try:
                ref = rfc8785.dumps(x)
            except Exception as exc:  # noqa: BLE001 - reference library error types vary
                R.error("E-JCS", d.path, f"[{i}] rfc8785 rejects the document: {exc}")
                continue
            R.check(mine == ref, "E-JCS", d.path, f"[{i}] canonical.jcs differs from rfc8785 0.1.4")


# ============================================================== 3 derived values + audit chain
def g_derived(R: Report, c: Ctx):
    problems: list = []
    exps = expectations.expectations(c.b, problems=[])
    R._checks += len(exps)
    for e, actual in expectations.compare(c.b, problems=problems):
        R.error("E-DERIVED", e.file, f"{derive.fmt_path(e.path)} = {str(actual)[:90]}, expected {str(e.expected)[:90]} ({e.why})")
    # v0.5 (review r7, group 5): a document that breaks a derivation is reported once; the others are still compared
    for path, exc in problems:
        R.error("E-INTERNAL", path, f"{type(exc).__name__}: {exc} (deriving this document's values; it was skipped)")
    for d in c.ix.audit_docs():
        # (the anchored line count / truncation is checked against run.audit_anchors in g_audit)
        lines = read_jsonl_lines(d.text or "")
        for i, ev in enumerate(d.data):
            want = ("sha256:" + sha256_hex(str(d.data[0].get("run_id", "")).encode("utf-8"))) if i == 0 \
                else "sha256:" + sha256_hex(lines[i - 1].encode("utf-8"))
            R.check(ev.get("prev_hash") == want, "E-AUDIT-CHAIN", d.path,
                    f"seq {ev.get('seq')}: prev_hash is not {'sha256(run_id)' if i == 0 else 'sha256 of the previous raw line'}")


# ============================================================== 4 key registry
def g_key_registry(R: Report, c: Ctx):
    kr, tk = c.registry, c.toolkit
    w = "key-registry.yaml"
    if not kr:
        R.error("E-KR-MISSING", w, "no key registry")
        return
    root_pk = kr.get("org_root_public_key", "")
    try:
        root_fp = crypto.fingerprint(crypto.unb64(root_pk))
    except Exception:  # noqa: BLE001
        root_fp = None
    pinned = (tk.get("org_root_key") or {}).get("fingerprint")
    R.check(root_fp is not None and root_fp == pinned, "E-KR-ROOT-PIN", w, f"org_root_public_key fingerprint {root_fp} != toolkit pin {pinned}")
    sigs = kr.get("signatures") or []
    R.check(len(sigs) == 1 and sigs[0].get("signer") == "org_root" and sigs[0].get("key_fingerprint") == pinned,
            "E-KR-ROOT-SIG", w, "the registry must carry exactly one org_root signature by the pinned key")
    for s in sigs:
        R.check(crypto.verify_bytes(root_pk, signing_payload(kr), s.get("value", "")), "E-KR-ROOT-SIG", w, "root signature does not verify")
    minv = (tk.get("key_registry") or {}).get("min_version", 0)
    R.check(isinstance(kr.get("version"), int) and kr.get("version") >= minv, "E-KR-ROLLBACK", w,
            f"registry version {kr.get('version')} < toolkit min_version {minv} (rollback)")
    loc = (tk.get("key_registry") or {}).get("location")
    R.check(kr.get("registry_id") == loc, "E-KR-LOCATION", w, f"registry_id {kr.get('registry_id')} != toolkit location {loc}")
    for name, doc in (("engagement.yaml", c.engagement), ("roe.yaml", c.roe)):
        if doc:
            R.check(doc.get("key_registry_ref") == loc, "E-KR-LOCATION", name, f"key_registry_ref {doc.get('key_registry_ref')} != {loc}")
    R.check(loc is not None and (c.b.root / loc).exists(), "E-KR-LOCATION", "toolkit.yaml", f"key registry {loc} does not exist")
    fps = [e.get("fingerprint") for e in c.entries]
    R.check(len(fps) == len(set(fps)), "E-KR-DUP", w, "duplicate fingerprints")
    for e in c.entries:
        where = f"{w} {e.get('person_id')}"
        try:
            real = crypto.fingerprint(crypto.unb64(e.get("public_key", "")))
        except Exception:  # noqa: BLE001
            real = None
        R.check(real == e.get("fingerprint"), "E-KR-FP", where, f"fingerprint {e.get('fingerprint')} != fingerprint(public_key) {real}")
        R.check(e.get("alg") == "ed25519", "E-KR-ALG", where, "alg must be ed25519")
        R.check((e.get("revoked_at") is None) == (e.get("revocation_reason") is None), "E-KR-REVOCATION", where,
                "revoked_at and revocation_reason must both be set or both be null")
        nb, na = ts(R, e.get("not_before"), where), ts(R, e.get("not_after"), where)
        R.check(nb is None or na is None or nb < na, "E-KR-VALIDITY", where, "not_before must precede not_after")
        rv = ts(R, e.get("revoked_at"), where)
        issued = ts(R, kr.get("issued_at"), w)
        R.check(rv is None or issued is None or rv <= issued, "E-KR-REVOCATION", where, "revoked_at is after the registry issued_at")
        R.check(e.get("person_id") not in c.automation, "E-KR-AUTOMATION", where, "automation accounts cannot hold person keys")
        if e.get("person_id") in c.services:
            R.check(e.get("roles") == ["z3_executor"] and e.get("person_id") == crypto.ANCHOR_SIGNER, "E-KR-SERVICE", where,
                    f"the z3_executor role is held only by the service identity {crypto.ANCHOR_SIGNER}, with no other role "
                    f"(got {e.get('person_id')} with roles {e.get('roles')})")


# ============================================================== 6 person references
def person_refs(c: Ctx):
    """(where, person_id, key_fingerprint or None, role or None)"""
    e, r = c.engagement, c.roe
    out = [("engagement.yaml run_owner", e.get("run_owner"), None, None)]
    if e.get("budget_approver"):
        out.append(("engagement.yaml budget_approver", e.get("budget_approver"), None, None))
    att = (e.get("code_ownership") or {}).get("attested_by") or {}
    out.append(("engagement.yaml code_ownership", att.get("person_id"), att.get("key_fingerprint"), att.get("role")))
    for s in e.get("signatories") or []:
        out.append(("engagement.yaml signatories", s.get("person_id"), s.get("key_fingerprint"), s.get("role")))
    for s in (r.get("signatories") or []) + (r.get("gate_approvers") or []):
        out.append(("roe.yaml signatories/gate_approvers", s.get("person_id"), s.get("key_fingerprint"), s.get("role")))
    if (r.get("legal_review") or {}).get("attested_by"):
        out.append(("roe.yaml legal_review", r["legal_review"]["attested_by"], None, None))
    for u in r.get("upstream_llm_providers") or []:
        out.append(("roe.yaml upstream_llm_providers", u.get("terms_confirmed_by"), None, None))
    for d in c.docs("gate-record"):
        if d.data.get("initiator") is not None:                 # null only on a Lane A run (E-GATE-INITIATOR)
            out.append((f"{d.path} initiator", d.data.get("initiator"), None, None))
        for a in d.data.get("approvers", []):
            out.append((f"{d.path} approvers", a.get("person_id"), a.get("key_fingerprint"), a.get("role")))
    for d in c.docs("run"):
        out.append((f"{d.path} run_owner", d.data.get("run_owner"), None, None))
        for p in d.data.get("initiators", []):
            out.append((f"{d.path} initiators", p, None, None))
    for d in c.docs("threat"):
        for l in d.data.get("crosswalk", []):
            if l.get("reviewed_by"):
                out.append((f"{d.path} crosswalk.reviewed_by", l["reviewed_by"], None, None))
    for l in c.crosswalk.get("links", []):
        if l.get("reviewed_by"):
            out.append(("crosswalk.yaml reviewed_by", l["reviewed_by"], None, None))
    ann = (c.calibration.get("config") or {}).get("annotation") or {}
    if ann.get("adjudicator_id"):   # annotators are external labellers, not registry persons
        out.append(("calibration.yaml adjudicator_id", ann["adjudicator_id"], None, None))
    for h in (c.calibration.get("result") or {}).get("holdout_access_log", []):
        out.append(("calibration.yaml holdout_access_log", h.get("person_id"), None, None))
    return out


def g_persons(R: Report, c: Ctx):
    for where, pid, fp, role in person_refs(c):
        if not R.check(pid not in c.services, "E-PERSON-AUTOMATION", where, f"{pid} is a service identity (z3_executor), not a person"):
            continue
        if not R.check(pid in c.persons, "E-PERSON-UNKNOWN", where, f"{pid!r} is not in the key registry"):
            continue
        R.check(pid not in c.automation, "E-PERSON-AUTOMATION", where, f"{pid} is an automation account")
        if fp is not None:
            e = c.by_fp.get(fp)
            R.check(e is not None and e.get("person_id") == pid, "E-PERSON-KEY", where, f"{pid}: key {fp} is not a registry key of this person")
        if role is not None:
            R.check(role in c.roles_of(pid), "E-PERSON-ROLE", where, f"{pid}: role {role} not granted in the key registry")
