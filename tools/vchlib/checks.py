"""Semantic checks over the example bundle (v0.2).

Every check reports through `Report`: errors fail the run, warnings are printed only.
Each group is isolated: an unexpected exception in one group becomes E-INTERNAL instead of
crashing the validator (graceful handling of broken or unknown input).

Trust model [H]: the key registry (docs/examples/key-registry.yaml) is the ONLY source of
public keys. Its root signature is checked against the fingerprint pinned in toolkit.yaml.
Fingerprints and roles written anywhere else are claims that must agree with the registry.
Signatures are real Ed25519 over RFC 8785 JCS; the example keys are TEST ONLY fixtures.
"""
from __future__ import annotations

import datetime as dt
import math
import re
import traceback
from dataclasses import dataclass, field

import rfc8785
from urllib.parse import urlsplit
from jsonschema import Draft202012Validator, FormatChecker, validators
from jsonschema.exceptions import SchemaError
from referencing import Registry, Resource

from . import adjudicate as adj
from . import crypto, derive, evidence, facets, llm_schema, safety, timeutil
from .bundle import Bundle, Doc, read_jsonl_lines
from .canonical import CanonicalizationError, content_hash, jcs, sha256_hex, signing_payload

GATE_ROLES = {
    "G0a": {"app_owner", "management"},
    "G0b": {"test_lead", "management", "infrastructure_owner"},
    "G1": {"app_owner"},
    "G2": {"security_reviewer"},
    "G3": {"security_reviewer", "app_owner"},
    "G4": {"security_reviewer"},
    "G5": {"security_reviewer"},
}
DETERMINISTIC_ROLES = {"aggregator", "scope_proxy", "executor"}
NON_ADJUDICATING_ROLES = {"reporter"}
SIGNED_EVENTS = {"initiator_claim", "run_resume"}
REQUIRED_AUTOMATION = {"run-controller", "scheduler", "ci-bot"}
LEGAL_GATE = "法務閘門"
M1_REQUIRED_SELFTESTS = {"ST-1", "ST-3", "ST-7"}
# placeholder model IDs: <...>, {...}, or a TBD / TODO / FIXME / 實作時確認 token (case-insensitive)
PLACEHOLDER_ID = re.compile(r"<[^<>]*>|\{[^{}]*\}|(?<![A-Za-z0-9])(?:TBD|TODO|FIXME)(?![A-Za-z0-9])|實作時確認", re.IGNORECASE)
TERMINAL_RUN_STATES = ("COMPLETED", "COMPLETED_WITH_GAPS", "ABORTED", "FAILED")   # D2; SUSPENDED and STOPPED are resumable
FINAL_STATUSES = ("CONFIRMED_EXECUTABLE", "CONFIRMED_CORROBORATED", "LIKELY", "UNCORROBORATED", "DISPUTED", "REJECTED")
# RFC 8785 §3.2.2.3 / Appendix B number vectors and §3.2.3 key-order vector
JCS_VECTORS = [
    ([333333333.33333329, 1e30, 4.50, 2e-3, 0.000000000000000000000000001], b"[333333333.3333333,1e+30,4.5,0.002,1e-27]"),
    ({"€": "Euro Sign", "\r": "Carriage Return", "דּ": "Hebrew Letter Dalet With Dagesh", "1": "One",
      "\U0001f600": "Emoji: Grinning Face", "\u0080": "Control", "ö": "Latin Small Letter O With Diaeresis"},
     '{"\\r":"Carriage Return","1":"One","\u0080":"Control","ö":"Latin Small Letter O With Diaeresis",'
     '"€":"Euro Sign","\U0001f600":"Emoji: Grinning Face","דּ":"Hebrew Letter Dalet With Dagesh"}'.encode("utf-8")),
    ([-0.0, 1e21, 1e-7, 9007199254740991, 0.1, 100], b"[0,1e+21,1e-7,9007199254740991,0.1,100]"),
]


# ============================================================== report
@dataclass
class Issue:
    level: str      # error | warning
    code: str
    where: str
    msg: str


@dataclass
class Report:
    issues: list[Issue] = field(default_factory=list)
    groups: list[tuple[str, int, int]] = field(default_factory=list)   # (name, checks, errors)
    notes: list[str] = field(default_factory=list)
    _checks: int = 0

    def error(self, code, where, msg):
        self.issues.append(Issue("error", code, where, msg))

    def warn(self, code, where, msg):
        self.issues.append(Issue("warning", code, where, msg))

    def check(self, cond, code, where, msg) -> bool:
        self._checks += 1
        if not cond:
            self.error(code, where, msg)
        return bool(cond)

    @property
    def errors(self):
        return [i for i in self.issues if i.level == "error"]

    @property
    def warnings(self):
        return [i for i in self.issues if i.level == "warning"]

    def codes(self) -> set[str]:
        return {i.code for i in self.errors}


# ============================================================== helpers
def ts(R: Report, value, where, what="timestamp"):
    """Parse an RFC 3339 timestamp; report E-DATETIME and return None when invalid."""
    if value is None:
        return None
    try:
        return timeutil.parse_dt(value)
    except timeutil.TimeError as exc:
        R.error("E-DATETIME", where, f"{what}: {exc}")
        return None


def is_date(value) -> bool:
    if not isinstance(value, str) or not re.match(r"^\d{4}-\d{2}-\d{2}$", value):
        return False
    try:
        dt.date.fromisoformat(value)
        return True
    except ValueError:
        return False


def is_uri(value) -> bool:
    """D3: an absolute URI with a scheme and a host (no whitespace)."""
    if not isinstance(value, str) or not value or any(ch.isspace() for ch in value):
        return False
    try:
        u = urlsplit(value)
        return bool(re.match(r"^[A-Za-z][A-Za-z0-9+.-]*$", u.scheme or "")) and bool(u.hostname)
    except ValueError:
        return False


FORMATS = {"date-time", "date", "uri"}     # every `format` a schema uses must have a checker (E-SCHEMA-FORMAT)
LOCAL_HTTP_HOSTS = ("localhost", "127.0.0.1", "::1")


def format_checker() -> FormatChecker:
    fc = FormatChecker(formats=())
    fc.checks("date-time")(lambda v: not isinstance(v, str) or timeutil.is_datetime(v))
    fc.checks("date")(lambda v: not isinstance(v, str) or is_date(v))
    fc.checks("uri")(lambda v: not isinstance(v, str) or is_uri(v))
    return fc


def schema_formats(node, path="") -> list[tuple[str, str]]:
    """[(json path, format)] of every `format` keyword in a schema."""
    out = []
    if isinstance(node, dict):
        for k, v in node.items():
            if k == "format" and isinstance(v, str):
                out.append((path, v))
            out += schema_formats(v, f"{path}/{k}")
    elif isinstance(node, list):
        for i, v in enumerate(node):
            out += schema_formats(v, f"{path}[{i}]")
    return out


def url_problem(url) -> str | None:
    """D3: ROE URLs must be https://; http:// only for localhost / 127.0.0.1 / [::1] (MVP-1 local targets)."""
    if not is_uri(url):
        return f"{url!r} is not an absolute URI"
    u = urlsplit(url)
    if u.scheme.lower() == "https":
        return None
    if u.scheme.lower() == "http" and (u.hostname or "").lower() in LOCAL_HTTP_HOSTS:
        return None
    return f"{url!r} must be https:// (http:// only for localhost, 127.0.0.1 or [::1])"


def _strict_integer(checker, instance) -> bool:
    """JSON Schema "integer" without the 2020-12 leniency: 3.0 / 3e0 (float) and bools are not integers."""
    return type(instance) is int


# Draft 2020-12 accepts 3.0 as an integer; a signed / hash-chained document must not depend on
# that (3e0 and 3 canonicalise identically but are different literals), so integer = Python int.
StrictValidator = validators.extend(
    Draft202012Validator,
    type_checker=Draft202012Validator.TYPE_CHECKER.redefine("integer", _strict_integer),
)


class Ctx:
    """Shared lookups for the checks."""

    def __init__(self, b: Bundle, real_run: bool = False):
        self.b = b
        self.real_run = real_run      # --real-run: placeholder models reachable from agents are errors
        self.ix = derive.Index(b)
        self.toolkit = b.data("toolkit-config") or {}
        self.registry = b.data("key-registry") or {}
        self.engagement = b.data("engagement") or {}
        self.roe = b.data("roe") or {}
        self.tools = b.data("tool-registry") or {}
        self.licenses = b.data("licenses") or {}
        self.models = b.data("model-registry") or {}
        self.agents = b.data("agent-registry") or {}
        self.manifest = b.data("seed-manifest") or {}
        self.invariants = b.data("invariants") or {}
        self.calibration = b.data("calibration") or {}
        self.crosswalk = b.data("crosswalk") or {}
        self.entries = [e for e in self.registry.get("entries", []) if isinstance(e, dict)]
        self.by_fp = {e.get("fingerprint"): e for e in self.entries}
        self.persons = {e.get("person_id") for e in self.entries}
        self.automation = set(self.toolkit.get("automation_accounts", [])) | REQUIRED_AUTOMATION
        self.runs = {d.data.get("run_id"): d.data for d in self.ix.docs("run")}
        # run_id -> audit Doc whose text the strict loader rejected (data None)
        self.broken_audit = {}
        for d in b.docs:
            if d.kind == "audit-event" and d.load_error:
                m = re.search(r'"run_id"\s*:\s*"([^"]+)"', d.text or "") or re.match(r"audit-event\.(.+?)\.example\.jsonl$", d.name)
                if m:
                    self.broken_audit.setdefault(m.group(1), d)
        self.broken_audit_runs = set(self.broken_audit)

    def roles_of(self, person) -> set[str]:
        return {r for e in self.entries if e.get("person_id") == person for r in e.get("roles", [])}

    def docs(self, kind):
        return self.ix.docs(kind)

    def record(self, rid):
        d = self.ix.first("gate-record", gate_record_id=rid)
        return d.data if d else None

    def model(self, key):
        m = self.models.get(key)
        return m if isinstance(m, dict) else None


def retention_max(tk: dict, data_class) -> int | None:
    """Org maximum (= default) content retention in days for a data class (toolkit.yaml retention)."""
    ret = tk.get("retention") or {}
    return ret.get("c_days_after_run_end") if data_class == "C" else ret.get("p_days") if data_class == "P" else None


def roe_windows(c: Ctx):
    return ((c.roe.get("validity") or {}).get("windows")) or []


# ============================================================== signatures
def verify_signature(R: Report, c: Ctx, where: str, payload: bytes, sig: dict, at: dt.datetime | None,
                     need_role: str | None = None) -> dict | None:
    """Check one signature against the key registry. Returns the registry entry if valid."""
    fp = sig.get("key_fingerprint")
    e = c.by_fp.get(fp)
    if e is None:
        R.error("E-SIG-UNKNOWN-KEY", where, f"{sig.get('signer')}: key {fp} is not in the key registry")
        return None
    ok = True
    if e.get("person_id") != sig.get("signer"):
        R.error("E-SIG-SIGNER", where, f"key {fp} belongs to {e.get('person_id')}, not {sig.get('signer')}")
        ok = False
    revoked = ts(R, e.get("revoked_at"), "key-registry.yaml", "revoked_at")
    if e.get("revocation_reason") == "compromised":
        R.error("E-SIG-COMPROMISED", where, f"{sig.get('signer')}: key {fp} was revoked as compromised; every signature by it is invalid")
        ok = False
    elif revoked is not None and at is not None and at >= revoked:
        R.error("E-SIG-REVOKED", where, f"{sig.get('signer')}: key {fp} revoked at {e.get('revoked_at')} ({e.get('revocation_reason')}); signature time {at.isoformat()}")
        ok = False
    nb = ts(R, e.get("not_before"), "key-registry.yaml", "not_before")
    na = ts(R, e.get("not_after"), "key-registry.yaml", "not_after")
    if at is None:
        R.error("E-SIG-EXPIRED", where, f"{sig.get('signer')}: no valid signature time")
        ok = False
    elif nb and na and not (nb <= at <= na):
        R.error("E-SIG-EXPIRED", where, f"{sig.get('signer')}: signature time {at.isoformat()} outside key validity {e.get('not_before')}..{e.get('not_after')}")
        ok = False
    if sig.get("alg") != "ed25519" or not crypto.verify_bytes(e.get("public_key", ""), payload, sig.get("value", "")):
        R.error("E-SIG-BAD", where, f"{sig.get('signer')}: Ed25519 signature does not verify")
        ok = False
    if need_role and need_role not in e.get("roles", []):
        R.error("E-SIG-ROLE", where, f"{sig.get('signer')}: registry key has roles {e.get('roles')}, needs {need_role}")
        ok = False
    return e if ok else None


def silent_verify(c: Ctx, payload: bytes, sig: dict, at) -> bool:
    """Same rules as verify_signature, without reporting (for G0 signer_results)."""
    scratch = Report()
    return verify_signature(scratch, c, "", payload, sig, at) is not None


def check_signed_doc(R: Report, c: Ctx, where: str, doc: dict, signers: list[dict]):
    """signers: [{person_id, role, key_fingerprint}] that must each have one valid signature."""
    sigs = doc.get("signatures") or []
    at = ts(R, doc.get("issued_at"), where, "issued_at")
    payload = signing_payload(doc)
    wanted = {(s.get("person_id"), s.get("key_fingerprint")): s for s in signers}
    for sig in sigs:
        key = (sig.get("signer"), sig.get("key_fingerprint"))
        if key not in wanted:
            R.error("E-SIG-EXTRA", where, f"signature by {sig.get('signer')} ({sig.get('key_fingerprint')}) is not expected")
            continue
        R._checks += 1
        verify_signature(R, c, where, payload, sig, at, wanted[key].get("role"))
    have = {(s.get("signer"), s.get("key_fingerprint")) for s in sigs}
    for key, s in wanted.items():
        R.check(key in have, "E-SIG-MISSING", where, f"{s.get('person_id')} ({s.get('role')}) has not signed")


# ============================================================== 1 schemas
def g_schemas(R: Report, c: Ctx):
    b = c.b
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
            R.check(name in seen, "E-SCHEMA-NO-EXAMPLE", f"{name}.schema.json", "no valid example instance")


# ============================================================== 2 JCS
def g_jcs(R: Report, c: Ctx):
    for value, expected in JCS_VECTORS:
        R.check(jcs(value) == expected, "E-JCS", "canonical.py", f"RFC 8785 vector mismatch: {jcs(value)!r} != {expected!r}")
        R.check(rfc8785.dumps(value) == expected, "E-JCS", "rfc8785", "reference library disagrees with the RFC 8785 vector")
    for d in c.b.docs:
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
    exps = derive.expectations(c.b)
    R._checks += len(exps)
    for e, actual in derive.compare(c.b):
        R.error("E-DERIVED", e.file, f"{derive.fmt_path(e.path)} = {str(actual)[:90]}, expected {str(e.expected)[:90]} ({e.why})")
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


# ============================================================== 5 signatures
def g_signatures(R: Report, c: Ctx):
    if c.engagement:
        check_signed_doc(R, c, "engagement.yaml", c.engagement, c.engagement.get("signatories") or [])
    if c.roe:
        lr = c.roe.get("legal_review") or {}
        signers = list(c.roe.get("signatories") or [])
        att = lr.get("attested_by")
        if att:
            e = next((x for x in c.entries if x.get("person_id") == att and not x.get("revoked_at")), None)
            fp = e.get("fingerprint") if e else None
            role = "legal_reviewer" if "legal_reviewer" in c.roles_of(att) else ("management" if "management" in c.roles_of(att) else "legal_reviewer")
            if not any(s.get("person_id") == att for s in signers):
                signers.append({"person_id": att, "role": role, "key_fingerprint": fp})
        check_signed_doc(R, c, "roe.yaml", c.roe, signers)
    for d in c.docs("gate-record"):
        rec = d.data
        at = ts(R, rec.get("timestamp"), d.path)
        if rec.get("gate") in ("G0a", "G0b"):
            R.check(rec.get("signatures") == [], "E-GATE-G0-SIG", d.path, "G0a/G0b are system verifications: signatures must be []")
            doc = c.engagement if rec.get("gate") == "G0a" else c.roe
            ver = rec.get("verification") or {}
            doc_at = ts(R, doc.get("issued_at"), d.path)
            real = [{"person_id": s.get("signer"), "key_fingerprint": s.get("key_fingerprint"),
                     "ok": silent_verify(c, signing_payload(doc), s, doc_at)} for s in doc.get("signatures") or []]
            got = [{k: r.get(k) for k in ("person_id", "key_fingerprint", "ok")} for r in ver.get("signer_results") or []]
            R.check(got == real, "E-GATE-G0-VERIFY", d.path, f"signer_results {got} do not match the real verification {real}")
            R.check(ver.get("key_registry_version") == c.registry.get("version"), "E-GATE-G0-VERIFY", d.path,
                    "verification.key_registry_version != registry version")
            if rec.get("outcome") == "VERIFIED":
                R.check(all(r["ok"] for r in real) and real, "E-GATE-G0-VERIFY", d.path, "VERIFIED although a signature failed")
            continue
        payload = signing_payload(rec)
        approvers = {(a.get("person_id"), a.get("key_fingerprint")): a for a in rec.get("approvers", [])}
        for s in rec.get("signatures") or []:
            key = (s.get("signer"), s.get("key_fingerprint"))
            if key not in approvers:
                R.error("E-SIG-EXTRA", d.path, f"signature by {s.get('signer')} is not an approver")
                continue
            R._checks += 1
            verify_signature(R, c, d.path, payload, s, at, approvers[key].get("role"))
        have = {(s.get("signer"), s.get("key_fingerprint")) for s in rec.get("signatures") or []}
        for key in approvers:
            R.check(key in have, "E-SIG-MISSING", d.path, f"approver {key[0]} has not signed")
    for d in c.ix.audit_docs():
        for ev in d.data:
            where = f"{d.path} seq {ev.get('seq')}"
            actor = ev.get("actor") or {}
            if ev.get("event_type") in SIGNED_EVENTS and actor.get("kind") == "human":
                sig = ev.get("signature")
                if not R.check(isinstance(sig, dict), "E-AUDIT-SIG", where, f"{ev.get('event_type')} by a human must be signed"):
                    continue
                R.check(sig.get("signer") == actor.get("id"), "E-SIG-SIGNER", where, "signature signer != actor.id")
                verify_signature(R, c, where, crypto.event_payload(ev), sig, ts(R, ev.get("ts"), where))
            else:
                R.check(ev.get("signature") is None, "E-AUDIT-SIG", where, "only human initiator_claim / run_resume events are signed")


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
        if not R.check(pid in c.persons, "E-PERSON-UNKNOWN", where, f"{pid!r} is not in the key registry"):
            continue
        R.check(pid not in c.automation, "E-PERSON-AUTOMATION", where, f"{pid} is an automation account")
        if fp is not None:
            e = c.by_fp.get(fp)
            R.check(e is not None and e.get("person_id") == pid, "E-PERSON-KEY", where, f"{pid}: key {fp} is not a registry key of this person")
        if role is not None:
            R.check(role in c.roles_of(pid), "E-PERSON-ROLE", where, f"{pid}: role {role} not granted in the key registry")


# ============================================================== 7 engagement
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
        for k, val in caps.items():
            R.check(val is not None, "E-ENG-BUDGET", w, f"budgets.{ph}.{k} must be set (no default for cost caps)")
            if ph != "run_total" and val is not None and total.get(k) is not None:
                R.check(val <= total[k], "E-ENG-BUDGET", w, f"budgets.{ph}.{k} exceeds run_total")
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
    provider_rules(R, c)
    R.check(e.get("telemetry_disabled") is True, "E-ENG-TELEMETRY", w, "telemetry_disabled must be true")


Z4_HOST_PREFIX = "z4-"      # self-hosted model servers live in Z4 (models.yaml api_base http://z4-...)


def self_hosted(m: dict) -> bool:
    try:
        host = urlsplit(m.get("api_base") or "").hostname or ""
    except ValueError:
        return False
    return host.startswith(Z4_HOST_PREFIX)


def provider_rules(R: Report, c: Ctx):
    """B13 (H-E14): every model an agent can reach that may receive C data (engagement data class C and the model
    takes C) is self-hosted in Z4, or its family has zdr confirmed and a signed DPA."""
    e, w = c.engagement, "engagement.yaml"
    if e.get("data_class") != "C":
        return
    prov = {p.get("family"): p for p in e.get("providers") or [] if isinstance(p, dict)}
    for k, users in sorted(reachable_models(c).items()):
        m = c.model(k)
        if not m or "C" not in (m.get("data_classes") or []) or self_hosted(m):
            continue
        p = prov.get(m.get("family")) or {}
        R.check(p.get("zdr") == "confirmed" and p.get("dpa_signed") is True, "E-ENG-PROVIDER", w,
                f"{k} ({m.get('family')}) can receive C data (agents {sorted(users)}) but providers.{m.get('family')} is not "
                f"zdr confirmed with a signed DPA (and the model is not self-hosted in Z4)")


# ============================================================== 8 ROE (+ L-1..L-6)
def g_roe(R: Report, c: Ctx):
    r, e, tk, w = c.roe, c.engagement, c.toolkit, "roe.yaml"
    if not r:
        R.error("E-ROE-MISSING", w, "no ROE")
        return
    eng = r.get("engagement") or {}
    R.check(eng.get("id") == e.get("engagement_id") and eng.get("version") == e.get("version"), "E-ROE-ENGAGEMENT", w,
            "engagement.id/version must match engagement.yaml")
    v = r.get("validity") or {}
    nb, na = ts(R, v.get("not_before"), w), ts(R, v.get("not_after"), w)
    ev = e.get("validity") or {}
    enb, ena = ts(R, ev.get("not_before"), "engagement.yaml"), ts(R, ev.get("not_after"), "engagement.yaml")
    R.check(nb and na and nb < na, "E-ROE-VALIDITY", w, "not_before must precede not_after")
    R.check(nb and na and enb and ena and enb <= nb and na <= ena, "E-ROE-VALIDITY", w, "ROE validity must lie inside the engagement validity")
    for i, win in enumerate(v.get("windows") or []):
        try:
            timeutil.zone(win.get("tz"))
            s, en = timeutil.hhmm(win.get("start")), timeutil.hhmm(win.get("end"))
            R.check(s != en, "E-ROE-WINDOW", w, f"windows[{i}]: start == end")
            R.check(set(win.get("days", [])) <= set(timeutil.DAYS) and win.get("days"), "E-ROE-WINDOW", w, f"windows[{i}]: bad days")
        except timeutil.TimeError as exc:
            R.error("E-ROE-WINDOW", w, f"windows[{i}]: {exc}")
    roles = {s.get("role") for s in r.get("signatories") or []}
    R.check(GATE_ROLES["G0b"] <= roles, "E-ROE-SIGNATORIES", w, f"signatories must include {sorted(GATE_ROLES['G0b'])}")
    # E1 / L-13: one person signs the ROE in at most one required role (lite + acknowledged consolidation excepted)
    holders: dict = {}
    for s in r.get("signatories") or []:
        if s.get("role") in GATE_ROLES["G0b"]:
            holders.setdefault(s.get("person_id"), set()).add(s.get("role"))
    for p, rs in holders.items():
        if len(rs) > 1:
            R.check(p == consolidation_person(c), "E-ROE-SOD", w,
                    f"{p} signs the ROE as {sorted(rs)}: required ROE roles need distinct persons (assurance_profile {profile(c)})")
    platform_rules(R, c)
    used_roles = {x for d in c.docs("testcase") for x in (d.data.get("data_needed") or {}).get("roles") or []}
    for tr_ in r.get("test_roles", []):
        if tr_.get("role") in used_roles:
            R.check(isinstance(tr_.get("whoami"), dict), "E-ROE-WHOAMI", w,
                    f"test role {tr_.get('role')} is used by testcases but has no whoami check (E3)")
    relay_ = r.get("relay") or {}
    if relay_.get("mode") == "adaptive":
        R.check(profile(c) == "full", "E-ROE-RELAY-MODE", w, f"relay mode adaptive is only allowed with assurance_profile full (got {profile(c)})")
    targets = {t.get("id"): t for t in r.get("targets", [])}
    R.check(len(targets) == len(r.get("targets", [])), "E-ROE-TARGETS", w, "duplicate target ids")
    for t in r.get("targets", []):
        if t.get("kind") == "http":
            R.check(t.get("base_url") and t.get("endpoint") is None, "E-ROE-TARGETS", w, f"{t.get('id')}: http target needs base_url only")
        elif t.get("kind") == "database":
            R.check(t.get("endpoint") and t.get("base_url") is None, "E-ROE-TARGETS", w, f"{t.get('id')}: database target needs endpoint only")
    # a target the ROE itself excludes is contradictory; for database targets the host comes from
    # the endpoint (base_url is null), so the exclusion list must be checked against it as well
    excl_hosts = (r.get("exclusions") or {}).get("hosts") or []
    for t in r.get("targets", []):
        if t.get("kind") == "database":
            h = safety.target_host(t)     # None: unparseable (bare host, '[::1', '::1:5432', trailing dot)
            R.check(h is not None, "E-ROE-DB-SCOPE", w,
                    f"{t.get('id')}: unparseable endpoint {t.get('endpoint')!r} (need host:port or [IPv6]:port)")
            R.check(h is None or not safety.host_excluded(h, excl_hosts), "E-ROE-DB-SCOPE", w,
                    f"{t.get('id')}: database host {h!r} is in exclusions.hosts (compared after trailing-dot/case/IDNA normalisation)")
        elif t.get("kind") == "http" and t.get("base_url"):
            prob = url_problem(t.get("base_url"))
            R.check(prob is None, "E-ROE-URL", w, f"{t.get('id')}: base_url {prob}")
            h = safety.host_of(t.get("base_url"))
            R.check(h is not None, "E-ROE-TARGETS", w, f"{t.get('id')}: unparseable base_url {t.get('base_url')!r} (no host)")
            R.check(h is None or not safety.host_excluded(h, excl_hosts), "E-ROE-TARGETS", w,
                    f"{t.get('id')}: base_url host {h!r} is in exclusions.hosts (compared after trailing-dot/case/IDNA normalisation)")
    for tr in r.get("test_roles", []):
        R.check((tr.get("login") or {}).get("target_id") in targets, "E-ROE-TARGETS", w, f"test role {tr.get('role')}: login target not in ROE")
    db = r.get("db_access")
    if db:
        t = targets.get(db.get("target_id")) or {}
        R.check(t.get("kind") == "database" and t.get("endpoint") == db.get("endpoint"), "E-ROE-DB", w,
                f"[binding rule] db_access.target_id {db.get('target_id')!r} must be a database target whose endpoint "
                f"string equals db_access.endpoint {db.get('endpoint')!r}")
        # scope: the db_access host must be the host of an in-scope ROE database target and not excluded
        dbh = safety.endpoint_host(db.get("endpoint"))
        in_scope = {h for x in r.get("targets", []) if x.get("kind") == "database" and (h := safety.target_host(x))}
        if R.check(dbh is not None, "E-ROE-DB-SCOPE", w,
                   f"[scope rule] db_access: unparseable endpoint {db.get('endpoint')!r} (need host:port or [IPv6]:port)"):
            R.check(dbh in in_scope, "E-ROE-DB-SCOPE", w,
                    f"[scope rule] db_access endpoint host {dbh!r} is not the (normalised) host of any ROE database target (out of scope)")
            R.check(not safety.host_excluded(dbh, excl_hosts), "E-ROE-DB-SCOPE", w,
                    f"[exclusion rule] db_access endpoint host {dbh!r} is in exclusions.hosts (compared after trailing-dot/case/IDNA normalisation)")
        R.check(db.get("oracle_readonly_attested") is True, "E-ROE-DB", w, "oracle_readonly_attested must be true")
        R.check(db.get("seed_manifest_ref") == c.manifest.get("manifest_ref"), "E-ROE-DB", w, "seed_manifest_ref != seed manifest manifest_ref")
        R.check(c.manifest.get("db_target_id") == db.get("target_id"), "E-ROE-DB", "seed-manifest.yaml", "db_target_id != roe db_access.target_id")
        R.check(c.manifest.get("engagement_id") == e.get("engagement_id"), "E-ROE-DB", "seed-manifest.yaml", "engagement_id mismatch")
        oracle = set(db.get("oracle_tables", []))
        for qid, q in (c.manifest.get("oracle_queries") or {}).items():
            R.check(q.get("table") in oracle, "E-ROE-DB", "seed-manifest.yaml", f"oracle query {qid}: table {q.get('table')} not in ROE oracle_tables")
    acts = r.get("activities") or {}
    R.check("S3" not in acts.get("allowed_safety_classes", []), "E-ROE-S3", w, "S3 can never be allowed")
    R.check(safety.TOOLKIT_DENYLIST <= set(acts.get("denied_modes", [])), "E-ROE-DENYLIST", w, "denied_modes must include the toolkit deny-list")
    tools = (c.tools.get("tools") or {})
    denied_in_registry = {f"{t}:{m}" for t, spec in tools.items() for m, ms in (spec.get("modes") or {}).items() if ms.get("toolkit_denied")}
    R.check(denied_in_registry == set(safety.TOOLKIT_DENYLIST), "E-TOOLS-DENYLIST", "tools.yaml",
            f"toolkit_denied modes {sorted(denied_in_registry)} != safety.TOOLKIT_DENYLIST {sorted(safety.TOOLKIT_DENYLIST)}")
    for t in acts.get("allowed_tools", []):
        spec = tools.get(t)
        R.check(spec is not None and any(m.get("b4_executable") for m in (spec.get("modes") or {}).values()), "E-ROE-TOOLS", w,
                f"allowed tool {t!r} is not a B4-executable tool in tools.yaml")
    for m in acts.get("denied_modes", []):
        R.check(safety.registry_entry(c.tools, m) is not None, "E-ROE-TOOLS", w, f"denied mode {m!r} is not registered")
    defaults = tk.get("stop_condition_defaults") or {}
    for k, val in (r.get("stop_conditions") or {}).items():
        if k in defaults and isinstance(val, (int, float)) and isinstance(defaults[k], (int, float)):
            stricter = val >= defaults[k] if k.startswith("min_") else val <= defaults[k]
            R.check(stricter, "E-ROE-STOP", w, f"stop_conditions.{k}={val} is looser than the toolkit default {defaults[k]}")
    R.check(bool((r.get("stop_conditions") or {}).get("contacts")), "E-ROE-STOP", w, "stop_conditions.contacts must not be empty")
    hu = (r.get("stop_conditions") or {}).get("health_url")
    if hu is not None:
        prob = url_problem(hu)
        R.check(prob is None, "E-ROE-URL", w, f"stop_conditions.health_url {prob}")
    for t in r.get("targets", []):
        bi = t.get("build_identity") or {}
        need = {"header": ("header_name",), "endpoint": ("path", "json_pointer"), "none": ()}.get(bi.get("method"), ())
        extra = [k for k in ("header_name", "path", "json_pointer") if k not in need and bi.get(k) is not None]
        missing = [k for k in need if bi.get(k) is None]
        R.check(not extra and not missing, "E-ROE-TARGETS", w,
                f"{t.get('id')}: build_identity method {bi.get('method')!r} needs {list(need)} and null {extra or 'others'}")
    for ce in c.manifest.get("create_only_endpoints") or []:
        R.check(ce.get("target_id") in targets and (targets.get(ce.get("target_id")) or {}).get("kind") == "http", "E-SEED-MANIFEST",
                "seed-manifest.yaml", f"create_only_endpoints: {ce.get('target_id')} is not an http target of the ROE")
    relay, trelay = r.get("relay") or {}, tk.get("relay") or {}
    for k in ("max_turns", "max_spend_usd_per_job", "max_spend_usd_per_run"):
        if k in relay:
            R.check(trelay.get(k) is not None and relay[k] <= trelay[k], "E-ROE-RELAY", w, f"relay.{k} exceeds toolkit relay")
    for mk in relay.get("models", []):
        m = c.model(mk)
        if R.check(m is not None, "E-MODEL-UNKNOWN", w, f"relay model {mk!r} unknown"):
            R.check(mk in (e.get("allowed_models") or {}).get(e.get("data_class"), []), "E-ROE-RELAY", w, f"relay model {mk} not allowed for the data class")
    dh = r.get("data_handling") or {}
    R.check(dh.get("data_class") == e.get("data_class"), "E-ROE-DATA-CLASS", w, "data_handling.data_class != engagement data_class")
    rrd = dh.get("retention_days")
    R.check(isinstance(rrd, int) and rrd <= e.get("retention_days", 0), "E-ROE-RETENTION", w,
            f"data_handling.retention_days {rrd} longer than the engagement retention_days {e.get('retention_days')} (ROE may only shorten)")
    lim = retention_max(tk, e.get("data_class"))
    R.check(lim is None or (isinstance(rrd, int) and rrd <= lim), "E-RETENTION", w,
            f"data_handling.retention_days {rrd} above the toolkit.yaml maximum {lim}")
    for u in r.get("upstream_llm_providers") or []:
        R.check(u.get("terms_confirmed_by") in c.persons, "E-PERSON-UNKNOWN", w, "upstream terms_confirmed_by must be a registry person")
    legal(R, c)


def legal(R: Report, c: Ctx):
    r, w = c.roe, "roe.yaml"
    lr = r.get("legal_review")
    # L-1
    if not R.check(isinstance(lr, dict), "E-L1", w, "legal_review is required (docs/06 §2.1.1 L-1)"):
        return
    for k, val in (lr.get("scope") or {}).items():
        ok = val is True or (isinstance(val, dict) and (val.get("value") is True or bool(val.get("not_applicable_reason"))))
        R.check(ok, "E-L1", w, f"legal_review.scope.{k} must be true or carry not_applicable_reason")
    # L-2
    att = lr.get("attested_by")
    live = [x for x in c.entries if x.get("person_id") == att and not x.get("revoked_at")]
    roles = {ro for x in live for ro in x.get("roles", [])}
    R.check(bool(live), "E-L2", w, f"legal_review.attested_by {att!r} has no unrevoked registry key")
    if live and "legal_reviewer" not in roles:
        if "management" in roles:
            R.warn("W-L2-MANAGEMENT", w, f"{att} attests as management (no legal_reviewer role): flag this in the report")
        else:
            R.error("E-L2", w, f"{att} has neither the legal_reviewer nor the management role")
    # L-3
    sig = next((s for s in r.get("signatures") or [] if s.get("signer") == att), None)
    ok3 = sig is not None and silent_verify(c, signing_payload(r), sig, ts(R, r.get("issued_at"), w))
    R.check(ok3, "E-L3", w, f"legal_review.attested_by {att} has no valid signature on this ROE")
    # L-4
    v = r.get("validity") or {}
    at, exp = ts(R, lr.get("attested_at"), w), ts(R, lr.get("expires_at"), w)
    nb, na = ts(R, v.get("not_before"), w), ts(R, v.get("not_after"), w)
    R.check(at and nb and at <= nb, "E-L4", w, "legal_review.attested_at must be on or before ROE not_before")
    R.check(exp and na and exp >= na, "E-L4", w, "legal_review.expires_at must be on or after ROE not_after")
    # L-5
    leads = {s.get("person_id") for s in r.get("signatories") or [] if s.get("role") == "test_lead"}
    if att in leads and att is not None and att == consolidation_person(c):
        # lite + acknowledged role consolidation: allowed, but the report header must say the attestation is self-signed
        R.warn("W-L5-LITE", w, f"legal_review.attested_by {att} is also the test_lead (lite role_consolidation): "
               "the report header must state that the legal attestation was self-signed")
    else:
        R.check(att not in leads, "E-L5", w, f"legal_review.attested_by {att} must not be the ROE test_lead "
                "(G0b -> VERIFY_FAILED, reason legal_attester_is_test_lead; the run is SUSPENDED until the ROE is fixed)")
    # L-6
    tools = c.tools.get("tools") or {}
    status = {x.get("component"): x.get("status") for x in c.licenses.get("components", [])}
    gated = [t for t in (r.get("activities") or {}).get("allowed_tools", []) if status.get((tools.get(t) or {}).get("license_ref")) == LEGAL_GATE]
    if gated:
        R.check((lr.get("scope") or {}).get("component_licenses") is True, "E-L6", w,
                f"enabled tools {gated} are 法務閘門 in licenses.yaml: legal_review.scope.component_licenses must be true")


def platform_of(host: str | None) -> str | None:
    """E2: the shared-platform suffix a host is under (safety.SHARED_PLATFORM_SUFFIXES), or None."""
    h = safety.norm_host(host) if host else ""
    for suffix, plat in safety.SHARED_PLATFORM_SUFFIXES.items():
        if h == suffix or h.endswith("." + suffix):
            return plat
    return None


def platform_rules(R: Report, c: Ctx):
    """E2 (H-D3): a target on a shared-platform domain proves ownership with platform_project and has an accepted
    platform_policies entry of the same platform; dns_txt / well_known_path are not accepted there."""
    r, w = c.roe, "roe.yaml"
    policies = {p.get("platform"): p for p in r.get("platform_policies") or [] if isinstance(p, dict)}
    for p in policies.values():
        R.check(p.get("accepted_by") in c.persons, "E-ROE-PLATFORM", w, f"platform_policies {p.get('platform')}: accepted_by must be a registry person")
    for t in r.get("targets", []):
        op = t.get("ownership_proof") or {}
        if op.get("method") == "platform_project":
            R.check(all(op.get(k) for k in ("platform", "project_ref", "evidence_ref")), "E-ROE-PLATFORM", w,
                    f"{t.get('id')}: platform_project needs platform, project_ref and evidence_ref")
        else:
            R.check(bool(op.get("token_ref")), "E-ROE-TARGETS", w, f"{t.get('id')}: {op.get('method')} needs token_ref")
        if t.get("kind") != "http":
            continue
        plat = platform_of(safety.host_of(t.get("base_url")))
        if plat is None:
            continue
        R.check(op.get("method") == "platform_project" and op.get("platform") == plat, "E-ROE-PLATFORM", w,
                f"{t.get('id')}: {t.get('base_url')} is on a shared {plat} domain: ownership_proof must be platform_project "
                f"with platform {plat} (dns_txt / well_known_path prove nothing there)")
        R.check(plat in policies, "E-ROE-PLATFORM", w, f"{t.get('id')}: no platform_policies entry for {plat}")


# ============================================================== 9 models / agents
def reachable_models(c: Ctx) -> dict[str, set[str]]:
    """model key -> agents that can call it: agent model, agent fallback_models, and the
    models.yaml `fallback` chain of either (transitively)."""
    out: dict[str, set[str]] = {}
    for name, a in (c.agents or {}).items():
        if not isinstance(a, dict):
            continue
        todo = [a.get("model"), *(a.get("fallback_models") or [])]
        seen: set[str] = set()
        while todo:
            k = todo.pop()
            if not isinstance(k, str) or k in seen:
                continue
            seen.add(k)
            out.setdefault(k, set()).add(name)
            m = c.model(k)
            if m:
                todo.extend(m.get("fallback") or [])
    return out


def g_models(R: Report, c: Ctx):
    e, models, agents = c.engagement, c.models, c.agents
    dc = e.get("data_class")
    allowed = set((e.get("allowed_models") or {}).get(dc, []))
    ev = e.get("validity") or {}
    enb, ena = ts(R, ev.get("not_before"), "engagement.yaml"), ts(R, ev.get("not_after"), "engagement.yaml")
    used = set()
    for name, a in agents.items():
        where = f"agents.yaml {name}"
        if not isinstance(a, dict):
            R.error("E-AGENT", where, "not an object")
            continue
        mk = a.get("model")
        if a.get("role") in DETERMINISTIC_ROLES:
            R.check(mk is None, "E-AGENT-MODEL", where, f"deterministic role {a.get('role')} must have model null")
            continue
        if not R.check(mk is not None, "E-AGENT-MODEL", where, "LLM role needs a model"):
            continue
        if not R.check(mk in models, "E-MODEL-UNKNOWN", where, f"unknown model {mk!r} (not in models.yaml)"):
            continue
        used.add(mk)
        R.check(mk in allowed, "E-AGENT-DATA-CLASS", where, f"model {mk} not allowed for data class {dc}")
        if a.get("fallback_models"):
            R.check(a.get("role") in NON_ADJUDICATING_ROLES, "E-AGENT-FALLBACK", where, "cross-family fallback_models only on non-adjudicating roles")
            for fb in a["fallback_models"]:
                R.check(fb in models and fb in allowed, "E-AGENT-FALLBACK", where, f"fallback model {fb!r} unknown or not allowed")
    lane = agents.get("lane_a") or {}
    R.check(lane.get("model") == e.get("lane_a_model"), "E-AGENT-LANE-A", "agents.yaml lane_a", "lane_a model must equal engagement lane_a_model")
    for name, a in agents.items():
        if not isinstance(a, dict):
            continue
        tools_ = set(a.get("tools") or [])
        role = a.get("role")
        where = f"agents.yaml {name}"
        # B10 (H-C1, H-C2, N-6): reviewers / verifiers see only their slice; the commander gets a typed view built by
        # code (no tools); the invariant drafter reads the W0 inventory, never code slices
        if role in ("reviewer", "verifier"):
            R.check(tools_ <= {"read_slice"}, "E-AGENT-TOOLS", where, f"{role} may only use read_slice, has {sorted(tools_)}")
        elif role == "commander":
            R.check(not tools_, "E-AGENT-TOOLS", where, f"commander has no tools (typed input view), has {sorted(tools_)}")
        elif role == "invariant_drafter":
            R.check("read_slice" not in tools_, "E-AGENT-TOOLS", where, "invariant_drafter must not read code slices")
        # D15 (M-V1): every model reachable through fallback must take the engagement's data class and be allowed for it
        if a.get("model") and role not in DETERMINISTIC_ROLES:
            todo, seen = list((c.model(a.get("model")) or {}).get("fallback") or []) + list(a.get("fallback_models") or []), set()
            while todo:
                k = todo.pop()
                if k in seen or not isinstance(k, str):
                    continue
                seen.add(k)
                m = c.model(k)
                R.check(m is not None and dc in (m.get("data_classes") or []) and k in allowed, "E-MODEL-FALLBACK-CLASS", where,
                        f"fallback model {k!r} (reachable from {a.get('model')}) cannot take {dc} data or is not in allowed_models.{dc}")
                todo.extend((m or {}).get("fallback") or [])
    reach = reachable_models(c)
    for k, m in models.items():
        where = f"models.yaml {k}"
        if not isinstance(m, dict):
            R.error("E-MODEL", where, "not an object")
            continue
        for fb in m.get("fallback", []):
            R.check(fb in models and models[fb].get("family") == m.get("family"), "E-MODEL-FALLBACK", where, f"fallback {fb!r} unknown or cross-family")
        lit = str(m.get("litellm", ""))
        # placeholder model IDs (e.g. nemotron_cloud): marked, never silent
        looks_placeholder = PLACEHOLDER_ID.search(lit) is not None
        if m.get("placeholder") is True or looks_placeholder:
            users = sorted(reach.get(k, ()))
            detail = (f"litellm {lit!r} is a placeholder model ID (replace before any real run)"
                      + (f"; reachable from agents {users}" if users else "") + ("; allowed by the engagement" if k in allowed else ""))
            if c.real_run and users:
                # --real-run: a placeholder an agent can actually call (primary, agent fallback or
                # models.yaml fallback chain) would send traffic to an unknown / wrong model
                R.error("E-MODEL-PLACEHOLDER", where, detail + " [--real-run]")
            elif m.get("placeholder") is True:
                R.warn("W-MODEL-PLACEHOLDER", where, detail)
        R.check(not looks_placeholder or m.get("placeholder") is True, "E-MODEL-PLACEHOLDER", where,
                f"litellm {lit!r} looks like a placeholder (<...>, {{...}}, TBD, TODO, FIXME, 實作時確認) but placeholder: true is not set")
        if lit.startswith("nvidia_nim/"):
            R.check("C" not in m.get("data_classes", []) and "production" not in m.get("purpose", []), "E-MODEL-NIM", where,
                    "build.nvidia.com trial endpoint must be P-only and non-production")
        if "C" in m.get("data_classes", []) and lit.startswith("openai/"):
            R.check(m.get("store") is False, "E-MODEL-STORE", where, "OpenAI API models taking C data must set store: false")
        er = m.get("earliest_retirement")
        if er and (k in used or k in allowed) and enb and ena:
            d = dt.date.fromisoformat(er)
            if d < enb.date():
                R.error("E-MODEL-RETIRED", where, f"earliest_retirement {er} is before the engagement starts")
            elif d <= ena.date():
                R.warn("W-MODEL-RETIREMENT", where, f"earliest_retirement {er} falls inside the engagement validity")
    # family diversity
    def fam(a):
        m = c.model(a.get("model"))
        return (m.get("family"), m.get("lineage"), set(m.get("data_classes", []))) if m else None
    reviewers = [f for f in (fam(a) for a in agents.values() if isinstance(a, dict) and a.get("role") == "reviewer") if f]
    verifiers = [f for f in (fam(a) for a in agents.values() if isinstance(a, dict) and a.get("role") == "verifier") if f]
    fams = {f for f, _, d in reviewers if dc in d}
    if len(fams) < 2:
        R.warn("W-DIVERSITY", "agents.yaml", f"reviewers for {dc} span {len(fams)} family: diversity degraded (verdicts capped)")
    R._checks += 1
    for rf, rl, _ in reviewers:
        R.check(any(vf != rf and vl != rl and dc in vd for vf, vl, vd in verifiers), "E-DIVERSITY-VERIFIER", "agents.yaml",
                f"no verifier outside family {rf} / lineage {rl} for {dc}")
    # model claims in findings, votes, testresults
    for d in c.docs("finding"):
        rep = d.data.get("reporter") or {}
        a = agents.get(rep.get("agent_id")) or {}
        m = c.model(rep.get("model_key"))
        R.check(a.get("model") == rep.get("model_key") and m is not None and m.get("family") == rep.get("family")
                and m.get("lineage") == rep.get("lineage"), "E-FINDING-REPORTER", d.path, "reporter agent/model/family/lineage disagree with the registries")
    for d in c.docs("verdict"):
        for i, vt in enumerate(d.data.get("votes", [])):
            a = agents.get(vt.get("voter_agent_id")) or {}
            m = c.model(vt.get("voter_model_key"))
            # (the verifier-role requirement is E-VERDICT-VOTER-ROLE in g_verdicts)
            R.check(a.get("model") == vt.get("voter_model_key") and m is not None
                    and m.get("family") == vt.get("voter_family") and m.get("lineage") == vt.get("voter_lineage"),
                    "E-VOTE-MODEL", d.path, f"votes[{i}] voter agent/model/family/lineage disagree with the registries")
    for d in c.docs("testresult"):
        ib = d.data.get("interpreted_by")
        if ib:
            m = c.ix.model_of_agent(ib.get("agent_id"))
            R.check(m is not None and m.get("family") == ib.get("family"), "E-RESULT-ANALYST", d.path, "interpreted_by family disagrees with the agent's model")
    # D14 (H-A4): threat modellers and the invariant drafter resolve to registry agents of the right role and family
    for d in c.docs("threat"):
        for mb in d.data.get("modeled_by") or []:
            a = agents.get(mb.get("agent_id")) if isinstance(mb.get("agent_id"), str) else None
            m = c.ix.model_of_agent(mb.get("agent_id"))
            R.check(isinstance(a, dict) and a.get("role") in ("threat_modeler", "threat_merger") and m is not None
                    and m.get("family") == mb.get("family") and (a.get("viewpoint") in (None, mb.get("viewpoint"))),
                    "E-PROVENANCE", d.path, f"modeled_by {mb.get('agent_id')!r} / {mb.get('family')!r} / {mb.get('viewpoint')!r} does not "
                    "match an agents.yaml threat_modeler (role, registry family, viewpoint)")
    db_ = c.invariants.get("drafted_by") or {}
    if c.invariants:
        a = agents.get(db_.get("agent_id")) if isinstance(db_.get("agent_id"), str) else None
        m = c.ix.model_of_agent(db_.get("agent_id"))
        R.check(isinstance(a, dict) and a.get("role") == "invariant_drafter" and m is not None and m.get("family") == db_.get("family"),
                "E-PROVENANCE", "invariants.yaml", f"drafted_by {db_} does not match an agents.yaml invariant_drafter and its registry family")
    for d in c.docs("slice"):
        for x in d.data.get("excluded_models", []):
            R.check(x.get("model_key") in models, "E-MODEL-UNKNOWN", d.path, f"excluded model {x.get('model_key')!r} unknown")
            if x.get("reason") == "data_class":
                m = c.model(x.get("model_key")) or {}
                run = c.runs.get(d.data.get("run_id")) or {}
                R.check(run.get("data_class") not in m.get("data_classes", []), "E-SLICE-EXCLUDED", d.path, "excluded for data_class but the model may take it")


# ============================================================== 10 gates
ENGAGEMENT_GATES = ("G0a", "G1", "G2")
ROE_GATES = ("G0b", "G3", "G4", "G5")


def profile(c: Ctx) -> str:
    return c.engagement.get("assurance_profile") or "team"


def consolidation_person(c: Ctx) -> str | None:
    """The one person allowed to hold several ROE / gate roles: only in lite, only when acknowledged."""
    rc = c.engagement.get("role_consolidation") or {}
    if profile(c) == "lite" and rc.get("acknowledged") is True:
        return rc.get("person_id")
    return None


def gate_sod(R: Report, c: Ctx, rec: dict, w: str):
    """E1: a person approves a gate in at most one of its required roles (lite + acknowledged consolidation excepted)."""
    by_person: dict = {}
    for a in rec.get("approvers", []):
        by_person.setdefault(a.get("person_id"), set()).add(a.get("role"))
    for p, roles in by_person.items():
        if len(roles) > 1:
            R.check(p == consolidation_person(c), "E-GATE-SOD", w,
                    f"{p} approves {rec.get('gate')} in several roles {sorted(roles)} (only an acknowledged lite role_consolidation allows this)")


def g_gates(R: Report, c: Ctx):
    e, r = c.engagement, c.roe
    tmo = e.get("gate_timeouts_hours") or {}
    ev = e.get("validity") or {}
    enb, ena = ts(R, ev.get("not_before"), "engagement.yaml"), ts(R, ev.get("not_after"), "engagement.yaml")
    rv = r.get("validity") or {}
    rnb, rna = ts(R, rv.get("not_before"), "roe.yaml"), ts(R, rv.get("not_after"), "roe.yaml")
    roe_people = {(p.get("person_id"), p.get("key_fingerprint")) for p in (r.get("signatories") or []) + (r.get("gate_approvers") or [])}
    for d in c.docs("gate-record"):
        rec, w = d.data, d.path
        gate = rec.get("gate")
        run = c.runs.get(rec.get("run_id"))
        if not R.check(run is not None, "E-GATE-RUN", w, f"run {rec.get('run_id')} not found"):
            continue
        R.check(rec.get("engagement_id") == e.get("engagement_id"), "E-GATE-RUN", w, "engagement_id mismatch")
        opened, at = ts(R, rec.get("opened_at"), w), ts(R, rec.get("timestamp"), w)
        if not (opened and at):
            continue
        R.check(opened <= at, "E-GATE-TIME", w, "opened_at after timestamp")
        R.check(enb and ena and enb <= at <= ena, "E-GATE-ENGAGEMENT", w, "decided outside the engagement validity")
        roles = {a.get("role") for a in rec.get("approvers", [])}
        if gate in GATE_ROLES:
            R.check(GATE_ROLES[gate] <= roles, "E-GATE-ROLES", w, f"missing roles {sorted(GATE_ROLES[gate] - roles)}")
        for a in rec.get("approvers", []):
            ent = c.by_fp.get(a.get("key_fingerprint"))
            R.check(ent is not None and ent.get("person_id") == a.get("person_id") and a.get("role") in ent.get("roles", []),
                    "E-GATE-APPROVER", w, f"approver {a.get('person_id')} / {a.get('role')} / key not registered together")
        R.check(rec.get("initiator") in c.persons and rec.get("initiator") not in c.automation, "E-GATE-INITIATOR", w,
                "initiator must be a registered person, not an automation account")
        R.check(rec.get("initiator") in run.get("initiators", []), "E-GATE-INITIATOR", w, "initiator is not a run initiator")
        if gate == "G0a":
            want = {(s.get("person_id"), s.get("role"), s.get("key_fingerprint")) for s in e.get("signatories") or []}
            got = {(a.get("person_id"), a.get("role"), a.get("key_fingerprint")) for a in rec.get("approvers", [])}
            R.check(want == got, "E-GATE-G0-APPROVERS", w, "G0a approvers must be the engagement signatories")
        if gate == "G0b":
            want = {(s.get("person_id"), s.get("role"), s.get("key_fingerprint")) for s in r.get("signatories") or []}
            got = {(a.get("person_id"), a.get("role"), a.get("key_fingerprint")) for a in rec.get("approvers", [])}
            R.check(want == got, "E-GATE-G0-APPROVERS", w, "G0b approvers must be the ROE signatories")
        # B8 (H-D2): white-box gates are approved from the engagement registry, black-box gates from the ROE
        if gate in ENGAGEMENT_GATES:
            allowed_eng = set(((e.get("gate_approvers") or {}).get(gate)) or [])
            for a in rec.get("approvers", []):
                R.check(a.get("person_id") in allowed_eng, "E-GATE-APPROVER-ENG", w,
                        f"{gate} approver {a.get('person_id')} is not in engagement.yaml gate_approvers.{gate} {sorted(allowed_eng)}")
        if gate in ROE_GATES:
            for a in rec.get("approvers", []):
                R.check((a.get("person_id"), a.get("key_fingerprint")) in roe_people, "E-GATE-ROE-APPROVER", w,
                        f"{gate} approver {a.get('person_id')} is not a ROE signatory or gate_approver")
            R.check(rnb and rna and rnb <= at <= rna, "E-GATE-ROE-VALIDITY", w, f"{gate} decided outside the ROE validity")
        gate_sod(R, c, rec, w)
        # timeouts
        limit = tmo.get(gate)
        if limit is not None and gate != "G5":
            R.check(at - opened <= dt.timedelta(hours=limit), "E-GATE-TIMEOUT", w, f"decided {at - opened} after opening; timeout {limit} h")
        # outcome vs decisions
        decs = [x.get("decision") for x in rec.get("decisions", [])]
        if rec.get("outcome") == "PARTIALLY_APPROVED":
            R.check(gate in ("G3", "G4"), "E-GATE-OUTCOME", w, "PARTIALLY_APPROVED is only allowed at G3 and G4 (D2)")
        if gate in ("G3", "G4") and decs:
            want = "APPROVED" if all(x == "accept" for x in decs) else ("REJECTED" if all(x == "reject" for x in decs) else "PARTIALLY_APPROVED")
            R.check(rec.get("outcome") == want, "E-GATE-OUTCOME", w, f"{gate} outcome {rec.get('outcome')} but decisions imply {want}")
        if gate == "G2":
            R.check(rec.get("outcome") in ("APPROVED", "EXPIRED"), "E-GATE-OUTCOME", w,
                    f"G2 whole-gate outcome must be APPROVED or EXPIRED (per-item REJECTED/NEEDS_INFO live in decisions), not {rec.get('outcome')}")
        if gate in ("G1", "G5") and rec.get("outcome") == "APPROVED":
            R.check(all(x == "accept" for x in decs), "E-GATE-OUTCOME", w, "APPROVED with non-accept decisions")
        if gate == "GB":
            gb = rec.get("gb") or {}
            ok_outcome = {"extend": "APPROVED", "stop_phase": "REJECTED", "abort": "APPROVED"}.get(gb.get("choice"))
            R.check(rec.get("outcome") == ok_outcome, "E-GATE-OUTCOME", w, f"GB choice {gb.get('choice')} needs outcome {ok_outcome}")
            allowed = {e.get("budget_approver") or e.get("run_owner"), e.get("run_owner")}
            for a in rec.get("approvers", []):
                R.check(a.get("person_id") in allowed, "E-GB-APPROVER", w, f"GB approver {a.get('person_id')} is neither run_owner nor budget_approver")
        if gate == "G4":
            for a in rec.get("approvers", []):
                R.check(a.get("person_id") in run.get("initiators", []), "E-G4-INITIATOR", w,
                        f"G4 approver {a.get('person_id')} must be recorded as a run initiator")
        if gate == "G5":
            for a in rec.get("approvers", []):
                R.check(a.get("person_id") not in run.get("initiators", []) and a.get("person_id") != rec.get("initiator"),
                        "E-G5-INITIATOR", w, f"G5 approver {a.get('person_id')} must not be a run initiator")
            if profile(c) == "full":
                revs = {a.get("person_id") for a in rec.get("approvers", []) if a.get("role") == "security_reviewer"}
                R.check(len(revs) >= 2, "E-G5-TWO-PERSON", w, f"assurance_profile full: G5 needs two distinct security_reviewer approvers, got {sorted(revs)}")
            win_end = timeutil.window_end(opened, roe_windows(c))
            R.check(win_end is not None, "E-G5-WINDOW", w, "G5 opened outside every ROE time window")
            R.check(timeutil.in_any_window(at, roe_windows(c)), "E-G5-WINDOW", w, "G5 decided outside every ROE time window")
            if win_end is not None:
                lim = min(win_end, opened + dt.timedelta(hours=tmo.get("G5", 24)))
                R.check(at < lim, "E-G5-WINDOW", w, f"G5 decided at/after the window end {win_end.isoformat()}")
            job = (run.get("jobs") or {}).get(rec.get("job_id"))
            R.check(job is not None and job.get("safety_class") == "S2", "E-G5-JOB", w, "G5 must reference an S2 job of the run")
        else:
            R.check(rec.get("job_id") is None, "E-GATE-JOB", w, "job_id is only used by G5")
        # threats vs G3 decisions
        if gate == "G3":
            for x in rec.get("decisions", []):
                t = c.ix.first("threat", threat_id=x.get("item_id"))
                if R.check(t is not None, "E-TRACE", w, f"threat {x.get('item_id')} not found"):
                    want = {"accept": "ACCEPTED", "reject": "REJECTED"}.get(x.get("decision"), "NEEDS_INFO")
                    rv_ = t.data.get("review") or {}
                    R.check(rv_.get("status") == want and rv_.get("gate_record_id") == rec.get("gate_record_id"), "E-TRACE-THREAT-REVIEW",
                            t.path, f"review must be {want} by {rec.get('gate_record_id')}")
        if gate == "G1":
            for inv in c.invariants.get("invariants", []):
                so = inv.get("signoff") or {}
                dec = next((x for x in rec.get("decisions", []) if x.get("item_id") == inv.get("requirement_id")), None)
                R.check(dec is not None and so.get("gate_record_id") == rec.get("gate_record_id")
                        and so.get("status") == {"accept": "ACCEPTED", "reject": "REJECTED"}.get(dec.get("decision")),
                        "E-TRACE-INVARIANT", "invariants.yaml", f"{inv.get('requirement_id')}: signoff does not match {rec.get('gate_record_id')}")


# ============================================================== 11 runs
def g_runs(R: Report, c: Ctx):
    tk, e = c.toolkit, c.engagement
    for d in c.docs("run"):
        run, w = d.data, d.path
        rid = run.get("run_id")
        R.check(run.get("engagement_id") == e.get("engagement_id"), "E-RUN", w, "engagement_id mismatch")
        R.check(run.get("data_class") == e.get("data_class"), "E-RUN", w, "data_class differs from the engagement")
        R.check(run.get("calibration_version") == c.calibration.get("calibration_version"), "E-RUN", w, "calibration_version differs")
        want_owasp = e.get("owasp_llm_version") or tk.get("owasp_llm_default")
        R.check(run.get("owasp_llm_version") == want_owasp, "E-RUN-OWASP", w, f"owasp_llm_version must be {want_owasp}")
        R.check(run.get("run_owner") == e.get("run_owner"), "E-RUN", w, "run_owner differs from the engagement")
        for p in run.get("initiators", []):
            R.check(p in c.persons and p not in c.automation, "E-RUN-INITIATOR", w, f"initiator {p} must be a registered person")
        status = run.get("status")
        pending = [g for g in run.get("gate_records", []) if g.get("gate_record_id") is None]
        if status in TERMINAL_RUN_STATES:
            R.check(run.get("current_node") is None and not pending, "E-RUN-STATUS", w, f"{status} run has a current node or pending gate")
        if status == "WAITING_GATE":
            R.check(len(pending) == 1 and run.get("current_node") == pending[0].get("gate"), "E-RUN-STATUS", w,
                    "WAITING_GATE needs exactly one pending gate equal to current_node")
            if pending:
                g = pending[0]
                op, dl = ts(R, g.get("opened_at"), w), ts(R, run.get("resume_deadline"), w)
                lim = (e.get("gate_timeouts_hours") or {}).get(g.get("gate"))
                R.check(op and dl and lim is not None and dl == op + dt.timedelta(hours=lim), "E-RUN-DEADLINE", w,
                        f"resume_deadline must be opened_at + {lim} h")
        run_manifest(R, c, d)
        kind = run.get("run_kind")
        gates = [g.get("gate") for g in run.get("gate_records", [])]
        if kind == "lane_a":
            R.check(run.get("roe_ref") is None and "G0b" not in gates and not run.get("jobs"), "E-RUN-LANE-A", w,
                    "Lane A runs never pass G0b or run black-box jobs")
            for vid in run.get("verdicts", []):
                v = c.ix.first("verdict", verdict_id=vid)
                R.check(v is not None and v.data.get("advisory") is True, "E-RUN-LANE-A", w, f"Lane A verdict {vid} must be advisory")
            R.check(set(run.get("lane_a_advisories", [])) == set(run.get("cluster_ids", [])), "E-RUN-LANE-A", w, "lane_a_advisories must list the run's clusters")
        if kind == "followup":
            R.check(run.get("parent_run_id") in c.runs, "E-RUN-FOLLOWUP", w, "parent run not found")
            parent = c.runs.get(run.get("parent_run_id")) or {}
            R.check(any(fd in parent.get("followup_drafts", []) for p in c.docs("commander-plan") if p.data.get("plan_id") in run.get("plan_ids", [])
                        for fd in (x.get("draft_id") for x in p.data.get("followup_drafts", []))), "E-RUN-FOLLOWUP", w,
                    "a follow-up run must come from a follow-up draft of its parent")
        else:
            R.check(run.get("parent_run_id") is None and run.get("reuse") == [], "E-RUN-FOLLOWUP", w, "only follow-up runs have a parent / reuse")
        # gate record ordering
        times = [ts(R, g.get("opened_at"), w) for g in run.get("gate_records", [])]
        times = [t for t in times if t]
        R.check(times == sorted(times), "E-RUN-GATES", w, "gate_records are not in opened_at order")
        for g in run.get("gate_records", []):
            if g.get("gate_record_id"):
                grec = c.record(g["gate_record_id"])
                if R.check(grec is not None, "E-RUN-GATES", w, f"gate record {g['gate_record_id']} not found"):
                    # D8: a run may only list its own gate records
                    R.check(grec.get("run_id") == rid, "E-GATE-RUN", w,
                            f"gate record {g['gate_record_id']} belongs to run {grec.get('run_id')}, not {rid}")
        # G4 approved ids
        g4 = [x.data for x in c.ix.gate_records(rid, "G4")]
        if g4:
            acc = sorted(x.get("item_id") for x in g4[-1].get("decisions", []) if x.get("decision") == "accept")
            R.check(sorted(run.get("approved_testcase_ids", [])) == acc, "E-RUN-G4", w, "approved_testcase_ids must be the G4 accepted items")
        else:
            R.check(not run.get("approved_testcase_ids") and not run.get("jobs"), "E-RUN-G4", w, "no G4 record but approved tests / jobs exist")
        R.check(set(run.get("approved_testcase_ids", [])) <= set(run.get("testcase_ids", [])), "E-RUN-G4", w, "approved ids not in testcase_ids")
        g4_at = ts(R, g4[-1].get("timestamp"), w) if g4 else None
        # budgets after GB
        for gbr in c.ix.gate_records(rid, "GB"):
            gb = gbr.data.get("gb") or {}
            if gbr.data.get("outcome") == "APPROVED" and gb.get("choice") == "extend":
                cur = (run.get("budgets") or {}).get(gb.get("phase")) or {}
                R.check(all(cur.get(k) == v for k, v in (gb.get("new_caps") or {}).items()), "E-RUN-BUDGET", w,
                        f"budgets.{gb.get('phase')} must carry the GB new_caps")
        for ph, bud in (run.get("budgets") or {}).items():
            if isinstance(bud, dict) and "max_input_tokens" in bud:
                for spent, cap in (("spent_input_tokens", "max_input_tokens"), ("spent_output_tokens", "max_output_tokens"),
                                   ("spent_cost_usd", "max_cost_usd"), ("compute_minutes", "max_compute_minutes")):
                    if bud.get(cap) is not None:
                        R.check(bud.get(spent, 0) <= bud[cap], "E-RUN-BUDGET", w, f"budgets.{ph}.{spent} exceeds {cap}")
        # jobs
        audit = c.ix.audit_for(rid)
        drills = [ts(R, x.get("ts"), w) for x in (audit.data if audit else []) if x.get("event_type") == "restore_drill" and (x.get("payload") or {}).get("ok")]
        drill_days = tk.get("restore_drill_interval_days", 7)
        for jid, job in (run.get("jobs") or {}).items():
            jw = f"{w} jobs.{jid}"
            R.check(job.get("job_id") == jid, "E-RUN-JOB", jw, "job_id != key")
            tc = c.ix.first("testcase", testcase_id=job.get("testcase_id"))
            if not R.check(tc is not None, "E-RUN-JOB", jw, "testcase not found"):
                continue
            R.check(job.get("testcase_id") in run.get("approved_testcase_ids", []), "E-RUN-JOB", jw, "job for a testcase not approved at G4")
            if profile(c) == "lite":
                R.check(job.get("safety_class") in ("S0", "S1"), "E-PROFILE-SAFETY", jw,
                        f"assurance_profile lite allows only S0/S1 jobs, got {job.get('safety_class')}")
            R.check(job.get("safety_class") == tc.data.get("safety_class_computed"), "E-RUN-JOB", jw, "safety_class != testcase computed class")
            R.check(job.get("target_id") in tc.data.get("target_ids", []), "E-RUN-JOB", jw, "target not in the testcase")
            tr = next((x.data for x in c.docs("testresult") if x.data.get("job_id") == jid and x.data.get("run_id") == rid), None)
            if job.get("safety_class") == "S2":
                g5 = c.record(job.get("g5_record_id"))
                R.check(g5 is not None and g5.get("gate") == "G5" and g5.get("outcome") == "APPROVED" and g5.get("job_id") == jid,
                        "E-RUN-S2", jw, "S2 job needs an APPROVED G5 record for this job")
                R.check(job.get("snapshot_ref") and job.get("restore_verified") is True and job.get("status") == "RESTORED",
                        "E-RUN-S2", jw, "S2 job needs a snapshot, a verified restore and status RESTORED")
                start = ts(R, tr.get("executed_at"), jw) if tr else (ts(R, g5.get("timestamp"), jw) if g5 else None)
                ok = start is not None and any(dd and dd <= start and start - dd <= dt.timedelta(days=drill_days) for dd in drills)
                # a log rejected by the strict loader is reported once (E-JSON-STRICT), not re-reported here
                R.check(ok or rid in c.broken_audit_runs, "E-RUN-RESTORE-DRILL", jw,
                        f"no successful restore drill within {drill_days} days before the S2 job")
                R.check(run.get("restore_drill_ref") is not None, "E-RUN-RESTORE-DRILL", jw, "restore_drill_ref missing")
                if tr and g5:
                    g5_at = ts(R, g5.get("timestamp"), jw)
                    end = timeutil.window_end(g5_at, roe_windows(c)) if g5_at else None
                    ex = ts(R, tr.get("executed_at"), jw)
                    R.check(g5_at and ex and end and g5_at <= ex < end, "E-RESULT-G5", jw, "S2 job must start after its G5 and inside the same window")
            else:
                R.check(job.get("g5_record_id") is None, "E-RUN-JOB", jw, "only S2 jobs have a G5 record")
            if job.get("status") in ("EXECUTED", "RESTORED"):
                R.check(tr is not None, "E-RUN-JOB", jw, "executed job without a testresult")
                R.check(jid in run.get("executed_jobs", []), "E-RUN-JOB", jw, "executed job not listed in executed_jobs")
        R.check(set(run.get("executed_jobs", [])) <= set((run.get("jobs") or {})), "E-RUN-JOB", w, "executed_jobs not in jobs")
        # testresults of this run
        rv = c.roe.get("validity") or {}
        rnb, rna = ts(R, rv.get("not_before"), "roe.yaml"), ts(R, rv.get("not_after"), "roe.yaml")
        for x in c.docs("testresult"):
            tr = x.data
            if tr.get("run_id") != rid:
                continue
            ex = ts(R, tr.get("executed_at"), x.path)
            tc = c.ix.first("testcase", testcase_id=tr.get("testcase_id"))
            black_box = tr.get("phase") == "B4"
            if black_box:
                job = (run.get("jobs") or {}).get(tr.get("job_id"))
                R.check(job is not None and job.get("testcase_id") == tr.get("testcase_id"), "E-RESULT-JOB", x.path, "job not in the run or for another testcase")
            else:                  # W4: Z2 sandbox test, no B4 job, no ROE window
                R.check(tr.get("job_id") is None, "E-RESULT-JOB", x.path, "W4 results have no B4 job (job_id null)")
            if ex and black_box:
                R.check(timeutil.in_any_window(ex, roe_windows(c)) and rnb and rna and rnb <= ex <= rna, "E-RESULT-WINDOW", x.path,
                        "executed outside the ROE validity / time windows")
                R.check(g4_at is not None and ex > g4_at, "E-RESULT-G4", x.path, "executed before G4 approval")
            if tc:
                result_controls(R, c, x, tc.data)
                R.check(tr.get("request_count", 0) <= (tc.data.get("rate_limit") or {}).get("max_requests", 0), "E-RESULT-REQUESTS", x.path,
                        "request_count exceeds the testcase max_requests")
                n = (tc.data.get("trials") or {}).get("n")
                R.check((tr.get("trials") or {}).get("n") == n, "E-RESULT-TRIALS", x.path, f"trials.n must equal the testcase n={n}")
                R.check(set(tr.get("target_ids", [])) <= set(tc.data.get("target_ids", [])), "E-RESULT-TARGETS", x.path, "targets outside the testcase")
            if black_box:
                result_build(R, c, x, run)
                R.check(tr.get("request_log_sha256") is not None, "E-RESULT-REQUEST-LOG", x.path,
                        "black-box (B4) results need request_log_sha256 (the Scope Proxy request log)")
            t = tr.get("trials") or {}
            R.check(0 <= t.get("k", 0) <= t.get("n", 0), "E-RESULT-TRIALS", x.path, "k must be between 0 and n")
            if tr.get("outcome") == "FAIL":
                R.check(t.get("k", 0) >= 1, "E-RESULT-TRIALS", x.path, "FAIL needs k >= 1")
            R.check(0 <= tr.get("replay_k", 0) <= tr.get("replays", 0), "E-RESULT-TRIALS", x.path,
                    "replay_k (k_r) must be between 0 and replays (n_r)")
        rm = c.ix.first("report-manifest", run_id=rid)
        if rm is not None:
            want = unverified_build_targets(c, rid)
            R.check(sorted(rm.data.get("build_unverified_targets") or []) == want, "E-RESULT-BUILD", rm.path,
                    f"build_unverified_targets {rm.data.get('build_unverified_targets')} must list exactly the tested targets whose "
                    f"ROE build_identity.method is none: {want}")


def build_matches(observed, commit) -> bool:
    """B7: observed build id == run.repo_commit, or one is a prefix of the other and the shorter has >= 12 hex chars."""
    if not isinstance(observed, str) or not isinstance(commit, str):
        return False
    if observed == commit:
        return True
    short, long_ = sorted((observed, commit), key=len)
    return len(short) >= 12 and long_.startswith(short)


def roe_target(c: Ctx, tid) -> dict:
    return next((t for t in c.roe.get("targets") or [] if isinstance(t, dict) and t.get("id") == tid), {})


def unverified_build_targets(c: Ctx, run_id) -> list[str]:
    tids = {t for x in c.docs("testresult") if x.data.get("run_id") == run_id and x.data.get("phase") == "B4"
            for t in x.data.get("target_ids") or []}
    return sorted(t for t in tids if (roe_target(c, t).get("build_identity") or {}).get("method") == "none")


def result_build(R: Report, c: Ctx, x: Doc, run: dict):
    """B7 (H-B4): targets with a build identity must have served the run's repo_commit."""
    tr = x.data
    for t in tr.get("target_ids") or []:
        method = (roe_target(c, t).get("build_identity") or {}).get("method")
        if method in ("header", "endpoint"):
            R.check(build_matches(tr.get("observed_build_id"), run.get("repo_commit")), "E-RESULT-BUILD", x.path,
                    f"{t}: observed_build_id {tr.get('observed_build_id')!r} is not the run's repo_commit {run.get('repo_commit')!r} "
                    "(full, or a prefix of at least 12 characters)")


def result_controls(R: Report, c: Ctx, x: Doc, tc: dict):
    """B5 / A2: controls, INVALID, fail_oracles, derived precondition_reached / positive_control, analyst role."""
    tr, w = x.data, x.path
    ctl = derive.control_results(tc, tr)
    want_ids = [cid for cid, _, _ in ctl]
    got_ids = [y.get("control_id") for y in tr.get("controls") or [] if isinstance(y, dict)]
    R.check(sorted(got_ids) == sorted(want_ids) and len(set(got_ids)) == len(got_ids), "E-RESULT-CONTROLS", w,
            f"controls {got_ids} must cover exactly the testcase controls {want_ids}")
    not_pass = [cid for cid, _, o in ctl if o != "PASS"]
    if not_pass:
        R.check(tr.get("outcome") == "INVALID", "E-RESULT-INVALID", w,
                f"controls {not_pass} did not PASS: the outcome must be INVALID (never PASS/FAIL), got {tr.get('outcome')}")
    else:
        R.check(tr.get("outcome") != "INVALID", "E-RESULT-INVALID", w, "INVALID needs at least one control that did not PASS")
    fo = tr.get("fail_oracles") or []
    R.check((tr.get("outcome") == "FAIL") == bool(fo), "E-RESULT-ORACLE", w, "fail_oracles must be non-empty iff the outcome is FAIL")
    R.check(set(fo) <= derive.oracle_types(tc), "E-RESULT-ORACLE", w,
            f"fail_oracles {sorted(set(fo) - derive.oracle_types(tc))} are not oracle.types of {tc.get('testcase_id')}")
    pr = (tr.get("precondition_reached") or {}).get("value")
    R.check(pr is derive.reachability_reached(tc, tr), "E-RESULT-PRECONDITION", w,
            f"precondition_reached {pr} != derived {derive.reachability_reached(tc, tr)} (every reachability control PASS)")
    pc = (tr.get("positive_control") or {}).get("value")
    R.check(pc is derive.positive_control_value(tc, tr), "E-RESULT-CONTROLS", w,
            f"positive_control {pc} != derived {derive.positive_control_value(tc, tr)} (an oracle_can_fail control exists and PASSed)")
    ib = tr.get("interpreted_by")
    R.check((ib is None) == (tr.get("interpretation") is None), "E-RESULT-ANALYST", w, "interpretation is set iff interpreted_by is set")
    if isinstance(ib, dict):
        a = c.agents.get(ib.get("agent_id")) if isinstance(ib.get("agent_id"), str) else None
        R.check(isinstance(a, dict) and a.get("role") == "result_analyst", "E-RESULT-ANALYST-ROLE", w,
                f"interpreted_by {ib.get('agent_id')!r} must be an agents.yaml agent with role result_analyst (got {(a or {}).get('role')!r})")


MAX_EXTRA_DISPATCH_ROUNDS = 2


def run_manifest(R: Report, c: Ctx, d: Doc):
    """B11 (N-5, H-E13): config refs name the right files, tool versions are registered and agree with the audit
    log, the rule version is the adjudicator's; B10 CMD-2 round bound; B9 baseline run."""
    run, w = d.data, d.path
    rid = run.get("run_id")
    for key, kind in derive.CONFIG_KINDS.items():
        ref = (run.get("config_refs") or {}).get(key)
        if ref is None:
            R.check(key == "seed_manifest" and run.get("run_kind") == "lane_a", "E-RUN-CONFIG", w,
                    f"config_refs.{key} may only be null for seed_manifest in a Lane A run")
            continue
        cd = next((x for x in c.b.docs if x.path == ref.get("path") and x.data is not None), None)
        R.check(cd is not None and cd.kind == kind, "E-RUN-CONFIG", w, f"config_refs.{key}.path {ref.get('path')!r} is not a {kind} file")
    versions = {}
    for tv in run.get("tool_versions") or []:
        R.check(safety.registry_entry(c.tools, tv.get("adapter")) is not None, "E-RUN-CONFIG", w,
                f"tool_versions: {tv.get('adapter')!r} is not a registered tools.yaml tool:mode")
        versions[tv.get("adapter")] = tv.get("version")
    audit = c.ix.audit_for(rid)
    for e in (audit.data if audit else []):
        p = e.get("payload") or {}
        if e.get("event_type") == "tool_invocation_end" and p.get("adapter"):
            R.check(versions.get(p.get("adapter")) is not None and versions.get(p.get("adapter")) == p.get("tool_version"), "E-RUN-CONFIG", w,
                    f"audit seq {e.get('seq')}: {p.get('adapter')} ran as version {p.get('tool_version')!r} but run.tool_versions says "
                    f"{versions.get(p.get('adapter'))!r}")
    R.check(run.get("rule_version") == adj.RULE_VERSION, "E-RUN-RULE-VERSION", w,
            f"rule_version {run.get('rule_version')!r} is not the adjudicator's {adj.RULE_VERSION!r}")
    for vid in run.get("verdicts") or []:
        v = c.ix.first("verdict", verdict_id=vid)
        if v is not None:
            R.check(v.data.get("rule_version") == run.get("rule_version"), "E-RUN-RULE-VERSION", w,
                    f"verdict {vid} rule_version {v.data.get('rule_version')!r} != run rule_version {run.get('rule_version')!r}")
    R.check((run.get("cmd2_rounds") or 0) <= MAX_EXTRA_DISPATCH_ROUNDS, "E-PLAN-ROUNDS", w,
            f"cmd2_rounds {run.get('cmd2_rounds')} exceeds max_extra_dispatch_rounds {MAX_EXTRA_DISPATCH_ROUNDS}")
    base = run.get("baseline_run_id")
    if base is not None:
        R.check(base in c.runs and base != rid, "E-CLUSTER-BASELINE", w, f"baseline_run_id {base!r} is not another run of the bundle")
    # E6: slices of this run use one of its prompt templates and its redaction map
    shas = {t.get("sha256") for t in run.get("prompt_templates") or []}
    for s in c.docs("slice"):
        if s.data.get("run_id") != rid:
            continue
        R.check(s.data.get("prompt_template_sha256") in shas, "E-SLICE-IDENTITY", s.path,
                "prompt_template_sha256 is not one of the run's prompt_templates")
        if run.get("redaction_map_ref") is not None:
            R.check(s.data.get("redaction_map_sha256") == run.get("redaction_map_ref"), "E-SLICE-IDENTITY", s.path,
                    "redaction_map_sha256 != run.redaction_map_ref")


def evidence_digest(c: Ctx, cluster: dict) -> list[str]:
    """B9: hashes of the member evidence (snippet hash, or JCS of the fact) used to tell unchanged from updated."""
    out = []
    for fid in cluster.get("member_finding_ids") or []:
        f = c.ix.finding(fid) or {}
        for e in f.get("evidence") or []:
            if not isinstance(e, dict):
                continue
            out.append(e.get("snippet_sha256") or content_hash({k: e.get(k) for k in ("kind", "file", "fact_ref", "key_path", "asserted")}))
    return sorted(out)


def derived_baseline_state(c: Ctx, cluster: dict) -> str | None:
    """B9 (SARIF 2.1.0 baselineState): None without a baseline run; new = fingerprint not in the baseline run;
    unchanged = same fingerprint and member evidence; updated = same fingerprint, evidence changed."""
    base = (c.runs.get(cluster.get("run_id")) or {}).get("baseline_run_id")
    if base is None:
        return None
    fp = derive.cluster_fingerprint(cluster)
    old = [k.data for k in c.docs("cluster") if k.data.get("run_id") == base and derive.cluster_fingerprint(k.data) == fp]
    if not old:
        return "new"
    return "unchanged" if any(evidence_digest(c, o) == evidence_digest(c, cluster) for o in old) else "updated"


def baseline_checks(R: Report, c: Ctx):
    for d in c.docs("cluster"):
        k = d.data
        want = derived_baseline_state(c, k)
        R.check(k.get("baseline_state") == want, "E-CLUSTER-BASELINE", d.path,
                f"baseline_state {k.get('baseline_state')!r} != derived {want!r} (run baseline_run_id / fingerprints)")
        R.check(not k.get("reopened") or k.get("baseline_state") == "new", "E-CLUSTER-BASELINE", d.path, "reopened only on a new cluster")
    for d in c.docs("report-manifest"):
        run = c.runs.get(d.data.get("run_id")) or {}
        base = run.get("baseline_run_id")
        cur = {derive.cluster_fingerprint(k.data) for k in c.docs("cluster") if k.data.get("run_id") == run.get("run_id")}
        old = {derive.cluster_fingerprint(k.data) for k in c.docs("cluster") if base is not None and k.data.get("run_id") == base}
        want = sorted(old - cur)
        R.check(sorted(d.data.get("absent_fingerprints") or []) == want, "E-CLUSTER-BASELINE", d.path,
                f"absent_fingerprints must be the baseline run's fingerprints missing from this run: {want}")


def plan_checks(R: Report, c: Ctx, d: Doc):
    """B10 / D16: typed extra-dispatch targets, round bound, agents with matching roles, budget within the run budget."""
    p, w = d.data, d.path
    patterns = {"cluster": r"^K-[0-9]{3,}$", "slice": r"^sha256:[0-9a-f]{64}$", "threat": r"^T-[0-9]{3,}$"}
    for i, x in enumerate(p.get("extra_dispatch") or []):
        t = x.get("target") or {}
        ok = isinstance(t, dict) and isinstance(t.get("id"), str) and re.match(patterns.get(t.get("kind"), r"(?!)"), t.get("id")) is not None
        found = ok and {"cluster": lambda i_: c.ix.first("cluster", cluster_id=i_), "slice": lambda i_: c.ix.first("slice", slice_id=i_),
                        "threat": lambda i_: c.ix.first("threat", threat_id=i_)}[t["kind"]](t["id"]) is not None
        R.check(ok and found, "E-PLAN-TARGET", w, f"extra_dispatch[{i}].target {t} is not an existing {t.get('kind') if isinstance(t, dict) else '?'}")
        for a in x.get("agents") or []:
            R.check((c.agents.get(a) or {}).get("role") in ("reviewer", "verifier"), "E-PLAN-AGENTS", w,
                    f"extra_dispatch[{i}] agent {a!r} is not an agents.yaml reviewer / verifier")
    R.check(isinstance(p.get("round"), int) and 1 <= p["round"] <= MAX_EXTRA_DISPATCH_ROUNDS, "E-PLAN-ROUNDS", w,
            f"round {p.get('round')} must be 1..{MAX_EXTRA_DISPATCH_ROUNDS} (max_extra_dispatch_rounds)")
    for i, s in enumerate(p.get("slices") or []):
        for a in s.get("agents") or []:
            R.check((c.agents.get(a) or {}).get("role") == "reviewer", "E-PLAN-AGENTS", w, f"slices[{i}] agent {a!r} is not an agents.yaml reviewer")
    phase = {"CMD-1": "W", "CMD-2": "W", "CMD-3": "B", "CMD-4": "B", "CMD-5": "run_total"}.get(p.get("decision_node"))
    for rid, run in c.runs.items():
        if p.get("plan_id") in run.get("plan_ids", []) and phase:
            cap = ((run.get("budgets") or {}).get(phase) or {}).get("max_input_tokens")
            R.check(cap is not None and (p.get("budget_tokens") or 0) <= cap, "E-PLAN-BUDGET", w,
                    f"budget_tokens {p.get('budget_tokens')} exceeds {rid} budgets.{phase}.max_input_tokens {cap}")


# ============================================================== 12 testcases vs ROE
def g_testcases(R: Report, c: Ctx):
    r = c.roe
    if not r:
        return
    keys = set((c.manifest.get("seeds") or {}).keys())
    oq = c.manifest.get("oracle_queries") or {}
    roe_roles = {x.get("role") for x in r.get("test_roles", [])}
    oracle_tables = set((r.get("db_access") or {}).get("oracle_tables", []))
    rl = r.get("rate_limits") or {}
    for d in c.docs("testcase"):
        tc, w = d.data, d.path
        ref = tc.get("seed_manifest_ref")
        mk = c.manifest if ref and ref == c.manifest.get("manifest_ref") else None
        R.check(ref is None or ref == (r.get("db_access") or {}).get("seed_manifest_ref"), "E-TC-SEEDS", w, "seed_manifest_ref must be the ROE's seed manifest")
        try:
            level, trace = safety.compute_safety_class(tc, r, c.tools, mk)
        except (KeyError, TypeError) as exc:
            R.error("E-TC-SAFETY", w, f"cannot compute safety class: missing {exc}")
            continue
        R.check(tc.get("safety_class_computed") == level, "E-TC-SAFETY", w,
                f"safety_class_computed {tc.get('safety_class_computed')} != algorithm {level} ({'; '.join(trace)})")
        prop = tc.get("safety_class_proposed") or "S0"
        R.check(safety.ORDER.index(level) >= safety.ORDER.index(prop), "E-TC-SAFETY", w, "computed class below the LLM proposal")
        R.check(safety.admissible(level, r), "E-TC-ADMISSIBLE", w, f"class {level} cannot enter G4 ({'; '.join(trace)})")
        scope = safety.mutation_scope_problems(tc, mk)
        R.check(not scope, "E-TC-MUTATION-SCOPE", w, "every mutation must be seed-bound or a create in the run namespace (B6): "
                + "; ".join(scope))
        dn = tc.get("data_needed") or {}
        R.check(set(dn.get("roles", [])) <= roe_roles, "E-TC-ROLES", w, f"roles not in ROE test_roles: {sorted(set(dn.get('roles', [])) - roe_roles)}")
        R.check(set(dn.get("db_tables", [])) <= oracle_tables, "E-TC-DB", w, f"db_tables not in ROE oracle_tables: {sorted(set(dn.get('db_tables', [])) - oracle_tables)}")
        R.check(set(dn.get("seed_data", [])) <= keys, "E-TC-SEEDS", w, f"seeds not in the manifest: {sorted(set(dn.get('seed_data', [])) - keys)}")
        for req in tc.get("request_allowlist", []):
            for k in safety.seed_keys(req.get("path", "")):
                R.check(k in keys, "E-TC-SEEDS", w, f"{req.get('path')}: seed {k!r} not in the manifest")
        o = tc.get("oracle") or {}
        if o.get("oracle_query_id"):
            q = oq.get(o["oracle_query_id"])
            if R.check(q is not None, "E-TC-ORACLE", w, f"oracle query {o['oracle_query_id']} not in the seed manifest"):
                R.check(q.get("table") in set(dn.get("db_tables", [])), "E-TC-DB", w, f"oracle query table {q.get('table')} not in data_needed.db_tables")
        R.check(set(o.get("requirement_refs", [])) <= set(tc.get("requirement_ids", [])), "E-TC-ORACLE", w, "oracle.requirement_refs not in requirement_ids")
        tb = tc.get("tool_binding") or {}
        if str(tb.get("adapter", "")).startswith("zap:"):
            p = tb.get("params") or {}
            R.check(isinstance(p.get("delayInMs"), int) and p["delayInMs"] >= rl.get("zap_delay_ms_min", 0), "E-TC-ZAP", w,
                    f"delayInMs must be >= ROE zap_delay_ms_min {rl.get('zap_delay_ms_min')}")
            th = p.get("threadPerHost")
            R.check(th is None or (isinstance(th, int) and 1 <= th <= rl.get("max_concurrency", 0)), "E-TC-ZAP-THREADS", w,
                    f"threadPerHost {th} must be 1..ROE rate_limits.max_concurrency {rl.get('max_concurrency')}")
            if tb.get("adapter") == "zap:active":
                mx = p.get("maxScanDurationInMins")
                R.check(isinstance(mx, int) and 0 < mx <= rl.get("zap_max_scan_minutes", 0), "E-TC-ZAP", w,
                        f"maxScanDurationInMins must be 1..{rl.get('zap_max_scan_minutes')} (0 = unlimited is not allowed)")
        tr = tc.get("trials") or {}
        if tc.get("multi_turn"):
            relay = r.get("relay") or {}
            R.check(bool(relay.get("models")), "E-TC-RELAY", w, "multi_turn needs a ROE relay")
            R.check(tr.get("multi_turn_max_turns") is not None and tr["multi_turn_max_turns"] <= relay.get("max_turns", 0), "E-TC-RELAY", w,
                    "multi_turn_max_turns exceeds ROE relay.max_turns")
            st = tc.get("script_turns")
            if relay.get("mode") == "scripted":
                R.check(isinstance(st, list) and 1 <= len(st) <= min(tr.get("multi_turn_max_turns") or 0, relay.get("max_turns", 0)),
                        "E-TC-SCRIPT", w, "relay mode scripted: script_turns must list 1..multi_turn_max_turns (<= ROE relay.max_turns) fixed user turns")
        else:
            R.check(tr.get("multi_turn_max_turns") is None, "E-TC-RELAY", w, "multi_turn_max_turns only for multi_turn testcases")
            R.check(tc.get("script_turns") is None, "E-TC-SCRIPT", w, "script_turns only for multi_turn testcases")
        if profile(c) == "lite" and tb.get("kind") != "MANUAL":
            R.check(level in ("S0", "S1"), "E-PROFILE-SAFETY", w, f"assurance_profile lite allows only S0/S1 toolkit-executed testcases, got {level}")
        approved = c.ix.approved_requirement_ids()
        refs = set(tc.get("requirement_ids") or []) | set(o.get("requirement_refs") or [])
        R.check(refs <= approved, "E-TC-REQ-UNAPPROVED", w,
                f"requirements {sorted(refs - approved)} are not approved at G1 (REJECTED / NEEDS_INFO requirements are not testable)")
        R.check(1 <= tr.get("fail_k_min", 1) <= tr.get("n", 1), "E-TC-TRIALS", w, "fail_k_min must be 1..n")
        ctls = [x for x in tc.get("controls") or [] if isinstance(x, dict)]
        R.check(any(x.get("kind") == "reachability" for x in ctls), "E-TC-CONTROLS", w,
                "a testcase needs at least one reachability control (B5)")
        ids = [x.get("control_id") for x in ctls]
        R.check(len(ids) == len(set(ids)), "E-TC-CONTROLS", w, f"duplicate control_id in {ids}")
        R.check(tb.get("adapter") == "manual" or safety.registry_entry(c.tools, tb.get("adapter", "")) is not None, "E-TC-TOOL", w,
                f"adapter {tb.get('adapter')} not registered")


# ============================================================== 13 verdicts
PRE_G3_PHASES = ("W3_adjudicate", "W4_readjudicate")


def g3_rejected(c: Ctx, v: dict, cluster: dict) -> bool:
    """R13: the cluster's seed threat(s) were rejected in a G3 gate record of the cluster's run.

    Derived from the G3 GateRecord decisions (not from threat.review), for every verdict produced
    after G3, i.e. any verdict that is not a W-phase (pre-G3) verdict. For each threat the latest
    G3 record that decides it counts; the cluster is g3_rejected when all its threats are rejected.
    """
    if v.get("readjudicated_by") in PRE_G3_PHASES:
        return False
    k = cluster.get("cluster_id")
    tids = {t.data.get("threat_id") for t in c.docs("threat") if t.data.get("source_cluster_id") == k}
    tids |= {s.get("threat_id") for d in c.docs("seed-threats") for s in d.data.get("seeds", [])
             if s.get("source_cluster_id") == k and s.get("threat_id")}
    if not tids:
        return False
    recs = [x.data for x in c.ix.gate_records(cluster.get("run_id"), "G3")]  # timestamp order
    last = {}
    for rec in recs:
        for x in rec.get("decisions", []):
            if x.get("item_id") in tids:
                last[x.get("item_id")] = x.get("decision")
    return all(last.get(t) == "reject" for t in tids)


def g2_latest(c: Ctx, cluster: dict) -> tuple[dict | None, str | None]:
    """R10: the latest G2 gate record of the cluster's run that decides the cluster, and its decision.

    Derived from all G2 GateRecords of the run (not from the verdict's own g2_decision_ref), so a
    verdict cannot escape R10 by omitting or pointing at an older G2 record.
    """
    k = cluster.get("cluster_id")
    rec = dec = None
    for x in c.ix.gate_records(cluster.get("run_id"), "G2"):  # timestamp order
        for d in x.data.get("decisions", []):
            if d.get("item_id") == k:
                rec, dec = x.data, d.get("decision")
    return rec, dec


def vote_model(c: Ctx, vt: dict) -> dict | None:
    """models.yaml entry that cast a vote, resolved through the registries (never the vote's own
    voter_family): voter_agent_id -> agents.yaml model; voter_model_key must be that model, or,
    when fallback_used names it, one of that model's (same-family) models.yaml fallbacks.
    None when the vote does not resolve consistently."""
    a = c.agents.get(vt.get("voter_agent_id")) if isinstance(vt.get("voter_agent_id"), str) else None
    if not isinstance(a, dict) or not a.get("model") or c.model(a.get("model")) is None:
        return None
    key = vt.get("voter_model_key")
    if key == a["model"] and vt.get("fallback_used") in (None, key):
        return c.model(key)
    if vt.get("fallback_used") == key and key in (c.model(a["model"]).get("fallback") or []):
        return c.model(key)
    return None


def eligible_verifier_models(c: Ctx, cluster: dict) -> dict[str, dict]:
    """model key -> models.yaml entry of every agents.yaml `verifier` whose registry family is not in
    cluster.families and whose registry lineage is not in cluster.lineages (never self-declared)."""
    fams, lins = set(cluster.get("families") or []), set(cluster.get("lineages") or [])
    out = {}
    for a in (c.agents or {}).values():
        if not isinstance(a, dict) or a.get("role") != "verifier":
            continue
        m = c.model(a.get("model"))
        if m and m.get("family") not in fams and m.get("lineage") not in lins and isinstance(m.get("family"), str):
            out[a.get("model")] = m
    return out


def eligible_verifier_families(c: Ctx, cluster: dict) -> set[str]:
    """E(cluster) (docs/05 §3, v0.3): the registry families of eligible_verifier_models."""
    return {m.get("family") for m in eligible_verifier_models(c, cluster).values()}


def derived_no_eligible_verifier(c: Ctx, cluster: dict) -> bool:
    return not eligible_verifier_families(c, cluster)


def derived_diversity_degraded(c: Ctx, v: dict, cluster: dict) -> bool:
    """docs/05 §3 rule 3 / §4.2 [H] (v0.3, N-1): derived, never taken from the verdict itself.

    diversity_degraded = not Lane A, and E(cluster) is non-empty, and the number of distinct families
    among the WEIGHTED-valid verifier votes is below min(2, |E|). A vote's family comes from the
    registries (vote_model: voter_agent_id -> agents.yaml model -> models.yaml family). A 2-family cluster
    has |E| = 1, so one weighted vote of the third family is full diversity (v0.2 capped every such
    cluster). No eligible verifier at all is `no_eligible_verifier`, not degraded diversity.
    """
    run = c.runs.get(cluster.get("run_id")) or {}
    if run.get("run_kind") == "lane_a":
        return False
    e = eligible_verifier_families(c, cluster)
    if not e:
        return False
    fams = set()
    for x in v.get("votes", []):
        m = vote_model(c, x)
        # only verifier-role votes count (others: E-VERDICT-VOTER-ROLE, ignored)
        if x.get("weighted_valid") and m is not None and derive.is_verifier_vote(c.ix, x):
            fams.add(m.get("family"))
    return len(fams) < min(2, len(e))


def derived_provisional(c: Ctx, v: dict, cluster: dict) -> bool:
    """E5 (H-E11): calibration_version null, or theta_confirm null, or every eligible verifier model of the
    cluster (E(cluster), from the registries, not from the votes present) has calibration weight 0 in the
    cluster's CWE bucket. A verdict without votes is therefore provisional iff the pool is uncalibrated."""
    if v.get("calibration_version") is None or v.get("theta_confirm") is None:
        return True
    return all(c.ix.weight(k, cluster.get("cwe_bucket"), v.get("calibration_version")) == 0
               for k in eligible_verifier_models(c, cluster))


LICENSE_CLEARED = ("OK", "注意")     # licenses.yaml statuses that may run; 法務閘門 / 不採用 / 待查 / 參考 may not (N-7)


def license_status(c: Ctx, tool: str) -> str | None:
    ref = ((c.tools.get("tools") or {}).get(tool) or {}).get("license_ref")
    return next((x.get("status") for x in c.licenses.get("components") or [] if isinstance(x, dict) and x.get("component") == ref), None)


def _resolving_event(c: Ctx, cluster: dict, ref) -> tuple[dict | None, str | None]:
    """(tool_invocation_end event that backs a cluster.sarif_refs entry, None) or (None, problem)."""
    rid = cluster.get("run_id")
    audit = c.ix.audit_for(rid)
    if audit is None:
        return None, f"run {rid!r} has no (loadable) audit log, so SARIF ref {ref} cannot be resolved"
    ends = [e for e in audit.data if isinstance(e, dict) and e.get("event_type") == "tool_invocation_end"
            and ref in (e.get("payload_refs") or [])]
    if not ends:
        return None, f"SARIF ref {ref} is not in payload_refs of any tool_invocation_end event of run {rid}"
    reasons = []
    for e in ends:
        p = e.get("payload") or {}
        adapter = p.get("adapter")
        entry = safety.registry_entry(c.tools, adapter)
        tool_spec = ((c.tools.get("tools") or {}).get(entry["tool"]) or {}) if entry else {}
        status = license_status(c, entry["tool"]) if entry else None
        if entry is None:
            reasons.append(f"seq {e.get('seq')}: adapter {adapter!r} is not a registered tools.yaml tool:mode")
        elif tool_spec.get("zone") != "Z2" or entry.get("b4_executable") is not False:
            reasons.append(f"seq {e.get('seq')}: {adapter} is not a white-box/static tool (zone Z2, b4_executable false)")
        elif status not in LICENSE_CLEARED:
            reasons.append(f"seq {e.get('seq')}: {adapter} is not legally cleared (licenses.yaml {tool_spec.get('license_ref')!r} "
                           f"status {status!r}; only {'/'.join(LICENSE_CLEARED)} may run)")
        elif e.get("zone") != "Z2":
            reasons.append(f"seq {e.get('seq')}: event zone {e.get('zone')!r} is not Z2")
        elif p.get("ok") is not True:
            reasons.append(f"seq {e.get('seq')}: invocation of {adapter} failed (payload.ok is not true)")
        else:
            return e, None
    return None, f"SARIF ref {ref}: " + "; ".join(reasons)


def sarif_ref_problem(c: Ctx, cluster: dict, ref) -> str | None:
    """E-SARIF-REF: why a cluster.sarif_refs entry is not backed by the audit log (None = resolved).

    A SARIF ref counts only when the audit log of the cluster's run has a `tool_invocation_end`
    event that lists the ref in payload_refs, whose payload.adapter is a tools.yaml tool:mode of a
    white-box tool (tool zone Z2, mode b4_executable false) whose licenses.yaml status is cleared
    (OK / 注意; not 法務閘門, N-7), with event zone Z2 and payload.ok true.
    """
    return _resolving_event(c, cluster, ref)[1]


def resolved_sarif_refs(c: Ctx, cluster: dict) -> list[str]:
    return sorted({r for r in cluster.get("sarif_refs") or [] if sarif_ref_problem(c, cluster, r) is None})


def sarif_rule(c: Ctx, cluster: dict, ref) -> tuple[str | None, str | None]:
    """(adapter, rule_id) of a resolved SARIF ref: payload.adapter and the payload.sarif_results entry for the ref."""
    e, _ = _resolving_event(c, cluster, ref)
    if e is None:
        return None, None
    p = e.get("payload") or {}
    rule = next((x.get("rule_id") for x in p.get("sarif_results") or [] if isinstance(x, dict) and x.get("ref") == ref), None)
    return p.get("adapter"), rule


HIGH_PRECISION_MIN_DEFAULT = 0.9


def high_precision_min(c: Ctx) -> float:
    """calibration.yaml result.thresholds.high_precision_min.value (default 0.90; null = disabled: nothing is strong)."""
    th = ((c.calibration.get("result") or {}).get("thresholds") or {}).get("high_precision_min")
    if not isinstance(th, dict):
        return HIGH_PRECISION_MIN_DEFAULT
    v = th.get("value")
    if v is None:
        return float("inf")
    return v if isinstance(v, (int, float)) and not isinstance(v, bool) else HIGH_PRECISION_MIN_DEFAULT


def sarif_is_strong(c: Ctx, cluster: dict, ref) -> bool:
    """H-A1: STRONG iff (adapter, rule_id, tool_version) of the resolving audit event is a calibration.yaml
    result.high_precision_rules entry for the cluster's CWE bucket with precision_lower95 >= high_precision_min.
    A scanner or rule-pack version other than the calibrated one is WEAK."""
    e, _ = _resolving_event(c, cluster, ref)
    adapter, rule = sarif_rule(c, cluster, ref)
    if e is None or adapter is None or rule is None:
        return False
    version = (e.get("payload") or {}).get("tool_version")
    lim = high_precision_min(c)
    return any(isinstance(h, dict) and h.get("adapter") == adapter and h.get("rule_id") == rule and h.get("tool_version") == version
               and h.get("cwe_bucket") == cluster.get("cwe_bucket") and (h.get("precision_lower95") or 0) >= lim
               for h in (c.calibration.get("result") or {}).get("high_precision_rules") or [])


def strong_sarif_refs(c: Ctx, cluster: dict) -> list[str]:
    return [r for r in resolved_sarif_refs(c, cluster) if sarif_is_strong(c, cluster, r)]


def weak_sarif_refs(c: Ctx, cluster: dict) -> list[str]:
    return [r for r in resolved_sarif_refs(c, cluster) if not sarif_is_strong(c, cluster, r)]


def e_fail_u_refs(v: dict) -> set[str]:
    return {x.get("result_ref") for x in (v.get("test_evidence") or {}).get("results", [])
            if isinstance(x, dict) and x.get("class") == "E_fail_u" and x.get("result_ref")}


def derived_tool_corroboration(c: Ctx, v: dict, cluster: dict) -> list[str]:
    """R2 (v0.3): STRONG tool corroboration only = resolved cluster.sarif_refs (E-SARIF-REF) whose
    (adapter, rule_id) is a calibrated high-precision rule for the cluster's bucket. Sorted; compared
    as a sorted list with the verdict's own list."""
    return sorted(strong_sarif_refs(c, cluster))


def derived_tool_signal(c: Ctx, v: dict, cluster: dict) -> list[str]:
    """R2 (v0.3): WEAK tool signals = the other resolved SARIF refs + result_refs of E_fail_u results."""
    return sorted(set(weak_sarif_refs(c, cluster)) | e_fail_u_refs(v))


def derived_independent_sources(c: Ctx, v: dict, cluster: dict) -> int:
    return (len(derive.independent_families(c.ix, cluster)) + (1 if weak_sarif_refs(c, cluster) else 0)
            + (1 if e_fail_u_refs(v) else 0))


def all_evidence_not_found(c: Ctx, cluster: dict) -> bool:
    """R0 (v0.3): every evidence item of every member finding is NOT_FOUND; False when there are no members."""
    members = [c.ix.finding(f) for f in cluster.get("member_finding_ids") or []]
    if not members or any(m is None for m in members):
        return False
    items = [e for m in members for e in m.get("evidence") or [] if isinstance(e, dict)]
    return bool(items) and all(e.get("match") == "NOT_FOUND" for e in items)


def verdict_inputs(c: Ctx, v: dict, cluster: dict) -> adj.Inputs:
    run = c.runs.get(cluster.get("run_id")) or {}
    g2_rej = g2_latest(c, cluster)[1] == "reject"
    all_fail = all_evidence_not_found(c, cluster)      # R0 (v0.3): every evidence item NOT_FOUND; False without members
    votes = [x for x in v.get("votes", []) if x.get("weighted_valid") and derive.is_verifier_vote(c.ix, x)]
    g3_rej = g3_rejected(c, v, cluster)
    prev = c.ix.first("verdict", verdict_id=v["supersedes_verdict_id"]) if v.get("supersedes_verdict_id") else None
    return adj.Inputs(
        lane_a=run.get("run_kind") == "lane_a",
        g2_rejected=g2_rej,
        all_snippets_fail=all_fail,
        evidence={x.get("class") for x in (v.get("test_evidence") or {}).get("results", [])},
        weighted_support=any(x.get("stance") == "SUPPORT" for x in votes),
        weighted_refute=any(x.get("stance") == "REFUTE" for x in votes),
        score=v.get("score") or 0.0,
        # audit-backed refs only (E-SARIF-REF), tiered by calibration (H-A1); never v.tool_corroboration / v.tool_signal
        strong_tool=bool(strong_sarif_refs(c, cluster)),
        weak_sarif=bool(weak_sarif_refs(c, cluster)),
        theta_confirm=v.get("theta_confirm"),
        theta_reject=v.get("theta_reject"),
        independent_families=len(derive.independent_families(c.ix, cluster)),   # recomputed (D14), not cluster.independent_families
        diversity_degraded=derived_diversity_degraded(c, v, cluster),   # derived, not self-declared
        g3_rejected=g3_rej,
        phase={"W3_adjudicate": "W3", "W4_readjudicate": "W4", "B5_readjudicate": "B5"}.get(v.get("readjudicated_by")),
        prev_status=prev.data.get("status") if prev else None,
    )


def g_verdicts(R: Report, c: Ctx):
    for d in c.docs("cluster"):
        for ref in d.data.get("sarif_refs") or []:
            prob = sarif_ref_problem(c, d.data, ref)
            R.check(prob is None, "E-SARIF-REF", d.path, f"{d.data.get('cluster_id')}: {prob}")
    for d in c.docs("verdict"):
        v, w = d.data, d.path
        cl = c.ix.first("cluster", cluster_id=v.get("cluster_id"))
        if not R.check(cl is not None, "E-TRACE", w, f"cluster {v.get('cluster_id')} not found"):
            continue
        # self-declared rule inputs are cross-checked against the derived values (docs/05 §4.2) [H]
        dd = derived_diversity_degraded(c, v, cl.data)
        R.check(v.get("diversity_degraded") is dd, "E-VERDICT-DIVERSITY", w,
                f"diversity_degraded {v.get('diversity_degraded')} but the weighted-valid votes' registry families give {dd} "
                f"(eligible verifier families {sorted(eligible_verifier_families(c, cl.data))})")
        ne = derived_no_eligible_verifier(c, cl.data)
        R.check(v.get("no_eligible_verifier") is ne, "E-VERDICT-NOELIGIBLE", w,
                f"no_eligible_verifier {v.get('no_eligible_verifier')} but agents.yaml verifiers outside the cluster's families/lineages give {ne}")
        tcx = derived_tool_corroboration(c, v, cl.data)
        R.check(sorted(v.get("tool_corroboration") or []) == tcx, "E-VERDICT-TOOLCORR", w,
                f"tool_corroboration {v.get('tool_corroboration')} != derived {tcx} (audit-backed SARIF refs of calibrated high-precision rules)")
        tsx = derived_tool_signal(c, v, cl.data)
        R.check(sorted(v.get("tool_signal") or []) == tsx, "E-VERDICT-TOOLSIGNAL", w,
                f"tool_signal {v.get('tool_signal')} != derived {tsx} (other audit-backed SARIF refs + E_fail_u results)")
        srcx = derived_independent_sources(c, v, cl.data)
        R.check(v.get("independent_sources") == srcx, "E-VERDICT-SOURCES", w,
                f"independent_sources {v.get('independent_sources')} != derived {srcx} (independent families + weak SARIF + E_fail_u)")
        pv = derived_provisional(c, v, cl.data)
        R.check(v.get("provisional") is pv, "E-VERDICT-PROVISIONAL", w,
                f"provisional {v.get('provisional')} != derived {pv} (no calibration version, theta_confirm null, or every eligible "
                "verifier model has weight 0 in the cluster's bucket)")
        R.check(v.get("rule_version") == adj.RULE_VERSION, "E-VERDICT-RULE-VERSION", w,
                f"rule_version {v.get('rule_version')!r} is not the adjudicator's {adj.RULE_VERSION!r}")
        out = adj.adjudicate(verdict_inputs(c, v, cl.data))
        R.check(v.get("status") == out.status, "E-VERDICT-STATUS", w, f"status {v.get('status')} but the rules give {out.status} (row {out.row})")
        R.check(v.get("status_cap") == out.status_cap, "E-VERDICT-STATUS", w, f"status_cap {v.get('status_cap')} != {out.status_cap}")
        R.check(v.get("advisory") is out.advisory, "E-VERDICT-STATUS", w, f"advisory {v.get('advisory')} != {out.advisory}")
        kinds = {a.get("kind") for a in v.get("annotations", [])}
        R.check(kinds == out.annotations, "E-VERDICT-ANNOTATIONS", w, f"annotations {sorted(kinds)} != {sorted(out.annotations)}")
        rules = [str(x).split(":", 1)[0] for x in v.get("rule_trace", [])]
        R.check(rules == out.rules, "E-VERDICT-TRACE", w, f"rule_trace rules {rules} != {out.rules}")
        if v.get("status") == "CONFIRMED_EXECUTABLE":
            p = v.get("executable_proof") or {}
            ib = p.get("interpretation_confirmed_by")
            # a pre-registered deterministic interpretation needs no analyst (v0.3); an analyst, if any, is cross-family
            R.check(ib is None or (isinstance(ib, dict) and ib.get("family") not in cl.data.get("families", [])), "E-VERDICT-PROOF", w,
                    "executable proof interpretation must come from another family")
        for vt in v.get("votes", []):
            a = c.agents.get(vt.get("voter_agent_id")) if isinstance(vt.get("voter_agent_id"), str) else None
            R.check(derive.is_verifier_vote(c.ix, vt), "E-VERDICT-VOTER-ROLE", w,
                    f"vote by {vt.get('voter_agent_id')!r} (agents.yaml role {(a or {}).get('role')!r}): only verifier-role agents "
                    "may vote; the vote is ignored for weighted_valid, score, support/refute and diversity")
            m = vote_model(c, vt)
            if R.check(m is not None, "E-VERDICT-VOTE", w,
                       f"vote by {vt.get('voter_agent_id')!r} with model {vt.get('voter_model_key')!r} does not resolve through agents.yaml / models.yaml"):
                R.check(vt.get("voter_family") == m.get("family") and vt.get("voter_lineage") == m.get("lineage"), "E-VERDICT-VOTE", w,
                        f"vote by {vt.get('voter_agent_id')}: voter_family/lineage {vt.get('voter_family')}/{vt.get('voter_lineage')} "
                        f"!= registry {m.get('family')}/{m.get('lineage')}")
            if vt.get("valid"):
                R.check(vt.get("voter_family") not in cl.data.get("families", []) and vt.get("voter_lineage") not in cl.data.get("lineages", []),
                        "E-VERDICT-VOTE", w, f"self-review vote by {vt.get('voter_agent_id')} counted as valid")
        if v.get("supersedes_verdict_id"):
            old = c.ix.first("verdict", verdict_id=v["supersedes_verdict_id"])
            R.check(old is not None and old.data.get("cluster_id") == v.get("cluster_id"), "E-TRACE", w, "supersedes a verdict of another cluster")
        R.check(v.get("calibration_version") == c.calibration.get("calibration_version"), "E-VERDICT-CALIBRATION", w, "calibration_version differs")


# ============================================================== 14 traceability
def cluster_origin(R: Report, c: Ctx, d: Doc):
    """E-CLUSTER-ORIGIN (A2): white_box clusters need members, a source-code location and no threat_id;
    black_box clusters come from a threat without source cluster and use the endpoint as location."""
    k, w = d.data, d.path
    loc = k.get("canonical_location") or {}
    if k.get("origin") == "black_box":
        t = c.ix.first("threat", threat_id=k.get("threat_id")) if k.get("threat_id") else None
        R.check(t is not None and t.data.get("source_cluster_id") is None, "E-CLUSTER-ORIGIN", w,
                f"black_box cluster needs a threat_id of a threat without source_cluster_id (got {k.get('threat_id')!r})")
        R.check(isinstance(loc.get("endpoint"), dict), "E-CLUSTER-ORIGIN", w, "black_box cluster needs canonical_location.endpoint")
        ep = loc.get("endpoint") or {}
        tc_ok = any(t2.data.get("threat_id") == k.get("threat_id") and any(
            r.get("target_id") == ep.get("target_id") and r.get("method") == ep.get("method") and r.get("path") == ep.get("path_template")
            for r in t2.data.get("request_allowlist") or []) for t2 in c.docs("testcase"))
        R.check(tc_ok, "E-CLUSTER-ORIGIN", w, "canonical_location.endpoint must be a request of a testcase of the cluster's threat")
    else:
        R.check(bool(k.get("member_finding_ids")) and bool(k.get("families")) and bool(k.get("lineages")), "E-CLUSTER-ORIGIN", w,
                "white_box cluster needs member findings, families and lineages")
        R.check(k.get("threat_id") is None, "E-CLUSTER-ORIGIN", w, "threat_id is only set on black_box clusters")
        R.check(all(isinstance(loc.get(x), (str, dict)) for x in ("file", "symbol", "sink")), "E-CLUSTER-ORIGIN", w,
                "white_box cluster needs canonical_location file, symbol and sink")


def inventory_of_run(c: Ctx, run_id) -> dict | None:
    d = c.ix.first("inventory", run_id=run_id)
    return d.data if d else None


def finding_evidence(R: Report, c: Ctx, d: Doc):
    """B1: evidence kinds, inventory facts recomputed against the run's W0 inventory, status from matches."""
    f, w = d.data, d.path
    inv = inventory_of_run(c, f.get("run_id"))
    for i, ev in enumerate(f.get("evidence") or []):
        if not isinstance(ev, dict):
            continue
        probs = evidence.shape_problems(ev)
        R.check(not probs, "E-FINDING-EVIDENCE", w, f"evidence[{i}]: {'; '.join(probs)}")
        if ev.get("kind") == "inventory_fact":
            if not R.check(inv is not None and evidence.resolves(inv, ev.get("fact_ref")), "E-INVENTORY-REF", w,
                           f"evidence[{i}].fact_ref {ev.get('fact_ref')!r} does not resolve in the W0 inventory of {f.get('run_id')}"):
                continue
            want = evidence.match_fact(inv, ev)
            R.check(ev.get("match") == want, "E-FINDING-MATCH", w,
                    f"evidence[{i}].match {ev.get('match')} but the inventory fact gives {want}")
        if ev.get("kind") == "config_fact" and inv is not None:
            R.check(ev.get("file") in {x.get("path") for x in inv.get("files") or []}, "E-INVENTORY-REF", w,
                    f"evidence[{i}].file {ev.get('file')!r} is not an inventory file")
    want = evidence.finding_status(f.get("evidence") or [])
    R.check(f.get("status") == want, "E-FINDING-STATUS", w, f"status {f.get('status')} but the evidence matches give {want}")
    for k in c.docs("cluster"):
        if f.get("finding_id") in (k.data.get("member_finding_ids") or []):
            allowed = facets.FACET_BUCKETS.get(f.get("facet"), frozenset())
            R.check(k.data.get("cwe_bucket") in allowed, "E-FINDING-FACET", w,
                    f"facet {f.get('facet')} may produce buckets {sorted(allowed)}, but cluster {k.data.get('cluster_id')} is {k.data.get('cwe_bucket')}")


def inventory_checks(R: Report, c: Ctx):
    """B2: internal references of every W0 inventory (middleware refs, source files)."""
    for d in c.docs("inventory"):
        inv, w = d.data, d.path
        paths = {x.get("path") for x in inv.get("files") or [] if isinstance(x, dict)}
        mws = {m.get("middleware_id") for m in (inv.get("auth") or {}).get("middleware") or [] if isinstance(m, dict)}
        for e in inv.get("endpoints") or []:
            bad = sorted(set(e.get("middleware_refs") or []) - mws)
            R.check(not bad, "E-INVENTORY", w, f"endpoint {e.get('method')} {e.get('path')}: unknown middleware_refs {bad}")
        srcs = [("endpoint", e.get("file")) for e in inv.get("endpoints") or []]
        srcs += [("llm_integration", x.get("file")) for x in inv.get("llm_integrations") or []]
        srcs += [("middleware", m.get("file")) for m in (inv.get("auth") or {}).get("middleware") or []]
        db = inv.get("db") or {}
        for t in db.get("tables") or []:
            srcs.append((f"table {t.get('name')}", (t.get("source") or {}).get("file")))
            srcs += [(f"policy {p.get('name')}", (p.get("source") or {}).get("file")) for p in t.get("policies") or []]
        srcs += [(f"function {x.get('name')}", (x.get("source") or {}).get("file")) for x in db.get("functions") or []]
        srcs += [(f"bucket {x.get('name')}", (x.get("source") or {}).get("file")) for x in db.get("storage_buckets") or [] if x.get("source")]
        srcs += [(f"env {x.get('name')}", r.get("file")) for x in inv.get("env_vars") or [] for r in x.get("referenced_in") or []]
        for what, fpath in srcs:
            R.check(fpath in paths, "E-INVENTORY", w, f"{what}: source file {fpath!r} is not in files")
        ids = [t.get("table_id") for t in db.get("tables") or []]
        R.check(len(ids) == len(set(ids)), "E-INVENTORY", w, "duplicate table_id")
        for x in inv.get("env_vars") or []:
            want = str(x.get("name", "")).startswith(PUBLIC_ENV_PREFIXES)
            R.check(x.get("public_prefix") is want, "E-INVENTORY", w, f"env var {x.get('name')}: public_prefix must be {want}")


PUBLIC_ENV_PREFIXES = ("NEXT_PUBLIC_", "VITE_", "EXPO_PUBLIC_", "PUBLIC_")
LEVELS = {"L1": 1, "L2": 2, "L3": 3}


def requirement_level(c: Ctx, rid) -> tuple[str | None, str | None, int | None]:
    """(standard asvs|aisvs, number like 8.2.3, level) of a baseline ASVS/AISVS requirement, else (None, None, None)."""
    x = next((b for b in c.invariants.get("baseline") or [] if isinstance(b, dict) and b.get("requirement_id") == rid), None)
    if not x:
        return None, None, None
    std = {"asvs-5.0.0": "asvs", "aisvs-1.0": "aisvs"}.get(x.get("source"))
    return std, str(x.get("ref", "")).rsplit("-", 1)[-1], LEVELS.get(x.get("level"))


def level_covered(c: Ctx, std: str, number: str, level: int) -> bool:
    inv = c.invariants
    if ((inv.get("baseline_levels") or {}).get(std) or 0) >= level:
        return True
    for t in inv.get("level_triggers") or []:
        if not isinstance(t, dict) or t.get("standard") != std or (t.get("level") or 0) < level:
            continue
        if any(number == s or number.startswith(s + ".") for s in t.get("sections") or []):
            return True
    return False


def invariants_checks(R: Report, c: Ctx):
    """B3: level triggers cover every cited L2+ ASVS/AISVS requirement; llm_tools refer to data classes."""
    inv, w = c.invariants, "invariants.yaml"
    if not inv:
        return
    features = {f for i in inv.get("invariants") or [] for f in i.get("applies_to_features") or []}
    run_inv = inventory_of_run(c, inv.get("run_id")) or {}
    features |= set(run_inv.get("features") or [])
    for t in inv.get("level_triggers") or []:
        R.check(t.get("feature") in features, "E-INVARIANT-LEVEL", w,
                f"level trigger feature {t.get('feature')!r} is neither an invariant applies_to_features value nor a W0 inventory feature")
    cited = [(w, x.get("requirement_id")) for x in inv.get("baseline") or []]
    cited += [(d.path, r) for d in c.docs("testcase") for r in set(d.data.get("requirement_ids") or [])
              | set((d.data.get("oracle") or {}).get("requirement_refs") or [])]
    for where, rid in cited:
        std, number, level = requirement_level(c, rid)
        if std and level and level >= 2:
            R.check(level_covered(c, std, number, level), "E-INVARIANT-LEVEL", where,
                    f"{rid} is {std.upper()} L{level} but neither baseline_levels.{std} nor a level trigger covers section {number}")
    dcs = {x.get("data_class_id") for x in inv.get("data_classification") or []}
    for t in inv.get("llm_tools") or []:
        bad = sorted(set(t.get("data_class_ids") or []) - dcs)
        R.check(not bad, "E-INVARIANT-REF", w, f"llm_tools {t.get('tool_name')}: unknown data_class_ids {bad}")
    for a in inv.get("access_matrix") or []:
        o = a.get("ownership") or {}
        R.check((o.get("kind") == "none") == (o.get("field") is None), "E-INVARIANT-REF", w,
                f"access_matrix {a.get('role')}/{a.get('resource')}: ownership.field is required unless kind is none")


def plan_facets(R: Report, c: Ctx, d: Doc):
    """E7: every slice of a commander plan covers the MANDATORY_FACETS of the W0 inventory of each run listing the plan."""
    for rid, run in c.runs.items():
        if d.data.get("plan_id") not in run.get("plan_ids", []):
            continue
        inv = inventory_of_run(c, rid)
        if inv is None:
            continue
        need = facets.mandatory_facets(inv)
        for i, s in enumerate(d.data.get("slices") or []):
            miss = sorted(need - set(s.get("facets") or []))
            R.check(not miss, "E-PLAN-FACETS", d.path, f"slices[{i}] misses mandatory facets {miss} (W0 inventory of {rid})")


def g_trace(R: Report, c: Ctx):
    ix = c.ix
    inv_ids = {i.get("requirement_id") for i in c.invariants.get("invariants", [])}
    req_ids = inv_ids | {x.get("requirement_id") for x in c.invariants.get("baseline", [])}
    inventory_checks(R, c)
    invariants_checks(R, c)
    for d in c.docs("finding"):
        f, w = d.data, d.path
        run = c.runs.get(f.get("run_id")) or {}
        R.check(f.get("finding_id") in run.get("findings", []), "E-TRACE", w, "finding not listed by its run")
        R.check(ix.first("slice", slice_id=f.get("slice_id")) is not None, "E-TRACE", w, "slice not found")
        if run.get("run_kind") != "lane_a":
            R.check(set(f.get("invariant_refs", [])) <= inv_ids, "E-TRACE", w, "invariant_refs not in invariants.yaml")
        finding_evidence(R, c, d)
    for d in c.docs("cluster"):
        k, w = d.data, d.path
        run = c.runs.get(k.get("run_id")) or {}
        R.check(k.get("cluster_id") in run.get("cluster_ids", []), "E-TRACE", w, "cluster not listed by its run")
        cluster_origin(R, c, d)
        members = [ix.first("finding", finding_id=f) for f in k.get("member_finding_ids", [])]
        if R.check(all(members), "E-TRACE", w, "member finding not found"):
            fams = {(m.data.get("reporter") or {}).get("family") for m in members}
            lins = {(m.data.get("reporter") or {}).get("lineage") for m in members}
            R.check(set(k.get("families", [])) == fams and set(k.get("lineages", [])) == lins, "E-CLUSTER-FAMILIES", w,
                    "families/lineages must be those of the member findings' reporters")
            R.check(all(m.data.get("run_id") == k.get("run_id") for m in members), "E-TRACE", w, "member finding from another run")
        indep = derive.independent_families(ix, k)
        R.check(sorted(k.get("independent_families", [])) == indep, "E-CLUSTER-FAMILIES", w,
                f"independent_families {k.get('independent_families')} != {indep} (families of round-1 members reported by a reviewer)")
        fp = derive.cluster_fingerprint(k)
        R.check(k.get("fingerprint") == fp, "E-CLUSTER-FINGERPRINT", w, f"fingerprint {k.get('fingerprint')} != {fp} (sha256(JCS(fingerprint key)))")
    for d in c.docs("verdict"):
        v = d.data
        cl = ix.first("cluster", cluster_id=v.get("cluster_id"))
        run = c.runs.get(cl.data.get("run_id")) if cl else None
        R.check(run is not None and v.get("verdict_id") in run.get("verdicts", []), "E-TRACE", d.path, "verdict not listed by its cluster's run")
        if v.get("g2_decision_ref"):
            g2 = c.record(v["g2_decision_ref"])
            R.check(g2 is not None and g2.get("gate") == "G2" and any(x.get("item_id") == v.get("cluster_id") for x in g2.get("decisions", [])),
                    "E-TRACE", d.path, "g2_decision_ref must be a G2 record deciding this cluster")
        if cl:
            # R10 is derived from the run's G2 records (g2_latest); the reference must agree with them.
            latest = g2_latest(c, cl.data)[0]
            lid = latest.get("gate_record_id") if latest else None
            if v.get("g2_decision_ref"):
                R.check(v["g2_decision_ref"] == lid, "E-VERDICT-G2", d.path,
                        f"g2_decision_ref {v['g2_decision_ref']} is not the latest G2 record deciding this cluster ({lid})")
            elif v.get("readjudicated_by") != "W3_adjudicate":
                R.check(lid is None, "E-VERDICT-G2", d.path,
                        f"verdict after G2 must reference the G2 record {lid} that decided this cluster")
    for d in c.docs("threat"):
        t, w = d.data, d.path
        # D9: the review record must be a G3 record that decided this threat, and the status must be that decision
        rv = t.get("review") or {}
        if rv.get("gate_record_id") is not None:
            g3 = c.record(rv.get("gate_record_id"))
            dec = next((x.get("decision") for x in (g3 or {}).get("decisions") or [] if x.get("item_id") == t.get("threat_id")), None)
            want = {"accept": "ACCEPTED", "reject": "REJECTED", "needs_info": "NEEDS_INFO"}.get(dec)
            R.check(g3 is not None and g3.get("gate") == "G3" and dec is not None and rv.get("status") == want, "E-THREAT-REVIEW", w,
                    f"review {rv.get('status')} by {rv.get('gate_record_id')!r} must be the decision of a G3 record that decides "
                    f"{t.get('threat_id')} (found {dec!r})")
        else:
            R.check(rv.get("status") == "PENDING", "E-THREAT-REVIEW", w, "a threat without a G3 record must be PENDING")
        for ev in t.get("evidence") or []:
            kind, ref = ev.get("kind"), ev.get("ref")
            if kind == "cluster":
                R.check(isinstance(ref, str) and ref.startswith("K-") and ix.first("cluster", cluster_id=ref) is not None, "E-TRACE", w,
                        f"evidence cluster {ref!r} not found")
            elif kind == "finding":
                R.check(isinstance(ref, str) and ref.startswith("F-") and ix.first("finding", finding_id=ref) is not None, "E-TRACE", w,
                        f"evidence finding {ref!r} not found (cluster refs use kind cluster)")
            elif kind == "inventory":
                invs = [x.data for x in c.docs("inventory")]
                R.check(any(evidence.resolves(inv, ref) for inv in invs), "E-INVENTORY-REF", w,
                        f"inventory evidence {ref!r} is not a JSON Pointer that resolves in a W0 inventory")
        if t.get("source_cluster_id"):
            cl = ix.first("cluster", cluster_id=t["source_cluster_id"])
            if R.check(cl is not None, "E-TRACE", w, "source cluster not found"):
                R.check(set(t.get("source_finding_ids", [])) <= set(cl.data.get("member_finding_ids", [])), "E-TRACE", w, "source findings not in the cluster")
        bad = [l.get("target_id") for l in t.get("crosswalk", []) if l.get("provenance") == "llm-suggested"]
        R.check((t.get("review") or {}).get("status") != "ACCEPTED" or not bad, "E-THREAT-LLM-LINK", w, f"accepted threat has llm-suggested links {bad}")
        for l in t.get("crosswalk", []):
            if l.get("target_scheme") == "invariant":
                R.check(l.get("target_id") in inv_ids, "E-TRACE", w, f"invariant {l.get('target_id')} not in invariants.yaml")
            R.check((l.get("provenance") == "curated") == (l.get("reviewed_by") is not None), "E-XWALK-REVIEW", w,
                    f"{l.get('target_id')}: curated links need reviewed_by, llm-suggested links must not have it")
        for x in t.get("taxonomy", []):
            if str(x.get("scheme", "")).startswith("owasp-llm@"):
                runs = [r for r in c.runs.values() if r.get("run_kind") == "initial"]
                R.check(all(x["scheme"] == f"owasp-llm@{r.get('owasp_llm_version')}" for r in runs), "E-XWALK-OWASP", w,
                        f"{x['scheme']} differs from the run's owasp_llm_version")
        dfd = ix.first("dfd", viewpoint="merged")
        if dfd:
            els = {e.get("element_id"): e.get("type") for e in dfd.data.get("elements", [])}
            for el in t.get("dfd_elements", []):
                R.check(els.get(el.get("element_id")) == el.get("type"), "E-TRACE-DFD", w, f"DFD element {el.get('element_id')} missing or of another type")
    for d in c.docs("testcase"):
        tc, w = d.data, d.path
        th = ix.first("threat", threat_id=tc.get("threat_id"))
        if R.check(th is not None, "E-TRACE", w, f"threat {tc.get('threat_id')} not found"):
            R.check((th.data.get("review") or {}).get("status") == "ACCEPTED", "E-TRACE", w, "testcases only for threats accepted at G3")
        R.check(set(tc.get("requirement_ids", [])) <= req_ids, "E-TRACE", w, "requirement_ids not in invariants.yaml (invariants or baseline)")
        if tc.get("source_cluster_id"):
            R.check(ix.first("cluster", cluster_id=tc["source_cluster_id"]) is not None, "E-TRACE", w, "source cluster not found")
    for d in c.docs("testresult"):
        tr, w = d.data, d.path
        tcd = ix.first("testcase", testcase_id=tr.get("testcase_id"))
        R.check(tcd is not None, "E-TRACE", w, "testcase not found")
        th = ix.first("threat", threat_id=tcd.data.get("threat_id")) if tcd else None
        if th is not None:
            src = th.data.get("source_cluster_id")
            if src is None:
                # A2 (clarified): every result of a testcase whose threat has no source cluster is recorded on a
                # black_box cluster of that threat (created at B5 for FAIL, PASS and INVALID alike)
                bad = [k for k in tr.get("cluster_ids", []) if not ((ix.first("cluster", cluster_id=k) or Doc("", "", {})).data.get("origin") == "black_box"
                                                                   and (ix.first("cluster", cluster_id=k)).data.get("threat_id") == th.data.get("threat_id"))]
                R.check(bool(tr.get("cluster_ids")) and not bad, "E-CLUSTER-ORIGIN", w,
                        f"result of {tcd.data.get('testcase_id')} (threat {th.data.get('threat_id')} has no source cluster) must be recorded "
                        f"on black_box clusters of that threat (cluster_ids {tr.get('cluster_ids')})")
            else:
                R.check(src in tr.get("cluster_ids", []), "E-TRACE", w,
                        f"cluster_ids {tr.get('cluster_ids')} must include the threat's source cluster {src}")
        for k in tr.get("cluster_ids", []):
            R.check(ix.first("cluster", cluster_id=k, run_id=tr.get("run_id")) is not None or
                    any(k in (r.get("cluster_ids") or []) for r in c.runs.values()), "E-TRACE", w, f"cluster {k} not found")
    for d in c.docs("requirement"):
        q = d.data
        if q.get("source") == "invariant":
            inv = next((i for i in c.invariants.get("invariants", []) if i.get("requirement_id") == q.get("requirement_id")), None)
            R.check(inv == q, "E-TRACE-REQUIREMENT", d.path, "must be identical to the invariants.yaml item")
        else:
            base = next((x for x in c.invariants.get("baseline", []) if x.get("requirement_id") == q.get("requirement_id")), None)
            R.check(base is not None and all(base.get(k) == q.get(k) for k in ("source", "ref", "level")), "E-TRACE-REQUIREMENT", d.path,
                    "must match the invariants.yaml baseline entry")
    for d in c.docs("seed-threats"):
        for s in d.data.get("seeds", []):
            cl = ix.first("cluster", cluster_id=s.get("source_cluster_id"))
            v = ix.first("verdict", verdict_id=s.get("verdict_id"))
            th = ix.first("threat", threat_id=s.get("threat_id")) if s.get("threat_id") else True
            ok = cl is not None and v is not None and th is not None and v.data.get("cluster_id") == s.get("source_cluster_id") \
                and v.data.get("status") == s.get("cluster_status") and cl.data.get("cwe_bucket") == s.get("cwe_bucket")
            R.check(ok, "E-TRACE-SEED", d.path, f"{s.get('seed_id')}: cluster/verdict/threat/status/bucket do not match")
    baseline_checks(R, c)
    for d in c.docs("commander-plan"):
        plan_facets(R, c, d)
        plan_checks(R, c, d)
        for tid in d.data.get("testcase_ids", []):
            R.check(ix.first("testcase", testcase_id=tid) is not None, "E-TRACE", d.path, f"testcase {tid} not found")
        for fd in d.data.get("followup_drafts", []):
            for k in fd.get("cluster_ids", []):
                R.check(ix.first("cluster", cluster_id=k) is not None, "E-TRACE", d.path, f"cluster {k} not found")
    drafts = {fd.get("draft_id") for p in c.docs("commander-plan") for fd in p.data.get("followup_drafts", [])}
    for rid, run in c.runs.items():
        for fd in run.get("followup_drafts", []):
            R.check(fd in drafts, "E-TRACE", rid, f"follow-up draft {fd} not found")
        for pid in run.get("plan_ids", []):
            R.check(c.ix.first("commander-plan", plan_id=pid) is not None, "E-TRACE", rid, f"plan {pid} not found")


# ============================================================== 15 audit log
def g_audit(R: Report, c: Ctx):
    interval = (c.toolkit.get("audit") or {}).get("anchor_interval_events", 500)
    for d in c.ix.audit_docs():
        evs, w = d.data, d.path
        rid = evs[0].get("run_id") if evs else None
        run = c.runs.get(rid)
        if not R.check(run is not None, "E-AUDIT-RUN", w, f"run {rid} not found"):
            continue
        prev_t, since = None, 0
        for i, ev in enumerate(evs):
            where = f"{w} seq {ev.get('seq')}"
            # type(...) is int: a float literal such as 3e0 / 3.0 (or a bool) is not a seq
            R.check(type(ev.get("seq")) is int and ev.get("seq") == i + 1, "E-AUDIT-SEQ", where,
                    f"seq must be the integer {i + 1} (1, 2, 3, ...; float literals such as 3e0 are rejected), got {ev.get('seq')!r}")
            R.check(ev.get("run_id") == rid and ev.get("engagement_id") == c.engagement.get("engagement_id"), "E-AUDIT-RUN", where, "run/engagement mismatch")
            R.check(ev.get("data_class") == run.get("data_class"), "E-AUDIT-RUN", where, "data_class differs from the run")
            t = ts(R, ev.get("ts"), where)
            if t and prev_t:
                R.check(t >= prev_t, "E-AUDIT-TS", where, "timestamps must not go backwards")
            prev_t = t or prev_t
            actor = ev.get("actor") or {}
            if actor.get("kind") == "human":
                R.check(actor.get("id") in c.persons and actor.get("id") not in c.automation, "E-AUDIT-ACTOR", where, "human actor must be a registered person")
            et = ev.get("event_type")
            since = 0 if et == "audit_anchor" else since + 1
            R.check(since <= interval, "E-AUDIT-ANCHOR", where, f"more than {interval} events without an anchor")
            if et == "gate_decision":
                nxt = evs[i + 1] if i + 1 < len(evs) else {}
                R.check(nxt.get("event_type") == "audit_anchor", "E-AUDIT-ANCHOR", where, "every gate_decision must be followed by an audit_anchor")
                p = ev.get("payload") or {}
                rec = c.record(p.get("gate_record_id"))
                R.check(rec is not None and rec.get("gate") == p.get("gate") and rec.get("outcome") == p.get("outcome")
                        and ts(R, rec.get("timestamp"), where) == t, "E-AUDIT-GATE", where, "gate_decision does not match its gate record")
            if et == "initiator_claim":
                R.check(actor.get("id") in run.get("initiators", []), "E-AUDIT-INITIATOR", where, "claimed initiator not in run.initiators")
            if et == "verdict_changed":
                p = ev.get("payload") or {}
                v = c.ix.first("verdict", verdict_id=p.get("verdict_id"))
                R.check(v is not None and v.data.get("status") == p.get("status"), "E-AUDIT-VERDICT", where, "verdict_changed does not match the verdict")
            if et == "report_published":
                rm = c.ix.first("report-manifest", run_id=rid)
                R.check(rm is not None and rm.data.get("report_id") == (ev.get("payload") or {}).get("report_id"), "E-AUDIT-REPORT", where, "report id mismatch")
        tail, last_anchor = audit_anchor_tail(R, w, run, d)
        if run.get("status") in TERMINAL_RUN_STATES:
            # at most one E-AUDIT-TAIL per run, listing every reason
            why = []
            if tail > 0:
                why.append(f"{tail} line(s) after the last audit_anchor (seq {last_anchor})")
            if not evs or evs[-1].get("event_type") != "audit_anchor":
                why.append("the last event is not an audit_anchor")
            elif (evs[-1].get("payload") or {}).get("reason") != "run_end":
                why.append("the final anchor is not a run_end anchor")
            R._checks += 1
            if why:
                R.error("E-AUDIT-TAIL", w, f"{run.get('status')} run must end with a run_end audit_anchor covering the last line: "
                        + "; ".join(why))
        elif tail > 0:
            R.warn("W-AUDIT-UNANCHORED-TAIL", w, f"{tail} line(s) after the last audit_anchor (seq {last_anchor}) are not yet anchored")
        logged = {(e.get("payload") or {}).get("gate_record_id") for e in evs if e.get("event_type") == "gate_decision"}
        for g in c.ix.gate_records(rid):
            R.check(g.data.get("gate_record_id") in logged, "E-AUDIT-GATE", w, f"{g.data.get('gate_record_id')} has no gate_decision event")


    audited = {d.data[0].get("run_id") for d in c.ix.audit_docs() if d.data}
    for rid, run in c.runs.items():
        if rid in audited:
            continue
        if rid in c.broken_audit_runs:
            # the log exists but the strict loader rejected it: the load error (E-JSON-STRICT in
            # group 1) is the only report for this run's audit group; no cascade
            continue
        where = f"run {rid}"
        R.check(not run.get("audit_anchors"), "E-AUDIT-TRUNCATED", where, "run.audit_anchors names lines of an audit log that is missing")
        R.check(run.get("status") not in TERMINAL_RUN_STATES, "E-AUDIT-TAIL", where,
                f"{run.get('status')} run has no audit log, so no final anchor covers its last line")


def audit_anchor_tail(R: Report, w: str, run: dict, d: Doc) -> tuple[int, int]:
    """Tail protection of the hash chain [H]. Returns (tail line count, seq of the last anchor event).

    run.audit_anchors = [{seq, line_sha256}] names audit_anchor lines by seq and by the sha256 of
    the raw line itself. It must name EVERY audit_anchor event of the log, in order (dropping an
    anchor from the run record is E-AUDIT-ANCHOR). The chain (prev_hash) protects every line up to
    the last anchor event; lines after it are the unanchored tail, reported by the caller
    (W-AUDIT-UNANCHORED-TAIL, or E-AUDIT-TAIL for a run in a terminal state, D2). Named seqs beyond
    the end of the log are E-AUDIT-TRUNCATED (and not compared again here).
    """
    lines = read_jsonl_lines(d.text or "")
    evs = d.data or []
    anchors = run.get("audit_anchors") or []
    prev = 0
    for j, a in enumerate(anchors):
        a = a if isinstance(a, dict) else {}
        s, h = a.get("seq"), a.get("line_sha256")
        where = f"{w} (run.audit_anchors[{j}])"
        if not R.check(type(s) is int and s > prev, "E-AUDIT-ANCHOR", where, f"anchor seq {s!r} must be an integer above {prev}"):
            continue
        prev = s
        if not R.check(s <= len(lines), "E-AUDIT-TRUNCATED", where,
                       f"anchor names seq {s} but the log has only {len(lines)} lines (truncated after the anchor)"):
            continue
        want = "sha256:" + sha256_hex(lines[s - 1].encode("utf-8"))
        R.check(h == want, "E-AUDIT-ANCHOR-MISMATCH", where, f"line_sha256 {h} != sha256 of line {s} ({want})")
        R.check(s - 1 < len(evs) and evs[s - 1].get("event_type") == "audit_anchor", "E-AUDIT-ANCHOR", where,
                f"line {s} is not an audit_anchor event")
    logged = [i + 1 for i, e in enumerate(evs) if isinstance(e, dict) and e.get("event_type") == "audit_anchor"]
    named = [a.get("seq") for a in anchors if isinstance(a, dict)]
    named_in_log = [s for s in named if type(s) is int and 0 < s <= len(lines)]
    R.check(named_in_log == logged, "E-AUDIT-ANCHOR", w,
            f"run.audit_anchors seqs {named_in_log} must name every audit_anchor event of the log, in order: {logged}"
            + (f" (missing {sorted(set(logged) - set(named_in_log))})" if set(logged) - set(named_in_log) else ""))
    last = logged[-1] if logged else 0
    return len(lines) - last, last


# ============================================================== 16 calibration
def wilson_lower(correct, n, z=1.959964):
    if n == 0:
        return 0.0
    p = correct / n
    den = 1 + z * z / n
    centre = p + z * z / (2 * n)
    margin = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return (centre - margin) / den


def g_calibration(R: Report, c: Ctx):
    cal, w = c.calibration, "calibration.yaml"
    if not cal:
        return
    cfg, res = cal.get("config") or {}, cal.get("result") or {}
    k = cfg.get("smoothing_k", 0)
    nz = cfg.get("near_zero_rules") or {}
    rows = res.get("weights", [])
    keys = {m.get("model_key"): m for m in cfg.get("models", [])}
    for mk, m in keys.items():
        reg = c.model(mk)
        R.check(reg is not None and reg.get("family") == m.get("family") and reg.get("lineage") == m.get("lineage"), "E-CAL-MODEL", w,
                f"config.models {mk}: family/lineage disagree with models.yaml")
    for mk in {r.get("model_key") for r in rows}:
        mine = [r for r in rows if r.get("model_key") == mk]
        tn = sum(r.get("n", 0) for r in mine)
        abar = sum(r.get("correct", 0) for r in mine) / tn if tn else 0
        for r in mine:
            where = f"{w} weights {mk}/{r.get('cwe_bucket')}"
            R.check(mk in keys, "E-CAL-MODEL", where, "model not in config.models")
            n, cc = r.get("n", 0), r.get("correct", 0)
            a = (cc + k * abar) / (n + k) if n + k else 0
            reasons = []
            wv = max(0.0, 2 * a - 1)
            if wv < nz.get("w_min", 0):
                reasons.append("w_below_min")
            if wilson_lower(cc, n) <= nz.get("wilson_lower_max", 0):
                reasons.append("wilson_lower_le_max")
            if n < nz.get("n_min", 0):
                reasons.append("n_below_min")
            near = bool(reasons)
            R.check(abs(r.get("a", -1) - round(a, 4)) <= 5e-4, "E-CAL-WEIGHT", where, f"a={r.get('a')} but recomputed {a:.4f}")
            R.check(abs(r.get("w", -1) - (0 if near else round(wv, 4))) <= 5e-4, "E-CAL-WEIGHT", where, f"w={r.get('w')} but recomputed {0 if near else round(wv, 4)}")
            R.check(r.get("near_zero") is near and sorted(r.get("near_zero_reasons", [])) == sorted(reasons), "E-CAL-WEIGHT", where,
                    f"near_zero/near_zero_reasons must be {near} {reasons}")
    for name, th in (res.get("thresholds") or {}).items():
        R.check(th.get("value") is not None or th.get("feasible") is False, "E-CAL-THETA", w, f"{name}: value null requires feasible false")
        R.check(th.get("value") is None or th.get("feasible") is True, "E-CAL-THETA", w, f"{name}: a value requires feasible true")
    for arm in cfg.get("arms", []):
        R.check(arm.get("exploratory") is (arm.get("arm") == "5"), "E-CAL-ARMS", w, f"arm {arm.get('arm')}: only arm 5 is exploratory")
        R.check(set(arm.get("model_keys", [])) <= set(keys), "E-CAL-ARMS", w, f"arm {arm.get('arm')}: unknown model keys")
    R.check((res.get("exploratory") or {}).get("arm") == "5", "E-CAL-ARMS", w, "result.exploratory.arm must be 5")
    for row in ((res.get("metrics") or {}).get("M-11") or {}).get("by_model", []):
        want = "support_leaning" if row.get("value") is not None and row["value"] < 0.5 else None
        R.check(row.get("flag") == want, "E-CAL-M11", w, f"M-11 {row.get('model_key')}: flag must be {want}")
    R.check(set(res.get("valid_for_model_keys", [])) <= set(keys), "E-CAL-MODEL", w, "valid_for_model_keys not in config.models")
    for x in res.get("annotator_agreement", []):
        R.check(x.get("accepted") is (x.get("kappa", 0) >= (cfg.get("annotation") or {}).get("kappa_min", 0)), "E-CAL-KAPPA", w,
                f"{x.get('batch_id')}: accepted must equal kappa >= kappa_min")


# ============================================================== 17 licenses
def g_licenses(R: Report, c: Ctx):
    comps = {x.get("component"): x for x in c.licenses.get("components", [])}
    R.check(len(comps) == len(c.licenses.get("components", [])), "E-LIC-DUP", "licenses.yaml", "duplicate components")
    for t, spec in (c.tools.get("tools") or {}).items():
        R.check(spec.get("license_ref") in comps, "E-LIC-MISSING", "tools.yaml", f"{t}: license_ref {spec.get('license_ref')!r} not in licenses.yaml")
    for x in comps.values():
        if x.get("status") == LEGAL_GATE:
            R.check(x.get("gate_milestone") is not None, "E-LIC-GATE", "licenses.yaml", f"{x.get('component')}: 法務閘門 needs a gate_milestone")
    req = c.b.requirements_txt
    if R.check(req is not None, "E-REQ", "requirements.txt", "requirements.txt missing"):
        names = [re.split(r"[<>=!~\[; ]", ln.strip())[0].lower() for ln in req.splitlines() if ln.strip() and not ln.startswith("#")]
        lic = {k.lower(): v for k, v in comps.items()}
        for n in names:
            R.check(n in lic and str(lic[n].get("usage", "")).startswith("validator"), "E-LIC-MISSING", "requirements.txt",
                    f"{n} is not listed in licenses.yaml as a validator dependency")
        R.check("rfc8785==0.1.4" in req.replace(" ", ""), "E-REQ", "requirements.txt", "rfc8785 must be pinned to 0.1.4")


# ============================================================== 18 crosswalk
def g_crosswalk(R: Report, c: Ctx):
    x, w = c.crosswalk, "crosswalk.yaml"
    if not x:
        return
    R.check(x.get("owasp_llm_default") == c.toolkit.get("owasp_llm_default"), "E-XWALK-OWASP", w, "owasp_llm_default differs from toolkit.yaml")
    seen = set()
    for l in x.get("links", []):
        key = (l.get("from_scheme"), l.get("from_id"), l.get("target_scheme"), l.get("target_id"))
        R.check(key not in seen, "E-XWALK-DUP", w, f"duplicate link {key}")
        seen.add(key)
        R.check((l.get("provenance") == "curated") == (l.get("reviewed_by") is not None), "E-XWALK-REVIEW", w,
                f"{key}: curated links need reviewed_by; llm-suggested links must not have it")
        if l.get("target_scheme") == "invariant":
            R.check(l.get("target_id") in {i.get("requirement_id") for i in c.invariants.get("invariants", [])}, "E-TRACE", w, f"{key}: unknown invariant")
        fs = str(l.get("from_scheme"))
        if fs.startswith("owasp-llm@"):
            R.check(fs[len("owasp-llm@"):] in ("2025", "2026"), "E-XWALK-OWASP", w, f"{fs}: unknown OWASP LLM version")


# ============================================================== 19 LLM-facing schemas
def g_llm_schemas(R: Report, c: Ctx):
    for name in ("finding", "threat", "testcase", "commander-plan"):
        s = c.b.schemas.get(name)
        if not R.check(s is not None, "E-LLM-SCHEMA", name, "schema missing"):
            continue
        deg = llm_schema.degrade_for_llm(s)
        hits = llm_schema.find_forbidden(deg)
        R.check(not hits, "E-LLM-SCHEMA", f"{name} (degraded)", f"outside the common subset: {hits[:5]}")
        try:
            Draft202012Validator.check_schema(deg)
        except SchemaError as exc:
            R.error("E-LLM-SCHEMA", f"{name} (degraded)", exc.message)
            continue
        v = Draft202012Validator(deg)
        for d in c.docs(name):
            errs = list(v.iter_errors(d.data))
            R.check(not errs, "E-LLM-SCHEMA", d.path, f"does not validate against the degraded schema: {errs[0].message[:200] if errs else ''}")


# ============================================================== 20 toolkit
def g_toolkit(R: Report, c: Ctx):
    tk, w = c.toolkit, "toolkit.yaml"
    if not R.check(bool(tk), "E-TOOLKIT", w, "toolkit.yaml missing"):
        return
    R.check(re.match(r"^\d+\.\d+\.\d+$", str(tk.get("toolkit_version", ""))) is not None, "E-TOOLKIT", w, "toolkit_version must be semver")
    R.check(REQUIRED_AUTOMATION <= set(tk.get("automation_accounts", [])), "E-TOOLKIT", w, f"automation_accounts must include {sorted(REQUIRED_AUTOMATION)}")
    R.check(tk.get("owasp_llm_default") in ("2025", "2026"), "E-TOOLKIT", w, "owasp_llm_default must be 2025 or 2026")
    R.check((tk.get("gate_timeouts_hours") or {}).get("G5", 99) <= 24, "E-TOOLKIT", w, "G5 timeout must be <= 24 h")
    R.check(set(GATE_ROLES) - {"G0a", "G0b"} | {"claim_run", "GB"} <= set(tk.get("gate_timeouts_hours") or {}), "E-TOOLKIT", w, "missing gate timeouts")
    ref = tk.get("tool_registry_ref")
    R.check(ref is not None and (c.b.root / ref).exists(), "E-TOOLKIT", w, f"tool_registry_ref {ref} does not exist")
    ret = tk.get("retention") or {}
    for f in ("p_days", "c_days_after_run_end", "audit_days", "checkpoint_days_after_run_end", "checkpoint_keep_last"):
        R.check(isinstance(ret.get(f), int) and ret[f] >= (1 if f == "checkpoint_keep_last" else 0), "E-RETENTION", w, f"retention.{f} must be a non-negative integer")
    R.check(isinstance(ret.get("legal_hold"), list), "E-RETENTION", w, "retention.legal_hold must be a list")
    R.check(ret.get("audit_days", 0) >= max(ret.get("p_days", 0), ret.get("c_days_after_run_end", 0)), "E-RETENTION", w,
            "audit records must be kept at least as long as the content")
    for t, spec in (c.tools.get("tools") or {}).items():
        for m in (spec.get("modes") or {}):
            R.check(safety.ADAPTER_RE.match(f"{t}:{m}") is not None, "E-TOOLS-ID", "tools.yaml", f"{t}:{m} is not a D13 tool:mode id")
        for m, ms in (spec.get("modes") or {}).items():
            if ms.get("b4_executable") and not ms.get("toolkit_denied"):
                R.check(ms.get("base_class") in safety.ORDER, "E-TOOLS-CLASS", "tools.yaml", f"{t}:{m}: executable mode needs a base_class")
            R.check(not ms.get("b4_executable") or spec.get("zone") == "Z3", "E-TOOLS-ZONE", "tools.yaml", f"{t}:{m}: B4 modes run in Z3")


# ============================================================== 21 DFD, report, selftest, checkpoint
def report_metrics(c: Ctx, run_id) -> dict:
    """B5: results_total, results_invalid, control_pass_rate (PASS control outcomes / all control outcomes, 4 decimals)."""
    results = [x.data for x in c.docs("testresult") if x.data.get("run_id") == run_id]
    outs = [y.get("outcome") for r in results for y in r.get("controls") or [] if isinstance(y, dict)]
    return {"results_total": len(results), "results_invalid": sum(1 for r in results if r.get("outcome") == "INVALID"),
            "control_pass_rate": round(sum(1 for o in outs if o == "PASS") / len(outs), 4) if outs else None}


def g_misc(R: Report, c: Ctx):
    for d in c.docs("dfd"):
        els = d.data.get("elements", [])
        ids = [e.get("element_id") for e in els]
        R.check(len(ids) == len(set(ids)), "E-DFD", d.path, "duplicate element ids")
        inv = inventory_of_run(c, d.data.get("run_id"))
        for e in els:
            R.check((e.get("type") == "trust_boundary") == (e.get("kind") is not None), "E-DFD", d.path,
                    f"{e.get('element_id')}: kind is required on trust boundaries and null on other elements")
            for r in e.get("evidence_refs") or []:
                if str(r).startswith("inventory:"):
                    R.check(inv is not None and evidence.resolves(inv, str(r)[len("inventory:"):]), "E-INVENTORY-REF", d.path,
                            f"{e.get('element_id')}: {r} does not resolve in the W0 inventory of {d.data.get('run_id')}")
            if e.get("type") == "data_flow":
                R.check(e.get("from") in ids and e.get("to") in ids, "E-DFD", d.path, f"{e.get('element_id')}: flow endpoints missing")
                R.check(all(x in ids for x in e.get("crosses", [])), "E-DFD", d.path, f"{e.get('element_id')}: unknown trust boundary")
    ext = {e.get("element_id") for d in c.ix.find("dfd", viewpoint="external") for e in d.data.get("elements", [])}
    mer = {e.get("element_id") for d in c.ix.find("dfd", viewpoint="merged") for e in d.data.get("elements", [])}
    for d in c.ix.find("dfd", viewpoint="merged"):
        for x in d.data.get("b1_diff") or []:
            eid = x.get("element_id")
            want = {"only_external": eid in ext and eid not in mer, "only_merged": eid in mer and eid not in ext,
                    "attribute_mismatch": eid in ext and eid in mer}.get(x.get("kind"), False)
            R.check(want, "E-DFD", d.path, f"b1_diff {eid}: kind {x.get('kind')} does not match the two views")
    for d in c.docs("report-manifest"):
        rm, w = d.data, d.path
        run = c.runs.get(rm.get("run_id"))
        if not R.check(run is not None, "E-REPORT", w, "run not found"):
            continue
        R.check(rm.get("advisory") is (run.get("run_kind") == "lane_a"), "E-REPORT", w, "advisory iff Lane A")
        superseded = {c.ix.first("verdict", verdict_id=v).data.get("supersedes_verdict_id") for v in run.get("verdicts", []) if c.ix.first("verdict", verdict_id=v)}
        final = [c.ix.first("verdict", verdict_id=v).data for v in run.get("verdicts", []) if v not in superseded and c.ix.first("verdict", verdict_id=v)]
        counts = {s: sum(1 for v in final if v.get("status") == s) for s in FINAL_STATUSES}
        R.check(rm.get("verdict_counts") == counts, "E-REPORT", w, f"verdict_counts must be {counts} (latest verdict per cluster)")
        want_m = report_metrics(c, rm.get("run_id"))
        got_m = rm.get("metrics") or {}
        R.check(derive._equal(got_m, want_m), "E-REPORT-METRICS", w, f"metrics {got_m} != recomputed {want_m} (the run's testresults and controls)")
        R.check(sorted(rm.get("manual_review_clusters", [])) == sorted(run.get("manual_review_clusters", [])), "E-REPORT", w, "manual_review_clusters differ from the run")
        for a in rm.get("artifacts", []):
            if a.get("kind") == "audit_log":
                R.check(c.b.doc(a.get("ref", "")) is not None, "E-REPORT", w, f"audit log {a.get('ref')} not found")
        grs = {a.get("ref") for a in rm.get("artifacts", []) if a.get("kind") == "gate_record"}
        R.check(grs == {g.data.get("gate_record_id") for g in c.ix.gate_records(rm.get("run_id"))}, "E-REPORT", w, "report must list every gate record of the run")
    for d in c.docs("selftest-report"):
        st, w = d.data, d.path
        items = {i.get("item"): i for i in st.get("items", [])}
        for i in items.values():
            if i.get("status") == "NOT_RUN":
                R.check(i.get("passed") is None and i.get("value") is None and i.get("runs") == 0, "E-SELFTEST", w, f"{i.get('item')}: NOT_RUN has no result")
            else:
                R.check(i.get("passed") is not None and i.get("runs", 0) >= 1, "E-SELFTEST", w, f"{i.get('item')}: RUN needs runs and passed")
        if st.get("milestone") == "M1":
            for need in M1_REQUIRED_SELFTESTS:
                it = items.get(need) or {}
                R.check(it.get("status") == "RUN" and it.get("passed") is True, "E-SELFTEST-M1", w, f"M1 requires {need} RUN and passed")
        ran = [i for i in items.values() if i.get("status") == "RUN"]
        R.check(st.get("overall_passed") is (bool(ran) and all(i.get("passed") for i in ran)), "E-SELFTEST", w, "overall_passed must be all RUN items passed")
        s, f = ts(R, st.get("started_at"), w), ts(R, st.get("finished_at"), w)
        R.check(s and f and s <= f, "E-SELFTEST", w, "finished_at before started_at")
        R.check(st.get("toolkit_version") == c.toolkit.get("toolkit_version"), "E-SELFTEST", w, "toolkit_version differs")
    for d in c.docs("checkpoint-metadata"):
        run = c.runs.get(d.data.get("run_id"))
        if R.check(run is not None, "E-CHECKPOINT", d.path, "run not found"):
            R.check(d.data.get("run_status") == run.get("status") and d.data.get("thread_id") == run.get("run_id"), "E-CHECKPOINT", d.path,
                    "run_status / thread_id disagree with the run")
            R.check(d.data.get("encrypted") is True or run.get("data_class") == "P", "E-CHECKPOINT", d.path, "C-class checkpoints must be encrypted")


GROUPS = [
    ("schemas and examples", g_schemas),
    ("RFC 8785 canonical JSON", g_jcs),
    ("derived hashes, weights and audit chain", g_derived),
    ("key registry", g_key_registry),
    ("Ed25519 signatures", g_signatures),
    ("person references", g_persons),
    ("engagement", g_engagement),
    ("ROE and legal review L-1..L-6", g_roe),
    ("models, agents, family diversity", g_models),
    ("gates", g_gates),
    ("run state, jobs, test results", g_runs),
    ("testcases vs ROE (docs/04 §5)", g_testcases),
    ("verdict recomputation (docs/05 §4.2)", g_verdicts),
    ("traceability", g_trace),
    ("audit log", g_audit),
    ("calibration", g_calibration),
    ("licenses and requirements", g_licenses),
    ("crosswalk", g_crosswalk),
    ("LLM-facing schemas (cross-vendor subset)", g_llm_schemas),
    ("toolkit, tools, retention", g_toolkit),
    ("DFD, report, self-test, checkpoint", g_misc),
]


def run_all(b: Bundle, real_run: bool = False) -> Report:
    """Run every check group. real_run=True (CLI --real-run): placeholder models reachable from an
    agent are E-MODEL-PLACEHOLDER errors instead of W-MODEL-PLACEHOLDER warnings."""
    R = Report()
    c = Ctx(b, real_run=real_run)
    for name, fn in GROUPS:
        before_checks, before_err = R._checks, len(R.errors)
        try:
            fn(R, c)
        except Exception as exc:  # noqa: BLE001 - graceful: report, keep going
            R.error("E-INTERNAL", name, f"{type(exc).__name__}: {exc} | {traceback.format_exc(limit=3).splitlines()[-2].strip()}")
        R.groups.append((name, R._checks - before_checks, len(R.errors) - before_err))
    return R


__all__ = ["Report", "Issue", "run_all", "GROUPS", "wilson_lower", "content_hash"]
