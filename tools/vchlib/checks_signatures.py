# SPDX-License-Identifier: Apache-2.0
"""Signature verification against the key registry, the receive-clock helpers every signed record is judged by
(decision_time, MAX_CLOCK_SKEW), and the check group over Ed25519 signatures.

Split out of checks.py (architecture refactor PR-D4, docs/adr/0003-split-checks.md). The text is moved verbatim; no
rule, error code or message changed. checks.GROUPS still lists the group in the same place.
"""
from __future__ import annotations

import datetime as dt

from . import crypto, derive, seal
from .canonical import signing_payload
from .context import Ctx
from .report import Report, doc_guard, ts


# ============================================================== receive clock (used by several groups)
MAX_CLOCK_SKEW = dt.timedelta(minutes=5)


def decision_time(c: Ctx, rec: dict) -> dt.datetime | None:
    """v0.4 (E4): the ts of the gate_decision audit event of `rec` (the Audit Writer's receive clock), or None.

    v0.3 used the approver's self-declared timestamp for validity, timeout and time-window checks, so a key holder
    could back-date a decision (e.g. before a role_change / retired revocation, or inside an expired ROE)."""
    return c.ix.decision_time(rec)


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


def first_verification(c: Ctx, gate: str) -> dt.datetime | None:
    """Audit Writer receive time of the earliest G0a/G0b record that verified the current document
    (verification.document_ref = its hash): the first moment the signed bytes provably existed."""
    times = [decision_time(c, g.data) for g in c.docs("gate-record")
             if g.data.get("gate") == gate and (g.data.get("verification") or {}).get("document_ref") is not None
             and (g.data.get("verification") or {}).get("document_ref") == derive.gate_artifact(c.ix, g.data)]
    times = [t for t in times if t is not None]
    return min(times) if times else None  # type: ignore[type-var]  # the line above dropped the None entries


def check_backdating(R: Report, c: Ctx, where: str, doc: dict, first_seen: dt.datetime | None):
    """v0.4 (06 §3 #25): issued_at is self-declared. A signature by a key later revoked for a reason
    other than compromise only counts if the document was first verified before revoked_at; otherwise
    the signer could have back-dated issued_at after losing the key (E-SIG-BACKDATED)."""
    issued = ts(R, doc.get("issued_at"), where, "issued_at")
    # v0.5 (review 2026-10-25 T-5): the signed bytes cannot be older than the first moment they were seen, so issued_at
    # may not lie after the first verification either (that would forward-date a signature into a key's validity)
    if first_seen is not None and issued is not None:
        R.check(issued <= first_seen + MAX_CLOCK_SKEW, "E-SIG-ISSUED-AT", where,
                f"issued_at {doc.get('issued_at')} is after the first verification at {first_seen.isoformat()}")
    known = ts(R, c.registry.get("issued_at"), "key-registry.yaml", "issued_at")
    for sig in doc.get("signatures") or []:
        e = c.by_fp.get(sig.get("key_fingerprint")) or {}
        rv = ts(R, e.get("revoked_at"), "key-registry.yaml", "revoked_at")
        if e.get("revocation_reason") == "compromised":
            continue
        if rv is not None:
            R.check(first_seen is not None and first_seen < rv, "E-SIG-BACKDATED", where,
                    f"{sig.get('signer')}: key {sig.get('key_fingerprint')} was revoked at {e.get('revoked_at')}, but the document "
                    f"was first verified {'never' if first_seen is None else 'at ' + first_seen.isoformat()}; issued_at alone cannot prove it was signed before")
        # v0.5 (review 2026-10-25 T-5): expiry is the same as a revocation: an expired key may not sign a document first
        # seen after its not_after (or never seen, once the registry knows the key has expired)
        na = ts(R, e.get("not_after"), "key-registry.yaml", "not_after")
        seen = first_seen if first_seen is not None else known
        if na is not None and seen is not None and (first_seen is not None or rv is None):
            R.check(seen <= na, "E-SIG-BACKDATED", where,
                    f"{sig.get('signer')}: key {sig.get('key_fingerprint')} expired at {e.get('not_after')}, but the document was "
                    + (f"first verified at {first_seen.isoformat()}" if first_seen is not None else
                       f"never verified (registry issued {c.registry.get('issued_at')})")
                    + "; issued_at alone cannot prove it was signed before")


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


# ============================================================== 5 signatures
def g_signatures(R: Report, c: Ctx):
    if c.engagement:
        check_signed_doc(R, c, "engagement.yaml", c.engagement, c.engagement.get("signatories") or [])
        check_backdating(R, c, "engagement.yaml", c.engagement, first_verification(c, "G0a"))
    if c.roe:
        lr = c.roe.get("legal_review") or {}
        signers = list(c.roe.get("signatories") or [])
        att = lr.get("attested_by")
        if att:
            # v0.5 (review 2026-10-25 T-7): expect the key the attester actually signed with when it is theirs, so a
            # routine rotation (old key retired after signing) does not break the ROE; verify_signature then judges
            # that key at the first-verification time like every other signature
            used = next((s.get("key_fingerprint") for s in c.roe.get("signatures") or [] if s.get("signer") == att
                         and (c.by_fp.get(s.get("key_fingerprint")) or {}).get("person_id") == att), None)
            e = c.by_fp.get(used) if used else next((x for x in c.entries if x.get("person_id") == att and not x.get("revoked_at")), None)
            fp = e.get("fingerprint") if e else None
            role = "legal_reviewer" if "legal_reviewer" in c.roles_of(att) else ("management" if "management" in c.roles_of(att) else "legal_reviewer")
            if not any(s.get("person_id") == att for s in signers):
                signers.append({"person_id": att, "role": role, "key_fingerprint": fp})
        check_signed_doc(R, c, "roe.yaml", c.roe, signers)
        check_backdating(R, c, "roe.yaml", c.roe, first_verification(c, "G0b"))
    for d in c.docs("gate-record"):
        with doc_guard(R, d.path):
            rec = d.data
            # v0.4 (E4): key validity is judged at the Audit Writer's receive time, not the self-declared timestamp
            at = decision_time(c, rec) or ts(R, rec.get("timestamp"), d.path)
            if rec.get("gate") in ("G0a", "G0b"):
                R.check(rec.get("signatures") == [], "E-GATE-G0-SIG", d.path, "G0a/G0b are system verifications: signatures must be []")
                doc = c.engagement if rec.get("gate") == "G0a" else c.roe
                ver = rec.get("verification") or {}
                doc_at = ts(R, doc.get("issued_at"), d.path)
                real = [{"person_id": s.get("signer"), "key_fingerprint": s.get("key_fingerprint"),
                         "ok": silent_verify(c, signing_payload(doc), s, doc_at)} for s in doc.get("signatures") or []]
                got = [{k: r.get(k) for k in ("person_id", "key_fingerprint", "ok")} for r in ver.get("signer_results") or []]
                R.check(got == real, "E-GATE-G0-VERIFY", d.path, f"signer_results {got} do not match the real verification {real}")
                # v0.5 (review 2026-10-25 T-6): the registry moves on (every revocation bumps its version), so a verification
                # names the version it used, which may be older but never newer than the loaded registry. Re-verifying with
                # the loaded registry (signer_results above) still catches a later compromise
                kv = ver.get("key_registry_version")
                R.check(type(kv) is int and 1 <= kv <= (c.registry.get("version") or 0), "E-GATE-G0-VERIFY", d.path,
                        f"verification.key_registry_version {kv!r} must be 1..{c.registry.get('version')} (the loaded registry version)")
                if rec.get("outcome") == "VERIFIED":
                    R.check(all(r["ok"] for r in real) and real, "E-GATE-G0-VERIFY", d.path, "VERIFIED although a signature failed")
                if rec.get("outcome") == "VERIFY_FAILED":
                    # r14 (internal review A5): a failure names what failed: a signature that does not verify or a reason
                    # (docs/06 L-5 legal_attester_is_test_lead, an expired key, ...); r12 accepted an all-ok, reasonless failure
                    R.check(any(not r["ok"] for r in real) or any(r.get("reason") for r in ver.get("signer_results") or [] if isinstance(r, dict)),
                            "E-GATE-G0-VERIFY", d.path, "VERIFY_FAILED although every signature verifies and no signer_results entry gives a reason")
                continue
            if rec.get("outcome") == "EXPIRED":
                # v0.5 (review 2026-10-25 T-3): nobody decided an expired gate, so nobody signs it. The record is the
                # Gate Service's; its proof is the two receive times (gate_opened, gate_decision) and the timeout
                # between them (E-GATE-EXPIRED-EARLY), not an approver signature
                R.check(rec.get("signatures") == [], "E-GATE-EXPIRED-SIG", d.path,
                        "an EXPIRED record is written by the Gate Service: signatures must be [] (no approver decided)")
                continue
            payload = signing_payload(rec)
            approvers = {(a.get("person_id"), a.get("key_fingerprint")): a for a in seal.required_signers("gate-record", rec)}
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
            if ev.get("event_type") in seal.SIGNED_EVENTS:
                # v0.4: a claim or a resume is a person's act; actor.kind system / agent must not skip the signature
                R.check(actor.get("kind") == "human", "E-AUDIT-ACTOR", where,
                        f"{ev.get('event_type')} must have actor.kind human (got {actor.get('kind')!r}); it is always signed")
            if seal.event_is_signed(ev):
                sig = ev.get("signature")
                if not R.check(isinstance(sig, dict), "E-AUDIT-SIG", where, f"{ev.get('event_type')} by a human must be signed"):
                    continue
                R.check(sig.get("signer") == actor.get("id"), "E-SIG-SIGNER", where, "signature signer != actor.id")
                # docs/03 §5.6: resuming a STOPPED run needs the ROE test_lead; v0.5 (review 2026-10-25 §4.3): a SUSPENDED
                # run is resumed by its run_owner or an initiator (v0.4 demanded a test_lead for every resume, against
                # the docs). payload.from_status names which (required by the schema since review r12)
                need = None
                if ev.get("event_type") == "run_resume":
                    p = ev.get("payload") or {}
                    run = c.runs.get(ev.get("run_id")) or {}
                    if p.get("from_status") == "SUSPENDED":
                        R.check(actor.get("id") == run.get("run_owner") or actor.get("id") in (run.get("initiators") or []),
                                "E-AUDIT-ACTOR", where, f"a SUSPENDED run is resumed by its run_owner or an initiator, not {actor.get('id')}")
                    elif p.get("from_status") == "STOPPED":
                        need = "test_lead"
                    else:
                        R.error("E-AUDIT-ACTOR", where, f"run_resume payload.from_status must be SUSPENDED or STOPPED (got {p.get('from_status')!r})")
                verify_signature(R, c, where, crypto.event_payload(ev), sig, ts(R, ev.get("ts"), where), need)
            else:
                R.check(ev.get("signature") is None, "E-AUDIT-SIG", where, "only human initiator_claim / run_resume / spot_check_result events are signed")
