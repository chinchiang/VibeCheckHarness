# SPDX-License-Identifier: Apache-2.0
"""Regenerate every derived value and TEST ONLY signature in the example bundle.

    python tools/sign_examples.py

1. Replace "FP:<key>" / "PK:<key>" placeholders with the fingerprint / raw public key of
   tests/fixtures/TEST_ONLY_private_keys/<key>.TEST_ONLY.pem.
2. Repeat until nothing changes:
   - sign engagement.yaml, roe.yaml, key-registry.yaml (the n-th `value:` of the
     `signatures:` block is replaced; the rest of the YAML text is left untouched);
   - apply vchlib.derive expectations to the JSON / JSONL examples;
   - sign gate records (one signature per approver; G0a/G0b records are system
     verifications and carry no signatures);
   - rebuild the audit hash chain and sign initiator_claim / run_resume events.

TEST ONLY: the private keys are public test fixtures. Never use this for real approvals.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from vchlib import crypto, derive, jsonstrict, timeutil, yamlstrict  # noqa: E402
from vchlib.bundle import SIGNED_YAML, load_bundle, read_jsonl_lines  # noqa: E402

KEY_DIR = ROOT / "tests" / "fixtures" / "TEST_ONLY_private_keys"
EXAMPLES = ROOT / "docs" / "schemas" / "examples"
CONFIG = ROOT / "docs" / "examples"
SIGNED_EVENTS = {"initiator_claim", "run_resume"}
PLACEHOLDER = re.compile(r'"(FP|PK):([a-z][a-z0-9_]*)"')


def load_keys():
    keys = {}
    for p in sorted(KEY_DIR.glob("*.TEST_ONLY.pem")):
        keys[p.name.split(".")[0]] = crypto.load_private_pem(p)
    return keys


def write(path: pathlib.Path, text: str) -> bool:
    old = path.read_text(encoding="utf-8") if path.exists() else None
    if old == text:
        return False
    path.write_text(text, encoding="utf-8", newline="\n")
    return True


def dump_json(obj) -> str:
    return json.dumps(obj, ensure_ascii=False, indent=2) + "\n"


def dump_jsonl(events) -> str:
    return "".join(json.dumps(e, ensure_ascii=False, separators=(",", ":")) + "\n" for e in events)


def replace_placeholders(keys) -> int:
    fp = {n: crypto.fingerprint(crypto.raw_public(k)) for n, k in keys.items()}
    pk = {n: crypto.b64(crypto.raw_public(k)) for n, k in keys.items()}
    n = 0
    files = list(CONFIG.glob("*.yaml")) + list(EXAMPLES.glob("*.example.json")) + list(EXAMPLES.glob("*.example.jsonl"))
    for p in files:
        text = p.read_text(encoding="utf-8")

        def sub(m):
            table = fp if m.group(1) == "FP" else pk
            if m.group(2) not in table:
                raise SystemExit(f"{p.name}: no TEST ONLY key named {m.group(2)!r}")
            return '"' + table[m.group(2)] + '"'
        new = PLACEHOLDER.sub(sub, text)
        n += write(p, new)
    return n


def sign_yaml(by_fp) -> int:
    changed = 0
    for name in sorted(SIGNED_YAML):
        p = CONFIG / name
        text = p.read_text(encoding="utf-8")
        data = yamlstrict.load(text)
        lines = text.split("\n")
        start = next(i for i, ln in enumerate(lines) if ln.startswith("signatures:"))
        value_lines = [i for i in range(start + 1, len(lines)) if re.match(r'^\s*value:\s*"', lines[i])]
        sigs = data.get("signatures", [])
        if len(value_lines) != len(sigs):
            raise SystemExit(f"{name}: {len(sigs)} signatures but {len(value_lines)} value: lines")
        for i, sig in zip(value_lines, sigs):
            key = by_fp.get(sig["key_fingerprint"])
            if key is None:
                raise SystemExit(f"{name}: no TEST ONLY key for {sig['key_fingerprint']}")
            value = crypto.sign_document(data, sig["signer"], key)["value"]
            lines[i] = re.sub(r'value:\s*"[^"]*"', f'value: "{value}"', lines[i])
        changed += write(p, "\n".join(lines))
    return changed


def apply_derivations() -> int:
    b = load_bundle(ROOT)
    docs = {d.path: d for d in b.docs}
    touched = set()
    for e in derive.expectations(b, for_writer=True):
        d = docs[e.file]
        if derive.get_path(d.data, e.path) != e.expected:
            derive.set_path(d.data, e.path, e.expected)
            touched.add(e.file)
    n = 0
    for f in sorted(touched):
        d = docs[f]
        n += write(ROOT / f, dump_jsonl(d.data) if f.endswith(".jsonl") else dump_json(d.data))
    return n


def sign_gate_records(by_fp) -> int:
    n = 0
    for p in sorted(EXAMPLES.glob("gate-record.*.example.json")):
        rec = jsonstrict.loads(p.read_text(encoding="utf-8"))
        if rec["gate"] in ("G0a", "G0b") or rec["outcome"] == "EXPIRED":
            rec["signatures"] = []
        else:
            rec["signatures"] = [crypto.sign_document(rec, a["person_id"], by_fp[a["key_fingerprint"]]) for a in rec["approvers"]]
        n += write(p, dump_json(rec))
    return n


def sign_feedback(by_fp) -> int:
    """v0.5 (BL-18): a feedback record is signed by its signed_by person (TEST ONLY keys)."""
    n = 0
    for p in sorted(EXAMPLES.glob("feedback.*.example.json")):
        rec = jsonstrict.loads(p.read_text(encoding="utf-8"))
        rec["signatures"] = [crypto.sign_document(rec, rec["signed_by"]["person_id"], by_fp[rec["signed_by"]["key_fingerprint"]])]
        n += write(p, dump_json(rec))
    return n


def current_key(registry, person, at, by_fp):
    for e in registry["entries"]:
        if e["person_id"] != person or e.get("revoked_at"):
            continue
        if timeutil.parse_dt(e["not_before"]) <= at <= timeutil.parse_dt(e["not_after"]):
            return by_fp[e["fingerprint"]]
    raise SystemExit(f"no valid registry key for {person} at {at}")


def load_events(text: str) -> list:
    """Audit JSONL -> events, split exactly like bundle.read_jsonl_lines (on "\\n" only).

    str.splitlines() would also split on U+2028 / U+2029 / U+0085 etc., which dump_jsonl writes
    raw (ensure_ascii=False) inside string values, so the writer and the reader would disagree.
    """
    return [jsonstrict.loads(ln) for ln in read_jsonl_lines(text)]


def sign_event_in_place(ev: dict, registry, by_fp) -> None:
    """Re-sign one audit event whose prev_hash is already set: human SIGNED_EVENTS get the actor's
    signature; every audit_anchor gets the Z3 executor's countersignature (crypto.anchor_payload)."""
    ev["signature"] = None
    at = timeutil.parse_dt(ev["ts"])
    if ev["event_type"] == "audit_anchor" and isinstance(ev.get("payload"), dict):
        ev["payload"]["z3_countersignature"] = crypto.countersign_anchor(
            ev, current_key(registry, crypto.ANCHOR_SIGNER, at, by_fp))
    if ev["event_type"] in SIGNED_EVENTS and ev["actor"]["kind"] == "human":
        ev["signature"] = crypto.sign_event(ev, ev["actor"]["id"], current_key(registry, ev["actor"]["id"], at, by_fp))


def rebuild_audit(by_fp) -> int:
    registry = yamlstrict.load((CONFIG / "key-registry.yaml").read_text(encoding="utf-8"))
    n = 0
    for p in sorted(EXAMPLES.glob("*.example.jsonl")):
        events = load_events(p.read_text(encoding="utf-8"))
        prev = hashlib.sha256(events[0]["run_id"].encode()).hexdigest()
        for ev in events:
            ev["prev_hash"] = "sha256:" + prev
            sign_event_in_place(ev, registry, by_fp)
            line = json.dumps(ev, ensure_ascii=False, separators=(",", ":"))
            prev = hashlib.sha256(line.encode("utf-8")).hexdigest()
        n += write(p, dump_jsonl(events))
    return n


def main() -> int:
    keys = load_keys()
    by_fp = {crypto.fingerprint(crypto.raw_public(k)): k for k in keys.values()}
    print(f"placeholders replaced in {replace_placeholders(keys)} file(s)")
    for rnd in range(1, 21):
        changed = sign_yaml(by_fp) + apply_derivations() + sign_gate_records(by_fp) + sign_feedback(by_fp) + rebuild_audit(by_fp)
        print(f"round {rnd}: {changed} file(s) changed")
        if changed == 0:
            print("fixpoint reached (TEST ONLY signatures)")
            return 0
    print("no fixpoint after 20 rounds", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
