#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build the variant example bundles (BL-60) from the main example bundle.

A variant is the main bundle with scripted edits (VARIANTS below), re-derived and re-signed with the TEST ONLY keys until
nothing changes, exactly as tools/sign_examples.py does for the main bundle. Only the files that differ from the main
bundle are written, to docs/examples/variants/<name>/ (same relative paths), plus removed.txt for the files the variant
drops; vchlib.bundle.load_variant applies that overlay. Ed25519 signatures are deterministic, so a rebuild reproduces
the overlay byte for byte.

    python tools/build_variants.py            # rewrite every variant
    python tools/build_variants.py --check    # exit 1 if any overlay is stale, or a variant does not validate cleanly
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import pathlib
import sys

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import sign_examples as S  # noqa: E402
from vchlib import crypto, derive, timeutil, yamlstrict  # noqa: E402
from vchlib.bundle import SIGNED_YAML, VARIANTS as VARIANTS_DIR, Bundle, Doc, load_bundle, reload_json  # noqa: E402
from vchlib.canonical import content_hash  # noqa: E402
from vchlib.checks import run_all  # noqa: E402

EX = "docs/schemas/examples/"
CFG = "docs/examples/"


# ---------------------------------------------------------------- serialisation
class _Dumper(yaml.SafeDumper):
    def ignore_aliases(self, data):
        return True


def _str(dumper, s):
    return dumper.represent_scalar("tag:yaml.org,2002:str", s, style='"')


_Dumper.add_representer(str, _str)


def dump_yaml(data) -> str:
    text = yaml.dump(data, Dumper=_Dumper, allow_unicode=True, sort_keys=False, width=1000)
    if yamlstrict.load(text) != data:
        raise SystemExit("YAML round trip changed the data")
    return text


def dump(d: Doc) -> str:
    if d.path.endswith(".jsonl"):
        return S.dump_jsonl(d.data)
    if d.path.endswith(".json"):
        return S.dump_json(d.data)
    return dump_yaml(d.data)


# ---------------------------------------------------------------- bundle helpers for the edit scripts
def doc(b: Bundle, suffix: str) -> Doc:
    hits = [d for d in b.docs if d.path.endswith(suffix)]
    if len(hits) != 1:
        raise SystemExit(f"{suffix}: {len(hits)} documents")
    return hits[0]


def drop(b: Bundle, *suffixes: str) -> None:
    for s in suffixes:
        b.docs.remove(doc(b, s))


def add(b: Bundle, path: str, kind: str, data) -> Doc:
    d = Doc(path, kind, data, S.dump_jsonl(data) if path.endswith(".jsonl") else S.dump_json(data))
    b.docs.append(d)
    return d


def fp(keys, name):
    return crypto.fingerprint(crypto.raw_public(keys[name]))


# ---------------------------------------------------------------- re-derive and re-sign in memory
def resign(b: Bundle, keys, rounds: int = 30) -> None:
    by_fp = {crypto.fingerprint(crypto.raw_public(k)): k for k in keys.values()}
    for d in b.docs:                       # edits may have inserted or dropped events: renumber and refresh the raw lines
        if d.kind == "audit-event" and d.data:
            for i, ev in enumerate(d.data):
                ev["seq"] = i + 1
            reload_json(d, S.dump_jsonl(d.data))
    for _ in range(rounds):
        changed = False
        docs = {d.path: d for d in b.docs}
        for e in derive.expectations(b, for_writer=True):
            d = docs[e.file]
            if derive.get_path(d.data, e.path) != e.expected:
                derive.set_path(d.data, e.path, e.expected)
                changed = True
        eng = next((d for d in b.docs if d.kind == "engagement"), None)
        if eng is not None:
            for name, ref in (eng.data.get("config_pins") or {}).items():
                cfg = next((d for d in b.docs if d.path == f"{CFG}{name}.yaml"), None)
                if cfg is not None and ref != content_hash(cfg.data):
                    eng.data["config_pins"][name] = content_hash(cfg.data)
                    changed = True
        for d in b.docs:
            if pathlib.PurePosixPath(d.path).name in SIGNED_YAML:
                for sig in d.data.get("signatures") or []:
                    value = crypto.sign_document(d.data, sig["signer"], by_fp[sig["key_fingerprint"]])["value"]
                    if sig.get("value") != value:
                        sig["value"], changed = value, True
            if d.kind == "gate-record":
                rec = d.data
                sigs = [] if rec["gate"] in ("G0a", "G0b") or rec["outcome"] == "EXPIRED" else \
                    [crypto.sign_document(rec, a["person_id"], by_fp[a["key_fingerprint"]]) for a in rec["approvers"]]
                if sigs != rec.get("signatures"):
                    rec["signatures"], changed = sigs, True
            if d.kind in ("feedback", "report-withdrawal"):
                rec = d.data
                signers = rec["signers"] if d.kind == "report-withdrawal" else \
                    [rec["signed_by"]] + ([rec["co_signed_by"]] if rec.get("co_signed_by") else [])
                sigs = [crypto.sign_document(rec, x["person_id"], by_fp[x["key_fingerprint"]]) for x in signers]
                if sigs != rec.get("signatures"):
                    rec["signatures"], changed = sigs, True
        registry = next(d for d in b.docs if d.kind == "key-registry").data
        for d in b.docs:
            if d.kind == "audit-event" and d.data:
                prev = hashlib.sha256(d.data[0]["run_id"].encode()).hexdigest()
                for i, ev in enumerate(d.data):
                    ev["seq"] = i + 1
                    ev["prev_hash"] = "sha256:" + prev
                    S.sign_event_in_place(ev, registry, by_fp)
                    prev = hashlib.sha256(json.dumps(ev, ensure_ascii=False, separators=(",", ":")).encode("utf-8")).hexdigest()
                text = S.dump_jsonl(d.data)
                if text != d.text:
                    reload_json(d, text)
                    changed = True
        for d in b.docs:
            if not d.path.endswith(".jsonl") and d.path.endswith(".json"):
                d.text = S.dump_json(d.data)
        if not changed:
            return
    raise SystemExit("no fixpoint")


# ---------------------------------------------------------------- the variants
VARIANTS: dict = {}


def variant(fn):
    VARIANTS[fn.__name__.removeprefix("v_").replace("_", "-")] = fn
    return fn


LITE_PERSON = "alice"
LITE_ROLES = ["test_lead", "management", "infrastructure_owner", "security_reviewer", "app_owner", "legal_reviewer"]
OTHER_PEOPLE = ("carol", "dave", "erin", "frank", "grace", "heidi")


def _subst(obj, names: dict):
    """Replace every string equal to a key of `names` (person ids, key fingerprints) inside obj."""
    if isinstance(obj, dict):
        return {k: _subst(v, names) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_subst(v, names) for v in obj]
    return names.get(obj, obj) if isinstance(obj, str) else obj


@variant
def v_lite(b: Bundle, keys) -> None:
    """A one-person (Lite) engagement: alice holds every role under a signed role_consolidation, the run only executes
    S0/S1 jobs (the S2 ZAP test becomes MANUAL, so there is no G5), and nobody spot-checks. Only the initial run of the
    main bundle is kept."""
    drop(b, "audit-event.run-2026-10-07-001.example.jsonl", "checkpoint-metadata.followup.example.json",
         "cluster.followup.k-301.example.json", "gate-record.followup.g0a.example.json", "gate-record.followup.g0b.example.json",
         "gate-record.followup.g1.example.json", "gate-record.followup.g3.example.json", "run.followup.example.json",
         "audit-event.run-2026-09-25-pr-118.example.jsonl", "cluster.k-101.example.json", "finding.f-101.example.json",
         "gate-record.lane-a.g0a.example.json", "run.lane-a.example.json", "slice.lane-a.example.json",
         "verdict.lane-a.example.json", "feedback.k-016.example.json")
    names = {p: LITE_PERSON for p in OTHER_PEOPLE}
    names.update({fp(keys, p): fp(keys, LITE_PERSON) for p in OTHER_PEOPLE})
    for d in b.docs:
        if d.kind not in ("key-registry", "schema-file") and d.data is not None:
            d.data = _subst(d.data, names)
    reg = doc(b, "key-registry.yaml").data
    for e in reg["entries"]:
        if e["person_id"] == LITE_PERSON:
            e["roles"] = list(LITE_ROLES)
    eng = doc(b, "engagement.yaml").data
    eng["assurance_profile"] = "lite"
    eng["role_consolidation"] = {"acknowledged": True, "person_id": LITE_PERSON,
                                 "statement": "單人專案：alice 同時是測試負責人、管理者、基礎設施擁有者、資安審查者、應用程式擁有者與法務聲明者"}
    for name, approvers in (eng.get("gate_approvers") or {}).items():
        eng["gate_approvers"][name] = list(dict.fromkeys(approvers))
    for d in b.docs:
        if d.kind == "run" and d.data.get("initiators"):
            d.data["initiators"] = list(dict.fromkeys(d.data["initiators"]))      # review r12: run.initiators is a set
    tc = doc(b, "testcase.zap-active.example.json").data
    tc["tool_binding"].update(kind="MANUAL", adapter="manual", manual_reason="Lite 只允許 S0／S1：S2 的主動掃描改為人工執行")
    tc["safety_class_computed"], tc["safety_class_proposed"] = "S0", None
    # no S2 job, so no G5: drop the ZAP job, its result, cluster and verdict, the G5 record and their events
    drop(b, "testresult.zap-active.example.json", "cluster.k-202.example.json", "verdict.k-202-b5.example.json",
         "gate-record.g5.example.json")
    run = doc(b, "run.example.json").data
    run["jobs"].pop("job-zap-active-001")
    run["executed_jobs"] = [j for j in run["executed_jobs"] if j != "job-zap-active-001"]
    run["gate_records"] = [g for g in run["gate_records"] if g["gate"] != "G5"]
    run["verdicts"] = [v for v in run["verdicts"] if v != "V-202-1"]
    run["cluster_ids"] = [k for k in run["cluster_ids"] if k != "K-202"]
    log = doc(b, "audit-event.run-2026-09-23-001.example.jsonl")
    gone = lambda e: (e["node"] == "G5" or (e.get("payload") or {}).get("job_id") == "job-zap-active-001"
                      or (e.get("payload") or {}).get("verdict_id") == "V-202-1")
    log.data = [e for e in log.data if not gone(e)]
    rm = doc(b, "report-manifest.example.json").data
    rm["artifacts"] = [a for a in rm["artifacts"] if a["ref"] not in ("V-202-1", "GR-G5-0001", "R-TC-027-01-1")]
    doc(b, "report-manifest.example.json").data["evidential"] = "self_attested"     # r11: one person holds every key
    # r12: the MANUAL testcase is on the untested list (docs/02 B6, E-RUN-GAPS); a MANUAL entry keeps the run COMPLETED
    run["gaps"] = run.get("gaps", []) + [{"kind": "manual", "ref": "TC-027-01", "reason": "Lite 只允許 S0／S1：S2 的主動掃描改為人工執行"}]
    rm["gaps"] = run["gaps"]
    _refresh_report(b, run["run_id"])


def _refresh_report(b: Bundle, rid: str) -> None:
    """The report manifest's counts and metrics after the run's verdicts changed (the validator recomputes them)."""
    from vchlib import checks
    rm = next(d for d in b.docs if d.kind == "report-manifest" and d.data.get("run_id") == rid).data
    c = checks.Ctx(b)
    heads = checks.verdict_heads(c, c.runs[rid]["verdicts"])
    rm["verdict_counts"] = {s: sum(1 for v in heads if v.get("status") == s) for s in checks.FINAL_STATUSES}
    rm["metrics"] = checks.report_metrics(c, rid)


def _append(log: Doc, after_seq: int, *events) -> None:
    """Insert events (dicts with event_type, node, ts, payload, key and optional actor/zone) after seq `after_seq`,
    cloned from that line of the log (seq and hashes are rebuilt by resign)."""
    base = log.data[after_seq - 1]
    new = []
    for e in events:
        ev = copy.deepcopy(base)
        ev.update({"event_type": e["event_type"], "node": e["node"], "ts": e["ts"], "payload": e["payload"],
                   "idempotency_key": f"{base['run_id']}:{e['node']}:{e['key']}", "signature": None, "payload_refs": []})
        ev["actor"] = e.get("actor", {"kind": "system", "id": "run-controller"})
        ev["zone"] = e.get("zone", "Z1")
        new.append(ev)
    log.data[after_seq:after_seq] = new


@variant
def v_edge(b: Bundle, keys) -> None:
    """Paths of a team-scale engagement that the main bundle does not walk, on the same three runs:
    - G2 rejects K-016 (not a seed): its post-G2 verdict follows R10 (REJECTED);
    - the engagement is `full`, so the S2 job's G5 is approved by two security reviewers (E-G5-TWO-PERSON);
    - the follow-up run hits a stop condition while waiting for G4 and the test lead aborts it (ABORTED, run_end)."""
    reg = doc(b, "key-registry.yaml").data
    for e in reg["entries"]:
        if e["person_id"] == "grace":
            e["roles"] = sorted(set(e["roles"]) | {"security_reviewer"})
    roe = doc(b, "roe.yaml").data
    roe["gate_approvers"].append({"person_id": "grace", "role": "security_reviewer", "key_fingerprint": fp(keys, "grace")})
    eng = doc(b, "engagement.yaml").data
    eng["assurance_profile"] = "full"
    g5 = doc(b, "gate-record.g5.example.json").data
    g5["approvers"].append({"person_id": "grace", "role": "security_reviewer", "key_fingerprint": fp(keys, "grace")})
    g2 = doc(b, "gate-record.g2.example.json").data
    for x in g2["decisions"]:
        if x["item_id"] == "K-016":
            x["decision"] = "reject"
            x["note"] = "審查者讀過程式碼：K-016 的輸入在進入查詢前已由型別化的參數綁定，駁回"
    # G2_apply writes the post-G2 version of K-016 (docs/05 R10); the event sits after the G2 anchor (seq 29)
    v1 = doc(b, "verdict.k-016-w3.example.json").data
    v2 = copy.deepcopy(v1)
    v2.update({"verdict_id": "V-016-2", "readjudicated_by": "G2_apply", "supersedes_verdict_id": "V-016-1",
               "g2_decision_ref": "GR-G2-0001", "status": "REJECTED", "status_cap": None, "annotations": [],
               "rule_trace": ["R10:G2 GR-G2-0001 rejected K-016 and no G4-approved replayed black-box proof overrides it->REJECTED"]})
    add(b, f"{EX}verdict.k-016-g2.example.json", "verdict", v2)
    run = doc(b, "run.example.json").data
    run["verdicts"].insert(run["verdicts"].index("V-016-1") + 1, "V-016-2")
    rlog = doc(b, "audit-event.run-2026-09-23-001.example.jsonl")
    _append(rlog, 29, {"event_type": "verdict_changed", "node": "G2", "ts": "2026-09-28T10:05:00+08:00",
                       "key": "verdict_changed:V-016-2", "actor": {"kind": "system", "id": "aggregator"},
                       "payload": {"verdict_id": "V-016-2", "status": "REJECTED", "verdict_sha256": None}})
    rm = doc(b, "report-manifest.example.json").data
    i = next(i for i, a in enumerate(rm["artifacts"]) if a["kind"] == "verdict" and a["ref"] == "V-016-1")
    rm["artifacts"][i] = {"kind": "verdict", "ref": "V-016-2", "sha256": None}
    rm["report_only_clusters"] = [k for k in rm["report_only_clusters"] if k != "K-016"]     # rejected, not report-only
    _refresh_report(b, run["run_id"])
    frun = doc(b, "run.followup.example.json").data
    log = doc(b, "audit-event.run-2026-10-07-001.example.jsonl")
    n = len(log.data)
    _append(log, n,
            {"event_type": "stop_condition", "node": "G4", "ts": "2026-10-08T09:00:00+08:00", "key": "stop_condition:roe-target-down",
             "payload": {"condition": "target_unavailable", "target_id": "tgt-staging-api", "detail": "staging 連續 30 分鐘回應 5xx"}},
            {"event_type": "run_status_changed", "node": "G4", "ts": "2026-10-08T09:30:00+08:00", "key": "run_status_changed:aborted",
             "payload": {"from": "WAITING_GATE", "to": "ABORTED", "reason": "測試負責人中止：staging 停機，重測改排下一個 run"}},
            {"event_type": "audit_anchor", "node": "END", "ts": "2026-10-08T09:30:00+08:00", "key": "audit_anchor:run_end",
             "payload": {"reason": "run_end", "anchor_counter": 0, "z3_countersignature": None}})
    frun.update({"status": "ABORTED", "current_node": None, "resume_deadline": None,
                 "status_reason": "測試負責人中止：staging 停機，重測改排下一個 run"})
    frun["gate_records"] = [g for g in frun["gate_records"] if g["gate_record_id"] is not None]
    ck = doc(b, "checkpoint-metadata.followup.example.json").data
    ck.update({"run_status": "ABORTED", "pending_interrupt": None})


@variant
def v_suspend(b: Bundle, keys) -> None:
    """The two remaining paths of the follow-up run (BL-60 follow-up):
    - nobody decides G4 within its 72 h timeout: the Gate Service writes an unsigned EXPIRED record and the run is
      SUSPENDED (docs/02 §1.4), resumable from its checkpoint; there is no run_end anchor, because the run has not ended;
    - the ASI09 spot check recorded in this run overturns the initial run's G5 decision (item_kind g5), so every run of
      the engagement that starts after it needs two security reviewers at G5 (checks.g5_escalation)."""
    log = doc(b, "audit-event.run-2026-10-07-001.example.jsonl")
    sc = next(e for e in log.data if e["event_type"] == "spot_check_result")
    # heidi approved GR-G5-0001 and erin initiated its run, so neither may check it: grace becomes a security reviewer
    reg = doc(b, "key-registry.yaml").data
    for e in reg["entries"]:
        if e["person_id"] == "grace":
            e["roles"] = sorted(set(e["roles"]) | {"security_reviewer"})
    doc(b, "roe.yaml").data["gate_approvers"].append({"person_id": "grace", "role": "security_reviewer", "key_fingerprint": fp(keys, "grace")})
    sc["actor"] = {"kind": "human", "id": "grace"}
    sc["payload"] = {"item_kind": "g5", "item_id": "GR-G5-0001", "outcome": "overturned",
                     "note": "ASI09 抽查（06 §1.1）：重看 GR-G5-0001 的 S2 主動掃描，回應證據不足以支持核准時的安全判斷；之後的 G5 需要兩位資安審查者"}
    g4 = copy.deepcopy(doc(b, "gate-record.followup.g3.example.json").data)
    main_g4 = doc(b, "gate-record.g4.example.json").data
    # the G4 reviewer (erin) claims the run before G4 opens, as in the initial run (E-G4-INITIATOR)
    _append(log, 19, {"event_type": "initiator_claim", "node": "claim_run", "ts": "2026-10-07T10:25:00+08:00",
                      "key": "initiator_claim:erin", "actor": {"kind": "human", "id": "erin"},
                      "payload": {"person_id": "erin", "role": "security_reviewer"}})
    frun0 = doc(b, "run.followup.example.json").data
    frun0["initiators"] = sorted(set(frun0.get("initiators") or []) | {"erin"})
    g4.update({"gate_record_id": "GR-G4-0002", "gate": "G4", "approvers": copy.deepcopy(main_g4["approvers"]), "outcome": "EXPIRED",
               "decisions": [{"item_id": "TC-012-01", "item_sha256": None, "decision": "needs_info", "risk_override": None,
                              "note": "逾時：沒有人在 72 小時內決定", "carried_from": None}],
               "opened_at": "2026-10-07T10:30:00+08:00", "timestamp": "2026-10-10T10:30:00+08:00", "signatures": []})
    g4["artifact"] = {"kind": "test_plan", "sha256": None}
    add(b, f"{EX}gate-record.followup.g4.example.json", "gate-record", g4)
    n = len(log.data)
    _append(log, n,
            {"event_type": "gate_decision", "node": "G4", "ts": "2026-10-10T10:30:00+08:00", "key": "gate_decision:GR-G4-0002",
             "actor": {"kind": "system", "id": "gate-service"},
             "payload": {"gate": "G4", "gate_record_id": "GR-G4-0002", "outcome": "EXPIRED", "gate_record_sha256": None}},
            {"event_type": "audit_anchor", "node": "G4", "ts": "2026-10-10T10:30:00+08:00", "key": "audit_anchor:g4-expired",
             "payload": {"reason": "gate_decision", "anchor_counter": 0, "z3_countersignature": None}},
            {"event_type": "run_status_changed", "node": "G4", "ts": "2026-10-10T10:30:00+08:00", "key": "run_status_changed:suspended",
             "payload": {"from": "WAITING_GATE", "to": "SUSPENDED", "reason": "G4 逾時（72 小時）未決定"}},
            {"event_type": "audit_anchor", "node": "G4", "ts": "2026-10-10T10:30:00+08:00", "key": "audit_anchor:suspended",
             "payload": {"reason": "phase_end", "anchor_counter": 0, "z3_countersignature": None}})
    frun = doc(b, "run.followup.example.json").data
    for g in frun["gate_records"]:
        if g["gate"] == "G4" and g["gate_record_id"] is None:
            g.update({"gate_record_id": "GR-G4-0002", "outcome": "EXPIRED", "decided_at": "2026-10-10T10:30:00+08:00"})
    frun.update({"status": "SUSPENDED", "status_reason": "G4 逾時未決定；由 run_owner 或發起者在委任到期前 resume，resume 時 G0b 重驗"})
    ck = doc(b, "checkpoint-metadata.followup.example.json").data
    ck.update({"run_status": "SUSPENDED"})


@variant
def v_regression(b: Bundle, keys) -> None:
    """The regression path (review r12, docs/02 §1.6, 05 §4.2 R14 / R16): the follow-up run becomes a `regression` run.
    Its carried cluster K-301 (from K-005, CONFIRMED_EXECUTABLE in the initial run) is first adjudicated at W3 with no
    evidence of its own, so R16 keeps the source's status (fix_unverified). erin claims the run and approves the re-run of
    TC-012-01 at G4, the B4 job passes with its controls, and B5 re-adjudicates K-301 as FIXED (R14: a qualified PASS
    with a positive control, the source's executable proof re-run, no tool signal, no weighted refute). The run is still
    RUNNING (B6 has not started), so it has no report yet."""
    from vchlib import checks
    from vchlib.checks import content_hash
    rid = "run-2026-10-07-001"
    log = doc(b, "audit-event.run-2026-10-07-001.example.jsonl")
    log.data[0]["payload"]["run_kind"] = "regression"                      # run_created pins it (E-RUN-COMMIT)
    frun = doc(b, "run.followup.example.json").data
    frun["run_kind"] = "regression"
    # r13: the regression path is G1 -> W1 -> W4 (docs/02 §1.6); W1 re-scans before anything at W3 (E-GATE-ORDER)
    frun["tool_versions"] = frun.get("tool_versions", []) + [copy.deepcopy(next(
        t for t in doc(b, "run.example.json").data["tool_versions"] if t["adapter"] == "opengrep:scan"))]   # E-RUN-CONFIG
    _append(log, 11,
            {"event_type": "tool_invocation_start", "node": "W1", "ts": "2026-10-07T10:01:40+08:00", "key": "inv-w1-opengrep-002:start",
             "zone": "Z2", "payload": {"adapter": "opengrep:scan", "tool_version": "1.6.0", "invocation_id": "inv-w1-opengrep-002"}},
            {"event_type": "tool_invocation_end", "node": "W1", "ts": "2026-10-07T10:01:50+08:00", "key": "inv-w1-opengrep-002:end",
             "zone": "Z2", "payload": {"adapter": "opengrep:scan", "tool_version": "1.6.0", "invocation_id": "inv-w1-opengrep-002",
                                       "ok": True, "results": 0, "format": "sarif-2.1.0", "sarif_results": []}})
    # erin claims the run before G4 opens (E-G4-INITIATOR), and W3 writes K-301's first version after G3
    _append(log, 21,
            {"event_type": "initiator_claim", "node": "claim_run", "ts": "2026-10-07T10:25:00+08:00",
             "key": "initiator_claim:erin", "actor": {"kind": "human", "id": "erin"},
             "payload": {"person_id": "erin", "role": "security_reviewer"}},
            {"event_type": "verdict_changed", "node": "W3", "ts": "2026-10-07T10:26:00+08:00", "key": "verdict_changed:V-301-1",
             "actor": {"kind": "system", "id": "aggregator"}, "payload": {"verdict_id": "V-301-1", "status": None, "verdict_sha256": None}})
    frun["initiators"] = sorted(set(frun.get("initiators") or []) | {"erin"})
    # B0 of this run: the ownership check B4_preflight needs (copied from the initial run's batch)
    main_log = doc(b, "audit-event.run-2026-09-23-001.example.jsonl")
    own = copy.deepcopy(next(e for e in main_log.data if e["event_type"] == "ownership_check"))
    own["payload"]["batch_id"] = "own-2026-10-07-1"
    # r14 (A4): target activity waits for the ROE window (Tue 20:00-23:00), so the check runs while the run waits at G4
    waiting = next(i for i, e in enumerate(log.data, 1) if e["event_type"] == "run_status_changed" and e["payload"].get("to") == "WAITING_GATE")
    _append(log, waiting + 1, {"event_type": "ownership_check", "node": "B0", "ts": "2026-10-07T20:30:00+08:00", "key": "ownership_check:own-2026-10-07-1",
                      "actor": own["actor"], "zone": own["zone"], "payload": own["payload"]})
    frun["ownership_results"] = [dict(o, batch_id="own-2026-10-07-1", checked_at="2026-10-07T20:30:00+08:00")
                                 for o in doc(b, "run.example.json").data["ownership_results"]]
    main_g4 = doc(b, "gate-record.g4.example.json").data
    g4 = copy.deepcopy(main_g4)
    g4.update({"gate_record_id": "GR-G4-0002", "run_id": rid, "round": 1, "outcome": "APPROVED",
               "decisions": [{"item_id": "TC-012-01", "item_sha256": None, "decision": "accept", "risk_override": None,
                              "note": "回歸：重跑來源的可執行證明", "carried_from": None}],
               "opened_at": "2026-10-07T10:30:00+08:00", "timestamp": "2026-10-08T10:00:00+08:00", "signatures": []})
    g4["artifact"] = {"kind": "test_plan", "sha256": None}
    add(b, f"{EX}gate-record.followup.g4.example.json", "gate-record", g4)
    res = copy.deepcopy(doc(b, "testresult.example.json").data)
    res.update({"result_id": "R-TC-012-01-2", "run_id": rid, "job_id": "job-idor-002", "executed_at": "2026-10-08T20:30:00+08:00",
                "cluster_ids": ["K-301"], "outcome": "PASS", "fail_oracles": [], "trials": {"n": 1, "k": 0, "n_effective": 1},
                "replays": 0, "replay_k": 0, "observed_build_id": frun["repo_commit"][:12],
                "oracle_observations": ["對照 CTL-01（A 讀自己的發票）與 CTL-02（oracle 在 B 的合法回應上判定命中）都 PASS",
                                        "GET 回應 404，body 不含 B 的發票欄位：修正後不再違反 REQ-ASVS-8.2.2、INV-AC-007"],
                "interpretation": {"agrees": True, "rationale": "tenantA_user 讀 tenant_b_invoice 得到 404；正對照證明 oracle 能判定命中"}})
    add(b, f"{EX}testresult.regression.example.json", "testresult", res)
    n = len(log.data)
    _append(log, n,
            {"event_type": "gate_decision", "node": "G4", "ts": "2026-10-08T10:00:00+08:00", "key": "gate_decision:GR-G4-0002",
             "actor": {"kind": "system", "id": "gate-service"},
             "payload": {"gate": "G4", "gate_record_id": "GR-G4-0002", "outcome": "APPROVED", "gate_record_sha256": None}},
            {"event_type": "audit_anchor", "node": "G4", "ts": "2026-10-08T10:00:00+08:00", "key": "audit_anchor:g4",
             "payload": {"reason": "gate_decision", "anchor_counter": 0, "z3_countersignature": None}},
            {"event_type": "run_status_changed", "node": "G4", "ts": "2026-10-08T10:00:00+08:00", "key": "run_status_changed:running",
             "payload": {"from": "WAITING_GATE", "to": "RUNNING"}},
            {"event_type": "sandbox_job_start", "node": "B4", "ts": "2026-10-08T20:30:00+08:00", "key": "sandbox_job_start:job-idor-002",
             "actor": {"kind": "system", "id": "z3-executor"}, "zone": "Z3", "payload": {"job_id": "job-idor-002"}},
            {"event_type": "sandbox_job_end", "node": "B4", "ts": "2026-10-08T20:40:00+08:00", "key": "sandbox_job_end:job-idor-002",
             "actor": {"kind": "system", "id": "z3-executor"}, "zone": "Z3",
             "payload": {"job_id": "job-idor-002", "outcome": "PASS", "testcase_sha256": None, "artifact_sha256": res["artifact_sha256"]}},
            {"event_type": "verdict_changed", "node": "B5", "ts": "2026-10-08T21:00:00+08:00", "key": "verdict_changed:V-301-2",
             "actor": {"kind": "system", "id": "aggregator"}, "payload": {"verdict_id": "V-301-2", "status": None, "verdict_sha256": None}},
            {"event_type": "audit_anchor", "node": "B5", "ts": "2026-10-08T21:00:00+08:00", "key": "audit_anchor:b5",
             "payload": {"reason": "phase_end", "anchor_counter": 0, "z3_countersignature": None}})
    for g in frun["gate_records"]:
        if g["gate"] == "G4" and g["gate_record_id"] is None:
            g.update({"gate_record_id": "GR-G4-0002", "outcome": "APPROVED", "decided_at": "2026-10-08T10:00:00+08:00"})
    frun.update({"status": "RUNNING", "status_reason": None, "current_node": "B6", "resume_deadline": None,
                 "approved_testcase_ids": ["TC-012-01"], "executed_jobs": ["job-idor-002"], "testresults": ["R-TC-012-01-2"],
                 "verdicts": ["V-301-1", "V-301-2"]})
    frun["jobs"] = {"job-idor-002": {"job_id": "job-idor-002", "testcase_id": "TC-012-01", "safety_class": "S1",
                                     "target_id": "tgt-staging-api", "status": "EXECUTED", "g5_record_id": None, "snapshot_ref": None,
                                     "restore_verified": False, "result_ref": None, "skip_reason": None}}
    ck = doc(b, "checkpoint-metadata.followup.example.json").data
    ck.update({"run_status": "RUNNING", "pending_interrupt": None})
    # the two versions of K-301, each decided by the reference adjudicator on what the run holds at that point
    base = doc(b, "verdict.example.json").data
    v1 = copy.deepcopy(base)
    v1.update({"verdict_id": "V-301-1", "cluster_id": "K-301", "readjudicated_by": "W3_adjudicate", "supersedes_verdict_id": None,
               "votes": [], "missing_votes": [], "test_evidence": {"class": None, "results": []}})
    v2 = copy.deepcopy(v1)
    v2.update({"verdict_id": "V-301-2", "readjudicated_by": "B5_readjudicate", "supersedes_verdict_id": "V-301-1",
               "test_evidence": {"class": "E_pass", "results": [{"result_ref": None, "class": "E_pass", "positive_control": True,
                                                                 "reason": "回歸 PASS，正對照通過"}]}})
    add(b, f"{EX}verdict.k-301-w3.example.json", "verdict", v1)
    add(b, f"{EX}verdict.k-301-b5.example.json", "verdict", v2)
    resign(b, keys)
    v2["test_evidence"]["results"][0]["result_ref"] = content_hash(res)
    for v in (v1, v2):
        c = checks.Ctx(b)
        cl = c.ix.first("cluster", cluster_id="K-301").data
        out = checks.adj.adjudicate(checks.verdict_inputs(c, v, cl))
        v.update({"status": out.status, "status_cap": out.status_cap, "advisory": out.advisory,
                  "annotations": [{"kind": k, "reason": k} for k in sorted(out.annotations)],
                  "rule_trace": [f"{r}: regression run 的帶入叢集 K-301（來源 K-005）" for r in out.rules],
                  "independent_sources": checks.derived_independent_sources(c, v, cl),
                  "tool_corroboration": checks.derived_tool_corroboration(c, v, cl),
                  "tool_signal": checks.derived_tool_signal(c, v, cl),
                  "diversity_degraded": checks.derived_diversity_degraded(c, v, cl),
                  "no_eligible_verifier": checks.derived_no_eligible_verifier(c, cl),
                  "provisional": checks.derived_provisional(c, v, cl)})
        next(e for e in log.data if e["event_type"] == "verdict_changed"
             and e["payload"]["verdict_id"] == v["verdict_id"])["payload"]["status"] = out.status
        resign(b, keys)


# ---------------------------------------------------------------- overlay
def overlay(name: str, keys) -> tuple[dict[str, str], list[str], Bundle]:
    base = load_bundle(ROOT)
    b = load_bundle(ROOT)
    b.variant = name
    VARIANTS[name](b, keys)
    resign(b, keys)
    base_by = {d.path: d for d in base.docs}
    files = {}
    for d in b.docs:
        old = base_by.get(d.path)
        if old is not None and old.data == d.data:
            continue
        files[d.path] = dump(d)
    removed = sorted(set(base_by) - {d.path for d in b.docs})
    return files, removed, b


def write_overlay(name: str, files: dict, removed: list, check: bool) -> bool:
    vdir = ROOT / VARIANTS_DIR / name
    want = dict(files)
    want["removed.txt"] = "# main-bundle files this variant drops (BL-60; generated by tools/build_variants.py)\n" + \
        "".join(r + "\n" for r in removed)
    have = {p.relative_to(vdir).as_posix(): p.read_text(encoding="utf-8")
            for p in vdir.rglob("*") if p.is_file() and p.name != "README.md"} if vdir.is_dir() else {}
    if check:
        return have == want
    for rel in set(have) - set(want):
        (vdir / rel).unlink()
    for rel, text in want.items():
        p = vdir / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        if not p.exists() or p.read_text(encoding="utf-8") != text:
            p.write_text(text, encoding="utf-8", newline="\n")
    return True


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--check", action="store_true")
    ap.add_argument("names", nargs="*", help="variants to build (default: all)")
    args = ap.parse_args(argv)
    keys = S.load_keys()
    bad = 0
    for name in args.names or sorted(VARIANTS):
        files, removed, b = overlay(name, keys)
        errs = run_all(b).errors
        for i in errs[:20]:
            print(f"{name}: ERROR {i.code} {i.where}: {i.msg}")
        ok = write_overlay(name, files, removed, args.check)
        print(f"variant {name}: {len(files)} file(s) replaced or added, {len(removed)} removed, {len(errs)} error(s)"
              + ("" if ok else " — overlay is stale; run python tools/build_variants.py"))
        bad += bool(errs) or not ok
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
