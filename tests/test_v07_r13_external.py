# SPDX-License-Identifier: Apache-2.0
"""Third external review, of main@6f50a79 (docs/evidence/review-2026-10-29-r13.md), the findings that held on re-run:

  1. run_transitions only checked that each run_status_changed `from` matched the previous `to`, so a terminal state
     could be left (RUNNING -> ABORTED -> RUNNING, then the B phase) and work could run while the run was not RUNNING.
  2. run_structure ordered the gates among themselves and W4 after G2, so W1 scanned, or W3 adjudicated, before G1
     approved the invariants.
  3. canonical._canon printed an integer-valued double at or above 2^53 as its exact binary value
     (1000000000000000100.0 -> "1000000000000000128"), unlike RFC 8785's reference and JavaScript.
  4. The gate timeout (a deadline for a HUMAN decision) was applied to the system's EXPIRED record too, so an honest
     EXPIRED one second after the deadline was E-GATE-TIMEOUT.
  5-9. Specification: MVP-0 excluded Z3 while every anchor needs its countersignature (user: a minimal countersign
     service in MVP-0); the Lite "confirm once" contract; a USD cap called fail-closed on unknown-priced cloud models
     (user: refuse by default, allow a conservative price bound, E-ENG-PRICING); calibration intervals ignoring the
     correlation of one application's clusters (user: n_apps >= 10 and a design-effect n_eff, rule_version 05-v0.14);
     two stale sentences.
Each test failed before the change and passes after it (tests/mutations/r13_external.json); see CONTRIBUTING.md."""
import copy
import datetime as dt
import pathlib
import random
import re
import struct

import pytest

from conftest import doc, rederive
from test_v07_r11_anchor import renumber
from vchlib import adjudicate as adj
from vchlib import checks
from vchlib.bundle import load_variant
from vchlib.canonical import jcs
from vchlib.checks import run_all

ROOT = pathlib.Path(__file__).resolve().parents[1]
MRUN, MAUDIT = "run.example.json", "audit-event.run-2026-09-23-001.example.jsonl"
FAUDIT = "audit-event.run-2026-10-07-001.example.jsonl"


def text(rel):
    return (ROOT / rel).read_text(encoding="utf-8")


def errors(b, code):
    return [i for i in run_all(b).errors if i.code == code]


def msgs(b, code):
    return [i.msg for i in errors(b, code)]


def insert(log, idx, **ev):
    """Insert one event before index idx, cloned from the line before it (seq and hashes are rebuilt by rederive)."""
    base = copy.deepcopy(log.data[idx - 1] if idx else log.data[0])
    base.update({"payload_refs": [], "signature": None, "actor": {"kind": "system", "id": "run-controller"}, "zone": "Z1"})
    base.update(ev)
    base["idempotency_key"] = f"{base['run_id']}:{base['node']}:{base['event_type']}:r13:{idx}:{len(log.data)}"
    log.data.insert(idx, base)
    renumber(log)


def first_index(log, **match):
    return next(i for i, e in enumerate(log.data) if all(
        (e.get("payload") or {}).get(k[2:]) == v if k.startswith("p_") else e.get(k) == v for k, v in match.items()))


# ================================================================ 1. run status transitions
def test_a_terminal_state_is_never_left(b, keys):
    log = doc(b, MAUDIT)
    i = first_index(log, node="B0")
    ts0, node0 = log.data[i]["ts"], log.data[i]["node"]
    insert(log, i, event_type="run_status_changed", node=node0, ts=ts0, payload={"from": "RUNNING", "to": "ABORTED"})
    insert(log, i + 1, event_type="run_status_changed", node=node0, ts=ts0, payload={"from": "ABORTED", "to": "RUNNING"})
    rederive(b, keys)
    assert any("ABORTED -> 'RUNNING' is not a legal transition" in m for m in msgs(b, "E-RUN-STATUS"))


def test_work_only_happens_while_the_run_is_running(b, keys):
    log = doc(b, MAUDIT)
    i = first_index(log, event_type="sandbox_job_start", node="B4")
    insert(log, i, event_type="run_status_changed", node="B4", ts=log.data[i]["ts"], payload={"from": "RUNNING", "to": "WAITING_GATE"})
    rederive(b, keys)
    assert any("sandbox_job_start while the run is WAITING_GATE" in m for m in msgs(b, "E-RUN-STATUS"))


def test_a_gate_is_decided_while_running_or_waiting(b, keys):
    log = doc(b, MAUDIT)
    i = first_index(log, event_type="gate_decision", p_gate="G4")
    insert(log, i, event_type="run_status_changed", node="G4", ts=log.data[i]["ts"], payload={"from": "RUNNING", "to": "SUSPENDED"})
    rederive(b, keys)
    assert any("gate_decision while the run is SUSPENDED" in m for m in msgs(b, "E-RUN-STATUS"))


def doc_transitions():
    s = text("docs/02-methodology.md").split("**合法轉移**", 1)[1].split("**W 階段的前置條件**", 1)[0]
    out = {}
    for src, dsts in re.findall(r"^\| (.+?) \| (.+?) \|$", s, re.M):
        if src == "來源":
            continue
        targets = tuple(re.findall(r"`([A-Z_]+)`", dsts))
        for state in re.findall(r"`([A-Z_]+)`", src):
            out[state] = targets
    return out


def test_the_transition_table_in_the_docs_is_the_validators():
    table = doc_transitions()
    assert table and table == {k: tuple(v) for k, v in checks.RUN_TRANSITIONS.items()}
    assert all(not checks.RUN_TRANSITIONS[s] for s in checks.TERMINAL_RUN_STATES)


# ================================================================ 2. the white-box phase follows G1, W1 first
def move_w_nodes_before_g1(log, nodes, hours=2):
    g1 = first_index(log, event_type="gate_decision", p_gate="G1")
    idx = [i for i, e in enumerate(log.data) if e.get("node") in nodes and i > g1]
    evs = [log.data[i] for i in idx]
    for i in sorted(idx, reverse=True):
        log.data.pop(i)
    g1 = first_index(log, event_type="gate_decision", p_gate="G1")
    t = dt.datetime.fromisoformat(log.data[g1]["ts"]) - dt.timedelta(hours=hours)
    for k, ev in enumerate(evs):
        ev["ts"] = (t + dt.timedelta(seconds=k)).isoformat()
        log.data.insert(g1 + k, ev)
    renumber(log)


def test_w1_cannot_scan_before_g1_approves(b, keys):
    move_w_nodes_before_g1(doc(b, MAUDIT), ("W1",))
    rederive(b, keys)
    assert any("node W1 without an APPROVED G1 before it" in m for m in msgs(b, "E-GATE-ORDER"))


def test_w3_cannot_adjudicate_before_g1_approves(b, keys):
    move_w_nodes_before_g1(doc(b, MAUDIT), ("W1", "W2", "W3"))
    rederive(b, keys)
    assert any("node W3 without an APPROVED G1 before it" in m for m in msgs(b, "E-GATE-ORDER"))


def test_w3_follows_the_first_w1_event(b, keys):
    log = doc(b, MAUDIT)
    w1 = first_index(log, node="W1")
    w3 = first_index(log, node="W3")
    ev = log.data.pop(w3)
    ev["ts"] = (dt.datetime.fromisoformat(log.data[w1]["ts"]) - dt.timedelta(minutes=1)).isoformat()
    log.data.insert(w1, ev)
    renumber(log)
    rederive(b, keys)
    assert any("node W3 before the first W1 event" in m for m in msgs(b, "E-GATE-ORDER"))


def test_a_lane_a_run_has_no_g1_and_still_validates(b):
    lane = doc(b, "run.lane-a.example.json").data
    assert lane["run_kind"] == "lane_a" and run_all(b).errors == []


def test_the_phase_prerequisites_are_documented():
    s = text("docs/02-methodology.md")
    assert "**W 階段的前置條件**" in s and "`checks.G1_GATED_NODES`" in s
    assert checks.G1_GATED_NODES == ("W1", "W2", "W3", "W4", "W5") and checks.AFTER_W1_NODES == ("W2", "W3", "W4", "W5")


# ================================================================ 3. JCS numbers at and above 2^53
@pytest.mark.parametrize("value, expected", [
    (1000000000000000100.0, b"1000000000000000100"),
    (-1000000000000000100.0, b"-1000000000000000100"),
    (1.2345678901234568e+20, b"123456789012345680000"),
    (1234567890123456789.0, b"1234567890123456800"),
    (9007199254740993.0, b"9007199254740992"),
    (9007199254740991.0, b"9007199254740991"),
    (1e21, b"1e+21"),
])
def test_integer_valued_doubles_print_their_shortest_digits(value, expected):
    assert jcs(value) == expected


def test_the_vectors_cover_the_boundary():
    assert any(1000000000000000100.0 in v for v, _ in checks.JCS_VECTORS if isinstance(v, list))


def test_random_doubles_agree_with_the_reference():
    rfc8785 = pytest.importorskip("rfc8785")
    rng = random.Random(13)
    seen = 0
    for _ in range(20000):
        k = rng.random()
        if k < 0.3:
            x = float(rng.randint(2 ** 53, 10 ** 21))
        elif k < 0.5:
            x = struct.unpack("<d", struct.pack("<Q", rng.getrandbits(64)))[0]
        elif k < 0.7:
            x = rng.uniform(-1e22, 1e22)
        else:
            x = rng.random() * 10 ** rng.randint(-30, 30)
        if x != x or x in (float("inf"), float("-inf")):
            continue
        seen += 1
        assert jcs(x) == rfc8785.dumps(x), repr(x)
    assert seen > 19000


# ================================================================ 4. the timeout is the human deadline
def delay_expired_g4(s, delta):
    log = doc(s, FAUDIT)
    i = first_index(log, event_type="gate_decision", p_gate="G4", p_outcome="EXPIRED")
    for e in log.data[i:]:
        e["ts"] = (dt.datetime.fromisoformat(e["ts"]) + delta).isoformat()
    renumber(log)
    rec = doc(s, "gate-record.followup.g4.example.json").data
    rec["timestamp"] = (dt.datetime.fromisoformat(rec["timestamp"]) + delta).isoformat()
    for g in doc(s, "run.followup.example.json").data["gate_records"]:
        if g.get("gate_record_id") == rec["gate_record_id"]:
            g["decided_at"] = rec["timestamp"]


@pytest.mark.parametrize("delta", [dt.timedelta(seconds=1), dt.timedelta(hours=1)])
def test_an_expired_record_written_after_the_deadline_is_honest(keys, delta):
    s = load_variant(ROOT, "suspend")
    delay_expired_g4(s, delta)
    rederive(s, keys)
    assert errors(s, "E-GATE-TIMEOUT") == [] and run_all(s).errors == []


def test_a_human_decision_after_the_deadline_is_still_late(b, keys):
    doc(b, "engagement.yaml").data["gate_timeouts_hours"]["G4"] = 12          # the example's G4 took 23 h
    rederive(b, keys)
    assert any("decided" in m for m in msgs(b, "E-GATE-TIMEOUT"))


def test_an_expired_record_before_the_deadline_is_still_early(keys):
    s = load_variant(ROOT, "suspend")
    delay_expired_g4(s, dt.timedelta(hours=-1))
    rederive(s, keys)
    assert errors(s, "E-GATE-EXPIRED-EARLY")


# ================================================================ 7. unknown-priced cloud models
def test_an_unknown_priced_cloud_model_needs_a_price_assumption(b):
    del doc(b, "engagement.yaml").data["budgets"]["price_assumptions"]["gpt_flagship"]
    assert any("model gpt_flagship is a cloud model with pricing null" in m for m in msgs(b, "E-ENG-PRICING"))


def test_a_self_hosted_model_needs_no_price(b):
    assert any(m.get("hosting") == "self" and m.get("pricing") is None for m in doc(b, "models.yaml").data.values())
    assert errors(b, "E-ENG-PRICING") == []


def test_a_cloud_model_turned_self_hosted_needs_no_assumption(b):
    doc(b, "models.yaml").data["gpt_flagship"]["hosting"] = "self"
    del doc(b, "engagement.yaml").data["budgets"]["price_assumptions"]["gpt_flagship"]
    assert errors(b, "E-ENG-PRICING") == []                              # the changed registry is E-ENG-CONFIG-PIN, not pricing


@pytest.mark.parametrize("price", [0, -1, None])
def test_a_price_bound_must_be_positive(b, price):
    doc(b, "engagement.yaml").data["budgets"]["price_assumptions"]["gpt_flagship"]["output_usd_per_mtok"] = price
    assert any("output_usd_per_mtok must be a positive unit price" in m for m in msgs(b, "E-ENG-PRICING"))


def test_a_price_assumption_names_a_model(b):
    doc(b, "engagement.yaml").data["budgets"]["price_assumptions"]["gpt_99"] = {"input_usd_per_mtok": 1, "output_usd_per_mtok": 1, "source": "x"}
    assert any("price_assumptions.gpt_99: unknown model" in m for m in msgs(b, "E-ENG-PRICING"))


def test_the_fallback_chain_counts(b):
    # nemotron_cloud is used by no agent; it is reached only as claude_sonnet's models.yaml fallback
    doc(b, "models.yaml").data["claude_sonnet"]["fallback"] = ["nemotron_cloud"]
    assert any("model nemotron_cloud is a cloud model" in m for m in msgs(b, "E-ENG-PRICING"))


def test_hosting_is_required_by_the_schema(b):
    del doc(b, "models.yaml").data["gpt_flagship"]["hosting"]
    assert any("hosting" in i.msg for i in run_all(b).errors if i.code.startswith("E-SCHEMA"))


# ================================================================ 8. calibration intervals and the applications behind them
def test_effective_n_is_the_design_effect_adjusted_count():
    assert abs(checks.effective_n(64, 16) - 64 / 1.15) < 1e-9 and checks.effective_n(40, 40) == 40 and checks.effective_n(0, 0) == 0


def test_a_feasible_threshold_needs_ten_applications(b):
    cal = doc(b, "calibration.yaml").data
    cal["result"]["thresholds"]["theta_confirm"]["calibration"]["n_apps"] = 9
    assert any("theta_confirm" in label and "clustering.min_apps 10" in m for label, m in checks.theta_problems(cal))


def test_the_bounds_shrink_with_fewer_applications(b):
    cal = doc(b, "calibration.yaml").data
    cs = cal["result"]["thresholds"]["theta_confirm"]["calibration"]
    cs["n_apps"] = 12                                                     # 64 clusters from 12 apps: n_eff 52.6, lower 0.817
    problems = [m for _, m in checks.split_problems("theta_confirm", "calibration", cs)]
    assert any("calibration.ci_low" in m and f"n_eff {checks.effective_n(64, 12):.2f}" in m for m in problems)


def test_the_example_bounds_are_recomputed_on_n_eff(b):
    assert checks.theta_problems(doc(b, "calibration.yaml").data) == []
    cal = doc(b, "calibration.yaml").data
    cs = cal["result"]["thresholds"]["theta_confirm"]["calibration"]
    assert cs["n_apps"] == 16 and cs["ci_low"] == round(checks.wilson_lower(59 / 64 * checks.effective_n(64, 16), checks.effective_n(64, 16)), 4)


def test_the_clustering_policy_is_pinned(b):
    cal = doc(b, "calibration.yaml").data
    cal["config"]["clustering"]["icc"] = 0.0
    assert any("clustering.icc" in p for p in checks.policy_problems(cal["config"]))
    cal["config"]["clustering"] = {"min_apps": 3, "icc": 0.05}
    assert any("clustering.min_apps" in p for p in checks.policy_problems(cal["config"]))
    assert checks.CAL_POLICY["clustering"] == {"min_apps": 10, "icc": 0.05}


def hp_row(n, tp, apps, h_apps=10):
    return {"adapter": "opengrep:scan", "rule_id": "r", "tool_version": "1", "cwe_bucket": "authz", "n": n, "tp": tp, "fp": n - tp,
            "precision_lower95": round(checks.clopper_pearson_lower(tp / n * checks.effective_n(n, apps), checks.effective_n(n, apps)), 4),
            "holdout_n": 10, "holdout_tp": 10, "n_apps": apps, "holdout_n_apps": h_apps}


def test_forty_hits_from_ten_applications_are_not_forty_observations():
    assert checks.high_precision_problems(hp_row(40, 40, 40), 0.9) == []                 # one hit per application: as before
    assert any("lower bound" in p for p in checks.high_precision_problems(hp_row(40, 40, 10), 0.9))
    assert checks.high_precision_problems(hp_row(41, 41, 10), 0.9) == []
    assert any("n_apps 9 < clustering.min_apps 10" in p for p in checks.high_precision_problems(hp_row(41, 41, 9), 0.9))


def test_clopper_pearson_still_matches_the_binomial_tail_on_integers():
    import math
    for n, k in ((40, 40), (54, 53), (70, 68), (10, 3)):
        want = next(p for p in (i / 100000 for i in range(100000)) if sum(math.comb(n, j) * p ** j * (1 - p) ** (n - j) for j in range(k, n + 1)) >= 0.025)
        assert abs(checks.clopper_pearson_lower(k, n) - want) < 2e-5


def test_the_rule_version_is_05_v0_14(b):
    assert adj.RULE_VERSION == "05-v0.14"
    assert {d.data.get("rule_version") for d in b.docs if d.kind in ("verdict", "run")} == {"05-v0.14"}


# ================================================================ 5, 6, 9. the specification
def test_mvp0_ships_the_anchor_countersign_service():
    row = next(ln for ln in text("docs/07-roadmap.md").splitlines() if ln.startswith("| **MVP-0"))
    assert "最小錨點副簽服務" in row and "| Z3、G0b" not in row
    assert "### 11.19 錨點副簽服務（MVP-0 的最小 Z3）" in text("docs/08-implementation-spec.md")
    assert "最小錨點副簽服務（鏈重算、編號）在 MVP-0" in text("docs/09-backlog.md")


def test_the_lite_contract_names_the_decisions_of_each_run():
    s = text("docs/07-roadmap.md").split("### 1.3", 1)[1].split("\n### ", 1)[0]
    assert "**首次**" in s and "**每次 run**" in s and "| G1 |" in s and "| G2 |" in s and "使用者只需確認一次" not in s


def test_the_cost_cap_is_enforced_only_with_a_price():
    s = text("docs/08-implementation-spec.md")
    assert "USD 上限只能對有單價的模型強制" in s and "依假設上界估算" in s and "報告註明「費用不完整」" not in s


def test_the_stale_sentences_are_gone():
    assert "由投票決定的裁決都是暫定的" in text("docs/00-overview.md")
    assert "validator 還沒檢查。" not in text("docs/08-implementation-spec.md")


def test_the_calibration_doc_defines_n_eff():
    s = text("docs/05-bias-calibration.md")
    assert "n_eff＝n／DE" in s and "`n_apps` ≥ `clustering.min_apps`（10）" in s
