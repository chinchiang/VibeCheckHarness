# SPDX-License-Identifier: Apache-2.0
"""Review round 8, group 5: the worked example and the process evidence. Each defect test fails on the PR3 head.

- audit events name a node of the design (no W6); run.w4_results is derived; repo_commit is a full SHA;
- the mutation lists under tests/mutations still match the source (tools/mutation_check.py --anchors-only);
- the lock file pins every direct dependency of requirements.txt.
"""
import json
import pathlib
import re

from conftest import doc, rederive
from vchlib.checks import run_all

ROOT = pathlib.Path(__file__).resolve().parents[1]
AUDIT = "audit-event.run-2026-09-23-001.example.jsonl"


def errors(b, code, where=None):
    return [i for i in run_all(b).errors if i.code == code and (where is None or where in i.where)]


def test_no_event_sits_on_a_node_outside_the_design(b):
    nodes = {e["node"] for d in b.docs if d.kind == "audit-event" for e in d.data}
    assert "W6" not in nodes and nodes <= {"START", "END", "claim_run", "feedback", "W0", "W0.5", "W1", "W2", "W3", "W4", "W5",
                                           "B0", "B1", "B2", "B3", "B4", "B5", "B6", "G0a", "G0b", "G1", "G2", "G3", "G4", "G5", "GB",
                                           "abort_handler", "resume"} | {n for n in nodes if re.match(r"^CMD-[1-9][0-9]*$", str(n))}


def test_an_unknown_node_is_a_schema_error(b, keys):
    doc(b, AUDIT).data[32]["node"] = "W6"
    rederive(b, keys)
    assert errors(b, "E-SCHEMA", AUDIT)


def test_budget_exhausted_precedes_the_g2_decision(b):
    evs = doc(b, AUDIT).data
    bud = next(e for e in evs if e["event_type"] == "budget_exhausted")
    g2 = next(e for e in evs if e["event_type"] == "gate_decision" and e["payload"].get("gate") == "G2")
    assert bud["node"] == "W3" and bud["seq"] < g2["seq"]


def test_w4_results_are_derived(b):
    run = doc(b, "run.example.json").data
    assert len(run["w4_results"]) == 1
    run["w4_results"] = []
    assert any("w4_results" in i.msg for i in errors(b, "E-DERIVED", "run.example"))


def test_repo_commit_is_a_full_sha(b):
    assert all(re.fullmatch(r"[0-9a-f]{40}", d.data["repo_commit"]) for d in b.docs if d.kind == "run")
    doc(b, "run.lane-a.example.json").data["repo_commit"] = "9b7e3d2"
    assert errors(b, "E-SCHEMA", "run.lane-a")


def test_mutation_lists_match_the_source():
    import importlib.util
    spec = importlib.util.spec_from_file_location("mutation_check", ROOT / "tools" / "mutation_check.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    lists = []
    for p in sorted((ROOT / "tests" / "mutations").glob("*.json")):
        s = json.loads(p.read_text(encoding="utf-8"))
        s["_name"] = p.name
        assert (ROOT / s["tests"]).exists() and s["mutations"]
        lists.append(s)
    assert lists and mod.anchor_problems(lists) == []


def test_the_lock_pins_every_direct_dependency():
    req = {re.split(r"[<>=!]", ln)[0].strip().lower() for ln in (ROOT / "requirements.txt").read_text().splitlines()
           if ln.strip() and not ln.startswith("#")}
    lock = {ln.split("==")[0].lower(): ln.split("==")[1] for ln in (ROOT / "requirements.lock").read_text().splitlines()
            if "==" in ln and not ln.startswith("#")}
    assert req <= set(lock), req - set(lock)
    assert all(re.fullmatch(r"[0-9][0-9A-Za-z.]*", v) for v in lock.values())
    assert "requirements.lock" in (ROOT / ".github" / "workflows" / "validate.yml").read_text()
