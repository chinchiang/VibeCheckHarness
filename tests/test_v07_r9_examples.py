# SPDX-License-Identifier: Apache-2.0
"""Review round 9 (docs/evidence/review-2026-10-27-r9.md), PR4: examples, robustness and stale text.
Each defect test failed on the PR3 head and passes with the fix; see CONTRIBUTING.md.

  spot check  the examples record an anchored, signed ASI09 spot check (of a verdict), so the path runs on real data;
  ids         a plan_id or dfd_id names one document, and a run has one inventory, one seed-threats document and one DFD
              per viewpoint (E-ID-DUP); a threat's DFD elements are checked against its own run's merged DFD;
  coverage    every documented path the examples do not exercise names the test that does (docs/schemas/README.md);
  stale text  the README lists every review record, 00 links the latest, 03 names every config_pins file and the
              current rule_version, 04 repeats the shared-platform list of the code, and the open backlog is in order.
"""
import ast
import copy
import json
import pathlib
import re

from conftest import doc
from vchlib import adjudicate, safety
from vchlib.bundle import Doc
from vchlib.checks import run_all

ROOT = pathlib.Path(__file__).resolve().parents[1]
RUN, FRUN = "run-2026-09-23-001", "run-2026-10-07-001"
FAUDIT = "audit-event.run-2026-10-07-001.example.jsonl"


def errors(b, code, where=None):
    return [i for i in run_all(b).errors if i.code == code and (where is None or where in i.where)]


def text(rel):
    return (ROOT / rel).read_text(encoding="utf-8")


def add_copy(b, src, name, **changes):
    data = copy.deepcopy(doc(b, src).data)
    data.update(changes)
    d = doc(b, src)
    b.docs.append(Doc(f"docs/schemas/examples/{name}", d.kind, data, json.dumps(data)))
    return data


def test_the_examples_are_clean(b):
    assert run_all(b).errors == []


# ================================================================ spot check on real data
def test_the_examples_record_an_anchored_signed_spot_check(b):
    evs = doc(b, FAUDIT).data
    last_anchor = max(i for i, e in enumerate(evs) if e["event_type"] == "audit_anchor")
    spots = [(i, e) for i, e in enumerate(evs) if e["event_type"] == "spot_check_result"]
    assert spots, "no spot_check_result in the examples"
    i, ev = spots[0]
    assert i < last_anchor and ev["signature"] is not None and ev["payload"]["item_kind"] == "verdict"


# ================================================================ ids: one document per id and per run
def test_a_second_inventory_of_a_run_is_reported(b):
    add_copy(b, "inventory.example.json", "inventory.copy.example.json")
    assert any("inventory" in i.msg for i in errors(b, "E-ID-DUP"))


def test_a_second_seed_threats_of_a_run_is_reported(b):
    add_copy(b, "seed-threats.example.json", "seed-threats.copy.example.json")
    assert any("seed-threats" in i.msg for i in errors(b, "E-ID-DUP"))


def test_a_second_redaction_map_of_a_run_is_reported(b):
    add_copy(b, "redaction-map.example.json", "redaction-map.copy.example.json")
    assert any("redaction-map" in i.msg for i in errors(b, "E-ID-DUP"))


def test_a_second_merged_dfd_of_a_run_is_reported(b):
    add_copy(b, "dfd.merged.example.json", "dfd.merged.copy.example.json", dfd_id="DFD-copy")
    assert any("dfd" in i.msg for i in errors(b, "E-ID-DUP"))


def test_a_duplicate_plan_id_is_reported(b):
    add_copy(b, "commander-plan.example.json", "commander-plan.copy.example.json")
    assert any("plan_id" in i.msg for i in errors(b, "E-ID-DUP"))


def test_a_threat_is_checked_against_its_own_runs_dfd(b):
    """Review r9 (validator) note: g_trace took the first merged DFD of the bundle, whatever its run."""
    data = copy.deepcopy(doc(b, "dfd.merged.example.json").data)
    data.update(run_id=FRUN, dfd_id="DFD-followup-merged")
    for e in data["elements"]:
        e["type"] = "external_entity"
    b.docs.insert(0, Doc("docs/schemas/examples/dfd.a-followup.merged.example.json", "dfd", data, json.dumps(data)))
    assert not errors(b, "E-TRACE-DFD")


# ================================================================ coverage of documented paths
def test_every_documented_path_names_an_existing_test():
    readme = text("docs/schemas/README.md")
    section = readme.split("### 範例沒有走過的路徑", 1)[1].split("\n## ", 1)[0]
    rows = [ln for ln in section.splitlines() if ln.startswith("| ") and not ln.startswith("| 路徑") and "---" not in ln]
    assert len(rows) >= 8
    for ln in rows:
        refs = re.findall(r"`(tests/[a-z0-9_]+\.py)::([a-z0-9_]+)`", ln)
        assert refs, ln
        for path, name in refs:
            assert f"def {name}(" in text(path), (path, name)


# ================================================================ stale text
def test_the_readme_lists_every_review_record():
    row = next(ln for ln in text("README.md").splitlines() if ln.startswith("| [docs/evidence/]"))
    for p in sorted((ROOT / "docs" / "evidence").glob("review-*.md")):
        assert f"docs/evidence/{p.name}" in row, p.name


def review_order(name):
    """review-YYYY-MM-DD[-rN].md by date, then round number (review r10: r10 sorts after r9 as text but is newer)."""
    m = re.match(r"review-(\d{4}-\d{2}-\d{2})(?:-r(\d+))?\.md$", name)
    return (m.group(1), int(m.group(2) or 0)) if m else (name, 0)


def test_the_overview_links_the_latest_review_record():
    newest = max((p.name for p in (ROOT / "docs" / "evidence").glob("review-*.md")), key=review_order)
    assert f"evidence/{newest}" in text("docs/00-overview.md"), newest


def test_03_names_every_pinned_config_file(b):
    row = next(ln for ln in text("docs/03-system-architecture.md").splitlines() if ln.startswith("| 設定檔釘選"))
    for key in doc(b, "engagement.yaml").data["config_pins"]:
        assert f"{key}.yaml" in row, key


def test_03_names_the_current_rule_version():
    row = next(ln for ln in text("docs/03-system-architecture.md").splitlines() if ln.startswith("| `verdict.schema.json`"))
    assert adjudicate.RULE_VERSION in row


def test_04_repeats_the_shared_platform_list_of_the_code():
    src = text("docs/04-threat-to-testcase.md")
    block = src.split("SHARED_PLATFORM_SUFFIXES = {", 1)[1].split("}", 1)[0]
    assert ast.literal_eval("{" + block + "}") == safety.SHARED_PLATFORM_SUFFIXES
    row = next(ln for ln in src.splitlines() if "`ownership_proof`（每個 target）" in ln)
    assert all(f"*.{s}" in row for s in safety.SHARED_PLATFORM_SUFFIXES)


def test_the_open_backlog_is_in_order():
    s = text("docs/09-backlog.md")
    open_part = s.split("\n## 4", 1)[1].split("\n## 5", 1)[0]
    ids = [int(x) for x in re.findall(r"^\| BL-(\d+) ", open_part, flags=re.M)]
    assert ids == sorted(ids), ids
