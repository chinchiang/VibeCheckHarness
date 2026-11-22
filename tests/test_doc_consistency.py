# SPDX-License-Identifier: Apache-2.0
"""Facts that several documents restate must agree with their single source (2026-11-22 internal review).

The review of the design documents found restated facts that had drifted from the code or from the example they
describe: the current rule_version, the registered inventory extractors, the W0 PII detector's milestone, the
probabilistic replay / PASS thresholds in docs/04 example B, the near_zero reasons in docs/05, the category table
of docs/06 §3, the rule that yields CONFIRMED_EXECUTABLE and the Result Analyst text in docs/02, the G2 exception,
edge-case table, kappa batch, M-11 note and sample-size references in docs/05, and the b1_crawl block in docs/03.
Each test reads the single source where there is one (adjudicate.RULE_VERSION, tools.yaml, toolkit.yaml,
calibration.yaml and its schema, derive, the numbered rows of docs/06 §3, the section headings of docs/05) and checks
the restatements against it. Each test failed before the fix and passes after it (tests/mutations/doc_consistency.json);
see CONTRIBUTING.md. The derive.classify_result docstring fixed in the same change is not specification and is not
covered."""
import json
import pathlib
import re

import yaml

from vchlib.adjudicate import RULE_VERSION

ROOT = pathlib.Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
NORMATIVE = sorted(DOCS.glob("0[0-9]-*.md"))


def text(name):
    return (DOCS / name).read_text(encoding="utf-8")


def test_every_current_rule_version_statement_matches_the_code():
    # "目前 `05-v0.N`" / "目前 \"05-v0.N\"" / "`rule_version` 是 `05-v0.N`" state the current version
    pat = re.compile(r"(?:目前\s*[`\"]|`rule_version` 是 `)(05-v0\.\d+)")
    bad = [(p.name, m.group(1)) for p in NORMATIVE for m in pat.finditer(p.read_text(encoding="utf-8"))
           if m.group(1) != RULE_VERSION]
    assert not bad, (RULE_VERSION, bad)


def test_registered_inventory_extractors_are_not_called_planned():
    tools = yaml.safe_load(text("examples/tools.yaml"))
    registered = set(tools["tools"]["inventory"]["modes"])
    spec = text("08-implementation-spec.md")
    for mode in registered:
        assert f"`inventory:{mode}`（規劃中）" not in spec, mode
    planned = re.search(r"下表標為「規劃中」的 adapter（([^）]*)）", spec)
    assert planned, "the support matrix lists its planned adapters"
    named = set(re.findall(r"`([a-z_]+)`", planned.group(1)))
    assert not (named & registered), named & registered
    for m in re.finditer(r"`inventory:\*` 模式（目前(?:只有|是) ([^；]*)；", spec):
        assert set(re.findall(r"`([a-z_]+)`", m.group(1))) == registered, m.group(0)
    assert "只登錄了 `fastapi`、`express`、`sql_rls` 三個模式" not in spec


def test_w0_pii_detector_milestone_is_m1_everywhere():
    spec = text("08-implementation-spec.md")
    assert "W0 用的規則式 PII 偵測器 → M2" not in spec
    assert "W0 用的規則式 PII 偵測器 → M1" in spec


def test_docs04_example_b_follows_the_probabilistic_rules():
    doc = text("04-threat-to-testcase.md")
    # §4.4: a silent replay of a probabilistic test does not demote the FAIL
    assert "k_r＝0 → `E_inc`" not in doc
    # T-031 has an attack tree, so derive.pass_min_effective asks for 60 effective trials
    t031 = json.loads(text("schemas/examples/threat.t-031.example.json"))
    assert t031.get("attack_tree_ref")
    assert "k＝0 且 n′ ≥ 30 → 解讀屬事先登記 → `E_pass`" not in doc
    assert "k＝0 且 n′ ≥ 60" in doc
    assert "n' < 30 時結果為 `E_inc`" not in doc


def test_docs05_lists_every_near_zero_reason_of_the_schema():
    schema = json.loads(text("schemas/calibration.schema.json"))
    reasons = set()

    def walk(node):
        if isinstance(node, dict):
            if "near_zero_reasons" in node.get("properties", {}):
                reasons.update(node["properties"]["near_zero_reasons"]["items"]["enum"])
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)

    walk(schema)
    assert reasons
    line = next(ln for ln in text("05-bias-calibration.md").splitlines() if "依序對應下列四項" in ln)
    listed = set(re.findall(r"`([a-z_]+)`", line.split("依序對應下列四項", 1)[1].split("）", 1)[0]))
    assert listed == reasons, (listed, reasons)
    assert len(reasons) == 4


def test_docs06_category_table_covers_every_numbered_limitation_once():
    doc = text("06-security-legal-limitations.md")
    section = doc.split("## 3. 做不到／不承諾的事", 1)[1]
    rows = {int(m.group(1)) for m in re.finditer(r"^\| (\d+) \| ", section, re.M)}
    assert rows == set(range(1, max(rows) + 1)), "numbered rows are contiguous"
    categories = [ln for ln in section.splitlines() if re.match(r"^\| [A-D]\. ", ln)]
    assert len(categories) == 4
    listed = [int(n) for ln in categories for n in re.findall(r"#(\d+)", ln.rsplit("|", 2)[1])]
    assert sorted(listed) == sorted(rows), (sorted(set(rows) - set(listed)), [n for n in listed if listed.count(n) > 1])
    assert f"下表共 {len(rows)} 條" in section


def test_no_rule_other_than_r1_yields_confirmed_executable_in_prose():
    # R0 ends in REJECTED (docs/05 §4.2); CONFIRMED_EXECUTABLE comes from R1 (E_proof)
    bad = [p.name for p in NORMATIVE if re.search(r"依 R0 為 `CONFIRMED_", p.read_text(encoding="utf-8"))]
    assert not bad, bad
    assert "重播命中 → 依 R1 為 `CONFIRMED_EXECUTABLE`" in text("02-methodology.md")


def test_docs02_result_analyst_text_matches_derive():
    doc = text("02-methodology.md")
    # a declared control that is not PASS makes the result INVALID (E_inc) before any analyst is asked
    assert "例如 `local_rls` 的某個對照沒有 PASS" not in doc
    # derive.classify_result: an eligible analyst that disagrees gives E_inc, pre-registered or not (as docs/05 says)
    assert "`agrees` 為 false → `E_inc`" in text("05-bias-calibration.md")
    assert "其他情況只撰寫結果說明，不影響分類。" not in doc
    line = next(ln for ln in doc.splitlines() if "它只在解讀未事先登記時決定分類" in ln)
    assert "`agrees` 為 false" in line and "`E_inc`" in line, line


def test_docs05_g2_accept_exception_is_stated():
    from vchlib import derive
    assert callable(derive.g2_accepted)
    line = next(ln for ln in text("05-bias-calibration.md").splitlines() if "G2 的 accept 與 NEEDS_INFO" in ln)
    assert "`derive.g2_accepted`" in line, line


def test_docs05_edge_table_uses_current_preregistration():
    doc = text("05-bias-calibration.md")
    assert "需求全部經 G1 簽核、`oracle_can_pass` 對照為 PASS 的 W4 測試" not in doc
    row = next(ln for ln in doc.splitlines() if ln.startswith("| 可重現、由確定性 oracle 判定的 FAIL"))
    assert "`oracle_can_fail`" in row and "G2 `accept`" in row, row


def test_docs05_kappa_batch_matches_calibration_example():
    cal = yaml.safe_load(text("examples/calibration.yaml"))

    def find(node):
        if isinstance(node, dict):
            if "batch_size_apps" in node:
                return node["batch_size_apps"]
            for v in node.values():
                if (r := find(v)) is not None:
                    return r
        return None

    batch = find(cal)
    assert isinstance(batch, int)
    line = next(ln for ln in text("05-bias-calibration.md").splitlines() if "**一致性門檻**" in ln)
    assert "約 10 個應用" not in line
    m = re.search(r"範例 (\d+) 個應用", line)
    assert m and int(m.group(1)) == batch, (line[:120], batch)


def test_docs05_m11_does_not_call_the_weights_unsplit():
    doc = text("05-bias-calibration.md")
    assert "§4.3 的權重公式本輪不改" not in doc
    row = next(ln for ln in doc.splitlines() if ln.startswith("| M-11 |"))
    assert "§4.3 已分邊加權" in row, row[-200:]


def test_docs05_sample_size_references_point_at_their_section():
    doc = text("05-bias-calibration.md")
    section = None
    for ln in doc.splitlines():
        if m := re.match(r"### (\d+\.\d+) ", ln):
            section = m.group(1)
        if "**樣本數計算（逐步）**" in ln:
            break
    assert section
    refs = re.findall(r"§(5\.\d+)(?:「樣本數計算」)?\s*(?:重算|第 5 步)", doc)
    assert len(refs) >= 2, refs
    assert set(refs) == {section}, (refs, section)


def test_docs03_b1_crawl_points_at_the_toolkit_block():
    assert "b1_crawl" in yaml.safe_load(text("examples/toolkit.yaml"))
    doc = text("03-system-architecture.md")
    assert "`toolkit.yaml` 還沒有對應的設定區塊" not in doc
    assert "`toolkit.yaml` 的 `b1_crawl` 區塊" in doc
