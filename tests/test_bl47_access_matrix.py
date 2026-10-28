# SPDX-License-Identifier: Apache-2.0
"""BL-47: the example G1 access matrix has the rows example B′ (docs/04 §6.3) relies on.

Example B′ tests indirect injection through a document U2 shares with U1 in a workspace. The example
invariants.yaml had no row allowing that read, so the threat had no G1 requirement to trace to and 04 said so. The
two workspace_document rows (members read, only the uploader updates or deletes) are now in the matrix, G1 is
re-signed over it, and the report's access-matrix coverage drops to 4 of 7 cells because no testcase covers the new
ones. Each test failed before this change and passes after it (tests/mutations/bl47_access_matrix.json)."""
from conftest import doc
from vchlib.checks import Ctx, access_matrix_cells, report_metrics, run_all
from vchlib.derive import approval_hash

RUN_ID = "run-2026-09-23-001"
WS = ("workspace_member", "workspace_document")


def rows(b):
    return [r for r in doc(b, "invariants.yaml").data["access_matrix"] if (r["role"], r["resource"]) == WS]


def test_workspace_members_may_read_a_shared_document(b):
    reads = [r for r in rows(b) if r["actions"] == ["read"]]
    assert len(reads) == 1, reads                      # r12 external review: an assertion, not an unpacking error
    read = reads[0]
    assert read["ownership"] == {"kind": "membership", "field": "document.workspace_id", "via": "session.workspace_ids"}


def test_only_the_uploader_may_change_it(b):
    (write,) = [r for r in rows(b) if "update" in r["actions"]]
    assert sorted(write["actions"]) == ["delete", "update"]
    assert write["ownership"] == {"kind": "owner_field", "field": "document.uploader_id", "via": "session.user_id"}


def test_g1_signs_the_matrix_with_the_rows(b):
    g1 = doc(b, "gate-record.g1.example.json").data
    assert g1["artifact"]["sha256"] == approval_hash(doc(b, "invariants.yaml").data)
    assert run_all(b).errors == []


def test_a_testcase_may_now_cover_the_shared_read(b):
    assert WS + ("read",) in access_matrix_cells(Ctx(b))
    tc = doc(b, "testcase.llm.example.json").data
    tc["access_cells"] = tc["access_cells"] + [{"role": WS[0], "resource": WS[1], "action": "read"}]
    assert "E-TC-ACCESS-CELL" not in run_all(b).codes()


def test_the_report_counts_the_uncovered_cells(b):
    m = report_metrics(Ctx(b), RUN_ID)
    assert (m["planned_access_matrix_coverage"], m["executed_access_matrix_coverage"]) == (0.5714, 0.5714)
    assert doc(b, "report-manifest.example.json").data["metrics"]["planned_access_matrix_coverage"] == 0.5714


def test_04_no_longer_says_the_row_is_missing():
    import pathlib
    text = (pathlib.Path(__file__).resolve().parents[1] / "docs" / "04-threat-to-testcase.md").read_text(encoding="utf-8")
    assert "沒有這一列" not in text and "BL-47" in text
