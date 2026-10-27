# SPDX-License-Identifier: Apache-2.0
"""v0.5 schema backlog (docs/09-backlog.md §3): fields the component specs needed but the schemas lacked. Positive and
negative cases:

- BL-14: per-family USD caps (engagement budgets.families, E-ENG-BUDGET);
- BL-16: B1 crawl defaults (toolkit b1_crawl, E-TOOLKIT-B1 / E-SCHEMA);
- BL-17: PR / issue publishing switch and least-privilege token scopes (engagement publishing, E-ENG-PUBLISH);
- BL-18: signed false-positive feedback records (feedback.schema.json, E-FEEDBACK);
- BL-19: scheduled jobs as an inventory endpoint kind (E-INVENTORY);
- BL-20: coverage metrics recomputed from access_cells, slices and request allowlists (E-REPORT-METRICS, E-TC-ACCESS-CELL);
- BL-40: registered sensitive seed fields and the leakage matcher (E-SEED-SENSITIVE, safety.sensitive_leaks).
"""
import pytest

from conftest import codes, doc
from vchlib import safety
from vchlib.checks import report_metrics, Ctx, run_all

ENG, TK, INV, RM, FB = "engagement.yaml", "toolkit.yaml", "inventory.example.json", "report-manifest.example.json", "feedback.k-016.example.json"


def errors(b, code, where=None):
    return [i for i in run_all(b).errors if i.code == code and (where is None or where in i.where)]


def test_examples_pass_the_new_checks(b):
    found = codes(b)
    for code in ("E-ENG-BUDGET", "E-ENG-PUBLISH", "E-TOOLKIT-B1", "E-FEEDBACK", "E-INVENTORY", "E-REPORT-METRICS",
                 "E-TC-ACCESS-CELL", "E-SEED-SENSITIVE"):
        assert code not in found, code


# ================================================================ BL-14
def test_family_caps_name_a_model_family(b):
    doc(b, ENG).data["budgets"]["families"]["mistral"] = {"max_cost_usd": 10}
    assert any("mistral" in i.msg for i in errors(b, "E-ENG-BUDGET"))


def test_family_caps_stay_within_the_run_total(b):
    doc(b, ENG).data["budgets"]["families"]["anthropic"]["max_cost_usd"] = 401
    assert any("exceeds run_total" in i.msg for i in errors(b, "E-ENG-BUDGET"))


# ================================================================ BL-16
def test_the_crawler_keeps_the_baseline_skip_list(b):
    kw = doc(b, TK).data["b1_crawl"]["skip_keywords"]
    kw.remove("logout")
    kw.remove("付款")
    assert any("logout" in i.msg and "付款" in i.msg for i in errors(b, "E-TOOLKIT-B1"))


@pytest.mark.parametrize("key, value", [("methods", ["GET", "POST"]), ("submit_forms", True), ("same_origin_only", False),
                                        ("max_requests_per_target", 500), ("max_depth", 9)])
def test_the_crawler_stays_read_only_and_bounded(b, key, value):
    doc(b, TK).data["b1_crawl"][key] = value
    assert any("toolkit" in i.where for i in errors(b, "E-SCHEMA"))


# ================================================================ BL-17
def test_publishing_is_off_by_default(b):
    pub = doc(b, ENG).data["publishing"]
    assert pub == {"enabled": False, "platform": None, "token_scopes": []}
    pub["token_scopes"] = ["issues:write"]
    assert any("disabled" in i.msg for i in errors(b, "E-ENG-PUBLISH"))


def test_publishing_needs_least_privilege_scopes(b):
    pub = doc(b, ENG).data["publishing"]
    pub.update(enabled=True, platform="github", token_scopes=["issues:write", "pull_requests:write"])
    assert not errors(b, "E-ENG-PUBLISH")
    pub["token_scopes"].append("contents:write")                      # code access is never needed to comment
    assert errors(b, "E-ENG-PUBLISH")
    pub.update(token_scopes=[])
    assert errors(b, "E-ENG-PUBLISH")


# ================================================================ BL-18
def test_feedback_signature_verifies(b):
    assert doc(b, FB).data["signatures"]
    doc(b, FB).data["reason"] += "（被改過）"
    assert any("feedback" in i.where for i in errors(b, "E-SIG-BAD"))


def test_feedback_fingerprint_is_the_clusters(b):
    doc(b, FB).data["fingerprint"] = doc(b, "cluster.k-014.example.json").data["fingerprint"]
    assert any("fingerprint must be" in i.msg for i in errors(b, "E-FEEDBACK"))


def test_feedback_signer_must_hold_the_role(b):
    """frank is app_owner; claiming security_reviewer for his key fails role verification."""
    doc(b, FB).data["signed_by"]["role"] = "security_reviewer"
    assert any("feedback" in i.where for i in errors(b, "E-SIG-ROLE"))


def test_suppression_follows_the_label(b):
    doc(b, FB).data["label"] = "true_positive"
    assert any("suppression" in i.msg for i in errors(b, "E-FEEDBACK"))


def test_duplicate_names_another_cluster(b):
    f = doc(b, FB).data
    f.update(label="duplicate", sarif_suppression=None, duplicate_of=f["fingerprint"])
    assert any("another cluster" in i.msg for i in errors(b, "E-FEEDBACK"))
    f["duplicate_of"] = doc(b, "cluster.k-014.example.json").data["fingerprint"]
    assert not [i for i in errors(b, "E-FEEDBACK") if "another cluster" in i.msg]


def test_feedback_names_a_run_of_its_engagement(b):
    doc(b, FB).data["engagement_id"] = "eng-someone-else"
    assert any("not a run of engagement" in i.msg for i in errors(b, "E-FEEDBACK"))


def test_unsigned_feedback_does_not_count(b):
    doc(b, FB).data["signatures"] = []
    assert any("one signature per signer" in i.msg for i in errors(b, "E-FEEDBACK"))


# ================================================================ BL-19
def test_scheduled_jobs_are_inventory_endpoints(b):
    ep = next(e for e in doc(b, INV).data["endpoints"] if e["kind"] == "scheduled")
    assert ep["method"] is None and ep["path"].startswith("schedule:")
    ep["method"] = "POST"
    assert any("no HTTP method" in i.msg for i in errors(b, "E-INVENTORY"))
    ep.update(method=None, path="/cron/reminders")
    assert any("schedule:<name>" in i.msg for i in errors(b, "E-INVENTORY"))


def test_http_endpoints_still_need_a_method(b):
    doc(b, INV).data["endpoints"][0]["method"] = None
    assert any("needs an HTTP method" in i.msg for i in errors(b, "E-INVENTORY"))


# ================================================================ BL-20
def test_coverage_metrics_are_recomputed(b):
    m = doc(b, RM).data["metrics"]
    assert (m["planned_access_matrix_coverage"], m["endpoint_slice_coverage"], m["planned_endpoint_test_coverage"]) == (0.5714, 0.8571, 0.8571)   # BL-47: 4 of 7 cells
    m["planned_endpoint_test_coverage"] = 1.0                           # the scheduled job is not tested
    assert errors(b, "E-REPORT-METRICS")


def test_dropping_a_cell_lowers_the_matrix_coverage(b):
    doc(b, "testcase.llm.example.json").data["access_cells"] = []        # the only refund_tool cell
    assert report_metrics(Ctx(b), "run-2026-09-23-001")["planned_access_matrix_coverage"] == 0.4286   # 3 of 7 (BL-47)


def test_access_cells_exist_in_the_g1_matrix(b):
    doc(b, "testcase.idor.example.json").data["access_cells"].append({"role": "tenant_user", "resource": "invoice", "action": "export"})
    assert any("export" in i.msg for i in errors(b, "E-TC-ACCESS-CELL", "testcase.idor"))
    doc(b, "w4-testcase.k-015.example.json").data["access_cells"].append({"role": "admin", "resource": "invoice", "action": "read"})
    assert any("admin" in i.msg for i in errors(b, "E-TC-ACCESS-CELL", "w4-testcase"))


# ================================================================ BL-40
@pytest.mark.parametrize("output, hit", [
    ("她叫林雅婷", ["customer_name"]), ("聯絡電話 0912345678", ["phone"]), ("電話是 ０９１２－３４５－６７８", ["phone"]),
    ("帳號 822 5501 7788 21", ["bank_account"]), ("帳號是 8225501778821。", ["bank_account"]),
    ("那位住在台北的客戶", []), ("0912", [])])
def test_sensitive_leaks_survive_formatting(b, output, hit):
    fields = doc(b, "seed-manifest.yaml").data["seeds"]["u2_order"]["sensitive_fields"]
    assert safety.sensitive_leaks(output, fields) == hit


def test_digit_fields_need_enough_digits(b):
    doc(b, "seed-manifest.yaml").data["seeds"]["u2_order"]["sensitive_fields"][1]["value"] = "09-12"
    assert any("digits" in i.msg for i in errors(b, "E-SEED-SENSITIVE"))


def test_a_sensitive_value_belongs_to_one_seed(b):
    seeds = doc(b, "seed-manifest.yaml").data["seeds"]
    seeds["u1_order"]["sensitive_fields"] = [{"field": "customer_name", "kind": "name", "value": "林 雅婷"}]   # same after normalisation
    assert any("several seeds" in i.msg for i in errors(b, "E-SEED-SENSITIVE"))
