# SPDX-License-Identifier: Apache-2.0
"""Second external review of main@782cba3 (docs/evidence/review-2026-10-28-r12.md §10), the findings that held on re-run:

  A. README's status line still said the latest review record was round 11.
  B. checks.py imported rfc8785 at module level, so the whole validator crashed without it, although only the JCS
     parity check uses it (canonical.jcs is the repo's own implementation); a missing core dependency gave a traceback.
  C. Same family, different base lineage (openai gpt / gpt-oss) counted as two independent observations, a common-mode
     risk. Decision (user): configurable, conservative by default: one family is one observation unless calibration.yaml
     records M-2 evidence that its lineages err independently (rule_version 05-v0.13).
  D. Positioning and MVP-0 entry, E. specification freeze: documentation.
Each test failed before the change and passes after it (tests/mutations/r12_external2.json); see CONTRIBUTING.md."""
import copy
import pathlib
import re
import subprocess
import sys

import pytest

from conftest import doc
from vchlib import adjudicate as adj
from vchlib import checks, derive
from vchlib.checks import run_all

ROOT = pathlib.Path(__file__).resolve().parents[1]
CN = {1: "一", 2: "二", 3: "三", 4: "四", 5: "五", 6: "六", 7: "七", 8: "八", 9: "九", 10: "十", 11: "十一", 12: "十二",
      13: "十三", 14: "十四", 15: "十五", 16: "十六", 17: "十七", 18: "十八", 19: "十九", 20: "二十"}


def text(rel):
    return (ROOT / rel).read_text(encoding="utf-8")


# ================================================================ A. the status line names the latest review record
def latest_round():
    return max(int(m.group(1)) for p in (ROOT / "docs/evidence").glob("review-*-r*.md")
               if (m := re.search(r"-r(\d+)\.md$", p.name)))


def test_readme_names_the_latest_review_record():
    status = next(ln for ln in text("README.md").splitlines() if ln.startswith("> **狀態**"))
    n = CN[latest_round()]
    assert f"最新一份是第{n}輪" in status, status[:200]


def test_overview_names_the_latest_round():
    status = next(ln for ln in text("docs/00-overview.md").splitlines() if ln.startswith("> **狀態**"))
    assert f"第{CN[latest_round()]}輪" in status


# ================================================================ B. rfc8785 is optional, core dependencies are named
def run_py(code):
    return subprocess.run([sys.executable, "-c", code], cwd=ROOT, capture_output=True, text=True)


BLOCK_RFC = ("import sys; sys.modules['rfc8785'] = None; sys.path.insert(0, 'tools')\n"
             "from vchlib.bundle import load_bundle\nfrom vchlib.checks import run_all\nimport pathlib\n"
             "R = run_all(load_bundle(pathlib.Path('.')))\n"
             "print('ERRORS', sorted({i.code for i in R.errors}))\nprint('WARNINGS', sorted({i.code for i in R.warnings}))\n")


def test_the_validator_runs_without_the_reference_jcs_library():
    r = run_py(BLOCK_RFC)
    assert r.returncode == 0, r.stderr[-500:]
    assert "ERRORS []" in r.stdout and "W-JCS-REFERENCE-MISSING" in r.stdout


def test_without_the_reference_the_own_jcs_still_meets_the_rfc_vectors(monkeypatch):
    monkeypatch.setattr(checks, "JCS_VECTORS", [({"a": 1}, '{"b":1}')])          # a wrong vector must still be caught
    monkeypatch.setitem(sys.modules, "rfc8785", None)
    R = checks.Report()
    checks.g_jcs(R, checks.Ctx(__import__("vchlib.bundle", fromlist=["x"]).load_bundle(ROOT)))
    assert any(i.code == "E-JCS" and "canonical.py" in i.where for i in R.errors)
    assert any(i.code == "W-JCS-REFERENCE-MISSING" for i in R.warnings)


def test_ci_has_the_reference_library(b):
    import rfc8785  # noqa: F401  (CI installs requirements.lock; the parity check must run there)
    assert "W-JCS-REFERENCE-MISSING" not in {i.code for i in run_all(b).warnings}


def test_a_missing_core_dependency_is_named_not_a_traceback():
    code = ("import sys; sys.modules['jsonschema'] = None; sys.path.insert(0, 'tools'); sys.argv = ['validate_schemas']\n"
            "from vchlib.cli import main\nraise SystemExit(main())\n")
    r = run_py(code)
    assert r.returncode == 2 and "jsonschema" in r.stderr and "requirements.lock" in r.stderr
    assert "Traceback" not in r.stderr


# ================================================================ C. independence: one family, one observation by default
def ix_with(b, split=None, extra_models=None):
    cal = doc(b, "calibration.yaml").data
    cal["config"]["independence"] = {"unit": "family", "lineage_split": split or []}
    if extra_models:
        doc(b, "models.yaml").data.update(extra_models)
    return derive.Index(b)


def evidence(n=60, upper=0.4, lineages=("gpt", "gpt-oss")):
    return [{"family": "openai", "lineages": list(lineages), "kappa": 0.3, "kappa_ci_upper": upper, "n": n,
             "source": "M-2 2026-12 calibration run"}]


def test_two_lineages_of_one_family_are_one_observation_by_default(b):
    ix = ix_with(b)
    assert ix.independence_key("gpt_flagship") == ix.independence_key("gpt_oss_self")
    assert ix.independence_key("gpt_flagship") != ix.independence_key("claude_sonnet")


def test_the_example_calibration_is_conservative(b):
    assert doc(b, "calibration.yaml").data["config"]["independence"] == {"unit": "family", "lineage_split": []}
    ix = derive.Index(b)
    assert ix.independence_key("gpt_flagship") == ix.independence_key("gpt_oss_self")


def test_m2_evidence_splits_a_family(b):
    ix = ix_with(b, evidence())
    assert ix.independence_key("gpt_flagship") != ix.independence_key("gpt_oss_self")


@pytest.mark.parametrize("kw", [{"upper": 0.6}, {"upper": 0.75}, {"n": 39}])
def test_weak_evidence_does_not_split(b, kw):
    ix = ix_with(b, evidence(**kw))
    assert ix.independence_key("gpt_flagship") == ix.independence_key("gpt_oss_self")


def test_a_shared_base_lineage_stays_one_observation_across_families(b):
    # a fine-tune of another family's base inherits its blind spots, whatever the split evidence says
    tuned = copy.deepcopy(doc(b, "models.yaml").data["nemotron_self"])
    tuned.update({"family": "acme", "lineage": "acme-tune", "derived_from": "gpt"})
    ix = ix_with(b, evidence(), {"acme_tuned": tuned})
    assert ix.independence_key("acme_tuned") == ix.independence_key("gpt_flagship")


def test_s_counts_one_family_once():
    assert derive.root_score([("openai", 1.3), ("openai", 1.3), ("anthropic", 1.2)]) == 2.5


def test_the_score_groups_by_the_independence_key(b, monkeypatch):
    ix = derive.Index(b)
    v, cl = doc(b, "verdict.k-014-w3.example.json").data, ix.first("cluster", cluster_id="K-014").data
    seen = []
    monkeypatch.setattr(derive, "root_score", lambda terms: seen.extend(terms) or 0.0)
    derive.derived_score(ix, v, cl)
    counted = [x["voter_model_key"] for x in v["votes"] if derive.vote_terms(ix, x, cl, v.get("calibration_version"))[2]]
    assert counted and [k for k, _ in seen] == [ix.independence_key(m) for m in counted]


def test_independent_sources_and_diversity_use_the_same_key(b, monkeypatch):
    c = checks.Ctx(b)
    v, cl = doc(b, "verdict.k-014-w3.example.json").data, c.ix.first("cluster", cluster_id="K-014").data
    calls = []
    real = derive.Index.independence_key

    def spy(self, key):
        calls.append(key)
        return real(self, key)
    monkeypatch.setattr(derive.Index, "independence_key", spy)
    seen = []
    real_obs = checks.vote_observation
    monkeypatch.setattr(checks, "vote_observation", lambda c_, x, m: seen.append(x["voter_model_key"]) or real_obs(c_, x, m))
    checks.derived_diversity_degraded(c, v, cl)
    counted = [x["voter_model_key"] for x in v["votes"] if derive.vote_terms(c.ix, x, cl, v.get("calibration_version"))[2]]
    assert counted and seen == counted, "diversity groups the counted votes by their observation"
    gpt = {"voter_model_key": "gpt_flagship"}
    assert checks.vote_observation(c, gpt, c.model("gpt_flagship")) == checks.vote_observation(
        c, {"voter_model_key": "gpt_oss_self"}, c.model("gpt_oss_self"))
    calls.clear()
    derive.independent_families(c.ix, cl)
    assert calls, "independent_families groups reporters by independence_key"


def test_the_calibration_policy_pins_the_split_rule(b, keys):
    cal = doc(b, "calibration.yaml").data
    cal["config"]["independence"] = {"unit": "lineage", "lineage_split": []}
    assert any("independence.unit" in p for p in checks.policy_problems(cal["config"]))


def test_a_split_without_evidence_is_rejected(b):
    cal = doc(b, "calibration.yaml").data
    cal["config"]["independence"] = {"unit": "family", "lineage_split": evidence(upper=0.7)}
    assert any("lineage_split" in p for p in checks.policy_problems(cal["config"]))


def test_the_rule_version_is_05_v0_13(b):
    assert adj.RULE_VERSION == "05-v0.14"
    assert {d.data.get("rule_version") for d in b.docs if d.kind in ("verdict", "run")} == {"05-v0.14"}


# ================================================================ D / E. positioning, MVP-0 entry, freeze
def test_readme_and_overview_state_the_two_axes():
    for rel in ("README.md", "docs/00-overview.md"):
        s = text(rel)
        assert "針對 AI 生成應用的安全測試控制框架" in s and "企業" in s, rel


def test_lite_whitebox_quick_mode_is_the_mvp0_entry_and_gates_stay_human():
    s = text("docs/07-roadmap.md").split("### 1.3", 1)[1].split("\n### ", 1)[0]
    assert "MVP-0 的預設入口" in s and "不自動核准" in s


def test_baas_targets_expect_s0_s1():
    assert "託管 DB" in text("docs/07-roadmap.md") and "06-security-legal-limitations.md#3" in text("docs/07-roadmap.md")


def test_the_specification_is_frozen():
    for rel in ("CONTRIBUTING.md", "docs/09-backlog.md"):
        assert "規格凍結" in text(rel), rel
