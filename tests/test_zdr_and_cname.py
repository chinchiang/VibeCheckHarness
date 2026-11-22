# SPDX-License-Identifier: Apache-2.0
"""Two declarations the validator took at their word (2026-11-22 review, findings C6 and C4).

C6  `providers[].zdr: confirmed` was one word in a signed file: no date, no scope, no expiry. A provider can exclude
    single models from zero data retention and a confirmation ends with its contract. A cloud model that can receive C
    data now needs, besides `confirmed` and a signed DPA: an evidence reference, its own key in `zdr_models`, a
    `zdr_confirmed_at` not later than the engagement's issued_at and a `zdr_expires_at` not earlier than validity.not_after
    (checks.zdr_problems, E-ENG-PROVIDER).
C4  A shared-platform target was recognised by its host name only, so a custom domain that is a CNAME to acme.vercel.app
    proved ownership with dns_txt and needed no platform policy. The executor records the CNAME names it resolved
    (run.ownership_results[].cname_chain); an ok result whose chain reaches a shared platform needs platform_project of
    that platform and its platform_policies entry (checks.cname_platform_problems, E-ROE-PLATFORM).

Each `..._is_refused` test failed before the change and passes after it (tests/mutations/zdr_and_cname.json); the
`..._still_...` tests check that nothing legitimate is refused. See CONTRIBUTING.md."""
import json
import pathlib

import pytest

from conftest import doc
from vchlib import checks
from vchlib.checks import run_all
from vchlib.context import Ctx

ROOT = pathlib.Path(__file__).resolve().parents[1]


def text(rel):
    return (ROOT / rel).read_text(encoding="utf-8")


def msgs(b, code):
    return [i.msg for i in run_all(b).errors if i.code == code]


def provider(b, family):
    return next(p for p in doc(b, "engagement.yaml").data["providers"] if p["family"] == family)


# ================================================================ C6: a ZDR confirmation has evidence, a scope and a period
def test_the_example_confirmations_cover_the_engagement(b):
    e = doc(b, "engagement.yaml").data
    for fam, models in (("anthropic", ["claude_sonnet", "claude_opus_48"]), ("openai", ["gpt_flagship"])):
        p = provider(b, fam)
        assert p["zdr_models"] == models and p["zdr_evidence_ref"]
        assert p["zdr_confirmed_at"] <= e["issued_at"] and p["zdr_expires_at"] >= e["validity"]["not_after"]
        for k in models:
            assert checks.zdr_problems(checks.Report(), e, p, k) == []
    nv = provider(b, "nvidia")
    assert (nv["zdr"], nv["zdr_models"], nv["zdr_confirmed_at"], nv["zdr_expires_at"]) == ("not_available", [], None, None)
    assert msgs(b, "E-ENG-PROVIDER") == []


def test_a_confirmation_that_does_not_name_the_model_is_refused(b):
    provider(b, "openai")["zdr_models"] = []
    got = msgs(b, "E-ENG-PROVIDER")
    assert any("gpt_flagship (openai) can receive C data but providers.openai.zdr_models does not list it" in m for m in got), got
    assert not any("claude" in m for m in got)                  # the other family is untouched


def test_a_confirmation_for_another_model_of_the_family_is_refused(b):
    provider(b, "anthropic")["zdr_models"] = ["claude_sonnet"]
    got = msgs(b, "E-ENG-PROVIDER")
    assert any(m.startswith("claude_opus_48 (anthropic)") and "zdr_models does not list it" in m for m in got), got
    assert not any(m.startswith("claude_sonnet") for m in got)


def test_a_confirmation_without_evidence_is_refused(b):
    provider(b, "openai")["zdr_evidence_ref"] = None
    assert any("zdr_evidence_ref is empty" in m for m in msgs(b, "E-ENG-PROVIDER"))


@pytest.mark.parametrize("value", [None, "2026-09-19T00:00:00+08:00"])
def test_a_confirmation_dated_after_the_engagement_or_undated_is_refused(b, value):
    provider(b, "openai")["zdr_confirmed_at"] = value           # issued_at is 2026-09-18T10:00:00+08:00
    assert any("zdr_confirmed_at" in m and "not later than issued_at" in m for m in msgs(b, "E-ENG-PROVIDER"))


@pytest.mark.parametrize("value", [None, "2026-10-31T23:59:58+08:00", "2026-10-01T00:00:00+08:00"])
def test_a_confirmation_that_ends_before_the_engagement_does_is_refused(b, value):
    provider(b, "openai")["zdr_expires_at"] = value             # validity.not_after is 2026-10-31T23:59:59+08:00
    assert any("zdr_expires_at" in m and "whole engagement" in m for m in msgs(b, "E-ENG-PROVIDER"))


def test_the_boundary_dates_still_pass(b):
    e = doc(b, "engagement.yaml").data
    p = provider(b, "openai")
    p["zdr_confirmed_at"], p["zdr_expires_at"] = e["issued_at"], e["validity"]["not_after"]
    assert checks.zdr_problems(checks.Report(), e, p, "gpt_flagship") == []
    assert msgs(b, "E-ENG-PROVIDER") == []


def test_a_family_without_cloud_c_models_still_needs_no_confirmation(b):
    """nvidia: the self-hosted model takes C data without ZDR, the cloud model takes P only (unchanged)."""
    nv = provider(b, "nvidia")
    assert nv["zdr"] == "not_available" and msgs(b, "E-ENG-PROVIDER") == []


def test_unconfirmed_is_still_the_first_refusal(b):
    """The earlier rule is not replaced: a family that is not confirmed gets that message, not the new ones."""
    provider(b, "openai")["zdr"] = "unknown"
    got = msgs(b, "E-ENG-PROVIDER")
    assert any("is not zdr confirmed with a signed DPA" in m for m in got) and not any("zdr_models" in m for m in got)


def test_the_provider_schema_requires_the_new_fields(b):
    s = json.loads(text("docs/schemas/engagement.schema.json"))["properties"]["providers"]["items"]
    assert {"zdr_models", "zdr_confirmed_at", "zdr_expires_at"} <= set(s["required"])
    del provider(b, "openai")["zdr_expires_at"]
    assert "E-SCHEMA" in run_all(b).codes()


# ================================================================ C4: a CNAME to a shared platform
RUN = "run.example.json"


def result(b, tid="tgt-staging-api"):
    return next(o for o in doc(b, RUN).data["ownership_results"] if o["target_id"] == tid)


def target(b, tid="tgt-staging-api"):
    return next(t for t in doc(b, "roe.yaml").data["targets"] if t["id"] == tid)


def test_the_examples_record_an_empty_chain(b):
    res = doc(b, RUN).data["ownership_results"]
    assert len(res) >= 4 and all(o["cname_chain"] == [] for o in res)
    assert msgs(b, "E-ROE-PLATFORM") == []


@pytest.mark.parametrize("chain, plat", [
    (["acme-staging.vercel.app"], "vercel"),
    (["edge.example.net", "acme.supabase.co"], "supabase"),
    (["ACME.Netlify.App."], "netlify"),
    (["x.pages.dev"], "other"),
])
def test_a_dns_txt_proof_for_a_host_that_resolves_to_a_shared_platform_is_refused(b, chain, plat):
    assert target(b)["ownership_proof"]["method"] == "dns_txt"
    result(b)["cname_chain"] = chain
    got = msgs(b, "E-ROE-PLATFORM")
    assert any(f"(a shared {plat} domain), so ownership cannot be ok with 'dns_txt'" in m for m in got), got


def test_a_platform_project_of_another_platform_is_refused(b):
    t = target(b)
    t["ownership_proof"] = {"method": "platform_project", "platform": "netlify", "project_ref": "p", "evidence_ref": "doc:x"}
    result(b).update(method="platform_project", cname_chain=["acme.vercel.app"])
    assert any("the ROE must declare platform_project with platform vercel" in m for m in msgs(b, "E-ROE-PLATFORM"))


def test_the_platform_policy_is_needed_too(b):
    c = Ctx(b)
    t = dict(target(b), ownership_proof={"method": "platform_project", "platform": "vercel", "project_ref": "p", "evidence_ref": "doc:x"})
    o = dict(result(b), method="platform_project", cname_chain=["acme.vercel.app"])
    assert not any(p.get("platform") == "vercel" for p in c.roe.get("platform_policies") or [])
    assert checks.cname_platform_problems(c, t, o) == [
        "tgt-staging-api: its host resolves through acme.vercel.app (a shared vercel domain) but the ROE has no platform_policies entry for vercel"]
    c.roe.setdefault("platform_policies", []).append({"platform": "vercel"})
    assert checks.cname_platform_problems(c, t, o) == []


def test_an_ordinary_cname_chain_still_passes(b):
    result(b)["cname_chain"] = ["lb.example.net", "edge-123.cdn.example.org", "notvercel.app.example.com"]
    assert msgs(b, "E-ROE-PLATFORM") == []
    assert checks.chain_platforms(["evilvercel.app", "vercel.app.example.com", 7, None]) == {}
    assert checks.chain_platforms(["a.vercel.app", "b.example.com"]) == {"a.vercel.app": "vercel"}


def test_a_failed_check_is_not_an_error(b):
    """The executor refusing the target (ok false) is the rule working; the validator only rejects an ok result."""
    c = Ctx(b)
    o = dict(result(b), ok=False, cname_chain=["acme.vercel.app"])
    assert checks.cname_platform_problems(c, target(b), o) == []
    assert checks.cname_platform_problems(c, target(b), dict(o, ok=True)) != []


def test_the_run_schema_requires_the_chain(b):
    s = json.loads(text("docs/schemas/run.schema.json"))["properties"]["ownership_results"]["items"]
    assert "cname_chain" in s["required"]
    del result(b)["cname_chain"]
    assert "E-SCHEMA" in run_all(b).codes()


# ================================================================ the documents
def test_the_documents_state_both_rules_and_what_they_miss():
    d08 = text("docs/08-implementation-spec.md")
    rows = {ln.split("|")[1].strip() for ln in d08.split("### 11.14 供應商資料處理宣告", 1)[1].split("\n### ", 1)[0].splitlines() if ln.startswith("| `")}
    assert {"`zdr_models`", "`zdr_confirmed_at`", "`zdr_expires_at`"} <= rows
    assert "`zdr_models` 列出這個模型、`zdr_confirmed_at` ≤ `issued_at`、`zdr_expires_at` ≥ `validity.not_after`（`checks.zdr_problems`）" in d08
    sec = d08.split("### 11.9 共享平台網域的所有權證明", 1)[1].split("\n### ", 1)[0]
    assert "`run.ownership_results[].cname_chain`" in sec and "`checks.cname_platform_problems`" in sec
    assert "以 A／ALIAS 記錄直接指向平台 IP" in sec and "`cname.vercel-dns.com`" in sec          # what it cannot see
    d06 = text("docs/06-security-legal-limitations.md")
    row = next(ln for ln in d06.splitlines() if ln.startswith("| 37 |"))
    assert "`cname_chain`" in row and "認不出來" in row
    assert "`providers[].zdr_models` 必須逐一列出已確認的模型" in d06
