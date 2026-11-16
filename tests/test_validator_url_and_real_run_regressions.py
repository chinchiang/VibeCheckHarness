# SPDX-License-Identifier: Apache-2.0
"""Regression tests for the two review findings left open by test_validator_bypass_regressions.py.

RED ON PURPOSE: the `Bypass` classes fail until the validator is fixed; the `Control` classes pass today and pin
behaviour that must not change.

1. A ROE base_url whose host differs between parsers. Python's urlsplit reads `https://good.com\\@evil.com/` as
   userinfo `good.com\\` and host `evil.com`; WHATWG-style parsers (browsers) read `\\` as `/` and connect to
   `good.com`. An exclusion of `good.com` is then not applied. The fix under test: url_problem refuses userinfo
   and backslashes (E-ROE-URL). Whether a real HTTP client would connect to good.com is NOT shown here.
2. `--real-run` must refuse the published TEST ONLY keys (docs/06 section 1.6: "正式登錄必須拒絕這些金鑰的指紋").
   The registry has no marker for them, so a key is TEST ONLY when its public key equals the public key of a
   private key in tests/fixtures/TEST_ONLY_private_keys. The expected error is any `E-KR-*` code (the exact
   name is the fixer's choice; add it to the error table and docs/03 section 6.1).
"""
import pytest

from conftest import KEY_DIR, codes, doc
from vchlib import checks, cli, crypto
from vchlib.checks import run_all


# --- 1. base_url userinfo and backslash ---------------------------------------------------------------------

class TestBaseUrlControl:
    @pytest.mark.parametrize("url", [
        "https://api.staging.example.com",
        "https://api.staging.example.com/v1/items?id=1#top",
        "https://api.staging.example.com:8443/",
        "https://[2001:4860:4860::8888]/",
        "http://localhost:3000/",
        "http://127.0.0.1/",
    ])
    def test_ordinary_urls_are_accepted(self, url):
        assert checks.url_problem(url) is None

    @pytest.mark.parametrize("url", ["ftp://example.com/", "http://api.staging.example.com/", "example.com", ""])
    def test_the_existing_refusals_stay(self, url):
        assert checks.url_problem(url) is not None


class TestBaseUrlBypass:
    @pytest.mark.parametrize("url", [
        "https://good.com\\@evil.com/",            # urlsplit: host evil.com; WHATWG: host good.com
        "https://good.com\\.evil.com/",
        "https://good.com\\evil.com/",
        "https://evil.com\\@good.com/",
        "https://api.staging.example.com\\/",
        "https://api.staging.example.com/a\\b",    # a backslash anywhere: the parsers disagree on where the path starts
    ])
    def test_a_backslash_is_refused(self, url):
        assert checks.url_problem(url) is not None

    @pytest.mark.parametrize("url", [
        "https://user@evil.com/",
        "https://user:pw@evil.com/",
        "https://:pw@evil.com/",
        "https://good.com@evil.com/",              # the classic: looks like good.com, connects to evil.com
        "https://api.staging.example.com@evil.com/",
        "http://user@localhost:3000/",             # the local-target exception does not allow userinfo either
    ])
    def test_userinfo_is_refused(self, url):
        assert checks.url_problem(url) is not None

    @pytest.mark.parametrize("url", ["https://good.com\\@evil.com/", "https://user@evil.com/"])
    def test_the_roe_check_reports_it_as_e_roe_url(self, b, url):
        d = doc(b, "roe.yaml").data
        t = next(x for x in d["targets"] if x.get("kind") == "http")
        t["base_url"] = url
        assert "E-ROE-URL" in codes(b)


# --- 2. --real-run and TEST ONLY keys -----------------------------------------------------------------------

def _published_public_keys():
    """Public keys (base64) of every published TEST ONLY private key."""
    import base64
    return {base64.b64encode(crypto.raw_public(crypto.load_private_pem(p))).decode() for p in KEY_DIR.glob("*.TEST_ONLY.pem")}


class TestRealRunControl:
    def test_the_example_bundle_is_made_of_test_only_keys(self, b):
        """Premise of the tests below: every key in the example registry is a published TEST ONLY key."""
        reg = doc(b, "key-registry.yaml").data
        published = _published()
        assert reg["org_root_public_key"] in published
        assert all(e["public_key"] in published for e in reg["entries"])

    def test_a_design_run_with_test_only_keys_is_fine(self, b):
        assert not [e for e in run_all(b).errors if e.code.startswith("E-KR")]

    def test_real_run_still_reports_placeholder_models_as_before(self, b):
        """Existing --real-run behaviour is unchanged: only a placeholder model reachable from an agent errors."""
        assert "E-MODEL-PLACEHOLDER" not in run_all(b, real_run=True).codes()


class TestEmbeddedKeyTable:
    def test_the_validator_table_equals_the_fixtures_directory(self):
        """crypto.TEST_ONLY_PUBLIC_KEYS is a copy; a key added to or removed from the fixtures must change it too."""
        assert set(crypto.TEST_ONLY_PUBLIC_KEYS) == _published()


class TestRealRunBypass:
    def test_real_run_refuses_the_test_only_keys(self, b):
        errs = [e for e in run_all(b, real_run=True).errors if e.code.startswith("E-KR")]
        assert errs, "--real-run accepted a registry made of published TEST ONLY keys"

    def test_real_run_reports_exactly_e_kr_test_only_on_the_examples(self, b):
        """The example bundle has no other real-run problem: every error is E-KR-TEST-ONLY, one per TEST ONLY key."""
        errs = run_all(b, real_run=True).errors
        assert {e.code for e in errs} == {"E-KR-TEST-ONLY"}
        reg = doc(b, "key-registry.yaml").data
        assert len(errs) == 1 + len(reg["entries"])          # the org root key and every registry entry

    def test_the_refusal_names_the_test_only_keys(self, b):
        msgs = " ".join(e.msg for e in run_all(b, real_run=True).errors if e.code.startswith("E-KR"))
        assert "TEST ONLY" in msgs

    def test_the_org_root_key_is_checked_too(self, b):
        """Not only the entries: a TEST ONLY org root key signs the whole registry."""
        errs = run_all(b, real_run=True).errors
        assert any(e.code.startswith("E-KR") and "org_root" in e.msg for e in errs)

    def test_the_command_line_exits_non_zero(self, capsys):
        rc = cli.main(["--real-run", "--quiet"])
        out = capsys.readouterr()
        assert rc != 0, "validate_schemas --real-run exited 0 on a registry of published TEST ONLY keys"
        assert "E-KR" in out.out + out.err


_PUBLISHED = None


def _published():
    global _PUBLISHED
    if _PUBLISHED is None:
        _PUBLISHED = _published_public_keys()
    return _PUBLISHED
