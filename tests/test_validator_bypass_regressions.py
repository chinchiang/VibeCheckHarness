# SPDX-License-Identifier: Apache-2.0
"""Regression tests for fail-open bypasses found in the 2026-11-16 repo review (reproduced read-only).

RED ON PURPOSE: the tests in the `BYPASS` classes fail until `safety.host_matches`, `yamlstrict.load` and
`safety.ip_problem` are fixed; the `CONTROL` tests pass today and pin the behaviour that must not change.
"""
import pytest

from conftest import codes, doc
from vchlib import safety, yamlstrict


def excluded(url: str, patterns) -> bool:
    """The ROE flow (checks.g_roe): target host from base_url, matched against exclusions.hosts."""
    return safety.host_excluded(safety.host_of(url), patterns)


# --- safety.host_matches: one address, several spellings --------------------------------------------------

class TestExclusionControl:
    @pytest.mark.parametrize("url,pattern", [
        ("https://api.example.com/", "api.example.com"),
        ("https://API.Example.com./", "api.example.com"),
        ("https://a.b.example.com/", "*.example.com"),
        ("https://127.0.0.1/", "127.0.0.1"),
    ])
    def test_the_same_spelling_is_excluded(self, url, pattern):
        assert excluded(url, [pattern])

    def test_a_different_host_is_not_excluded(self):
        assert not excluded("https://example.org/", ["example.com"])
        assert not excluded("https://example.com/", ["*.example.com"])


class TestExclusionBypass:
    # roe.schema.json allows an IPv6 exclusion only in the bracketed form (`^\[[0-9A-Fa-f:.]+\]$`)
    def test_bracketed_ipv6_exclusion_matches_an_ipv6_target(self):
        assert excluded("https://[::1]/", ["[::1]"])

    def test_ipv6_spellings_of_one_address_match(self):
        assert excluded("https://[0:0:0:0:0:0:0:1]/", ["[::1]"])
        assert excluded("https://[::1]/", ["[0:0:0:0:0:0:0:1]"])

    def test_ipv4_short_form_matches_the_dotted_exclusion(self):
        assert excluded("https://127.1/", ["127.0.0.1"])

    def test_ipv4_integer_form_matches_the_dotted_exclusion(self):
        assert excluded("https://2130706433/", ["127.0.0.1"])

    @pytest.mark.parametrize("host", ["0x7f.0.0.1", "0177.0.0.1", "0x7f000001", "017700000001", "127.0.0.01"])
    def test_ipv4_hex_and_octal_forms_are_refused_not_compared(self, host):
        """Parsers disagree on these spellings, so they are refused outright (host_of -> None), never matched."""
        assert safety.host_of(f"https://{host}/") is None
        assert not excluded(f"https://{host}/", ["127.0.0.1"])

    def test_the_roe_check_refuses_a_hex_or_octal_ipv4_target(self, b):
        d = doc(b, "roe.yaml").data
        t = next(x for x in d["targets"] if x.get("kind") == "http")
        t["base_url"] = "https://0x7f.0.0.1/"
        assert "E-ROE-TARGETS" in codes(b)

    def test_ipv4_mapped_ipv6_matches_the_ipv4_exclusion(self):
        assert excluded("https://[::ffff:127.0.0.1]/", ["127.0.0.1"])

    def test_the_roe_check_reports_the_ipv6_bypass(self, b):
        """End to end: a target the ROE itself excludes must give E-ROE-TARGETS (as it does for a plain host name)."""
        d = doc(b, "roe.yaml").data
        t = next(x for x in d["targets"] if x.get("kind") == "http")
        t["base_url"] = "https://[::1]/"
        d["exclusions"]["hosts"] = ["[::1]"]
        assert "E-ROE-TARGETS" in codes(b)


# --- yamlstrict: explicit tags change the value a signature covers ------------------------------------------

class TestYamlTagControl:
    def test_a_plain_document_loads(self):
        assert yamlstrict.load('a: "1"\nb: 2\n') == {"a": "1", "b": 2}

    @pytest.mark.parametrize("text", ["a: !!str 1\n", "a: !!int '1'\n", "a: !!binary AAAA\n"])
    def test_explicit_secondary_tags_are_rejected(self, text):
        with pytest.raises(yamlstrict.StrictYAMLError):
            yamlstrict.load(text)


class TestYamlTagBypass:
    @pytest.mark.parametrize("text", [
        'a: ! "1"\n',          # non-specific tag: PyYAML resolves it to int 1, other parsers keep the string "1"
        "a: ! 1\n",
        "a: !local 1\n",       # application-specific tag
        "a: !<tag:example.com,2026:x> 1\n",
    ])
    def test_the_non_specific_and_local_tags_are_rejected(self, text):
        with pytest.raises(yamlstrict.StrictYAMLError):
            yamlstrict.load(text)


# --- safety.ip_problem: IPv4-compatible IPv6 ------------------------------------------------------------------

class TestIpProblemControl:
    @pytest.mark.parametrize("ip", ["127.0.0.1", "10.0.0.1", "169.254.169.254", "::1", "::ffff:127.0.0.1"])
    def test_non_public_addresses_are_refused(self, ip):
        assert safety.ip_problem(ip) is not None

    def test_a_public_address_is_accepted(self):
        assert safety.ip_problem("93.184.216.34") is None


class TestIpProblemBypass:
    @pytest.mark.parametrize("ip", [
        "::127.0.0.1",         # IPv4-compatible (deprecated) form of loopback
        "::10.0.0.1",
        "::169.254.169.254",   # cloud metadata
        "::7f00:1",            # the same loopback written in hex groups
    ])
    def test_ipv4_compatible_ipv6_of_a_non_public_address_is_refused(self, ip):
        assert safety.ip_problem(ip) is not None
