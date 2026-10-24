# SPDX-License-Identifier: Apache-2.0
"""v0.4 Scope Proxy reference rules (docs/08 §11.7): resolved-address classifier, backslash as a path
separator, and the extended shared-platform suffix list."""
import copy

import pytest

from conftest import doc
from vchlib import safety
from vchlib.checks import platform_of, run_all


# ================================================================ resolved addresses
@pytest.mark.parametrize("addr", [
    "64:ff9b::a9fe:a9fe",      # NAT64 to 169.254.169.254 (Python is_global says True)
    "64:ff9b:1::1",
    "::ffff:8.8.8.8",          # IPv4-mapped literal
    "::ffff:10.0.0.1",
    "2002:a00:1::1",           # 6to4 with an embedded 10.0.0.1
    "2001:0:4136:e378::1",     # Teredo
    "fec0::1",                 # deprecated site-local (is_global True)
    "fd00::1", "fe80::1", "::1", "::",
    "169.254.169.254", "10.0.0.1", "100.64.0.1", "127.0.0.1", "0.0.0.0", "224.0.0.1", "ff02::1",
    "not-an-ip",
])
def test_non_public_addresses_are_denied(addr):
    assert safety.ip_problem(addr) is not None


@pytest.mark.parametrize("addr", ["8.8.8.8", "2606:4700::1111", "[2606:4700::1111]"])
def test_public_addresses_are_allowed(addr):
    assert safety.ip_problem(addr) is None


def test_local_target_allows_only_loopback():
    assert safety.ip_problem("127.0.0.1", local_target=True) is None
    assert safety.ip_problem("::1", local_target=True) is None
    assert safety.ip_problem("10.0.0.1", local_target=True) is not None


# ================================================================ backslash
@pytest.mark.parametrize("path", ["/admin%5Cbilling/x", "/admin\\billing/x", "/ADMIN%5cbilling/x"])
def test_backslash_is_a_separator(path):
    assert safety.normalize_for_match(path) == "/admin/billing/x"
    assert safety.path_may_match(safety.normalize_for_match(path), "/admin/billing/*")


def test_backslash_bypass_of_an_exclusion_is_s3(b):
    tc = copy.deepcopy(doc(b, "testcase.bola-list.example.json").data)
    roe = doc(b, "roe.yaml").data
    roe["exclusions"]["paths"] = ["/admin/billing/*"]
    tc["request_allowlist"] = [{"target_id": "tgt-staging-api", "method": "GET", "path": "/admin%5Cbilling/x",
                                "step_id": None, "graphql_operation": None}]
    lv, trace = safety.compute_safety_class(tc, roe, doc(b, "tools.yaml").data, doc(b, "seed-manifest.yaml").data)
    assert lv == "S3"


# ================================================================ shared platforms
@pytest.mark.parametrize("host", ["my-app.lovable.app", "demo.replit.app", "api.foo.workers.dev", "acme.github.io",
                                  "main.d1.amplifyapp.com", "acme.azurewebsites.net", "svc.up.railway.app"])
def test_vibe_coding_platforms_are_shared(host):
    assert platform_of(host) == "other"


def test_shared_platform_target_needs_platform_project(b):
    t = doc(b, "roe.yaml").data["targets"][0]
    t["base_url"] = "https://acme-invoices.lovable.app"
    assert "E-ROE-PLATFORM" in run_all(b).codes()
