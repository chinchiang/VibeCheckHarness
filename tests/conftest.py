"""Shared fixtures: load the example bundle once, hand each test a deep copy."""
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from vchlib import crypto  # noqa: E402
from vchlib.bundle import load_bundle  # noqa: E402
from vchlib.checks import run_all  # noqa: E402

KEY_DIR = ROOT / "tests" / "fixtures" / "TEST_ONLY_private_keys"


@pytest.fixture(scope="session")
def base_bundle():
    return load_bundle(ROOT)


@pytest.fixture
def b(base_bundle):
    return base_bundle.clone()


@pytest.fixture(scope="session")
def keys():
    """TEST ONLY private keys by name (erin_old, erin, heidi, ...)."""
    return {p.name.split(".")[0]: crypto.load_private_pem(p) for p in KEY_DIR.glob("*.TEST_ONLY.pem")}


def doc(bundle, suffix):
    d = bundle.doc(suffix)
    assert d is not None, suffix
    return d


def codes(bundle):
    return run_all(bundle).codes()


def resign_gate(bundle, suffix, keys, key_for=None):
    """Re-sign a gate record after mutating it (key_for: person_id -> TEST ONLY key name)."""
    rec = doc(bundle, suffix).data
    key_for = key_for or {}
    rec["signatures"] = [crypto.sign_document(rec, a["person_id"], keys[key_for.get(a["person_id"], a["person_id"])])
                         for a in rec["approvers"]]
    return rec
