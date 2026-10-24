# SPDX-License-Identifier: Apache-2.0
"""v0.4 third priority: example/JSON consistency.

- trials.n_effective (n') is recorded, bounded (k <= n' <= n, E-RESULT-TRIALS) and decides a probabilistic E_pass;
- oracle queries may return a row hash (detects in-place PUT/PATCH);
- example B has a query for unconfirmed refunds on any order;
- zap:baseline documents the -S requirement of zap-api-scan.py.
"""
import pytest

from conftest import codes, doc
from vchlib.checks import Ctx
from vchlib.derive import classify_result

TR_LLM = "testresult.llm-pass.example.json"


def errors(b, code):
    from vchlib.checks import run_all
    return [i for i in run_all(b).errors if i.code == code]


def test_examples_record_n_effective(b):
    assert not errors(b, "E-RESULT-TRIALS")


@pytest.mark.parametrize("trials", [{"n": 60, "k": 0, "n_effective": 61}, {"n": 60, "k": 5, "n_effective": 3}])
def test_n_effective_bounds(b, trials):
    doc(b, TR_LLM).data["trials"] = trials
    assert errors(b, "E-RESULT-TRIALS")


def test_probabilistic_pass_needs_30_effective_trials(b):
    c = Ctx(b)
    tr = doc(b, TR_LLM).data
    cl = c.ix.first("cluster", cluster_id="K-011").data
    assert classify_result(c.ix, tr, cl)[0] == "E_pass"          # n = n' = 60 in the example
    tr["trials"]["n_effective"] = 29                             # 31 trials never reached the document
    cls, why = classify_result(c.ix, tr, cl)
    assert cls == "E_inc" and "n'>=30" in why


def test_row_hash_oracle_queries(b):
    q = doc(b, "seed-manifest.yaml").data["oracle_queries"]
    assert q["Q-invoice-b-row"]["returns"] == "row_hash" and q["Q-u2-order"]["returns"] == "row_hash"
    assert q["Q-unconfirmed-refunds"]["params"] == ["const:refund"]
    assert "E-SCHEMA" not in codes(b)


def test_zap_baseline_requires_safe_mode_note(b):
    mode = doc(b, "tools.yaml").data["tools"]["zap"]["modes"]["baseline"]
    assert mode["base_class"] == "S0" and "-S" in mode["description"]
