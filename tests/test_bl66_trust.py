# SPDX-License-Identifier: Apache-2.0
"""BL-66 (review r10): engagement, key registry, signature and person checks — every error code below is triggered by at least one test.
Each test fails when its check is disabled (tests/mutations/bl66_trust.json); see CONTRIBUTING.md.

  engagement    E-ENG-MISSING, E-ENG-VALIDITY, E-ENG-DATA-CLASS, E-ENG-MODEL-CLASS, E-ENG-LANE-A, E-ENG-OWNERSHIP,
                E-ENG-SIGNATORIES, E-ENG-OWASP, E-ENG-TELEMETRY;
  key registry  E-KR-MISSING, E-KR-ROOT-SIG, E-KR-LOCATION, E-KR-DUP, E-KR-ALG, E-KR-REVOCATION, E-KR-VALIDITY,
                E-KR-AUTOMATION;
  signatures    E-SIG-UNKNOWN-KEY, E-SIG-EXPIRED;
  persons       E-PERSON-UNKNOWN, E-PERSON-KEY, E-PERSON-ROLE.
Edits to signed YAML break its signature (E-SIG-* / E-KR-ROOT-SIG), so most tests assert membership and, where a
code has several branches, the branch's message.
"""
import copy

import pytest

from conftest import codes, doc, rederive
from vchlib import crypto
from vchlib.checks import run_all

G1 = "gate-record.g1.example.json"
UNKNOWN_FP = "ed25519:SHA256:" + "A" * 43


def msgs(bundle, code):
    return [i.msg for i in run_all(bundle).errors if i.code == code]


def fp_of(keys, name):
    return crypto.fingerprint(crypto.raw_public(keys[name]))


def entry(b, person, n=0):
    return [e for e in doc(b, "key-registry.yaml").data["entries"] if e["person_id"] == person][n]


def eng(b):
    return doc(b, "engagement.yaml").data


def resign_eng(b, keys):
    e = eng(b)
    e["signatures"] = [crypto.sign_document(e, s["signer"], keys[s["signer"]]) for s in e["signatures"]]


def resign_registry(b, keys):
    kr = doc(b, "key-registry.yaml").data
    kr["signatures"] = [crypto.sign_document(kr, "org_root", keys["org_root"])]


def test_the_example_bundle_is_clean(b):
    assert codes(b) == set()


# ---------------------------------------------------------------- engagement
def test_e_eng_missing_without_an_engagement(b):
    doc(b, "engagement.yaml").data = {}
    assert "E-ENG-MISSING" in codes(b)


@pytest.mark.parametrize("change, needle", [
    (lambda e: e["validity"].update(not_before=e["validity"]["not_after"]), "not_before must precede"),
    (lambda e: e.update(issued_at="2026-11-01T00:00:00+08:00"), "issued_at after the end"),
])
def test_e_eng_validity(b, keys, change, needle):
    change(eng(b))
    resign_eng(b, keys)
    assert any(needle in m for m in msgs(b, "E-ENG-VALIDITY"))


def test_e_eng_data_class_must_be_p_or_c(b):
    eng(b)["data_class"] = "X"
    assert "E-ENG-DATA-CLASS" in codes(b)


def test_e_eng_model_class_p_only_model_listed_for_c(b, keys):
    eng(b)["allowed_models"]["C"].append("nemotron_cloud")
    resign_eng(b, keys)
    assert "E-ENG-MODEL-CLASS" in codes(b)


def test_e_eng_lane_a_model_not_allowed_for_the_data_class(b, keys):
    eng(b)["lane_a_model"] = "nemotron_cloud"
    resign_eng(b, keys)
    assert "E-ENG-LANE-A" in codes(b)


@pytest.mark.parametrize("change, needle", [
    (lambda e: e["code_ownership"]["attested_by"].update(role="management"), "must be the app_owner"),
    (lambda e: e["code_ownership"].update(attestation=False), "attestation must be true"),
])
def test_e_eng_ownership(b, keys, change, needle):
    change(eng(b))
    resign_eng(b, keys)
    assert any(needle in m for m in msgs(b, "E-ENG-OWNERSHIP"))


def test_e_eng_ownership_attester_not_among_signatories(b):
    """Branch 713 alone: attested_by keeps the app_owner role but names a key the signatories do not carry."""
    eng(b)["code_ownership"]["attested_by"]["key_fingerprint"] = UNKNOWN_FP
    assert msgs(b, "E-ENG-OWNERSHIP") == ["code_ownership.attested_by must also sign the engagement"]


def test_e_eng_signatories_must_cover_the_g0a_roles(b, keys):
    e = eng(b)
    e["signatories"] = [s for s in e["signatories"] if s["role"] != "management"]
    e["signatures"] = [s for s in e["signatures"] if s["signer"] != "carol"]
    resign_eng(b, keys)
    assert "E-ENG-SIGNATORIES" in codes(b)


def test_e_eng_owasp_version(b, keys):
    eng(b)["owasp_llm_version"] = "2024"
    resign_eng(b, keys)
    assert "E-ENG-OWASP" in codes(b)


def test_e_eng_telemetry_must_be_disabled(b, keys):
    eng(b)["telemetry_disabled"] = False
    resign_eng(b, keys)
    assert "E-ENG-TELEMETRY" in codes(b)


# ---------------------------------------------------------------- key registry
def test_e_kr_missing_without_a_registry(b):
    doc(b, "key-registry.yaml").data = {}
    assert "E-KR-MISSING" in codes(b)


def test_e_kr_root_sig_signer_must_be_org_root(b):
    doc(b, "key-registry.yaml").data["signatures"][0]["signer"] = "alice"
    assert msgs(b, "E-KR-ROOT-SIG") == ["the registry must carry exactly one org_root signature by the pinned key"]


def test_e_kr_root_sig_must_verify(b):
    entry(b, "alice")["display_name"] = "Mallory"
    assert msgs(b, "E-KR-ROOT-SIG") == ["root signature does not verify"]


def test_e_kr_root_sig_resigned_registry_is_clean(b, keys):
    entry(b, "alice")["display_name"] = "Mallory"
    resign_registry(b, keys)
    rederive(b, keys)                      # the runs pin the registry's content hash
    assert codes(b) == set()


def test_e_kr_location_registry_id(b, keys):
    doc(b, "key-registry.yaml").data["registry_id"] = "elsewhere/key-registry.yaml"
    resign_registry(b, keys)
    rederive(b, keys)
    assert codes(b) == {"E-KR-LOCATION"}


def test_e_kr_location_engagement_ref(b, keys):
    eng(b)["key_registry_ref"] = "elsewhere/key-registry.yaml"
    resign_eng(b, keys)
    assert any("key_registry_ref" in m for m in msgs(b, "E-KR-LOCATION"))


def test_e_kr_location_registry_file_must_exist(b, keys):
    loc = "docs/examples/no-such-registry.yaml"
    doc(b, "toolkit.yaml").data["key_registry"]["location"] = loc
    assert any(m == f"key registry {loc} does not exist" for m in msgs(b, "E-KR-LOCATION"))


def test_e_kr_dup_fingerprints(b, keys):
    kr = doc(b, "key-registry.yaml").data
    kr["entries"].append(copy.deepcopy(entry(b, "alice")))
    resign_registry(b, keys)
    assert "E-KR-DUP" in codes(b)


def test_e_kr_alg_must_be_ed25519(b, keys):
    entry(b, "alice")["alg"] = "rsa"
    resign_registry(b, keys)
    assert "E-KR-ALG" in codes(b)


def test_e_kr_revocation_both_or_neither(b, keys):
    entry(b, "erin", 0)["revocation_reason"] = None
    resign_registry(b, keys)
    assert any("both be set" in m for m in msgs(b, "E-KR-REVOCATION"))


def test_e_kr_revocation_after_registry_issue(b, keys):
    entry(b, "erin", 0)["revoked_at"] = "2026-09-16T09:00:00+08:00"
    resign_registry(b, keys)
    assert msgs(b, "E-KR-REVOCATION") == ["revoked_at is after the registry issued_at"]


def test_e_kr_validity_not_before_after_not_after(b, keys):
    entry(b, "alice")["not_before"] = "2028-01-01T00:00:00+08:00"
    resign_registry(b, keys)
    assert "E-KR-VALIDITY" in codes(b)


def test_e_kr_automation_account_holds_a_key(b, keys):
    kr = doc(b, "key-registry.yaml").data
    bot = copy.deepcopy(entry(b, "heidi"))
    bot["person_id"] = "ci-bot"
    kr["entries"] = [e for e in kr["entries"] if e["person_id"] != "heidi"] + [bot]
    resign_registry(b, keys)
    assert "E-KR-AUTOMATION" in codes(b)


# ---------------------------------------------------------------- signatures
def test_e_sig_unknown_key(b):
    rec = doc(b, G1).data
    rec["approvers"][0]["key_fingerprint"] = UNKNOWN_FP
    rec["signatures"][0]["key_fingerprint"] = UNKNOWN_FP
    assert "E-SIG-UNKNOWN-KEY" in codes(b)


def test_e_sig_expired_without_a_signature_time(b):
    del eng(b)["issued_at"]
    assert any("no valid signature time" in m for m in msgs(b, "E-SIG-EXPIRED"))


def test_e_sig_expired_outside_key_validity(b, keys):
    entry(b, "carol")["not_after"] = "2026-09-01T00:00:00+08:00"
    resign_registry(b, keys)
    assert any("outside key validity" in m for m in msgs(b, "E-SIG-EXPIRED"))


# ---------------------------------------------------------------- persons
def test_e_person_unknown_run_owner(b):
    eng(b)["run_owner"] = "mallory"
    assert any("'mallory' is not in the key registry" in m for m in msgs(b, "E-PERSON-UNKNOWN"))


def test_e_person_unknown_upstream_terms_confirmer(b):
    doc(b, "roe.yaml").data["upstream_llm_providers"][0]["terms_confirmed_by"] = "mallory"
    assert "upstream terms_confirmed_by must be a registry person" in msgs(b, "E-PERSON-UNKNOWN")


def test_e_person_key_of_another_person(b, keys):
    eng(b)["signatories"][1]["key_fingerprint"] = fp_of(keys, "heidi")
    assert any("carol: key" in m for m in msgs(b, "E-PERSON-KEY"))


def test_e_person_role_not_granted(b):
    eng(b)["signatories"][1]["role"] = "test_lead"
    assert any("carol: role test_lead" in m for m in msgs(b, "E-PERSON-ROLE"))
