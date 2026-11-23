# SPDX-License-Identifier: Apache-2.0
"""Document signatures carry no domain tag; what stands in for one is tested here (2026-11-22 review E11, docs/09 BL-76).

`crypto.sign_document` signs the JCS bytes of the document without its `signatures` field. An anchor countersignature
has a domain tag (crypto.ANCHOR_DOMAIN); a document signature does not, so in principle a signature made over one kind
of document could be presented with the same bytes as another kind. The review left it as an observation because the
signed kinds have disjoint shapes. That argument was never checked. These tests check it, so that a schema change which
makes two signed kinds overlap fails here instead of silently opening a replay:

  - every signed document kind is a closed object (additionalProperties false) that requires `signatures`;
  - for every ordered pair of signed kinds, some field the first requires is not allowed by the second, so no JSON
    object is valid as both;
  - no example of one signed kind validates under the schema of another;
  - an audit event (signed with crypto.sign_event over the event without `signature`) is not valid as any signed
    document kind either, and the anchor payload starts from its own domain tag.

A domain tag in the signed bytes is the durable fix; it changes every stored signature and is left to the product's
keys module (BL-76). See CONTRIBUTING.md; tests/mutations/signature_domains.json."""
import itertools
import json
import pathlib

import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from vchlib import crypto

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCHEMAS = ROOT / "docs" / "schemas"
SIGNED_KINDS = ["engagement", "feedback", "gate-record", "key-registry", "report-withdrawal", "roe"]


def schema(kind):
    return json.loads((SCHEMAS / f"{kind}.schema.json").read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def registry():
    res = [(p.name, Resource.from_contents(json.loads(p.read_text(encoding="utf-8")))) for p in SCHEMAS.glob("*.schema.json")]
    return Registry().with_resources(res)


def valid(registry, kind, obj):
    return Draft202012Validator(schema(kind), registry=registry).is_valid(obj)


def test_the_signed_kinds_are_exactly_the_schemas_with_top_level_signatures():
    found = sorted(p.name.removesuffix(".schema.json") for p in SCHEMAS.glob("*.schema.json")
                   if "signatures" in (json.loads(p.read_text(encoding="utf-8")).get("properties") or {}))
    assert found == SIGNED_KINDS                               # a new signed kind must be added here and pass the tests below


@pytest.mark.parametrize("kind", SIGNED_KINDS)
def test_a_signed_kind_is_a_closed_object_that_requires_its_signatures(kind):
    s = schema(kind)
    assert s.get("type") == "object" and s.get("additionalProperties") is False
    assert "signatures" in s["required"] and len(s["required"]) >= 4


@pytest.mark.parametrize("a, b", list(itertools.permutations(SIGNED_KINDS, 2)))
def test_no_object_is_valid_as_two_signed_kinds(a, b):
    """Some field `a` requires is not a property of `b`; `b` is closed, so an object valid as `a` is invalid as `b`."""
    sa, sb = schema(a), schema(b)
    only_a = set(sa["required"]) - set(sb["properties"]) - {"signatures"}
    assert only_a, f"every required field of {a} is allowed by {b}: a signature over one could be replayed as the other"


def test_no_signed_example_validates_as_another_signed_kind(b, registry):
    seen = set()
    for d in b.docs:
        if d.kind in SIGNED_KINDS and isinstance(d.data, dict):
            seen.add(d.kind)
            assert valid(registry, d.kind, d.data), d.path
            for other in SIGNED_KINDS:
                if other != d.kind:
                    assert not valid(registry, other, d.data), (d.path, other)
    assert seen >= {"engagement", "gate-record", "key-registry", "roe"}


def test_an_audit_event_is_not_a_signed_document(b, registry):
    ev = next(e for d in b.docs if d.kind == "audit-event" for e in d.data if e.get("signature"))
    body = {k: v for k, v in ev.items() if k != "signature"}
    assert crypto.event_payload(ev) == crypto.jcs(body)
    for kind in SIGNED_KINDS:
        assert not valid(registry, kind, body) and not valid(registry, kind, ev), kind


def test_the_anchor_payload_has_its_own_domain_tag(b):
    ev = next(e for d in b.docs if d.kind == "audit-event" for e in d.data if e.get("event_type") == "audit_anchor")
    payload = json.loads(crypto.anchor_payload(ev))
    assert payload.get("domain") == crypto.ANCHOR_DOMAIN == "vibecheck/audit_anchor/v2"
    assert set(payload) == {"domain", "run_id", "seq", "prev_hash", "event_sha256"}
    assert crypto.anchor_payload(ev) != crypto.event_payload(ev)


def test_the_backlog_records_the_missing_tag():
    row = next(ln for ln in (ROOT / "docs" / "09-backlog.md").read_text(encoding="utf-8").splitlines() if ln.startswith("| BL-76 |"))
    assert "領域標籤" in row and "`tests/test_signature_domains.py`" in row and "| 待辦" in row
