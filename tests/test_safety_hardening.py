# SPDX-License-Identifier: Apache-2.0
"""Scope Proxy reference rules hardened after the 2026-11-22 internal code review (vchlib.safety, docs/08 section 11.7).

The review ran bypass inputs against the reference implementation the product is to port:

1. ip_problem allowed IPv4-compatible IPv6 addresses (::7f00:1 is ::127.0.0.1, ::a9fe:a9fe is ::169.254.169.254) and
   the deprecated 6to4 relay anycast block, because Python's is_global is True for both;
2. the object-id binding recognised only id / *_id / *Id / *ID, so `userid`, `uid`, `guid`, `uuid`, `pk`, `user-id`
   and `USER_ID` carried any value;
3. is_mutation treated every method outside POST / PUT / PATCH / DELETE as a read (fail open);
4. a path template could hold control characters or full-width letters that an exclusion does not match.

Each `test_..._blocked` / `..._is_a_write` / `..._rejected` test failed before the fix and passes after it
(tests/mutations/safety_hardening.json); the `..._still_...` tests check that nothing legitimate is refused and no
earlier rule was relaxed. See CONTRIBUTING.md."""
import pytest

from vchlib import safety

ALLOWED = {"S1"}


# ---------------------------------------------------------------- 1. addresses
@pytest.mark.parametrize("addr", ["::7f00:1", "::127.0.0.1", "::a9fe:a9fe", "::0a00:0001"])
def test_ipv4_compatible_ipv6_is_blocked(addr):
    assert safety.ip_problem(addr) is not None


def test_6to4_relay_anycast_is_blocked():
    assert safety.ip_problem("192.88.99.1") is not None
    assert safety.edge_range_problem("192.88.99.0/24") is not None


def test_public_addresses_and_the_local_target_still_pass():
    assert safety.ip_problem("8.8.8.8") is None
    assert safety.ip_problem("2a00:1450:4001:81b::200e") is None
    assert safety.ip_problem("192.88.98.1") is None and safety.ip_problem("192.88.100.1") is None
    assert safety.ip_problem("::1", local_target=True) is None
    assert safety.ip_problem("::1") is not None and safety.ip_problem("::") is not None


# ---------------------------------------------------------------- 2. object-id keys
NEW_ID_KEYS = ["userid", "uid", "guid", "uuid", "pk", "user-id", "USER_ID", "orders.id", "ownerid", "ORDERID", "userUuid",
               "docGuid", "key", "Uid", "user_uuid", "row-pk"]


@pytest.mark.parametrize("key", NEW_ID_KEYS)
def test_unbound_value_under_an_id_like_key_is_blocked(key):
    assert safety.request_binding_problem(None, {key: "X"}, ALLOWED) is not None, key
    assert safety.request_binding_problem(None, {"data": [{"attrs": {key: "X"}}]}, ALLOWED) is not None, key
    # the query already names a bound object, so only the new key can be the reason
    assert safety.request_binding_problem({"id": "eq.S1"}, None, ALLOWED, True, "PATCH") is None
    assert safety.request_binding_problem({"id": "eq.S1", key: "eq.X"}, None, ALLOWED, True, "PATCH") is not None, key


@pytest.mark.parametrize("key", ["uids", "uuids", "user-ids", "USER_IDS", "userids", "pks", "docGuids", "keys"])
def test_plural_id_like_key_is_blocked(key):
    assert safety.request_binding_problem(None, {key: ["S1"]}, ALLOWED) is not None, key
    assert safety.request_binding_problem({key: "S1"}, None, ALLOWED) is not None, key


@pytest.mark.parametrize("key", NEW_ID_KEYS)
def test_bound_value_under_an_id_like_key_still_passes(key):
    assert safety.request_binding_problem(None, {key: "S1"}, ALLOWED, True, "POST") is None, key
    assert safety.request_binding_problem({key: "eq.S1"}, None, ALLOWED, True, "PATCH") is None, key


@pytest.mark.parametrize("key", ["paid", "valid", "void", "grid", "android", "liquid", "fluid", "isPaid", "hybrid",
                                 "api_key", "sort_key", "name", "status", "owner", "email", "slug"])
def test_ordinary_keys_are_still_not_bound(key):
    # `owner` / `email` / `slug` are the documented gap of the heuristic (docs/06 section 3, docs/09 BL-74)
    assert not safety.is_id_key(key) and not safety.is_ids_key(key), key
    assert safety.request_binding_problem(None, {key: "X", "id": "S1"}, ALLOWED, True, "POST") is None, key


@pytest.mark.parametrize("key", ["id", "invoice_id", "userId", "userID", "_id", "ACCTID", "Id"])
def test_the_earlier_id_keys_are_still_bound(key):
    assert safety.is_id_key(key), key
    assert safety.request_binding_problem(None, {key: "X"}, ALLOWED) is not None, key


@pytest.mark.parametrize("key", ["ids", "invoice_ids", "userIds", "userIDs"])
def test_the_earlier_plural_keys_are_still_rejected(key):
    assert safety.is_ids_key(key), key


# ---------------------------------------------------------------- 3. methods
@pytest.mark.parametrize("method", ["delete", "Post", "PURGE", "MOVE", "COPY", "MKCOL", "PROPPATCH", "LINK", "QUERY", "", None])
def test_unknown_method_is_a_write(method):
    assert safety.is_mutation({"method": method, "path": "/x", "target_id": "t"}) is True


def test_request_without_a_method_is_a_write():
    assert safety.is_mutation({"path": "/x", "target_id": "t"}) is True


@pytest.mark.parametrize("method", ["GET", "HEAD", "OPTIONS"])
def test_safe_methods_are_still_reads(method):
    # D5 (later change): a GET / HEAD is a read when that is proven; OPTIONS needs no proof
    proven = {("GET", "/x")}
    assert safety.is_mutation({"method": method, "path": "/x", "target_id": "t"}, proven_reads=proven) is False


def test_the_declared_exceptions_of_is_mutation_still_hold():
    gql = {"t": {"/graphql"}}
    query = {"method": "POST", "path": "/graphql", "target_id": "t", "graphql_operation": "query"}
    assert safety.is_mutation(query, gql) is False
    assert safety.is_mutation({**query, "graphql_operation": "mutation"}, gql) is True
    manifest = {"read_only_endpoints": [{"target_id": "t", "method": "POST", "path_template": "/search"}],
                "state_changing_reads": [{"target_id": "t", "method": "GET", "path_template": "/logout"}]}
    assert safety.is_mutation({"method": "POST", "path": "/search", "target_id": "t"}, None, manifest) is False
    assert safety.is_mutation({"method": "GET", "path": "/logout", "target_id": "t"}, None, manifest) is True
    for m in safety.STATE_CHANGING:
        assert safety.is_mutation({"method": m, "path": "/x", "target_id": "t"}) is True


# ---------------------------------------------------------------- 4. path characters
BAD_PATHS = ["/admin\t/x", "/admin\x00/x", "/admin\x7f/x", "/admin\n/x", "/ａdmin/x", "/admin/ｘ", "/café/x", "/ﬁle/x"]


@pytest.mark.parametrize("path", BAD_PATHS)
def test_control_and_non_nfkc_characters_are_rejected_in_a_template(path):
    assert safety.is_normalized(path) is False


@pytest.mark.parametrize("path", BAD_PATHS)
def test_control_and_non_nfkc_characters_are_rejected_at_run_time(path):
    allowlist = [{"target_id": "t", "method": "GET", "path": path}]
    assert safety.allowlist_match("t", "GET", path, allowlist, {}) is None


@pytest.mark.parametrize("path", ["/admin/x", "/api/v1/orders", "/訂單/明細", "/café/x", "/a-b_c.d~e/x"])
def test_ordinary_and_nfkc_non_ascii_paths_still_pass(path):
    assert safety.is_normalized(path) is True
    allowlist = [{"target_id": "t", "method": "GET", "path": path}]
    assert safety.allowlist_match("t", "GET", path, allowlist, {}) is not None
