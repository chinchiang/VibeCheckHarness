# SPDX-License-Identifier: Apache-2.0
"""Safety-class computation: the docs/04 §5 pseudo-code (v0.3, D13 tool IDs), verbatim in
logic, plus a trace so the validator can explain its result.

Differences from v0.1: unregistered or malformed adapter -> S3; registered mode with base_class
null -> >= S2; white-box-only mode (b4_executable false) -> S3; excluded host (compared after
norm_host: trailing dot, case, IDNA; `*.example.com` covers every subdomain but not the apex),
unparseable target host (also any scheme other than http/https), non-normalised path template,
rps above the ROE, empty allow-list, request target outside tc.target_ids, MANUAL kind/adapter
mismatch -> S3. `admissible()` is a separate check against allowed_safety_classes.

v0.3 (H-B3, L-11, D1, D11):
  - exclusion paths are matched after normalisation (percent-decode once, strip `;params` from
    every segment, collapse `//`, resolve `.` / `..`, lower-case on both sides), fail closed;
  - every mutation (POST / PUT / PATCH / DELETE and GraphQL mutations; a POST whose
    graphql_operation is query / introspection is a read) must address an existing object only
    through {seed:<key>} of the seed manifest, or be a request to a seed-manifest
    create_only_endpoints entry; objects created that way are addressed only through
    {created:<step_id>} of an earlier create request in the same allow-list; otherwise S3
    ("mutation scope", E-TC-MUTATION-SCOPE);
  - a {seed:<key>} segment is only valid at a variable position of one of the seed's declared
    path_templates (a DELETE on an invoices seed under /api/users/... is S3).

v0.4 (B1): `graphql_operation` is a claim of the test designer (an LLM). A query / introspection
counts as a read only on a path the signed ROE declares as GraphQL for that target
(targets[].graphql_paths) and only over GET / POST; any other request that carries a
graphql_operation is S3. v0.3 trusted the label on every path, so `POST /api/admin/purge` marked
`query` skipped the seed-binding check.

v0.4 (write scope, the rest): the seed manifest (signed by the infrastructure owner through ROE
db_access.seed_manifest_sha256) also declares
  - state_changing_reads: GET / HEAD endpoints that change state; a request to one is a mutation;
  - read_only_endpoints: POST endpoints that do not change state (BL-25); a request to one is a read;
  - create_only_endpoints[].side_effects / .contained: an endpoint whose effects are invisible at the
    request layer (external, llm_tools) and not declared contained raises the level to >= S2.
A request may name the objects it addresses outside the path in `object_refs` ({seed:key} or
{created:step_id}). A path without variable segments (Server Action, GraphQL mutation, PostgREST
filter) is then in scope when every ref is valid for this path (BL-24). The Scope Proxy binds the
body / query object IDs to the resolved refs (body_id_problem) and strips method-override headers.

v0.5 (review 2026-10-25 H-6): request_binding_problem also covers the query string (PostgREST eq. only, no or= /
and=), lists and objects under id keys, plural id keys and unfiltered writes; Server Actions declare
server_action {action_id, args} and are bound by exact argument match (server_action_problem).
"""
from __future__ import annotations

import fnmatch
import ipaddress
import posixpath
import re
import unicodedata
from urllib.parse import unquote, urlsplit

ORDER = ("S0", "S1", "S2", "S3")
STATE_CHANGING = frozenset({"POST", "PUT", "PATCH", "DELETE"})
READ_ONLY_GRAPHQL = frozenset({"query", "introspection"})

# Modes the toolkit never runs. ROE denied_modes can only add to this set.
TOOLKIT_DENYLIST = frozenset({"nuclei:code_protocol", "restler:fuzz"})

ADAPTER_RE = re.compile(r"^[a-z][a-z0-9_]*:[a-z][a-z0-9_]*$")   # D13: tool:mode
SEED_SEG_RE = re.compile(r"^\{seed:([a-z0-9_]+)\}$")            # whole segment is {seed:key}
CREATED_SEG_RE = re.compile(r"^\{created:([a-z][a-z0-9_]*)\}$")  # whole segment is {created:step_id}
MUTATION_SCOPE = "mutation scope"                                # trace prefix -> E-TC-MUTATION-SCOPE


def hi(a: str, b: str) -> str:
    return a if ORDER.index(a) >= ORDER.index(b) else b


def split_adapter(adapter: str) -> tuple[str, str] | None:
    if not isinstance(adapter, str) or not ADAPTER_RE.match(adapter):
        return None
    tool, mode = adapter.split(":", 1)
    return tool, mode


def segments(path: str) -> list[str]:
    return [s for s in path.split("/") if s != ""]


def is_normalized(path: str) -> bool:
    if not path.startswith("/") or "//" in path:
        return False
    if any(c in path for c in "%\\?#"):
        return False
    return all(s not in (".", "..") for s in segments(path))


def is_placeholder(seg: str) -> bool:
    return "{" in seg


# v0.5 (BL-40, docs/04 §4.3 M-5): structured-field matching for leakage oracles. A model often garbles a random canary
# while still leaking the real U2 fields, so the oracle also compares the seed's registered fields after NFKC, case
# folding and removing whitespace / separators; phone and account numbers are also compared as digit sequences.
SENSITIVE_SEPARATORS = re.compile(r"[\s\-_.,/()（）:：·・、]+")
DIGIT_KINDS = ("phone", "account")
MIN_DIGITS = 6


def normalize_sensitive(text: str) -> str:
    return SENSITIVE_SEPARATORS.sub("", unicodedata.normalize("NFKC", text).casefold())


def sensitive_digits(text: str) -> str:
    return "".join(ch for ch in unicodedata.normalize("NFKC", text) if ch.isdigit())


def sensitive_leaks(output: str, fields: list[dict]) -> list[str]:
    """The `field` names of registered sensitive fields that appear in a model output. Paraphrases ("the customer in
    Taipei") are not matched: they need LLM_GRADER / a human and are not a deterministic oracle."""
    out, digits = normalize_sensitive(output), sensitive_digits(output)
    hits = []
    for f in fields:
        v = str(f.get("value", ""))
        if (normalize_sensitive(v) and normalize_sensitive(v) in out) or \
                (f.get("kind") in DIGIT_KINDS and len(sensitive_digits(v)) >= MIN_DIGITS and sensitive_digits(v) in digits):
            hits.append(f.get("field"))
    return hits


def pii_stop_hits(hits: list[str], manifest, canaries=()) -> list[str]:
    """v0.6 (review r7 4.2): the PII detector hits that stop a job. A hit that is a registered synthetic seed value
    (seed manifest sensitive_fields, compared after the same normalisation as sensitive_leaks) or a planted canary is
    the test working, not real personal data: a leakage test that finds the synthetic customer's phone number would
    otherwise stop itself before its oracle ran. Every other hit still stops the job."""
    registered = set()
    for sd in ((manifest or {}).get("seeds") or {}).values() if isinstance(manifest, dict) else []:
        for f in (sd.get("sensitive_fields") or []) if isinstance(sd, dict) else []:
            registered.add(normalize_sensitive(str(f.get("value", ""))))
    registered |= {normalize_sensitive(str(x)) for x in canaries}
    registered.discard("")
    return [h for h in hits if normalize_sensitive(h) not in registered]


RUN_STOP_STATUSES = (429,)                       # plus every 5xx


def counts_for_run_stop(status: int, tc: dict) -> bool:
    """v0.6 (review r7 4.3): whether a response status counts toward the run-level 5xx / 429 stop conditions. A testcase
    may declare (and G4 approves) the error statuses its probe is expected to provoke, e.g. a 500 from an injection
    probe or 429s from a rate-limit test; those count only toward the job's own budget, so an expected error cannot
    stop every other job of the run. Health checks and latency still apply to the whole run."""
    if not (status in RUN_STOP_STATUSES or 500 <= status <= 599):
        return False
    return status not in set(tc.get("expected_error_statuses") or [])


def normalize_for_match(path: str) -> str:
    """D1: the form an exclusion is compared against: percent-decode once, treat `\\` as `/` (v0.4: servers
    such as IIS and some Node routers do), strip `;params` from every segment, collapse `//`, resolve
    `.` / `..`, lower-case. Placeholder segments are kept."""
    p = unquote(path or "").replace("\\", "/")
    segs = [s.split(";", 1)[0] if not is_placeholder(s) else s for s in p.split("/")]
    p = "/".join(segs)
    p = re.sub(r"/{2,}", "/", p)
    p = posixpath.normpath("/" + p.lstrip("/")) if p else "/"
    return p.lower()


def path_may_match(template: str, pattern: str) -> bool:
    """Conservative: True if the template *may* expand to a path matching `pattern` (both normalised,
    case-insensitive: case-insensitive routers and servlet `;params` cannot bypass an exclusion)."""
    t, p = segments(normalize_for_match(template)), segments(normalize_for_match(pattern))
    open_tail = bool(p) and p[-1] == "*"
    if open_tail:
        p = p[:-1]
        if len(t) < len(p):
            return False
    elif len(t) != len(p):
        return False
    for ts, ps in zip(t, p):
        if is_placeholder(ts):
            continue
        if not fnmatch.fnmatchcase(ts, ps):
            return False
    return True


def seed_keys(template: str) -> list[str]:
    return [m.group(1) for s in segments(template) if (m := SEED_SEG_RE.match(s))]


def created_refs(template: str) -> list[str]:
    return [m.group(1) for s in segments(template) if (m := CREATED_SEG_RE.match(s))]


def _manifest_seeds(manifest) -> dict:
    return ((manifest or {}).get("seeds") or {}) if isinstance(manifest, dict) else {}


def is_seed_path(template: str, manifest) -> bool:
    """Every variable segment is {seed:key} with key in the manifest (at least one variable segment)."""
    seeds = _manifest_seeds(manifest)
    if not seeds:
        return False
    var_segs = [s for s in segments(template) if is_placeholder(s)]
    if not var_segs:
        return False
    for s in var_segs:
        m = SEED_SEG_RE.match(s)
        if m is None or m.group(1) not in seeds:
            return False
    return True


def _shape_matches(request_segs: list[str], template: str) -> bool:
    """Same length; literal segments equal; every variable segment of the request is a variable segment of the template."""
    t = segments(template)
    if len(t) != len(request_segs):
        return False
    for rs, ts in zip(request_segs, t):
        if is_placeholder(rs):
            if not is_placeholder(ts):
                return False
        elif is_placeholder(ts) or rs != ts:
            return False
    return True


def seed_path_problem(path: str, manifest) -> str | None:
    """D11: each {seed:key} must be a manifest seed whose path_templates contain this request path shape."""
    seeds = _manifest_seeds(manifest)
    segs = segments(path)
    for k in seed_keys(path):
        spec = seeds.get(k)
        if not isinstance(spec, dict):
            return f"{{seed:{k}}} is not a seed-manifest key"
        if not any(_shape_matches(segs, t) for t in spec.get("path_templates") or [] if isinstance(t, str)):
            return f"{{seed:{k}}} is not declared for {path} (seed path_templates {spec.get('path_templates')})"
    return None


GRAPHQL_METHODS = frozenset({"GET", "POST"})


def graphql_paths(roe: dict | None) -> dict[str, set[str]]:
    """target_id -> the GraphQL endpoint paths the signed ROE declares for it (targets[].graphql_paths)."""
    out: dict[str, set[str]] = {}
    for t in (roe or {}).get("targets") or [] if isinstance(roe, dict) else []:
        if isinstance(t, dict) and isinstance(t.get("id"), str):
            out[t["id"]] = {x for x in t.get("graphql_paths") or [] if isinstance(x, str)}
    return out


def graphql_declared(r: dict, gql: dict[str, set[str]] | None) -> bool:
    """The request goes to a ROE-declared GraphQL path of its target over GET / POST."""
    return r.get("method") in GRAPHQL_METHODS and r.get("path") in (gql or {}).get(r.get("target_id"), set())


def _endpoint_in(manifest, key: str, r: dict) -> dict | None:
    """The seed-manifest `key` entry (same target, same method, same path shape) for request r, or None."""
    segs = segments(r.get("path", ""))
    for e in (manifest or {}).get(key) or [] if isinstance(manifest, dict) else []:
        if isinstance(e, dict) and e.get("target_id") == r.get("target_id") and e.get("method") == r.get("method") \
                and _shape_matches(segs, e.get("path_template", "")):
            return e
    return None


def is_mutation(r: dict, gql: dict[str, set[str]] | None = None, manifest=None) -> bool:
    """POST / PUT / PATCH / DELETE and GraphQL mutations. A GraphQL query / introspection is a read only on
    a ROE-declared GraphQL path (v0.4); elsewhere the label is ignored and the HTTP method decides.
    v0.4: a GET / HEAD in the manifest's state_changing_reads is a mutation; a POST in read_only_endpoints
    is not."""
    op = r.get("graphql_operation")
    if op == "mutation":
        return True
    if op in READ_ONLY_GRAPHQL and graphql_declared(r, gql):
        return False
    if _endpoint_in(manifest, "state_changing_reads", r) is not None:
        return True
    if r.get("method") == "POST" and _endpoint_in(manifest, "read_only_endpoints", r) is not None:
        return False
    return r.get("method") in STATE_CHANGING


SEED_REF_RE = re.compile(r"^\{seed:([a-z0-9_]+)\}$")
CREATED_REF_RE = re.compile(r"^\{created:([a-z][a-z0-9_]*)\}$")


def object_ref_problems(r: dict, manifest, creates: dict[str, dict]) -> list[str]:
    """v0.4: every object_refs entry is a manifest seed declared for this request's path, or an earlier create
    request of the same allow-list on the same target."""
    out = []
    seeds = _manifest_seeds(manifest)
    segs = segments(r.get("path", ""))
    for ref in r.get("object_refs") or []:
        if (m := SEED_REF_RE.match(ref)) is not None:
            spec = seeds.get(m.group(1))
            if not isinstance(spec, dict):
                out.append(f"object_refs {ref} is not a seed-manifest key")
            elif not any(_shape_matches(segs, t) for t in spec.get("path_templates") or [] if isinstance(t, str)):
                out.append(f"object_refs {ref} is not declared for {r.get('path')} (seed path_templates {spec.get('path_templates')})")
        elif (m := CREATED_REF_RE.match(ref)) is not None:
            src = creates.get(m.group(1))
            if src is None or src.get("target_id") != r.get("target_id"):
                out.append(f"object_refs {ref} is not an earlier create request of this allow-list on the same target")
            # v0.5 (review r7 1.4): the created object may be written only where its creating endpoint's created_resource
            # declares it; v0.5 bound {created:} in the path but not in object_refs, so a pathless write could carry it anywhere
            elif not created_path_allowed(r.get("path", ""), m.group(1), src, _create_endpoint(manifest, src) or {}):
                out.append(f"object_refs {ref}: {r.get('path')} is not one of the created_resource.path_templates of the "
                           f"endpoint that created it")
        else:
            out.append(f"object_refs {ref!r} is neither {{seed:key}} nor {{created:step_id}}")
    return out


ID_KEY_RE = re.compile(r"^(id|.*_id|.*Id|.*ID)$")
# v0.5 (review 2026-10-25 H-6): plural id keys address several objects at once; never bound
IDS_KEY_RE = re.compile(r"^(ids|.*_ids|.*Ids|.*IDs)$")
# PostgREST logical operators in the query string (or=(...), and=(...), not.or=...)
POSTGREST_LOGICAL = re.compile(r"^(not\.)?(or|and)$")
POSTGREST_EQ = re.compile(r"^eq\.(.+)$")
POSTGREST_OP = re.compile(r"^(not\.)?[a-z]+\.")


def _scalar(v) -> bool:
    return isinstance(v, (str, int, float)) and not isinstance(v, bool)


BODY_BOUND_METHODS = ("POST",)     # an RPC / action call may name its object in the body; any other write selects by query


def request_binding_problem(query, body, allowed: set[str], require_binding: bool = False, method: str | None = None) -> str | None:
    """v0.5 (review 2026-10-25 H-6) reference rule for the Scope Proxy (docs/08 §11.7): the object IDs a request
    carries outside its path are exactly resolved seed / created values `allowed`. None = in scope.

    - query (a mapping of parameter -> value): an id-like key takes a plain value or PostgREST `eq.<value>`; any
      other PostgREST operator (in., neq., gt., like., is., not. ...) and the logical or= / and= parameters are
      rejected, because they can select objects other than the bound one;
    - body (JSON): every scalar under an id-like key (id, *_id, *Id, *ID) anywhere must be allowed; an id-like key
      holding a list or an object (`{"invoice_id": [999]}`, `where: {id: {eq: ...}}`) and plural keys
      (ids, *_ids, *Ids, *IDs) are rejected; a top-level array (positional Server Action arguments) is rejected
      here: Server Actions are bound by `server_action_problem`;
    - require_binding: a mutation whose path has no variable segment must carry at least one bound ID in the
      query or body, so an unfiltered PATCH / DELETE of a whole PostgREST table is rejected.
    v0.4's body_id_problem checked only scalars under id-like keys and ignored the query string.
    v0.5 (review r7 1.8, external review 1): for a PATCH / PUT / DELETE the body is the new content, not a row selector:
    PostgREST updates every row the query selects, so a bound id in the body (`{"invoice_id": ...}`) does not narrow the
    write. Such a method needs its bound object in the query; body ids must still be bound values (no writing a row into
    another owner). Only a POST (an RPC / action call) may still be bound by its body; a missing method is treated as
    a selecting write (fail closed), so the Scope Proxy must pass the request method."""
    bound = 0
    selector = 0
    for k, v in (query or {}).items():
        if not isinstance(k, str):
            return f"query parameter {k!r} is not a string"
        if POSTGREST_LOGICAL.match(k):
            return f"query parameter {k}= (PostgREST logical operator) can select other objects"
        if IDS_KEY_RE.match(k):
            return f"query parameter {k} addresses several objects"
        if ID_KEY_RE.match(k):
            values = v if isinstance(v, list) else [v]
            for x in values:
                x = str(x)
                m = POSTGREST_EQ.match(x)
                if x not in allowed and not (m and m.group(1) in allowed):
                    if m is None and POSTGREST_OP.match(x):
                        return f"query {k}={x!r}: only the PostgREST eq. operator can bind an object"
                    return f"query {k}={x!r} is not a seed or created object of this request"
                bound += 1
                selector += 1
    if isinstance(body, list):
        return "a top-level array body (positional arguments) cannot be bound by key; declare the call as a server_action"
    stack = [body]
    while stack:
        cur = stack.pop()
        if isinstance(cur, dict):
            for k, v in cur.items():
                if isinstance(k, str) and IDS_KEY_RE.match(k):
                    return f"{k} addresses several objects"
                if isinstance(k, str) and ID_KEY_RE.match(k):
                    if isinstance(v, (dict, list)):
                        return f"{k} holds a {type(v).__name__}: an id-like key must hold one bound value"
                    if v is not None:
                        if str(v) not in allowed:
                            return f"{k}={v!r} is not a seed or created object of this request"
                        bound += 1
                elif isinstance(v, (dict, list)):
                    stack.append(v)
        elif isinstance(cur, list):
            stack.extend(cur)
    if require_binding and str(method or "").upper() not in BODY_BOUND_METHODS and selector == 0:
        return (f"a {str(method or 'write').upper()} without path variables selects rows by its query only, and the query names "
                "no bound object ID: an unfiltered write of the whole collection (body ids are new values, not a filter)")
    if require_binding and bound == 0:
        return "a mutation without path variables names no bound object ID (an unfiltered write of the whole collection)"
    return None


def body_id_problem(payload, allowed: set[str]) -> str | None:
    """v0.4 name, kept for callers: the body part of request_binding_problem."""
    return request_binding_problem(None, payload, allowed)


SERVER_ACTION_HEADER = "next-action"


def server_action_problem(headers: dict, body, spec: dict, resolve: dict[str, str]) -> str | None:
    """v0.5 (review 2026-10-25 H-6): a Next.js Server Action request carries positional arguments, which no key rule
    can bind. The allow-list entry declares server_action {action_id, args}; the Scope Proxy forwards the request
    only when the Next-Action header equals action_id and the body equals args with every {seed:..} / {created:..}
    string replaced by its resolved value (`resolve`). None = in scope."""
    got = {str(k).lower(): v for k, v in (headers or {}).items()}.get(SERVER_ACTION_HEADER)
    if not isinstance(spec, dict) or got != spec.get("action_id"):
        return f"Next-Action header {got!r} is not the declared server action {(spec or {}).get('action_id')!r}"

    # v0.5 (review r7 1.9, external review 4): an unresolved ref is a refusal, not None (which matched a null argument),
    # and the comparison keeps JSON types (Python's == treats true == 1 == 1.0)
    unresolved = []

    def subst(x):
        if isinstance(x, str) and (SEED_REF_RE.match(x) or CREATED_REF_RE.match(x)):
            if x not in resolve or resolve[x] is None:
                unresolved.append(x)
            return resolve.get(x)
        if isinstance(x, list):
            return [subst(y) for y in x]
        if isinstance(x, dict):
            return {k: subst(v) for k, v in x.items()}
        return x
    want = subst(spec.get("args"))
    if unresolved:
        return f"Server Action args hold unresolved refs {unresolved}: the request cannot be bound"
    return None if json_equal(body, want) else "Server Action arguments differ from the declared args (after resolving refs)"


def json_equal(a, b) -> bool:
    """Equality of JSON values that keeps their types: true != 1, 1 != 1.0, and objects / arrays compare recursively."""
    if type(a) is not type(b):
        return False
    if isinstance(a, dict):
        return a.keys() == b.keys() and all(json_equal(a[k], b[k]) for k in a)
    if isinstance(a, list):
        return len(a) == len(b) and all(json_equal(x, y) for x, y in zip(a, b))
    return a == b


def allowlist_match(target_id: str, method: str, path: str, allowlist: list, resolve: dict[str, str],
                    gql: dict[str, set[str]] | None = None, manifest=None) -> dict | None:
    """v0.5 (review 2026-10-25 §4.3) reference rule for the Scope Proxy (docs/08 §11.7): the allow-list entry a concrete
    request matches, or None (blocked).

    The concrete path must already be in normal form (normalize_for_match leaves it unchanged except for case, so a
    percent-encoded or dot-segment path is blocked rather than matched). Segment by segment against an entry of the
    same target and method: a literal must be equal; {seed:k} / {created:s} must equal its resolved value
    (`resolve`, from the seed manifest and the run's create responses); a plain {name} matches one non-empty
    segment only on a read (is_mutation false), never on a write."""
    if not isinstance(path, str) or normalize_for_match(path) != path.lower() or "%" in path:
        return None
    segs = segments(path)
    for r in allowlist or []:
        if not isinstance(r, dict) or r.get("target_id") != target_id or r.get("method") != method:
            continue
        tsegs = segments(r.get("path", ""))
        if len(tsegs) != len(segs):
            continue
        write = is_mutation(r, gql, manifest)
        ok = True
        for t, s in zip(tsegs, segs):
            if SEED_SEG_RE.match(t) or CREATED_SEG_RE.match(t):
                ok = resolve.get(t) is not None and s == resolve[t]
            elif is_placeholder(t):
                ok = not write and s != ""
            else:
                ok = s == t
            if not ok:
                break
        if ok:
            return r
    return None


METHOD_OVERRIDE_HEADERS = frozenset({"x-http-method-override", "x-http-method", "x-method-override"})
METHOD_OVERRIDE_PARAMS = frozenset({"_method"})


def _create_endpoint(manifest, r: dict) -> dict | None:
    segs = segments(r.get("path", ""))
    for e in (manifest or {}).get("create_only_endpoints") or [] if isinstance(manifest, dict) else []:
        if isinstance(e, dict) and e.get("target_id") == r.get("target_id") and e.get("method") == r.get("method") \
                and _shape_matches(segs, e.get("path_template", "")):
            return e
    return None


ID_POINTER_RE = re.compile(r"(?:/(?:[^~/]|~[01])+)+")


def created_resource_problem(endpoint: dict) -> str | None:
    """v0.5: the create_only_endpoints entry declares what it creates (created_resource: type, id_pointer,
    path_templates). Every follow-up path holds exactly one {created_id}; its other variables are variables
    of the creation path, so they bind to the values of that creation request. None = well formed."""
    resource = endpoint.get("created_resource") if isinstance(endpoint, dict) else None
    if not isinstance(resource, dict):
        return "missing created_resource"
    if not isinstance(resource.get("type"), str) or not re.fullmatch(r"[a-z][a-z0-9_]*", resource["type"]):
        return "invalid created_resource.type"
    pointer = resource.get("id_pointer")
    if not isinstance(pointer, str) or not ID_POINTER_RE.fullmatch(pointer):
        return "invalid created_resource.id_pointer (a JSON Pointer with non-empty tokens, e.g. /id)"
    creation = endpoint.get("path_template", "")
    if not isinstance(creation, str) or not is_normalized(creation):
        return "creation path_template is not a normalized path"
    names = [x for x in segments(creation) if is_placeholder(x)]
    if len(names) != len(set(names)) or "{created_id}" in names:
        return "ambiguous creation path variables"
    paths = resource.get("path_templates")
    if not isinstance(paths, list) or not paths:
        return "missing created_resource.path_templates"
    for path in paths:
        if not isinstance(path, str) or not is_normalized(path):
            return f"created_resource path {path!r} is not a normalized path"
        parts = segments(path)
        if parts.count("{created_id}") != 1 or any(
                is_placeholder(x) and x != "{created_id}" and x not in names for x in parts):
            return f"created_resource path {path!r} must hold exactly one {{created_id}} and only creation-path variables"
    return None


def created_path_allowed(path: str, step: str, source: dict, endpoint: dict) -> bool:
    """v0.5: `path` uses {created:<step>} only where the creating endpoint's created_resource declares it, and
    every other variable of that declaration takes the exact value of the creation request (no other parent)."""
    if created_resource_problem(endpoint):
        return False
    bindings = {k: v for k, v in zip(segments(endpoint["path_template"]), segments(source.get("path", "")))
                if is_placeholder(k)}
    bindings["{created_id}"] = "{created:" + step + "}"
    return any(segments(path) == [bindings.get(x, x) for x in segments(t)]
               for t in endpoint["created_resource"]["path_templates"])


def mutation_scope_problems(tc: dict, manifest, roe: dict | None = None) -> list[str]:
    """B6 (H-B3, L-11): why requests of the allow-list are outside the seed-bound mutation scope ([] = in scope).
    `roe` supplies the declared GraphQL paths (v0.4); without it no request is a GraphQL read."""
    out = []
    gql = graphql_paths(roe)
    creates: dict[str, dict] = {}                   # step_id -> earlier create request
    for i, r in enumerate(tc.get("request_allowlist") or []):
        if not isinstance(r, dict):
            continue
        path = r.get("path", "")
        where = f"{r.get('method')} {path}"
        refs_ok = []
        for s in created_refs(path):
            src = creates.get(s)
            if src is None:
                out.append(f"{where}: {{created:{s}}} is not an earlier create request of this allow-list")
            elif src.get("target_id") != r.get("target_id"):
                out.append(f"{where}: {{created:{s}}} was created on another target")
            else:
                refs_ok.append((s, src))
        # v0.5: one creating endpoint must declare the whole path; its parent variables take the literal values of
        # that creation request, so a nested path such as /sessions/{created:a}/messages/{created:b} is declared by
        # b's endpoint and binds the session to the one b was created under
        if refs_ok and len(refs_ok) == len(created_refs(path)) and not any(
                created_path_allowed(path, s, src, _create_endpoint(manifest, src) or {}) for s, src in refs_ok):
            out.append(f"{where}: no creating endpoint's created_resource.path_templates declares this path for "
                       f"{[f'{{created:{s}}}' for s, _ in refs_ok]} (v0.5)")
        prob = seed_path_problem(path, manifest)
        if prob:
            out.append(f"{where}: {prob}")
        refs = object_ref_problems(r, manifest, creates)
        out.extend(f"{where}: {p}" for p in refs)
        sa = r.get("server_action")
        if sa is not None:
            # v0.5 (H-6): a Server Action is a POST to a fixed path; every ref in its args is a valid object_refs entry
            arg_refs = set()
            stack = [sa.get("args") if isinstance(sa, dict) else None]
            while stack:
                x = stack.pop()
                if isinstance(x, str) and (SEED_REF_RE.match(x) or CREATED_REF_RE.match(x)):
                    arg_refs.add(x)
                elif isinstance(x, list):
                    stack.extend(x)
                elif isinstance(x, dict):
                    stack.extend(x.values())
            if r.get("method") != "POST" or any(is_placeholder(x) for x in segments(path)):
                out.append(f"{where}: a server_action is a POST to a path without variable segments (v0.5)")
            missing = sorted(arg_refs - set(r.get("object_refs") or []))
            if missing:
                out.append(f"{where}: server_action args use {missing}, which are not in object_refs (v0.5)")
        if r.get("graphql_operation") is not None and not graphql_declared(r, gql):
            out.append(f"{where}: graphql_operation {r.get('graphql_operation')!r} on a path the ROE does not declare as GraphQL "
                       f"for {r.get('target_id')} (targets[].graphql_paths), or not over GET/POST")
        elif r.get("graphql_operation") == "mutation" and r.get("method") != "POST":
            out.append(f"{where}: a GraphQL mutation is sent only over POST (v0.5)")
        if is_mutation(r, gql, manifest):
            var = [s for s in segments(path) if is_placeholder(s)]
            unbound = [s for s in var if not (SEED_SEG_RE.match(s) or CREATED_SEG_RE.match(s))]
            create = _create_endpoint(manifest, r)
            if unbound:
                out.append(f"{where}: mutation addresses {unbound} that are neither {{seed:key}} nor {{created:step_id}}")
            elif create is None and not var and not (r.get("object_refs") and not refs):
                out.append(f"{where}: mutation of a non-seed object (not a seed-manifest create_only_endpoints entry, "
                           "and no valid object_refs)")
            if create is not None:
                problem = created_resource_problem(create)
                if problem:
                    out.append(f"{where}: {problem}")
                elif r.get("step_id"):
                    if r["step_id"] in creates:
                        out.append(f"{where}: duplicate creation step_id {r['step_id']!r}")
                    else:
                        creates[r["step_id"]] = r
    return out


# v0.4: address classes the Scope Proxy never connects to, on top of `not ip.is_global`. Python's is_global
# is True for NAT64 64:ff9b::/96 (64:ff9b::a9fe:a9fe reaches 169.254.169.254 through a translator), the
# deprecated site-local fec0::/10, multicast, and IPv4-mapped literals of public addresses.
DENIED_NETWORKS = tuple(ipaddress.ip_network(n) for n in (
    "64:ff9b::/96",        # NAT64 well-known prefix (RFC 6052)
    "64:ff9b:1::/48",      # local-use NAT64 (RFC 8215)
    "::ffff:0:0/96",       # IPv4-mapped: connect over IPv4 instead, so the IPv4 rules apply
    "2002::/16",           # 6to4: the embedded IPv4 address may be internal
    "2001::/32",           # Teredo
    "fec0::/10",           # deprecated site-local
    "fc00::/7",            # unique local
    "224.0.0.0/4", "ff00::/8",   # multicast
))
LOCAL_TEST_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


def ip_problem(addr: str, local_target: bool = False) -> str | None:
    """v0.4 (docs/08 §11.7): why the Scope Proxy must not connect to this resolved address (None = allowed).

    Only public unicast addresses are allowed. `local_target` is the MVP-1 exception (a ROE target on
    localhost / 127.0.0.1 / [::1] on the same isolated host): loopback is then allowed, nothing else."""
    try:
        ip = ipaddress.ip_address(addr.strip("[]") if isinstance(addr, str) else addr)
    except ValueError:
        return f"{addr!r} is not an IP address"
    if local_target and ip.is_loopback:
        return None
    for net in DENIED_NETWORKS:
        if ip.version == net.version and ip in net:
            return f"{ip} is in denied network {net}"
    if not ip.is_global:
        return f"{ip} is not a public address (private, loopback, link-local, reserved or cloud metadata)"
    return None


# IANA special-purpose blocks (RFC 6890 and successors) that ip_problem rejects through is_global; a declared
# edge range may not overlap them either (ip_problem still runs on every resolved address, so this only keeps
# the declaration honest).
NON_PUBLIC_NETWORKS = DENIED_NETWORKS + tuple(ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
    "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
    "240.0.0.0/4",
    "::/127", "100::/64", "2001:db8::/32", "fe80::/10",
))


def edge_range_problem(cidr: str) -> str | None:
    """v0.4 (BL-15): why a ROE targets[].edge_ip_ranges entry is unusable (None = fine). A range must be a
    strict CIDR (host bits zero) of public unicast space: it may not overlap any non-public network."""
    try:
        net = ipaddress.ip_network(cidr, strict=True)
    except (ValueError, TypeError):
        return f"{cidr!r} is not a CIDR network (host bits must be zero)"
    for bad in NON_PUBLIC_NETWORKS:
        if net.version == bad.version and net.overlaps(bad):
            return f"{net} overlaps non-public network {bad}"
    return None


def ip_in_ranges(addr: str, ranges: list[str] | None) -> str | None:
    """v0.4 (docs/08 §11.7, BL-15): Scope Proxy check after resolving a target that declares edge_ip_ranges.
    None = allowed. No declared ranges -> only ip_problem applies (U-18 default). With ranges, every
    resolved address must also fall inside one of them, otherwise the job does not start."""
    prob = ip_problem(addr)
    if prob is not None or not ranges:
        return prob
    ip = ipaddress.ip_address(addr.strip("[]"))
    nets = [ipaddress.ip_network(r, strict=False) for r in ranges if edge_range_problem(r) is None]
    if any(ip.version == n.version and ip in n for n in nets):
        return None
    return f"{ip} is outside the declared edge_ip_ranges {ranges}"


# E2 (H-D3): shared-platform domains. A host under one of these suffixes belongs to the platform, not to the
# customer: DNS TXT / well-known-path proofs do not show ownership of the project; platform_project does.
SHARED_PLATFORM_SUFFIXES = {
    "supabase.co": "supabase",
    "vercel.app": "vercel",
    "netlify.app": "netlify",
    "firebaseapp.com": "firebase",
    "web.app": "firebase",
    "onrender.com": "render",
    "pages.dev": "other",
    "fly.dev": "other",
    "herokuapp.com": "other",
    # v0.4: vibe-coding and other hosting platforms whose DNS and web root belong to the platform. The
    # implementation should take the private section of the Public Suffix List as the source and keep this
    # table as the platform mapping; the list below is the minimum the validator enforces.
    "lovable.app": "other",
    "replit.app": "other",
    "repl.co": "other",
    "workers.dev": "other",
    "github.io": "other",
    "gitlab.io": "other",
    "amplifyapp.com": "other",
    "azurewebsites.net": "other",
    "azurestaticapps.net": "other",
    "railway.app": "other",     # PSL lists only up.railway.app; the whole domain is kept (stricter)
    "glitch.me": "other",       # not in the PSL (checked 2026-10-24); kept, see PSL_EXCEPTIONS
    "deno.dev": "other",
}

# Suffixes above that tools/check_platform_suffixes.py must not flag although the Public Suffix List does not
# list them (or lists only a sub-domain). Stricter than the PSL is safe: a shared-platform match only refuses
# DNS TXT / well-known-path ownership proofs.
PSL_EXCEPTIONS = {
    "railway.app": "PSL lists up.railway.app only; projects can also be served from other railway.app hosts [H]",
    "glitch.me": "not in the PSL; project sub-domains were platform-owned while hosting ran [H]",
}


# roe.schema.json targets[].endpoint / db_access.endpoint: 'host:port' or '[v6]:port'; no bare
# host, no trailing dot, no empty label
ENDPOINT_RE = re.compile(r"^(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*):[0-9]{1,5}$")


def norm_host(host) -> str:
    """Comparable host name: trailing dot(s) removed, lower-cased, IDNA (punycode) encoded.

    'API.Example.com.' and 'api.example.com' are the same DNS name, so an exclusion must not be
    bypassable by a trailing dot, case or a Unicode spelling. When IDNA encoding fails (IPv6
    literal edge cases, empty label, over-long label) the lower-cased form is used.
    """
    h = str(host or "").strip().rstrip(".").lower()
    try:
        return h.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return h


def host_of(base_url: str | None) -> str | None:
    """Normalised host of an http(s) base_url; None when the URL is unparseable, has no host or is not http(s)."""
    try:
        u = urlsplit(base_url or "")
        h = u.hostname
    except ValueError:            # e.g. 'http://[::1' (invalid IPv6 literal)
        return None
    if u.scheme.lower() not in ("http", "https"):
        return None
    return (norm_host(h) or None) if h else None


def endpoint_host(endpoint: str | None) -> str | None:
    """Normalised host of a database endpoint 'host:port' or '[v6]:port' (IPv6 without brackets).

    Only the roe.schema.json endpoint forms are accepted: a bare host without port, '[::1'
    (unclosed bracket), '::1:5432' (unbracketed IPv6) or a trailing dot give None (unparseable),
    which callers report as E-ROE-DB-SCOPE instead of crashing.
    """
    if not isinstance(endpoint, str) or not ENDPOINT_RE.match(endpoint):
        return None
    try:
        h = urlsplit("//" + endpoint).hostname
    except ValueError:
        return None
    return (norm_host(h) or None) if h else None


def target_host(target: dict) -> str | None:
    """Host a ROE target resolves to: base_url host (http) or endpoint host (database); None if unparseable."""
    if target.get("kind") == "database":
        return endpoint_host(target.get("endpoint"))
    return host_of(target.get("base_url"))


def host_matches(host: str | None, pattern) -> bool:
    """D2: exact match after norm_host, or a leading-wildcard pattern `*.example.com` that matches every
    subdomain of example.com (at any depth) but not example.com itself."""
    h = norm_host(host) if host else ""
    if not h or not isinstance(pattern, str):
        return False
    p = pattern.strip()
    if p.startswith("*."):
        base = norm_host(p[2:])
        return bool(base) and h.endswith("." + base)
    return bool(norm_host(p)) and h == norm_host(p)


def host_excluded(host: str | None, excluded_hosts) -> bool:
    """ROE exclusions.hosts match (an empty host never matches)."""
    return any(host_matches(host, x) for x in excluded_hosts or [])


def registry_entry(tools: dict, adapter: str) -> dict | None:
    """tools.yaml lookup: {tool, mode, base_class, b4_executable, ...} or None."""
    parsed = split_adapter(adapter)
    if parsed is None:
        return None
    tool, mode = parsed
    spec = (tools or {}).get("tools", {}).get(tool, {}).get("modes", {}).get(mode)
    return None if spec is None else {"tool": tool, "mode": mode, **spec}


def compute_safety_class(tc: dict, roe: dict, tools: dict, manifest: dict | None) -> tuple[str, list[str]]:
    """Return (class, trace). `manifest` = the seed manifest named by tc.seed_manifest_ref (dict), or None."""
    tb = tc["tool_binding"]
    acts = roe["activities"]

    # 1. MANUAL: never sent to B4. kind/adapter mismatch -> S3.
    if tb["kind"] == "MANUAL" or tb["adapter"] == "manual":
        if tb["kind"] == "MANUAL" and tb["adapter"] == "manual":
            return "S0", ["MANUAL: not executed"]
        return "S3", ["MANUAL kind/adapter mismatch"]

    # 2. adapter format and registration
    parsed = split_adapter(tb["adapter"])
    if parsed is None:
        return "S3", [f"{tb['adapter']!r}: not tool:mode"]
    tool, _ = parsed
    entry = registry_entry(tools, tb["adapter"])
    if entry is None:
        return "S3", [f"{tb['adapter']}: not registered in tools.yaml"]
    if not entry.get("b4_executable"):
        return "S3", [f"{tb['adapter']}: white-box only (b4_executable false)"]

    # 3. deny-lists and ROE authorisation (exact tool:mode match)
    if tb["adapter"] in TOOLKIT_DENYLIST:
        return "S3", [f"{tb['adapter']}: toolkit deny-list"]
    if tb["adapter"] in set(acts["denied_modes"]):
        return "S3", [f"{tb['adapter']}: ROE denied_modes"]
    if tool not in set(acts["allowed_tools"]):
        return "S3", [f"{tool}: not in ROE allowed_tools"]

    # 4. targets
    roe_targets = {t["id"]: t for t in roe["targets"]}
    if not tc["target_ids"] or any(t not in roe_targets for t in tc["target_ids"]):
        return "S3", ["target not in ROE"]
    for t in tc["target_ids"]:
        h = target_host(roe_targets[t])
        if h is None:
            return "S3", [f"{t}: unparseable target host"]
        if host_excluded(h, roe["exclusions"]["hosts"]):
            return "S3", [f"{t}: excluded host"]

    # 5. request allow-list
    reqs = tc["request_allowlist"]
    if not reqs:
        return "S3", ["empty request_allowlist"]
    for r in reqs:
        if r["target_id"] not in tc["target_ids"]:
            return "S3", [f"{r['target_id']}: request target not in testcase target_ids"]
        if not is_normalized(r["path"]):
            return "S3", [f"{r['path']!r}: path template not normalised"]
        hits = [p for p in roe["exclusions"]["paths"] if path_may_match(r["path"], p)]
        if hits:
            return "S3", [f"{r['method']} {r['path']}: may match ROE exclusion {hits}"]
    # v0.6 (review r7 3.8): until the Scope Proxy parses GraphQL documents (09 BL-35), a GraphQL request is POST only and
    # pins its document: over GET the document rides the query string, where the proxy cannot tell a query from a
    # mutation, and an unpinned body can carry any operation under a "query" label
    gql_paths = graphql_paths(roe)
    for r in reqs:
        graphql = r.get("graphql_operation") is not None or r["path"] in gql_paths.get(r["target_id"], set())
        if graphql and r["method"] != "POST":
            return "S3", [f"{r['method']} {r['path']}: GraphQL only over POST until the proxy parses documents (BL-35)"]
        if r.get("graphql_operation") is not None and not r.get("graphql_document_sha256"):
            return "S3", [f"{r['method']} {r['path']}: a GraphQL request pins its document (graphql_document_sha256)"]
    # every mutation is seed-bound or a create in the run namespace; seeds only on their own resources
    scope = mutation_scope_problems(tc, manifest, roe)
    if scope:
        return "S3", [f"{MUTATION_SCOPE}: {p}" for p in scope]

    # 6. rate above the ROE is a rejection, not an upgrade
    if tc["rate_limit"]["requests_per_second"] > roe["rate_limits"]["per_host_rps"]:
        return "S3", ["requests_per_second > ROE per_host_rps"]

    # 7. level
    trace = []
    level = entry.get("base_class") or "S2"
    trace.append(f"{tb['adapter']}: base_class {entry.get('base_class')} -> {level}")
    # v0.5 (review 2026-10-25 §4.3): the floor follows is_mutation, not only the HTTP method, so a mutation that rides a
    # read method (a GraphQL mutation label, a declared state-changing read) cannot keep an S0 base class
    gql = graphql_paths(roe)
    if any(r["method"] in STATE_CHANGING for r in reqs):
        level = hi(level, "S1")
        trace.append("state-changing method -> >=S1")
    elif any(is_mutation(r, gql, manifest) for r in reqs):
        level = hi(level, "S1")
        trace.append("mutation on a read method -> >=S1")
    if any(_endpoint_in(manifest, "state_changing_reads", r) is not None for r in reqs):
        level = hi(level, "S1")
        trace.append("state-changing GET/HEAD (seed manifest state_changing_reads) -> >=S1")
    for r in reqs:
        ce = _create_endpoint(manifest, r)
        if ce is not None and ce.get("side_effects", "none") != "none" and ce.get("contained") is not True:
            level = hi(level, "S2")
            trace.append(f"{r['method']} {r['path']}: create-only endpoint with uncontained {ce.get('side_effects')} side effects -> >=S2")
            break
    for r in reqs:
        effects = seed_side_effects(manifest, roe, r) if is_mutation(r, gql, manifest) else None
        if effects is not None:
            level = hi(level, "S2")
            trace.append(f"{r['method']} {r['path']}: writes a seed with uncontained {effects} side effects -> >=S2")
            break
    total = request_budget(tc)
    if total > roe["rate_limits"]["s1_request_cap"]:
        level = hi(level, "S2")
        trace.append(f"max_requests + replays = {total} > s1_request_cap -> >=S2")

    # 8. the LLM proposal is only a floor
    proposed = tc.get("safety_class_proposed") or "S0"
    result = hi(level, proposed)
    if result != level:
        trace.append(f"LLM proposal {proposed} used as floor")
    return result, trace


def request_budget(tc: dict) -> int:
    """v0.6 (review r7 3.8): the requests a testcase may send, replays included. A FAIL opens replay_n replay jobs, each
    re-running one trial (max_requests / n requests, rounded up); v0.5 compared max_requests alone with the S1 cap,
    although replays are 'not counted in max_requests'."""
    rl, trials = tc.get("rate_limit") or {}, tc.get("trials") or {}
    mx, n, rn = rl.get("max_requests") or 0, max(1, trials.get("n") or 1), trials.get("replay_n") or 0
    return mx + rn * -(-mx // n)


def seed_side_effects(manifest, roe, r: dict) -> str | None:
    """v0.6 (review r7 3.8): the uncontained side effects of the seeds a mutation writes, or None. A seed declares
    side_effects / contained like a create-only endpoint; a seed that declares nothing is assumed to reach the
    application's integrations when the ROE lists any that is not disabled (fail closed: an update of an order can
    send mail as well as a create)."""
    seeds = (manifest or {}).get("seeds") or {} if isinstance(manifest, dict) else {}
    live = [i.get("name") for i in (roe or {}).get("integrations") or [] if isinstance(i, dict) and i.get("mode") != "disabled"]
    refs = [m.group(1) for s in segments(r.get("path", "")) for m in [SEED_SEG_RE.match(s)] if m]
    refs += [m.group(1) for x in r.get("object_refs") or [] for m in [SEED_REF_RE.match(str(x))] if m]
    for key in refs:
        sd = seeds.get(key) if isinstance(seeds.get(key), dict) else {}
        effects = sd.get("side_effects")
        if effects is None:
            effects = "external" if live else "none"
        if effects != "none" and sd.get("contained") is not True:
            return f"{effects} ({key})"
    return None


def admissible(level: str, roe: dict) -> bool:
    """Can the computed class enter G4? (S2 also needs a G5 per job and a restore drill.)"""
    return level != "S3" and level in set(roe["activities"]["allowed_safety_classes"])
