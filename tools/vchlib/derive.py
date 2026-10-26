# SPDX-License-Identifier: Apache-2.0
"""Derived values of the example bundle.

Every hash, weight or copied field that is a pure function of other files is listed here as
an Expectation (file, json path, expected value, why). The validator compares each one with
the file (error E-DERIVED); tools/sign_examples.py writes them back until nothing changes.
Signatures and the audit hash chain are handled by checks.py / sign_examples.py, because
they need keys or raw lines.
"""
from __future__ import annotations

import contextlib

from dataclasses import dataclass
from typing import Any

from . import timeutil
from .bundle import Bundle, Doc, read_jsonl_lines
from .canonical import approval_hash, content_hash, jcs, set_digest, sha256_hex, sha256_ref, text_hash

ZERO = "sha256:" + "0" * 64
STANCE = {"SUPPORT": 1, "REFUTE": -1, "ABSTAIN": 0}


@dataclass
class Expectation:
    file: str
    path: tuple
    expected: Any
    why: str


class _Missing:
    def __repr__(self):
        return "<missing>"


MISSING = _Missing()


def get_path(obj, path):
    for p in path:
        try:
            obj = obj[p]
        except (KeyError, IndexError, TypeError):
            return MISSING
    return obj


def set_path(obj, path, value):
    for p in path[:-1]:
        obj = obj[p]
    obj[path[-1]] = value


def fmt_path(path) -> str:
    out = "$"
    for p in path:
        out += f"[{p}]" if isinstance(p, int) else f".{p}"
    return out


# ---------------------------------------------------------------- lookups
class Index:
    """Convenience lookups over a bundle (all tolerant of missing documents)."""

    def __init__(self, b: Bundle):
        self.b = b
        self.models = b.data("model-registry") or {}
        self.agents = b.data("agent-registry") or {}
        self.calibration = b.data("calibration") or {}
        self.manifest = b.data("seed-manifest") or {}

    def docs(self, kind) -> list[Doc]:
        return [d for d in self.b.by_kind(kind) if isinstance(d.data, dict)]

    def find(self, kind, **match) -> list[Doc]:
        return [d for d in self.docs(kind) if all(d.data.get(k) == v for k, v in match.items())]

    def first(self, kind, **match) -> Doc | None:
        f = self.find(kind, **match)
        return f[0] if f else None

    def testcase_for(self, tr: dict) -> Doc | None:
        """The testcase a result ran: a W4 result runs a w4-testcase (v0.5, BL-27), a B4 result a black-box testcase.
        v0.4 looked every result up among black-box testcases, so a W4 result had to borrow one."""
        kind = "w4-testcase" if tr.get("phase") == "W4" else "testcase"
        return self.first(kind, testcase_id=tr.get("testcase_id"))

    def audit_docs(self) -> list[Doc]:
        return [d for d in self.b.by_kind("audit-event") if isinstance(d.data, list)]

    def audit_for(self, run_id) -> Doc | None:
        for d in self.audit_docs():
            if d.data and d.data[0].get("run_id") == run_id:
                return d
        return None

    def decision_time(self, rec: dict):
        """v0.4 (E4): ts of the gate_decision audit event of `rec` (the Audit Writer's receive clock), or None."""
        audit = self.audit_for(rec.get("run_id"))
        for ev in (audit.data if audit and isinstance(audit.data, list) else []):
            if isinstance(ev, dict) and ev.get("event_type") == "gate_decision" \
                    and (ev.get("payload") or {}).get("gate_record_id") == rec.get("gate_record_id"):
                try:
                    return timeutil.parse_dt(ev.get("ts"))
                except (timeutil.TimeError, TypeError, ValueError):
                    return None
        return None

    def gate_records(self, run_id, gate=None) -> list[Doc]:
        """Gate records of a run (optionally one gate), ordered by the Audit Writer's receive time (v0.4), falling
        back to the self-declared timestamp only for a record without a gate_decision event."""
        recs = [d for d in self.docs("gate-record") if d.data.get("run_id") == run_id and (gate is None or d.data.get("gate") == gate)]

        def key(d):
            t = self.decision_time(d.data)
            return timeutil.sort_key(t.isoformat()) if t is not None else timeutil.sort_key(d.data.get("timestamp"))
        return sorted(recs, key=key)

    def model_of_agent(self, agent_id) -> dict | None:
        a = self.agents.get(agent_id)
        if not isinstance(a, dict) or not a.get("model"):
            return None
        m = self.models.get(a["model"])
        return m if isinstance(m, dict) else None

    def weight(self, model_key, bucket, version, stance="SUPPORT") -> float:
        """v0.4: calibration weight of one side. REFUTE votes use the refute side (accuracy on known non-defects),
        every other stance the support side (accuracy on true defects); docs/05 §4.3."""
        cal = self.calibration
        if not cal or version is None or cal.get("calibration_version") != version:
            return 0.0
        side_key = "refute" if stance == "REFUTE" else "support"
        res = cal.get("result") or {}
        # v0.5 (review 2026-10-25 A-6, docs/05 §5.8): a model whose calibration is invalidated (model or version
        # changed) or that the result is not valid for weighs 0 until the minimal rerun
        valid_for = res.get("valid_for_model_keys") or []
        if (valid_for and model_key not in valid_for) or any(
                isinstance(x, dict) and x.get("model_key") == model_key for x in res.get("invalidated_by") or []):
            return 0.0
        for row in res.get("weights", []):
            if row.get("model_key") == model_key and row.get("cwe_bucket") == bucket:
                side = row.get(side_key) or {}
                return 0.0 if side.get("near_zero") else float(side.get("w", 0))
        return 0.0

    def thresholds(self):
        th = ((self.calibration.get("result") or {}).get("thresholds") or {})
        return (th.get("theta_confirm") or {}).get("value"), (th.get("theta_reject") or {}).get("value")

    def approved_requirement_ids(self) -> set[str]:
        """Requirements approved at G1 (D10): invariants whose signoff is ACCEPTED by the G1 record named in
        invariants.yaml and whose decision there is accept; baseline items when that G1 record is APPROVED
        and the file-level signoff is ACCEPTED. REJECTED / NEEDS_INFO items are not testable."""
        inv = self.b.data("invariants") or {}
        so = inv.get("signoff") or {}
        rec = self.first("gate-record", gate_record_id=so.get("gate_record_id")) if so.get("gate_record_id") else None
        # v0.5 (review r7 1.1): an EXPIRED G1 is unsigned and approves nothing
        if rec is None or rec.data.get("gate") != "G1" or rec.data.get("outcome") == "EXPIRED":
            return set()
        accepted = {x.get("item_id") for x in rec.data.get("decisions") or [] if isinstance(x, dict) and x.get("decision") == "accept"}
        out = {i.get("requirement_id") for i in inv.get("invariants") or [] if isinstance(i, dict)
               and (i.get("signoff") or {}).get("status") == "ACCEPTED"
               and (i.get("signoff") or {}).get("gate_record_id") == rec.data.get("gate_record_id")
               and i.get("requirement_id") in accepted}
        if rec.data.get("outcome") == "APPROVED" and so.get("status") == "ACCEPTED":
            out |= {x.get("requirement_id") for x in inv.get("baseline") or [] if isinstance(x, dict)}
        return out

    def finding(self, fid) -> dict | None:
        d = self.first("finding", finding_id=fid)
        return d.data if d else None


GROUNDED_MATCHES = ("MATCHED", "MATCHED_SHIFTED")


def has_supporting_evidence(f: dict) -> bool:
    """At least one evidence item is grounded: MATCHED or MATCHED_SHIFTED (docs/05 §3 rule 5).

    v0.4: NOT_CHECKED (the harness could not check the item, e.g. an unparseable config file) is not
    grounded either. v0.3 counted every item that was not NOT_FOUND, so two families that each sent an
    uncheckable config_fact reached R6 LIKELY without any grounded evidence."""
    return any(isinstance(e, dict) and e.get("match") in GROUNDED_MATCHES for e in f.get("evidence") or [])


def independent_families(ix: Index, cluster: dict) -> list[str]:
    """docs/05 §4.1 (D14): families that contributed a member in the first round of this run, reported by an
    agents.yaml `reviewer` (Lane A advisories and CMD-2 extra rounds do not count), whose finding has at least
    one grounded evidence item (MATCHED / MATCHED_SHIFTED; UNVERIFIED and NOT_CHECKED-only findings do not count). Sorted."""
    fams = set()
    for fid in cluster.get("member_finding_ids") or []:
        f = ix.finding(fid)
        rep = (f or {}).get("reporter") or {}
        a = ix.agents.get(rep.get("agent_id")) if isinstance(rep.get("agent_id"), str) else None
        if (f and rep.get("round") == 1 and isinstance(a, dict) and a.get("role") == "reviewer"
                and f.get("run_id") == cluster.get("run_id") and has_supporting_evidence(f)):
            fams.add(rep.get("family"))
    return sorted(f for f in fams if isinstance(f, str))


def slice_identity(files, redaction_map_sha256, prompt_template_sha256) -> str:
    """E6 (H-E3): slice_id = sha256(JCS({files, redaction_map_sha256, prompt_template_sha256}))."""
    return sha256_ref(jcs({"files": files, "redaction_map_sha256": redaction_map_sha256,
                           "prompt_template_sha256": prompt_template_sha256}))


CONFIG_KINDS = {"models": "model-registry", "agents": "agent-registry", "tools": "tool-registry", "calibration": "calibration",
                "invariants": "invariants", "seed_manifest": "seed-manifest"}


def artifact_sha(rec: dict):
    """artifact.sha256 of a gate record; MISSING when the record has no artifact (reported as E-GATE-ARTIFACT, D6)."""
    a = rec.get("artifact") if isinstance(rec, dict) else None
    return a.get("sha256", MISSING) if isinstance(a, dict) else MISSING


def cluster_fingerprint(cluster: dict) -> str:
    """B9: stable cross-run fingerprint, no line numbers. white_box: {cwe_bucket, file, symbol};
    black_box: {cwe_bucket, target_id, method, path_template} of canonical_location.endpoint."""
    loc = cluster.get("canonical_location") or {}
    if cluster.get("origin") == "black_box":
        ep = loc.get("endpoint") or {}
        key = {"cwe_bucket": cluster.get("cwe_bucket"), "target_id": ep.get("target_id"), "method": ep.get("method"),
               "path_template": ep.get("path_template")}
    else:
        key = {"cwe_bucket": cluster.get("cwe_bucket"), "file": loc.get("file"), "symbol": loc.get("symbol")}
    return sha256_ref(jcs(key))


# ---------------------------------------------------------------- test evidence (docs/05 §4.2)
ORACLE_TYPES = ("STATUS_AND_BODY", "STATE_DIFF", "TOOL_CHECK", "TOOL_CALL_LOG", "CANARY", "THRESHOLD", "DOM_ASSERTION",
                "HUMAN", "LLM_GRADER")
NON_DETERMINISTIC_ORACLES = frozenset({"HUMAN", "LLM_GRADER"})
DETERMINISTIC_ORACLES = frozenset(ORACLE_TYPES) - NON_DETERMINISTIC_ORACLES


def oracle_types(tc: dict) -> set[str]:
    """testcase oracle.types (v0.3); a list-valued field that is missing or malformed gives the empty set."""
    types = (tc.get("oracle") or {}).get("types")
    return {t for t in types if isinstance(t, str)} if isinstance(types, list) else set()


def control_results(tc: dict, tr: dict) -> list[tuple[str, str, str | None]]:
    """[(control_id, kind, outcome or None)] for every control of the testcase, in testcase order."""
    got = {x.get("control_id"): x.get("outcome") for x in tr.get("controls") or [] if isinstance(x, dict)}
    return [(c.get("control_id"), c.get("kind"), got.get(c.get("control_id")))
            for c in tc.get("controls") or [] if isinstance(c, dict)]


def controls_of_kind_pass(tc: dict, tr: dict, kind: str) -> bool | None:
    """None when the testcase has no control of `kind`; else True iff every such control PASSed."""
    outs = [o for _, k, o in control_results(tc, tr) if k == kind]
    return None if not outs else all(o == "PASS" for o in outs)


def reachability_reached(tc: dict, tr: dict) -> bool:
    """The derived precondition_reached: at least one reachability control, and all of them PASS."""
    return controls_of_kind_pass(tc, tr, "reachability") is True


def positive_control_value(tc: dict, tr: dict) -> bool | None:
    """The derived positive_control.value: an oracle_can_fail control exists and PASSed (None: no such control)."""
    return controls_of_kind_pass(tc, tr, "oracle_can_fail")


PROBABILISTIC_TOOLS = ("promptfoo", "pyrit")                  # LLM test harnesses: a sampled target, not a fixed function


def is_probabilistic(tc: dict) -> bool:
    """v0.6 (review r7 3.3): a test is probabilistic because of what it runs against, not because of the n it declares.
    An LLM harness adapter, a multi-turn LLM test, or a testcase that records the target model is probabilistic. v0.5
    read `trials.n > 1`, so an LLM test declaring n = 1 was treated as deterministic and one clean trial was a qualified
    PASS. Such a test must also declare n >= pass_min_effective (E-TC-TRIALS)."""
    adapter = str((tc.get("tool_binding") or {}).get("adapter") or "")
    return (adapter.split(":")[0] in PROBABILISTIC_TOOLS or tc.get("multi_turn") is True
            or "target_model" in ((tc.get("trials") or {}).get("record") or []))


def pass_min_effective(ix: "Index", tc: dict) -> int:
    """docs/04 §4.4: the effective trials a probabilistic PASS needs. 30 (one-sided 95% bound about 10%); v0.5 (review
    2026-10-25 §4.3): 60 (bound about 5%) for a high-risk threat, recognised by its attack tree (docs/02 B2: every
    high-risk threat has one), so a PASS cannot claim the high-risk target bound with only 30 valid trials."""
    t = ix.first("threat", threat_id=tc.get("threat_id")) if tc.get("threat_id") else None
    return 60 if t is not None and t.data.get("attack_tree_ref") else 30


def fail_reproduced(tc: dict, tr: dict) -> tuple[bool, str]:
    """docs/04 §4.4: the first batch reaches fail_k_min and a separate replay job ran: a deterministic test fails on
    every replay (k_r = n_r). v0.5 (review 2026-10-25 M-3): for a probabilistic test the replay is a reproducibility
    record, not a second verdict: one confirmed violation already breaks the requirement, and a real 5% rate stays
    silent in all 20 replays about 36% of the time, so k_r is reported but does not demote the FAIL."""
    trials = tc.get("trials") or {}
    probabilistic = is_probabilistic(tc)
    k = (tr.get("trials") or {}).get("k", 0)
    fail_k_min = trials.get("fail_k_min", 1)
    n_r, k_r = tr.get("replays", 0), tr.get("replay_k", 0)
    if k < fail_k_min:
        return False, "FAIL below fail_k_min"
    if n_r < 1:
        return False, "FAIL not replayed"
    if not probabilistic and k_r != n_r:
        return False, "FAIL not reproduced by the replay job"
    return True, ""


def g4_approved(ix: "Index", tr: dict) -> bool:
    """The latest G4 record of the result's run that decides this testcase accepts it (black-box pre-registration).

    v0.5 (review 2026-10-25 §4.3): v0.4 read only the run's last G4 record, so a second-round G4 that covered other
    testcases turned an approved one into "not approved" (E_proof -> E_fail_u)."""
    latest = None
    for rec in ix.gate_records(tr.get("run_id"), "G4"):          # receive-time order
        if rec.data.get("outcome") not in ("APPROVED", "PARTIALLY_APPROVED"):
            continue
        for x in rec.data.get("decisions") or []:
            if isinstance(x, dict) and x.get("item_id") == tr.get("testcase_id"):
                latest = x.get("decision")
    return latest == "accept"


def preregistered(ix: "Index", tc: dict, tr: dict, control_kind: str) -> bool:
    """docs/05 §4.2 (v0.3): the oracle's interpretation was fixed before the test ran.
    B4: the testcase has an accepting G4 decision. W4: every requirement_id is approved at G1 and the
    testcase has a PASSed control of `control_kind` (oracle_can_pass for a FAIL, oracle_can_fail for a PASS)."""
    if tr.get("phase") == "B4":
        return g4_approved(ix, tr)
    if tr.get("phase") == "W4":
        reqs = set(tc.get("requirement_ids") or [])
        return bool(reqs) and reqs <= ix.approved_requirement_ids() and controls_of_kind_pass(tc, tr, control_kind) is True
    return False


TEST_AUTHOR_ROLES = {"W4": ("test_generator", "test_critic"), "B4": ("test_designer", "test_implementer", "test_critic")}


def test_author_families(ix: "Index", tr: dict) -> tuple[set, set]:
    """v0.6 (review r7 3.1): (families, lineages) of the agents that wrote or shaped the test the result came from: the
    W4 test generator, or the B3 test designer and implementer and the threat modelers of the testcase's threat. A
    Result Analyst from one of them would grade its own test."""
    fams, lins = set(), set()
    for a in (ix.agents or {}).values():
        if isinstance(a, dict) and a.get("role") in TEST_AUTHOR_ROLES.get(tr.get("phase"), ()):
            m = ix.models.get(a.get("model")) if isinstance(a.get("model"), str) else None
            if isinstance(m, dict):
                fams.add(m.get("family"))
                lins.add(m.get("lineage"))
    if tr.get("phase") == "B4":
        tc = ix.testcase_for(tr)
        th = ix.first("threat", threat_id=tc.data.get("threat_id")) if tc and tc.data.get("threat_id") else None
        for mb in (th.data.get("modeled_by") or []) if th else []:
            m = ix.model_of_agent(mb.get("agent_id")) if isinstance(mb, dict) else None
            if isinstance(m, dict):
                fams.add(m.get("family"))
                lins.add(m.get("lineage"))
    return fams - {None}, lins - {None}


def analyst_check(ix: "Index", tr: dict, cluster: dict) -> tuple[bool, str | None]:
    """(eligible, disagreement): the Result Analyst is an agents.yaml result_analyst whose registry
    family and lineage are not in the cluster; eligible only when its interpretation agrees.
    v0.6 (review r7 3.1): nor those of the test's authors (test_author_families)."""
    ib = tr.get("interpreted_by")
    if not isinstance(ib, dict):
        return False, None
    a = ix.agents.get(ib.get("agent_id")) if isinstance(ib.get("agent_id"), str) else None
    m = ix.model_of_agent(ib.get("agent_id"))
    if not isinstance(a, dict) or a.get("role") != "result_analyst" or m is None:
        return False, None
    if m.get("family") in set(cluster.get("families") or []) or m.get("lineage") in set(cluster.get("lineages") or []):
        return False, None
    author_fams, author_lins = test_author_families(ix, tr)
    if m.get("family") in author_fams or m.get("lineage") in author_lins:
        return False, None
    agrees = (tr.get("interpretation") or {}).get("agrees")
    if agrees is True:
        return True, None
    return False, "eligible analyst does not agree with the interpretation"


def classify_result(ix: Index, tr: dict, cluster: dict) -> tuple[str, str]:
    """Return (class, reason) for one testresult linked to `cluster` (docs/05 §4.2, v0.3).

    1. outcome not PASS / FAIL (ERROR, SKIPPED, STOPPED, INVALID) -> E_inc.
    2. FAIL: fail_k_min and the replay rules, else E_inc; a violation reported only by HUMAN /
       LLM_GRADER oracles is E_inc; a pre-registered interpretation (G4 for B4; G1-signed
       requirements and a PASSed oracle_can_pass control for W4) -> E_proof without any LLM;
       else an eligible cross-family Result Analyst that agrees -> E_proof; else E_fail_u.
    3. PASS: every reachability control PASSed, probabilistic k=0 and n' >= 30, a deterministic
       oracle, and a pre-registered interpretation (oracle_can_fail for W4) or an eligible analyst
       -> E_pass; else E_inc.
    """
    tc_doc = ix.testcase_for(tr)
    tc = tc_doc.data if tc_doc else {}
    probabilistic = is_probabilistic(tc)
    got = tr.get("trials") or {}
    n, k = got.get("n", 0), got.get("k", 0)
    outcome = tr.get("outcome")
    if outcome not in ("FAIL", "PASS"):
        return "E_inc", f"outcome {outcome}"
    eligible, disagreement = analyst_check(ix, tr, cluster)
    if outcome == "FAIL":
        ok, why = fail_reproduced(tc, tr)
        if not ok:
            return "E_inc", why
        if not (set(tr.get("fail_oracles") or []) & DETERMINISTIC_ORACLES):
            return "E_inc", "violation judged only by a non-deterministic oracle"
        if preregistered(ix, tc, tr, "oracle_can_pass"):
            return "E_proof", "reproduced FAIL, deterministic oracle, pre-registered interpretation"
        if eligible:
            return "E_proof", "reproduced FAIL, cross-family analyst"
        if disagreement:
            return "E_inc", disagreement
        return "E_fail_u", "reproduced FAIL, no pre-registered interpretation or eligible analyst"
    if not reachability_reached(tc, tr):
        return "E_inc", "reachability control not passed"
    n_eff = got.get("n_effective", n)          # v0.4: n' = trials whose precondition was reached (docs/04 §4.4)
    need = pass_min_effective(ix, tc)
    if probabilistic and not (k == 0 and isinstance(n_eff, int) and n_eff >= need):
        return "E_inc", f"probabilistic PASS needs k=0 and n'>={need}"
    if not (oracle_types(tc) & DETERMINISTIC_ORACLES):
        return "E_inc", "no deterministic oracle"
    if preregistered(ix, tc, tr, "oracle_can_fail"):
        return "E_pass", "qualified PASS, pre-registered interpretation"
    if eligible:
        return "E_pass", "qualified PASS, cross-family analyst"
    return "E_inc", disagreement or "no pre-registered interpretation or eligible analyst"


def job_end_of(e, tr: dict) -> bool:
    """The sandbox_job_end event of a result: by job_id for B4, by result_id for W4 (W4 jobs are not run.jobs)."""
    if not isinstance(e, dict) or e.get("event_type") != "sandbox_job_end":
        return False
    p = e.get("payload") or {}
    if tr.get("phase") == "W4":
        return p.get("result_id") == tr.get("result_id")
    return tr.get("job_id") is not None and p.get("job_id") == tr.get("job_id")


def execution_pins(tc: dict, tr: dict) -> dict:
    """v0.5 (review r7 1.10): hashes the executor records in sandbox_job_end: the testcase it ran, the artifact, and the
    result it returned."""
    return {"testcase_sha256": content_hash(tc), "artifact_sha256": tr.get("artifact_sha256"), "result_sha256": content_hash(tr)}


def vote_terms(ix: "Index", vote: dict, cluster: dict, version) -> tuple[bool, float, bool]:
    """(valid, weight, weighted_valid) of one vote. A vote by an agent without the verifier role is ignored
    (E-VERDICT-VOTER-ROLE in checks); v0.5 (review 2026-10-25 A-3): an abstention takes a side neither way, so it is never
    weighted-valid (v0.4 counted it, and one abstaining family could lift the R8 cap through diversity)."""
    valid = vote_valid(vote, cluster, ix)
    wgt = ix.weight(vote.get("voter_model_key"), cluster.get("cwe_bucket"), version, vote.get("stance"))
    counts = valid and wgt > 0 and is_verifier_vote(ix, vote) and vote.get("stance") in ("SUPPORT", "REFUTE")
    return valid, wgt, counts


def derived_score(ix: "Index", v: dict, cluster: dict) -> float:
    """S = sum(w * stance) over weighted-valid votes, recomputed (v0.5, review r7 1.7: the rules use this value, not the
    verdict's own score, which E-DERIVED compares only within rounding)."""
    score = 0.0
    for vote in v.get("votes", []):
        _, wgt, counts = vote_terms(ix, vote, cluster, v.get("calibration_version"))
        if counts:
            score += wgt * STANCE.get(vote.get("stance"), 0)
    return round(score, 4)


def strongest(classes) -> str | None:
    for c in ("E_proof", "E_fail_u", "E_pass", "E_inc"):
        if c in classes:
            return c
    return None


# v0.5 (review 2026-10-25 A-7): the test phases a verdict version may see. A W4 version is written before any
# black-box execution, so it cannot cite B4 results; v0.4 linked every result of the run to every version.
RESULT_PHASES = {"W3_adjudicate": (), "G2_apply": (), "W4_readjudicate": ("W4",), "B5_readjudicate": ("W4", "B4")}


def linked_results(ix: Index, cluster: dict, readjudicated_by: str | None = "B5_readjudicate") -> list[dict]:
    phases = RESULT_PHASES.get(readjudicated_by, ())
    rs = [d.data for d in ix.docs("testresult")
          if d.data.get("run_id") == cluster.get("run_id") and cluster.get("cluster_id") in d.data.get("cluster_ids", [])
          and d.data.get("phase") in phases]
    return sorted(rs, key=lambda r: (timeutil.sort_key(r.get("executed_at")), str(r.get("result_id"))))


def w4_became_disputed_clusters(ix: Index) -> dict[str, Any]:
    """cluster_id -> run_id for clusters with a verdict annotated w4_became_disputed."""
    out = {}
    for v in ix.docs("verdict"):
        if any(a.get("kind") == "w4_became_disputed" for a in v.data.get("annotations", []) if isinstance(a, dict)):
            cl = ix.first("cluster", cluster_id=v.data.get("cluster_id"))
            out[v.data.get("cluster_id")] = cl.data.get("run_id") if cl else None
    return out


VERIFIER_TEMPLATE_ID = "w3-verify"


def verifier_template_controls(ix: "Index", cluster: dict) -> tuple[bool, bool]:
    """v0.4: (anonymizes_candidates, randomizes_order) of the run's W3 verifier prompt template. These are
    properties of the harness template recorded in the run manifest, not of the vote."""
    run = ix.first("run", run_id=cluster.get("run_id"))
    for t in ((run.data if run else {}) or {}).get("prompt_templates") or []:
        if isinstance(t, dict) and t.get("template_id") == VERIFIER_TEMPLATE_ID:
            return t.get("anonymizes_candidates") is True, t.get("randomizes_order") is True
    return False, False


CITE_LINE_RE = __import__("re").compile(r"^(?P<file>.+):(?P<a>[1-9][0-9]*)(?:-(?P<b>[1-9][0-9]*))?$")


def _cite_lines(c: str) -> tuple[str, int, int] | None:
    """`file:line` or `file:start-end` -> (file, start, end); anything else (no line, bad range) -> None."""
    m = CITE_LINE_RE.match(c)
    if m is None:
        return None
    a = int(m.group("a"))
    b = int(m.group("b")) if m.group("b") else a
    return (m.group("file"), a, b) if b >= a else None


def cited_relevant(ix: "Index", v: dict, cluster: dict) -> bool:
    """v0.5 (review 2026-10-25 A-4, A-5): at least one cited item is about this cluster.

    - every vote: a `file:line[-line]` inside the line range of a member finding's code_snippet evidence (same
      file), or `inventory:<pointer>` equal to a member's inventory_fact fact_ref;
    - a REFUTE vote may also cite a line inside a member finding's slice (slice.files[] path and line range), or any
      `inventory:<pointer>` that resolves in the run's W0 inventory: a refutation usually rests on code elsewhere
      on the path (a middleware check, a policy) or on configuration.
    v0.4 compared the file name only, so `file:99999` or a bare file name counted."""
    from . import evidence
    members = [ix.finding(fid) or {} for fid in cluster.get("member_finding_ids") or []]
    ranges, facts = [], set()
    for f in members:
        for e in f.get("evidence") or []:
            if not isinstance(e, dict):
                continue
            if e.get("kind") == "code_snippet" and isinstance(e.get("line_start"), int) and isinstance(e.get("line_end"), int):
                ranges.append((e.get("file"), e["line_start"], e["line_end"]))
            elif e.get("kind") == "inventory_fact":
                facts.add(e.get("fact_ref"))
    refute = v.get("stance") == "REFUTE"
    if refute:
        sids = {f.get("slice_id") for f in members}
        for sl in ix.docs("slice"):
            if sl.data.get("slice_id") in sids and sl.data.get("run_id") == cluster.get("run_id"):
                ranges.extend((x.get("path"), x.get("line_start"), x.get("line_end"))
                              for x in sl.data.get("files") or [] if isinstance(x, dict))
        inv = ix.first("inventory", run_id=cluster.get("run_id"))
    for c in v.get("cited_evidence") or []:
        if not isinstance(c, str):
            continue
        if c.startswith("inventory:"):
            ptr = c[len("inventory:"):]
            if ptr in facts or (refute and inv is not None and evidence.resolves(inv.data, ptr)):
                return True
            continue
        loc = _cite_lines(c)
        if loc and any(loc[0] == f and isinstance(a, int) and isinstance(b, int) and a <= loc[1] and loc[2] <= b
                       for f, a, b in ranges):
            return True
    return False


def vote_valid(v: dict, cluster: dict, ix: "Index | None" = None) -> bool:
    """docs/05 §4.2: family / lineage not in the cluster; candidates anonymised and order randomised (v0.4: by the
    run's verifier template, not by the vote's own flags); and (v0.4) a cited item relevant to the cluster."""
    if v.get("voter_family") in cluster.get("families", []) or v.get("voter_lineage") in cluster.get("lineages", []):
        return False
    if ix is None:
        return bool(v.get("anonymized")) and bool(v.get("order_randomized"))
    anon, rand = verifier_template_controls(ix, cluster)
    return anon and rand and bool(v.get("anonymized")) and bool(v.get("order_randomized")) and cited_relevant(ix, v, cluster)


def is_verifier_vote(ix: "Index", v: dict) -> bool:
    """Only agents.yaml agents with role verifier may vote (docs/05 §3); other votes are ignored."""
    a = ix.agents.get(v.get("voter_agent_id")) if isinstance(v.get("voter_agent_id"), str) else None
    return isinstance(a, dict) and a.get("role") == "verifier"


# ---------------------------------------------------------------- gate artifacts
def gate_items(ix: Index, rec: dict) -> dict[str, Any]:
    """item_id -> the object shown at the gate (None if unknown)."""
    gate, run_id = rec.get("gate"), rec.get("run_id")
    out = {}
    for dec in rec.get("decisions", []):
        iid = dec.get("item_id")
        obj = None
        if gate == "G1":
            inv = ix.b.data("invariants") or {}
            obj = next((i for i in inv.get("invariants", []) if i.get("requirement_id") == iid), None)
        elif gate == "G2":
            d = ix.first("cluster", cluster_id=iid, run_id=run_id)
            obj = d.data if d else None
        elif gate == "G3":
            d = ix.first("threat", threat_id=iid)
            obj = d.data if d else None
        elif gate in ("G4", "G5"):
            d = ix.first("testcase", testcase_id=iid)
            obj = d.data if d else None
        out[iid] = obj
    return out


def gate_artifact(ix: Index, rec: dict) -> str | None:
    gate = rec.get("gate")
    if gate == "G0a":
        e = ix.b.data("engagement")
        return content_hash(e) if e else None
    if gate == "G0b":
        r = ix.b.data("roe")
        return content_hash(r) if r else None
    if gate == "G1":
        inv = ix.b.data("invariants")
        return approval_hash(inv) if inv else None
    items = gate_items(ix, rec)
    if gate in ("G2", "G3", "G4"):
        if any(v is None for v in items.values()):
            return None
        return set_digest([{"id": k, "sha256": approval_hash(v)} for k, v in items.items()])
    if gate == "G5":
        run = ix.first("run", run_id=rec.get("run_id"))
        job = ((run.data.get("jobs") or {}).get(rec.get("job_id")) if run else None) or {}
        tc = ix.first("testcase", testcase_id=job.get("testcase_id"))
        if not tc:
            return None
        return content_hash({"job_id": rec.get("job_id"), "testcase_sha256": approval_hash(tc.data)})
    if gate == "GB":
        gb = rec.get("gb") or {}
        return content_hash({"run_id": rec.get("run_id"), "phase": gb.get("phase"), "new_caps": gb.get("new_caps")})
    return None


def item_hash(ix: Index, rec: dict, item_id: str):
    gate = rec.get("gate")
    if gate in ("G0a", "G0b"):
        return gate_artifact(ix, rec)
    if gate == "GB":
        return None
    obj = gate_items(ix, rec).get(item_id)
    return approval_hash(obj) if obj is not None else MISSING


# ---------------------------------------------------------------- expectations
def expectations(b: Bundle, for_writer: bool = False, problems: list | None = None) -> list[Expectation]:
    """Derived values. for_writer=True adds values that only the writer (sign_examples) fills in
    and that the reader checks with dedicated rules instead (run.audit_anchors).
    v0.5 (review r7, group 5): each document is derived on its own; a document whose values break a derivation is
    appended to `problems` as (path, exception) and the other documents are still derived."""
    ix = Index(b)
    out: list[Expectation] = []

    @contextlib.contextmanager
    def guard(d):
        try:
            yield
        except Exception as exc:  # noqa: BLE001 - reported as E-INTERNAL for this document by checks.g_derived
            if problems is None:
                raise
            problems.append((d.path, exc))

    def exp(doc: Doc, path, value, why):
        if value is MISSING:
            return
        out.append(Expectation(doc.path, tuple(path), value, why))

    # slices (E6: the identity covers the files, the redaction map and the prompt template)
    slice_by_run: dict[str, list[str]] = {}
    for d in ix.docs("slice"):
        with guard(d):
            rm = ix.first("redaction-map", run_id=d.data.get("run_id"))
            if rm:
                exp(d, ["redaction_map_sha256"], content_hash(rm.data), "content hash of the run's redaction map")
            rm_sha = content_hash(rm.data) if rm else d.data.get("redaction_map_sha256")
            sid = slice_identity(d.data.get("files", []), rm_sha, d.data.get("prompt_template_sha256"))
            exp(d, ["slice_id"], sid, "sha256(JCS({files, redaction_map_sha256, prompt_template_sha256}))")
            slice_by_run.setdefault(d.data.get("run_id"), []).append(sid)

    # findings
    for d in ix.docs("finding"):
        with guard(d):
            for i, e in enumerate(d.data.get("evidence", [])):
                if isinstance(e.get("snippet"), str):
                    exp(d, ["evidence", i, "snippet_sha256"], text_hash(e["snippet"]), "sha256(snippet UTF-8)")
            sl = slice_by_run.get(d.data.get("run_id"), [])
            if len(sl) == 1:
                exp(d, ["slice_id"], sl[0], "the slice of the same run")

    if for_writer:
        # writer-only: the reader checks these with dedicated codes (E-CLUSTER-FINGERPRINT,
        # E-RESULT-PRECONDITION, E-RESULT-CONTROLS) so a tampered value is reported by its rule
        for d in ix.docs("cluster"):
            with guard(d):
                exp(d, ["fingerprint"], cluster_fingerprint(d.data), "sha256(JCS(fingerprint key))")
        for d in ix.docs("testresult"):
            with guard(d):
                tc = ix.testcase_for(d.data)
                if tc:
                    exp(d, ["precondition_reached", "value"], reachability_reached(tc.data, d.data), "all reachability controls PASS")
                    exp(d, ["positive_control", "value"], positive_control_value(tc.data, d.data), "oracle_can_fail control PASSed")
        # v0.5 (review r7 1.11): the adopting run's feedback_recorded event pins the feedback record (E-FEEDBACK reads it)
        for f in ix.docs("feedback"):
            for a in ix.audit_docs():
                for i, e in enumerate(a.data):
                    if isinstance(e, dict) and e.get("event_type") == "feedback_recorded" and \
                            (e.get("payload") or {}).get("feedback_id") == f.data.get("feedback_id"):
                        exp(a, [i, "payload", "feedback_sha256"], content_hash(f.data), "content hash of the recorded feedback")
        # v0.5 (review r7 1.10, external review 2): the executor's sandbox_job_end pins what ran and what it produced; the
        # reader compares them with dedicated codes (E-W4-AUDIT / E-JOB-AUDIT)
        for d in ix.docs("testresult"):
            with guard(d):
                tc = ix.testcase_for(d.data)
                audit = ix.audit_for(d.data.get("run_id"))
                if tc is None or audit is None:
                    continue
                for i, e in enumerate(audit.data):
                    if job_end_of(e, d.data):
                        for key, val in execution_pins(tc.data, d.data).items():
                            exp(audit, [i, "payload", key], val, f"{key} of what the job ran")

    # inventory -> redaction map
    for d in ix.docs("inventory"):
        with guard(d):
            rm = ix.first("redaction-map", run_id=d.data.get("run_id"))
            if rm:
                exp(d, ["redaction_map_ref"], content_hash(rm.data), "content hash of the run's redaction map")

    # testcases -> seed manifest oracle queries
    oq = ix.manifest.get("oracle_queries") or {}
    for d in ix.docs("testcase"):
        with guard(d):
            qid = (d.data.get("oracle") or {}).get("oracle_query_id")
            if qid and qid in oq:
                exp(d, ["oracle", "oracle_query_sha256"], oq[qid].get("sql_sha256"), f"seed-manifest oracle_queries.{qid}.sql_sha256")

    # testresults -> testcase artifact
    for d in ix.docs("testresult"):
        with guard(d):
            tc = ix.testcase_for(d.data)
            if tc:
                exp(d, ["artifact_sha256"], tc.data.get("artifact_sha256"), "testcase.artifact_sha256")

    # verdicts
    t_conf, t_rej = ix.thresholds()
    for d in ix.docs("verdict"):
        with guard(d):
            v = d.data
            cl = ix.first("cluster", cluster_id=v.get("cluster_id"))
            if not cl:
                continue
            cluster = cl.data
            version = v.get("calibration_version")
            for i, vote in enumerate(v.get("votes", [])):
                valid, wgt, counts = vote_terms(ix, vote, cluster, version)
                exp(d, ["votes", i, "valid"], valid, "family/lineage not in cluster, anonymized, order randomized")
                exp(d, ["votes", i, "weight"], wgt, "calibration.yaml w(model, cwe_bucket, side of the stance)")
                exp(d, ["votes", i, "weighted_valid"], counts, "valid, w > 0, a verifier-role voter, stance SUPPORT or REFUTE")
            exp(d, ["score"], derived_score(ix, v, cluster), "sum(w * stance) over weighted-valid votes")
            if version is not None and ix.calibration.get("calibration_version") == version:
                exp(d, ["theta_confirm"], t_conf, "calibration theta_confirm")
                exp(d, ["theta_reject"], t_rej, "calibration theta_reject")
            results = linked_results(ix, cluster, v.get("readjudicated_by"))
            classes = []
            exp(d, ["test_evidence", "results"], _merge_results(v, ix, results, cluster, classes), "linked testresults (docs/05 §4.2)")
            cls = strongest(classes)
            exp(d, ["test_evidence", "class"], cls, "strongest linked class")
            proof = None
            if cls == "E_proof":
                tr = next(r for r, c in zip(results, classes) if c == "E_proof")
                tc = ix.testcase_for(tr)
                probabilistic = tc is not None and (tc.data.get("trials") or {}).get("n", 1) > 1
                proof = {"testcase_id": tr.get("testcase_id"), "result_ref": content_hash(tr),
                         "trials": dict(tr.get("trials")) if probabilistic else None,
                         "interpretation_confirmed_by": tr.get("interpreted_by")}
            exp(d, ["executable_proof"], proof, "from the E_proof testresult")

    # disputed_after_g2: derived from verdicts carrying the w4_became_disputed annotation (docs/05 §4.2)
    became = w4_became_disputed_clusters(ix)
    for d in ix.docs("seed-threats"):
        with guard(d):
            for i, sd in enumerate(d.data.get("seeds", [])):
                exp(d, ["seeds", i, "disputed_after_g2"], sd.get("source_cluster_id") in became,
                    "a verdict of the source cluster carries w4_became_disputed")

    # gate records
    for d in ix.docs("gate-record"):
        with guard(d):
            rec = d.data
            art = gate_artifact(ix, rec)
            if art is not None:
                exp(d, ["artifact", "sha256"], art, f"{rec.get('gate')} artifact hash")
            for i, dec in enumerate(rec.get("decisions", [])):
                exp(d, ["decisions", i, "item_sha256"], item_hash(ix, rec, dec.get("item_id")), "approval hash of the item")
            if rec.get("gate") in ("G0a", "G0b") and art is not None and rec.get("verification"):
                exp(d, ["verification", "document_ref"], art, "hash of the verified document")

    # runs
    for d in ix.docs("run"):
        with guard(d):
            _run_expectations(ix, d, exp, slice_by_run, for_writer)

    # report manifest
    for d in ix.docs("report-manifest"):
        with guard(d):
            _report_expectations(ix, d, exp)

    # checkpoint
    for d in ix.docs("checkpoint-metadata"):
        with guard(d):
            run = ix.first("run", run_id=d.data.get("run_id"))
            if run:
                exp(d, ["state_sha256"], content_hash(run.data), "content hash of the run state")
                pi = d.data.get("pending_interrupt")
                pend = [g for g in run.data.get("gate_records", []) if g.get("gate_record_id") is None]
                if pi and pend:
                    exp(d, ["pending_interrupt", "gate"], pend[-1].get("gate"), "the run's pending gate")
                    exp(d, ["pending_interrupt", "subject_hash"], pend[-1].get("subject_hash"), "the run's pending gate subject")
                    exp(d, ["pending_interrupt", "deadline"], run.data.get("resume_deadline"), "run.resume_deadline")

    # commander plans: slice ids of the run that lists the plan
    for d in ix.docs("commander-plan"):
        with guard(d):
            runs = [r.data for r in ix.docs("run") if d.data.get("plan_id") in r.data.get("plan_ids", [])]
            if len(runs) == 1:
                sl = slice_by_run.get(runs[0].get("run_id"), [])
                if len(sl) == 1:
                    for i, _ in enumerate(d.data.get("slices", [])):
                        exp(d, ["slices", i, "slice_id"], sl[0], "the slice of the run that lists this plan")

    # (the audit hash chain is checked from raw lines in checks.py, E-AUDIT-CHAIN)
    return out


def _merge_results(v, ix, results, cluster, classes):
    old = (v.get("test_evidence") or {}).get("results", [])
    merged = []
    for i, tr in enumerate(results):
        cls, why = classify_result(ix, tr, cluster)
        classes.append(cls)
        reason = old[i].get("reason") if i < len(old) and isinstance(old[i], dict) else why
        merged.append({"result_ref": content_hash(tr), "class": cls,
                       "positive_control": (tr.get("positive_control") or {}).get("value"), "reason": reason})
    return merged


def tool_results_ref(ix: Index, rid) -> str | None:
    """v0.5 (BL-13): the run's ToolResult list, as the sorted unique payload_refs of its W1 / Z2 tool_invocation_end
    audit events; None when W1 recorded none."""
    audit = ix.audit_for(rid)
    refs = sorted({r for e in (audit.data if audit else []) if isinstance(e, dict) and e.get("event_type") == "tool_invocation_end"
                   and e.get("node") == "W1" and e.get("zone") == "Z2" for r in e.get("payload_refs") or [] if isinstance(r, str)})
    return sha256_ref(jcs(refs)) if refs else None


def _run_expectations(ix: Index, d: Doc, exp, slice_by_run, for_writer=False):
    r = d.data
    rid = r.get("run_id")
    b = ix.b
    for field, kind in (("toolkit_config_ref", "toolkit-config"), ("key_registry_ref", "key-registry"), ("engagement_ref", "engagement")):
        if b.data(kind) is not None:
            exp(d, [field], content_hash(b.data(kind)), f"content hash of {kind}")
    # B11: configuration files named by the run manifest (the kind is checked in checks.g_runs, E-RUN-CONFIG)
    for key in CONFIG_KINDS:
        ref = (r.get("config_refs") or {}).get(key)
        if isinstance(ref, dict) and isinstance(ref.get("path"), str):
            cd = next((x for x in b.docs if x.path == ref["path"] and x.data is not None), None)
            if cd is not None:
                exp(d, ["config_refs", key, "sha256"], content_hash(cd.data), f"content hash of {ref['path']}")
    has_g0b = any(g.get("gate") == "G0b" for g in r.get("gate_records", []))
    if b.data("roe") is not None:
        exp(d, ["roe_ref"], content_hash(b.data("roe")) if has_g0b else None, "content hash of roe.yaml when the run passed G0b")

    def by_run(kind, field, fn=content_hash, **extra):
        doc = ix.first(kind, run_id=rid, **extra)
        exp(d, [field], fn(doc.data) if doc else None, f"{kind} of this run")
        return doc

    inv = by_run("inventory", "inventory_ref")
    exp(d, ["sbom_ref"], inv.data.get("sbom_ref") if inv else None, "inventory.sbom_ref")
    exp(d, ["tool_results_ref"], tool_results_ref(ix, rid), "sha256(JCS(sorted payload_refs of the run's W1 Z2 tool_invocation_end events))")
    by_run("redaction-map", "redaction_map_ref")
    by_run("seed-threats", "seed_threats_ref")
    merged = by_run("dfd", "dfd_ref", viewpoint="merged")
    by_run("dfd", "b1_merged_ref", viewpoint="merged")
    by_run("dfd", "b1_external_ref", viewpoint="external")
    exp(d, ["b1_diff_ref"], sha256_ref(jcs(merged.data.get("b1_diff"))) if merged else None, "sha256(JCS(merged.b1_diff))")
    by_run("report-manifest", "report_manifest_ref")
    invariants = b.data("invariants")
    exp(d, ["invariants_ref"], content_hash(invariants) if invariants and invariants.get("run_id") == rid else None,
        "invariants.yaml of this run")
    exp(d, ["slice_refs"], slice_by_run.get(rid, []), "slices of this run")

    g3 = ix.gate_records(rid, "G3")
    exp(d, ["threat_model_ref"], artifact_sha(g3[-1].data) if g3 else None, "G3 artifact")
    tcs = {tid: ix.first("testcase", testcase_id=tid) for tid in r.get("testcase_ids", [])}
    if all(tcs.values()):
        exp(d, ["artifact_hashes"], {k: approval_hash(v.data) for k, v in tcs.items()}, "approval hash of each testcase")
        exp(d, ["testplan_ref"], set_digest([{"id": k, "sha256": approval_hash(v.data)} for k, v in tcs.items()]) if tcs else None,
            "set digest of the run's testcases (= G4 artifact)")
    trs = sorted((x.data for x in ix.docs("testresult") if x.data.get("run_id") == rid),
                 key=lambda t: (timeutil.sort_key(t.get("executed_at")), str(t.get("result_id"))))   # D4: by instant, not by text
    exp(d, ["testresults"], [content_hash(t) for t in trs], "content hash of each testresult (execution order)")
    for jid in (r.get("jobs") or {}):
        tr = next((t for t in trs if t.get("job_id") == jid), None)
        exp(d, ["jobs", jid, "result_ref"], content_hash(tr) if tr else None, "testresult of this job")
    recs = {x.data.get("gate_record_id"): x.data for x in ix.gate_records(rid)}
    for i, g in enumerate(r.get("gate_records", [])):
        rec = recs.get(g.get("gate_record_id"))
        if rec is None:
            if g.get("gate") == "G4" and g.get("gate_record_id") is None and r.get("testplan_ref") is not None:
                exp(d, ["gate_records", i, "subject_hash"], get_path(r, ["testplan_ref"]), "pending G4 subject = testplan_ref")
            continue
        for field, val in (("gate", rec.get("gate")), ("outcome", rec.get("outcome")), ("round", rec.get("round")),
                           ("subject_hash", artifact_sha(rec)), ("job_id", rec.get("job_id")),
                           ("opened_at", rec.get("opened_at")), ("decided_at", rec.get("timestamp"))):
            exp(d, ["gate_records", i, field], val, f"mirror of {rec.get('gate_record_id')}")
    parent = ix.first("run", run_id=r.get("parent_run_id")) if r.get("parent_run_id") else None
    if parent and r.get("run_kind") == "followup":
        exp(d, ["reuse"], [parent.data.get("invariants_ref"), parent.data.get("threat_model_ref")],
            "follow-up reuses the parent's approved invariants and threat model")
    exp(d, ["disputed_after_g2"], sorted(k for k, run_id in w4_became_disputed_clusters(ix).items() if run_id == rid),
        "clusters of this run with a verdict carrying w4_became_disputed")
    audit = ix.audit_for(rid)
    if audit and for_writer:
        # writer-only: the reader side checks the anchors against the raw lines in checks.g_audit
        # (E-AUDIT-ANCHOR / -MISMATCH / -TRUNCATED / -TAIL), so a tampered log is reported as such
        lines = read_jsonl_lines(audit.text or "")
        exp(d, ["audit_anchors"],
            [{"seq": i + 1, "line_sha256": "sha256:" + sha256_hex(lines[i].encode("utf-8"))}
             for i, e in enumerate(audit.data) if e.get("event_type") == "audit_anchor"],
            "one {seq, line_sha256} per audit_anchor event (sha256 of the anchor's own raw line)")


def _report_expectations(ix: Index, d: Doc, exp):
    rid = d.data.get("run_id")
    audit = ix.audit_for(rid)
    for i, a in enumerate(d.data.get("artifacts", [])):
        kind, ref = a.get("kind"), a.get("ref")
        val = MISSING
        if kind in ("threat_model", "test_plan", "gate_record"):
            rec = ix.first("gate-record", gate_record_id=ref)
            if rec:
                val = artifact_sha(rec.data) if kind != "gate_record" else content_hash(rec.data)
        elif kind == "testresult":
            x = ix.first("testresult", result_id=ref)
            val = content_hash(x.data) if x else MISSING
        elif kind == "verdict":
            x = ix.first("verdict", verdict_id=ref)
            val = content_hash(x.data) if x else MISSING
        elif kind == "audit_log" and audit:
            pub = [e for e in audit.data if e.get("event_type") == "report_published"]
            val = pub[0].get("prev_hash") if pub else MISSING
        elif kind == "followup_draft":
            x = next((p for p in ix.docs("commander-plan") if any(f.get("draft_id") == ref for f in p.data.get("followup_drafts", []))), None)
            val = content_hash(x.data) if x else MISSING
        exp(d, ["artifacts", i, "sha256"], val, f"{kind} {ref}")


def compare(b: Bundle, problems: list | None = None) -> list[tuple[Expectation, Any]]:
    """Mismatches: [(expectation, actual)]."""
    docs = {d.path: d for d in b.docs}
    bad = []
    for e in expectations(b, problems=problems):
        doc = docs.get(e.file)
        actual = get_path(doc.data, e.path) if doc and doc.data is not None else MISSING
        if not _equal(actual, e.expected):
            bad.append((e, actual))
    return bad


def _equal(a, b) -> bool:
    if isinstance(a, bool) or isinstance(b, bool):
        return a is b if isinstance(a, bool) and isinstance(b, bool) else False
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return abs(a - b) <= 5e-4
    if isinstance(a, dict) and isinstance(b, dict):
        return a.keys() == b.keys() and all(_equal(a[k], b[k]) for k in a)
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(_equal(x, y) for x, y in zip(a, b))
    return a == b


__all__ = ["Expectation", "Index", "expectations", "compare", "classify_result", "strongest", "gate_artifact",
           "get_path", "set_path", "fmt_path", "MISSING", "ZERO", "timeutil"]
