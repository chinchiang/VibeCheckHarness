# SPDX-License-Identifier: Apache-2.0
"""Ordered adjudication rules of docs/05 §4.2 (decision table rows 1-13, R8/R11 modifiers,
R12/R13 annotations). Pure function: the validator recomputes each example verdict and
compares status, deciding rule and annotations.

v0.3 (rule_version 05-v0.3): tool evidence has two tiers (H-A1). Reviewers and verifiers never
see W1 tool output; tools enter adjudication only through the deterministic Clusterer.
  - strong_tool: a resolved SARIF result whose (adapter, rule_id) is a calibrated
    high-precision rule for the cluster's CWE bucket -> R5 row 10 (not capped by R8);
  - weak_sarif: any other resolved SARIF result; E_fail_u (reproduced FAIL without a
    pre-registered interpretation or eligible analyst) stays in `evidence`.
    Weak signals never confirm on their own: they count as one extra independent source
    each (R6: sources >= 2 -> LIKELY) and turn a lone refutation into DISPUTED (R4 row 7).

v0.4 (rule_version 05-v0.4): three rule edges that could drop or downgrade a real defect unseen.
  - R0 needs that the cluster has nothing else: no resolved SARIF (strong or weak) and no
    FAIL-class test evidence (E_proof / E_fail_u). A mis-located LLM snippet no longer rejects a
    cluster that a scanner or a reproduced FAIL also points at.
  - R10: a G2 rejection stays final against votes, SARIF and E_fail_u, but not against an
    executable proof (E_proof): the cluster becomes CONFIRMED_EXECUTABLE with post_g2_conflict
    and goes to the B6 human review list. A pre-registered, replayed deterministic FAIL is
    stronger evidence than a judgement made before the test existed.
  - R11 downgrades CONFIRMED_CORROBORATED / LIKELY to DISPUTED only when a qualified PASS has a
    positive control (an oracle_can_fail control that PASSed). A PASS without one only adds
    test_not_reproduced: a test that was never shown able to fail cannot refute.

v0.7 (rule_version 05-v0.9, review r10 PR2):
  - S counts each base lineage as its strongest vote when its votes agree (derive.root_score): the mean let a weaker
    SUPPORT of the same root lower S, so adding evidence could remove a confirmation.
  - An eligible Result Analyst that disagrees makes a pre-registered result E_inc; unknown W4 test authors are not
    independent; `trials.sampling: sampled` is a declaration, not a probabilistic signal.
  - Calibration: an abstention counts as a coin flip (half right, half wrong) in the rates and the Wilson bound;
    theta_reject is above every single refute weight of its bucket; a threshold generalises only on a holdout of
    n >= 10; a reproduced canary zeroes the model's weights. The example weights and scores changed, statuses did not.

v0.7 (rule_version 05-v0.8, review r9 PR2):
  - S counts each base lineage once, as the mean of its weighted-valid votes (derive.root_score): log likelihood ratios
    add only for independent observations, and two verifiers of one root share its blind spots.
  - A W4 FAIL is pre-registered proof only when the test's authors are outside the cluster's families and roots; the
    FAIL replay rule uses the same probabilistic judgement as the rest of the classification.
  - Calibration: abstention rate near-zero rule; the theta limits of docs/05 §5.7 recomputed; theta_confirm above any
    single support weight of its bucket.

v0.7 (rule_version 05-v0.7, review r8 group 3):
  - R6 / R2 sources: an E_fail_u result is an independent source only when the agents that wrote or shaped its test
    are outside the cluster's families and base lineages (Inputs.fail_u_independent, derived by the validator); v0.6
    counted any E_fail_u, so one family could report a defect, write the W4 test and read its FAIL, and reach LIKELY.
    An E_fail_u still turns a lone refutation into DISPUTED (row 7): a dispute goes to a person.
  - Vote weights use a non-degenerate prior (docs/05 §4.3), so a verifier perfect on one side keeps its weight; the
    calibration example's weights and scores changed, theta_confirm stays 2.5.

v0.6 (rule_version 05-v0.6, review r7 group 3):
  - R10: only a G4-approved black-box proof that the replay job reproduced (k_r >= 1) overrides a G2 rejection.
    A W4 proof is written and interpreted inside the white-box pipeline the human just overruled; it still confirms
    a cluster that G2 did not reject (R1), but against a rejection it only adds post_g2_conflict (B6 human review).
  - R0: no member evidence item is grounded (MATCHED / MATCHED_SHIFTED) and at least one is NOT_FOUND; v0.5 needed
    every item NOT_FOUND, so one NOT_CHECKED item kept an otherwise ungrounded cluster alive.
"""
from __future__ import annotations

from dataclasses import dataclass, field

RULE_VERSION = "05-v0.13"
EVIDENCE_ORDER = ["E_proof", "E_fail_u", "E_pass", "E_inc"]


@dataclass
class Inputs:
    lane_a: bool = False
    g2_rejected: bool = False
    proof_overrides_g2: bool = False                      # an E_proof from a G4-approved B4 result with k_r >= 1 (R10, v0.6)
    all_snippets_fail: bool = False                       # no member evidence item grounded, one NOT_FOUND (v0.6; False without members)
    pass_positive: bool = False                           # some E_pass result has a PASSed oracle_can_fail control (R11, v0.4)
    evidence: set[str] = field(default_factory=set)       # classes present among linked results
    fail_u_independent: bool = False                      # an E_fail_u whose test authors are outside the cluster (v0.7)
    weighted_support: bool = False
    weighted_refute: bool = False
    score: float = 0.0                                    # S = sum(w * stance)
    strong_tool: bool = False                             # resolved high-precision SARIF result (row 10)
    weak_sarif: bool = False                              # any other resolved SARIF result (a signal, not corroboration)
    theta_confirm: float | None = None                    # None = +inf (disabled)
    theta_reject: float | None = None
    independent_families: int = 0
    diversity_degraded: bool = False
    g3_rejected: bool = False
    phase: str | None = None                              # caller context: "W3", "W4", "B5", ...
    prev_status: str | None = None                        # status of the superseded verdict (None = first verdict)
    regression_fixed: bool = False                        # r11 (05-v0.10); per testcase since 05-v0.12: every proving testcase of the confirmed source PASSed again with a positive control
    later_member_overlap: bool = False                    # r11: a weighted vote cast before a same-family / same-root member joined the cluster
    carried_status: str | None = None                     # r12 (05-v0.11): head status of the source cluster a carried-in cluster stands for


@dataclass
class Outcome:
    status: str
    row: int
    rules: list[str]
    status_cap: str | None = None
    advisory: bool = False
    annotations: set[str] = field(default_factory=set)
    sources: int = 0                                      # R2: independent families + weak SARIF + E_fail_u
    decided: str | None = None                            # status of the deciding rule, before the R8 / R11 modifiers


def trace_statuses(out: Outcome) -> list[str]:
    """The status each fired rule leaves (BL-01): the deciding rule and R2 leave `decided`, R8 caps to LIKELY,
    R11 and the R12 / R13 annotations leave the final status. A `->STATUS` claim in a rule_trace item must match."""
    return ["LIKELY" if r == "R8" else out.status if r in ("R11", "R12", "R13", "R15", "R16") else (out.decided or out.status)
            for r in out.rules]


def strongest(evidence: set[str]) -> str | None:
    for c in EVIDENCE_ORDER:
        if c in evidence:
            return c
    return None


def independent_sources(x: Inputs) -> int:
    """R2: independent families + (1 if a weak SARIF signal) + (1 if an independently authored E_fail_u result, v0.7)."""
    return x.independent_families + int(bool(x.weak_sarif)) + int(x.fail_u_independent)


def fail_class(x: Inputs) -> bool:
    """A FAIL-class test result (E_proof or E_fail_u) is linked to the cluster."""
    return bool({"E_proof", "E_fail_u"} & x.evidence)


def r0_applies(x: Inputs) -> bool:
    """R0 (v0.4): every member evidence item is NOT_FOUND and nothing else points at the cluster
    (no resolved SARIF of either tier, no FAIL-class test evidence)."""
    return x.all_snippets_fail and not (x.strong_tool or x.weak_sarif or fail_class(x))


def _annotate(x: Inputs, out: Outcome) -> Outcome:
    """R12 / R13 annotations (any status) and the W4 phase annotation; appends fired rules in order."""
    if "E_inc" in x.evidence:
        out.annotations.add("test_inconclusive")                        # R12
    if out.row == 5 and "E_pass" in x.evidence:
        out.annotations.add("conflicting_test_results")                 # R12 (R1 with E_pass)
    if {"test_inconclusive", "conflicting_test_results"} & out.annotations:
        out.rules.append("R12")
    if x.g3_rejected:
        out.annotations.add("g3_rejected")                              # R13
        out.rules.append("R13")
    if x.phase == "W4" and x.prev_status is not None and x.prev_status != "DISPUTED" and out.status == "DISPUTED":
        out.annotations.add("w4_became_disputed")                       # became DISPUTED on W4 re-adjudication; flagged at G3 (§4.2)
    if x.later_member_overlap:
        out.annotations.add("refute_by_later_member_family")           # R15 (r11): the vote stays valid; the overlap is shown, not hidden
        out.rules.append("R15")
    return out


CONFIRMED = ("CONFIRMED_EXECUTABLE", "CONFIRMED_CORROBORATED")


def adjudicate(x: Inputs) -> Outcome:
    """Ordered rules; every rule that fires is listed in Outcome.rules in firing order."""
    out = _floor(x, _decide(x))
    out.sources = independent_sources(x)
    return _annotate(x, out)


def _floor(x: Inputs, out: Outcome) -> Outcome:
    """R16 (r12, 05-v0.11; docs/02 §1.6): a carried-in cluster whose source was confirmed stays confirmed until a regression
    test shows it fixed (R14). A carried cluster has no members of its own, so the rules above land it on UNCORROBORATED
    or LIKELY when its regression test FAILs (E_fail_u), errors, or was never run; r11 let that downgrade a confirmed
    defect and even put it on the report-only list. A FIXED / contradicted fix (rows 14 / 15), a DISPUTED cluster (people
    decide), a G2 rejection and Lane A keep their outcome."""
    if x.carried_status not in CONFIRMED or x.lane_a or x.g2_rejected or out.row in (14, 15) \
            or out.status in CONFIRMED + ("DISPUTED",):
        return out
    out.annotations.add("regression_failed" if fail_class(x) else "fix_unverified")
    return Outcome(x.carried_status, 16, out.rules + ["R16"], None, False, out.annotations, decided=out.decided or out.status)


def _decide(x: Inputs) -> Outcome:
    inf = float("inf")
    t_conf = inf if x.theta_confirm is None else x.theta_confirm
    t_rej = inf if x.theta_reject is None else x.theta_reject
    ev = strongest(x.evidence)
    notes: set[str] = set()

    if x.lane_a:
        if r0_applies(x):
            return Outcome("REJECTED", 1, ["R9"], "UNCORROBORATED", True, notes)
        return Outcome("UNCORROBORATED", 2, ["R9"], "UNCORROBORATED", True, notes)
    if x.g2_rejected:
        if fail_class(x):
            notes.add("post_g2_conflict")
        if ev == "E_proof" and x.proof_overrides_g2:          # v0.6: only a G4-approved, replayed B4 proof
            return Outcome("CONFIRMED_EXECUTABLE", 5, ["R10", "R1"], None, False, notes)
        return Outcome("REJECTED", 3, ["R10"], None, False, notes)
    if x.regression_fixed:                                 # R14 (r11, 05-v0.10): the regression test of a confirmed defect passed
        # r12 (05-v0.11): not while other evidence still says the defect is there; a scanner rule that still fires or a
        # weighted refutation makes the "fix" a dispute for people (row 15), as the same PASS does outside a regression run
        if x.strong_tool or x.weak_sarif or x.weighted_refute:
            notes.add("fix_contradicted")
            return Outcome("DISPUTED", 15, ["R14"], None, False, notes)
        return Outcome("FIXED", 14, ["R14"], None, False, notes)
    if r0_applies(x):
        return Outcome("REJECTED", 4, ["R0"], None, False, notes)
    if ev == "E_proof":
        return Outcome("CONFIRMED_EXECUTABLE", 5, ["R1"], None, False, notes)

    # R2: S, the two tool tiers and the independent sources
    signal = x.strong_tool or x.weak_sarif or "E_fail_u" in x.evidence   # row 7: any tool corroboration or signal
    sources = independent_sources(x)
    sup, ref = x.weighted_support, x.weighted_refute
    if sup and ref:
        status, row, rule = "DISPUTED", 6, "R3"
    elif ref and signal:
        status, row, rule = "DISPUTED", 7, "R4"
    elif ref and x.score <= -t_rej and x.independent_families <= 1:
        # v0.5 (review 2026-10-25 H-4): automatic rejection only for a single-family report; two or more
        # independent families reported it, so a refutation alone is a dispute for G2 (row 9), not a rejection
        status, row, rule = "REJECTED", 8, "R4"
    elif ref:
        status, row, rule = "DISPUTED", 9, "R4"
    elif x.strong_tool:
        status, row, rule = "CONFIRMED_CORROBORATED", 10, "R5"
    elif sup and x.score >= t_conf:
        status, row, rule = "CONFIRMED_CORROBORATED", 11, "R5"
    elif sources >= 2:
        status, row, rule = "LIKELY", 12, "R6"
    else:
        status, row, rule = "UNCORROBORATED", 13, "R7"
    rules = ["R2", rule]
    decided = status
    cap = None
    if x.diversity_degraded and row == 11:                    # row 10 (strong tool) is never capped
        status, cap = "LIKELY", "LIKELY"
        rules.append("R8")
    if "E_pass" in x.evidence:
        if status in ("CONFIRMED_CORROBORATED", "LIKELY") and x.pass_positive:
            status = "DISPUTED"
            rules.append("R11")
        elif status in ("CONFIRMED_CORROBORATED", "LIKELY", "UNCORROBORATED"):
            notes.add("test_not_reproduced")                 # v0.4: no positive control -> annotate only
            rules.append("R11")
    return Outcome(status, row, rules, cap, False, notes, decided=decided)
