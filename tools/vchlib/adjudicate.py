"""Ordered adjudication rules of docs/05 §4.2 (decision table rows 1-13, R8/R11 modifiers,
R12/R13 annotations). Pure function: the validator recomputes each example verdict and
compares status, deciding rule and annotations.
"""
from __future__ import annotations

from dataclasses import dataclass, field

EVIDENCE_ORDER = ["E_proof", "E_fail_u", "E_pass", "E_inc"]


@dataclass
class Inputs:
    lane_a: bool = False
    g2_rejected: bool = False
    all_snippets_fail: bool = False
    evidence: set[str] = field(default_factory=set)       # classes present among linked results
    weighted_support: bool = False
    weighted_refute: bool = False
    score: float = 0.0                                    # S = sum(w * stance)
    sarif_corroboration: bool = False
    theta_confirm: float | None = None                    # None = +inf (disabled)
    theta_reject: float | None = None
    independent_families: int = 0
    diversity_degraded: bool = False
    g3_rejected: bool = False
    phase: str | None = None                              # caller context: "W3", "W4", "B5", ...
    prev_status: str | None = None                        # status of the superseded verdict (None = first verdict)


@dataclass
class Outcome:
    status: str
    row: int
    rules: list[str]
    status_cap: str | None = None
    advisory: bool = False
    annotations: set[str] = field(default_factory=set)


def strongest(evidence: set[str]) -> str | None:
    for c in EVIDENCE_ORDER:
        if c in evidence:
            return c
    return None


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
    return out


def adjudicate(x: Inputs) -> Outcome:
    """Ordered rules; every rule that fires is listed in Outcome.rules in firing order."""
    return _annotate(x, _decide(x))


def _decide(x: Inputs) -> Outcome:
    inf = float("inf")
    t_conf = inf if x.theta_confirm is None else x.theta_confirm
    t_rej = inf if x.theta_reject is None else x.theta_reject
    ev = strongest(x.evidence)
    notes: set[str] = set()

    if x.lane_a:
        if x.all_snippets_fail:
            return Outcome("REJECTED", 1, ["R9"], "UNCORROBORATED", True, notes)
        return Outcome("UNCORROBORATED", 2, ["R9"], "UNCORROBORATED", True, notes)
    if x.g2_rejected:
        if "E_proof" in x.evidence or "E_fail_u" in x.evidence:
            notes.add("post_g2_conflict")
        return Outcome("REJECTED", 3, ["R10"], None, False, notes)
    if x.all_snippets_fail:
        return Outcome("REJECTED", 4, ["R0"], None, False, notes)
    if ev == "E_proof":
        return Outcome("CONFIRMED_EXECUTABLE", 5, ["R1"], None, False, notes)

    tool = x.sarif_corroboration or "E_fail_u" in x.evidence            # R2 definition
    sup, ref = x.weighted_support, x.weighted_refute
    if sup and ref:
        status, row, rule = "DISPUTED", 6, "R3"
    elif ref and tool:
        status, row, rule = "DISPUTED", 7, "R4"
    elif ref and x.score <= -t_rej:
        status, row, rule = "REJECTED", 8, "R4"
    elif ref:
        status, row, rule = "DISPUTED", 9, "R4"
    elif tool:
        status, row, rule = "CONFIRMED_CORROBORATED", 10, "R5"
    elif sup and x.score >= t_conf:
        status, row, rule = "CONFIRMED_CORROBORATED", 11, "R5"
    elif x.independent_families >= 2:
        status, row, rule = "LIKELY", 12, "R6"
    else:
        status, row, rule = "UNCORROBORATED", 13, "R7"
    rules = ["R2", rule]
    cap = None
    if x.diversity_degraded and row == 11:
        status, cap = "LIKELY", "LIKELY"
        rules.append("R8")
    if "E_pass" in x.evidence:
        if status in ("CONFIRMED_CORROBORATED", "LIKELY"):
            status = "DISPUTED"
            rules.append("R11")
        elif status == "UNCORROBORATED":
            notes.add("test_not_reproduced")
            rules.append("R11")
    return Outcome(status, row, rules, cap, False, notes)
