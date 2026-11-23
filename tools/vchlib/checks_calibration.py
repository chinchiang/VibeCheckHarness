# SPDX-License-Identifier: Apache-2.0
"""The calibration check group (docs/05 section 5): calibration.yaml's counts, weights, thresholds, pre-registration,
primary hypothesis and contamination fields, recomputed from what the file itself declares.

Split out of checks.py (architecture refactor PR-D1, docs/adr/0003-split-checks.md). The text is moved verbatim; no
rule, error code or message changed. checks.GROUPS still lists g_calibration in the same place. The statistics that
need no Report (design effect, corpus splits, high-precision rows) stay in calibration.py.

The `type: ignore` comments were added for the move (a module split out of checks must pass mypy, ADR 0003). Each one
sits on a comparison or call whose operands the lines above it already guarded (num(...), a schema-validated field) in
a way mypy cannot follow; no logic was changed to satisfy the checker.
"""
from __future__ import annotations

import copy
import math
import re

from . import derive, timeutil
from .calibration import (CAL_POLICY, HOLDOUT_MIN_N, apps_problem, clustering_icc, corpus_splits, effective_n_of,
                          high_precision_min, high_precision_problems)
from .canonical import content_hash
from .context import Ctx
from .report import Report


# ============================================================== 16 calibration
THETA_MIN = 0.1                                                   # docs/05 §5.7: the threshold grid starts at 0.1


def count_problems(R: Report, where: str, k, n, what: str) -> bool:
    """v0.7 (review r8, external review 4; E-CAL-COUNT): 0 <= k <= n for a (successes, trials) pair of the calibration file.
    v0.6 accepted holdout_tp > holdout_n (the rule stayed high-precision) and crashed wilson_lower on correct > n."""
    ok = type(n) is int and type(k) is int and 0 <= k <= n
    R.check(ok, "E-CAL-COUNT", where, f"{what} {k!r} must be an integer between 0 and n {n!r}")
    return ok


def wilson_lower(correct, n, z=1.959964):
    if n == 0:
        return 0.0
    p = correct / n
    den = 1 + z * z / n
    centre = p + z * z / (2 * n)
    margin = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return (centre - margin) / den


def smoothed_rate(correct, n, k, abar) -> float:
    """docs/05 §4.3 (v0.7): the smoothed rate of one side, (C + k*abar + 1) / (n + k + 2); strictly inside (0, 1)."""
    return (correct + k * abar + 1) / (n + k + 2)


def lr_weights(tpr: float, tnr: float) -> dict:
    """v0.6 (review r7 3.2, docs/05 §4.3): vote weights as log likelihood ratios of the two calibrated rates.
    SUPPORT: ln(TPR / FPR) = ln(a_support / (1 - a_refute)); REFUTE: ln(TNR / FNR) = ln(a_refute / (1 - a_support)).
    v0.4-v0.5 weighted each side by its own accuracy (2a - 1), so a verifier that always supports scored a high
    support weight although its support carries no information (FPR = 1 - TNR is as high as its TPR). Floored at 0.
    v0.7 (review r8): the rates come from smoothed_rate, strictly inside (0, 1), so no ratio degenerates; a rate of 0
    or 1 handed in directly is still treated as no information."""
    def ln_ratio(p, q):
        return max(0.0, math.log(p / q)) if 0 < p and 0 < q else 0.0
    return {"support": ln_ratio(tpr, 1 - tnr), "refute": ln_ratio(tnr, 1 - tpr)}


def effective_counts(side: dict) -> tuple:
    """(correct, n + n_abstain): the rate of one side is P(the model takes the right stance | the case), over every case it
    was asked, so an abstention is a case it did not get right (docs/05 §4.3). r14 (05-v0.15, internal review B8): 05-v0.9
    scored an abstention as half a right answer, so the support rate P(SUPPORT | defect) was no longer a probability and
    the weight no longer a log likelihood ratio: a 27% abstainer kept a higher support weight than its votes earned and
    its refute weight was understated. v0.7 r9 used the answered cases only (abstain_rate_max stays as a hard cap)."""
    na = side.get("n_abstain", 0)
    na = na if type(na) is int and na > 0 else 0
    return side.get("correct", 0), side.get("n", 0) + na


def abstain_rate(side: dict) -> float:
    na, n = side.get("n_abstain", 0), side.get("n", 0)
    return na / (n + na) if isinstance(na, int) and isinstance(n, int) and n + na > 0 else 0.0


def contamination_problems(R: Report, c: Ctx, cfg: dict, res: dict, w: str):
    """v0.7 (review r10, E-CAL-CONTAMINATION; docs/05 §5.4): the contamination fields have consequences. v0.7 r9 recorded
    them and used none: a model that reproduced a canary kept its weights, a sentinel app could sit in the calibration
    split, and the holdout could be read before the preregistration.
    - a model whose canary was reproduced has weight 0 everywhere (derive.Index.weight returns 0 for it);
    - every sentinel app of the corpus is in the holdout split;
    - no holdout_access_log entry is before config.preregistration.registered_at;
    - a flagged variant recall gap on a model with a non-zero weight is a warning (W-CAL-CONTAMINATION)."""
    cont = res.get("contamination") or {}
    weighted = {r.get("model_key") for r in res.get("weights") or [] if isinstance(r, dict)
                and any(((r.get(sk) or {}).get("w") or 0) > 0 for sk in ("support", "refute"))}
    for x in cont.get("canary_results") or []:
        if isinstance(x, dict) and x.get("reproduced") is not False:
            R.check(x.get("model_key") not in weighted, "E-CAL-CONTAMINATION", w,
                    f"{x.get('model_key')} reproduced a corpus canary (reproduced {x.get('reproduced')!r}): its weights must be 0")
    # r11: a model the canary check never covered is not known to be clean: it has no weight until it is checked
    checked = {x.get("model_key") for x in cont.get("canary_results") or [] if isinstance(x, dict)}
    for mk in sorted(weighted - checked):  # type: ignore[type-var]
        R.error("E-CAL-CONTAMINATION", w, f"{mk} has a non-zero weight but no canary_results entry: every weighted model is canary-checked (docs/05 §5.4)")
    for app in cfg.get("corpus") or []:
        if isinstance(app, dict) and app.get("sentinel") is True:
            R.check(app.get("split") == "holdout", "E-CAL-CONTAMINATION", w,
                    f"sentinel app {app.get('app_id')} is in split {app.get('split')!r}: sentinels belong to the holdout")
    def when(v):
        try:
            return timeutil.parse_dt(v)
        except timeutil.TimeError:
            return None
    reg = when((cfg.get("preregistration") or {}).get("registered_at"))
    for h in res.get("holdout_access_log") or []:
        at = when(h.get("at")) if isinstance(h, dict) else None
        R.check(reg is not None and at is not None and at >= reg, "E-CAL-CONTAMINATION", w,
                f"holdout_access_log: {h.get('person_id') if isinstance(h, dict) else h} read the holdout at "
                f"{h.get('at') if isinstance(h, dict) else None}, before the preregistration (registered_at {reg})")
    for x in cont.get("variant_recall_gap") or []:
        if isinstance(x, dict) and x.get("flagged") is True and x.get("model_key") in weighted:
            R.warn("W-CAL-CONTAMINATION", w, f"{x.get('model_key')}: flagged variant recall gap {x.get('gap')} on a model "
                   "with a non-zero weight (possible memorisation; review before relying on its votes)")


def required_holdout_n(delta, psi, rho, alpha=0.05, power=0.8, m=9, attrition=0.05) -> int:
    """docs/05 §5.5 (the sample size of the pre-registered primary hypothesis, step by step): the McNemar normal
    approximation n0 = [z_{1-a/2} sqrt(psi) + z_{1-b} sqrt(psi - delta^2)]^2 / delta^2, times the design effect
    1 + (m - 1) rho of m defects per application, divided by (1 - attrition); each step rounded up. r14 (05-v0.15,
    internal review B3): re-estimated with the observed psi / rho (step "樣本數重估"), the validator checks holdout_n_final
    against it (E-CAL-HYPOTHESIS)."""
    if not all(isinstance(x, (int, float)) and not isinstance(x, bool) for x in (delta, psi, rho)) or delta <= 0 or psi <= delta * delta:
        return 0
    z_a = {0.05: 1.959964, 0.01: 2.575829, 0.1: 1.644854}.get(alpha, 1.959964)
    z_b = {0.8: 0.841621, 0.9: 1.281552}.get(power, 0.841621)
    n0 = math.ceil((z_a * math.sqrt(psi) + z_b * math.sqrt(psi - delta * delta)) ** 2 / (delta * delta) - 1e-9)
    n1 = math.ceil(n0 * (1 + (m - 1) * rho) - 1e-9)
    return math.ceil(n1 / (1 - attrition) - 1e-9)


def hypothesis_problems(cfg: dict, res: dict) -> list[str]:
    """r14 (05-v0.15, internal review B3; docs/05 §5.6): the primary hypothesis fields are derived from the interval, never
    declared: h1 = ci_low > 0; h2 is evaluated only when h1 holds (fixed-sequence procedure) and is null otherwise; the
    outcome follows (multi_family_wins / recall_only / single_best_wins when ci_high < 0 / not_shown); ci_low <= delta <=
    ci_high; holdout_n_final >= the sample size re-estimated with the observed psi / rho (not below the registered
    assumptions); the exploratory interval is ordered and contains its point estimate. The shipped example had ci_low
    0.02 > 0 with h1 false, h2 true under a failed H1, an exploratory interval with ci_low > ci_high and a holdout below
    the re-estimated size, and nothing read these fields."""
    out = []
    num = lambda x: isinstance(x, (int, float)) and not isinstance(x, bool)
    ph, pre = res.get("primary_hypothesis") or {}, cfg.get("preregistration") or {}
    lo, hi, d = ph.get("ci_low"), ph.get("ci_high"), ph.get("delta")
    if not all(num(x) for x in (lo, hi, d)):
        return ["primary_hypothesis: delta, ci_low and ci_high are required numbers"]
    if not lo <= d <= hi:  # type: ignore[operator]
        out.append(f"primary_hypothesis: delta {d} is outside its interval [{lo}, {hi}]")
    # 2026-11-22 review (D9, user decision; docs/05 §5.6): the result is about the comparison that was registered. The
    # primary comparison is the full pipeline against the single best model resampled with the same back end (4 vs 4s);
    # a result that names another comparator answers a question nobody pre-registered
    want = (pre.get("primary_comparison") or {}).get("comparator") if isinstance(pre.get("primary_comparison"), dict) else None
    if ph.get("comparator") != want:
        out.append(f"primary_hypothesis: comparator {ph.get('comparator')!r} is not the registered "
                   f"preregistration.primary_comparison.comparator {want!r}")
    # 2026-11-22 review (B9; docs/05 §5.6 "the holdout is used once"): thresholds retuned after a holdout was unblinded are
    # no longer tested on unseen data. A later calibration version on the same holdout registers how often it was
    # unblinded before; its result is then exploratory, and an exploratory result cannot claim that a strategy won
    prior = pre.get("holdout_prior_unblindings")
    confirmatory = type(prior) is int and prior == 0
    if ph.get("confirmatory") is not confirmatory:
        out.append(f"primary_hypothesis: confirmatory {ph.get('confirmatory')!r} but preregistration.holdout_prior_unblindings "
                   f"{prior!r} gives {confirmatory} (a holdout unblinded before supports only an exploratory result)")
    h1 = lo > 0  # type: ignore[operator]
    if ph.get("h1") is not h1:
        out.append(f"primary_hypothesis: h1 {ph.get('h1')!r} but ci_low {lo} {'>' if h1 else '<='} 0 gives {h1}")
    h2 = ph.get("h2")
    if h1 and not isinstance(h2, bool):
        out.append("primary_hypothesis: h2 must be decided (true / false) when H1 holds")
    if not h1 and h2 is not None:
        out.append(f"primary_hypothesis: h2 {h2!r} but H2 is not evaluated when H1 fails (fixed-sequence procedure): null")
    want = ("multi_family_wins" if h2 else "recall_only") if h1 else ("single_best_wins" if hi < 0 else "not_shown")  # type: ignore[operator]
    if not confirmatory:
        want = "not_shown"                              # B9: nothing is shown on a holdout that was seen before
    if ph.get("outcome") != want:
        out.append(f"primary_hypothesis: outcome {ph.get('outcome')!r} but h1 {h1} / h2 {h2!r} / ci_high {hi} / confirmatory "
                   f"{confirmatory} give {want!r}")
    psi = max(x for x in (pre.get("psi_assumed"), ph.get("psi_observed")) if num(x)) if any(num(x) for x in (pre.get("psi_assumed"), ph.get("psi_observed"))) else None  # type: ignore[type-var]
    rho = max(x for x in (pre.get("rho_assumed"), ph.get("rho_observed")) if num(x)) if any(num(x) for x in (pre.get("rho_assumed"), ph.get("rho_observed"))) else None  # type: ignore[type-var]
    need = required_holdout_n(pre.get("min_effect"), psi, rho, pre.get("alpha", 0.05))
    hn = ph.get("holdout_n_final")
    if not (type(hn) is int and hn >= need):
        out.append(f"primary_hypothesis: holdout_n_final {hn!r} < {need}, the sample size re-estimated with psi {psi} and rho {rho} "
                   f"(docs/05 §5.5: min_effect {pre.get('min_effect')}, m = 9, attrition 5%)")
    ex = res.get("exploratory") or {}
    elo, ehi, ed = ex.get("ci_low"), ex.get("ci_high"), ex.get("recall_diff_vs_arm3")
    if all(num(x) for x in (elo, ehi, ed)) and not elo <= ed <= ehi:  # type: ignore[operator]
        out.append(f"exploratory: recall_diff_vs_arm3 {ed} is outside its interval [{elo}, {ehi}] (ci_low <= estimate <= ci_high)")
    return out


RESAMPLED_ARM_SAMPLES = 3      # docs/05 §5.6: the comparator resamples the single best model three times


def primary_comparison_problems(cfg: dict) -> list[str]:
    """2026-11-22 review (D9, user decision; docs/05 §5.6): the registered primary comparison names two arms of the
    configuration, and its comparator is the single best model (the model of arm 1) resampled RESAMPLED_ARM_SAMPLES times
    with the pipeline's back end. The pipeline keeps a cluster one family reported (UNCORROBORATED, a seed threat), so
    comparing the ">= 2 agree" rule of arms 3 and 2 measured a rule the pipeline does not use, and its result switched
    the default strategy; comparing arm 4 with arm 2 mixed the effect of several families with that of the tools."""
    pc = (cfg.get("preregistration") or {}).get("primary_comparison")
    if not isinstance(pc, dict):
        return ["preregistration.primary_comparison is required (treatment and comparator arms)"]
    arms = {a.get("arm"): a for a in cfg.get("arms") or [] if isinstance(a, dict)}
    out = [f"preregistration.primary_comparison.{k} {pc.get(k)!r} is not an arm of config.arms"
           for k in ("treatment", "comparator") if pc.get(k) not in arms]
    if out:
        return out
    comp, best, treat = arms[pc["comparator"]], arms.get("1") or {}, arms[pc["treatment"]]
    if comp.get("model_keys") != best.get("model_keys"):
        out.append(f"arm {pc['comparator']}: model_keys {comp.get('model_keys')} must be those of arm 1 {best.get('model_keys')} "
                   "(the single best model)")
    if comp.get("n_samples") != RESAMPLED_ARM_SAMPLES:
        out.append(f"arm {pc['comparator']}: n_samples {comp.get('n_samples')!r} must be {RESAMPLED_ARM_SAMPLES}")
    if comp.get("acceptance_rule") != treat.get("acceptance_rule"):
        out.append(f"arm {pc['comparator']}: acceptance_rule {comp.get('acceptance_rule')!r} must equal that of arm "
                   f"{pc['treatment']} {treat.get('acceptance_rule')!r} (the same back end, so only the families differ)")
    if comp.get("exploratory") is not False or treat.get("exploratory") is not False:
        out.append("the arms of the primary comparison are not exploratory")
    return out


def preregistration_problems(cfg: dict, res: dict) -> list[str]:
    """r14 (05-v0.15, internal review B9; docs/05 §5.6): the pre-registration controls have teeth. doc_sha256 is the content
    hash of the registered configuration itself (config with preregistration.doc_sha256 set to null), so the configuration
    the thresholds were searched under cannot change silently after registration; result.frozen_at (when theta, the weights
    and the high-precision list were frozen) is not before registered_at and not after the first holdout access; any
    holdout statistic with n > 0 needs at least one holdout_access_log entry (somebody read the holdout to compute it)."""
    out = []
    pre = cfg.get("preregistration") or {}
    frozen = copy.deepcopy(cfg)
    if isinstance(frozen.get("preregistration"), dict):
        frozen["preregistration"]["doc_sha256"] = None
    want = content_hash(frozen)
    if pre.get("doc_sha256") != want:
        out.append(f"preregistration.doc_sha256 {pre.get('doc_sha256')!r} != {want} (the content hash of config with doc_sha256 null)")

    def when(v):
        try:
            return timeutil.parse_dt(v)
        except timeutil.TimeError:
            return None
    reg, fro = when(pre.get("registered_at")), when(res.get("frozen_at"))
    accesses = [when(h.get("at")) for h in res.get("holdout_access_log") or [] if isinstance(h, dict)]
    accesses = [a for a in accesses if a is not None]
    if fro is None:
        out.append("result.frozen_at is required: when theta, the weights and the high-precision list were frozen")
    else:
        if reg is not None and fro < reg:
            out.append(f"result.frozen_at {res.get('frozen_at')} is before preregistration.registered_at {pre.get('registered_at')}")
        if accesses and fro > min(accesses):
            out.append(f"result.frozen_at {res.get('frozen_at')} is after the first holdout access {min(accesses).isoformat()}: "
                       "theta, the weights and the high-precision list are frozen before the holdout is read")
    ho_n = [((t.get("holdout") or {}).get("n") if isinstance(t, dict) else 0) for name, th in (res.get("thresholds") or {}).items()
            for t in [th] + list(((th or {}).get("by_bucket") or {}).values())]
    ho_n += [h.get("holdout_n") for h in res.get("high_precision_rules") or [] if isinstance(h, dict)]
    if any(type(x) is int and x > 0 for x in ho_n) and not accesses:
        out.append("holdout statistics are reported but holdout_access_log is empty: every holdout read is logged")
    return out


def effective_n(n, n_apps, icc=None) -> float:
    """docs/05 §5.7 (05-v0.14): the design-effect-adjusted sample size of n clusters drawn from n_apps applications of EQUAL
    size with intra-application correlation icc: n_eff = n / (1 + (m - 1) * icc), m = n / n_apps. The validator uses
    effective_n_of (per-application counts, r14); this is the equal-size special case the documentation's examples use."""
    icc = CAL_POLICY["clustering"]["icc"] if icc is None else icc
    if not n or not n_apps:
        return 0.0
    return n / (1 + (n / n_apps - 1) * icc)


def policy_problems(cfg: dict) -> list[str]:
    out = []
    if cfg.get("smoothing_k") != CAL_POLICY["smoothing_k"]:
        out.append(f"smoothing_k {cfg.get('smoothing_k')!r} != {CAL_POLICY['smoothing_k']} (docs/05 §4.3)")
    for block, sec in (("near_zero_rules", "§4.3"), ("threshold_search", "§5.7"), ("clustering", "§5.7")):
        have = cfg.get(block) or {}
        for key, want in CAL_POLICY[block].items():
            if block == "clustering" and key == "icc":
                # r14 (05-v0.15, B6): a floor, not a pin; g_calibration checks it equals max(floor, rho_observed)
                v = have.get("icc")
                if not (isinstance(v, (int, float)) and not isinstance(v, bool) and v >= want):
                    out.append(f"clustering.icc {v!r} is below the floor {want} (docs/05 {sec}: the measured rho replaces it only upward)")
                continue
            if have.get(key) != want:
                out.append(f"{block}.{key} {have.get(key)!r} != {want} (docs/05 {sec})")
    # second external review of r12 (05-v0.13): one family is one observation; a family is split into its base lineages
    # only by M-2 evidence in lineage_split (derive.independence_evidence_ok), never by switching the unit
    ind = cfg.get("independence") if isinstance(cfg.get("independence"), dict) else {}
    if ind.get("unit") != CAL_POLICY["independence_unit"]:  # type: ignore[union-attr]
        out.append(f"independence.unit {ind.get('unit')!r} != {CAL_POLICY['independence_unit']!r} (docs/05 §4.3: a family is "  # type: ignore[union-attr]
                   "split only by M-2 evidence in lineage_split)")
    for i, x in enumerate(ind.get("lineage_split") or []):  # type: ignore[union-attr]
        if not (isinstance(x, dict) and derive.independence_evidence_ok(x)):
            out.append(f"independence.lineage_split[{i}] is not M-2 evidence of independence: kappa_ci_upper must be below "
                       f"{derive.INDEPENDENCE_SPLIT['kappa_ci_upper_max']} on n >= {derive.INDEPENDENCE_SPLIT['n_min']} clusters "
                       "for a pair of two lineages (docs/05 §4.3)")
    return out


def wilson_upper(correct, n, z=1.959964):
    if n == 0:
        return 0.0
    p = correct / n
    den = 1 + z * z / n
    centre = p + z * z / (2 * n)
    margin = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return (centre + margin) / den


def split_problems(label: str, split: str, s: dict, icc=None, corpus_split: dict | None = None) -> list[tuple[str, str]]:
    """r11: a threshold's split statistics are recomputed from the raw counts (tp of n), as the high-precision rules'
    are: precision = tp / n and the Wilson 95% bounds (0 when n = 0). v0.7 took precision and ci_low as written, so a
    threshold's feasibility was checked against numbers the same file declared. recall needs the corpus positives and
    stays declared. r13 (05-v0.14): the bounds use the design-effect-adjusted n_eff. r14 (05-v0.15, B5 / B6): the
    applications are named (`apps`, apps_problem) and the design effect uses their actual counts (design_effect)."""
    out = []
    num = lambda x: isinstance(x, (int, float)) and not isinstance(x, bool)
    tp, n, apps = s.get("tp"), s.get("n"), s.get("apps")
    if not (type(tp) is int and type(n) is int and 0 <= tp <= n):
        return [(label, f"{split}: tp {tp!r} of n {n!r} is not a count")]
    prob = apps_problem(apps, n, corpus_split, split)
    if prob:
        return [(label, prob)]
    icc = CAL_POLICY["clustering"]["icc"] if icc is None else icc
    n_eff = effective_n_of(apps, icc)  # type: ignore[arg-type]
    want = {"precision": tp / n if n else 0.0, "ci_low": wilson_lower(tp / n * n_eff if n else 0, n_eff),
            "ci_high": wilson_upper(tp / n * n_eff if n else 0, n_eff)}
    for k, v in want.items():
        if not (num(s.get(k)) and abs(s[k] - round(v, 4)) <= 5e-4):
            out.append((label, f"{split}.{k} {s.get(k)!r} but recomputed {v:.4f} from tp {tp} of n {n} (n_eff {n_eff:.2f} on "
                               f"{len(apps or {})} applications, icc {icc})"))
    return out


def split_n_apps(s: dict) -> int:
    """The number of applications a split statistic names (len of `apps`)."""
    apps = s.get("apps")
    return len(apps) if isinstance(apps, dict) else 0


# D6 (05-v0.16): how a statistical bound is stated in an annotation reason (p_u, an upper bound, a confidence bound)
BOUND_CLAIM_RE = re.compile(r"p_u|上界|upper\s+bound|信賴", re.IGNORECASE)


def theta_problems(cal: dict, observation=None) -> list[tuple[str, str]]:
    """v0.7 (review r9): the docs/05 §5.7 limits, recomputed from each feasible threshold's split statistics. v0.7 read
    `feasible` and `generalised` as declared, so two booleans on a threshold measured on 5 clusters at precision 0.5 switched
    on the confirm branch. Confirm: n >= min_clusters, precision >= confirm_precision_floor, Wilson lower >=
    confirm_wilson_lower_floor, and generalised only when the holdout precision is within 0.05 of the floor. Reject (the
    statistics describe the rejected clusters and `tp` counts the TRUE DEFECTS among them, as docs/05 §5.7 and the schema
    say, so precision = tp / n is the true-defect share and ci_high its Wilson upper bound; review r11, external): n >=
    min_clusters, precision <= reject_true_defect_max, ci_high <= reject_wilson_upper_max, and generalised only when the
    holdout share is within 0.05. (r11 first read `1 - precision` here, which made the documented example of 60 rejected
    clusters with no true defect infeasible and `tp = n` feasible.) And a bucket's theta_confirm is above every single vote's support weight in
    that bucket, or one vote confirms (docs/05 §4.3: "one vote is not enough").

    2026-11-22 internal review: and the threshold is not above S_max, the largest score the bucket's weights can reach
    (docs/05 §5.7: the search grid ends at S_max). S takes one vote per independent observation (verdict.root_score), so
    S_max is the sum over observations of the bucket's largest weight on that side. `observation` maps a model key to its
    observation (Index.independence_key); without it every model is its own observation, which only raises S_max. The
    example claimed theta_confirm 2.5 feasible with 46 confirmed clusters in a bucket whose weights add up to 2.1607."""
    cfg, res = cal.get("config") or {}, cal.get("result") or {}
    ts = cfg.get("threshold_search") or {}
    out = []
    num = lambda x: isinstance(x, (int, float)) and not isinstance(x, bool)
    icc, splits = clustering_icc(cfg), corpus_splits(cfg)
    for name in ("theta_confirm", "theta_reject"):
        th = (res.get("thresholds") or {}).get(name) or {}
        for label, t in [(name, th)] + [(f"{name}/{b}", x) for b, x in (th.get("by_bucket") or {}).items()]:
            if not isinstance(t, dict):
                continue
            cs, ho = t.get("calibration") or {}, t.get("holdout") or {}
            # r14 (05-v0.15, B5): every stated split names its applications consistently, feasible or not
            for split, st in (("calibration", cs), ("holdout", ho)):
                prob = apps_problem(st.get("apps"), st.get("n") if type(st.get("n")) is int else 0, splits, split)
                if prob:
                    out.append((label, prob))
            if t.get("feasible") is not True:
                continue
            if name in ("theta_confirm", "theta_reject"):
                out += split_problems(label, "calibration", cs, icc, splits) + split_problems(label, "holdout", ho, icc, splits)
            # v0.7 (review r10): a holdout of one cluster says nothing about generalising (the same floor as the
            # high-precision rules' holdout)
            if t.get("generalised") is True and not (num(ho.get("n")) and ho["n"] >= HOLDOUT_MIN_N):
                out.append((label, f"generalised on a holdout of {ho.get('n')} clusters: needs n >= {HOLDOUT_MIN_N}"))
            if not (num(cs.get("n")) and cs["n"] >= ts.get("min_clusters", 0)):
                out.append((label, f"feasible on {cs.get('n')} clusters: the search needs min_clusters {ts.get('min_clusters')}"))
            # r13 (05-v0.14): 40 clusters from three applications are not 40 observations (docs/05 §5.7); r14 (05-v0.15, B5):
            # the applications are the ones the split names, on the holdout too
            min_apps = (cfg.get("clustering") or {}).get("min_apps", CAL_POLICY["clustering"]["min_apps"])
            if split_n_apps(cs) < min_apps:
                out.append((label, f"feasible on {split_n_apps(cs)} applications: the search needs clustering.min_apps {min_apps}"))
            if t.get("generalised") is True and split_n_apps(ho) < min_apps:
                out.append((label, f"generalised on a holdout of {split_n_apps(ho)} applications: needs clustering.min_apps {min_apps}"))
            if name == "theta_confirm":
                floor = ts.get("confirm_precision_floor", 0)
                if not (num(cs.get("precision")) and cs["precision"] >= floor):
                    out.append((label, f"feasible at precision {cs.get('precision')}: below confirm_precision_floor {floor}"))
                if not (num(cs.get("ci_low")) and cs["ci_low"] >= ts.get("confirm_wilson_lower_floor", 0)):
                    out.append((label, f"feasible with Wilson lower {cs.get('ci_low')}: below confirm_wilson_lower_floor "
                                       f"{ts.get('confirm_wilson_lower_floor')}"))
                if t.get("generalised") is True and not (num(ho.get("precision")) and ho["precision"] >= floor - 0.05):
                    out.append((label, f"generalised with holdout precision {ho.get('precision')}: below {floor} - 0.05"))
                # r14 (05-v0.15, B6): the holdout generalises on its confidence bound too, not on the point estimate alone
                if t.get("generalised") is True and not (num(ho.get("ci_low")) and ho["ci_low"] >= ts.get("confirm_wilson_lower_floor", 0)):
                    out.append((label, f"generalised with holdout Wilson lower {ho.get('ci_low')}: below confirm_wilson_lower_floor "
                                       f"{ts.get('confirm_wilson_lower_floor')} (a point estimate on 10 clusters generalises nothing)"))
            else:
                cap = ts.get("reject_true_defect_max", 0)
                if not (num(cs.get("precision")) and cs["precision"] <= cap + 1e-9):
                    out.append((label, f"feasible with true-defect share {cs.get('precision')}: above reject_true_defect_max {cap}"))
                if not (num(cs.get("ci_high")) and cs["ci_high"] <= ts.get("reject_wilson_upper_max", 0) + 1e-9):
                    out.append((label, f"feasible with Wilson upper {cs.get('ci_high')}: above reject_wilson_upper_max "
                                       f"{ts.get('reject_wilson_upper_max')}"))
                if t.get("generalised") is True and not (num(ho.get("precision")) and ho["precision"] <= cap + 0.05 + 1e-9):
                    out.append((label, f"generalised with holdout true-defect share above {cap} + 0.05"))
                if t.get("generalised") is True and not (num(ho.get("ci_high")) and ho["ci_high"] <= ts.get("reject_wilson_upper_max", 0) + 0.05 + 1e-9):
                    out.append((label, f"generalised with holdout Wilson upper {ho.get('ci_high')}: above reject_wilson_upper_max "
                                       f"{ts.get('reject_wilson_upper_max')} + 0.05"))
    # v0.7 (review r10): theta_reject too; row 8 rejects a single-family cluster on S <= -theta_reject, so a theta_reject
    # at or below one refute weight let a single REFUTE vote reject it automatically
    for name, side, verb in (("theta_confirm", "support", "confirms"), ("theta_reject", "refute", "rejects")):
        for b, t in (((res.get("thresholds") or {}).get(name) or {}).get("by_bucket") or {}).items():
            val = t.get("value") if isinstance(t, dict) else None
            if not num(val):
                continue
            top = max((((r.get(side) or {}).get("w") or 0) for r in res.get("weights") or []
                       if isinstance(r, dict) and r.get("cwe_bucket") == b), default=0)
            if num(top) and val <= top:  # type: ignore[operator]
                out.append((f"{name}/{b}", f"value {val} <= {top}, the largest single {side} weight of the bucket: a single vote {verb}"))
            s_max = bucket_score_max(res.get("weights") or [], b, side, observation)
            if val > s_max + 1e-9:  # type: ignore[operator]
                out.append((f"{name}/{b}", f"value {val} > {s_max}, the largest score the bucket's {side} weights can reach "
                                           f"(one vote per independent observation): no set of votes meets the threshold"))
    return out


def bucket_score_max(weights: list, bucket: str, side: str, observation=None) -> float:
    """S_max of a bucket on one side (docs/05 §5.7): each independent observation contributes its largest weight."""
    best: dict = {}
    for r in weights:
        if not (isinstance(r, dict) and r.get("cwe_bucket") == bucket):
            continue
        w = (r.get(side) or {}).get("w") if isinstance(r.get(side), dict) else None
        if not (isinstance(w, (int, float)) and not isinstance(w, bool) and math.isfinite(w)):
            continue
        mk = r.get("model_key")
        key = (observation(mk) if observation else None) or mk
        best[key] = max(best.get(key, 0.0), w)
    return round(sum(best.values()), 4)


def g_calibration(R: Report, c: Ctx):
    cal, w = c.calibration, "calibration.yaml"
    if not cal:
        return
    cfg, res = cal.get("config") or {}, cal.get("result") or {}
    for msg in policy_problems(cfg):
        R.error("E-CAL-POLICY", w, msg)
    # r14 (05-v0.15, internal review B6): the measured intra-application correlation replaces the floor upward; 05-v0.14
    # pinned icc to 0.05, so the file's own rho_observed 0.06 could not be applied (E-CAL-POLICY rejected it)
    rho = (res.get("primary_hypothesis") or {}).get("rho_observed")
    want_icc = max(CAL_POLICY["clustering"]["icc"], rho) if isinstance(rho, (int, float)) and not isinstance(rho, bool) else CAL_POLICY["clustering"]["icc"]
    have_icc = (cfg.get("clustering") or {}).get("icc")
    R.check(not res or have_icc == want_icc, "E-CAL-POLICY", w,
            f"clustering.icc {have_icc!r} != max(floor {CAL_POLICY['clustering']['icc']}, rho_observed {rho!r}) = {want_icc} (docs/05 §5.7)")
    if res:
        for msg in hypothesis_problems(cfg, res):
            R.error("E-CAL-HYPOTHESIS", w, msg)
        for msg in preregistration_problems(cfg, res):
            R.error("E-CAL-PREREG", w, msg)
    # r12: the strong-tool floor is policy too (docs/05 §5.10: "政策下限，不是 θ 搜尋的結果"); a file value of 0.1 with one
    # rule at a Clopper-Pearson lower bound of 0.13 made a weak SARIF hit an R8-immune, non-provisional confirmation
    hp = ((res.get("thresholds") or {}).get("high_precision_min") or {}).get("value")
    R.check(hp is None or hp == CAL_POLICY["high_precision_min"], "E-CAL-POLICY", w,
            f"thresholds.high_precision_min.value {hp!r} != {CAL_POLICY['high_precision_min']} (docs/05 §5.10; null disables strong corroboration)")
    k = cfg.get("smoothing_k", 0)
    nz = cfg.get("near_zero_rules") or {}
    rows = res.get("weights", [])
    keys = {m.get("model_key"): m for m in cfg.get("models", [])}
    for mk, m in keys.items():
        reg = c.model(mk)
        R.check(reg is not None and reg.get("family") == m.get("family") and reg.get("lineage") == m.get("lineage"), "E-CAL-MODEL", w,
                f"config.models {mk}: family/lineage disagree with models.yaml")
    abar = {}
    for mk, side_key in {(r.get("model_key"), sk) for r in rows for sk in ("support", "refute")}:
        # v0.4: the support side (true defects) and the refute side (known non-defects) are computed separately
        mine = [r.get(side_key) or {} for r in rows if r.get("model_key") == mk]
        tn = sum(effective_counts(x)[1] for x in mine)
        abar[(mk, side_key)] = sum(effective_counts(x)[0] for x in mine) / tn if tn else 0
    for row in rows:
        mk = row.get("model_key")
        R.check(mk in keys, "E-CAL-MODEL", f"{w} weights {mk}/{row.get('cwe_bucket')}", "model not in config.models")
        sides = {sk: row.get(sk) or {} for sk in ("support", "refute")}
        # v0.7 (review r8, external review 4): the raw counts are consistent before anything is computed from them
        if not all(count_problems(R, f"{w} weights {mk}/{row.get('cwe_bucket')} {sk}", x.get("correct"), x.get("n"), "correct")
                   for sk, x in sides.items()):
            continue
        # v0.7 (review r8): a = (C + k*abar + 1) / (n + k + 2), a non-degenerate prior. v0.6 smoothed toward the model's own
        # cross-bucket rate, so a model perfect on one side in every bucket had a = 1, ln(a / (1 - a)) divided by zero and
        # lr_weights floored its weight to 0: the most accurate verifier got no say
        a = {sk: smoothed_rate(*effective_counts(x), k, abar[(mk, sk)]) for sk, x in sides.items()}  # type: ignore[call-arg]
        lr = lr_weights(a["support"], a["refute"])
        reasons = {}
        for sk, x in sides.items():
            n = x.get("n", 0)
            reasons[sk] = [r for r, hit in (("w_below_min", lr[sk] < nz.get("w_min", 0)),
                                            ("wilson_lower_le_max", wilson_lower(*effective_counts(x)) <= nz.get("wilson_lower_max", 0)),
                                            ("n_below_min", n < nz.get("n_min", 0)),
                                            # v0.7 (review r9): abstaining on the hard cases kept the accuracy, and the weight, high
                                            ("abstain_rate_gt_max", abstain_rate(x) > nz.get("abstain_rate_max", 1))) if hit]
        both_ok = not any(reasons.values())       # v0.6: each weight needs both rates, so an unreliable side zeroes both
        for sk, x in sides.items():
            where = f"{w} weights {mk}/{row.get('cwe_bucket')}/{sk}"
            near = bool(reasons[sk])
            want_w = round(lr[sk], 4) if both_ok else 0
            R.check(abs(x.get("a", -1) - round(a[sk], 4)) <= 5e-4, "E-CAL-WEIGHT", where, f"a={x.get('a')} but recomputed {a[sk]:.4f}")
            R.check(abs(x.get("w", -1) - want_w) <= 5e-4, "E-CAL-WEIGHT", where,
                    f"w={x.get('w')} but recomputed {want_w} (log likelihood ratio of both sides; 0 when either side is near zero)")
            R.check(x.get("near_zero") is near and sorted(x.get("near_zero_reasons", [])) == sorted(reasons[sk]), "E-CAL-WEIGHT", where,
                    f"near_zero/near_zero_reasons must be {near} {reasons[sk]}")
    contamination_problems(R, c, cfg, res, w)
    for name, th in (res.get("thresholds") or {}).items():
        # v0.6 (review r7 3.5): theta_confirm / theta_reject are searched per CWE bucket; the pooled entry is a summary
        per = [(f"{name}/{b}", t) for b, t in (th.get("by_bucket") or {}).items()]
        if name in ("theta_confirm", "theta_reject"):
            R.check(isinstance(th.get("by_bucket"), dict), "E-CAL-THETA", w, f"{name}: by_bucket is required (one threshold per CWE bucket)")
        else:
            R.check(th.get("by_bucket") is None, "E-CAL-THETA", w, f"{name}: a policy threshold has no by_bucket")
        for label, t in [(name, th)] + per:
            R.check(t.get("value") is not None or t.get("feasible") is False, "E-CAL-THETA", w, f"{label}: value null requires feasible false")
            R.check(t.get("value") is None or t.get("feasible") is True, "E-CAL-THETA", w, f"{label}: a value requires feasible true")
            # v0.7 (review r8): a threshold is a positive finite score (docs/05 §5.7 searches the grid from 0.1); S <= -theta_reject
            # with a negative theta_reject rejected on a single weak refute, theta_confirm 0 confirmed on any support
            val = t.get("value")
            R.check(val is None or (isinstance(val, (int, float)) and not isinstance(val, bool) and math.isfinite(val) and val >= THETA_MIN),
                    "E-CAL-THETA", w, f"{label}: value {val!r} must be a finite number >= {THETA_MIN}")
        for label, t in per:
            R.check(t.get("by_bucket") is None, "E-CAL-THETA", w, f"{label}: a bucket threshold has no by_bucket of its own")
    for label, msg in theta_problems(cal, c.ix.independence_key):
        R.error("E-CAL-THETA", w, f"{label}: {msg}")
    for arm in cfg.get("arms", []):
        R.check(arm.get("exploratory") is (arm.get("arm") == "5"), "E-CAL-ARMS", w, f"arm {arm.get('arm')}: only arm 5 is exploratory")
        R.check(set(arm.get("model_keys", [])) <= set(keys), "E-CAL-ARMS", w, f"arm {arm.get('arm')}: unknown model keys")
    R.check((res.get("exploratory") or {}).get("arm") == "5", "E-CAL-ARMS", w, "result.exploratory.arm must be 5")
    for msg in primary_comparison_problems(cfg):
        R.error("E-CAL-ARMS", w, msg)
    for row in ((res.get("metrics") or {}).get("M-11") or {}).get("by_model", []):
        want = "support_leaning" if row.get("value") is not None and row["value"] < 0.5 else None
        R.check(row.get("flag") == want, "E-CAL-M11", w, f"M-11 {row.get('model_key')}: flag must be {want}")
    R.check(set(res.get("valid_for_model_keys", [])) <= set(keys), "E-CAL-MODEL", w, "valid_for_model_keys not in config.models")
    lim = high_precision_min(c)
    for h in res.get("high_precision_rules") or []:
        if isinstance(h, dict):
            hw = f"{w} high_precision_rules {h.get('adapter')} {h.get('rule_id')} {h.get('cwe_bucket')}"
            if not (count_problems(R, hw, h.get("holdout_tp"), h.get("holdout_n"), "holdout_tp")
                    & count_problems(R, hw, h.get("tp"), h.get("n"), "tp") & count_problems(R, hw, h.get("fp"), h.get("n"), "fp")):
                continue                                       # v0.7 (review r8, external review 4): E-CAL-COUNT, not a bound
            for p in high_precision_problems(h, lim, clustering_icc(cfg), corpus_splits(cfg)):
                R.error("E-CAL-HIGH-PRECISION", w, f"high_precision_rules {h.get('adapter')} {h.get('rule_id')} {h.get('cwe_bucket')}: {p}")
    for x in res.get("annotator_agreement", []):
        R.check(x.get("accepted") is (x.get("kappa", 0) >= (cfg.get("annotation") or {}).get("kappa_min", 0)), "E-CAL-KAPPA", w,
                f"{x.get('batch_id')}: accepted must equal kappa >= kappa_min")
