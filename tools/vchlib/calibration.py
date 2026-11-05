# SPDX-License-Identifier: Apache-2.0
"""Calibration statistics and policy (docs/05 §4.3, §5.7): the policy constants calibration.yaml must restate, the
high-precision rule bounds (exact Clopper-Pearson on the effective n) and the design effect of clustered corpora.
Moved verbatim out of checks.py so that the verdict derivation can use them without importing checks (architecture
refactor PR-B0, no behaviour change).
"""
from __future__ import annotations

import math

from .context import Ctx


HIGH_PRECISION_MIN_DEFAULT = 0.9


def high_precision_min(c: Ctx) -> float:
    """calibration.yaml result.thresholds.high_precision_min.value (default 0.90; null = disabled: nothing is strong)."""
    th = ((c.calibration.get("result") or {}).get("thresholds") or {}).get("high_precision_min")
    if not isinstance(th, dict):
        return HIGH_PRECISION_MIN_DEFAULT
    v = th.get("value")
    if v is None:
        return float("inf")
    return v if isinstance(v, (int, float)) and not isinstance(v, bool) else HIGH_PRECISION_MIN_DEFAULT


HIGH_PRECISION_MIN_N, HOLDOUT_MIN_N, HOLDOUT_MARGIN = 40, 10, 0.05


def _betacf(a: float, b: float, x: float) -> float:
    """Continued fraction of the regularized incomplete beta function (modified Lentz)."""
    tiny = 1e-300
    qab, qap, qam = a + b, a + 1, a - 1
    c, d = 1.0, 1 - qab * x / qap
    d = 1 / (d if abs(d) > tiny else tiny)
    h = d
    for m in range(1, 300):
        m2 = 2 * m
        aa = m * (b - m) * x / ((qam + m2) * (a + m2))
        d = 1 + aa * d
        d = 1 / (d if abs(d) > tiny else tiny)
        c = 1 + aa / (c if abs(c) > tiny else tiny)
        h *= d * c
        aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2))
        d = 1 + aa * d
        d = 1 / (d if abs(d) > tiny else tiny)
        c = 1 + aa / (c if abs(c) > tiny else tiny)
        delta = d * c
        h *= delta
        if abs(delta - 1) < 1e-14:
            break
    return h


def betainc(a: float, b: float, x: float) -> float:
    """Regularized incomplete beta I_x(a, b), no SciPy. For integers it is the binomial tail P(X >= a | n = a + b - 1, x)."""
    if x <= 0:
        return 0.0
    if x >= 1:
        return 1.0
    ln_bt = math.lgamma(a + b) - math.lgamma(a) - math.lgamma(b) + a * math.log(x) + b * math.log(1 - x)
    bt = math.exp(ln_bt)
    if x < (a + 1) / (a + b + 2):
        return bt * _betacf(a, b, x) / a
    return 1 - bt * _betacf(b, a, 1 - x) / b


def clopper_pearson_lower(k, n, alpha: float = 0.05) -> float:
    """Lower end of the two-sided (1 - alpha) Clopper-Pearson interval for k successes in n: the p with
    P(X >= k | n, p) = I_p(k, n - k + 1) = alpha / 2 (docs/05 §5.10). Bisection on the regularized incomplete beta, no
    SciPy; k and n may be real (r13, 05-v0.14: the design-effect-adjusted counts of docs/05 §5.7)."""
    if not all(isinstance(x, (int, float)) and not isinstance(x, bool) for x in (k, n)) or n <= 0 or k <= 0:
        return 0.0
    k = min(k, n)
    lo, hi = 0.0, 1.0
    for _ in range(60):
        mid = (lo + hi) / 2
        lo, hi = (mid, hi) if betainc(k, n - k + 1, mid) < alpha / 2 else (lo, mid)
    return lo


def high_precision_problems(h: dict, lim: float, icc=None, corpus_split: dict | None = None) -> list[str]:
    """v0.6 (review r7 3.5): a high_precision_rules row is recomputed from its raw counts, never trusted: n = tp + fp
    >= 40 from at least clustering.min_apps applications (named in `apps`, r14 05-v0.15), precision_lower95 = the
    Clopper-Pearson lower bound of tp / n on the design-effect-adjusted n_eff (r13, 05-v0.14; docs/05 §5.7; r14: the design
    effect of the actual per-application counts) (+-0.0005) and >= high_precision_min, and the holdout split (named in
    `holdout_apps`) has n >= 10, a point precision >= high_precision_min - 0.05 and (r14, B6) a Clopper-Pearson lower bound
    on its n_eff >= high_precision_min - 0.05 (docs/05 §5.10)."""
    tp, fp, n = h.get("tp"), h.get("fp"), h.get("n")
    if not all(isinstance(x, int) for x in (tp, fp, n)):
        return ["tp, fp and n are required counts"]
    out = []
    if not all(type(x) is int and x >= 0 for x in (n, tp, fp, h.get("holdout_n"), h.get("holdout_tp"))) \
            or h.get("holdout_tp") > h.get("holdout_n"):
        return [f"counts tp {tp!r} / fp {fp!r} / n {n!r} / holdout {h.get('holdout_tp')!r}/{h.get('holdout_n')!r} must be non-negative "
                "integers with holdout_tp <= holdout_n (E-CAL-COUNT)"]       # v0.7 (review r8, external review 4)
    for split, key, cnt in (("calibration", "apps", n), ("holdout", "holdout_apps", h.get("holdout_n"))):
        prob = apps_problem(h.get(key), cnt, corpus_split, split)
        if prob:
            return [prob.replace(f"{split}.apps", key)]
    icc = CAL_POLICY["clustering"]["icc"] if icc is None else icc
    apps, h_apps = len(h.get("apps") or {}), len(h.get("holdout_apps") or {})
    if n != tp + fp:
        out.append(f"n {n} != tp + fp {tp + fp}")
    if n < HIGH_PRECISION_MIN_N:
        out.append(f"n {n} < {HIGH_PRECISION_MIN_N}")
    min_apps = CAL_POLICY["clustering"]["min_apps"]
    if apps < min_apps:
        out.append(f"apps {apps} < clustering.min_apps {min_apps}")
    n_eff = effective_n_of(h.get("apps"), icc)
    low = clopper_pearson_lower(tp / (tp + fp) * n_eff if tp + fp else 0, n_eff)
    if abs((h.get("precision_lower95") or 0) - round(low, 4)) > 5e-4:
        out.append(f"precision_lower95 {h.get('precision_lower95')} != recomputed {round(low, 4)} (n_eff {n_eff:.2f} on {apps} applications, icc {icc})")
    if low < lim:
        out.append(f"lower bound {round(low, 4)} < high_precision_min {lim}")
    hn, htp = h.get("holdout_n"), h.get("holdout_tp")
    if not (isinstance(hn, int) and isinstance(htp, int)) or hn < HOLDOUT_MIN_N or htp / hn < lim - HOLDOUT_MARGIN:
        out.append(f"holdout {htp}/{hn} needs n >= {HOLDOUT_MIN_N} and precision >= {round(lim - HOLDOUT_MARGIN, 4)}")
    elif hn:
        h_eff = effective_n_of(h.get("holdout_apps"), icc)
        h_low = clopper_pearson_lower(htp / hn * h_eff, h_eff)
        if h_low < lim - HOLDOUT_MARGIN:
            out.append(f"holdout lower bound {round(h_low, 4)} (n_eff {h_eff:.2f} on {h_apps} applications) < {round(lim - HOLDOUT_MARGIN, 4)}: "
                       "the holdout generalises on its confidence bound, not on the point estimate")
    return out


# r11: the policy constants of docs/05 §4.3 (near-zero rules, smoothing prior) and §5.7 (threshold search limits) live
# here; calibration.yaml must state the same numbers (E-CAL-POLICY). v0.7 read them from the file and checked only
# that the file agreed with itself, so wilson_lower_max: 0 and a lower theta turned LIKELY clusters CONFIRMED.
CAL_POLICY = {
    "smoothing_k": 10,
    "near_zero_rules": {"w_min": 0.2, "wilson_lower_max": 0.5, "n_min": 10, "abstain_rate_max": 0.3},
    "threshold_search": {"confirm_precision_floor": 0.9, "confirm_wilson_lower_floor": 0.8,
                         "reject_true_defect_max": 0.02, "reject_wilson_upper_max": 0.08, "min_clusters": 40},
    "high_precision_min": 0.9,                       # r12: result.thresholds.high_precision_min.value (docs/05 §5.10)
    "independence_unit": "family",                   # second external review of r12 (05-v0.13): docs/05 §4.3
    # third external review (r13, 05-v0.14; docs/05 §5.7): defects of one application are correlated, so a bucket's
    # interval is computed on the design-effect-adjusted n_eff and needs at least min_apps distinct applications.
    # r14 (05-v0.15, internal review B6): icc is a FLOOR; the file must carry max(0.05, result.primary_hypothesis.rho_observed)
    "clustering": {"min_apps": 10, "icc": 0.05},
}


def design_effect(counts, icc) -> float:
    """r14 (05-v0.15, internal review B6; docs/05 §5.7): the design effect of clusters of unequal size, DE = 1 + (sum(m_i^2) / n
    - 1) * icc with m_i the clusters per application (equal sizes give the familiar 1 + (m - 1) * icc). 05-v0.14 used the
    equal-size formula on n / n_apps, so 41 hits with 32 from one application were treated like 4 per application."""
    counts = [m for m in counts if isinstance(m, int) and not isinstance(m, bool) and m > 0]
    n = sum(counts)
    if not n:
        return 1.0
    return 1 + (sum(m * m for m in counts) / n - 1) * icc


def effective_n_of(apps: dict, icc) -> float:
    """n / DE for a split's `apps` map ({app_id: clusters from that application}); 0 for an empty map."""
    counts = list((apps or {}).values())
    n = sum(m for m in counts if isinstance(m, int) and not isinstance(m, bool) and m > 0)
    return n / design_effect(counts, icc) if n else 0.0


def apps_problem(apps, n, corpus_split: dict | None, split: str) -> str | None:
    """r14 (05-v0.15, internal review B5): a split statistic names the applications its n clusters come from, `apps` =
    {app_id: count}; n is their sum, every app_id is a corpus application of that split. 05-v0.14 took `n_apps` as written,
    so `n_apps = n` switched the design effect off and satisfied min_apps by itself."""
    if n == 0:
        return None if not apps else f"{split}.apps must be empty when n = 0, got {sorted(apps)}"
    if not isinstance(apps, dict) or not apps:
        return f"{split}.apps must map each application to its number of clusters (n {n})"
    bad = [k for k, m in apps.items() if type(m) is not int or m < 1]
    if bad:
        return f"{split}.apps {bad} must count at least one cluster each"
    if sum(apps.values()) != n:
        return f"{split}.apps sum to {sum(apps.values())}, not n {n}"
    if corpus_split is not None:
        wrong = sorted(k for k in apps if corpus_split.get(k) != split)
        if wrong:
            return f"{split}.apps {wrong} are not corpus applications of the {split} split"
    return None


def corpus_splits(cfg: dict) -> dict:
    """app_id -> split of config.corpus."""
    return {x.get("app_id"): x.get("split") for x in cfg.get("corpus") or [] if isinstance(x, dict)}


def clustering_icc(cfg: dict) -> float:
    """config.clustering.icc as the file states it (policy_problems / g_calibration check it against the floor and rho_observed)."""
    v = (cfg.get("clustering") or {}).get("icc")
    return v if isinstance(v, (int, float)) and not isinstance(v, bool) else CAL_POLICY["clustering"]["icc"]


__all__ = ["CAL_POLICY", "HIGH_PRECISION_MIN_DEFAULT", "HIGH_PRECISION_MIN_N", "HOLDOUT_MIN_N", "HOLDOUT_MARGIN", "high_precision_min", "high_precision_problems", "betainc", "clopper_pearson_lower", "design_effect", "effective_n_of", "corpus_splits", "clustering_icc", "apps_problem"]
