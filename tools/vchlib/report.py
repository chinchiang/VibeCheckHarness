# SPDX-License-Identifier: Apache-2.0
"""What every check group shares: the report the checks write to, the per-document guard, the timestamp parser, the
format checkers and the constants more than one group reads.

Split out of checks.py (architecture refactor PR-D0, docs/adr/0003-split-checks.md). The text is moved verbatim; no
rule, error code or message changed. Check groups import from here; this module imports no check group.
"""
from __future__ import annotations

import datetime as dt
import re
import traceback
from dataclasses import dataclass, field

from urllib.parse import urlsplit
from jsonschema import Draft202012Validator, FormatChecker, validators

from . import timeutil
from .context import Ctx

GATE_ROLES = {
    "G0a": {"app_owner", "management"},
    "G0b": {"test_lead", "management", "infrastructure_owner"},
    "G1": {"app_owner"},
    "G2": {"security_reviewer"},
    "G3": {"security_reviewer", "app_owner"},
    "G4": {"security_reviewer"},
    "G5": {"security_reviewer"},
}
ENGAGEMENT_GATES = ("G0a", "G1", "G2")
ROE_GATES = ("G0b", "G3", "G4", "G5")
DETERMINISTIC_ROLES = {"aggregator", "scope_proxy", "executor"}
NON_ADJUDICATING_ROLES = {"reporter"}
LEGAL_GATE = "法務閘門"
M1_REQUIRED_SELFTESTS = {"ST-1", "ST-3", "ST-7"}
# placeholder model IDs: <...>, {...}, or a TBD / TODO / FIXME / 實作時確認 token (case-insensitive)
PLACEHOLDER_ID = re.compile(r"<[^<>]*>|\{[^{}]*\}|(?<![A-Za-z0-9])(?:TBD|TODO|FIXME)(?![A-Za-z0-9])|實作時確認", re.IGNORECASE)
TERMINAL_RUN_STATES = ("COMPLETED", "COMPLETED_WITH_GAPS", "ABORTED", "FAILED")   # D2; SUSPENDED and STOPPED are resumable
FINAL_STATUSES = ("CONFIRMED_EXECUTABLE", "CONFIRMED_CORROBORATED", "LIKELY", "UNCORROBORATED", "DISPUTED", "REJECTED", "FIXED")   # FIXED: r11, 05-v0.10


# ============================================================== report
@dataclass
class Issue:
    level: str      # error | warning
    code: str
    where: str
    msg: str


@dataclass
class Report:
    issues: list[Issue] = field(default_factory=list)
    groups: list[tuple[str, int, int]] = field(default_factory=list)   # (name, checks, errors)
    notes: list[str] = field(default_factory=list)
    _checks: int = 0

    def error(self, code, where, msg):
        self.issues.append(Issue("error", code, where, msg))

    def warn(self, code, where, msg):
        self.issues.append(Issue("warning", code, where, msg))

    def check(self, cond, code, where, msg) -> bool:
        self._checks += 1
        if not cond:
            self.error(code, where, msg)
        return bool(cond)

    @property
    def errors(self):
        return [i for i in self.issues if i.level == "error"]

    @property
    def warnings(self):
        return [i for i in self.issues if i.level == "warning"]

    def codes(self) -> set[str]:
        return {i.code for i in self.errors}


# ============================================================== helpers
def ts(R: Report, value, where, what="timestamp"):
    """Parse an RFC 3339 timestamp; report E-DATETIME and return None when invalid."""
    if value is None:
        return None
    try:
        return timeutil.parse_dt(value)
    except timeutil.TimeError as exc:
        R.error("E-DATETIME", where, f"{what}: {exc}")
        return None


def is_date(value) -> bool:
    if not isinstance(value, str) or not re.match(r"^\d{4}-\d{2}-\d{2}$", value):
        return False
    try:
        dt.date.fromisoformat(value)
        return True
    except ValueError:
        return False


def is_uri(value) -> bool:
    """D3: an absolute URI with a scheme and a host (no whitespace)."""
    if not isinstance(value, str) or not value or any(ch.isspace() for ch in value):
        return False
    try:
        u = urlsplit(value)
        return bool(re.match(r"^[A-Za-z][A-Za-z0-9+.-]*$", u.scheme or "")) and bool(u.hostname)
    except ValueError:
        return False


FORMATS = {"date-time", "date", "uri"}     # every `format` a schema uses must have a checker (E-SCHEMA-FORMAT)
LOCAL_HTTP_HOSTS = ("localhost", "127.0.0.1", "::1")


def format_checker() -> FormatChecker:
    fc = FormatChecker(formats=())
    fc.checks("date-time")(lambda v: not isinstance(v, str) or timeutil.is_datetime(v))
    fc.checks("date")(lambda v: not isinstance(v, str) or is_date(v))
    fc.checks("uri")(lambda v: not isinstance(v, str) or is_uri(v))
    return fc


def schema_formats(node, path="") -> list[tuple[str, str]]:
    """[(json path, format)] of every `format` keyword in a schema."""
    out = []
    if isinstance(node, dict):
        for k, v in node.items():
            if k == "format" and isinstance(v, str):
                out.append((path, v))
            out += schema_formats(v, f"{path}/{k}")
    elif isinstance(node, list):
        for i, v in enumerate(node):
            out += schema_formats(v, f"{path}[{i}]")
    return out


def url_problem(url) -> str | None:
    """D3: ROE URLs must be https://; http:// only for localhost / 127.0.0.1 / [::1] (MVP-1 local targets)."""
    if not is_uri(url):
        return f"{url!r} is not an absolute URI"
    u = urlsplit(url)
    if u.scheme.lower() == "https":
        return None
    if u.scheme.lower() == "http" and (u.hostname or "").lower() in LOCAL_HTTP_HOSTS:
        return None
    return f"{url!r} must be https:// (http:// only for localhost, 127.0.0.1 or [::1])"


def _strict_integer(checker, instance) -> bool:
    """JSON Schema "integer" without the 2020-12 leniency: 3.0 / 3e0 (float) and bools are not integers."""
    return type(instance) is int


# Draft 2020-12 accepts 3.0 as an integer; a signed / hash-chained document must not depend on
# that (3e0 and 3 canonicalise identically but are different literals), so integer = Python int.
StrictValidator = validators.extend(
    Draft202012Validator,
    type_checker=Draft202012Validator.TYPE_CHECKER.redefine("integer", _strict_integer),
)


# v0.5 (BL-17): least-privilege token scopes the publisher may hold (comment on PRs, open / update issues; no code access)
PUBLISH_SCOPES = {"github": frozenset({"metadata:read", "issues:write", "pull_requests:write"})}
# v0.5 (BL-16, docs/08 §11.7): the crawler's baseline skip list; toolkit.yaml may add keywords, never drop these
B1_SKIP_BASELINE = frozenset({"logout", "log-out", "signout", "sign-out", "delete", "remove", "unsubscribe", "approve", "confirm", "reset",
                              "cron", "send", "pay", "toggle", "activate", "publish", "登出", "刪除", "移除", "取消訂閱", "核准", "確認",
                              "重設", "送出", "付款", "發布"})


def retention_max(tk: dict, data_class) -> int | None:
    """Org maximum (= default) content retention in days for a data class (toolkit.yaml retention)."""
    ret = tk.get("retention") or {}
    return ret.get("c_days_after_run_end") if data_class == "C" else ret.get("p_days") if data_class == "P" else None


def roe_windows(c: Ctx):
    return ((c.roe.get("validity") or {}).get("windows")) or []


class doc_guard:
    """D6: guard one document (not a whole group): an unexpected exception becomes one E-INTERNAL for that document
    and the loop continues with the next one."""

    def __init__(self, R: Report, where: str):
        self.R, self.where = R, where

    def __enter__(self):
        return self

    def __exit__(self, et, ev, tb):
        if et is None or not issubclass(et, Exception):
            return False
        last = traceback.extract_tb(tb)[-1] if tb else None
        self.R.error("E-INTERNAL", self.where, f"{et.__name__}: {ev} (at {last.name}:{last.lineno}; this document was skipped)"
                     if last else f"{et.__name__}: {ev}")
        return True


def anchored_seqs(evs) -> int:
    """The seq of the last audit_anchor of a log (0 when none): lines up to it are covered by the chain."""
    return max((i + 1 for i, e in enumerate(evs) if isinstance(e, dict) and e.get("event_type") == "audit_anchor"), default=0)
