"""Timezone-aware datetime handling. Never compare timestamps as strings.

Windows has no system IANA database: install the `tzdata` package (requirements.txt).
"""
from __future__ import annotations

import datetime as dt
import re
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

DAYS = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]
_HHMM = re.compile(r"^([01][0-9]|2[0-3]):([0-5][0-9])$")
_RFC3339 = re.compile(r"^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$")


class TimeError(ValueError):
    pass


def parse_dt(value) -> dt.datetime:
    """Parse an RFC 3339 date-time with an explicit offset; naive times are errors."""
    if not isinstance(value, str) or not _RFC3339.match(value):
        raise TimeError(f"not an RFC 3339 date-time with offset: {value!r}")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("z", "Z").replace("t", "T"))
    except ValueError as exc:  # e.g. 2026-02-30 or 24:00:00: well-formed but not a real instant
        raise TimeError(f"invalid date-time {value!r}: {exc}") from None
    if parsed.tzinfo is None:
        raise TimeError(f"timestamp without timezone: {value!r}")
    return parsed


def sort_key(value):
    """Sort key for timestamps: parsed instants in time order, unparsable values last (by text)."""
    try:
        return (0, parse_dt(value).timestamp(), "")
    except TimeError:
        return (1, 0.0, str(value))


def is_datetime(value) -> bool:
    try:
        parse_dt(value)
        return True
    except TimeError:
        return False


def zone(name: str) -> ZoneInfo:
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise TimeError(f"unknown time zone {name!r} (on Windows: pip install tzdata)") from exc


def hhmm(value: str) -> int:
    m = _HHMM.match(value or "")
    if not m:
        raise TimeError(f"not HH:MM (00:00-23:59): {value!r}")
    return int(m.group(1)) * 60 + int(m.group(2))


def in_window(ts: dt.datetime, window: dict) -> bool:
    """True if `ts` falls in [start, end) of `window` in its own time zone.

    If end <= start the window crosses midnight: it starts on a listed day and ends on
    the following day (e.g. fri 22:00 – sat 02:00 belongs to `fri`).
    """
    local = ts.astimezone(zone(window["tz"]))
    start, end = hhmm(window["start"]), hhmm(window["end"])
    minute = local.hour * 60 + local.minute + local.second / 60
    today = DAYS[local.weekday()]
    yesterday = DAYS[(local.weekday() - 1) % 7]
    if start < end:
        return today in window["days"] and start <= minute < end
    return (today in window["days"] and minute >= start) or (yesterday in window["days"] and minute < end)


def valid_window(window) -> bool:
    """A window whose tz, start and end parse (invalid ones are reported once as E-ROE-WINDOW and then ignored)."""
    try:
        zone(window["tz"])
        hhmm(window["start"])
        hhmm(window["end"])
        return isinstance(window.get("days"), list)
    except (TimeError, KeyError, TypeError, AttributeError):
        return False


def in_any_window(ts: dt.datetime, windows: list[dict]) -> bool:
    """D6: invalid windows are skipped (never raise), so one bad window does not abort other checks."""
    return any(in_window(ts, w) for w in windows or [] if valid_window(w))


def window_end(ts: dt.datetime, windows: list[dict]) -> dt.datetime | None:
    """End of the window containing `ts` (used for the G5 timeout), or None. Invalid windows are skipped."""
    for w in windows or []:
        if not valid_window(w) or not in_window(ts, w):
            continue
        tz = zone(w["tz"])
        local = ts.astimezone(tz)
        start, end = hhmm(w["start"]), hhmm(w["end"])
        day = local.date()
        minute = local.hour * 60 + local.minute
        if start >= end and minute >= start:
            day = day + dt.timedelta(days=1)
        return dt.datetime(day.year, day.month, day.day, end // 60, end % 60, tzinfo=tz)
    return None
