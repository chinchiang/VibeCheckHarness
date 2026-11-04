# SPDX-License-Identifier: Apache-2.0
"""Shared read-only lookups over one bundle (`Ctx`), moved out of checks.py so that modules the checks depend on can
take a `Ctx` without importing checks (architecture refactor PR-A, no behaviour change)."""
from __future__ import annotations

import re

from . import derive
from .bundle import Bundle


REQUIRED_AUTOMATION = {"run-controller", "scheduler", "ci-bot"}


class Ctx:
    """Shared lookups for the checks."""

    def __init__(self, b: Bundle, real_run: bool = False):
        self.b = b
        self.real_run = real_run      # --real-run: placeholder models reachable from agents are errors
        self.ix = derive.Index(b)
        self.toolkit = b.data("toolkit-config") or {}
        self.registry = b.data("key-registry") or {}
        self.engagement = b.data("engagement") or {}
        self.roe = b.data("roe") or {}
        self.tools = b.data("tool-registry") or {}
        self.licenses = b.data("licenses") or {}
        self.models = b.data("model-registry") or {}
        self.agents = b.data("agent-registry") or {}
        self.manifest = b.data("seed-manifest") or {}
        self.invariants = b.data("invariants") or {}
        self.calibration = b.data("calibration") or {}
        self.crosswalk = b.data("crosswalk") or {}
        self.entries = [e for e in self.registry.get("entries", []) if isinstance(e, dict)]
        self.by_fp = {e.get("fingerprint"): e for e in self.entries}
        # v0.5 (review 2026-10-25 T-4): a z3_executor key is a service identity, not a person: it can countersign
        # anchors but can never be an initiator, approver, human audit actor or any other person reference
        self.services = {e.get("person_id") for e in self.entries if "z3_executor" in (e.get("roles") or [])}
        self.persons = {e.get("person_id") for e in self.entries} - self.services
        self.automation = set(self.toolkit.get("automation_accounts", [])) | REQUIRED_AUTOMATION
        # v0.5 (review 2026-10-25 V-5): the first document wins, like Index.first; duplicates are E-ID-DUP
        self.runs = {}
        for d in self.ix.docs("run"):
            self.runs.setdefault(d.data.get("run_id"), d.data)
        # run_id -> audit Doc whose text the strict loader rejected (data None)
        self.broken_audit = {}
        for d in b.docs:
            if d.kind == "audit-event" and d.load_error:
                m = re.search(r'"run_id"\s*:\s*"([^"]+)"', d.text or "") or re.match(r"audit-event\.(.+?)\.example\.jsonl$", d.name)
                if m:
                    self.broken_audit.setdefault(m.group(1), d)
        self.broken_audit_runs = set(self.broken_audit)

    def roles_of(self, person) -> set[str]:
        return {r for e in self.entries if e.get("person_id") == person for r in e.get("roles", [])}

    def docs(self, kind):
        return self.ix.docs(kind)

    def record(self, rid):
        d = self.ix.first("gate-record", gate_record_id=rid)
        return d.data if d else None

    def model(self, key):
        m = self.models.get(key)
        return m if isinstance(m, dict) else None


__all__ = ["Ctx", "REQUIRED_AUTOMATION"]
