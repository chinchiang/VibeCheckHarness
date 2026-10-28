#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Mutation check for the regression-test rule in CONTRIBUTING.md (v0.7, review r8 M8; hardened in review r11).

A mutation list (tests/mutations/*.json) names, for each fix, the source text of the check, the text that puts the
old behaviour back, and the pytest `-k` expression of the test(s) that must then fail:

    {"tests": "tests/test_x.py",
     "mutations": [{"name": "...", "file": "tools/vchlib/checks.py", "old": "...", "new": "...", "k": "test_name"}]}

The script copies the tracked files of the repository into a scratch directory and, for every distinct (tests, k)
pair, first runs the selected tests on the UNMUTATED copy: they must select at least one test and all of them must pass
(otherwise every mutation using that pair is a VERIFY error: a test that already fails, a `-k` that selects nothing or a
collection error would otherwise be credited as a catch). It then applies one mutation at a time, runs the same tests and
reports

    CAUGHT   the tests ran and at least one ASSERTION failed, with no collection or setup error (exit status 1),
    MISSED   they still pass (the test does not cover the check),
    VERIFY   anything else: zero selected tests, a usage or internal error, a collection error, an import error caused
             by the mutation, a baseline that does not pass,
    SKIP     the anchor text is no longer in the file (the list is stale).

The repository itself is never modified. Exit status 1 when anything is missed, skipped or needs verification.

    python tools/mutation_check.py tests/mutations/r8_validator.json [more lists...]
    python tools/mutation_check.py --anchors-only tests/mutations/*.json      # fast: only check the anchors still match
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

ROOT = pathlib.Path(__file__).resolve().parents[1]


def tracked_files(root: pathlib.Path = ROOT) -> list[str]:
    out = subprocess.run(["git", "ls-files"], cwd=root, capture_output=True, text=True, check=True).stdout
    return [ln for ln in out.splitlines() if ln]


def copy_repo(dst: pathlib.Path, root: pathlib.Path = ROOT) -> None:
    for rel in tracked_files(root):
        src = root / rel
        if src.is_file():
            (dst / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst / rel)


def anchor_problems(lists: list[dict], root: pathlib.Path = ROOT) -> list[str]:
    problems = []
    for spec in lists:
        for m in spec["mutations"]:
            text = (root / m["file"]).read_text(encoding="utf-8")
            n = text.count(m["old"])
            if n != 1:
                problems.append(f"{spec['_name']}: {m['name']}: anchor found {n} times in {m['file']}")
    return problems


class Run:
    """One pytest run: its exit status and the junit counts (a plain class: tests load this file by path, without
    registering the module, which `@dataclass` under postponed annotations cannot handle)."""

    def __init__(self, code: int, tests: int = 0, failures: int = 0, errors: int = 0, skipped: int = 0):
        self.code = code              # pytest's exit status
        self.tests = tests            # test cases that ran (junit)
        self.failures = failures      # assertion failures
        self.errors = errors          # collection, import and setup errors
        self.skipped = skipped

    @property
    def passed(self) -> int:
        return self.tests - self.failures - self.errors - self.skipped

    def describe(self) -> str:
        return f"exit {self.code}, {self.tests} ran, {self.failures} failed, {self.errors} errors, {self.skipped} skipped"


def run_tests(repo: pathlib.Path, tests: str, k: str) -> Run:
    """Run the selected tests in `repo`; the result comes from pytest's junit report, not from its text output.
    `-o addopts=` keeps a project's own options (such as `-q`) from changing what is reported."""
    # no .pyc files: a mutation of the same size written within the same second would otherwise load the cached original
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    with tempfile.TemporaryDirectory(prefix="vch-junit-") as tmp:
        xml = pathlib.Path(tmp) / "r.xml"
        r = subprocess.run([sys.executable, "-m", "pytest", "-x", "-o", "addopts=", "-p", "no:cacheprovider",
                            f"--junitxml={xml}", tests, "-k", k], cwd=repo, capture_output=True, text=True, env=env)
        if not xml.is_file():
            return Run(r.returncode)
        try:
            suites = ET.parse(xml).getroot()
            suites = [suites] if suites.tag == "testsuite" else list(suites)
            return Run(r.returncode, *(sum(int(s.get(a, 0)) for s in suites) for a in ("tests", "failures", "errors", "skipped")))
        except (ET.ParseError, ValueError):
            return Run(r.returncode)


def baseline_problem(run: Run) -> str | None:
    """Why the selected tests are not a valid baseline on the unmutated source, or None."""
    if run.code == 0 and run.passed >= 1 and run.failures == 0 and run.errors == 0:
        return None
    if run.tests == 0:
        return f"selects no test ({run.describe()})"
    return f"do not all pass on the unmutated source ({run.describe()})"


def classify(run: Run) -> tuple[str, str]:
    """(CAUGHT | MISSED | VERIFY, detail) for a run on the mutated source."""
    if run.code == 0:
        return "MISSED", run.describe()
    if run.code == 1 and run.failures >= 1 and run.errors == 0:
        return "CAUGHT", run.describe()
    return "VERIFY", f"not an assertion failure ({run.describe()})"


def evaluate(lists: list[dict], root: pathlib.Path = ROOT) -> tuple[list[str], int]:
    """Run every mutation of `lists`; returns (report lines, number of lists entries that are not CAUGHT)."""
    lines, bad = [], 0
    problems = anchor_problems(lists, root)
    lines += [f"[SKIP  ] {p}" for p in problems]
    bad += len(problems)
    baselines: dict[tuple[str, str], str | None] = {}
    with tempfile.TemporaryDirectory(prefix="vch-mut-") as tmp:
        repo = pathlib.Path(tmp)
        copy_repo(repo, root)
        for spec in lists:
            for m in spec["mutations"]:
                path = repo / m["file"]
                src = path.read_text(encoding="utf-8")
                if src.count(m["old"]) != 1:
                    continue                                   # reported above
                key = (spec["tests"], m["k"])
                if key not in baselines:
                    baselines[key] = baseline_problem(run_tests(repo, *key))
                if baselines[key]:
                    lines.append(f"[VERIFY] {spec['_name']}: {m['name']}: the tests for -k {m['k']!r} {baselines[key]}")
                    bad += 1
                    continue
                path.write_text(src.replace(m["old"], m["new"]), encoding="utf-8")
                try:
                    status, detail = classify(run_tests(repo, *key))
                finally:
                    path.write_text(src, encoding="utf-8")
                lines.append(f"[{status:<6}] {spec['_name']}: {m['name']}: {detail}")
                bad += status != "CAUGHT"
    lines.append(f"missed, skipped or to verify: {bad}")
    return lines, bad


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("lists", nargs="+", help="mutation list JSON files")
    ap.add_argument("--anchors-only", action="store_true", help="only verify the anchors still match the source (no tests)")
    args = ap.parse_args(argv)
    lists = []
    for p in args.lists:
        spec = json.loads(pathlib.Path(p).read_text(encoding="utf-8"))
        spec["_name"] = pathlib.Path(p).name
        lists.append(spec)
    if args.anchors_only:
        problems = anchor_problems(lists)
        for p in problems:
            print(f"[SKIP ] {p}")
        print("stale anchors:", len(problems))
        return 1 if problems else 0
    lines, bad = evaluate(lists)
    print("\n".join(lines))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
