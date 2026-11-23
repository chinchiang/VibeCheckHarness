#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Print the mutation lists a change must re-run (2026-11-22 review E10).

CI only checked that the anchors of tests/mutations/*.json still match the source (`--anchors-only`); it never ran a
mutation. A list could be added with tests that catch nothing and CI stayed green. Running all lists on every push
takes hours, so a pull request runs the lists it touched:

  - a list file that was added or changed;
  - a list whose test file (its "tests" field) was added or changed.

A change to a file a list MUTATES (tools/vchlib/checks.py is mutated by almost every list) does not select the list:
`--anchors-only` already fails when such a change moves an anchor, and the weekly workflow runs every list.

    python tools/changed_mutation_lists.py origin/main        # lists touched since the merge base with origin/main
    python tools/changed_mutation_lists.py --all              # every list (the weekly run)
"""
from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
LIST_DIR = "tests/mutations"


def tests_of(list_path: pathlib.Path) -> str | None:
    try:
        tests = json.loads(list_path.read_text(encoding="utf-8")).get("tests")
    except (OSError, ValueError, AttributeError):
        return None
    return tests if isinstance(tests, str) else None


def changed_lists(changed: set[str], lists: dict[str, str | None]) -> list[str]:
    """`lists` maps a list's repo-relative path to its test file. A list is selected when the list itself or its test
    file is in `changed`; a list whose test file cannot be read is selected too (it has to be looked at)."""
    return sorted(p for p, tests in lists.items() if p in changed or tests is None or tests in changed)


def all_lists(root: pathlib.Path = ROOT) -> dict[str, str | None]:
    return {p.relative_to(root).as_posix(): tests_of(p) for p in sorted((root / LIST_DIR).glob("*.json"))}


def git_changed(base: str, root: pathlib.Path = ROOT) -> set[str]:
    out = subprocess.run(["git", "diff", "--name-only", "--diff-filter=ACMR", f"{base}...HEAD"], cwd=root, check=True,
                         capture_output=True, text=True).stdout
    return {ln.strip() for ln in out.splitlines() if ln.strip()}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("base", nargs="?", help="git ref to compare with (merge base ... HEAD)")
    ap.add_argument("--all", action="store_true", help="print every list")
    args = ap.parse_args(argv)
    lists = all_lists()
    if args.all:
        selected = sorted(lists)
    elif args.base:
        selected = changed_lists(git_changed(args.base), lists)
    else:
        ap.error("give a base ref or --all")
    print("\n".join(selected))
    return 0


if __name__ == "__main__":
    sys.exit(main())
