#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Mutation check for the regression-test rule in CONTRIBUTING.md (v0.7, review r8 M8).

A mutation list (tests/mutations/*.json) names, for each fix, the source text of the check, the text that puts the
old behaviour back, and the pytest `-k` expression of the test(s) that must then fail:

    {"tests": "tests/test_x.py",
     "mutations": [{"name": "...", "file": "tools/vchlib/checks.py", "old": "...", "new": "...", "k": "test_name"}]}

The script copies the tracked files of the repository into a scratch directory, applies one mutation at a time,
runs the named tests there and reports CAUGHT (the tests fail, as they should), MISSED (they still pass: the test does
not cover the check) or SKIP (the anchor text is no longer in the file: the list is stale). The repository itself is
never modified. Exit status 1 when anything is missed or skipped.

    python tools/mutation_check.py tests/mutations/r8_validator.json [more lists...]
    python tools/mutation_check.py --anchors-only tests/mutations/*.json      # fast: only check the anchors still match
"""
from __future__ import annotations

import argparse
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]


def tracked_files() -> list[str]:
    out = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True).stdout
    return [ln for ln in out.splitlines() if ln]


def copy_repo(dst: pathlib.Path) -> None:
    for rel in tracked_files():
        src = ROOT / rel
        if src.is_file():
            (dst / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst / rel)


def anchor_problems(lists: list[dict]) -> list[str]:
    problems = []
    for spec in lists:
        for m in spec["mutations"]:
            text = (ROOT / m["file"]).read_text(encoding="utf-8")
            n = text.count(m["old"])
            if n != 1:
                problems.append(f"{spec['_name']}: {m['name']}: anchor found {n} times in {m['file']}")
    return problems


def run_tests(repo: pathlib.Path, tests: str, k: str) -> tuple[int, str]:
    r = subprocess.run([sys.executable, "-m", "pytest", "-q", "-x", "--no-header", "-p", "no:cacheprovider", tests, "-k", k],
                       cwd=repo, capture_output=True, text=True)
    lines = r.stdout.strip().splitlines() or [""]
    return r.returncode, lines[-1]


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
    problems = anchor_problems(lists)
    for p in problems:
        print(f"[SKIP ] {p}")
    if args.anchors_only:
        print("stale anchors:", len(problems))
        return 1 if problems else 0
    bad = len(problems)
    with tempfile.TemporaryDirectory(prefix="vch-mut-") as tmp:
        repo = pathlib.Path(tmp)
        copy_repo(repo)
        for spec in lists:
            for m in spec["mutations"]:
                path = repo / m["file"]
                src = path.read_text(encoding="utf-8")
                if src.count(m["old"]) != 1:
                    continue                                   # reported above
                path.write_text(src.replace(m["old"], m["new"]), encoding="utf-8")
                try:
                    code, last = run_tests(repo, spec["tests"], m["k"])
                finally:
                    path.write_text(src, encoding="utf-8")
                caught = code != 0
                print(f"[{'CAUGHT' if caught else 'MISSED'}] {spec['_name']}: {m['name']}: {last}")
                bad += not caught
    print("missed or skipped:", bad)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
