#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Write the sha256 digests of every pinned requirement into a lock file (docs/09 BL-57, 2026-11-22 review E9).

requirements.lock pinned versions only, so `pip install -r requirements.lock` accepted whatever file an index served
under that version. With `--hash` lines pip refuses a file whose digest is not listed (`--require-hashes` is implied as
soon as one requirement carries a hash), and CI installs with `--require-hashes` explicitly.

For each `name==version` line the tool asks the index's JSON API for the files of that release and lists the digest of
every one of them (wheels of all platforms and the sdist), which is what `pip-compile --generate-hashes` does: the same
lock file then installs on every CI platform. Comment lines are kept.

    python tools/lock_hashes.py requirements.lock requirements-dev.txt     # needs network (pypi.org)
    python tools/lock_hashes.py --check requirements.lock ...              # offline: every pin has at least one hash

The digests are taken from the index at the time the tool runs: they pin what the index served then, they do not prove
the files are benign. Review the diff of a regenerated lock file like any other dependency change.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
import urllib.request

INDEX = "https://pypi.org/pypi/{name}/{version}/json"
PIN_RE = re.compile(r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)==(?P<version>[A-Za-z0-9.!+_-]+)\s*(?:\\\s*)?$")
HASH_RE = re.compile(r"^\s+--hash=sha256:(?P<digest>[0-9a-f]{64})\s*(?:\\\s*)?$")


def parse(text: str) -> list[dict]:
    """The entries of a lock file in order: {"comment": line} or {"name", "version", "hashes": [...]}. Raises ValueError
    on a line that is neither a comment, a blank line, a pin nor a hash of the pin above it."""
    out: list[dict] = []
    for n, line in enumerate(text.splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            out.append({"comment": line})
        elif m := PIN_RE.match(line):
            out.append({"name": m.group("name"), "version": m.group("version"), "hashes": []})
        elif (m := HASH_RE.match(line)) and out and "hashes" in out[-1]:
            out[-1]["hashes"].append(m.group("digest"))
        else:
            raise ValueError(f"line {n}: not a comment, a `name==version` pin or a `--hash=sha256:` line of a pin: {line!r}")
    return out


def render(entries: list[dict]) -> str:
    lines = []
    for e in entries:
        if "comment" in e:
            lines.append(e["comment"])
            continue
        hashes = sorted(set(e["hashes"]))
        lines.append(f"{e['name']}=={e['version']}" + (" \\" if hashes else ""))
        lines += [f"    --hash=sha256:{h}" + (" \\" if i < len(hashes) - 1 else "") for i, h in enumerate(hashes)]
    return "\n".join(lines) + "\n"


def problems(text: str) -> list[str]:
    """What keeps a lock file from being installed with --require-hashes: an unparsable line, or a pin without a hash."""
    try:
        entries = parse(text)
    except ValueError as exc:
        return [str(exc)]
    pins = [e for e in entries if "name" in e]
    out = [f"{e['name']}=={e['version']}: no --hash line" for e in pins if not e["hashes"]]
    return out if pins else ["no pinned requirement"]


def fetch(name: str, version: str) -> list[str]:
    with urllib.request.urlopen(INDEX.format(name=name, version=version), timeout=60) as r:    # noqa: S310 (fixed https URL)
        files = json.load(r)["urls"]
    return sorted({f["digests"]["sha256"] for f in files})


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("files", nargs="+", type=pathlib.Path)
    ap.add_argument("--check", action="store_true", help="offline: exit 1 unless every pin has a hash")
    args = ap.parse_args(argv)
    rc = 0
    for path in args.files:
        text = path.read_text(encoding="utf-8")
        if args.check:
            for p in problems(text):
                print(f"{path}: {p}", file=sys.stderr)
                rc = 1
            continue
        entries = parse(text)
        for e in entries:
            if "name" in e:
                e["hashes"] = fetch(e["name"], e["version"])
                if not e["hashes"]:
                    print(f"{path}: {e['name']}=={e['version']}: the index lists no file", file=sys.stderr)
                    rc = 1
        path.write_text(render(entries), encoding="utf-8", newline="\n")
        print(f"{path}: {sum(1 for e in entries if 'name' in e)} pin(s), {sum(len(e.get('hashes', [])) for e in entries)} digest(s)")
    return rc


if __name__ == "__main__":
    sys.exit(main())
