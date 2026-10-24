#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Compare safety.SHARED_PLATFORM_SUFFIXES with the Public Suffix List (opt-in, not run in CI).

docs/08 §11.9: the implementation takes the private section of the PSL as the source of shared-platform
domains; the validator keeps a hand-written minimum (vchlib/safety.py). This tool keeps the two honest:

  - every hand-written suffix must be a rule of the PSL private section, or a parent of one
    (`*.x` / `sub.x` count for `x`), unless it is listed in safety.PSL_EXCEPTIONS with a reason;
  - PSL_EXCEPTIONS entries that the PSL now covers are reported as stale.

    python tools/check_platform_suffixes.py                      # download the PSL (needs network)
    python tools/check_platform_suffixes.py --psl FILE           # use a local copy
    python tools/check_platform_suffixes.py --psl FILE --check   # exit 1 on any finding

Only the standard library is used; urllib honours HTTP(S)_PROXY. The PSL is not committed.
"""
import argparse
import pathlib
import sys
import urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from vchlib import safety  # noqa: E402

PSL_URL = "https://publicsuffix.org/list/public_suffix_list.dat"


def private_rules(text: str) -> tuple[set[str], str]:
    """Rules of the PSL private section (wildcard / exception markers stripped) and the VERSION line."""
    rules, version, inside = set(), "?", False
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("// VERSION:"):
            version = line.split(":", 1)[1].strip()
        if "===BEGIN PRIVATE DOMAINS===" in line:
            inside = True
        elif "===END PRIVATE DOMAINS===" in line:
            inside = False
        elif inside and line and not line.startswith("//"):
            rules.add(line.lstrip("!").removeprefix("*.").lower())
    return rules, version


def covered(suffix: str, rules: set[str]) -> bool:
    return suffix in rules or any(r.endswith("." + suffix) for r in rules)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--psl", type=pathlib.Path, help="local public_suffix_list.dat (default: download)")
    ap.add_argument("--check", action="store_true", help="exit 1 when any finding is reported")
    a = ap.parse_args()
    if a.psl:
        text = a.psl.read_text(encoding="utf-8")
    else:
        with urllib.request.urlopen(PSL_URL, timeout=30) as r:
            text = r.read().decode("utf-8")
    rules, version = private_rules(text)
    findings = []
    for suffix in sorted(safety.SHARED_PLATFORM_SUFFIXES):
        ok = covered(suffix, rules)
        exact = suffix in rules
        if not ok and suffix not in safety.PSL_EXCEPTIONS:
            findings.append(f"{suffix}: not in the PSL private section (add it to PSL_EXCEPTIONS with a reason, or remove it)")
        elif ok and not exact and suffix not in safety.PSL_EXCEPTIONS:
            findings.append(f"{suffix}: the PSL lists only sub-domains of it (add it to PSL_EXCEPTIONS with a reason)")
        elif exact and suffix in safety.PSL_EXCEPTIONS:
            findings.append(f"{suffix}: the PSL now lists it; remove the stale PSL_EXCEPTIONS entry")
    print(f"PSL version {version}: {len(rules)} private rules, {len(safety.SHARED_PLATFORM_SUFFIXES)} hand-written suffixes, "
          f"{len(safety.PSL_EXCEPTIONS)} exception(s)")
    for f in findings:
        print("  " + f)
    print(f"{len(findings)} finding(s)")
    return 1 if findings and a.check else 0


if __name__ == "__main__":
    sys.exit(main())
