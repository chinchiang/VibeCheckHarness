"""`python tools/validate_schemas.py [--root DIR] [--quiet]` — validate the design bundle."""
from __future__ import annotations

import argparse
import pathlib
import sys

from .bundle import load_bundle
from .checks import run_all

SIGNATURE_NOTE = ("signatures: real Ed25519 over RFC 8785 JCS, verified against the key registry; "
                  "the example keys are TEST ONLY fixtures (tests/fixtures/TEST_ONLY_private_keys) "
                  "and prove nothing about real approvals")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--root", default=str(pathlib.Path(__file__).resolve().parents[2]))
    ap.add_argument("--quiet", action="store_true", help="print only issues and the summary")
    args = ap.parse_args(argv)
    for s in (sys.stdout, sys.stderr):
        try:
            s.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    b = load_bundle(pathlib.Path(args.root))
    R = run_all(b)
    print(f"bundle: {len(b.schemas)} schemas, {len(b.docs)} documents")
    if not args.quiet:
        for name, n, errs in R.groups:
            print(f"  [{'FAIL' if errs else ' ok '}] {name}: {n} checks" + (f", {errs} error(s)" if errs else ""))
    for i in R.warnings:
        print(f"WARNING {i.code} {i.where}: {i.msg}")
    for i in R.errors:
        print(f"ERROR   {i.code} {i.where}: {i.msg}")
    print(SIGNATURE_NOTE)
    total = sum(n for _, n, _ in R.groups)
    if R.errors:
        print(f"{len(R.errors)} error(s), {len(R.warnings)} warning(s) in {total} checks")
        return 1
    print(f"all checks passed ({total} checks in {len(R.groups)} groups, {len(R.warnings)} warning(s))")
    return 0


if __name__ == "__main__":
    sys.exit(main())
