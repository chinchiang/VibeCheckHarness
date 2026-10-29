# SPDX-License-Identifier: Apache-2.0
"""`python tools/validate_schemas.py [--root DIR] [--quiet] [--real-run] [--variant NAME]` — validate the design bundle."""
from __future__ import annotations

import argparse
import pathlib
import sys

CORE_DEPENDENCIES = ("cryptography", "jsonschema", "referencing", "yaml")   # signatures, schemas, $ref, YAML


def missing_dependencies() -> list[str]:
    """Second external review of r12: the validator needs these to verify anything (signatures, schemas); a missing one
    is named, not shown as a traceback. rfc8785 is optional (only the JCS parity check, W-JCS-REFERENCE-MISSING)."""
    import importlib
    out = []
    for name in CORE_DEPENDENCIES:
        try:
            importlib.import_module(name)
        except ImportError:
            out.append(name)
    return out

SIGNATURE_NOTE = ("signatures: real Ed25519 over RFC 8785 JCS, verified against the key registry; "
                  "the example keys are TEST ONLY fixtures (tests/fixtures/TEST_ONLY_private_keys) "
                  "and prove nothing about real approvals")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--root", default=str(pathlib.Path(__file__).resolve().parents[2]))
    ap.add_argument("--quiet", action="store_true", help="print only issues and the summary")
    ap.add_argument("--real-run", action="store_true",
                    help="pre-flight for a real run: a placeholder model (placeholder: true or a placeholder-looking "
                         "litellm ID) reachable from any agents.yaml agent is E-MODEL-PLACEHOLDER instead of a warning")
    ap.add_argument("--variant", help="validate a variant bundle (docs/examples/variants/<name>, BL-60) instead of the main one")
    args = ap.parse_args(argv)
    missing = missing_dependencies()
    if missing:
        print(f"validate_schemas: missing required package(s): {', '.join(missing)}; "
              "install them with: python -m pip install -r requirements.lock", file=sys.stderr)
        return 2
    from .bundle import load_bundle, load_variant
    from .checks import run_all
    for s in (sys.stdout, sys.stderr):
        try:
            s.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    b = load_variant(pathlib.Path(args.root), args.variant) if args.variant else load_bundle(pathlib.Path(args.root))
    R = run_all(b, real_run=args.real_run)
    print(f"bundle{f' (variant {args.variant})' if args.variant else ''}: {len(b.schemas)} schemas, {len(b.docs)} documents")
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
