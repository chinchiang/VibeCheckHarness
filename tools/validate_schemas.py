#!/usr/bin/env python3
"""Validate the VibeCheck Harness schemas, examples and configuration (v0.3).

    python -m pip install -r requirements.txt
    python tools/validate_schemas.py

Thin entry point: the checks live in tools/vchlib (see docs/schemas/README.md).
"""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from vchlib.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
