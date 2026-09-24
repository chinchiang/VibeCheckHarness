"""Load every schema, example instance and configuration file of the design repo.

Layout:
  docs/schemas/*.schema.json                      schemas (JSON Schema 2020-12)
  docs/schemas/examples/<schema>.<name>.example.json   example instances (kind = text before the first '.')
  docs/schemas/examples/<schema>.<name>.example.jsonl  one instance per line (audit log)
  docs/examples/*.yaml                            configuration examples (kind from YAML_KINDS)

All YAML is read with the strict JSON-compatible loader (yamlstrict): signed documents must
be, and the other configuration files have no reason not to be.
"""
from __future__ import annotations

import copy
import json
import pathlib
from dataclasses import dataclass, field
from typing import Any

from . import yamlstrict

YAML_KINDS = {
    "toolkit.yaml": "toolkit-config",
    "key-registry.yaml": "key-registry",
    "tools.yaml": "tool-registry",
    "licenses.yaml": "licenses",
    "engagement.yaml": "engagement",
    "roe.yaml": "roe",
    "agents.yaml": "agent-registry",
    "models.yaml": "model-registry",
    "seed-manifest.yaml": "seed-manifest",
    "crosswalk.yaml": "crosswalk",
    "invariants.yaml": "invariants",
    "calibration.yaml": "calibration",
}
SIGNED_YAML = {"key-registry.yaml", "engagement.yaml", "roe.yaml"}


@dataclass
class Doc:
    path: str                 # repo-relative, forward slashes
    kind: str                 # schema name
    data: Any                 # dict, or list of dicts for .jsonl
    text: str | None = None   # original text (YAML / JSON)
    load_error: str | None = None

    @property
    def name(self) -> str:
        return self.path.rsplit("/", 1)[-1]


@dataclass
class Bundle:
    root: pathlib.Path
    schemas: dict[str, dict] = field(default_factory=dict)
    docs: list[Doc] = field(default_factory=list)
    requirements_txt: str | None = None

    def by_kind(self, kind: str) -> list[Doc]:
        return [d for d in self.docs if d.kind == kind and d.data is not None]

    def one(self, kind: str) -> Doc | None:
        docs = self.by_kind(kind)
        return docs[0] if docs else None

    def data(self, kind: str):
        d = self.one(kind)
        return None if d is None else d.data

    def doc(self, path_suffix: str) -> Doc | None:
        for d in self.docs:
            if d.path.endswith(path_suffix):
                return d
        return None

    def items(self, kind: str) -> list[dict]:
        """All instances of a kind (jsonl files contribute one item per line)."""
        out = []
        for d in self.by_kind(kind):
            out.extend(d.data if isinstance(d.data, list) else [d.data])
        return out

    def clone(self) -> "Bundle":
        return copy.deepcopy(self)


def _rel(root: pathlib.Path, p: pathlib.Path) -> str:
    return p.relative_to(root).as_posix()


def read_jsonl_lines(text: str) -> list[str]:
    """Lines without the terminator; tolerant of CRLF checkouts (the chain hashes LF-free bytes)."""
    return [ln.rstrip("\r") for ln in text.split("\n") if ln.strip() != ""]


def load_bundle(root: pathlib.Path) -> Bundle:
    root = pathlib.Path(root)
    b = Bundle(root=root)
    sdir = root / "docs" / "schemas"
    for p in sorted(sdir.glob("*.schema.json")):
        b.schemas[p.name.removesuffix(".schema.json")] = json.loads(p.read_text(encoding="utf-8"))
    for p in sorted((sdir / "examples").glob("*.example.json")):
        text = p.read_text(encoding="utf-8")
        kind = p.name.split(".")[0]
        try:
            b.docs.append(Doc(_rel(root, p), kind, json.loads(text), text))
        except json.JSONDecodeError as exc:
            b.docs.append(Doc(_rel(root, p), kind, None, text, f"JSON: {exc}"))
    for p in sorted((sdir / "examples").glob("*.example.jsonl")):
        text = p.read_text(encoding="utf-8")
        kind = p.name.split(".")[0]
        try:
            b.docs.append(Doc(_rel(root, p), kind, [json.loads(ln) for ln in read_jsonl_lines(text)], text))
        except json.JSONDecodeError as exc:
            b.docs.append(Doc(_rel(root, p), kind, None, text, f"JSONL: {exc}"))
    cdir = root / "docs" / "examples"
    for p in sorted(cdir.glob("*.yaml")):
        text = p.read_text(encoding="utf-8")
        kind = YAML_KINDS.get(p.name)
        if kind is None:
            b.docs.append(Doc(_rel(root, p), "unknown", None, text, "no schema mapping for this YAML file"))
            continue
        try:
            b.docs.append(Doc(_rel(root, p), kind, yamlstrict.load(text), text))
        except yamlstrict.StrictYAMLError as exc:
            b.docs.append(Doc(_rel(root, p), kind, None, text, f"strict YAML: {exc}"))
    req = root / "requirements.txt"
    if req.exists():
        b.requirements_txt = req.read_text(encoding="utf-8")
    return b


def reload_yaml(doc: Doc, text: str) -> None:
    """Replace a YAML document's text (tests use this to inject e.g. duplicate keys)."""
    doc.text = text
    try:
        doc.data = yamlstrict.load(text)
        doc.load_error = None
    except yamlstrict.StrictYAMLError as exc:
        doc.data = None
        doc.load_error = f"strict YAML: {exc}"
