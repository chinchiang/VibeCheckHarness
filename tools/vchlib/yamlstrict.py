# SPDX-License-Identifier: Apache-2.0
"""JSON-compatible YAML subset for signed documents (D11, docs/03 §6.1).

PyYAML is a YAML 1.1 parser and silently accepts duplicated keys (which value wins is not
guaranteed by spec), so signed documents are loaded with this stricter loader. A violation means the document (and so
every signature on it) is rejected. Rejected:
  - anchors, aliases, merge keys (`<<`), explicit or custom tags
  - duplicate mapping keys, non-string keys
  - YAML 1.1 implicit typing: yes/no/on/off stay strings, unquoted dates stay strings
    (times must be quoted ISO 8601 strings), 0x/0o/sexagesimal/1_000 numbers stay strings
  - integers beyond +-2^53 (not exactly representable in I-JSON), NaN and Infinity
Scalars resolve as in the YAML 1.2 JSON schema: null, true/false, decimal int, decimal float.
"""
from __future__ import annotations

import math
import re

import yaml

MAX_SAFE_INT = 2 ** 53


class StrictYAMLError(ValueError):
    pass


class _StrictResolver(yaml.resolver.BaseResolver):
    pass


_StrictResolver.add_implicit_resolver(
    "tag:yaml.org,2002:null", re.compile(r"^(?:~|null|Null|NULL|)$"), ["~", "n", "N", ""])
_StrictResolver.add_implicit_resolver(
    "tag:yaml.org,2002:bool", re.compile(r"^(?:true|True|TRUE|false|False|FALSE)$"), list("tTfF"))
_StrictResolver.add_implicit_resolver(
    "tag:yaml.org,2002:int", re.compile(r"^[-+]?(?:0|[1-9][0-9]*)$"), list("-+0123456789"))
_StrictResolver.add_implicit_resolver(
    "tag:yaml.org,2002:float",
    re.compile(r"^[-+]?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][-+]?[0-9]+)?$"), list("-+0123456789"))


class _StrictLoader(yaml.reader.Reader, yaml.scanner.Scanner, yaml.parser.Parser,
                    yaml.composer.Composer, yaml.constructor.SafeConstructor, _StrictResolver):
    def __init__(self, stream):
        yaml.reader.Reader.__init__(self, stream)
        yaml.scanner.Scanner.__init__(self)
        yaml.parser.Parser.__init__(self)
        yaml.composer.Composer.__init__(self)
        yaml.constructor.SafeConstructor.__init__(self)
        _StrictResolver.__init__(self)

    def compose_node(self, parent, index):
        ev = self.peek_event()
        line = ev.start_mark.line + 1
        if isinstance(ev, yaml.AliasEvent):
            raise StrictYAMLError(f"alias *{ev.anchor} not allowed (line {line})")
        if getattr(ev, "anchor", None):
            raise StrictYAMLError(f"anchor &{ev.anchor} not allowed (line {line})")
        tag = getattr(ev, "tag", None)
        if isinstance(ev, yaml.ScalarEvent):
            if tag is not None and ev.implicit == (False, False):
                raise StrictYAMLError(f"explicit tag {tag} not allowed (line {line})")
        elif tag is not None:
            raise StrictYAMLError(f"explicit tag {tag} not allowed (line {line})")
        return super().compose_node(parent, index)

    def construct_mapping(self, node, deep=False):
        seen = set()
        for key_node, _ in node.value:
            if key_node.tag == "tag:yaml.org,2002:merge" or (
                    isinstance(key_node, yaml.ScalarNode) and key_node.value == "<<" and key_node.style is None):
                raise StrictYAMLError(f"merge key not allowed (line {key_node.start_mark.line + 1})")
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str):
                raise StrictYAMLError(f"non-string key {key!r} (line {key_node.start_mark.line + 1})")
            if key in seen:
                raise StrictYAMLError(f"duplicate key {key!r} (line {key_node.start_mark.line + 1})")
            seen.add(key)
        return super().construct_mapping(node, deep=deep)


def _check_numbers(value, path="$"):
    if isinstance(value, bool) or value is None or isinstance(value, str):
        return
    if isinstance(value, int):
        if abs(value) > MAX_SAFE_INT:
            raise StrictYAMLError(f"{path}: integer {value} beyond +-2^53")
    elif isinstance(value, float):
        if not math.isfinite(value):
            raise StrictYAMLError(f"{path}: non-finite number")
    elif isinstance(value, dict):
        for k, v in value.items():
            _check_numbers(v, f"{path}.{k}")
    elif isinstance(value, list):
        for i, v in enumerate(value):
            _check_numbers(v, f"{path}[{i}]")
    else:
        raise StrictYAMLError(f"{path}: unsupported type {type(value).__name__}")


def load(text: str):
    try:
        data = yaml.load(text, Loader=_StrictLoader)  # noqa: S506 - strict SafeConstructor-based loader
    except yaml.YAMLError as exc:
        raise StrictYAMLError(str(exc)) from exc
    _check_numbers(data)
    return data
