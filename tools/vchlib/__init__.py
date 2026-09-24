"""VibeCheck Harness design-repo validation library (v0.2).

Modules:
  canonical   RFC 8785 (JCS) canonical JSON for the subset used here [H], content hashes
  crypto      Ed25519 signatures and key fingerprints (via `cryptography`)
  yamlstrict  JSON-compatible YAML loader (no anchors/aliases, no duplicate keys, no tags)
  timeutil    timezone-aware datetime parsing and ROE time windows (crossing midnight)
  safety      docs/04 §5 safety-class algorithm (D13 tool:mode IDs), admissible()
  adjudicate  docs/05 §4.2 ordered rules (decision table + R8/R11 modifiers)
  llm_schema  LLM-facing output schema derivation (docs/03 §8.3)
  bundle      loads every schema, example and configuration file
  checks      semantic checks over a bundle
  cli         `python tools/validate_schemas.py`
"""
