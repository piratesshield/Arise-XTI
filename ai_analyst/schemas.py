"""
AriseAI — LLM output contracts (Phase 2 / AI2).

Light, dependency-free JSON shape specs for each AI call. Two jobs:
  1. flag to the provider layer that JSON output is wanted (native JSON mode),
  2. validate the parsed structure so a malformed/half-truncated response is
     caught and retried instead of silently flowing downstream.

Intentionally minimal (top-level type + required keys) — not full JSON Schema —
so there is no new dependency and validation can never itself raise.
"""

from __future__ import annotations

from typing import Any, Optional

# Hypothesis list from brain.plan().
PLAN = {"type": "array", "item_any_of": ("vuln_class", "title")}

# Write-up object from brain.narrate().
NARRATE = {"type": "object", "required": ["executive_summary"]}


def validate(parsed: Any, schema: Optional[dict]) -> Optional[str]:
    """Return an error string if `parsed` doesn't match `schema`, else None.
    Never raises."""
    if not schema:
        return None
    try:
        t = schema.get("type")
        if t == "array":
            # Tolerate a wrapper object (e.g. {"hypotheses": [...]}) — the caller
            # unwraps it. Only a scalar/None is a hard failure.
            if isinstance(parsed, dict):
                return None
            if not isinstance(parsed, list):
                return "expected a JSON array"
            keys = schema.get("item_any_of")
            if keys and parsed:
                good = [x for x in parsed if isinstance(x, dict) and any(k in x for k in keys)]
                if not good:
                    return "array items missing required keys"
            return None
        if t == "object":
            if not isinstance(parsed, dict):
                return "expected a JSON object"
            for k in schema.get("required", []):
                if k not in parsed:
                    return f"missing required key: {k}"
            return None
    except Exception:
        return None
    return None
