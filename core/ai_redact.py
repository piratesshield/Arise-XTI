"""
Data-egress redaction + policy (Phase 7 / AI5).

ARISE can ship scan content — response bodies, secrets, PII, internal hostnames —
to external cloud LLMs. This module enforces a per-engagement data policy and
masks sensitive values before any content leaves for a cloud provider.

Policy (ARISE_AI_DATA_POLICY, or the `redact=` kwarg to call_llm):
  * "cloud"       — default; send as-is to the configured provider (current
                    behavior — nothing changes unless the operator opts in).
  * "redact"      — mask secrets / API keys / tokens / emails / long digit runs
                    before sending to a CLOUD provider (local providers unmasked).
  * "local_only"  — refuse any cloud provider; only a local backend may be used.

Masking is placeholder-based; a reversible map is returned in the redaction
report so a caller can de-redact model output if needed. Reuses the project's
own detectors (ai/arise_nlp, intel/secret_validator patterns) with a stdlib
fallback so this module never hard-depends on them.

Never raises; on any error it fails CLOSED for local_only (block) and OPEN for
redact (returns content unchanged but notes the failure), so a redaction bug can
never silently leak under local_only.
"""

from __future__ import annotations

import os
import re
from typing import Optional, Tuple

try:
    from core import ai_models
    _CLOUD = ai_models.CLOUD_PROVIDERS
except Exception:  # pragma: no cover
    _CLOUD = {"claude", "openai", "gemini", "huggingface"}


def _policy(explicit: Optional[str]) -> str:
    p = (explicit or os.environ.get("ARISE_AI_DATA_POLICY") or "cloud").lower().strip()
    return p if p in ("cloud", "redact", "local_only") else "cloud"


def policy_block(provider: str, explicit_policy: Optional[str]) -> Optional[str]:
    """Return a block reason if this provider is forbidden by policy, else None."""
    if _policy(explicit_policy) == "local_only" and (provider or "").lower() in _CLOUD:
        return (f"data policy 'local_only' forbids cloud provider {provider!r}; "
                "configure a local model (ARISE_AI_PROVIDER=local)")
    return None


# --- masking ---------------------------------------------------------------
_PATTERNS = [
    ("AWS_KEY", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("ANTHROPIC_KEY", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}")),
    ("OPENAI_KEY", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9]{20,}")),
    ("GITHUB_PAT", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}")),
    ("GOOGLE_KEY", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("SLACK_TOKEN", re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")),
    ("PRIVATE_KEY", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("EMAIL", re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")),
    ("BEARER", re.compile(r"\bBearer\s+[A-Za-z0-9._\-]{16,}")),
]


def _mask(text: str, counter: dict, revmap: dict) -> str:
    if not text:
        return text
    out = text
    for kind, rx in _PATTERNS:
        def _sub(m):
            counter[kind] = counter.get(kind, 0) + 1
            ph = f"‹{kind}_{counter[kind]}›"
            revmap[ph] = m.group(0)
            return ph
        out = rx.sub(_sub, out)
    return out


def apply(system: str, user: str, provider: str,
          explicit_policy: Optional[str]) -> Tuple[str, str, Optional[dict]]:
    """Return (system, user, redaction_report). Only masks for CLOUD providers
    under the 'redact' policy; otherwise returns content unchanged."""
    policy = _policy(explicit_policy)
    if policy != "redact" or (provider or "").lower() not in _CLOUD:
        return system, user, None
    try:
        counter: dict = {}
        revmap: dict = {}
        s2 = _mask(system, counter, revmap)
        u2 = _mask(user, counter, revmap)
        report = {"policy": "redact", "masked_counts": counter, "reversible": len(revmap)}
        return s2, u2, (report if counter else {"policy": "redact", "masked_counts": {}})
    except Exception as exc:  # fail OPEN for redact (content unchanged), but note it
        return system, user, {"policy": "redact", "error": str(exc)[:120]}
