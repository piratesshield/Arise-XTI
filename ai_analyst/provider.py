"""
AriseAI — LLM brain access.

Now a thin seam over the unified provider layer (core/ai_provider.py, Phase 0):
AriseAI's LLM calls get token/cost accounting, per-run budgets, run logging,
redaction and injection hardening for free, and can request native JSON output
with a schema (Phase 2). The `Brain` / `chat_json` surface the engine already
uses is preserved, and an injected `chat_fn` still wins so the whole engine stays
unit-testable offline (the --selftest path).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Callable, Optional, Tuple

# chat(system, user) -> (text_or_None, error_or_None)
ChatFn = Callable[[str, str], Tuple[Optional[str], Optional[str]]]


@dataclass
class Brain:
    chat: Optional[ChatFn]            # legacy (system,user)->(text,err) closure
    provider: str
    model: str
    error: Optional[str] = None
    scan_dir: Optional[str] = None
    api_key: Optional[str] = None
    injected: bool = False            # True when a chat_fn was supplied (tests)

    @property
    def available(self) -> bool:
        return self.chat is not None

    def call(self, system: str, user: str, *, schema: Optional[dict] = None,
             purpose: str = "ai_analyst") -> Tuple[Optional[str], Optional[Any], Optional[str]]:
        """Return (text, parsed, error). Uses native JSON when a schema is given
        and the real provider layer is in play; falls back to the injected
        chat_fn (+ local JSON extraction) in tests."""
        if self.injected and self.chat is not None:
            text, err = self.chat(system, user)
            return text, (extract_json(text) if (schema and text) else None), err
        try:
            from core import ai_provider
            r = ai_provider.call_llm(system, user, provider=self.provider, model=self.model,
                                     api_key=self.api_key, schema=schema, purpose=purpose,
                                     scan_dir=self.scan_dir)
            return r.text, r.parsed, (None if r.ok else (r.degrade_reason or r.blocked_reason or "AI unavailable"))
        except Exception as exc:
            return None, None, f"provider layer error: {str(exc)[:160]}"


def resolve_brain(provider: Optional[str] = None,
                  model: Optional[str] = None,
                  api_key: Optional[str] = None,
                  chat_fn: Optional[ChatFn] = None,
                  scan_dir: Optional[str] = None) -> Brain:
    """Build the brain. Injected chat_fn wins (offline tests)."""
    try:
        from core import ai_models, ai_provider
        rm = ai_models.resolve(provider, model)
        prov, mdl = rm["provider"], rm["model"]
    except Exception:
        prov, mdl = (provider or "claude"), (model or "")

    if chat_fn is not None:
        return Brain(chat=chat_fn, provider=prov, model=mdl or "injected",
                     scan_dir=scan_dir, injected=True)

    try:
        from core import ai_provider, ai_models
        key = api_key or ai_provider._resolve_key(prov, None)
        if prov in ai_models.CLOUD_PROVIDERS and not key:
            return Brain(chat=None, provider=prov, model=mdl,
                         error=f"no API key for {prov}", scan_dir=scan_dir)

        def _chat(system: str, user: str):
            return ai_provider.chat(system, user, provider=prov, model=model,
                                    api_key=api_key, purpose="ai_analyst", scan_dir=scan_dir)
        return Brain(chat=_chat, provider=prov, model=mdl, scan_dir=scan_dir, api_key=api_key)
    except Exception as exc:
        return Brain(chat=None, provider=prov, model=mdl, error=f"provider unavailable: {exc}",
                     scan_dir=scan_dir)


# ---------------------------------------------------------------------------
# Robust JSON extraction (retained; also used as the test-path fallback)
# ---------------------------------------------------------------------------
_FENCE_RE = re.compile(r"```(?:json)?\s*(.+?)```", re.DOTALL | re.IGNORECASE)


def extract_json(text: str) -> Optional[Any]:
    if not text:
        return None
    candidates = []
    m = _FENCE_RE.search(text)
    if m:
        candidates.append(m.group(1).strip())
    candidates.append(text.strip())
    for opn, cls in (("{", "}"), ("[", "]")):
        i, j = text.find(opn), text.rfind(cls)
        if 0 <= i < j:
            candidates.append(text[i:j + 1])
    for c in candidates:
        try:
            return json.loads(c)
        except Exception:
            continue
    return None


def chat_json(brain: Brain, system: str, user: str,
              schema: Optional[dict] = None, retries: int = 1) -> Tuple[Optional[Any], Optional[str]]:
    """Ask the brain for JSON; returns (parsed, error). Never raises.

    Passes the schema to the provider layer for native JSON when possible (Phase
    2); retries once with an explicit 'JSON only' nudge on a parse miss."""
    if not brain.available:
        return None, brain.error or "no LLM provider available"
    attempt, last_err = 0, None
    while attempt <= retries:
        sys_prompt = system if attempt == 0 else (
            system + "\n\nIMPORTANT: Return ONLY a single valid JSON value. "
            "No prose, no markdown fences, no commentary before or after it.")
        text, parsed, err = brain.call(sys_prompt, user, schema=schema or {"type": "object"})
        if parsed is None and text:
            parsed = extract_json(text)
        if parsed is not None:
            # Phase 2: shape-validate; a malformed/truncated structure retries.
            shape_err = _validate_shape(parsed, schema)
            if shape_err is None:
                return parsed, None
            last_err = shape_err
        else:
            last_err = err or "model returned no parseable JSON"
        attempt += 1
    return None, last_err


def _validate_shape(parsed, schema):
    try:
        from ai_analyst import schemas
        return schemas.validate(parsed, schema)
    except Exception:
        return None


def chat_text(brain: Brain, system: str, user: str) -> Tuple[Optional[str], Optional[str]]:
    if not brain.available:
        return None, brain.error or "no LLM provider available"
    try:
        return brain.chat(system, user)
    except Exception as exc:
        return None, f"chat raised: {str(exc)[:160]}"
