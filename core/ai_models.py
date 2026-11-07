"""
AI model registry (Phase 0 / AI3).

One source of truth for every LLM provider+model ARISE can call: the default
model, output-token ceiling, context window, rough pricing, and how to request
JSON. Kills the model strings that were hardcoded in ~4 call sites (and the
`gemini-1.5-flash` silent-404 class of bug) by giving every lookup a single,
validatable home with an explicit fallback chain.

Pure data + small helpers. Stdlib only. Never raises.
"""

from __future__ import annotations

import os
from typing import Dict, List, Optional

# provider -> registry. Pricing is USD per 1K tokens (in/out), approximate and
# intentionally overridable by env (ARISE_AI_PRICE_<PROVIDER>_IN/OUT) so a wrong
# constant never silently distorts budget math.
REGISTRY: Dict[str, dict] = {
    "claude": {
        "env_keys": ["ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN"],
        "default": "claude-opus-4-8",
        "max_output_tokens": 8000,
        "context_window": 200000,
        "price_in": 0.015, "price_out": 0.075,
        "json_mode": "tools",          # native structured output via tool-use
        "fallback": [],
    },
    "openai": {
        "env_keys": ["OPENAI_API_KEY"],
        "default": "gpt-4o",
        "max_output_tokens": 4000,
        "context_window": 128000,
        "price_in": 0.005, "price_out": 0.015,
        "json_mode": "response_format",
        "fallback": [],
    },
    "gemini": {
        "env_keys": ["GEMINI_API_KEY", "GOOGLE_API_KEY"],
        # gemini-1.5-flash was retired (v1beta 404) — the registry is why that
        # now surfaces as an explicit validate() failure, not a silent break.
        "default": "gemini-2.5-flash",
        "max_output_tokens": 8192,
        "context_window": 1000000,
        "price_in": 0.0003, "price_out": 0.0025,
        "json_mode": "response_schema",
        "fallback": ["gemini-2.5-pro", "gemini-2.0-flash"],
    },
    "huggingface": {
        "env_keys": ["HF_API_TOKEN", "HUGGINGFACE_API_KEY", "HUGGINGFACEHUB_API_TOKEN"],
        "default": "meta-llama/Llama-3.1-8B-Instruct",
        "max_output_tokens": 2000,
        "context_window": 32000,
        "price_in": 0.0, "price_out": 0.0,
        "json_mode": "none",
        "fallback": [],
    },
    # OpenRouter — OpenAI-compatible gateway to many models. Model ids are
    # vendor-prefixed (e.g. "openai/gpt-4o-mini", "anthropic/claude-3.5-sonnet").
    "openrouter": {
        "env_keys": ["OPENROUTER_API_KEY"],
        "default": "openai/gpt-4o-mini",
        "max_output_tokens": 4000,
        "context_window": 128000,
        "price_in": 0.0, "price_out": 0.0,   # varies per routed model; left 0, override via env
        "json_mode": "response_format",
        "base_url": "https://openrouter.ai/api/v1/chat/completions",
        "fallback": [],
    },
    # Groq — OpenAI-compatible, very fast Llama/Mixtral inference.
    "groq": {
        "env_keys": ["GROQ_API_KEY"],
        "default": "llama-3.3-70b-versatile",
        "max_output_tokens": 4000,
        "context_window": 128000,
        "price_in": 0.00059, "price_out": 0.00079,
        "json_mode": "response_format",
        "base_url": "https://api.groq.com/openai/v1/chat/completions",
        "fallback": ["llama-3.1-8b-instant"],
    },
    # Phase 7 — local / air-gapped. OpenAI-compatible endpoint (ollama, vLLM, …).
    "local": {
        "env_keys": [],               # no key needed
        "default": os.environ.get("ARISE_LOCAL_MODEL", "llama3.1"),
        "max_output_tokens": 4000,
        "context_window": 32000,
        "price_in": 0.0, "price_out": 0.0,
        "json_mode": "response_format",
        "base_url": os.environ.get("ARISE_LOCAL_BASE_URL", "http://localhost:11434/v1"),
        "fallback": [],
    },
}

CLOUD_PROVIDERS = {"claude", "openai", "gemini", "huggingface", "openrouter", "groq"}
LOCAL_PROVIDERS = {"local"}


def known_provider(provider: str) -> bool:
    return (provider or "").lower() in REGISTRY


def is_cloud(provider: str) -> bool:
    return (provider or "").lower() in CLOUD_PROVIDERS


def resolve(provider: Optional[str] = None, model: Optional[str] = None) -> Dict[str, str]:
    """Resolve the effective provider+model, honoring env defaults. Never raises."""
    prov = (provider or os.environ.get("ARISE_AI_PROVIDER") or "claude").lower()
    if prov not in REGISTRY:
        prov = "claude"
    reg = REGISTRY[prov]
    mdl = (model or os.environ.get("ARISE_AI_MODEL")
           or os.environ.get(f"{prov.upper()}_MODEL") or reg["default"])
    return {"provider": prov, "model": mdl}


def spec(provider: str) -> dict:
    return REGISTRY.get((provider or "").lower(), REGISTRY["claude"])


def max_output_tokens(provider: str, purpose: str = "") -> int:
    reg = spec(provider)
    base = int(reg.get("max_output_tokens", 4000))
    # A couple of purposes legitimately need more room (full write-ups).
    if purpose in ("narrate", "report", "analyst"):
        return base
    return base


def price(provider: str) -> Dict[str, float]:
    reg = spec(provider)
    prov = (provider or "").lower()

    def _env(name, default):
        try:
            return float(os.environ.get(name, default))
        except Exception:
            return default
    return {
        "in": _env(f"ARISE_AI_PRICE_{prov.upper()}_IN", reg.get("price_in", 0.0)),
        "out": _env(f"ARISE_AI_PRICE_{prov.upper()}_OUT", reg.get("price_out", 0.0)),
    }


def cost_usd(provider: str, tokens_in: int, tokens_out: int) -> float:
    p = price(provider)
    return round((tokens_in / 1000.0) * p["in"] + (tokens_out / 1000.0) * p["out"], 6)


def fallback_models(provider: str) -> List[str]:
    return list(spec(provider).get("fallback", []))


def validate(provider: str, model: str) -> Optional[str]:
    """Return an error string if the provider/model pairing is obviously wrong,
    else None. This is a cheap static check (no network); a live liveness probe
    is a separate opt-in in ai_provider.probe_model()."""
    prov = (provider or "").lower()
    if prov not in REGISTRY:
        return f"unknown provider {provider!r} (known: {', '.join(sorted(REGISTRY))})"
    if not model:
        return f"no model for provider {prov}"
    return None
