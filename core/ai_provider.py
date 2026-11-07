"""
Unified LLM provider layer (Phase 0 / AI3 + AI4).

ONE place every AI call in ARISE goes through. Responsibilities:
  * provider fan-out   — claude / openai / gemini / huggingface / local
  * model registry     — via core.ai_models (no more hardcoded model strings)
  * token + cost accounting, per-run USD budget cap (hard stop)
  * timeout + retry + model fallback chain
  * structured logging — one JSONL record per call → <scan>/logs/ai_runlog.jsonl
                         (+ a never-silent degrade signal: AI4)
  * record / replay    — cassette mode for the eval harness (Phase 1), keyless CI
  * hook points        — redact= (Phase 7) and schema= (Phase 2) + an injection
                         preamble (Phase 3), all optional and lazily loaded so
                         this module stands alone.

Legacy call sites (dashboard._run_ai_provider, synth_ai.build_chat_fn,
arise_autonomous._safe_chat, ai_analyst.provider) become thin wrappers over
`chat()` / `call_llm()` and keep their existing signatures.

Fail-safe by contract: call_llm NEVER raises; any failure returns an LLMResult
with ok=False and a degrade_reason.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, Optional, Tuple

from core import ai_models

# ---------------------------------------------------------------------------
# Result
# ---------------------------------------------------------------------------
@dataclass
class LLMResult:
    text: Optional[str] = None
    parsed: Optional[Any] = None           # set when a JSON schema/mode was used
    ok: bool = False
    provider: str = ""
    model: str = ""
    purpose: str = ""
    tokens_in: int = 0
    tokens_out: int = 0
    cost_usd: float = 0.0
    latency_ms: int = 0
    cache_hit: bool = False
    degrade_reason: Optional[str] = None   # why ok=False (AI4: never silent)
    blocked_reason: Optional[str] = None   # policy block (Phase 7 data policy)
    redaction: Optional[dict] = None       # what was masked (Phase 7)

    def as_tuple(self) -> Tuple[Optional[str], Optional[str]]:
        """Legacy (text, err) contract."""
        return (self.text if self.ok else None,
                None if self.ok else (self.degrade_reason or self.blocked_reason or "AI unavailable"))


# ---------------------------------------------------------------------------
# Per-run budget accounting (AI3)
# ---------------------------------------------------------------------------
_LOCK = threading.Lock()
_RUN_SPEND: Dict[str, float] = {}      # run_id -> usd spent


def _run_id(scan_dir: Optional[str]) -> str:
    return os.path.basename(os.path.normpath(scan_dir)) if scan_dir else "_global"


def _budget_left(scan_dir: Optional[str], cap: Optional[float]) -> Optional[float]:
    if cap is None:
        env = os.environ.get("ARISE_AI_MAX_USD")
        cap = float(env) if env else None
    if cap is None:
        return None
    with _LOCK:
        return cap - _RUN_SPEND.get(_run_id(scan_dir), 0.0)


def _spend(scan_dir: Optional[str], usd: float) -> None:
    with _LOCK:
        rid = _run_id(scan_dir)
        _RUN_SPEND[rid] = _RUN_SPEND.get(rid, 0.0) + usd


def run_spend(scan_dir: Optional[str] = None) -> float:
    with _LOCK:
        return _RUN_SPEND.get(_run_id(scan_dir), 0.0)


def reset_run_spend(scan_dir: Optional[str] = None) -> None:
    with _LOCK:
        _RUN_SPEND.pop(_run_id(scan_dir), None)


# ---------------------------------------------------------------------------
# Structured run log (AI4) — the "did AI run / skip / why" signal
# ---------------------------------------------------------------------------
def _runlog_path(scan_dir: Optional[str]) -> str:
    base = scan_dir or os.environ.get("ARISE_SCAN_DIR")
    if base and os.path.isdir(base):
        return os.path.join(base, "logs", "ai_runlog.jsonl")
    # project-root fallback
    root = os.environ.get("ARISE_PROJECT_ROOT") or os.getcwd()
    return os.path.join(root, "logs", "ai_runlog.jsonl")


def _log_call(scan_dir: Optional[str], rec: dict) -> None:
    try:
        p = _runlog_path(scan_dir)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "a") as fh:
            fh.write(json.dumps(rec) + "\n")
    except Exception:
        pass  # logging must never break a call


def run_summary(scan_dir: Optional[str] = None) -> dict:
    """Roll up ai_runlog.jsonl into a one-glance summary for the dashboard."""
    p = _runlog_path(scan_dir)
    calls, cost, degraded = 0, 0.0, []
    by_purpose: Dict[str, int] = {}
    try:
        with open(p) as fh:
            for line in fh:
                try:
                    r = json.loads(line)
                except Exception:
                    continue
                calls += 1
                cost += float(r.get("cost_usd", 0) or 0)
                by_purpose[r.get("purpose", "?")] = by_purpose.get(r.get("purpose", "?"), 0) + 1
                if not r.get("ok"):
                    degraded.append({"purpose": r.get("purpose"), "reason": r.get("degrade_reason")})
    except Exception:
        return {"calls": 0, "cost_usd": 0.0, "degraded": [], "by_purpose": {}}
    return {"calls": calls, "cost_usd": round(cost, 4), "degraded": degraded, "by_purpose": by_purpose}


# ---------------------------------------------------------------------------
# Cassette record / replay (Phase 1) — keyless eval in CI
# ---------------------------------------------------------------------------
def _cassette_key(provider, model, system, user, schema) -> str:
    h = hashlib.sha256()
    h.update(f"{provider}|{model}|{system}|{user}|{json.dumps(schema, sort_keys=True) if schema else ''}".encode())
    return h.hexdigest()[:40]


def _cassette_dir(explicit: Optional[str], env_name: str) -> Optional[str]:
    d = explicit or os.environ.get(env_name)
    return d or None


def _replay_lookup(key: str) -> Optional[dict]:
    d = _cassette_dir(None, "ARISE_AI_REPLAY")
    if not d:
        return None
    p = os.path.join(d, key + ".json")
    try:
        with open(p) as fh:
            return json.load(fh)
    except Exception:
        return None


def _record_store(key: str, payload: dict, record: Optional[str]) -> None:
    d = _cassette_dir(record, "ARISE_AI_RECORD")
    if not d:
        return
    try:
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, key + ".json"), "w") as fh:
            json.dump(payload, fh, indent=2)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Key resolution
# ---------------------------------------------------------------------------
def _resolve_key(provider: str, api_key: Optional[str]) -> Optional[str]:
    if api_key:
        return api_key
    # vault first (if available), then env fallbacks from the registry.
    try:
        from core import arise_secure
        for name in ai_models.spec(provider).get("env_keys", []):
            v = arise_secure.resolve_secret(name)
            if v:
                return v
    except Exception:
        pass
    for name in ai_models.spec(provider).get("env_keys", []):
        v = os.environ.get(name)
        if v:
            return v
    return None


# ---------------------------------------------------------------------------
# Provider bodies — return (text, tokens_in, tokens_out, err)
# ---------------------------------------------------------------------------
def _call_claude(model, key, system, user, max_tokens, timeout):
    try:
        import anthropic
    except ImportError:
        return None, 0, 0, "anthropic package not installed"
    try:
        client = anthropic.Anthropic(api_key=key)
        msg = client.messages.create(
            model=model, max_tokens=max_tokens, system=system,
            messages=[{"role": "user", "content": user}],
        )
        text = "".join(getattr(b, "text", "") for b in msg.content
                       if getattr(b, "type", None) == "text").strip()
        u = getattr(msg, "usage", None)
        ti = getattr(u, "input_tokens", 0) or 0
        to = getattr(u, "output_tokens", 0) or 0
        return (text or None), ti, to, (None if text else "empty response")
    except Exception as exc:
        return None, 0, 0, f"claude call failed: {str(exc)[:180]}"


def _call_openai_compatible(base_url, model, key, system, user, max_tokens, timeout, want_json):
    try:
        import requests
    except Exception:
        return None, 0, 0, "requests not installed"
    try:
        headers = {"Content-Type": "application/json"}
        if key:
            headers["Authorization"] = f"Bearer {key}"
        body = {"model": model, "max_tokens": max_tokens, "temperature": 0.3,
                "messages": [{"role": "system", "content": system},
                             {"role": "user", "content": user}]}
        if want_json:
            body["response_format"] = {"type": "json_object"}
        r = requests.post(base_url, headers=headers, json=body, timeout=timeout)
        if r.status_code // 100 != 2:
            return None, 0, 0, f"http {r.status_code}: {r.text[:120]}"
        j = r.json()
        text = (j["choices"][0]["message"]["content"] or "").strip()
        usage = j.get("usage", {}) or {}
        return (text or None), int(usage.get("prompt_tokens", 0) or 0), \
            int(usage.get("completion_tokens", 0) or 0), (None if text else "empty response")
    except Exception as exc:
        return None, 0, 0, f"openai-compatible call failed: {str(exc)[:180]}"


def _call_gemini(model, key, system, user, max_tokens, timeout, want_json):
    try:
        import requests
    except Exception:
        return None, 0, 0, "requests not installed"
    try:
        u = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={key}"
        gen = {"maxOutputTokens": max_tokens, "temperature": 0.3,
               "thinkingConfig": {"thinkingBudget": 0}}
        if want_json:
            gen["responseMimeType"] = "application/json"
        r = requests.post(u, json={"system_instruction": {"parts": [{"text": system}]},
                                   "contents": [{"role": "user", "parts": [{"text": user}]}],
                                   "generationConfig": gen}, timeout=timeout)
        if r.status_code // 100 != 2:
            return None, 0, 0, f"gemini http {r.status_code}: {r.text[:120]}"
        j = r.json()
        cands = j.get("candidates") or []
        if not cands:
            return None, 0, 0, "gemini returned no content"
        text = "".join(p.get("text", "") for p in cands[0].get("content", {}).get("parts", [])).strip()
        um = j.get("usageMetadata", {}) or {}
        return (text or None), int(um.get("promptTokenCount", 0) or 0), \
            int(um.get("candidatesTokenCount", 0) or 0), (None if text else "empty response")
    except Exception as exc:
        return None, 0, 0, f"gemini call failed: {str(exc)[:180]}"


def _dispatch(provider, model, key, system, user, max_tokens, timeout, want_json):
    prov = provider.lower()
    if prov == "claude":
        return _call_claude(model, key, system, user, max_tokens, timeout)
    if prov in ("openai", "huggingface"):
        base = ("https://api.openai.com/v1/chat/completions" if prov == "openai"
                else "https://router.huggingface.co/v1/chat/completions")
        return _call_openai_compatible(base, model, key, system, user, max_tokens, timeout,
                                       want_json and prov == "openai")
    if prov == "gemini":
        return _call_gemini(model, key, system, user, max_tokens, timeout, want_json)
    if prov in ("openrouter", "groq"):
        base = ai_models.spec(prov).get("base_url")
        if not base:
            return None, 0, 0, f"no base_url configured for {prov}"
        return _call_openai_compatible(base, model, key, system, user, max_tokens, timeout, want_json)
    if prov == "local":
        base = ai_models.spec("local").get("base_url", "http://localhost:11434/v1") + "/chat/completions"
        base = base.replace("/v1/chat/completions/chat/completions", "/v1/chat/completions")
        return _call_openai_compatible(base, model, None, system, user, max_tokens, timeout, want_json)
    return None, 0, 0, f"unknown provider {provider}"


# ---------------------------------------------------------------------------
# JSON handling (light; Phase 2 deepens)
# ---------------------------------------------------------------------------
def _extract_json(text: str):
    if not text:
        return None
    import re
    m = re.search(r"```(?:json)?\s*(.+?)```", text, re.DOTALL | re.IGNORECASE)
    cands = []
    if m:
        cands.append(m.group(1).strip())
    cands.append(text.strip())
    for opn, cls in (("{", "}"), ("[", "]")):
        i, j = text.find(opn), text.rfind(cls)
        if 0 <= i < j:
            cands.append(text[i:j + 1])
    for c in cands:
        try:
            return json.loads(c)
        except Exception:
            continue
    return None


# ---------------------------------------------------------------------------
# The one entry point
# ---------------------------------------------------------------------------
def call_llm(system: str, user: str, *, purpose: str = "generic",
             provider: Optional[str] = None, model: Optional[str] = None,
             api_key: Optional[str] = None, schema: Optional[dict] = None,
             max_tokens: Optional[int] = None, timeout: int = 120,
             retries: int = 1, scan_dir: Optional[str] = None,
             budget_usd: Optional[float] = None,
             redact: Optional[str] = None, record: Optional[str] = None,
             harden: bool = True) -> LLMResult:
    """Single fail-safe LLM call. Never raises."""
    t0 = time.time()
    rm = ai_models.resolve(provider, model)
    prov, mdl = rm["provider"], rm["model"]
    res = LLMResult(provider=prov, model=mdl, purpose=purpose)

    verr = ai_models.validate(prov, mdl)
    if verr:
        res.degrade_reason = verr
        _finish(res, t0, scan_dir, record, system, user, schema)
        return res

    # Phase 3 — injection hardening preamble (lazy; no-op if module absent).
    if harden:
        try:
            from core import ai_prompt
            system = ai_prompt.harden_system(system)
        except Exception:
            pass

    # Phase 7 — data policy + redaction (lazy; no-op if module absent).
    sent_system, sent_user = system, user
    if redact is None:
        redact = os.environ.get("ARISE_AI_DATA_POLICY")  # cloud|redact|local_only
    try:
        from core import ai_redact
        block = ai_redact.policy_block(prov, redact)
        if block:
            res.blocked_reason = block
            _finish(res, t0, scan_dir, record, system, user, schema)
            return res
        sent_system, sent_user, res.redaction = ai_redact.apply(system, user, prov, redact)
    except Exception:
        pass

    # Replay (cassette) — keyless path for CI.
    key_c = _cassette_key(prov, mdl, sent_system, sent_user, schema)
    replay = _replay_lookup(key_c)
    if replay is not None:
        res.text = replay.get("text")
        res.tokens_in = replay.get("tokens_in", 0)
        res.tokens_out = replay.get("tokens_out", 0)
        res.ok = res.text is not None
        res.cache_hit = True
        if schema is not None and res.text:
            res.parsed = _extract_json(res.text)
        if not res.ok:
            res.degrade_reason = "cassette had no text"
        _finish(res, t0, scan_dir, record, system, user, schema)
        return res

    # Budget gate.
    left = _budget_left(scan_dir, budget_usd)
    if left is not None and left <= 0:
        res.degrade_reason = "run budget exhausted"
        _finish(res, t0, scan_dir, record, system, user, schema)
        return res

    key = _resolve_key(prov, api_key)
    if not key and prov in ai_models.CLOUD_PROVIDERS:
        res.degrade_reason = f"no API key for {prov}"
        _finish(res, t0, scan_dir, record, system, user, schema)
        return res

    mt = max_tokens or ai_models.max_output_tokens(prov, purpose)
    want_json = schema is not None

    # Try model + fallbacks, with retries each.
    models_to_try = [mdl] + ai_models.fallback_models(prov)
    last_err = None
    for m_i, mm in enumerate(models_to_try):
        for attempt in range(retries + 1):
            text, ti, to, err = _dispatch(prov, mm, key, sent_system, sent_user, mt, timeout, want_json)
            if text:
                res.text, res.tokens_in, res.tokens_out = text, ti, to
                res.model = mm
                res.ok = True
                res.cost_usd = ai_models.cost_usd(prov, ti, to)
                _spend(scan_dir, res.cost_usd)
                if want_json:
                    res.parsed = _extract_json(text)
                _finish(res, t0, scan_dir, record, system, user, schema)
                return res
            last_err = err
    res.degrade_reason = last_err or "no response"
    _finish(res, t0, scan_dir, record, system, user, schema)
    return res


def _finish(res: LLMResult, t0, scan_dir, record, system, user, schema):
    res.latency_ms = int((time.time() - t0) * 1000)
    # record cassette on a real success (not a replay)
    should_record = res.ok and not res.cache_hit and (record is not None or os.environ.get("ARISE_AI_RECORD"))
    if should_record:
        _record_store(_cassette_key(res.provider, res.model, system, user, schema),
                      {"text": res.text, "tokens_in": res.tokens_in, "tokens_out": res.tokens_out},
                      record)
    rec = {k: v for k, v in asdict(res).items() if k not in ("text", "parsed")}
    rec["ts"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    rec["has_text"] = bool(res.text)
    _log_call(scan_dir, rec)


# ---------------------------------------------------------------------------
# Legacy convenience — the (text, err) contract every old caller expects
# ---------------------------------------------------------------------------
def chat(system: str, user: str, **opts) -> Tuple[Optional[str], Optional[str]]:
    return call_llm(system, user, **opts).as_tuple()
