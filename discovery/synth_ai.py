#!/usr/bin/env python3
"""
ARISE — Bounded AI layer for the attack synthesizer
===================================================
This is the "grounded second brain", NOT a free-roaming agent. It does exactly
two narrow, auditable jobs on top of the deterministic recon_attack_synth.py:

  1. propose_templates()  — given a RECON SUMMARY (hosts, tech, lane counts,
     sample endpoints), ask the model for extra custom nuclei templates a senior
     hunter would add. Every proposal is: id-rewritten to arise-synth-ai-*,
     scope-checked (ai_probing.ScopeGuard — no out-of-scope hosts), and passed
     through `nuclei -validate` before it is allowed to exist. Invalid or
     out-of-scope proposals are dropped. The model never holds the trigger —
     nuclei does.

  2. triage_findings()    — given findings that already exist (nuclei / intel),
     rank them confirmed | likely | dismissed with a one-line why + an
     exploitability note, so the operator reads signal first.

Fail-safe: every entry point degrades to a no-op with a clear reason (missing
key, missing SDK, provider error). It NEVER raises into the caller, so a scan
with --ai but no API key behaves exactly like a scan without --ai.

The AI call is the same shape the dashboard uses: chat_fn(system, user)->(text, err).
"""
from __future__ import annotations

import sys as _sys, os as _os
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)


import json
import os
import re
import shutil
import subprocess
import tempfile
from typing import Callable, List, Optional, Tuple

try:
    from ai.ai_probing import ScopeGuard  # reuse the SSRF/scope firewall
except Exception:  # pragma: no cover - ScopeGuard is a tiny fallback
    class ScopeGuard:  # type: ignore
        def __init__(self, target, allowlist=None):
            self.roots = {(target or "").lower()}
            for r in (allowlist or []):
                self.roots.add((r or "").lower())

        def in_scope(self, url):
            import urllib.parse
            h = (urllib.parse.urlparse(url).hostname or "").lower()
            return any(h == r or h.endswith("." + r) for r in self.roots if r)

ChatFn = Callable[[str, str], Tuple[Optional[str], Optional[str]]]


# ---------------------------------------------------------------------------
# Provider — now routes through the unified layer (core/ai_provider.py, Phase 0).
# The (system,user)->(text,err) contract is unchanged, so every existing caller
# (adaptive loop, recon_attack_synth --ai, ai_analyst) is unaffected; they now get
# token/cost accounting, run logging, budgets, redaction and injection hardening
# for free. A thin pre-check preserves the old "early skip when no key" behavior.
# ---------------------------------------------------------------------------

def build_chat_fn(provider: Optional[str] = None,
                  model: Optional[str] = None,
                  api_key: Optional[str] = None,
                  purpose: str = "synth",
                  scan_dir: Optional[str] = None) -> Tuple[Optional[ChatFn], Optional[str]]:
    try:
        from core import ai_provider, ai_models
    except Exception:
        return _build_chat_fn_legacy(provider, model, api_key)
    rm = ai_models.resolve(provider, model)
    prov = rm["provider"]
    key = api_key or ai_provider._resolve_key(prov, None)
    if prov in ai_models.CLOUD_PROVIDERS and not key:
        return None, f"no API key for {prov} — AI layer skipped"

    def _chat(system: str, user: str):
        return ai_provider.chat(system, user, provider=prov, model=model,
                                api_key=api_key, purpose=purpose, scan_dir=scan_dir)
    return _chat, None


def _build_chat_fn_legacy(provider: Optional[str] = None,
                          model: Optional[str] = None,
                          api_key: Optional[str] = None) -> Tuple[Optional[ChatFn], Optional[str]]:
    """Original self-contained implementation — fallback only if core.ai_provider
    is somehow unavailable. Kept so the pipeline AI layer degrades, never breaks."""
    provider = (provider or os.environ.get("ARISE_AI_PROVIDER") or "claude").lower()

    if provider == "claude":
        key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not key:
            return None, "no ANTHROPIC_API_KEY set — AI layer skipped"
        mdl = model or os.environ.get("ARISE_AI_MODEL") or "claude-opus-4-8"
        try:
            import anthropic  # noqa: F401
        except ImportError:
            return None, "the 'anthropic' package is not installed — AI layer skipped"

        def _chat(system: str, user: str):
            try:
                client = anthropic.Anthropic(api_key=key)
                msg = client.messages.create(
                    model=mdl, max_tokens=4000, system=system,
                    messages=[{"role": "user", "content": user}],
                )
                text = "".join(getattr(b, "text", "") for b in msg.content
                               if getattr(b, "type", None) == "text").strip()
                return (text or None), (None if text else "empty response")
            except Exception as exc:  # noqa: BLE001
                return None, f"claude call failed: {str(exc)[:180]}"
        return _chat, None

    if provider in ("openai", "huggingface"):
        key = api_key or os.environ.get("OPENAI_API_KEY" if provider == "openai" else "HF_API_TOKEN")
        if not key:
            return None, f"no API key for {provider} — AI layer skipped"
        url = ("https://api.openai.com/v1/chat/completions" if provider == "openai"
               else "https://router.huggingface.co/v1/chat/completions")
        mdl = model or os.environ.get("OPENAI_MODEL" if provider == "openai" else "HF_MODEL") or os.environ.get("ARISE_AI_MODEL") or "gpt-4o-mini"

        def _chat(system: str, user: str):
            try:
                import requests
                r = requests.post(url, headers={"Authorization": f"Bearer {key}"},
                                  json={"model": mdl, "max_tokens": 2000, "temperature": 0.3,
                                        "messages": [{"role": "system", "content": system},
                                                     {"role": "user", "content": user}]},
                                  timeout=120)
                if r.status_code // 100 != 2:
                    return None, f"{provider} error {r.status_code}"
                return (r.json()["choices"][0]["message"]["content"] or "").strip() or None, None
            except Exception as exc:  # noqa: BLE001
                return None, f"{provider} call failed: {str(exc)[:180]}"
        return _chat, None

    if provider == "gemini":
        key = api_key or os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
        if not key:
            return None, "no GEMINI_API_KEY set — AI layer skipped"
        # gemini-1.5-flash was retired from the v1beta API (confirmed via a
        # live ListModels call returning 404 for it, 2026-09-27) — every
        # caller through this shared build_chat_fn silently broke until this
        # default was updated, not just the attack-chain-v2 work that
        # surfaced it.
        mdl = model or os.environ.get("GEMINI_MODEL") or os.environ.get("ARISE_AI_MODEL") or "gemini-2.5-flash"

        def _chat(system: str, user: str):
            try:
                import requests
                u = f"https://generativelanguage.googleapis.com/v1beta/models/{mdl}:generateContent?key={key}"
                # thinkingBudget=0: 2.5+ models spend part of maxOutputTokens on
                # invisible "thoughts" tokens by default (confirmed live: a
                # trivial prompt still consumed 31 of them) — for every existing
                # caller of this shared function the actual answer is a short
                # JSON/text blob, not a reasoning trace, so disabling thinking
                # frees the whole budget for the real output instead of risking
                # silent truncation on anything non-trivial.
                r = requests.post(u, json={"system_instruction": {"parts": [{"text": system}]},
                                           "contents": [{"role": "user", "parts": [{"text": user}]}],
                                           "generationConfig": {"maxOutputTokens": 4096, "temperature": 0.3,
                                                                "thinkingConfig": {"thinkingBudget": 0}}},
                                  timeout=120)
                if r.status_code // 100 != 2:
                    return None, f"gemini error {r.status_code}"
                cands = r.json().get("candidates") or []
                if not cands:
                    return None, "gemini returned no content"
                return "".join(p.get("text", "") for p in cands[0]["content"]["parts"]).strip() or None, None
            except Exception as exc:  # noqa: BLE001
                return None, f"gemini call failed: {str(exc)[:180]}"
        return _chat, None

    return None, f"unknown provider: {provider}"


# ---------------------------------------------------------------------------
# Structured tool-calling  (Offensive AI Elevation, Phase 3)
# ---------------------------------------------------------------------------
# Additive: this does NOT change build_chat_fn or the (system,user)->(text,err)
# contract every existing caller relies on. It adds a SECOND builder that returns
# a tool-use-capable function so the Autonomous brain can emit typed tool calls
# (validated against a registry schema) instead of hand-writing shell strings.
#
# Contract:
#   tool_chat(system, user, tools) -> (result, err)
#     tools  : list of {"name","description","input_schema"(JSONSchema)}
#     result : {"text": str, "tool_calls": [{"id","name","input"(dict)}]}
# Only the Claude provider supports native tool-use here; other providers degrade
# to a clear error so the caller keeps its existing text-command loop as fallback.
ToolChatFn = Callable[[str, str, List[dict]], Tuple[Optional[dict], Optional[str]]]


def build_tool_chat_fn(provider: Optional[str] = None,
                       model: Optional[str] = None,
                       api_key: Optional[str] = None) -> Tuple[Optional[ToolChatFn], Optional[str]]:
    """Build a tool-use-capable chat function. Fail-safe: returns (None, reason)
    when the provider/SDK/key is unavailable, exactly like build_chat_fn."""
    provider = (provider or os.environ.get("ARISE_AI_PROVIDER") or "claude").lower()

    if provider == "claude":
        key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not key:
            return None, "no ANTHROPIC_API_KEY set — tool-calling skipped"
        mdl = model or os.environ.get("ARISE_AI_MODEL") or "claude-opus-4-8"
        try:
            import anthropic  # noqa: F401
        except ImportError:
            return None, "the 'anthropic' package is not installed — tool-calling skipped"

        def _tool_chat(system: str, user: str, tools: List[dict]):
            try:
                client = anthropic.Anthropic(api_key=key)
                msg = client.messages.create(
                    model=mdl, max_tokens=4000, system=system,
                    tools=tools or [],
                    messages=[{"role": "user", "content": user}],
                )
                text_parts, calls = [], []
                for b in msg.content:
                    btype = getattr(b, "type", None)
                    if btype == "text":
                        text_parts.append(getattr(b, "text", ""))
                    elif btype == "tool_use":
                        calls.append({"id": getattr(b, "id", ""),
                                      "name": getattr(b, "name", ""),
                                      "input": getattr(b, "input", {}) or {}})
                return {"text": "".join(text_parts).strip(), "tool_calls": calls}, None
            except Exception as exc:  # noqa: BLE001
                return None, f"claude tool-call failed: {str(exc)[:180]}"
        return _tool_chat, None

    # OpenAI/Gemini tool-calling have different wire shapes; until they are wired
    # the caller should fall back to the (system,user)->text loop.
    return None, f"tool-calling not yet supported for provider '{provider}' — use build_chat_fn"


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

def _yaml_blocks(text: str) -> List[str]:
    """Pull ```yaml ... ``` fenced blocks; fall back to splitting on 'id:' docs."""
    blocks = re.findall(r"```(?:ya?ml)?\s*\n(.*?)```", text, re.S)
    if blocks:
        return [b.strip() for b in blocks if "id:" in b and "http:" in b]
    # no fences — try to split multi-doc YAML on top-level 'id:' lines
    parts, cur = [], []
    for line in text.splitlines():
        if re.match(r"^id:\s", line) and cur:
            parts.append("\n".join(cur)); cur = [line]
        else:
            cur.append(line)
    if cur:
        parts.append("\n".join(cur))
    return [p.strip() for p in parts if "id:" in p and "http:" in p]


def _first_json(text: str):
    m = re.search(r"```(?:json)?\s*\n(.*?)```", text, re.S)
    raw = m.group(1) if m else text
    # find the first balanced [...] or {...}
    for op, cl in (("[", "]"), ("{", "}")):
        i = raw.find(op)
        if i < 0:
            continue
        depth = 0
        for j in range(i, len(raw)):
            if raw[j] == op:
                depth += 1
            elif raw[j] == cl:
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(raw[i:j + 1])
                    except Exception:
                        break
    return None


def _nuclei_validate(path: str, dast: bool = False) -> Tuple[bool, str]:
    """Return (ok, detail). `detail` carries the validator's error text when the
    template is invalid — that is the exact signal the repair loop feeds back to
    the model. When nuclei is absent we cannot validate here, so we do not block
    (the pipeline validates at run time); detail says so."""
    if not shutil.which("nuclei"):
        return True, "nuclei not installed — validation deferred to run time"
    cmd = ["nuclei", "-validate", "-t", path, "-disable-update-check"]
    if dast:
        cmd.insert(2, "-dast")
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        out = (r.stdout + r.stderr).strip()
        ok = "validated successfully" in out.lower()
        # keep the last few, most-specific lines — that is where the reason is
        detail = "" if ok else "\n".join(out.splitlines()[-8:])[:1500]
        return ok, detail
    except Exception as exc:  # noqa: BLE001
        return False, f"nuclei -validate crashed: {str(exc)[:180]}"


# ---------------------------------------------------------------------------
# 1) Template proposals
# ---------------------------------------------------------------------------

PROPOSE_SYSTEM = (
    "You are a senior bug-bounty hunter writing nuclei v3 templates. You are given a "
    "RECON SUMMARY of a black-box target. Propose up to 6 HIGH-SIGNAL custom nuclei "
    "templates that a skilled hunter would add for THIS surface — things the generic "
    "community templates miss because they depend on the specific tech, endpoints, or "
    "shapes seen here. Rules:\n"
    "  * Use {{BaseURL}} for paths — never hardcode a hostname.\n"
    "  * GET/POST/OPTIONS only. No destructive verbs. No auth bypass actions.\n"
    "  * Every template MUST have matchers that CONFIRM the issue (a signature, not a bare 200).\n"
    "  * Valid nuclei v3 YAML only. severity in info|low|medium|high|critical.\n"
    "Return ONLY the templates, each in its own ```yaml code block. No prose."
)

TRIAGE_SYSTEM = (
    "You are ARISE's findings triage analyst. You receive a JSON array of scan findings. "
    "Rank them by real exploitability for a black-box attacker. Respond with ONLY a JSON "
    "array (no prose, no fences) of objects:\n"
    '  {"ref":"<template-id or name>","host":"<host>","verdict":"confirmed|likely|dismissed",'
    '"priority":"P0|P1|P2|P3","why":"<one line>","next":"<the single next probe to confirm/exploit>"}\n'
    "Base every verdict only on the given findings. Do not invent findings or hosts."
)

REPAIR_SYSTEM = (
    "You are fixing a nuclei v3 YAML template that FAILED `nuclei -validate`. You are given "
    "the template and the EXACT validator error. Return the CORRECTED template, preserving "
    "its original intent (same endpoint, same class of check). Rules:\n"
    "  * Fix ONLY what the error requires; keep the matchers meaningful (never a bare 200).\n"
    "  * Use {{BaseURL}} for paths — never hardcode a hostname.\n"
    "  * GET/POST/OPTIONS only. No destructive verbs.\n"
    "  * Valid nuclei v3 YAML. severity in info|low|medium|high|critical.\n"
    "Return ONLY the corrected template in a single ```yaml code block. No prose."
)

REPAIR_TRIES = int(os.environ.get("ARISE_AI_REPAIR_TRIES", "2"))


def _sanitize_block(block: str, i: int, scope: ScopeGuard) -> Tuple[str, Optional[Tuple[str, str]]]:
    """Force a safe id + arise,synth,ai tags and scope-check any absolute URL the
    model baked into a path. Returns (block, drop) where drop is (reason, sample)
    or None. Applied to both first proposals AND repaired templates, so a repair
    can never (re)introduce an out-of-scope host."""
    block = re.sub(r"(?m)^id:\s*.*$", f"id: arise-synth-ai-{i}", block, count=1)
    if "tags:" in block:
        block = re.sub(r"(?m)^(\s*tags:\s*)(.*)$",
                       lambda m: m.group(1) + "arise,synth,ai," + m.group(2), block, count=1)
    abs_urls = re.findall(r"https?://[^\s\"'{}]+", block)
    bad = [u for u in abs_urls if not scope.in_scope(u)]
    if bad:
        return block, ("out-of-scope host", bad[0][:80])
    return block, None


def repair_template(block: str, error: str, chat_fn: ChatFn) -> Tuple[Optional[str], Optional[str]]:
    """Ask the model to fix a template that failed validation, feeding back the
    EXACT validator error. Returns (repaired_yaml, err). Never raises."""
    user = ("TEMPLATE (failed nuclei -validate):\n```yaml\n" + block[:6000]
            + "\n```\n\nVALIDATOR ERROR:\n" + (error or "(no detail)")[:1500]
            + "\n\nReturn the corrected template.")
    text, err = chat_fn(REPAIR_SYSTEM, user)
    if err or not text:
        return None, err or "empty repair response"
    # lenient extraction — a repaired template must have an id: but may momentarily
    # lack an http: block if the model is mid-fix; _yaml_blocks is too strict here.
    fenced = re.findall(r"```(?:ya?ml)?\s*\n(.*?)```", text, re.S)
    cand = [b.strip() for b in fenced if "id:" in b] or ([text.strip()] if "id:" in text else [])
    if not cand:
        return None, "no yaml in repair response"
    return cand[0], None


def propose_templates(recon_summary: dict, chat_fn: ChatFn, scope: ScopeGuard,
                      out_dir: str, cap: int = 6, repair_tries: int = REPAIR_TRIES) -> dict:
    """Ask the model for extra templates; keep only valid, in-scope ones.

    A proposal that fails `nuclei -validate` is NOT discarded — the validator's
    error is fed back to the model for up to `repair_tries` bounded repair passes
    (the exact 'check nuclei error → fix → retry' loop). Only if it is still
    invalid after repair is it dropped, with the last error recorded. The model
    never holds the trigger; nuclei does, every attempt."""
    result = {"requested": True, "written": [], "dropped": [], "repaired": [], "error": None}
    user = ("RECON SUMMARY (JSON):\n" + json.dumps(recon_summary, indent=2)[:11000]
            + f"\n\nPropose up to {cap} templates.")
    text, err = chat_fn(PROPOSE_SYSTEM, user)
    if err or not text:
        result["error"] = err or "empty model response"
        return result

    ai_dir = os.path.join(out_dir, "generated-templates", "ai")
    os.makedirs(ai_dir, exist_ok=True)
    for i, block in enumerate(_yaml_blocks(text)[:cap]):
        block, drop = _sanitize_block(block, i, scope)
        if drop:
            result["dropped"].append({"i": i, "reason": drop[0], "sample": drop[1]})
            continue
        fp = os.path.join(ai_dir, f"proposed_{i}.yaml")
        with open(fp, "w") as fh:
            fh.write(block + "\n")

        ok, detail = _nuclei_validate(fp)
        attempts = 0
        while not ok and attempts < repair_tries:
            attempts += 1
            repaired, rerr = repair_template(block, detail, chat_fn)
            if not repaired:
                detail = f"repair pass {attempts} unavailable: {rerr}"
                break  # provider/parse failure — stop repairing, fall through to drop
            block, drop = _sanitize_block(repaired, i, scope)
            if drop:
                detail = f"repair pass {attempts} introduced {drop[0]}: {drop[1]}"
                ok = False
                break  # a repair that reaches out of scope is refused outright
            with open(fp, "w") as fh:
                fh.write(block + "\n")
            ok, detail = _nuclei_validate(fp)

        if ok:
            rel = os.path.relpath(fp, out_dir)
            result["written"].append(rel)
            if attempts:
                result["repaired"].append({"i": i, "attempts": attempts, "path": rel})
        else:
            os.remove(fp)
            result["dropped"].append({
                "i": i, "reason": "failed nuclei -validate",
                "repair_attempts": attempts, "last_error": (detail or "")[:200],
            })
    if os.path.isdir(ai_dir) and not os.listdir(ai_dir):
        os.rmdir(ai_dir)
    return result


# ---------------------------------------------------------------------------
# 2) Findings triage
# ---------------------------------------------------------------------------

def triage_findings(findings: List[dict], chat_fn: ChatFn, cap: int = 60) -> dict:
    result = {"requested": True, "triaged": [], "error": None}
    if not findings:
        result["error"] = "no findings to triage yet"
        return result
    compact = []
    for f in findings[:cap]:
        info = f.get("info", {}) if isinstance(f.get("info"), dict) else {}
        compact.append({
            "ref": f.get("template-id") or f.get("templateID") or info.get("name") or f.get("name") or "?",
            "host": f.get("host") or f.get("matched-at") or f.get("url") or "?",
            "severity": info.get("severity") or f.get("severity") or "unknown",
            "matched": (f.get("matched-at") or f.get("matched") or "")[:160],
        })
    text, err = chat_fn(TRIAGE_SYSTEM, "FINDINGS (JSON):\n" + json.dumps(compact)[:12000])
    if err or not text:
        result["error"] = err or "empty model response"
        return result
    parsed = _first_json(text)
    if isinstance(parsed, list):
        result["triaged"] = parsed
    else:
        result["error"] = "could not parse triage JSON"
    return result
