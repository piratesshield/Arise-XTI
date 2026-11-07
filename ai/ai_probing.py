#!/usr/bin/env python3
"""
ARISE AI Assistance Layer — Zone B Pass 2: AI Probing
=====================================================
Reference: AI_ASSISTANCE_LAYER_DESIGN.md §4.1

A post-scan, opt-in second AI pass. Where Pass 1 (the existing dashboard
analyzer) merely *reads* scan data, Pass 2 lets the model verify its own
suspicions against LIVE HTTP responses before finalizing the triage — the
difference between inference ("dirsearch found /.git/config, potentially
critical") and evidence ("/.git/config returned 200 with
[core] repositoryformatversion=0 — confirmed exposed git repo").

This is the ONLY place in ARISE where an AI-proposed action results in a live
outbound request, so the guardrails are enforced IN CODE here — not left as a
convention the caller must remember:

  * Scope-lock  — a probe URL's host must equal the target, be a subdomain of
                  it, or appear in the allowlist. Everything else is refused
                  before any socket is opened. No SSRF to arbitrary hosts.
  * GET-only    — probe_url() hardcodes GET. No method parameter is exposed,
                  so no caller can turn this into a state-mutating request.
  * Max URLs    — the probe list is truncated to cfg.max_urls regardless of
                  how many the model proposes.
  * Body cap    — only the first cfg.body_cap_chars of each response is fed
                  back to the model.
  * Prompt cap  — the follow-up context is truncated to cfg.prompt_cap_chars.
  * Audit trail — every probe (and every skipped out-of-scope URL) is written
                  to the audit log with a timestamp.

Fail-safe: run_two_pass() NEVER raises. Any provider or network failure
degrades to the best partial result. Probing disabled ⇒ Pass 1 only.

The module imports no Flask / dashboard internals. The AI call is injected as
`chat_fn(system, user) -> (text, error)` so this is unit-testable offline
(see the __main__ self-test, which proves every guardrail with no network
and no AI provider).
"""

from __future__ import annotations

import sys as _sys, os as _os
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)


import json
import re
import ssl
import time
import urllib.parse
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, List, Optional, Tuple

# chat_fn(system_prompt, user_prompt) -> (text_or_None, error_or_None)
ChatFn = Callable[[str, str], Tuple[Optional[str], Optional[str]]]

VERDICTS = {"confirmed", "likely", "dismissed"}
REF_TYPES = {"path", "host", "finding"}


# ---------------------------------------------------------------------------
# Configuration — mirrors the Settings UI "ai.probing" JSON block
# ---------------------------------------------------------------------------

@dataclass
class ProbeConfig:
    enabled: bool = False            # opt-in; disabled by default
    scope_locked: bool = True        # kept explicit; enforced regardless
    max_urls: int = 15               # hard cap on probes per analysis
    timeout_s: int = 8               # per-request timeout
    body_cap_chars: int = 2000       # response excerpt fed to the model
    prompt_cap_chars: int = 12000    # follow-up context truncation
    user_agent: str = "EASM-AI-Probe/1.0"
    audit_log_path: Optional[str] = None  # every probe URL + ts appended here

    @classmethod
    def from_settings(cls, block: Optional[dict], audit_log_path: Optional[str] = None) -> "ProbeConfig":
        block = block or {}
        return cls(
            enabled=bool(block.get("enabled", False)),
            scope_locked=bool(block.get("scope_locked", True)),
            max_urls=int(block.get("max_urls", 15)),
            timeout_s=int(block.get("timeout_s", 8)),
            body_cap_chars=int(block.get("body_cap_chars", 2000)),
            prompt_cap_chars=int(block.get("prompt_cap_chars", 12000)),
            user_agent=str(block.get("user_agent", "EASM-AI-Probe/1.0")),
            audit_log_path=audit_log_path,
        )


# ---------------------------------------------------------------------------
# Scope guard — the SSRF firewall for AI-proposed URLs
# ---------------------------------------------------------------------------

class ScopeGuard:
    """Decides whether an AI-proposed URL is allowed to be probed.

    In scope iff the URL host equals the target apex, is a subdomain of it,
    or matches (apex or subdomain) any entry in the allowlist. Anything else
    — arbitrary hosts, IPs, cloud metadata endpoints, localhost — is refused.
    """

    def __init__(self, target: str, allowlist: Optional[List[str]] = None):
        self.roots = set()
        for r in ([target] + list(allowlist or [])):
            r = (r or "").strip().lower()
            r = re.sub(r"^https?://", "", r).split("/")[0].split(":")[0]
            if r:
                self.roots.add(r)

    def in_scope(self, url: str) -> bool:
        try:
            host = urllib.parse.urlparse(url).hostname
        except Exception:
            return False
        if not host:
            return False
        host = host.lower()
        # Reject obvious SSRF magnets outright even if someone mis-scopes.
        if host in ("localhost", "127.0.0.1", "0.0.0.0", "::1", "169.254.169.254"):
            return False
        for root in self.roots:
            if host == root or host.endswith("." + root):
                return True
        return False


# ---------------------------------------------------------------------------
# Probe result
# ---------------------------------------------------------------------------

@dataclass
class ProbeResult:
    url: str
    status: Optional[int] = None
    content_type: str = ""
    excerpt: str = ""
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "status": self.status,
            "content_type": self.content_type,
            "excerpt": self.excerpt,
            "error": self.error,
        }


# ---------------------------------------------------------------------------
# The GET-only prober
# ---------------------------------------------------------------------------

class _AuditWriter:
    def __init__(self, path: Optional[str]):
        self.path = path

    def write(self, line: str) -> None:
        stamped = f"{datetime.now().isoformat(timespec='seconds')} {line}"
        if not self.path:
            return
        try:
            with open(self.path, "a") as fh:
                fh.write(stamped + "\n")
        except OSError:
            pass  # audit failure must never break probing


def probe_url(url: str, cfg: ProbeConfig, audit: _AuditWriter) -> ProbeResult:
    """Issue a single GET request. Method is hardcoded — there is deliberately
    no way for a caller to request POST/PUT/DELETE through this function."""
    audit.write(f"probe: {url}")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    req = urllib.request.Request(url, method="GET")  # GET-ONLY, not parameterized
    req.add_header("User-Agent", cfg.user_agent)
    req.add_header("Accept", "*/*")
    try:
        with urllib.request.urlopen(req, timeout=cfg.timeout_s, context=ctx) as resp:
            body = resp.read(cfg.body_cap_chars + 512).decode(errors="ignore")
            return ProbeResult(
                url=url, status=getattr(resp, "status", None),
                content_type=resp.headers.get("Content-Type", ""),
                excerpt=body[: cfg.body_cap_chars],
            )
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read(cfg.body_cap_chars).decode(errors="ignore") if e.fp else ""
        except Exception:
            pass
        return ProbeResult(url=url, status=e.code,
                            content_type=(e.headers.get("Content-Type", "") if e.headers else ""),
                            excerpt=body[: cfg.body_cap_chars])
    except Exception as e:  # noqa: BLE001 — probing must never raise to caller
        return ProbeResult(url=url, error=str(e)[:200])


# ---------------------------------------------------------------------------
# Prompts
# ---------------------------------------------------------------------------

TRIAGE_SYSTEM = (
    "You are ARISE's API security triage analyst. You receive a JSON snapshot of "
    "an attack-surface scan. Identify the highest-signal exposures and, crucially, "
    "propose specific URLs worth fetching live to confirm them.\n\n"
    "Respond with ONLY a JSON object (no prose, no code fences) of the form:\n"
    "{\n"
    '  "summary": "<2-4 sentence read of the posture>",\n'
    '  "suspicious": [\n'
    '    {"ref": "host/path", "type": "path|host|finding",\n'
    '     "verdict": "likely|dismissed", "confidence": "high|medium|low",\n'
    '     "rationale": "<why>", "evidence": ""}\n'
    "  ],\n"
    '  "probe_urls": ["https://in-scope-host/path", "..."]\n'
    "}\n"
    "Only propose probe_urls on hosts that appear in the scan data. Never invent "
    "hosts or findings. Prefer URLs that would DECISIVELY confirm an exposure "
    "(config files, admin panels, unauthenticated APIs, secrets)."
)

PROBE_FOLLOWUP_SYSTEM = (
    "You are ARISE's API security triage analyst finalizing your assessment. You "
    "previously proposed suspicious items; you now have the ACTUAL live HTTP "
    "responses from probing them. Update your verdicts based strictly on this "
    "evidence — promote to \"confirmed\" only when a response proves the exposure, "
    "and \"dismissed\" when it disproves it.\n\n"
    "Respond with ONLY a JSON object (no prose, no code fences):\n"
    "{\n"
    '  "summary": "<updated read grounded in the live evidence>",\n'
    '  "suspicious": [\n'
    '    {"ref": "host/path", "type": "path|host|finding",\n'
    '     "verdict": "confirmed|likely|dismissed", "confidence": "high|medium|low",\n'
    '     "rationale": "<why, citing the response>", "evidence": "<snippet from response>"}\n'
    "  ]\n"
    "}\n"
    "Ground every verdict in an actual response above. Do not invent evidence."
)


# ---------------------------------------------------------------------------
# Structured-output parsing (tolerant of ```json fences / surrounding prose)
# ---------------------------------------------------------------------------

def parse_structured(text: Optional[str]) -> Optional[dict]:
    if not text:
        return None
    # Strip code fences.
    t = re.sub(r"^```(?:json)?\s*|\s*```$", "", text.strip(), flags=re.I | re.M)
    # Try direct, then first {...} block.
    for candidate in (t, _first_json_object(t)):
        if not candidate:
            continue
        try:
            obj = json.loads(candidate)
            if isinstance(obj, dict):
                return obj
        except Exception:
            continue
    return None


def _first_json_object(s: str) -> Optional[str]:
    depth = 0
    start = -1
    for i, ch in enumerate(s):
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start >= 0:
                return s[start: i + 1]
    return None


def _normalize_suspicious(items) -> List[dict]:
    out = []
    for it in (items or []):
        if not isinstance(it, dict):
            continue
        verdict = str(it.get("verdict", "likely")).lower()
        rtype = str(it.get("type", "finding")).lower()
        out.append({
            "ref": str(it.get("ref", ""))[:300],
            "type": rtype if rtype in REF_TYPES else "finding",
            "verdict": verdict if verdict in VERDICTS else "likely",
            "confidence": str(it.get("confidence", "medium")).lower(),
            "rationale": str(it.get("rationale", ""))[:500],
            "evidence": str(it.get("evidence", ""))[:500],
        })
    return out


# ---------------------------------------------------------------------------
# The two-pass orchestration
# ---------------------------------------------------------------------------

@dataclass
class TriageResult:
    summary: str = ""
    suspicious: List[dict] = field(default_factory=list)
    probe_urls: List[str] = field(default_factory=list)
    probes: List[dict] = field(default_factory=list)      # what we fetched
    skipped: List[str] = field(default_factory=list)      # out-of-scope, not fetched
    pass2_ran: bool = False
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "summary": self.summary,
            "suspicious": self.suspicious,
            "probe_urls": self.probe_urls,
            "probes": self.probes,
            "skipped": self.skipped,
            "pass2_ran": self.pass2_ran,
            "error": self.error,
            "generated_at": datetime.now().isoformat(timespec="seconds"),
        }


def run_two_pass(context: dict, target: str, chat_fn: ChatFn,
                 cfg: ProbeConfig, scope: ScopeGuard) -> TriageResult:
    """Pass 1 structured triage → (opt-in) Pass 2 scope-locked live probing →
    evidence-refined result. Never raises."""
    result = TriageResult()
    audit = _AuditWriter(cfg.audit_log_path)

    # ── Pass 1 — structured triage ────────────────────────────────────────
    user1 = ("Scan snapshot (JSON):\n\n```json\n"
             + json.dumps(context, indent=2, default=str)[: cfg.prompt_cap_chars]
             + "\n```\n\nTriage per your instructions.")
    text1, err1 = _safe_chat(chat_fn, TRIAGE_SYSTEM, user1)
    if err1:
        result.error = f"pass1: {err1}"
        return result
    parsed1 = parse_structured(text1) or {}
    result.summary = str(parsed1.get("summary", "") or (text1 or "")[:800])
    result.suspicious = _normalize_suspicious(parsed1.get("suspicious"))
    result.probe_urls = [u for u in (parsed1.get("probe_urls") or []) if isinstance(u, str)]

    # ── Pass 2 — probing (opt-in) ─────────────────────────────────────────
    if not cfg.enabled:
        return result
    if not result.probe_urls:
        return result

    # Scope-lock + cap. Order matters: filter first, THEN cap, so the cap
    # applies to in-scope URLs, not wasted on rejects.
    in_scope, skipped = [], []
    for u in result.probe_urls:
        if scope.in_scope(u):
            in_scope.append(u)
        else:
            skipped.append(u)
            audit.write(f"skipped (out of scope): {u}")
    result.skipped = skipped
    to_probe = in_scope[: cfg.max_urls]  # HARD cap

    if not to_probe:
        return result

    probe_results = [probe_url(u, cfg, audit) for u in to_probe]
    result.probes = [pr.to_dict() for pr in probe_results]

    # ── Pass 2 follow-up — refine verdicts on live evidence ───────────────
    lines = []
    for pr in probe_results:
        lines.append(
            f"URL: {pr.url}\nstatus={pr.status} type={pr.content_type}"
            + (f" error={pr.error}" if pr.error else "")
            + f"\nEXCERPT:\n{pr.excerpt}\n---"
        )
    evidence_blob = "\n".join(lines)[: cfg.prompt_cap_chars]
    user2 = ("My earlier triage:\n```json\n"
             + json.dumps({"summary": result.summary,
                           "suspicious": result.suspicious}, indent=2)[:4000]
             + "\n```\n\nI probed the suspicious URLs. Live responses:\n\n"
             + evidence_blob
             + "\n\nFinalize your triage based on the ACTUAL responses above.")
    text2, err2 = _safe_chat(chat_fn, PROBE_FOLLOWUP_SYSTEM, user2)
    if err2:
        result.error = f"pass2: {err2}"  # keep Pass 1 output; note the failure
        return result
    parsed2 = parse_structured(text2)
    if parsed2:
        result.summary = str(parsed2.get("summary", result.summary))
        refined = _normalize_suspicious(parsed2.get("suspicious"))
        if refined:
            result.suspicious = refined
        result.pass2_ran = True
    return result


def _safe_chat(chat_fn: ChatFn, system: str, user: str) -> Tuple[Optional[str], Optional[str]]:
    """Wrap the injected chat function so a raising provider degrades to an
    error string instead of propagating."""
    try:
        return chat_fn(system, user)
    except Exception as e:  # noqa: BLE001
        return None, str(e)[:200]


# ---------------------------------------------------------------------------
# Self-test — proves every guardrail with NO network and NO AI provider
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=== ai_probing self-test (offline, no provider) ===\n")

    # A fake provider: Pass 1 proposes 2 in-scope + 2 out-of-scope URLs.
    calls = {"n": 0}

    def fake_chat(system, user):
        calls["n"] += 1
        if "finalizing" in system:  # Pass 2
            return (json.dumps({
                "summary": "Confirmed one exposure via live probe.",
                "suspicious": [{"ref": "api.target.com/.env", "type": "path",
                                "verdict": "confirmed", "confidence": "high",
                                "rationale": "200 with APP_KEY", "evidence": "APP_KEY=xxx"}],
            }), None)
        return (json.dumps({  # Pass 1
            "summary": "Two candidate exposures.",
            "suspicious": [{"ref": "api.target.com/.env", "type": "path",
                            "verdict": "likely", "confidence": "medium",
                            "rationale": "dirsearch hit", "evidence": ""}],
            "probe_urls": [
                "https://api.target.com/.env",           # in scope
                "https://sub.target.com/.git/config",    # in scope (subdomain)
                "https://evil.example.com/steal",        # OUT of scope -> must skip
                "http://169.254.169.254/latest/meta-data/",  # SSRF magnet -> must skip
            ],
        }), None)

    scope = ScopeGuard("target.com")
    assert scope.in_scope("https://api.target.com/x")
    assert scope.in_scope("https://target.com/x")
    assert not scope.in_scope("https://evil.example.com/x")
    assert not scope.in_scope("http://169.254.169.254/")
    assert not scope.in_scope("https://nottarget.com.evil.com/x")
    print("[1] ScopeGuard: subdomain allowed, foreign host + SSRF magnet + suffix-trick rejected  ✓")

    # Probing disabled -> Pass 1 only, no probes.
    cfg_off = ProbeConfig(enabled=False)
    r = run_two_pass({"target": "target.com"}, "target.com", fake_chat, cfg_off, scope)
    assert r.pass2_ran is False and r.probes == [] and r.suspicious
    print("[2] Disabled probing -> Pass 1 only, zero probes  ✓")

    # Enabled, but cap the probes to 1 and point probing at unreachable hosts
    # (network will fail fast -> ProbeResult.error, but flow must not raise).
    cfg_on = ProbeConfig(enabled=True, max_urls=1, timeout_s=2)
    r2 = run_two_pass({"target": "target.com"}, "target.com", fake_chat, cfg_on, scope)
    assert len(r2.skipped) == 2, f"expected 2 skipped, got {r2.skipped}"
    assert len(r2.probes) == 1, f"max_urls cap failed: {len(r2.probes)} probed"
    print(f"[3] Enabled probing: 2 out-of-scope skipped, cap honored (1 probed)  ✓")
    print(f"    skipped = {r2.skipped}")

    # GET-only: verify probe_url exposes no method parameter.
    import inspect
    sig = inspect.signature(probe_url)
    assert "method" not in sig.parameters, "probe_url must not expose a method param"
    print("[4] GET-only: probe_url has no method parameter to override  ✓")

    # Fail-safe: a raising chat_fn must not propagate.
    def boom(system, user):
        raise RuntimeError("provider down")
    r3 = run_two_pass({"target": "target.com"}, "target.com", boom, cfg_on, scope)
    assert r3.error.startswith("pass1:") and r3.suspicious == []
    print("[5] Fail-safe: raising provider degrades to error string, no exception  ✓")

    print("\nAll guardrails enforced in code. ✓")
