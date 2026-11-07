"""
AriseAI — proof-of-concept replay & curl (Phase 5 / RT2).

"No false positives" is an aspiration, not a guarantee — differential checks can
still FP on dynamic content, timing, or WAF behavior, and a body-only differential
(same status/length) isn't self-evident from the stored snapshot. So AriseAI:

  * marks every proven finding `replay_confirmed: "pending"` until re-verified,
  * ships a copy-paste `curl` for each (operator can replay by hand),
  * exposes replay() — re-issue the exact recorded request through ARISE's
    scope-guarded, non-destructive HTTP client and return the live response so the
    operator (or the dashboard button) can confirm the exploit still reproduces.

GET-only and ScopeGuard-locked: replay never sends a state-changing request and
never touches an out-of-scope host. Never raises.
"""

from __future__ import annotations

import shlex
from typing import Any, Dict, Optional


def curl_for(finding: Dict[str, Any]) -> str:
    """Build a copy-paste curl for a finding's PoC request. Best-effort."""
    url = finding.get("url") or ""
    method = (finding.get("method") or "GET").upper()
    rl = finding.get("request_line") or ""
    # request_line is like "GET host/path?x=<payload>" and encodes the ATTACK
    # request — prefer it so the replay curl reproduces the exploit, not the
    # benign discovered URL.
    if rl:
        parts = rl.split(None, 1)
        if len(parts) == 2:
            method, url = parts[0].upper(), parts[1].strip()
    if not url:
        return ""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    bits = ["curl", "-sS", "-i"]
    if method and method != "GET":
        bits += ["-X", method]
    bits += [url]
    try:
        return " ".join(shlex.quote(b) for b in bits)
    except Exception:
        return "curl -sS -i " + url


def replay(finding: Dict[str, Any], target: str, scan_dir: str,
           timeout: int = 10) -> Dict[str, Any]:
    """Re-issue the PoC request (GET, scope-guarded) and return a result dict:
    {ok, status, len, elapsed, content_type, snippet, baseline, matches_baseline,
     error}. Never raises."""
    out: Dict[str, Any] = {"ok": False, "error": None}
    url = finding.get("url") or ""
    if not url:
        out["error"] = "finding has no URL to replay"
        return out
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    try:
        from offensive.offensive_verify import Http, _snap
        from ai_analyst.safety import build_scope
    except Exception as exc:
        out["error"] = f"replay substrate unavailable: {exc}"
        return out
    scope = build_scope(target, scan_dir)
    if scope is None:
        out["error"] = "ScopeGuard unavailable — cannot replay safely"
        return out
    if not scope.in_scope(url):
        out["error"] = f"URL out of scope: {url[:120]}"
        return out
    try:
        http = Http(rate=5, timeout=timeout, scope=scope)
        r = http.get(url)
        if r is None:
            out["error"] = "no response (blocked or unreachable)"
            return out
        snap = _snap(r)
        out.update({"ok": True, "status": snap.get("status"), "len": snap.get("len"),
                    "elapsed": snap.get("elapsed"), "content_type": snap.get("content_type")})
        try:
            from offensive.offensive_verify import body_of
            out["snippet"] = (body_of(r) or "")[:800]
        except Exception:
            out["snippet"] = ""
        base = finding.get("baseline") or {}
        if base:
            out["baseline"] = base
            out["matches_baseline"] = (snap.get("status") == base.get("status")
                                       and abs((snap.get("len") or 0) - (base.get("len") or 0)) < 32)
        return out
    except Exception as exc:
        out["error"] = f"replay failed: {str(exc)[:160]}"
        return out
