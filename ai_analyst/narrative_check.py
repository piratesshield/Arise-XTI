"""
AriseAI — narrative verification (Phase 4 / RT3).

`brain.narrate()` output is LLM prose. Proven findings carry real differential
evidence, but the narrative / chains / PoC text can invent a plausible endpoint
on a real host. This module cross-checks every host / URL / IP token the model
emitted against the actual evidence and flags anything not observed, so a
fabricated specific can never sit next to real proof as if equally grounded.

It does NOT delete the narrative (that would hide the model's reasoning); it
annotates: returns the writeup plus a list of unverified tokens, and the report/
UI render the narrative under an explicit "AI-generated — unverified" label with
the invented specifics marked.

Stdlib only. Never raises.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Set, Tuple

_HOST_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.IGNORECASE)
_URLPATH_RE = re.compile(r"https?://[^/\s]+(/[^\s'\"<>)\]]*)", re.IGNORECASE)
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Hosts/paths that are legitimate to mention even if not in this scan's evidence
# (well-known internal/metadata endpoints an operator expects in SSRF narratives).
_ALLOW_TOKENS = {
    "metadata.google.internal", "169.254.169.254", "localhost", "127.0.0.1",
    "example.com", "attacker.com", "evil.com",
}


def _norm_path(p: str) -> str:
    return (p or "").rstrip("/").lower()


def check(writeup: Dict[str, Any], evidence) -> Tuple[Dict[str, Any], List[Dict[str, str]]]:
    """Annotate `writeup` in place-ish and return (writeup, unverified[]).

    `evidence` is the ai_analyst.evidence.Evidence object (or any object exposing
    `.hosts` and `.endpoints`/`.items`)."""
    known_hosts: Set[str] = set(h.lower() for h in getattr(evidence, "hosts", []) or [])
    known_paths: Set[str] = set()
    for ep in getattr(evidence, "endpoints", []) or []:
        u = ep.get("sample_url") or ep.get("url") or ""
        m = _URLPATH_RE.match(u)
        if m:
            known_paths.add(_norm_path(m.group(1)))
    for it in getattr(evidence, "items", []) or []:
        m = _URLPATH_RE.match(getattr(it, "url", "") or "")
        if m:
            known_paths.add(_norm_path(m.group(1)))

    target = (getattr(evidence, "target", "") or "").lower().lstrip("*.")

    def _host_ok(h: str) -> bool:
        h = h.lower()
        return (h in known_hosts or h in _ALLOW_TOKENS
                or (target and (h == target or h.endswith("." + target))))

    # Gather every textual field the model produced.
    blobs: List[Tuple[str, str]] = []
    if writeup.get("executive_summary"):
        blobs.append(("executive_summary", writeup["executive_summary"]))
    if writeup.get("coverage"):
        blobs.append(("coverage", writeup["coverage"]))
    for i, f in enumerate(writeup.get("findings") or []):
        for k in ("narrative", "poc", "impact"):
            if f.get(k):
                blobs.append((f"finding[{i}].{k}", f[k]))
    for i, c in enumerate(writeup.get("chains") or []):
        for step in (c.get("path") or []):
            blobs.append((f"chain[{i}]", str(step)))

    unverified: List[Dict[str, str]] = []
    seen = set()
    for where, text in blobs:
        for h in _HOST_RE.findall(text):
            if not _host_ok(h) and h.lower() not in seen:
                seen.add(h.lower())
                unverified.append({"where": where, "type": "host", "token": h})
        for ip in _IP_RE.findall(text):
            if ip not in _ALLOW_TOKENS and ip not in seen:
                seen.add(ip)
                unverified.append({"where": where, "type": "ip", "token": ip})
        for m in _URLPATH_RE.finditer(text):
            p = _norm_path(m.group(1))
            if p and p not in known_paths and ("path:" + p) not in seen:
                seen.add("path:" + p)
                unverified.append({"where": where, "type": "url_path", "token": m.group(0)})

    writeup["_unverified_tokens"] = unverified
    writeup["_narrative_verified"] = (len(unverified) == 0)
    return writeup, unverified
