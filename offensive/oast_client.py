#!/usr/bin/env python3
"""
ARISE — Out-of-Band (OAST) Confirmation Client  (Offensive AI Elevation, Phase 6)
=================================================================================
Blind vuln classes (blind SSRF / blind RCE / blind XXE / blind SQLi) cannot be
confirmed from the response alone — adaptive_loop ships a placeholder
`arise-oob.example` and gives up. This is a pure FP-REDUCTION play: an
out-of-band interaction is CONCLUSIVE proof, so a class that today can only be
reported as "probable" becomes L5 (impact-demonstrated) — or is dropped.

How it stays safe (do no harm):
  * OFF BY DEFAULT. With no collector configured, `mint_token()` returns None and
    `poll()` returns []. It NEVER fabricates an interaction, so it can only ever
    REMOVE uncertainty, never add a finding on its own.
  * Pluggable backend: a null backend (default), or a generic self-hosted HTTP
    collector configured via env (ARISE_OAST_SERVER + optional ARISE_OAST_KEY).
    interactsh-compatible collectors expose the same register/poll shape.
  * Unique per-probe token so a received interaction is attributable to exactly
    one payload/endpoint — no cross-talk, no guessing.
  * Integrates with evidence/arise_evidence: a real interaction stamps L5.
  * Never raises to the caller.

Stdlib only (+ requests only when an HTTP collector is actually configured).
"""

from __future__ import annotations

import sys as _sys
import os
import uuid
import time
from dataclasses import dataclass
from typing import Dict, List, Optional

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)

try:
    from evidence import arise_evidence as _ev
except Exception:  # pragma: no cover
    _ev = None


# ---------------------------------------------------------------------------
# Backends
# ---------------------------------------------------------------------------
class OastBackend:
    """Interface: register() -> callback host (or None), poll(token) -> [interaction]."""
    enabled = False

    def register(self) -> Optional[Dict[str, str]]:
        return None

    def poll(self, token: str) -> List[dict]:
        return []


class NullBackend(OastBackend):
    """Default. No collector => no tokens, no interactions, no placeholder findings."""
    enabled = False


class HttpCollectorBackend(OastBackend):
    """Generic self-hosted collector over HTTP. Expected endpoints (interactsh-ish):
        GET  {server}/register            -> {"domain": "<collector-domain>"}  (optional)
        GET  {server}/poll?id=<token>     -> {"interactions": [ {...}, ... ]}
    The collector domain may also be pinned via ARISE_OAST_DOMAIN. Any transport
    error degrades to empty — we never block or raise the scan."""
    enabled = True

    def __init__(self, server: str, domain: Optional[str] = None, key: Optional[str] = None):
        self.server = server.rstrip("/")
        self.domain = domain
        self.key = key

    def _get(self, path: str) -> Optional[dict]:
        try:
            import requests
        except Exception:
            return None
        try:
            headers = {"Authorization": self.key} if self.key else {}
            r = requests.get(self.server + path, headers=headers, timeout=15, verify=False)
            if r.status_code // 100 != 2:
                return None
            return r.json()
        except Exception:
            return None

    def register(self) -> Optional[Dict[str, str]]:
        domain = self.domain
        if not domain:
            data = self._get("/register") or {}
            domain = data.get("domain")
        if not domain:
            return None
        token = uuid.uuid4().hex[:20]
        return {"token": token, "host": f"{token}.{domain}"}

    def poll(self, token: str) -> List[dict]:
        data = self._get(f"/poll?id={token}") or {}
        out = []
        for it in (data.get("interactions") or []):
            if isinstance(it, dict):
                out.append(it)
        return out


def _backend_from_env() -> OastBackend:
    server = os.environ.get("ARISE_OAST_SERVER", "").strip()
    if not server:
        return NullBackend()
    return HttpCollectorBackend(server,
                                domain=os.environ.get("ARISE_OAST_DOMAIN", "").strip() or None,
                                key=os.environ.get("ARISE_OAST_KEY", "").strip() or None)


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------
@dataclass
class OastClient:
    backend: OastBackend

    @classmethod
    def from_env(cls) -> "OastClient":
        return cls(_backend_from_env())

    def is_enabled(self) -> bool:
        return bool(getattr(self.backend, "enabled", False))

    def mint_token(self) -> Optional[Dict[str, str]]:
        """Return {'token','host'} for embedding in a payload, or None when OAST
        is disabled/unavailable. The caller puts `host` in the SSRF/RCE/XXE payload
        and later poll(token)."""
        if not self.is_enabled():
            return None
        try:
            return self.backend.register()
        except Exception:
            return None

    def poll(self, token: str) -> List[dict]:
        if not self.is_enabled() or not token:
            return []
        try:
            return self.backend.poll(token) or []
        except Exception:
            return []

    def to_evidence(self, interaction: dict, *, vuln_class: str, host: str = "",
                    url: str = "", payload: str = "") -> dict:
        """Turn one received interaction into a CONFIRMED (L5) lead-record for the
        reconciler. Only ever called with a REAL interaction from poll()."""
        proto = str(interaction.get("protocol") or interaction.get("proto") or "dns").lower()
        remote = interaction.get("remote-address") or interaction.get("remote_addr") or ""
        rung = "L5"
        return {
            "source": "OAST Interaction",
            "detection_tool": "oast",
            "template": f"{vuln_class} (out-of-band confirmed)",
            "title": f"Out-of-band {proto.upper()} interaction proves {vuln_class}",
            "severity": "high" if vuln_class in ("ssrf", "xxe") else "critical",
            "host": host,
            "url": url,
            "parameter": interaction.get("param", ""),
            "payload": payload,
            "impact": f"Server initiated an out-of-band {proto} callback to our "
                      f"unique collector{f' from {remote}' if remote else ''} — "
                      f"conclusive proof of {vuln_class}.",
            "evidence": f"{proto} interaction at {interaction.get('timestamp', '')}",
            "provenance": {"lane": vuln_class, "class": "oob"},
            "evidence_rung": rung,
            "confidence": "confirmed",
            "verification": "oob-interaction",
            "lead_only": False,   # an OOB callback IS the proof
        }


# ---------------------------------------------------------------------------
# Self-test (no network; fake backend)
# ---------------------------------------------------------------------------
def _selftest() -> int:
    # default (no env) => disabled, mints nothing, never a placeholder finding
    disabled = OastClient(NullBackend())
    assert disabled.is_enabled() is False
    assert disabled.mint_token() is None
    assert disabled.poll("anything") == []

    # a fake enabled backend: mint a token, receive an interaction for it
    class _Fake(OastBackend):
        enabled = True
        def register(self):
            return {"token": "abc123", "host": "abc123.oob.test"}
        def poll(self, token):
            return [{"protocol": "dns", "remote-address": "203.0.113.9",
                     "timestamp": "2026-01-01T00:00:00Z"}] if token == "abc123" else []

    c = OastClient(_Fake())
    assert c.is_enabled()
    tok = c.mint_token()
    assert tok and tok["host"].endswith(".oob.test")
    hits = c.poll(tok["token"])
    assert len(hits) == 1
    # wrong token -> nothing (attribution)
    assert c.poll("other") == []

    # a real interaction becomes CONFIRMED L5 evidence
    ev = c.to_evidence(hits[0], vuln_class="ssrf", host="x.com",
                       url="https://x.com/fetch?u=...", payload="http://abc123.oob.test/")
    assert ev["confidence"] == "confirmed"
    assert ev["evidence_rung"] == "L5"
    assert ev["lead_only"] is False
    if _ev:
        assert _ev.is_confirmed(ev["evidence_rung"]) is True

    # env wiring: no server => NullBackend
    old = os.environ.pop("ARISE_OAST_SERVER", None)
    try:
        assert OastClient.from_env().is_enabled() is False
    finally:
        if old is not None:
            os.environ["ARISE_OAST_SERVER"] = old

    print("[oast_client] self-test OK — disabled-by-default, unique-token attribution, L5 on real callback")
    return 0


if __name__ == "__main__":
    _sys.exit(_selftest())
