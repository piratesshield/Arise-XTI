#!/usr/bin/env python3
"""
ARISE — WebSocket / WSS Specialist  (R6, Module 24-WSS)
=======================================================
The WMS engagement's most interesting boundary was a persistent `wss://…/pconnect`
connection, and the pipeline treated WSS as HTTP. A WebSocket is a first-class
asset with its own authorization model; `offensive_verify.py` only had a single
CSWSH origin check. This is the dedicated specialist.

It learns each WSS endpoint from REAL traffic first (har_websockets.jsonl:
observed auth tokens + inferred message schema) and then runs differential,
scope-safe handshake tests, stamping each result on the L0-L6 evidence ladder.
Only L3+ (security-differential and up) becomes a finding.

Handshake test suite (default — non-mutating, connection-level)
---------------------------------------------------------------
  cswsh              foreign Origin accepted at upgrade (101) → cross-site
                     WebSocket hijacking. Differential: a clearly-foreign origin
                     is accepted the same as the legit one.
  origin_missing     upgrade with NO Origin header accepted.
  auth_binding       upgrade with the observed auth tokens STRIPPED still returns
                     101, where the captured connection carried auth → the socket
                     isn't bound to the session (the WMS question, at the
                     protocol boundary).

Frame-level tests (opt-in, --active-frames — sends into the socket)
-------------------------------------------------------------------
  schema_probe       after a tokenless connect, send one schema-shaped but inert
                     message and observe whether the server processes it.

Input
-----
  <scan>/00_har_ingest/har_websockets.jsonl        (targets, tokens, schema)
  <scan>/08_directory_discovery/discovered_endpoints.jsonl   (protocol=ws/wss)

Output
------
  <scan>/24_advanced_attacks/wss_findings.jsonl     (superset of offensive schema)

Usage
-----
  python3 wss_agent.py <scan_dir> [--target T] [--active-frames]
                       [--max-targets N] [--timeout S]
"""

from __future__ import annotations

import sys as _sys, os as _os
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)


import argparse
import json
import sys
import urllib.parse
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Dict, List, Optional

from evidence.protocol_exec import WSConnection

try:
    from evidence.arise_evidence import ladder_meta, climb, is_confirmed
except Exception:  # pragma: no cover
    def ladder_meta(r):  # type: ignore
        return {"code": r, "name": r, "confirmed": r >= "L4"}
    def climb(a, b):  # type: ignore
        return max(a, b)
    def is_confirmed(r):  # type: ignore
        return r >= "L4"

try:
    from ai.ai_probing import ScopeGuard
except Exception:  # pragma: no cover
    ScopeGuard = None


def log(msg: str) -> None:
    print(f"[wss] {msg}", file=sys.stderr, flush=True)


FOREIGN_ORIGIN = "https://arise-evil.example"


@dataclass
class WssFinding:
    check: str
    module: str = "wss_agent"
    severity: str = "medium"
    title: str = ""
    host: str = ""
    url: str = ""
    protocol: str = "wss"
    evidence: str = ""
    remediation: str = ""
    confidence: str = "confirmed"
    evidence_rung: str = "L3"
    rung_name: str = ""
    verification: str = "differential"
    baseline: Dict = field(default_factory=dict)
    attack: Dict = field(default_factory=dict)


def _read_jsonl(path: Path) -> List[dict]:
    out: List[dict] = []
    if not path.exists():
        return out
    for line in path.read_text(errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
            if isinstance(r, dict):
                out.append(r)
        except Exception:
            continue
    return out


class WssAgent:
    def __init__(self, scan_dir: Path, target: str = "", timeout: int = 10,
                 active_frames: bool = False, max_targets: int = 40):
        self.scan_dir = scan_dir
        self.target = target
        self.timeout = timeout
        self.active_frames = active_frames
        self.max_targets = max_targets
        self.findings: List[WssFinding] = []
        self.scope = None
        if ScopeGuard is not None and target:
            try:
                self.scope = ScopeGuard(target)
            except Exception:
                self.scope = None

    def _in_scope(self, url: str) -> bool:
        if self.scope is None:
            return True
        try:
            # ScopeGuard speaks http(s); normalise ws→http for the check
            probe = url.replace("wss://", "https://").replace("ws://", "http://")
            return self.scope.in_scope(probe)
        except Exception:
            return True

    def targets(self) -> List[dict]:
        seen, out = set(), []
        for rec in _read_jsonl(self.scan_dir / "00_har_ingest" / "har_websockets.jsonl"):
            u = rec.get("url")
            if u and u not in seen and self._in_scope(u):
                seen.add(u)
                out.append(rec)
        # also any inventory endpoint classified ws/wss
        for rec in _read_jsonl(self.scan_dir / "08_directory_discovery" /
                               "discovered_endpoints.jsonl"):
            if (rec.get("protocol") or "").lower() in ("ws", "wss"):
                u = rec.get("sample_url") or rec.get("url")
                if u and u not in seen and self._in_scope(u):
                    seen.add(u)
                    out.append({"url": u, "host": rec.get("host"),
                                "auth_tokens_observed": [], "inferred_schema": {}})
        return out[: self.max_targets]

    def run(self) -> Dict[str, int]:
        tgts = self.targets()
        if not tgts:
            log("no WSS targets (need har_websockets.jsonl or ws-classed inventory)")
            self._write()
            return {"targets": 0, "findings": 0}
        log(f"testing {len(tgts)} WSS endpoint(s), "
            f"frame-level={'on' if self.active_frames else 'off'}")
        for t in tgts:
            try:
                self._test_endpoint(t)
            except Exception as e:
                log(f"error on {t.get('url')}: {e}")
        self._write()
        confirmed = sum(1 for f in self.findings if is_confirmed(f.evidence_rung))
        log(f"done: {len(self.findings)} finding(s) ({confirmed} confirmed L4+)")
        return {"targets": len(tgts), "findings": len(self.findings)}

    def _test_endpoint(self, t: dict) -> None:
        url = t["url"]
        host = t.get("host") or urllib.parse.urlsplit(url).hostname or ""
        tokens = t.get("auth_tokens_observed") or []
        legit_origin = self._legit_origin(url, host)

        # --- baseline: does a legit-origin handshake succeed at all? ---
        base = WSConnection(url, origin=legit_origin, timeout=self.timeout)
        bhs = base.connect()
        base.close()
        if not bhs.ok and bhs.status != 101:
            # endpoint didn't upgrade even legitimately — record as observed only,
            # never escalate (this is the "200 ≠ vuln" discipline for WSS).
            return

        # --- cswsh: foreign origin accepted? ---
        eviln = WSConnection(url, origin=FOREIGN_ORIGIN, timeout=self.timeout)
        ehs = eviln.connect()
        eviln.close()
        if ehs.ok:
            # differential: foreign origin upgraded exactly like the legit one
            self._finding(
                "cswsh", "high", "Cross-Site WebSocket Hijacking (origin not enforced)",
                host, url,
                evidence=(f"upgrade succeeded (101) with a foreign Origin "
                          f"'{FOREIGN_ORIGIN}'; the legit origin also upgraded — "
                          f"the server does not validate Origin on the WS handshake"),
                rung="L4",
                remediation="Validate the Origin header on the WebSocket upgrade "
                            "and bind the connection to the authenticated session.",
                baseline={"origin": legit_origin, "status": bhs.status},
                attack={"origin": FOREIGN_ORIGIN, "status": ehs.status,
                        "accept_valid": ehs.accept_valid})

        # --- origin_missing: no Origin header accepted? ---
        noorigin = WSConnection(url, origin=None, timeout=self.timeout)
        nhs = noorigin.connect()
        noorigin.close()
        if nhs.ok and not ehs.ok:
            # only report separately when the foreign-origin test didn't already
            # cover it (avoid double-reporting the same weakness)
            self._finding(
                "origin_missing", "medium",
                "WebSocket upgrade accepted with no Origin header", host, url,
                evidence="upgrade succeeded (101) with the Origin header absent",
                rung="L3",
                remediation="Reject WebSocket upgrades that omit a valid, allow-"
                            "listed Origin.",
                baseline={"origin": legit_origin, "status": bhs.status},
                attack={"origin": None, "status": nhs.status})

        # --- auth_binding: strip observed auth tokens, still upgrades? ---
        if tokens:
            bare = WSConnection(url, origin=legit_origin, timeout=self.timeout)
            # deliberately send NO auth headers/cookies
            ahs = bare.connect()
            bare.close()
            if ahs.ok:
                self._finding(
                    "auth_binding", "high",
                    "WebSocket not bound to session (connects without observed auth)",
                    host, url,
                    evidence=(f"the captured connection carried auth "
                              f"({', '.join(tokens[:4])}), but an upgrade with "
                              f"those tokens stripped still returned 101 — the "
                              f"socket is not bound to the authenticated session"),
                    rung="L4",
                    remediation="Require and verify the session/auth token during "
                                "the WebSocket handshake; reject unauthenticated "
                                "upgrades.",
                    baseline={"auth_tokens": tokens, "status": bhs.status},
                    attack={"auth_tokens": [], "status": ahs.status})

        # --- frame-level (opt-in) ---
        if self.active_frames:
            self._frame_probe(t, url, host, legit_origin)

    def _frame_probe(self, t: dict, url: str, host: str, origin: str) -> None:
        schema = t.get("inferred_schema") or {}
        if not schema.get("json") or not schema.get("keys"):
            return
        # Build one INERT, schema-shaped message (no injection, no state change):
        # echo the observed discriminator with benign values.
        msg = {k: "" for k in schema["keys"][:8]}
        for disc in (schema.get("discriminators") or [])[:1]:
            if "=" in disc:
                k, v = disc.split("=", 1)
                msg[k] = v
        conn = WSConnection(url, origin=origin, timeout=self.timeout)
        hs = conn.connect()
        if not hs.ok:
            conn.close()
            return
        sent = conn.send_text(json.dumps(msg))
        reply = conn.recv(timeout=self.timeout) if sent else None
        conn.close()
        if reply is not None:
            op, payload = reply
            self._finding(
                "schema_probe", "info",
                "WebSocket processes tokenless schema-shaped message", host, url,
                evidence=(f"after a handshake, a schema-shaped inert message "
                          f"({sorted(msg.keys())}) was accepted and the server "
                          f"replied (opcode={op}, {len(payload)}B) — the message "
                          f"channel is reachable for further authz testing"),
                rung="L2",
                remediation="Ensure per-message authorization on the WebSocket, "
                            "not just at handshake.",
                baseline={}, attack={"sent_keys": sorted(msg.keys())})

    def _legit_origin(self, url: str, host: str) -> str:
        h = host or urllib.parse.urlsplit(url).hostname or ""
        return f"https://{h}"

    def _finding(self, check, severity, title, host, url, *, evidence, rung,
                 remediation, baseline, attack) -> None:
        meta = ladder_meta(rung)
        self.findings.append(WssFinding(
            check=check, severity=severity, title=title, host=host, url=url,
            evidence=evidence, remediation=remediation, evidence_rung=rung,
            rung_name=meta["name"], baseline=baseline, attack=attack,
            confidence="confirmed" if meta["confirmed"] else "candidate"))

    def _write(self) -> None:
        out_dir = self.scan_dir / "24_advanced_attacks"
        out_dir.mkdir(parents=True, exist_ok=True)
        out = out_dir / "wss_findings.jsonl"
        with out.open("w") as fh:
            for f in self.findings:
                fh.write(json.dumps(asdict(f)) + "\n")
        (out_dir / "wss_findings_summary.json").write_text(json.dumps({
            "module": "wss_agent",
            "findings": len(self.findings),
            "confirmed": sum(1 for f in self.findings if is_confirmed(f.evidence_rung)),
            "by_check": _count(self.findings, "check"),
        }, indent=2))


def _count(items, attr) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for it in items:
        k = getattr(it, attr)
        out[k] = out.get(k, 0) + 1
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="ARISE WSS specialist")
    ap.add_argument("scan_dir")
    ap.add_argument("--target", default="")
    ap.add_argument("--active-frames", action="store_true",
                    help="also send inert schema-shaped frames into the socket "
                         "(opt-in; connection-level tests run without it)")
    ap.add_argument("--max-targets", type=int, default=40)
    ap.add_argument("--timeout", type=int, default=10)
    args = ap.parse_args()
    scan_dir = Path(args.scan_dir)
    if not scan_dir.is_dir():
        log(f"scan-dir not found: {scan_dir}")
        return 1
    WssAgent(scan_dir, target=args.target, timeout=args.timeout,
             active_frames=args.active_frames,
             max_targets=args.max_targets).run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
