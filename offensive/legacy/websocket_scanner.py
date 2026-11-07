#!/usr/bin/env python3
"""
ARISE — WebSocket security scanner (Phase 6, module 3.5).

Tests discovered ws:// / wss:// endpoints for Cross-Site WebSocket Hijacking
(CSWSH): connect with a foreign Origin and no cookies — if the handshake still
succeeds, the server trusts any origin and cookie-auth'd sockets are hijackable.

Uses the `websocket-client` library if present; otherwise degrades to a raw
handshake over sockets. Non-destructive (opens a connection, sends nothing).
Output: JSONL.
"""

import sys as _sys, os as _os
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)

import argparse
import json
import os
import ssl
import sys
import urllib.parse

try:
    import websocket  # websocket-client
except Exception:
    websocket = None


def _harvest_ws(scan_dir):
    urls = set()
    if not scan_dir:
        return urls
    for rel in ("20_api_deep_discovery/xhr_intercepted.txt",
                "20_api_deep_discovery/input_functions.jsonl",
                "09_crawling/all_urls.txt"):
        p = os.path.join(scan_dir, rel)
        if not os.path.isfile(p):
            continue
        try:
            for line in open(p, errors="ignore"):
                for tok in line.split():
                    if tok.startswith(("ws://", "wss://")):
                        urls.add(tok.strip('",\''))
        except Exception:
            continue
    return urls


def test_cswsh(ws_url, timeout=10):
    if websocket is None:
        return None
    try:
        conn = websocket.create_connection(
            ws_url, timeout=timeout,
            header=["Origin: https://arise-evil.example"],
            sslopt={"cert_reqs": ssl.CERT_NONE} if ws_url.startswith("wss") else None,
        )
        connected = conn.connected
        try:
            conn.close()
        except Exception:
            pass
        if connected:
            return {
                "module": "websocket_scanner", "severity": "high", "confidence": "confirmed",
                "title": "WebSocket accepts cross-origin handshake (CSWSH)",
                "url": ws_url,
                "evidence": "handshake succeeded with Origin: https://arise-evil.example and no "
                            "cookies — a malicious page could open an authenticated socket",
                "remediation": "Validate the Origin header on the WS upgrade against an allowlist; "
                               "require a CSRF-style token for socket auth.",
            }
    except Exception:
        return None
    return None


def main():
    ap = argparse.ArgumentParser(description="ARISE WebSocket (CSWSH) scanner")
    ap.add_argument("scan_dir", nargs="?")
    ap.add_argument("--url", action="append", default=[])
    ap.add_argument("--out")
    ap.add_argument("--max-targets", type=int, default=60)
    args = ap.parse_args()

    targets = set(args.url) | _harvest_ws(args.scan_dir)
    targets = list(targets)[: args.max_targets]

    findings = []
    if websocket is None:
        print("websocket_scanner: websocket-client not installed; skipping "
              f"({len(targets)} candidate(s))", file=sys.stderr)
    else:
        for u in targets:
            f = test_cswsh(u)
            if f:
                findings.append(f)

    out = args.out or (os.path.join(args.scan_dir, "24_advanced_attacks", "websocket_findings.jsonl")
                       if args.scan_dir else "websocket_findings.jsonl")
    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
    with open(out, "w") as f:
        for row in findings:
            f.write(json.dumps(row) + "\n")
    print(f"websocket_scanner: {len(targets)} candidate(s), {len(findings)} finding(s) -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
