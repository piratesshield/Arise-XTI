#!/usr/bin/env python3
"""
ARISE — Protocol-Context Execution Engine  (R7)
===============================================
The strongest WMS technical lesson: a test must run in the SAME protocol and
session context the application actually uses. A raw `requests` replay returned
400 where the browser returned 200 — not a vulnerability, just the wrong
execution channel. This module is the shared router other attack modules call
to send a request through the RIGHT channel:

    HTTP/HTTPS   → requests (or urllib fallback)
    WS/WSS       → a native RFC 6455 client (stdlib only — no `websockets` dep)
    browser      → deferred to the CDP runtime (input_discovery/chrome_service);
                   here we only DECIDE it's needed and say so, so a caller can
                   route it, rather than silently sending a synthetic request
                   that will misfire.

It is a library (import it), with a small CLI for smoke-testing a WSS handshake.

Design
------
  * `choose_channel(endpoint)` — from provenance + protocol, pick http|ws|browser.
  * `WSConnection` — native WebSocket: handshake, masked send, framed recv,
    close. Enough to test auth-binding / CSWSH / schema mutation without pip.
  * Never raises to the caller; every failure is a returned status/None.

Scope must still be enforced by the CALLER (ScopeGuard) before invoking send —
this module executes what it's told; it does not decide targets.
"""

from __future__ import annotations

import sys as _sys, os as _os
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)


import argparse
import base64
import hashlib
import os
import socket
import ssl
import struct
import sys
import urllib.parse
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

try:
    import requests
    requests.packages.urllib3.disable_warnings()  # type: ignore
    _HAVE_REQUESTS = True
except Exception:  # pragma: no cover
    requests = None
    _HAVE_REQUESTS = False

try:
    from evidence.arise_evidence import is_real_traffic
except Exception:  # pragma: no cover
    def is_real_traffic(p):  # type: ignore
        return (p or "") in ("har", "browser", "api-runtime")

_WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def log(msg: str) -> None:
    print(f"[proto-exec] {msg}", file=sys.stderr, flush=True)


# ---------------------------------------------------------------------------
# Channel selection
# ---------------------------------------------------------------------------
def choose_channel(endpoint: dict, *, prior_synthetic_status: Optional[int] = None
                   ) -> str:
    """Return 'ws' | 'browser' | 'http' for how this endpoint should be exercised.

    endpoint: a discovered_endpoints / har_assets style dict with at least
    `protocol`, `provenance` (or `source`), and optionally `auth_state`.
    prior_synthetic_status: if a raw replay was already tried and failed (4xx),
    that's a strong signal browser context is required (the WMS 400 case).
    """
    proto = (endpoint.get("protocol") or "").lower()
    if proto in ("ws", "wss"):
        return "ws"
    prov = (endpoint.get("provenance")
            or endpoint.get("source") or "").lower()

    # Real browser traffic that a synthetic replay can't reproduce → browser.
    if is_real_traffic(prov):
        if prior_synthetic_status is not None and prior_synthetic_status >= 400:
            return "browser"
        # HttpOnly+SameSite session cookies aren't reproducible outside a browser
        toks = endpoint.get("auth_tokens_observed") or []
        if any("cookie:" in t for t in toks) and endpoint.get("auth_state") == "auth-required":
            return "browser"
    return "http"


# ---------------------------------------------------------------------------
# HTTP channel
# ---------------------------------------------------------------------------
@dataclass
class HttpResult:
    ok: bool
    status: int = 0
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    error: str = ""


def http_send(method: str, url: str, *, headers: Optional[dict] = None,
              data=None, timeout: int = 12, allow_redirects: bool = False,
              cookies: Optional[dict] = None) -> HttpResult:
    """Send over HTTP(S) using requests when available, urllib otherwise."""
    headers = headers or {}
    if _HAVE_REQUESTS:
        try:
            r = requests.request(method.upper(), url, headers=headers, data=data,
                                 timeout=timeout, allow_redirects=allow_redirects,
                                 verify=False, cookies=cookies)
            return HttpResult(True, r.status_code, dict(r.headers),
                              r.text[:65536])
        except Exception as e:
            return HttpResult(False, error=str(e))
    # urllib fallback
    import urllib.request, urllib.error
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    body = data.encode() if isinstance(data, str) else data
    req = urllib.request.Request(url, data=body, method=method.upper())
    for k, v in headers.items():
        req.add_header(k, v)
    if cookies:
        req.add_header("Cookie", "; ".join(f"{k}={v}" for k, v in cookies.items()))
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return HttpResult(True, resp.status, dict(resp.headers),
                              resp.read(65536).decode("utf-8", "ignore"))
    except urllib.error.HTTPError as e:
        return HttpResult(True, e.code,
                          dict(e.headers) if e.headers else {},
                          (e.read(65536).decode("utf-8", "ignore") if e.fp else ""))
    except Exception as e:
        return HttpResult(False, error=str(e))


# ---------------------------------------------------------------------------
# WebSocket channel — native RFC 6455 client
# ---------------------------------------------------------------------------
@dataclass
class WSHandshake:
    ok: bool
    status: int = 0
    accept_valid: bool = False
    headers: Dict[str, str] = field(default_factory=dict)
    error: str = ""


class WSConnection:
    """Minimal, correct RFC 6455 client. Handshake, masked text send, framed
    recv, close. Stdlib only. Not raise-y: check `.handshake.ok`."""

    OP_TEXT, OP_BINARY, OP_CLOSE, OP_PING, OP_PONG = 0x1, 0x2, 0x8, 0x9, 0xA

    def __init__(self, url: str, *, origin: Optional[str] = None,
                 headers: Optional[dict] = None, timeout: int = 10):
        self.url = url
        self.origin = origin
        self.extra_headers = headers or {}
        self.timeout = timeout
        self.sock: Optional[socket.socket] = None
        self.handshake = WSHandshake(ok=False)
        self._buf = b""

    def connect(self) -> WSHandshake:
        try:
            p = urllib.parse.urlsplit(self.url)
        except Exception as e:
            self.handshake = WSHandshake(False, error=f"bad url: {e}")
            return self.handshake
        secure = p.scheme in ("wss", "https")
        host = p.hostname or ""
        port = p.port or (443 if secure else 80)
        path = p.path or "/"
        if p.query:
            path += "?" + p.query
        key = base64.b64encode(os.urandom(16)).decode()

        lines = [
            f"GET {path} HTTP/1.1",
            f"Host: {host}:{port}" if p.port else f"Host: {host}",
            "Upgrade: websocket",
            "Connection: Upgrade",
            f"Sec-WebSocket-Key: {key}",
            "Sec-WebSocket-Version: 13",
            "User-Agent: ARISE-wss-agent",
        ]
        if self.origin is not None:
            lines.append(f"Origin: {self.origin}")
        for k, v in self.extra_headers.items():
            lines.append(f"{k}: {v}")
        raw = ("\r\n".join(lines) + "\r\n\r\n").encode()

        try:
            sock = socket.create_connection((host, port), timeout=self.timeout)
            if secure:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=host)
            sock.settimeout(self.timeout)
            sock.sendall(raw)
            resp = self._read_until(b"\r\n\r\n")
            self.sock = sock
        except Exception as e:
            self.handshake = WSHandshake(False, error=str(e))
            return self.handshake

        head = resp.decode("iso-8859-1", "ignore")
        status = 0
        try:
            status = int(head.split(" ", 2)[1])
        except Exception:
            pass
        headers = {}
        for ln in head.split("\r\n")[1:]:
            if ":" in ln:
                k, v = ln.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        expected = base64.b64encode(
            hashlib.sha1((key + _WS_GUID).encode()).digest()).decode()
        accept_ok = headers.get("sec-websocket-accept") == expected
        self.handshake = WSHandshake(
            ok=(status == 101 and accept_ok), status=status,
            accept_valid=accept_ok, headers=headers)
        return self.handshake

    def _read_until(self, delim: bytes) -> bytes:
        data = b""
        while delim not in data:
            chunk = self.sock.recv(4096) if self.sock else self._raw_recv()
            if not chunk:
                break
            data += chunk
            if len(data) > 65536:
                break
        return data

    def _raw_recv(self) -> bytes:
        return b""

    def send_text(self, text: str) -> bool:
        return self._send(self.OP_TEXT, text.encode("utf-8"))

    def _send(self, opcode: int, payload: bytes) -> bool:
        if not self.sock:
            return False
        fin_op = 0x80 | opcode
        mask = os.urandom(4)
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        n = len(payload)
        header = bytes([fin_op])
        if n < 126:
            header += bytes([0x80 | n])
        elif n < 65536:
            header += bytes([0x80 | 126]) + struct.pack(">H", n)
        else:
            header += bytes([0x80 | 127]) + struct.pack(">Q", n)
        try:
            self.sock.sendall(header + mask + masked)
            return True
        except Exception:
            return False

    def recv(self, timeout: Optional[float] = None) -> Optional[Tuple[int, bytes]]:
        """Receive one frame → (opcode, payload). None on timeout/close/error."""
        if not self.sock:
            return None
        if timeout is not None:
            self.sock.settimeout(timeout)
        try:
            two = self._recv_n(2)
            if len(two) < 2:
                return None
            b0, b1 = two[0], two[1]
            opcode = b0 & 0x0F
            masked = b1 & 0x80
            ln = b1 & 0x7F
            if ln == 126:
                ln = struct.unpack(">H", self._recv_n(2))[0]
            elif ln == 127:
                ln = struct.unpack(">Q", self._recv_n(8))[0]
            mask = self._recv_n(4) if masked else b""
            payload = self._recv_n(ln) if ln else b""
            if masked and mask:
                payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
            return (opcode, payload)
        except Exception:
            return None

    def _recv_n(self, n: int) -> bytes:
        while len(self._buf) < n:
            try:
                chunk = self.sock.recv(max(4096, n - len(self._buf)))
            except Exception:
                break
            if not chunk:
                break
            self._buf += chunk
        out, self._buf = self._buf[:n], self._buf[n:]
        return out

    def close(self) -> None:
        try:
            if self.sock:
                self._send(self.OP_CLOSE, b"")
                self.sock.close()
        except Exception:
            pass
        finally:
            self.sock = None


def main() -> int:
    ap = argparse.ArgumentParser(description="ARISE protocol-exec smoke test")
    ap.add_argument("url", help="ws:// or wss:// URL to handshake-test")
    ap.add_argument("--origin", default=None)
    args = ap.parse_args()
    ws = WSConnection(args.url, origin=args.origin)
    hs = ws.connect()
    log(f"handshake ok={hs.ok} status={hs.status} accept_valid={hs.accept_valid} "
        f"error={hs.error or '-'}")
    ws.close()
    return 0 if hs.ok else 2


if __name__ == "__main__":
    sys.exit(main())
