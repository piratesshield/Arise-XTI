#!/usr/bin/env python3
"""
ARISE — DNS-over-HTTPS fallback resolver
========================================
When the pipeline's normal resolver (dnsx over the local/system :53 resolver)
returns nothing — or returns HIJACKED answers (every host pointing at the
scanner's own egress IP, or at private/reserved space) — the whole scan dies
silently: no resolved.txt → no httpx targets → no http_hosts → every downstream
module skips. That is exactly what happened to www.toursgds.com.

This module resolves the SAME host list over DoH (HTTPS/443) against Cloudflare
(1.1.1.1) and Google (8.8.8.8). Port 443 is not subject to the :53 UDP
interception, captive-portal redirection, or ISP hijack that breaks plain DNS,
so it recovers the real answers.

Output is byte-compatible with `dnsx -json` (one JSON object per line with
`host`, `a`, `cname`), so Module 3's existing jq extraction is unchanged.

Two entry points:
  resolve   — resolve a host list over DoH → dnsx-format JSONL
  is-hijacked (default via --check) — report whether a dnsx result file looks
              empty / reflected / hijacked, so the caller can decide to re-run.
"""
from __future__ import annotations

import sys as _sys, os as _os
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)


import argparse
import ipaddress
import json
import os
import ssl
import sys
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

# Pure-Python, OS-independent transport. No external binaries (no curl), no
# platform branches — runs identically on macOS, Linux and Windows.
#
# The one portability wrinkle is the TLS trust store: a bare
# ssl.create_default_context() cannot verify https://1.1.1.1 on macOS framework
# Python builds (they ship no CA bundle). We resolve a CA bundle in a
# platform-neutral order — env override → certifi (cross-platform bundled CA,
# already a transitive dep via requests) → the OS default store — so the same
# code path works everywhere.


def _make_ssl_context() -> ssl.SSLContext:
    # 1) explicit override (SSL_CERT_FILE / REQUESTS_CA_BUNDLE)
    for env in ("SSL_CERT_FILE", "REQUESTS_CA_BUNDLE"):
        p = os.environ.get(env)
        if p and os.path.exists(p):
            try:
                return ssl.create_default_context(cafile=p)
            except Exception:
                pass
    # 2) certifi — identical CA bundle on every OS
    try:
        import certifi  # type: ignore
        return ssl.create_default_context(cafile=certifi.where())
    except Exception:
        pass
    # 3) OS default trust store (Linux distros, Windows, configured macOS)
    return ssl.create_default_context()


_SSL_CTX = _make_ssl_context()


def _http_get(url: str, accept: str | None, timeout: int) -> str | None:
    """GET a URL over HTTPS, returning the body text, or None on any failure."""
    headers = {"User-Agent": "arise-doh/1.0"}
    if accept:
        headers["accept"] = accept
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_SSL_CTX) as resp:
            return resp.read().decode("utf-8", "ignore")
    except Exception:
        return None

# DoH JSON endpoints (both speak the application/dns-json schema).
DOH_ENDPOINTS = [
    ("cloudflare", "https://1.1.1.1/dns-query"),
    ("google",     "https://8.8.8.8/resolve"),
]
TRACE_URL = "https://1.1.1.1/cdn-cgi/trace"  # returns ip=<caller public ip>

TYPE_A = 1
TYPE_CNAME = 5


def _doh_query(host: str, endpoint: str, timeout: int = 8) -> dict | None:
    """One DoH JSON query for an A record. Returns parsed JSON or None."""
    qs = urllib.parse.urlencode({"name": host, "type": "A"})
    body = _http_get(f"{endpoint}?{qs}", accept="application/dns-json", timeout=timeout)
    if not body:
        return None
    try:
        return json.loads(body)
    except Exception:
        return None


def resolve_host(host: str, timeout: int = 8) -> dict:
    """Resolve one host over DoH (CF first, Google fallback). dnsx-shaped dict."""
    host = host.strip().rstrip(".")
    if not host:
        return {}
    for name, ep in DOH_ENDPOINTS:
        data = _doh_query(host, ep, timeout=timeout)
        if not data or data.get("Status") != 0:
            continue
        a, cname = [], []
        for ans in data.get("Answer") or []:
            t = ans.get("type")
            val = (ans.get("data") or "").rstrip(".")
            if t == TYPE_A:
                a.append(val)
            elif t == TYPE_CNAME:
                cname.append(val)
        if a:  # only accept an answer that actually yields an A record
            rec = {"host": host, "a": sorted(set(a)),
                   "resolver": [f"doh:{name}"], "status_code": "NOERROR"}
            if cname:
                rec["cname"] = cname
            return rec
    return {}  # both providers failed / NXDOMAIN


def source_public_ip(timeout: int = 8) -> str | None:
    """The scanner's own egress IP, via Cloudflare trace (used for hijack test)."""
    body = _http_get(TRACE_URL, accept=None, timeout=timeout)
    if not body:
        return None
    for line in body.splitlines():
        if line.startswith("ip="):
            return line[3:].strip()
    return None


def _ips_from_dnsx(path: str) -> list[str]:
    ips = []
    try:
        with open(path, errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    r = json.loads(line)
                except Exception:
                    continue
                ips.extend(r.get("a") or [])
    except FileNotFoundError:
        return []
    return ips


def is_hijacked(dnsx_json: str, source_ip: str | None) -> tuple[bool, str]:
    """
    Decide whether a dnsx result file is untrustworthy and DoH should take over.
    Returns (should_refetch, reason).
    """
    ips = _ips_from_dnsx(dnsx_json)
    if not ips:
        return True, "empty (resolver returned no A records)"

    uniq = set(ips)

    # 1) Reflection: answers point at the scanner's own egress IP.
    if source_ip and uniq <= {source_ip}:
        return True, f"reflected: all answers == source IP {source_ip}"
    if source_ip and source_ip in uniq and len(uniq) == 1:
        return True, f"reflected: single answer == source IP {source_ip}"

    # 2) Captive-portal / parking: everything collapses to one IP that is
    #    private, loopback, or reserved.
    def _bad(ip: str) -> bool:
        try:
            a = ipaddress.ip_address(ip)
            return a.is_private or a.is_loopback or a.is_reserved or a.is_unspecified
        except ValueError:
            return True

    if all(_bad(ip) for ip in uniq):
        return True, f"all answers private/reserved ({sorted(uniq)[:3]})"

    return False, "ok"


def cmd_resolve(args) -> int:
    hosts = []
    with open(args.input, errors="ignore") as f:
        for line in f:
            h = line.strip()
            if h and not h.startswith("#"):
                hosts.append(h)
    hosts = sorted(set(hosts))
    if not hosts:
        print("[doh] no hosts to resolve", file=sys.stderr)
        open(args.output, "w").close()
        return 0

    results, ok = [], 0
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = {ex.submit(resolve_host, h, args.timeout): h for h in hosts}
        for fut in as_completed(futs):
            rec = fut.result()
            if rec:
                results.append(rec)
                ok += 1

    with open(args.output, "w") as w:
        for rec in results:
            w.write(json.dumps(rec) + "\n")
    print(f"[doh] resolved {ok}/{len(hosts)} host(s) over DoH -> {args.output}",
          file=sys.stderr)
    return 0


def cmd_check(args) -> int:
    src = source_public_ip() if not args.no_source else None
    hijacked, reason = is_hijacked(args.dnsx_json, src)
    # machine-readable one-liner for bash to consume
    print(json.dumps({"refetch": hijacked, "reason": reason, "source_ip": src}))
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="ARISE DoH fallback resolver")
    sub = ap.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("resolve", help="resolve a host list over DoH")
    r.add_argument("--input", required=True, help="hostnames, one per line")
    r.add_argument("--output", required=True, help="dnsx-format JSONL output")
    r.add_argument("--workers", type=int, default=20)
    r.add_argument("--timeout", type=int, default=8)
    r.set_defaults(func=cmd_resolve)

    c = sub.add_parser("check", help="is a dnsx result file empty/reflected/hijacked?")
    c.add_argument("--dnsx-json", required=True, help="dnsx -json output to inspect")
    c.add_argument("--no-source", action="store_true",
                   help="skip source-IP lookup (reflection test disabled)")
    c.set_defaults(func=cmd_check)

    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
