#!/usr/bin/env python3
"""
ARISE — Web cache poisoning scanner (Phase 6.2).

For each target URL: inject a unique canary via an unkeyed header, then re-request
WITHOUT the header. If the canary persists in the cached response, the cache is
poisonable. Non-destructive (a unique benign canary host, GET-only), but it does
write to the cache — so it is rate-limited and canary-scoped.

Output: JSONL findings to --out.
"""

import sys as _sys, os as _os
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)

import argparse
import json
import os
import sys
import time
import uuid
import urllib.parse

try:
    import requests
    requests.packages.urllib3.disable_warnings()  # type: ignore
except Exception:
    requests = None

UNKEYED_HEADERS = [
    "X-Forwarded-Host", "X-Forwarded-Scheme", "X-Forwarded-Proto",
    "X-Original-URL", "X-Rewrite-URL", "X-Host", "X-Forwarded-Server",
    "X-Forwarded-For", "X-HTTP-Host-Override", "Forwarded",
]


def _get(url, headers=None, timeout=12):
    if not requests:
        return None
    try:
        return requests.get(url, headers=headers or {}, timeout=timeout,
                            verify=False, allow_redirects=False)
    except Exception:
        return None


def scan_url(url, delay=0.3):
    findings = []
    for hdr in UNKEYED_HEADERS:
        canary = f"arise{uuid.uuid4().hex[:10]}.example"
        r1 = _get(url, {hdr: canary})
        if r1 is None:
            continue
        reflected = canary in (r1.text or "") or canary in " ".join(f"{k}:{v}" for k, v in r1.headers.items())
        if not reflected:
            continue
        # Confirm it stuck in cache: request again with NO special header.
        time.sleep(delay)
        r2 = _get(url, {})
        if r2 is not None and canary in (r2.text or ""):
            findings.append({
                "module": "cache_poison", "severity": "high", "confidence": "confirmed",
                "title": f"Web cache poisoning via unkeyed header {hdr}",
                "url": url, "header": hdr, "canary": canary,
                "evidence": f"canary injected via {hdr} persisted in a cache-served response "
                            f"issued without the header (cache-status: "
                            f"{r2.headers.get('X-Cache') or r2.headers.get('CF-Cache-Status') or 'n/a'})",
                "remediation": "Add the reflected header to the cache key, or strip it at the edge; "
                               "never reflect Host-family headers into cached responses.",
            })
        time.sleep(delay)
    return findings


def _load_targets(args):
    urls = list(args.url)
    if args.list and os.path.isfile(args.list):
        with open(args.list, errors="ignore") as f:
            urls += [l.strip() for l in f if l.strip().startswith("http")]
    if args.scan_dir:
        p = os.path.join(args.scan_dir, "04_http_discovery", "http_hosts.txt")
        if os.path.isfile(p):
            with open(p, errors="ignore") as f:
                urls += [l.strip() for l in f if l.strip().startswith("http")]
    # de-dupe, cap
    seen, out = set(), []
    for u in urls:
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out[: args.max_targets]


def main():
    ap = argparse.ArgumentParser(description="ARISE web cache poisoning scanner")
    ap.add_argument("scan_dir", nargs="?")
    ap.add_argument("--url", action="append", default=[])
    ap.add_argument("--list")
    ap.add_argument("--out")
    ap.add_argument("--max-targets", type=int, default=200)
    ap.add_argument("--delay", type=float, default=0.3)
    args = ap.parse_args()

    if not requests:
        print("cache_poison: requests not installed; skipping", file=sys.stderr)
        return 0
    targets = _load_targets(args)
    findings = []
    for u in targets:
        findings.extend(scan_url(u, args.delay))

    out = args.out or (os.path.join(args.scan_dir, "24_advanced_attacks", "cache_poison_findings.jsonl")
                       if args.scan_dir else "cache_poison_findings.jsonl")
    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
    with open(out, "w") as f:
        for row in findings:
            f.write(json.dumps(row) + "\n")
    print(f"cache_poison: {len(targets)} target(s), {len(findings)} finding(s) -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
