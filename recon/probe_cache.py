#!/usr/bin/env python3
"""
Shared HTTP response fingerprint cache — one file, every module reads/writes.

Why
---
Modules 5 (WAF baseline), 6 (headers), 8B (bypass_403 + WAF classify), and 12
(nuclei) each fire GET on the same host roots. On a 200-host scan that means
each root URL is probed 4+ times inside a single scan window. All those extra
requests cost time AND add WAF signal — the last thing you want when you're
also trying to look human.

This module offers a shared JSONL cache:

    probe_cache.jsonl  — {url, ts, status, headers_sha1, body_sha1, body_len,
                          content_type, location, ttl_epoch}

Any module can call:

    from recon.probe_cache import get_or_probe
    entry = get_or_probe(url, cache_dir, ttl=300)

If a fresh entry exists (< ttl seconds old), the cached row is returned with no
network call. Otherwise a single GET is issued (with HUMAN_USER_AGENT + TLS
skip), the row is written, and the row is returned.

Design notes
------------
* Append-only JSONL, atomic file locks with fcntl (POSIX). One row per lookup;
  duplicates are tolerated and the newest one wins on read. Compaction is a
  separate concern — the file rarely exceeds a few thousand rows per scan.
* No requests library — stdlib only, so this drops into every environment the
  pipeline runs in.
* Body hash uses SHA-1 of the first 64 KiB — big enough to distinguish real
  content from catchall/error pages, small enough to be cheap on large HTML.
* We deliberately capture BOTH status code AND body/headers hashes; consumers
  can dedupe by any of those axes without re-fetching.
"""

from __future__ import annotations

import sys as _sys, os as _os
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)


import fcntl
import hashlib
import json
import os
import ssl
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, Optional

DEFAULT_TTL = 300  # seconds — 5 min is longer than any single module's runtime
CACHE_FILENAME = "probe_cache.jsonl"
BODY_HASH_MAX = 65536

_DEFAULT_UA = os.environ.get(
    "HUMAN_USER_AGENT",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36",
)


def _cache_path(cache_dir: Path) -> Path:
    cache_dir = Path(cache_dir)
    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir / CACHE_FILENAME


def _sha1(b: bytes) -> str:
    return hashlib.sha1(b).hexdigest()


def _read_latest(url: str, cache_dir: Path) -> Optional[Dict[str, Any]]:
    """Return the newest entry for url, or None. Cheap linear scan — good
    enough for the ~few-thousand-row caches these scans produce."""
    p = _cache_path(cache_dir)
    if not p.is_file() or p.stat().st_size == 0:
        return None
    latest: Optional[Dict[str, Any]] = None
    try:
        with open(p, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except Exception:
                    continue
                if row.get("url") != url:
                    continue
                if latest is None or row.get("ts", 0) > latest.get("ts", 0):
                    latest = row
    except Exception:
        return None
    return latest


def _append(row: Dict[str, Any], cache_dir: Path) -> None:
    p = _cache_path(cache_dir)
    line = json.dumps(row, default=str) + "\n"
    with open(p, "a", encoding="utf-8") as fh:
        try:
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
        except OSError:
            pass  # non-POSIX — accept race risk (JSONL rows are self-contained)
        fh.write(line)
        try:
            fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
        except OSError:
            pass


def _probe(url: str, timeout: int) -> Dict[str, Any]:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"User-Agent": _DEFAULT_UA})
    ts = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            headers = dict(resp.headers.items())
            body = resp.read(BODY_HASH_MAX)
            status = resp.getcode()
            location = headers.get("Location", "")
            ct = headers.get("Content-Type", "")
    except urllib.error.HTTPError as e:
        try:
            body = e.read(BODY_HASH_MAX) if e.fp else b""
        except Exception:
            body = b""
        headers = dict(e.headers.items()) if e.headers else {}
        status = e.code
        location = headers.get("Location", "")
        ct = headers.get("Content-Type", "")
    except Exception:
        return {
            "url": url, "ts": ts, "status": 0, "error": True,
            "headers_sha1": "", "body_sha1": "", "body_len": 0,
            "content_type": "", "location": "",
        }
    headers_blob = "\n".join(f"{k}: {v}" for k, v in sorted(headers.items()))
    return {
        "url": url,
        "ts": ts,
        "status": status,
        "error": False,
        "headers_sha1": _sha1(headers_blob.encode("utf-8", errors="replace")),
        "body_sha1": _sha1(body),
        "body_len": len(body),
        "content_type": ct,
        "location": location,
    }


def get_or_probe(url: str, cache_dir: Path | str,
                 ttl: int = DEFAULT_TTL, timeout: int = 10) -> Dict[str, Any]:
    """Return the cache row for url, refreshing if stale.

    Consumers that just want the status can do:
        row = get_or_probe(url, cache_dir); row["status"]
    Consumers that want a per-body dedup key use row["body_sha1"] — two URLs
    with the same body_sha1 within a single scan are near-guaranteed to be
    serving the same catchall / redirect / SPA shell.
    """
    cache_dir = Path(cache_dir)
    now = time.time()
    hit = _read_latest(url, cache_dir)
    if hit is not None and (now - hit.get("ts", 0)) < ttl:
        return hit
    fresh = _probe(url, timeout)
    _append(fresh, cache_dir)
    return fresh


def prime_from_httpx_json(httpx_json_path: Path | str,
                          cache_dir: Path | str) -> int:
    """Seed the cache from Module 4's httpx output so downstream modules skip
    the first-probe network cost entirely. httpx already fetched every root;
    reusing its result is the biggest single win of the cache.

    Returns the number of rows written."""
    p = Path(httpx_json_path)
    if not p.is_file() or p.stat().st_size == 0:
        return 0
    n = 0
    cache_dir = Path(cache_dir)
    try:
        with open(p, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                except Exception:
                    continue
                url = e.get("url") or e.get("input") or ""
                if not url:
                    continue
                # httpx gives us status_code, content_type, location; we don't
                # have the raw body sha here, so leave body_sha1 empty. The
                # cache format still lets consumers use the status/CT signal.
                row = {
                    "url": url,
                    "ts": time.time(),
                    "status": e.get("status_code") or 0,
                    "error": False,
                    "headers_sha1": "",
                    "body_sha1": "",
                    "body_len": e.get("content_length") or 0,
                    "content_type": e.get("content_type") or "",
                    "location": (e.get("final_url") or "") if e.get("final_url") != url else "",
                    "source": "httpx-prime",
                }
                _append(row, cache_dir)
                n += 1
    except Exception:
        return n
    return n


if __name__ == "__main__":
    # CLI shim: warm the cache from httpx, or probe a URL.
    #   python3 probe_cache.py prime <scan_dir>
    #   python3 probe_cache.py get   <scan_dir> <url> [ttl]
    import sys
    if len(sys.argv) < 3:
        print("usage: probe_cache.py prime|get <scan_dir> [args...]",
              file=sys.stderr)
        sys.exit(2)
    cmd, scan_dir = sys.argv[1], Path(sys.argv[2])
    if cmd == "prime":
        httpx_out = scan_dir / "04_http_discovery" / "http_confirmed.json"
        n = prime_from_httpx_json(httpx_out, scan_dir / "05_waf_detection")
        print(f"probe_cache primed with {n} row(s) from httpx", file=sys.stderr)
    elif cmd == "get":
        if len(sys.argv) < 4:
            print("usage: probe_cache.py get <scan_dir> <url> [ttl]",
                  file=sys.stderr)
            sys.exit(2)
        url = sys.argv[3]
        ttl = int(sys.argv[4]) if len(sys.argv) > 4 else DEFAULT_TTL
        row = get_or_probe(url, scan_dir / "05_waf_detection", ttl=ttl)
        print(json.dumps(row, indent=2))
    else:
        print(f"unknown cmd: {cmd}", file=sys.stderr)
        sys.exit(2)
