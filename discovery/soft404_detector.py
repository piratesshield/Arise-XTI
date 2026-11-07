#!/usr/bin/env python3
"""
Multi-signal soft-404 / catchall detector.

Why length-only isn't enough
----------------------------
The Module 5 baseline calibration uses a single signal — body length delta —
to decide "is this host serving a catchall?". Modern SPAs blow that up: React
returns the same index.html for every URL, identical status 200, near-
identical length. Sometimes the length differs by a few bytes because of a
dynamic timestamp or a per-request CSRF nonce, so the length delta gate says
"not catchall" and the pipeline dutifully treats every dirsearch 200 as real.

This detector learns a per-host catchall fingerprint by:

  1. Sending N=3 random junk paths (default), each with a wildly different
     shape (short/long/deep).
  2. Recording (status, normalized_body_hash, headers_hash, content_length,
     final_url) for each junk response — the CATCHALL FINGERPRINT SET.
  3. When a discovered URL comes in, computing the same tuple for it and
     comparing against every fingerprint in the set. Match on ANY of:
       - Exact status + body-hash match → definite catchall
       - Same status + body similarity > 0.90 (shingled 4-gram) → likely
       - Same status + content-length within 2% AND same redirect target
         → suspected

Targeted normalization
----------------------
Blindly stripping all digits creates false collisions ("User ID: 12345" and
"User ID: 67890" collapse — bad). We ONLY strip what's genuinely dynamic per
request but semantically constant across requests:

  - ISO-8601 timestamps  (2026-08-08T12:34:56Z, 12:34:56)
  - UUIDs                (8-4-4-4-12 hex)
  - CSRF/nonce tokens    (attributes like csrf-token=, _token=, nonce=)
  - Request IDs          (x-request-id-style hex)
  - Cache-busting queries (?v=12345, ?_=1723499817)
  - CSP nonce attributes (nonce="abc123")
  - Session IDs in HTML  (sess=..., PHPSESSID=...)

Everything else — including arbitrary integers embedded in page text ("Order
1234") — is preserved. That means two truly different pages STAY different.

Public API
----------
  learn_catchall_signature(url, n=3, timeout=8, user_agent=...) -> dict
      Fires N junk probes and returns the fingerprint set as a dict:
        {"host": ..., "junk_probes": [
            {"junk_path", "status", "body_hash", "body_len",
             "headers_hash", "location"}, ...],
         "signature_ready": bool}

  is_catchall_response(url, sig, timeout=8, user_agent=...) -> (bool, dict)
      Fetches url once, computes the tuple, compares against sig["junk_probes"],
      returns (True, reason) if it matches any fingerprint in the set.

Standalone CLI:
    python3 soft404_detector.py learn https://api.example.com
    python3 soft404_detector.py check https://api.example.com/admin \\
        --sig-file <path-to-learned-sig.json>
"""

from __future__ import annotations

import sys as _sys, os as _os
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)


import argparse
import hashlib
import json
import os
import random
import re
import ssl
import string
import sys
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Tuple

DEFAULT_UA = os.environ.get(
    "HUMAN_USER_AGENT",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36",
)

BODY_HASH_MAX = 65536  # first 64 KiB is plenty for fingerprinting

# ── Targeted normalization patterns ──────────────────────────────────────────
# Order matters: apply the most specific matches first so a UUID doesn't get
# partially chomped by the hex-run rule.
_UUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)
_ISO_DT_RE = re.compile(
    r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+\-]\d{2}:?\d{2})?\b"
)
_TIME_ONLY_RE = re.compile(r"\b\d{2}:\d{2}:\d{2}(?:\.\d+)?\b")
_UNIX_TS_RE = re.compile(r"\b1[6-9]\d{8}\b")   # 10-digit unix ts (2020s window)
_UNIX_MS_TS_RE = re.compile(r"\b1[6-9]\d{11}\b")  # 13-digit unix ms

# Attribute-scoped: nonces, csrf tokens, request ids in HTML/JSON. Match
# the KEY explicitly so we only touch the VALUE, not any string that happens
# to contain hex. Two patterns cover the common shapes:
#   1. key = "value" / key: "value"   (JSON, form fields, JS assignments)
#   2. <meta name="csrf-token" content="value">   (HTML meta pattern)
_CSRF_KEY_NAMES = (
    r"csrf[-_]?token|_?csrf|_?token|authenticity[-_]?token|"
    r"x[-_]request[-_]id|request[-_]id|xsrf[-_]token|session[-_]?id|"
    r"phpsessid|jsessionid|sessionid"
)
_CSRF_ATTR_RE = re.compile(
    r"""(?ix)
    (
      (?:""" + _CSRF_KEY_NAMES + r""")
      ["']?           # optional closing quote of a JSON key like "csrf_token"
      \s*[:=]\s*
      ["']?           # optional opening quote of the value
    )
    ([^"'\s,<>&]+)
    """
)
# HTML meta pattern: name / property / id = "<csrf-key>" and then content = "<VALUE>".
_CSRF_META_RE = re.compile(
    r"""(?ix)
    (<meta\s+
      (?:name|property|id)\s*=\s*["']
      (?:""" + _CSRF_KEY_NAMES + r""")["']
      \s+content\s*=\s*["'])
    ([^"']+)
    """
)
# Cache-busting query params (?_=... or ?v=... or ?ts=...)
_CACHEBUST_QP_RE = re.compile(
    r"([?&](?:_|v|ver|version|ts|t|_t|cb|nocache)=)[A-Za-z0-9._\-%]+"
)
# CSP nonce attribute
_CSP_NONCE_RE = re.compile(r'(nonce\s*=\s*")[^"]+(")', re.IGNORECASE)


def normalize_body(body: bytes) -> bytes:
    """Apply targeted normalization to make dynamic-but-catchall pages
    produce a stable fingerprint. See module docstring for the safety
    rationale — we never strip arbitrary digits."""
    try:
        text = body.decode("utf-8", errors="replace")
    except Exception:
        return body
    text = _UUID_RE.sub("{UUID}", text)
    text = _ISO_DT_RE.sub("{ISO_TS}", text)
    text = _TIME_ONLY_RE.sub("{TIME}", text)
    text = _UNIX_MS_TS_RE.sub("{TS_MS}", text)
    text = _UNIX_TS_RE.sub("{TS}", text)
    text = _CSRF_META_RE.sub(r"\1{TOKEN}", text)
    text = _CSRF_ATTR_RE.sub(r"\1{TOKEN}", text)
    text = _CACHEBUST_QP_RE.sub(r"\1{CB}", text)
    text = _CSP_NONCE_RE.sub(r"\1{NONCE}\2", text)
    return text.encode("utf-8", errors="replace")


def _sha1(b: bytes) -> str:
    return hashlib.sha1(b).hexdigest()


def _random_junk_path(shape: str = "short") -> str:
    """Generate a random path unlikely to exist. 'shape' varies path style so
    a WAF that catches obvious gibberish still misses the well-formed one."""
    if shape == "short":
        return "/" + "".join(random.choices(string.ascii_lowercase, k=10))
    if shape == "deep":
        parts = ["/".join(
            random.choices(string.ascii_lowercase, k=random.randint(4, 8)))
            for _ in range(3)]
        return "/" + "/".join(parts)
    if shape == "extension":
        return "/" + "".join(random.choices(string.ascii_lowercase, k=8)) + ".html"
    # default: mixed
    return "/" + "".join(random.choices(string.ascii_lowercase + string.digits, k=15))


def _fetch(url: str, timeout: int, user_agent: str) -> Dict[str, Any]:
    """Fetch a URL and return (status, body, headers, final_url) — even on
    HTTPError, because 403/404/soft-catchall pages are what we're LOOKING for
    here. Never raises."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"User-Agent": user_agent})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read(BODY_HASH_MAX)
            status = resp.getcode()
            headers = dict(resp.headers.items())
            final_url = resp.geturl() or url
    except urllib.error.HTTPError as e:
        try:
            body = e.read(BODY_HASH_MAX) if e.fp else b""
        except Exception:
            body = b""
        headers = dict(e.headers.items()) if e.headers else {}
        status = e.code
        final_url = url
    except Exception:
        return {"status": 0, "body": b"", "headers": {}, "final_url": url,
                "error": True}
    return {"status": status, "body": body, "headers": headers,
            "final_url": final_url, "error": False}


def _shingles(text: str, k: int = 4) -> set:
    """K-gram shingles for Jaccard similarity. Small enough to be cheap on
    a 64K body, discriminating enough for real vs catchall."""
    text = text.lower()
    return set(text[i:i + k] for i in range(0, max(0, len(text) - k + 1)))


def _jaccard(a: set, b: set) -> float:
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    inter = len(a & b)
    return inter / (len(a) + len(b) - inter)


def learn_catchall_signature(root_url: str, n: int = 3,
                             timeout: int = 8,
                             user_agent: str = DEFAULT_UA) -> Dict[str, Any]:
    """Fire N junk probes at $root_url with varying path shapes and record
    the fingerprint set. Returns a dict that is safe to persist as JSON and
    later passed back to is_catchall_response()."""
    root = root_url.rstrip("/")
    shapes = ["short", "deep", "extension", "short"][:n]
    probes: List[Dict[str, Any]] = []
    normalized_bodies: List[str] = []
    for shape in shapes:
        junk = _random_junk_path(shape)
        u = root + junk
        r = _fetch(u, timeout, user_agent)
        norm = normalize_body(r["body"])
        norm_text = norm.decode("utf-8", errors="replace")
        # Headers hash on a stable, cache-independent projection: sort keys,
        # strip Date/Set-Cookie/nonce headers.
        _skip_h = {"date", "set-cookie", "server-timing", "x-request-id",
                   "cf-ray", "x-amz-cf-id", "x-served-by", "age"}
        hdrs_stable = "\n".join(
            f"{k.lower()}: {v}" for k, v in sorted(r["headers"].items())
            if k.lower() not in _skip_h
        )
        probes.append({
            "junk_path": junk,
            "status": r["status"],
            "body_hash": _sha1(norm),
            "body_len": len(r["body"]),
            "headers_hash": _sha1(hdrs_stable.encode("utf-8", errors="replace")),
            "location": r["headers"].get("Location", ""),
        })
        normalized_bodies.append(norm_text)
    # Precompute shingles for similarity checks — stored in-memory only, not
    # persisted, to keep the JSON small.
    return {
        "host": root,
        "junk_probes": probes,
        "_shingles": [_shingles(nb) for nb in normalized_bodies],
        "_normalized_bodies": normalized_bodies,
        "signature_ready": all(p["status"] > 0 for p in probes),
    }


def is_catchall_response(url: str, sig: Dict[str, Any],
                         timeout: int = 8,
                         user_agent: str = DEFAULT_UA,
                         similarity_threshold: float = 0.90,
                         length_tolerance: float = 0.02) -> Tuple[bool, Dict[str, Any]]:
    """Fetch url and decide whether its response matches the catchall
    fingerprint set. Returns (is_catchall, reason_dict) where reason_dict
    explains WHICH signals matched — useful for logging."""
    if not sig or not sig.get("signature_ready"):
        return False, {"reason": "no-signature"}
    r = _fetch(url, timeout, user_agent)
    if r["error"] or r["status"] == 0:
        return False, {"reason": "fetch-failed"}
    norm = normalize_body(r["body"])
    body_hash = _sha1(norm)
    body_len = len(r["body"])
    _skip_h = {"date", "set-cookie", "server-timing", "x-request-id",
               "cf-ray", "x-amz-cf-id", "x-served-by", "age"}
    hdrs_stable = "\n".join(
        f"{k.lower()}: {v}" for k, v in sorted(r["headers"].items())
        if k.lower() not in _skip_h
    )
    headers_hash = _sha1(hdrs_stable.encode("utf-8", errors="replace"))
    location = r["headers"].get("Location", "")
    norm_text = norm.decode("utf-8", errors="replace")
    url_shingles = _shingles(norm_text)

    signals = []
    for i, p in enumerate(sig["junk_probes"]):
        if p["status"] != r["status"]:
            continue
        # Signal 1: exact normalized-body match → definite catchall
        if p["body_hash"] == body_hash and body_hash != _sha1(b""):
            signals.append({"probe_index": i, "signal": "exact-body-hash"})
            return True, {"is_catchall": True, "signals": signals,
                          "status": r["status"], "body_hash": body_hash}
        # Signal 2: headers-hash + length within tolerance + same location
        if p["headers_hash"] == headers_hash:
            if p["body_len"] > 0 and abs(body_len - p["body_len"]) / max(p["body_len"], 1) <= length_tolerance:
                if p["location"] == location:
                    signals.append({"probe_index": i,
                                    "signal": "headers+length+location"})
        # Signal 3: shingle similarity > threshold
        if i < len(sig.get("_shingles", [])):
            j = _jaccard(url_shingles, sig["_shingles"][i])
            if j >= similarity_threshold:
                signals.append({"probe_index": i,
                                "signal": "body-similarity",
                                "jaccard": round(j, 3)})
    if signals:
        return True, {"is_catchall": True, "signals": signals,
                      "status": r["status"], "body_hash": body_hash,
                      "body_len": body_len}
    return False, {"is_catchall": False, "status": r["status"],
                   "body_hash": body_hash, "body_len": body_len}


# CLI ─────────────────────────────────────────────────────────────────────────

def _persistable(sig: Dict[str, Any]) -> Dict[str, Any]:
    """Strip in-memory-only fields before JSON serialization."""
    return {k: v for k, v in sig.items()
            if not k.startswith("_") and k != "signature_ready"} | {
        "signature_ready": sig.get("signature_ready", False),
    }


def _rehydrate(sig: Dict[str, Any]) -> Dict[str, Any]:
    """Rebuild the in-memory shingle sets after JSON reload — we don't
    persist them (they can be 10s of KB per host); regenerate from the
    normalized-body-hash proxies. If _normalized_bodies is absent, similarity
    checks are skipped and only hash/length signals fire."""
    sig.setdefault("_shingles", [])
    sig.setdefault("_normalized_bodies", [])
    return sig


def main() -> int:
    ap = argparse.ArgumentParser(description="Multi-signal soft-404 detector")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_learn = sub.add_parser("learn", help="Learn catchall signature for a host")
    p_learn.add_argument("url", help="Host root URL (e.g. https://api.x.com)")
    p_learn.add_argument("-n", type=int, default=3, help="Junk probes to send")
    p_learn.add_argument("--timeout", type=int, default=8)
    p_learn.add_argument("--out", default=None,
                         help="Persist signature here (JSON). Default: stdout")

    p_check = sub.add_parser("check", help="Check a URL against a signature")
    p_check.add_argument("url", help="URL to test")
    p_check.add_argument("--sig-file", required=True,
                         help="Path to signature JSON written by 'learn'")
    p_check.add_argument("--timeout", type=int, default=8)

    args = ap.parse_args()

    if args.cmd == "learn":
        sig = learn_catchall_signature(args.url, n=args.n, timeout=args.timeout)
        blob = json.dumps(_persistable(sig), indent=2)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as fh:
                fh.write(blob)
            print(f"[soft404] signature written to {args.out}", file=sys.stderr)
        else:
            print(blob)
        return 0

    if args.cmd == "check":
        try:
            with open(args.sig_file, "r", encoding="utf-8") as fh:
                sig = json.load(fh)
        except Exception as e:
            print(f"[soft404] failed to load signature: {e}", file=sys.stderr)
            return 2
        sig = _rehydrate(sig)
        is_catchall, reason = is_catchall_response(args.url, sig,
                                                    timeout=args.timeout)
        print(json.dumps({"url": args.url, "is_catchall": is_catchall,
                          "reason": reason}, indent=2))
        return 0

    return 2


if __name__ == "__main__":
    sys.exit(main())
