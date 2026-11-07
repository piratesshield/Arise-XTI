#!/usr/bin/env python3
"""
Content-based subdomain deduplication.

The URL inventory frequently contains multiple hostnames serving the same
application: `admin.zepto.com`, `admin-staging.zepto.com`, `admin-old.zepto.com`
often all return the same `<title>Admin Console</title>` shell with the same
first few KB of body. Treating them as three distinct trees means:

  * dirsearch fires 3× on identical wordlists → 3× the WAF signal, 3× the time
  * nuclei roots scan 3× the same app → 3× the CVE scan cost
  * the URL inventory shows 3× the endpoints, all duplicates

We cluster hosts by response fingerprint AFTER httpx confirms them, pick a
canonical member per cluster, and emit:

  host_clusters.jsonl — one row per cluster:
      {canonical: "admin.zepto.com",
       members: ["admin.zepto.com", "admin-staging.zepto.com", ...],
       cluster_size: 3,
       fingerprint: {status, title, body_sha1, body_len}}

The pipeline's dirsearch/nuclei feeders can consume this to scan the
canonical only; findings on the canonical apply to the whole cluster (mirrored
by the reporting layer).

Fingerprint design
------------------
We fingerprint on:
  1. HTTP status of the root
  2. HTML <title> (case-normalized, whitespace-collapsed)
  3. SHA-1 of the first 32 KiB body AFTER soft-404's targeted normalization
     (so per-request timestamps/nonces don't split identical apps)
  4. Body length bucketed to nearest 1 KiB

Two hosts are "same cluster" iff status matches AND title matches AND
(body_hash matches OR (body_len bucket matches AND shingle Jaccard >= 0.92)).

The 0.92 threshold is tighter than soft-404's 0.90 because we're not
detecting a catchall pattern (many wildly different URLs producing one
response) — we're detecting the SAME app on DIFFERENT hosts, which should
be a near-exact body match modulo dynamic bits.

Canonical selection rule
------------------------
Within a cluster, canonical is the SHORTEST hostname (fewest dots +
fewest chars). That reliably picks `admin.example.com` over
`admin-staging.example.com` — production-first, which is where CVEs and
config drift matter most.
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
import re
import ssl
import sys
import urllib.error
import urllib.request
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Reuse soft-404's normalizer — single source of truth for what "same page
# except for dynamic bits" means across the pipeline.
from discovery.soft404_detector import normalize_body, _shingles, _jaccard  # noqa: E402

DEFAULT_UA = os.environ.get(
    "HUMAN_USER_AGENT",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36",
)
BODY_HASH_MAX = 32768
LENGTH_BUCKET = 1024
SIMILARITY_THRESHOLD = 0.92

_TITLE_RE = re.compile(rb"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_WS_RE = re.compile(r"\s+")


def _sha1(b: bytes) -> str:
    return hashlib.sha1(b).hexdigest()


def _fetch(url: str, timeout: int, user_agent: str) -> Dict[str, Any]:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"User-Agent": user_agent})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return {"status": resp.getcode(),
                    "body": resp.read(BODY_HASH_MAX),
                    "final_url": resp.geturl() or url}
    except urllib.error.HTTPError as e:
        try:
            body = e.read(BODY_HASH_MAX) if e.fp else b""
        except Exception:
            body = b""
        return {"status": e.code, "body": body, "final_url": url}
    except Exception:
        return {"status": 0, "body": b"", "final_url": url}


def _title(body: bytes) -> str:
    m = _TITLE_RE.search(body)
    if not m:
        return ""
    try:
        raw = m.group(1).decode("utf-8", errors="replace")
    except Exception:
        return ""
    return _WS_RE.sub(" ", raw).strip().lower()[:200]


def _fingerprint(url: str, timeout: int, user_agent: str) -> Dict[str, Any]:
    """Compute the per-host fingerprint tuple."""
    r = _fetch(url, timeout, user_agent)
    body = r["body"]
    if not body and r["status"] == 0:
        return {"url": url, "status": 0, "usable": False}
    normalized = normalize_body(body)
    return {
        "url": url,
        "status": r["status"],
        "title": _title(body),
        "body_sha1": _sha1(normalized),
        "body_len_bucket": (len(body) // LENGTH_BUCKET),
        "_shingles": _shingles(normalized.decode("utf-8", errors="replace")),
        "usable": True,
    }


def _host_of(url: str) -> str:
    """Extract hostname (lower-cased, port stripped) from a URL.

    Standalone parse — no urllib.parse dep here because the pipeline
    sometimes passes bare hostnames. Handles both.
    """
    u = url.strip()
    if "://" in u:
        u = u.split("://", 1)[1]
    u = u.split("/", 1)[0]
    u = u.split(":", 1)[0]
    return u.lower()


def _canonical_of(hosts: List[str]) -> str:
    """Pick canonical host: fewest label parts, then shortest length. This
    reliably prefers `admin.x.com` over `admin-staging.x.com`."""
    return min(hosts, key=lambda h: (h.count("."), len(h), h))


def _cluster(fingerprints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Group fingerprints into equivalence classes. O(N^2) but N here is
    the number of confirmed live hosts, capped by target — real scans have
    dozens to a few hundred; not the bottleneck."""
    remaining = [f for f in fingerprints if f.get("usable")]
    clusters: List[List[Dict[str, Any]]] = []
    while remaining:
        seed = remaining.pop(0)
        cluster = [seed]
        keep: List[Dict[str, Any]] = []
        for other in remaining:
            if _same_cluster(seed, other):
                cluster.append(other)
            else:
                keep.append(other)
        remaining = keep
        clusters.append(cluster)
    return clusters


def _same_cluster(a: Dict[str, Any], b: Dict[str, Any]) -> bool:
    if a["status"] != b["status"]:
        return False
    if a["title"] != b["title"]:
        return False
    if a["body_sha1"] == b["body_sha1"]:
        return True
    # Fallback: length bucket AND shingle similarity above threshold
    if a["body_len_bucket"] != b["body_len_bucket"]:
        return False
    return _jaccard(a["_shingles"], b["_shingles"]) >= SIMILARITY_THRESHOLD


def _persistable(cluster: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Serialize a cluster without in-memory-only fields."""
    hosts = [_host_of(f["url"]) for f in cluster]
    hosts = sorted(set(hosts))
    canonical = _canonical_of(hosts)
    seed = cluster[0]
    return {
        "canonical": canonical,
        "members": hosts,
        "cluster_size": len(hosts),
        "fingerprint": {
            "status": seed["status"],
            "title": seed["title"],
            "body_sha1": seed["body_sha1"],
            "body_len_bucket": seed["body_len_bucket"],
        },
    }


def cluster_hosts(scan_dir: Path, timeout: int = 8,
                  user_agent: str = DEFAULT_UA) -> int:
    """Read http_hosts.txt, fingerprint each URL, cluster, and write
    host_clusters.jsonl. Returns the number of clusters written."""
    src = scan_dir / "04_http_discovery" / "http_hosts.txt"
    out = scan_dir / "04_http_discovery" / "host_clusters.jsonl"
    canonical_out = scan_dir / "04_http_discovery" / "host_canonical.txt"
    if not src.is_file() or src.stat().st_size == 0:
        return 0
    try:
        urls = [ln.strip() for ln in open(src, encoding="utf-8",
                                          errors="replace") if ln.strip()]
    except Exception:
        return 0
    if not urls:
        return 0
    fingerprints = [_fingerprint(u, timeout, user_agent) for u in urls]
    clusters = _cluster(fingerprints)
    with open(out, "w", encoding="utf-8") as w:
        for c in clusters:
            w.write(json.dumps(_persistable(c)) + "\n")
    # Companion file: bare-hostname list of canonicals only. Downstream
    # scanners (dirsearch, nuclei) can grep against this for O(1) inclusion.
    with open(canonical_out, "w", encoding="utf-8") as w:
        for c in clusters:
            hosts = sorted({_host_of(f["url"]) for f in c})
            w.write(_canonical_of(hosts) + "\n")
    return len(clusters)


def main() -> int:
    ap = argparse.ArgumentParser(description="Content-based host dedup")
    ap.add_argument("scan_dir")
    ap.add_argument("--timeout", type=int, default=8)
    args = ap.parse_args()
    n = cluster_hosts(Path(args.scan_dir), timeout=args.timeout)
    print(f"[host-dedup] clustered into {n} unique app(s)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
