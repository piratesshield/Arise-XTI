#!/usr/bin/env python3
"""
Consolidate every URL source produced upstream in the pipeline into a single
deduplicated list suitable for feeding nuclei -l.

Runs BEFORE the deep-surface nuclei phase (Module 12b), AFTER Module 20 has
finished, so the API deep-discovery outputs (XHR interception, katana-headless,
API-shaped injection targets) are visible to it.

Why this exists
---------------
Nuclei's deep-surface phase historically consumed only 09_crawling/all_urls.txt
(or a JSONL fallback). That silently missed:

  * 01_asset_discovery/gau_urls.txt       — historical wayback URLs
  * 08_directory_discovery/all_paths.txt  — dirsearch/ffuf hits
  * 11_param_fuzzing/urls_with_params.txt — parameterised endpoints
  * 20_api_deep_discovery/*               — XHR intercepts, katana-headless,
                                            API endpoints, injection targets

CVEs and misconfig templates that only fire on parameterised, XHR-only, or
historically-archived paths were never being tested against them.

We ALSO need the opposite: nuclei can't scan hundreds of thousands of near-
identical URLs, and probing every `/users/123`, `/users/456`, `/users/789`
independently is pure waste — they exercise the same code path. So the
consolidator template-collapses URLs (numeric IDs, UUIDs, opaque tokens) and
keeps one representative per template. Result: full coverage, tiny list.

Similarity dedup approach
-------------------------
There is no maintained pip library that does "collapse similar API URLs by
template". `url-normalize` only canonicalises (case, ports, trailing slash);
`urlcanon` same story. Every scanner rolls its own. We reuse the same
primitives the API engine and url_classify already use (ID_SEGMENT_RE, _UUID_RE)
so the whole pipeline speaks one language — no drift, no third-party dep.

Two-stage collapse:
  1. Canonicalise: lower-case host, drop fragment, keep query, strip default
     port, drop trailing '/' except for root.
  2. Template key: replace path segments matching ID_SEGMENT_RE / _UUID_RE
     with `{id}`, sort query keys and blank their values (values are usually
     the variable part; the *shape* of the query is what matters). Keep one
     concrete URL per template key — the SHORTEST one, which is usually the
     cleanest example.

Usage
-----
    python3 nuclei_url_consolidator.py <scan_dir> --out <path> \
        [--cap 8000] [--include-roots]

Exits 0 on success (or when there's simply nothing to consolidate).
"""

from __future__ import annotations

import sys as _sys, os as _os
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)


import argparse
import json
import os
import sys
from pathlib import Path
from typing import Iterable, Optional
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode

# Single source of truth: URL classification primitives.
# STATIC_ASSET_RE catches .js / .css / .png / fonts / etc — nuclei's CVE /
# exposure / misconfig templates are useless against these, so we drop them
# by default. Same regex Module 8B's classifier uses; keeping it centralised
# means the consolidator can never drift from the rest of the pipeline.
from discovery.url_classify import ID_SEGMENT_RE, _UUID_RE, STATIC_ASSET_RE  # noqa: E402


# --------------------------------------------------------------------------- #
# Sources — every file the pipeline produces that carries URLs. Order matters
# only for tie-breaks (shortest URL wins per template; source order doesn't).
# --------------------------------------------------------------------------- #

TEXT_URL_SOURCES = [
    # (relative path under scan_dir, is_JSONL, jsonl_url_field)
    ("01_asset_discovery/gau_urls.txt",                False, None),
    ("04_http_discovery/http_urls.txt",                False, None),
    ("08_directory_discovery/all_paths.txt",           False, None),
    ("09_crawling/all_urls.txt",                       False, None),
    ("09_crawling/js_urls.txt",                        False, None),
    ("11_param_fuzzing/urls_with_params.txt",          False, None),
    ("20_api_deep_discovery/xhr_intercepted.txt",      False, None),
    ("20_api_deep_discovery/katana_headless_urls.txt", False, None),
    ("20_api_deep_discovery/injection_targets.txt",    False, None),
    ("20_api_deep_discovery/sqli_targets.txt",         False, None),
]

JSONL_URL_SOURCES = [
    ("08_directory_discovery/discovered_endpoints.jsonl", "url"),
    ("20_api_deep_discovery/api_deep_discovery.jsonl",    "url"),
    ("20_api_deep_discovery/api_endpoints.jsonl",         "url"),
]

# Files that carry {url, status} pairs so we can drop URLs the pipeline
# already probed and observed as 404 / dead. discovered_endpoints.jsonl is
# Module 8B's merged, probed inventory — the authoritative source.
STATUS_SOURCES = [
    ("08_directory_discovery/discovered_endpoints.jsonl", "url", "status"),
]

# Statuses that mean "this URL is dead / gone / bad request — nuclei has
# nothing to test here". 401/403 are DELIBERATELY kept: an auth-gated endpoint
# is still a real endpoint and can still hit CVE / misconfig / info-disclosure
# templates that don't require auth to fire. 5xx is kept too — server errors
# often reveal vulns. 404 / 410 / 400 are the only clean drops.
DEAD_STATUSES = {400, 404, 410}

# httpx validation source: Module 4 runs httpx against every resolved hostname
# and writes confirmed live web services here. We use this as an allowlist so
# URLs whose hostname was never confirmed by httpx (stale GAU entries, dead
# subdomains, NXDOMAIN hosts that only appear in wayback history) are dropped
# before feeding nuclei. This catches both DNS failures and hosts that resolve
# but have no live HTTP service — httpx already did both checks.
# If the file is absent (e.g. partial scan, --only nuclei_scan), filtering is
# skipped so the consolidator still produces output.
HTTPX_CONFIRMED_HOSTS_SOURCE = "04_http_discovery/http_hosts.txt"

# Wildcard-DNS phantom filtering: a wildcard record (*.target.com -> one IP)
# makes every never-provisioned CT/gau/wayback subdomain resolve and pass the
# confirmed_hosts gate above, inflating the inventory with hosts that all
# serve the identical wildcard catch-all response. dns_security_audit.py
# (Module 3C) detects the wildcard and writes its IP set + an HTTP fingerprint
# of what it serves here; absent when no wildcard was detected (the common
# case) or on scans that predate this feature — filtering auto-skips then.
WILDCARD_DNS_SOURCE = "03c_dns_security/wildcard_dns.json"
HTTP_CONFIRMED_SOURCE = "04_http_discovery/http_confirmed.json"

# Host clusters: Module 4's host_dedup.py fingerprints every confirmed host by
# (status, title, normalized-body-hash, shingle-similarity) and groups hosts
# serving the same app. The clustering is used for REPORTING — findings on
# api.myntra.com can be mirrored to its cluster members in the dashboard.
#
# We do NOT drop non-canonical members from the nuclei feed by default. Same
# root fingerprint does NOT mean same subpaths: staging/UAT twins routinely
# ship older code (unpatched CVEs), debug endpoints, default credentials, and
# weaker WAF rules that production doesn't have. Dropping them silently
# reduces coverage on exactly the surface a pentester would probe first.
#
# --use-canonical-only exists for users who explicitly want the aggressive
# dedup (rare — usually only when scan time is more painful than missed
# findings). Off by default; safety over speed.
HOST_CANONICAL_SOURCE = "04_http_discovery/host_canonical.txt"

# Optional: include site roots (http_hosts.txt) — these are already covered by
# nuclei Phase 1's roots scan, so by default we exclude them here to avoid
# double work. --include-roots flips this if the caller wants a single unified
# feed instead.
ROOTS_SOURCE = "04_http_discovery/http_hosts.txt"


# --------------------------------------------------------------------------- #
# Canonicalisation + template-key derivation
# --------------------------------------------------------------------------- #

def _canonicalise(url: str) -> Optional[str]:
    """Return a canonical URL string, or None if not a real absolute HTTP(S) URL."""
    url = url.strip()
    if not url or url.startswith("#"):
        return None
    # Some sources emit "url status size" columns — tolerate them.
    url = url.split()[0]
    try:
        p = urlparse(url)
    except Exception:
        return None
    if p.scheme not in ("http", "https") or not p.netloc:
        return None
    host = p.hostname or ""
    if not host:
        return None
    host = host.lower()
    # Drop default ports (:80 for http, :443 for https).
    port = p.port
    if port and not ((p.scheme == "http" and port == 80) or
                     (p.scheme == "https" and port == 443)):
        netloc = f"{host}:{port}"
    else:
        netloc = host
    path = p.path or "/"
    # Collapse duplicate slashes; strip trailing slash except for bare root.
    while "//" in path:
        path = path.replace("//", "/")
    if len(path) > 1 and path.endswith("/"):
        path = path[:-1]
    # Preserve query verbatim (variability lives here — the template key blanks
    # values later; canonical form keeps them so representatives can differ).
    return urlunparse((p.scheme, netloc, path, "", p.query, ""))


def _template_key(canon_url: str) -> str:
    """Collapse concrete IDs/UUIDs/tokens in path + blank query values to a
    key that groups all variants of the same endpoint together."""
    p = urlparse(canon_url)
    segs = []
    for seg in p.path.split("/"):
        if not seg:
            segs.append(seg)
            continue
        if _UUID_RE.match(seg) or ID_SEGMENT_RE.match(seg):
            segs.append("{id}")
        else:
            segs.append(seg)
    path_key = "/".join(segs)
    # Query shape: keep sorted keys, blank values. Two URLs with the same query
    # keys but different values collapse to one — same code path.
    if p.query:
        try:
            pairs = parse_qsl(p.query, keep_blank_values=True)
            keys_only = sorted({k for k, _ in pairs})
            q_key = urlencode([(k, "") for k in keys_only])
        except Exception:
            q_key = p.query
    else:
        q_key = ""
    return f"{p.scheme}://{p.netloc}{path_key}?{q_key}"


# --------------------------------------------------------------------------- #
# Ingest
# --------------------------------------------------------------------------- #

def _iter_text_file(path: Path) -> Iterable[str]:
    if not path.is_file() or path.stat().st_size == 0:
        return
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                s = line.strip()
                if s:
                    yield s
    except Exception:
        return


def _iter_jsonl_urls(path: Path, field: str) -> Iterable[str]:
    if not path.is_file() or path.stat().st_size == 0:
        return
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except Exception:
                    continue
                v = obj.get(field)
                if isinstance(v, str) and v:
                    yield v
    except Exception:
        return


def _load_canonical_hosts(scan_dir: Path) -> Optional[set[str]]:
    """Return the set of canonical hostnames from Module 4's host_dedup output,
    or None if the file is absent (skip cluster filter, keep all hosts).

    Non-canonical cluster members serve the same app as the canonical, so
    their URLs would just double the nuclei scan load for zero unique
    coverage. Skipping is safe: findings on the canonical apply cluster-
    wide via the reporting layer."""
    path = scan_dir / HOST_CANONICAL_SOURCE
    if not path.is_file() or path.stat().st_size == 0:
        return None
    hosts: set[str] = set()
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                h = line.strip().lower()
                if h:
                    hosts.add(h)
    except Exception:
        return None
    return hosts if hosts else None


def _load_confirmed_hosts(scan_dir: Path) -> tuple[Optional[set[str]], set[str]]:
    """Parse http_hosts.txt (Module 4 httpx output) and return two sets:

      confirmed_hosts  — every hostname httpx confirmed as a live web service.
                         None if the file is absent (skip host-validation filter).
      https_hosts      — hostnames confirmed specifically via HTTPS. Used to
                         upgrade http:// URLs to https:// before dedup so that
                         http://host/path and https://host/path don't produce two
                         nuclei targets for the same endpoint. Always a set
                         (empty when file absent or no HTTPS entries).

    Each line in http_hosts.txt is a full URL (scheme included) written by httpx
    with the ACTUAL response scheme — not assumed. So if httpx confirmed
    https://api.acme-delivery.example.com and http://legacy.acme-delivery.example.com, each ends up in the
    right bucket."""
    path = scan_dir / HTTPX_CONFIRMED_HOSTS_SOURCE
    if not path.is_file() or path.stat().st_size == 0:
        return None, set()
    all_hosts: set[str] = set()
    https_hosts: set[str] = set()
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    p = urlparse(line)
                    h = p.hostname
                    if not h:
                        continue
                    h = h.lower()
                    all_hosts.add(h)
                    if p.scheme == "https":
                        https_hosts.add(h)
                except Exception:
                    continue
    except Exception:
        return None, set()
    return (all_hosts if all_hosts else None), https_hosts


def _load_wildcard_baseline(scan_dir: Path) -> tuple[Optional[set[str]], Optional[dict]]:
    """Read Module 3C's wildcard_dns.json (see dns_security_audit.py's
    _p2_wildcard). Returns (wildcard_ip_set, http_signature) or (None, None)
    if no wildcard was detected / the file is absent (auto-skip)."""
    path = scan_dir / WILDCARD_DNS_SOURCE
    if not path.is_file() or path.stat().st_size == 0:
        return None, None
    try:
        data = json.loads(path.read_text(errors="replace"))
    except Exception:
        return None, None
    if not data.get("wildcard") or not data.get("ips"):
        return None, None
    sig = data.get("http_signature") or None
    if sig is not None and not sig.get("signature_ready"):
        sig = None  # baseline probe failed at scan time — IP-only gate below
    return set(data["ips"]), sig


def _load_host_ips(scan_dir: Path) -> dict[str, set[str]]:
    """Map hostname -> resolved IP set, from Module 4's httpx output
    (host_ip = the IP actually connected to; 'a' = full answer set)."""
    path = scan_dir / HTTP_CONFIRMED_SOURCE
    out: dict[str, set[str]] = {}
    if not path.is_file() or path.stat().st_size == 0:
        return out
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                except Exception:
                    continue
                h = (e.get("host") or "").lower()
                if not h:
                    continue
                ips = set(e.get("a") or [])
                if e.get("host_ip"):
                    ips.add(e["host_ip"])
                if ips:
                    out.setdefault(h, set()).update(ips)
    except Exception:
        return out
    return out


def _load_dead_urls(scan_dir: Path) -> set[str]:
    """Read every status-carrying source and return the set of canonical URLs
    that should NOT be scanned. Two kinds of dead:

      1. Recorded HTTP status in DEAD_STATUSES (404 / 410 / 400) from Module
         8B's discovered_endpoints.jsonl — the pipeline already probed these
         and got a definite "gone / bad request" response.
      2. blocked_by_waf==true from discovered_endpoints.jsonl — the streaming
         access_control_pipeline classified this URL as WAF-blocked after
         bypass_403 failed. Nuclei scanning it just burns budget + WAF
         signal for zero coverage. The raw WAF list is also read from
         waf_blocked.jsonl as a fallback in case endpoint_consolidator
         hasn't run yet (e.g. selective --only nuclei_scan).

    Filter is by canonical URL — never template key — so a 404 or WAF block
    on one concrete URL never accidentally drops a live sibling under the
    same template."""
    dead: set[str] = set()
    for rel, url_field, status_field in STATUS_SOURCES:
        path = scan_dir / rel
        if not path.is_file() or path.stat().st_size == 0:
            continue
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                    except Exception:
                        continue
                    u = obj.get(url_field)
                    st = obj.get(status_field)
                    if isinstance(u, str):
                        # Dead status: definite non-endpoint response.
                        if isinstance(st, int) and st in DEAD_STATUSES:
                            canon = _canonicalise(u)
                            if canon:
                                dead.add(canon)
                        # WAF-classified block: bypass failed AND response
                        # matched a WAF signature.
                        if obj.get("blocked_by_waf") is True:
                            # sample_url is the concrete probe-able form.
                            for candidate in (obj.get("sample_url"), u):
                                if isinstance(candidate, str):
                                    canon = _canonicalise(candidate)
                                    if canon:
                                        dead.add(canon)
        except Exception:
            continue
    # Fallback: raw waf_blocked.jsonl from the streaming pipeline. Reads it
    # regardless of whether discovered_endpoints.jsonl is present, so a
    # selective nuclei_scan run without a prior endpoint_consolidation still
    # honours the WAF-block list.
    waf_path = scan_dir / "08_directory_discovery" / "waf_blocked.jsonl"
    if waf_path.is_file() and waf_path.stat().st_size > 0:
        try:
            with open(waf_path, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                    except Exception:
                        continue
                    u = obj.get("url")
                    if isinstance(u, str):
                        canon = _canonicalise(u)
                        if canon:
                            dead.add(canon)
        except Exception:
            pass
    return dead


def _load_inventory_urls(scan_dir: Path) -> list[str]:
    """Load URLs from the URL Inventory (endpoint_consolidator's output).

    ARCHITECTURE: `discovered_endpoints.jsonl` is the pipeline's source of
    truth for "every URL the pipeline discovered, validated, and classified".
    When it's present, we prefer it — it already carries status codes,
    WAF-block flags, and query_variants that let the nuclei feed become a
    true REDUCTION of the inventory rather than a parallel path with
    different sources.

    Returns URLs including all query_variants expanded — a row like
    `{sample_url: "/search?q=x", query_variants: ["q", "category,sort"]}`
    produces "/search?q=x" AND "/search?category=y&sort=asc" so nuclei
    tests both shapes. If the inventory is absent, returns [] and the
    caller falls back to reading raw sources."""
    p = scan_dir / "08_directory_discovery" / "discovered_endpoints.jsonl"
    if not p.is_file() or p.stat().st_size == 0:
        return []
    urls: list[str] = []
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
                sample = e.get("sample_url") or e.get("url") or ""
                if sample:
                    urls.append(sample)
                # Expand each additional query variant into a probe-able URL.
                # `keys` is a comma-separated string of query key names; we
                # generate one URL per variant with the keys blanked (nuclei
                # only cares about the shape, not the value).
                variants = e.get("query_variants") or []
                if not isinstance(variants, list):
                    continue
                try:
                    p_sample = urlparse(sample)
                except Exception:
                    continue
                if not p_sample.scheme or not p_sample.netloc:
                    continue
                base_no_q = urlunparse((p_sample.scheme, p_sample.netloc,
                                        p_sample.path, "", "", ""))
                for keys_csv in variants:
                    if not isinstance(keys_csv, str) or not keys_csv:
                        continue
                    keys = [k.strip() for k in keys_csv.split(",") if k.strip()]
                    if not keys:
                        continue
                    q = urlencode([(k, "") for k in keys])
                    urls.append(f"{base_no_q}?{q}")
    except Exception:
        return urls
    return urls


def consolidate(scan_dir: Path, include_roots: bool = False,
                cap: int = 8000, target_host: Optional[str] = None,
                include_static_assets: bool = False,
                include_dead: bool = False,
                skip_httpx_filter: bool = False,
                use_canonical_only: bool = False,
                inventory_first: bool = True) -> tuple[list[str], dict]:
    """Collect, canonicalise, template-collapse, and cap. One representative
    per template key wins; ties broken by shortest URL (cleanest example).

    Static assets (.js / .css / .png / fonts / etc — matched by the pipeline's
    shared STATIC_ASSET_RE) are dropped by default: nuclei's CVE / exposure /
    misconfig templates are meaningless against them, so scanning static assets
    only burns time and WAF budget for zero coverage. --include-static-assets
    disables the filter if the caller wants an unfiltered feed.

    URLs the pipeline already probed and observed as dead (404 / 410 / 400 —
    see DEAD_STATUSES) are dropped by default too: they're proven-gone, and
    scanning them just adds noise + WAF signal. --include-dead disables this.
    Filter is by canonical URL, NOT template key, so a 404 on one concrete
    URL never blocks its live siblings under the same template.

    Hosts not confirmed live by httpx (Module 4) are also dropped: if a
    hostname never appeared in http_hosts.txt it means httpx found no live
    web service there — either NXDOMAIN, TCP refused, or no HTTP response.
    GAU/wayback frequently returns thousands of such stale subdomains.
    Pass skip_httpx_filter=True to disable (e.g. partial scans without
    Module 4 output). If http_hosts.txt is absent the filter is auto-skipped.

    Returns (url_list, stats_dict) so callers can log the drop counts."""
    dead_urls = set() if include_dead else _load_dead_urls(scan_dir)
    if skip_httpx_filter:
        confirmed_hosts, https_hosts = None, set()
    else:
        confirmed_hosts, https_hosts = _load_confirmed_hosts(scan_dir)
    # Canonical-only is OFF by default — cluster twins get their own scans
    # because staging/UAT can have vulns production doesn't. Only enabled
    # when the caller passes use_canonical_only=True.
    canonical_hosts = (_load_canonical_hosts(scan_dir)
                       if use_canonical_only and not skip_httpx_filter
                       else None)
    wildcard_ips, wildcard_sig = (None, None) if skip_httpx_filter \
        else _load_wildcard_baseline(scan_dir)
    host_ips = _load_host_ips(scan_dir) if wildcard_ips else {}
    _wildcard_checked: dict[str, bool] = {}  # host -> is_phantom, memoized (1 live fetch/host)
    reps: dict[str, str] = {}   # template_key -> chosen canonical URL
    stats = {"seen": 0, "dropped_static": 0, "dropped_dead": 0,
             "dropped_unconfirmed_host": 0, "dropped_non_canonical_host": 0,
             "dropped_wildcard_phantom": 0,
             "http_upgraded_to_https": 0,
             "dropped_out_of_scope": 0, "collapsed": 0}

    def _consider(u: str) -> None:
        canon = _canonicalise(u)
        if canon is None:
            return
        stats["seen"] += 1
        p = urlparse(canon)

        # HTTP→HTTPS upgrade: if httpx confirmed this host responds on HTTPS,
        # rewrite the scheme before anything else. This means http://host/path
        # and https://host/path collapse to the same canonical URL and then to
        # the same template key — one nuclei target instead of two.
        # This is scheme-level dedup, not port-level (port 80 vs 443 is handled
        # separately by _canonicalise stripping default ports).
        host = (p.hostname or "").lower()
        if p.scheme == "http" and host in https_hosts:
            canon = "https://" + canon[len("http://"):]
            p = urlparse(canon)
            stats["http_upgraded_to_https"] += 1

        if not include_static_assets and STATIC_ASSET_RE.search(p.path or ""):
            stats["dropped_static"] += 1
            return
        if canon in dead_urls:
            stats["dropped_dead"] += 1
            return
        # httpx host validation: drop URLs whose hostname was never confirmed
        # as a live web service by httpx in Module 4. Covers NXDOMAIN hosts
        # (stale GAU/wayback entries) and hosts that resolve but aren't HTTP.
        if confirmed_hosts is not None:
            if host and host not in confirmed_hosts:
                stats["dropped_unconfirmed_host"] += 1
                return
        # Wildcard-DNS phantom filtering: a host that only "lives" because it
        # shares the wildcard's catch-all IP is not a real endpoint — CT/gau/
        # wayback are full of never-provisioned names that resolve this way.
        # Gate is IP-membership first (cheap, no network call), then ONE live
        # fetch (memoized per host) to confirm it actually serves the same
        # catch-all response — a real app that coincidentally shares the
        # wildcard IP (shared load balancer, same origin) is kept, not dropped.
        if wildcard_ips and host:
            host_ip_set = host_ips.get(host)
            if host_ip_set and (host_ip_set & wildcard_ips):
                if host not in _wildcard_checked:
                    # Fail OPEN: no baseline signature (probe failed at
                    # detection time) means we cannot prove this host is the
                    # phantom catch-all, so it is kept — IP overlap alone is
                    # not enough evidence to drop a URL. We'd rather show a
                    # possible duplicate than hide a real endpoint.
                    is_phantom = False
                    if wildcard_sig is not None:
                        try:
                            from discovery.soft404_detector import is_catchall_response
                            is_phantom, _ = is_catchall_response(canon, wildcard_sig)
                        except Exception:
                            is_phantom = False
                    _wildcard_checked[host] = is_phantom
                if _wildcard_checked[host]:
                    stats["dropped_wildcard_phantom"] += 1
                    return
        # Host clustering: drop URLs whose host is a non-canonical cluster
        # member. host_dedup.py already picked a representative per cluster;
        # scanning cluster twins doubles work for zero new coverage. Only
        # applied when host_canonical.txt is present (Module 4 completed
        # its dedup pass) — otherwise all hosts pass through.
        if canonical_hosts is not None:
            if host and host not in canonical_hosts:
                stats["dropped_non_canonical_host"] += 1
                return
        if target_host:
            # Scope filter: only keep URLs whose host matches the target or is
            # a subdomain of it. Nuclei against out-of-scope hosts is wasted
            # bandwidth AND a compliance risk on scoped engagements.
            if not (host == target_host or host.endswith("." + target_host)):
                stats["dropped_out_of_scope"] += 1
                return
        key = _template_key(canon)
        prev = reps.get(key)
        if prev is None or len(canon) < len(prev):
            reps[key] = canon

    # ── Source selection ──────────────────────────────────────────────
    # ARCHITECTURE: URL Inventory (discovered_endpoints.jsonl) is the
    # pipeline's source of truth. When it exists, we consume ONLY it —
    # every URL there has already been validated, classified, WAF-flagged
    # (blocked_by_waf), and 403-bypass-checked. The nuclei feed becomes
    # a REDUCTION of the inventory (drop static/dead/WAF-blocked, template-
    # collapse, cap) rather than a parallel scan of raw sources. This is
    # the deferred Phase 3 "feeder cutover" from url-inventory-layer.md.
    #
    # Fallback: if the inventory is absent (partial scan, --only nuclei_scan
    # without endpoint_consolidation first), read the raw 13 sources
    # directly — same behaviour as before this refactor. This keeps
    # selective runs working while making the default path inventory-first.
    inventory_urls = _load_inventory_urls(scan_dir) if inventory_first else []
    stats["source_mode"] = "inventory" if inventory_urls else "raw-sources"
    if inventory_urls:
        for u in inventory_urls:
            _consider(u)
    else:
        for rel, is_jsonl, field in TEXT_URL_SOURCES:
            for u in _iter_text_file(scan_dir / rel):
                _consider(u)
        for rel, field in JSONL_URL_SOURCES:
            for u in _iter_jsonl_urls(scan_dir / rel, field):
                _consider(u)
    if include_roots:
        for u in _iter_text_file(scan_dir / ROOTS_SOURCE):
            _consider(u)

    # Deterministic order — sorted so runs are reproducible and the cap slices
    # the same way each time.
    urls = sorted(reps.values())
    stats["collapsed"] = len(urls)
    if cap and len(urls) > cap:
        urls = urls[:cap]
    stats["kept"] = len(urls)
    stats["dead_url_set_size"] = len(dead_urls)
    return urls, stats


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def main() -> int:
    ap = argparse.ArgumentParser(description="Consolidate URL inventory for nuclei deep-surface scan")
    ap.add_argument("scan_dir", help="Path to the scan output directory (e.g. scans/<target>-<date>)")
    ap.add_argument("--out", required=True, help="Path to write the consolidated URL list")
    ap.add_argument("--cap", type=int, default=8000,
                    help="Max URLs to keep after template collapse (default: 8000). 0 = no cap.")
    ap.add_argument("--include-roots", action="store_true",
                    help="Also include 04_http_discovery/http_hosts.txt (site roots). "
                         "Off by default because nuclei Phase 1 already scans roots.")
    ap.add_argument("--target-host", default=None,
                    help="Restrict to URLs whose host equals or is a subdomain of this host. "
                         "Keeps consolidator honest on scoped engagements.")
    ap.add_argument("--include-static-assets", action="store_true",
                    help="Keep static-asset URLs (.js/.css/.png/fonts/etc). "
                         "Off by default — nuclei's exposure/CVE/misconfig "
                         "templates don't apply to them and they only burn "
                         "scan budget + WAF signal.")
    ap.add_argument("--include-dead", action="store_true",
                    help="Keep URLs the pipeline already probed and observed as "
                         "dead (404 / 410 / 400). Off by default — proven-gone "
                         "URLs only add WAF signal for zero coverage. 401/403 "
                         "and 5xx are kept regardless (still real endpoints).")
    ap.add_argument("--skip-httpx-filter", action="store_true",
                    help="Skip the httpx host-validation filter. By default URLs "
                         "whose hostname does not appear in "
                         "04_http_discovery/http_hosts.txt are dropped (they were "
                         "never confirmed as live web services by Module 4 httpx). "
                         "Use this flag if http_hosts.txt is unavailable (e.g. "
                         "partial scan or --only nuclei_scan without Module 4).")
    ap.add_argument("--use-canonical-only", action="store_true",
                    help="OPT-IN aggressive dedup: drop URLs whose hostname is a "
                         "non-canonical member of a Module-4 host_dedup cluster. "
                         "OFF BY DEFAULT because staging/UAT twins routinely "
                         "carry vulns production doesn't (unpatched CVEs, debug "
                         "endpoints, default creds). Only enable when scan time "
                         "matters more than coverage.")
    ap.add_argument("--no-inventory-first", action="store_true",
                    help="ARCHITECTURE ESCAPE HATCH. By default, when "
                         "discovered_endpoints.jsonl exists we consume it as "
                         "the sole URL source (URL Inventory = source of truth). "
                         "Pass this flag to force the old behaviour of reading "
                         "raw sources directly. Useful when the inventory is "
                         "suspected stale or when running --only nuclei_scan "
                         "without a fresh endpoint_consolidation.")
    ap.add_argument("--stats", action="store_true", help="Print raw/consolidated counts to stderr")
    args = ap.parse_args()

    scan_dir = Path(args.scan_dir)
    if not scan_dir.is_dir():
        print(f"[consolidator] scan_dir not found: {scan_dir}", file=sys.stderr)
        return 1

    urls, stats = consolidate(scan_dir, include_roots=args.include_roots,
                              cap=args.cap, target_host=args.target_host,
                              include_static_assets=args.include_static_assets,
                              include_dead=args.include_dead,
                              skip_httpx_filter=getattr(args, "skip_httpx_filter", False),
                              use_canonical_only=getattr(args, "use_canonical_only", False),
                              inventory_first=not getattr(args, "no_inventory_first", False))

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as fh:
        for u in urls:
            fh.write(u + "\n")

    if args.stats:
        print(
            f"[consolidator] source={stats.get('source_mode','?')} "
            f"wrote {len(urls)} URL(s) to {out_path} "
            f"(seen={stats['seen']}, "
            f"http_upgraded={stats.get('http_upgraded_to_https', 0)}, "
            f"static_dropped={stats['dropped_static']}, "
            f"dead_dropped={stats['dropped_dead']}, "
            f"unconfirmed_host_dropped={stats.get('dropped_unconfirmed_host', 0)}, "
            f"wildcard_phantom_dropped={stats.get('dropped_wildcard_phantom', 0)}, "
            f"non_canonical_host_dropped={stats.get('dropped_non_canonical_host', 0)}, "
            f"out_of_scope={stats['dropped_out_of_scope']}, "
            f"dead_set={stats['dead_url_set_size']})",
            file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
