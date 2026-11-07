#!/usr/bin/env python3
"""
ARISE Module 23 — Internet Intelligence Layer (IIL)
=====================================================

Consolidates every ARISE module's output into ONE deduplicated, geolocated
asset inventory and surfaces it as a single global-risk view for the Overview
dashboard. Tool-agnostic: the UI shows consolidated intelligence, never
"this came from tool X".

Design contract (same as Modules 18/22):
  * stdlib + certifi only — no new hard dependencies,
  * fully passive — public read-only APIs,
  * honours the "skip WAF/CDN IPs" rule (origin IPs only),
  * degrades gracefully — missing keys just skip that provider; never exits !=0.

Geolocation strategy (the map's lifeblood), in priority order per asset:
  1. Offline mining of PTR / hostname datacenter codes  (FREE, no key)
       - AWS/GCP/Azure region tokens   (ec2-…-.ap-south-1.compute.amazonaws.com)
       - legacy AWS `compute-1`         (= us-east-1)
       - CDN edge airport/colo codes    (…blr50.r.cloudfront.net → BLR/Bangalore)
  2. Censys host geo                    (if CENSYS_API_ID/SECRET set)
  3. ipinfo.io geo                      (fallback API — IPINFO_TOKEN in Settings)
  4. Shodan raw lat/lon                 (reused from Module 22, if present)
  5. Country centroid                   (from any country signal)

Data sources consumed (read-only):
  03_dns_resolution/    all_ips.txt, cdn_ips.txt, ip_annotations.json (JSONL,
                        keyed by `host` = IP, carries `ptr`/`all`/`cdn`)
  04_http_discovery/    http_confirmed.json (JSONL)
  05_waf_detection/     *.json
  07_service_fingerprint/ services.json (flat array of per-host/ip records)
  12_nuclei_scanning/   nuclei_results.txt (JSONL)
  14_port_scan/         all_ports.jsonl
  18_osint_intel/       osint_summary.json, osint_findings.jsonl
  22_shodan_correlation/ shodan_summary.json, shodan_assets.jsonl,
                         shodan_findings.jsonl, shodan_raw/<ip>.json
  manifest.json

External enrichment (optional, keyed):
  Censys    — services, geo, ASN          (CENSYS_API_ID + CENSYS_API_SECRET)
  GreyNoise — scanner classification       (GREYNOISE_API_KEY)
  ipinfo.io — geo/city/org fallback        (IPINFO_TOKEN)

Output (23_internet_intel/):
  intel_assets.jsonl    one consolidated asset per origin IP
  intel_findings.jsonl  deduplicated findings from all modules
  intel_summary.json    global stats, top 10s, geo breakdown, risk score

Usage:
  python3 internet_intel.py <OUTPUT_DIR> [--domain target.com] [--no-net]

Env knobs:
  CENSYS_API_ID / CENSYS_API_SECRET / GREYNOISE_API_KEY / IPINFO_TOKEN
  IIL_MAX_IPS   cap on IPs to API-enrich   (default 200)
  IIL_TIMEOUT   per-request seconds         (default 8)
  IIL_WORKERS   concurrent lookups          (default 8)
  IIL_BUDGET    overall wall-clock seconds  (default 180)
  IIL_NO_NET    true → skip all network calls
"""

import sys as _sys, os as _os
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)


import os
import re
import sys
import json
import time
import base64
import shutil
import ipaddress
import argparse
import subprocess
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

# .arise_kev_cache.json lives at PROJECT_ROOT, not next to this file, which
# now lives one level down at intel/ -- walk up one level.
_BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

try:
    import ssl
    from urllib.request import Request, urlopen
    from urllib.error import HTTPError
except Exception:
    ssl = Request = urlopen = HTTPError = None

try:
    import core.arise_secure as arise_secure
except Exception:
    arise_secure = None


# ── key resolution (vault → env) ──────────────────────────────────────────

def _resolve_key(name, *aliases):
    if arise_secure is not None:
        try:
            val = arise_secure.resolve_secret(name)
            if val:
                return val.strip()
        except Exception:
            pass
    for env in (name, *aliases):
        val = os.environ.get(env, "").strip()
        if val:
            return val
    return ""


# ── SSL / HTTP helpers ────────────────────────────────────────────────────

def _build_ssl_context():
    if ssl is None:
        return None
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except Exception:
        pass
    try:
        return ssl.create_default_context()
    except Exception:
        return None


_SSL_CTX = None


def _ssl_ctx():
    global _SSL_CTX
    if _SSL_CTX is None:
        _SSL_CTX = _build_ssl_context()
    return _SSL_CTX


def _http_get_json(url, timeout, headers=None):
    if urlopen is None:
        return None, "no-urllib"
    req = Request(url)
    req.add_header("User-Agent", "ARISE-IIL/2.0")
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)
    try:
        resp = urlopen(req, timeout=timeout, context=_ssl_ctx())
        return json.loads(resp.read().decode("utf-8", errors="replace")), None
    except HTTPError as e:
        return None, "http-%d" % e.code
    except Exception as e:
        return None, str(e)[:80]


# ── small utils ───────────────────────────────────────────────────────────

def _now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _log(logf, msg):
    ts = datetime.now().strftime("%H:%M:%S")
    logf.write("[%s] %s\n" % (ts, msg))
    logf.flush()


def _read_lines(path):
    if not os.path.isfile(path):
        return []
    with open(path) as f:
        return [l.strip() for l in f if l.strip()]


def _read_jsonl(path):
    if not os.path.isfile(path):
        return []
    out = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except Exception:
                    pass
    return out


def _read_json(path, default=None):
    if not os.path.isfile(path):
        return default
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return default


def _as_list(v):
    if v is None:
        return []
    if isinstance(v, list):
        return v
    return [v]


_HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9_]([a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$")


def _clean_host(h):
    """Return a normalized hostname, or None if `h` isn't a clean DNS name.

    IP-annotation `all` fields can contain raw dig output (PTR lines,
    ';; OPT PSEUDOSECTION', 'EDNS: …') — this rejects that noise and, when a
    line is a PTR record, extracts the actual hostname from it.
    """
    if not h:
        return None
    s = str(h).strip().lower().rstrip(".")
    if not s:
        return None
    # Pull the target out of a raw PTR line: "x.in-addr.arpa. 300 in ptr host."
    m = re.search(r"\bptr\s+(\S+?)\.?$", s)
    if m:
        s = m.group(1)
    # Reject dig-output / non-hostname noise.
    if any(bad in s for bad in (";", "pseudosection", "edns", "flags:",
                                "udp:", "in-addr.arpa", " ", "\t", "\n")):
        return None
    return s if _HOST_RE.match(s) else None


def _is_public_ip(s):
    try:
        a = ipaddress.ip_address(s)
        return a.is_global and not a.is_multicast
    except Exception:
        return False


KNOWN_CDN_CIDRS = [
    "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    "141.101.64.0/18", "173.245.48.0/20", "190.93.240.0/20", "197.234.240.0/22",
    "198.41.128.0/17", "162.158.0.0/15", "151.101.0.0/16",
    "23.32.0.0/11", "23.64.0.0/14", "23.192.0.0/11", "199.27.72.0/21",
]
_CDN_NETS = None


def _is_known_cdn_ip(s):
    global _CDN_NETS
    if _CDN_NETS is None:
        _CDN_NETS = [ipaddress.ip_network(c) for c in KNOWN_CDN_CIDRS]
    try:
        a = ipaddress.ip_address(s)
        return any(a in n for n in _CDN_NETS)
    except Exception:
        return False


SEV_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
# AI/MCP tag confidence ladder (Module 8D). Mirrors discovery/url_classify.py.
_AI_CONF_RANK = {"": 0, None: 0, "path-hint": 1, "fingerprint": 2, "confirmed": 3}

# Asset-level host-label tagging: an AI-named host (mcp.*, ai.*, llm.*) is an
# AI/MCP ASSET even if no individual AI URL was crawled on it. (URL-level
# tagging stays path/body-only to avoid flooding the URL inventory.)
try:
    from discovery.url_classify import ai_host_label as _ai_host_label
except Exception:  # pragma: no cover
    def _ai_host_label(_h):
        return None
# UNAMBIGUOUS AI default ports — a validated (nmap) open port here is a strong
# inventory hint even when no AI URL was crawled. Tag only (no finding; the
# probe module owns confirmed findings). Ambiguous shared ports (8000/8080) are
# deliberately excluded to stay false-positive-free.
_AI_PORT_HINT = {11434: ("llm-api", "ollama"), 7860: ("ai-agent", "gradio")}


# ── GEO reference tables ──────────────────────────────────────────────────
# Each entry: code -> [lat, lon, country_code]

# Cloud provider regions (AWS + GCP + Azure). Token as it appears in PTR/host.
CLOUD_REGION_GEO = {
    # AWS
    "us-east-1": [39.02, -77.47, "US"], "compute-1": [39.02, -77.47, "US"],
    "us-east-2": [40.00, -83.00, "US"], "us-west-1": [37.35, -121.96, "US"],
    "us-west-2": [45.87, -119.69, "US"], "af-south-1": [-33.93, 18.42, "ZA"],
    "ap-east-1": [22.28, 114.16, "HK"], "ap-south-1": [19.08, 72.88, "IN"],
    "ap-south-2": [17.41, 78.47, "IN"], "ap-southeast-1": [1.32, 103.80, "SG"],
    "ap-southeast-2": [-33.86, 151.21, "AU"], "ap-southeast-3": [-6.21, 106.85, "ID"],
    "ap-southeast-4": [-37.81, 144.96, "AU"], "ap-northeast-1": [35.68, 139.76, "JP"],
    "ap-northeast-2": [37.56, 126.97, "KR"], "ap-northeast-3": [34.69, 135.50, "JP"],
    "ca-central-1": [45.50, -73.57, "CA"], "eu-central-1": [50.11, 8.68, "DE"],
    "eu-central-2": [47.37, 8.54, "CH"], "eu-west-1": [53.34, -6.26, "IE"],
    "eu-west-2": [51.51, -0.13, "GB"], "eu-west-3": [48.86, 2.35, "FR"],
    "eu-north-1": [59.33, 18.06, "SE"], "eu-south-1": [45.46, 9.19, "IT"],
    "eu-south-2": [40.42, -3.70, "ES"], "me-south-1": [26.07, 50.55, "BH"],
    "me-central-1": [24.47, 54.37, "AE"], "sa-east-1": [-23.55, -46.63, "BR"],
    "il-central-1": [32.08, 34.78, "IL"],
    # GCP
    "us-central1": [41.26, -95.94, "US"], "us-east1": [33.20, -80.01, "US"],
    "us-east4": [39.02, -77.47, "US"], "us-west1": [45.60, -121.18, "US"],
    "us-west2": [34.05, -118.24, "US"], "europe-west1": [50.45, 3.82, "BE"],
    "europe-west2": [51.51, -0.13, "GB"], "europe-west3": [50.11, 8.68, "DE"],
    "europe-west4": [53.44, 6.83, "NL"], "asia-south1": [19.08, 72.88, "IN"],
    "asia-southeast1": [1.32, 103.80, "SG"], "asia-east1": [24.05, 120.52, "TW"],
    "asia-northeast1": [35.68, 139.76, "JP"], "australia-southeast1": [-33.86, 151.21, "AU"],
    "southamerica-east1": [-23.55, -46.63, "BR"],
    # Azure
    "eastus": [37.37, -79.82, "US"], "eastus2": [36.67, -78.39, "US"],
    "westus": [37.78, -122.42, "US"], "westus2": [47.23, -119.85, "US"],
    "centralus": [41.59, -93.62, "US"], "westeurope": [52.37, 4.90, "NL"],
    "northeurope": [53.34, -6.26, "IE"], "uksouth": [51.51, -0.13, "GB"],
    "southeastasia": [1.32, 103.80, "SG"], "japaneast": [35.68, 139.76, "JP"],
    "australiaeast": [-33.86, 151.21, "AU"], "centralindia": [18.52, 73.86, "IN"],
    "southindia": [12.97, 80.16, "IN"], "brazilsouth": [-23.55, -46.63, "BR"],
}

# IATA / CDN colo airport codes → coords (major datacenter cities).
IATA_GEO = {
    "iad": [39.02, -77.47, "US"], "dca": [38.85, -77.04, "US"], "sfo": [37.62, -122.38, "US"],
    "sjc": [37.36, -121.93, "US"], "lax": [33.94, -118.41, "US"], "sea": [47.45, -122.31, "US"],
    "ord": [41.98, -87.90, "US"], "dfw": [32.90, -97.04, "US"], "jfk": [40.64, -73.78, "US"],
    "ewr": [40.69, -74.17, "US"], "atl": [33.64, -84.43, "US"], "mia": [25.79, -80.29, "US"],
    "den": [39.86, -104.67, "US"], "phx": [33.43, -112.01, "US"], "iah": [29.98, -95.34, "US"],
    "bos": [42.36, -71.01, "US"], "yyz": [43.68, -79.63, "CA"], "yul": [45.47, -73.74, "CA"],
    "yvr": [49.19, -123.18, "CA"], "lhr": [51.47, -0.45, "GB"], "man": [53.35, -2.28, "GB"],
    "cdg": [49.01, 2.55, "FR"], "mrs": [43.44, 5.22, "FR"], "ams": [52.31, 4.76, "NL"],
    "fra": [50.04, 8.56, "DE"], "muc": [48.35, 11.79, "DE"], "ham": [53.63, 9.99, "DE"],
    "dus": [51.29, 6.77, "DE"], "txl": [52.56, 13.29, "DE"], "zrh": [47.46, 8.55, "CH"],
    "vie": [48.11, 16.57, "AT"], "waw": [52.17, 20.97, "PL"], "arn": [59.65, 17.92, "SE"],
    "osl": [60.19, 11.10, "NO"], "hel": [60.32, 24.96, "FI"], "cph": [55.62, 12.65, "DK"],
    "dub": [53.43, -6.27, "IE"], "mad": [40.47, -3.56, "ES"], "bcn": [41.30, 2.08, "ES"],
    "lis": [38.77, -9.13, "PT"], "mxp": [45.63, 8.72, "IT"], "fco": [41.80, 12.24, "IT"],
    "ath": [37.94, 23.95, "GR"], "prg": [50.10, 14.26, "CZ"], "bud": [47.44, 19.26, "HU"],
    "otp": [44.57, 26.09, "RO"], "sof": [42.70, 23.41, "BG"], "ist": [41.28, 28.75, "TR"],
    "sin": [1.36, 103.99, "SG"], "hkg": [22.31, 113.92, "HK"], "nrt": [35.77, 140.39, "JP"],
    "hnd": [35.55, 139.78, "JP"], "kix": [34.43, 135.24, "JP"], "icn": [37.46, 126.44, "KR"],
    "tpe": [25.08, 121.23, "TW"], "bkk": [13.69, 100.75, "TH"], "cgk": [-6.13, 106.66, "ID"],
    "kul": [2.75, 101.71, "MY"], "syd": [-33.95, 151.18, "AU"], "mel": [-37.67, 144.84, "AU"],
    "per": [-31.94, 115.97, "AU"], "akl": [-37.01, 174.79, "NZ"], "bom": [19.09, 72.87, "IN"],
    "del": [28.56, 77.10, "IN"], "maa": [12.99, 80.17, "IN"], "blr": [12.97, 77.59, "IN"],
    "hyd": [17.24, 78.43, "IN"], "ccu": [22.65, 88.45, "IN"], "pnq": [18.58, 73.92, "IN"],
    "nag": [21.09, 79.05, "IN"], "dxb": [25.25, 55.36, "AE"], "auh": [24.43, 54.65, "AE"],
    "ruh": [24.96, 46.70, "SA"], "jed": [21.68, 39.16, "SA"], "bah": [26.27, 50.63, "BH"],
    "tlv": [32.01, 34.89, "IL"], "gru": [-23.43, -46.47, "BR"], "gig": [-22.81, -43.25, "BR"],
    "scl": [-33.39, -70.79, "CL"], "eze": [-34.82, -58.54, "AR"], "bog": [4.70, -74.15, "CO"],
    "lim": [-12.02, -77.11, "PE"], "cpt": [-33.97, 18.60, "ZA"], "jnb": [-26.13, 28.24, "ZA"],
    "los": [6.58, 3.32, "NG"], "nbo": [-1.32, 36.93, "KE"],
}

COUNTRY_CENTROIDS = {
    "US": [39.8, -98.6], "GB": [54.0, -2.0], "DE": [51.2, 10.4], "FR": [46.2, 2.2],
    "JP": [36.2, 138.3], "AU": [-25.3, 133.8], "CA": [56.1, -106.3], "IN": [22.6, 79.0],
    "BR": [-14.2, -51.9], "SG": [1.35, 103.8], "NL": [52.1, 5.3], "IE": [53.4, -8.2],
    "SE": [60.1, 18.6], "KR": [35.9, 127.8], "HK": [22.4, 114.1], "CN": [35.9, 104.2],
    "RU": [61.5, 105.3], "ZA": [-30.6, 22.9], "IL": [31.0, 34.9], "AE": [23.4, 53.8],
    "SA": [23.9, 45.1], "IT": [41.9, 12.6], "ES": [40.5, -3.7], "PL": [51.9, 19.1],
    "CH": [46.8, 8.2], "AT": [47.5, 14.6], "FI": [61.9, 25.7], "NO": [60.5, 8.5],
    "DK": [56.3, 9.5], "PT": [39.4, -8.2], "BE": [50.5, 4.5], "CZ": [49.8, 15.5],
    "RO": [45.9, 25.0], "MX": [23.6, -102.6], "AR": [-38.4, -63.6], "CL": [-35.7, -71.5],
    "CO": [4.6, -74.3], "PE": [-9.2, -75.0], "TW": [23.7, 121.0], "TH": [15.9, 100.5],
    "VN": [14.1, 108.3], "PH": [12.9, 121.8], "ID": [-2.5, 118.0], "MY": [4.2, 101.9],
    "NZ": [-40.9, 174.9], "EG": [26.8, 30.8], "NG": [9.1, 8.7], "KE": [-0.02, 37.9],
    "PK": [30.4, 69.3], "BD": [23.7, 90.4], "UA": [48.4, 31.2], "TR": [39.0, 35.2],
    "GR": [39.1, 21.8], "HU": [47.2, 19.5], "BG": [42.7, 25.5], "BH": [26.0, 50.5],
}

# Sorted longest-first so ap-southeast-1 wins over any shorter substring.
_REGION_TOKENS = sorted(CLOUD_REGION_GEO.keys(), key=len, reverse=True)


def _provider_from(text):
    if not text:
        return ""
    t = text.lower()
    for kw, label in [("amazon", "AWS"), ("aws", "AWS"), ("cloudfront", "AWS"),
                      ("google", "GCP"), ("gcp", "GCP"), ("microsoft", "Azure"),
                      ("azure", "Azure"), ("digitalocean", "DigitalOcean"),
                      ("linode", "Linode"), ("akamai", "Akamai"), ("fastly", "Fastly"),
                      ("ovh", "OVH"), ("hetzner", "Hetzner"), ("oracle", "OCI"),
                      ("alibaba", "Alibaba"), ("vultr", "Vultr"), ("cloudflare", "Cloudflare")]:
        if kw in t:
            return label
    return ""


# ── GEO miner (offline, no key) ───────────────────────────────────────────

def _labels_from(strings):
    """Explode host/PTR strings into lowercase dot-labels."""
    labels = []
    for s in strings:
        if not s:
            continue
        for part in str(s).lower().split("."):
            part = part.strip()
            if part:
                labels.append(part)
    return labels


def mine_geo(ptrs, hostnames):
    """Derive datacenter coords from PTR/hostname datacenter codes.

    Returns {'lat','lon','country','source'} or None.
    """
    strings = list(ptrs or []) + list(hostnames or [])
    if not strings:
        return None
    blob = " ".join(str(s).lower() for s in strings)

    # 1) explicit cloud region token (delimited by non-alnum to avoid partials)
    for token in _REGION_TOKENS:
        if re.search(r"(?<![a-z0-9])" + re.escape(token) + r"(?![a-z0-9])", blob):
            lat, lon, cc = CLOUD_REGION_GEO[token]
            return {"lat": lat, "lon": lon, "country": cc, "source": "cloud-region"}

    # 2) CDN edge airport/colo code — a label like blr50 / iad12 / fra6
    for lab in _labels_from(strings):
        m = re.match(r"^([a-z]{3})\d{1,3}$", lab)
        if m and m.group(1) in IATA_GEO:
            lat, lon, cc = IATA_GEO[m.group(1)]
            return {"lat": lat, "lon": lon, "country": cc, "source": "cdn-colo"}

    # 3) bare 3-letter IATA label inside a CDN/edge domain
    if any(k in blob for k in ("cloudfront", "cloudflare", "fastly", "edge",
                               "cdn", "akamai", "llnwd", "cachefly")):
        for lab in _labels_from(strings):
            if len(lab) == 3 and lab in IATA_GEO:
                lat, lon, cc = IATA_GEO[lab]
                return {"lat": lat, "lon": lon, "country": cc, "source": "cdn-colo"}
    return None


def _country_centroid(cc):
    if cc and cc.upper() in COUNTRY_CENTROIDS:
        lat, lon = COUNTRY_CENTROIDS[cc.upper()]
        return {"lat": lat, "lon": lon, "country": cc.upper(), "source": "country"}
    return None


# ── Module output readers ─────────────────────────────────────────────────

def _corroborate_nuclei_severity(nuclei_findings, out_dir, logf):
    """Cluster A fix (P1 item 9, ARISE_REMEDIATION_ROADMAP.md): internet_intel
    used to derive issue severity from nuclei_results.txt in isolation, blind
    to whether Module 24 (offensive_verify), Module 27 (adaptive_loop) or the
    Autonomous engine independently confirmed the SAME vuln — which
    dashboard.py's Vulns tab already reconciles via offensive/finding_reconciler,
    so the identical bug could show two different severities in two tabs
    (exactly the "same bug, two severities" pattern found repeatedly this
    review). Smallest correct fix: run the SAME reconciler across the union of
    engines and adopt its corroboration-climbed severity back onto the native
    nuclei records in place, rather than restructuring internet_intel's own
    finding shape or its downstream consumers. Fail-open; mutates in place."""
    if not nuclei_findings:
        return nuclei_findings
    try:
        from offensive.finding_reconciler import (
            reconcile as _reconcile, from_autonomous as _from_auto, reconcile_key as _rkey)
    except Exception:
        return nuclei_findings

    def _nuclei_shape(nf):
        info = nf.get("info", {}) if isinstance(nf.get("info"), dict) else {}
        return {"detection_tool": "nuclei", "source": "Nuclei",
                "template": nf.get("template-id", "") or nf.get("template", ""),
                "severity": (info.get("severity") or nf.get("severity") or "info").lower(),
                "host": nf.get("host", ""), "url": nf.get("matched-at", "") or nf.get("url", ""),
                "extracted_results": nf.get("extracted-results") or nf.get("extracted_results")}

    # reconcile() only keeps ONE record per bucket (the richest) in its output
    # — it does not preserve a back-reference to every input, so a nuclei
    # record can lose to a richer offensive_verify one and vanish from the
    # merged list entirely. Match back by (class, host, path, param) key
    # instead of object identity, computed independently on each side.
    shaped = [_nuclei_shape(nf) for nf in nuclei_findings]
    other = []
    for rel, tool, src in (("24_advanced_attacks/offensive_findings.jsonl", "offensive_verify", "Offensive Verification"),
                           ("27_adaptive_loop/loop_findings.jsonl", "adaptive_loop", "Adaptive Loop")):
        for r in _read_jsonl(os.path.join(out_dir, rel)):
            info = r.get("info", {}) if isinstance(r.get("info"), dict) else {}
            other.append({"detection_tool": tool, "source": src,
                          "template": r.get("template-id", "") or r.get("check", "") or r.get("template", ""),
                          "severity": (info.get("severity") or r.get("severity") or "info").lower(),
                          "host": r.get("host", ""), "url": r.get("matched-at", "") or r.get("url", ""),
                          "confidence": r.get("confidence", "")})
    ai_path = os.path.join(out_dir, "ai_autonomous.json")
    if os.path.exists(ai_path):
        try:
            with open(ai_path, errors="ignore") as fh:
                other.extend(_from_auto(json.load(fh)))
        except Exception:
            pass

    if not other:
        return nuclei_findings  # nothing else to corroborate against

    try:
        merged = _reconcile(shaped + other)
        merged_by_key = {}
        for m in merged:
            try:
                merged_by_key[_rkey(m)] = m
            except Exception:
                continue
    except Exception as exc:
        _log(logf, "nuclei severity corroboration skipped: %s" % exc)
        return nuclei_findings

    boosted = 0
    for nf, sh in zip(nuclei_findings, shaped):
        try:
            m = merged_by_key.get(_rkey(sh))
        except Exception:
            continue
        # Only act when >=2 DISTINCT engines actually landed in this bucket —
        # corroborated_by is unset otherwise, so this never fires just
        # because another nuclei finding shared the bucket.
        if not m or len(m.get("corroborated_by") or []) < 2:
            continue
        new_sev = (m.get("severity") or "").lower()
        info = nf.get("info") if isinstance(nf.get("info"), dict) else None
        old_sev = ((info.get("severity") if info else nf.get("severity", "")) or "info").lower()
        if new_sev and new_sev != old_sev:
            if info is not None:
                info["severity"] = new_sev
            else:
                nf["severity"] = new_sev
            nf["_corroborated_by"] = m["corroborated_by"]
            boosted += 1
    if boosted:
        _log(logf, "reconciler: corroboration-adjusted severity for %d nuclei finding(s)" % boosted)
    return nuclei_findings


def load_all_modules(out_dir, logf):
    """Read every module's output into a unified observed-state dict."""

    # Module 3 — DNS resolution + IP annotations (keyed by `host` = IP).
    dns_dir = os.path.join(out_dir, "03_dns_resolution")
    all_ips = set(_read_lines(os.path.join(dns_dir, "all_ips.txt")))
    cdn_ips = set(_read_lines(os.path.join(dns_dir, "cdn_ips.txt")))

    ip_annotations = {}     # ip -> raw annotation record
    ip_ptr = {}             # ip -> [ptr strings]
    ip_hostnames = {}       # ip -> set(hostnames)
    for rec in _read_jsonl(os.path.join(dns_dir, "ip_annotations.json")):
        ip = rec.get("ip") or rec.get("host") or ""
        if not ip:
            continue
        ip_annotations[ip] = rec
        # PTR strings feed geo mining raw (regex tolerates noise); hostnames
        # shown in the UI must be cleaned.
        ptrs = _as_list(rec.get("ptr"))
        if ptrs:
            ip_ptr[ip] = ptrs
        hs = set()
        for h in (_as_list(rec.get("all")) + _as_list(rec.get("hostnames")) + ptrs):
            ch = _clean_host(h)
            if ch and ch != ip:
                hs.add(ch)
        if hs:
            ip_hostnames.setdefault(ip, set()).update(hs)
        if rec.get("cdn"):
            cdn_ips.add(ip)

    # Module 4 — HTTP discovery (host → record).
    http_hosts = {}
    for rec in _read_jsonl(os.path.join(out_dir, "04_http_discovery", "http_confirmed.json")):
        host = rec.get("host") or ""
        if not host:
            url = rec.get("url", "")
            if "://" in url:
                host = url.split("://")[1].split("/")[0].split(":")[0]
        if host:
            http_hosts[host] = rec

    # Module 7 — Service fingerprint (flat array; group by ip).
    svc_data = _read_json(os.path.join(out_dir, "07_service_fingerprint", "services.json"))
    ip_services = {}
    if isinstance(svc_data, list):
        for rec in svc_data:
            svc_ip = rec.get("ip") or rec.get("host") or ""
            if svc_ip:
                ip_services.setdefault(svc_ip, []).append(rec)
            ch = _clean_host(rec.get("host"))
            if ch and ch != svc_ip:
                ip_hostnames.setdefault(svc_ip, set()).add(ch)
    elif isinstance(svc_data, dict):
        for host_key, svc_list in svc_data.items():
            if isinstance(svc_list, list):
                ip_services[host_key] = svc_list

    # Module 12 — Nuclei findings.
    nuclei_findings = _read_jsonl(os.path.join(out_dir, "12_nuclei_scanning", "nuclei_results.txt"))
    _corroborate_nuclei_severity(nuclei_findings, out_dir, logf)

    # Module 14 — Port scan.
    ip_ports = {}
    for rec in _read_jsonl(os.path.join(out_dir, "14_port_scan", "all_ports.jsonl")):
        ip = rec.get("ip") or rec.get("host") or ""
        port = rec.get("port")
        if ip and port:
            try:
                ip_ports.setdefault(ip, set()).add(int(port))
            except (TypeError, ValueError):
                pass

    # Module 18 — OSINT.
    osint_summary = _read_json(os.path.join(out_dir, "18_osint_intel", "osint_summary.json"), {}) or {}
    osint_findings = _read_jsonl(os.path.join(out_dir, "18_osint_intel", "osint_findings.jsonl"))

    # Module 22 — Shodan correlation.
    shodan_dir = os.path.join(out_dir, "22_shodan_correlation")
    shodan_summary = _read_json(os.path.join(shodan_dir, "shodan_summary.json"), {}) or {}
    shodan_assets = _read_jsonl(os.path.join(shodan_dir, "shodan_assets.jsonl"))
    shodan_findings = _read_jsonl(os.path.join(shodan_dir, "shodan_findings.jsonl"))
    for sa in shodan_assets:
        ip = sa.get("ip", "")
        if ip:
            all_ips.add(ip)
            for h in sa.get("hostnames", []):
                ch = _clean_host(h)
                if ch:
                    ip_hostnames.setdefault(ip, set()).add(ch)
            if sa.get("cdn"):
                cdn_ips.add(ip)

    # Module 8D — MCP / AI surface probe (host → AI tag + posture findings).
    mcp_ai_dir = os.path.join(out_dir, "08_directory_discovery")
    ai_by_host = {}     # host -> {"surfaces":set,"flavors":set,"confidence":str,"tools":int}
    for rec in _read_jsonl(os.path.join(mcp_ai_dir, "mcp_ai_endpoints.jsonl")):
        surface = rec.get("ai_surface")
        if not surface:
            continue
        host = _clean_host(rec.get("host") or "")
        if not host:
            url = rec.get("url", "")
            if "://" in url:
                host = _clean_host(url.split("://")[1].split("/")[0].split(":")[0])
        if not host:
            continue
        ent = ai_by_host.setdefault(host, {"surfaces": set(), "flavors": set(),
                                           "confidence": "", "tools": 0})
        ent["surfaces"].add(surface)
        if rec.get("ai_flavor"):
            ent["flavors"].add(rec["ai_flavor"])
        conf = rec.get("ai_confidence") or "path-hint"
        if _AI_CONF_RANK.get(conf, 0) > _AI_CONF_RANK.get(ent["confidence"], 0):
            ent["confidence"] = conf
        ent["tools"] = max(ent["tools"], int(rec.get("tool_count") or 0))
    ai_findings = _read_jsonl(os.path.join(mcp_ai_dir, "mcp_ai_findings.jsonl"))
    if ai_by_host or ai_findings:
        _log(logf, "MCP/AI: %d host(s) with AI surfaces, %d finding(s)" % (
            len(ai_by_host), len(ai_findings)))

    # manifest + WAF detection.
    manifest = _read_json(os.path.join(out_dir, "manifest.json"), {}) or {}
    host_waf = {}
    waf_dir = os.path.join(out_dir, "05_waf_detection")
    if os.path.isdir(waf_dir):
        for fname in os.listdir(waf_dir):
            if fname.endswith(".json"):
                wdata = _read_json(os.path.join(waf_dir, fname), {}) or {}
                host = wdata.get("host") or fname.replace(".json", "")
                waf_name = wdata.get("waf", "")
                if waf_name:
                    host_waf[host] = waf_name

    for ip in ip_ports:
        all_ips.add(ip)
    for ip in ip_services:
        if _is_public_ip(ip):
            all_ips.add(ip)

    _log(logf, "loaded: %d ips, %d cdn, %d http, %d svc-ips, %d ptr, %d nuclei, "
         "%d port-ips, %d shodan, %d osint" % (
             len(all_ips), len(cdn_ips), len(http_hosts), len(ip_services),
             len(ip_ptr), len(nuclei_findings), len(ip_ports),
             len(shodan_assets), len(osint_findings)))

    return {
        "all_ips": all_ips, "cdn_ips": cdn_ips, "ip_annotations": ip_annotations,
        "ip_ptr": ip_ptr, "ip_hostnames": ip_hostnames,
        "http_hosts": http_hosts, "ip_services": ip_services,
        "nuclei_findings": nuclei_findings, "ip_ports": ip_ports,
        "osint_summary": osint_summary, "osint_findings": osint_findings,
        "shodan_summary": shodan_summary, "shodan_assets": shodan_assets,
        "shodan_findings": shodan_findings, "shodan_dir": shodan_dir,
        "manifest": manifest, "host_waf": host_waf,
        "ai_by_host": ai_by_host, "ai_findings": ai_findings,
    }


# ── External enrichment ───────────────────────────────────────────────────

def fetch_censys(ip, api_id, api_secret, timeout):
    cred = base64.b64encode(("%s:%s" % (api_id, api_secret)).encode()).decode()
    url = "https://search.censys.io/api/v2/hosts/%s" % ip
    data, err = _http_get_json(url, timeout, {"Authorization": "Basic %s" % cred})
    if err or not data:
        return None
    result = data.get("result", {})
    services = []
    for svc in (result.get("services") or []):
        services.append({
            "port": svc.get("port"),
            "service_name": svc.get("service_name", ""),
            "transport": svc.get("transport_protocol", "tcp"),
        })
    loc = result.get("location", {})
    coords = loc.get("coordinates", {})
    asys = result.get("autonomous_system", {})
    return {
        "services": services,
        "geo": {
            "country_code": loc.get("country_code", ""),
            "city": loc.get("city", ""),
            "lat": coords.get("latitude"),
            "lon": coords.get("longitude"),
        },
        "asn": "AS%s" % asys.get("asn", "") if asys.get("asn") else "",
        "asn_name": asys.get("name", ""),
    }


def fetch_greynoise(ip, api_key, timeout):
    url = "https://api.greynoise.io/v3/community/%s" % ip
    data, err = _http_get_json(url, timeout, {"key": api_key})
    if err or not data:
        return None
    return {
        "noise": data.get("noise", False),
        "riot": data.get("riot", False),
        "classification": data.get("classification", "unknown"),
        "name": data.get("name", ""),
        "last_seen": data.get("last_seen", ""),
    }


def fetch_ipinfo(ip, token, timeout):
    """ipinfo.io geo/org fallback. loc='lat,lon'; org='AS#### Name'."""
    url = "https://ipinfo.io/%s/json" % ip
    if token:
        url += "?token=%s" % token
    data, err = _http_get_json(url, timeout)
    if err or not data:
        return None
    lat = lon = None
    loc = data.get("loc", "")
    if isinstance(loc, str) and "," in loc:
        try:
            lat, lon = [float(x) for x in loc.split(",", 1)]
        except ValueError:
            lat = lon = None
    org = data.get("org", "") or ""
    asn = ""
    m = re.match(r"(AS\d+)\s+(.*)", org)
    if m:
        asn, org = m.group(1), m.group(2)
    return {
        "lat": lat, "lon": lon,
        "country_code": data.get("country", ""),
        "city": data.get("city", ""),
        "asn": asn, "org": org,
    }


def enrich_ip(ip, cfg, want_geo):
    """Censys + GreyNoise always (if keyed); ipinfo only when want_geo."""
    result = {}
    if cfg["censys_id"] and cfg["censys_secret"]:
        cdata = fetch_censys(ip, cfg["censys_id"], cfg["censys_secret"], cfg["timeout"])
        if cdata:
            result["censys"] = cdata
    if cfg["greynoise_key"]:
        gdata = fetch_greynoise(ip, cfg["greynoise_key"], cfg["timeout"])
        if gdata:
            result["greynoise"] = gdata
    if want_geo and cfg["ipinfo_token"] is not None:
        idata = fetch_ipinfo(ip, cfg["ipinfo_token"], cfg["timeout"])
        if idata:
            result["ipinfo"] = idata
    return result


# ── Consolidation ─────────────────────────────────────────────────────────

def _nuclei_cve(nf):
    info = nf.get("info", {})
    for r in _as_list(info.get("reference")):
        if isinstance(r, str) and r.upper().startswith("CVE-"):
            return r.upper()
    name = info.get("name", nf.get("template-id", ""))
    m = re.search(r"(CVE-\d{4}-\d{4,})", str(name), re.I)
    return m.group(1).upper() if m else ""


def consolidate(modules, mined_geo, enrichments, cfg, logf):
    all_ips = modules["all_ips"]
    cdn_ips = modules["cdn_ips"]

    # Index Shodan assets + findings by IP.
    shodan_idx = {sa.get("ip", ""): sa for sa in modules["shodan_assets"]}
    shodan_findings_idx = {}
    for sf in modules["shodan_findings"]:
        ip = sf.get("ip", "")
        if ip:
            shodan_findings_idx.setdefault(ip, []).append(sf)

    # Index MCP/AI posture/poisoning findings (Module 8D) by hostname.
    ai_findings_idx = {}
    for af in modules.get("ai_findings", []):
        h = _clean_host(af.get("host", ""))
        if h:
            ai_findings_idx.setdefault(h, []).append(af)

    # Index Nuclei findings by hostname AND ip.
    nuclei_by_key = {}
    for nf in modules["nuclei_findings"]:
        matched = nf.get("matched-at", nf.get("host", ""))
        if "://" in matched:
            matched = matched.split("://")[1].split("/")[0].split(":")[0]
        elif ":" in matched and not matched.startswith("["):
            head, _, tail = matched.rpartition(":")
            if tail.isdigit():
                matched = head
        if matched:
            nuclei_by_key.setdefault(matched, []).append(nf)
        nf_ip = nf.get("ip", "")
        if nf_ip and nf_ip != matched:
            nuclei_by_key.setdefault(nf_ip, []).append(nf)

    # Origin IPs only.
    origin_ips = sorted(
        ip for ip in all_ips
        if _is_public_ip(ip)
        and ip not in cdn_ips
        and not modules["ip_annotations"].get(ip, {}).get("cdn", False)
        and not _is_known_cdn_ip(ip)
    )
    _log(logf, "origin IPs: %d (of %d total, %d cdn-excluded)" % (
        len(origin_ips), len(all_ips), len(all_ips) - len(origin_ips)))

    assets, all_findings = [], []
    finding_dedup = set()
    geo_assets = []
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    cve_counts, service_counts, port_counts = {}, {}, {}
    provider_counts, country_counts = {}, {}
    geo_source_counts = {}

    for ip in origin_ips:
        hostnames = sorted(modules["ip_hostnames"].get(ip, set()))
        shodan = shodan_idx.get(ip, {})
        enrich = enrichments.get(ip, {})
        censys = enrich.get("censys", {})
        ipinfo = enrich.get("ipinfo", {})
        greynoise = enrich.get("greynoise", {})
        ann = modules["ip_annotations"].get(ip, {})

        # ── Ports — validated (nmap) vs reported (passive: shodan/censys) ──
        # nmap is an active probe against the live host, so those ports are
        # ground-truth. Shodan/Censys ports are third-party observations that
        # may be stale or mis-attributed; they are kept separately and do NOT
        # count as confirmed surface. "all_ports" is validated-only.
        arise_ports = set(p for p in modules["ip_ports"].get(ip, set()) if p)
        shodan_ports = set(shodan.get("observed_ports", []) + shodan.get("shodan_ports", []))
        censys_ports = set(s.get("port") for s in censys.get("services", []) if s.get("port"))
        reported_ports = sorted(p for p in (shodan_ports | censys_ports) - arise_ports if p)
        all_ports = sorted(arise_ports)            # validated ports only
        for p in all_ports:
            port_counts[p] = port_counts.get(p, 0) + 1

        # ── Services (nmap + shodan + censys), deduped ──
        services, seen_svc = [], set()
        for rec in modules["ip_services"].get(ip, []):
            port = rec.get("port")
            sname = rec.get("service") or rec.get("name") or ""
            key = (port, sname)
            if sname and key not in seen_svc:
                seen_svc.add(key)
                service_counts[sname] = service_counts.get(sname, 0) + 1
                services.append({"port": port, "service": sname,
                                 "product": rec.get("product", ""),
                                 "version": rec.get("version", "")})
        for sp in shodan.get("products", []):
            port = sp.get("port")
            sname = sp.get("module") or sp.get("product") or ""
            key = (port, sname)
            if sname and key not in seen_svc:
                seen_svc.add(key)
                service_counts[sname] = service_counts.get(sname, 0) + 1
                services.append({"port": port, "service": sname,
                                 "product": sp.get("product", ""),
                                 "version": sp.get("version", "")})
        for cs in censys.get("services", []):
            port = cs.get("port")
            sname = cs.get("service_name", "")
            key = (port, sname)
            if sname and key not in seen_svc:
                seen_svc.add(key)
                service_counts[sname] = service_counts.get(sname, 0) + 1
                services.append({"port": port, "service": sname, "product": "", "version": ""})

        # ── CVEs — validated (nuclei) vs reported (passive: shodan) ──
        # A nuclei hit is an active template match against the live target, so
        # its CVE is confirmed. Shodan CVEs are inferred from banner/version and
        # are frequently false positives; they are retained as "reported" only.
        validated_cves = set()
        for key in hostnames + [ip]:
            for nf in nuclei_by_key.get(key, []):
                cid = _nuclei_cve(nf)
                if cid:
                    validated_cves.add(cid)
        shodan_cves = set(v.upper() if isinstance(v, str) else str(v)
                          for v in shodan.get("cves", []))
        reported_cves = sorted(shodan_cves - validated_cves)
        cves = sorted(validated_cves)              # validated CVEs only
        for cve in cves:
            cve_counts[cve] = cve_counts.get(cve, 0) + 1

        # ── Provider / ASN / Org / Country ──
        provider = (shodan.get("provider", "") or ipinfo.get("org", "")
                    or _provider_from(shodan.get("org", "") or ipinfo.get("org", "")
                                      or " ".join(hostnames)))
        provider = _provider_from(provider) or provider
        asn = shodan.get("asn", "") or censys.get("asn", "") or ipinfo.get("asn", "")
        org = shodan.get("org", "") or censys.get("asn_name", "") or ipinfo.get("org", "")
        if provider:
            provider_counts[provider] = provider_counts.get(provider, 0) + 1

        # ── Geo (priority: mined → censys → ipinfo → shodan-raw → centroid) ──
        geo = mined_geo.get(ip)
        if not geo and censys.get("geo", {}).get("lat") is not None and censys["geo"].get("lon") is not None:
            geo = {"lat": censys["geo"]["lat"], "lon": censys["geo"]["lon"],
                   "country": censys["geo"].get("country_code", ""),
                   "city": censys["geo"].get("city", ""), "source": "censys"}
        if not geo and ipinfo.get("lat") is not None and ipinfo.get("lon") is not None:
            geo = {"lat": ipinfo["lat"], "lon": ipinfo["lon"],
                   "country": ipinfo.get("country_code", ""),
                   "city": ipinfo.get("city", ""), "source": "ipinfo"}
        if not geo:
            raw = _read_json(os.path.join(modules["shodan_dir"], "shodan_raw", "%s.json" % ip))
            if isinstance(raw, dict) and raw.get("latitude") and raw.get("longitude"):
                geo = {"lat": raw["latitude"], "lon": raw["longitude"],
                       "country": raw.get("country_code", ""),
                       "city": raw.get("city", ""), "source": "shodan"}

        # Country from any signal.
        country = (shodan.get("country", "") or (geo or {}).get("country", "")
                   or censys.get("geo", {}).get("country_code", "")
                   or ipinfo.get("country_code", ""))
        if not geo and country:
            geo = _country_centroid(country)
        if geo and not geo.get("country") and country:
            geo["country"] = country.upper()[:2]
        if geo:
            geo_source_counts[geo["source"]] = geo_source_counts.get(geo["source"], 0) + 1
        if country:
            cc = country.upper()[:2]
            country_counts[cc] = country_counts.get(cc, 0) + 1

        # ── Tags / WAF / GreyNoise ──
        tags = list(shodan.get("tags", []))
        waf = shodan.get("waf", "")
        if not waf:
            for h in hostnames:
                if modules["host_waf"].get(h):
                    waf = modules["host_waf"][h]
                    break
        gn_class = greynoise.get("classification", "")

        # ── AI / MCP surface tag (Module 8D) — fold host-level AI tags onto the
        #    origin asset, ADDITIVELY (never replaces shodan tags). An asset is
        #    an AI/MCP asset iff one of its hostnames exposed an AI/MCP surface. ──
        ai_surfaces = set()
        ai_confidence = ""
        ai_tools = 0
        for h in hostnames:
            ent = modules.get("ai_by_host", {}).get(h)
            if ent:
                ai_surfaces |= ent.get("surfaces", set())
                if _AI_CONF_RANK.get(ent.get("confidence"), 0) > _AI_CONF_RANK.get(ai_confidence, 0):
                    ai_confidence = ent.get("confidence") or ai_confidence
                ai_tools += int(ent.get("tools", 0) or 0)
            # Asset-level host-label tag (path-hint) — the host NAME alone marks
            # it AI/MCP even with no crawled AI URL (e.g. mcp-server.* / ai.*).
            hl = _ai_host_label(h)
            if hl:
                ai_surfaces.add(hl)
                if not ai_confidence:
                    ai_confidence = "path-hint"
        # Validated (nmap) AI default ports add a tag-only surface hint.
        for _p in all_ports:
            _hint = _AI_PORT_HINT.get(_p)
            if _hint:
                ai_surfaces.add(_hint[0])
                _ptag = "ai-port:" + _hint[1]
                if _ptag not in tags:
                    tags.append(_ptag)
        if ai_surfaces:
            for s in sorted(ai_surfaces):
                if s not in tags:
                    tags.append(s)
            if "ai-surface" not in tags:
                tags.append("ai-surface")

        # ── Findings for this IP (shodan + nuclei), deduped ──
        ip_findings = []
        for sf in shodan_findings_idx.get(ip, []):
            dk = (ip, sf.get("rule_id", ""), sf.get("port", 0))
            if dk not in finding_dedup:
                finding_dedup.add(dk)
                sev = (sf.get("severity") or "info").lower()
                if sev not in sev_counts:
                    sev = "info"
                sev_counts[sev] += 1
                ip_findings.append(sf)
        max_sev = shodan.get("max_severity", "info")
        for key in hostnames + [ip]:
            for nf in nuclei_by_key.get(key, []):
                info = nf.get("info", {})
                tid = nf.get("template-id", "")
                matched = nf.get("matched-at", "")
                dk = (ip, "nuclei-" + tid, matched)
                if dk in finding_dedup:
                    continue
                finding_dedup.add(dk)
                sev = (info.get("severity") or "info").lower()
                if sev not in sev_counts:
                    sev = "info"
                sev_counts[sev] += 1
                if SEV_RANK.get(sev, 0) > SEV_RANK.get(max_sev, 0):
                    max_sev = sev
                ip_findings.append({
                    "rule_id": "nuclei-" + tid, "title": info.get("name", tid),
                    "ip": ip, "port": 0, "severity": sev,
                    "hostnames": hostnames[:4], "evidence": matched,
                    "detected_at": nf.get("timestamp", _now_iso()),
                })
        # MCP/AI posture + poisoning findings (Module 8D), keyed by hostname.
        for h in hostnames:
            for af in ai_findings_idx.get(h, []):
                dk = (ip, af.get("title", ""), af.get("url", ""))
                if dk in finding_dedup:
                    continue
                finding_dedup.add(dk)
                sev = (af.get("severity") or "info").lower()
                if sev not in sev_counts:
                    sev = "info"
                sev_counts[sev] += 1
                if SEV_RANK.get(sev, 0) > SEV_RANK.get(max_sev, 0):
                    max_sev = sev
                ip_findings.append({
                    "rule_id": "mcp_ai-" + (af.get("mst") or af.get("owasp_llm") or "surface"),
                    "title": af.get("title", ""), "ip": ip, "port": 0,
                    "severity": sev, "hostnames": [h],
                    "evidence": af.get("evidence", ""), "detected_at": _now_iso(),
                })
        all_findings.extend(ip_findings)

        # ── Risk — driven by VALIDATED signal; reported-only data down-weighted ──
        # Confirmed CVEs (nuclei) and open ports (nmap) carry full weight.
        # Passive-only CVEs/ports contribute a small residual so they are not
        # ignored entirely, but never dominate the score the way unvalidated
        # third-party data did before.
        crit_mult = 1.5 if any(kw in h for h in hostnames
                               for kw in ("prod", "api", "auth", "admin", "pay", "db")) else 1.0
        risk = min(100, int((
            SEV_RANK.get(max_sev, 1) * 12
            + min(len(cves), 10) * 6                        # validated CVEs
            + min(len(reported_cves), 10) * 1.5            # reported-only CVEs
            + min(len(all_ports), 20) * 1.5               # validated ports
            + min(len(reported_ports), 20) * 0.4          # reported-only ports
            + (15 if any(t in tags for t in ("database", "eol-product", "eol-os")) else 0)
            + (10 if gn_class == "malicious" else 0)
        ) * crit_mult))

        if geo:
            geo_assets.append({
                "ip": ip, "lat": geo["lat"], "lon": geo["lon"],
                "country": geo.get("country", ""), "city": geo.get("city", ""),
                "risk": risk, "findings": len(ip_findings),
                "hostnames": hostnames[:3], "source": geo["source"],
            })

        assets.append({
            "ip": ip, "hostnames": hostnames[:12], "ports": all_ports,
            "ports_reported": reported_ports[:30],
            "services": services[:20], "cves": cves[:30],
            "cves_reported": reported_cves[:30], "tags": tags,
            # AI / MCP surface (Module 8D) — empty on non-AI assets.
            "ai_surfaces": sorted(ai_surfaces), "ai_confidence": ai_confidence,
            "ai_tool_count": ai_tools,
            "geo": geo, "country": (country or "").upper()[:2], "asn": asn, "org": org,
            "provider": provider or "", "waf": waf, "greynoise": gn_class,
            "risk_score": risk, "findings_count": len(ip_findings), "max_severity": max_sev,
            "validation": {
                "ports_validated": len(all_ports), "ports_reported": len(reported_ports),
                "cves_validated": len(cves), "cves_reported": len(reported_cves),
                "port_source": "nmap", "cve_source": "nuclei",
            },
        })

    # ── Top 10s ──
    top = lambda d: sorted(d.items(), key=lambda x: -x[1])[:10]
    top_cves = top(cve_counts)
    top_services = top(service_counts)
    top_ports = top(port_counts)
    top_providers = top(provider_counts)
    top_countries = top(country_counts)

    assets.sort(key=lambda a: (-a["risk_score"], -a["findings_count"]))
    critical_assets = assets[:10]

    total_findings = len(all_findings)
    global_risk = min(100, int(
        45 * sev_counts["critical"] + 22 * sev_counts["high"]
        + 8 * sev_counts["medium"] + 2 * sev_counts["low"] + 0.5 * sev_counts["info"]))
    if sev_counts["critical"] or global_risk >= 70:
        grade = "critical"
    elif sev_counts["high"] or global_risk >= 40:
        grade = "high"
    elif sev_counts["medium"] or global_risk >= 15:
        grade = "medium"
    else:
        grade = "low"

    all_findings.sort(key=lambda f: -SEV_RANK.get((f.get("severity") or "info").lower(), 0))

    _log(logf, "consolidated: %d assets, %d findings, %d cves, risk=%d (%s), "
         "geo=%d %s" % (len(assets), total_findings, len(cve_counts), global_risk,
                        grade, len(geo_assets), dict(geo_source_counts)))

    summary = {
        "domain": cfg.get("domain", ""), "generated_at": _now_iso(),
        "total_assets": len(origin_ips), "total_findings": total_findings,
        "total_cves": len(cve_counts), "total_ports": sum(len(a["ports"]) for a in assets),
        "geo_located": len(geo_assets), "by_severity": sev_counts,
        "risk_score": global_risk, "grade": grade,
        "geo_source_breakdown": geo_source_counts,
        "geo_assets": geo_assets[:1000],
        "critical_assets": [{
            "ip": a["ip"], "hostnames": a["hostnames"][:3], "risk_score": a["risk_score"],
            "findings_count": a["findings_count"], "ports": len(a["ports"]),
            "cves": len(a["cves"]), "max_severity": a["max_severity"],
            "provider": a["provider"], "country": a["country"], "waf": a["waf"],
            "greynoise": a["greynoise"], "city": (a["geo"] or {}).get("city", ""),
        } for a in critical_assets],
        "top_cves": [{"cve": c, "count": n} for c, n in top_cves],
        "top_services": [{"service": s, "count": n} for s, n in top_services],
        "top_ports": [{"port": p, "count": n} for p, n in top_ports],
        "top_providers": [{"provider": p, "count": n} for p, n in top_providers],
        "top_countries": [{"country": c, "count": n} for c, n in top_countries],
        "enrichment": {
            "censys": bool(cfg["censys_id"]),
            "greynoise": bool(cfg["greynoise_key"]),
            "ipinfo": cfg["ipinfo_token"] is not None,
            "shodan": modules["shodan_summary"].get("shodan_source", "none") != "local-only",
        },
    }
    return assets, all_findings, summary


# ── Attack-surface detection engine (Xpanse-style issues) ─────────────────
#
# Turns the consolidated observation data into named, categorized, remediable
# EXPOSURES — the operational product. Every issue is grounded in real
# evidence from the scan (a nuclei match, an open management port, a TLS
# defect); nothing is inferred without a concrete artifact.

import hashlib as _hashlib

# Severity weights for the attack-surface score.
_SEV_W = {"critical": 40, "high": 20, "medium": 8, "low": 2, "info": 0.5}

# Management / remote-access / database ports that are an exposure simply by
# being reachable from the internet on an origin IP.
PORT_EXPOSURES = {
    22:   ("Remote Access",     "medium", "SSH",
           "SSH is exposed to the internet, offering a direct credential-attack "
           "and brute-force surface on a shell-access protocol.",
           "Restrict SSH to a bastion/VPN or allow-listed CIDRs; enforce key-only auth and MFA."),
    23:   ("Remote Access",     "high",   "Telnet",
           "Telnet transmits credentials in cleartext and is trivially intercepted.",
           "Disable Telnet entirely; use SSH. Block port 23 at the edge."),
    3389: ("Remote Access",     "high",   "RDP",
           "Internet-exposed RDP is a top ransomware initial-access vector (BlueKeep, brute force).",
           "Place RDP behind a VPN/RD Gateway; never expose 3389 directly. Enforce NLA + MFA."),
    5900: ("Remote Access",     "high",   "VNC",
           "VNC often ships with weak/no authentication and grants full desktop control.",
           "Tunnel VNC over SSH/VPN; require strong auth; block 5900 at the edge."),
    3306: ("Exposed Database",  "high",   "MySQL",
           "A database port is reachable from the internet, exposing data to direct attack.",
           "Bind the database to private interfaces; front with a bastion; never expose to 0.0.0.0."),
    5432: ("Exposed Database",  "high",   "PostgreSQL",
           "A database port is reachable from the internet, exposing data to direct attack.",
           "Bind to private interfaces / security groups; require TLS and strong auth."),
    27017:("Exposed Database",  "critical","MongoDB",
           "Internet-exposed MongoDB has caused mass data breaches via unauthenticated access.",
           "Enable auth, bind to private networks, and block 27017 at the edge immediately."),
    6379: ("Exposed Database",  "critical","Redis",
           "Redis defaults to no auth; internet exposure allows data theft and RCE via config abuse.",
           "Require a password, enable protected-mode, bind privately, block 6379 at the edge."),
    9200: ("Exposed Database",  "high",   "Elasticsearch",
           "Exposed Elasticsearch frequently leaks full indices without authentication.",
           "Put behind auth/proxy, bind privately, block 9200 externally."),
    1433: ("Exposed Database",  "high",   "MSSQL",
           "A database port is reachable from the internet, exposing data to direct attack.",
           "Restrict to private networks; enforce TLS and strong auth."),
    2375: ("Exposed Service",   "critical","Docker API",
           "An unauthenticated Docker API grants root-equivalent control of the host.",
           "Never expose the Docker socket/API; require TLS client certs; block 2375."),
}

# nuclei template-id → (category, severity, impact, remediation). Curated so the
# severity reflects real exploitability, not nuclei's conservative default.
TID_RULES = {
    "graphiql-exposure": ("Exposed Dev Interface", "high",
        "A GraphQL IDE (GraphiQL) is publicly reachable, exposing the full API schema via "
        "introspection and enabling crafted queries against production data.",
        "Disable GraphiQL in production or restrict it to internal networks; turn off introspection."),
    "trace-axd-expose": ("Information Disclosure", "medium",
        "ASP.NET Trace.axd is exposed, leaking recent requests, headers, and sometimes session data.",
        "Set <trace enabled=\"false\"/> and deny access to Trace.axd in production."),
    "tomcat-stacktraces": ("Information Disclosure", "low",
        "Tomcat is returning stack traces, disclosing framework/version internals and code paths "
        "useful for targeting further attacks.",
        "Configure custom error pages; disable stack traces in production."),
    "expired-ssl": ("Encryption", "medium",
        "The TLS certificate has expired, breaking trust and conditioning users to bypass warnings.",
        "Renew and automate certificate rotation (ACME/Let's Encrypt or your CA)."),
    "weak-cipher-suites": ("Encryption", "medium",
        "Deprecated TLS (1.0/1.1) and weak CBC cipher suites are enabled, exposing sessions to "
        "downgrade and known cryptographic attacks.",
        "Disable TLS 1.0/1.1 and CBC ciphers; require TLS 1.2+ with modern AEAD suites."),
    "self-signed-ssl": ("Encryption", "low",
        "A self-signed certificate is in use, providing no third-party trust and enabling MITM.",
        "Replace with a CA-issued certificate."),
}

# Substring fallbacks when the exact template-id isn't curated.
_TID_PATTERNS = [
    (("graphql", "graphiql", "swagger", "actuator", "jenkins", "grafana",
      "kibana", "phpmyadmin", "adminer", "portainer", "gitlab", ".git", "env-file"),
     ("Exposed Dev Interface", "high",
      "A development/administrative interface is reachable from the internet.",
      "Restrict the interface to internal networks or require authentication.")),
    (("stacktrace", "trace", "debug", "disclosure", "exposure", "listing",
      "server-status", "phpinfo", "backup"),
     ("Information Disclosure", "medium",
      "Sensitive technical information is exposed publicly.",
      "Remove or restrict the exposed resource; disable verbose errors in production.")),
    (("ssl", "tls", "cipher", "cert", "hsts"),
     ("Encryption", "medium",
      "A TLS/encryption weakness was detected.",
      "Harden the TLS configuration; renew certificates; enforce modern protocols.")),
    (("default-login", "default-cred", "weak-cred", "login"),
     ("Weak Authentication", "high",
      "Default or weak credentials / an exposed login were detected.",
      "Change default credentials; enforce strong auth and MFA; restrict access.")),
    (("cve-", "cve_"),
     ("Known Vulnerability", "high",
      "A component matching a known CVE is exposed.",
      "Patch or upgrade the affected component; validate exploitability.")),
    (("coverage-gap", "hidden-service", "shodan-only"),
     ("Hidden Service", "low",
      "A third-party scanner (Shodan) observes a service/port that ARISE's active scan "
      "did not — a possible blind spot from firewalling, timing, or WAF interference.",
      "Re-scan the reported port to confirm, then inventory or close the service.")),
]


def _issue_id(*parts):
    return _hashlib.sha1("|".join(str(p) for p in parts).encode()).hexdigest()[:12]


def _host_from_evidence(evidence):
    """The affected host lives in the evidence (matched-at URL / host:port),
    not in the shared-IP hostname list. Extract it so titles are accurate."""
    if not evidence:
        return ""
    s = str(evidence).strip()
    if "://" in s:
        s = s.split("://", 1)[1]
    s = s.split("/", 1)[0]          # drop path
    s = s.split(":", 1)[0]          # drop port
    s = s.rstrip(".")
    return s if _HOST_RE.match(s.lower()) else ""


# Canonical category → base tags (OWASP-aligned where it applies).
CATEGORY_TAGS = {
    "Cross-Site Scripting": ["xss", "injection", "owasp-a03"],
    "SQL Injection": ["sqli", "injection", "owasp-a03"],
    "Local File Inclusion": ["lfi", "path-traversal", "owasp-a01"],
    "Exposed Dev Interface": ["exposed-interface", "api"],
    "Information Disclosure": ["info-disclosure", "owasp-a05"],
    "Encryption": ["tls", "encryption", "owasp-a02"],
    "Remote Access": ["remote-access", "exposure"],
    "Exposed Database": ["database", "exposure"],
    "Exposed Service": ["exposure"],
    "Known Vulnerability": ["cve", "known-exploit"],
    "Hidden Service": ["hidden-service", "external-intel", "coverage-gap"],
    "Weak Authentication": ["auth", "default-creds", "owasp-a07"],
    "Misconfiguration": ["misconfig", "owasp-a05"],
    "Other Exposure": ["exposure"],
}

# App-vulnerability rules (Cross-Site Scripting / SQL Injection / LFI).
VULN_RULES = {
    "xss": ("Cross-Site Scripting", "high", "xss-scan",
        "Reflected/stored XSS lets an attacker run script in victims' browsers — session "
        "theft, credential harvesting, and account takeover.",
        "Context-encode all output, adopt a strict CSP, and validate/sanitize input server-side."),
    "sqli": ("SQL Injection", "critical", "sqli-scan",
        "SQL injection allows reading or modifying the database directly — full data breach "
        "and, often, remote code execution.",
        "Use parameterized queries/prepared statements everywhere; apply least-privilege DB accounts."),
    "lfi": ("Local File Inclusion", "high", "lfi-scan",
        "Local File Inclusion / path traversal exposes server files (configs, secrets, source) "
        "and can escalate to remote code execution.",
        "Reject path traversal input, use allow-lists for file access, and run with least privilege."),
}


def _classify_finding(rule_id, sev_default):
    tid = rule_id[7:] if rule_id.startswith("nuclei-") else rule_id
    tid_l = tid.lower()
    if tid in TID_RULES:
        cat, sev, impact, rem = TID_RULES[tid]
        return cat, sev, impact, rem
    for keys, (cat, sev, impact, rem) in _TID_PATTERNS:
        if any(k in tid_l for k in keys):
            return cat, sev, impact, rem
    # Uncurated: keep as a generic exposure at the scanner's own severity.
    return ("Other Exposure", (sev_default or "info").lower(),
            "An exposure was detected by an active scanner.",
            "Review the evidence and remediate per your standards.")


def _tags_for(category, extra=None):
    tags = list(CATEGORY_TAGS.get(category, ["exposure"]))
    for t in (extra or []):
        t = str(t).lower().strip()
        if t and t not in tags:
            tags.append(t)
    return tags[:6]


# External cloud attack-surface rules → (category, severity, attack, impact, remediation, tags)
CLOUD_RULES = {
    "takeover": ("Subdomain Takeover", "critical", "T1584.001 Compromise Infrastructure: Domains",
        "A subdomain points (dangling DNS/CNAME) at a deprovisioned cloud resource. An attacker "
        "can claim that resource and serve content on your subdomain — phishing, cookie/OAuth theft, "
        "or malicious JS trusted as first-party.",
        "Remove the dangling DNS record, or re-claim the cloud resource before an attacker does.",
        ["cloud", "takeover", "dangling-dns"]),
    "public_storage": ("Public Cloud Storage", "high", "T1530 Data from Cloud Storage Object",
        "A cloud storage bucket is publicly readable — anyone on the internet can list/download its "
        "objects (source, backups, PII, secrets).",
        "Make the bucket private; block public access at the account level; audit what was exposed.",
        ["cloud", "storage", "data-exposure"]),
    "writable_storage": ("Writable Cloud Storage", "critical", "T1530 / Supply-Chain",
        "A cloud storage bucket accepts anonymous writes — an attacker can plant malware, deface "
        "content, or poison JS/assets served to your users (supply-chain).",
        "Remove anonymous write ACLs/policies immediately; enable account-level public-access block.",
        ["cloud", "storage", "writable"]),
    "unclaimed_bucket": ("Unclaimed Bucket Reference", "medium", "T1584.006 Compromise Infrastructure: Web Services",
        "Your app/DNS references a bucket name that does not exist. If the name is yours, an attacker "
        "can register it and serve/exfiltrate through the trusted reference.",
        "Confirm ownership: re-claim the name if it's yours, or remove the dangling reference.",
        ["cloud", "storage", "takeover-prone"]),
    "metadata": ("Cloud Metadata Exposure", "high", "T1552.005 Cloud Instance Metadata API",
        "A cloud instance metadata endpoint (169.254.169.254 / metadata.google.internal) is reachable "
        "— often via SSRF — allowing theft of IAM role credentials and pivot into the account.",
        "Enforce IMDSv2 (AWS) / require metadata headers; fix the SSRF; restrict egress to metadata IPs.",
        ["cloud", "imds", "ssrf", "credential-access"]),
    "debug": ("Exposed Debug Endpoint", "medium", "T1213 Data from Information Repositories",
        "An application debug/introspection endpoint is exposed, leaking configuration, environment, "
        "or internal state useful for further attack.",
        "Disable debug/introspection endpoints in production; require authentication.",
        ["cloud", "debug", "info-disclosure"]),
    "tfstate": ("Terraform State Exposure", "high", "T1552.001 Credentials in Files",
        "A Terraform state file is publicly reachable — it contains resource IDs, IPs, and frequently "
        "plaintext secrets and credentials.",
        "Remove public access; store state in a private, encrypted backend; rotate any exposed secrets.",
        ["cloud", "iac", "secrets"]),
    "origin_bypass": ("CDN Origin Bypass", "medium", "T1090 Proxy / WAF Bypass",
        "The origin IP behind the CDN/WAF is directly reachable — an attacker can hit the application "
        "directly, bypassing WAF rules, rate limiting, and DDoS protection.",
        "Restrict the origin to accept traffic only from the CDN/WAF IP ranges (origin ACL / security group).",
        ["cloud", "origin-exposure", "waf-bypass"]),
    "missing_waf": ("Missing WAF", "low", "",
        "An internet-facing host has no detectable WAF in front of it.",
        "Front the host with a WAF; enable managed rule sets.",
        ["cloud", "waf"]),
    "email_spoof": ("Email Spoofing Exposure", "medium", "T1566 Phishing",
        "Weak or missing email authentication (SPF/DKIM/DMARC) lets an attacker send mail that "
        "spoofs your domain — phishing your customers, partners, or staff as if it came from you.",
        "Publish SPF, enable DKIM, and set DMARC to p=quarantine or p=reject with rua reporting.",
        ["email", "spoofing", "phishing", "dmarc"]),
}

# CloudFront / CDN distribution-id pattern (e.g. d2kp246l9kuyos) — NOT a bucket.
_CF_DIST_RE = re.compile(r"^[a-z0-9]{13,14}$")


def derive_cloud_issues(out_dir, logf):
    """Read Module 17 cloud outputs → normalized cloud issues with provenance.

    Fixes the core defects: (1) CloudFront distribution IDs are recognized as
    CDN artifacts, never shown as buckets; (2) every issue records the host that
    references it; (3) one resource = one issue (no provider fan-out)."""
    cdir = os.path.join(out_dir, "17_cloud_exposure")
    if not os.path.isdir(cdir):
        return []

    # Build name → referencing host, and the set of CDN-distribution IDs, from
    # the asset map (which carries host-level provenance + evidence).
    ref_host = {}
    cdn_ids = set()
    asset_map = _read_jsonl(os.path.join(cdir, "cloud_asset_map.jsonl"))
    for e in asset_map:
        host = e.get("host", "")
        ev = e.get("evidence", "") or ""
        for tok in re.findall(r"[a-z0-9]{6,}", ev):
            ref_host.setdefault(tok, host)
        if e.get("category") == "cdn":
            for tok in re.findall(r"([a-z0-9]{13,14})\.cloudfront\.net", ev):
                cdn_ids.add(tok)

    out = []
    seen_storage = set()   # dedup storage findings across providers/sources
    seen_email_spoof = set()   # hosts already covered by Module 17's own email-auth finding

    def _is_cdn_artifact(name):
        # A known CloudFront dist id, or the single-label 13-14 char alnum
        # pattern CloudFront/CDN uses — never a real org-named bucket.
        return bool(name) and (name in cdn_ids or _CF_DIST_RE.match(name))

    def emit(rule_key, affected, evidence, ip="", extra_tags=None,
             referenced_by="", sev_override=""):
        cat, sev, attack, impact, rem, tags = CLOUD_RULES[rule_key]
        out.append(dict(
            cat=cat, sev=sev_override or sev,
            title="%s — %s" % (cat, affected), affected=affected, port=0,
            evidence=evidence[:220], impact=impact, rem=rem,
            confidence="confirmed", source="cloud-scan",
            tags=_tags_for(cat, tags + (extra_tags or [])),
            ip=ip, attack=attack, referenced_by=referenced_by,
        ))

    # 1) Subdomain takeover (dangling cloud) from the asset map.
    for e in asset_map:
        risk = (e.get("risk") or "").lower()
        if "takeover" in risk and e.get("severity") in ("critical", "high"):
            host = e.get("host", "")
            emit("takeover", host,
                 "%s — %s" % (e.get("service", "cloud resource"), e.get("risk", "")),
                 referenced_by=host)

    # 2) cloud_findings.jsonl (origin bypass, missing WAF, public storage, …).
    cat_map = {
        "cdn_origin_bypass": "origin_bypass", "missing_waf": "missing_waf",
        "public_cloud_storage": "public_storage", "writable_cloud_storage": "writable_storage",
        "cloud_metadata_exposure": "metadata", "terraform_state_exposure": "tfstate",
        "debug_endpoint": "debug", "missing_email_auth": "email_spoof",
    }
    for f in _read_jsonl(os.path.join(cdir, "cloud_findings.jsonl")):
        cc = f.get("cloud_category") or f.get("category") or ""
        rk = cat_map.get(cc)
        if not rk:
            continue
        host = f.get("host", "")
        if rk in ("public_storage", "writable_storage"):
            if _is_cdn_artifact(host) or host in seen_storage:
                continue    # CloudFront dist id, not a bucket; or already seen
            seen_storage.add(host)
        if rk == "email_spoof":
            seen_email_spoof.add(host)
        # Module 17 (easm-pipeline.sh) already computed this finding's real
        # severity — a weighted score for most categories, or per-bucket
        # CONTENT grading for storage (an images-only bucket scores low, a DB
        # dump scores critical; see cloud_storage_enum.py). Passing it through
        # here (emit() falls back to the CLOUD_RULES static default only when
        # this is empty) keeps the Cloud tab's Issue Queue and the Vulns tab
        # showing the SAME severity for the SAME underlying cloud_findings.jsonl
        # entry, instead of two independently-labeled numbers for one gap.
        emit(rk, host, f.get("evidence", "") or f.get("exposure_note", ""),
             referenced_by=host, sev_override=f.get("severity", ""))

    # 3) Buckets — suppress CloudFront-dist noise; keep real storage exposure.
    for b in _read_jsonl(os.path.join(cdir, "cloud_buckets.jsonl")):
        name = b.get("name", "")
        if not name or name in seen_storage or _is_cdn_artifact(name):
            continue
        seen_storage.add(name)
        access = b.get("access", "")
        rb = ref_host.get(name, "")
        if b.get("writable"):
            emit("writable_storage", name, b.get("evidence", ""), referenced_by=rb,
                 extra_tags=[b.get("provider", "")])
        elif access == "public" or b.get("policy_public") or b.get("acl_public_grants"):
            emit("public_storage", name, b.get("evidence", ""), referenced_by=rb,
                 extra_tags=[b.get("provider", "")])
        elif access == "unclaimed":
            emit("unclaimed_bucket", name, b.get("evidence", ""), referenced_by=rb,
                 extra_tags=[b.get("provider", "")])

    # 4) cloud_nuclei.jsonl (metadata, debug, terraform templates).
    for nf in _read_jsonl(os.path.join(cdir, "cloud_nuclei.jsonl")):
        tid = (nf.get("template-id") or "").lower()
        matched = nf.get("matched-at", nf.get("host", ""))
        host = _host_from_evidence(matched) or matched
        # evidence/nuclei_fp_filter.py already re-checked this record and
        # demoted info.severity when its only textual evidence was the
        # probe's own URL/path echoed back (reflected-input false positive —
        # the academy.payu.in cloud-metadata-exposure post-mortem). Without
        # this, a finding (2) correctly emits at "info" from the already-
        # demoted cloud_findings.jsonl would get a SECOND, undemoted "high"
        # duplicate from this raw-nuclei pass, re-asserting the false
        # positive right back into the issue queue.
        fp_check = nf.get("arise_fp_check") or {}
        reflected = bool(fp_check.get("reflected_input_fp"))
        fp_sev = "info" if reflected else ""
        fp_evidence = fp_check.get("reason", "") if reflected else ""
        if "metadata" in tid:
            emit("metadata", host, fp_evidence or matched, referenced_by=host,
                 sev_override=fp_sev)
        elif "terraform" in tid or "tfstate" in tid:
            emit("tfstate", host, fp_evidence or matched, referenced_by=host,
                 sev_override=fp_sev)
        elif "debug" in tid or "introspection" in tid:
            emit("debug", host, fp_evidence or matched, referenced_by=host,
                 sev_override=fp_sev)

    # 5) Email authentication (SPF/DKIM/DMARC) → domain-spoofing exposure.
    # Module 17 already computes this gap and writes it as `missing_email_auth`
    # into cloud_findings.jsonl, picked up by rule (2) above via cat_map. Only
    # fall back to deriving it directly from email_auth.json when that didn't
    # happen (older scan snapshots) — otherwise the same gap would surface
    # twice under two different labels ("Missing Email Auth" vs "Email
    # Spoofing Exposure").
    ea = _read_json(os.path.join(cdir, "email_auth.json"), {}) or {}
    if ea and not seen_email_spoof:
        summ = _read_json(os.path.join(cdir, "cloud_storage_summary.json"), {}) or {}
        domain = summ.get("target") or os.path.basename(out_dir).split("-")[0] or "domain"
        gaps = []
        if not ea.get("spf_present"):
            gaps.append("no SPF")
        if not ea.get("dkim_present"):
            gaps.append("no DKIM")
        dmarc_pol = (ea.get("dmarc_policy") or "").lower()
        if not ea.get("dmarc_present"):
            gaps.append("no DMARC")
        elif dmarc_pol in ("", "none"):
            gaps.append("DMARC p=none (monitor-only, not enforced)")
        if gaps:
            # Missing DMARC/SPF entirely is worse than a weak-but-present policy.
            sev = "high" if ("no DMARC" in gaps or "no SPF" in gaps) else "medium"
            emit("email_spoof", domain,
                 "Email auth gaps for %s: %s" % (domain, "; ".join(gaps)),
                 referenced_by=domain, sev_override=sev)

    _log(logf, "cloud issues: %d (cdn-artifacts suppressed: %d)" % (len(out), len(cdn_ids)))
    return out


def derive_issues(assets, findings, modules, out_dir, logf):
    """Build the unified security-issue set: attack-surface exposures AND app
    vulnerabilities (XSS/SQLi/LFI/nuclei), categorized and tagged."""
    by_ip = {a["ip"]: a for a in assets}

    def ctx(ip):
        a = by_ip.get(ip, {})
        host = ""
        for h in a.get("hostnames", []):
            if "amazonaws" not in h and "compute" not in h:
                host = h
                break
        host = host or (a.get("hostnames") or [""])[0]
        return {
            "asset_ip": ip, "asset_host": host,
            "provider": a.get("provider", ""), "asn": a.get("asn", ""),
            "country": a.get("country", ""), "city": (a.get("geo") or {}).get("city", ""),
        }

    issues = []
    by_key = {}     # dedup key → issue (collapses the same issue across IPs)

    def add(cat, sev, title, affected, port, evidence, impact, rem,
            confidence, source, tags, ip="", attack="", referenced_by=""):
        key = _issue_id(cat, source, affected, port, evidence[:40])
        if key in by_key:
            iss = by_key[key]
            if ip and ip not in iss["_ips"]:
                iss["_ips"].add(ip)
                iss["affected_assets"] = len(iss["_ips"])
            return
        c = ctx(ip)
        # Blast-radius bump: a crown-jewel host (prod/api/auth/pay/admin/db)
        # raises severity one notch — impact, not just the raw finding.
        crown = any(kw in (affected or "").lower()
                    for kw in ("prod", "api", "auth", "admin", "pay", "login", "db", "vault"))
        if crown and sev in ("low", "medium"):
            sev = {"low": "medium", "medium": "high"}[sev]
        iss = {
            "id": key, "title": title, "category": cat, "severity": sev,
            "affected_host": affected, "port": port, "evidence": evidence,
            "impact": impact, "remediation": rem, "confidence": confidence,
            "source": source, "tags": tags, "attack": attack,
            "referenced_by": referenced_by, "affected_assets": 1,
            "_ips": {ip} if ip else set(), **c,
        }
        iss["asset_host"] = affected
        by_key[key] = iss
        issues.append(iss)

    # 1a) ALL nuclei findings (every host, not just origin) → typed issues.
    for nf in modules.get("nuclei_findings", []):
        tid = nf.get("template-id", "")
        info = nf.get("info", {}) or {}
        matched = nf.get("matched-at", nf.get("host", ""))
        cat, sev, impact, rem = _classify_finding("nuclei-" + tid, info.get("severity"))
        affected = _host_from_evidence(matched) or matched or nf.get("host", "")
        port = 0
        try:
            port = int(nf.get("port")) if nf.get("port") else 0
        except (TypeError, ValueError):
            port = 0
        base = info.get("name") or tid
        add(cat, sev, "%s — %s" % (base, affected), affected, port, matched,
            impact, rem, "confirmed", "active-scan",
            _tags_for(cat, info.get("tags")), ip=nf.get("ip", ""))

    # 1b) Shodan-correlation findings (non-nuclei) → typed issues.
    for f in findings:
        rule_id = f.get("rule_id", "")
        if rule_id.startswith("nuclei-"):
            continue    # nuclei already handled above from the full set
        ip = f.get("ip", "")
        cat, sev, impact, rem = _classify_finding(rule_id, f.get("severity"))
        evidence = f.get("evidence") or f.get("matched_at") or ""
        c = ctx(ip)
        affected = _host_from_evidence(evidence) or c["asset_host"] or ip
        base = f.get("title") or rule_id
        add(cat, sev, "%s — %s" % (base, affected), affected, f.get("port", 0),
            evidence, impact, rem, "reported", "external-intel",
            _tags_for(cat), ip=ip)

    # 1c) App vulnerabilities: XSS / SQLi / LFI result files.
    for line in _read_lines(os.path.join(out_dir, "13_xss_testing", "xss_results.txt")):
        url = ""
        for tok in line.split():
            if tok.startswith("http"):
                url = tok
                break
        url = url or line
        host = _host_from_evidence(url) or url
        cat, sev, src, impact, rem = VULN_RULES["xss"]
        add(cat, sev, "Cross-Site Scripting — %s" % host, host, 0, url[:200],
            impact, rem, "confirmed", src, _tags_for(cat))
    for rec in _read_jsonl(os.path.join(out_dir, "15_sqli_testing", "sqli_results.jsonl")):
        url = rec.get("url") or rec.get("target") or ""
        host = _host_from_evidence(url) or rec.get("host") or url
        param = rec.get("parameter", "")
        cat, sev, src, impact, rem = VULN_RULES["sqli"]
        if (rec.get("confidence", "") or "").lower() in ("low", "medium"):
            sev = "high"
        ev = ("%s (param: %s)" % (url, param)) if param else url
        add(cat, sev, "SQL Injection — %s" % host, host, 0, ev[:200],
            impact, rem, "confirmed", src, _tags_for(cat, [rec.get("type", "")]))
    lfi = _read_json(os.path.join(out_dir, "11_param_fuzzing", "lfi_results.json"), [])
    for rec in (lfi if isinstance(lfi, list) else []):
        url = rec.get("url", "")
        host = _host_from_evidence(url) or url
        cat, sev, src, impact, rem = VULN_RULES["lfi"]
        add(cat, sev, "Local File Inclusion — %s" % host, host, 0, url[:200],
            impact, rem, "confirmed", src, _tags_for(cat))

    # 1d) Advanced attack modules (Phase 6) — JWT / GraphQL / cache-poison /
    #     prototype-pollution / race / websocket / subdomain-brute. Each writes
    #     24_advanced_attacks/*_findings.jsonl in a common shape; fold them into
    #     the unified issue set so they surface in the Attack Surface console.
    _ADV_CAT = {
        "jwt_attack": "Authentication / JWT",
        "graphql_scanner": "GraphQL Exposure",
        "cache_poison": "Web Cache Poisoning",
        "prototype_pollution": "Prototype Pollution",
        "race_condition": "Race Condition",
        "websocket_scanner": "WebSocket (CSWSH)",
        "subdomain_bruteforce": "Subdomain Discovery",
        # unified offensive_verify.py module ids
        "ssti": "Injection / SSTI",
        "crlf": "Injection / CRLF",
        "open_redirect": "Open Redirect",
        "ssrf": "SSRF",
        "exposure": "Sensitive Exposure",
        # R5/R6 evidence-driven modules (har_identity_protocol layer)
        "wss": "WebSocket Security",
        "auth_oracle": "Authorization Violation",
    }
    adv_dir = os.path.join(out_dir, "24_advanced_attacks")
    if os.path.isdir(adv_dir):
        for fn in sorted(os.listdir(adv_dir)):
            if not fn.endswith("_findings.jsonl"):
                continue
            for rec in _read_jsonl(os.path.join(adv_dir, fn)):
                mod = rec.get("module") or fn[: -len("_findings.jsonl")]
                # the unified engine emits a precise `category`; prefer it.
                cat = rec.get("category") or _ADV_CAT.get(mod, "Advanced Attack")
                sev = (rec.get("severity") or "info").lower()
                if sev not in SEV_RANK:
                    sev = "info"
                target = rec.get("url") or rec.get("host") or rec.get("token") or ""
                host = _host_from_evidence(target) or target
                title = rec.get("title") or cat
                evidence = rec.get("evidence") or ""
                impact = rec.get("impact") or evidence
                rem = rec.get("remediation") or ""
                conf = rec.get("confidence") or "reported"
                add(cat, sev, "%s — %s" % (title, host) if host else title,
                    host, 0, evidence[:300], impact, rem, conf,
                    "advanced:" + mod, _tags_for(cat, [mod]))

    # subdomain_bruteforce.py moved to Module 2 (subdomain_enum) so its
    # discoveries flow through the whole pipeline. Its findings JSONL now
    # lives at 02_subdomain_enum/subdomain_brute_findings.jsonl — pick it
    # up from there too, using the same category/schema mapping as before.
    sd_brute_file = os.path.join(
        out_dir, "02_subdomain_enum", "subdomain_brute_findings.jsonl"
    )
    if os.path.isfile(sd_brute_file):
        for rec in _read_jsonl(sd_brute_file):
            mod = rec.get("module") or "subdomain_bruteforce"
            cat = _ADV_CAT.get(mod, "Subdomain Discovery")
            sev = (rec.get("severity") or "info").lower()
            if sev not in SEV_RANK:
                sev = "info"
            target = rec.get("url") or rec.get("host") or ""
            host = _host_from_evidence(target) or target
            title = rec.get("title") or cat
            evidence = rec.get("evidence") or ""
            impact = rec.get("impact") or evidence
            rem = rec.get("remediation") or ""
            conf = rec.get("confidence") or "confirmed"
            add(cat, sev, "%s — %s" % (title, host) if host else title,
                host, 0, evidence[:300], impact, rem, conf,
                "advanced:" + mod, _tags_for(cat, [mod]))

    # 1e) Response Intelligence (Module 26) — NLP passive response analysis:
    #     PII leaks, secrets, info disclosure, unauth data, anomalies.
    _RI_CAT = {
        "pii": "PII Exposure",
        "secret": "Secret / Credential Exposure",
        "disclosure": "Information Disclosure",
        "unauth_data": "Unauthorized Data Access",
        "anomaly": "Response Anomaly",
    }
    ri_dir = os.path.join(out_dir, "26_response_intel")
    ri_findings_file = os.path.join(ri_dir, "response_findings_deduped.jsonl")
    if os.path.isfile(ri_findings_file):
        for rec in _read_jsonl(ri_findings_file):
            cat = _RI_CAT.get(rec.get("category", ""), "Response Intelligence")
            sev = (rec.get("severity") or "info").lower()
            if sev not in SEV_RANK:
                sev = "info"
            host = rec.get("host") or ""
            url = rec.get("url") or ""
            title = rec.get("type", "unknown")
            evidence = rec.get("evidence") or ""
            conf = rec.get("confidence") or "reported"
            cwe = rec.get("cwe") or ""
            capec = rec.get("capec") or ""
            rem_text = ""
            if "pii" in cat.lower():
                rem_text = "Remove PII from API responses; implement field-level access control."
            elif "secret" in cat.lower():
                rem_text = "Rotate exposed credentials; remove from response bodies; use secret management."
            elif "disclosure" in cat.lower():
                rem_text = "Suppress error details in production; add security headers."
            add(cat, sev, "%s — %s" % (title, host) if host else title,
                host, 0, evidence[:300],
                evidence[:200], rem_text, conf,
                "response_intel:" + rec.get("type", ""), [cwe, capec])

    # 2) Open management/DB/remote ports → exposure issues.
    for a in assets:
        ip = a["ip"]
        c = ctx(ip)
        for p in a.get("ports", []):
            if p not in PORT_EXPOSURES:
                continue
            cat, sev, svc, impact, rem = PORT_EXPOSURES[p]
            title_host = c["asset_host"] or ip
            add(cat, sev,
                "%s reachable from internet (port %d) — %s" % (svc, p, title_host),
                title_host, p, "%s:%d open to 0.0.0.0/0" % (ip, p),
                impact, rem, "confirmed", "port-scan",
                _tags_for(cat, [svc.lower(), "port-" + str(p)]), ip=ip)

    # 2b) Shodan-reported CVEs (version-inferred) → Known Vulnerability issues.
    #     These show as CVE chips already, but weren't listed as issues — so the
    #     Attack Surface under-reported vs. the Shodan tab. Marked "reported"
    #     (external intel, unconfirmed) at low severity so they don't drown the
    #     confirmed findings, but are fully listed and filterable.
    origin_ips = {a["ip"] for a in assets}
    cve_impact = ("Shodan reports this host runs software matching a known CVE "
                  "(inferred from product/version banners, not actively confirmed).")
    cve_rem = ("Verify the affected component and version, confirm exploitability, "
               "then patch or upgrade. Prioritize CVEs on KEV / with public exploits.")
    for sa in modules.get("shodan_assets", []):
        ip = sa.get("ip", "")
        if ip not in origin_ips:
            continue
        host = ctx(ip)["asset_host"] or ip
        for cve in list(dict.fromkeys(sa.get("cves", [])))[:60]:   # dedup, cap/host
            cve = cve.upper() if isinstance(cve, str) else str(cve)
            if not cve.startswith("CVE-"):
                continue
            add("Known Vulnerability", "low", "%s — %s" % (cve, host), host, 0,
                "Shodan: %s reported on %s" % (cve, ip), cve_impact, cve_rem,
                "reported", "external-intel",
                _tags_for("Known Vulnerability", [cve.lower(), "shodan", "unconfirmed"]),
                ip=ip, attack="T1190 Exploit Public-Facing Application",
                referenced_by=host)

    # 3) External cloud attack surface (Module 17) → correlated cloud issues.
    for ci in derive_cloud_issues(out_dir, logf):
        add(ci["cat"], ci["sev"], ci["title"], ci["affected"], ci["port"],
            ci["evidence"], ci["impact"], ci["rem"], ci["confidence"],
            ci["source"], ci["tags"], ip=ci["ip"],
            attack=ci["attack"], referenced_by=ci["referenced_by"])

    # Drop the internal IP-set before serialization.
    for iss in issues:
        iss.pop("_ips", None)

    return issues, rollup_issues(issues, logf)


# ── CVE validation (Tier 1 KEV/EPSS/CVSS · Tier 2 corroboration · Tier 3 active) ──

_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_EPSS_URL = "https://api.first.org/data/v1/epss?cve=%s"
_NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=%s"
_KEV_CACHE = os.path.join(_BASE, ".arise_kev_cache.json")


def _load_kev(timeout, logf):
    """CISA Known-Exploited-Vulnerabilities set (cached 24h)."""
    try:
        if os.path.isfile(_KEV_CACHE) and time.time() - os.path.getmtime(_KEV_CACHE) < 86400:
            cached = _read_json(_KEV_CACHE, {})
            if cached.get("cves"):
                return set(c.upper() for c in cached["cves"])
        data, err = _http_get_json(_KEV_URL, timeout)
        if data and data.get("vulnerabilities"):
            cves = [v["cveID"].upper() for v in data["vulnerabilities"] if v.get("cveID")]
            try:
                with open(_KEV_CACHE, "w") as f:
                    json.dump({"cves": cves, "ts": _now_iso()}, f)
            except Exception:
                pass
            return set(cves)
    except Exception as e:
        _log(logf, "KEV load failed: %s" % e)
    return set()


def _load_epss(cves, timeout, logf):
    """EPSS exploitation-probability per CVE (batched)."""
    out = {}
    cves = list(cves)
    for i in range(0, len(cves), 80):
        batch = cves[i:i + 80]
        data, err = _http_get_json(_EPSS_URL % ",".join(batch), timeout)
        if data and data.get("data"):
            for x in data["data"]:
                try:
                    out[x["cve"].upper()] = float(x["epss"])
                except (KeyError, ValueError, TypeError):
                    pass
    return out


def _nvd_cvss(cve, timeout, key):
    """NVD base CVSS score (best-effort; KEV CVEs only to respect rate limits)."""
    data, err = _http_get_json(_NVD_URL % cve, timeout, {"apiKey": key} if key else None)
    if not data:
        return None
    try:
        metrics = data["vulnerabilities"][0]["cve"]["metrics"]
        for k in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(k):
                return metrics[k][0]["cvssData"]["baseScore"]
    except (KeyError, IndexError, TypeError):
        pass
    return None


def _nuclei_bin():
    return (shutil.which("nuclei")
            or (os.path.expanduser("~/go/bin/nuclei")
                if os.path.isfile(os.path.expanduser("~/go/bin/nuclei")) else ""))


def _active_validate(host, cve, timeout, logf):
    """Validate a CVE by running its nuclei template against the live host.
    Returns one of:
      'validated'      — the nuclei template MATCHED the live host (confirmed)
      'not_confirmed'  — a template exists and ran, but did not match
      'not_available'  — nuclei has NO template for this CVE id (can't validate)
      None             — could not run (nuclei missing / timeout / error)
    """
    nuc = _nuclei_bin()
    if not nuc:
        return None
    url = host if host.startswith("http") else "https://" + host
    try:
        # No -silent: we need the "Templates loaded for current scan: N" line
        # (nuclei → stderr) to tell "no template exists" from "ran, no match".
        r = subprocess.run(
            [nuc, "-u", url, "-id", cve.lower(), "-jsonl", "-nc",
             "-timeout", "10", "-retries", "1", "-no-interactsh", "-duc"],
            capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return None
    except Exception as e:
        _log(logf, "active validate %s %s failed: %s" % (host, cve, e))
        return None
    if r.stdout.strip():
        return "validated"
    m = re.search(r"[Tt]emplates loaded for current scan:\s*(\d+)", r.stderr or "")
    if m is not None and int(m.group(1)) == 0:
        return "not_available"          # nuclei ships no template for this CVE
    if re.search(r"[Nn]o templates provided|could not find any templates", r.stderr or ""):
        return "not_available"
    return "not_confirmed"              # template exists, ran, no match


def _cve_of(issue):
    m = re.match(r"(CVE-\d{4}-\d{4,})", issue.get("title", ""), re.I)
    return m.group(1).upper() if m else ""


def validate_cve_issues(issues, modules, cfg, logf):
    """Validate Shodan-reported CVEs OVER NUCLEI ONLY. Each CVE ends in exactly
    one of three states: 'validated' (nuclei template matched the live host —
    confirmed, persists), 'not_available' (nuclei ships no template for it, so it
    can't be validated), or 'required' (a template exists but did not match, or the
    active budget was reached — needs validation). KEV/EPSS/CVSS still set severity;
    version-corroboration is kept only as context, never as a validation verdict."""
    cve_issues = [i for i in issues
                  if i.get("category") == "Known Vulnerability"
                  and i.get("source") == "external-intel"]
    if not cve_issues:
        return
    all_cves = set(filter(None, (_cve_of(i) for i in cve_issues)))

    kev, epss = set(), {}
    if not cfg["no_net"]:
        kev = _load_kev(cfg["timeout"], logf)
        epss = _load_epss(all_cves, cfg["timeout"], logf)
    _log(logf, "CVE validation: %d cves | KEV catalog=%d | EPSS scored=%d" % (
        len(all_cves), len(kev), len(epss)))

    have_nuclei = bool(_nuclei_bin())
    active_on = (not cfg["no_net"]
                 and os.environ.get("IIL_ACTIVE_VALIDATE", "true").lower() != "false"
                 and have_nuclei)
    active_deadline = time.time() + float(os.environ.get("IIL_CVE_ACTIVE_BUDGET", "240"))
    active_cap = int(os.environ.get("IIL_CVE_ACTIVE_MAX", "30"))
    active_done = 0
    nvd_key = _resolve_key("NVD_API_KEY")

    # KEV/EPSS decide severity + priority (validation is nuclei-only). Spend the
    # active budget on the highest-risk CVEs first, so the important ones get proven.
    for i in cve_issues:
        cve = _cve_of(i)
        i["kev"] = bool(cve and cve in kev)
        i["epss"] = round(epss.get(cve, 0.0), 4) if cve else 0.0
    cve_issues.sort(key=lambda x: (x.get("kev", False), x.get("epss", 0.0)), reverse=True)

    counts = {"validated": 0, "not_available": 0, "required": 0}
    for i in cve_issues:
        cve = _cve_of(i)
        if not cve:
            continue
        is_kev, ev = i["kev"], i["epss"]

        # Severity from real-world exploitation risk (NOT a validation verdict).
        sev = "critical" if is_kev else ("high" if ev >= 0.5 else ("medium" if ev >= 0.1 else "low"))
        ip = i.get("asset_ip", "")
        prod = next((s.get("product") for s in modules.get("ip_services", {}).get(ip, [])
                     if s.get("product")), "")
        i["corroborated"] = bool(prod)   # context only, never a validation state
        if is_kev and not cfg["no_net"]:
            cv = _nvd_cvss(cve, cfg["timeout"], nvd_key)
            if cv is not None:
                i["cvss"] = cv

        # ── VALIDATION — nuclei only, three states ───────────────────────────
        status = None
        if active_on and active_done < active_cap and time.time() < active_deadline:
            status = _active_validate(i.get("affected_host") or ip, cve, 25, logf)
            active_done += 1

        if status == "validated":
            i["validated"] = True
            i["validation_status"] = "validated"
            i["confidence"] = "confirmed"
            i["validation"] = "Validated — nuclei template matched the live host"
        elif status == "not_available":
            i["validated"] = False
            i["validation_status"] = "not_available"
            i["confidence"] = "reported"
            i["validation"] = "Validation not available — no nuclei template exists for this CVE"
        elif not have_nuclei:
            i["validated"] = False
            i["validation_status"] = "not_available"
            i["confidence"] = "reported"
            i["validation"] = "Validation not available — nuclei is not installed"
        else:
            # 'not_confirmed' (template ran, no match) OR budget reached / couldn't run
            i["validated"] = False
            i["validation_status"] = "required"
            i["confidence"] = "reported"
            i["validation"] = ("Not validated — nuclei ran, no match (validation required; likely patched)"
                               if status == "not_confirmed"
                               else "Not validated — validation required")
        counts[i["validation_status"]] = counts.get(i["validation_status"], 0) + 1

        i["severity"] = sev
        tags = i.get("tags") or []
        for t in [("kev" if is_kev else None), ("high-epss" if ev >= 0.1 else None),
                  ("validated" if i["validated"] else None),
                  ("validation-required" if i["validation_status"] == "required" else None),
                  ("no-template" if i["validation_status"] == "not_available" else None),
                  ("corroborated" if prod else None)]:
            if t and t not in tags:
                tags.append(t)
        i["tags"] = tags[:8]

    _log(logf, "CVE validation (nuclei-only): %d actively checked | validated=%d "
         "not_available=%d required=%d" % (active_done, counts["validated"],
                                           counts["not_available"], counts["required"]))


def rollup_issues(issues, logf=None):
    """Sort issues and compute posture stats. Re-run after CVE validation
    changes severities."""
    sev_rank = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    conf_rank = {"confirmed": 2, "corroborated": 1, "reported": 0}
    issues.sort(key=lambda i: (-sev_rank.get(i["severity"], 0),
                               -conf_rank.get(i.get("confidence"), 0),
                               -i.get("affected_assets", 1)))

    # Confidence weighting: a validated (confirmed) issue counts in full; an
    # unconfirmed third-party "reported" issue contributes only a fraction, so
    # passive/unvalidated content can no longer inflate the posture score.
    conf_weight = {"confirmed": 1.0, "corroborated": 0.6, "reported": 0.3}
    by_sev = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    by_cat, by_owner = {}, {}
    score_raw = 0.0
    for i in issues:
        by_sev[i["severity"]] = by_sev.get(i["severity"], 0) + 1
        by_cat[i["category"]] = by_cat.get(i["category"], 0) + 1
        owner = i.get("provider") or "unknown"
        by_owner[owner] = by_owner.get(owner, 0) + 1
        score_raw += _SEV_W.get(i["severity"], 0) * conf_weight.get(i.get("confidence"), 0.3)
    score = min(100, int(score_raw))
    if by_sev["critical"]:
        posture = "critical"
    elif by_sev["high"] or score >= 40:
        posture = "high"
    elif by_sev["medium"] or score >= 15:
        posture = "medium"
    else:
        posture = "low"
    if logf:
        _log(logf, "issues: %d (%s) score=%d posture=%s cats=%s" % (
            len(issues), by_sev, score, posture, by_cat))
    return {
        "issues_total": len(issues),
        "issues_by_severity": by_sev,
        "issues_by_category": sorted(by_cat.items(), key=lambda x: -x[1]),
        "issues_by_owner": sorted(by_owner.items(), key=lambda x: -x[1]),
        "attack_surface_score": score, "posture": posture,
    }


_PROVIDER_LABEL = {
    "aws": "AWS", "azure": "Azure", "gcp": "GCP", "cloudflare": "Cloudflare",
    "digitalocean": "DigitalOcean", "akamai": "Akamai", "fastly": "Fastly",
    "oracle": "OCI", "alibaba": "Alibaba", "vultr": "Vultr", "linode": "Linode",
}


def build_cloud_summary(out_dir, issues, logf):
    """Cloud-security console data: the host→cloud-resource inventory (the
    'which maps to which' the analyst needs), provider mix, cloud-issue rollups,
    email-spoofing posture, and takeover attack-paths."""
    cdir = os.path.join(out_dir, "17_cloud_exposure")
    cloud_issues = [i for i in issues if i.get("source") == "cloud-scan"]

    # Host → cloud-resource inventory with provenance (from the asset map).
    assets, prov_count = [], {}
    for e in _read_jsonl(os.path.join(cdir, "cloud_asset_map.jsonl")):
        prov = e.get("provider", "") or ""
        prov_count[prov or "—"] = prov_count.get(prov or "—", 0) + 1
        assets.append({
            "host": e.get("host", ""), "service": e.get("service", ""),
            "provider": prov, "provider_label": _PROVIDER_LABEL.get(prov, prov.upper() or "—"),
            "region": e.get("region", ""), "category": e.get("category", ""),
            "category_label": e.get("category_label", ""),
            "severity": e.get("severity", "info"), "risk": e.get("risk", ""),
            "evidence": (e.get("evidence") or "")[:160],
        })
    assets.sort(key=lambda a: -SEV_RANK.get(a["severity"], 0))

    by_sev = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    by_cat = {}
    for i in cloud_issues:
        by_sev[i["severity"]] = by_sev.get(i["severity"], 0) + 1
        by_cat[i["category"]] = by_cat.get(i["category"], 0) + 1
    score = min(100, int(sum(_SEV_W.get(s, 0) * n for s, n in by_sev.items())))
    if by_sev["critical"]:
        posture = "critical"
    elif by_sev["high"] or score >= 40:
        posture = "high"
    elif by_sev["medium"] or score >= 15:
        posture = "medium"
    else:
        posture = "low"

    # Takeover attack-paths (the guidebook's "connect the dots" story).
    paths = []
    for i in cloud_issues:
        if i["category"] == "Subdomain Takeover":
            paths.append({
                "host": i["affected_host"], "severity": "critical",
                "attack": i.get("attack", ""),
                "steps": ["Dangling DNS / CNAME still points at a cloud resource",
                          "That cloud resource has been deprovisioned",
                          "Attacker re-registers it → serves content on your subdomain"],
            })

    email = _read_json(os.path.join(cdir, "email_auth.json"), {}) or {}

    _log(logf, "cloud view: %d issues, %d assets, %d providers, score=%d (%s)" % (
        len(cloud_issues), len(assets), len(prov_count), score, posture))

    return {
        "score": score, "posture": posture, "total_issues": len(cloud_issues),
        "total_assets": len(assets), "by_severity": by_sev,
        "by_category": sorted(by_cat.items(), key=lambda x: -x[1]),
        "by_provider": sorted(prov_count.items(), key=lambda x: -x[1]),
        "assets": assets[:300], "attack_paths": paths[:20], "email_auth": email,
    }


# ── Main ──────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description="ARISE Internet Intelligence Layer (Module 23)")
    ap.add_argument("out_dir", help="scan OUTPUT_DIR")
    ap.add_argument("--domain", default="", help="target domain")
    ap.add_argument("--no-net", action="store_true", help="skip all external lookups")
    args = ap.parse_args()

    out_dir = args.out_dir
    base = os.path.join(out_dir, "23_internet_intel")
    os.makedirs(base, exist_ok=True)

    no_net = args.no_net or os.environ.get("IIL_NO_NET", "").lower() == "true"
    ipinfo_token = _resolve_key("IPINFO_TOKEN", "IPINFO_API_KEY")
    cfg = {
        "domain": args.domain,
        "censys_id": "" if no_net else _resolve_key("CENSYS_API_ID"),
        "censys_secret": "" if no_net else _resolve_key("CENSYS_API_SECRET"),
        "greynoise_key": "" if no_net else _resolve_key("GREYNOISE_API_KEY"),
        # None → ipinfo disabled; "" → anonymous ipinfo (works, rate-limited); str → keyed
        "ipinfo_token": None if no_net else (ipinfo_token if ipinfo_token else ""),
        "no_net": no_net,
        "max_ips": int(os.environ.get("IIL_MAX_IPS", "200")),
        "timeout": float(os.environ.get("IIL_TIMEOUT", "8")),
        "workers": int(os.environ.get("IIL_WORKERS", "8")),
        "budget": float(os.environ.get("IIL_BUDGET", "180")),
    }

    logf = open(os.path.join(base, "internet_intel.log"), "a")
    _log(logf, "=== IIL start (domain=%s no_net=%s censys=%s greynoise=%s ipinfo=%s) ===" % (
        cfg["domain"] or "?", no_net,
        "on" if cfg["censys_id"] else "off",
        "on" if cfg["greynoise_key"] else "off",
        "off" if cfg["ipinfo_token"] is None else ("keyed" if cfg["ipinfo_token"] else "anon")))

    try:
        modules = load_all_modules(out_dir, logf)

        # Origin IPs.
        origin_ips = [
            ip for ip in sorted(modules["all_ips"])
            if _is_public_ip(ip) and ip not in modules["cdn_ips"]
            and not modules["ip_annotations"].get(ip, {}).get("cdn", False)
            and not _is_known_cdn_ip(ip)
        ]

        # Offline geo mining FIRST (free).
        mined_geo = {}
        for ip in origin_ips:
            g = mine_geo(modules["ip_ptr"].get(ip, []),
                         sorted(modules["ip_hostnames"].get(ip, set())))
            if g:
                mined_geo[ip] = g
        _log(logf, "mined geo offline for %d/%d origin IPs" % (len(mined_geo), len(origin_ips)))

        # Enrich. ipinfo only for IPs that failed offline mining (fallback).
        enrichments = {}
        need_keys = cfg["censys_id"] or cfg["greynoise_key"] or (cfg["ipinfo_token"] is not None)
        if not no_net and need_keys:
            targets = origin_ips[:cfg["max_ips"]]
            deadline = time.time() + cfg["budget"]
            _log(logf, "enriching %d IPs (ipinfo fallback for %d un-mined)..." % (
                len(targets), sum(1 for ip in targets if ip not in mined_geo)))
            with ThreadPoolExecutor(max_workers=cfg["workers"]) as ex:
                futs = {ex.submit(enrich_ip, ip, cfg, ip not in mined_geo): ip
                        for ip in targets}
                hit_budget = False
                for fut in as_completed(futs):
                    if time.time() > deadline:
                        _log(logf, "budget hit (%ss) — stopping enrichment" % cfg["budget"])
                        hit_budget = True
                        break
                    ip = futs[fut]
                    try:
                        res = fut.result()
                        if res:
                            enrichments[ip] = res
                    except Exception as e:
                        _log(logf, "enrich %s failed: %s" % (ip, e))
                if hit_budget:
                    for f in futs:
                        f.cancel()
            _log(logf, "enriched %d IPs via API" % len(enrichments))

        assets, findings, summary = consolidate(modules, mined_geo, enrichments, cfg, logf)
        issues, issue_stats = derive_issues(assets, findings, modules, out_dir, logf)
        validate_cve_issues(issues, modules, cfg, logf)   # KEV/EPSS/CVSS + corroborate + active
        issue_stats = rollup_issues(issues, logf)         # re-rank after severities changed
        summary.update(issue_stats)
        summary["top_issues"] = issues[:25]
        summary["cloud"] = build_cloud_summary(out_dir, issues, logf)

    except Exception as e:
        _log(logf, "FATAL (handled): %s" % e)
        import traceback
        traceback.print_exc(file=logf)
        assets, findings, issues = [], [], []
        summary = {
            "domain": cfg["domain"], "generated_at": _now_iso(),
            "total_assets": 0, "total_findings": 0, "total_cves": 0, "total_ports": 0,
            "geo_located": 0, "by_severity": {}, "risk_score": 0, "grade": "low",
            "geo_source_breakdown": {}, "geo_assets": [], "critical_assets": [],
            "top_cves": [], "top_services": [], "top_ports": [],
            "top_providers": [], "top_countries": [],
            "enrichment": {"censys": False, "greynoise": False, "ipinfo": False, "shodan": False},
            "issues_total": 0, "issues_by_severity": {}, "issues_by_category": [],
            "issues_by_owner": [], "attack_surface_score": 0, "posture": "low",
            "top_issues": [], "cloud": {}, "error": str(e),
        }

    with open(os.path.join(base, "intel_assets.jsonl"), "w") as f:
        for a in assets:
            f.write(json.dumps(a) + "\n")
    with open(os.path.join(base, "intel_findings.jsonl"), "w") as f:
        for fx in findings:
            f.write(json.dumps(fx) + "\n")
    with open(os.path.join(base, "intel_issues.jsonl"), "w") as f:
        for ix in issues:
            f.write(json.dumps(ix) + "\n")
    with open(os.path.join(base, "intel_summary.json"), "w") as f:
        json.dump(summary, f, indent=1)

    _log(logf, "=== done: %d assets, %d issues, score=%s (%s), %d geo ===" % (
        len(assets), summary.get("issues_total", 0),
        summary.get("attack_surface_score"), summary.get("posture"),
        summary.get("geo_located", 0)))
    logf.close()

    print("internet_intel: assets=%d issues=%d score=%s posture=%s geo=%d" % (
        summary.get("total_assets", 0), summary.get("issues_total", 0),
        summary.get("attack_surface_score", 0), summary.get("posture", "?"),
        summary.get("geo_located", 0)))
    return 0


def _selftest() -> int:
    """Cluster A corroboration self-test (P1-9, ARISE_REMEDIATION_ROADMAP.md):
    internet_intel used to derive nuclei severity in isolation, blind to
    whether Module 24/27/Autonomous independently confirmed the same vuln —
    the exact 'same bug, two severities, two tabs' pattern found repeatedly
    in the review."""
    import tempfile

    with tempfile.TemporaryDirectory() as d:
        os.makedirs(os.path.join(d, "24_advanced_attacks"))
        with open(os.path.join(d, "24_advanced_attacks", "offensive_findings.jsonl"), "w") as f:
            f.write(json.dumps({
                "template-id": "sqli-boolean", "host": "api.target.com",
                "matched-at": "https://api.target.com/search?q=1",
                "info": {"severity": "critical"}, "confidence": "confirmed",
            }) + "\n")

        # Corroborated: nuclei said medium, offensive_verify independently
        # confirmed the SAME (host, endpoint, class) as critical -> must climb.
        corroborated = {"template-id": "sqli-boolean", "host": "api.target.com",
                        "matched-at": "https://api.target.com/search?q=1",
                        "info": {"severity": "medium"}}
        # Unrelated: different host/template entirely -> must be untouched.
        unrelated = {"template-id": "weak-cipher", "host": "other.target.com",
                    "matched-at": "https://other.target.com/", "info": {"severity": "low"}}

        nuclei_findings = [corroborated, unrelated]
        import io as _io
        logf = _io.StringIO()
        _corroborate_nuclei_severity(nuclei_findings, d, logf)

        assert corroborated["info"]["severity"] == "critical", \
            f"expected corroboration to climb medium->critical, got {corroborated['info']['severity']}"
        assert len(corroborated.get("_corroborated_by", [])) >= 2
        assert unrelated["info"]["severity"] == "low", \
            "an unrelated finding must never be touched by another host's corroboration"
        print("[1] _corroborate_nuclei_severity: cross-engine agreement climbs severity, "
              "unrelated findings untouched  ✓")

    print("\ninternet_intel corroboration self-test: ALL PASS")
    return 0


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        sys.exit(_selftest())
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as e:
        print("internet_intel: fatal (ignored): %s" % e, file=sys.stderr)
        sys.exit(0)
