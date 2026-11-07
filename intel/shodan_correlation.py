#!/usr/bin/env python3
"""
ARISE Module 22 — Shodan Correlation Engine
============================================

Passive external-view enrichment + correlation. This is the "Pass B" correlate
stage described in the design: it takes ARISE's own *observed* view (resolved
IPs, open ports, fingerprinted services, HTTP tech, WAF map) and reconciles it
against Shodan's *external cached* view of the same origin IPs, producing:

  * a per-asset correlation matrix (IP <-> hostnames <-> provider <-> ports),
  * coverage gaps (ports Shodan sees that our active scan did NOT, and vice-versa),
  * detection findings from port/product/CVE signatures (CWE + CAPEC + ATT&CK),
  * an exposure score + provider/severity rollups the dashboard renders.

Design guarantees (so it never disturbs the rest of the pipeline):
  * stdlib only — no new third-party dependencies,
  * fully passive — never sends a packet at the target; only reads Shodan's cache,
  * honors ARISE's "skip WAF/CDN IPs" rule — CDN/WAF edge IPs are excluded from
    every Shodan lookup (querying them would enrich shared CDN infra, not the target),
  * degrades gracefully — with no network / no key it still emits the local
    correlation matrix, and it never exits non-zero in a way that fails the scan.

Data sources for the external view, in priority order:
  1. Offline replay   : <out>/22_shodan_correlation/shodan_raw/<ip>.json (air-gapped / re-runs)
  2. Shodan REST API  : https://api.shodan.io/shodan/host/<ip>?key=$SHODAN_API_KEY  (rich banners)
  3. Shodan InternetDB: https://internetdb.shodan.io/<ip>  (free, no key: ports/cpes/vulns/tags)
  4. local-only       : no external view; matrix + observed-port rules only.

Usage:
  python3 shodan_correlation.py <OUTPUT_DIR> [--domain target.com] [--no-net]

Env knobs:
  SHODAN_API_KEY         if set, uses the full Shodan host API (else InternetDB)
  SHODAN_INTERNETDB      "false" disables the free InternetDB fallback
  SHODAN_CORR_MAX_IPS    cap on origin IPs to look up            (default 256)
  SHODAN_CORR_TIMEOUT    per-request timeout seconds             (default 6)
  SHODAN_CORR_WORKERS    concurrent lookups                      (default 10)
  SHODAN_CORR_BUDGET     overall wall-clock budget seconds       (default 120)
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
import socket
import ipaddress
import argparse
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

try:  # network is optional; guard the import so local-only mode still works
    import ssl
    from urllib.request import Request, urlopen
    from urllib.error import HTTPError, URLError
except Exception:  # pragma: no cover
    ssl = Request = urlopen = HTTPError = URLError = None


def _build_ssl_context():
    """Prefer verified TLS. Fall back to certifi's CA bundle (fixes the common
    macOS 'CERTIFICATE_VERIFY_FAILED' where the Python install has no CA store).
    Only if SHODAN_CORR_INSECURE_TLS=true do we allow an unverified context —
    acceptable *only* because Shodan/InternetDB are read-only public intel, and
    always with a loud warning. Default stays verified/secure."""
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


# ---------------------------------------------------------------------------
# Detection signatures — the machine-readable form of the "Table C" rule pack.
# Each rule fires on a port (and optionally a product/tag) present on an ORIGIN
# IP, and carries the enterprise finding fields: CWE + CAPEC + ATT&CK + severity.
# ---------------------------------------------------------------------------
DATASTORE_PORTS = {
    6379: "Redis", 6380: "Redis", 27017: "MongoDB", 27018: "MongoDB",
    9200: "Elasticsearch", 9300: "Elasticsearch", 5432: "PostgreSQL",
    3306: "MySQL", 11211: "Memcached", 9042: "Cassandra", 5984: "CouchDB",
    8086: "InfluxDB", 5601: "Kibana", 1433: "MSSQL", 1521: "Oracle DB",
}
REMOTE_ADMIN_PORTS = {
    3389: "RDP", 5900: "VNC", 5901: "VNC", 23: "Telnet", 445: "SMB",
    139: "NetBIOS", 512: "rexec", 513: "rlogin", 514: "rsh", 3283: "ARD",
}
ORCH_PORTS = {
    2375: "Docker API", 2376: "Docker API (TLS)", 2379: "etcd", 2380: "etcd",
    6443: "kube-apiserver", 10250: "kubelet", 10255: "kubelet-ro", 8001: "kube-proxy",
}
MSG_PORTS = {
    5672: "RabbitMQ", 15672: "RabbitMQ Mgmt", 9092: "Kafka", 1883: "MQTT",
    8883: "MQTT/TLS", 61616: "ActiveMQ", 4222: "NATS",
}
ICS_PORTS = {
    502: "Modbus", 102: "Siemens S7", 47808: "BACnet", 20000: "DNP3",
    2404: "IEC-104", 44818: "EtherNet/IP", 1911: "Niagara Fox",
}
MGMT_WEB_PORTS = {
    9000: "Portainer/Mgmt", 8081: "Nexus", 8500: "Consul", 4646: "Nomad",
    15672: "RabbitMQ Mgmt", 9090: "Prometheus", 3000: "Grafana",
}
# Standard web ports are benign and ubiquitous — a Shodan-only :80 next to our
# observed :443 is scan-coverage noise, never a finding. Shown in the matrix only.
BENIGN_WEB_PORTS = {80, 443, 8080, 8443, 8000, 8888, 4443}

# tag (from InternetDB / Shodan) -> finding template
TAG_RULES = {
    "self-signed-certificate": ("weak-tls-cert", "Self-signed certificate on internet-facing service",
                                "CWE-295", "CAPEC-459", "T1587.003", "medium"),
    "eol-product": ("eol-product", "End-of-life product exposed to the internet",
                    "CWE-1104", "CAPEC-310", "T1190", "high"),
    "eol-os": ("eol-os", "End-of-life operating system exposed",
               "CWE-1104", "CAPEC-310", "T1190", "high"),
    "vpn": ("vpn-exposed", "VPN concentrator exposed (patch-cadence sensitive)",
            "CWE-284", "CAPEC-560", "T1133", "medium"),
    "database": ("db-tag", "Database service exposed to the internet",
                 "CWE-306", "CAPEC-1", "T1078", "high"),
    "compromised": ("compromised-tag", "Host flagged as previously compromised",
                    "CWE-506", "CAPEC-549", "T1190", "critical"),
    "malware": ("malware-tag", "Host flagged as serving/hosting malware",
                "CWE-506", "CAPEC-549", "T1105", "critical"),
    "honeypot": ("honeypot-tag", "Host looks like a honeypot (may be decoy)",
                 "CWE-1029", "CAPEC-", "T1195", "info"),
}

SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
SEV_SCORE = {"critical": 40, "high": 25, "medium": 12, "low": 5, "info": 1}

# Well-known CDN/WAF edge ranges — a safety net *in addition to* Module 3's
# cdn_ips.txt. Querying Shodan for these enriches shared CDN infrastructure, not
# the target (the "skip WAF/CDN IPs" rule), so they are excluded from lookups.
KNOWN_CDN_CIDRS = [
    # Cloudflare
    "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "173.245.48.0/20",
    "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18",
    "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
    "198.41.128.0/17", "162.158.0.0/15", "131.0.72.0/22",
    # Fastly
    "151.101.0.0/16", "199.232.0.0/16",
    # Akamai (partial, common)
    "23.32.0.0/11", "23.192.0.0/11", "104.64.0.0/10", "184.24.0.0/13",
    "2.16.0.0/13", "95.100.0.0/15",
]
_KNOWN_CDN_NETS = []
for _c in KNOWN_CDN_CIDRS:
    try:
        _KNOWN_CDN_NETS.append(ipaddress.ip_network(_c))
    except Exception:
        pass


def _is_known_cdn_ip(s):
    try:
        ip = ipaddress.ip_address(s)
    except Exception:
        return False
    for net in _KNOWN_CDN_NETS:
        try:
            if ip in net:
                return True
        except Exception:
            continue
    return False


# provider inference from PTR / ASN-ish substrings
PROVIDER_HINTS = [
    ("amazonaws.com", "AWS"), ("aws", "AWS"), ("cloudfront", "AWS CloudFront"),
    ("azure", "Azure"), ("microsoft", "Azure"), ("googleusercontent", "GCP"),
    ("1e100.net", "GCP"), ("google", "GCP"), ("cloudflare", "Cloudflare"),
    ("akamai", "Akamai"), ("fastly", "Fastly"), ("digitalocean", "DigitalOcean"),
    ("linode", "Linode"), ("hetzner", "Hetzner"), ("ovh", "OVH"),
    ("oracle", "OCI"), ("vultr", "Vultr"), ("alibaba", "Alibaba"),
]


def _now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _log(logf, msg):
    line = "[%s] %s" % (_now_iso(), msg)
    try:
        logf.write(line + "\n")
        logf.flush()
    except Exception:
        pass
    print(line, file=sys.stderr)


def _read_lines(path):
    out = []
    try:
        with open(path, "r", errors="ignore") as f:
            for ln in f:
                ln = ln.strip()
                if ln and not ln.startswith("#"):
                    out.append(ln)
    except Exception:
        pass
    return out


def _read_jsonl(path):
    rows = []
    try:
        with open(path, "r", errors="ignore") as f:
            for ln in f:
                ln = ln.strip()
                if not ln:
                    continue
                try:
                    rows.append(json.loads(ln))
                except Exception:
                    continue
    except Exception:
        pass
    return rows


def _read_json(path, default=None):
    try:
        with open(path, "r", errors="ignore") as f:
            return json.load(f)
    except Exception:
        return default


def _is_ip(s):
    try:
        ipaddress.ip_address(s)
        return True
    except Exception:
        return False


def _is_public_ip(s):
    try:
        ip = ipaddress.ip_address(s)
        return not (ip.is_private or ip.is_loopback or ip.is_link_local
                    or ip.is_multicast or ip.is_reserved or ip.is_unspecified)
    except Exception:
        return False


def _provider_from(text):
    t = (text or "").lower()
    for needle, name in PROVIDER_HINTS:
        if needle in t:
            return name
    return ""


def _asset_class(hostnames):
    """Prod/staging/dev heuristic (mirrors ARISE's existing asset-class logic)."""
    blob = " ".join(hostnames).lower()
    for kw, cls in (("prod", "production"), ("stag", "staging"), ("uat", "uat"),
                    ("qa", "qa"), ("dev", "dev"), ("test", "test"),
                    ("sandbox", "dev"), ("integ", "staging")):
        if kw in blob:
            return cls
    return "production"  # internet-facing default


def _crit_weight(asset_class):
    return {"production": 1.0, "staging": 0.6, "uat": 0.6, "qa": 0.4,
            "dev": 0.3, "test": 0.3}.get(asset_class, 0.8)


# ---------------------------------------------------------------------------
# Load ARISE's own observed view from the scan output directory.
# ---------------------------------------------------------------------------
def load_observed(out_dir, logf):
    obs = {
        "all_ips": set(), "cdn_ips": set(), "resolved_hosts": [],
        "ip_hosts": {},        # ip -> set(hostnames)
        "ip_ptr": {},          # ip -> ptr string
        "ip_cdn": {},          # ip -> (cdn_bool, cdn_name)
        "ip_ports": {},        # ip -> set(ports observed by ARISE)
        "ip_services": {},     # ip -> [ {port, product, version, name, cpe[]} ]
        "host_http": {},       # host -> {webserver, tech[], title, status}
        "host_waf": {},        # host -> waf name
        "origin_hosts": set(),
        "waf_cdn_skipped": set(),
        "nuclei_cves": set(),
    }
    d3 = os.path.join(out_dir, "03_dns_resolution")
    d4 = os.path.join(out_dir, "04_http_discovery")
    d5 = os.path.join(out_dir, "05_waf_detection")
    d7 = os.path.join(out_dir, "07_service_fingerprint")
    d12 = os.path.join(out_dir, "12_nuclei_scanning")
    d14 = os.path.join(out_dir, "14_port_scan")

    obs["all_ips"] = {x for x in _read_lines(os.path.join(d3, "all_ips.txt")) if _is_ip(x)}
    obs["cdn_ips"] = {x for x in _read_lines(os.path.join(d3, "cdn_ips.txt")) if _is_ip(x)}
    obs["resolved_hosts"] = _read_lines(os.path.join(d3, "resolved.txt"))
    obs["origin_hosts"] = set(_read_lines(os.path.join(d14, "origin_hosts.txt")))
    obs["waf_cdn_skipped"] = set(_read_lines(os.path.join(d14, "waf_cdn_skipped.txt")))

    # ip_annotations.json is JSONL: {host:<ip>, ptr:[], cdn:bool, cdn-name:str}
    for row in _read_jsonl(os.path.join(d3, "ip_annotations.json")):
        ip = row.get("host") or row.get("ip")
        if not ip or not _is_ip(ip):
            continue
        ptr = row.get("ptr") or []
        if isinstance(ptr, list):
            ptr = ptr[0] if ptr else ""
        obs["ip_ptr"][ip] = ptr
        obs["ip_cdn"][ip] = (bool(row.get("cdn")), row.get("cdn-name") or "")
        if row.get("cdn"):
            obs["cdn_ips"].add(ip)

    # observed open ports (14_port_scan/all_ports.jsonl): {host, ip, port, ...}
    for row in _read_jsonl(os.path.join(d14, "all_ports.jsonl")):
        ip = row.get("ip"); host = row.get("host"); port = row.get("port")
        if ip:
            if port:
                obs["ip_ports"].setdefault(ip, set()).add(int(port))
            if host:
                obs["ip_hosts"].setdefault(ip, set()).add(host)

    # fingerprinted services (07_service_fingerprint/services.json)
    services = _read_json(os.path.join(d7, "services.json"), []) or []
    if isinstance(services, list):
        for s in services:
            ip = s.get("ip"); host = s.get("host")
            if not ip:
                continue
            obs["ip_services"].setdefault(ip, []).append({
                "port": s.get("port"), "name": s.get("name", ""),
                "product": s.get("product", ""), "version": s.get("version", ""),
                "cpe": s.get("cpe", []) or [],
            })
            if s.get("port"):
                obs["ip_ports"].setdefault(ip, set()).add(int(s["port"]))
            if host:
                obs["ip_hosts"].setdefault(ip, set()).add(host)

    # HTTP fingerprint (04_http_discovery/http_confirmed.json) — JSONL from httpx
    for row in _read_jsonl(os.path.join(d4, "http_confirmed.json")):
        host = (row.get("host") or row.get("input") or row.get("url") or "")
        host = re.sub(r"^https?://", "", host).split("/")[0].split(":")[0]
        if not host:
            continue
        obs["host_http"][host] = {
            "webserver": row.get("webserver", ""),
            "tech": row.get("tech") or row.get("technologies") or [],
            "title": row.get("title", ""),
            "status": row.get("status_code") or row.get("status-code") or "",
        }
        # some httpx rows carry the resolved a-record
        for ip in (row.get("a") or []):
            if _is_ip(ip):
                obs["ip_hosts"].setdefault(ip, set()).add(host)

    # WAF map (05_waf_detection/<host> — one wafw00f text file per host)
    try:
        for name in os.listdir(d5):
            fp = os.path.join(d5, name)
            if not os.path.isfile(fp):
                continue
            txt = ""
            try:
                with open(fp, "r", errors="ignore") as f:
                    txt = f.read()
            except Exception:
                continue
            m = re.search(r"is behind (.+?)(?:\s+WAF|\.|\n)", txt)
            if m:
                obs["host_waf"][name] = m.group(1).strip()
            elif re.search(r"No WAF detected", txt, re.I):
                obs["host_waf"][name] = ""
    except Exception:
        pass

    # nuclei CVE cross-reference (best-effort text grep)
    nuc = os.path.join(d12, "nuclei_results.txt")
    if os.path.exists(nuc):
        try:
            with open(nuc, "r", errors="ignore") as f:
                for ln in f:
                    for cve in re.findall(r"CVE-\d{4}-\d{4,7}", ln, re.I):
                        obs["nuclei_cves"].add(cve.upper())
        except Exception:
            pass

    _log(logf, "observed: %d ips (%d cdn), %d hosts with ports, %d services rows, %d http, %d waf files" % (
        len(obs["all_ips"]), len(obs["cdn_ips"]), len(obs["ip_ports"]),
        sum(len(v) for v in obs["ip_services"].values()),
        len(obs["host_http"]), len(obs["host_waf"])))
    return obs


# ---------------------------------------------------------------------------
# External view — Shodan (offline replay / REST API / InternetDB).
# ---------------------------------------------------------------------------
_SSL_CTX = _build_ssl_context()
_INSECURE_WARNED = [False]


def _http_get_json(url, timeout, headers=None):
    if urlopen is None:
        return None, "no-urllib"
    hdrs = headers or {"User-Agent": "ARISE-ShodanCorr/1.0"}

    def _do(ctx):
        req = Request(url, headers=hdrs)
        with urlopen(req, timeout=timeout, context=ctx) as resp:
            data = resp.read()
        return json.loads(data.decode("utf-8", "ignore"))

    try:
        return _do(_SSL_CTX), None
    except HTTPError as e:
        # 404 from InternetDB just means "no data for this IP" — not an error.
        return None, "http-%s" % getattr(e, "code", "?")
    except URLError as e:
        reason = getattr(e, "reason", "?")
        is_ssl = isinstance(reason, ssl.SSLError) if ssl else False
        if is_ssl and os.environ.get("SHODAN_CORR_INSECURE_TLS", "").lower() == "true":
            try:
                unverified = ssl._create_unverified_context() if ssl else None
                if not _INSECURE_WARNED[0]:
                    print("WARNING: TLS verification disabled for Shodan lookups "
                          "(SHODAN_CORR_INSECURE_TLS=true). Fix your Python CA store instead.",
                          file=sys.stderr)
                    _INSECURE_WARNED[0] = True
                return _do(unverified), None
            except Exception as e2:
                return None, "ssl-insecure-%s" % e2.__class__.__name__
        return None, "url-%s" % (reason.__class__.__name__ if hasattr(reason, "__class__") else reason)
    except socket.timeout:
        return None, "timeout"
    except Exception as e:
        return None, "err-%s" % e.__class__.__name__


def fetch_external(ip, cfg, raw_dir):
    """Return (normalized_dict, source) for one IP. Never raises."""
    # 1) offline replay
    replay = os.path.join(raw_dir, "%s.json" % ip)
    if os.path.exists(replay):
        raw = _read_json(replay)
        if raw is not None:
            return _normalize_external(raw), "offline"

    # 2) full Shodan API (rich)
    if cfg["api_key"] and not cfg["no_net"]:
        url = "https://api.shodan.io/shodan/host/%s?key=%s" % (ip, cfg["api_key"])
        data, err = _http_get_json(url, cfg["timeout"])
        if data is not None:
            try:  # persist for reproducibility / offline re-runs
                with open(replay, "w") as f:
                    json.dump(data, f)
            except Exception:
                pass
            return _normalize_external(data), "api"

    # 3) InternetDB (free, no key)
    if cfg["internetdb"] and not cfg["no_net"]:
        url = "https://internetdb.shodan.io/%s" % ip
        data, err = _http_get_json(url, cfg["timeout"])
        if data is not None:
            try:
                with open(replay, "w") as f:
                    json.dump(data, f)
            except Exception:
                pass
            return _normalize_external(data), "internetdb"

    return None, "none"


def _normalize_external(raw):
    """Fold Shodan API and InternetDB shapes into one normalized record."""
    ports, cpes, hostnames, tags, vulns, products = [], [], [], [], [], []
    if not isinstance(raw, dict):
        return {"ports": [], "cpes": [], "hostnames": [], "tags": [], "vulns": [], "products": []}

    # InternetDB shape
    if "ports" in raw and ("cpes" in raw or "vulns" in raw or "tags" in raw):
        ports = [int(p) for p in raw.get("ports", []) if isinstance(p, (int, str)) and str(p).isdigit()]
        cpes = list(raw.get("cpes", []) or [])
        hostnames = list(raw.get("hostnames", []) or [])
        tags = list(raw.get("tags", []) or [])
        vulns = list(raw.get("vulns", []) or [])

    # Full Shodan host API shape
    if "data" in raw and isinstance(raw["data"], list):
        for banner in raw["data"]:
            if not isinstance(banner, dict):
                continue
            p = banner.get("port")
            if p:
                ports.append(int(p))
            prod = banner.get("product")
            ver = banner.get("version")
            if prod:
                products.append({"port": p, "product": prod, "version": ver or "",
                                 "cpe": banner.get("cpe", []) or [],
                                 "module": (banner.get("_shodan", {}) or {}).get("module", "")})
            for c in (banner.get("cpe23") or banner.get("cpe") or []):
                cpes.append(c)
            for v in (banner.get("vulns") or {}):
                vulns.append(v)
        hostnames = list(raw.get("hostnames", []) or [])
        tags = list(raw.get("tags", []) or [])
        for v in (raw.get("vulns") or []):
            vulns.append(v)

    return {
        "ports": sorted(set(ports)),
        "cpes": sorted(set(cpes)),
        "hostnames": sorted(set(hostnames)),
        "tags": sorted(set(tags)),
        "vulns": sorted(set(v.upper() if isinstance(v, str) else v for v in vulns)),
        "products": products,
        "asn": raw.get("asn", ""), "org": raw.get("org", ""),
        "isp": raw.get("isp", ""), "os": raw.get("os", ""),
        "country": raw.get("country_name") or raw.get("country_code", ""),
        "city": raw.get("city", ""),
    }


# ---------------------------------------------------------------------------
# KEV lookup for Shodan-reported CVEs — READ ONLY, no network call here.
# ---------------------------------------------------------------------------
# Shodan's vulns[] is a version/CPE-banner GUESS, not a confirmed finding —
# payu.in post-mortem: of 320 distinct CVEs Shodan reported across 9 origin
# IPs, only 3 (<1%) were actually on CISA's Known Exploited Vulnerabilities
# catalog; many were 2007/2008-era CVEs on infrastructure scanned in 2026 —
# almost certainly stale/wrong banner matches, not 19-year-unpatched hosts.
# Every single one was still published at a flat "high" severity regardless.
#
# internet_intel.py (Module 23) already builds + refreshes a KEV cache
# (.arise_kev_cache.json, 24h TTL) for its own CVE-validation pass — but that
# pass runs on a SEPARATE copy of the Shodan CVE data it derives itself, not
# on this module's own `known-cve` findings (the ones the Shodan dashboard
# tab reads directly via /api/shodan), so those never benefited from it.
# Rather than duplicate _load_kev's fetch/refresh logic (and add a new
# network dependency to a module documented as "fully passive"), this is a
# read-only consumer of whatever KEV cache already exists on disk — Module
# 23 keeps it fresh; if it hasn't run yet or the file is missing, we simply
# don't escalate (fail toward the conservative, lower-severity classification,
# never toward an unjustified "critical").
_KEV_CACHE_PATH = _os.path.join(_ROOT, ".arise_kev_cache.json")


def _load_kev_local() -> set:
    try:
        with open(_KEV_CACHE_PATH, "r") as f:
            data = json.load(f)
        return set(data.get("cves", [])) if isinstance(data, dict) else set()
    except Exception:
        return set()


def _cve_severity(cve: str, correlation: str, kev: set) -> str:
    """Known-CVE severity, graded by evidence strength instead of a flat
    'high' for every Shodan banner-guess:
      - independently confirmed by our own nuclei scan -> high (real signal)
      - on CISA KEV (actively exploited in the wild)    -> critical, even if
        we haven't independently confirmed it locally — KEV membership is
        itself strong external evidence of real-world exploitability
      - neither -> low, matching internet_intel.py's own convention for an
        unconfirmed, version-inferred Shodan CVE (see its 2b/"external-intel"
        Known Vulnerability issues) — visible and filterable, but not
        drowning out genuinely confirmed findings at the same "high" level."""
    if correlation == "confirmed":
        return "high"
    if cve in kev:
        return "critical"
    return "low"


# ---------------------------------------------------------------------------
# Correlation + detection.
# ---------------------------------------------------------------------------
def make_finding(rule_id, title, ip, port, product, cwe, capec, attack,
                 severity, correlation, hostnames, asset_class, evidence, source):
    crit = _crit_weight(asset_class)
    # reachability is 1.0 — every origin IP here is internet-facing by construction
    conf = "high" if correlation in ("confirmed",) else ("medium" if correlation == "shodan_only" else "low")
    conf_w = {"high": 1.0, "medium": 0.75, "low": 0.5}[conf]
    priority = round(SEV_SCORE[severity] * crit * conf_w, 1)
    return {
        "rule_id": rule_id, "title": title, "ip": ip, "port": port,
        "product": product, "hostnames": sorted(hostnames)[:8],
        "cwe": cwe, "capec": capec, "attack": attack,
        "severity": severity, "confidence": conf, "correlation": correlation,
        "asset_class": asset_class, "priority": priority,
        "evidence": evidence, "source": source, "detected_at": _now_iso(),
    }


def correlate(obs, cfg, raw_dir, logf):
    kev = _load_kev_local()
    _log(logf, "KEV local cache: %d CVE(s) (read-only; Module 23 keeps it fresh)" % len(kev))

    # Build the union asset set keyed by IP. Query set = ORIGIN (non-CDN) public IPs.
    all_ips = set(obs["all_ips"])
    for ip in obs["ip_ports"]:
        all_ips.add(ip)
    for ip in obs["ip_services"]:
        all_ips.add(ip)

    cdn_ips = set(obs["cdn_ips"])
    origin_ips = sorted(ip for ip in all_ips
                        if _is_public_ip(ip) and ip not in cdn_ips
                        and not obs["ip_cdn"].get(ip, (False, ""))[0]
                        and not _is_known_cdn_ip(ip))
    origin_ips = origin_ips[: cfg["max_ips"]]

    _log(logf, "assets: %d total, %d cdn-excluded, %d origin to enrich (source=%s)" % (
        len(all_ips), len(all_ips) - len(origin_ips), len(origin_ips),
        "api" if cfg["api_key"] else ("internetdb" if cfg["internetdb"] and not cfg["no_net"] else "local-only")))

    # Fetch external view concurrently, under a wall-clock budget.
    external = {}
    src_counts = {}
    if origin_ips and not cfg["no_net"] or any(os.path.exists(os.path.join(raw_dir, "%s.json" % ip)) for ip in origin_ips):
        deadline = time.time() + cfg["budget"]
        with ThreadPoolExecutor(max_workers=cfg["workers"]) as ex:
            futs = {ex.submit(fetch_external, ip, cfg, raw_dir): ip for ip in origin_ips}
            for fut in as_completed(futs):
                ip = futs[fut]
                if time.time() > deadline:
                    _log(logf, "wall-clock budget (%ss) hit — stopping external lookups" % cfg["budget"])
                    break
                try:
                    norm, src = fut.result()
                except Exception:
                    norm, src = None, "error"
                src_counts[src] = src_counts.get(src, 0) + 1
                if norm is not None:
                    external[ip] = norm

    # Decide the reported source label
    if src_counts.get("api"):
        source_label = "api"
    elif src_counts.get("internetdb"):
        source_label = "internetdb"
    elif src_counts.get("offline"):
        source_label = "offline"
    else:
        source_label = "local-only"

    assets, findings = [], []
    cov = {"confirmed_ports": 0, "shodan_only_ports": 0, "arise_only_ports": 0, "port_deltas": 0}
    providers = {}

    for ip in origin_ips:
        ext = external.get(ip, {})
        hostnames = set(obs["ip_hosts"].get(ip, set()))
        ext_hostnames = set(ext.get("hostnames", []))
        hostnames |= ext_hostnames
        ptr = obs["ip_ptr"].get(ip, "")
        provider = (_provider_from(ptr) or _provider_from(ext.get("org", ""))
                    or _provider_from(ext.get("isp", "")) or _provider_from(" ".join(ext.get("cpes", []))))
        if provider:
            providers[provider] = providers.get(provider, 0) + 1
        aclass = _asset_class(list(hostnames) or [ip])

        obs_ports = set(obs["ip_ports"].get(ip, set()))
        ext_ports = set(ext.get("ports", []))
        confirmed = obs_ports & ext_ports
        shodan_only = ext_ports - obs_ports     # coverage gap: Shodan sees, we didn't scan
        arise_only = obs_ports - ext_ports       # Shodan cache blind / fresh finding
        cov["confirmed_ports"] += len(confirmed)
        cov["shodan_only_ports"] += len(shodan_only)
        cov["arise_only_ports"] += len(arise_only)
        cov["port_deltas"] += len(shodan_only) + len(arise_only)

        # waf status for any hostname on this ip
        waf = ""
        for h in hostnames:
            if obs["host_waf"].get(h):
                waf = obs["host_waf"][h]; break

        # ---- run detection rules over the union of ports ----
        union_ports = obs_ports | ext_ports
        asset_findings = []

        def _corr_for(p):
            if p in confirmed:
                return "confirmed"
            if p in shodan_only:
                return "shodan_only"
            return "arise_only"

        for p in sorted(union_ports):
            src = "shodan+arise" if p in confirmed else ("shodan" if p in shodan_only else "arise")
            if p in DATASTORE_PORTS:
                f = make_finding("datastore-exposed",
                                 "%s exposed to the internet" % DATASTORE_PORTS[p], ip, p,
                                 DATASTORE_PORTS[p], "CWE-306", "CAPEC-1", "T1078", "critical",
                                 _corr_for(p), hostnames, aclass,
                                 "port %d (%s) reachable on origin IP" % (p, DATASTORE_PORTS[p]), src)
                asset_findings.append(f)
            elif p in ORCH_PORTS:
                f = make_finding("orchestration-exposed",
                                 "%s control plane exposed" % ORCH_PORTS[p], ip, p,
                                 ORCH_PORTS[p], "CWE-284", "CAPEC-180", "T1610", "critical",
                                 _corr_for(p), hostnames, aclass,
                                 "port %d (%s) reachable on origin IP" % (p, ORCH_PORTS[p]), src)
                asset_findings.append(f)
            elif p in REMOTE_ADMIN_PORTS:
                f = make_finding("remote-admin-exposed",
                                 "%s remote-access service exposed" % REMOTE_ADMIN_PORTS[p], ip, p,
                                 REMOTE_ADMIN_PORTS[p], "CWE-284", "CAPEC-560", "T1133", "high",
                                 _corr_for(p), hostnames, aclass,
                                 "port %d (%s) reachable on origin IP" % (p, REMOTE_ADMIN_PORTS[p]), src)
                asset_findings.append(f)
            elif p in ICS_PORTS:
                f = make_finding("ics-ot-exposed",
                                 "%s ICS/OT protocol exposed" % ICS_PORTS[p], ip, p,
                                 ICS_PORTS[p], "CWE-284", "CAPEC-438", "T0883", "critical",
                                 _corr_for(p), hostnames, aclass,
                                 "port %d (%s) reachable on origin IP" % (p, ICS_PORTS[p]), src)
                asset_findings.append(f)
            elif p in MSG_PORTS:
                f = make_finding("messaging-exposed",
                                 "%s messaging/broker exposed" % MSG_PORTS[p], ip, p,
                                 MSG_PORTS[p], "CWE-306", "CAPEC-1", "T1078", "high",
                                 _corr_for(p), hostnames, aclass,
                                 "port %d (%s) reachable on origin IP" % (p, MSG_PORTS[p]), src)
                asset_findings.append(f)
            elif p in MGMT_WEB_PORTS and p in shodan_only:
                # only flag mgmt/alt-web when it's a Shodan-only coverage gap
                f = make_finding("mgmt-surface-gap",
                                 "%s reachable (not covered by active scan)" % MGMT_WEB_PORTS[p], ip, p,
                                 MGMT_WEB_PORTS[p], "CWE-284", "CAPEC-127", "T1190", "medium",
                                 "shodan_only", hostnames, aclass,
                                 "Shodan reports port %d open; ARISE port scan did not cover it" % p, "shodan")
                asset_findings.append(f)

        # ---- coverage-gap meta finding (Shodan-only ports beyond the known rules) ----
        # Benign/standard web ports are excluded — a Shodan-only :80 is not a
        # finding, just scan-coverage noise (still visible in the asset matrix).
        residual_gap = sorted(shodan_only - set(DATASTORE_PORTS) - set(ORCH_PORTS)
                              - set(REMOTE_ADMIN_PORTS) - set(ICS_PORTS) - set(MSG_PORTS)
                              - set(MGMT_WEB_PORTS) - BENIGN_WEB_PORTS)
        if residual_gap:
            asset_findings.append(make_finding(
                "coverage-gap", "Shodan reports %d uncommon port(s) our active scan missed" % len(residual_gap),
                ip, residual_gap[0], "", "CWE-1059", "CAPEC-169", "T1595", "info",
                "shodan_only", hostnames, aclass,
                "Ports seen only by Shodan: %s" % ", ".join(str(x) for x in residual_gap[:12]), "shodan"))

        # ---- CVE findings from Shodan vulns[] ----
        for cve in ext.get("vulns", []):
            in_nuclei = cve in obs["nuclei_cves"]
            correlation = "confirmed" if in_nuclei else "shodan_only"
            sev = _cve_severity(cve, correlation, kev)
            on_kev = cve in kev
            evidence = "Shodan vulns[] lists %s%s%s" % (
                cve,
                " (also confirmed by nuclei)" if in_nuclei else "",
                " (on CISA KEV — actively exploited in the wild)" if on_kev else
                " (version/banner-inferred only — not independently confirmed)" if not in_nuclei else "")
            asset_findings.append(make_finding(
                "known-cve", "Known CVE on internet-facing host: %s" % cve, ip, None, "",
                "CWE-1035", "CAPEC-", "T1190", sev,
                correlation, hostnames, aclass, evidence,
                "shodan+nuclei" if in_nuclei else "shodan"))
            findings_cve = asset_findings[-1]
            findings_cve["kev"] = on_kev
            findings_cve["cve"] = cve

        # ---- tag-based findings ----
        for tag in ext.get("tags", []):
            if tag in TAG_RULES:
                rid, title, cwe, capec, attack, sev = TAG_RULES[tag]
                asset_findings.append(make_finding(
                    rid, title, ip, None, "", cwe, capec, attack, sev,
                    "shodan_only", hostnames, aclass, "Shodan tag: %s" % tag, "shodan"))

        max_sev = "info"
        for f in asset_findings:
            if SEV_RANK[f["severity"]] > SEV_RANK[max_sev]:
                max_sev = f["severity"]

        # products (from services + shodan)
        prod_list = []
        for s in obs["ip_services"].get(ip, []):
            if s.get("product"):
                prod_list.append({"port": s["port"], "product": s["product"],
                                  "version": s.get("version", ""), "src": "arise"})
        for pr in ext.get("products", []):
            prod_list.append({"port": pr.get("port"), "product": pr.get("product"),
                              "version": pr.get("version", ""), "src": "shodan"})

        assets.append({
            "ip": ip, "hostnames": sorted(hostnames)[:12], "ptr": ptr,
            "provider": provider or "—", "asn": ext.get("asn", ""),
            "org": ext.get("org", ""), "country": ext.get("country", ""),
            "cdn": False, "waf": waf, "asset_class": aclass,
            "observed_ports": sorted(obs_ports), "shodan_ports": sorted(ext_ports),
            "confirmed_ports": sorted(confirmed), "shodan_only_ports": sorted(shodan_only),
            "arise_only_ports": sorted(arise_only),
            "products": prod_list, "cpes": ext.get("cpes", [])[:20],
            "tags": ext.get("tags", []), "cves": ext.get("vulns", []),
            "enriched": ip in external, "max_severity": max_sev,
            "findings": len(asset_findings),
        })
        findings.extend(asset_findings)

    # severity rollup + score. Weighting is dominated by critical/high so that a
    # pile of info-level coverage notes can never inflate the exposure grade.
    by_sev = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
    exposure_score = min(100, int(45 * by_sev["critical"] + 22 * by_sev["high"]
                                  + 8 * by_sev["medium"] + 2 * by_sev["low"]
                                  + 0.5 * by_sev["info"]))
    if by_sev["critical"] > 0 or exposure_score >= 70:
        grade = "critical"
    elif by_sev["high"] > 0 or exposure_score >= 40:
        grade = "high"
    elif by_sev["medium"] > 0 or exposure_score >= 15:
        grade = "medium"
    else:
        grade = "low"

    findings.sort(key=lambda x: (-x["priority"], -SEV_RANK[x["severity"]]))
    summary = {
        "domain": cfg["domain"], "generated_at": _now_iso(),
        "shodan_source": source_label,
        "total_assets": len(all_ips), "origin_assets": len(origin_ips),
        "cdn_excluded": len(all_ips) - len(origin_ips),
        "enriched_assets": len(external),
        "coverage": cov, "by_severity": by_sev,
        "total_findings": len(findings),
        "exposure_score": exposure_score, "grade": grade,
        "providers": providers,
        "top_findings": findings[:20],
        "assets": assets[:500],
        "source_counts": src_counts,
    }
    return assets, findings, summary


def main():
    ap = argparse.ArgumentParser(description="ARISE Shodan Correlation Engine (Module 22)")
    ap.add_argument("out_dir", help="scan OUTPUT_DIR")
    ap.add_argument("--domain", default="", help="target domain (for labels)")
    ap.add_argument("--no-net", action="store_true", help="disable all external lookups (local-only)")
    args = ap.parse_args()

    out_dir = args.out_dir
    base = os.path.join(out_dir, "22_shodan_correlation")
    raw_dir = os.path.join(base, "shodan_raw")
    os.makedirs(raw_dir, exist_ok=True)

    cfg = {
        "domain": args.domain,
        "api_key": os.environ.get("SHODAN_API_KEY", "").strip(),
        "internetdb": os.environ.get("SHODAN_INTERNETDB", "true").lower() != "false",
        "no_net": args.no_net or os.environ.get("SHODAN_CORR_NO_NET", "").lower() == "true",
        "max_ips": int(os.environ.get("SHODAN_CORR_MAX_IPS", "256")),
        "timeout": float(os.environ.get("SHODAN_CORR_TIMEOUT", "6")),
        "workers": int(os.environ.get("SHODAN_CORR_WORKERS", "10")),
        "budget": float(os.environ.get("SHODAN_CORR_BUDGET", "120")),
    }

    logf = open(os.path.join(base, "shodan_correlation.log"), "a")
    _log(logf, "=== Shodan Correlation start (domain=%s, no_net=%s, api_key=%s) ===" % (
        cfg["domain"] or "?", cfg["no_net"], "set" if cfg["api_key"] else "unset"))

    try:
        obs = load_observed(out_dir, logf)
        assets, findings, summary = correlate(obs, cfg, raw_dir, logf)
    except Exception as e:
        _log(logf, "FATAL (handled): %s" % e)
        # still emit an empty-but-valid summary so the dashboard/pipeline never break
        assets, findings = [], []
        summary = {"domain": cfg["domain"], "generated_at": _now_iso(),
                   "shodan_source": "error", "total_assets": 0, "origin_assets": 0,
                   "cdn_excluded": 0, "enriched_assets": 0,
                   "coverage": {}, "by_severity": {}, "total_findings": 0,
                   "exposure_score": 0, "grade": "low", "providers": {},
                   "top_findings": [], "assets": [], "error": str(e)}

    with open(os.path.join(base, "shodan_findings.jsonl"), "w") as f:
        for fx in findings:
            f.write(json.dumps(fx) + "\n")
    with open(os.path.join(base, "shodan_assets.jsonl"), "w") as f:
        for a in assets:
            f.write(json.dumps(a) + "\n")
    with open(os.path.join(base, "shodan_summary.json"), "w") as f:
        json.dump(summary, f, indent=1)

    _log(logf, "=== done: %d assets, %d findings, score=%s (%s), source=%s ===" % (
        len(assets), len(findings), summary.get("exposure_score"),
        summary.get("grade"), summary.get("shodan_source")))
    logf.close()

    # Human-friendly one-liner on stdout for the pipeline log
    print("shodan_correlation: assets=%d origin=%d enriched=%d findings=%d score=%s source=%s" % (
        summary.get("total_assets", 0), summary.get("origin_assets", 0),
        summary.get("enriched_assets", 0), summary.get("total_findings", 0),
        summary.get("exposure_score", 0), summary.get("shodan_source", "?")))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as e:  # last-resort guard — never fail the pipeline
        print("shodan_correlation: fatal (ignored): %s" % e, file=sys.stderr)
        sys.exit(0)
