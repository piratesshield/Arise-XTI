#!/usr/bin/env python3
"""
HTTP Request Smuggling — Safe Indicator Detection (Module 8C)
============================================================
EASM-safe HRS surface assessment. This module NEVER attempts desynchronisation
or exploitation. It fingerprints the HTTP stack, runs only low-impact,
well-formed differential requests, and scores the likelihood that front-end and
back-end components disagree on request parsing. Output is an INDICATOR with a
"manual verification recommended" band — never a proof of vulnerability.

What it does (all safe):
  * Fingerprint via httpx: HTTP/2 support, HTTP/1.1 pipelining, CDN/WAF, web
    server, tech stack.  (falls back to Python probes if httpx absent)
  * Collect intermediary evidence from response headers (Via, X-Forwarded-*,
    X-Cache/X-Served-By, CF-Ray, X-Amz-Cf-Id, LB cookies, Server banners).
  * Identify architecture layers: CDN / WAF / reverse-proxy / load-balancer /
    API-gateway.
  * HTTP/2 downgrade indicator (h2 at the edge + an intermediary that typically
    speaks h1 to the origin).
  * Differential on IDENTICAL, well-formed requests (status / length / header
    variance) -> multiple parsers / inconsistent handling.
  * Connection-reuse / keep-alive consistency.
  * Score per the standard rubric and assign a likelihood band.

What it deliberately does NOT do:
  * No CL.TE / TE.CL ambiguous requests, no malformed chunking, no partial
    requests, no smuggled prefixes. Nothing that could desync a shared proxy or
    affect other users. Those require a controlled environment + human sign-off.
"""

from __future__ import annotations

import sys as _sys, os as _os
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)


import argparse
import concurrent.futures
import http.client
import json
import re
import shutil
import socket
import ssl
import statistics
import subprocess
import sys
import time
import urllib.parse
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple


def log(msg: str) -> None:
    print(f"[hrs] {msg}", file=sys.stderr, flush=True)


_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode = ssl.CERT_NONE
HTTPX = shutil.which("httpx")

# --- rubric weights (exactly as specified) --------------------------------- #
SCORE = {
    "cdn": 5,
    "reverse_proxy": 10,
    "waf": 5,
    "http2_downgrade": 20,
    "multiple_parsers": 20,
    "timeout_differential": 15,
    "status_differential": 15,
    "header_differential": 10,
    "connection_reuse_anomaly": 15,
    "error_pattern_difference": 10,
}

# --- intermediary fingerprint signatures (response headers, lowercased) ---- #
REVERSE_PROXY_SIGS = {
    "nginx": r"nginx|openresty",
    "haproxy": r"haproxy",
    "envoy": r"envoy|x-envoy",
    "apache": r"apache|httpd",
    "iis": r"microsoft-iis|iis",
    "traefik": r"traefik",
    "kong": r"kong",
    "varnish": r"varnish|x-varnish",
    "squid": r"squid",
}
# NOTE: signatures are intentionally SPECIFIC header/cookie tokens, not bare
# vendor names, so a stray "azure"/"google" substring can't create a phantom
# intermediary.
LOAD_BALANCER_SIGS = {
    "aws-alb/elb": r"\bawselb\b|\bawsalb\b|x-amzn-trace-id",
    "f5-big-ip": r"bigipserver|\bbig-ip\b|x-f5-",
    "citrix-netscaler": r"\bnetscaler\b|\bns_af=|citrix-ns",
    "gcp-lb": r"\bgfe\b|via:\s*1\.1\s*google",
    "azure-lb": r"x-azure-ref\b",
}
API_GATEWAY_SIGS = {
    "aws-api-gw": r"x-amzn-requestid|x-amz-apigw-id",
    "kong-gw": r"\bx-kong\b|x-kong-",
    "apigee": r"x-apigee",
    "tyk": r"x-tyk",
    "azure-apim": r"apim-request-id",
}
WAF_HEADER_SIGS = r"cf-ray|x-sucuri|incap_ses|x-iinfo|x-datadome|" \
    r"x-sigsci|imperva|barracuda|fortiwaf|wallarm|x-sp-waf|\bx-waf\b"
# Specific CDN header/cookie tokens (fallback when httpx -cdn misses one).
CDN_HEADER_SIGS = {
    "cloudflare": r"\bcf-ray\b|cf-cache-status",
    "fastly": r"x-served-by|x-fastly|\bfastly\b",
    "akamai": r"x-akamai|akamai-|\bx-akamai-transformed\b",
    "cloudfront": r"x-amz-cf-id|x-amz-cf-pop|\bcloudfront\b",
    "google-cloud": r"via:\s*1\.1\s*google",
    "azure-cdn": r"x-azure-ref\b|x-msedge-ref",
}
INTERMEDIARY_HEADERS = ["via", "x-forwarded-for", "x-forwarded-host",
                        "x-forwarded-proto", "x-forwarded-server", "x-cache",
                        "x-served-by", "x-cache-hits", "forwarded",
                        "cf-ray", "x-amz-cf-id", "x-akamai-request-id"]


@dataclass
class HostFinding:
    url: str
    http2: bool = False
    http11_pipeline: bool = False
    alpn: str = ""
    cdn: bool = False
    cdn_name: str = ""
    waf: bool = False
    waf_name: str = ""
    reverse_proxy: List[str] = field(default_factory=list)
    load_balancer: List[str] = field(default_factory=list)
    api_gateway: List[str] = field(default_factory=list)
    webserver: str = ""
    intermediary_headers: List[str] = field(default_factory=list)
    parser_layers: int = 0
    # differential observations
    status_differential: bool = False
    header_differential: bool = False
    length_differential: bool = False
    connection_reuse_anomaly: bool = False
    timeout_differential: bool = False
    http2_downgrade: bool = False
    # scoring
    indicators: List[str] = field(default_factory=list)
    score: int = 0
    band: str = ""
    severity: str = "info"
    evidence: str = ""
    remediation: str = ""


# --------------------------------------------------------------------------- #
# Safe raw requester (well-formed only) with keep-alive support.
# --------------------------------------------------------------------------- #
def _connect(host: str, port: int, scheme: str, timeout: int):
    if scheme == "https":
        return http.client.HTTPSConnection(host, port, timeout=timeout, context=_SSL_CTX)
    return http.client.HTTPConnection(host, port, timeout=timeout)


def _one_get(host: str, port: int, scheme: str, path: str, timeout: int
             ) -> Tuple[Optional[int], Dict[str, str], int, float]:
    """A single well-formed GET. Returns (status, headers, body_len, elapsed)."""
    conn = None
    t0 = time.time()
    try:
        conn = _connect(host, port, scheme, timeout)
        conn.request("GET", path or "/", headers={
            "Host": host, "User-Agent": "ARISE-hrs/1.0", "Accept": "*/*"})
        r = conn.getresponse()
        body = r.read(4096) or b""
        hdrs = {k.lower(): v for k, v in r.getheaders()}
        return r.status, hdrs, len(body), time.time() - t0
    except (http.client.HTTPException, socket.error, ssl.SSLError, OSError):
        return None, {}, 0, time.time() - t0
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass


def _keepalive_probe(host: str, port: int, scheme: str, path: str, timeout: int
                     ) -> Tuple[bool, bool]:
    """Two sequential well-formed GETs on ONE connection. Returns
    (reuse_supported, anomaly). Safe: standard persistent-connection use."""
    conn = None
    try:
        conn = _connect(host, port, scheme, timeout)
        conn.request("GET", path or "/", headers={"Host": host,
                     "User-Agent": "ARISE-hrs/1.0", "Connection": "keep-alive"})
        r1 = conn.getresponse()
        r1.read(1024)
        conn1_hdr = (r1.getheader("Connection") or "").lower()
        # Second request on the same socket.
        try:
            conn.request("GET", path or "/", headers={"Host": host,
                         "User-Agent": "ARISE-hrs/1.0", "Connection": "keep-alive"})
            r2 = conn.getresponse()
            r2.read(1024)
            reused = True
        except Exception:
            reused = False
        # Anomaly: server said keep-alive but dropped the socket, or said close
        # yet accepted a second request.
        anomaly = (("keep-alive" in conn1_hdr and not reused) or
                   ("close" in conn1_hdr and reused))
        return reused, anomaly
    except Exception:
        return False, False
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass


# --------------------------------------------------------------------------- #
def run_httpx(urls: List[str], timeout: int) -> Dict[str, dict]:
    """Batch httpx fingerprint. Returns {input_url: json_obj}."""
    if not HTTPX or not urls:
        return {}
    out: Dict[str, dict] = {}
    try:
        proc = subprocess.run(
            [HTTPX, "-json", "-http2", "-pipeline", "-cdn", "-tech-detect",
             "-server", "-silent", "-timeout", str(timeout), "-threads", "50",
             "-no-color"],
            input="\n".join(urls), capture_output=True, text=True,
            timeout=max(60, timeout * len(urls)))
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except Exception:
                continue
            key = d.get("input") or d.get("url") or ""
            if key:
                out[key] = d
    except Exception as e:
        log(f"httpx fingerprint failed: {e}")
    return out


def detect_layers(headers: Dict[str, str], webserver: str, sigmap: dict) -> List[str]:
    blob = " ".join(f"{k}: {v}" for k, v in headers.items()).lower() + " " + webserver.lower()
    found = []
    for name, pat in sigmap.items():
        if re.search(pat, blob, re.I):
            found.append(name)
    return found


class HRSScanner:
    def __init__(self, timeout=8, threads=10, samples=4, waf_map=None):
        self.timeout = timeout
        self.threads = threads
        self.samples = max(3, samples)
        self.waf_map = waf_map or {}       # url/host -> waf vendor (from pipeline)
        self.httpx: Dict[str, dict] = {}

    def _score(self, f: HostFinding) -> None:
        ind = []
        if f.cdn:
            ind.append("cdn")
        if f.reverse_proxy:
            ind.append("reverse_proxy")
        if f.waf:
            ind.append("waf")
        if f.http2_downgrade:
            ind.append("http2_downgrade")
        if f.parser_layers >= 2:
            ind.append("multiple_parsers")
        if f.status_differential:
            ind.append("status_differential")
        if f.header_differential:
            ind.append("header_differential")
        if f.connection_reuse_anomaly:
            ind.append("connection_reuse_anomaly")
        if f.timeout_differential:
            ind.append("timeout_differential")
        f.indicators = ind
        f.score = sum(SCORE[i] for i in ind)
        if f.score <= 20:
            f.band, f.severity = "low_likelihood", "info"
        elif f.score <= 40:
            f.band, f.severity = "possible", "low"
        elif f.score <= 60:
            f.band, f.severity = "moderate_manual_verify", "medium"
        else:
            f.band, f.severity = "high_manual_verify", "medium"

    def scan_host(self, url: str) -> Optional[HostFinding]:
        u = urllib.parse.urlsplit(url)
        if not u.hostname:
            return None
        scheme = u.scheme or "https"
        port = u.port or (443 if scheme == "https" else 80)
        path = u.path or "/"
        host = u.hostname
        f = HostFinding(url=url)

        # ---- httpx fingerprint (protocol/cdn/tech) ----
        hx = self.httpx.get(url) or self.httpx.get(f"{scheme}://{host}") or {}
        f.http2 = bool(hx.get("http2"))
        f.http11_pipeline = bool(hx.get("pipeline"))
        f.cdn = bool(hx.get("cdn"))
        f.cdn_name = hx.get("cdn_name", "") or ""
        if (hx.get("cdn_type") or "").lower() == "waf":
            f.waf, f.waf_name = True, f.cdn_name
        f.webserver = hx.get("webserver", "") or ""

        # ---- baseline GET + header-based intermediary detection ----
        samples = [_one_get(host, port, scheme, path, self.timeout)
                   for _ in range(self.samples)]
        oks = [s for s in samples if s[0] is not None]
        if not oks:
            return None  # host unreachable now
        statuses = {s[0] for s in oks}
        lengths = {s[2] for s in oks}
        base_headers = oks[0][1]

        f.reverse_proxy = detect_layers(base_headers, f.webserver, REVERSE_PROXY_SIGS)
        f.load_balancer = detect_layers(base_headers, f.webserver, LOAD_BALANCER_SIGS)
        f.api_gateway = detect_layers(base_headers, f.webserver, API_GATEWAY_SIGS)
        # CDN header fallback (httpx -cdn can miss Fastly/Akamai on some hosts)
        if not f.cdn:
            cdn_hits = detect_layers(base_headers, f.webserver, CDN_HEADER_SIGS)
            if cdn_hits:
                f.cdn, f.cdn_name = True, f.cdn_name or cdn_hits[0]
        if re.search(WAF_HEADER_SIGS, " ".join(f"{k}:{v}" for k, v in base_headers.items()), re.I):
            f.waf = True
        # pipeline / manifest-supplied WAF vendor
        wv = self.waf_map.get(url) or self.waf_map.get(host) or ""
        if wv and wv.lower() not in ("none", "", "unknown"):
            f.waf, f.waf_name = True, f.waf_name or wv
        f.intermediary_headers = [h for h in INTERMEDIARY_HEADERS if h in base_headers]

        # ---- architecture layer count (DISTINCT HTTP-parsing hops) ----
        # Collapse same-vendor CDN+WAF (e.g. Cloudflare does both at one hop) so
        # a single provider is not miscounted as two parsers.
        layer_tokens = set()
        if f.cdn:
            layer_tokens.add("edge:" + (f.cdn_name or "cdn").lower())
        if f.waf:
            wn = (f.waf_name or "waf").lower()
            # same vendor as the CDN -> same hop, don't add a second token
            if not (f.cdn and wn == (f.cdn_name or "cdn").lower()):
                layer_tokens.add("waf:" + wn)
        for rp in f.reverse_proxy:
            layer_tokens.add("rp:" + rp)
        for lb in f.load_balancer:
            layer_tokens.add("lb:" + lb)
        for gw in f.api_gateway:
            layer_tokens.add("gw:" + gw)
        f.parser_layers = len(layer_tokens)

        # ---- HTTP/2 downgrade indicator ----
        # h2 negotiated at the edge + an intermediary that typically speaks h1
        # to the origin (CDN / reverse-proxy / LB) => translation layer present.
        f.http2_downgrade = bool(f.http2 and (f.cdn or f.reverse_proxy or f.load_balancer))

        # ---- differential on identical, well-formed requests ----
        f.status_differential = len(statuses) > 1
        f.length_differential = len(lengths) > 1
        # header differential: compare a routing-relevant header subset
        hdr_sets = []
        for s in oks:
            hd = s[1]
            sig = tuple(sorted((k, hd.get(k, "")) for k in
                        ("server", "via", "x-cache", "connection", "content-length")))
            hdr_sets.append(sig)
        f.header_differential = len(set(hdr_sets)) > 1

        # ---- timing differential (medium, still only well-formed GETs) ----
        times = [s[3] for s in oks]
        if len(times) >= 3:
            try:
                mean = statistics.mean(times)
                sd = statistics.pstdev(times)
                # High relative variance across identical requests can indicate
                # different backends / a translation layer.
                f.timeout_differential = mean > 0 and (sd / mean) > 0.75 and max(times) > 2.0
            except statistics.StatisticsError:
                pass

        # ---- connection reuse / keep-alive consistency ----
        # Require the anomaly to REPRODUCE (2 of 2) so a single flaky edge close
        # doesn't score +15.
        a1 = _keepalive_probe(host, port, scheme, path, self.timeout)[1]
        f.connection_reuse_anomaly = bool(
            a1 and _keepalive_probe(host, port, scheme, path, self.timeout)[1])

        self._score(f)

        arch = " -> ".join(x for x in [
            "CDN(%s)" % f.cdn_name if f.cdn else "",
            "WAF(%s)" % (f.waf_name or "yes") if f.waf else "",
            "LB(%s)" % ",".join(f.load_balancer) if f.load_balancer else "",
            "RP(%s)" % ",".join(f.reverse_proxy) if f.reverse_proxy else "",
            "GW(%s)" % ",".join(f.api_gateway) if f.api_gateway else "",
            "server(%s)" % f.webserver if f.webserver else "",
        ] if x) or "single-layer / undetected"
        f.evidence = (
            f"HRS-surface score {f.score} ({f.band}). Stack: {arch}. "
            f"HTTP/2={f.http2}, pipelining={f.http11_pipeline}, "
            f"parser-layers={f.parser_layers}. "
            f"Indicators: {', '.join(f.indicators) or 'none'}. "
            "These are architecture indicators, NOT proof of a smuggling "
            "vulnerability.")
        if f.score <= 20:
            f.remediation = ("Low HRS surface. No action needed beyond keeping "
                             "intermediaries patched.")
        else:
            f.remediation = (
                "Multiple HTTP-aware layers / parser indicators detected. "
                "Recommend MANUAL verification in a CONTROLLED environment "
                "(e.g. Burp HTTP Request Smuggler, or a staging replica) to "
                "confirm front-end/back-end parsing agreement. Ensure all "
                "intermediaries share one HTTP parser policy: reject ambiguous "
                "Content-Length/Transfer-Encoding, normalise before forwarding, "
                "and prefer end-to-end HTTP/2 or a single downgrade point.")
        return f

    def run(self, urls: List[str]) -> List[HostFinding]:
        self.httpx = run_httpx(urls, self.timeout)
        findings: List[HostFinding] = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            for res in ex.map(self.scan_host, urls):
                if res:
                    findings.append(res)
        return findings


def _load_urls(paths: List[str], max_hosts: int) -> List[str]:
    urls, seen = [], set()
    for path in paths:
        p = Path(path)
        if not p.exists():
            continue
        for line in p.read_text(errors="ignore").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # accept plain URLs or httpx json lines
            if line.startswith("{"):
                try:
                    line = json.loads(line).get("url", "")
                except Exception:
                    continue
            if not line.startswith("http"):
                line = "https://" + line
            u = urllib.parse.urlsplit(line)
            key = f"{u.scheme}://{u.netloc}{u.path or ''}"
            if u.netloc and key not in seen:
                seen.add(key)
                urls.append(key)
    return urls[:max_hosts]


def _load_waf_map(manifest: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if not manifest or not Path(manifest).exists():
        return out
    try:
        j = json.loads(Path(manifest).read_text())
        hosts = j.get("hosts", {}) or {}
        for host, meta in hosts.items():
            wv = (meta or {}).get("waf_vendor")
            if wv:
                out[host] = wv
    except Exception:
        pass
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="Safe HRS indicator detection (Module 8C)")
    ap.add_argument("--input", action="append", required=True,
                    help="URL list or httpx json (repeatable)")
    ap.add_argument("--output", required=True)
    ap.add_argument("--manifest", default="", help="scan manifest for WAF vendor reuse")
    ap.add_argument("--timeout", type=int, default=8)
    ap.add_argument("--threads", type=int, default=10)
    ap.add_argument("--samples", type=int, default=4)
    ap.add_argument("--max-hosts", type=int, default=150)
    args = ap.parse_args()

    urls = _load_urls(args.input, args.max_hosts)
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    if not urls:
        log("no URLs to assess")
        Path(args.output).write_text("")
        return 0

    log(f"assessing HRS surface on {len(urls)} hosts "
        f"(httpx={'yes' if HTTPX else 'no — python fallback'})")
    scanner = HRSScanner(timeout=args.timeout, threads=args.threads,
                         samples=args.samples, waf_map=_load_waf_map(args.manifest))
    findings = scanner.run(urls)
    findings.sort(key=lambda x: -x.score)

    bands: Dict[str, int] = {}
    with open(args.output, "w") as fh:
        for f in findings:
            fh.write(json.dumps(asdict(f)) + "\n")
            bands[f.band] = bands.get(f.band, 0) + 1
    (Path(args.output).parent / "hrs_summary.json").write_text(json.dumps({
        "module": "hrs_detect", "assessed": len(findings),
        "by_band": bands,
        "manual_verify_recommended": sum(1 for f in findings if f.score > 40),
    }, indent=2))
    log(f"done: {len(findings)} assessed -> {args.output}")
    for f in findings[:10]:
        log(f"  [{f.score:3} {f.band}] {f.url}  ({', '.join(f.indicators) or 'no indicators'})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
