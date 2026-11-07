#!/usr/bin/env python3
"""
ARISE API Intelligence Engine
==============================
Resolves the root cause of 0 API security findings:
  - Collects every endpoint already discovered by prior pipeline modules
  - Probes HTTP methods, detects auth requirements, expands with action wordlists
  - Classifies vulnerabilities deterministically (no AI required)
  - Writes api_findings.jsonl in the exact format the dashboard reads

Usage (called from easm-pipeline.sh):
  python3 api_intelligence_engine.py <scan_output_dir> [--rate N] [--timeout N] [--threads N]

Falls back gracefully if any tool (ffuf, nuclei) is missing.
"""

from __future__ import annotations

import sys as _sys, os as _os
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)


import argparse
import concurrent.futures
import hashlib
import json
import logging
import os
import random
import re
import signal
import subprocess
import sys
import threading
import time
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import urllib.request
import urllib.error
import ssl

# Shared URL-classification primitives (single source of truth, also imported
# by endpoint_consolidator.py / Module 8B). Keeping these in one module stops
# the consolidator and the engine from drifting apart on what counts as an API,
# a static asset, a sensitive path, an identifier segment, etc.
from discovery.url_classify import (  # noqa: E402
    API_PATH_RE,
    SENSITIVE_PATH_RE,
    AUTH_PATH_RE,
    STATIC_ASSET_RE,
    STATIC_CONTENT_TYPE_RE,
    API_CONTENT_TYPE_RE,
    _JSON_BODY_RE,
    _XML_BODY_RE,
    _UUID_RE,
    ID_SEGMENT_RE,
    _is_id_segment,
    JWT_RE,
    _SWAGGER_PATH_RE,
    _GRAPHQL_PATH_RE,
    _GRAPHQL_BODY_RE,
    _SOAP_BODY_RE,
    _JSONRPC_BODY_RE,
    _ODATA_RE,
    api_flavour as _shared_api_flavour,
)

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    format="[%(levelname)s] %(message)s",
    level=logging.INFO,
    stream=sys.stderr,
)
log = logging.getLogger("arise.api_intel")


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# API_PATH_RE, SENSITIVE_PATH_RE, AUTH_PATH_RE, STATIC_ASSET_RE,
# STATIC_CONTENT_TYPE_RE and API_CONTENT_TYPE_RE now live in url_classify.py
# (imported above) so Module 8B classifies identically.

# Domains belonging to security tooling infrastructure — never scan targets.
# Nuclei template-url fields, scanner update checks, telemetry, etc.
TOOL_INFRA_DOMAINS = {
    "projectdiscovery.io", "cloud.projectdiscovery.io",
    "interact.sh", "oast.pro", "oast.live", "oast.site",
    "oast.online", "oast.fun", "oast.me",
    "burpcollaborator.net",
    "canarytokens.com",
    "webhook.site",
    "pipedream.net",
    "requestbin.com", "requestbin.net",
    "hookbin.com",
    "beeceptor.com",
    "ngrok.io", "ngrok-free.app",
}

# Hosts that are cloud storage (not web APIs) — exclude from API surface
S3_HOST_RE = re.compile(
    r"(?i)(\.s3[.-]|\.s3\.amazonaws\.com|\.blob\.core\.windows\.net"
    r"|\.storage\.googleapis\.com|\.r2\.cloudflarestorage\.com"
    r"|\.digitaloceanspaces\.com|\.backblazeb2\.com"
    r"|s3-website|s3\.us-|s3\.eu-|s3\.ap-)",
)

_CDN_INFRA_PATH_RE = re.compile(
    r"(?:^|/)(?:cdn-cgi|__cf_|_cf_chl|challenge-platform|"
    r"_bx_html|akamai|_Incapsula_Resource)", re.I)


def _is_cdn_infra_url(url: str) -> bool:
    try:
        return bool(_CDN_INFRA_PATH_RE.search(urllib.parse.urlsplit(url).path))
    except Exception:
        return False


# Body-level auth-failure indicators: servers that return HTTP 200 but the
# JSON/text payload says the request was actually rejected.  Matching any of
# these means the endpoint is NOT truly "accessible unauthenticated".
AUTH_FAILURE_BODY_RE = re.compile(
    r"(?i)"
    r"(\"statusMessage\"\s*:\s*\"[Aa]uthentication\s+failed\")"
    r"|(\"message\"\s*:\s*\"[Uu]nauthori[sz]ed\")"
    r"|(\"error\"\s*:\s*\"[Uu]nauthori[sz]ed\")"
    r"|(\"error\"\s*:\s*\"[Aa]uthentication\s+(?:failed|required)\")"
    r"|(\"status\"\s*:\s*\"(?:UNAUTHENTICATED|UNAUTHORIZED|AUTH_FAILED)\")"
    r"|(\"authenticated\"\s*:\s*false)"
    r"|(\"isAuthenticated\"\s*:\s*false)"
    r"|(\"loggedIn\"\s*:\s*false)"
    r"|(\"success\"\s*:\s*false\b[^}]*\"(?:auth|login|token))"
    r"|(\bAccess\s+Denied\b)"
    r"|(\bForbidden\b.*\b(?:token|auth|login|session)\b)"
    r"|(\bInvalid\s+(?:token|session|credentials|api.?key)\b)"
    r"|(\btoken\s+(?:expired|invalid|required|missing)\b)"
    r"|(\bsession\s+(?:expired|invalid|required)\b)"
    r"|(\brequires?\s+authentication\b)"
    r"|(\bnot\s+logged\s+in\b)"
    r"|(\bplease\s+(?:log\s*in|sign\s*in|authenticate)\b)",
)

# Front-end/static assets are usually NOT API endpoints, and method-probing a
# webpack JS bundle / stylesheet / font / image (OPTIONS/PUT/DELETE/... ×N) is
# waste that manufactures phantom "method oracle"/"dangerous methods" findings.
# BUT a path ending .js/.css is only a *candidate* — it can still be a dynamic
# route (JSONP `?callback=`, a handler that returns JSON, an SPA catch-all).
# So the extension merely FLAGS a URL for verification; the actual exclusion is
# decided by verify_static_asset() from the server's real Content-Type.
# .json/.xml are never flagged — they are commonly real API responses/specs.
# STATIC_ASSET_RE and STATIC_CONTENT_TYPE_RE are imported from url_classify.

# Response Content-Types that POSITIVELY identify an API (machine) response, as
# opposed to a rendered web page (text/html). This is the pre-validation gate:
# an endpoint is only attacked as an API when the SERVER's own Content-Type (or,
# failing that, a JSON/XML body) says it is one. Path shape (/api/, /v1/…) is no
# longer sufficient on its own — that is what caused HTML pages at /api/* URLs to
# be flagged as broken-auth/BOLA false positives.
#   application/json, +json variants (problem+json, hal+json, vnd.api+json, ld+json)
#   application/xml, text/xml, +xml variants (SOAP)
#   application/x-ndjson (streamed JSON)          text/event-stream (SSE)
#   application/grpc, protobuf, x-protobuf        (gRPC / internal binary APIs)
#   application/octet-stream, pdf, zip, csv       (file/report/export APIs — real
#                                                  BOLA targets like /invoices/{id})
# Intentionally EXCLUDES image/* and font/video/audio: those are UI assets, and
# treating them as APIs would re-introduce the very false positives we remove
# (a public logo is not "broken authentication").
# API_CONTENT_TYPE_RE, the body-sniff regexes (_JSON_BODY_RE / _XML_BODY_RE) and
# _UUID_RE are imported from url_classify (single source of truth).

# ---------------------------------------------------------------------------
# Phase 1.6 — scope filter + URL-template similarity collapse
#
# Large crawls surface many URLs that are the SAME endpoint shape with a
# different instance value in one path segment — option-chain style codes
# (nse_crudeoil26aug7150pe vs ...7200ce), dates, numeric IDs, hex/UUID
# tokens. Testing every instance wastes scan time for zero extra coverage,
# so these are collapsed to one representative per template before the
# filter/probe phases and the apisec.py adapter (Phase 9) ever see them. This
# never drops a URL for failing/erroring — that's a runtime probe outcome
# decided later in Phases 3-9, unrelated to this dedup step.
# ---------------------------------------------------------------------------
_DIGITS_RE = re.compile(r"^\d+$")
_HEX_TOKEN_RE = re.compile(r"^[0-9a-fA-F]{8,}$")
_MIXED_ID_RE = re.compile(r"^(?=.*\d)[0-9A-Za-z_-]{8,}$")


def _normalize_path_segment(seg: str) -> str:
    """Map an instance-level path segment to a template placeholder;
    leave static path components (route names) untouched."""
    if not seg:
        return seg
    if _UUID_RE.match(seg):
        return "{uuid}"
    if _DIGITS_RE.match(seg):
        return "{num}"
    if _HEX_TOKEN_RE.match(seg):
        return "{hex}"
    if _MIXED_ID_RE.match(seg):
        return "{id}"
    return seg


def _url_in_scope(url: str, root_domain: str) -> bool:
    """True if url's host is the target root domain or one of its subdomains."""
    try:
        host = urllib.parse.urlparse(url).netloc.split(":")[0].lower()
    except Exception:
        return False
    return host == root_domain or host.endswith("." + root_domain)


def _reduce_similar_urls(urls: List[str]) -> List[str]:
    """Collapse URLs sharing the same host + normalized-path + query-key
    template down to one representative (the shortest URL in the group,
    treated as the canonical instance). Distinct path shapes and distinct
    query-key sets are never merged."""
    templates: Dict[Tuple[str, str, str], str] = {}
    for url in urls:
        try:
            parsed = urllib.parse.urlparse(url)
            path_template = "/".join(_normalize_path_segment(s) for s in parsed.path.split("/"))
            query_keys = ",".join(sorted(urllib.parse.parse_qs(parsed.query).keys()))
            key = (parsed.netloc.lower(), path_template, query_keys)
        except Exception:
            key = (url, "", "")
        if key not in templates or len(url) < len(templates[key]):
            templates[key] = url
    return list(templates.values())


def _infer_param_schema(value: str) -> Dict:
    """Infer an OpenAPI schema from a real discovered value, and carry the value
    itself as `example` so spec-driven tools replay the actual data EASM observed
    instead of generating a blank random string."""
    v = (value or "").strip()
    if v.isdigit():
        return {"type": "integer", "example": int(v)}
    if _UUID_RE.match(v):
        return {"type": "string", "format": "uuid", "example": v}
    if re.fullmatch(r"-?\d+\.\d+", v):
        return {"type": "number", "example": float(v)}
    if v.lower() in ("true", "false"):
        return {"type": "boolean", "example": v.lower() == "true"}
    schema = {"type": "string"}
    if v:
        schema["example"] = v
    return schema


def is_static_asset(url: str) -> bool:
    """True if the URL path *looks like* a front-end static asset by extension.
    This only FLAGS a candidate — call verify_static_asset() to confirm before
    excluding anything."""
    try:
        path = urllib.parse.urlparse(url).path
    except Exception:
        return False
    return bool(STATIC_ASSET_RE.search(path))


def verify_static_asset(url: str, probe: "HTTPProbe") -> Optional[bool]:
    """Confirm via HTTP whether an extension-flagged URL is TRULY a static asset.

    Returns:
        True  -> server returned a static Content-Type -> safe to EXCLUDE.
        False -> behaves like a dynamic/API response (JSON/HTML/XML, or an
                 auth-gated 401/403) -> KEEP it in the API surface.
        None  -> inconclusive (network error/timeout) -> KEEP (never drop an
                 unverified URL).
    HEAD first (cheap); fall back to GET if HEAD is refused or carries no type.
    """
    res = probe._request("HEAD", url)
    ct = ""
    if res is not None:
        ct = res[1].get("Content-Type") or res[1].get("content-type") or ""
    # HEAD refused / no content-type -> confirm with a small GET
    if res is None or res[0] in (405, 501) or not ct:
        res = probe._request("GET", url)
        if res is not None:
            ct = res[1].get("Content-Type") or res[1].get("content-type") or ""
    if res is None:
        return None  # inconclusive -> keep
    status = res[0]
    # Auth-gated asset path is likely a real protected endpoint -> keep.
    if status in (401, 403):
        return False
    # Only a successful fetch lets us trust the Content-Type.
    if status in (200, 206, 304) and STATIC_CONTENT_TYPE_RE.match(ct or ""):
        return True
    return False if ct else None

# ID_SEGMENT_RE and JWT_RE are imported from url_classify.

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

# SecLists-style action wordlist (built-in subset; engine also loads external file if present)
BUILTIN_ACTIONS = [
    "login", "logout", "register", "signup", "signin",
    "forgot-password", "reset-password", "verify", "confirm",
    "refresh", "token", "revoke", "validate",
    "create", "update", "delete", "remove", "add", "edit", "list",
    "search", "filter", "export", "import", "upload", "download",
    "status", "health", "ping", "metrics", "info", "version",
    "users", "user", "profile", "account", "accounts",
    "admin", "admins", "roles", "permissions", "groups",
    "orders", "order", "cart", "checkout", "payment", "payments",
    "products", "product", "catalog", "inventory",
    "notifications", "notification", "alerts", "messages",
    "settings", "config", "configuration", "preferences",
    "reports", "report", "analytics", "stats", "statistics",
    "audit", "logs", "events", "history",
    "debug", "test", "internal", "private", "secret",
    "graphql", "query", "mutation", "subscription",
    "webhook", "callback", "notify",
    "v1", "v2", "v3", "api", "rest",
]

INTERESTING_STATUS = {200, 201, 204, 301, 302, 400, 401, 403, 405, 422, 500}

# High-confidence sensitivity keywords, trusted on their own (subset of
# SENSITIVE_PATH_RE — see the sensitive_endpoint_exposed FP fix, F34 in
# ARISE_REMEDIATION_ROADMAP.md).
_STRONG_SENSITIVE_RE = re.compile(
    r"(/admin|/internal|/debug|/config|/settings|/manage|/console"
    r"|/panel|/backdoor|/secret|/backup|/dump)", re.IGNORECASE)
# A file-extension-suffixed path is shaped like a public asset download
# (report.pdf, animation.json, export.csv) rather than a REST resource.
_STATIC_ASSET_EXT_RE = re.compile(
    r"\.(?:json|csv|xlsx?|docx?|zip|tar|gz|txt)(?:$|\?)", re.IGNORECASE)

# Template tokens in a discovery/js_param_miner.py URL template
# ("/api/users/{id}", "/api/users/${id}", "/api/users/:id") — substituted
# with a placeholder to make the template concretely probe-able.
_TEMPLATE_TOKEN_RE = re.compile(
    r"\$\{[^}]+\}|\{[A-Za-z_][A-Za-z0-9_]{0,29}\}|:[A-Za-z_][A-Za-z0-9_]{0,29}")

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class Endpoint:
    url: str
    host: str = ""
    path: str = ""
    method: str = "GET"
    status_code: Optional[int] = None
    response_length: int = 0
    content_type: str = ""
    auth_required: bool = False
    accessible_unauthenticated: bool = False
    has_id_param: bool = False
    is_sensitive: bool = False
    is_auth_endpoint: bool = False
    source: str = ""
    response_snippet: str = ""
    query_params: Dict[str, str] = None
    response_headers: Dict[str, str] = None
    allow_methods: str = ""          # from an OPTIONS Allow: header, if probed
    url_type: str = ""               # API | WEBSITE | UNKNOWN (13-step tree)
    api_type: str = ""               # rest-json | graphql | soap | grpc | … (when API)

    def __post_init__(self):
        parsed = urllib.parse.urlparse(self.url)
        self.host = self.host or parsed.netloc.split(":")[0]
        self.path = self.path or parsed.path or "/"
        if self.query_params is None:
            self.query_params = dict(urllib.parse.parse_qsl(parsed.query or ""))
        # F08 (ARISE_REMEDIATION_ROADMAP.md): ID_SEGMENT_RE's bare
        # [A-Za-z0-9_-]{20,} matched any long kebab-case slug — a REST verb
        # path ("get-pending-approvals", 21 chars) or a public RFC 8414
        # discovery endpoint ("oauth-authorization-server") both satisfied
        # it, driving false BOLA/BFLA findings on paths with no object
        # reference at all. _is_id_segment() (discovery/url_classify.py)
        # requires an actual digit for the opaque-token case — a real
        # identifier almost always has one; a human-readable action/slug
        # almost never does.
        self.has_id_param = bool(
            any(_is_id_segment(seg) for seg in self.path.split("/") if seg)
            or re.search(r"\{[^}]+\}", self.path)
            or re.search(r"=[0-9]+(&|$)", parsed.query or "")
        )
        self.is_sensitive = bool(SENSITIVE_PATH_RE.search(self.path))
        self.is_auth_endpoint = bool(AUTH_PATH_RE.search(self.path))


@dataclass
class Finding:
    method: str
    path: str
    host: str
    issue_class: str
    category: str
    severity: str
    tool: str
    evidence: str
    status_code: Optional[int] = None
    remediation: str = ""
    endpoint: str = ""
    tools: List[str] = field(default_factory=list)

    def __post_init__(self):
        if not self.endpoint:
            self.endpoint = f"{self.method} {self.path}"
        if not self.tools:
            self.tools = [self.tool]

    def dedup_key(self) -> str:
        return hashlib.md5(
            f"{self.method}|{self.template_path()}|{self.issue_class}".encode()
        ).hexdigest()

    def template_path(self) -> str:
        """Collapse concrete IDs so /users/123 and /users/456 deduplicate."""
        parts = []
        for seg in self.path.split("/"):
            parts.append("{id}" if seg and _is_id_segment(seg) else seg)
        return "/".join(parts)

    def to_jsonl(self) -> str:
        return json.dumps({
            "method": self.method,
            "path": self.template_path(),
            "host": self.host,
            "endpoint": f"{self.method} {self.template_path()}",
            "issue_class": self.issue_class,
            "category": self.category,
            "severity": self.severity,
            "tool": self.tool,
            "tools": self.tools,
            "evidence": self.evidence[:500],
            "status_code": self.status_code,
            "remediation": self.remediation,
        })


# ---------------------------------------------------------------------------
# Phase 1 — Endpoint collection from all prior pipeline outputs
# ---------------------------------------------------------------------------

class EndpointCollector:
    """Reads every URL source the pipeline already produced."""

    def __init__(self, scan_dir: Path):
        self.scan_dir = scan_dir

    def collect(self) -> List[str]:
        urls: Set[str] = set()

        sources = [
            self.scan_dir / "09_crawling" / "all_urls.txt",
            self.scan_dir / "08_directory_discovery" / "all_paths.txt",
            self.scan_dir / "08_directory_discovery" / "urls_for_dirsearch.txt",
            self.scan_dir / "04_http_discovery" / "http_urls.txt",
            self.scan_dir / "01_asset_discovery" / "gau_urls.txt",
            self.scan_dir / "11_param_fuzzing" / "urls_with_params.txt",
            # Module 20 (API Deep Discovery, ARISEv3) — headless-intercepted XHR/fetch
            # API calls and classified injectable targets. These are the highest-value
            # endpoints (real runtime API traffic) and are NOT all merged into
            # 09_crawling/all_urls.txt, so pull them explicitly.
            self.scan_dir / "20_api_deep_discovery" / "xhr_intercepted.txt",
            self.scan_dir / "20_api_deep_discovery" / "katana_headless_urls.txt",
            self.scan_dir / "20_api_deep_discovery" / "injection_targets.txt",
            self.scan_dir / "20_api_deep_discovery" / "sqli_targets.txt",
        ]

        for f in sources:
            if f.exists():
                found_in_file = 0
                for line in f.read_text(errors="ignore").splitlines():
                    line = line.strip()
                    if line and line.startswith("http"):
                        urls.add(line.split()[0])  # strip trailing whitespace/columns
                        found_in_file += 1
                log.info("Collected from %s: %d URLs (running total %d)", f.name,
                         found_in_file, len(urls))

        # JSONL outputs (each line carries a "url" field).
        jsonl_sources = [
            (self.scan_dir / "20_api_deep_discovery", "api_deep_discovery.jsonl"),
            (self.scan_dir / "20_api_deep_discovery", "api_endpoints.jsonl"),
            (self.scan_dir / "08_directory_discovery", "discovered_endpoints.jsonl"),
        ]
        for parent_dir, jsonl_name in jsonl_sources:
            jf = parent_dir / jsonl_name
            if jf.exists():
                added = 0
                for line in jf.read_text(errors="ignore").splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                        # discovered_endpoints.jsonl has "url" (templated, e.g.
                        # /api/{token}/users) and "sample_url" (concrete, probe-able).
                        # Always prefer the concrete URL so probes don't hit {token}.
                        u = rec.get("sample_url") or rec.get("url", "")
                    except Exception:
                        continue
                    if u and u.startswith("http"):
                        urls.add(u)
                        added += 1
                log.info("Collected from %s: %d URLs (running total %d)",
                         jsonl_name, added, len(urls))

        # JS-extracted endpoints
        js_dir = self.scan_dir / "09_crawling" / "js_downloads"
        if js_dir.exists():
            for js_file in js_dir.glob("*.txt"):
                for line in js_file.read_text(errors="ignore").splitlines():
                    line = line.strip()
                    if line.startswith("http"):
                        urls.add(line)

        # discovery/js_param_miner.py's URL path templates (relative paths
        # like "/api/users/{id}" mined from JS but never resolved against a
        # host, so they never reach any URL corpus). Resolve each against
        # every known live host, substituting template tokens with a
        # placeholder — the concrete Endpoint filter/prober downstream
        # already handles a numeric-looking segment fine.
        js_templates_file = self.scan_dir / "09_crawling" / "js_url_templates.txt"
        if js_templates_file.exists():
            http_hosts_file = self.scan_dir / "04_http_discovery" / "http_hosts.txt"
            hosts = [h.strip().rstrip("/") for h in
                     http_hosts_file.read_text(errors="ignore").splitlines()
                     if h.strip().startswith("http")] if http_hosts_file.exists() else []
            added = 0
            for tmpl in js_templates_file.read_text(errors="ignore").splitlines():
                tmpl = tmpl.strip()
                if not tmpl.startswith("/"):
                    continue
                resolved = _TEMPLATE_TOKEN_RE.sub("1", tmpl)
                for host in hosts:
                    urls.add(host + resolved)
                    added += 1
            if added:
                log.info("Collected from js_url_templates.txt: %d URL(s) "
                         "(running total %d)", added, len(urls))

        # Nuclei findings — extract only the matched-at URL (the actual
        # target), NOT template-url (cloud.projectdiscovery.io) or
        # template-path (local filesystem).
        nuclei_file = self.scan_dir / "12_nuclei_scanning" / "nuclei_results.txt"
        if nuclei_file.exists():
            for line in nuclei_file.read_text(errors="ignore").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                    mat = rec.get("matched-at") or rec.get("host") or ""
                    if mat.startswith("http"):
                        urls.add(mat)
                except (json.JSONDecodeError, AttributeError):
                    pass

        # recon/schema_probe.py — confirmed OpenAPI/Swagger spec URLs. High
        # value: a spec at this URL enumerates the real endpoint/param
        # surface directly, no crawling/guessing needed.
        schema_file = self.scan_dir / "04_http_discovery" / "schema_endpoints.jsonl"
        if schema_file.exists():
            added = 0
            for line in schema_file.read_text(errors="ignore").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except Exception:
                    continue
                if rec.get("kind") == "openapi" and str(rec.get("url", "")).startswith("http"):
                    urls.add(rec["url"])
                    added += 1
            if added:
                log.info("Collected from schema_endpoints.jsonl: %d URL(s) "
                         "(running total %d)", added, len(urls))

        # Manifest: pull http URLs of all known API hosts
        manifest_file = self.scan_dir / "manifest.json"
        if manifest_file.exists():
            try:
                manifest = json.loads(manifest_file.read_text())
                for host, data in manifest.get("hosts", {}).items():
                    if data.get("is_api") and data.get("url"):
                        urls.add(data["url"].rstrip("/"))
            except Exception:
                pass

        # When corpus is thin (gau failed / external APIs down), seed all live
        # hosts with common API base paths so wordlist expansion can discover
        # endpoints that would normally be found via historical crawl data.
        if len(urls) < 500:
            http_hosts = self.scan_dir / "04_http_discovery" / "http_hosts.txt"
            if http_hosts.exists():
                api_seeds = ["/api", "/v1", "/v2", "/v3", "/graphql",
                             "/rest", "/service", "/services", "/app"]
                seed_count = 0
                for line in http_hosts.read_text(errors="ignore").splitlines():
                    host_url = line.strip().rstrip("/")
                    if not host_url or not host_url.startswith("http"):
                        continue
                    for seed in api_seeds:
                        urls.add(f"{host_url}{seed}")
                        seed_count += 1
                log.info("Thin corpus (%d URLs); seeded %d API base paths on live hosts",
                         len(urls) - seed_count, seed_count)

        # Strip tool-infrastructure domains that leak from nuclei metadata,
        # interactsh callbacks, etc.  These are never scan targets.
        def _is_tool_infra(u: str) -> bool:
            try:
                h = urllib.parse.urlparse(u).netloc.split(":")[0].lower()
            except Exception:
                return False
            return any(h == d or h.endswith("." + d) for d in TOOL_INFRA_DOMAINS)

        before = len(urls)
        urls = {u for u in urls if not _is_tool_infra(u)}
        if len(urls) < before:
            log.info("Dropped %d tool-infrastructure URLs (projectdiscovery, interactsh, etc.)",
                     before - len(urls))

        log.info("Total raw URLs collected: %d", len(urls))
        return list(urls)


# ---------------------------------------------------------------------------
# Phase 2 — Filter to API endpoints
# ---------------------------------------------------------------------------

class EndpointFilter:
    def filter(self, urls: List[str]) -> List[Endpoint]:
        endpoints: Dict[str, Endpoint] = {}

        for url in urls:
            try:
                parsed = urllib.parse.urlparse(url)
            except Exception:
                continue

            if not parsed.scheme or not parsed.netloc:
                continue

            # Only http/https
            if parsed.scheme not in ("http", "https"):
                continue

            # Exclude cloud storage hosts — they are bucket/blob endpoints, not web APIs
            if S3_HOST_RE.search(parsed.netloc):
                continue

            # Exclude tool-infrastructure domains (nuclei, interactsh, etc.)
            host_lower = parsed.netloc.split(":")[0].lower()
            if any(host_lower == d or host_lower.endswith("." + d)
                   for d in TOOL_INFRA_DOMAINS):
                continue

            # Skip static assets — publicly served by design, never authz findings
            if STATIC_ASSET_RE.search(parsed.path):
                continue

            # Must look like an API or interesting endpoint
            if not API_PATH_RE.search(parsed.path) and not SENSITIVE_PATH_RE.search(parsed.path):
                continue

            # Deduplicate by normalised path (strip query)
            key = f"{parsed.netloc}{parsed.path}"
            if key not in endpoints:
                ep = Endpoint(
                    url=f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
                    source="crawl",
                )
                endpoints[key] = ep

        log.info("API endpoints after filtering: %d", len(endpoints))
        return list(endpoints.values())


# ---------------------------------------------------------------------------
# Phase 3 — HTTP method discovery (deterministic probing)
# ---------------------------------------------------------------------------

class RateLimiter:
    """Thread-safe *global* request-rate limiter.

    The naive pattern — ``time.sleep(1/rate)`` inside each worker thread — is
    per-thread, so N workers multiply the real rate by N and fire in bursts:
    both a throughput lie and a textbook WAF/rate-rule trigger. This limiter
    instead hands out evenly-spaced dispatch slots that every thread shares, so
    the *aggregate* request rate holds no matter how many workers call it.

    Each caller reserves the next slot under a short lock, then sleeps until
    that slot OUTSIDE the lock — so workers wait concurrently instead of
    serialising on the mutex. A per-slot jitter of ``±jitter`` of the interval
    breaks up perfectly-uniform inter-request timing, which is itself a
    bot-detection signature; the jitter is symmetric so the mean rate is
    unchanged. ``rate <= 0`` disables throttling entirely (bounded only by
    thread count and the network).
    """

    def __init__(self, rate: float, jitter: float = 0.3):
        self._interval = 1.0 / rate if rate and rate > 0 else 0.0
        self._jitter = max(0.0, min(jitter, 0.9))
        self._lock = threading.Lock()
        self._next = 0.0

    def acquire(self) -> None:
        if self._interval <= 0:
            return
        step = self._interval
        if self._jitter:
            step *= 1.0 + random.uniform(-self._jitter, self._jitter)
        with self._lock:
            now = time.monotonic()
            target = self._next if self._next > now else now
            self._next = target + step
        wait = target - time.monotonic()
        if wait > 0:
            time.sleep(wait)


class HTTPProbe:
    """Lightweight HTTP prober — no external deps, uses urllib only."""

    def __init__(self, timeout: int = 8, verify_ssl: bool = False,
                 rate: float = 84, jitter: float = 0.3):
        self.timeout = timeout
        # Aggregate request rate is shared across every phase that borrows this
        # probe (static-verify, method probing, auth detection, expansion), so
        # the whole engine honours one global ceiling — not one-per-phase.
        self.rate = rate
        self.limiter = RateLimiter(rate, jitter)
        self.ctx = ssl.create_default_context()
        if not verify_ssl:
            self.ctx.check_hostname = False
            self.ctx.verify_mode = ssl.CERT_NONE

    def _request(self, method: str, url: str,
                 headers: Optional[Dict[str, str]] = None) -> Optional[Tuple[int, Dict, str]]:
        self.limiter.acquire()
        req = urllib.request.Request(url, method=method)
        req.add_header("User-Agent", "Mozilla/5.0 (ARISE-Scanner/2.1)")
        req.add_header("Accept", "application/json, */*")
        if headers:
            for k, v in headers.items():
                req.add_header(k, v)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self.ctx) as resp:
                body = resp.read(2048).decode(errors="ignore")
                return resp.status, dict(resp.headers), body
        except urllib.error.HTTPError as e:
            body = e.read(512).decode(errors="ignore") if e.fp else ""
            return e.code, dict(e.headers) if e.headers else {}, body
        except Exception:
            return None

    def probe(self, ep: Endpoint, extra_headers: Optional[Dict] = None) -> Endpoint:
        result = self._request("GET", ep.url, extra_headers)
        if result is None:
            return ep
        status, headers, body = result
        ep.status_code = status
        ep.content_type = headers.get("Content-Type", "")
        # Preserve the full response header set (lower-cased keys) so the API
        # classifier can inspect auth / rate-limit / CORS / request-id headers.
        ep.response_headers = {str(k).lower(): v for k, v in (headers or {}).items()}
        ep.response_length = len(body)
        ep.response_snippet = body[:300]
        ep.auth_required = status in (401, 403)
        ep.accessible_unauthenticated = (
            status in (200, 201, 204)
            and not AUTH_FAILURE_BODY_RE.search(body[:2000])
        )
        return ep

    def probe_methods(self, url: str) -> Dict[str, int]:
        """Returns {METHOD: status_code} for supported methods."""
        supported: Dict[str, int] = {}

        # OPTIONS first — cheapest
        opt = self._request("OPTIONS", url)
        if opt:
            allow = opt[1].get("Allow", "") or opt[1].get("allow", "")
            for m in allow.split(","):
                m = m.strip().upper()
                if m:
                    supported[m] = opt[0]

        # Probe remaining common methods
        for method in ["GET", "POST", "PUT", "DELETE", "PATCH"]:
            if method not in supported:
                r = self._request(method, url)
                if r and r[0] != 405:
                    supported[method] = r[0]

        return supported


# ---------------------------------------------------------------------------
# Phase 4 — Auth detection
# ---------------------------------------------------------------------------

class AuthDetector:
    """Detects authentication requirements and patterns without credentials."""

    def __init__(self, probe: HTTPProbe):
        self.probe = probe
        self.discovered_tokens: Dict[str, str] = {}

    def analyze(self, endpoints: List[Endpoint]) -> Dict[str, str]:
        """
        Probes auth endpoints for token patterns.
        Returns dict of {token_type: example_value_pattern}.
        No credentials stored or exfiltrated.
        """
        auth_eps = [ep for ep in endpoints if ep.is_auth_endpoint]
        log.info("Auth endpoints found: %d", len(auth_eps))

        for ep in auth_eps[:50]:
            r = self.probe._request("GET", ep.url)
            if not r:
                continue
            status, headers, body = r

            # Look for JWT pattern in response
            for m in JWT_RE.finditer(body):
                log.info("[auth] JWT pattern found at %s", ep.url)
                self.discovered_tokens["jwt_pattern"] = m.group(0)[:20] + "..."

            # WWW-Authenticate header reveals auth scheme
            www_auth = headers.get("Www-Authenticate", "") or headers.get("www-authenticate", "")
            if www_auth:
                self.discovered_tokens["www_authenticate"] = www_auth

            # Look for API key hints in headers
            for hdr in headers:
                if "api" in hdr.lower() or "token" in hdr.lower() or "key" in hdr.lower():
                    self.discovered_tokens[f"header_{hdr}"] = headers[hdr]

        return self.discovered_tokens


# ---------------------------------------------------------------------------
# Phase 5 — Endpoint expansion via actions wordlist
# ---------------------------------------------------------------------------

class EndpointExpander:
    """
    Takes each discovered base path and fuzzes with action wordlist via ffuf.
    Falls back to manual probing if ffuf is not installed.
    """

    def __init__(self, probe: HTTPProbe, wordlist_path: Optional[Path] = None):
        self.probe = probe
        self.wordlist = self._load_wordlist(wordlist_path)
        self.has_ffuf = self._check_ffuf()

    def _check_ffuf(self) -> bool:
        try:
            subprocess.run(["ffuf", "-h"], capture_output=True, timeout=3)
            return True
        except Exception:
            return False

    def _load_wordlist(self, path: Optional[Path]) -> List[str]:
        if path and path.exists():
            words = [l.strip() for l in path.read_text(errors="ignore").splitlines()
                     if l.strip() and not l.startswith("#")]
            log.info("Loaded %d words from %s", len(words), path)
            return words
        return BUILTIN_ACTIONS

    def expand(self, base_endpoints: List[Endpoint]) -> List[Endpoint]:
        """Expands each base endpoint by appending action words."""
        # Build unique base paths (strip trailing path segments that look like IDs)
        base_paths: Set[str] = set()
        for ep in base_endpoints:
            parts = ep.path.rstrip("/").split("/")
            # Use path up to (not including) the last ID-like segment
            if parts and _is_id_segment(parts[-1]):
                parts = parts[:-1]
            base = "/".join(parts).rstrip("/") or "/"
            base_paths.add(f"{urllib.parse.urlparse(ep.url).scheme}://"
                          f"{urllib.parse.urlparse(ep.url).netloc}{base}")

        new_endpoints: List[Endpoint] = []

        if self.has_ffuf:
            for base in list(base_paths)[:60]:  # Cap to avoid runaway
                new_endpoints.extend(self._ffuf_expand(base))
        else:
            log.info("ffuf not found — using built-in action probing")
            new_endpoints.extend(self._manual_expand(list(base_paths)[:40]))

        log.info("Endpoint expansion discovered %d new endpoints", len(new_endpoints))
        return new_endpoints

    def _ffuf_expand(self, base_url: str) -> List[Endpoint]:
        """Uses ffuf to fuzz FUZZ placeholder in base_url/FUZZ."""
        import tempfile
        fuzz_url = base_url.rstrip("/") + "/FUZZ"
        eps: List[Endpoint] = []

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as wf:
            wf.write("\n".join(self.wordlist))
            wf_path = wf.name

        # ffuf must write JSON to a real file — /dev/null loses the output
        out_file = wf_path + "_ffuf_out.json"

        try:
            # Mirror the engine's global rate onto ffuf so this phase can't
            # silently blow past the WAF-safe ceiling (ffuf's own default is
            # unthrottled). -rate 0 = unlimited, matching rate<=0 upstream.
            ffuf_rate = str(int(self.probe.rate)) if self.probe.rate and self.probe.rate > 0 else "0"
            cmd = [
                "ffuf", "-u", fuzz_url, "-w", wf_path,
                "-mc", "200,201,204,301,302,401,403,405",
                "-t", "20", "-timeout", "5",
                "-rate", ffuf_rate,
                "-o", out_file, "-of", "json",
                "-s",           # silent banner
                "-noninteractive",
            ]
            subprocess.run(cmd, capture_output=True, timeout=90)

            if os.path.exists(out_file):
                try:
                    data = json.loads(open(out_file).read())
                    for r in data.get("results", []):
                        ep = Endpoint(
                            url=r["url"],
                            method="GET",
                            status_code=r.get("status"),
                            response_length=r.get("length", 0),
                            source="ffuf_expand",
                        )
                        eps.append(ep)
                    log.debug("ffuf found %d endpoints under %s", len(eps), base_url)
                except Exception as e:
                    log.debug("ffuf output parse failed for %s: %s", base_url, e)
        except Exception as e:
            log.debug("ffuf expand failed for %s: %s", base_url, e)
        finally:
            for f in (wf_path, out_file):
                try:
                    os.unlink(f)
                except OSError:
                    pass

        return eps

    def _manual_expand(self, base_urls: List[str]) -> List[Endpoint]:
        """Manually probes base_url/action for each action in wordlist."""
        eps: List[Endpoint] = []
        for base in base_urls:
            for action in self.wordlist:
                url = base.rstrip("/") + "/" + action
                r = self.probe._request("GET", url)
                if r and r[0] in INTERESTING_STATUS:
                    ep = Endpoint(url=url, status_code=r[0], source="manual_expand")
                    eps.append(ep)
                    log.debug("Expand hit: %s → %d", url, r[0])
        return eps


# ---------------------------------------------------------------------------
# API-vs-Website classifier — the authoritative 13-step decision tree.
# Evaluated top to bottom; FIRST match wins. Only endpoints classified "API"
# are attacked (broken-auth / BOLA / injection); "WEBSITE" and "UNKNOWN" are
# not, which is what removes HTML-page false positives.
# ---------------------------------------------------------------------------

# 2. API subdomains
_API_SUBDOMAIN_RE = re.compile(r"^(?:api|graphql|gateway|rest|mobile-api|backend)\.", re.I)
# 3. OpenAPI / Swagger paths — _SWAGGER_PATH_RE imported from url_classify
# 4. GraphQL paths — _GRAPHQL_PATH_RE imported from url_classify
# 5. API content types (HEAD/GET Content-Type)
_STEP5_CT_RE = re.compile(
    r"(?:application/(?:json|.*\+json|xml|.*\+xml|(?:x-)?protobuf|grpc\S*)"
    r"|text/(?:xml|event-stream))", re.I)
# 9. API-shaped response headers
_API_HEADER_KEYS = (
    "x-ratelimit-limit", "x-ratelimit-remaining", "x-rate-limit-limit",
    "x-request-id", "x-correlation-id", "x-amzn-requestid", "x-amzn-trace-id",
    "access-control-allow-headers", "access-control-allow-methods",
)
# 11. REST resource path patterns
_RESOURCE_PATH_RE = re.compile(
    r"/(?:users?|accounts?|orders?|products?|login|oauth|token|payments?)(?:/|$|\?)", re.I)
# 12. Marketing/website body markers
_WEBSITE_BODY_RE = re.compile(r"(?:navbar|footer|<article|blog|marketing|<nav[\s>])", re.I)
_HTML_STRUCT_RE = re.compile(r"(?:<html[\s>]|<head[\s>]|<body[\s>])", re.I)
# 13. Endpoint sources that come from JS runtime interception (fetch/axios/XHR)
_JS_DISCOVERY_SOURCES = ("api_deep_discovery", "xhr", "fetch", "js", "headless")


def classify_url_type(ep: "Endpoint", probe: "HTTPProbe" = None) -> Tuple[str, str]:
    """Return (verdict, step) where verdict is 'API' | 'WEBSITE' | 'UNKNOWN'.
    Implements the fixed 13-step tree exactly; first match wins. Steps that
    need a live request (6 OPTIONS, 7 Accept-negotiation) run only when `probe`
    is supplied AND earlier steps were inconclusive; otherwise they fall through."""
    path = ep.path or "/"
    host = ep.host or ""
    ctype = (ep.content_type or "").lower()
    body = ep.response_snippet or ""
    headers = ep.response_headers or {}

    # 1. Static asset -> WEBSITE
    if STATIC_ASSET_RE.search(path) or STATIC_CONTENT_TYPE_RE.search(ctype):
        return "WEBSITE", "1-static-asset"

    # 2. API subdomain -> API
    if _API_SUBDOMAIN_RE.search(host):
        return "API", "2-api-subdomain"

    # 3. OpenAPI / Swagger -> API
    if _SWAGGER_PATH_RE.search(path):
        return "API", "3-openapi-swagger"

    # 4. GraphQL -> API
    if _GRAPHQL_PATH_RE.search(path):
        return "API", "4-graphql"

    # 5. HEAD/GET Content-Type is an API media type -> API
    if ctype and _STEP5_CT_RE.search(ctype):
        return "API", "5-content-type"

    # 6. OPTIONS advertises write methods (POST/PUT/PATCH/DELETE) -> API
    allow = (ep.allow_methods or headers.get("allow", "") or "").upper()
    if not allow and probe is not None:
        try:
            opt = probe._request("OPTIONS", ep.url)
            if opt:
                allow = (opt[1].get("Allow", "") or opt[1].get("allow", "")).upper()
        except Exception:
            allow = ""
    if allow and re.search(r"\b(?:POST|PUT|PATCH|DELETE)\b", allow):
        return "API", "6-options-methods"

    # 7. Accept negotiation: does Accept: application/json flip the response to JSON?
    if probe is not None:
        try:
            neg = probe._request("GET", ep.url, {"Accept": "application/json"})
            if neg and _STEP5_CT_RE.search((neg[1].get("Content-Type", "") or "").lower()):
                return "API", "7-accept-negotiation"
        except Exception:
            pass

    # 8. Authentication headers present -> API
    if "www-authenticate" in headers:
        return "API", "8-auth-header"
    wa = headers.get("www-authenticate", "")
    if re.search(r"(bearer|oauth|apikey|api[-_]key)", wa, re.I):
        return "API", "8-auth-header"

    # 9. API-shaped response headers (rate-limit / request-id / CORS methods) -> API
    if any(k in headers for k in _API_HEADER_KEYS):
        return "API", "9-response-headers"

    # 10. Response body is structured data (JSON / XML / SOAP / Problem+JSON) -> API
    stripped = body.lstrip()
    if _JSON_BODY_RE.match(stripped):
        return "API", "10-json-body"
    if _XML_BODY_RE.match(stripped):
        return "API", "10-xml-body"

    # 11. REST resource path pattern -> API
    if _RESOURCE_PATH_RE.search(path):
        return "API", "11-resource-pattern"

    # 12. HTML document with website chrome (navbar/footer/blog/marketing) -> WEBSITE
    if _HTML_STRUCT_RE.search(body) or "html" in ctype:
        if _WEBSITE_BODY_RE.search(body) or "html" in ctype:
            return "WEBSITE", "12-html-analysis"

    # 13. Endpoint was discovered via JS runtime (fetch/axios/XHR) -> API
    if any(s in (ep.source or "").lower() for s in _JS_DISCOVERY_SOURCES):
        return "API", "13-js-discovery"

    # Nothing matched — genuinely ambiguous.
    return "UNKNOWN", "unknown"


# ---------------------------------------------------------------------------
# API TYPE classification — run once the tree has confirmed an endpoint is an
# API, to tag WHICH flavour it is. This drives tailored testing (GraphQL →
# introspection/batching, SOAP → XXE/XML-injection, gRPC → reflection) and is
# surfaced per-endpoint in the report.
# ---------------------------------------------------------------------------
# _GRAPHQL_BODY_RE / _SOAP_BODY_RE / _JSONRPC_BODY_RE / _ODATA_RE imported from
# url_classify, which also owns the flavour logic (api_flavour).


def classify_api_type(ep: "Endpoint") -> str:
    """Return the API flavour for an endpoint already judged 'API':
    graphql | soap | grpc | jsonrpc | odata | sse | rest-json | rest-xml |
    binary | api-unknown. Thin wrapper over the shared url_classify core so the
    engine and Module 8B tag flavours identically."""
    return _shared_api_flavour(ep.path, ep.content_type, ep.response_snippet)


# ---------------------------------------------------------------------------
# Phase 9 — apisec.py adapter (4th engine)
#
# Unlike the filter/probe phases above (Phases 2-5), which only build the
# intel snapshot from the strict subset of endpoints that matched API_PATH_RE /
# SENSITIVE_PATH_RE (EndpointFilter.filter), this adapter is deliberately
# seeded with the FULL, unfiltered URL set every prior module discovered —
# including everything dirsearch found in 08_directory_discovery/all_paths.txt
# that was never tagged "API". apisec.py's own classifiers (soft-404
# suppression, verified 403-bypass, BOLA/BFLA differential auth via a second
# token, JWT weak-secret/alg-none, mass assignment, CORS/secrets/headers) are
# worth running on that broader set, per the explicit design requirement that
# untagged URLs shouldn't be silently dropped from API security testing.
#
# It also emits a synthetic OpenAPI spec straight into
# 16_api_security/specs/<host_hash>/spec.json for inspection/export — a
# best-effort "custom swagger" for hosts that never publish a real one.
# ---------------------------------------------------------------------------

# Maps apisec.py's fixed Finding.title strings (regex) onto ARISE's stable
# issue_class/category vocabulary, so every finding carries the same class
# names the dashboard, the KAIJU issue rules and dedup (Finding.dedup_key())
# key on. A title with no mapping falls back to a slug (see _classify) rather
# than being dropped.
# Titles with no existing equivalent get their own new issue_class (apisec.py
# is the only engine that currently detects them).
_APISEC_TITLE_MAP: List[Tuple[re.Pattern, str, str]] = [
    (re.compile(r"weak/guessable HMAC secret"), "jwt_weak_secret", "authn"),
    (re.compile(r"alg-confusion"), "jwt_alg_none_confusion", "authn"),
    (re.compile(r"Mass assignment"), "mass_assignment", "authz"),
    (re.compile(r"Function-Level Authorization \(BFLA\)"), "broken_function_level_authorization", "authz"),
    (re.compile(r"confirmed cross-token access"), "broken_object_authorization", "authz"),
    (re.compile(r"no rate limiting observed"), "no_rate_limiting", "resource"),
    (re.compile(r"specification publicly exposed"), "spec_publicly_exposed", "exposure"),
    (re.compile(r"Broken authentication"), "broken_authentication", "authn"),
    (re.compile(r"Broken Object-Level Authorization \(BOLA/IDOR\)"), "broken_object_authorization", "authz"),
    (re.compile(r"403 access control bypassed"), "403_bypass_confirmed", "authz"),
    (re.compile(r"Sensitive/internal endpoint exposed"), "sensitive_endpoint_exposed", "exposure"),
    (re.compile(r"Sensitive data exposure"), "sensitive_data_exposure", "exposure"),
    (re.compile(r"Method-not-allowed oracle"), "endpoint_enumeration", "exposure"),
    (re.compile(r"Server error on probe"), "server_error_on_probe", "robustness"),
    (re.compile(r"Secret leaked in API response"), "secret_leaked_in_response", "exposure"),
    (re.compile(r"Verbose error / stack trace"), "verbose_error_disclosure", "exposure"),
    (re.compile(r"Dangerous HTTP method enabled"), "dangerous_method_enabled", "config"),
    (re.compile(r"TRACE method advertised"), "trace_method_advertised", "config"),
    (re.compile(r"wildcard origin with credentials"), "cors_wildcard_with_credentials", "config"),
    (re.compile(r"arbitrary origin reflected"), "cors_arbitrary_origin_reflected", "config"),
    (re.compile(r"Missing security header"), "missing_security_header", "transport"),
    (re.compile(r"Version disclosure"), "version_disclosure", "config"),
    (re.compile(r"GraphQL introspection enabled"), "graphql_introspection_enabled", "exposure"),
]

# apisec.py finding titles that represent a *live, verified* exploit (an
# offline-cracked JWT secret, an actually-forged token the server accepted, a
# demonstrated 403 bypass, a cross-token BOLA/BFLA hit) rather than a
# heuristic pattern match. These are trustworthy enough to promote to the
# vulnerabilities dashboard even when no other tool corroborates them, since
# "single-tool" here still means "proven", not "guessed".
_APISEC_VERIFIED_EXPLOIT_CLASSES = {
    "jwt_weak_secret", "jwt_alg_none_confusion", "mass_assignment",
    "broken_function_level_authorization", "403_bypass_confirmed",
}


class ApiSecAdapter:
    """Wraps apisec.py (standalone stdlib-only black-box API security
    scanner) as the 4th testing engine, seeded per-host from the full raw
    URL set (see module docstring above)."""

    APISEC_SCRIPT = Path(__file__).resolve().parent / "apisec.py"

    def run(self, raw_urls: List[str], api_endpoints: List[Endpoint],
            out_dir: Path, specs_dir: Path, auth: Optional[str] = None,
            auth2: Optional[str] = None, cookie: Optional[str] = None,
            timeout: int = 8,
            threads: int = 20, deadline: Optional[float] = None,
            rate: float = 84, jitter: float = 0.3,
            sink: Optional[List["Finding"]] = None) -> List[Finding]:
        # `sink`, when given, receives each host's findings as that host
        # finishes — so a caller's SIGTERM handler can flush completed-host
        # results even if a later host gets SIGKILL'd mid-subprocess.
        if not self.APISEC_SCRIPT.exists():
            log.info("apisec.py not found at %s — skipping adapter", self.APISEC_SCRIPT)
            return []

        by_host: Dict[str, Set[str]] = {}
        for u in raw_urls:
            try:
                host = urllib.parse.urlparse(u).netloc.split(":")[0]
            except Exception:
                continue
            if not host:
                continue
            h = host.lower()
            if any(h == d or h.endswith("." + d) for d in TOOL_INFRA_DOMAINS):
                continue
            by_host.setdefault(host, set()).add(u)
        # API-tagged endpoints also seed in, in case a host only ever showed
        # up via that path (e.g. Module 20 XHR interception, never present in
        # a raw dirsearch/crawl list).
        for ep in api_endpoints:
            if ep.host:
                by_host.setdefault(ep.host, set()).add(ep.url)

        if not by_host:
            return []

        out_dir.mkdir(parents=True, exist_ok=True)
        findings: List[Finding] = []

        _API_SEED_PATHS = [
            "/api", "/api/v1", "/api/v2", "/api/v3",
            "/v1", "/v2", "/v3", "/graphql", "/rest",
            "/health", "/status", "/swagger.json", "/openapi.json",
            "/docs", "/api-docs", "/swagger/v1/swagger.json",
        ]

        for i, (host, urls) in enumerate(by_host.items()):
            if not urls:
                continue
            # A single host's apisec.py subprocess can take up to `timeout`
            # (per-request) x however many endpoints it probes, capped at 300s
            # below — but with many API hosts, a handful of slow/unresponsive
            # ones can burn through the ENTIRE module wall-clock budget before
            # ever reaching the rest, at which point the whole process gets
            # SIGTERM/SIGKILL'd by run_tool_timeout with nothing ever written
            # (this._write_findings only runs once, at the very end of run()).
            # Stop launching NEW hosts once we're out of runway so the loop
            # returns normally with whatever it already collected, letting the
            # caller reach _write_findings() instead of losing everything.
            if deadline is not None and time.monotonic() >= deadline:
                log.warning("apisec adapter: internal deadline reached — "
                            "stopping after %d/%d hosts (skipping %s and %d more)",
                            i, len(by_host), host, len(by_host) - i - 1)
                break
            if len(urls) < 20:
                base = f"https://{host}"
                for p in _API_SEED_PATHS:
                    urls.add(f"{base}{p}")
            host_hash = hashlib.md5(host.encode()).hexdigest()
            seed_file = out_dir / f"{host_hash}.seed.txt"
            seed_file.write_text("\n".join(sorted(urls)) + "\n")

            json_out = out_dir / f"{host_hash}.findings.jsonl"
            host_spec_dir = specs_dir / host_hash
            host_spec_dir.mkdir(parents=True, exist_ok=True)
            spec_out = host_spec_dir / "spec.json"

            base_url = f"https://{host}"
            cmd = [sys.executable, str(self.APISEC_SCRIPT), base_url,
                   "--seed-file", str(seed_file), "--seed-only",
                   "--json", str(json_out),
                   "--export-openapi", str(spec_out),
                   "--timeout", str(timeout), "--threads", str(threads),
                   "--rate", str(int(rate)), "--jitter", str(jitter),
                   "--quiet"]
            if auth:
                cmd += ["--auth", auth]
            if auth2:
                cmd += ["--auth2", auth2]
            if cookie:
                cmd += ["--cookie", cookie]

            log_path = out_dir / f"{host_hash}.log"
            try:
                with open(log_path, "w") as flog:
                    subprocess.run(cmd, stdout=flog, stderr=subprocess.STDOUT,
                                    timeout=300)
            except Exception as e:
                log.warning("apisec.py failed for %s: %s", host, e)
                continue

            if json_out.exists():
                host_findings = self._parse_jsonl(json_out, host)
                findings.extend(host_findings)
                if sink is not None:
                    # Flush this host into the live accumulator immediately so
                    # it survives a SIGKILL on a later host.
                    sink.extend(host_findings)

        log.info("apisec adapter: %d findings across %d hosts", len(findings), len(by_host))
        return findings

    @staticmethod
    def _classify(title: str) -> Tuple[str, str]:
        for pat, issue_class, category in _APISEC_TITLE_MAP:
            if pat.search(title or ""):
                return issue_class, category
        # Unmapped title (new apisec.py check we haven't catalogued yet) —
        # fall back to a stable slug rather than dropping the finding.
        slug = re.sub(r"[^a-z0-9]+", "_", (title or "apisec_finding").lower()).strip("_")[:60]
        return slug or "apisec_finding", "exposure"

    def _parse_jsonl(self, jf: Path, host: str) -> List[Finding]:
        out: List[Finding] = []
        try:
            for line in jf.read_text(errors="ignore").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                except Exception:
                    continue
                if d.get("_meta"):
                    continue
                title = d.get("title", "apisec finding")
                issue_class, category = self._classify(title)
                out.append(Finding(
                    method=d.get("method", "GET") or "GET",
                    path=d.get("path", "/") or "/",
                    host=host,
                    issue_class=issue_class,
                    category=category or d.get("category", "exposure"),
                    severity=d.get("severity", "medium"),
                    tool="apisec",
                    evidence=(d.get("evidence") or title)[:500],
                    status_code=d.get("status") or None,
                    remediation=d.get("remediation", ""),
                ))
        except Exception as e:
            log.warning("Failed to parse apisec findings %s: %s", jf, e)
        return out


# ---------------------------------------------------------------------------
# Main orchestrator
# ---------------------------------------------------------------------------

class APIIntelligenceEngine:

    def __init__(self, scan_dir: Path, rate: int = 84,
                 timeout: int = 8, threads: int = 40,
                 wordlist: Optional[Path] = None,
                 static_verify_cap: int = 3000,
                 deadline_seconds: Optional[int] = None,
                 jitter: float = 0.3):
        self.scan_dir = scan_dir
        self.rate = rate
        self.jitter = jitter
        self.timeout = timeout
        self.threads = threads
        # Above this many extension-flagged static candidates, skip the
        # (precision-only) live HTTP verification and exclude by extension —
        # otherwise Phase 1.5 can live-probe hundreds of thousands of URLs and
        # blow the whole module past its wall-clock cap (killed with 0 findings).
        self.static_verify_cap = static_verify_cap
        # Internal wall-clock deadline (monotonic), set with a safety margin
        # below the pipeline's external SIGTERM cap. The apisec.py adapter
        # (Phase 9) checks this before starting each new host so a handful of
        # slow hosts can't burn the entire budget and get the whole process
        # SIGKILL'd before _write_findings() ever runs.
        self.hard_deadline = (
            time.monotonic() + deadline_seconds if deadline_seconds else None
        )
        # Phases 1-6 (collection/probing/expansion/classification) had NO
        # deadline awareness at all — on a huge target (293k raw URLs, 44 API
        # hosts on the payu.in scan that exposed this) they consumed the
        # ENTIRE deadline_seconds budget before Phase 9 ever started, so
        # apisec.py — the only phase that produces confirmed/exploit-verified
        # findings — got to attempt exactly one host before the whole module
        # was SIGTERM'd (apisec_findings: 0 despite 44 API hosts). Reserving a
        # floor here means Phases 1-6 self-truncate (keeping whatever they've
        # probed/classified so far — same fail-open pattern as the rest of
        # this engine) instead of silently starving Phase 9 of its turn.
        self._phase16_deadline = (
            time.monotonic() + deadline_seconds * 0.6 if deadline_seconds else None
        )
        # Live findings accumulator — kept as an instance attribute (not a
        # local var in run()) so a SIGTERM handler can flush whatever's been
        # found so far instead of losing everything to a hard kill.
        self._live_findings: List[Finding] = []

        # Sub-components
        self.probe = HTTPProbe(timeout=timeout, rate=rate, jitter=jitter)
        self.collector = EndpointCollector(scan_dir)
        self.filter = EndpointFilter()
        self.auth_detector = AuthDetector(self.probe)
        self.expander = EndpointExpander(self.probe, wordlist)

        self.apisec = ApiSecAdapter()

        # Output paths
        self.api_sec_dir = scan_dir / "16_api_security"
        self.findings_file = self.api_sec_dir / "api_findings.jsonl"
        self.intel_dir = self.api_sec_dir / "intel"
        self.apisec_dir = self.api_sec_dir / "apisec"
        self.specs_dir = self.api_sec_dir / "specs"

    def _session_cookie_header(self) -> str:
        """Shared session jar (easm-pipeline.sh's ARISE_SESSION_JAR — Module 20's
        CDP crawl and any user-supplied cookie both land here) scoped to this
        scan's target domain, so apisec.py stops starting cold/unauthenticated
        when the rest of the pipeline has a session."""
        jar_path = os.environ.get("ARISE_SESSION_JAR")
        if not jar_path or not os.path.exists(jar_path):
            return ""
        try:
            from core import session_jar
            manifest = json.loads((self.scan_dir / "manifest.json").read_text())
            domain = (manifest.get("pipeline_info") or {}).get("target") or None
            return session_jar.load_header_string(jar_path, domain)
        except Exception:
            return ""

    def _prune_static_assets(self, raw_urls: List[str]) -> List[str]:
        """Verify extension-flagged candidates over HTTP and drop only those the
        server actually serves as static assets. Unverified/dynamic candidates
        are retained (fail-open). Concurrency-bounded; never raises."""
        candidates = [u for u in raw_urls if is_static_asset(u)]
        if not candidates:
            return raw_urls
        # Hard bound: live-verifying an unbounded candidate set (593k on the
        # hivelance scan) blew past the module's wall-clock cap and the whole
        # API scan was KILLED with zero findings. Above the cap, skip the
        # precision-only HTTP check and exclude by extension directly.
        if len(candidates) > self.static_verify_cap:
            cset = set(candidates)
            kept = [u for u in raw_urls if u not in cset]
            log.warning("[Phase 1.5] %d static-asset candidate(s) exceed the "
                        "verify cap (%d) — excluding by extension WITHOUT HTTP "
                        "verification; kept %d URL(s)",
                        len(candidates), self.static_verify_cap, len(kept))
            return kept
        log.info("[Phase 1.5] Verifying %d static-asset candidate(s) before exclusion…",
                 len(candidates))
        confirmed: Set[str] = set()
        workers = max(1, min(self.threads, 20))
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
                futs = {ex.submit(verify_static_asset, u, self.probe): u for u in candidates}
                for fut in concurrent.futures.as_completed(futs):
                    try:
                        if fut.result() is True:
                            confirmed.add(futs[fut])
                    except Exception:
                        pass  # inconclusive -> keep
        except Exception as exc:  # pool failure must not sink the scan
            log.warning("static-asset verification pool error: %s — keeping all URLs", exc)
            return raw_urls
        kept = [u for u in raw_urls if u not in confirmed]
        log.info("[Phase 1.5] Excluded %d VERIFIED static asset(s); kept %d "
                 "(%d unverified/dynamic candidate(s) retained)",
                 len(confirmed), len(kept), len(candidates) - len(confirmed))
        return kept

    def _seed_known_methods(self, endpoints: List[Endpoint]) -> None:
        """Seed ep.allow_methods from discovery/method_map.py's output
        (08_directory_discovery/method_map.jsonl — non-GET methods the
        consolidator already confirmed via an OPTIONS probe during
        discovery). Lets classify_url_type()'s step 6 (write-method ->
        API) use that known-good data instead of firing its own redundant
        live OPTIONS request for endpoints we've already probed once.
        Mutates in place; never raises."""
        mm_file = self.scan_dir / "08_directory_discovery" / "method_map.jsonl"
        if not mm_file.exists():
            return
        known: Dict[str, str] = {}
        try:
            for line in mm_file.read_text(errors="ignore").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except Exception:
                    continue
                url = rec.get("url") or ""
                methods = rec.get("methods") or []
                if url and methods:
                    known[url] = ",".join(methods)
        except OSError:
            return
        if not known:
            return
        seeded = 0
        for ep in endpoints:
            m = known.get(ep.url)
            if m and not ep.allow_methods:
                ep.allow_methods = m
                seeded += 1
        if seeded:
            log.info("Seeded allow_methods on %d endpoint(s) from method_map.jsonl", seeded)

    def _read_target_root_domain(self) -> Optional[str]:
        """Target domain for scope filtering, from manifest.json pipeline_info.target."""
        manifest_file = self.scan_dir / "manifest.json"
        if not manifest_file.exists():
            return None
        try:
            manifest = json.loads(manifest_file.read_text())
            target = (manifest.get("pipeline_info", {}).get("target", "") or "").strip().lower()
            return target.lstrip(".") or None
        except Exception:
            return None

    def _write_url_list(self, path: Path, urls: List[str]) -> None:
        try:
            path.write_text("\n".join(sorted(urls)) + ("\n" if urls else ""))
        except Exception as exc:
            log.warning("Could not write %s: %s", path, exc)

    def run(self) -> int:
        self.api_sec_dir.mkdir(parents=True, exist_ok=True)
        self.intel_dir.mkdir(parents=True, exist_ok=True)
        self.apisec_dir.mkdir(parents=True, exist_ok=True)
        self.specs_dir.mkdir(parents=True, exist_ok=True)

        log.info("=" * 60)
        log.info("ARISE API Intelligence Engine starting")
        log.info("Scan dir: %s", self.scan_dir)
        log.info("=" * 60)

        # ── Phase 1: Collect ──────────────────────────────────────────
        # raw_urls is EVERY URL any prior module discovered — including all
        # of dirsearch's unfiltered 08_directory_discovery/all_paths.txt.
        # This full list (not the API-tagged subset below) is what feeds
        # apisec.py in Phase 9, per design: untagged URLs still deserve
        # black-box API security testing.
        log.info("[Phase 1] Collecting endpoints from pipeline outputs…")
        raw_urls = self.collector.collect()

        # ── Phase 1.6: Scope filter + similarity collapse (runs FIRST) ─
        # Drop out-of-scope hosts, then collapse URLs that only differ by
        # instance-level path/query values (dates, strikes, IDs, hashes) to
        # one representative per template. This MUST run before the static
        # verification below: the raw collect can be 600k+ URLs (mostly
        # out-of-scope wayback junk + the same API endpoint repeated with
        # thousands of query values), and live-probing that set once ran the
        # module out of wall-clock time and it was killed with 0 findings.
        # Scope + collapse is pure-local and shrinks the set by orders of
        # magnitude first. Fail-open: any error falls back to the untouched set.
        try:
            root_domain = self._read_target_root_domain()
            scoped_urls = ([u for u in raw_urls if _url_in_scope(u, root_domain)]
                           if root_domain else raw_urls)
            if root_domain and len(scoped_urls) < len(raw_urls):
                log.info("[Phase 1.6] Dropped %d out-of-scope URL(s) (target: %s)",
                         len(raw_urls) - len(scoped_urls), root_domain)
            reduced_urls = _reduce_similar_urls(scoped_urls)
            if len(reduced_urls) < len(scoped_urls):
                log.info("[Phase 1.6] Collapsed %d similar URL(s) into %d template(s)",
                         len(scoped_urls) - len(reduced_urls), len(reduced_urls))
            raw_urls = reduced_urls
        except Exception as exc:
            log.warning("Phase 1.6 scope/similarity reduction failed: %s — "
                        "using unreduced URL set", exc)

        # ── Phase 1.5: Verify & prune confirmed static assets ─────────
        # Runs on the now-reduced, in-scope set. Extension flags a candidate;
        # HTTP Content-Type decides. Only URLs the server actually serves as
        # JS/CSS/font/image/media are excluded — a ".js" that returns
        # application/json (dynamic route) is kept. Bounded by
        # static_verify_cap (see _prune_static_assets). This cleans BOTH the
        # API-endpoint filter and the apisec seed.
        raw_urls = self._prune_static_assets(raw_urls)

        # Drop CDN/WAF infrastructure paths (Cloudflare cdn-cgi, challenge-platform,
        # etc.) — these are never the application and produce only FPs.
        _cdn_before = len(raw_urls)
        raw_urls = [u for u in raw_urls if not _is_cdn_infra_url(u)]
        if len(raw_urls) < _cdn_before:
            log.info("[Phase 1.7] Dropped %d CDN-infrastructure URL(s)",
                     _cdn_before - len(raw_urls))

        # Persist the final API-security target set for downstream tools/inspection.
        try:
            self._write_url_list(self.intel_dir / "apisecuritytarget.txt", raw_urls)
        except Exception as exc:
            log.warning("Could not write apisecuritytarget.txt: %s", exc)

        # ── Phase 2: Filter ───────────────────────────────────────────
        log.info("[Phase 2] Filtering to API endpoints…")
        api_endpoints = self.filter.filter(raw_urls)
        self._seed_known_methods(api_endpoints)

        # Alias to the instance accumulator (not a fresh local list) so a
        # SIGTERM flush mid-Phase-9 can see everything collected so far.
        findings: List[Finding] = self._live_findings

        if not api_endpoints:
            log.warning("No API-tagged endpoints found via strict filter — "
                        "method-probe/snapshot phases skipped, "
                        "but apisec.py (Phase 9) still runs against the full "
                        "unfiltered URL set below.")
        else:
            # ── Phase 3: HTTP method discovery ────────────────────────
            log.info("[Phase 3] Probing HTTP methods (%d endpoints, %d threads)…",
                     len(api_endpoints), self.threads)
            api_endpoints = self._probe_all(api_endpoints, deadline=self._phase16_deadline)

            # ── Phase 4: Auth detection ───────────────────────────────
            log.info("[Phase 4] Auth detection…")
            auth_tokens = self.auth_detector.analyze(api_endpoints)
            if auth_tokens:
                log.info("Auth patterns found: %s", list(auth_tokens.keys()))

            # ── Phase 5: Endpoint expansion ───────────────────────────
            # Skipped outright once the Phases-1-6 budget is gone (Phase 3's
            # probe above already ran long on a huge target) — this step
            # alone added 10,305 extra probes on the payu.in scan that
            # triggered this fix, which is what starved Phase 9 of its turn.
            if self._phase16_deadline is not None and time.monotonic() >= self._phase16_deadline:
                log.warning("[Phase 5] skipped — intel-phase budget exhausted; "
                            "leaving time for apisec.py (Phase 9)")
            else:
                log.info("[Phase 5] Expanding endpoints with action wordlist…")
                expanded = self.expander.expand(api_endpoints[:50])  # cap base paths
                # Probe expanded endpoints
                if expanded:
                    expanded = self._probe_all(expanded, deadline=self._phase16_deadline)
                    api_endpoints.extend(expanded)

            # Save intel snapshot — the probed method map + URL/API-type
            # classification that downstream modules (param_fuzzing, the
            # dashboard URL inventory) consume. This is the sole purpose of
            # Phases 3-5 now that apisec.py owns all finding emission.
            self._save_intel_snapshot(api_endpoints)

        # ── Phase 9: apisec.py (sole black-box finding engine) ────────
        # The ONLY engine that emits findings now — the former native
        # Phase-6 classifier (heuristic, path-shape + status-code) was
        # retired because apisec.py already covers every one of its classes
        # at response-gated / differential-confirmed confidence (and adds
        # JWT, mass-assignment, BFLA, CORS, GraphQL, SQLi, headers, …).
        # Always runs, independent of whether the strict API filter matched
        # anything above — seeded from the FULL raw_urls set collected in
        # Phase 1 (see ApiSecAdapter docstring). Also writes a synthetic
        # OpenAPI spec per host into 16_api_security/specs/<host_hash>/spec.json
        # for inspection/export.
        #
        # `sink=self._live_findings` makes the adapter append each host's
        # findings as that host completes, so the SIGTERM emergency_flush()
        # captures every finished host even if a later host's apisec.py
        # subprocess runs the process past the wall-clock cap and it gets
        # SIGKILL'd. This replaces the old pre-apisec checkpoint (which only
        # ever had the retired classifier's findings to save).
        if raw_urls:
            log.info("[Phase 9] Running apisec.py adapter (seeded with %d raw URLs)…",
                     len(raw_urls))
            # findings is an alias of self._live_findings, and the adapter
            # appends into that same list via sink — so its return value is
            # already present; _dedup() below collapses the duplicate refs.
            self.apisec.run(
                raw_urls, api_endpoints, self.apisec_dir, self.specs_dir,
                auth=os.environ.get("APISEC_AUTH_HEADER") or None,
                auth2=os.environ.get("APISEC_AUTH2_HEADER") or None,
                cookie=self._session_cookie_header() or None,
                timeout=self.timeout, threads=self.threads,
                deadline=self.hard_deadline,
                rate=self.rate, jitter=self.jitter,
                sink=self._live_findings)
            # Checkpoint — apisec.py findings survive even if something
            # after this point (dedup, summary write) throws.
            try:
                self._write_findings(self._dedup(list(findings)))
            except Exception as exc:
                log.warning("Post-apisec checkpoint write failed: %s", exc)
        else:
            log.warning("No URLs collected at all — apisec.py adapter skipped")

        if not findings and not api_endpoints:
            self._write_summary(0, 0)
            log.info("No endpoints and no findings — nothing to write")
            return 0

        # ── Deduplicate & write ───────────────────────────────────────
        findings = self._dedup(findings)
        self._write_findings(findings)
        self._write_summary(len(api_endpoints), len(findings))

        log.info("=" * 60)
        log.info("Complete. Endpoints: %d  Findings: %d  Output: %s",
                 len(api_endpoints), len(findings), self.findings_file)
        log.info("=" * 60)
        return len(findings)

    # ── Helpers ──────────────────────────────────────────────────────

    def _probe_all(self, endpoints: List[Endpoint],
                   deadline: Optional[float] = None) -> List[Endpoint]:
        """Probe all endpoints in parallel. Throttling is enforced globally
        inside HTTPProbe._request (shared RateLimiter), so the pool just
        provides concurrency to hide network latency — no per-batch sleep here,
        which used to gate result *collection* rather than request dispatch and
        let the real rate spike with thread count.

        Submitted in chunks (not all at once) so an optional `deadline` can
        actually take effect between chunks — ThreadPoolExecutor's own
        context-manager exit blocks until every already-submitted future
        finishes, so checking the deadline only between chunks, never inside
        one, is what makes early-exit real instead of cosmetic. Endpoints left
        unprobed when the deadline hits are kept as-is (status_code stays
        None) rather than dropped — fail-open, same as elsewhere here."""
        results: List[Endpoint] = []

        def probe_one(ep: Endpoint) -> Endpoint:
            try:
                return self.probe.probe(ep)
            except Exception as e:
                log.debug("Probe failed %s: %s", ep.url, e)
                return ep

        chunk_size = max(self.threads * 4, 50)
        idx = 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            while idx < len(endpoints):
                if deadline is not None and time.monotonic() >= deadline:
                    log.warning("[deadline] probe budget exhausted — %d/%d "
                                "endpoint(s) left unprobed (kept unprobed)",
                                len(endpoints) - idx, len(endpoints))
                    results.extend(endpoints[idx:])
                    break
                chunk = endpoints[idx: idx + chunk_size]
                futures = {ex.submit(probe_one, ep): ep for ep in chunk}
                for fut in concurrent.futures.as_completed(futures):
                    results.append(fut.result())
                idx += len(chunk)

        probed = sum(1 for e in results if e.status_code is not None)
        accessible = sum(1 for e in results if e.accessible_unauthenticated)
        log.info("Probed: %d/%d reachable. Accessible without auth: %d",
                 probed, len(results), accessible)
        return results

    @staticmethod
    def _dedup(findings: List[Finding]) -> List[Finding]:
        seen: Dict[str, Finding] = {}
        for f in findings:
            key = f.dedup_key()
            if key not in seen:
                seen[key] = f
            else:
                # Merge tools list
                existing_tools = set(seen[key].tools)
                for t in f.tools:
                    existing_tools.add(t)
                seen[key].tools = list(existing_tools)
                # Keep highest severity
                if (SEVERITY_RANK.get(f.severity, 0) >
                        SEVERITY_RANK.get(seen[key].severity, 0)):
                    seen[key].severity = f.severity
        return sorted(seen.values(),
                      key=lambda x: -SEVERITY_RANK.get(x.severity, 0))

    def _write_findings(self, findings: List[Finding]) -> None:
        with open(self.findings_file, "w") as fh:
            for f in findings:
                fh.write(f.to_jsonl() + "\n")
        log.info("Wrote %d findings → %s", len(findings), self.findings_file)

    def _save_intel_snapshot(self, endpoints: List[Endpoint]) -> None:
        snap = self.intel_dir / "endpoints_snapshot.jsonl"
        with open(snap, "w") as fh:
            for ep in endpoints:
                # Ensure every endpoint carries its 13-step verdict + API flavour,
                # even ones that never reached the vuln classifier.
                url_type = ep.url_type or classify_url_type(ep)[0]
                api_type = ep.api_type or (classify_api_type(ep) if url_type == "API" else "")
                fh.write(json.dumps({
                    "url": ep.url,
                    "host": ep.host,
                    "path": ep.path,
                    "method": ep.method,
                    "status_code": ep.status_code,
                    "accessible_unauthenticated": ep.accessible_unauthenticated,
                    "auth_required": ep.auth_required,
                    "has_id_param": ep.has_id_param,
                    "is_sensitive": ep.is_sensitive,
                    "content_type": ep.content_type,
                    "response_length": ep.response_length,
                    "source": ep.source,
                    "url_type": url_type,
                    "api_type": api_type,
                }) + "\n")

    def _write_summary(self, endpoint_count: int, finding_count: int) -> None:
        summary_file = self.api_sec_dir / "intel_summary.json"
        with open(summary_file, "w") as fh:
            json.dump({
                "module": "api_intelligence",
                "endpoints_analyzed": endpoint_count,
                "findings": finding_count,
                "output": str(self.findings_file),
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            }, fh, indent=2)

    def emergency_flush(self) -> None:
        """Best-effort flush called from the SIGTERM handler. Last line of
        defense if the internal deadline check in ApiSecAdapter didn't fire
        in time (e.g. the pipeline's external cap is shorter than expected,
        or the kill lands mid-subprocess-wait). Writes whatever's in
        self._live_findings so far rather than losing it to SIGKILL."""
        try:
            deduped = self._dedup(list(self._live_findings))
            self._write_findings(deduped)
            self._write_summary(len(self._live_findings), len(deduped))
            log.warning("Emergency flush on SIGTERM: wrote %d finding(s)", len(deduped))
        except Exception as exc:
            log.warning("Emergency flush failed: %s", exc)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="ARISE API Intelligence Engine")
    parser.add_argument("scan_dir", help="Path to the scan output directory")
    parser.add_argument("--rate", type=int, default=84,
                        help="Global requests/sec ceiling across all threads "
                             "(default: 84, ~5000/min). 0 = unlimited.")
    parser.add_argument("--jitter", type=float, default=0.3,
                        help="Randomise inter-request spacing by ±this fraction "
                             "of the interval (default: 0.3) so timing isn't "
                             "perfectly uniform — a WAF/bot-detection signal. "
                             "0 = evenly spaced.")
    parser.add_argument("--timeout", type=int, default=8, help="HTTP timeout seconds (default: 8)")
    parser.add_argument("--threads", type=int, default=40, help="Parallel threads (default: 40)")
    parser.add_argument("--wordlist", help="Path to actions wordlist (optional)")
    parser.add_argument("--static-verify-cap", type=int, default=3000,
                        help="Max static-asset candidates to HTTP-verify in "
                             "Phase 1.5; above this, exclude by extension "
                             "without probing (default: 3000)")
    parser.add_argument("--deadline-seconds", type=int, default=None,
                        help="Internal wall-clock budget; the apisec.py "
                             "adapter (Phase 9) stops starting new hosts once "
                             "this elapses, so partial results still get "
                             "written before the pipeline's external timeout "
                             "kills the process. Pass this a bit below the "
                             "pipeline's cap (e.g. cap - 150s).")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    scan_dir = Path(args.scan_dir)
    if not scan_dir.exists():
        log.error("Scan directory not found: %s", scan_dir)
        sys.exit(1)

    wordlist = Path(args.wordlist) if args.wordlist else None

    engine = APIIntelligenceEngine(
        scan_dir=scan_dir,
        rate=args.rate,
        timeout=args.timeout,
        threads=args.threads,
        wordlist=wordlist,
        static_verify_cap=args.static_verify_cap,
        deadline_seconds=args.deadline_seconds,
        jitter=args.jitter,
    )

    def _on_sigterm(signum, frame):
        log.warning("Received SIGTERM — flushing partial findings before exit")
        engine.emergency_flush()
        os._exit(1)

    signal.signal(signal.SIGTERM, _on_sigterm)

    findings_count = engine.run()
    sys.exit(0 if findings_count >= 0 else 1)


if __name__ == "__main__":
    main()
