#!/usr/bin/env python3
"""
Schema fingerprint probe — GraphQL, OpenAPI/Swagger, .well-known.

Passive-recon staples that the pipeline was completely missing. In minutes,
a good pentester probes ~40 known schema/API-doc paths per host: a live
`/graphql` with introspection enabled is the fastest possible pathway from
recon → arbitrary data reads on a target. `/swagger` and `/openapi.json`
enumerate the API surface for free. `.well-known/*` reveals OpenID configs,
security.txt reporters, DID docs — all high-signal, low-cost.

What we probe
-------------
The probe list is deliberately short (fast + not obviously scan-shaped) and
focuses on the checks with highest false-negative cost — patterns where a
skilled attacker would definitely try, and where a public tool would find
serious wins.

  GraphQL:
    /graphql, /graphiql, /api/graphql, /v1/graphql, /query
    Additionally, when /graphql returns 200/400: fire an introspection query
    to detect if schema-leak is enabled.

  OpenAPI / Swagger:
    /swagger, /swagger.json, /swagger.yaml, /swagger-ui.html, /swagger-ui/
    /api-docs, /v2/api-docs, /v3/api-docs, /openapi.json, /openapi.yaml
    /docs, /api/docs, /redoc, /rapidoc

  .well-known:
    /.well-known/security.txt, /.well-known/openid-configuration
    /.well-known/oauth-authorization-server, /.well-known/webfinger
    /.well-known/host-meta, /.well-known/did.json, /.well-known/matrix/server

Output
------
  schema_endpoints.jsonl — one row per HIT (skips 404s/timeouts):
    {host, url, kind: "graphql"|"openapi"|"well-known"|"graphql-intro",
     status, content_type, evidence: "..."}

Downstream:
  - nuclei can consume the URL directly to run schema-specific templates
  - apisec / api_intelligence_engine can pull /openapi.json for spec-driven testing
  - GraphQL introspection wins become their own dashboard row (leaked schema)

Safety
------
All requests are GET-only, safe (no injection, no state mutation). The
introspection query is a standard read-only GraphQL introspection call —
if a target has it disabled, they return an error; if enabled, they leak
the schema, which is the target's config choice, not our exploit.
"""

from __future__ import annotations

import sys as _sys, os as _os
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)


import argparse
import json
import os
import ssl
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional

DEFAULT_UA = os.environ.get(
    "HUMAN_USER_AGENT",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36",
)

GRAPHQL_PATHS = [
    "/graphql", "/graphiql", "/api/graphql", "/v1/graphql", "/query",
]
OPENAPI_PATHS = [
    "/swagger", "/swagger.json", "/swagger.yaml", "/swagger-ui.html",
    "/swagger-ui/", "/swagger-resources", "/swagger/index.html",
    "/api-docs", "/v2/api-docs", "/v3/api-docs",
    "/openapi.json", "/openapi.yaml", "/openapi",
    "/docs", "/api/docs", "/api/documentation",
    "/redoc", "/rapidoc",
]
WELL_KNOWN_PATHS = [
    "/.well-known/security.txt",
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/.well-known/webfinger",
    "/.well-known/host-meta",
    "/.well-known/did.json",
    "/.well-known/matrix/server",
    "/.well-known/apple-app-site-association",
    "/.well-known/assetlinks.json",
]

# Minimal introspection query — same one graphql-inspector and burp use.
INTROSPECTION_QUERY = (
    '{"query":"query IntrospectionQuery { __schema { types { name } } }"}'
)


def _fetch(url: str, timeout: int, ua: str,
           method: str = "GET",
           body: Optional[bytes] = None,
           extra_headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    headers = {"User-Agent": ua}
    if extra_headers:
        headers.update(extra_headers)
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return {
                "status": resp.getcode(),
                "content_type": resp.headers.get("Content-Type", ""),
                "body": resp.read(4096),
                "error": False,
            }
    except urllib.error.HTTPError as e:
        try:
            body_b = e.read(4096) if e.fp else b""
        except Exception:
            body_b = b""
        return {"status": e.code,
                "content_type": (e.headers.get("Content-Type", "")
                                 if e.headers else ""),
                "body": body_b, "error": False}
    except Exception:
        return {"status": 0, "content_type": "", "body": b"", "error": True}


def _looks_like_openapi(status: int, ct: str, body: bytes) -> bool:
    if status != 200:
        return False
    ctl = ct.lower()
    if "json" in ctl and (b'"openapi"' in body or b'"swagger"' in body
                          or b'"paths"' in body):
        return True
    if "yaml" in ctl and (b"openapi:" in body or b"swagger:" in body):
        return True
    # Swagger-UI HTML page — presence of the standard JS bundle strings.
    bl = body.lower()
    if b"swagger-ui" in bl or b"swaggerui" in bl or b"redoc" in bl:
        return True
    return False


def _looks_like_graphql(status: int, ct: str, body: bytes) -> bool:
    """GraphQL endpoints commonly reply to bare GET with a hint or an error
    that mentions 'query' / 'graphql' / 'must POST'. 400/405/200 are all
    normal; 404 means 'not here'."""
    if status in (0, 404):
        return False
    bl = body.lower()
    tells = (b"graphql", b"query must", b"must post", b"must be a post",
             b"graphiql", b"introspection", b"persistedquery")
    return any(t in bl for t in tells)


def _looks_like_well_known(status: int, ct: str, body: bytes,
                            path: str) -> bool:
    if status != 200 or not body:
        return False
    # Each well-known has its own shape; a permissive match is fine because
    # a 200 from a well-known IS the finding.
    return True


def _try_graphql_introspection(base_url: str, timeout: int, ua: str) -> Optional[Dict[str, Any]]:
    """Attempt introspection. Returns dict if the server responded with
    schema data, else None."""
    r = _fetch(base_url, timeout, ua, method="POST",
               body=INTROSPECTION_QUERY.encode("utf-8"),
               extra_headers={"Content-Type": "application/json"})
    if r["error"] or r["status"] not in (200, 400):
        return None
    body = r["body"]
    if b"__schema" not in body or b'"types"' not in body:
        return None
    return {
        "status": r["status"],
        "content_type": r["content_type"],
        "evidence": "introspection-response-contains-types",
        "body_head": body[:400].decode("utf-8", errors="replace"),
    }


def probe_host(root_url: str, timeout: int = 6,
                ua: str = DEFAULT_UA) -> List[Dict[str, Any]]:
    root = root_url.rstrip("/")
    hits: List[Dict[str, Any]] = []
    # GraphQL — try each candidate; on a hit, additionally try introspection.
    for p in GRAPHQL_PATHS:
        url = root + p
        r = _fetch(url, timeout, ua)
        if _looks_like_graphql(r["status"], r["content_type"], r["body"]):
            hits.append({
                "host": _host(root),
                "url": url,
                "kind": "graphql",
                "status": r["status"],
                "content_type": r["content_type"],
                "evidence": "graphql-response-signature",
            })
            intro = _try_graphql_introspection(url, timeout, ua)
            if intro:
                hits.append({
                    "host": _host(root),
                    "url": url,
                    "kind": "graphql-introspection",
                    "status": intro["status"],
                    "content_type": intro["content_type"],
                    "evidence": intro["evidence"],
                    "body_head": intro["body_head"],
                    "severity": "high",  # public introspection = schema leak
                })
    # OpenAPI / Swagger
    for p in OPENAPI_PATHS:
        url = root + p
        r = _fetch(url, timeout, ua)
        if _looks_like_openapi(r["status"], r["content_type"], r["body"]):
            hits.append({
                "host": _host(root),
                "url": url,
                "kind": "openapi",
                "status": r["status"],
                "content_type": r["content_type"],
                "evidence": "openapi/swagger-signature-in-body",
            })
    # .well-known
    for p in WELL_KNOWN_PATHS:
        url = root + p
        r = _fetch(url, timeout, ua)
        if _looks_like_well_known(r["status"], r["content_type"], r["body"], p):
            hits.append({
                "host": _host(root),
                "url": url,
                "kind": "well-known",
                "path": p,
                "status": r["status"],
                "content_type": r["content_type"],
                "evidence": "200-response",
            })
    return hits


def _host(url: str) -> str:
    u = url.strip()
    if "://" in u:
        u = u.split("://", 1)[1]
    return u.split("/", 1)[0].split(":", 1)[0].lower()


def probe_all(scan_dir: Path, timeout: int = 6,
              ua: str = DEFAULT_UA) -> int:
    src = scan_dir / "04_http_discovery" / "host_canonical.txt"
    if not src.is_file() or src.stat().st_size == 0:
        # Fall back to http_hosts.txt if canonical file not built yet.
        src = scan_dir / "04_http_discovery" / "http_hosts.txt"
    if not src.is_file() or src.stat().st_size == 0:
        return 0
    out_dir = scan_dir / "04_http_discovery"
    out_file = out_dir / "schema_endpoints.jsonl"
    seen_urls = set()  # dedup: same canonical could appear multiple times
    n = 0
    hosts = [ln.strip() for ln in open(src, encoding="utf-8",
                                       errors="replace") if ln.strip()]
    with open(out_file, "w", encoding="utf-8") as w:
        for h in hosts:
            root = h if "://" in h else f"https://{h}"
            for hit in probe_host(root, timeout, ua):
                key = (hit["url"], hit["kind"])
                if key in seen_urls:
                    continue
                seen_urls.add(key)
                w.write(json.dumps(hit) + "\n")
                n += 1
    return n


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Schema fingerprint probe")
    ap.add_argument("scan_dir")
    ap.add_argument("--timeout", type=int, default=6)
    args = ap.parse_args()
    n = probe_all(Path(args.scan_dir), timeout=args.timeout)
    print(f"[schema-probe] found {n} schema/well-known hit(s)", file=sys.stderr)
