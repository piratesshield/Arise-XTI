#!/usr/bin/env python3
"""
ARISE — Shared URL Classification Primitives
============================================
Single source of truth for the path / Content-Type / body regexes and the
light (no-extra-request) classifiers that BOTH the API intelligence engine
(``api_intelligence_engine.py``) and the endpoint consolidator
(``endpoint_consolidator.py``, Module 8B) rely on.

Before this module the regexes lived only inside the engine, which runs AFTER
the attack modules — so the consolidator could not classify, and each attack
feeder re-derived its own targets with ad-hoc gf/grep. Centralising here lets
Module 8B classify every URL once, up front, and emit an attack-routing map the
downstream modules consume.

Two tiers of signal:
  * path-only        — always available (URL string alone)
  * path + response  — Content-Type / body, when a probe has been done

``classify_url()`` returns whatever it can from the signals given; missing
signals just yield "unknown"/None for the dimensions that need them, never an
error. The engine keeps its richer 13-step runtime tree (``classify_url_type``)
for the live-probe case; this module is the shared, request-free core.
"""

from __future__ import annotations

import sys as _sys, os as _os
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)


import re
import urllib.parse
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Path-shape regexes
# ---------------------------------------------------------------------------

API_PATH_RE = re.compile(
    r"(/api/|/v[0-9]+[./]|/graphql|/rest/|/ws/|/rpc/|/oauth|/token"
    r"|/auth|/login|/signin|/logout|/register|/signup|/user|/users"
    r"|/account|/profile|/admin|/internal|/webhook|/callback|/health"
    r"|/status|/metrics|/docs|/swagger|/openapi)",
    re.IGNORECASE,
)

SENSITIVE_PATH_RE = re.compile(
    r"(/admin|/internal|/debug|/config|/settings|/manage|/console"
    r"|/panel|/backdoor|/test|/dev|/staging|/private|/secret"
    r"|/backup|/dump|/export|/import|/upload|/download|/file)",
    re.IGNORECASE,
)

AUTH_PATH_RE = re.compile(
    r"(/login|/signin|/auth|/oauth|/token|/session|/register|/signup"
    r"|/forgot.?password|/reset.?password|/verify|/2fa|/mfa|/otp)",
    re.IGNORECASE,
)

# Extension-based static-asset flag (the effective definition; a path ending in
# one of these is a *candidate* asset — a live probe / Content-Type confirms).
STATIC_ASSET_RE = re.compile(
    r"\.(?:js|mjs|cjs|jsx|ts|tsx|css|scss|sass|less|map"
    r"|png|jpe?g|gif|svg|ico|webp|avif|bmp|tiff?|heic"
    r"|woff2?|ttf|otf|eot"
    r"|mp4|webm|ogg|ogv|mp3|wav|flac|m4a|avi|mov|mkv|wmv"
    r"|wasm|swf|vtt|srt)"
    r"(?:$|\?)",
    re.IGNORECASE,
)

_SWAGGER_PATH_RE = re.compile(
    r"/(?:swagger(?:\.json|-ui)?|openapi\.json|v\d+/api-docs|api-docs)", re.I)

# Reserved CDN/edge-vendor path prefixes — infrastructure the target never
# wrote, so injection-testing them is noise, not app coverage. Kept to
# unambiguous, universally-reserved prefixes (Cloudflare's /cdn-cgi/ is
# reserved across every Cloudflare-fronted site) rather than a broad guess.
_VENDOR_INFRA_PATH_RE = re.compile(r"^/cdn-cgi/", re.I)

_GRAPHQL_PATH_RE = re.compile(r"/(?:graphql|graphiql)(?:/|$)", re.I)

# Host-shape signal: a hostname label that starts or ends with "api" (api,
# apitest, oneapi, uatoneapi, mapi, bob-api, pp20api, staticapi, ...), or an
# exact graphql/gql/grpc label. Anchored to the WHOLE label (split on "." and
# "-") so a coincidental mid-word match never fires — "capital.payu.in"
# contains the substring "api" but its only label, "capital", neither starts
# nor ends with "api", so it correctly does not match.
_API_HOST_TOKEN_RE = re.compile(r"^(?:api\w*|\w*api)$", re.IGNORECASE)
_API_HOST_EXACT_RE = re.compile(r"^(?:graphql|gql|grpc)$", re.IGNORECASE)


def is_api_host(host: str) -> bool:
    """True if the hostname itself names it as an API host (api.*, *-api,
    oneapi.*, graphql.*, ...). Used as a fallback signal in url_class() for
    the common case where an API backend returns a non-2xx/empty-body
    response (no Content-Type to classify from) and its path doesn't happen
    to contain an /api/-style segment."""
    h = (host or "").split("@")[-1].split(":")[0].lower()
    tokens = [t for t in re.split(r"[.\-]", h) if t]
    return any(_API_HOST_TOKEN_RE.match(t) or _API_HOST_EXACT_RE.match(t) for t in tokens)

# ---------------------------------------------------------------------------
# AI / MCP surface detection — ORTHOGONAL to url_class.
# An MCP server is a JSON-RPC API; an OpenAI-compatible endpoint is a JSON API.
# Forcing them into a new mutually-exclusive url_class value would REMOVE them
# from the `api` class and break every consumer that routes on url_class=="api".
# So AI/MCP is an ADDITIONAL tag (ai_surface / ai_flavor / ai_confidence), never
# a url_class value. Confidence ladder, weakest→strongest:
#   path-hint   — host label or path shape only (informational, not a finding)
#   fingerprint — response header / body matched a known AI/MCP shape
#   confirmed   — stamped by discovery/mcp_ai_probe.py after a live MCP
#                 handshake (initialize/tools/list) or model-list 200; carried
#                 through classify_url() via the *_override params.
# ---------------------------------------------------------------------------

# MCP transport / discovery paths specific enough to tag on the path alone.
# `/messages`/`/message` (the legacy SSE POST-back) is DELIBERATELY excluded —
# it collides with every chat/social app's message inbox; the probe module
# confirms it from the SSE `event: endpoint` response instead.
MCP_PATH_RE = re.compile(
    r"(?:^|/)(?:"
    r"mcp"                                   # streamable-HTTP default endpoint
    r"|sse"                                  # legacy SSE stream
    r"|\.well-known/mcp(?:\.json)?"          # well-known discovery doc
    r"|\.well-known/mcp/[\w.-]+"
    r")(?:/|$)",
    re.IGNORECASE,
)

# OpenAI-compatible inference paths (vLLM/LiteLLM/LocalAI/gateways) — specific.
_LLM_OPENAI_RE = re.compile(
    r"/v1/(?:chat/completions|completions|embeddings|models)(?:/|$)", re.I)
# Ollama's distinctive management paths (NOT the generic /api/chat).
_LLM_OLLAMA_RE = re.compile(
    r"/api/(?:tags|ps|version|pull|show|generate)(?:/|$)", re.I)
# Triton Inference Server v2 model-repo / readiness paths.
_LLM_TRITON_RE = re.compile(
    r"/v2/(?:models|health/(?:ready|live))(?:/|$)|/v2/models$", re.I)
# LangServe / agent-framework schema + playground routes (distinctive).
_AI_LANGSERVE_RE = re.compile(
    r"/(?:input_schema|output_schema|config_schema|playground)(?:/|$)", re.I)
# Gradio UI/API routes.
_AI_GRADIO_RE = re.compile(
    r"/(?:run/predict|api/predict|queue/join|gradio_api)(?:/|$)", re.I)
# Flowise / Dify / Langflow style prediction routes.
_AI_APPFLOW_RE = re.compile(r"/api/v1/(?:prediction|chatmessage)/", re.I)

# Convenience aggregate (used by the probe module's passive marker + tests).
LLM_PATH_RE = re.compile(
    r"/v1/(?:chat/completions|completions|embeddings|models)(?:/|$)"
    r"|/api/(?:tags|ps|version|pull|show|generate)(?:/|$)"
    r"|/v2/(?:models|health/ready)(?:/|$)"
    r"|/(?:input_schema|output_schema|config_schema|playground)(?:/|$)"
    r"|/(?:run/predict|api/predict|queue/join|gradio_api)(?:/|$)",
    re.IGNORECASE,
)

# AI/MCP host labels — matched WHOLE-LABEL (split on '.' and '-'), never a
# mid-word substring, so 'mailchimp', 'chairman', 'airtable' do NOT match.
# The ambiguous-with-plain-English labels (ml, model, models, infer) are left
# out on purpose; everything here doubles as a subdomain-brute affix (Phase 1).
_MCP_HOST_LABELS = {"mcp"}
_VECTOR_HOST_LABELS = {"vector", "vectordb", "qdrant", "weaviate", "milvus",
                       "pinecone", "embeddings"}
_AIAGENT_HOST_LABELS = {"copilot", "assistant", "chatbot", "genai", "agent",
                        "agents", "bot", "chat", "rag"}
_LLM_HOST_LABELS = {"ai", "llm", "llms", "gpt", "ollama", "vllm", "inference",
                    "aiapi"}


def _ai_host_label(host: str) -> Optional[str]:
    """Surface guessed purely from the hostname labels (path-hint tier)."""
    h = (host or "").split("@")[-1].split(":")[0].lower()
    labels = {t for t in re.split(r"[.\-]", h) if t}
    if labels & _MCP_HOST_LABELS:
        return "mcp"
    if labels & _VECTOR_HOST_LABELS:
        return "vector-db"
    if labels & _AIAGENT_HOST_LABELS:
        return "ai-agent"
    if labels & _LLM_HOST_LABELS:
        return "llm-api"
    return None


# Response-body / header fingerprints (fingerprint tier).
_MCP_BODY_RE = re.compile(
    r'"(?:protocolVersion|serverInfo)"\s*:'
    r'|"jsonrpc"\s*:\s*"2\.0"[\s\S]{0,400}?"(?:tools|resources|prompts|capabilities)"',
    re.I)
_MODEL_OBJ_RE = re.compile(r'"object"\s*:\s*"model"', re.I)         # OpenAI model list
_OLLAMA_BODY_RE = re.compile(r'"models"\s*:\s*\[', re.I)            # /api/tags
_OLLAMA_VER_RE = re.compile(r'"version"\s*:\s*"\d+\.\d+', re.I)      # /api/version


def ai_surface(url_or_path: str, *, host: str = "", content_type: str = "",
               body: str = "", headers: Optional[Dict] = None,
               host_label: bool = True
               ) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """Detect an AI/MCP surface from request-free + optional probe signals.
    Returns (surface, flavor, confidence); (None, None, None) when not AI/MCP.

    surface: mcp | llm-api | ai-agent | vector-db | ai-gateway
    flavor:  free detail (mcp-streamable | mcp-sse | openai-compat | ollama |
             triton | langserve | gradio | …) | None
    confidence: path-hint | fingerprint   (never 'confirmed' here — the probe
             module stamps that and passes it through classify_url overrides).

    `host_label` controls the WEAKEST signal — tagging purely because the
    hostname is AI-named (mcp.*, ai.*, llm.*). That is a HOST/ASSET attribute,
    not a per-URL one: an MCP-named host serves hundreds of ordinary URLs, and
    tagging every one of them floods the URL inventory. So PER-URL callers
    (classify_url, the consolidator, the probe's passive pass) pass
    host_label=False — a URL is AI-tagged only when its PATH or BODY is
    AI-shaped. ASSET-level callers (internet_intel, the Assets table) use the
    host label separately via ai_host_label()."""
    raw = url_or_path or ""
    path = _path_only(raw).lower()
    ctype = (content_type or "").lower()
    body = body or ""
    hdrs = {str(k).lower(): str(v) for k, v in (headers or {}).items()}

    # --- strongest available here: header / body fingerprints ---
    if "mcp-session-id" in hdrs:
        return ("mcp", "mcp-streamable", "fingerprint")
    if _MCP_BODY_RE.search(body):
        return ("mcp", "mcp-jsonrpc", "fingerprint")
    if "event-stream" in ctype and MCP_PATH_RE.search(path):
        return ("mcp", "mcp-sse", "fingerprint")
    if _MODEL_OBJ_RE.search(body) and _LLM_OPENAI_RE.search(path):
        return ("llm-api", "openai-compat", "fingerprint")
    if (_OLLAMA_BODY_RE.search(body) or _OLLAMA_VER_RE.search(body)) \
            and _LLM_OLLAMA_RE.search(path):
        return ("llm-api", "ollama", "fingerprint")

    # --- path shape (specific paths → path-hint) ---
    if MCP_PATH_RE.search(path):
        if re.search(r"(?:^|/)sse(?:/|$)", path):
            flavor = "mcp-sse"
        elif re.search(r"(?:^|/)mcp(?:/|$)", path):
            flavor = "mcp-streamable"
        else:
            flavor = "mcp-wellknown"
        return ("mcp", flavor, "path-hint")
    if _LLM_OPENAI_RE.search(path):
        return ("llm-api", "openai-compat", "path-hint")
    if _LLM_OLLAMA_RE.search(path):
        return ("llm-api", "ollama", "path-hint")
    if _LLM_TRITON_RE.search(path):
        return ("llm-api", "triton", "path-hint")
    if _AI_LANGSERVE_RE.search(path):
        return ("ai-agent", "langserve", "path-hint")
    if _AI_GRADIO_RE.search(path):
        return ("ai-agent", "gradio", "path-hint")
    if _AI_APPFLOW_RE.search(path):
        return ("ai-agent", "appflow", "path-hint")

    # --- host label (weakest → path-hint) — asset-level only (see docstring) ---
    if host_label:
        hl = _ai_host_label(host)
        if hl:
            flavor = {"mcp": "mcp-host", "vector-db": "vector-host",
                      "ai-agent": "agent-host", "llm-api": "llm-host"}.get(hl)
            return (hl, flavor, "path-hint")

    return (None, None, None)


# Public alias for asset-level host-label tagging (internet_intel.py, dashboard).
def ai_host_label(host: str) -> Optional[str]:
    """AI/MCP surface guessed from the hostname labels alone — a HOST attribute.
    Returns mcp | llm-api | ai-agent | vector-db, or None."""
    return _ai_host_label(host)


_AI_CONF_RANK = {None: 0, "": 0, "path-hint": 1, "fingerprint": 2, "confirmed": 3}

# ---------------------------------------------------------------------------
# Content-Type / body regexes
# ---------------------------------------------------------------------------

STATIC_CONTENT_TYPE_RE = re.compile(
    r"^\s*(?:"
    r"text/(?:javascript|css)"
    r"|application/(?:javascript|x-javascript|ecmascript|wasm"
    r"|font-woff2?|x-font-\w+|vnd\.ms-fontobject|octet-stream"
    # PDF is unambiguously never an API response type — its reachability is
    # never itself an access-control finding (F34, ARISE_REMEDIATION_ROADMAP.md:
    # a marketing PDF was flagged "sensitive_endpoint_exposed" purely because
    # its URL path contained a generic /download or /file segment).
    r"|pdf)"
    r"|image/|font/|video/|audio/"
    r")",
    re.IGNORECASE,
)

API_CONTENT_TYPE_RE = re.compile(
    r"(?:"
    r"application/(?:json|.*\+json|ld\+json|x-ndjson"
    r"|xml|.*\+xml"
    r"|grpc(?:\+proto|-web)?|(?:x-)?protobuf|x-google-protobuf"
    r"|octet-stream|pdf|zip|x-zip-compressed"
    r"|vnd\.ms-excel|vnd\.openxmlformats)"
    r"|text/(?:xml|csv|event-stream)"
    r")",
    re.IGNORECASE,
)

_JSON_BODY_RE = re.compile(r"^\s*[\[{]")
_XML_BODY_RE = re.compile(
    r"^\s*<\?xml|^\s*<(?!!doctype\s+html|html|head|body|div|script|meta|link|!--)[a-zA-Z]",
    re.IGNORECASE)

_GRAPHQL_BODY_RE = re.compile(r'"(?:data|errors)"\s*:', re.I)
_SOAP_BODY_RE = re.compile(r"<(?:soap(?:env)?|env):envelope", re.I)
_JSONRPC_BODY_RE = re.compile(r'"jsonrpc"\s*:\s*"2\.0"', re.I)
_ODATA_RE = re.compile(r'(?:/odata/|\$metadata|"@odata\.)', re.I)

# ---------------------------------------------------------------------------
# Identifier / token regexes (URL-shape)
# ---------------------------------------------------------------------------

_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")

ID_SEGMENT_RE = re.compile(
    r"^(\d{5,}|[0-9a-fA-F]{8,}|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}"
    r"-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|[A-Za-z0-9_-]{20,})$"
)

JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")


# ---------------------------------------------------------------------------
# Cloud storage host detection (S3 / Azure Blob / GCS / R2 / Spaces / B2 / OSS /
# COS). A cloud bucket URL surfaced during a target's crawl / JS / runtime is
# almost always OWNED-BY or REFERENCED-BY the target even though its host lives
# on a provider domain, not a subdomain of the target. The URL inventory keeps
# such URLs (they'd otherwise be scope-dropped), classes them 'cloud-storage',
# and attributes them back to the scoped target so buckets are visible.
# ---------------------------------------------------------------------------
CLOUD_HOST_RE = re.compile(
    r"(?i)("
    r"\.s3\.amazonaws\.com"                          # bucket.s3.amazonaws.com (vhost)
    r"|(?:^|\.|//)s3[.-][a-z0-9-]+\.amazonaws\.com"  # s3.region…/bucket & bucket.s3.region…
    r"|(?:^|\.|//)s3-website[.-][a-z0-9-]+\.amazonaws\.com"
    r"|\.blob\.core\.windows\.net"                   # azure blob
    r"|\.file\.core\.windows\.net"
    r"|(?:^|\.|//)storage\.googleapis\.com"          # gcs (path- and vhost-style)
    r"|\.r2\.cloudflarestorage\.com"                 # cloudflare r2
    r"|\.digitaloceanspaces\.com"                    # do spaces
    r"|\.backblazeb2\.com|\.s3\.[a-z0-9-]+\.backblazeb2\.com"  # backblaze b2
    r"|\.oss-[a-z0-9-]+\.aliyuncs\.com"              # alibaba oss
    r"|\.cos\.[a-z0-9-]+\.myqcloud\.com"             # tencent cos
    r")"
    # NB: the bare, region-less global endpoint `s3.amazonaws.com/<bucket>` is
    # deliberately NOT matched. AWS deprecated it, and it is the exact vector by
    # which the API base-path seeder fabricates junk (`s3.amazonaws.com/api`,
    # `/graphql`, `/swagger.json`) — real buckets use a regional or vhost form.
)


def _host_of(url_or_host: str) -> str:
    s = url_or_host or ""
    if "://" in s or "/" in s:
        try:
            netloc = urllib.parse.urlsplit(s if "://" in s else "//" + s).netloc
            return netloc.split(":")[0].lower()
        except Exception:
            return s.lower()
    return s.lower()


def is_cloud_storage(url_or_host: str) -> bool:
    """True if the host is a known cloud object-storage endpoint."""
    return bool(CLOUD_HOST_RE.search(url_or_host or ""))


def cloud_provider(url_or_host: str) -> Optional[str]:
    """Canonical provider slug for a cloud-storage host, else None."""
    h = _host_of(url_or_host)
    if "amazonaws.com" in h and "s3" in h:
        return "aws-s3"
    if "blob.core.windows.net" in h or "file.core.windows.net" in h:
        return "azure-blob"
    if "storage.googleapis.com" in h:
        return "gcp-gcs"
    if "r2.cloudflarestorage.com" in h:
        return "cloudflare-r2"
    if "digitaloceanspaces.com" in h:
        return "do-spaces"
    if "backblazeb2.com" in h:
        return "backblaze-b2"
    if "aliyuncs.com" in h:
        return "alibaba-oss"
    if "myqcloud.com" in h:
        return "tencent-cos"
    return None


def cloud_bucket(url: str) -> Optional[str]:
    """Extract the bucket/container name from a cloud-storage URL, handling both
    virtual-hosted (bucket.s3….) and path-style (s3…./bucket) layouts."""
    try:
        p = urllib.parse.urlsplit(url if "://" in url else "https://" + url)
        host = p.netloc.split(":")[0].lower()
        path = p.path or ""
    except Exception:
        return None
    # path-style: s3.region.amazonaws.com/<bucket>, storage.googleapis.com/<bucket>
    if (host.startswith(("s3.", "s3-")) and "amazonaws.com" in host) \
            or host == "storage.googleapis.com" \
            or host.startswith("storage.googleapis.com"):
        segs = [s for s in path.split("/") if s]
        return segs[0] if segs else None
    # virtual-hosted: leading label(s) before the provider suffix
    for suffix in (".s3.", ".s3-", ".blob.core.windows.net",
                   ".file.core.windows.net", ".storage.googleapis.com",
                   ".r2.cloudflarestorage.com", ".digitaloceanspaces.com",
                   ".backblazeb2.com", ".oss-", ".cos."):
        idx = host.find(suffix)
        if idx > 0:
            return host[:idx]
    seg = host.split(".")[0]
    return seg or None


# ---------------------------------------------------------------------------
# API flavour — shared core (path + Content-Type + body, no extra request)
# ---------------------------------------------------------------------------

def api_flavour(path: str, content_type: str = "", body: str = "") -> str:
    """Return the API flavour for an endpoint already judged 'API':
    graphql | soap | grpc | jsonrpc | odata | sse | rest-json | rest-xml |
    binary | api-unknown. Uses path, Content-Type and body only."""
    path = (path or "").lower()
    ctype = (content_type or "").lower()
    body = body or ""

    if _GRAPHQL_PATH_RE.search(path) or _GRAPHQL_BODY_RE.search(body):
        return "graphql"
    if "grpc" in ctype or "protobuf" in ctype:
        return "grpc"
    if "soap+xml" in ctype or _SOAP_BODY_RE.search(body):
        return "soap"
    if _JSONRPC_BODY_RE.search(body):
        return "jsonrpc"
    if _ODATA_RE.search(path) or _ODATA_RE.search(body):
        return "odata"
    if "event-stream" in ctype:
        return "sse"
    if "json" in ctype or _JSON_BODY_RE.match(body.lstrip()):
        return "rest-json"
    if "xml" in ctype or _XML_BODY_RE.match(body.lstrip()):
        return "rest-xml"
    if API_CONTENT_TYPE_RE.search(ctype):
        return "binary"
    return "api-unknown"


# ---------------------------------------------------------------------------
# Light per-dimension classifiers (request-free)
# ---------------------------------------------------------------------------

def is_static_path(url_or_path: str) -> bool:
    """True if the path *looks like* a static asset by extension (candidate)."""
    try:
        path = urllib.parse.urlsplit(url_or_path).path or url_or_path
    except Exception:
        path = url_or_path
    return bool(STATIC_ASSET_RE.search(path))


# A raw path segment is an OBJECT IDENTIFIER (not a human-readable content slug)
# only when it is numeric, a UUID, a long hex hash, or a high-entropy opaque
# token that CONTAINS A DIGIT. The digit requirement is what separates an id
# from a slug: `reliance-industries-ltd` / `hdfc-mid-cap-direct-growth` are all
# letters+hyphens -> NOT ids; `nse_crudeoil26aug7150pe` / `a1b2c3d4e5f6...` are.
# (ID_SEGMENT_RE's bare `[A-Za-z0-9_-]{20,}` matched slugs, over-routing them to
# sqli/bola.)
_RAW_ID_RE = re.compile(
    r"^(?:"
    r"\d{5,}"                                          # numeric id
    r"|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}"
    r"-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"                 # uuid
    r"|[0-9a-fA-F]{12,}"                               # long hex hash
    r"|(?=[A-Za-z0-9_-]*\d)[A-Za-z0-9_-]{16,}"         # opaque token, 16+, has a digit
    r")$"
)


def _is_id_segment(seg: str) -> bool:
    return (seg.startswith("{") and seg.endswith("}")) or bool(_RAW_ID_RE.match(seg))


def url_shape(url: str) -> str:
    """One of: static | tokenized | path-param | query-param | plain.
    Precedence: JWT token anywhere > static asset extension > path identifier >
    query string > plain route. Static wins over query so a cache-busted asset
    (`/app.js?v=9`) reads 'static', matching its 'static-asset' url_class."""
    try:
        parsed = urllib.parse.urlsplit(url)
    except Exception:
        return "plain"
    path = parsed.path or "/"
    segs = [s for s in path.split("/") if s]

    if JWT_RE.search(url):
        return "tokenized"
    if STATIC_ASSET_RE.search(path):
        return "static"
    for s in segs:
        if _is_id_segment(s):
            return "path-param"
    if parsed.query:
        return "query-param"
    return "plain"


def sensitivity(path_or_url: str) -> str:
    """'sensitive' when the path hits an admin/internal/backup-style route."""
    return "sensitive" if SENSITIVE_PATH_RE.search(path_or_url or "") else "normal"


# Boundary-anchored auth-endpoint detector. The shared AUTH_PATH_RE (used by the
# engine) matches `/auth` as a plain substring, so `/authors`, `/author/{id}`,
# `/oauthorization-guide` are wrongly flagged as auth. \b word-boundaries fix
# that while still matching `/user-login`, `/reset-password`, `/sessions`.
AUTH_ENDPOINT_RE = re.compile(
    r"\b(?:"
    r"login|signin|logout|signout|"
    r"oauth2?|sso|sessions?|tokens?|"
    r"register|signup|"
    r"forgot[-_]?password|reset[-_]?password|"
    r"2fa|mfa|otp|"
    r"authenticate|authentication|authorize|authorization|auth|verify"
    r")\b",
    re.IGNORECASE,
)


def _path_only(path_or_url: str) -> str:
    s = path_or_url or ""
    if "://" in s:
        try:
            return urllib.parse.urlsplit(s).path or "/"
        except Exception:
            return s
    return s


def auth_state(path_or_url: str, status: Optional[int] = None) -> str:
    """auth-endpoint | auth-required | public | unknown.
    Path shape identifies login/token endpoints; a 401/403 status marks a
    protected resource; a 2xx marks a public one."""
    # Strip templated id placeholders first: the consolidator collapses opaque
    # slugs to `{token}`/`{id}`, and a `{token}` slot on `/blog/{token}` is an
    # instance identifier, NOT the OAuth `/token` endpoint — matching the word
    # inside the placeholder would wrongly flag blog/category pages as auth.
    path = re.sub(r"\{[^}]*\}", "", _path_only(path_or_url))
    if AUTH_ENDPOINT_RE.search(path):
        return "auth-endpoint"
    if status in (401, 403):
        return "auth-required"
    if status and 200 <= status < 400:
        return "public"
    return "unknown"


# ---------------------------------------------------------------------------
# Input-function classification — what a form / runtime request lets a user do.
# Shared by input_discovery.py (CDP) so the "Input Functions" inventory column
# and any HTML-form fallback tag identically.
# ---------------------------------------------------------------------------
_SEARCH_PARAMS = {"q", "query", "search", "keyword", "keywords", "term", "s", "text"}
_PAYMENT_PARAMS = {"card", "cardnumber", "cc", "cvv", "cvc", "expiry", "amount",
                   "price", "currency", "paymentmethod", "upi", "vpa"}
_CONTACT_PARAMS = {"message", "subject", "inquiry", "feedback", "body", "comment"}
_PROFILE_PARAMS = {"bio", "avatar", "displayname", "phone", "address", "firstname",
                   "lastname", "dob", "gender"}
_FILTER_PARAMS = {"sort", "order", "filter", "from", "to", "start", "end", "date",
                  "range", "page", "limit", "offset", "category", "cat"}
_OTP_PARAMS = {"otp", "code", "pin", "token", "2fa", "mfa"}


def input_function(url: str, *, method: str = "GET", enctype: str = "",
                   params: Optional[List[str]] = None, accepts_file: bool = False,
                   controls: Optional[List[Dict]] = None) -> str:
    """Classify one input surface (form or runtime request) into a function:
    upload | login | register | password-reset | otp | search | payment |
    contact | profile | filter | comment | form-submit | input.
    Uses path shape, param names, method/enctype and control types."""
    path = (urllib.parse.urlsplit(url).path if "://" in url else url).lower()
    pset = {(p or "").lower() for p in (params or [])}
    ctypes = {(c.get("type") or "").lower() for c in (controls or [])}
    has_pw = "password" in ctypes or "password" in pset or any("password" in p for p in pset)
    m = (method or "GET").upper()

    # 1. File upload — strongest, most security-relevant signal
    if accepts_file or "multipart" in (enctype or "").lower() or "file" in ctypes:
        return "upload"
    # 2. Auth family (path + password field + param names)
    if re.search(r"\b(?:register|signup|sign-up|create[-_]?account)\b", path) or \
            (pset & {"confirmpassword", "password_confirm", "repassword"}):
        return "register"
    if re.search(r"\b(?:forgot[-_]?password|reset[-_]?password|recover)\b", path):
        return "password-reset"
    if (pset & _OTP_PARAMS) and re.search(r"\b(?:otp|verify|2fa|mfa|pin)\b", path):
        return "otp"
    if has_pw or re.search(r"\b(?:login|signin|sign-in|auth|token|session)\b", path):
        return "login"
    # 3. Payment / checkout
    if (pset & _PAYMENT_PARAMS) or re.search(r"\b(?:payment|checkout|billing|pay)\b", path):
        return "payment"
    # 4. Search
    if (pset & _SEARCH_PARAMS) or "search" in ctypes or re.search(r"\b(?:search|lookup|find|autocomplete|suggest)\b", path):
        return "search"
    # 5. Contact / comment (free-text body)
    if (pset & _CONTACT_PARAMS) or "textarea" in ctypes or re.search(r"\b(?:contact|feedback|support|comment|review|message)\b", path):
        return "contact" if re.search(r"\b(?:contact|feedback|support)\b", path) else "comment"
    # 6. Profile / account update
    if (pset & _PROFILE_PARAMS) or re.search(r"\b(?:profile|account|settings|edit)\b", path):
        return "profile"
    # 7. Filter / analytics query
    if pset & _FILTER_PARAMS:
        return "filter"
    # 8. Any state-changing submit
    if m in ("POST", "PUT", "PATCH", "DELETE"):
        return "form-submit"
    return "input"


def url_class(path: str, status: Optional[int] = None,
              content_type: str = "", body: str = "",
              source: str = "", host: str = "") -> str:
    """web-page | api | static-asset | unknown — request-free approximation of
    the engine's 13-step tree, using only path + (optional) Content-Type/body.

    The engine's live tree stays authoritative when a full probe exists; this is
    the up-front call the consolidator makes so the inventory is classified
    before the attack modules run."""
    ctype = (content_type or "").lower()
    body = body or ""

    # 1. static asset (path extension or asset Content-Type) — but NOT when the
    # path sits under an API route. `/api/export.pdf`, `/v2/report.xlsx?id=1`
    # and friends are dynamic endpoints that happen to end in a static-looking
    # extension; treating them as inert static files hides real download/IDOR/
    # injection surface. API-routed paths fall through to the API checks below.
    if (STATIC_ASSET_RE.search(path or "") or STATIC_CONTENT_TYPE_RE.search(ctype)) \
            and not API_PATH_RE.search(path or ""):
        return "static-asset"
    # 2. explicit API shapes on the path
    if _SWAGGER_PATH_RE.search(path or "") or _GRAPHQL_PATH_RE.search(path or ""):
        return "api"
    # 3. API media type on the response
    if ctype and API_CONTENT_TYPE_RE.search(ctype):
        return "api"
    # 4. structured body
    stripped = body.lstrip()
    if stripped and (_JSON_BODY_RE.match(stripped) or _XML_BODY_RE.match(stripped)):
        return "api"
    # 5. HTML response -> web page
    if "html" in ctype:
        return "web-page"
    # 6. runtime-discovered (fetch/xhr) -> API
    if source and any(s in source.lower() for s in ("api-runtime", "xhr", "fetch", "js")):
        return "api"
    # 7. API-ish path, or API-named host, with no contradicting Content-Type.
    # The host check only fires here (never earlier) so a genuinely static
    # file on an API host (api.example.com/favicon.ico) still classifies via
    # step 1 first — this step is purely the "nothing else matched" fallback.
    if API_PATH_RE.search(path or "") or (host and is_api_host(host)):
        return "api"
    return "unknown"


# ---------------------------------------------------------------------------
# Attack routing — which classified URL feeds which attack module
# ---------------------------------------------------------------------------

def route_attacks(cls: Dict) -> List[str]:
    """Given a classification dict (from classify_url), return the list of
    attack lanes this URL should be fed to. Mirrors the routing table in the
    URL-Inventory roadmap; downstream modules read their own lane instead of
    re-grepping. Static assets are routed nowhere."""
    routes: List[str] = []
    uc = cls.get("url_class")
    shape = cls.get("url_shape")
    atype = cls.get("api_type")
    auth = cls.get("auth_state")
    sens = cls.get("sensitivity")
    methods = cls.get("http_methods") or []

    if uc == "static-asset":
        return routes
    # CDN/vendor-reserved infrastructure paths, served on the target's own
    # hostname but never the target's application code — routing these into
    # injection lanes can't find a real bug in the app, only edge-vendor
    # noise. F33 (ARISE_REMEDIATION_ROADMAP.md): Cloudflare's own /cdn-cgi/rum
    # analytics beacon (query-param-bearing, so `has_query` routes it to sqli
    # like any other parameterised URL) was flagged as critical SQL injection
    # five times across three Cloudflare-fronted hosts — the differential
    # "true vs false" behaviour it produced had nothing to do with a database.
    if _VENDOR_INFRA_PATH_RE.match(cls.get("path", "") or ""):
        return routes
    # Cloud buckets go to the cloud-review lane (public-ACL / listing / takeover
    # checks by the cloud modules), never to web/API injection lanes.
    if uc == "cloud-storage":
        return ["cloud-review"]

    is_api = uc == "api"
    is_web = uc == "web-page"
    has_query = shape == "query-param"
    has_pathid = shape == "path-param"

    # XSS (dalfox, M13): query params on a rendered web surface
    if has_query and (is_web or uc == "unknown"):
        routes.append("xss")
    # SQLi (sqlmap, M15/M20.1): any parameterised surface
    if has_query or has_pathid:
        routes.append("sqli")
    # SSTI / LFI (sstimap, ffuf, M19/M11): query values
    if has_query:
        routes.append("ssti-lfi")
    # SSRF (M19): query params (value-level url-like check done in-module)
    if has_query:
        routes.append("ssrf")
    # GraphQL introspection (graphw00f, M19)
    if atype == "graphql":
        routes.append("graphql")
    # Auth / JWT (M19 + engine): auth endpoints or tokenised URLs
    if auth == "auth-endpoint" or shape == "tokenized":
        routes.append("auth-jwt")
    # API black-box (apisec.py, M16): every API URL
    if is_api:
        routes.append("api-blackbox")
    # BOLA/object-auth candidate: API + object id in path
    if is_api and has_pathid:
        routes.append("bola")
    # Version-swap inventory (gap lane): versioned API path
    if is_api and re.search(r"/v[0-9]+([./]|$)", cls.get("path", "") or ""):
        routes.append("version-swap")
    # Dangerous-method check: write methods advertised
    if any(m in ("PUT", "DELETE", "PATCH") for m in methods):
        routes.append("dangerous-methods")
    # Sensitive path always worth secrets/nuclei attention
    if sens == "sensitive":
        routes.append("sensitive-review")

    # AI / MCP lanes — additive, fire ONLY when the orthogonal ai_surface tag is
    # set, so non-AI URLs are byte-for-byte unchanged. The *-injection/*-ssrf/
    # *-dos lanes are routing labels only; the active module (mcp_ai_probe.py)
    # decides whether to actually fire them, gated by MCP_AI_ACTIVE.
    surface = cls.get("ai_surface")
    if surface:
        routes.append("mcp-recon" if surface == "mcp" else "ai-recon")
        routes.append("ai-auth")                 # posture: unauth / weak-auth (safe)
        routes.append("ai-prompt-injection")     # LLM01 (gated active)
        if surface in ("mcp", "ai-agent"):
            routes.append("ai-ssrf")             # tool/param SSRF (gated active)
        if surface in ("mcp", "llm-api", "ai-gateway"):
            routes.append("ai-dos")              # unbounded consumption / JSON-RPC batch
    return routes


def classify_url(url: str, *, status: Optional[int] = None,
                 content_type: str = "", body: str = "",
                 source: str = "", http_methods: Optional[List[str]] = None,
                 path: str = "", attributed_to: str = "",
                 headers: Optional[Dict] = None,
                 ai_surface_override: Optional[str] = None,
                 ai_flavor_override: Optional[str] = None,
                 ai_confidence_override: Optional[str] = None) -> Dict:
    """Full request-free classification of one URL into the URL-Inventory schema.
    Pass whatever signals are available; absent signals degrade gracefully.
    `path` may be given explicitly (e.g. a templated path) to classify the
    template rather than the concrete sample URL. `attributed_to` is the scoped
    target a cloud-storage URL maps back to.

    The `ai_*_override` params let the probe module (discovery/mcp_ai_probe.py)
    pass a stronger, handshake-'confirmed' AI/MCP tag that upgrades whatever the
    request-free detector computes here. The orthogonal ai_surface/ai_flavor/
    ai_confidence keys are ALWAYS present (default None) so the record schema is
    uniform and every existing consumer is unaffected."""
    p = path or (urllib.parse.urlsplit(url).path or "/")
    host = _host_of(url)

    # Cloud storage is decided on the HOST ONLY (never the path/query — a normal
    # in-scope URL that carries an s3.amazonaws.com link in a ?img= parameter is
    # NOT a bucket). Cloud wins over the path-only url_class: a bucket object
    # ending .jpg is cloud, not 'static'.
    if is_cloud_storage(host):
        uc = "cloud-storage"
        provider = cloud_provider(host)
        bucket = cloud_bucket(url)
    else:
        uc = url_class(p, status=status, content_type=content_type,
                       body=body, source=source, host=host)
        provider = None
        bucket = None

    # AI/MCP orthogonal tag — compute from the signals we have, then let a
    # caller-supplied (handshake-confirmed) override win when it is at least as
    # strong. Never computed for cloud-storage URLs (a bucket is not an AI host).
    if uc == "cloud-storage":
        a_surface = a_flavor = a_conf = None
    else:
        a_surface, a_flavor, a_conf = ai_surface(
            url, host=host, content_type=content_type, body=body, headers=headers,
            host_label=False)   # per-URL = path/body only (host-label is asset-level)
    if ai_surface_override and \
            _AI_CONF_RANK.get(ai_confidence_override, 1) >= _AI_CONF_RANK.get(a_conf, 0):
        a_surface = ai_surface_override
        a_flavor = ai_flavor_override or a_flavor
        a_conf = ai_confidence_override or "path-hint"

    cls: Dict = {
        "url_class": uc,
        "api_type": api_flavour(p, content_type, body) if uc == "api" else None,
        "http_methods": sorted(set(http_methods or [])),
        "url_shape": url_shape(url),
        "sensitivity": sensitivity(p),
        "auth_state": auth_state(p, status),
        "cloud_provider": provider,
        "cloud_bucket": bucket,
        "attributed_to": (attributed_to or None) if uc == "cloud-storage" else None,
        # AI / MCP surface (orthogonal to url_class; None on non-AI URLs)
        "ai_surface": a_surface,
        "ai_flavor": a_flavor if a_surface else None,
        "ai_confidence": a_conf if a_surface else None,
        "path": p,
    }
    cls["routed_to"] = route_attacks(cls)
    return cls


# ---------------------------------------------------------------------------
# Drift guard — assert the shared regexes still match the engine's, when it is
# importable. Run: python3 url_classify.py
# ---------------------------------------------------------------------------

def _parity_check() -> int:
    try:
        import api_security.api_intelligence_engine as eng
    except Exception as e:  # engine has heavy optional deps; skip if unavailable
        print(f"[url_classify] engine not importable, parity skipped: {e}")
        return 0
    shared = [
        "API_PATH_RE", "SENSITIVE_PATH_RE", "AUTH_PATH_RE",
        "STATIC_ASSET_RE", "STATIC_CONTENT_TYPE_RE", "API_CONTENT_TYPE_RE",
        "_JSON_BODY_RE", "_XML_BODY_RE", "_UUID_RE", "ID_SEGMENT_RE",
        "JWT_RE", "_GRAPHQL_PATH_RE", "_GRAPHQL_BODY_RE", "_SOAP_BODY_RE",
        "_JSONRPC_BODY_RE", "_ODATA_RE", "_SWAGGER_PATH_RE",
    ]
    bad = []
    for name in shared:
        a = globals().get(name)
        b = getattr(eng, name, None)
        if b is None:
            continue
        if a is not b and getattr(a, "pattern", None) != getattr(b, "pattern", None):
            bad.append(name)
    if bad:
        print(f"[url_classify] DRIFT DETECTED vs engine: {bad}")
        return 1
    print(f"[url_classify] parity OK ({len(shared)} shared primitives)")
    return 0


if __name__ == "__main__":
    import sys
    # quick self-demo
    for u in (
        "https://api.groww.in/v1/users/12345?sort=asc",
        "https://groww.in/charts/commodities/nse_crudeoil/nse_crudeoil26aug7150pe",
        "https://groww.in/static/app.4f2a.js",
        "https://groww.in/graphql",
        "https://groww.in/login",
        # AI / MCP surfaces
        "https://mcp.example.com/mcp",
        "https://example.com/sse",
        "https://example.com/.well-known/mcp.json",
        "https://ai.example.com/v1/chat/completions",
        "https://example.com/v1/models",
        "https://ollama.example.com/api/tags",
        "https://example.com/v2/models",
        "https://example.com/input_schema",
        "https://example.com/run/predict",
        # negatives — must NOT be tagged AI/MCP
        "https://mailchimp.com/campaigns",
        "https://example.com/messages",
        "https://example.com/api/chat",
    ):
        c = classify_url(u, status=200)
        print(u, "->", {k: c[k] for k in ("url_class", "ai_surface", "ai_flavor",
                                           "ai_confidence", "routed_to")})
    sys.exit(_parity_check())
