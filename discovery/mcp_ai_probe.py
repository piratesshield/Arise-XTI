#!/usr/bin/env python3
"""
MCP / AI Surface Probe   (MCP_AI_DISCOVERY roadmap, Phase 2 — Module 8D)
=======================================================================
Discovers and enumerates **MCP (Model Context Protocol) servers** and **AI/LLM
endpoints** on a target's already-discovered hosts, and emits them so the
endpoint consolidator (Module 8B) folds them into the URL Inventory with the
orthogonal ai_surface/ai_flavor/ai_confidence tag (discovery/url_classify.py).

THREE PASSES, weakest → strongest, all non-destructive:

  1. Passive marking (always, free): re-reads the URL files the pipeline already
     produced (gau/http/crawl/param-fuzz) and tags any URL matching the AI/MCP
     path/host shapes — confidence "path-hint", zero requests.

  2. Safe-GET fingerprint (default on, budgeted): GETs a small curated path list
     on each LIVE host and matches response body/headers — confidence
     "fingerprint". GET/HEAD only; never POSTs a prompt here.

  3. Read-only MCP handshake (default on for responsive MCP paths): JSON-RPC
     `initialize` → `tools/list` / `resources/list` / `prompts/list`. Captures
     serverInfo, capabilities, the tool/resource/prompt inventory, and the
     server `instructions` string — confidence "confirmed". NEVER calls a tool.

Then, over whatever it enumerated, PASSIVE analysis (always):
  * tool-poisoning / prompt-injection detection in tool descriptions + the
    server `instructions` string (fuzzd/mcp-fence/corvus heuristics — no live
    attack).
  * posture checks: unauthenticated MCP handshake (MCP07), open/unauthenticated
    inference endpoint (OWASP LLM10 unbounded consumption), cleartext transport,
    permissive CORS, weak Mcp-Session-Id entropy.

ACTIVE pass (--active / MCP_AI_ACTIVE=true) adds ONLY:
  * a single benign, token-capped generation request to confirm an inference
    endpoint really serves unauthenticated (cost-abuse proof).
Tool-call fuzzing is NOT performed — it runs real code and needs explicit
authorization; it is a documented follow-up (roadmap Phase 5), double-gated
behind --allow-tool-calls, which this build only logs and refuses.

SAFETY: ScopeGuard-locked to the target; budgeted (--max-hosts/--max-paths);
per-request timeout; read-only; degrades to a clean no-op when inputs/deps are
missing. Mirrors the repo convention of cloud/ssrf_metadata.py.

  python3 discovery/mcp_ai_probe.py --target example.com --scan-dir OUT \
      --endpoints-out OUT/08_directory_discovery/mcp_ai_endpoints.jsonl \
      --findings-out  OUT/08_directory_discovery/mcp_ai_findings.jsonl [--active]
"""

from __future__ import annotations

import sys as _sys, os as _os
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)

import argparse
import json
import math
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Shared classifier (single source of truth for AI/MCP shapes).
try:
    from discovery.url_classify import ai_surface as _classify_ai_surface
except Exception:  # pragma: no cover - import bootstrap
    _classify_ai_surface = None

try:
    from core.net import verified_ssl_context as _ssl_ctx_fn
except Exception:  # pragma: no cover
    _ssl_ctx_fn = None

try:
    from ai.ai_probing import ScopeGuard
except Exception:  # pragma: no cover
    ScopeGuard = None


UA = ("Mozilla/5.0 (compatible; ARISE-MCP-AI-Probe/1.0; "
      "+authorized-easm-scan)")


def log(msg: str) -> None:
    print(f"[mcp_ai_probe] {msg}", flush=True)


# ---------------------------------------------------------------------------
# Curated path lists (safe GETs). Kept small + high-signal; budgeted per host.
# ---------------------------------------------------------------------------
MCP_PROBE_PATHS = [
    "/mcp", "/sse", "/mcp/sse", "/api/mcp", "/mcp/v1",
    "/.well-known/mcp.json", "/.well-known/mcp/server-card.json",
]
LLM_PROBE_PATHS = [
    "/v1/models", "/api/tags", "/api/version", "/v2/models",
    "/v2/health/ready", "/info", "/openapi.json",
    "/.well-known/ai-plugin.json", "/input_schema", "/config",
]

# ---------------------------------------------------------------------------
# Tool-poisoning / prompt-injection detectors (passive — over description text)
# fuzzd / mcp-fence / corvus heuristics. No live attack.
# ---------------------------------------------------------------------------
_POISON_PHRASE_RE = re.compile(
    r"(ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions"
    r"|disregard\s+(?:the\s+)?(?:system|previous)"
    r"|you\s+are\s+now\b|new\s+instructions?:"
    r"|do\s+not\s+(?:tell|inform|mention)\s+the\s+user"
    r"|before\s+(?:using|calling)\s+(?:any\s+)?tool"
    r"|</?(?:important|system|secret)>|<!--)",
    re.I)
_EXFIL_VERB_RE = re.compile(
    r"\b(?:exfiltrat|curl\s|wget\s|base64|/etc/passwd|\.ssh|id_rsa"
    r"|AWS_SECRET|AWS_ACCESS|api[_-]?key|password|BEGIN (?:RSA|OPENSSH))\b", re.I)
_ENV_PATH_RE = re.compile(r"(~/\.ssh|/\.env\b|\benv\s*\[|process\.env|os\.environ)", re.I)
# Zero-width / bidi control characters used to hide instructions.
_HIDDEN_CHARS_RE = re.compile(r"[​-‏‪-‮⁦-⁩﻿]")
# High-risk schema parameter names with no obvious validation.
_RISKY_PARAM = {"command", "cmd", "exec", "shell", "path", "filepath", "file",
                "url", "uri", "webhook", "endpoint", "host", "query", "sql"}


def _poison_scan(text: str) -> List[str]:
    """Return the list of poisoning/injection signals found in a description /
    instructions string. Empty = clean."""
    if not text:
        return []
    sig = []
    if _POISON_PHRASE_RE.search(text):
        sig.append("injection-phrase")
    if _EXFIL_VERB_RE.search(text):
        sig.append("exfil-verb")
    if _ENV_PATH_RE.search(text):
        sig.append("credential-path-ref")
    if _HIDDEN_CHARS_RE.search(text):
        sig.append("hidden-unicode")
    if "<!--" in text:
        sig.append("hidden-html-comment")
    return sig


def _schema_risks(input_schema: Dict) -> List[str]:
    """Flag risky tool input-schema shapes (mcp-fence heuristic)."""
    risks = []
    try:
        props = (input_schema or {}).get("properties") or {}
        for name in props:
            if str(name).lower() in _RISKY_PARAM:
                risks.append(f"risky-param:{name}")
        if props and (input_schema or {}).get("additionalProperties") is not False:
            risks.append("no-additionalProperties-constraint")
    except Exception:
        pass
    return risks


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


# ---------------------------------------------------------------------------
# HTTP (stdlib — no hard dependency on requests)
# ---------------------------------------------------------------------------
class Resp:
    __slots__ = ("status", "headers", "body", "url", "error", "content_type")

    def __init__(self, status=0, headers=None, body="", url="", error=""):
        self.status = status
        self.headers = {str(k).lower(): v for k, v in (headers or {}).items()}
        self.body = body
        self.url = url
        self.error = error
        self.content_type = self.headers.get("content-type", "")


def _ctx() -> ssl.SSLContext:
    if _ssl_ctx_fn:
        try:
            return _ssl_ctx_fn()
        except Exception:
            pass
    return ssl.create_default_context()


def http(method: str, url: str, *, timeout: float, body: Optional[bytes] = None,
         extra_headers: Optional[Dict] = None, max_bytes: int = 262144) -> Resp:
    headers = {"User-Agent": UA, "Accept": "application/json, text/event-stream, */*"}
    if extra_headers:
        headers.update(extra_headers)
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_ctx()) as r:
            raw = r.read(max_bytes)
            return Resp(r.status, dict(r.headers), raw.decode("utf-8", "replace"),
                        url=r.geturl())
    except urllib.error.HTTPError as e:
        try:
            raw = e.read(max_bytes)
        except Exception:
            raw = b""
        return Resp(e.code, dict(e.headers or {}), raw.decode("utf-8", "replace"), url=url)
    except Exception as e:
        return Resp(0, {}, "", url=url, error=str(e))


# ---------------------------------------------------------------------------
# MCP handshake (read-only)
# ---------------------------------------------------------------------------
def _parse_sse_json(body: str) -> Optional[dict]:
    """Legacy/streamable responses can be text/event-stream: pull the first
    JSON `data:` payload."""
    for line in body.splitlines():
        line = line.strip()
        if line.startswith("data:"):
            frag = line[5:].strip()
            if frag.startswith("{"):
                try:
                    return json.loads(frag)
                except Exception:
                    continue
    return None


def _json_of(resp: Resp) -> Optional[dict]:
    b = (resp.body or "").lstrip()
    if not b:
        return None
    if "event-stream" in resp.content_type or b.startswith("event:") or b.startswith("data:"):
        return _parse_sse_json(resp.body)
    if b[0] in "{[":
        try:
            return json.loads(resp.body)
        except Exception:
            return _parse_sse_json(resp.body)
    return None


def mcp_handshake(base_url: str, timeout: float) -> Tuple[Optional[dict], Optional[str], List[dict]]:
    """Read-only MCP enumeration. Returns (serverInfo+capabilities dict,
    session_id, tools) — enumerating resources/prompts into the dict too.
    None when the endpoint is not a live MCP server."""
    init_body = json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "arise-mcp-ai-probe", "version": "1.0"},
        },
    }).encode()
    r = http("POST", base_url, timeout=timeout, body=init_body,
             extra_headers={"Content-Type": "application/json"})
    data = _json_of(r)
    if not data or not isinstance(data, dict):
        return None, None, []
    result = data.get("result") or {}
    if "protocolVersion" not in result and "serverInfo" not in result and "capabilities" not in result:
        # not an MCP initialize response
        if "error" not in data:
            return None, None, []
        # a JSON-RPC error still proves a JSON-RPC server exists, but not MCP
        return None, None, []
    session_id = r.headers.get("mcp-session-id")
    server = {
        "protocolVersion": result.get("protocolVersion"),
        "serverInfo": result.get("serverInfo") or {},
        "capabilities": result.get("capabilities") or {},
        "instructions": result.get("instructions") or "",
        "transport": "streamable" if session_id else "sse-or-streamable",
    }
    # enumerate tools / resources / prompts (read-only)
    def _list(method: str, key: str) -> list:
        hdr = {"Content-Type": "application/json"}
        if session_id:
            hdr["Mcp-Session-Id"] = session_id
        rb = json.dumps({"jsonrpc": "2.0", "id": 2, "method": method, "params": {}}).encode()
        rr = http("POST", base_url, timeout=timeout, body=rb, extra_headers=hdr)
        d = _json_of(rr) or {}
        return ((d.get("result") or {}).get(key)) or []

    tools = _list("tools/list", "tools")
    server["resources"] = _list("resources/list", "resources")
    server["prompts"] = _list("prompts/list", "prompts")
    return server, session_id, tools


# ---------------------------------------------------------------------------
# Probe engine
# ---------------------------------------------------------------------------
class Probe:
    def __init__(self, args):
        self.args = args
        self.target = args.target
        self.scan_dir = Path(args.scan_dir) if args.scan_dir else None
        self.scope = ScopeGuard(args.target) if (ScopeGuard and args.target) else None
        self.endpoints: Dict[str, dict] = {}   # url -> endpoint record (strongest wins)
        self.findings: List[dict] = []
        self.seen_hosts: set = set()

    # ---- scope ----
    def _in_scope(self, url: str) -> bool:
        if self.scope is None:
            return True
        try:
            return self.scope.in_scope(url)
        except Exception:
            return False

    # ---- record helpers ----
    _CONF_RANK = {None: 0, "": 0, "path-hint": 1, "fingerprint": 2, "confirmed": 3}

    def _emit_endpoint(self, url, surface, flavor, confidence, *, transport="",
                       evidence="", tools=None, resources=None, prompts=None,
                       server_info=None):
        prev = self.endpoints.get(url)
        if prev and self._CONF_RANK.get(confidence, 0) <= self._CONF_RANK.get(prev.get("ai_confidence"), 0):
            # keep the stronger record, but merge enumerated inventory if new one has it
            if tools and not prev.get("tools"):
                prev["tools"] = tools
            return
        rec = {
            "url": url,
            "host": urllib.parse.urlsplit(url).netloc,
            "ai_surface": surface,
            "ai_flavor": flavor,
            "ai_confidence": confidence,
            "transport": transport or (flavor or ""),
            "source": "mcp-probe",
            "evidence": evidence,
        }
        if tools is not None:
            rec["tools"] = [{"name": t.get("name"), "description": (t.get("description") or "")[:400]}
                            for t in tools if isinstance(t, dict)]
            rec["tool_count"] = len(tools)
        if resources is not None:
            rec["resource_count"] = len(resources)
        if prompts is not None:
            rec["prompt_count"] = len(prompts)
        if server_info:
            rec["server_info"] = server_info
        self.endpoints[url] = rec

    def _finding(self, severity, title, host, url, evidence, remediation,
                 *, confidence="confirmed", mst="", owasp_llm=""):
        self.findings.append({
            "module": "mcp_ai_probe",
            "severity": severity,
            "confidence": confidence,
            "title": title,
            "host": host,
            "url": url,
            "evidence": evidence,
            "remediation": remediation,
            "mst": mst,
            "owasp_llm": owasp_llm,
        })

    # ---- pass 1: passive marking of already-discovered URLs ----
    def pass_passive(self) -> None:
        if not self.scan_dir or _classify_ai_surface is None:
            return
        files = [
            "01_asset_discovery/gau_urls.txt",
            "04_http_discovery/http_urls.txt",
            "08_directory_discovery/all_paths.txt",
            "09_crawling/all_urls.txt",
            "11_param_fuzzing/urls_with_params.txt",
        ]
        n = 0
        for rel in files:
            p = self.scan_dir / rel
            if not p.exists():
                continue
            for line in p.read_text(errors="ignore").splitlines():
                u = line.strip()
                if not u or not u.lower().startswith("http"):
                    continue
                if not self._in_scope(u):
                    continue
                host = urllib.parse.urlsplit(u).netloc
                try:
                    # host_label=False: a URL is AI-tagged only when its PATH is
                    # AI-shaped — NOT just because it lives on an AI-named host
                    # (that would tag every URL on mcp-server.* and flood the
                    # inventory; host-label tagging is asset-level, in internet_intel).
                    s, f, c = _classify_ai_surface(u, host=host.split(":")[0], host_label=False)
                except Exception:
                    continue
                if s:
                    self._emit_endpoint(u, s, f, c or "path-hint",
                                        evidence="matched AI/MCP path shape (passive)")
                    n += 1
        if n:
            log(f"passive marking: {n} already-discovered URL(s) tagged AI/MCP")

    # ---- live-host list ----
    def _live_hosts(self) -> List[str]:
        hosts: List[str] = []
        seen = set()
        srcs = []
        if self.args.live_hosts:
            srcs.append(Path(self.args.live_hosts))
        if self.scan_dir:
            srcs.append(self.scan_dir / "04_http_discovery/http_urls.txt")
            srcs.append(self.scan_dir / "04_http_discovery/resolved_unique.txt")
        for p in srcs:
            if not p or not p.exists():
                continue
            for line in p.read_text(errors="ignore").splitlines():
                h = line.strip()
                if not h:
                    continue
                if not h.lower().startswith("http"):
                    h = "https://" + h
                root = f"{urllib.parse.urlsplit(h).scheme}://{urllib.parse.urlsplit(h).netloc}"
                if root in seen:
                    continue
                if not self._in_scope(root):
                    continue
                seen.add(root)
                hosts.append(root)
        return hosts[: self.args.max_hosts]

    # ---- pass 2 + 3: safe-GET fingerprint + MCP handshake ----
    def pass_active_discovery(self) -> None:
        hosts = self._live_hosts()
        if not hosts:
            log("no live hosts to probe (need 04_http_discovery/http_urls.txt or --live-hosts)")
            return
        log(f"probing {len(hosts)} live host(s), ≤{self.args.max_paths} paths each")
        for root in hosts:
            self._probe_host(root)
            time.sleep(self.args.delay)

    _MCP_TRANSPORT_PATHS = ("/mcp", "/sse", "/mcp/sse", "/api/mcp", "/mcp/v1")

    def _probe_host(self, root: str) -> None:
        scheme = urllib.parse.urlsplit(root).scheme
        host = urllib.parse.urlsplit(root).netloc
        paths = (MCP_PROBE_PATHS + LLM_PROBE_PATHS)[: self.args.max_paths]
        for path in paths:
            url = root.rstrip("/") + path
            r = http("GET", url, timeout=self.args.timeout)
            if r.status == 0:
                continue
            # An endpoint "exists" when it answers as a real route: a 2xx/3xx, or
            # an auth-gated 401/403, or a 405/429. A 404/410/5xx with only a path
            # name-match is dropped as noise.
            exists = (200 <= r.status < 400) or r.status in (401, 403, 405, 429)

            # --- MCP transport path: attempt a READ-ONLY handshake whenever the
            #     endpoint actually responds (incl. 401/403). A 401/403 means an
            #     AUTHENTICATED MCP server — still a confirmed discovery, not a
            #     mere path-hint. (The old code only handshook on 200/400/405/
            #     406/415, so a real auth-gated MCP server like mcp-server.*
            #     stayed at the weakest 'path-hint' tier with no finding.) ---
            if path in self._MCP_TRANSPORT_PATHS and r.status not in (404, 410, 501):
                server, sid, tools = mcp_handshake(url, self.args.timeout)
                if server:
                    self._handle_mcp(url, host, scheme, server, sid, tools, authed=False)
                    continue
                if exists:
                    self._handle_mcp_gated(url, host, scheme, r)
                    continue

            # --- generic fingerprint for the remaining (LLM/agent) paths ---
            s, f, c = (None, None, None)
            if _classify_ai_surface:
                s, f, c = _classify_ai_surface(
                    url, host=host.split(":")[0], content_type=r.content_type,
                    body=r.body, headers=r.headers, host_label=False)
            if not s:
                continue
            is_fp = c == "fingerprint"
            # A distinctive AI/MCP PATH that actually responds is itself a
            # fingerprint-grade signal — bump it above path-hint. Host-label-only
            # matches (flavor ends in "-host") do NOT get this bump (a 200 on a
            # host root is just the host existing, not an endpoint confirmation).
            path_based = bool(f) and not str(f).endswith("-host")
            if not (exists or is_fp):
                continue
            if is_fp:
                conf = "confirmed" if (200 <= r.status < 300) else "fingerprint"
            elif exists and path_based:
                conf = "fingerprint"
            else:
                conf = c or "path-hint"
            self._emit_endpoint(url, s, f, conf,
                                evidence=f"HTTP {r.status} {r.content_type[:40]}".strip())
            if exists:
                self._posture_http(url, host, scheme, s, f, r)

    def _handle_mcp_gated(self, url, host, scheme, r: Resp) -> None:
        """A live MCP transport endpoint whose anonymous initialize did NOT
        complete — an authenticated / gated MCP server (401/403) or a
        non-standard responder (other 2xx/3xx). Confirmed MCP SURFACE, no tool
        enumeration. 401/403 is the secure posture (reported low, surface
        confirmed); anything else is an info-grade 'responds but unconfirmed'."""
        flavor = ("mcp-sse" if re.search(r"/sse(?:/|$)", url)
                  else "mcp-streamable" if re.search(r"/mcp(?:/|$)", url) else "mcp")
        self._emit_endpoint(
            url, "mcp", flavor, "fingerprint", transport=flavor,
            evidence=f"MCP transport endpoint live (HTTP {r.status}); "
                     "anonymous handshake refused")
        wa = r.headers.get("www-authenticate", "")
        if r.status in (401, 403):
            self._finding(
                "low", "Authenticated MCP server detected (auth required)",
                host, url,
                f"MCP transport endpoint returned HTTP {r.status}"
                + (f"; WWW-Authenticate: {wa[:120]}" if wa else "")
                + " — anonymous initialize refused (good posture; MCP surface confirmed).",
                "Confirm the auth is strong (OAuth 2.1 + PKCE / scoped tokens) and "
                "rate-limited, and audit which tools the authenticated identity can call.",
                confidence="fingerprint", mst="MCP07", owasp_llm="LLM06")
        else:
            self._finding(
                "info", "MCP endpoint responds but anonymous handshake not completed",
                host, url,
                f"HTTP {r.status} on an MCP transport path; a standard MCP initialize "
                "did not parse (non-standard responder or a session is required).",
                "Verify manually whether this is an MCP server and how it is authenticated.",
                confidence="path-hint", mst="MCP07")

    def _handle_mcp(self, url, host, scheme, server, sid, tools, authed) -> None:
        info = server.get("serverInfo") or {}
        name = info.get("name") or ""
        ver = info.get("version") or ""
        self._emit_endpoint(
            url, "mcp", "mcp-" + (server.get("transport") or "streamable"), "confirmed",
            transport=server.get("transport", ""),
            evidence=f"MCP initialize OK: {name} {ver} proto={server.get('protocolVersion')}",
            tools=tools, resources=server.get("resources"),
            prompts=server.get("prompts"),
            server_info={"name": name, "version": ver,
                         "protocolVersion": server.get("protocolVersion")})
        # posture: unauthenticated handshake
        self._finding("high", "Unauthenticated MCP server — handshake succeeded with no credentials",
                      host, url,
                      f"initialize + tools/list returned {len(tools)} tool(s) with no auth; "
                      f"server={name} {ver}",
                      "Require authentication (OAuth 2.1 / bearer) on the MCP endpoint; "
                      "do not expose tool execution unauthenticated.",
                      mst="MCP07", owasp_llm="LLM06")
        if scheme == "http":
            self._finding("medium", "MCP server over cleartext HTTP", host, url,
                          "MCP JSON-RPC served over http:// — tokens/tool args in cleartext.",
                          "Serve MCP over HTTPS only.", mst="MCP01")
        # session-id entropy
        if sid and _entropy(sid) < 3.0:
            self._finding("low", "Weak MCP session identifier entropy", host, url,
                          f"Mcp-Session-Id={sid[:6]}… entropy={_entropy(sid):.1f} bits/char",
                          "Use a cryptographically-random session id.", confidence="fingerprint")
        # system-prompt / instructions leak
        instr = server.get("instructions") or ""
        if instr:
            self._finding("low", "MCP server leaks system instructions in handshake", host, url,
                          f"instructions field present ({len(instr)} chars) — may expose the "
                          "system prompt.", "Avoid returning sensitive system guidance in the "
                          "initialize response.", confidence="fingerprint",
                          owasp_llm="LLM07")
        # tool-poisoning / prompt-injection in tool descriptions + instructions
        self._scan_poisoning(host, url, tools, instr)

    def _scan_poisoning(self, host, url, tools, instructions) -> None:
        corpus = [("instructions", instructions or "")]
        for t in (tools or []):
            if isinstance(t, dict):
                corpus.append((f"tool:{t.get('name')}", t.get("description") or ""))
        for label, text in corpus:
            sig = _poison_scan(text)
            if sig:
                self._finding("high", "Tool-poisoning / prompt-injection content in MCP metadata",
                              host, url,
                              f"{label}: signals={sig} — suspicious instruction content in a "
                              "tool description/instructions the model will read.",
                              "Review and sanitise tool descriptions; treat third-party MCP tool "
                              "metadata as untrusted.", confidence="confirmed",
                              mst="MCP03", owasp_llm="LLM01")
        # schema risks
        for t in (tools or []):
            if not isinstance(t, dict):
                continue
            risks = _schema_risks(t.get("inputSchema") or {})
            if risks:
                self._finding("medium", "MCP tool exposes high-risk/unconstrained parameters",
                              host, url,
                              f"tool {t.get('name')}: {risks}",
                              "Constrain tool input schemas (enum/pattern/additionalProperties:false); "
                              "validate command/path/url params.", confidence="fingerprint",
                              mst="MCP05")

    def _posture_http(self, url, host, scheme, surface, flavor, r: Resp) -> None:
        # open / unauthenticated inference endpoint (cost abuse)
        if surface in ("llm-api", "ai-gateway") and 200 <= r.status < 300:
            self._finding("medium", "Unauthenticated AI/LLM inference endpoint exposed",
                          host, url,
                          f"{flavor or 'llm'} endpoint returned HTTP {r.status} without auth — "
                          "open inference enables cost abuse / data exfiltration.",
                          "Put the inference endpoint behind authentication and rate limiting; "
                          "do not expose model management (/v1/models, /api/tags) publicly.",
                          owasp_llm="LLM10")
        if scheme == "http" and surface:
            self._finding("low", "AI/LLM endpoint over cleartext HTTP", host, url,
                          "served over http:// — prompts/responses in cleartext.",
                          "Serve over HTTPS only.", confidence="fingerprint")
        aco = r.headers.get("access-control-allow-origin", "")
        if aco == "*" and surface:
            self._finding("low", "Permissive CORS on AI/MCP endpoint", host, url,
                          "Access-Control-Allow-Origin: * — any origin may call this endpoint.",
                          "Restrict CORS to trusted origins.", confidence="fingerprint")

    # ---- pass 4 (ACTIVE, gated): confirm open inference serves generations ----
    def pass_active_exploit(self) -> None:
        if not self.args.active:
            return
        if self.args.allow_tool_calls:
            log("--allow-tool-calls: MCP tool-call fuzzing requires explicit authorization and is "
                "NOT performed by this build (documented follow-up, roadmap Phase 5).")
        # Only confirm unauth inference on endpoints already fingerprinted as llm-api.
        targets = [rec for rec in self.endpoints.values()
                   if rec.get("ai_surface") in ("llm-api", "ai-gateway")
                   and rec.get("ai_flavor") in ("openai-compat", "ollama", None)]
        for rec in targets[: self.args.max_hosts]:
            self._confirm_inference(rec)

    def _confirm_inference(self, rec) -> None:
        url = rec["url"]
        root = f"{urllib.parse.urlsplit(url).scheme}://{urllib.parse.urlsplit(url).netloc}"
        host = urllib.parse.urlsplit(url).netloc
        # pick the minimal benign generation request for the flavour
        flavor = rec.get("ai_flavor")
        if flavor == "ollama":
            gen_url = root + "/api/generate"
            body = json.dumps({"model": "llama3", "prompt": "ping",
                               "stream": False, "options": {"num_predict": 1}}).encode()
        else:  # openai-compat
            gen_url = root + "/v1/chat/completions"
            body = json.dumps({"model": "gpt-3.5-turbo",
                               "messages": [{"role": "user", "content": "ping"}],
                               "max_tokens": 1}).encode()
        if not self._in_scope(gen_url):
            return
        r = http("POST", gen_url, timeout=self.args.timeout, body=body,
                 extra_headers={"Content-Type": "application/json"})
        # A 200 with a completion, OR a model-not-found error (400/404 w/ JSON),
        # both prove the endpoint ACCEPTS unauthenticated generation requests.
        if r.status in (200, 400, 404, 422) and _json_of(r) is not None:
            self._finding("high", "Confirmed unauthenticated AI generation endpoint",
                          host, gen_url,
                          f"POST {gen_url} accepted an unauthenticated generation request "
                          f"(HTTP {r.status}) — cost-abuse / prompt-injection exposure.",
                          "Require authentication + rate limiting on generation endpoints.",
                          owasp_llm="LLM10")

    # ---- write ----
    def write(self) -> None:
        if self.args.endpoints_out:
            op = Path(self.args.endpoints_out)
            op.parent.mkdir(parents=True, exist_ok=True)
            with op.open("w") as f:
                for rec in sorted(self.endpoints.values(), key=lambda r: r["url"]):
                    f.write(json.dumps(rec) + "\n")
            log(f"wrote {len(self.endpoints)} AI/MCP endpoint(s) -> {op}")
        if self.args.findings_out:
            fp = Path(self.args.findings_out)
            fp.parent.mkdir(parents=True, exist_ok=True)
            with fp.open("w") as f:
                for rec in self.findings:
                    f.write(json.dumps(rec) + "\n")
            log(f"wrote {len(self.findings)} finding(s) -> {fp}")

    def run(self) -> int:
        self.pass_passive()
        if not self.args.no_probe:
            self.pass_active_discovery()
            self.pass_active_exploit()
        self.write()
        n_conf = sum(1 for r in self.endpoints.values() if r.get("ai_confidence") == "confirmed")
        log(f"done: {len(self.endpoints)} endpoint(s) ({n_conf} confirmed), "
            f"{len(self.findings)} finding(s)")
        return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="ARISE MCP/AI surface probe (Module 8D)")
    ap.add_argument("--target", required=True, help="scope apex (ScopeGuard lock)")
    ap.add_argument("--scan-dir", help="scan output dir (for passive marking + live hosts)")
    ap.add_argument("--live-hosts", help="explicit live-host list (http_urls.txt)")
    ap.add_argument("--endpoints-out", help="output JSONL of AI/MCP endpoints")
    ap.add_argument("--findings-out", help="output JSONL of posture/poisoning findings")
    ap.add_argument("--active", action="store_true",
                    help="confirm unauthenticated inference with one benign generation req")
    ap.add_argument("--allow-tool-calls", action="store_true",
                    help="(double-gate; NOT performed by this build) MCP tool-call fuzzing")
    ap.add_argument("--no-probe", action="store_true", help="passive marking only")
    ap.add_argument("--max-hosts", type=int, default=60)
    ap.add_argument("--max-paths", type=int, default=len(MCP_PROBE_PATHS) + len(LLM_PROBE_PATHS))
    ap.add_argument("--timeout", type=float, default=8.0)
    ap.add_argument("--delay", type=float, default=0.0, help="seconds between hosts")
    args = ap.parse_args()

    if _classify_ai_surface is None:
        log("discovery.url_classify unavailable — cannot classify; exiting cleanly")
        # still write empty outputs so the pipeline's downstream reads are stable
        Probe(args).write()
        return 0
    return Probe(args).run()


if __name__ == "__main__":
    raise SystemExit(main())
