#!/usr/bin/env python3
"""
ARISE Endpoint Consolidator
===========================
Folds every URL the pipeline discovered — dirsearch brute-force hits, crawled
links (gospider/katana), JS-extracted endpoints, and the runtime XHR/fetch API
calls intercepted by the headless browser (Module 20) — into ONE deduplicated
endpoint inventory the directory-discovery view renders.

Deduplication: by (host, path). One representative query string is kept per
path, so a parameterized API endpoint (`/api/user?id=1`) stays visible for
testing while `/api/user?id=2..N` collapse into it.

Status: dirsearch hits keep their known status (200/403/500). Endpoints that
came only from crawling/interception have no status yet, so the NEW ones are
probed once with httpx (bounded) to attach a real code.

Usage:
  python3 endpoint_consolidator.py <target> --scan-dir <dir> [--max-probe N]
                                   [--no-probe] [--httpx httpx]

Output: <scan-dir>/08_directory_discovery/discovered_endpoints.jsonl
Degrades gracefully if httpx is missing (new endpoints get status 0/unknown).
"""

from __future__ import annotations

import sys as _sys, os as _os
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)


import argparse
import json
import os
import shutil
import ssl
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

# Shared classification primitives (same module the intel engine imports, so the
# inventory is classified identically to how the attack engine would).
try:
    from discovery.url_classify import classify_url, url_class, is_cloud_storage
except Exception:  # pragma: no cover - degrade if module missing
    classify_url = None
    url_class = None
    def is_cloud_storage(_):  # type: ignore
        return False


def log(msg: str) -> None:
    print(f"[endpoints] {msg}", file=sys.stderr, flush=True)


# Source priority: when probing is capped, keep the highest-value sources.
# `har` is real captured browser traffic — the highest-trust source there is.
SOURCE_PRIORITY = {"har": 0, "input": 0, "mcp-probe": 1, "api-runtime": 1,
                   "js": 2, "dirsearch": 3, "crawled": 4}

# Map a consolidator source tag onto a canonical request-provenance class (R4),
# so every inventory row records HOW it was discovered — a synthetic probe that
# 400s is not the same evidence as real browser traffic that 200s.
try:
    from evidence.arise_evidence import provenance_of
except Exception:  # pragma: no cover - degrade if module missing
    def provenance_of(_s):  # type: ignore
        return "unknown"

# Input-function -> extra attack lane (routing beyond the url_class lanes).
INPUT_FN_LANES = {
    "upload": "file-upload", "login": "auth-jwt", "register": "auth-jwt",
    "password-reset": "auth-jwt", "otp": "auth-jwt", "search": "search-fuzz",
    "payment": "business-logic", "contact": "xss", "comment": "xss",
    "profile": "bola", "filter": "sqli",
}

# Static resource extensions — assets, not actionable directory/API endpoints.
# Dropped from the consolidated inventory so it reflects the real endpoint
# surface (API calls, pages, handlers) instead of thousands of hashed JS
# chunks, images and fonts. dirsearch hits are exempt (a dirsearch 200 on a
# file is a deliberate finding worth keeping).
STATIC_EXT = {
    "png", "jpg", "jpeg", "gif", "svg", "webp", "avif", "ico", "bmp", "tiff",
    "woff", "woff2", "ttf", "eot", "otf",
    "css", "scss", "less", "map",
    "js", "mjs", "cjs",              # hashed SPA chunks dominate; JS endpoints
                                     # are mined separately by the intel engine
    "mp4", "webm", "ogg", "mp3", "wav", "avi", "mov", "flv", "m4a", "m4v",
    "woff2", "pdf", "zip", "gz", "tar", "rar", "7z",
}


def _is_static(path: str) -> bool:
    last = path.rsplit("/", 1)[-1]
    if "." not in last:
        return False
    return last.rsplit(".", 1)[-1].lower() in STATIC_EXT


# --- path templating: collapse instance identifiers to placeholders --------- #
import re

_NUM_RE = re.compile(r"^\d+$")
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_HEX_RE = re.compile(r"^[0-9a-fA-F]{16,}$")
_TOKEN_RE = re.compile(r"^(?=[A-Za-z0-9_-]*\d)[A-Za-z0-9_-]{24,}$")  # opaque token — must contain a digit to exclude content slugs


def _template_seg(seg: str) -> str:
    if not seg:
        return seg
    if _NUM_RE.match(seg):
        return "{id}"
    if _UUID_RE.match(seg):
        return "{uuid}"
    if _HEX_RE.match(seg):
        return "{hash}"
    if _TOKEN_RE.match(seg):
        return "{token}"
    return seg


def _id_template(path: str) -> str:
    """Collapse unambiguous instance identifiers (numeric/uuid/hash/opaque)."""
    return "/".join(_template_seg(s) for s in path.split("/"))


def _merge_query_params(q1: str, q2: str) -> str:
    """Union of two query strings by parameter NAME (first token per name wins).

    So /search?q=… and /search?category=… collapse to the same endpoint but the
    representative query keeps BOTH parameters (q + category) — every distinct
    parameter survives to be fuzzed, while repeated values of one parameter don't
    multiply the inventory."""
    merged: Dict[str, str] = {}
    for q in (q1, q2):
        if not q:
            continue
        for pair in q.split("&"):
            if not pair:
                continue
            name = pair.split("=", 1)[0]
            if name and name not in merged:
                merged[name] = pair
    return "&".join(merged.values())


def _is_placeholder(seg: str) -> bool:
    return seg.startswith("{") and seg.endswith("}")


@dataclass
class Endpoint:
    scheme: str
    host: str
    path: str
    query: str = ""               # representative sample query (may be empty)
    status: Optional[int] = None  # known status (dirsearch) or filled by probe
    sources: Set[str] = field(default_factory=set)
    # Distinct query-key SETS seen for this (host, path). "?q=x" and
    # "?category=y" have different key sets; the old behaviour merged them
    # into one row and silently lost the fact that TWO different vuln
    # surfaces exist. Track them as sorted comma-separated key names so the
    # dashboard and downstream scanners can enumerate them.
    query_variants: Set[str] = field(default_factory=set)

    @property
    def key(self) -> Tuple[str, str]:
        return (self.host.lower(), self.path)

    @property
    def url(self) -> str:
        base = f"{self.scheme}://{self.host}{self.path}"
        return f"{base}?{self.query}" if self.query else base

    def best_source(self) -> str:
        return min(self.sources, key=lambda s: SOURCE_PRIORITY.get(s, 9)) \
            if self.sources else "crawled"


@dataclass
class TemplatedEndpoint:
    scheme: str
    host: str
    tpath: str                    # templated path (the dedup key)
    sample_url: str = ""          # a real, probe-able URL for this template
    sample_query: str = ""
    status: Optional[int] = None
    content_type: str = ""        # filled by httpx probe (drives url_class/api_type)
    methods: List[str] = field(default_factory=list)  # OPTIONS Allow: set
    sources: Set[str] = field(default_factory=set)
    instances: int = 0            # how many concrete URLs collapsed here
    # Union of the distinct query key SETS seen across every concrete URL
    # that collapsed into this template. `{"q,limit", "category,sort"}`
    # means two distinct query shapes were seen on the same path template.
    # Preserved through the JSONL so downstream scanners can enumerate.
    query_variants: Set[str] = field(default_factory=set)

    @property
    def key(self) -> Tuple[str, str]:
        return (self.host.lower(), self.tpath)

    @property
    def url(self) -> str:
        base = f"{self.scheme}://{self.host}{self.tpath}"
        return f"{base}?{self.sample_query}" if self.sample_query else base

    def best_source(self) -> str:
        return min(self.sources, key=lambda s: SOURCE_PRIORITY.get(s, 9)) \
            if self.sources else "crawled"


class Consolidator:
    def __init__(self, target: str, scan_dir: Path, args):
        self.target = target.strip().lower().rstrip(".")
        self.scan_dir = scan_dir
        self.args = args
        self.eps: Dict[Tuple[str, str], Endpoint] = {}
        self.final: Dict[Tuple[str, str], TemplatedEndpoint] = {}
        # (host, id-templated-path) -> list of input-function records
        self.input_fns: Dict[Tuple[str, str], List[dict]] = {}
        # (host, id-templated-path) -> strongest AI/MCP tag from the probe module
        # (mcp_ai_probe.py). Carried through to classify_url() as overrides so a
        # handshake-'confirmed' tag survives templating/merge.
        self.ai_meta: Dict[Tuple[str, str], dict] = {}

    # ---- scope ------------------------------------------------------------ #
    def _in_scope(self, host: str) -> bool:
        h = host.lower().split(":")[0]
        return h == self.target or h.endswith("." + self.target)

    # ---- ingest one URL --------------------------------------------------- #
    def _add(self, raw: str, source: str, status: Optional[int] = None) -> None:
        raw = raw.strip()
        if not raw or not raw.lower().startswith(("http://", "https://")):
            return
        raw = raw.split()[0]  # tolerate "url  status  size" columns
        try:
            p = urllib.parse.urlsplit(raw)
        except Exception:
            return
        # Cloud-storage buckets live on provider domains (…s3.amazonaws.com,
        # …blob.core.windows.net, …storage.googleapis.com), NOT on a subdomain
        # of the target — but one referenced by the target's crawl/JS/runtime is
        # owned-by/relevant-to the target. Keep it (attributed later) instead of
        # scope-dropping it, so buckets are visible in the inventory.
        cloud = is_cloud_storage(p.netloc.split(":")[0])
        if not p.scheme or not p.netloc or (not self._in_scope(p.netloc) and not cloud):
            return
        # Preserve non-standard ports in the host so http://host:8080/path and
        # http://host/path are two distinct inventory entries. Without this,
        # split(":")[0] silently drops the port and both collapse to the same
        # key — every non-standard port URL disappears from the inventory.
        # Standard default ports (80 for http, 443 for https) are stripped so
        # explicit :443 and bare host don't produce spurious duplicates.
        _hostname = p.hostname or ""
        _port = p.port
        if _port and not ((p.scheme == "http" and _port == 80) or
                          (p.scheme == "https" and _port == 443)):
            host = f"{_hostname}:{_port}"
        else:
            host = _hostname
        path = p.path or "/"
        # Drop static assets — but never drop a deliberate dirsearch finding, and
        # never drop a cloud bucket object (the bucket itself is the signal).
        if source != "dirsearch" and not cloud and _is_static(path):
            return
        key = (host.lower(), path)
        ep = self.eps.get(key)
        if ep is None:
            ep = Endpoint(scheme=p.scheme, host=host, path=path)
            self.eps[key] = ep
        # Merge the UNION of distinct parameter names into the representative
        # query. The old behaviour kept only the first query seen, so a second
        # sample of the same path with a DIFFERENT parameter (e.g. /search?q=…
        # then /search?category=…) silently lost `category` and it was never
        # fuzzed. Collapsing repeated values of the SAME parameter is still fine
        # — one sample per parameter is all an injection test needs.
        if p.query:
            ep.query = _merge_query_params(ep.query, p.query)
            # ALSO track the distinct key SET for this variant so downstream
            # scanners can enumerate "how many different query shapes hit
            # this path". `?q=x` and `?category=y&sort=asc` are two variants
            # even though they're the same (host, path).
            try:
                keys = sorted({k for k, _ in urllib.parse.parse_qsl(
                    p.query, keep_blank_values=True)})
                if keys:
                    ep.query_variants.add(",".join(keys))
            except Exception:
                pass
        ep.sources.add(source)
        # A known status (from dirsearch) always wins over "unknown".
        if status is not None:
            ep.status = status

    # ---- gather all sources ---------------------------------------------- #
    def _read_lines(self, rel: str) -> List[str]:
        f = self.scan_dir / rel
        if not f.exists():
            return []
        try:
            return f.read_text(errors="ignore").splitlines()
        except Exception:
            return []

    def gather(self) -> None:
        # ARCHITECTURE: this method reads EVERY URL source the pipeline
        # produces, because URL Inventory is the source of truth. Downstream
        # scanners (nuclei, XSS, SQLi, api-security) then consume subsets of
        # the classified inventory — that's where reduction happens, not here.
        # If a source is missing from this list, the URL Inventory dashboard
        # is smaller than reality and downstream feeds are inconsistent.

        # 1. dirsearch hits carry a known status.
        for fname, code in (("200response.txt", 200),
                            ("forbidden_response.txt", 403),
                            ("500response.txt", 500)):
            for line in self._read_lines(f"08_directory_discovery/dirsearch/{fname}"):
                self._add(line, "dirsearch", status=code)
        n_dir = len(self.eps)
        log(f"dirsearch hits: {n_dir} unique paths")

        # 2. Historical asset discovery — gau/wayback. Previously read only
        # via 09_crawling/all_urls.txt (which Module 9 concatenates from
        # gau_urls.txt); but if Module 9's concat/scope filter drops any of
        # them, the inventory silently misses them. Read gau_urls.txt DIRECTLY
        # here — same source the nuclei consolidator has always used.
        for line in self._read_lines("01_asset_discovery/gau_urls.txt"):
            self._add(line, "gau")
        log(f"after gau: {len(self.eps)} unique paths")

        # 3. httpx-confirmed HTTP roots — Module 4's authoritative "these
        # URLs are live" file. Every root should appear in the inventory
        # (dashboard's "URL Inventory" is expected to include site roots).
        for line in self._read_lines("04_http_discovery/http_urls.txt"):
            self._add(line, "http-discovery")

        # 4. Dirsearch consolidated all_paths.txt — union of 200/301/302/500
        # response files that Module 8 emits. Belt-and-braces with source (1)
        # in case the individual response files are missing but all_paths is
        # present (partial scans / --only runs).
        for line in self._read_lines("08_directory_discovery/all_paths.txt"):
            self._add(line, "dirsearch")

        # 5. crawled links (gospider / katana).
        for line in self._read_lines("09_crawling/all_urls.txt"):
            self._add(line, "crawled")

        # 6. Parameter-fuzzing candidate URLs — every url_with_params entry
        # is a real query-shaped endpoint the crawler saw. Missing this
        # source was leaving ?utm= and ?filter= URLs invisible to the
        # inventory even though the param_fuzz module was testing them.
        for line in self._read_lines("11_param_fuzzing/urls_with_params.txt"):
            self._add(line, "param-fuzz")

        # 7. JS-extracted endpoints (api_intelligence_engine writes *.txt here).
        js_dir = self.scan_dir / "09_crawling" / "js_downloads"
        if js_dir.is_dir():
            for jf in js_dir.glob("*.txt"):
                for line in jf.read_text(errors="ignore").splitlines():
                    self._add(line, "js")

        # 8. runtime XHR/fetch interception (Module 20) — highest value.
        for rel in ("20_api_deep_discovery/katana_headless_urls.txt",
                    "20_api_deep_discovery/xhr_intercepted.txt",
                    "20_api_deep_discovery/injection_targets.txt",
                    "20_api_deep_discovery/sqli_targets.txt"):
            for line in self._read_lines(rel):
                self._add(line, "api-runtime")
        for rel in ("20_api_deep_discovery/api_deep_discovery.jsonl",
                    "20_api_deep_discovery/api_endpoints.jsonl"):
            for line in self._read_lines(rel):
                line = line.strip()
                if not line:
                    continue
                try:
                    u = json.loads(line).get("url", "")
                except Exception:
                    continue
                if u:
                    self._add(u, "api-runtime")

        # 9. Input-function endpoints (Module 20.2 CDP discovery). These are real
        #    submit targets (login/search/upload/... actions), so they become
        #    endpoints AND carry the input-function metadata onto their row.
        self._gather_inputs()

        # 9b. MCP / AI surface endpoints (Module 8D, mcp_ai_probe.py). Confirmed
        #     MCP servers + fingerprinted AI/LLM endpoints. They become endpoints
        #     AND carry their ai_surface/ai_flavor/ai_confidence tag forward so
        #     classify_url() keeps the handshake-'confirmed' tier (not just the
        #     path-hint it would re-derive from the URL shape).
        self._gather_mcp_ai()

        # 10. HAR / browser-trace URLs (Module 0-HAR, har_ingest.py). Real
        #     captured browser traffic — the highest-trust provenance. Reading it
        #     here means a HAR-only endpoint (e.g. a WSS bootstrap the crawler
        #     never sees) still enters the inventory. WSS URLs stay in the HAR
        #     asset file; only http(s) URLs are folded here.
        n_before_har = len(self.eps)
        for line in self._read_lines("00_har_ingest/har_urls.txt"):
            self._add(line, "har")
        if len(self.eps) != n_before_har:
            log(f"after HAR: {len(self.eps)} unique paths "
                f"(+{len(self.eps) - n_before_har} HAR-only)")

        log(f"total unique endpoints after merge: {len(self.eps)}")

    def _gather_inputs(self) -> None:
        n = 0
        for line in self._read_lines("20_api_deep_discovery/input_functions.jsonl"):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except Exception:
                continue
            u = rec.get("url", "")
            if not u:
                continue
            self._add(u, "input")                    # ensure the action is an endpoint
            try:
                p = urllib.parse.urlsplit(u)
                if not self._in_scope(p.netloc):
                    continue
                host = p.netloc.split(":")[0].lower()
                key = (host, _id_template(p.path or "/"))
            except Exception:
                continue
            self.input_fns.setdefault(key, []).append({
                "function": rec.get("function", "input"),
                "method": (rec.get("method") or "GET").upper(),
                "accepts_file": bool(rec.get("accepts_file")),
                "params": rec.get("params", []),
                "source": rec.get("source", ""),
            })
            n += 1
        if n:
            log(f"input functions ingested: {n} across {len(self.input_fns)} endpoints")

    _AI_CONF_RANK = {None: 0, "": 0, "path-hint": 1, "fingerprint": 2, "confirmed": 3}

    def _gather_mcp_ai(self) -> None:
        n = 0
        for line in self._read_lines("08_directory_discovery/mcp_ai_endpoints.jsonl"):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except Exception:
                continue
            u = rec.get("url", "")
            surface = rec.get("ai_surface")
            if not u or not surface:
                continue
            self._add(u, "mcp-probe")                 # ensure it is an endpoint
            try:
                p = urllib.parse.urlsplit(u)
                if not self._in_scope(p.netloc):
                    continue
                host = p.netloc.split(":")[0].lower()
                key = (host, _id_template(p.path or "/"))
            except Exception:
                continue
            meta = {
                "ai_surface": surface,
                "ai_flavor": rec.get("ai_flavor"),
                "ai_confidence": rec.get("ai_confidence") or "path-hint",
                "tool_count": rec.get("tool_count"),
                "server_info": rec.get("server_info"),
            }
            prev = self.ai_meta.get(key)
            # keep the strongest-confidence tag when several concrete URLs
            # collapse into one template.
            if prev is None or self._AI_CONF_RANK.get(meta["ai_confidence"], 0) \
                    > self._AI_CONF_RANK.get(prev.get("ai_confidence"), 0):
                self.ai_meta[key] = meta
            n += 1
        if n:
            log(f"MCP/AI surfaces ingested: {n} across {len(self.ai_meta)} endpoints")

    # ---- templatize: collapse instance IDs + high-cardinality slug sets --- #
    def templatize(self) -> None:
        from collections import defaultdict
        # Positional cardinality collapse: a path SEGMENT at any depth whose
        # parent-prefix has >= threshold distinct children is an instance
        # identifier (content slug), not a fixed route — collapse it to {id}.
        # Nodes are keyed by the id-templated prefix so /stocks/<slug>/financials
        # and /stocks/<slug>/holdings both fold to /stocks/{id}/... while a real
        # API namespace (/api/v1 with a handful of resources) stays expanded.
        #
        # Pass 1: count distinct concrete children under each id-templated node.
        children: Dict[Tuple[str, str], Set[str]] = defaultdict(set)
        for ep in self.eps.values():
            idp = _id_template(ep.path).split("/")
            concrete = ep.path.split("/")
            prefix = ""
            for i in range(1, len(idp)):
                child = concrete[i] if i < len(concrete) else idp[i]
                if child:                       # ignore trailing-slash empties
                    children[(ep.host.lower(), prefix)].add(child)
                prefix = prefix + "/" + idp[i]
        highcard = {node for node, kids in children.items()
                    if len(kids) >= self.args.slug_threshold}
        if highcard:
            log(f"collapsing {len(highcard)} high-cardinality path segments "
                f"(>= {self.args.slug_threshold} distinct children)")

        # Pass 2: emit templated path, collapsing high-cardinality segments.
        for k, ep in self.eps.items():
            idp = _id_template(ep.path).split("/")
            out = [""]
            prefix = ""
            for i in range(1, len(idp)):
                seg = idp[i]
                # Never collapse the first path segment (prefix==""): top-level
                # routes (/stocks, /api, /blog) are namespaces, not instance ids.
                if seg and prefix and (ep.host.lower(), prefix) in highcard:
                    out.append("{id}")          # unifies slug + opaque-token
                else:
                    out.append(seg)
                prefix = prefix + "/" + idp[i]   # advance with id-templated seg
            tpath = "/".join(out) or "/"
            fkey = (ep.host.lower(), tpath)
            te = self.final.get(fkey)
            if te is None:
                te = TemplatedEndpoint(scheme=ep.scheme, host=ep.host, tpath=tpath)
                self.final[fkey] = te
            te.instances += 1
            te.sources |= ep.sources
            te.query_variants |= ep.query_variants
            concrete = f"{ep.scheme}://{ep.host}{ep.path}"
            cand = concrete + (f"?{ep.query}" if ep.query else "")
            # Choose the most useful representative sample: prefer one with a
            # known status, then one carrying a query string, else first seen.
            take = (not te.sample_url
                    or (ep.status is not None and te.status is None)
                    or (not te.sample_query and ep.query))
            if take:
                te.sample_url = cand
                te.sample_query = ep.query
            if ep.status is not None and te.status is None:
                te.status = ep.status
        log(f"templated endpoints: {len(self.final)} (from {len(self.eps)} concrete)")

    # ---- probe templated endpoints (no known status) with httpx ----------- #
    def probe(self) -> None:
        httpx = shutil.which(self.args.httpx) or shutil.which("httpx")
        if self.args.no_probe or not httpx:
            if not httpx and not self.args.no_probe:
                log("httpx not found — new endpoints left with status unknown")
            return
        pending = [te for te in self.final.values() if te.status is None]
        pending.sort(key=lambda e: SOURCE_PRIORITY.get(e.best_source(), 9))
        if len(pending) > self.args.max_probe:
            log(f"probing capped: {self.args.max_probe} of {len(pending)} endpoints")
            pending = pending[: self.args.max_probe]
        if not pending:
            return

        url_to_te: Dict[str, List[TemplatedEndpoint]] = {}
        for te in pending:
            url_to_te.setdefault(te.sample_url, []).append(te)

        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as tf:
            tf.write("\n".join(url_to_te.keys()))
            list_path = tf.name

        log(f"probing {len(url_to_te)} endpoints with httpx…")
        try:
            proc = subprocess.run(
                [httpx, "-l", list_path, "-silent", "-json", "-no-color",
                 "-status-code", "-content-type", "-timeout", str(self.args.timeout),
                 "-threads", str(self.args.threads),
                 "-rate-limit", str(self.args.rate)],
                capture_output=True, text=True, timeout=self.args.probe_timeout)
            out = proc.stdout
        except subprocess.TimeoutExpired:
            log("httpx probe timed out — partial statuses applied")
            out = ""
        except Exception as e:
            log(f"httpx probe failed: {e}")
            out = ""
        finally:
            try:
                os.unlink(list_path)
            except OSError:
                pass

        filled = 0
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                j = json.loads(line)
            except Exception:
                continue
            code = j.get("status_code")
            ctype = j.get("content_type") or ""
            for cand in (j.get("input"), j.get("url")):
                if cand and cand in url_to_te and code is not None:
                    for te in url_to_te[cand]:
                        if te.status is None:
                            te.status = int(code)
                            filled += 1
                        if ctype and not te.content_type:
                            te.content_type = ctype
                    break
        log(f"httpx filled {filled} statuses")

    # ---- probe HTTP methods (OPTIONS) for API-classed endpoints only ------- #
    def method_probe(self) -> None:
        """Send one OPTIONS per API-classed endpoint (capped) to learn the real
        Allow: method set — so the inventory shows PUT/DELETE/PATCH surfaces
        instead of a hardcoded GET. Web pages and static assets are skipped:
        method-probing a rendered page just manufactures phantom findings and
        burns requests (decision: API-classed only)."""
        if self.args.no_method_probe or url_class is None:
            return
        api_eps = [te for te in self.final.values()
                   if not is_cloud_storage(te.host)
                   and url_class(te.tpath, status=te.status,
                                 content_type=te.content_type,
                                 source=te.best_source(), host=te.host) == "api"]
        api_eps.sort(key=lambda e: SOURCE_PRIORITY.get(e.best_source(), 9))
        if len(api_eps) > self.args.max_method_probe:
            log(f"method-probe capped: {self.args.max_method_probe} of "
                f"{len(api_eps)} API endpoints")
            api_eps = api_eps[: self.args.max_method_probe]
        if not api_eps:
            return

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        # Probe concurrently but bounded. Serial probing of up to max_method_probe
        # endpoints (default 800) at ~200-400ms each was minutes of the
        # classification stage. A small pool cuts that ~Nx while staying modest
        # enough (default 10 concurrent OPTIONS) not to look like a flood to a WAF.
        workers = max(1, min(self.args.method_probe_concurrency, len(api_eps)))
        probed = 0
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=workers) as ex:
            results = ex.map(
                lambda te: (te, self._options_allow(te.sample_url or te.url, ctx)),
                api_eps)
            for te, allow in results:
                if allow:
                    te.methods = allow
                    probed += 1
        log(f"method-probe: filled Allow: on {probed}/{len(api_eps)} API endpoints "
            f"({workers} concurrent)")

    def _options_allow(self, url: str, ctx) -> List[str]:
        try:
            req = urllib.request.Request(url, method="OPTIONS")
            req.add_header("User-Agent", "ARISE-endpoint-consolidator")
            with urllib.request.urlopen(req, timeout=self.args.timeout,
                                        context=ctx) as resp:
                allow = resp.headers.get("Allow") or resp.headers.get("allow") or ""
        except urllib.error.HTTPError as e:  # 4xx/5xx still carry Allow sometimes
            allow = (e.headers.get("Allow") or e.headers.get("allow") or "") if e.headers else ""
        except Exception:
            return []
        methods = [m.strip().upper() for m in allow.split(",") if m.strip()]
        # de-dup, keep canonical order
        order = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE"]
        seen = set(methods)
        return [m for m in order if m in seen] + [m for m in methods if m not in order]

    # ---- write ------------------------------------------------------------ #
    def _classify(self, te: "TemplatedEndpoint") -> dict:
        """Full URL-Inventory classification for one templated endpoint, using
        the shared url_classify core so it matches the attack engine exactly.
        Returns {} when url_classify is unavailable (graceful degrade)."""
        if classify_url is None:
            return {}
        meta = self.ai_meta.get((te.host.lower(), te.tpath)) or \
            self.ai_meta.get((te.host.lower(), _id_template(te.tpath))) or {}
        return classify_url(
            te.url, status=te.status, content_type=te.content_type,
            source=te.best_source(), http_methods=te.methods, path=te.tpath,
            attributed_to=self.target,
            ai_surface_override=meta.get("ai_surface"),
            ai_flavor_override=meta.get("ai_flavor"),
            ai_confidence_override=meta.get("ai_confidence"),
        )

    def write(self, out_path: Path) -> Tuple[int, dict]:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        rows = sorted(self.final.values(), key=lambda e: (e.host, e.tpath))
        by_source: Dict[str, int] = {}
        by_status: Dict[str, int] = {}
        by_class: Dict[str, int] = {}
        verified_count = 0
        routing_path = out_path.parent / "attack_routing.jsonl"

        # Load the streaming access-control pipeline's WAF-block classifier
        # output (written concurrently with dirsearch). Any URL here is a
        # persistent 403 whose response carried a WAF signature — bypass
        # failed AND the origin isn't reachable. Stamp blocked_by_waf on
        # matching endpoint records so downstream (nuclei_url_consolidator)
        # can drop them from vuln-scan feeds. Match by canonical URL string;
        # a miss is a miss (never fabricate the flag).
        waf_blocked_map: Dict[str, List[str]] = {}
        waf_jsonl = out_path.parent / "waf_blocked.jsonl"
        if waf_jsonl.exists() and waf_jsonl.stat().st_size > 0:
            try:
                with waf_jsonl.open("r", encoding="utf-8", errors="replace") as wf:
                    for line in wf:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            row = json.loads(line)
                        except Exception:
                            continue
                        u = row.get("url")
                        sigs = row.get("matched_signatures") or []
                        if isinstance(u, str) and u:
                            waf_blocked_map[u] = list(sigs) if isinstance(sigs, list) else []
            except Exception:
                # Missing / corrupt waf_blocked.jsonl is non-fatal — the whole
                # WAF filter is a coverage optimisation, not a correctness gate.
                waf_blocked_map = {}
        with out_path.open("w") as fh, routing_path.open("w") as rf:
            for te in rows:
                cls = self._classify(te)
                methods = te.methods or ["GET"]
                # Attach input-function metadata discovered by the CDP module.
                ifns = self.input_fns.get((te.host.lower(), te.tpath)) or \
                    self.input_fns.get((te.host.lower(), _id_template(te.tpath))) or []
                # de-dup by (function, method), keep the union of params/file flag
                seen_if: Dict[Tuple[str, str], dict] = {}
                for r in ifns:
                    k = (r["function"], r["method"])
                    if k not in seen_if:
                        seen_if[k] = {"function": r["function"], "method": r["method"],
                                      "accepts_file": r["accepts_file"],
                                      "params": list(r.get("params") or [])}
                    else:
                        seen_if[k]["accepts_file"] |= r["accepts_file"]
                        seen_if[k]["params"] = sorted(set(seen_if[k]["params"]) | set(r.get("params") or []))
                input_functions = list(seen_if.values())
                primary_fn = input_functions[0]["function"] if input_functions else None
                rec = {
                    "url": te.url,                 # templated (display key)
                    "sample_url": te.sample_url,   # concrete, clickable/probe-able
                    "host": te.host,
                    "path": te.tpath,
                    "query": te.sample_query,
                    "status": te.status if te.status is not None else 0,
                    # F29 (ARISE_REMEDIATION_ROADMAP.md): status=0 was the
                    # ONLY signal for "never actually fetched" (e.g. a
                    # dirbrute/wordlist-expanded or gau-mined URL nobody ever
                    # requested), indistinguishable downstream from a real
                    # probe result. Explicit flag so the UI/nuclei feed can
                    # default to confirmed-only instead of showing a 90%+
                    # noise floor of URLs nobody ever confirmed exist.
                    "verified": te.status is not None,
                    "source": te.best_source(),
                    "sources": sorted(te.sources),
                    "instances": te.instances,
                    # Distinct query-key shapes seen across all concrete URLs
                    # that collapsed into this template. Sorted list of
                    # comma-separated key names — e.g. ["q", "category,sort",
                    # "q,limit,offset"]. Downstream scanners can iterate this
                    # to generate one attack per query shape (query keys can
                    # gate different code paths, so treating them as one row
                    # would miss surfaces).
                    "query_variants": sorted(te.query_variants),
                    "method": methods[0],          # back-compat: primary method
                    "methods": methods,            # full probed Allow: set
                    # Request provenance (R4): canonical evidence class of the
                    # BEST source that discovered this endpoint. har/browser =
                    # real traffic; dirbrute/synthetic = we guessed/fabricated it.
                    "provenance": provenance_of(te.best_source()),
                    # --- URL-Inventory classification (new) ---
                    "url_class": cls.get("url_class", "unknown"),
                    "api_type": cls.get("api_type"),
                    "url_shape": cls.get("url_shape", "plain"),
                    "sensitivity": cls.get("sensitivity", "normal"),
                    "auth_state": cls.get("auth_state", "unknown"),
                    "content_type": te.content_type,
                    # cloud-storage attribution (bucket mapped to scoped target)
                    "cloud_provider": cls.get("cloud_provider"),
                    "cloud_bucket": cls.get("cloud_bucket"),
                    "attributed_to": cls.get("attributed_to"),
                    # AI / MCP surface tag (orthogonal to url_class; None on
                    # non-AI URLs). tool_count/server_info enrich the row when
                    # the probe module confirmed an MCP server via handshake.
                    "ai_surface": cls.get("ai_surface"),
                    "ai_flavor": cls.get("ai_flavor"),
                    "ai_confidence": cls.get("ai_confidence"),
                    "ai_tool_count": (self.ai_meta.get((te.host.lower(), te.tpath)) or {}).get("tool_count"),
                    "ai_server_info": (self.ai_meta.get((te.host.lower(), te.tpath)) or {}).get("server_info"),
                    # input-functions (CDP discovery)
                    "input_functions": input_functions,
                    "input_function": primary_fn,
                    "accepts_file": any(f["accepts_file"] for f in input_functions),
                    "routed_to": cls.get("routed_to", []),
                    # WAF-block classification (from access_control_pipeline.py):
                    # true = persistent 403 whose response matched a WAF
                    # signature after bypass_403 failed. nuclei_url_consolidator
                    # drops these; keep the field on non-blocked rows too so
                    # dashboard/exports have a uniform schema.
                    "blocked_by_waf": te.sample_url in waf_blocked_map,
                    "waf_signatures": waf_blocked_map.get(te.sample_url, []),
                }
                # Merge input-function attack lanes into the routing map.
                for f in input_functions:
                    lane = INPUT_FN_LANES.get(f["function"])
                    if lane and lane not in rec["routed_to"]:
                        rec["routed_to"].append(lane)
                fh.write(json.dumps(rec) + "\n")
                # Attack-routing map: one row per (url -> attack lane) so
                # downstream modules read their own lane instead of re-grepping.
                for lane in rec["routed_to"]:
                    rf.write(json.dumps({
                        "url": te.sample_url or te.url,
                        "template": te.url,
                        "host": te.host,
                        "attack": lane,
                        "url_class": rec["url_class"],
                        "api_type": rec["api_type"],
                        "url_shape": rec["url_shape"],
                        "ai_surface": rec["ai_surface"],
                        "ai_confidence": rec["ai_confidence"],
                        "methods": methods,
                        "status": rec["status"],
                        "verified": rec["verified"],
                    }) + "\n")
                by_source[rec["source"]] = by_source.get(rec["source"], 0) + 1
                sc = str(rec["status"])
                by_status[sc] = by_status.get(sc, 0) + 1
                by_class[rec["url_class"]] = by_class.get(rec["url_class"], 0) + 1
                if rec["verified"]:
                    verified_count += 1

        summary = {
            "module": "endpoint_consolidation",
            "target": self.target,
            "total_endpoints": len(rows),
            "verified_endpoints": verified_count,
            "concrete_urls_collapsed": sum(te.instances for te in rows),
            "by_source": by_source,
            "by_status": by_status,
            "by_class": by_class,
        }
        (out_path.parent / "discovered_endpoints_summary.json").write_text(
            json.dumps(summary, indent=2))

        # Class-aware dirsearch feed split — API endpoints get the wide
        # status allowlist; non-API URLs keep the leaner one. Both files
        # feed dirsearch's second pass; hits merge back into the URL
        # inventory downstream.
        api_targets_path = out_path.parent / "dirsearch_api_targets.txt"
        web_targets_path = out_path.parent / "dirsearch_web_targets.txt"
        api_urls = set()
        web_urls = set()
        for te in rows:
            cls = self._classify(te)
            uc = (cls.get("url_class") or "").lower()
            is_api = (uc.startswith("api") or
                      cls.get("api_type") in ("rest", "graphql", "json"))
            # Base URL for dirsearch — drop path so it fuzzes the host root
            # of each unique origin. host_canonical already handles dedup.
            base = te.host
            if is_api:
                api_urls.add(base)
            else:
                web_urls.add(base)
        with api_targets_path.open("w") as f:
            for h in sorted(api_urls):
                f.write(f"https://{h}\n")
        with web_targets_path.open("w") as f:
            for h in sorted(web_urls):
                f.write(f"https://{h}\n")

        return len(rows), summary

    def run(self, out_path: Path) -> Tuple[int, dict]:
        self.gather()
        self.templatize()
        self.probe()
        self.method_probe()
        return self.write(out_path)


def main() -> int:
    ap = argparse.ArgumentParser(description="ARISE Endpoint Consolidator")
    ap.add_argument("target")
    ap.add_argument("--scan-dir", required=True)
    ap.add_argument("--out", default="")
    ap.add_argument("--max-probe", type=int, default=3000)
    ap.add_argument("--slug-threshold", type=int, default=40,
                    help="Collapse a path prefix's leaf to {slug} when it has "
                         "at least this many distinct children (content pages). "
                         "Kept high enough that real API namespaces stay expanded.")
    ap.add_argument("--no-probe", action="store_true")
    ap.add_argument("--no-method-probe", action="store_true",
                    help="Skip the OPTIONS Allow: probe (methods stay [GET]).")
    ap.add_argument("--max-method-probe", type=int, default=800,
                    help="Cap on OPTIONS requests; only API-classed endpoints "
                         "are probed, highest-value sources first.")
    ap.add_argument("--method-probe-concurrency", type=int, default=10,
                    help="Concurrent OPTIONS probes. Kept modest by default so "
                         "the burst stays below WAF rate-limit thresholds.")
    ap.add_argument("--httpx", default="httpx")
    ap.add_argument("--timeout", type=int, default=7)
    ap.add_argument("--threads", type=int, default=40)
    ap.add_argument("--rate", type=int, default=150)
    ap.add_argument("--probe-timeout", type=int, default=600)
    args = ap.parse_args()

    scan_dir = Path(args.scan_dir)
    if not scan_dir.is_dir():
        log(f"scan-dir not found: {scan_dir}")
        return 1
    out_path = Path(args.out) if args.out else \
        scan_dir / "08_directory_discovery" / "discovered_endpoints.jsonl"

    c = Consolidator(args.target, scan_dir, args)
    n, summary = c.run(out_path)
    log(f"done: {n} endpoints -> {out_path}")
    log("by source: " + ", ".join(f"{k}={v}" for k, v in
                                   sorted(summary["by_source"].items())))
    return 0


if __name__ == "__main__":
    sys.exit(main())
