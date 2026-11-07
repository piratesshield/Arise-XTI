#!/usr/bin/env python3
"""SBOM builder — deep, multi-method software + version inventory (Phase 1).

Builds a Software Bill of Materials for a scan by MINING the data the pipeline
already captured (no re-probing), extracting component names AND versions from
several independent methods, tagged by surface (web / api / ai-llm / mcp / infra):

  http-header    Server, X-Powered-By, X-AspNet-Version, X-Generator, Via, …
  set-cookie     framework session-cookie fingerprints (ASP.NET, Laravel, …)
  html-meta      <meta name="generator" content="WordPress 6.4.2">
  html-asset     versioned <script>/<link> srcs (jquery-3.6.0, react@18.2.0, …)
  service-banner nmap -sV product/version/CPE
  wappalyzer     httpx tech-detect (name only; version usually absent)
  api-schema     OpenAPI info.version + API framework
  mcp-handshake  MCP serverInfo.name/version + protocolVersion
  llm-endpoint   LLM gateway / model-management fingerprint (/v1/models, …)

A component seen by >=2 methods is corroborated (higher confidence). Each record
carries purl + cpe (best-effort) so Phase 2 (CVE correlation) is a lookup.

Outputs (in <scan>/<SBOM_SUBDIR>/):
  sbom.jsonl     one row per consolidated component
  sbom.json      summary (counts by surface / category / confidence)
  sbom.cdx.json  CycloneDX 1.5 export
"""
import sys as _sys, os as _os
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)

import json
import os
import re
import glob
import argparse
from collections import defaultdict

SBOM_SUBDIR = "25_sbom"

# ---------------------------------------------------------------------------
# Signatures
# ---------------------------------------------------------------------------
# Specific response headers → component. version_group pulls the version out of
# the header value (None = presence only).  (header, name, category, surface, vregex)
HEADER_SIGS = [
    ("x-powered-by",        None,            None,            "web",   None),  # parsed specially
    ("x-aspnet-version",    "ASP.NET",       "framework",     "web",   r"([\d.]+)"),
    ("x-aspnetmvc-version", "ASP.NET MVC",   "framework",     "web",   r"([\d.]+)"),
    ("x-generator",         None,            "cms",           "web",   r"^([A-Za-z][\w .-]*?)[ /]?([\d.]+)?$"),
    ("x-drupal-dynamic-cache", "Drupal",     "cms",           "web",   None),
    ("x-drupal-cache",      "Drupal",        "cms",           "web",   None),
    ("x-runtime",           "Ruby on Rails", "framework",     "web",   None),
    ("x-turbo-charged-by",  "LiteSpeed",     "web-server",    "infra", None),
    ("x-litespeed-cache",   "LiteSpeed",     "web-server",    "infra", None),
    ("x-varnish",           "Varnish",       "cache",         "infra", None),
    ("x-shopify-stage",     "Shopify",       "cms",           "web",   None),
    ("x-jenkins",           "Jenkins",       "application",   "infra", r"([\d.]+)"),
    ("x-envoy-upstream-service-time", "Envoy", "proxy",       "infra", None),
    ("x-envoy-datacenter",  "Envoy",         "proxy",         "infra", None),
    ("akamai-grn",          "Akamai",        "cdn",           "infra", None),
    ("x-amz-cf-id",         "Amazon CloudFront", "cdn",       "infra", None),
    ("x-amz-request-id",    "Amazon S3",     "cloud-service", "infra", None),
    ("x-goog-generation",   "Google Cloud Storage", "cloud-service", "infra", None),
    ("cf-ray",              "Cloudflare",    "cdn",           "infra", None),
    ("x-vercel-id",         "Vercel",        "cloud-service", "infra", None),
    ("x-nf-request-id",     "Netlify",       "cloud-service", "infra", None),
    ("x-fastly-request-id", "Fastly",        "cdn",           "infra", None),
    ("request-context",     "Azure App Insights", "cloud-service", "infra", None),
    ("x-ms-request-id",     "Microsoft Azure", "cloud-service", "infra", None),
    ("x-sourcemap",         "Source Map",    "disclosure",    "web",   None),
    ("x-kong-upstream-latency", "Kong",      "api-gateway",   "api",   None),
    ("via",                 None,            "proxy",         "infra", None),  # parsed specially
]

# X-Powered-By tokens → (name, category, surface, vregex)
POWERED_BY = [
    (r"PHP/?([\d.]+)?",        "PHP",        "language",   "web"),
    (r"ASP\.NET",              "ASP.NET",    "framework",  "web"),
    (r"Express",               "Express",    "framework",  "web"),
    (r"Next\.js",              "Next.js",    "framework",  "web"),
    (r"Nuxt(?:\.js)?",         "Nuxt",       "framework",  "web"),
    (r"WP Engine",             "WP Engine",  "hosting",    "infra"),
    (r"Servlet/?([\d.]+)?",    "Java Servlet", "framework","web"),
    (r"PleskLin",              "Plesk",      "panel",      "infra"),
]

# Set-Cookie name fingerprints → (substr, name, category, surface)
COOKIE_SIGS = [
    ("asp.net_sessionid", "ASP.NET",       "framework", "web"),
    ("cfduid",            "Cloudflare",    "cdn",       "infra"),
    ("laravel_session",   "Laravel",       "framework", "web"),
    ("ci_session",        "CodeIgniter",   "framework", "web"),
    ("jsessionid",        "Java (JSP/Servlet)", "framework", "web"),
    ("phpsessid",         "PHP",           "language",  "web"),
    ("django",            "Django",        "framework", "web"),
    ("connect.sid",       "Express",       "framework", "web"),
    ("_shopify",          "Shopify",       "cms",       "web"),
    ("wordpress_",        "WordPress",     "cms",       "web"),
    ("wp-settings",       "WordPress",     "cms",       "web"),
    ("sails.sid",         "Sails.js",      "framework", "web"),
    ("rack.session",      "Ruby Rack",     "framework", "web"),
    ("_rails",            "Ruby on Rails", "framework", "web"),
    ("xsrf_token=cfdj8",  "ASP.NET Core",  "framework", "web"),  # CfDJ8 = AspNetCore DataProtection
    (".aspnetcore",       "ASP.NET Core",  "framework", "web"),
]

# HTML <meta name="generator"> → version captured generically.
_META_GEN_RE = re.compile(
    r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', re.I)

# Versioned asset srcs: name + version from <script src>/<link href>.
# (regex over the URL, group(1)=version)   name, category
ASSET_SIGS = [
    (r"jquery[.\-](\d+\.\d+(?:\.\d+)?)", "jQuery", "js-library"),
    (r"jquery-ui[.\-](\d+\.\d+(?:\.\d+)?)", "jQuery UI", "js-library"),
    (r"bootstrap[./@\-](\d+\.\d+(?:\.\d+)?)", "Bootstrap", "js-library"),
    (r"react(?:-dom)?[@/\-](\d+\.\d+(?:\.\d+)?)", "React", "js-library"),
    (r"angular(?:js)?[./@\-](\d+\.\d+(?:\.\d+)?)", "Angular", "js-library"),
    (r"vue[@./\-](\d+\.\d+(?:\.\d+)?)", "Vue.js", "js-library"),
    (r"d3[.\-]v?(\d+\.\d+(?:\.\d+)?)", "D3.js", "js-library"),
    (r"lodash[.\-](\d+\.\d+(?:\.\d+)?)", "Lodash", "js-library"),
    (r"moment[.\-](\d+\.\d+(?:\.\d+)?)", "Moment.js", "js-library"),
    (r"swiper[@./\-](\d+\.\d+(?:\.\d+)?)", "Swiper", "js-library"),
    (r"gsap[@./\-](\d+\.\d+(?:\.\d+)?)", "GSAP", "js-library"),
    (r"fontawesome[^0-9]*(\d+\.\d+(?:\.\d+)?)", "Font Awesome", "js-library"),
    (r"select2[.\-](\d+\.\d+(?:\.\d+)?)", "Select2", "js-library"),
    (r"slick[.\-](\d+\.\d+(?:\.\d+)?)", "Slick Carousel", "js-library"),
    (r"tailwind[^0-9]*(\d+\.\d+(?:\.\d+)?)", "Tailwind CSS", "js-library"),
]
# WordPress asset ?ver= hint
_WP_VER_RE = re.compile(r"/wp-(?:content|includes)/[^\"']*?[?&]ver=(\d+\.\d+(?:\.\d+)?)", re.I)

# Vendor map for CPE (name_lower -> (vendor, product))
VENDOR_MAP = {
    "nginx": ("nginx", "nginx"), "apache": ("apache", "http_server"),
    "apache httpd": ("apache", "http_server"), "openssh": ("openbsd", "openssh"),
    "php": ("php", "php"), "wordpress": ("wordpress", "wordpress"),
    "drupal": ("drupal", "drupal"), "joomla": ("joomla", "joomla"),
    "jquery": ("jquery", "jquery"), "bootstrap": ("getbootstrap", "bootstrap"),
    "react": ("facebook", "react"), "angular": ("angular", "angular"),
    "vue.js": ("vuejs", "vue"), "lodash": ("lodash", "lodash"),
    "express": ("openjsf", "express"), "django": ("djangoproject", "django"),
    "laravel": ("laravel", "laravel"), "asp.net": ("microsoft", "asp.net"),
    "asp.net core": ("microsoft", "asp.net_core"), "iis": ("microsoft", "iis"),
    "tomcat": ("apache", "tomcat"), "jenkins": ("jenkins", "jenkins"),
    "litespeed": ("litespeedtech", "litespeed_web_server"),
    "varnish": ("varnish-software", "varnish_cache"), "envoy": ("envoyproxy", "envoy"),
    "ruby on rails": ("rubyonrails", "rails"), "next.js": ("vercel", "next.js"),
}
# npm-ecosystem components (purl = pkg:npm)
_NPM = {"jquery", "jquery ui", "bootstrap", "react", "angular", "vue.js", "d3.js",
        "lodash", "moment.js", "swiper", "gsap", "select2", "express", "next.js",
        "nuxt", "tailwind css"}

_CONF_RANK = {"low": 0, "medium": 1, "high": 2}

# Collapse equivalent names reported differently by different methods.
_NAME_ALIASES = {
    "microsoft asp.net": "ASP.NET", "microsoft-iis": "IIS", "microsoft iis": "IIS",
    "akamaighost": "Akamai", "akamai ghost": "Akamai", "nginx": "nginx",
    "cloudflare": "Cloudflare", "ruby": "Ruby", "openresty": "OpenResty",
    "cloudfront": "Amazon CloudFront", "amazon cloudfront": "Amazon CloudFront",
    "microsoft-httpapi": "Microsoft HTTPAPI", "microsoft httpapi httpd": "Microsoft HTTPAPI",
    "amazon web services": "Amazon Web Services", "aws": "Amazon Web Services",
}


# ---------------------------------------------------------------------------
# Response parsing
# ---------------------------------------------------------------------------
def _read_response(path):
    """Parse an httpx stored response file → {status, headers(multi), body}."""
    try:
        with open(path, "r", errors="ignore") as f:
            data = f.read()
    except Exception:
        return None
    # httpx stores: <request block>\n\n<response block>. Seek the response.
    m = re.search(r"(?:^|\n)\s*(HTTP/\d[^\n]*)", data)
    # prefer the SECOND HTTP/ line (first is in the request echo on some versions)
    idxs = [mm.start() for mm in re.finditer(r"\nHTTP/\d", data)]
    start = idxs[-1] + 1 if idxs else (m.start() if m else 0)
    resp = data[start:]
    parts = re.split(r"\r?\n\r?\n", resp, maxsplit=1)
    head = parts[0]
    body = parts[1] if len(parts) > 1 else ""
    lines = head.splitlines()
    status = 0
    if lines and lines[0].startswith("HTTP/"):
        try:
            status = int(lines[0].split()[1])
        except Exception:
            pass
    headers = defaultdict(list)
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            headers[k.strip().lower()].append(v.strip())
    return {"status": status, "headers": headers, "body": body[:400000]}


def _h1(headers, name):
    v = headers.get(name)
    return v[0] if v else ""


# ---------------------------------------------------------------------------
# Component accumulator
# ---------------------------------------------------------------------------
class Sbom:
    def __init__(self):
        self.items = {}  # (name_lower, version) -> component

    def add(self, name, version, category, surface, method, host, evidence,
            confidence="medium"):
        name = (name or "").strip()
        if not name:
            return
        name = _NAME_ALIASES.get(name.lower(), name)
        version = (version or "").strip()
        key = (name.lower(), version)
        c = self.items.get(key)
        if not c:
            c = {"name": name, "version": version, "category": category or "other",
                 "surface": surface or "web", "methods": [], "hosts": [],
                 "evidence": [], "confidence": confidence}
            self.items[key] = c
        if method and method not in c["methods"]:
            c["methods"].append(method)
        if host and host not in c["hosts"]:
            c["hosts"].append(host)
        if evidence and evidence not in c["evidence"]:
            c["evidence"].append(evidence[:300])
        # keep the strongest category/surface we learn (prefer non-'other'/'web')
        if (c["category"] in ("other", None)) and category:
            c["category"] = category
        if c["surface"] == "web" and surface and surface != "web":
            c["surface"] = surface
        # confidence = max(seen); corroboration by >=2 methods bumps to >= high
        if _CONF_RANK.get(confidence, 1) > _CONF_RANK.get(c["confidence"], 1):
            c["confidence"] = confidence

    def finalize(self):
        out = []
        for c in self.items.values():
            if len(c["methods"]) >= 2 and c["version"]:
                c["confidence"] = "high"
            elif len(c["methods"]) >= 2 and _CONF_RANK.get(c["confidence"], 1) < 1:
                c["confidence"] = "medium"
            c["host_count"] = len(c["hosts"])
            c["purl"], c["cpe"] = _purl_cpe(c["name"], c["version"])
            out.append(c)
        out.sort(key=lambda x: (-_CONF_RANK.get(x["confidence"], 0),
                                -(1 if x["version"] else 0), -x["host_count"],
                                x["surface"], x["name"].lower()))
        return out


def _purl_cpe(name, version):
    nl = name.lower()
    purl = None
    if nl in _NPM:
        purl = "pkg:npm/%s%s" % (name.lower().replace(" ", "-"),
                                 "@" + version if version else "")
    else:
        slug = re.sub(r"[^a-z0-9.]+", "-", nl).strip("-")
        purl = "pkg:generic/%s%s" % (slug, "@" + version if version else "")
    cpe = None
    if nl in VENDOR_MAP:
        vendor, product = VENDOR_MAP[nl]
        cpe = "cpe:2.3:a:%s:%s:%s:*:*:*:*:*:*:*" % (vendor, product, version or "*")
    return purl, cpe


# ---------------------------------------------------------------------------
# Extractors
# ---------------------------------------------------------------------------
def _from_headers(sb, host, resp):
    H = resp["headers"]
    # Server: nginx/1.21.0 (Ubuntu)
    srv = _h1(H, "server")
    if srv:
        m = re.match(r"([A-Za-z][\w\-]*)(?:/([\d.]+))?", srv)
        if m and m.group(1).lower() not in ("cloudflare", "envoy", "akamaighost"):
            sb.add(m.group(1), m.group(2) or "", "web-server", "infra",
                   "http-header", host, "Server: " + srv,
                   "high" if m.group(2) else "medium")
        elif m:  # cdn/proxy servers
            cat = "cdn" if m.group(1).lower() in ("cloudflare", "akamaighost") else "proxy"
            sb.add(m.group(1), "", cat, "infra", "http-header", host, "Server: " + srv, "medium")
    # X-Powered-By (may list several)
    xpb = _h1(H, "x-powered-by")
    if xpb:
        for pat, nm, cat, surf in POWERED_BY:
            mm = re.search(pat, xpb, re.I)
            if mm:
                ver = mm.group(1) if mm.groups() and mm.lastindex else ""
                sb.add(nm, ver or "", cat, surf, "http-header", host,
                       "X-Powered-By: " + xpb, "high" if ver else "medium")
    # specific headers
    for hdr, nm, cat, surf, vregex in HEADER_SIGS:
        if hdr in ("x-powered-by", "via"):
            continue
        if hdr in H:
            val = _h1(H, hdr)
            name, ver = nm, ""
            if vregex:
                mm = re.search(vregex, val)
                if mm:
                    if nm is None and mm.lastindex and mm.lastindex >= 1:
                        name = mm.group(1)
                        ver = mm.group(2) if mm.lastindex >= 2 else ""
                    elif mm.groups():
                        ver = mm.group(mm.lastindex) if mm.lastindex else ""
            if name:
                sb.add(name, ver or "", cat, surf, "http-header", host,
                       "%s: %s" % (hdr, val), "high" if ver else "medium")
    # Via: 1.1 varnish, 1.1 google
    via = _h1(H, "via")
    if via:
        for tok in re.findall(r"[A-Za-z][\w\-]+", via):
            tl = tok.lower()
            if tl in ("varnish", "squid", "cloudfront", "google"):
                sb.add(tok.title(), "", "proxy" if tl in ("varnish", "squid") else "cdn",
                       "infra", "http-header", host, "Via: " + via, "medium")


def _from_cookies(sb, host, resp):
    cookies = resp["headers"].get("set-cookie", [])
    blob = " ".join(cookies).lower()
    for substr, nm, cat, surf in COOKIE_SIGS:
        if substr in blob:
            sb.add(nm, "", cat, surf, "set-cookie", host,
                   "Set-Cookie fingerprint: " + substr, "medium")


def _from_body(sb, host, resp):
    body = resp["body"]
    if not body:
        return
    # <meta generator>
    for g in _META_GEN_RE.findall(body):
        mm = re.match(r"([A-Za-z][\w .\-]*?)[ v]*?([\d.]+)?$", g.strip())
        if mm and mm.group(1):
            sb.add(mm.group(1).strip(), (mm.group(2) or "").strip(), "cms", "web",
                   "html-meta", host, 'generator="%s"' % g.strip(),
                   "high" if mm.group(2) else "medium")
    # versioned assets
    for pat, nm, cat in ASSET_SIGS:
        mm = re.search(pat, body, re.I)
        if mm:
            sb.add(nm, mm.group(1), cat, "web", "html-asset", host,
                   "asset match: %s@%s" % (nm, mm.group(1)), "high")
    # WordPress ?ver=
    wp = _WP_VER_RE.search(body)
    if wp:
        sb.add("WordPress", wp.group(1), "cms", "web", "html-asset", host,
               "wp asset ?ver=%s" % wp.group(1), "medium")
    elif "/wp-content/" in body or "/wp-includes/" in body:
        sb.add("WordPress", "", "cms", "web", "html-asset", host, "wp-content path", "medium")


def _from_nmap(sb, scan_dir):
    f = os.path.join(scan_dir, "07_service_fingerprint", "services.json")
    if not os.path.exists(f):
        return
    try:
        rows = json.load(open(f, errors="ignore"))
    except Exception:
        return
    for r in rows if isinstance(rows, list) else []:
        prod = (r.get("product") or "").strip()
        prod = re.sub(r"\s+httpd$", "", prod, flags=re.I)  # nmap appends " httpd" to HTTP services
        ver = (r.get("version") or "").strip()
        if not prod:
            continue
        host = r.get("host") or r.get("ip") or ""
        cat = "service"
        surf = "infra"
        sb.add(prod, ver, cat, surf, "service-banner", host,
               ("nmap %s/%s %s %s" % (r.get("port"), r.get("protocol"), prod, ver)).strip(),
               "high" if ver else "medium")
        # keep nmap's own CPE if present
        cpes = r.get("cpe") or []
        if cpes:
            key = (prod.lower(), ver)
            if key in sb.items and not sb.items[key].get("_nmap_cpe"):
                sb.items[key]["_nmap_cpe"] = cpes[0]


def _from_httpx_tech(sb, scan_dir):
    f = os.path.join(scan_dir, "04_http_discovery", "tech_by_host.jsonl")
    if not os.path.exists(f):
        return
    for line in open(f, errors="ignore"):
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
        except Exception:
            continue
        host = r.get("host", "")
        for t in r.get("tech", []):
            nm = (t.get("name") or "").strip()
            if not nm or nm.upper() == "HSTS":
                continue
            ver = (t.get("version") or "").strip()
            sb.add(nm, ver, "application", "web", "wappalyzer", host,
                   "httpx tech: " + nm, "high" if ver else "low")


def _from_api_schema(sb, scan_dir):
    for f in glob.glob(os.path.join(scan_dir, "**", "*schema*"), recursive=True) + \
             glob.glob(os.path.join(scan_dir, "**", "*openapi*"), recursive=True):
        if not f.endswith((".json", ".jsonl")):
            continue
        try:
            txt = open(f, errors="ignore").read()
        except Exception:
            continue
        for mm in re.finditer(r'"openapi"\s*:\s*"([\d.]+)"', txt):
            sb.add("OpenAPI", mm.group(1), "api-spec", "api", "api-schema", "",
                   "openapi %s in %s" % (mm.group(1), os.path.basename(f)), "high")
        for mm in re.finditer(r'"swagger"\s*:\s*"([\d.]+)"', txt):
            sb.add("Swagger", mm.group(1), "api-spec", "api", "api-schema", "",
                   "swagger %s" % mm.group(1), "high")
        if re.search(r'"__schema"|graphql', txt, re.I):
            sb.add("GraphQL", "", "api-framework", "api", "api-schema", "",
                   "GraphQL schema present", "medium")


def _from_ai_mcp(sb, scan_dir):
    """Ingest only CONFIRMED-identified AI/LLM + MCP software from mcp_ai_probe.

    A fingerprint-only surface (e.g. a 403 on /mcp) is a POSTURE finding, not an
    identified component — it has no name/version to inventory — so it is NOT an
    SBOM entry. Only a real handshake (serverInfo / protocolVersion), an actual
    advertised model list, or a 'confirmed'-confidence gateway becomes an SBOM
    component. (The posture findings still live in the AI/MCP findings view.)
    """
    files = (glob.glob(os.path.join(scan_dir, "**", "mcp_ai_findings.jsonl"), recursive=True) +
             glob.glob(os.path.join(scan_dir, "**", "*mcp_ai_probe_results.json"), recursive=True))
    for f in files:
        try:
            if f.endswith(".jsonl"):
                recs = [json.loads(l) for l in open(f, errors="ignore") if l.strip()]
            else:
                blob = json.load(open(f, errors="ignore"))
                recs = blob if isinstance(blob, list) else (
                    blob.get("findings") or blob.get("records") or blob.get("servers") or [])
            if not isinstance(recs, list):
                recs = []
        except Exception:
            continue
        for r in recs:
            if not isinstance(r, dict):
                continue
            host = r.get("host") or r.get("url") or ""
            conf = (r.get("ai_confidence") or r.get("confidence") or "").lower()
            info = r.get("serverInfo") or (r.get("detail") or {}).get("serverInfo") or {}
            proto = r.get("protocolVersion") or (r.get("detail") or {}).get("protocolVersion")
            models = r.get("models") or []
            if info.get("name"):  # confirmed MCP server identity
                sb.add("MCP: " + info["name"], info.get("version") or "", "mcp-server",
                       "mcp", "mcp-handshake", host,
                       "MCP serverInfo %s %s" % (info["name"], info.get("version") or ""),
                       "high" if info.get("version") else "medium")
            if proto:  # successful handshake negotiated a protocol
                sb.add("Model Context Protocol", str(proto), "protocol", "mcp",
                       "mcp-handshake", host, "MCP protocolVersion %s" % proto, "high")
            for m in models:  # actual advertised model list
                sb.add("Model: " + str(m), "", "ai-model", "ai-llm", "llm-endpoint",
                       host, "model advertised: %s" % m, "medium")
            if conf == "confirmed":  # confirmed LLM gateway (not a fingerprint guess)
                flavor = r.get("ai_flavor") or ""
                nm = {"openai-compat": "OpenAI-compatible LLM API",
                      "ollama": "Ollama"}.get(flavor, flavor or "LLM gateway")
                sb.add(nm, "", "ai-gateway", "ai-llm", "llm-endpoint", host,
                       (r.get("evidence") or "AI gateway " + flavor)[:200], "medium")


# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------
def build(scan_dir, hosts_filter=None):
    sb = Sbom()
    http_file = os.path.join(scan_dir, "04_http_discovery", "http_confirmed.json")
    entries = []
    if os.path.exists(http_file):
        for line in open(http_file, errors="ignore"):
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except Exception:
                pass
    # pick the best stored response per host (prefer https/200)
    best = {}
    for e in entries:
        host = e.get("host") or e.get("input")
        if not host or (hosts_filter and host not in hosts_filter):
            continue
        p = e.get("stored_response_path")
        if not p:
            continue
        score = (1 if (e.get("scheme") == "https" or ":443" in (e.get("url") or "")) else 0) * 10
        score += 5 if (e.get("status_code") in (200, 403, 401)) else 0
        if host not in best or score > best[host][0]:
            best[host] = (score, p)
    for host, (_, p) in best.items():
        resp = _read_response(p)
        if not resp:
            continue
        _from_headers(sb, host, resp)
        _from_cookies(sb, host, resp)
        _from_body(sb, host, resp)

    _from_nmap(sb, scan_dir)
    _from_httpx_tech(sb, scan_dir)
    _from_api_schema(sb, scan_dir)
    _from_ai_mcp(sb, scan_dir)

    components = sb.finalize()
    # fold nmap CPE into cpe field
    for c in components:
        nc = sb.items.get((c["name"].lower(), c["version"]), {}).get("_nmap_cpe")
        if nc and not c.get("cpe"):
            c["cpe"] = nc if nc.startswith("cpe:") else ("cpe:2.3:a:" + nc)

    summary = _summarize(components)
    out_dir = os.path.join(scan_dir, SBOM_SUBDIR)
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "sbom.jsonl"), "w") as f:
        for c in components:
            f.write(json.dumps(c) + "\n")
    with open(os.path.join(out_dir, "sbom.json"), "w") as f:
        json.dump(summary, f, indent=2)
    with open(os.path.join(out_dir, "sbom.cdx.json"), "w") as f:
        json.dump(_cyclonedx(components, scan_dir), f, indent=2)
    return summary


def _summarize(components):
    by_surface, by_cat, by_conf, by_method = {}, {}, {}, {}
    with_ver = 0
    for c in components:
        by_surface[c["surface"]] = by_surface.get(c["surface"], 0) + 1
        by_cat[c["category"]] = by_cat.get(c["category"], 0) + 1
        by_conf[c["confidence"]] = by_conf.get(c["confidence"], 0) + 1
        for m in c["methods"]:
            by_method[m] = by_method.get(m, 0) + 1
        if c["version"]:
            with_ver += 1
    return {
        "total_components": len(components),
        "with_version": with_ver,
        "by_surface": by_surface, "by_category": by_cat,
        "by_confidence": by_conf, "by_method": by_method,
    }


def _cyclonedx(components, scan_dir):
    target = os.path.basename(scan_dir.rstrip("/"))
    comps = []
    for c in components:
        comp = {"type": "library", "name": c["name"]}
        if c["version"]:
            comp["version"] = c["version"]
        if c.get("purl"):
            comp["purl"] = c["purl"]
        if c.get("cpe"):
            comp["cpe"] = c["cpe"]
        comp["properties"] = [
            {"name": "arise:surface", "value": c["surface"]},
            {"name": "arise:category", "value": c["category"]},
            {"name": "arise:methods", "value": ",".join(c["methods"])},
            {"name": "arise:confidence", "value": c["confidence"]},
            {"name": "arise:hosts", "value": ",".join(c["hosts"][:20])},
        ]
        comps.append(comp)
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
        "metadata": {"component": {"type": "application", "name": target}},
        "components": comps,
    }


def main():
    ap = argparse.ArgumentParser(description="Build the SBOM for a scan.")
    ap.add_argument("--scan-dir", required=True)
    ap.add_argument("--hosts", help="optional comma-separated host allowlist")
    args = ap.parse_args()
    hf = set(h.strip() for h in args.hosts.split(",")) if args.hosts else None
    summary = build(args.scan_dir, hosts_filter=hf)
    print(json.dumps(summary, indent=2), file=sys.stderr)


if __name__ == "__main__":
    import sys
    main()
