#!/usr/bin/env python3
"""
ARISE Module 26 — Response Intelligence Scanner
================================================
Fetches every HTTP-200 URL AND every error-status URL (5xx / 400 / 405) in the
URL Inventory (discovered_endpoints.jsonl) exactly once with its accepted HTTP
method, and runs a comprehensive NLP + pattern-analysis pass over every response
body looking for:

  * PII leakage      — SSNs, credit cards, email addresses, phone numbers
  * Secrets          — API keys, tokens, passwords, JWTs, private keys
  * Info disclosure  — internal IPs, stack traces, SQL errors, debug mode,
                       version info, directory listings, sensitive comments
  * Unauthorized data — JSON arrays/objects that smell like user records,
                       admin data, config blobs returned without auth
  * Security headers — missing HSTS, CSP, X-Frame-Options on HTML pages
  * CORS misconfig   — wildcard or reflective Access-Control-Allow-Origin
  * Response anomaly — unusually large responses, unexpected content types

  * ERROR-RESPONSE MINING (5xx/4xx) — server errors are attack gold. Stack
    traces, SQL error fragments, framework/version banners, and leaked
    filesystem paths are extracted and turned into TYPED ATTACK HYPOTHESES
    (attack_hypotheses.jsonl) that seed the adaptive attack loop: a MySQL error
    → error-based SQLi candidate; a leaked absolute path → traversal candidate;
    a versioned framework banner → known-CVE version-swap candidate.
  * METHOD-MATRIX SEEDS — endpoints the inventory reports as accepting PUT /
    DELETE / PATCH are emitted as dangerous-methods hypotheses (verb-tampering /
    state-change surface). Derived from inventory only — nothing is fired here.

This stays a PASSIVE analysis module: it makes the same GET/POST the pipeline
already would (one request per URL, with the method the inventory says is
accepted). No payloads, no fuzzing, no injection. The hypotheses it emits are
seeds for later stages to act on, not attacks it launches.

Design contract (ARISE stdlib):
  * stdlib + arise_nlp only — no new hard dependencies
  * fully bounded — MAX_URLS cap, per-request timeout, overall budget
  * WAF-blocked URLs skipped (blocked_by_waf=true in inventory)
  * degrades gracefully — missing inventory = empty output, never crash

Output (per scan, under 26_response_intel/):
  response_findings.jsonl    one finding per line (deduplicated)
  attack_hypotheses.jsonl    typed seeds for the adaptive loop (P0 contract §6)
  response_intel_summary.json  category totals, severity breakdown, top hosts
  response_samples/           response bodies for critical findings (evidence)

Usage:
    python3 response_intel.py <scan_dir> [--target T] [--max-urls N]
        [--timeout N] [--workers N] [--budget N] [--no-samples] [--summary]
"""
from __future__ import annotations

import sys as _sys, os as _os
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)


import argparse
import hashlib
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.request
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from ai.arise_nlp import (
    Entity, PIIFinding, DisclosureFinding, SecretFinding,
    extract_entities, detect_pii, detect_info_disclosure,
    detect_secrets, classify_response, similarity, dedup_findings,
    remediation_for,
)

DEFAULT_UA = os.environ.get(
    "HUMAN_USER_AGENT",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

MAX_URLS = int(os.environ.get("RI_MAX_URLS", "5000"))
TIMEOUT = int(os.environ.get("RI_TIMEOUT", "8"))
WORKERS = int(os.environ.get("RI_WORKERS", "15"))
BUDGET_S = int(os.environ.get("RI_BUDGET", "600"))
BODY_CAP = int(os.environ.get("RI_BODY_CAP", "65536"))  # 64 KiB per response


def _log(logf, msg: str) -> None:
    ts = datetime.now().strftime("%H:%M:%S")
    line = f"[{ts}] [response-intel] {msg}"
    print(line, file=sys.stderr, flush=True)
    if logf:
        try:
            logf.write(line + "\n")
            logf.flush()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# HTTP fetcher — one request per URL, bounded
# ---------------------------------------------------------------------------

_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode = ssl.CERT_NONE


def _fetch(url: str, method: str = "GET", timeout: int = TIMEOUT
           ) -> Tuple[int, Dict[str, str], str, float]:
    try:
        req = urllib.request.Request(url, method=method.upper())
        req.add_header("User-Agent", DEFAULT_UA)
        req.add_header("Accept", "text/html,application/json,*/*")
        t0 = time.monotonic()
        with urllib.request.urlopen(req, timeout=timeout, context=_SSL_CTX) as resp:
            elapsed = time.monotonic() - t0
            status = resp.status
            headers = {k: v for k, v in resp.headers.items()}
            body = resp.read(BODY_CAP).decode("utf-8", errors="replace")
        return status, headers, body, elapsed
    except urllib.error.HTTPError as e:
        elapsed = 0.0
        headers = {k: v for k, v in e.headers.items()} if e.headers else {}
        body = ""
        try:
            body = e.read(BODY_CAP).decode("utf-8", errors="replace")
        except Exception:
            pass
        return e.code, headers, body, elapsed
    except Exception:
        return 0, {}, "", 0.0


# ---------------------------------------------------------------------------
# Unauthorized data detection
# ---------------------------------------------------------------------------

_USER_RECORD_RE = re.compile(
    r"\"(?:user(?:name)?|email|first_?name|last_?name|phone|address"
    r"|role|is_?admin|created_?at|updated_?at|date_?of_?birth|dob"
    r"|ssn|account_?id|balance|salary|permissions)\"\s*:", re.I)

_ADMIN_DATA_RE = re.compile(
    r"\"(?:admin|superuser|root|staff|moderator|role)\"\s*:\s*"
    r"(?:true|\"admin\"|\"root\"|\"superuser\")", re.I)

_CONFIG_LEAK_RE = re.compile(
    r"\"(?:database_?url|db_?host|redis_?url|smtp_?host|aws_?region"
    r"|s3_?bucket|mongo_?uri|elasticsearch_?url|rabbitmq_?url"
    r"|kafka_?brokers|log_?level|app_?env|node_?env)\"\s*:", re.I)

_BULK_DATA_RE = re.compile(
    r"^\s*\[\s*\{", re.M)  # JSON array of objects at body start


def detect_unauth_data(body: str, url: str, status: int) -> List[dict]:
    if status != 200 or not body or len(body) < 20:
        return []
    findings: List[dict] = []

    # JSON array of objects that look like user records
    if _BULK_DATA_RE.search(body[:200]):
        try:
            data = json.loads(body)
            if isinstance(data, list) and len(data) >= 3:
                sample = json.dumps(data[0], indent=2)[:200]
                user_fields = len(_USER_RECORD_RE.findall(sample))
                if user_fields >= 2:
                    findings.append({
                        "type": "unauth_user_data", "severity": "high",
                        "evidence": f"JSON array of {len(data)} records with user fields "
                                    f"({user_fields} PII-like keys per record)",
                        "confidence": "high",
                        "cwe": "CWE-200", "capec": "CAPEC-169",
                    })
        except (json.JSONDecodeError, TypeError):
            pass

    # Admin/privileged data exposure
    for m in _ADMIN_DATA_RE.finditer(body):
        findings.append({
            "type": "admin_data_exposure", "severity": "high",
            "evidence": f"Admin/privilege flag in response: {m.group(0)[:60]}",
            "confidence": "high",
            "cwe": "CWE-285", "capec": "CAPEC-1",
        })
        break

    # Config/infra leak
    for m in _CONFIG_LEAK_RE.finditer(body):
        findings.append({
            "type": "config_leak", "severity": "high",
            "evidence": f"Infrastructure config in response: {m.group(0)[:60]}",
            "confidence": "high",
            "cwe": "CWE-215", "capec": "CAPEC-37",
        })
        break

    return findings


# ---------------------------------------------------------------------------
# Response anomaly detection
# ---------------------------------------------------------------------------

def detect_anomalies(body: str, headers: Dict[str, str],
                     status: int, elapsed: float, url: str) -> List[dict]:
    findings: List[dict] = []
    ct = ""
    for k, v in headers.items():
        if k.lower() == "content-type":
            ct = v.lower()
            break

    # Unusually large response on a non-static URL (possible data dump)
    if len(body) > 50000 and "text/html" not in ct:
        findings.append({
            "type": "large_response", "severity": "info",
            "evidence": f"Response body is {len(body):,} bytes (potential data exposure)",
            "confidence": "medium",
            "cwe": "CWE-200", "capec": "CAPEC-169",
        })

    # Content-type mismatch (claimed JSON but body is HTML, or vice versa)
    if "application/json" in ct and body.strip().startswith("<"):
        findings.append({
            "type": "content_type_mismatch", "severity": "low",
            "evidence": "Content-Type says JSON but body is HTML (potential error page leak)",
            "confidence": "medium",
            "cwe": "CWE-838", "capec": "CAPEC-153",
        })

    # Extremely slow response (potential denial of service / resource abuse)
    if elapsed > 10.0:
        findings.append({
            "type": "slow_response", "severity": "info",
            "evidence": f"Response took {elapsed:.1f}s (possible DoS vector or expensive query)",
            "confidence": "low",
            "cwe": "CWE-400", "capec": "CAPEC-469",
        })

    return findings


# ---------------------------------------------------------------------------
# Error-response mining (5xx / 400 / 405) — turns server errors into typed
# attack hypotheses. This is the P2 build: 500s are the richest injection /
# disclosure surface on the whole target and were previously ignored (the
# module was 200-only).
# ---------------------------------------------------------------------------

def _is_error_status(s: int) -> bool:
    """Error statuses worth mining. 401/403 are auth walls and 404 is noise —
    excluded on purpose; those rarely leak and would flood the hypotheses."""
    return s >= 500 or s in (400, 405)


_SQL_ERR_RE = re.compile(
    r"(You have an error in your SQL syntax|SQLSTATE\[|SQL syntax.*MySQL"
    r"|mysqli?_(?:query|fetch|num_rows)|Warning:\s+(?:mysql|pg)_"
    r"|ORA-\d{5}|PostgreSQL.*ERROR|PG::\w+Error|psql:\s|SQLite3?::"
    r"|Unclosed quotation mark|quoted string not properly terminated"
    r"|syntax error at or near|Microsoft OLE DB Provider for SQL Server"
    r"|System\.Data\.SqlClient\.SqlException)", re.I)

_STACK_RE = {
    "java":   re.compile(r"(Exception in thread|\bat (?:java|javax|jakarta|org|com)\."
                         r"[\w.$]+\((?:[\w.$]+\.java:\d+|Native Method)\)|Caused by:\s+[\w.]+Exception)"),
    "python": re.compile(r"(Traceback \(most recent call last\)|File \"[^\"]+\", line \d+, in )"),
    "node":   re.compile(r"(\bat (?:Object|Module|Function|process)\.[\w.<>]*\s*\([^)]*"
                         r"(?:node_modules|\.js:\d+)|\n\s+at [\w.<>]+ \([^)]+\.js:\d+:\d+\))"),
    "php":    re.compile(r"(Fatal error:|Stack trace:\s*#0|\.php on line \d+|PHP (?:Warning|Notice):"
                         r"|Uncaught \w*(?:Exception|Error))"),
    "dotnet": re.compile(r"(System\.\w+(?:\.\w+)*Exception|\bat System\.[\w.]+\(|\[HttpException)"),
    "ruby":   re.compile(r"([\w/]+\.rb:\d+:in\s|\(RuntimeError\)|ActionController::\w+)"),
}

_FRAMEWORK_RE = re.compile(
    r"(Laravel Framework [\d.]+|Django(?:/| Version )[\d.]+|Werkzeug/[\d.]+"
    r"|Spring Framework [\d.]+|Apache Tomcat/[\d.]+|Express|Ruby on Rails [\d.]+"
    r"|ASP\.NET(?: Version)?[\s:]*[\d.]+|Symfony [\d.]+|Rails [\d.]+"
    r"|Powered by [\w .]+/[\d.]+)", re.I)

_PATH_RE = re.compile(
    r"((?:/var/www|/home/[\w.-]+|/usr/(?:local/)?(?:share|lib|src)|/opt/[\w.-]+"
    r"|/app|/srv/www)[\w./-]+\.[a-z]{1,5}"
    r"|[A-Za-z]:\\(?:inetpub|wwwroot|xampp|Users|www)[\w\\./-]+)")

_SQL_ENGINE_RE = re.compile(r"(mysql|mariadb|postgre|ora-|oracle|sqlite|mssql|sql server)", re.I)


def _ctx(body: str, m: "re.Match", pad: int = 90) -> str:
    """One-line context window around a regex hit (evidence, not the whole dump)."""
    a = max(0, m.start() - pad)
    b = min(len(body), m.end() + pad)
    return " ".join(body[a:b].split())[:200]


def detect_error_disclosure(body: str, headers: Dict[str, str], status: int,
                            url: str) -> Tuple[List[dict], List[dict]]:
    """Mine a 5xx/4xx response for stack traces, SQL errors, framework/version
    banners, and leaked filesystem paths. Returns (findings, seeds) — findings
    for the report, seeds (typed hypotheses) for the adaptive loop. At most one
    of each type per URL, so a noisy dump cannot flood the output."""
    findings: List[dict] = []
    seeds: List[dict] = []
    b = body[:BODY_CAP]

    def _seed(seed_type, lane, tech, evidence, why, severity):
        seeds.append({
            "seed_type": seed_type, "url": url, "status": status,
            "lane": lane, "tech": tech, "evidence": evidence[:200],
            "why": why, "severity": severity, "source": "response_intel",
        })

    # 1. SQL error fragment → error-based SQLi candidate (highest signal)
    m = _SQL_ERR_RE.search(b)
    if m:
        ev = _ctx(b, m)
        eng = _SQL_ENGINE_RE.search(b)  # engine name may sit outside the ctx window
        tech = (eng.group(0).lower() if eng else "sql")
        findings.append({"type": "sql_error", "severity": "high", "confidence": "high",
                         "evidence": f"SQL error in {status} response: {ev}",
                         "cwe": "CWE-89", "capec": "CAPEC-66"})
        _seed("sql_error", "sqli", tech, ev,
              "SQL error surfaced in error response — error-based SQLi candidate", "high")

    # 2. Language stack trace → injection/logic surface (one language is enough)
    for lang, rx in _STACK_RE.items():
        m = rx.search(b)
        if m:
            ev = _ctx(b, m)
            findings.append({"type": f"stack_trace_{lang}", "severity": "medium",
                             "confidence": "high",
                             "evidence": f"{lang} stack trace in {status} response: {ev}",
                             "cwe": "CWE-209", "capec": "CAPEC-118"})
            _seed("stack_trace", "disclosure", lang, ev,
                  f"{lang} stack trace leaked — reveals code paths / injection surface", "medium")
            break

    # 3. Leaked absolute filesystem path → traversal candidate
    m = _PATH_RE.search(b)
    if m:
        ev = _ctx(b, m, pad=20)
        findings.append({"type": "path_disclosure", "severity": "medium", "confidence": "medium",
                         "evidence": f"Filesystem path in {status} response: {ev}",
                         "cwe": "CWE-200", "capec": "CAPEC-126"})
        _seed("path_disclosure", "lfi", "", ev,
              "Absolute filesystem path leaked — path-traversal / LFI candidate", "medium")

    # 4. Versioned framework banner → known-CVE version-swap candidate.
    #    Only when a VERSION is present (a bare Server header is low value).
    fw = _FRAMEWORK_RE.search(b)
    server = " ".join(v for k, v in headers.items()
                      if k.lower() in ("server", "x-powered-by") and v)
    banner = fw.group(0) if fw else (server if re.search(r"\d", server) else "")
    if banner:
        findings.append({"type": "framework_version_leak", "severity": "info", "confidence": "medium",
                         "evidence": f"Framework/version banner: {banner[:80]}",
                         "cwe": "CWE-200", "capec": "CAPEC-170"})
        _seed("framework_leak", "version-swap", banner[:80].strip(), banner[:80],
              "Versioned framework banner leaked — check known CVEs for this version", "info")

    return findings, seeds


# ---------------------------------------------------------------------------
# Per-URL analysis orchestrator
# ---------------------------------------------------------------------------

@dataclass
class URLResult:
    url: str
    method: str = "GET"
    status: int = 0
    host: str = ""
    findings: List[dict] = field(default_factory=list)
    entities: List[dict] = field(default_factory=list)
    hypotheses: List[dict] = field(default_factory=list)
    response_class: str = ""
    body_hash: str = ""
    elapsed: float = 0.0
    error: str = ""


def _snippet_around(body: str, needle: str, radius: int = 120) -> str:
    """A response-body snippet centered on `needle`, so 'Evidence / match
    location' has real surrounding context instead of nothing — every
    finding here used to reach the dashboard with no response evidence at
    all, only a short formatted description. Falls back to a body prefix
    when `needle` isn't a literal substring (e.g. an already-masked value)
    rather than omitting context entirely."""
    if needle and needle != "[REDACTED]":
        idx = body.find(needle)
        if idx >= 0:
            start = max(0, idx - radius)
            end = min(len(body), idx + len(needle) + radius)
            return body[start:end]
    return body[:200]


def analyze_url(url: str, method: str = "GET",
                host: str = "", timeout: int = TIMEOUT) -> URLResult:
    result = URLResult(url=url, method=method, host=host)
    status, headers, body, elapsed = _fetch(url, method, timeout)
    result.status = status
    result.elapsed = elapsed

    if status == 0 or not body:
        result.error = "fetch failed or empty body"
        return result

    result.body_hash = hashlib.sha256(body.encode()).hexdigest()[:16]

    # Response classification
    cls = classify_response(body, headers, status)
    result.response_class = cls["response_class"]

    # Error-response mining (5xx / 400 / 405) — stack traces, SQL errors,
    # framework banners, leaked paths → findings + typed hypotheses. An error
    # page won't carry the 200-style user-data, so this branch returns early.
    if _is_error_status(status):
        errs, seeds = detect_error_disclosure(body, headers, status, url)
        for f in errs:
            result.findings.append({"category": "error_disclosure", **f,
                                    "url": url, "host": host, "method": method})
        for s in seeds:
            result.hypotheses.append({**s, "host": host, "method": method})
        return result

    # Skip WAF blocks and redirects — nothing to analyze
    if result.response_class in ("waf_block", "redirect", "empty"):
        return result

    # --- NLP analysis passes ---

    # 1. PII detection
    for pii in detect_pii(body):
        result.findings.append({
            "category": "pii", "type": pii.pii_type,
            "severity": "high" if pii.pii_type in ("ssn", "credit_card") else "medium",
            "evidence": pii.evidence, "confidence": pii.confidence,
            "cwe": "CWE-359", "capec": "CAPEC-169",
            "url": url, "host": host, "method": method, "status_code": status,
            "remediation": remediation_for("pii", pii.pii_type),
            "response_snippet": _snippet_around(body, pii.value),
        })

    # 2. Secret detection
    for sec in detect_secrets(body):
        result.findings.append({
            "category": "secret", "type": sec.secret_type,
            "severity": sec.severity, "evidence": sec.evidence,
            "confidence": sec.confidence,
            "cwe": "CWE-798", "capec": "CAPEC-37",
            "url": url, "host": host, "method": method, "status_code": status,
            "remediation": remediation_for("secret", sec.secret_type),
            "response_snippet": _snippet_around(body, sec.value),
        })

    # 3. Info disclosure
    for disc in detect_info_disclosure(body, headers, url):
        result.findings.append({
            "category": "disclosure", "type": disc.disclosure_type,
            "severity": disc.severity, "evidence": disc.evidence,
            "confidence": disc.confidence,
            "cwe": disc.cwe, "capec": disc.capec,
            "url": url, "host": host, "method": method, "status_code": status,
            "remediation": remediation_for("disclosure", disc.disclosure_type),
            "response_snippet": body[:300],
        })

    # 4. Unauthorized data exposure
    for uauth in detect_unauth_data(body, url, status):
        result.findings.append({
            "category": "unauth_data", **uauth,
            "url": url, "host": host, "method": method,
        })

    # 5. Response anomalies
    for anom in detect_anomalies(body, headers, status, elapsed, url):
        result.findings.append({
            "category": "anomaly", **anom,
            "url": url, "host": host, "method": method,
        })

    # 6. Entity extraction (IOCs found in response — for the KG)
    ents = extract_entities(body)
    result.entities = [e.to_dict() for e in ents[:50]]

    return result


# ---------------------------------------------------------------------------
# Main scanner
# ---------------------------------------------------------------------------

def run_response_intel(scan_dir: str, target: str = "",
                       max_urls: int = MAX_URLS, timeout: int = TIMEOUT,
                       workers: int = WORKERS, budget_s: int = BUDGET_S,
                       save_samples: bool = True) -> dict:
    scan_path = Path(scan_dir)
    endpoints_file = scan_path / "08_directory_discovery" / "discovered_endpoints.jsonl"
    out_dir = scan_path / "26_response_intel"
    out_dir.mkdir(parents=True, exist_ok=True)
    log_file = out_dir / "response_intel.log"
    logf = open(log_file, "w")

    _log(logf, f"=== Response Intelligence Scanner start target={target} ===")

    if not endpoints_file.exists():
        _log(logf, f"No endpoint inventory at {endpoints_file} — skipping")
        summary = {"module": "response_intel", "status": "skipped",
                   "reason": "no discovered_endpoints.jsonl"}
        (out_dir / "response_intel_summary.json").write_text(json.dumps(summary, indent=2))
        logf.close()
        return summary

    # Load URL inventory
    urls_to_scan: List[Tuple[str, str, str]] = []  # (url, method, host)
    method_seeds: List[dict] = []                   # dangerous-verb hypotheses (no fetch)
    seen_urls: Set[str] = set()
    n_error_urls = 0
    with endpoints_file.open() as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except Exception:
                continue
            # Skip WAF-blocked URLs
            if rec.get("blocked_by_waf"):
                continue
            # Use sample_url (concrete, probe-able) over template
            url = rec.get("sample_url") or rec.get("url", "")
            if not url or url in seen_urls:
                continue
            seen_urls.add(url)
            method = rec.get("method", "GET")
            host = rec.get("host", "")
            status = rec.get("status", 0)

            # Method-matrix seed — inventory reports state-changing verbs on this
            # endpoint. Derived from inventory, nothing fired here (P2).
            methods = [str(m).upper() for m in (rec.get("methods") or [])]
            dangerous = sorted(set(methods) & {"PUT", "DELETE", "PATCH"})
            if dangerous:
                method_seeds.append({
                    "seed_type": "method_matrix", "url": url, "host": host,
                    "method": method, "methods": methods, "status": status,
                    "lane": "dangerous-methods", "tech": "",
                    "evidence": f"accepts {', '.join(dangerous)}",
                    "why": f"inventory reports {', '.join(dangerous)} accepted — "
                           "verb-tampering / state-change surface to attack per method",
                    "severity": "medium", "source": "response_intel",
                })

            # Scan endpoints that are HTTP-200, unknown (0), OR an error status
            # worth mining (5xx / 400 / 405).
            if status in (200, 0):
                urls_to_scan.append((url, method, host))
            elif _is_error_status(status):
                urls_to_scan.append((url, method, host))
                n_error_urls += 1

    _log(logf, f"Loaded {len(urls_to_scan)} URLs to fetch "
               f"({n_error_urls} error-status for mining) + {len(method_seeds)} "
               f"method-matrix seed(s), of {len(seen_urls)} total")

    # Cap
    if len(urls_to_scan) > max_urls:
        _log(logf, f"Capping to {max_urls} URLs")
        urls_to_scan = urls_to_scan[:max_urls]

    # Sample storage
    samples_dir = out_dir / "response_samples"
    if save_samples:
        samples_dir.mkdir(exist_ok=True)

    # Scan
    all_findings: List[dict] = []
    all_entities: List[dict] = []
    all_hypotheses: List[dict] = list(method_seeds)  # method-matrix seeds are known up front
    results: List[URLResult] = []
    by_host: Dict[str, int] = defaultdict(int)
    by_category: Dict[str, int] = defaultdict(int)
    by_severity: Dict[str, int] = defaultdict(int)
    by_type: Dict[str, int] = defaultdict(int)
    scanned = 0
    errors = 0
    t_start = time.monotonic()

    findings_file = out_dir / "response_findings.jsonl"
    with findings_file.open("w") as ff, ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {}
        for url, method, host in urls_to_scan:
            if time.monotonic() - t_start > budget_s:
                _log(logf, f"Budget exhausted ({budget_s}s) after {scanned} URLs")
                break
            fut = pool.submit(analyze_url, url, method, host, timeout)
            futures[fut] = (url, method, host)

        for fut in as_completed(futures):
            url, method, host = futures[fut]
            try:
                result = fut.result(timeout=timeout + 5)
            except Exception as e:
                _log(logf, f"Exception analyzing {url}: {e}")
                errors += 1
                continue

            scanned += 1
            if result.error:
                errors += 1

            # Write findings
            for f in result.findings:
                ff.write(json.dumps(f) + "\n")
                all_findings.append(f)
                by_category[f.get("category", "unknown")] += 1
                by_severity[f.get("severity", "info")] += 1
                by_type[f.get("type", "unknown")] += 1
                by_host[f.get("host", "unknown")] += 1

            all_entities.extend(result.entities)
            all_hypotheses.extend(result.hypotheses)

            # Save response sample for critical/high findings
            if save_samples and any(f["severity"] in ("critical", "high")
                                     for f in result.findings):
                sample_name = hashlib.sha256(url.encode()).hexdigest()[:12] + ".json"
                try:
                    (samples_dir / sample_name).write_text(json.dumps({
                        "url": url, "method": method, "host": host,
                        "status": result.status, "class": result.response_class,
                        "finding_count": len(result.findings),
                        "findings": result.findings,
                    }, indent=2))
                except Exception:
                    pass

            if scanned % 200 == 0:
                _log(logf, f"Progress: {scanned}/{len(urls_to_scan)} URLs, "
                           f"{len(all_findings)} findings so far")

    # Deduplicate findings
    deduped = dedup_findings(all_findings, threshold=0.85, key_field="evidence")
    dedup_removed = len(all_findings) - len(deduped)

    # Write deduplicated findings
    deduped_file = out_dir / "response_findings_deduped.jsonl"
    with deduped_file.open("w") as df:
        for f in deduped:
            df.write(json.dumps(f) + "\n")

    # Entity summary
    entity_types: Dict[str, int] = defaultdict(int)
    for e in all_entities:
        entity_types[e.get("type", "unknown")] += 1

    # Attack hypotheses (P2 seeds for the adaptive loop). Dedup key is per-type:
    # framework_leak is a HOST-level fact (a Server/version banner repeats on
    # every error URL of a host), so collapse it by (host, tech); everything else
    # is a per-URL attack target, keyed by (seed_type, url).
    seen_hyp: Set[Tuple[str, ...]] = set()
    deduped_hyp: List[dict] = []
    by_seed_type: Dict[str, int] = defaultdict(int)
    for h in all_hypotheses:
        st = h.get("seed_type", "")
        if st == "framework_leak":
            k = (st, h.get("host", ""), h.get("tech", ""))
        else:
            k = (st, h.get("url", ""))
        if k in seen_hyp:
            continue
        seen_hyp.add(k)
        deduped_hyp.append(h)
        by_seed_type[st or "unknown"] += 1
    hyp_file = out_dir / "attack_hypotheses.jsonl"
    with hyp_file.open("w") as hf:
        for h in deduped_hyp:
            hf.write(json.dumps(h) + "\n")

    # Top hosts by findings
    top_hosts = sorted(by_host.items(), key=lambda x: -x[1])[:10]

    elapsed_total = time.monotonic() - t_start
    summary = {
        "module": "response_intel",
        "status": "completed",
        "target": target,
        "urls_scanned": scanned,
        "urls_total": len(urls_to_scan),
        "errors": errors,
        "total_findings": len(all_findings),
        "deduped_findings": len(deduped),
        "dedup_removed": dedup_removed,
        "error_urls_mined": n_error_urls,
        "attack_hypotheses": len(deduped_hyp),
        "by_seed_type": dict(by_seed_type),
        "by_category": dict(by_category),
        "by_severity": dict(by_severity),
        "by_type": dict(by_type),
        "top_hosts": top_hosts,
        "entities_extracted": len(all_entities),
        "entity_types": dict(entity_types),
        "elapsed_s": round(elapsed_total, 1),
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    (out_dir / "response_intel_summary.json").write_text(json.dumps(summary, indent=2))

    _log(logf, f"=== done: {scanned} URLs, {len(deduped)} findings "
               f"({dedup_removed} dupes removed), {len(all_entities)} entities, "
               f"{len(deduped_hyp)} hypotheses ({n_error_urls} error URLs mined), "
               f"{elapsed_total:.0f}s ===")
    print(f"response_intel: scanned={scanned} findings={len(deduped)} "
          f"hypotheses={len(deduped_hyp)} entities={len(all_entities)} "
          f"elapsed={elapsed_total:.0f}s")
    logf.close()
    return summary


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description="ARISE Response Intelligence Scanner")
    ap.add_argument("scan_dir")
    ap.add_argument("--target", default="")
    ap.add_argument("--max-urls", type=int, default=MAX_URLS)
    ap.add_argument("--timeout", type=int, default=TIMEOUT)
    ap.add_argument("--workers", type=int, default=WORKERS)
    ap.add_argument("--budget", type=int, default=BUDGET_S)
    ap.add_argument("--no-samples", action="store_true")
    ap.add_argument("--summary", action="store_true")
    args = ap.parse_args()

    summary = run_response_intel(
        args.scan_dir, target=args.target, max_urls=args.max_urls,
        timeout=args.timeout, workers=args.workers, budget_s=args.budget,
        save_samples=not args.no_samples)

    if args.summary:
        print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
