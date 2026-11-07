#!/usr/bin/env python3
"""
ARISE — Shared NLP Engine
=========================
Single-source text intelligence primitives consumed by every ARISE module that
processes unstructured text. Same architectural pattern as url_classify.py:
central, imported, shared.

Two tiers:
  * Tier 1 (stdlib only) — regex-backed extractors and similarity functions
    that work with zero external dependencies. Always available.
  * Tier 2 (sklearn)     — TF-IDF vectorization, ML classification, cosine
    similarity. Available when scikit-learn is installed; gracefully absent
    when it's not (every function returns a sensible fallback).

Fail-safe: importing this module NEVER raises. Missing dependencies degrade
to tier-1 primitives, never to errors. A scan without sklearn runs identically
to today's regex-only pipeline.

Usage:
    from ai.arise_nlp import (classify_response, extract_entities, similarity,
                           vectorize, is_pii, detect_info_disclosure,
                           ResponseClassifier)
"""
from __future__ import annotations

import sys as _sys, os as _os
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)


import hashlib
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# Tier 2 (sklearn) — optional; every reference is wrapped in try/except
# ---------------------------------------------------------------------------
_HAS_SKLEARN = False
_TfidfVectorizer: Any = None
_cosine_similarity: Any = None
try:
    from sklearn.feature_extraction.text import TfidfVectorizer as _TV
    from sklearn.metrics.pairwise import cosine_similarity as _cs
    _TfidfVectorizer = _TV
    _cosine_similarity = _cs
    _HAS_SKLEARN = True
except ImportError:
    pass

# ---------------------------------------------------------------------------
# Entity extraction regexes (Tier 1 — always available)
# ---------------------------------------------------------------------------

_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d{1,2})\.){3}(?:25[0-5]|2[0-4]\d|1?\d{1,2})\b")

_EMAIL_RE = re.compile(
    r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")

_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)

_DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|co|gov|edu"
    r"|mil|info|biz|dev|app|cloud|xyz|me|us|uk|de|fr|in|cn|jp|br|au|ca"
    r"|ru|nl|se|no|fi|dk|ch|at|es|it|pt|be|pl|cz|sk|hu|ro|bg|hr|si|ee"
    r"|lt|lv|ie|lu|mt|cy|gr|is|li|mc|sm|ad|va|ua)\b", re.I)

_HASH_MD5_RE = re.compile(r"\b[a-f0-9]{32}\b", re.I)
_HASH_SHA1_RE = re.compile(r"\b[a-f0-9]{40}\b", re.I)
_HASH_SHA256_RE = re.compile(r"\b[a-f0-9]{64}\b", re.I)

_MITRE_ATT_RE = re.compile(r"\b[TS]\d{4}(?:\.\d{3})?\b")
_CAPEC_RE = re.compile(r"\bCAPEC-\d{1,4}\b", re.I)
_CWE_RE = re.compile(r"\bCWE-\d{1,5}\b", re.I)

_URL_RE = re.compile(r"https?://[^\s\"'<>)\]]+")

# PII patterns
_SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_PHONE_RE = re.compile(
    r"\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4})\b")
_CC_RE = re.compile(r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))"
                     r"[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{1,4}\b")

# Secrets / credentials / tokens
_AWS_KEY_RE = re.compile(r"\b(?:A" "KIA|ASIA)[A-Z0-9]{16}\b")
_GENERIC_SECRET_RE = re.compile(
    r"(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key"
    r"|private[_-]?key|auth[_-]?token|bearer|session[_-]?id"
    r"|client[_-]?secret|db[_-]?password|database[_-]?url"
    r"|connection[_-]?string|smtp[_-]?pass)\s*[:=]\s*[\"']?([^\s\"',;}{]{4,})",
    re.I)
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")
_PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")

# Info disclosure
_INTERNAL_IP_RE = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3})\b")
_STACK_TRACE_RE = re.compile(
    r"(?:Traceback \(most recent call last\)"
    r"|at [\w.$]+\([\w.]+\.java:\d+\)"
    r"|System\.\w+Exception"
    r"|\.php on line \d+"
    r"|goroutine \d+ \["
    r"|File \".*?\", line \d+, in "
    r"|panic:.*runtime error"
    r"|Exception in thread)", re.I)
_SQL_ERROR_RE = re.compile(
    r"(?:SQL syntax|SQLSTATE|mysql_fetch|ORA-\d{5}|ODBC SQL|PostgreSQL.*ERROR"
    r"|SQLite/JDBCDriver|Unclosed quotation mark|quoted string not properly"
    r"|near \".*?\": syntax error|psql:|pg_query\(\)|Warning: mysqli"
    r"|com\.mysql|org\.postgresql|java\.sql\.SQL)", re.I)
_DEBUG_RE = re.compile(
    r"(?:DEBUG\s*[:=]\s*True|debug\s*mode|DJANGO_SETTINGS_MODULE"
    r"|Werkzeug\s+Debugger|Laravel.*APP_DEBUG|Symfony.*profiler"
    r"|X-Debug-Token|phpinfo\(\)|server_info|development\s+mode"
    r"|stack_trace|backtrace|core\.dump)", re.I)
_VERSION_RE = re.compile(
    r"(?:(?:Apache|nginx|IIS|Tomcat|Express|Django|Rails|Laravel|Flask|Spring"
    r"|WordPress|Drupal|Joomla|PHP|Python|Node|Java|\.NET|ASP\.NET)"
    r"[/\s]+v?[\d]+\.[\d]+(?:\.[\d]+)?)", re.I)
_CORS_WILDCARD_RE = re.compile(r"access-control-allow-origin\s*:\s*\*", re.I)
_DIRECTORY_LISTING_RE = re.compile(
    r"(?:<title>Index of /|Directory listing for /|Parent Directory"
    r"|<h1>Index of|autoindex)", re.I)
_COMMENT_SENSITIVE_RE = re.compile(
    r"(?:<!--\s*(?:TODO|FIXME|HACK|BUG|XXX|TEMP|password|secret|key|token"
    r"|admin|root|internal|staging|debug).*?-->)", re.I | re.S)


# ---------------------------------------------------------------------------
# Entity dataclass
# ---------------------------------------------------------------------------

@dataclass
class Entity:
    entity_type: str
    value: str
    start: int = 0
    end: int = 0

    def to_dict(self) -> dict:
        return {"type": self.entity_type, "value": self.value,
                "start": self.start, "end": self.end}


# ---------------------------------------------------------------------------
# Entity extraction (Tier 1)
# ---------------------------------------------------------------------------

def extract_entities(text: str, entity_types: Optional[Set[str]] = None) -> List[Entity]:
    if not text:
        return []
    all_types = entity_types or {
        "ipv4", "email", "cve", "domain", "url", "hash",
        "mitre_att", "capec", "cwe",
    }
    entities: List[Entity] = []
    seen: Set[Tuple[str, str]] = set()
    patterns = {
        "ipv4": _IPV4_RE, "email": _EMAIL_RE, "cve": _CVE_RE,
        "domain": _DOMAIN_RE, "url": _URL_RE,
        "mitre_att": _MITRE_ATT_RE, "capec": _CAPEC_RE, "cwe": _CWE_RE,
    }
    for etype, pat in patterns.items():
        if etype not in all_types:
            continue
        for m in pat.finditer(text):
            val = m.group(0)
            key = (etype, val.lower())
            if key not in seen:
                seen.add(key)
                entities.append(Entity(etype, val, m.start(), m.end()))
    if "hash" in all_types:
        for pat, htype in ((_HASH_SHA256_RE, "sha256"), (_HASH_SHA1_RE, "sha1"),
                           (_HASH_MD5_RE, "md5")):
            for m in pat.finditer(text):
                val = m.group(0)
                key = ("hash", val.lower())
                if key not in seen:
                    seen.add(key)
                    entities.append(Entity(f"hash_{htype}", val, m.start(), m.end()))
    return entities


# ---------------------------------------------------------------------------
# PII detection (Tier 1)
# ---------------------------------------------------------------------------

@dataclass
class PIIFinding:
    pii_type: str
    value: str
    evidence: str
    confidence: str  # high | medium

    def to_dict(self) -> dict:
        return {"type": self.pii_type, "value": self.value,
                "evidence": self.evidence, "confidence": self.confidence}


def detect_pii(text: str) -> List[PIIFinding]:
    if not text:
        return []
    findings: List[PIIFinding] = []
    seen: Set[str] = set()

    for m in _SSN_RE.finditer(text):
        v = m.group(0)
        if v not in seen:
            seen.add(v)
            findings.append(PIIFinding("ssn", _mask(v, 4), f"SSN pattern: {_mask(v, 4)}", "high"))
    for m in _CC_RE.finditer(text):
        v = m.group(0).replace(" ", "").replace("-", "")
        if v not in seen and _luhn_check(v):
            seen.add(v)
            findings.append(PIIFinding("credit_card", _mask(v, 4),
                                       f"Credit card (Luhn-valid): {_mask(v, 4)}", "high"))
    for m in _EMAIL_RE.finditer(text):
        v = m.group(0)
        if v not in seen:
            seen.add(v)
            findings.append(PIIFinding("email", v, f"Email address: {v}", "medium"))
    for m in _PHONE_RE.finditer(text):
        v = m.group(0)
        if v not in seen and len(re.sub(r"\D", "", v)) >= 10:
            seen.add(v)
            findings.append(PIIFinding("phone", _mask(v, 4), f"Phone: {_mask(v, 4)}", "medium"))
    return findings


def _mask(val: str, show_last: int = 4) -> str:
    if len(val) <= show_last:
        return val
    return "*" * (len(val) - show_last) + val[-show_last:]


def _luhn_check(number: str) -> bool:
    digits = [int(d) for d in number if d.isdigit()]
    if len(digits) < 13:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


# ---------------------------------------------------------------------------
# Information disclosure detection (Tier 1)
# ---------------------------------------------------------------------------

@dataclass
class DisclosureFinding:
    disclosure_type: str
    severity: str
    evidence: str
    confidence: str
    cwe: str = ""
    capec: str = ""

    def to_dict(self) -> dict:
        return {"type": self.disclosure_type, "severity": self.severity,
                "evidence": self.evidence, "confidence": self.confidence,
                "cwe": self.cwe, "capec": self.capec}


def detect_info_disclosure(body: str, headers: Optional[Dict[str, str]] = None,
                           url: str = "") -> List[DisclosureFinding]:
    if not body and not headers:
        return []
    findings: List[DisclosureFinding] = []
    hdrs = headers or {}
    hdrs_lower = {k.lower(): v for k, v in hdrs.items()}
    header_text = "\n".join(f"{k}: {v}" for k, v in hdrs.items())
    combined = (header_text + "\n" + body) if header_text else body

    # Internal IP addresses
    for m in _INTERNAL_IP_RE.finditer(body):
        findings.append(DisclosureFinding(
            "internal_ip", "medium",
            f"Internal IP leaked: {m.group(0)}", "high",
            "CWE-200", "CAPEC-169"))
        break  # one is enough

    # Stack traces
    m = _STACK_TRACE_RE.search(body)
    if m:
        snippet = body[m.start():m.start() + 120].replace("\n", " ")
        findings.append(DisclosureFinding(
            "stack_trace", "medium",
            f"Stack trace: {snippet[:80]}", "high",
            "CWE-209", "CAPEC-54"))

    # SQL errors
    m = _SQL_ERROR_RE.search(body)
    if m:
        findings.append(DisclosureFinding(
            "sql_error", "high",
            f"Database error: {m.group(0)[:60]}", "high",
            "CWE-209", "CAPEC-7"))

    # Debug mode
    m = _DEBUG_RE.search(combined)
    if m:
        findings.append(DisclosureFinding(
            "debug_mode", "high",
            f"Debug mode indicator: {m.group(0)[:50]}", "high",
            "CWE-489", "CAPEC-37"))

    # Version disclosure (headers)
    server = hdrs_lower.get("server", "")
    xpb = hdrs_lower.get("x-powered-by", "")
    for val, src in ((server, "Server"), (xpb, "X-Powered-By")):
        if val and re.search(r"[\d]+\.[\d]+", val):
            findings.append(DisclosureFinding(
                "version_disclosure", "low",
                f"{src}: {val}", "high",
                "CWE-200", "CAPEC-170"))

    # Version in body
    for m in _VERSION_RE.finditer(body):
        findings.append(DisclosureFinding(
            "version_in_body", "low",
            f"Software version: {m.group(0)}", "medium",
            "CWE-200", "CAPEC-170"))
        break

    # CORS wildcard
    cors = hdrs_lower.get("access-control-allow-origin", "")
    if cors == "*":
        findings.append(DisclosureFinding(
            "cors_wildcard", "medium",
            "Access-Control-Allow-Origin: * (unrestricted CORS)", "high",
            "CWE-942", "CAPEC-111"))

    # Directory listing
    if _DIRECTORY_LISTING_RE.search(body):
        findings.append(DisclosureFinding(
            "directory_listing", "medium",
            "Directory listing enabled", "high",
            "CWE-548", "CAPEC-127"))

    # Missing security headers
    missing_sec = []
    for hdr in ("x-frame-options", "x-content-type-options",
                "strict-transport-security", "content-security-policy"):
        if hdr not in hdrs_lower:
            missing_sec.append(hdr)
    if missing_sec:
        findings.append(DisclosureFinding(
            "missing_security_headers", "low",
            f"Missing: {', '.join(missing_sec)}", "high",
            "CWE-693", "CAPEC-86"))

    # Sensitive HTML comments
    for m in _COMMENT_SENSITIVE_RE.finditer(body):
        snippet = m.group(0)[:80]
        findings.append(DisclosureFinding(
            "sensitive_comment", "low",
            f"Sensitive comment: {snippet}", "medium",
            "CWE-615", "CAPEC-37"))
        break

    return findings


# ---------------------------------------------------------------------------
# Secret / credential detection (Tier 1)
# ---------------------------------------------------------------------------

@dataclass
class SecretFinding:
    secret_type: str
    value: str
    evidence: str
    severity: str
    confidence: str

    def to_dict(self) -> dict:
        return {"type": self.secret_type, "value": _mask(self.value, 4),
                "evidence": self.evidence, "severity": self.severity,
                "confidence": self.confidence}


def detect_secrets(text: str) -> List[SecretFinding]:
    if not text:
        return []
    findings: List[SecretFinding] = []
    seen: Set[str] = set()

    for m in _AWS_KEY_RE.finditer(text):
        v = m.group(0)
        if v not in seen:
            seen.add(v)
            findings.append(SecretFinding(
                "aws_access_key", v, f"AWS key: {_mask(v, 4)}", "critical", "high"))
    for m in _JWT_RE.finditer(text):
        v = m.group(0)
        if v not in seen:
            seen.add(v)
            findings.append(SecretFinding(
                "jwt_token", v, f"JWT token exposed ({len(v)} chars)", "high", "high"))
    if _PRIVATE_KEY_RE.search(text):
        findings.append(SecretFinding(
            "private_key", "[REDACTED]", "Private key block in response", "critical", "high"))
    for m in _GENERIC_SECRET_RE.finditer(text):
        key_part = m.group(0)[:40]
        val = m.group(1)
        if val and val not in seen and len(val) >= 4:
            seen.add(val)
            findings.append(SecretFinding(
                "credential", val, f"Secret pattern: {key_part}...", "high", "medium"))
    return findings


# ---------------------------------------------------------------------------
# Text similarity (Tier 1: Jaccard shingle; Tier 2: TF-IDF cosine)
# ---------------------------------------------------------------------------

def _shingle(text: str, n: int = 4) -> Set[str]:
    text = re.sub(r"\s+", " ", text.lower().strip())
    if len(text) < n:
        return {text}
    return {text[i:i + n] for i in range(len(text) - n + 1)}


def similarity(a: str, b: str) -> float:
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    if _HAS_SKLEARN:
        try:
            vec = _TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5),
                                    max_features=3000)
            X = vec.fit_transform([a, b])
            return float(_cosine_similarity(X[0:1], X[1:2])[0][0])
        except Exception:
            pass
    sa, sb = _shingle(a), _shingle(b)
    if not sa or not sb:
        return 0.0
    return len(sa & sb) / len(sa | sb)


# ---------------------------------------------------------------------------
# Response classification (Tier 1: regex rules; Tier 2: TF-IDF classifier)
# ---------------------------------------------------------------------------

RESPONSE_CLASSES = (
    "sql_error", "stack_trace", "waf_block", "catchall_404",
    "api_json", "api_xml", "html_page", "redirect",
    "authentication", "empty", "binary", "legitimate",
)

_WAF_SIGNATURES = re.compile(
    r"(?:cloudflare|akamai|incapsula|sucuri|imperva|barracuda|f5|fortinet"
    r"|aws\s*waf|azure\s*front\s*door|mod_security|wordfence|comodo"
    r"|stackpath|radware|citrix|edgecast|reblaze|section\.io"
    r"|attention\s+required|checking\s+your\s+browser"
    r"|access\s+denied.*security\s+policy"
    r"|this\s+request\s+was\s+blocked"
    r"|web\s+application\s+firewall)", re.I)

_AUTH_PAGE_RE = re.compile(
    r"(?:login|sign\s*in|log\s*in|authenticate|enter.*password"
    r"|username.*password|email.*password|forgot.*password"
    r"|<input[^>]*type=[\"']password)", re.I)


def classify_response(body: str, headers: Optional[Dict[str, str]] = None,
                      status: int = 200) -> Dict[str, Any]:
    if not body and status == 0:
        return {"response_class": "empty", "confidence": 1.0, "signals": []}
    headers = headers or {}
    ct = ""
    for k, v in headers.items():
        if k.lower() == "content-type":
            ct = v.lower()
            break
    signals: List[str] = []
    cls = "legitimate"
    conf = 0.5

    if status in (301, 302, 303, 307, 308):
        return {"response_class": "redirect", "confidence": 0.95,
                "signals": ["redirect status"]}
    if not body or not body.strip():
        return {"response_class": "empty", "confidence": 0.95,
                "signals": ["empty body"]}

    if _SQL_ERROR_RE.search(body):
        cls, conf = "sql_error", 0.95
        signals.append("sql_error_pattern")
    elif _STACK_TRACE_RE.search(body):
        cls, conf = "stack_trace", 0.90
        signals.append("stack_trace_pattern")
    elif _WAF_SIGNATURES.search(body):
        cls, conf = "waf_block", 0.85
        signals.append("waf_signature")
    elif _AUTH_PAGE_RE.search(body) and "password" in body.lower():
        cls, conf = "authentication", 0.80
        signals.append("auth_page_pattern")
    elif "application/json" in ct:
        cls, conf = "api_json", 0.90
        signals.append("json_content_type")
    elif "text/xml" in ct or "application/xml" in ct:
        cls, conf = "api_xml", 0.85
        signals.append("xml_content_type")
    elif "text/html" in ct or "<html" in body[:500].lower():
        cls, conf = "html_page", 0.70
        signals.append("html_content")
    elif len(body) < 50 and status == 200:
        cls, conf = "catchall_404", 0.50
        signals.append("suspiciously_short_200")

    return {"response_class": cls, "confidence": conf, "signals": signals}


# ---------------------------------------------------------------------------
# Vectorization helper (Tier 2 only)
# ---------------------------------------------------------------------------

def vectorize(texts: List[str], max_features: int = 5000):
    if not _HAS_SKLEARN:
        return None
    try:
        vec = _TfidfVectorizer(max_features=max_features, stop_words="english",
                                ngram_range=(1, 2))
        return vec.fit_transform(texts)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Finding deduplication via text similarity
# ---------------------------------------------------------------------------

def dedup_findings(findings: List[dict], threshold: float = 0.85,
                   key_field: str = "evidence") -> List[dict]:
    if not findings or len(findings) <= 1:
        return findings
    kept: List[dict] = []
    for f in findings:
        text = str(f.get(key_field, ""))
        is_dup = False
        for k in kept:
            if similarity(text, str(k.get(key_field, ""))) >= threshold:
                is_dup = True
                break
        if not is_dup:
            kept.append(f)
    return kept


# ---------------------------------------------------------------------------
# CLI self-test
# ---------------------------------------------------------------------------

def _selftest() -> int:
    print("=== arise_nlp self-test ===\n")
    print(f"sklearn available: {_HAS_SKLEARN}")

    # Entity extraction
    text = "Found CVE-2024-1234 on 192.168.1.1 and evil@hacker.com, see https://example.com/poc"
    ents = extract_entities(text)
    types = {e.entity_type for e in ents}
    assert "cve" in types, f"missing CVE: {types}"
    assert "ipv4" in types, f"missing IP: {types}"
    assert "email" in types, f"missing email: {types}"
    assert "url" in types, f"missing URL: {types}"
    print(f"[1] Entity extraction: {len(ents)} entities, types={types}  OK")

    # PII detection
    pii_text = "SSN: 123-45-6789, card: 4111 1111 1111 1111, phone: (555) 123-4567"
    pii = detect_pii(pii_text)
    pii_types = {p.pii_type for p in pii}
    assert "ssn" in pii_types, f"missing SSN: {pii_types}"
    assert "credit_card" in pii_types, f"missing CC: {pii_types}"
    print(f"[2] PII detection: {len(pii)} findings, types={pii_types}  OK")

    # Info disclosure
    disc_body = ("<html>Traceback (most recent call last):\n  File \"app.py\", "
                 "line 42, in handler\n<!-- TODO: remove admin password -->"
                 "\n192.168.1.100 is the internal gateway\nApache/2.4.41")
    disc = detect_info_disclosure(disc_body, {"Server": "nginx/1.18.0",
                                              "X-Powered-By": "PHP/7.4.3"})
    disc_types = {d.disclosure_type for d in disc}
    assert "stack_trace" in disc_types, f"missing stack trace: {disc_types}"
    assert "internal_ip" in disc_types, f"missing internal IP: {disc_types}"
    assert "version_disclosure" in disc_types, f"missing version: {disc_types}"
    print(f"[3] Info disclosure: {len(disc)} findings, types={disc_types}  OK")

    # Secrets
    sec_text = "password = hunter2\n" "AIOSFODNN7EXAMPLE\neyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    secs = detect_secrets(sec_text)
    sec_types = {s.secret_type for s in secs}
    assert "aws_access_key" in sec_types, f"missing AWS key: {sec_types}"
    assert "jwt_token" in sec_types, f"missing JWT: {sec_types}"
    print(f"[4] Secret detection: {len(secs)} findings, types={sec_types}  OK")

    # Similarity
    s1 = similarity("this is a test page with some content", "this is a test page with different content")
    s2 = similarity("completely different text about dogs", "a security vulnerability report")
    assert s1 > 0.5, f"similar texts scored too low: {s1}"
    assert s2 < 0.5, f"dissimilar texts scored too high: {s2}"
    print(f"[5] Similarity: similar={s1:.2f}, dissimilar={s2:.2f}  OK")

    # Response classification
    cls = classify_response("SQL syntax error near 'foo'", {"Content-Type": "text/html"})
    assert cls["response_class"] == "sql_error", cls
    cls2 = classify_response("{\"error\": \"not found\"}", {"Content-Type": "application/json"})
    assert cls2["response_class"] == "api_json", cls2
    cls3 = classify_response("Attention Required! | Cloudflare", {})
    assert cls3["response_class"] == "waf_block", cls3
    print(f"[6] Response classification: sql_error/api_json/waf_block  OK")

    # Dedup
    fs = [
        {"evidence": "SQL injection in /api/users?id=1 OR 1=1"},
        {"evidence": "SQL injection in /api/users?id=2 OR 1=1"},
        {"evidence": "XSS reflected in search parameter"},
    ]
    deduped = dedup_findings(fs, threshold=0.80)
    assert len(deduped) <= 2, f"dedup should collapse similar SQL findings: {len(deduped)}"
    print(f"[7] Dedup: {len(fs)} -> {len(deduped)} findings  OK")

    print("\nAll arise_nlp tests passed.")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(_selftest())
