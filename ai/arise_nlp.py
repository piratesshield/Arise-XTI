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

# Placeholder/demo-form email addresses — checkout and signup widgets ship
# with example values (RFC 2606 reserved domains, "sample1@…", masked
# "xxxxxxxxxx@…") baked right into the production JS bundle. Matching these
# is not a PII disclosure; left unfiltered they drown out real addresses
# 1000:1 in a large SPA bundle.
_EMAIL_PLACEHOLDER_DOMAIN_RE = re.compile(
    r"@(?:example\.(?:com|org|net|edu)|test\.com|email\.com|domain\.com"
    r"|yourdomain\.com|acme\.com|company\.com|foo\.com|bar\.com"
    r"|yourcompany\.com)$", re.I)
_EMAIL_PLACEHOLDER_LOCAL_RE = re.compile(
    r"^(?:x{5,}|\*{3,}|test\d*|sample\d*|demo\d*|example\d*|dummy\d*|fake\d*"
    r"|john\.?doe|jane\.?doe|foo|bar|yourname|youremail|placeholder"
    r"|no-?reply|user\d*|abc\d*)$", re.I)


def _is_placeholder_email(v: str) -> bool:
    if _EMAIL_PLACEHOLDER_DOMAIN_RE.search(v):
        return True
    local = v.split("@", 1)[0]
    return bool(_EMAIL_PLACEHOLDER_LOCAL_RE.match(local))

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

# IMPORTANT:
# Do NOT treat "any 10 digits" as a phone number. Web/API responses contain
# IDs, timestamps, ZIP/postal codes, order numbers, account numbers, ports,
# transaction IDs, etc. This regex only produces CANDIDATES; validation and
# context scoring happen in _phone_candidates().
_PHONE_CANDIDATE_RE = re.compile(
    r"(?<![\w])(?:\+\d{1,3}[\s().-]*)?"
    r"(?:\d[\s().-]*){7,18}\d(?![\w])"
)

# Common region metadata. This is deliberately small and extensible rather
# than pretending every country's numbering plan can be expressed by regex.
_REGION_CALLING_CODES = {
    "IN": "91", "US": "1", "CA": "1", "GB": "44", "AU": "61",
    "NZ": "64", "SG": "65", "AE": "971", "SA": "966", "DE": "49",
    "FR": "33", "NL": "31", "CH": "41", "JP": "81", "CN": "86",
    "HK": "852", "KR": "82", "BR": "55", "MX": "52", "ZA": "27",
}

# Positive context: labels that strongly suggest the number is a phone/mobile.
_PHONE_POSITIVE_RE = re.compile(
    r"\b(?:mobile|cell(?:phone)?|phone|telephone|tel|contact|call|whatsapp|"
    r"sms|dial|hotline|helpline|emergency\s+(?:number|contact))\b",
    re.I,
)

# Negative context: fields where a numeric value is much more likely to be an
# identifier/date/code than a phone number.
_PHONE_NEGATIVE_RE = re.compile(
    r"\b(?:id|identifier|uuid|guid|account|customer\s*id|user\s*id|"
    r"order(?:\s*id|\s*number)?|invoice|transaction|reference|ref|ticket|"
    r"otp|one[-\s]?time\s*password|pin|zip|postal|postcode|amount|price|"
    r"timestamp|epoch|port|year|version|cve|cwe|capec|latitude|longitude|"
    r"latitude|longitude|ip(?:v4|v6)?|hash|checksum|quantity)\b",
    re.I,
)

# Country/region-aware mobile prefixes for the most common deployments.
# These are NOT used as universal rules; they are only score boosts.
_REGION_MOBILE_PREFIXES = {
    "IN": ("6", "7", "8", "9"),
    "GB": ("7",),
    "AU": ("4",),
    "SG": ("8", "9"),
    "AE": ("5",),
    "SA": ("5",),
    "DE": ("15", "16", "17"),
    "FR": ("6", "7"),
    "JP": ("70", "80", "90"),
    "CN": ("13", "14", "15", "16", "17", "18", "19"),
    "BR": ("9",),
    "ZA": ("6", "7", "8"),
}

_CC_RE = re.compile(r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))"
                     r"[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{1,4}\b")

# Secrets / credentials / tokens
_AWS_KEY_RE = re.compile(r"\b(?:A" "KIA|ASIA)[A-Z0-9]{16}\b")

# Branded, format-specific secret signatures — each provider's own fixed
# prefix makes these far lower false-positive-risk than the generic
# keyword=value heuristic below: a 24+ char string starting "sk_live_" is
# never anything BUT a live Stripe secret key, whereas "secret=X" could be
# a WordPress nonce, a CSRF token, or a thousand other benign things. These
# run first and claim their match before the generic matcher ever sees it.
#
# Deliberately NOT matched (would be noise, not signal):
#   - Stripe pk_live_/pk_test_/sk_test_ — publishable keys are meant to be
#     public (shipped to browsers by design); test-mode keys can't touch
#     real money/data. Only sk_live_/rk_live_ (secret/restricted, live) fire.
#   - Twilio Account SID / bare Mailgun-style 32-hex keys alone — a bare hex
#     string is indistinguishable from an MD5/git-sha and would just add FP
#     volume without a second, equally distinctive anchor.
_BRANDED_SECRET_PATTERNS = [
    ("stripe_live_key", re.compile(r"\b(?:sk|rk)_live_[0-9a-zA-Z]{24,}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,48}\b")),
    ("slack_webhook", re.compile(
        r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("sendgrid_key", re.compile(r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b")),
    ("npm_token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    # Credentials embedded directly in a DB/queue connection URI
    # (mongodb://user:pass@host, postgres://user:pass@host/db, …) — one of
    # the highest-value leak shapes (a full working connection string, not
    # just a bare key) and structurally unambiguous: scheme + "user:pass@".
    ("connection_string_creds", re.compile(
        r"\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp)://"
        r"[^:/\s@]+:[^@/\s]+@[^/\s]+", re.I)),
]

_GENERIC_SECRET_RE = re.compile(
    r"(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key"
    r"|private[_-]?key|auth[_-]?token|bearer|session[_-]?id"
    r"|client[_-]?secret|db[_-]?password|database[_-]?url"
    r"|connection[_-]?string|smtp[_-]?pass)\s*[:=]\s*[\"']?([^\s\"',;}{().]{6,})",
    re.I)
# ALL_CAPS_CONST / SCREAMING_SNAKE identifiers — minified JS is full of these
# as i18n keys and enum/constant names (e.g. token:"CONFIRMATION_PASSWORD"),
# never actual secret material.
_SECRET_VALUE_ENUM_RE = re.compile(r"^[A-Z_][A-Z0-9_]*$")


# Obvious placeholder/dummy values — docs, .env.example files, and tutorial
# snippets are full of these and they satisfy every shape-based check above
# (long enough, has digits/symbols) while never being a real secret.
_PLACEHOLDER_EXACT_RE = re.compile(r"^(?:x{4,}|0{4,}|1{4,})$", re.I)
_PLACEHOLDER_PHRASE_RE = re.compile(
    r"(?:^(?:your|my)[_-]"               # your_api_key_here, my_secret_token
    r"|[_-](?:here|goes[_-]?here)$"      # ..._key_here, ..._token_goes_here
    r"|change[_-]?me|replace[_-]?me|example|sample|dummy|fake|placeholder"
    r"|todo|redacted)", re.I)
_PLACEHOLDER_VALUE_RE = re.compile(r"^(?:<.*>|\.\.\.)$")  # kept for the angle-bracket/ellipsis shape


def _is_placeholder_value(val: str) -> bool:
    """True for obvious dummy/fill-in-the-blank values from docs,
    .env.example files, and tutorial snippets — these satisfy every
    shape-based check (long enough, has digits/symbols) while never being a
    real secret."""
    return bool(_PLACEHOLDER_EXACT_RE.match(val) or _PLACEHOLDER_PHRASE_RE.search(val)
                or _PLACEHOLDER_VALUE_RE.match(val))


def _looks_like_real_secret_value(val: str) -> bool:
    """Excluding '(', ')', '.' from the value charclass (see
    _GENERIC_SECRET_RE) already kills the bulk of minified-JS code noise —
    property-chain reads (e.data.token), function refs/calls
    (function(t){...}), and PropTypes/redux boilerplate never survive past
    the first '.' or '('. What's left still needs filtering: route paths,
    URLs, template placeholders, ALL_CAPS enum/i18n-key names, short bare
    words/identifiers (null, otpToken, Please, function) that contain no
    digit or symbol, and obvious dummy/placeholder values from docs and
    .env.example-style files — real secret values almost always carry
    digits/symbols AND aren't a recognizable "fill this in" convention."""
    if val.startswith(("/", "http://", "https://", "${", "{{")):
        return False
    if _SECRET_VALUE_ENUM_RE.match(val):
        return False
    if len(val) < 12 and val.isalpha():
        return False
    if _is_placeholder_value(val):
        return False
    # A single character repeated through the whole value ("aaaaaaaaaa") is
    # a padding/mask artifact or a deliberately fake value, never a real key.
    if len(set(val)) <= 2:
        return False
    return True


# Benign contexts where "secret"/"token"/"session-id" etc. precede `=`/`:`
# but denote something other than a server-side credential:
#   - an HTML `data-*` attribute name (`data-secret`, `data-session-id`) —
#     author-defined DOM/JS wiring a script reads, not credential storage.
#     Canonical case: WordPress core's oEmbed feature (wp-includes/js/
#     wp-embed.js) emits `<blockquote class="wp-embedded-content"
#     data-secret="RANDOM10CHARS">` on EVERY post's /embed/ page — a public
#     per-post nonce routing an iframe-resize postMessage, not a secret.
#   - a CSRF/XSRF anti-forgery token (`csrfToken=`, `xsrf-token:`,
#     `authenticity_token=` — Rails' name for the same thing). These are
#     deliberately embedded in every page/form by design and rotate per
#     session; leaking one isn't a "rotate this credential" finding.
# Both satisfy `_looks_like_real_secret_value` because the values are
# genuinely random-looking (that's the whole point of a nonce/CSRF token) —
# value-shape alone can't filter either; only the preceding-text context can.
_BENIGN_KEY_CONTEXT_RE = re.compile(r"(?:\bdata-|csrf[_-]?|xsrf[_-]?|authenticity_)$", re.I)


def _benign_key_context(text: str, match_start: int) -> bool:
    """True if the matched keyword (secret/token/session-id/...) is itself
    the tail of a known benign identifier (an HTML data-* attribute, or a
    CSRF/XSRF/Rails-authenticity token name) rather than a standalone
    config/credential key."""
    return bool(_BENIGN_KEY_CONTEXT_RE.search(text[max(0, match_start - 16):match_start]))


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


def _normalise_region(region: Optional[str]) -> Optional[str]:
    """Return an ISO-3166 alpha-2 region or None."""
    if not region:
        return None
    r = str(region).strip().upper()
    aliases = {
        "INDIA": "IN", "UNITED STATES": "US", "USA": "US",
        "UNITED KINGDOM": "GB", "UK": "GB", "UAE": "AE",
        "UNITED ARAB EMIRATES": "AE",
    }
    return aliases.get(r, r if len(r) == 2 else None)


def _phone_context(text: str, start: int, end: int) -> Tuple[int, List[str]]:
    """Score local context around a phone candidate."""
    left = max(0, start - 80)
    right = min(len(text), end + 80)
    ctx = text[left:right]
    score = 0
    signals: List[str] = []

    positives = _PHONE_POSITIVE_RE.findall(ctx)
    negatives = _PHONE_NEGATIVE_RE.findall(ctx)

    if positives:
        score += min(6, 2 * len(positives))
        signals.append("phone-context:" + ",".join(sorted(set(p.lower() for p in positives))))
    if negatives:
        score -= min(8, 3 * len(negatives))
        signals.append("non-phone-context:" + ",".join(sorted(set(n.lower() for n in negatives))))

    # JSON/HTML field labels are stronger than arbitrary nearby words.
    # The candidate regex starts at the first digit, so a formatted number's
    # leading "(" (e.g. phone: (555) 123-4567) sits between the ":" and the
    # match — tolerate an optional paren/space run so the label still counts.
    label_ctx = text[max(0, start - 45):start]
    if re.search(
        r"(?:[\"']?(?:mobile|phone|telephone|tel|contact|whatsapp)[\"']?)"
        r"\s*[:=]\s*[\"']?\s*[(\s]*$",
        label_ctx, re.I
    ):
        score += 4
        signals.append("labelled-phone-field")

    return score, signals


def _phone_candidates(
    text: str,
    region: Optional[str] = None,
) -> List[Tuple[str, int, int, str, str]]:
    """
    Return validated phone candidates as:
        (value, start, end, confidence, reason)

    Design goal:
      regex -> candidate generation
      structural checks -> reject obvious numbers
      region/context scoring -> decide whether it is a phone
      optional phonenumbers -> authoritative numbering-plan validation
    """
    if not text:
        return []

    region = _normalise_region(region)
    results: List[Tuple[str, int, int, str, str]] = []

    # Optional dependency. The scanner still works without it.
    phone_lib = None
    try:
        import phonenumbers as phone_lib  # type: ignore
    except ImportError:
        phone_lib = None

    for m in _PHONE_CANDIDATE_RE.finditer(text):
        raw = m.group(0)
        digits = re.sub(r"\D", "", raw)

        # Hard structural limits.
        if len(digits) < 7 or len(digits) > 15:
            continue

        # Reject obvious non-phone numeric structures.
        if len(set(digits)) == 1:
            continue
        if re.fullmatch(r"(?:19|20)\d{2}", digits):
            continue
        if re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", raw):
            continue
        if re.fullmatch(r"[0-9a-fA-F]{8,}", raw) and re.search(r"[A-Fa-f]", raw):
            continue

        # Reject a candidate that is just a long run of punctuation/spacing.
        if len(raw) - len(digits) > max(8, len(digits)):
            continue

        context_score, signals = _phone_context(text, m.start(), m.end())

        international = raw.lstrip().startswith("+")
        if international:
            context_score += 3
            signals.append("international-format")

        # Canonical phone FORMATTING is itself a signal — but only separated
        # forms, never a bare digit run, so this can never re-flag the
        # separator-free IDs/timestamps that caused the meesho false positives.
        # The candidate regex drops a leading "(", so look one char to its left
        # to see the parenthesised area-code form.
        fmt_window = text[max(0, m.start() - 1):m.end()]
        if re.search(r"\(\d{3}\)\s*\d{3}[.\s-]\d{4}", fmt_window):
            # (555) 123-4567 — parenthesised area code is essentially
            # phone-exclusive; strong enough to stand on its own.
            context_score += 3
            signals.append("parenthesised-format")
        elif re.search(r"\b\d{3}[.\s-]\d{3}[.\s-]\d{4}\b", raw):
            # 555-123-4567 / 555.123.4567 — phone-shaped, but dashes/dots also
            # appear in codes, so it corroborates rather than decides alone.
            context_score += 2
            signals.append("separated-format")

        # Region-aware local numbering validation.
        if region:
            cc = _REGION_CALLING_CODES.get(region)
            local_digits = digits
            if international and cc and digits.startswith(cc):
                local_digits = digits[len(cc):]

            prefixes = _REGION_MOBILE_PREFIXES.get(region, ())
            if prefixes and any(local_digits.startswith(p) for p in prefixes):
                context_score += 2
                signals.append(f"{region}-mobile-prefix")

            # Stronger handling for India's common 10-digit mobile format.
            if region == "IN" and len(local_digits) == 10 and local_digits[0] in "6789":
                context_score += 2
                signals.append("IN-10-digit-mobile")

        # A bare contiguous 10-digit number is intentionally NOT enough.
        if re.fullmatch(r"\d{10}", raw.strip()):
            context_score -= 3
            signals.append("bare-10-digit")

        # Country-code format is much more reliable than a bare local number.
        if international and 10 <= len(digits) <= 15:
            context_score += 2
            signals.append("international-length")

        # Optional authoritative numbering-plan validation.
        if phone_lib:
            try:
                parsed = phone_lib.parse(raw, region if not international else None)
                if phone_lib.is_possible_number(parsed):
                    context_score += 3
                    signals.append("numbering-plan-possible")
                if phone_lib.is_valid_number(parsed):
                    context_score += 4
                    signals.append("numbering-plan-valid")
            except Exception:
                pass

        # Decision thresholds:
        #  >= 5  : high confidence
        #  3-4   : medium confidence
        #  < 3   : reject
        if context_score < 3:
            continue

        confidence = "high" if context_score >= 5 else "medium"
        reason = "; ".join(signals) if signals else "phone-number structure"
        results.append((raw, m.start(), m.end(), confidence, reason))

    return results


def detect_pii(
    text: str,
    region: Optional[str] = None,
) -> List[PIIFinding]:
    """
    Detect PII with context-aware phone detection.

    `region` is optional and should be supplied when the application knows the
    expected locale, e.g. region="IN" for an India-focused scan. Existing
    callers that pass only `text` continue to work.

    Important: do not infer a user's geographic location from a phone number.
    Region is a validation hint supplied by the scanner/application.
    """
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
        if v not in seen and not _is_placeholder_email(v):
            seen.add(v)
            findings.append(PIIFinding("email", v, f"Email address: {v}", "medium"))

    for raw, start, end, confidence, reason in _phone_candidates(text, region):
        # Store a normalised identity for deduplication while preserving the
        # original formatting only in the evidence.
        digits = re.sub(r"\D", "", raw)
        key = "phone:" + digits
        if key in seen:
            continue
        seen.add(key)
        masked = _mask(digits, 4)
        findings.append(
            PIIFinding(
                "phone",
                masked,
                f"Phone candidate: {masked} ({reason})",
                confidence,
            )
        )

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
    # Branded formats first — their fixed, provider-specific prefix makes
    # them unambiguous, so they claim the match before the generic
    # keyword=value heuristic (which has no way to tell a Stripe key from a
    # WordPress nonce by shape alone) ever gets a chance to mis-grade it.
    for stype, pat in _BRANDED_SECRET_PATTERNS:
        for m in pat.finditer(text):
            v = m.group(0)
            if v in seen:
                continue
            seen.add(v)
            label = stype.replace("_", " ")
            findings.append(SecretFinding(
                stype, v, f"{label}: {_mask(v, 4)}", "critical", "high"))
    for m in _GENERIC_SECRET_RE.finditer(text):
        if _benign_key_context(text, m.start()):
            continue
        key_part = m.group(0)[:40]
        val = m.group(1)
        if (val and val not in seen and len(val) >= 6
                and _looks_like_real_secret_value(val)):
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


# ---------------------------------------------------------------------------
# Local-file content scan (Module 10.1)
# ---------------------------------------------------------------------------
# Module 26 (response_intel) runs these detectors over live HTTP responses.
# Module 10 (trufflehog) scans the same staged local tree but for SECRETS only.
# This scans that tree with the FULL detector set — adding PII + info-disclosure
# (and a second secret opinion) over JS bundles, source maps, staged 2xx bodies,
# .env / config files. Same finding shape as Module 26 (file replaces url).
import json as _json

# Extensions read as text; everything else (images, fonts, archives, media) is
# skipped without opening. Source maps (.map) are kept — they embed original
# source and routinely leak secrets, tokens, internal paths and PII.
_SCAN_TEXT_EXT = {
    ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".json", ".map",
    ".html", ".htm", ".xhtml", ".css", ".scss", ".txt", ".xml", ".csv",
    ".yml", ".yaml", ".ini", ".cfg", ".conf", ".config", ".env", ".properties",
    ".md", ".log", ".bak", ".old", ".tmp", ".sql", ".sh", ".py", ".rb", ".php",
    ".java", ".go", ".graphql", ".gql", ".vue", ".svelte", "",  # "" = extensionless (.env, dotfiles)
}
_SCAN_MAX_BYTES = 6_000_000      # skip files larger than this
_SCAN_MAX_FINDINGS = 20000       # hard ceiling so one tree can't explode output


def _is_probably_text(path: str, sniff: int = 2048) -> bool:
    """Cheap binary sniff — a NUL byte in the first chunk means skip."""
    try:
        with open(path, "rb") as fh:
            return b"\x00" not in fh.read(sniff)
    except OSError:
        return False


def _line_of(text: str, needle: str) -> Optional[int]:
    """1-indexed line number of the first occurrence of `needle` in `text`,
    or None if it isn't a literal substring (e.g. already masked)."""
    if not needle or needle == "[REDACTED]":
        return None
    idx = text.find(needle)
    return (text.count("\n", 0, idx) + 1) if idx >= 0 else None


# Remediation text per finding type — every Content Scan (10.1) / Response
# Intelligence (Module 26) finding used to reach the dashboard with an empty
# "Recommended remediation" field, since neither producer carried one at all
# (dashboard.py's loader always had somewhere to read it FROM; nothing ever
# wrote it). Public (no leading underscore) + remediation_for() below so
# response_intel.py can reuse the SAME mapping instead of a second copy.
SECRET_REMEDIATION = {
    "aws_access_key": "Revoke this AWS key immediately (IAM console or `aws iam delete-access-key`), "
                      "audit CloudTrail for unauthorized use, and remove it from the source/bundle. "
                      "Use short-lived credentials (STS/IRSA) instead of static keys in client-shipped code.",
    "jwt_token": "Treat this token as compromised — revoke/rotate the signing key if it's long-lived, "
                "and remove it from any file that ships to the client. Tokens embedded in JS bundles "
                "are visible to every visitor.",
    "private_key": "Rotate the key pair immediately and revoke the compromised key at every service "
                   "that trusts it. Private keys must never be shipped in client-accessible files.",
    "credential": "Rotate this credential immediately, remove it from the file, and use environment "
                 "variables or a secret manager instead of hardcoding it. Audit access logs for use "
                 "of the exposed value.",
    "stripe_live_key": "Roll this key immediately in the Stripe dashboard (Developers > API keys), "
                       "audit recent API/webhook activity for unauthorized use, and never ship a "
                       "secret/restricted key to client-accessible code — only publishable keys "
                       "belong in the browser.",
    "github_token": "Revoke this token immediately (GitHub Settings > Developer settings > "
                    "Personal access tokens), audit recent account/repo activity, and move it to "
                    "a secrets manager or CI secret store.",
    "slack_token": "Revoke this token in the Slack app's OAuth & Permissions page, rotate it, and "
                  "audit the workspace's access logs for unauthorized API calls.",
    "slack_webhook": "Regenerate this webhook URL (Slack app > Incoming Webhooks) — anyone with the "
                     "URL can post to the channel. Treat the old URL as compromised.",
    "google_api_key": "Restrict or regenerate this key in Google Cloud Console (APIs & Services > "
                      "Credentials); an unrestricted key usable from any referrer/IP is billable "
                      "and abusable by anyone who finds it.",
    "sendgrid_key": "Revoke this key in SendGrid (Settings > API Keys) and rotate it; audit send "
                   "logs for abuse (spam/phishing sent under your domain's reputation).",
    "npm_token": "Revoke this token (npmjs.com > Access Tokens) and audit for unauthorized package "
                "publishes — a leaked publish token can push a malicious version of your package.",
    "connection_string_creds": "Rotate the embedded database/queue credential immediately and remove "
                               "the raw connection string from client-accessible code or logs; use a "
                               "secret manager and least-privilege DB user instead of embedding "
                               "user:pass directly in a connection URI.",
}
PII_REMEDIATION = {
    "ssn": "Remove SSNs from client-accessible files/responses; they should never leave the server "
          "except over an authenticated, need-to-know channel.",
    "credit_card": "Remove card numbers from client-accessible files/responses immediately — this is "
                  "a PCI-DSS violation if exposed publicly. Verify no cardholder data is logged or cached.",
    "email": "Confirm this email address is intended to be public (e.g. a contact address); if it "
            "belongs to a user/customer, remove it from publicly reachable files.",
    "phone": "Confirm this phone number is intended to be public; if it belongs to a user/customer, "
            "remove it from publicly reachable files.",
}
DISCLOSURE_REMEDIATION = {
    "sql_error": "Disable verbose SQL error output in production; return a generic error to the "
                "client and log the real detail server-side only.",
    "stack_trace": "Disable debug/stack-trace output in production; return a generic error page.",
    "debug_mode": "Disable debug mode in production — it commonly leaks source paths, environment "
                 "variables, and allows arbitrary code execution via an interactive console.",
    "directory_listing": "Disable directory listing (autoindex off / equivalent) on the web server.",
    "internal_ip": "Remove internal/private IP addresses from client-accessible files — they leak "
                   "internal network topology.",
    "cors_wildcard": "Replace the wildcard CORS origin with an explicit allow-list of trusted origins.",
    "version_disclosure": "Suppress version banners/headers in production to reduce fingerprinting surface.",
    "version_in_body": "Remove version strings from client-accessible content to reduce fingerprinting surface.",
    "sensitive_comment": "Remove developer comments (TODO/FIXME/credentials/internal notes) before "
                        "shipping files to production.",
    "missing_security_headers": "Add the missing security headers to every HTTP response.",
}


def remediation_for(category: str, finding_type: str) -> str:
    """Single source of remediation text for a (category, type) pair — used
    by both scan_text_findings() (Module 10.1, local files) and
    response_intel.py (Module 26, live HTTP responses) so the two producers
    never drift onto different wording for the same underlying finding type."""
    table = {"secret": SECRET_REMEDIATION, "pii": PII_REMEDIATION,
            "disclosure": DISCLOSURE_REMEDIATION}.get(category, {})
    return table.get(finding_type, table.get("credential", "") if category == "secret" else "")


def scan_text_findings(text: str, region: Optional[str] = None) -> List[dict]:
    """Run PII + secret + disclosure detectors over one blob; return unified
    finding dicts. Mirrors the Module 26 aggregation so file and response
    findings share one shape."""
    out: List[dict] = []
    for pii in detect_pii(text, region):
        d = {"category": "pii", "type": pii.pii_type,
            "severity": "high" if pii.pii_type in ("ssn", "credit_card") else "medium",
            "evidence": pii.evidence, "confidence": pii.confidence,
            "cwe": "CWE-359", "capec": "CAPEC-169",
            "remediation": remediation_for("pii", pii.pii_type)}
        ln = _line_of(text, pii.value)
        if ln:
            d["location"] = "line %d" % ln
        out.append(d)
    for sec in detect_secrets(text):
        d = {"category": "secret", "type": sec.secret_type,
            "severity": sec.severity, "evidence": sec.evidence,
            "confidence": sec.confidence, "cwe": "CWE-798", "capec": "CAPEC-37",
            "remediation": remediation_for("secret", sec.secret_type)}
        ln = _line_of(text, sec.value)
        if ln:
            d["location"] = "line %d" % ln
        out.append(d)
    for disc in detect_info_disclosure(text, None, ""):
        # Header-only checks are meaningless for a file on disk — a file has no
        # HTTP response headers, so "missing_security_headers" would fire on
        # every single file. Keep only body-derived disclosures.
        if disc.disclosure_type == "missing_security_headers":
            continue
        out.append({"category": "disclosure", "type": disc.disclosure_type,
                    "severity": disc.severity, "evidence": disc.evidence,
                    "confidence": disc.confidence, "cwe": disc.cwe, "capec": disc.capec,
                    "remediation": remediation_for("disclosure", disc.disclosure_type)})
    return out


def _host_from_url(url: str) -> str:
    """Best-effort hostname from a URL (empty string if unparseable)."""
    try:
        from urllib.parse import urlparse
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def _load_staged_url_maps(root: str) -> Dict[str, str]:
    """Build {staged-file -> original source URL} from every `index.tsv` manifest
    under `root`. The crawler / Module-10 staging writes `url<TAB>filename` rows
    when it downloads a JS bundle (js_downloads/index.tsv, filename = md5(url).js)
    or a 2xx response body (http_responses_2xx/index.tsv, filename = sha1[:16].txt).

    Keyed by BOTH the path relative to `root` (e.g. 'js_downloads/<md5>.js') and
    the bare basename, so a finding's `file` resolves whichever form it carries.
    This is what turns a 'blind' hashed-filename finding into one that names the
    real URL and host the secret/PII was loaded from (see the same reverse-map in
    the cloud-credentials fold, easm-pipeline.sh)."""
    url_map: Dict[str, str] = {}
    for dirpath, _dirs, filenames in _os.walk(root, followlinks=True):
        if "index.tsv" not in filenames:
            continue
        subdir = _os.path.relpath(dirpath, root)
        try:
            with open(_os.path.join(dirpath, "index.tsv"), "r", errors="ignore") as fh:
                for line in fh:
                    parts = line.rstrip("\n").split("\t")
                    if len(parts) != 2:
                        continue
                    url, fname = parts[0].strip(), parts[1].strip()
                    if not url or not fname:
                        continue
                    rel = fname if subdir in (".", "") else _os.path.join(subdir, fname)
                    url_map[rel] = url
                    url_map.setdefault(_os.path.basename(fname), url)
        except OSError:
            continue
    return url_map


def scan_local_files(root: str, base: Optional[str] = None,
                     max_bytes: int = _SCAN_MAX_BYTES,
                     exts: Optional[Set[str]] = None,
                     region: Optional[str] = None) -> List[dict]:
    """Walk `root`, scan every eligible text file, and return findings tagged
    with the file path (relative to `base`, default `root`). Follows symlinks —
    Module 10 stages js_downloads as a symlink into the scan tree.

    Each finding is also stamped with `source_url` + `host` when the staged file
    can be reverse-mapped to its original URL via an index.tsv manifest, so the
    finding names the real site/URL the secret or PII came from instead of an
    opaque hashed filename."""
    exts = exts if exts is not None else _SCAN_TEXT_EXT
    base = base or root
    # Reverse map hashed staged filename -> original source URL (built once).
    url_map = _load_staged_url_maps(base)
    if root != base:
        for k, v in _load_staged_url_maps(root).items():
            url_map.setdefault(k, v)
    findings: List[dict] = []
    seen: Set[Tuple[str, str, str]] = set()   # (relpath, type, evidence) — dedupe within a file
    for dirpath, _dirs, filenames in _os.walk(root, followlinks=True):
        for name in filenames:
            fpath = _os.path.join(dirpath, name)
            ext = _os.path.splitext(name)[1].lower()
            if ext not in exts:
                continue
            try:
                if _os.path.getsize(fpath) > max_bytes:
                    continue
            except OSError:
                continue
            if not _is_probably_text(fpath):
                continue
            try:
                with open(fpath, "r", errors="ignore") as fh:
                    text = fh.read()
            except OSError:
                continue
            if not text:
                continue
            rel = _os.path.relpath(fpath, base)
            for f in scan_text_findings(text, region):
                key = (rel, f["type"], f["evidence"])
                if key in seen:
                    continue
                seen.add(key)
                f.update({"file": rel, "source": "local-file",
                          "detection_tool": "arise_nlp", "module": "10.1"})
                # Reverse-map the hashed staged file back to its real URL + host
                # so the finding is actionable (which file, loaded from where).
                src_url = url_map.get(rel) or url_map.get(_os.path.basename(rel))
                if src_url:
                    f["source_url"] = src_url
                    host = _host_from_url(src_url)
                    if host:
                        f["host"] = host
                findings.append(f)
                if len(findings) >= _SCAN_MAX_FINDINGS:
                    return findings
    return findings


def _cli(argv=None) -> int:
    """No --scan-dir → run the self-test. With --scan-dir → Module 10.1 file scan."""
    import argparse
    p = argparse.ArgumentParser(
        description="ARISE NLP — self-test, or a local-file content scan (Module 10.1)")
    p.add_argument("--scan-dir", help="directory of staged files to scan for PII/secrets/disclosure")
    p.add_argument("--base", help="base dir for relative paths in output (default: --scan-dir)")
    p.add_argument("--out", help="write findings as JSONL here (default: stdout)")
    p.add_argument("--region", help="region hint for phone validation, e.g. IN")
    p.add_argument("--max-bytes", type=int, default=_SCAN_MAX_BYTES)
    args = p.parse_args(argv)

    if not args.scan_dir:
        return _selftest()
    if not _os.path.isdir(args.scan_dir):
        _sys.stderr.write(f"[arise_nlp] scan-dir not found: {args.scan_dir}\n")
        return 0

    findings = scan_local_files(args.scan_dir, base=args.base,
                                max_bytes=args.max_bytes, region=args.region)
    lines = [_json.dumps(f, ensure_ascii=False) for f in findings]
    if args.out:
        with open(args.out, "w") as fh:
            fh.write("\n".join(lines) + ("\n" if lines else ""))
    else:
        for ln in lines:
            print(ln)

    from collections import Counter
    by_cat = dict(Counter(f["category"] for f in findings))
    _sys.stderr.write(f"[arise_nlp] scanned {args.scan_dir}: "
                      f"{len(findings)} finding(s) {by_cat}\n")
    return 0


if __name__ == "__main__":
    _sys.exit(_cli())
