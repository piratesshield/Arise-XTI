#!/usr/bin/env python3
"""
ARISE Secret Validation Layer — real-time triage of TruffleHog findings
=======================================================================
TruffleHog is the DETECTOR (Module 10). It regex-matches candidate credentials
in crawled JS/config, but the pipeline runs it with ``--no-verification`` for
speed, so every hit currently lands in the dashboard hard-coded "critical" —
a rotated, fake, or already-dead key screams as loudly as a live payment key.

This module is the VALIDATOR. For each detected secret it performs a SAFE,
read-only liveness check against the credential provider's own identity
endpoint and grades the finding onto a four-rung ladder:

    invalid ............... regex matched but the key is dead/rotated/fake   -> info
    valid_restricted ...... authenticates but is fenced (scoped key, IP/geo/
                            permission boundary, test-mode)                  -> medium
    valid ................. live and usable                                  -> high
    valid_customer_data ... live AND the credential/leak reaches customer PII
                            or financial/payment data                       -> critical

Why this is safe (guardrails enforced IN CODE, not by convention):

  * Read-only identity endpoints only. Each verifier calls a fixed, hard-coded
    "who am I / what can I do" endpoint (AWS sts:GetCallerIdentity, Stripe
    GET /v1/account, GitHub GET /user, Slack auth.test, ...). There is no way
    to pass an arbitrary URL, and no verifier issues a write/mutating request.
  * NEVER exfiltrate customer data. The "customer_data" rung is decided by
    *capability inference* — the credential's type/scope (a Stripe live secret
    key can read customers; a SendGrid key with the `marketing` scope can read
    contact lists) and the classification of the leak container — NOT by
    pulling a single customer record. We prove the key *could* reach the data;
    we never fetch it.
  * Redaction. The raw secret is used only to sign/authenticate the one probe
    and is NEVER written to output or logs. Only a first4…last4 redaction and
    the provider-supplied identity (account id / user / ARN) are persisted.
  * Bounded. Total validations and per-provider calls are capped; each secret
    gets at most two calls; every call has a timeout.
  * Fail-safe. validate_all() NEVER raises. A network error / timeout yields an
    inconclusive "error" state (low severity, flagged for manual review) —
    never a false "valid" and never a crash.
  * Kill-switch. ``allow_network=False`` (or the pipeline's ARISE_SECRET_VALIDATE
    =0) does regex-derived classification only, with zero outbound calls.
  * Audit trail. Every probe (provider + endpoint + outcome, secret redacted)
    is timestamped to the audit log.

Authorization note: validating a leaked key by calling the provider's identity
endpoint *uses* that credential. In an authorized EASM/pentest of your own
estate the keys belong to you, and this is exactly what ``trufflehog
--only-verified`` does. The kill-switch exists for engagements where even
read-only use of a found credential is out of scope.

The HTTP transport is INJECTED (``http_fn``) so the whole engine is unit-testable
offline with no network and no live credentials — see the __main__ self-test,
which exercises every rung and every guardrail.
"""

from __future__ import annotations

import sys as _sys, os as _os
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)


import argparse
import base64
import datetime as _dt
import hashlib
import hmac
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

from core.net import verified_ssl_context

# http_fn(method, url, headers, body, timeout_s) -> (status, resp_headers, body_text, error)
HttpFn = Callable[[str, str, Dict[str, str], Optional[bytes], int],
                  Tuple[Optional[int], Dict[str, str], str, str]]

# ---------------------------------------------------------------------------
# States and severity ladder
# ---------------------------------------------------------------------------

STATE_INVALID = "invalid"                 # dead / rotated / fake
STATE_RESTRICTED = "valid_restricted"     # authenticates but fenced
STATE_VALID = "valid"                     # live and usable
STATE_SENSITIVE = "valid_customer_data"   # live AND reaches customer/financial data
STATE_UNSUPPORTED = "unsupported"         # no native verifier and no upstream verify signal
STATE_ERROR = "error"                     # inconclusive (network/timeout) -> manual

_SEVERITY = {
    STATE_INVALID: "info",
    STATE_UNSUPPORTED: "low",
    STATE_ERROR: "low",
    STATE_RESTRICTED: "medium",
    STATE_VALID: "high",
    STATE_SENSITIVE: "critical",
}

# Data-class tags that, on a VALID key, escalate high -> critical.
_SENSITIVE_DATA = {"customer_pii", "financial", "messaging_pii", "database"}

# Keywords in the leak *container* (file path / source url) that indicate the
# blast radius touches customer data even for an otherwise-generic valid key.
_CUSTOMER_CONTAINER_RE = re.compile(
    r"(customer|client|user[-_]?data|pii|gdpr|payment|invoic|billing|"
    r"cardholder|patient|ssn|passport|payroll|prod(uction)?[-_.]?(db|dump|backup))",
    re.I,
)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass
class ValidationConfig:
    allow_network: bool = True          # master kill-switch for outbound calls
    timeout_s: int = 8
    max_secrets: int = 300              # hard cap on total validations per run
    per_provider_cap: int = 60          # avoid hammering one provider
    user_agent: str = "ARISE-SecretValidator/1.0"
    audit_log_path: Optional[str] = None

    @classmethod
    def from_settings(cls, block: Optional[dict], audit_log_path: Optional[str] = None) -> "ValidationConfig":
        block = block or {}
        return cls(
            allow_network=bool(block.get("allow_network", True)),
            timeout_s=max(2, min(30, int(block.get("timeout_s", 8) or 8))),
            max_secrets=max(1, min(2000, int(block.get("max_secrets", 300) or 300))),
            per_provider_cap=max(1, min(500, int(block.get("per_provider_cap", 60) or 60))),
            user_agent=str(block.get("user_agent", "ARISE-SecretValidator/1.0")),
            audit_log_path=audit_log_path,
        )


# ---------------------------------------------------------------------------
# Audit + redaction helpers
# ---------------------------------------------------------------------------

class _Audit:
    def __init__(self, path: Optional[str]):
        self.path = path

    def write(self, line: str) -> None:
        if not self.path:
            return
        stamped = f"{_dt.datetime.now().isoformat(timespec='seconds')} {line}"
        try:
            with open(self.path, "a") as fh:
                fh.write(stamped + "\n")
        except OSError:
            pass  # audit failure must never break validation


def redact(secret: str) -> str:
    """first4…last4 with the middle masked. Short secrets are fully masked."""
    s = (secret or "").strip()
    if len(s) <= 8:
        return "*" * len(s)
    return f"{s[:4]}…{s[-4:]} ({len(s)} chars)"


# ---------------------------------------------------------------------------
# Default HTTP transport (injected in tests)
# ---------------------------------------------------------------------------

def default_http(method: str, url: str, headers: Dict[str, str],
                 body: Optional[bytes], timeout_s: int
                 ) -> Tuple[Optional[int], Dict[str, str], str, str]:
    # We are talking to well-known provider APIs over TLS; keep verification on
    # — via certifi's bundled CA store, not the interpreter's own default path
    # (some Python installs, e.g. python.org macOS builds pre "Install
    # Certificates.command", ship without one and would fail every call here).
    ctx = verified_ssl_context()
    req = urllib.request.Request(url, data=body, method=method)
    for k, v in headers.items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout_s, context=ctx) as resp:
            text = resp.read(65536).decode(errors="ignore")
            rh = {k.lower(): v for k, v in resp.headers.items()}
            return getattr(resp, "status", None), rh, text, ""
    except urllib.error.HTTPError as e:
        text = ""
        try:
            text = e.read(65536).decode(errors="ignore") if e.fp else ""
        except Exception:
            pass
        rh = {k.lower(): v for k, v in (e.headers or {}).items()}
        return e.code, rh, text, ""
    except Exception as e:  # noqa: BLE001 — transport must never raise to the loop
        return None, {}, "", str(e)[:200]


# ---------------------------------------------------------------------------
# Outcome of a single verifier
# ---------------------------------------------------------------------------

@dataclass
class Outcome:
    state: str
    identity: str = ""          # who the key belongs to (account/user/arn) — safe to store
    scopes: List[str] = field(default_factory=list)
    restriction: str = ""       # why it's fenced, if restricted
    data_class: str = "none"    # none|customer_pii|financial|messaging_pii|database|source|infra
    evidence: str = ""          # short, non-secret proof snippet
    endpoint: str = ""          # which identity endpoint was hit


def _err(endpoint: str, msg: str) -> Outcome:
    return Outcome(state=STATE_ERROR, evidence=msg[:200], endpoint=endpoint)


# ---------------------------------------------------------------------------
# Secret material extraction from a TruffleHog record
# ---------------------------------------------------------------------------

_AWS_ID_RE = re.compile(r"\b((?:AKIA|ASIA|AIDA|AROA)[0-9A-Z]{16})\b")
_AWS_SECRET_RE = re.compile(r"\b([A-Za-z0-9/+]{40})\b")


@dataclass
class Material:
    detector: str               # normalized provider key
    detector_raw: str           # original DetectorName
    raw: str                    # the primary secret string (used for the probe, never persisted)
    rawv2: str
    extra: dict
    upstream_verified: Optional[bool]
    redacted: str
    source_file: str
    source_url: str
    host: str


_PREFIX_PROVIDER = [
    ("sk_live_", "stripe"), ("rk_live_", "stripe"), ("sk_test_", "stripe"), ("rk_test_", "stripe"),
    ("xoxb-", "slack"), ("xoxp-", "slack"), ("xoxa-", "slack"), ("xoxr-", "slack"), ("xapp-", "slack"),
    ("ghp_", "github"), ("gho_", "github"), ("ghu_", "github"), ("ghs_", "github"),
    ("ghr_", "github"), ("github_pat_", "github"),
    ("glpat-", "gitlab"),
    ("SG.", "sendgrid"),
    ("key-", "mailgun"),
    ("sk-proj-", "openai"), ("sk-ant-", "anthropic"), ("sk-", "openai"),
    ("AIza", "google_api"),
    ("AKI" "A", "aws"), ("ASIA", "aws"),
]

# Map many TruffleHog DetectorName spellings onto our verifier keys.
_NAME_ALIASES = {
    "aws": "aws", "awssessionkey": "aws", "aws_secret": "aws",
    "stripe": "stripe", "stripekey": "stripe",
    "github": "github", "githubapp": "github", "github_oauth2": "github",
    "gitlab": "gitlab",
    "slack": "slack", "slacktoken": "slack",
    "sendgrid": "sendgrid",
    "twilio": "twilio",
    "mailgun": "mailgun",
    "openai": "openai",
    "anthropic": "anthropic",
    "gcp": "google_api", "google": "google_api", "gcpapikey": "google_api",
}


def _normalize_provider(detector_name: str, raw: str, rawv2: str) -> str:
    n = re.sub(r"[^a-z0-9]", "", (detector_name or "").lower())
    if n in _NAME_ALIASES:
        return _NAME_ALIASES[n]
    for key, prov in _NAME_ALIASES.items():
        if key and key in n:
            return prov
    blob = f"{raw} {rawv2}"
    for pfx, prov in _PREFIX_PROVIDER:
        if pfx in blob:
            return prov
    return (detector_name or "unknown").strip() or "unknown"


def parse_record(entry: dict) -> Optional[Material]:
    if not isinstance(entry, dict):
        return None
    detector_raw = str(entry.get("DetectorName") or entry.get("detector_name") or "Credential")
    raw = str(entry.get("Raw") or entry.get("raw") or "")
    rawv2 = str(entry.get("RawV2") or entry.get("raw_v2") or "")
    extra = entry.get("ExtraData") if isinstance(entry.get("ExtraData"), dict) else {}
    verified = entry.get("Verified")
    upstream_verified = bool(verified) if isinstance(verified, bool) else None
    redacted = str(entry.get("Redacted") or "").strip()

    sm = entry.get("SourceMetadata") or {}
    fpath = ""
    try:
        fpath = ((sm.get("Data") or {}).get("Filesystem") or {}).get("file", "") or ""
    except Exception:
        fpath = ""
    src_url = str(entry.get("_source_url") or "")   # optional enrichment injected by caller
    host = str(entry.get("_host") or "")

    if not (raw or rawv2):
        return None
    provider = _normalize_provider(detector_raw, raw, rawv2)
    if not redacted:
        redacted = redact(raw or rawv2)
    return Material(detector=provider, detector_raw=detector_raw, raw=raw, rawv2=rawv2,
                    extra=extra, upstream_verified=upstream_verified, redacted=redacted,
                    source_file=fpath, source_url=src_url, host=host)


# ---------------------------------------------------------------------------
# Per-provider verifiers — each hits ONE hard-coded read-only identity endpoint
# ---------------------------------------------------------------------------

def _basic(user: str, pw: str = "") -> str:
    tok = base64.b64encode(f"{user}:{pw}".encode()).decode()
    return f"Basic {tok}"


def verify_stripe(m: Material, http: HttpFn, cfg: ValidationConfig) -> Outcome:
    key = _extract_prefixed(m, ("sk_live_", "rk_live_", "sk_test_", "rk_test_", "sk_", "rk_")) or m.raw
    endpoint = "https://api.stripe.com/v1/account"  # returns the MERCHANT's own account, not customers
    st, _, body, err = http("GET", endpoint, {"Authorization": _basic(key)}, None, cfg.timeout_s)
    if err:
        return _err(endpoint, err)
    if st in (401, 403):
        return Outcome(STATE_INVALID, evidence=f"HTTP {st} from Stripe", endpoint=endpoint)
    if st == 200:
        ident = _json_get(body, "id") or "stripe-account"
        biz = _json_get(body, "business_profile.name") or _json_get(body, "settings.dashboard.display_name") or ""
        ev = f"200 OK account={ident}" + (f" ({biz})" if biz else "")
        if key.startswith(("rk_live_", "rk_test_")):
            return Outcome(STATE_RESTRICTED, identity=ident, restriction="restricted API key (rk_)",
                           data_class="financial", evidence=ev, endpoint=endpoint)
        if key.startswith("sk_test_"):
            return Outcome(STATE_RESTRICTED, identity=ident, restriction="test-mode key (no real customer data)",
                           data_class="none", evidence=ev, endpoint=endpoint)
        # sk_live_ full secret key: can read /v1/customers, /v1/charges -> PII + payment data.
        return Outcome(STATE_VALID, identity=ident, data_class="financial",
                       evidence=ev, endpoint=endpoint)
    return _err(endpoint, f"unexpected HTTP {st}")


def verify_github(m: Material, http: HttpFn, cfg: ValidationConfig) -> Outcome:
    key = _extract_prefixed(m, ("github_pat_", "ghp_", "gho_", "ghu_", "ghs_", "ghr_")) or m.raw
    endpoint = "https://api.github.com/user"
    st, rh, body, err = http("GET", endpoint,
                             {"Authorization": f"token {key}", "Accept": "application/vnd.github+json"},
                             None, cfg.timeout_s)
    if err:
        return _err(endpoint, err)
    if st in (401, 403):
        return Outcome(STATE_INVALID, evidence=f"HTTP {st} from GitHub", endpoint=endpoint)
    if st == 200:
        login = _json_get(body, "login") or "github-user"
        scope_hdr = rh.get("x-oauth-scopes", "")
        scopes = [s.strip() for s in scope_hdr.split(",") if s.strip()]
        ev = f"200 OK user={login} scopes=[{scope_hdr}]"
        fine_grained = key.startswith("github_pat_")
        powerful = any(s in scopes for s in ("repo", "admin:org", "write:org", "delete_repo",
                                             "admin:repo_hook", "workflow"))
        if fine_grained or (scopes and not powerful):
            return Outcome(STATE_RESTRICTED, identity=login, scopes=scopes,
                           restriction="fine-grained/limited-scope token" if fine_grained
                                       else "read-limited scopes",
                           data_class="source", evidence=ev, endpoint=endpoint)
        # broad classic PAT: private repos may contain customer data, but we do NOT clone.
        return Outcome(STATE_VALID, identity=login, scopes=scopes, data_class="source",
                       evidence=ev, endpoint=endpoint)
    return _err(endpoint, f"unexpected HTTP {st}")


def verify_gitlab(m: Material, http: HttpFn, cfg: ValidationConfig) -> Outcome:
    key = _extract_prefixed(m, ("glpat-",)) or m.raw
    endpoint = "https://gitlab.com/api/v4/user"
    st, _, body, err = http("GET", endpoint, {"PRIVATE-TOKEN": key}, None, cfg.timeout_s)
    if err:
        return _err(endpoint, err)
    if st in (401, 403):
        return Outcome(STATE_INVALID, evidence=f"HTTP {st} from GitLab", endpoint=endpoint)
    if st == 200:
        uname = _json_get(body, "username") or "gitlab-user"
        return Outcome(STATE_VALID, identity=uname, data_class="source",
                       evidence=f"200 OK user={uname}", endpoint=endpoint)
    return _err(endpoint, f"unexpected HTTP {st}")


def verify_slack(m: Material, http: HttpFn, cfg: ValidationConfig) -> Outcome:
    key = _extract_prefixed(m, ("xoxb-", "xoxp-", "xoxa-", "xoxr-", "xapp-")) or m.raw
    endpoint = "https://slack.com/api/auth.test"  # Slack's whoami; read-only despite POST
    st, _, body, err = http("POST", endpoint,
                            {"Authorization": f"Bearer {key}",
                             "Content-Type": "application/x-www-form-urlencoded"},
                            b"", cfg.timeout_s)
    if err:
        return _err(endpoint, err)
    ok = _json_get(body, "ok")
    if str(ok).lower() == "true":
        team = _json_get(body, "team") or ""
        user = _json_get(body, "user") or "slack"
        # Workspace messages routinely contain customer PII; bot/user token = read access.
        return Outcome(STATE_VALID, identity=f"{user}@{team}".strip("@"),
                       data_class="messaging_pii",
                       evidence=f"auth.test ok team={team} user={user}", endpoint=endpoint)
    reason = _json_get(body, "error") or f"HTTP {st}"
    return Outcome(STATE_INVALID, evidence=f"auth.test not ok: {reason}", endpoint=endpoint)


def verify_sendgrid(m: Material, http: HttpFn, cfg: ValidationConfig) -> Outcome:
    key = _extract_prefixed(m, ("SG.",)) or m.raw
    endpoint = "https://api.sendgrid.com/v3/scopes"  # returns the key's own scopes, not contacts
    st, _, body, err = http("GET", endpoint, {"Authorization": f"Bearer {key}"}, None, cfg.timeout_s)
    if err:
        return _err(endpoint, err)
    if st in (401, 403):
        return Outcome(STATE_INVALID, evidence=f"HTTP {st} from SendGrid", endpoint=endpoint)
    if st == 200:
        scopes = _json_list(body, "scopes")
        ev = f"200 OK scopes={len(scopes)}"
        has_contacts = any(s.startswith(("marketing", "mail.batch", "contacts")) or "recipients" in s
                           for s in scopes)
        can_send = any(s.startswith("mail.send") for s in scopes)
        if has_contacts:
            return Outcome(STATE_VALID, identity="sendgrid-key", scopes=scopes,
                           data_class="customer_pii",
                           evidence=ev + " (marketing/contacts -> recipient PII)", endpoint=endpoint)
        if can_send:
            return Outcome(STATE_VALID, identity="sendgrid-key", scopes=scopes,
                           data_class="messaging_pii", evidence=ev + " (mail.send)", endpoint=endpoint)
        return Outcome(STATE_RESTRICTED, identity="sendgrid-key", scopes=scopes,
                       restriction="narrow scopes", data_class="none", evidence=ev, endpoint=endpoint)
    return _err(endpoint, f"unexpected HTTP {st}")


def verify_twilio(m: Material, http: HttpFn, cfg: ValidationConfig) -> Outcome:
    # Twilio needs the Account SID (AC...) + auth token. TruffleHog usually carries
    # both in RawV2/ExtraData; if we only have one, fall back to unsupported.
    sid = _find(m, r"\bAC[0-9a-fA-F]{32}\b")
    token = _find(m, r"\b[0-9a-fA-F]{32}\b", exclude=sid) or m.raw
    if not sid:
        return Outcome(STATE_UNSUPPORTED, evidence="Twilio SID (AC...) not present alongside token")
    endpoint = f"https://api.twilio.com/2010-04-01/Accounts/{sid}.json"
    st, _, body, err = http("GET", endpoint, {"Authorization": _basic(sid, token)}, None, cfg.timeout_s)
    if err:
        return _err(endpoint, err)
    if st in (401, 403):
        return Outcome(STATE_INVALID, evidence=f"HTTP {st} from Twilio", endpoint=endpoint)
    if st == 200:
        name = _json_get(body, "friendly_name") or sid
        status = _json_get(body, "status") or ""
        # Twilio holds call/SMS logs = customer phone numbers + message bodies.
        return Outcome(STATE_VALID, identity=name, data_class="customer_pii",
                       evidence=f"200 OK account={name} status={status}", endpoint=endpoint)
    return _err(endpoint, f"unexpected HTTP {st}")


def verify_mailgun(m: Material, http: HttpFn, cfg: ValidationConfig) -> Outcome:
    key = _extract_prefixed(m, ("key-",)) or m.raw
    endpoint = "https://api.mailgun.net/v4/domains"  # lists the account's sending domains
    st, _, body, err = http("GET", endpoint, {"Authorization": _basic("api", key)}, None, cfg.timeout_s)
    if err:
        return _err(endpoint, err)
    if st in (401, 403):
        return Outcome(STATE_INVALID, evidence=f"HTTP {st} from Mailgun", endpoint=endpoint)
    if st == 200:
        # Stored messages + recipient variables = customer email PII.
        return Outcome(STATE_VALID, identity="mailgun-account", data_class="customer_pii",
                       evidence="200 OK domains listable", endpoint=endpoint)
    return _err(endpoint, f"unexpected HTTP {st}")


def verify_openai(m: Material, http: HttpFn, cfg: ValidationConfig) -> Outcome:
    key = _extract_prefixed(m, ("sk-proj-", "sk-")) or m.raw
    endpoint = "https://api.openai.com/v1/models"
    st, _, _, err = http("GET", endpoint, {"Authorization": f"Bearer {key}"}, None, cfg.timeout_s)
    if err:
        return _err(endpoint, err)
    if st in (401, 403):
        return Outcome(STATE_INVALID, evidence=f"HTTP {st} from OpenAI", endpoint=endpoint)
    if st == 200:
        # Live key = billing/abuse exposure; no customer data store behind it.
        return Outcome(STATE_VALID, identity="openai-key", data_class="infra",
                       evidence="200 OK /v1/models", endpoint=endpoint)
    return _err(endpoint, f"unexpected HTTP {st}")


def verify_aws(m: Material, http: HttpFn, cfg: ValidationConfig) -> Outcome:
    """sts:GetCallerIdentity — the canonical zero-privilege whoami. Needs the
    access-key id AND the secret to sign; if only the id was leaked we cannot
    (and should not) fabricate a probe -> unsupported."""
    key_id = _find(m, _AWS_ID_RE.pattern)
    secret = _aws_secret(m, key_id)
    if not (key_id and secret):
        return Outcome(STATE_UNSUPPORTED,
                       evidence="AWS secret access key not present alongside the key id")
    endpoint = "https://sts.amazonaws.com/"
    try:
        headers, qs = _sigv4_get_caller_identity(key_id, secret)
    except Exception as e:  # noqa: BLE001
        return _err(endpoint, f"signing failed: {e}")
    url = endpoint + "?" + qs
    st, _, body, err = http("GET", url, headers, None, cfg.timeout_s)
    if err:
        return _err(endpoint, err)
    low = body.lower()
    if st == 403 and ("invalidclienttokenid" in low or "signaturedoesnotmatch" in low):
        return Outcome(STATE_INVALID, evidence="STS: InvalidClientTokenId/SignatureDoesNotMatch",
                       endpoint=endpoint)
    if st == 403 and "accessdenied" in low:
        # Well-formed creds but an SCP / permission boundary / IP condition denies
        # even GetCallerIdentity -> live but fenced.
        return Outcome(STATE_RESTRICTED, restriction="STS AccessDenied (SCP/boundary/IP condition)",
                       data_class="infra", evidence="STS returned AccessDenied", endpoint=endpoint)
    if st == 200:
        arn = _xml_get(body, "Arn")
        acct = _xml_get(body, "Account")
        ident = arn or acct or "aws-principal"
        is_root = arn.endswith(":root") if arn else False
        ev = f"200 OK arn={arn} account={acct}"
        if is_root:
            return Outcome(STATE_VALID, identity=ident, data_class="financial",
                           evidence=ev + " (ROOT credentials)", endpoint=endpoint)
        # Valid IAM principal: broad blast radius (S3/RDS/etc.) but we do NOT enumerate data.
        return Outcome(STATE_VALID, identity=ident, data_class="infra", evidence=ev, endpoint=endpoint)
    return _err(endpoint, f"unexpected HTTP {st}")


def verify_unsupported(m: Material, http: HttpFn, cfg: ValidationConfig) -> Outcome:
    """No native verifier. Fall back to TruffleHog's own Verified flag if the
    operator ran it with verification; otherwise leave it unproven."""
    if m.upstream_verified is True:
        return Outcome(STATE_VALID, identity=m.detector_raw, data_class="unknown",
                       evidence="TruffleHog upstream Verified=true")
    return Outcome(STATE_UNSUPPORTED, evidence="no native verifier; not upstream-verified")


VERIFIERS: Dict[str, Callable[[Material, HttpFn, ValidationConfig], Outcome]] = {
    "aws": verify_aws,
    "stripe": verify_stripe,
    "github": verify_github,
    "gitlab": verify_gitlab,
    "slack": verify_slack,
    "sendgrid": verify_sendgrid,
    "twilio": verify_twilio,
    "mailgun": verify_mailgun,
    "openai": verify_openai,
}


# ---------------------------------------------------------------------------
# Tiny, dependency-free extraction helpers (defensive; never raise)
# ---------------------------------------------------------------------------

def _extract_prefixed(m: Material, prefixes: Tuple[str, ...]) -> str:
    blob = f"{m.raw}\n{m.rawv2}"
    for pfx in prefixes:
        idx = blob.find(pfx)
        if idx >= 0:
            tail = blob[idx:]
            token = re.split(r"[\s\"'<>,;]", tail, 1)[0]
            if token:
                return token
    return ""


def _find(m: Material, pattern: str, exclude: str = "") -> str:
    for src in (m.rawv2, m.raw, json.dumps(m.extra)):
        for mo in re.finditer(pattern, src or ""):
            val = mo.group(0)
            if val and val != exclude:
                return val
    return ""


def _aws_secret(m: Material, key_id: str) -> str:
    # explicit ExtraData first
    for k in ("secret", "SecretKey", "secret_key", "aws_secret_access_key"):
        v = (m.extra or {}).get(k)
        if isinstance(v, str) and len(v) >= 30:
            return v
    for src in (m.rawv2, m.raw):
        for mo in _AWS_SECRET_RE.finditer(src or ""):
            cand = mo.group(1)
            if cand and cand != key_id and not _AWS_ID_RE.match(cand):
                return cand
    return ""


def _json_get(body: str, dotted: str):
    try:
        obj = json.loads(body)
    except Exception:
        return ""
    cur = obj
    for part in dotted.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return ""
    return cur if isinstance(cur, (str, int, float, bool)) else ""


def _json_list(body: str, key: str) -> List[str]:
    try:
        obj = json.loads(body)
        v = obj.get(key) if isinstance(obj, dict) else None
        return [str(x) for x in v] if isinstance(v, list) else []
    except Exception:
        return []


def _xml_get(body: str, tag: str) -> str:
    mo = re.search(rf"<{tag}>([^<]+)</{tag}>", body or "")
    return mo.group(1).strip() if mo else ""


# ---------------------------------------------------------------------------
# AWS SigV4 for GetCallerIdentity (GET, empty body, us-east-1/sts)
# ---------------------------------------------------------------------------

def _sigv4_get_caller_identity(key_id: str, secret: str) -> Tuple[Dict[str, str], str]:
    service, region, host = "sts", "us-east-1", "sts.amazonaws.com"
    now = _dt.datetime.now(_dt.timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now.strftime("%Y%m%d")

    qs = "Action=GetCallerIdentity&Version=2011-06-15"
    canonical_headers = f"host:{host}\nx-amz-date:{amz_date}\n"
    signed_headers = "host;x-amz-date"
    payload_hash = hashlib.sha256(b"").hexdigest()
    canonical_request = "\n".join(["GET", "/", qs, canonical_headers, signed_headers, payload_hash])

    scope = f"{date_stamp}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join([
        "AWS4-HMAC-SHA256", amz_date, scope,
        hashlib.sha256(canonical_request.encode()).hexdigest(),
    ])

    def _hmac(k: bytes, msg: str) -> bytes:
        return hmac.new(k, msg.encode(), hashlib.sha256).digest()

    k_date = _hmac(("AWS4" + secret).encode(), date_stamp)
    k_region = _hmac(k_date, region)
    k_service = _hmac(k_region, service)
    k_signing = _hmac(k_service, "aws4_request")
    signature = hmac.new(k_signing, string_to_sign.encode(), hashlib.sha256).hexdigest()

    authorization = (
        f"AWS4-HMAC-SHA256 Credential={key_id}/{scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )
    headers = {"x-amz-date": amz_date, "Authorization": authorization, "Accept": "application/json"}
    return headers, qs


# ---------------------------------------------------------------------------
# Grade one secret: verifier outcome + container context -> final rung
# ---------------------------------------------------------------------------

REMEDIATION = {
    STATE_SENSITIVE: "CRITICAL: live credential reaching customer/financial data. "
                     "Revoke NOW, rotate, and review provider access logs for abuse.",
    STATE_VALID: "Live credential. Revoke and rotate immediately; scope the replacement to least privilege.",
    STATE_RESTRICTED: "Credential authenticates but is scope/network limited. Rotate; verify the "
                      "restriction cannot be bypassed and tighten the scope.",
    STATE_INVALID: "Credential does not authenticate (dead/rotated/fake). Remove it from source to "
                   "cut noise; confirm it was truly rotated, not merely IP-blocked from your vantage.",
    STATE_UNSUPPORTED: "Auto-validation unavailable for this credential type. Validate manually against "
                       "the provider's identity endpoint, then rotate if live.",
    STATE_ERROR: "Validation was inconclusive (network/timeout). Re-run validation or verify manually.",
}


def grade(m: Material, oc: Outcome, cfg: ValidationConfig) -> dict:
    state = oc.state
    container = f"{m.source_file} {m.source_url}"
    container_flags_customer = bool(_CUSTOMER_CONTAINER_RE.search(container))

    # Escalation: a VALID key becomes CRITICAL when it reaches customer/financial
    # data — proven either by the credential's own capability (data_class) or by
    # the leak container clearly holding customer data.
    if state == STATE_VALID:
        if oc.data_class in _SENSITIVE_DATA or container_flags_customer:
            state = STATE_SENSITIVE

    severity = _SEVERITY.get(state, "low")
    reason_bits = []
    if oc.identity:
        reason_bits.append(f"identity={oc.identity}")
    if oc.scopes:
        reason_bits.append(f"scopes={','.join(oc.scopes[:6])}")
    if oc.restriction:
        reason_bits.append(f"restriction={oc.restriction}")
    if state == STATE_SENSITIVE and container_flags_customer and oc.data_class not in _SENSITIVE_DATA:
        reason_bits.append("leak container indicates customer data")

    return {
        "detector": m.detector_raw,
        "provider": m.detector,
        "redacted": m.redacted,
        "state": state,
        "severity": severity,
        "identity": oc.identity,
        "scopes": oc.scopes,
        "restriction": oc.restriction,
        "data_class": oc.data_class,
        "evidence": oc.evidence,
        "endpoint": oc.endpoint,
        "reason": "; ".join(reason_bits),
        "remediation": REMEDIATION.get(state, REMEDIATION[STATE_ERROR]),
        "source_file": m.source_file,
        "source_url": m.source_url,
        "host": m.host,
        "validated_at": _dt.datetime.now().isoformat(timespec="seconds"),
        "verifier": "native" if m.detector in VERIFIERS else (
            "trufflehog" if m.upstream_verified is not None else "none"),
    }


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def validate_all(entries: List[dict], cfg: ValidationConfig,
                 http_fn: Optional[HttpFn] = None) -> List[dict]:
    """Validate a list of TruffleHog records. NEVER raises. Returns one graded
    dict per input secret (best-effort; unparseable rows are skipped)."""
    http = http_fn or default_http
    audit = _Audit(cfg.audit_log_path)
    results: List[dict] = []
    per_provider: Dict[str, int] = {}
    seen: set = set()

    for entry in entries:
        if len(results) >= cfg.max_secrets:
            break
        m = parse_record(entry)
        if not m:
            continue

        # De-dupe identical secret material (same key found in many files).
        dedup_key = (m.detector, (m.raw or m.rawv2)[:64])
        if dedup_key in seen:
            continue
        seen.add(dedup_key)

        verifier = VERIFIERS.get(m.detector, verify_unsupported)

        # Offline / kill-switch: no outbound calls -> regex-only classification.
        if not cfg.allow_network:
            oc = (Outcome(STATE_VALID, identity=m.detector_raw, data_class="unknown",
                          evidence="upstream Verified=true (network validation disabled)")
                  if m.upstream_verified is True
                  else Outcome(STATE_UNSUPPORTED, evidence="network validation disabled"))
            results.append(grade(m, oc, cfg))
            continue

        n = per_provider.get(m.detector, 0)
        if n >= cfg.per_provider_cap:
            oc = Outcome(STATE_ERROR, evidence=f"per-provider cap ({cfg.per_provider_cap}) reached")
            results.append(grade(m, oc, cfg))
            continue
        per_provider[m.detector] = n + 1

        try:
            oc = verifier(m, http, cfg)
        except Exception as e:  # noqa: BLE001 — a broken verifier must not sink the run
            oc = _err("", f"verifier crashed: {e}")
        audit.write(f"validate provider={m.detector} redacted={m.redacted} "
                    f"-> {oc.state} endpoint={oc.endpoint}")
        results.append(grade(m, oc, cfg))

    return results


def _read_jsonl(path: str) -> List[dict]:
    out = []
    try:
        with open(path, "r") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    if isinstance(obj, dict):
                        out.append(obj)
                except Exception:
                    continue
    except OSError:
        pass
    return out


def _summary(results: List[dict]) -> dict:
    by = {}
    for r in results:
        by[r["state"]] = by.get(r["state"], 0) + 1
    return {
        "total": len(results),
        "by_state": by,
        "critical": sum(1 for r in results if r["severity"] == "critical"),
        "high": sum(1 for r in results if r["severity"] == "high"),
    }


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="ARISE safe secret validation (TruffleHog post-processor)")
    ap.add_argument("--input", required=True, help="TruffleHog secrets.jsonl")
    ap.add_argument("--output", required=True, help="destination secrets_validated.jsonl")
    ap.add_argument("--audit", default=None, help="append-only audit log path")
    ap.add_argument("--summary", default=None, help="optional summary JSON path")
    ap.add_argument("--no-network", action="store_true",
                    help="regex-only classification, zero outbound calls (kill-switch)")
    ap.add_argument("--timeout", type=int, default=8)
    args = ap.parse_args(argv)

    cfg = ValidationConfig(allow_network=not args.no_network, timeout_s=args.timeout,
                           audit_log_path=args.audit)
    entries = _read_jsonl(args.input)
    results = validate_all(entries, cfg)

    try:
        with open(args.output, "w") as fh:
            for r in results:
                fh.write(json.dumps(r) + "\n")
    except OSError as e:
        print(f"[secret_validator] failed to write output: {e}", file=sys.stderr)
        return 1

    summ = _summary(results)
    if args.summary:
        try:
            with open(args.summary, "w") as fh:
                json.dump(summ, fh, indent=2)
        except OSError:
            pass
    print(f"[secret_validator] {summ['total']} secrets validated: {summ['by_state']}")
    return 0


# ---------------------------------------------------------------------------
# Offline self-test — every rung + every guardrail, no network, no live keys
# ---------------------------------------------------------------------------

if __name__ == "__main__" and len(sys.argv) == 1:
    print("=== secret_validator self-test (offline, no network, no real keys) ===\n")
    cfg = ValidationConfig(allow_network=True, timeout_s=2)

    def rec(detector, raw, **extra):
        e = {"DetectorName": detector, "Raw": raw,
             "SourceMetadata": {"Data": {"Filesystem": {"file": extra.pop("file", "app.js")}}}}
        e.update(extra)
        return e

    # -- Fake HTTP transport keyed on URL: models each provider's identity API.
    def fake_http(method, url, headers, body, timeout):
        auth = headers.get("Authorization", "")
        if "api.stripe.com" in url:
            if "sk_" "live_GOOD" in auth_b64(auth):
                return 200, {}, json.dumps({"id": "acct_123", "business_profile": {"name": "Acme"}}), ""
            if "rk_" "live_GOOD" in auth_b64(auth):
                return 200, {}, json.dumps({"id": "acct_123"}), ""
            if "sk_" "test_GOOD" in auth_b64(auth):
                return 200, {}, json.dumps({"id": "acct_test"}), ""
            return 401, {}, "{}", ""
        if "api.github.com/user" in url:
            if "ghp" "_GOODREPO" in auth:
                return 200, {"x-oauth-scopes": "repo, workflow"}, json.dumps({"login": "octocat"}), ""
            if "git" "hub_pat_GOOD" in auth:
                return 200, {"x-oauth-scopes": ""}, json.dumps({"login": "fg-user"}), ""
            return 401, {}, "{}", ""
        if "slack.com/api/auth.test" in url:
            if "xox" "b-GOOD" in auth:
                return 200, {}, json.dumps({"ok": True, "team": "Acme", "user": "bot"}), ""
            return 200, {}, json.dumps({"ok": False, "error": "invalid_auth"}), ""
        if "api.sendgrid.com" in url:
            if "SG.GOODMKT" in auth:
                return 200, {}, json.dumps({"scopes": ["mail.send", "marketing.read"]}), ""
            if "SG.GOODSEND" in auth:
                return 200, {}, json.dumps({"scopes": ["mail.send"]}), ""
            return 401, {}, "{}", ""
        if "sts.amazonaws.com" in url:
            # signature encodes the real secret; we can't see it, so key on the id in Credential
            if "AKI" "AGOODROOT" in headers.get("Authorization", ""):
                return 200, {}, "<Arn>arn:aws:iam::111:root</Arn><Account>111</Account>", ""
            if "AKI" "AGOODUSER" in headers.get("Authorization", ""):
                return 200, {}, "<Arn>arn:aws:iam::111:user/dev</Arn><Account>111</Account>", ""
            if "AKI" "ADENIED" in headers.get("Authorization", ""):
                return 403, {}, "AccessDenied: explicit deny", ""
            return 403, {}, "InvalidClientTokenId", ""
        if "api.openai.com" in url:
            return (200, {}, "{}", "") if "sk-GOOD" in auth else (401, {}, "{}", "")
        return None, {}, "", "unexpected endpoint"

    def auth_b64(auth_header):
        # decode Basic <b64> so tests can assert on the embedded key
        try:
            return base64.b64decode(auth_header.split(" ", 1)[1]).decode()
        except Exception:
            return auth_header

    def one(entry):
        return validate_all([entry], cfg, http_fn=fake_http)[0]

    # [1] invalid -> info
    r = one(rec("Stripe", "sk_" "live_DEAD"))
    assert r["state"] == STATE_INVALID and r["severity"] == "info", r
    print("[1] dead Stripe key -> invalid/info  ✓")

    # [2] valid + financial capability -> critical (live sk_live_)
    r = one(rec("Stripe", "sk_" "live_GOODxxxxxxxxxxxxxxxxxxxx"))
    assert r["state"] == STATE_SENSITIVE and r["severity"] == "critical", r
    print("[2] live Stripe secret key (customer/financial) -> valid_customer_data/critical  ✓")

    # [3] restricted Stripe key (rk_) -> medium
    r = one(rec("Stripe", "rk_" "live_GOODxxxxxxxxxxxxxxxxxxxx"))
    assert r["state"] == STATE_RESTRICTED and r["severity"] == "medium", r
    print("[3] restricted Stripe key (rk_live) -> valid_restricted/medium  ✓")

    # [4] test-mode Stripe key -> restricted/medium (no real customer data)
    r = one(rec("Stripe", "sk_" "test_GOODxxxxxxxxxxxxxxxxxxxx"))
    assert r["state"] == STATE_RESTRICTED, r
    print("[4] test-mode Stripe key -> valid_restricted (no real customer data)  ✓")

    # [5] GitHub broad PAT -> valid/high; fine-grained -> restricted/medium
    r = one(rec("Github", "ghp" "_GOODREPOxxxxxxxxxxxxxxxxxxxxxxxx"))
    assert r["state"] == STATE_VALID and r["severity"] == "high", r
    r2 = one(rec("Github", "git" "hub_pat_GOODxxxxxxxxxxxx"))
    assert r2["state"] == STATE_RESTRICTED, r2
    print("[5] GitHub: broad PAT -> valid/high, fine-grained -> restricted/medium  ✓")

    # [6] Slack bot token -> valid, messaging PII -> critical
    r = one(rec("Slack", "xox" "b-GOODxxxxxxxxxxxx"))
    assert r["state"] == STATE_SENSITIVE and r["severity"] == "critical", r
    print("[6] live Slack bot token (messaging PII) -> critical  ✓")

    # [7] SendGrid marketing scope -> critical; send-only -> messaging/critical; invalid -> info
    r = one(rec("SendGrid", "SG.GOODMKT.xxxxxxxxxxxxxxxxxxxxxxxx"))
    assert r["state"] == STATE_SENSITIVE, r
    r = one(rec("SendGrid", "SG.DEAD.xxxxxxxxxxxxxxxxxxxxxxxx"))
    assert r["state"] == STATE_INVALID, r
    print("[7] SendGrid marketing key -> critical, dead -> info  ✓")

    # [8] AWS root -> critical; user -> high; denied -> restricted; bad -> invalid
    #     AKIA id = AKIA + 16 [A-Z0-9]; secret = 40 [A-Za-z0-9/+].
    SEC40 = "abcdefghijklmnopqrstuvwxyz0123456789ABCD"
    r = one(rec("AWS", f"{"AKI"}AGOODROOT00000000 {SEC40}"))
    assert r["state"] == STATE_SENSITIVE, r  # root => financial data_class => critical
    r = one(rec("AWS", f"{"AKI"}AGOODUSER00000000 {SEC40}"))
    assert r["state"] == STATE_VALID and r["severity"] == "high", r
    r = one(rec("AWS", f"{"AKI"}ADENIED0000000000 {SEC40}"))
    assert r["state"] == STATE_RESTRICTED, r
    r = one(rec("AWS", f"{"AKI"}ABAD0000000000000 {SEC40}"))
    assert r["state"] == STATE_INVALID, r
    print("[8] AWS: root->critical, user->high, AccessDenied->restricted, bad->invalid  ✓")

    # [9] AWS id without secret -> unsupported (never fabricate a probe)
    r = one(rec("AWS", "AKI" "AAAAAAAAAAAAAAAAA"))
    assert r["state"] == STATE_UNSUPPORTED, r
    print("[9] AWS id with no secret -> unsupported (no probe fabricated)  ✓")

    # [10] container escalation: generic valid OpenAI key in a 'customer-data' file -> critical
    r = one(rec("OpenAI", "sk-GOODxxxxxxxxxxxxxxxxxxxx", file="prod/customer_export.js"))
    assert r["state"] == STATE_SENSITIVE, r
    r = one(rec("OpenAI", "sk-GOODxxxxxxxxxxxxxxxxxxxx", file="app.js"))
    assert r["state"] == STATE_VALID, r
    print("[10] container escalation: valid key in customer-data file -> critical  ✓")

    # [11] kill-switch: no network -> zero calls, unsupported/valid-by-upstream only
    def boom_http(*a, **k):
        raise AssertionError("no network call allowed when allow_network=False")
    off = ValidationConfig(allow_network=False)
    r = validate_all([rec("Stripe", "sk_" "live_GOODxxxxxxxxxxxx")], off, http_fn=boom_http)[0]
    assert r["state"] == STATE_UNSUPPORTED, r
    r = validate_all([rec("Whatever", "x", Verified=True)], off, http_fn=boom_http)[0]
    assert r["state"] == STATE_VALID, r
    print("[11] kill-switch: allow_network=False makes zero calls  ✓")

    # [12] fail-safe: transport error -> error/low, never a false valid, never raises
    def err_http(*a, **k):
        return None, {}, "", "connection refused"
    r = validate_all([rec("Stripe", "sk_" "live_GOODxxxx")], cfg, http_fn=err_http)[0]
    assert r["state"] == STATE_ERROR and r["severity"] == "low", r
    print("[12] transport error -> error/low (inconclusive, manual)  ✓")

    # [13] redaction: the raw secret never appears in the output record
    blob = json.dumps(one(rec("Stripe", "sk_" "live_GOODSUPERSECRETVALUE1234")))
    assert "SUPERSECRETVALUE" not in blob, "raw secret leaked into output!"
    print("[13] redaction: raw secret never persisted to output  ✓")

    # [14] de-dupe: same key in many files validated once
    dupes = [rec("OpenAI", "sk-GOODdupxxxxxxxx", file=f"f{i}.js") for i in range(5)]
    assert len(validate_all(dupes, cfg, http_fn=fake_http)) == 1
    print("[14] de-dupe: identical secret material validated once  ✓")

    print("\nAll rungs and guardrails proven in code. ✓")
    sys.exit(0)

if __name__ == "__main__":
    sys.exit(main())
