#!/usr/bin/env python3
"""
ARISE Response Analysis — Hacker-POV Oracles
============================================
Input-function discovery (Module 20.2) tells us WHERE to attack (login, search,
upload, object-id, ...). This module decides WHETHER a response actually PROVES a
vulnerability — the confirmation oracle. A finding is emitted ONLY when the
response is self-evidence of the bug (payload reflected unencoded, DB error,
true/false or self/other differential, timing delay, OOB metadata, leaked
secret). "The parameter exists" or "the endpoint is an API" is NEVER a finding.
That response-gate is what turns input detection into low-false-positive output.

Each oracle returns Finding(fired, confidence, evidence) or None. Oracles come in
three shapes:
  * single       — one response
  * differential — a pair (true/false, valid/invalid, self/other)
  * timing       — response with elapsed_ms

Self-test: `python3 response_analysis.py --selftest` loads synthetic_data.json
and asserts every oracle FIRES on the vulnerable side and STAYS SILENT on the
safe side (100% true-positive, 0% false-positive).
"""

from __future__ import annotations

import sys as _sys, os as _os
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)


import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional


@dataclass
class Finding:
    oracle: str
    confidence: str       # high | medium
    evidence: str


# ---------------------------------------------------------------------------
# Signal libraries
# ---------------------------------------------------------------------------
_SQL_ERROR_RE = re.compile(
    r"(SQL syntax|SQLSTATE|mysql_fetch|ORA-\d{5}|ODBC SQL|PostgreSQL.*ERROR"
    r"|SQLite/JDBCDriver|Unclosed quotation mark|quoted string not properly"
    r"|near \".*\": syntax error|psql:|pg_query\(\)|Warning: mysqli)", re.I)

_STACK_TRACE_RE = re.compile(
    r"(Traceback \(most recent call last\)|at [\w.$]+\([\w.]+\.java:\d+\)"
    r"|System\.\w+Exception|\.php on line \d+|goroutine \d+ \[|stack trace:"
    r"|File \".*\", line \d+, in )", re.I)

# Cloud/instance metadata & credential markers (SSRF confirmation)
_METADATA_RE = re.compile(
    r"(AccessKeyId|SecretAccessKey|ami-[0-9a-f]+|iam/security-credentials"
    r"|computeMetadata|instance-identity|169\.254\.169\.254)", re.I)

# Secret leaked directly in a response body (OTP, tokens marked debug/test)
_OTP_LEAK_RE = re.compile(r"\"?(?:debug_otp|test_otp|otp|code|pin)\"?\s*[:=]\s*\"?(\d{4,8})\"?", re.I)

_HTML_CT_RE = re.compile(r"text/html", re.I)


def _b(resp: Dict) -> str:
    return resp.get("body", "") or ""


def _h(resp: Dict, k: str) -> str:
    hs = resp.get("headers", {}) or {}
    for kk, vv in hs.items():
        if kk.lower() == k.lower():
            return vv or ""
    return ""


def _host(url: str) -> str:
    m = re.match(r"https?://([^/:]+)", url or "")
    return m.group(1).lower() if m else ""


def _html_entity_encoded(payload: str, body: str) -> bool:
    """True if the payload appears only in entity-encoded form (safe)."""
    enc = (payload.replace("&", "&amp;").replace("<", "&lt;")
           .replace(">", "&gt;").replace('"', "&quot;"))
    return enc in body and payload not in body


# ---------------------------------------------------------------------------
# Single-response oracles
# ---------------------------------------------------------------------------
def reflected_xss(req: Dict, resp: Dict) -> Optional[Finding]:
    payload = req.get("payload", "")
    body = _b(resp)
    # must be rendered as HTML, and the raw (un-encoded) payload must appear
    if not _HTML_CT_RE.search(_h(resp, "content-type")):
        return None
    if not payload or "<" not in payload:
        return None
    if payload in body and not _html_entity_encoded(payload, body):
        return Finding("reflected_xss", "high",
                       f"payload reflected unencoded in text/html: {payload}")
    return None


def sql_error(req: Dict, resp: Dict) -> Optional[Finding]:
    m = _SQL_ERROR_RE.search(_b(resp))
    if m:
        return Finding("sql_error", "high", f"database error disclosed: '{m.group(0)[:60]}'")
    return None


def ssti(req: Dict, resp: Dict) -> Optional[Finding]:
    payload = req.get("payload", "")
    body = _b(resp)
    # arithmetic marker {{7*7}} / ${7*7} evaluated to 49 (and the literal is gone)
    if payload and payload in body:
        return None  # literal echoed = not evaluated = safe
    if re.search(r"\{\{\s*7\s*\*\s*7\s*\}\}|\$\{\s*7\s*\*\s*7\s*\}", payload) and \
            re.search(r"(^|[^0-9])49([^0-9]|$)", body):
        return Finding("ssti", "high", "template expression 7*7 evaluated to 49 (SSTI)")
    return None


def auth_state_change(req: Dict, resp: Dict) -> Optional[Finding]:
    # an injection payload that yields an authenticated session/token = bypass
    body = _b(resp)
    got_cookie = bool(_h(resp, "set-cookie"))
    got_token = bool(re.search(r"\"(?:token|access_token|jwt)\"\s*:", body)) or "eyJ" in body
    if resp.get("status") in (200, 302) and (got_cookie or got_token):
        return Finding("auth_state_change", "high",
                       "injection payload produced an authenticated session/token")
    return None


def open_redirect(req: Dict, resp: Dict) -> Optional[Finding]:
    if resp.get("status") not in (301, 302, 303, 307, 308):
        return None
    loc = _h(resp, "location")
    atk = (req.get("attacker_host") or "").lower()
    if atk and _host(loc) == atk:
        return Finding("open_redirect", "high", f"Location redirects to attacker host: {loc}")
    return None


def error_disclosure(req: Dict, resp: Dict) -> Optional[Finding]:
    m = _STACK_TRACE_RE.search(_b(resp))
    if m:
        return Finding("error_disclosure", "medium",
                       f"stack trace / internal path disclosed: '{m.group(0)[:50]}'")
    return None


def mass_assignment(req: Dict, resp: Dict) -> Optional[Finding]:
    injected = req.get("injected", {}) or {}
    body = _b(resp)
    try:
        j = json.loads(body)
    except Exception:
        j = {}
    for k, v in injected.items():
        if str(j.get(k)).lower() == str(v).lower() and str(v).lower() in ("admin", "true"):
            return Finding("mass_assignment", "high",
                           f"privileged field '{k}={v}' accepted from client input")
    return None


def otp_leak(req: Dict, resp: Dict) -> Optional[Finding]:
    m = _OTP_LEAK_RE.search(_b(resp))
    if m:
        return Finding("otp_leak", "high", f"one-time secret leaked in response: {m.group(0)[:40]}")
    return None


def ssrf_metadata(req: Dict, resp: Dict) -> Optional[Finding]:
    m = _METADATA_RE.search(_b(resp))
    if m and resp.get("status", 0) < 400:
        return Finding("ssrf_metadata", "high",
                       f"internal metadata/credentials returned: '{m.group(0)[:40]}' (SSRF)")
    return None


# ---------------------------------------------------------------------------
# Differential oracles (a pair of responses)
# ---------------------------------------------------------------------------
def _distinguishable(a: Dict, b: Dict) -> Optional[str]:
    if a.get("status") != b.get("status"):
        return f"status {a.get('status')} vs {b.get('status')}"
    la, lb = len(_b(a)), len(_b(b))
    if abs(la - lb) > max(16, 0.25 * max(la, lb, 1)):
        return f"body length {la} vs {lb}"
    # distinct human message
    if _b(a).strip() != _b(b).strip() and (la or lb):
        # only count if the wording actually differs semantically (not identical)
        return "response wording differs"
    return None


def _strip_payloads(resp: Dict, payloads: List[str]) -> Dict:
    """Remove echoed payload strings so a differential reflects BEHAVIOUR, not the
    reflected input itself (else any reflecting endpoint looks 'boolean')."""
    body = _b(resp)
    for p in payloads:
        if p:
            body = body.replace(p, "")
    out = dict(resp)
    out["body"] = body
    return out


def sql_boolean(req: Dict, pair: Dict) -> Optional[Finding]:
    # Neutralise reflected payloads first: /search?q=1 AND 1=1 echoing the query
    # differs from ...1=2 only because the input differs, not the DB — that is
    # the classic boolean-SQLi false positive.
    pays = [req.get("payload_true", ""), req.get("payload_false", "")]
    a = _strip_payloads(pair.get("a", {}), pays)
    b = _strip_payloads(pair.get("b", {}), pays)
    diff = _distinguishable(a, b)
    if diff:
        return Finding("sql_boolean", "high",
                       f"true vs false condition responses differ ({diff}) — boolean SQLi")
    return None


def user_enum(req: Dict, pair: Dict) -> Optional[Finding]:
    diff = _distinguishable(pair.get("valid", {}), pair.get("invalid", {}))
    if diff:
        return Finding("user_enum", "medium",
                       f"valid vs invalid account responses differ ({diff}) — username enumeration")
    return None


def bola_idor(req: Dict, pair: Dict) -> Optional[Finding]:
    other = pair.get("other", {})
    own = pair.get("own", {})
    if other.get("status") == 200 and own.get("status") == 200 and \
            _b(other).strip() != _b(own).strip():
        # confirmed only if we actually got another owner's object back
        if re.search(r"\"owner\"\s*:\s*\"(?!"+re.escape(_owner(own))+r")", _b(other)) or \
                _owner(other) and _owner(other) != _owner(own):
            return Finding("bola_idor", "high",
                           f"object of another owner ({_owner(other)}) returned to {req.get('identity')}")
    return None


def _owner(resp: Dict) -> str:
    m = re.search(r"\"owner\"\s*:\s*\"([^\"]+)\"", _b(resp))
    return m.group(1) if m else ""


# ---------------------------------------------------------------------------
# Timing oracle
# ---------------------------------------------------------------------------
def sql_time(req: Dict, resp: Dict, baseline_ms: int = 800) -> Optional[Finding]:
    payload = (req.get("payload") or "").upper()
    if not re.search(r"SLEEP|WAITFOR|PG_SLEEP|BENCHMARK", payload):
        return None
    if resp.get("elapsed_ms", 0) >= 4000:
        return Finding("sql_time", "high",
                       f"time-based delay observed ({resp['elapsed_ms']}ms) with SLEEP payload")
    return None


_CMD_OUTPUT_RE = re.compile(r"uid=\d+\([a-z_][a-z0-9_.-]*\)\s+gid=\d+", re.I)


def cmd_injection(req: Dict, resp: Dict) -> Optional[Finding]:
    """OS command injection — confirmed one of two non-destructive ways:
    the `id` command's output (uid=…gid=…) is reflected in the body, or a
    sleep/ping/timeout payload delayed the response (blind, timing-based)."""
    body = resp.get("body", "") or ""
    if _CMD_OUTPUT_RE.search(body):
        return Finding("cmd_injection", "critical",
                       "OS command output (uid=…gid=…) reflected — command injection confirmed")
    payload = req.get("payload") or ""
    if re.search(r"\bsleep\s*\d|timeout\s*/t|ping\s+-[nc]\s*\d", payload, re.I) \
            and resp.get("elapsed_ms", 0) >= 4000:
        return Finding("cmd_injection", "critical",
                       f"time-based command delay observed ({resp['elapsed_ms']}ms) with a sleep payload")
    return None


ORACLES = {
    "reflected_xss": ("single", reflected_xss),
    "sql_error": ("single", sql_error),
    "ssti": ("single", ssti),
    "auth_state_change": ("single", auth_state_change),
    "open_redirect": ("single", open_redirect),
    "error_disclosure": ("single", error_disclosure),
    "mass_assignment": ("single", mass_assignment),
    "otp_leak": ("single", otp_leak),
    "ssrf_metadata": ("single", ssrf_metadata),
    "sql_boolean": ("differential", sql_boolean),
    "user_enum": ("differential", user_enum),
    "bola_idor": ("differential", bola_idor),
    "upload_unrestricted": ("upload", None),
    "sql_time": ("timing", sql_time),
    "cmd_injection": ("timing", cmd_injection),
}


def upload_unrestricted(req: Dict, side: Dict) -> Optional[Finding]:
    """The uploaded payload is retrievable AND served as executable/raw."""
    fetch = side.get("fetch", {})
    payload = req.get("payload", "")
    marker = re.sub(r"[^A-Za-z0-9_]", "", payload)[-12:] if payload else ""
    body = _b(fetch)
    served_html = _HTML_CT_RE.search(_h(fetch, "content-type"))
    if fetch.get("status") == 200 and served_html and (
            "PWNED" in body or (marker and marker in re.sub(r"[^A-Za-z0-9_]", "", body))):
        return Finding("upload_unrestricted", "high",
                       "uploaded file retrievable and served as HTML/script (RCE-class)")
    return None


ORACLES["upload_unrestricted"] = ("upload", upload_unrestricted)


def run_oracle(name: str, req: Dict, side) -> Optional[Finding]:
    shape, fn = ORACLES[name]
    return fn(req, side)


# ---------------------------------------------------------------------------
# Self-test over the synthetic corpus
# ---------------------------------------------------------------------------
def selftest(data_path: Path) -> int:
    data = json.loads(data_path.read_text())
    cases = data.get("cases", [])
    tp = fp = fn_miss = 0
    print(f"{'ORACLE':20} {'ATTACK':20} {'VULN→fire':10} {'SAFE→silent':12} RESULT")
    print("-" * 82)
    for c in cases:
        oracle = c["oracle"]
        req = c.get("request", {})
        vuln = run_oracle(oracle, req, c["vulnerable"])
        safe = run_oracle(oracle, req, c["safe"])
        vuln_ok = vuln is not None
        safe_ok = safe is None
        if vuln_ok:
            tp += 1
        else:
            fn_miss += 1
        if not safe_ok:
            fp += 1
        verdict = "PASS" if (vuln_ok and safe_ok) else "FAIL"
        print(f"{oracle:20} {c['attack']:20} {'yes' if vuln_ok else 'NO ':10} "
              f"{'yes' if safe_ok else 'NO ':12} {verdict}")
    print("-" * 82)
    print(f"true positives (fired on vuln): {tp}/{len(cases)} | "
          f"false positives (fired on safe): {fp} | missed: {fn_miss}")
    ok = fp == 0 and fn_miss == 0
    print("SELFTEST:", "PASS — 100% TP, 0% FP" if ok else "FAIL")
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(description="ARISE response-analysis oracles")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--data", default=str(Path(__file__).parent / "synthetic_data.json"))
    args = ap.parse_args()
    if args.selftest:
        return selftest(Path(args.data))
    ap.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
