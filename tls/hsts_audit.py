#!/usr/bin/env python3
"""Full HSTS audit with evidence — dashboard-visible findings.

Tests per hostname:
  1. HTTP -> HTTPS redirect behavior (follow chain)
  2. Strict-Transport-Security header presence on HTTPS
  3. HSTS directive quality: max-age (>= 1yr), includeSubDomains, preload
  4. HSTS-on-HTTP misconfiguration (per RFC 6797, browsers must ignore)
  5. Chrome preload list membership (first-visit protection)

Findings JSONL includes full evidence for the dashboard.
Also produces http_deduped.json = httpx feed WITHOUT http entries that
have confirmed HTTPS redirect (to prevent duplicate scanning downstream).
"""

import sys as _sys, os as _os
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)

import json
import os
import sys
import ssl
import socket
import argparse
import datetime
from urllib import request, error
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID, ExtensionOID
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
    _HAVE_CRYPTO = True
except Exception:  # pragma: no cover
    _HAVE_CRYPTO = False

TIMEOUT = 8
UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15"
MIN_MAX_AGE = 31536000  # 1 year (RFC-recommended minimum for real HSTS)

# Curated subset of Chrome's HSTS preload list top entries.
# For a full check, hit https://hstspreload.org/api/v2/status?domain=X.
PRELOAD_HOSTS_APEX = {
    "google.com", "facebook.com", "twitter.com", "github.com", "paypal.com",
    "gmail.com", "youtube.com", "amazon.com", "apple.com", "microsoft.com",
    "cloudflare.com", "wordpress.com", "wikipedia.org", "netflix.com",
}


def _fetch(url: str, follow: bool = False, timeout: int = TIMEOUT):
    """Return (status, headers_dict, final_url, redirect_chain, error)."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = request.Request(url, headers={"User-Agent": UA})
        chain = []

        class _NoRedirect(request.HTTPRedirectHandler):
            def http_error_301(self, req, fp, code, msg, headers):
                chain.append((code, headers.get("Location", "")))
                if not follow:
                    raise error.HTTPError(
                        req.full_url, code, msg, headers, fp)
                return request.HTTPRedirectHandler.http_error_301(
                    self, req, fp, code, msg, headers)
            http_error_302 = http_error_301
            http_error_303 = http_error_301
            http_error_307 = http_error_301
            http_error_308 = http_error_301

        opener = request.build_opener(
            request.HTTPSHandler(context=ctx), _NoRedirect())
        try:
            resp = opener.open(req, timeout=timeout)
            headers = {k.lower(): v for k, v in resp.headers.items()}
            return (resp.status, headers, resp.url, chain, None)
        except error.HTTPError as e:
            headers = {k.lower(): v for k, v in (e.headers or {}).items()}
            return (e.code, headers, e.url or url, chain, None)
    except Exception as e:
        return (0, {}, url, [], str(e))


def _parse_hsts(header_value: str) -> dict:
    """Parse Strict-Transport-Security header value."""
    out = {"max_age": None, "include_sub_domains": False, "preload": False,
           "raw": header_value}
    for part in header_value.split(";"):
        part = part.strip().lower()
        if part.startswith("max-age"):
            try:
                out["max_age"] = int(part.split("=", 1)[1].strip().strip('"'))
            except Exception:
                pass
        elif part == "includesubdomains":
            out["include_sub_domains"] = True
        elif part == "preload":
            out["preload"] = True
    return out


def _apex(host: str) -> str:
    parts = host.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host


# ---------------------------------------------------------------------------
# Certificate / TLS posture inspection (SSL-Labs-style, black-box)
# ---------------------------------------------------------------------------
_WEAK_SIGS = {"md5", "md2", "sha1"}


def _name_attr(name, oid):
    try:
        vals = name.get_attributes_for_oid(oid)
        return vals[0].value if vals else ""
    except Exception:
        return ""


def _host_matches(host: str, names) -> bool:
    """RFC-6125-ish match of host against cert DNS names (one-label wildcard)."""
    host = (host or "").lower().rstrip(".")
    for n in names or []:
        n = (n or "").lower().rstrip(".")
        if not n:
            continue
        if n == host:
            return True
        if n.startswith("*.") and host.count(".") == n.count("."):
            if host.endswith(n[1:]):
                return True
    return False


def _key_facts(cert):
    """(key_type, key_bits, weak_key) for the cert's public key."""
    try:
        pub = cert.public_key()
        if isinstance(pub, rsa.RSAPublicKey):
            return "RSA", pub.key_size, pub.key_size < 2048
        if isinstance(pub, ec.EllipticCurvePublicKey):
            bits = getattr(pub.curve, "key_size", 256)
            return "EC", bits, bits < 224
        if isinstance(pub, dsa.DSAPublicKey):
            return "DSA", pub.key_size, True  # DSA is effectively deprecated
        return pub.__class__.__name__.replace("PublicKey", ""), 0, False
    except Exception:
        return "unknown", 0, False


def _parse_cert(der: bytes, host: str) -> dict:
    """Parse a DER leaf cert into the posture fields we present."""
    cert = x509.load_der_x509_certificate(der)
    try:
        na = cert.not_valid_after_utc
        nb = cert.not_valid_before_utc
        now = datetime.datetime.now(datetime.timezone.utc)
    except AttributeError:  # older cryptography — naive UTC
        na = cert.not_valid_after
        nb = cert.not_valid_before
        now = datetime.datetime.utcnow()
    try:
        sans = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        ).value.get_values_for_type(x509.DNSName)
    except Exception:
        sans = []
    cn = _name_attr(cert.subject, NameOID.COMMON_NAME)
    match_names = list(sans) or ([cn] if cn else [])
    key_type, key_bits, weak_key = _key_facts(cert)
    try:
        sig = (cert.signature_hash_algorithm.name or "").lower()
    except Exception:
        sig = ""
    days = (na - now).days
    return {
        "subject_cn": cn,
        "sans": sans,
        "issuer_org": _name_attr(cert.issuer, NameOID.ORGANIZATION_NAME),
        "issuer_cn": _name_attr(cert.issuer, NameOID.COMMON_NAME),
        "not_before": nb.isoformat(),
        "not_after": na.isoformat(),
        "days_to_expiry": days,
        "expired": days < 0,
        "expiring_soon": 0 <= days <= 30,
        "self_signed": cert.issuer == cert.subject,
        "hostname_match": _host_matches(host, match_names),
        "key_type": key_type,
        "key_bits": key_bits,
        "weak_key": weak_key,
        "sig_algo": sig,
        "weak_sig": sig in _WEAK_SIGS,
        "serial": format(cert.serial_number, "x"),
    }


def _verifying_ctx():
    """Strict context backed by certifi's portable CA bundle (core.net), so a
    framework/macOS interpreter without a wired-up system root store doesn't
    report every public cert as untrusted."""
    try:
        from core.net import verified_ssl_context
        return verified_ssl_context()
    except Exception:
        try:
            import certifi
            return ssl.create_default_context(cafile=certifi.where())
        except Exception:
            return ssl.create_default_context()


def _trust_verdict(host: str, port: int, timeout: int):
    """(trusted|None, error): verified connect against the certifi root store."""
    try:
        ctx = _verifying_ctx()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return True, None
    except ssl.SSLCertVerificationError as e:
        return False, (getattr(e, "verify_message", None) or str(e))
    except ssl.SSLError as e:
        return False, str(e)
    except Exception as e:
        return None, str(e)  # network/connect error, not a trust verdict


def inspect_tls(host: str, timeout: int = TIMEOUT, port: int = 443) -> dict:
    """Capture leaf cert + negotiated protocol/cipher + trust verdict.

    Returns a posture dict (tls_ok=False when the TLS handshake can't complete).
    Works on bad certs (expired/self-signed/mismatch) by grabbing the leaf over
    an unverified handshake, then getting the trust verdict from a second,
    verifying connect.
    """
    if not _HAVE_CRYPTO:
        return {"host": host, "tls_ok": False, "error": "cryptography missing"}
    der = None
    proto = cipher = None
    try:
        uctx = ssl._create_unverified_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with uctx.wrap_socket(sock, server_hostname=host) as ss:
                der = ss.getpeercert(binary_form=True)
                proto = ss.version()
                cipher = ss.cipher()  # (name, tls_version, bits)
    except Exception as e:
        return {"host": host, "tls_ok": False, "error": str(e)}
    if not der:
        return {"host": host, "tls_ok": False, "error": "no peer certificate"}

    out = {"host": host, "tls_ok": True, "port": port}
    try:
        out.update(_parse_cert(der, host))
    except Exception as e:
        out["parse_error"] = str(e)
    cname = (cipher or [None])[0] if cipher else None
    out["protocol"] = proto or ""
    out["cipher"] = cname or ""
    out["cipher_bits"] = (cipher[2] if cipher and len(cipher) > 2 else None)
    # TLS 1.3 is always forward-secret (all its suites are ephemeral), but its
    # cipher names omit the key-exchange, so name-matching alone misses it.
    out["forward_secrecy"] = bool(
        (proto or "") == "TLSv1.3"
        or (cname and ("ECDHE" in cname or "DHE" in cname)))

    trusted, terr = _trust_verdict(host, port, timeout)
    out["trusted"] = trusted
    out["trust_error"] = terr
    return out


def _grade(p: dict):
    """SSL-Labs-inspired letter grade + the reasons that set it."""
    if not p.get("tls_ok"):
        return "—", ["TLS handshake failed"]
    proto = p.get("protocol") or ""
    if p.get("hostname_match") is False:
        return "M", ["certificate name does not match hostname"]
    if p.get("expired"):
        return "F", ["certificate expired %sd ago" % abs(p.get("days_to_expiry", 0))]
    if p.get("self_signed"):
        return "T", ["self-signed certificate (not trusted)"]
    if p.get("trusted") is False:
        return "T", ["chain not trusted: " + (p.get("trust_error") or "unknown issuer")]
    if p.get("weak_key"):
        return "F", ["weak key: %s %s-bit" % (p.get("key_type"), p.get("key_bits"))]
    if proto in ("SSLv2", "SSLv3"):
        return "F", ["obsolete protocol %s" % proto]
    caps = []
    if proto in ("TLSv1", "TLSv1.1"):
        caps.append("legacy protocol %s negotiated" % proto)
    if p.get("weak_sig"):
        caps.append("weak signature algorithm %s" % p.get("sig_algo"))
    if p.get("forward_secrecy") is False and p.get("cipher"):
        caps.append("no forward secrecy")
    if caps:
        return "B", caps
    extra = []
    if p.get("expiring_soon"):
        extra.append("certificate expires in %sd" % p.get("days_to_expiry"))
    if not p.get("hsts"):
        extra.append("no HSTS")
    if p.get("hsts") and p.get("hsts_long") and not p.get("expiring_soon"):
        return "A+", []
    return "A", extra


def _tls_findings(host: str, p: dict) -> list:
    """Cert/TLS findings for the shared findings stream (flow into the vuln list)."""
    out = []

    def add(t, sev, note, extra=None):
        ev = {"host": host, "note": note}
        if extra:
            ev.update(extra)
        out.append({"host": host, "type": t, "severity": sev, "evidence": ev})

    if not p.get("tls_ok"):
        return out
    if p.get("expired"):
        add("tls_certificate_expired", "high",
            "Certificate expired %sd ago (valid until %s)" % (
                abs(p.get("days_to_expiry", 0)), p.get("not_after")),
            {"not_after": p.get("not_after")})
    elif p.get("expiring_soon"):
        add("tls_certificate_expiring", "medium",
            "Certificate expires in %sd (%s)" % (
                p.get("days_to_expiry"), p.get("not_after")),
            {"not_after": p.get("not_after")})
    if p.get("hostname_match") is False:
        add("tls_hostname_mismatch", "high",
            "Certificate names (%s) do not cover %s" % (
                ", ".join((p.get("sans") or [])[:4]) or p.get("subject_cn"), host),
            {"sans": p.get("sans"), "subject_cn": p.get("subject_cn")})
    if p.get("self_signed"):
        add("tls_self_signed", "medium",
            "Certificate is self-signed (issuer == subject) — not trusted by clients")
    elif p.get("trusted") is False:
        add("tls_chain_untrusted", "medium",
            "Certificate chain not trusted: " + (p.get("trust_error") or "unknown issuer"))
    if p.get("weak_key"):
        add("tls_weak_key", "high",
            "Weak key: %s %s-bit (RSA must be >= 2048)" % (
                p.get("key_type"), p.get("key_bits")))
    if p.get("weak_sig"):
        add("tls_weak_signature", "medium",
            "Weak signature algorithm: %s (use SHA-256+)" % p.get("sig_algo"))
    if (p.get("protocol") or "") in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1"):
        add("tls_legacy_protocol", "low",
            "Negotiated legacy protocol %s (disable < TLS 1.2)" % p.get("protocol"))
    return out


def audit_host(host: str) -> list:
    """Run all HSTS checks against one hostname. Returns list of findings."""
    findings = []
    http_url = f"http://{host}/"
    https_url = f"https://{host}/"

    # Test 1: HTTP -> HTTPS redirect
    status, headers, final, chain, err = _fetch(
        http_url, follow=True, timeout=TIMEOUT)
    redirect_confirmed = (
        final.lower().startswith("https://") if final else False)
    if err:
        findings.append({
            "host": host, "type": "http_probe_failed", "severity": "info",
            "evidence": {"error": err, "url": http_url}})

    if status and not redirect_confirmed and status < 400:
        findings.append({
            "host": host, "type": "no_http_to_https_redirect",
            "severity": "high",
            "evidence": {
                "url": http_url, "status": status, "final_url": final,
                "redirect_chain": [
                    {"status": c[0], "location": c[1]} for c in chain]},
            "remediation": (
                "Configure server to 301 redirect HTTP to HTTPS. "
                "First-visit users are exposed to MITM otherwise.")})

    # Test 2/3: HTTPS STS header + directive quality
    status_s, headers_s, _, _, err_s = _fetch(
        https_url, follow=False, timeout=TIMEOUT)
    sts_header = headers_s.get("strict-transport-security", "")

    if not sts_header and status_s and status_s < 500:
        findings.append({
            "host": host, "type": "hsts_header_missing", "severity": "medium",
            "evidence": {
                "url": https_url, "status": status_s,
                "note": "No Strict-Transport-Security header on HTTPS response"},
            "remediation": (
                "Add: Strict-Transport-Security: "
                "max-age=31536000; includeSubDomains; preload")})
    elif sts_header:
        parsed = _parse_hsts(sts_header)
        max_age = parsed["max_age"] or 0

        if max_age < MIN_MAX_AGE:
            findings.append({
                "host": host, "type": "hsts_max_age_too_short",
                "severity": "medium",
                "evidence": {
                    "url": https_url, "sts_header": sts_header,
                    "max_age": max_age,
                    "recommended_min": MIN_MAX_AGE,
                    "days": max_age // 86400},
                "remediation": (
                    f"Set max-age >= {MIN_MAX_AGE} (1 year). "
                    "Short max-age = weak HSTS.")})

        if not parsed["include_sub_domains"]:
            findings.append({
                "host": host, "type": "hsts_missing_include_sub_domains",
                "severity": "low",
                "evidence": {
                    "url": https_url, "sts_header": sts_header},
                "remediation": (
                    "Add includeSubDomains directive so subdomains are also "
                    "HSTS-protected.")})

        if not parsed["preload"]:
            findings.append({
                "host": host, "type": "hsts_not_preload_eligible",
                "severity": "info",
                "evidence": {
                    "url": https_url, "sts_header": sts_header,
                    "note": ("Add 'preload' directive and submit at "
                             "hstspreload.org for first-visit protection.")}})

    # Test 4: HSTS-on-HTTP misconfiguration (RFC 6797: MUST NOT process)
    http_sts = headers.get("strict-transport-security", "")
    if http_sts:
        findings.append({
            "host": host, "type": "hsts_on_http_misconfig",
            "severity": "info",
            "evidence": {
                "url": http_url, "sts_header_on_http": http_sts,
                "note": ("Browsers must ignore STS on HTTP responses "
                         "(RFC 6797). Move it to the HTTPS response only.")}})

    # Test 5: Preload list membership hint
    if not _apex(host) in PRELOAD_HOSTS_APEX and sts_header:
        parsed = _parse_hsts(sts_header)
        if not parsed["preload"]:
            findings.append({
                "host": host, "type": "hsts_first_visit_mitm_window",
                "severity": "info",
                "evidence": {
                    "host": host,
                    "note": ("Domain not in Chrome HSTS preload list — first "
                             "request over HTTP is exploitable until browser "
                             "sees the STS header.")}})

    # --- Certificate / TLS posture (SSL-Labs-style, additive) --------------
    posture = inspect_tls(host, timeout=TIMEOUT)
    if posture.get("tls_ok"):
        hsts_parsed = _parse_hsts(sts_header) if sts_header else {}
        posture["hsts"] = bool(sts_header)
        posture["hsts_max_age"] = hsts_parsed.get("max_age")
        posture["hsts_long"] = bool((hsts_parsed.get("max_age") or 0) >= MIN_MAX_AGE)
        posture["hsts_preload"] = bool(hsts_parsed.get("preload"))
        posture["redirect_to_https"] = redirect_confirmed
        grade, reasons = _grade(posture)
        posture["grade"] = grade
        posture["grade_reasons"] = reasons
        findings.extend(_tls_findings(host, posture))
    posture["type"] = "_tls_posture"
    findings.append(posture)

    # Meta: attach redirect confirmation flag for the pipeline dedup
    findings.append({
        "host": host, "type": "_meta_redirect_status",
        "redirect_to_https": redirect_confirmed,
    })

    return findings


def audit(http_confirmed_file: str, output_findings: str,
          output_deduped: str, workers: int = 10) -> dict:
    """Run HSTS audit on every unique host in the httpx output."""
    hosts = set()
    http_entries = []
    if not os.path.exists(http_confirmed_file):
        return {"error": "http_confirmed.json missing"}

    with open(http_confirmed_file, "r", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except Exception:
                continue
            host = r.get("host") or r.get("input")
            if host:
                hosts.add(host)
            http_entries.append(r)

    hosts = sorted(hosts)
    redirect_map = {}
    all_findings = []
    posture_records = []
    os.makedirs(os.path.dirname(output_findings) or ".", exist_ok=True)

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(audit_host, h): h for h in hosts}
        for fut in as_completed(futs):
            host = futs[fut]
            try:
                findings = fut.result() or []
            except Exception:
                findings = []
            for f in findings:
                t = f.get("type")
                if t == "_meta_redirect_status":
                    redirect_map[host] = f.get("redirect_to_https", False)
                elif t == "_tls_posture":
                    posture_records.append(f)
                else:
                    all_findings.append(f)

    with open(output_findings, "w") as out:
        for f in all_findings:
            out.write(json.dumps(f) + "\n")

    # Per-host TLS/certificate posture (one row per host) — the SSL-Labs-style
    # view. Written beside the findings so the dashboard can grade each host.
    posture_path = os.path.join(
        os.path.dirname(output_findings) or ".", "tls_posture.jsonl")
    grade_counts = {}
    with open(posture_path, "w") as out:
        for p in sorted(posture_records, key=lambda r: r.get("host", "")):
            out.write(json.dumps(p) + "\n")
            g = p.get("grade", "—")
            grade_counts[g] = grade_counts.get(g, 0) + 1

    # Dedup HTTP entries where HTTPS redirect is confirmed
    dropped = 0
    with open(output_deduped, "w") as out:
        for e in http_entries:
            host = e.get("host") or e.get("input") or ""
            scheme = (e.get("scheme") or "").lower()
            url = (e.get("url") or "").lower()
            is_http = (scheme == "http") or url.startswith("http://")
            if is_http and redirect_map.get(host):
                dropped += 1
                continue
            out.write(json.dumps(e) + "\n")

    severity_counts = {}
    for f in all_findings:
        s = f.get("severity", "info")
        severity_counts[s] = severity_counts.get(s, 0) + 1

    return {
        "hosts_tested": len(hosts),
        "findings": len(all_findings),
        "by_severity": severity_counts,
        "http_entries_dropped": dropped,
        "certs_graded": len(posture_records),
        "grade_counts": grade_counts,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--http-confirmed", required=True,
                    help="Path to httpx http_confirmed.json (input)")
    ap.add_argument("--findings", required=True,
                    help="Path to hsts_findings.jsonl (output)")
    ap.add_argument("--deduped", required=True,
                    help="Path to http_confirmed_deduped.json (output)")
    ap.add_argument("--workers", type=int, default=10)
    args = ap.parse_args()

    summary = audit(args.http_confirmed, args.findings, args.deduped,
                    args.workers)
    print(json.dumps(summary), file=sys.stderr)


if __name__ == "__main__":
    main()
