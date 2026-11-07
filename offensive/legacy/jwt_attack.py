#!/usr/bin/env python3
"""
ARISE — Comprehensive JWT attack surface analyzer (Phase 6.3).

Operates OFFLINE on JWTs discovered elsewhere in the scan (responses, JS, headers)
plus any passed on the CLI. Non-destructive: it never sends a forged token to the
target — it reports what an attacker COULD forge, with the concrete reason.

Checks:
  1. alg=none accepted-by-design (unsigned-token forgery risk)
  2. Weak HMAC secret (dictionary crack, offline)  -> full account takeover
  3. RS256->HS256 algorithm confusion candidate (asymmetric alg + no kid pinning)
  4. kid header injection surface (path/SQL-looking kid)
  5. Sensitive/privilege claims (role/admin/is_admin) an attacker would target
  6. Missing/!expired exp (replayable tokens)

Output: JSONL findings to --out (one object per finding).
"""

import sys as _sys, os as _os
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)

import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import sys
import time
from pathlib import Path

JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]*")

DEFAULT_SECRETS = [
    "secret", "secret123", "password", "123456", "changeme", "your-256-bit-secret",
    "jwt_secret", "jwtsecret", "supersecret", "mysecretkey", "key", "test", "qwerty",
    "admin", "default", "s3cr3t", "abc123", "letmein", "", "null", "development",
    "production", "staging", "secretkey", "secret_key", "my-secret", "topsecret",
    "password123", "passw0rd", "root", "guest", "demo", "signingkey", "signing_key",
    "hmac", "jwt", "token", "app_secret", "api_secret", "private_key", "keyboardcat",
    "changethis", "django-insecure", "flask", "express", "hello", "helloworld",
]
_SENSITIVE_CLAIMS = ("role", "roles", "admin", "is_admin", "isadmin", "scope",
                     "scopes", "permissions", "perms", "group", "groups", "priv",
                     "privilege", "authority", "authorities", "acl", "tenant")


def _b64url(seg):
    seg += "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg.encode())


def _decode(token):
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(_b64url(parts[0]))
        payload = json.loads(_b64url(parts[1]))
        sig = _b64url(parts[2]) if parts[2] else b""
    except Exception:
        return None
    return header, payload, sig, parts


def _crack_hmac(token, secrets):
    d = _decode(token)
    if not d:
        return None
    header, _, _, parts = d
    alg = (header.get("alg") or "").upper()
    fn = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}.get(alg)
    if not fn:
        return None
    signing_input = (parts[0] + "." + parts[1]).encode()
    want = _b64url(parts[2])
    for sec in secrets:
        mac = hmac.new(sec.encode(), signing_input, fn).digest()
        if hmac.compare_digest(mac, want):
            return sec
    return None


def analyze(token, secrets, source=""):
    findings = []
    d = _decode(token)
    if not d:
        return findings
    header, payload, sig, _ = d
    alg = (header.get("alg") or "").upper()
    tok_short = token[:24] + "…"

    def emit(sev, title, evidence, remediation):
        findings.append({
            "module": "jwt_attack", "severity": sev, "confidence": "confirmed",
            "title": title, "token": tok_short, "alg": alg, "source": source,
            "evidence": evidence, "remediation": remediation,
        })

    if alg in ("NONE", ""):
        emit("critical", "JWT alg=none — unsigned tokens accepted",
             f"header alg is '{header.get('alg')}'; tokens require no signature",
             "Reject alg=none; pin an allowlist of expected algorithms server-side.")

    if alg.startswith("HS"):
        sec = _crack_hmac(token, secrets)
        if sec is not None:
            emit("critical", "JWT signed with a weak/guessable HMAC secret",
                 f"signature verifies with secret '{sec or '(empty)'}' — full token forgery",
                 "Rotate to a long random secret (>=32 bytes) stored in a secret manager.")

    if alg.startswith("RS") or alg.startswith("ES") or alg.startswith("PS"):
        if not header.get("kid"):
            emit("high", "RS256→HS256 algorithm-confusion candidate",
                 "asymmetric alg with no kid pinning — if the server also accepts HS* and "
                 "uses the public key as an HMAC secret, tokens can be forged",
                 "Pin the exact algorithm; never let alg switch between asymmetric and HMAC.")

    kid = header.get("kid")
    if isinstance(kid, str) and re.search(r"[/\\]|\.\.|'|\"|;|\bunion\b|\bselect\b", kid, re.I):
        emit("high", "JWT kid header injection surface",
             f"kid='{kid}' looks path/SQL-derived — kid is often used to load a key by "
             "filename or DB lookup, enabling traversal/SQLi to control the signing key",
             "Treat kid as an opaque key id; look it up against a fixed allowlist.")

    present = [c for c in _SENSITIVE_CLAIMS if c in {k.lower() for k in payload}]
    if present:
        emit("medium", "JWT carries privilege claims an attacker would forge",
             f"claims present: {present} — combined with any forgery above this is priv-esc",
             "Do not trust client-held role/privilege claims; re-check authz server-side.")

    exp = payload.get("exp")
    if exp is None:
        emit("medium", "JWT has no expiry (exp) — indefinitely replayable",
             "payload has no 'exp' claim", "Set a short exp and validate it server-side.")
    elif isinstance(exp, (int, float)) and exp < time.time():
        emit("low", "JWT is expired (still worth testing replay acceptance)",
             f"exp={int(exp)} is in the past", "Ensure exp is enforced, not just present.")
    return findings


def _harvest_tokens(scan_dir: Path):
    tokens = set()
    if not scan_dir or not scan_dir.is_dir():
        return tokens
    exts = (".txt", ".json", ".jsonl", ".log", ".js", ".har")
    for p in scan_dir.rglob("*"):
        if not p.is_file() or p.suffix.lower() not in exts:
            continue
        try:
            if p.stat().st_size > 8_000_000:
                continue
            for m in JWT_RE.findall(p.read_text(errors="ignore")):
                tokens.add(m)
        except Exception:
            continue
    return tokens


def _load_secret_wordlist(path):
    secs = list(DEFAULT_SECRETS)
    if path and os.path.isfile(path):
        try:
            with open(path, errors="ignore") as f:
                secs.extend(l.strip() for l in f if l.strip())
        except Exception:
            pass
    # de-dupe, keep order
    seen, out = set(), []
    for s in secs:
        if s not in seen:
            seen.add(s)
            out.append(s)
    return out


def main():
    ap = argparse.ArgumentParser(description="ARISE JWT attack surface analyzer (offline)")
    ap.add_argument("scan_dir", nargs="?", help="scan output dir to harvest JWTs from")
    ap.add_argument("--token", action="append", default=[], help="explicit JWT(s) to analyze")
    ap.add_argument("--secrets", help="extra HMAC secret wordlist (one per line)")
    ap.add_argument("--out", help="JSONL output file")
    args = ap.parse_args()

    secrets = _load_secret_wordlist(args.secrets)
    tokens = set(args.token)
    if args.scan_dir:
        tokens |= _harvest_tokens(Path(args.scan_dir))

    findings = []
    for t in sorted(tokens):
        findings.extend(analyze(t, secrets, source="scan"))

    out = args.out or (os.path.join(args.scan_dir, "24_advanced_attacks", "jwt_findings.jsonl")
                       if args.scan_dir else "jwt_findings.jsonl")
    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
    with open(out, "w") as f:
        for row in findings:
            f.write(json.dumps(row) + "\n")
    print(f"jwt_attack: {len(tokens)} token(s), {len(findings)} finding(s) -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
