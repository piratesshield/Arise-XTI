#!/usr/bin/env python3
"""
ARISE shared session/cookie jar.

Without this, every scanner (dirsearch, nuclei, katana, gospider,
api_intelligence_engine/apisec) starts a cold, unauthenticated session — only
whichever module happens to expose its own --cookie/--auth flag ever sees a
user-supplied token, so authenticated-only surface is invisible to the rest
of the pipeline.

One jar, one on-disk format (Netscape cookie-jar — the format curl -b/-c and
Python's stdlib http.cookiejar.MozillaCookieJar both read/write natively, so
no bespoke JSON schema is invented here), consumed two ways:
  - `header`  — flatten to "name=value; name2=value2" for scanners whose only
    cookie support is a raw -H "Cookie: ..." (nuclei/katana/httpx) or
    --cookie "..." (gospider/dirsearch/apisec) flag.
  - `seed`    — parse the same "name=value; ..." string this codebase's other
    auth conventions already use (auth_contexts.json, protocol_exec.py) into
    the jar, so a user-supplied cookie is available to every scanner from the
    start of the scan, not just the one module that received it directly.

Domain scoping: matches a cookie's domain against the scan's target if
--domain is given (see _domain_matches) — the reason a Netscape jar was
chosen over a flat string file: it's the one format that carries a domain per
cookie, so a cookie captured on admin.target.com doesn't leak into a header
built for api.target.com if it's not a .target.com-scoped cookie.

Stdlib only. Importable, or usable as a CLI (see main()).
"""

from __future__ import annotations

import sys as _sys
import os as _os
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)

import argparse
import http.cookiejar as cookiejar
import time
from typing import Dict, Iterable, List, Optional


def _load_jar(path: str) -> cookiejar.MozillaCookieJar:
    jar = cookiejar.MozillaCookieJar(path)
    if _os.path.exists(path):
        try:
            jar.load(ignore_discard=True, ignore_expires=True)
        except Exception:
            pass  # corrupt/partial jar -> treat as empty rather than fail the scan
    return jar


def _domain_matches(cookie_domain: str, target_domain: str) -> bool:
    cd = (cookie_domain or "").lstrip(".").lower()
    td = (target_domain or "").lstrip(".").lower()
    if not cd or not td:
        return False
    return cd == td or cd.endswith("." + td) or td.endswith("." + cd)


def load_header_string(jar_path: str, target_domain: Optional[str] = None) -> str:
    """Return 'name=value; name2=value2' for cookies in the jar, optionally
    scoped to target_domain (+ its subdomains/parent). Empty string if the
    jar is missing, empty, or nothing matches — callers should treat that as
    "omit the cookie flag", not an error."""
    if not _os.path.exists(jar_path):
        return ""
    jar = _load_jar(jar_path)
    parts = []
    for c in jar:
        if target_domain and not _domain_matches(c.domain, target_domain):
            continue
        parts.append(f"{c.name}={c.value}")
    return "; ".join(parts)


def write_cookies(jar_path: str, cookies: Iterable[Dict], default_domain: str) -> int:
    """Merge cookies into the jar. Each item is a dict shaped like Playwright's
    BrowserContext.cookies() entries: name, value, domain, path, expires,
    secure, httpOnly (all but name/value optional). Returns count written."""
    jar = _load_jar(jar_path)
    _os.makedirs(_os.path.dirname(_os.path.abspath(jar_path)) or ".", exist_ok=True)
    now = int(time.time())
    n = 0
    for c in cookies:
        name = c.get("name")
        value = c.get("value")
        if not name or value is None:
            continue
        domain = c.get("domain") or default_domain
        path = c.get("path") or "/"
        expires = c.get("expires")
        # Playwright uses -1 for session cookies; keep those for 24h so a
        # cookie set mid-crawl still has real value to the next module
        # rather than expiring the instant the browser context closes.
        if expires is None or expires < 0:
            expires = now + 86400
        ck = cookiejar.Cookie(
            version=0, name=str(name), value=str(value),
            port=None, port_specified=False,
            domain=domain, domain_specified=True,
            domain_initial_dot=domain.startswith("."),
            path=path, path_specified=True,
            secure=bool(c.get("secure")), expires=int(expires), discard=False,
            comment=None, comment_url=None, rest={}, rfc2109=False,
        )
        jar.set_cookie(ck)
        n += 1
    if n:
        jar.save(ignore_discard=True, ignore_expires=True)
    return n


def add_raw(jar_path: str, raw_cookie_string: str, domain: str) -> int:
    """Parse this codebase's existing 'name=value; name2=value2' convention
    (auth_contexts.json / protocol_exec.py's format) into the jar."""
    cookies: List[Dict] = []
    for part in (raw_cookie_string or "").split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        name, value = part.split("=", 1)
        cookies.append({"name": name.strip(), "value": value.strip()})
    return write_cookies(jar_path, cookies, domain)


def main() -> int:
    ap = argparse.ArgumentParser(description="ARISE shared session/cookie jar")
    ap.add_argument("--jar", required=True, help="Path to the Netscape-format cookie jar file")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_header = sub.add_parser("header", help="Print 'name=value; ...' for scanner -H/--cookie flags")
    p_header.add_argument("--domain", default=None, help="Scope to this domain (+ subdomains)")

    p_seed = sub.add_parser("seed", help="Seed the jar from a raw 'name=value; ...' cookie string")
    p_seed.add_argument("--cookie", required=True)
    p_seed.add_argument("--domain", required=True)

    args = ap.parse_args()
    if args.cmd == "header":
        print(load_header_string(args.jar, args.domain))
    elif args.cmd == "seed":
        n = add_raw(args.jar, args.cookie, args.domain)
        print(f"[session_jar] seeded {n} cookie(s) into {args.jar}", file=_sys.stderr)
    return 0


def _selftest() -> int:
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        jar_path = _os.path.join(td, "session.jar")

        # seed from the codebase's existing raw-string convention
        n = add_raw(jar_path, "sessionid=abc123; csrftoken=xyz", "target.com")
        assert n == 2, n
        hdr = load_header_string(jar_path, "target.com")
        assert "sessionid=abc123" in hdr and "csrftoken=xyz" in hdr, hdr

        # write_cookies (Playwright ctx.cookies() shape), including a
        # different-domain cookie that must NOT leak into a target.com header
        write_cookies(jar_path, [
            {"name": "auth", "value": "tok1", "domain": ".target.com", "path": "/"},
            {"name": "sub_auth", "value": "tok2", "domain": "admin.target.com", "path": "/"},
            {"name": "other", "value": "tok3", "domain": "unrelated-cdn.example", "path": "/"},
        ], "target.com")
        hdr2 = load_header_string(jar_path, "target.com")
        assert "auth=tok1" in hdr2, hdr2
        assert "sub_auth=tok2" in hdr2, hdr2       # subdomain of target.com -> in scope
        assert "other=tok3" not in hdr2, hdr2      # unrelated domain -> must NOT leak

        # unscoped read returns everything, including the unrelated domain
        hdr_all = load_header_string(jar_path, None)
        assert "other=tok3" in hdr_all, hdr_all

        # missing jar -> empty string, not an exception
        assert load_header_string(_os.path.join(td, "nope.jar"), "target.com") == ""

    print("[session_jar] self-test OK — seed/header round-trip + domain scoping")
    return 0


if __name__ == "__main__":
    if len(_sys.argv) > 1 and _sys.argv[1] == "--selftest":
        _sys.exit(_selftest())
    _sys.exit(main())
