#!/usr/bin/env python3
"""
ARISE — Race condition / TOCTOU scanner (Phase 6.1).

Fires N identical requests simultaneously at sensitive single-use flows (coupon,
redeem, vote, transfer, register, apply, claim) and flags when more than one is
accepted — the signature of a missing lock / race window.

Safety: only endpoints whose path matches a sensitive-single-use keyword are
tested; GET by default; concurrency and per-target attempts are capped. This DOES
send parallel requests, so it is opt-in and scoped. Output: JSONL findings.
"""

import sys as _sys, os as _os
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)

import argparse
import concurrent.futures
import json
import os
import re
import sys

try:
    import requests
    requests.packages.urllib3.disable_warnings()  # type: ignore
except Exception:
    requests = None

SENSITIVE_RE = re.compile(
    r"/(?:coupon|promo|voucher|redeem|reward|claim|vote|like|follow|transfer|"
    r"withdraw|topup|recharge|apply|register|signup|invite|referral|gift|"
    r"checkout|purchase|order|book|reserve|cancel)\b", re.I)


def _one(method, url, body, timeout=12):
    if not requests:
        return None
    try:
        if body:
            r = requests.request(method, url, data=body, timeout=timeout,
                                 verify=False, allow_redirects=False)
        else:
            r = requests.request(method, url, timeout=timeout, verify=False,
                                 allow_redirects=False)
        return r.status_code
    except Exception:
        return None


def test_race(url, method="GET", body=None, concurrent=20):
    if not requests:
        return None
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrent) as pool:
        futs = [pool.submit(_one, method, url, body) for _ in range(concurrent)]
        codes = [f.result() for f in futs]
    ok = [c for c in codes if c in (200, 201, 202)]
    # A race is interesting only if MULTIPLE parallel attempts succeeded AND the
    # endpoint is a single-use-looking flow. One success is just normal.
    if len(ok) > 1:
        return {
            "module": "race_condition", "severity": "high", "confidence": "reported",
            "title": "Possible race condition on a single-use flow",
            "url": url, "method": method,
            "evidence": f"{len(ok)}/{concurrent} parallel requests were accepted "
                        f"(status {sorted(set(ok))}) — likely missing lock/idempotency",
            "remediation": "Enforce idempotency keys or row-level locks on single-use "
                           "operations; reject concurrent duplicates server-side.",
        }
    return None


def _load_targets(args):
    urls = list(args.url)
    if args.scan_dir:
        for rel in ("09_crawling/all_urls.txt",):
            p = os.path.join(args.scan_dir, rel)
            if os.path.isfile(p):
                with open(p, errors="ignore") as f:
                    urls += [l.strip() for l in f if l.strip().startswith("http")]
    cand = [u for u in urls if SENSITIVE_RE.search(u)]
    seen, out = set(), []
    for u in cand:
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out[: args.max_targets]


def main():
    ap = argparse.ArgumentParser(description="ARISE race condition scanner")
    ap.add_argument("scan_dir", nargs="?")
    ap.add_argument("--url", action="append", default=[])
    ap.add_argument("--out")
    ap.add_argument("--concurrent", type=int, default=20)
    ap.add_argument("--max-targets", type=int, default=40)
    args = ap.parse_args()
    if not requests:
        print("race_condition: requests not installed; skipping", file=sys.stderr)
        return 0
    findings = []
    for u in _load_targets(args):
        f = test_race(u, concurrent=args.concurrent)
        if f:
            findings.append(f)
    out = args.out or (os.path.join(args.scan_dir, "24_advanced_attacks", "race_condition_findings.jsonl")
                       if args.scan_dir else "race_condition_findings.jsonl")
    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
    with open(out, "w") as f:
        for row in findings:
            f.write(json.dumps(row) + "\n")
    print(f"race_condition: {len(findings)} finding(s) -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
