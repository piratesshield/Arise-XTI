#!/usr/bin/env python3
"""
ARISE JS-Referenced Host/API Extraction (Module 10.2)
======================================================
Passively extracts absolute URLs embedded in already-downloaded JS bundles
— the same staged corpus Module 10.1's arise_nlp content scan and trufflehog
already scan (10_secret_scanning/staged/js_downloads/) — and surfaces
same-organization hosts the scan hasn't targeted yet. No extra HTTP
requests: this reads files already on disk.

Why this exists: a CDN-fronted static asset host (checkout widget, marketing
SPA, JS bundle bucket) routinely has zero exploitable surface of its own,
while its JS ships fetch()/axios/apiSliceBaseQuery calls hardcoding the REAL
backend API hosts (api.<org>.com, <region>.<org>.com, ...) as plain string
literals. Those hosts are the actual attack surface a scan of the static
bucket alone will never touch — this module surfaces them as scan
candidates.

Scope discipline: this module only SURFACES same-root-domain (eTLD+1 match
with the scan target) candidate hosts for confirmation — it never scans or
attacks them. Third-party SaaS/CDN/analytics domains embedded in the same JS
(Google, Stripe, Sentry, Segment, ...) are explicitly excluded; they are not
the target organization's infrastructure and are not in scope.

Output: <scan_dir>/10.2_js_endpoints/js_referenced_hosts.jsonl (+
summary.json). history/ledger.py's ingest_scan() reads this and upserts
into the 'subdomains' store, so these candidates flow into the standard
asset-delta / new_targets.json / dashboard pipeline automatically.
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit

_URL_RE = re.compile(
    r"https?://[A-Za-z0-9][A-Za-z0-9.\-]*\.[A-Za-z]{2,}(?:[:/][^\s\"'<>\\]*)?")

# Common third-party SaaS/CDN/analytics/social domains that show up in almost
# every production JS bundle — never the target organization's own
# infrastructure, so never worth surfacing as a pivot candidate.
_THIRDPARTY_SUFFIXES = {
    "google-analytics.com", "googletagmanager.com", "googleapis.com",
    "gstatic.com", "doubleclick.net", "google.com", "googleadservices.com",
    "googlesyndication.com", "cloudflare.com", "cloudfront.net",
    "jsdelivr.net", "unpkg.com", "jquery.com", "bootstrapcdn.com",
    "fontawesome.com", "akamaihd.net", "fastly.net", "typekit.net",
    "sentry.io", "segment.com", "segment.io", "intercom.io", "zendesk.com",
    "hotjar.com", "mixpanel.com", "amplitude.com", "fullstory.com",
    "clarity.ms", "newrelic.com", "datadoghq.com", "launchdarkly.com",
    "optimizely.com", "facebook.com", "facebook.net", "twitter.com",
    "linkedin.com", "youtube.com", "instagram.com", "whatsapp.com",
    "recaptcha.net", "apple.com", "paypal.com", "stripe.com",
    "schema.org", "w3.org",
}

_MAX_FILE_BYTES = 2_000_000
_MAX_URLS_PER_FILE = 5000


def _registrable(host: str) -> str:
    """Naive eTLD+1 — good enough to compare 'same organization' domains;
    multi-label public suffixes (co.uk, co.in) handled leniently. Mirrors
    recon/dns_security_audit.py's registrable() (kept local/dependency-free
    here rather than cross-importing a heavy DNS-audit module for one
    10-line pure function)."""
    parts = host.strip().rstrip(".").lower().split(".")
    if len(parts) <= 2:
        return ".".join(parts)
    two_label_tlds = {"co", "com", "org", "net", "gov", "edu", "ac"}
    if parts[-2] in two_label_tlds and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _is_thirdparty(host: str) -> bool:
    h = host.lower()
    return any(h == s or h.endswith("." + s) for s in _THIRDPARTY_SUFFIXES)


def _load_url_index(staged_dir: Path) -> dict:
    """staged-filename -> real source URL, from Module 10's index.tsv
    (best-effort; an empty/missing index just means less provenance)."""
    idx = {}
    tsv = staged_dir / "index.tsv"
    if not tsv.exists():
        return idx
    try:
        with open(tsv, "r", errors="ignore") as fh:
            for line in fh:
                parts = line.rstrip("\n").split("\t")
                if len(parts) >= 2:
                    idx[parts[1]] = parts[0]
    except OSError:
        pass
    return idx


def extract_referenced_hosts(staged_js_dir: str, target: str) -> list:
    """Walk staged JS files, extract absolute URLs, return same-org
    candidate hosts (excludes the scan target itself, third-party SaaS/CDN
    domains, and hosts from a different organization entirely). Never
    raises — a missing/unreadable dir just yields no candidates."""
    root = Path(staged_js_dir)
    if not root.is_dir():
        return []
    target = (target or "").strip().lower()
    target_root = _registrable(target)
    url_index = _load_url_index(root)

    found: dict = {}
    for dirpath, _dirs, filenames in os.walk(root, followlinks=True):
        for name in filenames:
            if name == "index.tsv":
                continue
            fpath = os.path.join(dirpath, name)
            try:
                if os.path.getsize(fpath) > _MAX_FILE_BYTES:
                    continue
                with open(fpath, "r", errors="ignore") as fh:
                    text = fh.read()
            except OSError:
                continue
            if not text:
                continue

            source_url = url_index.get(name, fpath)
            for m in _URL_RE.findall(text)[:_MAX_URLS_PER_FILE]:
                try:
                    host = (urlsplit(m).hostname or "").lower().rstrip(".")
                except ValueError:
                    continue
                if not host or "." not in host:
                    continue
                if host == target:
                    continue          # the target itself, not a pivot
                if _is_thirdparty(host):
                    continue          # known SaaS/CDN — not the org's infra
                if _registrable(host) != target_root:
                    continue          # different organization — out of scope
                rec = found.setdefault(host, {
                    "host": host, "sample_url": m,
                    "referenced_in": source_url, "occurrences": 0,
                })
                rec["occurrences"] += 1

    return sorted(found.values(), key=lambda r: -r["occurrences"])


def run(scan_dir: str, target: str) -> list:
    """Pipeline entrypoint: locate the staged JS corpus under `scan_dir`,
    extract candidates, and write them to 10.2_js_endpoints/. Returns the
    list of records written (empty list on any failure — never raises)."""
    sd = Path(scan_dir)
    staged = sd / "10_secret_scanning" / "staged" / "js_downloads"
    out_dir = sd / "10.2_js_endpoints"
    out_dir.mkdir(parents=True, exist_ok=True)

    hosts = extract_referenced_hosts(str(staged), target)

    with open(out_dir / "js_referenced_hosts.jsonl", "w") as fh:
        for r in hosts:
            fh.write(json.dumps(r) + "\n")
    with open(out_dir / "summary.json", "w") as fh:
        json.dump({"target": target, "candidate_hosts": len(hosts),
                    "hosts": [r["host"] for r in hosts]}, fh, indent=2)
    return hosts


def _selftest() -> int:
    import tempfile

    print("=== js_endpoint_extract self-test ===\n")
    with tempfile.TemporaryDirectory() as tmp:
        staged = Path(tmp) / "js_downloads"
        staged.mkdir()
        (staged / "bundle1.js").write_text(
            'const a="https://api.razorpay.com/v1/payments";'
            'const b="https://lumberjack.razorpay.com/track";'
            'const c="https://www.google-analytics.com/collect";'
            'const d="https://sentry.io/api/123";'
            'const e="https://x.razorpay.com/self";'
            'const f="https://evil-unrelated.com/x";'
        )
        (staged / "bundle2.js").write_text(
            'fetch("https://api.razorpay.com/v1/orders")')
        (staged / "index.tsv").write_text(
            "https://x.razorpay.com/dist/bundle1.abc.js\tbundle1.js\n"
            "https://x.razorpay.com/dist/bundle2.abc.js\tbundle2.js\n")

        hosts = extract_referenced_hosts(str(staged), "x.razorpay.com")
        names = {r["host"] for r in hosts}

    assert "api.razorpay.com" in names, f"missed same-org API host: {names}"
    assert "lumberjack.razorpay.com" in names, f"missed same-org host: {names}"
    print(f"[1] same-org hosts found: {sorted(names)}  OK")

    assert "www.google-analytics.com" not in names, "should exclude known third-party"
    assert "sentry.io" not in names, "should exclude known third-party"
    print("[2] third-party SaaS/CDN hosts excluded  OK")

    assert "x.razorpay.com" not in names, "should exclude the scan target itself"
    print("[3] scan target excluded from its own results  OK")

    assert "evil-unrelated.com" not in names, "should exclude a different organization"
    print("[4] different-organization host excluded (scope discipline)  OK")

    api_rec = next(r for r in hosts if r["host"] == "api.razorpay.com")
    assert api_rec["occurrences"] == 2, f"expected 2 refs, got {api_rec['occurrences']}"
    print(f"[5] occurrence counting across files: {api_rec['occurrences']}  OK")

    print("\nAll js_endpoint_extract tests passed.")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Module 10.2: extract same-org hosts referenced in staged JS")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--scan-dir", help="scan directory (reads 10_secret_scanning/staged/js_downloads)")
    ap.add_argument("--target", help="scan target host (excluded from results)")
    args = ap.parse_args(argv)

    if args.selftest:
        return _selftest()
    if not args.scan_dir or not args.target:
        ap.error("--scan-dir and --target are required unless --selftest")

    hosts = run(args.scan_dir, args.target)
    print(f"[js_endpoint_extract] {len(hosts)} candidate same-org host(s) referenced in staged JS")
    for r in hosts[:20]:
        print(f"  {r['host']}  ({r['occurrences']} ref, e.g. {r['sample_url'][:80]})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
