#!/usr/bin/env python3
"""
ARISE — GraphQL introspection & security scanner (Phase 6, module 3.4).

For each candidate GraphQL endpoint:
  1. Introspection enabled? (schema leak — should be off in prod)
  2. Field-suggestion ("did you mean") enabled? (schema inference even w/o introspection)
  3. Deep nested query — is a depth limit enforced? (DoS surface)
  4. Batched queries accepted? (rate-limit / cost bypass)

Non-destructive: read-only queries only (no mutations executed). Output: JSONL.
"""

import sys as _sys, os as _os
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)

import argparse
import json
import os
import sys
import time

try:
    import requests
    requests.packages.urllib3.disable_warnings()  # type: ignore
except Exception:
    requests = None

INTROSPECTION = {"query": "{__schema{types{name}}}"}
BAD_FIELD = {"query": "{__typenameeee}"}
CANDIDATE_PATHS = ["/graphql", "/graphiql", "/api/graphql", "/v1/graphql",
                   "/query", "/gql", "/graphql/console"]


def _post(url, payload, timeout=12):
    if not requests:
        return None
    try:
        return requests.post(url, json=payload, timeout=timeout, verify=False,
                             allow_redirects=False,
                             headers={"Content-Type": "application/json"})
    except Exception:
        return None


def scan_endpoint(url):
    findings = []

    def emit(sev, conf, title, evidence, rem):
        findings.append({"module": "graphql_scanner", "severity": sev, "confidence": conf,
                         "title": title, "url": url, "evidence": evidence, "remediation": rem})

    r = _post(url, INTROSPECTION)
    if r is None:
        return findings
    body = (r.text or "")[:4000]
    if r.status_code == 200 and "__schema" in body and '"types"' in body:
        emit("high", "confirmed", "GraphQL introspection enabled",
             "the __schema introspection query returned the type system",
             "Disable introspection in production; expose it only in dev.")
    # Field suggestion
    r2 = _post(url, BAD_FIELD)
    if r2 is not None and ("did you mean" in (r2.text or "").lower()):
        emit("medium", "confirmed", "GraphQL field suggestions enabled",
             "an invalid field triggered a 'did you mean' hint (schema inference)",
             "Disable field suggestions in production error handling.")
    # Depth limit
    depth = 12
    nested = "{__typename " * depth + "}" * depth
    t0 = time.time()
    r3 = _post(url, {"query": nested})
    elapsed = time.time() - t0
    if r3 is not None and r3.status_code == 200 and elapsed > 5.0:
        emit("medium", "reported", "GraphQL query-depth limit not enforced",
             f"a depth-{depth} nested query was accepted and took {elapsed:.1f}s (DoS surface)",
             "Enforce a max query depth/complexity and a timeout.")
    # Batching
    rb = _post(url, [INTROSPECTION, INTROSPECTION, INTROSPECTION])
    if rb is not None and rb.status_code == 200 and rb.text.strip().startswith("["):
        emit("low", "reported", "GraphQL query batching accepted",
             "the endpoint processed an array of queries in one request (cost/limit bypass)",
             "Disable array batching or apply per-operation cost limits.")
    return findings


def _load_targets(args):
    urls = set(args.url)
    if args.scan_dir:
        hosts = os.path.join(args.scan_dir, "04_http_discovery", "http_hosts.txt")
        roots = []
        if os.path.isfile(hosts):
            with open(hosts, errors="ignore") as f:
                roots = [l.strip().rstrip("/") for l in f if l.strip().startswith("http")]
        for root in roots[: args.max_hosts]:
            for path in CANDIDATE_PATHS:
                urls.add(root + path)
        # Any crawled URL that already looks like graphql
        crawl = os.path.join(args.scan_dir, "09_crawling", "all_urls.txt")
        if os.path.isfile(crawl):
            with open(crawl, errors="ignore") as f:
                for l in f:
                    l = l.strip()
                    if l.startswith("http") and ("graphql" in l.lower() or "/gql" in l.lower()):
                        urls.add(l.split("?")[0])
    return list(urls)[: args.max_targets]


def main():
    ap = argparse.ArgumentParser(description="ARISE GraphQL scanner")
    ap.add_argument("scan_dir", nargs="?")
    ap.add_argument("--url", action="append", default=[])
    ap.add_argument("--out")
    ap.add_argument("--max-hosts", type=int, default=60)
    ap.add_argument("--max-targets", type=int, default=400)
    args = ap.parse_args()
    if not requests:
        print("graphql_scanner: requests not installed; skipping", file=sys.stderr)
        return 0
    findings = []
    for u in _load_targets(args):
        findings.extend(scan_endpoint(u))
    out = args.out or (os.path.join(args.scan_dir, "24_advanced_attacks", "graphql_findings.jsonl")
                       if args.scan_dir else "graphql_findings.jsonl")
    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
    with open(out, "w") as f:
        for row in findings:
            f.write(json.dumps(row) + "\n")
    print(f"graphql_scanner: {len(findings)} finding(s) -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
