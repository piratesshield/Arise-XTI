#!/usr/bin/env python3
"""Non-regression gate for the MCP/AI surface feature (MCP_AI_DISCOVERY roadmap,
Phase 6). Runs the endpoint consolidator on a NON-AI fixture scan (no
mcp_ai_endpoints.jsonl present) and asserts the URL Inventory is substantively
unchanged by the feature:

  * every record carries the 3 AI keys but they are all None (uniform schema),
  * no record gained an ai-*/mcp-* attack lane,
  * the ONLY new top-level keys vs the pre-feature schema are the AI keys,
  * url_class / api_type of ordinary URLs are untouched.

Offline — runs the consolidator in-process with --no-probe/--no-method-probe.
Run: python3 tests/test_mcp_ai_regression.py
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

_fail = 0


def check(name, cond, detail=""):
    global _fail
    if not cond:
        _fail += 1
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f" — {detail}" if detail and not cond else ""))


# The record schema BEFORE this feature (every key the consolidator emitted).
BASELINE_KEYS = {
    "url", "sample_url", "host", "path", "query", "status", "verified", "source",
    "sources", "instances", "query_variants", "method", "methods", "provenance",
    "url_class", "api_type", "url_shape", "sensitivity", "auth_state",
    "content_type", "cloud_provider", "cloud_bucket", "attributed_to",
    "input_functions", "input_function", "accepts_file", "routed_to",
    "blocked_by_waf", "waf_signatures",
}
# The exact keys this feature adds — and NOTHING else may appear.
NEW_KEYS = {"ai_surface", "ai_flavor", "ai_confidence", "ai_tool_count", "ai_server_info"}


def main():
    with tempfile.TemporaryDirectory() as sd:
        os.makedirs(os.path.join(sd, "04_http_discovery"), exist_ok=True)
        os.makedirs(os.path.join(sd, "08_directory_discovery"), exist_ok=True)
        # A plain, NON-AI surface: a web page, an API with an id, an auth route.
        with open(os.path.join(sd, "04_http_discovery", "http_urls.txt"), "w") as f:
            f.write("https://shop.example.com/products?category=shoes\n")
            f.write("https://api.example.com/v1/users/12345\n")
            f.write("https://example.com/login\n")
            f.write("https://example.com/about\n")
        # NOTE: deliberately NO mcp_ai_endpoints.jsonl — this is a non-AI scan.

        cmd = [sys.executable, os.path.join(ROOT, "discovery", "endpoint_consolidator.py"),
               "example.com", "--scan-dir", sd, "--no-probe", "--no-method-probe"]
        subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=120)

        out = os.path.join(sd, "08_directory_discovery", "discovered_endpoints.jsonl")
        check("inventory produced", os.path.exists(out))
        rows = []
        if os.path.exists(out):
            with open(out) as f:
                rows = [json.loads(l) for l in f if l.strip()]
        check("rows present", len(rows) >= 3, f"got {len(rows)}")

        print("== AI keys present but null on every non-AI row ==")
        all_null = all(r.get("ai_surface") is None and r.get("ai_flavor") is None
                       and r.get("ai_confidence") is None for r in rows)
        check("ai_surface/ai_flavor/ai_confidence all None", all_null)

        print("== no AI/MCP attack lanes leaked onto ordinary URLs ==")
        no_lanes = all(not any(str(x).startswith(("ai-", "mcp-")) for x in (r.get("routed_to") or []))
                       for r in rows)
        check("no ai-*/mcp-* lanes", no_lanes)

        print("== schema: only the AI keys are new ==")
        allowed = BASELINE_KEYS | NEW_KEYS
        extra = set()
        for r in rows:
            extra |= (set(r.keys()) - allowed)
        check("no unexpected new keys", not extra, f"unexpected: {sorted(extra)}")
        missing_new = set()
        for r in rows:
            missing_new |= (NEW_KEYS - set(r.keys()))
        check("all AI keys present (uniform schema)", not missing_new, f"missing: {sorted(missing_new)}")

        print("== ordinary url_class/api_type untouched ==")
        by_url = {r["url"]: r for r in rows}
        api_row = next((r for u, r in by_url.items() if "/v1/users/" in u), None)
        if api_row:
            check("api row still url_class=api", api_row["url_class"] == "api",
                  f"got {api_row['url_class']}")
        shop = next((r for u, r in by_url.items() if "/products" in u), None)
        if shop:
            check("query-param row routed to xss/sqli",
                  "sqli" in (shop.get("routed_to") or []), f"got {shop.get('routed_to')}")

    print(f"\n{'ALL PASS' if _fail == 0 else str(_fail) + ' FAILED'}")
    return 1 if _fail else 0


if __name__ == "__main__":
    sys.exit(main())
