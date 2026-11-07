#!/usr/bin/env python3
"""
Emit a URL→methods map from discovered_endpoints.jsonl so downstream scanners
can act on non-GET surfaces (POST-only login CVEs, PUT open buckets, DELETE
CSRF). Nuclei's URL feed is GET-only by default; anything non-GET requires
either a custom template or a workflow. The pragmatic output of this script
is a JSONL that api security modules (apisec, api_intelligence_engine) can
consume immediately without having to re-run OPTIONS themselves.

Output:
    method_map.jsonl — one row per URL that has methods beyond GET:
        {url, methods: ["GET", "POST", "PUT"], source: "options-probe"}

The endpoint_consolidator already fires OPTIONS on API-classed endpoints and
stores the Allow: set in the `methods` field of each discovered endpoint.
We just filter to endpoints where methods ≠ [GET] and emit the map.
"""

from __future__ import annotations

import sys as _sys, os as _os
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)


import json
import sys
from pathlib import Path

NON_TRIVIAL_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def build(scan_dir: Path) -> int:
    src = scan_dir / "08_directory_discovery" / "discovered_endpoints.jsonl"
    out = scan_dir / "08_directory_discovery" / "method_map.jsonl"
    if not src.is_file() or src.stat().st_size == 0:
        return 0
    n = 0
    with open(out, "w", encoding="utf-8") as w:
        try:
            with open(src, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        e = json.loads(line)
                    except Exception:
                        continue
                    methods = e.get("methods") or []
                    if not isinstance(methods, list):
                        continue
                    # Emit only if there's a non-GET method — GET-only rows
                    # are the default and don't need to be surfaced.
                    if not any(m in NON_TRIVIAL_METHODS for m in methods):
                        continue
                    url = e.get("sample_url") or e.get("url") or ""
                    if not url:
                        continue
                    w.write(json.dumps({
                        "url": url,
                        "methods": methods,
                        "source": "options-probe",
                    }) + "\n")
                    n += 1
        except FileNotFoundError:
            return 0
    return n


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: method_map.py <scan_dir>", file=sys.stderr)
        sys.exit(2)
    n = build(Path(sys.argv[1]))
    print(f"[method-map] wrote {n} non-GET endpoint row(s)", file=sys.stderr)
