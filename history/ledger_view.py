#!/usr/bin/env python3
"""
ARISE Historic Asset view — backend for the Asset History dashboard sub-tab
===========================================================================
Turns the durable Asset Ledger (ledger.py) + the latest scan's delta/regression
artifacts into a single JSON payload the dashboard renders: attack-surface
growth over time, what is NEW vs long-known, what has gone DEAD (surface
reduction), and the per-asset first_seen/last_seen/status history that answers
"when did this appear and is it still live?".

Pure stdlib, reuses ledger.py, never raises. Offline self-test + runs standalone
against a real state/ dir.
"""

from __future__ import annotations

import sys as _sys, os as _os
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)


import json
import os
from collections import Counter
from pathlib import Path
from typing import Dict, List, Optional

from history.ledger import Ledger, STORES


def _asset_row(store: str, r: dict) -> dict:
    return {
        "key": r.get("_key", ""),
        "first_seen": r.get("first_seen", ""),
        "last_seen": r.get("last_seen", ""),
        "first_scan_id": r.get("first_scan_id", ""),
        "last_scan_id": r.get("last_scan_id", ""),
        "status": r.get("status", "unknown"),
        "seen_count": r.get("seen_count", 1),
        "http_status": r.get("http_status", ""),
    }


def build_view(target: str, root: str = "state", scan_dir: Optional[str] = None,
               recent_limit: int = 200) -> dict:
    """Assemble the Asset History payload for one target."""
    lg = Ledger(target, root=root)

    stores_out: Dict[str, dict] = {}
    growth: Dict[str, Counter] = {}
    for store in STORES:
        recs = lg.all(store)
        rows = [_asset_row(store, r) for r in recs]
        # newest-first by first_seen (new assets are the priority to review)
        rows.sort(key=lambda x: (x["first_seen"], x["key"]), reverse=True)
        alive = sum(1 for r in rows if r["status"] == "alive")
        dead = sum(1 for r in rows if r["status"] == "dead")
        # growth curve: how many assets first appeared in each scan
        g = Counter(r["first_scan_id"] for r in rows if r["first_scan_id"])
        growth[store] = g
        stores_out[store] = {
            "total": len(rows),
            "alive": alive,
            "dead": dead,
            "recent": rows[:recent_limit],   # bounded for the wire
            "dead_assets": [r for r in rows if r["status"] == "dead"][:recent_limit],
            "by_scan": dict(g),
        }

    # Fold in the latest scan's delta + regression artifacts when available.
    delta = _read_json(Path(scan_dir) / "asset_delta.json") if scan_dir else None
    regression = _read_json(Path(scan_dir) / "regression.json") if scan_dir else None
    new_targets = _read_json(Path(scan_dir) / "new_targets.json") if scan_dir else None

    # A unified scan timeline across all stores (union of scan ids, ordered).
    all_scans = sorted({s for g in growth.values() for s in g})
    timeline = [{
        "scan_id": sid,
        "new": {store: growth[store].get(sid, 0) for store in STORES},
    } for sid in all_scans]

    return {
        "target": target,
        "summary": lg.summary()["stores"],
        "stores": stores_out,
        "timeline": timeline,
        "delta": delta,
        "regression": regression,
        "new_targets": new_targets,
    }


def _read_json(path: Path) -> Optional[dict]:
    try:
        with open(path) as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Self-test + standalone CLI
# ---------------------------------------------------------------------------

def _selftest():
    import shutil
    import tempfile
    import history.ledger as _l

    print("=== ledger_view self-test (offline) ===\n")
    tmp = tempfile.mkdtemp(prefix="arise_lv_")
    try:
        lg = Ledger("v.com", root=tmp)
        lg.upsert("subdomains", _l.subdomains_from_lines(["a.v.com", "b.v.com"]),
                  scan_id="s1", now="2026-01-01T00:00:00+00:00")
        lg.upsert("subdomains", _l.subdomains_from_lines(["a.v.com", "c.v.com"]),
                  scan_id="s2", now="2026-01-08T00:00:00+00:00")
        lg.mark_liveness("subdomains", ["a.v.com", "c.v.com"], scan_id="s2",
                         now="2026-01-08T00:00:00+00:00")  # b.v.com -> dead

        v = build_view("v.com", root=tmp)
        subs = v["stores"]["subdomains"]
        assert subs["total"] == 3 and subs["dead"] == 1, subs
        # newest-first: c.v.com (first_seen s2) before a/b (s1)
        assert v["stores"]["subdomains"]["recent"][0]["key"] == "c.v.com"
        # timeline: s1 added 2, s2 added 1
        tl = {t["scan_id"]: t["new"]["subdomains"] for t in v["timeline"]}
        assert tl == {"s1": 2, "s2": 1}, tl
        # dead asset surfaced
        assert any(d["key"] == "b.v.com" for d in subs["dead_assets"])
        print("[1] totals/alive/dead correct (3 total, 1 dead)  ✓")
        print("[2] recent newest-first; growth timeline s1=2, s2=1  ✓")
        print("[3] dead asset (b.v.com) surfaced for surface-reduction view  ✓")
        print("\nAsset History view assembled correctly. ✓")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    import sys
    if len(sys.argv) == 1 or sys.argv[1] == "selftest":
        _selftest()
        sys.exit(0)
    import argparse
    ap = argparse.ArgumentParser(description="ARISE historic asset view")
    ap.add_argument("--target", required=True)
    ap.add_argument("--root", default="state")
    ap.add_argument("--scan-dir")
    args = ap.parse_args()
    print(json.dumps(build_view(args.target, root=args.root, scan_dir=args.scan_dir), indent=2)[:3000])
