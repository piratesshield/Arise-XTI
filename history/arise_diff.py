#!/usr/bin/env python3
"""
ARISE Delta Engine — what changed since last time
=================================================
Consumes the durable Asset Ledger (see ledger.py) and computes, for a given
scan, exactly which assets are NEW, which were re-observed, and which were NOT
seen this scan. This is the engine that lets an incremental scan of a huge site
(the Flipkart lesson) attack only the delta instead of the whole surface.

The trick: the ledger already stamps every record with first_scan_id and
last_scan_id, so the delta is a pure filter over the post-ingest ledger — no
fragile file-vs-file diffing, and it is correct even when discovery is partial:

    new                 first_scan_id == this scan   -> never seen before
    seen                last_scan_id  == this scan   -> observed this scan
    not_observed        last_scan_id  != this scan   -> known asset we did not
                        (and still "alive")             re-observe this run

For a FULL scan, `not_observed` means "disappeared / attack-surface reduction".
For an INCREMENTAL/SELECTIVE scan it just means "out of this run's scope", so the
caller interprets it by mode — the engine only reports facts.

`verification_targets()` distils the NEW assets into the concrete host/url/api
work list the incremental verifier (P2/P3) feeds to the attack modules.

Pure stdlib, imports only ledger.py, never raises to the caller. Offline
self-test builds a two-scan history in a temp dir and proves the delta.
"""

from __future__ import annotations

import sys as _sys, os as _os
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)


import argparse
import json
import sys
from datetime import datetime
from typing import Dict, List, Optional

import history.ledger as _ledger
from history.ledger import Ledger, STORES


def _key_to_url(store: str, key: str) -> str:
    """Ledger keys are '<METHOD> <url>' for endpoints/apis, bare host for
    subdomains, 'host:port' for services. Return the useful locator."""
    if store in ("endpoints", "apis"):
        parts = key.split(" ", 1)
        return parts[1] if len(parts) == 2 else key
    return key


def compute_delta(target: str, scan_id: str, root: str = "state") -> dict:
    """Per-store new / seen / not-observed for `scan_id`, read from the ledger."""
    lg = Ledger(target, root=root)
    out: Dict[str, object] = {
        "target": target,
        "scan_id": scan_id,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "stores": {},
    }
    stores: Dict[str, dict] = {}
    for store in STORES:
        recs = lg.all(store)
        new_keys, seen_keys, not_obs = [], [], []
        for r in recs:
            k = r.get("_key")
            if not k:
                continue
            if r.get("first_scan_id") == scan_id:
                new_keys.append(k)
            if r.get("last_scan_id") == scan_id:
                seen_keys.append(k)
            elif r.get("status") == "alive":
                not_obs.append(k)
        stores[store] = {
            "total": len(recs),
            "new_count": len(new_keys),
            "seen_count": len(seen_keys),
            "not_observed_count": len(not_obs),
            # cap the materialised lists so a huge site cannot bloat delta.json;
            # counts are always exact, samples are bounded.
            "new": new_keys[:5000],
            "not_observed": not_obs[:2000],
        }
    out["stores"] = stores
    return out


def verification_targets(delta: dict) -> dict:
    """Distil a delta into the concrete work list for incremental verification:
    the NEW hosts / urls / apis that deserve the full attack chain."""
    stores = delta.get("stores", {})
    hosts = [_key_to_url("subdomains", k) for k in stores.get("subdomains", {}).get("new", [])]
    urls = [_key_to_url("endpoints", k) for k in stores.get("endpoints", {}).get("new", [])]
    apis = [_key_to_url("apis", k) for k in stores.get("apis", {}).get("new", [])]
    return {
        "hosts": sorted(set(hosts)),
        "urls": sorted(set(urls)),
        "apis": sorted(set(apis)),
        "count": len(set(hosts)) + len(set(urls)) + len(set(apis)),
    }


def write_delta(delta: dict, out_path: str) -> bool:
    try:
        with open(out_path, "w") as fh:
            json.dump(delta, fh, indent=2, default=str)
        return True
    except OSError:
        return False


def _summary_line(delta: dict) -> str:
    bits = []
    for store, s in delta["stores"].items():
        if s["total"] or s["new_count"]:
            bits.append(f"{store}: +{s['new_count']} new / {s['total']} total")
    return "; ".join(bits) if bits else "no assets in ledger"


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="ARISE delta engine (ledger-backed)")
    ap.add_argument("--target", required=True)
    ap.add_argument("--scan-id", required=True)
    ap.add_argument("--root", default="state")
    ap.add_argument("--out", help="write full delta JSON here")
    ap.add_argument("--targets-out", help="write the verification work list (hosts/urls/apis) here")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args(argv)

    delta = compute_delta(args.target, args.scan_id, root=args.root)
    if args.out:
        write_delta(delta, args.out)
    if args.targets_out:
        try:
            with open(args.targets_out, "w") as fh:
                json.dump(verification_targets(delta), fh, indent=2)
        except OSError:
            pass
    if not args.quiet:
        print(f"[delta] {args.target} @ {args.scan_id}: {_summary_line(delta)}")
        vt = verification_targets(delta)
        print(f"[delta] verification targets: {len(vt['hosts'])} new hosts, "
              f"{len(vt['urls'])} new urls, {len(vt['apis'])} new apis")
    return 0


# ---------------------------------------------------------------------------
# Offline self-test — build a 2-scan history, prove the delta
# ---------------------------------------------------------------------------

def _selftest():
    import shutil
    import tempfile

    print("=== arise_diff self-test (offline, deterministic) ===\n")
    tmp = tempfile.mkdtemp(prefix="arise_diff_")
    try:
        lg = Ledger("t.com", root=tmp)

        # Scan 1 — baseline
        lg.upsert("subdomains", _ledger.subdomains_from_lines(["a.t.com", "b.t.com"]),
                  scan_id="s1", now="2026-01-01T00:00:00+00:00")
        lg.upsert("endpoints", _ledger.endpoints_from_urls(
            ["https://a.t.com/x", "https://a.t.com/y"]),
            scan_id="s1", now="2026-01-01T00:00:00+00:00")
        lg.upsert("apis", [{"url": "https://a.t.com/api/v1/users", "method": "GET"}],
                  scan_id="s1", now="2026-01-01T00:00:00+00:00")

        d1 = compute_delta("t.com", "s1", root=tmp)
        assert d1["stores"]["subdomains"]["new_count"] == 2
        assert d1["stores"]["endpoints"]["new_count"] == 2
        assert d1["stores"]["apis"]["new_count"] == 1
        print("[1] baseline scan s1: everything is new (2 subs, 2 eps, 1 api)  ✓")

        # Scan 2 — one NEW subdomain, one NEW endpoint; b.t.com not re-observed
        lg.upsert("subdomains", _ledger.subdomains_from_lines(["a.t.com", "c.t.com"]),
                  scan_id="s2", now="2026-01-08T00:00:00+00:00")
        lg.upsert("endpoints", _ledger.endpoints_from_urls(
            ["https://a.t.com/x", "https://c.t.com/new"]),
            scan_id="s2", now="2026-01-08T00:00:00+00:00")

        d2 = compute_delta("t.com", "s2", root=tmp)
        s = d2["stores"]
        assert s["subdomains"]["new_count"] == 1 and s["subdomains"]["new"] == ["c.t.com"], s["subdomains"]
        assert s["endpoints"]["new_count"] == 1, s["endpoints"]
        assert "GET https://c.t.com/new" in s["endpoints"]["new"]
        # b.t.com was alive but not seen in s2 -> not_observed
        assert "b.t.com" in s["subdomains"]["not_observed"], s["subdomains"]
        # apis unchanged this scan -> 0 new
        assert s["apis"]["new_count"] == 0
        print("[2] incremental s2: exactly 1 new sub (c.t.com), 1 new endpoint  ✓")
        print("[3] not-observed: b.t.com flagged (disappeared / out-of-scope)  ✓")

        # verification_targets distils only the NEW work
        vt = verification_targets(d2)
        assert vt["hosts"] == ["c.t.com"], vt
        assert vt["urls"] == ["https://c.t.com/new"], vt
        assert vt["apis"] == [], vt
        assert vt["count"] == 2
        print("[4] verification_targets: {1 host, 1 url, 0 api} — attack the delta only  ✓")

        # write_delta round-trips
        out = f"{tmp}/delta.json"
        assert write_delta(d2, out)
        with open(out) as fh:
            assert json.load(fh)["scan_id"] == "s2"
        print("[5] delta.json written and valid  ✓")

        print("\nDelta engine proven: new/seen/not-observed from ledger scan ids,\n"
              "verification targets = the delta only. ✓")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    if len(sys.argv) == 1 or sys.argv[1] == "selftest":
        _selftest()
        sys.exit(0)
    sys.exit(main())
