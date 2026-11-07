#!/usr/bin/env python3
"""
ARISE Regression Reporter — "did the bug actually get fixed?"
=============================================================
Every ARISE scan re-runs the verification checks; kaiju_issues.correlate() then
compares this scan's findings against the stored issue state and moves each
issue through its lifecycle:

    seen again              -> stays open, last_verified stamped (still vulnerable)
    was resolved, seen again-> reopened  (regression!)
    open, no longer seen    -> auto_resolved, last_verified stamped (fixed)

Those transitions are logged, per scan, to state/<target>/events.jsonl with the
scan revision. This module turns that authoritative record into a crisp,
scan-time regression report so an operator running an incremental/selective scan
gets a direct answer — "3 fixed, 1 regressed, 12 still open" — without opening
the dashboard and eyeballing 47 issues.

It reads only the durable state kaiju_issues maintains (issues-state.json +
events.jsonl) via kaiju_issues' own helpers, so there is a single source of
truth and no risk of a second, drifting lifecycle implementation.

Pure stdlib, never raises to the caller, offline self-test with a synthetic
target. Wired into the pipeline (module_ledger_ingest) to drop a regression.json
into each scan dir.
"""

from __future__ import annotations

import sys as _sys, os as _os
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)


import argparse
import json
import os
import sys
from datetime import datetime, timezone
from typing import Dict, List, Optional

import history.kaiju_issues as kaiju_issues

_OPEN_STATES = ("open", "acknowledged", "in_progress")
_HUMAN_CLOSED = ("false_positive", "accepted_risk")


def _events_for_scan(target: str, scan_id: str) -> List[dict]:
    """Return the timeline events emitted for one scan revision."""
    path = kaiju_issues._events_path(target)
    out: List[dict] = []
    if not os.path.exists(path):
        return out
    try:
        with open(path, errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                except Exception:
                    continue
                if isinstance(e, dict) and e.get("rev") == scan_id:
                    out.append(e)
    except OSError:
        pass
    return out


def build_report(target: str, scan_id: str) -> dict:
    """Compose the regression report for a scan from state + events."""
    state = kaiju_issues.load_state(target)
    scan_events = _events_for_scan(target, scan_id)

    resolved_now = sorted({e["ref"] for e in scan_events if e.get("kind") == "issue_auto_resolved"})
    reopened_now = sorted({e["ref"] for e in scan_events if e.get("kind") == "issue_reopened"})
    new_now = sorted({e["ref"] for e in scan_events if e.get("kind") == "issue_created"})

    # Current standing, from the stored half.
    tally: Dict[str, int] = {}
    still_open: List[dict] = []
    for ref, st in state.items():
        status = st.get("status", "open")
        tally[status] = tally.get(status, 0) + 1
        if status in _OPEN_STATES:
            still_open.append({
                "ref": ref,
                "status": status,
                "detections": st.get("detections", 0),
                "first_seen_rev": st.get("first_seen_rev", ""),
                "last_seen_rev": st.get("last_seen_rev", ""),
                "last_verified_rev": st.get("last_verified_rev", st.get("last_seen_rev", "")),
                "verified_this_scan": st.get("last_verified_rev") == scan_id,
            })

    verified_this_scan = sum(1 for s in still_open if s["verified_this_scan"]) + len(resolved_now)

    return {
        "target": target,
        "scan_id": scan_id,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "this_scan": {
            "new": new_now,
            "resolved": resolved_now,      # confirmed fixed this scan
            "reopened": reopened_now,       # regression: was fixed, came back
            "new_count": len(new_now),
            "resolved_count": len(resolved_now),
            "reopened_count": len(reopened_now),
        },
        "standing": {
            "total_tracked": len(state),
            "open": sum(tally.get(s, 0) for s in _OPEN_STATES),
            "resolved": tally.get("resolved", 0),
            "false_positive": tally.get("false_positive", 0),
            "accepted_risk": tally.get("accepted_risk", 0),
        },
        "verified_this_scan": verified_this_scan,
        "still_open": sorted(still_open, key=lambda s: (-s["detections"], s["ref"])),
    }


def write_report(report: dict, out_path: str) -> bool:
    try:
        with open(out_path, "w") as fh:
            json.dump(report, fh, indent=2, default=str)
        return True
    except OSError:
        return False


def _summary_line(r: dict) -> str:
    ts = r["this_scan"]
    st = r["standing"]
    return (f"{r['target']} @ {r['scan_id']}: "
            f"{ts['resolved_count']} fixed, {ts['reopened_count']} regressed, "
            f"{ts['new_count']} new; {st['open']} still open "
            f"({r['verified_this_scan']} verified this scan)")


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="ARISE regression reporter (kaiju state/events)")
    ap.add_argument("--target", required=True)
    ap.add_argument("--scan-id", required=True)
    ap.add_argument("--out", help="write regression.json here")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args(argv)

    report = build_report(args.target, args.scan_id)
    if args.out:
        write_report(report, args.out)
    if not args.quiet:
        print("[regression] " + _summary_line(report))
        for ref in report["this_scan"]["reopened"]:
            print(f"[regression]   REGRESSED: {ref}")
    return 0


# ---------------------------------------------------------------------------
# Offline self-test — synthetic target, real kaiju_issues.correlate lifecycle
# ---------------------------------------------------------------------------

def _selftest():
    import tempfile
    import shutil

    print("=== arise_regression self-test (offline, real correlate lifecycle) ===\n")
    # Redirect kaiju_issues' state/ to a temp dir by monkeypatching state_dir.
    tmp = tempfile.mkdtemp(prefix="arise_reg_")
    orig_state_dir = kaiju_issues.state_dir
    tgt = "regtest.com"

    def fake_state_dir(target):
        d = os.path.join(tmp, "state", target)
        os.makedirs(d, exist_ok=True)
        return d
    kaiju_issues.state_dir = fake_state_dir
    try:
        def issue(ref, sev="high"):
            return {"ref": ref, "title": ref, "severity": sev, "summary_md": ""}

        # Scan 1: two issues found (A, B)
        merged, st1, ev1 = kaiju_issues.correlate(tgt, "scan1", [issue("issue:A"), issue("issue:B")])
        kaiju_issues.save_state(tgt, st1)
        kaiju_issues.append_events(tgt, ev1, rev="scan1")
        r1 = build_report(tgt, "scan1")
        assert r1["this_scan"]["new_count"] == 2, r1["this_scan"]
        assert r1["standing"]["open"] == 2
        print("[1] scan1: 2 new issues, 2 open  ✓")

        # Scan 2: A still there, B fixed (gone), C new
        merged, st2, ev2 = kaiju_issues.correlate(tgt, "scan2", [issue("issue:A"), issue("issue:C")])
        kaiju_issues.save_state(tgt, st2)
        kaiju_issues.append_events(tgt, ev2, rev="scan2")
        r2 = build_report(tgt, "scan2")
        assert r2["this_scan"]["resolved"] == ["issue:B"], r2["this_scan"]
        assert r2["this_scan"]["new"] == ["issue:C"], r2["this_scan"]
        assert r2["this_scan"]["reopened_count"] == 0
        assert r2["standing"]["open"] == 2  # A + C
        assert r2["standing"]["resolved"] == 1  # B
        # A was re-verified present this scan
        a = next(s for s in r2["still_open"] if s["ref"] == "issue:A")
        assert a["verified_this_scan"] is True, a
        print("[2] scan2: B fixed, C new, A re-verified open  ✓")

        # Scan 3: B comes BACK (regression), A gone
        merged, st3, ev3 = kaiju_issues.correlate(tgt, "scan3", [issue("issue:B"), issue("issue:C")])
        kaiju_issues.save_state(tgt, st3)
        kaiju_issues.append_events(tgt, ev3, rev="scan3")
        r3 = build_report(tgt, "scan3")
        assert r3["this_scan"]["reopened"] == ["issue:B"], r3["this_scan"]
        assert r3["this_scan"]["resolved"] == ["issue:A"], r3["this_scan"]
        print("[3] scan3: B REGRESSED (reopened), A now fixed  ✓")

        # last_verified stamped on B this scan
        stB = kaiju_issues.load_state(tgt)["issue:B"]
        assert stB.get("last_verified_rev") == "scan3", stB
        print("[4] last_verified stamped on re-checked issue  ✓")

        # write_report round-trips
        out = os.path.join(tmp, "regression.json")
        assert write_report(r3, out) and json.load(open(out))["scan_id"] == "scan3"
        print("[5] regression.json written and valid  ✓")

        print("\n" + _summary_line(r3))
        print("\nRegression reporter proven against the real correlate lifecycle. ✓")
    finally:
        kaiju_issues.state_dir = orig_state_dir
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    if len(sys.argv) == 1 or sys.argv[1] == "selftest":
        _selftest()
        sys.exit(0)
    sys.exit(main())
