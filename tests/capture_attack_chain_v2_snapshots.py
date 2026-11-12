#!/usr/bin/env python3
"""
attack_chain_v2.ROADMAP.md Phase 0 — golden-snapshot capture.

Captures the CURRENT (v1) behavior of the three independent chaining/scoring
systems this redesign unifies — intel/capec_attack_paths.py's on-disk output,
history/arise_report.py's _derive_attack_paths()/_rank_entry_points() (via
dashboard._report_model), and history/kaiju_issues.py's run_rules() — against
a fixed set of real scans, so every later phase can diff its own output
against a known-good baseline instead of guessing whether a change is a fix
or a regression.

This does not touch or invoke anything from Phase 1+ — it only reads what
already exists on disk / what the current pipeline already computes.

Run: python3 tests/capture_attack_chain_v2_snapshots.py
Re-run any time the underlying scan data or v1 code changes intentionally;
the fixtures are meant to be regenerated deliberately, not treated as fixed
forever — they're a snapshot of "today's correct behavior," not a spec.
"""
import os
import sys
import json

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import dashboard  # noqa: E402
from history import kaiju_issues  # noqa: E402

SCANS_DIR = os.path.join(ROOT, "scans")
OUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "attack_chain_v2")

# One target per real-world shape this redesign needs to handle correctly:
# a large multi-subdomain estate with convergent risk (acme-retail.example.com
# — synthetic fixture with 7 compounding-risk hosts, cited in
# ARISE_REMEDIATION_ROADMAP.md P2 item 13), a large modern estate with
# confirmed critical findings but zero nuclei hits (zepto), and a minimal
# single-host CDN-fronted target (x.razorpay.com) — the small-graph edge case.
TARGETS = [
    "zepto.com-250926-0237",
    "x.razorpay.com-240926-2121",
    "acme-retail.example.com-170826-1942",
]


def capec_v1_output(scan_id):
    base = os.path.join(SCANS_DIR, scan_id, "25_attack_paths")
    out = {}
    for fn in ("capec_attack_paths.json", "capec_kg.json"):
        p = os.path.join(base, fn)
        if os.path.exists(p):
            with open(p) as f:
                out[fn] = json.load(f)
        else:
            out[fn] = None
    return out


def report_output(scan_id):
    """arise_report.py's attack paths + entry points, via dashboard's own
    assembly function (_report_model) run inside a fake request context so
    it works standalone, the same way it runs inside a real Flask request."""
    with dashboard.app.test_request_context(f"/report/{scan_id}"):
        model = dashboard._report_model(scan_id)
    if not model:
        return None
    return {
        "path_count": len(model.get("paths", [])),
        "path_ids": [p["id"] for p in model.get("paths", [])],
        "path_severities": {p["id"]: p["severity"] for p in model.get("paths", [])},
        "entry_point_count": len(model.get("entry_points", [])),
        "entry_point_hosts": [e["host"] for e in model.get("entry_points", [])],
        "org_score": model.get("org_score"),
        "grade": model.get("grade"),
    }


def kaiju_output(scan_id):
    entities, relations = dashboard._build_entities_for_target(scan_id)
    if not entities:
        return {"entity_count": 0, "relation_count": 0, "issue_count": 0,
                "issues_by_rule": {}, "compounding_risk_hosts": []}
    computed = kaiju_issues.run_rules(entities, relations)
    by_rule = {}
    for issue in computed:
        by_rule[issue["rule_id"]] = by_rule.get(issue["rule_id"], 0) + 1
    return {
        "entity_count": len(entities),
        "relation_count": len(relations),
        "issue_count": len(computed),
        "issues_by_rule": by_rule,
        "compounding_risk_hosts": [i["ref"] for i in computed
                                   if i["rule_id"] == "compounding-risk"],
    }


def capture(scan_id):
    scan_dir = os.path.join(SCANS_DIR, scan_id)
    if not os.path.isdir(scan_dir):
        print(f"SKIP {scan_id}: scan dir missing")
        return None

    snapshot = {"scan_id": scan_id, "capec_v1": capec_v1_output(scan_id)}
    try:
        snapshot["report"] = report_output(scan_id)
    except Exception as exc:
        snapshot["report_error"] = str(exc)
    try:
        snapshot["kaiju"] = kaiju_output(scan_id)
    except Exception as exc:
        snapshot["kaiju_error"] = str(exc)
    return snapshot


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    written = []
    for scan_id in TARGETS:
        snapshot = capture(scan_id)
        if snapshot is None:
            continue
        out_path = os.path.join(OUT_DIR, f"{scan_id}.json")
        with open(out_path, "w") as f:
            json.dump(snapshot, f, indent=2)
        written.append(out_path)
        print(f"wrote {out_path}")

    # Phase 0's own checkpoint: the onequince snapshot must reproduce the
    # exact figure ARISE_REMEDIATION_ROADMAP.md cites as already-verified —
    # if this doesn't hold, the capture itself is wrong and must not be
    # trusted as a regression baseline.
    acme_path = os.path.join(OUT_DIR, "acme-retail.example.com-170826-1942.json")
    if os.path.exists(acme_path):
        with open(acme_path) as f:
            snap = json.load(f)
        n = len(snap.get("kaiju", {}).get("compounding_risk_hosts", []))
        assert n == 7, (
            f"acme-retail.example.com-170826-1942 compounding-risk count is {n}, expected 7 "
            "(ARISE_REMEDIATION_ROADMAP.md P2 item 13) — capture is not trustworthy "
            "as a regression baseline until this is understood.")
        print("[checkpoint] acme-retail.example.com compounding-risk count == 7 — matches "
              "the roadmap's own verified figure. Capture is trustworthy.")

    print(f"\n{len(written)} golden snapshot(s) written to {OUT_DIR}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
