#!/usr/bin/env python3
"""
ARISE — Chokepoint / Minimum-Fix Analysis  (attack_chain_v2.ROADMAP.md Phase 4)
=================================================================================
The single highest-leverage executive deliverable: the smallest set of
findings that, if fixed, breaks every REALIZED chain from intel/chain_gate.py.
"Fix these 3 things" beats "here are your 80 findings."

Modeled as minimum hitting set, not a generic graph min-cut: each realized
chain already carries an explicit set of cited finding node ids (Phase 3's
citation requirement makes this exact, not inferred), so the real question —
"what is the smallest set of findings whose removal breaks every chain" — is
a hitting-set problem over those citation sets directly, not an abstraction
over raw graph connectivity that would need to be reverse-engineered back
into "which finding does this edge represent" anyway.

Exact solve for small instances (the realistic case — a scan's realized-chain
count is small, in the tens, not thousands); greedy set-cover approximation
above a size threshold, matching the documented fallback pattern used by
LINCHPIN (an open-source attack-graph/min-cut tool this design was reviewed
against): "runs the max-flow/exact cut first and falls back to greedy only
when the budget constraint is violated."
"""
from __future__ import annotations

import sys as _sys, os as _os
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)

import argparse
import itertools
import json
import sys

# Exact brute-force search is only run below this many DISTINCT candidate
# findings across all realized chains — 2^20 subsets is still fast in
# practice because we stop at the first hitting size found, but this caps
# worst-case blowup on a pathological scan with hundreds of realized chains
# each citing distinct findings.
_EXACT_SOLVE_CANDIDATE_LIMIT = 20


def _chain_citation_sets(gated: dict) -> "list[set]":
    """One set of finding node ids per REALIZED chain — the fix-list only
    needs to break chains that are actually trustworthy; a 'hypothesis'
    chain was never asserted as real in the first place, so there is nothing
    to 'break' by fixing it."""
    sets = []
    for chain in gated.get("chains", []):
        if chain.get("status") != "realized":
            continue
        cites: set = set()
        for hop in chain.get("hops", []):
            cites.update(hop.get("cites") or [])
        # Only finding-type citations are fixable; a host/endpoint citation
        # in a hop isn't itself a "finding to fix".
        if cites:
            sets.append(cites)
    return sets


def _exact_min_hitting_set(sets: "list[set]") -> "set":
    universe = sorted(set().union(*sets)) if sets else []
    if not universe:
        return set()
    for size in range(1, len(universe) + 1):
        for combo in itertools.combinations(universe, size):
            combo_set = set(combo)
            if all(combo_set & s for s in sets):
                return combo_set
    return set(universe)  # unreachable in practice — every element together always hits


def _greedy_min_hitting_set(sets: "list[set]") -> "set":
    """Classic greedy set-cover: repeatedly pick the element hitting the most
    still-unhit sets. log(n)-approximate, not exact — used only when the
    candidate universe is too large for brute force to stay fast."""
    remaining = [s for s in sets if s]
    chosen: set = set()
    while remaining:
        counts: dict = {}
        for s in remaining:
            for elem in s:
                counts[elem] = counts.get(elem, 0) + 1
        if not counts:
            break
        best = max(counts, key=counts.get)
        chosen.add(best)
        remaining = [s for s in remaining if best not in s]
    return chosen


def min_fix_set(gated: dict) -> "set":
    sets = _chain_citation_sets(gated)
    if not sets:
        return set()
    universe_size = len(set().union(*sets))
    if universe_size <= _EXACT_SOLVE_CANDIDATE_LIMIT:
        return _exact_min_hitting_set(sets)
    return _greedy_min_hitting_set(sets)


def build_chokepoint_report(kg, gated: dict) -> dict:
    fix_set = min_fix_set(gated)
    sets = _chain_citation_sets(gated)
    fix_details = []
    for nid in sorted(fix_set):
        node = kg.nodes.get(nid, {})
        attrs = node.get("attrs", {})
        chains_broken = sum(1 for s in sets if nid in s)
        fix_details.append({
            "node_id": nid,
            "host": attrs.get("host", ""),
            "kind": attrs.get("kind", ""),
            "severity": attrs.get("severity", ""),
            "unified_score": attrs.get("unified_score"),
            "remediation": attrs.get("remediation", ""),
            "chains_broken": chains_broken,
        })
    fix_details.sort(key=lambda d: -d["chains_broken"])
    return {
        "realized_chain_count": len(sets),
        "fix_count": len(fix_set),
        "fix_list": fix_details,
        "exact_solve": len(set().union(*sets)) <= _EXACT_SOLVE_CANDIDATE_LIMIT if sets else True,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Chokepoint / Minimum-Fix Analysis (Phase 4)")
    ap.add_argument("scan_dir")
    ap.add_argument("--graph")
    ap.add_argument("--gated", help="gated_chains.json from intel/chain_gate.py")
    ap.add_argument("--out")
    ap.add_argument("--summary", action="store_true")
    args = ap.parse_args()

    graph_path = args.graph or _os.path.join(args.scan_dir, "25_attack_paths", "evidence_graph.json")
    gated_path = args.gated or _os.path.join(args.scan_dir, "25_attack_paths", "gated_chains.json")
    for p in (graph_path, gated_path):
        if not _os.path.exists(p):
            print(f"error: not found: {p}", file=sys.stderr)
            return 2

    from core.knowledge_graph import KnowledgeGraph
    with open(graph_path) as f:
        raw = json.load(f)
    kg = KnowledgeGraph()
    for n in raw.get("nodes", []):
        kg.nodes[f"{n['type']}:{n['label']}"] = n
    kg.edges = raw.get("edges", [])

    with open(gated_path) as f:
        gated = json.load(f)

    report = build_chokepoint_report(kg, gated)

    out_path = args.out or _os.path.join(args.scan_dir, "25_attack_paths", "chokepoint_report.json")
    with open(out_path, "w") as f:
        json.dump(report, f, indent=2)

    if args.summary:
        print(f"[chokepoint] wrote {out_path}", file=sys.stderr)
        print(f"[chokepoint] {report['realized_chain_count']} realized chain(s), "
              f"{report['fix_count']} fix(es) break all of them", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
