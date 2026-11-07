#!/usr/bin/env python3
"""
ARISE — Unified Chain Scoring  (attack_chain_v2.ROADMAP.md Phase 2)
=====================================================================
One scoring function for every chain consumer:

    unified_score = criticality x (evidence_rung + 1) x (1 + blast_radius) x exploit_likelihood

Deliberately reuses rather than reimplements:
  - intel/internet_intel.py's _load_kev()/_load_epss() — KEV/EPSS fetching
    already exists there, already cached (.arise_kev_cache.json, 24h TTL),
    already correct. No second implementation.
  - history/arise_report.py's _JUICY_HOST_PATTERNS — the hostname-meaning
    mapping already used by _rank_entry_points(); a criticality-relevant
    subset is reused verbatim below, not rewritten.
  - evidence/arise_evidence.py's ladder_rank() for the evidence axis.

Deliberately does NOT touch cloud_exposure's own weighted_score formula or
arise_report.py's _rank_entry_points() additive scorer — both already work
and are independently tuned for their own consumers. This is a third,
chain-specific score that mutates intel/evidence_graph.py's unified graph in
place, not a replacement for either existing scorer.
"""
from __future__ import annotations

import sys as _sys, os as _os
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)

import argparse
import io
import json
import re
import sys
from collections import defaultdict, deque
from typing import Optional

from evidence.arise_evidence import ladder_rank

# Criticality-relevant subset of arise_report.py's _JUICY_HOST_PATTERNS —
# reused verbatim (same regexes), not rewritten. Payment/auth/admin surfaces
# raise business-impact criticality; dev/staging lowers it — a distinct axis
# from arise_report.py's own "attacker attractiveness" framing, where
# dev/staging actually RAISES the score (weaker controls). Both are correct
# for what they measure; this module measures business impact, not
# attacker convenience.
_CRITICALITY_BOOST = [
    r'(^|[.-])(pay|payment|billing|checkout|invoice|order)([.-]|$)',
    r'(^|[.-])(auth|login|sso|idp|account|oauth)([.-]|$)',
    r'(^|[.-])(admin|manage|console|portal)([.-]|$)',
]
_CRITICALITY_DISCOUNT = [
    r'(^|[.-])(dev|test|staging|stage|uat|qa|sandbox|preprod|demo)([.-]|$)',
]

# Fallback exploit-likelihood by severity when a finding carries no CVE (the
# overwhelming majority of ARISE's own findings — logic/config/exposure
# issues, not versioned software vulnerabilities). Deliberately conservative:
# these are proxy numbers, not real exploit-probability data, so they sit
# below what a genuinely KEV-listed CVE would score (1.0).
_SEVERITY_LIKELIHOOD = {"critical": 0.7, "high": 0.5, "medium": 0.3, "low": 0.1, "info": 0.05}


def _null_log():
    """A throwaway, always-writable sink for internet_intel._load_kev/_load_epss,
    which write progress via logf.write(...) — never None, that would crash."""
    return io.StringIO()


def endpoint_criticality(host: str) -> float:
    """Business-impact multiplier from hostname semantics alone — endpoint-
    level url_class/auth_state/accepts_file signals are folded in by the
    caller when a specific endpoint node is available; this is the
    host-only floor every finding on that host shares."""
    score = 1.0
    h = host or ""
    for pat in _CRITICALITY_BOOST:
        if re.search(pat, h):
            score += 1.5
            break
    for pat in _CRITICALITY_DISCOUNT:
        if re.search(pat, h):
            score *= 0.5
            break
    return score


def _endpoint_criticality_bonus(endpoint_attrs: dict) -> float:
    bonus = 0.0
    if endpoint_attrs.get("auth_state") == "authenticated":
        bonus += 0.5
    if endpoint_attrs.get("accepts_file"):
        bonus += 0.5
    if endpoint_attrs.get("cloud_bucket"):
        bonus += 0.5
    if endpoint_attrs.get("url_class") == "api":
        bonus += 0.3
    return bonus


# Edge types that represent a genuine "blast" step — one asset's compromise
# plausibly extending to another asset, credential, or identity. ROUTES_TO
# (host -> endpoint) is deliberately excluded: a host can carry thousands of
# URL-Inventory endpoints (2,236 on one real host in this audit) with zero
# bearing on how far a specific finding's impact actually spreads — counting
# them turned "which host has the most crawled URLs" into the dominant signal
# and buried a confirmed critical SSRF-to-cloud-metadata finding outside the
# top 5, which is exactly the wrong answer. Blast radius counts REACHABLE
# ASSETS (other hosts, credentials, cloud-assets, identities), not inventory volume.
_BLAST_EDGE_TYPES = {"SAME_ASSET", "USES", "RESOLVES_TO", "RUNS"}
_BLAST_NODE_TYPES = {"host", "credential", "cloud-asset", "identity"}


def _build_adjacency(kg) -> dict:
    adj: dict = defaultdict(set)
    for e in kg.edges:
        if e.get("rel") not in _BLAST_EDGE_TYPES:
            continue
        adj[e["src"]].add(e["dst"])
        adj[e["dst"]].add(e["src"])  # undirected — blast radius cares about
                                     # reachability, not edge direction
    return adj


def blast_radius(kg, adjacency: dict, start_host_id: str, max_hops: int = 2) -> int:
    """Count of distinct OTHER assets (hosts/credentials/cloud-assets/
    identities) reachable from a finding's host within max_hops via
    genuine blast-relevant edges — never via ROUTES_TO's endpoint flood."""
    if start_host_id not in adjacency and start_host_id not in kg.nodes:
        return 0
    seen = {start_host_id}
    frontier = deque([(start_host_id, 0)])
    reachable_assets = 0
    while frontier:
        nid, depth = frontier.popleft()
        if depth >= max_hops:
            continue
        for nxt in adjacency.get(nid, ()):
            if nxt in seen:
                continue
            seen.add(nxt)
            if kg.nodes.get(nxt, {}).get("type") in _BLAST_NODE_TYPES:
                reachable_assets += 1
            frontier.append((nxt, depth + 1))
    return reachable_assets


def exploit_likelihood(cve_id: Optional[str], severity: str,
                       kev: set, epss: dict) -> float:
    if cve_id:
        cve_up = cve_id.upper()
        if cve_up in kev:
            return 1.0
        if cve_up in epss:
            return epss[cve_up]
    return _SEVERITY_LIKELIHOOD.get((severity or "").lower(), 0.1)


def score_graph(kg, timeout: int = 8) -> dict:
    """Mutate kg's finding nodes in place, adding criticality/blast_radius/
    exploit_likelihood/unified_score attrs. Returns a summary. Never raises:
    a KEV/EPSS fetch failure degrades to severity-only likelihood, exactly
    like every other network call in this pipeline degrades rather than
    crashing the scan."""
    from intel.internet_intel import _load_kev, _load_epss  # local import —
    # avoids paying internet_intel's own import cost for callers (e.g. unit
    # tests) that never need network scoring at all.

    cves = set()
    for node in kg.nodes.values():
        if node.get("type") == "finding":
            cve = (node.get("attrs") or {}).get("cve_id")
            if cve:
                cves.add(str(cve).upper())

    kev, epss = set(), {}
    net_error = None
    if cves:
        logf = _null_log()
        try:
            kev = _load_kev(timeout, logf)
            epss = _load_epss(cves, timeout, logf)
        except Exception as exc:  # noqa: BLE001 — degrade, never crash the scan
            net_error = str(exc)[:200]

    adjacency = _build_adjacency(kg)

    # endpoint criticality bonuses, indexed by host, so a finding node (which
    # only carries a host, not a specific endpoint) can still benefit from
    # the richest endpoint on that host — e.g. a WAF-detection host fact
    # co-located with a payment endpoint should score as sensitive as the
    # endpoint itself.
    endpoint_bonus_by_host: dict = defaultdict(float)
    for node in kg.nodes.values():
        if node.get("type") == "endpoint":
            host = (node.get("attrs") or {}).get("host", "")
            bonus = _endpoint_criticality_bonus(node.get("attrs") or {})
            if bonus > endpoint_bonus_by_host[host]:
                endpoint_bonus_by_host[host] = bonus

    scored = 0
    score_sum = 0.0
    for nid, node in kg.nodes.items():
        if node.get("type") != "finding":
            continue
        attrs = node["attrs"]
        host = attrs.get("host", "")
        rung = attrs.get("rung", "L0")
        rung_score = max(ladder_rank(rung), 0) + 1  # 1..7, never zero
        crit = endpoint_criticality(host) + endpoint_bonus_by_host.get(host, 0.0)
        host_id = f"host:{host}" if host else nid
        radius = blast_radius(kg, adjacency, host_id)
        likelihood = exploit_likelihood(attrs.get("cve_id"), attrs.get("severity"), kev, epss)
        unified = crit * rung_score * (1 + radius) * likelihood

        attrs["criticality"] = round(crit, 2)
        attrs["blast_radius"] = radius
        attrs["exploit_likelihood"] = round(likelihood, 3)
        attrs["unified_score"] = round(unified, 2)
        scored += 1
        score_sum += unified

    return {
        "scored_findings": scored,
        "cves_seen": len(cves),
        "kev_matches": len([c for c in cves if c in kev]),
        "epss_scored": len(epss),
        "net_error": net_error,
        "score_sum": round(score_sum, 2),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Unified Chain Scoring (Phase 2)")
    ap.add_argument("scan_dir")
    ap.add_argument("--graph", help="path to evidence_graph.json (default: <scan_dir>/25_attack_paths/evidence_graph.json)")
    ap.add_argument("--summary", action="store_true")
    args = ap.parse_args()

    graph_path = args.graph or _os.path.join(args.scan_dir, "25_attack_paths", "evidence_graph.json")
    if not _os.path.exists(graph_path):
        print(f"error: graph not found: {graph_path} — run intel/evidence_graph.py first", file=sys.stderr)
        return 2

    from core.knowledge_graph import KnowledgeGraph
    with open(graph_path) as f:
        raw = json.load(f)
    kg = KnowledgeGraph()
    for n in raw.get("nodes", []):
        kg.nodes[f"{n['type']}:{n['label']}"] = n
    kg.edges = raw.get("edges", [])

    summary = score_graph(kg)

    with open(graph_path, "w") as f:
        json.dump(kg.to_dict(), f, indent=2)

    if args.summary:
        print(f"[chain_scoring] {json.dumps(summary)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
