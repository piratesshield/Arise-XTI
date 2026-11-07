#!/usr/bin/env python3
"""
ARISE — Grounding Gate  (attack_chain_v2.ROADMAP.md Phase 3, part 2)
=======================================================================
"AI proposes, code disposes." Every hop the Chain Architect (intel/
chain_architect.py) proposes is checked HERE, in code, against the real
evidence graph before it is ever trusted as "realized" — the exact discipline
that already fixed arise_autonomous.py's own F07 bug (a verifier that only
checked evidence was non-empty, not that it was real; a fabricated-but-
plausible evidence string used to pass). This module is that same check,
one layer up, for whole chains instead of single findings.

Three checks per hop, all must pass for a hop to be "realized":
  1. Every cited node id actually exists in the graph (rejects hallucinated
     references outright — an id the model invented is not the same failure
     mode as a real citation with weak evidence, and is treated as worse).
  2. Every cited finding's host passes SAME_ASSET grounding against the
     chain's other hops (capec_attack_paths.py's exact same_asset() logic,
     imported unchanged — not reimplemented a second time).
  3. Every cited finding meets an evidence-rung floor (default L3+, per
     ARISE_REMEDIATION_ROADMAP.md §4's own recommendation) — a single
     unconfirmed lead cannot anchor a "confirmed" chain.

A hop that fails any check is never silently dropped OR silently upgraded —
it is demoted to "hypothesis" with the specific reason recorded, so the
narrator (Phase 5) can still mention it honestly as "worth investigating"
without asserting it as fact.
"""
from __future__ import annotations

import sys as _sys, os as _os
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)

import argparse
import json
import sys

RUNG_FLOOR_DEFAULT = "L3"

# Maps a finding's free-text `kind` to one of arise_autonomous.py's own 5
# disciplines (DISCIPLINE_LANES: injection/auth/exposure/recon/chaining) —
# reused verbatim so a hop this Gate produces can be handed straight to the
# autonomous worker without a second translation layer. Unknown kinds default
# to "recon" (the safest, least-presumptuous discipline) rather than guessing.
_DISCIPLINE_KEYWORDS = {
    "injection": ("ssrf", "sqli", "sql", "xss", "ssti", "lfi", "rce",
                  "xxe", "nosqli", "command_injection", "code_injection", "traversal"),
    "auth": ("bola", "idor", "auth", "jwt", "csrf", "mass_assignment",
             "mass-assignment", "no_rate_limiting", "credential", "session"),
    "exposure": ("exposure", "sensitive", "takeover", "missing_waf", "weak_security_headers",
                 "caa_missing", "internal_hostname", "cdn_origin_bypass", "secret",
                 "disclosure", "brand", "code_exposure", "dns_security"),
    "chaining": ("replay_after_delete", "state_matrix", "parity_drift"),
}


def _infer_discipline(kind: str) -> str:
    k = (kind or "").lower().replace("-", "_")
    for discipline, keywords in _DISCIPLINE_KEYWORDS.items():
        if any(kw in k for kw in keywords):
            return discipline
    return "recon"


def _rung_rank(rung: str) -> int:
    from evidence.arise_evidence import ladder_rank
    return ladder_rank(rung)


def _node_host(kg, node_id: str) -> str:
    node = kg.nodes.get(node_id)
    if not node:
        return ""
    return (node.get("attrs") or {}).get("host", "")


# Severity order shared with intel/chain_scoring.py's _SEVERITY_LIKELIHOOD
# vocabulary (not imported — this module stays import-light for the
# dashboard's request path; the 5-entry literal is the whole contract).
_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _citation_detail(kg, cid: str) -> dict:
    """Resolve one 'cites' entry back into the real finding it names — the
    fix for the single most common question a human asks looking at a chain
    hop: 'what IS finding:host|kind|<hash>, and where do I see it?' Every
    field here already lives in the evidence graph (intel/evidence_graph.py's
    normalizers write url/evidence/severity/capec/cwe; intel/chain_scoring.py
    mutates in criticality/blast_radius/unified_score before this file ever
    loads the graph) — this is pure lookup, nothing re-derived."""
    node = kg.nodes.get(cid) or {}
    a = node.get("attrs") or {}
    from evidence.arise_evidence import ladder_meta
    rung = a.get("rung", "L0")
    return {
        "id": cid,
        "host": a.get("host", ""),
        "kind": a.get("kind", ""),
        "rung": ladder_meta(rung),
        "severity": a.get("severity") or "info",
        "url": a.get("url") or "",
        "evidence": a.get("evidence") or a.get("impact") or "",
        "remediation": a.get("remediation") or "",
        "capec": a.get("capec"),
        "cwe": a.get("cwe"),
        "source_module": a.get("source_module") or "",
        "blast_radius": a.get("blast_radius"),
        "unified_score": a.get("unified_score"),
    }


def _hop_evidence_context(kg, cites: list) -> dict:
    """Everything an autonomous planner (or a human) needs to act on a hop
    without re-deriving it: which ARISE module(s) actually produced the
    cited evidence, which host/url/discipline it targets, and the real
    evidence text — pulled straight from the unified graph's node attrs,
    never re-inferred or guessed."""
    sources, hosts, urls, kinds, evidence_texts = [], [], [], [], []
    for cid in cites or []:
        node = kg.nodes.get(cid)
        if not node:
            continue
        a = node.get("attrs") or {}
        if a.get("source_module") and a["source_module"] not in sources:
            sources.append(a["source_module"])
        if a.get("host") and a["host"] not in hosts:
            hosts.append(a["host"])
        if a.get("url") and a["url"] not in urls:
            urls.append(a["url"])
        if a.get("kind") and a["kind"] not in kinds:
            kinds.append(a["kind"])
        ev = a.get("evidence") or a.get("impact") or a.get("title")
        if ev:
            evidence_texts.append(str(ev)[:300] if not isinstance(ev, list) else "; ".join(str(x)[:150] for x in ev[:3]))
    return {
        "sources": sources,
        "target_hosts": hosts,
        "target_urls": urls,
        "discipline": _infer_discipline(kinds[0] if kinds else ""),
        "evidence_texts": evidence_texts,
        # cite id -> full resolved finding (url/evidence/severity/capec/cwe/
        # remediation/blast_radius) — makes every 'cites' entry self-explaining
        # instead of an opaque hash the reader has to go grep a JSONL file for.
        "citations": {cid: _citation_detail(kg, cid) for cid in (cites or []) if cid in kg.nodes},
    }


def check_hop(kg, hop: dict, rung_floor: str = RUNG_FLOOR_DEFAULT) -> dict:
    """Returns the hop with a 'gate' key added: {"status": "realized"|
    "hypothesis", "reasons": [...]}, plus an always-present 'context' key
    (sources/target_hosts/target_urls/discipline/evidence_texts) — attached
    regardless of gate outcome, since a hypothesis hop is exactly the kind of
    "worth testing next" lead the autonomous engine needs this context for.
    Never raises — a malformed hop (missing 'cites', wrong types) fails
    closed as a hypothesis, not an exception."""
    from intel.capec_attack_paths import same_asset

    cites = hop.get("cites") or []
    context = _hop_evidence_context(kg, cites if isinstance(cites, list) else [])

    reasons = []
    if not isinstance(cites, list) or not cites:
        return {**hop, "context": context, "gate": {"status": "hypothesis", "reasons": ["no citations given"]}}

    # Check 1 — every cited id must exist for real.
    missing = [c for c in cites if c not in kg.nodes]
    if missing:
        reasons.append(f"cites non-existent node id(s): {missing}")
        return {**hop, "context": context, "gate": {"status": "hypothesis", "reasons": reasons}}

    # Check 3 — evidence-rung floor (checked before same-asset, since a
    # missing/low rung is a cheaper, more common failure to report clearly).
    floor_rank = _rung_rank(rung_floor)
    weak = []
    for c in cites:
        node = kg.nodes[c]
        if node.get("type") != "finding":
            continue
        rung = (node.get("attrs") or {}).get("rung", "L0")
        if _rung_rank(rung) < floor_rank:
            weak.append((c, rung))
    if weak:
        reasons.append(f"finding(s) below rung floor {rung_floor}: {weak}")
        return {**hop, "context": context, "gate": {"status": "hypothesis", "reasons": reasons}}

    # Check 2 — same-asset grounding across every pair of cited hosts. Uses
    # capec_attack_paths.py's own same_asset(), unchanged — fail-safe-not-open
    # by construction (no shared-IP data => not the same asset).
    hosts = sorted({_node_host(kg, c) for c in cites if _node_host(kg, c)})
    if len(hosts) > 1:
        fqdn_to_ip, _ip_to_fqdns = _host_ip_map(kg)
        for i, a in enumerate(hosts):
            for b in hosts[i + 1:]:
                if not same_asset(a, b, fqdn_to_ip):
                    reasons.append(f"hosts not grounded as the same asset: {a} <-> {b}")

    if reasons:
        return {**hop, "context": context, "gate": {"status": "hypothesis", "reasons": reasons}}

    hop_confidence = (hop.get("confidence") or "").lower()
    if hop_confidence == "confirmed":
        return {**hop, "context": context, "gate": {"status": "realized", "reasons": []}}
    # The model itself only claimed "hypothesis" even though grounding
    # checks passed — honor its own honesty rather than upgrading it.
    return {**hop, "context": context,
            "gate": {"status": "hypothesis", "reasons": ["model marked this as hypothesis, not confirmed"]}}


def _host_ip_map(kg):
    from intel.evidence_graph import host_ip_graph
    return host_ip_graph(kg)


def _chain_rollup(hops: list) -> dict:
    """Aggregate every hop's citations into chain-level answers to the
    questions a human asks before even reading the hops: how bad is this
    (severity), what does it map to for compliance (CAPEC/CWE), how far does
    it reach (blast radius), and what fixes each piece (remediation) — even
    for a hypothesis chain, where intel/chokepoint.py's min-hitting-set
    logic (gated to realized chains only) would otherwise surface nothing."""
    worst_sev, worst_rank = "info", -1
    capec, cwe, max_radius = set(), set(), 0
    remediations = []  # [{host, kind, remediation}], de-duped by (host, kind)
    seen_rem = set()
    for hop in hops:
        for cid, c in ((hop.get("context") or {}).get("citations") or {}).items():
            rank = _SEV_RANK.get((c.get("severity") or "info").lower(), 0)
            if rank > worst_rank:
                worst_rank, worst_sev = rank, (c.get("severity") or "info").lower()
            if c.get("capec"):
                capec.add(c["capec"])
            if c.get("cwe"):
                cwe.add(c["cwe"])
            if isinstance(c.get("blast_radius"), (int, float)):
                max_radius = max(max_radius, c["blast_radius"])
            rem_key = (c.get("host", ""), c.get("kind", ""))
            if c.get("remediation") and rem_key not in seen_rem:
                seen_rem.add(rem_key)
                remediations.append({"host": c.get("host", ""), "kind": c.get("kind", ""),
                                     "remediation": c["remediation"]})
    return {
        "severity": worst_sev,
        "capec_refs": sorted(capec),
        "cwe_refs": sorted(cwe),
        "blast_radius_max": max_radius,
        "remediations": remediations,
    }


def gate_chains(kg, candidates: dict, rung_floor: str = RUNG_FLOOR_DEFAULT) -> dict:
    """Runs every proposed chain's hops through check_hop(). A chain is
    'realized' only if ALL of its hops are; otherwise it's demoted whole
    (a chain is only as strong as its weakest cited hop) but kept, with the
    failing hops' reasons attached, so nothing is silently discarded."""
    from evidence.arise_evidence import LADDER, is_confirmed
    gated_chains = []
    for chain in candidates.get("chains", []):
        hops = [check_hop(kg, h, rung_floor) for h in chain.get("hops", [])]
        all_realized = bool(hops) and all(h["gate"]["status"] == "realized" for h in hops)
        gated_chains.append({
            **chain,
            "hops": hops,
            "status": "realized" if all_realized else "hypothesis",
            **_chain_rollup(hops),
        })
    return {
        "chains": gated_chains,
        "open_questions": candidates.get("open_questions", []),
        "error": candidates.get("error"),
        "rung_floor": rung_floor,
        # Static legend so the dashboard can explain "why hypothesis, not
        # realized" inline instead of a bare L0-L6 code the reader has to
        # already know this codebase's own confidence ladder to parse.
        "rung_legend": [{"code": code, "name": name, "description": desc,
                         "confirmed": is_confirmed(code)} for code, name, desc in LADDER],
    }


def build_autonomous_tasks(gated: dict) -> list:
    """Convert every gated hop into arise_autonomous.py's OWN task schema
    ({discipline, goal, why, chained_from, source_finding} — the exact shape
    _build_chain_tasks() already produces from ATTACK_CHAINS) so the
    autonomous worker can take v2's AI-proposed, code-verified chains as
    seed tasks the same way it already takes its own curated hypotheses —
    no second schema, no translation layer the worker has to learn.

    Every hop becomes a task, realized or hypothesis alike: a realized hop
    is something to ESCALATE (it's proven; the next move is to go further),
    a hypothesis hop is something to INVESTIGATE (it's plausible but
    unconfirmed; the next move is to test it). The gate's own reasons are
    folded into 'why' for hypothesis tasks so the worker understands exactly
    what's missing, not just that something is uncertain.
    """
    tasks = []
    for chain in gated.get("chains", []):
        for i, hop in enumerate(chain.get("hops", [])):
            ctx = hop.get("context") or {}
            gate = hop.get("gate") or {}
            realized = gate.get("status") == "realized"
            host_label = ", ".join(ctx.get("target_hosts") or []) or "target"
            verb = "Escalate confirmed" if realized else "Investigate hypothesized"
            why = hop.get("rationale") or ""
            if not realized and gate.get("reasons"):
                why = f"{why} (not yet confirmed: {'; '.join(gate['reasons'])})".strip()
            tasks.append({
                # arise_autonomous.py's own task schema — unchanged field names:
                "discipline": ctx.get("discipline", "recon"),
                "goal": f"{verb} on {host_label}: {hop.get('step', '')}".strip(),
                "why": why,
                "chained_from": chain.get("id", ""),
                "source_finding": ", ".join(hop.get("cites") or []),
                # Additive — extra context a worker or a human reviewer can use;
                # never required by arise_autonomous's existing consumption.
                "confirmed": realized,
                "sources": ctx.get("sources", []),
                "target_hosts": ctx.get("target_hosts", []),
                "target_urls": ctx.get("target_urls", []),
                "chain_id": chain.get("id", ""),
                "hop_index": i,
            })
    return tasks


def main() -> int:
    ap = argparse.ArgumentParser(description="Grounding Gate (Phase 3)")
    ap.add_argument("scan_dir")
    ap.add_argument("--graph")
    ap.add_argument("--candidates", help="chain_architect_candidates.json")
    ap.add_argument("--rung-floor", default=RUNG_FLOOR_DEFAULT)
    ap.add_argument("--out")
    ap.add_argument("--summary", action="store_true")
    args = ap.parse_args()

    graph_path = args.graph or _os.path.join(args.scan_dir, "25_attack_paths", "evidence_graph.json")
    cand_path = args.candidates or _os.path.join(args.scan_dir, "25_attack_paths", "chain_architect_candidates.json")
    for p in (graph_path, cand_path):
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

    with open(cand_path) as f:
        candidates = json.load(f)

    result = gate_chains(kg, candidates, rung_floor=args.rung_floor)
    # Wall-clock stamp so the dashboard can tell the reader whether this
    # chain analysis reflects findings from before or after a later re-run
    # of an upstream module (e.g. API Security) — gate_chains() itself stays
    # pure/deterministic for testing; "now" only enters here, at write time.
    import datetime
    result["generated_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()

    out_path = args.out or _os.path.join(args.scan_dir, "25_attack_paths", "gated_chains.json")
    with open(out_path, "w") as f:
        json.dump(result, f, indent=2)

    # The autonomous-attack feed — same directory, same naming convention as
    # the other Phase outputs, ready for module_autonomous_attack() to read
    # alongside its existing ATTACK_CHAINS-derived tasks.
    tasks = build_autonomous_tasks(result)
    tasks_path = _os.path.join(_os.path.dirname(out_path), "autonomous_attack_feed.json")
    with open(tasks_path, "w") as f:
        json.dump({"tasks": tasks}, f, indent=2)

    if args.summary:
        realized = sum(1 for c in result["chains"] if c["status"] == "realized")
        print(f"[chain_gate] wrote {out_path}", file=sys.stderr)
        print(f"[chain_gate] {len(result['chains'])} chain(s), {realized} realized, "
              f"{len(result['chains']) - realized} hypothesis", file=sys.stderr)
        print(f"[chain_gate] wrote {tasks_path} — {len(tasks)} autonomous task(s)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
