#!/usr/bin/env python3
"""
ARISE — AI Chain Architect  (attack_chain_v2.ROADMAP.md Phase 3)
===================================================================
The actual AI-driven pivot: one LLM call per scan reasons over the unified
evidence graph (intel/evidence_graph.py) plus a compact reference bundle
(intel/reference_bundle.py) and proposes candidate attack chains — CAPEC and
ARISE's own curated libraries are reference material the model reads, never
a mechanical graph it walks.

Every proposed hop MUST cite real graph node ids. Nothing here trusts the
model's citations at face value — intel/chain_gate.py checks every one
against the graph before a chain is ever labeled "realized," the same
"AI proposes, code disposes" discipline that already fixed arise_autonomous's
own F07 evidence-fabrication bug (a fabricated-but-plausible evidence string
is dropped, not trusted).

Reuses rather than reimplements:
  - discovery.synth_ai.build_chat_fn() — the ALREADY-shared, multi-provider
    (claude/openai/gemini/huggingface) LLM caller, already imported the same
    way by adaptive_loop.py/offensive_engine.py/recon_attack_synth.py. No new
    provider-switching code — an earlier draft of this roadmap assumed three
    independent implementations existed; verifying the actual imports showed
    they already share this one.
  - arise_autonomous._safe_chat() — trivial exception-safe call wrapper.
  - arise_autonomous.MANAGER_SYSTEM's own chain-strategy language (recon gaps
    -> direct exploitation -> lateral movement -> impact validation) as the
    base the Architect's prompt extends.
"""
from __future__ import annotations

import sys as _sys, os as _os
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)

import argparse
import json
import re
import sys
from typing import Optional

ARCHITECT_SYSTEM = """You are ARISE's Attack Chain Architect. You receive an evidence graph — real
findings from a completed security scan, each with a host, a confidence rung (L0-L6, only L4+ is
a confirmed vulnerability), and a unified risk score — plus a REFERENCE bundle of MITRE CAPEC
patterns and ARISE's own curated attack-hypothesis libraries.

Think in attack CHAINS, not isolated findings. Reason in this order, same as ARISE's own
autonomous-attack manager:
  1. Reconnaissance gaps -> what does the evidence graph suggest was missed?
  2. Direct exploitation -> can any single confirmed finding be escalated on its own?
  3. Lateral movement -> can one finding's access enable testing another (leaked credential ->
     authenticated endpoint; SSRF -> internal service; subdomain takeover -> cookie/CORS trust)?
  4. Impact validation -> what is the worst realistic business outcome if this chain plays out?

HARD RULES — a violation makes your entire output worthless, not just one chain wrong:
  - Every hop MUST cite one or more real node ids from the "EVIDENCE GRAPH" section below, using
    the exact id strings given (e.g. "finding:blog.acme-delivery.example.com | ssrf | 2c09525489").
  - NEVER invent a host, endpoint, or finding that is not present in the evidence graph you were
    given. The reference bundle is a guide book for REASONING about what attackers generally do
    next — it is not itself evidence that anything exists on this target.
  - A hop's "confidence" field must honestly reflect the underlying finding's rung: label a hop
    grounded only in an L0-L2 finding as "hypothesis", never "confirmed".
  - If you cannot ground a plausible next step in the graph, say so as an "open_question" instead
    of inventing a hop to fill the gap.

Respond with ONLY a JSON object (no prose, no markdown fences):
{
  "chains": [
    {
      "id": "<short-slug>",
      "title": "<one line>",
      "hops": [
        {"step": "<what happens>", "cites": ["<node id>", "..."], "confidence": "confirmed|hypothesis",
         "rationale": "<why this follows from the cited evidence>"}
      ],
      "worst_case_impact": "<one sentence, plain language>"
    }
  ],
  "open_questions": ["<a plausible next step the evidence doesn't yet support>", "..."]
}
Prefer 2-5 chains. Every chain must have at least one hop. A chain with zero real citations
anywhere in it should not be included at all."""


def _top_findings_context(kg, limit: int = 40) -> "list[dict]":
    """Rank by Phase 2's unified_score (falls back to rung if scoring hasn't
    run yet) and return only the highest-signal findings — the graph can have
    thousands of low-value endpoint nodes; the Architect only needs to see
    what actually matters, with enough context per finding to reason about
    chaining (its host's own attrs, for prerequisite/topology facts)."""
    findings = [(nid, n) for nid, n in kg.nodes.items() if n.get("type") == "finding"]

    def _sort_key(item):
        _nid, n = item
        a = n.get("attrs", {})
        return (a.get("unified_score", 0), _rung_rank(a.get("rung", "L0")))

    findings.sort(key=_sort_key, reverse=True)
    top = findings[:limit]

    host_attrs_cache: dict = {}
    out = []
    for nid, n in top:
        a = n.get("attrs", {})
        host = a.get("host", "")
        host_id = f"host:{host}"
        if host and host_id not in host_attrs_cache:
            hnode = kg.nodes.get(host_id)
            host_attrs_cache[host_id] = hnode.get("attrs", {}) if hnode else {}
        out.append({
            "id": nid,
            "host": host,
            "host_facts": host_attrs_cache.get(host_id, {}),
            "kind": a.get("kind", ""),
            "severity": a.get("severity", ""),
            "rung": a.get("rung", "L0"),
            "confirmed": a.get("confirmed", False),
            "unified_score": a.get("unified_score"),
            "evidence": a.get("evidence") or a.get("impact") or a.get("title") or "",
            "url": a.get("url", ""),
            "source_module": a.get("source_module", ""),
        })
    return out


def _rung_rank(rung: str) -> int:
    from evidence.arise_evidence import ladder_rank
    return max(ladder_rank(rung), 0)


def _same_asset_context(kg) -> "list[dict]":
    """SAME_ASSET edges among hosts — the exact grounding signal that fixed
    capec_attack_paths.py's own trust-crisis bug (chains linking unrelated
    hosts via coincidental CAPEC-ID adjacency). Surfaced explicitly so the
    Architect can reason about multi-host chains without inventing them."""
    out = []
    for e in kg.edges:
        if e.get("rel") == "SAME_ASSET":
            out.append({"a": e["src"], "b": e["dst"]})
    return out


def build_evidence_context(kg, limit: int = 40) -> str:
    findings = _top_findings_context(kg, limit=limit)
    same_asset = _same_asset_context(kg)
    return (
        "=== EVIDENCE GRAPH (top findings by risk score; cite these exact ids) ===\n"
        + json.dumps({"findings": findings, "same_asset_links": same_asset}, indent=2)
    )


def _extract_json(text: str) -> Optional[dict]:
    """Models occasionally wrap JSON in prose or fences despite instructions —
    tolerate that defensively rather than failing the whole call on a
    formatting slip."""
    text = (text or "").strip()
    text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text.strip())
    try:
        return json.loads(text)
    except Exception:
        pass
    m = re.search(r"\{.*\}", text, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(0))
        except Exception:
            return None
    return None


def propose_chains(kg, reference_bundle_text: str, provider: Optional[str] = None,
                   model: Optional[str] = None, finding_limit: int = 40) -> dict:
    """The one AI call per scan. Never raises: any failure (no provider key,
    network error, unparseable response) returns an empty-but-valid result
    with an 'error' field, so the pipeline degrades to 'no AI chains this
    run' rather than crashing the scan."""
    from discovery.synth_ai import build_chat_fn
    from arise_autonomous import _safe_chat

    chat_fn, err = build_chat_fn(provider, model)
    if chat_fn is None:
        return {"chains": [], "open_questions": [], "error": err}

    evidence_text = build_evidence_context(kg, limit=finding_limit)
    user_prompt = f"{reference_bundle_text}\n\n{evidence_text}"

    text, chat_err = _safe_chat(chat_fn, ARCHITECT_SYSTEM, user_prompt)
    if not text:
        return {"chains": [], "open_questions": [], "error": chat_err or "empty response"}

    parsed = _extract_json(text)
    if parsed is None:
        return {"chains": [], "open_questions": [], "error": "unparseable AI response",
                "raw_response": text[:2000]}

    parsed.setdefault("chains", [])
    parsed.setdefault("open_questions", [])
    parsed["error"] = None
    return parsed


def main() -> int:
    ap = argparse.ArgumentParser(description="AI Chain Architect (Phase 3)")
    ap.add_argument("scan_dir")
    ap.add_argument("--graph", help="path to evidence_graph.json")
    ap.add_argument("--provider")
    ap.add_argument("--model")
    ap.add_argument("--out", help="write candidate chains here (default: <scan_dir>/25_attack_paths/chain_architect_candidates.json)")
    ap.add_argument("--summary", action="store_true")
    args = ap.parse_args()

    graph_path = args.graph or _os.path.join(args.scan_dir, "25_attack_paths", "evidence_graph.json")
    if not _os.path.exists(graph_path):
        print(f"error: graph not found: {graph_path} — run intel/evidence_graph.py first", file=sys.stderr)
        return 2

    from core.knowledge_graph import KnowledgeGraph
    from intel.reference_bundle import build_bundle

    with open(graph_path) as f:
        raw = json.load(f)
    kg = KnowledgeGraph()
    for n in raw.get("nodes", []):
        kg.nodes[f"{n['type']}:{n['label']}"] = n
    kg.edges = raw.get("edges", [])

    bundle = build_bundle(kg)
    result = propose_chains(kg, bundle, provider=args.provider, model=args.model)

    out_path = args.out or _os.path.join(args.scan_dir, "25_attack_paths", "chain_architect_candidates.json")
    _os.makedirs(_os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(result, f, indent=2)

    if args.summary:
        print(f"[chain_architect] wrote {out_path}", file=sys.stderr)
        print(f"[chain_architect] {len(result.get('chains', []))} candidate chain(s), "
              f"error={result.get('error')}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
