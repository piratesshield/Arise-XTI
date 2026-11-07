#!/usr/bin/env python3
"""
ARISE — Chain Narrator  (attack_chain_v2.ROADMAP.md Phase 5)
================================================================
One AI call, two audiences — the same principle MITRE Attack Flow uses (one
graph, rendered for both technical and executive readers) applied to ARISE's
own gated chains + chokepoint fix-list.

Only ever narrates REALIZED chains (intel/chain_gate.py's output) plus the
chokepoint fix-list (intel/chokepoint.py) — a "hypothesis" chain is surfaced
as an open question, never narrated as if it happened, matching the same
"never assert what isn't grounded" discipline as every earlier phase.

Style-anchored on history/arise_report.py's already-proven prose (the
AP-01..AP-10 templates: real evidence citations, plain language, no
speculative claims) via few-shot examples, so AI output matches that
existing quality bar instead of generic LLM narration voice.
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

NARRATOR_SYSTEM = """You are ARISE's report narrator. You receive REALIZED attack chains (already
verified against real evidence — you can trust every fact in them) and a chokepoint fix-list
(the smallest set of findings that, if fixed, breaks every chain given). Write for TWO audiences
from the SAME facts — never invent anything beyond what's given, and never soften or invent
uncertainty for facts already marked realized.

STYLE — match this house style exactly, drawn from ARISE's own existing report generator:
  "The attacker does not need to build infrastructure — it already exists and is one DNS lookup
  from your brand." / "This is not a heuristic: registration is the only step left."
Plain language, leads with the conclusion, cites concrete evidence (hosts, ports, status codes,
CVE ids) inline rather than vaguely, never hedges a fact that's already confirmed.

Respond with ONLY a JSON object (no prose, no markdown fences):
{
  "technical": [
    {"chain_id": "<id>", "narrative": "<phase-by-phase, evidence-cited, for a security analyst>"}
  ],
  "executive": {
    "headline": "<one sentence, the single most important fact>",
    "blast_radius_summary": "<plain language, what could go wrong and how far it spreads>",
    "top_fix_recommendation": "<plain language framing of the chokepoint fix-list — what to fix and why it's enough>",
    "chain_summaries": [{"chain_id": "<id>", "business_impact": "<one or two sentences, no jargon>"}]
  }
}"""


def build_narrator_context(gated: dict, chokepoint: dict) -> str:
    realized = [c for c in gated.get("chains", []) if c.get("status") == "realized"]
    return (
        "=== REALIZED CHAINS (verified — narrate these as fact) ===\n"
        + json.dumps(realized, indent=2)
        + "\n\n=== CHOKEPOINT FIX-LIST ===\n"
        + json.dumps(chokepoint, indent=2)
        + "\n\n=== OPEN QUESTIONS (mention as 'worth investigating', never as fact) ===\n"
        + json.dumps(gated.get("open_questions", []), indent=2)
    )


def _extract_json(text: str) -> Optional[dict]:
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


def narrate(gated: dict, chokepoint: dict, provider: Optional[str] = None,
           model: Optional[str] = None) -> dict:
    """Never raises: no realized chains -> a clean empty result (nothing to
    narrate is not an error); AI failure -> empty result with an error field,
    same degrade-not-crash contract as intel/chain_architect.py."""
    realized = [c for c in gated.get("chains", []) if c.get("status") == "realized"]
    if not realized:
        return {"technical": [], "executive": {
            "headline": "No chain in this scan met the evidence bar to be reported as realized.",
            "blast_radius_summary": "", "top_fix_recommendation": "", "chain_summaries": [],
        }, "error": None}

    from discovery.synth_ai import build_chat_fn
    from arise_autonomous import _safe_chat

    chat_fn, err = build_chat_fn(provider, model)
    if chat_fn is None:
        return {"technical": [], "executive": {}, "error": err}

    user_prompt = build_narrator_context(gated, chokepoint)
    text, chat_err = _safe_chat(chat_fn, NARRATOR_SYSTEM, user_prompt)
    if not text:
        return {"technical": [], "executive": {}, "error": chat_err or "empty response"}

    parsed = _extract_json(text)
    if parsed is None:
        return {"technical": [], "executive": {}, "error": "unparseable AI response",
                "raw_response": text[:2000]}

    parsed.setdefault("technical", [])
    parsed.setdefault("executive", {})
    parsed["error"] = None
    return parsed


def main() -> int:
    ap = argparse.ArgumentParser(description="Chain Narrator (Phase 5)")
    ap.add_argument("scan_dir")
    ap.add_argument("--gated")
    ap.add_argument("--chokepoint")
    ap.add_argument("--provider")
    ap.add_argument("--model")
    ap.add_argument("--out")
    ap.add_argument("--summary", action="store_true")
    args = ap.parse_args()

    gated_path = args.gated or _os.path.join(args.scan_dir, "25_attack_paths", "gated_chains.json")
    chokepoint_path = args.chokepoint or _os.path.join(args.scan_dir, "25_attack_paths", "chokepoint_report.json")
    for p in (gated_path, chokepoint_path):
        if not _os.path.exists(p):
            print(f"error: not found: {p}", file=sys.stderr)
            return 2

    with open(gated_path) as f:
        gated = json.load(f)
    with open(chokepoint_path) as f:
        chokepoint = json.load(f)

    result = narrate(gated, chokepoint, provider=args.provider, model=args.model)

    out_path = args.out or _os.path.join(args.scan_dir, "25_attack_paths", "chain_narrative.json")
    with open(out_path, "w") as f:
        json.dump(result, f, indent=2)

    if args.summary:
        print(f"[chain_narrator] wrote {out_path}", file=sys.stderr)
        print(f"[chain_narrator] {len(result.get('technical', []))} technical narrative(s), "
              f"error={result.get('error')}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
