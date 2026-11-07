#!/usr/bin/env python3
"""
ARISE — Reference Knowledge Bundle  (attack_chain_v2.ROADMAP.md Phase 3, part 1)
=================================================================================
Per explicit product direction: MITRE CAPEC is a reference book, not the
algorithm. This module builds a COMPACT, per-scan-relevant slice of it (only
the CAPEC ids implicated by findings actually present in this scan — never
the full 559-pattern catalog) plus ARISE's own curated pattern libraries, and
hands the result to the AI Chain Architect as grounding context — the same
role redteam_skills playbooks already play in arise_autonomous.WORKER_SYSTEM's
prompt (skills_block), reused here rather than reinvented.

Folded in as few-shot reference, never as a mechanical driver:
  - MITRE CAPEC v3.9 (intel/capec_attack_paths.py's own load_capec()) — name,
    prerequisites, consequences, immediate CanPrecede/CanFollow neighbors.
  - arise_autonomous.ATTACK_CHAINS — 21 curated finding-type -> hypothesis rules.
  - capec_attack_paths.CLOUD_CHAINS — 8 hand-authored cloud attack narratives.
  - history/arise_report.py's AP-01..AP-10 — ATT&CK-technique-mapped scenario
    templates; only name/tactics/premise are pulled (not the full evidence-
    gated step logic, which stays exactly where it is and keeps running).

Token-bounded by design — this is prompt context, not a knowledge dump.
"""
from __future__ import annotations

import sys as _sys, os as _os
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)

import re
from typing import Optional


def _capec_slice(finding_kinds: set, patterns: dict, precedes: dict, cwe_index: dict,
                 max_patterns: int = 25) -> str:
    """Only the CAPEC ids a real finding in THIS scan could plausibly map to —
    via intel/capec_attack_paths.py's own LANE_CAPEC lane vocabulary — not the
    full catalog. A finding's `kind`/`category` text is matched against lane
    keywords the same way map_to_capec() already does for nuclei-shaped
    records, generalized here to any finding-graph node's free-text kind."""
    from intel.capec_attack_paths import LANE_CAPEC

    matched_ids: set = set()
    blob_by_kind = {k: k.lower().replace("_", "-") for k in finding_kinds}
    for kind, blob in blob_by_kind.items():
        for lane, cid in LANE_CAPEC.items():
            if lane in blob and cid in patterns:
                matched_ids.add(cid)

    if not matched_ids:
        return "(no CAPEC pattern matched any finding kind present in this scan)"

    lines = []
    for cid in sorted(matched_ids)[:max_patterns]:
        rec = patterns[cid]
        neighbors = sorted(precedes.get(cid, set()))[:5]
        neighbor_names = [patterns[n]["name"] for n in neighbors if n in patterns]
        prereqs = "; ".join(rec.get("prereqs", [])[:3]) or "none stated"
        impacts = sorted({i for c in rec.get("consequences", []) for i in c.get("impact", [])})[:4]
        lines.append(
            f"- CAPEC-{cid} \"{rec['name']}\": prereqs=[{prereqs}]; "
            f"impacts={impacts}; can precede: {neighbor_names or 'none'}"
        )
    return "\n".join(lines)


def _attack_chains_slice(max_rules: int = 21) -> str:
    """21 curated finding-type -> hypothesis rules already wired into the
    autonomous-attack manager's own task generation (arise_autonomous.py) —
    reused here as few-shot ARISE house-style reasoning, not duplicated."""
    from arise_autonomous import ATTACK_CHAINS
    lines = []
    for prereq, hypothesis, discipline, _probe in ATTACK_CHAINS[:max_rules]:
        lines.append(f"- if a confirmed \"{prereq}\" finding exists -> {hypothesis} [{discipline}]")
    return "\n".join(lines)


def _cloud_chains_slice() -> str:
    from intel.capec_attack_paths import CLOUD_CHAINS
    lines = []
    for c in CLOUD_CHAINS:
        lines.append(f"- {c['title']} (CAPEC {c.get('capec', [])}, ATT&CK {c.get('mitre', [])}): "
                     f"{' -> '.join(c.get('steps', []))}")
    return "\n".join(lines)


def _ap_templates_slice() -> str:
    """history/arise_report.py's 10 named, ATT&CK-mapped scenario templates —
    only name/tactics/premise pulled as style/technique-mapping examples; the
    templates themselves keep running unchanged in the report generator."""
    try:
        import ast
        path = _os.path.join(_ROOT, "history", "arise_report.py")
        with open(path) as f:
            src = f.read()
        # Extract the (pid, name, tactic_summary) triples from every
        # _mk_path(...) call without executing arise_report.py's own report
        # logic (which needs live scan signals this module doesn't have) —
        # a light static read of its own source is enough for reference text.
        tree = ast.parse(src)
        out = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and getattr(node.func, "id", "") == "_mk_path":
                args = node.args
                if len(args) >= 3:
                    def _lit(n):
                        return n.value if isinstance(n, ast.Constant) else None
                    pid, name, tactics = _lit(args[0]), _lit(args[1]), _lit(args[2])
                    if pid and name:
                        out.append(f"- {pid} \"{name}\": {tactics}")
        return "\n".join(out) if out else "(no AP templates extracted)"
    except Exception as exc:  # noqa: BLE001 — reference material only, never fatal
        return f"(AP templates unavailable: {exc})"


def build_bundle(kg, capec_xml_path: Optional[str] = None) -> str:
    """The full compact reference bundle text, ready to inject into the Chain
    Architect's system prompt. Never raises: any one sub-bundle failing (e.g.
    CAPEC XML missing) degrades to a short placeholder for that section only."""
    finding_kinds = {n["attrs"].get("kind", "") for n in kg.nodes.values()
                     if n.get("type") == "finding" and n["attrs"].get("kind")}

    capec_text = "(CAPEC unavailable)"
    try:
        from intel.capec_attack_paths import load_capec, DEFAULT_CAPEC
        xml_path = capec_xml_path or DEFAULT_CAPEC
        if _os.path.exists(xml_path):
            patterns, precedes, _parent_of, cwe_index, _oos = load_capec(xml_path)
            capec_text = _capec_slice(finding_kinds, patterns, precedes, cwe_index)
    except Exception as exc:  # noqa: BLE001
        capec_text = f"(CAPEC load failed: {exc})"

    try:
        attack_chains_text = _attack_chains_slice()
    except Exception as exc:  # noqa: BLE001
        attack_chains_text = f"(ATTACK_CHAINS unavailable: {exc})"

    try:
        cloud_chains_text = _cloud_chains_slice()
    except Exception as exc:  # noqa: BLE001
        cloud_chains_text = f"(CLOUD_CHAINS unavailable: {exc})"

    ap_text = _ap_templates_slice()

    return (
        "=== REFERENCE KNOWLEDGE (a guide book, not a script — apply judgment,\n"
        "never invent a chain that isn't grounded in the evidence graph you were\n"
        "given separately) ===\n\n"
        f"MITRE CAPEC patterns relevant to findings in THIS scan:\n{capec_text}\n\n"
        f"ARISE's own curated finding->hypothesis rules:\n{attack_chains_text}\n\n"
        f"ARISE's own cloud attack narratives:\n{cloud_chains_text}\n\n"
        f"ARISE's own named scenario styles (for narrative tone, not content):\n{ap_text}\n"
    )
