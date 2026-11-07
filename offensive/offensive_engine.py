#!/usr/bin/env python3
"""
ARISE — Unified Offensive Engine
================================
Wires the two attack-forming brains that used to run side-by-side into ONE tool:

  recon_attack_synth  (DETERMINISTIC backbone)   — recon → nuclei templates → execute
  arise_autonomous    (ADAPTIVE brain)           — LLM chases what templates can't

They now share the four things that make them one engine, not two:
  • SCOPE     — the same ai_probing.ScopeGuard SSRF/scope firewall
  • CONTEXT   — the autonomous engine is SEEDED by the synth's output (asset graph
                + every finding + hot hosts), fixing the "garbage in" problem its
                own analysis flagged: it starts from the full picture, not a blob
  • FINDINGS  — confirmed autonomous findings are written nuclei-shaped, so the
                SAME validator (internet_intel) and chainer (capec_attack_paths)
                consume them exactly like a template hit
  • GRAPH     — one KnowledgeGraph carries assets + findings + discoveries onward

The backbone always runs (no API key needed). The autonomous layer is opt-in
(--autonomous, needs a key) and bounded + non-destructive (arise_autonomous's
code-enforced firewall: allowlisted tools, safe verbs, no exploit/upload flags).

Flow:
  synth ──▶ build shared context ──▶ autonomous (bounded) ──▶ merge findings ──▶
  offensive_summary.json  (+ autonomous_results.txt appended to nuclei_results.txt)
  → internet_intel validates → capec_attack_paths chains

Usage:
    python3 offensive_engine.py <scan_dir> [--synth] [--autonomous]
        [--out DIR] [--target T] [--ai-provider P] [--ai-model M]
        [--max-actions N] [--objective "..."] [--summary]

Default (no flags) runs the synth backbone only. --autonomous adds the brain.
"""
from __future__ import annotations

import sys as _sys, os as _os
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)


import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone

import discovery.recon_attack_synth as synth
try:
    import discovery.synth_ai as synth_ai
except Exception:
    synth_ai = None
try:
    import arise_autonomous                    # the adaptive brain
except Exception:
    arise_autonomous = None


# ---------------------------------------------------------------------------
# Small readers
# ---------------------------------------------------------------------------

def _iter_jsonl(path):
    try:
        with open(path, errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        yield json.loads(line)
                    except Exception:
                        continue
    except OSError:
        return


def _read_json(path, default=None):
    try:
        with open(path) as fh:
            return json.load(fh)
    except Exception:
        return {} if default is None else default


def _target_from_scandir(scan_dir):
    base = os.path.basename(os.path.abspath(scan_dir))
    return re.sub(r"-\d{6}-\d{3,6}$", "", base)  # strip -DDMMYY-HHMM


# ---------------------------------------------------------------------------
# Shared context — the rich picture the autonomous engine is seeded with
# ---------------------------------------------------------------------------

SEV_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "unknown": 1}


def build_context(scan_dir, target, synth_manifest):
    findings = synth.load_findings(scan_dir)
    # top findings, most-severe first
    def _fv(f):
        info = f.get("info", {}) if isinstance(f.get("info"), dict) else {}
        return {
            "title": info.get("name") or f.get("template-id") or f.get("name") or "finding",
            "severity": (info.get("severity") or f.get("severity") or "unknown").lower(),
            "host": synth._host_only(f.get("host") or f.get("matched-at") or f.get("url") or ""),
            "source": "nuclei/synth",
            "matched": (f.get("matched-at") or f.get("url") or "")[:200],
            "cwes": ((info.get("classification") or {}).get("cwe-id") or []),
        }
    fvs = [_fv(f) for f in findings]
    fvs.sort(key=lambda v: -SEV_RANK.get(v["severity"], 1))

    # sensitive non-web services (seed_from_context reads this)
    services = []
    svc = _read_json(os.path.join(scan_dir, "07_service_fingerprint", "services.json"), {})
    for s in (svc.get("services") if isinstance(svc, dict) else svc) or []:
        if isinstance(s, dict) and s.get("host"):
            services.append({"host": s.get("host"), "port": s.get("port"),
                             "service": s.get("service") or s.get("product") or ""})
    # api endpoints (from the routing inventory)
    api_findings = []
    for r in synth.load_attack_routing(scan_dir):
        if r.get("url_class") == "api" and r.get("url"):
            api_findings.append({"endpoint": r["url"], "issue": r.get("attack") or "api"})
        if len(api_findings) >= 40:
            break
    # cve list from findings
    cves = []
    for v in fvs:
        for c in (v["cwes"] if isinstance(v["cwes"], list) else [v["cwes"]]):
            m = re.search(r"CVE-\d{4}-\d+", str(c), re.I)
            if m:
                cves.append({"cve": m.group(0)})

    # Response intelligence findings (Module 26) — PII, secrets, info disclosure.
    # High-value attack-chaining inputs: a leaked credential is an auth bypass.
    ri_findings = []
    ri_file = os.path.join(scan_dir, "26_response_intel",
                           "response_findings_deduped.jsonl")
    if os.path.isfile(ri_file):
        for rec in _iter_jsonl(ri_file):
            ri_findings.append({
                "type": rec.get("type", ""),
                "category": rec.get("category", ""),
                "severity": rec.get("severity", "info"),
                "evidence": (rec.get("evidence") or "")[:120],
                "url": (rec.get("url") or "")[:200],
                "host": rec.get("host", ""),
            })
            if len(ri_findings) >= 30:
                break

    rsum = (synth_manifest or {}).get("recon_summary", {})
    fi = (synth_manifest or {}).get("findings_informed", {})
    return {
        "target": target,
        "sensitive_services": services[:30],
        "top_vulnerabilities": fvs[:25],
        "cves": cves[:10],
        "api_findings": api_findings[:40],
        "response_intel_findings": ri_findings,
        "synth": {
            "template_counts": (synth_manifest or {}).get("template_counts", {}),
            "tech_tags": (synth_manifest or {}).get("tech_tags", []),
            "hot_hosts": fi.get("hot_hosts", []),
            "hosts": rsum.get("target_hosts", [])[:25],
            "tech_by_host": rsum.get("tech_by_host", {}),
        },
        "findings_total": len(findings),
    }


def load_attack_paths(scan_dir):
    """The tagged possible-attack chains produced by capec_attack_paths (L6)."""
    d = _read_json(os.path.join(scan_dir, "25_attack_paths", "capec_attack_paths.json"), {})
    return d.get("paths", []) if isinstance(d, dict) else []


def load_autonomous_feed(scan_dir):
    """attack_chain_v2.ROADMAP.md's own structured feed — every hop from the
    AI Chain Architect's chains, already checked against the real evidence
    graph by intel/chain_gate.py (intel/chain_gate.py:build_autonomous_tasks).
    Additive alongside load_attack_paths() above: v1's tagged CAPEC chains
    keep driving the objective exactly as before when v2 hasn't been run for
    this scan (empty list -> synth_objective()'s existing behavior is
    unchanged)."""
    d = _read_json(os.path.join(scan_dir, "25_attack_paths", "autonomous_attack_feed.json"), {})
    return d.get("tasks", []) if isinstance(d, dict) else []


def synth_objective(target, context, paths=None, v2_tasks=None):
    """Objective for the autonomous engine. When attack paths exist, the engine is
    DRIVEN BY the tagged chains (their next_actions); otherwise it falls back to the
    hottest findings. No user input — the plan comes from the analyzer."""
    lines = [f"Execute and validate the highest-value attack chains on {target}. "
             f"You are aimed by ARISE's CAPEC attack-path analyzer — work its tagged chains."]
    if paths:
        lines.append("\nTAGGED ATTACK CHAINS to execute (highest score first):")
        for p in paths[:6]:
            e = p.get("entry", {})
            fnd = e.get("finding", {})
            loc = (fnd.get("location") or {}).get("matched_at") or e.get("host", "")
            lines.append(f"  - [{p.get('score')}] {p.get('narrative', '')[:130]}")
            if loc:
                lines.append(f"      entry at: {loc}")
            if p.get("next_action"):
                lines.append(f"      NEXT MOVE: {p['next_action'][:170]}")
    if v2_tasks:
        # Confirmed-hop tasks (escalate what's already proven) sort first —
        # the same "prove the strongest thing first" ordering v1's paths use
        # (highest score first).
        ordered = sorted(v2_tasks, key=lambda t: not t.get("confirmed"))
        lines.append("\nAI-PROPOSED, EVIDENCE-VERIFIED CHAIN STEPS (attack_chain_v2 — "
                     "each already checked against real findings before being listed here):")
        for t in ordered[:8]:
            tag = "CONFIRMED" if t.get("confirmed") else "hypothesis"
            src = ", ".join(t.get("sources") or []) or "unknown source"
            lines.append(f"  - [{tag} · {t.get('discipline','recon')} · from {src}] {t.get('goal','')[:170]}")
            if t.get("why"):
                lines.append(f"      why: {t['why'][:170]}")
    if not paths and not v2_tasks:
        top = context["top_vulnerabilities"][:5]
        hot = context["synth"].get("hot_hosts", [])[:5]
        if top:
            lines.append("Hottest findings to work from:")
            for v in top:
                lines.append(f"  - [{v['severity']}] {v['title']} @ {v['host']}")
        if hot:
            lines.append("Hosts that already yielded hits (deepen these): " + ", ".join(hot))
    lines.append(
        "\nFor each chain: run the minimal CONFIRMING request per the matching skill playbook, "
        "prove the hop with a PoC, then advance one step along the chain "
        "(exposure→credentials→access, IDOR→data, SSRF→metadata, version-swap→hidden API). "
        "Stay strictly in scope. Confirm, never exploit. Report only what a real response proves."
    )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Autonomous findings → nuclei shape (so validation + chaining consume them)
# ---------------------------------------------------------------------------

def _to_nuclei_shape(finding, i):
    title = str(finding.get("title") or finding.get("name") or f"autonomous-finding-{i}")
    sev = str(finding.get("severity") or "info").lower()
    loc = finding.get("location") if isinstance(finding.get("location"), dict) else {}
    host = finding.get("host") or loc.get("url") or finding.get("url") or finding.get("endpoint") or ""
    matched = loc.get("url") or finding.get("matched-at") or finding.get("evidence") or host
    evidence = [str(x)[:200] for x in (finding.get("poc"), finding.get("evidence")) if x]
    slug = re.sub(r"[^a-z0-9]+", "-", title.lower())[:48].strip("-") or f"autonomous-{i}"
    return {
        "template-id": f"autonomous-{slug}",
        "info": {"name": title, "severity": sev if sev in SEV_RANK else "info",
                 "description": str(finding.get("rationale") or finding.get("fix") or "")[:300],
                 "tags": ["arise", "autonomous"] + ([finding["discipline"]] if finding.get("discipline") else [])},
        "host": host,
        "matched-at": matched,
        "extracted-results": evidence,
        "source": "autonomous",
    }


def write_autonomous_findings(confirmed, scan_dir):
    if not confirmed:
        return 0
    nd12 = os.path.join(scan_dir, "12_nuclei_scanning")
    os.makedirs(nd12, exist_ok=True)
    shaped = [_to_nuclei_shape(f, i) for i, f in enumerate(confirmed)]
    ar = os.path.join(nd12, "autonomous_results.txt")
    with open(ar, "w") as fh:
        for s in shaped:
            fh.write(json.dumps(s) + "\n")
    # append into the main nuclei file so internet_intel + capec + dashboard see them
    with open(os.path.join(nd12, "nuclei_results.txt"), "a") as fh:
        for s in shaped:
            fh.write(json.dumps(s) + "\n")
    return len(shaped)


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def run_offensive(scan_dir, out_dir, target, do_synth, do_autonomous,
                  ai_provider, ai_model, max_actions, objective, scope_roots):
    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scan_dir": os.path.abspath(scan_dir),
        "target": target,
        "synth": {"ran": False},
        "autonomous": {"ran": False, "enabled": bool(do_autonomous)},
    }

    # ── 1. Deterministic backbone ─────────────────────────────────────────
    synth_manifest = _read_json(os.path.join(out_dir, "synth_manifest.json"), {})
    if do_synth:
        man, err = synth.synthesize(scan_dir, out_dir, max_hosts=25, per_host_cap=60,
                                    emit_fuzz=True, allow_mutation=False)
        if err:
            summary["synth"] = {"ran": False, "error": err}
        else:
            synth_manifest = man
            summary["synth"] = {"ran": True,
                                "templates": sum(man.get("template_counts", {}).values()),
                                "template_counts": man.get("template_counts", {}),
                                "findings_informed": man.get("findings_informed", {})}

    # ── 2. Shared context ─────────────────────────────────────────────────
    context = build_context(scan_dir, target, synth_manifest)
    summary["context"] = {
        "findings_total": context["findings_total"],
        "top_findings": context["top_vulnerabilities"][:8],
        "hot_hosts": context["synth"].get("hot_hosts", []),
        "api_endpoints": len(context["api_findings"]),
    }

    # ── 3. Adaptive brain (opt-in, seeded by the synth) ───────────────────
    if do_autonomous:
        if not (synth_ai and arise_autonomous):
            summary["autonomous"]["error"] = "synth_ai/arise_autonomous unavailable"
        else:
            chat_fn, cerr = synth_ai.build_chat_fn(ai_provider, ai_model)
            if not chat_fn:
                summary["autonomous"]["error"] = cerr or "no chat provider"
            else:
                paths = load_attack_paths(scan_dir)   # the tagged chains drive the attack
                v2_tasks = load_autonomous_feed(scan_dir)  # attack_chain_v2 — additive, never required
                obj = objective or synth_objective(target, context, paths, v2_tasks)
                summary["autonomous"]["driven_by"] = ("attack_paths+v2" if (paths and v2_tasks)
                                                      else "attack_paths" if paths
                                                      else "v2_chain_feed" if v2_tasks else "findings")
                summary["autonomous"]["chains_targeted"] = len(paths)
                summary["autonomous"]["v2_tasks_targeted"] = len(v2_tasks)
                scope = synth_ai.ScopeGuard(target, allowlist=(scope_roots or context["synth"].get("hosts", [])))
                cfg = arise_autonomous.AutonomousConfig(
                    enabled=True, max_actions=max_actions,
                    audit_log_path=os.path.join(out_dir, "autonomous_audit.log"))
                result = arise_autonomous.run_autonomous(context, target, obj, chat_fn, cfg, scope)
                nwritten = write_autonomous_findings(result.confirmed_findings, scan_dir)
                # persist the enriched knowledge graph (feeds capec)
                with open(os.path.join(out_dir, "autonomous_kg.json"), "w") as fh:
                    json.dump(result.knowledge_graph, fh, indent=2)
                summary["autonomous"] = {
                    "ran": True, "enabled": True,
                    "objective": obj,
                    "tasks": len(result.tasks),
                    "actions": len(result.actions),
                    "candidate_findings": len(result.candidate_findings),
                    "confirmed_findings": len(result.confirmed_findings),
                    "written_to_pipeline": nwritten,
                    "kg_summary": (result.knowledge_graph or {}).get("summary", {}),
                    "error": result.error or None,
                    "model_summary": (result.summary or "")[:600],
                }

    with open(os.path.join(out_dir, "offensive_summary.json"), "w") as fh:
        json.dump(summary, fh, indent=2)
    return summary


def main():
    ap = argparse.ArgumentParser(description="ARISE Unified Offensive Engine (synth + autonomous)")
    ap.add_argument("scan_dir")
    ap.add_argument("--out", help="output dir (default: <scan_dir>/08d_attack_synth)")
    ap.add_argument("--target", help="target apex (default: inferred from scan dir name)")
    ap.add_argument("--synth", action="store_true", help="run the deterministic synth backbone")
    ap.add_argument("--autonomous", action="store_true", help="run the adaptive autonomous brain (needs API key)")
    ap.add_argument("--ai-provider", help="claude|openai|gemini|huggingface")
    ap.add_argument("--ai-model")
    ap.add_argument("--max-actions", type=int, default=25, help="autonomous action budget")
    ap.add_argument("--objective", help="override the autonomous objective")
    ap.add_argument("--summary", action="store_true")
    args = ap.parse_args()

    if not os.path.isdir(args.scan_dir):
        print(f"error: not a directory: {args.scan_dir}", file=sys.stderr)
        return 2
    out_dir = args.out or os.path.join(args.scan_dir, "08d_attack_synth")
    os.makedirs(out_dir, exist_ok=True)
    target = args.target or _target_from_scandir(args.scan_dir)
    # default: if neither flag given, run the synth backbone
    do_synth = args.synth or not (args.synth or args.autonomous)

    s = run_offensive(args.scan_dir, out_dir, target, do_synth, args.autonomous,
                      args.ai_provider, args.ai_model, args.max_actions, args.objective, None)

    syn = s.get("synth", {})
    au = s.get("autonomous", {})
    print(f"[offensive] target={target} | synth={'✓ ' + str(syn.get('templates', 0)) + ' tmpl' if syn.get('ran') else 'skipped'}"
          f" | autonomous={'✓' if au.get('ran') else ('off' if not au.get('enabled') else 'skipped: ' + str(au.get('error')))}")
    if args.summary:
        if syn.get("template_counts"):
            print("  synth:", ", ".join(f"{k}={v}" for k, v in syn["template_counts"].items()))
        if au.get("ran"):
            print(f"  autonomous: {au['actions']} actions, {au['confirmed_findings']} confirmed "
                  f"→ {au['written_to_pipeline']} merged into pipeline; KG {au.get('kg_summary')}")
            if au.get("error"):
                print(f"  autonomous note: {au['error']}")
        print(f"  → {os.path.join(out_dir, 'offensive_summary.json')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
