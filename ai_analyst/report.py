"""
AriseAI — artifact writer.

Emits the red-team deliverable set into <scan_dir>/28_ai_analyst/:
  * ariseai_pentest_report.md   — the operator report (read this first)
  * findings/<slug>.md          — one proof-of-concept file per proven finding
  * ariseai_findings.json / csv — structured index for ticketing/automation
  * ariseai_findings.sarif      — SARIF 2.1.0 for code-scanning / ASPM ingestion
  * ai_analyst_result.json      — machine record the dashboard reads back

Findings are presented RANKED BY PROVEN IMPACT (unauthenticated > cross-tenant >
authenticated > unproven observation), never by nominal severity. Every file is
written defensively; a write failure degrades to a partial artifact set.
"""

from __future__ import annotations

import csv
import json
import os
import re
import time
from typing import Any, Dict, List

from ai_analyst import constants as C
from ai_analyst.adversary import TACTIC_LABELS


def _slug(text: str, n: int = 56) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", (text or "finding").lower()).strip("-")
    return (s[:n].strip("-") or "finding")


def _sarif_level(sev: str) -> str:
    return {"critical": "error", "high": "error", "medium": "warning",
            "low": "note", "info": "note"}.get((sev or "info").lower(), "note")


# --- the three-part operator story: what we did / what came back / what it means
def _did(f: Dict[str, Any]) -> str:
    """WHAT ARISEAI DID — the concrete request/command sent to the target."""
    if f.get("action"):
        return str(f["action"])
    tx = f.get("exploit_transcript") or []
    cmds = [t.get("command") for t in tx if t.get("command") and not t.get("refused")]
    if cmds:
        return "\n".join(cmds[:6])
    # request_line carries the ATTACK request (payload in place); prefer it over
    # the plain-URL curl so "what we did" shows the actual exploit request.
    if f.get("request_line"):
        rl = str(f["request_line"])
        if f.get("payload") and f["payload"] not in rl:
            rl += f"    (payload: {f['payload']})"
        return rl
    if f.get("curl_command"):
        return str(f["curl_command"])
    return ""


def _got(f: Dict[str, Any]) -> str:
    """WHAT CAME BACK — the observable result that proves it."""
    if f.get("result"):
        return str(f["result"])
    if f.get("exploit_proof"):
        return str(f["exploit_proof"])
    bits = []
    b, a = f.get("baseline") or {}, f.get("attack") or {}
    if b or a:
        bits.append(f"response changed: baseline [status {b.get('status','?')}, {b.get('len','?')} bytes] "
                    f"→ attack [status {a.get('status','?')}, {a.get('len','?')} bytes]")
    # the last tool output, if this was exploited live
    tx = f.get("exploit_transcript") or []
    outs = [t.get("output") for t in tx if t.get("output")]
    if outs:
        bits.append(outs[-1][:500])
    if f.get("evidence"):
        bits.append(str(f["evidence"])[:500])
    return "\n".join(x for x in bits if x)


def _means(f: Dict[str, Any]) -> str:
    """WHAT IT MEANS — the business/security impact."""
    return str(f.get("impact") or f.get("exploit_impact") or "")


def write_artifacts(scan_dir: str, result: Dict[str, Any]) -> Dict[str, str]:
    """Write all artifacts. Returns a map of {artifact_key: path} for what landed."""
    out_dir = os.path.join(scan_dir, C.OUTPUT_SUBDIR)
    find_dir = os.path.join(out_dir, C.FINDINGS_DIR)
    try:
        os.makedirs(find_dir, exist_ok=True)
    except OSError:
        return {}

    findings: List[Dict[str, Any]] = result.get("findings", [])
    written: Dict[str, str] = {}

    # Per-finding PoC markdown.
    for i, f in enumerate(findings, 1):
        slug = f"{i:02d}-{f.get('severity','info')}-{_slug(f.get('vuln_class') or f.get('title'))}"
        path = os.path.join(find_dir, f"{slug}.md")
        try:
            with open(path, "w") as fh:
                fh.write(_finding_md(f))
            f["poc_file"] = os.path.join(C.OUTPUT_SUBDIR, C.FINDINGS_DIR, f"{slug}.md")
        except OSError:
            pass

    # Main report.
    rp = os.path.join(out_dir, C.REPORT_MD)
    _safe_write(rp, _report_md(result), written, "report_md", scan_dir)

    # JSON index.
    jp = os.path.join(out_dir, C.FINDINGS_JSON)
    _safe_write(jp, json.dumps(findings, indent=2), written, "findings_json", scan_dir)

    # CSV index.
    cp = os.path.join(out_dir, C.FINDINGS_CSV)
    try:
        with open(cp, "w", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(["rank", "tier", "severity", "vuln_class", "owasp_web",
                        "owasp_api", "cwe", "host", "url", "parameter",
                        "confidence", "proven", "title"])
            for i, f in enumerate(findings, 1):
                w.writerow([i, C.TIER_LABEL.get(f.get("impact_tier", 3), ""),
                            f.get("severity", ""), f.get("vuln_class", ""),
                            f.get("owasp_web", ""), f.get("owasp_api", ""),
                            f.get("cwe", ""), f.get("host", ""), f.get("url", ""),
                            f.get("parameter", ""), f.get("confidence", ""),
                            f.get("proven", False), f.get("title", "")])
        written["findings_csv"] = os.path.relpath(cp, scan_dir)
    except OSError:
        pass

    # SARIF 2.1.0.
    sp = os.path.join(out_dir, C.FINDINGS_SARIF)
    _safe_write(sp, json.dumps(_sarif(result), indent=2), written, "findings_sarif", scan_dir)

    # Machine record for the dashboard.
    mp = os.path.join(out_dir, C.RESULT_JSON)
    _safe_write(mp, json.dumps(result, indent=2), written, "result_json", scan_dir)

    return written


def _safe_write(path, text, registry, key, scan_dir):
    try:
        with open(path, "w") as fh:
            fh.write(text)
        registry[key] = os.path.relpath(path, scan_dir)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Markdown rendering
# ---------------------------------------------------------------------------
def _report_md(result: Dict[str, Any]) -> str:
    target = result.get("target", "")
    writeup = result.get("writeup", {}) or {}
    findings = result.get("findings", [])
    hyps = result.get("hypotheses", [])
    cov = result.get("coverage", {}) or {}
    L = []
    L.append(f"# AriseAI — Autonomous Red-Team Pentest")
    L.append("")
    L.append(f"**Target:** {target}  ")
    L.append(f"**Engine:** {C.ENGINE_NAME} (AI-driven, hybrid reason-then-verify)  ")
    L.append(f"**Generated:** {result.get('generated_at', '')}  ")
    L.append(f"**LLM:** {result.get('provider','?')} / {result.get('model','?')}  ")
    proven_n = sum(1 for f in findings if f.get("proven"))
    L.append(f"**Result:** {proven_n} proven finding(s), "
             f"{len(findings) - proven_n} unproven observation(s), "
             f"{len([h for h in hyps if h.get('status')=='realized'])} hypothesis(es) confirmed live.")
    L.append("")
    L.append("> ⚑ This report was produced by an AI red-team agent. Every *proven* "
             "finding below carries live proof-of-concept evidence; observations are "
             "labelled as unproven and must be validated before remediation sign-off.")
    L.append("")

    # Target & attack surface — what was tested.
    L.append("## Target & attack surface")
    L.append(f"- **Target:** {target}")
    L.append(f"- **Scope tested:** {cov.get('hosts', 0)} host(s), {cov.get('endpoints', 0)} endpoint(s) "
             f"from the EASM scan")
    L.append(f"- **Evidence reasoned over:** {cov.get('evidence_items', 0)} item(s)")
    L.append(f"- **Attack hypotheses:** {cov.get('hypotheses_total', 0)} formed, "
             f"{cov.get('hypotheses_rejected', 0)} rejected by the grounding gate, "
             f"{cov.get('hypotheses_realized', 0)} confirmed live")
    if cov.get("live_verify_ran") or cov.get("autonomous_ran"):
        L.append(f"- **Live testing:** differential verify={'yes' if cov.get('live_verify_ran') else 'no'}, "
                 f"autonomous exploitation={'yes' if cov.get('autonomous_ran') else 'no'} "
                 f"({cov.get('autonomous_actions', 0)} actions, {cov.get('autonomous_confirmed', 0)} exploited)")
    else:
        L.append("- **Live testing:** reasoning + report only (no new traffic sent this run)")
    L.append("")

    # Adversary profile + kill chain.
    adv_name = result.get("adversary_profile")
    kchain = result.get("killchain") or {}
    if adv_name:
        L.append(f"**Adversary Emulation:** {adv_name}  ")
    if kchain:
        L.append(f"**Kill Chain Depth:** {kchain.get('engagement_depth', 0)}/10 "
                 f"(deepest: {kchain.get('deepest_tactic', '?')})  ")
        L.append(f"**Breach Paths:** {len(kchain.get('breach_paths', []))}  ·  "
                 f"**Pivots Generated:** {kchain.get('pivots_generated', 0)}  ")
    L.append("")

    L.append("## Executive summary")
    L.append(writeup.get("executive_summary") or _fallback_exec(result))
    L.append("")

    # Demonstrated exploitation — the headline (Tier 3, read-only prove-impact).
    exploited = [f for f in findings if f.get("exploited")]
    if exploited:
        L.append("## 🎯 Demonstrated exploitation")
        L.append(f"AriseAI actively exploited {len(exploited)} finding(s) and proved impact "
                 "with live, read-only evidence:")
        L.append("")
        for f in exploited:
            L.append(f"### {f.get('title','exploit')} — {f.get('severity','')}")
            L.append(f"- **Where:** {f.get('host','')} {('`'+f['url']+'`') if f.get('url') else ''}"
                     + (f"  (param `{f['parameter']}`)" if f.get("parameter") else ""))
            L.append(f"- **OWASP:** {f.get('owasp_web','')} | {f.get('owasp_api','')}  ·  {f.get('cwe','')}")
            if f.get("exploit_impact"):
                L.append(f"- **Impact:** {f['exploit_impact']}")
            if f.get("exploit_proof"):
                L.append(f"\n**Proof (read-only):**\n```\n{str(f['exploit_proof'])[:1200]}\n```")
            tx = f.get("exploit_transcript") or []
            cmds = [t.get("command") for t in tx if t.get("command") and not t.get("refused")]
            if cmds:
                L.append(f"\n**Commands that landed:**\n```bash\n" + "\n".join(cmds[:8]) + "\n```")
            L.append("")

    # Attack chains.
    chains = writeup.get("chains") or []
    if chains:
        L.append("## Attack chains")
        for c in chains:
            L.append(f"### {c.get('name','chain')}")
            path = c.get("path") or []
            if path:
                L.append("  →  ".join(str(p) for p in path))
            if c.get("hosts"):
                L.append(f"\n*Hosts:* {', '.join(c['hosts'])}")
            if c.get("proven_links"):
                L.append(f"\n*Proven links:* {', '.join(c['proven_links'])}")
            L.append("")

    # Kill chain progression.
    if kchain and kchain.get("phase_timeline"):
        L.append("## Kill chain progression")
        if kchain.get("summary"):
            L.append(f"_{kchain['summary']}_")
            L.append("")
        L.append("| Phase | Tactic | Findings | Techniques |")
        L.append("|:---:|---|:---:|---|")
        for phase in kchain["phase_timeline"]:
            techs = ", ".join(phase.get("techniques", [])[:4]) or "—"
            L.append(f"| {'🔴' if phase.get('finding_count',0) > 0 else '⚪'} | "
                     f"**{phase.get('label', '')}** | {phase.get('finding_count', 0)} | "
                     f"`{techs}` |")
        L.append("")
        paths = kchain.get("breach_paths") or []
        if paths:
            L.append("### Breach paths")
            for bp in paths:
                L.append(f"- **{bp.get('name','')}** — depth {bp.get('depth', 1)}, "
                         f"trigger: `{bp.get('trigger','')}`")
            L.append("")

    # ATT&CK coverage (adversary emulation).
    att_cov = kchain.get("attack_coverage") if kchain else None
    if att_cov:
        L.append("## MITRE ATT&CK coverage")
        L.append(f"**Adversary:** {att_cov.get('adversary', '')}  ·  "
                 f"**Exercised:** {att_cov.get('exercised', 0)}/{att_cov.get('total_techniques', 0)} "
                 f"techniques ({att_cov.get('coverage_pct', 0)}%)")
        L.append("")
        for tac, techs in (att_cov.get("by_tactic") or {}).items():
            exercised = [t for t in techs if t.get("exercised")]
            total = len(techs)
            L.append(f"**{TACTIC_LABELS.get(tac, tac)}** — {len(exercised)}/{total}")
            for t in techs:
                mark = "✅" if t.get("exercised") else "⬜"
                L.append(f"  {mark} `{t['tid']}` {t['name']}")
            L.append("")

    # Findings, ranked by proven impact.
    L.append("## Findings (ranked by proven impact)")
    if not findings:
        L.append("_No findings._")
    for i, f in enumerate(findings, 1):
        badge = ("🎯 EXPLOITED" if f.get("exploited")
                 else "🟢 PROVEN" if f.get("proven") else "⚪ UNPROVEN OBSERVATION")
        L.append(f"### {i}. {f.get('title','finding')}")
        L.append(f"- **Severity:** {f.get('severity','info')}  ·  **{badge}**  ·  "
                 f"**Tier:** {C.TIER_LABEL.get(f.get('impact_tier',3),'')}")
        mitre = f"  ·  **ATT&CK:** `{f['mitre_technique']}`" if f.get("mitre_technique") else ""
        L.append(f"- **OWASP:** {f.get('owasp_web','')} | {f.get('owasp_api','')}  ·  "
                 f"**{f.get('cwe','')}**  ·  **Class:** `{f.get('vuln_class','')}`{mitre}")
        if f.get("host") or f.get("url"):
            L.append(f"- **Where:** {f.get('host','')} {('`'+f['url']+'`') if f.get('url') else ''}"
                     + (f"  (param `{f['parameter']}`)" if f.get("parameter") else ""))
        if f.get("instance_count", 0) > 1:
            L.append(f"- **Confirmed on {f['instance_count']} URLs** (see PoC file for the full list)")
        # The three-part operator story: what we did → what came back → what it means.
        did, got, means = _did(f), _got(f), _means(f)
        if did:
            L.append(f"\n**What AriseAI did**\n```\n{did[:800]}\n```")
        if got:
            L.append(f"**What came back**\n```\n{got[:900]}\n```")
        if means:
            L.append(f"**What it means:** {means}")
        if f.get("narrative"):
            L.append(f"\n{f['narrative']}")
        if f.get("poc") and f.get("poc") != did:
            L.append(f"\n**Reproduce**\n```\n{f['poc']}\n```")
        if f.get("remediation"):
            L.append(f"\n- **Fix:** {f['remediation']}")
        if f.get("proven") and f.get("curl_command"):
            state = f.get("replay_confirmed", "pending")
            L.append(f"\n- **Replay to confirm** ({state}): `{f['curl_command']}`")
        if f.get("poc_file"):
            L.append(f"\n_Full PoC: `{f['poc_file']}`_")
        L.append("")

    # Hypotheses considered (transparency on the gate).
    if hyps:
        L.append("## Attack hypotheses considered")
        L.append("| # | Hypothesis | Class | Status |")
        L.append("|---|---|---|---|")
        for i, h in enumerate(hyps, 1):
            st = h.get("status", "hypothesis")
            L.append(f"| {i} | {(h.get('title','') or '')[:90]} | "
                     f"`{h.get('vuln_class','')}` | {st}"
                     + (f" — {h.get('reject_reason')}" if st == "rejected" else "") + " |")
        L.append("")

    # Narrative verification (RT3) — did the AI invent any specifics?
    unv = writeup.get("_unverified_tokens") or []
    if writeup:
        L.append("## AI narrative verification")
        if not unv:
            L.append("✅ Every host/URL/IP in the AI narrative was cross-checked "
                     "against the scan evidence — no invented specifics. The narrative "
                     "prose is still AI-generated; the differential proof above is the "
                     "source of truth.")
        else:
            L.append(f"⚠️ {len(unv)} token(s) in the AI narrative were **not found in "
                     "the scan evidence** — treat them as AI-generated and unverified, "
                     "not facts:")
            for u in unv[:20]:
                L.append(f"- `{u.get('token','')}` ({u.get('type')}, in {u.get('where')})")
        L.append("")

    # Coverage.
    L.append("## Coverage & honesty statement")
    L.append(writeup.get("coverage") or _fallback_coverage(cov))
    L.append("")
    L.append("---")
    L.append(f"_Generated by {C.ENGINE_NAME}. Findings are AI-produced; proven items "
             f"are backed by live differential evidence. {result.get('budget_note','')}_")
    return "\n".join(L) + "\n"


def _finding_md(f: Dict[str, Any]) -> str:
    L = [f"# {f.get('title','finding')}", ""]
    L.append(f"- **Severity:** {f.get('severity','info')}")
    L.append(f"- **Proven:** {'yes — live proof-of-concept' if f.get('proven') else 'no — unproven observation'}")
    L.append(f"- **Impact tier:** {C.TIER_LABEL.get(f.get('impact_tier',3),'')}")
    L.append(f"- **OWASP:** {f.get('owasp_web','')} | {f.get('owasp_api','')}")
    L.append(f"- **CWE:** {f.get('cwe','')}")
    L.append(f"- **Class:** {f.get('vuln_class','')}")
    L.append(f"- **Host:** {f.get('host','')}")
    if f.get("url"):
        L.append(f"- **URL:** {f['url']}")
    if f.get("parameter"):
        L.append(f"- **Parameter:** {f['parameter']}")
    if f.get("verification"):
        L.append(f"- **Verification:** {f['verification']}")
    L.append("")
    did, got, means = _did(f), _got(f), _means(f)
    if did:
        L += ["## What AriseAI did", "```", did[:1000], "```", ""]
    if got:
        L += ["## What came back", "```", got[:1200], "```", ""]
    if means:
        L += ["## What it means (impact)", means, ""]
    if f.get("narrative"):
        L += ["## Attacker narrative", f["narrative"], ""]
    if f.get("poc"):
        L += ["## Proof of concept", "```", f["poc"], "```", ""]
    if f.get("request_line"):
        L += ["## Request", "```", str(f.get("request_line")), "```", ""]
    if f.get("evidence"):
        L += ["## Evidence", f["evidence"], ""]
    inst = f.get("instances") or []
    if len(inst) > 1:
        L += [f"## Affected URLs ({len(inst)})", ""]
        L += [f"- `{u}`" for u in inst[:50]]
        L += [""]
    if f.get("baseline") or f.get("attack"):
        L += ["## Differential", "```json",
              json.dumps({"baseline": f.get("baseline", {}), "attack": f.get("attack", {})}, indent=2),
              "```", ""]
    if f.get("remediation"):
        L += ["## Remediation", f["remediation"], ""]
    if f.get("proven") and f.get("curl_command"):
        L += ["## Replay this PoC",
              f"Status: **{f.get('replay_confirmed','pending')}** — re-run to confirm before reporting:",
              "```bash", f["curl_command"], "```", ""]
    return "\n".join(L) + "\n"


def _fallback_exec(result: Dict[str, Any]) -> str:
    findings = result.get("findings", [])
    proven = [f for f in findings if f.get("proven")]
    if not proven:
        return ("No vulnerabilities were proven with a live proof-of-concept in this run. "
                f"{len(findings)} unproven observation(s) were recorded for manual review. "
                "A clean proven-set is not a clean bill of health — see the coverage statement.")
    top = proven[0]
    return (f"{len(proven)} finding(s) were proven exploitable. The most urgent is "
            f"**{top.get('title','')}** ({top.get('severity','')}) on {top.get('host','')}, "
            f"mapped to {top.get('owasp_web','')}. {top.get('impact','')}")


def _fallback_coverage(cov: Dict[str, Any]) -> str:
    return (
        f"Reasoned over {cov.get('evidence_items', 0)} evidence items across "
        f"{cov.get('hosts', 0)} hosts. Live-verified {cov.get('live_checks', 0)} vulnerability "
        f"class(es); {cov.get('hypotheses_rejected', 0)} hypothesis(es) were rejected by the "
        "grounding gate as unsupported by evidence. This is a black-box, exploit-validated run: "
        "it cannot assess logging/alerting (OWASP A09), at-rest cryptography, or internal CI/CD "
        "trust boundaries. "
        + (cov.get("budget_note") or ""))


# ---------------------------------------------------------------------------
# SARIF 2.1.0
# ---------------------------------------------------------------------------
def _sarif(result: Dict[str, Any]) -> Dict[str, Any]:
    findings = result.get("findings", [])
    rules, results = {}, []
    for f in findings:
        rid = f.get("vuln_class") or "finding"
        if rid not in rules:
            rules[rid] = {
                "id": rid,
                "name": rid,
                "shortDescription": {"text": f.get("owasp_web", rid)},
                "properties": {"owasp_web": f.get("owasp_web", ""),
                               "owasp_api": f.get("owasp_api", ""),
                               "cwe": f.get("cwe", "")},
            }
        results.append({
            "ruleId": rid,
            "level": _sarif_level(f.get("severity")),
            "message": {"text": f"{f.get('title','')} — {f.get('impact','') or f.get('evidence','')}"[:1000]},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": f.get("url") or f.get("host") or result.get("target", "")}}}],
            "properties": {"proven": bool(f.get("proven")),
                           "impact_tier": C.TIER_LABEL.get(f.get("impact_tier", 3), ""),
                           "ai_generated": True},
            "partialFingerprints": {"ariseai": f.get("ref") or f.get("id") or rid},
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": C.ENGINE_NAME,
                "informationUri": "https://arise.local/ai-analyst",
                "version": "2.0",
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }
