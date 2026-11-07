"""
AriseAI — autonomous tool-execution tier (the merged Autonomous Action engine).

This is where the old "Autonomous Action" capability is MERGED into AriseAI: it is
no longer a separate user-facing engine but AriseAI's *deepest verification tier*.
When the operator asks for it, AriseAI — after reasoning over the evidence and
running the differential live-verify tier — drives `arise_autonomous.run_autonomous`
(the manager→worker→verifier live-tool loop) to chase what the typed differential
checks can't, then folds its no-false-positive `confirmed_findings` into AriseAI's
own finding set.

Nothing about the old engine's guardrails changes: it still runs scope-locked,
non-destructive, bounded, with its own Verifier gate. AriseAI just orchestrates it
as one tier and relabels the output under its own provenance. Fail-safe: any
problem returns an empty result and a reason, never an exception.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from ai_analyst import constants as C
from ai_analyst.evidence import Evidence, classify, _norm_class  # reuse the taxonomy


def _context_from_evidence(ev: Evidence) -> Dict[str, Any]:
    """Map AriseAI's evidence into the context dict the autonomous engine seeds
    its knowledge graph and manager prompt from (the _gather_ai_context shape)."""
    top = []
    for it in (ev.proven + ev.observations):
        top.append({
            "title": it.title, "severity": it.severity, "source": it.source,
            "host": it.host, "url": it.url, "impact": it.evidence[:240],
        })
    api = []
    for ep in ev.interesting_endpoints(cap=20):
        if ep.get("api") or ep.get("class") in ("api", "graphql"):
            api.append({"endpoint": ep.get("url", ""), "issue": ep.get("class", "")})
    resp = [{"type": it.title, "severity": it.severity, "evidence": it.evidence[:160],
             "url": it.url, "host": it.host}
            for it in ev.items if it.source == "response_intel"][:20]
    return {
        "target": ev.target,
        "top_vulnerabilities": top[:40],
        "cves": [{"cve": c} for c in ev.cves()],
        "api_findings": api,
        "response_intel_findings": resp,
        "bola_candidates": ev.bola_candidates[:12],
    }


def _to_finding(cf: Dict[str, Any]) -> Dict[str, Any]:
    """Convert an autonomous confirmed_finding into an AriseAI finding record."""
    loc = cf.get("location") or {}
    url = loc.get("url", "")
    cls = _norm_class(classify(cf.get("title", ""), cf.get("evidence", ""),
                               cf.get("rationale", "")))
    web, api, cwe = C.owasp_for(cls)
    return {
        "title": cf.get("title") or f"{cls} (autonomous-confirmed)",
        "severity": cf.get("severity", "info"),
        "vuln_class": cls,
        "host": cf.get("host", ""),
        "url": url,
        "parameter": loc.get("param", ""),
        "owasp_web": web, "owasp_api": api, "cwe": cwe,
        "impact": cf.get("rationale") or cf.get("evidence", ""),
        "evidence": cf.get("evidence", ""),
        "remediation": cf.get("fix", ""),
        "poc": cf.get("poc", ""),
        "confidence": "exploited",
        "verification": "autonomous-tool-execution",
        "proven": True,
        "source": C.ENGINE_SOURCE, "tool": C.ENGINE_TOOL, "ai_generated": True,
        "corroborated_by": ["autonomous_exec"],
        "origin_module": "ai_analyst_autonomous",
    }


def run_autonomous_tier(ev: Evidence, scan_dir: str, chat_fn,
                        scope, objective: str = "",
                        max_actions: int = 25,
                        audit_log_path: Optional[str] = None
                        ) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Drive the merged Autonomous engine as AriseAI's deepest tier.

    Returns (finding_records, meta). finding_records are PROVEN AriseAI rows.
    Never raises.
    """
    meta: Dict[str, Any] = {"ran": False, "error": None, "actions": 0, "confirmed": 0}
    if scope is None:
        meta["error"] = "ScopeGuard unavailable — autonomous tier cannot fire safely"
        return [], meta
    try:
        import arise_autonomous as aa
    except Exception as exc:
        meta["error"] = f"autonomous subengine unavailable: {exc}"
        return [], meta

    obj = objective or (f"Autonomously confirm and escalate the highest-impact "
                        f"exploitable weaknesses on {ev.target}, chaining findings "
                        f"into real attack paths. Prove each with live evidence.")
    try:
        cfg = aa.AutonomousConfig(enabled=True, scan_dir=scan_dir,
                                  max_actions=max(1, min(50, int(max_actions))),
                                  audit_log_path=audit_log_path)
        context = _context_from_evidence(ev)
        res = aa.run_autonomous(context, ev.target, obj, chat_fn, cfg, scope)
    except Exception as exc:
        meta["error"] = f"autonomous tier raised: {str(exc)[:160]}"
        return [], meta

    confirmed = getattr(res, "confirmed_findings", []) or []
    actions = getattr(res, "actions", []) or []
    meta.update({
        "ran": True,
        "actions": sum(1 for a in actions if a.get("executed")),
        "confirmed": len(confirmed),
        "error": getattr(res, "error", None),
    })
    return [_to_finding(cf) for cf in confirmed], meta
