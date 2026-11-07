"""
AriseAI — dashboard integration helpers.

Keeps the dashboard thin: the mapping from AriseAI's result record to the
dashboard's vuln-row shape lives here (owned by the engine), and the dashboard
just calls load_vuln_rows() fail-open.

Only PROVEN findings are merged into the main vuln list — observations would
flood it and the other engines already surface most of them. Because AriseAI's
proven findings are differential-confirmed (confidence=exploited / verification),
finding_reconciler collapses any that overlap an existing engine's finding into
ONE row and records `corroborated_by: [..., ai_analyst]`, so the merge adds the
AI badge + red-team narrative WITHOUT duplicating rows.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional

from ai_analyst import constants as C


def result_path(scan_dir: str) -> str:
    return os.path.join(scan_dir, C.OUTPUT_SUBDIR, C.RESULT_JSON)


def load_result(scan_dir: str) -> Optional[Dict[str, Any]]:
    """Read the AriseAI machine record for a scan, or None. Never raises."""
    p = result_path(scan_dir)
    try:
        with open(p, "r", errors="ignore") as fh:
            return json.load(fh)
    except Exception:
        return None


def _weighted_score(f: Dict[str, Any]) -> float:
    base = C.CVSS_HINT.get((f.get("severity") or "info").lower(), 1.0)
    # A proven exploit outranks an unproven observation of the same severity.
    return round(base + (1.5 if f.get("proven") else 0.0), 2)


def to_vuln_rows(result: Dict[str, Any], proven_only: bool = True) -> List[Dict[str, Any]]:
    """Convert AriseAI findings into dashboard vuln-list rows."""
    if not isinstance(result, dict):
        return []
    rows = []
    for f in result.get("findings", []):
        if proven_only and not f.get("proven"):
            continue
        title = f.get("title") or f.get("vuln_class") or "AriseAI finding"
        # A clustered finding ("confirmed on N URLs") emits one row per instance
        # URL so the dashboard reconciler — which keys per URL path — badges and
        # corroborates EVERY matching row, not just the representative one.
        urls = f.get("instances") or ([f.get("url")] if f.get("url") else [""])
        for u in urls:
            rows.append(_row(f, title, u))
    return rows


def _row(f: Dict[str, Any], title: str, url: str) -> Dict[str, Any]:
    return {
            # provenance / badge
            "source": C.ENGINE_SOURCE,
            "detection_tool": C.ENGINE_TOOL,
            "tool": C.ENGINE_TOOL,
            "ai_generated": True,
            # identity
            "template": title,
            "name": title,
            "check": f.get("vuln_class", ""),
            "issue_class": f.get("vuln_class", ""),
            "category": f.get("vuln_class", ""),
            "severity": f.get("severity", "info"),
            "host": f.get("host", ""),
            "url": url or f.get("url", ""),
            "parameter": f.get("parameter", ""),
            # evidence / proof (so reconciler scores richness correctly)
            "impact": f.get("impact") or f.get("evidence", ""),
            "evidence": f.get("evidence", ""),
            "remediation": f.get("remediation", ""),
            "confidence": f.get("confidence", "exploited" if f.get("proven") else ""),
            "verification": f.get("verification", ""),
            "request_line": f.get("request_line", ""),
            "payload": f.get("payload", ""),
            "baseline": f.get("baseline", {}),
            "attack": f.get("attack", {}),
            # AI-specific extras the UI can surface
            "cwe": f.get("cwe", ""),
            "owasp_web": f.get("owasp_web", ""),
            "owasp_api": f.get("owasp_api", ""),
            "ai_narrative": f.get("narrative", ""),
            "ai_poc": f.get("poc", ""),
            "proven": bool(f.get("proven")),
            "exploited": bool(f.get("exploited")),
            "exploit_proof": f.get("exploit_proof", ""),
            "exploit_impact": f.get("exploit_impact", ""),
            "impact_tier": C.TIER_LABEL.get(f.get("impact_tier", 3), ""),
            "instance_count": f.get("instance_count", 1),
            "poc_file": f.get("poc_file", ""),
            "curl_command": f.get("curl_command", ""),
            "replay_confirmed": f.get("replay_confirmed", ""),
            "weighted_score": _weighted_score(f),
    }


def load_vuln_rows(scan_dir: str, proven_only: bool = True) -> List[Dict[str, Any]]:
    """One-call convenience for the dashboard. Fail-open: [] on any problem."""
    try:
        res = load_result(scan_dir)
        return to_vuln_rows(res, proven_only) if res else []
    except Exception:
        return []
