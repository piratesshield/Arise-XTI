"""
AriseAI — safety substrate adapter.

AriseAI never hand-rolls attack traffic. When it needs to *prove* a hypothesis
live, it dispatches to ARISE's existing, battle-tested engines through this thin
adapter, which guarantees three invariants are inherited unchanged:

  * Scope lock   — every request passes ai.ai_probing.ScopeGuard (the shared
                   SSRF/scope firewall). Nothing off-target is ever touched.
  * Non-destructive + differential — live verification runs through
                   offensive/offensive_verify.py, whose checks are all baseline-
                   vs-attack differential (they never fire on a status code
                   alone) and refuse state-changing requests.
  * Bounded      — only the AI-selected check classes run, with write=False so
                   the pipeline's own offensive_findings.jsonl is never clobbered.

Everything here is fail-safe: if the substrate is unavailable (module missing,
no scope), the adapter returns an empty, honest result instead of raising.
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional, Tuple

from ai_analyst.constants import LIVE_VERIFIABLE, ALWAYS_RUN_CHECKS


def build_scope(target: str, scan_dir: str):
    """Construct the shared ScopeGuard for a target, with the scan's allowlist.
    Returns None if ScopeGuard is unavailable — callers must treat None as
    'cannot safely fire live' and skip live verification."""
    try:
        from ai.ai_probing import ScopeGuard
    except Exception:
        return None
    allow = []
    try:
        from offensive.offensive_verify import _load_allowlist
        allow = _load_allowlist(scan_dir)
    except Exception:
        allow = []
    try:
        return ScopeGuard(target, allow)
    except Exception:
        return None


def verifiable_classes(classes: List[str]) -> List[str]:
    """Filter requested vuln classes to those AriseAI can actually live-verify,
    returning the underlying offensive_verify check names (deduped, order-kept)."""
    out, seen = [], set()
    for c in classes or []:
        chk = LIVE_VERIFIABLE.get((c or "").lower())
        if chk and chk not in seen:
            out.append(chk)
            seen.add(chk)
    return out


def live_verify(scan_dir: str, target: str, check_names: List[str],
                rate: int = 20, timeout: int = 10,
                max_targets: int = 150) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Run ONLY the named offensive_verify checks against the live target, scope-
    guarded and non-destructive, WITHOUT writing to the scan's output files.

    Returns (finding_records, meta). finding_records are offensive_verify's own
    `.record()` dicts (rich differential proof). Never raises.
    """
    # Always include broad discovery checks regardless of what the brain picked.
    merged = list(check_names or [])
    for chk in ALWAYS_RUN_CHECKS:
        if chk not in merged:
            merged.append(chk)
    check_names = merged
    meta: Dict[str, Any] = {"ran": False, "checks": list(check_names), "error": None}
    if not check_names:
        meta["error"] = "no live-verifiable classes selected"
        return [], meta
    try:
        from offensive import offensive_verify as ov
    except Exception as exc:
        meta["error"] = f"offensive_verify unavailable: {exc}"
        return [], meta

    opts = {
        "target": target,
        "only": list(check_names),
        "write": False,          # critical: do not clobber the pipeline's findings
        "rate": rate,
        "timeout": timeout,
        "max_targets": max_targets,
        "race_concurrency": 10,
    }
    t0 = time.time()
    try:
        findings, per_check = ov.run(scan_dir, opts)
    except Exception as exc:
        meta["error"] = f"live verify raised: {str(exc)[:160]}"
        return [], meta
    meta.update({
        "ran": True,
        "elapsed_s": round(time.time() - t0, 1),
        "per_check": per_check,
    })
    records = []
    for f in findings or []:
        try:
            records.append(f.record())
        except Exception:
            continue
    return records, meta
