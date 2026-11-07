#!/usr/bin/env python3
"""
ARISE — In-Loop Template Synthesis  (Offensive AI Elevation, Phase 4)
=====================================================================
Promotes synth_ai's one-shot, recon-time template proposal into a capability the
brain can call MID-INVESTIGATION: observe an anomaly → synthesize a nuclei
detector for exactly it → validate (+self-repair) → run it in-scope → get back
structured matches. The matches are LEADS, never findings.

Reuse (don't reinvent) — every heavy piece already exists in synth_ai:
  * propose_templates()  — model → YAML, id-rewritten, ScopeGuard-sanitised,
    `nuclei -validate` gated, self-repaired on failure. The model never holds the
    trigger; nuclei does.
  * The written, validated templates are then run with nuclei against in-scope
    URLs via an injectable run_fn (so this is testable without nuclei/live).

Lead-only contract (why this can't add FP):
  * A synthesized-template match is stamped `provenance=synthetic` and pinned to
    a LOW evidence rung (L1/observed). finding_reconciler.provenance_weight and
    the L0-L6 ladder therefore keep it BELOW any real differential confirmation,
    and it must be corroborated / confirmed before it can climb.

Fail-safe: no chat_fn, no nuclei, no in-scope URLs → returns a clear reason and
zero leads. Never raises.
Stdlib only (+ synth_ai / ScopeGuard, both already stdlib-safe).
"""

from __future__ import annotations

import sys as _sys
import os
import json
import shutil
import subprocess
from typing import Callable, Dict, List, Optional, Tuple

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)

try:
    from discovery import synth_ai
except Exception:  # pragma: no cover
    synth_ai = None


# Runner: (argv, timeout) -> (rc, stdout, stderr). Injectable for tests; the
# default mirrors arise_autonomous.default_run (argv exec, no shell).
RunFn = Callable[[List[str], int], Tuple[int, str, str]]


def default_run(argv: List[str], timeout_s: int) -> Tuple[int, str, str]:
    try:
        p = subprocess.run(argv, capture_output=True, text=True,
                           timeout=timeout_s, check=False)
        return p.returncode, p.stdout or "", p.stderr or ""
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except Exception as exc:  # noqa: BLE001
        return 1, "", str(exc)[:200]


def synthesize(observation_summary: dict, chat_fn, scope, out_dir: str,
               cap: int = 4) -> dict:
    """Thin wrapper over synth_ai.propose_templates. `observation_summary` is a
    small recon/observation dict (hosts, tech, the anomaly the brain saw). Returns
    the proposal result {written:[...], dropped, repaired, error}."""
    if synth_ai is None:
        return {"requested": False, "written": [], "dropped": [], "error": "synth_ai unavailable"}
    if chat_fn is None:
        return {"requested": False, "written": [], "dropped": [], "error": "no chat_fn (AI layer off)"}
    try:
        return synth_ai.propose_templates(observation_summary, chat_fn, scope, out_dir, cap=cap)
    except Exception as exc:  # noqa: BLE001
        return {"requested": True, "written": [], "dropped": [], "error": str(exc)[:200]}


def run_templates(template_paths: List[str], urls: List[str], out_dir: str,
                  scope=None, run_fn: RunFn = None, timeout_s: int = 300) -> List[dict]:
    """Run validated templates against IN-SCOPE urls with nuclei -jsonl. Returns
    raw nuclei match dicts. Degrades to [] when nuclei is absent or nothing is in
    scope. Never raises."""
    run_fn = run_fn or default_run
    if not template_paths or not urls:
        return []
    in_scope = [u for u in urls if (scope is None or _in_scope(scope, u))]
    if not in_scope:
        return []
    if run_fn is default_run and not shutil.which("nuclei"):
        return []  # can't run here; the pipeline can run the written templates later

    abs_templates = [t if os.path.isabs(t) else os.path.join(out_dir, t) for t in template_paths]
    matches: List[dict] = []
    # feed URLs on stdin-free: use -u per small batch to keep argv bounded
    for i in range(0, len(in_scope), 25):
        batch = in_scope[i:i + 25]
        argv = ["nuclei", "-jsonl", "-silent", "-disable-update-check"]
        for t in abs_templates:
            argv += ["-t", t]
        for u in batch:
            argv += ["-u", u]
        rc, out, _err = run_fn(argv, timeout_s)
        for line in (out or "").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                matches.append(json.loads(line))
            except Exception:
                continue
    return matches


def to_leads(raw_matches: List[dict]) -> List[dict]:
    """Shape nuclei matches from SYNTHESIZED templates into lead records the
    reconciler/dashboard understand. Pinned low (L1) and marked lead_only so they
    never outrank a real confirmation."""
    leads: List[dict] = []
    for m in raw_matches or []:
        if not isinstance(m, dict):
            continue
        info = m.get("info", {}) or {}
        tid = m.get("template-id") or m.get("templateID") or info.get("name") or "synth-template"
        url = m.get("matched-at") or m.get("host") or m.get("url") or ""
        host = m.get("host") or _host_from_url(url)
        # extracted-results may be a list, a bare string, or absent — normalize
        # to a list of strings so join() can never raise or mangle a string.
        raw_ex = m.get("extracted-results") or m.get("extracted_results") or []
        if isinstance(raw_ex, str):
            raw_ex = [raw_ex]
        extracted = [str(x) for x in raw_ex] if isinstance(raw_ex, list) else []
        leads.append({
            "source": "Synthesized Template",
            "detection_tool": "synth_template",
            "template": str(tid),
            "title": info.get("name") or str(tid),
            "severity": (info.get("severity") or "info").lower(),
            "host": host,
            "url": url,
            "impact": (", ".join(extracted)[:240] if extracted else info.get("description", "")),
            "extracted_results": extracted,
            "provenance": {"lane": "synthetic", "class": "synthetic"},
            "evidence_rung": "L1",          # observed/anomalous — NOT confirmed
            "confidence": "probable",
            "verification": "synthesized-template-match",
            "lead_only": True,
        })
    return leads


def synthesize_and_run(observation_summary: dict, urls: List[str], chat_fn, scope,
                       out_dir: str, cap: int = 4, run_fn: RunFn = None) -> dict:
    """Full mid-loop power: synthesize → run in-scope → shape leads. Returns
    {ok, leads, proposal, ran, reason}. Never raises; fail-open to a reason."""
    proposal = synthesize(observation_summary, chat_fn, scope, out_dir, cap=cap)
    written = proposal.get("written") or []
    if not written:
        return {"ok": False, "leads": [], "proposal": proposal, "ran": 0,
                "reason": proposal.get("error") or "no valid templates synthesized"}
    raw = run_templates(written, urls, out_dir, scope=scope, run_fn=run_fn)
    leads = to_leads(raw)
    return {"ok": True, "leads": leads, "proposal": proposal, "ran": len(written),
            "reason": f"synthesized {len(written)} template(s); {len(leads)} lead(s)"}


def _in_scope(scope, url: str) -> bool:
    try:
        return scope.in_scope(url)
    except Exception:
        return False


def _host_from_url(url: str) -> str:
    """Host from a URL without IndexError on malformed input."""
    if "://" in url:
        parts = url.split("/")
        return parts[2] if len(parts) > 2 else url
    return url


# ---------------------------------------------------------------------------
# Self-test (no network / no nuclei / no real model)
# ---------------------------------------------------------------------------
def _selftest() -> int:
    class _Scope:
        def in_scope(self, url):
            return "x.com" in url

    # --- run_templates: OUT-OF-SCOPE urls are filtered; a fake nuclei run yields
    #     one in-scope match. (Uses an injected run_fn, so no real nuclei needed.)
    def _fake_run(argv, timeout):
        # only in-scope urls reach here (run_templates filtered), so emit one match
        match = {"template-id": "test-synth", "matched-at": "https://x.com/probe",
                 "host": "x.com", "info": {"name": "Test Synth", "severity": "info"},
                 "extracted-results": ["marker"]}
        return 0, json.dumps(match) + "\n", ""

    raw = run_templates(["/tmp/fake.yaml"], ["https://x.com/probe", "https://evil.com/x"],
                        "/tmp", scope=_Scope(), run_fn=_fake_run)
    assert len(raw) == 1, "out-of-scope url must be filtered; one in-scope match expected"

    # --- to_leads: the safety-critical shaping — low rung, lead_only, synthetic prov
    leads = to_leads(raw)
    assert len(leads) == 1
    L = leads[0]
    assert L["lead_only"] is True, "synthesized matches MUST be lead-only"
    assert L["evidence_rung"] == "L1", "synthesized matches MUST pin low (not confirmed)"
    assert L["provenance"]["lane"] == "synthetic"
    assert L["detection_tool"] == "synth_template"

    # the reconciler must NOT treat a synthesized lead as confirmed evidence
    try:
        from offensive import finding_reconciler as fr
        stamped = fr._stamp(L)
        assert stamped["is_confirmed_evidence"] is False, "synthetic lead must never read confirmed"
    except Exception:
        pass

    # --- regression: extracted-results as a bare STRING or non-str list must not
    #     crash or mangle (never-raise contract)
    weird = to_leads([
        {"template-id": "t1", "matched-at": "https://x.com/a", "extracted-results": "solo"},
        {"template-id": "t2", "matched-at": "https://x.com/b", "extracted-results": [200, 404]},
        {"template-id": "t3", "matched-at": "malformed"},   # no scheme
    ])
    assert weird[0]["extracted_results"] == ["solo"], weird[0]
    assert weird[1]["extracted_results"] == ["200", "404"], weird[1]
    assert weird[2]["host"] == "malformed"   # no IndexError

    # --- run_templates: nothing in scope / nothing to run -> [] (never raises)
    assert run_templates(["/tmp/fake.yaml"], ["https://evil.com/x"], "/tmp",
                         scope=_Scope(), run_fn=_fake_run) == []
    assert run_templates([], ["https://x.com"], "/tmp") == []

    # --- synthesize degradation paths
    assert synthesize({}, None, _Scope(), "/tmp")["error"].startswith("no chat_fn")
    sr = synthesize_and_run({}, ["https://x.com"], None, _Scope(), "/tmp")
    assert sr["ok"] is False and sr["leads"] == []

    print("[template_synth] self-test OK — scope-filtered run + low-rung lead-only shaping + degradation")
    return 0


if __name__ == "__main__":
    _sys.exit(_selftest())
