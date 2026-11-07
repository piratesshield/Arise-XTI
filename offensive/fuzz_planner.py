#!/usr/bin/env python3
"""
ARISE — Guided Fuzz Planner  (Offensive AI Elevation, Phase 5)
==============================================================
Replaces adaptive_loop's FIXED param names / payload lists with an
observation-driven PLAN — but produces LEADS ONLY. It sends nothing. Each probe
it emits names the confirmation oracle that must fire before the lead can become
a finding, so this can never add a false positive: the oracle (and then the
reconciler + Verifier) stays the gate.

What it grounds on (reuse, don't reinvent):
  * OBSERVED parameters — discovered_endpoints.jsonl `query_variants` and
    20_api_deep_discovery/input_functions.jsonl (real fetch/XHR/form params from
    the CDP driver). Not the hard-coded id/q/url.
  * DETECTED tech — 04_http_discovery/tech_manifest.jsonl → payload grammar
    selection (SQL dialect, template engine, path style).
  * CONFIRMATION oracles — discovery/response_analysis.ORACLES names, so a plan
    entry maps 1:1 onto an oracle the runner already trusts.

Design rules (same as Phases 1-4)
  - Sends nothing; deterministic; never raises.
  - Every probe carries `oracle` + `expects` — the runner MUST confirm via that
    oracle; a moved response with no oracle hit is discarded, not reported.
  - Stdlib only. Importable anywhere.
"""

from __future__ import annotations

import sys as _sys
import os
import json
import re
from dataclasses import dataclass
from typing import Dict, List, Optional

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)

# Oracle names we may target — kept in sync with response_analysis.ORACLES so a
# plan entry is always runnable. Falls back to a static list if that import fails.
try:
    from discovery.response_analysis import ORACLES as _RA_ORACLES
    _VALID_ORACLES = set(_RA_ORACLES.keys())
except Exception:  # pragma: no cover
    _VALID_ORACLES = {
        "reflected_xss", "sql_error", "sql_boolean", "sql_time", "ssti",
        "open_redirect", "ssrf_metadata", "cmd_injection", "error_disclosure",
    }


# ---------------------------------------------------------------------------
# Payload grammars, tech-aware. Each entry: (oracle, [payloads], severity_hint).
# Payloads are the SAME safe, GET-friendly probes adaptive_loop/response_analysis
# already use — nothing destructive, nothing state-changing.
# ---------------------------------------------------------------------------
_GRAMMARS: Dict[str, List[tuple]] = {
    "sqli": [
        ("sql_error", ["'", "1'\"", "1' OR '1'='1"], "high"),
        ("sql_boolean", ["1' AND '1'='1", "1' AND '1'='2"], "high"),  # true,false pair
        ("sql_time", ["1' AND SLEEP(5)-- -"], "high"),
    ],
    "xss": [("reflected_xss", ['"><arisexss>', "'><arisexss>"], "medium")],
    "ssti": [("ssti", ["{{7*7}}", "${7*7}", "#{7*7}"], "high")],
    "lfi": [("error_disclosure", ["../../../../../../etc/passwd",
                                   "....//....//....//etc/passwd"], "high")],
    "ssrf": [("ssrf_metadata", ["http://169.254.169.254/latest/meta-data/"], "high")],
    "open-redirect": [("open_redirect", ["https://arise-oob.example/", "//arise-oob.example/"], "medium")],
    "rce": [("cmd_injection", [";id", "|id", "$(id)", "`id`", "; sleep 5"], "critical")],
}

# Which grammars are worth trying for a given tech token (from tech_manifest).
# Absent/unknown tech -> a sensible default set. This is prioritisation, not a
# filter: unknown params still get the default battery.
_TECH_HINTS: List[tuple] = [
    (re.compile(r"php|laravel|symfony|wordpress|drupal", re.I), ["sqli", "lfi", "xss", "rce"]),
    (re.compile(r"node|express|next|nuxt", re.I), ["ssti", "xss", "sqli", "ssrf"]),
    (re.compile(r"python|django|flask|jinja", re.I), ["ssti", "sqli", "xss", "ssrf"]),
    (re.compile(r"java|spring|tomcat|struts", re.I), ["ssti", "sqli", "ssrf", "lfi"]),
    (re.compile(r"ruby|rails", re.I), ["ssti", "sqli", "xss"]),
    (re.compile(r"asp\.net|iis|\.net", re.I), ["sqli", "lfi", "xss"]),
]
_DEFAULT_GRAMMARS = ["sqli", "xss", "ssti", "lfi", "ssrf", "open-redirect"]

# Param-name → grammar hints (steer, don't restrict). Reuses the intuition that a
# param called `redirect` deserves an open-redirect probe first.
# Matched on TOKENS of the param name (split on non-alnum + camelCase), so a bare
# `q`/`s` matches the param q/s but NOT every name that merely contains those
# letters (the old regex `q|...|s` over-matched "password", "request", …), while
# underscore/camelCase names like `redirect_url` / `redirectUrl` still match.
_PARAM_HINT_SETS: List[tuple] = [
    ({"redirect", "return", "next", "url", "dest", "continue", "callback", "goto"}, ["open-redirect", "ssrf"]),
    ({"id", "uid", "pid", "user", "order", "account", "doc", "record"}, ["sqli", "lfi"]),
    ({"q", "query", "search", "keyword", "term", "s", "name", "title", "comment", "msg"}, ["xss", "ssti", "sqli"]),
    ({"page", "path", "file", "template", "include", "view", "load"}, ["lfi", "ssti"]),
    ({"cmd", "exec", "run", "command", "ping", "host"}, ["rce"]),
]


def _param_tokens(param: str) -> set:
    """Lowercased word tokens of a param name (splits snake_case, kebab-case and
    camelCase). `redirectUrl` -> {'redirect','url'}, `user_id` -> {'user','id'}."""
    s = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", param or "")
    return {t for t in re.split(r"[^a-zA-Z0-9]+", s.lower()) if t}


@dataclass
class Probe:
    url: str
    param: str
    grammar: str
    oracle: str
    payloads: List[str]
    severity_hint: str
    expects: str                 # human note: what the oracle must observe
    priority: int = 2            # lower = try first
    source: str = "guided_fuzz"

    def to_dict(self) -> dict:
        return {
            "url": self.url, "param": self.param, "grammar": self.grammar,
            "oracle": self.oracle, "payloads": self.payloads,
            "severity_hint": self.severity_hint, "expects": self.expects,
            "priority": self.priority, "source": self.source,
            # explicit reminder to the runner: this is a LEAD until the oracle fires
            "lead_only": True,
        }


# ---------------------------------------------------------------------------
# Observation loaders (best-effort; missing files -> empty)
# ---------------------------------------------------------------------------
def _iter_jsonl(path: str):
    if not os.path.exists(path):
        return
    try:
        with open(path, "r", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        yield json.loads(line)
                    except Exception:
                        continue
    except Exception:
        return


def observed_params(scan_dir: str) -> Dict[str, set]:
    """url -> {param names} from the endpoints inventory + CDP input functions."""
    out: Dict[str, set] = {}

    def _add(url, params):
        if not url:
            return
        s = out.setdefault(url, set())
        for p in params or []:
            if p:
                s.add(str(p))

    for rec in _iter_jsonl(os.path.join(scan_dir, "discovered_endpoints.jsonl")):
        url = rec.get("url") or rec.get("endpoint") or ""
        params = list(rec.get("query_variants") or rec.get("params") or [])
        # query string params embedded in the URL
        if "?" in url:
            qs = url.split("?", 1)[1]
            params += [kv.split("=", 1)[0] for kv in qs.split("&") if kv]
        _add(url.split("?", 1)[0] if "?" in url else url, params)

    for rec in _iter_jsonl(os.path.join(scan_dir, "20_api_deep_discovery", "input_functions.jsonl")):
        _add(rec.get("url", ""), rec.get("params", []))

    return out


def detected_techs(scan_dir: str) -> List[str]:
    techs: List[str] = []
    for rec in _iter_jsonl(os.path.join(scan_dir, "04_http_discovery", "tech_manifest.jsonl")):
        for t in (rec.get("techs") or rec.get("technologies") or []):
            if t:
                techs.append(str(t))
    return techs


# ---------------------------------------------------------------------------
# Planning
# ---------------------------------------------------------------------------
def _grammars_for(param: str, techs: List[str]) -> List[str]:
    """Prioritised grammar list for one param: param-name hints first, then
    tech-derived, then the default battery. Deduped, order-preserving."""
    ordered: List[str] = []

    def _push(names):
        for n in names:
            if n in _GRAMMARS and n not in ordered:
                ordered.append(n)

    toks = _param_tokens(param)
    for hint_set, names in _PARAM_HINT_SETS:
        if toks & hint_set:
            _push(names)
    blob = " ".join(techs)
    for rx, names in _TECH_HINTS:
        if rx.search(blob):
            _push(names)
    _push(_DEFAULT_GRAMMARS)
    return ordered


def plan_for_param(url: str, param: str, techs: List[str],
                   max_grammars: int = 4) -> List[Probe]:
    probes: List[Probe] = []
    grammars = _grammars_for(param, techs)[:max_grammars]
    for prio, grammar in enumerate(grammars):
        for oracle, payloads, sev in _GRAMMARS[grammar]:
            if oracle not in _VALID_ORACLES:
                continue
            probes.append(Probe(
                url=url, param=param, grammar=grammar, oracle=oracle,
                payloads=list(payloads), severity_hint=sev,
                expects=f"oracle '{oracle}' must fire on the attack response "
                        f"(baseline stays silent) before this is a finding",
                priority=prio,
            ))
    return probes


def build_plan(scan_dir: str, max_urls: int = 200, max_params_per_url: int = 12,
               max_grammars: int = 4) -> dict:
    """Whole-scan fuzz plan from observed params + detected tech. Deterministic;
    sends nothing. Returns {plan:[Probe...], stats:{...}} sorted by priority."""
    techs = detected_techs(scan_dir)
    params_by_url = observed_params(scan_dir)
    probes: List[Probe] = []
    urls = list(params_by_url.items())[:max_urls]
    for url, params in urls:
        for param in sorted(params)[:max_params_per_url]:
            probes.extend(plan_for_param(url, param, techs, max_grammars))
    probes.sort(key=lambda p: (p.priority, p.url, p.param))
    return {
        "plan": [p.to_dict() for p in probes],
        "stats": {
            "urls": len(urls), "probes": len(probes),
            "techs": sorted(set(techs))[:20],
            "lead_only": True,
            "note": "every probe is a LEAD; a finding requires its named oracle to fire",
        },
    }


# ---------------------------------------------------------------------------
# Self-test (no network, no files)
# ---------------------------------------------------------------------------
def _selftest() -> int:
    # param-name steering: a redirect param tries open-redirect first
    # (snake_case, kebab-case and camelCase all tokenize correctly)
    for pname in ("redirect_url", "redirect-url", "redirectUrl"):
        assert _grammars_for(pname, [])[0] == "open-redirect", (pname, _grammars_for(pname, []))

    # tech steering: python/jinja pushes ssti up for a neutral param
    g2 = _grammars_for("data", ["Django", "Python"])
    assert "ssti" in g2[:2], g2

    # regression: a bare single-letter hint must NOT match unrelated params.
    # "password" contains 's' but must not be treated as a search param.
    assert _grammars_for("password", []) == _grammars_for("zzz_neutral", []), \
        "single-letter param hint over-matched"
    # but the real 's' / 'q' params still steer to xss-first
    assert _grammars_for("q", [])[0] == "xss"

    # every planned probe names a REAL oracle and is flagged lead-only
    probes = plan_for_param("https://x.com/s", "q", ["nginx"])
    assert probes, "expected probes for a search param"
    for p in probes:
        d = p.to_dict()
        assert d["oracle"] in _VALID_ORACLES, d["oracle"]
        assert d["lead_only"] is True
        assert "must fire" in d["expects"]

    # sql_boolean carries the true+false pair the differential oracle needs
    sb = [p for p in plan_for_param("https://x.com/i", "id", []) if p.oracle == "sql_boolean"]
    assert sb and len(sb[0].payloads) == 2, "sql_boolean needs a true/false pair"

    # priority ordering holds
    plan = [Probe("u", "p", "sqli", "sql_error", ["'"], "high", "x", priority=3),
            Probe("u", "p", "xss", "reflected_xss", ["<x>"], "medium", "x", priority=0)]
    plan.sort(key=lambda p: p.priority)
    assert plan[0].oracle == "reflected_xss"

    print(f"[fuzz_planner] self-test OK — observation-driven, lead-only, "
          f"{len(_VALID_ORACLES)} oracles available")
    return 0


if __name__ == "__main__":
    _sys.exit(_selftest())
