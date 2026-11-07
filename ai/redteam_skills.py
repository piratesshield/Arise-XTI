#!/usr/bin/env python3
"""
ARISE — Red-Team Skill Loader
=============================
Strix's edge over a generic LLM pentester is a library of on-demand vulnerability
PLAYBOOKS injected into each specialist's context. This is ARISE's equivalent:
`redteam_skills/*.md` are per-lane testing methodologies; this module indexes them
by lane / CWE / keyword and hands the right one(s) to the autonomous engine so a
specialist reasons from a real methodology instead of guessing payloads from memory.

Public API:
    available_skills()              -> {name: description}
    load_skill(name)                -> body text (methodology), or None
    skills_for_finding(finding)     -> ordered [names] relevant to a finding/lane
    skill_context(lanes, cwes, tags, cap_chars) -> methodology + matched playbooks,
                                        capped, ready to drop into a system prompt.

No third-party deps; frontmatter is parsed by hand.
"""
from __future__ import annotations

import sys as _sys, os as _os
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)


import os
import re
from functools import lru_cache
from typing import Dict, List, Optional

SKILL_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "redteam_skills")
ALWAYS = "__always__"          # methodology.md — always loaded first
_CAP_DEFAULT = 14000


# ---------------------------------------------------------------------------
# Frontmatter parsing
# ---------------------------------------------------------------------------

def _parse_list(val: str) -> List[str]:
    val = val.strip()
    if val.startswith("[") and val.endswith("]"):
        val = val[1:-1]
    return [x.strip().strip("'\"") for x in val.split(",") if x.strip()]


def _parse_skill(text: str) -> dict:
    """Return {name, description, lanes, cwe, capec, body}."""
    meta = {"name": "", "description": "", "lanes": [], "cwe": [], "capec": [], "body": text}
    m = re.match(r"^---\s*\n(.*?)\n---\s*\n(.*)$", text, re.S)
    if not m:
        return meta
    fm, body = m.group(1), m.group(2)
    meta["body"] = body.strip()
    for line in fm.splitlines():
        if ":" not in line:
            continue
        k, _, v = line.partition(":")
        k = k.strip().lower()
        v = v.strip()
        if k in ("lanes", "cwe", "capec"):
            items = _parse_list(v)
            meta[k] = [int(x) for x in items if x.isdigit()] if k in ("cwe", "capec") else [x.lower() for x in items]
        elif k in ("name", "description"):
            meta[k] = v
    if not meta["name"]:
        meta["name"] = "unknown"
    return meta


@lru_cache(maxsize=1)
def _load_all() -> Dict[str, dict]:
    """name -> parsed skill dict. Cached."""
    out: Dict[str, dict] = {}
    if not os.path.isdir(SKILL_DIR):
        return out
    for fn in sorted(os.listdir(SKILL_DIR)):
        if not fn.endswith(".md"):
            continue
        try:
            with open(os.path.join(SKILL_DIR, fn), errors="ignore") as fh:
                sk = _parse_skill(fh.read())
        except OSError:
            continue
        name = sk["name"] or fn[:-3]
        sk["file"] = fn
        out[name] = sk
    return out


# ---------------------------------------------------------------------------
# Indexes (lane / cwe / keyword -> skill names)
# ---------------------------------------------------------------------------

@lru_cache(maxsize=1)
def _indexes():
    skills = _load_all()
    by_lane: Dict[str, List[str]] = {}
    by_cwe: Dict[int, List[str]] = {}
    for name, sk in skills.items():
        for lane in sk.get("lanes", []):
            by_lane.setdefault(lane, []).append(name)
        for c in sk.get("cwe", []):
            by_cwe.setdefault(c, []).append(name)
    return by_lane, by_cwe


# keyword → skill, for template-ids / finding names that carry no clean lane.
# Order matters: more specific patterns first (csrf before generic ssrf, etc.).
_KEYWORD_SKILL = [
    (re.compile(r"idor|bola|object.?level|broken.?access", re.I), "idor"),
    (re.compile(r"nosql|mongo|\$ne\b|\$where", re.I), "nosql_injection"),
    (re.compile(r"sqli|sql.?inj", re.I), "sqli"),
    (re.compile(r"\bxss\b|cross.?site.?script", re.I), "xss"),
    (re.compile(r"\bxxe\b|xml.?external|external.?entity", re.I), "xxe"),
    (re.compile(r"\bssrf\b|server.?side.?request|metadata|169\.254", re.I), "ssrf"),
    (re.compile(r"\bcsrf\b|cross.?site.?request.?forgery|samesite", re.I), "csrf"),
    (re.compile(r"open.?redirect|redirect.?uri|\bredirect\b", re.I), "open_redirect"),
    (re.compile(r"lfi|rfi|traversal|path.?travers|file.?inclu", re.I), "lfi"),
    (re.compile(r"ssti|template.?inj", re.I), "ssti"),
    (re.compile(r"\brce\b|command.?inj|os.?command|remote.?code", re.I), "rce"),
    (re.compile(r"graphql|introspection|graphiql", re.I), "graphql"),
    (re.compile(r"mass.?assign|auto.?bind|over.?post", re.I), "mass_assignment"),
    (re.compile(r"file.?upload|upload|malicious.?file|webshell", re.I), "file_upload"),
    (re.compile(r"verb.?tamper|http.?method|dangerous.?method|\bput\b|\bdelete\b|options", re.I), "http_methods"),
    (re.compile(r"business.?logic|race.?condition|toctou|workflow|coupon|price", re.I), "business_logic"),
    (re.compile(r"takeover|dangling|cname|nxdomain", re.I), "subdomain_takeover"),
    (re.compile(r"jwt|jwks|alg.?none|auth.?bypass|session|token", re.I), "jwt_auth"),
    (re.compile(r"exposure|\.git|\.env|secret|credential|actuator|backup|disclosure|api.?key", re.I), "secrets_exposure"),
]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def available_skills() -> Dict[str, str]:
    return {n: s.get("description", "") for n, s in _load_all().items() if n != "methodology"}


def list_skills() -> List[str]:
    return sorted(_load_all().keys())


def load_skill(name: str) -> Optional[str]:
    sk = _load_all().get((name or "").lower().strip())
    return sk["body"] if sk else None


def _extract_signals(finding) -> tuple:
    """From a finding dict (or a plain lane string) → (lanes:set, cwes:set, blob:str)."""
    if isinstance(finding, str):
        return {finding.lower()}, set(), finding.lower()
    f = finding or {}
    info = f.get("info", {}) if isinstance(f.get("info"), dict) else {}
    tags = info.get("tags") or f.get("tags") or []
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.split(",")]
    lanes = {str(t).lower() for t in tags}
    a = f.get("attack") or f.get("lane")
    if isinstance(a, str):
        lanes.add(a.lower())
    elif isinstance(a, list):
        lanes.update(str(x).lower() for x in a)
    cls = info.get("classification") or {}
    cwes = set()
    raw = cls.get("cwe-id") or cls.get("cwe_id") or f.get("cwes") or []
    if isinstance(raw, str):
        raw = [raw]
    for c in raw:
        m = re.search(r"(\d+)", str(c))
        if m:
            cwes.add(int(m.group(1)))
    blob = " ".join([str(f.get("template-id") or ""), str(info.get("name") or f.get("name") or ""),
                     " ".join(str(t) for t in tags)]).lower()
    return lanes, cwes, blob


def skills_for_finding(finding) -> List[str]:
    """Ordered, deduped skill names relevant to a finding/lane. methodology never here."""
    by_lane, by_cwe = _indexes()
    lanes, cwes, blob = _extract_signals(finding)
    out: List[str] = []

    def _add(n):
        if n and n != "methodology" and n in _load_all() and n not in out:
            out.append(n)

    for lane in lanes:
        for n in by_lane.get(lane, []):
            _add(n)
    for c in cwes:
        for n in by_cwe.get(c, []):
            _add(n)
    if not out:  # fall back to keyword match on the blob
        for rx, n in _KEYWORD_SKILL:
            if rx.search(blob):
                _add(n)
    return out


def skill_context(lanes=None, cwes=None, tags=None, findings=None,
                  cap_chars: int = _CAP_DEFAULT) -> str:
    """methodology + the playbooks matched by the given signals, capped. Ready to
    inject into a specialist's system prompt."""
    names: List[str] = []

    def _collect(sig):
        for n in skills_for_finding(sig):
            if n not in names:
                names.append(n)

    for lane in (lanes or []):
        _collect(str(lane))
    for t in (tags or []):
        _collect(str(t))
    for f in (findings or []):
        _collect(f)
    if cwes:
        _collect({"info": {"classification": {"cwe-id": [f"CWE-{c}" for c in cwes]}}})

    parts = []
    meth = load_skill("methodology")
    if meth:
        parts.append("# METHODOLOGY (always applies)\n\n" + meth)
    for n in names:
        body = load_skill(n)
        if body:
            parts.append(f"# SKILL: {n}\n\n" + body)
    ctx = "\n\n---\n\n".join(parts)
    return ctx[:cap_chars]


if __name__ == "__main__":
    import json
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "--list":
        print(json.dumps(available_skills(), indent=2))
    else:
        # demo: which skills fire for a sample finding
        demo = {"template-id": "arise-synth-idor-x", "info": {"name": "BOLA",
                "tags": ["arise", "synth", "bola", "idor"], "classification": {"cwe-id": ["CWE-639"]}},
                "attack": "bola"}
        print("skills_for_finding:", skills_for_finding(demo))
        print("available:", list(available_skills().keys()))
        print("context chars:", len(skill_context(findings=[demo])))
