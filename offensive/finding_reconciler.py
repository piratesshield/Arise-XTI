#!/usr/bin/env python3
"""
ARISE — Finding Reconciler  (Offensive AI Elevation, Phase 1)
=============================================================
One confluence point every offensive finding passes through before an operator
sees it, so that:

  * OVERLAP dies  — Nuclei, Offensive Verification (Module 24), Adaptive Loop
    (Module 27) and the Autonomous engine can each confirm the SAME vuln on the
    SAME URL. Today they surface as 2-3 separate rows with different wording.
    Here they collapse into ONE record keyed on a stable vuln identity.

  * CORROBORATION raises confidence, not row count — when >=2 independent engines
    agree on the same key, the merged record climbs the L0-L6 evidence ladder and
    records who agreed. This mirrors the API engine's existing "2+ tools -> promoted"
    rule (dashboard.py:876).

  * The ORPHAN is adopted — the Autonomous engine's confirmed findings live in
    ai_autonomous.json and are never merged into the vuln list. `from_autonomous`
    converts them into the same unified shape so they finally join (and corroborate).

DESIGN RULES (do no harm to a working, FP-tuned tool)
  - Pure read-side merge. No engine is modified; nothing here fires a request.
  - CONSERVATIVE: two findings merge ONLY when their canonical vuln-class is known
    AND their (class, host, path, param) key matches. An unclassifiable finding
    keeps a unique key and is never collapsed into another — we would rather show
    a near-duplicate than hide a distinct issue.
  - Evidence only accumulates upward (arise_evidence.climb). Merging never lowers
    a finding's rung and never fabricates confirmation.
  - Never raises to the caller. Builds on evidence/arise_evidence.py (L0-L6 ladder
    + provenance) — it does NOT reinvent that vocabulary.

Stdlib only. Importable everywhere.
"""

from __future__ import annotations

import sys as _sys
import os as _os
import re
from typing import Dict, List, Optional, Tuple

_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)

try:
    from evidence import arise_evidence as _ev
except Exception:  # pragma: no cover - evidence layer is stdlib, should always import
    _ev = None


# ---------------------------------------------------------------------------
# Canonical vuln-class taxonomy — single source of truth (tool_registry imports this)
# ---------------------------------------------------------------------------
# Every engine speaks its own dialect for the same underlying weakness. We map
# them all onto ONE class name so the reconcile key is engine-independent.
#
#   offensive_verify CHECKS   : jwt graphql ssti crlf redirect ssrf proto cache
#                               race ws exposure nosqli json_smuggling xxe
#                               business_logic bfla
#   adaptive_loop RECIPES/lanes: sqli xss ssti ssti-lfi rce cmd code-injection
#                               lfi traversal ssrf open-redirect methods
#                               dangerous-methods disclosure version-swap bola
#                               idor auth-jwt jwt graphql file-upload upload
#   nuclei / autonomous       : matched by keyword over template id / tags / title
#
# The VALUE is the canonical class; the KEY set is every alias that maps to it.
VULN_CLASS_ALIASES: Dict[str, set] = {
    "sqli":            {"sqli", "sql-injection", "sql_injection", "sqlinjection", "error-sqli", "blind-sqli"},
    "nosqli":          {"nosqli", "nosql-injection", "nosql_injection"},
    "xss":             {"xss", "reflected-xss", "reflected_xss", "stored-xss", "dom-xss", "cross-site-scripting"},
    "ssti":            {"ssti", "ssti-lfi", "template-injection", "server-side-template-injection"},
    "rce":             {"rce", "cmd", "cmd-injection", "cmd_injection", "command-injection",
                        "code-injection", "code_injection", "remote-code-execution", "os-command-injection"},
    "lfi":             {"lfi", "traversal", "path-traversal", "path_traversal", "lfi_passwd",
                        "local-file-inclusion", "directory-traversal"},
    "ssrf":            {"ssrf", "ssrf_metadata", "server-side-request-forgery"},
    "xxe":             {"xxe", "xml-external-entity", "xxe-injection"},
    "open-redirect":   {"open-redirect", "open_redirect", "redirect", "openredirect"},
    "crlf":            {"crlf", "crlf-injection", "http-response-splitting", "header-injection"},
    "request-smuggling": {"request-smuggling", "http-request-smuggling", "hrs",
                          "http_request_smuggling_surface", "desync", "smuggling"},
    "cors":            {"cors", "cors-misconfig", "cross-origin"},
    "jwt":             {"jwt", "auth-jwt", "jwt-auth", "jwt_forge", "jwt-none", "jwt-confusion"},
    "graphql":         {"graphql", "graphiql", "introspection"},
    "bola":            {"bola", "idor", "bfla", "broken-object-level-authorization",
                        "broken-function-level-authorization", "authz", "authorization"},
    "proto-pollution": {"proto", "proto-pollution", "prototype-pollution", "prototype_pollution"},
    "cache-poison":    {"cache", "cache-poison", "cache-poisoning", "web-cache-poisoning"},
    "race":            {"race", "race-condition", "toctou"},
    "websocket":       {"ws", "websocket", "cswsh", "wss"},
    "http-methods":    {"methods", "dangerous-methods", "http-methods", "http_methods", "verb-tampering"},
    "mass-assignment": {"mass-assignment", "mass_assignment", "autobind"},
    "csrf":            {"csrf", "xsrf", "cross-site-request-forgery"},
    "business-logic":  {"business_logic", "business-logic", "logic-flaw"},
    "json-smuggling":  {"json_smuggling", "json-smuggling"},
    "exposure":        {"exposure", "info-disclosure", "information-disclosure", "disclosure",
                        "version-swap", "debug-exposure", "sensitive-exposure"},
    "secret-leak":     {"secret", "secret-leak", "credential", "credentials", "api-key", "token-leak"},
    "subdomain-takeover": {"subdomain-takeover", "takeover", "dangling-cname"},
    "file-upload":     {"file-upload", "upload", "unrestricted-upload"},
    "pii-leak":        {"pii", "pii-leak", "personal-data"},
}

# Reverse index: alias -> canonical class. Built once.
_ALIAS_TO_CLASS: Dict[str, str] = {}
for _cls, _aliases in VULN_CLASS_ALIASES.items():
    _ALIAS_TO_CLASS[_cls] = _cls
    for _a in _aliases:
        _ALIAS_TO_CLASS[_a] = _cls

# Keyword patterns for classifying free-text template ids / titles / tags where
# there is no explicit check/lane field (nuclei, autonomous). Ordered: the FIRST
# pattern that hits wins, so put the most specific classes first.
_KEYWORD_CLASS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"\bnosql", re.I), "nosqli"),
    (re.compile(r"\bsql[\s_-]?inj|sqli\b", re.I), "sqli"),
    (re.compile(r"\bssti\b|template[\s_-]?inj", re.I), "ssti"),
    (re.compile(r"\bxxe\b|xml[\s_-]?external", re.I), "xxe"),
    (re.compile(r"\bssrf\b|request[\s_-]?forgery", re.I), "ssrf"),
    (re.compile(r"prototype[\s_-]?pollution|\bproto[\s_-]?pollution", re.I), "proto-pollution"),
    (re.compile(r"cache[\s_-]?poison", re.I), "cache-poison"),
    (re.compile(r"\bcrlf\b|response[\s_-]?splitting", re.I), "crlf"),
    (re.compile(r"request[\s_-]?smuggl|\bdesync\b|\bhrs\b", re.I), "request-smuggling"),
    (re.compile(r"\bcors\b|cross[\s_-]?origin", re.I), "cors"),
    (re.compile(r"open[\s_-]?redirect", re.I), "open-redirect"),
    (re.compile(r"\bjwt\b|json[\s_-]?web[\s_-]?token", re.I), "jwt"),
    (re.compile(r"graphql|graphiql|introspection", re.I), "graphql"),
    (re.compile(r"\bbola\b|\bidor\b|\bbfla\b|object[\s_-]?level|function[\s_-]?level", re.I), "bola"),
    (re.compile(r"race[\s_-]?condition|\btoctou\b", re.I), "race"),
    (re.compile(r"web[\s_-]?socket|\bcswsh\b|\bwss\b", re.I), "websocket"),
    (re.compile(r"mass[\s_-]?assign", re.I), "mass-assignment"),
    (re.compile(r"\bcsrf\b|\bxsrf\b", re.I), "csrf"),
    (re.compile(r"\brce\b|remote[\s_-]?code|command[\s_-]?inj|code[\s_-]?inj", re.I), "rce"),
    (re.compile(r"\blfi\b|path[\s_-]?traversal|directory[\s_-]?traversal|/etc/passwd", re.I), "lfi"),
    (re.compile(r"\bxss\b|cross[\s_-]?site[\s_-]?script", re.I), "xss"),
    (re.compile(r"subdomain[\s_-]?takeover|dangling[\s_-]?cname|\btakeover\b", re.I), "subdomain-takeover"),
    (re.compile(r"file[\s_-]?upload|unrestricted[\s_-]?upload", re.I), "file-upload"),
    (re.compile(r"\bsecret|credential|api[\s_-]?key|access[\s_-]?key|password\b", re.I), "secret-leak"),
    (re.compile(r"\bpii\b|personal[\s_-]?data|\bssn\b", re.I), "pii-leak"),
    (re.compile(r"dangerous[\s_-]?method|verb[\s_-]?tamper|http[\s_-]?method", re.I), "http-methods"),
    (re.compile(r"info(?:rmation)?[\s_-]?disclosure|debug|version|exposure", re.I), "exposure"),
]

UNKNOWN_CLASS = "unknown"


def canonical_vuln_class(finding: dict) -> str:
    """Map a finding from ANY engine onto one canonical vuln class, or 'unknown'.

    Precedence: explicit typed fields (check / category / issue_class / lane /
    provenance.lane) first, then a keyword pass over template + title + tags.
    """
    if not isinstance(finding, dict):
        return UNKNOWN_CLASS

    # 1) Explicit typed fields — trust these before free text.
    for field in ("check", "vuln_class", "category", "issue_class", "lane"):
        val = str(finding.get(field, "") or "").lower().strip()
        if val in _ALIAS_TO_CLASS:
            return _ALIAS_TO_CLASS[val]
    prov = finding.get("provenance")
    if isinstance(prov, dict):
        lane = str(prov.get("lane", "") or "").lower().strip()
        if lane in _ALIAS_TO_CLASS:
            return _ALIAS_TO_CLASS[lane]

    # 2) Keyword pass over the free-text identity of the finding.
    tags = finding.get("tags")
    tag_str = " ".join(tags) if isinstance(tags, list) else str(tags or "")
    blob = " ".join(str(finding.get(k, "") or "") for k in ("template", "title", "name")) + " " + tag_str
    for rx, cls in _KEYWORD_CLASS:
        if rx.search(blob):
            return cls
    return UNKNOWN_CLASS


# ---------------------------------------------------------------------------
# Key components — host, normalized path, parameter
# ---------------------------------------------------------------------------
_NUM_SEG = re.compile(r"^\d+$")
_UUID_SEG = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_LONGHEX_SEG = re.compile(r"^[0-9a-f]{16,}$", re.I)
_URL_SPLIT = re.compile(r"^(?:[a-z][a-z0-9+.-]*://)?([^/?#]*)([^?#]*)", re.I)


def _host_of(finding: dict) -> str:
    """Best available host, lower-cased, port/scheme-stripped."""
    host = str(finding.get("host", "") or "").strip().lower()
    if not host or host in ("unknown", "local-file"):
        url = str(finding.get("url", "") or "")
        m = _URL_SPLIT.match(url)
        host = (m.group(1) if m else "").lower()
    # strip creds@ and :port
    host = host.split("@")[-1].split(":")[0]
    return host


def _norm_path(finding: dict) -> str:
    """Path with dynamic id segments collapsed to {id}, so /user/123 and
    /user/456 reconcile to the same endpoint. Query string dropped (the param is
    keyed separately)."""
    url = str(finding.get("url", "") or "")
    if not url:
        # file-based findings (content scan) key on the file path instead
        return str(finding.get("path", "") or finding.get("file", "") or "").lower()
    m = _URL_SPLIT.match(url)
    path = (m.group(2) if m else url) or "/"
    path = path.split("?")[0].split("#")[0]
    segs = []
    for seg in path.split("/"):
        if _NUM_SEG.match(seg) or _UUID_SEG.match(seg) or _LONGHEX_SEG.match(seg):
            segs.append("{id}")
        else:
            segs.append(seg.lower())
    norm = "/".join(segs) or "/"
    return norm.rstrip("/") or "/"


def _param_of(finding: dict) -> str:
    """Injected/affected parameter, if the engine recorded one."""
    p = finding.get("parameter") or finding.get("param")
    if not p:
        loc = finding.get("location")
        if isinstance(loc, dict):
            p = loc.get("param")
    return str(p or "").strip().lower()


def _bucket_key(finding: dict) -> Tuple[str, str, str]:
    """Endpoint+class bucket: (vuln_class, host, normalized_path). Findings only
    ever merge WITHIN a bucket; the parameter is resolved as a second step so a
    param-less nuclei match can still merge with a param-specific confirmation on
    the same endpoint. Unknown-class findings fold their template/title into the
    class slot so they never share a bucket with anything else."""
    cls = canonical_vuln_class(finding)
    host = _host_of(finding)
    path = _norm_path(finding)
    if cls == UNKNOWN_CLASS:
        ident = str(finding.get("template") or finding.get("title") or finding.get("name") or "")[:80].lower()
        cls = UNKNOWN_CLASS + "::" + ident
    return (cls, host, path)


def reconcile_key(finding: dict) -> Tuple[str, str, str, str]:
    """Full engine-independent identity: bucket + parameter. Kept for callers /
    tests that want the complete key; reconcile() itself buckets then resolves
    params (so an empty param can merge into a single explicit-param group)."""
    cls, host, path = _bucket_key(finding)
    return (cls, host, path, _param_of(finding))


# ---------------------------------------------------------------------------
# Evidence rung — map each engine's confidence vocabulary onto the L0-L6 ladder
# ---------------------------------------------------------------------------
# A conservative mapping. When a record already carries an explicit
# `evidence_rung`, we trust it. Otherwise we derive from the engine's own signal.
def evidence_rung(finding: dict) -> str:
    """Return an L0-L6 code. Never raises; defaults conservatively low."""
    explicit = str(finding.get("evidence_rung", "") or "").strip()
    if _ev and _ev.ladder_rank(explicit) >= 0:
        return explicit if explicit.startswith("L") else _ev.ladder_meta(explicit)["code"]

    conf = str(finding.get("confidence", "") or "").lower().strip()
    verif = str(finding.get("verification", "") or "").lower().strip()
    src = str(finding.get("detection_tool") or finding.get("source") or "").lower()

    # Explicit exploitation / OOB / crypto proof is the top of the ladder.
    if conf in ("exploited",) or "oob" in verif or "crypto" in verif or "out-of-band" in verif:
        return "L5"
    if conf == "confirmed" or "differential" in verif:
        return "L4"

    # Autonomous verifier verdict.
    verdict = str(finding.get("verdict", "") or "").lower()
    if verdict == "confirmed":
        return "L4"
    if verdict == "likely":
        return "L3"

    # Adaptive loop: confirmed exploitation vs merely observed.
    if "adaptive" in src:
        return "L4" if finding.get("confirmed") is True else "L3"

    # Nuclei / signature detectors: a match with extracted evidence is a
    # security differential (L3); a bare match is a reproducible anomaly (L2).
    if "nuclei" in src or finding.get("extracted_results"):
        return "L3" if finding.get("extracted_results") else "L2"

    if conf == "probable":
        return "L3"
    # Exposure / secret / response-intel: security-relevant observation.
    return "L3" if canonical_vuln_class(finding) in ("secret-leak", "exposure", "pii-leak") else "L2"


# ---------------------------------------------------------------------------
# Evidence richness — which of two duplicates to keep as the canonical record
# ---------------------------------------------------------------------------
def _richness(finding: dict) -> int:
    """Higher = keep this one. Rewards real wire evidence over a bare label."""
    score = 0
    if finding.get("extracted_results"):
        score += 3
    if finding.get("request") or finding.get("request_line"):
        score += 2
    if finding.get("response"):
        score += 2
    if finding.get("baseline") and finding.get("attack"):
        score += 3
    if finding.get("payload"):
        score += 1
    score += min(len(str(finding.get("impact") or finding.get("evidence") or "")) // 120, 4)
    if finding.get("remediation"):
        score += 1
    return score


def _engine_of(finding: dict) -> str:
    """Coarse engine identity for corroboration counting."""
    return (str(finding.get("detection_tool") or "").lower()
            or str(finding.get("source") or "").lower()
            or "unknown")


# ---------------------------------------------------------------------------
# Autonomous orphan adoption
# ---------------------------------------------------------------------------
def from_autonomous(ai_autonomous: dict) -> List[dict]:
    """Convert ai_autonomous.json `confirmed_findings` into the vuln-list shape so
    they flow through reconcile() alongside every other engine. Only confirmed
    findings are adopted — the Autonomous engine's own no-FP Verifier gate already
    ran, and `likely` verdicts never reach confirmed_findings."""
    out: List[dict] = []
    if not isinstance(ai_autonomous, dict):
        return out
    for f in (ai_autonomous.get("confirmed_findings") or []):
        if not isinstance(f, dict):
            continue
        loc = f.get("location") if isinstance(f.get("location"), dict) else {}
        out.append({
            "source": "Autonomous Engine",
            "detection_tool": "autonomous",
            "template": f.get("title", "Autonomous finding"),
            "title": f.get("title", "Autonomous finding"),
            "severity": (f.get("severity") or "info").lower(),
            "host": f.get("host", "") or "",
            "url": loc.get("url", "") or "",
            "parameter": loc.get("param", "") or "",
            "method": loc.get("method", "") or "",
            "impact": f.get("evidence", "") or f.get("rationale", ""),
            "evidence": f.get("evidence", ""),
            "remediation": f.get("fix", ""),
            "payload": f.get("poc", ""),
            "confidence": "confirmed" if str(f.get("verdict", "")).lower() == "confirmed" else "probable",
            "verification": "autonomous-verifier",
            "verdict": f.get("verdict", ""),
        })
    return out


# ---------------------------------------------------------------------------
# The merge
# ---------------------------------------------------------------------------
_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def reconcile(findings: List[dict]) -> List[dict]:
    """Collapse cross-engine duplicates into one record each.

    For each reconcile_key group:
      - keep the richest finding as the canonical row,
      - climb its evidence rung to the strongest in the group,
      - if >=2 distinct engines contributed, record `corroborated_by` and climb
        one further rung (capped at L6) — agreement is stronger evidence,
      - keep the highest severity seen,
      - stamp the L0-L6 ladder metadata for the dashboard.

    Never raises; on any per-group error the group's members pass through
    unmerged (fail-open toward showing data, never toward hiding it).
    """
    if not isinstance(findings, list):
        return findings if isinstance(findings, list) else []

    # Pass 1 — bucket by (class, host, path).
    buckets: Dict[Tuple[str, str, str], List[dict]] = {}
    order: List[Tuple[str, str, str]] = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        try:
            b = _bucket_key(f)
        except Exception:
            b = (UNKNOWN_CLASS + "::" + str(id(f)), "", "")
        if b not in buckets:
            buckets[b] = []
            order.append(b)
        buckets[b].append(f)

    merged: List[dict] = []
    for b in order:
        # Pass 2 — resolve parameters within the bucket. If the bucket has 0 or 1
        # distinct explicit parameter, everything merges. If it has multiple
        # distinct explicit parameters, those are separate injection points: keep
        # one row per param, and let param-less members join the SINGLE largest
        # param group only when unambiguous (else they stand alone).
        members = buckets[b]
        try:
            for grp in _resolve_params(members):
                merged.append(_merge_group(grp) if len(grp) > 1 else _stamp(grp[0]))
        except Exception:
            for m in members:  # fail-open: never hide data on an edge case
                merged.append(_stamp(m))
    return merged


def _resolve_params(members: List[dict]) -> List[List[dict]]:
    """Split a (class,host,path) bucket into merge-groups by parameter."""
    explicit: Dict[str, List[dict]] = {}
    paramless: List[dict] = []
    for m in members:
        p = _param_of(m)
        if p:
            explicit.setdefault(p, []).append(m)
        else:
            paramless.append(m)
    if not explicit:
        return [members]                      # nobody named a param -> one group
    if len(explicit) == 1:
        only = next(iter(explicit.values()))
        return [only + paramless]             # one param -> absorb param-less
    # Multiple distinct params = distinct injection points. Param-less members are
    # ambiguous; keep them as their own group rather than guessing.
    groups = list(explicit.values())
    if paramless:
        groups.append(paramless)
    return groups


def _merge_group(members: List[dict]) -> dict:
    # Canonical row = richest evidence; tie-break on severity.
    canonical = max(members, key=lambda m: (_richness(m), _SEV_RANK.get(str(m.get("severity", "info")).lower(), 0)))
    out = dict(canonical)

    engines = sorted({_engine_of(m) for m in members if _engine_of(m) != "unknown"})
    # strongest rung across the group
    best_rung = "L0"
    for m in members:
        r = evidence_rung(m)
        best_rung = _ev.climb(best_rung, r) if _ev else (r if r > best_rung else best_rung)
    # highest severity across the group
    best_sev = max((str(m.get("severity", "info")).lower() for m in members),
                   key=lambda s: _SEV_RANK.get(s, 0))
    out["severity"] = best_sev

    # Corroboration: >=2 distinct engines agreeing climbs one further rung.
    if len(engines) >= 2:
        out["corroborated_by"] = engines
        if _ev:
            idx = _ev.ladder_rank(best_rung)
            if 0 <= idx < 6:
                best_rung = _ev.LADDER[idx + 1][0]
        tags = list(out.get("tags") or [])
        if "corroborated" not in tags:
            tags.append("corroborated")
        out["tags"] = tags

    out["reconciled_from"] = sorted({str(m.get("source", "")) for m in members if m.get("source")})

    # Preserve AI-red-team provenance regardless of which member won as canonical:
    # if any contributor was AriseAI, the merged row keeps the AI badge and (when
    # the canonical row lacks them) the AI narrative/PoC so the dashboard can show
    # both the differential proof and the operator write-up on one row.
    if any(m.get("ai_generated") or _engine_of(m) in ("ai_analyst", "ariseai") for m in members):
        out["ai_generated"] = True
        for field in ("ai_narrative", "ai_poc", "owasp_web", "owasp_api", "impact_tier"):
            if not out.get(field):
                for m in members:
                    if m.get(field):
                        out[field] = m[field]
                        break

    return _stamp(out, rung=best_rung)


def _stamp(finding: dict, rung: Optional[str] = None) -> dict:
    """Attach L0-L6 ladder metadata so the dashboard can rank/filter by evidence
    strength and never float an unproven lead above a corroborated confirmation."""
    out = dict(finding)
    r = rung or evidence_rung(finding)
    out["evidence_rung"] = r
    if _ev:
        meta = _ev.ladder_meta(r)
        out["evidence_ladder"] = meta
        out["is_confirmed_evidence"] = meta["confirmed"]
    return out


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------
def _selftest() -> int:
    # canonical class mapping
    assert canonical_vuln_class({"check": "ssti"}) == "ssti"
    assert canonical_vuln_class({"category": "ssti-lfi"}) == "ssti"
    assert canonical_vuln_class({"provenance": {"lane": "auth-jwt"}}) == "jwt"
    assert canonical_vuln_class({"template": "Server-Side Template Injection in q"}) == "ssti"
    assert canonical_vuln_class({"title": "IDOR on /api/orders"}) == "bola"
    assert canonical_vuln_class({"template": "Some Random Banner"}) == "unknown"

    # path normalization collapses ids
    assert _norm_path({"url": "https://x.com/api/user/123/profile"}) == "/api/user/{id}/profile"
    assert _norm_path({"url": "https://x.com/api/user/456/profile"}) == "/api/user/{id}/profile"

    # same vuln from three engines -> ONE row, corroborated, climbs rung
    f_ov = {"source": "Offensive Verification", "detection_tool": "offensive_verify",
            "check": "ssti", "host": "x.com", "url": "https://x.com/s?q=1", "parameter": "q",
            "severity": "high", "confidence": "confirmed", "verification": "differential",
            "baseline": {"status": 200}, "attack": {"status": 200}, "impact": "49 rendered"}
    f_al = {"source": "Adaptive Loop", "detection_tool": "adaptive_loop",
            "category": "ssti", "host": "x.com", "url": "https://x.com/s?q=1", "parameter": "q",
            "severity": "high", "confirmed": True}
    f_nu = {"source": "Nuclei", "detection_tool": "nuclei",
            "template": "ssti detection", "host": "x.com", "url": "https://x.com/s?q=1",
            "severity": "medium"}
    out = reconcile([f_ov, f_al, f_nu])
    assert len(out) == 1, f"expected 1 merged row, got {len(out)}"
    row = out[0]
    assert set(row["corroborated_by"]) >= {"offensive_verify", "adaptive_loop", "nuclei"}
    assert row["severity"] == "high"
    # confirmed (L4) + corroboration climb -> L5, and it must read as confirmed
    assert _ev.ladder_rank(row["evidence_rung"]) >= 4
    assert row["is_confirmed_evidence"] is True

    # distinct vulns do NOT merge
    a = {"check": "ssti", "host": "x.com", "url": "https://x.com/a?q=1", "parameter": "q"}
    b = {"check": "sqli", "host": "x.com", "url": "https://x.com/a?id=1", "parameter": "id"}
    assert len(reconcile([a, b])) == 2

    # unknown-class findings never collapse into each other
    u1 = {"template": "Weird Thing One", "host": "x.com", "url": "https://x.com/p"}
    u2 = {"template": "Weird Thing Two", "host": "x.com", "url": "https://x.com/p"}
    assert len(reconcile([u1, u2])) == 2

    # autonomous orphan adoption + corroboration with offensive_verify
    ai = {"confirmed_findings": [{
        "title": "SSTI via q", "severity": "high", "host": "x.com",
        "location": {"url": "https://x.com/s?q=1", "param": "q", "method": "GET"},
        "evidence": "template evaluated", "verdict": "confirmed", "fix": "escape"}]}
    adopted = from_autonomous(ai)
    assert len(adopted) == 1 and adopted[0]["detection_tool"] == "autonomous"
    out2 = reconcile([f_ov, adopted[0]])
    assert len(out2) == 1
    assert set(out2[0]["corroborated_by"]) >= {"offensive_verify", "autonomous"}

    print("[finding_reconciler] self-test OK — taxonomy + key + merge + corroboration + orphan adoption")
    return 0


if __name__ == "__main__":
    _sys.exit(_selftest())
