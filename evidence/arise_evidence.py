#!/usr/bin/env python3
"""
ARISE — Shared Evidence Primitives (Request Provenance + Confidence Ladder)
===========================================================================
Single source of truth for TWO cross-cutting concepts the WMS bug-bounty
post-mortem surfaced as missing:

  R4  REQUEST PROVENANCE — every URL/observation the pipeline records should
      know WHERE it came from, because a synthetic replay that returns 400 is
      NOT the same evidence as a real browser request that returned 200. The
      pipeline previously mixed HAR requests, browser-runtime requests, raw
      `requests.Session` replays and synthetic probes with no way to tell them
      apart, which is exactly how "200 from a static bootstrap doc" got mistaken
      for a finding and "400 from an incomplete synthetic replay" got mistaken
      for an auth bypass.

  L0-L6 CONFIDENCE LADDER — an autonomous system must not escalate on a status
      code or a mere response change. A finding climbs a ladder:

        L0 observed              — we saw it exist
        L1 anomalous             — it looks different from the norm
        L2 reproducible-anomaly  — the difference repeats
        L3 security-differential — the difference is security-relevant
        L4 authz-violation       — an authorization invariant was broken
        L5 impact-demonstrated   — concrete impact was shown
        L6 reproducible-finding  — independently reproduced

      Only L4-L6 are confirmed vulnerabilities. capec_attack_paths.py already
      scores realized/open chains numerically; this gives the *per-finding*
      evidence rung the offensive/oracle/WSS modules stamp onto each result.

  REFLECTED-INPUT CHECK — the academy.payu.in cloud-metadata-exposure
      post-mortem: a nuclei word-matcher required body text containing
      "iam/security-credentials" to call the finding a confirmed SSRF-to-IMDS
      leak. But that string is a literal substring of the PROBE PATH itself
      (/latest/meta-data/iam/security-credentials/) — any app that echoes the
      requested path anywhere (a redirect-after-login hidden field, a 404
      "no such page: X" message, a canonical link, analytics) satisfies the
      matcher without the server ever producing independent evidence. This is
      the same failure class discovery/response_analysis.py's _strip_payloads
      and api_security/apisec.py's echoed-path stripping already guard against
      for differential oracles — generalized here for single-shot matchers
      (nuclei word/regex matches) that have no baseline response to diff
      against, so any consumer (not just one offensive module) can re-verify
      a "matched word" is genuine server output and not a reflected probe.

Both live here so har_ingest, identity_graph, auth_oracle, wss_agent and the
consolidator all agree on the vocabulary. Stdlib only, importable everywhere,
never raises to the caller.
"""

from __future__ import annotations

import sys as _sys, os as _os
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)


from typing import Dict, Optional

# ---------------------------------------------------------------------------
# R4 — Request provenance
# ---------------------------------------------------------------------------
# Ordered strongest → weakest. "How much do we trust that this request/URL
# reflects REAL application behaviour a legitimate client would produce?"
PROVENANCE_ORDER = [
    "burp-authenticated",  # captured by a human operator in Burp with a KNOWN
                           # role (guest/user/admin) — strongest: carries the
                           # identity label raw HAR cookies can only hint at
    "har",          # captured from a real browser session (HAR export)
    "browser",      # observed live via CDP/Playwright instrumentation
    "api-runtime",  # runtime fetch/XHR intercepted during headless drive
    "crawl",        # gospider/katana/gau followed a real link
    "js",           # endpoint mined from JavaScript source
    "dirbrute",     # dirsearch/ffuf guessed the path (existence ≠ real flow)
    "synthetic",    # WE fabricated the request (probe / base-path seed)
    "attack",       # WE sent an attack payload (never a baseline)
    "unknown",
]

_PROV_RANK = {p: i for i, p in enumerate(PROVENANCE_ORDER)}

# Map the consolidator's `source` tags onto canonical provenance classes, so a
# record's provenance can be derived even before a HAR/browser layer exists.
SOURCE_PROVENANCE = {
    "input": "browser",         # Module 20.2 CDP input discovery
    "api-runtime": "api-runtime",
    "burp-authenticated": "burp-authenticated",
    "burp": "burp-authenticated",
    "burp-bridge": "burp-authenticated",
    "har": "har",
    "browser": "browser",
    "js": "js",
    "crawled": "crawl",
    "gau": "crawl",
    "http-discovery": "crawl",
    "param-fuzz": "crawl",
    "dirsearch": "dirbrute",
    "attack": "attack",
    "synthetic": "synthetic",
}


def provenance_of(source: str) -> str:
    """Canonical provenance class for a consolidator source tag."""
    return SOURCE_PROVENANCE.get((source or "").lower().strip(), "unknown")


def provenance_rank(prov: str) -> int:
    """Lower = stronger evidence. Unknown sorts last."""
    return _PROV_RANK.get((prov or "").lower().strip(), len(PROVENANCE_ORDER))


def stronger_provenance(a: str, b: str) -> str:
    """Return whichever provenance is the stronger evidence class."""
    return a if provenance_rank(a) <= provenance_rank(b) else b


def is_real_traffic(prov: str) -> bool:
    """True when the provenance means a real client produced this request —
    the class of evidence that must NOT be dismissed as 'endpoint broken' when
    a synthetic replay of the same URL fails."""
    return (prov or "").lower().strip() in ("burp-authenticated", "har", "browser", "api-runtime")


def provenance_weight(prov: str) -> float:
    """A 0..1 evidence multiplier for confidence scoring. Real browser traffic
    is fully trusted; a guessed/synthetic request is heavily discounted."""
    return {
        "burp-authenticated": 1.0, "har": 1.0, "browser": 0.95, "api-runtime": 0.9,
        "crawl": 0.7, "js": 0.6, "dirbrute": 0.45,
        "synthetic": 0.3, "attack": 0.5, "unknown": 0.4,
    }.get((prov or "").lower().strip(), 0.4)


def provenance_note(baseline_prov: str, synthetic_status: Optional[int],
                    observed_status: Optional[int]) -> Optional[str]:
    """The exact WMS lesson, encoded: a synthetic replay returning 4xx while the
    SAME url has real-traffic provenance returning 2xx means 'browser context
    required', NOT 'endpoint broken / auth bypass'. Returns a human note or
    None when the two agree / no real-traffic baseline exists."""
    if not is_real_traffic(baseline_prov):
        return None
    if synthetic_status is None or observed_status is None:
        return None
    syn_bad = synthetic_status >= 400
    obs_ok = 200 <= observed_status < 400
    if syn_bad and obs_ok:
        return ("browser-context-required: real traffic returned "
                f"{observed_status} but a synthetic replay returned "
                f"{synthetic_status} — the endpoint needs the browser's "
                "session/protocol context, this is NOT an auth bypass")
    return None


# ---------------------------------------------------------------------------
# L0-L6 — Confidence / evidence ladder
# ---------------------------------------------------------------------------
LADDER = [
    ("L0", "observed",             "we saw it exists"),
    ("L1", "anomalous",            "it differs from the norm"),
    ("L2", "reproducible-anomaly", "the difference repeats"),
    ("L3", "security-differential","the difference is security-relevant"),
    ("L4", "authz-violation",      "an authorization invariant was broken"),
    ("L5", "impact-demonstrated",  "concrete impact was shown"),
    ("L6", "reproducible-finding", "independently reproduced"),
]

_LADDER_RANK = {code: i for i, (code, _name, _desc) in enumerate(LADDER)}
_LADDER_BY_NAME = {name: code for code, name, _desc in LADDER}

# The rung at/above which a candidate becomes a CONFIRMED vulnerability.
CONFIRMED_RUNG = "L4"


def ladder_rank(rung: str) -> int:
    """Numeric rung (0..6). Accepts 'L4' or the name 'authz-violation'."""
    r = (rung or "").strip()
    if r in _LADDER_RANK:
        return _LADDER_RANK[r]
    if r in _LADDER_BY_NAME:
        return _LADDER_RANK[_LADDER_BY_NAME[r]]
    return -1


def ladder_name(rung: str) -> str:
    code = rung if rung in _LADDER_RANK else _LADDER_BY_NAME.get(rung, "")
    if not code:
        return "unknown"
    return LADDER[_LADDER_RANK[code]][1]


def is_confirmed(rung: str) -> bool:
    """True only for L4+ — the rungs an autonomous system may escalate on."""
    r = ladder_rank(rung)
    return r >= 0 and r >= _LADDER_RANK[CONFIRMED_RUNG]


def climb(current: str, target: str) -> str:
    """Return the higher of two rungs (evidence only ever accumulates upward)."""
    return current if ladder_rank(current) >= ladder_rank(target) else target


def ladder_meta(rung: str) -> Dict[str, str]:
    """Full {code,name,description,confirmed} for a rung, for finding records."""
    idx = ladder_rank(rung)
    if idx < 0:
        return {"code": "L0", "name": "observed",
                "description": "we saw it exists", "confirmed": False}
    code, name, desc = LADDER[idx]
    return {"code": code, "name": name, "description": desc,
            "confirmed": is_confirmed(code)}


# ---------------------------------------------------------------------------
# Reflected-input check — is a matched "word" genuine server output, or just
# the probe's own path/query echoed back?
# ---------------------------------------------------------------------------
import re as _re
import urllib.parse as _urlparse

_MIN_ECHO_LEN = 4  # shorter substrings (e.g. "id", "v1") echo-match by chance


def _echo_sources(url: str = "", request_path: str = "") -> list:
    """Every attacker-controlled string a probe sent that a response could
    trivially echo back: the URL path (raw + decoded) AND each individual
    "/"-delimited path segment, plus each query parameter's key and value.

    Segments matter because an app rarely echoes the exact path string back
    verbatim — a category breadcrumb, a client-side router, or a "subfilters"
    listing page will reorder/insert/drop segments (academy.payu.in's store
    page echoed .../subfilters/latest/meta-data/... — an extra segment the
    probe never sent) while still echoing the individual distinctive
    components ("security-credentials") that make a word-matcher fire.
    Stripping whole-path-only would miss that; segment-level stripping
    catches it without needing to model every possible reflection shape.

    Header values the probe set (e.g. a static 'Metadata: true') are NOT
    included — those are constant across every target and can't produce a
    false match by being echoed."""
    sources = []
    for raw in (request_path, url):
        if not raw:
            continue
        try:
            p = _urlparse.urlsplit(raw if "://" in raw else "x://x" + raw)
        except Exception:
            continue
        path = p.path or ""
        if path:
            sources.append(path)
            for seg in path.split("/"):
                if seg:
                    sources.append(seg)
            try:
                decoded = _urlparse.unquote(path)
                if decoded != path:
                    sources.append(decoded)
                    for seg in decoded.split("/"):
                        if seg:
                            sources.append(seg)
            except Exception:
                pass
        if p.query:
            try:
                for k, v in _urlparse.parse_qsl(p.query, keep_blank_values=True):
                    if k:
                        sources.append(k)
                    if v:
                        sources.append(v)
            except Exception:
                pass
    # Longest first, so a longer echo source "shadows" a shorter one it
    # contains when stripping (doesn't change correctness, just avoids
    # leaving short fragments of an already-stripped longer match).
    return sorted({s for s in sources if len(s) >= _MIN_ECHO_LEN}, key=len, reverse=True)


def strip_reflected_input(body: str, url: str = "", request_path: str = "") -> str:
    """Remove substrings that are simply the probe's own request path/query
    echoed back, so a downstream word/regex matcher only sees content the
    SERVER produced independently. Mirrors
    discovery/response_analysis.py's _strip_payloads (built for differential
    SQLi oracles) and api_security/apisec.py's echoed-path stripping (built
    for 404-fingerprint normalization) — same concept, generalized for any
    single-response matcher with no baseline to diff against."""
    if not body:
        return body
    out = body
    for src in _echo_sources(url, request_path):
        if src in out:
            out = out.replace(src, "")
    return out


def words_survive_reflection_strip(words: list, url: str = "",
                                   body: str = "", request_path: str = "") -> Dict[str, bool]:
    """For each word a template's word-matcher claims matched, confirm it is
    still present after the probe's own path/query is stripped from the body.
    `True` = the word appears in content the server produced independently;
    `False` = the word was only present because it's an echo of the request
    itself (or wasn't in the body at all)."""
    scrubbed = strip_reflected_input(body or "", url, request_path)
    return {w: bool(w) and w in scrubbed for w in (words or [])}


def reflected_fp_note(words: list, url: str = "", body: str = "",
                      request_path: str = "") -> Optional[str]:
    """None if at least one matched word is genuine (non-reflected) server
    evidence. Otherwise a human-readable false-positive explanation — every
    word this matcher relied on turned out to be an echo of the probe's own
    URL/path, not independent content the server produced."""
    if not words:
        return None
    present_in_raw = [w for w in words if w and w in (body or "")]
    if not present_in_raw:
        return None  # matcher didn't actually fire on this body at all
    survivors = words_survive_reflection_strip(present_in_raw, url, body, request_path)
    if any(survivors.values()):
        return None
    reflected = [w for w, ok in survivors.items() if not ok]
    return ("reflected-input false positive: matched word(s) "
            f"{reflected} only appear in the response because they are "
            "literal substrings of the probed URL/path, echoed back by the "
            "app (e.g. a redirect-after-login field, 404 message, canonical "
            "link, analytics) — not independent server-side evidence")


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------
def _selftest() -> int:
    assert provenance_of("dirsearch") == "dirbrute"
    assert provenance_of("input") == "browser"
    assert provenance_rank("har") < provenance_rank("synthetic")
    assert stronger_provenance("synthetic", "har") == "har"
    assert is_real_traffic("browser") and not is_real_traffic("dirbrute")
    assert provenance_weight("har") == 1.0

    note = provenance_note("har", 400, 200)
    assert note and "browser-context-required" in note
    assert provenance_note("dirbrute", 400, 200) is None
    assert provenance_note("har", 200, 200) is None

    assert ladder_rank("L4") == 4
    assert ladder_rank("authz-violation") == 4
    assert not is_confirmed("L3")
    assert is_confirmed("L4") and is_confirmed("L6")
    assert climb("L1", "L5") == "L5"
    assert climb("L5", "L2") == "L5"
    assert ladder_meta("L4")["confirmed"] is True
    assert ladder_meta("L3")["confirmed"] is False

    # Reflected-input check: the academy.payu.in cloud-metadata-exposure case.
    url = "https://academy.payu.in/s/latest/meta-data/iam/security-credentials/"
    body = ('<input type="hidden" id="redirectUrl" name="url" '
            'value="/s/latest/meta-data/iam/security-credentials/"/>')
    words = ["ami-id", "instance-id", "iam/security-credentials",
             "AccessKeyId", "InstanceProfileArn"]
    note = reflected_fp_note(words, url=url, body=body)
    assert note and "reflected-input false positive" in note
    assert strip_reflected_input(body, url=url).find("security-credentials") == -1

    # Same word list, but a body that genuinely carries IMDS output (not an
    # echo of the request path) must NOT be flagged.
    real_body = '{"Code":"Success","AccessKeyId":"ASIAABCDEF123456","Type":"AWS-HMAC"}'
    assert reflected_fp_note(words, url=url, body=real_body) is None

    # A word matcher that never actually matched the body at all (caller
    # error / unrelated template) is left alone — nothing to flag.
    assert reflected_fp_note(["ami-id"], url=url, body="totally unrelated page") is None

    print("[arise_evidence] self-test OK — provenance + L0-L6 ladder + "
          "reflected-input check")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(_selftest())
