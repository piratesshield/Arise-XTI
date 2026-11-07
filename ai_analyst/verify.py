"""
AriseAI — hypothesis grounding & live-verification reconciliation.

The brain PROPOSES attack hypotheses; this module DISPOSES:

  * ground()      — reject any hypothesis whose target host is not in the real
                    evidence (the hard anti-hallucination gate, mirroring the F07
                    fix pattern). Survivors are marked "hypothesis".
  * select()      — pick the top live-verifiable, grounded hypotheses within a
                    budget — the ones worth spending live traffic on.
  * reconcile()   — after safety.live_verify runs, flip a hypothesis to
                    "realized" when a differentially-confirmed live finding
                    matches it, and collapse the live findings into proven
                    records the report consumes.

No network here; the actual firing lives in ai_analyst.safety. Never raises.
"""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

from ai_analyst.constants import LIVE_VERIFIABLE


def _host_grounded(host: str, known_hosts: set, target: str) -> bool:
    if not host:
        return False
    h = host.lower().strip()
    if h in known_hosts:
        return True
    t = (target or "").lower().lstrip("*.")
    return bool(t) and (h == t or h.endswith("." + t) or t in h)


def _norm_path(url: str) -> str:
    import re as _re
    m = _re.match(r"https?://[^/]+(/[^?#]*)", url or "")
    return (m.group(1).rstrip("/") if m else "").lower()


_WAF_BLOCKED_CLASSES = frozenset({
    "sqli", "nosqli", "xss", "ssti", "xxe", "rce", "lfi", "crlf", "proto",
})


def ground(hypotheses: List[Dict[str, Any]], known_hosts, target: str,
           known_urls=None, known_params=None,
           waf_map=None, technologies=None) -> List[Dict[str, Any]]:
    """Anti-hallucination gate (RT3). A hypothesis is REJECTED if its host is not
    in the evidence. If the host is real but the cited URL path or parameter is
    NOT in the evidence, the hop is kept as a hypothesis but DEMOTED — flagged
    `url_grounded`/`param_grounded` False with a reason — so it can never be
    narrated as a confirmed, grounded fact.

    NEW: WAF-awareness — if the host is behind a WAF (from recon), injection-class
    hypotheses are demoted unless the brain explicitly acknowledged the WAF.
    Rejected/demoted hops keep their reason so the report shows the gate worked."""
    hs = {h.lower() for h in (known_hosts or [])}
    urls = {_norm_path(u) for u in (known_urls or []) if u}
    params = {str(p).lower() for p in (known_params or []) if p}
    wm = {h.lower(): v for h, v in (waf_map or {}).items()}
    out = []
    for h in hypotheses:
        hyp = dict(h)
        host = (hyp.get("target_host") or "").strip()
        hyp["vuln_class"] = (hyp.get("vuln_class") or "").lower().strip()
        if not _host_grounded(host, hs, target):
            hyp["status"] = "rejected"
            hyp["reject_reason"] = (
                f"target_host {host!r} not present in scan evidence" if host
                else "no target_host given")
            out.append(hyp)
            continue
        hyp["status"] = "hypothesis"
        # URL grounding (only when a concrete URL was claimed and we have an index).
        u = (hyp.get("target_url") or "").strip()
        if u and urls:
            hyp["url_grounded"] = _norm_path(u) in urls
            if not hyp["url_grounded"]:
                hyp["ground_note"] = f"cited URL path not found in scan evidence: {u[:120]}"
        # Parameter grounding.
        p = (hyp.get("parameter") or "").strip()
        if p and params:
            hyp["param_grounded"] = p.lower() in params
            if not hyp.get("param_grounded"):
                hyp["ground_note"] = (hyp.get("ground_note", "") +
                                      f" | cited parameter not observed: {p}").strip(" |")
        # WAF feasibility check — injection attacks behind a WAF are demoted
        # unless the brain explicitly acknowledged the WAF in waf_considered.
        waf_vendor = wm.get(host.lower())
        if waf_vendor and hyp["vuln_class"] in _WAF_BLOCKED_CLASSES:
            waf_ack = (hyp.get("waf_considered") or "").lower()
            if waf_vendor.lower() not in waf_ack and "bypass" not in waf_ack:
                hyp["waf_demoted"] = True
                hyp["ground_note"] = (hyp.get("ground_note", "") +
                                      f" | host behind {waf_vendor} WAF; injection "
                                      f"hypothesis unlikely without bypass evidence").strip(" |")
        out.append(hyp)
    return out


def select(hypotheses: List[Dict[str, Any]], budget: int = 6) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Return (hypotheses_to_verify, check_names). Only grounded, live-verifiable
    classes, capped at `budget`. WAF-demoted hypotheses are deprioritized (sorted
    after non-demoted), preserving the brain's ranking within each tier."""
    eligible = []
    for h in hypotheses:
        if h.get("status") != "hypothesis":
            continue
        chk = LIVE_VERIFIABLE.get(h.get("vuln_class", ""))
        if not chk:
            continue
        eligible.append((1 if h.get("waf_demoted") else 0, h, chk))
    eligible.sort(key=lambda t: t[0])
    chosen, checks, seen = [], [], set()
    for _, h, chk in eligible:
        chosen.append(h)
        if chk not in seen:
            checks.append(chk)
            seen.add(chk)
        if len(chosen) >= budget:
            break
    return chosen, checks


def _check_to_class(check: str) -> str:
    for cls, chk in LIVE_VERIFIABLE.items():
        if chk == check:
            return cls
    return check


def reconcile(hypotheses: List[Dict[str, Any]],
              live_records: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Match live findings back to hypotheses.

    Returns (updated_hypotheses, newly_proven_records). A hypothesis flips to
    "realized" when a live record shares its host and vuln class. Live records
    with no matching hypothesis are still returned as proven (opportunistic
    confirmations) — honesty over tidiness.
    """
    updated = [dict(h) for h in hypotheses]
    proven = []
    for rec in live_records or []:
        rec_class = _norm_class_from_record(rec)
        rec_host = (rec.get("host") or "").lower()
        matched = False
        for h in updated:
            if h.get("status") not in ("hypothesis", "realized"):
                continue
            if h.get("vuln_class") == rec_class and (h.get("target_host") or "").lower() == rec_host:
                h["status"] = "realized"
                h.setdefault("live_evidence", []).append(rec.get("evidence", "")[:200])
                matched = True
                break
        pr = dict(rec)
        pr["_matched_hypothesis"] = matched
        proven.append(pr)
    return updated, proven


def _norm_class_from_record(rec: Dict[str, Any]) -> str:
    chk = (rec.get("check") or rec.get("category") or "").lower()
    # offensive_verify uses check names; map a couple that differ from our classes.
    cls = _check_to_class(chk) if chk in {v for v in LIVE_VERIFIABLE.values() if v} else chk
    aliases = {"idor": "bola", "exposure": "info-disclosure"}
    return aliases.get(cls, cls)
