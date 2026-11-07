"""Offline-first KEV + best-effort EPSS lookup for Issues-view enrichment.

KEV (CISA Known-Exploited-Vulnerabilities) is read straight from the local
``.arise_kev_cache.json`` that internet_intel already maintains — no network in
the request path. EPSS (exploitation probability) is fetched best-effort with a
short timeout and memoised in-process for 24h, so a dashboard request never
blocks on it and degrades cleanly to ``None`` when offline.

Both functions are pure lookups: they never raise into the caller.
"""
import json
import os
import time

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_KEV_CACHE = os.path.join(PROJECT_ROOT, '.arise_kev_cache.json')

# in-process memo so repeated Issues-view loads don't re-read / re-fetch
_kev_memo = {'set': None, 'ts': 0.0}
_epss_memo = {}  # CVE (upper) -> (score|None, fetched_ts)

_KEV_TTL = 600       # re-read the local cache at most every 10 min
_EPSS_TTL = 86400    # EPSS moves daily


def load_kev():
    """Set of KEV CVE ids (upper-cased). Local cache only — never hits network."""
    now = time.time()
    if _kev_memo['set'] is not None and now - _kev_memo['ts'] < _KEV_TTL:
        return _kev_memo['set']
    s = set()
    try:
        with open(_KEV_CACHE, 'r') as f:
            d = json.load(f)
        if isinstance(d, dict):
            s = set(str(c).upper() for c in (d.get('cves') or []))
    except Exception:
        s = set()
    _kev_memo['set'] = s
    _kev_memo['ts'] = now
    return s


def load_epss(cves, timeout=4):
    """Best-effort {CVE: epss_prob} for the given CVE ids. Offline-safe → {}.

    Uses internet_intel._load_epss under the hood (same endpoint the pipeline
    uses) but only for CVEs not already memoised, with a short timeout.
    """
    out = {}
    cves = [str(c).upper() for c in (cves or []) if c]
    if not cves:
        return out
    now = time.time()
    missing = []
    for c in cves:
        memo = _epss_memo.get(c)
        if memo and now - memo[1] < _EPSS_TTL:
            if memo[0] is not None:
                out[c] = memo[0]
        else:
            missing.append(c)
    if missing:
        got = {}
        try:
            from intel import internet_intel as _ii
            got = _ii._load_epss(missing, timeout, None) or {}
        except Exception:
            got = {}
        for c in missing:
            sc = got.get(c)
            _epss_memo[c] = (sc, now)
            if sc is not None:
                out[c] = sc
    return out
