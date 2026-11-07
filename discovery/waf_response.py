#!/usr/bin/env python3
"""
WAF response detector — shared, extractable, single source of truth.

Previously this lived as an inline `python3 - << PYTHON_EOF` heredoc inside
easm-pipeline.sh (Module 8B's forbidden-response verifier). That worked but
nothing else could reuse it: apisec.py, nuclei_url_consolidator.py, and the
new access_control_pipeline.py all needed the same signature list, so they
either duplicated it or (worse) did without it. This module lifts the
signatures + detector into one place so every consumer sees the same rules.

Two entry points:

  is_waf_response(url, timeout=5) -> (is_waf, matched_signatures)
      Full HTTP fetch. Use when you only have a URL and need to ask the
      server "are you actually behind a WAF right now?" — e.g. the streaming
      access-control pipeline after bypass_403 fails.

  waf_signatures_in(headers, body) -> matched_signatures
      No HTTP. Works on a response you already have. Use when you're inside
      another scanner that just probed the URL and doesn't want to spend a
      second round-trip. Any non-empty return means the response looks like
      a WAF block.

Signatures are case-insensitive substrings matched against the combined
header + body blob. The list is deliberately permissive because a WAF's
"tell" can appear in either place — a header key, a cookie value, an
incident-ID in the body — and the false-positive cost (dropping a real 200
we happened to reach) is low compared to the false-negative cost (feeding
a WAF challenge page to nuclei as if it were a real endpoint).
"""

from __future__ import annotations

import sys as _sys, os as _os
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)


import ssl
import urllib.error
import urllib.request
import os
from typing import List, Tuple

# Default UA sent by is_waf_response's probe request. Matches the
# HUMAN_USER_AGENT exported by easm-pipeline.sh so every stage of a scan
# looks like the same browser session — cf-ray / bot-detection heuristics
# often trip on UA churn between stages. Env override wins when set.
DEFAULT_USER_AGENT = os.environ.get(
    "HUMAN_USER_AGENT",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/151.0.0.0 Safari/537.36",
)


# --------------------------------------------------------------------------- #
# Signature list — every WAF vendor whose responses we know how to fingerprint.
# Kept alphabetically-loose but grouped by vendor so additions stay readable.
# Substrings are lower-cased and compared against a lower-cased blob.
# --------------------------------------------------------------------------- #

WAF_SIGNATURES: List[str] = [
    # Cloudflare
    "cf-ray", "cloudflare ray id",
    # Akamai
    "_abck", "bm_sz", "ak_bmsc", "bm_sv", "x-akamai-request-id",
    # Imperva / Incapsula
    "visid_incap_", "incap_ses_", "nlbi_", "x-iinfo", "reference #",
    # AWS CloudFront
    "x-amz-cf-id", "x-amz-cf-pop",
    # Azure Front Door
    "x-azure-ref",
    # F5 BIG-IP / ASM
    "bigipserver", "mrhsession", "lastmrh_session", "support id",
    # Barracuda
    "bnes_", "barra_counter_session", "incident id",
    # Fortinet FortiWeb
    "fortiwafsid",
    # Sucuri
    "x-sucuri-id", "x-sucuri-cache",
    # DataDome
    "datadome", "x-datadome",
    # Signal Sciences / Fastly Next-Gen WAF
    "x-sigsci-requestid", "x-sigsci-agentresponse",
    # Citrix Netscaler AppFirewall
    "nsc_", "nsc_aaac",
    # StackPath
    "x-sl-compstate", "x-sl-gw-pt",
    # Reblaze
    "rbzid",
    # Sophos UTM
    "x-sp-waf",
    # Fastly / Varnish generic
    "x-served-by", "x-cache",
    # ModSecurity (open-source, self-hosted)
    "mod_security", "modsecurity action",
    # Alibaba Cloud WAF
    "eagleeye-traceid",
    # Tencent Cloud WAF
    "x-nws-log-uuid",
    # Huawei Cloud WAF
    "x-hw-waf",
    # Oracle Dyn
    "x-oracle-dms-ecid",
    # Wallarm
    "x-wallarm-block-reason",
    # AppTrana (Indusface)
    "x-apptrana-transaction-id",
    # NAXSI
    "x-naxsi-sig",
    # Cloudbric
    "cloudbric request id",
    # DOSarrest
    "x-dosarrest",
    # Alibaba Yundun
    "yundun", "yd-waf",
    # Safe3
    "safe3waf",
    # KS-WAF (Kingsoft)
    "ks-waf",
    # 360 (Qihoo) Website Guard
    "360wzws",
    # Anquanbao
    "x-powered-by-anquanbao",
]


def waf_signatures_in(headers, body: str) -> List[str]:
    """Return every WAF signature that appears in the given response.

    ``headers`` may be a dict, an http.client.HTTPResponse-style Message, or
    anything that stringifies with sensible key: value output. ``body`` is
    the response body as text (already decoded); binary bodies should be
    decoded with errors='ignore' before calling.

    An empty list = no WAF signal. A non-empty list = the response looks
    like a WAF block/challenge and shouldn't be treated as a real endpoint
    response. Substring matching keeps the check O(len(blob) * len(sigs))
    without regex overhead — the list is short enough for this to be a
    negligible cost even when called per-request.
    """
    if headers is None and not body:
        return []
    blob = (str(headers or "") + (body or "")).lower()
    return [sig for sig in WAF_SIGNATURES if sig in blob]


def is_waf_response(url: str, timeout: int = 5,
                    user_agent: str = None) -> Tuple[bool, List[str]]:
    """Fetch ``url`` and decide whether the response looks like a WAF block.

    Uses stdlib urllib on purpose — no requests-lib dep, so this can drop
    into any pipeline stage without altering imports. TLS verification is
    disabled because a WAF-fronted target may present the WAF's cert, not
    the origin's, and we're evaluating the WAF's response either way.

    Returns (is_waf, matched_signatures). On network error / timeout /
    unparseable response, returns (False, []) — never raises, so callers
    running this in worker threads don't have to wrap every call. That
    fail-open bias is intentional: an unreachable URL isn't proven to be
    WAF-blocked; treat unknowns as "not WAF" and let downstream stages
    decide what to do with them.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(
        url, headers={"User-Agent": user_agent or DEFAULT_USER_AGENT}
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            headers = resp.headers
            body = resp.read(65536).decode("utf-8", errors="ignore")
    except urllib.error.HTTPError as e:
        # A 403/406/429 IS the interesting case for WAF detection — an
        # HTTPError just means the server returned a non-2xx, which is
        # exactly what a WAF block looks like. Read its body + headers and
        # keep going.
        try:
            body = e.read(65536).decode("utf-8", errors="ignore") if e.fp else ""
        except Exception:
            body = ""
        headers = e.headers if e.headers else {}
    except Exception:
        # DNS failure, TLS error, timeout, connection reset — no signal.
        return False, []
    matches = waf_signatures_in(headers, body)
    return (bool(matches), matches)


if __name__ == "__main__":
    # Tiny CLI so operators can sanity-check a single URL from the shell:
    #   python3 waf_response.py https://target.example/api
    import json
    import sys
    if len(sys.argv) < 2:
        print("usage: waf_response.py <url>", file=sys.stderr)
        sys.exit(2)
    is_waf, matches = is_waf_response(sys.argv[1])
    print(json.dumps({"url": sys.argv[1], "is_waf": is_waf,
                      "matched_signatures": matches}, indent=2))
