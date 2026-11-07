#!/usr/bin/env python3
"""
Mine parameter names + URL fragments out of downloaded JS.

Every hardcoded param name inside a SPA bundle is a real submit key: `next`,
`redirect_url`, `callback`, `returnTo`, `debug`, `impersonate`, `siteId`. If
they never reach the param-fuzzing candidate list, whole classes of vulns
(open-redirect, SSRF via redirect, IDOR via siteId, debug-toggle info-leak)
get missed. arjun-style black-box param brute-force works for that but it's
slow and noisy — mining the client's own JS is faster, less-observable, and
almost always finds the RIGHT names.

What we mine
------------
From every .js file in scan_dir/09_crawling/js_downloads/:

  1. Query-string param names inside string literals — patterns like
     `"?utm_source=" + x`, `"&redirect_url=" + y`, `url.searchParams.append("id")`
  2. Form-field name attributes and axios/fetch config `params: { … }` keys
  3. Config object keys that look param-shaped in URLs (short, lowercase or
     snake_case, no punctuation)
  4. URL path templates — strings like `/api/v1/users/{id}` or `/api/users/${id}`
     that reveal endpoints not seen at crawl time

Output
------
  js_param_candidates.txt — one param name per line, sorted, deduped, filtered
    to plausible names (2..30 chars, alnum + _-)

  js_url_templates.txt — one URL template per line (raw, no substitution)

Downstream:
  - The parameter_fuzzing module can merge js_param_candidates.txt into its
    LFI_PARAM_RE-matched target list.
  - api_intelligence_engine can absorb js_url_templates as additional
    endpoints to probe (feed into method-enumeration/schema-diff).

Design decisions
----------------
* Pure Python + stdlib. No JS parser (esprima et al) — regex plus a light
  balanced-brace walk is enough for the shapes JS bundlers actually produce,
  and doesn't add a heavyweight dep to the pipeline. Fully-obfuscated bundles
  will still leak SOME param names via string literals.
* Whitelist-based param name filter: too permissive here creates FP fuzz
  targets. The whitelist keeps only ~real-world-looking API params.
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
from pathlib import Path
from typing import Iterable, Set

# Query-string embedded params inside JS string concatenation:
#   "?foo=" + x, "&bar=", '?q=', '?redirect_url='.
# Single-char names are allowed here (JSON-shaped `?q=`, `?v=` etc); noise
# filtering happens via _STOP_PARAMS.
_QS_LITERAL_RE = re.compile(r"""[?&]([A-Za-z_][A-Za-z0-9_\-.]{0,29})=""")

# searchParams.append("name", ...) / .set / .get / .has patterns
_SEARCH_PARAMS_RE = re.compile(
    r"""searchParams\s*\.\s*(?:append|set|get|has|delete)\s*\(\s*['"]([A-Za-z_][A-Za-z0-9_\-.]{0,29})['"]"""
)

# axios / fetch config: params: { key: val } — capture the block INCLUDING
# the outer braces so _OBJ_KEY_RE can anchor on the opening `{`. Without
# that anchor the first key in the block (e.g. `id`) was silently dropped.
_AXIOS_PARAMS_BLOCK_RE = re.compile(
    r"""\bparams\s*:\s*(\{[^{}]{0,600}\})""", re.DOTALL
)
_OBJ_KEY_RE = re.compile(r"""(?:^|[{,\s])\s*['"]?([A-Za-z_][A-Za-z0-9_]{0,29})['"]?\s*:""")

# URL path templates: any quoted string starting with `/` that also contains
# a template token (`${x}`, `{x}`, or `:x` express-route style). Extracting
# the whole quoted path and letting a second pass find the tokens keeps the
# regex simple and works on the shape SPAs actually emit (mixed literal +
# template segments like `/api/users/{id}/posts`).
_QUOTED_PATH_RE = re.compile(r"""(['"`])(/[^'"`\s]{1,300})['"`]""")
_HAS_TEMPLATE_TOKEN_RE = re.compile(r"""\$\{[^}]+\}|\{[A-Za-z_][A-Za-z0-9_]{0,29}\}|:[A-Za-z_][A-Za-z0-9_]{0,29}""")
_TEMPLATE_TOKEN_NAME_RE = re.compile(r"""(?:\$\{|\{|:)([A-Za-z_][A-Za-z0-9_]{0,29})""")

# Explicit form-field name= attributes in HTML fragments inside JS strings.
_FORM_NAME_RE = re.compile(r"""name\s*=\s*['"]([A-Za-z_][A-Za-z0-9_\-.]{0,29})['"]""")

# Stopwords that ARE common in query strings but are noise for param fuzzing.
# Kept short; the goal is to remove analytics/tracking params only.
_STOP_PARAMS = {
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "gclid", "fbclid", "msclkid", "yclid", "mc_cid", "mc_eid",
    "hsCtaTracking", "_ga", "_gid", "_gac",
    # Extremely generic names — safer to skip than to burn fuzz budget on them.
    "s", "k", "d", "e", "n", "t", "v",
}


def _iter_js_files(js_dir: Path) -> Iterable[Path]:
    if not js_dir.is_dir():
        return
    for f in js_dir.iterdir():
        if f.is_file() and f.suffix.lower() == ".js":
            yield f


def _extract_params(text: str) -> Set[str]:
    found: Set[str] = set()
    for m in _QS_LITERAL_RE.finditer(text):
        found.add(m.group(1))
    for m in _SEARCH_PARAMS_RE.finditer(text):
        found.add(m.group(1))
    for m in _AXIOS_PARAMS_BLOCK_RE.finditer(text):
        block = m.group(1)
        for km in _OBJ_KEY_RE.finditer(block):
            found.add(km.group(1))
    for m in _FORM_NAME_RE.finditer(text):
        found.add(m.group(1))
    # URL path template tokens — only quoted paths that CONTAIN a template
    # marker qualify; the token names inside `${...}` / `{...}` / `:name`
    # become param candidates.
    for m in _QUOTED_PATH_RE.finditer(text):
        path = m.group(2)
        if _HAS_TEMPLATE_TOKEN_RE.search(path):
            for tm in _TEMPLATE_TOKEN_NAME_RE.finditer(path):
                found.add(tm.group(1))
    # Filter noise. Single-char names must be alphabetic AND not in
    # the aggressive stopwords list.
    return {p for p in found
            if p not in _STOP_PARAMS
            and 1 <= len(p) <= 30
            and not p.isdigit()}


def _extract_url_templates(text: str) -> Set[str]:
    tmpls: Set[str] = set()
    for m in _QUOTED_PATH_RE.finditer(text):
        path = m.group(2)
        if _HAS_TEMPLATE_TOKEN_RE.search(path):
            tmpls.add(path)
    return tmpls


def mine(scan_dir: Path) -> tuple[int, int]:
    js_dir = scan_dir / "09_crawling" / "js_downloads"
    out_params = scan_dir / "09_crawling" / "js_param_candidates.txt"
    out_tmpls = scan_dir / "09_crawling" / "js_url_templates.txt"
    all_params: Set[str] = set()
    all_tmpls: Set[str] = set()
    for jf in _iter_js_files(js_dir):
        try:
            text = jf.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        all_params |= _extract_params(text)
        all_tmpls  |= _extract_url_templates(text)
    with open(out_params, "w", encoding="utf-8") as w:
        for p in sorted(all_params):
            w.write(p + "\n")
    with open(out_tmpls, "w", encoding="utf-8") as w:
        for t in sorted(all_tmpls):
            w.write(t + "\n")
    return len(all_params), len(all_tmpls)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Mine params + URL templates from JS")
    ap.add_argument("scan_dir")
    args = ap.parse_args()
    p, t = mine(Path(args.scan_dir))
    print(f"[js-param-miner] params={p} url_templates={t}", file=sys.stderr)
