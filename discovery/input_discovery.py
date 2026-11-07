#!/usr/bin/env python3
"""
ARISE Input-Functions Discovery (CDP / Playwright)
==================================================
Module 20.2 — drives a real Chrome over the Chrome DevTools Protocol (via
Playwright) to discover the application's INPUT FUNCTIONS: what each page lets a
user submit — search, login, register, file upload, comment/post, profile edit
— together with the captured request/query FORMAT (method, enctype, param/body
keys, whether it accepts a file).

Why CDP and not HTML crawling: modern SPAs build forms at runtime and submit via
fetch()/XHR with JSON or multipart bodies, so <form> tags in the initial HTML
miss most real input surface. Here we:
  1. inject instrumentation BEFORE page scripts run — hook fetch / XMLHttpRequest
     / FormData so every runtime request (method, content-type, body keys, file
     appends) is recorded, even for dynamically-created widgets;
  2. observe the live DOM (incl. MutationObserver-added nodes) for forms, inputs,
     textareas, selects and — critically — input[type=file] upload widgets;
  3. also tap the CDP network layer (page.on("request")) for real POST bodies.

Each discovered input function is classified and written to
  <scan-dir>/20_api_deep_discovery/input_functions.jsonl
for the endpoint consolidator (Module 8B) to fold into the URL Inventory as the
"Input Functions" column.

Degrades gracefully: if Playwright or a Chrome channel is unavailable the module
logs a warning and writes an empty result (the pipeline continues).

Usage:
  python3 input_discovery.py <target> --scan-dir <dir> [--max-pages N]
                             [--timeout MS] [--channel chrome] [--urls file]
"""

from __future__ import annotations

import sys as _sys, os as _os
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)


import argparse
import json
import os
import sys
import urllib.parse
from pathlib import Path
from typing import Dict, List, Optional, Set

try:
    from discovery.url_classify import input_function, _host_of  # shared classifier
except Exception:  # pragma: no cover
    input_function = None

    def _host_of(u):  # minimal fallback
        try:
            return urllib.parse.urlsplit(u if "://" in u else "//" + u).netloc.split(":")[0].lower()
        except Exception:
            return ""


def log(msg: str) -> None:
    print(f"[input-discovery] {msg}", file=sys.stderr, flush=True)


def _resolve_cdp(scan_dir: Path, cdp_arg: str = "") -> Optional[str]:
    """Find the app-owned dedicated Chrome's CDP url: explicit --cdp-url, then
    $ARISE_CHROME_CDP / the scan-dir endpoint file (via chrome_service)."""
    import json as _json
    import urllib.request as _rq

    def alive(u: str) -> bool:
        try:
            with _rq.urlopen(u + "/json/version", timeout=2) as r:
                return r.status == 200
        except Exception:
            return False

    if cdp_arg and alive(cdp_arg):
        return cdp_arg
    try:
        from recon.chrome_service import resolve_cdp_url
        return resolve_cdp_url(scan_dir)
    except Exception:
        # inline fallback if chrome_service isn't importable
        env = (os.environ.get("ARISE_CHROME_CDP") or "").strip()
        if env and alive(env):
            return env
        ep = scan_dir / ".arise_chrome.json"
        if ep.exists():
            try:
                u = _json.loads(ep.read_text()).get("url", "")
                if u and alive(u):
                    return u
            except Exception:
                pass
    return None


# ---------------------------------------------------------------------------
# Instrumentation injected into every page BEFORE its own scripts run.
# Records runtime fetch/XHR calls and FormData file appends into window.__ARISE.
# ---------------------------------------------------------------------------
INSTRUMENTATION = r"""
(() => {
  if (window.__ARISE) return;
  window.__ARISE = { xhr: [], file_fields: [] };
  const push = (rec) => { try { window.__ARISE.xhr.push(rec); } catch(e){} };

  // FormData.append(name, File|Blob) -> mark file-accepting field
  try {
    const origAppend = FormData.prototype.append;
    FormData.prototype.append = function(name, value) {
      try {
        if (value instanceof Blob || (value && typeof value === 'object'
            && 'size' in value && 'name' in value)) {
          window.__ARISE.file_fields.push(String(name));
        }
      } catch(e){}
      return origAppend.apply(this, arguments);
    };
  } catch(e){}

  const bodyKeys = (body) => {
    try {
      if (!body) return { keys: [], ct: '' };
      if (body instanceof FormData) {
        const ks = []; for (const k of body.keys()) ks.push(k);
        return { keys: ks, ct: 'multipart/form-data' };
      }
      if (typeof body === 'string') {
        const s = body.trim();
        if (s[0] === '{' || s[0] === '[') { try { return { keys: Object.keys(JSON.parse(s)), ct: 'application/json' }; } catch(e){} }
        if (s.includes('=')) return { keys: s.split('&').map(p => p.split('=')[0]), ct: 'application/x-www-form-urlencoded' };
      }
    } catch(e){}
    return { keys: [], ct: '' };
  };

  // fetch()
  try {
    const origFetch = window.fetch;
    window.fetch = function(input, init) {
      try {
        const url = (typeof input === 'string') ? input : (input && input.url) || '';
        let method = (init && init.method) || (input && input.method) || 'GET';
        let ct = '';
        try { if (init && init.headers) ct = new Headers(init.headers).get('content-type') || ''; } catch(e){}
        const bk = bodyKeys(init && init.body);
        push({ url, method: String(method).toUpperCase(), content_type: ct || bk.ct, body_keys: bk.keys, kind: 'fetch' });
      } catch(e){}
      return origFetch.apply(this, arguments);
    };
  } catch(e){}

  // XMLHttpRequest
  try {
    const origOpen = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function(method, url) {
      this.__arise = { method: String(method || 'GET').toUpperCase(), url: url };
      return origOpen.apply(this, arguments);
    };
    const origSend = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.send = function(body) {
      try {
        const info = this.__arise || {};
        const bk = bodyKeys(body);
        push({ url: info.url || '', method: info.method || 'GET', content_type: bk.ct, body_keys: bk.keys, kind: 'xhr' });
      } catch(e){}
      return origSend.apply(this, arguments);
    };
  } catch(e){}
})();
"""

# Extract every form + control from the live DOM (post-mutation).
FORM_EXTRACTOR = r"""
() => {
  const ctl = (el) => ({
    name: el.name || el.id || '',
    type: (el.type || el.tagName || '').toLowerCase(),
    required: !!el.required,
    placeholder: el.placeholder || '',
    aria: el.getAttribute('aria-label') || '',
    pattern: el.getAttribute('pattern') || '',
    maxlength: el.getAttribute('maxlength') || '',
    accept: el.getAttribute('accept') || '',
    is_file: (el.type || '').toLowerCase() === 'file'
  });
  const forms = [...document.querySelectorAll('form')].map(f => ({
    action: f.getAttribute('action') || '',
    method: (f.getAttribute('method') || 'get').toLowerCase(),
    enctype: f.enctype || (f.getAttribute('enctype') || ''),
    id: f.id || '', name: f.getAttribute('name') || '',
    controls: [...f.querySelectorAll('input,textarea,select,button')].map(ctl)
  }));
  // stand-alone controls not inside a <form> (SPA search boxes, uploaders)
  const loose = [...document.querySelectorAll('input,textarea,select')]
    .filter(el => !el.closest('form')).map(ctl);
  return { forms, loose, file_inputs: [...document.querySelectorAll('input[type=file]')].length,
           runtime: (window.__ARISE || { xhr: [], file_fields: [] }) };
}
"""


def _norm_url(base: str, action: str) -> str:
    if not action:
        return base
    try:
        return urllib.parse.urljoin(base, action)
    except Exception:
        return action or base


def _discover_page(page, url: str, timeout: int) -> List[Dict]:
    """Visit one URL, capture forms + runtime requests, return input-function records."""
    records: List[Dict] = []
    net: List[Dict] = []

    def on_request(req):
        try:
            m = req.method.upper()
            if m in ("GET", "HEAD") and not req.post_data:
                return  # only interesting for method+body-bearing requests
            ct = (req.headers or {}).get("content-type", "")
            keys: List[str] = []
            pd = req.post_data or ""
            if pd:
                s = pd.strip()
                if s[:1] in "{[":
                    try:
                        j = json.loads(s)
                        keys = list(j.keys()) if isinstance(j, dict) else []
                    except Exception:
                        pass
                elif "=" in s and "&" in s or "=" in s:
                    keys = [p.split("=")[0] for p in s.split("&") if "=" in p]
            net.append({"url": req.url, "method": m, "content_type": ct,
                        "body_keys": keys, "kind": "network"})
        except Exception:
            pass

    page.on("request", on_request)
    try:
        page.goto(url, wait_until="domcontentloaded", timeout=timeout)
        # Give slow SPA frameworks time to hydrate and fire their initial XHRs.
        page.wait_for_timeout(min(timeout, int(os.environ.get("INPUT_DISCOVERY_SPA_WAIT_MS", "4000"))))
        # Progressive scroll: many apps lazy-load routes/data only as the user
        # scrolls (infinite lists, deferred sections). Step down the page in
        # several passes so those deferred XHRs and DOM inputs actually appear,
        # instead of a single 2000px nudge that misses everything below the fold.
        try:
            steps = int(os.environ.get("INPUT_DISCOVERY_SCROLL_STEPS", "6"))
            for _ in range(max(1, steps)):
                page.mouse.wheel(0, 2400)
                page.wait_for_timeout(500)
            page.evaluate("window.scrollTo(0, 0)")
            page.wait_for_timeout(300)
        except Exception:
            pass
        data = page.evaluate(FORM_EXTRACTOR)
    except Exception as exc:
        log(f"visit failed {url}: {str(exc)[:100]}")
        return records

    file_fields: Set[str] = set(data.get("runtime", {}).get("file_fields", []) or [])

    # 1) forms
    for f in data.get("forms", []):
        action = _norm_url(url, f.get("action") or "")
        controls = f.get("controls", [])
        params = [c["name"] for c in controls if c.get("name")]
        accepts_file = any(c.get("is_file") for c in controls) \
            or "multipart" in (f.get("enctype") or "")
        records.append({
            "url": action, "page": url,
            "method": (f.get("method") or "get").upper(),
            "enctype": f.get("enctype") or "",
            "params": params, "accepts_file": accepts_file,
            "controls": controls, "source": "form",
        })

    # 2) runtime fetch/XHR (from injected hooks) + CDP network
    for r in (data.get("runtime", {}).get("xhr", []) or []) + net:
        u = _norm_url(url, r.get("url") or "")
        if not u:
            continue
        accepts_file = "multipart" in (r.get("content_type") or "") \
            or bool(set(r.get("body_keys", [])) & file_fields)
        records.append({
            "url": u, "page": url,
            "method": (r.get("method") or "GET").upper(),
            "enctype": r.get("content_type") or "",
            "params": r.get("body_keys", []), "accepts_file": accepts_file,
            "controls": [], "source": r.get("kind", "xhr"),
        })

    # 3) loose file inputs (SPA uploaders outside a form)
    for c in data.get("loose", []):
        if c.get("is_file"):
            records.append({
                "url": url, "page": url, "method": "POST", "enctype": "multipart/form-data",
                "params": [c.get("name")] if c.get("name") else [], "accepts_file": True,
                "controls": [c], "source": "dom",
            })
    return records


def _classify(rec: Dict) -> str:
    """Tag the input function (login/register/search/upload/...)."""
    if input_function is not None:
        return input_function(rec["url"], method=rec.get("method", "GET"),
                              enctype=rec.get("enctype", ""),
                              params=rec.get("params", []),
                              accepts_file=rec.get("accepts_file", False),
                              controls=rec.get("controls", []))
    return "upload" if rec.get("accepts_file") else "form"


def _save_session_cookies(ctx, target: str, scan_dir: Path) -> None:
    """Write whatever cookies this CDP crawl accumulated (login redirects,
    JS-set session/CSRF cookies) back into the shared ARISE_SESSION_JAR, so
    every scanner stage that runs AFTER Module 20 inherits the session
    automatically instead of starting cold. No-op if no jar is configured for
    this run (ARISE_SESSION_JAR unset — e.g. run outside easm-pipeline.sh)."""
    jar_path = os.environ.get("ARISE_SESSION_JAR") or str(scan_dir / "session.jar")
    try:
        cookies = ctx.cookies()
    except Exception:
        cookies = []
    if not cookies:
        return
    from core import session_jar
    n = session_jar.write_cookies(jar_path, cookies, target)
    if n:
        log(f"captured {n} session cookie(s) -> {jar_path}")


def run(target: str, scan_dir: Path, urls: List[str], max_pages: int,
        timeout: int, channel: Optional[str], cdp_arg: str = "") -> int:
    out_dir = scan_dir / "20_api_deep_discovery"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / "input_functions.jsonl"

    try:
        from playwright.sync_api import sync_playwright
    except Exception as exc:
        log(f"playwright unavailable ({exc}); writing empty result")
        out_file.write_text("")
        return 0

    seen: Set[tuple] = set()
    rows: List[Dict] = []
    pages = urls[:max_pages]

    # Prefer the app-owned dedicated headless Chrome (chrome_service) over cold-
    # launching a fresh browser: connect to its CDP endpoint and never close it.
    cdp_url = _resolve_cdp(scan_dir, cdp_arg)
    with sync_playwright() as p:
        launched = None          # a browser WE launched (must close)
        connected = None         # the dedicated browser (must NOT close)
        if cdp_url:
            try:
                connected = p.chromium.connect_over_cdp(cdp_url)
                log(f"connected to dedicated Chrome via CDP: {cdp_url}")
            except Exception as exc:
                log(f"CDP connect failed ({str(exc)[:60]}); falling back to launch")
        browser = connected
        if browser is None:
            for ch in ([channel] if channel else ["chrome", "chromium", None]):
                try:
                    launched = p.chromium.launch(headless=True, channel=ch) if ch \
                        else p.chromium.launch(headless=True)
                    break
                except Exception as exc:
                    log(f"launch channel={ch!r} failed: {str(exc)[:80]}")
            browser = launched
        if browser is None:
            log("no Chrome/Chromium available; writing empty result")
            out_file.write_text("")
            return 0
        log(f"visiting {len(pages)} page(s) via CDP "
            f"({'dedicated' if connected else 'launched'} Chrome)")

        ctx = browser.new_context(ignore_https_errors=True)
        ctx.add_init_script(INSTRUMENTATION)
        page = ctx.new_page()
        for i, u in enumerate(pages, 1):
            for rec in _discover_page(page, u, timeout):
                fn = _classify(rec)
                rec["function"] = fn
                key = (rec["url"], rec["method"], fn, tuple(sorted(rec.get("params", []))))
                if key in seen:
                    continue
                seen.add(key)
                # keep a COMPACT control map (name/type/required/file/validation)
                # so downstream testing knows which field is password / file / etc.
                rec["controls"] = [{
                    "name": c.get("name", ""), "type": c.get("type", ""),
                    "required": bool(c.get("required")), "is_file": bool(c.get("is_file")),
                    "accept": c.get("accept", ""), "pattern": c.get("pattern", ""),
                    "maxlength": c.get("maxlength", ""),
                } for c in (rec.get("controls") or []) if c.get("name") or c.get("is_file")]
                rows.append(rec)
            if i % 10 == 0:
                log(f"  {i}/{len(pages)} pages, {len(rows)} input functions so far")
        try:
            _save_session_cookies(ctx, target, scan_dir)
        except Exception:
            pass
        try:
            ctx.close()          # always release our context/pages
        except Exception:
            pass
        if launched is not None:
            launched.close()     # only close a browser we launched; leave the
                                 # app-owned dedicated Chrome running

    with out_file.open("w") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")
    by_fn: Dict[str, int] = {}
    for r in rows:
        by_fn[r["function"]] = by_fn.get(r["function"], 0) + 1
    (out_dir / "input_functions_summary.json").write_text(json.dumps({
        "module": "input_discovery", "target": target,
        "pages_visited": len(pages), "total": len(rows), "by_function": by_fn,
    }, indent=2))
    log(f"done: {len(rows)} input functions -> {out_file}")
    log("by function: " + ", ".join(f"{k}={v}" for k, v in sorted(by_fn.items())))
    return 0


def _load_seed_urls(scan_dir: Path, target: str, limit: int) -> List[str]:
    """Seed pages to visit: prefer HTTP-confirmed hosts + a sample of crawled
    pages (HTML routes, not static assets). Runtime capture is most valuable on
    real application pages."""
    urls: List[str] = []
    seen: Set[str] = set()

    def add(u: str):
        u = (u or "").strip()
        if u.startswith(("http://", "https://")) and u not in seen:
            seen.add(u)
            urls.append(u)

    for rel in ("04_http_discovery/http_urls.txt",
                "01_asset_discovery/httpx_urls.txt"):
        f = scan_dir / rel
        if f.exists():
            for line in f.read_text(errors="ignore").splitlines():
                add(line.split()[0] if line.split() else line)

    # a sample of crawled HTML pages (skip obvious static assets)
    craw = scan_dir / "09_crawling" / "all_urls.txt"
    if craw.exists():
        for line in craw.read_text(errors="ignore").splitlines():
            if len(urls) >= limit:
                break
            if any(line.lower().endswith(ext) for ext in
                   (".js", ".css", ".png", ".jpg", ".svg", ".woff", ".woff2", ".ico", ".gif")):
                continue
            add(line)
    return urls[:limit]


def main() -> int:
    ap = argparse.ArgumentParser(description="ARISE Input-Functions Discovery (CDP)")
    ap.add_argument("target")
    ap.add_argument("--scan-dir", required=True)
    ap.add_argument("--urls", default="", help="optional file of URLs to visit")
    ap.add_argument("--max-pages", type=int, default=100)
    ap.add_argument("--timeout", type=int, default=15000, help="per-page ms")
    ap.add_argument("--channel", default="chrome",
                    help="Chrome channel ('chrome'|'chromium'|'' for bundled)")
    ap.add_argument("--cdp-url", default="",
                    help="CDP url of an app-owned dedicated Chrome (chrome_service). "
                         "Falls back to $ARISE_CHROME_CDP / scan-dir endpoint / launch.")
    args = ap.parse_args()

    scan_dir = Path(args.scan_dir)
    if not scan_dir.is_dir():
        log(f"scan-dir not found: {scan_dir}")
        return 1

    if args.urls and Path(args.urls).exists():
        urls = [l.strip() for l in Path(args.urls).read_text().splitlines() if l.strip()]
    else:
        urls = _load_seed_urls(scan_dir, args.target, args.max_pages)
    if not urls:
        log("no seed URLs found; nothing to do")
        (scan_dir / "20_api_deep_discovery").mkdir(parents=True, exist_ok=True)
        (scan_dir / "20_api_deep_discovery" / "input_functions.jsonl").write_text("")
        return 0

    return run(args.target, scan_dir, urls, args.max_pages, args.timeout,
               args.channel or None, args.cdp_url)


if __name__ == "__main__":
    sys.exit(main())
