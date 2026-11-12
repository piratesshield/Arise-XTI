#!/usr/bin/env python3
"""Regression: arise_nlp (Module 10.1) must reverse-map a hashed staged file
back to its real source URL + host via the crawler's index.tsv, so Content-Scan
findings are not 'blind' (hashed filename with no idea which URL/site it came
from). Offline — no network.  Run:  python3 tests/test_nlp_source_url.py
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import ai.arise_nlp as nlp

_fail = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global _fail
    if not cond:
        _fail += 1
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
          + (f" — {detail}" if detail and not cond else ""))


def main() -> int:
    with tempfile.TemporaryDirectory() as td:
        staged = Path(td)
        # Mirror the real staging layout: js_downloads/<md5>.js + index.tsv, and
        # a second manifest for staged 2xx bodies.
        js = staged / "js_downloads"
        js.mkdir()
        hashed = "d9aa2ab1a695450cea9ff5ad6fca0777.js"
        src_url = "https://x.acme-payments.example.com/dist/app.3dd936b7.js"
        (js / hashed).write_text('var contact="acmecorporation2021@gmail.com";\n')
        (js / "index.tsv").write_text(f"{src_url}\t{hashed}\n")

        twoxx = staged / "http_responses_2xx"
        twoxx.mkdir()
        body_name = "abc123def4567890.txt"
        body_url = "https://api.acme-payments.example.com/v1/config"
        (twoxx / body_name).write_text("email: ops@acme-payments.example.com\n")
        (twoxx / "index.tsv").write_text(f"{body_url}\t{body_name}\n")

        rows = nlp.scan_local_files(str(staged), base=str(staged))
        check("findings produced", bool(rows), f"got {len(rows)}")

        js_rows = [r for r in rows if hashed in r.get("file", "")]
        check("hashed JS file -> real source_url",
              bool(js_rows) and all(r.get("source_url") == src_url for r in js_rows),
              f"got {[r.get('source_url') for r in js_rows]}")
        check("hashed JS file -> real host",
              bool(js_rows) and all(r.get("host") == "x.acme-payments.example.com" for r in js_rows),
              f"got {[r.get('host') for r in js_rows]}")

        body_rows = [r for r in rows if body_name in r.get("file", "")]
        check("staged 2xx body -> real source_url + host",
              bool(body_rows)
              and all(r.get("source_url") == body_url
                      and r.get("host") == "api.acme-payments.example.com" for r in body_rows),
              f"got {[(r.get('source_url'), r.get('host')) for r in body_rows]}")

        check("every finding carries source_url (full coverage)",
              rows and all(r.get("source_url") for r in rows),
              f"{sum(1 for r in rows if r.get('source_url'))}/{len(rows)}")

        # A file with no index.tsv entry must NOT invent a URL (no false mapping).
        orphan = staged / "js_downloads" / "deadbeefdeadbeefdeadbeefdeadbeef.js"
        orphan.write_text('var x="someuser2024@gmail.com";\n')
        rows2 = nlp.scan_local_files(str(staged), base=str(staged))
        orphan_rows = [r for r in rows2 if "deadbeef" in r.get("file", "")]
        check("unmapped file -> no fabricated source_url",
              bool(orphan_rows) and all(not r.get("source_url") for r in orphan_rows),
              f"got {[r.get('source_url') for r in orphan_rows]}")

    print()
    if _fail:
        print(f"❌ {_fail} check(s) failed")
        return 1
    print("✅ all nlp source-url checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
