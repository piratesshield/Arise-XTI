#!/usr/bin/env python3
"""
P3 hardening regressions — the three flaws found in the correlation audit.

  1. multi-param injection: a bug in the 2nd query param is now found
     (was: only the first param ever got the payload).
  2. sql_boolean dynamic-page guard: a noisy page (timestamp/nonce) no longer
     false-positives as boolean SQLi.
  3. lfi payloads survive urlencoding (no ..%2f → ..%252f double-encode).

Run: python3 tests/test_adaptive_loop_hardening.py
"""
import json
import os
import sys
import tempfile
import urllib.parse
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from offensive import adaptive_loop as al  # noqa: E402


def _write(d, routing, hosts=("vuln.test",)):
    inv = Path(d) / "08_directory_discovery"; inv.mkdir(parents=True)
    with (inv / "discovered_endpoints.jsonl").open("w") as fh:
        for h in hosts:
            fh.write(json.dumps({"host": h}) + "\n")
    with (inv / "attack_routing.jsonl").open("w") as fh:
        for r in routing:
            fh.write(json.dumps(r) + "\n")


def _run(routing, fetch, **cfgkw):
    with tempfile.TemporaryDirectory() as d:
        _write(d, routing)
        s = al.run_adaptive_loop(d, target="test", cfg=al.LoopConfig(**cfgkw), fetch=fetch)
        fs = [json.loads(l) for l in
              (Path(d) / "27_adaptive_loop" / "loop_findings.jsonl").read_text().splitlines()]
        return s, fs


def test_multi_param_injection():
    # SQLi lives ONLY in the 2nd param `b`; the deterministic default param is `id`.
    def fetch(url, method="GET", timeout=8):
        qs = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query, keep_blank_values=True))
        if "'" in qs.get("b", ""):
            return 500, {"Content-Type": "text/html"}, "SQL syntax error near ''", 0.02
        return 200, {"Content-Type": "text/html"}, "<html>ok</html>", 0.02
    s, fs = _run([{"url": "http://vuln.test/q?a=1&b=2", "host": "vuln.test", "attack": "sqli"}], fetch)
    assert s["confirmed"] == 1, s
    assert fs[0]["arise_provenance"]["oracle"] == "sql_error", fs
    print("  ✓ 1. multi-param: bug in the 2nd param is found (not just the first)")


def test_dynamic_page_no_boolean_fp():
    # Every response differs (a running counter) — pure dynamic noise, NO SQLi.
    n = {"i": 0}
    def fetch(url, method="GET", timeout=8):
        n["i"] += 1
        body = "<html>page " + ("x" * n["i"]) + " nonce=%d</html>" % n["i"]
        return 200, {"Content-Type": "text/html"}, body, 0.02
    s, fs = _run([{"url": "http://vuln.test/dyn?id=1", "host": "vuln.test", "attack": "sqli"}], fetch)
    assert s["confirmed"] == 0, s                 # stability guard refuses the boolean diff
    assert fs == [], fs
    print("  ✓ 2. dynamic page → sql_boolean refuted (no false positive)")


def test_lfi_payload_not_double_encoded():
    # Confirm the injected payload is a clean percent-encoding, never ..%252f.
    got = {"urls": []}
    def fetch(url, method="GET", timeout=8):
        got["urls"].append(url)
        # return /etc/passwd content so lfi_passwd confirms on a good payload
        return 200, {"Content-Type": "text/plain"}, "root:x:0:0:root:/root:/bin/bash", 0.02
    s, fs = _run([{"url": "http://vuln.test/read?page=home", "host": "vuln.test", "attack": "lfi"}], fetch)
    assert s["confirmed"] == 1 and fs[0]["arise_provenance"]["oracle"] == "lfi_passwd", (s, fs)
    assert not any("%252f" in u.lower() for u in got["urls"]), got["urls"]
    print("  ✓ 3. lfi payloads survive urlencoding (no ..%2f → ..%252f), and confirm")


if __name__ == "__main__":
    test_multi_param_injection()
    test_dynamic_page_no_boolean_fp()
    test_lfi_payload_not_double_encoded()
    print("P3 hardening: ALL PASS")
