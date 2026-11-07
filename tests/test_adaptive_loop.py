#!/usr/bin/env python3
"""
P3 self-test — adaptive_loop FSM core (deterministic, fully offline).

A scripted fetcher simulates a vulnerable host (SQL error, unencoded XSS
reflection, SSTI 7*7→49, dangerous OPTIONS verbs) and a safe host (static body).
Asserts the FSM CONFIRMS the real bugs, REFUTES the safe endpoint, keeps
out-of-scope seeds out of the worklist, respects the request budget, and shapes
findings like nuclei hits.

Run: python3 tests/test_adaptive_loop.py
"""
import json
import os
import sys
import tempfile
import urllib.parse
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from offensive import adaptive_loop as al  # noqa: E402


# --- scripted target: distinguishes payloads, drives every oracle deterministically ---
def mock_fetch(url, method="GET", timeout=8):
    parts = urllib.parse.urlsplit(url)
    host = parts.hostname or ""
    qs = dict(urllib.parse.parse_qsl(parts.query, keep_blank_values=True))
    vals = " ".join(qs.values())
    html = {"Content-Type": "text/html"}

    if host == "safe.test":
        if method == "OPTIONS":
            return 200, {"Allow": "GET, HEAD, OPTIONS"}, "", 0.01
        return 200, html, "<html>welcome, nothing to see</html>", 0.02

    if host == "vuln.test":
        if method == "OPTIONS":
            return 200, {"Allow": "GET, PUT, DELETE, OPTIONS"}, "", 0.01
        if parts.path == "/search":                       # SQLi (error-based)
            if "'" in vals:
                return 500, html, "SQLSTATE[42000]: You have an error in your SQL syntax near ''", 0.03
            return 200, html, "<html>results: 3 items</html>", 0.02
        if parts.path == "/echo":                          # reflected XSS
            body = f"<html>you said: {vals}</html>"         # reflect raw, unencoded
            return 200, html, body, 0.02
        if parts.path == "/tpl":                            # SSTI
            if "{{7*7}}" in vals or "${7*7}" in vals:
                return 200, html, "<html>render: 49 done</html>", 0.02
            return 200, html, "<html>render: hello</html>", 0.02
    return 0, {}, "", 0.0


def _write_inventory(d, records, routing):
    inv = Path(d) / "08_directory_discovery"
    inv.mkdir(parents=True)
    ri = Path(d) / "26_response_intel"
    ri.mkdir(parents=True)
    with (inv / "discovered_endpoints.jsonl").open("w") as fh:
        for r in records:
            fh.write(json.dumps(r) + "\n")
    with (inv / "attack_routing.jsonl").open("w") as fh:
        for r in routing:
            fh.write(json.dumps(r) + "\n")
    # P2 seeds live here
    with (ri / "attack_hypotheses.jsonl").open("w") as fh:
        for r in routing:
            if r.get("_seed"):
                fh.write(json.dumps(r["_seed"]) + "\n")


def _run(routing, records=None, **cfgkw):
    records = records or [{"host": "vuln.test"}, {"host": "safe.test"}]
    with tempfile.TemporaryDirectory() as d:
        _write_inventory(d, records, routing)
        cfg = al.LoopConfig(**cfgkw) if cfgkw else al.LoopConfig()
        summary = al.run_adaptive_loop(d, target="test", cfg=cfg, fetch=mock_fetch)
        findings = [json.loads(l) for l in
                    (Path(d) / "27_adaptive_loop" / "loop_findings.jsonl").read_text().splitlines()]
        return summary, findings


def test_confirms_real_bugs():
    routing = [
        {"url": "http://vuln.test/search?id=1", "host": "vuln.test", "attack": "sqli"},
        {"url": "http://vuln.test/echo?q=hi", "host": "vuln.test", "attack": "xss"},
        {"url": "http://vuln.test/tpl?q=x", "host": "vuln.test", "attack": "ssti"},
    ]
    summary, findings = _run(routing)
    oracles = {f["arise_provenance"]["oracle"] for f in findings}
    assert "sql_error" in oracles, findings
    assert "reflected_xss" in oracles, findings
    assert "ssti" in oracles, findings
    assert all(f["arise_provenance"]["confirmed"] for f in findings), findings
    assert summary["confirmed"] == 3, summary
    print(f"  ✓ 1. confirmed real bugs via oracles: {sorted(oracles)}")


def test_refutes_safe_endpoint():
    routing = [{"url": "http://safe.test/search?id=1", "host": "safe.test", "attack": "sqli"},
               {"url": "http://safe.test/echo?q=hi", "host": "safe.test", "attack": "xss"}]
    summary, findings = _run(routing)
    assert summary["confirmed"] == 0, summary
    assert summary["refuted_seeds"] == 2, summary
    assert findings == [], findings
    print("  ✓ 2. safe endpoint → 0 confirmed, refuted (no false positives)")


def test_out_of_scope_filtered():
    routing = [{"url": "http://evil.example/search?id=1", "host": "evil.example", "attack": "sqli"},
               {"url": "http://vuln.test/search?id=1", "host": "vuln.test", "attack": "sqli"}]
    summary, findings = _run(routing)
    # evil.example is not a subdomain of target 'test' → never enters the worklist
    assert summary["seeds_total"] == 1, summary
    assert summary["confirmed"] == 1, summary
    print("  ✓ 3. out-of-scope seed filtered from worklist")


def test_dangerous_methods_observed_not_fired():
    routing = [{"url": "http://vuln.test/api/item/1", "host": "vuln.test",
                "attack": "dangerous-methods", "methods": ["GET", "PUT", "DELETE"]}]
    summary, findings = _run(routing)
    assert len(findings) == 1, findings
    f = findings[0]
    assert f["arise_provenance"]["oracle"] == "allow_verbs", f
    assert f["arise_provenance"]["confirmed"] is False, f   # observed, not exploitation
    assert "PUT" in f["extracted-results"][0], f
    print("  ✓ 4. dangerous methods → OPTIONS-observed (state-changing verb never fired)")


def test_passive_disclosure_seed():
    routing = [{"url": "http://vuln.test/err", "host": "vuln.test", "attack": "disclosure",
                "_seed": {"url": "http://vuln.test/err", "host": "vuln.test", "lane": "disclosure",
                          "evidence": "java stack trace at com.acme.Foo", "source": "response_intel"}}]
    summary, findings = _run(routing)
    assert len(findings) == 1 and findings[0]["arise_provenance"]["oracle"] == "seed_evidence", findings
    assert findings[0]["arise_provenance"]["confirmed"] is False, findings
    print("  ✓ 5. passive disclosure seed → observed finding, no request fired")


def test_budget_enforced():
    routing = [{"url": f"http://vuln.test/search?id={i}", "host": "vuln.test", "attack": "sqli"}
               for i in range(20)]
    # each sqli seed can spend several requests; cap the global budget hard
    summary, findings = _run(routing, max_requests=3)
    assert summary["requests_spent"] <= 3, summary
    print(f"  ✓ 6. request budget enforced (spent {summary['requests_spent']}/3)")


def test_nuclei_shape():
    routing = [{"url": "http://vuln.test/search?id=1", "host": "vuln.test", "attack": "sqli"}]
    _, findings = _run(routing)
    f = findings[0]
    for k in ("template-id", "matched-at", "host", "info", "extracted-results"):
        assert k in f, f
    assert f["info"]["classification"]["cwe-id"] == ["CWE-89"], f
    assert "adaptive" in f["info"]["tags"], f
    print("  ✓ 7. findings are nuclei-shaped (capec/internet_intel consumable)")


if __name__ == "__main__":
    test_confirms_real_bugs()
    test_refutes_safe_endpoint()
    test_out_of_scope_filtered()
    test_dangerous_methods_observed_not_fired()
    test_passive_disclosure_seed()
    test_budget_enforced()
    test_nuclei_shape()
    print("P3 adaptive_loop FSM: ALL PASS")
