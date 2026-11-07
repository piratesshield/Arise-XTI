#!/usr/bin/env python3
"""
P5 self-test — the CAPEC feedback edge (confirmed → next hop re-seeds).

An endpoint is BOTH SSTI-injectable ({{7*7}}→49) AND OS-command-injectable
(;id→uid=gid). The worklist seeds it only as `ssti`. When SSTI confirms, the
feedback edge escalates SSTI→RCE on the same endpoint (depth 1), and that hop
confirms command injection — a real two-hop chain from a single seed.

Asserts:
  1. one ssti seed → two confirmed findings (ssti at depth 0, cmd_injection at
     depth 1, source=chain:ssti).
  2. depth cap stops runaway chaining.
  3. no chaining when the first hop only refutes.

Run: python3 tests/test_adaptive_loop_chain.py
"""
import json
import os
import sys
import tempfile
import urllib.parse
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from offensive import adaptive_loop as al  # noqa: E402


def _write(d, routing):
    inv = Path(d) / "08_directory_discovery"; inv.mkdir(parents=True)
    (inv / "discovered_endpoints.jsonl").write_text(json.dumps({"host": "vuln.test"}) + "\n")
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


def _ssti_and_cmd(url, method="GET", timeout=8):
    vals = " ".join(v for _, v in urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query))
    if any(t in vals for t in (";id", "|id", "$(id)")):        # command injection
        return 200, {"Content-Type": "text/plain"}, "uid=33(www-data) gid=33(www-data)", 0.02
    if "{{7*7}}" in vals or "${7*7}" in vals:                   # SSTI
        return 200, {"Content-Type": "text/html"}, "<html>= 49 =</html>", 0.02
    return 200, {"Content-Type": "text/html"}, "<html>hello</html>", 0.02


def test_ssti_chains_to_rce():
    s, fs = _run([{"url": "http://vuln.test/tpl?q=x", "host": "vuln.test", "attack": "ssti"}],
                 _ssti_and_cmd, per_endpoint=12)
    oracles = [f["arise_provenance"]["oracle"] for f in fs]
    assert s["confirmed"] == 2, s
    assert "ssti" in oracles and "cmd_injection" in oracles, oracles
    assert s["seeds_chained"] == 1 and s["chain_confirmed"] == 1, s
    cmd = next(f for f in fs if f["arise_provenance"]["oracle"] == "cmd_injection")
    assert cmd["arise_provenance"]["source_seed"] == "chain:ssti", cmd
    print("  ✓ 1. one ssti seed → SSTI confirmed → RCE chained hop confirmed (2-hop chain)")


def test_depth_cap():
    # depth 0 allowed to spawn depth 1; with max_chain_depth=0 no chain fires
    s, fs = _run([{"url": "http://vuln.test/tpl?q=x", "host": "vuln.test", "attack": "ssti"}],
                 _ssti_and_cmd, per_endpoint=12, max_chain_depth=0)
    assert s["seeds_chained"] == 0, s
    assert s["confirmed"] == 1, s          # only the SSTI, no escalation
    print("  ✓ 2. depth cap (max_chain_depth=0) stops escalation")


def test_no_chain_on_refute():
    # SSTI does NOT confirm (server ignores template) → no escalation
    def fetch(url, method="GET", timeout=8):
        return 200, {"Content-Type": "text/html"}, "<html>static</html>", 0.02
    s, fs = _run([{"url": "http://vuln.test/tpl?q=x", "host": "vuln.test", "attack": "ssti"}], fetch)
    assert s["confirmed"] == 0 and s["seeds_chained"] == 0, s
    print("  ✓ 3. no chaining when the first hop refutes")


if __name__ == "__main__":
    test_ssti_chains_to_rce()
    test_depth_cap()
    test_no_chain_on_refute()
    print("P5 adaptive_loop feedback edge: ALL PASS")
