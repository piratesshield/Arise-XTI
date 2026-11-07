#!/usr/bin/env python3
"""
P3/P4 coverage additions:
  1. DETERMINISTIC command injection — the rce lane and the ssti-lfi lane now
     confirm OS command injection (uid=…gid=… and blind sleep) with NO AI.
  2. AI-probe lanes — api-blackbox / sensitive-review are no longer dropped:
     when the AI brain is on they enter the worklist and reach the AI pass;
     when it is off they are still dropped (no wasted baselines).

Run: python3 tests/test_adaptive_loop_coverage.py
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


def _run(routing, fetch, chat_fn=None, **cfgkw):
    with tempfile.TemporaryDirectory() as d:
        _write(d, routing)
        s = al.run_adaptive_loop(d, target="test", cfg=al.LoopConfig(**cfgkw),
                                 fetch=fetch, chat_fn=chat_fn)
        fs = [json.loads(l) for l in
              (Path(d) / "27_adaptive_loop" / "loop_findings.jsonl").read_text().splitlines()]
        return s, fs


def test_deterministic_cmd_injection_id():
    # /exec runs `id` when a shell separator is injected — NO AI involved.
    def fetch(url, method="GET", timeout=8):
        vals = " ".join(v for _, v in urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query))
        if any(t in vals for t in (";id", "|id", "$(id)")):
            return 200, {"Content-Type": "text/plain"}, "uid=0(root) gid=0(root) groups=0(root)", 0.02
        return 200, {"Content-Type": "text/plain"}, "ok", 0.02
    s, fs = _run([{"url": "http://vuln.test/exec?cmd=ls", "host": "vuln.test", "attack": "rce"}], fetch)
    assert s["confirmed"] == 1, s
    f = fs[0]["arise_provenance"]
    assert f["oracle"] == "cmd_injection" and f["proposed_by"] == "deterministic", fs
    assert fs[0]["info"]["severity"] == "critical", fs
    assert fs[0]["info"]["classification"]["cwe-id"] == ["CWE-78"], fs
    print("  ✓ 1. deterministic cmd injection (rce lane) confirmed as critical/CWE-78, no AI")


def test_cmd_injection_blind_sleep():
    # blind: only the sleep payload delays; oracle confirms on timing
    def fetch(url, method="GET", timeout=8):
        vals = " ".join(v for _, v in urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query))
        if "sleep 5" in vals:
            return 200, {"Content-Type": "text/plain"}, "done", 5.0     # 5s delay
        return 200, {"Content-Type": "text/plain"}, "done", 0.02
    s, fs = _run([{"url": "http://vuln.test/ping?cmd=x", "host": "vuln.test", "attack": "rce"}], fetch)
    assert s["confirmed"] == 1 and fs[0]["arise_provenance"]["oracle"] == "cmd_injection", (s, fs)
    print("  ✓ 2. blind cmd injection confirmed via timing (sleep 5)")


def test_ssti_lfi_lane_also_tries_cmd():
    # a ssti-lfi endpoint that's actually OS-command-injectable is still caught
    def fetch(url, method="GET", timeout=8):
        vals = " ".join(v for _, v in urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query))
        if "id" in vals and any(s in vals for s in (";", "|", "$(")):
            return 200, {"Content-Type": "text/plain"}, "uid=33(www-data) gid=33(www-data)", 0.02
        return 200, {"Content-Type": "text/html"}, "<html>nothing</html>", 0.02
    s, fs = _run([{"url": "http://vuln.test/render?q=x", "host": "vuln.test", "attack": "ssti-lfi"}], fetch,
                 per_endpoint=12)
    assert s["confirmed"] == 1 and fs[0]["arise_provenance"]["oracle"] == "cmd_injection", (s, fs)
    print("  ✓ 3. ssti-lfi lane also probes OS command injection")


def test_ai_probe_lane_dropped_without_ai():
    # api-blackbox must NOT enter the worklist when AI is off (no wasted baseline)
    fetch = lambda u, m="GET", t=8: (200, {}, "ok", 0.01)
    s, _ = _run([{"url": "http://vuln.test/api/v1/users", "host": "vuln.test", "attack": "api-blackbox"}],
                fetch)  # ai_enabled defaults False
    assert s["seeds_total"] == 0, s
    print("  ✓ 4. api-blackbox dropped when AI disabled (no wasted requests)")


def test_ai_probe_lane_reaches_ai_when_enabled():
    # with AI on, api-blackbox enters and the AI proposes a probe the oracle judges
    def fetch(url, method="GET", timeout=8):
        vals = " ".join(v for _, v in urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query))
        if "'" in vals:
            return 500, {"Content-Type": "text/html"}, "SQL syntax error near ''", 0.02
        return 200, {"Content-Type": "application/json"}, '{"users":[]}', 0.02
    def ai(system, user):
        return json.dumps([{"oracle": "sql_error", "param": "filter", "payloads": ["'"]}]), None
    s, fs = _run([{"url": "http://vuln.test/api/v1/users?filter=active", "host": "vuln.test",
                   "attack": "api-blackbox"}], fetch, chat_fn=ai, ai_enabled=True)
    assert s["seeds_total"] == 1, s
    assert s["confirmed"] == 1 and fs[0]["arise_provenance"]["proposed_by"] == "ai", (s, fs)
    print("  ✓ 5. api-blackbox reaches the AI brain when enabled → AI-confirmed finding")


if __name__ == "__main__":
    test_deterministic_cmd_injection_id()
    test_cmd_injection_blind_sleep()
    test_ssti_lfi_lane_also_tries_cmd()
    test_ai_probe_lane_dropped_without_ai()
    test_ai_probe_lane_reaches_ai_when_enabled()
    print("P3/P4 coverage additions: ALL PASS")
