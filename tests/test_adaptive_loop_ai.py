#!/usr/bin/env python3
"""
P4 self-test — adaptive_loop AI brain (deterministic + AI, fully offline).

Scenario: an endpoint mislabeled `sqli` is actually command-injectable on the
`host` param. The deterministic SQL recipes all REFUTE. A mock chat_fn (standing
in for the model) proposes a cmd_injection recipe the lane never covered; the
SAME oracle library confirms it. This proves the AI expands coverage WITHOUT
being trusted to decide the verdict.

Asserts:
  1. AI recipe confirms a bug the deterministic recipes missed (proposed_by=ai).
  2. Provider error mid-run degrades silently to pure P3 (no crash, no finding).
  3. AI cannot mint a false positive — on a safe endpoint the oracle still refutes.
  4. The global AI-call budget is respected.
  5. Malformed AI output is ignored, not crashed on.

Run: python3 tests/test_adaptive_loop_ai.py
"""
import json
import os
import sys
import tempfile
import urllib.parse
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from offensive import adaptive_loop as al  # noqa: E402


def mock_fetch(url, method="GET", timeout=8):
    parts = urllib.parse.urlsplit(url)
    host = parts.hostname or ""
    vals = " ".join(v for _, v in urllib.parse.parse_qsl(parts.query, keep_blank_values=True))
    txt = {"Content-Type": "text/plain"}
    if host == "vuln.test" and parts.path == "/ping":
        if ";id" in vals:                       # command injection triggered
            return 200, txt, "uid=33(www-data) gid=33(www-data) groups=33(www-data)", 0.02
        return 200, txt, "pong", 0.02           # everything else: inert
    if host == "safe.test":
        return 200, txt, "pong", 0.02
    return 0, {}, "", 0.0


# mock model: proposes a command-injection recipe on the observed `host` param
def ai_cmd(system, user):
    return json.dumps([{"oracle": "cmd_injection", "param": "host", "payloads": [";id"]}]), None


def _write(d, routing):
    inv = Path(d) / "08_directory_discovery"; inv.mkdir(parents=True)
    with (inv / "discovered_endpoints.jsonl").open("w") as fh:
        fh.write(json.dumps({"host": "vuln.test"}) + "\n")
        fh.write(json.dumps({"host": "safe.test"}) + "\n")
    with (inv / "attack_routing.jsonl").open("w") as fh:
        for r in routing:
            fh.write(json.dumps(r) + "\n")


def _run(routing, chat_fn, **cfgkw):
    with tempfile.TemporaryDirectory() as d:
        _write(d, routing)
        cfg = al.LoopConfig(ai_enabled=True, **cfgkw)
        s = al.run_adaptive_loop(d, target="test", cfg=cfg, fetch=mock_fetch, chat_fn=chat_fn)
        fs = [json.loads(l) for l in
              (Path(d) / "27_adaptive_loop" / "loop_findings.jsonl").read_text().splitlines()]
        return s, fs


PING = [{"url": "http://vuln.test/ping?host=127.0.0.1", "host": "vuln.test", "attack": "sqli"}]


def test_ai_finds_what_deterministic_missed():
    s, fs = _run(PING, ai_cmd)
    assert s["confirmed"] == 1 and s["ai_confirmed"] == 1, s
    assert len(fs) == 1 and fs[0]["arise_provenance"]["oracle"] == "cmd_injection", fs
    assert fs[0]["arise_provenance"]["proposed_by"] == "ai", fs
    assert s["ai_calls_spent"] == 1, s
    print("  ✓ 1. AI recipe confirmed a bug the deterministic pass missed (proposed_by=ai)")


def test_provider_error_degrades():
    def boom(system, user):
        raise RuntimeError("529 overloaded")
    s, fs = _run(PING, boom)
    assert s["status"] == "completed", s
    assert s["confirmed"] == 0 and fs == [], (s, fs)     # deterministic refuted, AI failed safe
    assert s["ai_calls_spent"] == 1, s                    # the call was attempted, then degraded
    print("  ✓ 2. provider error mid-run → degrades to P3, no crash, no finding")


def test_ai_cannot_false_positive():
    safe = [{"url": "http://safe.test/ping?host=127.0.0.1", "host": "safe.test", "attack": "sqli"}]
    s, fs = _run(safe, ai_cmd)
    assert s["confirmed"] == 0 and fs == [], (s, fs)      # oracle refuses AI's payload on safe host
    print("  ✓ 3. AI proposal on a safe endpoint → oracle refutes (no AI-introduced FP)")


def test_ai_call_budget():
    many = [{"url": f"http://vuln.test/other?x={i}", "host": "vuln.test", "attack": "sqli"}
            for i in range(10)]                            # /other is inert → all refute → AI each
    s, _ = _run(many, ai_cmd, ai_max_calls=2)
    assert s["ai_calls_spent"] <= 2, s
    print(f"  ✓ 4. AI-call budget respected (spent {s['ai_calls_spent']}/2)")


def test_malformed_ai_output_ignored():
    def junk(system, user):
        return "sure! here are some ideas: try harder", None   # not a JSON array
    s, fs = _run(PING, junk)
    assert s["status"] == "completed" and s["confirmed"] == 0, s
    print("  ✓ 5. malformed AI output ignored, not crashed on")


if __name__ == "__main__":
    test_ai_finds_what_deterministic_missed()
    test_provider_error_degrades()
    test_ai_cannot_false_positive()
    test_ai_call_budget()
    test_malformed_ai_output_ignored()
    print("P4 adaptive_loop AI brain: ALL PASS")
