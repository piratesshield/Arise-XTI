#!/usr/bin/env python3
"""
P2 self-test — response_intel error-response mining + method-matrix seeds.

No network: exercises detect_error_disclosure() on fixture bodies and the
method-matrix seed logic on a synthetic inventory, then runs run_response_intel
end-to-end against a mock fetcher to confirm attack_hypotheses.jsonl is emitted.

Run: python3 tests/test_response_intel_errormine.py
"""
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from intel import response_intel as ri  # noqa: E402

FX = Path(__file__).parent / "fixtures"


def _seed_types(seeds):
    return {s["seed_type"] for s in seeds}


def test_sql_error_body():
    body = (FX / "sql_error_500.html").read_text()
    findings, seeds = ri.detect_error_disclosure(body, {}, 500, "http://t/x?id=1")
    st = _seed_types(seeds)
    assert "sql_error" in st, st
    sql = next(s for s in seeds if s["seed_type"] == "sql_error")
    assert sql["lane"] == "sqli", sql
    assert "mysql" in sql["tech"].lower(), sql
    # the same 500 also leaks a Laravel version + a /var/www path
    assert "path_disclosure" in st and "framework_leak" in st, st
    print(f"  ✓ 1. MySQL 500 → seeds {sorted(st)}")


def test_java_stack_body():
    body = (FX / "java_stack_500.txt").read_text()
    findings, seeds = ri.detect_error_disclosure(body, {"Server": "Apache-Coyote/1.1"}, 500,
                                                 "http://t/invoice/9")
    st = _seed_types(seeds)
    assert "stack_trace" in st, st
    stk = next(s for s in seeds if s["seed_type"] == "stack_trace")
    assert stk["tech"] == "java", stk
    assert "Tomcat" in json.dumps(seeds), seeds  # framework banner mined too
    print(f"  ✓ 2. Java 500 → seeds {sorted(st)}")


def test_clean_200_no_error_seeds():
    # A benign JSON 200 must NOT produce error-mining seeds.
    findings, seeds = ri.detect_error_disclosure('{"ok":true,"items":[]}', {}, 200, "http://t/api")
    assert seeds == [], seeds
    print("  ✓ 3. clean body → no false error hypotheses")


def test_error_status_gate():
    assert ri._is_error_status(500) and ri._is_error_status(400) and ri._is_error_status(405)
    assert not ri._is_error_status(200) and not ri._is_error_status(404)
    assert not ri._is_error_status(403) and not ri._is_error_status(401)
    print("  ✓ 4. status gate: mine 5xx/400/405, skip 200/401/403/404")


def test_end_to_end_hypotheses_file():
    """Full run against a mock fetcher: one 500 (SQL error) + one PUT-accepting
    endpoint → attack_hypotheses.jsonl with a sql_error and a method_matrix seed."""
    sql_body = (FX / "sql_error_500.html").read_text()

    def mock_fetch(url, method="GET", timeout=ri.TIMEOUT):
        if "boom" in url:
            return 500, {"Content-Type": "text/html"}, sql_body, 0.1
        return 200, {"Content-Type": "application/json"}, '{"ok":true}', 0.05
    ri._fetch = mock_fetch  # monkeypatch the fetcher

    with tempfile.TemporaryDirectory() as d:
        inv = Path(d) / "08_directory_discovery"
        inv.mkdir(parents=True)
        with (inv / "discovered_endpoints.jsonl").open("w") as fh:
            fh.write(json.dumps({"url": "http://t/boom", "sample_url": "http://t/boom",
                                 "host": "t", "method": "GET", "status": 500}) + "\n")
            fh.write(json.dumps({"url": "http://t/item/1", "sample_url": "http://t/item/1",
                                 "host": "t", "method": "GET", "status": 200,
                                 "methods": ["GET", "PUT", "DELETE"]}) + "\n")
        summary = ri.run_response_intel(d, target="t", workers=2, save_samples=False)

        hyp = [json.loads(l) for l in
               (Path(d) / "26_response_intel" / "attack_hypotheses.jsonl").read_text().splitlines()]
        st = _seed_types(hyp)
        assert "sql_error" in st, hyp
        assert "method_matrix" in st, hyp
        assert summary["error_urls_mined"] == 1, summary
        assert summary["attack_hypotheses"] >= 2, summary
        mm = next(h for h in hyp if h["seed_type"] == "method_matrix")
        assert mm["lane"] == "dangerous-methods" and "PUT" in mm["evidence"], mm
    print(f"  ✓ 5. end-to-end → attack_hypotheses.jsonl seed types {sorted(st)}")


if __name__ == "__main__":
    test_sql_error_body()
    test_java_stack_body()
    test_clean_200_no_error_seeds()
    test_error_status_gate()
    test_end_to_end_hypotheses_file()
    print("P2 response_intel error-mining: ALL PASS")
