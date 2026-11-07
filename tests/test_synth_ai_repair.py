#!/usr/bin/env python3
"""
P1 self-test — synth_ai template self-repair loop.

Runs WITHOUT a real API key and WITHOUT nuclei installed: we monkeypatch
synth_ai._nuclei_validate (the validator) and inject a fake chat_fn (the model),
so the test exercises the repair control-flow deterministically.

Asserts:
  1. A template that fails validation once but validates after one repair pass
     lands in `written` and is recorded in `repaired`.
  2. A template that NEVER validates is dropped after exactly `repair_tries`
     attempts, with the last validator error recorded.
  3. When the model errors during repair (provider down), the template is
     dropped gracefully — no exception, clear reason.
  4. A repair that reaches OUT OF SCOPE is refused (never written).

Run: python3 tests/test_synth_ai_repair.py
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from discovery import synth_ai  # noqa: E402

_GOOD = ("```yaml\nid: x\ninfo:\n  name: t\n  severity: info\n  tags: arise\n"
         "http:\n  - method: GET\n    path:\n      - \"{{BaseURL}}/a\"\n"
         "    matchers:\n      - type: word\n        words:\n          - ok\n```")
_BROKEN = _GOOD.replace("type: word", "type: nonexistent_matcher")


class _Scope:
    def in_scope(self, url):
        return "evil.example" not in url


def _run(chat_fn, validate_seq, repair_tries=2):
    """Drive propose_templates with a scripted validator + model."""
    calls = {"n": 0}

    def fake_validate(path, dast=False):
        i = min(calls["n"], len(validate_seq) - 1)
        calls["n"] += 1
        ok = validate_seq[i]
        return ok, ("" if ok else "invalid matcher type: line 9")

    synth_ai._nuclei_validate = fake_validate  # monkeypatch module global
    with tempfile.TemporaryDirectory() as d:
        return synth_ai.propose_templates({"target_hosts": ["t.com"]}, chat_fn,
                                          _Scope(), d, cap=1, repair_tries=repair_tries)


def test_repairs_then_accepts():
    # first proposal, then one repair — validator: False, then True
    def chat(system, user):
        if "FAILED" in system or "corrected" in system.lower():
            return _GOOD, None                       # repair returns a good template
        return _BROKEN, None                          # initial proposal is broken
    r = _run(chat, validate_seq=[False, True])
    assert len(r["written"]) == 1, r
    assert len(r["repaired"]) == 1 and r["repaired"][0]["attempts"] == 1, r
    assert not r["dropped"], r
    print("  ✓ 1. broken → repaired once → accepted")


def test_unrepairable_drops_after_n():
    def chat(system, user):
        return _BROKEN, None                          # model keeps returning broken
    r = _run(chat, validate_seq=[False, False, False, False], repair_tries=2)
    assert not r["written"], r
    assert len(r["dropped"]) == 1, r
    d = r["dropped"][0]
    assert d["repair_attempts"] == 2, d               # bounded exactly at repair_tries
    assert d["last_error"], d                          # the validator error is recorded
    print("  ✓ 2. unrepairable → dropped after exactly repair_tries, error kept")


def test_provider_error_during_repair():
    def chat(system, user):
        if "FAILED" in system:
            return None, "claude call failed: 529 overloaded"   # provider down on repair
        return _BROKEN, None
    r = _run(chat, validate_seq=[False, False])
    assert not r["written"] and len(r["dropped"]) == 1, r
    assert "unavailable" in r["dropped"][0]["last_error"], r
    print("  ✓ 3. provider error during repair → graceful drop, no raise")


def test_repair_out_of_scope_refused():
    oos = _GOOD.replace("{{BaseURL}}/a", "https://evil.example/a")
    def chat(system, user):
        if "FAILED" in system:
            return oos, None                          # repair sneaks in an OOS host
        return _BROKEN, None
    r = _run(chat, validate_seq=[False, True])        # would validate, but scope refuses
    assert not r["written"], r
    assert len(r["dropped"]) == 1 and "out-of-scope" in r["dropped"][0]["last_error"], r
    print("  ✓ 4. repair introducing out-of-scope host → refused")


if __name__ == "__main__":
    test_repairs_then_accepts()
    test_unrepairable_drops_after_n()
    test_provider_error_during_repair()
    test_repair_out_of_scope_refused()
    print("P1 synth_ai repair loop: ALL PASS")
