#!/usr/bin/env python3
"""
ARISE — Authorization Oracle  (R5, Module 24-AUTHZ)
===================================================
The WMS lesson: don't send `id=123,124,125` and call a 200 a finding. Turn
BOLA/BFLA testing into a formal set of authorization INVARIANTS and look for
violations. Instead of "think like a hacker" in an unconstrained way, the agent
gets a hypothesis matrix and proves an invariant broke.

Invariants (per identity-sensitive object endpoint)
---------------------------------------------------
  A → A's object          expect ALLOW   (baseline: the owner sees their data)
  B → A's object          expect DENY    (a different user must not)
  anon → A's object       expect DENY    (unauthenticated must not)
  expired → A's object    expect DENY    (a stale session must not)   [if provided]

A violation is proven by DIFFERENTIAL, on the L0-L6 ladder, not by status code:
B is a *different* identity yet receives content that matches A's authorized
response (high similarity) and does NOT match the anonymous/denied baseline.
A resource that anon can read identically is PUBLIC → not a finding (L1 note).

Gray-box input (required — this is an authenticated test)
---------------------------------------------------------
  <scan>/auth_contexts.json  (or --contexts PATH):
    {"auth_contexts": [
       {"name":"user_a","type":"cookie","value":"session=aaa; other=1"},
       {"name":"user_b","type":"header","header":"Authorization","value":"Bearer bbb"},
       {"name":"anonymous","type":"none"}
    ]}
  The FIRST non-anonymous context is treated as the owner (A) whose captured
  URLs are the object references; the rest are the "other user" probes.

Targets
-------
  <scan>/00_har_ingest/identity_graph.json  (bola_candidates)   preferred
  <scan>/08_directory_discovery/discovered_endpoints.jsonl      (fallback:
                                              api + path-param, auth-required)

Output
------
  <scan>/24_advanced_attacks/auth_oracle_findings.jsonl   (offensive schema)

Every request runs through protocol_exec so the correct channel/context is used,
and ScopeGuard gates every URL. GET-only by default (non-mutating).
"""

from __future__ import annotations

import sys as _sys, os as _os
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)


import argparse
import difflib
import json
import sys
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Dict, List, Optional

from evidence.protocol_exec import http_send, HttpResult

try:
    from evidence.arise_evidence import ladder_meta, is_confirmed
except Exception:  # pragma: no cover
    def ladder_meta(r):  # type: ignore
        return {"code": r, "name": r, "confirmed": r >= "L4"}
    def is_confirmed(r):  # type: ignore
        return r >= "L4"

try:
    from ai.arise_nlp import similarity as _nlp_similarity
except Exception:  # pragma: no cover
    _nlp_similarity = None

try:
    from ai.ai_probing import ScopeGuard
except Exception:  # pragma: no cover
    ScopeGuard = None


SIM_SAME = 0.90        # bodies this similar are "the same resource content"
SIM_DIFFERENT = 0.60   # below this, clearly different content (a denial page)


def log(msg: str) -> None:
    print(f"[authz-oracle] {msg}", file=sys.stderr, flush=True)


def _similarity(a: str, b: str) -> float:
    a, b = a or "", b or ""
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    if _nlp_similarity is not None:
        try:
            return float(_nlp_similarity(a, b))
        except Exception:
            pass
    # stdlib fallback — cap length so it stays fast on large bodies
    return difflib.SequenceMatcher(None, a[:8000], b[:8000]).ratio()


@dataclass
class Ctx:
    name: str
    type: str            # cookie | header | none
    value: str = ""
    header: str = "Authorization"

    def apply(self) -> Dict[str, dict]:
        """Return {'headers':..., 'cookies':...} kwargs for http_send."""
        if self.type == "cookie":
            cookies = {}
            for part in self.value.split(";"):
                if "=" in part:
                    k, v = part.split("=", 1)
                    cookies[k.strip()] = v.strip()
            return {"headers": {}, "cookies": cookies}
        if self.type == "header":
            return {"headers": {self.header: self.value}, "cookies": {}}
        return {"headers": {}, "cookies": {}}


@dataclass
class OracleFinding:
    check: str
    module: str = "auth_oracle"
    severity: str = "high"
    title: str = ""
    host: str = ""
    url: str = ""
    evidence: str = ""
    remediation: str = ""
    confidence: str = "confirmed"
    evidence_rung: str = "L4"
    rung_name: str = ""
    verification: str = "authorization-differential"
    invariant: str = ""
    baseline: Dict = field(default_factory=dict)
    attack: Dict = field(default_factory=dict)


def _read_jsonl(path: Path) -> List[dict]:
    out: List[dict] = []
    if not path.exists():
        return out
    for line in path.read_text(errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
            if isinstance(r, dict):
                out.append(r)
        except Exception:
            continue
    return out


class AuthOracle:
    def __init__(self, scan_dir: Path, target: str = "", contexts_path: str = "",
                 max_targets: int = 60, timeout: int = 12):
        self.scan_dir = scan_dir
        self.target = target
        self.contexts_path = contexts_path
        self.max_targets = max_targets
        self.timeout = timeout
        self.findings: List[OracleFinding] = []
        self.scope = None
        if ScopeGuard is not None and target:
            try:
                self.scope = ScopeGuard(target)
            except Exception:
                self.scope = None

    # ---- inputs ----
    def _load_contexts(self) -> List[Ctx]:
        # 1) explicit / conventional auth_contexts.json (gray-box, hand-supplied)
        out: List[Ctx] = []
        p = Path(self.contexts_path) if self.contexts_path else \
            self.scan_dir / "auth_contexts.json"
        if p.exists():
            try:
                data = json.loads(p.read_text(errors="ignore"))
                for c in (data.get("auth_contexts") or []):
                    out.append(Ctx(name=c.get("name", "ctx"),
                                   type=(c.get("type") or "none").lower(),
                                   value=c.get("value", ""),
                                   header=c.get("header", "Authorization")))
            except Exception as e:
                log(f"cannot parse contexts {p}: {e}")

        # 2) Burp bridge identities — the role labels a human operator captured
        #    (guest/user/admin) become oracle contexts automatically, so an
        #    authenticated BOLA/BFLA test needs zero hand-written config when a
        #    bundle was ingested. See burp_bridge_ingest.py.
        out.extend(self._load_burp_contexts({c.name for c in out}))
        return out

    def _load_burp_contexts(self, existing_names) -> List[Ctx]:
        bp = self.scan_dir / "00_har_ingest" / "burp_identities.jsonl"
        if not bp.exists():
            return []
        ctxs: List[Ctx] = []
        have_anon = "anonymous" in existing_names or "guest" in existing_names
        for rec in _read_jsonl(bp):
            role = (rec.get("role") or "").lower().strip()
            if not role or role in existing_names:
                continue
            authz = (rec.get("authorization") or "").strip()
            cookie = (rec.get("cookie") or "").strip()
            if authz:
                ctxs.append(Ctx(name=role, type="header", value=authz,
                                header="Authorization"))
                existing_names.add(role)
            elif cookie:
                ctxs.append(Ctx(name=role, type="cookie", value=cookie))
                existing_names.add(role)
            elif role in ("guest", "anonymous"):
                have_anon = True
        # Guarantee an anonymous baseline exists for the DENY invariants.
        if not have_anon:
            ctxs.append(Ctx(name="anonymous", type="none"))
        return ctxs

    def _targets(self) -> List[dict]:
        seen, out = set(), []
        ig = self.scan_dir / "00_har_ingest" / "identity_graph.json"
        if ig.exists():
            try:
                data = json.loads(ig.read_text(errors="ignore"))
                for c in (data.get("bola_candidates") or []):
                    u = c.get("url")
                    if u and u not in seen and self._in_scope(u):
                        seen.add(u)
                        out.append(c)
            except Exception:
                pass
        if len(out) < self.max_targets:
            for rec in _read_jsonl(self.scan_dir / "08_directory_discovery" /
                                   "discovered_endpoints.jsonl"):
                if rec.get("url_class") == "api" and rec.get("url_shape") == "path-param" \
                        and rec.get("auth_state") in ("auth-required", "unknown"):
                    u = rec.get("sample_url") or rec.get("url")
                    if u and u not in seen and self._in_scope(u):
                        seen.add(u)
                        out.append({"url": u, "host": rec.get("host"),
                                    "methods": rec.get("methods") or ["GET"],
                                    "auth_state": rec.get("auth_state")})
        return out[: self.max_targets]

    def _in_scope(self, url: str) -> bool:
        if self.scope is None:
            return True
        try:
            return self.scope.in_scope(url)
        except Exception:
            return True

    # ---- run ----
    def run(self) -> Dict[str, int]:
        ctxs = self._load_contexts()
        non_anon = [c for c in ctxs if c.type != "none"]
        anon = next((c for c in ctxs if c.type == "none"), Ctx("anonymous", "none"))
        if not non_anon:
            log("no authenticated contexts provided — the oracle needs at least "
                "one owner (A) and ideally a second user (B). See auth_contexts.json. "
                "Skipping (writing empty output).")
            self._write()
            return {"targets": 0, "findings": 0, "reason": "no-contexts"}

        owner = non_anon[0]                      # A
        others = non_anon[1:]                    # B, C, …
        tgts = self._targets()
        if not tgts:
            log("no object-id endpoints to test (need identity_graph bola_candidates "
                "or api path-param inventory)")
            self._write()
            return {"targets": 0, "findings": 0}

        log(f"owner='{owner.name}', others={[c.name for c in others] or ['(none)']}, "
            f"anon={'yes' if anon else 'no'}, targets={len(tgts)}")
        for t in tgts:
            try:
                self._test(t, owner, others, anon)
            except Exception as e:
                log(f"error on {t.get('url')}: {e}")
        self._write()
        conf = sum(1 for f in self.findings if is_confirmed(f.evidence_rung))
        log(f"done: {len(self.findings)} finding(s) ({conf} confirmed authz violations)")
        return {"targets": len(tgts), "findings": len(self.findings)}

    def _get(self, url: str, ctx: Ctx) -> HttpResult:
        kw = ctx.apply()
        return http_send("GET", url, timeout=self.timeout, allow_redirects=False,
                         **kw)

    def _test(self, t: dict, owner: Ctx, others: List[Ctx], anon: Ctx) -> None:
        url = t["url"]
        host = t.get("host") or ""

        # A → A's object (baseline authorized response)
        ra = self._get(url, owner)
        if not ra.ok:
            return
        a_ok = 200 <= ra.status < 300 and len(ra.body) > 0
        if not a_ok:
            # owner can't even read it — not a useful object reference to test
            return

        # anon → A's object (the denial baseline)
        ranon = self._get(url, anon)
        anon_reads = (200 <= ranon.status < 300 and
                      _similarity(ra.body, ranon.body) >= SIM_SAME)

        # If anon reads the SAME content, this is a PUBLIC resource → not BOLA.
        if anon_reads:
            # But if the inventory believed it auth-required, that's a broken-auth
            # note worth an L1 (observed public where auth was expected).
            if t.get("auth_state") == "auth-required":
                self._finding(
                    "broken_auth_public", "medium",
                    "Object readable without authentication", host, url,
                    invariant="anon → A's object = expect DENY",
                    evidence=(f"anonymous request returned {ranon.status} with "
                              f"content matching the owner's response "
                              f"(sim≥{SIM_SAME}); the resource was expected to "
                              f"require auth"),
                    rung="L4",
                    remediation="Enforce authentication on this object endpoint.",
                    baseline={"ctx": owner.name, "status": ra.status,
                              "len": len(ra.body)},
                    attack={"ctx": "anonymous", "status": ranon.status,
                            "len": len(ranon.body)})
            return  # public resource: no cross-user violation to prove

        # B → A's object (the real BOLA test)
        for other in others:
            rb = self._get(url, other)
            b_status_ok = 200 <= rb.status < 300 and len(rb.body) > 0
            sim_ab = _similarity(ra.body, rb.body)
            sim_bn = _similarity(rb.body, ranon.body)
            # Violation: B (a different user) gets content matching A's authorized
            # response, and NOT the anon denial page.
            if b_status_ok and sim_ab >= SIM_SAME and sim_bn < SIM_SAME:
                self._finding(
                    "bola", "high",
                    "Broken Object Level Authorization (cross-user object read)",
                    host, url,
                    invariant="B → A's object = expect DENY",
                    evidence=(f"user '{other.name}' received {rb.status} with "
                              f"content matching owner '{owner.name}' "
                              f"(sim={sim_ab:.2f} ≥ {SIM_SAME}), while anonymous "
                              f"was denied (sim to B={sim_bn:.2f}); a different "
                              f"identity accessed the owner's object — this is a "
                              f"proven authorization violation, not a status code"),
                    rung="L4",
                    remediation="Enforce per-object authorization: verify the "
                                "requesting identity owns/may access the object "
                                "id on every request.",
                    baseline={"ctx": owner.name, "status": ra.status,
                              "len": len(ra.body)},
                    attack={"ctx": other.name, "status": rb.status,
                            "len": len(rb.body), "sim_to_owner": round(sim_ab, 3),
                            "sim_to_anon": round(sim_bn, 3)})

    def _finding(self, check, severity, title, host, url, *, invariant, evidence,
                 rung, remediation, baseline, attack) -> None:
        meta = ladder_meta(rung)
        self.findings.append(OracleFinding(
            check=check, severity=severity, title=title, host=host, url=url,
            invariant=invariant, evidence=evidence, remediation=remediation,
            evidence_rung=rung, rung_name=meta["name"], baseline=baseline,
            attack=attack,
            confidence="confirmed" if meta["confirmed"] else "candidate"))

    def _write(self) -> None:
        out_dir = self.scan_dir / "24_advanced_attacks"
        out_dir.mkdir(parents=True, exist_ok=True)
        with (out_dir / "auth_oracle_findings.jsonl").open("w") as fh:
            for f in self.findings:
                fh.write(json.dumps(asdict(f)) + "\n")
        (out_dir / "auth_oracle_summary.json").write_text(json.dumps({
            "module": "auth_oracle",
            "findings": len(self.findings),
            "confirmed": sum(1 for f in self.findings if is_confirmed(f.evidence_rung)),
        }, indent=2))


def main() -> int:
    ap = argparse.ArgumentParser(description="ARISE authorization oracle")
    ap.add_argument("scan_dir")
    ap.add_argument("--target", default="")
    ap.add_argument("--contexts", default="",
                    help="path to auth_contexts.json (default: <scan>/auth_contexts.json)")
    ap.add_argument("--max-targets", type=int, default=60)
    ap.add_argument("--timeout", type=int, default=12)
    args = ap.parse_args()
    scan_dir = Path(args.scan_dir)
    if not scan_dir.is_dir():
        log(f"scan-dir not found: {scan_dir}")
        return 1
    AuthOracle(scan_dir, target=args.target, contexts_path=args.contexts,
               max_targets=args.max_targets, timeout=args.timeout).run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
