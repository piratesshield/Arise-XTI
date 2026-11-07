#!/usr/bin/env python3
"""
ARISE — Per-Target Learning Memory  (R8)
========================================
"The next scan should start with knowledge instead of rediscovering everything."
The WMS post-mortem's reusable intelligence — `wmsid is identity-bearing`,
`connector page is static`, `HTTP replay alone produces false negatives`,
`400/4281 = request-incomplete, not auth bypass` — is exactly the kind of fact
that must survive across scans so the tool stops re-learning (and re-mis-firing).

This is a durable, per-target fact store that sits ALONGSIDE the asset ledger
(`state/<target>/ledger/intelligence.jsonl`) and reuses its lifecycle discipline:
first_seen frozen, last_seen/seen_count bumped, confidence REINFORCED when a
fact is re-observed and DECAYED when it isn't. Facts confirmed across many scans
become high-confidence priors the attack modules consult at start.

Fact schema
-----------
  key            stable identity, e.g. "param:wmsid" | "url:/connector.html"
                 | "proto:wss://…/pconnect" | "error:400/4281"
  fact           the learned label, e.g. "identity-bearing" | "static-bootstrap"
                 | "requires-browser-context" | "request-incomplete"
  confidence     0..1, reinforced/decayed over scans
  source         which module taught it (identity_graph / response_intel / …)
  first_seen/last_seen/first_scan_id/last_scan_id/seen_count   lifecycle

Public API
----------
  TargetMemory(target).learn(key, fact, confidence, source, scan_id)
  TargetMemory(target).recall(prefix=None) -> [fact dicts]   (scan-start priors)
  TargetMemory(target).harvest_scan(scan_dir, scan_id)       (auto-derive facts)

Consumed by: offensive_verify / auth_oracle (skip known-static, use correct
protocol context), response_intel (suppress known error signatures),
arise_autonomous (seed the knowledge graph). Stdlib only, never raises.
"""

from __future__ import annotations

import sys as _sys, os as _os
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)


import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional

# Location labels har_ingest uses when it has no real parameter name — these are
# not learnable "params", so they're excluded from the identity-bearing facts.
_GENERIC_NAMES = {"cookie", "path-seg", "authorization", "", "header"}

REINFORCE = 0.15       # confidence added when a fact is re-observed
DECAY = 0.10           # confidence removed when a known fact is NOT re-observed
MIN_KEEP = 0.05        # below this a decayed fact is dropped


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def log(msg: str) -> None:
    print(f"[target-memory] {msg}", file=sys.stderr, flush=True)


def _read_jsonl(path: Path) -> List[dict]:
    out: List[dict] = []
    if not path.exists():
        return out
    try:
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
    except OSError:
        pass
    return out


class TargetMemory:
    def __init__(self, target: str, root: str = "state"):
        self.target = target
        self.dir = Path(root) / target / "ledger"
        self.path = self.dir / "intelligence.jsonl"

    # ---- low-level ----
    def _load(self) -> Dict[str, dict]:
        out: Dict[str, dict] = {}
        if not self.path.exists():
            return out
        try:
            with self.path.open("r", errors="ignore") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except Exception:
                        continue
                    k = rec.get("key")
                    if k:
                        out[k] = rec
        except OSError:
            pass
        return out

    def _save(self, recs: Dict[str, dict]) -> bool:
        try:
            self.dir.mkdir(parents=True, exist_ok=True)
        except OSError:
            return False
        tmp = self.path.with_suffix(".jsonl.tmp")
        try:
            with tmp.open("w") as fh:
                for k in sorted(recs.keys()):
                    fh.write(json.dumps(recs[k], default=str) + "\n")
            if self.path.exists():
                try:
                    os.replace(self.path, self.path.with_suffix(".jsonl.bak"))
                except OSError:
                    pass
            os.replace(tmp, self.path)
            return True
        except OSError:
            try:
                if tmp.exists():
                    tmp.unlink()
            except OSError:
                pass
            return False

    # ---- public API ----
    def learn(self, key: str, fact: str, confidence: float, source: str,
              scan_id: str, now: Optional[str] = None,
              recs: Optional[Dict[str, dict]] = None,
              flush: bool = True) -> None:
        """Insert or reinforce one fact. Re-observing bumps confidence toward 1.0."""
        if not key or not fact:
            return
        now = now or _now_iso()
        owns = recs is None
        recs = recs if recs is not None else self._load()
        cur = recs.get(key)
        if cur and cur.get("fact") == fact:
            cur["confidence"] = round(min(1.0, float(cur.get("confidence", 0.5)) + REINFORCE), 3)
            cur["last_seen"] = now
            cur["last_scan_id"] = scan_id
            cur["seen_count"] = int(cur.get("seen_count", 1)) + 1
            if source and source not in (cur.get("sources") or []):
                cur.setdefault("sources", []).append(source)
        else:
            recs[key] = {
                "key": key, "fact": fact,
                "confidence": round(float(confidence), 3),
                "source": source, "sources": [source] if source else [],
                "first_seen": now, "last_seen": now,
                "first_scan_id": scan_id, "last_scan_id": scan_id,
                "seen_count": 1,
            }
        if owns and flush:
            self._save(recs)

    def recall(self, prefix: Optional[str] = None,
               min_confidence: float = 0.0) -> List[dict]:
        """Return known facts (optionally filtered by key prefix), highest
        confidence first — the priors a module consults at scan start."""
        recs = self._load()
        out = [r for r in recs.values()
               if r.get("confidence", 0) >= min_confidence
               and (prefix is None or str(r.get("key", "")).startswith(prefix))]
        out.sort(key=lambda r: -float(r.get("confidence", 0)))
        return out

    def decay_unseen(self, seen_keys: Iterable[str], scan_id: str,
                     now: Optional[str] = None) -> Dict[str, int]:
        """Decay confidence of facts NOT re-observed this scan; drop the dead."""
        now = now or _now_iso()
        recs = self._load()
        seen = set(seen_keys)
        dropped = 0
        for k in list(recs.keys()):
            if k in seen:
                continue
            recs[k]["confidence"] = round(float(recs[k].get("confidence", 0)) - DECAY, 3)
            if recs[k]["confidence"] < MIN_KEEP:
                del recs[k]
                dropped += 1
        self._save(recs)
        return {"remaining": len(recs), "dropped": dropped}

    # ---- auto-harvest from a completed scan ----
    def harvest_scan(self, scan_dir: str, scan_id: str,
                     now: Optional[str] = None) -> Dict[str, int]:
        """Derive learnable facts from a scan's outputs and persist them.
        Best-effort per source; never raises."""
        sd = Path(scan_dir)
        now = now or _now_iso()
        recs = self._load()
        learned = 0

        def _learn(key, fact, conf, source):
            nonlocal learned
            self.learn(key, fact, conf, source, scan_id, now=now, recs=recs,
                       flush=False)
            learned += 1

        # 1. identity graph → identity-bearing parameters (the wmsid lesson)
        ig = sd / "00_har_ingest" / "identity_graph.json"
        if ig.exists():
            try:
                data = json.loads(ig.read_text(errors="ignore"))
                for ent in (data.get("entities") or []):
                    for name in (ent.get("names") or []):
                        if not name or name.lower() in _GENERIC_NAMES:
                            continue  # skip generic location labels, not real params
                        conf = 0.9 if ent.get("is_authenticator") else 0.7
                        _learn(f"param:{name}", "identity-bearing", conf,
                               "identity_graph")
                        if ent.get("cross_protocol"):
                            _learn(f"param:{name}", "cross-protocol-identity",
                                   0.85, "identity_graph")
            except Exception:
                pass

        # 2. flow graph → protocol transitions need browser/session context
        for f in _read_jsonl(sd / "00_har_ingest" / "flow_graph.jsonl"):
            for tr in (f.get("protocol_transitions") or []):
                url = tr.get("url") or ""
                if url:
                    _learn(f"proto:{url}", "requires-browser-context", 0.8,
                           "flow_reconstruct")

        # 3. response_intel → confirmed-static / bootstrap docs (connector lesson)
        for rec in _read_jsonl(sd / "26_response_intel" / "response_findings.jsonl"):
            url = rec.get("url") or ""
            cats = " ".join(str(rec.get(k, "")) for k in ("category", "type", "title"))
            if url and ("static" in cats.lower() or "bootstrap" in cats.lower()):
                _learn(f"url:{url}", "static-bootstrap", 0.75, "response_intel")

        # 4. offensive/oracle findings carrying a browser-context note
        for name in ("offensive_findings.jsonl", "auth_oracle_findings.jsonl",
                     "wss_findings.jsonl"):
            for rec in _read_jsonl(sd / "24_advanced_attacks" / name):
                ev = (rec.get("evidence") or "").lower()
                url = rec.get("url") or ""
                if url and "browser-context" in ev:
                    _learn(f"url:{url}", "requires-browser-context", 0.85,
                           rec.get("module", "offensive"))

        # 5. recurring error fingerprints (the "400/4281 = incomplete" lesson)
        #    scan discovered_endpoints for repeated identical non-2xx statuses.
        status_seen: Dict[str, int] = {}
        for rec in _read_jsonl(sd / "08_directory_discovery" /
                               "discovered_endpoints.jsonl"):
            st = rec.get("status")
            if isinstance(st, int) and st >= 400:
                status_seen[str(st)] = status_seen.get(str(st), 0) + 1
        for st, cnt in status_seen.items():
            if cnt >= 20:  # a status this common on a target is an app error state
                _learn(f"error:{st}", "recurring-error-state", 0.7,
                       "endpoint_inventory")

        self._save(recs)
        log(f"harvested {learned} fact(s) from scan {scan_id} "
            f"({len(recs)} total known for {self.target})")
        return {"learned": learned, "total": len(recs)}

    def summary(self) -> dict:
        recs = self._load()
        by_fact: Dict[str, int] = {}
        for r in recs.values():
            by_fact[r.get("fact", "?")] = by_fact.get(r.get("fact", "?"), 0) + 1
        return {"target": self.target, "total": len(recs), "by_fact": by_fact}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="ARISE per-target learning memory")
    sub = ap.add_subparsers(dest="cmd")

    ph = sub.add_parser("harvest", help="derive + persist facts from a scan dir")
    ph.add_argument("--target", required=True)
    ph.add_argument("--scan-dir", required=True)
    ph.add_argument("--scan-id", required=True)
    ph.add_argument("--root", default="state")

    pr = sub.add_parser("recall", help="print known facts (scan-start priors)")
    pr.add_argument("--target", required=True)
    pr.add_argument("--prefix", default=None)
    pr.add_argument("--min-confidence", type=float, default=0.0)
    pr.add_argument("--root", default="state")

    ps = sub.add_parser("stats", help="fact-store summary for a target")
    ps.add_argument("--target", required=True)
    ps.add_argument("--root", default="state")

    st = sub.add_parser("selftest", help="offline self-test")

    args = ap.parse_args(argv)
    if args.cmd == "harvest":
        r = TargetMemory(args.target, root=args.root).harvest_scan(
            args.scan_dir, args.scan_id)
        print(f"[target-memory] {args.target}: +{r['learned']} facts, "
              f"{r['total']} total")
        return 0
    if args.cmd == "recall":
        facts = TargetMemory(args.target, root=args.root).recall(
            prefix=args.prefix, min_confidence=args.min_confidence)
        for f in facts:
            print(f"  {f['confidence']:.2f}  {f['key']:40}  {f['fact']:24}  "
                  f"(x{f.get('seen_count',1)}, {f.get('source','')})")
        if not facts:
            print("  (no facts learned yet)")
        return 0
    if args.cmd == "stats":
        s = TargetMemory(args.target, root=args.root).summary()
        print(f"Target memory for {s['target']}: {s['total']} facts")
        for fact, n in sorted(s["by_fact"].items(), key=lambda x: -x[1]):
            print(f"  {n:5}  {fact}")
        return 0
    # default: selftest
    return _selftest()


def _selftest() -> int:
    import shutil, tempfile
    tmp = tempfile.mkdtemp(prefix="arise_tmem_")
    try:
        m = TargetMemory("example.com", root=tmp)
        m.learn("param:wmsid", "identity-bearing", 0.7, "identity_graph", "scan1")
        assert m.recall("param:")[0]["fact"] == "identity-bearing"
        # reinforce
        m.learn("param:wmsid", "identity-bearing", 0.7, "identity_graph", "scan2")
        rec = m.recall("param:")[0]
        assert rec["seen_count"] == 2 and rec["confidence"] > 0.7
        assert rec["first_scan_id"] == "scan1" and rec["last_scan_id"] == "scan2"
        # decay unseen
        m.learn("url:/x", "static-bootstrap", 0.1, "response_intel", "scan2")
        out = m.decay_unseen(["param:wmsid"], "scan3")
        assert m.recall("url:") == [], "low-confidence unseen fact should drop"
        assert m.recall("param:"), "reinforced fact should survive"
        print("[target-memory] self-test OK — learn/reinforce/recall/decay")
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
