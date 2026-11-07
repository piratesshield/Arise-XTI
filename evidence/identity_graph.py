#!/usr/bin/env python3
"""
ARISE — Identity / Object Graph  (R3, Module 0-IDG)
===================================================
The single most important thing the WMS post-mortem said to build. A normal
endpoint scanner sends `id=123, id=124, id=125`. That is useless. What matters
is the RELATIONSHIP graph between identity-bearing values — which identifiers
travel together, which cross a protocol boundary, which are bound to an auth
context — so the pentest agent can reason:

    "Does Account A's authentication remain bound to Device A
     when Device B's identifier appears?"

This module turns observed evidence into that graph.

Input
-----
  <scan>/00_har_ingest/har_identifiers.jsonl        (from har_ingest.py)
  <scan>/00_har_ingest/har_assets.jsonl             (protocol per url)
  <scan>/08_directory_discovery/discovered_endpoints.jsonl   (tokenised/path-id
                                                    endpoints from the inventory)

Method
------
  1. Collapse observations by redacted value-fingerprint → each distinct VALUE
     becomes one entity, even when it appears in a cookie AND a url AND a WSS
     frame (that cross-location reuse is the signal).
  2. Type each entity: session | user_ref | device_id | object_id | jwt |
     csrf_token | auth_token.
  3. Co-occurrence edges: identifiers seen on the SAME request are linked.
  4. Binding edges: a session/auth token co-occurring with a device_id/user_ref
     is a `binds`/`owns` relationship — the invariant the auth oracle tests.
  5. Cross-protocol flag: an identity observed under http AND wss is a
     protocol-spanning identity (test identity consistency across transitions).

Output
------
  <scan>/00_har_ingest/identity_graph.json
    {entities:[{entity_id,id_type,observed_in,protocols,hosts,cross_protocol,
                bound_to_auth}],
     edges:[{from,rel,to}],   rel ∈ cooccurs|binds|owns|derives
     bola_candidates:[{host,url}]   object-id endpoints worth authz testing}

Consumed by: auth_oracle (hypothesis targets), capec_attack_paths (identity
nodes/edges), offensive_verify (swap REAL observed ids, not random). Stdlib only.
"""

from __future__ import annotations

import sys as _sys, os as _os
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)


import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Set

def log(msg: str) -> None:
    print(f"[identity] {msg}", file=sys.stderr, flush=True)


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


# Which id types count as "authenticator" vs "resource" for binding logic.
_AUTHENTICATORS = {"session", "auth_token", "jwt", "csrf_token"}
_RESOURCES = {"user_ref", "device_id", "object_id"}


class IdentityGraph:
    def __init__(self, scan_dir: Path):
        self.scan_dir = scan_dir
        self.har_dir = scan_dir / "00_har_ingest"
        self.entities: Dict[str, dict] = {}
        self.edges: List[dict] = []
        self._edge_seen: Set = set()
        self.bola: List[dict] = []

    def run(self) -> Dict[str, int]:
        ids = _read_jsonl(self.har_dir / "har_identifiers.jsonl")
        assets = _read_jsonl(self.har_dir / "har_assets.jsonl")
        proto_by_url = {a.get("url"): a.get("protocol", "https") for a in assets}

        # 1. collapse by value fingerprint
        by_url: Dict[str, List[dict]] = defaultdict(list)
        for rec in ids:
            fp = rec.get("value_fp")
            if not fp:
                continue
            ent = self.entities.get(fp)
            if ent is None:
                ent = {
                    "entity_id": fp,
                    "id_type": rec.get("id_type", "object_id"),
                    "observed_in": set(),
                    "protocols": set(),
                    "hosts": set(),
                    "names": set(),
                }
                self.entities[fp] = ent
            ent["observed_in"].add(f"{rec.get('location','?')}:{rec.get('name','')}")
            ent["hosts"].add(rec.get("host", ""))
            if rec.get("name"):
                ent["names"].add(rec["name"])
            proto = proto_by_url.get(rec.get("url"), "https")
            ent["protocols"].add(proto)
            # prefer the more specific type if a later observation refines it
            if ent["id_type"] == "object_id" and rec.get("id_type") not in (None, "object_id"):
                ent["id_type"] = rec["id_type"]
            by_url[rec.get("url", "")].append(rec)

        # 3. co-occurrence + 4. binding edges (identifiers on the same request)
        for url, recs in by_url.items():
            fps = list({r["value_fp"] for r in recs if r.get("value_fp")})
            for i in range(len(fps)):
                for j in range(i + 1, len(fps)):
                    self._link(fps[i], fps[j], url)

        # 2/5. finalise entity flags + serialise sets
        ents_out = []
        for fp, ent in self.entities.items():
            protos = ent["protocols"]
            cross = len({_fam(p) for p in protos}) > 1
            bound = ent["id_type"] in _AUTHENTICATORS
            ents_out.append({
                "entity_id": fp,
                "id_type": ent["id_type"],
                "observed_in": sorted(ent["observed_in"]),
                "protocols": sorted(protos),
                "hosts": sorted(h for h in ent["hosts"] if h),
                "names": sorted(ent["names"]),
                "cross_protocol": cross,
                "is_authenticator": bound,
                "reuse_count": len(ent["observed_in"]),
            })
        ents_out.sort(key=lambda e: (-e["reuse_count"], e["id_type"]))

        # BOLA candidates: object-id-shaped endpoints from the inventory
        self._bola_candidates()

        graph = {
            "module": "identity_graph",
            "entities": ents_out,
            "edges": self.edges,
            "bola_candidates": self.bola,
            "stats": {
                "entities": len(ents_out),
                "edges": len(self.edges),
                "cross_protocol_identities": sum(1 for e in ents_out if e["cross_protocol"]),
                "authenticators": sum(1 for e in ents_out if e["is_authenticator"]),
                "bola_candidates": len(self.bola),
            },
        }
        self.har_dir.mkdir(parents=True, exist_ok=True)
        (self.har_dir / "identity_graph.json").write_text(json.dumps(graph, indent=2))
        s = graph["stats"]
        log(f"identities={s['entities']} edges={s['edges']} "
            f"cross-protocol={s['cross_protocol_identities']} "
            f"bola-candidates={s['bola_candidates']}")
        return s

    def _link(self, a: str, b: str, url: str) -> None:
        ta = self.entities[a]["id_type"]
        tb = self.entities[b]["id_type"]
        # binding: authenticator + resource on the same request
        if ta in _AUTHENTICATORS and tb in _RESOURCES:
            rel, src, dst = "binds", a, b
        elif tb in _AUTHENTICATORS and ta in _RESOURCES:
            rel, src, dst = "binds", b, a
        elif ta == "user_ref" and tb in _RESOURCES:
            rel, src, dst = "owns", a, b
        elif tb == "user_ref" and ta in _RESOURCES:
            rel, src, dst = "owns", b, a
        else:
            rel, src, dst = "cooccurs", a, b
        key = (src, rel, dst)
        if key in self._edge_seen:
            return
        self._edge_seen.add(key)
        self.edges.append({"from": src, "rel": rel, "to": dst, "via": url})

    def _bola_candidates(self) -> None:
        inv = self.scan_dir / "08_directory_discovery" / "discovered_endpoints.jsonl"
        seen: Set = set()
        for rec in _read_jsonl(inv):
            uc = rec.get("url_class")
            shape = rec.get("url_shape")
            routed = rec.get("routed_to") or []
            if (uc == "api" and shape == "path-param") or "bola" in routed:
                k = (rec.get("host"), rec.get("path"))
                if k in seen:
                    continue
                seen.add(k)
                self.bola.append({
                    "host": rec.get("host"),
                    "url": rec.get("sample_url") or rec.get("url"),
                    "path": rec.get("path"),
                    "methods": rec.get("methods") or ["GET"],
                    "auth_state": rec.get("auth_state", "unknown"),
                })


def _fam(proto: str) -> str:
    p = (proto or "").lower()
    if p in ("ws", "wss"):
        return "ws"
    if p == "sse":
        return "sse"
    return "http"


def main() -> int:
    ap = argparse.ArgumentParser(description="ARISE identity / object graph")
    ap.add_argument("--scan-dir", required=True)
    args = ap.parse_args()
    scan_dir = Path(args.scan_dir)
    if not scan_dir.is_dir():
        log(f"scan-dir not found: {scan_dir}")
        return 1
    IdentityGraph(scan_dir).run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
