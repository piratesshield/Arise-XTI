#!/usr/bin/env python3
"""
ARISE — Flow Reconstructor  (R2, Module 0-FLOW)
===============================================
The WMS lesson: raw `requests.Session` returned 400 where the browser worked,
because the browser had completed steps 1-3 (login → bootstrap → connect) before
step 4. An endpoint tested in isolation, out of its flow, produces false
negatives. This module reconstructs the multi-step application flows so a later
attack step can REPLAY its prerequisites first.

Input
-----
  <scan>/00_har_ingest/flow_sequences.jsonl   (from har_ingest.py — real order)
  <scan>/00_har_ingest/har_assets.jsonl       (protocol + auth_state per asset)

Method
------
  1. Group requests into flows by their flow_group (HAR pageref / session).
  2. Order each flow by observed sequence.
  3. Dependency edges: if step A's response PRODUCES token X (Set-Cookie,
     redirect) and a later step B REQUIRES X, draw A → B.
  4. Auth boundary: the earliest step that is an auth-endpoint OR first produces
     a session/auth cookie — everything after it is authenticated surface.
  5. Protocol transitions: where the flow crosses http(s) → wss/sse (the WMS
     "most interesting boundary"), record it as a first-class edge.

Output
------
  <scan>/00_har_ingest/flow_graph.jsonl   one row per reconstructed flow:
    {flow_id, steps:[{seq,url,method,protocol,requires,produces,status}],
     auth_boundary, protocol_transitions:[{from,to,at_step,url}],
     terminal_protocol, step_count}

Consumed by: offensive_verify / auth_oracle (replay prerequisites), wss_agent
(where a WSS connect sits in a flow), capec_attack_paths (protocol-boundary
edges). Stdlib only.
"""

from __future__ import annotations

import sys as _sys, os as _os
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)


import argparse
import json
import sys
from pathlib import Path
from typing import Dict, List, Optional

def log(msg: str) -> None:
    print(f"[flow] {msg}", file=sys.stderr, flush=True)


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


class FlowReconstructor:
    def __init__(self, scan_dir: Path):
        self.scan_dir = scan_dir
        self.har_dir = scan_dir / "00_har_ingest"
        self.flows: List[dict] = []

    def run(self) -> Dict[str, int]:
        seq = _read_jsonl(self.har_dir / "flow_sequences.jsonl")
        if not seq:
            log("no flow_sequences.jsonl — run har_ingest first; nothing to do")
            self._write()
            return {"flows": 0, "steps": 0}

        groups: Dict[str, List[dict]] = {}
        for r in seq:
            groups.setdefault(r.get("flow_group") or "default", []).append(r)

        total_steps = 0
        for gid, rows in groups.items():
            rows.sort(key=lambda r: (r.get("seq", 0), r.get("started", "")))
            flow = self._build_flow(gid, rows)
            if flow["step_count"] >= 1:
                self.flows.append(flow)
                total_steps += flow["step_count"]

        self._write()
        log(f"reconstructed {len(self.flows)} flow(s), {total_steps} steps")
        return {"flows": len(self.flows), "steps": total_steps}

    def _build_flow(self, gid: str, rows: List[dict]) -> dict:
        steps: List[dict] = []
        # map token -> the earliest step index that produced it
        produced_at: Dict[str, int] = {}
        auth_boundary: Optional[int] = None
        transitions: List[dict] = []
        prev_proto: Optional[str] = None

        for i, r in enumerate(rows):
            produces = list(r.get("produces") or [])
            requires = list(r.get("requires") or [])
            proto = r.get("protocol") or "https"
            # dependency edges: which prior step produced each required token
            depends_on = sorted({produced_at[t] for t in requires
                                 if t in produced_at})
            for t in produces:
                produced_at.setdefault(t, i)

            # auth boundary: first auth-endpoint or first session-cookie producer
            if auth_boundary is None:
                is_auth_ep = (r.get("auth_state") == "auth-endpoint")
                sets_session = any("session" in t.lower() or "sid" in t.lower()
                                   for t in produces)
                if is_auth_ep or sets_session:
                    auth_boundary = i

            # protocol transition (the WMS http→wss boundary)
            if prev_proto and _fam(proto) != _fam(prev_proto):
                transitions.append({
                    "from": prev_proto, "to": proto, "at_step": i,
                    "url": r.get("url", ""),
                })
            prev_proto = proto

            steps.append({
                "seq": i,
                "url": r.get("url", ""),
                "host": r.get("host", ""),
                "method": r.get("method", "GET"),
                "protocol": proto,
                "status": r.get("status", 0),
                "requires": requires,
                "produces": produces,
                "depends_on": depends_on,
                "auth_state": r.get("auth_state", "unknown"),
            })

        return {
            "flow_id": _flow_id(gid, steps),
            "flow_group": gid,
            "steps": steps,
            "step_count": len(steps),
            "auth_boundary": auth_boundary,
            "protocol_transitions": transitions,
            "terminal_protocol": prev_proto or "https",
            "authenticated_steps": (
                [] if auth_boundary is None
                else [s["seq"] for s in steps if s["seq"] > auth_boundary]),
        }

    def _write(self) -> None:
        self.har_dir.mkdir(parents=True, exist_ok=True)
        out = self.har_dir / "flow_graph.jsonl"
        with out.open("w") as fh:
            for f in self.flows:
                fh.write(json.dumps(f) + "\n")
        summary = {
            "module": "flow_reconstruct",
            "flows": len(self.flows),
            "steps": sum(f["step_count"] for f in self.flows),
            "flows_with_auth_boundary": sum(
                1 for f in self.flows if f["auth_boundary"] is not None),
            "flows_with_protocol_transition": sum(
                1 for f in self.flows if f["protocol_transitions"]),
        }
        (self.har_dir / "flow_graph_summary.json").write_text(
            json.dumps(summary, indent=2))


def _fam(proto: str) -> str:
    p = (proto or "").lower()
    if p in ("ws", "wss"):
        return "ws"
    if p == "sse":
        return "sse"
    return "http"


def _flow_id(gid: str, steps: List[dict]) -> str:
    # derive a stable, readable id from the group + first host
    host = steps[0]["host"] if steps else "flow"
    base = (gid or "flow").replace("http://", "").replace("https://", "")
    base = "".join(c if c.isalnum() else "_" for c in base)[:40].strip("_")
    return f"{host}:{base or 'flow'}:{len(steps)}"


def main() -> int:
    ap = argparse.ArgumentParser(description="ARISE flow reconstructor")
    ap.add_argument("--scan-dir", required=True)
    args = ap.parse_args()
    scan_dir = Path(args.scan_dir)
    if not scan_dir.is_dir():
        log(f"scan-dir not found: {scan_dir}")
        return 1
    FlowReconstructor(scan_dir).run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
