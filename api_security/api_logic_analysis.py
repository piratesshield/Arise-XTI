#!/usr/bin/env python3
"""
ARISE — API Logic Analysis (Module 24-API, Stage 1 "Understand")
================================================================
The five PASSIVE deep-logic analyzers, ported from BurpAPISecuritySuite and run
as pure functions over ARISE's evidence stream. They send ZERO packets — every
finding is a differential observed in already-captured traffic.

  counterfactual   — auth must be representation-invariant; identifier precedence;
                     sensitive-field redaction monotonicity
  golden_ticket    — one credential reused across many resources / long-lived /
                     unbound JWT scope (master-key anti-patterns)
  state_transition — workflow/state drift across a resource lifecycle
  token_lineage    — missing revoke/rotation, session-family drift
  parity_drift     — REST vs GraphQL vs internal auth parity gaps

Confidence discipline (arise_evidence L0-L6)
--------------------------------------------
Passive analysis can only OBSERVE differentials, never PROVE an authorization
invariant broke. So every lead here is capped at **L3 (security-differential)**
and marked stage="lead", needs_active_confirmation=True. Only auth_oracle /
offensive_verify (Stage 3, active) may mint L4+ (authz-violation and above),
which is what promotes a lead into the Vulnerabilities dashboard.

Input (in priority order)
-------------------------
  <scan>/00_har_ingest/evidence_captures.jsonl   rich req/resp records (har_ingest
                                                 + burp_bridge_ingest) — best
  <scan>/00_har_ingest/har_assets.jsonl          classified metadata (partial)
  <scan>/08_directory_discovery/discovered_endpoints.jsonl   thin fallback

Output
------
  <scan>/24_api_attack/api_logic_leads.jsonl     one row per lead (ARISE schema)
  <scan>/24_api_attack/api_logic_summary.json    counts by analyzer/severity/rung

Usage
-----
  python3 api_logic_analysis.py <scan_output_dir> [--summary]
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
import time
from pathlib import Path
from typing import Dict, List, Optional

# The five analyzers live in the api_logic/ package (4 vendored verbatim from
# BurpAPISecuritySuite, counterfactual ported to standalone).
import api_security.api_logic.golden_ticket_analysis as _golden
import api_security.api_logic.state_transition_analysis as _state
import api_security.api_logic.token_lineage_analysis as _lineage
import api_security.api_logic.parity_drift_analysis as _parity
import api_security.api_logic.counterfactual_analysis as _counter

# Shared L0-L6 ladder + provenance vocabulary (single source of truth).
try:
    import evidence.arise_evidence as _ev
except Exception:  # pragma: no cover - arise_evidence is always present
    _ev = None


# --------------------------------------------------------------------------- #
# Path templating — id/uuid segments collapse so an endpoint_key groups samples
# --------------------------------------------------------------------------- #
_NUM_SEG = re.compile(r"/\d+(?=/|$)")
_UUID_SEG = re.compile(
    r"/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?=/|$)", re.I)
_HEX24_SEG = re.compile(r"/[0-9a-f]{24}(?=/|$)", re.I)


def _normalize_path(path: str) -> str:
    p = (path or "/").split("?", 1)[0].split("#", 1)[0]
    if not p.startswith("/"):
        p = "/" + p
    p = _UUID_SEG.sub("/{uuid}", p)
    p = _HEX24_SEG.sub("/{id}", p)
    p = _NUM_SEG.sub("/{id}", p)
    p = re.sub(r"/+", "/", p)
    return p or "/"


def _endpoint_key(method: str, norm_path: str) -> str:
    return "{}:{}".format((method or "GET").upper(), norm_path or "/")


# --------------------------------------------------------------------------- #
# Evidence intake — build data_snapshot { endpoint_key: [entry, ...] }
# --------------------------------------------------------------------------- #
def _read_jsonl(path: Path) -> List[dict]:
    rows: List[dict] = []
    if not path.exists():
        return rows
    try:
        with path.open("r", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except Exception:
                    continue
    except Exception:
        pass
    return rows


def _entry_from_capture(rec: dict) -> Optional[dict]:
    """Normalize a rich evidence_captures.jsonl / bridge record into the entry
    shape the analyzers consume."""
    url = rec.get("url") or ""
    method = (rec.get("method") or "GET").upper()
    path = rec.get("path") or rec.get("normalized_path") or ""
    if not path and url:
        m = re.match(r"[a-z]+://[^/]+(/[^?#]*)", url, re.I)
        path = m.group(1) if m else "/"
    norm = rec.get("normalized_path") or _normalize_path(path)
    # Headers may arrive as a dict (bridge) or a list of {name,value} (HAR).
    headers = rec.get("headers") or rec.get("request_headers") or {}
    if isinstance(headers, list):
        headers = {str(h.get("name", "")).lower(): h.get("value", "")
                   for h in headers if isinstance(h, dict)}
    resp_headers = rec.get("response_headers") or {}
    if isinstance(resp_headers, list):
        resp_headers = {str(h.get("name", "")).lower(): h.get("value", "")
                        for h in resp_headers if isinstance(h, dict)}
    return {
        "method": method,
        "host": (rec.get("host") or "").lower(),
        "path": path or "/",
        "normalized_path": norm,
        "url": url,
        "headers": headers,
        "request_body": rec.get("request_body") or "",
        "response_status": _int(rec.get("response_status", rec.get("status", 0))),
        "response_headers": resp_headers,
        "response_body": rec.get("response_body") or "",
        "content_type": rec.get("content_type") or "",
        "auth_detected": rec.get("auth_detected") or rec.get("auth_methods") or [],
        "role": rec.get("role") or "",
        "parameters": rec.get("parameters") or {},
        "captured_at_epoch_ms": _int(rec.get("captured_at_epoch_ms", 0)),
        "provenance": rec.get("provenance") or "",
    }


def _entry_from_thin(rec: dict) -> Optional[dict]:
    """Fallback: build a minimal entry from discovered_endpoints.jsonl (no
    headers/bodies). state_transition + parity_drift still fire on method+path."""
    url = rec.get("url") or rec.get("sample_url") or ""
    method = (rec.get("method") or "GET").upper()
    path = rec.get("path") or ""
    if not path and url:
        m = re.match(r"[a-z]+://[^/]+(/[^?#]*)", url, re.I)
        path = m.group(1) if m else "/"
    return {
        "method": method,
        "host": (rec.get("host") or "").lower(),
        "path": path or "/",
        "normalized_path": _normalize_path(path),
        "url": url,
        "headers": {},
        "request_body": "",
        "response_status": _int(rec.get("status", 0)),
        "response_headers": {},
        "response_body": "",
        "content_type": "",
        "auth_detected": [],
        "role": "",
        "parameters": {},
        "captured_at_epoch_ms": 0,
        "provenance": rec.get("source") or "crawl",
    }


def _int(v) -> int:
    try:
        return int(v or 0)
    except (TypeError, ValueError):
        return 0


def build_data_snapshot(scan_dir: Path) -> (Dict[str, List[dict]], str):
    """Assemble { endpoint_key: [entry] } from the richest source available."""
    sources = [
        (scan_dir / "00_har_ingest" / "evidence_captures.jsonl", _entry_from_capture, "evidence_captures"),
        (scan_dir / "00_har_ingest" / "har_assets.jsonl", _entry_from_capture, "har_assets"),
        (scan_dir / "08_directory_discovery" / "discovered_endpoints.jsonl", _entry_from_thin, "discovered_endpoints"),
    ]
    snapshot: Dict[str, List[dict]] = {}
    used = "none"
    for path, builder, label in sources:
        rows = _read_jsonl(path)
        if not rows:
            continue
        used = label
        for rec in rows:
            entry = builder(rec)
            if not entry:
                continue
            key = _endpoint_key(entry["method"], entry["normalized_path"])
            snapshot.setdefault(key, []).append(entry)
        # Rich sources win outright; only fall through to the thin one if the
        # richer files were absent/empty.
        if label in ("evidence_captures", "har_assets"):
            break
    return snapshot, used


# --------------------------------------------------------------------------- #
# Finding normalization → ARISE lead schema with L0-L6 rung
# --------------------------------------------------------------------------- #
_SEV_TO_RUNG = {"critical": "L3", "high": "L3", "medium": "L2", "low": "L1", "info": "L1"}


def _rung_for(severity: str) -> str:
    """Passive leads cap at L3 (security-differential). Only the active oracle
    (Stage 3) mints L4+ authz-violations."""
    return _SEV_TO_RUNG.get((severity or "info").lower(), "L1")


def _to_lead(raw: dict, analyzer: str, snapshot: Dict[str, List[dict]]) -> dict:
    sev = (raw.get("severity") or "info").lower()
    rung = _rung_for(sev)
    scope = raw.get("endpoint_scope") or ([raw.get("endpoint")] if raw.get("endpoint") else [])
    scope = [s for s in scope if s]
    endpoint = scope[0] if scope else (raw.get("resource") or "")
    # Best-effort provenance + host attribution: the analyzers key by
    # method:path (host-agnostic on purpose), so resolve the host(s) that this
    # endpoint_key was actually observed on from the snapshot, and surface them
    # so the operator can tell which host each finding belongs to.
    prov = "crawl"
    hosts = []
    seen_hosts = set()
    for key in scope:
        for e in snapshot.get(key, []):
            cand = e.get("provenance") or "crawl"
            if _ev is not None:
                prov = _ev.stronger_provenance(prov, cand)
            else:
                prov = cand
            h = (e.get("host") or "").strip().lower()
            if h and h not in seen_hosts:
                seen_hosts.add(h)
                hosts.append(h)
    if raw.get("host"):
        rh = str(raw["host"]).strip().lower()
        if rh and rh not in seen_hosts:
            seen_hosts.add(rh)
            hosts.append(rh)
    if len(hosts) == 1:
        host_display = hosts[0]
    elif len(hosts) > 1:
        host_display = "%d hosts" % len(hosts)
    else:
        host_display = ""
    meta = _ev.ladder_meta(rung) if _ev is not None else {"code": rung, "confirmed": False}
    lead = {
        "analyzer": analyzer,
        "category": raw.get("category") or analyzer.upper(),
        "invariant": raw.get("invariant") or "",
        "title": raw.get("title") or "",
        "severity": sev,
        "endpoint": endpoint,
        "host": host_display,
        "hosts": hosts[:20],
        "endpoint_scope": scope[:20],
        "resource": raw.get("resource") or "",
        "evidence": raw.get("evidence") or [],
        "suggested_checks": raw.get("suggested_checks") or [],
        "confidence_score": raw.get("confidence_score"),
        "confidence_label": raw.get("confidence_label"),
        # Evidence discipline: leads are unconfirmed until actively proven.
        "rung": rung,
        "rung_name": meta.get("name", ""),
        "confirmed": False,
        "stage": "lead",
        "needs_active_confirmation": True,
        "provenance": prov,
        "non_destructive": True,
        "source": "api_logic_analysis",
    }
    return lead


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #
_ANALYZERS = [
    ("counterfactual", _counter.build_counterfactual_findings),
    ("golden_ticket", _golden.build_golden_ticket_findings),
    ("state_transition", _state.build_state_transition_findings),
    ("token_lineage", _lineage.build_token_lineage_findings),
    ("parity_drift", _parity.build_parity_drift_findings),
]

# Each analyzer module also ships a build_*_package() — the same findings plus
# an "evidence ledger" (analyst_guidance, coverage/observation stats,
# schema_version). Written every scan, alongside api_logic_leads.jsonl, so a
# future drill-down view has the richer analyst-facing detail on disk without
# re-running the (passive, in-memory) analysis.
_PACKAGE_BUILDERS = [
    ("counterfactual", _counter.build_counterfactual_package),
    ("golden_ticket", _golden.build_golden_ticket_package),
    ("state_transition", _state.build_state_transition_package),
    ("token_lineage", _lineage.build_token_lineage_package),
    ("parity_drift", _parity.build_parity_drift_package),
]


def run(scan_dir: str, emit_summary: bool = False) -> dict:
    scan = Path(scan_dir)
    out_dir = scan / "24_api_attack"
    out_dir.mkdir(parents=True, exist_ok=True)

    snapshot, source_used = build_data_snapshot(scan)
    n_endpoints = len(snapshot)
    n_samples = sum(len(v) for v in snapshot.values())

    leads: List[dict] = []
    per_analyzer: Dict[str, int] = {}
    for name, fn in _ANALYZERS:
        try:
            raw_findings = fn(snapshot) or []
        except Exception as exc:  # never let one analyzer sink the module
            print("[api-logic] analyzer %s failed: %s" % (name, exc), file=sys.stderr)
            raw_findings = []
        per_analyzer[name] = len(raw_findings)
        for raw in raw_findings:
            leads.append(_to_lead(raw, name, snapshot))

    # Sort: severity, then confirmed-rung desc, then analyzer.
    sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    leads.sort(key=lambda l: (
        -sev_rank.get(l["severity"], 0),
        -(_ev.ladder_rank(l["rung"]) if _ev is not None else 0),
        l["analyzer"]))

    leads_path = out_dir / "api_logic_leads.jsonl"
    with leads_path.open("w") as fh:
        for lead in leads:
            fh.write(json.dumps(lead) + "\n")

    # Evidence ledgers: each analyzer's richer analyst-facing package (findings
    # + analyst_guidance + coverage/observation stats). Same fail-open
    # discipline as the leads loop above — one analyzer's package failing
    # never blocks the others or the (already-written) leads file.
    ledgers: Dict[str, dict] = {}
    for name, fn in _PACKAGE_BUILDERS:
        try:
            ledgers[name] = fn(snapshot) or {}
        except Exception as exc:
            print("[api-logic] package %s failed: %s" % (name, exc), file=sys.stderr)
            ledgers[name] = {}
    ledgers_path = out_dir / "api_logic_evidence_ledgers.json"
    with ledgers_path.open("w") as fh:
        json.dump({"generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
                   "analyzers": ledgers}, fh, indent=2)

    summary = {
        "module": "api_logic_analysis",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "evidence_source": source_used,
        "endpoints_analyzed": n_endpoints,
        "samples_analyzed": n_samples,
        "total_leads": len(leads),
        "by_analyzer": per_analyzer,
        "by_severity": {s: sum(1 for l in leads if l["severity"] == s)
                        for s in ("critical", "high", "medium", "low", "info")},
        "by_rung": {code: sum(1 for l in leads if l["rung"] == code)
                    for code, _n, _d in (_ev.LADDER if _ev is not None else [])},
        "leads_file": str(leads_path),
        "evidence_ledgers_file": str(ledgers_path),
        "note": ("Passive leads — capped at L3 (security-differential). "
                 "Active confirmation (auth_oracle / offensive_verify) required "
                 "to reach L4+ and promote to Vulnerabilities."),
    }
    summary_path = out_dir / "api_logic_summary.json"
    with summary_path.open("w") as fh:
        json.dump(summary, fh, indent=2)

    if emit_summary:
        print("[api-logic] source=%s endpoints=%d samples=%d leads=%d %s"
              % (source_used, n_endpoints, n_samples, len(leads),
                 " ".join("%s=%d" % (k, v) for k, v in per_analyzer.items())))
    return summary


def main() -> int:
    ap = argparse.ArgumentParser(description="ARISE API Logic Analysis (5 passive analyzers)")
    ap.add_argument("scan_dir", help="Scan output directory")
    ap.add_argument("--summary", action="store_true", help="Print a one-line summary")
    args = ap.parse_args()
    if not os.path.isdir(args.scan_dir):
        print("scan dir not found: %s" % args.scan_dir, file=sys.stderr)
        return 2
    run(args.scan_dir, emit_summary=args.summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
