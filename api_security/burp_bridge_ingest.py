#!/usr/bin/env python3
"""
ARISE — Burp Bridge Ingestor  (Module 0-BURP, Stage 0 "Intake")
===============================================================
BurpAPISecuritySuite is the authenticated *sensor*: a human operator drives the
target logged in as guest / user / admin, and Burp records that real, stateful,
multi-role traffic. It exports an `excalibur-burp-bridge/v1` bundle — a strictly
richer HAR that carries full request/response bodies + the auth context per
capture.

This module makes that bundle a first-class ARISE recon source. It emits the
same evidence stream har_ingest produces, PLUS the one thing raw HAR can't give:
a per-capture **role label** (guest/user/admin), inferred from the auth material.
That label is exactly the input auth_oracle.py needs to turn "id=123 returned
200" into a proven BOLA/BFLA authorization-invariant violation.

Input
-----
  A bundle file with {"schema": "excalibur-burp-bridge/v1", "captures": [...]}.
  Passed explicitly (--bundle) or auto-discovered under the scan dir / CWD.

Output (into <scan>/00_har_ingest/, shared with har_ingest)
----------------------------------------------------------
  evidence_captures.jsonl   rich req/resp records the 5 passive analyzers +
                            auth_oracle consume; provenance=burp-authenticated,
                            role labelled
  burp_urls.txt             plain URL list (highest-trust feeder source)
  burp_identities.jsonl     observed (role -> auth material) map for the oracle
  burp_bridge_summary.json  counts

Usage
-----
  python3 burp_bridge_ingest.py <scan_output_dir> [--bundle FILE]
  python3 burp_bridge_ingest.py <scan_output_dir> --summary
"""

from __future__ import annotations

import sys as _sys, os as _os
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)


import argparse
import base64
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

BRIDGE_SCHEMA = "excalibur-burp-bridge/v1"
PROVENANCE = "burp-authenticated"

# Markers that push an inferred role up to "admin".
_ADMIN_MARKERS = ("admin", "root", "super", "owner", "system", "svc", "service", "internal")
_TOKEN_COOKIE_MARKERS = ("session", "token", "auth", "jwt", "sid", "access")

_NUM_SEG = re.compile(r"/\d+(?=/|$)")
_UUID_SEG = re.compile(
    r"/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?=/|$)", re.I)


def _text(v, lower=False):
    if v is None:
        v = ""
    if not isinstance(v, str):
        try:
            v = str(v)
        except Exception:
            v = ""
    return v.lower() if lower else v


def _normalize_path(path: str) -> str:
    p = (path or "/").split("?", 1)[0].split("#", 1)[0]
    if not p.startswith("/"):
        p = "/" + p
    p = _UUID_SEG.sub("/{uuid}", p)
    p = _NUM_SEG.sub("/{id}", p)
    return re.sub(r"/+", "/", p) or "/"


def _lower_headers(headers) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if isinstance(headers, dict):
        for k, v in headers.items():
            out[_text(k, lower=True).strip()] = _text(v)
    elif isinstance(headers, list):
        for h in headers:
            if isinstance(h, dict):
                out[_text(h.get("name"), lower=True).strip()] = _text(h.get("value"))
    return out


def _decode_jwt_claims(token: str) -> dict:
    raw = _text(token).strip()
    if raw.count(".") != 2:
        return {}
    payload = raw.split(".", 2)[1].strip()
    if not payload:
        return {}
    pad = len(payload) % 4
    if pad:
        payload += "=" * (4 - pad)
    try:
        decoded = base64.urlsafe_b64decode(payload)
        if isinstance(decoded, bytes):
            decoded = decoded.decode("utf-8", "ignore")
        claims = json.loads(decoded)
        return claims if isinstance(claims, dict) else {}
    except Exception:
        return {}


def _auth_material(req_headers: Dict[str, str]) -> (List[str], dict, str):
    """Return (auth_detected, jwt_claims, token_repr) from request headers."""
    detected: List[str] = []
    claims: dict = {}
    token_repr = ""
    authz = req_headers.get("authorization", "")
    low = _text(authz, lower=True)
    if low.startswith("bearer "):
        detected.append("bearer")
        token_repr = authz[7:].strip()
        claims = _decode_jwt_claims(token_repr)
    elif low.startswith("basic "):
        detected.append("basic")
        token_repr = authz.strip()
    if req_headers.get("x-api-key"):
        detected.append("api_key")
        token_repr = token_repr or req_headers["x-api-key"]
    cookie = req_headers.get("cookie", "")
    if cookie:
        for chunk in cookie.split(";"):
            if "=" in chunk:
                k, v = chunk.split("=", 1)
                if any(m in _text(k, lower=True) for m in _TOKEN_COOKIE_MARKERS):
                    detected.append("session_cookie")
                    token_repr = token_repr or v.strip()
                    if not claims:
                        claims = _decode_jwt_claims(v.strip())
                    break
    return detected or ["none"], claims, token_repr


def infer_role(req_headers: Dict[str, str], tags: List[str],
               auth_methods: List[str]) -> str:
    """Infer guest/user/admin from the auth material and any operator tags.

    This is the label raw HAR cannot supply. Precedence:
      1. explicit role tag from the operator
      2. JWT/claim privilege markers  -> admin
      3. any valid auth present       -> user
      4. no auth                      -> guest
    """
    tag_text = " ".join(_text(t, lower=True) for t in (tags or []))
    for role in ("admin", "user", "guest", "anonymous"):
        if re.search(r"(^|[^a-z])" + role + r"([^a-z]|$)", tag_text):
            return "guest" if role == "anonymous" else role

    detected, claims, token_repr = _auth_material(req_headers)
    blob = _text(token_repr, lower=True)
    claim_blob = _text(json.dumps(claims), lower=True) if claims else ""
    for key in ("role", "roles", "scope", "scp", "authorities", "groups"):
        if key in claims:
            claim_blob += " " + _text(claims.get(key), lower=True)
    if any(m in blob or m in claim_blob for m in _ADMIN_MARKERS):
        return "admin"

    has_auth = detected != ["none"] or any(a and a != "none" for a in (auth_methods or []))
    return "user" if has_auth else "guest"


def _capture_to_record(cap: dict) -> Optional[dict]:
    if not isinstance(cap, dict):
        return None
    req = cap.get("request") or {}
    resp = cap.get("response") or {}
    ctx = cap.get("context") or {}
    timing = cap.get("timing") or {}
    url = _text(req.get("url")).strip()
    if not url:
        return None
    method = _text(req.get("method") or "GET").upper()
    req_headers = _lower_headers(req.get("headers"))
    resp_headers = _lower_headers(resp.get("headers"))
    m = re.match(r"[a-z]+://([^/:]+)(?::\d+)?(/[^?#]*)?", url, re.I)
    host = _text(ctx.get("host") or (m.group(1) if m else "")).lower()
    path = _text(m.group(2) if (m and m.group(2)) else (ctx.get("normalized_path") or "/"))
    tags = list(ctx.get("tags") or [])
    auth_methods = list(ctx.get("auth_methods") or [])
    role = infer_role(req_headers, tags, auth_methods)
    detected, _claims, _tok = _auth_material(req_headers)
    return {
        "url": url,
        "host": host,
        "method": method,
        "path": path or "/",
        "normalized_path": ctx.get("normalized_path") or _normalize_path(path),
        "provenance": PROVENANCE,
        "role": role,
        "auth_detected": detected,
        "headers": req_headers,
        "request_body": _text(req.get("body") or ""),
        "content_type": _text(req.get("content_type") or req_headers.get("content-type") or ""),
        "response_status": int(resp.get("status") or 0) if str(resp.get("status") or "").isdigit() else 0,
        "response_headers": resp_headers,
        "response_body": _text(resp.get("body") or ""),
        "response_length": int(resp.get("length") or 0) if str(resp.get("length") or "").isdigit() else 0,
        "captured_at_epoch_ms": int(timing.get("captured_at_epoch_ms") or 0) if str(timing.get("captured_at_epoch_ms") or "").isdigit() else 0,
        "response_time_ms": int(timing.get("response_time_ms") or 0) if str(timing.get("response_time_ms") or "").isdigit() else 0,
        "tags": tags,
        "source_tool": _text(ctx.get("source_tool") or "burp"),
    }


def _discover_bundle(scan_dir: Path, explicit: Optional[str]) -> Optional[Path]:
    if explicit:
        p = Path(explicit)
        return p if p.exists() else None
    candidates = [
        scan_dir / "excalibur_bridge_bundle.json",
        scan_dir / "00_har_ingest" / "excalibur_bridge_bundle.json",
        Path.cwd() / "excalibur_bridge_bundle.json",
    ]
    # Also any *bridge*.json / *excalibur*.json under the scan dir.
    for pat in ("*bridge*.json", "*excalibur*.json"):
        candidates.extend(sorted(scan_dir.rglob(pat)))
    for c in candidates:
        if c.exists() and c.is_file():
            try:
                head = json.loads(c.read_text(errors="ignore"))
                if isinstance(head, dict) and _text(head.get("schema")).startswith("excalibur-burp-bridge"):
                    return c
            except Exception:
                continue
    return None


def run(scan_dir: str, bundle: Optional[str] = None, emit_summary: bool = False) -> dict:
    scan = Path(scan_dir)
    out_dir = scan / "00_har_ingest"
    out_dir.mkdir(parents=True, exist_ok=True)

    bundle_path = _discover_bundle(scan, bundle)
    summary = {
        "module": "burp_bridge_ingest",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "bundle": str(bundle_path) if bundle_path else None,
        "captures": 0, "records": 0,
        "roles": {}, "by_status_class": {},
    }
    if not bundle_path:
        summary["note"] = "No excalibur-burp-bridge/v1 bundle found — nothing to ingest."
        with (out_dir / "burp_bridge_summary.json").open("w") as fh:
            json.dump(summary, fh, indent=2)
        if emit_summary:
            print("[burp-bridge] no bundle found under %s" % scan_dir)
        return summary

    try:
        data = json.loads(bundle_path.read_text(errors="ignore"))
    except Exception as exc:
        summary["note"] = "Failed to parse bundle: %s" % exc
        with (out_dir / "burp_bridge_summary.json").open("w") as fh:
            json.dump(summary, fh, indent=2)
        return summary

    captures = data.get("captures") or []
    summary["captures"] = len(captures)

    records: List[dict] = []
    urls = set()
    identities: Dict[str, dict] = {}
    role_counts: Dict[str, int] = {}
    status_class: Dict[str, int] = {}
    for cap in captures:
        rec = _capture_to_record(cap)
        if not rec:
            continue
        records.append(rec)
        if rec["url"]:
            urls.add(rec["url"])
        role_counts[rec["role"]] = role_counts.get(rec["role"], 0) + 1
        sc = "%dxx" % (rec["response_status"] // 100) if rec["response_status"] else "0xx"
        status_class[sc] = status_class.get(sc, 0) + 1
        # Record the auth material per role, once, for the oracle.
        if rec["role"] not in identities and rec["auth_detected"] != ["none"]:
            authz = rec["headers"].get("authorization", "")
            cookie = rec["headers"].get("cookie", "")
            identities[rec["role"]] = {
                "role": rec["role"],
                "auth_detected": rec["auth_detected"],
                "authorization": authz,
                "cookie": cookie,
                "example_endpoint": "%s:%s" % (rec["method"], rec["normalized_path"]),
            }

    # ---- emit ----
    with (out_dir / "evidence_captures.jsonl").open("w") as fh:
        for rec in records:
            fh.write(json.dumps(rec) + "\n")
    with (out_dir / "burp_urls.txt").open("w") as fh:
        for u in sorted(urls):
            fh.write(u + "\n")
    with (out_dir / "burp_identities.jsonl").open("w") as fh:
        for role in sorted(identities.keys()):
            fh.write(json.dumps(identities[role]) + "\n")

    summary["records"] = len(records)
    summary["urls"] = len(urls)
    summary["roles"] = role_counts
    summary["identities"] = sorted(identities.keys())
    summary["by_status_class"] = status_class
    with (out_dir / "burp_bridge_summary.json").open("w") as fh:
        json.dump(summary, fh, indent=2)

    if emit_summary:
        print("[burp-bridge] bundle=%s captures=%d records=%d urls=%d roles=%s"
              % (bundle_path.name, len(captures), len(records), len(urls),
                 ",".join("%s:%d" % (k, v) for k, v in sorted(role_counts.items()))))
    return summary


def main() -> int:
    ap = argparse.ArgumentParser(description="ARISE Burp bridge-bundle ingestor")
    ap.add_argument("scan_dir", help="Scan output directory")
    ap.add_argument("--bundle", help="Path to excalibur_bridge_bundle.json (else auto-discover)")
    ap.add_argument("--summary", action="store_true", help="Print a one-line summary")
    args = ap.parse_args()
    if not os.path.isdir(args.scan_dir):
        print("scan dir not found: %s" % args.scan_dir, file=sys.stderr)
        return 2
    run(args.scan_dir, bundle=args.bundle, emit_summary=args.summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
