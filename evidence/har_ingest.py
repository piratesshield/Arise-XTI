#!/usr/bin/env python3
"""
ARISE — HAR / Browser-Trace Ingestor  (R1, Module 0-HAR)
========================================================
The WMS bug-bounty post-mortem's #1 lesson: the HAR contained far more useful
information than the first URL suggested — real auth context, cookies, the
WebSocket upgrade, and the request SEQUENCE that made the app work. A passive
crawler never sees any of that. This module makes a HAR (or a browser DevTools
export) a first-class recon source.

What it does
------------
Parses one or more `.har` files and emits, into the scan dir, four artefacts
that the rest of the ARISE pipeline consumes:

  har_urls.txt                plain URL list — read by endpoint_consolidator as
                              the `har` source (highest-trust provenance)
  har_assets.jsonl            one row per request/response, classified, tagged
                              provenance=har, protocol=http|https|wss|sse, with
                              the auth tokens observed on it
  har_websockets.jsonl        WebSocket connections as FIRST-CLASS assets (the
                              WMS `wss://…/pconnect` boundary), incl. any frames
  flow_sequences.jsonl        the time-ordered request stream per page/session —
                              the raw material flow_reconstruct.py turns into a
                              flow graph
  har_identifiers.jsonl       every identity-bearing value observed (session /
                              object-id / device / jwt / csrf) + where it lived,
                              seed for identity_graph.py

Everything degrades gracefully: a malformed entry is skipped, a missing field
is tolerated, the tool never raises to the caller.

Usage
-----
  python3 har_ingest.py <target> --scan-dir <dir> [--har a.har b.har ...]
  # with no --har, auto-discovers *.har under <scan-dir> and <scan-dir>/har_in/

Output dir: <scan-dir>/00_har_ingest/
"""

from __future__ import annotations

import sys as _sys, os as _os
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)


import argparse
import json
import re
import sys
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    from discovery.url_classify import (classify_url, JWT_RE, _RAW_ID_RE, _UUID_RE)
except Exception:  # pragma: no cover
    classify_url = None
    JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")
    _RAW_ID_RE = re.compile(r"^(?:\d{5,}|[0-9a-fA-F]{12,})$")
    _UUID_RE = re.compile(
        r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")

try:
    from evidence.arise_evidence import provenance_of  # noqa: F401  (marks the vocabulary)
except Exception:  # pragma: no cover
    def provenance_of(_s):  # type: ignore
        return "har"


def log(msg: str) -> None:
    print(f"[har-ingest] {msg}", file=sys.stderr, flush=True)


# --- identity-bearing detection --------------------------------------------
# Header / cookie / param NAMES that carry identity, matched case-insensitively.
_AUTH_HEADER_NAMES = {
    "authorization", "cookie", "x-csrf-token", "x-xsrf-token", "csrf-token",
    "x-auth-token", "x-api-key", "x-session-token", "x-access-token",
    "x-session-id", "x-request-id",
}
_ID_KEY_RE = re.compile(
    r"(?:^|[_\-.])(?:id|uid|guid|uuid|token|session|sid|sess|account|acct|"
    r"user|device|dev|tid|wmsid|tabid|conn|pconnect|ref|key)(?:$|[_\-.])",
    re.IGNORECASE,
)


def _id_type_for(name: str, value: str) -> Optional[str]:
    """Classify an observed (name, value) pair into an identity type, or None."""
    n = (name or "").lower()
    v = value or ""
    if JWT_RE.search(v):
        return "jwt"
    if _UUID_RE.match(v):
        # UUIDs are the classic object/device identifier
        pass
    if any(k in n for k in ("csrf", "xsrf")):
        return "csrf_token"
    if any(k in n for k in ("session", "sid", "sess", "sso")):
        return "session"
    if any(k in n for k in ("device", "dev_", "e2ee")):
        return "device_id"
    if any(k in n for k in ("account", "acct", "user", "uid", "member")):
        return "user_ref"
    if any(k in n for k in ("token", "key", "auth", "bearer")):
        return "auth_token"
    if _ID_KEY_RE.search(n) or _UUID_RE.match(v) or _RAW_ID_RE.match(v):
        return "object_id"
    return None


def _looks_like_id_value(v: str) -> bool:
    v = v or ""
    return bool(JWT_RE.search(v) or _UUID_RE.match(v) or _RAW_ID_RE.match(v))


@dataclass
class HarStats:
    files: int = 0
    entries: int = 0
    assets: int = 0
    websockets: int = 0
    identifiers: int = 0
    flows: int = 0
    parse_errors: int = 0


class HarIngestor:
    def __init__(self, target: str, scan_dir: Path):
        self.target = (target or "").strip().lower().rstrip(".")
        self.scan_dir = scan_dir
        self.out_dir = scan_dir / "00_har_ingest"
        self.stats = HarStats()
        self.assets: List[dict] = []
        self.websockets: List[dict] = []
        self.identifiers: List[dict] = []
        self.flow_entries: List[dict] = []  # flat, later grouped by page/session
        self._seen_assets: set = set()

    # ---- scope ----
    def _in_scope(self, host: str) -> bool:
        h = (host or "").lower().split(":")[0]
        if not self.target:
            return True
        return h == self.target or h.endswith("." + self.target)

    # ---- HAR discovery ----
    def discover(self, explicit: List[str]) -> List[Path]:
        if explicit:
            return [Path(p) for p in explicit if Path(p).is_file()]
        cands: List[Path] = []
        for d in (self.scan_dir, self.scan_dir / "har_in", self.out_dir):
            if d.is_dir():
                cands.extend(sorted(d.glob("*.har")))
        # de-dup preserving order
        seen, out = set(), []
        for p in cands:
            rp = p.resolve()
            if rp not in seen:
                seen.add(rp)
                out.append(p)
        return out

    # ---- parse ----
    def ingest(self, har_path: Path) -> None:
        try:
            data = json.loads(har_path.read_text(errors="ignore"))
        except Exception as e:
            log(f"cannot parse {har_path.name}: {e}")
            self.stats.parse_errors += 1
            return
        entries = (data.get("log") or {}).get("entries") or []
        if not isinstance(entries, list):
            return
        self.stats.files += 1
        # Sort by startedDateTime so the sequence is real request order.
        def _ts(e):
            return e.get("startedDateTime") or ""
        for pos, entry in enumerate(sorted(entries, key=_ts)):
            try:
                self._entry(entry, har_path.name, pos)
            except Exception:
                self.stats.parse_errors += 1

    def _entry(self, entry: dict, src_file: str, pos: int) -> None:
        self.stats.entries += 1
        req = entry.get("request") or {}
        resp = entry.get("response") or {}
        url = req.get("url") or ""
        if not url:
            return
        try:
            parsed = urllib.parse.urlsplit(url)
        except Exception:
            return
        host = parsed.hostname or ""
        if not self._in_scope(host):
            return

        method = (req.get("method") or "GET").upper()
        scheme = (parsed.scheme or "http").lower()
        status = (resp.get("status") if isinstance(resp.get("status"), int) else 0)
        req_ct = _header(req.get("headers"), "content-type")
        resp_ct = _header(resp.get("headers"), "content-type")
        page_ref = entry.get("pageref") or src_file

        # Protocol classification — the WMS lesson: WSS was treated as HTTP.
        protocol = self._protocol(scheme, url, resp, req_ct, resp_ct, entry)

        # Auth tokens observed on THIS request (name-level, values redacted).
        auth_tokens = self._auth_tokens(req)

        # Identity-bearing values across url/query/headers/cookies/body.
        self._harvest_identifiers(url, parsed, req, resp, src_file)

        # WebSocket connections are first-class assets.
        ws_msgs = entry.get("_webSocketMessages")
        if protocol in ("ws", "wss") or ws_msgs:
            self._websocket(url, host, scheme, entry, auth_tokens, src_file)

        # Classify (reuse the shared engine so it matches the inventory).
        body_head = _body_head(resp)
        if classify_url is not None:
            try:
                cls = classify_url(url, status=status or None,
                                   content_type=resp_ct or req_ct,
                                   body=body_head, source="har",
                                   http_methods=[method])
            except Exception:
                cls = {}
        else:
            cls = {}

        akey = (method, _templ(url))
        if akey not in self._seen_assets:
            self._seen_assets.add(akey)
            self.assets.append({
                "url": url,
                "host": host,
                "method": method,
                "protocol": protocol,
                "status": status,
                "provenance": "har",
                "request_content_type": req_ct,
                "content_type": resp_ct,
                "auth_tokens_observed": auth_tokens,
                "has_request_body": bool((req.get("postData") or {}).get("text")),
                "url_class": cls.get("url_class", "unknown"),
                "api_type": cls.get("api_type"),
                "url_shape": cls.get("url_shape", "plain"),
                "auth_state": cls.get("auth_state", "unknown"),
                "sensitivity": cls.get("sensitivity", "normal"),
                "routed_to": cls.get("routed_to", []),
                "source_har": src_file,
            })
            self.stats.assets += 1

        # Flow sequence entry (kept per-request; grouped on write).
        produced = self._tokens_set_by_response(resp)
        required = self._tokens_used_by_request(req)
        self.flow_entries.append({
            "flow_group": page_ref,
            "seq": pos,
            "started": entry.get("startedDateTime") or "",
            "url": url,
            "host": host,
            "method": method,
            "protocol": protocol,
            "status": status,
            "provenance": "har",
            "requires": sorted(required),
            "produces": sorted(produced),
            "auth_state": cls.get("auth_state", "unknown"),
        })

    # ---- protocol ----
    @staticmethod
    def _protocol(scheme: str, url: str, resp: dict,
                  req_ct: str, resp_ct: str, entry: dict) -> str:
        if scheme in ("ws", "wss"):
            return scheme
        # A 101 upgrade or an Upgrade: websocket response header = WebSocket.
        if isinstance(resp.get("status"), int) and resp["status"] == 101:
            return "wss" if scheme == "https" else "ws"
        up = _header(resp.get("headers"), "upgrade")
        if "websocket" in (up or "").lower():
            return "wss" if scheme == "https" else "ws"
        if entry.get("_webSocketMessages"):
            return "wss" if scheme == "https" else "ws"
        if "text/event-stream" in (resp_ct or "").lower():
            return "sse"
        return scheme  # http | https

    # ---- auth / identity extraction ----
    @staticmethod
    def _auth_tokens(req: dict) -> List[str]:
        """NAMES of auth-bearing headers/cookies present (values NOT stored)."""
        out: List[str] = []
        for h in (req.get("headers") or []):
            name = (h.get("name") or "").lower()
            if name in _AUTH_HEADER_NAMES:
                out.append(f"header:{name}")
        for c in (req.get("cookies") or []):
            cn = (c.get("name") or "")
            if _ID_KEY_RE.search(cn) or "session" in cn.lower():
                out.append(f"cookie:{cn}")
        return sorted(set(out))

    def _harvest_identifiers(self, url: str, parsed, req: dict, resp: dict,
                             src_file: str) -> None:
        host = parsed.hostname or ""
        # path segments
        for seg in (parsed.path or "").split("/"):
            if seg and _looks_like_id_value(seg):
                self._add_id(seg, "path", url, host, src_file, name="path-seg")
        # query values
        for k, v in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True):
            t = _id_type_for(k, v)
            if t or _looks_like_id_value(v):
                self._add_id(v, "query", url, host, src_file, name=k, id_type=t)
        # request headers + cookies
        for h in (req.get("headers") or []):
            n, v = h.get("name", ""), h.get("value", "")
            if (n or "").lower() in _AUTH_HEADER_NAMES or _looks_like_id_value(v):
                self._add_id(v, "req-header", url, host, src_file, name=n)
        for c in (req.get("cookies") or []):
            n, v = c.get("name", ""), c.get("value", "")
            if _id_type_for(n, v) or _looks_like_id_value(v):
                self._add_id(v, "cookie", url, host, src_file, name=n)
        # response Set-Cookie — these are PRODUCED identifiers
        for c in (resp.get("cookies") or []):
            n, v = c.get("name", ""), c.get("value", "")
            if _id_type_for(n, v) or _looks_like_id_value(v):
                self._add_id(v, "set-cookie", url, host, src_file, name=n)

    def _add_id(self, value: str, location: str, url: str, host: str,
                src_file: str, name: str = "", id_type: Optional[str] = None) -> None:
        value = (value or "").strip()
        if not value or len(value) < 4:
            return
        it = id_type or _id_type_for(name, value) or "object_id"
        # Redact the raw value to a short fingerprint; keep length + head/tail so
        # the same value observed in two places can still be correlated without
        # storing the full secret.
        fp = _fingerprint(value)
        self.identifiers.append({
            "id_type": it,
            "name": name,
            "location": location,
            "value_fp": fp,
            "value_len": len(value),
            "host": host,
            "url": url,
            "provenance": "har",
            "source_har": src_file,
        })
        self.stats.identifiers += 1

    @staticmethod
    def _tokens_set_by_response(resp: dict) -> set:
        out = set()
        for c in (resp.get("cookies") or []):
            n = c.get("name", "")
            if n:
                out.add(f"cookie:{n}")
        loc = _header(resp.get("headers"), "location")
        if loc:
            out.add("redirect:location")
        return out

    @staticmethod
    def _tokens_used_by_request(req: dict) -> set:
        out = set()
        for c in (req.get("cookies") or []):
            n = c.get("name", "")
            if n:
                out.add(f"cookie:{n}")
        if _header(req.get("headers"), "authorization"):
            out.add("header:authorization")
        return out

    # ---- websocket asset ----
    def _websocket(self, url: str, host: str, scheme: str, entry: dict,
                   auth_tokens: List[str], src_file: str) -> None:
        msgs = entry.get("_webSocketMessages") or []
        sent = [m for m in msgs if (m.get("type") == "send")]
        recv = [m for m in msgs if (m.get("type") == "receive")]
        # Infer a rough message schema from the first legitimate frames (the
        # WSS agent learns from real traffic before mutating).
        schema = _infer_ws_schema(msgs)
        self.websockets.append({
            "url": url,
            "host": host,
            "protocol": "wss" if scheme in ("https", "wss") else "ws",
            "provenance": "har",
            "frames_sent": len(sent),
            "frames_received": len(recv),
            "auth_tokens_observed": auth_tokens,
            "sample_sent": [_frame_head(m) for m in sent[:3]],
            "sample_received": [_frame_head(m) for m in recv[:3]],
            "inferred_schema": schema,
            "source_har": src_file,
        })
        self.stats.websockets += 1

    # ---- write ----
    def write(self) -> Dict[str, int]:
        self.out_dir.mkdir(parents=True, exist_ok=True)
        # 1. plain URL list for the consolidator (dedup)
        urls = sorted({a["url"] for a in self.assets
                       if a["protocol"] in ("http", "https")})
        (self.out_dir / "har_urls.txt").write_text("\n".join(urls) + ("\n" if urls else ""))
        # 2. assets
        _write_jsonl(self.out_dir / "har_assets.jsonl", self.assets)
        # 3. websockets
        _write_jsonl(self.out_dir / "har_websockets.jsonl", self.websockets)
        # 4. identifiers
        _write_jsonl(self.out_dir / "har_identifiers.jsonl", self.identifiers)
        # 5. flow sequences (grouped by flow_group, seq-ordered)
        self.stats.flows = len({f["flow_group"] for f in self.flow_entries})
        self.flow_entries.sort(key=lambda f: (f["flow_group"], f["seq"]))
        _write_jsonl(self.out_dir / "flow_sequences.jsonl", self.flow_entries)
        # 6. summary
        summary = {
            "module": "har_ingest",
            "target": self.target,
            "har_files": self.stats.files,
            "entries": self.stats.entries,
            "assets": self.stats.assets,
            "websockets": self.stats.websockets,
            "identifiers": self.stats.identifiers,
            "flow_groups": self.stats.flows,
            "parse_errors": self.stats.parse_errors,
            "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }
        (self.out_dir / "har_ingest_summary.json").write_text(
            json.dumps(summary, indent=2))
        return summary


# --- helpers ---------------------------------------------------------------
def _header(headers, name: str) -> str:
    if not isinstance(headers, list):
        return ""
    name = name.lower()
    for h in headers:
        if (h.get("name") or "").lower() == name:
            return h.get("value") or ""
    return ""


def _body_head(resp: dict, cap: int = 2048) -> str:
    content = resp.get("content") or {}
    text = content.get("text") or ""
    if content.get("encoding") == "base64":
        return ""  # don't decode blobs; classification uses head text only
    return text[:cap]


def _frame_head(msg: dict, cap: int = 200) -> str:
    data = msg.get("data")
    if not isinstance(data, str):
        return ""
    return data[:cap]


def _infer_ws_schema(msgs: list) -> dict:
    """Best-effort: if frames are JSON, collect the union of top-level keys and
    the 'type'/'op' discriminator values — enough for the WSS agent to fuzz
    field types instead of blasting random bytes."""
    keys: set = set()
    disc: set = set()
    n = 0
    for m in msgs:
        data = m.get("data")
        if not isinstance(data, str):
            continue
        s = data.strip()
        if not s or s[0] not in "[{":
            continue
        try:
            obj = json.loads(s)
        except Exception:
            continue
        if isinstance(obj, dict):
            keys.update(obj.keys())
            for dk in ("type", "op", "event", "action", "cmd"):
                if dk in obj and isinstance(obj[dk], (str, int)):
                    disc.add(f"{dk}={obj[dk]}")
            n += 1
            if n >= 50:
                break
    return {"json": bool(keys), "keys": sorted(keys)[:40],
            "discriminators": sorted(disc)[:40]}


def _templ(url: str) -> str:
    """Cheap templating for asset-dedup (numeric/uuid/hex → placeholders)."""
    try:
        p = urllib.parse.urlsplit(url)
    except Exception:
        return url
    segs = []
    for s in (p.path or "").split("/"):
        if re.fullmatch(r"\d+", s):
            segs.append("{id}")
        elif _UUID_RE.match(s):
            segs.append("{uuid}")
        elif re.fullmatch(r"[0-9a-fA-F]{16,}", s):
            segs.append("{hash}")
        else:
            segs.append(s)
    qkeys = ",".join(sorted({k for k, _ in urllib.parse.parse_qsl(p.query)}))
    return f"{p.scheme}://{p.netloc}{'/'.join(segs)}?{qkeys}"


def _fingerprint(value: str) -> str:
    import hashlib
    h = hashlib.sha1(value.encode("utf-8", "ignore")).hexdigest()[:12]
    head = value[:4]
    tail = value[-4:] if len(value) > 8 else ""
    return f"{head}…{tail}#{h}"


def _write_jsonl(path: Path, rows: List[dict]) -> None:
    with path.open("w") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")


def main() -> int:
    ap = argparse.ArgumentParser(description="ARISE HAR / browser-trace ingestor")
    ap.add_argument("target")
    ap.add_argument("--scan-dir", required=True)
    ap.add_argument("--har", nargs="*", default=[],
                    help="explicit .har files; if omitted, auto-discovers *.har "
                         "under the scan dir and <scan-dir>/har_in/")
    args = ap.parse_args()

    scan_dir = Path(args.scan_dir)
    if not scan_dir.is_dir():
        log(f"scan-dir not found: {scan_dir}")
        return 1

    ing = HarIngestor(args.target, scan_dir)
    hars = ing.discover(args.har)
    if not hars:
        log("no HAR files found — nothing to ingest (drop *.har into "
            f"{scan_dir}/har_in/ or pass --har)")
        # still emit empty artefacts so downstream reads don't error
        ing.write()
        return 0
    log(f"ingesting {len(hars)} HAR file(s): {', '.join(h.name for h in hars)}")
    for h in hars:
        ing.ingest(h)
    summary = ing.write()
    log(f"done: {summary['assets']} assets, {summary['websockets']} websockets, "
        f"{summary['identifiers']} identifiers, {summary['flow_groups']} flows "
        f"-> {ing.out_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
