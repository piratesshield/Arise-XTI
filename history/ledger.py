#!/usr/bin/env python3
"""
ARISE Asset Ledger — durable, per-target attack-surface archive
===============================================================
The ledger is the accumulated source-of-truth that persists ACROSS scans, so a
huge site (the Flipkart lesson) is discovered in full once and thereafter only
its *delta* is chased. Where `scans/<target>-<ts>/` is an immutable point-in-time
snapshot, the ledger is the running, upserted view of everything ever seen.

Lives at `state/<target>/ledger/` as one JSONL file per asset store:

    subdomains.jsonl   key = host
    endpoints.jsonl    key = "<METHOD> <url>"
    apis.jsonl         key = "<METHOD> <host><path>"
    services.jsonl     key = "<host>:<port>"
    secrets.jsonl      key = fingerprint

Every record carries the lifecycle fields the incremental engine and the
Historic Asset dashboard rely on:

    first_seen      ISO ts — set once, never moved (when the asset first appeared)
    last_seen       ISO ts — bumped every scan the asset is re-observed
    last_scan_id    the scan that last observed it
    status          "alive" | "dead" | "unknown"
    seen_count      how many scans have observed it

Design guarantees:
  * Upsert is idempotent — re-seeing an asset never duplicates it and never
    moves first_seen; it only bumps last_seen / seen_count / mutable fields.
  * Atomic writes — each store is written to a .tmp then os.replace()'d, with a
    .bak kept, so a crash mid-write can never corrupt the archive.
  * Fail-safe — a malformed line is skipped, not fatal; the API never raises to
    the caller for I/O or parse errors (returns best-effort).
  * No third-party deps — stdlib only, so it runs anywhere the pipeline does.

`now`/`scan_id` are injected on every mutating call, so the whole thing is
unit-testable offline with deterministic timestamps (see the __main__ self-test).
"""

from __future__ import annotations

import sys as _sys, os as _os
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)


import json
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Set, Tuple

STATUS_ALIVE = "alive"
STATUS_DEAD = "dead"
STATUS_UNKNOWN = "unknown"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _norm_host(h: str) -> str:
    h = (h or "").strip().lower()
    h = re.sub(r"^\w+://", "", h)          # strip scheme if a URL slipped in
    h = h.split("/")[0].split("@")[-1]      # strip path / userinfo
    return h.strip(".")


# ---------------------------------------------------------------------------
# Store definitions — each maps records to a stable natural key + mutable fields
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Store:
    name: str
    key_fn: Callable[[dict], Optional[str]]
    # fields that may be refreshed on re-observation (everything else is frozen
    # after first insert, except the lifecycle fields the ledger owns)
    mutable: Tuple[str, ...] = ()


def _sub_key(r: dict) -> Optional[str]:
    h = _norm_host(r.get("host", ""))
    return h or None


def _endpoint_key(r: dict) -> Optional[str]:
    url = (r.get("url", "") or "").strip()
    if not url:
        return None
    method = (r.get("method", "GET") or "GET").upper()
    return f"{method} {url}"


def _api_key(r: dict) -> Optional[str]:
    url = (r.get("url", "") or "").strip()
    if not url:
        return None
    method = (r.get("method", "GET") or "GET").upper()
    # normalise numeric/uuid path ids so /users/1 and /users/2 collapse to one API
    norm = re.sub(r"/(?:\d+|[0-9a-fA-F]{8,}|[0-9a-fA-F-]{36})(?=/|$)", "/{id}", url)
    return f"{method} {norm}"


def _service_key(r: dict) -> Optional[str]:
    host = _norm_host(r.get("host", ""))
    port = str(r.get("port", "")).strip()
    if not host or not port:
        return None
    return f"{host}:{port}"


def _secret_key(r: dict) -> Optional[str]:
    fp = (r.get("fingerprint") or r.get("redacted") or "").strip()
    if fp:
        return fp
    # fall back to detector + source so distinct secrets don't collide
    det = (r.get("detector") or r.get("provider") or "secret").strip()
    src = (r.get("source_file") or r.get("url") or "").strip()
    return f"{det}|{src}" if src else None


STORES: Dict[str, Store] = {
    "subdomains": Store("subdomains", _sub_key,
                        mutable=("status", "http_status", "ip", "cname", "source")),
    "endpoints": Store("endpoints", _endpoint_key,
                       mutable=("http_status", "content_type", "is_api", "title", "length")),
    "apis": Store("apis", _api_key,
                  mutable=("methods", "auth_required", "spec_ref", "content_type", "status")),
    "services": Store("services", _service_key,
                      mutable=("service", "banner", "tech", "status")),
    "secrets": Store("secrets", _secret_key,
                     mutable=("state", "severity", "validation_state", "identity")),
}


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------

@dataclass
class UpsertResult:
    store: str
    new: int = 0
    updated: int = 0
    skipped: int = 0
    new_keys: List[str] = None  # type: ignore

    def __post_init__(self):
        if self.new_keys is None:
            self.new_keys = []

    def to_dict(self) -> dict:
        return {"store": self.store, "new": self.new, "updated": self.updated,
                "skipped": self.skipped, "new_keys": self.new_keys}


class Ledger:
    def __init__(self, target: str, root: str = "state"):
        self.target = target
        self.dir = Path(root) / target / "ledger"

    # -- low-level IO (atomic, fail-safe) ----------------------------------

    def _path(self, store: str) -> Path:
        return self.dir / f"{store}.jsonl"

    def _load_raw(self, store: str) -> "Dict[str, dict]":
        """Load a store as {key: record}. Malformed lines are skipped."""
        out: Dict[str, dict] = {}
        p = self._path(store)
        if not p.exists():
            return out
        sdef = STORES[store]
        try:
            with open(p, "r", errors="ignore") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except Exception:
                        continue
                    if not isinstance(rec, dict):
                        continue
                    k = rec.get("_key") or sdef.key_fn(rec)
                    if k:
                        out[k] = rec
        except OSError:
            pass
        return out

    def _write_raw(self, store: str, records: "Dict[str, dict]") -> bool:
        """Atomically rewrite a store. Keeps a .bak of the prior version."""
        try:
            self.dir.mkdir(parents=True, exist_ok=True)
        except OSError:
            return False
        p = self._path(store)
        tmp = p.with_suffix(".jsonl.tmp")
        try:
            with open(tmp, "w") as fh:
                for k in sorted(records.keys()):
                    rec = dict(records[k])
                    rec["_key"] = k
                    fh.write(json.dumps(rec, default=str) + "\n")
            if p.exists():
                try:
                    os.replace(p, p.with_suffix(".jsonl.bak"))
                except OSError:
                    pass
            os.replace(tmp, p)
            return True
        except OSError:
            try:
                if tmp.exists():
                    tmp.unlink()
            except OSError:
                pass
            return False

    # -- public API --------------------------------------------------------

    def keys(self, store: str) -> Set[str]:
        return set(self._load_raw(store).keys())

    def all(self, store: str) -> List[dict]:
        return list(self._load_raw(store).values())

    def get(self, store: str, key: str) -> Optional[dict]:
        return self._load_raw(store).get(key)

    def upsert(self, store: str, records: Iterable[dict], scan_id: str,
               now: Optional[str] = None) -> UpsertResult:
        """Insert new records / refresh existing ones. first_seen is set once and
        never moved; last_seen, last_scan_id, seen_count and the store's mutable
        fields are updated on every re-observation. Idempotent."""
        if store not in STORES:
            raise KeyError(f"unknown store '{store}'")
        now = now or _now_iso()
        sdef = STORES[store]
        existing = self._load_raw(store)
        res = UpsertResult(store=store)

        for rec in records:
            if not isinstance(rec, dict):
                res.skipped += 1
                continue
            key = rec.get("_key") or sdef.key_fn(rec)
            if not key:
                res.skipped += 1
                continue
            if key in existing:
                cur = existing[key]
                cur["last_seen"] = now
                cur["last_scan_id"] = scan_id
                cur["seen_count"] = int(cur.get("seen_count", 1)) + 1
                for f in sdef.mutable:
                    if f in rec and rec[f] not in (None, "", []):
                        cur[f] = rec[f]
                res.updated += 1
            else:
                new_rec = dict(rec)
                new_rec["_key"] = key
                new_rec["first_seen"] = now
                new_rec["last_seen"] = now
                new_rec["first_scan_id"] = scan_id
                new_rec["last_scan_id"] = scan_id
                new_rec["seen_count"] = 1
                new_rec.setdefault("status", STATUS_ALIVE)
                existing[key] = new_rec
                res.new += 1
                res.new_keys.append(key)

        self._write_raw(store, existing)
        return res

    def diff(self, store: str, incoming_keys: Iterable[str]) -> Dict[str, Set[str]]:
        """Compare a set of incoming keys against the ledger.
        Returns {"new", "existing", "disappeared"} sets of keys."""
        have = self.keys(store)
        incoming = set(incoming_keys)
        return {
            "new": incoming - have,
            "existing": incoming & have,
            "disappeared": have - incoming,
        }

    def diff_records(self, store: str, records: Iterable[dict]) -> Dict[str, Set[str]]:
        sdef = STORES[store]
        keys = {k for k in (sdef.key_fn(r) for r in records if isinstance(r, dict)) if k}
        return self.diff(store, keys)

    def mark_liveness(self, store: str, alive_keys: Iterable[str], scan_id: str,
                      now: Optional[str] = None, mark_missing_dead: bool = True
                      ) -> Dict[str, int]:
        """Set status=alive for alive_keys (bumping last_seen); optionally mark
        every other record dead. Used by the incremental liveness refresh, which
        confirms known assets are still up without re-enumerating them."""
        now = now or _now_iso()
        existing = self._load_raw(store)
        alive = set(alive_keys)
        counts = {"alive": 0, "dead": 0}
        for k, rec in existing.items():
            if k in alive:
                rec["status"] = STATUS_ALIVE
                rec["last_seen"] = now
                rec["last_scan_id"] = scan_id
                counts["alive"] += 1
            elif mark_missing_dead and rec.get("status") != STATUS_DEAD:
                rec["status"] = STATUS_DEAD
                rec["dead_since"] = rec.get("dead_since") or now
                counts["dead"] += 1
        self._write_raw(store, existing)
        return counts

    def summary(self) -> dict:
        out = {"target": self.target, "stores": {}}
        for name in STORES:
            recs = self.all(name)
            out["stores"][name] = {
                "total": len(recs),
                "alive": sum(1 for r in recs if r.get("status") == STATUS_ALIVE),
                "dead": sum(1 for r in recs if r.get("status") == STATUS_DEAD),
            }
        return out


# ---------------------------------------------------------------------------
# Convenience loaders — turn raw pipeline outputs into ledger records
# ---------------------------------------------------------------------------

def subdomains_from_lines(lines: Iterable[str]) -> List[dict]:
    out = []
    for ln in lines:
        h = _norm_host(ln)
        if h and "." in h:
            out.append({"host": h, "source": "enum"})
    return out


def endpoints_from_urls(urls: Iterable[str], method: str = "GET") -> List[dict]:
    out = []
    for u in urls:
        u = (u or "").strip().split()[0] if u and u.strip() else ""
        if u.startswith("http"):
            out.append({"url": u, "method": method})
    return out


# ---------------------------------------------------------------------------
# Offline self-test — proves idempotency, first_seen stability, diff, liveness
# ---------------------------------------------------------------------------

def _selftest():
    import shutil
    import tempfile

    print("=== ledger self-test (offline, deterministic) ===\n")
    tmp = tempfile.mkdtemp(prefix="arise_ledger_")
    try:
        lg = Ledger("example.com", root=tmp)

        # -- [1] first insert sets first_seen == last_seen ------------------
        r = lg.upsert("subdomains",
                      subdomains_from_lines(["a.example.com", "b.example.com"]),
                      scan_id="scan1", now="2026-01-01T00:00:00+00:00")
        assert r.new == 2 and r.updated == 0, r.to_dict()
        rec_a = lg.get("subdomains", "a.example.com")
        assert rec_a["first_seen"] == rec_a["last_seen"] == "2026-01-01T00:00:00+00:00"
        assert rec_a["seen_count"] == 1
        print("[1] first insert: 2 new, first_seen==last_seen, seen_count=1  ✓")

        # -- [2] re-observe: idempotent, first_seen frozen, last_seen bumped -
        r = lg.upsert("subdomains",
                      subdomains_from_lines(["a.example.com", "b.example.com", "c.example.com"]),
                      scan_id="scan2", now="2026-01-08T00:00:00+00:00")
        assert r.new == 1 and r.updated == 2, r.to_dict()
        assert lg.keys("subdomains") == {"a.example.com", "b.example.com", "c.example.com"}
        rec_a = lg.get("subdomains", "a.example.com")
        assert rec_a["first_seen"] == "2026-01-01T00:00:00+00:00", "first_seen must not move"
        assert rec_a["last_seen"] == "2026-01-08T00:00:00+00:00", "last_seen must bump"
        assert rec_a["seen_count"] == 2
        print("[2] re-observe: no dup, first_seen frozen, last_seen+seen_count bumped  ✓")

        # -- [3] diff: new vs existing vs disappeared -----------------------
        d = lg.diff("subdomains", ["a.example.com", "z.example.com"])
        assert d["new"] == {"z.example.com"}
        assert d["existing"] == {"a.example.com"}
        assert d["disappeared"] == {"b.example.com", "c.example.com"}
        print("[3] diff: correctly splits new / existing / disappeared  ✓")

        # -- [4] mutable field refresh, immutable identity preserved --------
        lg.upsert("subdomains", [{"host": "a.example.com", "http_status": 200, "ip": "1.2.3.4"}],
                  scan_id="scan3", now="2026-01-09T00:00:00+00:00")
        rec_a = lg.get("subdomains", "a.example.com")
        assert rec_a["http_status"] == 200 and rec_a["ip"] == "1.2.3.4"
        assert rec_a["first_seen"] == "2026-01-01T00:00:00+00:00"
        print("[4] mutable fields (http_status/ip) refreshed; first_seen intact  ✓")

        # -- [5] API key normalises numeric/uuid path ids -------------------
        lg.upsert("apis", [
            {"url": "https://api.example.com/users/1", "method": "GET"},
            {"url": "https://api.example.com/users/2", "method": "GET"},
            {"url": "https://api.example.com/users/99999", "method": "GET"},
        ], scan_id="scan1", now="2026-01-01T00:00:00+00:00")
        assert len(lg.all("apis")) == 1, "numeric path ids must collapse to one API"
        print("[5] api key: /users/{id} collapses 3 numeric variants to 1  ✓")

        # -- [6] liveness: alive bumped, missing marked dead ----------------
        lg.upsert("endpoints", endpoints_from_urls([
            "https://example.com/a", "https://example.com/b"]),
            scan_id="scan1", now="2026-01-01T00:00:00+00:00")
        counts = lg.mark_liveness("endpoints", ["GET https://example.com/a"],
                                  scan_id="scan9", now="2026-02-01T00:00:00+00:00")
        assert counts == {"alive": 1, "dead": 1}, counts
        assert lg.get("endpoints", "GET https://example.com/b")["status"] == "dead"
        assert lg.get("endpoints", "GET https://example.com/a")["status"] == "alive"
        print("[6] liveness: alive bumped, missing endpoint marked dead  ✓")

        # -- [7] persistence + atomic .bak ----------------------------------
        lg2 = Ledger("example.com", root=tmp)  # fresh handle, same files
        assert lg2.keys("subdomains") == {"a.example.com", "b.example.com", "c.example.com"}
        assert (lg2._path("subdomains").with_suffix(".jsonl.bak")).exists()
        print("[7] persistence: reloaded from disk; .bak kept on rewrite  ✓")

        # -- [8] malformed line is skipped, not fatal -----------------------
        with open(lg._path("subdomains"), "a") as fh:
            fh.write("this-is-not-json\n")
        assert "a.example.com" in lg.keys("subdomains")  # still loads the rest
        print("[8] malformed line skipped, load stays fail-safe  ✓")

        # -- [9] summary ----------------------------------------------------
        s = lg.summary()
        assert s["stores"]["subdomains"]["total"] == 3
        assert s["stores"]["endpoints"]["dead"] == 1
        print("[9] summary: per-store totals + alive/dead counts  ✓")

        print("\nLedger foundation proven: idempotent upsert, stable first_seen,\n"
              "diff, liveness, atomic persistence, fail-safe load. ✓")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ---------------------------------------------------------------------------
# Scan ingestion — read a completed ARISE scan dir and upsert into the ledger
# ---------------------------------------------------------------------------

def _read_lines(path: Path, cap: Optional[int] = None) -> List[str]:
    """Read non-empty lines, stopping after `cap` lines. The cap matters: an
    all_urls.txt from a huge crawl can be many GB (the Flipkart case) — we must
    never slurp the whole file into the durable ledger."""
    out: List[str] = []
    try:
        with open(path, "r", errors="ignore") as fh:
            for i, line in enumerate(fh):
                if cap is not None and i >= cap:
                    break
                line = line.strip()
                if line:
                    out.append(line)
    except OSError:
        pass
    return out


def _http_status_map(path: Path) -> Dict[str, int]:
    """host -> status_code from httpx's http_confirmed.json (JSONL)."""
    out: Dict[str, int] = {}
    try:
        with open(path, "r", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                except Exception:
                    continue
                host = _norm_host(e.get("host") or e.get("input") or e.get("url") or "")
                sc = e.get("status_code") or e.get("status-code")
                if host and isinstance(sc, int):
                    out[host] = sc
    except OSError:
        pass
    return out


def _read_jsonl_field(path: Path, cap: Optional[int] = None) -> List[dict]:
    out: List[dict] = []
    try:
        with open(path, "r", errors="ignore") as fh:
            for i, line in enumerate(fh):
                if cap is not None and i >= cap:
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                    if isinstance(e, dict):
                        out.append(e)
                except Exception:
                    continue
    except OSError:
        pass
    return out


def ingest_scan(target: str, scan_dir: str, scan_id: str, root: str = "state",
                max_endpoints: int = 50000, now: Optional[str] = None) -> dict:
    """Read a completed ARISE scan directory and upsert its discovered assets
    into the durable ledger. Best-effort: every source is optional. Returns a
    per-store report. Never raises."""
    lg = Ledger(target, root=root)
    sd = Path(scan_dir)
    report: Dict[str, dict] = {}

    # -- subdomains (+ http status) ----------------------------------------
    subs = subdomains_from_lines(_read_lines(sd / "02_subdomain_enum" / "all_subdomains.txt"))
    if subs:
        status_map = _http_status_map(sd / "04_http_discovery" / "http_confirmed.json")
        for r in subs:
            sc = status_map.get(r["host"])
            if sc:
                r["http_status"] = sc
                r["status"] = STATUS_ALIVE
        report["subdomains"] = lg.upsert("subdomains", subs, scan_id, now).to_dict()

    # -- JS-referenced same-org hosts (Module 10.2) -------------------------
    # Passive candidates extracted from staged JS bundle content — not yet
    # scanned, so no http_status/liveness to attach. Tagged with a distinct
    # source so they're visibly different from active subdomain enum in the
    # dashboard/ledger, but flow through the exact same store + diff path
    # (new_targets.json) so they surface as scan candidates automatically.
    js_hosts: List[dict] = []
    for e in _read_jsonl_field(sd / "10.2_js_endpoints" / "js_referenced_hosts.jsonl"):
        h = _norm_host(e.get("host", ""))
        if h:
            js_hosts.append({
                "host": h, "source": "js-endpoint-extract",
                "referenced_in": e.get("referenced_in", ""),
                "occurrences": e.get("occurrences", 0),
            })
    if js_hosts:
        report["js_referenced_hosts"] = lg.upsert(
            "subdomains", js_hosts, scan_id, now).to_dict()

    # -- endpoints (bounded across the interesting corpora) ----------------
    ep_urls: List[str] = []
    for rel in ("04_http_discovery/http_urls.txt",
                "08_directory_discovery/all_paths.txt",
                "09_crawling/js_urls.txt",
                "09_crawling/all_urls.txt"):          # potentially huge -> last, capped
        remaining = max_endpoints - len(ep_urls)
        if remaining <= 0:
            break
        ep_urls.extend(_read_lines(sd / rel, cap=remaining))
    ep_recs = endpoints_from_urls(ep_urls)[:max_endpoints]
    if ep_recs:
        report["endpoints"] = lg.upsert("endpoints", ep_recs, scan_id, now).to_dict()

    # -- APIs (with methods when present) ----------------------------------
    api_recs: List[dict] = []
    for e in _read_jsonl_field(sd / "20_api_deep_discovery" / "api_endpoints.jsonl"):
        url = e.get("url") or ""
        if not str(url).startswith("http"):
            continue
        rec = {"url": url, "method": (e.get("method") or "GET")}
        if e.get("methods"):
            rec["methods"] = e["methods"]
        if "auth_required" in e:
            rec["auth_required"] = e["auth_required"]
        api_recs.append(rec)
    if api_recs:
        report["apis"] = lg.upsert("apis", api_recs, scan_id, now).to_dict()

    # -- secrets (prefer validated) ----------------------------------------
    sec_path = sd / "10_secret_scanning" / "secrets_validated.jsonl"
    validated = sec_path.exists()
    if not validated:
        sec_path = sd / "10_secret_scanning" / "secrets.jsonl"
    sec_recs: List[dict] = []
    for e in _read_jsonl_field(sec_path):
        if validated:
            sec_recs.append({
                "detector": e.get("detector", "secret"),
                "redacted": e.get("redacted", ""),
                "fingerprint": e.get("redacted") or e.get("detector"),
                "validation_state": e.get("state", ""),
                "severity": e.get("severity", ""),
                "source_file": e.get("source_file", ""),
            })
        else:
            sec_recs.append({
                "detector": e.get("DetectorName", "secret"),
                "redacted": e.get("Redacted", ""),
                "fingerprint": e.get("Redacted") or e.get("DetectorName"),
                "source_file": (e.get("SourceMetadata", {}).get("Data", {})
                                .get("Filesystem", {}).get("file", "")),
            })
    if sec_recs:
        report["secrets"] = lg.upsert("secrets", sec_recs, scan_id, now).to_dict()

    return report


def _cli_ingest(args) -> int:
    report = ingest_scan(args.target, args.scan_dir, args.scan_id,
                         root=args.root, max_endpoints=args.max_endpoints)
    if not report:
        print(f"[ledger] {args.target}: nothing ingested (no discovery outputs found)")
        return 0
    parts = [f"{s}: +{r['new']} new / {r['updated']} seen" for s, r in report.items()]
    print(f"[ledger] {args.target} <- scan {args.scan_id}: " + "; ".join(parts))
    return 0


def _cli_stats(args) -> int:
    lg = Ledger(args.target, root=args.root)
    s = lg.summary()
    print(f"Asset ledger for {args.target}")
    print("-" * 46)
    any_data = False
    for name, st in s["stores"].items():
        if st["total"]:
            any_data = True
            print(f"  {name:12} {st['total']:6}  (alive {st['alive']}, dead {st['dead']})")
    if not any_data:
        print("  (empty — no scans ingested yet)")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    import argparse
    ap = argparse.ArgumentParser(description="ARISE Asset Ledger")
    sub = ap.add_subparsers(dest="cmd")

    pi = sub.add_parser("ingest", help="ingest a completed scan dir into the ledger")
    pi.add_argument("--target", required=True)
    pi.add_argument("--scan-dir", required=True)
    pi.add_argument("--scan-id", required=True)
    pi.add_argument("--root", default="state")
    pi.add_argument("--max-endpoints", type=int, default=50000)
    pi.set_defaults(fn=_cli_ingest)

    ps = sub.add_parser("stats", help="show the ledger summary for a target")
    ps.add_argument("--target", required=True)
    ps.add_argument("--root", default="state")
    ps.set_defaults(fn=_cli_stats)

    sub.add_parser("selftest", help="run the offline self-test")

    args = ap.parse_args(argv)
    if args.cmd in (None, "selftest"):
        _selftest()
        return 0
    return args.fn(args)


if __name__ == "__main__":
    import sys
    sys.exit(main())
