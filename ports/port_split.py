#!/usr/bin/env python3
"""Split all_ports.jsonl into web / non-web + origin / CDN streams.

Downstream consumers:
  web_ports.jsonl              -> httpx (all web ports, CDN + origin alike)
  nonweb_origin_ports.jsonl    -> nuclei non-web scan (origin only)
  nonweb_cdn_dropped.jsonl     -> audit log of dropped non-web CDN findings

Rule: CDN skip applies ONLY to non-web. Web ports on CDN are still valid
attack surface (they hit the actual application via the CDN edge).

Web/non-web classification: a static port-number guess (WEB_PORTS) is only
a fallback. The real, dynamic signal is Module 4's own httpx verification
(04_http_discovery/http_confirmed.json) — httpx already made an actual HTTP
request to every discovered port and knows for a fact whether it answered.
A web service on an unusual port outside WEB_PORTS would otherwise be
misclassified as non-web and routed into the wrong scan lane. Pass
--http-confirmed to use it; this module still works (port-number guess
only) if that file isn't available yet.
"""

import sys as _sys, os as _os
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)

import json
import os
import sys
import argparse

# Standard web ports treated as HTTP/HTTPS surface
WEB_PORTS = {
    80, 443, 8000, 8008, 8080, 8088, 8443, 8888, 8880, 8881,
    3000, 3001, 5000, 5001, 8081, 8082, 8083, 8084, 8085,
    9000, 9001, 9090, 4443, 7443, 10443
}


def _load_cdn_ips(cdn_ips_file: str) -> set:
    ips = set()
    if not os.path.exists(cdn_ips_file):
        return ips
    with open(cdn_ips_file, "r", errors="ignore") as f:
        for line in f:
            ip = line.strip()
            if ip:
                ips.add(ip)
    return ips


def _load_cdn_hosts(cdn_hosts_file: str) -> set:
    hosts = set()
    if not os.path.exists(cdn_hosts_file):
        return hosts
    with open(cdn_hosts_file, "r", errors="ignore") as f:
        for line in f:
            h = line.strip().lower()
            if h:
                hosts.add(h)
    return hosts


def _load_confirmed_web(http_confirmed_file: str) -> dict:
    """{(host, port): meta} for ports httpx actually confirmed serve HTTP —
    real, per-port verification, not a guess by port number. `meta` carries
    the ip / CDN hints needed to synthesize an all_ports row when naabu
    missed the port (CDN/WAF silently drop SYN probes). Never raises; a
    missing/malformed file just yields an empty dict (pure fallback to the
    static WEB_PORTS list). Membership tests (`(h, p) in confirmed_web`)
    still work because they hit the dict keys."""
    confirmed = {}
    if not http_confirmed_file or not os.path.exists(http_confirmed_file):
        return confirmed
    with open(http_confirmed_file, "r", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except Exception:
                continue
            if r.get("failed") is True:
                continue
            host = (r.get("host") or r.get("input") or "").lower()
            port = r.get("port")
            if not host or not port:
                continue
            try:
                port = int(port)
            except (TypeError, ValueError):
                continue
            key = (host, port)
            if key in confirmed:
                continue
            a = r.get("a") or []
            ip = r.get("host_ip") or (a[0] if a else "") or ""
            confirmed[key] = {
                "ip": ip,
                "cdn": bool(r.get("cdn", False)),
                "cdn_name": r.get("cdn_name") or r.get("cdn_type") or "",
            }
    return confirmed


def _load_existing_pairs(all_ports_file: str) -> set:
    """(host, port) pairs already present in all_ports.jsonl."""
    pairs = set()
    if not os.path.exists(all_ports_file):
        return pairs
    with open(all_ports_file, "r", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except Exception:
                continue
            host = (r.get("host") or "").lower()
            port = r.get("port")
            if not host or not port:
                continue
            try:
                pairs.add((host, int(port)))
            except (TypeError, ValueError):
                continue
    return pairs


def _inject_confirmed_web(all_ports_file: str, existing: set,
                          confirmed_web: dict, cdn_hosts: set,
                          cdn_ips: set) -> int:
    """Append any httpx-confirmed (host, port) that naabu missed to
    all_ports.jsonl, tagged source=httpx and CDN-classified like the rest.

    This is the backfill that used to live inside module_full_port_scan —
    but that module runs BEFORE http_discovery produces http_confirmed.json,
    so the file never existed when it fired. port_split runs after
    http_discovery, so here the file is real. Idempotent: `existing` is read
    fresh from all_ports.jsonl each run, so a port injected on a previous run
    is already present and skipped."""
    missing = [k for k in confirmed_web if k not in existing]
    if not missing:
        return 0
    added = 0
    with open(all_ports_file, "a") as out:
        for (host, port) in missing:
            meta = confirmed_web[(host, port)]
            ip = meta.get("ip") or ""
            is_cdn = bool(meta.get("cdn", False))
            if not is_cdn and (host in cdn_hosts or (ip and ip in cdn_ips)):
                is_cdn = True
            row = {
                "host": host,
                "ip": ip,
                "port": port,
                "protocol": "tcp",
                "source": "httpx",
                "is_cdn_ip": is_cdn,
                "scan_tag": "cdn" if is_cdn else "origin",
            }
            out.write(json.dumps(row) + "\n")
            existing.add((host, port))
            added += 1
    return added


def split(all_ports_file: str, cdn_ips_file: str, cdn_hosts_file: str,
          out_dir: str, http_confirmed_file: str = "") -> dict:
    if not os.path.exists(all_ports_file):
        return {"error": "all_ports.jsonl missing"}

    cdn_ips = _load_cdn_ips(cdn_ips_file)
    cdn_hosts = _load_cdn_hosts(cdn_hosts_file)
    confirmed_web = _load_confirmed_web(http_confirmed_file)

    # Backfill naabu's blind spots: CDN/WAF-fronted hosts drop SYN probes, so
    # naabu reports no open port even on 80/443 that httpx provably reached.
    # Inject those httpx-confirmed ports into all_ports.jsonl so the inventory,
    # dashboard and every downstream reader see the real web surface, not just
    # the ~12% naabu got through.
    existing_pairs = _load_existing_pairs(all_ports_file)
    httpx_backfilled = _inject_confirmed_web(
        all_ports_file, existing_pairs, confirmed_web, cdn_hosts, cdn_ips)

    os.makedirs(out_dir, exist_ok=True)
    web_file = os.path.join(out_dir, "web_ports.jsonl")
    nonweb_origin_file = os.path.join(out_dir, "nonweb_origin_ports.jsonl")
    dropped_file = os.path.join(out_dir, "nonweb_cdn_dropped.jsonl")

    web_count = nonweb_origin_count = dropped_count = 0

    with open(web_file, "w") as web_out, \
         open(nonweb_origin_file, "w") as origin_out, \
         open(dropped_file, "w") as dropped_out, \
         open(all_ports_file, "r", errors="ignore") as src:
        for line in src:
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except Exception:
                continue
            host = (r.get("host") or "").lower()
            ip = r.get("ip") or ""
            port = r.get("port")
            if not host or not port:
                continue
            port = int(port)

            # CDN check — prefer explicit is_cdn_ip if already tagged,
            # else check cdn_hosts and cdn_ips lists.
            is_cdn = bool(r.get("is_cdn_ip", False))
            if not is_cdn:
                if host in cdn_hosts or (ip and ip in cdn_ips):
                    is_cdn = True

            # Real httpx verification wins when available; the static
            # port-number list is only a fallback for ports httpx hasn't
            # (yet) confirmed either way.
            is_web = port in WEB_PORTS or (host, port) in confirmed_web
            r["is_cdn_ip"] = is_cdn
            r["is_web"] = is_web

            if is_web:
                # Web ports: always kept, CDN or origin
                web_out.write(json.dumps(r) + "\n")
                web_count += 1
            else:
                # Non-web ports: origin only
                if is_cdn:
                    r["drop_reason"] = "non-web port on CDN edge"
                    dropped_out.write(json.dumps(r) + "\n")
                    dropped_count += 1
                else:
                    origin_out.write(json.dumps(r) + "\n")
                    nonweb_origin_count += 1

    return {
        "web_ports": web_count,
        "nonweb_origin_ports": nonweb_origin_count,
        "nonweb_cdn_dropped": dropped_count,
        "httpx_backfilled": httpx_backfilled,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--all-ports", required=True)
    ap.add_argument("--cdn-ips", default="")
    ap.add_argument("--cdn-hosts", default="")
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--http-confirmed", default="",
                    help="04_http_discovery/http_confirmed.json — real "
                         "per-port httpx verification, used as the "
                         "authoritative web/non-web signal when present")
    args = ap.parse_args()

    summary = split(args.all_ports, args.cdn_ips, args.cdn_hosts, args.out_dir,
                    http_confirmed_file=args.http_confirmed)
    print(json.dumps(summary), file=sys.stderr)


if __name__ == "__main__":
    main()
