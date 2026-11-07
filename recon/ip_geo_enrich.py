#!/usr/bin/env python3
"""IP geolocation + ASN enrichment via IPInfo.

Reads all_ips.txt (from dns_resolution) and dns_results.json (host->IP map).
Emits ip_geo.jsonl for the attack surface map: each entry pins one IP with
its geo/ASN/org and the list of resolved hostnames.

Fails soft: no IPINFO_TOKEN → skip silently, no IPInfo response → best-effort.
"""

import sys as _sys, os as _os
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)

import json
import os
import sys
import time
import argparse
import ipaddress
from pathlib import Path
from urllib import request, error, parse
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.net import verified_ssl_context

IPINFO_URL = "https://ipinfo.io/{ip}/json"
TIMEOUT = 6
WORKERS = 10


def _load_host_ip_map(dns_results_json: str) -> dict:
    """Build ip -> [hostnames] map from dnsx JSONL output."""
    m = {}
    if not os.path.exists(dns_results_json):
        return m
    with open(dns_results_json, "r", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except Exception:
                continue
            host = r.get("host") or ""
            for ip in (r.get("a") or []):
                m.setdefault(ip, [])
                if host and host not in m[ip]:
                    m[ip].append(host)
    return m


def _ip_category(ip: str):
    """Human note for a non-public IP (so the asset table can say WHY there is no
    geolocation), or None when the IP is public and should be geolocated."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "Invalid IP address"
    if addr.is_loopback or addr.is_link_local or addr.is_private:
        return "Private IP / Internal IP"
    if addr.is_reserved or addr.is_multicast or addr.is_unspecified:
        return "Reserved / non-routable IP"
    return None


def _fetch_ipinfo(ip: str, token: str) -> dict:
    # Private / reserved / internal IPs are not geolocatable — label them plainly
    # instead of sending a doomed request that returns a blank row.
    cat = _ip_category(ip)
    if cat:
        status = "private" if cat.startswith("Private") else (
                 "invalid" if cat.startswith("Invalid") else "non_routable")
        return {"ip": ip, "lat": None, "lon": None, "geo_status": status, "geo_note": cat}
    try:
        url = IPINFO_URL.format(ip=ip)
        if token:
            url += "?token=" + parse.quote(token)
        req = request.Request(url, headers={"Accept": "application/json"})
        with request.urlopen(req, timeout=TIMEOUT, context=verified_ssl_context()) as resp:
            data = json.loads(resp.read().decode("utf-8", "ignore"))
        # IPInfo flags non-routable space it was asked about.
        if data.get("bogon"):
            return {"ip": ip, "lat": None, "lon": None,
                    "geo_status": "private", "geo_note": "Private IP / Internal IP"}
        loc = (data.get("loc") or "").split(",") if data.get("loc") else []
        lat = float(loc[0]) if len(loc) == 2 else None
        lon = float(loc[1]) if len(loc) == 2 else None
        org = data.get("org") or ""
        asn = ""
        org_name = org
        if org.startswith("AS"):
            parts = org.split(" ", 1)
            asn = parts[0]
            org_name = parts[1] if len(parts) > 1 else ""
        rec = {
            "ip": ip,
            "country": data.get("country") or "",
            "city": data.get("city") or "",
            "region": data.get("region") or "",
            "lat": lat,
            "lon": lon,
            "asn": asn,
            "org": org_name,
            "hostname": data.get("hostname") or "",
        }
        if lat is None and not (rec["country"] or rec["city"]):
            rec["geo_status"] = "no_data"
            rec["geo_note"] = "No geolocation data from IPInfo"
        else:
            rec["geo_status"] = "ok"
        return rec
    except error.HTTPError as e:
        if e.code == 429:
            note, st = "IPInfo rate limit reached — set IPINFO_TOKEN for higher quota", "rate_limited"
        elif e.code in (401, 403):
            note, st = "IPInfo token rejected — check IPINFO_TOKEN", "auth_error"
        else:
            note, st = f"IPInfo error HTTP {e.code}", "http_error"
        return {"ip": ip, "lat": None, "lon": None, "geo_status": st, "geo_note": note}
    except Exception as e:  # network / timeout / parse
        return {"ip": ip, "lat": None, "lon": None,
                "geo_status": "error", "geo_note": "Geo lookup failed: " + str(e)[:80]}


def enrich(all_ips_file: str, dns_results_json: str, out_file: str,
           token: str = "") -> dict:
    if not os.path.exists(all_ips_file):
        return {"total": 0, "enriched": 0, "reason": "no all_ips.txt"}

    ips = []
    with open(all_ips_file, "r", errors="ignore") as f:
        for line in f:
            ip = line.strip()
            if ip and "." in ip:
                ips.append(ip)
    ips = sorted(set(ips))
    if not ips:
        return {"total": 0, "enriched": 0, "reason": "no ips"}

    host_map = _load_host_ip_map(dns_results_json)
    enriched = 0
    os.makedirs(os.path.dirname(out_file) or ".", exist_ok=True)
    with open(out_file, "w") as out:
        with ThreadPoolExecutor(max_workers=WORKERS) as ex:
            futs = {ex.submit(_fetch_ipinfo, ip, token): ip for ip in ips}
            for fut in as_completed(futs):
                ip = futs[fut]
                info = fut.result() or {"ip": ip}
                info["hosts"] = host_map.get(ip, [])
                if info.get("lat") is not None:
                    enriched += 1
                out.write(json.dumps(info) + "\n")
    return {"total": len(ips), "enriched": enriched}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--all-ips", required=True, help="Path to all_ips.txt")
    ap.add_argument("--dns-results", required=True,
                    help="Path to dnsx JSONL output")
    ap.add_argument("--output", required=True, help="Path to ip_geo.jsonl")
    ap.add_argument("--token", default=os.environ.get("IPINFO_TOKEN", ""),
                    help="IPInfo API token (env IPINFO_TOKEN)")
    args = ap.parse_args()

    if not args.token:
        # Free tier still works but rate-limited to ~50k/mo — proceed.
        print("[ip_geo_enrich] no IPINFO_TOKEN — using free-tier requests",
              file=sys.stderr)

    summary = enrich(args.all_ips, args.dns_results, args.output, args.token)
    print(json.dumps(summary), file=sys.stderr)


if __name__ == "__main__":
    main()
