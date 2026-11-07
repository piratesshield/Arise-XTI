#!/usr/bin/env python3
"""Reconcile OSINT-discovered ports with naabu port-scan results.

For each OSINT port not already in all_ports.jsonl, run a single-port naabu
alive check. If alive, append to all_ports.jsonl with source: osint_validated.

OSINT ports come from Shodan/Censys/OSINT modules (osint_findings.jsonl,
shodan_correlation.jsonl, internet_intel data).
"""

import sys as _sys, os as _os
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)

import json
import os
import sys
import argparse
import subprocess
from pathlib import Path


def _load_naabu_ports(all_ports_file: str) -> set:
    seen = set()
    if not os.path.exists(all_ports_file):
        return seen
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
            if host and port:
                seen.add((host, int(port)))
    return seen


def _load_osint_ports(osint_files: list) -> set:
    """Extract (host_or_ip, port) tuples from OSINT/shodan/censys jsonl files.

    Each producer has its own shape — this was originally written against a
    generic {host|hostname|target, ports|port} guess that matches NEITHER of
    the two files it's actually pointed at, so it silently found nothing from
    either source regardless of the naabu-diff logic below being correct:
      - intel/osint_intel.py's osint_findings.jsonl: identity is `subject`
        (an IP for the Shodan-InternetDB category), ports live nested under
        `meta.ports`.
      - intel/shodan_correlation.py's shodan_assets.jsonl: identity is `ip`
        + `hostnames` (a list, not `hostname`), and the port lists are
        `shodan_only_ports` (ports Shodan saw that ARISE's own scan didn't —
        the actual enrichment value), `confirmed_ports`, or `shodan_ports`.
    """
    seen = set()
    for path in osint_files:
        if not os.path.exists(path):
            continue
        with open(path, "r", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    r = json.loads(line)
                except Exception:
                    continue

                identities = set()
                for key in ("host", "hostname", "target", "ip", "subject"):
                    v = r.get(key)
                    if v:
                        identities.add(str(v).lower())
                hostnames = r.get("hostnames")
                if isinstance(hostnames, list):
                    identities.update(str(h).lower() for h in hostnames if h)
                if not identities:
                    continue

                port_lists = []
                for key in ("shodan_only_ports", "ports", "confirmed_ports", "shodan_ports"):
                    v = r.get(key)
                    if isinstance(v, list):
                        port_lists.append(v)
                meta = r.get("meta")
                if isinstance(meta, dict) and isinstance(meta.get("ports"), list):
                    port_lists.append(meta["ports"])
                single = r.get("port")
                if single is not None:
                    port_lists.append([single])

                for plist in port_lists:
                    for p in plist:
                        try:
                            pi = int(p)
                        except (TypeError, ValueError):
                            continue
                        for ident in identities:
                            seen.add((ident, pi))
    return seen


def _validate_with_naabu(candidates: list, naabu: str = "naabu",
                         timeout: int = 60) -> list:
    """Run naabu on the candidate host:port list to confirm each is alive."""
    if not candidates:
        return []
    import tempfile
    # naabu resolves DNS itself and scans every A record a hostname has, so a
    # host behind a multi-IP CDN/anycast front (Cloudflare, CloudFront — 2-4
    # IPs is typical) prints one JSON line per IP, all carrying the same
    # host:port. A plain list here would append each of those as if it were
    # a distinct new finding, quadrupling real hosts in all_ports.jsonl. We
    # only care whether the host:port is alive at all, so dedupe by (host, port).
    alive = set()
    hosts_by_port = {}
    for host, port in candidates:
        hosts_by_port.setdefault(port, []).append(host)

    for port, hosts in hosts_by_port.items():
        with tempfile.NamedTemporaryFile(
                mode="w", suffix=".txt", delete=False) as tf:
            for h in hosts:
                tf.write(h + "\n")
            tf_path = tf.name
        try:
            proc = subprocess.run(
                [naabu, "-l", tf_path, "-p", str(port),
                 "-silent", "-json", "-c", "10", "-rate", "500"],
                capture_output=True, text=True, timeout=timeout)
            for line in (proc.stdout or "").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    r = json.loads(line)
                    h = (r.get("host") or "").lower()
                    p = r.get("port")
                    if h and p:
                        alive.add((h, int(p)))
                except Exception:
                    continue
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            pass
        finally:
            try:
                os.unlink(tf_path)
            except Exception:
                pass
    return sorted(alive)


def reconcile(all_ports_file: str, osint_files: list,
              output_file: str) -> dict:
    naabu_ports = _load_naabu_ports(all_ports_file)
    osint_ports = _load_osint_ports(osint_files)
    new_candidates = sorted(osint_ports - naabu_ports)

    if not new_candidates:
        return {"osint_total": len(osint_ports), "already_known": 0,
                "new_candidates": 0, "validated_alive": 0}

    already_known = len(osint_ports & naabu_ports)
    alive = _validate_with_naabu(new_candidates)
    alive_set = set(alive)

    # Append validated to all_ports.jsonl
    if alive:
        with open(all_ports_file, "a") as out:
            for host, port in alive:
                out.write(json.dumps({
                    "host": host, "port": port,
                    "protocol": "tcp", "source": "osint_validated"
                }) + "\n")

    # Write reconcile summary
    os.makedirs(os.path.dirname(output_file) or ".", exist_ok=True)
    with open(output_file, "w") as out:
        for host, port in new_candidates:
            out.write(json.dumps({
                "host": host, "port": port,
                "source": "osint",
                "alive": (host, port) in alive_set,
            }) + "\n")

    return {
        "osint_total": len(osint_ports),
        "already_known": already_known,
        "new_candidates": len(new_candidates),
        "validated_alive": len(alive),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--all-ports", required=True,
                    help="Path to naabu all_ports.jsonl (will be appended)")
    ap.add_argument("--osint-files", nargs="+", default=[],
                    help="OSINT/shodan/censys jsonl files with port findings")
    ap.add_argument("--output", required=True,
                    help="Path to osint_reconcile.jsonl (audit log)")
    args = ap.parse_args()

    summary = reconcile(args.all_ports, args.osint_files, args.output)
    print(json.dumps(summary), file=sys.stderr)


if __name__ == "__main__":
    main()
