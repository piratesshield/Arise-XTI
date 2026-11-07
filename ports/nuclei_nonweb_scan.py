#!/usr/bin/env python3
"""Nuclei scan on origin non-web ports (SSH, MySQL, Redis, SMTP, etc.).

Reads nonweb_origin_ports.jsonl (from port_split), builds a target list of
host:port, runs nuclei with network/service templates, emits findings.

CDN non-web is never scanned (already dropped in port_split).
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
import tempfile

# Nuclei template tags that make sense for non-web services
DEFAULT_TAGS = "network,ssh,ftp,smtp,mysql,redis,mongodb,postgres,elastic,rdp,vnc,ldap,snmp,memcached,kubernetes,docker"


def _load_targets(nonweb_file: str) -> list:
    targets = []
    if not os.path.exists(nonweb_file):
        return targets
    with open(nonweb_file, "r", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
                host = r.get("host") or r.get("ip")
                port = r.get("port")
                if host and port:
                    targets.append(f"{host}:{port}")
            except Exception:
                continue
    return sorted(set(targets))


def scan(nonweb_file: str, output_file: str,
         nuclei_bin: str = "nuclei",
         tags: str = DEFAULT_TAGS,
         severity: str = "info,low,medium,high,critical",
         timeout: int = 1800,
         rate_limit: int = 100) -> dict:
    targets = _load_targets(nonweb_file)
    if not targets:
        return {"targets": 0, "findings": 0,
                "reason": "no origin non-web ports"}

    with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False) as tf:
        for t in targets:
            tf.write(t + "\n")
        tf_path = tf.name

    os.makedirs(os.path.dirname(output_file) or ".", exist_ok=True)
    findings = 0
    try:
        proc = subprocess.run(
            [nuclei_bin, "-l", tf_path,
             "-tags", tags,
             "-severity", severity,
             "-j", "-o", output_file,
             "-rate-limit", str(rate_limit),
             "-silent", "-no-color",
             "-timeout", "10",
             "-duc"],
            capture_output=True, text=True, timeout=timeout)
        # Count findings from output file (nuclei writes one per line)
        if os.path.exists(output_file):
            with open(output_file, "r", errors="ignore") as f:
                findings = sum(1 for line in f if line.strip())
    except subprocess.TimeoutExpired:
        print(f"[nuclei_nonweb_scan] timeout after {timeout}s",
              file=sys.stderr)
    except FileNotFoundError:
        print("[nuclei_nonweb_scan] nuclei binary not found", file=sys.stderr)
        return {"targets": len(targets), "findings": 0,
                "error": "nuclei not installed"}
    except Exception as e:
        print(f"[nuclei_nonweb_scan] error: {e}", file=sys.stderr)
    finally:
        try:
            os.unlink(tf_path)
        except Exception:
            pass

    return {"targets": len(targets), "findings": findings}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--nonweb-file", required=True,
                    help="Path to nonweb_origin_ports.jsonl (input)")
    ap.add_argument("--output", required=True,
                    help="Path to nuclei_nonweb_findings.jsonl (output)")
    ap.add_argument("--tags", default=DEFAULT_TAGS)
    ap.add_argument("--severity", default="info,low,medium,high,critical")
    ap.add_argument("--timeout", type=int, default=1800)
    ap.add_argument("--rate-limit", type=int, default=100)
    args = ap.parse_args()

    summary = scan(args.nonweb_file, args.output,
                   tags=args.tags, severity=args.severity,
                   timeout=args.timeout, rate_limit=args.rate_limit)
    print(json.dumps(summary), file=sys.stderr)


if __name__ == "__main__":
    main()
