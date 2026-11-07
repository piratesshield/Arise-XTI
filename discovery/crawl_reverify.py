#!/usr/bin/env python3
"""httpx alive check on crawled URLs to drop DNS-dead / connection-dead entries.

URL Inventory currently pulls in gau/gospider/katana URLs that may point to
dead subdomains or paths. This pass filters them via httpx before feeding
into endpoint_consolidator's final inventory build.
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
from urllib.parse import urlparse


def _extract_urls(input_files: list) -> set:
    urls = set()
    for path in input_files:
        if not os.path.exists(path):
            continue
        with open(path, "r", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                # JSONL first, then plain text
                if line.startswith("{"):
                    try:
                        r = json.loads(line)
                        u = r.get("url") or r.get("input") or ""
                        if u:
                            urls.add(u)
                        continue
                    except Exception:
                        pass
                if line.startswith("http://") or line.startswith("https://"):
                    urls.add(line)
    return urls


def reverify(input_files: list, out_alive: str, out_dead: str,
             httpx_bin: str = "httpx", timeout: int = 8,
             threads: int = 50, mc_codes: str = "200,301,302,401,403") -> dict:
    urls = _extract_urls(input_files)
    if not urls:
        return {"total": 0, "alive": 0, "dead": 0}

    with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False) as tf:
        for u in sorted(urls):
            tf.write(u + "\n")
        tf_path = tf.name

    alive_urls = set()
    # Outer subprocess cap: per-URL timeout * batches, with a floor of 60s
    # and a ceiling of 30 min. httpx handles concurrency internally.
    outer_timeout = max(60, min(1800, timeout * (len(urls) // threads + 1) + 30))
    try:
        proc = subprocess.run(
            [httpx_bin, "-l", tf_path, "-silent", "-json",
             "-mc", mc_codes, "-timeout", str(timeout),
             "-t", str(threads), "-nc"],
            capture_output=True, text=True, timeout=outer_timeout)
        for line in (proc.stdout or "").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
                u = r.get("url") or r.get("input")
                if u:
                    alive_urls.add(u)
            except Exception:
                continue
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as e:
        print(f"[crawl_reverify] httpx error: {e}", file=sys.stderr)
    finally:
        try:
            os.unlink(tf_path)
        except Exception:
            pass

    dead = urls - alive_urls
    os.makedirs(os.path.dirname(out_alive) or ".", exist_ok=True)
    with open(out_alive, "w") as f:
        for u in sorted(alive_urls):
            f.write(json.dumps({"url": u, "alive": True}) + "\n")
    os.makedirs(os.path.dirname(out_dead) or ".", exist_ok=True)
    with open(out_dead, "w") as f:
        for u in sorted(dead):
            f.write(json.dumps({"url": u, "alive": False}) + "\n")

    return {"total": len(urls), "alive": len(alive_urls), "dead": len(dead)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--inputs", nargs="+", required=True,
                    help="Files with URLs (jsonl or plain text)")
    ap.add_argument("--out-alive", required=True)
    ap.add_argument("--out-dead", required=True)
    ap.add_argument("--timeout", type=int, default=8)
    ap.add_argument("--threads", type=int, default=50)
    ap.add_argument("--mc", default="200,301,302,401,403",
                    help="httpx -mc match codes")
    args = ap.parse_args()

    summary = reverify(args.inputs, args.out_alive, args.out_dead,
                       timeout=args.timeout, threads=args.threads,
                       mc_codes=args.mc)
    print(json.dumps(summary), file=sys.stderr)


if __name__ == "__main__":
    main()
