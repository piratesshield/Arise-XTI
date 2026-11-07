#!/usr/bin/env python3
"""
ARISE Chrome Service — one app-owned dedicated headless Chrome
==============================================================
Launches a SINGLE long-lived headless Chrome exposing a CDP endpoint, so every
browser-driven module (input_discovery.py Module 20.2, and future runtime
modules) connects to the SAME warm browser via `connect_over_cdp` instead of
each cold-launching its own Chrome. Faster, lower memory, and the browser's
lifecycle is owned by ARISE, not by whichever tool ran last.

The running endpoint is written to <scan-dir>/.arise_chrome.json
  {"url": "http://127.0.0.1:PORT", "port": PORT, "pid": PID}
so other modules discover it without argument passing.

Usage:
  python3 chrome_service.py start  --scan-dir <dir> [--port 0] [--chrome PATH]
  python3 chrome_service.py stop   --scan-dir <dir>
  python3 chrome_service.py status --scan-dir <dir>
  python3 chrome_service.py url    --scan-dir <dir>     # prints CDP url or nothing
"""

from __future__ import annotations

import sys as _sys, os as _os
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)


import argparse
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from typing import Optional


def log(msg: str) -> None:
    print(f"[chrome-service] {msg}", file=sys.stderr, flush=True)


_CHROME_CANDIDATES = [
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    "/Applications/Google Chrome Canary.app/Contents/MacOS/Google Chrome Canary",
    "google-chrome", "google-chrome-stable", "chromium", "chromium-browser",
    "/usr/bin/google-chrome", "/usr/bin/chromium", "/usr/bin/chromium-browser",
    "/snap/bin/chromium",
]

CHROME_FLAGS = [
    "--headless=new", "--no-first-run", "--no-default-browser-check",
    "--disable-gpu", "--disable-dev-shm-usage", "--disable-background-networking",
    "--disable-extensions", "--disable-sync", "--mute-audio", "--hide-scrollbars",
    "--metrics-recording-only", "--no-sandbox",
]


def find_chrome(explicit: str = "") -> Optional[str]:
    if explicit:
        return explicit if (os.path.isfile(explicit) or shutil.which(explicit)) else None
    for c in _CHROME_CANDIDATES:
        if os.path.isfile(c) or shutil.which(c):
            return c if os.path.isfile(c) else shutil.which(c)
    return None


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _endpoint_file(scan_dir: Path) -> Path:
    return scan_dir / ".arise_chrome.json"


def _read_endpoint(scan_dir: Path) -> Optional[dict]:
    f = _endpoint_file(scan_dir)
    if not f.exists():
        return None
    try:
        return json.loads(f.read_text())
    except Exception:
        return None


def _alive(url: str) -> bool:
    try:
        with urllib.request.urlopen(url + "/json/version", timeout=2) as r:
            return r.status == 200
    except Exception:
        return False


def start(scan_dir: Path, port: int, chrome: str) -> int:
    existing = _read_endpoint(scan_dir)
    if existing and _alive(existing.get("url", "")):
        log(f"already running at {existing['url']}")
        print(existing["url"])
        return 0

    binary = find_chrome(chrome)
    if not binary:
        log("no Chrome/Chromium binary found; browser modules will fall back to launch")
        return 1

    port = port or _free_port()
    udd = scan_dir / ".arise_chrome_profile"
    udd.mkdir(parents=True, exist_ok=True)
    cmd = [binary, f"--remote-debugging-port={port}",
           f"--user-data-dir={udd}"] + CHROME_FLAGS
    log(f"launching dedicated Chrome on port {port}: {os.path.basename(binary)}")
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            start_new_session=True)
    url = f"http://127.0.0.1:{port}"
    for _ in range(40):  # up to ~8s
        if _alive(url):
            break
        if proc.poll() is not None:
            log("Chrome exited during startup")
            return 1
        time.sleep(0.2)
    else:
        log("Chrome did not expose CDP in time")
        try:
            proc.terminate()
        except Exception:
            pass
        return 1

    _endpoint_file(scan_dir).write_text(json.dumps(
        {"url": url, "port": port, "pid": proc.pid}))
    log(f"ready at {url} (pid {proc.pid})")
    print(url)
    return 0


def stop(scan_dir: Path) -> int:
    ep = _read_endpoint(scan_dir)
    if not ep:
        log("no endpoint file; nothing to stop")
        return 0
    pid = ep.get("pid")
    if pid:
        try:
            os.killpg(os.getpgid(pid), signal.SIGTERM)
        except Exception:
            try:
                os.kill(pid, signal.SIGTERM)
            except Exception:
                pass
        log(f"stopped Chrome pid {pid}")
    try:
        _endpoint_file(scan_dir).unlink()
    except Exception:
        pass
    return 0


def status(scan_dir: Path) -> int:
    ep = _read_endpoint(scan_dir)
    if ep and _alive(ep.get("url", "")):
        log(f"running at {ep['url']} (pid {ep.get('pid')})")
        return 0
    log("not running")
    return 1


def url(scan_dir: Path) -> int:
    ep = _read_endpoint(scan_dir)
    if ep and _alive(ep.get("url", "")):
        print(ep["url"])
        return 0
    return 1


def resolve_cdp_url(scan_dir: Path) -> Optional[str]:
    """Helper other modules import: return a live dedicated-Chrome CDP url or None
    (checks $ARISE_CHROME_CDP, then the scan-dir endpoint file)."""
    env = os.environ.get("ARISE_CHROME_CDP", "").strip()
    if env and _alive(env):
        return env
    ep = _read_endpoint(scan_dir)
    if ep and _alive(ep.get("url", "")):
        return ep["url"]
    return None


def main() -> int:
    ap = argparse.ArgumentParser(description="ARISE dedicated headless Chrome service")
    ap.add_argument("action", choices=["start", "stop", "status", "url"])
    ap.add_argument("--scan-dir", required=True)
    ap.add_argument("--port", type=int, default=0)
    ap.add_argument("--chrome", default="")
    args = ap.parse_args()
    scan_dir = Path(args.scan_dir)
    scan_dir.mkdir(parents=True, exist_ok=True)
    return {"start": lambda: start(scan_dir, args.port, args.chrome),
            "stop": lambda: stop(scan_dir),
            "status": lambda: status(scan_dir),
            "url": lambda: url(scan_dir)}[args.action]()


if __name__ == "__main__":
    sys.exit(main())
