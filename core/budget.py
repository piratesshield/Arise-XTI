"""
Live-action blast-radius controls (Phase 6 / RT4).

The autonomous tier is bounded by action COUNT (`max_actions`) but not by
intensity or operator control. This module adds the missing ceilings:

  * kill switch  — a scan-local `.ai_stop` file (or ARISE_AI_STOP env) the worker
                   loop checks before every action → aborts cleanly mid-run. The
                   dashboard "Stop" button and `request_kill()` set it.
  * wall-clock   — a Deadline the loop honors in addition to the action cap.
  * per-host rate— a token-bucket ceiling so a target host is never hammered,
                   independent of how many tools the model chooses.
  * authorization— active tool execution against live hosts requires an explicit
                   per-run operator confirmation; `require_authorization()` is the
                   gate the engine/CLI/pipeline check before tier-3 runs.

Stdlib only. Never raises.
"""

from __future__ import annotations

import os
import threading
import time
from typing import Dict, Optional, Tuple


# --- kill switch -----------------------------------------------------------
def _stop_path(scan_dir: Optional[str]) -> Optional[str]:
    return os.path.join(scan_dir, ".ai_stop") if scan_dir else None


def kill_requested(scan_dir: Optional[str]) -> bool:
    if str(os.environ.get("ARISE_AI_STOP", "")).lower() in ("1", "true", "yes"):
        return True
    p = _stop_path(scan_dir)
    try:
        return bool(p) and os.path.exists(p)
    except Exception:
        return False


def request_kill(scan_dir: Optional[str]) -> bool:
    p = _stop_path(scan_dir)
    if not p:
        return False
    try:
        with open(p, "w") as fh:
            fh.write(time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
        return True
    except Exception:
        return False


def clear_kill(scan_dir: Optional[str]) -> None:
    p = _stop_path(scan_dir)
    try:
        if p and os.path.exists(p):
            os.remove(p)
    except Exception:
        pass


# --- wall-clock ------------------------------------------------------------
class Deadline:
    def __init__(self, seconds: Optional[float]):
        self.seconds = seconds
        self.t0 = time.time()

    @property
    def expired(self) -> bool:
        return self.seconds is not None and (time.time() - self.t0) >= self.seconds

    def remaining(self) -> Optional[float]:
        if self.seconds is None:
            return None
        return max(0.0, self.seconds - (time.time() - self.t0))


# --- per-host rate ceiling (token bucket) ----------------------------------
class HostRateCeiling:
    """Blocks until sending to `host` stays within `per_host_rps`. Thread-safe."""
    def __init__(self, per_host_rps: float = 3.0):
        self.min_interval = 1.0 / max(0.1, per_host_rps)
        self._last: Dict[str, float] = {}
        self._lock = threading.Lock()

    def wait(self, host: str) -> None:
        if not host:
            return
        with self._lock:
            now = time.time()
            last = self._last.get(host, 0.0)
            delay = self.min_interval - (now - last)
            self._last[host] = now + (delay if delay > 0 else 0.0)
        if delay > 0:
            time.sleep(delay)


# --- authorization gate ----------------------------------------------------
def require_authorization(confirmed: bool, env_name: str = "AI_ANALYST_AUTHZ_CONFIRMED"
                          ) -> Tuple[bool, Optional[str]]:
    """Active tool execution against live hosts needs an explicit per-run OK.
    Returns (allowed, reason)."""
    if confirmed:
        return True, None
    if str(os.environ.get(env_name, "")).lower() in ("1", "true", "yes"):
        return True, None
    return False, ("active tool execution requires per-run authorization "
                   f"(set {env_name}=true or confirm in the UI) — refusing to fire")
