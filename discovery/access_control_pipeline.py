#!/usr/bin/env python3
"""
Streaming 401/403 access-control pipeline.

Runs IN PARALLEL with dirsearch so its findings are processed as they arrive
instead of waiting for the whole scan to finish. Each 401/403 URL flows
through two stages:

  Stage 1 (Bypass): try every technique in bypass_403.BypassEngine. If any
                    bypass succeeds (control-verified), record it.
  Stage 2 (WAF):    if Stage 1 did NOT bypass, ask waf_response whether the
                    still-403 is actually a WAF challenge/block. If yes,
                    record it — downstream (nuclei_url_consolidator) will
                    drop those URLs so we don't waste scan budget hitting
                    URLs the WAF will just block again.

Why streaming instead of batch
------------------------------
The old flow was strictly sequential:

    dirsearch  ->  awk-split by status  ->  WAF filter (inline heredoc)
              ->  bypass_403 (batch)    ->  Module 8B consolidation

Nothing downstream could start until dirsearch fully finished, and each
subsequent stage waited on the previous. On large scans dirsearch alone
takes 10-30min; adding a serial bypass+WAF pass on top pushed Module 8B
past an hour on some targets. Streaming shrinks that to roughly
max(dirsearch_time, bypass_time+waf_time), because each stage starts as
soon as its first input is available.

We deliberately do bypass BEFORE WAF check (not the other way around).
A URL that a bypass technique can crack open isn't actually WAF-blocked
in any useful sense — we've reached the underlying app. Doing WAF first
would falsely flag those as blocked and lose the coverage. Doing WAF only
on URLs where bypass has already failed is the correct gate.

Termination
-----------
The tailer treats "the end-marker file exists AND the log has stopped
growing" as end-of-stream. The marker is a small sentinel file the shell
touches AFTER dirsearch exits — cross-platform, zombie-proof, and works
whether the tailer runs alongside dirsearch or against an already-finished
log. As a fallback, a pid liveness check is honoured when both --end-marker
and --dirsearch-pid are set; that's belt-and-braces for cases where the
shell forgets to touch the marker (crash / SIGKILL / disk full). The
grace period (``TAIL_IDLE_TIMEOUT`` seconds of no growth after the marker
appears) protects against reading dirsearch's last buffered flush.

Output files
------------
  --bypass-output   bypass_findings.jsonl (same schema bypass_403.py already
                    writes when run standalone; downstream consumers don't
                    need to change).
  --waf-output      waf_blocked.jsonl — NEW. Schema:
                        {"url": "...", "http_status": 403,
                         "matched_signatures": ["cf-ray", ...],
                         "checked_at": "<iso8601>"}
                    endpoint_consolidator reads this and stamps
                    ``blocked_by_waf: true`` on matching endpoints;
                    nuclei_url_consolidator drops them from the nuclei
                    feed.
"""

from __future__ import annotations

import sys as _sys, os as _os
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)


import argparse
import json
import os
import queue
import re
import signal
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Set

# BypassEngine.process(url) returns a Finding or None. That per-URL API is
# exactly what streaming needs — no batch input file to construct.
from discovery.bypass_403 import BypassEngine  # noqa: E402
from discovery.waf_response import is_waf_response  # noqa: E402


# --------------------------------------------------------------------------- #
# Tuning knobs — all overridable via CLI. Defaults picked to match the values
# easm-pipeline.sh currently uses for bypass_403 (12 threads, 8s timeout).
# --------------------------------------------------------------------------- #

TAIL_POLL_INTERVAL = 0.5      # seconds between reads when at EOF
TAIL_IDLE_TIMEOUT = 3.0       # seconds of no growth before checking pid liveness
DRAIN_POLL_INTERVAL = 0.25    # seconds between queue-drain checks after EOF

# dirsearch's default output format is `<status> <size> <url>`. We match it
# loosely — anything that starts with a status code we recognise and ends
# with an https?://... URL counts. This tolerates format drift (extra
# columns, colour codes if -o didn't strip them, etc).
_DIRSEARCH_LINE_RE = re.compile(
    r"^\s*(?P<status>\d{3})\b.*?(?P<url>https?://\S+)\s*$"
)


# --------------------------------------------------------------------------- #
# JSONL writer — thread-safe line-buffered output. One instance per file.
# --------------------------------------------------------------------------- #

class JsonlWriter:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        # Line-buffered so a crash or SIGTERM mid-scan still has the
        # already-written findings on disk (matches the "checkpoint often"
        # discipline the rest of the pipeline uses).
        self._fh = open(path, "a", encoding="utf-8", buffering=1)

    def write(self, obj) -> None:
        line = json.dumps(obj, default=str) + "\n"
        with self._lock:
            self._fh.write(line)

    def close(self) -> None:
        with self._lock:
            try:
                self._fh.close()
            except Exception:
                pass


# --------------------------------------------------------------------------- #
# Pid liveness — no psutil dep. Falls back gracefully if the pid isn't ours.
# --------------------------------------------------------------------------- #

def _pid_alive(pid: Optional[int]) -> bool:
    if not pid:
        return False
    try:
        # Signal 0 = "does this pid exist and can I signal it?" — no signal
        # actually delivered. Raises OSError(ESRCH) if the process is gone.
        os.kill(pid, 0)
        return True
    except (OSError, ProcessLookupError):
        return False


# --------------------------------------------------------------------------- #
# Log tailer — yields (status, url) tuples as dirsearch writes them
# --------------------------------------------------------------------------- #

def tail_dirsearch(log_path: Path, end_marker: Optional[Path] = None,
                   dirsearch_pid: Optional[int] = None):
    """Generator: yields (status:int, url:str) for each new dirsearch line.

    End-of-stream is declared when EITHER of these becomes true and the
    file has then stopped growing for ``TAIL_IDLE_TIMEOUT`` seconds:

      * ``end_marker`` file exists (preferred, shell writes it after
        dirsearch exits — cross-platform, zombie-proof).
      * ``dirsearch_pid`` is set and ``os.kill(pid, 0)`` says it's gone
        (fallback, and only trusted after the idle timeout has elapsed
        so a zombie window doesn't cause premature exit).

    If both are None, the tailer only exits on the growth-stall path —
    useful when re-running against an already-completed log.
    """
    # Wait for the log to appear — dirsearch creates it lazily. If the
    # end-marker shows up first (dirsearch crashed before writing anything,
    # or the whole module was skipped), exit immediately instead of waiting
    # out the 60s deadline for a file that will never appear.
    deadline = time.monotonic() + 60
    while not log_path.exists():
        if end_marker is not None and end_marker.exists():
            return
        if time.monotonic() > deadline:
            return
        time.sleep(TAIL_POLL_INTERVAL)

    idle_since: Optional[float] = None
    with open(log_path, "r", encoding="utf-8", errors="replace") as fh:
        while True:
            line = fh.readline()
            if line:
                idle_since = None
                m = _DIRSEARCH_LINE_RE.match(line)
                if m:
                    try:
                        status = int(m.group("status"))
                    except ValueError:
                        continue
                    yield status, m.group("url")
                continue
            # EOF for now.
            if idle_since is None:
                idle_since = time.monotonic()
            idle_secs = time.monotonic() - idle_since

            done = False
            if end_marker is not None and end_marker.exists():
                done = True
            elif dirsearch_pid and not _pid_alive(dirsearch_pid) \
                    and idle_secs >= TAIL_IDLE_TIMEOUT:
                done = True
            elif end_marker is None and dirsearch_pid is None \
                    and idle_secs >= TAIL_IDLE_TIMEOUT:
                done = True

            if done and idle_secs >= TAIL_IDLE_TIMEOUT:
                # Read one more time in case a buffered flush landed between
                # our last read and marker creation.
                remainder = fh.read()
                for tail_line in remainder.splitlines():
                    m = _DIRSEARCH_LINE_RE.match(tail_line)
                    if m:
                        try:
                            status = int(m.group("status"))
                        except ValueError:
                            continue
                        yield status, m.group("url")
                return
            time.sleep(TAIL_POLL_INTERVAL)


# --------------------------------------------------------------------------- #
# Main pipeline
# --------------------------------------------------------------------------- #

def run_pipeline(args) -> int:
    bypass_writer = JsonlWriter(Path(args.bypass_output))
    waf_writer = JsonlWriter(Path(args.waf_output))

    engine = BypassEngine(
        timeout=args.timeout,
        threads=1,  # streaming does its own threading; keep engine sequential per-URL
        unsafe_methods=args.unsafe_methods,
    )

    # De-dupe: the same URL can appear multiple times in dirsearch output
    # (rerun-safe, or reprobed with different methods). Only process each
    # canonical URL once through the expensive bypass+WAF path.
    seen: Set[str] = set()
    seen_lock = threading.Lock()

    stats = {
        "urls_seen": 0,
        "urls_dispatched": 0,
        "bypass_attempted": 0,
        "bypass_succeeded": 0,
        "waf_attempted": 0,
        "waf_matched": 0,
        "real_403s": 0,
    }
    stats_lock = threading.Lock()

    def _bump(key: str, n: int = 1) -> None:
        with stats_lock:
            stats[key] += n

    # WAF pool receives URLs whose bypass failed. Separate pool so bypass
    # workers don't block on waf-check network latency.
    waf_pool = ThreadPoolExecutor(max_workers=args.waf_threads,
                                  thread_name_prefix="waf")

    def _check_waf(url: str, http_status: int) -> None:
        _bump("waf_attempted")
        try:
            is_waf, matches = is_waf_response(url, timeout=args.timeout)
        except Exception:
            is_waf, matches = False, []
        if is_waf:
            _bump("waf_matched")
            waf_writer.write({
                "url": url,
                "http_status": http_status,
                "matched_signatures": matches,
                "checked_at": datetime.now(timezone.utc).isoformat(),
            })
        else:
            _bump("real_403s")

    def _run_bypass_then_waf(url: str, http_status: int) -> None:
        _bump("bypass_attempted")
        finding = None
        try:
            finding = engine.process(url)
        except Exception:
            finding = None
        if finding is not None:
            _bump("bypass_succeeded")
            # bypass_403's Finding dataclass mirrors what its own --output
            # writes, so downstream consumers don't need to distinguish
            # who wrote the line.
            try:
                bypass_writer.write(asdict(finding))
            except Exception:
                # Finding might not be a dataclass in some code paths; fall
                # back to a best-effort dict.
                try:
                    bypass_writer.write(dict(finding.__dict__))
                except Exception:
                    pass
            return
        # No bypass — hand off to WAF check on a different pool so we don't
        # tie up a bypass worker on unrelated network I/O.
        waf_pool.submit(_check_waf, url, http_status)

    bypass_pool = ThreadPoolExecutor(max_workers=args.bypass_threads,
                                     thread_name_prefix="bypass")

    dirsearch_pid = args.dirsearch_pid if args.dirsearch_pid > 0 else None
    end_marker = Path(args.end_marker) if args.end_marker else None
    log_path = Path(args.input_log)

    for status, url in tail_dirsearch(log_path, end_marker=end_marker,
                                      dirsearch_pid=dirsearch_pid):
        _bump("urls_seen")
        if status not in (401, 403, 405):
            continue
        with seen_lock:
            if url in seen:
                continue
            seen.add(url)
        _bump("urls_dispatched")
        bypass_pool.submit(_run_bypass_then_waf, url, status)

    # Drain: no more URLs coming in. Wait for bypass pool first (its output
    # feeds WAF pool), then WAF pool. Poll rather than shutdown() so we can
    # print progress on long tail-latency URLs.
    while getattr(bypass_pool, "_work_queue", None) is not None and \
            not bypass_pool._work_queue.empty():
        time.sleep(DRAIN_POLL_INTERVAL)
    bypass_pool.shutdown(wait=True)
    waf_pool.shutdown(wait=True)

    bypass_writer.close()
    waf_writer.close()

    # Emit one-line summary — pipeline log parsers pick this up.
    print(f"[access-control-pipeline] "
          f"seen={stats['urls_seen']} dispatched={stats['urls_dispatched']} "
          f"bypass_attempted={stats['bypass_attempted']} "
          f"bypass_succeeded={stats['bypass_succeeded']} "
          f"waf_attempted={stats['waf_attempted']} "
          f"waf_matched={stats['waf_matched']} "
          f"real_403s={stats['real_403s']}",
          file=sys.stderr)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Streaming 401/403 bypass + WAF-block classifier "
                    "(runs concurrently with dirsearch)")
    ap.add_argument("--input-log", required=True,
                    help="Path to the dirsearch output log to tail. "
                         "Doesn't have to exist yet — tailer will wait.")
    ap.add_argument("--end-marker", default=None,
                    help="Path to a sentinel file the shell touches AFTER "
                         "dirsearch exits. Presence = no more input coming. "
                         "Preferred over --dirsearch-pid because it's "
                         "cross-platform and zombie-proof.")
    ap.add_argument("--dirsearch-pid", type=int, default=0,
                    help="PID of the dirsearch process. Fallback end-of-stream "
                         "signal used only when --end-marker is absent or "
                         "hasn't been created yet. 0 = don't check.")
    ap.add_argument("--bypass-output", required=True,
                    help="JSONL output for confirmed bypasses (schema "
                         "matches bypass_403.py's --output).")
    ap.add_argument("--waf-output", required=True,
                    help="JSONL output for WAF-blocked URLs. Consumed by "
                         "endpoint_consolidator + nuclei_url_consolidator.")
    ap.add_argument("--bypass-threads", type=int, default=12,
                    help="Concurrent bypass workers (default: 12).")
    ap.add_argument("--waf-threads", type=int, default=8,
                    help="Concurrent WAF-check workers (default: 8).")
    ap.add_argument("--timeout", type=int, default=8,
                    help="HTTP timeout per request in seconds (default: 8).")
    ap.add_argument("--unsafe-methods", action="store_true",
                    help="Pass-through to BypassEngine — allow state-changing "
                         "verbs. Default is read-only.")
    args = ap.parse_args()

    # SIGTERM is what run_tool_timeout uses to kill overshooting modules.
    # Trap it so both writers get closed cleanly and partial findings survive.
    def _on_sigterm(signum, frame):
        # Re-raise as SystemExit so ThreadPoolExecutor shutdown paths run.
        sys.exit(1)
    signal.signal(signal.SIGTERM, _on_sigterm)

    return run_pipeline(args)


if __name__ == "__main__":
    sys.exit(main())
