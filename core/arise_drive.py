#!/usr/bin/env python3
"""
ARISE → Google Drive sync (rclone backend) + local retention.

Design
------
- Sync is delegated to **rclone**, which the operator configures once on the host
  via `rclone config` (an OAuth remote pointing at a real Google account, or a
  service account against a Shared Drive). ARISE never handles the OAuth tokens
  itself — it only shells out to `rclone`, which keeps credential handling out of
  the app entirely.
- On scan completion the watcher calls `sync_scan()`, which runs
  `rclone copy scans/<scan_id> <remote>:<dest>/<scan_id>` and, on success, drops a
  `.drive_synced` marker inside the scan folder.
- Retention keeps the newest `keep` result folders per target (n, n-1 by default)
  on the **local disk** and deletes older ones — but only folders that carry the
  `.drive_synced` marker, so nothing that hasn't been backed up is ever removed.
  Google Drive retains the full history.

Config lives in the global settings file (`arise_settings.json`) under a `drive`
block; this module is a stateless engine that receives that dict.
"""

import sys as _sys, os as _os
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)


import os
import re
import json
import shutil
import subprocess
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # PROJECT_ROOT
SYNC_MARKER = '.drive_synced'

DEFAULT_CONFIG = {
    'enabled': False,      # master on/off
    'auto_sync': True,     # sync automatically when a scan completes
    'remote': '',          # rclone remote name, e.g. "gdrive"
    'dest': 'arise',       # folder path inside the remote
    'keep': 2,             # retention: keep newest n (=> n and n-1)
    'config_path': '',     # optional explicit rclone.conf path
}


# ---------------------------------------------------------------------------
# config helpers
# ---------------------------------------------------------------------------
def normalize_config(raw):
    """Coerce a stored/partial dict into a full, safe drive-config dict."""
    raw = raw or {}
    cfg = dict(DEFAULT_CONFIG)
    cfg['enabled'] = bool(raw.get('enabled', False))
    cfg['auto_sync'] = bool(raw.get('auto_sync', True))
    cfg['remote'] = (raw.get('remote') or '').strip().rstrip(':')
    cfg['dest'] = (raw.get('dest') or 'arise').strip().strip('/')
    try:
        cfg['keep'] = max(1, int(raw.get('keep', 2)))
    except (TypeError, ValueError):
        cfg['keep'] = 2
    cfg['config_path'] = (raw.get('config_path') or '').strip()
    return cfg


def _rclone_base(cfg):
    cmd = ['rclone']
    if cfg.get('config_path'):
        cmd += ['--config', cfg['config_path']]
    return cmd


def _run(cmd, timeout=None):
    """Run a command; return (rc, stdout, stderr). rc=-1 on launch failure."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return -2, '', f'timed out after {timeout}s'
    except FileNotFoundError:
        return -1, '', 'rclone not found on PATH'
    except Exception as exc:  # noqa: BLE001
        return -1, '', str(exc)


# ---------------------------------------------------------------------------
# rclone introspection
# ---------------------------------------------------------------------------
def rclone_available():
    return shutil.which('rclone') is not None


def rclone_version():
    if not rclone_available():
        return None
    rc, out, _ = _run(['rclone', 'version'], timeout=15)
    if rc != 0:
        return None
    first = (out.splitlines() or [''])[0]
    m = re.search(r'v[\d.]+', first)
    return m.group(0) if m else first.strip()


def list_remotes(cfg=None):
    """Names of configured rclone remotes (without the trailing colon)."""
    if not rclone_available():
        return []
    cmd = _rclone_base(cfg or {}) + ['listremotes']
    rc, out, _ = _run(cmd, timeout=15)
    if rc != 0:
        return []
    return [r.strip().rstrip(':') for r in out.splitlines() if r.strip()]


def test_remote(cfg):
    """Verify the configured remote is reachable/authorized. Returns (ok, message)."""
    if not rclone_available():
        return False, "rclone is not installed on the server. Install it and run `rclone config`."
    remote = cfg.get('remote')
    if not remote:
        return False, "No rclone remote configured."
    if remote not in list_remotes(cfg):
        return False, f"Remote '{remote}' is not defined in rclone. Run `rclone config` first."
    target = f"{remote}:{cfg.get('dest','')}".rstrip(':')
    # `lsd` lists directories at the destination — proves auth + reachability.
    cmd = _rclone_base(cfg) + ['lsd', f"{remote}:", '--max-depth', '1']
    rc, _out, err = _run(cmd, timeout=45)
    if rc == 0:
        return True, f"Connected to '{remote}'. Destination: {target}/"
    return False, (err.strip().splitlines()[-1] if err.strip() else f"rclone exited {rc}")


# ---------------------------------------------------------------------------
# sync
# ---------------------------------------------------------------------------
def is_synced(scan_id, base_scan_dir):
    return os.path.exists(os.path.join(base_scan_dir, scan_id, SYNC_MARKER))


def _write_marker(scan_dir, remote_path):
    try:
        with open(os.path.join(scan_dir, SYNC_MARKER), 'w') as fh:
            json.dump({'synced_at': datetime.now().isoformat(timespec='seconds'),
                       'remote': remote_path}, fh)
    except Exception:
        pass


def sync_scan(scan_id, cfg, base_scan_dir, timeout=3600):
    """rclone copy one scan folder to Drive. Returns (ok, message)."""
    cfg = normalize_config(cfg)
    if not cfg['enabled']:
        return False, "Drive sync is disabled."
    if not rclone_available():
        return False, "rclone is not installed."
    if not cfg['remote']:
        return False, "No rclone remote configured."

    src = os.path.join(base_scan_dir, scan_id)
    if not os.path.isdir(src):
        return False, f"Scan folder not found: {scan_id}"

    remote_path = f"{cfg['remote']}:{cfg['dest']}/{scan_id}".replace('//', '/')
    cmd = _rclone_base(cfg) + [
        'copy', src, remote_path,
        '--transfers', '4', '--checkers', '8',
        '--fast-list', '--no-update-modtime',
        '--exclude', f'/{SYNC_MARKER}',
        '--stats', '0',
    ]
    rc, _out, err = _run(cmd, timeout=timeout)
    if rc == 0:
        _write_marker(src, remote_path)
        return True, f"Synced {scan_id} → {remote_path}"
    tail = (err.strip().splitlines()[-1] if err.strip() else f"rclone exited {rc}")
    return False, f"Sync failed for {scan_id}: {tail}"


# ---------------------------------------------------------------------------
# retention (local only — Drive keeps full history)
# ---------------------------------------------------------------------------
def plan_retention(scans, keep=2):
    """Given [{id, target, sort}], return the scan dicts to delete locally.

    Keeps the newest `keep` per target; everything older is a deletion candidate.
    """
    keep = max(1, int(keep or 2))
    by_target = {}
    for s in scans:
        by_target.setdefault(s.get('target') or s.get('id'), []).append(s)
    doomed = []
    for _tgt, lst in by_target.items():
        lst.sort(key=lambda s: s.get('sort', 0), reverse=True)
        doomed.extend(lst[keep:])
    return doomed


def apply_retention(scans, cfg, base_scan_dir):
    """Delete older local scan folders, but only ones already synced to Drive.

    Returns {'deleted': [...], 'skipped_unsynced': [...], 'kept': int}.
    """
    cfg = normalize_config(cfg)
    doomed = plan_retention(scans, cfg['keep'])
    deleted, skipped = [], []
    for s in doomed:
        sid = s.get('id')
        if not sid:
            continue
        if not is_synced(sid, base_scan_dir):
            skipped.append(sid)            # never delete unbacked-up data
            continue
        path = os.path.join(base_scan_dir, sid)
        try:
            shutil.rmtree(path)
            deleted.append(sid)
        except Exception:
            skipped.append(sid)
    return {'deleted': deleted, 'skipped_unsynced': skipped,
            'kept': len(scans) - len(deleted)}
