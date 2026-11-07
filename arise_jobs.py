#!/usr/bin/env python3
"""
ARISE job runner + scheduler.

- launch_scan(target): spawns `easm-pipeline.sh <target>` as a DETACHED process
  (new session) so long scans survive a dashboard restart. Tracked under
  jobs/<job_id>/{meta.json,status.json,output.log,pid,exit_code}.
- Status is reconciled by checking pid liveness + the exit_code file.
- APScheduler drives recurring scans from schedules.json (per-target cadence).

Shell-injection safe: the target is passed as a positional parameter to bash,
never concatenated into a command string.
"""

import os
import re
import json
import signal
import subprocess
import threading
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
JOBS_DIR = os.path.join(BASE_DIR, 'jobs')
SCANS_DIR = os.path.join(BASE_DIR, 'scans')
SCHEDULES_FILE = os.path.join(BASE_DIR, 'schedules.json')
SETTINGS_FILE = os.path.join(BASE_DIR, 'arise_settings.json')
PIPELINE = os.path.join(BASE_DIR, 'easm-pipeline.sh')

VALID_TARGET = re.compile(r'^[A-Za-z0-9]([A-Za-z0-9.\-_:]{0,252}[A-Za-z0-9])?$')
FREQUENCIES = ('off', 'daily', 'weekly', 'monthly', 'once', 'custom')

# Scan modes exposed to the GUI.
#   full   → complete scan from scratch (default; no extra pipeline flags)
#   reuse  → reuse the target's previous recon (subdomains/DNS/HTTP/crawl/API
#            discovery) and re-run ONLY the attack/verification modules against
#            it. Maps to the pipeline's working `--mode selective --only …` path
#            (seed_from_latest_snapshot), so it needs a prior scan to exist.
SCAN_MODES = ('full', 'reuse')

# The attack/verification modules a "reuse recon" run re-executes. Discovery is
# intentionally excluded — that's the whole point of reusing prior recon.
REUSE_ATTACK_MODULES = (
    'nuclei_scan', 'api_security', 'xss_testing', 'sqli_testing',
    'api_sqli_testing', 'cloud_exposure', 'offensive_verify',
    'wss_agent', 'auth_oracle',  # evidence-driven attack/verification (R6, R5)
    'burp_bridge_ingest', 'api_logic',  # API Kill Chain (Burp evidence + 5 analyzers)
    'adaptive_loop',  # P3-P5 adaptive endpoint attack loop (deterministic + AI)
)

# Module names the GUI is allowed to pass through to `--only`, so a crafted
# request can never inject arbitrary tokens onto the pipeline command line.
ALLOWED_MODULES = frozenset({
    'asset_discovery', 'subdomain_enum', 'dns_resolution', 'dns_discovery',
    'subdomain_takeover', 'dns_security', 'http_discovery', 'waf_detection',
    'directory_discovery', 'crawling', 'header_analysis', 'hrs_detect',
    'secret_scanning', 'param_fuzzing', 'nuclei_scan', 'api_deep_discovery',
    'endpoint_consolidation', 'api_security', 'xss_testing', 'sqli_testing',
    'api_sqli_testing', 'full_port_scan', 'service_fingerprint',
    'cloud_exposure', 'osint_intel', 'offensive_verify', 'response_intel',
    'shodan_correlation', 'internet_intel',
    'attack_synth', 'attack_paths', 'autonomous_attack', 'adaptive_loop',
    # new pipeline flow modules (2026-08-15 rebuild)
    'ip_geo_enrich', 'osint_port_reconcile', 'port_split', 'hsts_audit',
    'tech_stack_detection', 'crawl_reverify', 'nuclei_nonweb_scan',
    'access_control', 'api_directory_scan',
    # SBOM — multi-method software + version inventory (2026-11-01)
    'sbom',
    # evidence-driven layer (2026-08-23, R1-R8 from WMS post-mortem)
    'har_ingest', 'flow_reconstruct', 'identity_graph',
    'wss_agent', 'auth_oracle', 'target_memory',
    # API Kill Chain (Burp evidence fusion + 5 passive analyzers)
    'burp_bridge_ingest', 'api_logic',
    # legacy aliases still accepted (both dispatch to module_offensive_verify)
    'extended_checks', 'advanced_attacks',
})


def _has_prior_scan(target):
    """True if at least one completed scan directory exists for this target.
    The pipeline names scan dirs `<safe_target>-<DDMMYY-HHMM>` where safe_target
    replaces any char outside [A-Za-z0-9.-] with '_' (matches easm-pipeline.sh)."""
    safe = re.sub(r'[^A-Za-z0-9.\-]', '_', target)
    try:
        for name in os.listdir(SCANS_DIR):
            if name.startswith(target + '-') or name.startswith(safe + '-'):
                if os.path.isdir(os.path.join(SCANS_DIR, name)):
                    return True
    except FileNotFoundError:
        return False
    return False


def _pipeline_args(mode, only_modules):
    """Translate a GUI (mode, only_modules) choice into safe pipeline flags.
    Every token is a fixed literal or a whitelisted module name — nothing from
    the request reaches the command line verbatim."""
    mode = (mode or 'full').strip().lower()
    if mode not in SCAN_MODES:
        mode = 'full'
    if mode == 'full':
        return []
    # reuse: selective run over the chosen (or default attack) modules
    mods = [m for m in (only_modules or REUSE_ATTACK_MODULES) if m in ALLOWED_MODULES]
    if not mods:
        mods = list(REUSE_ATTACK_MODULES)
    args = ['--mode', 'selective']
    for m in mods:
        args += ['--only', m]
    return args

_LOCK = threading.RLock()
_SCHEDULER = None


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _read_json(path, default):
    try:
        with open(path) as fh:
            return json.load(fh)
    except Exception:
        return default


def _write_json(path, obj):
    tmp = path + '.tmp'
    with open(tmp, 'w') as fh:
        json.dump(obj, fh, indent=2)
    os.replace(tmp, path)


def sanitize_target(target):
    t = (target or '').strip().lower()
    # strip scheme / trailing path if a URL was pasted
    t = re.sub(r'^https?://', '', t)
    t = t.split('/')[0].strip()
    if not t or not VALID_TARGET.match(t):
        return None
    return t


def _pid_alive(pid):
    if not pid:
        return False
    try:
        os.kill(int(pid), 0)
        return True
    except (OSError, ValueError):
        return False


def _reap(pid):
    """Non-blocking reap of a child process (prevents zombies).

    Returns the exit code if the process was our child and has finished
    (negative-ish signals mapped to 128+signal), or None if it's still
    running or is not our child (e.g. reparented to init after a dashboard
    restart, which raises ECHILD).
    """
    if not pid:
        return None
    try:
        wpid, wstatus = os.waitpid(int(pid), os.WNOHANG)
    except (OSError, ValueError):
        return None                      # ECHILD / not our child / bad pid
    if wpid == 0:
        return None                      # still running
    if os.WIFEXITED(wstatus):
        return os.WEXITSTATUS(wstatus)
    if os.WIFSIGNALED(wstatus):
        return 128 + os.WTERMSIG(wstatus)
    return 1


# ---------------------------------------------------------------------------
# jobs
# ---------------------------------------------------------------------------
def _job_dir(job_id):
    return os.path.join(JOBS_DIR, job_id)


def _reconcile(job_id):
    """Return the current status dict for a job, updating running->done/failed."""
    d = _job_dir(job_id)
    status = _read_json(os.path.join(d, 'status.json'), None)
    if not status:
        return None
    # Capture current_module early (before reconciliation changes status)
    log_path = os.path.join(d, 'output.log')
    current_mod = None
    if status.get('status') == 'running':
        current_mod = _detect_current_module(log_path)

    if status.get('status') == 'running':
        pid = status.get('pid')
        # Reap first: clears the zombie and tells us if a still-parented child
        # has exited (e.g. after an Emergency Stop / SIGTERM).
        reaped = _reap(pid)
        exit_file = os.path.join(d, 'exit_code')
        if os.path.exists(exit_file):
            # Pipeline finished normally and recorded its own exit code.
            try:
                code = int(open(exit_file).read().strip() or '1')
            except ValueError:
                code = 1
            status['status'] = 'done' if code == 0 else 'failed'
            status['exit_code'] = code
            status['ended_at'] = datetime.now().isoformat(timespec='seconds')
            _write_json(os.path.join(d, 'status.json'), status)
        elif reaped is not None:
            # Child exited without writing an exit code — killed/stopped.
            status['status'] = 'done' if reaped == 0 else 'failed'
            status['exit_code'] = reaped
            status['ended_at'] = datetime.now().isoformat(timespec='seconds')
            if reaped != 0:
                status['note'] = 'scan stopped before completion'
            _write_json(os.path.join(d, 'status.json'), status)
        elif not _pid_alive(pid):
            # Not our child and no longer alive (e.g. killed after a restart).
            status['status'] = 'failed'
            status['exit_code'] = None
            status['ended_at'] = datetime.now().isoformat(timespec='seconds')
            status['note'] = 'process ended without exit code (killed?)'
            _write_json(os.path.join(d, 'status.json'), status)

    # Attach live current_module for running jobs (cheap tail read, not persisted)
    if current_mod:
        status['current_module'] = current_mod
    return status


def list_jobs():
    if not os.path.isdir(JOBS_DIR):
        return []
    out = []
    for jid in os.listdir(JOBS_DIR):
        if not os.path.isdir(_job_dir(jid)):
            continue
        st = _reconcile(jid)
        if st:
            out.append(st)
    out.sort(key=lambda s: s.get('started_at', ''), reverse=True)
    return out


def job_status(job_id):
    return _reconcile(job_id)


def is_target_running(target):
    for st in list_jobs():
        if st.get('target') == target and st.get('status') == 'running':
            return st
    return None


def _adaptive_loop_env(override=None):
    """Build the ADAPTIVE_LOOP_* env vars for a scan.

    Reads the persisted global toggle from arise_settings.json; `override`
    (True/False from a per-scan GUI choice) wins over the stored `enabled`.
    Returns a dict of env strings, or {} if the loop is off and no override —
    leaving the pipeline's own env defaults (all OFF) untouched.
    """
    block = {}
    try:
        with open(SETTINGS_FILE) as fh:
            block = (json.load(fh) or {}).get('adaptive_loop') or {}
    except Exception:
        block = {}

    if override is True:
        enabled = True
    elif override is False:
        enabled = False
    else:
        enabled = bool(block.get('enabled', False))

    if not enabled:
        # Explicitly stamp false so a per-scan opt-out beats any inherited env.
        return {'ADAPTIVE_LOOP_ENABLED': 'false'}

    def _clamp(v, lo, hi, default):
        try:
            return str(max(lo, min(hi, int(v))))
        except Exception:
            return str(default)

    return {
        'ADAPTIVE_LOOP_ENABLED': 'true',
        'ADAPTIVE_LOOP_AI': 'true' if block.get('ai') else 'false',
        'ADAPTIVE_LOOP_MAX_REQUESTS': _clamp(block.get('max_requests', 300), 10, 5000, 300),
        'ADAPTIVE_LOOP_MAX_SEEDS': _clamp(block.get('max_seeds', 200), 10, 2000, 200),
        'ADAPTIVE_LOOP_BUDGET': _clamp(block.get('budget_s', 600), 30, 3600, 600),
    }


def launch_scan(target, source='manual', mode='full', only_modules=None, adaptive=None,
                 session_cookie=None, session_cookie_b=None):
    """Launch a detached pipeline run. Returns (job_dict, error_or_None).

    mode='full' runs a complete scan; mode='reuse' re-runs only the attack
    modules against the target's previous recon (requires a prior scan).

    session_cookie (optional): a raw 'name=value; name2=value2' cookie string
    for authenticated scanning (see core/session_jar.py). Passed ONLY via the
    subprocess env (ARISE_SESSION_COOKIE) for this one launch — deliberately
    never written to meta.json/status.json, matching how the AI provider's
    actual API key reaches scan_env without ever touching a persisted job
    file. It's session-scoped credential material, not a long-lived secret,
    so it isn't routed through the vault (core.arise_secure) either.

    session_cookie_b (optional): a SECOND identity's cookie string, enabling
    the real cross-account BOLA/BFLA differential in api_security/
    auth_oracle.py (does user B see user A's objects) instead of just an
    owner-vs-anonymous check. Same handling as session_cookie — subprocess
    env only (ARISE_SESSION_COOKIE_B), never persisted."""
    t = sanitize_target(target)
    if not t:
        return None, "Invalid target. Use a hostname/domain like example.com."
    if not os.path.exists(PIPELINE):
        return None, f"Pipeline script not found at {PIPELINE}."

    extra_args = _pipeline_args(mode, only_modules)
    # A reuse run has nothing to seed from if the target was never scanned.
    if extra_args and not _has_prior_scan(t):
        return None, (f"No previous scan found for {t} — run a full scan first "
                      f"before using 'reuse recon'.")

    with _LOCK:
        running = is_target_running(t)
        if running:
            return None, f"A scan for {t} is already running (job {running['job_id']})."

        os.makedirs(JOBS_DIR, exist_ok=True)
        ts = datetime.now().strftime('%Y%m%d-%H%M%S')
        job_id = f"{t}-{ts}"
        d = _job_dir(job_id)
        os.makedirs(d, exist_ok=True)

        log_path = os.path.join(d, 'output.log')
        exit_path = os.path.join(d, 'exit_code')
        scan_mode = 'reuse' if extra_args else 'full'
        meta = {
            'job_id': job_id, 'target': t, 'source': source,
            'started_at': datetime.now().isoformat(timespec='seconds'),
            'pipeline': PIPELINE, 'mode': scan_mode, 'pipeline_args': extra_args,
        }
        _write_json(os.path.join(d, 'meta.json'), meta)

        # positional params ($1=pipeline, $2=target, $3=exit_file, $4+=pipeline
        # flags) => injection-safe: every extra arg is a separate argv entry, so
        # nothing from the request is interpolated into the shell string.
        wrapper = 'bash "$1" "$2" "${@:4}"; echo $? > "$3"'

        # Inject vault secrets as env vars so the pipeline subprocess sees them.
        # arise_secure.resolve_secret() reads vault first, then env fallbacks.
        # Without this the subprocess only inherits whatever was in os.environ
        # at dashboard startup — GUI-saved tokens would never reach the scanner.
        scan_env = os.environ.copy()
        try:
            import core.arise_secure as arise_secure
            for secret_name in arise_secure.SECRET_ENV_FALLBACKS:
                val = arise_secure.resolve_secret(secret_name)
                if val:
                    scan_env[secret_name] = val
        except Exception:
            pass  # vault unavailable — subprocess falls back to env as before

        # Surface the GUI-configured AI provider + model so every pipeline AI
        # layer (synth_ai --ai and the adaptive-loop --ai brain) uses the
        # operator's chosen provider — and thus its vault key — instead of
        # build_chat_fn's hardcoded "claude" default. Without this the adaptive
        # loop would default to Claude, find no ANTHROPIC_API_KEY, and silently
        # degrade to deterministic even when (e.g.) a Gemini key is configured.
        try:
            with open(SETTINGS_FILE) as _sf:
                _sblock = json.load(_sf) or {}
            if _sblock.get('provider'):
                scan_env['ARISE_AI_PROVIDER'] = str(_sblock['provider'])
            if _sblock.get('model'):
                scan_env['ARISE_AI_MODEL'] = str(_sblock['model'])
            # AriseAI Red-Team Pentest auto-run (Settings → AriseAI tile). Maps the
            # ai_analyst settings block onto the pipeline's AI_ANALYST_* env so
            # module_ai_analyst runs post-scan with the operator's chosen depth.
            _ai = _sblock.get('ai_analyst')
            if isinstance(_ai, dict):
                scan_env['AI_ANALYST_ENABLED'] = 'true' if _ai.get('enabled') else 'false'
                scan_env['AI_ANALYST_LIVE_VERIFY'] = 'true' if _ai.get('live_verify') else 'false'
                if _ai.get('autonomous'):
                    scan_env['AI_ANALYST_AUTONOMOUS'] = 'true'
                    # Enabling the deep tier in Settings is the operator's per-run
                    # authorization for scheduled/automatic scans (RT4 gate).
                    scan_env['AI_ANALYST_AUTHZ_CONFIRMED'] = 'true'
                else:
                    scan_env['AI_ANALYST_AUTONOMOUS'] = 'false'
                if _ai.get('objective'):
                    scan_env['AI_ANALYST_OBJECTIVE'] = str(_ai['objective'])
        except Exception:
            pass  # no settings file / unreadable — AI layers keep their defaults

        # Adaptive Endpoint Attack Loop (Module 27): global Settings toggle, with
        # an optional per-scan override from the GUI. Stamped into the subprocess
        # env so the pipeline's ADAPTIVE_LOOP_* reads pick it up.
        try:
            scan_env.update(_adaptive_loop_env(adaptive))
        except Exception:
            pass

        # Shared session/cookie jar (core/session_jar.py) — easm-pipeline.sh
        # seeds ARISE_SESSION_JAR from this env var right after OUTPUT_DIR is
        # known, scoped to this target, then every scanner stage re-reads it.
        if session_cookie:
            scan_env['ARISE_SESSION_COOKIE'] = session_cookie
        if session_cookie_b:
            scan_env['ARISE_SESSION_COOKIE_B'] = session_cookie_b

        logf = open(log_path, 'ab', buffering=0)
        try:
            proc = subprocess.Popen(
                ['bash', '-c', wrapper, 'arise-job', PIPELINE, t, exit_path, *extra_args],
                cwd=BASE_DIR,
                stdout=logf,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                start_new_session=True,   # detach: survives dashboard restart
                env=scan_env,
            )
        except Exception as exc:  # noqa: BLE001
            logf.close()
            return None, f"Failed to launch scan: {exc}"

        with open(os.path.join(d, 'pid'), 'w') as fh:
            fh.write(str(proc.pid))
        status = {
            'job_id': job_id, 'target': t, 'source': source, 'pid': proc.pid,
            'status': 'running',
            'started_at': meta['started_at'],
            'log': os.path.relpath(log_path, BASE_DIR),
        }
        _write_json(os.path.join(d, 'status.json'), status)
        return status, None


_ANSI_RE = re.compile(r'(\x1b|\x9b)[\[\(][0-9;]*[A-Za-z]?|[\x00-\x08\x0b-\x1f\x7f]')
_MODULE_RE = re.compile(r'\bMODULE\s+(\S+)\s*:\s*(.+)')

def _detect_current_module(log_path):
    """Return the last MODULE header seen in the log, or None."""
    if not os.path.exists(log_path):
        return None
    try:
        with open(log_path, 'rb') as fh:
            # Read last 32 KB — enough to catch the most recent section header
            fh.seek(0, 2)
            size = fh.tell()
            fh.seek(max(0, size - 32768))
            chunk = fh.read().decode('utf-8', errors='replace')
        last = None
        for line in chunk.splitlines():
            clean = _ANSI_RE.sub('', line).strip()
            m = _MODULE_RE.search(clean)
            if m:
                last = {'num': m.group(1), 'name': m.group(2).strip()}
        return last
    except Exception:
        return None


def tail_log(job_id, lines=200):
    d = _job_dir(job_id)
    log_path = os.path.join(d, 'output.log')
    if not os.path.exists(log_path):
        return ''
    try:
        with open(log_path, 'rb') as fh:
            data = fh.read()
        text = data.decode('utf-8', errors='replace')
        return '\n'.join(text.splitlines()[-lines:])
    except Exception:
        return ''


def stop_job(job_id):
    """Best-effort terminate a running job's process group."""
    st = _reconcile(job_id)
    if not st or st.get('status') != 'running':
        return False, "Job is not running."
    pid = st.get('pid')
    try:
        os.killpg(os.getpgid(int(pid)), signal.SIGTERM)
    except Exception:
        try:
            os.kill(int(pid), signal.SIGTERM)
        except Exception as exc:  # noqa: BLE001
            return False, f"Could not stop job: {exc}"
    return True, "Stop signal sent."


def stop_all_jobs():
    """Emergency stop: terminate every currently-running job.

    Returns (stopped_count, [errors]). Safe to call when nothing is running.
    """
    stopped = 0
    errors = []
    for st in list_jobs():
        if st.get('status') != 'running':
            continue
        jid = st.get('job_id')
        ok, msg = stop_job(jid)
        if ok:
            stopped += 1
        else:
            errors.append(f"{jid}: {msg}")
    return stopped, errors


# ---------------------------------------------------------------------------
# scheduler (APScheduler)
# ---------------------------------------------------------------------------
def load_schedules():
    return _read_json(SCHEDULES_FILE, {})


def _save_schedules(sch):
    _write_json(SCHEDULES_FILE, sch)


def _parse_run_date(value):
    """Normalise a one-time run date into a datetime.

    The browser <input type="datetime-local"> control emits values like
    ``2026-07-15T02:30`` (no seconds), but APScheduler's own string parser
    requires seconds and rejects that form with "Invalid date string". Parse
    the common shapes here so any of them work, and return a real datetime so
    DateTrigger never has to guess.
    """
    if value is None:
        raise ValueError("once frequency requires a run_date")
    if isinstance(value, datetime):
        return value
    s = str(value).strip()
    if not s:
        raise ValueError("once frequency requires a run_date")
    # Accept both the "T" and space separators, with or without seconds.
    normalised = s.replace("T", " ")
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            return datetime.strptime(normalised, fmt)
        except ValueError:
            continue
    raise ValueError(f"Unrecognised date/time '{s}' (expected YYYY-MM-DD HH:MM)")


def _make_trigger(frequency, cron, hour=2, minute=0, day_of_week=None, day_of_month=None, run_date=None):
    from apscheduler.triggers.cron import CronTrigger
    from apscheduler.triggers.date import DateTrigger
    if frequency == 'daily':
        return CronTrigger(hour=hour, minute=minute)
    if frequency == 'weekly':
        dow = day_of_week if day_of_week is not None else 'sun'
        return CronTrigger(day_of_week=dow, hour=hour, minute=minute)
    if frequency == 'monthly':
        dom = int(day_of_month) if day_of_month else 1
        return CronTrigger(day=dom, hour=hour, minute=minute)
    if frequency == 'once':
        return DateTrigger(run_date=_parse_run_date(run_date))
    if frequency == 'custom':
        if not cron:
            raise ValueError("custom frequency requires a cron string")
        return CronTrigger.from_crontab(cron)
    raise ValueError(f"unschedulable frequency: {frequency}")


def _scheduled_run(target):
    launch_scan(target, source='schedule')


def init_scheduler():
    """Start APScheduler and register jobs from schedules.json. Degrades if missing."""
    global _SCHEDULER
    if _SCHEDULER is not None:
        return _SCHEDULER
    try:
        from apscheduler.schedulers.background import BackgroundScheduler
    except ImportError:
        print("[jobs] APScheduler not installed — scheduled scans disabled. "
              "Run: pip install APScheduler")
        return None
    _SCHEDULER = BackgroundScheduler(daemon=True)
    _SCHEDULER.start()
    for target, cfg in load_schedules().items():
        freq = cfg.get('frequency', 'off')
        if freq in ('off', None):
            continue
        try:
            trigger = _make_trigger(freq, cfg.get('cron'),
                                    hour=cfg.get('hour', 2), minute=cfg.get('minute', 0),
                                    day_of_week=cfg.get('day_of_week'),
                                    day_of_month=cfg.get('day_of_month'),
                                    run_date=cfg.get('run_date'))
            _SCHEDULER.add_job(_scheduled_run, trigger,
                               args=[target], id=f"scan:{target}", replace_existing=True)
        except Exception as exc:  # noqa: BLE001
            print(f"[jobs] Could not schedule {target}: {exc}")
    return _SCHEDULER


def set_schedule(target, frequency, cron=None, hour=2, minute=0,
                  day_of_week=None, day_of_month=None, run_date=None):
    t = sanitize_target(target)
    if not t:
        return None, "Invalid target."
    if frequency not in FREQUENCIES:
        return None, f"frequency must be one of {FREQUENCIES}"
    with _LOCK:
        sch = load_schedules()
        if frequency == 'off':
            sch.pop(t, None)
            _save_schedules(sch)
            if _SCHEDULER:
                try:
                    _SCHEDULER.remove_job(f"scan:{t}")
                except Exception:
                    pass
            return {'target': t, 'frequency': 'off'}, None

        cfg = {'frequency': frequency, 'cron': cron, 'enabled': True,
               'hour': hour, 'minute': minute,
               'day_of_week': day_of_week, 'day_of_month': day_of_month,
               'run_date': run_date}
        if _SCHEDULER:
            try:
                trigger = _make_trigger(frequency, cron, hour=hour, minute=minute,
                                        day_of_week=day_of_week, day_of_month=day_of_month,
                                        run_date=run_date)
                job = _SCHEDULER.add_job(_scheduled_run, trigger,
                                         args=[t], id=f"scan:{t}", replace_existing=True)
                cfg['next_run'] = job.next_run_time.isoformat() if job.next_run_time else None
            except Exception as exc:  # noqa: BLE001
                return None, f"Invalid schedule: {exc}"
        sch[t] = cfg
        _save_schedules(sch)
        return {'target': t, **cfg}, None


def list_schedules():
    sch = load_schedules()
    out = []
    for target, cfg in sch.items():
        next_run = cfg.get('next_run')
        if _SCHEDULER:
            job = _SCHEDULER.get_job(f"scan:{target}")
            if job and job.next_run_time:
                next_run = job.next_run_time.isoformat()
        out.append({'target': target, 'frequency': cfg.get('frequency', 'off'),
                    'cron': cfg.get('cron'), 'next_run': next_run,
                    'hour': cfg.get('hour', 2), 'minute': cfg.get('minute', 0),
                    'day_of_week': cfg.get('day_of_week'),
                    'day_of_month': cfg.get('day_of_month'),
                    'run_date': cfg.get('run_date')})
    return out
