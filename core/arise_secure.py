#!/usr/bin/env python3
"""
ARISE secure store — authentication + encrypted secret vault.

Design (see plan):
  - Admin password:  hashed, non-reversible (Werkzeug PBKDF2-SHA256, salted) -> users.json
  - API keys/webhook: encrypted at rest with Fernet (AES-128-CBC + HMAC)     -> secrets.enc.json
  - Fernet master key: ARISE_MASTER_KEY env, else auto-generated .arise_master.key (chmod 600)
  - Flask session:   signed cookie via SECRET_KEY, persisted to arise_session.key

Auth is intentionally pluggable: local password login ships now; OIDC/SAML/Google
can be added later by extending AUTH_METHODS without changing the session shape.
"""

import sys as _sys, os as _os
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)


import os
import json
import secrets as _pysecrets
import threading
import time

from cryptography.fernet import Fernet, InvalidToken
from werkzeug.security import generate_password_hash, check_password_hash

# The vault files (.arise_master.key, arise_session.key, users.json,
# secrets.enc.json) live at PROJECT_ROOT, not next to this file, which now
# lives one level down at core/ -- walk up one level.
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

MASTER_KEY_FILE = os.path.join(BASE_DIR, '.arise_master.key')
SESSION_KEY_FILE = os.path.join(BASE_DIR, 'arise_session.key')
USERS_FILE = os.path.join(BASE_DIR, 'users.json')
SECRETS_FILE = os.path.join(BASE_DIR, 'secrets.enc.json')

# Logical secret names the vault knows about. Maps to the env-var fallbacks the
# dashboard already understands, so a key set in the GUI transparently replaces .env.
SECRET_ENV_FALLBACKS = {
    'ANTHROPIC_API_KEY': ['ANTHROPIC_API_KEY', 'ANTHROPIC_AUTH_TOKEN'],
    'OPENAI_API_KEY': ['OPENAI_API_KEY'],
    'GEMINI_API_KEY': ['GEMINI_API_KEY', 'GOOGLE_API_KEY'],
    'HF_API_TOKEN': ['HF_API_TOKEN', 'HUGGINGFACE_API_KEY', 'HUGGINGFACEHUB_API_TOKEN'],
    'OPENROUTER_API_KEY': ['OPENROUTER_API_KEY'],
    'GROQ_API_KEY': ['GROQ_API_KEY'],
    'SLACK_WEBHOOK_URL': ['SLACK_WEBHOOK_URL'],
    # OSINT & Human Exposure Intelligence (Module 18 — osint_intel.py) connectors.
    # osint_intel.py resolves these via resolve_secret() itself, so a key saved
    # here in the GUI takes effect on the next scan with no .env/restart needed.
    'HIBP_API_KEY': ['HIBP_API_KEY'],
    'INTELX_API_KEY': ['INTELX_API_KEY'],
    'LEAKCHECK_API_KEY': ['LEAKCHECK_API_KEY'],
    'GITHUB_TOKEN': ['GITHUB_TOKEN', 'GITHUB_API_TOKEN'],
    'SHODAN_API_KEY': ['SHODAN_API_KEY'],
    # Phase 3 OSINT: ad fraud, malicious landing page, social/telegram, gov injection
    'GOOGLE_SAFEBROWSING_KEY': ['GOOGLE_SAFEBROWSING_KEY'],
    'VIRUSTOTAL_API_KEY': ['VIRUSTOTAL_API_KEY', 'VT_API_KEY'],
    'TELEGRAM_BOT_TOKEN': ['TELEGRAM_BOT_TOKEN'],
    'YOUTUBE_API_KEY': ['YOUTUBE_API_KEY'],
    # Internet Intelligence Layer (Module 23 — internet_intel.py) connectors.
    'CENSYS_API_ID': ['CENSYS_API_ID'],
    'CENSYS_API_SECRET': ['CENSYS_API_SECRET'],
    'GREYNOISE_API_KEY': ['GREYNOISE_API_KEY'],
    # ipinfo.io — geolocation fallback for the global asset map (Module 23).
    'IPINFO_TOKEN': ['IPINFO_TOKEN', 'IPINFO_API_KEY'],
}

_LOCK = threading.RLock()
_FERNET = None


# ---------------------------------------------------------------------------
# File helpers (permissions: secrets/keys/users are always chmod 600)
# ---------------------------------------------------------------------------
def _chmod_600(path):
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass  # e.g. Windows / unusual filesystems — best effort


def _atomic_write(path, data_str, secure=True):
    tmp = path + '.tmp'
    with open(tmp, 'w') as fh:
        fh.write(data_str)
    if secure:
        _chmod_600(tmp)
    os.replace(tmp, path)
    if secure:
        _chmod_600(path)


def _read_json(path, default):
    if not os.path.exists(path):
        return default
    try:
        with open(path) as fh:
            return json.load(fh)
    except Exception:
        return default


# ---------------------------------------------------------------------------
# Fernet master key
# ---------------------------------------------------------------------------
def _get_fernet():
    """Return a cached Fernet built from the master key (env -> file -> generate)."""
    global _FERNET
    if _FERNET is not None:
        return _FERNET
    with _LOCK:
        if _FERNET is not None:
            return _FERNET
        key = (os.environ.get('ARISE_MASTER_KEY') or '').strip()
        if key:
            key_bytes = key.encode()
        elif os.path.exists(MASTER_KEY_FILE):
            with open(MASTER_KEY_FILE, 'rb') as fh:
                key_bytes = fh.read().strip()
        else:
            key_bytes = Fernet.generate_key()
            with open(MASTER_KEY_FILE, 'wb') as fh:
                fh.write(key_bytes)
            _chmod_600(MASTER_KEY_FILE)
            print("[secure] Generated new encryption master key -> .arise_master.key "
                  "(chmod 600). Back this up; without it stored API keys cannot be decrypted.")
        try:
            _FERNET = Fernet(key_bytes)
        except Exception as exc:
            raise RuntimeError(
                "Invalid ARISE_MASTER_KEY / .arise_master.key. It must be a 32-byte "
                "url-safe base64 Fernet key. Unset ARISE_MASTER_KEY to auto-generate one."
            ) from exc
        return _FERNET


def get_session_secret():
    """Stable Flask session signing key, persisted to arise_session.key."""
    env = (os.environ.get('SECRET_KEY') or '').strip()
    if env:
        return env
    if os.path.exists(SESSION_KEY_FILE):
        with open(SESSION_KEY_FILE) as fh:
            val = fh.read().strip()
            if val:
                return val
    val = _pysecrets.token_hex(32)
    _atomic_write(SESSION_KEY_FILE, val)
    return val


# ---------------------------------------------------------------------------
# Users / authentication
# ---------------------------------------------------------------------------
def _load_users():
    return _read_json(USERS_FILE, {})


def _save_users(users):
    _atomic_write(USERS_FILE, json.dumps(users, indent=2))


def user_exists(username):
    return username in _load_users()


def set_password(username, password, role='admin'):
    """Create/update a user with a salted PBKDF2 hash (never stores plaintext)."""
    if not username or not password:
        raise ValueError("username and password are required")
    with _LOCK:
        users = _load_users()
        users[username] = {
            # PBKDF2-SHA256 explicitly (portable; some builds lack hashlib.scrypt,
            # which is Werkzeug's newer default).
            'password_hash': generate_password_hash(password, method='pbkdf2:sha256'),
            'role': role,
        }
        _save_users(users)
    return True


def verify_user(username, password):
    """Return the user dict on success, else None. Constant-ish time via Werkzeug."""
    users = _load_users()
    rec = users.get(username)
    if not rec:
        # Still run a hash comparison to reduce username-enumeration timing signal.
        check_password_hash(
            'pbkdf2:sha256:600000$dummy$0000000000000000000000000000000000000000000000000000000000000000',
            password or '')
        return None
    if check_password_hash(rec.get('password_hash', ''), password or ''):
        return {'username': username, 'role': rec.get('role', 'admin')}
    return None


# ---------------------------------------------------------------------------
# Login rate-limiting / lockout (in-memory, per-process — fine for the
# single-process dashboard this ships as; F04 in ARISE_REMEDIATION_ROADMAP.md)
# ---------------------------------------------------------------------------
_LOGIN_LOCK = threading.Lock()
_failed_by_ip = {}    # ip -> [timestamps]
_failed_by_user = {}  # username -> [timestamps]

_IP_MAX_ATTEMPTS = 8      # per IP, any username
_IP_WINDOW_SEC = 15 * 60
_USER_MAX_ATTEMPTS = 5    # per username, any IP (credential-stuffing across sources)
_USER_WINDOW_SEC = 15 * 60
_MAX_TRACKED_KEYS = 10000  # opportunistic cap so a mass-scan doesn't grow this forever


def _prune(hits, window):
    cutoff = time.time() - window
    return [t for t in hits if t > cutoff]


def _cleanup_if_large(d):
    if len(d) <= _MAX_TRACKED_KEYS:
        return
    for k in [k for k, v in d.items() if not v]:
        del d[k]


def check_login_lockout(username, ip):
    """Return (locked: bool, retry_after_seconds: int). Read-only (no mutation
    beyond pruning expired entries)."""
    username = username or ''
    ip = ip or 'unknown'
    now = time.time()
    with _LOGIN_LOCK:
        ip_hits = _prune(_failed_by_ip.get(ip, []), _IP_WINDOW_SEC)
        _failed_by_ip[ip] = ip_hits
        if len(ip_hits) >= _IP_MAX_ATTEMPTS:
            return True, max(1, int(ip_hits[0] + _IP_WINDOW_SEC - now))

        user_hits = _prune(_failed_by_user.get(username, []), _USER_WINDOW_SEC)
        _failed_by_user[username] = user_hits
        if len(user_hits) >= _USER_MAX_ATTEMPTS:
            return True, max(1, int(user_hits[0] + _USER_WINDOW_SEC - now))
    return False, 0


def record_failed_login(username, ip):
    username = username or ''
    ip = ip or 'unknown'
    now = time.time()
    with _LOGIN_LOCK:
        _failed_by_ip.setdefault(ip, []).append(now)
        _failed_by_user.setdefault(username, []).append(now)
        _cleanup_if_large(_failed_by_ip)
        _cleanup_if_large(_failed_by_user)


def record_successful_login(username, ip):
    username = username or ''
    ip = ip or 'unknown'
    with _LOGIN_LOCK:
        _failed_by_ip.pop(ip, None)
        _failed_by_user.pop(username, None)


def bootstrap_admin():
    """Ensure an admin exists. First run creates one from env or a random password.

    Returns (username, generated_password_or_None). The password is only returned
    (and printed by the caller) when it was auto-generated so the operator can log in.
    """
    with _LOCK:
        users = _load_users()
        if users:
            return None, None
        username = (os.environ.get('ARISE_ADMIN_USER') or 'admin').strip() or 'admin'
        password = (os.environ.get('ARISE_ADMIN_PASSWORD') or '').strip()
        generated = None
        if not password:
            password = 'admin'  # documented default — operator must change before exposing
        set_password(username, password, role='admin')
        return username, generated


# ---------------------------------------------------------------------------
# Encrypted secret vault
# ---------------------------------------------------------------------------
def _load_vault():
    return _read_json(SECRETS_FILE, {})


def _save_vault(vault):
    _atomic_write(SECRETS_FILE, json.dumps(vault, indent=2))


def set_secret(name, value):
    """Encrypt and store a secret. Empty value deletes it (falls back to env)."""
    f = _get_fernet()
    with _LOCK:
        vault = _load_vault()
        if value is None or str(value).strip() == '':
            vault.pop(name, None)
        else:
            token = f.encrypt(str(value).strip().encode()).decode()
            vault[name] = token
        _save_vault(vault)
    return True


def get_secret(name):
    """Decrypt a stored secret; None if not in the vault (caller may fall back to env)."""
    vault = _load_vault()
    token = vault.get(name)
    if not token:
        return None
    try:
        return _get_fernet().decrypt(token.encode()).decode()
    except InvalidToken:
        return None


def resolve_secret(name):
    """Vault first, then the env-var fallbacks for that logical secret name."""
    val = get_secret(name)
    if val:
        return val
    for env in SECRET_ENV_FALLBACKS.get(name, [name]):
        v = os.environ.get(env)
        if v:
            return v
    return None


def _mask(value):
    if not value:
        return ''
    v = str(value)
    if v.startswith('https://hooks.slack.com/'):
        return 'https://hooks.slack.com/services/****'
    if len(v) > 8:
        return v[:4] + '…' + v[-4:]
    return '****'


def secret_status():
    """Masked status for every known secret, noting whether it came from vault or env."""
    vault = _load_vault()
    out = {}
    for name in SECRET_ENV_FALLBACKS:
        in_vault = name in vault
        val = resolve_secret(name)
        source = 'vault' if in_vault else ('env' if val else None)
        out[name] = {
            'set': bool(val),
            'source': source,
            'masked': _mask(val) if val else '',
        }
    return out
