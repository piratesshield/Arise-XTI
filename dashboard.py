#!/usr/bin/env python3
"""
ARISE EASM v4.0 — "Summon Every Hidden Exposure."
Complete rewrite with proper data ingestion, caching, and state management
Fixes: Target switching, port data, multi-scan isolation, real-time updates
"""

import os
import json
import glob
import re
import ssl
import socket
import urllib.request
import urllib.parse
import subprocess
import logging
from datetime import datetime
from pathlib import Path
from functools import lru_cache, wraps
from flask import (Flask, render_template, jsonify, request, session,
                   redirect, url_for)
from flask_cors import CORS
import threading
import time
from logging.handlers import RotatingFileHandler

import history.kaiju_entities as kaiju_entities
import history.kaiju_issues as kaiju_issues

# Load .env (API keys, Slack webhook, AI settings) before reading any env vars.
try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env'))
except Exception:
    pass

# Secure store (auth + encrypted secret vault) and the detached job runner/scheduler.
import core.arise_secure as arise_secure
import arise_jobs
import core.arise_drive as arise_drive
import ai.ai_probing as ai_probing
import arise_autonomous
import history.ledger_view as ledger_view
import history.arise_report as arise_report
from evidence.target_memory import TargetMemory

app = Flask(__name__)
# Signed-cookie sessions. Same-origin CORS only — an open CORS policy combined
# with cookie auth would enable cross-site credential abuse.
app.secret_key = arise_secure.get_session_secret()
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    # Set ARISE_COOKIE_SECURE=true when the dashboard is served over HTTPS/behind TLS.
    SESSION_COOKIE_SECURE=os.environ.get('ARISE_COOKIE_SECURE', '').strip().lower()
    in ('1', 'true', 'yes', 'on'),
    # Always reload templates from disk so UI edits are visible without a server restart.
    TEMPLATES_AUTO_RELOAD=True,
    # Disable Flask's static-file max-age so browsers re-validate every request.
    SEND_FILE_MAX_AGE_DEFAULT=0,
)
CORS(app, supports_credentials=True, origins=[])


@app.after_request
def _no_cache_html(response):
    """Force browsers to revalidate HTML pages so UI changes are always picked up."""
    if 'text/html' in response.content_type:
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
    return response

# Endpoints reachable without a session. Everything else requires login.
_PUBLIC_PATHS = {'/login', '/api/auth/login', '/api/health'}


def _is_public(path):
    if path in _PUBLIC_PATHS:
        return True
    if path.startswith('/static/'):
        return True
    return False


@app.before_request
def _require_login():
    """Gate every route behind the single admin session (except public paths)."""
    if _is_public(request.path):
        return None
    if session.get('user'):
        return None
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Authentication required.'}), 401
    return redirect(url_for('login_page', next=request.path))


def login_required(fn):
    """Explicit guard for sensitive actions (defense in depth alongside the gate)."""
    @wraps(fn)
    def _wrap(*args, **kwargs):
        if not session.get('user'):
            return jsonify({'error': 'Authentication required.'}), 401
        return fn(*args, **kwargs)
    return _wrap

# ===========================================================================
# CONFIGURATION
# ===========================================================================

BASE_SCAN_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'scans')
CACHE_TIMEOUT = 120  # seconds — long enough to survive multiple refresh cycles
CURRENT_TARGET = {}  # Track per-session target
_SCAN_CACHE = {}
_SCAN_CACHE_LOCKS = {}  # per-scan-id locks to prevent thundering herd
_SCAN_CACHE_LOCKS_GUARD = threading.Lock()
_SCAN_INDEX_CACHE = {'timestamp': 0, 'scans': []}
PORT_MAPPINGS = {
    22: 'SSH', 21: 'FTP', 25: 'SMTP', 53: 'DNS', 80: 'HTTP', 110: 'POP3',
    143: 'IMAP', 389: 'LDAP', 443: 'HTTPS', 445: 'SMB', 587: 'SMTP',
    1433: 'MSSQL', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL',
    5984: 'CouchDB', 6379: 'Redis', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt',
    9200: 'Elasticsearch', 27017: 'MongoDB'
}
SEVERITY_WEIGHTS = {'critical': 40, 'high': 20, 'medium': 8, 'low': 2, 'info': 0}

# ---------------------------------------------------------------------------
# AI Security Analyst — reads assembled scan context, produces an executive
# analysis, and optionally pushes it to Slack. The model is Claude (Anthropic
# SDK); the Slack push uses an Incoming Webhook. Both are configured by env var
# and degrade gracefully when unset.
# ---------------------------------------------------------------------------
AI_MODEL = os.environ.get('ARISE_AI_MODEL', 'claude-opus-4-8')
SLACK_WEBHOOK_URL = os.environ.get('SLACK_WEBHOOK_URL', '')

# Persisted global AI settings (provider / model / auto-Slack), editable from the
# dashboard's Settings panel. Defaults come from .env; the file overrides them.
SETTINGS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'arise_settings.json')
AI_PROVIDER_ENV = os.environ.get('ARISE_AI_PROVIDER', '').strip()
AUTO_SLACK_DEFAULT = os.environ.get('ARISE_AUTO_SLACK', 'true').strip().lower() in ('1', 'true', 'yes', 'on')
AI_WATCH_INTERVAL = int(os.environ.get('ARISE_AI_WATCH_INTERVAL', '20'))  # seconds

# Ports grouped by blast radius: unauthenticated data stores and remote-shell
# services are tier-1; management protocols and legacy services are tier-2.
PORT_RISK_TIER1 = {6379, 9200, 27017, 5984, 11211}       # Redis, Elastic, Mongo, Couch, Memcached
PORT_RISK_TIER2 = {3306, 5432, 1433}                      # MySQL, Postgres, MSSQL
PORT_RISK_TIER3 = {3389, 22, 23, 445, 21, 25, 110, 143}  # RDP, SSH, Telnet, SMB, FTP, SMTP, POP, IMAP
SENSITIVE_PORTS = PORT_RISK_TIER1 | PORT_RISK_TIER2 | PORT_RISK_TIER3

# Cloud tab taxonomy — the Cloud dashboard shows ONLY these. Anything the
# pipeline classified into an app/API bucket (XSS, SQLi, SSRF, IDOR, JWT, …)
# never reaches here; the whitelist is the hard boundary between the Cloud tab
# and the Vulns/API tabs.
CLOUD_SECURITY_CATEGORIES = {
    'public_cloud_storage', 'public_kubernetes_api', 'metadata_service_exposure',
    'leaked_cloud_credentials', 'terraform_state_exposed', 'public_elasticsearch',
    'public_cicd', 'public_redis_mongo', 'grafana_prometheus_exposed',
    'cdn_origin_bypass', 'debug_endpoint',
}
# Control-gap posture findings — cloud/infra hygiene, shown in a separate group.
CLOUD_POSTURE_CATEGORIES = {'missing_waf', 'missing_email_auth', 'information_disclosure'}
CLOUD_ALL_CATEGORIES = CLOUD_SECURITY_CATEGORIES | CLOUD_POSTURE_CATEGORIES

# Provider fingerprints for cloud recon — maps httpx `tech`/CDN strings and IP
# owners to a canonical provider so the recon panel can inventory the estate.
CLOUD_PROVIDER_TECH = {
    'aws': ['amazon web services', 'amazon cloudfront', 'amazon s3', 'amazon elb',
            'aws', 'cloudfront', 's3', 'elastic load balancing', 'awselb'],
    'gcp': ['google cloud', 'google-cloud', 'gcs', 'google storage', 'firebase',
            'app engine', 'cloud run', 'googleusercontent'],
    'azure': ['azure', 'microsoft azure', 'azure blob', 'azure cdn', 'windows-azure'],
    'cloudflare': ['cloudflare'],
    'fastly': ['fastly'],
    'akamai': ['akamai'],
}

# Known CDN/WAF IP ranges that should be excluded from "direct origin IP" results.
# These are checked via CIDR membership; the list covers major providers.
# For runtime use we skip importing ipaddress for each call — instead we match
# the hostname strings or URL patterns which reliably signal these providers.
CDN_WAF_HOST_RE = re.compile(
    r'(?i)(cloudflare|akamai|fastly|imperva|incapsula|sucuri|stackpath'
    r'|edgecast|limelight|cdn77|keycdn|bunnycdn|gcore|azion'
    r'|cloudfront\.net|akamaitechnologies|googleusercontent\.com'
    r'|awsglobalaccelerator\.com|cdn\.)',
)

# AWS region / hosted-zone keywords found in URLs, CNAME targets, and S3/ELB
# hostnames.  Maps keyword → human-readable region label.
AWS_REGION_PATTERNS = [
    (re.compile(r'(?i)[\.\-]us[\-_]east[\-_]1[\.\-]'),   'us-east-1 (N. Virginia)'),
    (re.compile(r'(?i)[\.\-]us[\-_]east[\-_]2[\.\-]'),   'us-east-2 (Ohio)'),
    (re.compile(r'(?i)[\.\-]us[\-_]west[\-_]1[\.\-]'),   'us-west-1 (N. California)'),
    (re.compile(r'(?i)[\.\-]us[\-_]west[\-_]2[\.\-]'),   'us-west-2 (Oregon)'),
    (re.compile(r'(?i)[\.\-]ap[\-_]south[\-_]1[\.\-]'),  'ap-south-1 (Mumbai)'),
    (re.compile(r'(?i)[\.\-]ap[\-_]south[\-_]2[\.\-]'),  'ap-south-2 (Hyderabad)'),
    (re.compile(r'(?i)[\.\-]ap[\-_]southeast[\-_]1[\.\-]'), 'ap-southeast-1 (Singapore)'),
    (re.compile(r'(?i)[\.\-]ap[\-_]southeast[\-_]2[\.\-]'), 'ap-southeast-2 (Sydney)'),
    (re.compile(r'(?i)[\.\-]ap[\-_]southeast[\-_]3[\.\-]'), 'ap-southeast-3 (Jakarta)'),
    (re.compile(r'(?i)[\.\-]ap[\-_]northeast[\-_]1[\.\-]'), 'ap-northeast-1 (Tokyo)'),
    (re.compile(r'(?i)[\.\-]ap[\-_]northeast[\-_]2[\.\-]'), 'ap-northeast-2 (Seoul)'),
    (re.compile(r'(?i)[\.\-]ap[\-_]northeast[\-_]3[\.\-]'), 'ap-northeast-3 (Osaka)'),
    (re.compile(r'(?i)[\.\-]eu[\-_]west[\-_]1[\.\-]'),   'eu-west-1 (Ireland)'),
    (re.compile(r'(?i)[\.\-]eu[\-_]west[\-_]2[\.\-]'),   'eu-west-2 (London)'),
    (re.compile(r'(?i)[\.\-]eu[\-_]west[\-_]3[\.\-]'),   'eu-west-3 (Paris)'),
    (re.compile(r'(?i)[\.\-]eu[\-_]central[\-_]1[\.\-]'),'eu-central-1 (Frankfurt)'),
    (re.compile(r'(?i)[\.\-]eu[\-_]central[\-_]2[\.\-]'),'eu-central-2 (Zurich)'),
    (re.compile(r'(?i)[\.\-]eu[\-_]north[\-_]1[\.\-]'),  'eu-north-1 (Stockholm)'),
    (re.compile(r'(?i)[\.\-]eu[\-_]south[\-_]1[\.\-]'),  'eu-south-1 (Milan)'),
    (re.compile(r'(?i)[\.\-]ca[\-_]central[\-_]1[\.\-]'),'ca-central-1 (Canada)'),
    (re.compile(r'(?i)[\.\-]sa[\-_]east[\-_]1[\.\-]'),   'sa-east-1 (São Paulo)'),
    (re.compile(r'(?i)[\.\-]me[\-_]south[\-_]1[\.\-]'),  'me-south-1 (Bahrain)'),
    (re.compile(r'(?i)[\.\-]af[\-_]south[\-_]1[\.\-]'),  'af-south-1 (Cape Town)'),
    (re.compile(r'(?i)[\.\-]il[\-_]central[\-_]1[\.\-]'),'il-central-1 (Tel Aviv)'),
    # GCP regions
    (re.compile(r'(?i)[\.\-]asia[\-_]south[\-_]1[\.\-]'),    'asia-south1 (Mumbai)'),
    (re.compile(r'(?i)[\.\-]asia[\-_]southeast[\-_]1[\.\-]'),'asia-southeast1 (Singapore)'),
    (re.compile(r'(?i)[\.\-]us[\-_]central[\-_]1[\.\-]'),    'us-central1 (Iowa)'),
    (re.compile(r'(?i)[\.\-]europe[\-_]west[\-_]1[\.\-]'),   'europe-west1 (Belgium)'),
    # Azure regions embedded in FQDN
    (re.compile(r'(?i)\.eastus[2]?\.'),                       'eastus (Virginia)'),
    (re.compile(r'(?i)\.westus[2-3]?\.'),                     'westus (California)'),
    (re.compile(r'(?i)\.centralindia\.'),                     'centralindia (Pune)'),
    (re.compile(r'(?i)\.southindia\.'),                       'southindia (Chennai)'),
    (re.compile(r'(?i)\.westindia\.'),                        'westindia (Mumbai)'),
    (re.compile(r'(?i)\.northeurope\.'),                      'northeurope (Dublin)'),
    (re.compile(r'(?i)\.westeurope\.'),                       'westeurope (Netherlands)'),
]


def detect_hosted_zone(url_or_host: str) -> str:
    """Extract the cloud hosted-zone / region from a URL or hostname.

    Checks common AWS, GCP, and Azure region sub-strings that appear in
    service FQDNs (ELB, S3 website, API Gateway, Cloud Run, Azure App
    Service, etc.).  Returns a region label string or '' if not found.
    """
    text = (url_or_host or '').lower()
    for pat, label in AWS_REGION_PATTERNS:
        # pad with dots so the regex anchors work on the raw string too
        if pat.search('.' + text + '.'):
            return label
    return ''


def setup_logging():
    """Configure a central rotating log for the dashboard."""
    log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
    os.makedirs(log_dir, exist_ok=True)

    logger = logging.getLogger('dashboard')
    logger.setLevel(logging.INFO)
    logger.propagate = False

    if not logger.handlers:
        formatter = logging.Formatter('%(asctime)s %(levelname)s %(name)s %(message)s')

        file_handler = RotatingFileHandler(
            os.path.join(log_dir, 'dashboard.log'),
            maxBytes=1_000_000,
            backupCount=5
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(formatter)
        logger.addHandler(stream_handler)

    return logger


logger = setup_logging()


def load_json_file(filepath):
    """Load a JSON file safely and log any parse failures."""
    if not filepath or not os.path.exists(filepath):
        return {}
    try:
        with open(filepath, 'r') as handle:
            return json.load(handle)
    except Exception as exc:
        logger.error("Failed to load JSON %s: %s", filepath, exc)
        return {}


def parse_scan_time(value):
    """Parse pipeline timestamps, falling back cleanly when older data is incomplete."""
    if not value:
        return datetime.min
    try:
        return datetime.fromisoformat(str(value).replace('Z', '+00:00'))
    except Exception:
        return datetime.min


def scan_time_key(value, fallback=0):
    try:
        parsed = parse_scan_time(value)
        return parsed.timestamp() if parsed != datetime.min else fallback
    except Exception:
        return fallback

# ===========================================================================
# CORE DATA PIPELINE
# ===========================================================================

class ScanDataPipeline:
    """Manages data ingestion from easm-pipeline outputs"""
    
    def __init__(self, scan_dir):
        self.scan_dir = scan_dir
        self.manifest_file = os.path.join(scan_dir, 'manifest.json')
        self._cache = {}
        self._cache_time = {}
    
    def load_manifest(self):
        """Load and parse manifest.json"""
        if not os.path.exists(self.manifest_file):
            logger.info("Manifest missing: %s", self.manifest_file)
            return {'pipeline_info': {}, 'statistics': {}, 'hosts': {}}
        
        try:
            with open(self.manifest_file, 'r') as f:
                return json.load(f)
        except Exception as exc:
            logger.error("Failed to parse manifest %s: %s", self.manifest_file, exc)
            return {'pipeline_info': {}, 'statistics': {}, 'hosts': {}}
    
    def load_port_data(self):
        """Extract port data from naabu output + httpx-confirmed ports."""
        sources = [
            os.path.join(self.scan_dir, '04_http_discovery/all_ports_full.json'),
            os.path.join(self.scan_dir, '04_http_discovery/all_ports_list.txt'),
            os.path.join(self.scan_dir, '14_port_scan/all_ports.jsonl'),
            os.path.join(self.scan_dir, '04_http_discovery/all_ports.json'),
        ]
        ports_data = {}

        for source in sources:
            if not os.path.exists(source):
                continue

            try:
                with open(source, 'r', errors='ignore') as handle:
                    for line in handle:
                        line = line.strip()
                        if not line:
                            continue

                        host = None
                        port = None

                        if source.endswith('.txt'):
                            parts = line.split(':')
                            if len(parts) == 2 and parts[1].isdigit():
                                host, port = parts[0], int(parts[1])
                        else:
                            try:
                                entry = json.loads(line)
                            except Exception:
                                continue
                            host = entry.get('host') or entry.get('ip')
                            port = entry.get('port')

                        if host and port:
                            ports_data.setdefault(host, [])
                            if port not in ports_data[host]:
                                ports_data[host].append(int(port))
            except Exception as exc:
                logger.error("Failed to read port source %s: %s", source, exc)

        # Backfill from httpx-confirmed hosts — when naabu misses ports
        # (CDN/WAF blocks SYN scans), httpx still proves the port is open.
        http_confirmed = os.path.join(self.scan_dir, '04_http_discovery/http_confirmed.json')
        if os.path.exists(http_confirmed):
            try:
                with open(http_confirmed, 'r', errors='ignore') as fh:
                    for line in fh:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            entry = json.loads(line)
                        except Exception:
                            continue
                        host = entry.get('host') or entry.get('input')
                        port = entry.get('port')
                        if host and port:
                            port = int(port)
                            ports_data.setdefault(host, [])
                            if port not in ports_data[host]:
                                ports_data[host].append(port)
            except Exception as exc:
                logger.error("Failed to read httpx port backfill %s: %s", http_confirmed, exc)

        for host in ports_data:
            ports_data[host] = sorted(set(ports_data[host]))

        return ports_data

    def get_port_scan_status(self):
        """Detect whether the port scan succeeded, crashed, or is missing.

        Manifest status takes precedence BUT gets overridden if the httpx
        backfill (or any later source) actually produced ports — a naabu FTL
        stamps 'no_open_ports' before httpx has a chance to backfill web ports.
        """
        manifest = self.load_manifest()
        status_from_manifest = manifest.get('statistics', {}).get('port_scan_status')

        # If any port data source produced entries, that's the truth.
        backfill_has_ports = bool(self.load_port_data())

        if status_from_manifest:
            if status_from_manifest in ('no_open_ports', 'missing') and backfill_has_ports:
                return 'ok'  # httpx backfill saved the module
            return status_from_manifest

        jsonl = os.path.join(self.scan_dir, '14_port_scan/all_ports.jsonl')
        stderr = os.path.join(self.scan_dir, '14_port_scan/naabu.stderr')
        scan_dir_exists = os.path.isdir(os.path.join(self.scan_dir, '14_port_scan'))

        if not scan_dir_exists:
            return 'ok' if backfill_has_ports else 'missing'

        has_results = os.path.exists(jsonl) and os.path.getsize(jsonl) > 0
        if has_results or backfill_has_ports:
            return 'ok'

        if os.path.exists(stderr):
            try:
                with open(stderr, 'r', errors='ignore') as f:
                    head = f.read(4096)
                if 'pthread_create failed' in head or 'SIGABRT' in head or 'runtime/cgo' in head:
                    return 'crashed'
                if 'no valid ipv4 or ipv6 targets' in head.lower():
                    return 'dns_failed'
            except Exception:
                pass

        return 'no_open_ports'
    
    def load_service_data(self):
        """Load nmap service fingerprinting results"""
        services_json = os.path.join(self.scan_dir, '07_service_fingerprint/services.json')
        services = {}
        
        if os.path.exists(services_json):
            try:
                with open(services_json, 'r') as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        for svc in data:
                            host = svc.get('host')
                            if host:
                                if host not in services:
                                    services[host] = []
                                services[host].append(svc)
            except Exception as exc:
                logger.error("Failed to read service data %s: %s", services_json, exc)
        
        return services
    
    def load_vulnerabilities(self):
        """Load vulnerabilities from all sources"""
        vulns = []
        
        # Nuclei results (main scan + cloud exposure nuclei pass)
        nuclei_dirs = [
            os.path.join(self.scan_dir, '12_nuclei_scanning'),
            os.path.join(self.scan_dir, 'nuclei_scanning'),
        ]
        cloud_nuclei = os.path.join(self.scan_dir, '17_cloud_exposure/cloud_nuclei.jsonl')
        if os.path.exists(cloud_nuclei):
            try:
                with open(cloud_nuclei, 'r', errors='ignore') as f:
                    for line in f:
                        try:
                            entry = json.loads(line.strip())
                            vuln = self._parse_nuclei_result(entry)
                            if vuln:
                                vuln['source'] = 'Nuclei (Cloud)'
                                vulns.append(vuln)
                        except Exception:
                            continue
            except Exception as exc:
                logger.error("Failed to read cloud nuclei %s: %s", cloud_nuclei, exc)
        
        for nuclei_dir in nuclei_dirs:
            if os.path.exists(nuclei_dir):
                for root, dirs, files in os.walk(nuclei_dir):
                    for file in files:
                        # nuclei_nonweb_findings.jsonl (SSH/Redis/MySQL/etc.
                        # banner-based checks) has its own dedicated panel at
                        # /api/nuclei-nonweb (dashboard.py ~3961) with its own
                        # presentation. Including it here too would silently
                        # double-surface every non-web finding as a second,
                        # unlabeled generic "Nuclei" row with no shared dedup
                        # key between the two views.
                        if file == 'nuclei_nonweb_findings.jsonl':
                            continue
                        if file.endswith(('.json', '.txt', '.jsonl')):
                            filepath = os.path.join(root, file)
                            try:
                                with open(filepath, 'r') as f:
                                    for line in f:
                                        try:
                                            entry = json.loads(line.strip())
                                            vuln = self._parse_nuclei_result(entry)
                                            if vuln:
                                                vulns.append(vuln)
                                        except Exception:
                                            continue
                            except Exception as exc:
                                logger.error("Failed to read nuclei file %s: %s", filepath, exc)
        
        # XSS results
        xss_file = os.path.join(self.scan_dir, '13_xss_testing/xss_results.txt')
        if os.path.exists(xss_file):
            try:
                with open(xss_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            from urllib.parse import urlparse
                            try:
                                xss_host = urlparse(line).netloc or 'Unknown'
                            except Exception:
                                xss_host = 'Unknown'
                            # dalfox output line often carries the PoC:
                            #   [POC][V][GET] http://…?q=<payload>  triggered by …
                            poc_payload = ''
                            m = re.search(r'(<[^>]+>|"[^"]*on\w+=|javascript:)', line)
                            if m:
                                poc_payload = m.group(0)
                            vulns.append({
                                'source': 'XSS Testing',
                                'template': 'XSS Vulnerability',
                                'severity': 'high',
                                'host': xss_host,
                                'url': line,
                                'impact': 'Client-side code injection (reflected/DOM XSS confirmed by dalfox)',
                                'remediation': 'Context-aware output encoding + input validation; deploy a strict CSP',
                                'detection_tool': 'dalfox',
                                'poc_payload': poc_payload,
                                'evidence': line,
                            })
            except Exception as exc:
                logger.error("Failed to read XSS results %s: %s", xss_file, exc)
        
        # Secret scan results.
        # Prefer secret_validator.py output (secrets_validated.jsonl): it carries a
        # per-credential validation verdict and a graded severity
        #   invalid->info, valid_restricted->medium, valid->high, valid_customer_data->critical
        # Fall back to raw TruffleHog findings (all treated 'critical', unvalidated).
        validated_file = os.path.join(self.scan_dir, '10_secret_scanning/secrets_validated.jsonl')
        raw_secrets_file = os.path.join(self.scan_dir, '10_secret_scanning/secrets.jsonl')
        use_validated = os.path.exists(validated_file)
        secrets_file = validated_file if use_validated else raw_secrets_file
        if os.path.exists(secrets_file):
            # Load TSV index to map filenames to URLs
            index_tsv = os.path.join(self.scan_dir, '09_crawling/js_downloads/index.tsv')
            js_url_map = {}
            if os.path.exists(index_tsv):
                try:
                    with open(index_tsv, 'r') as f:
                        for line in f:
                            parts = line.strip().split('\t')
                            if len(parts) == 2:
                                js_url_map[parts[1]] = parts[0]
                except Exception as exc:
                    logger.error("Failed to read js index.tsv %s: %s", index_tsv, exc)

            # Human-readable label + one-line meaning per validation state.
            state_label = {
                'valid_customer_data': ('LIVE — reaches customer/financial data', 'critical'),
                'valid': ('LIVE — active credential', 'high'),
                'valid_restricted': ('LIVE but restricted (scope/IP/geo/test-mode)', 'medium'),
                'invalid': ('Invalid — dead/rotated/fake', 'info'),
                'unsupported': ('Unvalidated — no auto-verifier (manual check)', 'low'),
                'error': ('Validation inconclusive (network/timeout)', 'low'),
            }

            try:
                with open(secrets_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            entry = json.loads(line)

                            if use_validated:
                                # secret_validator.py schema
                                detector_name = entry.get('detector', 'Credential')
                                state = entry.get('state', 'unsupported')
                                severity = entry.get('severity') or state_label.get(state, ('', 'low'))[1]
                                redacted = entry.get('redacted', '')
                                file_path = entry.get('source_file', '')
                                identity = entry.get('identity', '')
                                evidence = entry.get('evidence', '')
                                reason = entry.get('reason', '')
                                remediation = entry.get('remediation') or 'Rotate credential and review access logs'
                            else:
                                # raw TruffleHog schema (no validation available)
                                detector_name = entry.get('DetectorName', 'Credential')
                                state = 'unvalidated'
                                severity = 'critical'
                                redacted = entry.get('Redacted', '') or entry.get('Raw', '')
                                file_path = entry.get('SourceMetadata', {}).get('Data', {}).get('Filesystem', {}).get('file', '')
                                identity = evidence = reason = ''
                                remediation = 'Rotate credential immediately and review access logs'

                            filename = os.path.basename(file_path)
                            # Skip the index file itself; its MD5 hashes cause false positives.
                            if filename == 'index.tsv':
                                continue

                            url = js_url_map.get(filename, filename)

                            # Extract host from URL
                            host = 'Unknown'
                            if url.startswith('http'):
                                try:
                                    host = url.split('//')[1].split('/')[0]
                                except Exception:
                                    pass

                            label = state_label.get(state, (state, severity))[0] if use_validated else 'Unvalidated'
                            impact = f"Exposed {detector_name} — {label}" if use_validated else f"Exposed {detector_name}"
                            detail_bits = []
                            if redacted:
                                detail_bits.append(f"key {redacted}")
                            if identity:
                                detail_bits.append(f"identity {identity}")
                            if evidence:
                                detail_bits.append(evidence)
                            elif reason:
                                detail_bits.append(reason)
                            if detail_bits:
                                impact += " (" + "; ".join(str(b) for b in detail_bits) + ")"

                            vulns.append({
                                'source': 'Secret Scan',
                                'template': f'{detector_name} Key' + (f' [{state}]' if use_validated else ''),
                                'severity': severity,
                                'validation_state': state,
                                'host': host,
                                'url': url,
                                'impact': impact,
                                'remediation': remediation
                            })
                        except Exception as exc:
                            logger.error("Failed to parse secret entry: %s", exc)
                            continue
            except Exception as exc:
                logger.error("Failed to read secrets %s: %s", secrets_file, exc)
        # SQL injection results
        sqli_file = os.path.join(self.scan_dir, '15_sqli_testing/sqli_results.jsonl')
        if os.path.exists(sqli_file):
            try:
                with open(sqli_file, 'r') as f:
                    for line in f:
                        try:
                            entry = json.loads(line.strip())
                            confidence = entry.get('confidence', 'medium')
                            sqli_type = entry.get('type', 'unknown')
                            param = entry.get('parameter', 'unknown')
                            waf = entry.get('waf_vendor', '')
                            detection_pass = entry.get('detection_pass', 'baseline')
                            severity_map = {'high': 'critical', 'medium': 'high', 'low': 'medium'}
                            severity = severity_map.get(confidence, 'high')
                            waf_note = f' [behind {waf}]' if waf else ''
                            pass_note = f' via {detection_pass}' if detection_pass != 'baseline' else ''
                            vulns.append({
                                'source': 'SQLi Testing',
                                'template': f'SQL Injection ({sqli_type})',
                                'severity': severity,
                                'host': entry.get('host', 'Unknown'),
                                'url': entry.get('url', ''),
                                'impact': f'SQLi on param: {param} (type: {sqli_type}, confidence: {confidence}{waf_note}{pass_note})',
                                'remediation': 'Use parameterized queries / prepared statements; never concatenate user input into SQL',
                                'confidence': confidence,
                                'detection_tool': 'sqlmap',
                                'parameter': param,
                                'sqli_type': sqli_type,
                                'detection_pass': detection_pass,
                                'waf_vendor': waf,
                                'poc_payload': entry.get('payload', ''),
                                'evidence': entry.get('evidence', '') or entry.get('title', ''),
                            })
                        except Exception:
                            continue
            except Exception as exc:
                logger.error("Failed to read SQLi results %s: %s", sqli_file, exc)

        # API-aware SQL injection results (Module 20.1 — sqlmap on discovered
        # API URLs from api_deep_discovery). Same schema as Module 15; tagged
        # with source 'SQLi Testing' so scoring/reporting treat it identically,
        # but with a distinct API template for the Vulns table.
        api_sqli_file = os.path.join(self.scan_dir, '20.1_api_sqli_testing/sqli_results.jsonl')
        if os.path.exists(api_sqli_file):
            try:
                with open(api_sqli_file, 'r') as f:
                    for line in f:
                        try:
                            entry = json.loads(line.strip())
                            confidence = entry.get('confidence', 'medium')
                            sqli_type = entry.get('type', 'unknown')
                            param = entry.get('parameter', 'unknown')
                            waf = entry.get('waf_vendor', '')
                            detection_pass = entry.get('detection_pass', 'baseline')
                            severity_map = {'high': 'critical', 'medium': 'high', 'low': 'medium'}
                            severity = severity_map.get(confidence, 'high')
                            waf_note = f' [behind {waf}]' if waf else ''
                            pass_note = f' via {detection_pass}' if detection_pass != 'baseline' else ''
                            vulns.append({
                                'source': 'SQLi Testing',
                                'template': f'API SQL Injection ({sqli_type})',
                                'severity': severity,
                                'host': entry.get('host', 'Unknown'),
                                'url': entry.get('url', ''),
                                'impact': f'SQLi on discovered API endpoint — param: {param} '
                                          f'(type: {sqli_type}, confidence: {confidence}{waf_note}{pass_note}); '
                                          f'target built by API deep discovery (Module 20.1)',
                                'remediation': 'Use parameterized queries / prepared statements; never concatenate user input into SQL',
                                'confidence': confidence,
                                'detection_source': 'api_deep_discovery',
                                'detection_tool': 'sqlmap',
                                'parameter': param,
                                'sqli_type': sqli_type,
                                'detection_pass': detection_pass,
                                'waf_vendor': waf,
                                'poc_payload': entry.get('payload', ''),
                                'evidence': entry.get('evidence', '') or entry.get('title', ''),
                            })
                        except Exception:
                            continue
            except Exception as exc:
                logger.error("Failed to read API SQLi results %s: %s", api_sqli_file, exc)

        # LFI / parameter fuzzing results
        lfi_file = os.path.join(self.scan_dir, '11_param_fuzzing/lfi_results.json')
        if os.path.exists(lfi_file):
            try:
                with open(lfi_file, 'r') as f:
                    lfi_results = json.load(f)
                for entry in lfi_results:
                    fuzz_url = entry.get('url', '')
                    host = 'Unknown'
                    if fuzz_url.startswith('http'):
                        try:
                            host = fuzz_url.split('//')[1].split('/')[0].split(':')[0]
                        except Exception:
                            pass
                    payload = entry.get('input', {}).get('FUZZ', '')
                    vulns.append({
                        'source': 'Param Fuzzing',
                        'template': 'Local File Inclusion (LFI)',
                        'severity': 'critical',
                        'host': host,
                        'url': fuzz_url,
                        'impact': f'LFI confirmed with payload: {payload}',
                        'remediation': 'Sanitize file path parameters; use allowlists instead of direct file access'
                    })
            except Exception as exc:
                logger.error("Failed to read LFI results %s: %s", lfi_file, exc)

        # Cloud attack surface exposure findings (weighted model)
        cloud_file = os.path.join(self.scan_dir, '17_cloud_exposure/cloud_findings.jsonl')
        if os.path.exists(cloud_file):
            # Build a reverse map: downloaded JS filename -> source URL
            # so credentials found in local JS files get a proper web URL.
            js_url_map = {}
            idx_tsv = os.path.join(self.scan_dir, '09_crawling/js_downloads/index.tsv')
            if os.path.exists(idx_tsv):
                try:
                    for tsv_line in open(idx_tsv, errors='ignore'):
                        parts = tsv_line.strip().split('\t')
                        if len(parts) == 2:
                            js_url_map[parts[1]] = parts[0]
                except OSError:
                    pass

            try:
                with open(cloud_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            entry = json.loads(line)
                        except Exception:
                            continue
                        label = entry.get('category_label', entry.get('cloud_category', 'Cloud Exposure'))

                        # Resolve local JS file paths to web source URLs
                        raw_url = entry.get('url', '')
                        source_url = raw_url
                        if raw_url and '/js_downloads/' in raw_url:
                            fname = os.path.basename(raw_url)
                            if fname in js_url_map:
                                source_url = js_url_map[fname]
                        host = entry.get('host', 'Unknown')
                        if source_url.startswith('http'):
                            try:
                                from urllib.parse import urlparse
                                host = urlparse(source_url).hostname or host
                            except Exception:
                                pass

                        vulns.append({
                            'source': 'Cloud Exposure',
                            'template': label,
                            'severity': entry.get('severity', 'info'),
                            'host': host,
                            'url': source_url,
                            'impact': entry.get('evidence', ''),
                            'remediation': entry.get('remediation', ''),
                            'description': entry.get('evidence', ''),
                            'cloud_category': entry.get('cloud_category'),
                            'base_weight': entry.get('base_weight'),
                            'exploitability': entry.get('exploitability'),
                            'exposure': entry.get('exposure'),
                            'exposure_note': entry.get('exposure_note'),
                            'weighted_score': entry.get('weighted_score'),
                            'detection_tool': entry.get('tool'),
                        })
            except Exception as exc:
                logger.error("Failed to read cloud findings %s: %s", cloud_file, exc)

        # Offensive / attack findings (Module 24 + R5/R6 evidence layer).
        # Glob all *_findings.jsonl in 24_advanced_attacks/ so wss_agent,
        # auth_oracle, and any future attack modules surface automatically.
        # Legacy 19_extended_checks/ fallback kept for older scan snapshots.
        _SOURCE_LABELS = {
            'offensive_findings': 'Offensive Verification',
            'wss_findings': 'WebSocket Security',
            'auth_oracle_findings': 'Authorization Oracle',
        }
        adv_dir = os.path.join(self.scan_dir, '24_advanced_attacks')
        adv_files = sorted(glob.glob(os.path.join(adv_dir, '*_findings.jsonl'))) if os.path.isdir(adv_dir) else []
        if not adv_files:
            legacy = os.path.join(self.scan_dir, '19_extended_checks/extended_findings.jsonl')
            if os.path.exists(legacy):
                adv_files = [legacy]
        for ext_file in adv_files:
            fname = os.path.basename(ext_file).replace('_findings.jsonl', '')
            source_label = _SOURCE_LABELS.get(fname, 'Offensive Verification')
            try:
                with open(ext_file, 'r', errors='ignore') as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            entry = json.loads(line)
                        except Exception:
                            continue
                        vulns.append({
                            'source': source_label,
                            'template': entry.get('template') or entry.get('title', 'Offensive finding'),
                            'severity': entry.get('severity', 'info'),
                            'host': entry.get('host', 'Unknown'),
                            'url': entry.get('url', ''),
                            'impact': entry.get('evidence', ''),
                            'remediation': entry.get('remediation', ''),
                            'check': entry.get('check'),
                            'detection_tool': entry.get('tool') or entry.get('module'),
                            'confidence': entry.get('confidence'),
                            'verification': entry.get('verification'),
                            'parameter': entry.get('parameter', ''),
                            'safe_mode': entry.get('safe_mode', False),
                            'request_line': entry.get('request_line', ''),
                            'payload': entry.get('payload', ''),
                            'baseline': entry.get('baseline', {}),
                            'attack': entry.get('attack', {}),
                            'evidence_rung': entry.get('evidence_rung', ''),
                        })
            except Exception as exc:
                logger.error("Failed to read attack findings %s: %s", ext_file, exc)

        # API Security findings (Module 16) — promoted from the API
        # Intelligence Engine's cross-tool dedup (arise-intel classifier,
        # apisec.py). Only findings that
        # were either corroborated by 2+ independent tools ("confirmed") or
        # represent a live-verified exploit from apisec.py ("verified-exploit")
        # land here — single-tool, unconfirmed pattern matches are
        # intentionally excluded so this view stays free of noise/false
        # positives (see 16_api_security/promoted_vulnerabilities.jsonl).
        api_sec_file = os.path.join(self.scan_dir, '16_api_security/promoted_vulnerabilities.jsonl')
        if os.path.exists(api_sec_file):
            try:
                with open(api_sec_file, 'r', errors='ignore') as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            entry = json.loads(line)
                        except Exception:
                            continue
                        vulns.append({
                            'source': 'API Security',
                            'template': entry.get('template', 'API security finding'),
                            'severity': entry.get('severity', 'medium'),
                            'host': entry.get('host', 'Unknown'),
                            'url': entry.get('url', ''),
                            'impact': entry.get('impact', ''),
                            'remediation': entry.get('remediation', ''),
                            'confidence': entry.get('confidence'),
                            'detection_tool': ','.join(entry.get('tools') or []) or None,
                            'method': entry.get('method'),
                            'issue_class': entry.get('issue_class'),
                            'status_code': entry.get('status_code'),
                            'category': entry.get('category'),
                            'path': entry.get('path'),
                        })
            except Exception as exc:
                logger.error("Failed to read API security findings %s: %s", api_sec_file, exc)

        # Response Intelligence findings (Module 26 — response_intel.py)
        ri_file = os.path.join(self.scan_dir, '26_response_intel/response_findings_deduped.jsonl')
        if os.path.exists(ri_file):
            try:
                with open(ri_file, 'r', errors='ignore') as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            entry = json.loads(line)
                        except Exception:
                            continue
                        ri_type = entry.get('type', 'response_finding')
                        ri_cat = entry.get('category', ri_type)
                        tpl = ri_type.replace('_', ' ').title()
                        vulns.append({
                            'source': 'Response Intelligence',
                            'template': tpl,
                            'severity': entry.get('severity', 'info'),
                            'host': entry.get('host', 'Unknown'),
                            'url': entry.get('url', ''),
                            'matched_at': entry.get('url', ''),
                            'impact': entry.get('evidence', ''),
                            'remediation': entry.get('remediation', ''),
                            'response': entry.get('response_snippet', ''),
                            'status_code': entry.get('status_code'),
                            'confidence': entry.get('confidence'),
                            'detection_tool': 'response_intel',
                            'category': ri_cat,
                            'method': entry.get('method'),
                        })
            except Exception as exc:
                logger.error("Failed to read response intel %s: %s", ri_file, exc)

        # Module 10.1 — arise_nlp content scan over the staged local files
        # (JS bundles, source maps, staged 2xx bodies, .env/config). Same
        # detectors as Module 26 but on files: PII + info-disclosure + a second
        # secret opinion that trufflehog's detectors don't cover. The finding's
        # location is a file path (not a URL), so surface it in the Host column.
        nlp_file = os.path.join(self.scan_dir, '10_secret_scanning/nlp_findings.jsonl')
        if os.path.exists(nlp_file):
            try:
                with open(nlp_file, 'r', errors='ignore') as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            entry = json.loads(line)
                        except Exception:
                            continue
                        n_type = entry.get('type', 'content_finding')
                        n_cat = entry.get('category', n_type)
                        # The dashboard's Attack-Surface detail drawer reads
                        # matched_at/url (never host) for "Evidence / match
                        # location" — this used to be left entirely unset for
                        # every Content Scan (10.1) finding, so that field
                        # always rendered blank regardless of what was found.
                        file_ref = entry.get('file', 'local-file')
                        loc = entry.get('location', '')
                        loc_str = f"{file_ref}:{loc}" if loc else file_ref
                        # arise_nlp now reverse-maps the hashed staged filename
                        # back to the real URL + host it was loaded from (via the
                        # crawler's index.tsv). Prefer those so the finding names
                        # the actual site/asset instead of an opaque hash; fall
                        # back to the file path for older scans without the map.
                        src_url = entry.get('source_url', '')
                        n_host = entry.get('host', '') or file_ref
                        if src_url:
                            # Keep the staged file + line as corroboration so the
                            # analyst can open the exact local copy and line.
                            located_at = f"{src_url}:{loc}" if loc else src_url
                            match_loc = f"{located_at}  (staged: {loc_str})"
                        else:
                            located_at = loc_str
                            match_loc = loc_str
                        vulns.append({
                            'source': 'Content Scan (10.1)',
                            'template': n_type.replace('_', ' ').title(),
                            'severity': entry.get('severity', 'info'),
                            'host': n_host,
                            # 'url' is the one location-ish field the Attack-Surface
                            # tab's light list payload doesn't strip (see
                            # _VULN_HEAVY_FIELDS, which drops matched_at); set both
                            # so this finding renders correctly in whichever view.
                            'url': located_at,
                            'matched_at': match_loc,
                            'source_url': src_url,
                            'staged_file': loc_str,
                            'impact': entry.get('evidence', ''),
                            'remediation': entry.get('remediation', ''),
                            'confidence': entry.get('confidence'),
                            'detection_tool': 'arise_nlp',
                            'category': n_cat,
                        })
            except Exception as exc:
                logger.error("Failed to read nlp content findings %s: %s", nlp_file, exc)

        # Adaptive Endpoint Attack Loop findings (Module 27 — offensive/adaptive_loop.py).
        # Nuclei-shaped, differential-confirmed. `confirmed=True` = exploitation
        # proven; `confirmed=False` = observed (e.g. dangerous verbs, framework leak).
        loop_file = os.path.join(self.scan_dir, '27_adaptive_loop/loop_findings.jsonl')
        if os.path.exists(loop_file):
            try:
                with open(loop_file, 'r', errors='ignore') as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            entry = json.loads(line)
                        except Exception:
                            continue
                        info = entry.get('info', {}) if isinstance(entry.get('info'), dict) else {}
                        prov = entry.get('arise_provenance', {}) if isinstance(entry.get('arise_provenance'), dict) else {}
                        extracted = entry.get('extracted-results') or []
                        vulns.append({
                            'source': 'Adaptive Loop',
                            'template': info.get('name', entry.get('template-id', 'adaptive')),
                            'severity': info.get('severity', 'info'),
                            'host': entry.get('host', 'Unknown'),
                            'url': entry.get('matched-at', ''),
                            'impact': (extracted[0] if extracted else prov.get('why', '')),
                            'remediation': '',
                            'confidence': prov.get('confidence'),
                            'detection_tool': 'adaptive_loop',
                            'category': prov.get('lane', 'adaptive'),
                            'method': 'GET',
                            'confirmed': prov.get('confirmed'),
                            'proposed_by': prov.get('proposed_by'),
                        })
            except Exception as exc:
                logger.error("Failed to read adaptive loop findings %s: %s", loop_file, exc)

        # Subdomain takeover results (Module 21 — subjack)
        takeover_file = os.path.join(self.scan_dir, '21_subdomain_takeover/takeover_findings.jsonl')
        if os.path.exists(takeover_file):
            try:
                with open(takeover_file, 'r', errors='ignore') as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            entry = json.loads(line)
                        except Exception:
                            continue
                        vulns.append({
                            'source': 'Subdomain Takeover',
                            'template': entry.get('template', 'Subdomain Takeover'),
                            'severity': entry.get('severity', 'high'),
                            'host': entry.get('host', 'Unknown'),
                            'url': entry.get('url', ''),
                            'impact': entry.get('evidence', ''),
                            'remediation': entry.get('remediation', ''),
                            'detection_tool': 'subjack',
                            'detection_method': entry.get('detection_method', 'cname'),
                            'detection_label': entry.get('detection_label', 'Dangling CNAME'),
                            'service': entry.get('service', ''),
                            'cname': entry.get('cname', ''),
                            'dead_record': entry.get('dead_record', False),
                            'takeover_candidate': True,
                            'tags': entry.get('tags', []),
                        })
            except Exception as exc:
                logger.error("Failed to read takeover findings %s: %s", takeover_file, exc)

        # DNS security findings (Module 3C — dns_security_audit.py). Only
        # actionable severities land in the Vulns table; pure informational
        # inventory (SaaS/mail fingerprint, GeoDNS, IPv6 note) is surfaced in
        # the DNS tab's DNS Security panel instead, not here.
        dns_sec_file = os.path.join(self.scan_dir, '03c_dns_security/dns_security_findings.jsonl')
        if os.path.exists(dns_sec_file):
            try:
                with open(dns_sec_file, 'r', errors='ignore') as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            entry = json.loads(line)
                        except Exception:
                            continue
                        if entry.get('severity') not in ('critical', 'high', 'medium', 'low'):
                            continue
                        host = entry.get('host', 'Unknown')
                        vulns.append({
                            'source': 'DNS Security',
                            'template': entry.get('template', 'DNS security finding'),
                            'severity': entry.get('severity', 'low'),
                            'host': host,
                            'url': host,
                            'impact': entry.get('evidence', ''),
                            'remediation': entry.get('remediation', ''),
                            'detection_tool': 'dns_security_audit',
                            'check': entry.get('check'),
                            'takeover_candidate': entry.get('takeover_candidate', False),
                        })
            except Exception as exc:
                logger.error("Failed to read DNS security findings %s: %s", dns_sec_file, exc)

        # HSTS audit (Module 4b — tls/hsts_audit.py). Previously ONLY
        # surfaced in the dedicated HSTS tab (/api/hsts) — a high-severity
        # "no HTTP->HTTPS redirect" finding (real MITM/SSL-strip exposure)
        # never counted toward the risk score or Open Findings total. Mirrors
        # the DNS Security block above: only actionable severities land here;
        # 'info' (e.g. "not preload-eligible") stays HSTS-tab-only.
        hsts_file = os.path.join(self.scan_dir, '04_http_discovery/hsts_findings.jsonl')
        if os.path.exists(hsts_file):
            try:
                with open(hsts_file, 'r', errors='ignore') as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            entry = json.loads(line)
                        except Exception:
                            continue
                        h_type = entry.get('type', '')
                        if h_type.startswith('_meta_'):
                            continue
                        if entry.get('severity') not in ('critical', 'high', 'medium', 'low'):
                            continue
                        host = entry.get('host', 'Unknown')
                        ev = entry.get('evidence') or {}
                        ev_str = (', '.join(f'{k}={v}' for k, v in ev.items()
                                             if v not in (None, '', []))
                                  if isinstance(ev, dict) else str(ev))
                        vulns.append({
                            'source': 'HSTS Audit',
                            'template': h_type.replace('_', ' ').title() or 'HSTS finding',
                            'severity': entry.get('severity', 'low'),
                            'host': host,
                            'url': ev.get('url', host) if isinstance(ev, dict) else host,
                            'impact': ev_str,
                            'remediation': entry.get('remediation', ''),
                            'detection_tool': 'hsts_audit',
                            'check': h_type,
                        })
            except Exception as exc:
                logger.error("Failed to read HSTS findings %s: %s", hsts_file, exc)

        # MCP / AI surface findings (Module 8D — discovery/mcp_ai_probe.py).
        # Unauthenticated MCP servers, tool-poisoning/prompt-injection content,
        # open inference endpoints, cleartext/CORS posture. Mirrors the HSTS
        # block: actionable severities fold into the Vulns list (so they count
        # toward risk + Open Findings + the Issues queue); 'info' stays in the
        # dedicated files only.
        mcp_ai_file = os.path.join(self.scan_dir, '08_directory_discovery/mcp_ai_findings.jsonl')
        if os.path.exists(mcp_ai_file):
            try:
                with open(mcp_ai_file, 'r', errors='ignore') as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            entry = json.loads(line)
                        except Exception:
                            continue
                        if entry.get('severity') not in ('critical', 'high', 'medium', 'low'):
                            continue
                        host = entry.get('host', 'Unknown')
                        tax = entry.get('mst') or entry.get('owasp_llm') or ''
                        vulns.append({
                            'source': 'MCP/AI Probe',
                            'template': entry.get('title', 'MCP/AI finding'),
                            'severity': entry.get('severity', 'low'),
                            'host': host,
                            'url': entry.get('url', host),
                            'impact': entry.get('evidence', ''),
                            'remediation': entry.get('remediation', ''),
                            'detection_tool': 'mcp_ai_probe',
                            'check': tax,
                        })
            except Exception as exc:
                logger.error("Failed to read MCP/AI findings %s: %s", mcp_ai_file, exc)

        # 401/403 access-control bypasses (Module 8B / bypass_403.py)
        bypass_file = os.path.join(self.scan_dir, '08_directory_discovery/bypass_findings.jsonl')
        if os.path.exists(bypass_file):
            try:
                with open(bypass_file, 'r', errors='ignore') as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            entry = json.loads(line)
                        except Exception:
                            continue
                        if not entry.get('bypassed'):
                            continue
                        url = entry.get('url', 'Unknown')
                        code = entry.get('original_status')
                        vulns.append({
                            'source': 'Access Control Bypass',
                            'template': '%s bypass via %s' % (
                                code, entry.get('technique_category', 'bypass')),
                            'severity': entry.get('severity', 'high'),
                            'host': url,
                            'url': url,
                            'impact': entry.get('evidence', ''),
                            'remediation': entry.get('remediation', ''),
                            'detection_tool': 'bypass_403',
                            'check': entry.get('technique_category'),
                            'payload': entry.get('payload'),
                            'bypass_status': entry.get('bypass_status'),
                        })
            except Exception as exc:
                logger.error("Failed to read bypass findings %s: %s", bypass_file, exc)

        # HRS surface indicators (Module 8C / hrs_detect.py) — only surface the
        # ones worth manual verification (score > 40), as informational context.
        hrs_file = os.path.join(self.scan_dir, '08c_hrs_detect/hrs_findings.jsonl')
        if os.path.exists(hrs_file):
            try:
                with open(hrs_file, 'r', errors='ignore') as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            entry = json.loads(line)
                        except Exception:
                            continue
                        if int(entry.get('score', 0)) <= 40:
                            continue  # low/possible -> not surfaced as a finding
                        url = entry.get('url', 'Unknown')
                        vulns.append({
                            'source': 'HRS Surface (indicator)',
                            'template': 'Potential parser inconsistency (%s)' % entry.get('band', ''),
                            'severity': entry.get('severity', 'medium'),
                            'host': url,
                            'url': url,
                            'impact': entry.get('evidence', ''),
                            'remediation': entry.get('remediation', ''),
                            'detection_tool': 'hrs_detect',
                            'check': 'http_request_smuggling_surface',
                            'hrs_score': entry.get('score'),
                            'hrs_indicators': entry.get('indicators'),
                            'manual_verification': True,
                        })
            except Exception as exc:
                logger.error("Failed to read HRS findings %s: %s", hrs_file, exc)

        # Schema fingerprint probe (recon/schema_probe.py) — GraphQL/OpenAPI/
        # well-known discovery. Was written every scan but never read
        # anywhere: a public GraphQL introspection endpoint (a real schema
        # leak, not just recon) never reached the Vulns tab at all. Only the
        # two hit kinds worth surfacing as findings are included here —
        # bare 'graphql'/'well-known' hits are recon signal, not a finding,
        # same selectivity precedent as the HRS score-gate above.
        schema_file = os.path.join(self.scan_dir, '04_http_discovery/schema_endpoints.jsonl')
        if os.path.exists(schema_file):
            try:
                with open(schema_file, 'r', errors='ignore') as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            entry = json.loads(line)
                        except Exception:
                            continue
                        kind = entry.get('kind', '')
                        url = entry.get('url', 'Unknown')
                        host = entry.get('host', url)
                        if kind == 'graphql-introspection':
                            vulns.append({
                                'source': 'Schema Discovery',
                                'template': 'GraphQL Introspection Enabled',
                                'severity': entry.get('severity', 'high'),
                                'host': host,
                                'url': url,
                                'impact': ('Full GraphQL schema is readable by anyone — '
                                           'reveals every type/field/mutation, including '
                                           'ones with no UI path, and materially eases '
                                           'targeting of authz/BOLA and injection issues.'),
                                'remediation': ('Disable introspection in production '
                                                '(most GraphQL frameworks: a single config '
                                                'flag), or gate it behind authentication.'),
                                'detection_tool': 'schema_probe',
                                'check': 'graphql_introspection',
                                'evidence': entry.get('body_head', ''),
                            })
                        elif kind == 'openapi':
                            vulns.append({
                                'source': 'Schema Discovery',
                                'template': 'Exposed API Documentation (OpenAPI/Swagger)',
                                'severity': 'low',
                                'host': host,
                                'url': url,
                                'impact': ('A machine-readable API spec is publicly '
                                           'reachable, enumerating the full endpoint/'
                                           'parameter surface for an attacker.'),
                                'remediation': ('Confirm this is intended to be public; '
                                                'if not, require authentication for the '
                                                'docs/spec route.'),
                                'detection_tool': 'schema_probe',
                                'check': 'openapi_exposed',
                                'evidence': entry.get('evidence', ''),
                            })
            except Exception as exc:
                logger.error("Failed to read schema probe findings %s: %s", schema_file, exc)

        # Offensive AI Elevation Phase 1 — adopt the orphaned Autonomous findings
        # and reconcile cross-engine duplicates (one vuln = one row; agreement
        # raises confidence, not row count). Fail-open: any error leaves the
        # pre-reconcile list untouched so the vuln view is never broken by this.
        vulns = self._ingest_autonomous(vulns)
        vulns = self._ingest_ai_analyst(vulns)
        vulns = self._reconcile_cross_engine(vulns)
        return self._dedup_vulns(vulns)

    def _ingest_ai_analyst(self, vulns):
        """Merge AriseAI (AI red-team pentester) proven findings into the vuln
        list so they corroborate the other engines (one row, AI-badged) instead
        of living only in the AI Analyst panel. Fail-open."""
        try:
            from ai_analyst.integration import load_vuln_rows
            rows = load_vuln_rows(self.scan_dir, proven_only=True)
            if rows:
                logger.info("AriseAI: merged %d proven AI finding(s) into the vuln list", len(rows))
            return vulns + rows
        except Exception as exc:
            logger.error("AriseAI ingest skipped: %s", exc)
            return vulns

    def _ingest_autonomous(self, vulns):
        """Merge ai_autonomous.json confirmed findings into the vuln list so they
        stop floating in a separate side panel and can corroborate other engines."""
        path = os.path.join(self.scan_dir, 'ai_autonomous.json')
        if not os.path.exists(path):
            return vulns
        try:
            from offensive import finding_reconciler
            with open(path, 'r', errors='ignore') as fh:
                data = json.load(fh)
            adopted = finding_reconciler.from_autonomous(data)
            if adopted:
                logger.info("Reconciler: adopted %d autonomous finding(s) into the vuln list", len(adopted))
            return vulns + adopted
        except Exception as exc:
            logger.error("Autonomous ingest skipped (%s): %s", path, exc)
            return vulns

    @staticmethod
    def _reconcile_cross_engine(vulns):
        """Collapse cross-engine duplicates via offensive/finding_reconciler.
        Fail-open — returns the input unchanged on any error."""
        try:
            from offensive import finding_reconciler
            merged = finding_reconciler.reconcile(vulns)
            if isinstance(merged, list) and len(merged) <= len(vulns):
                collapsed = len(vulns) - len(merged)
                if collapsed:
                    logger.info("Reconciler: collapsed %d cross-engine duplicate(s)", collapsed)
                return merged
            return vulns
        except Exception as exc:
            logger.error("Cross-engine reconcile skipped: %s", exc)
            return vulns

    @staticmethod
    def _dedup_vulns(vulns):
        """Cross-source deduplication.

        Priority order when two sources report the same underlying issue on the
        same host: keep the one with richer evidence / higher severity.
        Sources that cover the same ground:
          - Nuclei vs Nuclei (Cloud): same template+host → keep the one with
            extracted_results/request/response (Cloud usually wins).
          - Cloud Exposure vs Secret Scan: same credential on same URL → merge
            into one, prefer the source with more detail.
          - DNS Security vs Subdomain Takeover on same host: different angles
            of the same DNS problem → keep both but tag as correlated.
        """
        SEV = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}

        # Pass 1: exact same-source dedup (unchanged)
        stage1 = []
        seen_exact = set()
        for v in vulns:
            key = (v.get('source'), v.get('template'), v.get('host'),
                   v.get('url'), v.get('impact'))
            if key not in seen_exact:
                seen_exact.add(key)
                stage1.append(v)

        # Pass 2: Nuclei vs Nuclei (Cloud) — same template+host+url
        nuclei_key = {}
        drop_idx = set()
        for i, v in enumerate(stage1):
            src = v.get('source', '')
            if src not in ('Nuclei', 'Nuclei (Cloud)'):
                continue
            k = (v.get('template', ''), v.get('host', ''), v.get('url', ''))
            if k in nuclei_key:
                j = nuclei_key[k]
                prev = stage1[j]
                prev_rich = bool(prev.get('extracted_results') or prev.get('request'))
                curr_rich = bool(v.get('extracted_results') or v.get('request'))
                if curr_rich and not prev_rich:
                    drop_idx.add(j)
                    nuclei_key[k] = i
                else:
                    drop_idx.add(i)
            else:
                nuclei_key[k] = i

        # Pass 3: Cloud Exposure vs Secret Scan — same credential on same URL
        cred_key = {}
        for i, v in enumerate(stage1):
            if i in drop_idx:
                continue
            src = v.get('source', '')
            if src not in ('Cloud Exposure', 'Secret Scan'):
                continue
            url = v.get('url', '')
            host = v.get('host', '')
            k = (host, url)
            if k in cred_key:
                j = cred_key[k]
                prev = stage1[j]
                prev_sev = SEV.get(prev.get('severity', 'info'), 0)
                curr_sev = SEV.get(v.get('severity', 'info'), 0)
                prev_detail = len(prev.get('impact', '') or '')
                curr_detail = len(v.get('impact', '') or '')
                if curr_sev > prev_sev or (curr_sev == prev_sev and curr_detail > prev_detail):
                    drop_idx.add(j)
                    cred_key[k] = i
                else:
                    drop_idx.add(i)
            else:
                cred_key[k] = i

        # Pass 4: DNS Security + Subdomain Takeover on same host — correlate
        takeover_hosts = set()
        for i, v in enumerate(stage1):
            if i in drop_idx:
                continue
            if v.get('source') == 'Subdomain Takeover':
                takeover_hosts.add(v.get('host', ''))
        for i, v in enumerate(stage1):
            if i in drop_idx:
                continue
            if v.get('source') == 'DNS Security' and v.get('host', '') in takeover_hosts:
                v['correlated_with'] = 'Subdomain Takeover'
                tags = v.get('tags') or []
                if 'correlated-takeover' not in tags:
                    tags.append('correlated-takeover')
                    v['tags'] = tags

        return [v for i, v in enumerate(stage1) if i not in drop_idx]
    
    def _parse_nuclei_result(self, data):
        """Parse nuclei JSON output into a finding rich enough for the detail panel.

        Nuclei's real evidence lives in fields the old parser threw away:
        extracted-results (the actual matched secret/token), matcher-name,
        description, request/response, curl-command, references, tags, CVSS.
        Without these the side panel is blank for any template that has no
        info.impact/info.remediation (e.g. credentials-disclosure)."""
        try:
            info = data.get('info', {}) or {}
            severity = (info.get('severity', 'info') or 'info').lower()
            cls = info.get('classification', {}) or {}

            # references / tags may be a list or a comma string
            refs = info.get('reference') or []
            if isinstance(refs, str):
                refs = [r.strip() for r in re.split(r'[,\n]', refs) if r.strip()]
            tags = info.get('tags') or []
            if isinstance(tags, str):
                tags = [t.strip() for t in tags.split(',') if t.strip()]

            # cwe-id may be ["cwe-200"] or "CWE-200"
            cwe = cls.get('cwe-id') or []
            if isinstance(cwe, str):
                cwe = [cwe]
            cwe_str = ', '.join(str(c).upper() for c in cwe) if cwe else ''

            extracted = data.get('extracted-results') or data.get('extracted_results') or []
            if isinstance(extracted, str):
                extracted = [extracted]

            # Response/request bodies can be huge (e.g. metrics pages) — cap them
            # so the /api payload stays small but the evidence is still visible.
            req = (data.get('request') or '')[:2500]
            resp = (data.get('response') or '')[:4000]

            return {
                'source': 'Nuclei',
                'template': info.get('name', 'Unknown'),
                'template_id': data.get('template-id', ''),
                'severity': severity,
                'host': data.get('host', 'Unknown'),
                'url': data.get('matched-at', data.get('url', '')),
                'matched_at': data.get('matched-at', ''),
                'matcher_name': data.get('matcher-name', '') or '',
                'extracted_results': extracted,
                'description': info.get('description', '') or '',
                'impact': info.get('impact', '') or '',
                'remediation': info.get('remediation', '') or '',
                'reference': refs,
                'tags': tags,
                'nuclei_type': data.get('type', '') or '',
                'request': req,
                'response': resp,
                'curl_command': data.get('curl-command', '') or '',
                'cve_id': cls.get('cve-id'),
                'cwe': cwe_str,
                'cvss_score': cls.get('cvss-score'),
                'cvss_metrics': cls.get('cvss-metrics', '') or '',
            }
        except Exception as exc:
            logger.error("Failed to parse nuclei result: %s", exc)
            return None
    
    def load_http_status(self):
        """Backfill http_status from httpx output when manifest is missing it."""
        http_file = os.path.join(self.scan_dir, '04_http_discovery/http_confirmed.json')
        result = {}
        if not os.path.exists(http_file):
            return result
        try:
            with open(http_file, 'r', errors='ignore') as f:
                for line in f:
                    try:
                        entry = json.loads(line.strip())
                        host = entry.get('host') or entry.get('input')
                        status = entry.get('status_code')
                        if host and status:
                            result[host] = int(status)
                    except Exception:
                        continue
        except Exception as exc:
            logger.error("Failed to read http_confirmed.json: %s", exc)
        return result

    def aggregate_host_data(self, manifest, ports_data, services, vulns):
        """Merge all data sources for each host"""
        hosts = {}

        for host, host_data in manifest.get('hosts', {}).items():
            hosts[host] = dict(host_data)
            # Manifest can carry explicit None placeholders for hosts that
            # recon seeded but downstream modules never populated (e.g. a
            # CDN-fronted host where naabu found 0 open ports). dict.get(k, [])
            # does NOT substitute the default when the value is None, so
            # downstream iteration/int-coerce blows up. Normalize once here.
            if hosts[host].get('ports_open') is None:
                hosts[host]['ports_open'] = []
            if hosts[host].get('services') is None:
                hosts[host]['services'] = []

        for host, ports in ports_data.items():
            if host not in hosts:
                hosts[host] = {}
            hosts[host]['ports_open'] = sorted(set(ports))

        for host, svc_list in services.items():
            if host not in hosts:
                hosts[host] = {}
            hosts[host]['services'] = svc_list

        # Backfill http_status from httpx output for scans where the manifest is missing it
        http_status_map = self.load_http_status()
        for host, status in http_status_map.items():
            if host in hosts and not hosts[host].get('http_status'):
                hosts[host]['http_status'] = status
                hosts[host]['has_webapp'] = True

        # Compute per-host risk scores
        compute_risk_scores(hosts, vulns)

        return hosts


# ===========================================================================
# RISK SCORING ENGINE
# ===========================================================================

def compute_host_risk(host, host_data, host_vulns):
    """Compute a 0-100 host risk score across six weighted domains.

    Domains (raw caps; total clamped to 100):
      Vulnerability Exposure  35 — confirmed CVEs, nuclei findings, XSS
      Credential / Secret     25 — leaked keys, tokens, passwords in JS/repos
      Infrastructure Posture  20 — exposed ports, missing WAF, weak headers, cookies
      SSL / Domain Integrity  10 — dangling certs, missing SSL
      Attack Surface Breadth  10 — port count, service diversity, no-CDN exposure
      Cloud Exposure          40 — weighted cloud findings (base x exploitability x exposure)

    The cloud domain is additive and can drive a single host to critical on its
    own (e.g. a public bucket or leaked cloud credential), reflecting the blast
    radius of cloud-native exposures.
    """
    has_http = bool(host_data.get('http_status'))
    waf_vendor = (host_data.get('waf_vendor') or '').lower()
    has_waf = waf_vendor not in ('none', '')
    open_ports = set(int(p) for p in host_data.get('ports_open', []))
    header_score = host_data.get('security_header_score', 0)

    # ── Domain 1: Vulnerability Exposure (0-35) ──
    vuln_domain = 0.0
    non_secret_vulns = [v for v in host_vulns if v.get('source') not in ('Secret Scan', 'SQLi Testing', 'Cloud Exposure')]
    sqli_hits = [v for v in host_vulns if v.get('source') == 'SQLi Testing']
    if non_secret_vulns or sqli_hits:
        raw = 0
        for v in non_secret_vulns:
            raw += SEVERITY_WEIGHTS.get(v.get('severity', 'info'), 0)
        # Confirmed SQLi = direct DB access; weight higher than generic nuclei finding
        for v in sqli_hits:
            confidence = v.get('confidence', 'medium')
            raw += 50 if confidence == 'high' else 30
        vuln_domain = min(raw / 80.0, 1.0) * 35

    # ── Domain 2: Credential / Secret / Data Access Exposure (0-25) ──
    secret_domain = 0.0
    secrets = [v for v in host_vulns if v.get('source') == 'Secret Scan']
    lfi_hits = [v for v in host_vulns if v.get('source') == 'Param Fuzzing']
    # Respect the validation ladder: only VALIDATED-LIVE keys (high/critical) are
    # catastrophic. A restricted (medium) key is live-but-fenced -> moderate. An
    # invalid/unsupported key (info/low) must NOT spike the host score.
    def _sev(v):
        return str(v.get('severity', '')).lower()
    live_secrets = [v for v in secrets if _sev(v) in ('critical', 'high')]
    restricted_secrets = [v for v in secrets if _sev(v) == 'medium']
    if live_secrets or restricted_secrets or lfi_hits or sqli_hits:
        secret_raw = 0.0
        # First LIVE secret is catastrophic (70%), each additional adds diminishing impact.
        if live_secrets:
            secret_raw = 0.7 + min(len(live_secrets) - 1, 5) * 0.06
        elif restricted_secrets:
            # Live but scope/network-fenced -> real, but not full-blast catastrophic.
            secret_raw = 0.35 + min(len(restricted_secrets) - 1, 5) * 0.04
        # LFI = file read primitive, nearly as severe
        if lfi_hits:
            secret_raw = max(secret_raw, 0.5) + min(len(lfi_hits), 3) * 0.1
        # SQLi = potential full DB dump; high-confidence SQLi is near-secret severity
        if sqli_hits:
            high_conf = sum(1 for v in sqli_hits if v.get('confidence') == 'high')
            med_conf = len(sqli_hits) - high_conf
            sqli_raw = high_conf * 0.6 + med_conf * 0.3
            secret_raw = max(secret_raw, 0.0) + min(sqli_raw, 0.8)
        secret_domain = min(secret_raw, 1.0) * 25

    # ── Domain 3: Infrastructure Posture (0-20) ──
    posture_domain = 0.0
    posture_deductions = 0.0

    # Exposed data stores (tier 1) — direct unauthenticated access risk
    tier1_exposed = open_ports & PORT_RISK_TIER1
    posture_deductions += len(tier1_exposed) * 0.20

    # Exposed databases (tier 2) — auth-gated but still shouldn't be public
    tier2_exposed = open_ports & PORT_RISK_TIER2
    posture_deductions += len(tier2_exposed) * 0.12

    # Exposed management/legacy (tier 3)
    tier3_exposed = open_ports & PORT_RISK_TIER3
    posture_deductions += len(tier3_exposed) * 0.06

    # Missing WAF on an internet-facing web app
    if has_http and not has_waf:
        posture_deductions += 0.15

    # Weak security headers (scale: 0/6 = full penalty, 6/6 = none)
    if has_http:
        posture_deductions += (1.0 - header_score / 6.0) * 0.15

    # Cookie security issues
    cookie_issues = host_data.get('cookie_issues', [])
    if cookie_issues:
        posture_deductions += min(len(cookie_issues), 3) * 0.05

    posture_domain = min(posture_deductions, 1.0) * 20

    # ── Domain 4: SSL / Domain Integrity (0-10) ──
    ssl_domain = 0.0
    ssl_checked = host_data.get('ssl_checked', False)

    if ssl_checked:
        if host_data.get('ssl_dangling', False):
            # Dangling domain — full subdomain takeover risk
            ssl_domain = 10.0
    elif has_http:
        url = host_data.get('url', '')
        if url.startswith('https'):
            # HTTPS URL but SSL check failed (handshake error, expired, etc.)
            ssl_domain = 6.0
        elif not url.startswith('https'):
            # HTTP-only, no TLS at all
            ssl_domain = 4.0

    # ── Domain 5: Attack Surface Breadth (0-10) ──
    breadth_domain = 0.0
    port_count = len(open_ports)
    if port_count > 0:
        # More open ports = wider attack surface. 1-2 is normal, 10+ is excessive.
        breadth_domain += min(port_count / 15.0, 0.5) * 10

    # Non-HTTP services increase attack surface complexity
    services = host_data.get('services', [])
    non_http_services = [s for s in services if s.get('name') not in ('http', 'https', 'tcpwrapped', 'unknown', '')]
    if non_http_services:
        breadth_domain += min(len(non_http_services) / 5.0, 0.3) * 10

    # Internet-facing without CDN = direct IP exposure
    if has_http and not host_data.get('cdn', False) and not has_waf:
        breadth_domain += 0.2 * 10

    breadth_domain = min(breadth_domain, 10.0)

    # ── Domain 6: Cloud Attack Surface Exposure (0-40) ──
    # Fed by the weighted cloud model (base_weight x exploitability x exposure).
    # A single max-weight finding (public bucket, leaked creds) can alone drive
    # a host to critical; additional findings add with diminishing returns.
    cloud_domain = 0.0
    cloud_hits = [v for v in host_vulns if v.get('source') == 'Cloud Exposure']
    if cloud_hits:
        cloud_scores = sorted((v.get('weighted_score') or 0) for v in cloud_hits)
        cloud_scores.reverse()
        top = cloud_scores[0]
        rest = sum(cloud_scores[1:])
        cloud_raw = top + 0.25 * rest
        cloud_domain = min(cloud_raw / 100.0, 1.0) * 40

    total = vuln_domain + secret_domain + posture_domain + ssl_domain + breadth_domain + cloud_domain
    return max(0, min(int(round(total)), 100))


def risk_band(score):
    if score >= 70:
        return 'critical'
    if score >= 45:
        return 'high'
    if score >= 20:
        return 'medium'
    return 'low'


def risk_grade(org_score):
    if org_score <= 10:
        return 'A'
    if org_score <= 20:
        return 'B'
    if org_score <= 35:
        return 'C'
    if org_score <= 55:
        return 'D'
    return 'F'


def compute_risk_scores(hosts, vulns):
    """Mutates hosts dict to add risk_score, risk_band, and domain breakdown."""
    host_vulns = {}
    for v in vulns:
        h = v.get('host', 'Unknown')
        host_vulns.setdefault(h, []).append(v)
        url = v.get('url', '')
        if url:
            try:
                url_host = url.split('//')[1].split('/')[0].split(':')[0]
                if url_host != h:
                    host_vulns.setdefault(url_host, []).append(v)
            except Exception:
                pass

    for host, host_data in hosts.items():
        hv = host_vulns.get(host, [])
        score = compute_host_risk(host, host_data, hv)
        host_data['risk_score'] = score
        host_data['risk_band'] = risk_band(score)


def compute_org_risk(hosts):
    """Org-level risk: weighted top-N with concentration and breadth penalties.

    A CRO cares about: worst-case exposure (top hosts), how concentrated the
    risk is (many critical hosts vs one), and what fraction of the surface is
    exposed (breadth ratio).
    """
    scores = sorted([h.get('risk_score', 0) for h in hosts.values()], reverse=True)
    if not scores:
        return 0, 'A'

    total_hosts = len(scores)

    # Base: weighted average of top 20% (min 3 hosts) — worst-case exposure
    top_n = max(3, total_hosts // 5)
    top_scores = scores[:top_n]
    base = sum(top_scores) / len(top_scores)

    # Concentration penalty: multiple critical hosts compound org risk
    critical_count = sum(1 for s in scores if s >= 70)
    high_count = sum(1 for s in scores if 45 <= s < 70)
    concentration = min(critical_count * 4 + high_count * 1.5, 25)

    # Breadth penalty: what % of hosts carry material risk (score >= 20)
    at_risk = sum(1 for s in scores if s >= 20)
    breadth_ratio = at_risk / total_hosts if total_hosts else 0
    breadth_penalty = breadth_ratio * 10

    # Dangling domain penalty: each dangling sub is a takeover vector
    dangling_count = sum(1 for h in hosts.values() if h.get('ssl_dangling'))
    dangling_penalty = min(dangling_count * 3, 10)

    org_score = max(0, min(int(round(base + concentration + breadth_penalty + dangling_penalty)), 100))
    return org_score, risk_grade(org_score)


# ===========================================================================
# DATA ACCESS LAYER
# ===========================================================================

import re as _re
_SCAN_TS_SUFFIX = _re.compile(r'-\d{6}-\d{4}$')

def _target_from_scan_id(scan_id):
    """Extract the base target from a scan directory name like 'quince.com-150726-0230'."""
    return _SCAN_TS_SUFFIX.sub('', scan_id)


_UNVIABLE_SCAN_STATUSES = {'stalled', 'failed'}


def _pick_best_scan(scans):
    """Prefer the newest scan that actually finished (or is genuinely still
    running) over a newer one whose process died mid-run. A killed scan's
    directory can be the most recent by timestamp while holding only
    partial/empty data — silently serving it as "Latest" shows broken data
    with no indication anything is wrong. Falls back to the newest overall
    if every scan for this target is unviable (nothing better to show)."""
    for scan in scans:
        if scan.get('status') not in _UNVIABLE_SCAN_STATUSES:
            return scan
    return scans[0] if scans else None


def get_latest_scan_id():
    """Return the newest viable scan folder id, or None if nothing exists."""
    best = _pick_best_scan(get_available_scans())
    return best['id'] if best else None


def resolve_target(scan_id):
    """Resolve scan folder id from scan id, target name, or empty latest selection."""
    if not scan_id:
        return get_latest_scan_id()

    scan_dir = os.path.join(BASE_SCAN_DIR, scan_id)
    if os.path.isdir(scan_dir):
        return scan_id

    target_scans = get_scans_for_target(scan_id)
    best = _pick_best_scan(target_scans)
    return best['id'] if best else scan_id


def _cache_key(scan_id):
    return scan_id


def get_cached_scan_data(scan_id):
    """Return cached scan data when fresh enough.

    Uses a per-scan lock so only one thread re-parses when the cache
    expires — the rest wait and reuse the fresh result (thundering-herd guard).
    """
    cache_key = _cache_key(scan_id)
    entry = _SCAN_CACHE.get(cache_key)
    now = time.time()
    if entry and (now - entry.get('timestamp', 0) < CACHE_TIMEOUT):
        return entry['data']

    with _SCAN_CACHE_LOCKS_GUARD:
        if cache_key not in _SCAN_CACHE_LOCKS:
            _SCAN_CACHE_LOCKS[cache_key] = threading.Lock()
        lock = _SCAN_CACHE_LOCKS[cache_key]

    with lock:
        entry = _SCAN_CACHE.get(cache_key)
        now = time.time()
        if entry and (now - entry.get('timestamp', 0) < CACHE_TIMEOUT):
            return entry['data']
        data = get_scan_data(scan_id, use_cache=False)
        if data:
            _SCAN_CACHE[cache_key] = {'timestamp': now, 'data': data}
        return data


def _get_cached_only(scan_id):
    """Return scan data ONLY if already in cache — never triggers a cold load."""
    if not scan_id:
        return None
    entry = _SCAN_CACHE.get(_cache_key(scan_id))
    if entry and (time.time() - entry.get('timestamp', 0) < CACHE_TIMEOUT):
        return entry['data']
    return None


def get_available_scans(use_cache=True):
    """List all completed scans"""
    now = time.time()
    if use_cache and _SCAN_INDEX_CACHE['scans'] and now - _SCAN_INDEX_CACHE['timestamp'] < CACHE_TIMEOUT:
        return _SCAN_INDEX_CACHE['scans']

    scans = []
    
    if not os.path.exists(BASE_SCAN_DIR):
        return scans
    
    for item in sorted(os.listdir(BASE_SCAN_DIR), reverse=True):
        item_path = os.path.join(BASE_SCAN_DIR, item)
        if not os.path.isdir(item_path):
            continue
        
        manifest_file = os.path.join(item_path, 'manifest.json')
        if not os.path.exists(manifest_file):
            continue
        
        try:
            with open(manifest_file, 'r') as f:
                manifest = json.load(f)

            pipeline_info = manifest.get('pipeline_info', {})
            stats = manifest.get('statistics', {})

            start_time = pipeline_info.get('start_time', '')
            target = pipeline_info.get('target') or _target_from_scan_id(item)
            scans.append({
                'id': item,
                'name': target,
                'target': target,
                'status': pipeline_info.get('status', 'unknown'),
                'start_time': start_time,
                'end_time': stats.get('end_time', pipeline_info.get('end_time', '')),
                'scan_time_sort': scan_time_key(start_time, os.path.getmtime(item_path)),
                'total_hosts': stats.get('total_hosts', 0),
                'http_hosts': stats.get('http_hosts', 0),
                'waf_hosts': stats.get('waf_hosts', 0),
                'total_ports': stats.get('total_ports', stats.get('open_ports', 0))
            })
        except Exception as exc:
            logger.error("Failed to read scan manifest %s: %s", manifest_file, exc)

    scans.sort(key=lambda scan: scan.get('scan_time_sort', 0), reverse=True)
    _reconcile_stale_running(scans)
    _SCAN_INDEX_CACHE['timestamp'] = now
    _SCAN_INDEX_CACHE['scans'] = scans
    return scans


# The longest real completed scan on record is ~20.5h (jungleerummy.com,
# a very large target). This is set well above that (2.3x) so it never
# flags a legitimately slow-but-alive scan, while still safely catching
# everything actually stuck (most stale entries are weeks old).
_STALE_RUNNING_HOURS = 48


def _reconcile_stale_running(scans):
    """Overlay reality onto scans whose manifest still says 'running'.

    A scan's manifest.json is written by the pipeline shell script itself —
    if that process is killed externally (SIGKILL, machine sleep, terminal
    closed) instead of exiting normally, nothing ever comes back to patch
    it, so it shows 'running' forever even though the process is long dead.
    Two independent signals correct this for display, in order:

    1. arise_jobs' own registry reconciles PID liveness on every read
       (arise_jobs._reconcile) for scans launched through it — when a
       matching job is found to have actually died, prefer that truth.
       Job ids and scan-directory names are stamped independently, a few
       seconds apart, by two different processes (Python launches the job;
       the shell script computes its own directory timestamp moments later
       after its own preflight work) — so they're correlated by closest
       start time for the same target rather than an exact id match.

    2. Most historical scans predate the job registry entirely (launched
       by a direct shell invocation, not through arise_jobs.launch), so
       there's no job to correlate against at all. For those, a 'running'
       scan whose start_time is implausibly old is just as dead — nothing
       in this pipeline's history has ever run anywhere close to
       _STALE_RUNNING_HOURS, so age alone is a safe signal here.
    """
    running = [s for s in scans if s.get('status') == 'running']
    if not running:
        return

    try:
        jobs = arise_jobs.list_jobs()
    except Exception:
        jobs = []

    MATCH_WINDOW_SECONDS = 300  # generous — covers pipeline startup/preflight time
    now = time.time()
    for scan in running:
        scan_ts = scan_time_key(scan.get('start_time'))
        if not scan_ts:
            continue

        best_job, best_delta = None, None
        for job in jobs:
            if job.get('target') != scan.get('target'):
                continue
            job_ts = scan_time_key(job.get('started_at'))
            if not job_ts:
                continue
            delta = abs(scan_ts - job_ts)
            if delta <= MATCH_WINDOW_SECONDS and (best_delta is None or delta < best_delta):
                best_job, best_delta = job, delta

        if best_job and best_job.get('status') == 'failed':
            scan['status'] = 'stalled'
            scan['status_note'] = best_job.get('note') or 'Process ended unexpectedly — scan did not finish normally.'
        elif not best_job and (now - scan_ts) > _STALE_RUNNING_HOURS * 3600:
            scan['status'] = 'stalled'
            scan['status_note'] = (f'No matching job found and started over '
                                   f'{_STALE_RUNNING_HOURS}h ago — presumed dead.')


def get_scans_for_target(target):
    """Return all scans belonging to a target name, newest first."""
    return [scan for scan in get_available_scans() if scan.get('target') == target or scan.get('name') == target]


def get_target_summaries():
    """Group revisions by target so the UI behaves like an EASM monitor."""
    grouped = {}
    for scan in get_available_scans():
        target = scan.get('target') or scan.get('name') or scan['id']
        grouped.setdefault(target, []).append(scan)

    targets = []
    for target, scans in grouped.items():
        scans.sort(key=lambda scan: scan.get('scan_time_sort', 0), reverse=True)
        # Pick the newest viable scan, not just the newest by timestamp — a
        # killed/crashed run can be more recent than the last real result.
        # "Previous" is whatever comes right before it chronologically (for
        # diffing), not index 1, since a skipped unviable scan would
        # otherwise be reported as "previous" even though it's newer.
        latest_idx = 0
        for i, s in enumerate(scans):
            if s.get('status') not in _UNVIABLE_SCAN_STATUSES:
                latest_idx = i
                break
        latest = scans[latest_idx]
        previous = scans[latest_idx + 1] if latest_idx + 1 < len(scans) else None
        targets.append({
            'id': target,
            'name': target,
            'target': target,
            'status': latest.get('status', 'unknown'),
            'scan_id': latest['id'],
            'latest_scan_id': latest['id'],
            'previous_scan_id': previous['id'] if previous else None,
            'revision_count': len(scans),
            'start_time': latest.get('start_time', ''),
            'total_hosts': latest.get('total_hosts', 0),
            'http_hosts': latest.get('http_hosts', 0),
            'waf_hosts': latest.get('waf_hosts', 0),
            'total_ports': latest.get('total_ports', 0)
        })

    targets.sort(key=lambda target: scan_time_key(target.get('start_time')), reverse=True)
    return targets

def get_scan_data(scan_id, use_cache=True):
    """Get complete data for a scan"""
    scan_dir = os.path.join(BASE_SCAN_DIR, scan_id)
    
    if not os.path.isdir(scan_dir):
        return None

    if use_cache:
        cache_key = _cache_key(scan_id)
        entry = _SCAN_CACHE.get(cache_key)
        now = time.time()
        if entry and (now - entry.get('timestamp', 0) < CACHE_TIMEOUT):
            return entry['data']
    
    pipeline = ScanDataPipeline(scan_dir)
    manifest = pipeline.load_manifest()
    ports_data = pipeline.load_port_data()
    services = pipeline.load_service_data()
    vulns = pipeline.load_vulnerabilities()
    hosts = pipeline.aggregate_host_data(manifest, ports_data, services, vulns)
    
    port_scan_status = pipeline.get_port_scan_status()

    data = {
        'id': scan_id,
        'manifest': manifest,
        'hosts': hosts,
        'ports_data': ports_data,
        'services': services,
        'vulnerabilities': vulns,
        'pipeline_info': manifest.get('pipeline_info', {}),
        'statistics': manifest.get('statistics', {}),
        'port_scan_status': port_scan_status
    }
    if use_cache:
        _SCAN_CACHE[_cache_key(scan_id)] = {'timestamp': time.time(), 'data': data}
    return data


def get_previous_scan_id(scan_id):
    data = get_cached_scan_data(scan_id)
    if not data:
        return None
    target = data.get('pipeline_info', {}).get('target')
    if not target:
        return None
    scans = get_scans_for_target(target)
    for index, scan in enumerate(scans):
        if scan['id'] == scan_id and index + 1 < len(scans):
            return scans[index + 1]['id']
    return None


def _port_set(data):
    ports = set()
    for host, host_data in data.get('hosts', {}).items():
        for port in host_data.get('ports_open', []):
            try:
                ports.add(f"{host}:{int(port)}")
            except Exception:
                continue
    return ports


def _vuln_key(vuln):
    return '|'.join(str(vuln.get(field, '')) for field in ('source', 'template', 'host', 'url', 'severity'))


def compare_scans(current_scan_id, previous_scan_id=None):
    current = get_cached_scan_data(current_scan_id)
    if not current:
        return {}

    previous_scan_id = previous_scan_id or get_previous_scan_id(current_scan_id)
    previous = get_cached_scan_data(previous_scan_id) if previous_scan_id else None

    current_hosts = set(current.get('hosts', {}).keys())
    current_ports = _port_set(current)
    current_vulns = {_vuln_key(v): v for v in current.get('vulnerabilities', [])}

    if not previous:
        return {
            'target': current.get('pipeline_info', {}).get('target', current_scan_id),
            'current_scan_id': current_scan_id,
            'previous_scan_id': None,
            'has_baseline': False,
            'summary': {
                'new_hosts': len(current_hosts),
                'removed_hosts': 0,
                'new_ports': len(current_ports),
                'removed_ports': 0,
                'new_vulnerabilities': len(current_vulns),
                'removed_vulnerabilities': 0
            },
            'hosts': {'added': sorted(current_hosts), 'removed': []},
            'ports': {'added': sorted(current_ports), 'removed': []},
            'vulnerabilities': {'added': list(current_vulns.values()), 'removed': []}
        }

    previous_hosts = set(previous.get('hosts', {}).keys())
    previous_ports = _port_set(previous)
    previous_vulns = {_vuln_key(v): v for v in previous.get('vulnerabilities', [])}

    added_hosts = sorted(current_hosts - previous_hosts)
    removed_hosts = sorted(previous_hosts - current_hosts)
    added_ports = sorted(current_ports - previous_ports)
    removed_ports = sorted(previous_ports - current_ports)
    added_vuln_keys = sorted(set(current_vulns) - set(previous_vulns))
    removed_vuln_keys = sorted(set(previous_vulns) - set(current_vulns))

    return {
        'target': current.get('pipeline_info', {}).get('target', current_scan_id),
        'current_scan_id': current_scan_id,
        'previous_scan_id': previous_scan_id,
        'has_baseline': True,
        'summary': {
            'new_hosts': len(added_hosts),
            'removed_hosts': len(removed_hosts),
            'new_ports': len(added_ports),
            'removed_ports': len(removed_ports),
            'new_vulnerabilities': len(added_vuln_keys),
            'removed_vulnerabilities': len(removed_vuln_keys)
        },
        'hosts': {'added': added_hosts, 'removed': removed_hosts},
        'ports': {'added': added_ports, 'removed': removed_ports},
        'vulnerabilities': {
            'added': [current_vulns[key] for key in added_vuln_keys],
            'removed': [previous_vulns[key] for key in removed_vuln_keys]
        }
    }

# ===========================================================================
# API ROUTES
# ===========================================================================

@app.route('/')
def dashboard():
    """Main dashboard page"""
    return render_template('dashboard.html', arise_role=(session.get('role') or 'admin'))

@app.route('/kt')
def knowledge_transfer():
    """Knowledge Transfer document for ARISE EASM"""
    return render_template('kt.html')

@app.route('/api/scans')
def api_scans():
    """List all available scans"""
    scans = get_available_scans()
    return jsonify(scans)


@app.route('/api/targets/history')
def api_target_history():
    target = request.args.get('target')
    scans = get_scans_for_target(target) if target else []
    if not scans:
        scan_id = resolve_target(target)
        data = get_cached_scan_data(scan_id) if scan_id else None
        resolved = data.get('pipeline_info', {}).get('target') if data else None
        if resolved and resolved != target:
            scans = get_scans_for_target(resolved)
    return jsonify(scans)


@app.route('/api/compare')
def api_compare():
    scan_id = resolve_target(request.args.get('target'))
    previous = request.args.get('previous')
    if not scan_id:
        return jsonify({})
    return jsonify(compare_scans(scan_id, previous))

@app.route('/api/scan/<scan_id>')
def api_scan(scan_id):
    """Get complete scan data"""
    data = get_cached_scan_data(scan_id)
    
    if not data:
        return jsonify({'error': 'Scan not found'}), 404
    
    return jsonify({
        'id': data['id'],
        'pipeline_info': data['pipeline_info'],
        'statistics': data['statistics'],
        'hosts_count': len(data['hosts']),
        'ports_count': len(data['ports_data']),
        'vulnerabilities_count': len(data['vulnerabilities'])
    })

@app.route('/api/scan/<scan_id>/hosts')
def api_hosts(scan_id):
    """Get hosts for a scan"""
    data = get_cached_scan_data(scan_id)
    
    if not data:
        return jsonify([]), 404
    
    hosts_list = []
    for host, host_data in data['hosts'].items():
        ip = host_data.get('ip', '')
        is_cdn = host_data.get('cdn', False)
        waf = host_data.get('waf_vendor', 'none') or 'none'
        has_waf = waf.lower() not in ('none', '', 'unknown')
        # origin_ip: always the resolved IP, but we flag whether it is a true
        # direct origin (not shielded) or a CDN/WAF edge node.
        hosts_list.append({
            'name': host,
            'ip': ip,
            'origin_ip': ip,
            'origin_ip_direct': ip and not is_cdn and not has_waf,
            'resolved': host_data.get('resolved', False),
            'http_status': host_data.get('http_status', ''),
            'waf_vendor': waf,
            'security_score': host_data.get('security_header_score', 0),
            'ports': sorted(host_data.get('ports_open', [])),
            'services': host_data.get('services', []),
            'cdn': is_cdn,
            'risk_score': host_data.get('risk_score', 0),
            'risk_band': host_data.get('risk_band', 'low')
        })

    return jsonify(hosts_list)

@app.route('/api/scan/<scan_id>/ports')
def api_ports(scan_id):
    """Get ports for a scan, excluding CDN and WAF IPs"""
    data = get_cached_scan_data(scan_id)

    if not data:
        return jsonify([]), 404

    # Group by port, excluding CDN and WAF IPs
    port_map = {}
    for host, ports in data['ports_data'].items():
        host_info = data['hosts'].get(host, {})
        # Skip if host is behind CDN or WAF
        if host_info.get('cdn') or host_info.get('waf_vendor') not in (None, 'none', ''):
            continue

        for port in ports:
            port_num = int(port)
            if port_num not in port_map:
                port_map[port_num] = {
                    'port': port_num,
                    'service': PORT_MAPPINGS.get(port_num, 'Unknown'),
                    'hosts': []
                }
            port_map[port_num]['hosts'].append({
                'host': host,
                'ip': data['hosts'].get(host, {}).get('ip', ''),
                'http_status': data['hosts'].get(host, {}).get('http_status', '')
            })

    # Sort by port number
    result = [port_map[p] for p in sorted(port_map.keys())]
    return jsonify(result)

_VULN_HEAVY_FIELDS = {'response', 'request', 'curl_command', 'description',
                      'matched_at', 'extracted_results', 'reference'}


@app.route('/api/scan/<scan_id>/vulnerabilities')
def api_vulnerabilities(scan_id):
    """Get vulnerabilities for a scan (heavy evidence fields stripped for speed)."""
    data = get_cached_scan_data(scan_id)

    if not data:
        return jsonify([]), 404

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    vulns = sorted(
        data['vulnerabilities'],
        key=lambda x: severity_order.get(x.get('severity', 'info'), 4)
    )

    # Strip heavy evidence fields from the list payload; the front-end
    # loads them on demand via /api/scan/<id>/vulnerability/<idx>.
    light = []
    for idx, v in enumerate(vulns):
        rec = {k: val for k, val in v.items() if k not in _VULN_HEAVY_FIELDS}
        rec['_idx'] = idx
        light.append(rec)
    return jsonify(light)


@app.route('/api/scan/<scan_id>/vulnerability/<int:idx>')
def api_vulnerability_detail(scan_id, idx):
    """Return full detail (including evidence) for one vulnerability."""
    data = get_cached_scan_data(scan_id)
    if not data:
        return jsonify({'error': 'Scan not found.'}), 404

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    vulns = sorted(
        data['vulnerabilities'],
        key=lambda x: severity_order.get(x.get('severity', 'info'), 4)
    )
    if idx < 0 or idx >= len(vulns):
        return jsonify({'error': 'Index out of range.'}), 404
    return jsonify(vulns[idx])

@app.route('/api/scan/<scan_id>/statistics')
def api_statistics(scan_id):
    """Get statistics for a scan"""
    data = get_cached_scan_data(scan_id)
    
    if not data:
        return jsonify({}), 404
    
    hosts = data['hosts']
    
    return jsonify({
        'total_hosts': len(hosts),
        'resolved_hosts': sum(1 for h in hosts.values() if h.get('resolved')),
        'http_hosts': sum(1 for h in hosts.values() if h.get('http_status')),
        'waf_hosts': sum(1 for h in hosts.values() if h.get('waf_vendor') != 'none'),
        'cdn_hosts': sum(1 for h in hosts.values() if h.get('cdn')),
        'total_vulnerabilities': len(data['vulnerabilities']),
        'total_ports': sum(len(h.get('ports_open', [])) for h in hosts.values()),
        'non_http_services': sum(1 for h in hosts.values() if h.get('services')),
        'port_scan_status': data.get('port_scan_status', 'missing')
    })

@app.route('/api/scan/<scan_id>/modules')
def api_modules(scan_id):
    """Get module status for a scan"""
    scan_dir = os.path.join(BASE_SCAN_DIR, scan_id)
    
    if not os.path.isdir(scan_dir):
        return jsonify({}), 404
    
    modules = {}
    # Ordered to match the pipeline's ACTUAL execution sequence (easm-pipeline.sh
    # module_order), not the directory numbers — so the GUI reflects the real
    # flow: full port scan + service fingerprint run BEFORE http discovery, and
    # the advanced-attacks stage runs after nuclei. Dict insertion order is the
    # display order (Flask + the frontend both preserve it).
    module_names = {
        '01_asset_discovery': 'Asset Discovery',
        '02_subdomain_enum': 'Subdomain Enumeration',
        '03_dns_resolution': 'DNS Resolution',
        '03b_dns_discovery': 'DNS Discovery',
        '21_subdomain_takeover': 'Subdomain Takeover',
        '03c_dns_security': 'DNS Security Audit',
        '14_port_scan': 'Port Scanning',
        '07_service_fingerprint': 'Service Fingerprinting',
        '04_http_discovery': 'HTTP Discovery',
        '05_waf_detection': 'WAF Detection',
        '08_directory_discovery': 'Directory Discovery',
        '09_crawling': 'Web Crawling',
        '06_header_analysis': 'Header Analysis',
        '08c_hrs_detect': 'HRS Detection',
        '20_api_deep_discovery': 'API Deep Discovery',
        '11_param_fuzzing': 'Parameter Fuzzing',
        '16_api_security': 'API Security Testing',
        '13_xss_testing': 'XSS Testing',
        '15_sqli_testing': 'SQLi Testing',
        '20.1_api_sqli_testing': 'API SQLi Testing',
        '10_secret_scanning': 'Secret Scanning',
        '12_nuclei_scanning': 'Vulnerability Scanning',
        '24_advanced_attacks': 'Offensive Verification (JWT/GraphQL/SSTI/CRLF/SSRF/Race/Exposure/…)',
        '24_api_attack': 'API Attack (logic leads + authz invariants)',
        '22_shodan_correlation': 'Shodan Correlation',
        '17_cloud_exposure': 'Cloud Exposure',
        '18_osint_intel': 'OSINT Intelligence',
        '19_extended_checks': 'Extended Verification (legacy)',
        '23_internet_intel': 'Internet Intelligence',
        '08d_attack_synth': 'Attack Synthesis',
        '25_attack_paths': 'CAPEC Attack Paths',
        '26_response_intel': 'Response Intelligence',
        '27_adaptive_loop': 'Adaptive Loop',
    }

    for module_dir, module_name in module_names.items():
        module_path = os.path.join(scan_dir, module_dir)
        completed = False
        data_count = 0
        
        if os.path.isdir(module_path):
            files = glob.glob(os.path.join(module_path, '*'))
            data_count = len([f for f in files if os.path.isfile(f)])
            completed = data_count > 0
        
        modules[module_dir] = {
            'name': module_name,
            'completed': completed,
            'data_count': data_count
        }
    
    return jsonify(modules)


@app.route('/api/scan/<scan_id>/history')
def api_scan_history(scan_id):
    data = get_cached_scan_data(scan_id)
    if not data:
        return jsonify([]), 404
    target = data.get('pipeline_info', {}).get('target')
    return jsonify(get_scans_for_target(target))


@app.route('/api/scan/<scan_id>/compare')
def api_scan_compare(scan_id):
    if not get_cached_scan_data(scan_id):
        return jsonify({}), 404
    return jsonify(compare_scans(scan_id, request.args.get('previous')))


@app.route('/api/scan/<scan_id>/risk')
def api_risk(scan_id):
    """Per-host and org-level risk scores."""
    data = get_cached_scan_data(scan_id)
    if not data:
        return jsonify({}), 404

    hosts = data.get('hosts', {})
    org_score, grade = compute_org_risk(hosts)

    bands = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    host_scores = []
    for host, hd in hosts.items():
        band = hd.get('risk_band', 'low')
        bands[band] = bands.get(band, 0) + 1
        host_scores.append({
            'host': host,
            'score': hd.get('risk_score', 0),
            'band': band
        })

    host_scores.sort(key=lambda x: x['score'], reverse=True)
    return jsonify({
        'org_score': org_score,
        'grade': grade,
        'band_distribution': bands,
        'host_scores': host_scores
    })


def _classify_provider(*blobs):
    """Map httpx tech / CDN / server strings to a canonical cloud provider."""
    text = ' '.join(str(b or '') for b in blobs).lower()
    for provider, needles in CLOUD_PROVIDER_TECH.items():
        if any(n in text for n in needles):
            return provider
    return None


def build_cloud_recon(scan_id):
    """Cloud-estate inventory derived from HTTP discovery + bucket enumeration.

    This is recon, not vulnerabilities: which providers/CDNs front the estate,
    which origin IPs sit exposed, and which storage buckets were discovered.
    """
    recon = {
        'providers': {}, 'cdn_breakdown': {}, 'origin_ips': [],
        'buckets': [], 'cloud_hosts': 0, 'total_hosts': 0,
        'bucket_summary': {'total': 0, 'public': 0, 'private': 0},
    }
    if not scan_id:
        return recon

    scan_root = os.path.join(BASE_SCAN_DIR, scan_id)
    http_file = os.path.join(scan_root, '04_http_discovery/http_confirmed.json')
    seen_hosts = set()
    origin_seen = set()

    if os.path.exists(http_file):
        try:
            with open(http_file, 'r', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        e = json.loads(line)
                    except Exception:
                        continue
                    host = e.get('host') or e.get('input')
                    if not host or host in seen_hosts:
                        continue
                    seen_hosts.add(host)
                    recon['total_hosts'] += 1

                    tech = e.get('tech', []) or []
                    cdn_name = e.get('cdn_name') or ''
                    provider = _classify_provider(' '.join(tech), cdn_name,
                                                  e.get('webserver', ''))
                    if provider:
                        recon['cloud_hosts'] += 1
                        recon['providers'][provider] = recon['providers'].get(provider, 0) + 1

                    # CDN inventory
                    if e.get('cdn') and cdn_name:
                        label = cdn_name.title()
                        recon['cdn_breakdown'][label] = recon['cdn_breakdown'].get(label, 0) + 1

                    # Exposed origins: a resolved host that is NOT behind a CDN
                    # but sits on a cloud provider is a direct-origin candidate.
                    ip = e.get('host_ip') or (e.get('a') or [''])[0]
                    cname = ' '.join(e.get('cname', []) or [])
                    # Secondary CDN/WAF check via CNAME chain and server header —
                    # some hosts report cdn=false but their CNAME resolves through
                    # a CDN edge node (e.g. *.cloudfront.net, *.akamaiedge.net).
                    is_cdn_via_cname = bool(CDN_WAF_HOST_RE.search(cname or host))
                    if ip and not e.get('cdn') and not is_cdn_via_cname and ip not in origin_seen:
                        origin_seen.add(ip)
                        hosted_zone = detect_hosted_zone(host + ' ' + cname)
                        recon['origin_ips'].append({
                            'host': host, 'ip': ip, 'provider': provider,
                            'cdn': False, 'server': e.get('webserver', ''),
                            'hosted_zone': hosted_zone,
                            'cname': cname,
                        })
        except Exception as exc:
            logger.error("Failed to build cloud recon from %s: %s", http_file, exc)

    # Phase 2 — bucket enumeration output (CloudEnum + S3Scanner)
    buckets_file = os.path.join(scan_root, '17_cloud_exposure/cloud_buckets.jsonl')
    if os.path.exists(buckets_file):
        try:
            with open(buckets_file, 'r', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        b = json.loads(line)
                    except Exception:
                        continue
                    access = (b.get('access') or 'unknown').lower()
                    bucket_url = b.get('url', '')
                    risk_cat = b.get('risk_category', '')
                    # A referenced-but-unclaimed bucket is a takeover vector
                    # (claimability detection). NOTE: do NOT use takeover_prone
                    # here — that flag is set on every takeover-capable provider,
                    # including live public/forbidden buckets.
                    is_takeover = access == 'unclaimed' or risk_cat == 'bucket_takeover'
                    recon['buckets'].append({
                        'name': b.get('name', ''),
                        'provider': (b.get('provider') or 'aws').lower(),
                        'access': access,
                        # Plain open/closed/not-found signal from the enumerator
                        # (falls back to a label derived from access for older scans).
                        'status': (b.get('status') or {
                            'public': 'open', 'forbidden': 'closed',
                            'unclaimed': 'not-found'}.get(access, access)),
                        'url': bucket_url,
                        'files': b.get('files', 0),
                        'note': b.get('note', ''),
                        'hosted_zone': detect_hosted_zone(bucket_url or b.get('name', '')),
                        'region': b.get('region', ''),
                        'risk_category': risk_cat,
                        'severity': (b.get('severity') or '').lower(),
                        'takeover': is_takeover,
                        'evidence': b.get('evidence', ''),
                    })
                    recon['bucket_summary']['total'] += 1
                    if is_takeover:
                        recon['bucket_summary']['takeover'] = \
                            recon['bucket_summary'].get('takeover', 0) + 1
                    elif access in ('public', 'open', 'listable'):
                        recon['bucket_summary']['public'] += 1
                    else:
                        recon['bucket_summary']['private'] += 1
        except Exception as exc:
            logger.error("Failed to read cloud buckets %s: %s", buckets_file, exc)

    recon['origin_ips'] = recon['origin_ips'][:50]
    recon['buckets'].sort(key=lambda x: (x['access'] != 'public', x['name']))
    return recon


def load_cloud_compliance(scan_id):
    """Phase 3 — authenticated compliance audit (Prowler / ScoutSuite).

    Only present when the operator ran an authenticated audit with cloud
    credentials. Absent (enabled=False) for pure external scans.
    """
    result = {'enabled': False, 'findings': [], 'by_service': {},
              'by_severity': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0},
              'tool': None, 'total': 0}
    if not scan_id:
        return result
    comp_file = os.path.join(BASE_SCAN_DIR, scan_id, '17_cloud_exposure/cloud_compliance.jsonl')
    if not os.path.exists(comp_file):
        return result
    try:
        with open(comp_file, 'r', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    c = json.loads(line)
                except Exception:
                    continue
                result['enabled'] = True
                sev = (c.get('severity') or 'info').lower()
                svc = c.get('service', 'general')
                result['tool'] = result['tool'] or c.get('tool')
                result['findings'].append({
                    'check_id': c.get('check_id', ''),
                    'title': c.get('title', ''),
                    'service': svc,
                    'severity': sev,
                    'status': c.get('status', 'FAIL'),
                    'region': c.get('region', ''),
                    'resource': c.get('resource', ''),
                    'framework': c.get('framework', ''),
                    'remediation': c.get('remediation', ''),
                })
                result['by_service'][svc] = result['by_service'].get(svc, 0) + 1
                if sev in result['by_severity']:
                    result['by_severity'][sev] += 1
    except Exception as exc:
        logger.error("Failed to read cloud compliance %s: %s", comp_file, exc)
    result['findings'].sort(key=lambda x: {'critical': 0, 'high': 1, 'medium': 2,
                                           'low': 3, 'info': 4}.get(x['severity'], 5))
    result['total'] = len(result['findings'])
    return result


# Canonical category display order for the cloud attack-surface matrix.
CLOUD_ASSET_CATEGORY_ORDER = [
    'provider', 'compute', 'storage', 'origin_exposure', 'cdn', 'load_balancer',
    'api_gateway', 'serverless', 'kubernetes', 'registry', 'database', 'cache',
    'queue', 'object_website', 'app_service', 'bastion', 'vpn', 'cloud_dns',
]

# cloud_storage_enum.py's bucket-provider slug -> the same display label
# cloud/cloud_asset_intel.py's own "AWS S3"/"Azure Blob"/etc. Signature
# entries use, so a bucket folded in below groups with (not beside) the
# hostname-pattern-matched ones of the same real service.
CLOUD_BUCKET_PROVIDER_LABEL = {
    'aws': 'AWS S3', 'azure': 'Azure Blob', 'gcp': 'Google Cloud Storage',
    'digitalocean': 'DigitalOcean Spaces', 'wasabi': 'Backblaze B2 / Wasabi',
    'backblaze': 'Backblaze B2 / Wasabi', 'cloudflare': 'Cloudflare R2',
    'alibaba': 'Alibaba OSS', 'tencent': 'Tencent COS',
}


def _bucket_origin_hosts(scan_root):
    """bucket_name -> the real scanned host that CNAMEs/references it, from
    03b_dns_discovery/cloud_storage_targets.json's 'hits' (recon.py's own DNS
    CNAME-chain walk — e.g. api.payu.in -> d10atk8n46wl7x.cloudfront.net).
    cloud_buckets.jsonl itself never carries this (cloud_storage_enum.py only
    ever sees the bare candidate name by the time it runs) so a bucket row's
    'host' column would otherwise show an unidentifiable opaque string like
    'd132c8cyp8m99d' with no way to tell which real asset it came from."""
    mapping = {}
    path = os.path.join(scan_root, '03b_dns_discovery', 'cloud_storage_targets.json')
    if not os.path.exists(path):
        return mapping
    try:
        with open(path, 'r', errors='ignore') as f:
            data = json.load(f)
        for hit in data.get('hits', []):
            name = hit.get('bucket_name')
            host = hit.get('host')
            if name and host and name not in mapping:
                mapping[name] = host
    except Exception as exc:
        logger.error("Failed to read cloud storage targets %s: %s", path, exc)
    return mapping


def _bucket_findings_as_asset_map(base):
    """cloud_storage_enum.py's cloud_buckets.jsonl -> cloud_asset_intel.py's
    CloudFinding shape (category='storage'). These are two independently
    reasonable but very different detection paths for the same real asset
    class: cloud_asset_intel.py's "AWS S3" Signature only catches a bucket
    referenced by a recognisable *hostname pattern* during recon, while
    cloud_storage_enum.py does dedicated per-bucket enumeration (real
    access/exposure-state/takeover grading). Only the former ever reached
    the 'Cloud services & assets' asset map — this folds the latter in too,
    so a scan with zero hostname-pattern hits (common; most buckets are
    referenced by bare name, not a subdomain CNAME) still shows its real S3
    footprint here instead of only as a bare count in the Cloud Depth KPI."""
    out = []
    path = os.path.join(base, 'cloud_buckets.jsonl')
    if not os.path.exists(path):
        return out
    origin_hosts = _bucket_origin_hosts(os.path.dirname(base))
    try:
        with open(path, 'r', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    b = json.loads(line)
                except Exception:
                    continue
                provider = (b.get('provider') or 'other').lower()
                label = CLOUD_BUCKET_PROVIDER_LABEL.get(provider, f"{provider.title()} bucket")
                access = (b.get('access') or '').lower()
                status = (b.get('status') or '').lower()
                risk_cat = (b.get('risk_category') or '')
                # A takeover candidate is ONLY an unclaimed/dangling reference —
                # NOT every live public bucket. `takeover_prone` is True on every
                # bucket from a takeover-capable provider (all of S3/Azure/DO/
                # Wasabi), so using it here mislabelled every live public S3
                # bucket as a subdomain-takeover candidate (api.myntra.com FP).
                # Gate on the actual unclaimed state, mirroring build_cloud_recon.
                takeover = (access == 'unclaimed' or status == 'not-found'
                            or risk_cat == 'bucket_takeover')
                name = b.get('name', '')
                url = b.get('url', '')
                origin_host = origin_hosts.get(name, '')
                out.append({
                    # Primary identifier: the real scanned host this bucket
                    # name came from, when known — makes the row clickable
                    # through to that host's own profile, same as every other
                    # row in this table. Falls back to the bucket's own
                    # (identifying, not opaque) URL, never the bare name alone.
                    'host': origin_host or url or name,
                    'bucket_name': name,
                    'origin_host': origin_host,
                    'category': 'storage',
                    'category_label': 'Object Storage',  # matches cloud_asset_intel.CATEGORY_LABELS['storage']
                    'service': label,
                    'provider': provider,
                    'risk': (b.get('risk_category') or '').replace('_', ' '),
                    'severity': b.get('severity', 'info'),
                    'evidence': b.get('evidence', ''),
                    'matched': url,
                    'url': url,
                    'enumerate': (f"aws s3 ls s3://{name} --no-sign-request"
                                 if provider == 'aws' else f"curl -s '{url}'"),
                    'attack': ('Enumerate for public LIST/READ/WRITE access.' if not takeover else
                              'Referenced but unclaimed — register this bucket name under your '
                              'own account before an attacker claims it for takeover.'),
                    'tools': ['cloud_storage_enum'],
                    'source': 'cloud_storage_enum',
                    'takeover_candidate': takeover,
                    'confidence': 'high' if b.get('access') in ('public', 'authenticated') else 'medium',
                    'exposure_state': b.get('exposure_state', 'referenced'),
                })
    except Exception as exc:
        logger.error("Failed to read cloud buckets %s: %s", path, exc)
    return out


def load_cloud_asset_map(scan_id):
    """Load the cloud attack-surface classification (cloud_asset_intel.py).

    Returns the full categorized asset map + summary matrix produced by
    Module 17b. Groups findings by category so the dashboard can render the
    CSPM attack-surface matrix. Empty (enabled=False) for scans predating the
    classifier.
    """
    result = {
        'enabled': False, 'total': 0, 'findings': [], 'by_category': {},
        'by_severity': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0},
        'by_provider': {}, 'takeover_candidates': [], 'category_order': [],
    }
    if not scan_id:
        return result
    base = os.path.join(BASE_SCAN_DIR, scan_id, '17_cloud_exposure')
    map_file = os.path.join(base, 'cloud_asset_map.jsonl')

    findings = []
    if os.path.exists(map_file):
        try:
            with open(map_file, 'r', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        findings.append(json.loads(line))
                    except Exception:
                        continue
        except Exception as exc:
            logger.error("Failed to read cloud asset map %s: %s", map_file, exc)

    # Fold in cloud_storage_enum.py's dedicated per-bucket enumeration — see
    # _bucket_findings_as_asset_map() docstring for why this is a second,
    # non-overlapping detection path for the same 'storage' asset class, not
    # a duplicate of what cloud_asset_intel.py's own "AWS S3" Signature finds.
    # Folded in even when map_file is missing entirely, so a scan with only
    # bucket enumeration (no cloud_asset_intel.py pass) still shows its S3
    # footprint here instead of nowhere.
    findings.extend(_bucket_findings_as_asset_map(base))

    if not findings:
        return result
    result['enabled'] = True
    result['findings'] = findings
    result['total'] = len(findings)

    # Always computed fresh from the final (map + bucket) findings list — a
    # precomputed cloud_asset_summary.json predates buckets being folded in
    # here and would silently under-count 'storage' if preferred instead.
    _rank = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}
    for fnd in findings:
        cat = fnd.get('category', 'provider')
        entry = result['by_category'].setdefault(cat, {
            'label': fnd.get('category_label', cat), 'count': 0,
            'services': {}, 'max_severity': 'info', 'risk': fnd.get('risk', ''),
        })
        entry['count'] += 1
        svc = fnd.get('service', '')
        entry['services'][svc] = entry['services'].get(svc, 0) + 1
        sev = fnd.get('severity', 'info')
        if _rank.get(sev, 0) > _rank.get(entry['max_severity'], 0):
            entry['max_severity'] = sev
        result['by_severity'][sev] = result['by_severity'].get(sev, 0) + 1
        if fnd.get('provider'):
            result['by_provider'][fnd['provider']] = \
                result['by_provider'].get(fnd['provider'], 0) + 1
        if fnd.get('takeover_candidate'):
            result['takeover_candidates'].append({
                'host': fnd.get('host'), 'service': fnd.get('service'),
                'provider': fnd.get('provider')})
    result['category_order'] = [c for c in CLOUD_ASSET_CATEGORY_ORDER
                                if c in result['by_category']]
    return result


def _read_jsonl(path):
    """Read a .jsonl file into a list of dicts; [] if missing/unreadable."""
    out = []
    if not path or not os.path.exists(path):
        return out
    try:
        with open(path, 'r', errors='ignore') as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except Exception:
                    continue
    except Exception as exc:
        logger.error("Failed reading %s: %s", path, exc)
    return out


def load_cloud_depth(scan_id):
    """Cloud-depth (C1–C7) command-center payload — recon → takeover.

    Reads the self-contained C1–C5 module outputs from 17_cloud_exposure/ plus
    the cloud attack-path chains (kind=='cloud') from 25_attack_paths/ and shapes
    them into the single-glance scorecard the Cloud command center renders:
    provider attribution, the recon→takeover kill-chain funnel counts, KPI
    counters, guardrail posture and ranked takeover paths.
    """
    depth = {
        'enabled': False,
        'providers': [], 'primary_provider': '',
        'kpi': {'public_storage': 0, 'leaked_creds': 0, 'ssrf_imds': 0, 'guardrail_gaps': 0},
        'funnel': {'recon': 0, 'exposure': 0, 'cred': 0, 'ssrf': 0, 'takeover': 0},
        'verdict': {'takeover_reachable': False, 'realized_paths': 0},
        'guardrails': [], 'cloud_paths': [],
        'saas': [], 'credentials': [], 'ssrf': [],
    }
    if not scan_id:
        return depth
    base = os.path.join(BASE_SCAN_DIR, scan_id, '17_cloud_exposure')

    # C1 — passive SaaS/provider attribution
    saas = _read_jsonl(os.path.join(base, 'cloud_saas_fingerprint.jsonl'))
    prov_counts, prov_notes = {}, {}
    federation = 0
    cloud_provs = {'aws', 'azure', 'gcp', 'microsoft', 'google', 'cloudflare',
                   'alibaba', 'digitalocean', 'adfs-onprem'}
    for f in saas:
        p = f.get('provider', '')
        if p:
            prov_counts[p] = prov_counts.get(p, 0) + 1
            prov_notes.setdefault(p, f.get('note', ''))
        if f.get('category') == 'federation':
            federation += 1
    # primary = highest-count recognised cloud provider
    ranked = sorted(prov_counts.items(), key=lambda x: -x[1])
    primary = next((p for p, _ in ranked if p in cloud_provs), '')
    depth['providers'] = [{'provider': p, 'count': c, 'note': prov_notes.get(p, ''),
                           'primary': p == primary} for p, c in ranked]
    depth['primary_provider'] = primary
    depth['saas'] = saas

    # C3 — leaked cloud credentials
    creds = _read_jsonl(os.path.join(base, 'cloud_credentials.jsonl'))
    depth['credentials'] = creds

    # C4 — SSRF → IMDS
    ssrf = _read_jsonl(os.path.join(base, 'ssrf_metadata.jsonl'))
    ssrf_confirmed = [s for s in ssrf if s.get('confidence') == 'confirmed']
    depth['ssrf'] = ssrf

    # C5 — guardrail posture gaps
    posture = _read_jsonl(os.path.join(base, 'cloud_posture.jsonl'))
    depth['guardrails'] = posture

    # C2 — storage exposure count (public buckets from the scored cloud findings)
    buckets = _read_jsonl(os.path.join(base, 'cloud_buckets.jsonl'))
    public_buckets = [b for b in buckets
                      if (b.get('access') == 'public'
                          or b.get('exposure_state') in ('anon_accessible', 'sensitive_confirmed'))]

    # C6 — cloud attack-path chains (kind == 'cloud')
    paths_doc = os.path.join(BASE_SCAN_DIR, scan_id, '25_attack_paths', 'capec_attack_paths.json')
    cloud_paths = []
    if os.path.exists(paths_doc):
        try:
            with open(paths_doc, 'r', errors='ignore') as fh:
                doc = json.load(fh)
            cloud_paths = [p for p in doc.get('paths', []) if p.get('kind') == 'cloud']
        except Exception as exc:
            logger.error("Failed reading cloud paths %s: %s", paths_doc, exc)
    realized = [p for p in cloud_paths if p.get('realized')]
    depth['cloud_paths'] = sorted(cloud_paths, key=lambda p: -p.get('score', 0))

    # KPIs + funnel + verdict
    depth['kpi'] = {
        'public_storage': len(public_buckets),
        'leaked_creds': len(creds),
        'ssrf_imds': len(ssrf_confirmed),
        'guardrail_gaps': len(posture),
    }
    depth['funnel'] = {
        'recon': len(saas),
        'exposure': len(public_buckets) + sum(1 for b in buckets if b not in public_buckets),
        'cred': len(creds),
        'ssrf': len(ssrf_confirmed),
        'takeover': len(realized),
    }
    depth['verdict'] = {
        'takeover_reachable': len(realized) > 0,
        'realized_paths': len(realized),
    }
    depth['enabled'] = bool(saas or creds or ssrf or posture or cloud_paths or buckets)
    return depth


@app.route('/api/scan/<scan_id>/cloud')
def api_cloud(scan_id):
    """Cloud attack surface — infrastructure security findings + cloud recon.

    Strictly cloud-scoped: app/API vulnerabilities (XSS, SQLi, SSRF, IDOR, JWT)
    are excluded by the CLOUD_ALL_CATEGORIES whitelist and live in the Vulns/API
    tabs instead.
    """
    data = get_cached_scan_data(scan_id)
    if not data:
        return jsonify({}), 404

    cloud = [v for v in data.get('vulnerabilities', [])
             if v.get('source') == 'Cloud Exposure'
             and v.get('cloud_category') in CLOUD_ALL_CATEGORIES]
    cloud.sort(key=lambda v: v.get('weighted_score', 0), reverse=True)

    by_category = {}
    sev_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    security_count = 0
    posture_count = 0
    for v in cloud:
        cat = v.get('cloud_category', 'unknown')
        if cat in CLOUD_SECURITY_CATEGORIES:
            security_count += 1
        else:
            posture_count += 1
        entry = by_category.setdefault(cat, {
            'label': v.get('template', cat),
            'base_weight': v.get('base_weight', 0),
            'count': 0,
            'max_score': 0,
            'group': 'security' if cat in CLOUD_SECURITY_CATEGORIES else 'posture',
        })
        entry['count'] += 1
        entry['max_score'] = max(entry['max_score'], v.get('weighted_score', 0))
        sev = v.get('severity', 'info')
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    categories = sorted(by_category.values(), key=lambda c: c['max_score'], reverse=True)
    return jsonify({
        'total': len(cloud),
        'security_count': security_count,
        'posture_count': posture_count,
        'by_severity': sev_counts,
        'categories': categories,
        'findings': cloud,
        'recon': build_cloud_recon(scan_id),
        'compliance': load_cloud_compliance(scan_id),
        'asset_map': load_cloud_asset_map(scan_id),
        'depth': load_cloud_depth(scan_id),
    })


# ===========================================================================
# OSINT & Human Exposure Intelligence (Module 18 — osint_intel.py)
# ===========================================================================
OSINT_CATEGORY_ORDER = [
    'organization', 'brand', 'certificate', 'supply_chain', 'internet_exposure',
    'email_exposure', 'breach', 'ransomware', 'code_exposure', 'api_docs',
    'recruitment', 'mobile_app', 'public_documents', 'news_media', 'social',
    'ad_fraud', 'malicious_landing', 'gov_injection', 'takeover',
]


def load_osint_intel(scan_id):
    """Load the passive OSINT / human-exposure findings produced by Module 18.

    Reads 18_osint_intel/osint_findings.jsonl + osint_summary.json for the scan
    and returns the findings plus the category matrix + exposure score the OSINT
    dashboard tab renders. Empty (enabled=False) for scans predating the engine.
    """
    result = {
        'enabled': False, 'total': 0, 'findings': [], 'by_category': {},
        'by_severity': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0},
        'category_order': [], 'exposure_score': 0, 'grade': 'low',
        'new_since_last': 0, 'connectors': {}, 'domain': '',
        'correlation': {}, 'executive_summary': '',
    }
    if not scan_id:
        return result
    base = os.path.join(BASE_SCAN_DIR, scan_id, '18_osint_intel')
    map_file = os.path.join(base, 'osint_findings.jsonl')
    summary_file = os.path.join(base, 'osint_summary.json')
    if not os.path.exists(map_file):
        return result

    findings = []
    try:
        with open(map_file, 'r', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    findings.append(json.loads(line))
                except Exception:
                    continue
    except Exception as exc:
        logger.error("Failed to read OSINT findings %s: %s", map_file, exc)
        return result

    if not findings:
        return result

    # Strip non-actionable placeholders: connector-status "set X_API_KEY …"
    # messages and info-severity "No X found/discovered" empty-result stubs.
    # These inflate counts and clutter the UI with noise.
    def _is_actionable(f):
        if f.get('source') == 'connector':
            return False
        if (f.get('severity', 'info') == 'info'
                and (f.get('title') or '').startswith('No ')):
            return False
        return True

    findings = [f for f in findings if _is_actionable(f)]
    if not findings:
        return result

    result['enabled'] = True
    result['findings'] = findings
    result['total'] = len(findings)

    summary = None
    if os.path.exists(summary_file):
        try:
            with open(summary_file, 'r', errors='ignore') as f:
                summary = json.load(f)
        except Exception:
            summary = None

    if summary:
        result['exposure_score'] = summary.get('exposure_score', 0)
        result['grade'] = summary.get('grade', 'low')
        result['new_since_last'] = summary.get('new_since_last', 0)
        result['connectors'] = summary.get('connectors', {})
        result['domain'] = summary.get('domain', '')
        result['correlation'] = summary.get('correlation', {})
        result['executive_summary'] = summary.get('executive_summary', '')

    # Always recompute category/severity counts from the filtered findings
    # so stripped placeholders don't inflate the numbers.
    _rank = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}
    for fnd in findings:
        cat = fnd.get('category', 'social')
        entry = result['by_category'].setdefault(cat, {
            'label': fnd.get('category_label', cat), 'count': 0,
            'max_severity': 'info', 'new': 0})
        entry['count'] += 1
        sev = fnd.get('severity', 'info')
        if _rank.get(sev, 0) > _rank.get(entry['max_severity'], 0):
            entry['max_severity'] = sev
        result['by_severity'][sev] = result['by_severity'].get(sev, 0) + 1

    if not result['category_order']:
        result['category_order'] = [c for c in OSINT_CATEGORY_ORDER
                                    if c in result['by_category']]
    # Drop categories that ended up with zero findings after filtering.
    result['by_category'] = {k: v for k, v in result['by_category'].items()
                             if v.get('count', 0) > 0}
    result['category_order'] = [c for c in result['category_order']
                                if c in result['by_category']]
    return result


@app.route('/api/scan/<scan_id>/osint')
def api_osint(scan_id):
    """OSINT & human-exposure intelligence for a specific scan."""
    logger.info("API request: /api/scan/%s/osint", scan_id)
    return jsonify(load_osint_intel(scan_id))


@app.route('/api/osint')
def api_osint_legacy():
    """OSINT endpoint keyed by ?target=."""
    scan_id = resolve_target(request.args.get('target'))
    logger.info("API request: /api/osint target=%s", scan_id)
    return jsonify(load_osint_intel(scan_id))


# ===========================================================================
# Shodan Correlation (Module 22 — shodan_correlation.py)
# Reconciles ARISE's observed view (ports/services/WAF) against Shodan's
# external cached view of the same origin IPs. Read-only loader — additive,
# never touches any other module's data path.
# ===========================================================================
def load_shodan_correlation(scan_id):
    """Load the Shodan correlation matrix + findings produced by Module 22.

    Reads 22_shodan_correlation/shodan_summary.json (+ shodan_findings.jsonl)
    for the scan. Returns enabled=False for scans predating the engine so the
    dashboard tab degrades cleanly.
    """
    result = {
        'enabled': False, 'domain': '', 'shodan_source': 'local-only',
        'total_assets': 0, 'origin_assets': 0, 'cdn_excluded': 0,
        'enriched_assets': 0, 'coverage': {}, 'by_severity': {},
        'total_findings': 0, 'exposure_score': 0, 'grade': 'low',
        'providers': {}, 'assets': [], 'findings': [], 'top_findings': [],
    }
    if not scan_id:
        return result
    base = os.path.join(BASE_SCAN_DIR, scan_id, '22_shodan_correlation')
    summary_file = os.path.join(base, 'shodan_summary.json')
    findings_file = os.path.join(base, 'shodan_findings.jsonl')
    if not os.path.exists(summary_file):
        return result

    try:
        with open(summary_file, 'r', errors='ignore') as f:
            summary = json.load(f)
    except Exception as exc:
        logger.error("Failed to read Shodan summary %s: %s", summary_file, exc)
        return result

    findings = []
    if os.path.exists(findings_file):
        try:
            with open(findings_file, 'r', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        findings.append(json.loads(line))
                    except Exception:
                        continue
        except Exception as exc:
            logger.error("Failed to read Shodan findings %s: %s", findings_file, exc)

    result['enabled'] = True
    result['domain'] = summary.get('domain', '')
    result['shodan_source'] = summary.get('shodan_source', 'local-only')
    result['total_assets'] = summary.get('total_assets', 0)
    result['origin_assets'] = summary.get('origin_assets', 0)
    result['cdn_excluded'] = summary.get('cdn_excluded', 0)
    result['enriched_assets'] = summary.get('enriched_assets', 0)
    result['coverage'] = summary.get('coverage', {})
    result['by_severity'] = summary.get('by_severity', {})
    result['total_findings'] = summary.get('total_findings', len(findings))
    result['exposure_score'] = summary.get('exposure_score', 0)
    result['grade'] = summary.get('grade', 'low')
    result['providers'] = summary.get('providers', {})
    result['assets'] = summary.get('assets', [])
    result['top_findings'] = summary.get('top_findings', [])
    result['findings'] = findings or summary.get('top_findings', [])
    return result


@app.route('/api/scan/<scan_id>/shodan')
def api_shodan(scan_id):
    """Shodan correlation matrix + findings for a specific scan."""
    logger.info("API request: /api/scan/%s/shodan", scan_id)
    return jsonify(load_shodan_correlation(scan_id))


@app.route('/api/shodan')
def api_shodan_legacy():
    """Shodan correlation endpoint keyed by ?target=."""
    scan_id = resolve_target(request.args.get('target'))
    logger.info("API request: /api/shodan target=%s", scan_id)
    return jsonify(load_shodan_correlation(scan_id))


def load_internet_intel(scan_id):
    """Load consolidated Internet Intelligence Layer data (Module 23).

    Reads 23_internet_intel/intel_summary.json for the scan. Returns
    enabled=False for scans predating Module 23 so the overview degrades.
    """
    result = {
        'enabled': False, 'total_assets': 0, 'total_findings': 0,
        'total_cves': 0, 'total_ports': 0, 'geo_located': 0,
        'geo_source_breakdown': {}, 'by_severity': {},
        'risk_score': 0, 'grade': 'low',
        'geo_assets': [], 'critical_assets': [],
        'top_cves': [], 'top_services': [], 'top_ports': [],
        'top_providers': [], 'top_countries': [],
        'enrichment': {'censys': False, 'greynoise': False,
                       'ipinfo': False, 'shodan': False},
        # Attack-surface detection engine (Xpanse-style issues)
        'issues': [], 'issues_total': 0, 'issues_by_severity': {},
        'issues_by_category': [], 'issues_by_owner': [],
        'attack_surface_score': 0, 'posture': 'low',
        # Cloud-security console
        'cloud': {},
    }
    if not scan_id:
        return result
    base = os.path.join(BASE_SCAN_DIR, scan_id, '23_internet_intel')
    summary_file = os.path.join(base, 'intel_summary.json')
    if not os.path.exists(summary_file):
        return result
    try:
        with open(summary_file, 'r', errors='ignore') as f:
            summary = json.load(f)
    except Exception as exc:
        logger.error("Failed to read internet intel %s: %s", summary_file, exc)
        return result

    result['enabled'] = True
    for key in ('total_assets', 'total_findings', 'total_cves', 'total_ports',
                'geo_located', 'geo_source_breakdown', 'by_severity', 'risk_score',
                'grade', 'geo_assets', 'critical_assets', 'top_cves', 'top_services',
                'top_ports', 'top_providers', 'top_countries', 'enrichment',
                'issues_total', 'issues_by_severity', 'issues_by_category',
                'issues_by_owner', 'attack_surface_score', 'posture', 'cloud'):
        if key in summary:
            result[key] = summary[key]

    # Full issue list (the console needs all issues, not just the summary's top 25).
    issues_file = os.path.join(base, 'intel_issues.jsonl')
    if os.path.exists(issues_file):
        issues = []
        try:
            with open(issues_file, 'r', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        issues.append(json.loads(line))
        except Exception as exc:
            logger.error("Failed to read intel issues %s: %s", issues_file, exc)
        result['issues'] = issues
    elif summary.get('top_issues'):
        result['issues'] = summary['top_issues']
    return result


@app.route('/api/scan/<scan_id>/internet-intel')
def api_internet_intel(scan_id):
    logger.info("API request: /api/scan/%s/internet-intel", scan_id)
    return jsonify(load_internet_intel(scan_id))


@app.route('/api/internet-intel')
def api_internet_intel_legacy():
    scan_id = resolve_target(request.args.get('target'))
    logger.info("API request: /api/internet-intel target=%s", scan_id)
    return jsonify(load_internet_intel(scan_id))


### Attack synthesis + CAPEC attack paths ####################################
# recon_attack_synth.py (Module 8D) emits custom nuclei templates from recon;
# capec_attack_paths.py (Module L6) chains confirmed findings into ranked paths.
# These routes serve their JSON and can build them on demand for older scans.

def _scan_root(scan_id):
    """Resolve a scan_id to its directory, refusing path traversal."""
    root = os.path.realpath(os.path.join(BASE_SCAN_DIR, scan_id))
    base = os.path.realpath(BASE_SCAN_DIR)
    if (root == base) or not root.startswith(base + os.sep) or not os.path.isdir(root):
        return None
    return root


def _read_json_file(path, default=None):
    try:
        with open(path) as fh:
            return json.load(fh)
    except Exception:
        return {} if default is None else default


def _read_jsonl_file(path):
    """Read a .jsonl file into a list of dicts; tolerant of blank/broken lines."""
    rows = []
    try:
        with open(path, errors='ignore') as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except Exception:
                    continue
    except Exception:
        pass
    return rows


@app.route('/api/scan/<scan_id>/synth')
def api_synth(scan_id):
    root = _scan_root(scan_id)
    if not root:
        return jsonify({"error": "unknown scan"}), 404
    return jsonify(_read_json_file(os.path.join(root, '08d_attack_synth', 'synth_manifest.json')))


@app.route('/api/scan/<scan_id>/attack-paths')
def api_attack_paths(scan_id):
    root = _scan_root(scan_id)
    if not root:
        return jsonify({"error": "unknown scan"}), 404
    return jsonify(_read_json_file(os.path.join(root, '25_attack_paths', 'capec_attack_paths.json')))


@app.route('/api/scan/<scan_id>/attack-chain-v2/build', methods=['POST'])
def api_attack_chain_v2_build(scan_id):
    """Run the full attack_chain_v2.ROADMAP.md pipeline for a scan: build the
    unified evidence graph (Phase 1), score it (Phase 2), have the AI propose
    candidate chains (Phase 3a), gate them against real evidence (Phase 3b),
    compute the chokepoint fix-list (Phase 4), then narrate (Phase 5). v1's
    own /api/scan/<id>/attack-paths/build above is untouched — this is a
    fully separate, additive pipeline (Phase 0's own contract)."""
    root = _scan_root(scan_id)
    if not root:
        return jsonify({"error": "unknown scan"}), 404
    here = os.path.dirname(os.path.abspath(__file__))
    body = request.get_json(silent=True) or {}

    # Same key-resolution path as /api/scan/<id>/attack-paths/build above and
    # the AI Analyst engine — Settings-configured provider/model/vault key,
    # never a separate credential.
    _s = load_settings()
    provider = (body.get('provider') or _s.get('provider') or 'claude').lower()
    model = body.get('model') or _s.get('model') or ''
    key = _provider_key(provider, supplied=body.get('api_key'))
    sub_env = os.environ.copy()
    if key:
        for env_name in AI_PROVIDERS.get(provider, {}).get('env_names', []):
            sub_env[env_name] = key
    sub_env['ARISE_AI_PROVIDER'] = provider
    # ARISE_AI_MODEL is a single, provider-agnostic override shared across every
    # provider in discovery/synth_ai.py's build_chat_fn — a value meant for one
    # provider (e.g. .env's own ARISE_AI_MODEL=claude-opus-4-8) silently leaks
    # into a DIFFERENT provider's resolution otherwise (confirmed live: this
    # exact leak sent "claude-opus-4-8" to Gemini's API and produced a 404).
    # Set it only when this call explicitly wants a non-default model for the
    # CHOSEN provider; otherwise strip whatever the parent process inherited so
    # synth_ai.py falls through to that provider's own correct default.
    sub_env.pop('ARISE_AI_MODEL', None)
    if model:
        sub_env['ARISE_AI_MODEL'] = model

    steps = []
    pipeline = [
        ('evidence_graph', ['python3', os.path.join(here, 'intel', 'evidence_graph.py'), root, '--summary']),
        ('chain_scoring', ['python3', os.path.join(here, 'intel', 'chain_scoring.py'), root, '--summary']),
        ('chain_architect', ['python3', os.path.join(here, 'intel', 'chain_architect.py'), root,
                             '--summary', '--provider', provider] + (['--model', model] if model else [])),
        ('chain_gate', ['python3', os.path.join(here, 'intel', 'chain_gate.py'), root, '--summary']),
        ('chokepoint', ['python3', os.path.join(here, 'intel', 'chokepoint.py'), root, '--summary']),
        ('chain_narrator', ['python3', os.path.join(here, 'intel', 'chain_narrator.py'), root,
                            '--summary', '--provider', provider] + (['--model', model] if model else [])),
    ]
    for name, cmd in pipeline:
        try:
            p = subprocess.run(cmd, cwd=here, capture_output=True, text=True, timeout=180, env=sub_env)
            steps.append({'step': name, 'rc': p.returncode,
                         'out': (p.stdout or p.stderr or '').strip()[-1000:]})
            # A phase that hard-fails (nonzero exit) means every phase after it
            # has nothing to read — stop rather than run 4 more steps against
            # missing input and report confusing downstream errors.
            if p.returncode != 0:
                break
        except Exception as exc:  # noqa: BLE001
            steps.append({'step': name, 'rc': -1, 'out': str(exc)[:300]})
            break

    ap_dir = os.path.join(root, '25_attack_paths')
    return jsonify({
        'steps': steps,
        'gated_chains': _read_json_file(os.path.join(ap_dir, 'gated_chains.json')),
        'chokepoint': _read_json_file(os.path.join(ap_dir, 'chokepoint_report.json')),
        'narrative': _read_json_file(os.path.join(ap_dir, 'chain_narrative.json')),
        'autonomous_feed': _read_json_file(os.path.join(ap_dir, 'autonomous_attack_feed.json')),
    })


@app.route('/api/scan/<scan_id>/attack-chain-v2')
def api_attack_chain_v2(scan_id):
    """attack_chain_v2.ROADMAP.md — the AI-driven redesign's output, additive
    alongside (never replacing) /api/scan/<id>/attack-paths above. Each file
    is produced by running, in order: intel/evidence_graph.py,
    intel/chain_scoring.py, intel/chain_architect.py, intel/chain_gate.py,
    intel/chokepoint.py, intel/chain_narrator.py. Any file not yet generated
    for this scan (v2 hasn't been run, or ran before a given phase existed)
    returns {} for that key (matching _read_json_file's own missing-file default)
    rather than erroring — the frontend can render whatever subset is available."""
    root = _scan_root(scan_id)
    if not root:
        return jsonify({"error": "unknown scan"}), 404
    ap_dir = os.path.join(root, '25_attack_paths')
    return jsonify({
        "gated_chains": _read_json_file(os.path.join(ap_dir, 'gated_chains.json')),
        "chokepoint": _read_json_file(os.path.join(ap_dir, 'chokepoint_report.json')),
        "narrative": _read_json_file(os.path.join(ap_dir, 'chain_narrative.json')),
        "autonomous_feed": _read_json_file(os.path.join(ap_dir, 'autonomous_attack_feed.json')),
    })


@app.route('/api/scan/<scan_id>/offensive')
def api_offensive(scan_id):
    """Unified offensive summary — synth + autonomous-attack results for this scan."""
    root = _scan_root(scan_id)
    if not root:
        return jsonify({"error": "unknown scan"}), 404
    return jsonify(_read_json_file(os.path.join(root, '08d_attack_synth', 'offensive_summary.json')))


@app.route('/api/scan/<scan_id>/response-intel')
def api_response_intel(scan_id):
    root = _scan_root(scan_id)
    if not root:
        return jsonify({"error": "unknown scan"}), 404
    ri_dir = os.path.join(root, '26_response_intel')
    summary = _read_json_file(os.path.join(ri_dir, 'response_intel_summary.json'))
    findings = []
    deduped = os.path.join(ri_dir, 'response_findings_deduped.jsonl')
    if os.path.exists(deduped):
        try:
            with open(deduped, 'r', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            findings.append(json.loads(line))
                        except Exception:
                            continue
        except Exception:
            pass
    return jsonify({"summary": summary, "findings": findings})


@app.route('/api/scan/<scan_id>/attack-paths/build', methods=['POST'])
def api_attack_paths_build(scan_id):
    """Run the synthesizer + CAPEC path builder for a scan and return the result."""
    root = _scan_root(scan_id)
    if not root:
        return jsonify({"error": "unknown scan"}), 404
    here = os.path.dirname(os.path.abspath(__file__))
    body = request.get_json(silent=True) or {}
    use_ai = bool(body.get('ai'))
    target = re.sub(r'-\d{6}-\d{3,6}$', '', os.path.basename(root))
    # One unified offensive engine: synth backbone always; --autonomous adds the
    # LLM brain when the operator ticks AI-augment.
    off_cmd = ['python3', os.path.join(here, 'offensive', 'offensive_engine.py'), root,
               '--out', os.path.join(root, '08d_attack_synth'), '--synth', '--summary',
               '--target', target]
    # Reuse the AI-engine's configured key so no separate env var is needed: the
    # autonomous subprocess inherits the SAME key the AI Analyst uses (request →
    # encrypted vault → env, via _provider_key), injected into its environment.
    sub_env = os.environ.copy()
    if use_ai:
        off_cmd.append('--autonomous')
        # Use the SAME provider/model/key the AI Analyst engine uses — resolved
        # from Settings (arise_settings.json) → .env → auto-detect, exactly like
        # load_settings()/_provider_key. No separate Claude key required.
        _s = load_settings()
        provider = (body.get('provider') or _s.get('provider') or 'claude').lower()
        model = body.get('model') or _s.get('model') or ''
        key = _provider_key(provider, supplied=body.get('api_key'))
        if key:
            for env_name in AI_PROVIDERS.get(provider, {}).get('env_names', []):
                sub_env[env_name] = key
            sub_env['ARISE_AI_PROVIDER'] = provider
            if model:
                sub_env['ARISE_AI_MODEL'] = model
            off_cmd += ['--ai-provider', provider]
            if model:
                off_cmd += ['--ai-model', model]
    capec_cmd = ['python3', os.path.join(here, 'intel', 'capec_attack_paths.py'), root, '--summary']
    steps = []
    for name, cmd, tmo in (('offensive', off_cmd, 900), ('capec', capec_cmd, 300)):
        try:
            p = subprocess.run(cmd, cwd=here, capture_output=True, text=True, timeout=tmo, env=sub_env)
            steps.append({'step': name, 'rc': p.returncode,
                          'out': (p.stdout or p.stderr or '').strip()[-1000:]})
        except Exception as exc:  # noqa: BLE001
            steps.append({'step': name, 'rc': -1, 'out': str(exc)[:300]})
    return jsonify({
        'steps': steps,
        'paths': _read_json_file(os.path.join(root, '25_attack_paths', 'capec_attack_paths.json')),
        'synth': _read_json_file(os.path.join(root, '08d_attack_synth', 'synth_manifest.json')),
        'offensive': _read_json_file(os.path.join(root, '08d_attack_synth', 'offensive_summary.json')),
    })


@app.route('/api/scan/<scan_id>/executive')
def api_executive(scan_id):
    """Executive / CXO summary."""
    data = get_cached_scan_data(scan_id)
    if not data:
        return jsonify({}), 404

    hosts = data.get('hosts', {})
    vulns = data.get('vulnerabilities', [])
    org_score, grade = compute_org_risk(hosts)

    total_assets = len(hosts)
    http_hosts = sum(1 for h in hosts.values() if h.get('http_status'))
    resolved = sum(1 for h in hosts.values() if h.get('resolved'))
    waf_covered = sum(1 for h in hosts.values()
                      if h.get('waf_vendor') not in ('none', '', None) and h.get('http_status'))
    waf_uncovered = http_hosts - waf_covered
    waf_coverage_pct = round(waf_covered * 100 / http_hosts) if http_hosts else 0
    cdn_fronted = sum(1 for h in hosts.values() if h.get('cdn'))

    sev_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    for v in vulns:
        s = v.get('severity', 'info')
        sev_counts[s] = sev_counts.get(s, 0) + 1

    secrets_count = sum(1 for v in vulns if v.get('source') == 'Secret Scan')

    sensitive_services = []
    for host, hd in hosts.items():
        exposed = set(hd.get('ports_open', [])) & SENSITIVE_PORTS
        for p in exposed:
            sensitive_services.append({'host': host, 'port': p, 'service': PORT_MAPPINGS.get(p, 'Unknown')})

    # Delta: only compare if previous scan is already cached (avoid 5s cold load)
    prev_id = get_previous_scan_id(scan_id)
    if prev_id and _get_cached_only(prev_id):
        delta = compare_scans(scan_id, prev_id)
    else:
        delta = {'has_baseline': False, 'summary': {}}

    # Top 5 remediation priorities
    scored_items = []
    for v in vulns:
        prio = SEVERITY_WEIGHTS.get(v.get('severity', 'info'), 0)
        if v.get('source') == 'Secret Scan':
            prio += 25
        scored_items.append((prio, v))
    for s in sensitive_services:
        scored_items.append((15, {
            'source': 'Port Scan',
            'template': f"Exposed {s['service']}",
            'severity': 'high',
            'host': s['host'],
            'url': f"{s['host']}:{s['port']}",
            'impact': f"Sensitive service {s['service']} exposed to internet",
            'remediation': 'Restrict access via firewall or VPN'
        }))
    scored_items.sort(key=lambda x: x[0], reverse=True)
    top_priorities = [item[1] for item in scored_items[:5]]

    # Historical trend — only use already-cached scans (avoid cold-loading 10 datasets)
    scan_history = get_scans_for_target(data.get('pipeline_info', {}).get('target', ''))
    trend = []
    for s in scan_history[:5]:
        sid = s['id']
        hist_data = _get_cached_only(sid) if sid != scan_id else data
        if hist_data:
            h_score, h_grade = compute_org_risk(hist_data.get('hosts', {}))
            trend.append({
                'scan_id': sid,
                'start_time': s.get('start_time', ''),
                'org_score': h_score,
                'grade': h_grade,
                'total_hosts': s.get('total_hosts', 0),
                'vuln_count': len(hist_data.get('vulnerabilities', []))
            })

    return jsonify({
        'org_score': org_score,
        'grade': grade,
        'exposure': {
            'total_assets': total_assets,
            'internet_facing_http': http_hosts,
            'resolved': resolved,
            'waf_covered': waf_covered,
            'waf_uncovered': waf_uncovered,
            'waf_coverage_pct': waf_coverage_pct,
            'cdn_fronted': cdn_fronted
        },
        'findings': {
            'by_severity': sev_counts,
            'secrets': secrets_count,
            'sensitive_services': len(sensitive_services)
        },
        'delta': delta.get('summary', {}),
        'has_baseline': delta.get('has_baseline', False),
        'top_priorities': top_priorities,
        'trend': trend,
        'port_scan_status': data.get('port_scan_status', 'missing')
    })


_CVE_SEV_ORDER = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}


@app.route('/api/scan/<scan_id>/cves')
def api_cves(scan_id):
    """CVE-grouped vulnerability view — nuclei template hits (classification.cve-id)
    PLUS Shodan-reported CVEs (22_shodan_correlation/shodan_findings.jsonl's
    known-cve rule), which were previously invisible here: this tab only ever
    read data['vulnerabilities'], built exclusively from nuclei output, so a
    CVE Shodan inferred from a banner/CPE match (ARISE's only other CVE
    source) never showed up even after it was graded (see
    intel/shodan_correlation.py's KEV-aware severity — most of these are
    "low" unconfirmed guesses, but a few are "critical" CISA-KEV-confirmed
    exploited-in-the-wild CVEs that belong in this list as much as any
    nuclei hit, arguably more given KEV is stronger evidence than a
    community template merely existing for a CVE ID)."""
    data = get_cached_scan_data(scan_id)
    if not data:
        return jsonify([]), 404

    cve_map = {}

    def _upsert(cve_id, severity, template, cwe_ids, host, source):
        if not cve_id:
            return
        entry = cve_map.get(cve_id)
        if entry is None:
            entry = cve_map[cve_id] = {
                'cve_id': cve_id, 'severity': severity, 'template': template,
                'cwe_ids': [], 'affected_hosts': [], 'count': 0, 'sources': [],
            }
        # Max-severity wins when the same CVE is reported by more than one
        # source (e.g. nuclei confirms a CVE Shodan also inferred) — never
        # let a weaker source's grading downgrade a stronger one's verdict.
        if _CVE_SEV_ORDER.get(severity, 4) < _CVE_SEV_ORDER.get(entry['severity'], 4):
            entry['severity'] = severity
        if not entry['template'] and template:
            entry['template'] = template
        if source not in entry['sources']:
            entry['sources'].append(source)
        entry['count'] += 1
        if host and host not in entry['affected_hosts']:
            entry['affected_hosts'].append(host)
        for c in (cwe_ids or []):
            if c and c not in entry['cwe_ids']:
                entry['cwe_ids'].append(c)

    for v in data.get('vulnerabilities', []):
        cve_ids = v.get('cve_id') or []
        if isinstance(cve_ids, str):
            cve_ids = [cve_ids] if cve_ids else []
        cwe = v.get('cwe_id', [])
        if isinstance(cwe, str):
            cwe = [cwe]
        for cve_id in cve_ids:
            _upsert(cve_id, v.get('severity', 'info'), v.get('template', ''),
                   cwe, v.get('host', 'Unknown'), 'nuclei')

    shodan_file = os.path.join(BASE_SCAN_DIR, scan_id,
                               '22_shodan_correlation/shodan_findings.jsonl')
    if os.path.exists(shodan_file):
        try:
            with open(shodan_file, 'r', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        sf = json.loads(line)
                    except Exception:
                        continue
                    if sf.get('rule_id') != 'known-cve':
                        continue
                    cve_id = sf.get('cve', '')
                    host = (sf.get('hostnames') or [None])[0] or sf.get('ip', 'Unknown')
                    if sf.get('correlation') == 'confirmed':
                        label = 'Shodan (confirmed by nuclei)'
                    elif sf.get('kev'):
                        label = 'Shodan (CISA KEV — exploited in the wild)'
                    else:
                        label = 'Shodan (banner-inferred, unconfirmed)'
                    cwe = sf.get('cwe', '')
                    _upsert(cve_id, sf.get('severity', 'info'), label,
                           [cwe] if cwe else [], host, 'shodan')
        except Exception as exc:
            logger.error("Failed to read shodan findings %s: %s", shodan_file, exc)

    result = sorted(cve_map.values(),
                    key=lambda x: (_CVE_SEV_ORDER.get(x['severity'], 4), -x['count']))
    return jsonify(result)


_TOOL_INFRA_DOMAINS = {
    "projectdiscovery.io", "cloud.projectdiscovery.io",
    "interact.sh", "oast.pro", "oast.live", "oast.site",
    "oast.online", "oast.fun", "oast.me",
    "burpcollaborator.net", "canarytokens.com",
    "webhook.site", "pipedream.net",
    "requestbin.com", "requestbin.net",
    "hookbin.com", "beeceptor.com",
    "ngrok.io", "ngrok-free.app",
}


def _is_tool_infra_finding(f):
    """True if the finding's host belongs to security-tooling infrastructure."""
    h = (f.get('host') or '').split(':')[0].lower()
    if not h:
        return False
    return any(h == d or h.endswith('.' + d) for d in _TOOL_INFRA_DOMAINS)


# ---------------------------------------------------------------------------
# API Attack (Module 24-API) — the Kill Chain view: passive logic leads +
# actively-confirmed authorization violations, ranked on the L0-L6 ladder.
# ---------------------------------------------------------------------------
_LADDER_ORDER = ['L0', 'L1', 'L2', 'L3', 'L4', 'L5', 'L6']


def _load_api_attack(scan_id):
    """Merge the three API-attack surfaces for a scan into one payload:
      - passive logic LEADS   (api_logic_analysis, capped at L3)
      - authz-oracle findings (auth_oracle, L4+ when an invariant broke)
      - active confirmations  (offensive_verify bfla/nosqli/xxe/etc.)
    Leads are hypotheses; oracle + active findings are the proofs that promote."""
    if not scan_id:
        return {'leads': [], 'confirmed': [], 'summary': {}, 'burp': {}}
    base = os.path.join(BASE_SCAN_DIR, scan_id)

    # 1) passive leads
    leads = []
    for rec in _read_jsonl_file(os.path.join(base, '24_api_attack', 'api_logic_leads.jsonl')):
        if _is_tool_infra_finding(rec):
            continue
        leads.append(rec)

    # 2) actively-confirmed authorization violations (the promotions)
    confirmed = []
    conf_sources = [
        os.path.join(base, '24_advanced_attacks', 'auth_oracle_findings.jsonl'),
        os.path.join(base, '24_advanced_attacks', 'offensive_findings.jsonl'),
    ]
    _API_ATTACK_CHECKS = {'bfla', 'nosqli', 'json_smuggling', 'xxe',
                          'business_logic', 'race', 'graphql', 'jwt'}
    for src in conf_sources:
        for rec in _read_jsonl_file(src):
            if _is_tool_infra_finding(rec):
                continue
            # From offensive_findings, keep the API-surface checks; auth_oracle
            # findings are all authorization violations and always belong here.
            chk = (rec.get('check') or '').lower()
            is_oracle = src.endswith('auth_oracle_findings.jsonl')
            if is_oracle or chk in _API_ATTACK_CHECKS:
                confirmed.append(rec)

    # 3) Burp bridge context (did an authenticated capture feed this scan?)
    burp = _read_json_file(os.path.join(base, '00_har_ingest', 'burp_bridge_summary.json')) or {}
    logic_summary = _read_json_file(os.path.join(base, '24_api_attack', 'api_logic_summary.json')) or {}

    # Invariant board — pair each authz-sensitive lead/finding with its rung.
    def _rung(rec):
        r = rec.get('rung') or (rec.get('extra') or {}).get('ladder_rung') or ''
        if r in _LADDER_ORDER:
            return r
        # infer from confidence for active findings without an explicit rung
        conf = (rec.get('confidence') or '').lower()
        if conf in ('exploited',):
            return 'L5'
        if conf in ('confirmed',):
            return 'L4'
        return 'L3'

    board = []
    for rec in confirmed:
        board.append({
            'endpoint': rec.get('url') or rec.get('endpoint') or '',
            'invariant': rec.get('category') or rec.get('check') or rec.get('title') or '',
            'verdict': 'VIOLATED',
            'rung': _rung(rec),
            'severity': (rec.get('severity') or 'info').lower(),
            'evidence': (rec.get('evidence') or '')[:400],
            'stage': 'confirmed',
        })
    for rec in leads:
        board.append({
            'endpoint': rec.get('endpoint') or '',
            'invariant': rec.get('invariant') or rec.get('category') or '',
            'verdict': 'LEAD',
            'rung': rec.get('rung') or 'L2',
            'severity': (rec.get('severity') or 'info').lower(),
            'evidence': '; '.join(rec.get('evidence') or [])[:400],
            'stage': 'lead',
        })
    board.sort(key=lambda b: (_LADDER_ORDER.index(b['rung']) if b['rung'] in _LADDER_ORDER else 0,
                              {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}.get(b['severity'], 0)),
               reverse=True)

    summary = {
        'total_leads': len(leads),
        'total_confirmed': len(confirmed),
        'by_analyzer': logic_summary.get('by_analyzer', {}),
        'leads_by_severity': {s: sum(1 for l in leads if (l.get('severity') or '').lower() == s)
                              for s in ('critical', 'high', 'medium', 'low', 'info')},
        'confirmed_by_severity': {s: sum(1 for c in confirmed if (c.get('severity') or '').lower() == s)
                                  for s in ('critical', 'high', 'medium', 'low', 'info')},
        'by_rung': {r: sum(1 for b in board if b['rung'] == r) for r in _LADDER_ORDER},
        'evidence_source': logic_summary.get('evidence_source', 'none'),
        'promoted': sum(1 for b in board if b['rung'] in ('L4', 'L5', 'L6')),
    }
    return {'leads': leads, 'confirmed': confirmed, 'board': board,
            'summary': summary, 'burp': burp}


@app.route('/api/scan/<scan_id>/api-attack')
def api_api_attack(scan_id):
    """API Kill Chain view: passive logic leads + actively-confirmed authz
    violations, ranked on the L0-L6 evidence ladder."""
    return jsonify(_load_api_attack(scan_id))


@app.route('/api/api-attack')
def api_api_attack_legacy():
    """Legacy API-attack endpoint keyed by ?target= (matches the dashboard's
    target-scoped fetch convention)."""
    scan_id = resolve_target(request.args.get('target'))
    if not scan_id:
        return jsonify({'leads': [], 'confirmed': [], 'board': [], 'summary': {}, 'burp': {}})
    return jsonify(_load_api_attack(scan_id))


def _load_api_security_findings(scan_id):
    """Read the deduplicated, tool-tagged API security findings for a scan."""
    if not scan_id:
        return []
    api_dir = os.path.join(BASE_SCAN_DIR, scan_id, '16_api_security')
    # Merge engine findings with oracle-confirmed input-probe findings (Module
    # 20.3). Both use the same schema, so the API Security view shows them together.
    src_files = [os.path.join(api_dir, 'api_findings.jsonl'),
                 os.path.join(api_dir, 'input_probe_findings.jsonl')]
    findings = []
    if not any(os.path.exists(p) for p in src_files):
        return findings
    try:
        for findings_file in src_files:
            if not os.path.exists(findings_file):
                continue
            with open(findings_file, 'r', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except Exception:
                        continue
                    if _is_tool_infra_finding(rec):
                        continue
                    # Strip local filesystem paths leaked from nuclei template-path
                    for key in ('path', 'endpoint', 'evidence'):
                        val = rec.get(key, '')
                        if isinstance(val, str) and '/nuclei-templates/' in val:
                            rec[key] = re.sub(
                                r'/[^\s"]*?/nuclei-templates/[^\s"]*', '<nuclei-template>', val)
                    findings.append(rec)
    except Exception as exc:
        logger.error("Failed to read API findings: %s", exc)
    return findings


# Engine → human label + canonical family. One analyst-facing vocabulary so the
# UI can facet by "which engine found this" without the user knowing file names.
_ENGINE_LABELS = {
    'arise-intel': 'Intelligence Engine',
    'apisec': 'apisec.py',
    'api_logic': 'Logic Analyzer',
    'auth_oracle': 'Authz Oracle',
    'offensive_verify': 'Offensive Verify',
}
_ACTIVE_CHECK_ENGINE = {  # offensive_verify check → stays under offensive_verify
    'bfla': 'offensive_verify', 'nosqli': 'offensive_verify',
    'json_smuggling': 'offensive_verify', 'xxe': 'offensive_verify',
    'business_logic': 'offensive_verify', 'race': 'offensive_verify',
    'jwt': 'offensive_verify', 'graphql': 'offensive_verify',
}


def _rung_idx(rung):
    order = ['L0', 'L1', 'L2', 'L3', 'L4', 'L5', 'L6']
    return order.index(rung) if rung in order else -1


def _host_from_endpoint(endpoint):
    """Extract a host from an endpoint when it's a full URL (findings whose
    endpoint is 'METHOD:/path' carry the host separately)."""
    ep = endpoint or ''
    m = re.match(r'[a-z]+://([^/:]+)', ep, re.I)
    return m.group(1).lower() if m else ''


def _norm_api(severity, endpoint, host, finding, category, engine, tier,
              rung, confidence, evidence, hosts=None):
    host = (host or '').strip()
    if not host:
        host = _host_from_endpoint(endpoint)
    return {
        'severity': (severity or 'info').lower(),
        'endpoint': endpoint or '',
        'host': host or '',
        # Full host list for endpoints that span several (host shows "N hosts").
        'hosts': [h for h in (hosts or []) if h][:20],
        'finding': finding or '—',
        'category': category or '',
        'engine': engine,
        'engine_label': _ENGINE_LABELS.get(engine, engine),
        'tier': tier,                      # 'confirmed' | 'potential'
        'rung': rung or '',
        'confidence': confidence or '',
        'evidence': (evidence or '')[:400],
    }


def _load_api_unified(scan_id):
    """One analyst-facing API findings surface (Qualys/Tenable model): every
    finding from every engine, normalized, and organized by CONFIDENCE TIER
    (confirmed vs potential) rather than by which engine produced it. Engine
    becomes a filter facet, not a separate screen."""
    unified = []

    # 1) Classifier findings (Intelligence Engine + apisec) — Module 16.
    for f in _load_api_security_findings(scan_id):
        tools = [t for t in (f.get('tools') or [f.get('tool')]) if t]
        engine = 'arise-intel' if 'arise-intel' in tools else (tools[0] if tools else 'arise-intel')
        conf = (f.get('confidence') or '').lower()
        is_conf = conf in ('confirmed', 'verified-exploit')
        ep = f.get('endpoint') or ((f.get('method', '') + ' ' + (f.get('path') or '')).strip())
        unified.append(_norm_api(
            f.get('severity'), ep, f.get('host'),
            (f.get('issue_class') or f.get('title') or '').replace('_', ' '),
            f.get('category'), engine,
            'confirmed' if is_conf else 'potential',
            'L4' if is_conf else '', conf or 'single-tool',
            f.get('evidence')))

    # 2) Passive logic leads + active confirmations — Module 24-API.
    attack = _load_api_attack(scan_id)
    for lead in attack.get('leads', []):
        unified.append(_norm_api(
            lead.get('severity'), lead.get('endpoint'), lead.get('host'),
            (lead.get('invariant') or lead.get('title') or lead.get('category') or '').replace('_', ' '),
            lead.get('category'), 'api_logic', 'potential',
            lead.get('rung') or 'L2', 'lead',
            '; '.join(lead.get('evidence') or []), hosts=lead.get('hosts')))
    for c in attack.get('confirmed', []):
        chk = (c.get('check') or '').lower()
        engine = 'auth_oracle' if 'auth_oracle' in (c.get('module') or '') or chk in ('bola', 'bfla') and c.get('tool') == 'auth_oracle' else _ACTIVE_CHECK_ENGINE.get(chk, 'auth_oracle')
        rung = c.get('rung') or (c.get('extra') or {}).get('ladder_rung') or ('L4' if (c.get('confidence') or '').lower() in ('confirmed', 'exploited') else 'L3')
        unified.append(_norm_api(
            c.get('severity'), c.get('url') or c.get('endpoint'), c.get('host'),
            (c.get('title') or c.get('category') or c.get('check') or '').replace('_', ' '),
            c.get('category') or c.get('check'), engine,
            'confirmed' if _rung_idx(rung) >= 4 else 'potential',
            rung, c.get('confidence') or 'confirmed',
            c.get('evidence')))

    sev_rank = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}
    unified.sort(key=lambda x: (
        0 if x['tier'] == 'confirmed' else 1,
        -_rung_idx(x['rung']),
        -sev_rank.get(x['severity'], 0)))

    asummary = attack.get('summary', {})
    summary = {
        'total': len(unified),
        'confirmed': sum(1 for f in unified if f['tier'] == 'confirmed'),
        'potential': sum(1 for f in unified if f['tier'] == 'potential'),
        'unique_endpoints': len({f['endpoint'] for f in unified if f['endpoint']}),
        'by_severity': {s: sum(1 for f in unified if f['severity'] == s)
                        for s in ('critical', 'high', 'medium', 'low', 'info')},
        'by_engine': {e: sum(1 for f in unified if f['engine'] == e)
                      for e in _ENGINE_LABELS},
        'by_tier': {'confirmed': sum(1 for f in unified if f['tier'] == 'confirmed'),
                    'potential': sum(1 for f in unified if f['tier'] == 'potential')},
        'by_rung': asummary.get('by_rung', {}),
        'by_analyzer': asummary.get('by_analyzer', {}),
        'evidence_source': asummary.get('evidence_source', 'none'),
    }
    return {
        'findings': unified,
        'summary': summary,
        'engine_labels': _ENGINE_LABELS,
        'burp': attack.get('burp', {}),
    }


@app.route('/api/scan/<scan_id>/api-security')
def api_api_security(scan_id):
    """Unified API security surface — all engines, one list, tiered by confidence."""
    return jsonify(_load_api_unified(scan_id))


@app.route('/api/api-security')
def api_api_security_legacy():
    """Legacy API security endpoint keyed by ?target=."""
    scan_id = resolve_target(request.args.get('target'))
    logger.info("API request: /api/api-security target=%s", scan_id)
    if not scan_id:
        return jsonify({'findings': [], 'summary': {'total': 0, 'confirmed': 0,
                        'potential': 0, 'by_severity': {}, 'by_engine': {},
                        'by_tier': {}, 'by_rung': {}, 'by_analyzer': {},
                        'evidence_source': 'none'}, 'engine_labels': _ENGINE_LABELS, 'burp': {}})
    return api_api_security(scan_id)


@app.route('/api/cloud')
def api_cloud_legacy():
    """Cloud exposure endpoint keyed by ?target=."""
    scan_id = resolve_target(request.args.get('target'))
    logger.info("API request: /api/cloud target=%s", scan_id)
    if not scan_id:
        return jsonify({
            'total': 0, 'security_count': 0, 'posture_count': 0,
            'by_severity': {}, 'categories': [], 'findings': [],
            'recon': build_cloud_recon(None),
            'compliance': load_cloud_compliance(None),
            'asset_map': load_cloud_asset_map(None),
            'depth': load_cloud_depth(None),
        })
    return api_cloud(scan_id)


@app.route('/api/ledger')
def api_ledger():
    """Historic Asset Ledger view keyed by ?target=.
    Serves the durable per-target attack-surface archive (subdomains/endpoints/
    apis/services/secrets with first_seen/last_seen/status) plus the latest
    scan's delta + regression artifacts, for the Asset History sub-tab."""
    raw = (request.args.get('target') or '').strip()
    scan_id = resolve_target(raw)
    target = None
    scan_dir = None
    if scan_id:
        scan_dir = os.path.join(BASE_SCAN_DIR, scan_id)
        data = get_cached_scan_data(scan_id)
        if data:
            target = data.get('pipeline_info', {}).get('target')
    if not target:
        target = raw  # fall back to the raw ?target= value (domain)
    if not target:
        return jsonify({'target': None, 'summary': {}, 'stores': {}, 'timeline': []})
    state_root = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'state')
    try:
        view = ledger_view.build_view(target, root=state_root, scan_dir=scan_dir)
    except Exception as exc:
        logger.exception("ledger view failed for %s: %s", target, exc)
        view = {'target': target, 'summary': {}, 'stores': {}, 'timeline': [], 'error': str(exc)}
    return jsonify(view)


def _legacy_host_rows(scan_id):
    data = get_cached_scan_data(scan_id)
    if not data:
        return []

    rows = []
    for host, host_data in data['hosts'].items():
        rows.append({
            'host': host,
            'ip': host_data.get('ip', ''),
            'resolved': host_data.get('resolved', False),
            'http_status': host_data.get('http_status', ''),
            'cdn': host_data.get('cdn', False),
            'waf_vendor': host_data.get('waf_vendor', 'none'),
            'skip_bruteforce': host_data.get('skip_bruteforce', False),
            'security_score': host_data.get('security_header_score', 0),
            'server_banner': host_data.get('server_banner', ''),
            'service_type': host_data.get('service_type', 'http'),
            'ports_open': sorted(set(host_data.get('ports_open', []))),
            'cve_count': len(host_data.get('cve_candidates', [])),
            'risk_score': host_data.get('risk_score', 0),
            'risk_band': host_data.get('risk_band', 'low'),
            'ssl_dangling': host_data.get('ssl_dangling', False),
            'ssl_cert_cn': host_data.get('ssl_cert_cn', ''),
            'ssl_checked': host_data.get('ssl_checked', False),
            'is_api': host_data.get('is_api', False),
            'api_signals': host_data.get('api_signals', []),
            'is_s3': host_data.get('is_s3', False),
            'tech_tag': host_data.get('tech_tag', ''),
        })
    return rows


def _legacy_port_rows(scan_id):
    data = get_cached_scan_data(scan_id)
    if not data:
        return []

    port_map = {}
    for host, host_data in data['hosts'].items():
        ip = host_data.get('ip', '')
        services_list = host_data.get('services', [])
        
        # Build a quick lookup for port -> service name
        port_service_map = {}
        for srv in services_list:
            if 'port' in srv and 'name' in srv:
                port_service_map[int(srv['port'])] = srv['name']
                
        for port in sorted(set(host_data.get('ports_open', []))):
            port = int(port)
            
            # Get service name from Nmap, fallback to HTTP logic if missing
            service_name = port_service_map.get(port)
            if not service_name or service_name == 'unknown':
                if port == 443 or port == 8443:
                    service_name = 'https'
                elif port == 80 or port == 8080:
                    service_name = 'http'
                else:
                    service_name = 'unknown'

            port_map.setdefault(port, {'port': port, 'host_count': 0, 'hosts': []})
            port_map[port]['hosts'].append({
                'host': host,
                'ip': ip,
                'http_status': host_data.get('http_status', ''),
                'waf': host_data.get('waf_vendor', 'none') != 'none',
                'service': service_name
            })
            port_map[port]['host_count'] = len({entry['host'] for entry in port_map[port]['hosts']})

    return [port_map[port] for port in sorted(port_map)]


@app.route('/api/targets')
def api_targets_legacy():
    """Legacy target list for the older frontend."""
    logger.info("API request: /api/targets")
    return jsonify(get_target_summaries())


@app.route('/api/status')
def api_status_legacy():
    """Legacy status endpoint."""
    scan_id = resolve_target(request.args.get('target'))
    logger.info("API request: /api/status target=%s", scan_id)
    data = get_cached_scan_data(scan_id) if scan_id else None
    if not data:
        return jsonify({'status': 'no_data', 'target': scan_id or '', 'message': 'No scan data available'})

    pipeline_info = data.get('pipeline_info', {})
    statistics = data.get('statistics', {})
    return jsonify({
        'status': pipeline_info.get('status', 'unknown'),
        'target': pipeline_info.get('target', scan_id),
        'version': pipeline_info.get('version', ''),
        'start_time': pipeline_info.get('start_time', ''),
        'scan_id': scan_id,
        'duration': statistics.get('duration_seconds', 0)
    })


@app.route('/api/statistics')
def api_statistics_legacy():
    """Legacy statistics endpoint."""
    scan_id = resolve_target(request.args.get('target'))
    logger.info("API request: /api/statistics target=%s", scan_id)
    data = get_cached_scan_data(scan_id) if scan_id else None
    if not data:
        return jsonify({})

    hosts = data.get('hosts', {})
    statistics = data.get('statistics', {})
    computed_http = sum(1 for h in hosts.values() if h.get('http_status'))
    computed_waf = sum(1 for h in hosts.values() if h.get('waf_vendor') not in ('none', '', None))
    return jsonify({
        'total_hosts': statistics.get('total_hosts', len(hosts)),
        'resolved_hosts': statistics.get('resolved_hosts', sum(1 for h in hosts.values() if h.get('resolved'))),
        'http_hosts': max(statistics.get('http_hosts', 0), computed_http),
        'waf_hosts': max(statistics.get('waf_hosts', 0), computed_waf),
        'cdn_hosts': statistics.get('cdn_hosts', sum(1 for h in hosts.values() if h.get('cdn'))),
        'non_http_services': statistics.get('non_http_services', sum(1 for h in hosts.values() if h.get('service_type') == 'non_http')),
        'total_vulnerabilities': len(data.get('vulnerabilities', [])),
        # Port counts: manifest value can be stale (written before httpx
        # backfill / crawl_reverify populated ports_open). Use max() so the
        # computed count wins when it's higher — never let a stale 0 override
        # real data. Same pattern as http_hosts / waf_hosts above.
        'total_ports': max(statistics.get('total_ports', 0) or 0,
                           sum(len(h.get('ports_open', [])) for h in hosts.values())),
        'open_ports': max(statistics.get('open_ports', 0) or 0,
                          sum(len(h.get('ports_open', [])) for h in hosts.values())),
        'services_fingerprinted': statistics.get('services_fingerprinted', sum(1 for h in hosts.values() if h.get('services'))),
        'total_urls': statistics.get('total_urls', 0),
        'total_js_files': statistics.get('total_js_files', 0),
        'total_secrets': statistics.get('total_secrets', 0),
        'port_scan_status': data.get('port_scan_status', statistics.get('port_scan_status', 'missing'))
    })


@app.route('/api/hosts')
def api_hosts_legacy():
    """Legacy hosts endpoint."""
    scan_id = resolve_target(request.args.get('target'))
    logger.info("API request: /api/hosts target=%s", scan_id)
    return jsonify(_legacy_host_rows(scan_id))


@app.route('/api/hosts/search')
def api_hosts_search():
    """Search endpoint — also respects an optional filter parameter."""
    scan_id = resolve_target(request.args.get('target'))
    query = request.args.get('q', '').strip().lower()
    filter_type = request.args.get('filter', 'all').strip()
    logger.info("API request: /api/hosts/search target=%s query=%s filter=%s", scan_id, query, filter_type)
    hosts = _legacy_host_rows(scan_id)
    hosts = _apply_host_filter(hosts, filter_type)
    if query:
        hosts = [h for h in hosts if query in h['host'].lower() or query in h['ip'].lower()]
    return jsonify(hosts)


@app.route('/api/hosts/filter/<filter_type>')
def api_hosts_filter(filter_type):
    """Filter endpoint — also respects an optional search query."""
    scan_id = resolve_target(request.args.get('target'))
    query = request.args.get('q', '').strip().lower()
    logger.info("API request: /api/hosts/filter/%s target=%s query=%s", filter_type, scan_id, query)
    hosts = _legacy_host_rows(scan_id)
    hosts = _apply_host_filter(hosts, filter_type)
    if query:
        hosts = [h for h in hosts if query in h['host'].lower() or query in h['ip'].lower()]
    return jsonify(hosts)


def _apply_host_filter(hosts, filter_type):
    if filter_type == 'waf':
        return [h for h in hosts if (h.get('waf_vendor') or '').lower() not in ('none', '')]
    elif filter_type == 'http':
        return [h for h in hosts if h.get('http_status')]
    elif filter_type == 'resolved':
        return [h for h in hosts if h.get('resolved')]
    elif filter_type == 'cdn':
        return [h for h in hosts if h.get('cdn')]
    elif filter_type == 'takeover':
        return [h for h in hosts if h.get('ssl_dangling')]
    elif filter_type == 'api':
        return [h for h in hosts if h.get('is_api')]
    return hosts


@app.route('/api/ports')
def api_ports_legacy():
    """Legacy ports endpoint."""
    scan_id = resolve_target(request.args.get('target'))
    logger.info("API request: /api/ports target=%s", scan_id)
    if not scan_id:
        return jsonify([])
    return jsonify(_legacy_port_rows(scan_id))


@app.route('/api/services')
def api_services():
    """Nmap service fingerprinting results with risk classification."""
    scan_id = resolve_target(request.args.get('target'))
    logger.info("API request: /api/services target=%s", scan_id)
    data = get_cached_scan_data(scan_id) if scan_id else None
    if not data:
        return jsonify({'services': [], 'summary': {}})

    hosts = data.get('hosts', {})
    rows = []
    proto_counts = {}
    for host, hd in hosts.items():
        svc_list = hd.get('services', [])
        open_ports = sorted(set(int(p) for p in hd.get('ports_open', [])))
        svc_map = {}
        for svc in svc_list:
            p = int(svc.get('port', 0))
            svc_map[p] = svc

        for port in open_ports:
            svc = svc_map.get(port, {})
            name = svc.get('name', PORT_MAPPINGS.get(port, 'unknown'))
            product = svc.get('product', '')
            version = svc.get('version', '')
            extra = svc.get('extrainfo', '')
            is_t1 = port in PORT_RISK_TIER1
            is_t2 = port in PORT_RISK_TIER2
            is_t3 = port in PORT_RISK_TIER3
            risk = 'critical' if is_t1 else 'high' if is_t2 else 'medium' if is_t3 else 'low'
            proto_counts[name] = proto_counts.get(name, 0) + 1

            rows.append({
                'host': host,
                'ip': hd.get('ip', ''),
                'port': port,
                'service': name,
                'product': product,
                'version': version,
                'extra': extra,
                'fingerprint': f"{product} {version}".strip() if product else '',
                'risk': risk,
                'waf': hd.get('waf_vendor', 'none'),
            })

    unique_hosts = len(set(r['host'] for r in rows))
    sensitive_count = sum(1 for r in rows if r['risk'] in ('critical', 'high'))
    top_services = sorted(proto_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    return jsonify({
        'services': rows,
        'summary': {
            'total_ports': len(rows),
            'unique_hosts': unique_hosts,
            'sensitive_ports': sensitive_count,
            'unique_services': len(proto_counts),
            'top_services': [{'name': n, 'count': c} for n, c in top_services],
        }
    })


@app.route('/api/hsts')
def api_hsts():
    """HSTS audit findings — one row per finding with evidence."""
    scan_id = resolve_target(request.args.get('target'))
    logger.info("API request: /api/hsts target=%s", scan_id)
    if not scan_id:
        return jsonify({'findings': [], 'by_severity': {}, 'hosts_tested': 0})

    base = os.path.join(BASE_SCAN_DIR, scan_id, '04_http_discovery')
    f = os.path.join(base, 'hsts_findings.jsonl')
    findings = []
    by_severity = {}
    hosts = set()
    if os.path.exists(f):
        try:
            with open(f, 'r', errors='ignore') as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        r = json.loads(line)
                    except Exception:
                        continue
                    # _meta_ = pipeline bookkeeping; _tls_posture lives in its
                    # own file (older scans may still have it inline — skip here).
                    if r.get('type', '').startswith('_meta_') or r.get('type') == '_tls_posture':
                        continue
                    findings.append(r)
                    s = r.get('severity', 'info')
                    by_severity[s] = by_severity.get(s, 0) + 1
                    if r.get('host'):
                        hosts.add(r['host'])
        except Exception as exc:
            logger.error("hsts read failed: %s", exc)

    # Per-host TLS/certificate posture (SSL-Labs-style graded rows).
    posture = []
    pf = os.path.join(base, 'tls_posture.jsonl')
    if os.path.exists(pf):
        try:
            with open(pf, 'r', errors='ignore') as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        posture.append(json.loads(line))
                    except Exception:
                        continue
        except Exception as exc:
            logger.error("tls_posture read failed: %s", exc)

    # Roll-up KPIs for the posture view (the numbers a reviewer scans first).
    gc = {}
    kpis = {'graded': 0, 'no_tls': 0, 'expired': 0, 'expiring': 0, 'mismatch': 0,
            'untrusted': 0, 'weak': 0, 'no_hsts': 0, 'legacy_tls': 0}
    for p in posture:
        g = p.get('grade', '—')
        gc[g] = gc.get(g, 0) + 1
        if p.get('host'):
            hosts.add(p['host'])
        if not p.get('tls_ok'):
            kpis['no_tls'] += 1
            continue
        kpis['graded'] += 1
        if p.get('expired'):
            kpis['expired'] += 1
        elif p.get('expiring_soon'):
            kpis['expiring'] += 1
        if p.get('hostname_match') is False:
            kpis['mismatch'] += 1
        if p.get('self_signed') or p.get('trusted') is False:
            kpis['untrusted'] += 1
        if p.get('weak_key') or p.get('weak_sig'):
            kpis['weak'] += 1
        if not p.get('hsts'):
            kpis['no_hsts'] += 1
        if (p.get('protocol') or '') in ('SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1'):
            kpis['legacy_tls'] += 1

    return jsonify({
        'findings': findings,
        'by_severity': by_severity,
        'hosts_tested': len(hosts),
        'total_findings': len(findings),
        'posture': posture,
        'grade_counts': gc,
        'kpis': kpis,
    })


@app.route('/api/sbom')
def api_sbom():
    """Software Bill of Materials — components + versions, multi-method (Module 25)."""
    scan_id = resolve_target(request.args.get('target'))
    logger.info("API request: /api/sbom target=%s", scan_id)
    if not scan_id:
        return jsonify({'components': [], 'summary': {}})
    base = os.path.join(BASE_SCAN_DIR, scan_id, '25_sbom')
    components = []
    pf = os.path.join(base, 'sbom.jsonl')
    if os.path.exists(pf):
        try:
            with open(pf, 'r', errors='ignore') as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        components.append(json.loads(line))
                    except Exception:
                        continue
        except Exception as exc:
            logger.error("sbom read failed: %s", exc)
    summary = {}
    sf = os.path.join(base, 'sbom.json')
    if os.path.exists(sf):
        try:
            summary = json.load(open(sf, 'r', errors='ignore'))
        except Exception:
            pass
    return jsonify({'components': components, 'summary': summary})


def _parse_stored_http(path, max_body=16000):
    """Parse an httpx stored-response file → the real captured HTTP exchange
    (request headers + response status/headers + body) for reproduction."""
    try:
        with open(path, 'r', errors='ignore') as f:
            data = f.read(400000)
    except Exception:
        return None
    # The file is: <request block>\n\n<response block>. The response status line
    # is the first "\nHTTP/<d>" (the request's "GET / HTTP/1.1" has no leading \n).
    m = re.search(r'\nHTTP/\d', data)
    if m:
        req_block = data[:m.start()].strip()
        resp_block = data[m.start() + 1:]
    else:
        req_block, resp_block = '', data
    parts = re.split(r'\r?\n\r?\n', resp_block, maxsplit=1)
    head = parts[0]
    body = parts[1] if len(parts) > 1 else ''
    hlines = head.splitlines()
    status_line = hlines[0] if hlines else ''
    resp_headers = [ln for ln in hlines[1:] if ':' in ln]
    # Strip chunked-transfer size markers so the body is readable/reproducible.
    if body and any('transfer-encoding' in h.lower() and 'chunked' in h.lower()
                    for h in resp_headers):
        body = re.sub(r'(?m)^[0-9a-fA-F]{1,6}\r?\n', '', body)
    req_lines = req_block.splitlines()
    req_line = req_lines[0] if req_lines else ''
    method = (req_line.split(' ', 1)[0] or 'GET').strip() or 'GET'
    return {
        'request': req_block,
        'request_line': req_line,
        'method': method,
        'status': status_line,
        'response_headers': resp_headers,
        'body': body[:max_body],
        'body_bytes': len(body),
        'body_truncated': len(body) > max_body,
    }


@app.route('/api/http-evidence')
def api_http_evidence():
    """Real captured HTTP evidence (request + response headers + body) for a host,
    straight from the httpx stored responses — the proof to reproduce a finding."""
    scan_id = resolve_target(request.args.get('target'))
    host = (request.args.get('host') or '').strip().lower()
    want_port = (request.args.get('port') or '').strip()
    if not scan_id or not host:
        return jsonify({'error': 'target and host required'}), 400
    hc = os.path.join(BASE_SCAN_DIR, scan_id, '04_http_discovery', 'http_confirmed.json')
    if not os.path.exists(hc):
        return jsonify({'error': 'no http_confirmed.json for this scan'}), 404

    best = None  # (score, entry)
    try:
        with open(hc, 'r', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                except Exception:
                    continue
                eh = (e.get('host') or e.get('input') or '').strip().lower()
                if eh != host:
                    continue
                if not e.get('stored_response_path'):
                    continue
                if want_port and str(e.get('port') or '') != want_port:
                    continue
                score = 0
                if (e.get('scheme') == 'https') or ':443' in (e.get('url') or ''):
                    score += 10
                if e.get('status_code') in (200, 403, 401, 500):
                    score += 5
                if best is None or score > best[0]:
                    best = (score, e)
    except Exception as exc:
        logger.error("http-evidence read failed: %s", exc)
        return jsonify({'error': 'read failed'}), 500

    if not best:
        return jsonify({'error': 'no captured HTTP response stored for this host',
                        'host': host}), 404

    entry = best[1]
    parsed = _parse_stored_http(entry['stored_response_path'])
    if not parsed:
        return jsonify({'error': 'stored response unreadable'}), 404

    url = entry.get('url') or ('https://' + host + '/')
    parsed.update({
        'host': host,
        'url': url,
        'port': entry.get('port'),
        'status_code': entry.get('status_code'),
        'ip': (entry.get('a') or [None])[0] if isinstance(entry.get('a'), list) else entry.get('host_ip'),
        'captured_at': entry.get('timestamp') or entry.get('time'),
        'curl': "curl -s -i -k -A 'Mozilla/5.0' '%s'" % url,
    })
    return jsonify(parsed)


@app.route('/api/geo')
def api_geo():
    """IP geo enrichment — one row per IP with lat/lon/ASN + resolved hosts."""
    scan_id = resolve_target(request.args.get('target'))
    logger.info("API request: /api/geo target=%s", scan_id)
    if not scan_id:
        return jsonify({'entries': [], 'total': 0, 'geo_located': 0})

    f = os.path.join(BASE_SCAN_DIR, scan_id,
                     '03_dns_resolution/ip_geo.jsonl')
    entries = []
    geo_located = 0
    if os.path.exists(f):
        try:
            with open(f, 'r', errors='ignore') as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        r = json.loads(line)
                        entries.append(r)
                        if r.get('lat') is not None:
                            geo_located += 1
                    except Exception:
                        continue
        except Exception as exc:
            logger.error("geo read failed: %s", exc)

    return jsonify({
        'entries': entries,
        'total': len(entries),
        'geo_located': geo_located,
    })


_SEVERITY_RANK = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4, 'unknown': 5}


@app.route('/api/nuclei-nonweb')
def api_nuclei_nonweb():
    """Non-web service findings — one row per discovered non-web service
    (SSH/MySQL/etc), nmap-fingerprint enriched, service-first.

    Also lists every non-web origin port ports/port_split.py discovered that
    did NOT get a confirmed vulnerability, as a clean 'info' baseline row.
    Without this, the tab is indistinguishable between "we found this port
    and tested it, nothing wrong" and "we never found anything here at
    all" — both render as empty.

    Every row (confirmed or baseline) is enriched from the same nmap
    service-fingerprint data /api/services uses (svc.name/product/version),
    since a confirmed nuclei finding is otherwise just a template hit with
    no product/version context. Rows are sorted confirmed-first (by
    severity), then baseline rows by service name — so real signal never
    gets buried under "nothing found here" rows, and grouping reads by
    service rather than by raw port number.
    """
    scan_id = resolve_target(request.args.get('target'))
    logger.info("API request: /api/nuclei-nonweb target=%s", scan_id)
    if not scan_id:
        return jsonify({'findings': [], 'by_severity': {}, 'total': 0})

    data = get_cached_scan_data(scan_id) or {}
    hosts_data = data.get('hosts', {})
    svc_maps = {}  # host -> {port: svc_dict}, built lazily per host

    def _svc_for(host, port):
        svc_map = svc_maps.get(host)
        if svc_map is None:
            svc_map = {int(s.get('port', 0)): s
                       for s in hosts_data.get(host, {}).get('services', [])}
            svc_maps[host] = svc_map
        return svc_map.get(port, {})

    f = os.path.join(BASE_SCAN_DIR, scan_id,
                     '12_nuclei_scanning/nuclei_nonweb_findings.jsonl')
    findings = []
    by_severity = {}
    confirmed_keys = set()
    if os.path.exists(f):
        try:
            with open(f, 'r', errors='ignore') as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        r = json.loads(line)
                        s = (r.get('info', {}).get('severity') or 'info').lower()
                        by_severity[s] = by_severity.get(s, 0) + 1
                        matched = r.get('matched-at', '') or ''
                        host = r.get('host', '')
                        port_str = matched.rsplit(':', 1)[-1] if ':' in matched else ''
                        if host and port_str:
                            confirmed_keys.add((host, str(port_str)))
                        if host and port_str.isdigit():
                            svc = _svc_for(host, int(port_str))
                            r['service'] = svc.get('name') or PORT_MAPPINGS.get(int(port_str), '')
                        else:
                            svc = {}
                            r['service'] = ''
                        r['product'] = svc.get('product', '')
                        r['version'] = svc.get('version', '')
                        r['baseline'] = False
                        findings.append(r)
                    except Exception:
                        continue
        except Exception as exc:
            logger.error("nuclei-nonweb read failed: %s", exc)

    ports_file = os.path.join(BASE_SCAN_DIR, scan_id, '14_port_scan/nonweb_origin_ports.jsonl')
    if os.path.exists(ports_file):
        try:
            with open(ports_file, 'r', errors='ignore') as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        p = json.loads(line)
                    except Exception:
                        continue
                    host = p.get('host', '')
                    port = p.get('port')
                    if not host or port is None:
                        continue
                    port = int(port)
                    if (host, str(port)) in confirmed_keys:
                        continue  # already has a real finding above
                    svc = _svc_for(host, port)
                    name = svc.get('name') or PORT_MAPPINGS.get(port, 'unknown')
                    product = svc.get('product', '')
                    version = svc.get('version', '')
                    fingerprint = f"{product} {version}".strip()
                    label = (f"{name}" + (f" ({fingerprint})" if fingerprint else "")
                            + f" — port {port} open, no vulnerability confirmed")
                    findings.append({
                        'host': host, 'ip': p.get('ip', ''),
                        'matched-at': f"{host}:{port}",
                        'template-id': 'port-baseline',
                        'info': {'name': label, 'severity': 'info'},
                        'service': name, 'product': product, 'version': version,
                        'baseline': True,
                    })
                    by_severity['info'] = by_severity.get('info', 0) + 1
        except Exception as exc:
            logger.error("nonweb baseline read failed: %s", exc)

    findings.sort(key=lambda r: (
        bool(r.get('baseline')),
        _SEVERITY_RANK.get((r.get('info', {}).get('severity') or 'info').lower(), 5),
        (r.get('service') or '').lower(),
        r.get('host') or '',
    ))

    return jsonify({
        'findings': findings,
        'by_severity': by_severity,
        'total': len(findings),
    })


@app.route('/api/techstack')
def api_techstack():
    """Technology stack detected via httpx tech-detect across all hosts."""
    scan_id = resolve_target(request.args.get('target'))
    logger.info("API request: /api/techstack target=%s", scan_id)
    if not scan_id:
        return jsonify({'technologies': [], 'by_category': {}, 'total_hosts': 0})

    http_file = os.path.join(BASE_SCAN_DIR, scan_id, '04_http_discovery/http_confirmed.json')
    tech_counts = {}
    tech_hosts = {}
    total_hosts = 0

    TECH_CATEGORIES = {
        'Amazon Web Services': 'cloud', 'Amazon CloudFront': 'cdn', 'Amazon S3': 'cloud',
        'Amazon ELB': 'cloud', 'Google Cloud': 'cloud', 'Firebase': 'cloud',
        'Azure': 'cloud', 'Microsoft Azure': 'cloud', 'DigitalOcean': 'cloud',
        'Cloudflare': 'cdn', 'Cloudflare Bot Management': 'security',
        'Cloudflare Browser Insights': 'analytics', 'Fastly': 'cdn',
        'Akamai': 'cdn', 'Varnish': 'cdn', 'jsDelivr': 'cdn', 'cdnjs': 'cdn',
        'Nginx': 'web-server', 'Apache': 'web-server', 'IIS': 'web-server',
        'LiteSpeed': 'web-server', 'OpenResty': 'web-server', 'Envoy': 'web-server',
        'React': 'frontend', 'Vue.js': 'frontend', 'Angular': 'frontend',
        'jQuery': 'frontend', 'Bootstrap': 'frontend', 'Next.js': 'frontend',
        'Nuxt.js': 'frontend', 'Gatsby': 'frontend', 'Svelte': 'frontend',
        'Node.js': 'backend', 'Express': 'backend', 'Django': 'backend',
        'Flask': 'backend', 'Laravel': 'backend', 'Ruby on Rails': 'backend',
        'Spring': 'backend', 'ASP.NET': 'backend', 'Microsoft ASP.NET': 'backend',
        'PHP': 'backend', 'Python': 'backend', 'Go': 'backend', 'Java': 'backend',
        'WordPress': 'cms', 'Drupal': 'cms', 'Joomla': 'cms', 'Shopify': 'cms',
        'Magento': 'cms', 'Ghost': 'cms', 'Contentful': 'cms', 'Strapi': 'cms',
        'Google Analytics': 'analytics', 'Google Tag Manager': 'analytics',
        'Hotjar': 'analytics', 'Segment': 'analytics', 'Mixpanel': 'analytics',
        'HSTS': 'security', 'HTTP/3': 'protocol', 'HTTP/2': 'protocol',
        'GitHub Pages': 'hosting', 'Netlify': 'hosting', 'Vercel': 'hosting',
        'Heroku': 'hosting', 'Render': 'hosting',
        'Windows Server': 'os', 'Ubuntu': 'os', 'Debian': 'os', 'CentOS': 'os',
        'Redis': 'database', 'MySQL': 'database', 'PostgreSQL': 'database',
        'MongoDB': 'database', 'Elasticsearch': 'database',
    }

    CAT_LABELS = {
        'cloud': 'Cloud Provider', 'cdn': 'CDN / Edge', 'security': 'Security',
        'analytics': 'Analytics', 'web-server': 'Web Server', 'frontend': 'Frontend',
        'backend': 'Backend', 'cms': 'CMS', 'protocol': 'Protocol',
        'hosting': 'Hosting', 'os': 'Operating System', 'database': 'Database',
        'other': 'Other',
    }

    if os.path.exists(http_file):
        try:
            with open(http_file, 'r', errors='ignore') as f:
                for line in f:
                    try:
                        entry = json.loads(line.strip())
                    except Exception:
                        continue
                    host = entry.get('host') or entry.get('input')
                    if host:
                        total_hosts += 1
                    techs = entry.get('tech', [])
                    for t in techs:
                        clean = t.split(':')[0].strip()
                        tech_counts[clean] = tech_counts.get(clean, 0) + 1
                        tech_hosts.setdefault(clean, set()).add(host or '')
        except Exception as exc:
            logger.error("Failed to read tech stack from %s: %s", http_file, exc)

    by_category = {}
    technologies = []
    for name, count in sorted(tech_counts.items(), key=lambda x: x[1], reverse=True):
        cat = TECH_CATEGORIES.get(name, 'other')
        for prefix, prefix_cat in TECH_CATEGORIES.items():
            if name.startswith(prefix):
                cat = prefix_cat
                break
        technologies.append({
            'name': name,
            'count': count,
            'hosts': sorted(list(tech_hosts.get(name, set()))),
            'category': cat,
        })
        by_category.setdefault(cat, {'label': CAT_LABELS.get(cat, cat.title()), 'count': 0, 'techs': []})
        by_category[cat]['count'] += count
        by_category[cat]['techs'].append(name)

    return jsonify({
        'technologies': technologies,
        'by_category': by_category,
        'total_hosts': total_hosts,
    })


def _load_dirsearch(scan_id):
    """Directory-discovery results for a scan.

    Prefers the consolidated endpoint inventory (Module 8B), which already
    merges dirsearch brute-force hits with crawled links and the runtime
    XHR/fetch API calls, deduplicated and path-templated. Falls back to the
    raw dirsearch 200/403/500 files for scans that predate consolidation.
    """
    if not scan_id:
        return []
    base = os.path.join(BASE_SCAN_DIR, scan_id, '08_directory_discovery')

    # Preferred: consolidated, deduplicated endpoint inventory.
    merged = os.path.join(base, 'discovered_endpoints.jsonl')
    if os.path.exists(merged):
        rows = []
        try:
            with open(merged, 'r', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        e = json.loads(line)
                    except Exception:
                        continue
                    methods = e.get("methods") or [e.get("method", "GET")]
                    rows.append({
                        "url": e.get("url", ""),
                        "sample_url": e.get("sample_url", e.get("url", "")),
                        "host": e.get("host", ""),
                        "status": e.get("status", 0) or 0,
                        # F29 (ARISE_REMEDIATION_ROADMAP.md): explicit
                        # never-fetched flag — a scan written before this
                        # field existed has no "verified" key at all, which
                        # the frontend treats as verified (not hidden) rather
                        # than dropping that scan's entire inventory.
                        "verified": e.get("verified"),
                        "source": e.get("source", "crawled"),
                        "instances": e.get("instances", 1),
                        # URL-Inventory classification (Module 8B); older scans
                        # without these keys fall back to sensible defaults.
                        "url_class": e.get("url_class", "unknown"),
                        "api_type": e.get("api_type"),
                        "methods": methods,
                        # Distinct query key sets seen on this endpoint —
                        # ["q", "category,sort"] means the path was seen with
                        # both a `?q=` shape and a `?category=&sort=` shape.
                        # Downstream scanners treat each as a separate attack
                        # surface; dashboard can show them for humans.
                        "query_variants": e.get("query_variants", []),
                        "url_shape": e.get("url_shape", "plain"),
                        "sensitivity": e.get("sensitivity", "normal"),
                        "auth_state": e.get("auth_state", "unknown"),
                        "content_type": e.get("content_type", ""),
                        "cloud_provider": e.get("cloud_provider"),
                        "cloud_bucket": e.get("cloud_bucket"),
                        "attributed_to": e.get("attributed_to"),
                        # AI / MCP surface tag (Module 8D, orthogonal to
                        # url_class). None/absent on non-AI and older scans.
                        "ai_surface": e.get("ai_surface"),
                        "ai_flavor": e.get("ai_flavor"),
                        "ai_confidence": e.get("ai_confidence"),
                        "ai_tool_count": e.get("ai_tool_count"),
                        "ai_server_info": e.get("ai_server_info"),
                        "input_function": e.get("input_function"),
                        "input_functions": e.get("input_functions", []),
                        "accepts_file": e.get("accepts_file", False),
                        "routed_to": e.get("routed_to", []),
                        # 403-bypass + WAF-block classification from the
                        # streaming access-control pipeline (Module 8B).
                        # blocked_by_waf=true is the "URL exists but response
                        # is a WAF challenge" signal — nuclei drops these from
                        # its feed, but URL Inventory keeps them visible.
                        "blocked_by_waf": e.get("blocked_by_waf", False),
                        "waf_signatures": e.get("waf_signatures", []),
                        "provenance": e.get("provenance", ""),
                    })
            if rows:
                return rows
        except Exception as exc:
            logger.error("Failed to read consolidated endpoints %s: %s", merged, exc)

    # Fallback: raw dirsearch hits only.
    dirsearch_dir = os.path.join(base, 'dirsearch')
    urls = []
    for filename, status_code in (('200response.txt', 200),
                                  ('forbidden_response.txt', 403),
                                  ('500response.txt', 500)):
        file_path = os.path.join(dirsearch_dir, filename)
        if os.path.exists(file_path):
            try:
                with open(file_path, 'r', errors='ignore') as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            urls.append({"url": line, "status": status_code,
                                         "source": "dirsearch", "instances": 1})
            except Exception as exc:
                logger.error("Failed to read dirsearch file %s: %s", file_path, exc)
    return urls


@app.route('/api/internet-intel-assets')
def api_internet_intel_assets():
    """Full per-IP consolidated asset inventory from intel/internet_intel.py
    (Module 23) — intel_assets.jsonl. The Overview tab already shows a
    curated top-N slice via intel_summary.json's critical_assets/geo_assets;
    this exposes the complete list (every consolidated origin IP, not just
    the top ones) for scans with more assets than that top-N view covers."""
    scan_id = resolve_target(request.args.get('target'))
    logger.info("API request: /api/internet-intel-assets target=%s", scan_id)
    if not scan_id:
        return jsonify({'assets': [], 'total': 0})

    f = os.path.join(BASE_SCAN_DIR, scan_id, '23_internet_intel/intel_assets.jsonl')
    assets = []
    if os.path.exists(f):
        try:
            with open(f, 'r', errors='ignore') as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        assets.append(json.loads(line))
                    except Exception:
                        continue
        except Exception as exc:
            logger.error("Failed to read internet intel assets %s: %s", f, exc)

    return jsonify({'assets': assets, 'total': len(assets)})


@app.route('/api/page-classifications')
def api_page_classifications():
    """Page-type breakdown from api_security/api_deep_discovery.py's
    classifications.json (login/admin_panel/search/file_download/... pages
    with their URLs) — written every scan, never surfaced anywhere before.
    Read-only, self-contained (mirrors /api/techstack's pattern)."""
    scan_id = resolve_target(request.args.get('target'))
    logger.info("API request: /api/page-classifications target=%s", scan_id)
    if not scan_id:
        return jsonify({'classifications': {}, 'total_pages': 0})

    f = os.path.join(BASE_SCAN_DIR, scan_id,
                     '20_api_deep_discovery/classifications.json')
    data = {}
    if os.path.exists(f):
        try:
            with open(f, 'r', errors='ignore') as fh:
                data = json.load(fh) or {}
        except Exception as exc:
            logger.error("Failed to read page classifications %s: %s", f, exc)

    # Surface the security-relevant categories first; 'generic'/'api_endpoint'
    # are recon noise here (api_endpoint URLs already have their own tab).
    priority = ['admin_panel', 'login', 'registration', 'password_reset',
                'file_download', 'profile_update', 'contact_form',
                'filter_analytics']
    ordered = {k: data[k] for k in priority if k in data}
    ordered.update({k: v for k, v in data.items() if k not in ordered})

    return jsonify({
        'classifications': ordered,
        'total_pages': sum(v.get('count', 0) for v in data.values()) if data else 0,
    })


@app.route('/api/dirsearch')
def api_dirsearch():
    """Returns dirsearch results (200, 403, 500)."""
    scan_id = resolve_target(request.args.get('target'))
    logger.info("API request: /api/dirsearch target=%s", scan_id)
    return jsonify(_load_dirsearch(scan_id))


@app.route('/api/dns')
def api_dns():
    """Full DNS discovery data: zone records, NS, SOA audit, cloud storage targets."""
    scan_id = resolve_target(request.args.get('target'))
    logger.info("API request: /api/dns target=%s", scan_id)
    scan_dir = os.path.join(BASE_SCAN_DIR, scan_id) if scan_id else None
    dns_dir = os.path.join(scan_dir, '03b_dns_discovery') if scan_dir else None

    result = {
        'zone': [], 'nameservers': {}, 'soa_audit': {},
        'cloud_storage': {}, 'records': {}, 's3_detections': {},
        'record_stats': {}, 'total_records': 0, 'total_hosts': 0,
        'subdomain_takeover': [], 'dns_security': [], 'dns_security_summary': {},
    }

    if not dns_dir or not os.path.isdir(dns_dir):
        return jsonify(result)

    def load_json(fname):
        fp = os.path.join(dns_dir, fname)
        if os.path.exists(fp):
            try:
                with open(fp) as f:
                    return json.load(f)
            except Exception:
                pass
        return None

    zone = load_json('dns_zone.json')
    if zone:
        result['zone'] = zone
        result['total_records'] = len(zone)
        # Build per-type stats
        type_counts = {}
        hosts_seen = set()
        for entry in zone:
            t = entry.get('type', '')
            type_counts[t] = type_counts.get(t, 0) + 1
            hosts_seen.add(entry.get('name', ''))
        result['record_stats'] = type_counts
        result['total_hosts'] = len(hosts_seen)

    ns = load_json('authoritative_ns.json')
    if ns:
        result['nameservers'] = ns

    soa = load_json('soa_audit.json')
    if soa:
        result['soa_audit'] = soa

    cloud = load_json('cloud_storage_targets.json')
    if cloud:
        result['cloud_storage'] = cloud

    records = load_json('dns_all_records.json')
    if records:
        result['records'] = records

    # Subdomain takeover findings (Module 21 — subjack)
    takeover_dir = os.path.join(scan_dir, '21_subdomain_takeover') if scan_dir else None
    if takeover_dir:
        tk_file = os.path.join(takeover_dir, 'takeover_findings.jsonl')
        if os.path.exists(tk_file):
            try:
                with open(tk_file, 'r', errors='ignore') as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            result['subdomain_takeover'].append(json.loads(line))
                        except Exception:
                            continue
            except Exception as exc:
                logger.error("Failed to read takeover findings %s: %s", tk_file, exc)

    # DNS security findings (Module 3C — dns_security_audit.py)
    dns_sec_dir = os.path.join(scan_dir, '03c_dns_security') if scan_dir else None
    if dns_sec_dir:
        ds_file = os.path.join(dns_sec_dir, 'dns_security_findings.jsonl')
        if os.path.exists(ds_file):
            try:
                with open(ds_file, 'r', errors='ignore') as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            result['dns_security'].append(json.loads(line))
                        except Exception:
                            continue
            except Exception as exc:
                logger.error("Failed to read DNS security findings %s: %s", ds_file, exc)
        ds_sum = os.path.join(dns_sec_dir, 'dns_security_summary.json')
        if os.path.exists(ds_sum):
            try:
                with open(ds_sum) as f:
                    result['dns_security_summary'] = json.load(f)
            except Exception:
                pass

    # Also load S3 header detections from header_analysis
    ha_dir = os.path.join(scan_dir, '06_header_analysis') if scan_dir else None
    if ha_dir:
        s3_fp = os.path.join(ha_dir, 's3_detections.json')
        if os.path.exists(s3_fp):
            try:
                with open(s3_fp) as f:
                    result['s3_detections'] = json.load(f)
            except Exception:
                pass

    return jsonify(result)


@app.route('/api/modules')
def api_modules_legacy():
    """Legacy module summary endpoint."""
    scan_id = resolve_target(request.args.get('target'))
    logger.info("API request: /api/modules target=%s", scan_id)
    scan_dir = os.path.join(BASE_SCAN_DIR, scan_id) if scan_id else None
    if not scan_dir or not os.path.isdir(scan_dir):
        return jsonify({})

    # Ordered to match the pipeline's ACTUAL execution sequence (easm-pipeline.sh
    # module_order), not the directory numbers — so the GUI reflects the real
    # flow: full port scan + service fingerprint run BEFORE http discovery, and
    # the advanced-attacks stage runs after nuclei. Dict insertion order is the
    # display order (Flask + the frontend both preserve it).
    module_names = {
        '01_asset_discovery': 'Asset Discovery',
        '02_subdomain_enum': 'Subdomain Enumeration',
        '03_dns_resolution': 'DNS Resolution',
        '03b_dns_discovery': 'DNS Discovery',
        '21_subdomain_takeover': 'Subdomain Takeover',
        '03c_dns_security': 'DNS Security Audit',
        '14_port_scan': 'Port Scanning',
        '07_service_fingerprint': 'Service Fingerprinting',
        '04_http_discovery': 'HTTP Discovery',
        '05_waf_detection': 'WAF Detection',
        '08_directory_discovery': 'Directory Discovery',
        '09_crawling': 'Web Crawling',
        '06_header_analysis': 'Header Analysis',
        '08c_hrs_detect': 'HRS Detection',
        '20_api_deep_discovery': 'API Deep Discovery',
        '11_param_fuzzing': 'Parameter Fuzzing',
        '16_api_security': 'API Security Testing',
        '13_xss_testing': 'XSS Testing',
        '15_sqli_testing': 'SQLi Testing',
        '20.1_api_sqli_testing': 'API SQLi Testing',
        '10_secret_scanning': 'Secret Scanning',
        '12_nuclei_scanning': 'Vulnerability Scanning',
        '24_advanced_attacks': 'Offensive Verification (JWT/GraphQL/SSTI/CRLF/SSRF/Race/Exposure/…)',
        '24_api_attack': 'API Attack (logic leads + authz invariants)',
        '22_shodan_correlation': 'Shodan Correlation',
        '17_cloud_exposure': 'Cloud Exposure',
        '18_osint_intel': 'OSINT Intelligence',
        '19_extended_checks': 'Extended Verification (legacy)',
        '23_internet_intel': 'Internet Intelligence',
        '08d_attack_synth': 'Attack Synthesis',
        '25_attack_paths': 'CAPEC Attack Paths',
        '26_response_intel': 'Response Intelligence',
        '27_adaptive_loop': 'Adaptive Loop',
    }

    modules = {}
    for module_dir, module_name in module_names.items():
        module_path = os.path.join(scan_dir, module_dir)
        results_file = None
        data_count = 0
        if os.path.isdir(module_path):
            files = [f for f in glob.glob(os.path.join(module_path, '*')) if os.path.isfile(f)]
            data_count = len(files)
            matches = sorted(glob.glob(os.path.join(module_path, '*_results.json')), key=os.path.getmtime)
            if matches:
                results_file = matches[-1]

        # "Completed" = the module produced output. Newer stages write
        # *_findings.jsonl / *_summary.json rather than *_results.json, so key
        # completion off any output file, not just the legacy _results.json.
        modules[module_dir] = {
            'name': module_name,
            'completed': bool(results_file) or data_count > 0,
            'data_count': data_count,
            'data': load_json_file(results_file) if results_file else {}
        }
    return jsonify(modules)


@app.route('/api/vulnerabilities')
def api_vulnerabilities_legacy():
    """Legacy vulnerability endpoint (heavy evidence fields stripped)."""
    scan_id = resolve_target(request.args.get('target'))
    logger.info("API request: /api/vulnerabilities target=%s", scan_id)
    data = get_cached_scan_data(scan_id) if scan_id else None
    if not data:
        return jsonify([])
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    vulns = sorted(data.get('vulnerabilities', []),
                   key=lambda x: severity_order.get(x.get('severity', 'info'), 4))
    light = []
    for idx, v in enumerate(vulns):
        rec = {k: val for k, val in v.items() if k not in _VULN_HEAVY_FIELDS}
        rec['_idx'] = idx
        light.append(rec)
    return jsonify(light)


@app.route('/api/vulnerability/<int:idx>')
def api_vulnerability_detail_legacy(idx):
    """Return full detail for one vulnerability (legacy proxy)."""
    scan_id = resolve_target(request.args.get('target'))
    if not scan_id:
        return jsonify({'error': 'No target specified.'}), 400
    data = get_cached_scan_data(scan_id)
    if not data:
        return jsonify({'error': 'Scan not found.'}), 404
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    vulns = sorted(data.get('vulnerabilities', []),
                   key=lambda x: severity_order.get(x.get('severity', 'info'), 4))
    if idx < 0 or idx >= len(vulns):
        return jsonify({'error': 'Index out of range.'}), 404
    return jsonify(vulns[idx])


@app.route('/api/risk')
def api_risk_legacy():
    """Legacy risk endpoint."""
    scan_id = resolve_target(request.args.get('target'))
    logger.info("API request: /api/risk target=%s", scan_id)
    if not scan_id:
        return jsonify({})
    data = get_cached_scan_data(scan_id)
    if not data:
        return jsonify({})
    hosts = data.get('hosts', {})
    org_score, grade = compute_org_risk(hosts)
    bands = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    for hd in hosts.values():
        band = hd.get('risk_band', 'low')
        bands[band] = bands.get(band, 0) + 1
    return jsonify({'org_score': org_score, 'grade': grade, 'band_distribution': bands})


@app.route('/api/executive')
def api_executive_legacy():
    """Legacy executive summary endpoint."""
    scan_id = resolve_target(request.args.get('target'))
    logger.info("API request: /api/executive target=%s", scan_id)
    if not scan_id:
        return jsonify({})
    data = get_cached_scan_data(scan_id)
    if not data:
        return jsonify({})
    # Reuse the structured endpoint
    return api_executive(scan_id)


@app.route('/api/cves')
def api_cves_legacy():
    """Legacy CVE endpoint."""
    scan_id = resolve_target(request.args.get('target'))
    logger.info("API request: /api/cves target=%s", scan_id)
    if not scan_id:
        return jsonify([])
    return api_cves(scan_id)


@app.route('/api/manifest')
def api_manifest_legacy():
    """Legacy manifest endpoint."""
    scan_id = resolve_target(request.args.get('target'))
    logger.info("API request: /api/manifest target=%s", scan_id)
    data = get_cached_scan_data(scan_id) if scan_id else None
    return jsonify(data.get('manifest', {}) if data else {})


@app.route('/api/report')
def api_report_legacy():
    """Legacy report endpoint."""
    scan_id = resolve_target(request.args.get('target'))
    logger.info("API request: /api/report target=%s", scan_id)
    if not scan_id:
        return jsonify({})
    report_file = os.path.join(BASE_SCAN_DIR, scan_id, 'reports', 'report.json')
    return jsonify(load_json_file(report_file))


def _report_model(scan_id):
    """Assemble the attack-surface report model for a scan, or None if unknown."""
    data = get_cached_scan_data(scan_id)
    if not data:
        return None
    # The scan-scoped API views are plain functions returning a JSON Response,
    # so the report reuses their aggregation rather than duplicating it.
    return arise_report.build_report(
        scan_id,
        data,
        api_osint(scan_id).get_json() or {},
        api_cloud(scan_id).get_json() or {},
        api_executive(scan_id).get_json() or {},
        api_risk(scan_id).get_json() or {},
        api_internet_intel(scan_id).get_json() or {},
    )


@app.route('/report')
@app.route('/report/<scan_id>')
@login_required
def view_report(scan_id=None):
    """Adversary-perspective attack surface report (print to PDF from the browser)."""
    scan_id = resolve_target(scan_id or request.args.get('target'))
    logger.info("Report request: target=%s", scan_id)
    if not scan_id:
        return render_template('report.html', r=None, error='No scan selected.'), 404
    model = _report_model(scan_id)
    if not model:
        return render_template('report.html', r=None, error=f'Scan {scan_id} not found.'), 404
    return render_template('report.html', r=model)


@app.route('/api/report/model')
@login_required
def api_report_model():
    """The report model as JSON — same data the HTML report renders."""
    scan_id = resolve_target(request.args.get('target'))
    if not scan_id:
        return jsonify({'error': 'No scan selected.'}), 404
    model = _report_model(scan_id)
    if not model:
        return jsonify({'error': f'Scan {scan_id} not found.'}), 404
    return jsonify(model)


@app.route('/api/report/json-summary')
@login_required
def api_report_json_summary():
    """Agent-friendly single-object JSON summary with path_template on each finding."""
    scan_id = resolve_target(request.args.get('target'))
    if not scan_id:
        return jsonify({'error': 'No scan selected.'}), 404
    model = _report_model(scan_id)
    if not model:
        return jsonify({'error': f'Scan {scan_id} not found.'}), 404
    return jsonify(arise_report.build_json_summary(model))


def _host_of_url(url):
    """Best-effort extraction of a hostname from a URL or host:port string."""
    if not url:
        return ''
    try:
        if '//' in url:
            url = url.split('//', 1)[1]
        return url.split('/')[0].split(':')[0]
    except Exception:
        return ''


def build_host_detail(scan_id, host):
    """Aggregate every finding for a single host into a grouped tree.

    Returns the host's metadata plus a list of finding categories, each holding
    the individual findings. This powers the click-through vulnerability report.
    """
    data = get_cached_scan_data(scan_id)
    if not data or not host:
        return {}

    hosts = data.get('hosts', {})
    host_data = hosts.get(host)
    if host_data is None:
        # Fall back to a case-insensitive lookup
        for h, hd in hosts.items():
            if h.lower() == host.lower():
                host, host_data = h, hd
                break
    if host_data is None:
        return {'host': host, 'found': False, 'categories': []}

    # Collect all findings that belong to this host (by host field or URL host)
    host_vulns = []
    for v in data.get('vulnerabilities', []):
        if v.get('host') == host or _host_of_url(v.get('url', '')) == host:
            host_vulns.append(v)

    # Group vulnerabilities by their source into report categories
    source_labels = {
        'Nuclei': 'Vulnerability Findings',
        'Secret Scan': 'Exposed Secrets & Credentials',
        'SQLi Testing': 'SQL Injection',
        'XSS Testing': 'Cross-Site Scripting (XSS)',
        'Param Fuzzing': 'File Inclusion / Path Traversal',
    }
    grouped = {}
    for v in host_vulns:
        src = v.get('source', 'Other')
        grouped.setdefault(src, []).append(v)

    severity_rank = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}
    categories = []
    for src, items in grouped.items():
        items.sort(key=lambda x: severity_rank.get(x.get('severity', 'info'), 0), reverse=True)
        top_sev = max((i.get('severity', 'info') for i in items),
                      key=lambda s: severity_rank.get(s, 0), default='info')
        categories.append({
            'key': src,
            'name': source_labels.get(src, src),
            'type': 'vulnerability',
            'count': len(items),
            'max_severity': top_sev,
            'findings': [{
                'title': i.get('template', 'Finding'),
                'severity': i.get('severity', 'info'),
                'url': i.get('url', ''),
                'impact': i.get('impact', ''),
                'remediation': i.get('remediation', ''),
                'cve_id': i.get('cve_id'),
                'source': i.get('source', ''),
            } for i in items]
        })

    # Exposed ports as a category
    ports = sorted(set(int(p) for p in host_data.get('ports_open', [])))
    if ports:
        sensitive = [p for p in ports if p in SENSITIVE_PORTS]
        port_findings = []
        for p in ports:
            is_sensitive = p in SENSITIVE_PORTS
            port_findings.append({
                'title': 'Port ' + str(p) + ' (' + PORT_MAPPINGS.get(p, 'Unknown') + ')',
                'severity': 'high' if is_sensitive else 'info',
                'url': host + ':' + str(p),
                'impact': ('Sensitive service exposed to the internet' if is_sensitive
                           else 'Open port reachable from the internet'),
                'remediation': ('Restrict access via firewall/VPN' if is_sensitive else ''),
                'source': 'Port Scan',
            })
        categories.append({
            'key': 'ports',
            'name': 'Exposed Ports',
            'type': 'infrastructure',
            'count': len(ports),
            'max_severity': 'high' if sensitive else 'info',
            'findings': port_findings,
        })

    # Security header posture as a category
    missing_headers = host_data.get('missing_headers', [])
    if host_data.get('http_status') and missing_headers:
        categories.append({
            'key': 'headers',
            'name': 'Missing Security Headers',
            'type': 'posture',
            'count': len(missing_headers),
            'max_severity': 'medium' if len(missing_headers) >= 4 else 'low',
            'findings': [{
                'title': h,
                'severity': 'low',
                'url': '',
                'impact': 'Security header not set',
                'remediation': 'Add the ' + h + ' response header',
                'source': 'Header Analysis',
            } for h in missing_headers]
        })

    # Discovered directories for this host (from dirsearch output)
    dir_hits = []
    for entry in _load_dirsearch(scan_id):
        if _host_of_url(entry.get('url', '')) == host:
            dir_hits.append(entry)
    if dir_hits:
        dir_hits.sort(key=lambda e: (e.get('status') != 200, e.get('url', '')))
        categories.append({
            'key': 'directories',
            'name': 'Discovered Directories & Files',
            'type': 'discovery',
            'count': len(dir_hits),
            'max_severity': 'medium' if any(e.get('status') == 200 for e in dir_hits) else 'low',
            'findings': [{
                'title': ('[' + str(e.get('status')) + '] ') + e.get('url', ''),
                'severity': 'medium' if e.get('status') == 200 else 'low',
                'url': e.get('url', ''),
                'impact': 'Reachable path (HTTP ' + str(e.get('status')) + ')',
                'remediation': ('Restrict or remove exposed path' if e.get('status') == 200 else ''),
                'source': 'Directory Discovery',
            } for e in dir_hits]
        })

    # Cookie issues
    cookie_issues = host_data.get('cookie_issues', [])
    if cookie_issues:
        categories.append({
            'key': 'cookies',
            'name': 'Cookie Security Issues',
            'type': 'posture',
            'count': len(cookie_issues),
            'max_severity': 'low',
            'findings': [{
                'title': str(c),
                'severity': 'low',
                'url': '',
                'impact': 'Cookie missing a security attribute',
                'remediation': 'Set Secure, HttpOnly and SameSite attributes',
                'source': 'Header Analysis',
            } for c in cookie_issues]
        })

    categories.sort(key=lambda c: severity_rank.get(c.get('max_severity', 'info'), 0), reverse=True)

    severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    for cat in categories:
        for f in cat['findings']:
            s = f.get('severity', 'info')
            severity_counts[s] = severity_counts.get(s, 0) + 1

    return {
        'host': host,
        'found': True,
        'ip': host_data.get('ip', ''),
        'url': host_data.get('url', ''),
        'resolved': host_data.get('resolved', False),
        'http_status': host_data.get('http_status', ''),
        'cdn': host_data.get('cdn', False),
        'waf_vendor': host_data.get('waf_vendor', 'none'),
        'is_api': host_data.get('is_api', False),
        'api_signals': host_data.get('api_signals', []),
        'is_s3': host_data.get('is_s3', False),
        'tech_tag': host_data.get('tech_tag', ''),
        'server_banner': host_data.get('server_banner', ''),
        'security_header_score': host_data.get('security_header_score', 0),
        'ssl_dangling': host_data.get('ssl_dangling', False),
        'ssl_cert_cn': host_data.get('ssl_cert_cn', ''),
        'risk_score': host_data.get('risk_score', 0),
        'risk_band': host_data.get('risk_band', 'low'),
        'ports': ports,
        'total_findings': sum(severity_counts.values()),
        'severity_counts': severity_counts,
        'categories': categories,
    }


@app.route('/api/scan/<scan_id>/host/<path:host>')
def api_host_detail(scan_id, host):
    """Full drill-down report tree for a single host within a scan."""
    detail = build_host_detail(scan_id, host)
    if not detail:
        return jsonify({}), 404
    return jsonify(detail)


@app.route('/api/host')
def api_host_detail_legacy():
    """Host drill-down keyed by ?target=&host=."""
    scan_id = resolve_target(request.args.get('target'))
    host = request.args.get('host', '')
    logger.info("API request: /api/host target=%s host=%s", scan_id, host)
    if not scan_id or not host:
        return jsonify({})
    return jsonify(build_host_detail(scan_id, host))


# ===========================================================================
# AI SECURITY ANALYST
# ===========================================================================

def _gather_ai_context(scan_id):
    """Assemble a compact, structured snapshot of a scan for the AI analyst.

    Pulls from the same loaders the dashboard tabs use so the model sees exactly
    what the operator sees — risk score, exposure, prioritized findings across
    vulns / cloud / API / CVEs — capped so the prompt stays token-bounded.
    """
    data = get_cached_scan_data(scan_id)
    if not data:
        return None

    hosts = data.get('hosts', {})
    vulns = data.get('vulnerabilities', [])
    org_score, grade = compute_org_risk(hosts)
    target = data.get('pipeline_info', {}).get('target', scan_id)

    sev_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    for v in vulns:
        s = v.get('severity', 'info')
        sev_counts[s] = sev_counts.get(s, 0) + 1

    def _sev_rank(v):
        return {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}.get(v.get('severity', 'info'), 0)

    def _slim(v):
        return {
            'title': v.get('template') or v.get('name') or v.get('issue_class') or 'finding',
            'severity': v.get('severity', 'info'),
            'source': v.get('source', ''),
            'host': v.get('host', ''),
            'url': v.get('url', ''),
            'impact': (v.get('impact') or '')[:240],
        }

    # App/infra vulns (exclude cloud + API, which are summarized separately).
    app_vulns = [v for v in vulns if v.get('source') not in ('Cloud Exposure', 'API Security')]
    app_vulns.sort(key=lambda v: (_sev_rank(v), v.get('weighted_score', 0)), reverse=True)
    top_vulns = [_slim(v) for v in app_vulns[:25]]

    # Cloud findings (whitelist-scoped, same as the Cloud tab).
    cloud = [v for v in vulns
             if v.get('source') == 'Cloud Exposure'
             and v.get('cloud_category') in CLOUD_ALL_CATEGORIES]
    cloud.sort(key=lambda v: v.get('weighted_score', 0), reverse=True)
    cloud_findings = [{
        'category': v.get('cloud_category', ''),
        'title': v.get('template', ''),
        'severity': v.get('severity', 'info'),
        'host': v.get('host', ''),
        'impact': (v.get('impact') or '')[:240],
    } for v in cloud[:20]]

    # API security findings.
    api_findings = _load_api_security_findings(scan_id)
    api_slim = [{
        'endpoint': f.get('endpoint') or f"{f.get('method', '')} {f.get('path', '')}".strip(),
        'issue': f.get('issue_class', ''),
        'severity': f.get('severity', 'info'),
        'tools': f.get('tools') or ([f.get('tool')] if f.get('tool') else []),
    } for f in sorted(api_findings, key=lambda x: _sev_rank(x), reverse=True)[:20]]

    # CVEs harvested from nuclei findings.
    cve_re = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)
    cves = {}
    for v in vulns:
        blob = f"{v.get('template', '')} {v.get('name', '')} {v.get('cve', '')}"
        for m in cve_re.findall(blob):
            cid = m.upper()
            cves.setdefault(cid, {'cve': cid, 'severity': v.get('severity', 'info'), 'host': v.get('host', '')})

    # Sensitive exposed services.
    sensitive = []
    for host, hd in hosts.items():
        for p in set(hd.get('ports_open', [])) & SENSITIVE_PORTS:
            sensitive.append({'host': host, 'port': p, 'service': PORT_MAPPINGS.get(p, 'Unknown')})

    secrets_count = sum(1 for v in vulns if v.get('source') == 'Secret Scan')
    http_hosts = sum(1 for h in hosts.values() if h.get('http_status'))
    waf_uncovered = sum(1 for h in hosts.values()
                        if h.get('http_status') and h.get('waf_vendor') in ('none', '', None))

    # evidence/target_memory.py (R8) — durable, cross-scan learned facts for
    # this exact target (identity-bearing params, known-static URLs, recurring
    # non-bug error states). Was harvested every scan but never recalled
    # anywhere: the autonomous engine re-discovered (and sometimes
    # re-mis-fired on) the same things scan after scan. Only reasonably
    # confident, repeatedly-reinforced facts are worth spending prompt budget
    # on; capped short since this is a hint, not the main context.
    try:
        priors = TargetMemory(target).recall(min_confidence=0.5)
        target_memory_priors = [
            {'key': p['key'], 'fact': p['fact'], 'confidence': p['confidence']}
            for p in priors[:15]
        ]
    except Exception:
        target_memory_priors = []

    return {
        'target': target,
        'scan_id': scan_id,
        'risk_score': org_score,
        'grade': grade,
        'assets': {
            'total_hosts': len(hosts),
            'internet_facing_http': http_hosts,
            'waf_uncovered': waf_uncovered,
            'cdn_fronted': sum(1 for h in hosts.values() if h.get('cdn')),
        },
        'severity_counts': sev_counts,
        'secrets_found': secrets_count,
        'sensitive_services': sensitive[:20],
        'top_vulnerabilities': top_vulns,
        'cloud_findings': cloud_findings,
        'api_findings': api_slim,
        'cves': list(cves.values())[:30],
        'target_memory_priors': target_memory_priors,
    }


# Base analyst persona shared by every preset. The concrete output shape comes
# from the per-preset instruction appended to the user message.
AI_SYSTEM_PROMPT = (
    "You are ARISE's security analyst. You receive a JSON snapshot of an External "
    "Attack Surface Monitoring scan (risk score, exposed assets, and prioritized "
    "findings across web vulnerabilities, cloud misconfigurations, API security, and "
    "CVEs) and write clear, decision-ready output in GitHub-flavored Markdown. "
    "Ground every claim in the provided data — never invent findings, hosts, or CVEs. "
    "If the data is thin, say so plainly. Be direct and specific; avoid filler and "
    "vendor-speak."
)

# System prompt for the folder-review mode (analyzing raw scan output files).
AI_FOLDER_SYSTEM_PROMPT = (
    "You are ARISE's security analyst reviewing raw scan output files. Read the files "
    "provided and produce a clear, decision-ready security review in GitHub-flavored "
    "Markdown. Ground every claim in the file contents and reference the specific file "
    "a finding came from. Never invent results. Call out secrets, misconfigurations, "
    "exposed services, and high-signal findings; note what is inconclusive."
)

# Default analysis commands. 'executive' is the default; the operator can pick any,
# but a custom prompt or a folder target overrides the preset entirely.
AI_PRESETS = {
    'executive': {
        'label': 'Executive Briefing',
        'instruction': (
            "Produce the security briefing with these sections: **Executive Summary** "
            "(2-3 sentences, readable by a non-technical CXO), **Top Risks** (ranked 3-6, "
            "each with concrete business impact and the affected asset), **Recommended "
            "Actions** (prioritized P0/P1/P2), and **Positive Signals** (what's being done "
            "well). Keep the whole briefing under ~450 words."
        ),
    },
    'remediation': {
        'label': 'Remediation Plan',
        'instruction': (
            "Produce a prioritized remediation plan. For each issue give: title, severity, "
            "affected asset(s), concrete fix steps, a suggested owning team (Platform / "
            "AppSec / Cloud / Network), and rough effort (S/M/L). Order by risk reduced per "
            "unit of effort. End with a **Do this week** shortlist of 3-5 items."
        ),
    },
    'attack_paths': {
        'label': 'Attack Path Analysis',
        'instruction': (
            "Think like an attacker. Identify the 2-4 most plausible attack chains that link "
            "these findings into a real breach (initial access -> pivot -> impact). For each "
            "chain: the steps, the specific hosts/findings involved, and the single control "
            "that would break the chain. Only use findings present in the data."
        ),
    },
    'compliance': {
        'label': 'Compliance & Hardening Gaps',
        'instruction': (
            "Map the findings to common control expectations (OWASP Web/API Top 10, CIS-style "
            "cloud hardening, TLS and email-auth hygiene). List gaps as: control area, what's "
            "failing, the evidence from the data, and the remediation. Note where the data is "
            "insufficient to judge a control."
        ),
    },
    'triage': {
        'label': 'Quick Triage',
        'instruction': (
            "Fast triage in under 200 words: the single biggest risk right now, the top 3 "
            "things to verify or fix today, and one thing that looks fine. Bullet points, no "
            "preamble."
        ),
    },
    'mitre': {
        'label': 'MITRE ATT&CK Mapping',
        'instruction': (
            "Map the scan findings to the MITRE ATT&CK framework (Enterprise). For each "
            "finding or cluster of related findings, identify:\n"
            "- **Tactic** (e.g. Initial Access, Reconnaissance, Credential Access)\n"
            "- **Technique** and **Sub-technique ID** (e.g. T1190 Exploit Public-Facing Application)\n"
            "- **Affected host(s)** and the specific finding that maps\n"
            "- **Detection opportunity** — what the defender should log or alert on\n\n"
            "Present as a table: Tactic | Technique (ID) | Finding | Host | Detection Opportunity. "
            "Only map findings actually present in the data — never invent. End with a paragraph on "
            "which kill-chain stages have the most coverage gaps."
        ),
    },
    'playbook': {
        'label': 'Remediation Playbook',
        'instruction': (
            "Generate a step-by-step remediation playbook organized by severity tier. For each finding:\n\n"
            "### [P0/P1/P2] Finding Title\n"
            "- **Affected:** host(s) and URL\n"
            "- **Risk:** plain-language explanation of what an attacker could do\n"
            "- **Fix steps:** numbered, copy-pasteable commands or config changes where possible "
            "(e.g. exact nginx/Apache directives, AWS CLI commands, CSP headers)\n"
            "- **Verify:** how to confirm the fix worked (curl command, expected output)\n"
            "- **Owner:** suggested team (Platform / AppSec / Cloud / Network / DevOps)\n"
            "- **Effort:** S (< 1 hour) / M (1 day) / L (multi-day)\n\n"
            "End with a **This week** checklist of the 3-5 highest-impact fixes. "
            "For any CVE found, include a 1-sentence plain-language summary of what the vulnerability "
            "does and its CVSS context."
        ),
    },
    'cve_intel': {
        'label': 'CVE Intelligence',
        'instruction': (
            "For every CVE found in this scan, produce an intelligence brief:\n"
            "- **CVE ID** and severity\n"
            "- **Plain-language summary** — what the vulnerability is, in one sentence a non-security "
            "person can understand\n"
            "- **Affected host(s)** from this scan\n"
            "- **Exploitability** — is there a public PoC? Is it in CISA KEV?\n"
            "- **Remediation** — patch version, workaround, or compensating control\n\n"
            "If no CVEs are found, state that clearly and instead list the top 3 non-CVE findings "
            "that pose the highest risk. End with a prioritized patch list."
        ),
    },
}

# Supported AI providers. Claude uses the Anthropic SDK; the others are called over
# their HTTPS APIs (OpenAI-compatible chat for OpenAI/Hugging Face, generateContent
# for Gemini). Keys resolve from the request first, then any of the listed env vars.
AI_PROVIDERS = {
    'claude': {
        'label': 'Claude (Anthropic)',
        'default_model': AI_MODEL,
        'env_names': ['ANTHROPIC_API_KEY', 'ANTHROPIC_AUTH_TOKEN'],
    },
    'openai': {
        'label': 'OpenAI',
        'default_model': os.environ.get('OPENAI_MODEL', 'gpt-4o'),
        'env_names': ['OPENAI_API_KEY'],
    },
    'gemini': {
        'label': 'Google Gemini',
        'default_model': os.environ.get('GEMINI_MODEL', 'gemini-2.5-flash'),
        'env_names': ['GEMINI_API_KEY', 'GOOGLE_API_KEY'],
    },
    'huggingface': {
        'label': 'Hugging Face',
        'default_model': os.environ.get('HF_MODEL', 'meta-llama/Llama-3.1-8B-Instruct'),
        'env_names': ['HF_API_TOKEN', 'HUGGINGFACE_API_KEY', 'HUGGINGFACEHUB_API_TOKEN'],
    },
    'openrouter': {
        'label': 'OpenRouter',
        'default_model': os.environ.get('OPENROUTER_MODEL', 'openai/gpt-4o-mini'),
        'env_names': ['OPENROUTER_API_KEY'],
    },
    'groq': {
        'label': 'Groq',
        'default_model': os.environ.get('GROQ_MODEL', 'llama-3.3-70b-versatile'),
        'env_names': ['GROQ_API_KEY'],
    },
}


# Map an AI provider to its canonical vault secret name.
_PROVIDER_SECRET = {
    'claude': 'ANTHROPIC_API_KEY',
    'openai': 'OPENAI_API_KEY',
    'gemini': 'GEMINI_API_KEY',
    'huggingface': 'HF_API_TOKEN',
    'openrouter': 'OPENROUTER_API_KEY',
    'groq': 'GROQ_API_KEY',
}


def _provider_key(provider, supplied=None):
    """Resolve an API key: request-supplied first, then the encrypted vault, then env."""
    if supplied and supplied.strip():
        return supplied.strip()
    secret_name = _PROVIDER_SECRET.get(provider)
    if secret_name:
        val = arise_secure.resolve_secret(secret_name)  # vault, then env fallbacks
        if val:
            return val
    for env in AI_PROVIDERS.get(provider, {}).get('env_names', []):
        val = os.environ.get(env)
        if val:
            return val
    return ''


def _slack_webhook():
    """Slack webhook from the encrypted vault, falling back to the .env value."""
    return arise_secure.resolve_secret('SLACK_WEBHOOK_URL') or SLACK_WEBHOOK_URL


def _gather_folder_context(folder, scan_id=None):
    """Read text files from a scan output folder for the folder-review mode.

    Sandboxed to the scans directory (path traversal is rejected). Relative paths
    resolve against the current scan first, then the scans root.
    """
    base = os.path.realpath(BASE_SCAN_DIR)
    candidates = []
    if scan_id:
        candidates.append(os.path.join(BASE_SCAN_DIR, scan_id, folder))
    candidates.append(os.path.join(BASE_SCAN_DIR, folder))
    candidates.append(folder)

    target = None
    for cand in candidates:
        rp = os.path.realpath(cand)
        if os.path.isdir(rp) and (rp == base or rp.startswith(base + os.sep)):
            target = rp
            break
    if not target:
        return None, ("Folder not found or outside the scans directory. Use a path like "
                      "'<scan-id>/16_api_security' or a module folder within the current scan.")

    exts = {'.json', '.jsonl', '.txt', '.md', '.csv', '.log', '.yaml', '.yml'}
    PER_FILE, TOTAL_CAP, MAX_FILES = 20000, 200000, 40
    files, total = [], 0
    for root, _dirs, fnames in os.walk(target):
        for fn in sorted(fnames):
            if len(files) >= MAX_FILES or total >= TOTAL_CAP:
                break
            if os.path.splitext(fn)[1].lower() not in exts:
                continue
            fp = os.path.join(root, fn)
            try:
                with open(fp, errors='ignore') as fh:
                    content = fh.read(PER_FILE)
            except Exception:
                continue
            files.append({'path': os.path.relpath(fp, target), 'content': content})
            total += len(content)
    if not files:
        return None, "No readable text files (json/jsonl/txt/log/csv/yaml) found in that folder."
    return {
        'folder': os.path.relpath(target, base),
        'file_count': len(files),
        'files': files,
        'truncated': total >= TOTAL_CAP,
    }, None


def _call_claude(model, api_key, system, user):
    try:
        import anthropic
    except ImportError:
        return None, ("The 'anthropic' package is not installed. Run "
                      "`pip install anthropic` to use the Claude provider.")
    try:
        client = anthropic.Anthropic(api_key=api_key) if api_key else anthropic.Anthropic()
        # Server-side streaming guards against HTTP timeouts on longer generations.
        with client.messages.stream(
            model=model,
            max_tokens=4000,
            system=system,
            thinking={"type": "adaptive"},
            output_config={"effort": "medium"},
            messages=[{"role": "user", "content": user}],
        ) as stream:
            final = stream.get_final_message()
        if final.stop_reason == 'refusal':
            return None, "The model declined to analyze this content."
        text = "".join(b.text for b in final.content if getattr(b, 'type', None) == 'text').strip()
        return (text or "The model returned an empty response."), None
    except anthropic.AuthenticationError:
        return None, "Anthropic authentication failed. Set a valid ANTHROPIC_API_KEY in .env and restart."
    except anthropic.APIStatusError as exc:
        return None, f"Anthropic API error ({exc.status_code}): {getattr(exc, 'message', str(exc))}"
    except Exception as exc:  # noqa: BLE001
        msg = str(exc)
        if 'authentication method' in msg or 'api_key' in msg:
            return None, "No Anthropic credentials found. Set ANTHROPIC_API_KEY in .env and restart the dashboard."
        logger.error("Claude call failed: %s", exc)
        return None, f"Claude call failed: {exc}"


def _call_openai_chat(url, model, api_key, system, user, provider_label):
    """OpenAI-compatible chat completions (used for OpenAI and the Hugging Face router)."""
    if not api_key:
        return None, f"No API key for {provider_label}. Set its API key in .env and restart the dashboard."
    import requests as _requests
    try:
        resp = _requests.post(
            url,
            headers={'Authorization': f'Bearer {api_key}', 'Content-Type': 'application/json'},
            json={
                'model': model,
                'messages': [
                    {'role': 'system', 'content': system},
                    {'role': 'user', 'content': user},
                ],
                'max_tokens': 1800,
                'temperature': 0.3,
            },
            timeout=120,
        )
    except Exception as exc:  # noqa: BLE001
        return None, f"{provider_label} request failed: {exc}"
    if resp.status_code // 100 != 2:
        return None, f"{provider_label} API error ({resp.status_code}): {resp.text[:200]}"
    try:
        data = resp.json()
        text = (data['choices'][0]['message']['content'] or '').strip()
    except Exception:
        return None, f"{provider_label} returned an unexpected response."
    return (text or "The model returned an empty response."), None


def _call_gemini(model, api_key, system, user):
    if not api_key:
        return None, "No API key for Google Gemini. Set GEMINI_API_KEY in .env and restart the dashboard."
    import requests as _requests
    url = (f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
           f"?key={api_key}")
    try:
        resp = _requests.post(
            url,
            json={
                'system_instruction': {'parts': [{'text': system}]},
                'contents': [{'role': 'user', 'parts': [{'text': user}]}],
                'generationConfig': {'maxOutputTokens': 2048, 'temperature': 0.3},
            },
            timeout=120,
        )
    except Exception as exc:  # noqa: BLE001
        return None, f"Gemini request failed: {exc}"
    if resp.status_code // 100 != 2:
        return None, f"Gemini API error ({resp.status_code}): {resp.text[:200]}"
    try:
        data = resp.json()
        cands = data.get('candidates') or []
        if not cands:
            reason = (data.get('promptFeedback') or {}).get('blockReason', 'no candidates')
            return None, f"Gemini returned no content ({reason})."
        parts = cands[0].get('content', {}).get('parts', [])
        text = "".join(p.get('text', '') for p in parts).strip()
    except Exception:
        return None, "Gemini returned an unexpected response."
    return (text or "The model returned an empty response."), None


def _run_ai_provider(provider, model, api_key, system, user, purpose='analyst', scan_dir=None):
    """Dispatch a completion to the selected provider. Returns (markdown_text, error).

    Routes through the unified provider layer (core/ai_provider.py, Phase 0) so
    every dashboard AI call gets token/cost accounting, run logging, budgets,
    redaction and injection hardening. Falls back to the legacy direct callers
    only if that layer is unavailable."""
    try:
        from core import ai_provider
        return ai_provider.chat(system, user, provider=provider, model=model,
                                api_key=api_key, purpose=purpose, scan_dir=scan_dir)
    except Exception as exc:
        logger.error("ai_provider layer unavailable, using legacy path: %s", exc)
    if provider == 'claude':
        return _call_claude(model, api_key, system, user)
    if provider == 'openai':
        return _call_openai_chat('https://api.openai.com/v1/chat/completions',
                                 model, api_key, system, user, 'OpenAI')
    if provider == 'huggingface':
        return _call_openai_chat('https://router.huggingface.co/v1/chat/completions',
                                 model, api_key, system, user, 'Hugging Face')
    if provider == 'gemini':
        return _call_gemini(model, api_key, system, user)
    return None, f"Unknown provider: {provider}"


def _markdown_to_slack(md):
    """Convert the briefing's GitHub Markdown into Slack mrkdwn.

    Slack uses *bold* / _italic_ and has no heading syntax, so headings become
    bold lines and `**bold**` collapses to `*bold*`.
    """
    lines = []
    for raw in md.splitlines():
        line = raw.rstrip()
        m = re.match(r'^(#{1,6})\s+(.*)$', line)
        if m:
            lines.append(f"*{m.group(2).strip()}*")
            continue
        # **bold** -> *bold*
        line = re.sub(r'\*\*(.+?)\*\*', r'*\1*', line)
        # markdown bullets -> slack bullets
        line = re.sub(r'^\s*[-*]\s+', '• ', line)
        lines.append(line)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Global settings (provider / model / auto-Slack), persisted to a JSON file.
# ---------------------------------------------------------------------------
def _default_ready_provider():
    for pid in AI_PROVIDERS:
        if _provider_key(pid, None):
            return pid
    return 'claude'


def load_settings():
    """Effective settings: file overrides .env defaults override built-ins."""
    data = {}
    try:
        with open(SETTINGS_FILE) as fh:
            data = json.load(fh) or {}
    except Exception:
        data = {}
    provider = (data.get('provider') or AI_PROVIDER_ENV or _default_ready_provider())
    if provider not in AI_PROVIDERS:
        provider = 'claude'
    return {
        'provider': provider,
        'model': (data.get('model') or '').strip(),
        'auto_slack': bool(data.get('auto_slack', AUTO_SLACK_DEFAULT)),
        'drive': arise_drive.normalize_config(data.get('drive')),
        'probing': _normalize_probing(data.get('probing')),
        'autonomous': _normalize_autonomous(data.get('autonomous')),
        'adaptive_loop': _normalize_adaptive(data.get('adaptive_loop')),
        'ai_analyst': _normalize_ai_analyst(data.get('ai_analyst')),
    }


# AI Pass-2 probing config (see ai_probing.py). Opt-in, disabled by default.
_PROBING_DEFAULTS = {
    'enabled': False,
    'scope_locked': True,
    'max_urls': 15,
    'timeout_s': 8,
}


def _normalize_probing(block):
    """Coerce a stored/patched probing block to safe, bounded values."""
    block = block if isinstance(block, dict) else {}
    return {
        'enabled': bool(block.get('enabled', _PROBING_DEFAULTS['enabled'])),
        'scope_locked': bool(block.get('scope_locked', _PROBING_DEFAULTS['scope_locked'])),
        'max_urls': max(1, min(50, int(block.get('max_urls', _PROBING_DEFAULTS['max_urls']) or 15))),
        'timeout_s': max(1, min(30, int(block.get('timeout_s', _PROBING_DEFAULTS['timeout_s']) or 8))),
    }


# Autonomous AI action config (see arise_autonomous.py). Opt-in, OFF by default —
# autonomous tool execution must be a deliberate manual choice by the operator.
_AUTONOMOUS_DEFAULTS = {
    'enabled': False,
    'max_actions': 12,
    'max_retries': 2,
    'timeout_s': 30,
    'enable_threat_intel': False,
    'objective': 'Audit this environment for confirmable, high-signal exposures.',
}


def _normalize_autonomous(block):
    """Coerce a stored/patched autonomous block to safe, bounded values.

    Note: the tool allowlist is intentionally NOT operator-editable here — it is
    fixed in arise_autonomous.AutonomousConfig (non-destructive tools, dirsearch
    excluded) so the UI cannot widen the executor's reach.
    """
    block = block if isinstance(block, dict) else {}
    obj = str(block.get('objective', _AUTONOMOUS_DEFAULTS['objective']) or '').strip()
    return {
        'enabled': bool(block.get('enabled', _AUTONOMOUS_DEFAULTS['enabled'])),
        'max_actions': max(1, min(50, int(block.get('max_actions', 12) or 12))),
        'max_retries': max(0, min(5, int(block.get('max_retries', 2) or 2))),
        'timeout_s': max(2, min(120, int(block.get('timeout_s', 30) or 30))),
        'enable_threat_intel': bool(block.get('enable_threat_intel', False)),
        'objective': (obj or _AUTONOMOUS_DEFAULTS['objective'])[:400],
    }


# Adaptive Endpoint Attack Loop config (Module 27 — offensive/adaptive_loop.py).
# Opt-in, OFF by default. These map 1:1 onto the ADAPTIVE_LOOP_* env vars the
# pipeline reads (easm-pipeline.sh); arise_jobs.launch_scan injects them per scan.
_ADAPTIVE_DEFAULTS = {
    'enabled': False,
    'ai': False,           # P4 AI mutation brain
    'max_requests': 300,
    'max_seeds': 200,
    'budget_s': 600,       # wall-clock cap for the loop
}


def _normalize_adaptive(block):
    """Coerce a stored/patched adaptive-loop block to safe, bounded values.

    Safety (non-destructive GET/OPTIONS-only, scope-lock, oracle-gated) is fixed
    in offensive/adaptive_loop.py — only the operator-tunable knobs live here."""
    block = block if isinstance(block, dict) else {}
    return {
        'enabled': bool(block.get('enabled', _ADAPTIVE_DEFAULTS['enabled'])),
        'ai': bool(block.get('ai', _ADAPTIVE_DEFAULTS['ai'])),
        'max_requests': max(10, min(5000, int(block.get('max_requests', 300) or 300))),
        'max_seeds': max(10, min(2000, int(block.get('max_seeds', 200) or 200))),
        'budget_s': max(30, min(3600, int(block.get('budget_s', 600) or 600))),
    }


# AriseAI Red-Team Pentest auto-run config (ai_analyst package). Supersedes the
# old Autonomous Engine tile. Maps onto the AI_ANALYST_* env vars the pipeline's
# module_ai_analyst reads; arise_jobs.launch_scan injects them per scan.
# Safety: tier-3 (autonomous tool execution) is gated by its own authorization —
# enabling it here IS the operator's per-run authorization for scheduled scans.
_AI_ANALYST_DEFAULTS = {
    'enabled': False,          # auto-run after every full EASM scan
    'live_verify': True,       # tier 2 — scope-locked, non-destructive differential probes
    'autonomous': False,       # tier 3 — the merged Autonomous Action live-tool loop
    'objective': 'Audit this environment for confirmable, high-impact exposures.',
}


def _normalize_ai_analyst(block):
    """Coerce a stored/patched AriseAI block to safe, bounded values. The live
    tiers' safety (ScopeGuard, differential confirmation, non-destructive) is
    fixed in code; only the operator toggles live here."""
    block = block if isinstance(block, dict) else {}
    obj = str(block.get('objective', _AI_ANALYST_DEFAULTS['objective']) or '').strip()
    return {
        'enabled': bool(block.get('enabled', _AI_ANALYST_DEFAULTS['enabled'])),
        'live_verify': bool(block.get('live_verify', _AI_ANALYST_DEFAULTS['live_verify'])),
        'autonomous': bool(block.get('autonomous', _AI_ANALYST_DEFAULTS['autonomous'])),
        'objective': (obj or _AI_ANALYST_DEFAULTS['objective'])[:400],
    }


def save_settings(patch):
    settings = load_settings()
    if 'provider' in patch and patch['provider'] in AI_PROVIDERS:
        settings['provider'] = patch['provider']
    if 'model' in patch:
        settings['model'] = (patch.get('model') or '').strip()
    if 'auto_slack' in patch:
        settings['auto_slack'] = bool(patch['auto_slack'])
    if 'drive' in patch and isinstance(patch['drive'], dict):
        # merge partial drive patch over the current drive config
        merged = dict(settings['drive'])
        merged.update(patch['drive'])
        settings['drive'] = arise_drive.normalize_config(merged)
    if 'probing' in patch and isinstance(patch['probing'], dict):
        merged = dict(settings.get('probing') or {})
        merged.update(patch['probing'])
        settings['probing'] = _normalize_probing(merged)
    if 'autonomous' in patch and isinstance(patch['autonomous'], dict):
        merged = dict(settings.get('autonomous') or {})
        merged.update(patch['autonomous'])
        settings['autonomous'] = _normalize_autonomous(merged)
    if 'adaptive_loop' in patch and isinstance(patch['adaptive_loop'], dict):
        merged = dict(settings.get('adaptive_loop') or {})
        merged.update(patch['adaptive_loop'])
        settings['adaptive_loop'] = _normalize_adaptive(merged)
    if 'ai_analyst' in patch and isinstance(patch['ai_analyst'], dict):
        merged = dict(settings.get('ai_analyst') or {})
        merged.update(patch['ai_analyst'])
        settings['ai_analyst'] = _normalize_ai_analyst(merged)
    try:
        with open(SETTINGS_FILE, 'w') as fh:
            json.dump(settings, fh, indent=2)
    except Exception as exc:
        logger.error("Failed to write settings: %s", exc)
    return settings


# ---------------------------------------------------------------------------
# Secret masking — never leak API keys or webhooks into Slack/logs.
# ---------------------------------------------------------------------------
_SECRET_RE = re.compile(
    r'(https://hooks\.slack\.com/services/[A-Za-z0-9/_+-]+'
    r'|sk-[A-Za-z0-9_\-]{6,}'
    r'|ghp_[A-Za-z0-9]{6,}'
    r'|AIza[A-Za-z0-9_\-]{10,}'
    r'|hf_[A-Za-z0-9]{6,}'
    r'|xox[baprs]-[A-Za-z0-9-]{6,})'
)


def _mask_token(tok):
    if tok.startswith('https://hooks.slack.com/'):
        return 'https://hooks.slack.com/services/****'
    if len(tok) > 8:
        return tok[:4] + '…' + tok[-4:]
    return '****'


def _mask_secrets(text):
    """Redact any API key / Slack webhook that may appear in a string."""
    return _SECRET_RE.sub(lambda m: _mask_token(m.group(0)), text or '')


def _post_slack(webhook, text):
    """Post a message to a Slack Incoming Webhook. Returns (ok, error)."""
    if not (webhook or '').startswith('https://hooks.slack.com/'):
        return False, ("No valid Slack Incoming Webhook. Set SLACK_WEBHOOK_URL in .env "
                       "or paste a webhook URL.")
    try:
        import requests as _requests
        resp = _requests.post(webhook, json={'text': _mask_secrets(text)}, timeout=15)
    except Exception as exc:  # noqa: BLE001
        logger.error("Slack push failed: %s", exc)
        return False, f"Slack push failed: {exc}"
    if resp.status_code // 100 != 2:
        return False, f"Slack returned {resp.status_code}: {resp.text[:200]}"
    return True, None


# ---------------------------------------------------------------------------
# Automated post-scan AI review -> Slack.
# ---------------------------------------------------------------------------
AI_REVIEW_SYSTEM_PROMPT = (
    "You are ARISE's senior security analyst writing a short review of a completed"
    "External Attack Surface scan, the way an experienced human reviewer would in a "
    "Slack update to the security team. Read the JSON snapshot and write in "
    "GitHub-flavored Markdown, warm but precise, first-person where natural.\n\n"
    "Structure:\n"
    "1. **Overall** — 2-3 sentences: your read on the posture and the one thing that "
    "matters most right now.\n"
    "2. **What stood out** — 3-5 bullets, each naming the issue, why it matters in "
    "practice, and the affected asset.\n"
    "3. **What I'd do next** — 2-4 prioritized actions.\n\n"
    "Ground every claim in the data — never invent findings, hosts, or CVEs. If the "
    "data is thin, say so. Keep it under ~300 words."
)


def _cve_link(cve):
    return f"https://nvd.nist.gov/vuln/detail/{cve}"


def _build_slack_summary(context, review_md, provider, model, scan_id):
    """Compose the rich Slack message for an automated post-scan review."""
    sev = context.get('severity_counts', {})
    score = context.get('risk_score', 0)
    grade = context.get('grade', '?')
    target = context.get('target', scan_id)

    # Severity emoji for the headline.
    if sev.get('critical'):
        head_icon = ':rotating_light:'
    elif sev.get('high'):
        head_icon = ':red_circle:'
    elif sev.get('medium'):
        head_icon = ':large_yellow_circle:'
    else:
        head_icon = ':large_green_circle:'

    lines = [f"{head_icon} *ARISE scan complete — {target}*"]
    lines.append(
        f"*Overall vulnerability score:* {grade} · {score}/100    "
        f"C:{sev.get('critical',0)}  H:{sev.get('high',0)}  M:{sev.get('medium',0)}  "
        f"L:{sev.get('low',0)}    Assets: {context.get('assets',{}).get('total_hosts',0)}"
    )
    lines.append("")
    lines.append(_markdown_to_slack(review_md))

    # Top issues with reference URLs (affected asset link).
    issues = (context.get('top_vulnerabilities') or [])[:6]
    cloud = (context.get('cloud_findings') or [])[:4]
    if issues or cloud:
        lines.append("")
        lines.append("*Top issues*")
        for v in issues:
            ref = v.get('url') or v.get('host') or ''
            ref = f"  <{ref}>" if ref.startswith('http') else (f"  `{ref}`" if ref else '')
            lines.append(f"• [{v.get('severity','info').upper()}] {v.get('title','finding')}{ref}")
        for c in cloud:
            lines.append(f"• [{c.get('severity','info').upper()}] {c.get('title','')} — `{c.get('host','')}`")

    # Reference URLs (CVEs + distinct affected hosts).
    refs = []
    for cve in (context.get('cves') or [])[:8]:
        refs.append(_cve_link(cve.get('cve', '')))
    seen = set()
    for v in issues:
        u = v.get('url') or ''
        if u.startswith('http') and u not in seen:
            seen.add(u)
            refs.append(u)
        if len(refs) >= 12:
            break
    if refs:
        lines.append("")
        lines.append("*References*")
        for r in refs[:12]:
            lines.append(f"• {r}")

    # Trace line — provider/model + the key used, masked.
    key = _provider_key(provider, None)
    key_disp = _mask_token(key) if key else 'none'
    lines.append("")
    lines.append(
        f"_Trace — scan `{scan_id}` · engine {provider}/{model} · "
        f"key {key_disp} · {datetime.now().isoformat(timespec='seconds')}_"
    )
    return "\n".join(lines)


def _build_easm_report_slack(scan_id):
    """Build a compact EASM scan report as a second Slack message.

    Covers every major scan dimension in 2-3 lines each:
    attack surface, vulnerabilities, subdomain takeover, cloud exposure,
    API security, DNS, secrets, and HRS.
    """
    data = get_cached_scan_data(scan_id)
    if not data:
        return None

    from collections import Counter, defaultdict

    hosts = data.get('hosts', {})
    vulns = data.get('vulnerabilities', [])
    target = data.get('pipeline_info', {}).get('target', scan_id)
    org_score, grade = compute_org_risk(hosts)

    sev = Counter(v.get('severity', 'info') for v in vulns)
    by_source = Counter(v.get('source', '?') for v in vulns)
    affected_hosts = set(v.get('host', '') for v in vulns if v.get('host'))

    http_hosts = sum(1 for h in hosts.values() if h.get('http_status'))
    waf_count = sum(1 for h in hosts.values()
                    if h.get('waf_vendor') and h.get('waf_vendor') not in ('none', ''))
    cdn_count = sum(1 for h in hosts.values() if h.get('cdn'))

    lines = []
    lines.append(f":page_facing_up: *ARISE EASM Report — {target}*")
    lines.append(f"_Scan `{scan_id}` · {datetime.now().strftime('%d %b %Y %H:%M')}_")
    lines.append("")

    # ── Attack Surface ──
    lines.append("*:globe_with_meridians: Attack Surface*")
    lines.append(
        f">{len(hosts)} subdomains discovered · {http_hosts} HTTP-responsive · "
        f"{waf_count} behind WAF · {cdn_count} CDN-fronted"
    )
    lines.append(
        f">Risk score *{org_score}/100 ({grade})* · "
        f"{len(affected_hosts)} hosts with findings"
    )
    lines.append("")

    # ── Vulnerability Summary ──
    total = len(vulns)
    lines.append("*:warning: Vulnerabilities*")
    lines.append(
        f">{total} total findings — "
        f":red_circle: {sev.get('critical',0)} critical · "
        f":large_orange_circle: {sev.get('high',0)} high · "
        f":large_yellow_circle: {sev.get('medium',0)} medium · "
        f":white_circle: {sev.get('low',0)} low"
    )
    src_parts = [f"{c} {s}" for s, c in by_source.most_common()]
    lines.append(f">Sources: {' · '.join(src_parts)}")
    lines.append("")

    # ── Subdomain Takeover ──
    takeover = [v for v in vulns if v.get('source') == 'Subdomain Takeover']
    if takeover:
        tk_methods = Counter(v.get('detection_label', '?') for v in takeover)
        tk_hosts = set(v.get('host', '') for v in takeover)
        lines.append("*:lock: Subdomain Takeover*")
        lines.append(
            f">{len(takeover)} takeover risks across {len(tk_hosts)} subdomains"
        )
        tk_parts = [f"{c} {m}" for m, c in tk_methods.most_common()]
        lines.append(f">{' · '.join(tk_parts)}")

        top_tk = takeover[:3]
        for v in top_tk:
            host = v.get('host', '')
            tags = v.get('tags', [])
            tag_str = '  '.join(f'`{t}`' for t in tags[:3]) if tags else ''
            lines.append(f">• *{host}* — {v.get('template','')[:60]}  {tag_str}")
        lines.append("")

    def _unique_top(items, n=3):
        """Pick top N items with distinct host+template combos."""
        seen_k, out = set(), []
        for v in items:
            k = (v.get('host', ''), v.get('template', ''))
            if k not in seen_k:
                seen_k.add(k)
                out.append(v)
            if len(out) >= n:
                break
        return out

    SEV_R = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}

    # ── Cloud Exposure ──
    cloud = [v for v in vulns if v.get('source') == 'Cloud Exposure']
    if cloud:
        cloud_sev = Counter(v.get('severity', 'info') for v in cloud)
        cloud_hosts = set(v.get('host', '') for v in cloud)
        lines.append("*:cloud: Cloud Exposure*")
        lines.append(
            f">{len(cloud)} findings across {len(cloud_hosts)} assets — "
            f"{cloud_sev.get('critical',0)} critical · {cloud_sev.get('high',0)} high · "
            f"{cloud_sev.get('medium',0)} medium"
        )
        top_cloud = _unique_top(sorted(cloud, key=lambda v: SEV_R.get(
            v.get('severity', 'info'), 0), reverse=True))
        for v in top_cloud:
            lines.append(
                f">• [{v.get('severity','info').upper()}] {v.get('template','')} — "
                f"`{v.get('host','')}`"
            )
        lines.append("")

    # ── API Security ──
    api = [v for v in vulns if v.get('source') == 'API Security']
    if api:
        api_hosts = set(v.get('host', '') for v in api)
        lines.append("*:electric_plug: API Security*")
        lines.append(
            f">{len(api)} findings across {len(api_hosts)} API hosts"
        )
        top_api = _unique_top(api)
        for v in top_api:
            conf = v.get('confidence', '')
            conf_str = f" `{conf}`" if conf else ''
            lines.append(
                f">• [{v.get('severity','info').upper()}] {v.get('template','')} — "
                f"`{v.get('host','')}`{conf_str}"
            )
        lines.append("")

    # ── DNS Security ──
    dns = [v for v in vulns if v.get('source') == 'DNS Security']
    if dns:
        dns_hosts = set(v.get('host', '') for v in dns)
        lines.append("*:shield: DNS Security*")
        lines.append(f">{len(dns)} findings across {len(dns_hosts)} domains")
        for v in _unique_top(dns):
            corr = ' _(correlated with Subdomain Takeover)_' if v.get('correlated_with') else ''
            lines.append(
                f">• [{v.get('severity','info').upper()}] {v.get('template','')} — "
                f"`{v.get('host','')}`{corr}"
            )
        lines.append("")

    # ── Nuclei ──
    nuclei = [v for v in vulns if 'Nuclei' in (v.get('source') or '')]
    if nuclei:
        nuclei_sev = Counter(v.get('severity', 'info') for v in nuclei)
        lines.append("*:microscope: Nuclei Scan*")
        lines.append(
            f">{len(nuclei)} findings — "
            f"{nuclei_sev.get('critical',0)} critical · {nuclei_sev.get('high',0)} high · "
            f"{nuclei_sev.get('medium',0)} medium"
        )
        top_nuclei = _unique_top(sorted(nuclei, key=lambda v: SEV_R.get(
            v.get('severity', 'info'), 0), reverse=True), 2)
        for v in top_nuclei:
            lines.append(
                f">• [{v.get('severity','info').upper()}] {v.get('template','')} — "
                f"`{v.get('host','')}`"
            )
        lines.append("")

    # ── Secrets ──
    secrets = [v for v in vulns if v.get('source') == 'Secret Scan']
    if secrets:
        sec_hosts = set(v.get('host', '') for v in secrets)
        lines.append("*:key: Exposed Secrets*")
        lines.append(f">{len(secrets)} leaked credentials/keys across {len(sec_hosts)} assets")
        for v in _unique_top(secrets, 2):
            lines.append(
                f">• [{v.get('severity','info').upper()}] {v.get('template','')} — "
                f"`{v.get('host','')}`"
            )
        lines.append("")

    # ── HRS ──
    hrs = [v for v in vulns if v.get('source') == 'HRS Surface (indicator)']
    if hrs:
        lines.append("*:twisted_rightwards_arrows: HTTP Request Smuggling*")
        lines.append(f">{len(hrs)} potential smuggling indicators found (manual verification needed)")
        lines.append("")

    lines.append(
        f"_Full report: ARISE Dashboard · {len(vulns)} findings · "
        f"{len(hosts)} assets · grade {grade}_"
    )

    return "\n".join(lines)


def _scan_status(scan_id):
    """Return the pipeline status string for a scan, or '' if unreadable."""
    try:
        with open(os.path.join(BASE_SCAN_DIR, scan_id, 'manifest.json')) as fh:
            return (json.load(fh).get('pipeline_info', {}) or {}).get('status', '')
    except Exception:
        return ''


def _auto_summarize_scan(scan_id, force=False):
    """Generate an AI review of a completed scan and post it to Slack.

    Idempotent: writes a marker file so a scan is summarized at most once unless
    forced. Returns (ok, message).
    """
    marker = os.path.join(BASE_SCAN_DIR, scan_id, '.ai_summary_posted')
    settings = load_settings()

    if not force and not settings['auto_slack']:
        return False, "Automated Slack summary is disabled."

    provider = settings['provider']
    model = settings['model'] or AI_PROVIDERS[provider]['default_model']
    api_key = _provider_key(provider, None)
    webhook = _slack_webhook()

    # If we can't post, mark as handled (so re-enabling later doesn't flood old scans).
    if not api_key or not webhook.startswith('https://hooks.slack.com/'):
        if not force:
            _write_marker(marker, 'skipped: missing provider key or Slack webhook')
        return False, "Missing provider API key or Slack webhook (.env)."

    context = _gather_ai_context(scan_id)
    if context is None:
        return False, "Scan data not found."

    user = ("Here is the completed scan snapshot as JSON:\n\n```json\n"
            + json.dumps(context, indent=2, default=str) + "\n```\n\n"
            + "Write your review.")
    review, error = _run_ai_provider(provider, model, api_key, AI_REVIEW_SYSTEM_PROMPT, user)
    if error:
        logger.warning("Auto-summary AI call failed for %s: %s", scan_id, error)
        return False, error

    body = _build_slack_summary(context, review, provider, model, scan_id)
    ok, serr = _post_slack(webhook, body)
    if ok:
        report = _build_easm_report_slack(scan_id)
        if report:
            ok2, serr2 = _post_slack(webhook, report)
            if not ok2:
                logger.warning("EASM report Slack post failed for %s: %s", scan_id, serr2)
        _write_marker(marker, f"posted via {provider}/{model}")
        logger.info("Auto-summary + EASM report posted to Slack for %s", scan_id)
        return True, "Posted to Slack."
    logger.warning("Auto-summary Slack post failed for %s: %s", scan_id, serr)
    return False, serr


def _write_marker(path, note):
    try:
        with open(path, 'w') as fh:
            fh.write(f"{datetime.now().isoformat(timespec='seconds')} {note}\n")
    except Exception as exc:
        logger.error("Failed to write marker %s: %s", path, exc)


def _ai_watcher_loop():
    """Background thread: post an AI Slack summary when a scan newly completes.

    On the first pass it baselines every already-completed scan (writes the marker
    without posting) so restarting the dashboard never floods the backlog. After
    that, any scan that reaches 'completed' without a marker gets summarized.
    """
    baseline_done = False
    logger.info("AI scan watcher started (interval %ss)", AI_WATCH_INTERVAL)
    while True:
        try:
            for scan in get_available_scans(use_cache=False):
                sid = scan.get('id')
                status = scan.get('status', '')
                if status not in ('completed', 'completed_with_errors'):
                    continue
                marker = os.path.join(BASE_SCAN_DIR, sid, '.ai_summary_posted')
                if os.path.exists(marker):
                    continue
                if not baseline_done:
                    _write_marker(marker, 'baseline (existing scan at dashboard start)')
                    continue
                _auto_summarize_scan(sid)
                _auto_drive_sync(sid)      # sync results to Drive + apply retention
                try:
                    _run_correlate_for_target(sid)
                    logger.info("Auto-correlated %s", sid)
                except Exception as exc:
                    logger.warning("Auto-correlate failed for %s: %s", sid, exc)
                _auto_autonomous_scan(sid)  # opt-in; no-op unless enabled in Settings
            baseline_done = True
        except Exception as exc:  # noqa: BLE001
            logger.error("AI watcher error: %s", exc)
        time.sleep(AI_WATCH_INTERVAL)


def _auto_autonomous_scan(scan_id):
    """Fire the autonomous action engine for a newly completed scan — but ONLY if
    the operator has explicitly enabled it in Settings. Off by default; any error
    is logged and swallowed so it never disturbs the watcher."""
    try:
        settings = load_settings()
        cfg_block = settings.get('autonomous') or {}
        if not cfg_block.get('enabled'):
            return
        if os.path.exists(os.path.join(BASE_SCAN_DIR, scan_id, 'ai_autonomous.json')):
            return  # already run for this scan
        provider = settings['provider']
        model = settings['model'] or AI_PROVIDERS[provider]['default_model']
        api_key = _provider_key(provider, None)
        if not api_key:
            logger.info("Autonomous auto-run skipped for %s: no %s API key", scan_id, provider)
            return
        objective = cfg_block.get('objective') or _AUTONOMOUS_DEFAULTS['objective']
        logger.info("Auto-autonomous run starting for %s (provider=%s)", scan_id, provider)
        out = _run_autonomous_for_scan(scan_id, provider, model, api_key, cfg_block, objective)
        if out is not None:
            logger.info("Auto-autonomous %s: %d confirmed finding(s)",
                        scan_id, len(out.get('confirmed_findings') or []))
    except Exception as exc:  # noqa: BLE001
        logger.error("Auto-autonomous run failed for %s: %s", scan_id, exc)


def start_ai_watcher():
    t = threading.Thread(target=_ai_watcher_loop, name='ai-watcher', daemon=True)
    t.start()
    return t


# ---------------------------------------------------------------------------
# Google Drive sync (rclone) + local retention
# ---------------------------------------------------------------------------
def _drive_scan_list():
    """[{id, target, sort}] for every scan, for retention planning."""
    return [{'id': s['id'], 'target': s.get('target') or s['id'],
             'sort': s.get('scan_time_sort', 0)}
            for s in get_available_scans(use_cache=False)]


def sync_scan_to_drive(scan_id, force=False):
    """Sync one scan to Drive (if enabled). On success, apply local retention.

    Returns (ok, message). `force=True` bypasses the auto_sync toggle (manual button).
    """
    cfg = load_settings()['drive']
    if not cfg['enabled']:
        return False, "Google Drive sync is disabled in settings."
    if not force and not cfg['auto_sync']:
        return False, "Auto-sync is off; use the manual Sync button."
    if not force and arise_drive.is_synced(scan_id, BASE_SCAN_DIR):
        return True, f"{scan_id} already synced."

    ok, msg = arise_drive.sync_scan(scan_id, cfg, BASE_SCAN_DIR)
    logger.info("Drive sync %s: %s", 'ok' if ok else 'FAIL', msg)
    if ok:
        # Retention runs only after a successful sync (local-only deletion).
        try:
            result = arise_drive.apply_retention(_drive_scan_list(), cfg, BASE_SCAN_DIR)
            if result['deleted']:
                logger.info("Drive retention: deleted %d old local scan(s): %s",
                            len(result['deleted']), ', '.join(result['deleted']))
            if result['skipped_unsynced']:
                logger.info("Drive retention: kept %d unsynced scan(s) for safety: %s",
                            len(result['skipped_unsynced']), ', '.join(result['skipped_unsynced']))
        except Exception as exc:  # noqa: BLE001
            logger.error("Retention error: %s", exc)
    return ok, msg


def _auto_drive_sync(scan_id):
    """Fire-and-log auto-sync for a newly completed scan."""
    try:
        cfg = load_settings()['drive']
        if not (cfg['enabled'] and cfg['auto_sync']):
            return
        if arise_drive.is_synced(scan_id, BASE_SCAN_DIR):
            return
        sync_scan_to_drive(scan_id)
    except Exception as exc:  # noqa: BLE001
        logger.error("Auto Drive sync error for %s: %s", scan_id, exc)


@app.route('/api/settings', methods=['GET', 'POST'])
def api_settings():
    """Read or update the global AI settings (provider / model / auto-Slack)."""
    if request.method == 'POST':
        save_settings(request.get_json(silent=True) or {})
    settings = load_settings()
    prov = AI_PROVIDERS[settings['provider']]
    return jsonify({
        'provider': settings['provider'],
        'provider_label': prov['label'],
        'model': settings['model'],
        'effective_model': settings['model'] or prov['default_model'],
        'auto_slack': settings['auto_slack'],
        'autonomous': settings['autonomous'],
        'adaptive_loop': settings['adaptive_loop'],
        'ai_analyst': settings['ai_analyst'],
        'provider_ready': bool(_provider_key(settings['provider'], None)),
        'slack_configured': bool(_slack_webhook()),
        # Intel-enrichment API keys (vault or env) — so the UI can warn, per page,
        # when a key-dependent surface is running without its key.
        'keys': {
            'shodan': bool(arise_secure.resolve_secret('SHODAN_API_KEY') or os.environ.get('SHODAN_API_KEY')),
            'censys': bool((arise_secure.resolve_secret('CENSYS_API_ID') or os.environ.get('CENSYS_API_ID'))
                           and (arise_secure.resolve_secret('CENSYS_API_SECRET') or os.environ.get('CENSYS_API_SECRET'))),
            'greynoise': bool(arise_secure.resolve_secret('GREYNOISE_API_KEY') or os.environ.get('GREYNOISE_API_KEY')),
            'ipinfo': bool(arise_secure.resolve_secret('IPINFO_TOKEN') or os.environ.get('IPINFO_TOKEN')),
        },
        'providers': [
            {'id': pid, 'label': p['label'], 'default_model': p['default_model'],
             'ready': bool(_provider_key(pid, None))}
            for pid, p in AI_PROVIDERS.items()
        ],
    })


@app.route('/api/ai/slack-test', methods=['POST'])
def api_ai_slack_test():
    """Send a test message to the configured Slack webhook."""
    ok, err = _post_slack(_slack_webhook(),
                          ":white_check_mark: *ARISE* — Slack integration test. "
                          "Automated scan summaries will arrive here.")
    if ok:
        return jsonify({'ok': True})
    return jsonify({'error': err}), 400


@app.route('/api/ai/auto-summary/<path:scan_id>', methods=['POST'])
def api_ai_auto_summary(scan_id):
    """Force-generate and post an AI summary for a scan (used by the UI 'resend')."""
    resolved = resolve_target(scan_id) or scan_id
    ok, msg = _auto_summarize_scan(resolved, force=True)
    if ok:
        return jsonify({'ok': True, 'message': msg})
    return jsonify({'error': msg}), 502


@app.route('/api/ai/analyze', methods=['POST'])
def api_ai_analyze():
    """Generate an AI security analysis with the selected provider.

    Precedence: a target **folder** or a **custom prompt** overrides the default
    analysis command (preset). Folder wins over custom prompt when both are given.
    """
    payload = request.get_json(silent=True) or {}
    scan_id = resolve_target(payload.get('target') or request.args.get('target'))

    # Provider/model come from the global Settings unless the request overrides them.
    settings = load_settings()
    provider = (payload.get('provider') or settings['provider']).strip()
    if provider not in AI_PROVIDERS:
        return jsonify({'error': f'Unknown provider: {provider}'}), 400
    model = ((payload.get('model') or '').strip()
             or (settings['model'] if provider == settings['provider'] else '')
             or AI_PROVIDERS[provider]['default_model'])
    api_key = _provider_key(provider, payload.get('api_key'))
    question = (payload.get('question') or '').strip()
    folder = (payload.get('folder') or '').strip()
    preset = (payload.get('preset') or 'executive').strip()
    logger.info("API request: /api/ai/analyze provider=%s target=%s mode=%s",
                provider, scan_id, 'folder' if folder else ('custom' if question else preset))

    risk_score = grade = target_name = None
    mode = None

    if folder:
        # Folder review — the default preset is ignored.
        fctx, ferr = _gather_folder_context(folder, scan_id)
        if ferr:
            return jsonify({'error': ferr}), 400
        system = AI_FOLDER_SYSTEM_PROMPT
        instruction = question or ("Review these files for security issues, misconfigurations, "
                                   "exposed secrets, and notable findings, then summarize what "
                                   "matters and what to do about it.")
        user = ("Here are the files from folder `" + fctx['folder'] + "`"
                + (" (truncated)" if fctx['truncated'] else "") + ":\n\n```json\n"
                + json.dumps(fctx['files'], indent=2, default=str) + "\n```\n\n" + instruction)
        target_name = fctx['folder']
        mode = 'folder'
    else:
        if not scan_id:
            return jsonify({'error': 'No scan selected.'}), 400
        context = _gather_ai_context(scan_id)
        if context is None:
            return jsonify({'error': 'Scan data not found.'}), 404
        risk_score, grade, target_name = context['risk_score'], context['grade'], context['target']
        snapshot = ("Here is the scan snapshot as JSON:\n\n```json\n"
                    + json.dumps(context, indent=2, default=str) + "\n```\n\n")
        system = AI_SYSTEM_PROMPT
        if question:
            # Custom prompt — the default preset is ignored.
            user = snapshot + "The operator asked, answer it directly using the data above:\n\n" + question
            mode = 'custom'
        else:
            p = AI_PRESETS.get(preset, AI_PRESETS['executive'])
            user = snapshot + p['instruction']
            mode = 'preset:' + (preset if preset in AI_PRESETS else 'executive')

    analysis, error = _run_ai_provider(provider, model, api_key, system, user)
    if error:
        return jsonify({'error': error}), 502
    return jsonify({
        'target': target_name,
        'scan_id': scan_id,
        'provider': provider,
        'provider_label': AI_PROVIDERS[provider]['label'],
        'model': model,
        'mode': mode,
        'risk_score': risk_score,
        'grade': grade,
        'analysis': analysis,
        'generated_at': datetime.now().isoformat(timespec='seconds'),
    })


def _scope_roots_for(scan_id, target):
    """Allowlist for AI probing: the scan target plus any roots in scope/roots.txt."""
    roots = []
    roots_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'scope', 'roots.txt')
    try:
        with open(roots_file) as fh:
            roots = [ln.strip() for ln in fh if ln.strip() and not ln.startswith('#')]
    except Exception:
        pass
    return roots


@app.route('/api/ai/probe-analyze', methods=['POST'])
@login_required
def api_ai_probe_analyze():
    """Zone B two-pass AI triage with opt-in live probing (see ai_probing.py).

    Pass 1 produces a structured triage + candidate probe URLs. Pass 2 (only if
    probing is enabled in Settings) fetches the in-scope URLs GET-only and asks
    the model to finalize verdicts on the live evidence. Scope-lock, GET-only,
    max-URL cap, body/prompt caps and the audit trail are enforced inside
    ai_probing — the dashboard only supplies the AI call and the scope.
    """
    payload = request.get_json(silent=True) or {}
    scan_id = resolve_target(payload.get('target') or request.args.get('target'))
    if not scan_id:
        return jsonify({'error': 'No scan selected.'}), 400

    context = _gather_ai_context(scan_id)
    if context is None:
        return jsonify({'error': 'Scan data not found.'}), 404
    target = context.get('target') or scan_id

    settings = load_settings()
    provider = (payload.get('provider') or settings['provider']).strip()
    if provider not in AI_PROVIDERS:
        return jsonify({'error': f'Unknown provider: {provider}'}), 400
    model = ((payload.get('model') or '').strip()
             or (settings['model'] if provider == settings['provider'] else '')
             or AI_PROVIDERS[provider]['default_model'])
    api_key = _provider_key(provider, payload.get('api_key'))
    if not api_key:
        return jsonify({'error': f'No API key configured for {provider}.'}), 400

    # Probing config: Settings block, with an optional per-request override so the
    # operator can force a one-off probing run without flipping the global toggle.
    prob_cfg = dict(settings.get('probing') or {})
    if isinstance(payload.get('probing'), dict):
        prob_cfg.update(payload['probing'])
    prob_cfg = _normalize_probing(prob_cfg)

    audit_path = os.path.join(BASE_SCAN_DIR, scan_id, 'logs', 'ai_probe_audit.log')
    try:
        os.makedirs(os.path.dirname(audit_path), exist_ok=True)
    except OSError:
        audit_path = None

    cfg = ai_probing.ProbeConfig.from_settings(prob_cfg, audit_log_path=audit_path)
    scope = ai_probing.ScopeGuard(target, allowlist=_scope_roots_for(scan_id, target))

    # Bind v3's provider dispatch as the injected chat function.
    def chat_fn(system, user):
        return _run_ai_provider(provider, model, api_key, system, user)

    logger.info("API request: /api/ai/probe-analyze target=%s provider=%s probing=%s",
                scan_id, provider, cfg.enabled)
    result = ai_probing.run_two_pass(context, target, chat_fn, cfg, scope)
    out = result.to_dict()
    out.update({
        'target': target, 'scan_id': scan_id,
        'provider': provider, 'model': model,
        'probing_enabled': cfg.enabled,
    })

    # Persist alongside the scan for the dashboard/API to read back.
    try:
        with open(os.path.join(BASE_SCAN_DIR, scan_id, 'ai_analysis.json'), 'w') as fh:
            json.dump(out, fh, indent=2)
    except Exception as exc:
        logger.error("Failed to write ai_analysis.json: %s", exc)

    status = 502 if (result.error and not result.summary) else 200
    return jsonify(out), status


@app.route('/api/scan/<path:scan_id>/ai-analysis')
@login_required
def api_get_ai_analysis(scan_id):
    """Read back the stored two-pass AI analysis for a scan (empty if never run)."""
    resolved = resolve_target(scan_id) or scan_id
    path = os.path.join(BASE_SCAN_DIR, resolved, 'ai_analysis.json')
    if not os.path.exists(path):
        return jsonify({'error': 'not_analyzed'}), 404
    try:
        with open(path) as fh:
            return jsonify(json.load(fh))
    except Exception as exc:
        return jsonify({'error': str(exc)}), 500


# ---------------------------------------------------------------------------
# Zone C — Autonomous AI action (see arise_autonomous.py). Opt-in, OFF by default.
# ---------------------------------------------------------------------------

def _run_autonomous_for_scan(scan_id, provider, model, api_key, cfg_block, objective):
    """Assemble context + guardrails and drive arise_autonomous.run_autonomous.

    Returns the result dict (also persisted to scans/<id>/ai_autonomous.json), or
    None if the scan data is missing. Never raises — the engine is fail-safe.
    """
    context = _gather_ai_context(scan_id)
    if context is None:
        return None
    target = context.get('target') or scan_id

    audit_path = os.path.join(BASE_SCAN_DIR, scan_id, 'logs', 'ai_autonomous_audit.log')
    try:
        os.makedirs(os.path.dirname(audit_path), exist_ok=True)
    except OSError:
        audit_path = None

    cfg = arise_autonomous.AutonomousConfig.from_settings(
        cfg_block, audit_log_path=audit_path,
        scan_dir=os.path.join(BASE_SCAN_DIR, scan_id))
    scope = ai_probing.ScopeGuard(target, allowlist=_scope_roots_for(scan_id, target))

    def chat_fn(system, user):
        return _run_ai_provider(provider, model, api_key, system, user)

    result = arise_autonomous.run_autonomous(context, target, objective, chat_fn, cfg, scope)
    out = result.to_dict()
    out.update({'target': target, 'scan_id': scan_id, 'provider': provider, 'model': model})
    try:
        with open(os.path.join(BASE_SCAN_DIR, scan_id, 'ai_autonomous.json'), 'w') as fh:
            json.dump(out, fh, indent=2)
    except Exception as exc:
        logger.error("Failed to write ai_autonomous.json: %s", exc)
    return out


@app.route('/api/ai/autonomous', methods=['POST'])
@login_required
def api_ai_autonomous():
    """Manually launch the autonomous AI action engine for a completed scan.

    Runs the manager->worker->verifier->report loop with non-destructive,
    scope-locked tool execution (arise_autonomous.py). Requires the autonomous
    feature to be enabled — either globally in Settings or via a per-request
    override — since it executes live security tooling.
    """
    payload = request.get_json(silent=True) or {}
    scan_id = resolve_target(payload.get('target') or request.args.get('target'))
    if not scan_id:
        return jsonify({'error': 'No scan selected.'}), 400

    settings = load_settings()
    provider = (payload.get('provider') or settings['provider']).strip()
    if provider not in AI_PROVIDERS:
        return jsonify({'error': f'Unknown provider: {provider}'}), 400
    model = ((payload.get('model') or '').strip()
             or (settings['model'] if provider == settings['provider'] else '')
             or AI_PROVIDERS[provider]['default_model'])
    api_key = _provider_key(provider, payload.get('api_key'))
    if not api_key:
        return jsonify({'error': f'No API key configured for {provider}.'}), 400

    cfg_block = dict(settings.get('autonomous') or {})
    if isinstance(payload.get('autonomous'), dict):
        cfg_block.update(payload['autonomous'])
    cfg_block = _normalize_autonomous(cfg_block)
    # Manual launch is itself an explicit opt-in, so honor a per-request enable.
    if not cfg_block['enabled']:
        return jsonify({'error': 'Autonomous action is disabled. Enable it in Settings '
                                 'or pass autonomous.enabled=true to run once.'}), 400

    objective = (payload.get('objective') or cfg_block.get('objective') or '').strip()
    logger.info("API request: /api/ai/autonomous target=%s provider=%s objective=%r",
                scan_id, provider, objective)
    out = _run_autonomous_for_scan(scan_id, provider, model, api_key, cfg_block, objective)
    if out is None:
        return jsonify({'error': 'Scan data not found.'}), 404
    status = 502 if (out.get('error') and not out.get('confirmed_findings')) else 200
    return jsonify(out), status


@app.route('/api/scan/<path:scan_id>/autonomous')
@login_required
def api_get_autonomous(scan_id):
    """Read back the stored autonomous action result for a scan."""
    resolved = resolve_target(scan_id) or scan_id
    path = os.path.join(BASE_SCAN_DIR, resolved, 'ai_autonomous.json')
    if not os.path.exists(path):
        return jsonify({'error': 'not_run'}), 404
    try:
        with open(path) as fh:
            return jsonify(json.load(fh))
    except Exception as exc:
        return jsonify({'error': str(exc)}), 500


# ---------------------------------------------------------------------------
# AriseAI — Autonomous AI Red-Team Pentester (the rebuilt AI Analyst engine).
# Runs AFTER a full EASM scan: reasons over the collected evidence, ranks attack
# hypotheses, live-verifies the top ones through the scope-guarded differential
# substrate, and emits proven, PoC-backed findings + a red-team report.
# ---------------------------------------------------------------------------
# In-progress AriseAI pentest runs (scan_id -> {started, error}). The run is a
# background thread; the UI polls /api/scan/<id>/ai_pentest until it clears.
_AI_PENTEST_RUNNING = {}
_AI_PENTEST_LOCK = threading.Lock()


def _run_ai_pentest_for_scan(scan_id, provider, model, api_key, live_verify, budget,
                             autonomous_exec=False, objective='', authz_confirmed=False,
                             adversary=''):
    """Drive ai_analyst.run_pentest for a completed scan. Never raises; the engine
    is fail-safe and writes its own artifacts into 28_ai_analyst/.

    The AriseAI engine now subsumes the old Autonomous Action: `autonomous_exec`
    turns on its deepest tier (the scope-locked live-tool loop)."""
    import ai_analyst
    scan_dir = os.path.join(BASE_SCAN_DIR, scan_id)
    target = resolve_target(scan_id) or scan_id
    try:
        ctx = _gather_ai_context(scan_id)
        if isinstance(ctx, dict) and ctx.get('target'):
            target = ctx['target']
    except Exception:
        pass

    def chat_fn(system, user):
        return _run_ai_provider(provider, model, api_key, system, user)

    cfg = ai_analyst.PentestConfig()
    cfg.live_verify = bool(live_verify)
    cfg.autonomous_exec = bool(autonomous_exec)
    cfg.authz_confirmed = bool(authz_confirmed)
    if objective:
        cfg.objective = str(objective)
    if budget:
        cfg.verify_budget = int(budget)
    if adversary:
        cfg.adversary = str(adversary)
    res = ai_analyst.run_pentest(scan_dir, target=target, provider=provider,
                                 model=model, chat_fn=chat_fn, config=cfg)
    out = res.to_dict()
    out.update({'scan_id': scan_id, 'provider': provider, 'model': model})
    return out


@app.route('/api/ai/pentest', methods=['POST'])
@login_required
def api_ai_pentest():
    """Launch the AriseAI autonomous red-team pentest for a completed scan.

    Reasons over the EASM evidence and (when live_verify is on) actively confirms
    the top hypotheses through ARISE's scope-guarded, non-destructive differential
    engine. live_verify defaults OFF for a manual button press (it sends live
    traffic); the post-scan pipeline run enables it automatically.
    """
    payload = request.get_json(silent=True) or {}
    scan_id = resolve_target(payload.get('target') or request.args.get('target'))
    if not scan_id:
        return jsonify({'error': 'No scan selected.'}), 400

    settings = load_settings()
    provider = (payload.get('provider') or settings['provider']).strip()
    if provider not in AI_PROVIDERS:
        return jsonify({'error': f'Unknown provider: {provider}'}), 400
    model = ((payload.get('model') or '').strip()
             or (settings['model'] if provider == settings['provider'] else '')
             or AI_PROVIDERS[provider]['default_model'])
    api_key = _provider_key(provider, payload.get('api_key'))
    if not api_key:
        return jsonify({'error': f'No API key configured for {provider}.'}), 400

    live_verify = bool(payload.get('live_verify', False))
    autonomous_exec = bool(payload.get('autonomous_exec', False))
    authz_confirmed = bool(payload.get('authz_confirmed', False))
    objective = (payload.get('objective') or '').strip()
    adversary_profile = (payload.get('adversary') or '').strip()
    budget = payload.get('verify_budget')
    logger.info("API request: /api/ai/pentest target=%s provider=%s live_verify=%s autonomous=%s authz=%s adversary=%s",
                scan_id, provider, live_verify, autonomous_exec, authz_confirmed, adversary_profile)

    # Run as a BACKGROUND job and let the UI poll /api/scan/<id>/ai_pentest. The
    # autonomous/live tiers can take minutes (iterate-until-exploit + live tools),
    # so blocking the HTTP request here made the button look dead. The engine
    # writes 28_ai_analyst/ai_analyst_result.json; polling reads it back.
    with _AI_PENTEST_LOCK:
        if scan_id in _AI_PENTEST_RUNNING:
            return jsonify({'status': 'running', 'scan_id': scan_id}), 202
        _AI_PENTEST_RUNNING[scan_id] = {'started': time.time(), 'error': None}

    def _worker():
        try:
            _run_ai_pentest_for_scan(scan_id, provider, model, api_key, live_verify, budget,
                                     autonomous_exec=autonomous_exec, objective=objective,
                                     authz_confirmed=authz_confirmed,
                                     adversary=adversary_profile)
        except Exception as exc:
            logger.error("AriseAI background run failed: %s", exc)
            with _AI_PENTEST_LOCK:
                if scan_id in _AI_PENTEST_RUNNING:
                    _AI_PENTEST_RUNNING[scan_id]['error'] = str(exc)[:300]
        finally:
            with _AI_PENTEST_LOCK:
                _AI_PENTEST_RUNNING.pop(scan_id, None)

    threading.Thread(target=_worker, name=f"ariseai-{scan_id}", daemon=True).start()
    return jsonify({'status': 'started', 'scan_id': scan_id}), 202


@app.route('/api/ai/recon', methods=['POST'])
@login_required
def api_ai_recon():
    """Run AriseAI recon-only analysis on a scan (any stage — works on partial data).

    Produces an attack surface assessment from recon data: tech stacks, WAFs,
    OSINT signals, missing headers, exposed ports, prioritized targets.
    No live traffic. Works on scans still in progress."""
    payload = request.get_json(silent=True) or {}
    scan_id = resolve_target(payload.get('target') or request.args.get('target'))
    if not scan_id:
        return jsonify({'error': 'No scan selected.'}), 400

    settings = load_settings()
    provider = (payload.get('provider') or settings['provider']).strip()
    if provider not in AI_PROVIDERS:
        return jsonify({'error': f'Unknown provider: {provider}'}), 400
    model = ((payload.get('model') or '').strip()
             or (settings['model'] if provider == settings['provider'] else '')
             or AI_PROVIDERS[provider]['default_model'])
    api_key = _provider_key(provider, payload.get('api_key'))
    if not api_key:
        return jsonify({'error': f'No API key configured for {provider}.'}), 400

    logger.info("API request: /api/ai/recon target=%s provider=%s", scan_id, provider)

    scan_dir = os.path.join(BASE_SCAN_DIR, scan_id)
    target = resolve_target(scan_id) or scan_id
    try:
        ctx = _gather_ai_context(scan_id)
        if isinstance(ctx, dict) and ctx.get('target'):
            target = ctx['target']
    except Exception:
        pass

    def chat_fn(system, user):
        return _run_ai_provider(provider, model, api_key, system, user)

    import ai_analyst
    cfg = ai_analyst.PentestConfig(recon_only=True, live_verify=False)
    res = ai_analyst.run_pentest(scan_dir, target=target, provider=provider,
                                 model=model, chat_fn=chat_fn, config=cfg)
    out = res.to_dict()
    out.update({'scan_id': scan_id, 'provider': provider, 'model': model, 'mode': 'recon_only'})
    return jsonify(out)


@app.route('/api/ai/adversaries', methods=['GET'])
@login_required
def api_ai_adversaries():
    """List available adversary emulation profiles for AriseAI red team engagements."""
    try:
        from ai_analyst.adversary import list_profiles
        return jsonify({'profiles': list_profiles()})
    except Exception as exc:
        return jsonify({'error': str(exc)}), 500


@app.route('/api/ai/stop', methods=['POST'])
@login_required
def api_ai_stop():
    """Kill switch (Phase 6 / RT4): request a clean abort of a running autonomous
    AI tier for a scan by setting its scan-local .ai_stop sentinel."""
    payload = request.get_json(silent=True) or {}
    scan_id = resolve_target(payload.get('target') or request.args.get('target'))
    if not scan_id:
        return jsonify({'error': 'No scan selected.'}), 400
    try:
        from core import budget
        ok = budget.request_kill(os.path.join(BASE_SCAN_DIR, scan_id))
        return jsonify({'ok': bool(ok)})
    except Exception as exc:
        return jsonify({'error': str(exc)}), 500


@app.route('/api/ai/replay_poc', methods=['POST'])
@login_required
def api_ai_replay_poc():
    """Replay a proven finding's PoC (Phase 5 / RT2): re-issue the exact recorded
    request through the scope-guarded, non-destructive HTTP client and return the
    live response so the operator can confirm the exploit still reproduces."""
    payload = request.get_json(silent=True) or {}
    scan_id = resolve_target(payload.get('target') or request.args.get('target'))
    if not scan_id:
        return jsonify({'error': 'No scan selected.'}), 400
    finding = payload.get('finding') or {}
    if not isinstance(finding, dict) or not finding.get('url'):
        return jsonify({'error': 'A finding with a url is required.'}), 400
    target = resolve_target(scan_id) or scan_id
    try:
        from ai_analyst import poc
        out = poc.replay(finding, target, os.path.join(BASE_SCAN_DIR, scan_id))
    except Exception as exc:
        return jsonify({'error': str(exc)}), 500
    return jsonify(out), (200 if out.get('ok') else 502)


@app.route('/api/scan/<path:scan_id>/ai_pentest')
@login_required
def api_get_ai_pentest(scan_id):
    """Read back the stored AriseAI pentest result, or report that a background
    run is still in progress (so the UI can poll)."""
    resolved = resolve_target(scan_id) or scan_id
    with _AI_PENTEST_LOCK:
        running = _AI_PENTEST_RUNNING.get(resolved)
    if running:
        return jsonify({'status': 'running',
                        'elapsed_s': int(time.time() - running['started'])}), 200
    try:
        from ai_analyst.integration import load_result
        data = load_result(os.path.join(BASE_SCAN_DIR, resolved))
    except Exception as exc:
        return jsonify({'error': str(exc)}), 500
    if not data:
        return jsonify({'error': 'not_run'}), 404
    return jsonify(data)


@app.route('/api/ai/slack', methods=['POST'])
def api_ai_slack():
    """Push a manual analysis to Slack via the configured Incoming Webhook (.env).

    Sends two messages:
      1. The AI briefing (analysis text)
      2. The full EASM scan report (data-driven breakdown by category)
    """
    payload = request.get_json(silent=True) or {}
    text = (payload.get('text') or '').strip()
    target = payload.get('target') or ''
    scan_id = payload.get('scan_id') or ''
    if not text:
        return jsonify({'error': 'Nothing to send — generate an analysis first.'}), 400

    webhook = _slack_webhook()

    header = f":shield: *ARISE Security Briefing — {target}*" if target else ":shield: *ARISE Security Briefing*"
    body = f"{header}\n\n{_markdown_to_slack(text)}"
    ok, err = _post_slack(webhook, body)
    if not ok:
        return jsonify({'error': err}), 502

    if scan_id:
        report = _build_easm_report_slack(scan_id)
        if report:
            ok2, err2 = _post_slack(webhook, report)
            if not ok2:
                logger.warning("EASM report Slack post failed: %s", err2)

    return jsonify({'ok': True})


@app.route('/api/ai/slack-report', methods=['POST'])
@login_required
def api_ai_slack_report():
    """Send just the EASM report to Slack (no AI analysis needed)."""
    payload = request.get_json(silent=True) or {}
    scan_id = payload.get('scan_id') or ''
    if not scan_id:
        scan_id = resolve_target(payload.get('target'))
    if not scan_id:
        return jsonify({'error': 'No scan selected.'}), 400

    report = _build_easm_report_slack(scan_id)
    if not report:
        return jsonify({'error': 'Scan data not found.'}), 404

    ok, err = _post_slack(_slack_webhook(), report)
    if ok:
        return jsonify({'ok': True})
    return jsonify({'error': err}), 502


@app.route('/api/ai/status')
def api_ai_status():
    """Report available providers, presets, and Slack config so the UI can guide setup."""
    try:
        import anthropic  # noqa: F401
        claude_installed = True
    except ImportError:
        claude_installed = False

    providers = []
    default_provider = None
    for pid, p in AI_PROVIDERS.items():
        installed = claude_installed if pid == 'claude' else True  # others just need requests
        key_set = bool(_provider_key(pid, None))
        ready = installed and key_set
        if ready and default_provider is None:
            default_provider = pid
        providers.append({
            'id': pid, 'label': p['label'], 'default_model': p['default_model'],
            'installed': installed, 'key_set': key_set, 'ready': ready,
        })
    presets = [{'id': k, 'label': v['label']} for k, v in AI_PRESETS.items()]
    return jsonify({
        'providers': providers,
        'presets': presets,
        'default_provider': default_provider or 'claude',
        'any_ready': any(p['ready'] for p in providers),
        'slack_env_configured': bool(_slack_webhook()),
    })


@app.route('/api/ai/context')
@login_required
def api_ai_context():
    """Return the raw context dict that would be sent to an AI provider."""
    scan_id = resolve_target(request.args.get('target'))
    if not scan_id:
        return jsonify({'error': 'No scan selected.'}), 400
    context = _gather_ai_context(scan_id)
    if not context:
        return jsonify({'error': 'No scan data found.'}), 404
    return jsonify(context)


# ===========================================================================
# ASSET GRAPH — WebGL-rendered attack surface topology
# ===========================================================================
@app.route('/api/graph')
@login_required
def api_graph():
    """Build a relationship graph of the scan's attack surface.

    Node types: target (root), host (subdomain), ip, waf, service.
    Edge types: subdomain, resolves, protected, exposes.
    """
    scan_id = resolve_target(request.args.get('target'))
    if not scan_id:
        return jsonify({'nodes': [], 'edges': [], 'error': 'No scan selected.'}), 400
    data = get_cached_scan_data(scan_id)
    if not data:
        return jsonify({'nodes': [], 'edges': []}), 404

    target = data.get('pipeline_info', {}).get('target', scan_id)
    hosts = data.get('hosts', {})
    vulns = data.get('vulnerabilities', [])
    nodes, edges = [], []

    # Vuln counts per host
    vcnt = {}
    for v in vulns:
        h = v.get('host', '')
        vcnt[h] = vcnt.get(h, 0) + 1

    # Root
    nodes.append({'id': f't:{target}', 'label': target, 'nodeType': 'target', 'size': 24, 'color': '#2dd4bf'})

    ip_set, waf_set, svc_set = set(), set(), set()
    band_color = {'critical': '#f87171', 'high': '#f97316', 'medium': '#eab308', 'low': '#38bdf8', 'ok': '#22c55e'}

    for host, hd in hosts.items():
        risk = hd.get('risk_score', 0)
        band = hd.get('risk_band', 'low')
        vc = vcnt.get(host, 0)
        short = host.replace(f'.{target}', '') if host.endswith(f'.{target}') else host
        nodes.append({
            'id': f'h:{host}', 'label': short, 'nodeType': 'host',
            'size': 6 + min(risk / 8, 10), 'color': band_color.get(band, '#94a3b8'),
            'risk_score': risk, 'risk_band': band, 'vuln_count': vc,
            'full_host': host, 'http_status': hd.get('http_status'),
            'waf': hd.get('waf_vendor'), 'ip': hd.get('ip'),
        })
        edges.append({'source': f't:{target}', 'target': f'h:{host}', 'edgeType': 'subdomain'})

        # IP
        ip = hd.get('ip')
        if ip:
            nid = f'ip:{ip}'
            if ip not in ip_set:
                nodes.append({'id': nid, 'label': ip, 'nodeType': 'ip', 'size': 5, 'color': '#818cf8'})
                ip_set.add(ip)
            edges.append({'source': f'h:{host}', 'target': nid, 'edgeType': 'resolves'})

        # WAF
        waf = (hd.get('waf_vendor') or '').strip()
        if waf and waf.lower() not in ('none', ''):
            nid = f'waf:{waf}'
            if waf not in waf_set:
                nodes.append({'id': nid, 'label': waf, 'nodeType': 'waf', 'size': 12, 'color': '#22c55e'})
                waf_set.add(waf)
            edges.append({'source': f'h:{host}', 'target': nid, 'edgeType': 'protected'})

        # Services
        for svc in (hd.get('services') or [])[:8]:
            port = svc.get('port')
            name = svc.get('name') or svc.get('product') or f'port-{port}'
            product = (svc.get('product') or '').strip()
            skey = f"{port}/{name}"
            nid = f'svc:{skey}'
            if skey not in svc_set:
                lbl = f'{port}/{name}' + (f' ({product})' if product else '')
                nodes.append({'id': nid, 'label': lbl, 'nodeType': 'service', 'size': 4, 'color': '#eab308'})
                svc_set.add(skey)
            edges.append({'source': f'h:{host}', 'target': nid, 'edgeType': 'exposes'})

    return jsonify({
        'target': target, 'nodes': nodes, 'edges': edges,
        'stats': {'hosts': len(hosts), 'ips': len(ip_set),
                  'wafs': len(waf_set), 'services': len(svc_set)},
    })


# ===========================================================================
# AUTH — single admin, session cookie. Structured so SSO/SAML/Google can be
# added later as extra AUTH_METHODS without changing the session shape.
# ===========================================================================
AUTH_METHODS = {'local'}  # future: 'google', 'saml', 'oidc'


@app.route('/login')
def login_page():
    if session.get('user'):
        return redirect('/')
    return render_template('login.html')


@app.route('/api/auth/login', methods=['POST'])
def api_auth_login():
    payload = request.get_json(silent=True) or request.form
    username = (payload.get('username') or '').strip()
    password = payload.get('password') or ''
    ip = request.remote_addr or 'unknown'

    locked, retry_after = arise_secure.check_login_lockout(username, ip)
    if locked:
        logger.warning("Login blocked (lockout): user=%s ip=%s retry_after=%ss", username, ip, retry_after)
        resp = jsonify({'error': f'Too many failed attempts. Try again in {retry_after}s.'})
        resp.headers['Retry-After'] = str(retry_after)
        return resp, 429

    user = arise_secure.verify_user(username, password)
    if not user:
        arise_secure.record_failed_login(username, ip)
        logger.info("Failed login attempt for user=%s from %s", username, ip)
        return jsonify({'error': 'Invalid username or password.'}), 401
    arise_secure.record_successful_login(username, ip)
    session.clear()
    session['user'] = user['username']
    session['role'] = user.get('role', 'admin')
    session.permanent = False
    logger.info("Login: %s from %s", username, ip)
    return jsonify({'ok': True, 'user': user['username'], 'role': user.get('role')})


@app.route('/api/auth/logout', methods=['POST'])
def api_auth_logout():
    session.clear()
    return jsonify({'ok': True})


@app.route('/api/health')
def api_health():
    """Unauthenticated liveness probe (whitelisted in the auth gate)."""
    return jsonify({'ok': True, 'service': 'arise-dashboard'})


@app.route('/api/ip-reputation/<ip>')
@login_required
def api_ip_reputation(ip):
    """Server-side proxy for IP reputation lookups.

    Proxies to IPInfo (free tier, no key required) and returns structured
    data.  Shodan and Talos are deep-linked client-side (no API key stored
    here).  This endpoint prevents the browser from leaking the user's IP to
    third-party services on every lookup.
    """
    # Basic IPv4/IPv6 validation — reject obviously bad input
    import re as _re
    if not _re.match(r'^[0-9a-fA-F.:]{3,45}$', ip or ''):
        return jsonify({'error': 'Invalid IP address'}), 400

    result = {'ip': ip, 'ipinfo': None, 'error': None}

    # IPInfo — free-tier endpoint, no API key needed for basic fields
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(
            f'https://ipinfo.io/{urllib.parse.quote(ip)}/json',
            headers={'User-Agent': 'ARISE-EASM/2.1', 'Accept': 'application/json'}
        )
        with urllib.request.urlopen(req, timeout=6, context=ctx) as resp:
            raw = resp.read(8192).decode(errors='ignore')
            result['ipinfo'] = json.loads(raw)
    except Exception as exc:
        result['error'] = str(exc)

    # Try reverse DNS for context
    try:
        result['rdns'] = socket.gethostbyaddr(ip)[0]
    except Exception:
        result['rdns'] = None

    # Check whether the IP resolves to a known CDN/WAF hostname
    rdns = result.get('rdns') or ''
    result['is_cdn_waf'] = bool(CDN_WAF_HOST_RE.search(rdns))

    # Deep-link URLs for the client to open in new tabs
    result['shodan_url'] = f'https://www.shodan.io/host/{urllib.parse.quote(ip)}'
    result['talos_url'] = (
        f'https://talosintelligence.com/reputation_center/lookup?search={urllib.parse.quote(ip)}'
    )
    result['ipinfo_url'] = f'https://ipinfo.io/{urllib.parse.quote(ip)}'
    result['abuseipdb_url'] = f'https://www.abuseipdb.com/check/{urllib.parse.quote(ip)}'

    return jsonify(result)


@app.route('/api/secrets/test/<name>', methods=['POST'])
@login_required
def api_secret_test(name):
    """Live-test a stored secret by making a real API call.
    Returns {ok, error, detail} so the GUI can show a meaningful status badge.
    """
    # AI provider keys → verified with a tiny real completion through the unified
    # provider layer (works for every provider, incl. OpenRouter + Groq).
    _AI_KEY_PROVIDER = {
        'ANTHROPIC_API_KEY': 'claude', 'OPENAI_API_KEY': 'openai',
        'GEMINI_API_KEY': 'gemini', 'HF_API_TOKEN': 'huggingface',
        'OPENROUTER_API_KEY': 'openrouter', 'GROQ_API_KEY': 'groq',
    }
    if name in _AI_KEY_PROVIDER:
        if not arise_secure.resolve_secret(name):
            return jsonify({'ok': False, 'error': 'Key not set — save it in Settings first'})
        provider = _AI_KEY_PROVIDER[name]
        try:
            from core import ai_provider, ai_models
            model = ai_models.resolve(provider)['model']
            r = ai_provider.call_llm("You are a connectivity health check.",
                                     "Reply with the single word: OK",
                                     provider=provider, purpose='keytest',
                                     max_tokens=16, timeout=20, retries=0, harden=False)
            if r.ok:
                return jsonify({'ok': True, 'detail': f"{AI_PROVIDERS.get(provider,{}).get('label',provider)} "
                                f"key valid — model {r.model} responded ({r.tokens_out} tok)."})
            return jsonify({'ok': False, 'error': f"{r.degrade_reason or 'no response'} (model {model})"})
        except Exception as exc:
            return jsonify({'ok': False, 'error': str(exc)[:200]})

    allowed = {'IPINFO_TOKEN', 'CENSYS_API_ID', 'CENSYS_API_SECRET',
               'GREYNOISE_API_KEY', 'SHODAN_API_KEY'}
    if name not in allowed:
        return jsonify({'ok': False, 'error': 'Unknown secret name'}), 400

    token = arise_secure.resolve_secret(name)
    if not token:
        return jsonify({'ok': False, 'error': 'Token not set — save it in Settings first'})

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        if name == 'IPINFO_TOKEN':
            req = urllib.request.Request(
                f'https://ipinfo.io/8.8.8.8/json?token={urllib.parse.quote(token)}',
                headers={'User-Agent': 'ARISE-EASM/2.1', 'Accept': 'application/json'}
            )
            with urllib.request.urlopen(req, timeout=8, context=ctx) as resp:
                data = json.loads(resp.read(4096).decode(errors='ignore'))
            if 'bogon' in str(data.get('error', '')).lower() or data.get('ip'):
                return jsonify({'ok': True, 'detail': f"Token valid — org: {data.get('org','?')}"})
            if data.get('error'):
                return jsonify({'ok': False, 'error': f"IPInfo: {data['error']}"})
            return jsonify({'ok': True, 'detail': 'Token accepted'})

        if name == 'GREYNOISE_API_KEY':
            req = urllib.request.Request(
                'https://api.greynoise.io/v3/community/8.8.8.8',
                headers={'key': token, 'Accept': 'application/json', 'User-Agent': 'ARISE-EASM/2.1'}
            )
            with urllib.request.urlopen(req, timeout=8, context=ctx) as resp:
                data = json.loads(resp.read(4096).decode(errors='ignore'))
            return jsonify({'ok': True, 'detail': f"GreyNoise token valid — noise: {data.get('noise')}"})

        if name == 'SHODAN_API_KEY':
            req = urllib.request.Request(
                f'https://api.shodan.io/api-info?key={urllib.parse.quote(token)}',
                headers={'User-Agent': 'ARISE-EASM/2.1'}
            )
            with urllib.request.urlopen(req, timeout=8, context=ctx) as resp:
                data = json.loads(resp.read(4096).decode(errors='ignore'))
            return jsonify({'ok': True, 'detail': f"Shodan valid — plan: {data.get('plan','?')}, credits: {data.get('scan_credits','?')}"})

        return jsonify({'ok': False, 'error': f'No test implemented for {name}'})

    except urllib.error.HTTPError as e:
        body = ''
        try:
            body = e.read(512).decode(errors='ignore')
        except Exception:
            pass
        if e.code == 401:
            return jsonify({'ok': False, 'error': f'Invalid token (401 Unauthorized). Check the value and try again.'})
        if e.code == 403:
            return jsonify({'ok': False, 'error': f'Access denied (403). Token may be expired or plan restricted.'})
        return jsonify({'ok': False, 'error': f'HTTP {e.code}: {body[:200]}'})
    except Exception as exc:
        return jsonify({'ok': False, 'error': str(exc)})


@app.route('/api/auth/me')
def api_auth_me():
    return jsonify({'user': session.get('user'), 'role': session.get('role'),
                    'methods': sorted(AUTH_METHODS)})


@app.route('/api/auth/password', methods=['POST'])
@login_required
def api_auth_password():
    payload = request.get_json(silent=True) or {}
    current = payload.get('current_password') or ''
    new = (payload.get('new_password') or '').strip()
    if len(new) < 8:
        return jsonify({'error': 'New password must be at least 8 characters.'}), 400
    if not arise_secure.verify_user(session['user'], current):
        return jsonify({'error': 'Current password is incorrect.'}), 401
    arise_secure.set_password(session['user'], new, role=session.get('role', 'admin'))
    return jsonify({'ok': True})


# ===========================================================================
# SCAN CONTROL — trigger / rescan / jobs (detached runner in arise_jobs.py)
# ===========================================================================
@app.route('/api/scan/trigger', methods=['POST'])
@login_required
def api_scan_trigger():
    """Add a new host and launch a scan; optionally set a recurring schedule."""
    payload = request.get_json(silent=True) or {}
    target = payload.get('target')
    frequency = (payload.get('frequency') or 'off').strip()
    cron = (payload.get('cron') or '').strip() or None
    mode = (payload.get('mode') or 'full').strip()
    only_modules = payload.get('only_modules') or None
    # Per-scan Adaptive Loop override: True/False forces it for this scan;
    # None (key absent) falls back to the global Settings toggle.
    adaptive = payload.get('adaptive_loop')
    adaptive = bool(adaptive) if isinstance(adaptive, bool) else None
    # Optional session cookie ('name=value; name2=value2') for authenticated
    # scanning — see core/session_jar.py. Per-scan only, never persisted.
    session_cookie = (payload.get('session_cookie') or '').strip() or None
    # Optional SECOND identity — enables the real cross-account BOLA/BFLA
    # differential (api_security/auth_oracle.py, R5): does user B see user
    # A's objects. Without it, auth_oracle still runs owner-vs-anonymous
    # (catches "no auth required at all"), just not the full cross-account
    # check. Per-scan only, never persisted (F08/P2-14, ARISE_REMEDIATION_ROADMAP.md).
    session_cookie_b = (payload.get('session_cookie_b') or '').strip() or None

    schedule = None
    sched_only = frequency == 'once'

    if sched_only:
        # "Scheduled once" — don't launch now; just set the schedule.
        t = arise_jobs.sanitize_target(target)
        if not t:
            return jsonify({'error': 'Invalid target.'}), 400
        job = {'target': t, 'job_id': None, 'status': 'scheduled'}
    else:
        job, err = arise_jobs.launch_scan(target, source='manual',
                                          mode=mode, only_modules=only_modules,
                                          adaptive=adaptive,
                                          session_cookie=session_cookie,
                                          session_cookie_b=session_cookie_b)
        if err:
            return jsonify({'error': err}), 400

    if frequency and frequency != 'off':
        hour = int(payload.get('hour', 2))
        minute = int(payload.get('minute', 0))
        day_of_week = payload.get('day_of_week') or None
        day_of_month = payload.get('day_of_month') or None
        run_date = payload.get('run_date') or None
        schedule, serr = arise_jobs.set_schedule(
            job['target'], frequency, cron,
            hour=hour, minute=minute, day_of_week=day_of_week,
            day_of_month=day_of_month, run_date=run_date)
        if serr:
            return jsonify({'ok': True, 'job': job, 'schedule_error': serr})
    return jsonify({'ok': True, 'job': job, 'schedule': schedule})


@app.route('/api/scan/rescan', methods=['POST'])
@login_required
def api_scan_rescan():
    """Re-run the pipeline for an existing target (the per-dashboard Rescan button)."""
    payload = request.get_json(silent=True) or {}
    target = payload.get('target')
    mode = (payload.get('mode') or 'full').strip()
    only_modules = payload.get('only_modules') or None
    adaptive = payload.get('adaptive_loop')
    adaptive = bool(adaptive) if isinstance(adaptive, bool) else None
    job, err = arise_jobs.launch_scan(target, source='rescan',
                                      mode=mode, only_modules=only_modules,
                                      adaptive=adaptive)
    if err:
        return jsonify({'error': err}), 400
    return jsonify({'ok': True, 'job': job})


@app.route('/api/jobs')
@login_required
def api_jobs():
    return jsonify({'jobs': arise_jobs.list_jobs()})


@app.route('/api/jobs/<job_id>')
@login_required
def api_job(job_id):
    st = arise_jobs.job_status(job_id)
    if not st:
        return jsonify({'error': 'Job not found.'}), 404
    return jsonify(st)


@app.route('/api/jobs/<job_id>/log')
@login_required
def api_job_log(job_id):
    lines = int(request.args.get('lines', 200))
    return jsonify({'job_id': job_id, 'log': arise_jobs.tail_log(job_id, lines)})


@app.route('/api/jobs/<job_id>/stop', methods=['POST'])
@login_required
def api_job_stop(job_id):
    ok, msg = arise_jobs.stop_job(job_id)
    if not ok:
        return jsonify({'error': msg}), 400
    return jsonify({'ok': True, 'message': msg})


@app.route('/api/jobs/stop-all', methods=['POST'])
@login_required
def api_jobs_stop_all():
    """Emergency stop — terminate every running scan at once."""
    stopped, errors = arise_jobs.stop_all_jobs()
    return jsonify({'ok': not errors, 'stopped': stopped, 'errors': errors})


# ===========================================================================
# SCHEDULES
# ===========================================================================
@app.route('/api/schedules', methods=['GET', 'POST'])
@login_required
def api_schedules():
    if request.method == 'POST':
        payload = request.get_json(silent=True) or {}
        result, err = arise_jobs.set_schedule(
            payload.get('target'),
            (payload.get('frequency') or 'off').strip(),
            (payload.get('cron') or '').strip() or None,
            hour=int(payload.get('hour', 2)),
            minute=int(payload.get('minute', 0)),
            day_of_week=payload.get('day_of_week') or None,
            day_of_month=payload.get('day_of_month') or None,
            run_date=payload.get('run_date') or None,
        )
        if err:
            return jsonify({'error': err}), 400
        return jsonify({'ok': True, 'schedule': result})
    return jsonify({'schedules': arise_jobs.list_schedules()})


# ===========================================================================
# SECRETS VAULT — API keys / Slack webhook (Fernet-encrypted, masked on read)
# ===========================================================================
@app.route('/api/secrets', methods=['GET', 'POST'])
@login_required
def api_secrets():
    if request.method == 'POST':
        payload = request.get_json(silent=True) or {}
        updated = []
        for name in arise_secure.SECRET_ENV_FALLBACKS:
            if name in payload:
                arise_secure.set_secret(name, payload.get(name))
                updated.append(name)
        return jsonify({'ok': True, 'updated': updated, 'status': arise_secure.secret_status()})
    return jsonify({'status': arise_secure.secret_status()})


# ===========================================================================
# GOOGLE DRIVE SYNC (rclone) — config, connectivity test, manual sync
# ===========================================================================
@app.route('/api/drive/config', methods=['GET', 'POST'])
@login_required
def api_drive_config():
    if request.method == 'POST':
        patch = request.get_json(silent=True) or {}
        settings = save_settings({'drive': patch})
        return jsonify({'ok': True, 'drive': settings['drive']})
    cfg = load_settings()['drive']
    return jsonify({
        'drive': cfg,
        'rclone': {
            'installed': arise_drive.rclone_available(),
            'version': arise_drive.rclone_version(),
            'remotes': arise_drive.list_remotes(cfg),
        },
    })


@app.route('/api/drive/test', methods=['POST'])
@login_required
def api_drive_test():
    # Allow testing an unsaved config passed in the body, else use stored config.
    body = request.get_json(silent=True) or {}
    cfg = arise_drive.normalize_config(body) if body else load_settings()['drive']
    ok, msg = arise_drive.test_remote(cfg)
    return jsonify({'ok': ok, 'message': msg})


@app.route('/api/drive/sync', methods=['POST'])
@login_required
def api_drive_sync():
    body = request.get_json(silent=True) or {}
    scan_id = (body.get('scan_id') or '').strip()
    target = (body.get('target') or '').strip()

    if scan_id:
        ids = [scan_id]
    elif target:
        ids = [s['id'] for s in get_scans_for_target(target)]
    else:
        return jsonify({'ok': False, 'error': 'Provide scan_id or target.'}), 400

    results = []
    for sid in ids:
        ok, msg = sync_scan_to_drive(sid, force=True)
        results.append({'scan_id': sid, 'ok': ok, 'message': msg})
    return jsonify({'ok': all(r['ok'] for r in results), 'results': results})


@app.route('/api/drive/status')
@login_required
def api_drive_status():
    """Per-scan sync status (does the folder carry a .drive_synced marker)."""
    cfg = load_settings()['drive']
    scans = get_available_scans(use_cache=False)
    out = [{'scan_id': s['id'], 'target': s.get('target'),
            'synced': arise_drive.is_synced(s['id'], BASE_SCAN_DIR)}
           for s in scans]
    synced = sum(1 for s in out if s['synced'])
    return jsonify({'enabled': cfg['enabled'], 'keep': cfg['keep'],
                    'total': len(out), 'synced': synced, 'scans': out})


# ===========================================================================
# CORRELATION LAYER — Issues, Entities, Timeline (v1.1 spec)
# ===========================================================================

def _build_entities_for_target(target_scan_id):
    """Build the entity index for a scan, using cache if available."""
    scan_dir = os.path.join(BASE_SCAN_DIR, target_scan_id)
    entities, relations = kaiju_entities.load_entity_index(scan_dir)
    if entities is not None:
        return entities, relations
    data = get_cached_scan_data(target_scan_id)
    if not data:
        return [], []
    entities, relations = kaiju_entities.build_entity_index(data, target_scan_id)
    kaiju_entities.save_entity_index(scan_dir, entities, relations)
    return entities, relations


def _run_correlate_for_target(target_scan_id):
    """Full correlate step: build entities, run rules, merge state, emit events."""
    data = get_cached_scan_data(target_scan_id)
    if not data:
        return None
    target = data.get('pipeline_info', {}).get('target', '')
    if not target:
        return None
    entities, relations = _build_entities_for_target(target_scan_id)
    if not entities:
        return None

    # Try to get previous scan entities for new-asset rule
    prev_scan_id = get_previous_scan_id(target_scan_id)
    prev_entities = None
    if prev_scan_id:
        prev_entities, _ = _build_entities_for_target(prev_scan_id)

    computed = kaiju_issues.run_rules(entities, relations, previous_entities=prev_entities)

    # Save field coverage on first run
    scan_dir = os.path.join(BASE_SCAN_DIR, target_scan_id)
    fc_path = os.path.join(scan_dir, '.derived', 'field-coverage.json')
    if not os.path.exists(fc_path):
        audit = kaiju_issues.audit_field_coverage(entities)
        os.makedirs(os.path.dirname(fc_path), exist_ok=True)
        with open(fc_path, 'w') as f:
            json.dump(audit, f, indent=2)

    # Run correlate (INV-2 merge)
    merged, new_state, events = kaiju_issues.correlate(target, target_scan_id, computed)
    kaiju_issues.save_state(target, new_state)

    # Diff against previous revision for timeline events
    if prev_scan_id and prev_entities:
        diff_events = kaiju_issues.diff_revisions(entities, prev_entities, target_scan_id, prev_scan_id)
        events.extend(diff_events)

    kaiju_issues.append_events(target, events, rev=target_scan_id)

    return {
        'target': target, 'scan_id': target_scan_id,
        'issues_created': sum(1 for e in events if e.get('kind') == 'issue_created'),
        'issues_auto_resolved': sum(1 for e in events if e.get('kind') == 'issue_auto_resolved'),
        'total_issues': len(merged),
        'total_events': len(events),
    }


def _enrich_issue_list(merged, entities, scan_id):
    """Attach exploitability-first signals (KEV/EPSS/confidence/SLA/priority) to
    a merged issue list, in place. Offline-safe — never raises into the route."""
    kev_set, epss_map = set(), {}
    try:
        from intel import kev_epss as _ke
        kev_set = _ke.load_kev()
        entity_map = {e.get('ref'): e for e in (entities or [])}
        cand = set()
        for i in merged:
            for c in kaiju_issues._issue_cves(i, entity_map):
                cand.add(c)
        if cand:
            epss_map = _ke.load_epss(cand)
    except Exception:
        logger.exception("issue KEV/EPSS enrichment lookup failed")
    try:
        kaiju_issues.enrich_issues(merged, entities, scan_id, kev_set, epss_map)
    except Exception:
        logger.exception("issue enrichment failed")
    return merged


@app.route('/api/t/<path:target>/issues')
@login_required
def api_issues(target):
    """List issues for a target, filtered and sorted."""
    scan_id = resolve_target(target)
    if not scan_id:
        return jsonify({'items': [], 'counts_by_severity': {}, 'error': 'No scan found.'}), 400

    data = get_cached_scan_data(scan_id)
    actual_target = data.get('pipeline_info', {}).get('target', target) if data else target

    entities, relations = _build_entities_for_target(scan_id)
    prev_scan_id = get_previous_scan_id(scan_id)
    prev_entities = None
    if prev_scan_id:
        prev_entities, _ = _build_entities_for_target(prev_scan_id)

    computed = kaiju_issues.run_rules(entities, relations, previous_entities=prev_entities)
    state = kaiju_issues.load_state(actual_target)
    merged, _, _ = kaiju_issues.correlate(actual_target, scan_id, computed, state=state)
    _enrich_issue_list(merged, entities, scan_id)

    # Filters
    sev_filter = request.args.get('severity', '').lower().split(',')
    sev_filter = [s.strip() for s in sev_filter if s.strip()]
    status_filter = request.args.get('status', '').lower().split(',')
    status_filter = [s.strip() for s in status_filter if s.strip()]
    rule_filter = request.args.get('rule', '').split(',')
    rule_filter = [r.strip() for r in rule_filter if r.strip()]
    search_q = request.args.get('q', '').strip().lower()

    filtered = merged
    if sev_filter:
        filtered = [i for i in filtered if i.get('severity') in sev_filter]
    if status_filter:
        filtered = [i for i in filtered if i.get('status') in status_filter]
    if rule_filter:
        filtered = [i for i in filtered if i.get('rule_id') in rule_filter]
    if search_q:
        def _issue_matches(i, q):
            """Full-text search across all useful issue fields."""
            searchable = ' '.join([
                i.get('title', ''), i.get('ref', ''), i.get('rule_id', ''),
                i.get('severity', ''), i.get('status', ''), i.get('summary_md', ''),
                ' '.join(i.get('affected_assets', [])),
                ' '.join(str(e) for e in i.get('evidence_chain', [])),
                ' '.join(str(e.get('label', '')) for e in i.get('evidence', []) if isinstance(e, dict)),
            ]).lower()
            return all(tok in searchable for tok in q.split())
        filtered = [i for i in filtered if _issue_matches(i, search_q)]

    # Sort — priority_desc (exploitability-first blended rank) is the new default.
    sort = request.args.get('sort', 'priority_desc')
    if sort == 'priority_desc':
        filtered.sort(key=lambda i: i.get('priority', i.get('risk_score', 0)), reverse=True)
    elif sort == 'risk_desc':
        filtered.sort(key=lambda i: i.get('risk_score', 0), reverse=True)
    elif sort == 'newest':
        filtered.sort(key=lambda i: i.get('first_seen_at', ''), reverse=True)
    elif sort == 'severity':
        sev_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        filtered.sort(key=lambda i: sev_order.get(i.get('severity', 'info'), 5))

    # Counts
    counts = {}
    for i in merged:
        s = i.get('severity', 'info')
        counts[s] = counts.get(s, 0) + 1

    return jsonify({'items': filtered, 'counts_by_severity': counts, 'total': len(merged),
                    'summary': kaiju_issues.issue_summary(merged, scan_id)})


@app.route('/api/t/<path:target>/issues/bulk-status', methods=['POST'])
@login_required
def api_bulk_issue_status(target):
    """Bulk update status for multiple issues at once."""
    try:
        scan_id = resolve_target(target)
        if not scan_id:
            return jsonify({'error': 'No scan found.'}), 400
        data = get_cached_scan_data(scan_id)
        actual_target = data.get('pipeline_info', {}).get('target', target) if data else target

        body = request.get_json(force=True) or {}
        refs = body.get('refs', [])
        new_status = body.get('status', '').strip()
        note = body.get('note', '').strip()

        if not refs or not isinstance(refs, list):
            return jsonify({'error': 'refs must be a non-empty list.'}), 400

        valid = {'open', 'acknowledged', 'in_progress', 'resolved', 'false_positive', 'accepted_risk'}
        if new_status not in valid:
            return jsonify({'error': f'Invalid status. Valid: {", ".join(sorted(valid))}'}), 400
        if new_status in ('false_positive', 'accepted_risk') and not note:
            return jsonify({'error': f'A note is required when setting status to {new_status}.'}), 400

        state = kaiju_issues.load_state(actual_target)
        now = datetime.utcnow().isoformat(timespec='seconds') + 'Z'
        user = session.get('user', 'admin')
        updated = []
        skipped = []
        bulk_events = []

        for ref in refs:
            if not ref.startswith('issue:'):
                ref = f'issue:{ref}'
            if ref not in state:
                skipped.append(ref)
                continue
            state[ref]['status'] = new_status
            state[ref].setdefault('history', []).append({
                'at': now, 'event': 'status_changed', 'by': user,
                'note': note, 'new_status': new_status, 'bulk': True,
            })
            bulk_events.append({
                'kind': 'issue_status_changed', 'ref': ref, 'rev': scan_id, 'at': now,
                'detail': {'status': new_status, 'by': user, 'bulk': True},
            })
            updated.append(ref)

        if updated:
            kaiju_issues.save_state(actual_target, state)
            kaiju_issues.append_events(actual_target, bulk_events)

        return jsonify({'ok': True, 'updated': len(updated), 'skipped': len(skipped),
                        'updated_refs': updated, 'skipped_refs': skipped})
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': f'Bulk status update failed: {str(e)}'}), 500


@app.route('/api/t/<path:target>/issues/<path:issue_ref>')
@login_required
def api_issue_detail(target, issue_ref):
    """Get a single issue by ref."""
    scan_id = resolve_target(target)
    if not scan_id:
        return jsonify({'error': 'No scan found.'}), 400
    data = get_cached_scan_data(scan_id)
    actual_target = data.get('pipeline_info', {}).get('target', target) if data else target

    entities, relations = _build_entities_for_target(scan_id)
    computed = kaiju_issues.run_rules(entities, relations)
    state = kaiju_issues.load_state(actual_target)
    merged, _, _ = kaiju_issues.correlate(actual_target, scan_id, computed, state=state)
    _enrich_issue_list(merged, entities, scan_id)

    if not issue_ref.startswith('issue:'):
        issue_ref = f'issue:{issue_ref}'
    for i in merged:
        if i['ref'] == issue_ref:
            return jsonify(i)
    return jsonify({'error': 'Issue not found.'}), 404


@app.route('/api/t/<path:target>/issues/<path:issue_ref>/status', methods=['POST'])
@login_required
def api_issue_status(target, issue_ref):
    """Update issue status (requires note for false_positive/accepted_risk)."""
    scan_id = resolve_target(target)
    if not scan_id:
        return jsonify({'error': 'No scan found.'}), 400
    data = get_cached_scan_data(scan_id)
    actual_target = data.get('pipeline_info', {}).get('target', target) if data else target

    body = request.get_json(force=True) or {}
    new_status = body.get('status', '').strip()
    note = body.get('note', '').strip()

    valid = {'open', 'acknowledged', 'in_progress', 'resolved', 'false_positive', 'accepted_risk'}
    if new_status not in valid:
        return jsonify({'error': f'Invalid status. Valid: {", ".join(sorted(valid))}'}), 400
    if new_status in ('false_positive', 'accepted_risk') and not note:
        return jsonify({'error': f'A note is required when setting status to {new_status}.'}), 400

    if not issue_ref.startswith('issue:'):
        issue_ref = f'issue:{issue_ref}'

    state = kaiju_issues.load_state(actual_target)
    if issue_ref not in state:
        return jsonify({'error': 'Issue not found in state.'}), 404

    now = datetime.utcnow().isoformat(timespec='seconds') + 'Z'
    state[issue_ref]['status'] = new_status
    state[issue_ref].setdefault('history', []).append({
        'at': now, 'event': 'status_changed', 'by': session.get('user', 'admin'),
        'note': note, 'new_status': new_status,
    })
    kaiju_issues.save_state(actual_target, state)
    kaiju_issues.append_events(actual_target, [{
        'kind': 'issue_status_changed', 'ref': issue_ref, 'rev': scan_id, 'at': now,
        'detail': {'status': new_status, 'by': session.get('user', 'admin')},
    }])

    return jsonify({'ok': True, 'ref': issue_ref, 'status': new_status})


@app.route('/api/t/<path:target>/entities/<path:ref>')
@login_required
def api_entity(target, ref):
    """Get a single entity by ref."""
    scan_id = resolve_target(target)
    if not scan_id:
        return jsonify({'error': 'No scan found.'}), 400
    entities, relations = _build_entities_for_target(scan_id)
    entity = kaiju_entities.entity_by_ref(entities, ref)
    if not entity:
        return jsonify({'error': 'Entity not found.'}), 404
    return jsonify(entity)


@app.route('/api/t/<path:target>/entities/<path:ref>/related')
@login_required
def api_entity_related(target, ref):
    """Get related entities within N hops."""
    scan_id = resolve_target(target)
    if not scan_id:
        return jsonify({'error': 'No scan found.'}), 400
    hops = int(request.args.get('hops', 1))
    entities, relations = _build_entities_for_target(scan_id)
    visited_refs, matched_rels = kaiju_entities.related(relations, ref, hops=hops)
    nodes = [e for e in entities if e['ref'] in visited_refs]
    return jsonify({'nodes': nodes, 'edges': matched_rels})


@app.route('/api/t/<path:target>/entities/<path:ref>/issues')
@login_required
def api_entity_issues(target, ref):
    """Get issues affecting an entity."""
    scan_id = resolve_target(target)
    if not scan_id:
        return jsonify({'items': []}), 400
    data = get_cached_scan_data(scan_id)
    actual_target = data.get('pipeline_info', {}).get('target', target) if data else target

    entities, relations = _build_entities_for_target(scan_id)
    computed = kaiju_issues.run_rules(entities, relations)
    state = kaiju_issues.load_state(actual_target)
    merged, _, _ = kaiju_issues.correlate(actual_target, scan_id, computed, state=state)
    _enrich_issue_list(merged, entities, scan_id)

    matching = [i for i in merged if ref in i.get('affected_assets', []) or ref in i.get('evidence_chain', []) or ref in i.get('vuln_refs', [])]
    return jsonify({'items': matching})


@app.route('/api/t/<path:target>/timeline')
@login_required
def api_timeline(target):
    """Get timeline events for a target."""
    scan_id = resolve_target(target)
    if not scan_id:
        return jsonify({'events': [], 'diff_summary': {}}), 400
    data = get_cached_scan_data(scan_id)
    actual_target = data.get('pipeline_info', {}).get('target', target) if data else target

    kind = request.args.get('kind')
    limit = int(request.args.get('limit', 200))
    events = kaiju_issues.load_events(actual_target, kind=kind, limit=limit)

    # Diff summary (counts by kind)
    summary = {}
    for ev in events:
        k = ev.get('kind', 'unknown')
        summary[k] = summary.get(k, 0) + 1

    return jsonify({'events': events, 'diff_summary': summary})


@app.route('/api/t/<path:target>/field-coverage')
@login_required
def api_field_coverage(target):
    """Return the Phase-0 field coverage audit."""
    scan_id = resolve_target(target)
    if not scan_id:
        return jsonify({'error': 'No scan found.'}), 400
    scan_dir = os.path.join(BASE_SCAN_DIR, scan_id)
    fc_path = os.path.join(scan_dir, '.derived', 'field-coverage.json')
    if os.path.exists(fc_path):
        with open(fc_path) as f:
            return jsonify(json.load(f))
    # Generate on demand
    entities, _ = _build_entities_for_target(scan_id)
    audit = kaiju_issues.audit_field_coverage(entities)
    return jsonify(audit)


@app.route('/internal/correlate', methods=['POST'])
def internal_correlate():
    """Pipeline hook: run correlation after a scan completes."""
    body = request.get_json(force=True) or {}
    target_param = body.get('target') or request.args.get('target')
    scan_id = resolve_target(target_param)
    if not scan_id:
        return jsonify({'error': 'No scan found.'}), 400
    result = _run_correlate_for_target(scan_id)
    if not result:
        return jsonify({'error': 'Correlate failed.'}), 500
    return jsonify(result)


# ===========================================================================
# MAIN
# ===========================================================================

if __name__ == '__main__':
    print("=" * 70)
    print("   ARISE EASM v4.0 — Summon Every Hidden Exposure")
    print("=" * 70)
    print()
    
    os.makedirs('templates', exist_ok=True)
    
    if not os.path.exists(BASE_SCAN_DIR):
        os.makedirs(BASE_SCAN_DIR, exist_ok=True)
        print(f"[*] Created scans directory: {BASE_SCAN_DIR}")
    
    scans = get_available_scans()
    print(f"[*] Found {len(scans)} completed scans")

    if scans:
        print("\n[+] Available scans:")
        for scan in scans[:5]:
            print(f"    - {scan['name']} ({scan['id']})")
            print(f"      Hosts: {scan['total_hosts']} | HTTP: {scan['http_hosts']} | Ports: {scan['total_ports']}")

    # --- Auth bootstrap: ensure an admin exists ------------------------------
    _admin_user, _admin_pw = arise_secure.bootstrap_admin()
    if _admin_pw:
        print("\n" + "=" * 70)
        print("   FIRST-RUN LOGIN — an admin account was created:")
        print(f"     username: {_admin_user}")
        print(f"     password: {_admin_pw}")
        print("   Save this now and change it in Settings after logging in.")
        print("   (Set ARISE_ADMIN_USER / ARISE_ADMIN_PASSWORD to choose your own.)")
        print("=" * 70)
    elif _admin_user:
        print(f"[*] Admin account ready: {_admin_user}")

    # --- Scheduler: register recurring scans from schedules.json -------------
    if arise_jobs.init_scheduler():
        _sched = arise_jobs.list_schedules()
        print(f"[*] Scheduler: started ({len(_sched)} recurring target(s))")

    # Warm the data cache for the most-recent scan of each target so the
    # first page load is instant instead of waiting for a full file parse.
    if scans:
        _warmed = set()
        for s in scans:
            tid = s.get('name') or s.get('target') or s.get('id')
            if tid in _warmed:
                continue
            _warmed.add(tid)
            sid = s.get('id')
            if sid:
                try:
                    get_cached_scan_data(sid)
                    print(f"[*] Cache warm: {sid}")
                except Exception as exc:
                    print(f"[!] Cache warm failed for {sid}: {exc}")
            if len(_warmed) >= 5:
                break

    _port = int(os.environ.get('ARISE_DASHBOARD_PORT', 5000))
    _host = os.environ.get('ARISE_DASHBOARD_HOST', '0.0.0.0')
    # Debug (Werkzeug interactive debugger) is OFF unless explicitly requested —
    # it allows arbitrary code execution via the in-browser console. Previously
    # this was hardcoded debug=True alongside host='0.0.0.0', i.e. shipped as an
    # RCE reachable from the network by default (F01 in ARISE_REMEDIATION_ROADMAP.md).
    _debug = os.environ.get('ARISE_DASHBOARD_DEBUG', '').strip().lower() in ('1', 'true', 'yes')
    if _debug and _host not in ('127.0.0.1', 'localhost', '::1'):
        print(f"[!] ARISE_DASHBOARD_DEBUG=1 with ARISE_DASHBOARD_HOST={_host} would expose the")
        print(f"    Werkzeug interactive debugger (arbitrary code execution) to the network.")
        print(f"    Refusing — binding to 127.0.0.1 instead. Set ARISE_DASHBOARD_HOST=127.0.0.1")
        print(f"    explicitly (in addition to DEBUG=1) if this is genuinely intended.")
        _host = '127.0.0.1'

    print()
    print("Dashboard running at:")
    print(f"  http://localhost:{_port}" if _host in ('0.0.0.0', '127.0.0.1', 'localhost') else f"  http://{_host}:{_port}")
    print()
    print("Press Ctrl+C to stop")
    print()

    # Watch for newly completed scans and auto-post AI summaries to Slack.
    _settings = load_settings()
    print(f"[*] AI: provider={_settings['provider']} | auto-Slack={'on' if _settings['auto_slack'] else 'off'} "
          f"| Slack webhook={'set' if _slack_webhook() else 'unset'}")
    start_ai_watcher()

    if _debug:
        print("[*] Mode: DEVELOPMENT (Werkzeug debug server — interactive debugger enabled)")
        app.run(host=_host, port=_port, debug=True, use_reloader=False)
    else:
        try:
            from waitress import serve as _waitress_serve
            _threads = int(os.environ.get('ARISE_DASHBOARD_THREADS', 8))
            print(f"[*] Mode: PRODUCTION (waitress WSGI server, {_threads} threads, debug off)")
            _waitress_serve(app, host=_host, port=_port, threads=_threads)
        except ImportError:
            print("[!] waitress not installed (pip3 install waitress, or `pip3 install -r")
            print("    requirements.txt`) — falling back to Flask's built-in server with debug=False.")
            print("    Fine for local single-analyst use; install waitress before exposing this")
            print("    dashboard beyond localhost.")
            app.run(host=_host, port=_port, debug=False, use_reloader=False)
