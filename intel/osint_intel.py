#!/usr/bin/env python3
"""ARISE OSINT & Human Exposure Intelligence — Module 18.

Passive, publicly-available-information (PAI) attack-surface intelligence for
authorised external attack-surface management (EASM). This engine complements
the active recon pipeline with the *observable-from-the-outside* exposures an
attacker could enumerate without ever touching the target: brand abuse, leaked
credentials, third-party/supply-chain dependencies, internet-wide exposure,
public code, and human/organisational footprint.

Scope & ethics
--------------
Everything here is strictly **passive and public**. The engine:

  * queries only reputable public sources (Certificate Transparency, Shodan
    InternetDB, dnstwist DNS lookups) and, when API keys are configured,
    legitimate breach/threat-intel services (HIBP, IntelX, LeakCheck) and the
    GitHub code-search API;
  * performs **no** authentication, credential testing, exploitation, or
    scraping of illegal dark-web markets;
  * degrades gracefully — a missing tool or API key produces a "not configured"
    status finding, never a failure and never fabricated data.

It ingests recon already collected on disk by earlier pipeline modules —

    * 03b_dns_discovery/dns_all_records.json      (CNAME / MX / NS / TXT chains)
    * 04_http_discovery/http_confirmed.json       (httpx tech fingerprints)
    * 09_crawling/*                               (emails harvested from pages)
    * 16_api_security / 20_api_deep_discovery     (public API documentation)
    * manifest.json                               (per-host resolved IPs / tech)

— then runs the public-source collectors below and writes:

    18_osint_intel/osint_findings.jsonl   (one finding per line)
    18_osint_intel/osint_summary.json     (category matrix + exposure score)
    state/<domain>/osint_baseline.json    (continuous-monitoring snapshot)

Taxonomy (category → what it surfaces):
    organization       · WHOIS/RDAP registrant, registrar, expiry (free)
    brand              · typosquatting / phishing lookalikes (dnstwist)
    certificate        · TLS certs, SANs, related domains (CT logs)
    supply_chain       · third-party vendors / SaaS dependencies (DNS + tech)
    internet_exposure  · publicly reachable services (Shodan InternetDB)
    email_exposure     · public email inventory + address format (defensive)
    breach             · credential exposure / dark-web monitoring (keyed)
    ransomware         · extortion leak-site victim listings (free tracker)
    code_exposure      · public repos / leaked keys (GitHub, keyed)
    api_docs           · public Swagger / OpenAPI / GraphQL documentation
    recruitment        · job postings revealing org structure + tech stack
    mobile_app         · App Store presence + metadata (iTunes Search API)
    public_documents   · metadata leakage in publicly crawled documents
    news_media         · recent coverage: M&A, incidents, layoffs (free RSS)
    social             · official corporate social presence

Every collector is best-effort and independent — a failed or unreachable
source degrades to an informational "not configured/unavailable" finding and
never blocks the rest of the run. A lightweight Threat-Intelligence
Correlation step blends this passive score with the active-scan vulnerability
count already in manifest.json, and an Executive Summary synthesises both
into one plain-language paragraph for the dashboard.
"""

from __future__ import annotations

import sys as _sys, os as _os
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)


import argparse
import json
import os
import re
import socket
import ssl
import time
import subprocess
import sys
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Taxonomy + risk model
# ---------------------------------------------------------------------------

CATEGORIES = [
    "organization", "brand", "certificate", "supply_chain", "internet_exposure",
    "email_exposure", "breach", "ransomware", "code_exposure", "api_docs",
    "recruitment", "mobile_app", "public_documents", "news_media", "social",
    "ad_fraud", "malicious_landing", "gov_injection", "takeover",
]

CATEGORY_LABELS = {
    "organization": "Organization Discovery",
    "brand": "Brand Monitoring",
    "certificate": "Certificate Intelligence",
    "supply_chain": "Third-Party & Supply Chain",
    "internet_exposure": "Internet-Wide Exposure",
    "email_exposure": "Public Email / Human Exposure",
    "breach": "Credential & Dark-Web Exposure",
    "ransomware": "Ransomware & Extortion Listings",
    "code_exposure": "Public Code Exposure",
    "api_docs": "Public API Documentation",
    "recruitment": "Recruitment Intelligence",
    "mobile_app": "Mobile App Intelligence",
    "public_documents": "Public Document Analysis",
    "news_media": "News & Media",
    "social": "Social & Media Presence",
    "ad_fraud": "Ad & Brand Impersonation",
    "malicious_landing": "Malicious Landing Pages",
    "gov_injection": "Government Site Injection",
    "takeover": "Subdomain Takeover",
}

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
SEVERITY_WEIGHT = {"critical": 40, "high": 20, "medium": 8, "low": 2, "info": 0}

USER_AGENT = "ARISE-OSINT/1.0 (+authorised EASM assessment)"
HTTP_TIMEOUT = 15

# Retry policy. Collectors run serially, so retries are deliberately shallow —
# 2 extra attempts with short backoff recovers the common case (crt.sh 502s,
# transient DNS) without letting one dead source stall the whole scan.
HTTP_RETRIES = 2          # extra attempts after the first
RETRY_BACKOFF = 1.5       # seconds; doubles each attempt
RETRY_MAX_WAIT = 20.0     # ceiling for any single sleep, incl. Retry-After

# Subdomain-takeover probing. Bounded tightly because collectors run serially:
# every second here delays every later category.
TAKEOVER_PROBE_CAP = 25       # max delegated hosts probed per run
TAKEOVER_PROBE_TIMEOUT = 8    # seconds per host

# Build a verified SSL context from certifi's CA bundle rather than trusting
# the interpreter's default OpenSSL cert path — some Python.org macOS builds
# ship without running "Install Certificates.command", which leaves the
# default context unable to verify ANY public HTTPS endpoint. certifi is a
# transitive dependency of `requests` and is portable across OSes, so this
# fixes the common case without ever disabling certificate verification.
try:
    import certifi
    _SSL_CONTEXT = ssl.create_default_context(cafile=certifi.where())
except Exception:
    _SSL_CONTEXT = ssl.create_default_context()

# GUI-managed encrypted secret vault (dashboard.py Settings → API Keys). Import
# is optional — this engine also runs as a bare standalone script with only
# .env/environment variables, e.g. outside the full ARISE checkout. Python
# already puts this script's own directory on sys.path, where arise_secure.py
# lives, so no path manipulation is needed.
try:
    import core.arise_secure as arise_secure
except Exception:
    arise_secure = None


def _resolve_key(name: str, *env_aliases: str) -> str:
    """Vault first (sourced from the dashboard's Settings panel), then the
    environment/.env under `name` and any legacy aliases."""
    if arise_secure is not None:
        try:
            val = arise_secure.resolve_secret(name)
            if val:
                return val.strip()
        except Exception:
            pass
    for env in (name, *env_aliases):
        val = os.environ.get(env, "").strip()
        if val:
            return val
    return ""


def _retry_after_seconds(headers) -> Optional[float]:
    """Parse a Retry-After header (delta-seconds or HTTP-date) into seconds.

    Returns None when absent or unparseable so the caller falls back to its
    own backoff. Negative/past dates clamp to 0.
    """
    raw = None
    try:
        raw = headers.get("Retry-After")
    except Exception:
        return None
    if not raw:
        return None
    raw = str(raw).strip()
    try:
        return max(0.0, float(raw))
    except ValueError:
        pass
    try:
        from email.utils import parsedate_to_datetime
        when = parsedate_to_datetime(raw)
        if when is None:
            return None
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        return max(0.0, (when - datetime.now(timezone.utc)).total_seconds())
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Third-party / supply-chain vendor fingerprint database
#
# Maps a substring token (found in a CNAME target, MX host, NS host, SPF/TXT
# include, or httpx tech string) to the vendor and the class of dependency it
# represents. This is how the outside world infers an organisation's supply
# chain with zero packets to the target.
# ---------------------------------------------------------------------------

# (token, vendor, kind)
VENDOR_SIGNATURES: List[Tuple[str, str, str]] = [
    # --- Cloud providers ---
    ("amazonaws.com", "Amazon Web Services", "cloud"),
    ("cloudfront.net", "AWS CloudFront", "cdn"),
    ("elb.amazonaws.com", "AWS Elastic Load Balancing", "cloud"),
    ("awsdns", "AWS Route 53", "dns"),
    ("azure", "Microsoft Azure", "cloud"),
    ("azureedge.net", "Azure CDN", "cdn"),
    ("azurewebsites.net", "Azure App Service", "cloud"),
    ("windows.net", "Microsoft Azure", "cloud"),
    ("googleusercontent.com", "Google Cloud", "cloud"),
    ("googlehosted.com", "Google Cloud", "cloud"),
    ("appspot.com", "Google App Engine", "cloud"),
    ("run.app", "Google Cloud Run", "cloud"),
    ("gcp", "Google Cloud", "cloud"),
    ("digitaloceanspaces.com", "DigitalOcean", "cloud"),
    ("herokuapp.com", "Heroku", "cloud"),
    ("herokudns.com", "Heroku", "cloud"),
    ("oraclecloud.com", "Oracle Cloud", "cloud"),
    # --- CDN / WAF / edge ---
    ("cloudflare", "Cloudflare", "cdn_waf"),
    ("cloudflare.net", "Cloudflare", "cdn_waf"),
    ("fastly", "Fastly", "cdn"),
    ("akamai", "Akamai", "cdn"),
    ("akamaiedge.net", "Akamai", "cdn"),
    ("edgekey.net", "Akamai", "cdn"),
    ("edgesuite.net", "Akamai", "cdn"),
    ("incapdns.net", "Imperva Incapsula", "cdn_waf"),
    ("impervadns", "Imperva", "cdn_waf"),
    ("sucuri.net", "Sucuri", "cdn_waf"),
    ("stackpathdns.com", "StackPath", "cdn"),
    ("cdn77", "CDN77", "cdn"),
    ("bunnycdn", "BunnyCDN", "cdn"),
    ("netlify", "Netlify", "hosting"),
    ("vercel", "Vercel", "hosting"),
    ("github.io", "GitHub Pages", "hosting"),
    ("pages.dev", "Cloudflare Pages", "hosting"),
    ("wpengine.com", "WP Engine", "hosting"),
    # --- Email providers / deliverability ---
    ("google.com", "Google Workspace", "email"),
    ("googlemail.com", "Google Workspace", "email"),
    ("aspmx.l.google.com", "Google Workspace", "email"),
    ("outlook.com", "Microsoft 365", "email"),
    ("protection.outlook.com", "Microsoft 365 / EOP", "email"),
    ("pphosted.com", "Proofpoint", "email_security"),
    ("mimecast", "Mimecast", "email_security"),
    ("messagelabs.com", "Symantec MessageLabs", "email_security"),
    ("zoho", "Zoho Mail", "email"),
    ("sendgrid", "SendGrid", "email_marketing"),
    ("mailgun", "Mailgun", "email_marketing"),
    ("mandrillapp.com", "Mailchimp Mandrill", "email_marketing"),
    ("mcsv.net", "Mailchimp", "email_marketing"),
    ("amazonses.com", "Amazon SES", "email_marketing"),
    ("sparkpost", "SparkPost", "email_marketing"),
    ("postmarkapp.com", "Postmark", "email_marketing"),
    ("_spf.salesforce.com", "Salesforce", "crm"),
    ("hubspot", "HubSpot", "marketing"),
    ("marketo", "Marketo", "marketing"),
    ("pardot", "Salesforce Pardot", "marketing"),
    ("intercom", "Intercom", "support"),
    ("zendesk", "Zendesk", "support"),
    ("freshdesk", "Freshworks", "support"),
    ("desk.com", "Salesforce Desk", "support"),
    ("helpscout", "Help Scout", "support"),
    # --- Identity / auth ---
    ("okta.com", "Okta", "identity"),
    ("auth0.com", "Auth0", "identity"),
    ("onelogin.com", "OneLogin", "identity"),
    ("pingidentity", "Ping Identity", "identity"),
    ("duosecurity.com", "Cisco Duo", "identity"),
    ("jumpcloud", "JumpCloud", "identity"),
    # --- Payments ---
    ("stripe.com", "Stripe", "payments"),
    ("braintreegateway.com", "Braintree", "payments"),
    ("paypal.com", "PayPal", "payments"),
    ("adyen.com", "Adyen", "payments"),
    ("razorpay", "Razorpay", "payments"),
    ("squareup.com", "Square", "payments"),
    # --- HR / recruitment ---
    ("greenhouse.io", "Greenhouse", "hr"),
    ("lever.co", "Lever", "hr"),
    ("workday", "Workday", "hr"),
    ("bamboohr", "BambooHR", "hr"),
    ("myworkday.com", "Workday", "hr"),
    ("icims.com", "iCIMS", "hr"),
    ("ashbyhq.com", "Ashby", "hr"),
    ("smartrecruiters", "SmartRecruiters", "hr"),
    # --- Source code / CI/CD / dev ---
    ("github.com", "GitHub", "source_code"),
    ("gitlab", "GitLab", "source_code"),
    ("bitbucket", "Atlassian Bitbucket", "source_code"),
    ("atlassian.net", "Atlassian", "dev_tools"),
    ("circleci", "CircleCI", "cicd"),
    ("travis-ci", "Travis CI", "cicd"),
    ("jenkins", "Jenkins", "cicd"),
    ("readthedocs", "Read the Docs", "dev_tools"),
    ("statuspage.io", "Atlassian Statuspage", "status"),
    ("pagerduty", "PagerDuty", "monitoring"),
    ("opsgenie", "Atlassian Opsgenie", "monitoring"),
    # --- Analytics / monitoring / marketing ---
    ("google-analytics", "Google Analytics", "analytics"),
    ("googletagmanager", "Google Tag Manager", "analytics"),
    ("segment.com", "Segment", "analytics"),
    ("mixpanel", "Mixpanel", "analytics"),
    ("amplitude", "Amplitude", "analytics"),
    ("hotjar", "Hotjar", "analytics"),
    ("datadog", "Datadog", "monitoring"),
    ("newrelic", "New Relic", "monitoring"),
    ("sentry.io", "Sentry", "monitoring"),
    ("nr-data.net", "New Relic", "monitoring"),
    ("optimizely", "Optimizely", "marketing"),
    ("cdn.shopify.com", "Shopify", "ecommerce"),
    ("myshopify.com", "Shopify", "ecommerce"),
    ("wixdns.net", "Wix", "hosting"),
    ("squarespace.com", "Squarespace", "hosting"),
    ("zohohost", "Zoho", "saas"),
    # --- DNS / security vendors ---
    ("nsone.net", "NS1", "dns"),
    ("dnsmadeeasy", "DNS Made Easy", "dns"),
    ("ultradns", "UltraDNS", "dns"),
    ("dyn.com", "Oracle Dyn", "dns"),
    ("cscdns.net", "CSC", "dns"),
    ("markmonitor", "MarkMonitor", "brand_protection"),
    ("_dmarc", "DMARC record", "email_security"),
]

# Technology / infrastructure buzzwords surfaced in job-posting descriptions —
# distinct from VENDOR_SIGNATURES (which fingerprints DNS/tech evidence): this
# list is about what an org *says* it uses, not what a scanner *observed*.
TECH_KEYWORDS = [
    "aws", "amazon web services", "gcp", "google cloud", "azure", "kubernetes",
    "k8s", "docker", "terraform", "ansible", "jenkins", "circleci", "github actions",
    "kafka", "rabbitmq", "sqs", "redis", "memcached", "elasticsearch", "opensearch",
    "postgres", "postgresql", "mysql", "mongodb", "dynamodb", "cassandra", "snowflake",
    "bigquery", "redshift", "spark", "hadoop", "airflow", "react", "angular", "vue",
    "node.js", "nodejs", "django", "flask", "fastapi", "spring boot", "rails", ".net",
    "golang", "python", "java", "typescript", "graphql", "grpc", "microservices",
    "istio", "envoy", "datadog", "new relic", "grafana", "prometheus", "splunk",
    "okta", "auth0", "stripe api", "twilio", "segment", "salesforce",
]

VENDOR_KIND_LABELS = {
    "cloud": "Cloud Provider",
    "cdn": "CDN / Edge",
    "cdn_waf": "CDN / WAF",
    "hosting": "Hosting / PaaS",
    "email": "Email Provider",
    "email_security": "Email Security Gateway",
    "email_marketing": "Email / Marketing Delivery",
    "crm": "CRM",
    "marketing": "Marketing Platform",
    "support": "Customer Support",
    "identity": "Identity Provider",
    "payments": "Payment Processor",
    "hr": "HR / Recruitment",
    "source_code": "Source-Code Hosting",
    "cicd": "CI/CD Platform",
    "dev_tools": "Developer Tooling",
    "status": "Status Page",
    "monitoring": "Monitoring / Observability",
    "analytics": "Analytics",
    "ecommerce": "E-commerce Platform",
    "saas": "SaaS",
    "dns": "DNS Provider",
    "brand_protection": "Brand Protection",
}


# ---------------------------------------------------------------------------
# Finding model
# ---------------------------------------------------------------------------

@dataclass
class OsintFinding:
    category: str
    title: str
    subject: str                      # the entity: a domain, email, IP, vendor…
    severity: str = "info"
    confidence: str = "medium"        # high | medium | low
    source: str = ""                  # where the signal came from
    evidence: str = ""                # concrete data that triggered it
    risk: str = ""                    # what an attacker/defender should know
    recommendation: str = ""          # defensive action
    meta: dict = field(default_factory=dict)
    first_seen: str = ""
    is_new: bool = False              # new since last monitoring baseline

    @property
    def category_label(self) -> str:
        return CATEGORY_LABELS.get(self.category, self.category)

    def key(self) -> str:
        return f"{self.category}|{self.subject.lower().strip()}"


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class OsintIntel:
    def __init__(self, scan_dir: Path, domain: str = "", active: bool = False,
                 offline: bool = False, verbose: bool = False):
        self.scan_dir = Path(scan_dir)
        self.domain = (domain or self._derive_domain()).lower().strip()
        self.active = active
        self.offline = offline
        self.verbose = verbose
        self.findings: Dict[str, OsintFinding] = {}
        self.now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        # ingested recon
        self.dns_records: dict = {}
        self.hosts: dict = {}
        self.resolved_ips: set = set()
        self.emails: set = set()
        self.retry_count = 0        # transport retries across the whole run
        self._fingerprints: dict = {}   # takeover fingerprints, lazily fetched
        self._fingerprint_source = ""
        # Connector config — the encrypted GUI vault (arise_secure.py) wins when
        # a key has been set from the dashboard's Settings panel; otherwise
        # falls back to the environment/.env, so this engine also runs
        # standalone (no dashboard/vault) with no behaviour change.
        self.cfg = {
            "hibp": _resolve_key("HIBP_API_KEY"),
            "intelx": _resolve_key("INTELX_API_KEY"),
            "leakcheck": _resolve_key("LEAKCHECK_API_KEY"),
            "github": _resolve_key("GITHUB_TOKEN", "GITHUB_API_TOKEN"),
            "shodan": _resolve_key("SHODAN_API_KEY"),
            "safebrowsing": _resolve_key("GOOGLE_SAFEBROWSING_KEY"),
            "virustotal": _resolve_key("VIRUSTOTAL_API_KEY"),
            "telegram": _resolve_key("TELEGRAM_BOT_TOKEN"),
            "youtube": _resolve_key("YOUTUBE_API_KEY"),
        }

    # -- utilities --------------------------------------------------------
    def log(self, *a):
        if self.verbose:
            print("[osint]", *a, file=sys.stderr)

    def _derive_domain(self) -> str:
        """Best-effort apex from scan-dir name (e.g. quince.com-140726-0830)."""
        name = self.scan_dir.name
        m = re.match(r"^([a-z0-9.\-]+?)(?:-\d{6}-\d{4})?$", name, re.IGNORECASE)
        cand = m.group(1) if m else name
        # strip a trailing date-ish token if the regex under-matched
        cand = re.sub(r"-\d{6,}.*$", "", cand)
        return cand

    def _load_json(self, rel: str):
        p = self.scan_dir / rel
        if not p.exists():
            return None
        try:
            return json.loads(p.read_text(errors="ignore"))
        except Exception as e:
            self.log(f"load {rel} failed: {e}")
            return None

    def _http_raw(self, url: str, headers: Optional[dict] = None,
                  timeout: int = HTTP_TIMEOUT, accept: str = "application/json",
                  retries: Optional[int] = None, body_on_error: bool = False):
        """GET a URL with bounded retry. Returns (body_text, error_str).

        Retries only what is worth retrying:
          - transient transport faults (timeout, reset, DNS blip)
          - 5xx, and 429 where the server is telling us to slow down
        A 4xx other than 429 is a permanent answer — retrying it only burns
        wall-clock, and this engine runs its collectors serially, so every
        wasted second delays every later collector.

        429 honours Retry-After when the server sends a sane value, otherwise
        falls back to exponential backoff. RETRY_MAX_WAIT caps any single
        sleep so a hostile/misconfigured header cannot stall the scan.

        `retries` overrides the default budget. Pass 0 for bulk probing (many
        hosts, each individually unimportant): retrying N hosts multiplies
        wall-clock by the retry count for no analytic gain, because a host
        that does not answer is simply skipped either way. Retries are for
        single authoritative sources whose loss would empty a category.

        `body_on_error` returns the response body for 4xx/5xx instead of
        discarding it. Required for takeover fingerprinting: providers serve
        their unclaimed-resource page *with* a 404 ("There isn't a GitHub
        Pages site here"), so the status code is the least interesting part
        of the response and the body is the whole signal.
        """
        if self.offline:
            return None, "offline"
        budget = HTTP_RETRIES if retries is None else max(0, retries)
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT,
                                                   "Accept": accept,
                                                   **(headers or {})})
        last_err = "unknown error"
        for attempt in range(budget + 1):
            try:
                with urllib.request.urlopen(req, timeout=timeout,
                                            context=_SSL_CONTEXT) as r:
                    return r.read().decode("utf-8", errors="ignore"), None
            except urllib.error.HTTPError as e:
                last_err = f"http {e.code}"
                if body_on_error and e.code not in (429,) and not (500 <= e.code < 600):
                    try:
                        return e.read().decode("utf-8", errors="ignore"), None
                    except Exception:
                        return None, last_err
                if e.code == 429:
                    wait = _retry_after_seconds(e.headers) if e.headers else None
                    if wait is None:
                        wait = RETRY_BACKOFF * (2 ** attempt)
                elif 500 <= e.code < 600:
                    wait = RETRY_BACKOFF * (2 ** attempt)
                else:
                    return None, last_err          # permanent — do not retry
            except Exception as e:
                last_err = str(e)[:120]
                wait = RETRY_BACKOFF * (2 ** attempt)

            if attempt >= budget:
                break
            wait = min(wait, RETRY_MAX_WAIT)
            self.log(f"retry {attempt + 1}/{budget} in {wait:.1f}s "
                     f"({last_err}) {url[:80]}")
            self.retry_count += 1
            time.sleep(wait)
        return None, last_err

    def _http_json(self, url: str, headers: Optional[dict] = None,
                   timeout: int = HTTP_TIMEOUT):
        """GET a URL and parse JSON. Returns (data, error_str)."""
        body, err = self._http_raw(url, headers=headers, timeout=timeout)
        if err:
            return None, err
        if body is None or not body.strip():
            return None, None
        try:
            return json.loads(body), None
        except Exception as e:
            return None, f"bad json: {str(e)[:80]}"

    def _http_text(self, url: str, headers: Optional[dict] = None,
                   timeout: int = HTTP_TIMEOUT, retries: Optional[int] = None,
                   body_on_error: bool = False):
        """GET a URL as text (HTML bodies, CSV indexes). Returns (text, error)."""
        return self._http_raw(url, headers=headers, timeout=timeout,
                              accept="text/html,application/xhtml+xml,*/*",
                              retries=retries, body_on_error=body_on_error)

    def _add(self, f: OsintFinding):
        f.first_seen = f.first_seen or self.now
        existing = self.findings.get(f.key())
        if existing is None or SEVERITY_RANK[f.severity] > SEVERITY_RANK[existing.severity]:
            self.findings[f.key()] = f

    # ================================================================
    # INGEST — read what earlier pipeline modules already collected
    # ================================================================
    def ingest(self):
        dns = self._load_json("03b_dns_discovery/dns_all_records.json")
        if isinstance(dns, dict):
            self.dns_records = dns

        manifest = self._load_json("manifest.json")
        if isinstance(manifest, dict):
            self.hosts = manifest.get("hosts", {}) or {}
            for host, hd in self.hosts.items():
                ip = (hd or {}).get("ip")
                if ip and _is_ip(ip):
                    self.resolved_ips.add(ip)

        # harvest email addresses from crawl output + any text artifacts
        self._ingest_emails()
        self.log(f"ingested: {len(self.hosts)} hosts, "
                 f"{len(self.resolved_ips)} IPs, {len(self.dns_records)} dns rows, "
                 f"{len(self.emails)} emails")

    def _ingest_emails(self):
        email_re = re.compile(
            r"[a-z0-9._%+\-]+@" + re.escape(self.domain), re.IGNORECASE)
        # crawl output + any harvested text under the scan
        for rel in ("09_crawling", "10_secret_scanning"):
            d = self.scan_dir / rel
            if not d.is_dir():
                continue
            for p in list(d.rglob("*"))[:400]:
                if not p.is_file() or p.stat().st_size > 5_000_000:
                    continue
                try:
                    txt = p.read_text(errors="ignore")
                except Exception:
                    continue
                for m in email_re.findall(txt):
                    self.emails.add(m.lower())

    # ================================================================
    # COLLECTORS
    # ================================================================

    # -- Certificate / passive-DNS name discovery (multi-source) ----------
    #
    # crt.sh is the best single CT source but is also frequently slow or
    # 502-ing. Relying on it alone meant one bad day produced an empty
    # certificate category that read as "clean". These sources are queried
    # independently and unioned: any one succeeding still yields discovery,
    # and per-source status is recorded so partial coverage is visible.
    # All are free and require no API key.

    def _src_crtsh(self) -> Tuple[Optional[set], dict, bool, Optional[str]]:
        """crt.sh — full CT log search. Returns (names, issuers, wildcard, err)."""
        url = f"https://crt.sh/?q=%25.{urllib.parse.quote(self.domain)}&output=json"
        data, err = self._http_json(url, timeout=25)
        if err:
            return None, {}, False, err
        if not isinstance(data, list):
            return None, {}, False, "unexpected response shape"
        names: set = set()
        issuers: dict = {}
        wildcard = False
        for row in data:
            raw = str(row.get("name_value", ""))
            if raw.strip().startswith("*."):
                wildcard = True
            for nm in raw.splitlines():
                nm = nm.strip().lower().lstrip("*.")
                if nm:
                    names.add(nm)
            m = re.search(r"O=([^,]+)", str(row.get("issuer_name", "")))
            if m:
                key = m.group(1).strip()
                issuers[key] = issuers.get(key, 0) + 1
        return names, issuers, wildcard, None

    def _src_certspotter(self) -> Tuple[Optional[set], Optional[str]]:
        """SSLMate Cert Spotter — CT log API, free tier without a key."""
        url = ("https://api.certspotter.com/v1/issuances?"
               + urllib.parse.urlencode({
                   "domain": self.domain,
                   "include_subdomains": "true",
                   "expand": "dns_names",
               }))
        data, err = self._http_json(url, timeout=20)
        if err:
            return None, err
        if not isinstance(data, list):
            return None, "unexpected response shape"
        names: set = set()
        for row in data:
            for nm in (row.get("dns_names") or []):
                nm = str(nm).strip().lower().lstrip("*.")
                if nm:
                    names.add(nm)
        return names, None

    def _src_otx(self) -> Tuple[Optional[set], Optional[str]]:
        """AlienVault OTX passive DNS — names actually observed resolving."""
        url = ("https://otx.alienvault.com/api/v1/indicators/domain/"
               f"{urllib.parse.quote(self.domain)}/passive_dns")
        data, err = self._http_json(url, timeout=20)
        if err:
            return None, err
        if not isinstance(data, dict):
            return None, "unexpected response shape"
        names: set = set()
        for row in (data.get("passive_dns") or []):
            nm = str(row.get("hostname", "")).strip().lower().lstrip("*.")
            if nm:
                names.add(nm)
        return names, None

    def _src_rapiddns(self) -> Tuple[Optional[set], Optional[str]]:
        """RapidDNS — HTML subdomain index. No API, so this scrapes the results
        table and then *checks its own work*.

        Scraping is only acceptable here because the page states how many
        subdomains it holds ("Found N subdomains"). We parse the table cells
        and compare against that number: if we recovered materially less than
        the page claims (markup changed, results paginated, bot-walled), we
        return an error instead of a short list. Silently handing back 4 names
        when the source has 92 would manufacture exactly the false-clean this
        engine is meant to eliminate.
        """
        url = f"https://rapiddns.io/subdomain/{urllib.parse.quote(self.domain)}?full=1"
        body, err = self._http_text(url, timeout=20)
        if err:
            return None, err
        if not body:
            return None, "empty response"

        # First cell of each result row holds the hostname.
        cells = re.findall(r"<td>\s*([A-Za-z0-9._\-]+)\s*</td>", body)
        names = {c.lower().lstrip("*.") for c in cells
                 if c.lower().endswith(self.domain)}

        claimed_m = re.search(r"Found\s+([\d,]+)\s+subdomains", body, re.I)
        if claimed_m:
            claimed = int(claimed_m.group(1).replace(",", ""))
            # Tolerate a small gap (dedup, apex row), reject a large one.
            if claimed > 5 and len(names) < claimed * 0.5:
                return None, (f"parsed {len(names)} of {claimed} advertised "
                              f"subdomains — markup likely changed or results "
                              f"are paginated; treating as unreliable")
        if not names:
            return None, "no parseable rows"
        return names, None

    def collect_certificates(self):
        if not self.domain:
            return

        names: set = set()
        issuers: dict = {}
        wildcard = False
        per_source: dict = {}      # source -> count or error string
        ok_sources: List[str] = []
        failed_sources: List[str] = []

        ct_names, issuers, wildcard, ct_err = self._src_crtsh()
        if ct_err:
            per_source["crt.sh"] = f"failed: {ct_err}"
            failed_sources.append(f"crt.sh ({ct_err})")
        else:
            names |= (ct_names or set())
            per_source["crt.sh"] = len(ct_names or ())
            ok_sources.append("crt.sh")

        for label, fn in (("Cert Spotter", self._src_certspotter),
                          ("AlienVault OTX", self._src_otx),
                          ("RapidDNS", self._src_rapiddns)):
            got, err = fn()
            if err:
                per_source[label] = f"failed: {err}"
                failed_sources.append(f"{label} ({err})")
                continue
            got = {n for n in (got or set())
                   if n.endswith(self.domain) or n == self.domain}
            names |= got
            per_source[label] = len(got)
            ok_sources.append(label)

        # Every source failed — say so rather than implying an empty CT record.
        if not ok_sources:
            self._add(OsintFinding(
                category="certificate",
                title="Certificate Transparency lookup unavailable (all sources)",
                subject=self.domain, severity="info", confidence="high",
                source="crt.sh + Cert Spotter + OTX + RapidDNS",
                evidence="; ".join(failed_sources),
                risk="CT/passive-DNS enumeration could not run against any "
                     "source, so shadow-asset discovery did NOT happen on this "
                     "run. An empty result here means 'not checked', not 'none'.",
                recommendation="Retry when network access is available; if this "
                               "persists, check egress filtering to crt.sh, "
                               "api.certspotter.com, otx.alienvault.com.",
                meta={"sources": per_source}))
            return

        if failed_sources:
            self._connector_status(
                "certificate", "CT / passive-DNS sources", True,
                f"{len(ok_sources)} of {len(ok_sources) + len(failed_sources)} "
                f"sources answered ({', '.join(ok_sources)}); failed: "
                f"{'; '.join(failed_sources)} — name discovery is partial.")

        # subdomains not already known from active recon → new attack surface
        known = {h.lower() for h in self.hosts}
        new_names = sorted(n for n in names if n.endswith(self.domain) and n not in known)
        src_summary = ", ".join(
            f"{k}={v}" for k, v in per_source.items() if isinstance(v, int))
        self._add(OsintFinding(
            category="certificate",
            title=f"{len(names)} names across CT logs & passive DNS",
            subject=self.domain, severity="info", confidence="high",
            source=" + ".join(ok_sources),
            evidence=f"{len(names)} unique hostnames from {len(ok_sources)} "
                     f"source(s) [{src_summary}]"
                     + ("; top issuer(s): "
                        + ", ".join(f"{k} ({v})" for k, v in
                                    sorted(issuers.items(), key=lambda x: -x[1])[:3])
                        if issuers else ""),
            risk="CT logs publicly reveal every certificate — including internal "
                 "and staging hostnames — the moment it is issued. Passive DNS "
                 "additionally records names that actually resolved.",
            recommendation="Review discovered hostnames for unintended exposure; "
                            "consider wildcard certs to reduce hostname leakage.",
            meta={"total_names": len(names), "wildcard": wildcard,
                  "issuers": issuers, "sources": per_source,
                  "names": sorted(names)[:400]}))

        if new_names:
            self._add(OsintFinding(
                category="certificate",
                title=f"{len(new_names)} hostnames seen only in CT/passive DNS",
                subject=f"{self.domain}:ct-shadow", severity="low", confidence="medium",
                source=" + ".join(ok_sources),
                evidence="e.g. " + ", ".join(new_names[:12])
                         + (" …" if len(new_names) > 12 else ""),
                risk="These names appear in issued certificates or passive-DNS "
                     "records but were not found by active subdomain "
                     "enumeration — potential shadow assets.",
                recommendation="Confirm ownership and bring these hosts into scope "
                               "for scanning.",
                meta={"names": new_names[:400], "sources": per_source,
                      "total_new": len(new_names)}))

    # -- Brand Monitoring (dnstwist) -------------------------------------
    def collect_brand(self):
        if not self.domain or self.offline:
            if self.offline:
                self._connector_status("brand", "dnstwist", False,
                                       "offline mode — brand monitoring skipped")
            return
        rows = self._run_dnstwist()
        if rows is None:
            self._connector_status(
                "brand", "dnstwist", False,
                "dnstwist not installed (pip install dnstwist)")
            return

        registered = [r for r in rows
                      if r.get("domain", "").lower() != self.domain
                      and (r.get("dns_a") or r.get("dns_ns") or r.get("dns_mx"))]
        self._add(OsintFinding(
            category="brand",
            title=f"{len(registered)} registered look-alike domain(s)",
            subject=self.domain,
            severity="high" if len(registered) >= 5 else
                     ("medium" if registered else "info"),
            confidence="high", source="dnstwist",
            evidence=f"{len(rows)} permutations generated, {len(registered)} resolve",
            risk="Registered permutations of your domain can host phishing, "
                 "credential-harvesting, or brand-impersonation pages.",
            recommendation="Triage each look-alike; file takedowns/UDRP for "
                           "malicious ones and defensively register high-risk typos.",
            meta={"registered_count": len(registered),
                  "permutations": len(rows)}))

        for r in registered[:60]:
            dom = r.get("domain", "")
            has_mx = bool(r.get("dns_mx"))
            fuzz = r.get("fuzzer", "")
            sev = "high" if has_mx else "medium"   # MX = ready to receive phishing mail
            self._add(OsintFinding(
                category="brand",
                title=f"Look-alike domain: {dom}",
                subject=dom, severity=sev, confidence="high",
                source=f"dnstwist ({fuzz})",
                evidence="A=" + ",".join(r.get("dns_a", [])[:2])
                         + ("; MX present" if has_mx else "")
                         + ("; NS=" + ",".join(r.get("dns_ns", [])[:1])
                            if r.get("dns_ns") else ""),
                risk=("Domain has mail records — can send/receive phishing mail "
                      "impersonating you." if has_mx else
                      "Registered permutation resolves — possible impersonation host."),
                recommendation="Verify intent; monitor content and certificates; "
                               "action takedown if abusive.",
                meta={"fuzzer": fuzz, "dns_a": r.get("dns_a", []),
                      "dns_mx": r.get("dns_mx", []), "mx": has_mx}))

    def _run_dnstwist(self):
        """Return dnstwist rows (list of dicts) or None if unavailable."""
        cmds = [
            [sys.executable, "-m", "dnstwist", "--format", "json",
             "--registered", self.domain],
            ["dnstwist", "--format", "json", "--registered", self.domain],
        ]
        for cmd in cmds:
            try:
                out = subprocess.run(cmd, capture_output=True, text=True,
                                     timeout=240)
            except FileNotFoundError:
                continue
            except subprocess.TimeoutExpired:
                self.log("dnstwist timed out")
                return []
            if out.returncode == 0 and out.stdout.strip():
                try:
                    return json.loads(out.stdout)
                except Exception:
                    return []
            if out.returncode == 0:
                return []
        return None

    # -- Third-party & Supply-chain mapping ------------------------------
    # -- Subdomain takeover (CNAME-targeted, body-fingerprinted) ----------
    #
    # Detection is two-stage so this stays cheap and polite:
    #   1. PASSIVE — read CNAMEs already captured by httpx and keep only hosts
    #      pointing at third-party infrastructure. A CNAME into your own zone
    #      cannot be taken over by a stranger.
    #   2. TARGETED — fetch a body only for those candidates and match it
    #      against fingerprints from can-i-take-over-xyz.
    # Matching the body rather than the page title matters: most takeover
    # markers ("NoSuchBucket", "There isn't a GitHub Pages site here") appear
    # in the body of a page whose <title> is generic or empty.

    # Fallback set used when the live fingerprint list is unreachable. Keys are
    # body markers, values are the service that claims the name.
    TAKEOVER_FALLBACK = {
        'NoSuchBucket': 'AWS/S3',
        'The specified bucket does not exist': 'AWS/S3',
        "There isn't a GitHub Pages site here": 'GitHub Pages',
        'No such app': 'Heroku',
        'herokucdn.com/error-pages/no-such-app.html': 'Heroku',
        'The gods are wise, but do not know of the site which you seek': 'Fastly',
        'Repository not found': 'Bitbucket',
        'Project doesnt exist... yet!': 'Readme.io',
        'The feed has not been found.': 'Feedpress',
        'Do you want to register': 'Wordpress',
        'Whatever you were looking for doesn\'t currently exist at this address': 'Tumblr',
        'This UserVoice subdomain is currently available!': 'UserVoice',
        "Uh oh. That page doesn't exist.": 'Intercom',
        'Sorry, We Couldn\'t Find That Page': 'Desk',
        'No settings were found for this company': 'Help Scout',
        'is not a registered InCloud YouTrack': 'JetBrains',
        'No Site For Domain': 'Kinsta',
        '404 error unknown site!': 'Pantheon',
        'project not found': 'Surge.sh',
        'Domain uses DO name serves with no records in DO.': 'DigitalOcean',
        'It looks like you may have taken a wrong turn somewhere': 'LaunchRock',
        "We could not find what you're looking for.": 'Help Juice',
        'Trying to access your account?': 'Campaign Monitor',
    }

    # CNAME targets worth probing. A CNAME to one of these is the precondition
    # for nearly every documented takeover.
    TAKEOVER_PRONE_TARGETS = (
        's3.amazonaws.com', 's3-website', 'cloudfront.net', 'elasticbeanstalk.com',
        'github.io', 'herokuapp.com', 'herokudns.com', 'wordpress.com',
        'pantheonsite.io', 'domains.tumblr.com', 'desk.com', 'zendesk.com',
        'helpscoutdocs.com', 'uservoice.com', 'surge.sh', 'bitbucket.io',
        'fastly.net', 'readme.io', 'feedpress.me', 'ghost.io', 'kinsta.cloud',
        'launchrock.com', 'myjetbrains.com', 'statuspage.io', 'netlify.app',
        'netlify.com', 'azurewebsites.net', 'cloudapp.net', 'trafficmanager.net',
        'blob.core.windows.net', 'shopify.com', 'myshopify.com', 'unbouncepages.com',
        'wpengine.com', 'agilecrm.com', 'aftership.com', 'helpjuice.com',
        'campaignmonitor.com', 'createsend.com', 'acquia-sites.com', 'smugmug.com',
    )

    # Fingerprints too generic to ever confirm a takeover on their own. Several
    # appear verbatim in can-i-take-over-xyz, where they are safe only because a
    # human has already confirmed the CNAME points at that service. Matched
    # blindly against any response body they fire on ordinary 404 pages.
    TAKEOVER_GENERIC_FP = {
        '404 not found', 'page not found', 'not found', '404 error',
        'page not found.', '404', 'no such file or directory',
    }

    # can-i-take-over-xyz leaves `cname` empty for several services whose
    # delegation patterns are nonetheless well known. Supplying them here lets
    # those services reach the corroborated tier (CNAME + body agree) instead
    # of resting on the marker alone — and it is what rescues short-but-real
    # markers like Heroku's "No such app" from a blunt length cutoff.
    SERVICE_CNAME_HINTS = {
        'github':     ['github.io'],
        'heroku':     ['herokuapp.com', 'herokudns.com', 'herokussl.com'],
        'netlify':    ['netlify.app', 'netlify.com'],
        'pantheon':   ['pantheonsite.io'],
        'wordpress':  ['wordpress.com'],
        'tumblr':     ['domains.tumblr.com'],
        'shopify':    ['myshopify.com'],
        'fastly':     ['fastly.net'],
        'ghost':      ['ghost.io'],
        'helpscout':  ['helpscoutdocs.com'],
        'uservoice':  ['uservoice.com'],
        'readme.io':  ['readme.io'],
        'feedpress':  ['feedpress.me'],
        'intercom':   ['custom.intercom.help'],
        'kinsta':     ['kinsta.cloud'],
        'launchrock': ['launchrock.com'],
        'campaign monitor': ['createsend.com', 'campaignmonitor.com'],
        'aftership':  ['aftership.com'],
        'agilecrm':   ['agilecrm.com'],
        'wpengine':   ['wpengine.com'],
        'smartling':  ['smartling.com'],
        'short.io':   ['short.io', 'shortio.link'],
        'mashery':    ['mashery.com'],
        'vercel':     ['cname.vercel-dns.com', 'vercel.app'],
    }

    def _load_takeover_fingerprints(self) -> Tuple[list, str]:
        """Load takeover rules from can-i-take-over-xyz; fall back to static.

        Returns (rules, source_label) where each rule is
        {'service', 'fingerprint', 'cnames': [...]}.

        Two filters matter for precision, both learned from a live false
        positive: this check originally flagged two CloudFront-backed hosts as
        "Cargo Collective" takeovers because that entry pairs an empty CNAME
        list with the fingerprint "404 Not Found".

          1. Drop non-body fingerprints. Entries like NXDOMAIN or
             HTTP_STATUS=301 are directives about DNS/status, not text that
             appears in a body — substring-matching them is meaningless.
          2. Drop generic fingerprints. "404 Not Found" identifies nothing.

        The surviving rules also carry their CNAME patterns, which the matcher
        requires to line up with the host's actual delegation before a
        fingerprint is even considered.
        """
        if self._fingerprints:
            return self._fingerprints, self._fingerprint_source

        rules: list = []
        url = ("https://raw.githubusercontent.com/EdOverflow/"
               "can-i-take-over-xyz/master/fingerprints.json")
        data, err = self._http_json(url, timeout=20)
        skipped_generic = 0
        if not err and isinstance(data, list):
            for row in data:
                if not isinstance(row, dict):
                    continue
                if row.get("status") not in ("Vulnerable", "Edge case"):
                    continue
                fp = (row.get("fingerprint") or "").strip()
                svc = row.get("service") or "unknown"
                # The upstream list carries some malformed cname entries —
                # bare IPs and at least one full URL. A CNAME pattern must be
                # a domain fragment; anything else would match unpredictably
                # against a delegation target.
                cnames = []
                for c in (row.get("cname") or []):
                    c = str(c).strip().lower().strip("/")
                    if not c or "://" in c or "/" in c:
                        continue
                    if re.fullmatch(r"[\d.]+", c):     # bare IPv4
                        continue
                    if "." not in c:
                        continue
                    cnames.append(c)
                if not fp or len(fp) < 8:
                    continue
                if fp.upper().startswith(("NXDOMAIN", "HTTP_STATUS")):
                    continue
                if fp.strip().lower().rstrip('.') in self.TAKEOVER_GENERIC_FP:
                    skipped_generic += 1
                    continue
                if not cnames:
                    svc_l = svc.lower()
                    for hint, pats in self.SERVICE_CNAME_HINTS.items():
                        if hint in svc_l:
                            cnames = list(pats)
                            break
                rules.append({"service": svc, "fingerprint": fp, "cnames": cnames})

        if rules:
            src = (f"can-i-take-over-xyz ({len(rules)} rules, live"
                   + (f"; {skipped_generic} generic fingerprint(s) rejected"
                      if skipped_generic else "") + ")")
        else:
            # Give the fallback the same CNAME hints, so short-but-real markers
            # ("NoSuchBucket", "No such app") still reach the corroborated tier
            # offline instead of being dropped by the marker-only length bar.
            rules = []
            for fp, svc in self.TAKEOVER_FALLBACK.items():
                svc_l = svc.lower()
                cn: List[str] = []
                for hint, pats in self.SERVICE_CNAME_HINTS.items():
                    if hint in svc_l:
                        cn = list(pats)
                        break
                if not cn and 's3' in svc_l:
                    cn = ['s3.amazonaws.com', 's3-website', 's3.dualstack']
                rules.append({"service": svc, "fingerprint": fp, "cnames": cn})
            src = (f"static fallback list ({len(rules)} rules"
                   + (f"; live fetch failed: {err}" if err else "") + ")")

        self._fingerprints = rules
        self._fingerprint_source = src
        return rules, src

    def _takeover_candidates(self, cname_tokens: Optional[tuple] = None
                             ) -> List[Tuple[str, str]]:
        """Hosts whose CNAME points at third-party infra. Passive — reads disk.

        `cname_tokens` defaults to the static TAKEOVER_PRONE_TARGETS list but
        is normally passed the CNAME patterns from the live ruleset, so the
        candidate set and the fingerprints always describe the same services.
        """
        tokens = cname_tokens or self.TAKEOVER_PRONE_TARGETS
        out: List[Tuple[str, str]] = []
        seen: set = set()
        path = self.scan_dir / "04_http_discovery/http_confirmed.json"
        if not path.exists():
            return out
        for line in path.read_text(errors="ignore").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except Exception:
                continue
            host = (row.get("host") or row.get("input") or "").strip().lower()
            cnames = row.get("cname") or []
            if isinstance(cnames, str):
                cnames = [cnames]
            for cn in cnames:
                cn = str(cn).strip().lower().rstrip(".")
                if not cn or not host or host in seen:
                    continue
                # A CNAME inside our own zone is not a third-party dependency.
                if self.domain and cn.endswith(self.domain):
                    continue
                if any(t in cn for t in tokens):
                    seen.add(host)
                    out.append((host, cn))
        return out

    def collect_takeover(self):
        if self.offline:
            self._connector_status("takeover", "Subdomain takeover check", False,
                                   "offline mode — takeover fingerprinting skipped")
            return

        # Load rules first so candidate selection uses the same CNAME patterns
        # the matcher will require — the two must describe one service set.
        fps, fp_src = self._load_takeover_fingerprints()
        live_tokens = tuple({c for r in fps for c in r["cnames"]}) or None

        candidates = self._takeover_candidates(live_tokens)
        if not candidates:
            self._add(OsintFinding(
                category="takeover",
                title="No takeover-prone CNAME delegations found",
                subject=f"{self.domain}:takeover", severity="info",
                confidence="high", source=f"CNAME analysis (passive) [{fp_src}]",
                evidence="No host CNAMEs into third-party infrastructure known "
                         "to be takeover-prone.",
                risk="No dangling-delegation exposure observed at scan time.",
                recommendation="Re-check after DNS changes; takeover risk is "
                               "created the moment a backend is decommissioned "
                               "while its CNAME remains.",
                meta={"candidates": 0, "fingerprint_source": fp_src}))
            return

        confirmed: List[dict] = []
        probed = 0
        probe_errors = 0

        # Bulk probing is deliberately cheap: no retries and a short timeout.
        # With a 25-host cap this bounds the collector at roughly 25 x 8s worst
        # case instead of the minutes a retrying probe would cost — and the
        # engine runs collectors serially, so that cost is paid by every
        # category queued behind it.
        for host, cname in candidates[:TAKEOVER_PROBE_CAP]:
            body = None
            for scheme in ("https", "http"):
                # body_on_error is essential here: the takeover page is served
                # WITH a 404 by most providers, so discarding error bodies
                # would blind this check to the majority of real takeovers.
                body, err = self._http_text(f"{scheme}://{host}/",
                                            timeout=TAKEOVER_PROBE_TIMEOUT,
                                            retries=0, body_on_error=True)
                if body:
                    break
            probed += 1
            if not body:
                probe_errors += 1
                continue

            # Two tiers, because the upstream dataset leaves `cname` empty for
            # several real services (Heroku, Netlify, Pantheon) whose markers
            # are nonetheless unmistakable:
            #
            #   corroborated — the host's CNAME matches the service's own
            #                  delegation pattern AND the body carries its
            #                  marker. Two independent signals agree.
            #   marker-only  — no CNAME pattern published, but the marker is
            #                  distinctive enough to name the service by itself.
            #
            # Generic markers were already dropped at load time, so neither
            # tier can fire on an ordinary 404. This is the guard that stops a
            # CloudFront host being reported as a Cargo Collective takeover.
            corroborated = [r for r in fps
                            if r["cnames"] and any(c in cname for c in r["cnames"])]
            marker_only = [r for r in fps
                           if not r["cnames"] and len(r["fingerprint"]) >= 15]

            hit = next(((r, r["fingerprint"], "corroborated") for r in corroborated
                        if r["fingerprint"] in body), None)
            if not hit:
                hit = next(((r, r["fingerprint"], "marker-only") for r in marker_only
                            if r["fingerprint"] in body), None)
            if not hit:
                continue
            rule, marker, tier = hit
            service = rule["service"]
            confirmed.append({"host": host, "cname": cname, "service": service,
                              "fingerprint": marker, "basis": tier})
            corr = tier == "corroborated"
            self._add(OsintFinding(
                category="takeover",
                title=f"Subdomain takeover: {host} ({service})"
                      + ("" if corr else " — unconfirmed delegation"),
                subject=host, severity="critical",
                confidence="high" if corr else "medium",
                source=f"CNAME + body fingerprint [{fp_src}]",
                evidence=(f"CNAME → {cname} (matches {service} delegation "
                          f"pattern); response body contains the {service} "
                          f"unclaimed-resource marker: \"{marker[:90]}\""
                          if corr else
                          f"CNAME → {cname}; response body contains the "
                          f"{service} unclaimed-resource marker: "
                          f"\"{marker[:90]}\". The upstream dataset publishes "
                          f"no CNAME pattern for {service}, so the delegation "
                          f"could not be independently corroborated — verify "
                          f"the CNAME target belongs to {service} before acting."),
                risk=f"{host} delegates to {cname}, but {service} is serving its "
                     f"unclaimed-resource page. Anyone can register that resource "
                     f"and serve content from your hostname — with a valid "
                     f"certificate, your cookie scope, and any OAuth/CORS trust "
                     f"your other systems extend to *.{self.domain}.",
                recommendation=f"Remove the {host} DNS record, or reclaim the "
                               f"resource at {service} immediately. Then audit "
                               f"cookie scope and OAuth redirect allowlists for "
                               f"wildcard subdomain trust.",
                meta={"host": host, "cname": cname, "service": service,
                      "fingerprint": marker, "url": f"https://{host}/",
                      "basis": tier,
                      "matched_cname_patterns": rule["cnames"]}))

        # Always report coverage — a takeover check that silently probed nothing
        # is exactly the false-clean this refactor exists to eliminate.
        if not confirmed:
            self._add(OsintFinding(
                category="takeover",
                title=f"No takeover confirmed across {probed} delegated host(s)",
                subject=f"{self.domain}:takeover", severity="info",
                confidence="medium" if probe_errors else "high",
                source=f"CNAME + body fingerprint [{fp_src}]",
                evidence=f"{len(candidates)} host(s) CNAME into third-party "
                         f"infrastructure; {probed} probed, none matched a "
                         f"takeover fingerprint."
                         + (f" {probe_errors} host(s) did not respond."
                            if probe_errors else ""),
                risk="Third-party delegations exist but none currently serve an "
                     "unclaimed-resource page."
                     + (" Coverage is partial — unreachable hosts were not "
                        "assessed." if probe_errors else ""),
                recommendation="Keep an inventory of these delegations; takeover "
                               "risk appears the moment a backend is retired.",
                meta={"candidates": [{"host": h, "cname": c}
                                     for h, c in candidates[:60]],
                      "probed": probed, "unreachable": probe_errors,
                      "fingerprint_source": fp_src}))
        elif probe_errors:
            self._connector_status(
                "takeover", "Subdomain takeover check", True,
                f"{probe_errors} of {probed} candidate host(s) did not respond "
                f"— those delegations were not assessed.")

    def collect_supply_chain(self):
        # gather candidate strings: DNS record targets + tech tags
        blobs: List[Tuple[str, str]] = []   # (text, source)
        for host, rec in self.dns_records.items():
            if not isinstance(rec, dict):
                continue
            for rtype in ("CNAME", "MX", "NS", "TXT", "A", "AAAA"):
                for val in rec.get(rtype, []) or []:
                    blobs.append((str(val), f"{rtype} {host}"))
        for host, hd in self.hosts.items():
            hd = hd or {}
            for key in ("tech_tag", "server_banner", "waf_vendor"):
                if hd.get(key):
                    blobs.append((str(hd[key]), f"{key} {host}"))

        vendors: Dict[str, dict] = {}
        for text, src in blobs:
            low = text.lower()
            for token, vendor, kind in VENDOR_SIGNATURES:
                if token in low:
                    v = vendors.setdefault(vendor, {
                        "kind": kind, "evidence": set(), "sources": set()})
                    v["evidence"].add(_short(text, 70))
                    v["sources"].add(src)

        if not vendors:
            self._add(OsintFinding(
                category="supply_chain",
                title="No third-party vendors inferred from DNS/tech data",
                subject=self.domain, severity="info", confidence="low",
                source="DNS + tech fingerprints",
                evidence="No known vendor tokens matched in collected records.",
                risk="Either a lean supply chain or insufficient recon depth.",
                recommendation="Ensure DNS discovery ran before OSINT correlation."))
            return

        # rollup finding
        by_kind: Dict[str, int] = {}
        for v in vendors.values():
            by_kind[v["kind"]] = by_kind.get(v["kind"], 0) + 1
        self._add(OsintFinding(
            category="supply_chain",
            title=f"{len(vendors)} third-party vendor(s) in the supply chain",
            subject=self.domain, severity="info", confidence="high",
            source="DNS + tech fingerprints",
            evidence="; ".join(f"{VENDOR_KIND_LABELS.get(k, k)}: {n}"
                               for k, n in sorted(by_kind.items(), key=lambda x: -x[1])),
            risk="Every third party is part of your attack surface — a compromise "
                 "or misconfiguration at a vendor can cascade to you.",
            recommendation="Maintain a vendor inventory; assess the security posture "
                           "and data access of each critical dependency.",
            meta={"by_kind": by_kind, "vendor_count": len(vendors)}))

        for vendor, v in sorted(vendors.items()):
            kind = v["kind"]
            # identity / payments / email-security dependencies are higher stakes
            sev = "low" if kind in ("identity", "payments", "email_security",
                                    "source_code", "cicd") else "info"
            self._add(OsintFinding(
                category="supply_chain",
                title=f"{VENDOR_KIND_LABELS.get(kind, kind)}: {vendor}",
                subject=vendor, severity=sev, confidence="high",
                source="DNS + tech fingerprints",
                evidence="; ".join(sorted(v["evidence"])[:3]),
                risk=f"{vendor} is a {VENDOR_KIND_LABELS.get(kind, kind).lower()} "
                     "dependency observable from public DNS/tech data.",
                recommendation="Include in third-party risk register; verify data "
                               "handling and breach-notification terms.",
                meta={"kind": kind,
                      "sources": sorted(v["sources"])[:6]}))

    # -- Internet-wide exposure (Shodan InternetDB — free, no key) -------
    def collect_internet_exposure(self):
        if self.offline:
            self._connector_status("internet_exposure", "Shodan InternetDB",
                                   False, "offline mode")
            return
        if not self.resolved_ips:
            return
        checked = 0
        failed = 0          # transport/server errors — we did not get an answer
        no_data = 0         # 404: InternetDB answered "nothing indexed here"
        for ip in sorted(self.resolved_ips):
            if checked >= 40:      # politeness / rate cap
                break
            checked += 1
            data, err = self._http_json(f"https://internetdb.shodan.io/{ip}",
                                        timeout=12)
            if err:
                # A 404 is a real answer ("no data for this IP"), not a failure.
                if err.strip() == "http 404":
                    no_data += 1
                else:
                    failed += 1
                continue
            if not isinstance(data, dict):
                failed += 1
                continue
            ports = data.get("ports", []) or []
            vulns = data.get("vulns", []) or []
            hostnames = data.get("hostnames", []) or []
            tags = data.get("tags", []) or []
            if not (ports or vulns):
                continue

            # Shared CDN/anycast IPs return every tenant's hostname on that
            # edge node — attributing those to the scanned target would be
            # wrong. Split "our" hostnames from other tenants sharing the IP,
            # and only let vulns/severity drive risk when the IP is dedicated.
            is_shared = "cdn" in tags
            own_hosts = [h for h in hostnames if self.domain in h.lower()]
            other_hosts = [h for h in hostnames if self.domain not in h.lower()]

            if is_shared and not own_hosts and not vulns:
                # Nothing here is attributable to this target beyond "uses a
                # shared CDN edge" — not worth a standalone finding.
                continue

            sev = "high" if (vulns and not is_shared) else \
                  ("medium" if vulns else ("low" if len(ports) > 3 else "info"))
            shared_note = (f" (shared CDN edge IP — {len(other_hosts)} other "
                          f"tenant hostname(s) observed on it, excluded below)"
                          if is_shared and other_hosts else "")
            evidence = f"ports={ports[:15]}"
            if vulns:
                evidence += f"; vulns={vulns[:8]}"
            if own_hosts:
                evidence += f"; hostnames={own_hosts[:3]}"
            evidence += shared_note

            risk = ("Internet-wide scanners have already indexed this host; "
                    "attackers can find it with a single query.")
            if vulns:
                risk += (" Known CVEs are associated with this IP"
                        + (" — verify whether they apply to the shared "
                           "CDN/edge provider rather than your own stack."
                           if is_shared else ".") )

            self._add(OsintFinding(
                category="internet_exposure",
                title=f"Shodan sees {ip}: {len(ports)} port(s)"
                      + (f", {len(vulns)} CVE(s)" if vulns else "")
                      + (" [shared CDN IP]" if is_shared else ""),
                subject=ip, severity=sev, confidence="high" if not is_shared else "medium",
                source="Shodan InternetDB",
                evidence=evidence,
                risk=risk,
                recommendation="Confirm every exposed port is intended; remediate "
                               "flagged CVEs; restrict management interfaces."
                               + (" For shared CDN IPs, verify findings against "
                                  "the origin server, not the edge node."
                                  if is_shared else ""),
                meta={"ports": ports, "vulns": vulns, "own_hostnames": own_hosts,
                      "other_tenant_hostnames": other_hosts[:20],
                      "tags": tags, "shared_ip": is_shared}))
        self.log(f"internetdb: checked {checked} IPs "
                 f"({failed} failed, {no_data} no-data)")

        # Report coverage honestly. Without this, a source outage renders as
        # "no internet exposure" — indistinguishable from a genuinely clean
        # result, which is the worst failure mode an EASM tool can have.
        if failed and failed >= checked:
            self._connector_status(
                "internet_exposure", "Shodan InternetDB", True,
                f"query failed for all {checked} IP(s) — this category was NOT "
                f"assessed on this run; absence of findings here means "
                f"'not checked', not 'clean'.")
        elif failed:
            self._connector_status(
                "internet_exposure", "Shodan InternetDB", True,
                f"{failed} of {checked} IP lookup(s) failed — coverage is "
                f"partial; {checked - failed} IP(s) were assessed.")

    # -- Public email / human exposure (defensive) -----------------------
    def collect_email_exposure(self):
        # 1. inventory of public emails already harvested
        emails = sorted(self.emails)
        if emails:
            self._add(OsintFinding(
                category="email_exposure",
                title=f"{len(emails)} public corporate email address(es) found",
                subject=self.domain, severity="low", confidence="high",
                source="crawled pages / public artifacts",
                evidence=", ".join(emails[:15]) + (" …" if len(emails) > 15 else ""),
                risk="Publicly exposed addresses feed phishing, credential-stuffing, "
                     "and social-engineering campaigns.",
                recommendation="Prefer role aliases over personal addresses on public "
                               "pages; enrol staff in phishing-awareness training.",
                meta={"emails": emails[:200], "count": len(emails)}))

            # 2. infer the organisational email format (defensive awareness)
            fmt = self._infer_email_format(emails)
            if fmt:
                self._add(OsintFinding(
                    category="email_exposure",
                    title=f"Corporate email format appears to be {fmt}",
                    subject=f"{self.domain}:email-format", severity="info", confidence="medium",
                    source="pattern inference",
                    evidence=f"derived from {len(emails)} sample address(es)",
                    risk="A known email format lets attackers construct valid "
                         "addresses for any employee whose name is public.",
                    recommendation="Assume employee addresses are enumerable; harden "
                                   "auth (MFA) and monitor for credential stuffing.",
                    meta={"format": fmt}))
        else:
            self._add(OsintFinding(
                category="email_exposure",
                title="No public corporate email addresses harvested",
                subject=self.domain, severity="info", confidence="low",
                source="crawled pages / public artifacts",
                evidence="No addresses matching the domain were found in scan data.",
                risk="Low public email footprint (or crawl did not run).",
                recommendation="Re-run with crawling enabled for fuller coverage."))

    @staticmethod
    def _infer_email_format(emails: List[str]) -> str:
        """Heuristically label the local-part convention."""
        locals_ = [e.split("@", 1)[0] for e in emails
                   if "@" in e and e.split("@", 1)[0] not in
                   ("info", "support", "contact", "hello", "sales", "admin",
                    "help", "hr", "careers", "press", "security", "noreply",
                    "no-reply")]
        if not locals_:
            return ""
        dotted = sum(1 for l in locals_ if "." in l)
        if dotted >= len(locals_) / 2:
            return "first.last@ (dotted)"
        if all(len(l) <= 8 for l in locals_):
            return "flast@ / initials (short)"
        return "firstlast@ / mixed"

    # -- Breach / dark-web monitoring (keyed connectors) -----------------
    def collect_breach(self):
        # Hudson Rock infostealer intelligence — free, no API key. Runs first
        # because it is the only unkeyed source in this category: without it a
        # deployment with no paid keys produces zero breach intelligence.
        self._hudsonrock_search()

        # HaveIBeenPwned domain search (requires paid API key)
        if self.cfg["hibp"]:
            self._hibp_domain_search()
        else:
            self._connector_status(
                "breach", "Have I Been Pwned", False,
                "set HIBP_API_KEY to enable domain breach monitoring")
        # IntelX / LeakCheck — presence-only connector status
        self._connector_status(
            "breach", "Intelligence X (paste/leak index)",
            bool(self.cfg["intelx"]),
            "set INTELX_API_KEY to enable paste/leak index monitoring")
        self._connector_status(
            "breach", "LeakCheck", bool(self.cfg["leakcheck"]),
            "set LEAKCHECK_API_KEY to enable credential-exposure monitoring")

    def _hudsonrock_search(self):
        """Hudson Rock Cavalier — infostealer / stealer-log intelligence (free).

        This is a different class of signal from breach corpora. A breach dump
        is historical: a password that may since have been rotated. An
        infostealer record means a machine with access to this domain was (or
        is) infected, and the operator holds whatever that browser held —
        including *session cookies*, which defeat MFA without ever touching the
        password. That is why these findings are rated above ordinary breach
        hits at equivalent volume.

        The API is public and unauthenticated. Response shape is parsed
        defensively: counts are read from several plausible keys and anything
        unrecognised degrades to a status note rather than a crash.
        """
        if self.offline:
            self._connector_status("breach", "Hudson Rock (infostealer intel)",
                                   False, "offline mode")
            return

        base = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools"
        url = f"{base}/search-by-domain?domain={urllib.parse.quote(self.domain)}"
        data, err = self._http_json(url, timeout=20)

        if err:
            self._connector_status(
                "breach", "Hudson Rock (infostealer intel)", True,
                f"query failed ({err}) — infostealer exposure was NOT assessed "
                f"on this run; this is not a clean verdict.")
            return
        if not isinstance(data, dict):
            self._connector_status(
                "breach", "Hudson Rock (infostealer intel)", True,
                "unexpected response shape — infostealer exposure not assessed.")
            return

        def _num(*keys) -> int:
            for k in keys:
                v = data.get(k)
                if isinstance(v, (int, float)):
                    return int(v)
                if isinstance(v, list):
                    return len(v)
            return 0

        employees = _num("employees", "totalEmployees", "employees_count")
        users = _num("users", "totalUsers", "users_count")
        third_party = _num("third_parties", "thirdParties")
        total = _num("total", "totalStealers") or (employees + users)

        # The compromised-URL records are the actionable "where": each is a login
        # page / system where a stealer captured a credential for this domain.
        # IMPORTANT: on the current Cavalier API these live under data["data"][...]
        # ({url,type,occurrence}), NOT at the top level. The old code read the top
        # level and so ALWAYS got an empty list. The free domain API does NOT
        # return the leaked identity (email/username — redacted) or the infection
        # DATE; those require Hudson Rock's authenticated API. We surface the URLs
        # + type + occurrence, and capture a date only when a record carries one.
        inner = data.get("data") if isinstance(data.get("data"), dict) else {}

        def _records(*keys) -> List[dict]:
            out: List[dict] = []
            seen = set()
            for src in (inner, data):          # nested location first, then top-level fallback
                for k in keys:
                    for row in (src.get(k) or []):
                        if isinstance(row, dict):
                            u = row.get("url", "")
                            rec = {
                                "url": u,
                                "type": row.get("type", ""),
                                "occurrence": row.get("occurrence"),
                                "date": (row.get("date_compromised") or row.get("last_breach")
                                         or row.get("date") or ""),
                            }
                        else:
                            u = str(row)
                            rec = {"url": u, "type": "", "occurrence": None, "date": ""}
                        # Hudson Rock redacts some URLs with bullet characters.
                        if u and "•" not in u and u not in seen:
                            seen.add(u)
                            out.append(rec)
                if out:
                    break
            return out

        emp_records = _records("employees_urls")
        usr_records = _records("clients_urls", "users_urls")
        all_records = _records("all_urls") or (emp_records + usr_records)
        leak_dates = sorted({r["date"] for r in all_records if r.get("date")})
        emp_urls = [r["url"] for r in emp_records]
        usr_urls = [r["url"] for r in usr_records]

        if not total:
            self._add(OsintFinding(
                category="breach",
                title="No infostealer records for the domain (Hudson Rock)",
                subject=f"{self.domain}:infostealer", severity="info",
                confidence="high", source="Hudson Rock (Cavalier)",
                evidence="Cavalier returned no compromised employee or user "
                         "records for this domain.",
                risk="No known infostealer infection associated with this "
                     "domain at scan time.",
                recommendation="Keep monitoring — stealer logs surface "
                               "continuously as new infections are traded.",
                meta={"total": 0, "source_url": url}))
            return

        # Employee credentials are the higher-impact side: corporate SSO and
        # admin panels rather than customer accounts.
        sev = "critical" if employees >= 5 or total >= 50 else (
              "high" if employees or total >= 10 else "medium")

        # Human-readable "where": compromised URL + who (employee/user) + count.
        def _fmt(records: List[dict]) -> str:
            parts = []
            for r in records[:6]:
                seg = r["url"]
                extra = []
                if r.get("type"):
                    extra.append(r["type"])
                if r.get("occurrence"):
                    extra.append(f"×{r['occurrence']}")
                if extra:
                    seg += f" ({', '.join(extra)})"
                if r.get("date"):
                    seg += f" [{r['date']}]"
                parts.append(seg)
            return "; ".join(parts)

        where = _fmt(all_records)
        # Be explicit about what the FREE API gives vs. withholds, so the analyst
        # knows the missing identity/date is an API-tier limit, not a scan gap.
        if leak_dates:
            date_note = f" Infection date(s): {', '.join(leak_dates)}."
        else:
            date_note = (" The leaked identity (email/username) and the infection "
                         "date are redacted on Hudson Rock's free domain API — "
                         "retrieve per-victim detail from the authenticated Cavalier "
                         "API or the source URL below.")

        self._add(OsintFinding(
            category="breach",
            title=f"{total} infostealer record(s) linked to the domain"
                  + (f" — {employees} employee-side" if employees else ""),
            subject=f"{self.domain}:infostealer", severity=sev,
            confidence="high", source="Hudson Rock (Cavalier)",
            evidence=f"employees={employees}, users={users}, "
                     f"third-party={third_party}, total={total}."
                     + (f" Compromised URLs (where credentials were captured): "
                        f"{where}." if where else "")
                     + date_note,
            risk="Machines with access to this domain appear in infostealer "
                 "logs. Unlike a breach dump, stealer logs typically include "
                 "live session cookies and saved browser credentials — an "
                 "attacker can resume an authenticated session without the "
                 "password and without triggering MFA."
                 + (" Employee-side records mean corporate access, not just "
                    "customer accounts." if employees else ""),
            recommendation="Treat as an active incident, not a password reset: "
                           "invalidate all server-side sessions for affected "
                           "accounts, rotate credentials, and get the infected "
                           "endpoints re-imaged. Rotating passwords alone does "
                           "not revoke a stolen session cookie. To scope exactly "
                           "which identities to reset, pull the per-victim records "
                           "(login, machine name, stealer family, infection date) "
                           "from Hudson Rock's authenticated Cavalier API.",
            meta={"total": total, "employees": employees, "users": users,
                  "third_parties": third_party,
                  # structured records the dashboard renders: url/type/occurrence/date
                  "records": all_records[:60],
                  "employee_urls": emp_urls[:60],
                  "user_urls": usr_urls[:60],
                  "leak_dates": leak_dates,
                  # False = identity+date withheld by the free tier (not a scan gap)
                  "per_record_detail_available": bool(leak_dates),
                  "source_url": url}))

    def _hibp_domain_search(self):
        url = ("https://haveibeenpwned.com/api/v3/breacheddomain/"
               + urllib.parse.quote(self.domain))
        data, err = self._http_json(
            url, headers={"hibp-api-key": self.cfg["hibp"]}, timeout=20)
        if err:
            self._connector_status("breach", "Have I Been Pwned", True,
                                   f"query error: {err}")
            return
        # response: {alias: [breach names], ...}
        if not isinstance(data, dict) or not data:
            self._add(OsintFinding(
                category="breach",
                title="No breached accounts for the domain (HIBP)",
                subject=self.domain, severity="info", confidence="high",
                source="Have I Been Pwned",
                evidence="HIBP domain search returned no exposed accounts.",
                risk="No known credential exposure at time of query.",
                recommendation="Keep monitoring — HIBP is authoritative but not "
                               "exhaustive."))
            return
        total = sum(len(v) for v in data.values())
        all_breaches = sorted({b for v in data.values() for b in v})
        self._add(OsintFinding(
            category="breach",
            title=f"{len(data)} account(s) exposed across {len(all_breaches)} breach(es)",
            subject=self.domain, severity="critical" if total >= 25 else "high",
            confidence="high", source="Have I Been Pwned",
            evidence=f"{total} account/breach pairs; breaches: "
                     + ", ".join(all_breaches[:10]),
            risk="Corporate credentials appear in known breach corpora — prime "
                 "material for credential-stuffing and account takeover.",
            recommendation="Force password resets for affected accounts; enforce MFA; "
                           "monitor for reuse.",
            meta={"accounts": len(data), "breaches": all_breaches,
                  "total_pairs": total}))

    # -- Public code exposure (GitHub, keyed) ----------------------------
    def collect_code_exposure(self):
        if not self.cfg["github"]:
            self._connector_status(
                "code_exposure", "GitHub code search", False,
                "set GITHUB_TOKEN to enable public code / leaked-secret search")
            return
        q = urllib.parse.quote(f"\"{self.domain}\"")
        # per_page=100 so the drill-down can show real files, not just a count.
        url = f"https://api.github.com/search/code?q={q}&per_page=100"
        data, err = self._http_json(url, headers={
            "Authorization": f"Bearer {self.cfg['github']}",
            "Accept": "application/vnd.github+json"}, timeout=20)
        if err or not isinstance(data, dict):
            self._connector_status("code_exposure", "GitHub code search", True,
                                   f"query error: {err or 'no data'}")
            return
        total = data.get("total_count", 0)
        items = data.get("items", []) or []
        if not total:
            self._add(OsintFinding(
                category="code_exposure",
                title="No public code references the domain (GitHub)",
                subject=self.domain, severity="info", confidence="high",
                source="GitHub code search",
                evidence="0 matches for the domain string.",
                risk="No obvious public-code leakage detected.",
                recommendation="Keep scanning; expand queries to org/product names."))
            return
        repos = sorted({(i.get("repository") or {}).get("full_name", "")
                        for i in items if i.get("repository")})

        # Capture the individual files so the finding is investigable rather
        # than a bare count. Without these, "182 files reference the domain"
        # tells an analyst there is a problem but nothing about where to look.
        matches: List[dict] = []
        for i in items:
            repo = (i.get("repository") or {})
            matches.append({
                "repo": repo.get("full_name", ""),
                "repo_url": repo.get("html_url", ""),
                "path": i.get("path", ""),
                "name": i.get("name", ""),
                "url": i.get("html_url", ""),
                "private_repo": bool(repo.get("private")),
            })
        # Group by repo so the drill-down can lead with the worst offenders.
        by_repo: dict = {}
        for m in matches:
            by_repo.setdefault(m["repo"], []).append(m)
        repo_ranked = sorted(by_repo.items(), key=lambda kv: -len(kv[1]))

        search_url = ("https://github.com/search?type=code&q="
                      + urllib.parse.quote(f'"{self.domain}"'))

        self._add(OsintFinding(
            category="code_exposure",
            title=f"{total} public code file(s) reference the domain",
            subject=self.domain, severity="medium" if total >= 10 else "low",
            confidence="medium", source="GitHub code search",
            evidence=f"{total} matches across {len(by_repo)} repo(s); "
                     f"top: " + ", ".join(f"{r} ({len(f)})"
                                          for r, f in repo_ranked[:5]),
            risk="Public code mentioning your domain may leak internal hostnames, "
                 "endpoints, tokens, or configuration.",
            recommendation="Review the referencing repos for secrets and internal "
                           "detail; rotate any exposed credentials.",
            meta={"total": total,
                  "returned": len(matches),
                  "repos": list(repos)[:60],
                  "repo_counts": [{"repo": r, "files": len(f),
                                   "url": (f[0].get("repo_url") or "")}
                                  for r, f in repo_ranked[:40]],
                  "files": matches[:100],
                  "search_url": search_url}))

    # -- Public API documentation ----------------------------------------
    def collect_api_docs(self):
        # correlate discovered API specs from the API modules already on disk
        specs: List[str] = []
        for rel in ("16_api_security", "20_api_deep_discovery"):
            d = self.scan_dir / rel
            if not d.is_dir():
                continue
            for p in d.rglob("*"):
                n = p.name.lower()
                if any(t in n for t in ("swagger", "openapi", "graphql",
                                        "api-docs", "apidocs")) and p.is_file():
                    specs.append(str(p.relative_to(self.scan_dir)))
        specs = sorted(set(specs))
        if not specs:
            return
        self._add(OsintFinding(
            category="api_docs",
            title=f"{len(specs)} public API documentation artifact(s) discovered",
            subject=self.domain, severity="low", confidence="medium",
            source="API discovery modules",
            evidence=", ".join(os.path.basename(s) for s in specs[:10]),
            risk="Publicly reachable Swagger/OpenAPI/GraphQL docs hand attackers a "
                 "complete map of your API surface and its parameters.",
            recommendation="Confirm public docs are intended; require auth on "
                           "internal specs; remove verbose error/example data.",
            meta={"artifacts": specs[:50]}))

    # -- Social / media presence (light, public) -------------------------
    def collect_social(self):
        """GitHub organizations get a real existence check via GitHub's public
        API, which returns an honest 404 for a name that doesn't exist. The
        big consumer social platforms (LinkedIn/X/Facebook/Instagram) are
        deliberately NOT probed for existence: their SPA front-ends return
        HTTP 200 for essentially any profile URL regardless of whether the
        handle is real (confirmed empirically — this used to trip an earlier
        version of this collector into false "confirmed presence" claims), so
        any automated verdict for them would be fabricated confidence. They
        are surfaced as manual-verification candidates instead."""
        brand = self.domain.split(".")[0]
        gh_org, gh_err = self._http_json(
            f"https://api.github.com/orgs/{urllib.parse.quote(brand)}", timeout=10)
        if not gh_err and isinstance(gh_org, dict) and gh_org.get("login"):
            self._add(OsintFinding(
                category="social",
                title="Confirmed GitHub organization",
                subject=f"{self.domain}:github", severity="info", confidence="high",
                source="GitHub public API",
                evidence=f"{gh_org.get('html_url','')} — "
                         f"{gh_org.get('public_repos',0)} public repo(s)",
                risk="Official accounts are impersonation targets and can leak "
                     "operational detail via public repos/membership.",
                recommendation="Monitor for impersonating orgs using a similar "
                               "name.",
                meta={"login": gh_org.get("login"),
                      "public_repos": gh_org.get("public_repos", 0)}))
        elif gh_err == "http 404":
            self._add(OsintFinding(
                category="social",
                title="GitHub organization name unclaimed",
                subject=f"{self.domain}:github", severity="low", confidence="high",
                source="GitHub public API",
                evidence=f"https://github.com/{brand} — no org registered "
                         f"under this name.",
                risk="An unclaimed org name can be registered by an "
                     "impersonator to host convincing lookalike repos.",
                recommendation="Register the brand's GitHub org defensively, "
                               "even if unused for code hosting."))
        else:
            self._connector_status("social", "GitHub organization lookup",
                                   False, f"lookup unavailable: {gh_err}")

        self._add(OsintFinding(
            category="social",
            title="Manual verification candidates (consumer platforms)",
            subject=f"{self.domain}:consumer-platforms", severity="info", confidence="low",
            source="brand-token inference",
            evidence=f"LinkedIn: https://www.linkedin.com/company/{brand}; "
                     f"X/Twitter: https://x.com/{brand}; "
                     f"Facebook: https://www.facebook.com/{brand}; "
                     f"Instagram: https://www.instagram.com/{brand}",
            risk="These platforms return HTTP 200 for both real and fake "
                 "profile URLs, so automated existence checks would be "
                 "unreliable — verify manually.",
            recommendation="Manually confirm each handle is owned by the "
                           "organization and register unclaimed ones "
                           "defensively; monitor claimed ones for impersonation."))

    # -- Organization Discovery (RDAP — free, no key) --------------------
    def collect_organization(self):
        if not self.domain:
            return
        data, err = self._http_json(
            f"https://rdap.org/domain/{urllib.parse.quote(self.domain)}",
            headers={"Accept": "application/rdap+json"}, timeout=20)
        if err or not isinstance(data, dict):
            self._connector_status("organization", "RDAP (domain registry)",
                                   False, f"lookup unavailable: {err or 'no data'}")
            return

        events = {e.get("eventAction"): e.get("eventDate")
                 for e in data.get("events", []) or []}
        registered = events.get("registration", "")
        expiring = events.get("expiration", "")
        changed = events.get("last changed", "")
        nameservers = sorted({n.get("ldhName", "").lower()
                              for n in data.get("nameservers", []) or []
                              if n.get("ldhName")})
        status = data.get("status", []) or []

        registrar = ""
        for ent in data.get("entities", []) or []:
            if "registrar" in (ent.get("roles") or []):
                for card in (ent.get("vcardArray") or [None, []])[1]:
                    if card and card[0] == "fn":
                        registrar = card[3]
                        break

        age_note = ""
        if registered:
            try:
                reg_dt = datetime.fromisoformat(registered.replace("Z", "+00:00"))
                years = (datetime.now(timezone.utc) - reg_dt).days // 365
                age_note = f"{years}y old"
            except Exception:
                pass

        self._add(OsintFinding(
            category="organization",
            title=f"Domain registration profile ({registrar or 'unknown registrar'})",
            subject=self.domain, severity="info", confidence="high",
            source="RDAP", evidence=f"registered {registered[:10]} ({age_note}); "
                     f"nameservers: {', '.join(nameservers[:4])}",
            risk="Registration metadata (age, registrar, nameservers) is public "
                 "and used by attackers to assess domain legitimacy and pivot to "
                 "related infrastructure.",
            recommendation="Enable registrar transfer-lock; keep contact/renewal "
                           "info current.",
            meta={"registrar": registrar, "registered": registered,
                  "expiring": expiring, "last_changed": changed,
                  "nameservers": nameservers, "status": status}))

        # domain expiring soon → real, exploitable risk (drop-catch / hijack)
        if expiring:
            try:
                exp_dt = datetime.fromisoformat(expiring.replace("Z", "+00:00"))
                days_left = (exp_dt - datetime.now(timezone.utc)).days
                if days_left <= 60:
                    sev = "critical" if days_left <= 14 else "high"
                    self._add(OsintFinding(
                        category="organization",
                        title=f"Domain expires in {days_left} day(s)",
                        subject=f"{self.domain}:expiry", severity=sev, confidence="high",
                        source="RDAP", evidence=f"expiration: {expiring[:10]}",
                        risk="An expired apex domain can be re-registered by an "
                             "attacker, hijacking mail, SSO, and every subdomain.",
                        recommendation="Renew immediately; enable auto-renew and "
                                       "registry lock."))
            except Exception:
                pass

    # -- Recruitment Intelligence (public ATS job boards) ----------------
    def collect_recruitment(self):
        if self.offline or not self.domain:
            return
        brand = re.sub(r"[^a-z0-9]", "", self.domain.split(".")[0].lower())
        if not brand:
            return

        # A 404 here is a real answer — "no board under this slug". Anything
        # else (timeout, 5xx) means we never learned whether a board exists,
        # and that must not be reported as "no board found".
        jobs, ats = None, ""
        probe_errors: List[str] = []

        gh_data, gh_err = self._http_json(
            f"https://boards-api.greenhouse.io/v1/boards/{brand}/jobs?content=true",
            timeout=15)
        if not gh_err and isinstance(gh_data, dict) and gh_data.get("jobs"):
            jobs, ats = gh_data["jobs"], "Greenhouse"
        else:
            if gh_err and gh_err.strip() != "http 404":
                probe_errors.append(f"Greenhouse: {gh_err}")
            lv_data, lv_err = self._http_json(
                f"https://api.lever.co/v0/postings/{brand}?mode=json", timeout=15)
            if not lv_err and isinstance(lv_data, list) and lv_data:
                jobs, ats = lv_data, "Lever"
            elif lv_err and lv_err.strip() != "http 404":
                probe_errors.append(f"Lever: {lv_err}")

        if not jobs:
            if probe_errors:
                self._connector_status(
                    "recruitment", "Public ATS job board (Greenhouse/Lever)", True,
                    "board lookup failed (" + "; ".join(probe_errors) + ") — "
                    "recruitment exposure was NOT assessed on this run; this is "
                    "not evidence that no public job board exists.")
            else:
                self._connector_status(
                    "recruitment", "Public ATS job board (Greenhouse/Lever)", False,
                    "no public Greenhouse/Lever board found under the brand token "
                    "(company may use a different ATS or careers-page slug)")
            return

        titles = [str(j.get("title", "")) for j in jobs][:200]
        blob = " ".join(titles).lower()
        if ats == "Greenhouse":
            for j in jobs[:60]:
                blob += " " + str((j.get("content") or "")).lower()

        self._add(OsintFinding(
            category="recruitment",
            title=f"{len(jobs)} open job posting(s) on {ats}",
            subject=self.domain, severity="info", confidence="high",
            source=f"{ats} public job board",
            evidence="; ".join(titles[:8]) + (" …" if len(titles) > 8 else ""),
            risk="Public job postings reveal team structure, growth areas, and — "
                 "in descriptions — internal technology.",
            recommendation="Keep descriptions free of internal hostnames, tool "
                           "versions, and architecture detail.",
            meta={"ats": ats, "count": len(jobs), "titles": titles[:100]}))

        found_tech = sorted({kw for kw in TECH_KEYWORDS if kw in blob})
        if found_tech:
            self._add(OsintFinding(
                category="recruitment",
                title=f"Technology stack revealed via job postings ({len(found_tech)} terms)",
                subject=f"{self.domain}:techstack", severity="low", confidence="medium",
                source=f"{ats} public job board",
                evidence=", ".join(found_tech[:20]),
                risk="Job descriptions name the exact stack (cloud, databases, "
                     "frameworks) an attacker would target with tailored exploits.",
                recommendation="Generalise tech mentions in postings (e.g. "
                               "\"cloud infrastructure\" instead of specific "
                               "vendor/version); keep deep-stack detail internal.",
                meta={"technologies": found_tech}))

    # -- Mobile App Intelligence (Apple iTunes Search API — free) --------
    def collect_mobile_app(self):
        if self.offline or not self.domain:
            return
        brand = self.domain.split(".")[0]
        data, err = self._http_json(
            "https://itunes.apple.com/search?"
            + urllib.parse.urlencode({"term": brand, "entity": "software",
                                      "limit": 10}), timeout=15)
        if err or not isinstance(data, dict):
            self._connector_status("mobile_app", "Apple App Store (iTunes Search API)",
                                   False, f"lookup unavailable: {err or 'no data'}")
            return

        results = data.get("results", []) or []
        # word-boundary match — a raw substring check would false-positive on
        # e.g. "Quinceanera Planner" for the brand token "quince"
        brand_re = re.compile(r"\b" + re.escape(brand.lower()) + r"\b")
        matches = [r for r in results
                  if brand_re.search(str(r.get("sellerName", "")).lower())
                  or brand_re.search(str(r.get("trackName", "")).lower())]
        if not matches:
            self._add(OsintFinding(
                category="mobile_app",
                title="No matching iOS app found (App Store)",
                subject=self.domain, severity="info", confidence="low",
                source="Apple iTunes Search API",
                evidence=f"0/{len(results)} results matched the brand token.",
                risk="No confirmed iOS presence via this search — verify manually; "
                     "Google Play has no equivalent free public API.",
                recommendation="Manually confirm official app listings on both "
                               "stores and check for impersonating clones."))
            return

        for r in matches[:5]:
            self._add(OsintFinding(
                category="mobile_app",
                title=f"iOS app: {r.get('trackName','?')}",
                subject=str(r.get("bundleId", r.get("trackName", ""))),
                severity="info", confidence="medium",
                source="Apple iTunes Search API",
                evidence=f"seller={r.get('sellerName','')}; "
                         f"version={r.get('version','')}; "
                         f"updated={str(r.get('currentVersionReleaseDate',''))[:10]}; "
                         f"minOS={r.get('minimumOsVersion','')}",
                risk="App Store metadata (version, update cadence, permissions) "
                     "is public and can reveal stale/vulnerable app builds.",
                recommendation="Keep the app updated; monitor for impersonating "
                               "clones using a similar name/icon.",
                meta={"bundle_id": r.get("bundleId"), "track_id": r.get("trackId"),
                      "url": r.get("trackViewUrl", "")}))

    # -- Public Document Analysis (metadata of docs already on disk) ----
    def collect_public_documents(self):
        exts = (".pdf", ".docx", ".xlsx", ".pptx", ".doc", ".xls", ".ppt")
        found: List[Path] = []
        for rel in ("09_crawling", "20_api_deep_discovery"):
            d = self.scan_dir / rel
            if not d.is_dir():
                continue
            for p in d.rglob("*"):
                if p.is_file() and p.suffix.lower() in exts:
                    found.append(p)
        if not found:
            self._add(OsintFinding(
                category="public_documents",
                title="No public documents discovered during crawl",
                subject=self.domain, severity="info", confidence="low",
                source="crawl artifacts",
                evidence="No .pdf/.docx/.xlsx/.pptx files found on disk.",
                risk="Either no public documents are exposed, or crawling did not "
                     "download binary files.",
                recommendation="Re-run crawling with document capture enabled for "
                               "fuller coverage."))
            return

        self._add(OsintFinding(
            category="public_documents",
            title=f"{len(found)} public document(s) discovered",
            subject=self.domain, severity="low", confidence="high",
            source="crawl artifacts",
            evidence=", ".join(p.name for p in found[:10]),
            risk="Public documents often embed author names, internal usernames, "
                 "software versions, and file paths in metadata.",
            recommendation="Strip metadata before publishing documents; audit "
                           "existing public files for sensitive properties.",
            meta={"files": [p.name for p in found[:100]]}))

        try:
            import pypdf  # type: ignore
        except Exception:
            self._connector_status(
                "public_documents", "PDF metadata extraction (pypdf)", False,
                "install pypdf to extract author/producer metadata from PDFs")
            return

        authors = set()
        for p in [f for f in found if f.suffix.lower() == ".pdf"][:20]:
            try:
                meta = pypdf.PdfReader(str(p)).metadata or {}
                for key in ("/Author", "/Producer", "/Creator"):
                    v = meta.get(key)
                    if v and str(v).strip():
                        authors.add(str(v).strip())
            except Exception:
                continue
        if authors:
            self._add(OsintFinding(
                category="public_documents",
                title=f"Document metadata reveals {len(authors)} author/tool value(s)",
                subject=f"{self.domain}:doc-metadata", severity="low", confidence="medium",
                source="PDF metadata (pypdf)",
                evidence=", ".join(sorted(authors)[:10]),
                risk="Author/producer metadata can leak employee usernames and "
                     "internal software (versions useful for exploit targeting).",
                recommendation="Strip document metadata before publishing.",
                meta={"authors": sorted(authors)[:50]}))

    # -- News & Media (Google News RSS — free, public, no key) -----------
    def collect_news_media(self):
        if self.offline or not self.domain:
            return
        brand = self.domain.split(".")[0]
        url = ("https://news.google.com/rss/search?"
               + urllib.parse.urlencode({"q": f'"{brand}"', "hl": "en-US",
                                        "gl": "US", "ceid": "US:en"}))
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(req, timeout=15,
                                        context=_SSL_CONTEXT) as r:
                body = r.read()
        except Exception as e:
            self._connector_status("news_media", "Google News RSS", False,
                                   f"query error: {str(e)[:120]}")
            return

        try:
            root = ET.fromstring(body)
        except Exception:
            return
        items = []
        for item in root.findall(".//item")[:15]:
            title = (item.findtext("title") or "").strip()
            pub = (item.findtext("pubDate") or "").strip()
            link = (item.findtext("link") or "").strip()
            if title:
                items.append({"title": title, "pubDate": pub, "link": link})
        if not items:
            self._add(OsintFinding(
                category="news_media",
                title="No recent news mentions found",
                subject=self.domain, severity="info", confidence="low",
                source="Google News RSS",
                evidence="0 items returned for the brand query.",
                risk="Low public news footprint (or brand token is too generic "
                     "to search reliably).",
                recommendation="No action needed."))
            return

        # incident/attention keywords worth flagging for a social-engineering
        # pretext window (breach, layoffs, M&A activity, leadership change)
        alert_kw = ("breach", "hack", "ransomware", "layoff", "lawsuit",
                   "acquisition", "acquire", "merger", "outage", "leak",
                   "resign", "ceo", "investigation")
        flagged = [i for i in items
                  if any(k in i["title"].lower() for k in alert_kw)]
        self._add(OsintFinding(
            category="news_media",
            title=f"{len(items)} recent news mention(s)",
            subject=self.domain, severity="medium" if flagged else "info",
            confidence="medium", source="Google News RSS",
            evidence="; ".join(i["title"] for i in items[:6]),
            risk=("Coverage includes incident/organisational-change keywords — "
                  "these events are commonly used as phishing/social-engineering "
                  "pretexts." if flagged else
                  "Recent coverage; monitor for events attackers could use as "
                  "context for pretexting."),
            recommendation="Brief staff when incident/M&A/leadership news breaks — "
                           "these windows see elevated targeted phishing.",
            meta={"items": items[:15], "flagged": [i["title"] for i in flagged]}))

    # -- Ransomware & Extortion Listings (public leak-site tracker) ------
    def collect_ransomware(self):
        if self.offline or not self.domain:
            return
        data, err = self._http_json(
            "https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json",
            timeout=25)
        if err or not isinstance(data, list):
            self._connector_status(
                "ransomware", "Ransomware leak-site tracker (ransomwatch)", False,
                f"feed unavailable: {err or 'no data'}")
            return

        brand = re.sub(r"[^a-z0-9]", "", self.domain.split(".")[0].lower())
        if len(brand) < 4:      # too short → unacceptable false-positive rate
            return
        brand_re = re.compile(r"\b" + re.escape(brand) + r"\b", re.IGNORECASE)
        hits = [row for row in data
               if brand_re.search(str(row.get("post_title", "")))]

        if not hits:
            self._add(OsintFinding(
                category="ransomware",
                title="No ransomware leak-site listings found",
                subject=self.domain, severity="info", confidence="medium",
                source="ransomwatch (public leak-site tracker)",
                evidence=f"0/{len(data)} tracked posts matched the brand token.",
                risk="No known ransomware-group victim posting at time of query.",
                recommendation="Keep monitoring — trackers cover known leak sites "
                               "only, not the full extortion ecosystem."))
            return

        groups = sorted({h.get("group_name", "?") for h in hits})
        self._add(OsintFinding(
            category="ransomware",
            title=f"Possible ransomware victim listing ({len(hits)} match(es))",
            subject=self.domain, severity="critical", confidence="low",
            source="ransomwatch (public leak-site tracker)",
            evidence="; ".join(f"{h.get('post_title')} — {h.get('group_name')} "
                               f"({str(h.get('discovered',''))[:10]})"
                               for h in hits[:5]),
            risk="A brand-token match on a ransomware leak site — verify "
                 "immediately; this is a low-confidence textual match, not a "
                 "confirmed compromise.",
            recommendation="Manually verify each listing (post title collisions "
                           "happen); if genuine, activate incident response.",
            meta={"groups": groups, "matches": len(hits)}))

    # -- connector status helper -----------------------------------------
    def _connector_status(self, category: str, name: str, configured: bool,
                          hint: str):
        self._add(OsintFinding(
            category=category,
            title=f"{name}: {'configured' if configured else 'not configured'}",
            subject=name, severity="info",
            confidence="high", source="connector",
            evidence=hint,
            risk="" if configured else
                 "Monitoring source inactive — exposure via this channel is not "
                 "being observed.",
            recommendation=hint,
            meta={"connector": name, "configured": configured}))

    # -- Ad & Brand Impersonation (Meta Ad Library — free, public) -----
    def collect_ad_fraud(self):
        if self.offline or not self.domain:
            return
        brand = self.domain.split(".")[0]
        ad_library_url = (
            "https://www.facebook.com/ads/library/?active_status=active"
            f"&ad_type=all&country=ALL&q={urllib.parse.quote(brand)}")
        google_ads_url = (
            "https://adstransparency.google.com/?region=anywhere"
            f"&query={urllib.parse.quote(brand)}")
        self._add(OsintFinding(
            category="ad_fraud",
            title="Meta Ad Library brand search (manual review)",
            subject=f"{self.domain}:meta-ads", severity="medium",
            confidence="low", source="Meta Ad Library (public)",
            evidence=f"Search URL: {ad_library_url}",
            risk="Attackers run paid ads under a brand name to drive traffic "
                 "to phishing pages, fake app downloads, or cloaked landing "
                 "pages. Meta's Ad Library is the only public, free way to "
                 "discover these campaigns.",
            recommendation="Review active ads for your brand periodically; "
                           "report impersonating ads to Meta's takedown form.",
            meta={"search_url": ad_library_url, "platform": "meta"}))
        self._add(OsintFinding(
            category="ad_fraud",
            title="Google Ads Transparency Center brand search",
            subject=f"{self.domain}:google-ads", severity="medium",
            confidence="low", source="Google Ads Transparency Center",
            evidence=f"Search URL: {google_ads_url}",
            risk="Fake Google Ads under your brand can redirect to cloaked "
                 "landing pages distributing malware or harvesting credentials.",
            recommendation="Review the Google Ads Transparency Center; report "
                           "trademark-violating ads via Google's IP complaint form.",
            meta={"search_url": google_ads_url, "platform": "google"}))
        brand_typosquats = [f for f in self.findings.values()
                            if f.category == "brand"
                            and f.severity in ("high", "critical")]
        if brand_typosquats:
            self._add(OsintFinding(
                category="ad_fraud",
                title=f"{len(brand_typosquats)} typosquat domain(s) may run ads",
                subject=f"{self.domain}:typosquat-ads", severity="high",
                confidence="medium",
                source="cross-reference (brand + ad_fraud)",
                evidence="; ".join(f.subject for f in brand_typosquats[:8]),
                risk="Live typosquat domains with MX or web presence can also "
                     "run paid ads, amplifying their phishing reach beyond "
                     "organic search.",
                recommendation="Search each typosquat domain in the Meta Ad "
                               "Library and Google Transparency Center."))

    # -- Malicious Landing Page Detection ----------------------------------
    def collect_malicious_landing(self):
        if self.offline or not self.domain:
            return
        domains_to_check = set()
        for f in self.findings.values():
            if f.category == "brand" and f.severity in ("high", "critical"):
                subj = f.subject.lower().strip()
                if subj and subj != self.domain:
                    domains_to_check.add(subj)
        domains_to_check = list(domains_to_check)[:15]

        # Google Safe Browsing Lookup API (free, 10k/day)
        sb_key = self.cfg.get("safebrowsing", "")
        if sb_key and domains_to_check:
            threat_entries = [{"url": f"https://{d}/"} for d in domains_to_check[:10]]
            payload = json.dumps({
                "client": {"clientId": "arise-easm", "clientVersion": "1.0"},
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING",
                                    "UNWANTED_SOFTWARE",
                                    "POTENTIALLY_HARMFUL_APPLICATION"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": threat_entries,
                }
            }).encode()
            sb_url = (
                "https://safebrowsing.googleapis.com/v4/threatMatches:find"
                f"?key={sb_key}")
            req = urllib.request.Request(
                sb_url, data=payload,
                headers={"Content-Type": "application/json",
                         "User-Agent": USER_AGENT},
                method="POST")
            try:
                with urllib.request.urlopen(req, timeout=15,
                                            context=_SSL_CONTEXT) as r:
                    sb_data = json.loads(r.read().decode("utf-8", "ignore"))
                matches = sb_data.get("matches", []) or []
                if matches:
                    flagged = set()
                    for m in matches:
                        flagged.add(m.get("threat", {}).get("url", ""))
                    self._add(OsintFinding(
                        category="malicious_landing",
                        title=f"{len(flagged)} domain(s) flagged by Google Safe Browsing",
                        subject=f"{self.domain}:safebrowsing",
                        severity="critical", confidence="high",
                        source="Google Safe Browsing API",
                        evidence="; ".join(sorted(flagged)[:10]),
                        risk="Google's crawler has confirmed these URLs serve "
                             "malware, phishing, or unwanted software.",
                        recommendation="Initiate takedown immediately; these are "
                                       "active threats to your users.",
                        meta={"flagged": sorted(flagged), "matches": matches[:20]}))
                else:
                    self._add(OsintFinding(
                        category="malicious_landing",
                        title="No typosquats flagged by Google Safe Browsing",
                        subject=f"{self.domain}:safebrowsing", severity="info",
                        confidence="high", source="Google Safe Browsing API",
                        evidence=f"Checked {len(threat_entries)} typosquat URLs — "
                                 f"none flagged.",
                        risk="Clean at scan time; does not guarantee safety.",
                        recommendation="Re-check periodically; Safe Browsing "
                                       "lists update continuously."))
            except Exception as e:
                # The key IS configured — the query failed. Reporting this as
                # "not configured" would send the operator to fix Settings when
                # the real problem is reachability.
                self._connector_status(
                    "malicious_landing", "Google Safe Browsing", True,
                    f"query failed ({str(e)[:100]}) — typosquat reputation was "
                    f"NOT assessed on this run; this is not a clean verdict.")
        elif not sb_key:
            self._connector_status(
                "malicious_landing", "Google Safe Browsing", False,
                "Set GOOGLE_SAFEBROWSING_KEY in Settings to enable. "
                "Free: https://console.cloud.google.com/apis/api/"
                "safebrowsing.googleapis.com")

        # VirusTotal domain report (free tier: 4 req/min)
        vt_key = self.cfg.get("virustotal", "")
        if vt_key:
            checked = 0
            vt_targets = (domains_to_check or [self.domain])[:4]
            vt_errors: List[str] = []
            for d in vt_targets:
                data, err = self._http_json(
                    f"https://www.virustotal.com/api/v3/domains/{d}",
                    headers={"x-apikey": vt_key}, timeout=15)
                if err:
                    # 404 = VT has never seen the domain: a real answer, and for
                    # a freshly-registered typosquat an expected one.
                    if err.strip() != "http 404":
                        vt_errors.append(f"{d}: {err}")
                    continue
                checked += 1
                attrs = (data or {}).get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0) + stats.get("suspicious", 0)
                if malicious > 0:
                    self._add(OsintFinding(
                        category="malicious_landing",
                        title=f"VirusTotal: {d} flagged by {malicious} engine(s)",
                        subject=f"{d}:virustotal", severity="high" if malicious >= 3
                                else "medium", confidence="high",
                        source="VirusTotal",
                        evidence=f"malicious={stats.get('malicious',0)}, "
                                 f"suspicious={stats.get('suspicious',0)}, "
                                 f"clean={stats.get('harmless',0)}, "
                                 f"undetected={stats.get('undetected',0)}",
                        risk="Multiple AV engines classify this domain as "
                             "malicious — active threat to users who land here.",
                        recommendation="Initiate domain takedown; report to "
                                       "registrar abuse contact.",
                        meta={"domain": d, "stats": stats,
                              "reputation": attrs.get("reputation", 0)}))
            if checked:
                self._add(OsintFinding(
                    category="malicious_landing",
                    title=f"VirusTotal: {checked} domain(s) checked",
                    subject=f"{self.domain}:virustotal-scan", severity="info",
                    confidence="high", source="VirusTotal",
                    evidence=f"Checked {checked} of {len(vt_targets)} domains "
                             f"against 70+ AV engines."
                             + (f" {len(vt_errors)} lookup(s) failed."
                                if vt_errors else ""),
                    risk="", recommendation="",
                    meta={"checked": checked, "attempted": len(vt_targets),
                          "errors": vt_errors}))
            if vt_errors:
                self._connector_status(
                    "malicious_landing", "VirusTotal", True,
                    f"{len(vt_errors)} of {len(vt_targets)} domain lookup(s) "
                    f"failed ({'; '.join(vt_errors[:3])}) — reputation coverage "
                    f"is partial"
                    + ("; no domain was successfully checked, so this run "
                       "provides no reputation evidence."
                       if not checked else "."))
        else:
            self._connector_status(
                "malicious_landing", "VirusTotal", False,
                "Set VIRUSTOTAL_API_KEY in Settings to enable. "
                "Free tier: 4 req/min. https://www.virustotal.com/gui/join-us")

        # Redirect chain analysis on typosquat domains (stdlib, no key)
        for d in domains_to_check[:5]:
            chain = self._follow_redirects(f"https://{d}/")
            if not chain:
                chain = self._follow_redirects(f"http://{d}/")
            if chain and len(chain) > 1:
                final = chain[-1]
                apk_download = any(u.lower().endswith(".apk") for u in chain)
                sev = "critical" if apk_download else (
                    "high" if final != chain[0] and self.domain not in final
                    else "low")
                self._add(OsintFinding(
                    category="malicious_landing",
                    title=f"Redirect chain: {d} → {len(chain)} hop(s)",
                    subject=f"{d}:redirect-chain", severity=sev,
                    confidence="medium",
                    source="HTTP redirect follow",
                    evidence=" → ".join(chain[:8]),
                    risk=("APK download detected in redirect chain — likely "
                          "distributing a malicious mobile app." if apk_download
                          else "Redirect chain lands on a different domain — "
                               "potential cloaked phishing page."),
                    recommendation="Capture the full chain; check the final "
                                   "destination for credential harvesting or "
                                   "malware payload.",
                    meta={"chain": chain, "apk_detected": apk_download}))

    def _follow_redirects(self, url: str, max_hops: int = 8) -> list:
        chain = [url]
        for _ in range(max_hops):
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT},
                                         method="HEAD")
            try:
                with urllib.request.urlopen(req, timeout=8,
                                            context=_SSL_CONTEXT) as r:
                    final = r.url
                    if final and final != url:
                        chain.append(final)
                        url = final
                    else:
                        break
            except urllib.error.HTTPError as e:
                if e.code in (301, 302, 303, 307, 308):
                    loc = e.headers.get("Location", "")
                    if loc:
                        chain.append(loc)
                        url = loc
                    else:
                        break
                else:
                    break
            except Exception:
                break
        return chain if len(chain) > 1 else []

    # -- Enhanced Mobile App: Google Play multi-region ---------------------
    def collect_mobile_app_play(self):
        if self.offline or not self.domain:
            return
        brand = self.domain.split(".")[0]
        countries = ["us", "in", "gb", "de", "br", "id", "ph", "ng"]
        play_url = (f"https://play.google.com/store/search?"
                    f"q={urllib.parse.quote(brand)}&c=apps")
        self._add(OsintFinding(
            category="mobile_app",
            title="Google Play Store brand search (multi-region)",
            subject=f"{self.domain}:play-store", severity="medium",
            confidence="low", source="Google Play Store (public)",
            evidence=f"Search URL: {play_url}",
            risk="Fake apps impersonating your brand may exist on the Play "
                 "Store in regional storefronts — India, SE Asia, and Africa "
                 "see the highest volumes of fake rummy/gambling/finance apps.",
            recommendation="Search each regional Play Store for your brand; "
                           "file trademark takedowns for impersonating apps.",
            meta={"search_url": play_url, "countries": countries}))
        itunes_countries = ["US", "IN", "GB", "DE", "BR"]
        brand_re = re.compile(r"\b" + re.escape(brand.lower()) + r"\b")
        total_found = 0
        regions = itunes_countries[1:]
        failed_regions: List[str] = []
        for cc in regions:
            data, err = self._http_json(
                "https://itunes.apple.com/search?"
                + urllib.parse.urlencode({"term": brand, "entity": "software",
                                          "limit": 5, "country": cc}),
                timeout=10)
            if err or not isinstance(data, dict):
                failed_regions.append(f"{cc}({err or 'no data'})")
                continue
            results = data.get("results", []) or []
            matches = [r for r in results
                       if brand_re.search(str(r.get("sellerName", "")).lower())
                       or brand_re.search(str(r.get("trackName", "")).lower())]
            for r in matches[:3]:
                total_found += 1
                self._add(OsintFinding(
                    category="mobile_app",
                    title=f"iOS app ({cc}): {r.get('trackName','?')}",
                    subject=f"{r.get('bundleId', r.get('trackName', ''))}:{cc}",
                    severity="info", confidence="medium",
                    source=f"Apple iTunes Search API ({cc})",
                    evidence=f"seller={r.get('sellerName','')}; "
                             f"version={r.get('version','')}; "
                             f"country={cc}",
                    risk="Regional app listings may differ from the primary "
                         "storefront; fake apps often target specific countries.",
                    recommendation="Verify each regional listing is the official "
                                   "app; report trademark-violating clones.",
                    meta={"bundle_id": r.get("bundleId"),
                          "track_id": r.get("trackId"),
                          "country": cc,
                          "url": r.get("trackViewUrl", "")}))

        if failed_regions:
            self._connector_status(
                "mobile_app", "Apple iTunes Search (regional)", True,
                f"{len(failed_regions)} of {len(regions)} regional storefront "
                f"queries failed ({', '.join(failed_regions[:4])}) — regional "
                f"clone detection is incomplete for those markets."
                + (" No region was successfully queried, so this run provides "
                   "no evidence either way."
                   if len(failed_regions) == len(regions) else ""))

    # -- Enhanced Social: Telegram + YouTube --------------------------------
    def collect_social_telegram(self):
        if self.offline or not self.domain:
            return
        brand = self.domain.split(".")[0]

        # Telegram public channel probe (t.me/s/ is publicly viewable)
        tg_url = f"https://t.me/s/{brand}"
        req = urllib.request.Request(tg_url, headers={"User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(req, timeout=10,
                                        context=_SSL_CONTEXT) as r:
                body = r.read().decode("utf-8", "ignore")
            if "tgme_page_title" in body or "tgme_channel_info" in body:
                title_m = re.search(
                    r'class="tgme_page_title"[^>]*>.*?<span[^>]*>(.*?)</span>',
                    body, re.DOTALL)
                ch_title = title_m.group(1).strip() if title_m else brand
                members_m = re.search(
                    r'class="tgme_page_extra"[^>]*>(.*?)</div>', body, re.DOTALL)
                members = members_m.group(1).strip() if members_m else ""
                self._add(OsintFinding(
                    category="social",
                    title=f"Telegram public channel: @{brand}",
                    subject=f"{self.domain}:telegram", severity="medium",
                    confidence="medium", source="Telegram (t.me)",
                    evidence=f"Channel: {ch_title}; {members}; URL: {tg_url}",
                    risk="Telegram channels distributing APKs or promoting fake "
                         "apps/gambling under your brand are a top vector for "
                         "mobile-first fraud campaigns.",
                    recommendation="Verify channel ownership; if impersonating, "
                                   "report to Telegram abuse.",
                    meta={"url": tg_url, "title": ch_title}))
            elif "tgme_page_description" not in body:
                self._add(OsintFinding(
                    category="social",
                    title=f"Telegram: @{brand} appears unclaimed",
                    subject=f"{self.domain}:telegram", severity="low",
                    confidence="medium", source="Telegram (t.me)",
                    evidence=f"No public channel at {tg_url}",
                    risk="An unclaimed Telegram handle matching your brand can "
                         "be registered by an impersonator.",
                    recommendation="Register the Telegram channel/username "
                                   "defensively."))
        except Exception as e:
            self.log(f"telegram probe failed: {e}")

        # Telegram Bot API search (if token configured)
        tg_token = self.cfg.get("telegram", "")
        if tg_token:
            search_terms = [brand, f"{brand} app", f"{brand} apk"]
            for term in search_terms[:2]:
                pass  # Bot API doesn't support channel search directly

        # YouTube Data API v3 (free, 10k units/day)
        yt_key = self.cfg.get("youtube", "")
        if yt_key:
            yt_data, yt_err = self._http_json(
                "https://www.googleapis.com/youtube/v3/search?"
                + urllib.parse.urlencode({
                    "part": "snippet", "q": f'"{brand}" app download',
                    "type": "video", "maxResults": 5, "key": yt_key}),
                timeout=15)
            if not yt_err and isinstance(yt_data, dict):
                items = yt_data.get("items", []) or []
                if items:
                    titles = [i.get("snippet", {}).get("title", "")
                              for i in items[:5]]
                    channels = list({i.get("snippet", {}).get("channelTitle", "")
                                     for i in items[:5]})
                    self._add(OsintFinding(
                        category="social",
                        title=f"{len(items)} YouTube video(s) mentioning brand",
                        subject=f"{self.domain}:youtube", severity="medium",
                        confidence="medium", source="YouTube Data API v3",
                        evidence="; ".join(titles[:3]),
                        risk="YouTube videos promoting fake apps or APK "
                             "downloads are a common distribution channel; "
                             "videos rank in Google search results.",
                        recommendation="Review videos for brand impersonation; "
                                       "report violating content to YouTube.",
                        meta={"videos": items[:5], "channels": channels}))
            else:
                self._connector_status("social", "YouTube Data API", False,
                                       f"query error: {yt_err}")
        else:
            self._connector_status("social", "YouTube Data API v3", False,
                                   "Set YOUTUBE_API_KEY in Settings. Free: "
                                   "https://console.cloud.google.com/apis/api/"
                                   "youtube.googleapis.com")

    # -- Government Site Injection Detection --------------------------------
    def collect_gov_injection(self):
        if self.offline or not self.domain:
            return
        brand = self.domain.split(".")[0]
        if len(brand) < 3:
            return

        # Wayback Machine CDX API (free, no auth)
        gov_suffixes = [".gov.in", ".nic.in", ".ac.in"]
        total_hits = 0
        all_injections = []
        queried_ok: List[str] = []
        query_errors: List[str] = []
        for suffix in gov_suffixes:
            cdx_url = (
                "https://web.archive.org/cdx/search/cdx?"
                + urllib.parse.urlencode({
                    "url": f"*{suffix}/*",
                    "output": "json",
                    "fl": "original,timestamp,statuscode",
                    "filter": f"original:.*{brand}.*",
                    "limit": 20,
                    "from": (datetime.now(timezone.utc) - timedelta(days=365)
                             ).strftime("%Y"),
                }))
            data, err = self._http_json(cdx_url, timeout=20)
            if err:
                query_errors.append(f"{suffix}: {err}")
                continue
            if not isinstance(data, list):
                query_errors.append(f"{suffix}: unexpected response shape")
                continue
            # A valid CDX reply with <2 rows is a real "no captures" answer.
            queried_ok.append(suffix)
            if len(data) < 2:
                continue
            header = data[0]
            for row in data[1:]:
                rec = dict(zip(header, row))
                url = rec.get("original", "")
                ts = rec.get("timestamp", "")
                if brand.lower() in url.lower():
                    total_hits += 1
                    all_injections.append({
                        "url": url,
                        "timestamp": ts,
                        "wayback": f"https://web.archive.org/web/{ts}/{url}",
                    })

        if total_hits > 0:
            sev = "critical" if total_hits >= 3 else "high"
            self._add(OsintFinding(
                category="gov_injection",
                title=f"{total_hits} gov site(s) contain brand references",
                subject=f"{self.domain}:gov-injection", severity=sev,
                confidence="medium",
                source="Wayback Machine CDX API",
                evidence="; ".join(
                    i["url"] for i in all_injections[:5]),
                risk="Brand name or app references injected into government "
                     "websites (.gov.in/.nic.in/.ac.in) indicates SEO spam "
                     "injection or defacement — these pages rank highly in "
                     "search and lend false legitimacy to fake downloads.",
                recommendation="Capture WARC evidence; file a CERT-In alert; "
                               "contact the site's webmaster for remediation.",
                meta={"injections": all_injections[:50],
                      "suffixes_checked": queried_ok,
                      "suffixes_failed": query_errors}))
        elif queried_ok:
            # Only claim "clean" for the archives we actually reached.
            self._add(OsintFinding(
                category="gov_injection",
                title="No government site injections detected (Wayback)"
                      + ("" if not query_errors else
                         f" — {len(query_errors)} archive(s) unreachable"),
                subject=f"{self.domain}:gov-injection", severity="info",
                confidence="medium" if not query_errors else "low",
                source="Wayback Machine CDX API",
                evidence=f"Checked {', '.join(queried_ok)} for '{brand}' "
                         f"references — none found."
                         + ("" if not query_errors else
                            f" NOT checked: {'; '.join(query_errors)}."),
                risk="Clean at scan time for the archives queried; injection "
                     "campaigns can appear at any time."
                     + ("" if not query_errors else
                        " Coverage is partial — the unreachable archives were "
                        "not assessed."),
                recommendation="Re-check periodically; consider monitoring "
                               "Google search results for site:gov.in brand "
                               "mentions.",
                meta={"suffixes_checked": queried_ok,
                      "suffixes_failed": query_errors}))
        else:
            # Nothing was reachable — say so instead of implying a clean result.
            self._connector_status(
                "gov_injection", "Wayback Machine CDX API", True,
                "all archive queries failed (" + "; ".join(query_errors)
                + ") — government-site injection was NOT assessed on this run; "
                  "this is not evidence that no injection exists.")

        # CommonCrawl index (free, no auth)
        cc_url = (
            "https://index.commoncrawl.org/CC-MAIN-2024-10-index?"
            + urllib.parse.urlencode({
                "url": f"*.gov.in/*{brand}*",
                "output": "json",
                "limit": 10,
            }))
        cc_data, cc_err = self._http_json(cc_url, timeout=20)
        if not cc_err and isinstance(cc_data, list) and cc_data:
            cc_urls = [r.get("url", "") for r in cc_data if r.get("url")]
            if cc_urls:
                self._add(OsintFinding(
                    category="gov_injection",
                    title=f"CommonCrawl: {len(cc_urls)} gov page(s) with brand",
                    subject=f"{self.domain}:commoncrawl-gov",
                    severity="high", confidence="medium",
                    source="CommonCrawl Index",
                    evidence="; ".join(cc_urls[:5]),
                    risk="Independent crawl corpus confirms brand references "
                         "in government pages — strengthens injection signal.",
                    recommendation="Cross-reference with Wayback evidence; "
                                   "file CERT-In notification.",
                    meta={"urls": cc_urls[:20]}))

    # ================================================================
    # BASELINE / CONTINUOUS MONITORING
    # ================================================================
    def _baseline_path(self) -> Path:
        root = self.scan_dir.parent.parent  # scans/<scan>/  -> project root
        state_dir = root / "state" / self.domain
        state_dir.mkdir(parents=True, exist_ok=True)
        return state_dir / "osint_baseline.json"

    def apply_baseline(self):
        """Mark findings new vs the previous run, then persist the new baseline."""
        path = self._baseline_path()
        prev_keys: set = set()
        if path.exists():
            try:
                prev = json.loads(path.read_text())
                prev_keys = set(prev.get("keys", []))
            except Exception:
                prev_keys = set()
        for f in self.findings.values():
            if prev_keys and f.key() not in prev_keys and f.severity != "info":
                f.is_new = True
        try:
            path.write_text(json.dumps({
                "domain": self.domain, "updated": self.now,
                "keys": sorted(self.findings.keys()),
            }, indent=2))
        except Exception as e:
            self.log(f"baseline write failed: {e}")

    # ================================================================
    # WRITE
    # ================================================================
    def write(self) -> Tuple[int, dict]:
        out_dir = self.scan_dir / "18_osint_intel"
        out_dir.mkdir(parents=True, exist_ok=True)
        findings = sorted(
            self.findings.values(),
            key=lambda f: (-SEVERITY_RANK[f.severity],
                           CATEGORIES.index(f.category)
                           if f.category in CATEGORIES else 99,
                           f.subject))
        with open(out_dir / "osint_findings.jsonl", "w") as w:
            for f in findings:
                row = asdict(f)
                row["category_label"] = f.category_label
                w.write(json.dumps(row) + "\n")
        summary = self._summary(findings)
        with open(out_dir / "osint_summary.json", "w") as w:
            json.dump(summary, w, indent=2)
        return len(findings), summary

    def _summary(self, findings: List[OsintFinding]) -> dict:
        by_cat: Dict[str, dict] = {}
        by_sev = {s: 0 for s in SEVERITY_RANK}
        score = 0
        new_count = 0
        for f in findings:
            c = by_cat.setdefault(f.category, {
                "label": f.category_label, "count": 0,
                "max_severity": "info", "new": 0})
            c["count"] += 1
            if SEVERITY_RANK[f.severity] > SEVERITY_RANK[c["max_severity"]]:
                c["max_severity"] = f.severity
            by_sev[f.severity] += 1
            score += SEVERITY_WEIGHT[f.severity]
            if f.is_new:
                new_count += 1
                c["new"] += 1
        # exposure score capped 0-100; grade band
        exposure = min(100, score)
        grade = ("critical" if exposure >= 80 else "high" if exposure >= 50
                 else "medium" if exposure >= 20 else "low")
        correlation = self._correlate_threat_intel(exposure, grade)
        return {
            "domain": self.domain,
            "generated": self.now,
            "total": len(findings),
            "categories": by_cat,
            "by_severity": by_sev,
            "exposure_score": exposure,
            "grade": grade,
            "new_since_last": new_count,
            "category_order": [c for c in CATEGORIES if c in by_cat],
            "connectors": {
                "hibp": bool(self.cfg["hibp"]),
                "intelx": bool(self.cfg["intelx"]),
                "leakcheck": bool(self.cfg["leakcheck"]),
                "github": bool(self.cfg["github"]),
                "safebrowsing": bool(self.cfg["safebrowsing"]),
                "virustotal": bool(self.cfg["virustotal"]),
                "telegram": bool(self.cfg["telegram"]),
                "youtube": bool(self.cfg["youtube"]),
            },
            "correlation": correlation,
            "executive_summary": self._executive_summary(findings, exposure, grade,
                                                          correlation),
        }

    # -- Threat Intelligence Correlation ----------------------------------
    def _correlate_threat_intel(self, osint_exposure: int, osint_grade: str) -> dict:
        """Blend the passive OSINT exposure score with the active-scan
        vulnerability count already recorded in manifest.json, so a defender
        sees one combined risk picture instead of two disconnected numbers."""
        manifest = self._load_json("manifest.json") or {}
        stats = manifest.get("statistics", {}) or {}
        active_vulns = int(stats.get("total_vulnerabilities", 0) or 0)
        # cheap active-scan signal, capped the same way as the OSINT score
        active_score = min(100, active_vulns * 4)
        blended = min(100, round(0.6 * osint_exposure + 0.4 * active_score))
        blended_grade = ("critical" if blended >= 80 else "high" if blended >= 50
                        else "medium" if blended >= 20 else "low")
        return {
            "active_vulnerabilities": active_vulns,
            "active_score": active_score,
            "osint_score": osint_exposure,
            "osint_grade": osint_grade,
            "blended_score": blended,
            "blended_grade": blended_grade,
        }

    def _executive_summary(self, findings: List[OsintFinding], exposure: int,
                           grade: str, correlation: dict) -> str:
        """Plain-language synthesis for the dashboard's executive panel."""
        if not findings:
            return f"No OSINT signals collected yet for {self.domain}."
        brand_hits = [f for f in findings if f.category == "brand"
                     and f.severity in ("high", "critical")]
        ransom_hits = [f for f in findings if f.category == "ransomware"
                      and f.severity == "critical"]
        breach_hits = [f for f in findings if f.category == "breach"
                      and f.severity in ("high", "critical")]
        expiring = [f for f in findings if f.category == "organization"
                   and "expires in" in f.title]

        parts = [f"{self.domain} carries a {grade.upper()} passive-OSINT "
                f"exposure ({exposure}/100), blending to a "
                f"{correlation['blended_grade'].upper()} combined risk "
                f"({correlation['blended_score']}/100) once "
                f"{correlation['active_vulnerabilities']} active-scan "
                f"vulnerabilit{'y' if correlation['active_vulnerabilities']==1 else 'ies'} "
                f"{'is' if correlation['active_vulnerabilities']==1 else 'are'} factored in."]
        if ransom_hits:
            parts.append(f"⚠ {len(ransom_hits)} possible ransomware leak-site "
                        f"match(es) require immediate manual verification.")
        if brand_hits:
            parts.append(f"{len(brand_hits)} high-risk look-alike domain(s) "
                        f"(mail-capable typosquats) are live and usable for "
                        f"phishing today.")
        if breach_hits:
            parts.append(f"Corporate credentials appear in known breach data "
                        f"({len(breach_hits)} signal(s)).")
        if expiring:
            parts.append(f"{len(expiring)} domain(s) approaching expiration — "
                        f"a lapse would let an attacker capture the apex.")
        ad_hits = [f for f in findings if f.category == "ad_fraud"
                   and f.severity in ("high", "critical")]
        if ad_hits:
            parts.append(f"{len(ad_hits)} ad-fraud/impersonation signal(s) — "
                        f"typosquat domains may be running paid ads.")
        mal_hits = [f for f in findings if f.category == "malicious_landing"
                    and f.severity in ("high", "critical")]
        if mal_hits:
            parts.append(f"{len(mal_hits)} domain(s) flagged as malicious by "
                        f"Safe Browsing/VirusTotal or redirect to suspicious "
                        f"landing pages.")
        gov_hits = [f for f in findings if f.category == "gov_injection"
                    and f.severity in ("high", "critical")]
        if gov_hits:
            parts.append(f"Brand references found injected into government "
                        f"websites — file CERT-In alert immediately.")
        if len(parts) == 1:
            parts.append("No high-severity human/brand exposure stands out this "
                        "run; continue routine monitoring.")
        return " ".join(parts)

    # ================================================================
    # ORCHESTRATION
    # ================================================================
    def run(self) -> int:
        self.log(f"scan dir: {self.scan_dir}  domain: {self.domain}")
        self.ingest()
        collectors = [
            ("organization", self.collect_organization),
            ("certificates", self.collect_certificates),
            ("brand", self.collect_brand),
            ("takeover", self.collect_takeover),
            ("supply_chain", self.collect_supply_chain),
            ("internet_exposure", self.collect_internet_exposure),
            ("email_exposure", self.collect_email_exposure),
            ("breach", self.collect_breach),
            ("ransomware", self.collect_ransomware),
            ("code_exposure", self.collect_code_exposure),
            ("api_docs", self.collect_api_docs),
            ("recruitment", self.collect_recruitment),
            ("mobile_app", self.collect_mobile_app),
            ("mobile_app_play", self.collect_mobile_app_play),
            ("public_documents", self.collect_public_documents),
            ("news_media", self.collect_news_media),
            ("social", self.collect_social),
            ("social_telegram", self.collect_social_telegram),
            ("ad_fraud", self.collect_ad_fraud),
            ("malicious_landing", self.collect_malicious_landing),
            ("gov_injection", self.collect_gov_injection),
        ]
        for name, fn in collectors:
            try:
                fn()
            except Exception as e:
                self.log(f"collector {name} failed: {e}")
        self.apply_baseline()
        n, summary = self.write()
        cats = ", ".join(f"{c}:{d['count']}" for c, d in summary["categories"].items())
        print(f"[osint] {n} findings — {cats}")
        print(f"[osint] exposure score {summary['exposure_score']}/100 "
              f"({summary['grade']}); {summary['new_since_last']} new since last run")
        return n


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _is_ip(s: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(str(s).strip().rstrip("."))
        return True
    except Exception:
        return False


def _short(s: str, n: int = 80) -> str:
    s = str(s)
    return s if len(s) <= n else s[:n] + "…"


def main():
    ap = argparse.ArgumentParser(
        description="ARISE OSINT & Human Exposure Intelligence — passive public-"
                    "source attack-surface intelligence over an existing scan.")
    ap.add_argument("scan_dir", help="path to a scan output directory")
    ap.add_argument("--domain", default="",
                    help="target apex domain (default: derived from scan-dir name)")
    ap.add_argument("--offline", action="store_true",
                    help="skip all network calls (crt.sh, InternetDB, dnstwist, APIs)")
    ap.add_argument("--active", action="store_true",
                    help="reserved for future light active probes")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    scan_dir = Path(args.scan_dir)
    if not scan_dir.exists():
        print(f"scan dir not found: {scan_dir}", file=sys.stderr)
        return 2

    if os.environ.get("ARISE_OSINT_OFFLINE", "").strip().lower() in ("1", "true", "yes"):
        args.offline = True

    eng = OsintIntel(scan_dir, domain=args.domain, active=args.active,
                     offline=args.offline, verbose=args.verbose)
    eng.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
