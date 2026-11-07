#!/usr/bin/env python3
"""
Multi-Cloud Storage Enumeration + Content Classification (single pass)
=====================================================================
Discovers, verifies AND classifies public cloud storage in one pass — the
listing body is inspected at the moment access is confirmed, so findings are
graded by what is actually exposed:

  * public + creds/.env/tfstate/db-dump/PII/financial  -> critical
  * public + backups / server-side source / ML models  -> high
  * public + generic (non-secret) config / logs        -> medium
  * public + dominant static web assets (marketing/CDN) -> low   (static_asset_bucket)
  * public + only images/videos                         -> low
  * public + unknown extensions / empty                 -> low   (recon breadcrumb)
  * public + allowlisted intentional-public name        -> info  (--known-public)
  * access denied (403)                                 -> low   (recon only)
  * bucket not found / private / unknown                -> DROPPED (not a finding)

Each finding carries an explicit, plain-English `status` (open | open-objects |
closed | not-found) alongside the legacy `access`/`exposure_state` fields, so the
operator/dashboard can read open-vs-closed directly.

Discovery technique (three layers, cheapest first):
  1. --preknown   verify exact DNS/crawl-discovered names (authoritative).
  2. expansion    DEFAULT: bounded keyword × high-value-affix set (backup, dev,
                  staging, assets, uploads, logs, ...) — runs on every scan so
                  buckets are found even without a wordlist. --no-expand to skip.
  3. --brute      full mutation-wordlist brute (opt-in; base × lists file, or the
                  built-in DEFAULT_AFFIXES fallback when no --mutations given).
Azure is enumerated per-CONTAINER (the only level that is ever anonymous), not
via the almost-never-anonymous account-level listing.

False-positive controls: keyword-derived (brute/expansion) names that merely
EXIST but are locked down are dropped (unattributable noise); only truly OPEN
ones are reported, tagged `attribution:keyword-derived` for the dashboard.
Severity is graded by CONFIRMED sensitivity (an object that is actually a
secret), never by a broad extension bucket — so an intentionally public CDN /
marketing bucket is not reported as a data breach (see cloud/aws.md notes).

Providers: AWS S3, Azure Blob, Google Cloud Storage, DigitalOcean Spaces,
Wasabi, Alibaba OSS (MinIO only when --minio-host is supplied).

Read-only: performs GET/HEAD/OPTIONS listing probes. It never writes to a
bucket (no PutObject / ACL-change tests).

  python3 cloud_storage_enum.py --target domain.com \
     --keywords kw.txt --mutations lists/bucket-mutations.txt \
     --providers s3,azure,gcs,digitalocean,wasabi \
     --preknown preknown.txt --output cloud_buckets.jsonl
"""

from __future__ import annotations

import sys as _sys, os as _os
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)


import argparse
import concurrent.futures
import json
import re
import sys
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import quote

try:
    import requests
    from requests.exceptions import RequestException
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


def log(msg: str) -> None:
    print(f"[cloudstore] {msg}", file=sys.stderr, flush=True)


SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

# --------------------------------------------------------------------------- #
# Content classification: filename/extension -> (bucket-purpose, severity, score)
# Ordered by descending sensitivity; the WORST match in a bucket wins.
# --------------------------------------------------------------------------- #
#
# W2 note: severity is graded by CONFIRMED sensitivity of the object, not by a
# broad extension bucket. The aws.md/gcp.md notes are explicit that an
# "intentionally public static-asset bucket with no sensitive keys" is a FALSE
# POSITIVE — so client-side web assets (.js/.css/.map that a site serves itself)
# are LOW, generic non-secret config (.yaml/.ini) is MEDIUM, and only genuinely
# secret-bearing files (.env/.tfstate/creds/keys/db-dumps/PII) are CRITICAL.
CONTENT_RULES: List[Tuple[re.Pattern, str, str, float, str]] = [
    # (pattern, file_type, severity, risk_score, purpose_category)
    (re.compile(r"\.(pem|key|ppk|pfx|jks|p12)$|id_rsa|private[_-]?key|\.ovpn$", re.I),
     "credential", "critical", 1.0, "credential_exposure"),
    (re.compile(r"\.(sql|dump|bak|db|sqlite|sqlite3|mdb|bson)$|dbdump|db[_-]?backup", re.I),
     "database", "critical", 1.0, "database_backup"),
    (re.compile(r"(^|[/_.\-])(secrets?|passwords?|passwd|api[_-]?keys?|tokens?|"
                r"access[_-]?keys?|credentials?)([/_.\-]|$)", re.I),
     "secret", "critical", 1.0, "secret_exposure"),
    # C2/C3 — Cloud credential artifacts. An exposed .publishsettings, saved ARM
    # token cache, or cloud-service package is direct cloud initial-access (see
    # memory: cloud-security-domain — Azure kill-chain credential sources).
    (re.compile(r"\.publishsettings$|(^|/)azureProfile\.json$|"
                r"(^|/)accessTokens\.json$|\.cspkg$|(^|/)\.azure/|"
                r"(^|/)gcloud/credentials|service[_-]?account.*\.json$|"
                r"(^|/)\.boto$|(^|/)\.s3cfg$", re.I),
     "cloud_credential", "critical", 1.0, "cloud_credential_exposure"),
    # C2 — Virtual-disk images / VM snapshots. VHD/VMDK theft → offline mount →
    # SAM/SYSTEM or /etc/shadow extraction → hash crack → credential reuse
    # against the live VM (Pentesting-Azure ch5 chain). CRITICAL regardless of
    # other content because the disk *is* the machine.
    (re.compile(r"\.(vhd|vhdx|vmdk|qcow2?|ova|ovf|img|vdi|raw)$|"
                r"(^|[/_.\-])(snapshot|disk[_-]?image|vm[_-]?backup)([/_.\-]|$)", re.I),
     "disk_image", "critical", 1.0, "disk_image_exposure"),
    # TRUE-SECRET config/state ONLY — .env, terraform state, package/registry
    # creds, cloud CLI creds, kube/docker config. Generic .yaml/.ini/.conf are
    # handled far lower as MEDIUM to stop benign web-config FPs.
    (re.compile(r"(^|/)\.env(\.[a-z0-9]+)?$|\.(tfstate|tfvars)$|"
                r"(^|/)\.(npmrc|pypirc|dockercfg|netrc|htpasswd|git-credentials)$|"
                r"(^|/)\.docker/config\.json$|(^|/)\.kube/config$|"
                r"(^|/)\.aws/credentials$|(^|/)credentials\.json$", re.I),
     "secret_config", "critical", 0.95, "secret_config_exposure"),
    (re.compile(r"passport|aadhaar|\bssn\b|social.?security|tax[_-]?id|driver.?licen|\bkyc\b|\bpii\b", re.I),
     "pii", "critical", 1.0, "pii_exposure"),
    (re.compile(r"invoice|receipt|payment|payout|creditcard|card[_-]?number|bank[_-]?statement|transaction", re.I),
     "financial", "critical", 0.95, "financial_data"),
    # Real ML model artifacts only — bare .bin removed (fonts/wasm/firmware FP).
    (re.compile(r"\.(pth|pt|pb|h5|hdf5|onnx|pkl|pickle|ckpt|safetensors|joblib|"
                r"caffemodel|tflite|mlmodel|npz|npy|gguf|ggml)$|"
                r"(^|[/_.\-])(model|weights|checkpoint|embeddings?|dataset)s?([/_.\-]|$)", re.I),
     "ml_artifact", "high", 0.85, "ml_model_artifact"),
    # SERVER-SIDE source, VCS dirs, and sourcemaps (which leak original source).
    # Client-side .js/.ts/.css are NOT here — a site serving its own bundle is
    # not "source code exposure" (see static-asset rules below).
    (re.compile(r"\.(py|rb|go|rs|php|cs|java|cpp|pl|sh)$|(^|/)src/|source[_-]?code|"
                r"(^|/)\.git(/|$)|(^|/)\.svn/|\.(js|css|ts)\.map$", re.I),
     "source_code", "high", 0.8, "source_code_exposure"),
    (re.compile(r"\.(tar\.gz|tgz|zip|7z|rar|gz|tar)$|(^|/)backup|(^|/)archive|snapshot", re.I),
     "backup", "high", 0.7, "backup_exposure"),
    # Generic (non-secret) config — MEDIUM, not critical.
    (re.compile(r"\.(ya?ml|conf|cfg|config|ini|properties|toml)$", re.I),
     "config", "medium", 0.5, "config_file"),
    (re.compile(r"\.log$|(^|/)logs?/|access[_-]?log|error[_-]?log", re.I),
     "log", "medium", 0.5, "log_exposure"),
    (re.compile(r"\.(mp4|webm|mkv|mov|avi|m4v|flv|wmv)$", re.I),
     "video", "low", 0.2, "video_bucket"),
    (re.compile(r"\.(jpe?g|png|gif|webp|svg|bmp|ico|tiff?|avif)$", re.I),
     "image", "low", 0.2, "image_bucket"),
    # Client-side scripts served by a site = static asset, LOW.
    (re.compile(r"\.(jsx?|tsx?|mjs|cjs)$", re.I),
     "script_asset", "low", 0.2, "static_asset_bucket"),
    (re.compile(r"\.(css|woff2?|ttf|eot|otf|html?)$", re.I),
     "static_asset", "low", 0.15, "static_asset_bucket"),
]

# Object types that, when they dominate a bucket, mark it as an intentional
# static-web / CDN / marketing bucket (aws.md/gcp.md documented FP class).
STATIC_WEB_TYPES = {"image", "video", "static_asset", "script_asset"}

REMEDIATION = {
    "critical": ("IMMEDIATE: revoke public access (Block Public Access / bucket "
                 "policy), audit access logs, rotate any exposed credentials, "
                 "enable encryption + versioning."),
    "high": ("Restrict the bucket to authenticated principals only; audit what "
             "was exposed and enable access logging."),
    "medium": ("Remove public read; logs may contain secrets/PII. Enable "
               "server-side encryption and lifecycle expiry."),
    "low": ("Confirm this bucket is intended to be public (e.g. CDN/marketing "
            "assets). Prefer a private bucket fronted by a CDN with signed URLs."),
}

# --------------------------------------------------------------------------- #
# Human-readable bucket STATUS (orthogonal to severity). `access` keeps its
# legacy values (public|forbidden|unclaimed) for backward compatibility; `status`
# is the plain open/closed signal the operator/dashboard actually wants to read.
# --------------------------------------------------------------------------- #
STATUS_OPEN = "open"                 # anonymous listing succeeded (contents visible)
STATUS_OPEN_OBJECTS = "open-objects" # listing denied but objects anonymously readable
STATUS_CLOSED = "closed"             # exists but denies anonymous access (403/401)
STATUS_NOT_FOUND = "not-found"       # NoSuchBucket / referenced-but-unclaimed

# High-value affixes always combined with each base keyword (the "targeted
# expansion" set). Kept small/curated so expansion stays fast and on-target even
# when no --mutations wordlist is supplied. The full 200-term wordlist
# (lists/bucket-mutations.txt) is layered on top ONLY in full --brute mode.
DEFAULT_AFFIXES: List[str] = [
    "backup", "backups", "bak", "archive", "archives", "dev", "development",
    "staging", "stage", "stg", "test", "testing", "qa", "uat", "sandbox", "demo",
    "prod", "production", "live", "assets", "static", "media", "images", "img",
    "files", "uploads", "upload", "download", "downloads", "data", "db",
    "database", "dumps", "logs", "log", "public", "private", "internal", "cdn",
    "storage", "store", "s3", "bucket", "content", "export", "exports", "config",
    "cfg", "secret", "secrets", "temp", "tmp", "web", "app", "apps", "api",
    "admin", "user", "users", "customer", "customers", "reports", "invoices",
]

# Common Azure Blob container names — anonymous container listing is per-container
# (?restype=container&comp=list), so once an account is confirmed to exist we
# brute a bounded set rather than relying on the almost-never-anonymous
# account-level ?comp=list. "$web" is the static-website container.
AZURE_CONTAINERS: List[str] = [
    "$web", "web", "public", "assets", "static", "media", "images", "img",
    "files", "uploads", "upload", "documents", "docs", "content", "data",
    "backup", "backups", "downloads", "export", "exports", "logs", "temp",
    "public-assets", "cdn", "www", "site", "blob", "container", "storage",
]

# --------------------------------------------------------------------------- #
# Provider probe configuration.
#   vhost  : virtual-hosted URL template (breaks TLS on dotted names)
#   path   : path-style URL template (dot-safe; preferred when name has a dot)
#   list   : query string that triggers an anonymous listing
# --------------------------------------------------------------------------- #
PROVIDERS: Dict[str, dict] = {
    "s3": {
        "out": "aws", "takeover_prone": True, "allow_dots": True,
        "vhost": "https://{name}.s3.amazonaws.com/",
        "path":  "https://s3.amazonaws.com/{name}/",
        "list":  "?list-type=2",
    },
    "gcs": {
        "out": "gcp", "takeover_prone": False, "allow_dots": True,
        "vhost": "https://storage.googleapis.com/{name}/",
        "path":  "https://storage.googleapis.com/{name}/",
        "list":  "",
    },
    "wasabi": {
        "out": "wasabi", "takeover_prone": True, "allow_dots": True,
        "vhost": "https://{name}.s3.wasabisys.com/",
        "path":  "https://s3.wasabisys.com/{name}/",
        "list":  "?list-type=2",
    },
    "digitalocean": {
        "out": "digitalocean", "takeover_prone": True, "allow_dots": True,
        "vhost": "https://{name}.nyc3.digitaloceanspaces.com/",
        "path":  "https://nyc3.digitaloceanspaces.com/{name}/",
        "list":  "?list-type=2",
    },
    "azure": {
        # Azure account names are 3-24 lowercase alnum (no dots/hyphens); we
        # probe the account's default listing endpoint.
        "out": "azure", "takeover_prone": True, "allow_dots": False,
        "vhost": "https://{name}.blob.core.windows.net/",
        "path":  "https://{name}.blob.core.windows.net/",
        "list":  "?comp=list",
    },
    "alibaba": {
        "out": "alibaba", "takeover_prone": True, "allow_dots": False,
        "vhost": "https://{name}.oss-ap-southeast-1.aliyuncs.com/",
        "path":  "https://{name}.oss-ap-southeast-1.aliyuncs.com/",
        "list":  "?list-type=2",
    },
    "minio": {  # only used when --minio-host supplied; {host} substituted then
        "out": "minio", "takeover_prone": False, "allow_dots": True,
        "vhost": "{host}/{name}/",
        "path":  "{host}/{name}/",
        "list":  "?list-type=2",
    },
}

# Listing markers that confirm an anonymous LIST succeeded.
LISTING_MARKERS = re.compile(
    r"<ListBucketResult|<ListAllMyBucketsResult|<EnumerationResults|"
    r"<Blobs>|<Contents>|<CommonPrefixes|\"items\"\s*:|<Name>", re.I)
ACCESS_DENIED_MARKER = re.compile(
    r"AccessDenied|InvalidAccessKeyId|<Code>AccessDenied|Authorization",
    re.I)
NOT_FOUND_MARKER = re.compile(
    r"NoSuchBucket|BucketNotFound|<Code>NoSuchBucket|The specified bucket does not exist"
    r"|ContainerNotFound|NoSuchKey.*bucket", re.I)
_KEY_RE = re.compile(r"<Key>([^<]+)</Key>", re.I)          # S3/GCS/Wasabi/DO objects
_BLOB_RE = re.compile(r"<Blob>.*?<Name>([^<]+)</Name>", re.I | re.S)  # Azure blobs
_JSONKEY_RE = re.compile(r"\"(?:name|key)\"\s*:\s*\"([^\"]+)\"", re.I)  # JSON listings


# Per-object blocks (carry size / last-modified / etag).
_S3_CONTENTS_RE = re.compile(r"<Contents>(.*?)</Contents>", re.I | re.S)
_AZ_BLOB_RE = re.compile(r"<Blob>(.*?)</Blob>", re.I | re.S)
_SUB = {
    "key":  re.compile(r"<Key>([^<]+)</Key>", re.I),
    "name": re.compile(r"<Name>([^<]+)</Name>", re.I),
    "size": re.compile(r"<(?:Size|Content-Length)>(\d+)</(?:Size|Content-Length)>", re.I),
    "lm":   re.compile(r"<(?:LastModified|Last-Modified)>([^<]+)</(?:LastModified|Last-Modified)>", re.I),
    "etag": re.compile(r"<E[Tt]ag>\"?([^<\"]+)\"?</E[Tt]ag>", re.I),
}
HUGE_OBJECT_BYTES = 100 * 1024 * 1024   # 100 MB — "large object" threshold


def _sub(block: str, field_re: re.Pattern, default: str = "") -> str:
    m = field_re.search(block)
    if not m:
        return default
    val = m.group(1).strip()
    # S3 XML-escapes the quotes around ETags as &quot;...&quot;
    return val.replace("&quot;", "").strip('"')


def parse_objects(body: str) -> List[dict]:
    """Extract per-object metadata (key, size, last_modified, etag) from an
    S3/GCS/Azure listing. Never returns the bucket/container-level <Name>."""
    objs: List[dict] = []
    for block in _S3_CONTENTS_RE.findall(body):        # S3 / GCS / Wasabi / DO
        key = _sub(block, _SUB["key"])
        if not key:
            continue
        objs.append({"key": key,
                     "size": int(_sub(block, _SUB["size"], "0") or 0),
                     "lm": _sub(block, _SUB["lm"]),
                     "etag": _sub(block, _SUB["etag"])})
    if not objs:
        for block in _AZ_BLOB_RE.findall(body):        # Azure
            key = _sub(block, _SUB["name"])
            if not key:
                continue
            objs.append({"key": key,
                         "size": int(_sub(block, _SUB["size"], "0") or 0),
                         "lm": _sub(block, _SUB["lm"]),
                         "etag": _sub(block, _SUB["etag"])})
    if not objs:                                        # JSON-style fallback
        for key in _JSONKEY_RE.findall(body):
            if key:
                objs.append({"key": key, "size": 0, "lm": "", "etag": ""})
    return objs


def extract_object_keys(body: str) -> List[str]:
    return [o["key"] for o in parse_objects(body)]

# S3-style name validity (also a good baseline for the S3-compatible providers).
_VALID_NAME = re.compile(r"^[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9]$")
_IP_LIKE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def valid_bucket_name(name: str, allow_dots: bool = True) -> bool:
    if not (3 <= len(name) <= 63) or not _VALID_NAME.match(name):
        return False
    if ".." in name or ".-" in name or "-." in name or _IP_LIKE.match(name):
        return False
    if not allow_dots and "." in name:
        return False
    return True


# Generic service / affix labels that must NEVER be used as a bucket-brute BASE
# keyword. base × affix of a generic word yields generic names owned by random
# third parties (api-backup, apidb, secret-api, db-api, ...), the classic
# bucket-brute false positive: for target api.myntra.com the service label 'api'
# generated 20 unrelated public buckets. These words are fine as AFFIXES
# (DEFAULT_AFFIXES), never as the thing we anchor a brute on.
GENERIC_LABELS: Set[str] = {
    "api", "apis", "www", "web", "app", "apps", "mobile", "static", "assets",
    "asset", "cdn", "media", "img", "images", "image", "files", "file", "data",
    "db", "database", "store", "storage", "cloud", "origin", "edge", "gateway",
    "gw", "proxy", "service", "services", "svc", "internal", "external",
    "public", "private", "secure", "login", "auth", "sso", "admin", "portal",
    "dashboard", "console", "dev", "development", "stage", "staging", "test",
    "testing", "qa", "uat", "sandbox", "prod", "production", "preprod", "demo",
    "beta", "alpha", "backup", "backups", "archive", "archives", "logs", "log",
    "mail", "smtp", "ftp", "ns", "dns", "vpn", "git", "ci", "status", "help",
    "support", "docs", "doc", "blog", "shop", "secret", "secrets", "token",
    "upload", "uploads", "download", "downloads", "export", "exports", "config",
    "temp", "tmp", "misc", "default", "common", "shared", "main", "site", "home",
}

# Compact set of 2-label public suffixes so we can take the registrable label
# to the LEFT of them (not a full PSL — covers the frequent ccTLD second levels).
_TWO_LABEL_TLDS: Set[str] = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "co.in", "net.in", "org.in", "gen.in",
    "ind.in", "firm.in", "co.jp", "or.jp", "ne.jp", "com.au", "net.au", "org.au",
    "com.br", "com.cn", "com.mx", "com.sg", "com.hk", "com.tr", "co.kr", "co.za",
    "co.nz", "com.ar", "com.co", "co.id", "com.my", "com.ph", "com.tw", "com.ua",
    "co.il", "com.sa", "com.eg", "com.ng", "com.pk", "com.bd", "com.vn", "com.ru",
}

_SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.\-]*://", re.I)


def registrable_label(host: str) -> str:
    """Best-effort ORG label: the label immediately left of the (possibly
    two-level) public suffix. api.myntra.com -> 'myntra'; shop.foo.co.uk ->
    'foo'; myntra.com -> 'myntra'. Returns '' for IPs / unparseable input.

    This is the only reliable anchor for bucket brute-forcing — the target's
    service subdomain label (e.g. 'api') is generic and must not be used."""
    host = (host or "").strip().strip(".").lower()
    host = _SCHEME_RE.sub("", host).split("/")[0].split(":")[0]
    if not host or _IP_LIKE.match(host):
        return ""
    labels = [l for l in host.split(".") if l]
    if len(labels) < 2:
        return host
    if ".".join(labels[-2:]) in _TWO_LABEL_TLDS and len(labels) >= 3:
        return labels[-3]
    return labels[-2]


@dataclass
class Finding:
    name: str
    provider: str                 # friendly out-name (aws/gcp/azure/...)
    url: str
    access: str                   # public|forbidden|unclaimed  (legacy field)
    # Plain-English open/closed signal: open | open-objects | closed | not-found.
    status: str = ""
    # W1 unified exposure ladder: referenced | exists | anon_accessible |
    # sensitive_confirmed — grades findings by CONFIRMED exposure, not existence.
    exposure_state: str = "exists"
    severity: str = "low"
    risk_score: float = 0.1
    risk_category: str = ""
    data_count: int = 0
    file_types: List[str] = field(default_factory=list)
    cors_enabled: bool = False
    takeover_prone: bool = False
    tags: List[str] = field(default_factory=list)
    evidence: str = ""
    remediation: str = ""
    sources: List[str] = field(default_factory=list)

    # enrichment (large objects / metadata leak / encryption / website)
    total_bytes: int = 0
    largest_bytes: int = 0
    largest_object: str = ""
    oldest_modified: str = ""
    newest_modified: str = ""
    sample_etags: List[str] = field(default_factory=list)
    object_encryption: str = ""      # AES256 | aws:kms | none | unknown
    static_website: bool = False

    # permission-probe results (?acl / ?policy / ?versions)
    acl_public_grants: List[str] = field(default_factory=list)
    writable: bool = False
    policy_readable: bool = False
    policy_public: bool = False
    versioning_enabled: bool = False
    version_count: int = 0
    delete_markers: int = 0

    # legacy-compatible aliases consumed by the pipeline scorer
    files: int = 0
    endpoint: str = ""
    note: str = ""


def _human_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{int(n)}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024.0
    return f"{n:.1f}TB"


def classify_listing(body: str) -> dict:
    """Classify a listing body by content AND extract object metadata
    (sizes, timestamps, ETags, large objects). Returns a dict."""
    objs = parse_objects(body)
    count = len(objs)
    meta = {
        "count": count, "file_types": [], "severity": "low",
        "risk_score": 0.1, "category": "empty_bucket", "classify_note": "",
        "total_bytes": 0, "largest_bytes": 0, "largest_object": "",
        "oldest_modified": "", "newest_modified": "", "sample_etags": [],
        "has_large_object": False,
    }
    if count == 0:
        return meta

    file_types: Set[str] = set()
    type_counts: Dict[str, int] = {}
    matched_objs = 0
    worst = ("low", 0.1, "storage_bucket")
    total_bytes = 0
    largest = {"size": -1, "key": ""}
    lms, etags = [], []
    for o in objs:
        total_bytes += o["size"]
        if o["size"] > largest["size"]:
            largest = {"size": o["size"], "key": o["key"]}
        if o["lm"]:
            lms.append(o["lm"])
        if o["etag"] and len(etags) < 5:
            etags.append(o["etag"])
        for pat, ftype, sev, score, cat in CONTENT_RULES:
            if pat.search(o["key"]):
                file_types.add(ftype)
                type_counts[ftype] = type_counts.get(ftype, 0) + 1
                matched_objs += 1
                if score > worst[1]:
                    worst = (sev, score, cat)
                break

    # ── Static-asset / CDN bucket suppression (W2, balanced) ─────────────────
    # If the bucket is dominated (>=80% of classified objects) by static web
    # assets AND nothing sensitive (critical/high) was found, treat it as an
    # intentional public CDN/marketing bucket → LOW, with a breadcrumb so the
    # finding is downgraded, not hidden. Directly implements the documented
    # aws.md/gcp.md "intentionally public static-asset bucket" false positive.
    note = ""
    static_count = sum(type_counts.get(t, 0) for t in STATIC_WEB_TYPES)
    if not file_types:
        # Unknown extensions no longer default to medium (was a noise source);
        # a listable bucket of unclassified objects is a LOW recon breadcrumb.
        sev, risk, cat = "low", 0.3, "unknown_content"
    elif (matched_objs and static_count / matched_objs >= 0.8
          and SEV_RANK[worst[0]] <= SEV_RANK["medium"]):
        sev, risk, cat = "low", 0.25, "static_asset_bucket"
        non_static = sorted(file_types - STATIC_WEB_TYPES)
        note = ("dominant static web assets — treated as intentional CDN/"
                "marketing bucket" +
                (f"; review incidental {', '.join(non_static)} objects"
                 if non_static else ""))
    else:
        sev, risk, cat = worst

    lms_sorted = sorted(lms)
    meta.update({
        "file_types": sorted(file_types),
        "severity": sev, "risk_score": risk, "category": cat,
        "classify_note": note,
        "total_bytes": total_bytes,
        "largest_bytes": max(largest["size"], 0),
        "largest_object": largest["key"],
        "oldest_modified": lms_sorted[0] if lms_sorted else "",
        "newest_modified": lms_sorted[-1] if lms_sorted else "",
        "sample_etags": etags,
        "has_large_object": largest["size"] >= HUGE_OBJECT_BYTES,
    })
    return meta


class CloudStorageScanner:
    def __init__(self, target: str, providers: List[str], threads: int = 25,
                 timeout: int = 6, minio_host: str = "",
                 known_public: Optional[Set[str]] = None,
                 anchor_tokens: Optional[Set[str]] = None):
        self.target = target.strip(".").lower()
        self.providers = [p for p in providers if p in PROVIDERS
                          and (p != "minio" or minio_host)]
        self.threads = threads
        self.timeout = timeout
        self.minio_host = minio_host.rstrip("/")
        self.known_public = {n.strip().lower() for n in (known_public or set())
                             if n.strip()}
        # Org tokens the target is known by (e.g. {'myntra'}). A keyword-derived
        # (brute/expansion) OPEN bucket whose NAME contains none of these cannot
        # be attributed to the target and is dropped as noise. Empty set disables
        # the check (never drop everything when we have no anchor).
        self.anchor_tokens = {t.strip().lower() for t in (anchor_tokens or set())
                              if t and len(t.strip()) >= 3}
        self.findings: Dict[Tuple[str, str], Finding] = {}
        self._lock = threading.Lock()
        self._session = requests.Session() if HAS_REQUESTS else None
        if self._session:
            self._session.headers.update({"User-Agent": "ARISE-cloudstore/1.0"})

    # ---- URL builders ----------------------------------------------------- #
    def _probe_url(self, provider: str, name: str) -> Optional[str]:
        conf = PROVIDERS[provider]
        if not valid_bucket_name(name, conf["allow_dots"]):
            return None
        tmpl = conf["path"] if ("." in name and conf.get("path")) else conf["vhost"]
        return tmpl.format(name=name, host=self.minio_host)

    # ---- network probes --------------------------------------------------- #
    def _get(self, url: str):
        try:
            return self._session.get(url, timeout=self.timeout, allow_redirects=True)
        except RequestException:
            return None

    def _cors(self, url: str) -> bool:
        try:
            r = self._session.options(url, timeout=self.timeout,
                                      headers={"Origin": "https://arise.attacker.test",
                                               "Access-Control-Request-Method": "GET"})
            acao = r.headers.get("Access-Control-Allow-Origin", "")
            return acao == "*" or "attacker.test" in acao
        except RequestException:
            return False

    def _object_headers(self, bucket_url: str, obj_key: str) -> Tuple[str, bool]:
        """HEAD the first object to read encryption + website-redirect headers
        in a single request. Returns (encryption, website_redirect_seen).
        encryption: 'AES256' | 'aws:kms' | 'azure-sse' | 'none' | 'unknown'."""
        if not obj_key:
            return "unknown", False
        try:
            obj_url = bucket_url.rstrip("/") + "/" + quote(obj_key)
            r = self._session.head(obj_url, timeout=self.timeout, allow_redirects=True)
            if r.status_code >= 400:
                return "unknown", False
            website = bool(r.headers.get("x-amz-website-redirect-location"))
            sse = r.headers.get("x-amz-server-side-encryption")
            if sse:
                return sse, website
            if r.headers.get("x-ms-server-encrypted", "").lower() == "true":
                return "azure-sse", website
            return "none", website
        except RequestException:
            return "unknown", False

    # Sensitive object keys that are never a legitimate public web asset — if one
    # of these is anonymously readable even when listing is denied, it is a real
    # exposure (not a static-site index). Kept tiny + sensitive-only so this never
    # fires on a normal CDN/marketing bucket (FP control).
    _SENSITIVE_PROBE_KEYS = (
        ".env", "backup.sql", "db.sql", "database.sql", "dump.sql",
        ".git/config", "credentials.json", ".aws/credentials",
        "config/database.yml", "wp-config.php", "backup.zip",
    )

    def _object_level_read(self, provider: str, name: str,
                           bucket_url: str) -> Tuple[bool, str]:
        """When bucket LISTING is denied, check whether individual sensitive
        objects are still anonymously readable (a common real-world exposure:
        ListBucket denied but object ACLs public-read). Probes a tiny set of
        never-legitimately-public keys; returns (found, key). Read-only HEAD/GET."""
        base = bucket_url.rstrip("/")
        for key in self._SENSITIVE_PROBE_KEYS:
            try:
                r = self._session.get(base + "/" + quote(key),
                                      timeout=self.timeout, allow_redirects=True)
            except RequestException:
                continue
            if r.status_code != 200:
                continue
            body = (r.text or "")[:512]
            # A 200 that is actually an S3/Azure error document is not a read.
            if re.search(r"<Error>|AccessDenied|NoSuchKey|<Code>|ContainerNotFound",
                         body, re.I):
                continue
            if r.content:                      # non-empty body = genuinely readable
                return True, key
        return False, ""

    def _static_website(self, provider: str, name: str) -> bool:
        """Best-effort anonymous static-website-hosting detection.

        The authoritative signal (GetBucketWebsite via ?website) requires
        authentication, so we probe the S3 website endpoint directly: a
        website-enabled bucket serves HTTP there, while a non-website bucket
        returns an S3 'NoSuchWebsiteConfiguration'/404 website error. Only
        implemented for AWS S3 (distinct website-endpoint hostname)."""
        if provider != "s3":
            return False
        for host in (f"http://{name}.s3-website-us-east-1.amazonaws.com/",
                     f"http://{name}.s3-website.us-east-1.amazonaws.com/"):
            try:
                r = self._session.get(host, timeout=self.timeout, allow_redirects=False)
            except RequestException:
                continue
            b = (r.text or "")[:2000]
            # S3 website endpoint replies (even a 403/404) carry this header;
            # a non-website bucket cannot be reached at this hostname at all.
            if "x-amz-error-code" in {k.lower() for k in r.headers} or \
               r.headers.get("Server", "").startswith("AmazonS3"):
                if re.search(r"NoSuchWebsiteConfiguration", b, re.I):
                    return False
                # 200, or a website-style error other than "not a website".
                if r.status_code == 200 or re.search(r"<html", b, re.I) \
                   or "x-amz-website" in {k.lower() for k in r.headers}:
                    return True
        return False

    def _permission_probes(self, bucket_url: str) -> dict:
        """Anonymous read of ?acl, ?policy and ?versions subresources on a
        confirmed-public bucket. All read-only; never mutates the bucket.
        Returns a dict of what each subresource exposed."""
        out = {
            "acl_public_grants": [], "policy_readable": False,
            "policy_public": False, "versioning_enabled": False,
            "version_count": 0, "delete_markers": 0,
        }
        base = bucket_url.rstrip("/")

        # ---- ?acl : public READ/WRITE ACL grants (ACL misconfiguration) ----
        try:
            r = self._session.get(base + "/?acl", timeout=self.timeout)
            if r.status_code == 200 and "<AccessControlPolicy" in (r.text or ""):
                for grant in re.findall(r"<Grant>(.*?)</Grant>", r.text, re.I | re.S):
                    gm = re.search(r"acs\.amazonaws\.com/groups/global/(\w+)", grant, re.I)
                    pm = re.search(r"<Permission>([^<]+)</Permission>", grant, re.I)
                    if gm and pm and gm.group(1).lower() in ("allusers", "authenticatedusers"):
                        out["acl_public_grants"].append(f"{gm.group(1)}:{pm.group(1)}")
        except RequestException:
            pass

        # ---- ?policy : anonymous bucket-policy disclosure ----
        try:
            r = self._session.get(base + "/?policy", timeout=self.timeout)
            if r.status_code == 200 and r.text.strip().startswith("{"):
                out["policy_readable"] = True
                try:
                    pol = json.loads(r.text)
                    for stmt in pol.get("Statement", []):
                        if stmt.get("Effect") != "Allow":
                            continue
                        pr = stmt.get("Principal")
                        if pr == "*" or (isinstance(pr, dict)
                                         and "*" in str(pr.get("AWS", ""))):
                            out["policy_public"] = True
                            break
                except Exception:
                    pass
        except RequestException:
            pass

        # ---- ?versions : versioning + deleted-object recovery ----
        try:
            r = self._session.get(base + "/?versions", timeout=self.timeout)
            if r.status_code == 200 and "<ListVersionsResult" in (r.text or ""):
                versions = len(re.findall(r"<Version>", r.text, re.I))
                markers = len(re.findall(r"<DeleteMarker>", r.text, re.I))
                if versions or markers:
                    out["versioning_enabled"] = True
                    out["version_count"] = versions
                    out["delete_markers"] = markers
        except RequestException:
            pass
        return out

    def _fetch(self, provider: str, name: str):
        """GET the listing endpoint, transparently following S3/Wasabi
        cross-region redirects (301 + x-amz-bucket-region, which `requests`
        cannot auto-follow because there is no Location header)."""
        conf = PROVIDERS[provider]
        url = self._probe_url(provider, name)
        if not url:
            return None, "", url
        r = self._get(url + conf["list"])
        if r is None:
            return None, "", url
        body = r.text or ""
        if provider in ("s3", "wasabi") and (
                r.status_code in (301, 307, 308)
                or (r.status_code == 400 and "PermanentRedirect" in body)):
            region = r.headers.get("x-amz-bucket-region") or r.headers.get("x-amz-region")
            if not region:
                m = re.search(r"<Endpoint>([^<]+)</Endpoint>", body)
                if m:
                    mr = re.search(r"s3[.-]([a-z0-9-]+)\.(?:amazonaws|wasabisys)", m.group(1))
                    if mr and mr.group(1) != "amazonaws":
                        region = mr.group(1)
            if region:
                base = "wasabisys.com" if provider == "wasabi" else "amazonaws.com"
                url = f"https://s3.{region}.{base}/{name}/"
                r2 = self._get(url + conf["list"])
                if r2 is not None:
                    r = r2
                    body = r.text or ""
        return r, body, url

    def _is_org_anchored(self, name: str) -> bool:
        """True if `name` references the target org (so a keyword-derived hit is
        attributable to it). No anchor tokens configured -> always True (we never
        drop everything for lack of an anchor). The bucket name must CONTAIN an
        anchor token as a substring (myntra-backups ✓, api-static ✗)."""
        if not self.anchor_tokens:
            return True
        n = name.lower()
        return any(tok in n for tok in self.anchor_tokens)

    def _probe(self, provider: str, name: str, source: str):
        # Azure anonymous access is per-CONTAINER, not account-level, so it needs
        # its own enumeration path (may yield several container findings).
        if provider == "azure":
            return self._azure_probe(name, source)
        conf = PROVIDERS[provider]
        r, body, url = self._fetch(provider, name)
        if r is None:
            return None  # DNS/connection failure / invalid name -> drop
        status = r.status_code

        # --- decide access ---
        if status == 404 or NOT_FOUND_MARKER.search(body):
            # Bucket does NOT exist (NoSuchBucket). This is NOT an open bucket —
            # nothing is exposed. A random brute-force miss is pure noise (drop).
            # A name the org REFERENCES (DNS/crawled link) that is unclaimed is a
            # POTENTIAL takeover vector, but from here we cannot confirm the
            # reference is authoritative/org-owned (a crawled URL may point at a
            # third-party bucket). So this is an INFO recon signal only — verify
            # ownership manually. The authoritative HIGH takeover finding comes
            # from dns_security's dangling-CNAME check, not from here.
            # DETECTION ONLY — we never create/claim the bucket.
            if source not in ("brute-force", "expansion") and conf["takeover_prone"]:
                return Finding(
                    name=name, provider=conf["out"], url=url, access="unclaimed",
                    status=STATUS_NOT_FOUND,
                    exposure_state="referenced",
                    severity="info", risk_score=0.15,
                    risk_category="unclaimed_reference",
                    tags=["unclaimed", "verify-ownership", provider],
                    evidence=(f"{conf['out'].upper()} bucket '{name}' is referenced "
                              f"(source: {source}) but does NOT exist (NoSuchBucket) — "
                              "this is not an open bucket. IF your org owns/uses this "
                              "reference it is a takeover vector; if the reference is "
                              "third-party it is informational. Verify ownership."),
                    remediation=("Confirm whether this name belongs to your org. If so, "
                                 "reclaim it or remove the DNS/app reference. If it is a "
                                 "third-party reference, no action is required."),
                    sources=[source], takeover_prone=True,
                    files=0, data_count=0, endpoint=url,
                    note="unclaimed reference (NoSuchBucket) — verify ownership")
            return None  # brute-force miss -> not a finding
        if status in (401, 403) or (status == 200 and ACCESS_DENIED_MARKER.search(body)
                                    and not LISTING_MARKERS.search(body)):
            # Access denied: the bucket EXISTS but denies anonymous listing.
            # FP reduction: a keyword-derived (brute/expansion) name that merely
            # exists somewhere in the global namespace but is locked down cannot
            # be attributed to this target — reporting it is pure noise. Only
            # keep "closed" findings for authoritative, target-tied sources
            # (DNS/crawl preknown), where the name IS the org's. For those we may
            # still find object-level public read even though listing is denied.
            if source in ("brute-force", "expansion"):
                return None
            objects_public, sample_key = self._object_level_read(provider, name, url)
            if objects_public:
                return Finding(
                    name=name, provider=conf["out"], url=url, access="public",
                    status=STATUS_OPEN_OBJECTS, exposure_state="anon_accessible",
                    severity="medium", risk_score=0.5,
                    risk_category="object_read_no_list",
                    tags=["object-public", "no-listing", provider],
                    evidence=(f"{conf['out'].upper()} bucket '{name}' denies listing "
                              f"(HTTP {status}) but objects are anonymously readable "
                              f"(e.g. '{sample_key}'). Listing is hidden; known object "
                              "keys are still exposed."),
                    remediation="Remove public-read object ACLs / bucket policy; "
                                "disabling listing alone does not protect objects.",
                    sources=[source], takeover_prone=conf["takeover_prone"],
                    files=0, data_count=0, endpoint=url,
                    note=f"objects readable, listing denied ({status})")
            return Finding(
                name=name, provider=conf["out"], url=url, access="forbidden",
                status=STATUS_CLOSED,
                exposure_state="exists",
                severity="low", risk_score=0.2, risk_category="access_denied",
                tags=["access-denied", provider],
                evidence=f"{conf['out'].upper()} bucket '{name}' exists but denies "
                         f"anonymous access (HTTP {status}). Contents not exposed.",
                remediation="No action required if intentional; confirms the bucket "
                            "is not publicly listable.",
                sources=[source], takeover_prone=conf["takeover_prone"],
                files=0, data_count=0, endpoint=url,
                note=f"access-denied ({status})")
        if status == 200 and LISTING_MARKERS.search(body):
            # FP control (api.myntra.com post-mortem): a keyword-derived
            # (brute/expansion) bucket whose NAME does not reference the target
            # org is an unattributable third-party bucket that merely happens to
            # exist and be public (e.g. 'api-static', 'secret-api', 'apidb' for
            # target api.myntra.com — none are Myntra's). Drop it. Authoritative
            # (DNS/crawl preknown) names are exempt: they were seen on the target.
            if source in ("brute-force", "expansion") and not self._is_org_anchored(name):
                return None
            m = classify_listing(body)
            count = m["count"]
            ftypes = m["file_types"]
            sev, score, cat = m["severity"], m["risk_score"], m["category"]
            cors = self._cors(url) if count else False
            if cors and sev == "low":
                sev, score = "medium", max(score, 0.5)
                cat = cat + "+cors"

            # Enrichment probes (only for confirmed public, non-empty buckets).
            encryption, website = "", False
            perms = {"acl_public_grants": [], "policy_readable": False,
                     "policy_public": False, "versioning_enabled": False,
                     "version_count": 0, "delete_markers": 0}
            if count:
                first_key = m["largest_object"] or parse_objects(body)[0]["key"]
                encryption, redirect_hdr = self._object_headers(url, first_key)
                website = redirect_hdr or self._static_website(provider, name)
                perms = self._permission_probes(url)

            # A public WRITE ACL is far worse than public read (upload/overwrite/
            # ransomware) -> force critical.
            writable = any("write" in g.lower() for g in perms["acl_public_grants"])
            if writable:
                sev, score, cat = "critical", 1.0, "public_writable"

            # W1 exposure ladder: sensitive content (or writable/publicly-granted
            # policy) is CONFIRMED sensitive; anything else merely anon-listable.
            if writable or perms["policy_public"] or SEV_RANK[sev] >= SEV_RANK["high"]:
                exposure_state = "sensitive_confirmed"
            else:
                exposure_state = "anon_accessible"

            # W5 known-public allowlist: a bucket the operator has declared an
            # intentional public asset store is a confirmed-benign FP — downgrade
            # to info (kept as a breadcrumb), never a data-breach finding, unless
            # it is world-writable (that is never intended).
            allow_note = ""
            if name.lower() in self.known_public and not writable:
                sev, score, cat = "info", 0.1, "allowlisted_public"
                exposure_state = "anon_accessible"
                allow_note = "allowlisted intentional public bucket"

            tags = ["public", provider] + ftypes
            # Attribution confidence: a keyword-derived (brute/expansion) name is
            # a lower-confidence lead than a DNS/crawl-tied one — tag it so the
            # dashboard can show "verify ownership" rather than asserting breach.
            keyword_derived = source in ("brute-force", "expansion")
            if keyword_derived:
                tags.append("attribution:keyword-derived")
            if cors:
                tags.append("cors-wildcard")
            if m["has_large_object"]:
                tags.append("large-object")
            if website:
                tags.append("static-website")
            if encryption == "none":
                tags.append("unencrypted")
            if writable:
                tags.append("world-writable")
            if perms["acl_public_grants"]:
                tags.append("public-acl")
            if perms["policy_readable"]:
                tags.append("policy-exposed")
            if perms["versioning_enabled"]:
                tags.append("versioned")

            if count == 0:
                ev = (f"{conf['out'].upper()} bucket '{name}' is publicly listable "
                      f"but currently empty.")
            else:
                extra = []
                if m["total_bytes"]:
                    extra.append(f"~{_human_bytes(m['total_bytes'])} total")
                if m["has_large_object"]:
                    extra.append(f"largest '{m['largest_object']}' "
                                 f"{_human_bytes(m['largest_bytes'])}")
                if m["newest_modified"]:
                    extra.append(f"modified {m['oldest_modified'][:10]}..{m['newest_modified'][:10]}")
                if encryption == "none":
                    extra.append("objects NOT encrypted at rest")
                if website:
                    extra.append("static-website hosting ON (phishing/abuse risk)")
                if writable:
                    extra.append(f"WORLD-WRITABLE ACL ({', '.join(perms['acl_public_grants'])}) "
                                 "— anonymous upload/overwrite/ransomware")
                elif perms["acl_public_grants"]:
                    extra.append(f"public ACL grants: {', '.join(perms['acl_public_grants'])}")
                if perms["policy_public"]:
                    extra.append("bucket policy readable AND grants public access")
                elif perms["policy_readable"]:
                    extra.append("bucket policy anonymously readable (IAM disclosure)")
                if perms["versioning_enabled"]:
                    extra.append(f"versioning ON ({perms['version_count']} versions, "
                                 f"{perms['delete_markers']} delete-markers — deleted "
                                 "objects recoverable)")
                ev = (f"{conf['out'].upper()} bucket '{name}' is PUBLICLY LISTABLE "
                      f"({count} objects"
                      + (f"; types: {', '.join(ftypes)}" if ftypes else "; unclassified")
                      + (", CORS wildcard" if cors else "") + ")"
                      + (". " + "; ".join(extra) if extra else "") + ".")
            note_bits = [b for b in (f"public listable ({cat})",
                                     m.get("classify_note", ""), allow_note,
                                     ("keyword-derived name — verify org ownership"
                                      if keyword_derived else "")) if b]
            return Finding(
                name=name, provider=conf["out"], url=url, access="public",
                status=STATUS_OPEN,
                exposure_state=exposure_state,
                severity=sev, risk_score=score, risk_category=cat,
                data_count=count, file_types=ftypes, cors_enabled=cors,
                tags=tags, evidence=ev, remediation=REMEDIATION.get(sev, ""),
                sources=[source], takeover_prone=conf["takeover_prone"],
                total_bytes=m["total_bytes"], largest_bytes=m["largest_bytes"],
                largest_object=m["largest_object"],
                oldest_modified=m["oldest_modified"],
                newest_modified=m["newest_modified"],
                sample_etags=m["sample_etags"],
                object_encryption=encryption, static_website=website,
                acl_public_grants=perms["acl_public_grants"], writable=writable,
                policy_readable=perms["policy_readable"],
                policy_public=perms["policy_public"],
                versioning_enabled=perms["versioning_enabled"],
                version_count=perms["version_count"],
                delete_markers=perms["delete_markers"],
                files=count, endpoint=url,
                note="; ".join(note_bits))
        # 200 without listing markers (e.g. a website index), redirects we
        # couldn't resolve, or other codes -> not a confirmed storage finding.
        return None

    def _azure_probe(self, account: str, source: str) -> List[Finding]:
        """Azure Blob enumeration. Account-level ?comp=list is almost never
        anonymous, so we (1) confirm the storage account exists, then (2) brute a
        bounded set of common container names with the per-container anonymous
        listing query (?restype=container&comp=list). Returns one finding per
        OPEN container (plus, for authoritative sources, a single 'exists but
        locked' finding when nothing anonymous was found)."""
        account = account.lower().strip(".")
        if not valid_bucket_name(account, allow_dots=False):
            return []
        authoritative = source not in ("brute-force", "expansion")
        # Keyword-derived account that does not reference the target org cannot be
        # attributed to it — skip (same FP control as the S3/GCS path).
        if not authoritative and not self._is_org_anchored(account):
            return []
        root = f"https://{account}.blob.core.windows.net/"

        # (1) existence: ANY HTTP reply (even 400/403) means the account resolves;
        # a connection/DNS failure (None) means it does not exist → drop.
        probe = self._get(root + "?comp=list&maxresults=1")
        if probe is None:
            if authoritative and PROVIDERS["azure"]["takeover_prone"]:
                return [Finding(
                    name=account, provider="azure", url=root, access="unclaimed",
                    status=STATUS_NOT_FOUND, exposure_state="referenced",
                    severity="info", risk_score=0.15,
                    risk_category="unclaimed_reference",
                    tags=["unclaimed", "verify-ownership", "azure"],
                    evidence=(f"Azure storage account '{account}' is referenced "
                              f"(source: {source}) but does not resolve — verify "
                              "ownership (potential subdomain-takeover vector)."),
                    remediation="Reclaim the name or remove the DNS/app reference.",
                    sources=[source], takeover_prone=True, endpoint=root,
                    note="unclaimed reference — verify ownership")]
            return []

        # (2) brute common containers for anonymous listing.
        findings: List[Finding] = []
        any_open = False
        for container in AZURE_CONTAINERS:
            url = f"{root}{quote(container)}?restype=container&comp=list"
            r = self._get(url)
            if r is None:
                continue
            body = r.text or ""
            if r.status_code == 200 and LISTING_MARKERS.search(body):
                any_open = True
                m = classify_listing(body)
                sev, score, cat = m["severity"], m["risk_score"], m["category"]
                count = m["count"]
                keyword_derived = not authoritative
                cont_url = f"{root}{quote(container)}/"
                cors = self._cors(cont_url) if count else False
                if cors and sev == "low":
                    sev, score = "medium", max(score, 0.5)
                    cat += "+cors"
                tags = ["public", "azure"] + m["file_types"]
                if cors:
                    tags.append("cors-wildcard")
                if keyword_derived:
                    tags.append("attribution:keyword-derived")
                exposure = ("sensitive_confirmed"
                            if SEV_RANK[sev] >= SEV_RANK["high"] else "anon_accessible")
                note_bits = [b for b in (
                    f"public container ({cat})", m.get("classify_note", ""),
                    ("keyword-derived name — verify org ownership"
                     if keyword_derived else "")) if b]
                findings.append(Finding(
                    name=f"{account}/{container}", provider="azure", url=cont_url,
                    access="public", status=STATUS_OPEN, exposure_state=exposure,
                    severity=sev, risk_score=score, risk_category=cat,
                    data_count=count, file_types=m["file_types"], cors_enabled=cors,
                    tags=tags,
                    evidence=(f"Azure container '{container}' on account '{account}' "
                              f"is PUBLICLY LISTABLE ({count} objects"
                              + (f"; types: {', '.join(m['file_types'])}"
                                 if m["file_types"] else "; unclassified") + ")."),
                    remediation=REMEDIATION.get(sev, ""),
                    sources=[source], takeover_prone=True,
                    total_bytes=m["total_bytes"], largest_bytes=m["largest_bytes"],
                    largest_object=m["largest_object"],
                    oldest_modified=m["oldest_modified"],
                    newest_modified=m["newest_modified"],
                    sample_etags=m["sample_etags"],
                    files=count, endpoint=cont_url, note="; ".join(note_bits)))

        if not any_open and authoritative:
            # Account exists, no anonymous container found — low recon signal,
            # only for target-tied names (brute/expansion locked accounts = noise).
            findings.append(Finding(
                name=account, provider="azure", url=root, access="forbidden",
                status=STATUS_CLOSED, exposure_state="exists",
                severity="low", risk_score=0.2, risk_category="access_denied",
                tags=["access-denied", "azure"],
                evidence=(f"Azure storage account '{account}' exists but no "
                          "anonymously listable container was found."),
                remediation="No action required if intentional.",
                sources=[source], takeover_prone=True, endpoint=root,
                note="account exists; no anonymous container"))
        return findings

    def _record_result(self, res) -> None:
        """Normalize a probe result (None | Finding | list[Finding]) into the
        findings table."""
        if res is None:
            return
        if isinstance(res, list):
            for f in res:
                self._record(f)
        else:
            self._record(res)

    def _record(self, f: Optional[Finding]) -> None:
        if not f:
            return
        key = (f.name.lower(), f.provider)
        with self._lock:
            existing = self.findings.get(key)
            if existing is None:
                self.findings[key] = f
            else:
                existing.sources = sorted(set(existing.sources) | set(f.sources))
                if SEV_RANK.get(f.severity, 0) > SEV_RANK.get(existing.severity, 0):
                    self.findings[key] = f
                    self.findings[key].sources = existing.sources

    # ---- candidate generation --------------------------------------------- #
    @staticmethod
    def _norm(s: str) -> str:
        """Hyphen-canonical bucket label (S3/DO/Wasabi-safe)."""
        s = re.sub(r"[^a-z0-9.\-]", "-", s.strip().lower()).strip("-.")
        return re.sub(r"-{2,}", "-", s)

    def _expand_one(self, base: str, affix: str, seen: Set[str],
                    cands: List[str]) -> None:
        """Push every realistic join of base+affix. Hyphen joins are universally
        valid; a dotted join (base.affix) is also pushed because S3/GCS/Wasabi/DO
        allow dots and real buckets use them — invalid-for-provider names are
        dropped later by valid_bucket_name(), so over-generating here is free."""
        for cand in (f"{base}-{affix}", f"{affix}-{base}",
                     f"{base}{affix}", f"{base}.{affix}"):
            cand = self._norm(cand)
            if cand and cand not in seen and 3 <= len(cand) <= 63:
                seen.add(cand)
                cands.append(cand)

    def generate_candidates(self, keywords: List[str], mutations: List[str],
                            cap: int) -> List[str]:
        """Full brute candidate set: every base keyword plus base×(mutation set).
        When no --mutations wordlist is supplied, fall back to DEFAULT_AFFIXES so
        a brute run is still productive instead of silently doing nothing."""
        cands: List[str] = []
        seen: Set[str] = set()

        def push(n: str):
            n = self._norm(n)
            if n and n not in seen and 3 <= len(n) <= 63:
                seen.add(n)
                cands.append(n)

        for kw in keywords:
            push(kw)
        affixes = [self._norm(m) for m in (mutations or DEFAULT_AFFIXES)]
        affixes = [a for a in affixes if a]
        for kw in keywords:
            base = self._norm(kw)
            if len(base) < 3:
                continue
            for aff in affixes:
                self._expand_one(base, aff, seen, cands)
                if len(cands) >= cap:
                    return cands[:cap]
        return cands[:cap]

    def targeted_candidates(self, keywords: List[str], cap: int) -> List[str]:
        """Bounded, high-signal candidate set used by the DEFAULT (non-brute)
        path: bare keywords + keyword×DEFAULT_AFFIXES only. Small enough to run
        on every scan, so buckets are found even when full brute is disabled."""
        cands: List[str] = []
        seen: Set[str] = set()

        def push(n: str):
            n = self._norm(n)
            if n and n not in seen and 3 <= len(n) <= 63:
                seen.add(n)
                cands.append(n)

        for kw in keywords:
            push(kw)
        for kw in keywords:
            base = self._norm(kw)
            if len(base) < 3:
                continue
            for aff in DEFAULT_AFFIXES:
                self._expand_one(base, aff, seen, cands)
                if len(cands) >= cap:
                    return cands[:cap]
        return cands[:cap]

    # ---- run -------------------------------------------------------------- #
    def _probe_many(self, provider: str, cands: List[str], source: str):
        log(f"{provider:13} {source}: probing {len(cands)} candidates...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            futs = [ex.submit(self._probe, provider, n, source) for n in cands]
            done = 0
            for fut in concurrent.futures.as_completed(futs):
                self._record_result(fut.result())
                done += 1
                if done % 250 == 0:
                    log(f"    {provider}: {done}/{len(cands)}")

    def expand(self, keywords: List[str], cap_per_provider: int):
        """Default targeted expansion (runs even without full --brute)."""
        for provider in self.providers:
            cands = self.targeted_candidates(keywords, cap_per_provider)
            self._probe_many(provider, cands, "expansion")

    def brute(self, keywords: List[str], mutations: List[str], cap_per_provider: int):
        for provider in self.providers:
            cands = self.generate_candidates(keywords, mutations, cap_per_provider)
            self._probe_many(provider, cands, "brute-force")

    def verify_preknown(self, names: List[str], source: str = "preknown"):
        pairs = [(p, n) for p in self.providers for n in names]
        if not pairs:
            return
        log(f"verifying {len(names)} pre-known names across {len(self.providers)} providers...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            futs = [ex.submit(self._probe, p, n, source) for p, n in pairs]
            for fut in concurrent.futures.as_completed(futs):
                self._record_result(fut.result())

    def write(self, out_path: Path) -> Tuple[int, dict]:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        rows = sorted(self.findings.values(),
                      key=lambda f: (-SEV_RANK.get(f.severity, 0), -f.risk_score, f.name))
        by_sev: Dict[str, int] = {}
        by_cat: Dict[str, int] = {}
        by_status: Dict[str, int] = {}
        with out_path.open("w") as fh:
            for f in rows:
                fh.write(json.dumps(asdict(f)) + "\n")
                by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
                by_cat[f.risk_category] = by_cat.get(f.risk_category, 0) + 1
                st = f.status or "unknown"
                by_status[st] = by_status.get(st, 0) + 1
        summary = {
            "module": "cloud_storage_enum",
            "target": self.target,
            "total_findings": len(rows),
            "public": sum(1 for f in rows if f.access == "public"),
            "access_denied": sum(1 for f in rows if f.access == "forbidden"),
            "open": by_status.get(STATUS_OPEN, 0) + by_status.get(STATUS_OPEN_OBJECTS, 0),
            "closed": by_status.get(STATUS_CLOSED, 0),
            "not_found": by_status.get(STATUS_NOT_FOUND, 0),
            "by_severity": by_sev,
            "by_status": by_status,
            "by_category": by_cat,
        }
        (out_path.parent / "cloud_storage_summary.json").write_text(json.dumps(summary, indent=2))
        return len(rows), summary


def _read_list(path: str) -> List[str]:
    if not path:
        return []
    p = Path(path)
    if not p.exists():
        return []
    out = []
    for line in p.read_text(errors="ignore").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            out.append(line)
    return out


# --------------------------------------------------------------------------- #
# Presigned / SAS URL harvesting from crawled client-side content
# --------------------------------------------------------------------------- #
_URL_RE = re.compile(r"https?://[^\s\"'<>()\\]+", re.I)
_PRESIGN = [
    # (provider, required-any-of markers, expiry-extractor-key)
    ("aws-sigv4", ("x-amz-signature=",), "sigv4"),
    ("aws-sigv2", ("awsaccesskeyid=",), "sigv2"),
    ("gcp-signed", ("x-goog-signature=", "googleaccessid="), "gcp"),
    ("azure-sas", ("sig=",), "azure"),
]


def _parse_expiry(url_l: str, kind: str) -> Tuple[Optional[int], bool]:
    """Return (epoch_expiry_or_None, expired?) for a signed URL."""
    import urllib.parse as up
    q = up.parse_qs(up.urlparse(url_l).query)
    now = time.time()
    try:
        if kind == "sigv4":
            d = q.get("x-amz-date", [""])[0]           # 20240101T000000Z
            exp = int(q.get("x-amz-expires", ["0"])[0])
            if d and exp:
                t = time.mktime(time.strptime(d, "%Y%m%dT%H%M%SZ")) - time.timezone
                return int(t + exp), (t + exp) < now
        elif kind == "sigv2":
            e = int(q.get("expires", ["0"])[0])         # epoch seconds
            if e:
                return e, e < now
        elif kind == "gcp":
            e = int(q.get("expires", ["0"])[0])
            if e:
                return e, e < now
        elif kind == "azure":
            se = q.get("se", [""])[0]                    # ISO8601 expiry
            if se:
                se2 = se.replace("Z", "").split(".")[0]
                for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M", "%Y-%m-%d"):
                    try:
                        t = time.mktime(time.strptime(se2, fmt)) - time.timezone
                        return int(t), t < now
                    except ValueError:
                        continue
    except (ValueError, OverflowError):
        pass
    return None, False


def _signed_url_scope(url_l: str, kind: str) -> dict:
    """Extract permission breadth + resource type from a signed URL/SAS.
    Returns {'perms': str, 'writable': bool, 'resource': str}. Any write/delete/
    add/create/update permission (or an unscoped account-SAS) marks it writable."""
    import urllib.parse as up
    q = up.parse_qs(up.urlparse(url_l).query)
    perms, resource, writable = "", "", False
    if kind == "azure":
        perms = q.get("sp", [""])[0]            # e.g. "rwdl"
        resource = q.get("sr", q.get("srt", [""]))[0]  # b/c/o or s/c/o
        # account SAS uses ss= (services) + srt= + sp=; presence of write perms
        writable = any(c in perms.lower() for c in ("w", "d", "a", "c", "u"))
        # an account-level SAS (ss=/srt=) is broad even if perms unparsed
        if q.get("ss") or "c" in (resource or "").lower():
            writable = writable or bool(q.get("ss"))
    elif kind in ("sigv4", "sigv2"):
        # AWS presigned inherit the signer's verb; the URL itself is scoped to one
        # object+method. If the signed request is not GET/HEAD it is writable.
        # x-amz-* presigned rarely encode method in query; default read.
        resource = "object"
        writable = False
    elif kind == "gcp":
        resource = "object"
        writable = False
    return {"perms": perms, "writable": writable, "resource": resource}


def harvest_presigned_urls(corpus_paths: List[str]) -> List[dict]:
    """Scan crawled text/JS/HTML for leaked presigned (AWS/GCP) and SAS (Azure)
    URLs. A live (non-expired) signed URL is a credential — anyone with the link
    gets the signer's access to that object."""
    seen: Set[str] = set()
    findings: List[dict] = []
    for path in corpus_paths:
        p = Path(path)
        if not p.exists():
            continue
        try:
            text = p.read_text(errors="ignore")
        except Exception:
            continue
        for raw in _URL_RE.findall(text):
            url = raw.rstrip(".,);]}\"'")
            low = url.lower()
            if "sig" not in low and "amz" not in low and "goog" not in low:
                continue
            for provider, markers, kind in _PRESIGN:
                if not any(mk in low for mk in markers):
                    continue
                # Azure SAS needs sig= AND sv=/se= to avoid matching random sig=
                if kind == "azure" and not ("sv=" in low or "se=" in low
                                            or "blob.core.windows.net" in low):
                    continue
                key = url.split("?")[0] + "|" + provider
                if key in seen:
                    break
                seen.add(key)
                expiry, expired = _parse_expiry(low, kind)
                # C2 — SAS/permission-breadth grading. Azure SAS `sp=` encodes
                # permissions (r read, w write, d delete, l list, a add, c create,
                # u update). A live token granting write/delete/list is not just
                # object read — it is data tamper/exfil, so grade it CRITICAL.
                scope = _signed_url_scope(low, kind)
                if expired:
                    sev = "info"
                elif scope["writable"]:
                    sev = "critical"
                else:
                    sev = "high"
                exp_txt = ("expired" if expired else
                           (f"valid until {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(expiry))}"
                            if expiry else "no parseable expiry"))
                perm_txt = (f" perms={scope['perms']}" if scope["perms"] else "")
                findings.append({
                    "type": "presigned_url_leak", "provider": provider,
                    "url": url[:400], "object": url.split("?")[0][:300],
                    "expired": expired, "expiry_epoch": expiry,
                    "sas_permissions": scope["perms"], "writable": scope["writable"],
                    "sas_resource": scope["resource"],
                    "severity": sev, "source_file": str(p.name),
                    "evidence": (f"{provider} presigned/SAS URL leaked in crawled "
                                 f"content ({exp_txt}{perm_txt}). Grants direct "
                                 f"{'READ+WRITE' if scope['writable'] else 'read'} "
                                 "access to anyone holding the link."),
                    "remediation": ("Stop embedding signed URLs in client-side code; "
                                    "use short TTLs, least-privilege (read-only) "
                                    "scope, generate per-request server-side, and "
                                    "rotate the signing key if a live URL leaked."),
                })
                break
    return findings


def main() -> int:
    ap = argparse.ArgumentParser(description="Multi-cloud storage enum + classify")
    ap.add_argument("--target", required=True)
    ap.add_argument("--keywords", default="")
    ap.add_argument("--mutations", default="")
    ap.add_argument("--preknown", default="")
    ap.add_argument("--providers", default="s3,azure,gcs,digitalocean,wasabi")
    ap.add_argument("--output", required=True)
    ap.add_argument("--minio-host", default="")
    ap.add_argument("--known-public", default="",
                    help="File of bucket names that are intentionally public "
                         "(CDN/marketing) — matches are downgraded to info to "
                         "suppress the documented static-asset false positive.")
    ap.add_argument("--threads", type=int, default=25)
    ap.add_argument("--timeout", type=int, default=6)
    ap.add_argument("--cap-per-provider", type=int, default=2500)
    ap.add_argument("--no-brute", action="store_true",
                    help="Skip the full mutation-wordlist brute-force (targeted "
                         "expansion still runs unless --no-expand).")
    ap.add_argument("--no-expand", action="store_true",
                    help="Also skip the default targeted keyword×affix expansion "
                         "(verify --preknown names only — fastest, lowest coverage).")
    ap.add_argument("--expand-cap", type=int, default=1500,
                    help="Max targeted-expansion candidates per provider (default "
                         "1500) — bounds the default non-brute coverage.")
    ap.add_argument("--presigned-corpus", default="",
                    help="Comma/space-separated crawl files to scan for leaked "
                         "presigned/SAS URLs; findings written to "
                         "<output-dir>/presigned_urls.jsonl")
    args = ap.parse_args()

    if not HAS_REQUESTS:
        log("ERROR: python 'requests' not installed (pip3 install requests); "
            "writing empty output.")
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text("")
        return 0

    providers = [p.strip() for p in args.providers.split(",") if p.strip()]
    keywords = _read_list(args.keywords) or [args.target, args.target.split(".")[0]]
    mutations = _read_list(args.mutations)
    preknown = _read_list(args.preknown)

    # ---- Org anchoring (api.myntra.com FP fix) --------------------------------
    # Derive the registrable ORG label from the target (and any hostname-looking
    # keyword), e.g. api.myntra.com -> 'myntra'. This is the ONLY reliable brute
    # anchor; the service subdomain label ('api') is generic and brute-expanding
    # it produces unrelated third-party buckets.
    anchor_tokens: Set[str] = set()
    org = registrable_label(args.target)
    if org:
        anchor_tokens.add(org)
    for kw in keywords:
        if "." in kw:
            lbl = registrable_label(kw)
            if lbl:
                anchor_tokens.add(lbl)
    # Base keywords for brute/expansion: the org tokens, plus any non-generic,
    # non-hostname operator keyword (a brand/sub-brand). Generic service labels
    # (api/www/static/db/...) and bare TLDs are never used as a brute base.
    base_keywords: List[str] = sorted(anchor_tokens)
    for kw in keywords:
        k = kw.strip().lower()
        if "." in k or len(k) < 3:
            continue
        if k in GENERIC_LABELS or k in anchor_tokens:
            continue
        base_keywords.append(k)

    log(f"target={args.target} providers={providers} org={org or '?'} "
        f"anchors={sorted(anchor_tokens) or '[]'} base_keywords={base_keywords} "
        f"keywords={len(keywords)} mutations={len(mutations)} preknown={len(preknown)}")

    known_public = set(_read_list(args.known_public)) if args.known_public else set()
    scanner = CloudStorageScanner(args.target, providers, threads=args.threads,
                                  timeout=args.timeout, minio_host=args.minio_host,
                                  known_public=known_public,
                                  anchor_tokens=anchor_tokens)
    if preknown:
        scanner.verify_preknown(preknown)
    if not base_keywords:
        # No org-anchored base to brute from (e.g. target is an IP, or only
        # generic labels were supplied). Expanding generic words would just hit
        # unrelated third-party buckets, so skip brute/expansion entirely.
        log("no org-anchored base keyword — skipping brute/expansion "
            "(verifying pre-known names only, if any)")
    elif not args.no_brute:
        # Full mutation brute (opt-in via caller): base × full wordlist.
        scanner.brute(base_keywords, mutations, args.cap_per_provider)
    elif not args.no_expand:
        # Default path: bounded, high-signal keyword × affix expansion. Runs even
        # when the caller passes --no-brute, so buckets are still discovered
        # instead of only verifying a (possibly empty) pre-known list.
        scanner.expand(base_keywords, args.expand_cap)
    else:
        log("brute + expansion both disabled — verifying pre-known names only")

    n, summary = scanner.write(Path(args.output))
    log(f"done: {n} findings ({summary['public']} public, "
        f"{summary['access_denied']} access-denied; "
        f"open={summary['open']} closed={summary['closed']} "
        f"not-found={summary['not_found']}) -> {args.output}")
    if summary["by_severity"]:
        log("severity: " + ", ".join(f"{k}={v}" for k, v in sorted(
            summary["by_severity"].items(), key=lambda x: -SEV_RANK.get(x[0], 0))))

    # Optional: harvest leaked presigned/SAS URLs from crawled content.
    if args.presigned_corpus:
        corpus = [c for c in re.split(r"[,\s]+", args.presigned_corpus) if c]
        ph = harvest_presigned_urls(corpus)
        ppath = Path(args.output).parent / "presigned_urls.jsonl"
        with ppath.open("w") as fh:
            for f in ph:
                fh.write(json.dumps(f) + "\n")
        live = sum(1 for f in ph if not f["expired"])
        log(f"presigned harvest: {len(ph)} signed URLs ({live} still valid) -> {ppath}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
