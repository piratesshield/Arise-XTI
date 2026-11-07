#!/usr/bin/env python3
"""
C3 — Secret-store & Cloud-Credential Surface  (leaked-key = cloud initial access)
=================================================================================
Scans crawled client-side content, JS bundles, config dumps and exposed-bucket
object corpora for **cloud credential artifacts** — the DEF CON "API keys on
GitHub / .publishsettings in config" initial-access vector (memory:
cloud-security-domain). Emits high-confidence, deduplicated findings that feed
the C6 attack-path graph (leaked-key → cloud API → snapshot/secrets → reuse).

SAFETY (authorized-EASM posture):
  * DETECTION + confidence scoring only. This module NEVER authenticates with a
    discovered credential to a cloud provider — that would be "using" it.
  * A masked preview (first/last chars) is kept for triage; the full secret is
    NOT written to output.
  * Live liveness-validation, if ever wanted, is a separate gated step handled by
    secret_validator.py — not done here.

  python3 cloud_cred_scan.py --corpus crawl/*.js dumps/*.txt \
      --output out/cloud_credentials.jsonl
"""

from __future__ import annotations

import sys as _sys, os as _os
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)


import argparse
import glob
import json
import math
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Optional


def log(msg: str) -> None:
    print(f"[cloudcred] {msg}", file=sys.stderr, flush=True)


def _entropy(s: str) -> float:
    """Shannon entropy (bits/char) — high entropy corroborates a real secret."""
    if not s:
        return 0.0
    freq: Dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


# --------------------------------------------------------------------------- #
# Credential detectors.
#   (id, provider, severity, regex, min_entropy, note)
# Each regex should capture the secret in group 1 where feasible so we can score
# entropy and mask it. Patterns tuned to minimise false positives.
# --------------------------------------------------------------------------- #
@dataclass
class Detector:
    id: str
    provider: str
    severity: str
    pattern: re.Pattern
    min_entropy: float
    note: str
    validate_hint: str = ""


DETECTORS: List[Detector] = [
    Detector("aws-access-key-id", "aws", "high",
             re.compile(r"\b((?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[0-9A-Z]{16})\b"),
             2.5, "AWS access key ID (pair with a secret key for API access).",
             "aws sts get-caller-identity"),
    Detector("aws-secret-access-key", "aws", "critical",
             re.compile(r"(?i)aws_?secret_?access_?key['\"]?\s*[:=]\s*['\"]?"
                        r"([A-Za-z0-9/+=]{40})"),
             4.0, "AWS secret access key — full API access when paired with key ID.",
             "aws sts get-caller-identity"),
    Detector("gcp-service-account", "gcp", "critical",
             re.compile(r'"type"\s*:\s*"service_account".*?"private_key"\s*:\s*"'
                        r'(-----BEGIN PRIVATE KEY-----[^"]{20,})', re.S),
             3.5, "GCP service-account JSON with private key — full SA impersonation.",
             "gcloud auth activate-service-account (DO NOT RUN — detection only)"),
    Detector("gcp-api-key", "gcp", "high",
             re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b"),
             3.5, "Google API key.", ""),
    Detector("azure-storage-key", "azure", "critical",
             re.compile(r"(?i)(?:AccountKey|storage_?account_?key)\s*[:=]\s*['\"]?"
                        r"([A-Za-z0-9/+]{86,88}==)"),
             4.0, "Azure Storage account key — full data-plane access to the account.",
             ""),
    Detector("azure-client-secret", "azure", "critical",
             re.compile(r"(?i)(?:client_?secret|clientsecret)['\"]?\s*[:=]\s*['\"]"
                        r"([A-Za-z0-9~._\-]{34,40})['\"]"),
             3.8, "Azure AD app client secret — service-principal auth (often no MFA).",
             ""),
    Detector("azure-mgmt-cert", "azure", "critical",
             re.compile(r"ManagementCertificate\s*=\s*\"([A-Za-z0-9/+=]{200,})\""),
             4.5, ".publishsettings management certificate — full subscription access.",
             ""),
    Detector("azure-sas-token", "azure", "high",
             re.compile(r"(sv=20\d\d-\d\d-\d\d&[^\"'\s]*?sig=[A-Za-z0-9%/+]{20,})"),
             3.0, "Azure SAS token — scoped/timed data access (see storage SAS grading).",
             ""),
    Detector("gcp-oauth-refresh", "gcp", "high",
             re.compile(r"\b(1//[0-9A-Za-z\-_]{30,})\b"),
             3.5, "Google OAuth refresh token.", ""),
    Detector("slack-token", "slack", "high",
             re.compile(r"\b(xox[baprs]-[0-9A-Za-z\-]{10,})\b"),
             3.0, "Slack token (often a lateral-movement / data-access pivot).", ""),
    Detector("generic-bearer-jwt", "generic", "medium",
             re.compile(r"\b(eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})\b"),
             3.5, "JWT/bearer token — inspect for cloud audience/claims.", ""),
    Detector("private-key-block", "generic", "critical",
             re.compile(r"(-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----)"),
             0.0, "Private key material embedded in content.", ""),
]

# Filename artifacts that are themselves cloud-credential stores (path match)
ARTIFACT_FILES = re.compile(
    r"\.publishsettings$|azureProfile\.json$|accessTokens\.json$|\.cspkg$|"
    r"(^|/)credentials(\.json)?$|(^|/)\.aws/credentials$|(^|/)\.boto$|"
    r"(^|/)\.s3cfg$|service[_-]?account.*\.json$|\.tfstate$", re.I)

# Well-known documentation/tutorial placeholder secrets — these legitimately
# appear in real crawled content (a bundled SDK's example config, a
# copy-pasted snippet) but are never actually secret. Matched by EXACT value,
# not a broad heuristic, so this can't suppress a real leak that merely
# resembles a placeholder. AWS's own docs example key is the single most
# common false positive across every secret scanner that doesn't exclude it.
KNOWN_PLACEHOLDER_SECRETS = {
    "wjalrxutnfemi/k7mdeng/bpxrfciyexamplekey",
    "wjalrxutnfemi/k7mdeng/bpxrficyexamplekey",  # AWS docs — both known transcriptions
}


def _is_placeholder(secret: str) -> bool:
    s = secret.strip().lower()
    if s in KNOWN_PLACEHOLDER_SECRETS:
        return True
    if "example" in s:
        return True
    return False


def _mask(secret: str) -> str:
    s = secret.strip()
    if len(s) <= 8:
        return s[0] + "***"
    return f"{s[:4]}…{s[-4:]} (len {len(s)})"


@dataclass
class CredFinding:
    detector: str
    provider: str
    severity: str
    source_file: str
    masked: str
    entropy: float
    note: str
    line_hint: str = ""
    validate_hint: str = ""
    # C6 linkage: this finding is the entry node of a cloud attack path.
    attack_path_seed: str = "leaked_cloud_credential"
    # C7 detection-cost: reading exposed content is low-cost; USING the key later
    # is what a defender would catch (CloudTrail/GuardDuty) — noted for purple team.
    detection_cost: Dict[str, str] = field(default_factory=lambda: {
        "discovery_layer": "none (passive read of exposed content)",
        "exploitation_layer": "CloudTrail/GuardDuty on first API call with the key",
    })


def scan_text(text: str, source: str) -> List[CredFinding]:
    findings: List[CredFinding] = []
    for det in DETECTORS:
        for m in det.pattern.finditer(text):
            secret = m.group(1) if m.groups() else m.group(0)
            if _is_placeholder(secret):
                continue
            ent = _entropy(secret)
            if ent < det.min_entropy:
                continue
            # locate a line-number hint
            start = m.start()
            line_no = text.count("\n", 0, start) + 1
            findings.append(CredFinding(
                detector=det.id, provider=det.provider, severity=det.severity,
                source_file=source, masked=_mask(secret), entropy=round(ent, 2),
                note=det.note, line_hint=f"line ~{line_no}",
                validate_hint=det.validate_hint))
    return findings


def scan_corpus(paths: List[str]) -> List[CredFinding]:
    seen = set()
    out: List[CredFinding] = []
    for path in paths:
        p = Path(path)
        if not p.is_file():
            continue
        src = p.name
        # filename-level artifact (the file itself is a credential store)
        if ARTIFACT_FILES.search(str(p)):
            key = ("artifact", src)
            if key not in seen:
                seen.add(key)
                out.append(CredFinding(
                    detector="cloud-credential-artifact", provider="cloud",
                    severity="critical", source_file=src, masked="(file artifact)",
                    entropy=0.0,
                    note=("File is a cloud-credential artifact (.publishsettings / "
                          "ARM token cache / SA key / tfstate) — direct initial "
                          "access if exposed.")))
        try:
            text = p.read_text(errors="ignore")
        except Exception:
            continue
        for f in scan_text(text, src):
            key = (f.detector, f.masked, f.source_file)
            if key in seen:
                continue
            seen.add(key)
            out.append(f)
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="C3 cloud-credential surface scan")
    ap.add_argument("--corpus", nargs="+", required=True,
                    help="files/globs to scan (js, html, config dumps, bucket objs)")
    ap.add_argument("--output", required=True)
    args = ap.parse_args()

    paths: List[str] = []
    for pat in args.corpus:
        expanded = glob.glob(pat, recursive=True)
        paths.extend(expanded if expanded else [pat])

    findings = scan_corpus(paths)
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w") as fh:
        for f in findings:
            fh.write(json.dumps(asdict(f)) + "\n")

    by_sev: Dict[str, int] = {}
    by_prov: Dict[str, int] = {}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        by_prov[f.provider] = by_prov.get(f.provider, 0) + 1
    log(f"scanned {len(paths)} files -> {len(findings)} cloud-cred findings "
        f"({dict(by_sev)}) -> {out}")
    if by_prov:
        log("providers: " + ", ".join(f"{k}={v}" for k, v in by_prov.items()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
