#!/usr/bin/env python3
"""
C5 — Control-Presence Inversion  ("what SHOULD exist" → gaps are findings)
==========================================================================
Grades a target against the AWS immutable-guardrails / CIS-benchmark baseline
(memory: grc-standards-domain + cloud-security-domain). The ABSENCE of a control
is the finding. Works black-box by correlating what the earlier ARISE modules
already observed — no cloud API keys required for the black-box subset.

Black-box signals consumed from the scan directory:
  * cloud_buckets.jsonl        → public bucket  ⇒ S3 Block-Public-Access OFF
  * ssrf_metadata.jsonl        → IMDS reachable ⇒ IMDSv2 not enforced (critical)
  * cloud_credential findings  → leaked key     ⇒ no key-rotation / secret-store
  * header/TLS data (httpx)    → missing HSTS / weak TLS ⇒ transport guardrail gap
  * cloud_saas_fingerprint     → provider baseline to grade against

Severity uses the GuardDuty finding-category taxonomy as the label vocabulary
(Backdoor/Behavior/Persistence/PrivilegeEscalation/Recon/Stealth/Policy/…).

  python3 cloud_posture.py --scan-dir out/ --output out/cloud_posture.jsonl
"""

from __future__ import annotations

import sys as _sys, os as _os
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)


import argparse
import json
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Optional


def log(msg: str) -> None:
    print(f"[cloudposture] {msg}", file=sys.stderr, flush=True)


def _iter_jsonl(path: Path):
    if not path.exists():
        return
    for line in path.read_text(errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            yield json.loads(line)
        except json.JSONDecodeError:
            continue


# Guardrail catalog: id -> (control, provider, guardduty_category, default_sev,
#                           remediation)
GUARDRAILS = {
    "s3-block-public-access": (
        "S3 Block Public Access", "aws", "Policy", "high",
        "Enable account- and bucket-level S3 Block Public Access; a public bucket "
        "proves it is off or overridden."),
    "imdsv2-not-enforced": (
        "IMDSv2 enforcement (hop-limit/token)", "aws", "PrivilegeEscalation", "critical",
        "Set instance metadata to IMDSv2-required (HttpTokens=required, "
        "HttpPutResponseHopLimit=1); reachable IMDSv1 via SSRF = credential theft."),
    "cloud-key-rotation": (
        "Credential rotation / managed secret store", "cloud", "Persistence", "high",
        "Move secrets to a managed store (Secrets Manager/Key Vault/Secret Manager); "
        "rotate the leaked key immediately; never embed keys in client content."),
    "transport-hsts": (
        "HSTS / TLS transport guardrail", "cloud", "Policy", "medium",
        "Enforce HSTS (Strict-Transport-Security) and disable weak TLS versions/"
        "ciphers on all public endpoints."),
    "public-service-exposure": (
        "Boundary defense / no public admin service", "cloud", "Recon", "high",
        "Restrict management/data services (RDP/SSH/DB/kubelet) to a bastion or VPN; "
        "an internet-reachable control port is a takeover entry."),
    "storage-sas-least-priv": (
        "Least-privilege signed URLs", "azure", "Policy", "high",
        "Issue read-only, short-TTL SAS/presigned URLs; a writable leaked token is "
        "data-tamper/exfil."),
    "federation-hardening": (
        "Federation / token-signing cert protection", "microsoft", "PrivilegeEscalation", "medium",
        "Protect ADFS token-signing certs and the AAD-Connect sync account; live "
        "federation host = Golden-SAML / sync-account leverage prerequisite."),
}


@dataclass
class PostureFinding:
    guardrail: str
    control: str
    provider: str
    guardduty_category: str
    severity: str
    state: str                 # "absent" (the gap) | "present"
    evidence: str
    remediation: str
    host: str = ""
    attack_path_seed: str = ""
    detection_cost: Dict[str, str] = field(default_factory=lambda: {
        "note": "posture gap — no probe of its own; derived from prior modules",
    })


class PostureGrader:
    def __init__(self, scan_dir: Path):
        self.dir = scan_dir
        self.findings: List[PostureFinding] = []
        self._seen = set()

    def _emit(self, gid: str, evidence: str, host: str = "",
              sev: Optional[str] = None, seed: str = "") -> None:
        if gid not in GUARDRAILS:
            return
        control, provider, cat, dsev, remed = GUARDRAILS[gid]
        key = (gid, host)
        if key in self._seen:
            return
        self._seen.add(key)
        self.findings.append(PostureFinding(
            guardrail=gid, control=control, provider=provider,
            guardduty_category=cat, severity=sev or dsev, state="absent",
            evidence=evidence, remediation=remed, host=host,
            attack_path_seed=seed))

    def grade(self) -> None:
        self._from_buckets()
        self._from_ssrf()
        self._from_creds()
        self._from_headers()
        self._from_ports()
        self._from_saas()

    def _from_buckets(self) -> None:
        for f in _iter_jsonl(self.dir / "cloud_buckets.jsonl"):
            access = (f.get("access") or "").lower()
            state = (f.get("exposure_state") or "").lower()
            if access == "public" or state in ("anon_accessible", "sensitive_confirmed"):
                self._emit("s3-block-public-access",
                           f"Public bucket '{f.get('name','?')}' "
                           f"({f.get('provider','?')}, {state or access}) — "
                           "Block Public Access is off or overridden.",
                           host=f.get("name", ""), seed="public_bucket")
        # SAS least-privilege from presigned harvest
        for f in _iter_jsonl(self.dir / "presigned_urls.jsonl"):
            if f.get("writable") and not f.get("expired"):
                self._emit("storage-sas-least-priv",
                           f"Live writable {f.get('provider','')} signed URL "
                           f"(perms={f.get('sas_permissions','')}) leaked in "
                           f"{f.get('source_file','')}.", seed="writable_sas")

    def _from_ssrf(self) -> None:
        for f in _iter_jsonl(self.dir / "ssrf_metadata.jsonl"):
            if f.get("confidence") == "confirmed" and "aws" in (f.get("metadata_target") or ""):
                self._emit("imdsv2-not-enforced",
                           f"SSRF reached AWS IMDSv1 ({f.get('metadata_target')}) via "
                           f"param '{f.get('parameter')}' on {f.get('endpoint','')[:80]} "
                           "— IMDSv2 is not enforced.",
                           sev="critical", seed="ssrf_to_imds")

    def _from_creds(self) -> None:
        for f in _iter_jsonl(self.dir / "cloud_credentials.jsonl"):
            self._emit("cloud-key-rotation",
                       f"Leaked {f.get('provider','')} credential "
                       f"({f.get('detector','')}) in {f.get('source_file','')} — "
                       "no managed secret store / rotation.",
                       seed="leaked_cloud_credential")

    def _from_headers(self) -> None:
        # httpx output commonly at http_probe.jsonl / httpx.jsonl — try a few
        for fname in ("httpx.jsonl", "http_probe.jsonl", "headers.jsonl"):
            for r in _iter_jsonl(self.dir / fname):
                url = r.get("url") or r.get("input") or ""
                hdrs = r.get("header") or r.get("headers") or {}
                if isinstance(hdrs, dict):
                    hk = {k.lower() for k in hdrs}
                    scheme = (url.split("://", 1)[0] if "://" in url else "").lower()
                    if scheme == "https" and "strict-transport-security" not in hk:
                        self._emit("transport-hsts",
                                   f"{url[:80]} serves HTTPS without HSTS header.",
                                   host=url)

    def _from_ports(self) -> None:
        # cloud_asset_intel emits port findings; flag internet-reachable mgmt svc
        for fname in ("cloud_asset_findings.jsonl", "origin_ports.jsonl",
                      "open_ports.jsonl"):
            for r in _iter_jsonl(self.dir / fname):
                cat = (r.get("category") or r.get("service") or "").lower()
                port = r.get("port")
                state = (r.get("exposure_state") or r.get("access") or "").lower()
                if any(k in cat for k in ("rdp", "ssh", "database", "kubelet",
                                          "redis", "mongo", "elastic", "docker")):
                    if state in ("anon_accessible", "sensitive_confirmed", "public",
                                 "exists", ""):
                        self._emit("public-service-exposure",
                                   f"Management/data service '{cat}' port {port} "
                                   f"reachable ({state or 'open'}) on "
                                   f"{r.get('host', r.get('target',''))}.",
                                   host=str(r.get("host", "")), seed="public_mgmt_port")

    def _from_saas(self) -> None:
        for f in _iter_jsonl(self.dir / "cloud_saas_fingerprint.jsonl"):
            if f.get("category") == "federation":
                self._emit("federation-hardening",
                           f"Federation host {f.get('host','')} live "
                           f"({f.get('note','')}).",
                           host=f.get("host", ""), seed="federation_present")


def main() -> int:
    ap = argparse.ArgumentParser(description="C5 cloud control-presence inversion")
    ap.add_argument("--scan-dir", required=True,
                    help="directory holding prior ARISE cloud outputs")
    ap.add_argument("--output", required=True)
    args = ap.parse_args()

    grader = PostureGrader(Path(args.scan_dir))
    grader.grade()

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w") as fh:
        for f in grader.findings:
            fh.write(json.dumps(asdict(f)) + "\n")

    by_sev: Dict[str, int] = {}
    for f in grader.findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
    log(f"done: {len(grader.findings)} guardrail-gap findings ({dict(by_sev)}) -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
