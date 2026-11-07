#!/usr/bin/env python3
"""
C1 — Passive Cloud / SaaS Attribution  (cloud recon, pre-auth, zero-touch)
==========================================================================
Fingerprints which clouds, mail providers, SaaS and federation a target uses
purely from public DNS — MX / TXT / SPF / verification tokens — *before* any
active probe is sent. This is the DEF CON "Hacking the Cloud" passive-recon
technique (see memory: cloud-security-domain): management APIs replace network
access, so the first move is to learn the provider footprint from DNS alone.

Output feeds:
  * internet_intel.py       — provider/SaaS attribution per apex
  * ssrf_metadata.py (C4)   — which metadata endpoints to prioritise
  * cloud_posture.py (C5)   — which provider baseline to grade against
  * capec_attack_paths.py   — Golden-SAML / AAD-Connect prerequisites (ADFS found)

Read-only: issues DNS queries only (via `dig`). No connection to the target.

  python3 cloud_saas_fingerprint.py --target example.com \
      --output out/cloud_saas_fingerprint.jsonl
"""

from __future__ import annotations

import sys as _sys, os as _os
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)


import argparse
import json
import re
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

DIG = "dig"


def log(msg: str) -> None:
    print(f"[saasfp] {msg}", file=sys.stderr, flush=True)


# --------------------------------------------------------------------------- #
# Fingerprint tables — token (lowercased, substring) -> (provider, category,
# note). Derived from the DEF CON deck's MX/TXT/SPF fingerprint set.
# --------------------------------------------------------------------------- #
MX_FINGERPRINTS: List[Tuple[str, str, str, str]] = [
    ("outlook.com",           "microsoft", "mail", "Microsoft 365 / Exchange Online"),
    ("mail.protection.outlook", "microsoft", "mail", "Microsoft 365 (EOP)"),
    ("google.com",            "google",    "mail", "Google Workspace (Gmail)"),
    ("googlemail.com",        "google",    "mail", "Google Workspace (Gmail)"),
    ("pphosted.com",          "proofpoint","mail", "Proofpoint email security"),
    ("mimecast.com",          "mimecast",  "mail", "Mimecast email security"),
    ("messagelabs.com",       "broadcom",  "mail", "Symantec.cloud / MessageLabs"),
    ("amazonaws.com",         "aws",       "mail", "Amazon SES / WorkMail"),
    ("zoho.com",              "zoho",      "mail", "Zoho Mail"),
    ("secureserver.net",      "godaddy",   "mail", "GoDaddy mail"),
    ("qq.com",                "tencent",   "mail", "Tencent Exmail"),
]

# TXT / verification-token fingerprints (substring match, case-insensitive)
TXT_FINGERPRINTS: List[Tuple[str, str, str, str]] = [
    ("ms=",                       "microsoft",  "tenant",    "Microsoft 365 domain verification"),
    ("v=verifydomain",            "microsoft",  "tenant",    "Microsoft domain verification"),
    ("google-site-verification",  "google",     "tenant",    "Google Workspace / Search Console"),
    ("amazonses:",                "aws",        "saas",      "Amazon SES sending domain"),
    ("docusign=",                 "docusign",   "saas",      "DocuSign"),
    ("atlassian-",                "atlassian",  "saas",      "Atlassian (Jira/Confluence)"),
    ("atlassian-domain-verification", "atlassian", "saas",   "Atlassian domain verification"),
    ("adobe-idp-site-verification","adobe",     "saas",      "Adobe enterprise / IdP"),
    ("stripe-verification",       "stripe",     "saas",      "Stripe"),
    ("facebook-domain-verification","meta",     "saas",      "Meta / Facebook business"),
    ("dropbox-domain-verification","dropbox",   "saas",      "Dropbox Business"),
    ("miro-verification",         "miro",       "saas",      "Miro"),
    ("zoom-domain-verification",  "zoom",       "saas",      "Zoom"),
    ("workplace-domain-verification","meta",    "saas",      "Meta Workplace"),
    ("citrix-verification-code",  "citrix",     "saas",      "Citrix"),
    ("cisco-ci-domain-verification","cisco",    "saas",      "Cisco Webex/CI"),
    ("logmein-verification-code", "goto",       "saas",      "GoTo / LogMeIn"),
    ("mongodb-site-verification", "mongodb",    "saas",      "MongoDB Atlas"),
    ("onetrust-domain-verification","onetrust", "saas",      "OneTrust"),
    ("pardot",                    "salesforce", "saas",      "Salesforce Pardot"),
    ("azurewebsites.net",         "azure",      "cloud",     "Azure App Service reference"),
    ("windows-azure",             "azure",      "cloud",     "Azure reference in TXT"),
    ("aws",                       "aws",        "cloud",     "AWS reference in TXT (weak)"),
    ("have-i-been-pwned-verification","hibp",   "saas",      "HaveIBeenPwned domain"),
    ("status-page-domain-verification","atlassian","saas",   "Statuspage"),
    ("wrike-verification",        "wrike",      "saas",      "Wrike"),
    ("shopify",                   "shopify",    "saas",      "Shopify"),
]

# SPF `include:` fingerprints — enumerate third-party senders (SaaS footprint)
SPF_INCLUDE_FINGERPRINTS: List[Tuple[str, str, str, str]] = [
    ("_spf.google.com",         "google",     "mail", "Google Workspace sender"),
    ("spf.protection.outlook",  "microsoft",  "mail", "Microsoft 365 sender"),
    ("amazonses.com",           "aws",        "mail", "Amazon SES sender"),
    ("mailgun.org",             "mailgun",    "mail", "Mailgun"),
    ("sendgrid.net",            "sendgrid",   "mail", "SendGrid / Twilio"),
    ("servers.mcsv.net",        "mailchimp",  "mail", "Mailchimp / Mandrill"),
    ("spf.mandrillapp.com",     "mailchimp",  "mail", "Mandrill"),
    ("mktomail.com",            "marketo",    "mail", "Marketo"),
    ("zendesk.com",             "zendesk",    "saas", "Zendesk"),
    ("mail.zendesk.com",        "zendesk",    "saas", "Zendesk mail"),
    ("stspg-customer.com",      "atlassian",  "saas", "Statuspage"),
    ("spf.mtasv.net",           "postmark",   "mail", "Postmark"),
    ("_spf.salesforce.com",     "salesforce", "saas", "Salesforce"),
    ("spf.constantcontact.com", "constantcontact", "mail", "Constant Contact"),
    ("pphosted.com",            "proofpoint", "mail", "Proofpoint"),
    ("mimecast.com",            "mimecast",   "mail", "Mimecast"),
    ("hubspotemail.net",        "hubspot",    "saas", "HubSpot"),
    ("spf.exclaimer.net",       "exclaimer",  "saas", "Exclaimer"),
    ("intercom.io",             "intercom",   "saas", "Intercom"),
    ("qualtrics.com",           "qualtrics",  "saas", "Qualtrics"),
    ("freshemail.io",           "freshworks", "saas", "Freshworks"),
    ("spf.freshdesk.com",       "freshworks", "saas", "Freshdesk"),
    ("mailanyone.net",          "mailanyone", "mail", "Mail Anyone"),
    ("_spf.paychex.com",        "paychex",    "saas", "Paychex payroll"),
]

# Federation / ADFS host-name candidates to probe (prepended to apex)
ADFS_HOST_CANDIDATES = [
    "adfs", "sts", "fs", "sso", "federation", "login", "auth", "adfs01", "sts01",
]

# CNAME targets that reveal cloud/SaaS hosting when a candidate host resolves
FEDERATION_CNAME_HINTS: List[Tuple[str, str, str]] = [
    ("windows.net",         "microsoft", "Azure AD / hosted STS"),
    ("msappproxy.net",      "microsoft", "Azure AD App Proxy (on-prem ADFS published)"),
    ("okta.com",            "okta",      "Okta IdP"),
    ("onelogin.com",        "onelogin",  "OneLogin IdP"),
    ("pingidentity.com",    "ping",      "Ping Identity"),
    ("duosecurity.com",     "duo",       "Duo SSO"),
    ("auth0.com",           "auth0",     "Auth0"),
]


@dataclass
class SaaSFinding:
    apex: str
    provider: str
    category: str              # mail | tenant | saas | cloud | federation
    record_type: str           # MX | TXT | SPF | CNAME | A
    evidence: str
    note: str = ""
    severity: str = "info"     # attribution is informational by default
    host: str = ""             # for federation findings
    # C7 detection-cost: passive DNS lookups are invisible to the target.
    detection_cost: Dict[str, str] = field(default_factory=lambda: {
        "layer": "none", "target_visible": "false",
        "note": "passive third-party DNS resolution; target sees nothing",
    })


def _dig(name: str, rtype: str, timeout: int = 5) -> List[str]:
    """Return +short answer lines for name/rtype, [] on failure."""
    try:
        r = subprocess.run(
            [DIG, "+short", f"+time={timeout}", "+tries=1", name, rtype],
            capture_output=True, text=True, timeout=timeout + 3,
        )
    except (subprocess.SubprocessError, FileNotFoundError, OSError):
        return []
    out = []
    for line in r.stdout.splitlines():
        line = line.strip().strip('"')
        if line:
            out.append(line)
    return out


def _match(tokens: List[Tuple[str, str, str, str]], haystack: str
           ) -> List[Tuple[str, str, str]]:
    """Return list of (provider, category, note) whose token is in haystack."""
    hits = []
    low = haystack.lower()
    for token, provider, category, note in tokens:
        if token in low:
            hits.append((provider, category, note))
    return hits


class SaaSFingerprinter:
    def __init__(self, target: str, timeout: int = 5, probe_federation: bool = True):
        self.apex = target.strip().lower().rstrip(".")
        self.timeout = timeout
        self.probe_federation = probe_federation
        self.findings: List[SaaSFinding] = []
        self._seen = set()

    def _add(self, f: SaaSFinding) -> None:
        key = (f.provider, f.category, f.record_type, f.host)
        if key in self._seen:
            return
        self._seen.add(key)
        self.findings.append(f)

    def run(self) -> List[SaaSFinding]:
        self._mx()
        self._txt_and_spf()
        if self.probe_federation:
            self._federation()
        return self.findings

    def _mx(self) -> None:
        for rec in _dig(self.apex, "MX", self.timeout):
            host = rec.split()[-1].rstrip(".") if rec.split() else rec
            for provider, category, note in _match(MX_FINGERPRINTS, host):
                self._add(SaaSFinding(self.apex, provider, category, "MX",
                                      f"MX → {host}", note))

    def _txt_and_spf(self) -> None:
        txts = _dig(self.apex, "TXT", self.timeout)
        for rec in txts:
            for provider, category, note in _match(TXT_FINGERPRINTS, rec):
                self._add(SaaSFinding(self.apex, provider, category, "TXT",
                                      f"TXT contains token ({rec[:120]})", note))
            # SPF is a TXT record starting v=spf1
            if rec.lower().startswith("v=spf1"):
                for provider, category, note in _match(SPF_INCLUDE_FINGERPRINTS, rec):
                    self._add(SaaSFinding(self.apex, provider, category, "SPF",
                                          f"SPF include → {note}", note))
                # any include: not matched is still a third-party sender breadcrumb
                for inc in re.findall(r"include:([^\s]+)", rec, re.I):
                    if not any(tok in inc.lower()
                               for tok, *_ in SPF_INCLUDE_FINGERPRINTS):
                        self._add(SaaSFinding(
                            self.apex, "unknown", "mail", "SPF",
                            f"SPF include:{inc[:80]} (unrecognised 3rd-party sender)",
                            "third-party sender in SPF not in fingerprint table"))

    def _federation(self) -> None:
        """Discover ADFS / hosted IdP by resolving well-known host candidates.
        A live sts/adfs host is a Golden-SAML / AAD-Connect prerequisite."""
        for cand in ADFS_HOST_CANDIDATES:
            host = f"{cand}.{self.apex}"
            cnames = _dig(host, "CNAME", self.timeout)
            a = _dig(host, "A", self.timeout)
            if not cnames and not a:
                continue
            target_str = " ".join(cnames + a).lower()
            matched = False
            for hint, provider, note in FEDERATION_CNAME_HINTS:
                if hint in target_str:
                    self._add(SaaSFinding(
                        self.apex, provider, "federation", "CNAME",
                        f"{host} → {target_str[:120]}", note,
                        severity="low", host=host))
                    matched = True
            if not matched and a:
                # A record on adfs/sts = likely on-prem ADFS (Golden-SAML target)
                self._add(SaaSFinding(
                    self.apex, "adfs-onprem", "federation", "A",
                    f"{host} resolves to {', '.join(a)[:80]}",
                    "Federation host live — likely ADFS/STS (Golden-SAML + "
                    "AAD-Connect prerequisite; see cloud attack paths)",
                    severity="low", host=host))


def summarize(findings: List[SaaSFinding]) -> dict:
    providers: Dict[str, int] = {}
    by_cat: Dict[str, int] = {}
    for f in findings:
        providers[f.provider] = providers.get(f.provider, 0) + 1
        by_cat[f.category] = by_cat.get(f.category, 0) + 1
    return {
        "total": len(findings),
        "providers": dict(sorted(providers.items(), key=lambda x: -x[1])),
        "by_category": by_cat,
        "federation_found": any(f.category == "federation" for f in findings),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="C1 passive cloud/SaaS attribution")
    ap.add_argument("--target", required=True, help="apex domain")
    ap.add_argument("--output", required=True, help="output .jsonl path")
    ap.add_argument("--timeout", type=int, default=5)
    ap.add_argument("--no-federation", action="store_true",
                    help="skip ADFS/IdP host probing")
    args = ap.parse_args()

    fp = SaaSFingerprinter(args.target, timeout=args.timeout,
                           probe_federation=not args.no_federation)
    findings = fp.run()

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w") as fh:
        for f in findings:
            fh.write(json.dumps(asdict(f)) + "\n")

    summary = summarize(findings)
    (out.parent / "cloud_saas_summary.json").write_text(json.dumps(summary, indent=2))
    log(f"done: {summary['total']} attributions "
        f"({len(summary['providers'])} providers"
        f"{', FEDERATION' if summary['federation_found'] else ''}) -> {out}")
    if summary["providers"]:
        log("providers: " + ", ".join(f"{k}={v}"
                                       for k, v in summary["providers"].items()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
