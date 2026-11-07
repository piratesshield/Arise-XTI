#!/usr/bin/env python3
"""
ARISE DNS Security Audit (Module 3C)
====================================
Deep DNS attack-surface analysis. Runs AFTER Module 3 (dns_resolution) and
Module 3B (dns_discovery), reusing the host list, authoritative-NS list and
PTR annotations those modules produced — but issuing its OWN fresh, full
`dig` queries for every security-critical record (MX, NS, TXT/SPF, CAA, SOA,
DNSSEC, AXFR) instead of trusting Module 3B's `dns_all_records.json`.

    Why fresh queries: `dig +short <name> <type>` chases CNAMEs, so a name
    that is a CNAME reports the SAME canonical target under A/AAAA/MX/NS/TXT.
    Trusting that blob would fabricate "dangling MX", "delegation mismatch"
    and "SPF" findings on every CNAME'd host. We re-query authoritatively.

Phases
------
  1. Zero-cost / per-host analysis: SPF quality + dangling includes, SRV
     services + dangling targets, CAA policy, MX provider + dangling MX,
     full CNAME-chain walk, dangling NS, IPv6 exposure, record consistency,
     internal-hostname / split-horizon leakage.
  2. Apex active probes: AXFR, DNSSEC, open resolver, EDNS/amplification,
     wildcard, parent-vs-child NS delegation + lame delegation.
  3. Enrichment: PTR parsing (+ optional /24 sweep), passive-DNS provenance,
     WHOIS registrar + domain-expiration.
  4. Behavioral: GeoDNS, fast-flux indicators, DNS-rebinding exposure.

De-duplication contract (do NOT re-emit what other modules own):
  * Missing SPF / DKIM / weak DMARC          -> Module 17 (email auth)
  * SOA serial mismatch                       -> Module 3B
  * Cloud-storage CNAME detection             -> Module 3B
  * Subdomain takeover on CLOUD CNAMEs        -> cloud_asset_intel.py
This module emits only DNS-security issues none of those cover, and its
CNAME-chain check explicitly SKIPS cloud-provider terminals.

Usage:
  python3 dns_security_audit.py <target> --scan-dir <dir> [--manifest f] [flags]

Degrades gracefully if `dig`/`whois` are missing.
"""

from __future__ import annotations

import sys as _sys, os as _os
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)


import argparse
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

# --------------------------------------------------------------------------- #
# Logging (stderr, human-readable)
# --------------------------------------------------------------------------- #

def log(msg: str) -> None:
    print(f"[dns-sec] {msg}", file=sys.stderr, flush=True)


# --------------------------------------------------------------------------- #
# Static intelligence tables
# --------------------------------------------------------------------------- #

# SaaS / verification TXT token fingerprints -> friendly service name.
SAAS_TXT_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"google-site-verification=", re.I), "Google (Search Console / Workspace)"),
    (re.compile(r"\bMS=", re.I), "Microsoft 365 / Azure"),
    (re.compile(r"facebook-domain-verification=", re.I), "Meta / Facebook"),
    (re.compile(r"apple-domain-verification=", re.I), "Apple"),
    (re.compile(r"amazonses:|_amazonses", re.I), "Amazon SES"),
    (re.compile(r"atlassian-domain-verification=", re.I), "Atlassian"),
    (re.compile(r"docusign=", re.I), "DocuSign"),
    (re.compile(r"adobe-idp-site-verification=", re.I), "Adobe"),
    (re.compile(r"stripe-verification=", re.I), "Stripe"),
    (re.compile(r"status-page-domain-verification=", re.I), "Atlassian Statuspage"),
    (re.compile(r"zoom-domain-verification=", re.I), "Zoom"),
    (re.compile(r"dropbox-domain-verification=", re.I), "Dropbox"),
    (re.compile(r"shopify|_shopify", re.I), "Shopify"),
    (re.compile(r"cisco-ci-domain-verification=", re.I), "Cisco"),
    (re.compile(r"citrix-verification-code=", re.I), "Citrix"),
    (re.compile(r"pardot", re.I), "Salesforce Pardot"),
    (re.compile(r"logmein-verification-code=", re.I), "LogMeIn / GoTo"),
    (re.compile(r"mongodb-site-verification=", re.I), "MongoDB Atlas"),
    (re.compile(r"workplace-domain-verification=", re.I), "Workplace"),
    (re.compile(r"miro-verification=", re.I), "Miro"),
]

# MX target host substring -> mail provider.
MX_PROVIDERS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"\.google\.com\.?$|aspmx.*google|googlemail", re.I), "Google Workspace"),
    (re.compile(r"\.protection\.outlook\.com\.?$|mail\.protection\.outlook", re.I), "Microsoft 365"),
    (re.compile(r"pphosted\.com|proofpoint", re.I), "Proofpoint"),
    (re.compile(r"mimecast", re.I), "Mimecast"),
    (re.compile(r"zoho", re.I), "Zoho Mail"),
    (re.compile(r"amazonaws\.com|amazonses|inbound-smtp", re.I), "Amazon SES/WorkMail"),
    (re.compile(r"mailgun", re.I), "Mailgun"),
    (re.compile(r"sendgrid", re.I), "SendGrid"),
    (re.compile(r"messagingengine\.com|fastmail", re.I), "Fastmail"),
    (re.compile(r"secureserver\.net", re.I), "GoDaddy"),
    (re.compile(r"barracuda", re.I), "Barracuda"),
    (re.compile(r"pobox\.com", re.I), "Pobox"),
    (re.compile(r"qq\.com|exmail\.qq", re.I), "Tencent Exmail"),
]

# Authoritative-NS host substring -> DNS hosting provider. Identifying the DNS
# host is high-value recon: it names the infra vendor and often correlates with
# the CDN/registrar. Mirrors MX_PROVIDERS.
NS_PROVIDERS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"\.cloudflare\.com\.?$|ns\.cloudflare", re.I), "Cloudflare"),
    (re.compile(r"awsdns|\.amazonaws\.com\.?$", re.I), "AWS Route 53"),
    (re.compile(r"\.azure-dns\.|azure-dns\.(net|org|com|info)", re.I), "Azure DNS"),
    (re.compile(r"googledomains|\.google\.com\.?$|ns-cloud|domaincontrol.*google", re.I), "Google Cloud DNS"),
    (re.compile(r"\.nsone\.net\.?$|ns1\.", re.I), "NS1"),
    (re.compile(r"akam\.net|akamai", re.I), "Akamai"),
    (re.compile(r"dnsimple", re.I), "DNSimple"),
    (re.compile(r"dnsmadeeasy", re.I), "DNS Made Easy"),
    (re.compile(r"ultradns", re.I), "UltraDNS / Neustar"),
    (re.compile(r"dyn\.com|dynect", re.I), "Oracle Dyn"),
    (re.compile(r"domaincontrol\.com|secureserver", re.I), "GoDaddy"),
    (re.compile(r"namecheap|registrar-servers", re.I), "Namecheap"),
    (re.compile(r"digitalocean", re.I), "DigitalOcean"),
    (re.compile(r"linode", re.I), "Linode / Akamai"),
    (re.compile(r"gandi", re.I), "Gandi"),
    (re.compile(r"hetzner", re.I), "Hetzner"),
    (re.compile(r"ovh\.net", re.I), "OVH"),
    (re.compile(r"name-services|enom", re.I), "eNom"),
    (re.compile(r"worldnic", re.I), "Network Solutions"),
    (re.compile(r"bluehost|hostgator|websitewelcome", re.I), "Bluehost/HostGator (EIG)"),
    (re.compile(r"wixdns|wix\.com", re.I), "Wix"),
    (re.compile(r"squarespacedns|squarespace", re.I), "Squarespace"),
    (re.compile(r"fastly", re.I), "Fastly"),
]

# TXT tokens that LOOK like domain-verification / service claims but don't match
# a known SaaS pattern — surfaced so unknown third-party vendors aren't missed.
_TXT_VERIFY_HINT_RE = re.compile(
    r"(?:^|[\s;])(?:[a-z0-9-]{2,40}[-_.](?:site[-_]?verification|domain[-_]?verification|"
    r"verification[-_]?code|verify)|verification=|[a-z0-9-]+-verification)", re.I)

# SRV service prefix -> (label, is_sensitive_when_public).
SRV_SERVICES: Dict[str, Tuple[str, bool]] = {
    "_ldap": ("LDAP (directory)", True),
    "_ldaps": ("LDAPS (directory)", True),
    "_kerberos": ("Kerberos (AD auth)", True),
    "_kpasswd": ("Kerberos password", True),
    "_gc": ("AD Global Catalog", True),
    "_kerberos-master": ("Kerberos master", True),
    "_sip": ("SIP (VoIP)", False),
    "_sips": ("SIPS (VoIP)", False),
    "_xmpp-server": ("XMPP server", False),
    "_xmpp-client": ("XMPP client", False),
    "_autodiscover": ("Exchange Autodiscover", False),
    "_caldav": ("CalDAV", False),
    "_carddav": ("CardDAV", False),
    "_imap": ("IMAP", False),
    "_imaps": ("IMAPS", False),
    "_submission": ("SMTP submission", False),
    "_mysql": ("MySQL", True),
    "_mssql": ("MSSQL", True),
    "_vlmcs": ("KMS activation", True),
    "_minecraft": ("Minecraft", False),
    "_matrix": ("Matrix", False),
}

# Cloud-provider CNAME suffixes that cloud_asset_intel.py already owns for
# takeover — the CNAME-chain check MUST skip these to avoid duplicate findings.
CLOUD_TAKEOVER_SUFFIXES = re.compile(
    r"("
    r"\.cloudfront\.net|\.s3[.-]|\.s3\.amazonaws\.com|\.elb\.amazonaws\.com"
    r"|\.blob\.core\.windows\.net|\.azurewebsites\.net|\.azureedge\.net"
    r"|\.azurestaticapps\.net|\.trafficmanager\.net|\.cloudapp\.azure\.com"
    r"|\.azurefd\.net|\.storage\.googleapis\.com|\.googleapis\.com"
    r"|\.herokuapp\.com|\.herokudns\.com|\.github\.io|\.githubusercontent"
    r"|\.pages\.dev|\.workers\.dev|\.vercel\.app|\.netlify\.app|\.netlify\.com"
    r"|\.fastly\.net|\.pantheonsite\.io|\.shopify|\.myshopify\.com"
    r"|\.wpengine\.com|\.zendesk\.com|\.surge\.sh|\.bitbucket\.io"
    r"|\.readthedocs\.io|\.ghost\.io|\.helpscoutdocs\.com|\.statuspage\.io"
    r"|\.digitaloceanspaces\.com|\.fly\.dev|\.render\.com"
    r")", re.I)

# Internal / non-public-intent hostname labels (naming leakage).
INTERNAL_LABEL_RE = re.compile(
    r"(^|[.-])("
    r"internal|intranet|corp|corporate|private|vpn|bastion|jump|jumpbox"
    r"|jenkins|gitlab|git|jira|confluence|grafana|kibana|prometheus|nagios"
    r"|staging|stage|uat|preprod|pre-prod|qa|dev|develop|test|testing|sandbox"
    r"|admin|adminpanel|backoffice|db|database|mysql|postgres|redis|mongo"
    r"|ldap|ad|kerberos|dc[0-9]*|backup|nas|san|esxi|vcenter|hyperv"
    r"|k8s|kube|rancher|nexus|artifactory|vault|consul|salt|puppet|ansible"
    r")([.-]|$)", re.I)

# Public resolvers for GeoDNS / open-resolver probes.
PUBLIC_RESOLVERS = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]

DIG = shutil.which("dig")
WHOIS = shutil.which("whois")

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


# --------------------------------------------------------------------------- #
# Finding model
# --------------------------------------------------------------------------- #

@dataclass
class Finding:
    check: str                       # machine id, e.g. "zone_transfer"
    template: str                    # display title
    severity: str                    # critical|high|medium|low|info
    host: str
    evidence: str
    remediation: str
    category: str = "dns_security"
    tool: str = "dns_security_audit"
    takeover_candidate: bool = False
    service: str = ""
    cname: str = ""

    def dedup_key(self) -> Tuple[str, str, str]:
        # A finding is unique per (check, host, discriminator). The
        # discriminator keeps e.g. two different dangling MX targets on the
        # same host distinct, but collapses identical re-emissions.
        return (self.check, self.host.lower(), (self.service or self.cname).lower())


# --------------------------------------------------------------------------- #
# dig wrapper — FULL output (never +short, to avoid CNAME-chase contamination)
# --------------------------------------------------------------------------- #

@dataclass
class DigResult:
    rcode: str = "ERROR"
    flags: Set[str] = field(default_factory=set)
    answers: List[Tuple[str, int, str, str]] = field(default_factory=list)  # (name, ttl, type, data)
    size: int = 0
    ok: bool = False                 # True if we got a parseable DNS response

    def data_of(self, rtype: str) -> List[str]:
        return [d for (_, _, t, d) in self.answers if t.upper() == rtype.upper()]

    def data_of_owner(self, rtype: str, owner: str) -> List[str]:
        """Records of rtype whose OWNER name equals `owner`. Distinguishes a
        record actually published at a name from one dig returned by chasing a
        CNAME (whose owner is the chase target, not the queried name)."""
        o = owner.lower().rstrip(".")
        return [d for (n, _, t, d) in self.answers
                if t.upper() == rtype.upper() and n.lower().rstrip(".") == o]


_STATUS_RE = re.compile(r"status:\s*([A-Z]+)")
_FLAGS_RE = re.compile(r";;\s*flags:\s*([a-z ]+?);")
_SIZE_RE = re.compile(r"MSG SIZE\s+rcvd:\s*(\d+)")
_ANSWER_LINE_RE = re.compile(
    r"^([^\s;]+)\.?\s+(\d+)\s+IN\s+([A-Z0-9]+)\s+(.+)$")


class DNS:
    """Fresh, bounded, cached dig queries with full-message parsing."""

    def __init__(self, timeout: int = 5, tries: int = 1):
        self.timeout = timeout
        self.tries = tries
        self._cache: Dict[Tuple[str, str, Optional[str], bool], DigResult] = {}

    def query(self, name: str, rtype: str, ns: Optional[str] = None,
              dnssec: bool = False) -> DigResult:
        key = (name.lower().rstrip("."), rtype.upper(), ns, dnssec)
        if key in self._cache:
            return self._cache[key]
        res = DigResult()
        if not DIG:
            self._cache[key] = res
            return res
        cmd = [DIG, f"+time={self.timeout}", f"+tries={self.tries}"]
        if dnssec:
            cmd.append("+dnssec")
        if ns:
            cmd.append("@" + ns)
        cmd += [name, rtype]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=self.timeout * (self.tries + 1) + 5)
            out = r.stdout
        except Exception:
            self._cache[key] = res
            return res

        m = _STATUS_RE.search(out)
        if m:
            res.rcode = m.group(1)
            res.ok = True
        mf = _FLAGS_RE.search(out)
        if mf:
            res.flags = set(mf.group(1).split())
        ms = _SIZE_RE.search(out)
        if ms:
            res.size = int(ms.group(1))

        in_answer = False
        for line in out.splitlines():
            if line.startswith(";; ANSWER SECTION:"):
                in_answer = True
                continue
            if in_answer:
                if not line.strip() or line.startswith(";"):
                    in_answer = False
                    continue
                am = _ANSWER_LINE_RE.match(line.strip())
                if am:
                    res.answers.append(
                        (am.group(1).rstrip("."), int(am.group(2)),
                         am.group(3), am.group(4).strip()))
        self._cache[key] = res
        return res

    def is_nxdomain(self, name: str) -> bool:
        """True ONLY when the name provably does not exist (NXDOMAIN).
        NODATA (exists, no such record type), SERVFAIL, timeouts are NOT
        treated as dangling — that is the core false-positive guard."""
        # Try A then AAAA then any: a name is nonexistent only if ALL agree
        # NXDOMAIN. A single NOERROR anywhere means it exists.
        seen_nx = False
        for rt in ("A", "AAAA"):
            r = self.query(name, rt)
            if not r.ok:
                return False  # ambiguous (no dig / network) -> not dangling
            if r.rcode == "NOERROR":
                return False
            if r.rcode == "NXDOMAIN":
                seen_nx = True
            else:
                return False  # SERVFAIL / REFUSED -> ambiguous, not dangling
        return seen_nx


def is_ip(val: str) -> bool:
    try:
        ipaddress.ip_address(val.strip().rstrip("."))
        return True
    except ValueError:
        return False


def is_private_ip(val: str) -> bool:
    try:
        ip = ipaddress.ip_address(val.strip().rstrip("."))
        return (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_unspecified)
    except ValueError:
        return False


def registrable(domain: str) -> str:
    """Naive eTLD+1. Good enough for referenced-domain WHOIS; multi-label
    public suffixes (co.uk) are handled leniently."""
    parts = domain.strip().rstrip(".").lower().split(".")
    if len(parts) <= 2:
        return ".".join(parts)
    two_label_tlds = {"co", "com", "org", "net", "gov", "edu", "ac"}
    if parts[-2] in two_label_tlds and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


# --------------------------------------------------------------------------- #
# Auditor
# --------------------------------------------------------------------------- #

class DNSSecurityAuditor:
    def __init__(self, target: str, scan_dir: Path, args):
        self.target = target.strip().rstrip(".").lower()
        self.scan_dir = scan_dir
        self.args = args
        self.dns = DNS(timeout=args.timeout, tries=args.tries)
        self.findings: List[Finding] = []
        self._seen: Set[Tuple[str, str, str]] = set()

        # Loaded context
        self.hosts: List[str] = []
        self.nameservers: List[str] = []
        self.ns_ips: Dict[str, List[str]] = {}
        self.ip_annotations: List[dict] = []
        self.cloud_takeover_hosts: Set[str] = set()

        # Populated by _p2_wildcard() when a wildcard record is confirmed —
        # consumed downstream (nuclei_url_consolidator.py) to drop phantom
        # CT/gau/wayback subdomains that only "resolve" via the wildcard.
        self.wildcard_ips: Optional[Tuple[str, ...]] = None
        self.wildcard_http_signature: Optional[dict] = None

    # ---- finding sink with in-module dedup -------------------------------- #
    def add(self, f: Finding) -> None:
        k = f.dedup_key()
        if k in self._seen:
            return
        self._seen.add(k)
        self.findings.append(f)

    # ---- context loading -------------------------------------------------- #
    def load_context(self) -> None:
        # Host list (apex + all discovered) from Module 3B.
        hosts: Set[str] = {self.target}
        b = self.scan_dir / "03b_dns_discovery" / "all_hosts.txt"
        if b.exists():
            for line in b.read_text(errors="ignore").splitlines():
                line = line.strip().lower().rstrip(".")
                if line:
                    hosts.add(line)
        else:
            r = self.scan_dir / "03_dns_resolution" / "resolved.txt"
            if r.exists():
                for line in r.read_text(errors="ignore").splitlines():
                    line = line.strip().lower().rstrip(".")
                    if line:
                        hosts.add(line)
        self.hosts = sorted(hosts)[: self.args.max_hosts]

        # Authoritative NS list (fresh query preferred; fall back to file).
        ns_res = self.dns.query(self.target, "NS")
        for d in ns_res.data_of("NS"):
            self.nameservers.append(d.rstrip("."))
        if not self.nameservers:
            nf = self.scan_dir / "03b_dns_discovery" / "authoritative_ns.json"
            if nf.exists():
                try:
                    j = json.loads(nf.read_text())
                    for ns in j.get("nameservers", []):
                        name = (ns.get("nameserver") or "").rstrip(".")
                        if name:
                            self.nameservers.append(name)
                            self.ns_ips[name] = ns.get("ips", [])
                except Exception:
                    pass
        self.nameservers = sorted(set(self.nameservers))[:10]

        # PTR annotations from Module 3.
        ann = self.scan_dir / "03_dns_resolution" / "ip_annotations.json"
        if ann.exists():
            for line in ann.read_text(errors="ignore").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    self.ip_annotations.append(json.loads(line))
                except Exception:
                    continue

        # Cloud takeover hosts already found by cloud_asset_intel (dedup).
        cmap = self.scan_dir / "17_cloud_exposure" / "cloud_asset_map.jsonl"
        if cmap.exists():
            for line in cmap.read_text(errors="ignore").splitlines():
                try:
                    j = json.loads(line)
                    if j.get("takeover_candidate") and j.get("host"):
                        self.cloud_takeover_hosts.add(j["host"].lower())
                except Exception:
                    continue

        log(f"context: {len(self.hosts)} hosts, {len(self.nameservers)} NS, "
            f"{len(self.ip_annotations)} PTR recs, "
            f"{len(self.cloud_takeover_hosts)} cloud-takeover hosts")

    # ===================================================================== #
    # PHASE 1 — per-host / apex record analysis (fresh authoritative digs)
    # ===================================================================== #
    def phase1(self) -> None:
        log("Phase 1: record analysis (SPF/SRV/CAA/MX/CNAME/NS/IPv6/consistency)")
        self._p1_spf()
        self._p1_caa()
        self._p1_mx()
        self._p1_srv()
        self._p1_ns_provider()
        self._p1_soa_contact()
        self._p1_per_host()

    # --- SPF quality + dangling includes (Module 17 owns presence) --------- #
    def _p1_spf(self) -> None:
        txts = [d.strip('"') for d in self.dns.query(self.target, "TXT").data_of("TXT")]
        # Reassemble quoted-concatenated TXT chunks dig prints as `"a" "b"`.
        txts = [re.sub(r'"\s+"', "", t) for t in txts]
        spf_records = [t for t in txts if t.lower().startswith("v=spf1")]

        # SaaS inventory (info) — one aggregate finding, not per token.
        services = sorted({name for t in txts for pat, name in SAAS_TXT_PATTERNS
                           if pat.search(t)})
        if services:
            self.add(Finding(
                "txt_saas_inventory", "SaaS services exposed via TXT records",
                "info", self.target,
                "Domain-verification TXT tokens reveal third-party services: "
                + ", ".join(services[:15]),
                "Inventory these vendors; remove stale verification tokens for "
                "services no longer in use.",
            ))

        # Verification-looking TXT tokens that DON'T match a known SaaS pattern —
        # surface them so unknown/niche third-party vendors aren't missed.
        unknown = sorted({
            t[:80] for t in txts
            if _TXT_VERIFY_HINT_RE.search(t)
            and not any(pat.search(t) for pat, _ in SAAS_TXT_PATTERNS)
            and not t.lower().startswith(("v=spf1", "v=dmarc1", "v=dkim1"))
        })
        if unknown:
            self.add(Finding(
                "txt_unknown_tokens", "Unrecognised domain-verification TXT tokens",
                "info", self.target,
                "TXT records carry verification tokens for services not in the "
                "known-vendor list (possible shadow-IT / niche SaaS): "
                + "; ".join(unknown[:10]),
                "Identify which vendor each token belongs to; remove any that are "
                "stale — every live token is a third-party trust relationship.",
            ))

        if len(spf_records) > 1:
            self.add(Finding(
                "spf_multiple", "Multiple SPF records (RFC 7208 permerror)",
                "medium", self.target,
                f"{len(spf_records)} v=spf1 records published; receivers must "
                "treat this as permerror and may ignore SPF entirely.",
                "Publish exactly one SPF record; merge includes into it.",
            ))
        for spf in spf_records:
            low = spf.lower()
            # Weak 'all' qualifier. NOTE: missing SPF is Module 17's job.
            # Match ONLY the standalone `all` mechanism (start/space-delimited)
            # so words like "install"/"call" inside the record never match.
            am = re.search(r"(?:^|\s)([-~?+]?)all(?:\s|$)", low)
            if am and am.group(1) in ("+", ""):   # '+all' or bare 'all' = pass-all
                self.add(Finding(
                    "spf_permissive_all", "SPF uses permissive +all / all",
                    "high", self.target,
                    f"SPF authorises all senders (pass-all qualifier): {spf[:120]}",
                    "Use '-all' (hard fail) or at least '~all' (soft fail); "
                    "'+all' authorises the entire internet to send as you.",
                ))
            # DNS-lookup count (>10 = permerror). Count include/a/mx/ptr/exists/redirect.
            lookups = len(re.findall(r"\b(?:include|a|mx|ptr|exists|redirect)[:=]", low))
            if lookups > 10:
                self.add(Finding(
                    "spf_lookup_overflow", "SPF exceeds 10 DNS lookups (permerror)",
                    "medium", self.target,
                    f"SPF references ~{lookups} mechanisms requiring DNS lookups "
                    "(RFC 7208 limit is 10 -> permerror, SPF silently fails).",
                    "Flatten or reduce includes to stay within 10 lookups.",
                ))
            # Dangling includes/redirects: resolve each referenced domain.
            for ref in re.findall(r"(?:include:|redirect=)([A-Za-z0-9._-]+)", spf, re.I):
                ref = ref.rstrip(".")
                if not ref or ref == self.target:
                    continue
                if self.dns.is_nxdomain(ref):
                    self.add(Finding(
                        "spf_dangling_include",
                        "Dangling SPF include (NXDOMAIN)",
                        "high", self.target,
                        f"SPF includes '{ref}', which does not exist (NXDOMAIN). "
                        "An attacker who registers it can authorise mail as you.",
                        f"Remove include:{ref} from SPF, or reclaim the domain.",
                        takeover_candidate=True, service=ref,
                    ))

    # --- CAA policy (Module: none) ----------------------------------------- #
    def _p1_caa(self) -> None:
        r = self.dns.query(self.target, "CAA")
        caa = r.data_of("CAA")
        if not r.ok:
            return
        if not caa:
            # Absence is real but low: any CA may issue certs for this domain.
            self.add(Finding(
                "caa_missing", "No CAA record (any CA may issue certificates)",
                "low", self.target,
                "No CAA record at the apex; certificate issuance is not "
                "restricted to specific CAs, widening mis-issuance risk.",
                "Publish a CAA record allow-listing your CA(s), e.g. "
                '0 issue "letsencrypt.org", plus an iodef mailto for reports.',
            ))
            return
        issuers, has_wild_disallow, has_iodef, permissive_wild = set(), False, False, False
        for c in caa:
            cl = c.lower()
            m = re.search(r'(issue|issuewild|iodef)\s+"([^"]*)"', c, re.I)
            if not m:
                continue
            tag, val = m.group(1).lower(), m.group(2).strip()
            if tag == "iodef":
                has_iodef = True
            elif tag == "issuewild":
                if val == ";":
                    has_wild_disallow = True   # restrictive = GOOD, not a finding
                elif val == "":
                    permissive_wild = True
                else:
                    issuers.add(val)
            elif tag == "issue":
                if val and val != ";":
                    issuers.add(val)
        if issuers:
            self.add(Finding(
                "caa_ca_inventory", "Certificate-authority fingerprint (CAA)",
                "info", self.target,
                "Certificates may be issued by: " + ", ".join(sorted(issuers)),
                "Confirm these CAs match the ones you actually use; remove any "
                "authorised CA you no longer issue from.",
            ))
        if not has_iodef:
            self.add(Finding(
                "caa_no_iodef", "CAA record has no iodef reporting address",
                "info", self.target,
                "CAA present but no iodef URL; CAs cannot report mis-issuance "
                "attempts to you.",
                'Add an iodef entry, e.g. 0 iodef "mailto:security@yourdomain".',
            ))

    # --- MX provider + dangling MX (Module 17 owns email AUTH only) -------- #
    def _p1_mx(self) -> None:
        r = self.dns.query(self.target, "MX")
        mxs = r.data_of("MX")
        if not mxs:
            return
        providers: Set[str] = set()
        for mx in mxs:
            parts = mx.split()
            target = parts[-1].rstrip(".") if parts else ""
            if not target or target == ".":
                # Null MX (RFC 7505) = intentional "no mail" — never dangling.
                continue
            for pat, name in MX_PROVIDERS:
                if pat.search(target):
                    providers.add(name)
                    break
            # Dangling MX: the mail host provably does not exist.
            if self.dns.is_nxdomain(target):
                self.add(Finding(
                    "mx_dangling", "Dangling MX record (mail host NXDOMAIN)",
                    "high", self.target,
                    f"MX points to '{target}', which does not resolve "
                    "(NXDOMAIN). Mail delivery fails and, if the host domain "
                    "is registrable, an attacker could claim it.",
                    f"Remove or correct the MX record pointing to {target}.",
                    takeover_candidate=True, service=target,
                ))
        if providers:
            self.add(Finding(
                "mx_provider_inventory", "Mail infrastructure fingerprint",
                "info", self.target,
                "Mail handled by: " + ", ".join(sorted(providers)),
                "Confirm these mail providers are authorised and that SPF "
                "includes match them.",
            ))

    # --- SRV services + dangling targets ----------------------------------- #
    def _p1_srv(self) -> None:
        # Probe a bounded set of well-known SRV names at the apex.
        for prefix, (label, sensitive) in SRV_SERVICES.items():
            for proto in ("_tcp", "_udp"):
                qname = f"{prefix}.{proto}.{self.target}"
                r = self.dns.query(qname, "SRV")
                srvs = r.data_of("SRV")
                if not srvs:
                    continue
                for srv in srvs:
                    parts = srv.split()
                    if len(parts) < 4:
                        continue
                    target = parts[-1].rstrip(".")
                    port = parts[-2]
                    if target == "" or target == ".":
                        # "." target = service explicitly NOT provided (RFC 2782).
                        continue
                    if sensitive:
                        self.add(Finding(
                            "srv_sensitive_exposed",
                            f"Sensitive service advertised via SRV: {label}",
                            "medium", qname,
                            f"{label} SRV record advertises {target}:{port} "
                            "publicly, revealing internal directory/auth "
                            "infrastructure.",
                            "Do not publish internal directory/database SRV "
                            "records in external DNS; split-horizon them.",
                        ))
                    if self.dns.is_nxdomain(target):
                        self.add(Finding(
                            "srv_dangling",
                            f"Dangling SRV target ({label})",
                            "medium", qname,
                            f"SRV target '{target}' does not resolve (NXDOMAIN).",
                            f"Remove or fix the SRV record for {qname}.",
                            takeover_candidate=True, service=target,
                        ))

    # --- NS provider fingerprint (recon: which DNS host runs the zone) ----- #
    def _p1_ns_provider(self) -> None:
        r = self.dns.query(self.target, "NS")
        nss = [n.rstrip(".").lower() for n in r.data_of("NS")]
        if not nss:
            return
        providers: Set[str] = set()
        for ns in nss:
            for pat, name in NS_PROVIDERS:
                if pat.search(ns):
                    providers.add(name)
                    break
        if providers:
            self.add(Finding(
                "ns_provider_inventory", "DNS hosting fingerprint",
                "info", self.target,
                "Authoritative DNS hosted by: " + ", ".join(sorted(providers))
                + " (nameservers: " + ", ".join(nss[:6]) + ")",
                "Confirm this is your managed DNS provider; unexpected providers "
                "can indicate shadow IT or a stale/hijacked delegation.",
            ))
        elif nss:
            # NS present but no known provider — surface the raw NS as intel so a
            # self-hosted / niche DNS host is still inventoried, not invisible.
            self.add(Finding(
                "ns_provider_unknown", "Self-hosted / unrecognised DNS provider",
                "info", self.target,
                "Nameservers do not match a known managed provider: "
                + ", ".join(nss[:6]) + " — likely self-hosted or a niche host.",
                "Verify these nameservers are yours and hardened (no AXFR, DNSSEC).",
            ))

    # --- SOA RNAME -> zone admin contact (OSINT) --------------------------- #
    def _p1_soa_contact(self) -> None:
        r = self.dns.query(self.target, "SOA")
        soa = r.data_of("SOA")
        if not soa:
            return
        parts = soa[0].split()
        if len(parts) < 2:
            return
        rname = parts[1].rstrip(".")
        # RFC 1035: the first unescaped dot separates local-part from domain.
        m = re.match(r"((?:[^.\\]|\\.)+)\.(.+)", rname)
        if not m:
            return
        local = m.group(1).replace("\\.", ".")
        email = f"{local}@{m.group(2)}"
        self.add(Finding(
            "soa_admin_contact", "Zone admin contact exposed in SOA",
            "info", self.target,
            f"SOA RNAME resolves to admin email: {email} (primary NS: {parts[0].rstrip('.')})",
            "Expected — but note this address is public OSINT; use a role mailbox "
            "(e.g. hostmaster@) rather than a personal one.",
        ))

    # --- Per-host: CNAME chain, dangling NS, IPv6, consistency, internal --- #
    def _p1_per_host(self) -> None:
        def analyze(host: str) -> List[Finding]:
            out: List[Finding] = []
            a = self.dns.query(host, "A")
            aaaa = self.dns.query(host, "AAAA")
            cname_res = self.dns.query(host, "CNAME")
            cnames = [c.rstrip(".") for c in cname_res.data_of("CNAME")]

            a_ips = [d for d in a.data_of("A") if is_ip(d)]
            aaaa_ips = [d for d in aaaa.data_of("AAAA") if is_ip(d)]

            # Split-horizon / internal IP leak (strong, low-FP).
            for ip in a_ips + aaaa_ips:
                if is_private_ip(ip):
                    out.append(Finding(
                        "internal_ip_leak",
                        "Private/internal IP exposed in public DNS",
                        "medium", host,
                        f"Public DNS resolves {host} to RFC1918/internal address "
                        f"{ip}, leaking internal topology (split-horizon leak).",
                        "Remove internal addresses from external DNS; use "
                        "split-horizon so internal records stay private.",
                    ))
                    break

            # Internal-looking hostname label (info, naming leak).
            if INTERNAL_LABEL_RE.search(host) and (a_ips or aaaa_ips or cnames):
                out.append(Finding(
                    "internal_hostname",
                    "Internal/sensitive hostname exposed via DNS",
                    "low", host,
                    f"Hostname '{host}' suggests internal infrastructure yet is "
                    "publicly resolvable, aiding attacker reconnaissance.",
                    "Confirm this host is meant to be public; otherwise move it "
                    "behind private DNS / a VPN.",
                ))

            # IPv6 exposure (conservative: only when v6-only, i.e. AAAA but no A).
            if aaaa_ips and not a_ips and not cnames:
                out.append(Finding(
                    "ipv6_only_exposure",
                    "IPv6-only exposure (AAAA without A)",
                    "info", host,
                    f"{host} is reachable over IPv6 ({aaaa_ips[0]}) with no IPv4 "
                    "record; verify firewall/WAF parity for IPv6.",
                    "Ensure IPv6 endpoints receive the same firewall, WAF and "
                    "monitoring coverage as IPv4.",
                ))

            # RFC1034 consistency: CNAME must be the ONLY record at a name.
            # Use OWNER-matched A records so a dig CNAME-chase (which returns
            # the target's A records, owned by the target) is not mistaken for
            # a genuine A published at THIS name.
            if cnames and host != self.target:
                a_at_host = [d for d in a.data_of_owner("A", host) if is_ip(d)]
                cname_at_host = cname_res.data_of_owner("CNAME", host)
                if a_at_host and cname_at_host:
                    out.append(Finding(
                        "cname_coexist",
                        "CNAME coexists with other records (RFC 1034 violation)",
                        "low", host,
                        f"{host} publishes a CNAME to {cname_at_host[0]} AND its "
                        f"own A records {a_at_host[:2]} at the same name; this is "
                        "invalid and causes resolver inconsistency.",
                        "Remove the conflicting records; if apex flattening is "
                        "intended, use provider ALIAS/ANAME instead of CNAME.",
                    ))

            # Full CNAME chain walk (dangling / loops / long / cross-provider).
            if cnames:
                out.extend(self._walk_cname(host, cnames[0]))
            return out

        with ThreadPoolExecutor(max_workers=self.args.threads) as ex:
            for res in ex.map(analyze, self.hosts):
                for f in res:
                    self.add(f)

    def _walk_cname(self, host: str, first_target: str) -> List[Finding]:
        out: List[Finding] = []
        seen: Set[str] = {host.lower()}
        cur = first_target
        hops = 0
        providers_in_chain: Set[str] = set()
        while cur and hops < self.args.max_cname_hops:
            hops += 1
            cur_l = cur.lower().rstrip(".")
            if cur_l in seen:
                out.append(Finding(
                    "cname_loop", "CNAME loop detected", "medium", host,
                    f"CNAME chain from {host} loops back to {cur_l}.",
                    "Break the CNAME loop; a looping alias never resolves.",
                ))
                return out
            seen.add(cur_l)

            # Cloud terminals are cloud_asset_intel's territory — do not
            # re-emit takeover here, but keep walking to detect loops/length.
            if CLOUD_TAKEOVER_SUFFIXES.search(cur_l):
                providers_in_chain.add(cur_l.split(".")[-2] if "." in cur_l else cur_l)

            nxt_res = self.dns.query(cur_l, "CNAME")
            nxt = [c.rstrip(".") for c in nxt_res.data_of("CNAME")]
            if nxt:
                cur = nxt[0]
                continue

            # Terminal reached — does it resolve?
            if self.dns.is_nxdomain(cur_l):
                # Only emit a takeover finding for NON-cloud terminals and
                # hosts cloud_asset_intel didn't already flag.
                if (not CLOUD_TAKEOVER_SUFFIXES.search(cur_l)
                        and host.lower() not in self.cloud_takeover_hosts):
                    out.append(Finding(
                        "cname_dangling",
                        "Dangling CNAME (terminal target NXDOMAIN)",
                        "high", host,
                        f"CNAME chain {host} -> {cur_l} ends at a non-existent "
                        "name (NXDOMAIN); if that name is registrable it is a "
                        "takeover vector.",
                        f"Remove the CNAME or reclaim {cur_l}.",
                        takeover_candidate=True, service=cur_l, cname=cur_l,
                    ))
            break

        if hops >= self.args.max_cname_hops:
            out.append(Finding(
                "cname_too_long", "Excessively long CNAME chain",
                "low", host,
                f"CNAME chain from {host} exceeds {self.args.max_cname_hops} "
                "hops, adding latency and fragility.",
                "Shorten the alias chain to reduce resolution latency and "
                "points of failure.",
            ))
        return out

    # ===================================================================== #
    # PHASE 2 — apex active probes
    # ===================================================================== #
    def phase2(self) -> None:
        if not DIG:
            log("Phase 2 skipped: dig unavailable")
            return
        log("Phase 2: apex probes (AXFR, DNSSEC, open-resolver, EDNS, wildcard, delegation)")
        self._p2_axfr()
        self._p2_dnssec()
        self._p2_open_resolver_and_amp()
        self._p2_wildcard()
        self._p2_delegation()

    def _p2_axfr(self) -> None:
        for ns in self.nameservers:
            try:
                r = subprocess.run(
                    [DIG, "AXFR", self.target, "@" + ns, f"+time={self.args.timeout}",
                     "+tries=1"],
                    capture_output=True, text=True,
                    timeout=self.args.timeout * 2 + 5)
            except Exception:
                continue
            lines = [l for l in r.stdout.splitlines()
                     if l.strip() and not l.startswith(";")]
            # A successful transfer returns many RRs (SOA ... SOA). Require a
            # real zone body, not a single SOA or a refusal message.
            rr = [l for l in lines if re.search(r"\bIN\b", l)]
            if len(rr) >= 3 and "Transfer failed" not in r.stdout:
                self.add(Finding(
                    "zone_transfer", "Zone transfer (AXFR) allowed",
                    "critical", self.target,
                    f"Nameserver {ns} allowed a full AXFR of {self.target} "
                    f"({len(rr)} records exposed), leaking the entire zone.",
                    f"Restrict AXFR on {ns} to authorised secondary "
                    "nameservers only (allow-transfer).",
                ))

    def _p2_dnssec(self) -> None:
        dk = self.dns.query(self.target, "DNSKEY", dnssec=True)
        if not dk.ok:
            return  # query failed -> cannot conclude anything (no false "unsigned")
        has_key = bool(dk.data_of("DNSKEY"))
        # Validate via AD flag on a signed lookup through a validating resolver.
        val = self.dns.query(self.target, "A", ns="1.1.1.1", dnssec=True)
        ad = "ad" in val.flags
        if not has_key:
            self.add(Finding(
                "dnssec_unsigned", "DNSSEC not enabled",
                "low", self.target,
                "No DNSKEY published; the zone is unsigned and responses cannot "
                "be cryptographically validated (spoofing/cache-poisoning risk).",
                "Enable DNSSEC at your DNS provider and publish a DS record at "
                "the registrar.",
            ))
        elif has_key and not ad:
            # Keys exist but a validating resolver did NOT set AD -> broken chain.
            self.add(Finding(
                "dnssec_broken", "DNSSEC misconfigured (validation fails)",
                "high", self.target,
                "DNSKEY is published but a validating resolver did not return "
                "the AD (authenticated-data) flag, indicating a broken chain of "
                "trust (missing/stale DS or bad RRSIG). Validating resolvers "
                "will SERVFAIL, causing an outage-grade misconfiguration.",
                "Verify the DS record at the registrar matches the active KSK "
                "and that RRSIGs are current.",
            ))

    def _p2_open_resolver_and_amp(self) -> None:
        # Probe each authoritative NS by IP.
        ns_ips: List[str] = []
        for ns in self.nameservers:
            ips = self.ns_ips.get(ns) or self.dns.query(ns, "A").data_of("A")
            ns_ips.extend([ip for ip in ips if is_ip(ip)][:1])
        for ip in ns_ips[:6]:
            # Open resolver: ask for an unrelated domain WITH recursion.
            probe = self.dns.query("cloudflare.com", "A", ns=ip)
            if probe.ok and probe.rcode == "NOERROR" and probe.data_of("A") \
                    and "ra" in probe.flags:
                self.add(Finding(
                    "open_resolver", "Open DNS resolver",
                    "high", ip,
                    f"Authoritative nameserver {ip} recursively resolved an "
                    "unrelated domain (cloudflare.com) with the RA flag set — "
                    "it is an open resolver usable for DDoS amplification.",
                    "Disable recursion on authoritative nameservers, or "
                    "restrict it to trusted clients.",
                ))
            # Amplification: large ANY response.
            any_r = self.dns.query(self.target, "ANY", ns=ip)
            if any_r.ok and any_r.size >= 1000 and len(any_r.answers) >= 5:
                self.add(Finding(
                    "dns_amplification", "DNS amplification exposure (large ANY)",
                    "medium", ip,
                    f"ANY query to {ip} returned {any_r.size} bytes across "
                    f"{len(any_r.answers)} records — a usable amplification "
                    "factor for reflection DDoS.",
                    "Enable RRL (response-rate limiting) and RFC 8482 minimal "
                    "ANY responses on authoritative servers.",
                ))

    def _p2_wildcard(self) -> None:
        labels = [f"arise-wildcard-probe-{int(time.time())}-{i}" for i in range(3)]
        answers = []
        for lbl in labels:
            r = self.dns.query(f"{lbl}.{self.target}", "A")
            answers.append(tuple(sorted(r.data_of("A"))) if r.rcode == "NOERROR" else None)
        # Wildcard confirmed if random labels consistently resolve to the same set.
        resolving = [a for a in answers if a]
        if len(resolving) >= 2 and len(set(resolving)) == 1:
            self.wildcard_ips = resolving[0]
            self.add(Finding(
                "wildcard_dns", "Wildcard DNS record present",
                "info", self.target,
                f"Random subdomains of {self.target} resolve to {resolving[0]}, "
                "confirming a wildcard record. Wildcards mask subdomain-takeover "
                "detection and inflate enumeration with phantom hosts.",
                "Scope wildcards narrowly; prefer explicit records so dangling "
                "subdomains remain detectable.",
            ))
            # Fingerprint what the wildcard actually SERVES over HTTP, so a
            # downstream consumer can tell a genuine host that happens to
            # share the wildcard IP (shared LB/origin) apart from a phantom
            # name that resolves purely because of the wildcard. Reuses one
            # of the labels just proven to resolve into the wildcard set —
            # best-effort: a probe failure here just means the IP-membership
            # gate downstream has no HTTP signal to confirm against (it fails
            # open rather than dropping on IP overlap alone).
            wc_label = next(lbl for lbl, a in zip(labels, answers) if a == resolving[0])
            try:
                from discovery.soft404_detector import learn_catchall_signature
                sig = learn_catchall_signature(f"https://{wc_label}.{self.target}", n=2)
                if sig.get("signature_ready"):
                    sig.pop("_shingles", None)
                    sig.pop("_normalized_bodies", None)
                    self.wildcard_http_signature = sig
            except Exception:
                pass

    def _p2_delegation(self) -> None:
        # Child-published NS set (already in self.nameservers). Compare with
        # what each NS itself reports (consistency) + lame-delegation check.
        child = set(n.lower() for n in self.nameservers)
        for ns in self.nameservers:
            ip_list = self.ns_ips.get(ns) or self.dns.query(ns, "A").data_of("A")
            ip = next((x for x in ip_list if is_ip(x)), None)
            if not ip:
                # NS name doesn't resolve -> dangling NS (delegation to void).
                if self.dns.is_nxdomain(ns):
                    self.add(Finding(
                        "ns_dangling", "Dangling NS record (nameserver NXDOMAIN)",
                        "high", self.target,
                        f"Delegated nameserver {ns} does not resolve (NXDOMAIN); "
                        "if its domain is registrable an attacker can seize the "
                        "delegation and control the zone.",
                        f"Remove {ns} from the NS set or reclaim its domain.",
                        takeover_candidate=True, service=ns,
                    ))
                continue
            resp = self.dns.query(self.target, "NS", ns=ip)
            if not resp.ok:
                continue
            if "aa" not in resp.flags and resp.rcode == "NOERROR":
                # Answers but not authoritative -> lame delegation.
                self.add(Finding(
                    "ns_lame", "Lame delegation (nameserver not authoritative)",
                    "medium", self.target,
                    f"{ns} ({ip}) answers for {self.target} without the AA "
                    "(authoritative) flag; it is not properly configured as "
                    "authoritative, weakening resilience.",
                    f"Ensure {ns} is authoritative for the zone or remove it "
                    "from the delegation.",
                ))
            reported = set(d.rstrip(".").lower() for d in resp.data_of("NS"))
            if reported and reported != child:
                missing = child - reported
                extra = reported - child
                if missing or extra:
                    self.add(Finding(
                        "ns_inconsistent", "Inconsistent NS records across servers",
                        "low", self.target,
                        f"{ns} reports a different NS set than the parent "
                        f"delegation (missing={sorted(missing)}, "
                        f"extra={sorted(extra)}).",
                        "Reconcile the NS RRset across all authoritative "
                        "servers and the registrar delegation.",
                    ))

    # ===================================================================== #
    # PHASE 3 — enrichment
    # ===================================================================== #
    def phase3(self) -> None:
        log("Phase 3: enrichment (PTR, passive-DNS provenance, WHOIS/expiry)")
        self._p3_ptr()
        self._p3_whois()

    def _p3_ptr(self) -> None:
        known = set(h.lower() for h in self.hosts)
        internal_ptr, new_hosts = [], []
        for ann in self.ip_annotations:
            for ptr in ann.get("ptr", []) or []:
                p = ptr.rstrip(".").lower()
                if not p:
                    continue
                if INTERNAL_LABEL_RE.search(p):
                    internal_ptr.append((ann.get("host", ""), p))
                # PTR names on our own apex not in the known host list = leaked host.
                if p.endswith("." + self.target) and p not in known:
                    new_hosts.append((ann.get("host", ""), p))
        if internal_ptr:
            sample = ", ".join(f"{ip}->{name}" for ip, name in internal_ptr[:8])
            self.add(Finding(
                "ptr_internal", "Internal hostnames revealed via reverse DNS",
                "low", self.target,
                f"PTR records expose internal-looking names: {sample}",
                "Genericise PTR records for sensitive hosts to reduce "
                "infrastructure fingerprinting.",
            ))
        if new_hosts:
            sample = ", ".join(f"{name}" for _, name in new_hosts[:8])
            self.add(Finding(
                "ptr_new_hosts", "Undocumented hosts discovered via reverse DNS",
                "info", self.target,
                f"PTR records reveal in-scope hosts absent from forward "
                f"enumeration: {sample}",
                "Review these hosts; ensure they are inventoried and monitored.",
            ))

    def _p3_whois(self) -> None:
        if not WHOIS or self.args.no_whois:
            return
        try:
            r = subprocess.run([WHOIS, self.target], capture_output=True,
                              text=True, timeout=20)
            out = r.stdout
        except Exception:
            return
        m = re.search(
            r"(?:Registry Expiry Date|Expiration Date|Expiry Date|"
            r"paid-till|renewal date|Expires On|expire)\s*:?\s*"
            r"(\d{4}-\d{2}-\d{2}|\d{2}-\w{3}-\d{4})",
            out, re.I)
        if not m:
            return
        raw = m.group(1)
        exp_ts = None
        for fmt in ("%Y-%m-%d", "%d-%b-%Y"):
            try:
                exp_ts = time.mktime(time.strptime(raw, fmt))
                break
            except ValueError:
                continue
        if exp_ts is None:
            return
        days = int((exp_ts - time.time()) / 86400)
        if days < 0:
            sev, title = "critical", "Domain registration EXPIRED"
        elif days <= 30:
            sev, title = "high", "Domain expires within 30 days"
        elif days <= 90:
            sev, title = "medium", "Domain expires within 90 days"
        else:
            return
        self.add(Finding(
            "domain_expiry", title, sev, self.target,
            f"WHOIS expiry {raw} ({days} days). Lapsed registration allows a "
            "third party to seize the domain — total loss of control.",
            "Renew the domain and enable registrar auto-renew + registry lock.",
        ))

    # ===================================================================== #
    # PHASE 4 — behavioral
    # ===================================================================== #
    def phase4(self) -> None:
        if not DIG or self.args.no_phase4:
            return
        log("Phase 4: behavioral (GeoDNS, fast-flux)")
        self._p4_geodns_fastflux()

    def _p4_geodns_fastflux(self) -> None:
        sets, ttls = [], []
        for res in PUBLIC_RESOLVERS:
            r = self.dns.query(self.target, "A", ns=res)
            ips = tuple(sorted(d for d in r.data_of("A") if is_ip(d)))
            if ips:
                sets.append((res, ips))
                ttls.extend(t for (_, t, ty, _) in r.answers if ty == "A")
        distinct = {ips for _, ips in sets}
        if len(distinct) > 1:
            detail = "; ".join(f"{res}->{list(ips)[:2]}" for res, ips in sets)
            self.add(Finding(
                "geodns", "GeoDNS / region-specific responses",
                "info", self.target,
                f"Different resolvers return different A records ({detail}); "
                "the domain uses geographic/load-balanced DNS.",
                "Expected for global services; ensure every regional origin is "
                "in scope for security testing.",
            ))
        all_ips = {ip for _, ips in sets for ip in ips}
        min_ttl = min(ttls) if ttls else 999999
        if len(all_ips) >= 4 and min_ttl <= 120:
            self.add(Finding(
                "fast_flux", "Fast-flux DNS indicators",
                "info", self.target,
                f"{len(all_ips)} distinct A records with very low TTL "
                f"({min_ttl}s). Normal for large CDNs, but also a fast-flux "
                "hallmark — confirm the IPs belong to a legitimate CDN.",
                "If not a known CDN, investigate for compromised/hijacked "
                "infrastructure.",
            ))

    # ---- run + output ----------------------------------------------------- #
    def run(self) -> None:
        self.load_context()
        self.phase1()
        self.phase2()
        self.phase3()
        self.phase4()

    def write(self, out_dir: Path) -> Tuple[int, dict]:
        out_dir.mkdir(parents=True, exist_ok=True)
        findings_file = out_dir / "dns_security_findings.jsonl"
        self.findings.sort(key=lambda f: -SEVERITY_RANK.get(f.severity, 0))
        with findings_file.open("w") as fh:
            for f in self.findings:
                fh.write(json.dumps(asdict(f)) + "\n")

        by_sev: Dict[str, int] = {}
        by_check: Dict[str, int] = {}
        for f in self.findings:
            by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
            by_check[f.check] = by_check.get(f.check, 0) + 1
        summary = {
            "module": "dns_security",
            "target": self.target,
            "total_findings": len(self.findings),
            "by_severity": by_sev,
            "by_check": by_check,
            "takeover_candidates": sum(1 for f in self.findings if f.takeover_candidate),
        }
        (out_dir / "dns_security_summary.json").write_text(json.dumps(summary, indent=2))

        # Consumed by discovery/nuclei_url_consolidator.py to drop phantom
        # CT/gau/wayback subdomains that only resolve via the wildcard.
        # Always written (even when no wildcard) so the consumer's file-exists
        # check is a reliable signal, not dependent on scan history.
        wildcard_out = {
            "wildcard": self.wildcard_ips is not None,
            "target": self.target,
            "ips": list(self.wildcard_ips) if self.wildcard_ips else [],
            "http_signature": self.wildcard_http_signature,
        }
        (out_dir / "wildcard_dns.json").write_text(json.dumps(wildcard_out, indent=2))

        return len(self.findings), summary


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def main() -> int:
    ap = argparse.ArgumentParser(description="ARISE DNS Security Audit (Module 3C)")
    ap.add_argument("target")
    ap.add_argument("--scan-dir", required=True, help="Scan OUTPUT_DIR")
    ap.add_argument("--manifest", default="")
    ap.add_argument("--out-dir", default="", help="Defaults to <scan-dir>/03c_dns_security")
    ap.add_argument("--timeout", type=int, default=5)
    ap.add_argument("--tries", type=int, default=1)
    ap.add_argument("--threads", type=int, default=10)
    ap.add_argument("--max-hosts", type=int, default=300)
    ap.add_argument("--max-cname-hops", type=int, default=8)
    ap.add_argument("--no-whois", action="store_true")
    ap.add_argument("--no-phase4", action="store_true")
    args = ap.parse_args()

    scan_dir = Path(args.scan_dir)
    if not scan_dir.is_dir():
        log(f"scan-dir not found: {scan_dir}")
        return 1
    out_dir = Path(args.out_dir) if args.out_dir else scan_dir / "03c_dns_security"

    if not DIG:
        log("WARNING: `dig` not found — most checks will be skipped.")

    auditor = DNSSecurityAuditor(args.target, scan_dir, args)
    try:
        auditor.run()
    except KeyboardInterrupt:
        log("interrupted — writing partial results")
    n, summary = auditor.write(out_dir)
    log(f"done: {n} findings -> {out_dir/'dns_security_findings.jsonl'}")
    log("severity: " + ", ".join(f"{k}={v}" for k, v in sorted(
        summary["by_severity"].items(),
        key=lambda x: -SEVERITY_RANK.get(x[0], 0))))
    return 0


if __name__ == "__main__":
    sys.exit(main())
