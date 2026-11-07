#!/usr/bin/env python3
"""
ARISE attack-surface report builder.

Turns a completed scan into an adversary-perspective report: instead of listing
findings by tool, it derives *attack paths* — chains of steps an external
attacker could realistically execute against this target using only what the
scan observed — and ranks the assets an attacker would reach for first.

The renderer lives in templates/report.html; this module only produces data.
Every claim in the output is traceable to an observed signal (see `evidence`
on each path/step), because a report that asserts more than it saw is worse
than no report.

Consumed by dashboard.py's /report/<scan_id> route.
"""

import sys as _sys, os as _os
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)


import json
import os
import re
from collections import Counter
from datetime import datetime, timezone

ENGINE_VERSION = '2.1.0'

ID_SEGMENT_RE = re.compile(
    r"^(\d{5,}|[0-9a-fA-F]{8,}|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}"
    r"-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|[A-Za-z0-9_-]{20,})$"
)


def _path_template(path):
    """Collapse concrete IDs so /users/123 and /users/456 normalise to /users/{id}."""
    if not path:
        return ''
    parts = []
    for seg in path.split('/'):
        parts.append('{id}' if seg and ID_SEGMENT_RE.match(seg) else seg)
    return '/'.join(parts)


# Severity ordering shared by findings, paths, and entry points.
SEV_ORDER = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
SEV_RANK = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}


def _sev_key(sev):
    return SEV_ORDER.get((sev or 'info').lower(), 9)


def _score_to_sev(score):
    if score >= 75:
        return 'critical'
    if score >= 50:
        return 'high'
    if score >= 25:
        return 'medium'
    return 'low'


# Hostnames that tell an attacker "this is worth my time" before they send a
# single packet. Ordered most- to least-interesting; first match wins.
_JUICY_HOST_PATTERNS = [
    (r'(^|[.-])(admin|manage|console|portal)([.-]|$)', 'Administrative interface — direct route to privileged functions'),
    (r'(^|[.-])(auth|login|sso|idp|account|oauth)([.-]|$)', 'Authentication surface — the target for credential stuffing and phishing landings'),
    (r'(^|[.-])(vpn|remote|citrix|rdp|gateway)([.-]|$)', 'Remote-access gateway — network foothold if credentials are obtained'),
    (r'(^|[.-])(jenkins|gitlab|git|jira|confluence|ci|build|artifactory|nexus)([.-]|$)', 'Developer/CI infrastructure — source code, secrets, and build pipeline access'),
    (r'(^|[.-])(dev|test|staging|stage|uat|qa|sandbox|preprod|demo)([.-]|$)', 'Non-production environment — typically weaker controls with production-shaped data'),
    (r'(^|[.-])(internal|intranet|corp|private|vpc)([.-]|$)', 'Internally-named host exposed externally — likely assumes network trust it no longer has'),
    (r'(^|[.-])(api|graphql|rest|gateway|gw)([.-]|$)', 'API surface — machine interface, often with thinner authorisation checks than the UI'),
    (r'(^|[.-])(pay|payment|billing|checkout|invoice|order)([.-]|$)', 'Payment/commerce flow — direct financial impact and cardholder data in scope'),
    (r'(^|[.-])(db|database|sql|mongo|redis|elastic|kibana|grafana)([.-]|$)', 'Data-tier or observability service — bulk data access if reachable'),
    (r'(^|[.-])(mail|smtp|webmail|exchange|owa)([.-]|$)', 'Mail infrastructure — phishing relay and mailbox access'),
    (r'(^|[.-])(files?|upload|share|cdn|assets|static|media|images?)([.-]|$)', 'File/asset host — upload handling and stored-object exposure'),
]

# Ports that are interesting because they should not be facing the internet.
_SENSITIVE_PORTS = {
    21: 'FTP — cleartext credentials and often anonymous access',
    22: 'SSH — brute-force and key-reuse target',
    23: 'Telnet — cleartext protocol, no transport security',
    25: 'SMTP — relay abuse and user enumeration',
    445: 'SMB — file share and remote-exec surface',
    1433: 'MSSQL — database directly reachable',
    1521: 'Oracle DB — database directly reachable',
    2375: 'Docker API — unauthenticated container control if unprotected',
    3306: 'MySQL — database directly reachable',
    3389: 'RDP — brute-force and ransomware entry point',
    5432: 'PostgreSQL — database directly reachable',
    5900: 'VNC — often weak or absent authentication',
    6379: 'Redis — historically unauthenticated by default',
    8080: 'Alternate HTTP — commonly an unproxied app or admin panel',
    8443: 'Alternate HTTPS — commonly a management interface',
    9200: 'Elasticsearch — bulk data access if unauthenticated',
    11211: 'Memcached — unauthenticated cache access and DDoS reflector',
    27017: 'MongoDB — bulk data access if unauthenticated',
}

_STANDARD_WEB_PORTS = {80, 443}


# ---------------------------------------------------------------------------
# Signal extraction — normalise the scan into the facts the path engine reasons over
# ---------------------------------------------------------------------------
def _extract_signals(hosts, vulns, osint, cloud):
    """Reduce the scan to the discrete facts an attacker could act on."""
    osint_findings = osint.get('findings') or []
    by_cat = {}
    for f in osint_findings:
        by_cat.setdefault(f.get('category'), []).append(f)

    resolved = {h: d for h, d in hosts.items() if d.get('resolved')}
    live = {h: d for h, d in resolved.items() if d.get('http_status')}

    def _waf(d):
        return (d.get('waf_vendor') or 'none').lower() not in ('none', '', 'unknown')

    # Typosquats that can actually send mail are the ones that matter — a parked
    # look-alike with no MX cannot run the phishing step of the chain.
    mail_typosquats = [
        f for f in by_cat.get('brand', [])
        if (f.get('meta') or {}).get('mx') and _sev_key(f.get('severity')) <= 1
    ]

    dangling = [h for h, d in hosts.items() if d.get('ssl_dangling')]
    # Confirmed takeovers from the OSINT engine (CNAME + body fingerprint) are
    # a stronger claim than the dangling-TLS heuristic: the service is actively
    # serving its unclaimed-resource page.
    takeover_confirmed = [
        f for f in by_cat.get('takeover', [])
        if (f.get('meta') or {}).get('service') and _sev_key(f.get('severity')) <= 1
    ]
    apis = [h for h, d in live.items() if d.get('is_api')]
    unprotected_apis = [h for h, d in live.items() if d.get('is_api') and not _waf(d)]
    buckets = [h for h, d in hosts.items() if d.get('is_s3')]
    no_waf = [h for h, d in live.items() if not _waf(d)]
    direct_origin = [h for h, d in live.items() if not d.get('cdn') and not _waf(d)]

    sensitive_ports = []
    for h, d in resolved.items():
        for p in d.get('ports_open') or []:
            try:
                p = int(p)
            except (TypeError, ValueError):
                continue
            if p in _SENSITIVE_PORTS:
                sensitive_ports.append({'host': h, 'ip': d.get('ip', ''), 'port': p,
                                        'why': _SENSITIVE_PORTS[p]})

    secret_vulns = [v for v in vulns if v.get('source') == 'Secret Scan']
    cloud_findings = cloud.get('findings') or []

    return {
        'osint_by_cat': by_cat,
        'hosts': hosts,
        'resolved': resolved,
        'live': live,
        'mail_typosquats': mail_typosquats,
        'all_typosquats': by_cat.get('brand', []),
        'breach': by_cat.get('breach', []),
        'email_exposure': by_cat.get('email_exposure', []),
        'code_exposure': by_cat.get('code_exposure', []),
        'supply_chain': by_cat.get('supply_chain', []),
        'ransomware': by_cat.get('ransomware', []),
        'internet_exposure': by_cat.get('internet_exposure', []),
        'mobile_app': by_cat.get('mobile_app', []),
        'malicious_landing': by_cat.get('malicious_landing', []),
        'ad_fraud': by_cat.get('ad_fraud', []),
        'gov_injection': by_cat.get('gov_injection', []),
        'recruitment': by_cat.get('recruitment', []),
        'api_docs': by_cat.get('api_docs', []),
        'dangling': dangling,
        'takeover_confirmed': takeover_confirmed,
        'apis': apis,
        'unprotected_apis': unprotected_apis,
        'buckets': buckets,
        'no_waf': no_waf,
        'direct_origin': direct_origin,
        'sensitive_ports': sensitive_ports,
        'secret_vulns': secret_vulns,
        'cloud_findings': cloud_findings,
        'vulns': vulns,
    }


# ---------------------------------------------------------------------------
# Attack path engine
# ---------------------------------------------------------------------------
def _mk_path(pid, name, tactic_summary, severity, likelihood, impact,
             premise, steps, evidence, mitigations):
    return {
        'id': pid,
        'name': name,
        'tactics': tactic_summary,
        'severity': severity,
        'likelihood': likelihood,
        'impact': impact,
        'premise': premise,
        'steps': steps,
        'evidence': evidence,
        'mitigations': mitigations,
    }


def _derive_attack_paths(sig, domain):
    """Build the attack paths this scan actually supports.

    A path is only emitted when the scan observed the signals that make each of
    its steps executable — no speculative chains.
    """
    paths = []

    # --- AP-01: brand impersonation -> credential harvesting -----------------
    if sig['mail_typosquats']:
        n = len(sig['mail_typosquats'])
        emails = len(sig['email_exposure'])
        breaches = len(sig['breach'])
        likelihood = 'high' if (emails or breaches) else 'medium'
        steps = [
            {'phase': 'Reconnaissance', 'technique': 'T1589.002 — Gather Victim Identity Information: Email Addresses',
             'action': f'Harvest staff addresses and the {domain} mail naming convention from public sources.',
             'observed': f'{emails} email-exposure signal(s) already visible without authentication.' if emails
                         else 'No email exposure observed; addresses would be inferred from naming convention.'},
            {'phase': 'Resource Development', 'technique': 'T1583.001 — Acquire Infrastructure: Domains',
             'action': 'Use an existing look-alike domain that already accepts and sends mail — no new registration needed.',
             'observed': f'{n} live look-alike domain(s) with MX records configured.'},
            {'phase': 'Initial Access', 'technique': 'T1566.002 — Phishing: Spearphishing Link',
             'action': 'Send mail from the look-alike. It passes casual inspection and clears SPF/DKIM for its own domain.',
             'observed': 'Look-alike domains resolve and hold mail records — the send path is live today.'},
            {'phase': 'Credential Access', 'technique': 'T1056.003 — Input Capture: Web Portal Capture',
             'action': f'Host a clone of the {domain} login on the look-alike and capture submitted credentials.',
             'observed': 'Authentication surfaces are publicly reachable (see Priority Entry Points).'},
            {'phase': 'Initial Access', 'technique': 'T1078 — Valid Accounts',
             'action': 'Replay harvested credentials against the real estate.',
             'observed': f'{breaches} breach corpus signal(s) suggest credential reuse is already plausible.' if breaches
                         else 'Harvested credentials used directly.'},
        ]
        paths.append(_mk_path(
            'AP-01', 'Brand impersonation to credential harvesting',
            'Reconnaissance → Resource Development → Initial Access → Credential Access',
            'critical' if n >= 5 and (emails or breaches) else 'high',
            likelihood, 'high',
            f'{n} look-alike domain(s) of {domain} are registered, resolving, and mail-capable right now. '
            'The attacker does not need to build infrastructure — it already exists and is one DNS lookup from your brand.',
            steps,
            [f"{f.get('subject')} — {f.get('evidence','')}" for f in sig['mail_typosquats'][:8]],
            ['File takedowns for mail-capable look-alikes; prioritise those with MX records.',
             'Publish and enforce DMARC at p=reject for the real domain so spoofing of the exact domain fails.',
             'Enforce phishing-resistant MFA (WebAuthn/FIDO2) so harvested passwords alone are not sufficient.',
             'Monitor certificate transparency for new look-alike issuance and alert on first sighting.'],
        ))

    # --- AP-02: subdomain takeover ------------------------------------------
    if sig['dangling'] or sig['takeover_confirmed']:
        confirmed = sig['takeover_confirmed']
        n = len(sig['dangling']) or len(confirmed)
        if confirmed:
            svcs = sorted({(f.get('meta') or {}).get('service', '?') for f in confirmed})
            # Corroborated = the host's CNAME matches the service's delegation
            # pattern AND the body carries its marker. Marker-only rests on the
            # marker alone, so it warrants a weaker claim in the report.
            corr = [f for f in confirmed
                    if (f.get('meta') or {}).get('basis') == 'corroborated']
            all_corr = len(corr) == len(confirmed)
            basis_note = ('' if all_corr else
                          f' {len(confirmed) - len(corr)} of these rest on the '
                          f'provider marker alone (no published CNAME pattern to '
                          f'corroborate against) and should be confirmed manually '
                          f'before action.')
            recon_observed = (
                f'{len(confirmed)} host(s) observed serving an unclaimed-resource '
                f'page from {", ".join(svcs)} — matched by response-body fingerprint, '
                f'not inferred.' + basis_note)
            claim_observed = (
                'The backend is demonstrably unclaimed: the provider is returning '
                'its "this resource does not exist" page for your hostname.')
            premise = (
                f'{len(confirmed)} hostname(s) under {domain} are takeover-ready — '
                f'their CNAME targets ({", ".join(svcs)}) are serving unclaimed-resource pages '
                f'right now. This is not a heuristic: registration is the only step left.'
                + basis_note)
            severity = 'critical'
            likelihood = 'high' if corr else 'medium'
        else:
            recon_observed = f'{n} host(s) with dangling DNS/certificate state observed by this scan.'
            claim_observed = 'Dangling target detected — the backend is claimable by whoever asks first.'
            premise = (
                f'{n} hostname(s) under {domain} point at infrastructure that no longer answers for you. '
                'Anyone can claim the backend and inherit your domain\'s trust, TLS, and cookie scope.')
            severity, likelihood = 'critical', ('high' if n > 1 else 'medium')

        steps = [
            {'phase': 'Reconnaissance', 'technique': 'T1590.002 — Gather Victim Network Information: DNS',
             'action': f'Enumerate {domain} subdomains and resolve each CNAME to find records pointing at unclaimed backends.',
             'observed': recon_observed},
            {'phase': 'Resource Development', 'technique': 'T1584.001 — Compromise Infrastructure: Domains',
             'action': 'Register the unclaimed backend resource the CNAME still points to.',
             'observed': claim_observed},
            {'phase': 'Initial Access', 'technique': 'T1584.001 — Compromise Infrastructure: Domains',
             'action': f'Serve attacker content from a genuine *.{domain} hostname with a valid certificate.',
             'observed': 'Takeover yields authentic-origin content on your own namespace.'},
            {'phase': 'Credential Access', 'technique': 'T1539 — Steal Web Session Cookie',
             'action': f'Read cookies scoped to .{domain}, and abuse OAuth/CORS allowlists that trust the subdomain.',
             'observed': 'Parent-domain cookie scope and subdomain trust are the standard blast radius.'},
        ]
        paths.append(_mk_path(
            'AP-02', 'Subdomain takeover to trust abuse',
            'Reconnaissance → Resource Development → Initial Access → Credential Access',
            severity, likelihood, 'high',
            premise,
            steps,
            ([f"{(f.get('meta') or {}).get('host', f.get('subject'))} → "
              f"{(f.get('meta') or {}).get('cname', '?')} "
              f"[{(f.get('meta') or {}).get('service', '?')} fingerprint matched]"
              for f in confirmed[:8]]
             or [f'{h} — dangling DNS/TLS state' for h in sig['dangling'][:8]]),
            ['Delete the dangling DNS records, or reclaim the backend resource immediately.',
             'Scope session cookies to the exact host rather than .{}; avoid wildcard domain cookies.'.format(domain),
             'Audit OAuth redirect URIs and CORS allowlists for wildcard subdomain trust.',
             'Add takeover detection to the DNS change workflow so records outlive their backends by hours, not months.'],
        ))

    # --- AP-03: credential stuffing from breach corpora ----------------------
    if sig['breach']:
        n = len(sig['breach'])
        auth_hosts = [h for h in sig['live'] if re.search(r'(^|[.-])(auth|login|sso|account|api)([.-]|$)', h)]
        steps = [
            {'phase': 'Reconnaissance', 'technique': 'T1589.001 — Gather Victim Identity Information: Credentials',
             'action': f'Pull {domain} accounts out of public breach corpora and combolists.',
             'observed': f'{n} breach/credential-exposure signal(s) tied to this domain.'},
            {'phase': 'Credential Access', 'technique': 'T1110.004 — Brute Force: Credential Stuffing',
             'action': 'Replay username/password pairs against authentication endpoints at a low, rate-limit-aware rate.',
             'observed': (f'{len(auth_hosts)} authentication-shaped host(s) reachable: ' + ', '.join(auth_hosts[:4]))
                         if auth_hosts else 'Authentication surfaces reachable over HTTP.'},
            {'phase': 'Initial Access', 'technique': 'T1078 — Valid Accounts',
             'action': 'Authenticate with a reused password. This is indistinguishable from a real login in most logs.',
             'observed': 'Password reuse across services is the default human behaviour.'},
        ]
        paths.append(_mk_path(
            'AP-03', 'Credential stuffing from breach corpora',
            'Reconnaissance → Credential Access → Initial Access',
            'high', 'high' if n >= 2 else 'medium', 'high',
            f'Credentials associated with {domain} already sit in public breach data. '
            'This path needs no exploit — it is a login, and it succeeds whenever a password was reused.',
            steps,
            [f"{f.get('subject')} — {f.get('evidence','')}" for f in sig['breach'][:8]],
            ['Force a reset for every account appearing in breach corpora and block known-breached passwords at set time.',
             'Enforce MFA on all externally-reachable authentication surfaces.',
             'Rate-limit and alert on distributed low-and-slow authentication failures per-account, not just per-IP.',
             'Enable impossible-travel and new-device detection on login.'],
        ))

    # --- AP-04: unauthenticated / unprotected API abuse ----------------------
    if sig['unprotected_apis'] or sig['api_docs']:
        n = len(sig['unprotected_apis'])
        docs = len(sig['api_docs'])
        steps = [
            {'phase': 'Reconnaissance', 'technique': 'T1595.003 — Active Scanning: Wordlist Scanning',
             'action': 'Enumerate API routes from JS bundles, published specs, and path brute-force.',
             'observed': f'{docs} exposed API documentation/spec signal(s) — the route map is published.' if docs
                         else 'API routes recoverable from client-side JavaScript.'},
            {'phase': 'Initial Access', 'technique': 'T1190 — Exploit Public-Facing Application',
             'action': 'Probe for object-level authorisation gaps (IDOR), missing authentication, and mass assignment.',
             'observed': f'{n} API host(s) with no WAF in front — probing is unthrottled and unlogged by any edge control.'
                         if n else 'API hosts reachable directly.'},
            {'phase': 'Collection', 'technique': 'T1213 — Data from Information Repositories',
             'action': 'Iterate object identifiers to pull records belonging to other tenants or users.',
             'observed': 'APIs commonly enforce authentication but not per-object authorisation.'},
        ]
        paths.append(_mk_path(
            'AP-04', 'Unprotected API enumeration and abuse',
            'Reconnaissance → Initial Access → Collection',
            'high' if n else 'medium', 'high' if n else 'medium', 'high',
            (f'{n} API host(s) answer directly with no WAF between the attacker and the application. '
             if n else 'API surface is externally reachable. ') +
            'APIs fail differently from web apps: the authorisation bug is usually per-object, and the edge cannot see it.',
            steps,
            ([f'{h} — API, no WAF' for h in sig['unprotected_apis'][:6]] +
             [f"{f.get('subject')} — {f.get('title','')}" for f in sig['api_docs'][:4]]),
            ['Put every API host behind the WAF/edge that already fronts the web estate.',
             'Test object-level authorisation per endpoint (BOLA/IDOR) — this cannot be caught at the edge.',
             'Remove or authenticate public API specs and documentation.',
             'Apply per-identity rate limits and log at the application, not just the edge.'],
        ))

    # --- AP-05: leaked secrets -> authenticated access -----------------------
    if sig['code_exposure'] or sig['secret_vulns']:
        n = len(sig['code_exposure']) + len(sig['secret_vulns'])
        steps = [
            {'phase': 'Reconnaissance', 'technique': 'T1593.003 — Search Open Websites/Domains: Code Repositories',
             'action': f'Search public repositories and JS bundles for {domain} keys, tokens, and endpoints.',
             'observed': f'{n} code/secret exposure signal(s) observed.'},
            {'phase': 'Credential Access', 'technique': 'T1552.001 — Unsecured Credentials: Credentials In Files',
             'action': 'Extract the credential and confirm it is live.',
             'observed': 'Leaked material found in publicly readable locations.'},
            {'phase': 'Initial Access', 'technique': 'T1078 — Valid Accounts',
             'action': 'Authenticate with the leaked credential — no exploitation required, and the access looks legitimate.',
             'observed': 'A valid key is indistinguishable from the real client that owns it.'},
        ]
        paths.append(_mk_path(
            'AP-05', 'Leaked secrets to authenticated access',
            'Reconnaissance → Credential Access → Initial Access',
            'critical', 'high', 'critical',
            'Credential material tied to this estate is publicly readable. This is the shortest path in this report: '
            'it skips exploitation entirely and grants whatever the key is scoped to.',
            steps,
            ([f"{f.get('subject')} — {f.get('evidence','')}" for f in sig['code_exposure'][:5]] +
             [f"{v.get('host','')} — {v.get('template','secret')}" for v in sig['secret_vulns'][:5]]),
            ['Revoke and rotate every exposed credential — assume it is already used, not merely exposed.',
             'Purge the secret from git history; deleting the file does not remove it from clones.',
             'Add pre-commit and CI secret scanning to stop the next one.',
             'Scope keys narrowly and give them expiry so a leak has a blast radius and a deadline.'],
        ))

    # --- AP-06: cloud storage exposure ---------------------------------------
    if sig['buckets'] or sig['cloud_findings']:
        n = len(sig['buckets'])
        cf = len(sig['cloud_findings'])
        steps = [
            {'phase': 'Reconnaissance', 'technique': 'T1580 — Cloud Infrastructure Discovery',
             'action': f'Enumerate buckets and cloud endpoints using {domain} naming permutations.',
             'observed': f'{n} storage-backed host(s) and {cf} cloud finding(s) observed.'},
            {'phase': 'Collection', 'technique': 'T1530 — Data from Cloud Storage',
             'action': 'Attempt anonymous list and read against each discovered object store.',
             'observed': 'Storage endpoints externally resolvable.'},
            {'phase': 'Exfiltration', 'technique': 'T1537 — Transfer Data to Cloud Account',
             'action': 'Bulk-copy readable objects. Egress from object storage is rarely alerted on.',
             'observed': 'Object storage reads are high-volume and low-signal by default.'},
        ]
        paths.append(_mk_path(
            'AP-06', 'Cloud storage discovery and data access',
            'Reconnaissance → Collection → Exfiltration',
            'high', 'medium', 'high',
            f'{n} storage-backed hostname(s) are externally resolvable. Bucket names are guessable by design, '
            'and an anonymous read leaves almost no trace in default logging.',
            steps,
            ([f'{h} — storage-backed host' for h in sig['buckets'][:6]] +
             [f"{(f.get('resource') or f.get('subject') or '')} — {f.get('title','')}" for f in sig['cloud_findings'][:4]]),
            ['Enable Block Public Access at the account level, not per bucket.',
             'Audit bucket policies and ACLs for anonymous and authenticated-any principals.',
             'Turn on object-level access logging and alert on anonymous reads.',
             'Serve public assets through the CDN with an origin identity rather than a public bucket.'],
        ))

    # --- AP-07: exposed sensitive services -----------------------------------
    if sig['sensitive_ports']:
        n = len(sig['sensitive_ports'])
        top = sig['sensitive_ports'][:6]
        steps = [
            {'phase': 'Reconnaissance', 'technique': 'T1595.001 — Active Scanning: Scanning IP Blocks',
             'action': 'Sweep resolved hosts for non-web services. Internet-wide scan data makes this free.',
             'observed': f'{n} sensitive service port(s) reachable outside the standard web ports.'},
            {'phase': 'Reconnaissance', 'technique': 'T1595.002 — Active Scanning: Vulnerability Scanning',
             'action': 'Fingerprint each service and match versions to known exploits.',
             'observed': 'Service banners are exposed to any connecting client.'},
            {'phase': 'Initial Access', 'technique': 'T1190 — Exploit Public-Facing Application',
             'action': 'Exploit an unpatched service, or brute-force where the protocol permits authentication.',
             'observed': 'These protocols sit outside WAF/CDN inspection entirely.'},
        ]
        paths.append(_mk_path(
            'AP-07', 'Exposed non-web service exploitation',
            'Reconnaissance → Initial Access',
            'high', 'medium', 'high',
            f'{n} service(s) answer on ports that carry no WAF and no CDN. '
            'Everything you bought at the edge applies to 80/443 only — these ports are the raw application.',
            steps,
            [f"{p['host']}:{p['port']} — {p['why']}" for p in top],
            ['Close these ports at the perimeter; expose management protocols only via VPN or a bastion.',
             'Where the service must stay public, put it behind an authenticating proxy with allowlisting.',
             'Patch to current and remove default credentials.',
             'Alert on new listening ports appearing on internet-facing IPs.'],
        ))

    # --- AP-08: supply chain / third-party pivot ------------------------------
    if sig['supply_chain']:
        n = len(sig['supply_chain'])
        steps = [
            {'phase': 'Reconnaissance', 'technique': 'T1596 — Search Open Technical Databases',
             'action': f'Map the third parties {domain} depends on and which of them touch production.',
             'observed': f'{n} supply-chain relationship(s) discoverable from outside.'},
            {'phase': 'Initial Access', 'technique': 'T1195.002 — Supply Chain Compromise: Software Supply Chain',
             'action': 'Target the weakest supplier rather than the hardened primary target.',
             'observed': 'Supplier relationships are externally visible; their security posture is not yours.'},
            {'phase': 'Initial Access', 'technique': 'T1199 — Trusted Relationship',
             'action': 'Use supplier access, integrations, or injected script to reach the primary target.',
             'observed': 'Third-party access paths typically bypass perimeter controls by design.'},
        ]
        paths.append(_mk_path(
            'AP-08', 'Third-party and supply-chain pivot',
            'Reconnaissance → Initial Access',
            'medium', 'medium', 'high',
            f'{n} externally-visible supplier relationship(s). An attacker picks the softest of your suppliers, '
            'not the hardest part of you — and their access was granted deliberately.',
            steps,
            [f"{f.get('subject')} — {f.get('evidence') or f.get('title','')}" for f in sig['supply_chain'][:8]],
            ['Inventory third parties with production access and review what each can actually reach.',
             'Pin and use Subresource Integrity for third-party scripts; apply a strict CSP.',
             'Require security attestation and breach-notification terms in supplier contracts.',
             'Scope and expire supplier credentials the same way you would your own.'],
        ))

    # --- AP-09: ransomware targeting ------------------------------------------
    if sig['ransomware']:
        steps = [
            {'phase': 'Reconnaissance', 'technique': 'T1593 — Search Open Websites/Domains',
             'action': 'Confirm the target appears on leak-site or affiliate targeting data.',
             'observed': f"{len(sig['ransomware'])} ransomware-ecosystem signal(s) referencing this estate."},
            {'phase': 'Initial Access', 'technique': 'T1078 — Valid Accounts',
             'action': 'Buy access from an initial-access broker rather than developing it.',
             'observed': 'Credential and access markets sit upstream of most ransomware operations.'},
            {'phase': 'Impact', 'technique': 'T1486 — Data Encrypted for Impact',
             'action': 'Exfiltrate first, then encrypt, then extort on both.',
             'observed': 'Double-extortion is the prevailing model.'},
        ]
        paths.append(_mk_path(
            'AP-09', 'Ransomware ecosystem targeting',
            'Reconnaissance → Initial Access → Impact',
            'critical', 'medium', 'critical',
            'This estate appears in ransomware-ecosystem data. That shifts the question from whether you are '
            'interesting to an operator to whether an access broker has already sold the way in.',
            steps,
            [f"{f.get('subject')} — {f.get('evidence') or f.get('title','')}" for f in sig['ransomware'][:6]],
            ['Verify backups are offline, immutable, and restore-tested — not merely present.',
             'Enforce MFA on every remote-access and administrative path.',
             'Hunt for pre-ransomware indicators: new admin accounts, remote tooling, staged archives.',
             'Rehearse the incident and extortion decision path before you need it.'],
        ))

    # --- AP-10: mobile app / ad / landing-page impersonation ------------------
    imp = sig['mobile_app'] + sig['malicious_landing'] + sig['ad_fraud']
    if imp:
        steps = [
            {'phase': 'Resource Development', 'technique': 'T1583.001 — Acquire Infrastructure: Domains',
             'action': 'Stand up impersonating apps, ads, or landing pages carrying the brand.',
             'observed': f'{len(imp)} impersonation signal(s) across app stores, ad networks, and landing pages.'},
            {'phase': 'Initial Access', 'technique': 'T1566 — Phishing',
             'action': 'Buy brand-keyword ads so the fake outranks the real destination.',
             'observed': f"{len(sig['ad_fraud'])} ad-fraud signal(s)." if sig['ad_fraud'] else 'Impersonating properties observed.'},
            {'phase': 'Credential Access', 'technique': 'T1056 — Input Capture',
             'action': 'Harvest credentials or push a trojanised app to users who believe they are with you.',
             'observed': f"{len(sig['malicious_landing'])} malicious landing signal(s)." if sig['malicious_landing']
                         else 'Impersonating properties can capture user input.'},
        ]
        paths.append(_mk_path(
            'AP-10', 'App, ad, and landing-page impersonation',
            'Resource Development → Initial Access → Credential Access',
            'high', 'medium', 'high',
            'Impersonating properties are live. This path never touches your infrastructure — your users are the '
            'attack surface, and the damage lands on your brand regardless.',
            steps,
            [f"{f.get('subject')} — {f.get('title','')}" for f in imp[:8]],
            ['File takedowns with the app stores, ad networks, and hosting providers.',
             'Register brand keywords defensively so the paid slot above your organic result is yours.',
             'Publish official app and domain lists so users can verify.',
             'Monitor app stores and ad transparency data continuously, not per-incident.'],
        ))

    paths.sort(key=lambda p: (_sev_key(p['severity']), -SEV_RANK.get(p['likelihood'], 0)))
    return paths


# ---------------------------------------------------------------------------
# Priority entry points — which assets an attacker reaches for first
# ---------------------------------------------------------------------------
def _rank_entry_points(sig, limit=15):
    """Score live hosts by attacker attractiveness, with the reasoning attached."""
    out = []
    for host, d in sig['live'].items():
        reasons = []
        score = float(d.get('risk_score') or 0)

        waf = (d.get('waf_vendor') or 'none').lower()
        has_waf = waf not in ('none', '', 'unknown')

        for pattern, why in _JUICY_HOST_PATTERNS:
            if re.search(pattern, host):
                reasons.append(why)
                score += 14
                break

        if not has_waf and not d.get('cdn'):
            reasons.append('No WAF and no CDN — requests hit the application directly, unfiltered and unrated')
            score += 18
        elif not has_waf:
            reasons.append('No WAF — only CDN caching sits in front of the application')
            score += 10

        if d.get('is_api'):
            reasons.append('API endpoint — authorisation bugs here are per-object and invisible to edge controls')
            score += 10

        if d.get('is_s3'):
            reasons.append('Storage-backed — object listing and read are the immediate test')
            score += 12

        if d.get('ssl_dangling'):
            reasons.append('Dangling DNS/TLS — claimable backend, full subdomain takeover')
            score += 30

        cves = int(d.get('cve_count') or 0)
        if cves:
            reasons.append(f'{cves} CVE(s) matched against the fingerprinted stack')
            score += min(cves * 6, 24)

        extra = sorted({int(p) for p in (d.get('ports_open') or [])
                        if str(p).isdigit()} - _STANDARD_WEB_PORTS)
        if extra:
            named = [f'{p} ({_SENSITIVE_PORTS[p].split(" — ")[0]})' if p in _SENSITIVE_PORTS else str(p)
                     for p in extra[:5]]
            reasons.append('Non-web ports open: ' + ', '.join(named))
            score += min(len(extra) * 5, 20)

        sec = d.get('security_header_score')
        if isinstance(sec, (int, float)) and sec <= 2:
            reasons.append('Weak security headers — client-side defences largely absent')
            score += 6

        if not reasons:
            continue

        out.append({
            'host': host,
            'ip': d.get('ip', ''),
            'status': d.get('http_status', ''),
            'waf': d.get('waf_vendor') or 'none',
            'cdn': bool(d.get('cdn')),
            'tech': d.get('tech_tag') or d.get('server_banner') or '',
            'score': min(int(round(score)), 100),
            'severity': _score_to_sev(min(score, 100)),
            'reasons': reasons,
        })

    out.sort(key=lambda e: -e['score'])
    return out[:limit]


# ---------------------------------------------------------------------------
# Narrative
# ---------------------------------------------------------------------------
def _build_narrative(domain, sig, paths, corr, exposure):
    """Plain-language summary that leads with the conclusion."""
    if not paths:
        return (f'This scan found no attack path against {domain} that the observed data supports. '
                f'{exposure.get("total_assets", 0)} asset(s) were enumerated with '
                f'{exposure.get("waf_coverage_pct", 0)}% WAF coverage across the internet-facing estate. '
                'That is a statement about what was observed, not a guarantee of safety — '
                're-run after any material change to the estate.')

    crit = [p for p in paths if p['severity'] == 'critical']
    high = [p for p in paths if p['severity'] == 'high']
    lead = paths[0]

    bits = [
        f'{domain} has {len(paths)} viable attack path(s) derived from what this scan could observe from the '
        f'outside: {len(crit)} critical and {len(high)} high.'
    ]
    bits.append(
        f'The most immediate is {lead["id"]} — {lead["name"].lower()} — rated {lead["severity"]} '
        f'with {lead["likelihood"]} likelihood. {lead["premise"]}'
    )

    blended = corr.get('blended_score')
    if blended is not None:
        bits.append(
            f'Blended risk sits at {blended}/100 ({str(corr.get("blended_grade","")).upper()}), combining a '
            f'{corr.get("osint_score", 0)}/100 passive-OSINT exposure with '
            f'{corr.get("active_vulnerabilities", 0)} active-scan vulnerabilities.'
        )

    counter = []
    if sig['mail_typosquats']:
        counter.append(f'{len(sig["mail_typosquats"])} mail-capable look-alike domain(s)')
    if sig['dangling']:
        counter.append(f'{len(sig["dangling"])} dangling hostname(s)')
    if sig['breach']:
        counter.append(f'{len(sig["breach"])} breach signal(s)')
    if sig['unprotected_apis']:
        counter.append(f'{len(sig["unprotected_apis"])} unprotected API host(s)')
    if sig['sensitive_ports']:
        counter.append(f'{len(sig["sensitive_ports"])} exposed sensitive service(s)')
    if counter:
        bits.append('The signals driving this are ' + ', '.join(counter) + '.')

    if exposure.get('waf_coverage_pct') == 100 and sig['mail_typosquats']:
        bits.append(
            'Note the shape of this: WAF coverage is complete, yet the leading path never touches your '
            'infrastructure. The perimeter is not where this estate is weakest.'
        )

    return ' '.join(bits)


# ---------------------------------------------------------------------------
# Findings normalisation
# ---------------------------------------------------------------------------
def _as_list(x):
    if isinstance(x, list):
        return [str(i) for i in x if i not in (None, '')]
    if x in (None, ''):
        return []
    return [str(x)]


def _normalise_active_findings(vulns):
    """Preserve the full proof-of-concept, testing, and output detail every
    scanner emits — not just a title/severity — so the report can show HOW each
    finding was reached and WHAT came back, per module."""
    out = []
    for v in vulns:
        # --- Testing details: how the finding was exercised ---
        testing = []
        if v.get('method') or v.get('status_code'):
            m = v.get('method') or 'GET'
            sc = v.get('status_code')
            testing.append(('Request', f"{m} → HTTP {sc}" if sc else m))
        if v.get('path'):
            testing.append(('Endpoint path', v.get('path')))
        if v.get('parameter'):
            testing.append(('Injected parameter', v.get('parameter')))
        if v.get('sqli_type'):
            testing.append(('Injection technique', v.get('sqli_type')))
        if v.get('detection_pass') and v.get('detection_pass') != 'baseline':
            testing.append(('Detection pass', v.get('detection_pass')))
        if v.get('waf_vendor'):
            testing.append(('WAF in front', v.get('waf_vendor')))
        if v.get('check'):
            testing.append(('Check', v.get('check')))
        if v.get('detection_method'):
            testing.append(('Detection method', v.get('detection_method')))
        if v.get('detection_label'):
            testing.append(('Detection label', v.get('detection_label')))
        if v.get('service'):
            testing.append(('Target service', v.get('service')))
        if v.get('cloud_category'):
            testing.append(('Cloud category', v.get('cloud_category')))
        if v.get('exploitability'):
            testing.append(('Exploitability', v.get('exploitability')))
        if v.get('matcher_name'):
            testing.append(('Matcher', v.get('matcher_name')))
        if v.get('nuclei_type'):
            testing.append(('Protocol', v.get('nuclei_type')))
        if v.get('confidence'):
            testing.append(('Confidence', v.get('confidence')))
        tool = v.get('detection_tool') or v.get('detection_source') or ''
        if tool:
            testing.append(('Detection tool', tool))
        cvss = ''
        if v.get('cvss_score'):
            cvss = f"{v.get('cvss_score')}"
            if v.get('cvss_metrics'):
                cvss += f" · {v.get('cvss_metrics')}"
            testing.append(('CVSS', cvss))

        # --- Output: what the scanner actually got back ---
        output = []
        for e in _as_list(v.get('extracted_results')):
            output.append(('Extracted', e))
        if v.get('evidence'):
            output.append(('Evidence', v.get('evidence')))
        if v.get('hrs_indicators'):
            output.append(('HRS indicators', ', '.join(_as_list(v.get('hrs_indicators')))))
        if v.get('hrs_score') not in (None, ''):
            output.append(('HRS score', str(v.get('hrs_score'))))
        if v.get('exposure_note'):
            output.append(('Exposure note', v.get('exposure_note')))
        if v.get('correlated_with'):
            output.append(('Correlated with', ', '.join(_as_list(v.get('correlated_with')))))
        if v.get('manual_verification'):
            output.append(('Manual verification', v.get('manual_verification')))

        # --- PoC: the reproducible request/response/payload ---
        poc = {
            'request': v.get('request') or '',
            'response': v.get('response') or '',
            'curl': v.get('curl_command') or '',
            'payload': v.get('poc_payload') or '',
        }

        raw_path = v.get('path') or ''
        out.append({
            'title': v.get('template') or 'Finding',
            'severity': (v.get('severity') or 'info').lower(),
            'host': v.get('host') or '',
            'path': raw_path,
            'path_template': _path_template(raw_path),
            'method': v.get('method') or '',
            'status_code': v.get('status_code'),
            'url': v.get('url') or v.get('matched_at') or '',
            'source': v.get('source') or '',
            'category': v.get('category') or '',
            'template_id': v.get('template_id') or '',
            'cve': v.get('cve_id') or '',
            'cwe': ', '.join(v.get('cwe_id') or []) if isinstance(v.get('cwe_id'), list) else (v.get('cwe_id') or v.get('cwe') or ''),
            'impact': v.get('impact') or v.get('description') or '',
            'remediation': v.get('remediation') or '',
            'verified': bool(v.get('verified')),
            'confidence': v.get('confidence') or '',
            'tags': _as_list(v.get('tags')),
            'reference': _as_list(v.get('reference')),
            'testing': testing,
            'output': output,
            'poc': poc,
            'has_detail': bool(testing or output or poc['request'] or poc['response'] or poc['curl'] or poc['payload']),
        })
    out.sort(key=lambda f: (_sev_key(f['severity']), f['source'], f['host']))
    return out


# Human labels + fix guidance per finding source, so each module gets its own
# titled subsection in the report rather than a single undifferentiated table.
_SOURCE_META = {
    'API Security':            ('API Security Testing', 'apisec.py + intelligence engine — BOLA/IDOR, broken auth, mass assignment, JWT, 403-bypass'),
    'SQLi Testing':            ('SQL Injection', 'sqlmap — WAF-aware, boolean/time/error/union, incl. discovered API endpoints'),
    'XSS Testing':             ('Cross-Site Scripting', 'dalfox — reflected/DOM XSS on parameterised URLs incl. API surface'),
    'Nuclei':                  ('Nuclei Templates', 'community + custom templates — CVEs, misconfigurations, exposures'),
    'Nuclei (Cloud)':          ('Nuclei — Cloud', 'cloud-specific templates against storage/CDN/edge'),
    'Subdomain Takeover':      ('Subdomain Takeover', 'subjack — CNAME/NS/stale-A/mail delegation checks'),
    'DNS Security':            ('DNS Security', 'dns_security_audit.py — SPF/DKIM/DMARC/DNSSEC/zone hygiene'),
    'HRS Surface (indicator)': ('HTTP Request Smuggling (surface)', 'hrs_detect.py — safe indicator-only surface assessment'),
    'Cloud Exposure':          ('Cloud Exposure', 'bucket/ACL/policy enumeration, presigned URLs, artifact fingerprinting'),
    'Secret Scan':             ('Leaked Secrets', 'TruffleHog + secret_validator.py — live-credential validation'),
    'Param Fuzzing':           ('Parameter Fuzzing', 'ffuf/arjun — LFI, hidden parameters'),
    '403 Bypass':              ('403/401 Access-Control Bypass', 'bypass_403.py — path/header mutation confirmation'),
    'Access Control Bypass':   ('403/401 Access-Control Bypass', 'bypass_403.py — path/header mutation confirmation'),
}

# Which finding sources are genuine *web application / API security* issues
# (the report's primary findings) versus infrastructure / cloud / DNS / network
# exposure. This is what keeps the "Web Application & API Vulnerabilities"
# section pure — app-sec only — instead of burying the API/SQLi/XSS findings
# under bucket, DNS, and takeover noise.
_APPSEC_SOURCES = {
    'API Security', 'SQLi Testing', 'XSS Testing', 'Param Fuzzing',
    '403 Bypass', 'Access Control Bypass', 'HRS Surface (indicator)',
    'Nuclei', 'Secret Scan',
}
_INFRA_SOURCES = {
    'Cloud Exposure', 'DNS Security', 'Subdomain Takeover', 'Nuclei (Cloud)',
}


def _domain_of(source):
    if source in _APPSEC_SOURCES:
        return 'appsec'
    if source in _INFRA_SOURCES:
        return 'infra'
    return 'infra'  # unknown sources default to the infrastructure bucket


def _group_findings_by_source(active, domain=None):
    """Group the normalised active findings into per-module sections, each
    ordered by severity, so the report presents POC/testing detail per tool.

    If `domain` is 'appsec' or 'infra', only sources in that domain are kept —
    this is how the report separates true web/API vulnerabilities from
    infrastructure/cloud/DNS exposure."""
    groups = {}
    for f in active:
        src = f['source'] or 'Other'
        if domain and _domain_of(src) != domain:
            continue
        groups.setdefault(src, []).append(f)
    sections = []
    for src, fs in groups.items():
        label, blurb = _SOURCE_META.get(src, (src or 'Other', ''))
        counts = Counter(x['severity'] for x in fs)
        sections.append({
            'source': src,
            'label': label,
            'blurb': blurb,
            'count': len(fs),
            'worst': min((x['severity'] for x in fs), key=_sev_key) if fs else 'info',
            'counts': dict(counts),
            'findings': fs,
        })
    sections.sort(key=lambda s: (_sev_key(s['worst']), -s['count']))
    return sections


def _osint_sections(sig, osint):
    """Group OSINT findings by category, ordered by worst severity present."""
    labels = {}
    for f in osint.get('findings') or []:
        if f.get('category'):
            labels[f['category']] = f.get('category_label') or f['category']

    sections = []
    for cat, findings in sig['osint_by_cat'].items():
        if not cat:
            continue
        fs = sorted(findings, key=lambda f: _sev_key(f.get('severity')))
        counts = Counter((f.get('severity') or 'info').lower() for f in fs)
        sections.append({
            'category': cat,
            'label': labels.get(cat, cat.replace('_', ' ').title()),
            'count': len(fs),
            'worst': fs[0].get('severity') if fs else 'info',
            'counts': dict(counts),
            'findings': fs,
        })
    sections.sort(key=lambda s: (_sev_key(s['worst']), -s['count']))
    return sections


# ---------------------------------------------------------------------------
# Attack Surface Intelligence (Module 23 — Internet Intelligence Layer)
# ---------------------------------------------------------------------------

def _norm_bars(items, label_key, count_key='count', limit=12):
    """Normalise IIL top-N dict lists into [label, count] tuples for the report.

    IIL emits e.g. [{'port':443,'count':7}, …]; the report's bar template wants
    a uniform [label, count] shape regardless of the source key names.
    """
    out = []
    for it in (items or [])[:limit]:
        if isinstance(it, dict):
            label = it.get(label_key, '')
            if label in ('', '—', None):
                label = 'unknown'
            out.append([label, it.get(count_key, 0) or 0])
        elif isinstance(it, (list, tuple)) and len(it) >= 2:
            out.append([it[0] if it[0] not in ('', '—', None) else 'unknown', it[1]])
    return out


def _build_attack_surface_section(iil):
    """Reshape IIL data (Module 23) into the report's attack_surface section."""
    if not iil.get('enabled'):
        return {'enabled': False}

    issues = iil.get('issues') or []
    issue_rows = sorted(issues, key=lambda i: _sev_key(i.get('severity')))

    # Critical assets — flatten to a uniform display shape.
    crit = []
    for a in (iil.get('critical_assets') or [])[:15]:
        host = (a.get('hostnames') or [None])[0] or a.get('ip') or '—'
        crit.append({
            'host': host,
            'ip': a.get('ip', ''),
            'risk_score': a.get('risk_score', 0),
            'risk_band': _score_to_sev(a.get('risk_score', 0)),
            'findings': a.get('findings_count', 0),
            'ports': a.get('ports', 0),
            'cves': a.get('cves', 0),
            'location': ', '.join(x for x in (a.get('country'), a.get('city')) if x) or '—',
            'provider': a.get('provider') or '',
        })

    # issues_by_category is already [label, count]; normalise defensively.
    cats = _norm_bars(iil.get('issues_by_category'), 'category', 'count', limit=10)

    return {
        'enabled': True,
        'score': iil.get('attack_surface_score', 0),
        'posture': iil.get('posture', 'low'),
        'total_assets': iil.get('total_assets', 0),
        'total_findings': iil.get('total_findings', 0),
        'total_cves': iil.get('total_cves', 0),
        'total_ports': iil.get('total_ports', 0),
        'geo_located': iil.get('geo_located', 0),
        'issues_total': iil.get('issues_total', len(issues)),
        'issues_by_severity': iil.get('issues_by_severity') or {},
        'issues_by_category': cats,
        'issues': issue_rows,
        'critical_assets': crit,
        'top_cves': _norm_bars(iil.get('top_cves'), 'cve'),
        'top_ports': _norm_bars(iil.get('top_ports'), 'port'),
        'top_services': _norm_bars(iil.get('top_services'), 'service'),
        'top_providers': _norm_bars(iil.get('top_providers'), 'provider'),
        'top_countries': _norm_bars(iil.get('top_countries'), 'country'),
        'enrichment': iil.get('enrichment') or {},
    }


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------
def build_report(scan_id, scan_data, osint, cloud, executive, risk, iil=None):
    """Assemble the full report model.

    Args:
        scan_id:    scan folder id
        scan_data:  dashboard.get_scan_data() result
        osint:      /api/osint payload for this scan
        cloud:      /api/cloud payload for this scan
        executive:  /api/executive payload for this scan
        risk:       /api/risk payload for this scan
        iil:        /api/internet-intel payload (Module 23 attack surface)
    """
    iil = iil or {}
    pipeline_info = scan_data.get('pipeline_info') or {}
    hosts = scan_data.get('hosts') or {}
    vulns = scan_data.get('vulnerabilities') or []
    stats = scan_data.get('statistics') or {}

    domain = pipeline_info.get('target') or re.sub(r'-\d{6}-\d{4}$', '', scan_id)

    sig = _extract_signals(hosts, vulns, osint or {}, cloud or {})
    paths = _derive_attack_paths(sig, domain)
    entry_points = _rank_entry_points(sig)

    corr = (osint or {}).get('correlation') or {}
    exposure = (executive or {}).get('exposure') or {}

    active = _normalise_active_findings(vulns)
    sev_counts = Counter(f['severity'] for f in active)

    # Port roll-up across resolved hosts.
    port_counter = Counter()
    for d in sig['resolved'].values():
        for p in d.get('ports_open') or []:
            try:
                port_counter[int(p)] += 1
            except (TypeError, ValueError):
                continue

    tech_counter = Counter()
    for d in hosts.values():
        for t in re.split(r'[,;]\s*', str(d.get('tech_tag') or '')):
            if t.strip():
                tech_counter[t.strip()] += 1

    path_sev = Counter(p['severity'] for p in paths)

    # OSINT is only "present" when the passive engine actually returned findings.
    # When it didn't (module disabled, no connectors, or genuinely nothing found)
    # the report omits every OSINT surface entirely rather than printing empty
    # placeholders, dashes, or "no signal" cards.
    osint_findings_list = (osint or {}).get('findings') or []
    osint_total = (osint or {}).get('total', len(osint_findings_list))
    has_osint = bool(osint_findings_list) or bool(osint_total)

    return {
        'meta': {
            'target': domain,
            'scan_id': scan_id,
            'generated_at': datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC'),
            'scan_started': pipeline_info.get('start_time') or '',
            'scan_status': pipeline_info.get('status') or 'unknown',
            'engine_version': ENGINE_VERSION,
            'classification': 'CONFIDENTIAL — Attack Surface Assessment',
        },
        'summary': {
            'narrative': _build_narrative(domain, sig, paths, corr, exposure),
            'org_score': (risk or {}).get('org_score', executive.get('org_score', 0) if executive else 0),
            'grade': (risk or {}).get('grade', executive.get('grade', '') if executive else ''),
            'has_osint': has_osint,
            'osint_score': corr.get('osint_score') if has_osint else None,
            'osint_grade': corr.get('osint_grade') if has_osint else None,
            'blended_score': corr.get('blended_score'),
            'blended_grade': corr.get('blended_grade'),
            'osint_narrative': ((osint or {}).get('executive_summary') or '') if has_osint else '',
            'path_counts': {
                'total': len(paths),
                'critical': path_sev.get('critical', 0),
                'high': path_sev.get('high', 0),
                'medium': path_sev.get('medium', 0),
                'low': path_sev.get('low', 0),
            },
        },
        'surface': {
            'total_assets': exposure.get('total_assets', stats.get('total_hosts', len(hosts))),
            'resolved': exposure.get('resolved', stats.get('resolved_hosts', len(sig['resolved']))),
            'internet_facing': exposure.get('internet_facing_http', len(sig['live'])),
            'waf_coverage_pct': exposure.get('waf_coverage_pct', 0),
            'waf_uncovered': exposure.get('waf_uncovered', len(sig['no_waf'])),
            'cdn_fronted': exposure.get('cdn_fronted', 0),
            'open_ports': stats.get('open_ports', sum(port_counter.values())),
            'apis': len(sig['apis']),
            'buckets': len(sig['buckets']),
            'dangling': len(sig['dangling']),
            'secrets': (executive or {}).get('findings', {}).get('secrets', len(sig['secret_vulns'])),
            'osint_total': osint_total,
            'top_ports': port_counter.most_common(12),
            'top_tech': tech_counter.most_common(12),
        },
        'attack_paths': paths,
        'entry_points': entry_points,
        'attack_surface': _build_attack_surface_section(iil),
        'findings': {
            'active': active,
            'active_counts': dict(sev_counts),
            'active_sections': _group_findings_by_source(active),
            'appsec_sections': _group_findings_by_source(active, domain='appsec'),
            'infra_sections': _group_findings_by_source(active, domain='infra'),
            'appsec_count': sum(1 for f in active if _domain_of(f['source']) == 'appsec'),
            'infra_count': sum(1 for f in active if _domain_of(f['source']) == 'infra'),
            'osint_sections': _osint_sections(sig, osint or {}),
            'cloud': sig['cloud_findings'],
        },
        'appendix': {
            'assets': sorted(
                [{
                    'host': h,
                    'ip': d.get('ip', ''),
                    'status': d.get('http_status', ''),
                    'waf': d.get('waf_vendor') or 'none',
                    'cdn': bool(d.get('cdn')),
                    'ports': sorted(int(p) for p in (d.get('ports_open') or []) if str(p).isdigit()),
                    'tech': d.get('tech_tag') or d.get('server_banner') or '',
                    'risk_score': d.get('risk_score', 0),
                    'risk_band': d.get('risk_band', 'low'),
                } for h, d in sig['resolved'].items()],
                key=lambda a: (-(a['risk_score'] or 0), a['host'])
            ),
            'unresolved_count': len(hosts) - len(sig['resolved']),
        },
    }


# ---------------------------------------------------------------------------
# Agent-friendly JSON summary — single-object export
# ---------------------------------------------------------------------------
def build_json_summary(report_model):
    """Flatten the full report model into a single {"meta": ..., "findings": [...]}
    document optimised for cross-version AI agent consumption.

    Each finding is a flat dict with path_template for version-stable joins,
    verified/confidence for prioritisation, and curl_poc for re-execution."""
    meta = report_model.get('meta', {})
    active = report_model.get('findings', {}).get('active', [])
    counts = report_model.get('findings', {}).get('active_counts', {})

    verified = sum(1 for f in active if f.get('verified'))
    confirmed = sum(1 for f in active if f.get('confidence') == 'confirmed')
    unconfirmed = sum(1 for f in active if f.get('confidence') == 'unconfirmed')

    flat_findings = []
    for f in active:
        flat_findings.append({
            'title': f.get('title', ''),
            'severity': f.get('severity', 'info'),
            'category': f.get('category', ''),
            'method': f.get('method', ''),
            'path': f.get('path', ''),
            'path_template': f.get('path_template', ''),
            'status_code': f.get('status_code'),
            'host': f.get('host', ''),
            'evidence': next(
                (val for label, val in (f.get('output') or []) if label == 'Evidence'),
                ''
            ),
            'remediation': f.get('remediation', ''),
            'verified': f.get('verified', False),
            'confidence': f.get('confidence', ''),
            'curl_poc': (f.get('poc') or {}).get('curl', ''),
            'cve': f.get('cve', ''),
            'cwe': f.get('cwe', ''),
            'source': f.get('source', ''),
            'template_id': f.get('template_id', ''),
        })

    return {
        'meta': {
            '_meta': True,
            'target': meta.get('target', ''),
            'version': ENGINE_VERSION,
            'generated': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
            'scan_id': meta.get('scan_id', ''),
            'total': len(active),
            'findings_verified': verified,
            'findings_confirmed': confirmed,
            'findings_unconfirmed': unconfirmed,
            'severity_counts': counts,
        },
        'findings': flat_findings,
    }
