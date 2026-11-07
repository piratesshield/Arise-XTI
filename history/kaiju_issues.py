#!/usr/bin/env python3
"""
KAIJU Correlation Engine — Issues, rules, state, timeline.

INV-1: Issue refs are stable across revisions (derived from rule_id + primary_asset + discriminator).
INV-2: Computed half (evidence/severity/risk) is always recomputed; stored half
       (status/first_seen/detections/history) lives in issues-state.json and is never
       overwritten by computation.  Orphaned state entries are tombstoned, never deleted.

Atomic writes: issues-state.json is written via temp+os.rename with a .bak copy.
events.jsonl appends are idempotent on (rev_from, rev_to, kind, ref).
"""

import sys as _sys, os as _os
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)


import hashlib
import json
import os
import shutil
import tempfile
import logging
from datetime import datetime

import history.kaiju_entities as ke

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Issue ref (INV-1)
# ---------------------------------------------------------------------------

def _issue_ref(rule_id, primary_ref, discriminator=''):
    """Stable issue ref = hash(rule_id:primary_ref:discriminator)."""
    key = f"{rule_id}:{primary_ref}:{discriminator}"
    digest = hashlib.sha1(key.encode('utf-8')).hexdigest()[:12]
    return f"issue:{digest}"


# ---------------------------------------------------------------------------
# Correlation rules — each returns a list of computed issues
# ---------------------------------------------------------------------------

# Sensitive ports — DB, cache, message queue (shouldn't be public)
SENSITIVE_PORTS = {
    3306: 'MySQL', 5432: 'PostgreSQL', 6379: 'Redis', 27017: 'MongoDB',
    1433: 'MSSQL', 9200: 'Elasticsearch', 5601: 'Kibana', 11211: 'Memcached',
    9042: 'Cassandra', 2181: 'ZooKeeper',
}

# Management / remote-access ports
MGMT_PORTS = {22: 'SSH', 23: 'Telnet', 3389: 'RDP', 5900: 'VNC', 8080: 'HTTP-Alt', 9090: 'Management'}

# Dev/staging hostname patterns
DEV_PATTERNS = ['dev', 'staging', 'stage', 'test', 'uat', 'qa', 'sandbox', 'demo', 'beta', 'alpha', 'preprod', 'internal']


def _sev_color(sev):
    return {'critical': '#f87171', 'high': '#f97316', 'medium': '#eab308', 'low': '#38bdf8', 'info': '#94a3b8'}.get(sev, '#94a3b8')


# ---------------------------------------------------------------------------
# Risk scoring — computed, not hardcoded (F14, ARISE_REMEDIATION_ROADMAP.md)
# ---------------------------------------------------------------------------
# Every rule below used to emit one hardcoded risk_score/severity pair
# regardless of the issue's actual context — two hosts hitting the same rule
# always scored identically even when one was directly reachable with zero
# controls and the other sat behind partial mitigations. This mirrors the
# pattern cloud_storage_enum.py's content grading already proves works in
# this codebase: a real severity base, scaled by real per-issue signals
# already present on the entity — not a new framework, just no longer
# discarding evidence that was already computed and sitting right there.
_SEV_BASE = {'critical': 9.0, 'high': 7.0, 'medium': 5.0, 'low': 3.0, 'info': 1.5}


def _risk_score(severity, factor=1.0):
    base = _SEV_BASE.get(severity, 3.0)
    return round(min(max(base * factor, 0.5), 10.0), 1)


def rule_exposed_service(entities, relations):
    """Sensitive database/cache ports exposed to the internet."""
    issues = []
    for e in entities:
        if e['type'] != 'svc':
            continue
        port = e['attrs'].get('port')
        if port not in SENSITIVE_PORTS:
            continue
        product = SENSITIVE_PORTS[port]
        svc_product = e['attrs'].get('product', '')

        # Find the host running this service
        host_refs = [r['source'] for r in relations if r['target'] == e['ref'] and r['type'] == 'RUNS']
        for hr in host_refs:
            host_e = ke.entity_by_ref(entities, hr)
            if not host_e:
                continue

            # Find subs pointing to this host
            sub_refs = [r['source'] for r in relations if r['target'] == hr and r['type'] == 'RESOLVES_TO']
            sub_labels = []
            for sr in sub_refs:
                se = ke.entity_by_ref(entities, sr)
                if se:
                    sub_labels.append(se['label'])

            chain = sub_refs[:1] + [hr, e['ref']]
            severity = 'critical' if port in (6379, 27017, 9200, 11211) else 'high'
            # More distinct subdomains resolving onto the same exposed
            # service = wider blast radius if it's breached.
            factor = 1.0 + min(0.05 * max(len(sub_labels) - 1, 0), 0.15)
            issues.append({
                'ref': _issue_ref('exposed-service', hr, str(port)),
                'rule_id': 'exposed-service',
                'title': f"Publicly exposed {product} (port {port}) on {host_e['label']}",
                'severity': severity,
                'risk_score': _risk_score(severity, factor),
                'risk_inputs': [f'port={port}', f'product={product}', 'exposure=public',
                               f'hostnames_affected={len(sub_labels) or 1}'],
                'summary_md': f"Port **{port}** ({product}) is reachable from the public internet on **{host_e['label']}**"
                              + (f" (subdomain: {', '.join(sub_labels)})" if sub_labels else '')
                              + f". {svc_product or product} should never be directly exposed — it allows unauthenticated "
                              + "data access or remote code execution depending on configuration.",
                'evidence_chain': chain,
                'evidence': [
                    {'ref': e['ref'], 'fact': 'port_open_public', 'detail': {'port': port, 'product': product}},
                ],
                'affected_assets': [hr],
                'vuln_refs': [],
                'remediation_md': f"1. Restrict port {port} to internal networks (VPC security group / firewall rule).\n"
                                  f"2. If remote access is needed, use SSH tunnelling or a VPN.\n"
                                  f"3. Enable authentication if not already configured.",
            })
    return issues


def rule_dev_staging_exposed(entities, relations):
    """Dev/staging/test subdomains exposed to the internet."""
    issues = []
    for e in entities:
        if e['type'] != 'sub':
            continue
        fqdn = e['attrs'].get('fqdn', e['label']).lower()
        label_part = fqdn.split('.')[0]
        matched_pattern = None
        for pat in DEV_PATTERNS:
            if pat in label_part:
                matched_pattern = pat
                break
        if not matched_pattern:
            continue
        if not e['attrs'].get('resolved', False):
            continue

        # Find host
        host_refs = [r['target'] for r in relations if r['source'] == e['ref'] and r['type'] == 'RESOLVES_TO']
        chain = [e['ref']] + host_refs[:1]

        severity = 'medium'
        factor = 1.0
        if e['attrs'].get('has_webapp'):
            factor += 0.15  # actually serving an app, not just a bare DNS-resolved host
        hs = e['attrs'].get('http_status')
        if isinstance(hs, int) and 200 <= hs < 400:
            factor += 0.1  # publicly reachable content, not gated by 401/403

        issues.append({
            'ref': _issue_ref('dev-staging-exposed', e['ref'], matched_pattern),
            'rule_id': 'dev-staging-exposed',
            'title': f"Dev/staging subdomain exposed: {fqdn}",
            'severity': severity,
            'risk_score': _risk_score(severity, factor),
            'risk_inputs': [f'pattern={matched_pattern}', 'exposure=public',
                           f'has_webapp={bool(e["attrs"].get("has_webapp"))}',
                           f'http_status={hs}'],
            'summary_md': f"The subdomain **{fqdn}** matches the pattern `{matched_pattern}`, indicating a "
                          f"development or staging environment. It resolves to a public IP, potentially exposing "
                          f"unfinished code, debug endpoints, or test data.",
            'evidence_chain': chain,
            'evidence': [
                {'ref': e['ref'], 'fact': 'dev_hostname', 'detail': {'pattern': matched_pattern, 'fqdn': fqdn}},
            ],
            'affected_assets': [e['ref']],
            'vuln_refs': [],
            'remediation_md': f"1. If {fqdn} is not needed publicly, restrict DNS or remove the record.\n"
                              f"2. If it must be public, ensure it has the same security controls as production.\n"
                              f"3. Never run debug mode or expose admin panels on dev/staging hosts.",
        })
    return issues


def rule_missing_security_headers(entities, relations):
    """Web applications missing critical security headers."""
    issues = []
    for e in entities:
        if e['type'] != 'sub':
            continue
        if not e['attrs'].get('has_webapp'):
            continue
        missing = e['attrs'].get('missing_headers', [])
        score = e['attrs'].get('security_header_score', 6)
        if score is None:
            score = 6
        if score >= 4:  # 4+ out of 6 = acceptable
            continue
        critical_missing = [h for h in missing if h in ('strict-transport-security', 'content-security-policy', 'x-content-type-options')]
        if not critical_missing:
            continue

        fqdn = e['attrs'].get('fqdn', e['label'])
        severity = 'high' if score == 0 else 'medium'
        # Continuous with how many of the 6 headers are actually present
        # (this branch only reaches score 0-3, since score>=4 is skipped
        # above) instead of a single binary split at zero.
        factor = 1.0 + (4 - min(score, 4)) / 4.0 * 0.3

        issues.append({
            'ref': _issue_ref('missing-headers', e['ref'], ''),
            'rule_id': 'missing-headers',
            'title': f"Missing security headers on {fqdn} ({score}/6)",
            'severity': severity,
            'risk_score': _risk_score(severity, factor),
            'risk_inputs': [f'header_score={score}/6', f'missing={len(missing)}'],
            'summary_md': f"**{fqdn}** is missing {len(missing)} security headers (score {score}/6). "
                          f"Critical missing: {', '.join(critical_missing)}. "
                          f"This exposes the application to clickjacking, MIME-sniffing, and XSS attacks.",
            'evidence_chain': [e['ref']],
            'evidence': [
                {'ref': e['ref'], 'fact': 'missing_headers', 'detail': {'score': score, 'missing': missing}},
            ],
            'affected_assets': [e['ref']],
            'vuln_refs': [],
            'remediation_md': "Add the following headers to all HTTP responses:\n"
                              "- `Strict-Transport-Security: max-age=31536000; includeSubDomains`\n"
                              "- `Content-Security-Policy: default-src 'self'`\n"
                              "- `X-Content-Type-Options: nosniff`\n"
                              "- `X-Frame-Options: DENY`\n"
                              "- `Referrer-Policy: strict-origin-when-cross-origin`\n"
                              "- `Permissions-Policy: camera=(), microphone=()`",
        })
    return issues


def rule_leaked_secrets(entities, relations):
    """Leaked API keys or credentials found in source/JS."""
    issues = []
    for e in entities:
        if e['type'] != 'vuln':
            continue
        if e['attrs'].get('source') != 'Secret Scan':
            continue
        template = e['attrs'].get('template', '')
        host = e['attrs'].get('host', 'Unknown')
        url = e['attrs'].get('url', '')
        # Trust the detector's own severity when it gave one (e.g. a
        # generic/low-confidence secret-shaped pattern tagged 'medium' should
        # not be silently promoted to critical) — 'critical' is the fallback
        # for a source that genuinely doesn't grade itself, not a blanket
        # override of a real signal.
        severity = (e['attrs'].get('severity') or 'critical').lower()
        if severity not in _SEV_BASE:
            severity = 'critical'
        factor = 1.05 if url else 1.0  # a live URL location is more actionable than a bare match

        # Find sub for this host
        sub_r = ke._sub_ref(host) if host != 'Unknown' else None
        chain = [sub_r, e['ref']] if sub_r else [e['ref']]

        issues.append({
            'ref': _issue_ref('leaked-secret', e['ref'], ''),
            'rule_id': 'leaked-secret',
            'title': f"Leaked credential: {template}",
            'severity': severity,
            'risk_score': _risk_score(severity, factor),
            'risk_inputs': ['source=trufflehog', 'type=credential', 'exposure=public_js',
                           f'detector_severity={severity}'],
            'summary_md': f"A **{template}** was found exposed in a publicly accessible file"
                          + (f" on **{host}**" if host != 'Unknown' else '')
                          + f". URL: `{url[:120]}`. This credential should be rotated immediately.",
            'evidence_chain': chain,
            'evidence': [
                {'ref': e['ref'], 'fact': 'leaked_credential', 'detail': {'template': template, 'host': host}},
            ],
            'affected_assets': [sub_r] if sub_r else [],
            'vuln_refs': [e['ref']],
            'remediation_md': f"1. **Rotate the {template} immediately** — assume it has been compromised.\n"
                              f"2. Review access logs for unauthorized use.\n"
                              f"3. Remove the credential from the source file.\n"
                              f"4. Use environment variables or a secret manager instead of hardcoding.",
        })
    return issues


def rule_hsts_gap(entities, relations):
    """HSTS misconfiguration — missing redirect, missing/weak header, no
    preload. One issue per (host, check): the vuln entity ref already
    encodes template_id+host (kaiju_entities.build_entity_index), so a host
    failing multiple distinct HSTS checks gets multiple stable, separately-
    tracked issues rather than one that silently drops detail — same as
    rule_missing_security_headers and rule_leaked_secrets never collapse
    distinct findings on one asset into a single row.

    Note: 'missing-headers' above already flags a missing STS header, but
    ONLY when a host is missing 2+ of 6 headers overall (score < 4/6) — a
    host with otherwise-good headers but no HSTS, and the most severe HSTS
    check (no HTTP->HTTPS redirect, a real SSL-strip/MITM exposure), have
    ZERO coverage anywhere else in this rule engine. This rule closes that.
    """
    issues = []
    for e in entities:
        if e['type'] != 'vuln':
            continue
        if e['attrs'].get('source') != 'HSTS Audit':
            continue
        template = e['attrs'].get('template', 'HSTS finding')
        host = e['attrs'].get('host', 'Unknown')
        severity = e['attrs'].get('severity', 'low')
        impact = e['attrs'].get('impact', '')
        remediation = e['attrs'].get('remediation', '')

        sub_r = ke._sub_ref(host) if host != 'Unknown' else None
        chain = [sub_r, e['ref']] if sub_r else [e['ref']]

        issues.append({
            'ref': _issue_ref('hsts-gap', e['ref'], ''),
            'rule_id': 'hsts-gap',
            'title': f"{template} on {host}" if host != 'Unknown' else template,
            'severity': severity,
            'risk_score': _risk_score(severity),
            'risk_inputs': [f'hsts_check={e["attrs"].get("template_id", "")}', f'severity={severity}'],
            'summary_md': f"**{host}**: {template}. " + (impact or "See evidence for details.")
                          + (" This weakens HSTS enforcement — a first-visit or "
                             "misconfigured client can be downgraded to plain HTTP "
                             "and intercepted (SSL-strip/MITM)."
                             if severity in ('critical', 'high') else ""),
            'evidence_chain': chain,
            'evidence': [
                {'ref': e['ref'], 'fact': 'hsts_gap', 'detail': {'check': e['attrs'].get('template_id', ''), 'impact': impact}},
            ],
            'affected_assets': [sub_r] if sub_r else [],
            'vuln_refs': [e['ref']],
            'remediation_md': remediation or "Configure Strict-Transport-Security correctly for this host.",
        })
    return issues


def rule_mcp_ai_exposure(entities, relations):
    """MCP / AI surface exposure (Module 8D — discovery/mcp_ai_probe.py).
    Unauthenticated MCP servers, tool-poisoning / prompt-injection content in
    tool metadata, open/unauthenticated inference endpoints, cleartext/CORS
    posture. One issue per (host, finding); the vuln entity ref encodes
    title+host so distinct findings on one host stay separately tracked. These
    had ZERO coverage anywhere else in the rule engine before this rule."""
    issues = []
    for e in entities:
        if e['type'] != 'vuln':
            continue
        if e['attrs'].get('source') != 'MCP/AI Probe':
            continue
        template = e['attrs'].get('template', 'MCP/AI finding')
        host = e['attrs'].get('host', 'Unknown')
        severity = e['attrs'].get('severity', 'low')
        impact = e['attrs'].get('impact', '')
        remediation = e['attrs'].get('remediation', '')

        sub_r = ke._sub_ref(host) if host != 'Unknown' else None
        chain = [sub_r, e['ref']] if sub_r else [e['ref']]

        issues.append({
            'ref': _issue_ref('mcp-ai-exposure', e['ref'], ''),
            'rule_id': 'mcp-ai-exposure',
            'title': f"{template} on {host}" if host != 'Unknown' else template,
            'severity': severity,
            'risk_score': _risk_score(severity),
            'risk_inputs': [f'mcp_ai_check={e["attrs"].get("template_id", "")}',
                            f'severity={severity}'],
            'summary_md': f"**{host}**: {template}. " + (impact or "See evidence for details.")
                          + (" An exposed MCP server or AI/LLM endpoint is a direct "
                             "prompt-injection / tool-abuse / cost-abuse surface."
                             if severity in ('critical', 'high') else ""),
            'evidence_chain': chain,
            'evidence': [
                {'ref': e['ref'], 'fact': 'mcp_ai_exposure',
                 'detail': {'check': e['attrs'].get('template_id', ''), 'impact': impact}},
            ],
            'affected_assets': [sub_r] if sub_r else [],
            'vuln_refs': [e['ref']],
            'remediation_md': remediation or "Authenticate and rate-limit the MCP/AI endpoint; "
                              "treat third-party tool metadata as untrusted.",
        })
    return issues


def rule_new_asset(entities, relations, previous_entities=None):
    """Assets appearing for the first time (not seen in previous scan)."""
    if not previous_entities:
        return []
    prev_refs = {e['ref'] for e in previous_entities}
    issues = []
    for e in entities:
        if e['type'] != 'sub':
            continue
        if e['ref'] in prev_refs:
            continue
        if not e['attrs'].get('resolved', False):
            continue
        fqdn = e['attrs'].get('fqdn', e['label'])
        severity = 'info'
        # A new asset that's already serving an app is more actionable than
        # a bare DNS entry — still info-level (not itself a vulnerability),
        # but worth a slightly higher look-at-this-first weight.
        factor = 1.2 if e['attrs'].get('has_webapp') else 1.0
        issues.append({
            'ref': _issue_ref('new-asset', e['ref'], ''),
            'rule_id': 'new-asset',
            'title': f"New subdomain discovered: {fqdn}",
            'severity': severity,
            'risk_score': _risk_score(severity, factor),
            'risk_inputs': ['type=new_subdomain', 'first_seen=current_rev',
                           f'has_webapp={bool(e["attrs"].get("has_webapp"))}'],
            'summary_md': f"**{fqdn}** was not seen in the previous scan. New assets may indicate "
                          f"shadow IT, unsanctioned deployments, or legitimate infrastructure changes. "
                          f"Review to confirm it is expected.",
            'evidence_chain': [e['ref']],
            'evidence': [
                {'ref': e['ref'], 'fact': 'new_asset', 'detail': {'fqdn': fqdn}},
            ],
            'affected_assets': [e['ref']],
            'vuln_refs': [],
            'remediation_md': "1. Verify the subdomain is authorized and expected.\n"
                              "2. Ensure it follows the same security policies as production.\n"
                              "3. If unsanctioned, investigate who created it and why.",
        })
    return issues


def rule_webapp_no_waf(entities, relations):
    """Web application without WAF protection."""
    issues = []
    for e in entities:
        if e['type'] != 'sub':
            continue
        if not e['attrs'].get('has_webapp'):
            continue
        waf = (e['attrs'].get('waf_vendor') or '').strip().lower()
        if waf and waf != 'none':
            continue
        fqdn = e['attrs'].get('fqdn', e['label'])
        severity = 'medium'
        factor = 1.0
        missing = e['attrs'].get('missing_headers') or []
        if len(missing) >= 4:
            factor += 0.2  # no WAF AND poor header posture compounds
        hs = e['attrs'].get('http_status')
        if isinstance(hs, int) and 200 <= hs < 400:
            factor += 0.1  # live and publicly reachable, not gated

        issues.append({
            'ref': _issue_ref('no-waf', e['ref'], ''),
            'rule_id': 'no-waf',
            'title': f"Web application without WAF: {fqdn}",
            'severity': severity,
            'risk_score': _risk_score(severity, factor),
            'risk_inputs': ['waf=none', 'has_webapp=true', f'missing_headers={len(missing)}',
                           f'http_status={hs}'],
            'summary_md': f"**{fqdn}** serves a web application but has no detectable WAF "
                          f"(Web Application Firewall). This exposes the application directly to "
                          f"automated attacks, scanners, and exploitation attempts.",
            'evidence_chain': [e['ref']],
            'evidence': [
                {'ref': e['ref'], 'fact': 'no_waf', 'detail': {'fqdn': fqdn}},
            ],
            'affected_assets': [e['ref']],
            'vuln_refs': [],
            'remediation_md': "1. Deploy a WAF (e.g. Cloudflare, AWS WAF, Akamai) in front of the application.\n"
                              "2. Configure WAF rules for OWASP Top 10 protections.\n"
                              "3. Enable rate limiting and bot protection.",
        })
    return issues


def rule_compounding_risk(entities, relations):
    """Multiple independent risk factors converging on the SAME host compound
    exploitability beyond any single factor alone — an exposed database is
    bad; the same database on a host that ALSO runs a vulnerable,
    unprotected web app is dramatically worse, because a single web
    compromise becomes a direct pivot to the data.

    F28 (ARISE_REMEDIATION_ROADMAP.md): kaiju_entities.py's domain->sub->
    host->svc->tech->vuln relationship graph existed, but only
    exposed-service and dev-staging-exposed ever walked it, and only to
    print cosmetic subdomain labels — never to combine signals for a real
    risk computation. This rule is the first to actually use RUNS/
    RESOLVES_TO/AFFECTS together to detect convergence a single-signal rule
    structurally cannot see.
    """
    issues = []
    for h in ke.entities_by_type(entities, 'host'):
        host_ref = h['ref']
        factors = []

        exposed_ports = [
            ke.entity_by_ref(entities, r['target'])['attrs'].get('port')
            for r in relations
            if r['source'] == host_ref and r['type'] == 'RUNS'
            and ke.entity_by_ref(entities, r['target'])
            and ke.entity_by_ref(entities, r['target'])['attrs'].get('port') in SENSITIVE_PORTS
        ]
        if exposed_ports:
            names = sorted({SENSITIVE_PORTS[p] for p in exposed_ports})
            factors.append(('exposed_service', f"exposed {', '.join(names)}"))

        sub_refs_here = [r['source'] for r in relations
                        if r['target'] == host_ref and r['type'] == 'RESOLVES_TO']
        vuln_hits, no_waf_subs, bad_header_subs = [], [], []
        for sr in sub_refs_here:
            sub_e = ke.entity_by_ref(entities, sr)
            if not sub_e:
                continue
            for r in relations:
                if r['type'] == 'AFFECTS' and r['target'] == sr:
                    ve = ke.entity_by_ref(entities, r['source'])
                    if ve and ve['attrs'].get('severity') in ('critical', 'high'):
                        vuln_hits.append(ve)
            waf = (sub_e['attrs'].get('waf_vendor') or '').strip().lower()
            if sub_e['attrs'].get('has_webapp') and (not waf or waf == 'none'):
                no_waf_subs.append(sub_e['label'])
            hscore = sub_e['attrs'].get('security_header_score')
            if hscore is not None and hscore < 3:
                bad_header_subs.append(sub_e['label'])

        if vuln_hits:
            factors.append(('confirmed_vuln',
                           f"{len(vuln_hits)} high/critical finding(s) on this host's subdomain(s)"))
        if no_waf_subs:
            factors.append(('no_waf', f"{len(no_waf_subs)} subdomain(s) with no WAF"))
        if bad_header_subs:
            factors.append(('weak_headers', f"{len(bad_header_subs)} subdomain(s) with weak security headers"))

        if len(factors) < 2:
            continue  # this rule is specifically about CONVERGENCE, not any one factor alone

        severity = 'critical' if len(factors) >= 3 else 'high'
        factor_mult = 1.0 + 0.15 * (len(factors) - 2)
        chain = [host_ref] + sub_refs_here[:3]

        issues.append({
            'ref': _issue_ref('compounding-risk', host_ref, str(sorted(k for k, _ in factors))),
            'rule_id': 'compounding-risk',
            'title': f"Compounding risk on {h['label']}: {len(factors)} converging factors",
            'severity': severity,
            'risk_score': _risk_score(severity, factor_mult),
            'risk_inputs': [f'{k}={v}' for k, v in factors],
            'summary_md': f"Host **{h['label']}** has {len(factors)} independent risk factors "
                          f"converging: " + "; ".join(v for _, v in factors) + ". Each factor alone "
                          "may look moderate on its own issue row, but together they materially "
                          "increase exploitability — e.g. a web vulnerability becomes a direct pivot "
                          "to an exposed database on the same host.",
            'evidence_chain': chain,
            'evidence': [{'ref': host_ref, 'fact': 'compounding_risk',
                         'detail': {'factors': [k for k, _ in factors]}}],
            'affected_assets': [host_ref] + sub_refs_here,
            'vuln_refs': [ve['ref'] for ve in vuln_hits],
            'remediation_md': "Prioritise this host over others with only one isolated issue — "
                              "address the individual factors listed above; the combination, not "
                              "any single one, is what makes it dangerous.",
        })
    return issues


# ---------------------------------------------------------------------------
# Rule registry
# ---------------------------------------------------------------------------

ALL_RULES = {
    'exposed-service': rule_exposed_service,
    'dev-staging-exposed': rule_dev_staging_exposed,
    'missing-headers': rule_missing_security_headers,
    'leaked-secret': rule_leaked_secrets,
    'hsts-gap': rule_hsts_gap,
    'mcp-ai-exposure': rule_mcp_ai_exposure,
    'new-asset': rule_new_asset,
    'no-waf': rule_webapp_no_waf,
    'compounding-risk': rule_compounding_risk,
}


def run_rules(entities, relations, previous_entities=None, disabled_rules=None):
    """Execute all enabled correlation rules.  Returns a list of computed issues."""
    disabled = set(disabled_rules or [])
    computed = []
    for rule_id, fn in ALL_RULES.items():
        if rule_id in disabled:
            continue
        try:
            if rule_id == 'new-asset':
                results = fn(entities, relations, previous_entities=previous_entities)
            else:
                results = fn(entities, relations)
            computed.extend(results)
        except Exception:
            logger.exception(f"Rule {rule_id} failed")
    return computed


# ---------------------------------------------------------------------------
# State management — issues-state.json (INV-2)
# ---------------------------------------------------------------------------

def state_dir(target):
    """Return the sacred state/ directory for a target.

    state/ lives at PROJECT_ROOT (shared with easm-pipeline.sh, which writes
    to it directly at $PROJECT_ROOT/state/$target) — NOT next to this file,
    which now lives one level down at history/. Walk up one level.
    """
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    d = os.path.join(base, 'state', target)
    os.makedirs(d, exist_ok=True)
    return d


def _state_path(target):
    return os.path.join(state_dir(target), 'issues-state.json')


def _events_path(target):
    return os.path.join(state_dir(target), 'events.jsonl')


def load_state(target):
    """Load the stored half of all issues for a target."""
    path = _state_path(target)
    if not os.path.exists(path):
        return {}
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        logger.exception(f"Failed to load issues-state for {target}")
        return {}


def _atomic_write_json(path, data):
    """Write JSON atomically: temp → rename, keep .bak of prior version."""
    dir_path = os.path.dirname(path)
    if os.path.exists(path):
        bak = path + '.bak'
        try:
            shutil.copy2(path, bak)
        except Exception:
            pass  # best-effort backup
    try:
        fd, tmp = tempfile.mkstemp(dir=dir_path, suffix='.tmp')
        with os.fdopen(fd, 'w') as f:
            json.dump(data, f, indent=2, sort_keys=True)
        os.rename(tmp, path)
    except Exception:
        logger.exception(f"Atomic write failed for {path}")
        # Try to clean up temp
        try:
            os.unlink(tmp)
        except Exception:
            pass
        raise


def save_state(target, state_dict):
    """Atomically save the issues-state.json."""
    _atomic_write_json(_state_path(target), state_dict)


# ---------------------------------------------------------------------------
# Correlate step — the main pipeline hook
# ---------------------------------------------------------------------------

def correlate(target, scan_id, computed_issues, state=None):
    """Run the INV-2 merge: computed issues + stored state → merged issues + updated state.

    Returns:
        merged: list of full Issue dicts (computed + state overlay)
        new_state: the updated state dict (caller should save)
        events: list of timeline events emitted
    """
    now = datetime.utcnow().isoformat(timespec='seconds') + 'Z'
    if state is None:
        state = load_state(target)

    computed_refs = {i['ref'] for i in computed_issues}
    computed_map = {i['ref']: i for i in computed_issues}
    events = []

    # 1. Process each computed issue
    for ci in computed_issues:
        ref = ci['ref']
        if ref in state:
            # Existing — update detections, last_seen
            st = state[ref]
            st['detections'] = st.get('detections', 0) + 1
            st['last_seen_rev'] = scan_id
            st['last_seen_at'] = now
            # Actively re-checked this scan and still present -> verified open.
            st['last_verified_rev'] = scan_id
            st['last_verified_at'] = now
            # Clear orphan flag if reattaching
            if st.get('orphaned_at'):
                del st['orphaned_at']
            # Evidence returned after an auto-resolve → RESURFACED, a distinct,
            # louder state than a first-time finding (a regression you thought
            # you'd fixed). See ISSUES_DASHBOARD.RESEARCH.md §3a. Global event
            # kind stays 'issue_reopened' so the timeline label map is unchanged.
            if st.get('status') == 'resolved':
                st['status'] = 'resurfaced'
                st['history'].append({'at': now, 'event': 'resurfaced', 'by': 'system'})
                events.append({'kind': 'issue_reopened', 'ref': ref, 'rev': scan_id, 'at': now})
        else:
            # New issue
            state[ref] = {
                'status': 'open',
                'first_seen_rev': scan_id,
                'first_seen_at': now,
                'last_seen_rev': scan_id,
                'last_seen_at': now,
                'last_verified_rev': scan_id,
                'last_verified_at': now,
                'detections': 1,
                'assignee': None,
                'history': [{'at': now, 'event': 'created', 'by': 'system'}],
            }
            events.append({'kind': 'issue_created', 'ref': ref, 'rev': scan_id, 'at': now,
                           'detail': {'title': ci.get('title', ''), 'severity': ci.get('severity', '')}})

    # 2. Auto-resolve: open issues NOT in computed set (but not false_positive/accepted_risk — INV-2)
    human_statuses = {'false_positive', 'accepted_risk'}
    for ref, st in state.items():
        if ref not in computed_refs:
            if st.get('status') in ('open', 'acknowledged', 'in_progress', 'resurfaced'):
                st['status'] = 'resolved'
                # Actively re-checked this scan and no longer present -> verified fixed.
                st['last_verified_rev'] = scan_id
                st['last_verified_at'] = now
                st['resolved_rev'] = scan_id
                st.setdefault('history', []).append({'at': now, 'event': 'auto_resolved', 'by': 'system'})
                events.append({'kind': 'issue_auto_resolved', 'ref': ref, 'rev': scan_id, 'at': now})
            elif st.get('status') not in human_statuses and not st.get('orphaned_at'):
                # Tombstone orphans (rule removed/edited) — never delete
                st['orphaned_at'] = now

    # 3. Merge computed + state → full issues
    merged = []
    for ci in computed_issues:
        ref = ci['ref']
        st = state.get(ref, {})
        full = dict(ci)
        full['status'] = st.get('status', 'open')
        full['first_seen_rev'] = st.get('first_seen_rev', scan_id)
        full['first_seen_at'] = st.get('first_seen_at', now)
        full['last_seen_rev'] = st.get('last_seen_rev', scan_id)
        full['last_seen_at'] = st.get('last_seen_at', now)
        full['last_verified_rev'] = st.get('last_verified_rev', st.get('last_seen_rev', scan_id))
        full['last_verified_at'] = st.get('last_verified_at', st.get('last_seen_at', now))
        full['detections'] = st.get('detections', 1)
        full['assignee'] = st.get('assignee')
        full['history'] = st.get('history', [])
        merged.append(full)

    # Also include non-orphaned resolved/state-only issues so they show in history
    for ref, st in state.items():
        if ref not in computed_refs and st.get('status') in ('resolved', 'false_positive', 'accepted_risk') and not st.get('orphaned_at'):
            # Create a minimal Issue for display
            merged.append({
                'ref': ref, 'rule_id': 'unknown', 'title': f'Resolved issue {ref}',
                'severity': 'info', 'risk_score': 0, 'risk_inputs': [],
                'summary_md': 'This issue was auto-resolved (evidence no longer detected).',
                'evidence_chain': [], 'evidence': [], 'affected_assets': [], 'vuln_refs': [],
                'remediation_md': '',
                'status': st['status'],
                'first_seen_rev': st.get('first_seen_rev', ''),
                'first_seen_at': st.get('first_seen_at', ''),
                'last_seen_rev': st.get('last_seen_rev', ''),
                'last_seen_at': st.get('last_seen_at', ''),
                'detections': st.get('detections', 0),
                'assignee': st.get('assignee'),
                'history': st.get('history', []),
            })

    return merged, state, events


# ---------------------------------------------------------------------------
# Timeline — events.jsonl (append-only, idempotent)
# ---------------------------------------------------------------------------

def _load_existing_event_keys(target):
    """Load existing event identity keys for idempotent append."""
    path = _events_path(target)
    keys = set()
    if not os.path.exists(path):
        return keys
    try:
        with open(path) as f:
            for line in f:
                try:
                    ev = json.loads(line)
                    keys.add((ev.get('rev', ''), ev.get('kind', ''), ev.get('ref', '')))
                except Exception:
                    continue
    except Exception:
        pass
    return keys


def append_events(target, events, rev=None):
    """Append events to events.jsonl, deduping on (rev, kind, ref)."""
    if not events:
        return
    existing = _load_existing_event_keys(target)
    path = _events_path(target)
    new_lines = []
    for ev in events:
        r = ev.get('rev', rev or '')
        key = (r, ev.get('kind', ''), ev.get('ref', ''))
        if key in existing:
            continue
        existing.add(key)
        ev['rev'] = r
        new_lines.append(json.dumps(ev, separators=(',', ':'), sort_keys=True))
    if new_lines:
        with open(path, 'a') as f:
            for line in new_lines:
                f.write(line + '\n')


def load_events(target, kind=None, limit=200):
    """Load timeline events, newest first."""
    path = _events_path(target)
    if not os.path.exists(path):
        return []
    events = []
    try:
        with open(path) as f:
            for line in f:
                try:
                    ev = json.loads(line)
                    if kind and ev.get('kind') != kind:
                        continue
                    events.append(ev)
                except Exception:
                    continue
    except Exception:
        pass
    events.reverse()  # newest first
    return events[:limit]


# ---------------------------------------------------------------------------
# Revision differ — emits timeline events from two scans
# ---------------------------------------------------------------------------

def diff_revisions(current_entities, previous_entities, scan_id, prev_scan_id):
    """Diff two entity indexes and emit timeline events."""
    now = datetime.utcnow().isoformat(timespec='seconds') + 'Z'
    curr_refs = {e['ref']: e for e in current_entities}
    prev_refs = {e['ref']: e for e in previous_entities}
    events = []

    # New entities
    for ref in sorted(set(curr_refs) - set(prev_refs)):
        e = curr_refs[ref]
        kind_map = {'sub': 'new_subdomain', 'host': 'new_ip', 'svc': 'port_opened', 'vuln': 'new_vuln_match'}
        kind = kind_map.get(e['type'])
        if kind:
            events.append({
                'kind': kind, 'ref': ref, 'rev': scan_id, 'from_rev': prev_scan_id, 'at': now,
                'detail': {'label': e.get('label', ''), 'type': e['type']},
            })

    # Removed entities
    for ref in sorted(set(prev_refs) - set(curr_refs)):
        e = prev_refs[ref]
        kind_map = {'sub': 'subdomain_gone', 'host': 'ip_gone', 'svc': 'port_closed'}
        kind = kind_map.get(e['type'])
        if kind:
            events.append({
                'kind': kind, 'ref': ref, 'rev': scan_id, 'from_rev': prev_scan_id, 'at': now,
                'detail': {'label': e.get('label', ''), 'type': e['type']},
            })

    # Service changes (same ref, different attrs)
    for ref in sorted(set(curr_refs) & set(prev_refs)):
        if curr_refs[ref]['type'] != 'svc':
            continue
        ca = curr_refs[ref]['attrs']
        pa = prev_refs[ref]['attrs']
        if ca.get('product') != pa.get('product') or ca.get('version') != pa.get('version'):
            events.append({
                'kind': 'service_changed', 'ref': ref, 'rev': scan_id, 'from_rev': prev_scan_id, 'at': now,
                'detail': {
                    'label': curr_refs[ref].get('label', ''),
                    'was': f"{pa.get('product','')} {pa.get('version','')}".strip(),
                    'now': f"{ca.get('product','')} {ca.get('version','')}".strip(),
                },
            })

    return events


# ---------------------------------------------------------------------------
# Field coverage audit (Phase 0 deliverable)
# ---------------------------------------------------------------------------

RULE_FIELD_REQUIREMENTS = {
    'exposed-service': ['svc.port', 'host.ip'],
    'dev-staging-exposed': ['sub.fqdn', 'sub.resolved'],
    'missing-headers': ['sub.has_webapp', 'sub.security_header_score', 'sub.missing_headers'],
    'leaked-secret': ['vuln.source=Secret Scan'],
    'hsts-gap': ['vuln.source=HSTS Audit'],
    'mcp-ai-exposure': ['vuln.source=MCP/AI Probe'],
    'new-asset': ['sub.fqdn', 'sub.resolved'],
    'no-waf': ['sub.has_webapp', 'sub.waf_vendor'],
    'compounding-risk': ['host.ip', 'svc.port', 'sub.waf_vendor', 'sub.security_header_score', 'vuln.severity'],
    # Future rules (❓ pending audit)
    'subdomain-takeover': ['sub.cname_chain', 'sub.dangling'],
    'expired-cert': ['cert.not_after', 'cert.self_signed'],
    'known-exploited-vuln': ['vuln.cve_id', 'vuln.kev'],
    'eol-software': ['tech.product', 'tech.version', 'tech.eol_date'],
}


def audit_field_coverage(entities):
    """Produce field-coverage.json: which fields exist in the data."""
    coverage = {}
    for field_spec in set(f for reqs in RULE_FIELD_REQUIREMENTS.values() for f in reqs):
        parts = field_spec.split('.')
        etype = parts[0]
        if '=' in parts[-1]:
            fname, expected = parts[-1].split('=', 1)
        else:
            fname = parts[-1] if len(parts) > 1 else ''
            expected = None

        matching = [e for e in entities if e['type'] == etype]
        if not matching:
            coverage[field_spec] = {'present_pct': 0, 'sample_values': [], 'count': 0}
            continue

        if expected:
            hits = [e for e in matching if str(e.get('attrs', {}).get(fname, '')) == expected]
        elif fname:
            hits = [e for e in matching if e.get('attrs', {}).get(fname) is not None]
        else:
            hits = matching

        pct = round(len(hits) / len(matching) * 100, 1) if matching else 0
        samples = []
        for e in hits[:3]:
            v = e.get('attrs', {}).get(fname) if fname else e.get('label', '')
            samples.append(str(v)[:80] if v is not None else '')
        coverage[field_spec] = {'present_pct': pct, 'sample_values': samples, 'count': len(hits)}

    # Rule readiness
    rule_status = {}
    for rule_id, fields in RULE_FIELD_REQUIREMENTS.items():
        missing = [f for f in fields if coverage.get(f, {}).get('present_pct', 0) == 0]
        rule_status[rule_id] = {
            'ready': len(missing) == 0,
            'missing_fields': missing,
            'enabled': rule_id in ALL_RULES and len(missing) == 0,
        }

    return {'fields': coverage, 'rules': rule_status}


# ---------------------------------------------------------------------------
# Issue enrichment — exploitability-first ranking signals (ISSUES_DASHBOARD.RESEARCH.md)
#
# Additive and purely COMPUTED (INV-2): attaches KEV / EPSS / L0-L6 confidence /
# SLA clock / blended priority to each merged issue every scan. Never persisted.
# ---------------------------------------------------------------------------
import re as _re

try:
    import evidence.arise_evidence as _evi
except Exception:  # pragma: no cover - ladder is optional at import time
    _evi = None

_CVE_RE = _re.compile(r'CVE-\d{4}-\d{3,7}', _re.I)

# Intrinsic evidence rung per rule — the L0-L6 strength of what each rule PROVES
# (arise_evidence ladder: L0 observed … L3 security-differential … L4 authz-
# violation = first CONFIRMED rung … L5 impact-demonstrated … L6 reproduced).
# CONFIRMED (L4+) is reserved for affirmatively-verified exposures; heuristics,
# inferences and passive observations stay POTENTIAL (≤L3) until proven — which
# is the honest, noise-reducing default (ISSUES_DASHBOARD.RESEARCH.md §1b/§4).
_RULE_RUNG = {
    'exposed-service':     'L4',  # sensitive service reachable from the internet — affirmatively verified exposure
    'leaked-secret':       'L5',  # a secret actually retrieved from a public resource — impact shown
    'dev-staging-exposed': 'L1',  # name-pattern inference, not proven sensitive
    'missing-headers':     'L3',  # config differential, directly measured but low-impact
    'hsts-gap':            'L3',  # MITM-relevant config differential, directly measured
    'mcp-ai-exposure':     'L3',  # measured AI/MCP exposure; unauth handshake findings climb via their own confidence
    'no-waf':              'L1',  # absence → risk is an inference
    'new-asset':           'L0',  # merely new
    'compounding-risk':    'L3',  # correlation; climbs to L4 only via a confirmed backing finding
}
_DEFAULT_RUNG = 'L3'

# Blended-priority inputs (0-100). Severity is the FLOOR; KEV + confirmed +
# public-exposure + EPSS drive the rank (CISA BOD 26-04 signal order).
_SEV_PRIORITY_BASE = {'critical': 70, 'high': 55, 'medium': 35, 'low': 18, 'info': 6}
# Per-severity remediation SLA, in hours (KEV/critical 72h → low 90d).
_SLA_HOURS = {'critical': 72, 'high': 168, 'medium': 720, 'low': 2160, 'info': 4320}
# Statuses that still count as "needs work" (resurfaced is active and louder).
ACTIVE_STATUSES = {'open', 'acknowledged', 'in_progress', 'resurfaced'}


def _issue_cves(issue, entity_map):
    """CVE ids referenced by an issue — from its vuln entities + a text fallback."""
    cves = set()
    for vr in issue.get('vuln_refs') or []:
        ent = entity_map.get(vr)
        if ent:
            cid = (ent.get('attrs') or {}).get('cve_id')
            if cid:
                cves.add(str(cid).upper())
    blob = ' '.join([issue.get('title', ''), issue.get('summary_md', '')])
    for m in _CVE_RE.findall(blob):
        cves.add(m.upper())
    return sorted(cves)


def _issue_rung(issue, entity_map):
    """L0-L6 evidence rung for an issue: the rule's intrinsic rung, climbed by
    strong provenance on any backing vuln entity (scanner/offensive = confirmed)."""
    rung = _RULE_RUNG.get(issue.get('rule_id'), _DEFAULT_RUNG)
    if _evi is None:
        return rung
    try:
        for vr in issue.get('vuln_refs') or []:
            ent = entity_map.get(vr) or {}
            for p in (ent.get('provenance') or []):
                pc = _evi.provenance_of(str(p))
                if _evi.provenance_weight(pc) >= 0.9:
                    rung = _evi.climb(rung, 'L4')
    except Exception:
        pass
    return rung


def _sla_state(issue):
    """SLA clock: age vs per-severity policy → met / on_track / due_soon / breached."""
    policy = _SLA_HOURS.get(issue.get('severity', 'info'), 2160)
    age_h = 0.0
    fs = issue.get('first_seen_at') or ''
    try:
        t0 = datetime.fromisoformat(fs.replace('Z', ''))
        age_h = (datetime.utcnow() - t0).total_seconds() / 3600.0
    except Exception:
        age_h = 0.0
    if issue.get('status') not in ACTIVE_STATUSES:
        state = 'met'
    elif age_h > policy:
        state = 'breached'
    elif age_h > policy * 0.8:
        state = 'due_soon'
    else:
        state = 'on_track'
    return {'policy_hours': policy, 'age_hours': round(age_h, 1),
            'remaining_hours': round(policy - age_h, 1), 'state': state}


def enrich_issues(issues, entities, scan_id, kev_set=None, epss_map=None):
    """Attach kev / epss / cves / rung / confidence / exposure / is_new /
    is_resurfaced / sla / priority to each issue in place. Returns the list."""
    kev_set = kev_set or set()
    epss_map = epss_map or {}
    entity_map = {e.get('ref'): e for e in (entities or [])}
    for i in issues:
        cves = _issue_cves(i, entity_map)
        i['cves'] = cves
        i['kev'] = any(c in kev_set for c in cves)
        eps = [epss_map[c] for c in cves if c in epss_map]
        i['epss'] = round(max(eps), 4) if eps else None

        rung = _issue_rung(i, entity_map)
        i['rung'] = rung
        if _evi is not None:
            try:
                i['rung_name'] = _evi.ladder_meta(rung).get('name', '')
                i['confidence'] = 'confirmed' if _evi.is_confirmed(rung) else 'potential'
            except Exception:
                i['rung_name'] = ''
                i['confidence'] = 'potential'
        else:
            i['rung_name'] = ''
            i['confidence'] = 'confirmed' if (i.get('evidence')) else 'potential'

        ri = ' '.join(i.get('risk_inputs') or [])
        i['exposure'] = ('public' if 'exposure=public' in ri
                         else 'internal' if 'exposure=internal' in ri else 'unknown')
        i['is_new'] = (i.get('first_seen_rev') == scan_id)
        i['is_resurfaced'] = (i.get('status') == 'resurfaced'
                              or any(h.get('event') in ('reopened', 'resurfaced')
                                     for h in (i.get('history') or [])))
        i['sla'] = _sla_state(i)

        p = _SEV_PRIORITY_BASE.get(i.get('severity', 'info'), 6)
        if i['kev']:
            p += 25
        if i['confidence'] == 'confirmed':
            p += 12
        if i['exposure'] == 'public':
            p += 10
        if i['epss']:
            p += i['epss'] * 20
        if i['sla']['state'] == 'breached':
            p += 6
        i['priority'] = round(min(p, 100.0), 1)
    return issues


def issue_summary(issues, scan_id):
    """Header-ribbon roll-up: KEV-exposed, SLA-breached, trend (new vs resolved),
    confirmed/potential split, MTTR — the numbers a CISO reports upward."""
    active = [i for i in issues if i.get('status') in ACTIVE_STATUSES]
    by_sev = {}
    for i in active:
        s = i.get('severity', 'info')
        by_sev[s] = by_sev.get(s, 0) + 1
    new_count = sum(1 for i in active if i.get('first_seen_rev') == scan_id)
    # "resolved this scan" = verified-fixed in the current revision.
    resolved_now = sum(1 for i in issues
                       if i.get('status') == 'resolved' and i.get('last_verified_rev') == scan_id)
    confirmed = sum(1 for i in active if i.get('confidence') == 'confirmed')
    spans = []
    for i in issues:
        if i.get('status') == 'resolved' and i.get('first_seen_at') and i.get('last_verified_at'):
            try:
                a = datetime.fromisoformat(i['first_seen_at'].replace('Z', ''))
                b = datetime.fromisoformat(i['last_verified_at'].replace('Z', ''))
                spans.append((b - a).total_seconds() / 86400.0)
            except Exception:
                pass
    return {
        'open_by_severity': by_sev,
        'kev_exposed': sum(1 for i in active if i.get('kev')),
        'sla_breached': sum(1 for i in active if (i.get('sla') or {}).get('state') == 'breached'),
        'sla_due_soon': sum(1 for i in active if (i.get('sla') or {}).get('state') == 'due_soon'),
        'new': new_count,
        'resolved': resolved_now,
        'net': new_count - resolved_now,
        'confirmed': confirmed,
        'potential': len(active) - confirmed,
        'mttr_days': round(sum(spans) / len(spans), 1) if spans else None,
        'active_total': len(active),
    }


# ---------------------------------------------------------------------------
# Self-test — risk scoring (F14) + compounding-risk (F28), ARISE_REMEDIATION_ROADMAP.md
# ---------------------------------------------------------------------------
def _selftest() -> int:
    # -- _risk_score bounds and severity ordering --
    assert _risk_score('critical') > _risk_score('high') > _risk_score('medium') \
        > _risk_score('low') > _risk_score('info')
    assert _risk_score('critical', 5.0) <= 10.0, "must cap at 10"
    assert _risk_score('info', 0.01) >= 0.5, "must floor at 0.5"
    print("[1] _risk_score: bounded, severity-ordered  ✓")

    # -- missing-headers: continuous scaling, not a binary split --
    def sub_entity(ref, fqdn, **attrs):
        return {'ref': ref, 'type': 'sub', 'label': fqdn, 'attrs': {'fqdn': fqdn, **attrs}}

    e0 = sub_entity('sub:a', 'zero.example.com', has_webapp=True,
                    security_header_score=0, missing_headers=['strict-transport-security'])
    e3 = sub_entity('sub:b', 'three.example.com', has_webapp=True,
                    security_header_score=3, missing_headers=['strict-transport-security'])
    r0 = rule_missing_security_headers([e0], [])
    r3 = rule_missing_security_headers([e3], [])
    assert r0 and r3, "both should fire (both below the 4/6 threshold)"
    assert r0[0]['risk_score'] > r3[0]['risk_score'], \
        "0/6 headers must score higher than 3/6 — was a flat binary split before this fix"
    print("[2] missing-headers: continuous scaling with header count  ✓")

    # -- leaked-secret: trusts the detector's own severity, doesn't force critical --
    def vuln_entity(ref, source, severity, host='h.example.com', url=''):
        return {'ref': ref, 'type': 'vuln', 'label': ref,
               'attrs': {'source': source, 'template': 'Generic Secret Pattern',
                        'severity': severity, 'host': host, 'url': url}}

    v_med = vuln_entity('vuln:1', 'Secret Scan', 'medium')
    v_crit = vuln_entity('vuln:2', 'Secret Scan', 'critical')
    out_med = rule_leaked_secrets([v_med], [])
    out_crit = rule_leaked_secrets([v_crit], [])
    assert out_med[0]['severity'] == 'medium', \
        f"expected the detector's own 'medium' preserved, got {out_med[0]['severity']}"
    assert out_med[0]['risk_score'] < out_crit[0]['risk_score'], \
        "a medium-severity secret must not score the same as a critical one"
    print("[3] leaked-secret: real severity preserved, not force-promoted to critical  ✓")

    # -- compounding-risk: fires ONLY on convergence (2+ factors), not one alone --
    host_e = {'ref': 'host:h1', 'type': 'host', 'label': '10.0.0.1', 'attrs': {'ip': '10.0.0.1', 'ports': [6379]}}
    svc_e = {'ref': 'svc:s1', 'type': 'svc', 'label': '6379/tcp redis',
            'attrs': {'port': 6379, 'proto': 'tcp', 'product': 'redis'}}
    sub_one_factor = sub_entity('sub:c1', 'db.example.com', has_webapp=False, waf_vendor='Cloudflare')
    rel_one = [
        {'source': 'host:h1', 'target': 'svc:s1', 'type': 'RUNS'},
        {'source': 'sub:c1', 'target': 'host:h1', 'type': 'RESOLVES_TO'},
    ]
    one_factor_issues = rule_compounding_risk([host_e, svc_e, sub_one_factor], rel_one)
    assert not one_factor_issues, \
        f"exposed service ALONE (1 factor) must not fire compounding-risk, got {one_factor_issues}"

    sub_two_factor = sub_entity('sub:c2', 'db2.example.com', has_webapp=True, waf_vendor='none')
    rel_two = [
        {'source': 'host:h1', 'target': 'svc:s1', 'type': 'RUNS'},
        {'source': 'sub:c2', 'target': 'host:h1', 'type': 'RESOLVES_TO'},
    ]
    two_factor_issues = rule_compounding_risk([host_e, svc_e, sub_two_factor], rel_two)
    assert len(two_factor_issues) == 1, \
        f"exposed service + no-WAF webapp (2 factors) must converge into one issue, got {two_factor_issues}"
    assert two_factor_issues[0]['severity'] == 'high'
    print("[4] compounding-risk: fires only on real convergence (2+ factors), not a single signal  ✓")

    # -- run_rules: new rule is registered and doesn't crash the pipeline --
    all_entities = [host_e, svc_e, sub_two_factor]
    computed = run_rules(all_entities, rel_two)
    assert any(i['rule_id'] == 'compounding-risk' for i in computed)
    print("[5] run_rules: compounding-risk registered in ALL_RULES and executes cleanly  ✓")

    print("\nkaiju_issues risk-scoring self-test: ALL PASS")
    return 0


if __name__ == '__main__':
    import sys as _sys_main
    _sys_main.exit(_selftest())
