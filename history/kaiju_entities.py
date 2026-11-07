#!/usr/bin/env python3
"""
KAIJU Entity Index — INV-1 compliant entity resolution.

Builds a typed entity graph from raw scan JSON.  Every entity ref
``type:id`` derives its ``id`` from a **natural-key hash** (never from
array position, discovery order, or scan timestamp).  Recomputing the
same scan twice MUST yield byte-identical refs.

Entity types:
    domain, sub, host, svc, tech, vuln, cert

Entity ref format:
    {type}:{sha1(natural_key)[:10]}
"""

import sys as _sys, os as _os
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)


import hashlib
import json
import os
import logging

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# INV-1: stable ref derivation
# ---------------------------------------------------------------------------

def _ref(etype, natural_key):
    """Derive a stable, deterministic entity ref from a natural key."""
    digest = hashlib.sha1(natural_key.encode('utf-8')).hexdigest()[:10]
    return f"{etype}:{digest}"


def _domain_ref(domain):
    return _ref('domain', domain.lower().strip('.'))


def _sub_ref(fqdn):
    return _ref('sub', fqdn.lower().strip('.'))


def _host_ref(ip):
    """Host identity = IP address (decision: IP, not subdomain-anchored)."""
    return _ref('host', ip.strip())


def _svc_ref(host_ip, port, proto='tcp'):
    return _ref('svc', f"{host_ip}:{port}/{proto}")


def _tech_ref(product, version=''):
    return _ref('tech', f"{product.lower().strip()}:{version.strip()}")


def _vuln_ref(template_id, host_key):
    """template_id = nuclei template-id, or source+template for others."""
    return _ref('vuln', f"{template_id}:{host_key}")


def _cert_ref(cn, not_after=''):
    return _ref('cert', f"{cn}:{not_after}")


# ---------------------------------------------------------------------------
# Entity builder — scan JSON → entity index
# ---------------------------------------------------------------------------

def build_entity_index(scan_data, scan_id=None):
    """Build a list of typed entities from a get_scan_data() result.

    Returns:
        entities: list of dicts, each with 'ref', 'type', 'label', 'attrs', 'provenance'
        relations: list of dicts, each with 'source', 'target', 'type'
    """
    entities = {}   # ref → entity dict
    relations = []  # list of {source, target, type}

    target = scan_data.get('pipeline_info', {}).get('target', '')
    hosts_data = scan_data.get('hosts', {})
    services_data = scan_data.get('services', {})
    vulns = scan_data.get('vulnerabilities', [])
    stats = scan_data.get('statistics', {})

    if not target:
        return [], []

    # --- Domain (root) ---
    domain_r = _domain_ref(target)
    entities[domain_r] = {
        'ref': domain_r, 'type': 'domain', 'label': target,
        'attrs': {'target': target, 'total_hosts': stats.get('total_hosts', 0)},
        'provenance': ['pipeline'],
    }

    seen_ips = {}       # ip → host_ref
    seen_techs = {}     # (product,ver) → tech_ref
    seen_vulns = set()

    for fqdn, hd in sorted(hosts_data.items()):
        # --- Subdomain ---
        sub_r = _sub_ref(fqdn)
        entities[sub_r] = {
            'ref': sub_r, 'type': 'sub', 'label': fqdn,
            'attrs': {
                'fqdn': fqdn,
                'resolved': hd.get('resolved', False),
                'source': hd.get('source', ''),
                'http_status': hd.get('http_status'),
                'has_webapp': hd.get('has_webapp', False),
                'cdn': hd.get('cdn', False),
                'waf_vendor': hd.get('waf_vendor'),
                'security_header_score': hd.get('security_header_score'),
                'missing_headers': hd.get('missing_headers', []),
                'risk_score': hd.get('risk_score', 0),
                'risk_band': hd.get('risk_band', 'low'),
            },
            'provenance': [hd.get('source', 'subdomain_enum')],
        }
        relations.append({'source': domain_r, 'target': sub_r, 'type': 'HAS_SUB'})

        # --- Host (IP) ---
        ip = hd.get('ip')
        if ip:
            host_r = _host_ref(ip)
            if ip not in seen_ips:
                seen_ips[ip] = host_r
                entities[host_r] = {
                    'ref': host_r, 'type': 'host', 'label': ip,
                    'attrs': {'ip': ip, 'ports': sorted(set(int(p) for p in hd.get('ports_open', [])))},
                    'provenance': ['dns_resolution'],
                }
            else:
                # merge ports
                existing = entities[seen_ips[ip]]
                existing_ports = set(existing['attrs'].get('ports', []))
                new_ports = set(int(p) for p in hd.get('ports_open', []))
                existing['attrs']['ports'] = sorted(existing_ports | new_ports)

            relations.append({'source': sub_r, 'target': host_r, 'type': 'RESOLVES_TO'})

            # --- Services on this host ---
            host_services = services_data.get(fqdn, [])
            for svc in host_services:
                port = svc.get('port')
                proto = svc.get('protocol', 'tcp')
                if not port:
                    continue
                svc_r = _svc_ref(ip, port, proto)
                if svc_r not in entities:
                    product = svc.get('product', '') or svc.get('name', '')
                    version = svc.get('version', '')
                    cpe_list = svc.get('cpe', [])
                    entities[svc_r] = {
                        'ref': svc_r, 'type': 'svc', 'label': f"{port}/{proto} {product}".strip(),
                        'attrs': {
                            'port': port, 'proto': proto, 'name': svc.get('name', ''),
                            'product': product, 'version': version,
                            'cpe': cpe_list, 'tunnel': svc.get('tunnel', ''),
                            'service_type': svc.get('service_type', ''),
                        },
                        'provenance': ['service_fingerprint'],
                    }
                relations.append({'source': host_r, 'target': svc_r, 'type': 'RUNS'})

                # --- Technology (from service fingerprint) ---
                if product:
                    tech_key = (product.lower(), version)
                    if tech_key not in seen_techs:
                        tech_r = _tech_ref(product, version)
                        seen_techs[tech_key] = tech_r
                        entities[tech_r] = {
                            'ref': tech_r, 'type': 'tech', 'label': f"{product} {version}".strip(),
                            'attrs': {
                                'product': product, 'version': version,
                                'cpe': cpe_list,
                            },
                            'provenance': ['service_fingerprint'],
                        }
                    relations.append({'source': svc_r, 'target': seen_techs[tech_key], 'type': 'USES'})

    # --- Vulnerabilities ---
    for v in vulns:
        source = v.get('source', 'Unknown')
        template = v.get('template', 'Unknown')
        template_id = v.get('template_id', '') or f"{source}:{template}"
        host = v.get('host', 'Unknown')
        severity = v.get('severity', 'info')
        url = v.get('url', '')

        vr = _vuln_ref(template_id, host)
        if vr in seen_vulns:
            continue
        seen_vulns.add(vr)

        entities[vr] = {
            'ref': vr, 'type': 'vuln', 'label': template,
            'attrs': {
                'source': source, 'template': template, 'template_id': template_id,
                'severity': severity, 'host': host, 'url': url,
                'impact': v.get('impact', ''),
                'remediation': v.get('remediation', ''),
                'cve_id': v.get('cve_id'),
                'cwe_id': v.get('cwe_id', []),
            },
            'provenance': [source.lower().replace(' ', '_')],
        }
        # Link vuln to the subdomain it was found on
        sub_r = _sub_ref(host)
        if sub_r in entities:
            relations.append({'source': vr, 'target': sub_r, 'type': 'AFFECTS'})

    entity_list = sorted(entities.values(), key=lambda e: (e['type'], e['ref']))
    relations_sorted = sorted(relations, key=lambda r: (r['source'], r['target'], r['type']))
    return entity_list, relations_sorted


# ---------------------------------------------------------------------------
# Persistence — .derived/ cache
# ---------------------------------------------------------------------------

def cache_path(scan_dir):
    return os.path.join(scan_dir, '.derived')


# Bump whenever build_entity_index()'s attrs/entity-type semantics change (a
# new attr a rule now reads, a new entity source, etc.) — every scan's cache
# was unversioned before this and, with no bump, is trusted FOREVER with no
# staleness check at all: a scan cached before a rule change silently never
# picks it up until someone deletes .derived/entities.json by hand. Bumping
# this makes every existing scan's stale cache self-invalidate on next read,
# with no manual cleanup needed. (v2: added the hsts-gap rule's dependency on
# 'vuln' entities carrying HSTS Audit findings, via the pre-existing generic
# vulnerabilities loop — no entity-schema change, but the CACHED data for any
# scan viewed before that fix predates it.)
# (v3: added the mcp-ai-exposure rule's dependency on 'vuln' entities carrying
# 'MCP/AI Probe' findings (Module 8D), same generic-loop path as HSTS.)
ENTITY_CACHE_VERSION = 3


def save_entity_index(scan_dir, entities, relations):
    """Cache the entity index to .derived/entities.json (regenerable)."""
    derived = cache_path(scan_dir)
    os.makedirs(derived, exist_ok=True)
    data = {'version': ENTITY_CACHE_VERSION, 'entities': entities, 'relations': relations}
    path = os.path.join(derived, 'entities.json')
    with open(path, 'w') as f:
        json.dump(data, f, separators=(',', ':'), sort_keys=True)
    return path


def load_entity_index(scan_dir):
    """Load cached entity index, or (None, None) if not cached OR the cache
    predates the current ENTITY_CACHE_VERSION (forces a fresh rebuild)."""
    path = os.path.join(cache_path(scan_dir), 'entities.json')
    if not os.path.exists(path):
        return None, None
    try:
        with open(path) as f:
            data = json.load(f)
        if data.get('version') != ENTITY_CACHE_VERSION:
            return None, None
        return data.get('entities', []), data.get('relations', [])
    except Exception:
        return None, None


# ---------------------------------------------------------------------------
# Lookup helpers
# ---------------------------------------------------------------------------

def entities_by_type(entities, etype):
    return [e for e in entities if e.get('type') == etype]


def entity_by_ref(entities, ref):
    for e in entities:
        if e.get('ref') == ref:
            return e
    return None


def related(relations, ref, hops=1):
    """Return all entities within N hops of ref."""
    visited = {ref}
    frontier = {ref}
    matched_rels = []
    for _ in range(hops):
        next_frontier = set()
        for r in relations:
            if r['source'] in frontier:
                next_frontier.add(r['target'])
                matched_rels.append(r)
            elif r['target'] in frontier:
                next_frontier.add(r['source'])
                matched_rels.append(r)
        next_frontier -= visited
        visited |= next_frontier
        frontier = next_frontier
    return visited, matched_rels
