#!/usr/bin/env python3
"""
ARISE — Unified Evidence & Identity Graph  (attack_chain_v2.ROADMAP.md Phase 1)
================================================================================
One graph, replacing three independent implementations that grew up separately
in this codebase: capec_attack_paths.py's own load_host_graph()/same_asset(),
kaiju_entities.py's domain->sub->host->svc->tech->vuln entity/relation graph,
and arise_autonomous.KnowledgeGraph's ad-hoc seed_from_context(). This module
extends the third (it already has to_dict()/compact() — a token-bounded text
view built specifically to hand to an LLM) rather than inventing a fourth.

Every source this pipeline produces gets ONE normalizer function here, each
emitting nodes/edges into the SAME graph with a real evidence rung (L0-L6,
evidence/arise_evidence.py) computed once at ingestion — not re-invented per
consumer, which is exactly the duplication ARISE_REMEDIATION_ROADMAP.md's
Cluster A/C already diagnosed.

Node types : host, endpoint, finding, credential, cloud-asset, identity, target
Edge types : RESOLVES_TO, RUNS, USES, AFFECTS (kaiju_entities.py's vocabulary,
             reused verbatim, not renamed) + ROUTES_TO (host -> endpoint) +
             SAME_ASSET (host <-> host sharing an IP; capec_attack_paths.py's
             own fail-safe-not-open same_asset() check, unchanged).

Usage:
    python3 intel/evidence_graph.py <scan_dir> [--summary]
"""
from __future__ import annotations

import sys as _sys, os as _os
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)

import argparse
import hashlib
import json
import re
import sys
from typing import Optional

from core.knowledge_graph import KnowledgeGraph
from evidence.arise_evidence import ladder_rank, is_confirmed  # noqa: F401 (public re-export)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _iter_jsonl(path):
    try:
        with open(path, errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        yield json.loads(line)
                    except Exception:
                        continue
    except OSError:
        return


def _short_hash(*parts: str) -> str:
    h = hashlib.sha1("|".join(str(p) for p in parts).encode("utf-8", "ignore"))
    return h.hexdigest()[:10]


def _host_only(url_or_host: str) -> str:
    """Best-effort host extraction from a URL or a bare hostname — never a
    port suffix (the exact class of bug fixed elsewhere in this pipeline for
    httpx's host:port targeting; the same discipline applies here)."""
    if not url_or_host:
        return ""
    s = str(url_or_host).strip()
    s = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", s)   # strip scheme
    s = s.split("/", 1)[0]                              # strip path
    s = s.split("@")[-1]                                # strip userinfo
    s = s.rsplit(":", 1)[0] if s.count(":") == 1 and not s.startswith("[") else s
    return s.strip(". ").lower()


def _finding_label(host: str, kind: str, discriminator: str = "") -> str:
    """A finding node's label must stay unique per real finding but readable —
    two hosts with the same check name must NOT collide into one node
    (KnowledgeGraph.add_node merges attrs into an existing id if the label
    matches). Keying on host+kind+a short hash of the discriminator (url,
    evidence, or template) keeps genuinely-identical findings deduped while
    keeping distinct ones apart."""
    disc = _short_hash(discriminator or kind)
    return f"{host or 'unknown-host'} | {kind} | {disc}"


def _norm_host(host: str) -> str:
    """Case-fold every host used as a graph key. Sources vary in casing (some
    tools emit 'API.zepto.com', manifest.json is consistently lowercase) —
    without this, the same real host could silently split into two node ids
    that never merge, which would quietly break same-asset grounding for
    exactly the hosts it matters most for. Centralized here rather than
    fixed per call site so no normalizer can forget it."""
    return (host or "").strip().lower()


def _host_node(kg: KnowledgeGraph, host: str, **attrs) -> Optional[str]:
    host = _norm_host(host)
    if not host:
        return None
    return kg.add_node("host", host, **attrs)


def _finding_node(kg: KnowledgeGraph, host: str, kind: str, rung: str,
                  discriminator: str = "", **attrs) -> str:
    host = _norm_host(host)
    label = _finding_label(host, kind, discriminator)
    fid = kg.add_node("finding", label, host=host, kind=kind, rung=rung,
                      confirmed=is_confirmed(rung), **attrs)
    if host:
        hn = _host_node(kg, host)
        kg.add_edge(hn, "AFFECTS", fid)
    return fid


def _endpoint_node(kg: KnowledgeGraph, host: str, url: str, **attrs) -> Optional[str]:
    if not url:
        return None
    host = _norm_host(host)
    en = kg.add_node("endpoint", url, host=host, **attrs)
    if host:
        hn = _host_node(kg, host)
        kg.add_edge(hn, "ROUTES_TO", en)
    return en


# ---------------------------------------------------------------------------
# Rung inference — each source reports confidence differently; this maps each
# one's own vocabulary onto the shared L0-L6 ladder. Conservative by design:
# when uncertain, rate LOWER, matching the fail-safe-not-open discipline
# already used by same_asset() elsewhere in this codebase. A source that
# already stamps a real rung (api_logic_leads.jsonl) is read directly, never
# re-derived.
# ---------------------------------------------------------------------------

def _rung_from_confidence(confidence: str, default: str = "L1") -> str:
    c = (confidence or "").strip().lower()
    if c in ("exploited", "confirmed"):
        return "L5"
    if c in ("multi-tool", "corroborated"):
        return "L4"
    if c in ("single-tool", "high"):
        return "L3"
    if c in ("medium",):
        return "L2"
    if c in ("low", "unknown", ""):
        return default
    return default


# ---------------------------------------------------------------------------
# Per-source normalizers — one per real schema audited against live scan data
# (zepto.com-250926-0237, x.razorpay.com-240926-2121, onequince.com-*).
# Each returns the number of finding/endpoint nodes it added.
# ---------------------------------------------------------------------------

def add_dns_security(scan_dir: str, kg: KnowledgeGraph) -> int:
    path = _os.path.join(scan_dir, "03c_dns_security", "dns_security_findings.jsonl")
    n = 0
    for r in _iter_jsonl(path):
        host = r.get("host", "")
        sev = (r.get("severity") or "low").lower()
        # A takeover_candidate flag baked into a DNS-security record is a much
        # stronger signal than the check's own base severity suggests.
        rung = "L3" if r.get("takeover_candidate") else {"critical": "L2", "high": "L2"}.get(sev, "L1")
        _finding_node(kg, host, r.get("check", "dns_security"), rung,
                     discriminator=r.get("evidence", ""), severity=sev,
                     template=r.get("template", ""), evidence=r.get("evidence", ""),
                     remediation=r.get("remediation", ""), source_module="dns_security_audit")
        n += 1
    return n


def add_subdomain_takeover(scan_dir: str, kg: KnowledgeGraph) -> int:
    path = _os.path.join(scan_dir, "21_subdomain_takeover", "takeover_findings.jsonl")
    n = 0
    for r in _iter_jsonl(path):
        host = r.get("host", "")
        basis = ((r.get("meta") or {}).get("basis") or "").lower()
        # Corroborated (published CNAME pattern match + body marker) is a real
        # confirmed hop; marker-only rests on one weaker signal.
        rung = "L4" if basis == "corroborated" else "L2"
        _finding_node(kg, host, "subdomain_takeover", rung,
                     discriminator=host, severity="critical",
                     service=(r.get("meta") or {}).get("service", ""),
                     source_module="subdomain_takeover")
        n += 1
    return n


def add_waf_detection(scan_dir: str, kg: KnowledgeGraph) -> int:
    path = _os.path.join(scan_dir, "05_waf_detection", "waf_detections.jsonl")
    n = 0
    for r in _iter_jsonl(path):
        host = _host_only(r.get("host") or r.get("url", ""))
        if not host:
            continue
        _host_node(kg, host, waf_vendor=r.get("waf_vendor", ""),
                  catchall_detected=bool(r.get("catchall_detected")))
        n += 1
    return n


def add_header_analysis(scan_dir: str, kg: KnowledgeGraph) -> int:
    path = _os.path.join(scan_dir, "06_header_analysis", "header_findings.jsonl")
    n = 0
    for r in _iter_jsonl(path):
        host = _host_only(r.get("host") or r.get("url", ""))
        score = r.get("security_header_score")
        if score is None:
            continue
        _host_node(kg, host, security_header_score=score,
                  missing_headers=r.get("missing_headers") or [])
        # A real, chainable weak-headers finding only when the score is low
        # enough to matter — a bare host attribute would otherwise flood the
        # graph with a "finding" for every host regardless of severity.
        if isinstance(score, (int, float)) and score <= 2:
            _finding_node(kg, host, "weak_security_headers", "L1",
                         discriminator=str(sorted(r.get("missing_headers") or [])),
                         missing_headers=r.get("missing_headers") or [],
                         source_module="header_analysis")
            n += 1
    return n


def add_hrs_topology(scan_dir: str, kg: KnowledgeGraph) -> int:
    path = _os.path.join(scan_dir, "08c_hrs_detect", "hrs_findings.jsonl")
    n = 0
    for r in _iter_jsonl(path):
        host = _host_only(r.get("url", ""))
        if not host:
            continue
        _host_node(kg, host, cdn=bool(r.get("cdn")), cdn_name=r.get("cdn_name", ""),
                  waf=bool(r.get("waf")), api_gateway=bool(r.get("api_gateway")),
                  webserver=r.get("webserver", ""))
        n += 1
    return n


def add_url_inventory(scan_dir: str, kg: KnowledgeGraph) -> int:
    """The real classified endpoint map — sensitivity/auth_state/accepts_file/
    cloud_bucket/routed_to — reduced by the pre-redesign chain builder to two
    booleans. Every endpoint becomes a real graph node here, not a statistic."""
    path = _os.path.join(scan_dir, "08_directory_discovery", "discovered_endpoints.jsonl")
    n = 0
    for r in _iter_jsonl(path):
        host = r.get("host", "")
        url = r.get("url", "")
        if not url:
            continue
        _endpoint_node(kg, host, url,
                      url_class=r.get("url_class", ""), api_type=r.get("api_type"),
                      sensitivity=r.get("sensitivity", "normal"),
                      auth_state=r.get("auth_state", "unknown"),
                      accepts_file=bool(r.get("accepts_file")),
                      cloud_provider=r.get("cloud_provider"),
                      cloud_bucket=r.get("cloud_bucket"),
                      input_function=r.get("input_function"),
                      routed_to=r.get("routed_to") or [],
                      verified=bool(r.get("verified")),
                      blocked_by_waf=bool(r.get("blocked_by_waf")))
        n += 1
    return n


def add_api_security(scan_dir: str, kg: KnowledgeGraph) -> int:
    n = 0
    # promoted_vulnerabilities.jsonl — apisec.py, confidence is single/multi-tool.
    for r in _iter_jsonl(_os.path.join(scan_dir, "16_api_security", "promoted_vulnerabilities.jsonl")):
        host = r.get("host", "")
        rung = _rung_from_confidence(r.get("confidence"), default="L2")
        _finding_node(kg, host, r.get("issue_class", "api_security"), rung,
                     discriminator=r.get("url", ""), severity=r.get("severity", ""),
                     template=r.get("template", ""), url=r.get("url", ""),
                     impact=r.get("impact", ""), remediation=r.get("remediation", ""),
                     tools=r.get("tools") or [], source_module="api_security")
        n += 1
    # api_logic_leads.jsonl — already stamped with a real rung; read it directly,
    # never re-derive (this is the one source that already does this correctly).
    for r in _iter_jsonl(_os.path.join(scan_dir, "24_api_attack", "api_logic_leads.jsonl")):
        host = r.get("host", "") or (r.get("hosts") or [""])[0]
        rung = r.get("rung") or "L2"
        _finding_node(kg, host, r.get("category", "api_logic"), rung,
                     discriminator=r.get("endpoint", ""), severity=r.get("severity", ""),
                     title=r.get("title", ""), endpoint=r.get("endpoint", ""),
                     evidence=r.get("evidence") or [], confirmed_flag=bool(r.get("confirmed")),
                     needs_active_confirmation=bool(r.get("needs_active_confirmation")),
                     remediation="; ".join(r.get("suggested_checks") or []),
                     source_module="api_logic_analysis")
        n += 1
    return n


def add_cloud_exposure(scan_dir: str, kg: KnowledgeGraph) -> int:
    """The real scored findings (weighted_score = base_weight x exploitability
    x exposure) — the pre-redesign chain builder only ever checked whether
    17_cloud_exposure/ existed as a directory, never read this file."""
    path = _os.path.join(scan_dir, "17_cloud_exposure", "cloud_findings.jsonl")
    n = 0
    for r in _iter_jsonl(path):
        host = _host_only(r.get("host") or r.get("url", ""))
        sev = (r.get("severity") or "low").lower()
        score = r.get("weighted_score") or 0
        rung = "L3" if score >= 30 else "L2" if score >= 10 else "L1"
        _finding_node(kg, host, r.get("cloud_category", "cloud_exposure"), rung,
                     discriminator=r.get("evidence", ""), severity=sev,
                     weighted_score=score, evidence=r.get("evidence", ""),
                     remediation=r.get("remediation", ""), url=r.get("url", ""),
                     source_module="cloud_exposure")
        n += 1
    return n


def add_offensive_verify(scan_dir: str, kg: KnowledgeGraph) -> int:
    """Differentially-confirmed active exploits (JWT, GraphQL, SSTI, SSRF,
    race conditions, ...) — the highest-confidence source in the pipeline and,
    before this redesign, entirely invisible to the chain builder."""
    path = _os.path.join(scan_dir, "24_advanced_attacks", "offensive_findings.jsonl")
    n = 0
    for r in _iter_jsonl(path):
        host = r.get("host", "")
        rung = _rung_from_confidence(r.get("confidence"), default="L4")
        _finding_node(kg, host, r.get("module", "offensive_verify"), rung,
                     discriminator=r.get("payload", "") + r.get("parameter", ""),
                     severity=r.get("severity", ""), title=r.get("title", ""),
                     url=r.get("url", ""), evidence=r.get("evidence", ""),
                     verification=r.get("verification", ""),
                     request_line=r.get("request_line", ""),
                     payload=r.get("payload", ""), remediation=r.get("remediation", ""),
                     source_module="offensive_verify")
        n += 1
    return n


def add_osint(scan_dir: str, kg: KnowledgeGraph) -> int:
    path = _os.path.join(scan_dir, "18_osint_intel", "osint_findings.jsonl")
    n = 0
    for r in _iter_jsonl(path):
        subject = r.get("subject", "")
        rung = _rung_from_confidence(r.get("confidence"), default="L1")
        # OSINT subjects are often look-alike domains, not the target's own
        # hosts — model them as their own host node rather than forcing them
        # onto the scanned estate, so downstream host-grounding stays correct.
        _finding_node(kg, subject, r.get("category", "osint"), rung,
                     discriminator=r.get("title", ""), severity=r.get("severity", ""),
                     title=r.get("title", ""), evidence=r.get("evidence", ""),
                     risk=r.get("risk", ""), remediation=r.get("recommendation", ""),
                     source_module="osint_intel")
        n += 1
    return n


def add_shodan(scan_dir: str, kg: KnowledgeGraph) -> int:
    path = _os.path.join(scan_dir, "22_shodan_correlation", "shodan_assets.jsonl")
    n = 0
    for r in _iter_jsonl(path):
        for host in (r.get("hostnames") or []) or [r.get("ip", "")]:
            if not host:
                continue
            _host_node(kg, host, ip=r.get("ip", ""), provider=r.get("provider", ""),
                      asn=r.get("asn", ""), shodan_ports=r.get("shodan_ports") or [])
            n += 1
    return n


def add_identity_graph(scan_dir: str, kg: KnowledgeGraph) -> int:
    """bola_candidates fires from URL-shape pattern matching alone — present
    even with zero HAR/gray-box input, confirmed live on a real black-box scan."""
    path = _os.path.join(scan_dir, "00_har_ingest", "identity_graph.json")
    if not _os.path.exists(path):
        return 0
    try:
        with open(path, errors="ignore") as f:
            data = json.load(f)
    except Exception:
        return 0
    n = 0
    for c in data.get("bola_candidates") or []:
        host = c.get("host", "")
        idn = kg.add_node("identity", f"{host}:{c.get('path', '')}",
                          host=host, url=c.get("url", ""),
                          auth_state=c.get("auth_state", "unknown"))
        _finding_node(kg, host, "bola_candidate", "L1",
                     discriminator=c.get("path", ""), url=c.get("url", ""),
                     methods=c.get("methods") or [], source_module="identity_graph")
        hn = _host_node(kg, host)
        kg.add_edge(hn, "USES", idn)
        n += 1
    return n


def add_response_intel(scan_dir: str, kg: KnowledgeGraph) -> int:
    """Already pre-tagged with a real CAPEC id in several categories — the
    pre-redesign chain builder needed zero inference for these and still
    never read them."""
    path = _os.path.join(scan_dir, "26_response_intel", "response_findings_deduped.jsonl")
    n = 0
    for r in _iter_jsonl(path):
        host = r.get("host", "")
        rung = _rung_from_confidence(r.get("confidence"), default="L2")
        _finding_node(kg, host, r.get("type", "response_intel"), rung,
                     discriminator=r.get("url", ""), severity=r.get("severity", ""),
                     category=r.get("category", ""), capec=r.get("capec"),
                     cwe=r.get("cwe"), url=r.get("url", ""),
                     evidence=r.get("evidence", ""), source_module="response_intel")
        n += 1
    return n


def add_adaptive_loop(scan_dir: str, kg: KnowledgeGraph) -> int:
    path = _os.path.join(scan_dir, "27_adaptive_loop", "loop_findings.jsonl")
    n = 0
    for r in _iter_jsonl(path):
        info = r.get("info") or {}
        host = r.get("host", "")
        rung = "L4"  # adaptive_loop findings are oracle-gated (0% FP by design)
        _finding_node(kg, host, info.get("name", "adaptive_loop"), rung,
                     discriminator=r.get("matched-at", ""), severity=info.get("severity", ""),
                     matched_at=r.get("matched-at", ""), source_module="adaptive_loop")
        n += 1
    return n


def add_nuclei(scan_dir: str, kg: KnowledgeGraph) -> int:
    """Kept even though it's currently near-empty on live scans (audited: zero
    hits across every Sept 2026 scan) — for when it does fire, and for older
    scans where it does."""
    n = 0
    for rel in ("12_nuclei_scanning/nuclei_results.txt",
               "12_nuclei_scanning/synth_results.txt",
               "12_nuclei_scanning/full_results.txt",
               "12_nuclei_scanning/nuclei_nonweb_findings.jsonl"):
        for r in _iter_jsonl(_os.path.join(scan_dir, rel)):
            info = r.get("info") or {}
            host = r.get("host", "")
            cls = info.get("classification") or {}
            cve = cls.get("cve-id") or cls.get("cve_id")
            rung = "L3" if (r.get("matcher-name") or info.get("severity") in ("critical", "high")) else "L2"
            _finding_node(kg, host, r.get("template-id", "nuclei"), rung,
                         discriminator=r.get("matched-at", ""),
                         severity=info.get("severity", ""), name=info.get("name", ""),
                         cve_id=cve if isinstance(cve, str) else (cve[0] if cve else None),
                         matched_at=r.get("matched-at", ""), source_module="nuclei")
            n += 1
    return n


_XSS_POC_RE = re.compile(r"\[POC\]\[(?P<kind>[RS])\]\[(?P<method>\w+)\]\[(?P<ctx>\w+)\]\s+(?P<url>\S+)")


def add_xss_text(scan_dir: str, kg: KnowledgeGraph) -> int:
    """xss_results.txt is plain text, not JSON — every other module in this
    pipeline emits JSONL; this one and sqli's don't, confirmed by direct read
    of real output. A dedicated parser is required, not a JSON key-mapper."""
    path = _os.path.join(scan_dir, "13_xss_testing", "xss_results.txt")
    n = 0
    try:
        with open(path, errors="ignore") as f:
            lines = f.readlines()
    except OSError:
        return 0
    for line in lines:
        m = _XSS_POC_RE.search(line.strip())
        if not m:
            continue
        url = m.group("url")
        host = _host_only(url)
        # [S]tored XSS demonstrates persistent impact; [R]eflected is a real
        # PoC but session-bound to the request that triggered it.
        rung = "L4" if m.group("kind") == "S" else "L3"
        _finding_node(kg, host, "xss", rung, discriminator=url,
                     severity="high", method=m.group("method"),
                     context=m.group("ctx"), url=url, source_module="xss_testing")
        n += 1
    return n


def add_sqli(scan_dir: str, kg: KnowledgeGraph) -> int:
    """sqli output is JSONL when present, but audited real scans show it's
    usually empty; kept for when a target actually has a finding here, mixed
    format handled defensively (a bad line is just skipped by _iter_jsonl)."""
    n = 0
    for rel in ("15_sqli_testing/sqli_results.jsonl", "20.1_api_sqli_testing/sqli_results.jsonl"):
        for r in _iter_jsonl(_os.path.join(scan_dir, rel)):
            host = r.get("host") or _host_only(r.get("url", ""))
            rung = _rung_from_confidence(r.get("confidence"), default="L4")
            _finding_node(kg, host, "sqli", rung, discriminator=r.get("url", ""),
                         severity="critical", url=r.get("url", ""),
                         evidence=r.get("evidence", ""), source_module="sqli_testing")
            n += 1
    return n


def add_host_identity(scan_dir: str, kg: KnowledgeGraph) -> int:
    """Seeds host nodes + SAME_ASSET edges from manifest.json's hosts{} — the
    same host->IP data capec_attack_paths.py's own load_host_graph() reads,
    now built once, here, for every consumer instead of being reimplemented
    per file."""
    manifest_path = _os.path.join(scan_dir, "manifest.json")
    try:
        with open(manifest_path, errors="ignore") as f:
            manifest = json.load(f)
    except Exception:
        return 0
    hosts = manifest.get("hosts") or {}
    ip_to_hosts: dict = {}
    n = 0
    for host, hd in hosts.items():
        host = (host or "").strip().lower()
        if not host or ":" in host:  # defensive: never a host:port literal
            continue
        ip = (hd or {}).get("ip") or ""
        _host_node(kg, host, ip=ip, waf_vendor=(hd or {}).get("waf_vendor", ""),
                  http_status=(hd or {}).get("http_status"),
                  has_webapp=bool((hd or {}).get("has_webapp")))
        if ip:
            ip_to_hosts.setdefault(ip, []).append(host)
        n += 1
    for ip, group in ip_to_hosts.items():
        if len(group) < 2:
            continue
        for i, a in enumerate(group):
            for b in group[i + 1:]:
                kg.add_edge(_host_node(kg, a), "SAME_ASSET", _host_node(kg, b))
    return n


# ---------------------------------------------------------------------------
# Assembly
# ---------------------------------------------------------------------------

# Order matters only for readability of --summary output; graph construction
# itself is commutative (add_node/add_edge are idempotent-by-id).
_NORMALIZERS = [
    ("host_identity", add_host_identity),
    ("url_inventory", add_url_inventory),
    ("dns_security", add_dns_security),
    ("subdomain_takeover", add_subdomain_takeover),
    ("waf_detection", add_waf_detection),
    ("header_analysis", add_header_analysis),
    ("hrs_topology", add_hrs_topology),
    ("api_security", add_api_security),
    ("cloud_exposure", add_cloud_exposure),
    ("offensive_verify", add_offensive_verify),
    ("osint", add_osint),
    ("shodan", add_shodan),
    ("identity_graph", add_identity_graph),
    ("response_intel", add_response_intel),
    ("adaptive_loop", add_adaptive_loop),
    ("nuclei", add_nuclei),
    ("xss", add_xss_text),
    ("sqli", add_sqli),
]


def host_ip_graph(kg: KnowledgeGraph) -> "tuple[dict, dict]":
    """(fqdn_to_ip, ip_to_fqdns) derived from the unified graph's host nodes —
    the same shape capec_attack_paths.py's own load_host_graph() returns, so
    that function can delegate here instead of re-reading manifest.json
    independently. Only hosts with a real, non-empty ip attr participate —
    an OSINT look-alike domain or a bare DNS-security subject modeled as a
    host node never carries one, so it naturally can't corrupt same-asset
    grounding for the target's real infrastructure."""
    fqdn_to_ip: dict = {}
    ip_to_fqdns: dict = {}
    for node in kg.nodes.values():
        if node.get("type") != "host":
            continue
        host = node.get("label", "")
        ip = (node.get("attrs") or {}).get("ip") or ""
        if not host or not ip:
            continue
        fqdn_to_ip[host] = ip
        ip_to_fqdns.setdefault(ip, set()).add(host)
    return fqdn_to_ip, ip_to_fqdns


def build_graph(scan_dir: str) -> "tuple[KnowledgeGraph, dict]":
    """Build the unified graph for one scan. Never raises: a normalizer that
    fails is recorded as an error in the returned counts, not a crash of the
    whole pass — the same fail-open-on-errors, fail-safe-on-security-checks
    split already used throughout this codebase."""
    kg = KnowledgeGraph()
    counts: dict = {}
    for name, fn in _NORMALIZERS:
        try:
            counts[name] = fn(scan_dir, kg)
        except Exception as exc:  # noqa: BLE001 — one bad source must not sink the graph
            counts[name] = f"ERROR: {exc}"
    return kg, counts


def main() -> int:
    ap = argparse.ArgumentParser(description="Unified Evidence & Identity Graph (Phase 1)")
    ap.add_argument("scan_dir")
    ap.add_argument("--summary", action="store_true")
    ap.add_argument("--out", help="write the graph JSON here (default: <scan_dir>/25_attack_paths/evidence_graph.json)")
    args = ap.parse_args()

    if not _os.path.isdir(args.scan_dir):
        print(f"error: not a directory: {args.scan_dir}", file=sys.stderr)
        return 2

    kg, counts = build_graph(args.scan_dir)
    out_path = args.out or _os.path.join(args.scan_dir, "25_attack_paths", "evidence_graph.json")
    _os.makedirs(_os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(kg.to_dict(), f, indent=2)

    if args.summary:
        print(f"[evidence_graph] wrote {out_path}", file=sys.stderr)
        print(f"[evidence_graph] {json.dumps(kg.summary())}", file=sys.stderr)
        print(f"[evidence_graph] per-source counts: {json.dumps(counts)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
