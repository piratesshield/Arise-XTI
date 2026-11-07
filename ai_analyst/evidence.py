"""
AriseAI — EASM evidence loader.

Reads a completed EASM scan directory into one normalized evidence model the
agent brain reasons over. Self-contained (does not depend on the half-built
chain_v2 graph); every source is parsed defensively and a missing/garbled file
is skipped, never fatal.

Two products:
  * Evidence.items        — a flat, normalized list of everything found, each
                            classified to a canonical vuln_class, severity, and a
                            `proven` flag (live exploit evidence upstream vs. a
                            mere observation).
  * Evidence.dossier()    — a compact, token-bounded snapshot for the LLM: the
                            target, attack-surface shape, proven findings,
                            observations, BOLA candidates, CVEs, and prior chains.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ai_analyst.constants import PROVEN_CONFIDENCE, sev_rank

_CDN_INFRA_PATH_RE = re.compile(
    r"(?:^|/)(?:cdn-cgi|__cf_|_cf_chl|challenge-platform|"
    r"_bx_html|akamai|_Incapsula_Resource)", re.I)


def _is_cdn_infra(url: str) -> bool:
    return bool(_CDN_INFRA_PATH_RE.search(url))


# ---------------------------------------------------------------------------
# Normalized item
# ---------------------------------------------------------------------------
@dataclass
class EvidenceItem:
    kind: str                  # "finding" | "endpoint" | "bola" | "asset" | "chain"
    vuln_class: str
    title: str
    severity: str
    host: str = ""
    url: str = ""
    parameter: str = ""
    confidence: str = ""
    proven: bool = False
    source: str = ""           # which EASM module produced it
    evidence: str = ""
    remediation: str = ""
    category: str = ""
    raw: Dict[str, Any] = field(default_factory=dict)

    def slim(self) -> Dict[str, Any]:
        """Compact form for the LLM prompt — drops heavy raw payloads."""
        d = {
            "class": self.vuln_class,
            "title": self.title[:160],
            "severity": self.severity,
            "host": self.host,
            "url": self.url[:200],
            "source": self.source,
        }
        if self.parameter:
            d["param"] = self.parameter
        if self.proven:
            d["proven"] = True
        if self.confidence:
            d["confidence"] = self.confidence
        if self.evidence:
            d["evidence"] = self.evidence[:280]
        return d


# ---------------------------------------------------------------------------
# Classification — map any source's wording to one canonical vuln class
# ---------------------------------------------------------------------------
_CLASS_RULES = [
    (r"\bssrf\b|metadata|169\.254|computeMetadata", "ssrf"),
    (r"\bbola\b|object.?level.?auth|\bidor\b", "bola"),
    (r"\bbfla\b|function.?level.?auth", "bfla"),
    (r"\bsqli?\b|sql.?inject", "sqli"),
    (r"nosql", "nosqli"),
    (r"\bxss\b|cross.?site.?script", "xss"),
    (r"\bssti\b|template.?inject", "ssti"),
    (r"\bxxe\b|xml.?external", "xxe"),
    (r"\brce\b|remote.?code|command.?inject", "rce"),
    (r"\blfi\b|path.?travers|directory.?travers|file.?inclusion", "lfi"),
    (r"\bcrlf\b|header.?inject|response.?split", "crlf"),
    (r"open.?redirect|unvalidated.?redirect", "redirect"),
    (r"prototype.?pollut", "proto"),
    (r"cache.?poison|cache.?deception", "cache"),
    (r"race.?condition|toctou", "race"),
    (r"graphql", "graphql"),
    (r"request.?smuggl|desync", "crlf"),
    (r"\bjwt\b|json.?web.?token|algorithm.?confusion", "jwt"),
    (r"auth.?bypass|broken.?auth|weak.?session|password.?reset|mfa", "auth-bypass"),
    (r"\bcors\b|cross.?origin", "cors"),
    (r"subdomain.?takeover|dangling|takeover", "takeover"),
    (r"secret|credential|api.?key|access.?key|token.?leak|password", "secret-exposure"),
    (r"\bpii\b|personal.?data|email.?leak|phone", "info-disclosure"),
    (r"stack.?trace|debug|verbose.?error|disclosure|exposed|listing", "info-disclosure"),
    (r"\bcve-\d{4}", "cve"),
    (r"misconfig|default.?cred|security.?header|hsts|tls|cipher", "misconfig"),
    (r"business.?logic|workflow|price|quantity", "business_logic"),
    (r"websocket|\bwss?\b|cswsh", "ws"),
]
_CLASS_RE = [(re.compile(pat, re.IGNORECASE), cls) for pat, cls in _CLASS_RULES]


def classify(*blobs: str, default: str = "info-disclosure") -> str:
    text = " ".join(b for b in blobs if b)
    for rx, cls in _CLASS_RE:
        if rx.search(text):
            return cls
    return default


def _is_proven(confidence: str, source: str = "") -> bool:
    if (confidence or "").lower() in PROVEN_CONFIDENCE:
        return True
    # offensive_verify only ever writes differentially-confirmed findings.
    return "offensive_verify" in (source or "").lower()


# ---------------------------------------------------------------------------
# Small IO helpers (never raise)
# ---------------------------------------------------------------------------
def _read_jsonl(path: str, cap: int = 5000) -> List[dict]:
    out = []
    try:
        with open(path, "r", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except Exception:
                    continue
                if len(out) >= cap:
                    break
    except Exception:
        pass
    return out


def _read_json(path: str, default=None):
    try:
        with open(path, "r", errors="replace") as fh:
            return json.load(fh)
    except Exception:
        return default


def _read_lines(path: str, cap: int = 2000) -> List[str]:
    try:
        with open(path, "r", errors="replace") as fh:
            return [ln.rstrip("\n") for ln in fh][:cap]
    except Exception:
        return []


# ---------------------------------------------------------------------------
# Evidence container
# ---------------------------------------------------------------------------
@dataclass
class Evidence:
    scan_dir: str
    target: str
    items: List[EvidenceItem] = field(default_factory=list)
    endpoints: List[dict] = field(default_factory=list)
    bola_candidates: List[dict] = field(default_factory=list)
    prior_chains: List[dict] = field(default_factory=list)
    hosts: List[str] = field(default_factory=list)
    stats: Dict[str, Any] = field(default_factory=dict)
    # Recon context (Modules 3-9, 14, 18) — grounds the brain against real infra.
    technologies: Dict[str, List[str]] = field(default_factory=dict)
    waf_map: Dict[str, str] = field(default_factory=dict)
    services: List[dict] = field(default_factory=list)
    open_ports: Dict[str, List[int]] = field(default_factory=dict)
    dns_records: List[dict] = field(default_factory=list)
    osint: List[dict] = field(default_factory=list)

    @property
    def proven(self) -> List[EvidenceItem]:
        return [i for i in self.items if i.proven]

    @property
    def observations(self) -> List[EvidenceItem]:
        return [i for i in self.items if not i.proven]

    def cves(self) -> List[str]:
        rx = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
        seen = []
        for it in self.items:
            for m in rx.findall(f"{it.title} {it.evidence} {it.category}"):
                cid = m.upper()
                if cid not in seen:
                    seen.append(cid)
        return seen[:40]

    # --- interesting attack surface -------------------------------------
    def interesting_endpoints(self, cap: int = 40) -> List[dict]:
        """Endpoints a pentester would probe first: auth, object-ref, upload,
        admin, redirect, search, and API routes — with their observed shape."""
        want = {"login", "auth", "admin", "upload", "object-ref", "idor",
                "redirect", "search", "api", "graphql", "payment", "account"}
        picked = []
        for ep in self.endpoints:
            uc = (ep.get("url_class") or "").lower()
            interesting = (uc in want
                           or ep.get("accepts_file")
                           or ep.get("api_type")
                           or (ep.get("query_variants") and uc not in ("static", "asset")))
            if not interesting:
                continue
            picked.append({
                "url": (ep.get("sample_url") or ep.get("url") or "")[:200],
                "class": uc or "unknown",
                "method": ep.get("method") or (ep.get("methods") or ["GET"])[0],
                "auth": ep.get("auth_state") or "unknown",
                "params": (ep.get("query_variants") or list((ep.get("query") or {}).keys()))[:8],
                "accepts_file": bool(ep.get("accepts_file")),
                "api": ep.get("api_type") or "",
            })
            if len(picked) >= cap:
                break
        return picked

    # --- compact snapshot for the LLM -----------------------------------
    def dossier(self, max_proven: int = 30, max_obs: int = 25) -> Dict[str, Any]:
        proven = sorted(self.proven, key=lambda i: sev_rank(i.severity), reverse=True)
        obs = sorted(self.observations, key=lambda i: sev_rank(i.severity), reverse=True)
        d: Dict[str, Any] = {
            "target": self.target,
            "scan_dir": os.path.basename(self.scan_dir),
            "attack_surface": {
                "hosts": len(self.hosts),
                "endpoints": len(self.endpoints),
                "proven_findings": len(proven),
                "observations": len(obs),
                "bola_candidates": len(self.bola_candidates),
            },
            "proven_findings": [i.slim() for i in proven[:max_proven]],
            "observations": [i.slim() for i in obs[:max_obs]],
            "interesting_endpoints": self.interesting_endpoints(),
            "bola_candidates": self.bola_candidates[:12],
            "cves": self.cves(),
            "prior_chains": [
                {"name": c.get("name") or c.get("chain_id") or c.get("title"),
                 "hosts": c.get("target_hosts") or c.get("hosts"),
                 "summary": (c.get("summary") or c.get("why") or c.get("goal") or "")[:200]}
                for c in self.prior_chains[:10]
            ],
        }
        recon = self._recon_context()
        if recon:
            d["recon_context"] = recon
        return d

    def _recon_context(self) -> Dict[str, Any]:
        """Recon-stage context the brain needs to ground hypotheses against real
        infrastructure — tech stacks, WAFs, ports, services, OSINT signals."""
        ctx: Dict[str, Any] = {}
        if self.technologies:
            ctx["technologies"] = {h: ts[:10] for h, ts in list(self.technologies.items())[:30]}
        if self.waf_map:
            ctx["waf_protected_hosts"] = dict(list(self.waf_map.items())[:30])
        if self.services:
            ctx["non_http_services"] = self.services[:20]
        if self.open_ports:
            interesting = {h: ps for h, ps in self.open_ports.items()
                          if any(p not in (80, 443) for p in ps)}
            if interesting:
                ctx["interesting_ports"] = dict(list(interesting.items())[:20])
        if self.osint:
            ctx["osint_signals"] = [
                {"category": o.get("category"), "title": o.get("title", "")[:120],
                 "severity": o.get("severity"), "subject": o.get("subject", "")[:80]}
                for o in self.osint[:15]
            ]
        return ctx


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------
def load_evidence(scan_dir: str, target: Optional[str] = None) -> Evidence:
    """Parse a scan dir into an Evidence model. Never raises."""
    scan_dir = str(scan_dir)
    tgt = target or _infer_target(scan_dir)
    ev = Evidence(scan_dir=scan_dir, target=tgt)

    def J(*parts):  # path join
        return os.path.join(scan_dir, *parts)

    # 1) offensive_verify — differentially confirmed exploits (the gold).
    for r in _read_jsonl(J("24_advanced_attacks", "offensive_findings.jsonl")):
        if _is_cdn_infra(r.get("url", "")):
            continue
        # Filter WAF-tainted findings: if both baseline and attack returned 403/503,
        # the "differential" is WAF noise, not a real finding.
        baseline = r.get("baseline") or {}
        attack = r.get("attack") or {}
        b_st = baseline.get("status", 0)
        a_st = attack.get("status", 0)
        if b_st in (403, 503) and a_st in (403, 503):
            continue
        cls = (r.get("check") or r.get("category") or "").lower() or classify(
            r.get("title", ""), r.get("category", ""))
        ev.items.append(EvidenceItem(
            kind="finding", vuln_class=_norm_class(cls),
            title=r.get("title") or r.get("template") or "offensive finding",
            severity=r.get("severity", "info"), host=r.get("host", ""),
            url=r.get("url", ""), parameter=r.get("parameter", ""),
            confidence=r.get("confidence", "confirmed"),
            proven=_is_proven(r.get("confidence"), "offensive_verify"),
            source="offensive_verify", evidence=r.get("evidence") or r.get("impact") or "",
            remediation=r.get("remediation", ""), category=r.get("category", ""), raw=r))

    # 2) API security — promoted (already 2+-tool / live-verified) vulns.
    for r in _read_jsonl(J("16_api_security", "promoted_vulnerabilities.jsonl")):
        if _is_cdn_infra(r.get("url") or r.get("path", "")):
            continue
        cls = classify(r.get("issue_class", ""), r.get("category", ""), r.get("template", ""))
        ev.items.append(EvidenceItem(
            kind="finding", vuln_class=cls,
            title=r.get("template") or r.get("issue_class") or "API finding",
            severity=r.get("severity", "info"), host=r.get("host", ""),
            url=r.get("url") or r.get("path", ""), parameter="",
            confidence=r.get("confidence", ""),
            proven=_is_proven(r.get("confidence"), r.get("source", "")),
            source="api_security", evidence=r.get("impact", ""),
            remediation=r.get("remediation", ""), category=r.get("issue_class", ""), raw=r))

    # 3) Cloud exposure — scored misconfig / exposure.
    for r in _read_jsonl(J("17_cloud_exposure", "cloud_findings.jsonl")):
        cls = classify(r.get("cloud_category", ""), r.get("template", ""), r.get("evidence", ""),
                       default="misconfig")
        ev.items.append(EvidenceItem(
            kind="finding", vuln_class=cls,
            title=r.get("template") or r.get("category_label") or "cloud exposure",
            severity=r.get("severity", "info"), host=r.get("host", ""),
            url=r.get("url", ""), confidence="",
            proven=False, source="cloud_exposure", evidence=r.get("evidence", ""),
            remediation=r.get("remediation", ""), category=r.get("cloud_category", ""), raw=r))

    # 4) Response intel — already CAPEC/CWE tagged info-disclosure/leaks.
    for r in _read_jsonl(J("26_response_intel", "response_findings_deduped.jsonl")):
        cls = classify(r.get("type", ""), r.get("category", ""), default="info-disclosure")
        ev.items.append(EvidenceItem(
            kind="finding", vuln_class=cls,
            title=r.get("type") or r.get("category") or "response finding",
            severity=r.get("severity", "info"), host=r.get("host", ""),
            url=r.get("url", ""), confidence=r.get("confidence", ""),
            proven=_is_proven(r.get("confidence"), "response_intel"),
            source="response_intel", evidence=r.get("evidence") or r.get("response_snippet", ""),
            remediation=r.get("remediation", ""),
            category=r.get("category", "") or (r.get("capec") or ""), raw=r))

    # 5) Secrets — exposed credentials (high-value observations/leads).
    for cand in ("10_secret_scanning/secrets.jsonl", "10_secret_scanning/nlp_findings.jsonl"):
        for r in _read_jsonl(J(cand)):
            ev.items.append(EvidenceItem(
                kind="finding", vuln_class="secret-exposure",
                title=r.get("detector") or r.get("type") or r.get("rule") or "secret exposed",
                severity=r.get("severity", "high") if r.get("verified") else r.get("severity", "medium"),
                host=r.get("host", ""), url=r.get("url") or r.get("file", ""),
                confidence="verified" if r.get("verified") else "",
                proven=bool(r.get("verified")), source="secret_scan",
                evidence=(r.get("evidence") or r.get("raw") or r.get("match") or "")[:200],
                category="secret", raw=r))

    # 6) DNS security + subdomain takeover.
    for r in _read_jsonl(J("03c_dns_security", "dns_security_findings.jsonl")):
        ev.items.append(EvidenceItem(
            kind="finding", vuln_class=classify(r.get("type", ""), r.get("title", ""), default="misconfig"),
            title=r.get("title") or r.get("type") or "DNS issue",
            severity=r.get("severity", "low"), host=r.get("host") or r.get("domain", ""),
            source="dns_security", evidence=r.get("evidence") or r.get("detail", ""),
            remediation=r.get("remediation", ""), raw=r))
    for r in _read_jsonl(J("21_subdomain_takeover", "takeover_findings.jsonl")):
        ev.items.append(EvidenceItem(
            kind="finding", vuln_class="takeover",
            title="Subdomain takeover candidate",
            severity=r.get("severity", "high"), host=r.get("host") or r.get("subdomain", ""),
            confidence=r.get("confidence", ""), proven=_is_proven(r.get("confidence")),
            source="subdomain_takeover", evidence=r.get("evidence") or r.get("service", ""), raw=r))

    # 7) XSS / SQLi PoC-line formats ([POC][R][GET][sink] <url>).
    _poc_rx = re.compile(r"\[POC\]\[(\w+)\]\[(\w+)\]\[(\w+)\]\s*(.+)")
    for sub, cls in (("13_xss_testing/xss_results.txt", "xss"),
                     ("15_sqli_testing/sqli_results.jsonl", "sqli")):
        for ln in _read_lines(J(sub)):
            m = _poc_rx.search(ln)
            if not m:
                # sqli jsonl may also hold json objects
                try:
                    r = json.loads(ln)
                    if isinstance(r, dict) and (r.get("url") or r.get("endpoint")):
                        ev.items.append(EvidenceItem(
                            kind="finding", vuln_class=cls,
                            title=f"{cls.upper()} (PoC)", severity="high",
                            url=r.get("url") or r.get("endpoint", ""),
                            parameter=r.get("param") or r.get("parameter", ""),
                            confidence="confirmed", proven=True, source=f"{cls}_testing",
                            evidence=(r.get("payload") or r.get("evidence") or "")[:200], raw=r))
                except Exception:
                    pass
                continue
            kind_r, method, sink, url = m.groups()
            ev.items.append(EvidenceItem(
                kind="finding", vuln_class=cls, title=f"{cls.upper()} via {sink} ({method})",
                severity="high", url=url.strip(), confidence="confirmed", proven=True,
                source=f"{cls}_testing", evidence=f"PoC: [{kind_r}][{method}][{sink}]",
                raw={"line": ln}))

    # 8) nuclei — structured JSON preferred, text fallback.
    _load_nuclei(ev, scan_dir)

    # 9) Header analysis — missing security headers are real findings.
    for r in _read_jsonl(J("06_header_analysis", "header_findings.jsonl")):
        missing = r.get("missing_headers") or []
        if not missing:
            continue
        host = r.get("host", "")
        ev.items.append(EvidenceItem(
            kind="finding", vuln_class="misconfig",
            title=f"Missing security headers ({len(missing)})",
            severity="low" if len(missing) <= 2 else "medium",
            host=host, url=r.get("url", ""),
            source="header_analysis",
            evidence=f"Missing: {', '.join(missing[:6])}; server={r.get('server_banner','')}",
            remediation="Deploy missing security headers (CSP, HSTS, X-Frame-Options, etc.)",
            raw=r))

    # 10) 403 bypass — confirmed bypasses are proven findings.
    for r in _read_jsonl(J("08_directory_discovery", "bypass_findings.jsonl")):
        ev.items.append(EvidenceItem(
            kind="finding", vuln_class="auth-bypass",
            title=r.get("title") or "403 bypass confirmed",
            severity=r.get("severity", "medium"), host=r.get("host", ""),
            url=r.get("url", ""), confidence=r.get("confidence", "confirmed"),
            proven=_is_proven(r.get("confidence", "confirmed")),
            source="bypass_403",
            evidence=r.get("evidence") or r.get("technique", ""),
            raw=r))

    # 11) OSINT intelligence — breach/exposure/brand signals.
    #     Skip connector-status messages ("not configured" / "configured") —
    #     these are config diagnostics, not security findings.
    for r in _read_jsonl(J("18_osint_intel", "osint_findings.jsonl")):
        sev = r.get("severity", "medium")
        cat = r.get("category", "")
        src = r.get("source", "")
        title = r.get("title", "OSINT finding")[:160]
        if src == "connector" or "not configured" in title.lower() or "configured" == title.rsplit(": ", 1)[-1].strip().lower():
            continue
        ev.items.append(EvidenceItem(
            kind="finding", vuln_class="info-disclosure" if cat == "breach" else classify(
                cat, title, default="info-disclosure"),
            title=title,
            severity=sev, host=r.get("host") or r.get("subject", ""),
            confidence=r.get("confidence", ""),
            proven=cat in ("breach", "leaked_creds"),
            source="osint_intel",
            evidence=(r.get("evidence") or r.get("risk") or "")[:200],
            remediation=r.get("recommendation") or r.get("remediation", ""),
            category=r.get("category_label") or cat, raw=r))

    # 12) Port scan — non-HTTP open ports as observations.
    for r in _read_jsonl(J("14_port_scan", "all_ports.jsonl")):
        port = r.get("port")
        host = r.get("host", "")
        if port in (80, 443) or not port:
            continue
        ev.items.append(EvidenceItem(
            kind="finding", vuln_class="misconfig",
            title=f"Non-HTTP port {port} open",
            severity="info", host=host,
            source="port_scan",
            evidence=f"port={port} proto={r.get('protocol','tcp')} tls={r.get('tls',False)}",
            raw=r))

    # --- non-finding context --------------------------------------------
    ev.endpoints = _read_jsonl(J("08_directory_discovery", "discovered_endpoints.jsonl"), cap=8000)
    idg = _read_json(J("00_har_ingest", "identity_graph.json"), {}) or {}
    ev.bola_candidates = (idg.get("bola_candidates") or [])[:40]
    ev.hosts = _collect_hosts(ev)
    caps = _read_json(J("25_attack_paths", "capec_attack_paths.json"), {}) or {}
    ev.prior_chains = (caps.get("paths") or caps.get("chains") or [])[:20]

    # --- recon context (grounds the brain) --------------------------------
    _load_recon_context(ev, scan_dir)

    ev.stats = {
        "items": len(ev.items),
        "proven": len(ev.proven),
        "observations": len(ev.observations),
        "endpoints": len(ev.endpoints),
        "bola_candidates": len(ev.bola_candidates),
        "hosts": len(ev.hosts),
        "recon_hosts_with_tech": len(ev.technologies),
        "waf_protected": len(ev.waf_map),
        "non_http_services": len(ev.services),
        "osint_signals": len(ev.osint),
    }
    return ev


def _load_recon_context(ev: Evidence, scan_dir: str) -> None:
    """Populate recon-stage context fields from Modules 3-7, 14."""
    def J(*parts):
        return os.path.join(scan_dir, *parts)

    # httpx — tech stack + CDN/CNAME per host (Module 4).
    # The file is typically JSONL (one dict per line), but may also be a JSON array.
    http_confirmed = J("04_http_discovery", "http_confirmed.json")
    rows = _read_jsonl(http_confirmed, cap=500)
    if not rows:
        data = _read_json(http_confirmed)
        if data is not None:
            rows = data if isinstance(data, list) else [data] if isinstance(data, dict) else []
    if rows:
        for r in rows[:500]:
            if not isinstance(r, dict):
                continue
            host = r.get("host", "")
            if not host:
                continue
            tech = r.get("tech") or []
            if tech:
                ev.technologies[host] = tech
            cname = r.get("cname") or []
            if cname:
                ev.dns_records.append({"host": host, "cname": cname,
                                       "ip": r.get("host_ip") or (r.get("a") or [""])[0]})

    # WAF detections (Module 5).
    for r in _read_jsonl(J("05_waf_detection", "waf_detections.jsonl")):
        host = r.get("host", "")
        vendor = r.get("waf_vendor", "")
        if host and vendor:
            ev.waf_map[host] = vendor

    # Service fingerprints (Module 7) — non-HTTP services.
    svc_data = _read_json(J("07_service_fingerprint", "services.json"))
    if isinstance(svc_data, list):
        for r in svc_data[:200]:
            if not isinstance(r, dict):
                continue
            stype = (r.get("service_type") or "").lower()
            if stype == "non_http" or r.get("port") not in (80, 443, None):
                ev.services.append({
                    "host": r.get("host", ""), "port": r.get("port"),
                    "name": r.get("name", ""), "product": r.get("product", ""),
                    "version": r.get("version", "")})

    # Port scan (Module 14) — build per-host port list.
    for r in _read_jsonl(J("14_port_scan", "all_ports.jsonl")):
        host = r.get("host", "")
        port = r.get("port")
        if host and port:
            ev.open_ports.setdefault(host, []).append(port)

    # Infer WAF from tech stack when the dedicated WAF module didn't detect it.
    _WAF_TECH_KEYWORDS = {
        "cloudflare": "Cloudflare", "akamai": "Akamai", "imperva": "Imperva",
        "sucuri": "Sucuri", "barracuda": "Barracuda", "f5": "F5",
        "fortinet": "Fortinet", "bot manager": "WAF/Bot Manager",
        "aws waf": "AWS WAF", "azure front door": "Azure Front Door",
    }
    for host, techs in ev.technologies.items():
        if host in ev.waf_map:
            continue
        for t in techs:
            tl = t.lower()
            for kw, vendor in _WAF_TECH_KEYWORDS.items():
                if kw in tl:
                    ev.waf_map[host] = vendor
                    break
            if host in ev.waf_map:
                break

    # OSINT summary for context (not findings — those are loaded above).
    for r in _read_jsonl(J("18_osint_intel", "osint_findings.jsonl")):
        ev.osint.append(r)


def _norm_class(cls: str) -> str:
    c = (cls or "").lower().strip()
    aliases = {"idor": "bola", "open-redirect": "redirect", "prototype-pollution": "proto"}
    return aliases.get(c, c) or "info-disclosure"


def _load_nuclei(ev: Evidence, scan_dir: str) -> None:
    import glob
    for jf in glob.glob(os.path.join(scan_dir, "12_nuclei_scanning", "*nuclei_scan_results.json")):
        data = _read_json(jf)
        rows = data if isinstance(data, list) else (data.get("findings") or data.get("results") or []) if isinstance(data, dict) else []
        for r in rows[:2000]:
            if not isinstance(r, dict):
                continue
            info = r.get("info", {}) if isinstance(r.get("info"), dict) else {}
            name = info.get("name") or r.get("template-id") or r.get("templateID") or "nuclei"
            sev = (info.get("severity") or r.get("severity") or "info").lower()
            url = r.get("matched-at") or r.get("host") or r.get("url") or ""
            if sev in ("info", "unknown") and "cve" not in name.lower():
                continue  # keep nuclei noise out of the dossier
            ev.items.append(EvidenceItem(
                kind="finding", vuln_class=classify(name, str(info.get("tags", "")), default="cve" if "cve" in name.lower() else "misconfig"),
                title=name, severity=sev, url=url, host=_host_of(url),
                source="nuclei", proven=False,
                evidence=(info.get("description") or "")[:200], raw=r))
        return  # one results file is enough


def _collect_hosts(ev: Evidence) -> List[str]:
    hosts = set()
    for it in ev.items:
        if it.host:
            hosts.add(it.host)
    for ep in ev.endpoints:
        if ep.get("host"):
            hosts.add(ep["host"])
    return sorted(hosts)


def _host_of(url: str) -> str:
    m = re.search(r"https?://([^/:]+)", url or "")
    return m.group(1) if m else ""


def _infer_target(scan_dir: str) -> str:
    mani = _read_json(os.path.join(scan_dir, "manifest.json"), {}) or {}
    if mani.get("target"):
        return mani["target"]
    base = os.path.basename(os.path.normpath(scan_dir))
    return re.sub(r"-\d{6}.*$", "", base) or base
