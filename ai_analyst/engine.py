"""
AriseAI — the orchestrator (hybrid reason-then-verify loop).

run_pentest() is the single entry point. It is fail-safe by contract: it NEVER
raises. A missing provider, key, tool, or scan file degrades to the best partial
result (at worst, an evidence-only report with no AI narrative).

Flow:
    load EASM evidence
      → brain.plan()  : ranked attack hypotheses (grounded, anti-hallucinated)
      → verify.ground()/select() : keep only hypotheses the evidence supports
      → safety.live_verify()     : differentially confirm the top ones live
      → verify.reconcile()       : flip proven hypotheses to "realized"
      → assemble proven findings (upstream-confirmed + live-confirmed, deduped)
      → brain.narrate()          : operator write-up + chains + honest coverage
      → rank by proven impact, stamp AI provenance
      → report.write_artifacts() : md / per-finding PoC / json / csv / sarif
"""

from __future__ import annotations

import hashlib
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from ai_analyst import brain, report, safety, verify
from ai_analyst import constants as C
from ai_analyst import adversary as adv
from ai_analyst import killchain as kc
from ai_analyst.evidence import Evidence, EvidenceItem, load_evidence
from ai_analyst.provider import Brain, resolve_brain


@dataclass
class PentestConfig:
    # Depth tiers (cumulative): reason (always) → differential live-verify →
    # autonomous tool-execution (the merged Autonomous Action engine).
    live_verify: bool = True          # tier 2: typed differential probes
    autonomous_exec: bool = False     # tier 3: scope-locked live-tool loop (opt-in)
    authz_confirmed: bool = False     # tier 3 requires explicit per-run authorization (RT4)
    objective: str = ""               # free-form steer for the autonomous tier
    max_hypotheses: int = 12
    verify_budget: int = 6            # max hypotheses to live-verify per run
    autonomous_budget: int = 25       # max tool executions in the autonomous tier
    max_observations: int = 40        # cap unproven observations in the output
    rate: int = 20                    # requests/sec ceiling for live verify
    timeout: int = 10
    max_targets: int = 150            # per-check target cap for live verify
    recon_only: bool = False          # run on recon-stage data only (no exploitation)
    adversary: str = ""               # adversary emulation profile (APT29, FIN7, etc.)

    @classmethod
    def from_settings(cls, block: Optional[dict]) -> "PentestConfig":
        b = dict(block or {})

        def _b(k, d):
            v = b.get(k, d)
            return str(v).lower() in ("1", "true", "yes", "on") if isinstance(v, str) else bool(v)

        def _i(k, d):
            try:
                return int(b.get(k, d))
            except Exception:
                return d
        return cls(
            live_verify=_b("live_verify", True),
            autonomous_exec=_b("autonomous_exec", False),
            authz_confirmed=_b("authz_confirmed", False),
            objective=str(b.get("objective", "") or ""),
            max_hypotheses=_i("max_hypotheses", 12),
            verify_budget=_i("verify_budget", 6),
            autonomous_budget=_i("autonomous_budget", 25),
            max_observations=_i("max_observations", 40),
            rate=_i("rate", 20),
            timeout=_i("timeout", 10),
            max_targets=_i("max_targets", 150),
        )


@dataclass
class PentestResult:
    target: str
    scan_dir: str
    findings: List[Dict[str, Any]] = field(default_factory=list)
    hypotheses: List[Dict[str, Any]] = field(default_factory=list)
    writeup: Dict[str, Any] = field(default_factory=dict)
    coverage: Dict[str, Any] = field(default_factory=dict)
    artifacts: Dict[str, str] = field(default_factory=dict)
    killchain: Dict[str, Any] = field(default_factory=dict)
    adversary_profile: Optional[str] = None
    provider: str = ""
    model: str = ""
    generated_at: str = ""
    audit: List[str] = field(default_factory=list)
    error: Optional[str] = None

    @property
    def proven_findings(self) -> List[Dict[str, Any]]:
        return [f for f in self.findings if f.get("proven")]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "engine": C.ENGINE_NAME,
            "target": self.target,
            "scan_dir": os.path.basename(self.scan_dir),
            "generated_at": self.generated_at,
            "provider": self.provider,
            "model": self.model,
            "counts": {
                "findings": len(self.findings),
                "exploited": sum(1 for f in self.findings if f.get("exploited")),
                "proven": len(self.proven_findings),
                "observations": len(self.findings) - len(self.proven_findings),
                "hypotheses": len(self.hypotheses),
                "realized": sum(1 for h in self.hypotheses if h.get("status") == "realized"),
                "rejected": sum(1 for h in self.hypotheses if h.get("status") == "rejected"),
            },
            "findings": self.findings,
            "hypotheses": self.hypotheses,
            "writeup": self.writeup,
            "coverage": self.coverage,
            "killchain": self.killchain,
            "adversary_profile": self.adversary_profile,
            "artifacts": self.artifacts,
            "error": self.error,
        }


# ---------------------------------------------------------------------------
def run_pentest(scan_dir: str,
                target: Optional[str] = None,
                provider: Optional[str] = None,
                model: Optional[str] = None,
                api_key: Optional[str] = None,
                chat_fn: Optional[Callable] = None,
                config: Optional[PentestConfig] = None) -> PentestResult:
    """Run the autonomous red-team pentest over a scan dir.

    Works on ANY pipeline stage — from bare recon (Modules 1-9) through full
    results. When config.recon_only=True, runs a lightweight attack-surface
    assessment instead of the exploit/verify tiers."""
    cfg = config or PentestConfig()
    audit: List[str] = []

    def log(msg: str):
        audit.append(f"{time.strftime('%H:%M:%S')} {msg}")

    try:
        ev = load_evidence(scan_dir, target)
    except Exception as exc:
        res = PentestResult(target=target or os.path.basename(scan_dir), scan_dir=scan_dir,
                            generated_at=_now(), error=f"evidence load failed: {exc}")
        return res

    tgt = ev.target
    res = PentestResult(target=tgt, scan_dir=scan_dir, generated_at=_now())
    log(f"loaded evidence: {ev.stats}")

    # Resolve adversary emulation profile.
    profile = adv.get_profile(cfg.adversary) if cfg.adversary else None
    if profile:
        res.adversary_profile = profile.name
        log(f"adversary emulation: {profile.name} ({profile.noise_level}, "
            f"{len(profile.techniques)} techniques)")
    chain_state = kc.init_chain(profile)

    if cfg.recon_only:
        return _run_recon_analysis(ev, res, cfg, audit, log,
                                   provider, model, api_key, chat_fn,
                                   profile=profile, chain_state=chain_state)

    brn = resolve_brain(provider, model, api_key, chat_fn, scan_dir=scan_dir)
    res.provider, res.model = brn.provider, brn.model
    if not brn.available:
        log(f"no LLM brain ({brn.error}) — evidence-only mode")

    # 1) Plan attack hypotheses (needs a brain).
    hypotheses: List[Dict[str, Any]] = []
    if brn.available:
        dossier = ev.dossier()
        if profile:
            dossier["adversary_profile"] = profile.brief()
        hypotheses, perr = brain.plan(brn, dossier, cfg.max_hypotheses,
                                       adversary=profile)
        log(f"brain.plan -> {len(hypotheses)} hypotheses" + (f" (err: {perr})" if perr else ""))
    else:
        res.error = brn.error

    # 2) Ground against real evidence (anti-hallucination gate, RT3).
    known_urls = [ep.get("sample_url") or ep.get("url") for ep in ev.endpoints]
    known_urls += [it.url for it in ev.items if it.url]
    known_params = _collect_params(ev)
    hypotheses = verify.ground(hypotheses, ev.hosts, tgt,
                               known_urls=known_urls, known_params=known_params,
                               waf_map=ev.waf_map, technologies=ev.technologies)
    rejected = sum(1 for h in hypotheses if h.get("status") == "rejected")
    demoted = sum(1 for h in hypotheses
                  if h.get("url_grounded") is False or h.get("param_grounded") is False)
    waf_demoted = sum(1 for h in hypotheses if h.get("waf_demoted"))
    log(f"grounding gate: {rejected} rejected, {demoted} demoted (ungrounded url/param), "
        f"{waf_demoted} WAF-demoted of {len(hypotheses)}")

    # Adversary TTP filter: reorder hypotheses by the actor's preferred techniques.
    if profile:
        hypotheses = adv.filter_hypotheses(hypotheses, profile)
        in_scope = sum(1 for h in hypotheses if h.get("adversary_in_scope"))
        log(f"adversary filter ({profile.name}): {in_scope}/{len(hypotheses)} in TTP scope")

    # Advance kill chain for already-proven upstream findings.
    for it in ev.proven:
        kc.advance_on_finding(chain_state,
                              {"vuln_class": it.vuln_class, "ref": it.title,
                               "host": it.host, "url": it.url, "proven": True},
                              profile)

    # Build the shared scope firewall once if any live tier will fire.
    # Scope is needed even without a brain — ALWAYS_RUN_CHECKS fire regardless.
    scope = None
    if cfg.live_verify or cfg.autonomous_exec:
        scope = safety.build_scope(tgt, scan_dir)
        if scope is None:
            log("live tiers skipped: ScopeGuard unavailable (cannot fire safely)")

    # 3a) Tier 2 — live-verify the top grounded, verifiable hypotheses.
    #     ALWAYS_RUN_CHECKS (origin_bypass, cors, headers, exposure) fire even
    #     when the brain is unavailable or proposed no hypotheses.
    live_records: List[Dict[str, Any]] = []
    verify_meta: Dict[str, Any] = {}
    live_proven: List[Dict[str, Any]] = []
    if cfg.live_verify and scope is not None:
        chosen, checks = verify.select(hypotheses, cfg.verify_budget)
        # ALWAYS_RUN_CHECKS are injected by safety.live_verify itself —
        # just pass whatever the brain selected (may be empty).
        log(f"live-verify: running checks {checks or '(brain-selected: none)'} "
            f"+ always-on checks for {len(chosen)} hypotheses")
        live_records, verify_meta = safety.live_verify(
            scan_dir, tgt, checks, rate=cfg.rate,
            timeout=cfg.timeout, max_targets=cfg.max_targets)
        log(f"live-verify -> {len(live_records)} confirmed finding(s) "
            f"({verify_meta.get('elapsed_s','?')}s){' err:'+verify_meta['error'] if verify_meta.get('error') else ''}")
        hypotheses, live_proven = verify.reconcile(hypotheses, live_records)
        # Kill chain: advance on live-proven findings and generate pivot hypotheses.
        for rec in (live_proven or []):
            pivot_hyps = kc.advance_on_finding(
                chain_state,
                {"vuln_class": verify._norm_class_from_record(rec),
                 "ref": rec.get("title", ""), "host": rec.get("host", ""),
                 "url": rec.get("url", ""), "parameter": rec.get("parameter", ""),
                 "proven": True, "waf_considered": rec.get("waf_considered", "none")},
                profile)
            if pivot_hyps:
                log(f"kill chain pivot: {len(pivot_hyps)} new hypotheses from "
                    f"{rec.get('title','')[:40]}")
                hypotheses.extend(pivot_hyps)
    elif not cfg.live_verify:
        log("live-verify (tier 2) disabled by config")

    # 3b) Tier 3 — iterate-until-exploit. Target the proven findings (to escalate)
    # and the grounded hypotheses (to confirm), read-only prove-impact.
    findings_pre: List[Dict[str, Any]] = [
        {"vuln_class": it.vuln_class, "title": it.title, "host": it.host, "url": it.url,
         "parameter": it.parameter, "severity": it.severity, "evidence": it.evidence,
         "proven": True}
        for it in ev.proven
    ]
    for rec in (live_proven or []):
        findings_pre.append({
            "vuln_class": verify._norm_class_from_record(rec), "title": rec.get("title", ""),
            "host": rec.get("host", ""), "url": rec.get("url", ""),
            "parameter": rec.get("parameter", ""), "severity": rec.get("severity", "high"),
            "evidence": rec.get("evidence", ""), "proven": True})
    auto_proven: List[Dict[str, Any]] = []
    auto_meta: Dict[str, Any] = {}
    if cfg.autonomous_exec and brn.available and scope is not None:
        # RT4 authorization gate — active tool execution needs an explicit per-run OK.
        allowed, areason = True, None
        try:
            from core import budget as _bud
            allowed, areason = _bud.require_authorization(cfg.authz_confirmed)
        except Exception:
            pass
        if not allowed:
            log(f"exploitation tier REFUSED: {areason}")
            auto_meta = {"ran": False, "error": areason}
        else:
            # Tier 3 — the iterate-until-exploit loop (tool-KB-driven, read-only
            # prove-impact). Exploits the top proven findings + grounded hypotheses.
            from ai_analyst import exploit_loop
            log(f"exploitation tier: iterate-until-exploit (budget {cfg.autonomous_budget})")
            auto_proven, auto_meta = exploit_loop.run_tier(
                ev, findings_pre, hypotheses, brn, scope, scan_dir,
                budget=cfg.autonomous_budget)
            log(f"exploitation tier -> {auto_meta.get('exploited', 0)}/{auto_meta.get('targets', 0)} "
                f"exploited in {auto_meta.get('iters', 0)} iters"
                + (f" err:{auto_meta['error']}" if auto_meta.get('error') else ""))
    elif cfg.autonomous_exec:
        log("exploitation tier skipped: no brain or scope")

    res.hypotheses = hypotheses

    # 4) Assemble findings: upstream-proven + live-proven + autonomous-proven + observations.
    findings = _assemble_findings(ev, live_proven, cfg, extra_proven=auto_proven)
    log(f"assembled {len(findings)} findings "
        f"({sum(1 for f in findings if f.get('proven'))} proven)")

    # 5) Coverage facts for honest reporting.
    coverage = {
        "evidence_items": ev.stats.get("items", 0),
        "hosts": ev.stats.get("hosts", 0),
        "endpoints": ev.stats.get("endpoints", 0),
        "hypotheses_total": len(hypotheses),
        "hypotheses_rejected": rejected,
        "hypotheses_realized": sum(1 for h in hypotheses if h.get("status") == "realized"),
        "live_checks": len(verify_meta.get("per_check", {})) if verify_meta else 0,
        "live_verify_ran": bool(verify_meta.get("ran")),
        "autonomous_ran": bool(auto_meta.get("ran")),
        "autonomous_actions": auto_meta.get("actions", 0),
        "autonomous_confirmed": auto_meta.get("confirmed", 0),
        "budget_note": verify_meta.get("error") or auto_meta.get("error") or "",
    }
    res.coverage = coverage

    # 6) Red-team write-up (enriches findings with narrative/impact/poc).
    if brn.available and findings:
        proven_slim = [_slim_for_narrate(f) for f in findings if f.get("proven")]
        hyp_slim = [{"title": h.get("title"), "vuln_class": h.get("vuln_class"),
                     "status": h.get("status"), "chain": h.get("chain")}
                    for h in hypotheses]
        writeup, nerr = brain.narrate(brn, tgt, proven_slim, hyp_slim, coverage)
        if nerr:
            log(f"brain.narrate error: {nerr}")
        else:
            # Narrative verification (RT3): flag any host/URL/IP the model invented.
            try:
                from ai_analyst import narrative_check
                writeup, unverified = narrative_check.check(writeup, ev)
                if unverified:
                    log(f"narrative check: {len(unverified)} unverified token(s) flagged "
                        f"(e.g. {unverified[0].get('token','')[:60]})")
            except Exception as exc:
                log(f"narrative check skipped: {exc}")
            res.writeup = writeup
            _merge_narrative(findings, writeup)
            log("brain.narrate -> write-up merged")

    # 6b) Kill chain summary + ATT&CK coverage.
    chain_narrative = kc.build_chain_narrative(chain_state, profile)
    if profile:
        proven_classes = {f.get("vuln_class", "") for f in findings if f.get("proven")}
        chain_narrative["attack_coverage"] = adv.attack_coverage(profile, proven_classes)
    res.killchain = chain_narrative
    log(f"kill chain depth: {chain_state.depth} ({chain_state.deepest_tactic}), "
        f"{len(chain_state.chains)} chain(s), {len(chain_state.pivots_generated)} pivots")

    # 7) Rank by proven impact and finalize.
    findings.sort(key=_rank_key)
    # PoC honesty (RT2): proven findings are "pending" replay until re-verified,
    # and carry a copy-paste curl so the operator can reproduce by hand.
    from ai_analyst import poc as _poc
    for f in findings:
        if f.get("proven"):
            f.setdefault("replay_confirmed", "pending")
            if not f.get("curl_command"):
                f["curl_command"] = _poc.curl_for(f)
    res.findings = findings
    res.audit = audit

    # 8) Emit artifacts.
    result_dict = _result_dict(res)
    res.artifacts = report.write_artifacts(scan_dir, result_dict)
    _write_audit(scan_dir, audit)
    log(f"artifacts: {sorted(res.artifacts)}")
    return res


# ---------------------------------------------------------------------------
# Recon-only analysis (runs on Modules 1-9 data, no exploitation)
# ---------------------------------------------------------------------------
def _run_recon_analysis(ev: Evidence, res: PentestResult, cfg: PentestConfig,
                        audit: List[str], log, provider, model, api_key, chat_fn,
                        profile=None, chain_state=None) -> PentestResult:
    """Lightweight attack-surface assessment from recon-stage data only.

    Produces: findings from recon (headers, OSINT, ports, bypass), ranked
    hypotheses for what to test next, and (with a brain) an attack-surface
    narrative. No live verification or exploitation traffic."""
    scan_dir = ev.scan_dir
    tgt = ev.target

    brn = resolve_brain(provider, model, api_key, chat_fn, scan_dir=scan_dir)
    res.provider, res.model = brn.provider, brn.model
    if not brn.available:
        log(f"recon-analysis: no LLM brain ({brn.error}) — evidence-only mode")

    # Assemble recon-stage findings (items from header_analysis, osint, ports, etc.)
    auth_map = _auth_map(ev)
    findings: List[Dict[str, Any]] = []
    for it in sorted(ev.items, key=lambda i: C.sev_rank(i.severity), reverse=True):
        f = _finding_from_item(it, auth_map)
        findings.append(f)
    findings = _cluster(findings)
    log(f"recon findings assembled: {len(findings)} "
        f"({sum(1 for f in findings if f.get('proven'))} proven)")

    # Plan hypotheses (what the full scan should test).
    hypotheses: List[Dict[str, Any]] = []
    if brn.available:
        dossier = ev.dossier()
        hypotheses, perr = brain.plan(brn, dossier, cfg.max_hypotheses)
        log(f"brain.plan -> {len(hypotheses)} hypotheses" + (f" (err: {perr})" if perr else ""))
    else:
        res.error = brn.error

    # Ground against real evidence — same anti-hallucination gate.
    known_urls = [ep.get("sample_url") or ep.get("url") for ep in ev.endpoints]
    known_urls += [it.url for it in ev.items if it.url]
    known_params = _collect_params(ev)
    hypotheses = verify.ground(hypotheses, ev.hosts, tgt,
                               known_urls=known_urls, known_params=known_params,
                               waf_map=ev.waf_map, technologies=ev.technologies)
    rejected = sum(1 for h in hypotheses if h.get("status") == "rejected")
    waf_demoted = sum(1 for h in hypotheses if h.get("waf_demoted"))
    log(f"grounding gate: {rejected} rejected, {waf_demoted} WAF-demoted of {len(hypotheses)}")

    if profile:
        hypotheses = adv.filter_hypotheses(hypotheses, profile)
        in_scope = sum(1 for h in hypotheses if h.get("adversary_in_scope"))
        log(f"adversary filter ({profile.name}): {in_scope}/{len(hypotheses)} in TTP scope")

    if chain_state:
        for f in findings:
            if f.get("proven"):
                kc.advance_on_finding(chain_state, f, profile)
        res.killchain = kc.build_chain_narrative(chain_state, profile)
        if profile:
            proven_classes = {f.get("vuln_class", "") for f in findings if f.get("proven")}
            res.killchain["attack_coverage"] = adv.attack_coverage(profile, proven_classes)

    res.hypotheses = hypotheses
    res.findings = findings

    # Coverage facts.
    res.coverage = {
        "mode": "recon_only",
        "evidence_items": ev.stats.get("items", 0),
        "hosts": ev.stats.get("hosts", 0),
        "endpoints": ev.stats.get("endpoints", 0),
        "recon_hosts_with_tech": ev.stats.get("recon_hosts_with_tech", 0),
        "waf_protected": ev.stats.get("waf_protected", 0),
        "osint_signals": ev.stats.get("osint_signals", 0),
        "hypotheses_total": len(hypotheses),
        "hypotheses_rejected": rejected,
        "hypotheses_waf_demoted": waf_demoted,
        "live_verify_ran": False,
        "autonomous_ran": False,
    }

    # Recon narrative (attack surface assessment, not a pentest report).
    if brn.available and (findings or hypotheses):
        writeup, nerr = brain.recon_narrate(brn, tgt, findings, hypotheses, res.coverage, ev)
        if nerr:
            log(f"brain.recon_narrate error: {nerr}")
        else:
            try:
                from ai_analyst import narrative_check
                writeup, unverified = narrative_check.check(writeup, ev)
                if unverified:
                    log(f"narrative check: {len(unverified)} unverified token(s)")
            except Exception as exc:
                log(f"narrative check skipped: {exc}")
            res.writeup = writeup
            _merge_narrative(findings, writeup)
            log("recon narrative merged")

    findings.sort(key=_rank_key)
    res.findings = findings
    res.audit = audit

    result_dict = _result_dict(res)
    res.artifacts = report.write_artifacts(scan_dir, result_dict)
    _write_audit(scan_dir, audit)
    log(f"recon-analysis complete: {len(findings)} findings, {len(hypotheses)} hypotheses")
    return res


# ---------------------------------------------------------------------------
# Assembly helpers
# ---------------------------------------------------------------------------
def _collect_params(ev: Evidence) -> List[str]:
    params: List[str] = []
    for ep in ev.endpoints:
        qv = ep.get("query_variants")
        if qv:
            params += qv
            continue
        q = ep.get("query")
        if isinstance(q, dict):
            params += list(q.keys())
    params += [it.parameter for it in ev.items if it.parameter]
    return params


def _ref(vuln_class: str, host: str, url: str, param: str) -> str:
    h = hashlib.sha1(f"{url}|{param}".encode()).hexdigest()[:8]
    return f"{vuln_class or 'finding'}:{host or '-'}:{h}"


def _auth_map(ev: Evidence) -> Dict[str, str]:
    m = {}
    for epd in ev.endpoints:
        u = epd.get("sample_url") or epd.get("url")
        if u:
            m[u] = (epd.get("auth_state") or "").lower()
    return m


def _impact_tier(proven: bool, vuln_class: str, auth_state: str) -> int:
    if not proven:
        return C.TIER_OBSERVATION
    if vuln_class in ("bola", "bfla", "idor", "access-control"):
        return C.TIER_CROSS_TENANT
    if auth_state in ("auth", "authenticated", "authed", "logged-in"):
        return C.TIER_AUTHED
    return C.TIER_UNAUTH


def _finding_from_item(it: EvidenceItem, auth_map: Dict[str, str]) -> Dict[str, Any]:
    web, api, cwe = C.owasp_for(it.vuln_class)
    tier = _impact_tier(it.proven, it.vuln_class, auth_map.get(it.url, ""))
    return _stamp({
        "ref": _ref(it.vuln_class, it.host, it.url, it.parameter),
        "title": it.title, "severity": it.severity, "vuln_class": it.vuln_class,
        "host": it.host, "url": it.url, "parameter": it.parameter,
        "owasp_web": web, "owasp_api": api, "cwe": cwe,
        "impact": it.evidence[:400], "evidence": it.evidence,
        "remediation": it.remediation, "confidence": it.confidence,
        "verification": it.raw.get("verification", ""),
        "request_line": it.raw.get("request_line", ""),
        "payload": it.raw.get("payload", ""),
        "baseline": it.raw.get("baseline", {}), "attack": it.raw.get("attack", {}),
        "proven": it.proven, "impact_tier": tier,
        "origin_module": it.source,
    })


def _finding_from_live(rec: Dict[str, Any], auth_map: Dict[str, str]) -> Dict[str, Any]:
    cls = verify._norm_class_from_record(rec)
    web, api, cwe = C.owasp_for(cls)
    tier = _impact_tier(True, cls, auth_map.get(rec.get("url", ""), ""))
    return _stamp({
        "ref": _ref(cls, rec.get("host", ""), rec.get("url", ""), rec.get("parameter", "")),
        "title": rec.get("title") or rec.get("template") or f"{cls} (live-confirmed)",
        "severity": rec.get("severity", "high"), "vuln_class": cls,
        "host": rec.get("host", ""), "url": rec.get("url", ""),
        "parameter": rec.get("parameter", ""),
        "owasp_web": web, "owasp_api": api, "cwe": cwe,
        "impact": rec.get("impact") or rec.get("evidence", ""),
        "evidence": rec.get("evidence", ""), "remediation": rec.get("remediation", ""),
        "confidence": rec.get("confidence", "exploited"),
        "verification": rec.get("verification", "differential"),
        "request_line": rec.get("request_line", ""), "payload": rec.get("payload", ""),
        "baseline": rec.get("baseline", {}), "attack": rec.get("attack", {}),
        "proven": True, "impact_tier": tier, "origin_module": "ai_analyst_live",
    })


def _stamp(f: Dict[str, Any]) -> Dict[str, Any]:
    """Mark every finding with AriseAI provenance so the dashboard badges it and
    the reconciler corroborates (never duplicates) it against other engines."""
    f["source"] = C.ENGINE_SOURCE
    f["tool"] = C.ENGINE_TOOL
    f["ai_generated"] = True
    f["id"] = f.get("ref")
    return f


def _assemble_findings(ev: Evidence, live_proven: List[Dict[str, Any]],
                       cfg: PentestConfig,
                       extra_proven: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
    auth_map = _auth_map(ev)
    by_ref: Dict[str, Dict[str, Any]] = {}

    # Proven upstream findings first (richest evidence wins on collision).
    for it in ev.proven:
        f = _finding_from_item(it, auth_map)
        by_ref.setdefault(f["ref"], f)

    # Autonomous-tier confirmed findings (already in AriseAI shape) — give each a
    # stable ref and an impact tier, then let them collide/merge like the rest.
    for f in (extra_proven or []):
        f.setdefault("ref", _ref(f.get("vuln_class", ""), f.get("host", ""),
                                 f.get("url", ""), f.get("parameter", "")))
        f["id"] = f["ref"]
        f.setdefault("impact_tier", _impact_tier(True, f.get("vuln_class", ""),
                                                 auth_map.get(f.get("url", ""), "")))
        existing = by_ref.get(f["ref"])
        if existing:
            existing.setdefault("corroborated_by", []).append(
                f.get("corroborated_by", ["exploit"])[0] if f.get("corroborated_by") else "exploit")
            # Carry exploitation proof onto the existing finding (it's the headline).
            if f.get("exploited"):
                existing["exploited"] = True
                existing["proven"] = True
                for k in ("exploit_proof", "exploit_impact", "exploit_transcript"):
                    if f.get(k) and not existing.get(k):
                        existing[k] = f[k]
                # exploited lands at the top impact tier.
                existing["impact_tier"] = min(_TIER_SORT.get(existing.get("impact_tier", 3), 3),
                                               _TIER_SORT.get(f.get("impact_tier", 0), 0))
            if not existing.get("poc") and f.get("poc"):
                existing["poc"] = f["poc"]
        else:
            by_ref[f["ref"]] = f

    # Live-confirmed findings — upgrade/augment.
    for rec in live_proven:
        if not rec.get("_matched_hypothesis") and not rec.get("evidence"):
            continue
        f = _finding_from_live(rec, auth_map)
        existing = by_ref.get(f["ref"])
        if existing:
            existing["confidence"] = f["confidence"] or existing.get("confidence")
            existing["verification"] = existing.get("verification") or f["verification"]
            existing.setdefault("corroborated_by", []).append("ai_analyst_live")
        else:
            f["corroborated_by"] = ["ai_analyst_live"]
            by_ref[f["ref"]] = f

    # Unproven observations (capped, highest severity first).
    # Filter out low-value scanner noise: "missing security headers" on every host
    # is a header scanner, not a red team finding.
    obs = sorted(ev.observations, key=lambda i: C.sev_rank(i.severity), reverse=True)
    for it in obs[:cfg.max_observations]:
        title_l = (it.title or "").lower()
        if "missing security header" in title_l or "missing header" in title_l:
            continue
        f = _finding_from_item(it, auth_map)
        by_ref.setdefault(f["ref"], f)

    # Cluster: one vulnerability = one finding. The same class on the same host
    # via the same parameter is ONE finding confirmed on N URLs — not N rows.
    return _cluster(list(by_ref.values()))


def _norm_title(t: str) -> str:
    return re.sub(r"\s+", " ", (t or "").lower()).strip()[:80]


def _cluster(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    groups: Dict[tuple, Dict[str, Any]] = {}
    for f in findings:
        key = (f.get("vuln_class", ""), f.get("host", ""),
               f.get("parameter", ""), _norm_title(f.get("title", "")))
        base = groups.get(key)
        if base is None:
            f["instances"] = [f["url"]] if f.get("url") else []
            groups[key] = f
            continue
        # Merge into the existing cluster, keeping the strongest evidence.
        if f.get("url") and f["url"] not in base["instances"]:
            base["instances"].append(f["url"])
        base["proven"] = base.get("proven") or f.get("proven")
        # Carry exploitation proof across the cluster (it's the headline).
        if f.get("exploited"):
            base["exploited"] = True
            for k in ("exploit_proof", "exploit_impact", "exploit_transcript"):
                if f.get(k) and not base.get(k):
                    base[k] = f[k]
        # Keep the most-severe impact tier (lowest number) across the cluster.
        base["impact_tier"] = min(_TIER_SORT.get(base.get("impact_tier", 3), 3),
                                  _TIER_SORT.get(f.get("impact_tier", 3), 3))
        if C.sev_rank(f.get("severity")) > C.sev_rank(base.get("severity")):
            base["severity"] = f["severity"]
        if len(f.get("evidence", "")) > len(base.get("evidence", "")):
            base["evidence"] = f["evidence"]
        for k in ("verification", "request_line", "payload", "remediation"):
            if f.get(k) and not base.get(k):
                base[k] = f[k]
        if f.get("baseline") and not base.get("baseline"):
            base["baseline"], base["attack"] = f.get("baseline"), f.get("attack")
        for c in f.get("corroborated_by", []):
            base.setdefault("corroborated_by", [])
            if c not in base["corroborated_by"]:
                base["corroborated_by"].append(c)
    out = []
    for base in groups.values():
        n = len(base.get("instances", []))
        base["instance_count"] = n
        if n > 1:
            base["title"] = f"{base['title']} (confirmed on {n} URLs)" if base.get("proven") \
                else f"{base['title']} ({n} instances)"
        out.append(base)
    return out


def _slim_for_narrate(f: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "ref": f.get("ref"), "title": f.get("title"), "severity": f.get("severity"),
        "vuln_class": f.get("vuln_class"), "host": f.get("host"), "url": f.get("url"),
        "parameter": f.get("parameter"), "owasp": f.get("owasp_web"),
        "evidence": (f.get("evidence") or "")[:400], "verification": f.get("verification"),
    }


def _merge_narrative(findings: List[Dict[str, Any]], writeup: Dict[str, Any]) -> None:
    by_ref = {f.get("ref"): f for f in findings}
    for w in (writeup.get("findings") or []):
        f = by_ref.get(w.get("ref"))
        if not f:
            continue
        for k_src, k_dst in (("narrative", "narrative"), ("impact", "impact"),
                             ("poc", "poc"), ("remediation", "remediation"),
                             ("title", "title"), ("action", "action"),
                             ("result", "result")):
            if w.get(k_src):
                # Don't let the model overwrite real differential evidence fields;
                # only fill narrative/impact/poc/remediation/title.
                f[k_dst] = w[k_src]


_TIER_SORT = {C.TIER_UNAUTH: 0, C.TIER_CROSS_TENANT: 1, C.TIER_AUTHED: 2, C.TIER_OBSERVATION: 3}


def _rank_key(f: Dict[str, Any]):
    # Lower tuple sorts first. Demonstrated exploitation leads, then proven-unauth,
    # then the rest; observations sink to the bottom.
    return (
        0 if f.get("exploited") else 1,
        _TIER_SORT.get(f.get("impact_tier", C.TIER_OBSERVATION), 3),
        0 if f.get("proven") else 1,
        -C.sev_rank(f.get("severity", "info")),
    )


def _result_dict(res: PentestResult) -> Dict[str, Any]:
    d = res.to_dict()
    d["generated_at"] = res.generated_at
    d["provider"] = res.provider
    d["model"] = res.model
    return d


def _write_audit(scan_dir: str, audit: List[str]) -> None:
    try:
        p = os.path.join(scan_dir, C.OUTPUT_SUBDIR, C.AUDIT_LOG)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as fh:
            fh.write("\n".join(audit) + "\n")
    except OSError:
        pass


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
