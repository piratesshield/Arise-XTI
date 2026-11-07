"""
AriseAI — Kill Chain State Machine.

Tracks the engagement through ATT&CK tactical phases and auto-generates
pivot hypotheses when findings are proven at one phase, advancing the
engagement to the next.

The key insight: isolated findings become breach paths. A proven SSRF isn't
just "SSRF found" — it's the gateway to cloud metadata → service account
token → cloud API access. The kill chain state machine encodes these pivots
as first-class transitions so AriseAI chains findings automatically.

Pure data + logic. No network, no side effects, safe to import anywhere.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from ai_analyst.adversary import (
    TACTIC_LABELS, TACTIC_ORDER, TECHNIQUES, AdversaryProfile,
)


# ---------------------------------------------------------------------------
# Pivot rules: when finding X is proven, generate hypothesis Y
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class PivotRule:
    trigger_class: str
    trigger_tactic: str
    next_tactic: str
    pivot_title: str
    pivot_class: str
    pivot_rationale: str
    requires_field: str = ""  # only fire if the trigger finding has this field non-empty
    chain_label: str = ""


PIVOT_RULES: List[PivotRule] = [
    # SSRF → credential theft via cloud metadata
    PivotRule("ssrf", "initial-access", "credential-access",
             "Steal cloud service-account token via SSRF to metadata endpoint",
             "ssrf", "Proven SSRF can reach internal hosts — pivot to cloud metadata "
             "(169.254.169.254 / metadata.google.internal) to steal SA tokens",
             chain_label="SSRF → Cloud Token Theft"),

    # SSRF → internal service discovery
    PivotRule("ssrf", "initial-access", "discovery",
             "Discover internal services via SSRF port scan",
             "ssrf", "Proven SSRF — scan internal network for admin panels, databases, "
             "and other services reachable through the proxy",
             chain_label="SSRF → Internal Discovery"),

    # SSRF → lateral movement to internal APIs
    PivotRule("ssrf", "credential-access", "lateral-movement",
             "Access internal APIs using stolen cloud credentials via SSRF",
             "ssrf", "Cloud token obtained via SSRF — pivot to internal APIs, "
             "cloud storage, or management consoles",
             chain_label="SSRF → Cloud API Lateral"),

    # SQLi → credential dump
    PivotRule("sqli", "initial-access", "credential-access",
             "Read database credentials/hashes via confirmed SQL injection",
             "sqli", "Proven SQLi — enumerate database users, read password hashes, "
             "and check for plaintext credentials in related tables",
             chain_label="SQLi → Credential Harvest"),

    # SQLi → data access
    PivotRule("sqli", "credential-access", "collection",
             "Read sensitive data from database via SQL injection",
             "sqli", "Database access confirmed — read application data tables "
             "(users, orders, payment info) to prove data exposure impact",
             chain_label="SQLi → Data Access"),

    # XSS → session hijack → account takeover
    PivotRule("xss", "initial-access", "credential-access",
             "Steal session tokens via proven stored/reflected XSS",
             "xss", "Proven XSS — check if HttpOnly flag is missing on session cookies; "
             "if so, session hijack is feasible",
             chain_label="XSS → Session Theft"),

    PivotRule("xss", "credential-access", "impact",
             "Achieve account takeover via stolen session from XSS",
             "xss", "Session token stealable — prove account takeover by accessing "
             "authenticated endpoints with the stolen session",
             chain_label="XSS → Account Takeover"),

    # RCE/SSTI → system discovery
    PivotRule("rce", "execution", "discovery",
             "Enumerate system context after proven code execution",
             "rce", "Proven RCE — read hostname, user context, environment variables, "
             "and network interfaces to map blast radius",
             chain_label="RCE → System Discovery"),

    PivotRule("ssti", "execution", "discovery",
             "Enumerate system context after proven SSTI→RCE",
             "ssti", "Proven SSTI with code execution — map the system context "
             "(user, hostname, env) to assess lateral movement potential",
             chain_label="SSTI → System Discovery"),

    # RCE → credential access
    PivotRule("rce", "discovery", "credential-access",
             "Read credentials from environment/config after proven RCE",
             "rce", "System context mapped — read environment variables, config files, "
             "and cloud metadata for credential material",
             chain_label="RCE → Credential Harvest"),

    # Auth bypass → privilege escalation
    PivotRule("auth-bypass", "initial-access", "privilege-escalation",
             "Escalate from bypassed auth to admin functionality",
             "auth-bypass", "Authentication bypassed — test admin-only endpoints and "
             "privilege-gated operations accessible without proper authorization",
             chain_label="Auth Bypass → Admin Escalation"),

    # JWT forge → privilege escalation
    PivotRule("jwt", "initial-access", "privilege-escalation",
             "Forge admin-level JWT after algorithm confusion/weak secret",
             "jwt", "JWT weakness proven — forge a token with admin role/elevated "
             "claims and test access to privileged endpoints",
             chain_label="JWT → Admin Forge"),

    # BOLA/IDOR → data enumeration
    PivotRule("bola", "initial-access", "collection",
             "Enumerate cross-tenant data via proven BOLA/IDOR",
             "bola", "IDOR confirmed — enumerate accessible object IDs to prove "
             "scope of data exposure (user records, orders, documents)",
             chain_label="BOLA → Data Enumeration"),

    # Secret exposure → valid accounts
    PivotRule("secret-exposure", "credential-access", "initial-access",
             "Authenticate using exposed credentials/tokens",
             "auth-bypass", "Credentials exposed — test if they grant access to APIs, "
             "admin panels, or third-party services",
             chain_label="Leaked Creds → Account Access"),

    # Subdomain takeover → impact
    PivotRule("takeover", "initial-access", "impact",
             "Prove impact via subdomain takeover — cookie scope, phishing surface",
             "takeover", "Subdomain takeover confirmed — check if the parent domain's "
             "cookies are scoped to include the taken-over subdomain (cookie theft), "
             "and assess phishing/brand-abuse surface",
             chain_label="Takeover → Cookie/Brand Abuse"),

    # GraphQL introspection → data access
    PivotRule("graphql", "discovery", "collection",
             "Access sensitive data via GraphQL queries after introspection",
             "graphql", "GraphQL schema exposed — craft queries for sensitive types "
             "(User, Payment, Order) and test authorization on each resolver",
             chain_label="GraphQL → Data Access"),

    # Business logic → financial impact
    PivotRule("business_logic", "initial-access", "impact",
             "Prove financial impact from business logic flaw",
             "business_logic", "Business logic flaw confirmed — test edge cases: "
             "negative quantities, race conditions on balance, coupon reuse, "
             "price manipulation",
             chain_label="Logic Flaw → Financial Impact"),

    # Race condition → financial impact
    PivotRule("race", "initial-access", "impact",
             "Exploit race condition for double-spend or duplicate action",
             "race", "Race condition confirmed — prove financial impact: double-spend, "
             "duplicate redemption, or concurrent state corruption",
             chain_label="Race → Double-Spend"),

    # LFI → credential access
    PivotRule("lfi", "initial-access", "credential-access",
             "Read sensitive files via proven local file inclusion",
             "lfi", "LFI confirmed — read /etc/passwd, config files with credentials, "
             "environment files, or cloud metadata via file:// wrapper",
             chain_label="LFI → Credential Read"),

    # Misconfig → deeper discovery
    PivotRule("misconfig", "discovery", "credential-access",
             "Harvest credentials from exposed configuration/admin interfaces",
             "secret-exposure", "Misconfiguration exposes admin interfaces — check for "
             "default credentials, exposed debug endpoints, environment variables",
             chain_label="Misconfig → Credential Harvest"),
]


# ---------------------------------------------------------------------------
# Kill chain state
# ---------------------------------------------------------------------------
@dataclass
class KillChainPhase:
    tactic: str
    label: str
    entered: bool = False
    entered_at: Optional[str] = None
    findings: List[str] = field(default_factory=list)
    techniques_exercised: List[str] = field(default_factory=list)


@dataclass
class KillChainState:
    """Tracks the engagement's progression through ATT&CK tactical phases."""
    phases: Dict[str, KillChainPhase] = field(default_factory=dict)
    chains: List[Dict[str, Any]] = field(default_factory=list)
    pivots_generated: List[Dict[str, Any]] = field(default_factory=list)
    deepest_tactic: str = "reconnaissance"
    started_at: str = ""

    def __post_init__(self):
        if not self.phases:
            for tac in TACTIC_ORDER:
                self.phases[tac] = KillChainPhase(
                    tactic=tac, label=TACTIC_LABELS.get(tac, tac))
        if not self.started_at:
            self.started_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    def advance(self, tactic: str, finding_ref: str,
                technique_id: str = "") -> bool:
        """Record that a finding proved something in this tactic. Returns True
        if this is a NEW phase entry (the engagement advanced)."""
        phase = self.phases.get(tactic)
        if not phase:
            return False
        newly_entered = not phase.entered
        phase.entered = True
        if not phase.entered_at:
            phase.entered_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        if finding_ref and finding_ref not in phase.findings:
            phase.findings.append(finding_ref)
        if technique_id and technique_id not in phase.techniques_exercised:
            phase.techniques_exercised.append(technique_id)
        tactic_idx = TACTIC_ORDER.index(tactic) if tactic in TACTIC_ORDER else -1
        deepest_idx = TACTIC_ORDER.index(self.deepest_tactic) if self.deepest_tactic in TACTIC_ORDER else -1
        if tactic_idx > deepest_idx:
            self.deepest_tactic = tactic
        return newly_entered

    @property
    def active_phases(self) -> List[KillChainPhase]:
        return [p for p in self.phases.values() if p.entered]

    @property
    def depth(self) -> int:
        if self.deepest_tactic not in TACTIC_ORDER:
            return 0
        return TACTIC_ORDER.index(self.deepest_tactic) + 1

    def to_dict(self) -> Dict[str, Any]:
        return {
            "started_at": self.started_at,
            "deepest_tactic": self.deepest_tactic,
            "depth": self.depth,
            "phases": {
                tac: {
                    "label": p.label,
                    "entered": p.entered,
                    "entered_at": p.entered_at,
                    "finding_count": len(p.findings),
                    "techniques": p.techniques_exercised,
                } for tac, p in self.phases.items()
            },
            "chains": self.chains,
            "pivots_generated": len(self.pivots_generated),
        }


# ---------------------------------------------------------------------------
# Orchestration API
# ---------------------------------------------------------------------------
def init_chain(profile: Optional[AdversaryProfile] = None) -> KillChainState:
    state = KillChainState()
    state.advance("reconnaissance", "easm-recon")
    return state


def classify_tactic(vuln_class: str, proven: bool = False) -> str:
    """Map a vuln_class to its primary ATT&CK tactic."""
    _MAP = {
        "ssrf": "initial-access", "sqli": "initial-access",
        "nosqli": "initial-access", "xss": "initial-access",
        "ssti": "execution", "xxe": "initial-access",
        "rce": "execution", "lfi": "initial-access",
        "crlf": "initial-access", "proto": "initial-access",
        "graphql": "discovery", "json_smuggling": "initial-access",
        "bola": "initial-access", "bfla": "privilege-escalation",
        "idor": "initial-access", "access-control": "privilege-escalation",
        "auth-bypass": "initial-access", "jwt": "initial-access",
        "redirect": "initial-access", "cache": "initial-access",
        "race": "initial-access", "ws": "initial-access",
        "business_logic": "initial-access",
        "secret-exposure": "credential-access",
        "info-disclosure": "discovery",
        "misconfig": "discovery",
        "takeover": "initial-access",
        "cors": "initial-access",
        "cve": "initial-access",
    }
    return _MAP.get((vuln_class or "").lower(), "initial-access" if proven else "reconnaissance")


def advance_on_finding(state: KillChainState, finding: Dict[str, Any],
                       profile: Optional[AdversaryProfile] = None) -> List[Dict[str, Any]]:
    """Process a proven finding: advance the kill chain and generate pivot hypotheses.

    Returns a list of new hypotheses the engine should add to its plan."""
    vc = (finding.get("vuln_class") or "").lower()
    ref = finding.get("ref", "")
    host = finding.get("host", "")

    tactic = classify_tactic(vc, finding.get("proven", False))
    technique_id = ""
    if profile:
        tech = profile.technique_for_vuln(vc)
        if tech:
            technique_id = tech.tid

    newly_entered = state.advance(tactic, ref, technique_id)

    pivots = _generate_pivots(state, finding, vc, tactic, host, profile)
    state.pivots_generated.extend(pivots)

    if newly_entered and pivots:
        chain_entry = {
            "trigger": ref,
            "trigger_class": vc,
            "trigger_tactic": tactic,
            "pivots": [p.get("id", "") for p in pivots],
            "label": pivots[0].get("chain_label", f"{vc} → pivot"),
        }
        state.chains.append(chain_entry)

    return pivots


def _generate_pivots(state: KillChainState, finding: Dict[str, Any],
                     vuln_class: str, tactic: str, host: str,
                     profile: Optional[AdversaryProfile] = None) -> List[Dict[str, Any]]:
    """Generate pivot hypotheses from matching rules."""
    pivots: List[Dict[str, Any]] = []
    seen_titles: Set[str] = set()
    profile_classes = profile.vuln_classes if profile else None

    for rule in PIVOT_RULES:
        if rule.trigger_class != vuln_class:
            continue
        if rule.trigger_tactic != tactic:
            continue
        if rule.requires_field and not finding.get(rule.requires_field):
            continue
        if profile_classes is not None and rule.pivot_class not in profile_classes:
            continue
        already_deep = state.phases.get(rule.next_tactic, KillChainPhase("", ""))
        if already_deep.entered and len(already_deep.findings) >= 3:
            continue
        if rule.pivot_title in seen_titles:
            continue
        seen_titles.add(rule.pivot_title)

        pivot = {
            "id": f"pivot-{vuln_class}-{rule.next_tactic}-{len(pivots)}",
            "title": f"{rule.pivot_title} on {host}" if host else rule.pivot_title,
            "vuln_class": rule.pivot_class,
            "target_host": host,
            "target_url": finding.get("url", ""),
            "parameter": finding.get("parameter", ""),
            "chain": [vuln_class, rule.next_tactic.replace("-", " "), rule.pivot_title.split(" ")[0].lower()],
            "based_on": [finding.get("title", vuln_class)],
            "impact": rule.pivot_rationale,
            "owasp": "",
            "live_verifiable": True,
            "confidence": "high",
            "waf_considered": finding.get("waf_considered", "none"),
            "alternatives": "The trigger finding may not chain — WAF or network segmentation could block the pivot",
            "pivot_from": finding.get("ref", ""),
            "pivot_rule": rule.chain_label,
            "chain_label": rule.chain_label,
            "mitre_tactic": rule.next_tactic,
            "adversary_in_scope": True,
        }
        pivots.append(pivot)

    return pivots[:4]


def build_chain_narrative(state: KillChainState,
                          profile: Optional[AdversaryProfile] = None) -> Dict[str, Any]:
    """Produce a structured kill chain summary for the report and dashboard."""
    phase_timeline = []
    for tac in TACTIC_ORDER:
        phase = state.phases.get(tac)
        if phase and phase.entered:
            phase_timeline.append({
                "tactic": tac,
                "label": phase.label,
                "entered_at": phase.entered_at,
                "finding_count": len(phase.findings),
                "techniques": phase.techniques_exercised,
            })

    breach_paths = []
    for chain in state.chains:
        breach_paths.append({
            "name": chain.get("label", ""),
            "trigger": chain.get("trigger_class", ""),
            "pivots": chain.get("pivots", []),
            "depth": len(chain.get("pivots", [])) + 1,
        })

    return {
        "adversary": profile.name if profile else "Opportunistic",
        "engagement_depth": state.depth,
        "deepest_tactic": TACTIC_LABELS.get(state.deepest_tactic, state.deepest_tactic),
        "phase_timeline": phase_timeline,
        "breach_paths": breach_paths,
        "pivots_generated": len(state.pivots_generated),
        "summary": _chain_summary(state, profile),
    }


def _chain_summary(state: KillChainState,
                   profile: Optional[AdversaryProfile] = None) -> str:
    active = [p for p in state.phases.values() if p.entered]
    if len(active) <= 1:
        return "Engagement limited to reconnaissance — no exploitation achieved."
    deepest = TACTIC_LABELS.get(state.deepest_tactic, state.deepest_tactic)
    n_chains = len(state.chains)
    name = profile.name if profile else "the attacker"
    if state.depth >= 7:
        return (f"Critical: {name} achieved deep penetration through {deepest} "
                f"with {n_chains} attack chain(s). Full breach path demonstrated.")
    if state.depth >= 4:
        return (f"Significant: {name} advanced to {deepest} with {n_chains} chain(s). "
                f"Multiple exploitation stages confirmed.")
    return (f"{name} achieved {deepest} with {n_chains} chain(s). "
            f"Limited exploitation depth — defensive controls may be effective.")
