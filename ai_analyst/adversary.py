"""
AriseAI — Adversary Emulation Profiles (MITRE ATT&CK-mapped).

Each profile models a real-world threat actor's TTP repertoire so AriseAI
can run the engagement *as* that adversary: filter hypotheses to techniques
the actor actually uses, weight attack chains by the actor's known playbook,
steer the brain's persona and objectives, and report ATT&CK coverage.

Posture is unchanged — read-only, prove-impact, scope-locked. The adversary
profile shapes WHAT AriseAI looks for, not what it's allowed to do.

Profiles are pure data. No imports beyond stdlib, no side effects.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Optional, Set, Tuple


# ---------------------------------------------------------------------------
# ATT&CK technique catalog (external-only, black-box-feasible subset)
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Technique:
    tid: str
    name: str
    tactic: str
    vuln_classes: FrozenSet[str] = frozenset()
    description: str = ""


TECHNIQUES: Dict[str, Technique] = {}


def _t(tid, name, tactic, vuln_classes=(), desc=""):
    tech = Technique(tid, name, tactic, frozenset(vuln_classes), desc)
    TECHNIQUES[tid] = tech
    return tid


# -- Reconnaissance
T_RECON_SCAN       = _t("T1595.002", "Active Scanning: Vulnerability Scanning", "reconnaissance")
T_RECON_GATHER     = _t("T1592",     "Gather Victim Host Information",          "reconnaissance")
T_RECON_NETWORK    = _t("T1590",     "Gather Victim Network Information",       "reconnaissance")
T_RECON_IDENTITY   = _t("T1589",     "Gather Victim Identity Information",      "reconnaissance")
T_RECON_OSINT      = _t("T1593",     "Search Open Websites/Domains",            "reconnaissance")
T_RECON_TECH       = _t("T1592.004", "Gather Client Configurations",            "reconnaissance")

# -- Initial Access
T_EXPLOIT_PUBLIC   = _t("T1190", "Exploit Public-Facing Application", "initial-access",
                         ("sqli", "nosqli", "xss", "ssti", "xxe", "rce", "lfi", "crlf",
                          "proto", "graphql", "json_smuggling"),
                         "Exploit a vulnerability in an internet-facing app")
T_SUPPLY_CHAIN     = _t("T1195", "Supply Chain Compromise",          "initial-access",
                         ("cve", "takeover"),
                         "Compromise via third-party dependency or subdomain takeover")
T_TRUSTED_REL      = _t("T1199", "Trusted Relationship",             "initial-access",
                         ("ssrf", "cors"),
                         "Abuse trust between services — SSRF, permissive CORS")
T_VALID_ACCTS      = _t("T1078", "Valid Accounts",                   "initial-access",
                         ("auth-bypass", "jwt", "secret-exposure"),
                         "Use leaked/forged credentials or tokens")
T_PHISHING         = _t("T1566", "Phishing",                         "initial-access")

# -- Execution
T_COMMAND_EXEC     = _t("T1059", "Command and Scripting Interpreter", "execution",
                         ("rce", "ssti", "xxe"),
                         "Achieve code execution on the target")
T_EXPLOIT_API      = _t("T1106", "Native API",                       "execution",
                         ("graphql", "business_logic"),
                         "Abuse application-level APIs")

# -- Privilege Escalation
T_EXPLOIT_PRIV     = _t("T1068", "Exploitation for Privilege Escalation", "privilege-escalation",
                         ("bola", "bfla", "idor", "access-control", "jwt"),
                         "Escalate from low to high privilege via app flaw")
T_ACCESS_TOKEN     = _t("T1134", "Access Token Manipulation",            "privilege-escalation",
                         ("jwt",),
                         "Forge or tamper with auth tokens to gain higher privileges")

# -- Credential Access
T_UNSECURED_CREDS  = _t("T1552", "Unsecured Credentials",            "credential-access",
                         ("secret-exposure", "info-disclosure", "misconfig"),
                         "Harvest credentials from exposed configs, env vars, or metadata")
T_STEAL_TOKEN      = _t("T1528", "Steal Application Access Token",   "credential-access",
                         ("ssrf", "xss", "jwt"),
                         "Steal OAuth/JWT tokens via SSRF to metadata or XSS exfil")
T_BRUTE_FORCE      = _t("T1110", "Brute Force",                      "credential-access",
                         ("auth-bypass",))

# -- Discovery
T_CLOUD_DISCOVERY  = _t("T1580", "Cloud Infrastructure Discovery",   "discovery",
                         ("ssrf", "misconfig"),
                         "Discover cloud services via SSRF to metadata or exposed dashboards")
T_NETWORK_SNIFF    = _t("T1040", "Network Service Discovery",        "discovery",
                         ("info-disclosure",))
T_APP_DISCOVERY    = _t("T1087", "Account Discovery",                "discovery",
                         ("bola", "graphql", "info-disclosure"),
                         "Enumerate users/roles via IDOR or introspection")

# -- Lateral Movement
T_LATERAL_SSRF     = _t("T1021.001", "Lateral via SSRF / Internal Service", "lateral-movement",
                         ("ssrf",),
                         "Pivot from an SSRF to internal services — metadata, DBs, admin panels")
T_INTERNAL_PROXY   = _t("T1090", "Proxy: Internal Proxy",             "lateral-movement",
                         ("ssrf", "redirect"),
                         "Use an SSRF or redirect as a proxy to reach internal hosts")

# -- Collection
T_DATA_STAGED      = _t("T1074", "Data Staged",                      "collection",
                         ("sqli", "nosqli", "bola", "graphql"),
                         "Read data from the application backend")

# -- Impact
T_DATA_DESTRUCTION = _t("T1485", "Data Destruction",                  "impact")
T_DEFACEMENT       = _t("T1491", "Defacement",                       "impact", ("xss",))
T_ACCOUNT_TAKEOVER = _t("T1531", "Account Access Removal",           "impact",
                         ("auth-bypass", "jwt", "xss"),
                         "Full account takeover — session hijack, password reset abuse")

# -- Defense Evasion
T_WAF_BYPASS       = _t("T1562.001", "Impair Defenses: Disable or Modify Tools", "defense-evasion",
                         ("auth-bypass",),
                         "Bypass WAF/security controls to reach the application")


# ---------------------------------------------------------------------------
# ATT&CK tactics in kill chain order (external engagement)
# ---------------------------------------------------------------------------
TACTIC_ORDER = [
    "reconnaissance",
    "initial-access",
    "execution",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "impact",
]

TACTIC_LABELS = {
    "reconnaissance":        "Reconnaissance",
    "initial-access":        "Initial Access",
    "execution":             "Execution",
    "privilege-escalation":  "Privilege Escalation",
    "defense-evasion":       "Defense Evasion",
    "credential-access":     "Credential Access",
    "discovery":             "Discovery",
    "lateral-movement":      "Lateral Movement",
    "collection":            "Collection",
    "impact":                "Impact",
}


# ---------------------------------------------------------------------------
# Adversary profiles
# ---------------------------------------------------------------------------
@dataclass
class AdversaryProfile:
    name: str
    aliases: List[str]
    description: str
    objectives: List[str]
    techniques: List[str]
    preferred_chains: List[List[str]]
    noise_level: str  # "stealth" | "moderate" | "loud"
    target_sectors: List[str]
    persona_overlay: str  # injected into the brain persona
    vuln_priority: List[str] = field(default_factory=list)

    @property
    def technique_set(self) -> Set[str]:
        return set(self.techniques)

    @property
    def vuln_classes(self) -> Set[str]:
        """All vuln_classes this adversary's TTP repertoire can exploit."""
        out: Set[str] = set()
        for tid in self.techniques:
            t = TECHNIQUES.get(tid)
            if t:
                out |= t.vuln_classes
        return out

    @property
    def tactics_covered(self) -> List[str]:
        seen = set()
        for tid in self.techniques:
            t = TECHNIQUES.get(tid)
            if t:
                seen.add(t.tactic)
        return [tc for tc in TACTIC_ORDER if tc in seen]

    def technique_for_vuln(self, vuln_class: str) -> Optional[Technique]:
        for tid in self.techniques:
            t = TECHNIQUES.get(tid)
            if t and vuln_class in t.vuln_classes:
                return t
        return None

    def brief(self) -> Dict:
        return {
            "name": self.name,
            "aliases": self.aliases,
            "description": self.description,
            "objectives": self.objectives,
            "noise_level": self.noise_level,
            "tactics_covered": self.tactics_covered,
            "technique_count": len(self.techniques),
            "vuln_classes": sorted(self.vuln_classes),
        }


# ---------------------------------------------------------------------------
# Profile definitions (real-world threat actors)
# ---------------------------------------------------------------------------
PROFILES: Dict[str, AdversaryProfile] = {}


def _register(p: AdversaryProfile):
    PROFILES[p.name.lower()] = p
    for alias in p.aliases:
        PROFILES[alias.lower()] = p
    return p


APT29 = _register(AdversaryProfile(
    name="APT29",
    aliases=["cozy-bear", "midnight-blizzard", "nobelium", "the-dukes"],
    description="Russian state-sponsored actor (SVR). Patient, stealthy, cloud-focused. "
                "Known for SolarWinds supply chain, OAuth abuse, cloud API pivots.",
    objectives=[
        "Gain persistent access to cloud infrastructure",
        "Steal authentication tokens and pivot to cloud APIs",
        "Exfiltrate sensitive data through trusted channels",
        "Maintain long-term covert access",
    ],
    techniques=[
        T_RECON_SCAN, T_RECON_GATHER, T_RECON_NETWORK, T_RECON_OSINT, T_RECON_TECH,
        T_EXPLOIT_PUBLIC, T_SUPPLY_CHAIN, T_TRUSTED_REL, T_VALID_ACCTS,
        T_EXPLOIT_PRIV, T_ACCESS_TOKEN,
        T_UNSECURED_CREDS, T_STEAL_TOKEN,
        T_CLOUD_DISCOVERY, T_APP_DISCOVERY,
        T_LATERAL_SSRF, T_INTERNAL_PROXY,
        T_DATA_STAGED,
        T_WAF_BYPASS,
    ],
    preferred_chains=[
        ["ssrf", "cloud-metadata", "service-account-token", "cloud-api-access"],
        ["secret-exposure", "valid-credentials", "api-access", "data-exfiltration"],
        ["jwt", "token-forge", "privilege-escalation", "admin-access"],
        ["takeover", "subdomain-control", "cookie-theft", "account-takeover"],
    ],
    noise_level="stealth",
    target_sectors=["government", "technology", "defense", "energy"],
    persona_overlay=(
        "You are emulating APT29 (Cozy Bear / Midnight Blizzard). You think like a "
        "patient, methodical state-sponsored operator. Prioritize: (1) SSRF→cloud metadata→token "
        "theft, (2) leaked credentials→API pivot, (3) subdomain takeover→cookie scope. "
        "Avoid noisy attacks. Prefer chaining low-severity findings into high-impact paths. "
        "Cloud infrastructure compromise is your endgame."
    ),
    vuln_priority=["ssrf", "secret-exposure", "jwt", "takeover", "auth-bypass", "bola"],
))

FIN7 = _register(AdversaryProfile(
    name="FIN7",
    aliases=["carbon-spider", "sangria-tempest"],
    description="Financially motivated cybercrime group. Targets payment systems, POS, "
                "and e-commerce. Known for web skimming, SQLi for card data, business logic abuse.",
    objectives=[
        "Access payment card data and PII",
        "Exploit business logic flaws for financial gain",
        "Compromise e-commerce checkout flows",
        "Harvest credentials for account takeover",
    ],
    techniques=[
        T_RECON_SCAN, T_RECON_GATHER, T_RECON_OSINT,
        T_EXPLOIT_PUBLIC, T_VALID_ACCTS,
        T_COMMAND_EXEC, T_EXPLOIT_API,
        T_EXPLOIT_PRIV,
        T_UNSECURED_CREDS, T_BRUTE_FORCE,
        T_APP_DISCOVERY,
        T_DATA_STAGED,
        T_ACCOUNT_TAKEOVER,
    ],
    preferred_chains=[
        ["sqli", "database-access", "card-data-read", "data-exfiltration"],
        ["xss", "session-hijack", "account-takeover", "payment-fraud"],
        ["bola", "idor-enumeration", "pii-harvest", "identity-theft"],
        ["auth-bypass", "admin-access", "business-logic", "financial-loss"],
    ],
    noise_level="moderate",
    target_sectors=["retail", "hospitality", "financial", "e-commerce"],
    persona_overlay=(
        "You are emulating FIN7 (Carbon Spider). You are a financially motivated operator. "
        "Prioritize: (1) SQLi→database read (look for card/PII tables), (2) XSS→session "
        "hijack on checkout/payment pages, (3) BOLA/IDOR on order/user endpoints for PII "
        "enumeration, (4) business logic flaws in pricing/discount/payment flows. "
        "Data theft and financial fraud are your endgame."
    ),
    vuln_priority=["sqli", "xss", "bola", "business_logic", "auth-bypass", "secret-exposure"],
))

APT28 = _register(AdversaryProfile(
    name="APT28",
    aliases=["fancy-bear", "forest-blizzard", "sofacy", "strontium"],
    description="Russian military intelligence (GRU Unit 26165). Aggressive, fast-moving. "
                "Credential harvesting, web exploits, rapid escalation.",
    objectives=[
        "Rapidly gain access through web application exploits",
        "Harvest credentials and authentication material",
        "Escalate privileges quickly and pivot",
        "Disrupt or deface if primary mission fails",
    ],
    techniques=[
        T_RECON_SCAN, T_RECON_GATHER, T_RECON_IDENTITY, T_RECON_OSINT,
        T_EXPLOIT_PUBLIC, T_VALID_ACCTS, T_PHISHING,
        T_COMMAND_EXEC,
        T_EXPLOIT_PRIV, T_ACCESS_TOKEN,
        T_UNSECURED_CREDS, T_STEAL_TOKEN, T_BRUTE_FORCE,
        T_APP_DISCOVERY, T_NETWORK_SNIFF,
        T_LATERAL_SSRF,
        T_DATA_STAGED,
        T_DEFACEMENT, T_ACCOUNT_TAKEOVER,
        T_WAF_BYPASS,
    ],
    preferred_chains=[
        ["rce", "command-exec", "credential-dump", "lateral-movement"],
        ["sqli", "auth-bypass", "admin-access", "defacement"],
        ["xss", "credential-theft", "account-takeover", "data-access"],
        ["ssti", "rce", "system-access", "persistence"],
    ],
    noise_level="loud",
    target_sectors=["government", "military", "media", "political"],
    persona_overlay=(
        "You are emulating APT28 (Fancy Bear). You are an aggressive, fast-moving military "
        "intelligence operator. Prioritize: (1) any RCE/SSTI/XXE for immediate code execution, "
        "(2) SQLi for credential theft, (3) XSS for session hijack on auth pages, (4) auth-bypass "
        "for admin access. Speed over stealth — test every injection surface. "
        "Code execution and credential access are your endgame."
    ),
    vuln_priority=["rce", "ssti", "sqli", "xxe", "xss", "auth-bypass", "lfi"],
))

LAZARUS = _register(AdversaryProfile(
    name="Lazarus",
    aliases=["lazarus-group", "hidden-cobra", "diamond-sleet", "zinc"],
    description="North Korean state-sponsored (RGB). Financially motivated + espionage. "
                "Targets crypto, fintech, supply chains. Known for creative exploitation.",
    objectives=[
        "Compromise cryptocurrency and financial platforms",
        "Exploit supply chain dependencies",
        "Steal financial assets and credentials",
        "Maintain persistent access for ongoing theft",
    ],
    techniques=[
        T_RECON_SCAN, T_RECON_GATHER, T_RECON_OSINT, T_RECON_TECH,
        T_EXPLOIT_PUBLIC, T_SUPPLY_CHAIN, T_TRUSTED_REL,
        T_COMMAND_EXEC, T_EXPLOIT_API,
        T_EXPLOIT_PRIV, T_ACCESS_TOKEN,
        T_UNSECURED_CREDS, T_STEAL_TOKEN,
        T_CLOUD_DISCOVERY,
        T_LATERAL_SSRF,
        T_DATA_STAGED,
        T_ACCOUNT_TAKEOVER,
    ],
    preferred_chains=[
        ["ssrf", "internal-api", "financial-transaction", "asset-theft"],
        ["jwt", "token-forge", "admin-access", "fund-transfer"],
        ["takeover", "supply-chain", "code-injection", "credential-harvest"],
        ["business_logic", "race-condition", "double-spend", "financial-loss"],
    ],
    noise_level="moderate",
    target_sectors=["cryptocurrency", "financial", "technology", "defense"],
    persona_overlay=(
        "You are emulating Lazarus Group (Hidden Cobra). You target financial systems and "
        "cryptocurrency platforms. Prioritize: (1) business logic flaws in transaction/payment "
        "flows (race conditions, double-spend), (2) SSRF→internal financial APIs, (3) JWT "
        "forgery for admin/privileged access, (4) supply chain via subdomain takeover. "
        "Financial asset theft is your endgame."
    ),
    vuln_priority=["business_logic", "race", "ssrf", "jwt", "takeover", "auth-bypass"],
))

OPPORTUNISTIC = _register(AdversaryProfile(
    name="Opportunistic",
    aliases=["generic", "default", "script-kiddie", "ransomware-affiliate"],
    description="Opportunistic attacker — automated scanning + manual escalation. "
                "No specific TTP preference; tests everything the surface exposes.",
    objectives=[
        "Find and exploit the lowest-hanging fruit",
        "Maximize impact with minimal effort",
        "Chain any available findings into access",
        "Prove the worst realistic outcome",
    ],
    techniques=list(TECHNIQUES.keys()),
    preferred_chains=[
        ["sqli", "database-access", "credential-dump", "account-takeover"],
        ["ssrf", "cloud-metadata", "token-theft", "cloud-access"],
        ["rce", "system-access", "data-exfiltration"],
        ["auth-bypass", "admin-panel", "full-control"],
        ["xss", "session-hijack", "account-takeover"],
    ],
    noise_level="loud",
    target_sectors=["any"],
    persona_overlay=(
        "You are an opportunistic attacker. Test every exploitable surface — no filtering "
        "by actor TTP. Prioritize by proven impact: (1) any RCE/SSRF/SQLi for maximum "
        "blast radius, (2) auth-bypass and privilege escalation, (3) data access via BOLA/IDOR, "
        "(4) credential exposure. Prove the worst realistic outcome."
    ),
    vuln_priority=[],
))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def get_profile(name: str) -> Optional[AdversaryProfile]:
    return PROFILES.get((name or "").lower().strip())


def list_profiles() -> List[Dict]:
    seen = set()
    out = []
    for p in PROFILES.values():
        if p.name not in seen:
            seen.add(p.name)
            out.append(p.brief())
    return out


def filter_hypotheses(hypotheses: List[dict], profile: AdversaryProfile) -> List[dict]:
    """Reorder and annotate hypotheses based on the adversary's TTP repertoire.

    In-scope hypotheses (vuln_class matches the actor's techniques) are boosted;
    out-of-scope ones get an adversary_note but are kept (they still matter for
    the full engagement view)."""
    allowed = profile.vuln_classes
    priority = {vc: i for i, vc in enumerate(profile.vuln_priority)}

    for h in hypotheses:
        vc = (h.get("vuln_class") or "").lower()
        if vc in allowed:
            h["adversary_in_scope"] = True
            tech = profile.technique_for_vuln(vc)
            if tech:
                h["mitre_technique"] = tech.tid
                h["mitre_tactic"] = tech.tactic
        else:
            h["adversary_in_scope"] = False
            h["adversary_note"] = f"outside {profile.name} TTP repertoire"

    def _sort_key(h):
        vc = (h.get("vuln_class") or "").lower()
        in_scope = 0 if h.get("adversary_in_scope") else 1
        prio = priority.get(vc, 99)
        return (in_scope, prio, h.get("status") == "rejected")

    hypotheses.sort(key=_sort_key)
    return hypotheses


def attack_coverage(profile: AdversaryProfile,
                    proven_classes: Set[str]) -> Dict:
    """Report ATT&CK technique coverage: which of the actor's techniques were
    exercised by proven findings."""
    exercised = set()
    for vc in proven_classes:
        for tid in profile.techniques:
            t = TECHNIQUES.get(tid)
            if t and vc in t.vuln_classes:
                exercised.add(tid)

    by_tactic: Dict[str, List[Dict]] = {}
    for tid in profile.techniques:
        t = TECHNIQUES.get(tid)
        if not t:
            continue
        entry = {
            "tid": t.tid, "name": t.name,
            "exercised": tid in exercised,
        }
        by_tactic.setdefault(t.tactic, []).append(entry)

    return {
        "adversary": profile.name,
        "total_techniques": len(profile.techniques),
        "exercised": len(exercised),
        "coverage_pct": round(100 * len(exercised) / max(len(profile.techniques), 1), 1),
        "by_tactic": {
            tac: techs for tac in TACTIC_ORDER
            if (techs := by_tactic.get(tac))
        },
    }
