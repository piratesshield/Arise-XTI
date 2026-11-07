"""
AriseAI — shared vocabulary and taxonomy.

One source of truth for: the engine's brand/source stamping, severity ordering,
the OWASP mappings the pentester reasons in, the proven-impact ranking tiers, and
the set of vuln classes that can be *live-verified* through the ARISE substrate.
Pure data — no imports, no side effects, safe to import anywhere.
"""

from __future__ import annotations

# --- Branding / stamping -----------------------------------------------------
# Every finding and artifact this engine emits carries these so the dashboard can
# badge AI-authored output and the reconciler can corroborate (not duplicate) it.
ENGINE_NAME = "AriseAI"
ENGINE_SOURCE = "AriseAI"          # goes in finding['source']
ENGINE_TOOL = "ai_analyst"         # goes in finding['tool']
AI_TAG = "ai"                      # dashboard badge key: finding['ai_generated']=True

# Output directory under a scan dir (keeps module numbering after attack_paths).
OUTPUT_SUBDIR = "28_ai_analyst"

# Artifact filenames (no "strix" anywhere — this is AriseAI).
REPORT_MD = "ariseai_pentest_report.md"
FINDINGS_JSON = "ariseai_findings.json"
FINDINGS_CSV = "ariseai_findings.csv"
FINDINGS_SARIF = "ariseai_findings.sarif"
RESULT_JSON = "ai_analyst_result.json"     # machine-readable run record (dashboard reads this)
FINDINGS_DIR = "findings"                  # per-finding PoC markdown files
AUDIT_LOG = "ai_analyst_audit.log"

# --- Severity ----------------------------------------------------------------
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
SEVERITY_RANK = {s: i for i, s in enumerate(reversed(SEVERITY_ORDER))}  # critical=4..info=0


def sev_rank(sev: str) -> int:
    return SEVERITY_RANK.get((sev or "info").lower(), 0)


# A proven exploit never ranks below an unproven one of nominally higher severity.
# The engine sorts by (impact_tier, proven, sev_rank, score).
CVSS_HINT = {"critical": 9.5, "high": 8.0, "medium": 5.5, "low": 3.0, "info": 1.0}

# --- Proven-impact tiers (the ranking spine from the methodology) ------------
TIER_UNAUTH = 0       # proven, reachable without authentication      (highest)
TIER_CROSS_TENANT = 1  # proven cross-tenant / privilege escalation
TIER_AUTHED = 2       # proven, requires an authenticated account
TIER_OBSERVATION = 3  # unproven observation (config / hardening note)  (lowest)

TIER_LABEL = {
    TIER_UNAUTH: "Proven — unauthenticated",
    TIER_CROSS_TENANT: "Proven — cross-tenant / privilege escalation",
    TIER_AUTHED: "Proven — authenticated",
    TIER_OBSERVATION: "Unproven observation",
}

# --- OWASP taxonomy (the pentester's coverage checklist) ---------------------
# OWASP Top 10:2025 (web) — current edition.
OWASP_2025 = {
    "A01": "Broken Access Control (incl. SSRF)",
    "A02": "Security Misconfiguration",
    "A03": "Software Supply Chain Failures",
    "A04": "Cryptographic Failures",
    "A05": "Injection",
    "A06": "Insecure Design",
    "A07": "Authentication Failures",
    "A08": "Software or Data Integrity Failures",
    "A09": "Security Logging & Alerting Failures",
    "A10": "Mishandling of Exceptional Conditions",
}
# OWASP API Security Top 10:2023.
OWASP_API_2023 = {
    "API1": "Broken Object Level Authorization (BOLA/IDOR)",
    "API2": "Broken Authentication",
    "API3": "Broken Object Property Level Authorization",
    "API4": "Unrestricted Resource Consumption",
    "API5": "Broken Function Level Authorization",
    "API6": "Unrestricted Access to Sensitive Business Flows",
    "API7": "Server Side Request Forgery",
    "API8": "Security Misconfiguration",
    "API9": "Improper Inventory Management",
    "API10": "Unsafe Consumption of APIs",
}

# Canonical vuln-class -> (web OWASP id, API OWASP id, CWE). The brain and report
# both key on this so a finding's category is mapped consistently.
VULN_CLASS_MAP = {
    "ssrf":            ("A01", "API7", "CWE-918"),
    "idor":            ("A01", "API1", "CWE-639"),
    "bola":            ("A01", "API1", "CWE-639"),
    "bfla":            ("A01", "API5", "CWE-285"),
    "access-control":  ("A01", "API5", "CWE-284"),
    "auth-bypass":     ("A07", "API2", "CWE-287"),
    "jwt":             ("A07", "API2", "CWE-345"),
    "sqli":            ("A05", "API8", "CWE-89"),
    "nosqli":          ("A05", "API8", "CWE-943"),
    "xss":             ("A05", "API8", "CWE-79"),
    "ssti":            ("A05", "API8", "CWE-1336"),
    "xxe":             ("A05", "API8", "CWE-611"),
    "rce":             ("A05", "API8", "CWE-94"),
    "lfi":             ("A01", "API1", "CWE-22"),
    "crlf":            ("A03", "API8", "CWE-93"),
    "redirect":        ("A01", "API8", "CWE-601"),
    "proto":           ("A08", "API8", "CWE-1321"),
    "cache":           ("A02", "API8", "CWE-525"),
    "race":            ("A06", "API6", "CWE-362"),
    "graphql":         ("A05", "API8", "CWE-284"),
    "json_smuggling":  ("A05", "API8", "CWE-444"),
    "business_logic":  ("A06", "API6", "CWE-840"),
    "secret-exposure": ("A04", "API8", "CWE-200"),
    "info-disclosure": ("A04", "API8", "CWE-200"),
    "misconfig":       ("A02", "API8", "CWE-16"),
    "takeover":        ("A02", "API9", "CWE-350"),
    "cors":            ("A01", "API8", "CWE-942"),
    "ws":              ("A01", "API2", "CWE-1385"),
    "cve":             ("A03", "API8", "CWE-1035"),
}

# Vuln classes AriseAI can actively *live-verify* via offensive_verify.CHECKS.
# Mapped to the check name that engine exposes. Only these can be promoted from
# "hypothesis" to "proven" with fresh live evidence in-run.
LIVE_VERIFIABLE = {
    "ssrf": "ssrf",
    "ssti": "ssti",
    "sqli": None,            # offensive_verify has no sqli check; handled by EASM sqli module
    "nosqli": "nosqli",
    "xxe": "xxe",
    "jwt": "jwt",
    "graphql": "graphql",
    "crlf": "crlf",
    "redirect": "redirect",
    "proto": "proto",
    "cache": "cache",
    "race": "race",
    "bfla": "bfla",
    "business_logic": "business_logic",
    "json_smuggling": "json_smuggling",
    "ws": "ws",
    "info-disclosure": "exposure",
    "misconfig": "exposure",
    "origin_bypass": "origin_bypass",
    "cors": "cors",
    "headers": "headers",
}

# Checks AriseAI ALWAYS runs regardless of what the brain selected — these are
# fast, broad, and find things behind WAF that injection checks never can.
ALWAYS_RUN_CHECKS = ["origin_bypass", "cors", "headers", "exposure"]

# Confidence strings that mean "proven with live evidence" (from offensive_verify
# and the EASM finding schema). Anything else is treated as an observation/lead.
PROVEN_CONFIDENCE = {"exploited", "confirmed", "proven"}


def owasp_for(vuln_class: str):
    """Return ('A0x: name', 'APIx: name', 'CWE-...') for a vuln class, best-effort."""
    key = (vuln_class or "").lower().strip()
    web, api, cwe = VULN_CLASS_MAP.get(key, ("A06", "API8", "CWE-noinfo"))
    web_s = f"{web}: {OWASP_2025.get(web, '')}".strip().rstrip(":")
    api_s = f"{api}: {OWASP_API_2023.get(api, '')}".strip().rstrip(":")
    return web_s, api_s, cwe
