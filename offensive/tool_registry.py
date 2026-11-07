#!/usr/bin/env python3
"""
ARISE — Offensive Tool Registry  (Offensive AI Elevation, Phase 2)
==================================================================
A single, typed catalogue of EVERY ARISE-developed capability the Autonomous /
Offensive brain may wield — not just the 16 native checks and 10 generic CLIs,
but ARISE's own purpose-built engines across attack, cloud, API-security, recon,
the R1-R8 evidence/identity layer, and passive intel.

Two jobs:

  1. GIVE THE AI ITS OWN ARSENAL — today the brain shells out to 10 generic CLIs
     and is blind to ~35 ARISE modules that already exist. It reinvents WAF-bypass
     with curl while discovery/bypass_403.py sits unused. This registry describes
     the whole toolbox so a model can choose the RIGHT ARISE engine.

  2. KILL DIVERGENT DUPLICATES (anti-overlap) — every capability declares the
     canonical `vuln_class` it emits (the SAME taxonomy finding_reconciler keys
     on). Dispatch to the one canonical engine for a class instead of hand-rolling
     it ⇒ every result speaks the differential-evidence dialect ⇒ it reconciles
     cleanly. One code path per vuln class.

EXECUTION HONESTY (do no harm)
  - `wired=True`  → invoke() is live NOW. The 16 native offensive_verify checks
    are wired: they call the existing offensive_verify.run(only=[check]) with full
    ScopeGuard/Inventory plumbing, no reimplementation.
  - `wired=False` → KNOWLEDGE is registered (summary / when_to_use / vuln_class /
    module path / safety class) so the brain is AWARE of the engine and can plan
    with it, but a subprocess/adapter is not attached yet. These are wired
    incrementally by later phases — never faked.
  - Metadata-only import: safe to import anywhere; heavy engines import lazily.
  - Never raises to the caller.

Stdlib only (+ lazy offensive_verify on native-check invoke).
"""

from __future__ import annotations

import sys as _sys
import os as _os
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)

# Single source of truth for the vuln-class vocabulary lives in the reconciler.
try:
    from offensive.finding_reconciler import VULN_CLASS_ALIASES as _VC
    _KNOWN_CLASSES = set(_VC.keys())
except Exception:  # pragma: no cover
    _KNOWN_CLASSES = set()


# ---------------------------------------------------------------------------
# Vocabularies
# ---------------------------------------------------------------------------
# safety_class — how aggressive is it?
SAFETY_PASSIVE = "passive"                              # reads/observes, no attack payload
SAFETY_ACTIVE_NONDESTRUCTIVE = "active-nondestructive"  # sends probes, GET-safe / benign body
SAFETY_GATED = "gated"                                  # default-off; explicit operator opt-in

# kind — how is it executed?
KIND_NATIVE_CHECK = "native_check"   # an offensive_verify check (wired via run())
KIND_PYTHON = "python"               # an ARISE python engine (module path)
KIND_CLI = "cli"                     # an external binary

# category — which domain of the kill chain? (drives the model-facing menu)
CAT_CONFIRM = "confirm"      # differential exploit confirmation
CAT_ATTACK = "attack"        # active offensive probing
CAT_API = "api"              # API-security engines
CAT_CLOUD = "cloud"          # cloud attack/enumeration/posture
CAT_RECON = "recon"          # surface discovery / fingerprinting
CAT_EVIDENCE = "evidence"    # R1-R8 evidence / identity / memory
CAT_INTEL = "intel"          # passive external + correlation intel
CAT_ANALYSIS = "analysis"    # oracles / NLP / attack-path reasoning
CAT_POWER = "power"          # Elevation powers (Phase 4-7): synth / fuzz / OAST / DSL
CAT_TOOL = "tool"            # generic CLIs


@dataclass(frozen=True)
class Capability:
    name: str
    kind: str
    category: str
    summary: str                 # one line the model reads to pick it
    when_to_use: str             # the selection heuristic, model-facing
    vuln_class: Optional[str] = None   # canonical class it emits, or None (multi/recon)
    safety_class: str = SAFETY_ACTIVE_NONDESTRUCTIVE
    cost_hint: str = "medium"    # cheap | medium | expensive
    module: str = ""             # source path (for python/native)
    reads: tuple = ()            # scan artifacts it consumes
    emits: tuple = ()            # KG / finding node types it produces
    wired: bool = True           # is invoke() live yet?
    invoke: Optional[Callable] = field(default=None, compare=False, repr=False)

    def describe(self) -> dict:
        return {
            "name": self.name, "kind": self.kind, "category": self.category,
            "summary": self.summary, "when_to_use": self.when_to_use,
            "vuln_class": self.vuln_class, "safety_class": self.safety_class,
            "cost_hint": self.cost_hint, "module": self.module, "wired": self.wired,
        }


# ---------------------------------------------------------------------------
# native_check adapter — invoke ONE offensive_verify check via its own run()
# ---------------------------------------------------------------------------
def _native_check_invoke(check_name: str) -> Callable:
    """Adapter that runs a single offensive_verify check in-scope and returns its
    structured findings. Lazy-imports offensive_verify so this registry stays cheap."""
    def _run(scan_dir: str, target: Optional[str] = None, **opts) -> dict:
        try:
            from offensive import offensive_verify
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "error": f"offensive_verify unavailable: {exc}", "findings": []}
        try:
            run_opts = dict(opts)
            run_opts["only"] = [check_name]
            if target:
                run_opts["target"] = target
            findings, per_check = offensive_verify.run(scan_dir, run_opts)
            return {"ok": True, "check": check_name,
                    "count": per_check.get(check_name, len(findings)), "findings": findings}
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "error": str(exc)[:200], "findings": []}
    return _run


# ===========================================================================
# THE CATALOGUE
# ===========================================================================

# --- 1) offensive_verify's 16 differential-confirmed checks (WIRED) --------
# check -> (vuln_class, summary, when_to_use)
_NATIVE_CHECKS = {
    "jwt":            ("jwt", "Forge/replay JWTs (alg:none, HS/RS confusion, weak-secret crack).",
                       "A JWT was observed. Confirms auth bypass by forging and replaying."),
    "graphql":        ("graphql", "GraphQL introspection + field/mutation abuse.",
                       "A /graphql endpoint exists. Confirms introspection + unauthorized fields."),
    "ssti":           ("ssti", "Server-side template injection ({{7*7}}->49 differential).",
                       "A reflected parameter renders server-side. Confirms by expression eval."),
    "crlf":           ("crlf", "CRLF / HTTP response splitting via header reflection.",
                       "A parameter reflects into a response header."),
    "redirect":       ("open-redirect", "Open redirect to an attacker-named host.",
                       "A redirect/return/next parameter controls Location."),
    "ssrf":           ("ssrf", "SSRF to cloud metadata / internal hosts (differential).",
                       "A url/uri/callback parameter is server-fetched."),
    "proto":          ("proto-pollution", "Prototype pollution gadget probing.",
                       "A JSON body / query merges into objects."),
    "cache":          ("cache-poison", "Web cache poisoning via unkeyed header reflection.",
                       "A cached response reflects an unkeyed header."),
    "race":           ("race", "Race condition / TOCTOU on a state-changing endpoint.",
                       "A limited action may double-spend."),
    "ws":             ("websocket", "Cross-site WebSocket hijacking (CSWSH) origin check.",
                       "A ws:// or wss:// endpoint exists."),
    "exposure":       ("exposure", "Sensitive file / debug / config exposure.",
                       "Recon hinted at exposed .env/.git/actuator/debug."),
    "nosqli":         ("nosqli", "NoSQL injection (operator/boolean differential).",
                       "A Mongo/JSON-backed parameter exists."),
    "json_smuggling": ("json-smuggling", "JSON interoperability / duplicate-key smuggling.",
                       "A JSON API parses bodies."),
    "xxe":            ("xxe", "XML external entity injection.",
                       "An endpoint accepts XML/SOAP."),
    "business_logic": ("business-logic", "Business-logic abuse (negative qty, price tamper, step skip).",
                       "A multi-step or priced flow exists."),
    "bfla":           ("bola", "Broken function/object-level authorization (role diffing).",
                       "Burp role identities exist. Confirms cross-role access."),
}

# --- 2) ARISE-developed engines (knowledge now; execution wired incrementally)
# (name, module, category, vuln_class, safety, cost, summary, when_to_use)
_ARISE_ENGINES = [
    # ---- Active attack / offensive ----
    ("waf_bypass", "discovery/bypass_403.py", CAT_ATTACK, "exposure",
     SAFETY_ACTIVE_NONDESTRUCTIVE, "cheap",
     "403/401 access-control bypass verifier (header/method/path/case mutations).",
     "A path returns 401/403. Use INSTEAD of hand-rolled curl — tries known bypass primitives consistently."),
    ("hrs_detect", "discovery/hrs_detect.py", CAT_ATTACK, "request-smuggling",
     SAFETY_ACTIVE_NONDESTRUCTIVE, "medium",
     "HTTP request smuggling — safe desync indicator detection.",
     "A CDN/front-end + origin split exists. Detects desync WITHOUT exploitation."),
    ("input_probe", "discovery/input_probe.py", CAT_ATTACK, None,
     SAFETY_ACTIVE_NONDESTRUCTIVE, "medium",
     "Oracle-confirmed active input testing (Module 20.3) across discovered input functions.",
     "Discovered login/search/upload inputs need active, oracle-gated probing."),
    ("response_analysis", "discovery/response_analysis.py", CAT_ANALYSIS, None,
     SAFETY_PASSIVE, "cheap",
     "Hacker-POV response oracles (soft-404, WAF, length/timing/status differentials).",
     "Need a calibrated baseline to judge whether an attack response actually 'moved'."),
    ("recon_attack_synth", "discovery/recon_attack_synth.py", CAT_ATTACK, None,
     SAFETY_ACTIVE_NONDESTRUCTIVE, "medium",
     "Recon->attack pivot: routes the classified surface into nuclei + DAST lanes.",
     "Turn a finished recon surface into targeted attack templates/lanes."),
    ("adaptive_loop", "offensive/adaptive_loop.py", CAT_ATTACK, None,
     SAFETY_GATED, "expensive",
     "Per-endpoint attack FSM (observe->classify->mutate->fire->verify), oracle-gated.",
     "One endpoint refuted canned payloads and needs adaptive, budgeted probing."),

    # ---- API security ----
    ("api_deep_discovery", "api_security/api_deep_discovery.py", CAT_API, None,
     SAFETY_ACTIVE_NONDESTRUCTIVE, "medium",
     "API deep discovery (Module 20): headless interception, form/method enumeration.",
     "An app exposes APIs; enumerate real methods/params/bodies before attacking."),
    ("api_intelligence_engine", "api_security/api_intelligence_engine.py", CAT_API, None,
     SAFETY_ACTIVE_NONDESTRUCTIVE, "expensive",
     "API Intelligence Engine — cross-tool API security with dedup/promotion.",
     "A rich API surface needs multi-tool, corroborated API testing."),
    ("apisec", "api_security/apisec.py", CAT_API, None,
     SAFETY_ACTIVE_NONDESTRUCTIVE, "medium",
     "Black-box API security scanner (stdlib-only).",
     "Quick black-box pass over an API with no schema available."),
    ("api_logic_analysis", "api_security/api_logic_analysis.py", CAT_API, "business-logic",
     SAFETY_ACTIVE_NONDESTRUCTIVE, "medium",
     "API logic analysis (Module 24-API): parity drift, token lineage, state transitions.",
     "Confirm business-logic / auth-state flaws across API interfaces."),
    ("auth_oracle", "api_security/auth_oracle.py", CAT_API, "bola",
     SAFETY_ACTIVE_NONDESTRUCTIVE, "medium",
     "Authorization Oracle (R5): role-aware BOLA/BFLA cross-identity diffing.",
     "Two+ identities/roles exist; confirm authorization-boundary violations."),
    ("schema_probe", "recon/schema_probe.py", CAT_API, None,
     SAFETY_ACTIVE_NONDESTRUCTIVE, "cheap",
     "Schema fingerprint: GraphQL, OpenAPI/Swagger, .well-known.",
     "Locate machine-readable API schemas to drive precise API attacks."),
    ("burp_bridge_ingest", "api_security/burp_bridge_ingest.py", CAT_EVIDENCE, None,
     SAFETY_PASSIVE, "cheap",
     "Burp Bridge intake (Module 0-BURP): authenticated evidence + role identities.",
     "Operator captured authenticated Burp traffic; ingest it for authz testing."),

    # ---- Cloud ----
    ("cloud_storage_enum", "cloud/cloud_storage_enum.py", CAT_CLOUD, "exposure",
     SAFETY_ACTIVE_NONDESTRUCTIVE, "medium",
     "Multi-cloud bucket/blob enumeration + content classification.",
     "A cloud storage host (S3/GCS/Azure) is in scope."),
    ("ssrf_metadata", "cloud/ssrf_metadata.py", CAT_CLOUD, "ssrf",
     SAFETY_GATED, "medium",
     "SSRF -> cloud IMDS probe, differential-confirmed (--active gated).",
     "SSRF suspected against a cloud-hosted target; confirm metadata/cred reach."),
    ("cloud_cred_scan", "cloud/cloud_cred_scan.py", CAT_CLOUD, "secret-leak",
     SAFETY_PASSIVE, "cheap",
     "Masked cloud-credential surface scan.",
     "Assess exposed cloud keys/tokens across the collected surface."),
    ("cloud_posture", "cloud/cloud_posture.py", CAT_CLOUD, "exposure",
     SAFETY_PASSIVE, "cheap",
     "Guardrail-gap inversion — cloud posture weaknesses.",
     "Judge cloud misconfig/guardrail gaps from fingerprints."),
    ("cloud_saas_fingerprint", "cloud/cloud_saas_fingerprint.py", CAT_CLOUD, None,
     SAFETY_PASSIVE, "cheap",
     "Passive DNS/SaaS/ADFS attribution.",
     "Attribute hosts to cloud/SaaS providers before cloud attacks."),
    ("cloud_asset_intel", "cloud/cloud_asset_intel.py", CAT_CLOUD, None,
     SAFETY_PASSIVE, "cheap",
     "Cloud asset intelligence (Module 17b).",
     "Correlate cloud assets across the collected surface."),

    # ---- Recon / fingerprint ----
    ("subdomain_bruteforce", "recon/subdomain_bruteforce.py", CAT_RECON, None,
     SAFETY_ACTIVE_NONDESTRUCTIVE, "medium",
     "Intelligent subdomain brute-force (Phase 6.5).",
     "The host surface looks thin; expand it before attacking."),
    ("dns_security_audit", "recon/dns_security_audit.py", CAT_RECON, "exposure",
     SAFETY_PASSIVE, "cheap",
     "DNS posture audit (SPF/DMARC/DNSSEC/zone-transfer/dangling).",
     "Assess DNS/email-spoofing/takeover exposure for a domain."),
    ("tech_stack_detection", "recon/tech_stack_detection.py", CAT_RECON, None,
     SAFETY_PASSIVE, "cheap",
     "Normalized technology-stack detection from httpx output.",
     "Pick tech-matched payload grammars before fuzzing/injection."),
    ("mcp_ai_probe", "discovery/mcp_ai_probe.py", CAT_RECON, "exposure",
     SAFETY_ACTIVE_NONDESTRUCTIVE, "medium",
     "MCP/AI surface discovery + enumeration (Module 8D): passive marking, "
     "safe-GET fingerprint, read-only MCP initialize/tools-list handshake, "
     "tool-poisoning + posture findings. --active confirms open inference.",
     "Target may expose MCP servers or AI/LLM endpoints; discover, tag "
     "(ai_surface), enumerate tools, and flag unauth/poisoning exposure."),

    # ---- Evidence / identity / memory (R1-R8) ----
    ("har_ingest", "evidence/har_ingest.py", CAT_EVIDENCE, None,
     SAFETY_PASSIVE, "cheap",
     "HAR / browser-trace ingestor (R1) — real-traffic provenance.",
     "A HAR/browser trace is available; ingest real requests as strong evidence."),
    ("flow_reconstruct", "evidence/flow_reconstruct.py", CAT_EVIDENCE, None,
     SAFETY_PASSIVE, "cheap",
     "Flow reconstructor (R2) — rebuild multi-step request flows.",
     "Understand the real sequence a client follows before logic/authz tests."),
    ("identity_graph", "evidence/identity_graph.py", CAT_EVIDENCE, None,
     SAFETY_PASSIVE, "cheap",
     "Identity / object graph (R3) — who-can-touch-what.",
     "Map object ownership across identities to target BOLA/IDOR precisely."),
    ("protocol_exec", "evidence/protocol_exec.py", CAT_EVIDENCE, None,
     SAFETY_ACTIVE_NONDESTRUCTIVE, "medium",
     "Protocol-context execution engine (R7) — replay in real browser/protocol context.",
     "A synthetic replay failed but real traffic worked; replay WITH the needed context."),
    ("wss_agent", "evidence/wss_agent.py", CAT_EVIDENCE, "websocket",
     SAFETY_ACTIVE_NONDESTRUCTIVE, "medium",
     "WebSocket/WSS specialist (R6) — native WSS client + checks.",
     "A live WebSocket needs message-level security testing."),
    ("target_memory", "evidence/target_memory.py", CAT_EVIDENCE, None,
     SAFETY_PASSIVE, "cheap",
     "Per-target learning memory (R8) — priors from prior scans.",
     "Seed the plan with what worked/failed on this target before."),

    # ---- Intel / passive / correlation ----
    ("response_intel", "intel/response_intel.py", CAT_INTEL, "exposure",
     SAFETY_PASSIVE, "cheap",
     "Passive HTTP-200 body scan for PII / secrets / info disclosure (Module 26).",
     "Confirmed-live 2xx bodies are staged; extract leaks without attacks."),
    ("secret_validator", "intel/secret_validator.py", CAT_INTEL, "secret-leak",
     SAFETY_ACTIVE_NONDESTRUCTIVE, "cheap",
     "Validate a candidate leaked secret against its provider API.",
     "A credential was found; confirm it is LIVE before reporting."),
    ("osint_intel", "intel/osint_intel.py", CAT_INTEL, None,
     SAFETY_PASSIVE, "medium",
     "OSINT & human-exposure intelligence (Module 18): breaches, emails, leaks.",
     "Enrich with human/credential exposure for the target org."),
    ("shodan_correlation", "intel/shodan_correlation.py", CAT_INTEL, None,
     SAFETY_PASSIVE, "cheap",
     "Shodan external-view correlation (Module 22).",
     "Cross-check the external internet view of in-scope hosts."),
    ("internet_intel", "intel/internet_intel.py", CAT_INTEL, None,
     SAFETY_PASSIVE, "cheap",
     "Internet Intelligence Layer (Module 23) — Censys/GreyNoise consolidation.",
     "Aggregate external intel into unified asset intelligence."),
    ("capec_attack_paths", "intel/capec_attack_paths.py", CAT_ANALYSIS, None,
     SAFETY_PASSIVE, "cheap",
     "CAPEC attack-path builder (Layer 6) — chain confirmed findings into paths.",
     "Confirmed findings exist; chain them into scored attack paths."),

    # ---- AI / NLP analysis ----
    ("arise_nlp", "ai/arise_nlp.py", CAT_ANALYSIS, None,
     SAFETY_PASSIVE, "cheap",
     "Shared NLP engine — PII / secret / info-disclosure detection over text.",
     "Extract structured intelligence from unstructured tool output or bodies."),
    ("redteam_skills", "ai/redteam_skills.py", CAT_ANALYSIS, None,
     SAFETY_PASSIVE, "cheap",
     "Red-team playbook loader — methodology + per-vuln 'the proof' playbooks.",
     "Ground a specialist in the real methodology for a vuln class before probing."),
]

# --- 3) The 10 external CLIs (already in the autonomous allowlist, WIRED via
#        arise_autonomous.validate_action's vetted shell path). ----
_CLI_TOOLS = [
    ("curl", SAFETY_ACTIVE_NONDESTRUCTIVE, "cheap", "Single HTTP request with full control.",
     "Manual probe of one URL/header/body. Prefer a native_check when one exists."),
    ("httpx", SAFETY_ACTIVE_NONDESTRUCTIVE, "cheap", "Fast HTTP prober (status/title/tech/TLS).",
     "Liveness/tech fingerprint across many hosts."),
    ("nuclei", SAFETY_ACTIVE_NONDESTRUCTIVE, "medium", "Template-based vulnerability scanner.",
     "Signature-detectable CVEs/misconfigs. Emits leads; reconcile vs native confirmations."),
    ("ffuf", SAFETY_ACTIVE_NONDESTRUCTIVE, "medium", "Content/parameter fuzzer.",
     "Discover hidden paths/params. Hits are leads, confirmed by a native_check."),
    ("nmap", SAFETY_ACTIVE_NONDESTRUCTIVE, "medium", "Port/service scanner (non-intrusive NSE only).",
     "Service exposure on a host. Intrusive/exploit NSE categories are refused."),
    ("naabu", SAFETY_ACTIVE_NONDESTRUCTIVE, "cheap", "Fast port scanner.",
     "Quick open-port sweep before service fingerprinting."),
    ("dnsx", SAFETY_PASSIVE, "cheap", "DNS toolkit (resolve/bruteforce/records).",
     "Resolve hosts / enumerate records."),
    ("katana", SAFETY_ACTIVE_NONDESTRUCTIVE, "medium", "Crawler for endpoint discovery.",
     "Harvest links/endpoints from a live app."),
    ("gau", SAFETY_PASSIVE, "cheap", "Fetch known URLs from archives.",
     "Passive historical URL surface."),
    ("subfinder", SAFETY_PASSIVE, "cheap", "Passive subdomain enumeration.",
     "Expand the host surface for a domain."),
]


# --- 4) Elevation POWERS (Phases 4-7) — wired lead-generators / proof engines ---
# Each is fail-safe and additive; findings still pass the oracle + reconciler +
# Verifier gates. invoke adapters lazy-import their module.
def _power_fuzz_plan():
    def _run(scan_dir: str, target: Optional[str] = None, **opts) -> dict:
        try:
            from offensive import fuzz_planner
            return {"ok": True, **fuzz_planner.build_plan(scan_dir, **{
                k: v for k, v in opts.items()
                if k in ("max_urls", "max_params_per_url", "max_grammars")})}
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "error": str(exc)[:200], "plan": []}
    return _run


def _power_template_synth():
    def _run(scan_dir: str, target: Optional[str] = None, *,
             observation=None, urls=None, chat_fn=None, scope=None, out_dir=None, **opts) -> dict:
        try:
            from offensive import template_synth
            if chat_fn is None:
                return {"ok": False, "error": "template synthesis needs a chat_fn (AI layer)", "leads": []}
            return template_synth.synthesize_and_run(
                observation or {}, urls or [], chat_fn, scope,
                out_dir or _os.path.join(scan_dir, "generated-templates"),
                cap=int(opts.get("cap", 4)))
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "error": str(exc)[:200], "leads": []}
    return _run


def _power_oast():
    def _run(scan_dir: str, target: Optional[str] = None, *, action="status", token=None, **opts) -> dict:
        try:
            from offensive.oast_client import OastClient
            c = OastClient.from_env()
            if action == "mint":
                return {"ok": True, "enabled": c.is_enabled(), "token": c.mint_token()}
            if action == "poll":
                return {"ok": True, "enabled": c.is_enabled(), "interactions": c.poll(token or "")}
            return {"ok": True, "enabled": c.is_enabled(),
                    "note": "OAST disabled — set ARISE_OAST_SERVER to enable blind-vuln confirmation"
                            if not c.is_enabled() else "OAST ready"}
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "error": str(exc)[:200]}
    return _run


def _power_probe_dsl():
    def _run(scan_dir: str, target: Optional[str] = None, *,
             probe=None, scope=None, request_fn=None, host="", **opts) -> dict:
        try:
            from offensive import probe_dsl
            if not probe_dsl.is_enabled():
                return {"ok": False, "reason": "probe DSL disabled (set PROBE_SYNTH_ENABLED=true)"}
            if request_fn is None:
                request_fn = probe_dsl.default_request_fn(scope=scope)
            return probe_dsl.run_probe(probe or {}, scope, request_fn, host=host).to_dict()
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "reason": str(exc)[:200], "leads": []}
    return _run


def _invoke_capec_attack_paths():
    """attack_chain_v2.ROADMAP.md Phase 6 — the first of the 36 knowledge-only
    _ARISE_ENGINES entries to actually get wired for execution, letting the
    autonomous worker re-trigger chain-building mid-investigation (the exact
    re-chain step module_autonomous_attack() already runs automatically at
    end-of-scan in easm-pipeline.sh, now exposed as a general callable
    instead of only a hardcoded pipeline step). Read-only over already-
    collected scan data — no new request ever reaches the target, matching
    the SAFETY_PASSIVE classification this capability already carries."""
    def _run(scan_dir: str, target: Optional[str] = None, **opts) -> dict:
        try:
            import subprocess as _subprocess
            script = _os.path.join(_ROOT, "intel", "capec_attack_paths.py")
            if not _os.path.isfile(script):
                return {"ok": False, "error": "intel/capec_attack_paths.py not found", "paths": []}
            proc = _subprocess.run([_sys.executable, script, scan_dir, "--summary"],
                                   capture_output=True, text=True, timeout=90)
            out_file = _os.path.join(scan_dir, "25_attack_paths", "capec_attack_paths.json")
            if not _os.path.isfile(out_file):
                return {"ok": False, "error": "no output produced",
                        "stderr": (proc.stderr or "")[-500:], "paths": []}
            import json as _json
            with open(out_file) as f:
                data = _json.load(f)
            return {"ok": True, "paths": data.get("paths", []),
                    "findings_mapped": data.get("findings_mapped", 0),
                    "findings_total": data.get("findings_total", 0)}
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "error": str(exc)[:200], "paths": []}
    return _run


# Name -> invoke factory for the small subset of _ARISE_ENGINES entries that
# are wired for real execution. Every entry NOT in this dict stays
# wired=False, invoke=None (knowledge-only) exactly as before — this is
# additive, incremental wiring, never a blanket flip (per this file's own
# EXECUTION HONESTY doctrine: never fake a wired=True).
_ARISE_ENGINE_INVOKES: Dict[str, Callable] = {
    "capec_attack_paths": _invoke_capec_attack_paths,
}


# (name, category, vuln_class, safety, cost, summary, when_to_use, invoke_factory)
_POWERS = [
    ("guided_fuzz_plan", CAT_POWER, None, SAFETY_PASSIVE, "cheap",
     "Observation-driven fuzz PLAN (observed params + tech -> prioritized probe list). Sends nothing.",
     "You want to fuzz an endpoint but need param/payload/oracle choices grounded in what the scan observed.",
     _power_fuzz_plan),
    ("synthesize_template", CAT_POWER, None, SAFETY_ACTIVE_NONDESTRUCTIVE, "medium",
     "Synthesize+validate+run a nuclei detector for an observed anomaly; returns low-rung LEADS.",
     "You saw an anomaly no existing check covers; write a detector for exactly it (leads, must be confirmed).",
     _power_template_synth),
    ("oob_interaction", CAT_POWER, None, SAFETY_GATED, "cheap",
     "Out-of-band (OAST) token mint/poll — confirms blind SSRF/RCE/XXE. Disabled without a collector.",
     "A blind class is suspected; embed a unique OOB host and poll for the callback (conclusive L5 proof).",
     _power_oast),
    ("probe_sequence", CAT_POWER, None, SAFETY_GATED, "medium",
     "Run a declarative multi-step HTTP probe (request/capture/assert). No shell/eval. Flag-gated.",
     "A bespoke multi-request flow (auth-then-IDOR, race) is needed; author it as a DSL, oracle-confirmed.",
     _power_probe_dsl),
]


def _build_registry() -> Dict[str, Capability]:
    reg: Dict[str, Capability] = {}

    for check, (vcls, summary, when) in _NATIVE_CHECKS.items():
        name = f"verify_{check}"
        reg[name] = Capability(
            name=name, kind=KIND_NATIVE_CHECK, category=CAT_CONFIRM,
            summary=summary, when_to_use=when, vuln_class=vcls,
            safety_class=SAFETY_ACTIVE_NONDESTRUCTIVE, cost_hint="medium",
            module="offensive/offensive_verify.py",
            reads=("discovered_endpoints.jsonl",), emits=("finding",),
            wired=True, invoke=_native_check_invoke(check),
        )

    for (name, module, cat, vcls, safety, cost, summary, when) in _ARISE_ENGINES:
        invoke_factory = _ARISE_ENGINE_INVOKES.get(name)
        reg[name] = Capability(
            name=name, kind=KIND_PYTHON, category=cat,
            summary=summary, when_to_use=when, vuln_class=vcls,
            safety_class=safety, cost_hint=cost, module=module,
            reads=(module,), emits=("finding",),
            # knowledge registered by default; wired incrementally, one at a
            # time, only for entries with a real adapter in
            # _ARISE_ENGINE_INVOKES above — never a blanket flip.
            wired=invoke_factory is not None,
            invoke=invoke_factory() if invoke_factory else None,
        )

    for (name, cat, vcls, safety, cost, summary, when, factory) in _POWERS:
        reg[name] = Capability(
            name=name, kind=KIND_PYTHON, category=cat,
            summary=summary, when_to_use=when, vuln_class=vcls,
            safety_class=safety, cost_hint=cost, module="offensive/",
            reads=(), emits=("lead", "finding"), wired=True, invoke=factory(),
        )

    for (name, safety, cost, summary, when) in _CLI_TOOLS:
        reg[name] = Capability(
            name=name, kind=KIND_CLI, category=CAT_TOOL,
            summary=summary, when_to_use=when, vuln_class=None,
            safety_class=safety, cost_hint=cost, module="",
            reads=(), emits=("kg_node",), wired=True, invoke=None,
        )
    return reg


_REGISTRY: Dict[str, Capability] = _build_registry()


# ---------------------------------------------------------------------------
# Public accessors
# ---------------------------------------------------------------------------
def all_capabilities() -> List[Capability]:
    return list(_REGISTRY.values())


def get(name: str) -> Optional[Capability]:
    return _REGISTRY.get(name)


def by_category(category: str) -> List[Capability]:
    return [c for c in _REGISTRY.values() if c.category == category]


def by_vuln_class(vuln_class: str) -> List[Capability]:
    """Every capability emitting this canonical class; native confirming checks
    first (the engines the reconciler should prefer)."""
    vc = (vuln_class or "").lower().strip()
    hits = [c for c in _REGISTRY.values() if c.vuln_class == vc]
    hits.sort(key=lambda c: 0 if c.kind == KIND_NATIVE_CHECK else 1)
    return hits


def canonical_check_for(vuln_class: str) -> Optional[Capability]:
    """The ONE native check the brain should call for a class (anti-overlap)."""
    for c in by_vuln_class(vuln_class):
        if c.kind == KIND_NATIVE_CHECK:
            return c
    return None


def wired_capabilities() -> List[Capability]:
    return [c for c in _REGISTRY.values() if c.wired]


def to_tool_schema(cap: Capability) -> dict:
    """Provider-neutral tool definition (Anthropic tool-use / OpenAI tools shape).
    Minimal input surface by design — fewer free-text args the model can get wrong."""
    props: Dict[str, dict] = {}
    if cap.kind == KIND_NATIVE_CHECK:
        props = {
            "url_hint": {"type": "string",
                         "description": "Optional: restrict to endpoints matching this URL/host substring."},
            "reason": {"type": "string",
                       "description": "Why this check is warranted now (grounded in an observation)."},
        }
    return {
        "name": cap.name,
        "description": f"{cap.summary} WHEN: {cap.when_to_use}"
                       + (f" [emits vuln_class:{cap.vuln_class}]" if cap.vuln_class else ""),
        "input_schema": {"type": "object", "properties": props, "required": []},
    }


def tool_schemas(kinds: Optional[List[str]] = None, wired_only: bool = True) -> List[dict]:
    """Tool definitions ready for synth_ai.build_tool_chat_fn. Defaults to WIRED
    capabilities only — never offer the model a tool the harness can't execute."""
    kinds = kinds or [KIND_NATIVE_CHECK]
    return [to_tool_schema(c) for c in _REGISTRY.values()
            if c.kind in kinds and (c.wired or not wired_only)]


_CAT_LABELS = {
    CAT_CONFIRM: "CONFIRMING CHECKS (differential-proof; prefer these)",
    CAT_ATTACK: "ACTIVE ATTACK ENGINES", CAT_API: "API-SECURITY ENGINES",
    CAT_CLOUD: "CLOUD ENGINES", CAT_RECON: "RECON / FINGERPRINT",
    CAT_EVIDENCE: "EVIDENCE / IDENTITY / MEMORY (R1-R8)",
    CAT_INTEL: "PASSIVE / EXTERNAL INTEL", CAT_ANALYSIS: "ANALYSIS / ORACLES / CHAINING",
    CAT_TOOL: "GENERIC TOOLS",
}
_CAT_LABELS[CAT_POWER] = "ELEVATION POWERS (synth / fuzz / OAST / DSL — leads, gated)"
_CAT_ORDER = [CAT_CONFIRM, CAT_ATTACK, CAT_POWER, CAT_API, CAT_CLOUD, CAT_RECON,
              CAT_EVIDENCE, CAT_INTEL, CAT_ANALYSIS, CAT_TOOL]


def tool_menu(categories: Optional[List[str]] = None, include_unwired: bool = True) -> str:
    """Model-facing menu grouped by category, generated from the registry so
    adding a capability never means editing a prompt. Unwired engines are shown
    (so the brain can PLAN with them) but marked '(planned)'."""
    cats = categories or _CAT_ORDER
    lines: List[str] = []
    for cat in cats:
        caps = [c for c in _REGISTRY.values() if c.category == cat and (include_unwired or c.wired)]
        if not caps:
            continue
        lines.append(f"\n## {_CAT_LABELS.get(cat, cat.upper())}")
        for c in sorted(caps, key=lambda x: (0 if x.wired else 1, x.name)):
            vc = f" [class:{c.vuln_class}]" if c.vuln_class else ""
            gate = "" if c.wired else " (planned)"
            lines.append(f"- {c.name}{vc} ({c.safety_class}) — {c.summary} WHEN: {c.when_to_use}{gate}")
    return "\n".join(lines).strip()


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------
def _selftest() -> int:
    caps = all_capabilities()
    assert len(caps) == len(_NATIVE_CHECKS) + len(_ARISE_ENGINES) + len(_POWERS) + len(_CLI_TOOLS)

    natives = by_category(CAT_CONFIRM)
    assert len(natives) == 16 and all(c.wired and c.invoke for c in natives)

    # Phase 4-7 powers are registered AND wired (callable now)
    powers = by_category(CAT_POWER)
    assert len(powers) == 4, f"expected 4 elevation powers, got {len(powers)}"
    assert all(p.wired and callable(p.invoke) for p in powers)
    for n in ("guided_fuzz_plan", "synthesize_template", "oob_interaction", "probe_sequence"):
        assert get(n) is not None and get(n).invoke, f"power not wired: {n}"
    # the safe power (fuzz plan) actually runs and returns lead-only plan on empty dir
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        out = get("guided_fuzz_plan").invoke(d)
        assert out["ok"] is True and out["stats"]["lead_only"] is True
    # gated powers refuse safely when disabled
    _os.environ.pop("PROBE_SYNTH_ENABLED", None)
    assert get("probe_sequence").invoke("/tmp", probe={"steps": []})["ok"] is False
    assert get("oob_interaction").invoke("/tmp")["enabled"] in (True, False)  # never raises

    # the ARISE arsenal is actually present now, across every domain
    engines = [c for c in caps if c.kind == KIND_PYTHON and c.category != CAT_POWER]
    assert len(engines) >= 30, f"expected the full ARISE arsenal, got {len(engines)}"
    for cat in (CAT_ATTACK, CAT_API, CAT_CLOUD, CAT_RECON, CAT_EVIDENCE, CAT_INTEL, CAT_ANALYSIS):
        assert by_category(cat), f"no capability registered in category {cat}"
    # spot-check specific ARISE engines the brain was blind to before
    for n in ("waf_bypass", "hrs_detect", "auth_oracle", "cloud_storage_enum",
              "capec_attack_paths", "target_memory", "wss_agent", "response_analysis",
              "schema_probe", "osint_intel", "arise_nlp", "input_probe"):
        assert get(n) is not None, f"missing ARISE engine: {n}"

    # every declared vuln_class is a real canonical class the reconciler knows
    if _KNOWN_CLASSES:
        for c in caps:
            if c.vuln_class is not None:
                assert c.vuln_class in _KNOWN_CLASSES, f"{c.name}: unknown class {c.vuln_class}"

    # anti-overlap routing
    assert canonical_check_for("ssti").name == "verify_ssti"
    assert canonical_check_for("jwt").name == "verify_jwt"
    assert canonical_check_for("bola").name == "verify_bfla"
    assert by_vuln_class("ssrf")[0].kind == KIND_NATIVE_CHECK  # native before cloud engine

    # honesty: engines carry knowledge only EXCEPT the small, explicit,
    # incrementally-grown set in _ARISE_ENGINE_INVOKES (attack_chain_v2.
    # ROADMAP.md Phase 6) — every other engine must still be wired=False.
    for c in engines:
        if c.name in _ARISE_ENGINE_INVOKES:
            assert c.wired and c.invoke is not None, f"{c.name}: declared in _ARISE_ENGINE_INVOKES but not actually wired"
        else:
            assert not c.wired and c.invoke is None, f"{c.name}: wired without a declared invoke factory"

    # tool schemas cover the 16 wired native checks; menu shows every category
    assert len(tool_schemas()) == 16
    menu = tool_menu()
    for label in ("CONFIRMING CHECKS", "ACTIVE ATTACK", "CLOUD ENGINES",
                  "EVIDENCE / IDENTITY", "API-SECURITY"):
        assert label in menu, f"menu missing section {label}"
    assert "(planned)" in menu  # unwired engines are surfaced, honestly marked

    print(f"[tool_registry] self-test OK — {len(caps)} capabilities: "
          f"{len(natives)} native checks, {len(engines)} ARISE engines, {len(_CLI_TOOLS)} CLIs")
    return 0


if __name__ == "__main__":
    _sys.exit(_selftest())
