#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║   ARISE — Project Analyzer & Dependency Inspector               ║
║   "Summon Every Hidden Exposure." — Environment Readiness Tool  ║
╚══════════════════════════════════════════════════════════════════╝

Scans the ARISE project and reports:
  • Python package dependencies (status, version, category)
  • External Go/system tools availability (subfinder, nuclei, etc.)
  • Environment variables / API keys present or missing
  • Project file structure completeness
  • Recommended setup steps

Usage:
    python3 analyze_project.py              # full analysis, colored output
    python3 analyze_project.py --json       # machine-readable JSON output
    python3 analyze_project.py --missing    # show only missing items
    python3 analyze_project.py --fix        # attempt to pip-install missing packages
"""

import sys as _sys, os as _os
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)


import argparse
import importlib
import importlib.metadata
import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional


# ── ANSI colour helpers ───────────────────────────────────────────────────────
class C:
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    BLUE   = "\033[94m"
    MAGENTA= "\033[95m"
    DIM    = "\033[2m"

def _supports_color() -> bool:
    return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None

USE_COLOR = _supports_color()

def c(color: str, text: str) -> str:
    return f"{color}{text}{C.RESET}" if USE_COLOR else text

def ok(msg):    print(f"  {c(C.GREEN, '✔')}  {msg}")
def fail(msg):  print(f"  {c(C.RED,   '✘')}  {msg}")
def warn(msg):  print(f"  {c(C.YELLOW,'⚠')}  {msg}")
def info(msg):  print(f"  {c(C.CYAN,  '●')}  {msg}")
def section(title: str):
    bar = "─" * (len(title) + 4)
    print(f"\n{c(C.BOLD + C.BLUE, bar)}")
    print(f"{c(C.BOLD + C.BLUE, '  ' + title)}")
    print(f"{c(C.BLUE, bar)}")


# ── Data models ───────────────────────────────────────────────────────────────
@dataclass
class PyDep:
    pip_name: str
    import_name: str
    category: str
    min_version: str = ""
    description: str = ""
    # filled in at runtime
    installed: bool = False
    installed_version: str = ""
    status: str = "MISSING"   # OK | MISSING | VERSION_WARN

@dataclass
class ToolDep:
    name: str
    category: str
    description: str
    install_hint: str
    # filled in at runtime
    available: bool = False
    path: str = ""
    status: str = "MISSING"   # OK | MISSING

@dataclass
class EnvVar:
    key: str
    description: str
    required: bool = False
    # filled in at runtime
    present: bool = False
    value_preview: str = ""

@dataclass
class ProjectFile:
    rel_path: str
    description: str
    critical: bool = True
    # filled in at runtime
    exists: bool = False


# ── Dependency catalogue ──────────────────────────────────────────────────────

PYTHON_DEPS: list[PyDep] = [
    # HTTP / API
    PyDep("requests",        "requests",        "HTTP/API",        "2.31.0",  "HTTP client for API calls"),
    PyDep("urllib3",         "urllib3",          "HTTP/API",        "2.0.0",   "Low-level HTTP library"),
    # Security
    PyDep("pyOpenSSL",       "OpenSSL",          "Security",        "23.2.0",  "TLS/SSL bindings"),
    PyDep("cryptography",    "cryptography",     "Security",        "41.0.0",  "Cryptographic primitives"),
    PyDep("scapy",           "scapy",            "Security",        "2.5.0",   "Packet crafting & analysis"),
    # Web scraping / DOM
    PyDep("beautifulsoup4",  "bs4",              "Web Scraping",    "4.12.2",  "HTML/XML DOM parser"),
    PyDep("lxml",            "lxml",             "Web Scraping",    "4.9.3",   "Fast XML/HTML parser"),
    PyDep("html5lib",        "html5lib",         "Web Scraping",    "1.1",     "HTML5-compliant parser"),
    # Data processing
    PyDep("pandas",          "pandas",           "Data",            "2.1.1",   "DataFrame analysis"),
    PyDep("python-dateutil", "dateutil",         "Data",            "2.8.2",   "Date parsing utilities"),
    PyDep("pytz",            "pytz",             "Data",            "2023.3",  "Timezone support"),
    PyDep("tabulate",        "tabulate",         "Data",            "0.9.0",   "Table formatting"),
    # Visualization
    PyDep("matplotlib",      "matplotlib",       "Visualization",   "3.7.2",   "Chart/plot generation"),
    # CLI / UX
    PyDep("colorama",        "colorama",         "CLI",             "0.4.6",   "Cross-platform ANSI colors"),
    PyDep("tqdm",            "tqdm",             "CLI",             "4.66.1",  "Progress bars"),
    PyDep("rich",            "rich",             "CLI",             "13.6.0",  "Rich terminal output"),
    # Config
    PyDep("PyYAML",          "yaml",             "Config",          "6.0.1",   "YAML parsing"),
    PyDep("python-dotenv",   "dotenv",           "Config",          "1.0.0",   ".env file loading"),
    # Dashboard
    PyDep("flask",           "flask",            "Dashboard",       "3.0.0",   "Web dashboard server"),
    PyDep("flask-cors",      "flask_cors",       "Dashboard",       "4.0.0",   "CORS middleware for Flask"),
    # AI integrations
    PyDep("anthropic",       "anthropic",        "AI",              "0.40.0",  "Claude AI SDK"),
    # Utilities
    PyDep("python-magic",    "magic",            "Utilities",       "0.4.27",  "File type detection"),
    PyDep("filetype",        "filetype",         "Utilities",       "1.2.0",   "File MIME type sniffing"),
    PyDep("validators",      "validators",       "Utilities",       "0.22.0",  "Data validation helpers"),
    PyDep("dirsearch",       "dirsearch",        "Utilities",       "0.4.3",   "Web directory discovery"),
    # Xtractor / AWS
    PyDep("boto3",           "boto3",            "Cloud/AWS",       "1.28.40", "AWS SDK"),
    PyDep("botocore",        "botocore",         "Cloud/AWS",       "1.31.40", "AWS low-level SDK"),
    PyDep("s3transfer",      "s3transfer",       "Cloud/AWS",       "0.6.2",   "S3 multipart transfers"),
    PyDep("jmespath",        "jmespath",         "Cloud/AWS",       "1.0.1",   "JSON query language"),
    # Xtractor / Concurrency
    PyDep("gevent",          "gevent",           "Concurrency",     "23.9.1",  "Coroutine-based networking"),
    PyDep("greenlet",        "greenlet",         "Concurrency",     "3.0.3",   "Lightweight coroutines"),
    # Xtractor / Validation
    PyDep("pydantic",        "pydantic",         "Validation",      "2.1.1",   "Data validation (v2)"),
    PyDep("pydantic-settings","pydantic_settings","Validation",     "2.0.3",   "Settings management"),
    # Xtractor / Storage
    PyDep("pymongo",         "pymongo",          "Storage",         "4.5.0",   "MongoDB driver (optional)"),
    PyDep("tinydb",          "tinydb",           "Storage",         "4.8.0",   "Embedded JSON database"),
    PyDep("slack-sdk",       "slack_sdk",        "Notifications",   "3.21.3",  "Slack API integration"),
]

TOOL_DEPS: list[ToolDep] = [
    # Subdomain enumeration
    ToolDep("subfinder",    "Recon",           "Passive subdomain discovery",
            "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"),
    ToolDep("puredns",      "Recon",           "DNS brute-force with massdns backend",
            "go install -v github.com/d3mondev/puredns/v2@latest"),
    ToolDep("massdns",      "Recon",           "High-performance DNS stub resolver",
            "apt-get install massdns  OR  compile from source"),
    ToolDep("dnsx",         "Recon",           "DNS toolkit — A/AAAA/CNAME resolution",
            "go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest"),
    ToolDep("anew",         "Recon",           "Append lines uniquely (dedup)",
            "go install -v github.com/tomnomnom/anew@latest"),
    # HTTP & Port
    ToolDep("naabu",        "HTTP/Port",       "Fast SYN/CONNECT port scanner",
            "go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"),
    ToolDep("httpx",        "HTTP/Port",       "HTTP probing & tech detection",
            "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"),
    ToolDep("nmap",         "HTTP/Port",       "Service version fingerprinting",
            "apt-get install nmap  OR  brew install nmap"),
    # Crawling
    ToolDep("katana",       "Crawling",        "Active web crawler with JS rendering",
            "go install -v github.com/projectdiscovery/katana/cmd/katana@latest"),
    ToolDep("gospider",     "Crawling",        "Go-based web spider",
            "go install -v github.com/jaeles-project/gospider@latest"),
    ToolDep("gau",          "Crawling",        "Passive URL fetcher (Wayback, OTX)",
            "go install -v github.com/lc/gau/v2/cmd/gau@latest"),
    # Directory Discovery
    ToolDep("ffuf",         "Discovery",       "Fast web fuzzer for dirs/params/vhosts",
            "go install -v github.com/ffuf/ffuf@latest"),
    ToolDep("gf",           "Discovery",       "Grep pattern matcher for params/secrets",
            "go install -v github.com/tomnomnom/gf@latest"),
    # Vulnerability
    ToolDep("nuclei",       "Vulnerability",   "Template-based vulnerability scanner",
            "go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest"),
    ToolDep("dalfox",       "Vulnerability",   "XSS scanner and validator",
            "go install -v github.com/hahwul/dalfox/v2@latest"),
    ToolDep("sqlmap",       "Vulnerability",   "SQL injection detection",
            "apt-get install sqlmap  OR  pip install sqlmap"),
    ToolDep("trufflehog",   "Vulnerability",   "Secret and credential scanner",
            "go install -v github.com/trufflesecurity/trufflehog/v3/cmd/trufflehog@latest"),
    ToolDep("wafw00f",      "Vulnerability",   "WAF fingerprinting",
            "pip install wafw00f"),
    # Extended Verification
    ToolDep("interactsh-client", "Extended",   "OOB callback oracle for blind SSRF",
            "go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"),
    ToolDep("crlfuzz",      "Extended",        "CRLF injection detection",
            "go install -v github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest"),
    # Go toolchain
    ToolDep("go",           "Platform",        "Go toolchain (required for most tools)",
            "https://go.dev/dl/  OR  brew install go"),
    ToolDep("git",          "Platform",        "Version control",
            "apt-get install git  OR  brew install git"),
    ToolDep("curl",         "Platform",        "HTTP transfer tool",
            "apt-get install curl  OR  brew install curl"),
    ToolDep("jq",           "Platform",        "Command-line JSON processor",
            "apt-get install jq  OR  brew install jq"),
    ToolDep("bash",         "Platform",        "Bash shell (easm-pipeline.sh runtime)",
            "pre-installed on Linux/macOS"),
]

ENV_VARS: list[EnvVar] = [
    EnvVar("ANTHROPIC_API_KEY",   "Claude AI API key (AI Analyst panel)",    required=False),
    EnvVar("OPENAI_API_KEY",      "OpenAI GPT API key",                       required=False),
    EnvVar("GEMINI_API_KEY",      "Google Gemini API key",                    required=False),
    EnvVar("GOOGLE_API_KEY",      "Google API key (alias for GEMINI)",        required=False),
    EnvVar("HF_API_TOKEN",        "Hugging Face API token",                   required=False),
    EnvVar("SLACK_WEBHOOK_URL",   "Slack Incoming Webhook for briefings",     required=False),
    EnvVar("ARISE_AI_PROVIDER",   "Default AI provider (claude/openai/gemini/huggingface)", required=False),
    EnvVar("ARISE_AI_MODEL",      "Default AI model name",                    required=False),
    EnvVar("ARISE_DASHBOARD_PORT","Flask dashboard port (default: 5000)",     required=False),
    EnvVar("PORT_SCAN_MODE",      "Naabu mode: full (all 65535, default) or fast (top 1000)",      required=False),
    EnvVar("NAABU_RATE",          "Naabu packets/sec rate limit",              required=False),
    EnvVar("CLOUD_BUCKET_ENUM_ENABLED", "Enable Phase 2 S3/GCS/Azure enum",  required=False),
    EnvVar("CLOUD_AUDIT_ENABLED", "Enable Phase 3 authenticated cloud audit", required=False),
    EnvVar("CLOUD_AUDIT_PROVIDER","Phase 3 provider: aws|gcp|azure",          required=False),
    EnvVar("EXTENDED_CHECKS_ENABLED", "Enable Module 19 extended verification",required=False),
    EnvVar("EXTENDED_SAFE_MODE",  "Confirm-only mode (keep ON for prod)",     required=False),
]

PROJECT_FILES: list[ProjectFile] = [
    ProjectFile("arise.py",             "Main CLI orchestrator",                  critical=True),
    ProjectFile("dashboard.py",         "Flask dashboard server",                 critical=True),
    ProjectFile("easm-pipeline.sh",     "18-module EASM scanning pipeline",       critical=True),
    ProjectFile("setup.sh",             "System dependency installer",            critical=True),
    ProjectFile("requirements.txt",     "Python pip dependencies",                critical=True),
    ProjectFile("hosts.txt",            "Target domain list",                     critical=True),
    ProjectFile("templates/dashboard.html", "Main 10-tab dashboard UI",          critical=True),
    ProjectFile("templates/kt.html",    "Knowledge Transfer document",            critical=False),
    ProjectFile(".env.example",         "Environment config template",            critical=False),
    ProjectFile("cloud-templates/cloud-metadata-exposure.yaml", "Nuclei: cloud metadata", critical=False),
    ProjectFile("cloud-templates/debug-endpoints.yaml",         "Nuclei: debug endpoints", critical=False),
    ProjectFile("cloud-templates/public-object-storage.yaml",   "Nuclei: public storage",  critical=False),
    ProjectFile("cloud-templates/terraform-state-exposure.yaml","Nuclei: terraform state",  critical=False),
    ProjectFile("lists/",               "Wordlists & DNS resolver lists dir",     critical=False),
    ProjectFile("scans/",               "Scan output directories",                critical=False),
    ProjectFile("scope/",               "Target scope configuration files",       critical=False),
    ProjectFile("logs/",                "Execution logs directory",               critical=False),
    ProjectFile("requir/requirements.txt",   "Xtractor secondary requirements",   critical=False),
    ProjectFile("requir/install_deps.py",    "Xtractor Python venv installer",    critical=False),
]


# ── Inspection helpers ────────────────────────────────────────────────────────

def _parse_version(v: str) -> tuple:
    """Loosely parse 'X.Y.Z' → (X, Y, Z) ints, ignoring suffixes."""
    parts = []
    for segment in v.split(".")[:3]:
        clean = "".join(ch for ch in segment if ch.isdigit())
        parts.append(int(clean) if clean else 0)
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts)


def check_python_dep(dep: PyDep) -> PyDep:
    # 1. Try importlib.metadata for installed version
    try:
        installed_ver = importlib.metadata.version(dep.pip_name)
        dep.installed = True
        dep.installed_version = installed_ver
    except importlib.metadata.PackageNotFoundError:
        # Might be installed under a different dist name — try import
        pass

    # 2. Verify import actually works
    if not dep.installed:
        try:
            importlib.import_module(dep.import_name)
            dep.installed = True
            dep.installed_version = "unknown"
        except ImportError:
            dep.installed = False
            dep.status = "MISSING"
            return dep

    # 3. Version check
    if dep.min_version and dep.installed_version not in ("", "unknown"):
        try:
            if _parse_version(dep.installed_version) < _parse_version(dep.min_version):
                dep.status = "VERSION_WARN"
                return dep
        except Exception:
            pass

    dep.status = "OK"
    return dep


def check_tool(tool: ToolDep) -> ToolDep:
    found = shutil.which(tool.name)
    if found:
        tool.available = True
        tool.path = found
        tool.status = "OK"
    else:
        tool.status = "MISSING"
    return tool


def check_env_var(ev: EnvVar) -> EnvVar:
    val = os.environ.get(ev.key, "")
    ev.present = bool(val)
    if ev.present:
        # Mask secrets: show first 4 chars + stars
        ev.value_preview = val[:4] + "****" if len(val) > 4 else "****"
    return ev


def check_project_file(root: Path, pf: ProjectFile) -> ProjectFile:
    pf.exists = (root / pf.rel_path).exists()
    return pf


# ── Formatters ────────────────────────────────────────────────────────────────

def _status_badge(status: str) -> str:
    badges = {
        "OK":           c(C.GREEN,  "[OK]     "),
        "MISSING":      c(C.RED,    "[MISSING]"),
        "VERSION_WARN": c(C.YELLOW, "[OLD VER]"),
    }
    return badges.get(status, status)


def print_python_section(deps: list[PyDep], missing_only: bool):
    section("Python Package Dependencies")
    categories: dict[str, list[PyDep]] = {}
    for d in deps:
        categories.setdefault(d.category, []).append(d)

    total = len(deps)
    installed_count = sum(1 for d in deps if d.status == "OK")

    for cat, items in sorted(categories.items()):
        cat_ok  = sum(1 for d in items if d.status == "OK")
        cat_tot = len(items)
        header_color = C.GREEN if cat_ok == cat_tot else (C.YELLOW if cat_ok > 0 else C.RED)
        print(f"\n  {c(C.BOLD, cat)}  {c(header_color, f'({cat_ok}/{cat_tot})')}")
        for d in items:
            if missing_only and d.status == "OK":
                continue
            badge = _status_badge(d.status)
            ver_str = ""
            if d.status == "OK":
                ver_str = c(C.DIM, f"v{d.installed_version}")
            elif d.status == "VERSION_WARN":
                ver_str = c(C.YELLOW, f"v{d.installed_version} (need >={d.min_version})")
            elif d.status == "MISSING":
                ver_str = c(C.DIM, f"pip install {d.pip_name}")
            print(f"    {badge}  {d.pip_name:<25} {ver_str}  {c(C.DIM, d.description)}")

    print(f"\n  {c(C.BOLD, 'Summary:')} {installed_count}/{total} packages installed", end="")
    if installed_count == total:
        print(f"  {c(C.GREEN, '— All good!')}")
    else:
        missing = total - installed_count
        print(f"  {c(C.RED, f'— {missing} missing')}")


def print_tool_section(tools: list[ToolDep], missing_only: bool):
    section("External Tool Dependencies")
    categories: dict[str, list[ToolDep]] = {}
    for t in tools:
        categories.setdefault(t.category, []).append(t)

    total = len(tools)
    avail = sum(1 for t in tools if t.status == "OK")

    for cat, items in sorted(categories.items()):
        cat_ok  = sum(1 for t in items if t.status == "OK")
        cat_tot = len(items)
        header_color = C.GREEN if cat_ok == cat_tot else (C.YELLOW if cat_ok > 0 else C.RED)
        print(f"\n  {c(C.BOLD, cat)}  {c(header_color, f'({cat_ok}/{cat_tot})')}")
        for t in items:
            if missing_only and t.status == "OK":
                continue
            badge = _status_badge(t.status)
            detail = c(C.DIM, t.path) if t.available else c(C.DIM, f"Install: {t.install_hint}")
            print(f"    {badge}  {t.name:<22} {detail}")

    print(f"\n  {c(C.BOLD, 'Summary:')} {avail}/{total} tools found", end="")
    if avail == total:
        print(f"  {c(C.GREEN, '— All good!')}")
    else:
        print(f"  {c(C.YELLOW, f'— {total - avail} missing (pipeline modules may be skipped)')}")


def print_env_section(evars: list[EnvVar], missing_only: bool):
    section("Environment Variables / API Keys")
    present = [e for e in evars if e.present]
    missing = [e for e in evars if not e.present]

    if not missing_only:
        for ev in present:
            print(f"    {c(C.GREEN, '✔')}  {ev.key:<35} {c(C.DIM, ev.value_preview)}")
    for ev in missing:
        req_label = c(C.RED, " [REQUIRED]") if ev.required else c(C.DIM, " [optional]")
        print(f"    {c(C.YELLOW, '○')}  {ev.key:<35}{req_label}  {c(C.DIM, ev.description)}")

    print(f"\n  {c(C.BOLD, 'Summary:')} {len(present)}/{len(evars)} env vars configured")
    required_missing = [e for e in evars if e.required and not e.present]
    if required_missing:
        print(f"  {c(C.RED, f'WARNING: {len(required_missing)} required env vars missing!')}")


def print_files_section(files: list[ProjectFile], missing_only: bool):
    section("Project File Structure")
    for pf in files:
        if missing_only and pf.exists:
            continue
        if pf.exists:
            print(f"    {c(C.GREEN, '✔')}  {pf.rel_path:<50} {c(C.DIM, pf.description)}")
        else:
            badge = c(C.RED, "✘") if pf.critical else c(C.YELLOW, "○")
            label = c(C.RED, " [CRITICAL MISSING]") if pf.critical else c(C.DIM, " [optional]")
            print(f"    {badge}  {pf.rel_path:<50}{label}  {c(C.DIM, pf.description)}")

    found = sum(1 for f in files if f.exists)
    print(f"\n  {c(C.BOLD, 'Summary:')} {found}/{len(files)} files present")
    critical_missing = [f for f in files if f.critical and not f.exists]
    if critical_missing:
        print(f"  {c(C.RED, f'CRITICAL: {len(critical_missing)} required file(s) missing!')}")
        for f in critical_missing:
            print(f"    {c(C.RED, '→')} {f.rel_path}")


def print_summary(py_deps, tools, evars, files):
    section("Overall Readiness Summary")
    py_ok    = sum(1 for d in py_deps if d.status == "OK")
    tool_ok  = sum(1 for t in tools   if t.status == "OK")
    env_ok   = sum(1 for e in evars   if e.present)
    file_ok  = sum(1 for f in files   if f.exists)

    rows = [
        ("Python packages",    py_ok,   len(py_deps)),
        ("External tools",     tool_ok, len(tools)),
        ("Env vars / API keys",env_ok,  len(evars)),
        ("Project files",      file_ok, len(files)),
    ]
    for label, ok_count, total in rows:
        pct = ok_count / total * 100 if total else 0
        bar_len = 20
        filled  = int(bar_len * ok_count / total) if total else 0
        bar     = c(C.GREEN, "█" * filled) + c(C.DIM, "░" * (bar_len - filled))
        color   = C.GREEN if pct == 100 else (C.YELLOW if pct >= 50 else C.RED)
        print(f"  {label:<25} {bar}  {c(color, f'{ok_count}/{total} ({pct:.0f}%)')}")

    print()
    # Actionable recommendations
    missing_py    = [d for d in py_deps if d.status == "MISSING"]
    missing_tools = [t for t in tools   if t.status == "MISSING"]
    critical_files= [f for f in files   if f.critical and not f.exists]

    if not missing_py and not missing_tools and not critical_files:
        print(f"  {c(C.GREEN + C.BOLD, '🎉 Environment is fully configured. Run: python3 arise.py')}")
    else:
        print(f"  {c(C.BOLD, 'Recommended next steps:')}")
        if critical_files:
            print(f"  {c(C.RED, '1.')} Restore missing critical files (clone repo or run setup.sh)")
        if missing_py:
            print(f"  {c(C.YELLOW, '2.')} Install missing Python packages:")
            pkgs = " ".join(d.pip_name for d in missing_py[:8])
            ellipsis = " ..." if len(missing_py) > 8 else ""
            print(f"       {c(C.DIM, f'pip install {pkgs}{ellipsis}')}")
            print(f"       {c(C.DIM, 'OR: pip install -r requirements.txt')}")
        if missing_tools:
            print(f"  {c(C.CYAN, '3.')} Install missing external tools (Go/system):")
            print(f"       {c(C.DIM, 'Run: bash setup.sh  (Debian/Ubuntu)')}")
            print(f"       {c(C.DIM, 'Or install individually — see README.md Tools section')}")


def print_header():
    header = r"""
 █████╗ ██████╗ ██╗███████╗███████╗
██╔══██╗██╔══██╗██║██╔════╝██╔════╝
███████║██████╔╝██║███████╗█████╗
██╔══██║██╔══██╗██║╚════██║██╔══╝
██║  ██║██║  ██║██║███████║███████╗
╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝
    """
    if USE_COLOR:
        print(c(C.CYAN + C.BOLD, header))
    else:
        print(header)
    print(c(C.BOLD, "  Project Analyzer & Dependency Inspector"))
    print(c(C.DIM,  "  ─────────────────────────────────────────"))


# ── Auto-fix helper ───────────────────────────────────────────────────────────

def auto_fix(missing_py: list[PyDep]):
    if not missing_py:
        print(c(C.GREEN, "\nNo missing Python packages to install."))
        return
    pkgs = [d.pip_name for d in missing_py]
    cmd  = [sys.executable, "-m", "pip", "install"] + pkgs
    print(c(C.CYAN, f"\nInstalling {len(pkgs)} package(s): {', '.join(pkgs)}"))
    result = subprocess.run(cmd)
    if result.returncode == 0:
        print(c(C.GREEN, "✔  Installation completed. Re-run analyzer to verify."))
    else:
        print(c(C.RED, "✘  pip install encountered errors. Check output above."))


# ── JSON output ───────────────────────────────────────────────────────────────

def to_json_report(py_deps, tools, evars, files) -> str:
    def py_d(d): return {
        "pip_name": d.pip_name, "import_name": d.import_name, "category": d.category,
        "status": d.status, "installed_version": d.installed_version,
        "min_version": d.min_version, "description": d.description,
    }
    def tool_d(t): return {
        "name": t.name, "category": t.category, "description": t.description,
        "available": t.available, "path": t.path, "install_hint": t.install_hint,
    }
    def env_d(e): return {
        "key": e.key, "present": e.present, "required": e.required,
        "description": e.description,
    }
    def file_d(f): return {
        "path": f.rel_path, "exists": f.exists, "critical": f.critical,
        "description": f.description,
    }
    report = {
        "python_deps": [py_d(d) for d in py_deps],
        "external_tools": [tool_d(t) for t in tools],
        "env_vars": [env_d(e) for e in evars],
        "project_files": [file_d(f) for f in files],
        "summary": {
            "python_installed": sum(1 for d in py_deps if d.status == "OK"),
            "python_total": len(py_deps),
            "tools_available": sum(1 for t in tools if t.available),
            "tools_total": len(tools),
            "env_present": sum(1 for e in evars if e.present),
            "env_total": len(evars),
            "files_found": sum(1 for f in files if f.exists),
            "files_total": len(files),
        }
    }
    return json.dumps(report, indent=2)


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="ARISE — Project Analyzer & Dependency Inspector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--json",    action="store_true", help="Output machine-readable JSON")
    parser.add_argument("--missing", action="store_true", help="Show only missing / failed items")
    parser.add_argument("--fix",     action="store_true", help="Auto-install missing Python packages via pip")
    args = parser.parse_args()

    # Determine project root relative to this script (now one level down, in tools/)
    root = Path(__file__).resolve().parent.parent

    # ── Run all checks ────────────────────────────────────────────────────────
    py_deps = [check_python_dep(d) for d in PYTHON_DEPS]
    tools   = [check_tool(t)       for t in TOOL_DEPS]
    evars   = [check_env_var(e)    for e in ENV_VARS]
    files   = [check_project_file(root, f) for f in PROJECT_FILES]

    # ── Output ────────────────────────────────────────────────────────────────
    if args.json:
        print(to_json_report(py_deps, tools, evars, files))
        return

    print_header()
    print_python_section(py_deps, args.missing)
    print_tool_section(tools, args.missing)
    print_env_section(evars, args.missing)
    print_files_section(files, args.missing)
    print_summary(py_deps, tools, evars, files)

    if args.fix:
        missing_py = [d for d in py_deps if d.status == "MISSING"]
        auto_fix(missing_py)


if __name__ == "__main__":
    main()
