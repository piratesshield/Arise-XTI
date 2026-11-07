"""
AriseAI — offensive tool knowledge base (Tier-3 exploitation).

The AI red-team loop doesn't hallucinate commands — it READS a documented card
per tool (what it does, when to reach for it, the safe flags, the FORBIDDEN
flags, output shape, example) and composes a real command grounded in that card.
Each card is written for the one exploitation posture AriseAI is allowed to run:
**prove impact, read-only** — demonstrate the exploit (read the token, the
version, the cross-tenant record, run `id`) WITHOUT changing target state.

`read_only_guard()` is the hard code enforcement of that posture; it layers on
top of arise_autonomous.validate_action's non-destructive firewall (scope lock,
no shell, argv exec). A command that could change state, destroy data, DoS, or
run a non-benign RCE proof is refused unexecuted — the loop is aggressive about
*proving*, never about *damaging*.

Stdlib only. Never raises.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional

# Benign, read-only commands acceptable as RCE / command-injection PROOF. The loop
# proves code execution with these and nothing else — never a writer/destroyer.
READ_ONLY_PROOF_CMDS = {
    "id", "whoami", "hostname", "uname", "pwd", "ver", "set",
    "cat /etc/hostname", "hostname -i", "hostname -I", "echo",
    "curl http://169.254.169.254", "curl http://metadata.google.internal",
}

# Tokens that make a request/command change state or destroy — always forbidden
# for the read-only posture, regardless of tool.
_DESTRUCTIVE = re.compile(
    r"\b(rm|mkfs|dd|shutdown|reboot|halt|poweroff|kill|pkill|"
    r"drop\s+table|truncate\s+table|delete\s+from|update\s+.+\s+set|insert\s+into|"
    r"format|del\s+/|rmdir|unlink|chmod\s+000|chown|:>\s|>\s*/|mv\s|cp\s+-f|"
    r"shred|wipe|fdisk|crontab|useradd|userdel|passwd|iptables|ufw|"
    r"sqlmap.*--(os-shell|sql-shell|os-cmd|file-write|file-dest|dump-all|dump\b)|"
    r"nuclei.*-(code|headless)|ffuf.*-(d|data)|hydra|medusa|msfconsole|"
    r"slowloris|hping3|--flood|-sS\s+-p-\s.*-T5|"
    r"nmap.*--script[= ]\S*(exploit|intrusive|dos|brute|malware|backdoor))",
    re.IGNORECASE,
)

# Non-GET HTTP verbs in a curl/httpx command → state change.
_WRITE_VERB = re.compile(r"-X\s*(POST|PUT|PATCH|DELETE)|--request\s*(POST|PUT|PATCH|DELETE)", re.IGNORECASE)
_BODY_FLAG = re.compile(r"(^|\s)(-d|--data|--data-raw|--data-binary|--data-urlencode|-T|--upload-file|-F|--form)(\s|=)", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Tool cards
# ---------------------------------------------------------------------------
TOOLS: Dict[str, dict] = {
    "curl": {
        "title": "curl — the workhorse HTTP client",
        "purpose": "issue a single precise HTTP request and read the full response (headers+body) — the primary tool for proving web/SSRF/injection impact.",
        "when": "prove an SSRF reaches internal metadata, read a reflected/stored value, confirm an IDOR response body, follow a redirect.",
        "safe_flags": ["-s (silent)", "-i (include headers)", "-k (ignore TLS)", "-L (follow redirects)",
                       "--max-time N", "-H 'Header: v'", "-A 'UA'", "-b 'cookie'", "-o /dev/null -w '%{http_code}'"],
        "forbidden_flags": ["-X POST/PUT/PATCH/DELETE", "-d/--data*", "-F/--form", "-T/--upload-file (any state change)"],
        "example": "curl -s -i --max-time 12 'https://blog.host/about?source=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token' -H 'Metadata-Flavor: Google'",
        "proof": "the response body containing the metadata/token/leaked value absent from the baseline.",
    },
    "httpx": {
        "title": "httpx (ProjectDiscovery) — fast HTTP prober",
        "purpose": "probe a URL/host and emit structured status/title/tech/headers/body, JSON for easy parsing.",
        "when": "fingerprint a host, confirm a path exists and what it returns, grab tech/headers as evidence.",
        "safe_flags": ["-silent", "-json", "-include-response", "-status-code", "-title", "-tech-detect",
                       "-location", "-web-server", "-content-length", "-ip", "-H 'Header: v'", "-path /x", "-timeout N"],
        "forbidden_flags": ["-x/-method POST/PUT/… with a body", "anything that writes to the target"],
        "example": "httpx -silent -json -include-response -status-code -title -tech-detect -timeout 12 -u https://app.host -path '/api/v1/orders/1337'",
        "proof": "the JSON response (status+body) showing the resource or leak.",
    },
    "nuclei": {
        "title": "nuclei (ProjectDiscovery) — templated detection",
        "purpose": "run a (validated) detection template to confirm a known/synthesized issue with a matcher.",
        "when": "confirm a CVE/misconfig with a public template, or fire an AI-synthesized template AFTER it validates.",
        "safe_flags": ["-t <template>", "-u <url>", "-silent", "-jsonl", "-severity", "-timeout N", "-rl <rate>"],
        "forbidden_flags": ["-code (runs code)", "-headless (browser exec)", "-itags fuzz that writes", "any template with a POST/PUT body that mutates"],
        "example": "nuclei -silent -jsonl -timeout 12 -t /tmp/ariseai_tmpl.yaml -u https://app.host",
        "proof": "a matched result line with extracted evidence.",
        "note": "AI-synthesized templates MUST pass `nuclei -validate` + ScopeGuard sanitize before running, and are DELETED after the test (see nuclei_runner).",
    },
    "ffuf": {
        "title": "ffuf — content/parameter discovery",
        "purpose": "GET-fuzz paths/params to discover reachable resources for an exploit.",
        "when": "find an admin path, an object-id range, a hidden parameter to then exploit with curl/httpx.",
        "safe_flags": ["-u 'https://host/FUZZ'", "-w <wordlist>", "-mc 200,301,403", "-t <threads small>", "-rate N", "-timeout N", "-H 'Header: v'"],
        "forbidden_flags": ["-d/--data (POST body)", "-X POST/PUT/DELETE", "uploads"],
        "example": "ffuf -u 'https://app.host/api/v1/orders/FUZZ' -w ids.txt -mc 200 -rate 20 -t 10",
        "proof": "the discovered reachable path/id (then prove impact with curl).",
    },
    "nmap": {
        "title": "nmap — service/version + safe NSE",
        "purpose": "confirm an exposed service and its version; run only safe/default NSE scripts.",
        "when": "prove a sensitive service (DB, redis, admin) is reachable and fingerprint it.",
        "safe_flags": ["-sV", "-sC (default scripts only)", "-Pn", "-p <ports>", "--open", "--script-timeout", "-T3"],
        "forbidden_flags": ["--script with intrusive/exploit/dos/brute categories", "-T5 flood", "--min-rate huge", "-O (needs root)"],
        "example": "nmap -sV -Pn -p 6379,27017,9200 --open app.host",
        "proof": "the open port + version banner.",
    },
    "sqlmap": {
        "title": "sqlmap — SQL injection confirmation (read-only proof)",
        "purpose": "confirm SQLi and prove impact with READ-ONLY enumeration — never dump real data or get a shell.",
        "when": "a SQLi lead needs proof: confirm injectability + read the DB banner/user/privilege.",
        "safe_flags": ["--batch", "-u <url>", "-p <param>", "--technique=BEUST", "--banner", "--current-user",
                       "--current-db", "--is-dba", "--level 1-2", "--risk 1"],
        "forbidden_flags": ["--dump / --dump-all (reads real data)", "--os-shell / --sql-shell / --os-cmd (RCE)",
                            "--file-write / --file-dest (writes)", "--risk 3 (may include state-changing)"],
        "example": "sqlmap --batch -u 'https://app.host/item?id=1' -p id --technique=BEUST --banner --current-user --is-dba",
        "proof": "the DB banner / current user / is-dba result proving the injection reads the backend.",
    },
}


def render_for(tool_names: Optional[List[str]] = None) -> str:
    """Render the tool cards as a compact markdown brief for the AI prompt."""
    names = [t for t in (tool_names or list(TOOLS)) if t in TOOLS]
    out = ["# Offensive tool knowledge (read-only, prove-impact posture)"]
    out.append("You may ONLY use these tools, and ONLY in a way that proves impact "
               "WITHOUT changing target state. Use the safe flags; never the forbidden "
               "ones. Prove code execution only with a benign command "
               "(id/whoami/hostname/uname). Compose ONE command per step as a plain "
               "argv string (no shell operators ; | & > `).")
    for n in names:
        t = TOOLS[n]
        out.append(f"\n## {n} — {t['title']}")
        out.append(f"- Purpose: {t['purpose']}")
        out.append(f"- When: {t['when']}")
        out.append(f"- Safe flags: {', '.join(t['safe_flags'])}")
        out.append(f"- FORBIDDEN: {', '.join(t['forbidden_flags'])}")
        out.append(f"- Example: `{t['example']}`")
        out.append(f"- Proof = {t['proof']}")
        if t.get("note"):
            out.append(f"- Note: {t['note']}")
    return "\n".join(out)


def tool_names() -> List[str]:
    return list(TOOLS)


# ---------------------------------------------------------------------------
# Read-only enforcement (hard gate, on top of validate_action)
# ---------------------------------------------------------------------------
def read_only_guard(argv: List[str]) -> Optional[str]:
    """Return a refusal reason if `argv` would change target state, destroy, DoS,
    or run a non-benign RCE proof. None means read-only-safe. Never raises."""
    if not argv:
        return "empty command"
    cmd = " ".join(argv)
    tool = (argv[0].rsplit("/", 1)[-1] or "").lower()
    if tool not in TOOLS:
        return f"tool '{tool}' is not in the read-only tool knowledge base"
    if _DESTRUCTIVE.search(cmd):
        return "command matches a destructive/state-changing/DoS pattern — refused (read-only posture)"
    if tool in ("curl", "httpx", "ffuf") and _WRITE_VERB.search(cmd):
        return "non-GET HTTP verb (state change) — refused (read-only posture)"
    if tool in ("curl", "httpx", "ffuf") and _BODY_FLAG.search(cmd):
        return "request body/upload flag (state change) — refused (read-only posture)"
    # RCE proof: if the command carries an injected OS command, it must be benign.
    inj = _extract_injected_cmd(cmd)
    if inj is not None and not _is_benign_proof(inj):
        return f"RCE proof command '{inj[:60]}' is not a benign read-only proof (allowed: id/whoami/hostname/uname/pwd)"
    return None


def _extract_injected_cmd(cmd: str) -> Optional[str]:
    """Best-effort: pull a command out of a classic injection payload so we can
    verify it's a benign proof. Returns None if no obvious injected command."""
    for pat in (r";\s*([a-z][\w\-/ ]{0,40})", r"\|\s*([a-z][\w\-/ ]{0,40})",
                r"\$\(([^)]{1,40})\)", r"`([^`]{1,40})`",
                r"(?:cmd|exec|system|run)=([a-z][\w\-/ ]{0,40})"):
        m = re.search(pat, cmd, re.IGNORECASE)
        if m:
            return m.group(1).strip()
    return None


def _is_benign_proof(injected: str) -> bool:
    base = injected.strip().split()
    if not base:
        return True
    head = base[0].lower()
    benign_heads = {"id", "whoami", "hostname", "uname", "pwd", "ver", "echo", "cat"}
    if head in benign_heads:
        # `cat` only for harmless proof files
        if head == "cat":
            return any(p in injected for p in ("/etc/hostname", "/proc/version", "/etc/os-release"))
        return True
    return False
