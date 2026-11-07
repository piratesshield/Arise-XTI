#!/usr/bin/env python3
"""
ARISE — Intelligent subdomain brute-force (Phase 6.5).

Goes beyond passive enumeration:
  1. Pattern generation from ALREADY-discovered names (dev-/staging-/api-/internal-
     prefixes and suffixes applied to observed labels).
  2. A high-signal cloud/env wordlist.
  3. DNS resolution of candidates (resolve-based brute) — only names that resolve
     and were NOT already known are reported as newly discovered.

Prefers `dnsx` if available for speed; falls back to the stdlib resolver.
Non-destructive (DNS only). Output: newly-resolved hosts to --out (+ JSONL).
"""

import sys as _sys, os as _os
_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys

AFFIXES = ["dev", "staging", "stage", "test", "qa", "uat", "preprod", "prod",
           "api", "internal", "intranet", "admin", "portal", "vpn", "gateway",
           "gw", "auth", "sso", "git", "jenkins", "jira", "grafana", "kibana",
           "backup", "old", "new", "beta", "demo", "sandbox", "mobile", "app",
           "cdn", "static", "assets", "media", "img", "mail", "smtp", "ns1",
           "db", "sql", "redis", "cache", "mq", "k8s", "docker", "registry"]

# AI / MCP host labels (MCP_AI_DISCOVERY roadmap, Phase 1). Kept as a separate
# list so the AI surface is explicit and easy to tune; concatenated into the
# candidate generator alongside AFFIXES. These are the same labels the URL
# classifier tags on (discovery/url_classify.py _*_HOST_LABELS) — brute and tag
# stay in sync. Newly-resolved names flow through Module 3 DNS + everything
# downstream exactly like any other subdomain (tagging happens later).
AI_MCP_AFFIXES = ["mcp", "ai", "llm", "llms", "chat", "chatbot", "copilot",
                  "assistant", "agent", "agents", "gpt", "bot", "rag", "genai",
                  "ollama", "vllm", "inference", "aiapi", "ai-api", "vector",
                  "vectordb", "embeddings", "copilot-api", "mcp-server",
                  "mcp-gateway", "prompt", "completions"]


def _known_and_root(scan_dir, root_arg):
    known, labels, root = set(), set(), root_arg or ""
    if scan_dir:
        for rel in ("02_subdomain_enumeration/all_subdomains.txt",
                    "03_dns_resolution/resolved.txt",
                    "04_http_discovery/resolved_unique.txt"):
            p = os.path.join(scan_dir, rel)
            if not os.path.isfile(p):
                continue
            for line in open(p, errors="ignore"):
                h = line.strip().lower().replace("https://", "").replace("http://", "").split("/")[0]
                if h and "." in h:
                    known.add(h)
    # infer apex/root as the most common 2-label suffix
    if not root and known:
        from collections import Counter
        c = Counter(".".join(h.split(".")[-2:]) for h in known if h.count(".") >= 1)
        root = c.most_common(1)[0][0] if c else ""
    for h in known:
        if root and h.endswith("." + root):
            first = h[: -(len(root) + 1)].split(".")[-1]
            if first:
                labels.add(first)
    return known, labels, root


def _gen_candidates(labels, root, extra_affixes=None):
    cand = set()
    if not root:
        return cand
    affixes = AFFIXES + AI_MCP_AFFIXES + list(extra_affixes or [])
    # AI/MCP labels are highest-value as bare third-level names (mcp.root,
    # ai.root, ollama.root); the combined ai-{lbl}/{lbl}-ai forms are generated
    # too but are lower-signal and bounded by --max-candidates.
    for a in affixes:
        cand.add(f"{a}.{root}")
    for lbl in list(labels)[:200]:
        for a in affixes:
            cand.add(f"{a}-{lbl}.{root}")
            cand.add(f"{lbl}-{a}.{root}")
            cand.add(f"{a}.{lbl}.{root}")
    return cand


def _resolve_dnsx(names, timeout=30):
    dnsx = shutil.which("dnsx")
    if not dnsx:
        return None
    try:
        p = subprocess.run([dnsx, "-silent", "-a", "-resp-only"],
                           input="\n".join(names), text=True, capture_output=True,
                           timeout=max(30, len(names) // 50))
        # dnsx -resp-only prints IPs; re-run without -resp-only to get hostnames
        p2 = subprocess.run([dnsx, "-silent"], input="\n".join(names), text=True,
                            capture_output=True, timeout=max(30, len(names) // 50))
        return {l.strip().lower() for l in p2.stdout.splitlines() if l.strip()}
    except Exception:
        return None


def _resolve_stdlib(names):
    out = set()
    for n in names:
        try:
            socket.gethostbyname(n)
            out.add(n.lower())
        except Exception:
            continue
    return out


def main():
    ap = argparse.ArgumentParser(description="ARISE intelligent subdomain brute-force")
    ap.add_argument("scan_dir", nargs="?")
    ap.add_argument("--root", help="apex domain (inferred from scan if omitted)")
    ap.add_argument("--out",
                    help="Path to write the newly-resolved subdomain list. "
                         "Default: <scan_dir>/02_subdomain_enum/brute_subdomains.txt "
                         "(this is the RECON module the script belongs to — findings "
                         "flow into Module 3 DNS resolution and everything downstream).")
    ap.add_argument("--jsonl-out",
                    help="Path to write per-finding JSONL. Default alongside --out.")
    ap.add_argument("--max-candidates", type=int, default=5000)
    ap.add_argument("--ai-extra", default="",
                    help="Comma-separated extra AI/MCP host labels to brute "
                         "(e.g. org-anchored names); appended to AI_MCP_AFFIXES.")
    args = ap.parse_args()

    known, labels, root = _known_and_root(args.scan_dir, args.root)
    if not root:
        print("subdomain_bruteforce: could not determine apex domain; skipping", file=sys.stderr)
        return 0
    extra = [s.strip() for s in (args.ai_extra or "").split(",") if s.strip()]
    candidates = _gen_candidates(labels, root, extra_affixes=extra) - known
    candidates = list(candidates)[: args.max_candidates]

    resolved = _resolve_dnsx(candidates)
    if resolved is None:
        resolved = _resolve_stdlib(candidates)
    new = sorted((resolved or set()) - known)

    # Default output directory is Module 2 (subdomain enumeration) — this
    # script is a subdomain ENUMERATION tool, and previously landing in
    # 24_advanced_attacks meant its discoveries never got resolved / probed
    # / scanned by downstream stages (Module 24 runs at end of pipeline).
    # Callers can still override --out and --jsonl-out for custom placement.
    base = os.path.join(args.scan_dir, "02_subdomain_enum") if args.scan_dir else "."
    os.makedirs(base, exist_ok=True)
    txt_out = args.out or os.path.join(base, "brute_subdomains.txt")
    jsonl_out = args.jsonl_out or os.path.join(base, "subdomain_brute_findings.jsonl")
    os.makedirs(os.path.dirname(txt_out), exist_ok=True)
    os.makedirs(os.path.dirname(jsonl_out), exist_ok=True)
    with open(txt_out, "w") as f:
        f.write("\n".join(new) + ("\n" if new else ""))
    with open(jsonl_out, "w") as f:
        for h in new:
            f.write(json.dumps({
                "module": "subdomain_bruteforce", "severity": "info", "confidence": "confirmed",
                "title": "New subdomain discovered via resolve-based brute-force",
                "host": h, "root": root,
                "evidence": f"{h} resolves in DNS and was not in passive enumeration",
                "remediation": "Review the exposure; retire forgotten dev/staging hosts.",
            }) + "\n")
    print(f"subdomain_bruteforce: {len(candidates)} candidate(s), {len(new)} NEW resolved -> {txt_out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
