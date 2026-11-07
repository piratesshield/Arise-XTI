"""
AriseAI CLI — run the autonomous red-team pentester over a completed scan.

    python3 -m ai_analyst <scan_dir> [--target T] [--provider P] [--model M]
                          [--no-live-verify] [--budget N] [--fail-on-proven]
    python3 -m ai_analyst --selftest        # offline, no network/key/tools

Provider/model default to ARISE_AI_PROVIDER / ARISE_AI_MODEL from the environment
(arise_jobs.py injects these + vault keys into the scan subprocess). The command
is fail-safe: it exits 0 even when the AI or tools are unavailable, so it never
breaks a pipeline — unless --fail-on-proven is set (CI gate: exit 2 on a proven
finding).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile


def _run(args) -> int:
    from ai_analyst.engine import PentestConfig, run_pentest
    cfg = PentestConfig()
    cfg.live_verify = not args.no_live_verify
    cfg.autonomous_exec = bool(args.autonomous_exec)
    cfg.authz_confirmed = bool(args.authorized)
    cfg.recon_only = bool(args.recon_only)
    if args.adversary:
        cfg.adversary = args.adversary
    if args.objective:
        cfg.objective = args.objective
    if args.budget:
        cfg.verify_budget = args.budget
    if args.autonomous_budget:
        cfg.autonomous_budget = args.autonomous_budget
    res = run_pentest(args.scan_dir, target=args.target,
                      provider=args.provider, model=args.model, config=cfg)
    d = res.to_dict()
    counts = d["counts"]
    print(f"[ai_analyst] target={res.target} provider={res.provider}/{res.model}", file=sys.stderr)
    if res.adversary_profile:
        print(f"[ai_analyst] adversary={res.adversary_profile}", file=sys.stderr)
    print(f"[ai_analyst] findings={counts['findings']} proven={counts['proven']} "
          f"observations={counts['observations']} hypotheses={counts['hypotheses']} "
          f"realized={counts['realized']} rejected={counts['rejected']}", file=sys.stderr)
    if res.killchain:
        kc = res.killchain
        print(f"[ai_analyst] killchain depth={kc.get('engagement_depth',0)} "
              f"deepest={kc.get('deepest_tactic','?')} "
              f"chains={len(kc.get('breach_paths',[]))} "
              f"pivots={kc.get('pivots_generated',0)}", file=sys.stderr)
    if res.error:
        print(f"[ai_analyst] note: {res.error}", file=sys.stderr)
    for k, p in sorted(res.artifacts.items()):
        print(f"[ai_analyst] wrote {k}: {p}", file=sys.stderr)
    if args.summary:
        print(json.dumps({"target": res.target, "counts": counts,
                          "artifacts": res.artifacts}, indent=2))
    if args.fail_on_proven and counts["proven"] > 0:
        return 2
    return 0


def _selftest() -> int:
    """Offline end-to-end proof: synthetic scan dir + injected brain, no network."""
    from ai_analyst.engine import PentestConfig, run_pentest

    d = tempfile.mkdtemp(prefix="ariseai_selftest_")
    os.makedirs(os.path.join(d, "24_advanced_attacks"), exist_ok=True)
    os.makedirs(os.path.join(d, "08_directory_discovery"), exist_ok=True)
    with open(os.path.join(d, "manifest.json"), "w") as f:
        json.dump({"target": "example.com"}, f)
    with open(os.path.join(d, "24_advanced_attacks", "offensive_findings.jsonl"), "w") as f:
        f.write(json.dumps({
            "check": "ssrf", "title": "SSRF — cloud metadata reachable",
            "severity": "critical", "host": "app.example.com",
            "url": "https://app.example.com/fetch?url=x", "parameter": "url",
            "confidence": "exploited", "verification": "metadata-content-differential",
            "evidence": "param 'url' fetched metadata endpoint absent from baseline",
            "remediation": "egress allowlist + IMDSv2",
            "baseline": {"status": 200, "len": 10}, "attack": {"status": 200, "len": 400},
        }) + "\n")
    with open(os.path.join(d, "08_directory_discovery", "discovered_endpoints.jsonl"), "w") as f:
        f.write(json.dumps({"host": "app.example.com", "url_class": "api",
                            "sample_url": "https://app.example.com/fetch?url=x",
                            "auth_state": "unauth", "query_variants": ["url"],
                            "method": "GET"}) + "\n")

    # Injected brain: canned plan + narrate, zero network.
    def chat_fn(system, user):
        # The plan prompt leads with the dossier; the narrate prompt leads with
        # "PROVEN FINDINGS". Route on that, not on the word "hypotheses" (which
        # appears in both prompts).
        if "EVIDENCE DOSSIER" in user and "PROVEN FINDINGS" not in user:
            return json.dumps([{
                "id": "ssrf-metadata", "title": "Escalate SSRF on app.example.com to steal GCP token",
                "vuln_class": "ssrf", "target_host": "app.example.com",
                "target_url": "https://app.example.com/fetch?url=x", "parameter": "url",
                "chain": ["recon", "ssrf", "metadata read", "token theft"],
                "based_on": ["SSRF — cloud metadata reachable"],
                "impact": "cloud account compromise", "owasp": "A01",
                "live_verifiable": True, "confidence": "high"},
                {"id": "ghost", "title": "attack a host not in scan",
                 "vuln_class": "xss", "target_host": "evil.invalid",
                 "live_verifiable": True, "confidence": "low"}]), None
        # narrate
        return json.dumps({
            "executive_summary": "One critical SSRF proven; it reaches cloud metadata.",
            "coverage": "Verified SSRF live; A09 not assessable black-box.",
            "findings": [{"ref": None, "title": "SSRF to GCP metadata",
                          "severity": "critical", "owasp": "A01",
                          "impact": "Cloud account takeover via stolen SA token.",
                          "narrative": "Attacker sets url= to the metadata IP; server proxies it.",
                          "poc": "GET /fetch?url=http://169.254.169.254/...",
                          "remediation": "Block link-local egress; require IMDSv2."}],
            "chains": [{"name": "SSRF -> cloud takeover",
                        "path": ["SSRF", "metadata", "SA token", "cloud API"],
                        "hosts": ["app.example.com"], "proven_links": ["ssrf"]}],
        }), None

    cfg = PentestConfig(live_verify=False)  # no live traffic in a self-test
    res = run_pentest(d, chat_fn=chat_fn, config=cfg)
    ok = True

    def check(cond, msg):
        nonlocal ok
        print(("  PASS " if cond else "  FAIL ") + msg)
        ok = ok and cond

    check(res.error is None or "no LLM" not in str(res.error), "engine ran without fatal error")
    check(len(res.proven_findings) == 1, f"exactly one proven finding (got {len(res.proven_findings)})")
    check(res.proven_findings and res.proven_findings[0]["vuln_class"] == "ssrf", "proven finding is SSRF")
    check(res.proven_findings and res.proven_findings[0]["impact_tier"] == 0, "SSRF ranked TIER_UNAUTH (0)")
    check(any(h.get("status") == "rejected" for h in res.hypotheses),
          "grounding gate rejected the out-of-scope (evil.invalid) hypothesis")
    check(all(f.get("ai_generated") for f in res.findings), "every finding stamped ai_generated")
    check(res.writeup.get("executive_summary"), "write-up produced an executive summary")
    check("report_md" in res.artifacts and "findings_sarif" in res.artifacts,
          "wrote report.md + SARIF artifacts")
    # Artifact sanity.
    rp = os.path.join(d, res.artifacts.get("report_md", ""))
    check(os.path.isfile(rp) and "AriseAI" in open(rp).read(), "report.md exists and is branded AriseAI")
    check("strix" not in open(rp).read().lower(), "no 'strix' string anywhere in the report")
    print(f"\nSelf-test artifacts in: {d}")
    print("RESULT:", "ALL PASS ✅" if ok else "FAILURES ❌")
    return 0 if ok else 1


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="ai_analyst", description="AriseAI autonomous red-team pentester")
    ap.add_argument("scan_dir", nargs="?", help="completed EASM scan output directory")
    ap.add_argument("--target", help="scope apex (defaults to manifest.json / dir name)")
    ap.add_argument("--provider", help="LLM provider (default: $ARISE_AI_PROVIDER)")
    ap.add_argument("--model", help="LLM model (default: $ARISE_AI_MODEL)")
    ap.add_argument("--recon-only", action="store_true",
                    help="run on recon-stage data only — attack surface assessment, no exploitation")
    ap.add_argument("--adversary", default="",
                    help="adversary emulation profile: APT29, FIN7, APT28, Lazarus, Opportunistic")
    ap.add_argument("--no-live-verify", action="store_true", help="skip live differential verification (tier 2)")
    ap.add_argument("--autonomous-exec", action="store_true",
                    help="enable the deepest tier — the merged Autonomous Action live-tool loop (needs a key + scope)")
    ap.add_argument("--authorized", action="store_true",
                    help="confirm you are authorized to actively test these hosts (required for --autonomous-exec)")
    ap.add_argument("--objective", help="free-form objective to steer the autonomous tier")
    ap.add_argument("--budget", type=int, help="max hypotheses to live-verify")
    ap.add_argument("--autonomous-budget", type=int, help="max tool executions in the autonomous tier")
    ap.add_argument("--fail-on-proven", action="store_true", help="exit 2 if any finding is proven (CI gate)")
    ap.add_argument("--summary", action="store_true", help="print a JSON summary to stdout")
    ap.add_argument("--selftest", action="store_true", help="run the offline self-test and exit")
    args = ap.parse_args(argv)

    if args.selftest:
        return _selftest()
    if not args.scan_dir:
        ap.error("scan_dir is required (or use --selftest)")
    return _run(args)


if __name__ == "__main__":
    sys.exit(main())
