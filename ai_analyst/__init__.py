"""
AriseAI — Autonomous AI Red-Team Pentester (the "AI Analyst")
=============================================================
Works on ANY pipeline stage — from bare recon (Modules 1-9) through full results:

  * **Recon analysis** (--recon-only): attack surface assessment from recon data —
    tech stacks, WAFs, OSINT, missing headers, exposed ports → prioritized targets.
  * **Full pentest** (default): reason over all evidence → rank attack hypotheses →
    live-verify the top ones → emit only findings proven with a PoC.
  * **Adversary emulation** (--adversary APT29|FIN7|APT28|Lazarus|Opportunistic):
    run as a specific threat actor — hypotheses filtered to the actor's real-world
    TTP repertoire, kill chain tracked through ATT&CK tactical phases, dynamic
    pivot hypotheses generated when findings are proven.

Design principles:
  * Exploit-and-prove, never flag. A finding needs live proof or upstream
    exploit-confirmation. Unproven observations are labelled, never confirmed.
  * Kill chain state machine: proven findings advance the engagement through
    ATT&CK phases — dynamic pivot rules auto-generate next-step hypotheses.
  * Adversary-aware: the brain thinks like the selected threat actor.
  * Rank by proven impact, not scanner severity.
  * WAF-aware: injection hypotheses against WAF-protected hosts are demoted.
  * Recon-grounded: the brain sees real tech stacks, WAFs, ports, and OSINT.
  * ATT&CK coverage: report shows which techniques were exercised vs. the
    actor's known repertoire.
  * Honest coverage. The report states what was tested and what could not be.
  * Safety is reused (ScopeGuard + offensive_verify), never reinvented.

Fail-safe: run_pentest() never raises; missing data degrades to the best partial result.
"""

from __future__ import annotations

__all__ = ["run_pentest", "PentestConfig", "PentestResult"]

# Lazy re-exports so `import ai_analyst` is cheap and never drags in a provider
# SDK or the heavy offensive engine unless the caller actually runs a pentest.


def run_pentest(*args, **kwargs):
    from ai_analyst.engine import run_pentest as _run
    return _run(*args, **kwargs)


def __getattr__(name):  # PEP 562 — expose dataclasses without eager imports
    if name in ("PentestConfig", "PentestResult"):
        from ai_analyst import engine
        return getattr(engine, name)
    raise AttributeError(f"module 'ai_analyst' has no attribute {name!r}")
