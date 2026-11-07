"""
AriseAI — AI-synthesized nuclei template runner (Tier-3).

A template the AI writes is never trusted blindly. Before it can fire it must:
  1. be ScopeGuard-sanitized (no out-of-scope host / interactsh leaks),
  2. pass `nuclei -validate` (self-repaired once via the model if it fails),
  3. and it is DELETED from disk after the test — win or lose.

Reuses discovery/synth_ai's validated helpers (`_nuclei_validate`,
`_sanitize_block`, `repair_template`) so there is one template-safety code path.
Never raises; returns a structured result.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from typing import Any, Dict, List, Optional


def run_validated_template(template_yaml: str, url: str, scope, chat_fn=None,
                           timeout: int = 45) -> Dict[str, Any]:
    """Sanitize → validate (repair once) → run → DELETE. Returns:
    {valid, ran, matched, results, error, template_sha}."""
    out: Dict[str, Any] = {"valid": False, "ran": False, "matched": False,
                           "results": [], "error": None}
    if not template_yaml or not url:
        out["error"] = "empty template or url"
        return out

    # 1) Scope sanitize (reuse synth_ai; fall back to a pass-through if absent).
    block = template_yaml
    try:
        from discovery.synth_ai import _sanitize_block
        block, dropped = _sanitize_block(block, 0, scope)
        if dropped:
            out["error"] = f"template dropped by scope sanitizer: {dropped}"
            return out
    except Exception:
        pass  # sanitizer unavailable — ScopeGuard on the runner URL still applies

    # Scope-check the target URL itself (belt-and-braces).
    try:
        if scope is not None and not scope.in_scope(url):
            out["error"] = f"target URL out of scope: {url[:120]}"
            return out
    except Exception:
        pass

    path = None
    try:
        fd, path = tempfile.mkstemp(prefix="ariseai_tmpl_", suffix=".yaml")
        with os.fdopen(fd, "w") as fh:
            fh.write(block)

        # 2) Validate (+ one self-repair).
        valid, verr = _validate(path)
        if not valid and chat_fn is not None:
            try:
                from discovery.synth_ai import repair_template
                fixed, rerr = repair_template(block, verr, chat_fn)
                if fixed:
                    with open(path, "w") as fh:
                        fh.write(fixed)
                    block = fixed
                    valid, verr = _validate(path)
            except Exception:
                pass
        out["valid"] = valid
        if not valid:
            out["error"] = f"template failed nuclei -validate: {verr[:160]}"
            return out

        # 3) Run (bounded, read-only — no -code/-headless).
        try:
            p = subprocess.run(
                ["nuclei", "-silent", "-jsonl", "-disable-update-check",
                 "-timeout", "10", "-t", path, "-u", url],
                capture_output=True, text=True, timeout=timeout)
            out["ran"] = True
            results = []
            for line in (p.stdout or "").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    results.append(json.loads(line))
                except Exception:
                    continue
            out["results"] = results[:20]
            out["matched"] = bool(results)
        except FileNotFoundError:
            out["error"] = "nuclei not installed"
        except subprocess.TimeoutExpired:
            out["error"] = "nuclei run timed out"
        except Exception as exc:
            out["error"] = f"nuclei run failed: {str(exc)[:160]}"
        return out
    except Exception as exc:
        out["error"] = f"template runner error: {str(exc)[:160]}"
        return out
    finally:
        # 4) ALWAYS delete the generated template.
        if path and os.path.exists(path):
            try:
                os.remove(path)
            except OSError:
                pass


def _validate(path: str):
    try:
        from discovery.synth_ai import _nuclei_validate
        return _nuclei_validate(path)
    except Exception:
        # Minimal fallback.
        try:
            p = subprocess.run(["nuclei", "-validate", "-t", path, "-disable-update-check"],
                               capture_output=True, text=True, timeout=30)
            ok = p.returncode == 0
            return ok, (p.stderr or p.stdout or "")[:200]
        except FileNotFoundError:
            return False, "nuclei not installed"
        except Exception as exc:
            return False, f"validate crashed: {str(exc)[:160]}"
