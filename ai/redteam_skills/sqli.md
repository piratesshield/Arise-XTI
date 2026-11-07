---
name: sqli
description: SQL injection — error-based, boolean-blind, time-blind, across query/body/header
lanes: [sqli]
cwe: [89, 943]
capec: [66]
---

# SQL Injection

User input reaches a SQL statement unparameterized. Confirm by *controlling the query's truth or timing*, not by seeing one error.

## Attack surface
Every parameter: query string, POST body (form + JSON), path segments, `Cookie`, `X-Forwarded-For`/custom headers, `User-Agent`, GraphQL args, ORDER BY / column names (identifier injection), search & filter params, pagination.

## Recon / triage
- Fast pass: append `'`, `"`, `)`, `` ` `` to each param; watch for a 500, a DB error signature (`SQL syntax.*MySQL`, `ORA-\d{5}`, `PostgreSQL.*ERROR`, `Unclosed quotation`), or a length/shape change vs baseline. **This is triage, not proof.**
- Nuclei `-dast` error-based fuzz first to shortlist; only promising params go to sqlmap.

## Validate (PoC — the proof)
Pick the strongest oracle that works:
- **Boolean-blind:** `id=1 AND 1=1` vs `id=1 AND 1=2` → same page vs different/empty. Two responses that flip on a true/false condition = confirmed.
- **Error-based:** force a DB-specific error that reflects a computed value (`AND 1=CONVERT(int,@@version)`).
- **Time-blind (last resort, capped):** `id=1 AND SLEEP(5)` vs `SLEEP(0)` — measure delta with a tight timeout; require 2–3 consistent trials to rule out jitter. Never chain long sleeps.
- **UNION** only to prove column read on a clearly injectable point; extract `@@version`/`current_user`, not real table data.
- Confirm the **injection context**: numeric vs single-quote vs double-quote vs identifier — the working breaker tells you.

## Safe-confirm
Prove controllability (version/user/boolean-flip), do NOT dump tables, `--os-shell`, stack queries, or write files. One confirmed oracle + the exact request is the finding.

## sqlmap discipline
`sqlmap -u <url> --batch --risk=2 --level=3 -p <param>` with `--technique=BEUST`; add `--time-sec=8` cautiously; `--tamper` for WAF; feed a saved request file (`-r req.txt`) for JSON/auth bodies. Time-box each target (ARISE caps per-run). WAF-aware: back off on 403 bursts.

## Tools
nuclei `-dast` (triage), sqlmap (deep), `arjun` (hidden params), Python for concurrent boolean/time trials with statistical timing.
