---
name: rce
description: OS command injection & RCE — OOB-confirmed, safe markers, never drop a shell
lanes: [rce, command-injection, cmdi]
cwe: [77, 78, 94, 917]
capec: [248, 88, 6]
---

# Command Injection / RCE

The highest-impact class. Confirm with an **out-of-band callback or a benign observable side effect** — never by running a real destructive command.

## Attack surface
Params that reach a shell/exec: `cmd`, `exec`, `ping`, `host`, `ip`, `domain`, `url`, `file`, `path`, `name`, `id` feeding system tools; features like "ping/traceroute this host", format conversion (ImageMagick, ffmpeg, LibreOffice), archive handling, PDF/thumbnail generation, git/svn operations, backup/restore, webhook runners. Also expression/template injection (see ssti) and unsafe deserialization.

## Recon
- Identify inputs that plausibly hit a shell (network diagnostics, file converters, "run"/"import" features).
- Fingerprint OS (headers, error messages) to pick separators + payload style.

## Validate (PoC — the proof)
- **OOB is the safest, strongest proof:** inject a callback, e.g. `; nslookup {{interactsh}}` / `$(curl {{interactsh}})` / backticks / `| ping -c1 {{interactsh}}`; a DNS/HTTP hit from the target = confirmed RCE. Works blind.
- **Time-based (no OOB):** `; sleep 5` vs `sleep 0` with a tight timeout, 2–3 consistent trials to rule out jitter.
- **Separators/wrappers to try:** `;` `|` `||` `&&` `\n` `$(...)` `` `...` `` `{cmd,arg}`; for arg-injection, `-flag` style; for Windows, `& `/`| `.
- **Deserialization RCE:** identify the format (Java `ac ed 00 05`/`rO0`, PHP `O:`, Python pickle, .NET) → note the sink; confirm via OOB gadget, don't pop a real shell.

## Safe-confirm
An OOB interaction or a controlled time delay proves execution. Do NOT run `id`/`whoami`-and-exfil, read files, add users, or establish a shell. Report proof-of-execution + potential impact.

## Tools
`interactsh-client` (OOB), Python for separator/encoding corpus with concurrency, `commix` in detect-mode, nuclei `-dast` where applicable. Chain from SSTI/LFI/upload where those give a code path.
