---
name: secrets_exposure
description: Exposed secrets, config, VCS, backups, debug endpoints — and safe validation
lanes: [exposure, sensitive-review, cloud-review]
cwe: [200, 538, 540, 552, 615]
capec: [545, 118, 150]
---

# Secrets & Sensitive Exposure

Recon finds the path; the finding is only real when the response **content** confirms it (a signature, not a 200) and, for credentials, when they're shown to be *live* — read-only.

## Attack surface
`/.git/config`+`/HEAD`, `/.env`(+`.local`/`.prod`/`.bak`), `/.aws/credentials`, `/actuator/env|heapdump`, `/server-status`, `/phpinfo.php`, `wp-config.php.bak`, `/debug|/_profiler|/trace`, `/backup|dump.sql|db.zip`, `/swagger|/openapi|/api-docs`, source maps (`.js.map`), CI files, `/.DS_Store`, exposed `/config.json`.

## Validate (PoC — the proof)
- **Content signature, not status:** `.git/config` → `[core]`+`repositoryformatversion`; `.env` → `APP_KEY=`/`DB_PASSWORD=`; actuator/env → `propertySources`; heapdump → downloadable binary. Match the signature = confirmed exposure.
- **`.git` → full source:** if `/.git/` is listable or objects fetch, reconstruct with `git-dumper` → then secret-scan the recovered repo (secondary findings).
- **Live-credential validation (read-only, high value):** a leaked key is *info-disclosure* until proven live. Validate against the provider's **read-only identity** endpoint only — e.g. AWS `sts get-caller-identity`, GitHub `GET /user`, Slack `auth.test`, Stripe `GET /v1/account`. A 200 identity = confirmed live credential (critical). Never write, spend, or pivot.

## Safe-confirm
Confirm by signature or a single read-only identity call. Do NOT clone mass data, use write scopes, or move laterally. In the report, fingerprint the secret (`AKIA…last4`), never paste it in full.

## Impact grading
Live credential > source disclosure with secrets > config with secrets > generic config/info leak. A static asset or public metadata is an observation, not a vuln.

## Tools
`git-dumper`, `trufflehog`/`gitleaks` on recovered source, provider CLIs for the *identity* call only, `curl`+grep for signatures. nuclei exposure templates for breadth.
