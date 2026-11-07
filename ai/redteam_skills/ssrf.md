---
name: ssrf
description: Server-Side Request Forgery — OOB-confirmed, cloud metadata, internal reach
lanes: [ssrf]
cwe: [918]
capec: [664]
---

# SSRF

The server fetches a URL you influence. Confirm out-of-band (the server pings *your* listener) — that proves server-side fetch with zero access to internal data.

## Attack surface
Params/bodies named `url`, `uri`, `link`, `src`, `dest`, `redirect`, `next`, `callback`, `webhook`, `image`/`imageUrl`, `file`, `path`, `domain`, `host`, `feed`, `proxy`, `target`. Also: URL-fetching features (link preview, PDF/screenshot render, avatar-from-URL, import-from-URL, webhooks, SSO metadata/JWKS URLs, XML/SVG parsers → XXE-SSRF).

## Recon
- Route every url-like param to an **interactsh/OOB** callback and watch for DNS/HTTP interaction.
- Note the parser: full-URL vs host-only vs path; does it follow redirects? (open-redirect → SSRF chain).

## Validate (PoC — the proof)
1. **OOB is the proof:** inject `http://{{interactsh-url}}`; a DNS **and/or** HTTP hit from the target's egress IP = confirmed blind SSRF. Nuclei `-dast` `ssrf-oob` template does exactly this.
2. **Response-based:** if the fetched body is reflected, point at `http://127.0.0.1:<port>` / internal hostnames and diff.
3. **Cloud metadata (high impact — confirm reachability, don't exfil creds):** `http://169.254.169.254/latest/meta-data/` (AWS IMDSv1), `metadata.google.internal` (GCP, needs `Metadata-Flavor:Google`), Azure IMDS. A 200 from metadata = critical; capture the *path list*, not the credential body.
4. **Bypasses when filtered:** IP encodings (decimal `2130706433`, octal, IPv6 `[::1]`, `[::ffff:127.0.0.1]`), DNS rebinding, `@`-in-authority (`http://allowed@169.254.169.254`), redirect-to-internal, alternate schemes (`gopher://`, `dict://`, `file://`).

## Safe-confirm
OOB interaction or a metadata **path listing** proves it. Do NOT read/exfiltrate actual cloud credentials, keys, or internal secrets — stop at proof of reach and report the potential.

## Tools
`interactsh-client` (OOB oracle), nuclei `-dast` ssrf template, `curl` for scheme/encoding bypass trials, Python for concurrent bypass corpus. Chain with open-redirect findings.
