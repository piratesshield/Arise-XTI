---
name: subdomain_takeover
description: Subdomain takeover — dangling CNAME/records pointing at claimable services
lanes: [subdomain-takeover, takeover, dns]
cwe: [350, 284]
capec: [142]
---

# Subdomain Takeover

A DNS record points at a third-party service that no longer owns the resource, so you register it and serve content on the victim's subdomain.

## Attack surface
`CNAME`/`ALIAS`/`NS` records pointing at cloud/SaaS: S3, CloudFront, Azure (`*.azurewebsites.net`, `*.blob.core.windows.net`, `*.trafficmanager.net`), GitHub Pages, Heroku, Netlify/Vercel, Fastly, Shopify, Zendesk, Helpscout, Readme, Cargo, Surge, Fly, Firebase. Also dangling `A` records to released cloud IPs, and `NS` delegation to an unclaimed zone.

## Recon
- Resolve every subdomain's `CNAME` chain; flag ones pointing at a known service host.
- Fetch the subdomain: a service-specific **"not found / no such bucket / no app / project not found"** fingerprint page is the tell.

## Validate (PoC — the proof)
- Match the response against the known **takeover fingerprint** for that service (e.g. S3 `NoSuchBucket`, GitHub `There isn't a GitHub Pages site here`, Heroku `No such app`, Fastly `Fastly error: unknown domain`).
- **Proof (safe):** confirm the target resource is **unclaimed/claimable** — the fingerprint + verifying the service reports the name as available. That's a confirmed takeover *without* actually claiming it.
- Only if authorized to fully demonstrate: register the resource and serve a single unique marker page, then show it loads on the victim subdomain. Prefer the fingerprint-only proof.

## Impact
Takeover → phishing on a trusted domain, cookie theft (if cookies are scoped to the parent), OAuth/SSO redirect abuse, CSP/bypass. Grade by what the subdomain is trusted for.

## Safe-confirm
Fingerprint match + "claimable" verification. Do NOT keep a claimed resource or serve real content beyond a throwaway marker if you claim at all.

## Tools
`dnsx`/`dig` for the CNAME chain, `subjack`/`nuclei` takeover templates for fingerprints, `httpx` to fetch the service error page. ARISE already has a subdomain_takeover module — this guides the confirm/validate step.
