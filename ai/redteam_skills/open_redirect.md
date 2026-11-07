---
name: open_redirect
description: Open redirect — off-site redirect, SSRF/OAuth-token-theft chains
lanes: [open-redirect, redirect]
cwe: [601]
capec: [194]
---

# Open Redirect

The app redirects to a URL you control. Low-impact alone; a strong chain link (SSRF, OAuth token theft, filter bypass).

## Attack surface
Params: `redirect`, `redirect_uri`, `next`, `url`, `return`, `returnTo`, `dest`, `destination`, `continue`, `callback`, `r`, `u`, `goto`, `back`, `success_url`. Common at: login/logout, OAuth `redirect_uri`, post-action redirects, email links, SSO.

## Validate (PoC — the proof)
- Set the param to an external host and follow the redirect: a `Location:` header (or JS/meta redirect) pointing **off-site** to your host = confirmed. The `Location: https://attacker.example` in the response is the proof.
- **Bypasses when filtered:** `//evil.com`, `https:evil.com`, `/\evil.com`, `https://target.com@evil.com`, `https://target.com.evil.com`, whitelisted-prefix tricks, CRLF in the value, double-encoding, `%09`/`%0d` tricks, unicode dot/slash.
- **Chains (where the real impact is):**
  - **OAuth `redirect_uri`** → if a loose match is accepted, the auth **code/token** is sent to your host = account takeover. High severity — prove the code lands off-site.
  - **SSRF** → if the redirect is followed *server-side*, open-redirect becomes SSRF to internal.
  - **Filter/SSRF-allowlist bypass** → allowed host redirects to internal.

## Safe-confirm
Show the off-site `Location`, or (for OAuth) that a code/token would be delivered to an external host — using your own account. Don't harvest real users' tokens.

## Tools
`curl -sI` to read `Location` without following, Python for the bypass corpus, the ssrf skill when the redirect is server-side-followed.
