---
name: jwt_auth
description: JWT & authentication — alg confusion, weak secret, claim tampering, session flaws
lanes: [auth-jwt]
cwe: [287, 345, 347, 384, 613]
capec: [115, 593, 21]
---

# JWT & Authentication

Most JWT wins are **offline** (crack/analyze a captured token) or a single tampered request. Harvest tokens from responses/cookies/localStorage first.

## Attack surface
`Authorization: Bearer`, cookies, `localStorage`/`sessionStorage`, response bodies at login/refresh, SSO/OAuth callbacks. Also: password reset tokens, session cookies (flags, fixation), remember-me, MFA bypass.

## Validate (PoC — the proof)
- **alg:none:** set header `{"alg":"none"}`, strip signature, keep/escalate claims (`role:admin`, `sub:<other>`) → if the server accepts it, auth is broken. Proof = a privileged action/response with the unsigned token.
- **HS/RS confusion (alg confusion):** server verifies RS256 but you re-sign HS256 using the **public key** as the HMAC secret → forged valid token.
- **Weak HMAC secret:** crack offline with `jwt_tool`/`hashcat` against a wordlist; if cracked, mint arbitrary claims. 100% offline — zero requests until you test the forged token once.
- **Claim tampering:** flip `role`, `isAdmin`, `tenant`, `sub`, `exp` (expiry not enforced?), `kid` (path traversal / SQLi in key lookup), `jku`/`x5u` (point at attacker JWKS → forge).
- **Session:** does logout invalidate server-side? Fixation (token unchanged across auth boundary)? Reset-token entropy/reuse?

## Safe-confirm
Prove acceptance of a forged/tampered token with a **single** privileged request against your own account context; don't take over other accounts. Report the exact tampered token (redact any real secret cracked → note "weak secret: <N> chars, cracked").

## Tools
`jwt_tool` (analyze, alg:none, confusion, crack), `hashcat -m 16500` for HMAC brute, Python `pyjwt` to forge/verify, the proxy to replay. Decode every JWT you see before anything else.
