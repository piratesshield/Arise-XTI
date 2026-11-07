---
name: csrf
description: Cross-Site Request Forgery — state-changing actions without anti-CSRF protection
lanes: [csrf]
cwe: [352]
capec: [62, 111]
---

# CSRF

A state-changing request that rides the victim's cookies without an unguessable token or a same-site barrier. Only matters for **cookie-based** auth performing sensitive actions.

## Attack surface
Cookie-authenticated POST/PUT/PATCH/DELETE that change state: change email/password, transfer, add member, update settings, delete, purchase. NOT bearer-token/`Authorization`-header APIs (those aren't auto-sent cross-site).

## Recon
- Confirm the action uses an **ambient cookie** for auth (not a header token).
- Look for the defenses: a CSRF token (form field/header), `SameSite` cookie attribute (`Lax`/`Strict`), Origin/Referer checks, custom-header requirement, re-auth.

## Validate (PoC — the proof)
- **Missing token:** replay the state-changing request **without** the CSRF token / with a wrong or another user's token → if it still succeeds, protection is absent/broken. Proof = the action completes token-less.
- **SameSite gap:** cookie lacks `SameSite` (or `=None` without justification) and no token → cross-site auto-send works. Build a minimal auto-submitting HTML form PoC that performs the action.
- **Bypasses:** token not validated server-side, token reuse across users/sessions, token in a predictable place, method downgrade (GET performs the action), `Content-Type` change to `text/plain`/`multipart` to dodge preflight, Referer-check bypass (omit/spoof).
- **Login CSRF / logout CSRF** where relevant.

## Safe-confirm
Show the action succeeds without a valid token (or a working auto-submit PoC) against your **own** account. Don't perform irreversible actions on real users.

## Tools
`curl` to replay token-stripped requests, a tiny HTML auto-submit form for the PoC, the proxy to compare with/without token. Check `SameSite` on every auth cookie.
