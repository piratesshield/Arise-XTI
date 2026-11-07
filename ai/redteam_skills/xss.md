---
name: xss
description: Cross-site scripting — reflected, stored, DOM; context-aware breakout
lanes: [xss, search-fuzz]
cwe: [79, 80, 83]
capec: [63, 591, 592]
---

# XSS

Input is reflected into a page without correct output encoding. The bug is **context-specific** — the same input is safe in one sink and executes in another.

## Attack surface
Reflected: any param echoed into the response (search, error messages, redirects, headers → body). Stored: profile fields, comments, filenames, support tickets, webhook/callback labels, admin views of user input. DOM: `location.hash`/`search`/`referrer` → `innerHTML`/`document.write`/`eval`/jQuery `$()`/template sinks.

## Recon
1. Inject a **unique benign marker** (`aris0x{{rand}}`) into every param; grep responses for it. No reflection → no reflected XSS there.
2. For each reflection, identify the **context**: HTML text, attribute (single/double/unquoted), `<script>` block, JS string, URL attribute (`href`/`src`), CSS, comment.
3. DOM: map source→sink in JS bundles (`katana -jc`, then grep for sinks); use the browser to trace taint.

## Validate (PoC — the proof)
- Break out of the exact context, then execute. Attribute: `"><svg onload=...>`; JS string: `';alert()//`; unquoted attr: ` onmouseover=...`; URL: `javascript:...`.
- **Proof = execution**, evidenced by the marker firing (a unique DOM mutation / a callback), not mere reflection. Use a non-`alert` oracle that's scriptable: set `document.title` to a unique token and read it back, or hit an interactsh/OOB URL from the payload.
- Stored: confirm it executes when the *storing* view is rendered (and note who sees it — admin-viewed stored XSS = higher impact).
- Bypass reflected filters with the smallest working mutation; record WAF/encoding behavior.

## Safe-confirm
A unique, self-evident execution marker (title change, OOB ping) proves it without hijacking a real session. Do NOT steal cookies/tokens or pivot to account takeover; note the *potential* impact instead.

## Tools
`dalfox` (context-aware, `--skip-bav` off to catch SSTI/CRLF/redirect too), nuclei `-dast` reflection fuzz, `katana -jc` for JS/DOM sources, the browser for DOM-XSS taint. Spray via script — never iterate payloads by hand in the browser.
