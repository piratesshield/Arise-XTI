---
name: http_methods
description: HTTP verb tampering & method-based access bypass, dangerous methods
lanes: [dangerous-methods, http-methods, verb]
cwe: [650, 285, 749]
capec: [274]
---

# HTTP Method Tampering

Access control is often applied per-method. Swap the verb and the check may not follow.

## Attack surface
Any endpoint with method-sensitive authz: admin actions gated on POST but reachable via GET, framework routes that treat unknown verbs as GET, WebDAV (`PUT`/`DELETE`/`MOVE`/`COPY`/`PROPFIND`), API gateways with per-method rules.

## Recon
- `OPTIONS <path>` → read the `Allow` / `Access-Control-Allow-Methods` header: does it advertise `PUT`/`DELETE`/`PATCH`/`TRACE`? (ARISE synth's methods.yaml already does this.)
- Note which state-changing routes exist and how they're normally invoked.

## Validate (PoC — the proof)
- **Verb-swap authz bypass:** take a protected action normally done via `POST` and issue it as `GET`/`HEAD`/`PUT`; if the action executes (or data returns) without the expected auth, that's the finding. Proof = the state change / data appears under the swapped verb.
- **Method override headers:** `X-HTTP-Method-Override: PUT`, `X-HTTP-Method: DELETE`, `_method=PUT` body param — bypasses gateway rules that only inspect the real verb.
- **Dangerous methods enabled:** `PUT` a file → fetch it (write primitive); `DELETE` a resource (confirm carefully — don't destroy real data; a 200/204 on a throwaway object is enough). `TRACE` → XST.
- **HEAD as GET:** some stacks run the handler for HEAD, leaking side effects or bypassing GET-only auth.

## Safe-confirm
Confirm the bypass on a **read** or a throwaway/idempotent action; never `DELETE` or overwrite real data to prove it. `OPTIONS`/`HEAD`/override-header evidence + one benign swapped-verb success is enough.

## Tools
`curl -X <VERB>` and `-H 'X-HTTP-Method-Override:'`, nuclei synth methods.yaml (OPTIONS read), Python to sweep verbs × endpoints and diff auth outcomes.
