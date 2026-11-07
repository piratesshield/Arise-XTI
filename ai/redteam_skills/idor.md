---
name: idor
description: IDOR / BOLA — object-level authorization failures, cross-account data access
lanes: [bola, idor, api-blackbox]
cwe: [639, 284, 285, 566, 862, 863]
capec: [1, 180]
---

# IDOR / BOLA

Object-level authorization failures let one principal reach another's objects. Treat every object reference as untrusted until proven bound to the caller. This is the #1 API bug class and rarely needs a payload — just a swapped identifier and two identities.

## Attack surface
- **Reference locations:** path segments, query params, JSON body fields, form-data, headers, cookies, JWT claims, GraphQL args.
- **Identifier forms:** ints, UUID/ULID (UUIDv1/ULID are time-ordered → guessable in a window), Snowflake, slugs, base64/hex blobs, composite `{org}:{user}`.
- **Relationship refs that widen it:** `ownerId`, `accountId`, `tenantId`, `orgId`, `projectId`, `teamId`.
- **Projection knobs that bypass serializer authz:** `fields`, `include`, `expand`, `select`, `populate`.

## High-value targets
Exports/reports (CSV/PDF/ZIP), invoices/payment-methods/transactions, messages/notifications, audit logs, admin/impersonation tools, file-storage keys (signed URLs), background-job result IDs, multi-tenant org/workspace/project resources.

## Recon
- Seed valid IDs from list/search/suggest/export endpoints, JS bundles, notifications, webhooks — **secondary IDOR** (leak an ID here, use it there).
- Find hidden params with `arjun -u <url>` and `-m POST` — surfaces `as_user=`, `owner_id=`, `include_deleted=1`.
- Note ID entropy: sequential ints → trivially enumerable; UUIDv4 → need a leak source.

## Validate (PoC — the proof)
1. Capture the **legitimate** request for *your own* object → baseline (status + body shape + length).
2. Re-issue with a **neighbor/other-tenant** object id, **same token**. Broken authz = `200` + *another* subject's object (different email/name/amount), not your own and not a generic 403/empty.
3. Horizontal (peer object), vertical (admin-only object), cross-tenant (other org). Try PATCH/PUT for silent *write* IDOR.
4. Batch/bulk endpoints often check only element[0] — slip a foreign id mid-array.
- **Differential is the proof:** two responses, two identities, showing data that isn't the caller's.

## Safe-confirm (ARISE is confirm-not-exploit)
Read one adjacent object and diff it; do NOT enumerate mass PII or mutate records. A single cross-identity read with a length/field diff is a confirmed finding. Redact the leaked value in the report to a fingerprint (first/last 4).

## Tools
`arjun` (param discovery), `ffuf` for id ranges (`-w ids.txt`), `curl`/httpx for the two-identity diff, `jq` to compare body shape. Prefer a small Python diff over manual eyeballing.
