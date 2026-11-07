---
name: graphql
description: GraphQL — introspection, BOLA via nodes, injection, batching/DoS, auth gaps
lanes: [graphql]
cwe: [200, 639, 863, 770]
capec: [54, 118]
---

# GraphQL

One endpoint, many operations. The authz and injection surface hides in resolvers, so map the schema first, then treat every argument like a REST param.

## Attack surface
`/graphql`, `/api/graphql`, `/v1/graphql`, `/query`, `/graphiql`, `/playground`, `/_/graphql`. Operations: queries, mutations (state change), subscriptions. Args: ids, filters, `first/last/after` pagination, nested selections.

## Recon
- **Introspection:** POST `{"query":"{__schema{types{name fields{name}}}}"}` — if it returns the schema, you have the full map (types, queries, mutations, args). Also try GET `?query={__schema...}`. If disabled, use field-suggestion errors ("Did you mean…") to brute the schema, or grab it from JS bundles.
- Enumerate mutations especially — they change state and often skip authz.

## Validate (PoC — the proof)
- **Introspection enabled** = confirmed info-exposure (medium): the `__schema` response is the proof. Nuclei synth already fires this.
- **BOLA via node/id args:** call a query with another user's object id (`user(id:"2")`, `node(id:"…")`); a 200 with another subject's fields = broken object authz.
- **Auth gaps:** run a privileged query/mutation **unauthenticated** or with a low-priv token; success = missing field-level authz.
- **Injection:** GraphQL args feed SQL/NoSQL resolvers — apply the sqli/nosql playbook to string args (`filter`, `search`, `orderBy`).
- **Batching / alias abuse (DoS + auth-brute):** send an array of ops or many aliases (`a:login(…) b:login(…)`) to bypass rate limits (credential-stuffing) or amplify cost. Deeply nested queries = resource exhaustion.

## Safe-confirm
Introspection response, one cross-identity node read, or one unauthenticated privileged query. Don't mass-enumerate or run destructive mutations.

## Tools
`graphw00f` (engine fingerprint), Python `requests` for introspection + alias batching, the sqli/nosql skills for arg injection, `clairvoyance` for schema brute when introspection is off.
