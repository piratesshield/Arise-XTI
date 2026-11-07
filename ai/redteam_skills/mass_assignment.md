---
name: mass_assignment
description: Mass assignment / auto-binding — privilege & field tampering via extra params
lanes: [mass-assignment, api-blackbox, version-swap]
cwe: [915, 639, 863]
capec: [1, 77]
---

# Mass Assignment

The server binds request fields straight to an object/model, so you set attributes you were never meant to control (`isAdmin`, `role`, `balance`, `verified`).

## Attack surface
Create/update endpoints (POST/PUT/PATCH) that accept JSON/form bodies and map them to a model: user profile update, registration, settings, order/cart, subscription, org membership. Frameworks prone to it: Rails, Django (ModelForm), Laravel, Spring, Sequelize/Mongoose, ActiveRecord.

## Recon
- Get the object's full shape first: read it via a GET (or a create response) to learn the field names — `role`, `is_admin`, `status`, `owner_id`, `tenant_id`, `price`, `credit`, `email_verified`, `permissions`.
- Diff the fields the UI sends vs the fields the object actually has (from GET/schema/JS) — the delta is the mass-assignment candidate set.

## Validate (PoC — the proof)
- Re-send a legitimate update with **extra fields** you shouldn't control: `{"role":"admin"}`, `{"isAdmin":true}`, `{"owner_id":"<other>"}`, `{"balance":999999}`, `{"email_verified":true}`, `{"tenant_id":"<other>"}`.
- **Proof = the privileged field actually changed:** re-read the object (or observe behavior) and show the escalated value took effect — not just a 200. E.g. GET now returns `role:admin`, or an admin-only action now succeeds.
- Try nested/aliased forms: `user[role]`, `role[]`, JSON nesting, snake vs camel, GraphQL input objects.
- Combine with **BOLA**: set `owner_id`/`tenant_id` to move an object cross-account.

## Safe-confirm
Escalate only your **own** test account by one field and show it applied; then note the impact. Don't grant real admin broadly or alter other users.

## Tools
`arjun` to discover hidden bindable params, Python to diff object shape vs sent fields and to spray extra-field sets, the idor skill for the cross-account variant.
