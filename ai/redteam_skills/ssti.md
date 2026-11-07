---
name: ssti
description: Server-Side Template Injection — engine fingerprint, arithmetic proof, safe confirm
lanes: [ssti-lfi, ssti]
cwe: [1336, 94, 95]
capec: [242, 253]
---

# SSTI

User input is rendered as a template. Confirm with a **arithmetic marker** that only a template engine would evaluate — never with `os-shell`.

## Attack surface
Anything reflected that might hit a template: name/email in emails & PDFs, error pages, search, `subject`/`greeting` fields, CMS blocks, notification templates, filename rendering, admin-configurable messages, `Accept-Language`.

## Recon / fingerprint
- Inject `${7*7}` `{{7*7}}` `#{7*7}` `<%= 7*7 %>` `${{7*7}}` `#{7*7}` — if any renders **49**, a template engine evaluated it.
- Fingerprint the engine from which syntax fires + follow-ups: Jinja2/Twig `{{7*7}}`, Freemarker `${7*7}`, Velocity `#set`, ERB `<%= %>`, Handlebars, Thymeleaf `__${...}__`. The `{{7*'7'}}` → `7777777` (Jinja) vs error (Twig) disambiguates.

## Validate (PoC — the proof)
- **Proof = arithmetic evaluation** (`{{7*7}}`→49) plus engine confirmation via a second distinct expression. That alone is a confirmed SSTI; the RCE potential follows from the engine.
- Escalate *only in a lab*: Jinja `{{config}}` / `{{self.__init__.__globals__}}`, Freemarker `freemarker.template.utility.Execute`. In production, STOP at arithmetic proof and report the engine + the RCE potential.

## Safe-confirm
`{{7*7}}`→49 with a second confirming expression. Do NOT run `--os-shell`, read files, or execute commands. Note engine + why it's RCE-capable.

## Tools
`SSTImap`/`tplmap` (detection, keep to detect mode), dalfox catches some, Python for the marker-corpus sweep across params. nuclei `-dast` where a template exists.
