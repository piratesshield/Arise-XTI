---
name: xxe
description: XML External Entity — file read, SSRF-via-XML, OOB, blind exfil
lanes: [xxe]
cwe: [611, 776, 827]
capec: [221, 231]
---

# XXE

An XML parser resolves external entities you define. Reads files, reaches internal hosts (SSRF), or exfiltrates blind via OOB.

## Attack surface
Anywhere XML is parsed: `Content-Type: application/xml`/`text/xml`, SOAP endpoints, SAML responses, RSS/Atom, SVG upload, DOCX/XLSX/ODF (zip-of-XML), `.xml` config import, XML-RPC. Also: endpoints that *accept JSON but also XML* if you flip the `Content-Type`.

## Recon
- Find XML sinks; try switching a JSON request to `Content-Type: application/xml` with an equivalent XML body — many parsers accept both.
- Note whether responses reflect parsed values (in-band) or not (→ blind/OOB).

## Validate (PoC — the proof)
- **In-band file read:** define `<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>` and reference `&x;` in a reflected field → `root:.*:0:0:` in the response = confirmed.
- **SSRF via XML:** `SYSTEM "http://169.254.169.254/…"` or an internal host → the fetch proves server-side reach.
- **Blind / OOB (no reflection):** external DTD on your interactsh host that triggers a callback (parameter entities); a DNS/HTTP hit = confirmed blind XXE. This is the common modern case (most parsers block in-band but leak OOB).
- **Billion-laughs / DoS:** note the potential, do NOT actually exhaust the target.

## Safe-confirm
A signature-file read, an OOB callback, or an internal-host reach proves it. Don't exfiltrate secrets or run DoS payloads.

## Tools
Python `requests` to post crafted XML + `interactsh-client` for the OOB DTD, `curl` for `Content-Type` flips, an SVG/DOCX builder for upload-based XXE.
