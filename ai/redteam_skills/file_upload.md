---
name: file_upload
description: Insecure file upload — type/extension bypass, path control, content sinks
lanes: [file-upload, upload]
cwe: [434, 22, 646]
capec: [17, 1, 650]
---

# Insecure File Upload

An upload becomes critical when the file is (a) executable in web root, (b) written to an attacker-chosen path, or (c) parsed unsafely (XXE/SSRF/image libs).

## Attack surface
Avatar/profile pics, document/attachment upload, import (CSV/XML/ZIP), logo/theme upload, resume, ticket attachments, bulk import. Note: multipart field name, allowed types (client vs server), where the file lands, and whether it's re-served.

## Validate (PoC — the proof)
- **Executable-in-webroot:** upload a benign server-side script (e.g. a PHP/JSP that echoes a unique token) with a bypass, then fetch it — if the token renders (executed), that's confirmed RCE-via-upload. Prove with a harmless marker, not a shell.
- **Extension/type bypasses:** double ext `x.php.jpg`, null `x.php%00.jpg`, case `x.PhP`, trailing dot/space `x.php.`/`x.php `, alt exts (`.phtml`,`.php5`,`.phar`,`.jsp`,`.jspx`,`.asp`,`.aspx`,`.svg`,`.html`), `Content-Type` spoof, magic-byte prefix (`GIF89a;`), polyglot.
- **Path traversal in filename:** `../../uploads/x` or absolute path → write outside intended dir (Zip-Slip for archives).
- **Content-sink bugs (no exec needed):** SVG/XML → **XXE/stored-XSS** (SVG with `<script>`), image lib → **SSRF/RCE** (ImageMagick/Ghostscript), CSV → **formula injection**, HTML → **stored XSS**.
- **Overwrite:** upload to a fixed name that clobbers config/other users' files.

## Safe-confirm
A rendered unique marker (exec), an off-path write, or a fetched stored-XSS/SVG-XXE proof. Don't drop a real webshell or overwrite live files.

## Tools
Python `requests` multipart for the bypass matrix, `curl` to fetch and confirm execution, the xxe/xss skills for content-sink cases.
