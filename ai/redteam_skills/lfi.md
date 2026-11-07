---
name: lfi
description: Path traversal / LFI / RFI — file read, log poisoning, wrapper abuse
lanes: [ssti-lfi, lfi]
cwe: [22, 23, 35, 98]
capec: [126, 76, 139]
---

# Path Traversal / LFI

A file path is built from user input. Confirm by reading a file whose contents you can recognize.

## Attack surface
Params that name a file/template/page: `file`, `path`, `page`, `template`, `include`, `doc`, `download`, `attachment`, `img`, `lang`, `theme`, `view`. Also: archive extraction (Zip-Slip), image/PDF processors, `Content-Disposition` download endpoints, i18n loaders.

## Recon
- Map which params feed a filesystem read (download/render/include behavior).
- Fingerprint OS (headers, error messages) → pick `/etc/passwd` vs `C:\windows\win.ini`.

## Validate (PoC — the proof)
- **Read a signature file:** `../../../../etc/passwd` → body contains `root:.*:0:0:`; Windows `..\..\windows\win.ini` → `[extensions]`/`[fonts]`. That regex match **is** the proof.
- **Encodings/bypasses:** `....//` (filter-collapse), URL-encode `%2e%2e%2f`, double-encode `%252e`, UTF-8 overlong, null-byte on old stacks `%00`, absolute path, nested `....\/`.
- **PHP wrappers (read source without exec):** `php://filter/convert.base64-encode/resource=index.php` → base64 blob you decode = source disclosure.
- **Depth sweep:** vary `../` count 1–12; the depth that returns the signature confirms the traversal root.
- **Log poisoning / RFI → RCE** is an escalation: note the *potential*, don't drop a shell.

## Safe-confirm
One signature-file read (passwd/win.ini) or a base64 source blob confirms it. Do NOT read secrets/keys, poison logs, or include remote code. Report the traversal + the depth that worked.

## Tools
nuclei `-dast` lfi-traversal template, `ffuf` for depth/encoding sweep (`-w traversal.txt`), Python for encoding-corpus + signature matching. `curl` to fetch and grep.
