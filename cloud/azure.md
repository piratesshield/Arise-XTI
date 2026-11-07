# Azure Cloud Methodology Notes (ARISE cloud modules)

Companion to `aws.md` / `gcp.md` / `kubernetes.md`. Distilled from *Pentesting
Azure Applications* + DEF CON "Hacking the Cloud" (see workspace memory:
`cloud-security-domain`). Governs how ARISE grades Azure exposure and chains it
into cloud takeover (C1–C7 cloud-depth build).

## Core principle (shared with aws/gcp notes)
Grade by **confirmed exposure**, never by existence. Azure adds a **control-plane
identity** dimension AWS/GCP share but Azure makes explicit: management APIs
replace network access, so recon starts at DNS/identity, not ports.

## Two control planes
- **ASM** (classic, certificate-based) — `.publishsettings` management cert = full
  subscription. Treat any leaked `.publishsettings` / `.cspkg` as CRITICAL initial
  access.
- **ARM** (modern, AAD RBAC) — service principals / managed identities. SPs are
  **non-interactive and frequently exempt from MFA** → flag SP-only auth as a gap.

## Storage (C2) — Azure Blob/Table/Queue/File
- Container ACL ladder maps onto the shared `exposure_state` ladder:
  `private → blob-anon (referenced/exists) → container-anon (anon_accessible) →
  sensitive object confirmed (sensitive_confirmed)`.
- SAS tokens: grade by **permission breadth** (`sp=` r/w/d/l/a/c/u) and TTL (`se=`).
  A live token with `w/d/a/c/u` is data-tamper/exfil = CRITICAL (see
  `cloud_storage_enum._signed_url_scope`). Read-only short-TTL = high.
- Content re-grade: **VHD/VHDX/snapshot = CRITICAL** (disk theft → offline
  SAM/shadow crack → cred reuse against the live VM). `*.pfx/*.pem` keys =
  CRITICAL. Static web assets stay suppressed (aws.md FP rule).

## Credential surface (C3)
Scan crawled/exposed content for: `.publishsettings` ManagementCertificate,
`azureProfile.json` / `accessTokens.json` (ARM token caches), storage account
keys (86–88-char base64 `==`), AAD client secrets, SAS tokens. Detection +
mask + report only — **never authenticate with a found credential**.

## Metadata / SSRF (C4)
Azure IMDS: `http://169.254.169.254/metadata/instance?api-version=…` and the
identity token endpoint `/metadata/identity/oauth2/token` — both require the
`Metadata:true` header, so a naive SSRF that cannot set headers may fail; still
test, and always flag **IMDSv1-style reachable metadata** as the posture gap.

## Control plane → takeover (C6 chains)
- **VM credential reset:** an owner/contributor RBAC (from a leaked key) can reset
  local admin password / SSH key via the VMAccess extension — takeover with **no
  prior VM credential**.
- **Key Vault / Automation RunAs:** vault access cascades (disk-encryption keys,
  stored SP creds); Automation RunAs/Runbooks execute privileged, Hybrid Runbook
  Workers reach on-prem.
- **Golden SAML:** ADFS token-signing cert → forge SAML → impersonate any user →
  bypass MFA. **AAD Connect** sync account is tenant-wide leverage.
- **Cloud→on-prem pivot:** VPN gateway / Service Bus relay / Logic Apps / Hybrid
  Runbook Worker ("circle of access").

## Networks
NSG `0.0.0.0/0` rules, Azure-SQL "allow all Azure services", App Gateway WAF
mis-scope. Internet-reachable RDP/SSH/WinRM = takeover entry (port-truth layer).

## Passive attribution (C1)
Azure/O365 footprint from DNS: `*.mail.protection.outlook.com` MX, `MS=` TXT,
`*.azurewebsites`/`windows-azure` references, SPF `spf.protection.outlook.com`.
ADFS/STS host discovery seeds the Golden-SAML chain.

## Posture guardrails to check absent (C5)
IMDSv2 enforcement, Storage anon-access disabled, Key Vault access policies
least-priv, Security Center / diagnostic logging present, SP-with-MFA. Absence =
finding, graded with the GuardDuty-style category vocabulary.
