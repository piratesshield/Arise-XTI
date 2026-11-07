![ARISE XTI — AI-Powered External Threat Intelligence](screenshots/banner.webp)

# ARISE — External Attack Surface Monitoring

**A**utonomous **R**econ, **I**ntelligence, **S**ecurity & **E**xposure platform.
ARISE turns a domain into a continuously-monitored external attack surface: 28-module pipeline, exploitability-ranked issues, CAPEC/MITRE attack chains, and an autonomous AI pentester — all behind a single Flask dashboard.

---

## 📸 Dashboards

| | |
|---|---|
| **Overview** — risk score, attack chains, asset ribbon | **Issues** — KEV/EPSS-ranked, SLA-tracked |
| ![](screenshots/01-overview.jpg) | ![](screenshots/02-issues.jpg) |
| **Attack Surface** — adversary-perspective inventory | **Attack Paths** — CAPEC chains to crown jewels |
| ![](screenshots/03-attack-surface.jpg) | ![](screenshots/04-attack-paths.jpg) |
| **CVEs** — KEV/EPSS-blended | **Assets** — all hosts, IPs, WAF/CDN posture |
| ![](screenshots/05-cves.jpg) | ![](screenshots/06-assets.jpg) |
| **URL Inventory** — classified endpoints | **API Security** — BOLA/BFLA with evidence ladder |
| ![](screenshots/07-url-inventory.jpg) | ![](screenshots/08-api-security.jpg) |
| **Cloud** — AWS/GCP/Azure + takeover chain | **SSL / TLS** — SSL-Labs-style per-host grades |
| ![](screenshots/09-cloud.jpg) | ![](screenshots/10-ssl-tls.jpg) |
| **SBOM** — components × versions × hosts | **OSINT** — brand, breach, code, impersonation |
| ![](screenshots/11-sbom.jpg) | ![](screenshots/12-osint.jpg) |
| **Shodan** — external-view correlation | **Red Team** — AriseAI autonomous pentester |
| ![](screenshots/13-shodan.jpg) | ![](screenshots/14-red-team.jpg) |
| **Changes** — asset / port / finding diff | |
| ![](screenshots/15-changes.jpg) | |

---

## ⚡ Quick Start

```bash
./setup.sh                                          # one-shot installer (macOS/Linux)
./easm-pipeline.sh piratesshield.com                # run a scan
python3 dashboard.py                                # open http://localhost:5059
```

**Default login:** `admin` / `admin` — change `ARISE_ADMIN_PASSWORD` before exposing the dashboard.


---

## 🔑 API Keys & Secrets

All keys are read from environment variables (export in your shell, `.env`, or `~/.zshrc`).
They can also be pasted into **Settings → API Keys** in the dashboard — the vault is encrypted at rest with `ARISE_SECRET`.

### Mandatory

| Key | Purpose |
|---|---|
| `ARISE_ADMIN_USER` | Dashboard login username. **Default: `admin`** |
| `ARISE_ADMIN_PASSWORD` | Dashboard login password. **Default: `admin`** (change before any public deployment). |
| `ARISE_SECRET` | Fernet key that encrypts the on-disk secrets vault (`secrets.enc.json`). |

### Optional — AI Analyst / Red Team

At least **one** provider key is required for the AI Analyst and Red Team tabs to run; otherwise they show a "key required" banner.

| Key | Enables |
|---|---|
| `ANTHROPIC_API_KEY` | Claude (recommended for AriseAI pentester). |
| `OPENAI_API_KEY` | GPT models. |
| `GEMINI_API_KEY` *(or `GOOGLE_API_KEY`)* | Google Gemini (default provider). |

### Optional — External Intel

Each key unlocks the matching dashboard without blocking the rest of the pipeline.

| Key | Enables |
|---|---|
| `SHODAN_API_KEY` | **Shodan** tab — external-view enrichment, coverage-gap ports, geo exposure map. |
| `CENSYS_API_ID` + `CENSYS_API_SECRET` | **Internet Intel** — TLS/services from Censys. |
| `GREYNOISE_API_KEY` | Background-noise scoring in Internet Intel. |
| `VIRUSTOTAL_API_KEY` | Passive DNS / subdomain enrichment. |
| `INTELX_API` | IntelX breach & paste search in OSINT. |
| `GITHUB_TOKEN` | OSINT — GitHub code / secret hunting (unauthenticated is rate-limited). |

### Optional — Notifications & Infra

| Key | Enables |
|---|---|
| `SLACK_WEBHOOK` | One-click scan-summary / finding export to Slack. |
| `ARISE_DASHBOARD_PORT` | Override default port (`5059`). |

### Example `.env`

```bash
# --- mandatory ---
ARISE_ADMIN_USER=admin          # default
ARISE_ADMIN_PASSWORD=admin      # default — CHANGE before exposing the dashboard
ARISE_SECRET=$(python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")

# --- AI (pick one) ---
ANTHROPIC_API_KEY=sk-ant-...
# OPENAI_API_KEY=sk-...
# GEMINI_API_KEY=AIza...

# --- intel ---
SHODAN_API_KEY=...
CENSYS_API_ID=...
CENSYS_API_SECRET=...
GREYNOISE_API_KEY=...

# --- notify ---
SLACK_WEBHOOK=https://hooks.slack.com/services/...
```

---

## 🧠 What runs under the hood

28-module pipeline — *asset discovery → DNS → HTTP probe → WAF → service fingerprint → directory discovery → crawling → JS mining → secret scanning → param fuzzing → nuclei → XSS/SQLi/LFI → port scan → **API Security** → **Cloud Exposure** → OSINT → **Shodan** → **Internet Intel** → **Advanced Attacks (offensive_verify)** → **Attack Paths (CAPEC v3.9)** → **AriseAI Analyst***.

Every finding carries an **L0–L6 evidence ladder** (observed → security-differential → reproducible → authz-violation → impact → reproduced) and feeds the **exploitability-first Issues** view with KEV / EPSS / SLA tracking.

---

## 🛠 Tooling

Recon: `subfinder`, `puredns`, `massdns`, `dnsx`, `httpx`, `naabu`, `nmap` · Crawl: `katana`, `gospider`, `gau`, `waybackurls` · Content: `dirsearch`, `ffuf`, `wappalyzer` · JS: `subjs`, `getJS`, `linkfinder`, `secretfinder`, `trufflehog` · Fuzzing: `ffuf`, `arjun`, `paramspider` · CVE: `nuclei` · Cloud: `cloud_nuclei`, `cloud_enum`, `s3-recon` · API: `autoswagger`, `RESTler`, native `apisec.py` · Attack: `offensive_verify.py`, `adaptive_loop.py`, `capec_attack_paths.py`.

---

## 📁 Repo Layout

```
arise.py                 CLI entry
dashboard.py             Flask dashboard (port 5059)
easm-pipeline.sh         Full 28-module pipeline
recon/ discovery/ ports/ tls/ cloud/ api_security/
offensive/ intel/ evidence/ history/ ai/ ai_analyst/
scans/<target>-<ts>/     per-scan outputs (reads by dashboard)
screenshots/             dashboard captures (shown above)
```

---

## 📜 License

Commercial — Piratesshield. Contact for evaluation licenses.
