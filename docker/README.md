# ARISE EASM — Docker Deployment & Setup Guide

"Summon Every Hidden Exposure." — External Attack Surface Monitoring dashboard + pipeline.

---

## 1. Quick start

```bash
docker pull dagaltikick/arise:latest

docker run -d --name arise \
  -p 3333:3333 \
  --cap-add=NET_RAW --cap-add=NET_ADMIN \
  -v arise-data:/app/scans \
  dagaltikick/arise:latest
```

Open **http://localhost:3333**

| | |
|---|---|
| **Default username** | `admin` |
| **Default password** | `admin` |
| **Port** | `3333` |

> ⚠️ **Change the password immediately** in *Settings → Account* after first login.
> `admin/admin` is a convenience default for local use only — never expose it to the internet.

`--cap-add=NET_RAW --cap-add=NET_ADMIN` are required for SYN port scanning (naabu/nmap). Without them the app still runs; port scans fall back or are skipped.

---

## 2. Change the default credentials

Two ways:

- **In the UI:** log in → *Settings → Account → Change password*.
- **At launch (recommended for servers):**
  ```bash
  -e ARISE_ADMIN_USER=youradmin -e ARISE_ADMIN_PASSWORD='a-strong-passphrase'
  ```
  These only take effect on **first run** (when no user exists). To reset later, remove the users file in the data volume and restart, or change it in the UI.

---

## 3. API keys — what unlocks what

ARISE runs a full scan with **zero keys**, but keys turn on the AI brain and the external-intelligence modules.

### 3a. Make it an AI-enabled EASM (pick ONE provider)

The AI Analyst, autonomous confirmation, finding triage, and Slack summaries need one LLM provider.

| Env var | Provider | Get a key at | Notes |
|---|---|---|---|
| `GEMINI_API_KEY` (or `GOOGLE_API_KEY`) | Google Gemini | https://aistudio.google.com/apikey | **Default provider** |
| `ANTHROPIC_API_KEY` | Anthropic Claude | https://console.anthropic.com/settings/keys | |
| `OPENAI_API_KEY` | OpenAI | https://platform.openai.com/api-keys | |
| `HF_API_TOKEN` | Hugging Face router | https://huggingface.co/settings/tokens | |

Select the provider + model:

```bash
-e ARISE_AI_PROVIDER=gemini        # claude | gemini | openai | huggingface
-e ARISE_AI_MODEL=gemini-1.5-flash # optional; provider default used if unset
```

Full AI example:

```bash
docker run -d --name arise -p 3333:3333 \
  --cap-add=NET_RAW --cap-add=NET_ADMIN \
  -v arise-data:/app/scans \
  -e ARISE_AI_PROVIDER=gemini \
  -e GEMINI_API_KEY=YOUR_KEY \
  dagaltikick/arise:latest
```

### 3b. External-intelligence connectors (all optional)

Each key enriches a specific module; missing ones just degrade that module.

| Env var | Service | Get a key at | Enables |
|---|---|---|---|
| `SHODAN_API_KEY` | Shodan | https://account.shodan.io | External host view (Module 22) |
| `CENSYS_API_ID` + `CENSYS_API_SECRET` | Censys | https://search.censys.io/account/api | Internet Intelligence (Module 23) |
| `GREYNOISE_API_KEY` | GreyNoise | https://viz.greynoise.io/account | Noise/threat enrichment |
| `IPINFO_TOKEN` | ipinfo.io | https://ipinfo.io/account/token | Geo map for the asset globe |
| `GITHUB_TOKEN` | GitHub PAT | https://github.com/settings/tokens | Code / secret recon |
| `VIRUSTOTAL_API_KEY` | VirusTotal | https://www.virustotal.com/gui/my-apikey | Reputation checks |
| `HIBP_API_KEY` | Have I Been Pwned | https://haveibeenpwned.com/API/Key | Breach/OSINT (Module 18) |
| `INTELX_API_KEY` | Intelligence X | https://intelx.io/account?tab=developer | OSINT |
| `LEAKCHECK_API_KEY` | LeakCheck | https://leakcheck.io | Credential-leak OSINT |
| `GOOGLE_SAFEBROWSING_KEY` | Google Safe Browsing | https://console.cloud.google.com | Malicious-URL checks |
| `TELEGRAM_BOT_TOKEN` | Telegram | https://core.telegram.org/bots | OSINT (phase 3) |
| `YOUTUBE_API_KEY` | YouTube Data API | https://console.cloud.google.com | OSINT (phase 3) |
| `SLACK_WEBHOOK_URL` | Slack Incoming Webhook | https://api.slack.com/messaging/webhooks | Auto-posts scan summaries |

---

## 4. Two ways to set keys

**A. In the dashboard (recommended, encrypted at rest).**
*Settings → API Keys / Integrations* → paste keys → Save. They're encrypted into `secrets.enc.json` with the vault master key and take effect on the **next scan** (no restart). To keep them across container re-creates, persist the master key + vault (see §5).

**B. Environment variables at `docker run`.** Good for servers / reproducible deploys. Use an env file to avoid keys in your shell history:

```bash
# arise.env  (chmod 600; NEVER commit this)
ARISE_AI_PROVIDER=gemini
GEMINI_API_KEY=...
SHODAN_API_KEY=...
CENSYS_API_ID=...
CENSYS_API_SECRET=...
```
```bash
docker run -d --name arise -p 3333:3333 \
  --cap-add=NET_RAW --cap-add=NET_ADMIN \
  -v arise-data:/app/scans \
  --env-file arise.env \
  dagaltikick/arise:latest
```

---

## 5. Data persistence (scans + vault + login)

Scan results, the encrypted secret vault, the vault **master key**, and the users file live under the app root. To survive container re-creation, persist them:

```bash
-v arise-data:/app/scans                       # scan outputs (can be large)
-e ARISE_MASTER_KEY='<base64 fernet key>'       # keep vault keys decryptable across restarts
```

If you don't set `ARISE_MASTER_KEY`, a new one is generated per container and previously vault-saved API keys can't be decrypted after a re-create (set them again, or use env vars from §4B).

---

## 6. Other run modes

The image entrypoint dispatches:

```bash
# Dashboard (default)
docker run ... dagaltikick/arise:latest

# Run the full pipeline against a target (headless)
docker run --rm --cap-add=NET_RAW -v arise-data:/app/scans \
  dagaltikick/arise:latest pipeline example.com

# CLI
docker run --rm dagaltikick/arise:latest cli --help

# Shell inside the container
docker run --rm -it --entrypoint bash dagaltikick/arise:latest
```

---

## 7. Operations

```bash
docker logs -f arise          # follow logs (first-run admin bootstrap prints here)
docker stop arise             # stop
docker start arise            # resume
docker rm -f arise            # remove (data survives in the arise-data volume)
```

---

## 8. Security notes (read before exposing beyond localhost)

- The dashboard runs Flask's **development server with debug mode on** — fine for local use, **not** for a public/production deployment. Front it with a reverse proxy + real WSGI server, or keep it bound to localhost / a private network.
- **`admin/admin` and any baked key are for local convenience only** — change them.
- Treat scan data as sensitive; the `arise-data` volume can contain findings, tokens, and PII discovered during scans.
- ARISE is an **authorized-testing** tool — only scan assets you own or are permitted to test.

---

## 9. Build it yourself

```bash
git clone <your repo> && cd <repo>
docker build -f docker/Dockerfile -t arise:local .
docker/build-and-run.sh          # builds + runs on 3333 with admin/admin
```
