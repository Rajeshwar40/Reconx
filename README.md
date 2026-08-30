<div align="center">

# 🔍 ReconX v1.0

[![ReconX](https://img.shields.io/badge/ReconX-Bug_Bounty_Edition-3ce095?style=for-the-badge&logo=target&logoColor=white)](https://rajeshwar40.github.io/Reconx/)
[![Author](https://img.shields.io/badge/author-%40Rajeshwar40-5ad0e0?style=for-the-badge&logo=github)](https://github.com/Rajeshwar40)
[![License](https://img.shields.io/badge/License-MIT-ffb454?style=for-the-badge)](LICENSE)
[![Node](https://img.shields.io/badge/Node-20%2B-333333?style=for-the-badge&logo=node.js&logoColor=white)]()
[![Zero False Positives](https://img.shields.io/badge/Takeover_Detection-Zero_False_Positives-34d399?style=for-the-badge)]()
[![Platform](https://img.shields.io/badge/Platform-macOS_%C2%B7_Linux-090c0d?style=for-the-badge)]()

**Production-grade subdomain enumeration & takeover detection for bug bounty hunters.**
Passive + active recon, DNS resolution, HTTP probing, and double-verified takeover checks — one pipeline.

[🚀 **Launch Tool**](https://github.com/Rajeshwar40/Reconx/) · [🌐 **Landing Page**](https://rajeshwar40.github.io/Reconx/) · [🎬 **Watch Demo**](#-demo) · [🐛 **Report a Bug**](https://github.com/Rajeshwar40/Reconx/issues)

</div>

---

## 🎬 Demo

<div align="center">

[![ReconX Demo](https://img.youtube.com/vi/YOUR_VIDEO_ID/maxresdefault.jpg)](https://www.youtube.com/watch?v=YOUR_VIDEO_ID)

**▶ [Watch the full demo on YouTube](https://www.youtube.com/watch?v=YOUR_VIDEO_ID)**
*(placeholder until the video is uploaded — swap `YOUR_VIDEO_ID` in both spots above)*

</div>

---

## Overview

**ReconX** is a full subdomain intelligence pipeline built for bug bounty workflows: it chains passive and active enumeration, DNS resolution, HTTP probing, and a strict double-verification takeover scan into one run, exposed through both a real-time web dashboard and a headless CLI.

| Stage | Tool(s) | What it does |
|---|---|---|
| 🕵️ **Passive enumeration** | `subfinder` · `assetfinder` · `amass` | Pulls subdomains from public sources in parallel, no traffic to the target |
| 🔨 **Active bruteforce** | `shuffledns` | Wordlist bruteforce with auto-generated resolvers (`--active`) |
| 🌐 **DNS resolution** | `dnsx` | Confirms which discovered names actually resolve |
| 📡 **HTTP probing** | `httpx` | Status code, page title, tech stack, response time per host |
| 🎯 **Takeover detection** | `nuclei` (double-verification) | Only reports hosts vulnerable in **both** scan passes |

All scanning runs against real infrastructure you control or are authorized to test — this is a recon *pipeline*, not a hosted scanning service.

---

## ✨ Features

- ⚡ **Full pipeline, one command** — passive → active → resolve → probe → takeover, chained automatically
- 🖥️ **Real-time dashboard** — Next.js UI with terminal aesthetic, streamed over SSE
- ⌨️ **Headless CLI mode** — `./scanner -d target.com` for scripting and CI
- 🔁 **Double-verified takeover detection** — two-pass nuclei scan eliminates transient false positives
- 🧰 **Cross-platform installer** — `install-tools.sh` detects OS/distro/arch and installs the right recon tool chain
- 🔑 **Optional API-key auth** — gate `/api/scan/*` behind `x-api-key` for public deployments
- 🐳 **Docker / cloud ready** — multi-stage builds, `docker-compose.yml` wires backend + frontend + persistent volume
- 🛡️ **Sanitized inputs** — domain inputs regex-validated and shell-injection sanitized, tool paths resolved via `which`

---

## 📁 Output Files

| File | Description |
|------|-------------|
| `all_subdomains.txt` | All discovered subdomains (deduplicated) |
| `live.txt` | DNS-resolved live subdomains |
| `final.json` | Structured HTTP probe results |
| `takeover.txt` | Raw nuclei takeover findings (double-verified) |
| `logs.txt` | Full timestamped scan log |

**Example `final.json` entry:**

```json
{
  "subdomain": "dev.example.com",
  "url": "http://dev.example.com",
  "ip": "1.2.3.4",
  "status": 200,
  "title": "Dev Portal",
  "tech": "nginx, React",
  "responseTime": "123ms",
  "takeover": false
}
```

---

## 🚀 Usage

### Option 1 — Local (no Docker)

```bash
git clone https://github.com/Rajeshwar40/Reconx.git
cd Reconx/
./scripts/install-tools.sh   # installs subfinder, assetfinder, amass, dnsx, httpx, nuclei, shuffledns
./start.sh                   # backend :2000, frontend :4000
```

Copy `backend/.env.example` → `backend/.env` and `frontend/.env.example` → `frontend/.env` to configure `API_KEY`, `CORS_ORIGIN`, and `NEXT_PUBLIC_API_URL` for anything beyond local dev.

### Option 2 — CLI only

```zsh
./scanner -d example.com                 # basic scan
./scanner -d example.com --active        # + active amass enumeration
./scanner -d example.com --web           # open dashboard after scan
```

### Option 3 — Docker / cloud deployment

```bash
API_KEY=your-shared-secret \
CORS_ORIGIN=https://your-frontend-domain \
NEXT_PUBLIC_API_URL=https://your-backend-domain/api \
NEXT_PUBLIC_API_KEY=your-shared-secret \
docker compose up --build -d
```

> **Before exposing this on a public IP:** set `API_KEY` — without it, anyone reaching `/api/scan` can trigger scans against arbitrary domains on your compute. Put a reverse proxy in front with buffering disabled on `/api/scan/:id/events` (long-lived SSE stream).

---

## 🛠 Tech Stack

| Technology | Purpose |
|---|---|
| **Node.js / Express** | Backend API + SSE log streaming (port 2000) |
| **Next.js** | Terminal-styled dashboard frontend (port 4000) |
| **subfinder / assetfinder / amass** | Passive subdomain discovery |
| **shuffledns** | Active DNS bruteforce |
| **dnsx** | Bulk DNS resolution |
| **httpx** | HTTP probing & tech fingerprinting |
| **nuclei** | Takeover template scanning, double-verified |
| **Docker Compose** | Multi-service deployment with persistent scan volume |

---

## 📁 Project Structure

```
Reconx
├── scanner                    # CLI entry point
├── start.sh                   # Local (non-Docker) launcher
├── docker-compose.yml
├── scripts/
│    └── install-tools.sh      # OS-detecting recon tool chain installer
├── backend/
│    ├── index.js              # Express server (port 2000)
│    ├── middleware/auth.js    # API key gate for /api/scan/*
│    ├── routes/scan.js        # API routes + SSE
│    ├── services/             # enumeration.js, scanManager.js
│    └── utils/                # validator.js, toolPaths.js, logger.js
├── frontend/
│    └── src/app/               # page.js, globals.css
└── ~/recon/<domain>/           # Output: subdomains, live hosts, JSON, takeover, logs
```

---

## 👤 Author

**Rajeshwar Singh** · `@Rajeshwar40`
Independent Security Researcher

| | |
|--|--|
| 🐙 GitHub | [@Rajeshwar40](https://github.com/Rajeshwar40) |
| 🔍 Project | [ReconX](https://github.com/Rajeshwar40/Reconx) |
| 📜 Certs | CRTP · CEH · CCNA |
| 🐛 CVEs | 10+ credited |

---

## ⚖️ License

MIT License — free to use, modify, and distribute. Attribution appreciated.

---

<div align="center">

🔍 **ReconX v1.0** · Built by [@Rajeshwar40](https://github.com/Rajeshwar40) · Bug Bounty Edition · Zero False Positives

⭐ **Star this repo if it helped you** ⭐

</div>
