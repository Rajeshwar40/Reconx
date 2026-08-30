# ReconX — Subdomain Intelligence Platform

> Production-grade subdomain enumeration & takeover detection for bug bounty hunters  
> **Powered by Rajeshwar Singh**

---

## Features

- **Passive enumeration** via subfinder, assetfinder, amass (parallel)
- **Active bruteforce** via shuffledns with auto-generated resolvers
- **DNS resolution** via dnsx
- **HTTP probing** via httpx (status, title, tech, RTT)
- **Takeover detection** via nuclei with **double-verification** (zero false positives)
- **Real-time logs** via SSE stream
- **Professional dashboard** (Next.js + terminal aesthetic)
- **CLI mode** for headless operation
- macOS / Apple Silicon compatible

---

## Quick Start (local machine)

Requires Node.js 20+. Works on macOS and Linux (Ubuntu/Debian/RHEL/Fedora/Alpine/Arch) — the installer below detects your OS/distro/architecture and installs the right recon tool chain automatically.

### 1. Clone and install the recon tool chain

```bash
git clone <this-repo-url>
cd DNS_project
./scripts/install-tools.sh
```

This installs Go (if missing) and then `subfinder`, `assetfinder`, `amass`, `dnsx`, `httpx`, `nuclei`, and `shuffledns` via the right package manager for your machine, skipping anything already present. Safe to re-run.

If you use `subfinder` with API-keyed sources (Shodan, VirusTotal, etc.), put your keys in `~/.config/subfinder/provider-config.yaml` — the backend explicitly points subfinder at that file (see [enumeration.js](backend/services/enumeration.js)) instead of relying on subfinder's OS-dependent default, so this is the one place to configure.

### 2. Launch (macOS/Linux, no Docker)

```bash
./start.sh
```

This installs Node dependencies on first run, starts the backend on port **2000** and frontend on port **4000**, and opens the dashboard.

Optional environment variables (copy `backend/.env.example` → `backend/.env`, `frontend/.env.example` → `frontend/.env`):

| Var | Where | Purpose |
|---|---|---|
| `API_KEY` | backend | Requires `x-api-key` on `/api/scan/*` when set. Leave blank for local dev. |
| `CORS_ORIGIN` | backend | Restrict CORS in production; defaults to `*`. |
| `NEXT_PUBLIC_API_URL` | frontend | Full backend URL, e.g. `https://recon.example.com/api`. Leave blank for local (relative `/api`). |
| `NEXT_PUBLIC_API_KEY` | frontend | Must match backend `API_KEY` if auth is enabled. |

### 3. CLI mode

```zsh
# Basic scan
./scanner -d example.com

# With active amass enumeration
./scanner -d example.com --active

# Open web UI after scan completes
./scanner -d example.com --web
```

---

## Docker / Cloud Deployment

For deploying to a VM or container platform rather than running locally:

```bash
API_KEY=your-shared-secret \
CORS_ORIGIN=https://your-frontend-domain \
NEXT_PUBLIC_API_URL=https://your-backend-domain/api \
NEXT_PUBLIC_API_KEY=your-shared-secret \
docker compose up --build -d
```

- `backend/Dockerfile` — multi-stage build that runs `scripts/install-tools.sh` in a builder stage, then copies just the compiled tool binaries into a slim runtime image.
- `frontend/Dockerfile` — standard multi-stage Next.js build; `NEXT_PUBLIC_*` vars are baked in at build time via `docker-compose.yml`'s `args`.
- `docker-compose.yml` — wires both services together with a persistent volume (`recon-data`) for scan output, since results are written to disk.

**Before exposing this on a public IP:** set `API_KEY` — without it, anyone who reaches `/api/scan` can trigger real scans against arbitrary domains using your server's IP and compute. Also put a reverse proxy (Nginx/Caddy/your platform's LB) in front with **buffering disabled** on `/api/scan/:id/events`, since it's a long-lived SSE stream that gets cut if the proxy buffers it.

---

## Architecture

```
DNS_project
 ├── scanner                    # CLI entry point
 ├── start.sh                   # Local (non-Docker) launcher
 ├── docker-compose.yml
 ├── scripts/
 │    └── install-tools.sh      # OS-detecting recon tool chain installer
 ├── backend/
 │    ├── Dockerfile
 │    ├── index.js              # Express server (port 2000)
 │    ├── middleware/
 │    │    └── auth.js          # API key gate for /api/scan/*
 │    ├── routes/
 │    │    └── scan.js          # API routes + SSE
 │    ├── services/
 │    │    ├── enumeration.js   # Full recon pipeline
 │    │    └── scanManager.js   # Scan state + SSE clients
 │    └── utils/
 │         ├── validator.js     # Domain sanitization
 │         ├── toolPaths.js     # Dynamic tool detection
 │         └── logger.js        # File + SSE logging
 ├── frontend/
 │    ├── Dockerfile
 │    └── src/app/
 │         ├── page.js          # Dashboard UI
 │         └── globals.css
 └── ~/recon/                   # Output directory (outside the repo)
      └── <domain>/
           ├── all_subdomains.txt
           ├── live.txt
           ├── final.json
           ├── takeover.txt
           └── logs.txt
```

---

## API Endpoints

`/api/scan/*` routes require the `x-api-key` header (or `?apiKey=` query param for the SSE endpoint) when `API_KEY` is set in the backend environment. Unset by default for local dev.

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/scan` | Start scan `{ domain }` |
| GET | `/api/scan/:id/events` | SSE log stream |
| GET | `/api/scan/:id/status` | Scan status |
| GET | `/api/scan/:id/results` | Full JSON results |
| GET | `/api/scan/:id/file/:name` | Download output file |
| GET | `/api/scans` | List all scans |
| GET | `/api/tools/check` | Tool availability |
| GET | `/api/health` | Health check |

---

## Output Files

| File | Description |
|------|-------------|
| `all_subdomains.txt` | All discovered subdomains (deduplicated) |
| `live.txt` | DNS-resolved live subdomains |
| `final.json` | Structured HTTP probe results |
| `takeover.txt` | Raw nuclei takeover findings |
| `logs.txt` | Full timestamped scan log |

---

## Takeover Detection

Strict double-verification mode:
1. **Pass 1**: nuclei scans all live subdomains with takeover templates
2. **Pass 2**: Re-scans only candidates from pass 1
3. **Only reports** hosts that appear as vulnerable in **both** passes

This eliminates false positives from transient network conditions.

---

## Example Scan Output

```
~/recon/example.com/final.json
[
  {
    "subdomain": "dev.example.com",
    "url": "http://dev.example.com",
    "ip": "1.2.3.4",
    "status": 200,
    "title": "Dev Portal",
    "tech": "nginx, React",
    "responseTime": "123ms",
    "takeover": false
  },
  ...
]
```

---

## Security Notes

- All domain inputs are regex-validated and shell-injection sanitized
- No external data is sent anywhere
- Tool paths resolved dynamically via `which` (no hardcoded paths)
- Rate limiting applied on nuclei to avoid bans

---

*ReconX v1.0 — Bug Bounty Edition — Zero False Positives*  
*Powered by Rajeshwar Singh*
