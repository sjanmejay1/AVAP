# AVAP — Automated Vulnerability Assessment Platform

AVAP is a full-stack web app that runs a network vulnerability assessment
from start to finish:

```
Add a target → Nmap scan → parse results → asset & vulnerability inventory
→ deterministic risk score → AI remediation advice (optional, advisory)
→ PDF report → audit trail
```

It is a learning project for security awareness, built only on free and
open-source software.

> **Only scan systems you own or have written permission to test.**
> Port scanning networks you don't control can be illegal where you live.

---

## Contents

1. [What's inside](#1-whats-inside)
2. [Quick start with Docker (recommended)](#2-quick-start-with-docker-recommended)
3. [Running without Docker (for development)](#3-running-without-docker-for-development)
4. [Using the app](#4-using-the-app)
5. [Configuration reference](#5-configuration-reference)
6. [Running the tests](#6-running-the-tests)
7. [Troubleshooting](#7-troubleshooting)
8. [Security notes](#8-security-notes)
9. [Project layout and further docs](#9-project-layout-and-further-docs)
10. [Public deployment (Oracle Cloud)](#10-public-deployment-oracle-cloud)

---

## 1. What's inside

| Part | Tech |
|---|---|
| Backend (`backend/`) | Python 3.12, FastAPI, SQLAlchemy 2, Alembic, PostgreSQL, Pydantic v2, ReportLab |
| Frontend (`frontend/`) | Next.js (App Router), TypeScript, TanStack Query, shadcn/ui + Tailwind, React Hook Form + Zod |
| Scanner | Nmap, with two profiles: **QUICK** and **FULL** (FULL also runs safe NSE scripts) |
| AI (optional) | OpenRouter, **free models only**. Each user enters their own key in the app; there is no server-wide key |
| Storage | Raw scan output in a local folder (default) or an S3 bucket |

The browser talks to the backend only through the REST API at `/api/v1`.
Users sign up with open registration, and each user only ever sees their own
targets, scans and reports.

---

## 2. Quick start with Docker (recommended)

This runs everything (PostgreSQL, backend with Nmap built in, frontend) with
one command. You don't need Python, Node or Nmap installed.

### 2.1 Prerequisites

- [Git](https://git-scm.com/downloads)
- [Docker Desktop](https://www.docker.com/products/docker-desktop/) (Windows/macOS)
  or Docker Engine + the Compose plugin (Linux)
- Python 3 on your machine, only to generate two secret keys in step 2.3.
  Any other way of generating random values works too.

### 2.2 Get the code

```bash
git clone https://github.com/sjanmejay1/VASP.git
cd VASP
```

### 2.3 Create your `.env` file

Copy the template (it sits next to `docker-compose.yml`):

```bash
# macOS / Linux / Git Bash
cp env.docker.example .env
```

```powershell
# Windows PowerShell
Copy-Item env.docker.example .env
```

Open `.env` and fill in the **three required values**:

| Variable | What to put |
|---|---|
| `POSTGRES_PASSWORD` | A strong password, **letters and digits only** (it goes into a database URL, where `@ : / %` break it) |
| `JWT_SECRET_KEY` | At least 64 random characters, used to sign login tokens |
| `APP_ENCRYPTION_KEY` | A Fernet key, used to encrypt users' saved OpenRouter keys |

Generate the two keys like this:

```bash
python -c "import secrets; print(secrets.token_hex(64))"
```

```bash
pip install cryptography   # only if you don't have it already
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

> `.env` is ignored by git. **Never commit it.** If you lose
> `APP_ENCRYPTION_KEY`, saved OpenRouter keys can't be decrypted and users
> have to enter them again. Nothing else is lost.

### 2.4 Start the stack

```bash
docker compose up -d --build
```

The first build takes a few minutes. The backend applies the database
migrations automatically on start-up. Check that everything is healthy:

```bash
docker compose ps
```

### 2.5 Open the app

- App: **http://localhost:3001**
- API health check: http://localhost:8000/health
- API docs (Swagger): http://localhost:8000/docs

Click **Register**, create an account, and continue with
[Using the app](#4-using-the-app).

### 2.6 Everyday commands

```bash
docker compose logs -f backend      # follow backend logs
docker compose stop                 # stop, keep data
docker compose up -d                # start again
docker compose up -d --build        # rebuild after pulling new code
docker compose down                 # remove containers, keep data volumes
docker compose down -v              # remove containers AND all data (irreversible)
```

### 2.7 Optional: safe demo targets

`docker-compose.demo.yml` adds two harmless containers (an nginx web server
and a redis cache) on an isolated internal network that only the backend can
reach. They give you something legal to scan straight away:

```bash
docker compose -f docker-compose.yml -f docker-compose.demo.yml up -d --build
```

Then add the targets `demo-web` and `demo-cache` in the app.

---

## 3. Running without Docker (for development)

Use this when you want hot reload while changing the code. You need two
terminals: one for the backend, one for the frontend.

### 3.1 Prerequisites

| Tool | Version | Notes |
|---|---|---|
| Python | 3.12+ | backend |
| Node.js | 20+ (with npm) | frontend |
| PostgreSQL | 15+ | database |
| Nmap | any recent | **Windows:** install from [nmap.org](https://nmap.org/download.html) and **include Npcap**. **macOS:** `brew install nmap`. **Debian/Ubuntu:** `sudo apt install nmap` |

### 3.2 Database

Create a database and user (in `psql` or pgAdmin). Use your own password:

```sql
CREATE USER avap_user WITH PASSWORD 'choose-a-password';
CREATE DATABASE avap OWNER avap_user;
```

### 3.3 Backend

```bash
cd backend
python -m venv .venv

# Windows PowerShell
.venv\Scripts\Activate.ps1
# macOS / Linux
source .venv/bin/activate

pip install -e ".[dev]"
cp .env.example .env          # PowerShell: Copy-Item .env.example .env
```

Edit `backend/.env`:

- `POSTGRES_PASSWORD`: the password from step 3.2
- `JWT_SECRET_KEY` and `APP_ENCRYPTION_KEY`: generate them as in
  [step 2.3](#23-create-your-env-file)
- `NMAP_EXECUTABLE`: the full path to Nmap. On Windows this is usually
  `C:\Program Files (x86)\Nmap\nmap.exe`. On Linux it's usually
  `/usr/bin/nmap` (run `which nmap` to check).

Create the tables, then start the API:

```bash
alembic upgrade head
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Check it: http://localhost:8000/health should return `"status": "healthy"`.

### 3.4 Frontend

In a second terminal:

```bash
cd frontend
npm install
cp .env.example .env.local    # PowerShell: Copy-Item .env.example .env.local
npm run dev
```

`.env.local` only needs `NEXT_PUBLIC_API_BASE_URL=http://localhost:8000`. This
value ends up in the browser bundle, so never put a secret in it.

Open **http://localhost:3000**.

---

## 4. Using the app

1. **Register** an account, then sign in.
2. **(Optional) Profile → OpenRouter key:** paste a free key from
   [openrouter.ai](https://openrouter.ai/keys) to enable AI remediation
   advice. Without a key, scanning, risk scoring and reports all still work.
3. **Targets → Add target:** enter an IPv4 address (`192.168.1.10`), a CIDR
   range (`192.168.1.0/24`, no wider than `/16` by default) or a hostname
   (`scanme.nmap.org`). Loopback, multicast and `localhost` targets are
   refused.
4. **Start a scan** from the target, choosing **QUICK** (top 1,000 ports,
   light version detection) or **FULL** (all 65,535 ports, deeper version
   detection and safe NSE scripts; this can take a long time on big ranges).
5. Open the scan to follow it from *pending* to *running* to *completed*.
   When it finishes, the risk score is calculated automatically, and AI
   analysis runs automatically if you saved an OpenRouter key. The scan page
   then has these tabs:
   - **Overview, Hosts, Ports, Findings:** what Nmap discovered, with risk levels
   - **AI:** advisory findings and remediation. *Run AI analysis* re-runs it
   - **Raw:** the Nmap output
6. Use **Download PDF** for the report. Use the **⋯** menu to regenerate a
   fresh report, download the Nmap XML or delete the scan.

> `scanme.nmap.org` is a host that the Nmap project explicitly lets you scan
> for testing. Please don't scan it heavily.

---

## 5. Configuration reference

The authoritative list is `backend/app/core/config.py`. For Docker, set
values in the root `.env`. For local development, set them in `backend/.env`.

| Variable | Default | Purpose |
|---|---|---|
| `POSTGRES_PASSWORD` | — (**required**) | Database password |
| `JWT_SECRET_KEY` | — (**required**, 64+ chars) | Signs access tokens |
| `APP_ENCRYPTION_KEY` | — (**required**, Fernet key) | Encrypts users' saved AI keys |
| `POSTGRES_DB` / `POSTGRES_USER` | `avap` / `avap_user` | Database name and user |
| `DATABASE_URL` | unset | Full URL; overrides the `POSTGRES_*` values. Use `postgresql+psycopg2://…` |
| `CORS_ALLOWED_ORIGINS` | `http://localhost:3000` (Docker: `http://localhost:3001`) | Browser origin(s) allowed to call the API, comma-separated |
| `FRONTEND_API_BASE_URL` | `http://localhost:8000` | (Docker) URL the **browser** uses to reach the API. It's baked in at build time, so rebuild after changing it |
| `BACKEND_PORT` / `FRONTEND_PORT` | `8000` / `3001` | (Docker) host ports, bound to `127.0.0.1` only |
| `NMAP_EXECUTABLE` | `/usr/bin/nmap` | (local dev) path to the Nmap binary |
| `NMAP_SCAN_MODE` | `auto` | `auto`, `privileged` (raw SYN scans) or `unprivileged` (TCP connect) |
| `SCAN_TIMEOUT` | `900` | Seconds before a QUICK scan is stopped |
| `MIN_CIDR_PREFIX_LENGTH` | `16` | (local dev; not passed through by `docker-compose.yml`) widest CIDR range allowed (`/16` = 65,536 addresses) |
| `REGISTRATIONS_PER_IP_PER_HOUR` | `10` | Sign-up rate limit |
| `SCAN_TARGET_ALLOWLIST` | empty (any target) | Comma-separated IPv4 addresses, CIDRs and hostnames that may be scanned. Set it on any public deployment |
| `TRUSTED_PROXY_SECRET` | empty (off) | Shared secret from the HTTPS proxy (Caddy) so the backend uses the real client IP for rate limits and the audit log. 32+ characters |
| `AVAP_DOMAIN` | — | (public deployment) hostname Caddy gets an HTTPS certificate for |
| `OPENROUTER_MODEL` | `google/gemma-4-31b-it:free` | Must end in `:free` (or be `openrouter/free`) |
| `AI_FINDINGS_IN_RISK` | `false` | AI-inferred findings stay out of the risk score unless this is `true` |
| `STORAGE_BACKEND` | `local` | `local` or `s3` for raw scan output. For S3, also set `S3_BUCKET`, `S3_REGION` and AWS credentials |
| `LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR` or `CRITICAL` |

---

## 6. Running the tests

None of the unit tests need a real database, Nmap or OpenRouter.

**Backend** (from `backend/`, with the venv active):

```bash
DATABASE_URL=sqlite:// pytest      # PowerShell: $env:DATABASE_URL="sqlite://"; pytest
ruff check .                       # lint
mypy .                             # types
bandit -r app                      # security lint
pip-audit                          # known-vulnerable dependencies
```

**Frontend** (from `frontend/`):

```bash
npm run test         # unit tests (Vitest)
npm run typecheck    # TypeScript
npm run lint         # ESLint
npm run build        # production build
```

**Browser tests** (Playwright). These need Docker and start their own
isolated stack on ports 3100 and 18100:

```bash
npx playwright install chromium   # first time only
npm run e2e:stack:up
npm run test:e2e
npm run e2e:stack:down
```

---

## 7. Troubleshooting

| Symptom | Fix |
|---|---|
| `docker compose up` says *Set POSTGRES_PASSWORD / JWT_SECRET_KEY / APP_ENCRYPTION_KEY in .env* | Create the root `.env` (step 2.3) and fill in all three |
| Backend container keeps restarting | Run `docker compose logs backend`. Usually the JWT key is too short or `APP_ENCRYPTION_KEY` isn't a valid Fernet key |
| Migrations fail with an authentication or URL error | `POSTGRES_PASSWORD` contains special characters. Use letters and digits only, then `docker compose down -v` (this **deletes the data**) and start again |
| Browser shows a network or CORS error | `CORS_ALLOWED_ORIGINS` must exactly match the address in your browser bar (e.g. `http://localhost:3001`), and `FRONTEND_API_BASE_URL` / `NEXT_PUBLIC_API_BASE_URL` must point to the backend |
| You're logged out on every page reload | The session cookie is `Secure`: it works on `http://localhost` and over HTTPS, but not over plain HTTP on another IP or hostname. Use localhost, or put the app behind HTTPS |
| A scan fails straight away (local dev) | `NMAP_EXECUTABLE` is wrong, or Nmap isn't installed. On Windows, reinstall Nmap with Npcap |
| Scans work but OS detection or SYN scans are missing | Nmap lacks raw-socket rights. AVAP falls back to TCP connect scans automatically. Run with admin/root or `NMAP_SCAN_MODE=privileged` if you need them |
| "Download PDF" fails with 422 | The scan has no risk score yet (it is calculated automatically when a scan completes). Wait for the scan to finish, or check the backend logs |
| AI remediation fails | No OpenRouter key on your Profile, the key is invalid, or the free model is rate-limited. Everything else keeps working |
| Port 3001 or 8000 is already in use | Change `FRONTEND_PORT` / `BACKEND_PORT` in `.env`. Also update `CORS_ALLOWED_ORIGINS` (and `FRONTEND_API_BASE_URL` if you change the backend port), then `docker compose up -d --build` |

---

## 8. Security notes

- **Secrets** only ever live in `.env` files, which git ignores. The
  committed `*.example` files hold placeholders only.
- **Default exposure:** Docker publishes the ports on `127.0.0.1` only, so
  the app can't be reached from other machines. To host it for others, use
  the Caddy HTTPS setup in [docs/deployment.md](docs/deployment.md).
- **Scanning reach:** the backend scans from wherever it runs. Private
  network ranges can be scanned on purpose, because that's what a LAN
  assessment is. If you open registration to the public, remember that any
  user can then scan whatever your server can reach, including other
  machines on its private network. Set `SCAN_TARGET_ALLOWLIST` on any public
  deployment (`deploy/make-env.sh` does this for you).
- **Built-in safeguards:**
  - Passwords are hashed with Argon2id.
  - Access tokens are short-lived and kept in memory only. The refresh token
    sits in an httpOnly, SameSite=strict cookie.
  - Users' AI keys are encrypted with Fernet.
  - Every query is scoped to the current user.
  - Nmap is started without a shell, and target values are strictly
    validated.
  - Report text is escaped.
  - The audit trail is append-only (a database trigger blocks edits).

---

## 9. Project layout and further docs

```
.
├── backend/                 FastAPI app
│   ├── app/                 routes → services → repositories → models
│   ├── alembic/             database migrations
│   └── tests/               pytest suite
├── frontend/                Next.js app
│   ├── app/                 pages (login, register, targets, scans, profile)
│   ├── features/            one folder per feature (api, hooks, components)
│   └── e2e/                 Playwright browser tests
├── docs/                    design and engineering specs
│   ├── project.md           scope and deferred features
│   ├── ai_contract.md       engineering rules the code follows
│   ├── architecture/        system, data-flow, database and security design
│   ├── modules/             one spec per backend module
│   ├── backend.md, frontend.md, design_system.md
├── deploy/                  Caddyfile and make-env.sh for public deployment
├── docker-compose.yml       full stack
├── docker-compose.demo.yml  optional demo scan targets
├── docker-compose.prod.yml  public deployment: Caddy HTTPS proxy
└── env.docker.example       template for the root .env
```

Some specs in `docs/` predate later changes. Where they disagree with the
code, the code is right.

---

## 10. Public deployment (Oracle Cloud)

[docs/deployment.md](docs/deployment.md) puts the whole stack on one free
Oracle Cloud VM, step by step and without prior Docker knowledge. Caddy
serves it over HTTPS with a free certificate, and visitors can scan only
the targets on the allowlist (the demo containers and `scanme.nmap.org` by
default). In short, on the server:

```bash
sh deploy/make-env.sh your-name.duckdns.org
docker compose up -d --build
```
