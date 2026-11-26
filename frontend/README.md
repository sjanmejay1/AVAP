# AVAP Frontend

Next.js (App Router) frontend for the Automated Vulnerability Assessment
Platform. See `../docs/frontend.md` for architecture and `../docs/design_system.md`/this
codebase's `app/globals.css` for the design system. Deploys independently
from the FastAPI backend — see "Environment" below.

## Prerequisites

- Node.js 20+
- The AVAP backend running and reachable (see the root `README.md`)

## Setup

```bash
npm install
cp .env.example .env.local   # then set NEXT_PUBLIC_API_BASE_URL
npm run dev
```

Open [http://localhost:3000](http://localhost:3000).

The app fails fast with a clear error if `NEXT_PUBLIC_API_BASE_URL` is
missing or not a valid absolute URL — this is intentional (see
`config/env.ts`).

## Environment

| Variable | Required | Description |
|---|---|---|
| `NEXT_PUBLIC_API_BASE_URL` | Yes | Base URL of the deployed AVAP backend, no trailing slash, no `/api/v1` suffix (e.g. `https://api.avap.example.com`). Bundled into the browser — never put secrets in a `NEXT_PUBLIC_*` variable. |

For local development against the backend's default CORS allowlist, the
backend's `CORS_ALLOWED_ORIGINS` must include this app's origin
(`http://localhost:3000` by default — see `backend/.env.example`).

## Commands

```bash
npm run dev         # start the dev server
npm run build        # production build
npm run start         # run the production build
npm run typecheck    # tsc --noEmit
npm run lint          # eslint
npm run test           # vitest (single run)
npm run test:watch    # vitest (watch mode)
```

## Architecture

Feature-oriented structure; see `../docs/frontend.md` for the full rationale.

```
app/            Next.js App Router routes: (auth)/ login, register; (app)/ targets, scans, profile
components/     ui/ (shadcn primitives) + shared/ (cross-feature components)
features/       one folder per domain (api/, components/, hooks/, types/)
lib/            api client, auth token + refresh, error normalization, request unwrapping
providers/      QueryClient, auth session, theme, toast composition
config/         validated environment configuration
constants/      shared design/domain constants (e.g. severity color map)
utils/          formatting helpers
types/          shared cross-feature contract types
```

Sign-in uses the backend's JWT access token (kept in memory only) and its
httpOnly refresh cookie; see `../docs/frontend.md` → Authentication. There are no
roles: every user sees only their own targets and scans.
