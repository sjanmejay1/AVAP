AVAP — Automated Vulnerability Assessment Platform

Full-stack security assessment platform. Pipeline:
Target Validation → Nmap Scan → Parse → Asset/Vuln Inventory → Deterministic Risk Scoring → AI Remediation (advisory) → PDF Report → Audit Trail.

Built for security awareness and learning. Free/open-source stack only.

Stack


Backend (backend/): Python 3.12, FastAPI, SQLAlchemy 2.x, Alembic, PostgreSQL, Pydantic v2, ReportLab, pytest (SQLite in-memory).
Frontend (frontend/): Next.js App Router, TypeScript, TanStack Query, Zustand, shadcn/ui + Tailwind, React Hook Form + Zod, Vitest.
Scanners: Nmap only, QUICK and FULL profiles (OpenVAS stub removed 2026-11-20). Raw output goes to object storage (local folder backend/storage/ by default, or S3; code in app/storage/).
AI: OpenRouter only, FREE models only (app/ai/providers/openrouter.py; OPENROUTER_MODEL must end in ':free' or be 'openrouter/free'), called with each user's own encrypted key; no server-wide key. AI findings are advisory and excluded from risk unless AI_FINDINGS_IN_RISK=true.


Commands

Backend dev: uvicorn app.main:app --reload --host 0.0.0.0 --port 8000 (from backend/, venv active)
Backend tests: pytest
Backend checks: ruff check . · mypy . · bandit -r app · pip-audit
Frontend dev: npm run dev
Frontend checks: npm run test (vitest) · npm run typecheck (tsc --noEmit) · npm run lint (eslint)
Browser tests: npm run e2e:stack:up · npm run test:e2e (Playwright, 13 tests against docker-compose.demo.yml targets) · npm run e2e:stack:down
Migrations: alembic upgrade head (11 migrations, 0001→0011)


Quality bar to match: 661 backend tests + 180 frontend tests + 13 Playwright tests passing, 0 ruff/mypy/bandit findings, pip-audit clean, frontend tsc/eslint/next build clean (browser-test phase, 2026-11-24). Run pytest with DATABASE_URL=sqlite:// as a safety net.

Architecture — non-negotiable

Backend layering. Route → Service → Repository → DB. No exceptions.


Services own business logic and own transactions/commits.
Repositories own persistence and flush only — a repository must never commit.
Routes contain zero business logic.
No DB access bypasses a repository. No raw SQL in business logic.
Layers talk only to adjacent layers. Dependencies point inward.


Frontend layering. Component → Feature Hook → API Service → Axios Client → Backend.


Feature-folder organization: features/{auth,profile,targets,scans,vulnerabilities,risk,ai,reports} (global dashboard, assets, audit and findings pages removed 2026-11-21).
TanStack Query for server state. Zustand for UI state only.
Forms: React Hook Form + Zod.
Reuse the existing response envelope, error normalization, and loading/empty/error states. Do not invent parallel patterns.


App independence. Backend and frontend communicate only over versioned REST at /api/v1. No shared DB, session, or filesystem.

Pure-logic packages stay pure.


app/risk_engine/ — deterministic, versioned (CALCULATION_VERSION = "1.0.0"), frozen formula: severity base + asset/service bonuses, max-aggregated up the scope chain (vuln → asset → scan → assessment). AI must never influence risk scoring.
app/ai/ — provider-neutral abstraction, advisory output only, never a source of truth. Swapping providers must touch only the provider implementation.
app/reporting/ — PDF via ReportLab. Independent of scanners; adding a format must not change business logic. Requires risk calculated first.
app/audit/ — actor/request context. audit_events is append-only; a Postgres trigger blocks UPDATE/DELETE. Don't fight it.


Adapters. Scanners are reached only through their adapters; business logic never invokes CLI tools. Raw scanner output is never consumed directly — it always passes through a parser, which validates, normalizes, handles malformed input, and emits typed models. Parsers hold no business rules.

Security rules

Treat every input as hostile. Never shell=True, never concatenate shell commands, never hardcode credentials or secrets. Parameterized queries only. All config from environment variables. Guard against command injection, SQLi, path traversal, SSRF, XSS, RCE, unsafe deserialization. Errors returned to clients are sanitized; diagnostic detail goes to structured logs, never sensitive values.

Off-limits / out of scope

Do not add, even if it seems natural:


RBAC, roles, admin users, multi-tenancy/organizations
CI-CD pipelines, distributed/orchestrated deployment
Message queues, scheduling, distributed scanners
Configurable sort order
New libraries or state-management patterns without asking

(Single-host Docker Compose was delivered on owner request 2026-07-20.
Authentication (JWT + rotating refresh cookie), open registration and
per-user ownership of all data were delivered on owner request 2026-11-20 —
see audit/final-goal-plan.md. Every user-facing query must be scoped to the
current user; another user's resource returns 404. The broader deferrals
above still stand.)


These are deliberate deferrals documented in docs/project.md, not gaps. Current architecture must not prevent them later, but must not implement them now.

Conventions


Explicit type hints everywhere. Small functions, small classes, clear names.
Structured logging with module, operation, and failure reason.
No placeholder implementations, TODOs, dead code, commented-out code, print() statements, or unused imports in committed work.
Production code is not accepted without tests.
Architectural changes require explicit owner approval. Do not redesign established architecture unprompted.


Reference docs


README.md — current "how to run this" (most authoritative, root)
docs/ai_contract.md — full engineering contract; this file is its working summary
docs/archive/ (backend_api_manifest.yaml, Backend_Walk.md, old Run.md) — API spec/walkthrough (gitignored, local-only)
docs/modules/01–10 — per-module specs
docs/project.md — scope and deferred phases


If backend_api_manifest.yaml and running code disagree, trust the code and flag the drift.