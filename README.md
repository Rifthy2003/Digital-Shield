# Infora Digital Shield

**Your Personal Digital Security Center** — Protect · Detect · Respond

A citizen-focused cybersecurity platform: a security dashboard with an
explainable score, a URL threat checker, a scam/phishing message analyzer,
breach monitoring, password health, security alerts, an AI-assisted
assistant, an "I've Been Hacked" recovery wizard, citizen incident
reporting, and an admin dashboard.

This repository is a **real, running MVP** — not a mockup. Every module
listed in `docs/MVP_CHECKLIST.md` as "implemented" has working backend
logic, a tested API, and a connected frontend screen. Where a feature
depends on something not yet configured (e.g. live breach data, a full AI
provider), it says so honestly in its response rather than faking a result.

## Status at a glance

| Area | Status |
|---|---|
| Auth, RBAC, JWT + refresh rotation | ✅ Implemented & tested |
| Security Dashboard & Score Engine | ✅ Implemented & tested |
| URL Threat Checker (with SSRF guard) | ✅ Implemented & tested |
| Scam/Phishing Message Analyzer | ✅ Implemented & tested |
| Password Health (local-first) | ✅ Implemented & tested |
| Breach Monitoring | ✅ Implemented (honest "not configured" without an HIBP key) |
| Alerts | ✅ Implemented |
| Incident Reporting | ✅ Implemented |
| AI Assistant | ✅ Implemented (rule-based fallback without an AI provider key) |
| Admin Dashboard | ✅ Implemented |
| Frontend (all 14 pages) | ✅ Implemented, builds cleanly |
| OAuth integrations, device/login monitoring, Privacy Center, enterprise, government dashboard | 🔲 Not built — architectural placeholders only, see `docs/ROADMAP.md` |
| Automated email delivery, MFA enrollment UI | 🔲 Not built this pass |
| Dockerized stack end-to-end | ⚠️ Written and reviewed, **not verified with a real Docker daemon** in this environment (no Docker available in the build sandbox) |

## Tech stack

- **Backend:** Python, FastAPI, SQLAlchemy 2.x, Alembic, PostgreSQL (SQLite for local/dev/tests), Argon2id, PyJWT, slowapi (rate limiting)
- **Frontend:** React 19, TypeScript, Vite, Tailwind CSS v4, React Router, Axios
- **Infra:** Docker, Docker Compose, Nginx (serving the built frontend)

## Project structure

```
infora-digital-shield/
├── backend/
│   ├── app/
│   │   ├── api/routes/       # One router per module (auth, dashboard, url_checker, ...)
│   │   ├── core/             # security.py (hashing/JWT), rbac.py, rate_limit.py
│   │   ├── models/           # SQLAlchemy models, one file per table
│   │   ├── schemas/          # Pydantic request/response schemas
│   │   ├── services/         # Business logic: url_analysis, message_analysis,
│   │   │                     #   password_strength, breach_provider, security_score, ssrf_guard
│   │   ├── utils/audit.py
│   │   ├── config.py
│   │   ├── database.py
│   │   └── main.py
│   ├── alembic/               # Migrations (initial schema generated & verified)
│   ├── tests/                 # pytest — 30 tests, all passing
│   ├── requirements.txt
│   └── Dockerfile
├── frontend/
│   ├── src/
│   │   ├── api/                # client.ts (axios + token refresh), endpoints.ts, types.ts
│   │   ├── components/         # AppShell, Card, RiskBadge, ScoreRing, ProtectedRoute
│   │   ├── context/AuthContext.tsx
│   │   └── pages/               # Login, Register, Dashboard, UrlChecker, MessageChecker,
│   │                             # BreachChecker, PasswordHealth, Alerts, Incidents,
│   │                             # Assistant, Emergency, Profile, Admin
│   ├── Dockerfile               # multi-stage build → nginx
│   └── nginx.conf
├── docs/
│   ├── ARCHITECTURE.md
│   ├── SECURITY.md
│   ├── ROADMAP.md
│   └── MVP_CHECKLIST.md
├── docker-compose.yml
├── .env.example
└── README.md
```

## Running locally — option A: Docker Compose (not verified end-to-end here)

```bash
cp .env.example .env
# edit .env — at minimum set JWT_SECRET_KEY and POSTGRES_PASSWORD
docker compose up --build
```

- Backend: http://localhost:8000 (interactive API docs at `/api/docs`)
- Frontend: http://localhost:5173

> This compose file was written and reviewed but the build sandbox used to
> create this project has no Docker daemon, so `docker compose up` itself
> has not been executed. The backend and frontend were each verified to
> run and build correctly outside Docker (see below) — treat the Compose
> path as "should work, please verify on first run" rather than proven.

## Running locally — option B: directly (this is how it was verified)

**Backend:**
```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export DATABASE_URL="sqlite:///./dev.db"   # or a real Postgres URL
export JWT_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(64))')"
alembic upgrade head
uvicorn app.main:app --reload
```

**Frontend:**
```bash
cd frontend
npm install
echo "VITE_API_BASE_URL=http://localhost:8000/api/v1" > .env.local
npm run dev
```

**Tests:**
```bash
cd backend
python -m pytest tests/ -v
```
30 tests covering auth/lockout/RBAC/token rotation, the SSRF guard, URL
scoring determinism, password strength, message analysis, and the honest
"not configured" behavior of the breach checker — all passing as of this
build.

## Configuration

See `.env.example` for the full list. Nothing sensitive has a real default
— `JWT_SECRET_KEY` ships with an obviously-fake dev value that must be
replaced before any real deployment. `HIBP_API_KEY` and
`AI_PROVIDER_API_KEY` are optional: leaving them blank does not break
anything, it just puts those two features into their documented
"not configured" state instead of faking a result.

## Where to read more

- **`docs/ARCHITECTURE.md`** — service boundaries, data flow, why this stack
- **`docs/SECURITY.md`** — threat model summary, credential handling, SSRF defenses, known gaps
- **`docs/ROADMAP.md`** — what's deliberately not built yet, and why
- **`docs/MVP_CHECKLIST.md`** — feature-by-feature completion status
