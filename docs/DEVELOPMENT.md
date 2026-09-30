# Development Guide

This guide covers local environment setup, testing, and contribution workflows for the **Cloud Security Monitoring & Intelligent Threat Detection Platform**.

## 1. Prerequisites

- **Python 3.11+**
- **Node.js 18+ / 22+** (with npm)
- **Docker & Docker Compose** (optional for containerized setup; local native execution is also fully supported)

---

## 2. Quickstart with Docker Compose

To spin up all services (PostgreSQL 16, Redis 7, FastAPI backend, and React frontend) in one command:

```bash
# 1. Copy environment template
cp .env.example .env

# 2. Build and launch services
docker compose up --build
```

The services will be available at:
- **Frontend Dashboard**: `http://localhost:5173`
- **Backend API & Swagger Docs**: `http://localhost:8000/docs`
- **PostgreSQL**: `localhost:5432` (database: `secplatform_db`, user: `secplatform_user`)
- **Redis**: `localhost:6379`

---

## 3. Local Development (Native Mode)

If running without Docker:

### Backend Setup

```bash
cd backend

# Create and activate Python virtual environment
python -m venv .venv
# On Windows:
.venv\Scripts\activate
# On Linux/macOS:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run database migrations
alembic upgrade head

# Seed initial development data (SOC admin, analysts, detection rules)
python -m app.core.seed

# Start backend development server
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

### Frontend Setup

```bash
cd frontend

# If using Windows with symbolic links, ensure symlinks are preserved:
# In PowerShell:
$env:NODE_OPTIONS = "--preserve-symlinks-main --preserve-symlinks"

# Install dependencies
npm install

# Start Vite development server
npm run dev
```

---

## 4. Running the Test Suite

The backend uses `pytest` with `pytest-asyncio` and `httpx`:

```bash
cd backend
.venv\Scripts\activate  # Or source .venv/bin/activate
pytest -v
```

Tests cover:
- Health check endpoints (`/health` and `/api/v1/health`)
- Security event Pydantic schema validation
- Synthetic normal background event generation
- Synthetic multi-stage attack scenario generation
- Database connection & migration readiness
- Ingestion endpoint (`/api/v1/ingest/raw`)
