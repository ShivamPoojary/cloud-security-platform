# Security Architecture & Policies (Phase 1)

This document outlines the security controls, baseline policies, and threat mitigations implemented in Phase 1 of the **Cloud Security Monitoring & Intelligent Threat Detection Platform**.

---

## 1. Secrets Management Policy
- **No Hardcoded Credentials**: API secrets, database credentials, and session tokens are strictly sourced from environment variables.
- **Development Passwords**: The initial development seed password is read from `DEV_SEED_PASSWORD`. If not provided, a secure documented default is used.
- **Version Control Guardrails**: All environment configuration files (`.env`, `.env.local`) are excluded via `.gitignore`. An example template is provided in `.env.example`.

---

## 2. Ingestion & Input Validation
- **Strict Pydantic v2 Models**: Every event received via `/api/v1/ingest/raw` is validated for type safety, required security attributes, ISO-8601 timestamps, and schema constraints.
- **SQL Injection Prevention**: All persistence operations utilize SQLAlchemy 2.0 Async parameterized queries and ORM mappings, eliminating raw SQL concatenation.
- **JSONB Sanitization**: Unstructured event metadata stored in PostgreSQL `JSONB` fields undergoes JSON structure validation before persistence.

---

## 3. Network & Transport Security
- **Cross-Origin Resource Sharing (CORS)**: Configured explicitly via FastAPI's `CORSMiddleware`. In development, allowed origins are restricted to `ALLOWED_ORIGINS` (default: `http://localhost:5173`). Wildcards (`*`) are prohibited in production.
- **Correlation & Request ID Tracing**: Every inbound HTTP request is assigned a unique `X-Request-ID` header to enable forensic tracing through backend logs.

---

## 4. Threat Mitigation Summary
| Risk Identified | Phase 1 Mitigation |
| :--- | :--- |
| **Log Spoofing / Malformed Ingest** | Strict Pydantic schema rejection (`HTTP 422 Unprocessable Entity`). |
| **Ingestion Pipeline Flooding** | Redis Stream buffer decouples raw ingestion from database writes. |
| **Authentication & Password Leaks** | Passwords stored with cryptographic hashing (bcrypt/passlib). |
| **Tampering with Seed Data** | Seed script checks existing user accounts by unique email before insertion. |
