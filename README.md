# Cloud Security Monitoring & Intelligent Threat Detection Platform

A portfolio-grade Cloud SIEM and User & Entity Behavior Analytics (UEBA) platform designed to detect, correlate, and respond to advanced cloud attacks.

---

## 1. Project Overview

Modern cloud environments face complex, multi-stage threats that evade traditional static threshold rules: credential stuffing, MFA push fatigue, privilege escalation, and lateral movement.

This platform bridges the gap by providing:
- **Zero-Cloud-Cost Development**: A high-fidelity Azure Security Telemetry Generator emitting realistic Azure Activity Logs, Entra ID (Azure AD) sign-in logs, and Key Vault events.
- **Normalized Ingestion**: Schema normalization supporting cloud-scale attributes.
- **Dual-Track Detection**: Rule-based detection coupled with ML-driven behavioral anomaly detection.
- **Multi-Event Graph Correlation**: Automated incident formation across the MITRE ATT&CK kill-chain.
- **Automated SOAR Playbooks**: Rapid containment with dry-run safety modes.

---

## 2. Technology Stack

- **Backend**: Python 3.11+, FastAPI, Pydantic v2, SQLAlchemy 2 (Async), Alembic
- **Database & Cache**: PostgreSQL 16 (JSONB, partitioning-ready), Redis 7
- **Frontend**: React, TypeScript, Vite, Tailwind CSS
- **Testing**: pytest, pytest-asyncio, httpx
- **DevOps**: Docker, Docker Compose

---

## 3. Architecture Specification

The authoritative architecture and design document is located at:
- [SYSTEM_ARCHITECTURE.md](../../brain/6cf8911c-8294-4b48-b3cc-4f90a8f49c2e/SYSTEM_ARCHITECTURE.md)

---

## 4. Current Implementation Status

✅ **Completed in Phase 1 (Foundations & Synthetic Telemetry)**:
- Complete backend structure (`app/core`, `app/domain`, `app/ingestion`, etc.)
- Database schema (SQLAlchemy 2 Async & Alembic migrations for all 11 core tables)
- Development database seeder (SOC Admin, L1 Analyst, L2 Responder, initial detection rules)
- Synthetic Azure Telemetry Generator (Normal background noise + 3 multi-stage attack scenarios)
- Fast ingestion endpoint (`/api/v1/ingest/raw`) and scenario trigger (`/api/v1/ingest/synthetic/trigger`)
- Basic SOC shell frontend (React + TypeScript + Vite + Tailwind CSS with live metrics)
- Health endpoints (`/health` and `/api/v1/health`)
- Docker Compose configuration (`postgres`, `redis`, `backend`, `frontend`)
- Baseline pytest test suite (13 tests)

✅ **Completed in Phase 2 (Ingestion Pipeline & Detection Rule Engine)**:
- Asynchronous Redis Stream Ingestion Worker (`app/workers/ingestion_worker.py`) with consumer group offset tracking and graceful reconnection backoff
- Stateful & Stateless Detection Rule Engine (`app/detection/evaluator.py`, `app/detection/window.py`)
- Thread-safe sliding window tracking with deduplication and threshold evaluation
- Configured 7 detection rules covering all 3 synthetic attack kill-chains (Credential Compromise, Key Vault Exfiltration, Ransomware)
- Telemetry & Alert APIs: `GET /api/v1/events`, `GET /api/v1/detections`, `GET /api/v1/rules`, `PATCH /api/v1/rules/{rule_id}/toggle`
- Connected Frontend Live Monitor (`frontend/src/pages/LiveMonitor.tsx`) displaying real-time events, alert stream, and KPI counters
- Connected Frontend Detection Rules catalog (`frontend/src/pages/DetectionRules.tsx`) with MITRE ATT&CK tags and active toggle controls
- Expanded test suite (29/29 tests passed, 100% success)

✅ **Completed in Phase 3 (ML Anomaly Detection & UEBA Modeling)**:
- **Feature Extraction Engine (`app/ml/features.py`)**: 20 security and behavioral signals (failed login ratios, MFA prompts, Key Vault operations, secret downloads, deletion actions, temporal off-hours, IP/geo novelty).
- **Statistical UEBA Baselines (`app/ml/baseline.py`)**: Entity-level and population-level moving profiles tracking mean, median, standard deviation, IQR, and robust z-scores for users and service principals.
- **Calibrated Isolation Forest (`app/ml/model.py`)**: scikit-learn Isolation Forest ensemble with normalized $0.0 - 100.0$ anomaly scoring, confidence grading, and Joblib bundle persistence.
- **Explainability Engine (`app/ml/explain.py`)**: Human-readable explanations citing real statistical deviations (e.g. "Secret retrieval activity (16 secrets accessed, 32.0x baseline)", novel caller IP).
- **Inference Pipeline & Persistence (`app/ml/pipeline.py`)**: Synchronous & asynchronous evaluation with database persistence to `ml_anomaly_scores`.
- **Integrated Ingestion Pipeline (`app/workers/ingestion_worker.py`)**: Dual-track processing evaluating both static rules and ML anomaly scores concurrently.
- **Local Training CLI (`backend/scripts/train_ml_model.py`)**: Command-line training pipeline generating diverse operational cloud telemetry.
- **REST Endpoints (`app/api/v1/ml.py`)**: `GET /api/v1/ml/anomalies`, `GET /api/v1/ml/anomalies/{id}`, and `GET /api/v1/ml/metrics`.
- **Frontend UEBA Console (`frontend/src/pages/UEBA.tsx`)**: Real-time anomaly feed, score color-coding, filters, and full detail inspection drawer with deviations table.
- **Dashboard ML Integration (`frontend/src/pages/Dashboard.tsx`)**: Live UEBA & ML Intelligence cards displaying total anomalies, high-risk anomalies, and anomalous identities.
- **Verified Zero-Regression Test Suite**: 43/43 tests passing (100% pass rate).

❌ **Deferred to Later Phases (Per Architecture Roadmap)**:
- Advanced multi-event graph correlation & timeline player — *Phase 4*
- MITRE ATT&CK interactive heatmap matrix — *Phase 4*
- SOAR playbook live cloud executions — *Phase 5*
- Direct Azure Event Hub / Microsoft Graph production live ingest — *Phase 6*

---

## 5. Quickstart & Local Setup

### Option A: Docker Compose (Recommended for Containerized Environments)

```bash
# 1. Copy environment template
cp .env.example .env

# 2. Build and run containers
docker compose up --build
```

- Frontend: `http://localhost:5173`
- Backend API Docs: `http://localhost:8000/docs`

### Option B: Native Local Setup

#### Backend

```bash
cd backend

# Setup Python virtual environment
python -m venv .venv
# Windows:
.venv\Scripts\activate
# Linux/macOS:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run migrations and seed data
alembic upgrade head
python -m app.core.seed

# Start API
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

#### Frontend

```bash
cd frontend
npm install
npm run dev
```

---

## 6. Running Tests

```bash
cd backend
.venv\Scripts\activate  # Or source .venv/bin/activate
pytest -v
```

---

## 7. Synthetic Attack Scenarios

The platform includes 3 built-in realistic multi-stage Azure attack scenarios:

1. **`credential_compromise`**:
   - High-volume failed logins from anomalous IPs (Credential stuffing)
   - MFA prompt fatigue followed by successful login
   - `Microsoft.Authorization/roleAssignments/write` elevating a principal to Owner
2. **`keyvault_exfiltration`**:
   - Service Principal authentication from a novel location
   - Azure Key Vault enumeration (`Microsoft.KeyVault/vaults/read`)
   - Bulk secret retrieval (`Microsoft.KeyVault/vaults/secrets/getSecret/action`)
3. **`ransomware`**:
   - Disabling security monitoring (Defense evasion)
   - Mass storage container deletions (`Microsoft.Storage/storageAccounts/blobServices/containers/delete`)

---

## 8. Phase 3: Machine Learning & UEBA Architecture

### Why ML Exists Alongside Detection Rules
Static detection rules identify known, explicit threat patterns with zero false tolerance (e.g. 5 failed logins within 180 seconds or disabling security tiers). However, advanced attackers frequently operate *below* static thresholds or execute novel sequences with legitimate credentials.

The **ML Anomaly Detection Subsystem** provides **User & Entity Behavior Analytics (UEBA)**:
- **Baseline Profiling**: Learns typical operational patterns per identity (working hours, usual IP addresses, average resource velocities).
- **Outlier Detection**: Flags anomalous deviations without requiring predefined rule signatures.
- **Explainability Guarantee**: Every flagged anomaly is grounded in mathematical feature deltas with human-readable rationale.

### Feature Space (20 Behavioral Features)
1. `failed_auth_count`: Failed login attempts in moving window
2. `successful_auth_count`: Successful login attempts in moving window
3. `failed_auth_ratio`: Ratio of failed to total authentications
4. `mfa_prompt_count`: Repeated MFA push prompts / challenges
5. `privileged_role_ops`: Azure RBAC role assignments / privilege escalations
6. `is_service_principal`: Binary flag distinguishing SPNs from human users
7. `hour_of_day`: Event timestamp hour in UTC (0 - 23)
8. `day_of_week`: Day of week (0=Monday, 6=Sunday)
9. `is_off_hours`: Binary indicator for events outside 08:00 - 18:00 UTC
10. `event_frequency_10m`: Total events by principal in sliding 10-minute window
11. `unique_source_ips`: Number of distinct caller IPs in window
12. `unique_resources`: Number of distinct Azure resource IDs accessed
13. `keyvault_ops`: Azure Key Vault read and write volume
14. `secret_retrievals`: Count of `getSecret` API downloads
15. `storage_ops`: Blob read, write, and container actions
16. `admin_ops`: ResourceManagement write actions
17. `security_config_mods`: Modifications to Defender pricing or security tiers
18. `deletion_ops`: Container, secret, or resource deletion operations
19. `is_novel_ip`: 1.0 if caller IP is not present in principal baseline history
20. `is_novel_country`: 1.0 if geographical origin is outside known baseline history

### Calibrated Anomaly Scoring Formula
The raw scikit-learn Isolation Forest decision function $d \in [-0.35, +0.35]$ is combined with the per-identity statistical baseline:

$$\text{base\_score} = \text{clip}(35.0 - (d \times 220.0), \; 5.0, \; 75.0)$$
$$\text{deviation\_boost} = \min\left(35.0, \; \sum_{f} \max(0, z_f - 1.5) \times 3.5 + 8.0 \cdot \mathbf{1}_{\text{novel\_ip}} + 8.0 \cdot \mathbf{1}_{\text{novel\_geo}}\right)$$
$$\text{anomaly\_score} = \text{clip}(\text{base\_score} + \text{deviation\_boost}, \; 0.0, \; 100.0)$$

- **Critical** ($\ge 80.0$): Extreme outlier with severe deviations
- **High** ($65.0 - 79.9$): Elevated threat velocity or mass resource access
- **Medium** ($55.0 - 64.9$): Actionable behavioral deviation
- **Low** ($< 55.0$): Standard operational baseline activity

### Local Model Training
To train or retrain the Isolation Forest model locally:

```bash
# Run training script (generates diverse baseline telemetry and saves bundle)
python backend/scripts/train_ml_model.py --samples 350 --contamination 0.03
```

Artifact bundle saved at `backend/app/ml/artifacts/isolation_forest_v1.joblib`.

### End-to-End Verification
To execute the comprehensive Phase 3 verification suite:

```bash
python backend/scripts/verify_phase3.py
```
