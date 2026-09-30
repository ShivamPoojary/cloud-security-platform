# API Specification (Phase 1)

The platform provides a versioned, RESTful API along with OpenAPI documentation accessible at `http://localhost:8000/docs`.

---

## 1. Health Endpoints

### Basic Health Check
- **Endpoint**: `GET /health`
- **Description**: Lightweight health probe for load balancers and container orchestrators.
- **Response `200 OK`**:
```json
{
  "status": "ok",
  "service": "cloud-security-platform"
}
```

### Detailed Component Health Check
- **Endpoint**: `GET /api/v1/health`
- **Description**: Probes PostgreSQL and Redis connectivity status.
- **Response `200 OK`**:
```json
{
  "status": "ok",
  "service": "cloud-security-platform",
  "version": "0.1.0",
  "database": "connected",
  "redis": "connected",
  "timestamp": "2026-09-25T09:45:00.000000Z"
}
```

---

## 2. Telemetry Ingestion Endpoints

### Ingest Raw Security Event
- **Endpoint**: `POST /api/v1/ingest/raw`
- **Description**: Ingests a single synthetic or cloud-like telemetry event. The event is validated against the schema and buffered into Redis.
- **Request Body**:
```json
{
  "source": "AzureActivity",
  "event_category": "ResourceManagement",
  "event_name": "Microsoft.Compute/virtualMachines/write",
  "principal_id": "usr-018f23a9",
  "principal_name": "developer1@secplatform.local",
  "caller_ip": "198.51.100.12",
  "target_resource_id": "/subscriptions/sub-01/resourceGroups/rg-core/providers/Microsoft.Compute/virtualMachines/vm-dev-01",
  "target_resource_name": "vm-dev-01",
  "action_status": "Success",
  "geo_country": "United States",
  "user_agent": "AzurePortal/1.0",
  "metadata": {
    "vm_size": "Standard_B2s",
    "os_type": "Linux"
  }
}
```
- **Response `202 Accepted`**:
```json
{
  "status": "queued",
  "event_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "timestamp": "2026-09-25T09:45:00.000000Z"
}
```

---

### Trigger Synthetic Attack Scenario
- **Endpoint**: `POST /api/v1/ingest/synthetic/trigger`
- **Description**: Triggers a realistic synthetic Azure security scenario. Supported scenarios:
  1. `credential_compromise`: Brute force / Credential stuffing $\to$ MFA push fatigue $\to$ Role assignment escalation.
  2. `keyvault_exfiltration`: Compromised Service Principal $\to$ Key Vault enumeration $\to$ Bulk secret retrieval.
  3. `ransomware`: Defense evasion (disabling security monitoring) $\to$ Mass storage container deletion.
- **Request Body**:
```json
{
  "scenario_name": "keyvault_exfiltration",
  "custom_target_resource": "kv-production-core"
}
```
- **Response `200 OK`**:
```json
{
  "execution_id": "scen-0192a83f-e8b4",
  "scenario_name": "keyvault_exfiltration",
  "status": "generated",
  "events_count": 18,
  "events": [...]
}
```

---

## 3. Telemetry & Detections Query Endpoints

### Query Normalized Telemetry Events
- **Endpoint**: `GET /api/v1/events`
- **Query Params**: `limit` (default: 50), `offset` (default: 0), `category`, `action_status`
- **Response `200 OK`**:
```json
{
  "items": [
    {
      "id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
      "timestamp": "2026-09-25T09:45:00Z",
      "source": "AzureActivity",
      "event_category": "ResourceManagement",
      "event_name": "Microsoft.Compute/virtualMachines/write",
      "principal_name": "developer1@secplatform.local",
      "caller_ip": "198.51.100.12",
      "action_status": "Success"
    }
  ],
  "total": 128,
  "limit": 50,
  "offset": 0
}
```

---

### Query Threat Detections & Alerts
- **Endpoint**: `GET /api/v1/detections`
- **Query Params**: `limit` (default: 50), `offset` (default: 0), `severity` (e.g. `HIGH`, `CRITICAL`)
- **Response `200 OK`**:
```json
{
  "items": [
    {
      "id": "7fa85f64-5717-4562-b3fc-2c963f66afa6",
      "rule_id": "2fa85f64-5717-4562-b3fc-2c963f66afa6",
      "rule_code": "AZ-RULE-0042",
      "rule_title": "Azure Key Vault Mass Secret Retrieval",
      "severity": "HIGH",
      "alert_summary": "[HIGH] Azure Key Vault Mass Secret Retrieval - Detected on 'spn-github-cicd' at kv-production-core (Credential Access / T1555.006)",
      "mitre_tactic": "Credential Access",
      "mitre_technique_id": "T1555.006",
      "detected_at": "2026-09-25T09:46:30Z"
    }
  ],
  "total": 4,
  "limit": 50,
  "offset": 0
}
```

---

## 4. Detection Rules Catalog Endpoints

### List Detection Rules
- **Endpoint**: `GET /api/v1/rules`
- **Query Params**: `is_active` (optional boolean)
- **Response `200 OK`**: Returns array of rule definitions with current `detection_count`.

### Toggle Detection Rule Active Status
- **Endpoint**: `PATCH /api/v1/rules/{rule_id}/toggle`
- **Response `200 OK`**:
```json
{
  "rule_id": "AZ-RULE-0010",
  "is_active": false,
  "message": "Detection rule 'AZ-RULE-0010' has been disabled."
}
```

---

## 5. Machine Learning & UEBA Endpoints

### List ML Anomalies & Scores
- **Endpoint**: `GET /api/v1/ml/anomalies`
- **Query Params**:
  - `limit`: Number of records (default: 50, max: 500)
  - `offset`: Pagination offset (default: 0)
  - `principal`: Filter by principal email or ID (e.g. `spn-github-cicd`, `alex.rivera`)
  - `severity`: Filter by severity (`low`, `medium`, `high`, `critical`)
  - `min_score`: Filter records with anomaly score $\ge$ minimum (e.g. `60.0`)
  - `is_anomalous`: Boolean flag (`true` to return only flagged outliers)
- **Response `200 OK`**:
```json
{
  "items": [
    {
      "id": "e8115e21-1b6c-4ae5-813a-5cffe90e1ba8",
      "event_id": "bdcf3887-765a-4cfa-829f-72c5303b0935",
      "model_version": "ueba-isolation-forest-v1",
      "anomaly_score": 80.3,
      "confidence": 0.88,
      "is_anomalous": true,
      "severity": "critical",
      "summary": "Mass Key Vault secret retrieval activity (16 secrets accessed, 32.0x baseline)",
      "reasons": [
        "Mass Key Vault secret retrieval activity (16 secrets accessed, 32.0x baseline)",
        "Activity originated from a previously unseen source IP (203.0.113.199)",
        "Activity originated from an unfamiliar geographical location (Netherlands)"
      ],
      "top_deviations": {
        "secret_retrievals": {
          "observed": 16.0,
          "baseline_mean": 0.5,
          "z_score": 4.8
        }
      },
      "principal_id": "spn-github-cicd",
      "principal_name": "spn-github-actions-deploy",
      "caller_ip": "203.0.113.199",
      "event_name": "Microsoft.KeyVault/vaults/secrets/getSecret/action",
      "created_at": "2026-09-25T19:37:24Z"
    }
  ],
  "total": 70,
  "limit": 50,
  "offset": 0
}
```

---

### Get Single ML Anomaly Record
- **Endpoint**: `GET /api/v1/ml/anomalies/{anomaly_id}`
- **Response `200 OK`**: Detailed anomaly record including complete feature vector and statistical baseline deltas.
- **Response `404 Not Found`**: Returned if the anomaly ID does not exist.

---

### Get UEBA System Metrics
- **Endpoint**: `GET /api/v1/ml/metrics`
- **Response `200 OK`**: Aggregated counters for executive and operations dashboards.
```json
{
  "total_anomalies": 70,
  "high_risk_anomalies": 29,
  "anomalous_principals": 3,
  "avg_anomaly_score": 48.6,
  "model_version": "ueba-isolation-forest-v1",
  "active_features_count": 20
}
```
