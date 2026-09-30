"""API integration tests for Incident Management endpoints (Milestone 4.2).

Validates:
1. Incident list pagination & filtering (by status, severity, min_risk).
2. Incident detail with detections, ML anomalies, and timeline events.
3. Status update and resolution timestamp management.
4. On-demand correlation endpoint.
"""

import uuid
from datetime import datetime, timezone, timedelta
import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.domain.models.logs import NormalizedEvent
from app.domain.models.rules import DetectionRule
from app.domain.models.detections import ThreatDetection
from app.domain.models.ml import MLAnomalyScore
from app.domain.models.incidents import Incident, IncidentTimelineEvent


@pytest.mark.asyncio
async def test_list_incidents_pagination_and_filtering(client: AsyncClient, db_session: AsyncSession):
    """Test GET /api/v1/incidents with pagination and query filters."""
    now = datetime.now(timezone.utc)

    inc1 = Incident(
        id=uuid.uuid4(),
        incident_number=f"INC-TEST-{uuid.uuid4().hex[:6].upper()}",
        title="Critical Exfiltration",
        status="NEW",
        severity="CRITICAL",
        risk_score=92.0,
        mitre_tactics=["Exfiltration"],
        mitre_techniques=["T1567"],
        created_at=now - timedelta(hours=2),
        updated_at=now - timedelta(hours=2),
    )
    inc2 = Incident(
        id=uuid.uuid4(),
        incident_number=f"INC-TEST-{uuid.uuid4().hex[:6].upper()}",
        title="Medium Brute Force",
        status="TRIAGED",
        severity="MEDIUM",
        risk_score=45.0,
        mitre_tactics=["Initial Access"],
        mitre_techniques=["T1110.001"],
        created_at=now - timedelta(hours=1),
        updated_at=now - timedelta(hours=1),
    )
    inc3 = Incident(
        id=uuid.uuid4(),
        incident_number=f"INC-TEST-{uuid.uuid4().hex[:6].upper()}",
        title="Resolved Defense Tampering",
        status="RESOLVED",
        severity="HIGH",
        risk_score=78.0,
        mitre_tactics=["Defense Evasion"],
        mitre_techniques=["T1562.008"],
        created_at=now,
        updated_at=now,
        resolved_at=now,
    )
    db_session.add_all([inc1, inc2, inc3])
    await db_session.commit()

    # 1. Basic pagination
    res = await client.get("/api/v1/incidents?limit=2&offset=0")
    assert res.status_code == 200
    data = res.json()
    assert "items" in data
    assert "total" in data
    assert data["total"] >= 3
    assert len(data["items"]) == 2

    # 2. Filter by status=NEW
    res_status = await client.get("/api/v1/incidents?status=NEW")
    assert res_status.status_code == 200
    items_status = res_status.json()["items"]
    assert all(i["status"] == "NEW" for i in items_status)

    # 3. Filter by severity=CRITICAL
    res_sev = await client.get("/api/v1/incidents?severity=CRITICAL")
    assert res_sev.status_code == 200
    items_sev = res_sev.json()["items"]
    assert all(i["severity"] == "CRITICAL" for i in items_sev)

    # 4. Filter by min_risk=75.0
    res_risk = await client.get("/api/v1/incidents?min_risk=75.0")
    assert res_risk.status_code == 200
    items_risk = res_risk.json()["items"]
    assert all(i["risk_score"] >= 75.0 for i in items_risk)


@pytest.mark.asyncio
async def test_get_incident_detail(client: AsyncClient, db_session: AsyncSession):
    """Test GET /api/v1/incidents/{incident_id} retrieves detections, anomalies, and timeline."""
    now = datetime.now(timezone.utc)

    # Create supporting models
    event = NormalizedEvent(
        id=uuid.uuid4(),
        event_timestamp=now,
        event_category="Security",
        event_name="DefenderTampered",
        principal_name="attacker@test.local",
        caller_ip="198.51.100.77",
        target_resource_name="DefenderPricing",
        action_status="Success",
        security_context={},
    )
    rule = DetectionRule(
        id=uuid.uuid4(),
        rule_id="AZ-RULE-TEST-DET",
        title="Defender Pricing Tampering",
        severity="CRITICAL",
        mitre_tactic="Defense Evasion",
        mitre_technique_id="T1562.008",
        description="Rule description",
        rule_logic={"type": "stateless", "filter": {"event_name": "DefenderPricingTamperMatch"}},
        is_active=True,
    )
    incident = Incident(
        id=uuid.uuid4(),
        incident_number=f"INC-TEST-{uuid.uuid4().hex[:6].upper()}",
        title="Tampering on DefenderPricing",
        status="IN_INVESTIGATION",
        severity="CRITICAL",
        risk_score=95.0,
        mitre_tactics=["Defense Evasion"],
        mitre_techniques=["T1562.008"],
        created_at=now,
        updated_at=now,
    )
    db_session.add_all([event, rule, incident])
    await db_session.flush()

    detection = ThreatDetection(
        id=uuid.uuid4(),
        rule_id=rule.id,
        event_id=event.id,
        incident_id=incident.id,
        severity="CRITICAL",
        alert_summary="Disabled pricing plan",
        detected_at=now,
    )
    anomaly = MLAnomalyScore(
        id=uuid.uuid4(),
        event_id=event.id,
        incident_id=incident.id,
        model_version="ueba-v1.0.0",
        anomaly_score=85.0,
        confidence=0.92,
        is_anomalous=True,
        feature_contributions={"severity": "CRITICAL", "summary": "Extreme behavioral outlier"},
        created_at=now,
    )
    timeline_event = IncidentTimelineEvent(
        id=uuid.uuid4(),
        incident_id=incident.id,
        event_id=event.id,
        correlation_reason="Security Alert: Defender Pricing Tampered",
        sequence_order=0,
        created_at=now,
    )
    db_session.add_all([detection, anomaly, timeline_event])
    await db_session.commit()

    # Query detail
    res = await client.get(f"/api/v1/incidents/{incident.id}")
    assert res.status_code == 200
    data = res.json()

    assert data["id"] == str(incident.id)
    assert data["incident_number"] == incident.incident_number
    assert data["severity"] == "CRITICAL"
    assert data["risk_score"] == 95.0
    assert len(data["detections"]) == 1
    assert data["detections"][0]["rule_code"] == "AZ-RULE-TEST-DET"
    assert len(data["anomalies"]) == 1
    assert data["anomalies"][0]["anomaly_score"] == 85.0
    assert len(data["timeline"]) == 1
    assert data["timeline"][0]["sequence_order"] == 0
    assert data["timeline"][0]["principal_name"] == "attacker@test.local"

    # 404 on non-existent ID
    res_404 = await client.get(f"/api/v1/incidents/{uuid.uuid4()}")
    assert res_404.status_code == 404


@pytest.mark.asyncio
async def test_update_incident_status_and_resolution(client: AsyncClient, db_session: AsyncSession):
    """Test PATCH /api/v1/incidents/{incident_id}/status lifecycle transitions."""
    now = datetime.now(timezone.utc)
    incident = Incident(
        id=uuid.uuid4(),
        incident_number=f"INC-STATUS-{uuid.uuid4().hex[:6].upper()}",
        title="Test Status Incident",
        status="NEW",
        severity="MEDIUM",
        risk_score=50.0,
        mitre_tactics=["Initial Access"],
        mitre_techniques=["T1110.001"],
        created_at=now,
        updated_at=now,
    )
    db_session.add(incident)
    await db_session.commit()

    # 1. Update to TRIAGED
    res_triaged = await client.patch(
        f"/api/v1/incidents/{incident.id}/status",
        json={"status": "TRIAGED"},
    )
    assert res_triaged.status_code == 200
    data_triaged = res_triaged.json()
    assert data_triaged["status"] == "TRIAGED"
    assert data_triaged["resolved_at"] is None

    # 2. Update to RESOLVED -> sets resolved_at
    res_resolved = await client.patch(
        f"/api/v1/incidents/{incident.id}/status",
        json={"status": "RESOLVED"},
    )
    assert res_resolved.status_code == 200
    data_resolved = res_resolved.json()
    assert data_resolved["status"] == "RESOLVED"
    assert data_resolved["resolved_at"] is not None

    # 3. Invalid status returns 422
    res_invalid = await client.patch(
        f"/api/v1/incidents/{incident.id}/status",
        json={"status": "NON_EXISTENT_STATUS"},
    )
    assert res_invalid.status_code == 422


@pytest.mark.asyncio
async def test_trigger_correlation_api_endpoint(client: AsyncClient, db_session: AsyncSession):
    """Test POST /api/v1/incidents/correlate endpoint."""
    res = await client.post("/api/v1/incidents/correlate")
    assert res.status_code == 200
    data = res.json()
    assert "created_incidents" in data
    assert "updated_incidents" in data
    assert "correlated_events" in data
    assert "message" in data
