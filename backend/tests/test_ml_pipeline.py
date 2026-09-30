import uuid
from datetime import datetime, timezone, timedelta
import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.domain.models.logs import NormalizedEvent
from app.domain.models.ml import MLAnomalyScore
from app.ml.pipeline import ml_pipeline
from app.ml.features import FEATURE_NAMES


@pytest.mark.asyncio
async def test_ml_pipeline_evaluates_and_persists(db_session: AsyncSession):
    """Verify ml_pipeline evaluates a normalized event and persists MLAnomalyScore to database."""
    event = NormalizedEvent(
        id=uuid.uuid4(),
        event_timestamp=datetime.now(timezone.utc),
        event_category="Identity",
        event_name="UserLoggedIn",
        principal_id="usr-test-pipeline-01",
        principal_name="normal.user@secplatform.local",
        caller_ip="198.51.100.20",
        geo_country="United States",
        action_status="Success",
    )
    db_session.add(event)
    await db_session.flush()

    # Evaluate with ML pipeline
    score_record = await ml_pipeline.evaluate_and_persist(event, db_session)
    assert score_record is not None
    assert score_record.event_id == event.id
    assert score_record.model_version == ml_pipeline.model_version
    assert 0.0 <= score_record.anomaly_score <= 100.0
    assert 0.5 <= score_record.confidence <= 1.0

    # Normal event should have low anomaly score
    assert score_record.anomaly_score < 60.0
    assert not score_record.is_anomalous

    # Verify queryable from DB
    q = select(MLAnomalyScore).where(MLAnomalyScore.id == score_record.id)
    db_record = (await db_session.execute(q)).scalar_one_or_none()
    assert db_record is not None
    assert db_record.event_id == event.id


@pytest.mark.asyncio
async def test_ml_pipeline_flags_attack_behavior(db_session: AsyncSession):
    """Verify ml_pipeline produces elevated anomaly score and explanation reasons for an attack sequence."""
    attacker_ip = "203.0.113.199"
    target_spn = "spn-compromised-pipeline"
    now = datetime.now(timezone.utc)

    # Simulate attack sequence: 10 secret downloads in rapid succession from unfamiliar IP
    events = []
    for i in range(10):
        ev = NormalizedEvent(
            id=uuid.uuid4(),
            event_timestamp=now + timedelta(seconds=i * 2),
            event_category="Storage",
            event_name="Microsoft.KeyVault/vaults/secrets/getSecret/action",
            principal_id=target_spn,
            principal_name="spn-compromised-svc",
            caller_ip=attacker_ip,
            target_resource_id=f"/subscriptions/sub-1/vaults/kv-core/secrets/sec-{i}",
            target_resource_name=f"sec-{i}",
            geo_country="Netherlands",
            action_status="Success",
        )
        db_session.add(ev)
        events.append(ev)
    await db_session.flush()

    # Evaluate the final event with the preceding sequence as history
    last_event = events[-1]
    score_record = await ml_pipeline.evaluate_and_persist(
        last_event, db_session, custom_history=events
    )

    assert score_record is not None
    assert score_record.anomaly_score >= 60.0  # Elevated anomaly score
    assert score_record.is_anomalous

    # Verify explanation reasons
    contributions = score_record.feature_contributions
    assert "reasons" in contributions
    assert len(contributions["reasons"]) > 0
    reasons_text = " ".join(contributions["reasons"]).lower()
    assert "secret" in reasons_text or "resource" in reasons_text or "novel" in reasons_text


@pytest.mark.asyncio
async def test_ml_api_endpoints(client: AsyncClient, db_session: AsyncSession):
    """Verify GET /api/v1/ml/anomalies and GET /api/v1/ml/metrics endpoints."""
    # 1. Ingest an event to generate an anomaly record
    event = NormalizedEvent(
        id=uuid.uuid4(),
        event_timestamp=datetime.now(timezone.utc),
        event_category="Identity",
        event_name="UserLoginFailed",
        principal_id="usr-api-eval-01",
        principal_name="eval.user@secplatform.local",
        caller_ip="198.51.100.99",
        geo_country="China",
        action_status="Failure",
    )
    db_session.add(event)
    await db_session.flush()

    ml_record = await ml_pipeline.evaluate_and_persist(event, db_session)
    await db_session.commit()

    # 2. Query /api/v1/ml/anomalies
    res = await client.get("/api/v1/ml/anomalies?limit=10")
    assert res.status_code == 200
    data = res.json()
    assert "items" in data
    assert "total" in data
    assert data["total"] >= 1
    assert any(a["id"] == str(ml_record.id) for a in data["items"])

    # 3. Query /api/v1/ml/anomalies/{id}
    detail_res = await client.get(f"/api/v1/ml/anomalies/{ml_record.id}")
    assert detail_res.status_code == 200
    detail_data = detail_res.json()
    assert detail_data["id"] == str(ml_record.id)
    assert detail_data["model_version"] == ml_pipeline.model_version
    assert "reasons" in detail_data

    # 4. Query /api/v1/ml/metrics
    metrics_res = await client.get("/api/v1/ml/metrics")
    assert metrics_res.status_code == 200
    metrics_data = metrics_res.json()
    assert "total_anomalies" in metrics_data
    assert "high_risk_anomalies" in metrics_data
    assert "anomalous_principals" in metrics_data
    assert "avg_anomaly_score" in metrics_data
    assert metrics_data["model_version"] == ml_pipeline.model_version
    assert metrics_data["active_features_count"] == len(FEATURE_NAMES)
