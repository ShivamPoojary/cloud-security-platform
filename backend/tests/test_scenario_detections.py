import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.seed import seed_data
from app.domain.models.detections import ThreatDetection
from app.detection.window import window_tracker


@pytest.fixture(autouse=True)
def reset_window():
    """Clears sliding window state between scenario runs."""
    window_tracker.clear()
    yield
    window_tracker.clear()


@pytest.mark.asyncio
async def test_scenario_credential_compromise_detections(client: AsyncClient, db_session: AsyncSession):
    """End-to-End: Scenario 1 triggers Brute Force, MFA Fatigue, and Role Assignment detections."""
    await seed_data()

    response = await client.post(
        "/api/v1/ingest/synthetic/trigger",
        json={"scenario_name": "credential_compromise"},
    )
    assert response.status_code == 200

    # Query all created detections
    result = await db_session.execute(
        select(ThreatDetection).options(selectinload(ThreatDetection.rule))
    )
    detections = result.scalars().all()
    triggered_rules = {d.rule.rule_id for d in detections if d.rule}

    assert "AZ-RULE-0010" in triggered_rules, "Missing Brute Force detection (AZ-RULE-0010)"
    assert "AZ-RULE-0012" in triggered_rules, "Missing MFA Fatigue detection (AZ-RULE-0012)"
    assert "AZ-RULE-0025" in triggered_rules, "Missing Role Assignment detection (AZ-RULE-0025)"


@pytest.mark.asyncio
async def test_scenario_keyvault_exfiltration_detections(client: AsyncClient, db_session: AsyncSession):
    """End-to-End: Scenario 2 triggers Vault Discovery and Bulk Secret Retrieval detections."""
    await seed_data()

    response = await client.post(
        "/api/v1/ingest/synthetic/trigger",
        json={"scenario_name": "keyvault_exfiltration", "custom_target_resource": "kv-prod-db"},
    )
    assert response.status_code == 200

    result = await db_session.execute(
        select(ThreatDetection).options(selectinload(ThreatDetection.rule))
    )
    detections = result.scalars().all()
    triggered_rules = {d.rule.rule_id for d in detections if d.rule}

    assert "AZ-RULE-0040" in triggered_rules, "Missing Key Vault Discovery detection (AZ-RULE-0040)"
    assert "AZ-RULE-0042" in triggered_rules, "Missing Mass Secret Retrieval detection (AZ-RULE-0042)"


@pytest.mark.asyncio
async def test_scenario_ransomware_detections(client: AsyncClient, db_session: AsyncSession):
    """End-to-End: Scenario 3 triggers Defender Disabled and Mass Container Deletion detections."""
    await seed_data()

    response = await client.post(
        "/api/v1/ingest/synthetic/trigger",
        json={"scenario_name": "ransomware"},
    )
    assert response.status_code == 200

    result = await db_session.execute(
        select(ThreatDetection).options(selectinload(ThreatDetection.rule))
    )
    detections = result.scalars().all()
    triggered_rules = {d.rule.rule_id for d in detections if d.rule}

    assert "AZ-RULE-0080" in triggered_rules, "Missing Defender Disabled detection (AZ-RULE-0080)"
    assert "AZ-RULE-0085" in triggered_rules, "Missing Mass Container Deletion detection (AZ-RULE-0085)"
