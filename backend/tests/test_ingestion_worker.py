import json
import uuid
from datetime import datetime, timezone
import pytest
from sqlalchemy.ext.asyncio import AsyncSession
from app.workers.ingestion_worker import IngestionWorker
from app.domain.models.logs import NormalizedEvent
from app.domain.models.rules import DetectionRule


@pytest.mark.asyncio
async def test_worker_process_valid_payload(db_session: AsyncSession):
    """Test worker parses valid payload, normalizes, persists, and runs detection."""
    worker = IngestionWorker(consumer_name="test-worker-01")

    # Seed a simple detection rule
    rule = DetectionRule(
        id=uuid.uuid4(),
        rule_id="WORKER-TEST-001",
        title="Worker Test Event",
        severity="MEDIUM",
        mitre_tactic="Discovery",
        mitre_technique_id="T1087",
        description="Test rule",
        rule_logic={"type": "stateless_pattern", "filter": {"event_name": "TestDiscovery"}},
        is_active=True,
    )
    db_session.add(rule)
    await db_session.commit()

    event_id = uuid.uuid4()
    payload = {
        "event_id": str(event_id),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": "AzureActivity",
        "event_category": "ResourceManagement",
        "event_name": "TestDiscovery",
        "principal_id": "usr-worker-01",
        "principal_name": "worker.test@secplatform.local",
        "caller_ip": "198.51.100.44",
        "action_status": "Success",
        "metadata": {"test_run": True},
    }

    norm_event, detections = await worker.process_single_payload(json.dumps(payload), db_session)

    assert norm_event is not None
    assert norm_event.id == event_id
    assert norm_event.event_name == "TestDiscovery"
    assert len(detections) == 1
    assert detections[0].rule_id == rule.id
    assert worker.processed_count == 1
    assert worker.error_count == 0


@pytest.mark.asyncio
async def test_worker_handles_malformed_json(db_session: AsyncSession):
    """Test worker handles corrupted JSON without raising unhandled exceptions."""
    worker = IngestionWorker(consumer_name="test-worker-02")
    bad_payload = "NOT_VALID_JSON{:::broken"

    norm_event, detections = await worker.process_single_payload(bad_payload, db_session)

    assert norm_event is None
    assert len(detections) == 0
    assert worker.error_count == 1


@pytest.mark.asyncio
async def test_worker_handles_missing_required_schema_fields(db_session: AsyncSession):
    """Test worker handles JSON missing mandatory security schema fields."""
    worker = IngestionWorker(consumer_name="test-worker-03")
    incomplete_payload = json.dumps({"arbitrary_field": "val"})

    norm_event, detections = await worker.process_single_payload(incomplete_payload, db_session)

    assert norm_event is None
    assert len(detections) == 0
    assert worker.error_count == 1


@pytest.mark.asyncio
async def test_worker_stream_batch_with_mock_redis(db_session: AsyncSession):
    """Test worker reading stream batch using a mock Redis interface."""
    worker = IngestionWorker(consumer_name="test-worker-04")

    # Mock Redis client
    test_event = {
        "event_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": "SignInLogs",
        "event_category": "Identity",
        "event_name": "MockWorkerLogin",
        "action_status": "Success",
    }
    payload_str = json.dumps(test_event)

    class MockRedis:
        async def xreadgroup(self, **kwargs):
            return [
                (
                    "secplatform:events_stream",
                    [("1710000000000-0", {"payload": payload_str})],
                )
            ]

        async def xack(self, stream, group, msg_id):
            return 1

    mock_redis = MockRedis()
    processed = await worker.process_stream_batch(mock_redis, batch_size=5)
    assert processed == 1


def test_worker_stop_signal():
    """Test worker stop signal toggles running flag."""
    worker = IngestionWorker(consumer_name="test-worker-05")
    worker.is_running = True
    worker.stop()
    assert worker.is_running is False
