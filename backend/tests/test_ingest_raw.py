import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_ingest_raw_valid_event(client: AsyncClient):
    """Test raw telemetry ingestion via POST /api/v1/ingest/raw."""
    payload = {
        "source": "AzureActivity",
        "event_category": "ResourceManagement",
        "event_name": "Microsoft.Compute/virtualMachines/write",
        "principal_id": "usr-test-999",
        "principal_name": "engineer@secplatform.local",
        "caller_ip": "198.51.100.55",
        "target_resource_id": "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Compute/virtualMachines/vm-test",
        "target_resource_name": "vm-test",
        "action_status": "Success",
        "geo_country": "United States",
        "user_agent": "AzurePortal/1.0",
        "metadata": {"environment": "staging"},
    }

    response = await client.post("/api/v1/ingest/raw", json=payload)
    assert response.status_code == 202
    data = response.json()
    assert data["status"] == "queued"
    assert "event_id" in data
    assert "timestamp" in data


@pytest.mark.asyncio
async def test_trigger_synthetic_scenario(client: AsyncClient):
    """Test triggering a synthetic attack scenario via POST /api/v1/ingest/synthetic/trigger."""
    payload = {
        "scenario_name": "keyvault_exfiltration",
        "custom_target_resource": "kv-secure-staging",
    }

    response = await client.post("/api/v1/ingest/synthetic/trigger", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["scenario_name"] == "keyvault_exfiltration"
    assert data["status"] == "generated"
    assert data["events_count"] >= 15
    assert len(data["events"]) == data["events_count"]
    assert "execution_id" in data
