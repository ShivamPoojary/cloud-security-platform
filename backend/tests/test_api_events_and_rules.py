import pytest
from httpx import AsyncClient
from app.core.seed import seed_data


@pytest.mark.asyncio
async def test_get_events_endpoint(client: AsyncClient):
    """Test GET /api/v1/events pagination and filtering."""
    # Ingest a sample event
    event_payload = {
        "source": "AzureActivity",
        "event_category": "ResourceManagement",
        "event_name": "Microsoft.Compute/virtualMachines/write",
        "principal_id": "usr-query-01",
        "principal_name": "query.tester@secplatform.local",
        "caller_ip": "198.51.100.33",
        "action_status": "Success",
        "metadata": {"test": True},
    }
    ingest_res = await client.post("/api/v1/ingest/raw", json=event_payload)
    assert ingest_res.status_code == 202

    # Query events
    res = await client.get("/api/v1/events?limit=10")
    assert res.status_code == 200
    data = res.json()
    assert "items" in data
    assert "total" in data
    assert data["total"] >= 1
    assert any(e["principal_name"] == "query.tester@secplatform.local" for e in data["items"])


@pytest.mark.asyncio
async def test_get_rules_and_toggle_endpoint(client: AsyncClient):
    """Test GET /api/v1/rules and PATCH /api/v1/rules/{rule_id}/toggle."""
    await seed_data()

    # 1. Fetch rules
    rules_res = await client.get("/api/v1/rules")
    assert rules_res.status_code == 200
    rules = rules_res.json()
    assert len(rules) >= 4

    target_rule = rules[0]
    initial_state = target_rule["is_active"]
    rule_code = target_rule["rule_id"]

    # 2. Toggle rule active state
    toggle_res = await client.patch(f"/api/v1/rules/{rule_code}/toggle")
    assert toggle_res.status_code == 200
    toggle_data = toggle_res.json()
    assert toggle_data["is_active"] == (not initial_state)

    # 3. Toggle back
    toggle_back_res = await client.patch(f"/api/v1/rules/{rule_code}/toggle")
    assert toggle_back_res.status_code == 200
    assert toggle_back_res.json()["is_active"] == initial_state


@pytest.mark.asyncio
async def test_get_detections_endpoint(client: AsyncClient):
    """Test GET /api/v1/detections endpoint."""
    await seed_data()

    # Trigger a scenario to generate detections
    await client.post(
        "/api/v1/ingest/synthetic/trigger",
        json={"scenario_name": "keyvault_exfiltration"},
    )

    det_res = await client.get("/api/v1/detections?limit=20")
    assert det_res.status_code == 200
    data = det_res.json()
    assert "items" in data
    assert "total" in data
    assert data["total"] >= 1
    assert len(data["items"]) >= 1
