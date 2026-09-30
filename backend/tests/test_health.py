import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_root_health_endpoint(client: AsyncClient):
    """Test 1: GET /health must return status ok and service name."""
    response = await client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["service"] == "cloud-security-platform"


@pytest.mark.asyncio
async def test_api_v1_health_endpoint(client: AsyncClient):
    """Test 2: GET /api/v1/health must return detailed component status."""
    response = await client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["service"] == "cloud-security-platform"
    assert "version" in data
    assert "database" in data
    assert "redis" in data
