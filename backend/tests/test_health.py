import pytest
from httpx import AsyncClient
from backend.main import app

@pytest.mark.asyncio
async def test_health_endpoint():
  async with AsyncClient(app=app, base_url="http://test") as ac:
    resp = await ac.get("/api/health/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data.get("status") == "healthy"
