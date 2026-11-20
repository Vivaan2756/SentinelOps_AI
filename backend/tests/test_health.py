"""Health endpoint test suite."""

from fastapi.testclient import TestClient


def test_root_health_endpoint(client: TestClient):
    """Test GET /health returns 200 with service information and database status."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert "status" in data
    assert data["service"] == "SentinelOps AI"
    assert "version" in data
    assert "timestamp" in data
    assert "database" in data
    assert "connected" in data["database"]
    assert "message" in data["database"]


def test_v1_health_endpoint(client: TestClient):
    """Test GET /api/v1/health returns 200 with matching schema."""
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert "status" in data
    assert data["service"] == "SentinelOps AI"
    assert "version" in data
    assert "timestamp" in data
    assert "database" in data
    assert "connected" in data["database"]
    assert "message" in data["database"]
