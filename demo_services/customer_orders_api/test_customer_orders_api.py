"""Unit and Integration Tests for Customer Orders API.

Validates:
1. Root identity endpoint returns service details.
2. Healthy health endpoint returns HTTP 200.
3. Failure injection via POST /demo/simulate-failure returns success.
4. Subsequent GET /health returns HTTP 503 Service Unavailable.
5. GET /demo/status accurately reflects failure state and error count.
6. Recovery reset via POST /admin/recovery/reset restores HTTP 200.
7. Metrics endpoint GET /metrics exposes valid Prometheus text format metrics:
   - http_requests_total
   - http_5xx_errors_total
   - http_request_duration_seconds
8. Normal business domain endpoints (/api/v1/orders, /orders) operate as expected.
"""

import pytest
from fastapi.testclient import TestClient

from main import app, reset_failure_state


@pytest.fixture(autouse=True)
def clean_state():
    """Ensure in-memory failure state is clean before and after every test."""
    reset_failure_state()
    yield
    reset_failure_state()


@pytest.fixture
def client():
    """FastAPI TestClient fixture."""
    return TestClient(app)


# -------------------------------------------------------------------
# 1. Root & Health Check Tests
# -------------------------------------------------------------------

def test_root_endpoint(client: TestClient):
    """GET / returns service identity and API information."""
    resp = client.get("/")
    assert resp.status_code == 200
    data = resp.json()
    assert data["service"] == "Customer Orders API"
    assert data["version"] == "1.0.0"
    assert data["status"] == "running"
    assert data["operational_status"] == "operational"
    assert "endpoints" in data
    assert data["endpoints"]["health"] == "/health"
    assert data["endpoints"]["simulate_failure"] == "POST /demo/simulate-failure"
    assert data["endpoints"]["recovery_reset"] == "POST /admin/recovery/reset"


def test_health_endpoint_healthy(client: TestClient):
    """GET /health returns HTTP 200 with operational status when healthy."""
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "healthy"
    assert data["service"] == "Customer Orders API"
    assert data["operational_status"] == "operational"
    assert data["failure_active"] is False
    assert "timestamp" in data

    # Verify alias /api/v1/health also returns HTTP 200
    alias_resp = client.get("/api/v1/health")
    assert alias_resp.status_code == 200
    assert alias_resp.json()["status"] == "healthy"


# -------------------------------------------------------------------
# 2. Failure Injection & Recovery Tests
# -------------------------------------------------------------------

def test_simulate_failure_and_health_503(client: TestClient):
    """Failure injection causes /health to deterministically return HTTP 503."""
    # 1. Initially healthy
    assert client.get("/health").status_code == 200

    # 2. Inject failure
    payload = {"reason": "Database connection pool timeout under load"}
    inject_resp = client.post("/demo/simulate-failure", json=payload)
    assert inject_resp.status_code == 200
    inject_data = inject_resp.json()
    assert inject_data["success"] is True
    assert inject_data["failure_active"] is True
    assert inject_data["failure_reason"] == "Database connection pool timeout under load"

    # 3. /health must now return 503
    health_resp = client.get("/health")
    assert health_resp.status_code == 503
    health_data = health_resp.json()
    assert health_data["status"] == "unhealthy"
    assert health_data["service"] == "Customer Orders API"
    assert health_data["operational_status"] == "degraded"
    assert health_data["failure_active"] is True
    assert health_data["failure_reason"] == "Database connection pool timeout under load"
    assert health_data["error_count"] == 1

    # Second failure probe increments error count
    health_resp2 = client.get("/health")
    assert health_resp2.status_code == 503
    assert health_resp2.json()["error_count"] == 2


def test_demo_status_endpoint(client: TestClient):
    """GET /demo/status returns complete simulation state without altering it."""
    # 1. Healthy status
    status_resp = client.get("/demo/status")
    assert status_resp.status_code == 200
    data = status_resp.json()
    assert data["service"] == "Customer Orders API"
    assert data["failure_active"] is False
    assert data["failure_reason"] is None
    assert data["operational_status"] == "operational"
    assert data["error_count"] == 0

    # 2. Inject failure
    client.post("/demo/simulate-failure", json={"reason": "Disk I/O failure"})

    # 3. Failed status
    status_resp2 = client.get("/demo/status")
    assert status_resp2.status_code == 200
    data2 = status_resp2.json()
    assert data2["failure_active"] is True
    assert data2["failure_reason"] == "Disk I/O failure"
    assert data2["operational_status"] == "degraded"


def test_recovery_reset(client: TestClient):
    """POST /admin/recovery/reset restores the service to operational HTTP 200."""
    # 1. Inject failure
    client.post("/demo/simulate-failure", json={"reason": "Memory leak"})
    assert client.get("/health").status_code == 503

    # 2. Reset via recovery endpoint
    reset_resp = client.post("/admin/recovery/reset")
    assert reset_resp.status_code == 200
    reset_data = reset_resp.json()
    assert reset_data["success"] is True
    assert reset_data["failure_active"] is False
    assert reset_data["operational_status"] == "operational"

    # 3. Verify health endpoint immediately restores to HTTP 200
    health_resp = client.get("/health")
    assert health_resp.status_code == 200
    health_data = health_resp.json()
    assert health_data["status"] == "healthy"
    assert health_data["operational_status"] == "operational"
    assert health_data["failure_active"] is False

    # 4. Status endpoint reflects healthy state
    status_resp = client.get("/demo/status")
    assert status_resp.json()["failure_active"] is False


# -------------------------------------------------------------------
# 3. Prometheus Telemetry Tests
# -------------------------------------------------------------------

def test_metrics_endpoint(client: TestClient):
    """GET /metrics returns valid Prometheus exposition text format."""
    # Generate some traffic and an error
    client.get("/health")
    client.post("/demo/simulate-failure", json={"reason": "Telemetry check"})
    client.get("/health")  # Triggers 503
    client.post("/admin/recovery/reset")
    client.get("/api/v1/orders")

    # Scrape metrics
    metrics_resp = client.get("/metrics")
    assert metrics_resp.status_code == 200
    assert "text/plain" in metrics_resp.headers["content-type"]
    text = metrics_resp.text

    # Verify required metric names
    assert "http_requests_total" in text
    assert "http_5xx_errors_total" in text
    assert "http_request_duration_seconds" in text

    # Verify Prometheus format header conventions
    assert "# HELP http_requests_total" in text
    assert "# TYPE http_requests_total counter" in text
    assert "# HELP http_5xx_errors_total" in text
    assert "# TYPE http_5xx_errors_total counter" in text
    assert "# HELP http_request_duration_seconds" in text
    assert "# TYPE http_request_duration_seconds histogram" in text

    # Verify 5xx errors were recorded
    assert 'http_5xx_errors_total{endpoint="/health",method="GET"}' in text


# -------------------------------------------------------------------
# 4. Business Domain API Tests
# -------------------------------------------------------------------

def test_normal_api_requests(client: TestClient):
    """Normal customer order endpoints function as expected."""
    # List orders
    list_resp = client.get("/api/v1/orders")
    assert list_resp.status_code == 200
    orders = list_resp.json()
    assert isinstance(orders, list)
    assert len(orders) >= 3
    assert orders[0]["id"] == "ord-001"
    assert orders[0]["customer_name"] == "Acme Industries"

    # Specific order lookup
    detail_resp = client.get("/api/v1/orders/ord-001")
    assert detail_resp.status_code == 200
    detail = detail_resp.json()
    assert detail["id"] == "ord-001"
    assert detail["total_usd"] == 349.50

    # Nonexistent order lookup returns 404
    missing_resp = client.get("/api/v1/orders/ord-999")
    assert missing_resp.status_code == 404
    assert "not found" in missing_resp.json()["detail"].lower()
