import sys
import os
import pytest
from fastapi.testclient import TestClient

# Ensure order-api directory is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from service.main import app, demo_state


@pytest.fixture(autouse=True)
def reset_demo_state():
    """Ensure demo state is healthy before and after each test."""
    demo_state.restore_healthy()
    yield
    demo_state.restore_healthy()


@pytest.fixture
def client():
    """Provide TestClient for Order API."""
    return TestClient(app)


def test_order_api_healthy_baseline(client: TestClient):
    """Verify normal operation of health and orders endpoints."""
    # Health check
    res_health = client.get("/health")
    assert res_health.status_code == 200
    assert res_health.json()["status"] == "healthy"

    # Orders listing
    res_orders = client.get("/orders")
    assert res_orders.status_code == 200
    assert "orders" in res_orders.json()
    assert res_orders.json()["count"] >= 2

    # Order creation
    payload = {"customer_id": "test_user_42", "items_count": 3, "total_amount": 120.50}
    res_create = client.post("/orders", json=payload)
    assert res_create.status_code == 201
    assert res_create.json()["customer_id"] == "test_user_42"


def test_order_api_deterministic_failure_and_recovery(client: TestClient):
    """Verify deterministic failure mode injection and safe restoration."""
    # 1. Initially healthy
    assert client.get("/health").status_code == 200

    # 2. Inject failure
    res_fail = client.post("/demo/simulate-failure?reason=Simulated+DB+pool+timeout")
    assert res_fail.status_code == 200
    assert res_fail.json()["failure_active"] is True

    # 3. Operations fail with HTTP 500
    health_500 = client.get("/health")
    assert health_500.status_code == 500
    assert health_500.json()["status"] == "unhealthy"

    orders_500 = client.get("/orders")
    assert orders_500.status_code == 500

    create_500 = client.post("/orders", json={"customer_id": "fail_user", "items_count": 1, "total_amount": 10.0})
    assert create_500.status_code == 500

    # 4. Safe recovery
    res_restore = client.post("/demo/restore")
    assert res_restore.status_code == 200
    assert res_restore.json()["failure_active"] is False

    # 5. Operations restored to normal
    assert client.get("/health").status_code == 200
    assert client.get("/orders").status_code == 200


def test_order_api_metrics_endpoint_and_telemetry(client: TestClient):
    """Verify Prometheus metrics exposition and telemetry counters."""
    # Hit healthy endpoint
    client.get("/health")
    client.get("/orders")

    metrics_res = client.get("/metrics")
    assert metrics_res.status_code == 200
    content = metrics_res.text
    assert "order_api_http_requests_total" in content
    assert "order_api_http_request_duration_seconds" in content

    # Trigger failure and verify 5xx metrics recorded
    client.post("/demo/simulate-failure?reason=Timeout+error")
    client.get("/orders")  # produces 500

    metrics_res_after = client.get("/metrics")
    content_after = metrics_res_after.text
    assert "order_api_http_5xx_errors_total" in content_after
    assert 'status_code="500"' in content_after


def test_order_api_repeated_recovery_is_graceful(client: TestClient):
    """Verify that calling /demo/restore repeatedly handles already healthy states gracefully."""
    # 1. First inject failure
    client.post("/demo/simulate-failure")
    assert client.get("/health").status_code == 500

    # 2. First recovery restores service
    res1 = client.post("/demo/restore")
    assert res1.status_code == 200
    assert res1.json()["status"] == "restored"
    assert res1.json()["failure_active"] is False
    assert client.get("/health").status_code == 200

    # 3. Second recovery on already-healthy service returns 200 OK with already_healthy status
    res2 = client.post("/demo/restore")
    assert res2.status_code == 200
    assert res2.json()["status"] == "already_healthy"
    assert res2.json()["failure_active"] is False
    assert client.get("/health").status_code == 200


def test_order_api_secret_token_authentication(client: TestClient, monkeypatch):
    """Verify secret token authentication on demo control endpoints when configured."""
    test_token = "secret-render-token-xyz123"
    monkeypatch.setenv("DEMO_ADMIN_TOKEN", test_token)

    # 1. Public health check remains completely accessible without auth
    health_res = client.get("/health")
    assert health_res.status_code == 200
    assert health_res.json()["status"] == "healthy"

    # 2. Unauthenticated failure injection is rejected with 401
    fail_no_auth = client.post("/demo/simulate-failure")
    assert fail_no_auth.status_code == 401
    assert "Unauthorized" in fail_no_auth.json()["detail"]

    # 3. Invalid token failure injection is rejected with 401
    fail_bad_auth = client.post("/demo/simulate-failure", headers={"X-Demo-Token": "wrong-token"})
    assert fail_bad_auth.status_code == 401

    # 4. Valid token via X-Demo-Token header succeeds
    fail_ok_header = client.post(
        "/demo/simulate-failure",
        headers={"X-Demo-Token": test_token},
        params={"reason": "Testing header auth"},
    )
    assert fail_ok_header.status_code == 200
    assert fail_ok_header.json()["failure_active"] is True
    assert client.get("/health").status_code == 500

    # 5. Unauthenticated restore is rejected with 401
    restore_no_auth = client.post("/demo/restore")
    assert restore_no_auth.status_code == 401

    # 6. Valid token via Authorization Bearer header succeeds
    restore_bearer = client.post(
        "/demo/restore",
        headers={"Authorization": f"Bearer {test_token}"},
    )
    assert restore_bearer.status_code == 200
    assert restore_bearer.json()["failure_active"] is False
    assert client.get("/health").status_code == 200

    # 7. Valid token via query parameter (?token=...)
    client.post("/demo/simulate-failure", params={"token": test_token})
    assert client.get("/health").status_code == 500

    restore_query = client.post("/demo/restore", params={"token": test_token})
    assert restore_query.status_code == 200
    assert restore_query.json()["failure_active"] is False
    assert client.get("/health").status_code == 200

    # 8. Valid token via JSON body ({"token": ...})
    client.post("/demo/simulate-failure", json={"token": test_token, "reason": "Body test"})
    assert client.get("/health").status_code == 500

    restore_body = client.post("/demo/restore", json={"token": test_token})
    assert restore_body.status_code == 200
    assert restore_body.json()["failure_active"] is False
    assert client.get("/health").status_code == 200

    # 9. Valid token via path parameter (/demo/restore/{path_token})
    client.post("/demo/simulate-failure", headers={"X-Demo-Token": test_token})
    assert client.get("/health").status_code == 500

    restore_path = client.post(f"/demo/restore/{test_token}")
    assert restore_path.status_code == 200
    assert restore_path.json()["failure_active"] is False
    assert client.get("/health").status_code == 200
