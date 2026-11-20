import sys
import os
import pytest
from fastapi.testclient import TestClient

# Ensure order-api directory is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from service.main import app, demo_state


DEFAULT_TEST_TOKEN = "test-order-api-token-2026"


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


@pytest.fixture
def auth_env(monkeypatch):
    """Configure DEMO_ADMIN_TOKEN environment variable for testing."""
    monkeypatch.setenv("DEMO_ADMIN_TOKEN", DEFAULT_TEST_TOKEN)
    return DEFAULT_TEST_TOKEN


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


def test_order_api_deterministic_failure_and_recovery(client: TestClient, auth_env: str):
    """Verify deterministic failure mode injection and safe restoration with authentication."""
    headers = {"X-Demo-Token": auth_env}

    # 1. Initially healthy
    assert client.get("/health").status_code == 200

    # 2. Inject failure
    res_fail = client.post(
        "/demo/simulate-failure?reason=Simulated+DB+pool+timeout",
        headers=headers,
    )
    assert res_fail.status_code == 200
    assert res_fail.json()["failure_active"] is True

    # 3. Operations fail with HTTP 500
    health_500 = client.get("/health")
    assert health_500.status_code == 500
    assert health_500.json()["status"] == "unhealthy"

    orders_500 = client.get("/orders")
    assert orders_500.status_code == 500

    create_500 = client.post(
        "/orders",
        json={"customer_id": "fail_user", "items_count": 1, "total_amount": 10.0},
    )
    assert create_500.status_code == 500

    # 4. Safe recovery
    res_restore = client.post("/demo/restore", headers=headers)
    assert res_restore.status_code == 200
    assert res_restore.json()["failure_active"] is False
    assert res_restore.json()["status"] == "restored"

    # 5. Operations restored to normal
    assert client.get("/health").status_code == 200
    assert client.get("/orders").status_code == 200


def test_order_api_metrics_endpoint_and_telemetry(client: TestClient, auth_env: str):
    """Verify Prometheus metrics exposition and telemetry counters."""
    headers = {"X-Demo-Token": auth_env}

    # Hit healthy endpoint
    client.get("/health")
    client.get("/orders")

    metrics_res = client.get("/metrics")
    assert metrics_res.status_code == 200
    content = metrics_res.text
    assert "order_api_http_requests_total" in content
    assert "order_api_http_request_duration_seconds" in content

    # Trigger failure and verify 5xx metrics recorded
    client.post(
        "/demo/simulate-failure?reason=Timeout+error",
        headers=headers,
    )
    client.get("/orders")  # produces 500

    metrics_res_after = client.get("/metrics")
    content_after = metrics_res_after.text
    assert "order_api_http_5xx_errors_total" in content_after
    assert 'status_code="500"' in content_after


def test_order_api_repeated_recovery_is_graceful(client: TestClient, auth_env: str):
    """Verify that calling /demo/restore repeatedly handles already healthy states gracefully."""
    headers = {"X-Demo-Token": auth_env}

    # 1. First inject failure
    client.post("/demo/simulate-failure", headers=headers)
    assert client.get("/health").status_code == 500

    # 2. First recovery restores service
    res1 = client.post("/demo/restore", headers=headers)
    assert res1.status_code == 200
    assert res1.json()["status"] == "restored"
    assert res1.json()["failure_active"] is False
    assert client.get("/health").status_code == 200

    # 3. Second recovery on already-healthy service returns 200 OK with already_healthy status
    res2 = client.post("/demo/restore", headers=headers)
    assert res2.status_code == 200
    assert res2.json()["status"] == "already_healthy"
    assert res2.json()["failure_active"] is False
    assert client.get("/health").status_code == 200


def test_order_api_missing_configured_token_denies_demo_control(client: TestClient, monkeypatch):
    """Verify fail-closed behavior: missing DEMO_ADMIN_TOKEN denies demo control endpoints."""
    monkeypatch.delenv("DEMO_ADMIN_TOKEN", raising=False)
    monkeypatch.delenv("ORDER_API_SECRET_TOKEN", raising=False)

    # Both simulate-failure and restore must return 401
    res_fail = client.post("/demo/simulate-failure", headers={"X-Demo-Token": "any-token"})
    assert res_fail.status_code == 401
    assert "disabled" in res_fail.json()["detail"].lower()

    res_restore = client.post("/demo/restore", headers={"X-Demo-Token": "any-token"})
    assert res_restore.status_code == 401
    assert "disabled" in res_restore.json()["detail"].lower()


def test_order_api_missing_request_token_denies_demo_control(client: TestClient, auth_env: str):
    """Verify that requests missing credentials header are rejected with 401."""
    res_fail = client.post("/demo/simulate-failure")
    assert res_fail.status_code == 401
    assert "missing" in res_fail.json()["detail"].lower()

    res_restore = client.post("/demo/restore")
    assert res_restore.status_code == 401
    assert "missing" in res_restore.json()["detail"].lower()


def test_order_api_incorrect_token_denies_demo_control(client: TestClient, auth_env: str):
    """Verify that incorrect credentials are rejected with 401."""
    res_fail = client.post("/demo/simulate-failure", headers={"X-Demo-Token": "wrong-secret-token"})
    assert res_fail.status_code == 401
    assert "invalid" in res_fail.json()["detail"].lower()

    res_restore = client.post("/demo/restore", headers={"Authorization": "Bearer wrong-secret-token"})
    assert res_restore.status_code == 401
    assert "invalid" in res_restore.json()["detail"].lower()


def test_order_api_header_authentication_succeeds(client: TestClient, auth_env: str):
    """Verify that both X-Demo-Token and Bearer Authorization headers succeed."""
    # 1. X-Demo-Token succeeds
    res_fail = client.post("/demo/simulate-failure", headers={"X-Demo-Token": auth_env})
    assert res_fail.status_code == 200
    assert res_fail.json()["failure_active"] is True
    assert client.get("/health").status_code == 500

    # 2. Authorization: Bearer <token> succeeds
    res_restore = client.post("/demo/restore", headers={"Authorization": f"Bearer {auth_env}"})
    assert res_restore.status_code == 200
    assert res_restore.json()["failure_active"] is False
    assert client.get("/health").status_code == 200


def test_order_api_query_string_token_cannot_authorize(client: TestClient, auth_env: str):
    """Verify query-string token parameters cannot authorize demo actions."""
    res_fail = client.post(f"/demo/simulate-failure?token={auth_env}")
    assert res_fail.status_code == 401

    res_restore = client.post(f"/demo/restore?token={auth_env}")
    assert res_restore.status_code == 401


def test_order_api_body_token_cannot_authorize(client: TestClient, auth_env: str):
    """Verify JSON body token parameters cannot authorize demo actions."""
    res_fail = client.post(
        "/demo/simulate-failure",
        json={"token": auth_env, "reason": "Attack with body token"},
    )
    assert res_fail.status_code == 401

    res_restore = client.post(
        "/demo/restore",
        json={"token": auth_env},
    )
    assert res_restore.status_code == 401


def test_order_api_path_token_cannot_authorize(client: TestClient, auth_env: str):
    """Verify path-token alias is disabled / cannot authorize."""
    res = client.post(f"/demo/restore/{auth_env}")
    # Endpoint was removed / not matched -> 404
    assert res.status_code == 404


def test_order_api_public_endpoints_accessible_without_admin_auth(client: TestClient, auth_env: str):
    """Verify public endpoints remain accessible without admin authentication."""
    # /live
    l_res = client.get("/live")
    assert l_res.status_code == 200
    assert l_res.json()["status"] == "alive"
    assert l_res.json()["service"] == "order-api"
    assert "timestamp" in l_res.json()

    # /health
    h_res = client.get("/health")
    assert h_res.status_code == 200
    assert h_res.json()["status"] == "healthy"

    # /metrics
    m_res = client.get("/metrics")
    assert m_res.status_code == 200

    # /orders
    o_res = client.get("/orders")
    assert o_res.status_code == 200

    # /demo/status
    s_res = client.get("/demo/status")
    assert s_res.status_code == 200
    assert s_res.json()["failure_active"] is False


def test_order_api_liveness_remains_healthy_during_simulated_failure(client: TestClient, auth_env: str):
    """
    Verify platform liveness check (/live) remains HTTP 200 during failure simulation,
    preventing platform (Render) container restarts while /health returns HTTP 500.
    """
    # 1. Healthy baseline: /live returns HTTP 200
    res_live_init = client.get("/live")
    assert res_live_init.status_code == 200
    assert res_live_init.json()["status"] == "alive"
    assert res_live_init.json()["service"] == "order-api"
    assert "timestamp" in res_live_init.json()

    # 2. Inject failure
    headers = {"X-Demo-Token": auth_env}
    res_fail = client.post("/demo/simulate-failure", headers=headers)
    assert res_fail.status_code == 200
    assert res_fail.json()["failure_active"] is True

    # 3. Assert /health returns HTTP 500 (unhealthy application)
    res_health = client.get("/health")
    assert res_health.status_code == 500
    assert res_health.json()["status"] == "unhealthy"

    # 4. Assert /live STILL returns HTTP 200 (platform container remains alive)
    res_live_during_failure = client.get("/live")
    assert res_live_during_failure.status_code == 200
    assert res_live_during_failure.json()["status"] == "alive"
    assert res_live_during_failure.json()["service"] == "order-api"
    assert "timestamp" in res_live_during_failure.json()

    # 5. Restore healthy
    res_restore = client.post("/demo/restore", headers=headers)
    assert res_restore.status_code == 200

    # 6. Both /health and /live are HTTP 200
    assert client.get("/health").status_code == 200
    assert client.get("/live").status_code == 200
