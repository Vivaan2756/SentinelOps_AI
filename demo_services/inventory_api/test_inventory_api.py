"""Unit tests for Inventory Management API."""

import pytest
from fastapi.testclient import TestClient
from main import app, HTTP_REQUESTS_TOTAL, HTTP_5XX_ERRORS_TOTAL, HTTP_REQUEST_DURATION_SECONDS

client = TestClient(app)


def test_root_endpoint():
    """Verify GET / returns service identity and status."""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["service"] == "Inventory Management API"
    assert data["status"] == "running"
    assert data["version"] == "1.0.0"


def test_health_endpoint():
    """Verify GET /api/v1/health returns exact required structure."""
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data == {
        "status": "healthy",
        "service": "Inventory Management API",
    }


def test_health_alias_endpoint():
    """Verify GET /health compatibility alias functions."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["service"] == "Inventory Management API"


def test_metrics_endpoint():
    """Verify GET /metrics returns valid Prometheus text with required counters and histograms."""
    # First make a request to ensure telemetry has been recorded
    client.get("/api/v1/health")

    response = client.get("/metrics")
    assert response.status_code == 200
    text = response.text

    # Assert required Prometheus metric definitions exist
    assert "http_requests_total" in text
    assert "http_5xx_errors_total" in text
    assert "http_request_duration_seconds" in text

    # Verify Prometheus exposition format headers
    assert "# HELP http_requests_total" in text
    assert "# TYPE http_requests_total counter" in text
    assert "# HELP http_5xx_errors_total" in text
    assert "# TYPE http_5xx_errors_total counter" in text
    assert "# HELP http_request_duration_seconds" in text
    assert "# TYPE http_request_duration_seconds histogram" in text


def test_inventory_items_endpoints():
    """Verify inventory item query endpoints."""
    # List items
    list_resp = client.get("/api/v1/items")
    assert list_resp.status_code == 200
    items = list_resp.json()
    assert len(items) >= 3

    # Get specific item
    item_resp = client.get("/api/v1/items/inv_001")
    assert item_resp.status_code == 200
    item = item_resp.json()
    assert item["sku"] == "SKU-WIDGET-01"
    assert item["quantity"] == 150

    # Nonexistent item returns 404
    missing_resp = client.get("/api/v1/items/nonexistent_id")
    assert missing_resp.status_code == 404
