"""Service API endpoints and validation test suite."""

import uuid
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from app.models.workspace import Workspace


def test_service_registration_and_validation(client: TestClient, db_session: Session, auth_context):
    """Test service registration validation, authorization, and workspace scoping."""
    workspace = auth_context["workspace"]
    headers = auth_context["headers"]

    # 1. Invalid URL scheme should fail validation
    invalid_payload = {
        "workspace_id": workspace.id,
        "name": "Order Service",
        "environment": "development",
        "health_check_url": "ftp://bad-scheme.com/health",
        "monitoring_method": "prometheus",
        "execution_policy": "demo",
    }
    res = client.post("/api/v1/services", json=invalid_payload, headers=headers)
    assert res.status_code == 422

    # 2. Valid payload succeeds (without network probing)
    valid_payload = {
        "workspace_id": workspace.id,
        "name": "Order Service",
        "environment": "development",
        "health_check_url": "http://127.0.0.1:8001/health",
        "monitoring_method": "prometheus",
        "execution_policy": "demo",
    }
    res = client.post("/api/v1/services", json=valid_payload, headers=headers)
    assert res.status_code == 201
    data = res.json()
    assert data["name"] == "Order Service"
    assert data["workspace_id"] == workspace.id
    assert data["is_active"] is True
    assert data["health_status"] == "unknown"

    # 3. Duplicate name in same workspace rejected
    res_dup = client.post("/api/v1/services", json=valid_payload, headers=headers)
    assert res_dup.status_code == 409

    # 4. List services scoped to workspace
    res_list = client.get(f"/api/v1/services?workspace_id={workspace.id}", headers=headers)
    assert res_list.status_code == 200
    services = res_list.json()
    assert len(services) == 1
    assert services[0]["name"] == "Order Service"

    # 5. Service detail view
    service_id = data["id"]
    res_detail = client.get(f"/api/v1/services/{service_id}?workspace_id={workspace.id}", headers=headers)
    assert res_detail.status_code == 200
    detail_data = res_detail.json()
    assert detail_data["service"]["id"] == service_id
    assert "recent_incidents" in detail_data

    # 6. Service capability discovery endpoint for generic service
    # Stage 3.3 Invariant: Generic service named "Order Service" receives only universal capabilities (2)
    res_caps = client.get(f"/api/v1/services/{service_id}/capabilities?workspace_id={workspace.id}", headers=headers)
    assert res_caps.status_code == 200
    caps_data = res_caps.json()
    assert caps_data["service_id"] == service_id
    assert caps_data["total_count"] == 8
    assert caps_data["compatible_count"] == 2
    assert caps_data["executable_count"] == 2
    assert len(caps_data["capabilities"]) == 8
    # Explicitly verify demo recovery is strictly incompatible for generic service
    cap_dict = {c["action_id"]: c for c in caps_data["capabilities"]}
    assert cap_dict["restore_order_api_demo"]["is_compatible"] is False

    # 7. Authorized demo service provisioning yields full demo capabilities (4)
    demo_payload = {
        "workspace_id": workspace.id,
        "name": "Order API Live Demo",
        "health_check_url": "http://127.0.0.1:8001/health",
        "environment": "development",
        "monitoring_method": "prometheus",
        "execution_policy": "demo",
        "demo_integration": "order_api",
    }
    res_demo = client.post("/api/v1/services/provision-demo", json=demo_payload, headers=headers)
    assert res_demo.status_code == 201
    demo_service_id = res_demo.json()["id"]

    res_demo_caps = client.get(f"/api/v1/services/{demo_service_id}/capabilities?workspace_id={workspace.id}", headers=headers)
    assert res_demo_caps.status_code == 200
    demo_caps_data = res_demo_caps.json()
    assert demo_caps_data["compatible_count"] == 4
    assert demo_caps_data["executable_count"] == 4

    # 8. Cross-workspace capability request fails closed with 404
    other_ws_id = str(uuid.uuid4())
    res_cross = client.get(f"/api/v1/services/{service_id}/capabilities?workspace_id={other_ws_id}", headers=headers)
    assert res_cross.status_code == 404


def test_unauthorized_service_access(client: TestClient, db_session: Session, auth_context):
    """Verify unauthorized or cross-workspace access is rejected."""
    workspace = auth_context["workspace"]

    # 1. No token -> 401 Unauthorized
    res = client.get(f"/api/v1/services?workspace_id={workspace.id}")
    assert res.status_code == 401

    # 2. Access to random non-existent workspace -> 404
    headers = auth_context["headers"]
    fake_ws_id = str(uuid.uuid4())
    res_fake = client.get(f"/api/v1/services?workspace_id={fake_ws_id}", headers=headers)
    assert res_fake.status_code == 404
