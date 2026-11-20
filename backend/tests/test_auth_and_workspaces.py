"""Test suite for authentication, authorization, role levels, and workspace isolation."""

import uuid
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from app.core.security import get_password_hash, create_access_token
from app.models.user import User
from app.models.workspace import Workspace, WorkspaceMembership
from app.models.service import Service


def test_auth_login_success_and_failure(client: TestClient, db_session: Session):
    """Verify login authentication flows."""
    email = f"sre-{uuid.uuid4().hex[:6]}@sentinelops.local"
    raw_password = "SecurePassword2026!"

    user = User(
        email=email,
        full_name="Staff SRE",
        hashed_password=get_password_hash(raw_password),
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()

    # 1. Invalid password -> 401
    bad_res = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": "WrongPassword!"},
    )
    assert bad_res.status_code == 401
    assert "Invalid email or password" in bad_res.json()["detail"]

    # 2. Non-existent user -> 401
    missing_res = client.post(
        "/api/v1/auth/login",
        json={"email": "nobody@sentinelops.local", "password": raw_password},
    )
    assert missing_res.status_code == 401

    # 3. Valid login -> 200 with JWT access token
    good_res = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": raw_password},
    )
    assert good_res.status_code == 200
    data = good_res.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["user"]["email"] == email

    # 4. GET /api/v1/auth/me
    token = data["access_token"]
    me_res = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_res.status_code == 200
    assert me_res.json()["user"]["email"] == email


def test_workspace_membership_and_cross_tenant_isolation(client: TestClient, db_session: Session):
    """Verify that a user in Workspace A CANNOT access or mutate Workspace B."""
    # User 1 & Workspace 1
    u1 = User(
        email=f"u1-{uuid.uuid4().hex[:6]}@sentinelops.local",
        hashed_password=get_password_hash("Pass123!"),
        is_active=True,
    )
    ws1 = Workspace(name="Workspace One", slug=f"ws1-{uuid.uuid4().hex[:6]}")
    db_session.add_all([u1, ws1])
    db_session.flush()

    m1 = WorkspaceMembership(workspace_id=ws1.id, user_id=u1.id, role="admin")
    db_session.add(m1)

    # Workspace 2 (owned by someone else)
    ws2 = Workspace(name="Workspace Two", slug=f"ws2-{uuid.uuid4().hex[:6]}")
    db_session.add(ws2)
    db_session.flush()

    # Service in Workspace 2
    s2 = Service(
        workspace_id=ws2.id,
        name="Private API",
        environment="production",
        health_check_url="http://127.0.0.1:9000/health",
        monitoring_method="prometheus",
        execution_policy="observe_only",
    )
    db_session.add(s2)
    db_session.commit()

    token1 = create_access_token({"sub": u1.id, "email": u1.email})
    headers1 = {"Authorization": f"Bearer {token1}"}

    # 1. User 1 can access Workspace 1
    res_ws1 = client.get(f"/api/v1/services?workspace_id={ws1.id}", headers=headers1)
    assert res_ws1.status_code == 200

    # 2. User 1 CANNOT access Workspace 2 -> 403 Forbidden
    res_ws2 = client.get(f"/api/v1/services?workspace_id={ws2.id}", headers=headers1)
    assert res_ws2.status_code == 403
    assert "not a member" in res_ws2.json()["detail"].lower()

    # 3. User 1 CANNOT access Service in Workspace 2 -> 403
    res_s2 = client.get(f"/api/v1/services/{s2.id}?workspace_id={ws2.id}", headers=headers1)
    assert res_s2.status_code == 403


def test_role_based_permission_enforcement(client: TestClient, db_session: Session):
    """Verify that 'viewer' role CANNOT register new services (requires engineer/admin)."""
    viewer = User(
        email=f"viewer-{uuid.uuid4().hex[:6]}@sentinelops.local",
        hashed_password=get_password_hash("Pass123!"),
        is_active=True,
    )
    workspace = Workspace(name="Ops Room", slug=f"ops-{uuid.uuid4().hex[:6]}")
    db_session.add_all([viewer, workspace])
    db_session.flush()

    membership = WorkspaceMembership(workspace_id=workspace.id, user_id=viewer.id, role="viewer")
    db_session.add(membership)
    db_session.commit()

    token = create_access_token({"sub": viewer.id, "email": viewer.email})
    headers = {"Authorization": f"Bearer {token}"}

    # Viewer CAN view services
    res_list = client.get(f"/api/v1/services?workspace_id={workspace.id}", headers=headers)
    assert res_list.status_code == 200

    # Viewer CANNOT create services -> 403 Forbidden
    payload = {
        "workspace_id": workspace.id,
        "name": "Forbidden Service",
        "environment": "development",
        "health_check_url": "http://127.0.0.1:8000/health",
        "monitoring_method": "prometheus",
        "execution_policy": "demo",
    }
    res_create = client.post("/api/v1/services", json=payload, headers=headers)
    assert res_create.status_code == 403
    assert "requires 'engineer' role" in res_create.json()["detail"]


def test_dashboard_overview_metrics(client: TestClient, db_session: Session, auth_context):
    """Verify that dashboard overview returns real computed counts from the database."""
    workspace = auth_context["workspace"]
    headers = auth_context["headers"]

    # Register services with different statuses
    s1 = Service(
        workspace_id=workspace.id,
        name="Service A",
        environment="development",
        health_check_url="http://127.0.0.1:8001/health",
        monitoring_method="prometheus",
        execution_policy="demo",
        health_status="healthy",
    )
    s2 = Service(
        workspace_id=workspace.id,
        name="Service B",
        environment="production",
        health_check_url="http://127.0.0.1:8002/health",
        monitoring_method="prometheus",
        execution_policy="demo",
        health_status="unhealthy",
    )
    db_session.add_all([s1, s2])
    db_session.commit()

    res = client.get(f"/api/v1/dashboard/overview?workspace_id={workspace.id}", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["total_services"] == 2
    assert data["healthy_services"] == 1
    assert data["unhealthy_services"] == 1
    assert data["active_incidents"] == 0
    assert "incidents_by_severity" in data
    assert "recent_events" in data
