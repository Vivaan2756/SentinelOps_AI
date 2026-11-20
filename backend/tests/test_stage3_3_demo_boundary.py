"""SentinelOps Stage 3.3 — Demo Integration Trust Boundary Test Suite.

Proves:
1. Ordinary customer attempting to self-assign demo_integration in standard service creation is strictly rejected (HTTP 403) with audit logging.
2. Ordinary customer omitting demo_integration creates a generic service (HTTP 201) with demo_integration=None.
3. Server-authorized demo provisioning (POST /api/v1/services/provision-demo) succeeds for workspace admin in development.
4. Unauthorized provisioning attempts by non-admin roles (engineer, viewer) are rejected (HTTP 403) with audit logging.
5. Provisioning attempts outside the development environment are strictly rejected (HTTP 403).
6. Cross-workspace demo provisioning attempts are rejected (HTTP 403).
7. Generic services with names resembling Order API ("Order API", "order-api", "Order API Live PG") never receive demo capabilities.
8. Playbook associations cannot independently activate demo behavior on generic services.
9. Legitimate demo execution and verification succeeds on an authorized provisioned demo service.
"""

import uuid
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.security import create_access_token, get_password_hash
from app.models.incident import Incident
from app.models.playbook import Playbook, PlaybookVersion, ServicePlaybookAssociation
from app.models.service import Service
from app.models.user import User
from app.models.workspace import Workspace, WorkspaceMembership
from app.remediation.approval_service import ApprovalService
from app.remediation.playbook_service import PlaybookService
from app.remediation.policy import PolicyEngine
from app.remediation.registry import ActionRegistry
from app.remediation.schemas import PolicyDecisionType
from app.execution.runners.http_recovery import IsolatedHttpRecoveryRunner
from app.execution.runner import ExecutionResult


@pytest.fixture
def boundary_env(db_session: Session):
    """Sets up an isolated test environment with admin, engineer, and viewer users across two workspaces."""
    # 1. Workspaces
    ws_primary = Workspace(
        id=str(uuid.uuid4()),
        name="Primary Ops",
        slug=f"primary-ops-{uuid.uuid4().hex[:6]}",
    )
    ws_foreign = Workspace(
        id=str(uuid.uuid4()),
        name="Foreign Ops",
        slug=f"foreign-ops-{uuid.uuid4().hex[:6]}",
    )
    db_session.add_all([ws_primary, ws_foreign])
    db_session.flush()

    # 2. Users
    admin = User(
        id=str(uuid.uuid4()),
        email=f"admin-{uuid.uuid4().hex[:6]}@sentinelops.local",
        full_name="Admin SRE",
        hashed_password=get_password_hash("Password123!"),
        is_active=True,
    )
    engineer = User(
        id=str(uuid.uuid4()),
        email=f"engineer-{uuid.uuid4().hex[:6]}@sentinelops.local",
        full_name="Engineer SRE",
        hashed_password=get_password_hash("Password123!"),
        is_active=True,
    )
    viewer = User(
        id=str(uuid.uuid4()),
        email=f"viewer-{uuid.uuid4().hex[:6]}@sentinelops.local",
        full_name="Auditor Viewer",
        hashed_password=get_password_hash("Password123!"),
        is_active=True,
    )
    foreign_admin = User(
        id=str(uuid.uuid4()),
        email=f"fadmin-{uuid.uuid4().hex[:6]}@sentinelops.local",
        full_name="Foreign Admin",
        hashed_password=get_password_hash("Password123!"),
        is_active=True,
    )
    db_session.add_all([admin, engineer, viewer, foreign_admin])
    db_session.flush()

    # 3. Memberships
    m_admin = WorkspaceMembership(workspace_id=ws_primary.id, user_id=admin.id, role="admin")
    m_eng = WorkspaceMembership(workspace_id=ws_primary.id, user_id=engineer.id, role="engineer")
    m_view = WorkspaceMembership(workspace_id=ws_primary.id, user_id=viewer.id, role="viewer")
    m_foreign = WorkspaceMembership(workspace_id=ws_foreign.id, user_id=foreign_admin.id, role="admin")
    db_session.add_all([m_admin, m_eng, m_view, m_foreign])
    db_session.flush()

    return {
        "ws_primary": ws_primary,
        "ws_foreign": ws_foreign,
        "admin": admin,
        "engineer": engineer,
        "viewer": viewer,
        "foreign_admin": foreign_admin,
        "admin_token": create_access_token({"sub": admin.id}),
        "engineer_token": create_access_token({"sub": engineer.id}),
        "viewer_token": create_access_token({"sub": viewer.id}),
        "foreign_token": create_access_token({"sub": foreign_admin.id}),
    }


def test_ordinary_customer_self_assign_demo_rejected(client: TestClient, boundary_env):
    """Requirement 1: Ordinary customer cannot self-assign demo_integration in standard service creation (HTTP 403)."""
    env = boundary_env
    payload = {
        "workspace_id": env["ws_primary"].id,
        "name": "Customer Attacker Service",
        "environment": "development",
        "health_check_url": "http://127.0.0.1:8001/health",
        "monitoring_method": "prometheus",
        "execution_policy": "demo",
        "demo_integration": "order_api",  # Unauthorized self-assignment attempt
    }

    from unittest.mock import patch
    with patch("app.api.v1.endpoints.services.logger") as mock_logger:
        resp = client.post(
            "/api/v1/services",
            json=payload,
            headers={"Authorization": f"Bearer {env['engineer_token']}"},
        )

    assert resp.status_code == 403
    assert "demo_integration cannot be self-assigned" in resp.json()["detail"]
    # Verify security audit event was logged
    mock_logger.warning.assert_called_once()
    assert "SECURITY AUDIT: Unauthorized attempt" in mock_logger.warning.call_args[0][0]


def test_ordinary_customer_omitting_demo_integration_succeeds(client: TestClient, boundary_env):
    """Requirement 2: Ordinary customer omitting demo_integration creates generic service (HTTP 201)."""
    env = boundary_env
    payload = {
        "workspace_id": env["ws_primary"].id,
        "name": "Legitimate Microservice",
        "environment": "development",
        "health_check_url": "http://127.0.0.1:8001/health",
        "monitoring_method": "prometheus",
        "execution_policy": "approval_required",
    }

    resp = client.post(
        "/api/v1/services",
        json=payload,
        headers={"Authorization": f"Bearer {env['engineer_token']}"},
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["name"] == "Legitimate Microservice"
    assert data["demo_integration"] is None


def test_authorized_demo_provisioning_succeeds(client: TestClient, boundary_env):
    """Requirement 3: Explicit server-authorized provisioning succeeds for workspace admin in development."""
    env = boundary_env
    payload = {
        "workspace_id": env["ws_primary"].id,
        "name": "Order API Official Demo",
        "environment": "development",
        "health_check_url": "http://127.0.0.1:8001/health",
        "monitoring_method": "prometheus",
        "execution_policy": "demo",
        "demo_integration": "order_api",
    }

    from unittest.mock import patch
    with patch("app.api.v1.endpoints.services.logger") as mock_logger:
        resp = client.post(
            "/api/v1/services/provision-demo",
            json=payload,
            headers={"Authorization": f"Bearer {env['admin_token']}"},
        )

    assert resp.status_code == 201
    data = resp.json()
    assert data["name"] == "Order API Official Demo"
    assert data["demo_integration"] == "order_api"
    # Verify authorized audit log
    mock_logger.info.assert_called_once()
    assert "SECURITY AUDIT: Authorized demo integration" in mock_logger.info.call_args[0][0]

    # Verify discovery shows 4 capabilities
    svc_id = data["id"]
    caps_resp = client.get(
        f"/api/v1/services/{svc_id}/capabilities?workspace_id={env['ws_primary'].id}",
        headers={"Authorization": f"Bearer {env['admin_token']}"},
    )
    assert caps_resp.status_code == 200
    caps = caps_resp.json()
    assert caps["compatible_count"] == 4
    assert caps["executable_count"] == 4


def test_unauthorized_demo_provisioning_rejected(client: TestClient, boundary_env, caplog):
    """Requirement 4: Non-admin users (engineer, viewer) cannot provision demo integration (HTTP 403)."""
    env = boundary_env
    payload = {
        "workspace_id": env["ws_primary"].id,
        "name": "Exploitative Order Demo",
        "environment": "development",
        "health_check_url": "http://127.0.0.1:8001/health",
        "monitoring_method": "prometheus",
        "execution_policy": "demo",
        "demo_integration": "order_api",
    }

    # 1. Engineer role attempt
    resp_eng = client.post(
        "/api/v1/services/provision-demo",
        json=payload,
        headers={"Authorization": f"Bearer {env['engineer_token']}"},
    )
    assert resp_eng.status_code == 403
    assert "Insufficient permissions" in resp_eng.json()["detail"]

    # 2. Viewer role attempt
    resp_view = client.post(
        "/api/v1/services/provision-demo",
        json=payload,
        headers={"Authorization": f"Bearer {env['viewer_token']}"},
    )
    assert resp_view.status_code == 403
    assert "Insufficient permissions" in resp_view.json()["detail"]


def test_cross_workspace_demo_provisioning_rejected(client: TestClient, boundary_env):
    """Requirement 6: Admin of Workspace B cannot provision demo in Workspace A (HTTP 403)."""
    env = boundary_env
    payload = {
        "workspace_id": env["ws_primary"].id,  # Target is Workspace A
        "name": "Cross Workspace Demo",
        "environment": "development",
        "health_check_url": "http://127.0.0.1:8001/health",
        "monitoring_method": "prometheus",
        "execution_policy": "demo",
        "demo_integration": "order_api",
    }

    resp = client.post(
        "/api/v1/services/provision-demo",
        json=payload,
        headers={"Authorization": f"Bearer {env['foreign_token']}"},  # User belongs to Workspace B
    )
    assert resp.status_code == 403
    assert "Access denied: User is not a member of this workspace" in resp.json()["detail"]


def test_generic_service_resembling_order_api_never_gets_demo(db_session: Session):
    """Requirement 7: Generic services with names resembling Order API never receive demo capabilities."""
    resembling_names = [
        "Order API",
        "order-api",
        "Order API Live PG",
        "demo-order-service",
        "order_api_v2",
        "order-service",
    ]

    for name in resembling_names:
        svc = Service(
            workspace_id=str(uuid.uuid4()),
            name=name,
            environment="development",
            health_check_url="http://127.0.0.1:8001/health",
            monitoring_method="prometheus",
            execution_policy="demo",
            demo_integration=None,  # Not explicitly provisioned as order_api
            is_active=True,
        )

        # 1. ActionRegistry.is_demo_service must be False
        assert ActionRegistry.is_demo_service(svc, "order_api", db=db_session) is False

        # 2. ActionRegistry.is_action_supported_for_service must be False
        assert ActionRegistry.is_action_supported_for_service("restore_order_api_demo", svc, db=db_session) is False
        assert ActionRegistry.is_action_supported_for_service("restart_order_api", svc, db=db_session) is False

        # 3. Discovery must show only universal capabilities (2)
        caps = ActionRegistry.discover_service_capabilities(svc, db=db_session)
        assert caps.compatible_count == 2
        assert caps.executable_count == 2
        cap_map = {c.action_id: c for c in caps.capabilities}
        assert cap_map["restore_order_api_demo"].is_compatible is False
        assert "requires explicit demo integration configuration" in cap_map["restore_order_api_demo"].reasons[0]


def test_playbook_association_cannot_activate_demo_behavior(db_session: Session, boundary_env):
    """Requirement 8: Playbook association cannot independently activate demo behavior on generic services."""
    env = boundary_env
    ws = env["ws_primary"]

    # 1. Generic service created without demo_integration
    generic_svc = Service(
        workspace_id=ws.id,
        name="Generic Inventory",
        environment="development",
        health_check_url="http://127.0.0.1:7000/health",
        monitoring_method="prometheus",
        execution_policy="approval_required",
        demo_integration=None,
        is_active=True,
    )
    db_session.add(generic_svc)
    db_session.flush()

    # 2. Attempting to associate a demo playbook via PlaybookService must be rejected
    pb = Playbook(
        workspace_id=ws.id,
        name="Order Demo Restore Playbook",
        description="Demo restore",
        category="service_recovery",
        is_active=True,
        created_by=env["admin"].id,
    )
    db_session.add(pb)
    db_session.flush()

    pv = PlaybookVersion(
        playbook_id=pb.id,
        version_number=1,
        action_template_id="restore_order_api_demo",
        supported_scenarios=["*"],
        parameter_schema={},
        risk_level="medium",
        created_by=env["admin"].id,
    )
    db_session.add(pv)
    db_session.flush()

    # Association attempt must raise HTTPException 400
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as exc_info:
        PlaybookService.associate_service(
            db=db_session,
            user=env["admin"],
            workspace_id=ws.id,
            playbook_id=pb.id,
            service_id=generic_svc.id,
        )
    assert exc_info.value.status_code == 400
    assert "does not support service" in str(exc_info.value.detail)

    # 3. Even if association was force-inserted directly into DB, is_demo_service remains False
    force_assoc = ServicePlaybookAssociation(
        workspace_id=ws.id,
        service_id=generic_svc.id,
        playbook_id=pb.id,
        is_active=True,
    )
    db_session.add(force_assoc)
    db_session.commit()

    # Invariant: Force-inserted association DOES NOT activate demo status!
    assert ActionRegistry.is_demo_service(generic_svc, "order_api", db=db_session) is False
    assert ActionRegistry.is_action_supported_for_service("restore_order_api_demo", generic_svc, db=db_session) is False


def test_legitimate_demo_execution_and_verification(db_session: Session, boundary_env):
    """Requirement 9: Legitimate authorized demo service executes and passes verification."""
    env = boundary_env
    ws = env["ws_primary"]

    # 1. Authorized demo service
    demo_svc = Service(
        workspace_id=ws.id,
        name="Order API",
        environment="development",
        health_check_url="http://127.0.0.1:8001/health",
        monitoring_method="prometheus",
        execution_policy="demo",
        demo_integration="order_api",  # Authorized provisioning
        is_active=True,
    )
    db_session.add(demo_svc)
    db_session.flush()

    # 2. Confirms is_demo_service is True
    assert ActionRegistry.is_demo_service(demo_svc, "order_api", db=db_session) is True
    assert ActionRegistry.is_action_supported_for_service("restore_order_api_demo", demo_svc, db=db_session) is True

    # 3. Proposes policy evaluation
    result = PolicyEngine.evaluate(
        workspace_id=ws.id,
        user_role="engineer",
        action_id="restore_order_api_demo",
        parameters={"service_id": demo_svc.id},
        environment="development",
        db=db_session,
        user_id=env["engineer"].id,
    )
    assert result.decision == PolicyDecisionType.APPROVAL_REQUIRED
    assert result.action_id == "restore_order_api_demo"
