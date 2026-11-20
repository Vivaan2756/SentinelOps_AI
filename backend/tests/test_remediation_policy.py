"""Tests for Remediation Foundation (Phase 4.1).

Validates:
1. Allowlisted Action Registry:
   - Known action lookup
   - Unknown action rejection
   - Action categorization and risk assignment
   - Disabled action handling
2. Strict Typed Parameter Validation:
   - Required parameters
   - Missing parameters
   - Extra / arbitrary fields rejected (extra="forbid")
   - Invalid UUID format rejected
3. Risk Classification & Approval Rules:
   - Low-risk read-only action allowed without approval
   - Medium-risk action requires approval when configured
   - High-risk action always requires approval
   - AI-supplied risk downgrade is ignored
   - AI-supplied approval override is ignored
4. Multi-Tenant Safety & Preconditions:
   - Cross-workspace service references rejected
   - Non-existent service references rejected
   - Inactive service restart rejected
   - Unsupported environment rejected
5. Role-Based Permissions:
   - Viewer cannot authorize operational actions
   - Viewer can inspect low-risk diagnostics and view action catalog
   - Engineer and Admin can evaluate operational policies
6. API Endpoints & Persistence:
   - GET /api/v1/remediation/actions
   - POST /api/v1/remediation/policy/evaluate
   - GET /api/v1/remediation/policy/decisions
   - Tenant scoping and unauthorized workspace access rejection
"""

import uuid
import pytest
from fastapi.testclient import TestClient

from app.core.security import create_access_token, get_password_hash
from app.models.remediation import PolicyDecision
from app.models.service import Service
from app.models.user import User
from app.models.workspace import Workspace, WorkspaceMembership
from app.remediation.policy import PolicyEngine, POLICY_ENGINE_VERSION
from app.remediation.registry import ActionRegistry, ALLOWLISTED_ACTIONS
from app.remediation.schemas import (
    ActionCategory,
    ActionDefinition,
    PolicyDecisionType,
    RiskLevel,
)


@pytest.fixture
def remediation_env(db_session):
    """Sets up a comprehensive multi-user, multi-workspace environment."""
    # 1. Primary Workspace
    ws1 = Workspace(
        name="Primary Ops",
        slug=f"primary-ops-{uuid.uuid4().hex[:6]}",
        description="Primary Workspace for testing",
    )
    # 2. Secondary Workspace (for cross-workspace isolation tests)
    ws2 = Workspace(
        name="Foreign Ops",
        slug=f"foreign-ops-{uuid.uuid4().hex[:6]}",
        description="Foreign Workspace for cross-tenant tests",
    )
    db_session.add_all([ws1, ws2])
    db_session.flush()

    # 3. Users: Admin, Engineer, Viewer, ForeignUser
    admin_user = User(
        email=f"admin-{uuid.uuid4().hex[:6]}@sentinelops.local",
        full_name="Admin User",
        hashed_password=get_password_hash("Password123!"),
        is_active=True,
    )
    engineer_user = User(
        email=f"eng-{uuid.uuid4().hex[:6]}@sentinelops.local",
        full_name="Engineer User",
        hashed_password=get_password_hash("Password123!"),
        is_active=True,
    )
    viewer_user = User(
        email=f"viewer-{uuid.uuid4().hex[:6]}@sentinelops.local",
        full_name="Viewer User",
        hashed_password=get_password_hash("Password123!"),
        is_active=True,
    )
    foreign_user = User(
        email=f"foreign-{uuid.uuid4().hex[:6]}@sentinelops.local",
        full_name="Foreign User",
        hashed_password=get_password_hash("Password123!"),
        is_active=True,
    )
    db_session.add_all([admin_user, engineer_user, viewer_user, foreign_user])
    db_session.flush()

    # 4. Memberships
    m_admin = WorkspaceMembership(workspace_id=ws1.id, user_id=admin_user.id, role="admin")
    m_eng = WorkspaceMembership(workspace_id=ws1.id, user_id=engineer_user.id, role="engineer")
    m_viewer = WorkspaceMembership(workspace_id=ws1.id, user_id=viewer_user.id, role="viewer")
    m_foreign = WorkspaceMembership(workspace_id=ws2.id, user_id=foreign_user.id, role="engineer")
    db_session.add_all([m_admin, m_eng, m_viewer, m_foreign])
    db_session.flush()

    # 5. Services:
    # Service in WS1 (active)
    svc1_active = Service(
        workspace_id=ws1.id,
        name="Order API",
        environment="development",
        health_check_url="http://127.0.0.1:8001/health",
        execution_policy="demo",
        demo_integration="order_api",
        is_active=True,
        health_status="healthy",
    )
    # Service in WS1 (inactive)
    svc1_inactive = Service(
        workspace_id=ws1.id,
        name="Legacy Catalog",
        environment="development",
        health_check_url="http://127.0.0.1:8002/health",
        is_active=False,
        health_status="unhealthy",
    )
    # Service in WS2 (active foreign service)
    svc2_foreign = Service(
        workspace_id=ws2.id,
        name="Foreign Billing API",
        environment="development",
        health_check_url="http://127.0.0.1:8003/health",
        is_active=True,
        health_status="healthy",
    )
    db_session.add_all([svc1_active, svc1_inactive, svc2_foreign])
    db_session.commit()

    return {
        "ws1": ws1,
        "ws2": ws2,
        "admin": admin_user,
        "engineer": engineer_user,
        "viewer": viewer_user,
        "foreign_user": foreign_user,
        "svc_active": svc1_active,
        "svc_inactive": svc1_inactive,
        "svc_foreign": svc2_foreign,
        "admin_token": create_access_token({"sub": admin_user.id}),
        "engineer_token": create_access_token({"sub": engineer_user.id}),
        "viewer_token": create_access_token({"sub": viewer_user.id}),
        "foreign_token": create_access_token({"sub": foreign_user.id}),
    }


# ============================================================================
# 1. Action Registry Unit Tests
# ============================================================================

def test_registry_known_actions_found():
    """Verify that all predefined allowlisted actions exist in the registry."""
    restart_action = ActionRegistry.get_action("restart_order_api")
    assert restart_action is not None
    assert restart_action.action_id == "restart_order_api"
    assert restart_action.category == ActionCategory.SERVICE_RECOVERY
    assert restart_action.risk_level == RiskLevel.MEDIUM
    assert restart_action.approval_required is True
    assert restart_action.enabled is True

    inspect_action = ActionRegistry.get_action("inspect_service_health")
    assert inspect_action is not None
    assert inspect_action.category == ActionCategory.DIAGNOSTICS
    assert inspect_action.risk_level == RiskLevel.LOW
    assert inspect_action.approval_required is False

    disable_action = ActionRegistry.get_action("disable_service_monitoring")
    assert disable_action is not None
    assert disable_action.category == ActionCategory.MONITORING
    assert disable_action.risk_level == RiskLevel.HIGH
    assert disable_action.approval_required is True


def test_registry_unknown_action_returns_none():
    """Verify that an unknown action ID returns None from registry."""
    assert ActionRegistry.get_action("arbitrary_command_execution") is None
    assert ActionRegistry.get_action("drop_database") is None
    assert ActionRegistry.get_action("") is None


def test_registry_list_actions():
    """Verify action catalog listing."""
    actions = ActionRegistry.list_actions(include_disabled=False)
    action_ids = [a.action_id for a in actions]
    assert "restart_order_api" in action_ids
    assert "inspect_service_health" in action_ids
    assert "disable_service_monitoring" in action_ids
    assert len(actions) >= 3


# ============================================================================
# 2. Parameter Validation Unit Tests
# ============================================================================

def test_validate_parameters_valid():
    """Valid parameters pass validation with sanitized model returned."""
    valid_uuid = str(uuid.uuid4())
    is_valid, model, err = ActionRegistry.validate_parameters(
        "restart_order_api", {"service_id": valid_uuid}
    )
    assert is_valid is True
    assert model is not None
    assert model.service_id == valid_uuid
    assert err is None


def test_validate_parameters_missing_required():
    """Missing required parameters are strictly rejected."""
    is_valid, model, err = ActionRegistry.validate_parameters("restart_order_api", {})
    assert is_valid is False
    assert model is None
    assert "Field 'service_id'" in err


def test_validate_parameters_extra_fields_forbidden():
    """Extra arbitrary parameters are rejected via extra='forbid'."""
    valid_uuid = str(uuid.uuid4())
    is_valid, model, err = ActionRegistry.validate_parameters(
        "restart_order_api",
        {
            "service_id": valid_uuid,
            "shell_cmd": "reboot",
            "docker_container": "order-api",
        },
    )
    assert is_valid is False
    assert model is None
    assert "extra fields not permitted" in err.lower() or "extra" in err.lower()


def test_validate_parameters_invalid_uuid():
    """Malformed UUID strings are rejected."""
    is_valid, model, err = ActionRegistry.validate_parameters(
        "restart_order_api", {"service_id": "not-a-valid-uuid"}
    )
    assert is_valid is False
    assert model is None
    assert "valid 36-character UUID" in err or "service_id" in err


# ============================================================================
# 3. Policy Engine Evaluation Unit Tests
# ============================================================================

def test_policy_unknown_action_rejected(db_session, remediation_env):
    """Rule 1: Unknown action proposals are rejected."""
    res = PolicyEngine.evaluate(
        workspace_id=remediation_env["ws1"].id,
        user_role="engineer",
        action_id="execute_custom_bash",
        parameters={"cmd": "echo 1"},
        environment="development",
        db=db_session,
    )
    assert res.decision == PolicyDecisionType.REJECTED
    assert "not registered" in res.decision_reason
    assert res.approval_required is True


def test_policy_disabled_action_rejected(db_session, remediation_env, monkeypatch):
    """Rule 2: Disabled action proposals are rejected."""
    # Temporarily set an action to disabled
    act = ActionRegistry.get_action("restart_order_api")
    monkeypatch.setattr(act, "enabled", False)

    res = PolicyEngine.evaluate(
        workspace_id=remediation_env["ws1"].id,
        user_role="engineer",
        action_id="restart_order_api",
        parameters={"service_id": remediation_env["svc_active"].id},
        environment="development",
        db=db_session,
    )
    assert res.decision == PolicyDecisionType.REJECTED
    assert "currently disabled" in res.decision_reason


def test_policy_invalid_parameters_rejected(db_session, remediation_env):
    """Rule 3: Proposals with invalid parameters are rejected."""
    res = PolicyEngine.evaluate(
        workspace_id=remediation_env["ws1"].id,
        user_role="engineer",
        action_id="restart_order_api",
        parameters={"service_id": "malformed-uuid"},
        environment="development",
        db=db_session,
    )
    assert res.decision == PolicyDecisionType.REJECTED
    assert "Invalid parameters" in res.decision_reason


def test_policy_cross_workspace_rejected(db_session, remediation_env):
    """Rule 4: Referencing a service from another workspace is strictly rejected."""
    res = PolicyEngine.evaluate(
        workspace_id=remediation_env["ws1"].id,
        user_role="engineer",
        action_id="restart_order_api",
        parameters={"service_id": remediation_env["svc_foreign"].id},  # Service in WS2
        environment="development",
        db=db_session,
    )
    assert res.decision == PolicyDecisionType.REJECTED
    assert "Cross-workspace violation" in res.decision_reason


def test_policy_nonexistent_service_rejected(db_session, remediation_env):
    """Rule 4: Referencing a non-existent service ID is rejected."""
    res = PolicyEngine.evaluate(
        workspace_id=remediation_env["ws1"].id,
        user_role="engineer",
        action_id="restart_order_api",
        parameters={"service_id": str(uuid.uuid4())},
        environment="development",
        db=db_session,
    )
    assert res.decision == PolicyDecisionType.REJECTED
    assert "does not exist" in res.decision_reason


def test_policy_inactive_service_restart_rejected(db_session, remediation_env):
    """Rule 4 Precondition: Inactive service cannot be restarted."""
    res = PolicyEngine.evaluate(
        workspace_id=remediation_env["ws1"].id,
        user_role="engineer",
        action_id="restart_order_api",
        parameters={"service_id": remediation_env["svc_inactive"].id},
        environment="development",
        db=db_session,
    )
    assert res.decision == PolicyDecisionType.REJECTED
    assert "Precondition failed" in res.decision_reason
    assert "inactive" in res.decision_reason


def test_policy_unsupported_environment_rejected(db_session, remediation_env):
    """Rule 5: Unsupported environments are rejected."""
    res = PolicyEngine.evaluate(
        workspace_id=remediation_env["ws1"].id,
        user_role="engineer",
        action_id="restart_order_api",
        parameters={"service_id": remediation_env["svc_active"].id},
        environment="production",  # only 'development' supported
        db=db_session,
    )
    assert res.decision == PolicyDecisionType.REJECTED
    assert "Unsupported environment 'production'" in res.decision_reason


def test_policy_low_risk_action_allowed(db_session, remediation_env):
    """Rule 8: Low-risk read-only diagnostics allowed without approval."""
    res = PolicyEngine.evaluate(
        workspace_id=remediation_env["ws1"].id,
        user_role="engineer",
        action_id="inspect_service_health",
        parameters={"service_id": remediation_env["svc_active"].id},
        environment="development",
        db=db_session,
    )
    assert res.decision == PolicyDecisionType.ALLOWED
    assert res.risk_level == "low"
    assert res.approval_required is False
    assert res.target_service_id == remediation_env["svc_active"].id


def test_policy_medium_risk_action_requires_approval(db_session, remediation_env):
    """Rule 7: Medium-risk service restart requires human approval."""
    res = PolicyEngine.evaluate(
        workspace_id=remediation_env["ws1"].id,
        user_role="engineer",
        action_id="restart_order_api",
        parameters={"service_id": remediation_env["svc_active"].id},
        environment="development",
        db=db_session,
    )
    assert res.decision == PolicyDecisionType.APPROVAL_REQUIRED
    assert res.risk_level == "medium"
    assert res.approval_required is True


def test_policy_high_risk_action_always_requires_approval(db_session, remediation_env):
    """Rule 6: High-risk action always requires human approval."""
    res = PolicyEngine.evaluate(
        workspace_id=remediation_env["ws1"].id,
        user_role="engineer",
        action_id="disable_service_monitoring",
        parameters={"service_id": remediation_env["svc_active"].id},
        environment="development",
        db=db_session,
    )
    assert res.decision == PolicyDecisionType.APPROVAL_REQUIRED
    assert res.risk_level == "high"
    assert res.approval_required is True


def test_policy_ai_risk_downgrade_ignored(db_session, remediation_env):
    """Rule 9: AI attempting to pass a downgraded risk level is ignored."""
    res = PolicyEngine.evaluate(
        workspace_id=remediation_env["ws1"].id,
        user_role="engineer",
        action_id="disable_service_monitoring",  # canonical: high risk
        parameters={"service_id": remediation_env["svc_active"].id},
        environment="development",
        db=db_session,
        ai_proposed_risk="low",  # AI attempts to downgrade
    )
    # Must remain HIGH risk and require approval
    assert res.risk_level == "high"
    assert res.approval_required is True
    assert res.decision == PolicyDecisionType.APPROVAL_REQUIRED


def test_policy_ai_approval_override_ignored(db_session, remediation_env):
    """Rule 9: AI attempting to override approval flag is ignored."""
    res = PolicyEngine.evaluate(
        workspace_id=remediation_env["ws1"].id,
        user_role="engineer",
        action_id="restart_order_api",  # canonical: approval_required=True
        parameters={"service_id": remediation_env["svc_active"].id},
        environment="development",
        db=db_session,
        ai_proposed_approval=False,  # AI attempts to bypass approval
    )
    assert res.approval_required is True
    assert res.decision == PolicyDecisionType.APPROVAL_REQUIRED


def test_policy_viewer_cannot_authorize_operational_actions(db_session, remediation_env):
    """Rule 10: Viewers cannot authorize medium or high risk operational actions."""
    # Attempt restart (medium risk)
    res_restart = PolicyEngine.evaluate(
        workspace_id=remediation_env["ws1"].id,
        user_role="viewer",
        action_id="restart_order_api",
        parameters={"service_id": remediation_env["svc_active"].id},
        environment="development",
        db=db_session,
    )
    assert res_restart.decision == PolicyDecisionType.REJECTED
    assert "not authorized to request or approve operational action" in res_restart.decision_reason

    # Attempt disable monitoring (high risk)
    res_disable = PolicyEngine.evaluate(
        workspace_id=remediation_env["ws1"].id,
        user_role="viewer",
        action_id="disable_service_monitoring",
        parameters={"service_id": remediation_env["svc_active"].id},
        environment="development",
        db=db_session,
    )
    assert res_disable.decision == PolicyDecisionType.REJECTED
    assert "not authorized to request or approve operational action" in res_disable.decision_reason

    # But Viewer CAN evaluate low-risk read-only diagnostics
    res_diag = PolicyEngine.evaluate(
        workspace_id=remediation_env["ws1"].id,
        user_role="viewer",
        action_id="inspect_service_health",
        parameters={"service_id": remediation_env["svc_active"].id},
        environment="development",
        db=db_session,
    )
    assert res_diag.decision == PolicyDecisionType.ALLOWED


# ============================================================================
# 4. API Endpoints Integration Tests
# ============================================================================

def test_api_list_actions_authenticated(client: TestClient, remediation_env):
    """GET /api/v1/remediation/actions returns allowlisted actions catalog."""
    resp = client.get(
        f"/api/v1/remediation/actions?workspace_id={remediation_env['ws1'].id}",
        headers={"Authorization": f"Bearer {remediation_env['engineer_token']}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "actions" in data
    assert data["total"] >= 3
    action_ids = [a["action_id"] for a in data["actions"]]
    assert "restart_order_api" in action_ids
    assert "inspect_service_health" in action_ids
    assert "disable_service_monitoring" in action_ids


def test_api_list_actions_unauthorized_workspace(client: TestClient, remediation_env):
    """GET /api/v1/remediation/actions fails with 403 if caller lacks workspace membership."""
    resp = client.get(
        f"/api/v1/remediation/actions?workspace_id={remediation_env['ws1'].id}",
        headers={"Authorization": f"Bearer {remediation_env['foreign_token']}"},
    )
    assert resp.status_code == 403


def test_api_evaluate_policy_success_and_persistence(client: TestClient, db_session, remediation_env):
    """POST /api/v1/remediation/policy/evaluate evaluates proposal and persists audit log."""
    payload = {
        "workspace_id": remediation_env["ws1"].id,
        "action_id": "restart_order_api",
        "parameters": {"service_id": remediation_env["svc_active"].id},
        "environment": "development",
    }
    resp = client.post(
        "/api/v1/remediation/policy/evaluate",
        json=payload,
        headers={"Authorization": f"Bearer {remediation_env['engineer_token']}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["decision"] == "approval_required"
    assert data["risk_level"] == "medium"
    assert data["action_id"] == "restart_order_api"
    assert data["target_service_id"] == remediation_env["svc_active"].id
    assert data["policy_version"] == POLICY_ENGINE_VERSION
    assert "id" in data

    # Verify persisted record in database
    record = db_session.query(PolicyDecision).filter(PolicyDecision.id == data["id"]).first()
    assert record is not None
    assert record.workspace_id == remediation_env["ws1"].id
    assert record.decision == "approval_required"
    assert record.action_id == "restart_order_api"
    assert record.target_service_id == remediation_env["svc_active"].id


def test_api_evaluate_policy_unknown_action(client: TestClient, remediation_env):
    """POST /api/v1/remediation/policy/evaluate records rejection for unknown actions."""
    payload = {
        "workspace_id": remediation_env["ws1"].id,
        "action_id": "drop_all_tables",
        "parameters": {},
        "environment": "development",
    }
    resp = client.post(
        "/api/v1/remediation/policy/evaluate",
        json=payload,
        headers={"Authorization": f"Bearer {remediation_env['engineer_token']}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["decision"] == "rejected"
    assert "not registered" in data["decision_reason"]


def test_api_evaluate_policy_cross_workspace_forbidden(client: TestClient, remediation_env):
    """POST /api/v1/remediation/policy/evaluate rejects non-member workspace access with 403."""
    payload = {
        "workspace_id": remediation_env["ws1"].id,
        "action_id": "inspect_service_health",
        "parameters": {"service_id": remediation_env["svc_active"].id},
    }
    resp = client.post(
        "/api/v1/remediation/policy/evaluate",
        json=payload,
        headers={"Authorization": f"Bearer {remediation_env['foreign_token']}"},
    )
    assert resp.status_code == 403


def test_api_list_policy_decisions(client: TestClient, remediation_env):
    """GET /api/v1/remediation/policy/decisions lists audit records scoped to workspace."""
    # 1. Create a decision in WS1
    payload = {
        "workspace_id": remediation_env["ws1"].id,
        "action_id": "inspect_service_health",
        "parameters": {"service_id": remediation_env["svc_active"].id},
        "environment": "development",
    }
    client.post(
        "/api/v1/remediation/policy/evaluate",
        json=payload,
        headers={"Authorization": f"Bearer {remediation_env['engineer_token']}"},
    )

    # 2. Query decisions for WS1
    resp = client.get(
        f"/api/v1/remediation/policy/decisions?workspace_id={remediation_env['ws1'].id}",
        headers={"Authorization": f"Bearer {remediation_env['viewer_token']}"},
    )
    assert resp.status_code == 200
    decisions = resp.json()
    assert len(decisions) >= 1
    assert decisions[0]["workspace_id"] == remediation_env["ws1"].id
    assert decisions[0]["action_id"] == "inspect_service_health"
