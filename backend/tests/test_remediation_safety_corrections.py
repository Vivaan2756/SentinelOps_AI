"""Isolated tests for SentinelOps AI Backend Safety Corrections (Revision 10).

Covers:
- Correction A: Enforce services.execution_policy (observe_only, approval_required, demo, unknown/null)
  in PolicyEngine.evaluate(), ApprovalService, and RemediationExecutionManager / Worker.
- Correction B: Validate incident and investigation ownership in ApprovalService.create_approval_request().
"""

import uuid
from datetime import datetime, timezone
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from app.core.security import create_access_token, get_password_hash
from app.execution.exceptions import PreconditionFailedError
from app.execution.manager import RemediationExecutionManager
from app.execution.manifest_signer import generate_and_sign_execution_manifest
from app.execution.worker import DurableExecutionWorker
from app.models.incident import Incident
from app.models.investigation import Investigation
from app.models.remediation import PolicyDecision, RemediationApproval, RemediationExecution
from app.models.service import Service
from app.models.user import User
from app.models.workspace import Workspace, WorkspaceMembership
from app.remediation.approval_service import ApprovalService
from app.remediation.policy import PolicyEngine
from app.remediation.schemas import PolicyDecisionType


@pytest.fixture
def safety_test_env(db_session):
    """Sets up isolated workspaces, services, incidents, investigations, and users."""
    # 1. Workspaces
    ws_primary = Workspace(
        name="Primary Safety Ops",
        slug=f"primary-safety-{uuid.uuid4().hex[:6]}",
        description="Primary Workspace for Safety Tests",
    )
    ws_foreign = Workspace(
        name="Foreign Safety Ops",
        slug=f"foreign-safety-{uuid.uuid4().hex[:6]}",
        description="Foreign Workspace for Cross-Tenant Tests",
    )
    db_session.add_all([ws_primary, ws_foreign])
    db_session.flush()

    # 2. Users
    user_eng = User(
        email=f"eng-{uuid.uuid4().hex[:6]}@sentinelops.local",
        full_name="Safety Engineer",
        hashed_password=get_password_hash("Password123!"),
        is_active=True,
    )
    user_admin = User(
        email=f"admin-{uuid.uuid4().hex[:6]}@sentinelops.local",
        full_name="Safety Admin",
        hashed_password=get_password_hash("Password123!"),
        is_active=True,
    )
    user_foreign = User(
        email=f"foreign-{uuid.uuid4().hex[:6]}@sentinelops.local",
        full_name="Foreign Engineer",
        hashed_password=get_password_hash("Password123!"),
        is_active=True,
    )
    db_session.add_all([user_eng, user_admin, user_foreign])
    db_session.flush()

    # 3. Memberships
    m_eng = WorkspaceMembership(workspace_id=ws_primary.id, user_id=user_eng.id, role="engineer")
    m_admin = WorkspaceMembership(workspace_id=ws_primary.id, user_id=user_admin.id, role="admin")
    m_foreign = WorkspaceMembership(workspace_id=ws_foreign.id, user_id=user_foreign.id, role="engineer")
    db_session.add_all([m_eng, m_admin, m_foreign])
    db_session.flush()

    # 4. Services
    # Primary target service
    svc_primary = Service(
        workspace_id=ws_primary.id,
        name="Order API Demo",
        environment="development",
        health_check_url="http://127.0.0.1:8001/health",
        execution_policy="demo",
        demo_integration="order_api",
        is_active=True,
        health_status="healthy",
    )
    # Secondary service in primary workspace (different service)
    svc_other = Service(
        workspace_id=ws_primary.id,
        name="Inventory API",
        environment="development",
        health_check_url="http://127.0.0.1:8002/health",
        execution_policy="demo",
        is_active=True,
        health_status="healthy",
    )
    # Foreign service in foreign workspace
    svc_foreign = Service(
        workspace_id=ws_foreign.id,
        name="Foreign Payment Gateway",
        environment="development",
        health_check_url="http://127.0.0.1:8003/health",
        execution_policy="demo",
        is_active=True,
        health_status="healthy",
    )
    db_session.add_all([svc_primary, svc_other, svc_foreign])
    db_session.flush()

    # 5. Incidents
    inc_primary = Incident(
        workspace_id=ws_primary.id,
        service_id=svc_primary.id,
        title="Order API High Latency",
        severity="high",
        status="investigating",
        trigger="p99 > 500ms",
    )
    inc_other_svc = Incident(
        workspace_id=ws_primary.id,
        service_id=svc_other.id,
        title="Inventory Sync Hang",
        severity="medium",
        status="investigating",
        trigger="sync_timeout",
    )
    inc_foreign = Incident(
        workspace_id=ws_foreign.id,
        service_id=svc_foreign.id,
        title="Foreign Gateway Error",
        severity="high",
        status="investigating",
        trigger="gateway_timeout",
    )
    db_session.add_all([inc_primary, inc_other_svc, inc_foreign])
    db_session.flush()

    # 6. Investigations
    inv_primary = Investigation(
        incident_id=inc_primary.id,
        workspace_id=ws_primary.id,
        status="completed",
        model_name="gemini-2.5-flash",
        prompt_version="v1.0",
        evidence=[],
        hypotheses=[],
        summary={"recommended_action": "restart_order_api"},
    )
    inv_other_inc = Investigation(
        incident_id=inc_other_svc.id,
        workspace_id=ws_primary.id,
        status="completed",
        model_name="gemini-2.5-flash",
        prompt_version="v1.0",
        evidence=[],
        hypotheses=[],
        summary={"recommended_action": "restart_order_api"},
    )
    inv_foreign = Investigation(
        incident_id=inc_foreign.id,
        workspace_id=ws_foreign.id,
        status="completed",
        model_name="gemini-2.5-flash",
        prompt_version="v1.0",
        evidence=[],
        hypotheses=[],
        summary={"recommended_action": "restart_order_api"},
    )
    db_session.add_all([inv_primary, inv_other_inc, inv_foreign])

    # 7. Base Policy Decision
    decision_primary = PolicyDecision(
        workspace_id=ws_primary.id,
        user_id=user_eng.id,
        action_id="restart_order_api",
        target_service_id=svc_primary.id,
        risk_level="medium",
        decision="approval_required",
        decision_reason="Medium-risk action requires human approval.",
        policy_version="v1.0",
        validated_parameters={"service_id": svc_primary.id},
    )
    db_session.add(decision_primary)
    db_session.commit()

    return {
        "ws_primary": ws_primary,
        "ws_foreign": ws_foreign,
        "user_eng": user_eng,
        "user_admin": user_admin,
        "user_foreign": user_foreign,
        "svc_primary": svc_primary,
        "svc_other": svc_other,
        "svc_foreign": svc_foreign,
        "inc_primary": inc_primary,
        "inc_other_svc": inc_other_svc,
        "inc_foreign": inc_foreign,
        "inv_primary": inv_primary,
        "inv_other_inc": inv_other_inc,
        "inv_foreign": inv_foreign,
        "decision_primary": decision_primary,
        "eng_token": create_access_token({"sub": user_eng.id}),
        "admin_token": create_access_token({"sub": user_admin.id}),
        "foreign_token": create_access_token({"sub": user_foreign.id}),
    }


# ============================================================================
# Correction A Tests: Enforce services.execution_policy
# ============================================================================

def test_correction_a_observe_only_operational_rejected(db_session, safety_test_env):
    """Scenario 1: observe_only + operational action -> Rejected."""
    env = safety_test_env
    env["svc_primary"].execution_policy = "observe_only"
    db_session.commit()

    res = PolicyEngine.evaluate(
        workspace_id=env["ws_primary"].id,
        user_role="engineer",
        action_id="restart_order_api",
        parameters={"service_id": env["svc_primary"].id},
        environment="development",
        db=db_session,
    )
    assert res.decision == PolicyDecisionType.REJECTED
    assert "observe_only" in res.decision_reason
    assert "Operational remediation is disabled" in res.decision_reason

    # Diagnostic read-only action is permitted under observe_only
    res_diag = PolicyEngine.evaluate(
        workspace_id=env["ws_primary"].id,
        user_role="engineer",
        action_id="inspect_service_health",
        parameters={"service_id": env["svc_primary"].id},
        environment="development",
        db=db_session,
    )
    assert res_diag.decision == PolicyDecisionType.ALLOWED


def test_correction_a_observe_only_execution_rejected_before_dispatch(db_session, safety_test_env):
    """Scenario 2: observe_only + execution of previously approved proposal -> Rejected before dispatch."""
    env = safety_test_env
    svc = env["svc_primary"]
    svc.execution_policy = "approval_required"
    db_session.commit()

    # Create and approve an approval request while under approval_required
    approval = ApprovalService.create_approval_request(
        db=db_session,
        workspace_id=env["ws_primary"].id,
        policy_decision_id=env["decision_primary"].id,
        requested_by=env["user_eng"],
    )
    approval = ApprovalService.approve_request(
        db=db_session,
        approval_id=approval.id,
        workspace_id=env["ws_primary"].id,
        reviewer=env["user_admin"],
        user_role="admin",
    )
    assert approval.approval_status == "approved"

    # Now change service policy to observe_only
    svc.execution_policy = "observe_only"
    db_session.commit()

    # Pre-dispatch check in RemediationExecutionManager rejects execution creation
    with pytest.raises(PreconditionFailedError) as exc_info:
        RemediationExecutionManager.create_execution(
            db=db_session,
            workspace_id=env["ws_primary"].id,
            approval_id=approval.id,
            triggered_by=env["user_admin"],
            user_role="admin",
            idempotency_key=str(uuid.uuid4()),
        )
    assert "observe_only" in str(exc_info.value)
    assert "cannot be dispatched" in str(exc_info.value) or "Operational remediation" in str(exc_info.value)


def test_correction_a_approval_required_medium_risk(db_session, safety_test_env):
    """Scenario 3: approval_required + medium-risk action -> Approval required."""
    env = safety_test_env
    env["svc_primary"].execution_policy = "approval_required"
    db_session.commit()

    res = PolicyEngine.evaluate(
        workspace_id=env["ws_primary"].id,
        user_role="engineer",
        action_id="restart_order_api",
        parameters={"service_id": env["svc_primary"].id},
        environment="development",
        db=db_session,
    )
    assert res.decision == PolicyDecisionType.APPROVAL_REQUIRED
    assert res.approval_required is True
    assert res.risk_level == "medium"


def test_correction_a_approval_required_unapproved_execution_rejected(db_session, safety_test_env):
    """Scenario 4: approval_required + unapproved execution -> Rejected."""
    env = safety_test_env
    env["svc_primary"].execution_policy = "approval_required"
    db_session.commit()

    # Create approval in pending state
    approval = ApprovalService.create_approval_request(
        db=db_session,
        workspace_id=env["ws_primary"].id,
        policy_decision_id=env["decision_primary"].id,
        requested_by=env["user_eng"],
    )
    assert approval.approval_status == "pending"

    # Execution attempted while unapproved (pending)
    with pytest.raises(HTTPException) as exc_info:
        RemediationExecutionManager.create_execution(
            db=db_session,
            workspace_id=env["ws_primary"].id,
            approval_id=approval.id,
            triggered_by=env["user_admin"],
            user_role="admin",
            idempotency_key=str(uuid.uuid4()),
        )
    assert exc_info.value.status_code == 409
    assert "pending" in exc_info.value.detail.lower()


def test_correction_a_demo_allowlisted_action_development(db_session, safety_test_env):
    """Scenario 5: demo + allowlisted demo action in development -> Risk/approval rules preserved."""
    env = safety_test_env
    env["svc_primary"].execution_policy = "demo"
    env["svc_primary"].environment = "development"
    db_session.commit()

    # restore_order_api_demo requires human approval per registry policy
    res = PolicyEngine.evaluate(
        workspace_id=env["ws_primary"].id,
        user_role="engineer",
        action_id="restore_order_api_demo",
        parameters={"service_id": env["svc_primary"].id},
        environment="development",
        db=db_session,
    )
    assert res.decision == PolicyDecisionType.APPROVAL_REQUIRED
    assert res.approval_required is True
    assert res.risk_level == "medium"

    # inspect_service_health is diagnostic and allowed without approval
    res_diag = PolicyEngine.evaluate(
        workspace_id=env["ws_primary"].id,
        user_role="engineer",
        action_id="inspect_service_health",
        parameters={"service_id": env["svc_primary"].id},
        environment="development",
        db=db_session,
    )
    assert res_diag.decision == PolicyDecisionType.ALLOWED
    assert res_diag.approval_required is False


def test_correction_a_demo_unsupported_production_environment_rejected(db_session, safety_test_env):
    """Scenario 6: demo + unsupported production environment -> Rejected."""
    env = safety_test_env
    env["svc_primary"].execution_policy = "demo"
    env["svc_primary"].environment = "production"
    db_session.commit()

    # Case A: Service is in production, evaluated with environment='development'
    res_dev = PolicyEngine.evaluate(
        workspace_id=env["ws_primary"].id,
        user_role="engineer",
        action_id="restore_order_api_demo",
        parameters={"service_id": env["svc_primary"].id},
        environment="development",
        db=db_session,
    )
    assert res_dev.decision == PolicyDecisionType.REJECTED
    assert "restricted to the 'development' environment" in res_dev.decision_reason

    # Case B: Evaluated with environment='production'
    res_prod = PolicyEngine.evaluate(
        workspace_id=env["ws_primary"].id,
        user_role="engineer",
        action_id="restore_order_api_demo",
        parameters={"service_id": env["svc_primary"].id},
        environment="production",
        db=db_session,
    )
    assert res_prod.decision == PolicyDecisionType.REJECTED
    assert "Unsupported environment 'production'" in res_prod.decision_reason


def test_correction_a_unknown_execution_policy_rejected(db_session, safety_test_env):
    """Scenario 7: Unknown execution policy -> Rejected (fail closed)."""
    env = safety_test_env
    env["svc_primary"].execution_policy = "unrecognized_policy_xyz"
    db_session.commit()

    # Policy evaluation fails closed
    res = PolicyEngine.evaluate(
        workspace_id=env["ws_primary"].id,
        user_role="engineer",
        action_id="restart_order_api",
        parameters={"service_id": env["svc_primary"].id},
        environment="development",
        db=db_session,
    )
    assert res.decision == PolicyDecisionType.REJECTED
    assert "invalid or unsupported execution policy" in res.decision_reason.lower()

    # Approval creation fails closed
    with pytest.raises(HTTPException) as exc_info:
        ApprovalService.create_approval_request(
            db=db_session,
            workspace_id=env["ws_primary"].id,
            policy_decision_id=env["decision_primary"].id,
            requested_by=env["user_eng"],
        )
    assert exc_info.value.status_code == 400
    assert "invalid or unsupported execution policy" in exc_info.value.detail.lower()


def test_correction_a_null_execution_policy_rejected(db_session, safety_test_env, monkeypatch):
    """Scenario 8: Null execution policy -> Rejected (fail closed)."""
    env = safety_test_env
    svc = env["svc_primary"]

    # 1. Test whitespace-only string (committed in DB)
    svc.execution_policy = "   "
    db_session.commit()

    res_empty = PolicyEngine.evaluate(
        workspace_id=env["ws_primary"].id,
        user_role="engineer",
        action_id="restart_order_api",
        parameters={"service_id": svc.id},
        environment="development",
        db=db_session,
    )
    assert res_empty.decision == PolicyDecisionType.REJECTED
    assert "null or missing execution policy" in res_empty.decision_reason.lower()

    # 2. Test literal None via query proxy (simulating null column from DB)
    original_query = db_session.query

    class QueryProxy:
        def __init__(self, target):
            self.target = target
        def filter(self, *args, **kwargs):
            return self
        def first(self):
            svc.execution_policy = None
            return svc
        def all(self):
            return [svc]
        def with_for_update(self):
            return self

    def fake_query(model):
        if model is Service:
            return QueryProxy(model)
        return original_query(model)

    monkeypatch.setattr(db_session, "query", fake_query)

    # Policy evaluation fails closed on None
    res_none = PolicyEngine.evaluate(
        workspace_id=env["ws_primary"].id,
        user_role="engineer",
        action_id="restart_order_api",
        parameters={"service_id": svc.id},
        environment="development",
        db=db_session,
    )
    assert res_none.decision == PolicyDecisionType.REJECTED
    assert "null or missing execution policy" in res_none.decision_reason.lower()

    # Approval creation fails closed on None
    with pytest.raises(HTTPException) as exc_info:
        ApprovalService.create_approval_request(
            db=db_session,
            workspace_id=env["ws_primary"].id,
            policy_decision_id=env["decision_primary"].id,
            requested_by=env["user_eng"],
        )
    assert exc_info.value.status_code == 400
    assert "null or missing execution policy" in exc_info.value.detail.lower()


def test_correction_a_service_policy_changed_after_approval_to_observe_only_rejected(db_session, safety_test_env):
    """Scenario 9: Service policy changed after approval to observe_only -> Execution rejected."""
    env = safety_test_env
    svc = env["svc_primary"]
    svc.execution_policy = "approval_required"
    env["decision_primary"].action_id = "restore_order_api_demo"
    env["decision_primary"].suggested_parameters = {"service_id": svc.id}
    db_session.commit()

    # Create and approve request
    approval = ApprovalService.create_approval_request(
        db=db_session,
        workspace_id=env["ws_primary"].id,
        policy_decision_id=env["decision_primary"].id,
        requested_by=env["user_eng"],
    )
    approval = ApprovalService.approve_request(
        db=db_session,
        approval_id=approval.id,
        workspace_id=env["ws_primary"].id,
        reviewer=env["user_admin"],
        user_role="admin",
    )
    assert approval.approval_status == "approved"

    # Service execution policy changed after approval
    svc.execution_policy = "observe_only"
    db_session.commit()

    # RemediationExecutionManager pre-dispatch check rejects execution
    with pytest.raises(PreconditionFailedError) as exc_info:
        RemediationExecutionManager.create_execution(
            db=db_session,
            workspace_id=env["ws_primary"].id,
            approval_id=approval.id,
            triggered_by=env["user_admin"],
            user_role="admin",
            idempotency_key=str(uuid.uuid4()),
        )
    assert "observe_only" in str(exc_info.value)

    # Worker preflight check also rejects if an execution was queued
    # Simulate an execution record already queued before policy switch
    exec_id = str(uuid.uuid4())
    manifest, manifest_signature, manifest_digest = generate_and_sign_execution_manifest(
        execution_id=exec_id,
        approval=approval,
        service=svc,
    )
    exec_record = RemediationExecution(
        id=exec_id,
        workspace_id=env["ws_primary"].id,
        approval_id=approval.id,
        action_id=approval.action_id,
        target_service_id=svc.id,
        approved_parameters=approval.validated_parameters or {},
        status="queued",
        idempotency_key=f"idem-{uuid.uuid4().hex[:8]}",
        fencing_token=0,
        triggered_by=env["user_admin"].id,
        timeout_seconds=30,
        attempt_count=0,
        max_attempts=1,
        manifest_id=manifest.manifest_id,
        authorization_manifest=manifest.model_dump(),
        manifest_signature=manifest_signature,
        manifest_digest=manifest_digest,
        manifest_key_id=manifest.key_id,
        manifest_expires_at=datetime.fromtimestamp(manifest.expires_at, tz=timezone.utc),
    )
    db_session.add(exec_record)
    db_session.commit()

    worker = DurableExecutionWorker(
        worker_id="test-worker-safety",
        workspace_id=env["ws_primary"].id,
        db_factory=lambda: db_session,
        poll_interval=0.01,
        lease_seconds=30,
        enable_coordinator=False,
    )
    # run_once processes the queued execution
    processed_id = worker.run_once()
    assert processed_id == exec_record.id

    db_session.refresh(exec_record)
    assert exec_record.status == "execution_failed"
    assert "observe_only" in (exec_record.error_message or "")


# ============================================================================
# Correction B Tests: Validate incident and investigation ownership
# ============================================================================

def test_correction_b_matching_workspace_service_incident_investigation_succeeds(client: TestClient, safety_test_env):
    """Scenario 1: Matching workspace, service, incident and investigation -> Approval creation succeeds."""
    env = safety_test_env
    payload = {
        "workspace_id": env["ws_primary"].id,
        "policy_decision_id": env["decision_primary"].id,
        "incident_id": env["inc_primary"].id,
        "investigation_id": env["inv_primary"].id,
        "expires_in_hours": 24,
    }
    resp = client.post(
        "/api/v1/remediation/approvals",
        json=payload,
        headers={"Authorization": f"Bearer {env['eng_token']}"},
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["incident_id"] == env["inc_primary"].id
    assert data["investigation_id"] == env["inv_primary"].id
    assert data["approval_status"] == "pending"


def test_correction_b_incident_from_another_workspace_rejected(client: TestClient, safety_test_env):
    """Scenario 2: Incident from another workspace -> Rejected (403 Forbidden)."""
    env = safety_test_env
    payload = {
        "workspace_id": env["ws_primary"].id,
        "policy_decision_id": env["decision_primary"].id,
        "incident_id": env["inc_foreign"].id,  # Foreign workspace incident
    }
    resp = client.post(
        "/api/v1/remediation/approvals",
        json=payload,
        headers={"Authorization": f"Bearer {env['eng_token']}"},
    )
    assert resp.status_code == 403
    assert "Cross-workspace violation" in resp.json()["detail"]


def test_correction_b_incident_for_another_service_rejected(client: TestClient, safety_test_env):
    """Scenario 3: Incident for another service -> Rejected (400 Bad Request)."""
    env = safety_test_env
    payload = {
        "workspace_id": env["ws_primary"].id,
        "policy_decision_id": env["decision_primary"].id,  # Targets svc_primary
        "incident_id": env["inc_other_svc"].id,             # Belongs to svc_other
    }
    resp = client.post(
        "/api/v1/remediation/approvals",
        json=payload,
        headers={"Authorization": f"Bearer {env['eng_token']}"},
    )
    assert resp.status_code == 400
    assert "does not match target service" in resp.json()["detail"]


def test_correction_b_investigation_from_another_incident_rejected(client: TestClient, safety_test_env):
    """Scenario 4: Investigation from another incident -> Rejected (400 Bad Request)."""
    env = safety_test_env
    payload = {
        "workspace_id": env["ws_primary"].id,
        "policy_decision_id": env["decision_primary"].id,
        "incident_id": env["inc_primary"].id,
        "investigation_id": env["inv_other_inc"].id,  # Linked to inc_other_svc
    }
    resp = client.post(
        "/api/v1/remediation/approvals",
        json=payload,
        headers={"Authorization": f"Bearer {env['eng_token']}"},
    )
    assert resp.status_code == 400
    assert "does not belong to incident" in resp.json()["detail"]


def test_correction_b_investigation_from_another_workspace_rejected(client: TestClient, safety_test_env):
    """Scenario 5: Investigation from another workspace -> Rejected (403 Forbidden)."""
    env = safety_test_env
    payload = {
        "workspace_id": env["ws_primary"].id,
        "policy_decision_id": env["decision_primary"].id,
        "incident_id": env["inc_primary"].id,
        "investigation_id": env["inv_foreign"].id,  # Foreign workspace investigation
    }
    resp = client.post(
        "/api/v1/remediation/approvals",
        json=payload,
        headers={"Authorization": f"Bearer {env['eng_token']}"},
    )
    assert resp.status_code == 403
    assert "Cross-workspace violation" in resp.json()["detail"]


def test_correction_b_nonexistent_incident_rejected(client: TestClient, safety_test_env):
    """Scenario 6: Nonexistent incident -> Rejected (404 Not Found)."""
    env = safety_test_env
    fake_incident_id = str(uuid.uuid4())
    payload = {
        "workspace_id": env["ws_primary"].id,
        "policy_decision_id": env["decision_primary"].id,
        "incident_id": fake_incident_id,
    }
    resp = client.post(
        "/api/v1/remediation/approvals",
        json=payload,
        headers={"Authorization": f"Bearer {env['eng_token']}"},
    )
    assert resp.status_code == 404
    assert f"Incident '{fake_incident_id}' not found" in resp.json()["detail"]


def test_correction_b_nonexistent_investigation_rejected(client: TestClient, safety_test_env):
    """Scenario 7: Nonexistent investigation -> Rejected (404 Not Found)."""
    env = safety_test_env
    fake_inv_id = str(uuid.uuid4())
    payload = {
        "workspace_id": env["ws_primary"].id,
        "policy_decision_id": env["decision_primary"].id,
        "incident_id": env["inc_primary"].id,
        "investigation_id": fake_inv_id,
    }
    resp = client.post(
        "/api/v1/remediation/approvals",
        json=payload,
        headers={"Authorization": f"Bearer {env['eng_token']}"},
    )
    assert resp.status_code == 404
    assert f"Investigation '{fake_inv_id}' not found" in resp.json()["detail"]


def test_correction_b_investigation_supplied_without_required_incident_rejected(client: TestClient, safety_test_env):
    """Scenario 8: Investigation supplied without required incident -> Rejected (400 Bad Request)."""
    env = safety_test_env
    payload = {
        "workspace_id": env["ws_primary"].id,
        "policy_decision_id": env["decision_primary"].id,
        "investigation_id": env["inv_primary"].id,  # No incident_id supplied
    }
    resp = client.post(
        "/api/v1/remediation/approvals",
        json=payload,
        headers={"Authorization": f"Bearer {env['eng_token']}"},
    )
    assert resp.status_code == 400
    assert "without a corresponding incident_id" in resp.json()["detail"]


def test_correction_b_optional_references_omitted_preserved(client: TestClient, db_session, safety_test_env):
    """Scenario 9: Optional references omitted where supported -> Existing behaviour preserved."""
    env = safety_test_env

    # 1. Both incident_id and investigation_id omitted
    payload1 = {
        "workspace_id": env["ws_primary"].id,
        "policy_decision_id": env["decision_primary"].id,
    }
    resp1 = client.post(
        "/api/v1/remediation/approvals",
        json=payload1,
        headers={"Authorization": f"Bearer {env['eng_token']}"},
    )
    assert resp1.status_code == 201
    data1 = resp1.json()
    assert data1["incident_id"] is None
    assert data1["investigation_id"] is None

    # Cancel approval to allow creating another for the same policy decision
    ApprovalService.cancel_request(
        db=db_session,
        approval_id=data1["id"],
        workspace_id=env["ws_primary"].id,
        user=env["user_eng"],
        user_role="engineer",
    )

    # 2. Only incident_id provided, investigation_id omitted
    payload2 = {
        "workspace_id": env["ws_primary"].id,
        "policy_decision_id": env["decision_primary"].id,
        "incident_id": env["inc_primary"].id,
    }
    resp2 = client.post(
        "/api/v1/remediation/approvals",
        json=payload2,
        headers={"Authorization": f"Bearer {env['eng_token']}"},
    )
    assert resp2.status_code == 201
    data2 = resp2.json()
    assert data2["incident_id"] == env["inc_primary"].id
    assert data2["investigation_id"] is None
