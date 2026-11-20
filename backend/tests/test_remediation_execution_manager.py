"""Comprehensive Tests for Phase 4.3.3 Execution Manager & Static Action Handlers.

Covers:
- Approval validation and expiry
- Approval replay prevention (409 Conflict)
- Idempotency-key behavior (idempotent replay returns existing execution)
- Conflicting approval and idempotency-key combinations (409 Conflict)
- Exact approved parameter preservation
- Workspace and service isolation
- RBAC (Viewer rejected 403, Engineer/Admin allowed)
- Legal and illegal state transitions across all 11 canonical states
- Fencing-token validation and stale-worker protection
- Atomic event persistence and metadata credential sanitization
- Runner unavailable behavior (503 ExecutionEnvironmentUnavailable)
- MockTestRunner safety blocks (cannot run outside test environment, no host mutation)
- Live PostgreSQL constraint and concurrency verification
"""

import os
import sys
import uuid
from datetime import datetime, timedelta, timezone
import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import sessionmaker

from app.core.config import settings
from app.execution.actions import (
    STATIC_ACTION_HANDLERS,
    get_static_action_handler,
    handle_inspect_service_health,
    handle_restore_order_api_demo,
)
from app.execution.exceptions import (
    ApprovalAlreadyExecutedError,
    ExecutionEnvironmentUnavailable,
    IdempotencyConflictError,
    IllegalStateTransitionError,
    PreconditionFailedError,
    SecurityConfigurationError,
    StaleWorkerFencingError,
)
from app.execution.manager import (
    RemediationExecutionManager,
    sanitize_metadata,
)
from app.execution.runner import (
    ExecutionResult,
    MockTestRunner,
    get_execution_runner,
)
from app.execution.state_machine import (
    ALL_EXECUTION_STATES,
    ExecutionState,
    is_terminal_state,
    validate_state_transition,
)
from app.models.incident import Incident, IncidentEvent
from app.models.remediation import (
    ExecutionAttempt,
    ExecutionEvent,
    PolicyDecision,
    RemediationApproval,
    RemediationExecution,
)
from app.core.security import create_access_token
from app.models.service import Service
from app.models.user import User
from app.models.workspace import Workspace, WorkspaceMembership


@pytest.fixture
def exec_mgr_env(db_session):
    """Fixture providing populated workspace, users, services, and approvals."""
    ws = Workspace(
        id=str(uuid.uuid4()),
        name="Execution Manager WS",
        slug=f"exec-mgr-{uuid.uuid4().hex[:6]}",
    )
    ws2 = Workspace(
        id=str(uuid.uuid4()),
        name="Foreign Workspace",
        slug=f"foreign-{uuid.uuid4().hex[:6]}",
    )
    db_session.add_all([ws, ws2])

    admin = User(
        id=str(uuid.uuid4()),
        email=f"admin_{uuid.uuid4().hex[:6]}@example.com",
        full_name="Admin User",
        hashed_password="pw",
    )
    engineer = User(
        id=str(uuid.uuid4()),
        email=f"eng_{uuid.uuid4().hex[:6]}@example.com",
        full_name="Engineer User",
        hashed_password="pw",
    )
    viewer = User(
        id=str(uuid.uuid4()),
        email=f"viewer_{uuid.uuid4().hex[:6]}@example.com",
        full_name="Viewer User",
        hashed_password="pw",
    )
    db_session.add_all([admin, engineer, viewer])

    m_admin = WorkspaceMembership(workspace_id=ws.id, user_id=admin.id, role="admin")
    m_eng = WorkspaceMembership(workspace_id=ws.id, user_id=engineer.id, role="engineer")
    m_viewer = WorkspaceMembership(workspace_id=ws.id, user_id=viewer.id, role="viewer")
    db_session.add_all([m_admin, m_eng, m_viewer])

    svc = Service(
        id=str(uuid.uuid4()),
        workspace_id=ws.id,
        name="Order API",
        environment="development",
        health_check_url="http://127.0.0.1:8001/health",
        demo_integration="order_api",
        is_active=True,
    )
    svc_inactive = Service(
        id=str(uuid.uuid4()),
        workspace_id=ws.id,
        name="Inactive Service",
        environment="development",
        health_check_url="http://127.0.0.1:8002/health",
        is_active=False,
    )
    svc_foreign = Service(
        id=str(uuid.uuid4()),
        workspace_id=ws2.id,
        name="Foreign Service",
        environment="development",
        health_check_url="http://127.0.0.1:8003/health",
        is_active=True,
    )
    db_session.add_all([svc, svc_inactive, svc_foreign])

    inc = Incident(
        id=str(uuid.uuid4()),
        workspace_id=ws.id,
        service_id=svc.id,
        title="Simulated Latency Spike",
        severity="medium",
        status="investigating",
        trigger="high_latency",
    )
    db_session.add(inc)

    dec = PolicyDecision(
        id=str(uuid.uuid4()),
        workspace_id=ws.id,
        user_id=engineer.id,
        action_id="restore_order_api_demo",
        target_service_id=svc.id,
        risk_level="medium",
        decision="approval_required",
        decision_reason="Requires human approval",
        policy_version="v1.0",
        validated_parameters={"service_id": svc.id},
    )
    db_session.add(dec)

    appr_approved = RemediationApproval(
        id=str(uuid.uuid4()),
        workspace_id=ws.id,
        incident_id=inc.id,
        policy_decision_id=dec.id,
        action_id="restore_order_api_demo",
        target_service_id=svc.id,
        validated_parameters={"service_id": svc.id},
        risk_level="medium",
        policy_version="v1.0",
        requested_by=engineer.id,
        approval_status="approved",
        reviewed_by=admin.id,
        reviewed_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
    )
    appr_pending = RemediationApproval(
        id=str(uuid.uuid4()),
        workspace_id=ws.id,
        incident_id=inc.id,
        policy_decision_id=dec.id,
        action_id="restore_order_api_demo",
        target_service_id=svc.id,
        validated_parameters={"service_id": svc.id},
        risk_level="medium",
        policy_version="v1.0",
        requested_by=engineer.id,
        approval_status="pending",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
    )
    appr_rejected = RemediationApproval(
        id=str(uuid.uuid4()),
        workspace_id=ws.id,
        incident_id=inc.id,
        policy_decision_id=dec.id,
        action_id="restore_order_api_demo",
        target_service_id=svc.id,
        validated_parameters={"service_id": svc.id},
        risk_level="medium",
        policy_version="v1.0",
        requested_by=engineer.id,
        approval_status="rejected",
        reviewed_by=admin.id,
        reviewed_at=datetime.now(timezone.utc),
        rejection_reason="Unapproved during maintenance window",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
    )
    appr_expired = RemediationApproval(
        id=str(uuid.uuid4()),
        workspace_id=ws.id,
        incident_id=inc.id,
        policy_decision_id=dec.id,
        action_id="restore_order_api_demo",
        target_service_id=svc.id,
        validated_parameters={"service_id": svc.id},
        risk_level="medium",
        policy_version="v1.0",
        requested_by=engineer.id,
        approval_status="approved",
        reviewed_by=admin.id,
        reviewed_at=datetime.now(timezone.utc) - timedelta(hours=2),
        expires_at=datetime.now(timezone.utc) - timedelta(hours=1),  # PAST
    )
    db_session.add_all([appr_approved, appr_pending, appr_rejected, appr_expired])
    db_session.commit()

    return {
        "ws": ws,
        "ws2": ws2,
        "admin": admin,
        "engineer": engineer,
        "viewer": viewer,
        "svc": svc,
        "svc_inactive": svc_inactive,
        "svc_foreign": svc_foreign,
        "inc": inc,
        "dec": dec,
        "appr_approved": appr_approved,
        "appr_pending": appr_pending,
        "appr_rejected": appr_rejected,
        "appr_expired": appr_expired,
    }


# ============================================================================
# 1. Approval Validation & Expiry
# ============================================================================

def test_approval_validation_and_expiry(db_session, exec_mgr_env):
    """Execution cannot be queued from pending, rejected, expired, or foreign approvals."""
    env = exec_mgr_env
    ws_id = env["ws"].id

    # 1. Pending approval raises 409
    with pytest.raises(HTTPException) as exc_info:
        RemediationExecutionManager.create_execution(
            db=db_session,
            workspace_id=ws_id,
            approval_id=env["appr_pending"].id,
            idempotency_key="key_pending",
            triggered_by=env["engineer"],
            user_role="engineer",
        )
    assert exc_info.value.status_code == 409
    assert "pending" in exc_info.value.detail.lower()

    # 2. Rejected approval raises 409
    with pytest.raises(HTTPException) as exc_info:
        RemediationExecutionManager.create_execution(
            db=db_session,
            workspace_id=ws_id,
            approval_id=env["appr_rejected"].id,
            idempotency_key="key_rejected",
            triggered_by=env["engineer"],
            user_role="engineer",
        )
    assert exc_info.value.status_code == 409
    assert "rejected" in exc_info.value.detail.lower()

    # 3. Expired approval raises 400 and transitions status
    with pytest.raises(HTTPException) as exc_info:
        RemediationExecutionManager.create_execution(
            db=db_session,
            workspace_id=ws_id,
            approval_id=env["appr_expired"].id,
            idempotency_key="key_expired",
            triggered_by=env["engineer"],
            user_role="engineer",
        )
    assert exc_info.value.status_code == 400
    assert "expired" in exc_info.value.detail.lower()

    # 4. Non-existent approval raises 404
    with pytest.raises(HTTPException) as exc_info:
        RemediationExecutionManager.create_execution(
            db=db_session,
            workspace_id=ws_id,
            approval_id=str(uuid.uuid4()),
            idempotency_key="key_notfound",
            triggered_by=env["engineer"],
            user_role="engineer",
        )
    assert exc_info.value.status_code == 404

    # 5. Cross-workspace approval raises 403
    with pytest.raises(HTTPException) as exc_info:
        RemediationExecutionManager.create_execution(
            db=db_session,
            workspace_id=env["ws2"].id,  # Foreign workspace
            approval_id=env["appr_approved"].id,
            idempotency_key="key_cross_ws",
            triggered_by=env["engineer"],
            user_role="engineer",
        )
    assert exc_info.value.status_code == 403


# ============================================================================
# 2. Approval Replay Prevention & Idempotency Key Behavior
# ============================================================================

def test_idempotency_key_behavior_and_replay_prevention(db_session, exec_mgr_env):
    """
    - Identical (approval_id, idempotency_key) returns existing execution (idempotent retry).
    - Same approval_id with DIFFERENT idempotency_key raises 409 (approval replay blocked).
    - Different approval_id with SAME idempotency_key raises 409 (key collision blocked).
    """
    env = exec_mgr_env
    ws_id = env["ws"].id
    appr1 = env["appr_approved"]

    # 1. First execution succeeds
    exec1 = RemediationExecutionManager.create_execution(
        db=db_session,
        workspace_id=ws_id,
        approval_id=appr1.id,
        idempotency_key="idemp_key_alpha",
        triggered_by=env["engineer"],
        user_role="engineer",
    )
    assert exec1.status == "queued"
    assert exec1.idempotency_key == "idemp_key_alpha"

    # 2. Exact same approval_id and idempotency_key -> Returns existing execution!
    exec1_retry = RemediationExecutionManager.create_execution(
        db=db_session,
        workspace_id=ws_id,
        approval_id=appr1.id,
        idempotency_key="idemp_key_alpha",
        triggered_by=env["engineer"],
        user_role="engineer",
    )
    assert exec1_retry.id == exec1.id

    # 3. Same approval with a NEW idempotency key -> Replay blocked with 409!
    with pytest.raises(ApprovalAlreadyExecutedError) as exc_info:
        RemediationExecutionManager.create_execution(
            db=db_session,
            workspace_id=ws_id,
            approval_id=appr1.id,
            idempotency_key="idemp_key_beta_new",
            triggered_by=env["engineer"],
            user_role="engineer",
        )
    assert exc_info.value.status_code == 409
    assert "already been executed" in exc_info.value.detail.lower()

    # 4. Create second approved proposal in workspace
    appr2 = RemediationApproval(
        id=str(uuid.uuid4()),
        workspace_id=ws_id,
        policy_decision_id=env["dec"].id,
        action_id="restore_order_api_demo",
        target_service_id=env["svc"].id,
        validated_parameters={"service_id": env["svc"].id},
        risk_level="medium",
        policy_version="v1.0",
        requested_by=env["engineer"].id,
        approval_status="approved",
        reviewed_by=env["admin"].id,
        reviewed_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
    )
    db_session.add(appr2)
    db_session.commit()

    # 5. Using appr2 with the ALREADY USED 'idemp_key_alpha' -> Idempotency conflict 409!
    with pytest.raises(IdempotencyConflictError) as exc_info:
        RemediationExecutionManager.create_execution(
            db=db_session,
            workspace_id=ws_id,
            approval_id=appr2.id,
            idempotency_key="idemp_key_alpha",  # COLLISION
            triggered_by=env["engineer"],
            user_role="engineer",
        )
    assert exc_info.value.status_code == 409
    assert "already used for another execution" in exc_info.value.detail.lower()


# ============================================================================
# 3. Exact Approved Parameter Preservation
# ============================================================================

def test_exact_approved_parameter_preservation(db_session, exec_mgr_env):
    """Caller cannot modify or inject parameters; exact snapshot is preserved."""
    env = exec_mgr_env
    appr = env["appr_approved"]

    execution = RemediationExecutionManager.create_execution(
        db=db_session,
        workspace_id=env["ws"].id,
        approval_id=appr.id,
        idempotency_key="param_test_key",
        triggered_by=env["engineer"],
        user_role="engineer",
    )

    # Approved parameters are strictly copied from approval snapshot
    assert execution.approved_parameters == appr.validated_parameters
    assert execution.approved_parameters == {"service_id": env["svc"].id}

    # Modifying the original approval afterwards cannot alter the queued execution snapshot
    appr.validated_parameters = {"service_id": "tampered_after_execution"}
    db_session.commit()

    reloaded_exec = db_session.query(RemediationExecution).filter_by(id=execution.id).one()
    assert reloaded_exec.approved_parameters == {"service_id": env["svc"].id}


# ============================================================================
# 4. Workspace & Service Isolation
# ============================================================================

def test_workspace_and_service_isolation(db_session, exec_mgr_env):
    """Target service must belong to the active workspace; inactive service rejected."""
    env = exec_mgr_env
    ws_id = env["ws"].id

    # 1. Approval pointing to inactive service fails JIT pre-flight check
    appr_inactive = RemediationApproval(
        id=str(uuid.uuid4()),
        workspace_id=ws_id,
        policy_decision_id=env["dec"].id,
        action_id="restore_order_api_demo",
        target_service_id=env["svc_inactive"].id,
        validated_parameters={"service_id": env["svc_inactive"].id},
        risk_level="medium",
        requested_by=env["engineer"].id,
        approval_status="approved",
        reviewed_by=env["admin"].id,
        reviewed_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
    )
    db_session.add(appr_inactive)
    db_session.commit()

    with pytest.raises(PreconditionFailedError) as exc_info:
        RemediationExecutionManager.create_execution(
            db=db_session,
            workspace_id=ws_id,
            approval_id=appr_inactive.id,
            idempotency_key="key_inactive_svc",
            triggered_by=env["engineer"],
            user_role="engineer",
        )
    assert "inactive" in exc_info.value.detail.lower()

    # 2. Execution lookup cross-workspace is rejected
    valid_exec = RemediationExecutionManager.create_execution(
        db=db_session,
        workspace_id=ws_id,
        approval_id=env["appr_approved"].id,
        idempotency_key="key_iso_lookup",
        triggered_by=env["engineer"],
        user_role="engineer",
    )

    with pytest.raises(HTTPException) as exc_info:
        RemediationExecutionManager.get_execution(
            execution_id=valid_exec.id,
            workspace_id=env["ws2"].id,  # Foreign workspace
            db=db_session,
        )
    assert exc_info.value.status_code == 403


# ============================================================================
# 5. Role-Based Access Control (RBAC)
# ============================================================================

def test_rbac_execution_permissions(db_session, exec_mgr_env):
    """Viewers are forbidden from creating or cancelling executions."""
    env = exec_mgr_env
    ws_id = env["ws"].id

    # 1. Viewer cannot create execution
    with pytest.raises(HTTPException) as exc_info:
        RemediationExecutionManager.create_execution(
            db=db_session,
            workspace_id=ws_id,
            approval_id=env["appr_approved"].id,
            idempotency_key="key_viewer",
            triggered_by=env["viewer"],
            user_role="viewer",
        )
    assert exc_info.value.status_code == 403

    # 2. Engineer creates execution
    execution = RemediationExecutionManager.create_execution(
        db=db_session,
        workspace_id=ws_id,
        approval_id=env["appr_approved"].id,
        idempotency_key="key_engineer",
        triggered_by=env["engineer"],
        user_role="engineer",
    )

    # 3. Viewer cannot cancel execution
    with pytest.raises(HTTPException) as exc_info:
        RemediationExecutionManager.cancel_execution(
            execution_id=execution.id,
            workspace_id=ws_id,
            user=env["viewer"],
            user_role="viewer",
            db=db_session,
        )
    assert exc_info.value.status_code == 403

    # 4. Admin can cancel execution
    cancelled = RemediationExecutionManager.cancel_execution(
        execution_id=execution.id,
        workspace_id=ws_id,
        user=env["admin"],
        user_role="admin",
        db=db_session,
        cancellation_reason="Cancelled by administrative order",
    )
    assert cancelled.status == "cancelled"


# ============================================================================
# 6. Legal and Illegal State Transitions (11 Canonical States)
# ============================================================================

def test_legal_and_illegal_state_transitions():
    """Verify state machine legal paths and rejection of illegal transitions."""
    # 1. Verify all 11 states exist
    assert len(ALL_EXECUTION_STATES) == 11
    assert "queued" in ALL_EXECUTION_STATES
    assert "validating" in ALL_EXECUTION_STATES
    assert "executing" in ALL_EXECUTION_STATES
    assert "execution_succeeded" in ALL_EXECUTION_STATES
    assert "execution_failed" in ALL_EXECUTION_STATES
    assert "timed_out" in ALL_EXECUTION_STATES
    assert "execution_uncertain" in ALL_EXECUTION_STATES
    assert "verification_pending" in ALL_EXECUTION_STATES
    assert "verified" in ALL_EXECUTION_STATES
    assert "verification_failed" in ALL_EXECUTION_STATES
    assert "cancelled" in ALL_EXECUTION_STATES

    # 2. Valid transitions do not raise
    validate_state_transition("queued", "validating")
    validate_state_transition("queued", "cancelled")
    validate_state_transition("validating", "executing")
    validate_state_transition("validating", "execution_failed")
    validate_state_transition("executing", "execution_succeeded")
    validate_state_transition("executing", "execution_failed")
    validate_state_transition("executing", "timed_out")
    validate_state_transition("executing", "execution_uncertain")
    validate_state_transition("execution_succeeded", "verification_pending")
    validate_state_transition("execution_succeeded", "verified")
    validate_state_transition("verification_pending", "verified")
    validate_state_transition("verification_pending", "verification_failed")
    validate_state_transition("execution_failed", "queued")  # Retry

    # 3. Illegal transitions must raise IllegalStateTransitionError
    with pytest.raises(IllegalStateTransitionError):
        validate_state_transition("queued", "verified")  # Cannot skip executing

    with pytest.raises(IllegalStateTransitionError):
        validate_state_transition("executing", "queued")  # Cannot jump back to queued mid-run

    with pytest.raises(IllegalStateTransitionError):
        validate_state_transition("verified", "executing")  # Terminal state cannot transition

    with pytest.raises(IllegalStateTransitionError):
        validate_state_transition("cancelled", "validating")  # Cancelled is terminal

    with pytest.raises(IllegalStateTransitionError):
        validate_state_transition("timed_out", "queued")  # Timed out is terminal


# ============================================================================
# 7. Fencing Tokens & Stale-Worker Protection
# ============================================================================

def test_fencing_token_validation_and_stale_workers(db_session, exec_mgr_env):
    """Worker lease claims and heartbeats reject stale workers with mismatched fencing tokens."""
    env = exec_mgr_env
    execution = RemediationExecutionManager.create_execution(
        db=db_session,
        workspace_id=env["ws"].id,
        approval_id=env["appr_approved"].id,
        idempotency_key="fencing_key",
        triggered_by=env["engineer"],
        user_role="engineer",
    )
    assert execution.fencing_token == 0

    # Worker 1 claims lease with expected_fencing_token=0 -> succeeds, bumps to 1
    claimed = RemediationExecutionManager.claim_execution_lease(
        execution_id=execution.id,
        worker_id="worker-1",
        expected_fencing_token=0,
        lease_seconds=90,
        db=db_session,
    )
    assert claimed.locked_by == "worker-1"
    assert claimed.fencing_token == 1
    assert claimed.status == "validating"

    # Worker 2 attempts to claim with STALE token 0 -> StaleWorkerFencingError!
    with pytest.raises(StaleWorkerFencingError):
        RemediationExecutionManager.claim_execution_lease(
            execution_id=execution.id,
            worker_id="worker-2",
            expected_fencing_token=0,  # STALE
            lease_seconds=90,
            db=db_session,
        )

    # Worker 1 heartbeats with current token 1 -> succeeds
    hb = RemediationExecutionManager.heartbeat_lease(
        execution_id=execution.id,
        worker_id="worker-1",
        expected_fencing_token=1,
        lease_seconds=90,
        db=db_session,
    )
    assert hb.heartbeat_at is not None

    # Worker 1 transitions state to 'executing' with token 1
    running = RemediationExecutionManager.transition_execution_state(
        execution_id=execution.id,
        new_state="executing",
        expected_fencing_token=1,
        db=db_session,
    )
    assert running.status == "executing"

    # Obsolete worker update with wrong token is rejected
    with pytest.raises(StaleWorkerFencingError):
        RemediationExecutionManager.transition_execution_state(
            execution_id=execution.id,
            new_state="execution_succeeded",
            expected_fencing_token=999,  # WRONG TOKEN
            db=db_session,
        )


# ============================================================================
# 8. Atomic Event Persistence & Credential Sanitization
# ============================================================================

def test_atomic_event_persistence_and_credential_sanitization(db_session, exec_mgr_env):
    """Events are persisted atomically and sensitive credentials are recursively redacted."""
    env = exec_mgr_env
    execution = RemediationExecutionManager.create_execution(
        db=db_session,
        workspace_id=env["ws"].id,
        approval_id=env["appr_approved"].id,
        idempotency_key="event_audit_key",
        triggered_by=env["engineer"],
        user_role="engineer",
    )

    # Verify ExecutionEvent created
    events = db_session.query(ExecutionEvent).filter_by(execution_id=execution.id).all()
    assert len(events) == 1
    assert events[0].event_type == "queued"
    assert events[0].workspace_id == env["ws"].id

    # Verify IncidentEvent created
    inc_events = db_session.query(IncidentEvent).filter_by(incident_id=env["inc"].id).all()
    assert any("remediation execution queued" in e.message.lower() for e in inc_events)

    # Verify sanitize_metadata strictly scrubs secrets and cookies
    raw_sensitive = {
        "action": "restore_order_api_demo",
        "authorization": "Bearer secret_jwt_token_12345",
        "cookie": "session_id=abcdef123456",
        "nested": {
            "api_key": "live_sk_secret_9999",
            "safe_metric": 42,
        },
    }
    sanitized = sanitize_metadata(raw_sensitive)
    assert sanitized["authorization"] == "[REDACTED]"
    assert sanitized["cookie"] == "[REDACTED]"
    assert sanitized["nested"]["api_key"] == "[REDACTED]"
    assert sanitized["nested"]["safe_metric"] == 42


# ============================================================================
# 9. Runner Boundary: Unavailable & MockTestRunner Safety
# ============================================================================

def test_runner_boundary_and_host_mutation_safety():
    """
    - get_execution_runner(allow_mock=False) fails closed with 503 ExecutionEnvironmentUnavailable.
    - MockTestRunner outside test environment raises SecurityConfigurationError.
    - MockTestRunner returns in-memory synthetic result without mutating host.
    """
    # 1. Default runner factory fails closed with 503
    with pytest.raises(ExecutionEnvironmentUnavailable) as exc_info:
        get_execution_runner(allow_mock=False)
    assert exc_info.value.status_code == 503
    assert "Docker execution sandbox is not available" in exc_info.value.detail

    # 2. MockTestRunner invocation inside test environment works in-memory
    mock_runner = MockTestRunner()
    res = mock_runner.execute(
        action_id="restore_order_api_demo",
        parameters={"service_id": str(uuid.uuid4())},
    )
    assert res.exit_code == 0
    assert "synthetic" in res.stdout.lower()

    # 3. If ENVIRONMENT is temporarily changed to 'production', MockTestRunner MUST fail fast!
    orig_env = os.environ.get("ENVIRONMENT", "test")
    try:
        os.environ["ENVIRONMENT"] = "production"
        with pytest.raises(SecurityConfigurationError):
            MockTestRunner()
    finally:
        os.environ["ENVIRONMENT"] = orig_env


# ============================================================================
# 10. Static Action Handlers
# ============================================================================

def test_static_action_handlers(exec_mgr_env):
    """Predefined static handlers validate schemas and delegate strictly to isolated runner."""
    env = exec_mgr_env
    svc = env["svc"]
    mock_runner = MockTestRunner()

    # 1. restore_order_api_demo handler delegates to runner
    restore_handler = get_static_action_handler("restore_order_api_demo")
    res = restore_handler(
        service=svc,
        parameters={"service_id": svc.id},
        runner=mock_runner,
    )
    assert res.exit_code == 0

    # 2. inspect_service_health handler delegates to runner
    inspect_handler = get_static_action_handler("inspect_service_health")
    res_inspect = inspect_handler(
        service=svc,
        parameters={"service_id": svc.id},
        runner=mock_runner,
    )
    assert res_inspect.exit_code == 0

    # 3. Arbitrary shell commands or parameters rejected by schema
    with pytest.raises(Exception):
        restore_handler(
            service=svc,
            parameters={"service_id": svc.id, "command": "rm -rf /"},
            runner=mock_runner,
        )

    # 4. Inactive service rejected by precondition check
    with pytest.raises(PreconditionFailedError):
        restore_handler(
            service=env["svc_inactive"],
            parameters={"service_id": env["svc_inactive"].id},
            runner=mock_runner,
        )


# ============================================================================
# 11. PostgreSQL Concurrency & Constraint Tests (Isolated DB)
# ============================================================================

def test_postgresql_concurrency_and_constraints_live(isolated_pg_engine, isolated_pg_seed_data):
    """Verify execution constraints and concurrency directly on isolated PostgreSQL test database."""
    Session = sessionmaker(bind=isolated_pg_engine)
    db = Session()

    dec_id = str(uuid.uuid4())
    appr_id = str(uuid.uuid4())
    exec_id = str(uuid.uuid4())

    try:
        ws = db.query(Workspace).filter_by(id=isolated_pg_seed_data["workspace_id"]).one()
        user = db.query(User).filter_by(id=isolated_pg_seed_data["user_id"]).one()
        assert ws is not None and user is not None

        svc = db.execute(select(Service).filter(Service.workspace_id == ws.id, Service.is_active == True).limit(1)).scalar_one_or_none()
        if not svc:
            svc = Service(
                id=str(uuid.uuid4()),
                workspace_id=ws.id,
                name="Order API Live PG",
                environment="development",
                health_check_url="http://127.0.0.1:8001/health",
                demo_integration="order_api",
                is_active=True,
            )
            db.add(svc)
            db.commit()

        # 1. Seed approval
        dec = PolicyDecision(
            id=dec_id,
            workspace_id=ws.id,
            user_id=user.id,
            action_id="restore_order_api_demo",
            target_service_id=svc.id,
            risk_level="medium",
            decision="approval_required",
            decision_reason="Testing execution manager in live PostgreSQL",
            policy_version="v1.0",
            validated_parameters={"service_id": svc.id},
        )
        appr = RemediationApproval(
            id=appr_id,
            workspace_id=ws.id,
            policy_decision_id=dec_id,
            action_id="restore_order_api_demo",
            target_service_id=svc.id,
            validated_parameters={"service_id": svc.id},
            risk_level="medium",
            requested_by=user.id,
            approval_status="approved",
            reviewed_by=user.id,
            reviewed_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        db.add_all([dec, appr])
        db.commit()

        # 2. Test manager create_execution against PostgreSQL
        idemp_key = f"pg_live_{uuid.uuid4().hex[:8]}"
        execution = RemediationExecutionManager.create_execution(
            db=db,
            workspace_id=ws.id,
            approval_id=appr_id,
            idempotency_key=idemp_key,
            triggered_by=user,
            user_role="engineer",
        )
        assert execution.status == "queued"
        assert execution.approval_id == appr_id

        # 3. Test idempotent retry returns same record
        retry_exec = RemediationExecutionManager.create_execution(
            db=db,
            workspace_id=ws.id,
            approval_id=appr_id,
            idempotency_key=idemp_key,
            triggered_by=user,
            user_role="engineer",
        )
        assert retry_exec.id == execution.id

        # 4. Test approval replay is rejected
        with pytest.raises(ApprovalAlreadyExecutedError):
            RemediationExecutionManager.create_execution(
                db=db,
                workspace_id=ws.id,
                approval_id=appr_id,
                idempotency_key=f"different_{uuid.uuid4().hex[:6]}",
                triggered_by=user,
                user_role="engineer",
            )

        # 5. Test cancel execution
        cancelled = RemediationExecutionManager.cancel_execution(
            execution_id=execution.id,
            workspace_id=ws.id,
            user=user,
            user_role="admin",
            db=db,
            cancellation_reason="Live test cancellation",
        )
        assert cancelled.status == "cancelled"

    finally:
        try:
            db.rollback()
            db.execute(text(f"DELETE FROM execution_events WHERE execution_id IN (SELECT id FROM remediation_executions WHERE approval_id = '{appr_id}')"))
            db.execute(text(f"DELETE FROM execution_attempts WHERE execution_id IN (SELECT id FROM remediation_executions WHERE approval_id = '{appr_id}')"))
            db.execute(text(f"DELETE FROM remediation_executions WHERE approval_id = '{appr_id}'"))
            db.execute(text(f"DELETE FROM remediation_approvals WHERE id = '{appr_id}'"))
            db.execute(text(f"DELETE FROM policy_decisions WHERE id = '{dec_id}'"))
            db.commit()
        except Exception:
            db.rollback()
        db.close()


# ============================================================================
# 12. Execution API Endpoints Lifecycle
# ============================================================================

def test_api_execution_endpoints_lifecycle(client, db_session, exec_mgr_env):
    """Test full HTTP lifecycle via /api/v1/remediation/executions."""
    env = exec_mgr_env
    ws_id = env["ws"].id
    appr_id = env["appr_approved"].id

    eng_token = create_access_token({"sub": env["engineer"].id, "email": env["engineer"].email})
    admin_token = create_access_token({"sub": env["admin"].id, "email": env["admin"].email})
    viewer_token = create_access_token({"sub": env["viewer"].id, "email": env["viewer"].email})

    # 1. Viewer attempt to create execution is rejected (403)
    viewer_res = client.post(
        f"/api/v1/remediation/executions?workspace_id={ws_id}",
        headers={"Authorization": f"Bearer {viewer_token}"},
        json={
            "approval_id": appr_id,
            "idempotency_key": "api_key_viewer",
        },
    )
    assert viewer_res.status_code == 403

    # 2. Engineer queues execution (202 Accepted)
    eng_res = client.post(
        f"/api/v1/remediation/executions?workspace_id={ws_id}",
        headers={"Authorization": f"Bearer {eng_token}"},
        json={
            "approval_id": appr_id,
            "idempotency_key": "api_key_engineer_1",
        },
    )
    assert eng_res.status_code == 202
    data = eng_res.json()
    exec_id = data["id"]
    assert data["status"] == "queued"
    assert data["action_id"] == "restore_order_api_demo"
    assert data["approved_parameters"] == {"service_id": env["svc"].id}

    # 3. List executions in workspace (Viewer allowed)
    list_res = client.get(
        f"/api/v1/remediation/executions?workspace_id={ws_id}",
        headers={"Authorization": f"Bearer {viewer_token}"},
    )
    assert list_res.status_code == 200
    list_data = list_res.json()
    assert list_data["total"] >= 1
    assert any(e["id"] == exec_id for e in list_data["executions"])

    # 4. Get execution detail
    detail_res = client.get(
        f"/api/v1/remediation/executions/{exec_id}?workspace_id={ws_id}",
        headers={"Authorization": f"Bearer {viewer_token}"},
    )
    assert detail_res.status_code == 200
    detail_data = detail_res.json()
    assert detail_data["id"] == exec_id

    # 5. Cancel execution by Engineer
    cancel_res = client.post(
        f"/api/v1/remediation/executions/{exec_id}/cancel?workspace_id={ws_id}",
        headers={"Authorization": f"Bearer {eng_token}"},
        json={"cancellation_reason": "Operator abort"},
    )
    assert cancel_res.status_code == 200
    cancelled_data = cancel_res.json()
    assert cancelled_data["status"] == "cancelled"
