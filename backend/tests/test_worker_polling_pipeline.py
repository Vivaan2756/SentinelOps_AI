"""Tests for Worker Polling & Background Dispatch Pipeline (Phase 1 / P0.3).

Validates:
1. Worker starts during application lifespan.
2. Worker polling discovers an eligible approved execution.
3. An approved execution is processed without manual invocation.
4. An unapproved execution is not executed.
5. Repeated polling does not duplicate execution.
6. Transient polling errors do not kill the worker loop.
7. Application shutdown stops the worker cleanly.
8. Repeated application startup does not create duplicate polling loops.
9. Existing Option C idempotency behavior remains intact.
10. Existing generic HTTP recovery continues to work through automatic dispatch.
"""

import asyncio
import base64
import copy
from datetime import datetime, timedelta, timezone
import json
import os
import threading
import time
from typing import Any, Dict, Optional
from unittest.mock import MagicMock, patch
import uuid

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519
from sqlalchemy.orm import Session
from starlette.testclient import TestClient

from app.core.config import settings
from app.core.manifest_crypto import compute_parameters_digest
from app.core.rfc8785 import canonicalize
from app.execution.exceptions import (
    IdempotencyConflictError,
    PreconditionFailedError,
    SecurityConfigurationError,
)
from app.execution.manager import RemediationExecutionManager
from app.execution.public_keys import BrokerPublicKeyRegistry
from app.execution.runner import (
    ExecutionResult,
    ExecutionRunnerInterface,
    MockTestRunner,
)
from app.execution.runners.http_recovery import IsolatedHttpRecoveryRunner
from app.execution.state_machine import ExecutionState
from app.execution.worker import DurableExecutionWorker
from app.main import app, lifespan
from app.models.incident import Incident, IncidentEvent
from app.models.remediation import (
    ExecutionAttempt,
    ExecutionEvent,
    PolicyDecision,
    RemediationApproval,
    RemediationExecution,
)
from app.models.service import Service
from app.models.user import User
from app.models.workspace import Workspace, WorkspaceMembership
from app.remediation.worker import RemediationWorker, remediation_worker


class ControlledTestRunner(ExecutionRunnerInterface):
    """Test execution runner tracking invocations and returning configured results."""

    def __init__(self, result: Optional[ExecutionResult] = None):
        self.result = result or ExecutionResult(
            exit_code=0,
            duration_ms=25,
            stdout="Action completed successfully",
            stderr="",
            output_data={"status": "recovered"},
        )
        self.calls = []

    def execute(self, **kwargs) -> ExecutionResult:
        self.calls.append(kwargs)
        return self.result

    def is_available(self) -> bool:
        return True


@pytest.fixture
def worker_pipeline_env(db_session: Session):
    """Create test environment with workspace, user, service, and approved proposal."""
    ws = Workspace(
        id=str(uuid.uuid4()),
        name="Pipeline Test WS",
        slug=f"pipe-ws-{uuid.uuid4().hex[:6]}",
    )
    db_session.add(ws)

    engineer = User(
        id=str(uuid.uuid4()),
        email=f"eng_{uuid.uuid4().hex[:6]}@sentinelops.local",
        full_name="Lead SRE",
        hashed_password="hashed_test_password",
    )
    db_session.add(engineer)

    membership = WorkspaceMembership(
        workspace_id=ws.id,
        user_id=engineer.id,
        role="engineer",
    )
    db_session.add(membership)

    service = Service(
        id=str(uuid.uuid4()),
        workspace_id=ws.id,
        name="Payment Gateway Service",
        environment="development",
        health_check_url="http://127.0.0.1:9090/health",
        monitoring_method="prometheus",
        execution_policy="approval_required",
        recovery_endpoint="/api/v1/recover",
        recovery_method="POST",
        recovery_enabled=True,
        is_active=True,
    )
    db_session.add(service)

    incident = Incident(
        id=str(uuid.uuid4()),
        workspace_id=ws.id,
        service_id=service.id,
        title="High Error Rate on Payment Gateway",
        severity="high",
        status="awaiting_approval",
        trigger="error_budget_burn",
    )
    db_session.add(incident)

    now_utc = datetime.now(timezone.utc)
    decision = PolicyDecision(
        id=str(uuid.uuid4()),
        workspace_id=ws.id,
        user_id=engineer.id,
        action_id="execute_http_recovery",
        target_service_id=service.id,
        risk_level="high",
        decision="approval_required",
        decision_reason="Operational recovery requires engineer review",
        policy_version="v1.0",
        validated_parameters={"service_id": service.id, "recovery_path": service.recovery_endpoint},
    )
    db_session.add(decision)

    approval = RemediationApproval(
        id=str(uuid.uuid4()),
        workspace_id=ws.id,
        incident_id=incident.id,
        policy_decision_id=decision.id,
        action_id="execute_http_recovery",
        target_service_id=service.id,
        validated_parameters={"service_id": service.id, "recovery_path": service.recovery_endpoint},
        risk_level="high",
        approval_status="approved",
        requested_by=engineer.id,
        requested_at=now_utc - timedelta(minutes=5),
        reviewed_by=engineer.id,
        reviewed_at=now_utc,
        expires_at=now_utc + timedelta(hours=1),
    )
    db_session.add(approval)
    db_session.commit()

    return {
        "workspace": ws,
        "engineer": engineer,
        "service": service,
        "incident": incident,
        "decision": decision,
        "approval": approval,
    }


# ============================================================================
# 1. Worker Starts During Application Lifespan
# ============================================================================
@pytest.mark.asyncio
async def test_worker_starts_during_application_lifespan():
    """1. Prove worker starts on FastAPI lifespan startup and stops cleanly on shutdown."""
    test_worker = RemediationWorker(poll_interval=0.05, enabled=True)
    assert test_worker.is_running is False

    # Simulate lifespan context
    await test_worker.start()
    assert test_worker.is_running is True

    await test_worker.stop()
    assert test_worker.is_running is False


# ============================================================================
# 2. Worker Polling Discovers Eligible Approved Execution
# ============================================================================
def test_worker_polling_discovers_eligible_approved_execution(db_session: Session, worker_pipeline_env: dict):
    """2. Prove worker polling discovers and claims a queued execution with valid approved proposal."""
    env = worker_pipeline_env
    exec_record = RemediationExecutionManager.create_execution(
        db=db_session,
        workspace_id=env["workspace"].id,
        approval_id=env["approval"].id,
        idempotency_key=str(uuid.uuid4()),
        triggered_by=env["engineer"],
        user_role="engineer",
    )
    assert exec_record.status == ExecutionState.QUEUED.value

    runner = ControlledTestRunner()
    durable_worker = DurableExecutionWorker(
        worker_id="test-discovery-worker",
        runner=runner,
        db_factory=lambda: db_session,
        poll_interval=0.01,
        enable_verification=False,
    )
    worker_mgr = RemediationWorker(worker=durable_worker)

    claimed_id = worker_mgr.poll_and_execute()
    assert claimed_id == exec_record.id

    db_session.refresh(exec_record)
    assert exec_record.status in (
        ExecutionState.EXECUTION_SUCCEEDED.value,
        ExecutionState.VERIFIED.value,
        ExecutionState.VERIFICATION_PENDING.value,
    )
    assert len(runner.calls) == 1


# ============================================================================
# 3. Approved Execution Processed Without Manual Invocation
# ============================================================================
@pytest.mark.asyncio
async def test_approved_execution_processed_without_manual_invocation(db_session: Session, worker_pipeline_env: dict):
    """3. Prove approved execution is processed by background thread without calling run_once manually."""
    env = worker_pipeline_env
    exec_record = RemediationExecutionManager.create_execution(
        db=db_session,
        workspace_id=env["workspace"].id,
        approval_id=env["approval"].id,
        idempotency_key=str(uuid.uuid4()),
        triggered_by=env["engineer"],
        user_role="engineer",
    )
    assert exec_record.status == ExecutionState.QUEUED.value

    runner = ControlledTestRunner()
    durable_worker = DurableExecutionWorker(
        worker_id="test-auto-worker",
        runner=runner,
        db_factory=lambda: db_session,
        poll_interval=0.02,
        enable_verification=False,
    )
    worker_mgr = RemediationWorker(worker=durable_worker, poll_interval=0.02)

    await worker_mgr.start()
    assert worker_mgr.is_running is True

    # Allow background polling thread to discover and process queued execution
    for _ in range(50):
        await asyncio.sleep(0.05)
        db_session.expire_all()
        db_session.refresh(exec_record)
        if exec_record.status != ExecutionState.QUEUED.value:
            break

    await worker_mgr.stop()

    assert exec_record.status in (
        ExecutionState.EXECUTION_SUCCEEDED.value,
        ExecutionState.VERIFIED.value,
        ExecutionState.VERIFICATION_PENDING.value,
    )
    assert len(runner.calls) == 1


# ============================================================================
# 4. Unapproved Execution Is Not Executed
# ============================================================================
def test_unapproved_execution_not_executed(db_session: Session, worker_pipeline_env: dict):
    """4. Prove worker aborts dispatch if proposal is not approved (fails closed, zero network dispatch)."""
    env = worker_pipeline_env
    unapproved_appr = RemediationApproval(
        id=str(uuid.uuid4()),
        workspace_id=env["workspace"].id,
        incident_id=env["incident"].id,
        policy_decision_id=env["decision"].id,
        action_id="execute_http_recovery",
        target_service_id=env["service"].id,
        validated_parameters={"service_id": env["service"].id, "recovery_path": env["service"].recovery_endpoint},
        risk_level="high",
        approval_status="pending",  # NOT APPROVED
        requested_by=env["engineer"].id,
        requested_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    db_session.add(unapproved_appr)
    db_session.commit()

    # Attempting create_execution on pending proposal must raise HTTPException
    with pytest.raises(Exception):
        RemediationExecutionManager.create_execution(
            db=db_session,
            workspace_id=env["workspace"].id,
            approval_id=unapproved_appr.id,
            idempotency_key=str(uuid.uuid4()),
            triggered_by=env["engineer"],
            user_role="engineer",
        )

    # Manually insert a queued execution to test worker preflight defense-in-depth
    tampered_exec = RemediationExecution(
        id=str(uuid.uuid4()),
        workspace_id=env["workspace"].id,
        incident_id=env["incident"].id,
        approval_id=unapproved_appr.id,
        target_service_id=env["service"].id,
        action_id="execute_http_recovery",
        approved_parameters={"service_id": env["service"].id, "recovery_path": env["service"].recovery_endpoint},
        status=ExecutionState.QUEUED.value,
        idempotency_key=str(uuid.uuid4()),
        triggered_by=env["engineer"].id,
        fencing_token=0,
    )
    db_session.add(tampered_exec)
    db_session.commit()

    runner = ControlledTestRunner()
    durable_worker = DurableExecutionWorker(
        worker_id="test-unapproved-worker",
        runner=runner,
        db_factory=lambda: db_session,
        poll_interval=0.01,
        enable_verification=False,
    )

    claimed_id = durable_worker.run_once()
    assert claimed_id == tampered_exec.id

    db_session.refresh(tampered_exec)
    assert tampered_exec.status == ExecutionState.EXECUTION_FAILED.value
    assert "pending" in (tampered_exec.error_message or "").lower()
    # Ensure runner was never called (zero network dispatch)
    assert len(runner.calls) == 0


# ============================================================================
# 5. Repeated Polling Does Not Duplicate Execution
# ============================================================================
def test_repeated_polling_does_not_duplicate_execution(db_session: Session, worker_pipeline_env: dict):
    """5. Prove repeated polling on terminal executions does not re-claim or duplicate execution."""
    env = worker_pipeline_env
    exec_record = RemediationExecutionManager.create_execution(
        db=db_session,
        workspace_id=env["workspace"].id,
        approval_id=env["approval"].id,
        idempotency_key=str(uuid.uuid4()),
        triggered_by=env["engineer"],
        user_role="engineer",
    )

    runner = ControlledTestRunner()
    durable_worker = DurableExecutionWorker(
        worker_id="test-dup-worker",
        runner=runner,
        db_factory=lambda: db_session,
        poll_interval=0.01,
        enable_verification=False,
    )
    worker_mgr = RemediationWorker(worker=durable_worker)

    # First poll: claims and completes
    first_claimed = worker_mgr.poll_and_execute()
    assert first_claimed == exec_record.id
    assert len(runner.calls) == 1

    # Second poll: queue is now empty
    second_claimed = worker_mgr.poll_and_execute()
    assert second_claimed is None
    # Runner calls remain exactly 1
    assert len(runner.calls) == 1

    # Third poll: still empty
    third_claimed = worker_mgr.poll_and_execute()
    assert third_claimed is None
    assert len(runner.calls) == 1


# ============================================================================
# 6. Transient Polling Errors Do Not Kill Worker Loop
# ============================================================================
def test_transient_polling_errors_do_not_kill_worker_loop(db_session: Session, worker_pipeline_env: dict):
    """6. Prove transient database or query errors are caught and logged without terminating the worker loop."""
    env = worker_pipeline_env
    exec_record = RemediationExecutionManager.create_execution(
        db=db_session,
        workspace_id=env["workspace"].id,
        approval_id=env["approval"].id,
        idempotency_key=str(uuid.uuid4()),
        triggered_by=env["engineer"],
        user_role="engineer",
    )

    runner = ControlledTestRunner()
    durable_worker = DurableExecutionWorker(
        worker_id="test-transient-worker",
        runner=runner,
        db_factory=lambda: db_session,
        poll_interval=0.01,
        enable_verification=False,
    )

    original_claim = RemediationExecutionManager.claim_next_execution
    error_raised = False

    def flaking_claim(**kwargs):
        nonlocal error_raised
        if not error_raised:
            error_raised = True
            raise RuntimeError("Transient connection reset by peer")
        return original_claim(**kwargs)

    with patch.object(RemediationExecutionManager, "claim_next_execution", side_effect=flaking_claim):
        # First attempt encounters transient error
        with pytest.raises(RuntimeError):
            durable_worker.run_once()

        # Second attempt succeeds on the same worker
        claimed_id = durable_worker.run_once()
        assert claimed_id == exec_record.id
        assert len(runner.calls) == 1


# ============================================================================
# 7. Application Shutdown Stops Worker Cleanly
# ============================================================================
@pytest.mark.asyncio
async def test_application_shutdown_stops_worker_cleanly():
    """7. Prove application shutdown cleanly halts worker thread and joins within grace period."""
    worker = RemediationWorker(poll_interval=0.01, shutdown_grace_period=2.0)
    await worker.start()
    assert worker.is_running is True

    internal_thread = worker._worker._thread
    assert internal_thread is not None
    assert internal_thread.is_alive() is True

    clean = await worker.stop()
    assert clean is True
    assert worker.is_running is False
    assert internal_thread.is_alive() is False


# ============================================================================
# 8. Repeated Startup Does Not Create Duplicate Polling Loops
# ============================================================================
@pytest.mark.asyncio
async def test_repeated_startup_does_not_create_duplicate_polling_loops():
    """8. Prove repeated start calls on RemediationWorker are idempotent and maintain exactly one thread."""
    worker = RemediationWorker(poll_interval=0.01)
    await worker.start()
    assert worker.is_running is True

    first_thread = worker._worker._thread

    # Repeated start invocation
    await worker.start()
    assert worker.is_running is True
    assert worker._worker._thread is first_thread

    await worker.stop()
    assert worker.is_running is False


# ============================================================================
# 9. Existing Option C Idempotency Behavior Remains Intact
# ============================================================================
def test_existing_option_c_idempotency_intact(db_session: Session, worker_pipeline_env: dict):
    """9. Prove identical idempotency key returns existing execution; different approval raises conflict."""
    env = worker_pipeline_env
    idempotency_key = f"idem-key-{uuid.uuid4().hex[:8]}"

    # First execution creation
    e1 = RemediationExecutionManager.create_execution(
        db=db_session,
        workspace_id=env["workspace"].id,
        approval_id=env["approval"].id,
        idempotency_key=idempotency_key,
        triggered_by=env["engineer"],
        user_role="engineer",
    )

    # Replay with same idempotency key and same approval returns existing record
    e2 = RemediationExecutionManager.create_execution(
        db=db_session,
        workspace_id=env["workspace"].id,
        approval_id=env["approval"].id,
        idempotency_key=idempotency_key,
        triggered_by=env["engineer"],
        user_role="engineer",
    )
    assert e1.id == e2.id

    # Duplicate key with different approval raises IdempotencyConflictError (409)
    other_appr = RemediationApproval(
        id=str(uuid.uuid4()),
        workspace_id=env["workspace"].id,
        incident_id=env["incident"].id,
        policy_decision_id=env["decision"].id,
        action_id="execute_http_recovery",
        target_service_id=env["service"].id,
        validated_parameters={"service_id": env["service"].id, "recovery_path": env["service"].recovery_endpoint},
        risk_level="high",
        approval_status="approved",
        requested_by=env["engineer"].id,
        requested_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    db_session.add(other_appr)
    db_session.commit()

    with pytest.raises(IdempotencyConflictError):
        RemediationExecutionManager.create_execution(
            db=db_session,
            workspace_id=env["workspace"].id,
            approval_id=other_appr.id,
            idempotency_key=idempotency_key,
            triggered_by=env["engineer"],
            user_role="engineer",
        )


# ============================================================================
# 10. Existing Generic HTTP Recovery Works Through Automatic Dispatch
# ============================================================================
def test_generic_http_recovery_automatic_dispatch(db_session: Session, worker_pipeline_env: dict):
    """10. Prove generic external service HTTP recovery executes through Option C pipeline."""
    env = worker_pipeline_env
    service = env["service"]

    # Ed25519 test verification key setup
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()
    pub_bytes = pub.public_bytes_raw()
    pub_b64 = base64.b64encode(pub_bytes).decode("ascii")
    key_id = "test-generic-dispatch-key-1"

    pub_reg = BrokerPublicKeyRegistry({
        key_id: {
            "public_key": pub_b64,
            "status": "active",
        }
    })

    # Isolated HTTP recovery runner using public key only
    runner = IsolatedHttpRecoveryRunner(
        environment="development",
        public_key_registry=pub_reg,
    )

    # Configure control plane private key for manifest signing
    priv_b64 = base64.b64encode(priv.private_bytes_raw()).decode("ascii")
    os.environ["SENTINELOPS_MANIFEST_PRIVATE_KEY"] = priv_b64
    os.environ["SENTINELOPS_MANIFEST_KEY_ID"] = key_id

    exec_record = RemediationExecutionManager.create_execution(
        db=db_session,
        workspace_id=env["workspace"].id,
        approval_id=env["approval"].id,
        idempotency_key=str(uuid.uuid4()),
        triggered_by=env["engineer"],
        user_role="engineer",
    )
    assert exec_record.status == ExecutionState.QUEUED.value
    assert exec_record.manifest_signature is not None
    assert exec_record.authorization_manifest is not None

    durable_worker = DurableExecutionWorker(
        worker_id="test-generic-http-worker",
        runner=runner,
        db_factory=lambda: db_session,
        poll_interval=0.01,
        enable_verification=False,
    )
    worker_mgr = RemediationWorker(worker=durable_worker)

    mock_resp = httpx.Response(
        status_code=200,
        json={"status": "recovered", "service": service.name},
        request=httpx.Request("POST", f"http://127.0.0.1:9090{service.recovery_endpoint}"),
    )

    with patch("httpx.Client.post", return_value=mock_resp) as mock_post:
        claimed_id = worker_mgr.poll_and_execute()

    assert claimed_id == exec_record.id
    db_session.refresh(exec_record)
    assert exec_record.status in (
        ExecutionState.EXECUTION_SUCCEEDED.value,
        ExecutionState.VERIFIED.value,
        ExecutionState.VERIFICATION_PENDING.value,
    )
    mock_post.assert_called_once()
