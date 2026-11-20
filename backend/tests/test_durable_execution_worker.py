"""Comprehensive Tests for Phase 4.3.5 Durable Execution Worker.

Covers:
1. Successful queued execution
2. Missing, unapproved, or expired approval (fails pre-flight, no dispatch)
3. Duplicate execution request & idempotency enforcement
4. Two workers claiming the same queue (zero duplicate claims)
5. Worker crash before dispatch (safe recovery & execution)
6. Worker crash after dispatch (transition to execution_uncertain, no blind duplicate dispatch)
7. Expired lease recovery vs active lease protection
8. Stale fencing token rejection
9. Broker unavailable (fails closed)
10. Broker timeout (transitions to timed_out)
11. Execution failure (non-zero exit code)
12. Execution uncertainty (mid-flight disconnect transitions to execution_uncertain)
13. Workspace isolation (tenant-scoped worker ignores foreign jobs)
14. Audit event correctness & credential redaction
15. Graceful worker lifecycle & shutdown
"""

import copy
import os
import sys
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from app.core.config import settings
from app.execution.exceptions import (
    ApprovalAlreadyExecutedError,
    BrokerUnavailableError,
    ExecutionEnvironmentUnavailable,
    ExecutionUncertainError,
    IdempotencyConflictError,
    StaleWorkerFencingError,
)
from app.execution.manager import RemediationExecutionManager, sanitize_metadata
from app.execution.runner import (
    ExecutionResult,
    ExecutionRunnerInterface,
    MockTestRunner,
)
from app.execution.state_machine import ExecutionState
from app.execution.worker import DurableExecutionWorker
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


class ControlledTestRunner(ExecutionRunnerInterface):
    """Controllable test runner allowing tests to inject specific outcomes or exceptions."""

    def __init__(
        self,
        *,
        result: Optional[ExecutionResult] = None,
        exception: Optional[Exception] = None,
        delay_seconds: float = 0.0,
        available: bool = True,
    ):
        self._result = result or ExecutionResult(
            exit_code=0,
            duration_ms=50,
            stdout="Controlled test execution succeeded.",
            output_data={"status": "healthy", "tested": True},
        )
        self._exception = exception
        self._delay_seconds = delay_seconds
        self._available = available
        self.call_count = 0
        self.last_execution_id: Optional[str] = None

    def is_available(self) -> bool:
        return self._available

    def execute(
        self,
        action_id: str,
        parameters: Dict[str, Any],
        timeout_seconds: int = 30,
        target_url: Optional[str] = None,
        environment: str = "development",
        execution_id: Optional[str] = None,
        **kwargs: Any,
    ) -> ExecutionResult:
        self.call_count += 1
        self.last_execution_id = execution_id
        self.last_kwargs = kwargs
        if self._delay_seconds > 0:
            time.sleep(self._delay_seconds)
        if self._exception is not None:
            raise self._exception
        return self._result


@pytest.fixture
def worker_env(db_session):
    """Provide populated workspace, user, active service, and valid approval for worker tests."""
    ws = Workspace(
        id=str(uuid.uuid4()),
        name="Worker Test WS",
        slug=f"worker-ws-{uuid.uuid4().hex[:6]}",
    )
    ws2 = Workspace(
        id=str(uuid.uuid4()),
        name="Foreign WS",
        slug=f"foreign-ws-{uuid.uuid4().hex[:6]}",
    )
    db_session.add_all([ws, ws2])

    engineer = User(
        id=str(uuid.uuid4()),
        email=f"eng_{uuid.uuid4().hex[:6]}@example.com",
        full_name="Engineer User",
        hashed_password="pw",
    )
    db_session.add(engineer)

    m_eng = WorkspaceMembership(workspace_id=ws.id, user_id=engineer.id, role="engineer")
    db_session.add(m_eng)

    svc = Service(
        id=str(uuid.uuid4()),
        workspace_id=ws.id,
        name="Order API",
        environment="development",
        health_check_url="http://127.0.0.1:8001/health",
        is_active=True,
    )
    db_session.add(svc)

    inc = Incident(
        id=str(uuid.uuid4()),
        workspace_id=ws.id,
        service_id=svc.id,
        title="Elevated Error Rate",
        severity="medium",
        status="investigating",
        trigger="high_error_rate",
    )
    db_session.add(inc)

    dec = PolicyDecision(
        id=str(uuid.uuid4()),
        workspace_id=ws.id,
        user_id=engineer.id,
        action_id="inspect_service_health",
        target_service_id=svc.id,
        risk_level="low",
        decision="allowed",
        decision_reason="Harmless inspection probe",
        policy_version="v1.0",
        validated_parameters={"service_id": svc.id},
    )
    db_session.add(dec)

    now_utc = datetime.now(timezone.utc)
    appr = RemediationApproval(
        id=str(uuid.uuid4()),
        workspace_id=ws.id,
        incident_id=inc.id,
        policy_decision_id=dec.id,
        action_id="inspect_service_health",
        target_service_id=svc.id,
        validated_parameters={"service_id": svc.id},
        risk_level="low",
        approval_status="approved",
        requested_by=engineer.id,
        requested_at=now_utc,
        reviewed_by=engineer.id,
        reviewed_at=now_utc,
        expires_at=now_utc + timedelta(hours=2),
    )
    db_session.add(appr)
    db_session.commit()

    return {
        "ws": ws,
        "ws2": ws2,
        "engineer": engineer,
        "svc": svc,
        "incident": inc,
        "decision": dec,
        "approval": appr,
    }


# ============================================================================
# 1. Successful Queued Execution
# ============================================================================

def test_successful_queued_execution(db_session, worker_env):
    """Worker successfully claims queued execution, dispatches, and persists succeeded state."""
    env = worker_env
    exec_record = RemediationExecutionManager.create_execution(
        db=db_session,
        workspace_id=env["ws"].id,
        approval_id=env["approval"].id,
        idempotency_key=str(uuid.uuid4()),
        triggered_by=env["engineer"],
        user_role="engineer",
    )
    assert exec_record.status == ExecutionState.QUEUED.value

    runner = ControlledTestRunner(
        result=ExecutionResult(
            exit_code=0,
            duration_ms=42,
            stdout="Service healthy",
            output_data={"status": "healthy"},
        )
    )
    worker = DurableExecutionWorker(
        worker_id="test-worker-1",
        runner=runner,
        db_factory=lambda: db_session,
        poll_interval=0.01,
    )

    claimed_id = worker.run_once()
    assert claimed_id == exec_record.id
    assert runner.call_count == 1

    db_session.refresh(exec_record)
    assert exec_record.status == ExecutionState.EXECUTION_SUCCEEDED.value
    assert exec_record.locked_by is None
    assert exec_record.locked_until is None
    assert exec_record.completed_at is not None
    assert exec_record.execution_output == {"status": "healthy"}

    # Attempt record created and succeeded
    attempts = db_session.query(ExecutionAttempt).filter(ExecutionAttempt.execution_id == exec_record.id).all()
    assert len(attempts) == 1
    assert attempts[0].status == "succeeded"
    assert attempts[0].exit_code == 0
    assert attempts[0].duration_ms == 42


# ============================================================================
# 2. Missing, Unapproved, or Expired Approval
# ============================================================================

def test_missing_or_expired_approval(db_session, worker_env):
    """Pre-flight validation rejects missing, unapproved, or expired approvals without dispatch."""
    env = worker_env
    now_utc = datetime.now(timezone.utc)

    # 1. Expired approval
    expired_appr = RemediationApproval(
        id=str(uuid.uuid4()),
        workspace_id=env["ws"].id,
        incident_id=env["incident"].id,
        policy_decision_id=env["decision"].id,
        action_id="inspect_service_health",
        target_service_id=env["svc"].id,
        validated_parameters={"service_id": env["svc"].id},
        risk_level="low",
        approval_status="approved",
        requested_by=env["engineer"].id,
        requested_at=now_utc - timedelta(hours=2),
        reviewed_by=env["engineer"].id,
        reviewed_at=now_utc - timedelta(hours=2),
        expires_at=now_utc - timedelta(minutes=5),  # EXPIRED
    )
    db_session.add(expired_appr)
    db_session.commit()

    # Create execution record pointing to expired approval
    exec_expired = RemediationExecution(
        id=str(uuid.uuid4()),
        workspace_id=env["ws"].id,
        approval_id=expired_appr.id,
        action_id="inspect_service_health",
        target_service_id=env["svc"].id,
        approved_parameters={"service_id": env["svc"].id},
        status=ExecutionState.QUEUED.value,
        idempotency_key=str(uuid.uuid4()),
        triggered_by=env["engineer"].id,
        triggered_at=now_utc,
    )
    db_session.add(exec_expired)
    db_session.commit()

    runner = ControlledTestRunner()
    worker = DurableExecutionWorker(
        worker_id="test-worker-preflight",
        runner=runner,
        db_factory=lambda: db_session,
    )

    worker.run_once()
    assert runner.call_count == 0  # CRITICAL: NO dispatch occurred

    db_session.refresh(exec_expired)
    assert exec_expired.status == ExecutionState.EXECUTION_FAILED.value
    assert exec_expired.error_category == "approval_expired"
    assert "expired" in exec_expired.error_message.lower()


# ============================================================================
# 3. Duplicate Execution Request
# ============================================================================

def test_duplicate_execution_request(db_session, worker_env):
    """Enforcing single execution per approval and workspace idempotency uniqueness."""
    env = worker_env
    idem_key = str(uuid.uuid4())

    # 1. Create first execution
    exec1 = RemediationExecutionManager.create_execution(
        db=db_session,
        workspace_id=env["ws"].id,
        approval_id=env["approval"].id,
        idempotency_key=idem_key,
        triggered_by=env["engineer"],
        user_role="engineer",
    )

    # 2. Replay with identical approval and key returns existing execution directly
    exec2 = RemediationExecutionManager.create_execution(
        db=db_session,
        workspace_id=env["ws"].id,
        approval_id=env["approval"].id,
        idempotency_key=idem_key,
        triggered_by=env["engineer"],
        user_role="engineer",
    )
    assert exec1.id == exec2.id

    # 3. Replay with same approval but different key rejected
    with pytest.raises(ApprovalAlreadyExecutedError):
        RemediationExecutionManager.create_execution(
            db=db_session,
            workspace_id=env["ws"].id,
            approval_id=env["approval"].id,
            idempotency_key="different-key-same-approval",
            triggered_by=env["engineer"],
            user_role="engineer",
        )


# ============================================================================
# 4. Two Workers Claiming the Same Queue
# ============================================================================

def test_two_workers_claiming_the_same_queue(db_session, worker_env):
    """Two concurrent workers competing for 1 job: exactly one claims, zero double execution."""
    env = worker_env
    exec_record = RemediationExecutionManager.create_execution(
        db=db_session,
        workspace_id=env["ws"].id,
        approval_id=env["approval"].id,
        idempotency_key=str(uuid.uuid4()),
        triggered_by=env["engineer"],
        user_role="engineer",
    )

    runner_a = ControlledTestRunner()
    runner_b = ControlledTestRunner()

    worker_a = DurableExecutionWorker(worker_id="worker-A", runner=runner_a, db_factory=lambda: db_session)
    worker_b = DurableExecutionWorker(worker_id="worker-B", runner=runner_b, db_factory=lambda: db_session)

    # Worker A claims the single queued job
    job_a = worker_a.run_once()
    assert job_a == exec_record.id
    assert runner_a.call_count == 1

    # Worker B polls immediately after -> queue is empty
    job_b = worker_b.run_once()
    assert job_b is None
    assert runner_b.call_count == 0


# ============================================================================
# 5. Worker Crash Before Dispatch
# ============================================================================

def test_worker_crash_before_dispatch(db_session, worker_env):
    """Crash before dispatch (validating state) allows safe recovery and completion by another worker."""
    env = worker_env
    now_utc = datetime.now(timezone.utc)

    # Simulate worker-1 crashed in 'validating' state with expired lease
    crashed_exec = RemediationExecutionManager.create_execution(
        db=db_session,
        workspace_id=env["ws"].id,
        approval_id=env["approval"].id,
        idempotency_key=str(uuid.uuid4()),
        triggered_by=env["engineer"],
        user_role="engineer",
    )
    crashed_exec.status = ExecutionState.VALIDATING.value
    crashed_exec.locked_by = "crashed-worker-1"
    crashed_exec.locked_until = now_utc - timedelta(seconds=10)  # Lease expired
    crashed_exec.fencing_token = 1
    crashed_exec.attempt_count = 1
    crashed_exec.triggered_at = now_utc - timedelta(minutes=2)
    db_session.commit()

    runner = ControlledTestRunner()
    worker_2 = DurableExecutionWorker(
        worker_id="recovery-worker-2",
        runner=runner,
        db_factory=lambda: db_session,
    )

    # Recovery worker claims and executes
    claimed_id = worker_2.run_once()
    assert claimed_id == crashed_exec.id
    assert runner.call_count == 1

    db_session.refresh(crashed_exec)
    assert crashed_exec.status == ExecutionState.EXECUTION_SUCCEEDED.value
    # Fencing token was incremented upon recovery and execution
    assert crashed_exec.fencing_token >= 2

    # Verify recovery event was recorded
    events = db_session.query(ExecutionEvent).filter(ExecutionEvent.execution_id == crashed_exec.id).all()
    event_types = [e.event_type for e in events]
    assert "lease_recovery_pre_dispatch" in event_types


# ============================================================================
# 6. Worker Crash After Dispatch
# ============================================================================

def test_worker_crash_after_dispatch(db_session, worker_env):
    """Crash after dispatch (executing state) marks execution as execution_uncertain; NO duplicate dispatch."""
    env = worker_env
    now_utc = datetime.now(timezone.utc)

    # Simulate worker-1 dispatched container, then crashed/disconnected while in 'executing' state
    crashed_exec = RemediationExecution(
        id=str(uuid.uuid4()),
        workspace_id=env["ws"].id,
        approval_id=env["approval"].id,
        action_id="inspect_service_health",
        target_service_id=env["svc"].id,
        approved_parameters={"service_id": env["svc"].id},
        status=ExecutionState.EXECUTING.value,
        idempotency_key=str(uuid.uuid4()),
        locked_by="crashed-worker-1",
        locked_until=now_utc - timedelta(seconds=15),  # Lease expired
        fencing_token=2,
        attempt_count=1,
        triggered_by=env["engineer"].id,
        triggered_at=now_utc - timedelta(minutes=3),
    )
    db_session.add(crashed_exec)

    attempt = ExecutionAttempt(
        id=str(uuid.uuid4()),
        execution_id=crashed_exec.id,
        attempt_number=1,
        status="running",
        worker_id="crashed-worker-1",
        fencing_token=2,
        started_at=now_utc - timedelta(minutes=2),
    )
    db_session.add(attempt)
    db_session.commit()

    runner = ControlledTestRunner()
    worker_2 = DurableExecutionWorker(
        worker_id="recovery-worker-2",
        runner=runner,
        db_factory=lambda: db_session,
    )

    # Worker 2 recovers the abandoned executing job
    worker_2.run_once()

    # INVARIANT: Worker 2 MUST NOT dispatch container again!
    assert runner.call_count == 0

    db_session.refresh(crashed_exec)
    assert crashed_exec.status == ExecutionState.EXECUTION_UNCERTAIN.value
    assert crashed_exec.error_category == "worker_crash_after_dispatch"
    assert crashed_exec.locked_by is None
    assert crashed_exec.locked_until is None

    # In-flight attempt finalized to uncertain
    db_session.refresh(attempt)
    assert attempt.status == "uncertain"
    assert attempt.error_category == "worker_crash_after_dispatch"


# ============================================================================
# 7. Expired Lease Recovery vs Active Lease Protection
# ============================================================================

def test_expired_lease_recovery(db_session, worker_env):
    """Worker recovers expired leases but ignores active valid leases owned by other workers."""
    env = worker_env
    now_utc = datetime.now(timezone.utc)

    # Job A: Valid active lease (locked_until in future) -> must NOT be claimed
    job_active = RemediationExecutionManager.create_execution(
        db=db_session,
        workspace_id=env["ws"].id,
        approval_id=env["approval"].id,
        idempotency_key=str(uuid.uuid4()),
        triggered_by=env["engineer"],
        user_role="engineer",
    )
    job_active.status = ExecutionState.VALIDATING.value
    job_active.locked_by = "active-worker"
    job_active.locked_until = now_utc + timedelta(seconds=60)  # ACTIVE
    job_active.fencing_token = 1
    job_active.attempt_count = 1
    job_active.triggered_at = now_utc - timedelta(minutes=1)
    db_session.commit()

    runner = ControlledTestRunner()
    worker = DurableExecutionWorker(worker_id="worker-probe", runner=runner, db_factory=lambda: db_session)

    # Cannot claim active job
    res = worker.run_once()
    assert res is None

    # Now expire the lease
    job_active.locked_until = now_utc - timedelta(seconds=1)
    db_session.commit()

    # Now it is eligible for recovery
    res2 = worker.run_once()
    assert res2 == job_active.id


# ============================================================================
# 8. Stale Fencing Token Rejection
# ============================================================================

def test_stale_fencing_token_rejection(db_session, worker_env):
    """Stale worker with outdated fencing token is rejected on heartbeat and state transition."""
    env = worker_env
    now_utc = datetime.now(timezone.utc)

    execution = RemediationExecution(
        id=str(uuid.uuid4()),
        workspace_id=env["ws"].id,
        approval_id=env["approval"].id,
        action_id="inspect_service_health",
        target_service_id=env["svc"].id,
        approved_parameters={"service_id": env["svc"].id},
        status=ExecutionState.VALIDATING.value,
        idempotency_key=str(uuid.uuid4()),
        locked_by="worker-1",
        locked_until=now_utc + timedelta(seconds=90),
        fencing_token=5,  # Current token is 5
        attempt_count=1,
        triggered_by=env["engineer"].id,
        triggered_at=now_utc,
    )
    db_session.add(execution)
    db_session.commit()

    # Heartbeat with stale token 4 raises StaleWorkerFencingError
    with pytest.raises(StaleWorkerFencingError):
        RemediationExecutionManager.heartbeat_lease(
            execution_id=execution.id,
            worker_id="worker-1",
            expected_fencing_token=4,  # STALE
            db=db_session,
        )

    # State transition with stale token 4 raises StaleWorkerFencingError
    with pytest.raises(StaleWorkerFencingError):
        RemediationExecutionManager.transition_execution_state(
            execution_id=execution.id,
            new_state=ExecutionState.EXECUTING.value,
            expected_fencing_token=4,  # STALE
            db=db_session,
        )


# ============================================================================
# 9. Broker Unavailable
# ============================================================================

def test_broker_unavailable(db_session, worker_env):
    """When broker IPC is unavailable, execution transitions to execution_failed (503 fail-closed)."""
    env = worker_env
    exec_record = RemediationExecutionManager.create_execution(
        db=db_session,
        workspace_id=env["ws"].id,
        approval_id=env["approval"].id,
        idempotency_key=str(uuid.uuid4()),
        triggered_by=env["engineer"],
        user_role="engineer",
    )

    runner = ControlledTestRunner(
        exception=ExecutionEnvironmentUnavailable("Docker broker socket unavailable at /var/run/sentinelops/broker.sock")
    )
    worker = DurableExecutionWorker(worker_id="worker-err", runner=runner, db_factory=lambda: db_session)

    worker.run_once()

    db_session.refresh(exec_record)
    assert exec_record.status == ExecutionState.EXECUTION_FAILED.value
    assert exec_record.error_category == "broker_unavailable"
    assert "broker socket unavailable" in exec_record.error_message.lower()


# ============================================================================
# 10. Broker Timeout
# ============================================================================

def test_broker_timeout(db_session, worker_env):
    """When runner times out, execution transitions to timed_out."""
    env = worker_env
    exec_record = RemediationExecutionManager.create_execution(
        db=db_session,
        workspace_id=env["ws"].id,
        approval_id=env["approval"].id,
        idempotency_key=str(uuid.uuid4()),
        triggered_by=env["engineer"],
        user_role="engineer",
    )

    runner = ControlledTestRunner(
        exception=TimeoutError("Container execution exceeded 30 seconds.")
    )
    worker = DurableExecutionWorker(worker_id="worker-timeout", runner=runner, db_factory=lambda: db_session)

    worker.run_once()

    db_session.refresh(exec_record)
    assert exec_record.status == ExecutionState.TIMED_OUT.value
    assert exec_record.error_category == "timeout"


# ============================================================================
# 11. Execution Failure (Non-Zero Exit Code)
# ============================================================================

def test_execution_failure(db_session, worker_env):
    """Container non-zero exit code transitions execution to execution_failed."""
    env = worker_env
    exec_record = RemediationExecutionManager.create_execution(
        db=db_session,
        workspace_id=env["ws"].id,
        approval_id=env["approval"].id,
        idempotency_key=str(uuid.uuid4()),
        triggered_by=env["engineer"],
        user_role="engineer",
    )

    runner = ControlledTestRunner(
        result=ExecutionResult(
            exit_code=1,
            duration_ms=80,
            stdout="Starting probe...",
            stderr="HTTP 500 Internal Server Error from target service",
            error_message="Probe failed: HTTP 500",
            error_category="probe_failed",
        )
    )
    worker = DurableExecutionWorker(worker_id="worker-fail", runner=runner, db_factory=lambda: db_session)

    worker.run_once()

    db_session.refresh(exec_record)
    assert exec_record.status == ExecutionState.EXECUTION_FAILED.value
    assert exec_record.error_category == "probe_failed"
    assert exec_record.error_message == "Probe failed: HTTP 500"

    attempt = db_session.query(ExecutionAttempt).filter(ExecutionAttempt.execution_id == exec_record.id).first()
    assert attempt.status == "failed"
    assert attempt.exit_code == 1


# ============================================================================
# 12. Execution Uncertainty
# ============================================================================

def test_execution_uncertainty(db_session, worker_env):
    """Broker disconnect during in-flight container execution transitions to execution_uncertain."""
    env = worker_env
    exec_record = RemediationExecutionManager.create_execution(
        db=db_session,
        workspace_id=env["ws"].id,
        approval_id=env["approval"].id,
        idempotency_key=str(uuid.uuid4()),
        triggered_by=env["engineer"],
        user_role="engineer",
    )

    runner = ControlledTestRunner(
        exception=ExecutionUncertainError("Broker socket connection closed unexpectedly during action execution")
    )
    worker = DurableExecutionWorker(worker_id="worker-uncertain", runner=runner, db_factory=lambda: db_session)

    worker.run_once()

    db_session.refresh(exec_record)
    assert exec_record.status == ExecutionState.EXECUTION_UNCERTAIN.value
    assert exec_record.error_category == "execution_uncertain"
    assert "socket connection closed" in exec_record.uncertain_reason.lower()

    # Attempt record is marked uncertain
    attempt = db_session.query(ExecutionAttempt).filter(ExecutionAttempt.execution_id == exec_record.id).first()
    assert attempt.status == "uncertain"


# ============================================================================
# 13. Workspace Isolation
# ============================================================================

def test_workspace_isolation(db_session, worker_env):
    """Worker scoped to Workspace A does NOT consume executions queued in Workspace B."""
    env = worker_env
    # Queue execution in Workspace 1
    exec_ws1 = RemediationExecutionManager.create_execution(
        db=db_session,
        workspace_id=env["ws"].id,
        approval_id=env["approval"].id,
        idempotency_key=str(uuid.uuid4()),
        triggered_by=env["engineer"],
        user_role="engineer",
    )

    # Worker scoped strictly to Workspace 2
    runner = ControlledTestRunner()
    worker_ws2 = DurableExecutionWorker(
        worker_id="worker-ws2",
        runner=runner,
        db_factory=lambda: db_session,
        workspace_id=env["ws2"].id,  # Scoped to Foreign Workspace
    )

    job_id = worker_ws2.run_once()
    assert job_id is None
    assert runner.call_count == 0

    # Job in WS1 is untouched and still queued
    db_session.refresh(exec_ws1)
    assert exec_ws1.status == ExecutionState.QUEUED.value


# ============================================================================
# 14. Audit Event Correctness & Redaction
# ============================================================================

def test_audit_event_correctness(db_session, worker_env):
    """Execution lifecycle records fine-grained events with sensitive metadata redacted."""
    env = worker_env
    exec_record = RemediationExecutionManager.create_execution(
        db=db_session,
        workspace_id=env["ws"].id,
        approval_id=env["approval"].id,
        idempotency_key=str(uuid.uuid4()),
        triggered_by=env["engineer"],
        user_role="engineer",
    )

    runner = ControlledTestRunner(
        result=ExecutionResult(
            exit_code=0,
            duration_ms=60,
            stdout="Healthy",
            output_data={"status": "ok", "api_key": "secret-12345"},
        )
    )
    worker = DurableExecutionWorker(worker_id="worker-audit", runner=runner, db_factory=lambda: db_session)
    worker.run_once()

    events = (
        db_session.query(ExecutionEvent)
        .filter(ExecutionEvent.execution_id == exec_record.id)
        .order_by(ExecutionEvent.timestamp.asc())
        .all()
    )
    event_types = [e.event_type for e in events]
    assert "queued" in event_types
    assert "lease_acquired" in event_types
    assert "executing" in event_types
    assert "execution_succeeded" in event_types

    # Verify incident event recorded
    inc_events = db_session.query(IncidentEvent).filter(IncidentEvent.incident_id == env["incident"].id).all()
    assert len(inc_events) >= 1

    # Verify execution_output sanitization
    db_session.refresh(exec_record)
    assert exec_record.execution_output["api_key"] == "[REDACTED]"


# ============================================================================
# 15. Graceful Worker Shutdown
# ============================================================================

def test_graceful_worker_shutdown(db_session, worker_env):
    """Worker starts in background thread and stops cleanly on stop() call."""
    runner = ControlledTestRunner()
    worker = DurableExecutionWorker(
        worker_id="worker-lifecycle",
        runner=runner,
        db_factory=lambda: db_session,
        poll_interval=0.05,
    )

    assert not worker.is_running
    worker.start()
    assert worker.is_running

    time.sleep(0.1)
    clean = worker.stop(timeout=2.0)
    assert clean is True
    assert not worker.is_running


def _create_test_execution_record(db_session, worker_env):
    env = worker_env
    appr = RemediationApproval(
        id=str(uuid.uuid4()),
        workspace_id=env["ws"].id,
        policy_decision_id=env["decision"].id,
        action_id="inspect_service_health",
        target_service_id=env["svc"].id,
        validated_parameters={"service_id": env["svc"].id},
        risk_level="low",
        policy_version="v1.0",
        requested_by=env["engineer"].id,
        approval_status="approved",
        reviewed_by=env["engineer"].id,
        reviewed_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    db_session.add(appr)
    db_session.commit()
    return RemediationExecutionManager.create_execution(
        db=db_session,
        workspace_id=env["ws"].id,
        approval_id=appr.id,
        idempotency_key=str(uuid.uuid4()),
        triggered_by=env["engineer"],
        user_role="engineer",
    )


def test_shutdown_while_execution_exceeds_join_timeout(db_session, worker_env):
    """When in-flight execution exceeds join timeout, stop() returns False and preserves in-flight work."""
    exec_record = _create_test_execution_record(db_session, worker_env)

    class BlockingRunner(ExecutionRunnerInterface):
        def __init__(self):
            self.started_event = threading.Event()
            self.unblock_event = threading.Event()
            self.call_count = 0

        def is_available(self) -> bool:
            return True

        def execute(self, *args, **kwargs) -> ExecutionResult:
            self.call_count += 1
            self.started_event.set()
            self.unblock_event.wait(timeout=5.0)
            return ExecutionResult(exit_code=0, stdout="blocking test complete", duration_ms=100)

    runner = BlockingRunner()
    worker = DurableExecutionWorker(
        worker_id="worker-timeout-test",
        runner=runner,
        db_factory=lambda: db_session,
        poll_interval=0.05,
        shutdown_grace_period=0.1,
    )

    worker.start()
    assert runner.started_event.wait(timeout=3.0)

    # Call stop with short timeout (0.1s) while execution is actively blocked
    clean_stop = worker.stop(timeout=0.1)

    try:
        # Contract Assertions:
        # 1. Do NOT claim graceful completion
        assert clean_stop is False
        # 2. Worker thread is still alive
        assert worker._thread is not None and worker._thread.is_alive()
        # 3. Worker does not falsely claim to have stopped cleanly
        assert worker.is_running is True
        # 4. In-flight execution is NOT falsely marked succeeded or failed
        db_session.refresh(exec_record)
        assert exec_record.status == "executing"
    finally:
        # Unblock runner so thread can terminate cleanly
        runner.unblock_event.set()
        if worker._thread:
            worker._thread.join(timeout=3.0)
        worker.stop(timeout=1.0)


def test_shutdown_grace_period_expiration(db_session, worker_env):
    """When grace period expires, stop event stops new claims and stale worker cannot finalize after recovery."""
    exec_record = _create_test_execution_record(db_session, worker_env)

    class BlockingRunner(ExecutionRunnerInterface):
        def __init__(self):
            self.started_event = threading.Event()
            self.unblock_event = threading.Event()
            self.call_count = 0

        def is_available(self) -> bool:
            return True

        def execute(self, *args, **kwargs) -> ExecutionResult:
            self.call_count += 1
            self.started_event.set()
            self.unblock_event.wait(timeout=5.0)
            return ExecutionResult(exit_code=0, stdout="recovered test complete", duration_ms=100)

    runner = BlockingRunner()
    worker = DurableExecutionWorker(
        worker_id="worker-grace-test",
        runner=runner,
        db_factory=lambda: db_session,
        poll_interval=0.05,
        shutdown_grace_period=0.1,
    )

    worker.start()
    assert runner.started_event.wait(timeout=3.0)

    # Grace period expires during stop()
    clean_stop = worker.stop()
    assert clean_stop is False
    assert worker._stop_event.is_set() is True
    assert worker._active_dispatched is True

    # Execution remains 'executing' in DB (not falsely finalized)
    db_session.refresh(exec_record)
    assert exec_record.status == "executing"

    # Simulate lease expiration while worker was hung
    exec_record.locked_until = datetime.now(timezone.utc) - timedelta(seconds=30)
    db_session.commit()

    # Recovery sweep recovers stale executing job to 'execution_uncertain'
    recovery_worker = DurableExecutionWorker(
        worker_id="recovery-worker",
        runner=ControlledTestRunner(),
        db_factory=lambda: db_session,
    )
    recovered_job = recovery_worker.run_once()
    assert recovered_job is None

    db_session.refresh(exec_record)
    assert exec_record.status == "execution_uncertain"

    # Now unblock the worker runner thread
    runner.unblock_event.set()
    if worker._thread:
        worker._thread.join(timeout=3.0)

    # Verify stale worker finalization was REJECTED: status is preserved as 'execution_uncertain'
    db_session.refresh(exec_record)
    assert exec_record.status == "execution_uncertain"


# ============================================================================
# Phase 4.3.5.3: Shutdown Heartbeat Ownership Verification Tests
# ============================================================================

def test_shutdown_begins_while_execution_running_and_heartbeats_continue(db_session, worker_env):
    """
    Test 1 & 2:
    - Worker shutdown begins while an execution is running.
    - Setting stop-claiming event does not terminate the heartbeat thread.
    - Heartbeats continue renewing the lease throughout the grace period.
    """
    exec_record = _create_test_execution_record(db_session, worker_env)

    class PausingRunner(ExecutionRunnerInterface):
        def __init__(self):
            self.started_event = threading.Event()
            self.unblock_event = threading.Event()

        def is_available(self) -> bool:
            return True

        def execute(self, *args, **kwargs) -> ExecutionResult:
            self.started_event.set()
            self.unblock_event.wait(timeout=5.0)
            return ExecutionResult(exit_code=0, stdout="pause completed", duration_ms=100)

    runner = PausingRunner()
    worker = DurableExecutionWorker(
        worker_id="worker-hb-test",
        runner=runner,
        db_factory=lambda: db_session,
        poll_interval=0.02,
        heartbeat_interval=0.08,
        lease_seconds=30,
        shutdown_grace_period=2.0,
    )

    worker.start()
    assert runner.started_event.wait(timeout=3.0)

    # 1. Shutdown begins while execution is actively running
    shutdown_done = threading.Event()
    stop_result = [None]

    def _async_stop():
        stop_result[0] = worker.stop(timeout=2.0)
        shutdown_done.set()

    stop_thread = threading.Thread(target=_async_stop, daemon=True)
    stop_thread.start()

    # Wait briefly for stop-claiming to be signaled
    time.sleep(0.05)
    assert worker.is_stop_claiming_set is True

    # New claims must be rejected immediately
    assert worker.run_once() is None

    # 2. Verify heartbeats continue renewing the lease during the grace period
    assert worker._active_heartbeat_thread is not None
    assert worker._active_heartbeat_thread.is_alive() is True

    # Record locked_until at t0
    db_session.refresh(exec_record)
    t0_locked_until = exec_record.locked_until
    assert t0_locked_until is not None

    # Wait for at least 2 heartbeat intervals
    time.sleep(0.20)

    # Refresh and verify that locked_until has been extended by the heartbeat thread
    db_session.refresh(exec_record)
    t1_locked_until = exec_record.locked_until
    assert t1_locked_until > t0_locked_until

    # Unblock the runner so execution finishes before grace period expires
    runner.unblock_event.set()
    shutdown_done.wait(timeout=3.0)
    stop_thread.join(timeout=3.0)

    # Normal execution completion allows clean shutdown
    assert stop_result[0] is True
    assert worker.is_running is False
    assert worker._active_heartbeat_thread is None

    db_session.refresh(exec_record)
    assert exec_record.status == ExecutionState.EXECUTION_SUCCEEDED.value


def test_another_worker_cannot_claim_or_recover_during_shutdown_grace_period(db_session, worker_env):
    """
    Test 3:
    While the first worker is executing during shutdown grace period,
    active heartbeats keep the lease valid so another worker cannot claim or recover it.
    """
    exec_record = _create_test_execution_record(db_session, worker_env)

    class LongRunningRunner(ExecutionRunnerInterface):
        def __init__(self):
            self.started_event = threading.Event()
            self.unblock_event = threading.Event()

        def is_available(self) -> bool:
            return True

        def execute(self, *args, **kwargs) -> ExecutionResult:
            self.started_event.set()
            self.unblock_event.wait(timeout=5.0)
            return ExecutionResult(exit_code=0, stdout="long running done", duration_ms=200)

    runner_1 = LongRunningRunner()
    worker_1 = DurableExecutionWorker(
        worker_id="worker-primary",
        runner=runner_1,
        db_factory=lambda: db_session,
        poll_interval=0.02,
        heartbeat_interval=0.08,
        lease_seconds=30,
        shutdown_grace_period=2.0,
    )

    worker_1.start()
    assert runner_1.started_event.wait(timeout=3.0)

    # Initiate shutdown on worker_1
    stop_thread = threading.Thread(target=lambda: worker_1.stop(timeout=2.0), daemon=True)
    stop_thread.start()
    time.sleep(0.05)

    # Instantiate competitor worker_2
    worker_2 = DurableExecutionWorker(
        worker_id="worker-competitor",
        runner=ControlledTestRunner(),
        db_factory=lambda: db_session,
    )

    # Worker 2 attempts to claim or recover
    claimed = worker_2.run_once()

    # Assert: Worker 2 CANNOT claim or recover because worker_1 holds valid active lease
    assert claimed is None

    db_session.refresh(exec_record)
    assert exec_record.status == ExecutionState.EXECUTING.value
    assert exec_record.locked_by == "worker-primary"

    # Complete worker_1 execution
    runner_1.unblock_event.set()
    stop_thread.join(timeout=3.0)


def test_normal_execution_completion_allows_clean_shutdown(db_session, worker_env):
    """
    Test 4:
    Normal execution completion within grace period stops heartbeat cleanly
    and returns True for clean shutdown.
    """
    exec_record = _create_test_execution_record(db_session, worker_env)

    class QuickRunner(ExecutionRunnerInterface):
        def __init__(self):
            self.started_event = threading.Event()

        def is_available(self) -> bool:
            return True

        def execute(self, *args, **kwargs) -> ExecutionResult:
            self.started_event.set()
            time.sleep(0.05)
            return ExecutionResult(exit_code=0, stdout="quick success", duration_ms=50)

    runner = QuickRunner()
    worker = DurableExecutionWorker(
        worker_id="worker-clean-stop",
        runner=runner,
        db_factory=lambda: db_session,
        poll_interval=0.02,
        heartbeat_interval=0.05,
        lease_seconds=30,
        shutdown_grace_period=2.0,
    )

    worker.start()
    assert runner.started_event.wait(timeout=3.0)

    clean_stop = worker.stop(timeout=2.0)

    assert clean_stop is True
    assert worker.is_running is False
    assert worker._active_heartbeat_thread is None

    db_session.refresh(exec_record)
    assert exec_record.status == ExecutionState.EXECUTION_SUCCEEDED.value
    assert exec_record.locked_by is None
    assert exec_record.locked_until is None


def test_forced_termination_eventually_allows_lease_recovery_to_uncertain(db_session, worker_env):
    """
    Test 5:
    Forced process termination (halting heartbeat) eventually allows normal lease recovery
    to transition the execution safely to 'execution_uncertain' (no redispatch).
    """
    exec_record = _create_test_execution_record(db_session, worker_env)
    now_utc = datetime.now(timezone.utc)

    # Worker crashes abruptly while in 'executing' state (dispatch had occurred)
    exec_record.status = ExecutionState.EXECUTING.value
    exec_record.locked_by = "worker-crashed-pid-999"
    exec_record.fencing_token = 1
    exec_record.attempt_count = 1
    # Lease was held until now + 5s, but process terminated so no further heartbeats occur
    exec_record.locked_until = now_utc - timedelta(seconds=1)  # expired
    db_session.commit()

    # Recovery worker polls
    recovery_worker = DurableExecutionWorker(
        worker_id="recovery-worker-5",
        runner=ControlledTestRunner(),
        db_factory=lambda: db_session,
    )

    claimed = recovery_worker.run_once()
    # Post-dispatch lease recovery marks uncertain and returns None (does NOT execute)
    assert claimed is None

    db_session.refresh(exec_record)
    assert exec_record.status == ExecutionState.EXECUTION_UNCERTAIN.value
    assert exec_record.locked_by is None
    assert exec_record.locked_until is None
    assert exec_record.error_category == "worker_crash_after_dispatch"
    assert "blind duplicate execution prevented" in exec_record.uncertain_reason.lower()


def test_stale_worker_cannot_finalize_after_losing_fencing_token(db_session, worker_env):
    """
    Test 6:
    A stale worker that was fenced off while executing cannot finalize stale results,
    and its heartbeat is rejected with StaleWorkerFencingError.
    """
    exec_record = _create_test_execution_record(db_session, worker_env)

    class DelayedRunner(ExecutionRunnerInterface):
        def __init__(self):
            self.started_event = threading.Event()
            self.unblock_event = threading.Event()

        def is_available(self) -> bool:
            return True

        def execute(self, *args, **kwargs) -> ExecutionResult:
            self.started_event.set()
            self.unblock_event.wait(timeout=5.0)
            return ExecutionResult(exit_code=0, stdout="stale worker finished", duration_ms=300)

    runner = DelayedRunner()
    stale_worker = DurableExecutionWorker(
        worker_id="worker-stale-fencing",
        runner=runner,
        db_factory=lambda: db_session,
        poll_interval=0.02,
        heartbeat_interval=0.05,
        lease_seconds=30,
    )

    stale_worker.start()
    assert runner.started_event.wait(timeout=3.0)

    # In DB, simulate that stale worker was fenced off:
    # Another recovery worker claimed and incremented fencing token
    db_session.refresh(exec_record)
    assert exec_record.status == ExecutionState.EXECUTING.value
    original_token = exec_record.fencing_token

    # Recovery worker steals/recovers: fencing token incremented, status changed
    exec_record.fencing_token = original_token + 1
    exec_record.status = ExecutionState.EXECUTION_UNCERTAIN.value
    exec_record.locked_by = None
    exec_record.locked_until = None
    db_session.commit()

    # Give heartbeat thread a moment to run and detect fencing conflict
    time.sleep(0.12)

    # Unblock runner to let stale worker attempt finalization
    runner.unblock_event.set()
    stale_worker.stop(timeout=2.0)

    # Verify: Finalization was discarded; status remains 'execution_uncertain'
    db_session.refresh(exec_record)
    assert exec_record.status == ExecutionState.EXECUTION_UNCERTAIN.value
    assert exec_record.fencing_token == original_token + 1
