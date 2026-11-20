"""Live PostgreSQL Concurrency & Lease Fencing Tests for Phase 4.3.5.1.

STRICT INVARIANT:
- This test file connects directly to the session-scoped isolated PostgreSQL test database.
- Never connects to or modifies sentinelops_dev or protected databases.
- Proves genuine row-level lock concurrency (FOR UPDATE SKIP LOCKED).
- Proves monotonic fencing tokens, stale worker rejection, and zero duplicate dispatch on recovery.
"""

import concurrent.futures
import os
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

import pytest
from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import Session, sessionmaker

from app.execution.exceptions import (
    ApprovalAlreadyExecutedError,
    StaleWorkerFencingError,
)
from app.execution.manager import RemediationExecutionManager
from app.execution.runner import ExecutionResult, ExecutionRunnerInterface
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
    """Test runner tracking call counts without mutating host."""

    def __init__(self, exit_code: int = 0, delay_seconds: float = 0.0):
        self.call_count = 0
        self.exit_code = exit_code
        self.delay_seconds = delay_seconds

    def is_available(self) -> bool:
        return True

    def execute(
        self,
        action_id: str,
        parameters: Dict[str, Any],
        timeout_seconds: int = 30,
        target_url: Optional[str] = None,
        environment: str = "development",
        execution_id: Optional[str] = None,
    ) -> ExecutionResult:
        self.call_count += 1
        if self.delay_seconds > 0:
            time.sleep(self.delay_seconds)
        return ExecutionResult(
            exit_code=self.exit_code,
            duration_ms=40,
            stdout="Live PG controlled execution succeeded",
            output_data={"status": "healthy"},
        )


@pytest.fixture(scope="module")
def pg_engine(isolated_pg_engine):
    """Provide isolated PostgreSQL engine backed by ephemeral test database."""
    return isolated_pg_engine


@pytest.fixture
def pg_session(pg_engine):
    """Provide a dedicated isolated PostgreSQL session with cleanup."""
    SessionLocal = sessionmaker(bind=pg_engine, autoflush=False)
    db = SessionLocal()
    yield db
    db.close()


@pytest.fixture
def live_pg_env(pg_engine, isolated_pg_seed_data):
    """Seed test fixtures directly into isolated PostgreSQL."""
    SessionLocal = sessionmaker(bind=pg_engine, autoflush=False)
    db = SessionLocal()

    # Create synthetic test workspace and user dedicated to worker concurrency testing
    ws_id = str(uuid.uuid4())
    user_id = str(uuid.uuid4())
    svc_id = str(uuid.uuid4())
    inc_id = str(uuid.uuid4())
    dec_id = str(uuid.uuid4())

    ws = Workspace(
        id=ws_id,
        name=f"Worker Concurrency WS {ws_id[:8]}",
        slug=f"worker-conc-{ws_id[:8]}",
        description="Isolated workspace for worker concurrency testing",
    )
    user = User(
        id=user_id,
        email=f"worker-tester-{user_id[:8]}@isolated.local",
        full_name="Worker Concurrency Tester",
        hashed_password="hashed_pw_test",
        is_active=True,
    )
    membership = WorkspaceMembership(
        workspace_id=ws_id,
        user_id=user_id,
        role="admin",
    )
    svc = Service(
        id=svc_id,
        workspace_id=ws_id,
        name="PG Concurrency Service",
        environment="development",
        health_check_url="http://127.0.0.1:8001/health",
        is_active=True,
    )
    inc = Incident(
        id=inc_id,
        workspace_id=ws_id,
        service_id=svc_id,
        title="Isolated PG Concurrency Incident",
        severity="medium",
        status="investigating",
        trigger="automated_detection",
    )
    dec = PolicyDecision(
        id=dec_id,
        workspace_id=ws_id,
        user_id=user_id,
        action_id="inspect_service_health",
        target_service_id=svc_id,
        risk_level="low",
        decision="approved",
        decision_reason="Testing isolated PG concurrency",
        policy_version="v1.0",
        validated_parameters={"service_id": svc_id},
    )
    db.add_all([ws, user, membership, svc, inc, dec])
    db.commit()

    created_approval_ids = []

    def make_approval() -> RemediationApproval:
        appr_db = SessionLocal()
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
            requested_by=user.id,
            requested_at=datetime.now(timezone.utc),
            reviewed_by=user.id,
            reviewed_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        appr_db.add(appr)
        appr_db.commit()
        created_approval_ids.append(appr.id)
        appr_db.close()
        return appr

    yield {
        "ws": ws,
        "user": user,
        "svc": svc,
        "incident": inc,
        "decision": dec,
        "make_approval": make_approval,
        "SessionLocal": SessionLocal,
    }

    # Teardown created records safely using a fresh dedicated session
    teardown_db = SessionLocal()
    try:
        # 1. Clean up incident events for this specific synthetic incident
        teardown_db.execute(text(f"DELETE FROM incident_events WHERE incident_id = '{inc_id}'"))
        teardown_db.commit()
    except Exception:
        teardown_db.rollback()

    for appr_id in created_approval_ids:
        try:
            teardown_db.execute(text(f"DELETE FROM execution_events WHERE execution_id IN (SELECT id FROM remediation_executions WHERE approval_id = '{appr_id}')"))
            teardown_db.execute(text(f"DELETE FROM execution_attempts WHERE execution_id IN (SELECT id FROM remediation_executions WHERE approval_id = '{appr_id}')"))
            teardown_db.execute(text(f"DELETE FROM remediation_executions WHERE approval_id = '{appr_id}'"))
            teardown_db.execute(text(f"DELETE FROM remediation_approvals WHERE id = '{appr_id}'"))
            teardown_db.commit()
        except Exception:
            teardown_db.rollback()

    try:
        teardown_db.execute(text(f"DELETE FROM policy_decisions WHERE id = '{dec_id}'"))
        teardown_db.execute(text(f"DELETE FROM incidents WHERE id = '{inc_id}'"))
        teardown_db.execute(text(f"DELETE FROM services WHERE id = '{svc_id}'"))
        teardown_db.execute(text(f"DELETE FROM workspace_memberships WHERE workspace_id = '{ws_id}'"))
        teardown_db.execute(text(f"DELETE FROM users WHERE id = '{user_id}'"))
        teardown_db.execute(text(f"DELETE FROM workspaces WHERE id = '{ws_id}'"))
        teardown_db.commit()
    except Exception:
        teardown_db.rollback()
    teardown_db.close()


# ============================================================================
# 1. Real PostgreSQL Concurrency: Two Independent Workers Competing for Same Queue
# ============================================================================

def test_live_postgres_two_workers_competing_claims_exactly_once(pg_engine, live_pg_env):
    """
    Real PostgreSQL concurrency test:
    - 2 independent worker threads backed by separate database sessions.
    - 1 queued job in PostgreSQL.
    - Proves: Exactly ONE worker claims and executes the job via FOR UPDATE SKIP LOCKED.
    - Proves: ZERO duplicate container dispatches occur.
    """
    env = live_pg_env
    SessionLocal = env["SessionLocal"]
    db = SessionLocal()

    appr = env["make_approval"]()
    exec_record = RemediationExecutionManager.create_execution(
        db=db,
        workspace_id=env["ws"].id,
        approval_id=appr.id,
        idempotency_key=f"pg_race_{uuid.uuid4().hex[:8]}",
        triggered_by=env["user"],
        user_role="engineer",
    )
    exec_id = exec_record.id
    db.close()

    runner_1 = ControlledTestRunner(delay_seconds=0.05)
    runner_2 = ControlledTestRunner(delay_seconds=0.05)

    worker_1 = DurableExecutionWorker(
        worker_id="pg-worker-1",
        runner=runner_1,
        db_factory=SessionLocal,
        workspace_id=env["ws"].id,
    )
    worker_2 = DurableExecutionWorker(
        worker_id="pg-worker-2",
        runner=runner_2,
        db_factory=SessionLocal,
        workspace_id=env["ws"].id,
    )

    results = []

    def run_worker(w: DurableExecutionWorker):
        res = w.run_once()
        results.append((w.worker_id, res))
        return res

    # Launch both workers simultaneously against live PostgreSQL
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        f1 = executor.submit(run_worker, worker_1)
        f2 = executor.submit(run_worker, worker_2)
        f1.result()
        f2.result()

    # Exactly one worker claimed the job; the other worker received None
    claimed_workers = [w_id for w_id, job_id in results if job_id == exec_id]
    empty_workers = [w_id for w_id, job_id in results if job_id is None]

    assert len(claimed_workers) == 1, f"Expected exactly 1 claim, got: {claimed_workers}, results: {results}"
    assert len(empty_workers) == 1, f"Expected exactly 1 empty poll, got: {empty_workers}, results: {results}"

    # Verify runner dispatch counts: exactly one was dispatched, zero duplicate dispatch
    total_dispatches = runner_1.call_count + runner_2.call_count
    assert total_dispatches == 1

    # Reload from live PostgreSQL
    verify_db = SessionLocal()
    saved_exec = verify_db.query(RemediationExecution).filter_by(id=exec_id).one()
    assert saved_exec.status == ExecutionState.EXECUTION_SUCCEEDED.value
    assert saved_exec.fencing_token >= 1
    assert saved_exec.locked_by is None
    verify_db.close()


# ============================================================================
# 2. Real PostgreSQL Monotonic Fencing Token Enforcement
# ============================================================================

def test_live_postgres_monotonic_fencing_token_increase(pg_engine, live_pg_env):
    """
    Real PostgreSQL test verifying fencing tokens increase monotonically:
    - Initial claim sets token = 1.
    - Worker crashes in validating state; lease expires.
    - Recovery worker claims; token increases to 2.
    - Recovery worker crashes; lease expires.
    - Third worker claims; token increases to 3.
    """
    env = live_pg_env
    SessionLocal = env["SessionLocal"]
    db = SessionLocal()

    appr = env["make_approval"]()
    now_utc = datetime.now(timezone.utc)

    # Insert execution into PostgreSQL with fencing_token = 1, locked in validating
    crashed_exec = RemediationExecution(
        id=str(uuid.uuid4()),
        workspace_id=env["ws"].id,
        approval_id=appr.id,
        action_id="inspect_service_health",
        target_service_id=env["svc"].id,
        approved_parameters={"service_id": env["svc"].id},
        status=ExecutionState.VALIDATING.value,
        idempotency_key=f"pg_fence_{uuid.uuid4().hex[:8]}",
        locked_by="worker-crashed-1",
        locked_until=now_utc - timedelta(seconds=10),  # EXPIRED LEASE
        fencing_token=1,
        attempt_count=1,
        triggered_by=env["user"].id,
        triggered_at=now_utc - timedelta(minutes=1),
    )
    db.add(crashed_exec)
    db.commit()

    # Worker 2 recovers in live PostgreSQL
    claimed_rec = RemediationExecutionManager.claim_next_execution(
        worker_id="worker-recovery-2",
        lease_seconds=60,
        workspace_id=env["ws"].id,
        db=db,
    )
    assert claimed_rec is not None
    assert claimed_rec.id == crashed_exec.id
    assert claimed_rec.fencing_token == 2  # Monotonically incremented to 2
    assert claimed_rec.locked_by == "worker-recovery-2"
    db.commit()

    # Simulate Worker 2 lease expiring
    claimed_rec.locked_until = now_utc - timedelta(seconds=5)
    db.commit()

    # Worker 3 recovers in live PostgreSQL
    claimed_rec_3 = RemediationExecutionManager.claim_next_execution(
        worker_id="worker-recovery-3",
        lease_seconds=60,
        workspace_id=env["ws"].id,
        db=db,
    )
    assert claimed_rec_3 is not None
    assert claimed_rec_3.id == crashed_exec.id
    assert claimed_rec_3.fencing_token == 3  # Monotonically incremented to 3
    assert claimed_rec_3.locked_by == "worker-recovery-3"
    db.close()


# ============================================================================
# 3. Real PostgreSQL Stale Worker Rejection
# ============================================================================

def test_live_postgres_stale_worker_cannot_overwrite_newer_worker_state(pg_engine, live_pg_env):
    """
    Real PostgreSQL test verifying that a stale worker with an outdated fencing token
    cannot update execution state or heartbeat after lease was stolen.
    """
    env = live_pg_env
    SessionLocal = env["SessionLocal"]
    db = SessionLocal()

    appr = env["make_approval"]()
    now_utc = datetime.now(timezone.utc)

    # Job currently held by Worker 2 with fencing_token = 5
    execution = RemediationExecution(
        id=str(uuid.uuid4()),
        workspace_id=env["ws"].id,
        approval_id=appr.id,
        action_id="inspect_service_health",
        target_service_id=env["svc"].id,
        approved_parameters={"service_id": env["svc"].id},
        status=ExecutionState.EXECUTING.value,
        idempotency_key=f"pg_stale_{uuid.uuid4().hex[:8]}",
        locked_by="worker-current-2",
        locked_until=now_utc + timedelta(seconds=90),
        fencing_token=5,  # CURRENT ACTIVE TOKEN IS 5
        attempt_count=1,
        triggered_by=env["user"].id,
        triggered_at=now_utc,
    )
    db.add(execution)
    db.commit()

    try:
        # 1. Stale Worker attempts heartbeat with stale token = 4 -> REJECTED
        with pytest.raises(StaleWorkerFencingError) as exc_info:
            RemediationExecutionManager.heartbeat_lease(
                execution_id=execution.id,
                worker_id="worker-current-2",
                expected_fencing_token=4,  # STALE TOKEN (active is 5)
                lease_seconds=60,
                db=db,
            )
        assert "fencing token mismatch" in str(exc_info.value).lower()
        db.rollback()

        # 2. Non-owning worker attempts heartbeat -> REJECTED
        with pytest.raises(StaleWorkerFencingError) as exc_info:
            RemediationExecutionManager.heartbeat_lease(
                execution_id=execution.id,
                worker_id="worker-stale-1",  # NOT lock owner
                expected_fencing_token=5,
                lease_seconds=60,
                db=db,
            )
        assert "locked by" in str(exc_info.value).lower()
        db.rollback()

        # 3. Stale Worker attempts state transition with token = 4 -> REJECTED
        with pytest.raises(StaleWorkerFencingError) as exc_info:
            RemediationExecutionManager.transition_execution_state(
                execution_id=execution.id,
                new_state=ExecutionState.EXECUTION_SUCCEEDED.value,
                expected_fencing_token=4,  # STALE TOKEN
                db=db,
            )
        assert "fencing token mismatch" in str(exc_info.value).lower()
        db.rollback()

        # Verify PostgreSQL state was NOT altered by stale worker
        db.refresh(execution)
        assert execution.status == ExecutionState.EXECUTING.value
        assert execution.fencing_token == 5
        assert execution.locked_by == "worker-current-2"
    finally:
        db.close()


# ============================================================================
# 4. Real PostgreSQL Post-Dispatch Crash: Zero Duplicate Dispatch
# ============================================================================

def test_live_postgres_lease_expiry_does_not_permit_duplicate_dispatch_after_executing(pg_engine, live_pg_env):
    """
    Real PostgreSQL test verifying crash after dispatch (executing state with expired lease):
    - Recovers directly into execution_uncertain.
    - Proves runner.call_count == 0 (ZERO DUPLICATE CONTAINER DISPATCH).
    """
    env = live_pg_env
    SessionLocal = env["SessionLocal"]
    db = SessionLocal()

    appr = env["make_approval"]()
    now_utc = datetime.now(timezone.utc)

    crashed_exec_id = str(uuid.uuid4())
    attempt_id = str(uuid.uuid4())

    # Dispatched execution that crashed mid-flight
    crashed_exec = RemediationExecution(
        id=crashed_exec_id,
        workspace_id=env["ws"].id,
        approval_id=appr.id,
        action_id="inspect_service_health",
        target_service_id=env["svc"].id,
        approved_parameters={"service_id": env["svc"].id},
        status=ExecutionState.EXECUTING.value,
        idempotency_key=f"pg_post_crash_{uuid.uuid4().hex[:8]}",
        locked_by="crashed-worker",
        locked_until=now_utc - timedelta(seconds=20),  # EXPIRED LEASE
        fencing_token=2,
        attempt_count=1,
        triggered_by=env["user"].id,
        triggered_at=now_utc - timedelta(minutes=5),
    )
    db.add(crashed_exec)

    attempt = ExecutionAttempt(
        id=attempt_id,
        execution_id=crashed_exec_id,
        attempt_number=1,
        status="running",
        worker_id="crashed-worker",
        fencing_token=2,
        started_at=now_utc - timedelta(minutes=4),
    )
    db.add(attempt)
    db.commit()
    db.close()

    runner = ControlledTestRunner()
    worker = DurableExecutionWorker(
        worker_id="pg-recovery-worker",
        runner=runner,
        db_factory=SessionLocal,
        workspace_id=env["ws"].id,
    )

    # Recovery worker runs
    recovered_job = worker.run_once()

    # CRITICAL INVARIANT: ZERO duplicate dispatch
    assert runner.call_count == 0, "Dispatched container must NEVER be re-dispatched blindly!"

    # Verify state in PostgreSQL
    verify_db = SessionLocal()
    try:
        saved = verify_db.query(RemediationExecution).filter_by(id=crashed_exec_id).one()
        assert saved.status == ExecutionState.EXECUTION_UNCERTAIN.value
        assert saved.error_category == "worker_crash_after_dispatch"
        assert saved.locked_by is None
        assert saved.locked_until is None

        # In-flight attempt finalized to uncertain
        saved_attempt = verify_db.query(ExecutionAttempt).filter_by(id=attempt_id).one()
        assert saved_attempt.status == "uncertain"
    finally:
        verify_db.close()
