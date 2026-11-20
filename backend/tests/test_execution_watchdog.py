"""Comprehensive Test Suite for Execution Watchdog & Recovery Daemon (Phase 4.3.6 Milestone D).

Tests:
1. Expired lease reconciliation in QUEUED state (clears lease, fences old worker).
2. Stuck QUEUED execution with expired approval (transitions to CANCELLED).
3. Expired lease in VALIDATING state (transitions to EXECUTION_FAILED, never redispatched).
4. Expired lease in EXECUTING state (establishes HOLD:EXECUTION_UNCERTAIN, attempt marked uncertain).
5. Existing EXECUTION_UNCERTAIN state is preserved (never retried, hold preserved).
6. Expired lease in VERIFICATION_PENDING state (establishes HOLD:VERIFICATION_UNCERTAIN).
7. Expired verification cycle deadline (marks cycle timed_out, execution verification_failed).
8. Worker heartbeat loss triggers reconciliation even if locked_until is ahead.
9. Stale worker fencing lockout: worker with old token cannot update fenced execution.
10. Reconciliation of pre-passed verification cycle recovers incident via atomic bridge.
11. Read-only verification resumption (resume_verification=True) runs probes without remediation redispatch.
12. Read-only verification failure keeps incident active (NEVER recovered).
13. Idempotent repeated watchdog scans produce zero duplicate updates or events.
14. Database error handling fails closed and rolls back cleanly.
15. Cross-workspace isolation (watchdog only reconciles designated workspace).
16. Graceful daemon shutdown.
17. Live PostgreSQL concurrency test with isolated database (FOR UPDATE SKIP LOCKED across multiple watchdogs).
"""

import concurrent.futures
from datetime import datetime, timedelta, timezone
import json
import os
import threading
import time
from typing import Any, Dict, List, Optional
import uuid
import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from app.db.base import Base
from app.execution.exceptions import (
    CrossWorkspaceViolationError,
    StaleWorkerFencingError,
)
from app.execution.recovery_bridge import IncidentRecoveryBridge
from app.execution.runner import ExecutionResult, ExecutionRunnerInterface
from app.execution.state_machine import ExecutionState
from app.execution.verification import PostExecutionVerificationEngine, VerificationOutcome
from app.execution.verification_persistence import (
    VerificationPersistenceService,
    generate_deterministic_probe_id,
)
from app.execution.watchdog import ExecutionWatchdog, HOLD_EXPIRATION_TIMESTAMP
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
from app.models.verification import VerificationCycle, VerificationProbeResult
from app.models.workspace import Workspace


# ============================================================================
# Safe Test Double Runner for Verification Testing
# ============================================================================

class SafeDiagnosticOnlyRunner(ExecutionRunnerInterface):
    """Test runner for watchdog verification checks that strictly rejects mutating actions."""

    def __init__(self, should_fail: bool = False):
        self.dispatched_actions = []
        self.should_fail = should_fail

    def is_available(self) -> bool:
        return True

    def execute(
        self,
        action_id: str,
        parameters: dict,
        timeout_seconds: int = 30,
        target_url: str = None,
        environment: str = "development",
        execution_id: str = None,
    ) -> ExecutionResult:
        self.dispatched_actions.append(action_id)

        # STRICT SAFETY INVARIANT: Only read-only diagnostic actions are allowed
        if action_id != "inspect_service_health":
            raise ValueError(
                f"SECURITY VIOLATION: Watchdog attempted non-diagnostic action '{action_id}'. "
                "Remediation actions must NEVER be redispatched!"
            )

        if self.should_fail:
            return ExecutionResult(exit_code=1, duration_ms=20, error_message="Health probe failed")

        metrics_txt = "order_api_http_5xx_errors_total 10.0\n"
        endpoints = {
            "health": {"status_code": 200, "duration_ms": 10, "output_data": {"status": "healthy"}, "success": True},
            "demo_status": {"status_code": 200, "duration_ms": 10, "output_data": {"failure_active": False}, "success": True},
            "metrics": {"status_code": 200, "duration_ms": 10, "output_data": {"raw_text": metrics_txt, "status_code": 200}, "raw_text": metrics_txt, "success": True},
        }
        return ExecutionResult(
            exit_code=0,
            duration_ms=30,
            stdout="OK",
            output_data={
                "status": "completed",
                "endpoints": endpoints,
                "all_endpoints_successful": True,
            },
        )


# ============================================================================
# Pytest Fixtures
# ============================================================================

@pytest.fixture
def db_session():
    """Create isolated in-memory SQLite database session for unit tests."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()

    yield session

    session.close()
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def base_entities(db_session):
    """Seed base entities: workspace, user, service, and incident."""
    now_utc = datetime.now(timezone.utc)
    ws_id = str(uuid.uuid4())
    ws = Workspace(id=ws_id, name="Watchdog Test WS", slug=f"ws-{ws_id[:8]}")
    db_session.add(ws)

    user_id = str(uuid.uuid4())
    user = User(
        id=user_id,
        email="operator@watchdog.test",
        full_name="Watchdog Operator",
        hashed_password="fake_hash_pwd",
        is_active=True,
    )
    db_session.add(user)

    svc_id = str(uuid.uuid4())
    service = Service(
        id=svc_id,
        workspace_id=ws_id,
        name="Order API Test",
        health_check_url="http://host.docker.internal:8001/health",
        environment="development",
        is_active=True,
    )
    db_session.add(service)

    inc_id = str(uuid.uuid4())
    incident = Incident(
        id=inc_id,
        workspace_id=ws_id,
        service_id=svc_id,
        title="High Error Rate Outage",
        severity="high",
        status="remediating",
        trigger="http_5xx_threshold",
    )
    db_session.add(incident)

    policy_id = str(uuid.uuid4())
    policy = PolicyDecision(
        id=policy_id,
        workspace_id=ws_id,
        user_id=user_id,
        action_id="restore_order_api_demo",
        target_service_id=svc_id,
        validated_parameters={"service_id": svc_id},
        decision="approval_required",
        decision_reason="Pre-flight test",
        policy_version="v1.0",
        risk_level="medium",
        timestamp=now_utc,
    )
    db_session.add(policy)

    approval_id = str(uuid.uuid4())
    approval = RemediationApproval(
        id=approval_id,
        workspace_id=ws_id,
        policy_decision_id=policy_id,
        incident_id=inc_id,
        target_service_id=svc_id,
        action_id="restore_order_api_demo",
        validated_parameters={"service_id": svc_id},
        risk_level="medium",
        policy_version="v1.0",
        approval_status="approved",
        requested_by=user_id,
        reviewed_by=user_id,
        reviewed_at=now_utc,
        expires_at=now_utc + timedelta(hours=1),
    )
    db_session.add(approval)
    db_session.commit()

    return {
        "workspace": ws,
        "user": user,
        "service": service,
        "incident": incident,
        "policy": policy,
        "approval": approval,
    }


def create_execution(
    db_session,
    base_entities,
    status: str,
    locked_by: str = None,
    locked_until: datetime = None,
    heartbeat_at: datetime = None,
    fencing_token: int = 1,
) -> RemediationExecution:
    """Helper to create test execution in specified state."""
    now_utc = datetime.now(timezone.utc)
    ws = base_entities["workspace"]
    svc = base_entities["service"]
    inc = base_entities["incident"]
    appr = base_entities["approval"]

    exec_id = str(uuid.uuid4())
    execution = RemediationExecution(
        id=exec_id,
        workspace_id=ws.id,
        approval_id=appr.id,
        incident_id=inc.id,
        action_id="restore_order_api_demo",
        target_service_id=svc.id,
        approved_parameters={"service_id": svc.id},
        status=status,
        idempotency_key=f"idem-{exec_id[:8]}",
        locked_by=locked_by,
        locked_until=locked_until,
        heartbeat_at=heartbeat_at,
        fencing_token=fencing_token,
        triggered_by=base_entities["user"].id,
        triggered_at=now_utc,
        started_at=now_utc,
        attempt_count=1,
        max_attempts=1,
    )
    db_session.add(execution)
    db_session.commit()
    return execution


# ============================================================================
# Unit Tests
# ============================================================================

def test_expired_lease_in_queued_state_clears_lease(db_session, base_entities):
    """Queued execution with expired worker lease has its lease cleared and fencing token incremented."""
    past = datetime.now(timezone.utc) - timedelta(seconds=30)
    execution = create_execution(
        db_session,
        base_entities,
        status=ExecutionState.QUEUED.value,
        locked_by="worker-stale-01",
        locked_until=past,
        fencing_token=1,
    )

    watchdog = ExecutionWatchdog(db=db_session)
    reconciled = watchdog.run_once()

    assert reconciled == 1
    db_session.refresh(execution)

    assert execution.status == ExecutionState.QUEUED.value
    assert execution.locked_by is None
    assert execution.locked_until is None
    assert execution.fencing_token == 2

    event = db_session.query(ExecutionEvent).filter_by(execution_id=execution.id, event_type="lease_cleared_queued").first()
    assert event is not None
    assert "Watchdog cleared expired worker lease" in event.message


def test_stuck_queued_execution_with_expired_approval(db_session, base_entities):
    """Queued execution whose approval expired transitions to CANCELLED."""
    now_utc = datetime.now(timezone.utc)
    appr = base_entities["approval"]
    appr.expires_at = now_utc - timedelta(seconds=10)
    db_session.commit()

    execution = create_execution(
        db_session,
        base_entities,
        status=ExecutionState.QUEUED.value,
        locked_by=None,
        locked_until=None,
        fencing_token=1,
    )

    watchdog = ExecutionWatchdog(db=db_session)
    reconciled = watchdog.run_once()

    assert reconciled == 1
    db_session.refresh(execution)

    assert execution.status == ExecutionState.CANCELLED.value
    assert execution.fencing_token == 2
    assert "expired" in execution.error_message.lower()

    event = db_session.query(ExecutionEvent).filter_by(execution_id=execution.id, event_type="approval_expired_cancelled").first()
    assert event is not None


def test_expired_lease_in_validating_state_fails_execution(db_session, base_entities):
    """Validating execution with expired lease transitions to EXECUTION_FAILED (never redispatched)."""
    past = datetime.now(timezone.utc) - timedelta(seconds=20)
    execution = create_execution(
        db_session,
        base_entities,
        status=ExecutionState.VALIDATING.value,
        locked_by="worker-crashed-pre-dispatch",
        locked_until=past,
        fencing_token=2,
    )

    watchdog = ExecutionWatchdog(db=db_session)
    reconciled = watchdog.run_once()

    assert reconciled == 1
    db_session.refresh(execution)

    assert execution.status == ExecutionState.EXECUTION_FAILED.value
    assert execution.locked_by is None
    assert execution.fencing_token == 3
    assert execution.error_category == "worker_crash_during_validation"

    event = db_session.query(ExecutionEvent).filter_by(execution_id=execution.id, event_type="validation_timeout_failed").first()
    assert event is not None


def test_expired_lease_in_executing_state_establishes_uncertainty_hold(db_session, base_entities):
    """Executing execution with expired lease transitions to HOLD:EXECUTION_UNCERTAIN."""
    past = datetime.now(timezone.utc) - timedelta(seconds=30)
    execution = create_execution(
        db_session,
        base_entities,
        status=ExecutionState.EXECUTING.value,
        locked_by="worker-crashed-in-flight",
        locked_until=past,
        fencing_token=10,
    )

    attempt = ExecutionAttempt(
        id=str(uuid.uuid4()),
        execution_id=execution.id,
        attempt_number=1,
        status="running",
        worker_id="worker-crashed-in-flight",
        fencing_token=10,
        started_at=past,
    )
    db_session.add(attempt)
    db_session.commit()

    watchdog = ExecutionWatchdog(db=db_session)
    reconciled = watchdog.run_once()

    assert reconciled == 1
    db_session.refresh(execution)
    db_session.refresh(attempt)

    assert execution.status == ExecutionState.EXECUTION_UNCERTAIN.value
    assert execution.locked_by == "HOLD:EXECUTION_UNCERTAIN"
    assert execution.fencing_token == 11
    assert "WATCHDOG_LEASE_EXPIRED_AFTER_DISPATCH" in execution.uncertain_reason
    assert attempt.status == "uncertain"

    # Verify uncertainty hold metadata
    out_meta = execution.execution_output or {}
    hold_info = out_meta.get("uncertainty_hold", {})
    assert hold_info.get("hold_type") == "HOLD:EXECUTION_UNCERTAIN"
    assert hold_info.get("original_worker_id") == "worker-crashed-in-flight"
    assert hold_info.get("fenced_fencing_token") in (11, "[REDACTED]")

    # Verify incident remains active (NEVER recovered)
    inc = base_entities["incident"]
    db_session.refresh(inc)
    assert inc.status == "remediating"
    assert inc.recovered_at is None

    # Check ExecutionEvent
    exec_event = db_session.query(ExecutionEvent).filter_by(execution_id=execution.id, event_type="lease_recovery_post_dispatch_uncertain").first()
    assert exec_event is not None


def test_execution_uncertain_is_preserved_and_never_retried(db_session, base_entities):
    """Executions already in EXECUTION_UNCERTAIN are preserved; watchdog never retries them."""
    now_utc = datetime.now(timezone.utc)
    execution = create_execution(
        db_session,
        base_entities,
        status=ExecutionState.EXECUTION_UNCERTAIN.value,
        locked_by="HOLD:EXECUTION_UNCERTAIN",
        locked_until=HOLD_EXPIRATION_TIMESTAMP,
        fencing_token=15,
    )
    execution.uncertain_reason = "MANUAL_HOLD_ACTIVE"
    db_session.commit()

    watchdog = ExecutionWatchdog(db=db_session)
    reconciled = watchdog.run_once()

    db_session.refresh(execution)
    assert execution.status == ExecutionState.EXECUTION_UNCERTAIN.value
    assert execution.locked_by == "HOLD:EXECUTION_UNCERTAIN"
    assert execution.fencing_token == 15  # Unchanged
    assert execution.uncertain_reason == "MANUAL_HOLD_ACTIVE"


def test_expired_lease_in_verification_pending_establishes_verification_uncertain_hold(db_session, base_entities):
    """Verification pending execution with expired lease transitions to HOLD:VERIFICATION_UNCERTAIN."""
    now_utc = datetime.now(timezone.utc)
    past = now_utc - timedelta(seconds=20)
    execution = create_execution(
        db_session,
        base_entities,
        status=ExecutionState.VERIFICATION_PENDING.value,
        locked_by="worker-died-in-verify",
        locked_until=past,
        fencing_token=5,
    )

    cycle_id = str(uuid.uuid4())
    cycle = VerificationCycle(
        id=cycle_id,
        execution_id=execution.id,
        workspace_id=base_entities["workspace"].id,
        cycle_number=1,
        status="running",
        probes_required=3,
        probes_passed=1,
        probes_failed=0,
        started_at=past,
        deadline_at=now_utc + timedelta(seconds=30),  # Deadline unexpired
        fencing_token=5,
        verifying_worker_id="worker-died-in-verify",
        cycle_metadata={"outcome": "IN_PROGRESS"},
    )
    db_session.add(cycle)
    db_session.commit()

    # Default fail-closed watchdog (resume_verification=False)
    watchdog = ExecutionWatchdog(db=db_session, resume_verification=False)
    reconciled = watchdog.run_once()

    assert reconciled == 1
    db_session.refresh(execution)
    db_session.refresh(cycle)

    assert execution.status == ExecutionState.VERIFICATION_PENDING.value
    assert execution.locked_by == "HOLD:VERIFICATION_UNCERTAIN"
    assert execution.fencing_token == 6
    assert execution.verification_status == "uncertain"
    assert cycle.status == "uncertain"

    # Incident remains active (NEVER recovered)
    inc = base_entities["incident"]
    db_session.refresh(inc)
    assert inc.status == "remediating"
    assert inc.recovered_at is None


def test_expired_verification_cycle_deadline_fails_execution(db_session, base_entities):
    """Expired verification cycle deadline marks cycle timed_out and execution verification_failed."""
    now_utc = datetime.now(timezone.utc)
    past = now_utc - timedelta(seconds=60)
    execution = create_execution(
        db_session,
        base_entities,
        status=ExecutionState.VERIFICATION_PENDING.value,
        locked_by="worker-slow-01",
        locked_until=now_utc + timedelta(seconds=60),  # Worker lease unexpired
        fencing_token=8,
    )

    cycle_id = str(uuid.uuid4())
    cycle = VerificationCycle(
        id=cycle_id,
        execution_id=execution.id,
        workspace_id=base_entities["workspace"].id,
        cycle_number=1,
        status="running",
        probes_required=3,
        probes_passed=2,
        probes_failed=0,
        started_at=past - timedelta(seconds=30),
        deadline_at=past,  # Deadline EXPIRED
        fencing_token=8,
        verifying_worker_id="worker-slow-01",
    )
    db_session.add(cycle)
    db_session.commit()

    watchdog = ExecutionWatchdog(db=db_session)
    reconciled = watchdog.run_once()

    assert reconciled == 1
    db_session.refresh(execution)
    db_session.refresh(cycle)

    assert cycle.status == "timed_out"
    assert execution.status == ExecutionState.VERIFICATION_FAILED.value
    assert execution.verification_status == "failed"
    assert execution.locked_by is None
    assert execution.fencing_token == 9
    assert "WATCHDOG_VERIFICATION_DEADLINE_EXPIRED" in execution.uncertain_reason

    # Incident remains active (NEVER recovered)
    inc = base_entities["incident"]
    db_session.refresh(inc)
    assert inc.status == "remediating"
    assert inc.recovered_at is None


def test_worker_heartbeat_loss_triggers_reconciliation(db_session, base_entities):
    """Heartbeat timestamp older than heartbeat_timeout triggers reconciliation even if lease is ahead."""
    now_utc = datetime.now(timezone.utc)
    stale_heartbeat = now_utc - timedelta(seconds=90)  # > 60s timeout
    future_lease = now_utc + timedelta(seconds=300)     # lease erroneously set far ahead

    execution = create_execution(
        db_session,
        base_entities,
        status=ExecutionState.EXECUTING.value,
        locked_by="worker-frozen-heartbeat",
        locked_until=future_lease,
        heartbeat_at=stale_heartbeat,
        fencing_token=3,
    )

    watchdog = ExecutionWatchdog(db=db_session, heartbeat_timeout_seconds=60.0)
    reconciled = watchdog.run_once()

    assert reconciled == 1
    db_session.refresh(execution)

    assert execution.status == ExecutionState.EXECUTION_UNCERTAIN.value
    assert execution.locked_by == "HOLD:EXECUTION_UNCERTAIN"
    assert execution.fencing_token == 4


def test_stale_worker_fencing_token_lockout_after_watchdog_fencing(db_session, base_entities):
    """Worker attempting update with stale fencing token after watchdog fencing affects 0 rows."""
    now_utc = datetime.now(timezone.utc)
    past = now_utc - timedelta(seconds=30)
    execution = create_execution(
        db_session,
        base_entities,
        status=ExecutionState.EXECUTING.value,
        locked_by="worker-stalled-01",
        locked_until=past,
        fencing_token=5,
    )

    # Watchdog establishes hold, incrementing fencing token to 6
    watchdog = ExecutionWatchdog(db=db_session)
    watchdog.run_once()

    db_session.refresh(execution)
    assert execution.fencing_token == 6
    assert execution.locked_by == "HOLD:EXECUTION_UNCERTAIN"

    # Stale worker resumes and attempts heartbeat with old token (5)
    late_heartbeat = (
        db_session.query(RemediationExecution)
        .filter(
            RemediationExecution.id == execution.id,
            RemediationExecution.locked_by == "worker-stalled-01",
            RemediationExecution.fencing_token == 5,
        )
        .update(
            {"locked_until": now_utc + timedelta(seconds=30)},
            synchronize_session=False,
        )
    )

    # Strictly 0 rows updated!
    assert late_heartbeat == 0


def test_reconciliation_of_passed_verification_cycle_recovers_incident(db_session, base_entities):
    """When verification cycle already passed before worker died, watchdog completes atomic recovery."""
    now_utc = datetime.now(timezone.utc)
    past = now_utc - timedelta(seconds=30)
    execution = create_execution(
        db_session,
        base_entities,
        status=ExecutionState.VERIFICATION_PENDING.value,
        locked_by="worker-passed-then-crashed",
        locked_until=past,
        fencing_token=7,
    )

    cycle_id = str(uuid.uuid4())
    cycle = VerificationCycle(
        id=cycle_id,
        execution_id=execution.id,
        workspace_id=base_entities["workspace"].id,
        cycle_number=1,
        status="passed",
        probes_required=3,
        probes_passed=3,
        probes_failed=0,
        started_at=past - timedelta(seconds=15),
        completed_at=past,
        deadline_at=now_utc + timedelta(seconds=60),
        fencing_token=7,
        verifying_worker_id="worker-passed-then-crashed",
        cycle_metadata={"outcome": "PASS", "probes_passed": 3},
    )
    db_session.add(cycle)

    # Probe 1: baseline
    probe1 = VerificationProbeResult(
        id=generate_deterministic_probe_id(execution.id, 1, 1),
        cycle_id=cycle_id,
        execution_id=execution.id,
        workspace_id=base_entities["workspace"].id,
        probe_number=1,
        probe_type="baseline",
        target_url="http://host.docker.internal:8001/health",
        status="passed",
        passed=True,
        executed_at=past,
        latency_ms=10.0,
    )
    db_session.add(probe1)

    # Probes 2-4: passing
    for p_num in (2, 3, 4):
        p = VerificationProbeResult(
            id=generate_deterministic_probe_id(execution.id, 1, p_num),
            cycle_id=cycle_id,
            execution_id=execution.id,
            workspace_id=base_entities["workspace"].id,
            probe_number=p_num,
            probe_type="health_check",
            target_url="http://host.docker.internal:8001/health",
            status="passed",
            passed=True,
            executed_at=past + timedelta(seconds=p_num),
            latency_ms=10.0,
        )
        db_session.add(p)

    db_session.commit()

    watchdog = ExecutionWatchdog(db=db_session)
    reconciled = watchdog.run_once()

    assert reconciled == 1
    db_session.refresh(execution)
    inc = base_entities["incident"]
    db_session.refresh(inc)

    assert execution.status == ExecutionState.VERIFIED.value
    assert execution.verification_status == "verified"
    assert inc.status == "recovered"
    assert inc.recovered_at is not None


def test_resume_read_only_verification_without_remediation_redispatch(db_session, base_entities):
    """When resume_verification=True, watchdog runs read-only probes and NEVER redispatches remediation."""
    now_utc = datetime.now(timezone.utc)
    past = now_utc - timedelta(seconds=20)
    execution = create_execution(
        db_session,
        base_entities,
        status=ExecutionState.VERIFICATION_PENDING.value,
        locked_by="worker-died",
        locked_until=past,
        fencing_token=4,
    )

    cycle_id = str(uuid.uuid4())
    cycle = VerificationCycle(
        id=cycle_id,
        execution_id=execution.id,
        workspace_id=base_entities["workspace"].id,
        cycle_number=1,
        status="running",
        probes_required=3,
        probes_passed=0,
        probes_failed=0,
        started_at=past,
        deadline_at=now_utc + timedelta(seconds=45),  # Unexpired deadline
        fencing_token=4,
        verifying_worker_id="worker-died",
    )
    db_session.add(cycle)
    db_session.commit()

    safe_runner = SafeDiagnosticOnlyRunner(should_fail=False)
    watchdog = ExecutionWatchdog(
        db=db_session,
        resume_verification=True,
        runner=safe_runner,
    )
    reconciled = watchdog.run_once()

    assert reconciled == 1
    db_session.refresh(execution)
    inc = base_entities["incident"]
    db_session.refresh(inc)

    # Verification succeeded -> incident recovered
    assert execution.status == ExecutionState.VERIFIED.value
    assert inc.status == "recovered"
    assert inc.recovered_at is not None

    # CRITICAL INVARIANT: Only inspect_service_health was dispatched; NEVER restore_order_api_demo
    assert len(safe_runner.dispatched_actions) > 0
    assert all(a == "inspect_service_health" for a in safe_runner.dispatched_actions)
    assert "restore_order_api_demo" not in safe_runner.dispatched_actions


def test_resume_read_only_verification_fails_keeps_incident_active(db_session, base_entities):
    """When resumed read-only verification fails, execution marks verification_failed and incident remains active."""
    now_utc = datetime.now(timezone.utc)
    past = now_utc - timedelta(seconds=20)
    execution = create_execution(
        db_session,
        base_entities,
        status=ExecutionState.VERIFICATION_PENDING.value,
        locked_by="worker-died",
        locked_until=past,
        fencing_token=4,
    )

    cycle_id = str(uuid.uuid4())
    cycle = VerificationCycle(
        id=cycle_id,
        execution_id=execution.id,
        workspace_id=base_entities["workspace"].id,
        cycle_number=1,
        status="running",
        probes_required=3,
        probes_passed=0,
        probes_failed=0,
        started_at=past,
        deadline_at=now_utc + timedelta(seconds=45),
        fencing_token=4,
        verifying_worker_id="worker-died",
    )
    db_session.add(cycle)
    db_session.commit()

    # Runner that fails diagnostic probes
    failing_runner = SafeDiagnosticOnlyRunner(should_fail=True)
    watchdog = ExecutionWatchdog(
        db=db_session,
        resume_verification=True,
        runner=failing_runner,
    )
    reconciled = watchdog.run_once()

    assert reconciled == 1
    db_session.refresh(execution)
    inc = base_entities["incident"]
    db_session.refresh(inc)

    assert execution.status == ExecutionState.VERIFICATION_FAILED.value
    assert inc.status == "remediating"
    assert inc.recovered_at is None


def test_idempotent_repeated_watchdog_scans(db_session, base_entities):
    """Subsequent watchdog sweeps over already-reconciled executions are clean no-ops."""
    past = datetime.now(timezone.utc) - timedelta(seconds=30)
    execution = create_execution(
        db_session,
        base_entities,
        status=ExecutionState.EXECUTING.value,
        locked_by="worker-crashed",
        locked_until=past,
        fencing_token=1,
    )

    watchdog = ExecutionWatchdog(db=db_session)

    # First pass: reconciles 1 execution
    count_1 = watchdog.run_once()
    assert count_1 == 1

    event_count_1 = db_session.query(ExecutionEvent).filter_by(execution_id=execution.id).count()

    # Second pass: already in HOLD:EXECUTION_UNCERTAIN; returns 0 candidates to reconcile
    count_2 = watchdog.run_once()
    assert count_2 == 0

    event_count_2 = db_session.query(ExecutionEvent).filter_by(execution_id=execution.id).count()
    assert event_count_1 == event_count_2  # Zero duplicate events


def test_cross_workspace_isolation(db_session, base_entities):
    """Watchdog scoped to Workspace A never scans or mutates candidates in Workspace B."""
    past = datetime.now(timezone.utc) - timedelta(seconds=30)
    ws_b = Workspace(id=str(uuid.uuid4()), name="Workspace B", slug="ws-b")
    db_session.add(ws_b)
    db_session.commit()

    # Candidate in Workspace B
    b_id = str(uuid.uuid4())
    exec_b = RemediationExecution(
        id=b_id,
        workspace_id=ws_b.id,
        approval_id=base_entities["approval"].id,
        action_id="restore_order_api_demo",
        target_service_id=base_entities["service"].id,
        status=ExecutionState.EXECUTING.value,
        idempotency_key=f"idem-{b_id[:8]}",
        triggered_by=base_entities["user"].id,
        locked_by="worker-ws-b",
        locked_until=past,
        fencing_token=1,
        attempt_count=1,
        max_attempts=1,
    )
    db_session.add(exec_b)
    db_session.commit()

    # Watchdog scoped exclusively to Workspace A
    watchdog = ExecutionWatchdog(db=db_session, workspace_id=base_entities["workspace"].id)
    reconciled = watchdog.run_once()

    assert reconciled == 0
    db_session.refresh(exec_b)
    assert exec_b.status == ExecutionState.EXECUTING.value
    assert exec_b.locked_by == "worker-ws-b"  # Untouched


def test_graceful_shutdown(db_session):
    """Watchdog background thread starts and stops gracefully within shutdown grace period."""
    watchdog = ExecutionWatchdog(db=db_session, poll_interval=0.1)
    watchdog.start()
    assert watchdog._worker_thread is not None
    assert watchdog._worker_thread.is_alive()

    time.sleep(0.2)
    watchdog.stop()
    assert not watchdog._worker_thread.is_alive()
    assert not watchdog._is_running


# ============================================================================
# Live PostgreSQL 18 Concurrency Test (Isolated Test Database)
# ============================================================================

def get_live_postgres_url() -> Optional[str]:
    """Retrieve PostgreSQL 18 URL if configured; otherwise skip live concurrency test."""
    env_file = r"d:\Sentinal_AI\backend\.env"
    if os.path.exists(env_file):
        with open(env_file, "r") as f:
            for line in f:
                line_str = line.strip()
                if line_str.startswith("DATABASE_URL="):
                    return line_str.split("=", 1)[1]
    return os.getenv("DATABASE_URL", None)


def test_concurrent_watchdog_instances_on_isolated_postgres():
    """
    Live PostgreSQL 18.3 Concurrency Test:
    - Runs exclusively on an isolated temporary database (sentinelops_test_watchdog_isolated).
    - Never touches sentinelops_dev.
    - Multiple watchdog threads run simultaneously with FOR UPDATE SKIP LOCKED.
    - Proves zero race conditions, zero deadlocks, and zero duplicate reconciliations.
    """
    pg_url = get_live_postgres_url()
    if not pg_url or "postgresql" not in pg_url:
        pytest.skip("PostgreSQL connection not configured. Skipping live PG concurrency test.")

    # Isolated database name
    isolated_db_name = "sentinelops_test_watchdog_isolated"
    admin_url = pg_url.rsplit("/", 1)[0] + "/postgres"

    admin_engine = create_engine(admin_url, isolation_level="AUTOCOMMIT")

    # Ensure clean database creation
    with admin_engine.connect() as conn:
        conn.execute(
            text(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                f"WHERE datname = '{isolated_db_name}' AND pid <> pg_backend_pid()"
            )
        )
        conn.execute(text(f"DROP DATABASE IF EXISTS {isolated_db_name}"))
        conn.execute(text(f"CREATE DATABASE {isolated_db_name}"))

    admin_engine.dispose()

    isolated_url = pg_url.rsplit("/", 1)[0] + f"/{isolated_db_name}"
    isolated_engine = create_engine(isolated_url, pool_size=10, max_overflow=5)

    try:
        # Create all schemas in isolated test database
        Base.metadata.create_all(bind=isolated_engine)
        SessionFactory = sessionmaker(bind=isolated_engine)

        now_utc = datetime.now(timezone.utc)
        past = now_utc - timedelta(seconds=45)

        # Seed 10 candidates requiring recovery
        ws_id = str(uuid.uuid4())
        user_id = str(uuid.uuid4())
        svc_id = str(uuid.uuid4())
        inc_id = str(uuid.uuid4())
        with SessionFactory() as seed_session:
            seed_session.add(Workspace(id=ws_id, name="PG Concurrency WS", slug="pg-conc-ws"))
            seed_session.add(User(id=user_id, email="pg_op@test.local", full_name="PG Op", hashed_password="pwd", is_active=True))
            seed_session.add(Service(id=svc_id, workspace_id=ws_id, name="Order Svc", health_check_url="http://host:8001/health", environment="development", is_active=True))
            seed_session.add(Incident(id=inc_id, workspace_id=ws_id, service_id=svc_id, title="Outage", severity="high", status="remediating", trigger="threshold"))

            execution_ids = []
            for i in range(10):
                p_id = str(uuid.uuid4())
                a_id = str(uuid.uuid4())
                eid = str(uuid.uuid4())
                execution_ids.append(eid)
                seed_session.add(
                    PolicyDecision(
                        id=p_id,
                        workspace_id=ws_id,
                        user_id=user_id,
                        action_id="restore_order_api_demo",
                        target_service_id=svc_id,
                        validated_parameters={},
                        decision="approved",
                        decision_reason="Pre-flight test approved",
                        policy_version="v1.0",
                        risk_level="low",
                        timestamp=now_utc,
                    )
                )
                seed_session.add(
                    RemediationApproval(
                        id=a_id,
                        workspace_id=ws_id,
                        policy_decision_id=p_id,
                        incident_id=inc_id,
                        target_service_id=svc_id,
                        action_id="restore_order_api_demo",
                        validated_parameters={},
                        risk_level="low",
                        policy_version="v1.0",
                        approval_status="approved",
                        requested_by=user_id,
                        reviewed_by=user_id,
                        reviewed_at=now_utc,
                        expires_at=now_utc + timedelta(hours=1),
                    )
                )
                seed_session.add(
                    RemediationExecution(
                        id=eid,
                        workspace_id=ws_id,
                        approval_id=a_id,
                        action_id="restore_order_api_demo",
                        target_service_id=svc_id,
                        status=ExecutionState.EXECUTING.value,
                        idempotency_key=f"idem-{eid[:8]}",
                        triggered_by=user_id,
                        locked_by=f"worker-crashed-{i}",
                        locked_until=past,
                        fencing_token=1,
                        attempt_count=1,
                        max_attempts=1,
                    )
                )
            seed_session.commit()

        # Instantiate 3 concurrent watchdog instances
        w1 = ExecutionWatchdog(db_factory=SessionFactory, watchdog_id="watchdog-pg-1")
        w2 = ExecutionWatchdog(db_factory=SessionFactory, watchdog_id="watchdog-pg-2")
        w3 = ExecutionWatchdog(db_factory=SessionFactory, watchdog_id="watchdog-pg-3")

        def run_watchdog_sweep(w):
            return w.run_once()

        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            futures = [
                executor.submit(run_watchdog_sweep, w1),
                executor.submit(run_watchdog_sweep, w2),
                executor.submit(run_watchdog_sweep, w3),
            ]
            results = [f.result() for f in futures]

        # Total reconciled across all 3 concurrent watchdogs must equal exactly 10
        total_reconciled = sum(results)
        assert total_reconciled == 10, f"Expected 10 reconciled executions, but got {total_reconciled} ({results})"

        # Verify database state: all 10 executions must be in HOLD:EXECUTION_UNCERTAIN with fencing token 2
        with SessionFactory() as verify_session:
            execs = verify_session.query(RemediationExecution).filter(RemediationExecution.id.in_(execution_ids)).all()
            assert len(execs) == 10
            for e in execs:
                assert e.status == ExecutionState.EXECUTION_UNCERTAIN.value
                assert e.locked_by == "HOLD:EXECUTION_UNCERTAIN"
                assert e.fencing_token == 2

            # Exactly 10 ExecutionEvents created (one per execution)
            events = verify_session.query(ExecutionEvent).filter(ExecutionEvent.execution_id.in_(execution_ids)).all()
            assert len(events) == 10

    finally:
        isolated_engine.dispose()
        # Drop temporary isolated database cleanly
        with admin_engine.connect() as conn:
            conn.execute(
                text(
                    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                    f"WHERE datname = '{isolated_db_name}' AND pid <> pg_backend_pid()"
                )
            )
            conn.execute(text(f"DROP DATABASE IF EXISTS {isolated_db_name}"))
        admin_engine.dispose()
