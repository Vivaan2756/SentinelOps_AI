"""Comprehensive Test Suite for Phase 4.3.6 Milestone E.3.4.

Durable Worker & Watchdog Integration:
- DurableExecutionWorker with Local Dispatch Coordinator & BrokerDispatcher.
- PostExecutionVerificationEngine & IncidentRecoveryBridge integration.
- ExecutionWatchdog pre-dispatch recovery and failure-mode reconciliation.
- Complete 12-stage worker execution ordering.
- All 12 boundary crash/failure scenarios under Revision 10 rules.
- Zero-redispatch invariant and non-redispatch locks.
- Strict read-only verification resumption.
- Concurrency & idempotency verification.
"""

from datetime import datetime, timedelta, timezone
import json
import os
import tempfile
import uuid
from typing import Any, Dict, List, Optional
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.execution.broker import (
    ALLOWED_BROKER_ACTIONS,
    BrokerExecuteRequest,
    BrokerExecuteResponse,
)
from app.execution.broker_dispatcher import (
    BrokerDispatcher,
    BrokerDispatchResult,
)
from app.execution.dispatch_coordinator import (
    CoordinatorConflictError,
    CoordinatorInvalidStateError,
    CoordinatorValidationError,
    DispatchCoordinator,
    PreDispatchResolution,
    PreDispatchState,
)
from app.execution.exceptions import (
    BrokerUnavailableError,
    ExecutionEnvironmentUnavailable,
    ExecutionUncertainError,
    StaleWorkerFencingError,
)
from app.execution.journal import (
    JournalError,
    JournalRecordType,
    OperationJournal,
)
from app.execution.manager import RemediationExecutionManager
from app.execution.manifest_signer import generate_and_sign_execution_manifest
from app.execution.recovery_bridge import IncidentRecoveryBridge
from app.execution.registry import (
    OperationRecord,
    OperationRegistry,
    OperationStatus,
)
from app.execution.runner import (
    ExecutionResult,
    ExecutionRunnerInterface,
)
from app.execution.state_machine import ExecutionState
from app.execution.verification import (
    PostExecutionVerificationEngine,
    VerificationOutcome,
)
from app.execution.watchdog import ExecutionWatchdog, HOLD_EXPIRATION_TIMESTAMP
from app.execution.worker import DurableExecutionWorker, RunnerBrokerClientAdapter
from app.db.base import Base
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
# Controllable Test Fixtures & Mocks
# ============================================================================

class ControlledBrokerClient:
    """Mock Unix domain socket broker client for testing dispatcher boundaries."""

    def __init__(
        self,
        exit_code: int = 0,
        stdout: str = "Broker action succeeded.",
        stderr: str = "",
        output_data: Optional[Dict[str, Any]] = None,
        duration_ms: int = 45,
        exception_to_raise: Optional[Exception] = None,
    ):
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr
        self.output_data = output_data or {"stdout": stdout}
        self.duration_ms = duration_ms
        self.exception_to_raise = exception_to_raise
        self.call_count = 0
        self.last_request: Optional[BrokerExecuteRequest] = None

    def execute_action(self, request: BrokerExecuteRequest) -> BrokerExecuteResponse:
        self.call_count += 1
        self.last_request = request
        if self.exception_to_raise is not None:
            raise self.exception_to_raise
        return BrokerExecuteResponse(
            execution_id=request.execution_id,
            exit_code=self.exit_code,
            duration_ms=self.duration_ms,
            stdout_sample=self.stdout,
            stderr_sample=self.stderr,
            output_data=self.output_data,
            error_message=f"Process exited with code {self.exit_code}" if self.exit_code != 0 else None,
            error_category="container_nonzero_exit" if self.exit_code != 0 else None,
        )


class ControlledProbeRunner(ExecutionRunnerInterface):
    """Controllable runner for post-execution verification probes."""

    def __init__(
        self,
        should_fail_probes: bool = False,
        probe_latency_ms: int = 15,
    ):
        self.should_fail_probes = should_fail_probes
        self.probe_latency_ms = probe_latency_ms
        self.call_count = 0
        self.dispatched_actions: List[str] = []

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
        self.dispatched_actions.append(action_id)

        # STRICT SAFETY INVARIANT: Only read-only diagnostic actions are allowed during verification
        if action_id != "inspect_service_health":
            raise ValueError(
                f"SAFETY VIOLATION: Verification attempted non-diagnostic action '{action_id}'. "
                "Mutating remediation actions must NEVER be redispatched during verification!"
            )

        if self.should_fail_probes:
            return ExecutionResult(
                exit_code=1,
                duration_ms=self.probe_latency_ms,
                error_message="Probe check failed",
                error_category="probe_failed",
            )

        metrics_txt = "order_api_http_5xx_errors_total 10.0\n"
        endpoints = {
            "health": {"status_code": 200, "duration_ms": self.probe_latency_ms, "output_data": {"status": "healthy"}, "success": True},
            "demo_status": {"status_code": 200, "duration_ms": self.probe_latency_ms, "output_data": {"failure_active": False}, "success": True},
            "metrics": {"status_code": 200, "duration_ms": self.probe_latency_ms, "output_data": {"raw_text": metrics_txt, "status_code": 200}, "raw_text": metrics_txt, "success": True},
        }
        return ExecutionResult(
            exit_code=0,
            duration_ms=self.probe_latency_ms * 3,
            stdout="OK",
            output_data={
                "status": "completed",
                "endpoints": endpoints,
                "all_endpoints_successful": True,
            },
        )


@pytest.fixture
def db_session():
    """Create isolated in-memory SQLite database session."""
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
    """Seed test workspace, user, active service, incident, policy, and approval."""
    now_utc = datetime.now(timezone.utc)
    ws_id = str(uuid.uuid4())
    ws = Workspace(id=ws_id, name="Integration Test WS", slug=f"ws-{ws_id[:8]}")
    db_session.add(ws)

    user_id = str(uuid.uuid4())
    user = User(
        id=user_id,
        email="devops@integration.test",
        full_name="DevOps Engineer",
        hashed_password="pw_hash",
        is_active=True,
    )
    db_session.add(user)

    svc_id = str(uuid.uuid4())
    service = Service(
        id=svc_id,
        workspace_id=ws_id,
        name="Order API",
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
        title="Order API High Error Rate",
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
        decision_reason="Production remediation requires review",
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
        expires_at=now_utc + timedelta(hours=2),
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


@pytest.fixture
def isolated_coordinator():
    """Provides isolated coordinator with clean temp SQLite and binary journal directories."""
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp_dir:
        db_path = os.path.join(tmp_dir, "test_registry.db")
        journal_dir = os.path.join(tmp_dir, "test_journal")
        os.makedirs(journal_dir, exist_ok=True)

        reg = OperationRegistry(db_path=db_path)
        jour = OperationJournal(journal_dir=journal_dir)
        coord = DispatchCoordinator(registry=reg, journal=jour)
        coord.initialize()

        yield coord

        coord.close()


def create_execution_record(
    db_session,
    base_entities,
    status: str = "queued",
    locked_by: Optional[str] = None,
    locked_until: Optional[datetime] = None,
    fencing_token: int = 1,
) -> RemediationExecution:
    """Helper to create execution in specified database state."""
    now_utc = datetime.now(timezone.utc)
    ws = base_entities["workspace"]
    svc = base_entities["service"]
    inc = base_entities["incident"]
    appr = base_entities["approval"]

    exec_id = str(uuid.uuid4())
    manifest, manifest_signature, manifest_digest = generate_and_sign_execution_manifest(
        execution_id=exec_id,
        approval=appr,
        service=svc,
    )

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
        fencing_token=fencing_token,
        triggered_by=base_entities["user"].id,
        triggered_at=now_utc,
        started_at=now_utc,
        attempt_count=1,
        max_attempts=1,
        manifest_id=manifest.manifest_id,
        authorization_manifest=manifest.model_dump(),
        manifest_signature=manifest_signature,
        manifest_digest=manifest_digest,
        manifest_key_id=manifest.key_id,
        manifest_expires_at=datetime.fromtimestamp(manifest.expires_at, tz=timezone.utc),
    )
    db_session.add(execution)
    db_session.commit()
    return execution


# ============================================================================
# 1. Worker Dispatch Integration Tests
# ============================================================================

def test_worker_dispatches_via_broker_dispatcher_with_strict_ordering(
    db_session, base_entities, isolated_coordinator
):
    """
    Test that worker dispatches through BrokerDispatcher following the exact 12-stage sequence:
    1. Lease & fencing token claimed in PostgreSQL.
    2. Identity & approval validated.
    3. State transitioned to EXECUTING.
    4. Local reservation created in SQLite registry.
    5. DISPATCH_PREPARED persisted to durable journal.
    6. Revalidation immediately before dispatch.
    7. DOCKER_CALL_STARTED persisted and fsynced.
    8. Broker IPC dispatched.
    9. Outcome persisted in journal and registry.
    10. State mapped to execution_succeeded.
    11. Transitioned to verification_pending.
    12. PostExecutionVerificationEngine invoked and IncidentRecoveryBridge recovers incident.
    """
    coord = isolated_coordinator
    broker_client = ControlledBrokerClient(exit_code=0)
    dispatcher = BrokerDispatcher(coordinator=coord, broker_client=broker_client)
    probe_runner = ControlledProbeRunner(should_fail_probes=False)
    verification_engine = PostExecutionVerificationEngine(runner=probe_runner)

    exec_rec = create_execution_record(db_session, base_entities, status="queued")

    worker = DurableExecutionWorker(
        worker_id="worker-test-1",
        coordinator=coord,
        broker_dispatcher=dispatcher,
        verification_engine=verification_engine,
        enable_verification=True,
        db_factory=lambda: db_session,
    )

    claimed_id = worker.run_once()
    assert claimed_id == exec_rec.id

    db_session.refresh(exec_rec)
    # Verification passed, so IncidentRecoveryBridge transitioned execution to VERIFIED
    assert exec_rec.status == ExecutionState.VERIFIED.value

    # Incident was atomically recovered
    incident = db_session.query(Incident).filter(Incident.id == base_entities["incident"].id).first()
    assert incident.status == "recovered"

    # Journal ordering verification
    records = coord.journal.replay()
    rec_types = [r.record_type for r in records if r.execution_id == exec_rec.id]
    assert len(rec_types) >= 3
    assert rec_types[0] == JournalRecordType.DISPATCH_PREPARED.value
    assert rec_types[1] == JournalRecordType.DOCKER_CALL_STARTED.value
    assert rec_types[2] == JournalRecordType.DOCKER_CALL_COMPLETED.value

    # Registry state verification
    op = coord.registry.get_operation(records[0].operation_id)
    assert op is not None
    assert op.operation_status == OperationStatus.DOCKER_CALL_COMPLETED

    # Broker client called exactly once
    assert broker_client.call_count == 1
    assert broker_client.last_request.action_id == "restore_order_api_demo"


def test_pre_dispatch_persistence_failure_aborts_without_broker_invocation(
    db_session, base_entities, isolated_coordinator
):
    """If pre-dispatch persistence fails, fail-closed barrier prevents broker invocation."""
    coord = isolated_coordinator
    broker_client = ControlledBrokerClient(exit_code=0)
    dispatcher = BrokerDispatcher(coordinator=coord, broker_client=broker_client)

    # Force journal to fail writes
    from unittest.mock import MagicMock
    coord.journal.append = MagicMock(side_effect=JournalError("Simulated disk error"))

    exec_rec = create_execution_record(db_session, base_entities, status="queued")

    worker = DurableExecutionWorker(
        worker_id="worker-fail-pers",
        coordinator=coord,
        broker_dispatcher=dispatcher,
        db_factory=lambda: db_session,
    )

    worker.run_once()

    db_session.refresh(exec_rec)
    assert exec_rec.status == ExecutionState.EXECUTION_FAILED.value
    assert exec_rec.error_category == "pre_dispatch_persistence_failure"
    assert broker_client.call_count == 0


def test_broker_exit_code_zero_does_not_directly_recover_incident(
    db_session, base_entities, isolated_coordinator
):
    """
    Blueprint & Milestone E.3.4 Rule:
    Container exit code 0 indicates local container completion ONLY.
    Remediation success alone NEVER marks the incident recovered.
    """
    coord = isolated_coordinator
    broker_client = ControlledBrokerClient(exit_code=0)
    dispatcher = BrokerDispatcher(coordinator=coord, broker_client=broker_client)

    exec_rec = create_execution_record(db_session, base_entities, status="queued")

    # Worker configured without auto-verification to inspect the intermediate state
    worker = DurableExecutionWorker(
        worker_id="worker-no-ver",
        coordinator=coord,
        broker_dispatcher=dispatcher,
        enable_verification=False,
        db_factory=lambda: db_session,
    )

    worker.run_once()

    db_session.refresh(exec_rec)
    assert exec_rec.status == ExecutionState.EXECUTION_SUCCEEDED.value

    # Incident MUST remain active ('remediating'), not recovered
    incident = db_session.query(Incident).filter(Incident.id == base_entities["incident"].id).first()
    assert incident.status == "remediating"


def test_broker_nonzero_exit_maps_to_execution_failed(
    db_session, base_entities, isolated_coordinator
):
    """Container process exit code non-zero maps directly to execution_failed."""
    coord = isolated_coordinator
    broker_client = ControlledBrokerClient(exit_code=2, stderr="Service failed to start.")
    dispatcher = BrokerDispatcher(coordinator=coord, broker_client=broker_client)

    exec_rec = create_execution_record(db_session, base_entities, status="queued")

    worker = DurableExecutionWorker(
        worker_id="worker-nz-exit",
        coordinator=coord,
        broker_dispatcher=dispatcher,
        db_factory=lambda: db_session,
    )

    worker.run_once()

    db_session.refresh(exec_rec)
    assert exec_rec.status == ExecutionState.EXECUTION_FAILED.value
    assert exec_rec.error_category == "container_nonzero_exit"
    assert "2" in exec_rec.error_message

    # Operation in coordinator is marked DISPATCH_FAILED
    ops = coord.registry.list_uncertain_operations()
    assert len(ops) == 0  # Not uncertain, clean failure


def test_broker_ipc_timeout_maps_to_execution_uncertain_with_hold(
    db_session, base_entities, isolated_coordinator
):
    """
    Any timeout or connection failure after start marker maps to execution_uncertain
    and establishes HOLD:EXECUTION_UNCERTAIN to prevent automated redispatch.
    """
    coord = isolated_coordinator
    broker_client = ControlledBrokerClient(
        exception_to_raise=TimeoutError("Broker IPC timed out waiting for container exit.")
    )
    dispatcher = BrokerDispatcher(coordinator=coord, broker_client=broker_client)

    exec_rec = create_execution_record(db_session, base_entities, status="queued")

    worker = DurableExecutionWorker(
        worker_id="worker-tout",
        coordinator=coord,
        broker_dispatcher=dispatcher,
        db_factory=lambda: db_session,
    )

    worker.run_once()

    db_session.refresh(exec_rec)
    assert exec_rec.status == ExecutionState.EXECUTION_UNCERTAIN.value
    assert exec_rec.locked_by == "HOLD:EXECUTION_UNCERTAIN"
    assert exec_rec.locked_until is not None and exec_rec.locked_until.year == 9999

    # Registry has DISPATCH_UNCERTAIN
    uncertain_ops = coord.registry.list_uncertain_operations()
    assert len(uncertain_ops) == 1
    assert uncertain_ops[0].operation_status == OperationStatus.DISPATCH_UNCERTAIN


def test_expired_approval_blocks_execution_before_broker_call(
    db_session, base_entities, isolated_coordinator
):
    """Expired approval fails pre-flight validation before broker call."""
    coord = isolated_coordinator
    broker_client = ControlledBrokerClient(exit_code=0)
    dispatcher = BrokerDispatcher(coordinator=coord, broker_client=broker_client)

    # Expire approval
    approval = base_entities["approval"]
    approval.expires_at = datetime.now(timezone.utc) - timedelta(minutes=10)
    db_session.commit()

    exec_rec = create_execution_record(db_session, base_entities, status="queued")

    worker = DurableExecutionWorker(
        worker_id="worker-exp-app",
        coordinator=coord,
        broker_dispatcher=dispatcher,
        db_factory=lambda: db_session,
    )

    worker.run_once()

    db_session.refresh(exec_rec)
    assert exec_rec.status == ExecutionState.EXECUTION_FAILED.value
    assert exec_rec.error_category == "approval_expired"
    assert broker_client.call_count == 0


def test_stale_worker_fencing_token_split_brain_prevention(
    db_session, base_entities, isolated_coordinator
):
    """Worker whose fencing token is advanced mid-flight cannot finalize outcome."""
    coord = isolated_coordinator
    broker_client = ControlledBrokerClient(exit_code=0)
    dispatcher = BrokerDispatcher(coordinator=coord, broker_client=broker_client)

    exec_rec = create_execution_record(db_session, base_entities, status="queued")

    worker = DurableExecutionWorker(
        worker_id="worker-stale-test",
        coordinator=coord,
        broker_dispatcher=dispatcher,
        db_factory=lambda: db_session,
    )

    # Claim execution to obtain token 1
    with worker._get_db() as db:
        claimed = RemediationExecutionManager.claim_next_execution(
            worker_id=worker.worker_id,
            lease_seconds=60,
            db=db,
        )
        assert claimed is not None
        claimed_id = claimed.id
        claimed_token = claimed.fencing_token

    # Simulate watchdog or another worker advancing fencing token
    with worker._get_db() as db:
        rec = db.query(RemediationExecution).filter(RemediationExecution.id == claimed_id).first()
        rec.fencing_token = claimed_token + 5
        db.commit()

    # Worker attempts to process with old claimed_token
    worker._process_claimed_execution(execution_id=claimed_id, fencing_token=claimed_token)

    # Execution was untouched by stale worker
    db_session.refresh(exec_rec)
    assert exec_rec.fencing_token == claimed_token + 5
    assert exec_rec.status == ExecutionState.VALIDATING.value  # Aborted during validation before executing
    assert broker_client.call_count == 0


# ============================================================================
# 2. Worker / Watchdog Concurrency & Race-Free Protection
# ============================================================================

def test_worker_watchdog_concurrency_fencing_lockout(
    db_session, base_entities, isolated_coordinator
):
    """
    Watchdog increments monotonic fencing token on lease expiration,
    immediately locking out a stalled worker from committing results.
    """
    coord = isolated_coordinator
    broker_client = ControlledBrokerClient(exit_code=0)
    dispatcher = BrokerDispatcher(coordinator=coord, broker_client=broker_client)

    exec_rec = create_execution_record(
        db_session,
        base_entities,
        status="executing",
        locked_by="worker-stalled",
        locked_until=datetime.now(timezone.utc) - timedelta(seconds=10),
        fencing_token=1,
    )

    watchdog = ExecutionWatchdog(
        watchdog_id="watchdog-reconciler",
        coordinator=coord,
        db_factory=lambda: db_session,
    )

    # Watchdog reconciles stalled execution
    res = watchdog.reconcile_execution(exec_rec.id)
    assert res is not None
    assert res["resulting_state"] == ExecutionState.EXECUTION_UNCERTAIN.value

    db_session.refresh(exec_rec)
    assert exec_rec.fencing_token == 2
    assert exec_rec.status == ExecutionState.EXECUTION_UNCERTAIN.value

    # Worker tries to finalize with old token 1
    worker = DurableExecutionWorker(
        worker_id="worker-stalled",
        coordinator=coord,
        broker_dispatcher=dispatcher,
        db_factory=lambda: db_session,
    )

    with worker._get_db() as db:
        worker._finalize_coordinated_outcome(
            db=db,
            execution_id=exec_rec.id,
            fencing_token=1,  # Stale token
            action_id="restore_order_api_demo",
            dispatch_result=BrokerDispatchResult(
                operation_id="op-1",
                execution_id=exec_rec.id,
                action_id="restore_order_api_demo",
                fencing_token=1,
                status=OperationStatus.DOCKER_CALL_COMPLETED,
                exit_code=0,
                broker_completed=True,
            ),
            dispatch_error=None,
            timeout_seconds=30,
            incident_id=base_entities["incident"].id,
            workspace_id=base_entities["workspace"].id,
        )

    # Verification: Watchdog hold remains authoritative, worker update was discarded
    db_session.refresh(exec_rec)
    assert exec_rec.status == ExecutionState.EXECUTION_UNCERTAIN.value
    assert exec_rec.fencing_token == 2


# ============================================================================
# 3. Crash & Concurrency Coverage (All 12 Boundary Scenarios)
# ============================================================================

def test_boundary_1_crash_during_preflight_validation(
    db_session, base_entities, isolated_coordinator
):
    """
    Scenario 1: Worker crashes during validation before DB transition.
    Execution is QUEUED with expired lease. Watchdog clears lease safely.
    """
    exec_rec = create_execution_record(
        db_session,
        base_entities,
        status="queued",
        locked_by="crashed-worker-1",
        locked_until=datetime.now(timezone.utc) - timedelta(seconds=5),
        fencing_token=1,
    )

    watchdog = ExecutionWatchdog(
        watchdog_id="watchdog-b1",
        coordinator=isolated_coordinator,
        db_factory=lambda: db_session,
    )

    res = watchdog.reconcile_execution(exec_rec.id)
    assert res is not None
    assert res["action"] == "cleared_expired_queue_lease"
    assert res["resulting_state"] == ExecutionState.QUEUED.value

    db_session.refresh(exec_rec)
    assert exec_rec.locked_by is None
    assert exec_rec.fencing_token == 2


def test_boundary_2_crash_after_validation_before_sqlite_reservation(
    db_session, base_entities, isolated_coordinator
):
    """
    Scenario 2: Worker crashes after advancing DB to EXECUTING, before SQLite reservation.
    Watchdog finds no coordinator record; fails closed to HOLD:EXECUTION_UNCERTAIN.
    """
    exec_rec = create_execution_record(
        db_session,
        base_entities,
        status="executing",
        locked_by="crashed-worker-2",
        locked_until=datetime.now(timezone.utc) - timedelta(seconds=5),
        fencing_token=1,
    )

    watchdog = ExecutionWatchdog(
        watchdog_id="watchdog-b2",
        coordinator=isolated_coordinator,
        db_factory=lambda: db_session,
    )

    res = watchdog.reconcile_execution(exec_rec.id)
    assert res is not None
    assert res["resulting_state"] == ExecutionState.EXECUTION_UNCERTAIN.value

    db_session.refresh(exec_rec)
    assert exec_rec.locked_by == "HOLD:EXECUTION_UNCERTAIN"


def test_boundary_3_crash_after_sqlite_reservation_before_journal_prepared(
    db_session, base_entities, isolated_coordinator
):
    """
    Scenario 3: SQLite has RESERVED, journal is empty.
    Watchdog evaluates pre-dispatch state: UNRESOLVED_RESERVED.
    Zero-redispatch rule: preserves reservation, establishes uncertainty hold.
    """
    coord = isolated_coordinator
    exec_rec = create_execution_record(
        db_session,
        base_entities,
        status="executing",
        locked_by="crashed-worker-3",
        locked_until=datetime.now(timezone.utc) - timedelta(seconds=5),
        fencing_token=1,
    )

    # SQLite reservation created, but worker died before journal write
    op = coord.reserve_operation(
        execution_id=exec_rec.id,
        workspace_id=exec_rec.workspace_id,
        approval_id=exec_rec.approval_id,
        attempt_number=1,
        fencing_token=1,
    )

    eval_res = coord.evaluate_pre_dispatch_state(op.operation_id)
    assert eval_res.state == PreDispatchState.UNRESOLVED_RESERVED

    watchdog = ExecutionWatchdog(
        watchdog_id="watchdog-b3",
        coordinator=coord,
        db_factory=lambda: db_session,
    )

    res = watchdog.reconcile_execution(exec_rec.id)
    assert res["resulting_state"] == ExecutionState.EXECUTION_UNCERTAIN.value

    # Reservation preserved in registry
    preserved_op = coord.registry.get_operation(op.operation_id)
    assert preserved_op is not None
    assert preserved_op.operation_status == OperationStatus.RESERVED


def test_boundary_4_crash_after_journal_prepared_before_start_marker(
    db_session, base_entities, isolated_coordinator
):
    """
    Scenario 4: Journal and SQLite have DISPATCH_PREPARED, no start marker.
    Watchdog evaluates pre-dispatch state without physical proof -> UNCERTAINTY_HOLD.
    Never infers Docker was not contacted without complete proof.
    """
    coord = isolated_coordinator
    exec_rec = create_execution_record(
        db_session,
        base_entities,
        status="executing",
        locked_by="crashed-worker-4",
        locked_until=datetime.now(timezone.utc) - timedelta(seconds=5),
        fencing_token=1,
    )

    op = coord.reserve_operation(
        execution_id=exec_rec.id,
        workspace_id=exec_rec.workspace_id,
        approval_id=exec_rec.approval_id,
        attempt_number=1,
        fencing_token=1,
    )
    coord.prepare_dispatch(
        operation_id=op.operation_id,
        execution_id=exec_rec.id,
        fencing_token=1,
        workspace_id=exec_rec.workspace_id,
    )

    # Absence of start marker does not prove non-invocation (Revision 10 boundary)
    eval_res = coord.evaluate_pre_dispatch_state(op.operation_id)
    assert eval_res.state == PreDispatchState.UNRESOLVED_PREPARED
    assert not eval_res.is_safe_abort

    watchdog = ExecutionWatchdog(
        watchdog_id="watchdog-b4",
        coordinator=coord,
        db_factory=lambda: db_session,
    )

    res = watchdog.reconcile_execution(exec_rec.id)
    assert res["resulting_state"] == ExecutionState.EXECUTION_UNCERTAIN.value


def test_boundary_5_crash_after_docker_call_started_before_broker_ipc(
    db_session, base_entities, isolated_coordinator
):
    """
    Scenario 5: Journal has DOCKER_CALL_STARTED.
    Watchdog recognizes start marker; establishes HOLD:EXECUTION_UNCERTAIN.
    Zero-redispatch invariant strictly enforced.
    """
    coord = isolated_coordinator
    exec_rec = create_execution_record(
        db_session,
        base_entities,
        status="executing",
        locked_by="crashed-worker-5",
        locked_until=datetime.now(timezone.utc) - timedelta(seconds=5),
        fencing_token=1,
    )

    op = coord.reserve_operation(
        execution_id=exec_rec.id,
        workspace_id=exec_rec.workspace_id,
        approval_id=exec_rec.approval_id,
        attempt_number=1,
        fencing_token=1,
    )
    coord.prepare_dispatch(
        operation_id=op.operation_id,
        execution_id=exec_rec.id,
        fencing_token=1,
        workspace_id=exec_rec.workspace_id,
    )
    coord.record_docker_call_started(
        operation_id=op.operation_id,
        execution_id=exec_rec.id,
        fencing_token=1,
        workspace_id=exec_rec.workspace_id,
    )

    watchdog = ExecutionWatchdog(
        watchdog_id="watchdog-b5",
        coordinator=coord,
        db_factory=lambda: db_session,
    )

    res = watchdog.reconcile_execution(exec_rec.id)
    assert res["resulting_state"] == ExecutionState.EXECUTION_UNCERTAIN.value

    db_session.refresh(exec_rec)
    assert exec_rec.locked_by == "HOLD:EXECUTION_UNCERTAIN"


def test_boundary_6_7_crash_after_broker_completion_before_db_finalization(
    db_session, base_entities, isolated_coordinator
):
    """
    Scenario 6 & 7: Container completed with exit code 0; coordinator has DOCKER_CALL_COMPLETED.
    Worker crashed before DB update. Watchdog recognizes completion from coordinator,
    advances DB to EXECUTION_SUCCEEDED -> VERIFICATION_PENDING, and resumes verification.
    """
    coord = isolated_coordinator
    exec_rec = create_execution_record(
        db_session,
        base_entities,
        status="executing",
        locked_by="crashed-worker-6",
        locked_until=datetime.now(timezone.utc) - timedelta(seconds=5),
        fencing_token=1,
    )

    op = coord.reserve_operation(
        execution_id=exec_rec.id,
        workspace_id=exec_rec.workspace_id,
        approval_id=exec_rec.approval_id,
        attempt_number=1,
        fencing_token=1,
    )
    coord.prepare_dispatch(
        operation_id=op.operation_id,
        execution_id=exec_rec.id,
        fencing_token=1,
        workspace_id=exec_rec.workspace_id,
    )
    coord.record_docker_call_started(
        operation_id=op.operation_id,
        execution_id=exec_rec.id,
        fencing_token=1,
        workspace_id=exec_rec.workspace_id,
    )
    coord.complete_dispatch(
        operation_id=op.operation_id,
        exit_code=0,
        duration_ms=50,
        output_data={"status": "remediated"},
    )

    probe_runner = ControlledProbeRunner(should_fail_probes=False)
    verification_engine = PostExecutionVerificationEngine(runner=probe_runner)

    watchdog = ExecutionWatchdog(
        watchdog_id="watchdog-b6",
        coordinator=coord,
        resume_verification=True,
        verification_engine=verification_engine,
        runner=probe_runner,
        db_factory=lambda: db_session,
    )

    res = watchdog.reconcile_execution(exec_rec.id)
    assert res is not None
    # Reconciles completed broker call, advances to verification, passes verification, recovers incident
    assert res["resulting_state"] == ExecutionState.VERIFIED.value

    db_session.refresh(exec_rec)
    assert exec_rec.status == ExecutionState.VERIFIED.value

    incident = db_session.query(Incident).filter(Incident.id == base_entities["incident"].id).first()
    assert incident.status == "recovered"


def test_watchdog_reconciliation_of_completed_call_zero_redispatch_and_no_premature_recovery(
    db_session, base_entities, isolated_coordinator
):
    """
    Focused Safety Regression Test (E.3.4 Safety Clarification):
    1. An operation with durable DOCKER_CALL_COMPLETED and exit code 0 must NEVER trigger
       another BrokerDispatcher or Docker request.
    2. Watchdog reconciles existing completion result into PostgreSQL (EXECUTION_SUCCEEDED -> VERIFICATION_PENDING).
    3. Watchdog resumes the existing read-only verification workflow.
    4. Original operation identity is preserved; no new reservation or DOCKER_CALL_STARTED is created.
    5. Incident is NEVER recovered before verification passes (remains remediating until verification succeeds).
    """
    coord = isolated_coordinator
    broker_client = ControlledBrokerClient(exit_code=0)
    dispatcher = BrokerDispatcher(coordinator=coord, broker_client=broker_client)

    now_utc = datetime.now(timezone.utc)
    exec_rec = create_execution_record(
        db_session,
        base_entities,
        status="executing",
        locked_by="crashed-worker-completed",
        locked_until=now_utc - timedelta(seconds=10),
        fencing_token=1,
    )

    attempt = ExecutionAttempt(
        id=str(uuid.uuid4()),
        execution_id=exec_rec.id,
        attempt_number=1,
        status="running",
        worker_id="crashed-worker-completed",
        fencing_token=1,
        started_at=now_utc - timedelta(seconds=20),
    )
    db_session.add(attempt)
    db_session.commit()

    # Create durable DOCKER_CALL_COMPLETED record with exit code 0 in coordinator
    op = coord.reserve_operation(
        execution_id=exec_rec.id,
        workspace_id=exec_rec.workspace_id,
        approval_id=exec_rec.approval_id,
        attempt_number=1,
        fencing_token=1,
    )
    coord.prepare_dispatch(
        operation_id=op.operation_id,
        execution_id=exec_rec.id,
        fencing_token=1,
        workspace_id=exec_rec.workspace_id,
    )
    coord.record_docker_call_started(
        operation_id=op.operation_id,
        execution_id=exec_rec.id,
        fencing_token=1,
        workspace_id=exec_rec.workspace_id,
    )
    coord.complete_dispatch(
        operation_id=op.operation_id,
        exit_code=0,
        duration_ms=65,
        output_data={"status": "order_api_remediated"},
    )

    # Initial state assertions
    initial_records = coord.journal.replay()
    initial_record_count = len(initial_records)
    initial_start_markers = [r for r in initial_records if r.record_type == JournalRecordType.DOCKER_CALL_STARTED.value]
    assert len(initial_start_markers) == 1
    assert broker_client.call_count == 0

    # Ensure incident is active
    incident = db_session.query(Incident).filter(Incident.id == base_entities["incident"].id).first()
    assert incident.status == "remediating"
    assert incident.recovered_at is None

    # Track incident status during active verification probes to assert it is NOT recovered before verification passes
    incident_status_during_verification = []
    probe_runner = ControlledProbeRunner(should_fail_probes=False)
    original_execute = probe_runner.execute

    def tracking_probe_execute(*args, **kwargs):
        db_session.expire_all()
        inc = db_session.query(Incident).filter(Incident.id == base_entities["incident"].id).first()
        incident_status_during_verification.append(inc.status)
        return original_execute(*args, **kwargs)

    probe_runner.execute = tracking_probe_execute
    verification_engine = PostExecutionVerificationEngine(runner=probe_runner)

    watchdog = ExecutionWatchdog(
        watchdog_id="watchdog-safety-test",
        coordinator=coord,
        resume_verification=True,
        verification_engine=verification_engine,
        runner=probe_runner,
        db_factory=lambda: db_session,
    )

    # Run watchdog reconciliation
    res = watchdog.reconcile_execution(exec_rec.id)
    assert res is not None
    assert res["resulting_state"] == ExecutionState.VERIFIED.value

    # ASSERTION 1: BrokerDispatcher was NEVER invoked again (zero redispatch)
    assert broker_client.call_count == 0

    # ASSERTION 2: No new operation reservation or DOCKER_CALL_STARTED record was created
    final_records = coord.journal.replay()
    assert len(final_records) == initial_record_count
    final_start_markers = [r for r in final_records if r.record_type == JournalRecordType.DOCKER_CALL_STARTED.value]
    assert len(final_start_markers) == 1
    preserved_op = coord.registry.get_operation(op.operation_id)
    assert preserved_op is not None
    assert preserved_op.operation_id == op.operation_id
    assert preserved_op.operation_status == OperationStatus.DOCKER_CALL_COMPLETED

    # ASSERTION 3: Verification resumed with read-only probes
    assert len(incident_status_during_verification) > 0
    assert len(probe_runner.dispatched_actions) > 0
    assert all(a == "inspect_service_health" for a in probe_runner.dispatched_actions)

    # ASSERTION 4: Incident was NOT recovered before verification passes
    assert all(status == "remediating" for status in incident_status_during_verification)

    # ASSERTION 5: Incident is atomically recovered ONLY AFTER verification passes
    db_session.refresh(exec_rec)
    db_session.refresh(incident)
    assert exec_rec.status == ExecutionState.VERIFIED.value
    assert incident.status == "recovered"
    assert incident.recovered_at is not None


def test_watchdog_reconciliation_of_completed_call_failed_verification_never_recovers_incident(
    db_session, base_entities, isolated_coordinator
):
    """
    Focused Safety Test: If verification probes fail during watchdog resumption of a
    completed broker call, the incident remains active and is NEVER recovered.
    """
    coord = isolated_coordinator
    broker_client = ControlledBrokerClient(exit_code=0)
    dispatcher = BrokerDispatcher(coordinator=coord, broker_client=broker_client)

    now_utc = datetime.now(timezone.utc)
    exec_rec = create_execution_record(
        db_session,
        base_entities,
        status="executing",
        locked_by="crashed-worker-completed-2",
        locked_until=now_utc - timedelta(seconds=10),
        fencing_token=1,
    )

    op = coord.reserve_operation(
        execution_id=exec_rec.id,
        workspace_id=exec_rec.workspace_id,
        approval_id=exec_rec.approval_id,
        attempt_number=1,
        fencing_token=1,
    )
    coord.prepare_dispatch(
        operation_id=op.operation_id,
        execution_id=exec_rec.id,
        fencing_token=1,
        workspace_id=exec_rec.workspace_id,
    )
    coord.record_docker_call_started(
        operation_id=op.operation_id,
        execution_id=exec_rec.id,
        fencing_token=1,
        workspace_id=exec_rec.workspace_id,
    )
    coord.complete_dispatch(
        operation_id=op.operation_id,
        exit_code=0,
        duration_ms=50,
        output_data={"status": "remediated"},
    )

    initial_records = coord.journal.replay()
    initial_record_count = len(initial_records)

    # Verification probes FAIL
    probe_runner = ControlledProbeRunner(should_fail_probes=True)
    verification_engine = PostExecutionVerificationEngine(runner=probe_runner)

    watchdog = ExecutionWatchdog(
        watchdog_id="watchdog-safety-fail-test",
        coordinator=coord,
        resume_verification=True,
        verification_engine=verification_engine,
        runner=probe_runner,
        db_factory=lambda: db_session,
    )

    res = watchdog.reconcile_execution(exec_rec.id)
    assert res is not None
    assert res["resulting_state"] == ExecutionState.VERIFICATION_FAILED.value

    # BrokerDispatcher was NEVER called
    assert broker_client.call_count == 0

    # No new records in coordinator
    assert len(coord.journal.replay()) == initial_record_count

    # Incident MUST remain active and unrecovered
    incident = db_session.query(Incident).filter(Incident.id == base_entities["incident"].id).first()
    assert incident.status == "remediating"
    assert incident.recovered_at is None


def test_boundary_8_crash_before_verification_begins(
    db_session, base_entities, isolated_coordinator
):
    """
    Scenario 8: Worker crashed right after transitioning to VERIFICATION_PENDING.
    No verification cycle exists yet. Watchdog starts initial cycle #1 and verifies.
    """
    exec_rec = create_execution_record(
        db_session,
        base_entities,
        status="verification_pending",
        locked_by="crashed-worker-8",
        locked_until=datetime.now(timezone.utc) - timedelta(seconds=5),
        fencing_token=1,
    )

    probe_runner = ControlledProbeRunner(should_fail_probes=False)
    verification_engine = PostExecutionVerificationEngine(runner=probe_runner)

    watchdog = ExecutionWatchdog(
        watchdog_id="watchdog-b8",
        coordinator=isolated_coordinator,
        resume_verification=True,
        verification_engine=verification_engine,
        runner=probe_runner,
        db_factory=lambda: db_session,
    )

    res = watchdog.reconcile_execution(exec_rec.id)
    assert res["resulting_state"] == ExecutionState.VERIFIED.value

    db_session.refresh(exec_rec)
    assert exec_rec.status == ExecutionState.VERIFIED.value

    incident = db_session.query(Incident).filter(Incident.id == base_entities["incident"].id).first()
    assert incident.status == "recovered"


def test_boundary_9_crash_during_active_verification(
    db_session, base_entities, isolated_coordinator
):
    """
    Scenario 9: Cycle 1 was in progress when worker crashed.
    Watchdog resumes verification with cycle 2, passes, and recovers incident.
    """
    now_utc = datetime.now(timezone.utc)
    exec_rec = create_execution_record(
        db_session,
        base_entities,
        status="verification_pending",
        locked_by="crashed-worker-9",
        locked_until=now_utc - timedelta(seconds=5),
        fencing_token=1,
    )

    cycle1 = VerificationCycle(
        id=str(uuid.uuid4()),
        execution_id=exec_rec.id,
        workspace_id=exec_rec.workspace_id,
        cycle_number=1,
        status="running",
        deadline_at=now_utc + timedelta(seconds=45),
        probes_required=1,
        started_at=now_utc - timedelta(seconds=10),
    )
    db_session.add(cycle1)
    db_session.commit()

    probe_runner = ControlledProbeRunner(should_fail_probes=False)
    verification_engine = PostExecutionVerificationEngine(runner=probe_runner)

    watchdog = ExecutionWatchdog(
        watchdog_id="watchdog-b9",
        coordinator=isolated_coordinator,
        resume_verification=True,
        verification_engine=verification_engine,
        runner=probe_runner,
        db_factory=lambda: db_session,
    )

    res = watchdog.reconcile_execution(exec_rec.id)
    assert res["resulting_state"] == ExecutionState.VERIFIED.value

    db_session.refresh(exec_rec)
    assert exec_rec.status == ExecutionState.VERIFIED.value


def test_boundary_10_crash_after_verification_passes_before_incident_recovery(
    db_session, base_entities, isolated_coordinator
):
    """
    Scenario 10: Cycle passed before worker died, but incident recovery was interrupted.
    Watchdog detects passed cycle and atomically completes incident recovery.
    """
    now_utc = datetime.now(timezone.utc)
    exec_rec = create_execution_record(
        db_session,
        base_entities,
        status="verification_pending",
        locked_by="crashed-worker-10",
        locked_until=now_utc - timedelta(seconds=5),
        fencing_token=1,
    )

    cycle = VerificationCycle(
        id=str(uuid.uuid4()),
        execution_id=exec_rec.id,
        workspace_id=exec_rec.workspace_id,
        cycle_number=1,
        status="passed",
        deadline_at=now_utc + timedelta(seconds=45),
        probes_required=1,
        probes_passed=1,
        probes_failed=0,
        started_at=now_utc - timedelta(seconds=10),
        cycle_metadata={"outcome": "PASS"},
    )
    db_session.add(cycle)

    from app.execution.verification_persistence import generate_deterministic_probe_id
    probe1 = VerificationProbeResult(
        id=generate_deterministic_probe_id(exec_rec.id, 1, 1),
        cycle_id=cycle.id,
        execution_id=exec_rec.id,
        workspace_id=exec_rec.workspace_id,
        probe_number=1,
        probe_type="baseline",
        target_url="http://host.docker.internal:8001/health",
        status="passed",
        status_code=200,
        passed=True,
        executed_at=now_utc - timedelta(seconds=8),
        latency_ms=15.0,
        probe_output={"status": "healthy"},
    )
    probe2 = VerificationProbeResult(
        id=generate_deterministic_probe_id(exec_rec.id, 1, 2),
        cycle_id=cycle.id,
        execution_id=exec_rec.id,
        workspace_id=exec_rec.workspace_id,
        probe_number=2,
        probe_type="health_check",
        target_url="http://host.docker.internal:8001/health",
        status="passed",
        status_code=200,
        passed=True,
        executed_at=now_utc - timedelta(seconds=6),
        latency_ms=15.0,
        probe_output={"status": "healthy"},
    )
    db_session.add(probe1)
    db_session.add(probe2)
    db_session.commit()

    # Incident is still active
    incident = db_session.query(Incident).filter(Incident.id == base_entities["incident"].id).first()
    assert incident.status == "remediating"

    watchdog = ExecutionWatchdog(
        watchdog_id="watchdog-b10",
        coordinator=isolated_coordinator,
        db_factory=lambda: db_session,
    )

    res = watchdog.reconcile_execution(exec_rec.id)
    assert res["action"] == "atomic_incident_recovery_from_passed_cycle"
    assert res["resulting_state"] == ExecutionState.VERIFIED.value

    db_session.refresh(incident)
    assert incident.status == "recovered"


def test_boundary_11_broker_ipc_timeout_in_coordinator(
    db_session, base_entities, isolated_coordinator
):
    """
    Scenario 11: Mid-flight IPC timeout leaves operation in DISPATCH_UNCERTAIN.
    Watchdog preserves uncertain hold and enforces non-redispatch invariant.
    """
    coord = isolated_coordinator
    exec_rec = create_execution_record(
        db_session,
        base_entities,
        status="executing",
        locked_by="crashed-worker-11",
        locked_until=datetime.now(timezone.utc) - timedelta(seconds=5),
        fencing_token=1,
    )

    op = coord.reserve_operation(
        execution_id=exec_rec.id,
        workspace_id=exec_rec.workspace_id,
        approval_id=exec_rec.approval_id,
        attempt_number=1,
        fencing_token=1,
    )
    coord.prepare_dispatch(
        operation_id=op.operation_id,
        execution_id=exec_rec.id,
        fencing_token=1,
        workspace_id=exec_rec.workspace_id,
    )
    coord.record_docker_call_started(
        operation_id=op.operation_id,
        execution_id=exec_rec.id,
        fencing_token=1,
        workspace_id=exec_rec.workspace_id,
    )
    coord.record_dispatch_uncertain(
        operation_id=op.operation_id,
        reason="Unix socket broken pipe mid-stream",
    )

    watchdog = ExecutionWatchdog(
        watchdog_id="watchdog-b11",
        coordinator=coord,
        db_factory=lambda: db_session,
    )

    res = watchdog.reconcile_execution(exec_rec.id)
    assert res["resulting_state"] == ExecutionState.EXECUTION_UNCERTAIN.value

    db_session.refresh(exec_rec)
    assert exec_rec.locked_by == "HOLD:EXECUTION_UNCERTAIN"


def test_boundary_12_fencing_token_mismatch_at_coordinator_layer(
    db_session, base_entities, isolated_coordinator
):
    """
    Scenario 12: Fencing token mismatch at coordinator layer raises CoordinatorConflictError
    and prevents any broker contact.
    """
    coord = isolated_coordinator
    broker_client = ControlledBrokerClient(exit_code=0)
    dispatcher = BrokerDispatcher(coordinator=coord, broker_client=broker_client)

    op = coord.reserve_operation(
        execution_id="exec-12",
        workspace_id=base_entities["workspace"].id,
        approval_id=base_entities["approval"].id,
        attempt_number=1,
        fencing_token=1,
    )

    with pytest.raises(CoordinatorConflictError):
        dispatcher.dispatch_action(
            execution_id="exec-12",
            workspace_id=base_entities["workspace"].id,
            approval_id=base_entities["approval"].id,
            attempt_number=1,
            fencing_token=99,  # Mismatch against reservation token 1
            action_id="restore_order_api_demo",
            target_url="http://host.docker.internal:8001/health",
            operation_id=op.operation_id,
        )

    assert broker_client.call_count == 0


# ============================================================================
# 4. Strict Read-Only Verification & Idempotency
# ============================================================================

def test_verification_resumption_strictly_executes_read_only_probes(
    db_session, base_entities, isolated_coordinator
):
    """
    Watchdog verification recovery performs ONLY read-only diagnostic probes.
    Mutating remediation actions are strictly forbidden from redispatch.
    """
    exec_rec = create_execution_record(
        db_session,
        base_entities,
        status="verification_pending",
        locked_by="crashed-worker",
        locked_until=datetime.now(timezone.utc) - timedelta(seconds=5),
        fencing_token=1,
    )

    probe_runner = ControlledProbeRunner(should_fail_probes=False)
    verification_engine = PostExecutionVerificationEngine(runner=probe_runner)

    watchdog = ExecutionWatchdog(
        watchdog_id="watchdog-read-only-test",
        coordinator=isolated_coordinator,
        resume_verification=True,
        verification_engine=verification_engine,
        runner=probe_runner,
        db_factory=lambda: db_session,
    )

    watchdog.reconcile_execution(exec_rec.id)

    # Confirm only read-only inspect action was executed
    assert len(probe_runner.dispatched_actions) > 0
    for action in probe_runner.dispatched_actions:
        assert action == "inspect_service_health"
        assert action != "restore_order_api_demo"


def test_idempotent_repeated_watchdog_reconciliation(
    db_session, base_entities, isolated_coordinator
):
    """
    Repeated watchdog reconciliations on the same state produce identical safe results
    without side effects, state regression, or unwanted mutations.
    """
    exec_rec = create_execution_record(
        db_session,
        base_entities,
        status="executing",
        locked_by="crashed-worker",
        locked_until=datetime.now(timezone.utc) - timedelta(seconds=5),
        fencing_token=1,
    )

    watchdog = ExecutionWatchdog(
        watchdog_id="watchdog-idempotent",
        coordinator=isolated_coordinator,
        db_factory=lambda: db_session,
    )

    # First reconciliation establishes uncertainty hold
    res1 = watchdog.reconcile_execution(exec_rec.id)
    assert res1 is not None
    assert res1["resulting_state"] == ExecutionState.EXECUTION_UNCERTAIN.value

    db_session.refresh(exec_rec)
    fencing_token_after_first = exec_rec.fencing_token
    status_after_first = exec_rec.status
    locked_by_after_first = exec_rec.locked_by

    # Second reconciliation on terminal/hold state
    res2 = watchdog.reconcile_execution(exec_rec.id)
    assert res2 is None  # Already terminal/held, no further state transition

    db_session.refresh(exec_rec)
    assert exec_rec.fencing_token == fencing_token_after_first
    assert exec_rec.status == status_after_first
    assert exec_rec.locked_by == locked_by_after_first
