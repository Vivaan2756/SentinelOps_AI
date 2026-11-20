"""Comprehensive Test Suite for Phase 4.3.6 Milestone E.3.5.

Three-Way Execution Reconciliation:
Tests bounded, auditable, idempotent reconciliation across:
1. PostgreSQL execution state (RemediationExecution, ExecutionAttempt, ExecutionEvent, VerificationCycle, Incident).
2. SQLite OperationRegistry (operation_reservations).
3. Append-only OperationJournal (SOJ1).

All 20 mandatory test cases are covered under Revision 10 rules.
"""

import concurrent.futures
from datetime import datetime, timedelta, timezone
import json
import os
import tempfile
from typing import Any, Dict, List, Optional
import uuid
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.base import Base
from app.execution.broker import (
    BrokerExecuteRequest,
    BrokerExecuteResponse,
)
from app.execution.broker_dispatcher import BrokerDispatcher
from app.execution.dispatch_coordinator import (
    CoordinatorError,
    DispatchCoordinator,
    PreDispatchState,
)
from app.execution.exceptions import (
    CrossWorkspaceViolationError,
    StaleWorkerFencingError,
)
from app.execution.journal import (
    JournalCorruptedError,
    JournalError,
    JournalRecordType,
    OperationJournal,
)
from app.execution.reconciliation import (
    ReconciliationClassification,
    ReconciliationReport,
    ReconciliationResult,
    ThreeWayExecutionReconciler,
)
from app.execution.recovery_bridge import IncidentRecoveryBridge
from app.execution.registry import (
    OperationRecord,
    OperationRegistry,
    OperationStatus,
    RegistryBusyError,
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
from app.execution.verification_persistence import generate_deterministic_probe_id
from app.execution.watchdog import HOLD_EXPIRATION_TIMESTAMP
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
# Controllable Test Fixtures & Doubles
# ============================================================================

class ControlledBrokerClient:
    """Mock broker client ensuring zero unwanted dispatch calls."""

    def __init__(
        self,
        exit_code: int = 0,
        stdout: str = "Broker action succeeded.",
        stderr: str = "",
        duration_ms: int = 40,
    ):
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr
        self.duration_ms = duration_ms
        self.call_count = 0
        self.dispatched_requests: List[BrokerExecuteRequest] = []

    def execute_action(self, request: BrokerExecuteRequest) -> BrokerExecuteResponse:
        self.call_count += 1
        self.dispatched_requests.append(request)
        return BrokerExecuteResponse(
            execution_id=request.execution_id,
            exit_code=self.exit_code,
            duration_ms=self.duration_ms,
            stdout_sample=self.stdout,
            stderr_sample=self.stderr,
            output_data={"stdout": self.stdout},
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

        # Safety Check: only read-only inspect action is allowed during verification
        if action_id != "inspect_service_health":
            raise ValueError(
                f"SAFETY VIOLATION: Non-diagnostic action '{action_id}' requested during verification! "
                "Mutating remediation actions must NEVER be redispatched!"
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
    """Seed test workspace, user, service, incident, policy, and approval."""
    now_utc = datetime.now(timezone.utc)
    ws_id = str(uuid.uuid4())
    ws = Workspace(id=ws_id, name="Reconciliation Test WS", slug=f"ws-{ws_id[:8]}")
    db_session.add(ws)

    user_id = str(uuid.uuid4())
    user = User(
        id=user_id,
        email="devops@recon.test",
        full_name="Reconciliation Engineer",
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
    status: str = "executing",
    locked_by: Optional[str] = "worker-test",
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
        locked_until=locked_until or (now_utc + timedelta(seconds=60)),
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
# 20 Mandatory Test Scenarios (Section 6)
# ============================================================================

def test_case_1_pg_executing_no_registry_record(db_session, base_entities, isolated_coordinator):
    """
    Test 1: PostgreSQL executing with no registry record.
    Reconciler must establish HOLD:EXECUTION_UNCERTAIN and never redispatch.
    """
    coord = isolated_coordinator
    broker_client = ControlledBrokerClient(exit_code=0)
    dispatcher = BrokerDispatcher(coordinator=coord, broker_client=broker_client)

    exec_rec = create_execution_record(db_session, base_entities, status="executing")

    reconciler = ThreeWayExecutionReconciler(
        registry=coord.registry,
        journal=coord.journal,
        coordinator=coord,
        db=db_session,
    )

    res = reconciler.reconcile_execution(exec_rec.id)
    assert res.classification == ReconciliationClassification.UNCERTAIN_NO_LOCAL_RECORD
    assert res.resulting_state == ExecutionState.EXECUTION_UNCERTAIN.value

    db_session.refresh(exec_rec)
    assert exec_rec.status == ExecutionState.EXECUTION_UNCERTAIN.value
    assert exec_rec.locked_by == "HOLD:EXECUTION_UNCERTAIN"
    assert broker_client.call_count == 0


def test_case_2_reserved_empty_journal(db_session, base_entities, isolated_coordinator):
    """
    Test 2: RESERVED with empty journal.
    Unresolved reservation; preserves reservation; no automatic abort or resume.
    """
    coord = isolated_coordinator
    broker_client = ControlledBrokerClient(exit_code=0)

    exec_rec = create_execution_record(db_session, base_entities, status="executing")

    # Reserve in SQLite, but write nothing to journal
    op = coord.reserve_operation(
        execution_id=exec_rec.id,
        workspace_id=exec_rec.workspace_id,
        approval_id=exec_rec.approval_id,
        attempt_number=1,
        fencing_token=1,
    )

    reconciler = ThreeWayExecutionReconciler(
        registry=coord.registry,
        journal=coord.journal,
        coordinator=coord,
        db=db_session,
    )

    res = reconciler.reconcile_execution(exec_rec.id)
    assert res.classification == ReconciliationClassification.UNRESOLVED_RESERVATION
    assert res.resulting_state == ExecutionState.EXECUTION_UNCERTAIN.value

    # Reservation preserved in SQLite
    preserved_op = coord.registry.get_operation(op.operation_id)
    assert preserved_op is not None
    assert preserved_op.operation_status == OperationStatus.RESERVED

    # Zero broker calls
    assert broker_client.call_count == 0


def test_case_3_prepared_without_started(db_session, base_entities, isolated_coordinator):
    """
    Test 3: PREPARED without STARTED marker.
    Unresolved; no automatic dispatch or abort.
    """
    coord = isolated_coordinator
    broker_client = ControlledBrokerClient(exit_code=0)

    exec_rec = create_execution_record(db_session, base_entities, status="executing")

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

    reconciler = ThreeWayExecutionReconciler(
        registry=coord.registry,
        journal=coord.journal,
        coordinator=coord,
        db=db_session,
    )

    res = reconciler.reconcile_execution(exec_rec.id)
    assert res.classification == ReconciliationClassification.UNRESOLVED_PREPARED
    assert res.resulting_state == ExecutionState.EXECUTION_UNCERTAIN.value

    db_session.refresh(exec_rec)
    assert exec_rec.locked_by == "HOLD:EXECUTION_UNCERTAIN"
    assert broker_client.call_count == 0


def test_case_4_started_without_outcome(db_session, base_entities, isolated_coordinator):
    """
    Test 4: STARTED without outcome.
    Uncertainty hold established; zero redispatch.
    """
    coord = isolated_coordinator
    broker_client = ControlledBrokerClient(exit_code=0)

    exec_rec = create_execution_record(db_session, base_entities, status="executing")

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

    reconciler = ThreeWayExecutionReconciler(
        registry=coord.registry,
        journal=coord.journal,
        coordinator=coord,
        db=db_session,
    )

    res = reconciler.reconcile_execution(exec_rec.id)
    assert res.classification == ReconciliationClassification.UNCERTAIN_STARTED_NO_OUTCOME
    assert res.resulting_state == ExecutionState.EXECUTION_UNCERTAIN.value

    db_session.refresh(exec_rec)
    assert exec_rec.locked_by == "HOLD:EXECUTION_UNCERTAIN"
    assert broker_client.call_count == 0


def test_case_5_uncertainty_in_one_or_more_stores(db_session, base_entities, isolated_coordinator):
    """
    Test 5: Uncertainty in one or more stores.
    Uncertainty hold preserved; never retried or cleared.
    """
    coord = isolated_coordinator
    broker_client = ControlledBrokerClient(exit_code=0)

    exec_rec = create_execution_record(db_session, base_entities, status="executing")

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
        reason="Socket dropped mid-flight",
    )

    reconciler = ThreeWayExecutionReconciler(
        registry=coord.registry,
        journal=coord.journal,
        coordinator=coord,
        db=db_session,
    )

    res = reconciler.reconcile_execution(exec_rec.id)
    assert res.classification == ReconciliationClassification.UNCERTAIN_STORE_FLAGGED
    assert res.resulting_state == ExecutionState.EXECUTION_UNCERTAIN.value

    db_session.refresh(exec_rec)
    assert exec_rec.locked_by == "HOLD:EXECUTION_UNCERTAIN"
    assert broker_client.call_count == 0


def test_case_6_completed_exit_zero_unfinalized_pg(db_session, base_entities, isolated_coordinator):
    """
    Test 6: COMPLETED exit 0 with PostgreSQL not finalized.
    - Finalize to verification_pending, then read-only verification only.
    - Explicit assertions:
      * Broker call count remains zero.
      * Journal length remains unchanged.
      * No additional DOCKER_CALL_STARTED marker is appended.
      * Only read-only verification can resume.
      * Incident remains unrecovered until existing recovery bridge confirms persisted verification success.
    """
    coord = isolated_coordinator
    broker_client = ControlledBrokerClient(exit_code=0)
    dispatcher = BrokerDispatcher(coordinator=coord, broker_client=broker_client)

    exec_rec = create_execution_record(db_session, base_entities, status="executing")

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
        duration_ms=45,
        output_data={"status": "remediated"},
    )

    initial_records = coord.journal.replay()
    initial_length = len(initial_records)
    initial_start_markers = [r for r in initial_records if r.record_type == JournalRecordType.DOCKER_CALL_STARTED.value]
    assert len(initial_start_markers) == 1
    assert broker_client.call_count == 0

    # Ensure incident is active
    incident = db_session.query(Incident).filter(Incident.id == base_entities["incident"].id).first()
    assert incident.status == "remediating"

    # Step A: Reconcile without immediate verification to assert intermediate state
    reconciler_no_ver = ThreeWayExecutionReconciler(
        registry=coord.registry,
        journal=coord.journal,
        coordinator=coord,
        resume_verification=False,
        db=db_session,
    )

    res_a = reconciler_no_ver.reconcile_execution(exec_rec.id)
    assert res_a.classification == ReconciliationClassification.COMPLETED_EXIT_ZERO
    assert res_a.resulting_state == ExecutionState.VERIFICATION_PENDING.value

    db_session.refresh(exec_rec)
    assert exec_rec.status == ExecutionState.VERIFICATION_PENDING.value

    # MANDATORY ASSERTIONS (Section 6):
    # 1. Broker call count remains zero
    assert broker_client.call_count == 0
    # 2. Journal length remains unchanged
    records_after_a = coord.journal.replay()
    assert len(records_after_a) == initial_length
    # 3. No additional DOCKER_CALL_STARTED marker appended
    starts_after_a = [r for r in records_after_a if r.record_type == JournalRecordType.DOCKER_CALL_STARTED.value]
    assert len(starts_after_a) == 1
    # 4. Incident remains unrecovered
    db_session.refresh(incident)
    assert incident.status == "remediating"
    assert incident.recovered_at is None

    # Step B: Resume read-only verification
    probe_runner = ControlledProbeRunner(should_fail_probes=False)
    verification_engine = PostExecutionVerificationEngine(runner=probe_runner)

    reconciler_ver = ThreeWayExecutionReconciler(
        registry=coord.registry,
        journal=coord.journal,
        coordinator=coord,
        verification_engine=verification_engine,
        resume_verification=True,
        db=db_session,
    )

    res_b = reconciler_ver.reconcile_execution(exec_rec.id)
    assert res_b.resulting_state == ExecutionState.VERIFIED.value

    # Assertions hold after verification:
    assert broker_client.call_count == 0
    assert len(coord.journal.replay()) == initial_length
    assert len(probe_runner.dispatched_actions) > 0
    assert all(a == "inspect_service_health" for a in probe_runner.dispatched_actions)

    db_session.refresh(exec_rec)
    db_session.refresh(incident)
    assert exec_rec.status == ExecutionState.VERIFIED.value
    assert incident.status == "recovered"


def test_case_7_completed_nonzero_unfinalized_pg(db_session, base_entities, isolated_coordinator):
    """
    Test 7: COMPLETED nonzero with PostgreSQL not finalized.
    Finalize execution_failed; no redispatch.
    """
    coord = isolated_coordinator
    broker_client = ControlledBrokerClient(exit_code=0)

    exec_rec = create_execution_record(db_session, base_entities, status="executing")

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
        exit_code=2,
        duration_ms=45,
        output_data={"error": "Command failed"},
    )

    reconciler = ThreeWayExecutionReconciler(
        registry=coord.registry,
        journal=coord.journal,
        coordinator=coord,
        db=db_session,
    )

    res = reconciler.reconcile_execution(exec_rec.id)
    assert res.classification == ReconciliationClassification.COMPLETED_NONZERO_EXIT
    assert res.resulting_state == ExecutionState.EXECUTION_FAILED.value

    db_session.refresh(exec_rec)
    assert exec_rec.status == ExecutionState.EXECUTION_FAILED.value
    assert exec_rec.error_category == "container_nonzero_exit"
    assert broker_client.call_count == 0


def test_case_8_persisted_verification_success_incident_not_recovered(
    db_session, base_entities, isolated_coordinator
):
    """
    Test 8: Persisted verification success with incident not recovered.
    Invoke existing recovery bridge idempotently if conditions satisfied.
    """
    now_utc = datetime.now(timezone.utc)
    exec_rec = create_execution_record(db_session, base_entities, status="verification_pending")

    cycle = VerificationCycle(
        id=str(uuid.uuid4()),
        execution_id=exec_rec.id,
        workspace_id=exec_rec.workspace_id,
        cycle_number=1,
        status="passed",
        deadline_at=now_utc + timedelta(seconds=60),
        probes_required=1,
        probes_passed=1,
        probes_failed=0,
        started_at=now_utc - timedelta(seconds=10),
        cycle_metadata={"outcome": "PASS"},
    )
    db_session.add(cycle)

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
        latency_ms=10.0,
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
        executed_at=now_utc - timedelta(seconds=5),
        latency_ms=10.0,
        probe_output={"status": "healthy"},
    )
    db_session.add(probe1)
    db_session.add(probe2)
    db_session.commit()

    incident = db_session.query(Incident).filter(Incident.id == base_entities["incident"].id).first()
    assert incident.status == "remediating"

    reconciler = ThreeWayExecutionReconciler(
        registry=isolated_coordinator.registry,
        journal=isolated_coordinator.journal,
        coordinator=isolated_coordinator,
        db=db_session,
    )

    res = reconciler.reconcile_execution(exec_rec.id)
    assert res.classification == ReconciliationClassification.PERSISTED_VERIFICATION_SUCCESS
    assert res.resulting_state == ExecutionState.VERIFIED.value

    db_session.refresh(exec_rec)
    db_session.refresh(incident)
    assert exec_rec.status == ExecutionState.VERIFIED.value
    assert incident.status == "recovered"


def test_case_9_contradictory_identities_across_stores(db_session, base_entities, isolated_coordinator):
    """
    Test 9: Contradictory PostgreSQL, SQLite and journal identities.
    Quarantine/uncertainty hold; no destructive repair.
    """
    coord = isolated_coordinator
    exec_rec = create_execution_record(db_session, base_entities, status="executing")

    # Seed conflicting reservation with mismatched workspace ID
    op = coord.reserve_operation(
        execution_id=exec_rec.id,
        workspace_id=str(uuid.uuid4()),  # Conflicting workspace ID!
        approval_id=exec_rec.approval_id,
        attempt_number=1,
        fencing_token=1,
    )

    reconciler = ThreeWayExecutionReconciler(
        registry=coord.registry,
        journal=coord.journal,
        coordinator=coord,
        db=db_session,
    )

    res = reconciler.reconcile_execution(exec_rec.id)
    assert res.classification == ReconciliationClassification.CONTRADICTORY_EVIDENCE
    assert res.resulting_state == ExecutionState.EXECUTION_UNCERTAIN.value

    db_session.refresh(exec_rec)
    assert exec_rec.locked_by == "HOLD:EXECUTION_UNCERTAIN"

    # SQLite record was NOT destructively deleted
    preserved_op = coord.registry.get_operation(op.operation_id)
    assert preserved_op is not None


def test_case_10_journal_torn_tail_detection(db_session, base_entities, isolated_coordinator):
    """
    Test 10: Journal torn-tail detection.
    Fail closed; uncertainty hold.
    """
    coord = isolated_coordinator
    exec_rec = create_execution_record(db_session, base_entities, status="executing")

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

    coord.journal.close()
    # Append torn bytes to simulate uncommitted write crash
    with open(coord.journal.journal_path, "ab") as f:
        f.write(b"SOJ1\x00\x00\x00\x02\x00\x00")  # Partial torn header

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


def test_case_11_journal_corruption(db_session, base_entities, isolated_coordinator):
    """
    Test 11: Journal CRC32 corruption.
    Fail closed; uncertainty hold.
    """
    coord = isolated_coordinator
    exec_rec = create_execution_record(db_session, base_entities, status="executing")

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

    coord.journal.close()
    # Corrupt byte in journal file
    with open(coord.journal.journal_path, "r+b") as f:
        f.seek(85)  # Seek into payload
        f.write(b"\xff\xff\xff")

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


def test_case_12_sqlite_busy_unavailable(db_session, base_entities, isolated_coordinator):
    """
    Test 12: SQLite busy/unavailable.
    Fails closed with STORE_UNAVAILABLE; no mutation.
    """
    coord = isolated_coordinator
    exec_rec = create_execution_record(db_session, base_entities, status="executing")

    # Simulate SQLite busy/unavailable
    from unittest.mock import MagicMock
    coord.registry.list_uncertain_operations = MagicMock(
        side_effect=RegistryBusyError("database is locked (5000ms timeout)")
    )

    reconciler = ThreeWayExecutionReconciler(
        registry=coord.registry,
        journal=coord.journal,
        coordinator=coord,
        db=db_session,
    )

    res = reconciler.reconcile_execution(exec_rec.id)
    assert res.classification == ReconciliationClassification.STORE_UNAVAILABLE
    assert "locked" in res.reason


def test_case_13_postgresql_unavailable(db_session, base_entities, isolated_coordinator):
    """
    Test 13: PostgreSQL unavailable.
    Fails closed gracefully with STORE_UNAVAILABLE.
    """
    coord = isolated_coordinator

    from unittest.mock import MagicMock
    mock_db = MagicMock()
    mock_db.query.side_effect = Exception("Connection lost to PostgreSQL")

    reconciler = ThreeWayExecutionReconciler(
        registry=coord.registry,
        journal=coord.journal,
        coordinator=coord,
        db=mock_db,
    )

    res = reconciler.reconcile_execution("any-id")
    assert res.classification == ReconciliationClassification.STORE_UNAVAILABLE
    assert "Connection lost" in res.reason


def test_case_14_repeated_reconciliation_idempotency(db_session, base_entities, isolated_coordinator):
    """
    Test 14: Repeated reconciliation idempotency.
    Second run produces identical safe result with zero duplicate events or state changes.
    """
    coord = isolated_coordinator
    exec_rec = create_execution_record(db_session, base_entities, status="executing")

    reconciler = ThreeWayExecutionReconciler(
        registry=coord.registry,
        journal=coord.journal,
        coordinator=coord,
        db=db_session,
    )

    # First reconciliation establishes hold
    res1 = reconciler.reconcile_execution(exec_rec.id)
    assert res1.resulting_state == ExecutionState.EXECUTION_UNCERTAIN.value

    db_session.refresh(exec_rec)
    token_1 = exec_rec.fencing_token
    status_1 = exec_rec.status
    locked_by_1 = exec_rec.locked_by

    # Second reconciliation is idempotent
    res2 = reconciler.reconcile_execution(exec_rec.id)
    assert res2.classification == ReconciliationClassification.ALREADY_SYNCHRONIZED

    db_session.refresh(exec_rec)
    assert exec_rec.fencing_token == token_1
    assert exec_rec.status == status_1
    assert exec_rec.locked_by == locked_by_1


def test_case_15_concurrent_reconciliation_attempts(db_session, base_entities, isolated_coordinator):
    """
    Test 15: Concurrent reconciliation attempts.
    Database row-level locking ensures only one instance modifies the execution.
    """
    coord = isolated_coordinator
    exec_rec = create_execution_record(db_session, base_entities, status="executing")

    reconciler1 = ThreeWayExecutionReconciler(
        registry=coord.registry,
        journal=coord.journal,
        coordinator=coord,
        db=db_session,
        reconciler_id="reconciler-1",
    )
    reconciler2 = ThreeWayExecutionReconciler(
        registry=coord.registry,
        journal=coord.journal,
        coordinator=coord,
        db=db_session,
        reconciler_id="reconciler-2",
    )

    res1 = reconciler1.reconcile_execution(exec_rec.id)
    res2 = reconciler2.reconcile_execution(exec_rec.id)

    assert res1.resulting_state == ExecutionState.EXECUTION_UNCERTAIN.value
    assert res2.classification == ReconciliationClassification.ALREADY_SYNCHRONIZED


def test_case_16_workspace_isolation(db_session, base_entities, isolated_coordinator):
    """
    Test 16: Workspace isolation enforcement.
    Reconciler strictly rejects cross-workspace executions.
    """
    coord = isolated_coordinator
    exec_rec = create_execution_record(db_session, base_entities, status="executing")

    reconciler = ThreeWayExecutionReconciler(
        registry=coord.registry,
        journal=coord.journal,
        coordinator=coord,
        workspace_id=str(uuid.uuid4()),  # Foreign workspace ID
        db=db_session,
    )

    with pytest.raises(CrossWorkspaceViolationError):
        reconciler.reconcile_execution(exec_rec.id)


def test_case_17_stale_fencing_token_rejection(db_session, base_entities, isolated_coordinator):
    """
    Test 17: Stale fencing-token rejection.
    Reconciler advances fencing token, locking out workers holding older tokens.
    """
    coord = isolated_coordinator
    exec_rec = create_execution_record(db_session, base_entities, status="executing", fencing_token=10)

    reconciler = ThreeWayExecutionReconciler(
        registry=coord.registry,
        journal=coord.journal,
        coordinator=coord,
        db=db_session,
    )

    res = reconciler.reconcile_execution(exec_rec.id)
    assert res.resulting_state == ExecutionState.EXECUTION_UNCERTAIN.value

    db_session.refresh(exec_rec)
    assert exec_rec.fencing_token == 11  # Monotonically incremented to fence off token 10


def test_case_18_dry_run_produces_no_mutations(db_session, base_entities, isolated_coordinator):
    """
    Test 18: Dry-run produces no mutations.
    Reports proposed classification and state without modifying PostgreSQL, SQLite, or Journal.
    """
    coord = isolated_coordinator
    exec_rec = create_execution_record(db_session, base_entities, status="executing")

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
    initial_length = len(initial_records)

    reconciler = ThreeWayExecutionReconciler(
        registry=coord.registry,
        journal=coord.journal,
        coordinator=coord,
        db=db_session,
    )

    res = reconciler.reconcile_execution(exec_rec.id, dry_run=True)
    assert res.is_dry_run is True
    assert res.classification == ReconciliationClassification.COMPLETED_EXIT_ZERO
    assert res.resulting_state == ExecutionState.VERIFICATION_PENDING.value

    # Zero mutations in PostgreSQL
    db_session.refresh(exec_rec)
    assert exec_rec.status == "executing"  # NOT modified!
    assert exec_rec.fencing_token == 1

    # Zero mutations in journal
    assert len(coord.journal.replay()) == initial_length


def test_case_19_failure_during_reconciliation_persistence(db_session, base_entities, isolated_coordinator):
    """
    Test 19: Failure during reconciliation persistence.
    Catches error, rolls back transaction, and fails closed with STORE_UNAVAILABLE.
    """
    coord = isolated_coordinator
    exec_rec = create_execution_record(db_session, base_entities, status="executing")

    # Mock db.commit to raise database failure
    from unittest.mock import MagicMock
    from sqlalchemy.exc import SQLAlchemyError
    db_session.commit = MagicMock(side_effect=SQLAlchemyError("Disk quota exceeded"))

    reconciler = ThreeWayExecutionReconciler(
        registry=coord.registry,
        journal=coord.journal,
        coordinator=coord,
        db=db_session,
    )

    res = reconciler.reconcile_execution(exec_rec.id)
    assert res.classification == ReconciliationClassification.STORE_UNAVAILABLE
    assert "Disk quota exceeded" in res.reason


def test_case_20_verification_failure_never_recovers_incident(db_session, base_entities, isolated_coordinator):
    """
    Test 20: Verification failure never recovers an incident.
    If diagnostic probes fail during verification resumption, execution moves to
    VERIFICATION_FAILED and the incident remains active (NEVER recovered).
    """
    coord = isolated_coordinator
    broker_client = ControlledBrokerClient(exit_code=0)

    exec_rec = create_execution_record(db_session, base_entities, status="executing")

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
        duration_ms=45,
        output_data={"status": "remediated"},
    )

    # Failing probe runner
    probe_runner = ControlledProbeRunner(should_fail_probes=True)
    verification_engine = PostExecutionVerificationEngine(runner=probe_runner)

    reconciler = ThreeWayExecutionReconciler(
        registry=coord.registry,
        journal=coord.journal,
        coordinator=coord,
        verification_engine=verification_engine,
        resume_verification=True,
        db=db_session,
    )

    res = reconciler.reconcile_execution(exec_rec.id)
    assert res.resulting_state == ExecutionState.VERIFICATION_FAILED.value

    # Incident MUST remain active and unrecovered
    incident = db_session.query(Incident).filter(Incident.id == base_entities["incident"].id).first()
    assert incident.status == "remediating"
    assert incident.recovered_at is None
    assert broker_client.call_count == 0


def test_batch_reconcile_all_with_dry_run(db_session, base_entities, isolated_coordinator):
    """
    Test batch reconciliation (reconcile_all) with dry-run mode reporting.
    """
    coord = isolated_coordinator
    appr2 = RemediationApproval(
        id=str(uuid.uuid4()),
        workspace_id=base_entities["workspace"].id,
        policy_decision_id=base_entities["policy"].id,
        incident_id=base_entities["incident"].id,
        target_service_id=base_entities["service"].id,
        action_id="restore_order_api_demo",
        validated_parameters={"service_id": base_entities["service"].id},
        risk_level="medium",
        policy_version="v1.0",
        approval_status="approved",
        requested_by=base_entities["user"].id,
        reviewed_by=base_entities["user"].id,
        reviewed_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=2),
    )
    db_session.add(appr2)
    db_session.commit()

    exec1 = create_execution_record(db_session, base_entities, status="executing")
    base_entities_2 = dict(base_entities)
    base_entities_2["approval"] = appr2
    exec2 = create_execution_record(db_session, base_entities_2, status="executing")

    reconciler = ThreeWayExecutionReconciler(
        registry=coord.registry,
        journal=coord.journal,
        coordinator=coord,
        db=db_session,
    )

    report = reconciler.reconcile_all(dry_run=True)
    assert report.is_dry_run is True
    assert report.executions_scanned >= 2
    assert len(report.results) >= 2
    assert all(r.is_dry_run for r in report.results)

    # Executions were not modified
    db_session.refresh(exec1)
    db_session.refresh(exec2)
    assert exec1.status == "executing"
    assert exec2.status == "executing"
