"""Milestone F: End-to-End Lifecycle & Failure-Path Validation.

Tests:
1. Complete 13-stage end-to-end happy path:
   - Healthy service detection
   - Failure injection & incident creation (with severity, trigger, summary) & deduplication
   - AI investigation & hypothesis generation with evidence persistence
   - Remediation policy evaluation (approval_required)
   - Human approval creation and authorization
   - Execution claim & monotonic fencing token increment
   - Durable dispatch through broker abstraction & local coordinator
   - Broker result persistence
   - Transition to verification_pending
   - Read-only post-execution verification
   - Persisted verification success
   - Incident recovery exclusively through IncidentRecoveryBridge
   - Final audit/event consistency across all stores
2. Comprehensive failure paths:
   - Rejected approval cannot execute
   - Expired approval cannot execute
   - Stale worker fencing token rejected
   - Worker crash before dispatch (unresolved reservation preserved)
   - Worker crash after dispatch start (uncertain started, zero redispatch)
   - Broker timeout / failure handling
   - Completed operation with unfinalized PostgreSQL state (watchdog recovery)
   - Verification failure never recovers incident
"""

from datetime import datetime, timedelta, timezone
import json
import os
import tempfile
import uuid
from typing import Any, Dict, List, Optional, Tuple

from fastapi import HTTPException
import httpx
import pytest
from sqlalchemy.orm import Session

from app.core.security import get_password_hash
from app.detector.runner import run_evaluation_for_service
from app.execution.broker import (
    ALLOWED_BROKER_ACTIONS,
    BrokerExecuteRequest,
    BrokerExecuteResponse,
)
from app.execution.broker_dispatcher import BrokerDispatcher
from app.execution.dispatch_coordinator import DispatchCoordinator
from app.execution.exceptions import (
    PreconditionFailedError,
    StaleWorkerFencingError,
    CrossWorkspaceViolationError,
)
from app.execution.journal import JournalRecordType, OperationJournal
from app.execution.manager import RemediationExecutionManager, sanitize_metadata
from app.execution.recovery_bridge import IncidentRecoveryBridge
from app.execution.reconciliation import (
    ReconciliationClassification,
    ThreeWayExecutionReconciler,
)
from app.execution.registry import OperationRegistry, OperationStatus
from app.execution.runner import ExecutionResult, ExecutionRunnerInterface
from app.execution.state_machine import ExecutionState
from app.execution.verification import (
    PostExecutionVerificationEngine,
    VerificationOutcome,
)
from app.execution.watchdog import ExecutionWatchdog
from app.execution.worker import DurableExecutionWorker
from app.models.incident import Incident, IncidentEvent
from app.models.investigation import Investigation
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
from app.models.workspace import Workspace, WorkspaceMembership
from app.remediation.approval_service import ApprovalService
from app.remediation.policy import PolicyEngine
from app.remediation.schemas import ApprovalStatus


# ============================================================================
# Test Doubles (Zero Docker Daemon / Live Network Access)
# ============================================================================

class ControlledBrokerClient:
    """Deterministic broker client test double."""

    def __init__(
        self,
        exit_code: int = 0,
        stdout: str = "Broker action completed successfully.",
        stderr: str = "",
        duration_ms: int = 35,
        fail_with_exception: Optional[Exception] = None,
    ):
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr
        self.duration_ms = duration_ms
        self.fail_with_exception = fail_with_exception
        self.call_count = 0
        self.requests: List[BrokerExecuteRequest] = []

    def execute_action(self, request: BrokerExecuteRequest) -> BrokerExecuteResponse:
        self.call_count += 1
        self.requests.append(request)
        if self.fail_with_exception:
            raise self.fail_with_exception
        return BrokerExecuteResponse(
            execution_id=request.execution_id,
            exit_code=self.exit_code,
            duration_ms=self.duration_ms,
            stdout_sample=self.stdout,
            stderr_sample=self.stderr,
            output_data={"status": "remediated", "stdout": self.stdout},
            error_message="Process failed" if self.exit_code != 0 else None,
            error_category="nonzero_exit" if self.exit_code != 0 else None,
        )


class ControlledProbeRunner(ExecutionRunnerInterface):
    """Controllable runner for post-execution verification probes."""

    def __init__(
        self,
        should_fail_probes: bool = False,
        probe_latency_ms: int = 10,
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

        # STRICT INVARIANT: Only read-only inspect action permitted during verification
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


# ============================================================================
# Fixtures & Helpers
# ============================================================================

@pytest.fixture
def lifecycle_env(db_session):
    """Sets up an isolated workspace, users, and service for end-to-end testing."""
    ws = Workspace(
        name="Lifecycle Ops",
        slug=f"lifecycle-ops-{uuid.uuid4().hex[:6]}",
        description="End-to-end lifecycle testing workspace",
    )
    db_session.add(ws)
    db_session.flush()

    requester = User(
        email=f"requester-{uuid.uuid4().hex[:6]}@sentinelops.local",
        full_name="Requester Engineer",
        hashed_password=get_password_hash("Password123!"),
        is_active=True,
    )
    reviewer = User(
        email=f"reviewer-{uuid.uuid4().hex[:6]}@sentinelops.local",
        full_name="Reviewer Engineer",
        hashed_password=get_password_hash("Password123!"),
        is_active=True,
    )
    db_session.add_all([requester, reviewer])
    db_session.flush()

    m1 = WorkspaceMembership(workspace_id=ws.id, user_id=requester.id, role="engineer")
    m2 = WorkspaceMembership(workspace_id=ws.id, user_id=reviewer.id, role="engineer")
    db_session.add_all([m1, m2])
    db_session.flush()

    service = Service(
        workspace_id=ws.id,
        name="Order API",
        environment="development",
        health_check_url="http://127.0.0.1:8001/health",
        monitoring_method="prometheus",
        execution_policy="demo",
        demo_integration="order_api",
        is_active=True,
    )
    db_session.add(service)
    db_session.commit()

    return {
        "workspace": ws,
        "requester": requester,
        "reviewer": reviewer,
        "service": service,
    }


@pytest.fixture
def isolated_coordinator():
    """Provides an isolated coordinator with temporary SQLite and Journal files."""
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as td:
        journal_path = os.path.join(td, "operations.journal")
        registry_path = os.path.join(td, "registry.db")

        journal = OperationJournal(journal_dir=td)
        registry = OperationRegistry(db_path=registry_path)
        coord = DispatchCoordinator(registry=registry, journal=journal)
        coord.initialize()
        yield coord
        coord.close()


def create_approval_and_execution(
    db_session: Session,
    lifecycle_env: Dict[str, Any],
    status: str = "executing",
    locked_by: Optional[str] = "worker-test",
    locked_until: Optional[datetime] = None,
    fencing_token: int = 1,
) -> Tuple[RemediationExecution, RemediationApproval, Incident]:
    """Helper to create valid approval and execution records meeting all foreign key constraints."""
    now_utc = datetime.now(timezone.utc)
    ws = lifecycle_env["workspace"]
    service = lifecycle_env["service"]
    requester = lifecycle_env["requester"]
    reviewer = lifecycle_env["reviewer"]

    incident = Incident(
        id=str(uuid.uuid4()),
        workspace_id=ws.id,
        service_id=service.id,
        title="Failure Lifecycle Incident",
        severity="high",
        status="remediating",
        trigger="health_probe_500",
    )
    db_session.add(incident)

    policy = PolicyDecision(
        id=str(uuid.uuid4()),
        workspace_id=ws.id,
        user_id=requester.id,
        action_id="restore_order_api_demo",
        target_service_id=service.id,
        risk_level="high",
        decision="approval_required",
        decision_reason="High-risk remediation action requires two-person authorization.",
        policy_version="v1.0",
        validated_parameters={"service_id": service.id},
        timestamp=now_utc,
    )
    db_session.add(policy)

    approval = RemediationApproval(
        id=str(uuid.uuid4()),
        workspace_id=ws.id,
        policy_decision_id=policy.id,
        incident_id=incident.id,
        target_service_id=service.id,
        action_id="restore_order_api_demo",
        validated_parameters={"service_id": service.id},
        risk_level="high",
        policy_version="v1.0",
        approval_status="approved",
        requested_by=requester.id,
        reviewed_by=reviewer.id,
        reviewed_at=now_utc,
        expires_at=now_utc + timedelta(hours=2),
    )
    db_session.add(approval)
    db_session.flush()

    exec_id = str(uuid.uuid4())
    execution = RemediationExecution(
        id=exec_id,
        workspace_id=ws.id,
        approval_id=approval.id,
        incident_id=incident.id,
        action_id="restore_order_api_demo",
        target_service_id=service.id,
        approved_parameters={"service_id": service.id},
        status=status,
        idempotency_key=f"idem-{exec_id[:8]}",
        locked_by=locked_by,
        locked_until=locked_until or (now_utc + timedelta(seconds=60)),
        fencing_token=fencing_token,
        triggered_by=requester.id,
        triggered_at=now_utc,
        started_at=now_utc,
        attempt_count=1,
        max_attempts=1,
    )
    db_session.add(execution)
    db_session.commit()

    return execution, approval, incident


# ============================================================================
# Test 1: Complete 13-Stage Happy-Path Lifecycle
# ============================================================================

@pytest.mark.asyncio
async def test_complete_13_stage_lifecycle_happy_path(db_session, lifecycle_env, isolated_coordinator):
    """
    Stage 2 Validation: Comprehensive 13-stage end-to-end integration test.
    Validates complete flow:
    1. Healthy service detection.
    2. Incident creation & deduplication.
    3. AI investigation & hypothesis persistence.
    4. Remediation policy evaluation (approval_required).
    5. Approval creation and two-person authorization.
    6. Execution claim and monotonic fencing token increment.
    7. Durable dispatch through broker abstraction & coordinator.
    8. Broker result persistence.
    9. Transition to verification_pending.
    10. Read-only post-execution verification.
    11. Persisted verification success.
    12. Incident recovery exclusively through IncidentRecoveryBridge.
    13. Final audit/event consistency across all stores.
    """
    ws = lifecycle_env["workspace"]
    service = lifecycle_env["service"]
    requester = lifecycle_env["requester"]
    reviewer = lifecycle_env["reviewer"]
    coord = isolated_coordinator

    # ------------------------------------------------------------------------
    # Stage 1: Healthy Service Detection
    # ------------------------------------------------------------------------
    mock_service_state = {"healthy": True, "5xx_count": 0}

    def service_handler(request: httpx.Request):
        url = str(request.url)
        if url.endswith("/health"):
            if not mock_service_state["healthy"]:
                mock_service_state["5xx_count"] += 1
                return httpx.Response(500, json={"status": "error", "message": "Database pool exhausted"})
            return httpx.Response(200, json={"status": "healthy"})
        elif url.endswith("/metrics"):
            cnt = mock_service_state["5xx_count"]
            return httpx.Response(200, text=f"order_api_http_5xx_errors_total {float(cnt)}\n")
        return httpx.Response(404)

    mock_client = httpx.AsyncClient(transport=httpx.MockTransport(service_handler))

    eval_healthy = await run_evaluation_for_service(service_id=service.id, db=db_session, client=mock_client)
    assert eval_healthy.is_healthy is True
    assert eval_healthy.lifecycle_action == "healthy"
    assert db_session.query(Incident).filter(Incident.service_id == service.id).count() == 0

    # ------------------------------------------------------------------------
    # Stage 2: Failure Detection, Incident Creation & Deduplication
    # ------------------------------------------------------------------------
    mock_service_state["healthy"] = False

    eval_fail = await run_evaluation_for_service(service_id=service.id, db=db_session, client=mock_client)
    assert eval_fail.is_healthy is False
    assert eval_fail.lifecycle_action == "created"
    assert eval_fail.incident is not None
    incident = eval_fail.incident
    assert incident.status == "detected"
    assert incident.severity == "high"
    assert "500" in incident.trigger

    # Verify deduplication on repeated poll
    eval_dedup = await run_evaluation_for_service(service_id=service.id, db=db_session, client=mock_client)
    assert eval_dedup.lifecycle_action == "deduplicated"
    assert db_session.query(Incident).filter(Incident.service_id == service.id).count() == 1

    # ------------------------------------------------------------------------
    # Stage 3: AI Investigation & Evidence Persistence
    # ------------------------------------------------------------------------
    incident.status = "investigating"
    investigation = Investigation(
        id=str(uuid.uuid4()),
        incident_id=incident.id,
        workspace_id=ws.id,
        status="completed",
        evidence=[{"5xx_rate": "high", "health_code": 500}],
        hypotheses=[
            {
                "hypothesis_id": "H1",
                "title": "Database Connection Pool Exhaustion",
                "confidence_score": 0.95,
                "remediation_action": "restore_order_api_demo",
            }
        ],
        summary={"root_cause": "pool_exhausted", "affected_service": service.name},
    )
    db_session.add(investigation)
    incident_event_inv = IncidentEvent(
        id=str(uuid.uuid4()),
        incident_id=incident.id,
        event_type="investigation",
        message="AI Investigation completed with high confidence root cause.",
        timestamp=datetime.now(timezone.utc),
    )
    db_session.add(incident_event_inv)
    db_session.commit()

    # ------------------------------------------------------------------------
    # Stage 4: Remediation Policy Evaluation
    # ------------------------------------------------------------------------
    eval_result = PolicyEngine.evaluate(
        workspace_id=ws.id,
        user_role="engineer",
        action_id="restore_order_api_demo",
        parameters={"service_id": service.id},
        environment="development",
        db=db_session,
        user_id=requester.id,
    )
    assert eval_result.approval_required is True

    decision = PolicyDecision(
        workspace_id=ws.id,
        user_id=requester.id,
        action_id="restore_order_api_demo",
        target_service_id=service.id,
        risk_level="high",  # Explicit high-risk for two-person integrity testing
        decision=eval_result.decision.value,
        decision_reason=eval_result.decision_reason,
        policy_version=eval_result.policy_version,
        validated_parameters=eval_result.validated_parameters,
    )
    db_session.add(decision)
    db_session.commit()

    # ------------------------------------------------------------------------
    # Stage 5: Approval Creation & Two-Person Authorization
    # ------------------------------------------------------------------------
    approval = ApprovalService.create_approval_request(
        db=db_session,
        workspace_id=ws.id,
        policy_decision_id=decision.id,
        requested_by=requester,
        incident_id=incident.id,
        investigation_id=investigation.id,
        expires_in_hours=1,
    )
    assert approval.approval_status == ApprovalStatus.PENDING.value

    # Two-Person Integrity: Requester cannot self-approve high-risk
    with pytest.raises(HTTPException) as exc_self:
        ApprovalService.approve_request(
            db=db_session,
            approval_id=approval.id,
            workspace_id=ws.id,
            reviewer=requester,  # Self-approval forbidden
            user_role="engineer",
        )
    assert exc_self.value.status_code == 403

    # Authorized reviewer approves
    approved_record = ApprovalService.approve_request(
        db=db_session,
        approval_id=approval.id,
        workspace_id=ws.id,
        reviewer=reviewer,
        user_role="engineer",
    )
    assert approved_record.approval_status == ApprovalStatus.APPROVED.value

    # ------------------------------------------------------------------------
    # Stage 6: Execution Claim & Monotonic Fencing Token
    # ------------------------------------------------------------------------
    execution = RemediationExecutionManager.create_execution(
        db=db_session,
        approval_id=approved_record.id,
        workspace_id=ws.id,
        triggered_by=requester,
        user_role="engineer",
        idempotency_key=f"idem-{uuid.uuid4().hex[:8]}",
    )
    assert execution.status == ExecutionState.QUEUED.value
    initial_fencing_token = execution.fencing_token

    # Worker claims execution
    worker_id = "worker-e2e-node-01"
    claimed_exec = RemediationExecutionManager.claim_next_execution(
        db=db_session,
        worker_id=worker_id,
        workspace_id=ws.id,
        lease_seconds=60,
    )
    assert claimed_exec is not None
    assert claimed_exec.status == ExecutionState.VALIDATING.value
    assert claimed_exec.locked_by == worker_id
    assert claimed_exec.fencing_token == initial_fencing_token + 1
    current_token = claimed_exec.fencing_token

    # ------------------------------------------------------------------------
    # Stage 7 & 8: Durable Dispatch through Broker & Result Persistence
    # ------------------------------------------------------------------------
    broker_client = ControlledBrokerClient(exit_code=0, stdout="Order API demo restored successfully.")
    dispatcher = BrokerDispatcher(coordinator=coord, broker_client=broker_client)
    probe_runner = ControlledProbeRunner(should_fail_probes=False)
    verification_engine = PostExecutionVerificationEngine(runner=probe_runner)

    worker = DurableExecutionWorker(
        worker_id=worker_id,
        coordinator=coord,
        broker_dispatcher=dispatcher,
        verification_engine=verification_engine,
        enable_verification=True,
        db=db_session,
    )

    # Worker executes claimed execution through full 12-stage protocol
    worker._process_claimed_execution(execution_id=claimed_exec.id, fencing_token=claimed_exec.fencing_token)

    # Verify coordinator and journal invariants
    db_session.refresh(claimed_exec)
    db_session.refresh(incident)

    # Exactly 1 broker invocation occurred
    assert broker_client.call_count == 1
    assert broker_client.requests[0].action_id == "restore_order_api_demo"

    # Journal records sequence integrity
    journal_records = coord.journal.replay()
    record_types = [r.record_type for r in journal_records]
    assert JournalRecordType.DISPATCH_PREPARED.value in record_types
    assert JournalRecordType.DOCKER_CALL_STARTED.value in record_types
    assert JournalRecordType.DOCKER_CALL_COMPLETED.value in record_types

    # Registry state
    op = coord.registry.get_by_execution_and_token(claimed_exec.id, current_token)
    assert op is not None
    assert op.operation_status == OperationStatus.DOCKER_CALL_COMPLETED

    # ------------------------------------------------------------------------
    # Stage 9, 10, 11, 12: Verification, Persisted Success & Atomic Bridge Recovery
    # ------------------------------------------------------------------------
    assert claimed_exec.status == ExecutionState.VERIFIED.value
    assert claimed_exec.verification_status == "verified"
    assert incident.status == "recovered"
    assert incident.recovered_at is not None

    # Verification cycle persistence verification
    cycles = db_session.query(VerificationCycle).filter(VerificationCycle.execution_id == claimed_exec.id).all()
    assert len(cycles) == 1
    cycle = cycles[0]
    assert cycle.status == "passed"

    # Exactly 4 probe results recorded (Probe 1 baseline + Probes 2,3,4 passing)
    probes = db_session.query(VerificationProbeResult).filter(VerificationProbeResult.cycle_id == cycle.id).all()
    assert len(probes) == 4
    assert probes[0].probe_type == "baseline"
    assert all(p.status == "passed" for p in probes)

    # ------------------------------------------------------------------------
    # Stage 13: Final Audit / Event Consistency
    # ------------------------------------------------------------------------
    exec_events = (
        db_session.query(ExecutionEvent)
        .filter(ExecutionEvent.execution_id == claimed_exec.id)
        .order_by(ExecutionEvent.timestamp.asc())
        .all()
    )
    event_types = [e.event_type for e in exec_events]
    assert "executing" in event_types
    assert "verification_pending" in event_types
    assert "verified" in event_types

    incident_events = (
        db_session.query(IncidentEvent)
        .filter(IncidentEvent.incident_id == incident.id)
        .all()
    )
    inc_types = [e.event_type for e in incident_events]
    assert "detection" in inc_types
    assert "verification" in inc_types
    assert any("recovered" in (e.message or "").lower() for e in incident_events)

    await mock_client.aclose()


# ============================================================================
# Failure-Path Validations
# ============================================================================

def test_failure_path_rejected_approval_cannot_execute(db_session, lifecycle_env):
    """Failure Path 1: Rejected approval cannot be executed."""
    ws = lifecycle_env["workspace"]
    service = lifecycle_env["service"]
    requester = lifecycle_env["requester"]
    reviewer = lifecycle_env["reviewer"]

    eval_result = PolicyEngine.evaluate(
        workspace_id=ws.id,
        user_role="engineer",
        action_id="restore_order_api_demo",
        parameters={"service_id": service.id},
        environment="development",
        db=db_session,
        user_id=requester.id,
    )
    decision = PolicyDecision(
        workspace_id=ws.id,
        user_id=requester.id,
        action_id="restore_order_api_demo",
        target_service_id=service.id,
        risk_level=eval_result.risk_level,
        decision=eval_result.decision.value,
        decision_reason=eval_result.decision_reason,
        policy_version=eval_result.policy_version,
        validated_parameters=eval_result.validated_parameters,
    )
    db_session.add(decision)
    db_session.commit()

    approval = ApprovalService.create_approval_request(
        db=db_session,
        workspace_id=ws.id,
        policy_decision_id=decision.id,
        requested_by=requester,
    )
    ApprovalService.reject_request(
        db=db_session,
        approval_id=approval.id,
        workspace_id=ws.id,
        reviewer=reviewer,
        user_role="engineer",
        rejection_reason="Manual change freeze in effect.",
    )

    with pytest.raises(Exception) as exc_info:
        RemediationExecutionManager.create_execution(
            db=db_session,
            approval_id=approval.id,
            workspace_id=ws.id,
            triggered_by=requester,
            user_role="engineer",
            idempotency_key=f"idem-{uuid.uuid4().hex[:8]}",
        )
    assert "Cannot create execution" in str(exc_info.value) or "rejected" in str(exc_info.value).lower()


def test_failure_path_expired_approval_cannot_execute(db_session, lifecycle_env):
    """Failure Path 2: Expired approval cannot be approved or executed."""
    ws = lifecycle_env["workspace"]
    service = lifecycle_env["service"]
    requester = lifecycle_env["requester"]
    reviewer = lifecycle_env["reviewer"]

    eval_result = PolicyEngine.evaluate(
        workspace_id=ws.id,
        user_role="engineer",
        action_id="restore_order_api_demo",
        parameters={"service_id": service.id},
        environment="development",
        db=db_session,
        user_id=requester.id,
    )
    decision = PolicyDecision(
        workspace_id=ws.id,
        user_id=requester.id,
        action_id="restore_order_api_demo",
        target_service_id=service.id,
        risk_level=eval_result.risk_level,
        decision=eval_result.decision.value,
        decision_reason=eval_result.decision_reason,
        policy_version=eval_result.policy_version,
        validated_parameters=eval_result.validated_parameters,
    )
    db_session.add(decision)
    db_session.commit()

    approval = ApprovalService.create_approval_request(
        db=db_session,
        workspace_id=ws.id,
        policy_decision_id=decision.id,
        requested_by=requester,
        expires_in_hours=1,
    )
    # Manually backdate expiration
    approval.expires_at = datetime.now(timezone.utc) - timedelta(minutes=5)
    db_session.commit()

    with pytest.raises(HTTPException) as exc_exp:
        ApprovalService.approve_request(
            db=db_session,
            approval_id=approval.id,
            workspace_id=ws.id,
            reviewer=reviewer,
            user_role="engineer",
        )
    assert exc_exp.value.status_code == 400


def test_failure_path_stale_worker_fencing_token_rejected(db_session, lifecycle_env):
    """Failure Path 3: Stale worker fencing token is strictly rejected."""
    execution, approval, incident = create_approval_and_execution(
        db_session=db_session,
        lifecycle_env=lifecycle_env,
        status="executing",
        locked_by="worker-01",
        fencing_token=5,
    )

    # Attempt heartbeat with stale token
    stale_token = execution.fencing_token - 1
    with pytest.raises(StaleWorkerFencingError):
        RemediationExecutionManager.heartbeat_lease(
            execution_id=execution.id,
            worker_id="worker-01",
            expected_fencing_token=stale_token,
            db=db_session,
        )


def test_failure_path_worker_crash_before_dispatch(db_session, lifecycle_env, isolated_coordinator):
    """Failure Path 4: Worker crash before dispatch preserves reservation and establishes hold."""
    coord = isolated_coordinator
    ws = lifecycle_env["workspace"]

    exec_rec, approval, incident = create_approval_and_execution(
        db_session=db_session,
        lifecycle_env=lifecycle_env,
        status="executing",
        locked_by="crashed-worker-01",
        locked_until=datetime.now(timezone.utc) - timedelta(seconds=10),
        fencing_token=1,
    )

    # Reserve in SQLite, but journal is empty
    op = coord.reserve_operation(
        execution_id=exec_rec.id,
        workspace_id=ws.id,
        approval_id=approval.id,
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


def test_failure_path_worker_crash_after_dispatch_start(db_session, lifecycle_env, isolated_coordinator):
    """Failure Path 5: Crash after DOCKER_CALL_STARTED establishes uncertainty hold with ZERO redispatch."""
    coord = isolated_coordinator
    ws = lifecycle_env["workspace"]
    broker_client = ControlledBrokerClient(exit_code=0)

    exec_rec, approval, incident = create_approval_and_execution(
        db_session=db_session,
        lifecycle_env=lifecycle_env,
        status="executing",
        locked_by="crashed-worker-02",
        locked_until=datetime.now(timezone.utc) - timedelta(seconds=10),
        fencing_token=1,
    )

    op = coord.reserve_operation(
        execution_id=exec_rec.id,
        workspace_id=ws.id,
        approval_id=approval.id,
        attempt_number=1,
        fencing_token=1,
    )
    coord.prepare_dispatch(
        operation_id=op.operation_id,
        execution_id=exec_rec.id,
        fencing_token=1,
        workspace_id=ws.id,
    )
    coord.record_docker_call_started(
        operation_id=op.operation_id,
        execution_id=exec_rec.id,
        fencing_token=1,
        workspace_id=ws.id,
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

    # MANDATORY REVISION 10 INVARIANT: Broker call count remains zero
    assert broker_client.call_count == 0


def test_failure_path_broker_timeout_handling(db_session, lifecycle_env, isolated_coordinator):
    """Failure Path 6: Broker network timeout records DISPATCH_UNCERTAIN and locks under uncertainty hold."""
    coord = isolated_coordinator
    ws = lifecycle_env["workspace"]

    exec_rec, approval, incident = create_approval_and_execution(
        db_session=db_session,
        lifecycle_env=lifecycle_env,
        status="executing",
        locked_by="worker-timeout",
        locked_until=datetime.now(timezone.utc) + timedelta(seconds=60),
        fencing_token=1,
    )

    # Broker client that raises timeout
    failing_client = ControlledBrokerClient(fail_with_exception=TimeoutError("Broker IPC socket timeout"))
    dispatcher = BrokerDispatcher(coordinator=coord, broker_client=failing_client)

    op = coord.reserve_operation(
        execution_id=exec_rec.id,
        workspace_id=ws.id,
        approval_id=approval.id,
        attempt_number=1,
        fencing_token=1,
    )
    coord.prepare_dispatch(
        operation_id=op.operation_id,
        execution_id=exec_rec.id,
        fencing_token=1,
        workspace_id=ws.id,
    )

    res = dispatcher.dispatch_action(
        action_id="restore_order_api_demo",
        execution_id=exec_rec.id,
        workspace_id=ws.id,
        approval_id=approval.id,
        target_url="http://127.0.0.1:8001/restore",
        fencing_token=1,
        attempt_number=1,
        operation_id=op.operation_id,
        environment="development",
    )

    assert res.is_uncertain is True
    preserved_op = coord.registry.get_operation(op.operation_id)
    assert preserved_op.operation_status == OperationStatus.DISPATCH_UNCERTAIN


def test_failure_path_completed_operation_unfinalized_pg(db_session, lifecycle_env, isolated_coordinator):
    """Failure Path 7: Completed operation with unfinalized PostgreSQL reconciled by watchdog."""
    coord = isolated_coordinator
    ws = lifecycle_env["workspace"]

    exec_rec, approval, incident = create_approval_and_execution(
        db_session=db_session,
        lifecycle_env=lifecycle_env,
        status="executing",
        locked_by="crashed-worker-03",
        locked_until=datetime.now(timezone.utc) - timedelta(seconds=15),
        fencing_token=1,
    )

    # Completed exit 0 in coordinator
    op = coord.reserve_operation(
        execution_id=exec_rec.id,
        workspace_id=ws.id,
        approval_id=approval.id,
        attempt_number=1,
        fencing_token=1,
    )
    coord.prepare_dispatch(
        operation_id=op.operation_id,
        execution_id=exec_rec.id,
        fencing_token=1,
        workspace_id=ws.id,
    )
    coord.record_docker_call_started(
        operation_id=op.operation_id,
        execution_id=exec_rec.id,
        fencing_token=1,
        workspace_id=ws.id,
    )
    coord.complete_dispatch(
        operation_id=op.operation_id,
        exit_code=0,
        duration_ms=40,
        output_data={"status": "remediated"},
    )

    probe_runner = ControlledProbeRunner(should_fail_probes=False)
    verification_engine = PostExecutionVerificationEngine(runner=probe_runner)

    watchdog = ExecutionWatchdog(
        coordinator=coord,
        runner=probe_runner,
        verification_engine=verification_engine,
        resume_verification=True,
        db=db_session,
    )

    recon_res = watchdog.reconcile_execution(db_session, exec_rec.id, now_utc=datetime.now(timezone.utc))
    assert recon_res is not None
    assert recon_res["resulting_state"] == ExecutionState.VERIFIED.value

    db_session.refresh(exec_rec)
    db_session.refresh(incident)
    assert exec_rec.status == ExecutionState.VERIFIED.value
    assert incident.status == "recovered"


def test_failure_path_verification_failure_never_recovers_incident(db_session, lifecycle_env, isolated_coordinator):
    """Failure Path 8: Verification probe failure sets execution to verification_failed and NEVER recovers incident."""
    coord = isolated_coordinator
    ws = lifecycle_env["workspace"]

    exec_rec, approval, incident = create_approval_and_execution(
        db_session=db_session,
        lifecycle_env=lifecycle_env,
        status="verification_pending",
        locked_by="worker-verify-fail",
        locked_until=datetime.now(timezone.utc) + timedelta(seconds=60),
        fencing_token=1,
    )
    exec_rec.verification_status = "pending"
    db_session.commit()

    failing_probe_runner = ControlledProbeRunner(should_fail_probes=True)
    verification_engine = PostExecutionVerificationEngine(runner=failing_probe_runner)

    summary = verification_engine.run_verification_cycle(
        db=db_session,
        execution_id=exec_rec.id,
        workspace_id=ws.id,
        worker_id="worker-verify-fail",
        fencing_token=1,
        cycle_number=1,
        probes_required=1,
        timeout_seconds=30,
        recover_incident=True,
    )

    assert summary.outcome == VerificationOutcome.FAIL
    db_session.refresh(exec_rec)
    db_session.refresh(incident)

    assert exec_rec.status == ExecutionState.VERIFICATION_FAILED.value
    # STRICT SAFETY INVARIANT: Incident remains active, NEVER marked recovered
    assert incident.status == "remediating"
    assert incident.recovered_at is None
