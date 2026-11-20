"""Test Suite for Atomic Incident Recovery Bridge (Phase 4.3.6 Milestone C).

Covers:
1. Successful atomic execution finalization and incident recovery.
2. Single-transaction ACID atomicity (rollback leaves zero partial state).
3. Execution success alone never recovers an incident.
4. Cross-workspace access rejection (execution, incident, cycle).
5. Incident association mismatch rejection.
6. Service ID mismatch rejection.
7. Unrelated incidents for the same service remain untouched.
8. Monotonic fencing token validation & stale worker rejection.
9. Expired worker lease rejection.
10. Worker identity mismatch rejection.
11. Expired verification cycle deadline rejection.
12. Failed verification cycle rejection (incident never recovered).
13. Inconclusive/uncertain verification cycle rejection.
14. Missing or failed baseline probe rejection.
15. Insufficient consecutive passing probes rejection.
16. Closed incident terminal protection (cannot be overwritten).
17. Idempotent re-execution with identical parameters.
18. Conflicting duplicate parameters rejection.
19. End-to-end PostExecutionVerificationEngine with recover_incident=True (success).
20. End-to-end PostExecutionVerificationEngine with recover_incident=True (failure: incident active).
"""

from datetime import datetime, timedelta, timezone
import json
import uuid
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.base import Base
from app.execution.exceptions import (
    CrossWorkspaceViolationError,
    IncidentAssociationMismatchError,
    PreconditionFailedError,
    StaleWorkerFencingError,
    VerificationCycleNotFoundError,
    VerificationDeadlineExpiredError,
    VerificationPreconditionError,
)
from app.execution.recovery_bridge import IncidentRecoveryBridge
from app.execution.runner import ExecutionResult, ExecutionRunnerInterface
from app.execution.state_machine import ExecutionState
from app.execution.verification import (
    PostExecutionVerificationEngine,
    VerificationOutcome,
)
from app.execution.verification_persistence import (
    VerificationPersistenceService,
    generate_deterministic_probe_id,
)
from app.models.incident import Incident, IncidentEvent
from app.models.remediation import (
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

class SafeVerificationTestRunner(ExecutionRunnerInterface):
    """Deterministic runner mock for post-execution verification tests."""

    def __init__(self, failure_on_probe: int = -1):
        self.call_count = 0
        self.failure_on_probe = failure_on_probe

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
        self.call_count += 1

        metrics_txt = (
            "# HELP order_api_http_5xx_errors_total Total 5xx HTTP errors\n"
            "# TYPE order_api_http_5xx_errors_total counter\n"
            "order_api_http_5xx_errors_total 10.0\n"
        )
        endpoints = {
            "health": {
                "status_code": 200,
                "duration_ms": 15,
                "output_data": {"status": "healthy"},
                "error_message": None,
                "success": True,
            },
            "demo_status": {
                "status_code": 200,
                "duration_ms": 10,
                "output_data": {"failure_active": False},
                "error_message": None,
                "success": True,
            },
            "metrics": {
                "status_code": 200,
                "duration_ms": 20,
                "output_data": {"raw_text": metrics_txt, "status_code": 200},
                "raw_text": metrics_txt,
                "error_message": None,
                "success": True,
            },
        }

        if self.failure_on_probe > 0 and self.call_count >= self.failure_on_probe:
            endpoints["health"]["status_code"] = 500
            endpoints["health"]["success"] = False
            endpoints["health"]["error_message"] = "Service unhealthy"
            return ExecutionResult(
                exit_code=0,
                duration_ms=45,
                output_data={"status": "completed", "endpoints": endpoints, "all_endpoints_successful": False},
            )

        return ExecutionResult(
            exit_code=0,
            duration_ms=45,
            output_data={"status": "completed", "endpoints": endpoints, "all_endpoints_successful": True},
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
def test_setup(db_session):
    """Seed base entities: workspace, user, service, incident, execution, and verification cycle."""
    now_utc = datetime.now(timezone.utc)
    ws_id = str(uuid.uuid4())
    ws = Workspace(id=ws_id, name="Test WS", slug=f"ws-{ws_id[:8]}")
    db_session.add(ws)

    user_id = str(uuid.uuid4())
    user = User(
        id=user_id,
        email="operator@test.local",
        full_name="Operator Local",
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

    exec_id = str(uuid.uuid4())
    execution = RemediationExecution(
        id=exec_id,
        workspace_id=ws_id,
        approval_id=approval_id,
        incident_id=inc_id,
        action_id="restore_order_api_demo",
        target_service_id=svc_id,
        approved_parameters={"service_id": svc_id},
        status=ExecutionState.VERIFICATION_PENDING.value,
        verification_status="pending",
        idempotency_key=f"idem-{exec_id[:8]}",
        locked_by="worker-rec-01",
        locked_until=now_utc + timedelta(seconds=120),
        heartbeat_at=now_utc,
        fencing_token=5,
        triggered_by=user_id,
        triggered_at=now_utc,
        started_at=now_utc,
        completed_at=None,
        attempt_count=1,
        max_attempts=1,
    )
    db_session.add(execution)

    cycle_id = str(uuid.uuid4())
    cycle = VerificationCycle(
        id=cycle_id,
        execution_id=exec_id,
        workspace_id=ws_id,
        cycle_number=1,
        status="passed",
        probes_required=3,
        probes_passed=3,
        probes_failed=0,
        started_at=now_utc,
        completed_at=now_utc + timedelta(seconds=10),
        deadline_at=now_utc + timedelta(seconds=60),
        fencing_token=5,
        verifying_worker_id="worker-rec-01",
        cycle_metadata={"outcome": "PASS", "probes_passed": 3},
    )
    db_session.add(cycle)

    # Add Probe 1: baseline passed
    probe1 = VerificationProbeResult(
        id=generate_deterministic_probe_id(exec_id, 1, 1),
        cycle_id=cycle_id,
        execution_id=exec_id,
        workspace_id=ws_id,
        probe_number=1,
        probe_type="baseline",
        target_url="http://host.docker.internal:8001/health",
        status="passed",
        status_code=200,
        passed=True,
        executed_at=now_utc,
        latency_ms=25.0,
        probe_output={"status": "baseline_ok", "metrics_5xx_total": 10.0, "delta_5xx": 0.0},
    )
    db_session.add(probe1)

    # Add Probes 2..4: three consecutive passing probes
    for p_num in (2, 3, 4):
        p = VerificationProbeResult(
            id=generate_deterministic_probe_id(exec_id, 1, p_num),
            cycle_id=cycle_id,
            execution_id=exec_id,
            workspace_id=ws_id,
            probe_number=p_num,
            probe_type="health_check",
            target_url="http://host.docker.internal:8001/health",
            status="passed",
            status_code=200,
            passed=True,
            executed_at=now_utc + timedelta(seconds=p_num),
            latency_ms=20.0,
            probe_output={"status": "healthy", "metrics_5xx_total": 10.0, "delta_5xx": 0.0},
        )
        db_session.add(p)

    db_session.commit()

    return {
        "workspace": ws,
        "service": service,
        "incident": incident,
        "execution": execution,
        "cycle": cycle,
        "user": user,
    }


# ============================================================================
# Unit & Integration Tests
# ============================================================================

def test_successful_atomic_execution_and_incident_recovery(db_session, test_setup):
    """Execution transitions to VERIFIED and Incident transitions to RECOVERED atomically."""
    exec_obj = test_setup["execution"]
    inc_obj = test_setup["incident"]
    cycle_obj = test_setup["cycle"]
    ws_obj = test_setup["workspace"]

    res_exec, res_inc = IncidentRecoveryBridge.recover_incident_on_verification_success(
        db=db_session,
        execution_id=exec_obj.id,
        workspace_id=ws_obj.id,
        cycle_id=cycle_obj.id,
        incident_id=inc_obj.id,
        worker_id="worker-rec-01",
        fencing_token=5,
        auto_commit=True,
    )

    assert res_exec.status == ExecutionState.VERIFIED.value
    assert res_exec.verification_status == "verified"
    assert res_exec.completed_at is not None
    assert res_exec.locked_by is None
    assert res_exec.locked_until is None

    assert res_inc is not None
    assert res_inc.status == "recovered"
    assert res_inc.recovered_at is not None

    # Check ExecutionEvent
    exec_event = (
        db_session.query(ExecutionEvent)
        .filter(ExecutionEvent.execution_id == exec_obj.id, ExecutionEvent.event_type == "verified")
        .first()
    )
    assert exec_event is not None
    assert exec_event.workspace_id == ws_obj.id
    assert "verified successfully" in exec_event.message
    assert exec_event.metadata_json["cycle_id"] == cycle_obj.id
    assert exec_event.metadata_json["fencing_token"] in (5, "[REDACTED]")

    # Check IncidentEvent
    inc_event = (
        db_session.query(IncidentEvent)
        .filter(IncidentEvent.incident_id == inc_obj.id, IncidentEvent.event_type == "verification")
        .first()
    )
    assert inc_event is not None
    assert "Remediation verified" in inc_event.message
    meta = json.loads(inc_event.metadata_json)
    assert meta["execution_id"] == exec_obj.id
    assert meta["cycle_id"] == cycle_obj.id
    assert meta["status"] == "recovered"


def test_execution_verified_and_incident_recovered_in_same_transaction(db_session, test_setup):
    """Validates transactional atomicity: uncommitted mutations rollback cleanly on failure."""
    exec_obj = test_setup["execution"]
    inc_obj = test_setup["incident"]
    cycle_obj = test_setup["cycle"]
    ws_obj = test_setup["workspace"]

    # Call with auto_commit=False
    res_exec, res_inc = IncidentRecoveryBridge.recover_incident_on_verification_success(
        db=db_session,
        execution_id=exec_obj.id,
        workspace_id=ws_obj.id,
        cycle_id=cycle_obj.id,
        incident_id=inc_obj.id,
        worker_id="worker-rec-01",
        fencing_token=5,
        auto_commit=False,
    )

    # In session, changes are present
    assert res_exec.status == ExecutionState.VERIFIED.value
    assert res_inc.status == "recovered"

    # Roll back transaction
    db_session.rollback()

    # Re-query
    db_exec = db_session.query(RemediationExecution).filter_by(id=exec_obj.id).first()
    db_inc = db_session.query(Incident).filter_by(id=inc_obj.id).first()

    assert db_exec.status == ExecutionState.VERIFICATION_PENDING.value
    assert db_inc.status == "remediating"
    assert db_inc.recovered_at is None


def test_execution_success_alone_never_recovers_incident(db_session, test_setup):
    """Execution in execution_succeeded state must NOT recover incident without verification."""
    exec_obj = test_setup["execution"]
    inc_obj = test_setup["incident"]
    cycle_obj = test_setup["cycle"]
    ws_obj = test_setup["workspace"]

    # Set execution status to execution_succeeded
    exec_obj.status = ExecutionState.EXECUTION_SUCCEEDED.value
    db_session.commit()

    with pytest.raises(VerificationPreconditionError) as exc_info:
        IncidentRecoveryBridge.recover_incident_on_verification_success(
            db=db_session,
            execution_id=exec_obj.id,
            workspace_id=ws_obj.id,
            cycle_id=cycle_obj.id,
            incident_id=inc_obj.id,
            worker_id="worker-rec-01",
            fencing_token=5,
        )

    assert "Execution success alone must never recover an incident" in str(exc_info.value)

    # Incident remains active
    db_inc = db_session.query(Incident).filter_by(id=inc_obj.id).first()
    assert db_inc.status == "remediating"
    assert db_inc.recovered_at is None


def test_cross_workspace_rejections(db_session, test_setup):
    """Rejects cross-workspace operations for execution, incident, and cycle."""
    exec_obj = test_setup["execution"]
    inc_obj = test_setup["incident"]
    cycle_obj = test_setup["cycle"]
    alien_ws_id = str(uuid.uuid4())

    # 1. Wrong workspace_id passed
    with pytest.raises(CrossWorkspaceViolationError):
        IncidentRecoveryBridge.recover_incident_on_verification_success(
            db=db_session,
            execution_id=exec_obj.id,
            workspace_id=alien_ws_id,
            cycle_id=cycle_obj.id,
            incident_id=inc_obj.id,
        )

    # 2. Cycle belongs to different workspace
    cycle_obj.workspace_id = alien_ws_id
    db_session.commit()
    with pytest.raises(CrossWorkspaceViolationError):
        IncidentRecoveryBridge.recover_incident_on_verification_success(
            db=db_session,
            execution_id=exec_obj.id,
            workspace_id=test_setup["workspace"].id,
            cycle_id=cycle_obj.id,
            incident_id=inc_obj.id,
        )
    cycle_obj.workspace_id = test_setup["workspace"].id
    db_session.commit()

    # 3. Incident belongs to different workspace
    inc_obj.workspace_id = alien_ws_id
    db_session.commit()
    with pytest.raises(CrossWorkspaceViolationError):
        IncidentRecoveryBridge.recover_incident_on_verification_success(
            db=db_session,
            execution_id=exec_obj.id,
            workspace_id=test_setup["workspace"].id,
            cycle_id=cycle_obj.id,
            incident_id=inc_obj.id,
        )


def test_wrong_incident_association_rejection(db_session, test_setup):
    """Rejects call when incident ID does not match execution.incident_id."""
    exec_obj = test_setup["execution"]
    cycle_obj = test_setup["cycle"]
    ws_obj = test_setup["workspace"]

    alien_inc = Incident(
        id=str(uuid.uuid4()),
        workspace_id=ws_obj.id,
        service_id=test_setup["service"].id,
        title="Different Incident",
        severity="low",
        status="detected",
        trigger="cpu_threshold",
    )
    db_session.add(alien_inc)
    db_session.commit()

    with pytest.raises(IncidentAssociationMismatchError):
        IncidentRecoveryBridge.recover_incident_on_verification_success(
            db=db_session,
            execution_id=exec_obj.id,
            workspace_id=ws_obj.id,
            cycle_id=cycle_obj.id,
            incident_id=alien_inc.id,
            worker_id="worker-rec-01",
            fencing_token=5,
        )

    # Alien incident is NOT recovered
    db_session.refresh(alien_inc)
    assert alien_inc.status == "detected"


def test_wrong_service_association_rejection(db_session, test_setup):
    """Rejects call when incident belongs to a different service than execution target service."""
    exec_obj = test_setup["execution"]
    cycle_obj = test_setup["cycle"]
    ws_obj = test_setup["workspace"]
    inc_obj = test_setup["incident"]

    # Create another service
    other_svc = Service(
        id=str(uuid.uuid4()),
        workspace_id=ws_obj.id,
        name="Payment API",
        health_check_url="http://host.docker.internal:8002/health",
        environment="development",
        is_active=True,
    )
    db_session.add(other_svc)
    # Point incident to other service
    inc_obj.service_id = other_svc.id
    db_session.commit()

    with pytest.raises(IncidentAssociationMismatchError) as exc_info:
        IncidentRecoveryBridge.recover_incident_on_verification_success(
            db=db_session,
            execution_id=exec_obj.id,
            workspace_id=ws_obj.id,
            cycle_id=cycle_obj.id,
            incident_id=inc_obj.id,
            worker_id="worker-rec-01",
            fencing_token=5,
        )

    assert "Incident service mismatch" in str(exc_info.value)
    db_session.refresh(inc_obj)
    assert inc_obj.status == "remediating"


def test_unrelated_incidents_for_same_service_not_recovered(db_session, test_setup):
    """Unrelated active incidents on the same service remain active when target incident is recovered."""
    exec_obj = test_setup["execution"]
    inc_obj = test_setup["incident"]
    cycle_obj = test_setup["cycle"]
    ws_obj = test_setup["workspace"]
    svc_obj = test_setup["service"]

    # Create an unrelated incident for the same service
    unrelated_inc = Incident(
        id=str(uuid.uuid4()),
        workspace_id=ws_obj.id,
        service_id=svc_obj.id,
        title="Unrelated Concurrent Latency Spike",
        severity="medium",
        status="investigating",
        trigger="latency_p99_spike",
    )
    db_session.add(unrelated_inc)
    db_session.commit()

    # Recover target incident
    IncidentRecoveryBridge.recover_incident_on_verification_success(
        db=db_session,
        execution_id=exec_obj.id,
        workspace_id=ws_obj.id,
        cycle_id=cycle_obj.id,
        incident_id=inc_obj.id,
        worker_id="worker-rec-01",
        fencing_token=5,
        auto_commit=True,
    )

    db_session.refresh(inc_obj)
    db_session.refresh(unrelated_inc)

    assert inc_obj.status == "recovered"
    # Unrelated incident is strictly untouched
    assert unrelated_inc.status == "investigating"
    assert unrelated_inc.recovered_at is None


def test_stale_fencing_token_rejection(db_session, test_setup):
    """Rejects stale worker attempts with obsolete fencing token."""
    exec_obj = test_setup["execution"]
    inc_obj = test_setup["incident"]
    cycle_obj = test_setup["cycle"]
    ws_obj = test_setup["workspace"]

    with pytest.raises(StaleWorkerFencingError) as exc_info:
        IncidentRecoveryBridge.recover_incident_on_verification_success(
            db=db_session,
            execution_id=exec_obj.id,
            workspace_id=ws_obj.id,
            cycle_id=cycle_obj.id,
            incident_id=inc_obj.id,
            worker_id="worker-rec-01",
            fencing_token=4,  # Stale token (execution has 5)
        )

    assert "Stale worker fencing token" in str(exc_info.value)
    db_session.refresh(inc_obj)
    assert inc_obj.status == "remediating"


def test_worker_lease_expired_rejection(db_session, test_setup):
    """Rejects recovery when worker lease has expired."""
    exec_obj = test_setup["execution"]
    inc_obj = test_setup["incident"]
    cycle_obj = test_setup["cycle"]
    ws_obj = test_setup["workspace"]

    # Expire the lease
    exec_obj.locked_until = datetime.now(timezone.utc) - timedelta(seconds=10)
    db_session.commit()

    with pytest.raises(StaleWorkerFencingError) as exc_info:
        IncidentRecoveryBridge.recover_incident_on_verification_success(
            db=db_session,
            execution_id=exec_obj.id,
            workspace_id=ws_obj.id,
            cycle_id=cycle_obj.id,
            incident_id=inc_obj.id,
            worker_id="worker-rec-01",
            fencing_token=5,
        )

    assert "Worker lease expired" in str(exc_info.value)
    db_session.refresh(inc_obj)
    assert inc_obj.status == "remediating"


def test_worker_identity_mismatch_rejection(db_session, test_setup):
    """Rejects recovery when worker identity does not match execution locked_by."""
    exec_obj = test_setup["execution"]
    inc_obj = test_setup["incident"]
    cycle_obj = test_setup["cycle"]
    ws_obj = test_setup["workspace"]

    with pytest.raises(StaleWorkerFencingError) as exc_info:
        IncidentRecoveryBridge.recover_incident_on_verification_success(
            db=db_session,
            execution_id=exec_obj.id,
            workspace_id=ws_obj.id,
            cycle_id=cycle_obj.id,
            incident_id=inc_obj.id,
            worker_id="worker-imposter-99",
            fencing_token=5,
        )

    assert "Execution is locked by worker 'worker-rec-01'" in str(exc_info.value)


def test_expired_verification_cycle_deadline_rejection(db_session, test_setup):
    """Rejects recovery if cycle completed after deadline."""
    exec_obj = test_setup["execution"]
    inc_obj = test_setup["incident"]
    cycle_obj = test_setup["cycle"]
    ws_obj = test_setup["workspace"]

    # Set deadline before completion
    cycle_obj.deadline_at = cycle_obj.started_at + timedelta(seconds=5)
    cycle_obj.completed_at = cycle_obj.started_at + timedelta(seconds=10)
    db_session.commit()

    with pytest.raises(VerificationDeadlineExpiredError) as exc_info:
        IncidentRecoveryBridge.recover_incident_on_verification_success(
            db=db_session,
            execution_id=exec_obj.id,
            workspace_id=ws_obj.id,
            cycle_id=cycle_obj.id,
            incident_id=inc_obj.id,
            worker_id="worker-rec-01",
            fencing_token=5,
        )

    assert "expired before completion" in str(exc_info.value)
    db_session.refresh(inc_obj)
    assert inc_obj.status == "remediating"


def test_failed_verification_cycle_never_recovers_incident(db_session, test_setup):
    """Failed verification cycle status or outcome FAIL never recovers incident."""
    exec_obj = test_setup["execution"]
    inc_obj = test_setup["incident"]
    cycle_obj = test_setup["cycle"]
    ws_obj = test_setup["workspace"]

    cycle_obj.status = "failed"
    cycle_obj.cycle_metadata = {"outcome": "FAIL", "error": "5xx increased"}
    db_session.commit()

    with pytest.raises(VerificationPreconditionError) as exc_info:
        IncidentRecoveryBridge.recover_incident_on_verification_success(
            db=db_session,
            execution_id=exec_obj.id,
            workspace_id=ws_obj.id,
            cycle_id=cycle_obj.id,
            incident_id=inc_obj.id,
            worker_id="worker-rec-01",
            fencing_token=5,
        )

    assert "status is 'failed'" in str(exc_info.value)
    db_session.refresh(inc_obj)
    assert inc_obj.status == "remediating"


def test_inconclusive_verification_cycle_never_recovers_incident(db_session, test_setup):
    """Uncertain / inconclusive verification cycle never recovers incident."""
    exec_obj = test_setup["execution"]
    inc_obj = test_setup["incident"]
    cycle_obj = test_setup["cycle"]
    ws_obj = test_setup["workspace"]

    cycle_obj.status = "uncertain"
    cycle_obj.cycle_metadata = {"outcome": "INCONCLUSIVE", "reason": "Broker unavailable"}
    db_session.commit()

    with pytest.raises(VerificationPreconditionError) as exc_info:
        IncidentRecoveryBridge.recover_incident_on_verification_success(
            db=db_session,
            execution_id=exec_obj.id,
            workspace_id=ws_obj.id,
            cycle_id=cycle_obj.id,
            incident_id=inc_obj.id,
            worker_id="worker-rec-01",
            fencing_token=5,
        )

    assert "status is 'uncertain'" in str(exc_info.value)
    db_session.refresh(inc_obj)
    assert inc_obj.status == "remediating"


def test_missing_baseline_probe_rejection(db_session, test_setup):
    """Rejects recovery if Probe 1 is not a passed baseline probe."""
    exec_obj = test_setup["execution"]
    inc_obj = test_setup["incident"]
    cycle_obj = test_setup["cycle"]
    ws_obj = test_setup["workspace"]

    # Mark probe 1 as failed
    probe1 = (
        db_session.query(VerificationProbeResult)
        .filter_by(cycle_id=cycle_obj.id, probe_number=1)
        .first()
    )
    probe1.passed = False
    probe1.status = "failed"
    db_session.commit()

    with pytest.raises(VerificationPreconditionError) as exc_info:
        IncidentRecoveryBridge.recover_incident_on_verification_success(
            db=db_session,
            execution_id=exec_obj.id,
            workspace_id=ws_obj.id,
            cycle_id=cycle_obj.id,
            incident_id=inc_obj.id,
            worker_id="worker-rec-01",
            fencing_token=5,
        )

    assert "Probe 1 is not a passed baseline probe" in str(exc_info.value)
    db_session.refresh(inc_obj)
    assert inc_obj.status == "remediating"


def test_insufficient_consecutive_passing_probes_rejection(db_session, test_setup):
    """Rejects recovery if required consecutive passes are not met."""
    exec_obj = test_setup["execution"]
    inc_obj = test_setup["incident"]
    cycle_obj = test_setup["cycle"]
    ws_obj = test_setup["workspace"]

    # Probe 3 failed (flapping: passes were 1, then reset)
    probe3 = (
        db_session.query(VerificationProbeResult)
        .filter_by(cycle_id=cycle_obj.id, probe_number=3)
        .first()
    )
    probe3.passed = False
    probe3.status = "failed"
    db_session.commit()

    with pytest.raises(VerificationPreconditionError) as exc_info:
        IncidentRecoveryBridge.recover_incident_on_verification_success(
            db=db_session,
            execution_id=exec_obj.id,
            workspace_id=ws_obj.id,
            cycle_id=cycle_obj.id,
            incident_id=inc_obj.id,
            worker_id="worker-rec-01",
            fencing_token=5,
        )

    assert "probe sequence validation failed" in str(exc_info.value)
    db_session.refresh(inc_obj)
    assert inc_obj.status == "remediating"


def test_closed_incident_is_never_overwritten(db_session, test_setup):
    """Terminal 'closed' incident can never be recovered or overwritten."""
    exec_obj = test_setup["execution"]
    inc_obj = test_setup["incident"]
    cycle_obj = test_setup["cycle"]
    ws_obj = test_setup["workspace"]

    inc_obj.status = "closed"
    inc_obj.closed_at = datetime.now(timezone.utc)
    db_session.commit()

    with pytest.raises(PreconditionFailedError) as exc_info:
        IncidentRecoveryBridge.recover_incident_on_verification_success(
            db=db_session,
            execution_id=exec_obj.id,
            workspace_id=ws_obj.id,
            cycle_id=cycle_obj.id,
            incident_id=inc_obj.id,
            worker_id="worker-rec-01",
            fencing_token=5,
        )

    assert "already closed and terminal" in str(exc_info.value)
    db_session.refresh(inc_obj)
    assert inc_obj.status == "closed"


def test_duplicate_finalization_is_idempotent(db_session, test_setup):
    """Repeated finalization with identical valid parameters is a clean idempotent no-op."""
    exec_obj = test_setup["execution"]
    inc_obj = test_setup["incident"]
    cycle_obj = test_setup["cycle"]
    ws_obj = test_setup["workspace"]

    # First call: performs atomic mutation
    res1_exec, res1_inc = IncidentRecoveryBridge.recover_incident_on_verification_success(
        db=db_session,
        execution_id=exec_obj.id,
        workspace_id=ws_obj.id,
        cycle_id=cycle_obj.id,
        incident_id=inc_obj.id,
        worker_id="worker-rec-01",
        fencing_token=5,
        auto_commit=True,
    )
    assert res1_exec.status == ExecutionState.VERIFIED.value
    assert res1_inc.status == "recovered"

    exec_event_count_1 = (
        db_session.query(ExecutionEvent)
        .filter_by(execution_id=exec_obj.id, event_type="verified")
        .count()
    )
    inc_event_count_1 = (
        db_session.query(IncidentEvent)
        .filter_by(incident_id=inc_obj.id, event_type="verification")
        .count()
    )
    assert exec_event_count_1 == 1
    assert inc_event_count_1 == 1

    # Second call: clean idempotent no-op
    res2_exec, res2_inc = IncidentRecoveryBridge.recover_incident_on_verification_success(
        db=db_session,
        execution_id=exec_obj.id,
        workspace_id=ws_obj.id,
        cycle_id=cycle_obj.id,
        incident_id=inc_obj.id,
        worker_id="worker-rec-01",
        fencing_token=5,
        auto_commit=True,
    )
    assert res2_exec.status == ExecutionState.VERIFIED.value
    assert res2_inc.status == "recovered"

    # Event counts MUST NOT increase
    exec_event_count_2 = (
        db_session.query(ExecutionEvent)
        .filter_by(execution_id=exec_obj.id, event_type="verified")
        .count()
    )
    inc_event_count_2 = (
        db_session.query(IncidentEvent)
        .filter_by(incident_id=inc_obj.id, event_type="verification")
        .count()
    )
    assert exec_event_count_2 == 1
    assert inc_event_count_2 == 1


def test_idempotent_duplicate_with_conflicting_incident_rejected(db_session, test_setup):
    """Already-verified execution rejects conflicting incident parameter."""
    exec_obj = test_setup["execution"]
    inc_obj = test_setup["incident"]
    cycle_obj = test_setup["cycle"]
    ws_obj = test_setup["workspace"]

    # First call verifies
    IncidentRecoveryBridge.recover_incident_on_verification_success(
        db=db_session,
        execution_id=exec_obj.id,
        workspace_id=ws_obj.id,
        cycle_id=cycle_obj.id,
        incident_id=inc_obj.id,
        worker_id="worker-rec-01",
        fencing_token=5,
        auto_commit=True,
    )

    alien_inc_id = str(uuid.uuid4())
    with pytest.raises(IncidentAssociationMismatchError):
        IncidentRecoveryBridge.recover_incident_on_verification_success(
            db=db_session,
            execution_id=exec_obj.id,
            workspace_id=ws_obj.id,
            cycle_id=cycle_obj.id,
            incident_id=alien_inc_id,
            worker_id="worker-rec-01",
            fencing_token=5,
        )


def test_end_to_end_verification_cycle_engine_with_recovery(db_session, test_setup):
    """End-to-end integration: PostExecutionVerificationEngine with recover_incident=True."""
    exec_obj = test_setup["execution"]
    inc_obj = test_setup["incident"]
    ws_obj = test_setup["workspace"]
    svc_obj = test_setup["service"]

    # Reset execution to verification_pending and fresh cycle_number=2
    exec_obj.status = ExecutionState.VERIFICATION_PENDING.value
    exec_obj.verification_status = "pending"
    db_session.commit()

    runner = SafeVerificationTestRunner()
    engine = PostExecutionVerificationEngine(runner=runner)

    summary = engine.run_verification_cycle(
        db=db_session,
        execution_id=exec_obj.id,
        workspace_id=ws_obj.id,
        service=svc_obj,
        cycle_number=2,
        probes_required=3,
        timeout_seconds=30,
        worker_id="worker-rec-01",
        fencing_token=5,
        recover_incident=True,
    )

    assert summary.outcome == VerificationOutcome.PASS
    assert summary.consecutive_passes == 3

    db_session.refresh(exec_obj)
    db_session.refresh(inc_obj)

    assert exec_obj.status == ExecutionState.VERIFIED.value
    assert exec_obj.verification_status == "verified"
    assert inc_obj.status == "recovered"
    assert inc_obj.recovered_at is not None

    # Check that incident event was persisted
    inc_event = (
        db_session.query(IncidentEvent)
        .filter_by(incident_id=inc_obj.id, event_type="verification")
        .first()
    )
    assert inc_event is not None
    assert "Incident marked recovered" in inc_event.message


def test_end_to_end_verification_cycle_engine_failed_cycle_incident_untouched(db_session, test_setup):
    """End-to-end integration: failed cycle does NOT recover incident even with recover_incident=True."""
    exec_obj = test_setup["execution"]
    inc_obj = test_setup["incident"]
    ws_obj = test_setup["workspace"]
    svc_obj = test_setup["service"]

    # Reset execution
    exec_obj.status = ExecutionState.VERIFICATION_PENDING.value
    exec_obj.verification_status = "pending"
    db_session.commit()

    # Runner that fails on probe #2
    runner = SafeVerificationTestRunner(failure_on_probe=2)
    engine = PostExecutionVerificationEngine(runner=runner)

    summary = engine.run_verification_cycle(
        db=db_session,
        execution_id=exec_obj.id,
        workspace_id=ws_obj.id,
        service=svc_obj,
        cycle_number=3,
        probes_required=3,
        timeout_seconds=30,
        worker_id="worker-rec-01",
        fencing_token=5,
        recover_incident=True,
    )

    assert summary.outcome == VerificationOutcome.FAIL

    db_session.refresh(exec_obj)
    db_session.refresh(inc_obj)

    assert exec_obj.status == ExecutionState.VERIFICATION_FAILED.value
    # Invariant: incident remains active, NOT recovered
    assert inc_obj.status == "remediating"
    assert inc_obj.recovered_at is None
