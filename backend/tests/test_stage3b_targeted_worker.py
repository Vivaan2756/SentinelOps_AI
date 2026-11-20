"""Tests for Stage 3B Targeted Single-Execution Worker Mode.

Validates that:
1. Target execution is claimed and processed exclusively.
2. Second queued execution is never claimed, locked, or touched in one-shot mode.
3. Missing target exits safely without claiming any other job.
4. Invalid/unapproved/expired approval exits safely without selecting another job.
5. Parameter/action/service/workspace tampering is rejected in preflight.
6. Duplicate claims against an active lease are prevented.
7. Fencing token increments only through legitimate lease acquisition.
8. One-shot mode terminates after exactly one execution.
9. Normal worker continuous mode remains unchanged.
"""

import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

import pytest

from app.execution.broker import BrokerExecuteRequest, BrokerExecuteResponse
from app.execution.manager import RemediationExecutionManager
from app.execution.manifest_signer import generate_and_sign_execution_manifest
from app.execution.runner import ExecutionResult, ExecutionRunnerInterface
from app.execution.state_machine import ExecutionState
from app.execution.verification import PostExecutionVerificationEngine
from app.execution.worker import DurableExecutionWorker
from app.models.incident import Incident
from app.models.remediation import (
    PolicyDecision,
    RemediationApproval,
    RemediationExecution,
)
from app.models.service import Service
from app.models.user import User
from app.models.workspace import Workspace


class MockBrokerRunner(ExecutionRunnerInterface):
    """Mock execution runner for safe, isolated tests without real container mutations."""

    def __init__(self, exit_code: int = 0):
        self.exit_code = exit_code
        self.call_count = 0
        self.dispatched_actions = []
        self.dispatched_execution_ids = []

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
        self.dispatched_execution_ids.append(execution_id)
        return ExecutionResult(
            exit_code=self.exit_code,
            duration_ms=25,
            stdout="Remediation mock completed successfully.",
            stderr="",
            output_data={"status": "restored"},
        )


@pytest.fixture
def test_setup(db_session):
    """Set up baseline workspace, user, service, and incident."""
    now_utc = datetime.now(timezone.utc)
    ws = Workspace(
        id=str(uuid.uuid4()),
        name="Targeted Worker Test Workspace",
        slug=f"tw-test-{uuid.uuid4().hex[:6]}",
    )
    db_session.add(ws)

    user = User(
        id=str(uuid.uuid4()),
        email=f"tester-{uuid.uuid4().hex[:6]}@sentinelops.local",
        full_name="Targeted Worker Tester",
        hashed_password="not-a-real-hash",
        is_active=True,
    )
    db_session.add(user)

    svc = Service(
        id=str(uuid.uuid4()),
        workspace_id=ws.id,
        name="Order API Demo",
        environment="development",
        execution_policy="demo",
        is_active=True,
        health_check_url="http://localhost:8001/health",
    )
    db_session.add(svc)

    inc = Incident(
        id=str(uuid.uuid4()),
        workspace_id=ws.id,
        service_id=svc.id,
        title="Order API Demo Failure",
        severity="high",
        status="investigating",
        trigger="manual_demo_failure",
    )
    db_session.add(inc)

    dec = PolicyDecision(
        id=str(uuid.uuid4()),
        workspace_id=ws.id,
        user_id=user.id,
        action_id="restore_order_api_demo",
        target_service_id=svc.id,
        risk_level="medium",
        decision="approved",
        decision_reason="Testing targeted worker mode",
        policy_version="v1.0",
        validated_parameters={"service_id": svc.id},
    )
    db_session.add(dec)
    db_session.commit()

    return {
        "workspace": ws,
        "user": user,
        "service": svc,
        "incident": inc,
        "decision": dec,
    }


def _create_approval(db_session, setup, *, status="approved", is_expired=False, params=None):
    now_utc = datetime.now(timezone.utc)
    expires_at = now_utc - timedelta(hours=1) if is_expired else now_utc + timedelta(hours=2)
    params = params if params is not None else {"service_id": setup["service"].id}

    appr = RemediationApproval(
        id=str(uuid.uuid4()),
        workspace_id=setup["workspace"].id,
        incident_id=setup["incident"].id,
        policy_decision_id=setup["decision"].id,
        action_id="restore_order_api_demo",
        target_service_id=setup["service"].id,
        validated_parameters=params,
        risk_level="medium",
        approval_status=status,
        requested_by=setup["user"].id,
        requested_at=now_utc - timedelta(minutes=10),
        reviewed_by=setup["user"].id if status == "approved" else None,
        reviewed_at=now_utc - timedelta(minutes=5) if status == "approved" else None,
        expires_at=expires_at,
    )
    db_session.add(appr)
    db_session.commit()
    return appr


def _create_execution(db_session, setup, approval, *, status="queued", params=None, triggered_delta_seconds=0):
    now_utc = datetime.now(timezone.utc) + timedelta(seconds=triggered_delta_seconds)
    params = params if params is not None else {"service_id": setup["service"].id}
    exec_id = str(uuid.uuid4())

    manifest, manifest_signature, manifest_digest = generate_and_sign_execution_manifest(
        execution_id=exec_id,
        approval=approval,
        service=setup["service"],
    )

    exc = RemediationExecution(
        id=exec_id,
        workspace_id=setup["workspace"].id,
        approval_id=approval.id,
        incident_id=setup["incident"].id,
        action_id="restore_order_api_demo",
        target_service_id=setup["service"].id,
        approved_parameters=params,
        status=status,
        fencing_token=0,
        attempt_count=0,
        max_attempts=1,
        idempotency_key=f"idemp-{uuid.uuid4().hex[:12]}",
        triggered_by=setup["user"].id,
        triggered_at=now_utc,
        created_at=now_utc,
        updated_at=now_utc,
        manifest_id=manifest.manifest_id,
        authorization_manifest=manifest.model_dump(),
        manifest_signature=manifest_signature,
        manifest_digest=manifest_digest,
        manifest_key_id=manifest.key_id,
        manifest_expires_at=datetime.fromtimestamp(manifest.expires_at, tz=timezone.utc),
    )
    db_session.add(exc)
    db_session.commit()
    return exc


# ============================================================================
# Test Cases
# ============================================================================

def test_targeted_claim_selects_target_execution_only(db_session, test_setup):
    """Confirm SQL-level execution_id filter selects ONLY target execution and ignores second queued job."""
    appr1 = _create_approval(db_session, test_setup)
    appr2 = _create_approval(db_session, test_setup)

    # Exec 1 triggered earlier, Exec 2 triggered later
    exec1 = _create_execution(db_session, test_setup, appr1, triggered_delta_seconds=0)
    exec2 = _create_execution(db_session, test_setup, appr2, triggered_delta_seconds=10)

    # Claim specifically Exec 2 (even though Exec 1 was triggered earlier)
    claimed = RemediationExecutionManager.claim_next_execution(
        worker_id="worker-test-1",
        execution_id=exec2.id,
        db=db_session,
    )

    assert claimed is not None
    assert claimed.id == exec2.id
    assert claimed.status == ExecutionState.VALIDATING.value
    assert claimed.fencing_token == 1
    assert claimed.attempt_count == 1
    assert claimed.locked_by == "worker-test-1"

    # Confirm Exec 1 remains 100% untouched
    db_session.refresh(exec1)
    assert exec1.status == ExecutionState.QUEUED.value
    assert exec1.fencing_token == 0
    assert exec1.attempt_count == 0
    assert exec1.locked_by is None


def test_second_queued_execution_never_selected_by_targeted_worker(db_session, test_setup):
    """Confirm DurableExecutionWorker.run_target() executes target and never touches the second queued job."""
    appr1 = _create_approval(db_session, test_setup)
    appr2 = _create_approval(db_session, test_setup)

    target_exec = _create_execution(db_session, test_setup, appr1, triggered_delta_seconds=0)
    second_exec = _create_execution(db_session, test_setup, appr2, triggered_delta_seconds=10)

    mock_runner = MockBrokerRunner()
    worker = DurableExecutionWorker(
        worker_id="worker-target-test",
        runner=mock_runner,
        db=db_session,
        enable_verification=False,
    )

    result_id = worker.run_target(target_exec.id)

    assert result_id == target_exec.id
    assert mock_runner.call_count == 1
    assert mock_runner.dispatched_execution_ids == [target_exec.id]

    # Target completed
    db_session.refresh(target_exec)
    assert target_exec.status == ExecutionState.EXECUTION_SUCCEEDED.value
    assert target_exec.fencing_token == 1
    assert target_exec.attempt_count == 1

    # Second queued job remains untouched in 'queued' state
    db_session.refresh(second_exec)
    assert second_exec.status == ExecutionState.QUEUED.value
    assert second_exec.fencing_token == 0
    assert second_exec.attempt_count == 0
    assert second_exec.locked_by is None


def test_missing_target_exits_safely(db_session, test_setup):
    """Confirm querying a non-existent target ID returns None and leaves existing jobs untouched."""
    appr = _create_approval(db_session, test_setup)
    existing_exec = _create_execution(db_session, test_setup, appr)

    mock_runner = MockBrokerRunner()
    worker = DurableExecutionWorker(
        worker_id="worker-missing-test",
        runner=mock_runner,
        db=db_session,
        enable_verification=False,
    )

    non_existent_id = str(uuid.uuid4())
    result_id = worker.run_target(non_existent_id)

    assert result_id is None
    assert mock_runner.call_count == 0

    # Existing execution was not touched
    db_session.refresh(existing_exec)
    assert existing_exec.status == ExecutionState.QUEUED.value
    assert existing_exec.fencing_token == 0


def test_unapproved_approval_fails_preflight_without_dispatch(db_session, test_setup):
    """Confirm execution whose approval is pending (unapproved) fails preflight without dispatching."""
    unapproved_appr = _create_approval(db_session, test_setup, status="pending")
    appr_valid = _create_approval(db_session, test_setup, status="approved")

    target_exec = _create_execution(db_session, test_setup, unapproved_appr)
    second_exec = _create_execution(db_session, test_setup, appr_valid)

    mock_runner = MockBrokerRunner()
    worker = DurableExecutionWorker(
        worker_id="worker-unapproved-test",
        runner=mock_runner,
        db=db_session,
        enable_verification=False,
    )

    result_id = worker.run_target(target_exec.id)

    assert result_id == target_exec.id
    assert mock_runner.call_count == 0  # Preflight failed, zero dispatches

    db_session.refresh(target_exec)
    assert target_exec.status == ExecutionState.EXECUTION_FAILED.value
    assert target_exec.error_category == "approval_not_approved"

    # Second execution remains queued
    db_session.refresh(second_exec)
    assert second_exec.status == ExecutionState.QUEUED.value


def test_expired_approval_fails_preflight_without_dispatch(db_session, test_setup):
    """Confirm execution whose approval has expired fails preflight without dispatching."""
    expired_appr = _create_approval(db_session, test_setup, status="approved", is_expired=True)
    target_exec = _create_execution(db_session, test_setup, expired_appr)

    mock_runner = MockBrokerRunner()
    worker = DurableExecutionWorker(
        worker_id="worker-expired-test",
        runner=mock_runner,
        db=db_session,
        enable_verification=False,
    )

    result_id = worker.run_target(target_exec.id)

    assert result_id == target_exec.id
    assert mock_runner.call_count == 0

    db_session.refresh(target_exec)
    assert target_exec.status == ExecutionState.EXECUTION_FAILED.value
    assert target_exec.error_category == "approval_expired"


def test_parameter_tampering_rejected_in_preflight(db_session, test_setup):
    """Confirm that if execution approved_parameters differ from approval validated_parameters, preflight fails."""
    appr = _create_approval(db_session, test_setup, params={"service_id": test_setup["service"].id})
    tampered_exec = _create_execution(
        db_session,
        test_setup,
        appr,
        params={"service_id": test_setup["service"].id, "malicious_flag": True},
    )

    mock_runner = MockBrokerRunner()
    worker = DurableExecutionWorker(
        worker_id="worker-tamper-test",
        runner=mock_runner,
        db=db_session,
        enable_verification=False,
    )

    result_id = worker.run_target(tampered_exec.id)

    assert result_id == tampered_exec.id
    assert mock_runner.call_count == 0  # Zero dispatches

    db_session.refresh(tampered_exec)
    assert tampered_exec.status == ExecutionState.EXECUTION_FAILED.value
    assert tampered_exec.error_category == "parameters_tampered"


def test_duplicate_claim_prevented_while_active_lease_held(db_session, test_setup):
    """Confirm that while worker 1 holds an active lease, worker 2 cannot claim the target execution."""
    appr = _create_approval(db_session, test_setup)
    target_exec = _create_execution(db_session, test_setup, appr)

    # Worker 1 claims lease
    claimed1 = RemediationExecutionManager.claim_next_execution(
        worker_id="worker-1",
        execution_id=target_exec.id,
        lease_seconds=90,
        db=db_session,
    )
    assert claimed1 is not None
    assert claimed1.fencing_token == 1

    # Worker 2 attempts targeted claim on same ID
    claimed2 = RemediationExecutionManager.claim_next_execution(
        worker_id="worker-2",
        execution_id=target_exec.id,
        lease_seconds=90,
        db=db_session,
    )
    assert claimed2 is None  # Active lease held by worker 1; claim rejected


def test_one_shot_mode_terminates_after_one_execution(db_session, test_setup):
    """Confirm that worker initialized in one-shot mode terminates its run loop after 1 execution."""
    appr1 = _create_approval(db_session, test_setup)
    appr2 = _create_approval(db_session, test_setup)

    target_exec = _create_execution(db_session, test_setup, appr1, triggered_delta_seconds=0)
    second_exec = _create_execution(db_session, test_setup, appr2, triggered_delta_seconds=10)

    mock_runner = MockBrokerRunner()
    worker = DurableExecutionWorker(
        worker_id="worker-oneshot-loop-test",
        runner=mock_runner,
        db=db_session,
        target_execution_id=target_exec.id,
        one_shot=True,
        enable_verification=False,
    )

    # Start worker in thread
    worker.start()

    # Wait for thread to finish (should terminate immediately after 1 execution)
    timeout = 5.0
    start = time.time()
    while worker.is_running and (time.time() - start) < timeout:
        time.sleep(0.1)

    assert not worker.is_running, "Worker thread should terminate cleanly in one-shot mode"
    assert mock_runner.call_count == 1
    assert mock_runner.dispatched_execution_ids == [target_exec.id]

    # Target succeeded
    db_session.refresh(target_exec)
    assert target_exec.status == ExecutionState.EXECUTION_SUCCEEDED.value

    # Second queued job remains completely untouched
    db_session.refresh(second_exec)
    assert second_exec.status == ExecutionState.QUEUED.value
    assert second_exec.fencing_token == 0


def test_normal_worker_mode_remains_unchanged(db_session, test_setup):
    """Confirm that with one_shot=False and target_execution_id=None, normal FIFO queue polling works."""
    appr1 = _create_approval(db_session, test_setup)
    appr2 = _create_approval(db_session, test_setup)

    exec1 = _create_execution(db_session, test_setup, appr1, triggered_delta_seconds=0)
    exec2 = _create_execution(db_session, test_setup, appr2, triggered_delta_seconds=10)

    mock_runner = MockBrokerRunner()
    worker = DurableExecutionWorker(
        worker_id="worker-normal-mode-test",
        runner=mock_runner,
        db=db_session,
        one_shot=False,
        target_execution_id=None,
        enable_verification=False,
    )

    # Standard run_once claims earliest queued job
    claimed_id = worker.run_once()
    assert claimed_id == exec1.id
    assert mock_runner.call_count == 1

    db_session.refresh(exec1)
    assert exec1.status == ExecutionState.EXECUTION_SUCCEEDED.value

    # Exec 2 is still queued
    db_session.refresh(exec2)
    assert exec2.status == ExecutionState.QUEUED.value

    # Second standard run_once claims next queued job
    claimed_id_2 = worker.run_once()
    assert claimed_id_2 == exec2.id
    assert mock_runner.call_count == 2

    db_session.refresh(exec2)
    assert exec2.status == ExecutionState.EXECUTION_SUCCEEDED.value


def test_worker_initialization_with_real_verification_engine_contract(db_session):
    """Confirm DurableExecutionWorker initializes correctly with default PostExecutionVerificationEngine contract."""
    mock_runner = MockBrokerRunner()
    worker = DurableExecutionWorker(
        worker_id="worker-real-engine-init-test",
        runner=mock_runner,
        db=db_session,
        enable_verification=True,
        enable_coordinator=False,
    )
    assert worker.verification_engine is not None
    assert isinstance(worker.verification_engine, PostExecutionVerificationEngine)
    assert worker.verification_engine._runner == mock_runner
    assert hasattr(worker.verification_engine, "run_verification_cycle")

    # Also confirm targeted one-shot worker initialization with real verification engine
    targeted_worker = DurableExecutionWorker(
        worker_id="worker-targeted-real-engine-test",
        runner=mock_runner,
        db=db_session,
        target_execution_id="some-test-exec-id",
        one_shot=True,
        enable_verification=True,
        enable_coordinator=False,
    )
    assert targeted_worker.verification_engine is not None
    assert isinstance(targeted_worker.verification_engine, PostExecutionVerificationEngine)
    assert targeted_worker.target_execution_id == "some-test-exec-id"
    assert targeted_worker.one_shot is True
