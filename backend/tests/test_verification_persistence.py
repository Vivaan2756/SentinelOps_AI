"""Unit and Persistence Tests for Phase 4.3.6 Milestone A: Verification Persistence.

Validates:
1. Verification cycle creation and lifecycle fields (cycle_number, started_at, deadline_at, fencing_token).
2. Deterministic probe identity generation.
3. Duplicate consistency:
   - Identical duplicate probe: idempotent no-op (same record returned, no duplicate row).
   - Conflicting duplicate probe: raises ConflictingProbePayloadError (409 Conflict).
4. Workspace isolation and cross-workspace access rejection.
5. Execution relationships and cascade delete integrity.
6. Probe output sanitization (credential and token scrubbing).
7. Probe status validation and check constraints.
8. Cycle stats tracking (probes_passed and probes_failed counts).
9. Alembic migration 0008 reversible upgrade and downgrade on an isolated engine.
"""

import copy
import os
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from app.execution.exceptions import (
    ConflictingCyclePayloadError,
    ConflictingProbePayloadError,
    CrossWorkspaceViolationError,
    VerificationCycleNotFoundError,
)
from app.execution.manager import RemediationExecutionManager
from app.execution.verification_persistence import (
    VerificationPersistenceService,
    generate_deterministic_probe_id,
)
from app.models.remediation import (
    PolicyDecision,
    RemediationApproval,
    RemediationExecution,
)
from app.models.service import Service
from app.models.user import User
from app.models.verification import VerificationCycle, VerificationProbeResult
from app.models.workspace import Workspace, WorkspaceMembership


@pytest.fixture
def test_setup(db_session: Session):
    """Set up user, workspace, service, approval, and execution for testing."""
    now_utc = datetime.now(timezone.utc)
    user = User(
        id=str(uuid.uuid4()),
        email=f"tester-{uuid.uuid4().hex[:6]}@sentinelops.local",
        full_name="Verification Tester",
        hashed_password="hashed_val_here",
        is_active=True,
    )
    db_session.add(user)

    workspace = Workspace(
        id=str(uuid.uuid4()),
        name="Verification Test Ops",
        slug=f"verif-ops-{uuid.uuid4().hex[:6]}",
    )
    db_session.add(workspace)
    db_session.flush()

    membership = WorkspaceMembership(
        workspace_id=workspace.id,
        user_id=user.id,
        role="engineer",
    )
    db_session.add(membership)

    service = Service(
        id=str(uuid.uuid4()),
        workspace_id=workspace.id,
        name="Order API Test",
        environment="development",
        health_check_url="http://127.0.0.1:8001/health",
        is_active=True,
    )
    db_session.add(service)

    decision = PolicyDecision(
        id=str(uuid.uuid4()),
        workspace_id=workspace.id,
        user_id=user.id,
        action_id="restore_order_api_demo",
        target_service_id=service.id,
        risk_level="medium",
        decision="approval_required",
        decision_reason="Pre-flight test",
        policy_version="v1.0",
        validated_parameters={"service_name": "order-api"},
        timestamp=now_utc,
    )
    db_session.add(decision)

    approval = RemediationApproval(
        id=str(uuid.uuid4()),
        workspace_id=workspace.id,
        policy_decision_id=decision.id,
        action_id="restore_order_api_demo",
        target_service_id=service.id,
        validated_parameters={"service_name": "order-api"},
        risk_level="medium",
        policy_version="v1.0",
        requested_by=user.id,
        approval_status="approved",
        requested_at=now_utc,
        reviewed_by=user.id,
        reviewed_at=now_utc,
        expires_at=now_utc + timedelta(hours=1),
    )
    db_session.add(approval)
    db_session.flush()

    execution = RemediationExecution(
        id=str(uuid.uuid4()),
        workspace_id=workspace.id,
        approval_id=approval.id,
        action_id="restore_order_api_demo",
        target_service_id=service.id,
        approved_parameters={"service_name": "order-api"},
        status="executing",
        idempotency_key=str(uuid.uuid4()),
        triggered_by=user.id,
        triggered_at=now_utc,
        timeout_seconds=30,
        fencing_token=5,
    )
    db_session.add(execution)
    db_session.commit()

    return {
        "user": user,
        "workspace": workspace,
        "service": service,
        "approval": approval,
        "execution": execution,
    }


def test_create_verification_cycle_success(db_session: Session, test_setup: dict):
    """Verify that a verification cycle is successfully created with correct attributes."""
    execution = test_setup["execution"]
    workspace = test_setup["workspace"]

    cycle = VerificationPersistenceService.create_or_get_verification_cycle(
        db=db_session,
        execution_id=execution.id,
        workspace_id=workspace.id,
        cycle_number=1,
        timeout_seconds=30,
        fencing_token=5,
        verifying_worker_id="worker-test-01",
        probes_required=3,
        cycle_metadata={"trigger": "post_remediation_success"},
    )
    db_session.commit()

    assert cycle.id is not None
    assert cycle.execution_id == execution.id
    assert cycle.workspace_id == workspace.id
    assert cycle.cycle_number == 1
    assert cycle.status == "pending"
    assert cycle.fencing_token == 5
    assert cycle.verifying_worker_id == "worker-test-01"
    assert cycle.probes_required == 3
    assert cycle.probes_passed == 0
    assert cycle.probes_failed == 0
    assert cycle.deadline_at > cycle.started_at
    assert (cycle.deadline_at - cycle.started_at).total_seconds() == pytest.approx(30, abs=1)
    assert cycle.cycle_metadata == {"trigger": "post_remediation_success"}


def test_create_verification_cycle_idempotent(db_session: Session, test_setup: dict):
    """Verify that re-requesting an existing verification cycle is an idempotent no-op."""
    execution = test_setup["execution"]
    workspace = test_setup["workspace"]

    cycle1 = VerificationPersistenceService.create_or_get_verification_cycle(
        db=db_session,
        execution_id=execution.id,
        workspace_id=workspace.id,
        cycle_number=1,
        fencing_token=5,
    )
    db_session.commit()

    # Re-call with identical parameters
    cycle2 = VerificationPersistenceService.create_or_get_verification_cycle(
        db=db_session,
        execution_id=execution.id,
        workspace_id=workspace.id,
        cycle_number=1,
        fencing_token=5,
    )

    assert cycle1.id == cycle2.id
    # Assert only 1 cycle row exists for this execution in DB
    count = (
        db_session.query(VerificationCycle)
        .filter(VerificationCycle.execution_id == execution.id)
        .count()
    )
    assert count == 1


def test_create_verification_cycle_conflicting_fencing_token(db_session: Session, test_setup: dict):
    """Verify that attempting to create a cycle with a conflicting fencing token raises ConflictingCyclePayloadError."""
    execution = test_setup["execution"]
    workspace = test_setup["workspace"]

    VerificationPersistenceService.create_or_get_verification_cycle(
        db=db_session,
        execution_id=execution.id,
        workspace_id=workspace.id,
        cycle_number=1,
        fencing_token=5,
    )
    db_session.commit()

    with pytest.raises(ConflictingCyclePayloadError) as exc_info:
        VerificationPersistenceService.create_or_get_verification_cycle(
            db=db_session,
            execution_id=execution.id,
            workspace_id=workspace.id,
            cycle_number=1,
            fencing_token=6,  # Conflicting token
        )
    assert "Conflicting fencing token" in str(exc_info.value.detail)


def test_create_verification_cycle_workspace_mismatch(db_session: Session, test_setup: dict):
    """Verify that attempting to create a cycle with a foreign workspace_id raises CrossWorkspaceViolationError."""
    execution = test_setup["execution"]
    foreign_workspace_id = str(uuid.uuid4())

    with pytest.raises(CrossWorkspaceViolationError) as exc_info:
        VerificationPersistenceService.create_or_get_verification_cycle(
            db=db_session,
            execution_id=execution.id,
            workspace_id=foreign_workspace_id,
            cycle_number=1,
        )
    assert "Cross-workspace violation" in str(exc_info.value.detail)


def test_create_verification_cycle_nonexistent_execution(db_session: Session, test_setup: dict):
    """Verify that creating a cycle for a non-existent execution raises ValueError."""
    fake_exec_id = str(uuid.uuid4())
    workspace = test_setup["workspace"]

    with pytest.raises(ValueError) as exc_info:
        VerificationPersistenceService.create_or_get_verification_cycle(
            db=db_session,
            execution_id=fake_exec_id,
            workspace_id=workspace.id,
            cycle_number=1,
        )
    assert "does not exist" in str(exc_info.value)


def test_record_probe_result_success(db_session: Session, test_setup: dict):
    """Verify recording a passing probe generates deterministic ID and increments probes_passed."""
    execution = test_setup["execution"]
    workspace = test_setup["workspace"]

    cycle = VerificationPersistenceService.create_or_get_verification_cycle(
        db=db_session,
        execution_id=execution.id,
        workspace_id=workspace.id,
        cycle_number=1,
    )
    db_session.commit()

    expected_probe_id = generate_deterministic_probe_id(execution.id, 1, 1)

    probe = VerificationPersistenceService.record_probe_result(
        db=db_session,
        cycle_id=cycle.id,
        probe_number=1,
        probe_type="http_health",
        target_url="http://127.0.0.1:8001/health",
        passed=True,
        status="passed",
        status_code=200,
        latency_ms=12.45,
        probe_output={"status": "healthy", "service": "order-api"},
    )
    db_session.commit()

    assert probe.id == expected_probe_id
    assert probe.cycle_id == cycle.id
    assert probe.execution_id == execution.id
    assert probe.workspace_id == workspace.id
    assert probe.probe_number == 1
    assert probe.passed is True
    assert probe.status == "passed"
    assert probe.status_code == 200
    assert probe.latency_ms == 12.45
    assert probe.probe_output == {"status": "healthy", "service": "order-api"}

    # Assert cycle counters
    db_session.refresh(cycle)
    assert cycle.probes_passed == 1
    assert cycle.probes_failed == 0


def test_record_probe_result_failure_increments_probes_failed(db_session: Session, test_setup: dict):
    """Verify recording a failed probe increments probes_failed."""
    execution = test_setup["execution"]
    workspace = test_setup["workspace"]

    cycle = VerificationPersistenceService.create_or_get_verification_cycle(
        db=db_session,
        execution_id=execution.id,
        workspace_id=workspace.id,
        cycle_number=1,
    )
    db_session.commit()

    probe = VerificationPersistenceService.record_probe_result(
        db=db_session,
        cycle_id=cycle.id,
        probe_number=1,
        probe_type="http_health",
        target_url="http://127.0.0.1:8001/health",
        passed=False,
        status="failed",
        status_code=500,
        latency_ms=45.0,
        error_message="HTTP 500 Database timeout",
    )
    db_session.commit()

    assert probe.passed is False
    assert probe.status == "failed"
    assert probe.status_code == 500
    assert probe.error_message == "HTTP 500 Database timeout"

    db_session.refresh(cycle)
    assert cycle.probes_passed == 0
    assert cycle.probes_failed == 1


def test_deterministic_probe_id_identical_duplicate_is_idempotent(db_session: Session, test_setup: dict):
    """Verify identical duplicate probe payload is an idempotent no-op without double-counting."""
    execution = test_setup["execution"]
    workspace = test_setup["workspace"]

    cycle = VerificationPersistenceService.create_or_get_verification_cycle(
        db=db_session,
        execution_id=execution.id,
        workspace_id=workspace.id,
        cycle_number=1,
    )
    db_session.commit()

    payload = {
        "cycle_id": cycle.id,
        "probe_number": 1,
        "probe_type": "http_health",
        "target_url": "http://127.0.0.1:8001/health",
        "passed": True,
        "status": "passed",
        "status_code": 200,
        "latency_ms": 15.0,
        "probe_output": {"status": "healthy"},
    }

    probe1 = VerificationPersistenceService.record_probe_result(db=db_session, **payload)
    db_session.commit()

    # Re-record identical probe
    probe2 = VerificationPersistenceService.record_probe_result(db=db_session, **payload)

    assert probe1.id == probe2.id
    # Assert only 1 probe row exists in database
    probe_count = (
        db_session.query(VerificationProbeResult)
        .filter(VerificationProbeResult.cycle_id == cycle.id)
        .count()
    )
    assert probe_count == 1

    # Assert cycle probes_passed count was not double incremented
    db_session.refresh(cycle)
    assert cycle.probes_passed == 1


def test_deterministic_probe_id_conflicting_duplicate_raises_error(db_session: Session, test_setup: dict):
    """Verify conflicting probe payload raises ConflictingProbePayloadError."""
    execution = test_setup["execution"]
    workspace = test_setup["workspace"]

    cycle = VerificationPersistenceService.create_or_get_verification_cycle(
        db=db_session,
        execution_id=execution.id,
        workspace_id=workspace.id,
        cycle_number=1,
    )
    db_session.commit()

    # First probe: passed=True, status=passed, code=200
    VerificationPersistenceService.record_probe_result(
        db=db_session,
        cycle_id=cycle.id,
        probe_number=1,
        probe_type="http_health",
        target_url="http://127.0.0.1:8001/health",
        passed=True,
        status="passed",
        status_code=200,
    )
    db_session.commit()

    # Second probe: same probe_number (1), but passed=False, status=failed, code=500
    with pytest.raises(ConflictingProbePayloadError) as exc_info:
        VerificationPersistenceService.record_probe_result(
            db=db_session,
            cycle_id=cycle.id,
            probe_number=1,
            probe_type="http_health",
            target_url="http://127.0.0.1:8001/health",
            passed=False,
            status="failed",
            status_code=500,
        )
    assert "Conflicting payload for probe" in str(exc_info.value.detail)


def test_probe_output_credential_sanitization(db_session: Session, test_setup: dict):
    """Verify sensitive patterns and secrets are sanitized before persistence in probe_output."""
    execution = test_setup["execution"]
    workspace = test_setup["workspace"]

    cycle = VerificationPersistenceService.create_or_get_verification_cycle(
        db=db_session,
        execution_id=execution.id,
        workspace_id=workspace.id,
        cycle_number=1,
    )
    db_session.commit()

    sensitive_output = {
        "status": "healthy",
        "authorization": "Bearer super-secret-jwt-token-12345",
        "password": "db_password_cleartext",
        "token": "api_key_xyz",
        "nested": {
            "api_key": "nested_secret_val",
            "normal_metric": 42.0,
        },
    }

    probe = VerificationPersistenceService.record_probe_result(
        db=db_session,
        cycle_id=cycle.id,
        probe_number=1,
        probe_type="http_health",
        target_url="http://127.0.0.1:8001/health",
        passed=True,
        status="passed",
        status_code=200,
        probe_output=sensitive_output,
    )
    db_session.commit()

    out = probe.probe_output
    assert out["authorization"] == "[REDACTED]"
    assert out["password"] == "[REDACTED]"
    assert out["token"] == "[REDACTED]"
    assert out["nested"]["api_key"] == "[REDACTED]"
    assert out["nested"]["normal_metric"] == 42.0


def test_invalid_probe_status_rejected(db_session: Session, test_setup: dict):
    """Verify invalid probe status strings are rejected before DB insertion."""
    execution = test_setup["execution"]
    workspace = test_setup["workspace"]

    cycle = VerificationPersistenceService.create_or_get_verification_cycle(
        db=db_session,
        execution_id=execution.id,
        workspace_id=workspace.id,
        cycle_number=1,
    )
    db_session.commit()

    with pytest.raises(ValueError) as exc_info:
        VerificationPersistenceService.record_probe_result(
            db=db_session,
            cycle_id=cycle.id,
            probe_number=1,
            probe_type="http_health",
            target_url="http://127.0.0.1:8001/health",
            passed=True,
            status="unknown_status_foo",
        )
    assert "Invalid probe status" in str(exc_info.value)


def test_get_and_list_probes_for_cycle(db_session: Session, test_setup: dict):
    """Verify listing probes returns all probe results in strict probe_number sequence."""
    execution = test_setup["execution"]
    workspace = test_setup["workspace"]

    cycle = VerificationPersistenceService.create_or_get_verification_cycle(
        db=db_session,
        execution_id=execution.id,
        workspace_id=workspace.id,
        cycle_number=1,
    )
    db_session.commit()

    # Insert probes 1, 2, 3
    for p_num in [1, 2, 3]:
        VerificationPersistenceService.record_probe_result(
            db=db_session,
            cycle_id=cycle.id,
            probe_number=p_num,
            probe_type="http_health",
            target_url="http://127.0.0.1:8001/health",
            passed=True,
            status="passed",
            status_code=200,
            latency_ms=10.0 * p_num,
        )
    db_session.commit()

    probes = VerificationPersistenceService.list_probes_for_cycle(
        db=db_session,
        cycle_id=cycle.id,
        workspace_id=workspace.id,
    )
    assert len(probes) == 3
    assert [p.probe_number for p in probes] == [1, 2, 3]


def test_workspace_isolation_on_get_and_list(db_session: Session, test_setup: dict):
    """Verify accessing a cycle with mismatched workspace raises CrossWorkspaceViolationError."""
    execution = test_setup["execution"]
    workspace = test_setup["workspace"]
    foreign_workspace_id = str(uuid.uuid4())

    cycle = VerificationPersistenceService.create_or_get_verification_cycle(
        db=db_session,
        execution_id=execution.id,
        workspace_id=workspace.id,
        cycle_number=1,
    )
    db_session.commit()

    with pytest.raises(CrossWorkspaceViolationError):
        VerificationPersistenceService.get_verification_cycle(
            db=db_session,
            cycle_id=cycle.id,
            workspace_id=foreign_workspace_id,
        )

    with pytest.raises(CrossWorkspaceViolationError):
        VerificationPersistenceService.list_probes_for_cycle(
            db=db_session,
            cycle_id=cycle.id,
            workspace_id=foreign_workspace_id,
        )


def test_execution_relationship_cascade_delete(db_session: Session, test_setup: dict):
    """Verify that deleting an execution cascades cleanly to verification cycles and probe results."""
    execution = test_setup["execution"]
    workspace = test_setup["workspace"]

    cycle = VerificationPersistenceService.create_or_get_verification_cycle(
        db=db_session,
        execution_id=execution.id,
        workspace_id=workspace.id,
        cycle_number=1,
    )
    VerificationPersistenceService.record_probe_result(
        db=db_session,
        cycle_id=cycle.id,
        probe_number=1,
        probe_type="http_health",
        target_url="http://127.0.0.1:8001/health",
        passed=True,
        status="passed",
        status_code=200,
    )
    db_session.commit()

    cycle_id = cycle.id
    probe_id = generate_deterministic_probe_id(execution.id, 1, 1)

    # Delete parent execution
    db_session.delete(execution)
    db_session.commit()

    # Assert cascade deletion
    assert db_session.query(VerificationCycle).filter(VerificationCycle.id == cycle_id).first() is None
    assert db_session.query(VerificationProbeResult).filter(VerificationProbeResult.id == probe_id).first() is None


def test_alembic_migration_0008_upgrade_and_downgrade_on_isolated_engine(tmp_path, monkeypatch):
    """Verify Alembic migration 0008 can be upgraded and downgraded cleanly on an isolated test database."""
    from alembic.config import Config
    from alembic import command
    from app.core.config import settings

    db_path = tmp_path / "isolated_migration_test.db"
    db_url = f"sqlite:///{db_path}"

    monkeypatch.setenv("DATABASE_URL", db_url)
    monkeypatch.setattr(settings, "DATABASE_URL", db_url)

    alembic_ini_path = r"d:\Sentinal_AI\backend\alembic.ini"
    alembic_cfg = Config(alembic_ini_path)
    alembic_cfg.set_main_option("sqlalchemy.url", db_url)
    alembic_cfg.set_main_option("script_location", r"d:\Sentinal_AI\backend\alembic")

    # 1. Upgrade to head (runs all migrations 0001 through 0008 on isolated SQLite)
    command.upgrade(alembic_cfg, "head")

    # Verify tables created
    test_eng = create_engine(db_url)
    with test_eng.connect() as conn:
        tables = {row[0] for row in conn.execute(text("SELECT name FROM sqlite_master WHERE type='table'")).fetchall()}
        assert "verification_cycles" in tables
        assert "verification_probe_results" in tables
        assert "remediation_executions" in tables

    # 2. Downgrade migration 0008 to 0007
    command.downgrade(alembic_cfg, "0007_remediation_executions")

    # Verify verification tables dropped while 0007 tables remain
    with test_eng.connect() as conn:
        tables_after_down = {row[0] for row in conn.execute(text("SELECT name FROM sqlite_master WHERE type='table'")).fetchall()}
        assert "verification_cycles" not in tables_after_down
        assert "verification_probe_results" not in tables_after_down
        # 0007 tables must still exist
        assert "remediation_executions" in tables_after_down
        assert "execution_attempts" in tables_after_down
        assert "execution_events" in tables_after_down

    # 3. Upgrade back to head cleanly
    command.upgrade(alembic_cfg, "head")
    with test_eng.connect() as conn:
        tables_reup = {row[0] for row in conn.execute(text("SELECT name FROM sqlite_master WHERE type='table'")).fetchall()}
        assert "verification_cycles" in tables_reup
        assert "verification_probe_results" in tables_reup
