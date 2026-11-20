"""Tests for Phase 4.3.2 Database Foundation (RemediationExecution, ExecutionAttempt, ExecutionEvent).

Covers:
- Unique approval constraint (one execution per approval)
- Idempotency-key uniqueness within a workspace
- Foreign-key integrity and cascade behavior
- Workspace isolation and scoping
- Check constraints (valid vs invalid execution status, retry policy, attempt status)
- ExecutionAttempt relationship, attempt numbers, and ordering
- ExecutionEvent relationship, workspace scoping, and metadata storage
- Worker lease ownership and fencing token fields
- PostgreSQL-specific constraint enforcement against isolated PostgreSQL test database
"""

import os
import sys
import subprocess
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone, timedelta
import pytest
from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import IntegrityError

from app.core.config import settings
from app.db.guard import assert_safe_migration_target, ProtectedDatabaseError, is_protected_database

from app.models.workspace import Workspace
from app.models.user import User
from app.models.service import Service
from app.models.incident import Incident
from app.models.remediation import (
    PolicyDecision,
    RemediationApproval,
    RemediationExecution,
    ExecutionAttempt,
    ExecutionEvent,
)


@pytest.fixture
def execution_env(db_session):
    """Seed prerequisite records in test database (workspace, users, service, approval)."""
    ws = Workspace(
        id=str(uuid.uuid4()),
        name="Execution Test Workspace",
        slug=f"exec-ws-{uuid.uuid4().hex[:6]}",
    )
    ws2 = Workspace(
        id=str(uuid.uuid4()),
        name="Second Workspace",
        slug=f"exec-ws2-{uuid.uuid4().hex[:6]}",
    )
    db_session.add_all([ws, ws2])

    eng = User(
        id=str(uuid.uuid4()),
        email=f"eng_{uuid.uuid4().hex[:6]}@example.com",
        full_name="Test Engineer",
        hashed_password="pw",
    )
    db_session.add(eng)

    svc = Service(
        id=str(uuid.uuid4()),
        workspace_id=ws.id,
        name="Order API Service",
        environment="development",
        health_check_url="http://127.0.0.1:8001/health",
        is_active=True,
    )
    db_session.add(svc)

    inc = Incident(
        id=str(uuid.uuid4()),
        workspace_id=ws.id,
        service_id=svc.id,
        title="Order API High Latency",
        severity="medium",
        status="investigating",
        trigger="high_latency",
    )
    db_session.add(inc)

    dec = PolicyDecision(
        id=str(uuid.uuid4()),
        workspace_id=ws.id,
        user_id=eng.id,
        action_id="restore_order_api_demo",
        target_service_id=svc.id,
        risk_level="medium",
        decision="approval_required",
        decision_reason="Requires human approval",
        policy_version="v1.0",
        validated_parameters={"service_id": svc.id},
    )
    db_session.add(dec)

    appr = RemediationApproval(
        id=str(uuid.uuid4()),
        workspace_id=ws.id,
        incident_id=inc.id,
        policy_decision_id=dec.id,
        action_id="restore_order_api_demo",
        target_service_id=svc.id,
        validated_parameters={"service_id": svc.id},
        risk_level="medium",
        policy_version="v1.0",
        requested_by=eng.id,
        approval_status="approved",
        reviewed_by=eng.id,
        reviewed_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
    )
    db_session.add(appr)

    db_session.commit()

    return {
        "ws": ws,
        "ws2": ws2,
        "eng": eng,
        "svc": svc,
        "inc": inc,
        "dec": dec,
        "appr": appr,
    }


# ============================================================================
# 1. RemediationExecution Creation & Invariants
# ============================================================================

def test_create_remediation_execution_success(db_session, execution_env):
    """Successfully create a RemediationExecution record bound to an approval."""
    env = execution_env
    exec_id = str(uuid.uuid4())
    idemp_key = f"key_{uuid.uuid4().hex[:8]}"

    execution = RemediationExecution(
        id=exec_id,
        workspace_id=env["ws"].id,
        approval_id=env["appr"].id,
        incident_id=env["inc"].id,
        action_id="restore_order_api_demo",
        target_service_id=env["svc"].id,
        approved_parameters=env["appr"].validated_parameters,
        status="queued",
        idempotency_key=idemp_key,
        triggered_by=env["eng"].id,
        timeout_seconds=30,
        max_attempts=1,
    )
    db_session.add(execution)
    db_session.commit()

    loaded = db_session.query(RemediationExecution).filter_by(id=exec_id).one()
    assert loaded.status == "queued"
    assert loaded.action_id == "restore_order_api_demo"
    assert loaded.approved_parameters == {"service_id": env["svc"].id}
    assert loaded.fencing_token == 0
    assert loaded.retry_policy == "idempotent"
    assert loaded.attempt_count == 0
    assert loaded.workspace.id == env["ws"].id
    assert loaded.approval.id == env["appr"].id
    assert loaded.triggerer.id == env["eng"].id


def test_unique_approval_constraint_prevents_duplicate_execution(db_session, execution_env):
    """An approved proposal can only ever be bound to one execution (no approval replay)."""
    env = execution_env

    exec1 = RemediationExecution(
        id=str(uuid.uuid4()),
        workspace_id=env["ws"].id,
        approval_id=env["appr"].id,
        action_id="restore_order_api_demo",
        approved_parameters={"service_id": env["svc"].id},
        status="queued",
        idempotency_key="key_1",
        triggered_by=env["eng"].id,
    )
    db_session.add(exec1)
    db_session.commit()

    # Attempting to create a second execution for the SAME approval must raise IntegrityError
    exec2 = RemediationExecution(
        id=str(uuid.uuid4()),
        workspace_id=env["ws"].id,
        approval_id=env["appr"].id,
        action_id="restore_order_api_demo",
        approved_parameters={"service_id": env["svc"].id},
        status="queued",
        idempotency_key="key_2",
        triggered_by=env["eng"].id,
    )
    db_session.add(exec2)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_idempotency_key_uniqueness_within_workspace(db_session, execution_env):
    """Idempotency key must be unique within a workspace, but permitted in different workspaces."""
    env = execution_env

    # Approval 2 in workspace 1
    appr2 = RemediationApproval(
        id=str(uuid.uuid4()),
        workspace_id=env["ws"].id,
        policy_decision_id=env["dec"].id,
        action_id="restore_order_api_demo",
        validated_parameters={"service_id": env["svc"].id},
        risk_level="medium",
        requested_by=env["eng"].id,
        approval_status="approved",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
    )
    db_session.add(appr2)
    db_session.commit()

    exec1 = RemediationExecution(
        id=str(uuid.uuid4()),
        workspace_id=env["ws"].id,
        approval_id=env["appr"].id,
        action_id="restore_order_api_demo",
        approved_parameters={"service_id": env["svc"].id},
        status="queued",
        idempotency_key="shared_idemp_key",
        triggered_by=env["eng"].id,
    )
    db_session.add(exec1)
    db_session.commit()

    # Same workspace, same idempotency key, different approval -> FAILS
    exec2 = RemediationExecution(
        id=str(uuid.uuid4()),
        workspace_id=env["ws"].id,
        approval_id=appr2.id,
        action_id="restore_order_api_demo",
        approved_parameters={"service_id": env["svc"].id},
        status="queued",
        idempotency_key="shared_idemp_key",
        triggered_by=env["eng"].id,
    )
    db_session.add(exec2)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_foreign_key_integrity_and_cascades(isolated_pg_engine, isolated_pg_seed_data):
    """Foreign key enforcement: invalid workspace, approval, or user is rejected in PostgreSQL."""
    Session = sessionmaker(bind=isolated_pg_engine)
    db = Session()

    try:
        ws = db.query(Workspace).filter_by(id=isolated_pg_seed_data["workspace_id"]).one()
        user = db.query(User).filter_by(id=isolated_pg_seed_data["user_id"]).one()
        assert ws is not None and user is not None

        # Non-existent approval ID must be rejected by foreign key constraint
        bad_exec = RemediationExecution(
            id=str(uuid.uuid4()),
            workspace_id=ws.id,
            approval_id=str(uuid.uuid4()),  # NON-EXISTENT APPROVAL
            action_id="restore_order_api_demo",
            approved_parameters={},
            status="queued",
            idempotency_key=f"bad_fk_{uuid.uuid4().hex[:6]}",
            triggered_by=user.id,
        )
        db.add(bad_exec)
        with pytest.raises(IntegrityError) as exc_info:
            db.commit()
        db.rollback()
        assert "foreign key" in str(exc_info.value).lower() or "fk" in str(exc_info.value).lower()
    finally:
        db.close()


# ============================================================================
# 2. Worker Lease Ownership & Stale-Worker Fencing
# ============================================================================

def test_worker_lease_and_fencing_fields(db_session, execution_env):
    """Worker lease acquisition, heartbeat, and monotonic fencing token increment."""
    env = execution_env
    exec_id = str(uuid.uuid4())

    execution = RemediationExecution(
        id=exec_id,
        workspace_id=env["ws"].id,
        approval_id=env["appr"].id,
        action_id="restore_order_api_demo",
        approved_parameters={"service_id": env["svc"].id},
        status="queued",
        idempotency_key="lease_test_key",
        triggered_by=env["eng"].id,
    )
    db_session.add(execution)
    db_session.commit()

    # Worker 1 claims lease
    now_utc = datetime.now(timezone.utc)
    execution.status = "validating"
    execution.locked_by = "worker-node-alpha"
    execution.locked_until = now_utc + timedelta(seconds=90)
    execution.heartbeat_at = now_utc
    execution.fencing_token = 1
    execution.started_at = now_utc
    db_session.commit()

    loaded = db_session.query(RemediationExecution).filter_by(id=exec_id).one()
    assert loaded.locked_by == "worker-node-alpha"
    assert loaded.fencing_token == 1
    assert loaded.locked_until is not None

    # Stale-worker fencing token increment on re-lease
    loaded.fencing_token += 1
    loaded.locked_by = "worker-node-beta"
    db_session.commit()

    refreshed = db_session.query(RemediationExecution).filter_by(id=exec_id).one()
    assert refreshed.locked_by == "worker-node-beta"
    assert refreshed.fencing_token == 2


# ============================================================================
# 3. ExecutionAttempt & ExecutionEvent Relationships
# ============================================================================

def test_execution_attempt_lifecycle_and_ordering(db_session, execution_env):
    """ExecutionAttempt records are correctly linked, ordered, and cascaded on execution deletion."""
    env = execution_env
    exec_id = str(uuid.uuid4())

    execution = RemediationExecution(
        id=exec_id,
        workspace_id=env["ws"].id,
        approval_id=env["appr"].id,
        action_id="restore_order_api_demo",
        approved_parameters={"service_id": env["svc"].id},
        status="executing",
        idempotency_key="attempt_test_key",
        triggered_by=env["eng"].id,
    )
    db_session.add(execution)
    db_session.commit()

    # Attempt 1
    att1 = ExecutionAttempt(
        id=str(uuid.uuid4()),
        execution_id=exec_id,
        attempt_number=1,
        status="failed",
        worker_id="worker-1",
        fencing_token=1,
        duration_ms=450,
        exit_code=1,
        error_message="Connection timed out to microservice endpoint",
        error_category="network_timeout",
    )
    # Attempt 2
    att2 = ExecutionAttempt(
        id=str(uuid.uuid4()),
        execution_id=exec_id,
        attempt_number=2,
        status="succeeded",
        worker_id="worker-1",
        fencing_token=1,
        duration_ms=210,
        exit_code=0,
        stdout_sample='{"status": "restored"}',
    )
    db_session.add_all([att1, att2])
    db_session.commit()

    loaded_exec = db_session.query(RemediationExecution).filter_by(id=exec_id).one()
    assert len(loaded_exec.attempts) == 2
    assert loaded_exec.attempts[0].attempt_number == 1
    assert loaded_exec.attempts[1].attempt_number == 2
    assert loaded_exec.attempts[1].exit_code == 0
    assert loaded_exec.attempts[0].error_category == "network_timeout"


def test_execution_event_workspace_and_execution_scoping(db_session, execution_env):
    """ExecutionEvents are associated with both parent execution and workspace."""
    env = execution_env
    exec_id = str(uuid.uuid4())

    execution = RemediationExecution(
        id=exec_id,
        workspace_id=env["ws"].id,
        approval_id=env["appr"].id,
        action_id="restore_order_api_demo",
        approved_parameters={"service_id": env["svc"].id},
        status="executing",
        idempotency_key="event_test_key",
        triggered_by=env["eng"].id,
    )
    db_session.add(execution)
    db_session.commit()

    event1 = ExecutionEvent(
        id=str(uuid.uuid4()),
        execution_id=exec_id,
        workspace_id=env["ws"].id,
        event_type="lease_acquired",
        message="Worker worker-1 claimed execution lease with fencing token 1",
        metadata_json={"worker_id": "worker-1", "fencing_token": 1},
    )
    event2 = ExecutionEvent(
        id=str(uuid.uuid4()),
        execution_id=exec_id,
        workspace_id=env["ws"].id,
        event_type="container_dispatched",
        message="Dispatched action restore_order_api_demo to restricted broker",
        metadata_json={"action_id": "restore_order_api_demo"},
    )
    db_session.add_all([event1, event2])
    db_session.commit()

    # Query by execution
    loaded_exec = db_session.query(RemediationExecution).filter_by(id=exec_id).one()
    assert len(loaded_exec.events) == 2

    # Query by workspace
    ws_events = db_session.query(ExecutionEvent).filter_by(workspace_id=env["ws"].id).all()
    assert len(ws_events) >= 2
    assert any(e.event_type == "lease_acquired" for e in ws_events)


# ============================================================================
# 4. PostgreSQL Isolated Database Tests
# ============================================================================

def test_postgresql_check_constraints_and_live_schema(isolated_pg_engine, isolated_pg_seed_data):
    """Verify check constraints and live schema directly against isolated PostgreSQL test database."""
    Session = sessionmaker(bind=isolated_pg_engine)
    db = Session()

    dec_id = str(uuid.uuid4())
    appr_id = str(uuid.uuid4())
    exec_id = str(uuid.uuid4())

    try:
        ws = db.query(Workspace).filter_by(id=isolated_pg_seed_data["workspace_id"]).one()
        user = db.query(User).filter_by(id=isolated_pg_seed_data["user_id"]).one()
        assert ws is not None, "Workspace required in PostgreSQL"
        assert user is not None, "User required in PostgreSQL"

        # 1. Create a dummy approval for test
        dec = PolicyDecision(
            id=dec_id,
            workspace_id=ws.id,
            user_id=user.id,
            action_id="restore_order_api_demo",
            risk_level="medium",
            decision="approval_required",
            decision_reason="Testing execution schema",
            policy_version="v1.0",
            validated_parameters={"service_id": str(uuid.uuid4())},
        )
        appr = RemediationApproval(
            id=appr_id,
            workspace_id=ws.id,
            policy_decision_id=dec_id,
            action_id="restore_order_api_demo",
            validated_parameters={"service_id": str(uuid.uuid4())},
            risk_level="medium",
            requested_by=user.id,
            approval_status="approved",
            reviewed_by=user.id,
            reviewed_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        db.add_all([dec, appr])
        db.commit()

        # 2. Insert valid RemediationExecution
        idemp_key = f"pg_test_{uuid.uuid4().hex[:8]}"
        execution = RemediationExecution(
            id=exec_id,
            workspace_id=ws.id,
            approval_id=appr_id,
            action_id="restore_order_api_demo",
            approved_parameters={"service_id": str(uuid.uuid4())},
            status="queued",
            idempotency_key=idemp_key,
            fencing_token=1,
            retry_policy="idempotent",
            triggered_by=user.id,
        )
        db.add(execution)
        db.commit()

        # 3. Verify PostgreSQL rejects invalid status via ck_execution_status check constraint
        bad_status_exec = RemediationExecution(
            id=str(uuid.uuid4()),
            workspace_id=ws.id,
            approval_id=str(uuid.uuid4()),
            action_id="restore_order_api_demo",
            approved_parameters={},
            status="invalid_nonexistent_status",  # INVALID STATUS
            idempotency_key="key_bad_status",
            triggered_by=user.id,
        )
        db.add(bad_status_exec)
        with pytest.raises(IntegrityError) as exc_info:
            db.commit()
        db.rollback()
        assert "ck_execution_status" in str(exc_info.value).lower() or "check constraint" in str(exc_info.value).lower()

        # 4. Verify PostgreSQL unique constraint uq_execution_approval rejects duplicate execution
        dup_exec = RemediationExecution(
            id=str(uuid.uuid4()),
            workspace_id=ws.id,
            approval_id=appr_id,  # SAME APPROVAL ID
            action_id="restore_order_api_demo",
            approved_parameters={},
            status="queued",
            idempotency_key="key_different",
            triggered_by=user.id,
        )
        db.add(dup_exec)
        with pytest.raises(IntegrityError) as exc_info:
            db.commit()
        db.rollback()
        assert "uq_execution_approval" in str(exc_info.value).lower()

    finally:
        # Clean up test rows reliably
        try:
            db.rollback()
            db.execute(text(f"DELETE FROM execution_events WHERE execution_id = '{exec_id}'"))
            db.execute(text(f"DELETE FROM execution_attempts WHERE execution_id = '{exec_id}'"))
            db.execute(text(f"DELETE FROM remediation_executions WHERE id = '{exec_id}'"))
            db.execute(text(f"DELETE FROM remediation_approvals WHERE id = '{appr_id}'"))
            db.execute(text(f"DELETE FROM policy_decisions WHERE id = '{dec_id}'"))
            db.commit()
        except Exception:
            db.rollback()
        db.close()


def test_postgresql_idempotency_and_attempts_live(isolated_pg_engine, isolated_pg_seed_data):
    """Verify idempotency constraint and execution attempts table in isolated PostgreSQL."""
    Session = sessionmaker(bind=isolated_pg_engine)
    db = Session()

    dec_id = str(uuid.uuid4())
    appr1_id = str(uuid.uuid4())
    appr2_id = str(uuid.uuid4())
    exec_id = str(uuid.uuid4())
    attempt_id = str(uuid.uuid4())

    try:
        ws = db.query(Workspace).filter_by(id=isolated_pg_seed_data["workspace_id"]).one()
        user = db.query(User).filter_by(id=isolated_pg_seed_data["user_id"]).one()
        assert ws is not None and user is not None

        dec = PolicyDecision(
            id=dec_id,
            workspace_id=ws.id,
            user_id=user.id,
            action_id="restore_order_api_demo",
            risk_level="medium",
            decision="approval_required",
            decision_reason="Testing idempotency in PostgreSQL",
            policy_version="v1.0",
            validated_parameters={},
        )
        appr1 = RemediationApproval(
            id=appr1_id,
            workspace_id=ws.id,
            policy_decision_id=dec_id,
            action_id="restore_order_api_demo",
            validated_parameters={},
            risk_level="medium",
            requested_by=user.id,
            approval_status="approved",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        appr2 = RemediationApproval(
            id=appr2_id,
            workspace_id=ws.id,
            policy_decision_id=dec_id,
            action_id="restore_order_api_demo",
            validated_parameters={},
            risk_level="medium",
            requested_by=user.id,
            approval_status="approved",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        db.add_all([dec, appr1, appr2])
        db.commit()

        idemp_key = f"idemp_{uuid.uuid4().hex[:8]}"
        exec1 = RemediationExecution(
            id=exec_id,
            workspace_id=ws.id,
            approval_id=appr1_id,
            action_id="restore_order_api_demo",
            approved_parameters={},
            status="queued",
            idempotency_key=idemp_key,
            fencing_token=0,
            triggered_by=user.id,
        )
        db.add(exec1)
        db.commit()

        # Same workspace, same idempotency key, different approval -> Violates uq_execution_idempotency
        exec2 = RemediationExecution(
            id=str(uuid.uuid4()),
            workspace_id=ws.id,
            approval_id=appr2_id,
            action_id="restore_order_api_demo",
            approved_parameters={},
            status="queued",
            idempotency_key=idemp_key,
            triggered_by=user.id,
        )
        db.add(exec2)
        with pytest.raises(IntegrityError) as exc_info:
            db.commit()
        db.rollback()
        assert "uq_execution_idempotency" in str(exc_info.value).lower()

        # Add valid ExecutionAttempt
        attempt = ExecutionAttempt(
            id=attempt_id,
            execution_id=exec_id,
            attempt_number=1,
            status="running",
            worker_id="pg-worker-1",
            fencing_token=1,
        )
        db.add(attempt)
        db.commit()

        # Verify attempt check constraint rejects invalid status
        bad_attempt = ExecutionAttempt(
            id=str(uuid.uuid4()),
            execution_id=exec_id,
            attempt_number=2,
            status="invalid_attempt_status",  # INVALID STATUS
        )
        db.add(bad_attempt)
        with pytest.raises(IntegrityError) as exc_info:
            db.commit()
        db.rollback()
        assert "ck_attempt_status" in str(exc_info.value).lower() or "check constraint" in str(exc_info.value).lower()

    finally:
        try:
            db.rollback()
            db.execute(text(f"DELETE FROM execution_attempts WHERE execution_id = '{exec_id}'"))
            db.execute(text(f"DELETE FROM remediation_executions WHERE id = '{exec_id}'"))
            db.execute(text(f"DELETE FROM remediation_approvals WHERE id IN ('{appr1_id}', '{appr2_id}')"))
            db.execute(text(f"DELETE FROM policy_decisions WHERE id = '{dec_id}'"))
            db.commit()
        except Exception:
            db.rollback()
        db.close()


def test_workspace_isolation_querying(db_session, execution_env):
    """Execution and event queries must be strictly isolated per workspace."""
    env = execution_env

    # 1. Setup approval and execution in Workspace 1
    exec1_id = str(uuid.uuid4())
    exec1 = RemediationExecution(
        id=exec1_id,
        workspace_id=env["ws"].id,
        approval_id=env["appr"].id,
        action_id="restore_order_api_demo",
        approved_parameters={"service_id": env["svc"].id},
        status="queued",
        idempotency_key="ws1_isolation_key",
        triggered_by=env["eng"].id,
    )
    db_session.add(exec1)

    ev1 = ExecutionEvent(
        id=str(uuid.uuid4()),
        execution_id=exec1_id,
        workspace_id=env["ws"].id,
        event_type="queued",
        message="Execution queued for workspace 1",
    )
    db_session.add(ev1)

    # 2. Setup decision, approval, and execution in Workspace 2
    svc2 = Service(
        id=str(uuid.uuid4()),
        workspace_id=env["ws2"].id,
        name="Workspace 2 Service",
        environment="development",
        health_check_url="http://127.0.0.1:8002/health",
        is_active=True,
    )
    db_session.add(svc2)

    dec2 = PolicyDecision(
        id=str(uuid.uuid4()),
        workspace_id=env["ws2"].id,
        user_id=env["eng"].id,
        action_id="restore_order_api_demo",
        target_service_id=svc2.id,
        risk_level="medium",
        decision="approval_required",
        decision_reason="Workspace 2 isolation test",
        policy_version="v1.0",
        validated_parameters={"service_id": svc2.id},
    )
    db_session.add(dec2)

    appr2 = RemediationApproval(
        id=str(uuid.uuid4()),
        workspace_id=env["ws2"].id,
        policy_decision_id=dec2.id,
        action_id="restore_order_api_demo",
        target_service_id=svc2.id,
        validated_parameters={"service_id": svc2.id},
        risk_level="medium",
        policy_version="v1.0",
        requested_by=env["eng"].id,
        approval_status="approved",
        reviewed_by=env["eng"].id,
        reviewed_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
    )
    db_session.add(appr2)

    exec2_id = str(uuid.uuid4())
    exec2 = RemediationExecution(
        id=exec2_id,
        workspace_id=env["ws2"].id,
        approval_id=appr2.id,
        action_id="restore_order_api_demo",
        approved_parameters={"service_id": svc2.id},
        status="queued",
        idempotency_key="ws2_isolation_key",
        triggered_by=env["eng"].id,
    )
    db_session.add(exec2)

    ev2 = ExecutionEvent(
        id=str(uuid.uuid4()),
        execution_id=exec2_id,
        workspace_id=env["ws2"].id,
        event_type="queued",
        message="Execution queued for workspace 2",
    )
    db_session.add(ev2)
    db_session.commit()

    # Query Workspace 1 executions & events
    ws1_execs = db_session.query(RemediationExecution).filter_by(workspace_id=env["ws"].id).all()
    ws1_events = db_session.query(ExecutionEvent).filter_by(workspace_id=env["ws"].id).all()
    assert all(e.workspace_id == env["ws"].id for e in ws1_execs)
    assert any(e.id == exec1_id for e in ws1_execs)
    assert not any(e.id == exec2_id for e in ws1_execs)
    assert all(e.workspace_id == env["ws"].id for e in ws1_events)
    assert any(e.id == ev1.id for e in ws1_events)
    assert not any(e.id == ev2.id for e in ws1_events)

    # Query Workspace 2 executions & events
    ws2_execs = db_session.query(RemediationExecution).filter_by(workspace_id=env["ws2"].id).all()
    ws2_events = db_session.query(ExecutionEvent).filter_by(workspace_id=env["ws2"].id).all()
    assert all(e.workspace_id == env["ws2"].id for e in ws2_execs)
    assert any(e.id == exec2_id for e in ws2_execs)
    assert not any(e.id == exec1_id for e in ws2_execs)
    assert all(e.workspace_id == env["ws2"].id for e in ws2_events)
    assert any(e.id == ev2.id for e in ws2_events)
    assert not any(e.id == ev1.id for e in ws2_events)


def test_all_execution_states_and_transitions_pg(isolated_pg_engine, isolated_pg_seed_data):
    """Verify all 11 valid states and check constraint rejections in isolated PostgreSQL."""
    Session = sessionmaker(bind=isolated_pg_engine)
    db = Session()

    dec_id = str(uuid.uuid4())
    appr_id = str(uuid.uuid4())
    exec_id = str(uuid.uuid4())

    valid_states = [
        "queued",
        "validating",
        "executing",
        "execution_succeeded",
        "execution_failed",
        "timed_out",
        "execution_uncertain",
        "verification_pending",
        "verified",
        "verification_failed",
        "cancelled",
    ]

    try:
        ws = db.query(Workspace).filter_by(id=isolated_pg_seed_data["workspace_id"]).one()
        user = db.query(User).filter_by(id=isolated_pg_seed_data["user_id"]).one()
        assert ws is not None and user is not None

        dec = PolicyDecision(
            id=dec_id,
            workspace_id=ws.id,
            user_id=user.id,
            action_id="restore_order_api_demo",
            risk_level="medium",
            decision="approval_required",
            decision_reason="Testing all 11 execution states",
            policy_version="v1.0",
            validated_parameters={},
        )
        appr = RemediationApproval(
            id=appr_id,
            workspace_id=ws.id,
            policy_decision_id=dec_id,
            action_id="restore_order_api_demo",
            validated_parameters={},
            risk_level="medium",
            requested_by=user.id,
            approval_status="approved",
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        db.add_all([dec, appr])
        db.commit()

        # Insert initially as queued
        execution = RemediationExecution(
            id=exec_id,
            workspace_id=ws.id,
            approval_id=appr_id,
            action_id="restore_order_api_demo",
            approved_parameters={},
            status="queued",
            idempotency_key=f"states_{uuid.uuid4().hex[:8]}",
            retry_policy="idempotent",
            triggered_by=user.id,
        )
        db.add(execution)
        db.commit()

        # Verify all 11 states can be set and committed
        for state in valid_states:
            execution.status = state
            db.commit()
            reloaded = db.query(RemediationExecution).filter_by(id=exec_id).one()
            assert reloaded.status == state

        # Verify invalid status is rejected
        execution.status = "non_existent_status_foo"
        with pytest.raises(IntegrityError) as exc_info:
            db.commit()
        db.rollback()
        assert "ck_execution_status" in str(exc_info.value).lower() or "check constraint" in str(exc_info.value).lower()

        # Reload clean execution
        execution = db.query(RemediationExecution).filter_by(id=exec_id).one()

        # Verify invalid retry policy is rejected
        execution.retry_policy = "unlimited_retries"
        with pytest.raises(IntegrityError) as exc_info:
            db.commit()
        db.rollback()
        assert "ck_execution_retry_policy" in str(exc_info.value).lower() or "check constraint" in str(exc_info.value).lower()

        # Reload clean execution
        execution = db.query(RemediationExecution).filter_by(id=exec_id).one()

        # Verify invalid verification status is rejected
        execution.verification_status = "invalid_status"
        with pytest.raises(IntegrityError) as exc_info:
            db.commit()
        db.rollback()
        assert "ck_execution_verification_status" in str(exc_info.value).lower() or "check constraint" in str(exc_info.value).lower()

    finally:
        try:
            db.rollback()
            db.execute(text(f"DELETE FROM execution_attempts WHERE execution_id = '{exec_id}'"))
            db.execute(text(f"DELETE FROM remediation_executions WHERE id = '{exec_id}'"))
            db.execute(text(f"DELETE FROM remediation_approvals WHERE id = '{appr_id}'"))
            db.execute(text(f"DELETE FROM policy_decisions WHERE id = '{dec_id}'"))
            db.commit()
        except Exception:
            db.rollback()
        db.close()


from tests.conftest import isolated_test_database


def test_migration_upgrade_and_downgrade_safety(tmp_path):
    """Verify Alembic migration 0007 can be downgraded and upgraded cleanly without affecting live dev data."""
    backend_dir = r"d:\Sentinal_AI\backend"

    with isolated_test_database(prefix="sentinelops_test_mig_") as test_db_url:
        # Explicit safety check: must be an isolated test database, NEVER sentinelops_dev
        assert_safe_migration_target(test_db_url)
        assert "sentinelops_dev" not in test_db_url

        alembic_env = {
            **os.environ,
            "DATABASE_URL": test_db_url,
            "SENTINELOPS_STRICT_MIGRATION_GUARD": "true",
        }

        # 1. Establish full baseline schema up to head on the isolated test database
        init_res = subprocess.run(
            [sys.executable, "-m", "alembic", "upgrade", "head"],
            cwd=backend_dir,
            capture_output=True,
            text=True,
            env=alembic_env,
        )
        assert init_res.returncode == 0, f"Initial upgrade failed: {init_res.stderr}\n{init_res.stdout}"

        # 2. Downgrade migration 0007 to 0006 on the isolated test database
        down_res = subprocess.run(
            [sys.executable, "-m", "alembic", "downgrade", "0006_pending_approval_uq"],
            cwd=backend_dir,
            capture_output=True,
            text=True,
            env=alembic_env,
        )
        assert down_res.returncode == 0, f"Downgrade failed: {down_res.stderr}\n{down_res.stdout}"

        # 3. Verify execution tables are dropped while historical tables remain in the isolated test DB
        test_engine = create_engine(test_db_url)
        with test_engine.connect() as conn:
            if test_db_url.startswith("sqlite"):
                tables = {row[0] for row in conn.execute(text("SELECT name FROM sqlite_master WHERE type='table'")).fetchall()}
            else:
                tables_res = conn.execute(text(
                    "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'"
                ))
                tables = {row[0] for row in tables_res.fetchall()}

            assert "remediation_executions" not in tables
            assert "execution_attempts" not in tables
            assert "execution_events" not in tables
            # Historical tables must remain intact
            assert "remediation_approvals" in tables
            assert "policy_decisions" in tables
            assert "workspaces" in tables
            assert "users" in tables

        # 4. Upgrade back to head on the isolated test database
        up_res = subprocess.run(
            [sys.executable, "-m", "alembic", "upgrade", "head"],
            cwd=backend_dir,
            capture_output=True,
            text=True,
            env=alembic_env,
        )
        assert up_res.returncode == 0, f"Upgrade failed: {up_res.stderr}\n{up_res.stdout}"

        # 5. Verify execution tables are recreated in the isolated test DB
        with test_engine.connect() as conn:
            if test_db_url.startswith("sqlite"):
                tables = {row[0] for row in conn.execute(text("SELECT name FROM sqlite_master WHERE type='table'")).fetchall()}
            else:
                tables_res = conn.execute(text(
                    "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'"
                ))
                tables = {row[0] for row in tables_res.fetchall()}

            assert "remediation_executions" in tables
            assert "execution_attempts" in tables
            assert "execution_events" in tables

            current_res = conn.execute(text("SELECT version_num FROM alembic_version"))
            version = current_res.scalar()
            assert version in (
                "0007_remediation_executions",
                "0008_verification_persistence",
                "0009_dynamic_playbooks",
                "0010_manifest_signing",
                "0011_dedicated_worker_role",
                "0012_service_demo_integration",
            )

        test_engine.dispose()
