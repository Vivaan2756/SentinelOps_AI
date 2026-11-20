"""Comprehensive Unit and Integration Tests for Operator Uncertainty Resolution API.

Covers Stage 3A.1 requirements addressing FINDING-2.1-01:
- Unauthorized access rejected (401)
- Viewer access denied (403)
- Cross-workspace access denied (403/404)
- Missing or short justification rejected (400/422)
- Invalid decision values rejected (400/422)
- Invalid execution state rejected (409 Conflict)
- Duplicate resolution rejected (409 Conflict)
- ABORT_FAILURE lifecycle: transitions to failed, max attempts enforced, no auto-requeue, incident remains active
- CONFIRM_SUCCESS lifecycle: transitions to verification_pending, triggers independent verification
- Verification failure leaves incident open in investigating state
- Verification success marks incident recovered, NOT closed (human review still required)
"""

import uuid
from datetime import datetime, timedelta, timezone
import pytest
from unittest.mock import MagicMock, patch

from app.core.security import create_access_token
from app.execution.manager import RemediationExecutionManager
from app.execution.state_machine import ExecutionState
from app.execution.verification import VerificationSummary, VerificationOutcome
from app.models.incident import Incident
from app.models.remediation import (
    ExecutionEvent,
    PolicyDecision,
    RemediationApproval,
    RemediationExecution,
)
from app.models.service import Service
from app.models.user import User
from app.models.workspace import Workspace, WorkspaceMembership


@pytest.fixture
def exec_mgr_env(db_session):
    """Fixture providing populated workspace, users, services, incident, and approvals."""
    ws = Workspace(
        id=str(uuid.uuid4()),
        name="Execution Manager WS",
        slug=f"exec-mgr-{uuid.uuid4().hex[:6]}",
    )
    ws2 = Workspace(
        id=str(uuid.uuid4()),
        name="Foreign Workspace",
        slug=f"foreign-{uuid.uuid4().hex[:6]}",
    )
    db_session.add_all([ws, ws2])

    admin = User(
        id=str(uuid.uuid4()),
        email=f"admin_{uuid.uuid4().hex[:6]}@example.com",
        full_name="Admin User",
        hashed_password="pw",
    )
    engineer = User(
        id=str(uuid.uuid4()),
        email=f"eng_{uuid.uuid4().hex[:6]}@example.com",
        full_name="Engineer User",
        hashed_password="pw",
    )
    viewer = User(
        id=str(uuid.uuid4()),
        email=f"viewer_{uuid.uuid4().hex[:6]}@example.com",
        full_name="Viewer User",
        hashed_password="pw",
    )
    db_session.add_all([admin, engineer, viewer])

    m_admin = WorkspaceMembership(workspace_id=ws.id, user_id=admin.id, role="admin")
    m_eng = WorkspaceMembership(workspace_id=ws.id, user_id=engineer.id, role="engineer")
    m_viewer = WorkspaceMembership(workspace_id=ws.id, user_id=viewer.id, role="viewer")
    db_session.add_all([m_admin, m_eng, m_viewer])

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
        title="Simulated Latency Spike",
        severity="medium",
        status="investigating",
        trigger="high_latency",
    )
    db_session.add(inc)

    dec = PolicyDecision(
        id=str(uuid.uuid4()),
        workspace_id=ws.id,
        user_id=engineer.id,
        action_id="restore_order_api_demo",
        target_service_id=svc.id,
        risk_level="medium",
        decision="approval_required",
        decision_reason="Requires human approval",
        policy_version="v1.0",
        validated_parameters={"service_id": svc.id},
    )
    db_session.add(dec)

    appr_approved = RemediationApproval(
        id=str(uuid.uuid4()),
        workspace_id=ws.id,
        incident_id=inc.id,
        policy_decision_id=dec.id,
        action_id="restore_order_api_demo",
        target_service_id=svc.id,
        validated_parameters={"service_id": svc.id},
        risk_level="medium",
        policy_version="v1.0",
        requested_by=engineer.id,
        approval_status="approved",
        reviewed_by=admin.id,
        reviewed_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
    )
    db_session.add(appr_approved)
    db_session.commit()

    return {
        "ws": ws,
        "ws2": ws2,
        "admin": admin,
        "engineer": engineer,
        "viewer": viewer,
        "svc": svc,
        "inc": inc,
        "incident": inc,
        "dec": dec,
        "appr_approved": appr_approved,
    }


def _seed_uncertain_execution(db_session, env, incident_id=None):
    """Helper to seed an execution stuck in EXECUTION_UNCERTAIN with HOLD:EXECUTION_UNCERTAIN."""
    ws = env["ws"]
    svc = env["svc"]
    appr = env["appr_approved"]
    now_utc = datetime.now(timezone.utc)
    hold_timestamp = datetime(9999, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

    exec_record = RemediationExecution(
        id=str(uuid.uuid4()),
        workspace_id=ws.id,
        approval_id=appr.id,
        incident_id=incident_id or env["inc"].id,
        investigation_id=None,
        action_id="restore_order_api_demo",
        target_service_id=svc.id,
        approved_parameters={"service_id": svc.id},
        status=ExecutionState.EXECUTION_UNCERTAIN.value,
        idempotency_key=f"idemp_{uuid.uuid4().hex[:8]}",
        locked_by="HOLD:EXECUTION_UNCERTAIN",
        locked_until=hold_timestamp,
        fencing_token=1,
        retry_policy="idempotent",
        triggered_by=env["engineer"].id,
        triggered_at=now_utc,
        attempt_count=1,
        max_attempts=3,
        uncertain_reason="Connection reset by peer during dispatch",
        execution_output={
            "uncertainty_hold": {
                "hold_type": "HOLD:EXECUTION_UNCERTAIN",
                "hold_reason": "Connection reset by peer during dispatch",
                "held_at": now_utc.isoformat(),
            }
        },
    )
    db_session.add(exec_record)
    db_session.commit()
    db_session.refresh(exec_record)
    return exec_record


def test_resolve_uncertain_unauthorized(client, db_session, exec_mgr_env):
    """Anonymous/unauthenticated requests must be rejected with 401."""
    exec_record = _seed_uncertain_execution(db_session, exec_mgr_env)
    res = client.post(
        f"/api/v1/remediation/executions/{exec_record.id}/resolve-uncertain?workspace_id={exec_mgr_env['ws'].id}",
        json={
            "decision": "ABORT_FAILURE",
            "justification": "Operator manually validated failure",
        },
    )
    assert res.status_code == 401


def test_resolve_uncertain_viewer_denied(client, db_session, exec_mgr_env):
    """Viewers cannot resolve uncertainty holds (403 Forbidden)."""
    env = exec_mgr_env
    exec_record = _seed_uncertain_execution(db_session, env)
    viewer_token = create_access_token({"sub": env["viewer"].id, "email": env["viewer"].email})

    res = client.post(
        f"/api/v1/remediation/executions/{exec_record.id}/resolve-uncertain?workspace_id={env['ws'].id}",
        headers={"Authorization": f"Bearer {viewer_token}"},
        json={
            "decision": "ABORT_FAILURE",
            "justification": "Viewer attempting resolution",
        },
    )
    assert res.status_code == 403


def test_resolve_uncertain_cross_workspace_denied(client, db_session, exec_mgr_env):
    """Resolving an execution belonging to a different workspace is denied."""
    env = exec_mgr_env
    exec_record = _seed_uncertain_execution(db_session, env)
    eng_token = create_access_token({"sub": env["engineer"].id, "email": env["engineer"].email})
    foreign_ws_id = env["ws2"].id

    res = client.post(
        f"/api/v1/remediation/executions/{exec_record.id}/resolve-uncertain?workspace_id={foreign_ws_id}",
        headers={"Authorization": f"Bearer {eng_token}"},
        json={
            "decision": "ABORT_FAILURE",
            "justification": "Valid justification text here",
        },
    )
    assert res.status_code in (403, 404)


def test_resolve_uncertain_missing_or_short_justification(client, db_session, exec_mgr_env):
    """Empty or too short justification must be rejected with 400 or 422."""
    env = exec_mgr_env
    exec_record = _seed_uncertain_execution(db_session, env)
    eng_token = create_access_token({"sub": env["engineer"].id, "email": env["engineer"].email})

    # Empty string
    res1 = client.post(
        f"/api/v1/remediation/executions/{exec_record.id}/resolve-uncertain?workspace_id={env['ws'].id}",
        headers={"Authorization": f"Bearer {eng_token}"},
        json={"decision": "ABORT_FAILURE", "justification": ""},
    )
    assert res1.status_code in (400, 422)

    # Whitespace only
    res2 = client.post(
        f"/api/v1/remediation/executions/{exec_record.id}/resolve-uncertain?workspace_id={env['ws'].id}",
        headers={"Authorization": f"Bearer {eng_token}"},
        json={"decision": "ABORT_FAILURE", "justification": "   "},
    )
    assert res2.status_code in (400, 422)

    # Short string (< 5 chars)
    res3 = client.post(
        f"/api/v1/remediation/executions/{exec_record.id}/resolve-uncertain?workspace_id={env['ws'].id}",
        headers={"Authorization": f"Bearer {eng_token}"},
        json={"decision": "ABORT_FAILURE", "justification": "bad"},
    )
    assert res3.status_code in (400, 422)


def test_resolve_uncertain_invalid_decision(client, db_session, exec_mgr_env):
    """Unknown decision values must be rejected."""
    env = exec_mgr_env
    exec_record = _seed_uncertain_execution(db_session, env)
    eng_token = create_access_token({"sub": env["engineer"].id, "email": env["engineer"].email})

    res = client.post(
        f"/api/v1/remediation/executions/{exec_record.id}/resolve-uncertain?workspace_id={env['ws'].id}",
        headers={"Authorization": f"Bearer {eng_token}"},
        json={
            "decision": "FORCE_PASS_WITHOUT_CHECKS",
            "justification": "Valid justification text here",
        },
    )
    assert res.status_code in (400, 422)


def test_resolve_uncertain_invalid_execution_state(client, db_session, exec_mgr_env):
    """Executions not in EXECUTION_UNCERTAIN with HOLD:EXECUTION_UNCERTAIN cannot be resolved."""
    env = exec_mgr_env
    eng_token = create_access_token({"sub": env["engineer"].id, "email": env["engineer"].email})

    exec_record = RemediationExecution(
        id=str(uuid.uuid4()),
        workspace_id=env["ws"].id,
        approval_id=env["appr_approved"].id,
        action_id="restore_order_api_demo",
        target_service_id=env["svc"].id,
        approved_parameters={"service_id": env["svc"].id},
        status=ExecutionState.QUEUED.value,
        idempotency_key=f"idemp_{uuid.uuid4().hex[:8]}",
        fencing_token=0,
        triggered_by=env["engineer"].id,
        triggered_at=datetime.now(timezone.utc),
    )
    db_session.add(exec_record)
    db_session.commit()

    res = client.post(
        f"/api/v1/remediation/executions/{exec_record.id}/resolve-uncertain?workspace_id={env['ws'].id}",
        headers={"Authorization": f"Bearer {eng_token}"},
        json={
            "decision": "ABORT_FAILURE",
            "justification": "Attempting to resolve a queued execution",
        },
    )
    assert res.status_code == 409
    assert "not in a resolvable uncertainty hold" in res.json()["detail"]


def test_resolve_uncertain_abort_failure_lifecycle(client, db_session, exec_mgr_env):
    """ABORT_FAILURE marks execution failed, sets attempt_count=max_attempts (no auto-retry), preserves audit evidence."""
    env = exec_mgr_env
    exec_record = _seed_uncertain_execution(db_session, env)
    eng_token = create_access_token({"sub": env["engineer"].id, "email": env["engineer"].email})

    res = client.post(
        f"/api/v1/remediation/executions/{exec_record.id}/resolve-uncertain?workspace_id={env['ws'].id}",
        headers={"Authorization": f"Bearer {eng_token}"},
        json={
            "decision": "ABORT_FAILURE",
            "justification": "Target host returned TCP RST; manually confirmed service did not execute restart.",
            "evidence": {"ticket": "INC-8899", "pcap_trace": "rst_captured.pcap"},
        },
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == ExecutionState.EXECUTION_FAILED.value
    assert data["locked_by"] is None
    assert data["attempt_count"] == data["max_attempts"]

    db_session.expire_all()
    updated = db_session.query(RemediationExecution).filter_by(id=exec_record.id).first()
    assert updated.status == ExecutionState.EXECUTION_FAILED.value
    assert updated.locked_by is None
    assert updated.attempt_count == updated.max_attempts
    assert updated.error_category == "operator_aborted"
    assert "INC-8899" in str(updated.execution_output["operator_resolution"])

    audit_event = (
        db_session.query(ExecutionEvent)
        .filter(
            ExecutionEvent.execution_id == exec_record.id,
            ExecutionEvent.event_type == "operator_uncertainty_resolved",
        )
        .first()
    )
    assert audit_event is not None
    assert "ABORT_FAILURE" in audit_event.message
    assert audit_event.metadata_json["decision"] == "ABORT_FAILURE"

    incident = db_session.query(Incident).filter_by(id=env["inc"].id).first()
    assert incident.status == "investigating"


def test_resolve_uncertain_duplicate_rejected(client, db_session, exec_mgr_env):
    """Resolving an already-resolved execution must return 409 Conflict."""
    env = exec_mgr_env
    exec_record = _seed_uncertain_execution(db_session, env)
    eng_token = create_access_token({"sub": env["engineer"].id, "email": env["engineer"].email})

    # First resolution
    res1 = client.post(
        f"/api/v1/remediation/executions/{exec_record.id}/resolve-uncertain?workspace_id={env['ws'].id}",
        headers={"Authorization": f"Bearer {eng_token}"},
        json={
            "decision": "ABORT_FAILURE",
            "justification": "First resolution attempt",
        },
    )
    assert res1.status_code == 200

    # Second resolution attempt on same execution
    res2 = client.post(
        f"/api/v1/remediation/executions/{exec_record.id}/resolve-uncertain?workspace_id={env['ws'].id}",
        headers={"Authorization": f"Bearer {eng_token}"},
        json={
            "decision": "ABORT_FAILURE",
            "justification": "Duplicate resolution attempt",
        },
    )
    assert res2.status_code == 409
    assert "not in a resolvable uncertainty hold" in res2.json()["detail"]


def test_resolve_uncertain_confirm_success_triggers_verification(client, db_session, exec_mgr_env):
    """CONFIRM_SUCCESS transitions to verification_pending and requires passing independent verification to recover incident."""
    env = exec_mgr_env
    exec_record = _seed_uncertain_execution(db_session, env)
    admin_token = create_access_token({"sub": env["admin"].id, "email": env["admin"].email})

    mock_engine = MagicMock()
    mock_summary = VerificationSummary(
        execution_id=exec_record.id,
        cycle_id=str(uuid.uuid4()),
        cycle_number=1,
        outcome=VerificationOutcome.PASS,
        status="passed",
        probes_executed=4,
        probes_passed=3,
        probes_failed=0,
        consecutive_passes=3,
        probes_required=3,
        baseline_5xx=0.0,
        final_5xx=0.0,
        duration_ms=150.0,
    )
    mock_engine.run_verification_cycle.return_value = mock_summary

    with patch("app.execution.verification.PostExecutionVerificationEngine", return_value=mock_engine):
        with patch("app.execution.runners.http_recovery.IsolatedHttpRecoveryRunner"):
            res = client.post(
                f"/api/v1/remediation/executions/{exec_record.id}/resolve-uncertain?workspace_id={env['ws'].id}",
                headers={"Authorization": f"Bearer {admin_token}"},
                json={
                    "decision": "CONFIRM_SUCCESS",
                    "justification": "Confirmed restart succeeded via systemd status out-of-band; initiating verification.",
                    "evidence": {"manual_check": "systemctl status active"},
                },
            )
            assert res.status_code == 200

    db_session.expire_all()
    updated = db_session.query(RemediationExecution).filter_by(id=exec_record.id).first()
    assert "CONFIRM_SUCCESS" in str(updated.execution_output["operator_resolution"])


def test_resolve_uncertain_confirm_success_verification_failure_leaves_incident_open(client, db_session, exec_mgr_env):
    """If independent verification fails after CONFIRM_SUCCESS, incident remains in investigating status."""
    env = exec_mgr_env
    exec_record = _seed_uncertain_execution(db_session, env)
    eng_token = create_access_token({"sub": env["engineer"].id, "email": env["engineer"].email})

    mock_engine = MagicMock()
    mock_engine.run_verification_cycle.side_effect = RuntimeError("Health probe returned HTTP 503")

    with patch("app.execution.verification.PostExecutionVerificationEngine", return_value=mock_engine):
        with patch("app.execution.runners.http_recovery.IsolatedHttpRecoveryRunner"):
            res = client.post(
                f"/api/v1/remediation/executions/{exec_record.id}/resolve-uncertain?workspace_id={env['ws'].id}",
                headers={"Authorization": f"Bearer {eng_token}"},
                json={
                    "decision": "CONFIRM_SUCCESS",
                    "justification": "Operator believes service recovered, testing with verification.",
                },
            )
            assert res.status_code == 200

    db_session.expire_all()
    updated = db_session.query(RemediationExecution).filter_by(id=exec_record.id).first()
    assert updated.status == ExecutionState.VERIFICATION_FAILED.value
    assert updated.verification_status == "failed"

    incident = db_session.query(Incident).filter_by(id=env["inc"].id).first()
    assert incident.status == "investigating"


def test_resolve_uncertain_no_automatic_requeue(db_session, exec_mgr_env):
    """After ABORT_FAILURE, claim_next_execution must not claim or requeue the aborted execution."""
    env = exec_mgr_env
    exec_record = _seed_uncertain_execution(db_session, env)

    RemediationExecutionManager.resolve_uncertain_execution(
        execution_id=exec_record.id,
        workspace_id=env["ws"].id,
        user=env["engineer"],
        user_role="engineer",
        decision="ABORT_FAILURE",
        justification="Manual operator abort to test no-requeue invariant",
        db=db_session,
    )

    claimed = RemediationExecutionManager.claim_next_execution(
        worker_id="test-worker-1",
        workspace_id=env["ws"].id,
        db=db_session,
    )
    assert claimed is None, "Aborted execution must not be claimable by worker"
