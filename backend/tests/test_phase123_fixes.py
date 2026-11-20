"""Regression tests for SentinelOps AI Phase 1-3 Critical Fixes.

Covers:
- Task 1: Secure Detector Endpoints (Auth, Role, Tenant Isolation)
- Task 2: Protect Demo Seed Endpoint (Environment Restrictions, Credential Privacy)
- Task 3: Investigation Lifecycle State Transitions (Success, Failure, Retry, Concurrency, Recovery Preservation)
- Task 4: Autonomous Background Detector Polling (Lifespan, Concurrency, Deduplication, Error Isolation, Overlap Prevention)
"""

import asyncio
import json
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch, MagicMock
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.security import get_password_hash, create_access_token
from app.models.user import User
from app.models.workspace import Workspace, WorkspaceMembership
from app.models.service import Service
from app.models.incident import Incident, IncidentEvent
from app.models.investigation import Investigation
from app.detector.runner import EvaluationResult
from app.detector.evaluator import DetectionReport
from app.detector.poller import BackgroundDetectorPoller
from app.agents.graph import run_investigation


# ============================================================================
# Fixtures and Helpers
# ============================================================================

def create_user_with_role(
    db: Session,
    workspace: Workspace,
    role: str,
    email_prefix: str = "user",
) -> tuple[User, str, dict]:
    """Helper to create a user with a specific workspace role and return auth headers."""
    unique = uuid.uuid4().hex[:6]
    user = User(
        email=f"{email_prefix}-{unique}@sentinelops.local",
        full_name=f"Test {role.capitalize()}",
        hashed_password=get_password_hash("ValidPass123!"),
        is_active=True,
    )
    db.add(user)
    db.flush()

    membership = WorkspaceMembership(
        workspace_id=workspace.id,
        user_id=user.id,
        role=role,
    )
    db.add(membership)
    db.commit()

    token = create_access_token({"sub": user.id, "email": user.email})
    headers = {"Authorization": f"Bearer {token}"}
    return user, token, headers


@pytest.fixture
def multi_tenant_setup(db_session: Session):
    """Creates two distinct workspaces (WS-A and WS-B) with Admin, Engineer, and Viewer accounts."""
    # Workspace A
    ws_a = Workspace(
        name="Workspace Alpha",
        slug=f"ws-alpha-{uuid.uuid4().hex[:6]}",
        description="Tenant A",
    )
    db_session.add(ws_a)
    db_session.flush()

    admin_a, token_admin_a, headers_admin_a = create_user_with_role(db_session, ws_a, "admin", "admin-a")
    eng_a, token_eng_a, headers_eng_a = create_user_with_role(db_session, ws_a, "engineer", "eng-a")
    view_a, token_view_a, headers_view_a = create_user_with_role(db_session, ws_a, "viewer", "view-a")

    # Service in Workspace A
    svc_a = Service(
        workspace_id=ws_a.id,
        name="Order API Alpha",
        environment="staging",
        health_check_url="http://127.0.0.1:8001/health",
        monitoring_method="prometheus",
        execution_policy="demo",
        is_active=True,
    )
    db_session.add(svc_a)

    # Workspace B
    ws_b = Workspace(
        name="Workspace Beta",
        slug=f"ws-beta-{uuid.uuid4().hex[:6]}",
        description="Tenant B",
    )
    db_session.add(ws_b)
    db_session.flush()

    admin_b, token_admin_b, headers_admin_b = create_user_with_role(db_session, ws_b, "admin", "admin-b")
    eng_b, token_eng_b, headers_eng_b = create_user_with_role(db_session, ws_b, "engineer", "eng-b")

    svc_b = Service(
        workspace_id=ws_b.id,
        name="Order API Beta",
        environment="staging",
        health_check_url="http://127.0.0.1:8001/health",
        monitoring_method="prometheus",
        execution_policy="demo",
        is_active=True,
    )
    db_session.add(svc_b)
    db_session.commit()

    return {
        "ws_a": ws_a,
        "svc_a": svc_a,
        "admin_a": (admin_a, headers_admin_a),
        "eng_a": (eng_a, headers_eng_a),
        "view_a": (view_a, headers_view_a),
        "ws_b": ws_b,
        "svc_b": svc_b,
        "admin_b": (admin_b, headers_admin_b),
        "eng_b": (eng_b, headers_eng_b),
    }


def make_mock_client_500():
    """Helper to mock an HTTP client returning 500 with timeout error."""
    mock_client = AsyncMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 500
    mock_resp.text = '{"status": "error", "message": "Database request timed out after 5000ms"}'
    mock_resp.json.return_value = {"status": "error", "message": "Database request timed out after 5000ms"}

    async def mock_get(url, **kwargs):
        return mock_resp

    mock_client.get.side_effect = mock_get
    return mock_client


# ============================================================================
# Task 1: Secure Detector Endpoints Tests
# ============================================================================

def test_detector_anonymous_request_rejected(client: TestClient, multi_tenant_setup):
    """Anonymous request to /evaluate/{service_id} or /evaluate-workspace must return 401."""
    svc_a = multi_tenant_setup["svc_a"]
    ws_a = multi_tenant_setup["ws_a"]

    res1 = client.post(f"/api/v1/detector/evaluate/{svc_a.id}")
    assert res1.status_code == 401

    res2 = client.post(f"/api/v1/detector/evaluate-workspace/{ws_a.id}")
    assert res2.status_code == 401


def test_detector_viewer_request_rejected(client: TestClient, multi_tenant_setup):
    """Users with Viewer role must be rejected with HTTP 403 Forbidden."""
    svc_a = multi_tenant_setup["svc_a"]
    ws_a = multi_tenant_setup["ws_a"]
    _, headers_view_a = multi_tenant_setup["view_a"]

    res1 = client.post(f"/api/v1/detector/evaluate/{svc_a.id}", headers=headers_view_a)
    assert res1.status_code == 403
    assert "Insufficient permissions" in res1.json()["detail"]

    res2 = client.post(f"/api/v1/detector/evaluate-workspace/{ws_a.id}", headers=headers_view_a)
    assert res2.status_code == 403
    assert "Insufficient permissions" in res2.json()["detail"]


@patch("app.api.v1.endpoints.detector.run_evaluation_for_service", new_callable=AsyncMock)
def test_detector_engineer_request_succeeds(
    mock_run_eval, client: TestClient, multi_tenant_setup
):
    """Users with Engineer role in the service's workspace must succeed with HTTP 200."""
    svc_a = multi_tenant_setup["svc_a"]
    _, headers_eng_a = multi_tenant_setup["eng_a"]

    mock_report = DetectionReport(
        service_id=svc_a.id,
        workspace_id=svc_a.workspace_id,
        service_name=svc_a.name,
        is_healthy=True,
        trigger=None,
        triggered_rule=None,
        severity="low",
        summary="Healthy",
        evidence={},
    )
    mock_eval = EvaluationResult(
        service_id=svc_a.id,
        service_name=svc_a.name,
        workspace_id=svc_a.workspace_id,
        is_healthy=True,
        lifecycle_action="healthy",
        incident=None,
        report=mock_report,
    )
    mock_run_eval.return_value = mock_eval

    res = client.post(f"/api/v1/detector/evaluate/{svc_a.id}", headers=headers_eng_a)
    assert res.status_code == 200
    assert res.json()["service_id"] == svc_a.id
    assert res.json()["lifecycle_action"] == "healthy"


def test_detector_cross_workspace_rejected(client: TestClient, multi_tenant_setup):
    """Users from Workspace B must NOT be allowed to evaluate services in Workspace A."""
    svc_a = multi_tenant_setup["svc_a"]
    ws_a = multi_tenant_setup["ws_a"]
    _, headers_eng_b = multi_tenant_setup["eng_b"]

    # Trying to probe service belonging to Workspace A
    res1 = client.post(f"/api/v1/detector/evaluate/{svc_a.id}", headers=headers_eng_b)
    assert res1.status_code == 403

    # Trying to evaluate Workspace A
    res2 = client.post(f"/api/v1/detector/evaluate-workspace/{ws_a.id}", headers=headers_eng_b)
    assert res2.status_code == 403


@patch("app.api.v1.endpoints.detector.run_evaluation_for_workspace", new_callable=AsyncMock)
def test_detector_admin_request_succeeds(
    mock_run_ws, client: TestClient, multi_tenant_setup
):
    """Admins within the workspace must succeed."""
    ws_a = multi_tenant_setup["ws_a"]
    svc_a = multi_tenant_setup["svc_a"]
    _, headers_admin_a = multi_tenant_setup["admin_a"]

    mock_report = DetectionReport(
        service_id=svc_a.id,
        workspace_id=svc_a.workspace_id,
        service_name=svc_a.name,
        is_healthy=True,
        trigger=None,
        triggered_rule=None,
        severity="low",
        summary="Healthy",
        evidence={},
    )
    mock_eval = EvaluationResult(
        service_id=svc_a.id,
        service_name=svc_a.name,
        workspace_id=svc_a.workspace_id,
        is_healthy=True,
        lifecycle_action="healthy",
        incident=None,
        report=mock_report,
    )
    mock_run_ws.return_value = [mock_eval]

    res = client.post(f"/api/v1/detector/evaluate-workspace/{ws_a.id}", headers=headers_admin_a)
    assert res.status_code == 200
    assert len(res.json()) == 1


def test_detector_service_not_found(client: TestClient, multi_tenant_setup):
    """Requesting evaluation for non-existent service returns 404."""
    _, headers_eng_a = multi_tenant_setup["eng_a"]
    res = client.post(f"/api/v1/detector/evaluate/{uuid.uuid4()}", headers=headers_eng_a)
    assert res.status_code == 404


# ============================================================================
# Task 2: Protect Demo Seed Endpoint Tests
# ============================================================================

def test_seed_demo_development_succeeds(client: TestClient, monkeypatch):
    """In development/test environments, POST /seed-demo works."""
    monkeypatch.setattr(settings, "ENVIRONMENT", "development")
    res = client.post("/api/v1/auth/seed-demo")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ready"
    assert data["demo_user"]["email"] == "sre@sentinelops.local"


def test_seed_demo_production_returns_403_and_no_credentials(client: TestClient, monkeypatch):
    """In production environment, POST /seed-demo returns HTTP 403 and never exposes credentials."""
    monkeypatch.setattr(settings, "ENVIRONMENT", "production")
    res = client.post("/api/v1/auth/seed-demo")
    assert res.status_code == 403
    assert "disabled in production" in res.json()["detail"].lower()
    # Confirm no credentials appear in response body
    raw_body = res.text
    assert "SentinelOps2026!" not in raw_body
    assert "demo_user" not in raw_body


def test_seed_demo_staging_returns_403(client: TestClient, monkeypatch):
    """Staging environment must also return 403."""
    monkeypatch.setattr(settings, "ENVIRONMENT", "staging")
    res = client.post("/api/v1/auth/seed-demo")
    assert res.status_code == 403


# ============================================================================
# Task 3: Fix Investigation Lifecycle Tests
# ============================================================================

@pytest.mark.asyncio
async def test_investigation_success_transitions_to_awaiting_approval(
    db_session: Session, multi_tenant_setup
):
    """Successful investigation must transition incident out of investigating into awaiting_approval."""
    ws = multi_tenant_setup["ws_a"]
    svc = multi_tenant_setup["svc_a"]

    incident = Incident(
        workspace_id=ws.id,
        service_id=svc.id,
        title="Test Investigation Lifecycle",
        severity="high",
        status="detected",
        trigger="health_500",
        summary="Service failure",
    )
    db_session.add(incident)
    db_session.commit()
    db_session.refresh(incident)

    mock_client = make_mock_client_500()

    final_state = await run_investigation(
        incident_id=incident.id,
        workspace_id=ws.id,
        db=db_session,
        client=mock_client,
    )

    db_session.refresh(incident)
    assert final_state["status"] == "completed"
    # Lifecycle state must be awaiting_approval, NOT recovered, NOT investigating
    assert incident.status == "awaiting_approval"
    assert incident.recovered_at is None


@pytest.mark.asyncio
async def test_investigation_failure_persists_state_and_audit(
    db_session: Session, multi_tenant_setup
):
    """Failed graph execution must record failed state, audit event, and set incident status to investigation_failed."""
    ws = multi_tenant_setup["ws_a"]
    svc = multi_tenant_setup["svc_a"]

    incident = Incident(
        workspace_id=ws.id,
        service_id=svc.id,
        title="Test Failure Investigation",
        severity="high",
        status="detected",
        trigger="health_500",
    )
    db_session.add(incident)
    db_session.commit()
    db_session.refresh(incident)

    # Force an unhandled exception inside graph execution via a failing app mock
    mock_app = MagicMock()
    mock_app.ainvoke = AsyncMock(side_effect=RuntimeError("Simulated LLM pipeline crash"))

    with patch("app.agents.graph.create_investigation_graph", return_value=mock_app):
        final_state = await run_investigation(
            incident_id=incident.id,
            workspace_id=ws.id,
            db=db_session,
        )

    db_session.refresh(incident)
    assert final_state["status"] == "failed"
    assert incident.status == "investigation_failed"

    # Verify failed investigation row in DB
    inv = db_session.query(Investigation).filter(Investigation.incident_id == incident.id).first()
    assert inv is not None
    assert inv.status == "failed"
    assert "Simulated LLM pipeline crash" in inv.error_message

    # Verify failure audit event was logged
    fail_event = (
        db_session.query(IncidentEvent)
        .filter(IncidentEvent.incident_id == incident.id, IncidentEvent.event_type == "investigation")
        .order_by(IncidentEvent.timestamp.desc())
        .first()
    )
    assert fail_event is not None
    assert "failed" in fail_event.message.lower()


@pytest.mark.asyncio
async def test_investigation_retry_after_failure_works(
    client: TestClient, db_session: Session, multi_tenant_setup
):
    """An incident in investigation_failed can be retried cleanly via API."""
    ws = multi_tenant_setup["ws_a"]
    svc = multi_tenant_setup["svc_a"]
    _, headers_eng_a = multi_tenant_setup["eng_a"]

    incident = Incident(
        workspace_id=ws.id,
        service_id=svc.id,
        title="Retryable Incident",
        severity="high",
        status="investigation_failed",
        trigger="health_500",
    )
    db_session.add(incident)
    db_session.commit()

    # Previous failed investigation
    prev_inv = Investigation(
        incident_id=incident.id,
        workspace_id=ws.id,
        status="failed",
        error_message="Previous network timeout",
    )
    db_session.add(prev_inv)
    db_session.commit()

    mock_state = {
        "investigation_id": None,
        "status": "completed",
    }

    with patch("app.api.v1.endpoints.investigations.run_investigation", new_callable=AsyncMock, return_value=mock_state):
        res = client.post(
            f"/api/v1/incidents/{incident.id}/investigate?workspace_id={ws.id}",
            headers=headers_eng_a,
        )
        assert res.status_code == 201
        data = res.json()
        assert data["incident_id"] == incident.id


def test_investigation_concurrent_execution_rejected(
    client: TestClient, db_session: Session, multi_tenant_setup
):
    """Concurrent investigations on the same incident are rejected with HTTP 409 Conflict."""
    ws = multi_tenant_setup["ws_a"]
    svc = multi_tenant_setup["svc_a"]
    _, headers_eng_a = multi_tenant_setup["eng_a"]

    incident = Incident(
        workspace_id=ws.id,
        service_id=svc.id,
        title="Concurrent Target Incident",
        severity="high",
        status="investigating",
        trigger="health_500",
    )
    db_session.add(incident)
    db_session.commit()

    active_inv = Investigation(
        incident_id=incident.id,
        workspace_id=ws.id,
        status="running",
    )
    db_session.add(active_inv)
    db_session.commit()

    # Second request while first is still running
    res = client.post(
        f"/api/v1/incidents/{incident.id}/investigate?workspace_id={ws.id}",
        headers=headers_eng_a,
    )
    assert res.status_code == 409
    assert "already in progress" in res.json()["detail"]


@pytest.mark.asyncio
async def test_investigation_preserves_recovered_incidents(
    db_session: Session, multi_tenant_setup
):
    """Investigation must never overwrite an incident marked 'recovered'."""
    ws = multi_tenant_setup["ws_a"]
    svc = multi_tenant_setup["svc_a"]
    now_utc = datetime.now(timezone.utc)

    incident = Incident(
        workspace_id=ws.id,
        service_id=svc.id,
        title="Recovered Incident",
        severity="high",
        status="recovered",
        trigger="health_500",
        recovered_at=now_utc,
    )
    db_session.add(incident)
    db_session.commit()

    mock_client = AsyncMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = '{"status": "ok"}'
    mock_resp.json.return_value = {"status": "ok"}

    async def mock_get(url, **kwargs):
        return mock_resp

    mock_client.get.side_effect = mock_get

    await run_investigation(
        incident_id=incident.id,
        workspace_id=ws.id,
        db=db_session,
        client=mock_client,
    )

    db_session.refresh(incident)
    # Incident status must remain recovered
    assert incident.status == "recovered"
    assert incident.recovered_at is not None


# ============================================================================
# Task 4: Autonomous Background Detector Polling Tests
# ============================================================================

@pytest.mark.asyncio
async def test_poller_start_and_stop():
    """BackgroundDetectorPoller starts and cancels/stops cleanly."""
    poller = BackgroundDetectorPoller(poll_interval=0.1, enabled=True)
    assert not poller.is_running

    await poller.start()
    assert poller.is_running

    await poller.stop()
    assert not poller.is_running


@pytest.mark.asyncio
async def test_poller_disabled_setting_refuses_start():
    """Poller does not start if enabled=False."""
    poller = BackgroundDetectorPoller(poll_interval=0.1, enabled=False)
    await poller.start()
    assert not poller.is_running


@pytest.mark.asyncio
async def test_poller_evaluates_active_services_and_detects_failure(
    db_session: Session, multi_tenant_setup
):
    """Poller automatically detects failure and persists an incident."""
    svc_a = multi_tenant_setup["svc_a"]
    ws_a = multi_tenant_setup["ws_a"]

    mock_report = DetectionReport(
        service_id=svc_a.id,
        workspace_id=ws_a.id,
        service_name=svc_a.name,
        is_healthy=False,
        trigger="health_probe_status_code_500",
        triggered_rule="health_status_rule",
        severity="high",
        summary="Internal Server Error (HTTP 500)",
        evidence={"status_code": 500},
    )

    with patch("app.detector.runner.evaluate_service_health", new_callable=AsyncMock, return_value=mock_report):
        from app.detector.runner import run_evaluation_for_service
        res = await run_evaluation_for_service(service_id=svc_a.id, db=db_session)

        assert res.is_healthy is False
        assert res.lifecycle_action == "created"
        assert res.incident is not None
        assert res.incident.status == "detected"


@pytest.mark.asyncio
async def test_poller_repeated_failures_deduplicate(
    db_session: Session, multi_tenant_setup
):
    """Repeated failures on active incident deduplicate and do not create duplicate incidents."""
    svc_a = multi_tenant_setup["svc_a"]
    ws_a = multi_tenant_setup["ws_a"]

    mock_report = DetectionReport(
        service_id=svc_a.id,
        workspace_id=ws_a.id,
        service_name=svc_a.name,
        is_healthy=False,
        trigger="health_probe_status_code_500",
        triggered_rule="health_status_rule",
        severity="high",
        summary="Internal Server Error (HTTP 500)",
        evidence={"status_code": 500},
    )

    with patch("app.detector.runner.evaluate_service_health", new_callable=AsyncMock, return_value=mock_report):
        from app.detector.runner import run_evaluation_for_service
        # Cycle 1: Creates incident
        res1 = await run_evaluation_for_service(service_id=svc_a.id, db=db_session)
        assert res1.lifecycle_action == "created"

        # Cycle 2: Deduplicates incident
        res2 = await run_evaluation_for_service(service_id=svc_a.id, db=db_session)
        assert res2.lifecycle_action == "deduplicated"
        assert res2.incident.id == res1.incident.id

        # Total incidents in DB must be exactly 1
        count = db_session.query(Incident).filter(Incident.service_id == svc_a.id).count()
        assert count == 1


@pytest.mark.asyncio
async def test_poller_recovery_marks_incident_recovered(
    db_session: Session, multi_tenant_setup
):
    """Recovery automatically transitions active incident to recovered with timestamp."""
    svc_a = multi_tenant_setup["svc_a"]
    ws_a = multi_tenant_setup["ws_a"]

    # Active incident in awaiting_approval
    incident = Incident(
        workspace_id=ws_a.id,
        service_id=svc_a.id,
        title="Failing Order API",
        severity="high",
        status="awaiting_approval",
        trigger="health_500",
    )
    db_session.add(incident)
    db_session.commit()

    # Recovery report
    mock_report = DetectionReport(
        service_id=svc_a.id,
        workspace_id=ws_a.id,
        service_name=svc_a.name,
        is_healthy=True,
        trigger=None,
        triggered_rule=None,
        severity="low",
        summary="Health restored",
        evidence={"status_code": 200},
    )

    with patch("app.detector.runner.evaluate_service_health", new_callable=AsyncMock, return_value=mock_report):
        from app.detector.runner import run_evaluation_for_service
        res = await run_evaluation_for_service(service_id=svc_a.id, db=db_session)

        assert res.lifecycle_action == "recovered"
        assert res.incident.status == "recovered"
        assert res.incident.recovered_at is not None


@pytest.mark.asyncio
async def test_poller_error_isolation_and_overlap_prevention():
    """Individual service failures do not crash the poller and overlap is safely rejected."""
    poller = BackgroundDetectorPoller(max_concurrency=2)

    # 1. Overlap test: service already in flight
    poller._evaluating_services.add("svc-in-flight-1")
    guarded = await poller._evaluate_service_guarded("svc-in-flight-1", "Busy Svc", "ws-1")
    assert guarded is False  # Skipped because already in flight

    poller._evaluating_services.clear()

    # 2. Error isolation: when evaluation raises exception, it returns False and doesn't crash
    with patch("app.detector.poller.run_evaluation_for_service", new_callable=AsyncMock, side_effect=ConnectionError("DNS resolution failed")):
        guarded2 = await poller._evaluate_service_guarded("svc-err", "Broken Svc", "ws-1")
        assert guarded2 is False
        # Service ID was cleaned up from evaluating set
        assert "svc-err" not in poller._evaluating_services
