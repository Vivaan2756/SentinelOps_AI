"""Incident closure and tracking API test suite."""

import uuid
from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from app.core.security import create_access_token, get_password_hash
from app.models.incident import Incident, IncidentEvent
from app.models.service import Service
from app.models.user import User
from app.models.workspace import Workspace, WorkspaceMembership


@pytest.fixture
def test_setup(db_session: Session, auth_context: dict):
    """Provides workspace, service, and authenticated engineer context."""
    workspace = auth_context["workspace"]
    user = auth_context["user"]
    headers = auth_context["headers"]

    service = Service(
        workspace_id=workspace.id,
        name=f"Payments Service {uuid.uuid4().hex[:6]}",
        environment="production",
        health_check_url="http://127.0.0.1:8001/health",
        monitoring_method="synthetic",
        execution_policy="demo",
    )
    db_session.add(service)
    db_session.commit()

    return {
        "workspace": workspace,
        "user": user,
        "headers": headers,
        "service": service,
    }


def test_recovered_incident_closes_successfully(client: TestClient, db_session: Session, test_setup: dict):
    """1. Recovered incident closes successfully, populates timestamp, notes, and timeline event."""
    ws = test_setup["workspace"]
    svc = test_setup["service"]
    headers = test_setup["headers"]

    incident = Incident(
        workspace_id=ws.id,
        service_id=svc.id,
        title="High Latency Spike",
        severity="high",
        status="recovered",
        trigger="HTTP 503 Threshold",
        summary="Service connection pool recovered following database reset.",
        recovered_at=datetime.now(timezone.utc),
    )
    db_session.add(incident)
    db_session.commit()

    payload = {
        "resolution_notes": "Service confirmed fully recovered. Pool exhaustion resolved by automated restart."
    }
    res = client.post(
        f"/api/v1/incidents/{incident.id}/close?workspace_id={ws.id}",
        json=payload,
        headers=headers,
    )
    assert res.status_code == 200
    data = res.json()

    assert data["id"] == incident.id
    assert data["status"] == "closed"
    assert data["closed_at"] is not None
    assert "Resolution Notes: Service confirmed fully recovered." in data["summary"]

    # Verify database state directly
    db_session.refresh(incident)
    assert incident.status == "closed"
    assert incident.closed_at is not None
    assert "Service confirmed fully recovered." in incident.summary

    # Verify timeline event was persisted
    events = (
        db_session.query(IncidentEvent)
        .filter(IncidentEvent.incident_id == incident.id)
        .all()
    )
    assert len(events) == 1
    assert events[0].event_type == "incident_closed"
    assert "Service confirmed fully recovered." in events[0].message
    assert events[0].metadata_json is not None
    assert "closed_by_user_id" in events[0].metadata_json


def test_mitigated_incident_closes_successfully(client: TestClient, db_session: Session, test_setup: dict):
    """2. Mitigated incident closes successfully with notes."""
    ws = test_setup["workspace"]
    svc = test_setup["service"]
    headers = test_setup["headers"]

    incident = Incident(
        workspace_id=ws.id,
        service_id=svc.id,
        title="Memory Leak Anomaly",
        severity="medium",
        status="mitigated",
        trigger="Memory > 90%",
        summary=None,
    )
    db_session.add(incident)
    db_session.commit()

    payload = {
        "resolution_notes": "Mitigated by traffic shifting. Root cause identified in upstream cache."
    }
    res = client.post(
        f"/api/v1/incidents/{incident.id}/close?workspace_id={ws.id}",
        json=payload,
        headers=headers,
    )
    assert res.status_code == 200
    data = res.json()

    assert data["status"] == "closed"
    assert data["closed_at"] is not None
    assert data["summary"] == "Mitigated by traffic shifting. Root cause identified in upstream cache."

    # Verify database event
    events = (
        db_session.query(IncidentEvent)
        .filter(IncidentEvent.incident_id == incident.id, IncidentEvent.event_type == "incident_closed")
        .all()
    )
    assert len(events) == 1


def test_closed_timestamp_and_notes_populated(client: TestClient, db_session: Session, test_setup: dict):
    """3 & 4. Closed timestamp is populated with UTC datetime and resolution notes are preserved."""
    ws = test_setup["workspace"]
    svc = test_setup["service"]
    headers = test_setup["headers"]

    incident = Incident(
        workspace_id=ws.id,
        service_id=svc.id,
        title="Gateway Timeout",
        severity="critical",
        status="recovered",
        trigger="HTTP 504",
        summary="Initial incident summary.",
    )
    db_session.add(incident)
    db_session.commit()

    before_closure = datetime.now(timezone.utc)
    res = client.post(
        f"/api/v1/incidents/{incident.id}/close?workspace_id={ws.id}",
        json={"resolution_notes": "Verified gateway configuration restored."},
        headers=headers,
    )
    assert res.status_code == 200
    after_closure = datetime.now(timezone.utc)

    db_session.refresh(incident)
    assert incident.closed_at is not None
    # Normalize naive datetime from SQLite if needed
    closed_at_utc = (
        incident.closed_at
        if incident.closed_at.tzinfo is not None
        else incident.closed_at.replace(tzinfo=timezone.utc)
    )
    assert before_closure <= closed_at_utc <= after_closure
    assert "Initial incident summary." in incident.summary
    assert "Verified gateway configuration restored." in incident.summary


def test_timeline_event_created_on_closure(client: TestClient, db_session: Session, test_setup: dict):
    """5. Timeline event of type incident_closed is created."""
    ws = test_setup["workspace"]
    svc = test_setup["service"]
    headers = test_setup["headers"]

    incident = Incident(
        workspace_id=ws.id,
        service_id=svc.id,
        title="Worker Disk Pressure",
        severity="low",
        status="recovered",
        trigger="Disk Usage > 85%",
    )
    db_session.add(incident)
    db_session.commit()

    res = client.post(
        f"/api/v1/incidents/{incident.id}/close",
        json={
            "workspace_id": ws.id,
            "resolution_notes": "Cleaned up temporary journal files. Disk usage down to 42%.",
        },
        headers=headers,
    )
    assert res.status_code == 200

    # Also test via get_incident_detail endpoint to ensure timeline includes the closure event
    res_detail = client.get(f"/api/v1/incidents/{incident.id}?workspace_id={ws.id}", headers=headers)
    assert res_detail.status_code == 200
    detail = res_detail.json()
    timeline = detail["timeline"]
    closure_events = [e for e in timeline if e["event_type"] == "incident_closed"]
    assert len(closure_events) == 1
    assert "Cleaned up temporary journal files." in closure_events[0]["message"]


def test_unknown_incident_returns_404(client: TestClient, test_setup: dict):
    """6. Unknown incident returns 404."""
    ws = test_setup["workspace"]
    headers = test_setup["headers"]
    fake_id = str(uuid.uuid4())

    res = client.post(
        f"/api/v1/incidents/{fake_id}/close?workspace_id={ws.id}",
        json={"resolution_notes": "Should not work."},
        headers=headers,
    )
    assert res.status_code == 404
    assert f"Incident '{fake_id}' not found" in res.json()["detail"]


def test_active_incident_cannot_be_closed(client: TestClient, db_session: Session, test_setup: dict):
    """7. Active incident (detected or investigating) cannot be closed."""
    ws = test_setup["workspace"]
    svc = test_setup["service"]
    headers = test_setup["headers"]

    for active_status in ("detected", "investigating", "awaiting_approval"):
        incident = Incident(
            workspace_id=ws.id,
            service_id=svc.id,
            title=f"Failure in state {active_status}",
            severity="high",
            status=active_status,
            trigger="Alert",
        )
        db_session.add(incident)
        db_session.commit()

        res = client.post(
            f"/api/v1/incidents/{incident.id}/close?workspace_id={ws.id}",
            json={"resolution_notes": "Premature closure attempt."},
            headers=headers,
        )
        assert res.status_code == 409
        assert "Cannot close incident" in res.json()["detail"]
        assert active_status in res.json()["detail"]

        # Verify status did not change
        db_session.refresh(incident)
        assert incident.status == active_status
        assert incident.closed_at is None


def test_executing_incident_cannot_be_closed(client: TestClient, db_session: Session, test_setup: dict):
    """8. Executing or remediating incident cannot be closed."""
    ws = test_setup["workspace"]
    svc = test_setup["service"]
    headers = test_setup["headers"]

    for in_progress_status in ("remediating", "verifying"):
        incident = Incident(
            workspace_id=ws.id,
            service_id=svc.id,
            title=f"Incident in {in_progress_status}",
            severity="critical",
            status=in_progress_status,
            trigger="Alert",
        )
        db_session.add(incident)
        db_session.commit()

        res = client.post(
            f"/api/v1/incidents/{incident.id}/close?workspace_id={ws.id}",
            json={"resolution_notes": "Cannot close while execution is in flight."},
            headers=headers,
        )
        assert res.status_code == 409
        assert "Cannot close incident" in res.json()["detail"]
        assert in_progress_status in res.json()["detail"]

        db_session.refresh(incident)
        assert incident.status == in_progress_status
        assert incident.closed_at is None


def test_repeated_closure_does_not_create_duplicate_events(client: TestClient, db_session: Session, test_setup: dict):
    """9. Repeated closure requests predictably succeed without creating duplicate closure events."""
    ws = test_setup["workspace"]
    svc = test_setup["service"]
    headers = test_setup["headers"]

    incident = Incident(
        workspace_id=ws.id,
        service_id=svc.id,
        title="Flapping Circuit Breaker",
        severity="medium",
        status="recovered",
        trigger="Circuit Breaker Open",
    )
    db_session.add(incident)
    db_session.commit()

    # First closure
    res1 = client.post(
        f"/api/v1/incidents/{incident.id}/close?workspace_id={ws.id}",
        json={"resolution_notes": "Circuit breaker reset verified."},
        headers=headers,
    )
    assert res1.status_code == 200
    first_closed_at = res1.json()["closed_at"]

    # Verify 1 event in DB
    events1 = (
        db_session.query(IncidentEvent)
        .filter(IncidentEvent.incident_id == incident.id, IncidentEvent.event_type == "incident_closed")
        .all()
    )
    assert len(events1) == 1

    # Second closure (idempotent repeat)
    res2 = client.post(
        f"/api/v1/incidents/{incident.id}/close?workspace_id={ws.id}",
        json={"resolution_notes": "Repeated closure call."},
        headers=headers,
    )
    assert res2.status_code == 200
    assert res2.json()["status"] == "closed"
    assert res2.json()["closed_at"] == first_closed_at

    # Verify STILL exactly 1 event in DB (no duplicates)
    events2 = (
        db_session.query(IncidentEvent)
        .filter(IncidentEvent.incident_id == incident.id, IncidentEvent.event_type == "incident_closed")
        .all()
    )
    assert len(events2) == 1


def test_user_cannot_close_incident_outside_authorized_workspace(client: TestClient, db_session: Session, test_setup: dict):
    """10. A user cannot close an incident outside their authorized workspace."""
    user = test_setup["user"]
    headers = test_setup["headers"]

    # Create Foreign Workspace and foreign service/incident
    foreign_ws = Workspace(
        name="Foreign Workspace",
        slug=f"foreign-ws-{uuid.uuid4().hex[:6]}",
        description="Foreign tenant",
    )
    db_session.add(foreign_ws)
    db_session.commit()

    foreign_svc = Service(
        workspace_id=foreign_ws.id,
        name="Foreign Service",
        environment="production",
        health_check_url="http://127.0.0.1:9000/health",
        monitoring_method="synthetic",
        execution_policy="demo",
    )
    db_session.add(foreign_svc)
    db_session.commit()

    foreign_incident = Incident(
        workspace_id=foreign_ws.id,
        service_id=foreign_svc.id,
        title="Foreign Outage",
        severity="high",
        status="recovered",
        trigger="External Alert",
    )
    db_session.add(foreign_incident)
    db_session.commit()

    # Attempt A: User targets foreign incident with their own workspace_id (mismatch)
    user_ws = test_setup["workspace"]
    res_a = client.post(
        f"/api/v1/incidents/{foreign_incident.id}/close?workspace_id={user_ws.id}",
        json={"resolution_notes": "Attempting cross-tenant closure"},
        headers=headers,
    )
    assert res_a.status_code == 404

    # Attempt B: User targets foreign incident with foreign workspace_id (no membership)
    res_b = client.post(
        f"/api/v1/incidents/{foreign_incident.id}/close?workspace_id={foreign_ws.id}",
        json={"resolution_notes": "Attempting unauthorized workspace closure"},
        headers=headers,
    )
    assert res_b.status_code == 403

    # Attempt C: User targets foreign incident without specifying workspace_id
    res_c = client.post(
        f"/api/v1/incidents/{foreign_incident.id}/close",
        json={"resolution_notes": "Attempting untracked cross-tenant closure"},
        headers=headers,
    )
    assert res_c.status_code in (403, 404)

    # Verify foreign incident remains unchanged
    db_session.refresh(foreign_incident)
    assert foreign_incident.status == "recovered"
    assert foreign_incident.closed_at is None


def test_blank_resolution_notes_rejected(client: TestClient, test_setup: dict):
    """Empty or whitespace-only resolution notes rejected with 422."""
    ws = test_setup["workspace"]
    headers = test_setup["headers"]

    res = client.post(
        f"/api/v1/incidents/{uuid.uuid4()}/close?workspace_id={ws.id}",
        json={"resolution_notes": "   "},
        headers=headers,
    )
    assert res.status_code == 422
