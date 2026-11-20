"""Test suite for incident lifecycle management and deduplication."""

import uuid
from sqlalchemy.orm import Session
from app.models.workspace import Workspace
from app.models.service import Service
from app.models.incident import Incident, IncidentEvent
from app.detector.evaluator import DetectionReport
from app.detector.lifecycle import process_detection_lifecycle


def test_incident_lifecycle_creation_deduplication_recovery(db_session: Session):
    """Verify full incident lifecycle: creation, deduplication, and recovery update."""
    # 1. Setup Workspace and Service
    workspace = Workspace(
        name="Reliability Ops",
        slug=f"reliability-ops-{uuid.uuid4().hex[:6]}",
    )
    db_session.add(workspace)
    db_session.commit()

    service = Service(
        workspace_id=workspace.id,
        name="Order API",
        environment="development",
        health_check_url="http://127.0.0.1:8001/health",
        monitoring_method="prometheus",
        execution_policy="demo",
    )
    db_session.add(service)
    db_session.commit()

    # 2. First failure report -> creates new incident
    report_fail_1 = DetectionReport(
        service_id=service.id,
        workspace_id=workspace.id,
        service_name=service.name,
        is_healthy=False,
        triggered_rule="HTTP_Health_Status_Rule",
        severity="high",
        trigger="Elevated 5xx error: HTTP 500 returned",
        summary="Simulated DB pool timeout",
        evidence={"status_code": 500, "error": "Database timeout"},
    )

    inc1, action1 = process_detection_lifecycle(db_session, report_fail_1)
    assert action1 == "created"
    assert inc1 is not None
    assert inc1.status == "detected"
    assert inc1.severity == "high"
    assert inc1.workspace_id == workspace.id
    assert inc1.service_id == service.id

    # Verify detection event was persisted
    events = db_session.query(IncidentEvent).filter(IncidentEvent.incident_id == inc1.id).all()
    assert len(events) == 1
    assert events[0].event_type == "detection"
    assert "HTTP_Health_Status_Rule" in events[0].message

    # 3. Second failure report -> deduplicated (no duplicate incident created)
    report_fail_2 = DetectionReport(
        service_id=service.id,
        workspace_id=workspace.id,
        service_name=service.name,
        is_healthy=False,
        triggered_rule="HTTP_Health_Status_Rule",
        severity="high",
        trigger="Elevated 5xx error: HTTP 500 returned",
        summary="Simulated DB pool timeout (persisting)",
        evidence={"status_code": 500},
    )

    inc2, action2 = process_detection_lifecycle(db_session, report_fail_2)
    assert action2 == "deduplicated"
    assert inc2.id == inc1.id

    # Total active incidents in workspace should still be exactly 1
    total_active = (
        db_session.query(Incident)
        .filter(Incident.workspace_id == workspace.id, Incident.status == "detected")
        .count()
    )
    assert total_active == 1

    # 4. Healthy report -> marks recovery on existing incident
    report_healthy = DetectionReport(
        service_id=service.id,
        workspace_id=workspace.id,
        service_name=service.name,
        is_healthy=True,
        evidence={"status_code": 200},
    )

    inc_rec, action_rec = process_detection_lifecycle(db_session, report_healthy)
    assert action_rec == "recovered"
    assert inc_rec.id == inc1.id
    assert inc_rec.status == "recovered"
    assert inc_rec.recovered_at is not None

    # Verify recovery verification event recorded
    events_after = (
        db_session.query(IncidentEvent)
        .filter(IncidentEvent.incident_id == inc1.id)
        .order_by(IncidentEvent.timestamp.asc())
        .all()
    )
    assert len(events_after) == 2
    assert events_after[1].event_type == "verification"

    # 5. Subsequent healthy report -> returns healthy, no new actions
    inc_sub, action_sub = process_detection_lifecycle(db_session, report_healthy)
    assert action_sub == "healthy"
    assert inc_sub is None
