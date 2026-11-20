"""End-to-end test suite for deterministic detection, incident creation, deduplication, and recovery."""

import uuid
import pytest
import httpx
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from app.models.workspace import Workspace
from app.models.service import Service
from app.models.incident import Incident, IncidentEvent
from app.detector.runner import run_evaluation_for_service


@pytest.mark.asyncio
async def test_end_to_end_order_api_failure_and_recovery(db_session: Session):
    """
    End-to-end test verifying:
    Healthy service -> Injected failure -> Persisted incident -> Deduplication -> Recovery update.
    """
    # 1. Register Workspace and Service
    workspace = Workspace(
        name="Checkout Ops",
        slug=f"checkout-ops-{uuid.uuid4().hex[:6]}",
    )
    db_session.add(workspace)
    db_session.commit()

    service = Service(
        workspace_id=workspace.id,
        name="Order API Demo",
        environment="development",
        health_check_url="http://127.0.0.1:8001/health",
        monitoring_method="prometheus",
        execution_policy="demo",
    )
    db_session.add(service)
    db_session.commit()

    # Create mock transport for target Order API service
    mock_state = {"healthy": True, "5xx_count": 0}

    def order_api_handler(request: httpx.Request):
        url = str(request.url)
        if url.endswith("/health"):
            if not mock_state["healthy"]:
                mock_state["5xx_count"] += 1
                return httpx.Response(
                    500,
                    json={"status": "unhealthy", "error": "Database timeout after 5000ms"},
                )
            return httpx.Response(200, json={"status": "healthy", "service": "order-api"})
        elif url.endswith("/metrics"):
            count = mock_state["5xx_count"]
            metrics_body = f"""# HELP order_api_http_5xx_errors_total Total 5xx
# TYPE order_api_http_5xx_errors_total counter
order_api_http_5xx_errors_total{{method="GET",endpoint="/health"}} {float(count)}
"""
            return httpx.Response(200, text=metrics_body)
        return httpx.Response(404)

    mock_client = httpx.AsyncClient(transport=httpx.MockTransport(order_api_handler))

    # Phase A: Initial healthy check
    res_healthy = await run_evaluation_for_service(
        service_id=service.id,
        db=db_session,
        client=mock_client,
    )
    assert res_healthy.is_healthy is True
    assert res_healthy.lifecycle_action == "healthy"
    assert res_healthy.incident is None

    # Assert no incidents in DB
    assert db_session.query(Incident).filter(Incident.service_id == service.id).count() == 0

    # Phase B: Inject failure into target Order API
    mock_state["healthy"] = False

    res_fail = await run_evaluation_for_service(
        service_id=service.id,
        db=db_session,
        client=mock_client,
    )
    assert res_fail.is_healthy is False
    assert res_fail.lifecycle_action == "created"
    assert res_fail.incident is not None

    created_incident = res_fail.incident
    assert created_incident.status == "detected"
    assert created_incident.severity == "high"
    assert created_incident.service_id == service.id
    assert created_incident.workspace_id == workspace.id
    assert "500" in created_incident.trigger

    # Check database directly for incident and detection event
    db_incident = db_session.query(Incident).filter(Incident.id == created_incident.id).first()
    assert db_incident is not None
    assert db_incident.status == "detected"

    events = db_session.query(IncidentEvent).filter(IncidentEvent.incident_id == db_incident.id).all()
    assert len(events) == 1
    assert events[0].event_type == "detection"
    assert "metadata_json" in events[0].__dict__

    # Phase C: Deduplication on repeated failure check
    res_repeat = await run_evaluation_for_service(
        service_id=service.id,
        db=db_session,
        client=mock_client,
    )
    assert res_repeat.is_healthy is False
    assert res_repeat.lifecycle_action == "deduplicated"
    assert res_repeat.incident.id == created_incident.id

    # Verify still exactly 1 incident exists in DB
    total_incidents = db_session.query(Incident).filter(Incident.service_id == service.id).count()
    assert total_incidents == 1

    # Phase D: Restore target Order API to healthy state
    mock_state["healthy"] = True
    mock_state["5xx_count"] = 0

    res_recovery = await run_evaluation_for_service(
        service_id=service.id,
        db=db_session,
        client=mock_client,
    )
    assert res_recovery.is_healthy is True
    assert res_recovery.lifecycle_action == "recovered"
    assert res_recovery.incident.id == created_incident.id
    assert res_recovery.incident.status == "recovered"
    assert res_recovery.incident.recovered_at is not None

    # Check database records directly for recovery update
    db_session.refresh(db_incident)
    assert db_incident.status == "recovered"
    assert db_incident.recovered_at is not None

    # Verify recovery verification event added
    events_after = (
        db_session.query(IncidentEvent)
        .filter(IncidentEvent.incident_id == db_incident.id)
        .order_by(IncidentEvent.timestamp.asc())
        .all()
    )
    assert len(events_after) == 2
    assert events_after[0].event_type == "detection"
    assert events_after[1].event_type == "verification"
    assert "recovered" in events_after[1].message

    # Clean up mock client
    await mock_client.aclose()
