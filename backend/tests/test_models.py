"""Domain models test suite."""

import uuid
from sqlalchemy.orm import Session
from app.models.workspace import Workspace, WorkspaceMembership
from app.models.user import User
from app.models.service import Service
from app.models.incident import Incident, IncidentEvent


def test_workspace_and_membership_creation(db_session: Session):
    """Verify workspace and membership isolation structures."""
    workspace = Workspace(
        name="Reliability Core",
        slug=f"reliability-core-{uuid.uuid4().hex[:6]}",
        description="Core SRE team workspace",
    )
    db_session.add(workspace)

    user = User(
        email=f"sre-{uuid.uuid4().hex[:6]}@example.com",
        hashed_password="hashed_placeholder_pw",
        full_name="Lead SRE",
    )
    db_session.add(user)
    db_session.commit()

    membership = WorkspaceMembership(
        workspace_id=workspace.id,
        user_id=user.id,
        role="admin",
    )
    db_session.add(membership)
    db_session.commit()

    # Query back
    saved_ws = db_session.query(Workspace).filter(Workspace.id == workspace.id).first()
    assert saved_ws is not None
    assert len(saved_ws.memberships) == 1
    assert saved_ws.memberships[0].role == "admin"
    assert saved_ws.memberships[0].user.email == user.email


def test_service_and_incident_lifecycle(db_session: Session):
    """Verify service registration and incident lifecycle relationships."""
    workspace = Workspace(
        name="Production Apps",
        slug=f"prod-apps-{uuid.uuid4().hex[:6]}",
    )
    db_session.add(workspace)
    db_session.commit()

    service = Service(
        workspace_id=workspace.id,
        name="Order API",
        environment="development",
        health_check_url="http://localhost:8001/health",
        monitoring_method="prometheus",
        execution_policy="demo",
    )
    db_session.add(service)
    db_session.commit()

    incident = Incident(
        workspace_id=workspace.id,
        service_id=service.id,
        title="High 5xx error rate detected",
        severity="high",
        status="detected",
        trigger="HTTP 500 error rate exceeded 5% over 1m",
        summary="Database timeout failure scenario",
    )
    db_session.add(incident)
    db_session.commit()

    event = IncidentEvent(
        incident_id=incident.id,
        event_type="detection",
        message="Alert rule 'OrderAPI_High5xx' triggered",
    )
    db_session.add(event)
    db_session.commit()

    # Verification
    retrieved_inc = db_session.query(Incident).filter(Incident.id == incident.id).first()
    assert retrieved_inc is not None
    assert retrieved_inc.service.name == "Order API"
    assert retrieved_inc.workspace.id == workspace.id
    assert len(retrieved_inc.events) == 1
    assert retrieved_inc.events[0].event_type == "detection"
