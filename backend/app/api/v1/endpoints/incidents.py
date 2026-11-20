"""Incident tracking endpoints with workspace authorization and timeline detail."""

from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
import json
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.models.user import User
from app.models.incident import Incident, IncidentEvent
from app.models.service import Service
from app.schemas.incident import IncidentCreate, IncidentResponse, IncidentCloseRequest
from app.api.deps import RequireWorkspaceRole, get_current_user, check_workspace_role

router = APIRouter()

CLOSABLE_INCIDENT_STATUSES = {"recovered", "mitigated"}


@router.get("", response_model=List[IncidentResponse], summary="List workspace incidents")
def list_incidents(
    workspace_id: str = Query(..., description="Workspace ID for authorization"),
    service_id: Optional[str] = Query(None, description="Optional service ID filter"),
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by incident status"),
    severity_filter: Optional[str] = Query(None, alias="severity", description="Filter by severity"),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    membership=Depends(RequireWorkspaceRole()),
    db: Session = Depends(get_db),
) -> List[Incident]:
    """List incidents filtered by workspace, service, status, and severity."""
    query = db.query(Incident).filter(Incident.workspace_id == workspace_id)
    if service_id:
        query = query.filter(Incident.service_id == service_id)
    if status_filter:
        query = query.filter(Incident.status == status_filter)
    if severity_filter:
        query = query.filter(Incident.severity == severity_filter)

    incidents = (
        query.order_by(Incident.detected_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    return incidents


@router.get("/{incident_id}", summary="Get incident detail with event timeline")
def get_incident_detail(
    incident_id: str,
    workspace_id: str = Query(..., description="Workspace ID for authorization"),
    membership=Depends(RequireWorkspaceRole()),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Retrieve detailed incident record and complete chronological event timeline."""
    incident = (
        db.query(Incident)
        .filter(Incident.id == incident_id, Incident.workspace_id == workspace_id)
        .first()
    )
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found in this workspace.",
        )

    service = db.query(Service).filter(Service.id == incident.service_id).first()

    events = (
        db.query(IncidentEvent)
        .filter(IncidentEvent.incident_id == incident.id)
        .order_by(IncidentEvent.timestamp.asc())
        .all()
    )

    formatted_events = []
    for ev in events:
        meta = None
        if ev.metadata_json:
            try:
                meta = json.loads(ev.metadata_json)
            except Exception:
                meta = None
        formatted_events.append({
            "id": ev.id,
            "incident_id": ev.incident_id,
            "event_type": ev.event_type,
            "message": ev.message,
            "metadata": meta,
            "timestamp": ev.timestamp,
        })

    return {
        "incident": IncidentResponse.model_validate(incident),
        "service": {
            "id": service.id if service else incident.service_id,
            "name": service.name if service else "Unknown Service",
            "environment": service.environment if service else "unknown",
        },
        "timeline": formatted_events,
    }


@router.post(
    "",
    response_model=IncidentResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Record an incident",
)
def create_incident(
    payload: IncidentCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Incident:
    """Create a new incident triggered by alert or anomaly."""
    check_workspace_role(
        workspace_id=payload.workspace_id,
        user_id=current_user.id,
        db=db,
        min_role="engineer",
    )

    service = (
        db.query(Service)
        .filter(
            Service.id == payload.service_id,
            Service.workspace_id == payload.workspace_id,
        )
        .first()
    )
    if not service:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Service '{payload.service_id}' not found in workspace '{payload.workspace_id}'",
        )

    incident = Incident(
        workspace_id=payload.workspace_id,
        service_id=payload.service_id,
        title=payload.title,
        severity=payload.severity,
        status=payload.status,
        trigger=payload.trigger,
        summary=payload.summary,
    )
    db.add(incident)
    db.commit()
    db.refresh(incident)
    return incident


@router.post(
    "/{incident_id}/close",
    response_model=IncidentResponse,
    status_code=status.HTTP_200_OK,
    summary="Formally close a recovered or mitigated incident",
)
def close_incident(
    incident_id: str,
    payload: IncidentCloseRequest,
    workspace_id: Optional[str] = Query(None, description="Workspace ID for authorization"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Incident:
    """
    Formally closes an incident that has been successfully recovered or mitigated.
    Records resolution notes, sets closed_at timestamp, and creates an 'incident_closed' timeline event.
    Rejects closure if incident is in active or executing state.
    Repeated closure calls on an already closed incident are handled idempotently.
    """
    target_workspace_id = workspace_id or payload.workspace_id

    if target_workspace_id:
        check_workspace_role(
            workspace_id=target_workspace_id,
            user_id=current_user.id,
            db=db,
            min_role="engineer",
        )
        incident = (
            db.query(Incident)
            .filter(Incident.id == incident_id, Incident.workspace_id == target_workspace_id)
            .first()
        )
        if not incident:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Incident '{incident_id}' not found in workspace '{target_workspace_id}'.",
            )
    else:
        incident = db.query(Incident).filter(Incident.id == incident_id).first()
        if not incident:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Incident '{incident_id}' not found.",
            )
        check_workspace_role(
            workspace_id=incident.workspace_id,
            user_id=current_user.id,
            db=db,
            min_role="engineer",
        )

    # Idempotent closure: if already closed, return without creating duplicate events
    if incident.status == "closed":
        return incident

    # Reject closure of active or executing incidents
    if incident.status not in CLOSABLE_INCIDENT_STATUSES:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"Cannot close incident '{incident_id}' in state '{incident.status}'. "
                f"Only recovered or mitigated incidents can be closed."
            ),
        )

    now_utc = datetime.now(timezone.utc)
    previous_status = incident.status

    incident.status = "closed"
    incident.closed_at = now_utc
    incident.updated_at = now_utc

    # Append resolution notes to summary
    if incident.summary:
        if payload.resolution_notes not in incident.summary:
            incident.summary = f"{incident.summary}\n\nResolution Notes: {payload.resolution_notes}"
    else:
        incident.summary = payload.resolution_notes

    closure_event = IncidentEvent(
        incident_id=incident.id,
        event_type="incident_closed",
        message=f"Incident closed: {payload.resolution_notes}",
        metadata_json=json.dumps({
            "resolution_notes": payload.resolution_notes,
            "closed_by_user_id": current_user.id,
            "closed_by_email": current_user.email,
            "previous_status": previous_status,
        }),
        timestamp=now_utc,
    )

    db.add(incident)
    db.add(closure_event)
    db.commit()
    db.refresh(incident)

    return incident
