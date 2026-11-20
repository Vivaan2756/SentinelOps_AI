"""Investigation API endpoints for Agentic AI Incident Diagnosis."""

from typing import List, Optional
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.core.config import settings
from app.models.investigation import Investigation
from app.models.incident import Incident
from app.schemas.investigation import (
    InvestigationResponse,
    EvidenceItem,
    Hypothesis,
    StartInvestigationRequest,
)
from app.api.deps import RequireWorkspaceRole
from app.agents.graph import run_investigation

router = APIRouter()


@router.post(
    "/incidents/{incident_id}/investigate",
    response_model=InvestigationResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Start Agentic AI Incident Investigation",
    description="Orchestrates LangGraph investigation: gathers real evidence, generates root-cause hypotheses via Gemini 2.5 Flash, and persists explainable report.",
)
async def start_incident_investigation(
    incident_id: str,
    workspace_id: str = Query(..., description="Workspace ID for tenant authorization"),
    payload: Optional[StartInvestigationRequest] = None,
    membership=Depends(RequireWorkspaceRole(min_role="engineer")),
    db: Session = Depends(get_db),
) -> Investigation:
    """Initiates an automated agentic investigation for an authorized incident."""
    incident = (
        db.query(Incident)
        .filter(Incident.id == incident_id, Incident.workspace_id == workspace_id)
        .first()
    )
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found in workspace '{workspace_id}'.",
        )

    force_refresh = payload.force_refresh if payload else False

    # Prevent duplicate concurrent running investigations
    active_inv = (
        db.query(Investigation)
        .filter(
            Investigation.incident_id == incident.id,
            Investigation.workspace_id == workspace_id,
            Investigation.status.in_(["pending", "running"]),
        )
        .first()
    )
    if (active_inv or incident.status == "investigating") and not force_refresh:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"An active investigation is already in progress for incident '{incident_id}'.",
        )

    if active_inv and force_refresh:
        active_inv.status = "failed"
        active_inv.error_message = "Superseded by force_refresh investigation run."
        db.add(active_inv)
        db.commit()

    # Pre-persist investigation record in 'running' state to block race conditions
    now_utc = datetime.now(timezone.utc)
    new_inv = Investigation(
        incident_id=incident.id,
        workspace_id=workspace_id,
        status="running",
        model_name=settings.GEMINI_MODEL,
        prompt_version=settings.INVESTIGATION_PROMPT_VERSION,
        evidence=[],
        hypotheses=[],
        started_at=now_utc,
    )
    db.add(new_inv)
    db.commit()
    db.refresh(new_inv)

    # Execute LangGraph investigation workflow
    final_state = await run_investigation(
        incident_id=incident.id,
        workspace_id=workspace_id,
        db=db,
        investigation_id=new_inv.id,
    )

    inv_id = final_state.get("investigation_id") or new_inv.id
    investigation = db.query(Investigation).filter(Investigation.id == inv_id).first()
    if not investigation:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Persisted investigation could not be retrieved from database.",
        )

    return investigation


@router.get(
    "/incidents/{incident_id}/investigation",
    response_model=InvestigationResponse,
    summary="Get Latest Investigation for Incident",
)
def get_latest_incident_investigation(
    incident_id: str,
    workspace_id: str = Query(..., description="Workspace ID for authorization"),
    membership=Depends(RequireWorkspaceRole()),
    db: Session = Depends(get_db),
) -> Investigation:
    """Retrieve the most recent investigation report for an incident."""
    # Verify incident exists and belongs to workspace
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

    investigation = (
        db.query(Investigation)
        .filter(
            Investigation.incident_id == incident.id,
            Investigation.workspace_id == workspace_id,
        )
        .order_by(Investigation.created_at.desc())
        .first()
    )
    if not investigation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No investigation has been conducted yet for incident '{incident_id}'.",
        )

    return investigation


@router.get(
    "/investigations/{investigation_id}",
    response_model=InvestigationResponse,
    summary="Get Complete Investigation Report",
)
def get_investigation_detail(
    investigation_id: str,
    workspace_id: str = Query(..., description="Workspace ID for authorization"),
    membership=Depends(RequireWorkspaceRole()),
    db: Session = Depends(get_db),
) -> Investigation:
    """Retrieve full investigation report by investigation ID."""
    investigation = (
        db.query(Investigation)
        .filter(
            Investigation.id == investigation_id,
            Investigation.workspace_id == workspace_id,
        )
        .first()
    )
    if not investigation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation '{investigation_id}' not found in this workspace.",
        )

    return investigation


@router.get(
    "/investigations/{investigation_id}/evidence",
    response_model=List[EvidenceItem],
    summary="Get Evidence Collected for Investigation",
)
def get_investigation_evidence(
    investigation_id: str,
    workspace_id: str = Query(..., description="Workspace ID for authorization"),
    membership=Depends(RequireWorkspaceRole()),
    db: Session = Depends(get_db),
) -> List[EvidenceItem]:
    """Retrieve diagnostic evidence items collected during the investigation."""
    investigation = (
        db.query(Investigation)
        .filter(
            Investigation.id == investigation_id,
            Investigation.workspace_id == workspace_id,
        )
        .first()
    )
    if not investigation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation '{investigation_id}' not found in this workspace.",
        )

    return [EvidenceItem(**item) for item in investigation.evidence]


@router.get(
    "/investigations/{investigation_id}/hypotheses",
    response_model=List[Hypothesis],
    summary="Get Evaluated Hypotheses for Investigation",
)
def get_investigation_hypotheses(
    investigation_id: str,
    workspace_id: str = Query(..., description="Workspace ID for authorization"),
    membership=Depends(RequireWorkspaceRole()),
    db: Session = Depends(get_db),
) -> List[Hypothesis]:
    """Retrieve ranked candidate root-cause hypotheses evaluated in this investigation."""
    investigation = (
        db.query(Investigation)
        .filter(
            Investigation.id == investigation_id,
            Investigation.workspace_id == workspace_id,
        )
        .first()
    )
    if not investigation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation '{investigation_id}' not found in this workspace.",
        )

    return [Hypothesis(**item) for item in investigation.hypotheses]
