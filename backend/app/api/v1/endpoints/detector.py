"""API endpoints for triggering deterministic detection and inspecting lifecycle."""

from typing import List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.models.user import User
from app.models.service import Service
from app.api.deps import get_current_user, check_workspace_role
from app.detector.runner import run_evaluation_for_service, run_evaluation_for_workspace

router = APIRouter()


@router.post(
    "/evaluate/{service_id}",
    summary="Evaluate service and update incident lifecycle",
    description="Deterministically probes the service, applies alert rules, and persists incident state in PostgreSQL.",
)
async def evaluate_service(
    service_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Execute evaluation and incident lifecycle update for a single service."""
    service = db.query(Service).filter(Service.id == service_id).first()
    if not service:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Service '{service_id}' not found",
        )

    # Enforce tenant isolation and minimum 'engineer' role
    check_workspace_role(
        workspace_id=service.workspace_id,
        user_id=current_user.id,
        db=db,
        min_role="engineer",
    )

    result = await run_evaluation_for_service(service_id=service_id, db=db)
    return result.to_dict()


@router.post(
    "/evaluate-workspace/{workspace_id}",
    summary="Evaluate all active services in workspace",
)
async def evaluate_workspace(
    workspace_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> List[Dict[str, Any]]:
    """Execute evaluation across all registered services in a workspace."""
    # Enforce tenant isolation and minimum 'engineer' role
    check_workspace_role(
        workspace_id=workspace_id,
        user_id=current_user.id,
        db=db,
        min_role="engineer",
    )

    results = await run_evaluation_for_workspace(workspace_id=workspace_id, db=db)
    return [r.to_dict() for r in results]
