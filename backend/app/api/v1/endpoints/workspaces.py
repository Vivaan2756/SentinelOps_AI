"""Workspace management and context endpoints."""

from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.models.user import User
from app.models.workspace import Workspace, WorkspaceMembership
from app.schemas.workspace import WorkspaceCreate, WorkspaceResponse
from app.api.deps import get_current_user, RequireWorkspaceRole

router = APIRouter()


@router.get("", response_model=List[WorkspaceResponse], summary="List authorized workspaces")
def list_my_workspaces(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> List[WorkspaceResponse]:
    """Retrieve all workspaces where the current user holds membership."""
    memberships = (
        db.query(WorkspaceMembership)
        .filter(WorkspaceMembership.user_id == current_user.id)
        .all()
    )
    result = []
    for m in memberships:
        ws = db.query(Workspace).filter(Workspace.id == m.workspace_id).first()
        if ws:
            item = WorkspaceResponse(
                id=ws.id,
                name=ws.name,
                slug=ws.slug,
                description=ws.description,
                role=m.role,
                created_at=ws.created_at,
                updated_at=ws.updated_at,
            )
            result.append(item)
    return result


@router.get(
    "/{workspace_id}",
    response_model=WorkspaceResponse,
    summary="Get workspace details",
)
def get_workspace(
    workspace_id: str,
    membership: WorkspaceMembership = Depends(RequireWorkspaceRole()),
    db: Session = Depends(get_db),
) -> WorkspaceResponse:
    """Retrieve specific workspace metadata if user has access."""
    ws = db.query(Workspace).filter(Workspace.id == workspace_id).first()
    return WorkspaceResponse(
        id=ws.id,
        name=ws.name,
        slug=ws.slug,
        description=ws.description,
        role=membership.role,
        created_at=ws.created_at,
        updated_at=ws.updated_at,
    )


@router.post(
    "",
    response_model=WorkspaceResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new workspace",
)
def create_workspace(
    payload: WorkspaceCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> WorkspaceResponse:
    """Create a new tenant workspace and assign current user as admin."""
    existing = db.query(Workspace).filter(Workspace.slug == payload.slug).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Workspace with slug '{payload.slug}' already exists.",
        )

    workspace = Workspace(
        name=payload.name,
        slug=payload.slug,
        description=payload.description,
    )
    db.add(workspace)
    db.flush()

    # Assign creating user as Admin
    membership = WorkspaceMembership(
        workspace_id=workspace.id,
        user_id=current_user.id,
        role="admin",
    )
    db.add(membership)
    db.commit()
    db.refresh(workspace)

    return WorkspaceResponse(
        id=workspace.id,
        name=workspace.name,
        slug=workspace.slug,
        description=workspace.description,
        role="admin",
        created_at=workspace.created_at,
        updated_at=workspace.updated_at,
    )
