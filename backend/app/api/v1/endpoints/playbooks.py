"""Dynamic Remediation Playbooks API Endpoints.

Phase 4.1:
- Workspace-isolated, role-protected endpoints for user-configurable playbooks.
- Strict allowlist enforcement against ActionRegistry templates.
- Version history preservation on every spec modification.
- Service-to-playbook association management.
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.api.deps import RequireWorkspaceRole, check_workspace_role, get_current_user
from app.db.session import get_db
from app.models.user import User
from app.remediation.playbook_service import (
    PlaybookService,
    build_playbook_detail_response,
    build_playbook_response,
)
from app.schemas.playbook import (
    PlaybookCreate,
    PlaybookDetailResponse,
    PlaybookResponse,
    PlaybookUpdate,
    PlaybookValidationRequest,
    PlaybookValidationResponse,
    ServicePlaybookAssociationRequest,
    ServicePlaybookAssociationResponse,
)

router = APIRouter()


@router.post(
    "",
    response_model=PlaybookResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new dynamic remediation playbook",
    description="Requires 'engineer' role or higher in the target workspace.",
)
def create_playbook(
    payload: PlaybookCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> PlaybookResponse:
    """Create a new playbook and initial version (v1)."""
    check_workspace_role(
        workspace_id=payload.workspace_id,
        user_id=current_user.id,
        db=db,
        min_role="engineer",
    )
    playbook = PlaybookService.create_playbook(
        db=db,
        user=current_user,
        data=payload,
    )
    return build_playbook_response(playbook)


@router.get(
    "",
    response_model=List[PlaybookResponse],
    summary="List workspace playbooks",
    description="Returns playbooks scoped to the specified workspace.",
)
def list_playbooks(
    workspace_id: str = Query(..., description="Workspace ID for scoping"),
    service_id: Optional[str] = Query(None, description="Filter by associated service ID"),
    is_active: Optional[bool] = Query(None, description="Filter by active status"),
    category: Optional[str] = Query(None, description="Filter by category"),
    q: Optional[str] = Query(None, description="Search query by name"),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    membership=Depends(RequireWorkspaceRole()),
    db: Session = Depends(get_db),
) -> List[PlaybookResponse]:
    """List all playbooks in workspace."""
    playbooks = PlaybookService.list_playbooks(
        db=db,
        workspace_id=workspace_id,
        service_id=service_id,
        is_active=is_active,
        category=category,
        q=q,
        limit=limit,
        offset=offset,
    )
    return [build_playbook_response(pb) for pb in playbooks]


@router.post(
    "/validate",
    response_model=PlaybookValidationResponse,
    summary="Validate playbook configuration",
    description="Validates action template compatibility, schemas, and security invariants without saving. Requires 'engineer' role or higher.",
)
def validate_playbook(
    payload: PlaybookValidationRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> PlaybookValidationResponse:
    """Validate candidate playbook specification."""
    check_workspace_role(
        workspace_id=payload.workspace_id,
        user_id=current_user.id,
        db=db,
        min_role="engineer",
    )
    return PlaybookService.validate_playbook_spec(
        db=db,
        workspace_id=payload.workspace_id,
        action_template_id=payload.action_template_id,
        service_ids=payload.service_ids,
        parameter_schema=payload.parameter_schema,
        verification_criteria=payload.verification_criteria,
        risk_level=payload.risk_level,
    )


@router.get(
    "/services/{service_id}",
    response_model=List[PlaybookResponse],
    summary="Retrieve compatible active playbooks for a service",
    description="Returns all active playbooks bound to the given service, ordered by priority.",
)
def get_playbooks_for_service(
    service_id: str,
    workspace_id: str = Query(..., description="Workspace ID for scoping"),
    scenario: Optional[str] = Query(None, description="Filter by supported incident scenario"),
    membership=Depends(RequireWorkspaceRole()),
    db: Session = Depends(get_db),
) -> List[PlaybookResponse]:
    """Retrieve active playbooks associated with a specific service."""
    playbooks = PlaybookService.get_playbooks_for_service(
        db=db,
        service_id=service_id,
        scenario=scenario,
    )
    return [build_playbook_response(pb) for pb in playbooks]


@router.get(
    "/{playbook_id}",
    response_model=PlaybookDetailResponse,
    summary="Retrieve playbook details with version history and associated services",
)
def get_playbook_detail(
    playbook_id: str,
    workspace_id: str = Query(..., description="Workspace ID for authorization"),
    membership=Depends(RequireWorkspaceRole()),
    db: Session = Depends(get_db),
) -> PlaybookDetailResponse:
    """Retrieve playbook details including full version history and service associations."""
    playbook = PlaybookService.get_playbook(
        db=db,
        workspace_id=workspace_id,
        playbook_id=playbook_id,
    )
    return build_playbook_detail_response(playbook)


@router.put(
    "/{playbook_id}",
    response_model=PlaybookDetailResponse,
    summary="Update a playbook",
    description="Updates playbook metadata or creates a new immutable version if specification changes. Requires 'engineer' role or higher.",
)
def update_playbook(
    playbook_id: str,
    payload: PlaybookUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> PlaybookDetailResponse:
    """Update playbook configuration or create a new version."""
    check_workspace_role(
        workspace_id=payload.workspace_id,
        user_id=current_user.id,
        db=db,
        min_role="engineer",
    )
    playbook = PlaybookService.update_playbook(
        db=db,
        user=current_user,
        playbook_id=playbook_id,
        data=payload,
    )
    return build_playbook_detail_response(playbook)


@router.post(
    "/{playbook_id}/activate",
    response_model=PlaybookResponse,
    summary="Activate a playbook",
    description="Enables a playbook for evaluation and remediation dispatch. Requires 'engineer' role or higher.",
)
def activate_playbook(
    playbook_id: str,
    workspace_id: str = Query(..., description="Workspace ID"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> PlaybookResponse:
    """Activate playbook."""
    check_workspace_role(
        workspace_id=workspace_id,
        user_id=current_user.id,
        db=db,
        min_role="engineer",
    )
    playbook = PlaybookService.toggle_playbook_activation(
        db=db,
        workspace_id=workspace_id,
        playbook_id=playbook_id,
        activate=True,
    )
    return build_playbook_response(playbook)


@router.post(
    "/{playbook_id}/deactivate",
    response_model=PlaybookResponse,
    summary="Deactivate a playbook",
    description="Disables a playbook. Deactivated playbooks fail closed and cannot be proposed or executed. Requires 'engineer' role or higher.",
)
def deactivate_playbook(
    playbook_id: str,
    workspace_id: str = Query(..., description="Workspace ID"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> PlaybookResponse:
    """Deactivate playbook."""
    check_workspace_role(
        workspace_id=workspace_id,
        user_id=current_user.id,
        db=db,
        min_role="engineer",
    )
    playbook = PlaybookService.toggle_playbook_activation(
        db=db,
        workspace_id=workspace_id,
        playbook_id=playbook_id,
        activate=False,
    )
    return build_playbook_response(playbook)


@router.post(
    "/{playbook_id}/services",
    response_model=ServicePlaybookAssociationResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Associate a playbook with a service",
    description="Binds a playbook to an authorized service within the workspace. Requires 'engineer' role or higher.",
)
def associate_service_to_playbook(
    playbook_id: str,
    payload: ServicePlaybookAssociationRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ServicePlaybookAssociationResponse:
    """Associate a service to a playbook."""
    check_workspace_role(
        workspace_id=payload.workspace_id,
        user_id=current_user.id,
        db=db,
        min_role="engineer",
    )
    assoc = PlaybookService.associate_service(
        db=db,
        user=current_user,
        workspace_id=payload.workspace_id,
        playbook_id=playbook_id,
        service_id=payload.service_id,
        priority=payload.priority,
    )
    return ServicePlaybookAssociationResponse(
        id=assoc.id,
        workspace_id=assoc.workspace_id,
        service_id=assoc.service_id,
        service_name=assoc.service.name if assoc.service else "Unknown Service",
        playbook_id=assoc.playbook_id,
        playbook_name=assoc.playbook.name if assoc.playbook else "Unknown Playbook",
        is_active=assoc.is_active,
        priority=assoc.priority,
        created_at=assoc.created_at,
    )


@router.delete(
    "/{playbook_id}/services/{service_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Disassociate a playbook from a service",
    description="Removes the association between a playbook and a service. Requires 'engineer' role or higher.",
)
def disassociate_service_from_playbook(
    playbook_id: str,
    service_id: str,
    workspace_id: str = Query(..., description="Workspace ID"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> None:
    """Disassociate service from playbook."""
    check_workspace_role(
        workspace_id=workspace_id,
        user_id=current_user.id,
        db=db,
        min_role="engineer",
    )
    PlaybookService.disassociate_service(
        db=db,
        workspace_id=workspace_id,
        playbook_id=playbook_id,
        service_id=service_id,
    )
    return None
