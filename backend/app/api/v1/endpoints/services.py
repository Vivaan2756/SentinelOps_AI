"""Service management endpoints with workspace authorization and detail views."""

from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from app.core.config import settings
from app.core.logging import get_logger
from app.db.session import get_db
from app.models.user import User
from app.models.service import Service
from app.models.incident import Incident
from app.schemas.service import ServiceCreate, ServiceResponse, DemoServiceProvisionRequest
from app.schemas.incident import IncidentResponse
from app.remediation.registry import ActionRegistry
from app.remediation.schemas import ServiceCapabilitiesResponse
from app.api.deps import RequireWorkspaceRole, get_current_user, check_workspace_role

logger = get_logger(__name__)

router = APIRouter()


@router.get("", response_model=List[ServiceResponse], summary="List registered services")
def list_services(
    workspace_id: str = Query(..., description="Workspace ID for tenant scoping"),
    q: Optional[str] = Query(None, description="Search query by service name"),
    environment: Optional[str] = Query(None, description="Filter by environment"),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    membership=Depends(RequireWorkspaceRole()),
    db: Session = Depends(get_db),
) -> List[Service]:
    """Retrieve all services belonging to the specified workspace with authorization."""
    query = db.query(Service).filter(Service.workspace_id == workspace_id)
    if q:
        query = query.filter(Service.name.ilike(f"%{q.strip()}%"))
    if environment:
        query = query.filter(Service.environment == environment)

    services = query.order_by(Service.name.asc()).offset(offset).limit(limit).all()
    return services


@router.get("/{service_id}", summary="Get service detail and recent incidents")
def get_service_detail(
    service_id: str,
    workspace_id: str = Query(..., description="Workspace ID for authorization"),
    membership=Depends(RequireWorkspaceRole()),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Retrieve service detail and recent incidents for authorized workspace members."""
    service = (
        db.query(Service)
        .filter(Service.id == service_id, Service.workspace_id == workspace_id)
        .first()
    )
    if not service:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Service '{service_id}' not found in this workspace.",
        )

    recent_incidents = (
        db.query(Incident)
        .filter(Incident.service_id == service.id)
        .order_by(Incident.detected_at.desc())
        .limit(5)
        .all()
    )

    return {
        "service": ServiceResponse.model_validate(service),
        "recent_incidents": [IncidentResponse.model_validate(inc) for inc in recent_incidents],
    }


@router.get(
    "/{service_id}/capabilities",
    response_model=ServiceCapabilitiesResponse,
    summary="Get service remediation capabilities",
    description="Returns evaluated compatible and adapter-dependent remediation capabilities for the registered service. Scoped strictly to workspace.",
)
def get_service_capabilities(
    service_id: str,
    workspace_id: str = Query(..., description="Workspace ID for authorization"),
    membership=Depends(RequireWorkspaceRole()),
    db: Session = Depends(get_db),
) -> ServiceCapabilitiesResponse:
    """Evaluate and return all allowlisted action capabilities for the target service."""
    service = (
        db.query(Service)
        .filter(Service.id == service_id, Service.workspace_id == workspace_id)
        .first()
    )
    if not service:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Service '{service_id}' not found in workspace '{workspace_id}'.",
        )

    return ActionRegistry.discover_service_capabilities(service, db=db)


@router.post(
    "",
    response_model=ServiceResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new service",
    description="Registers service configuration. Requires 'engineer' role or higher. Does NOT probe endpoint.",
)
def create_service(
    payload: ServiceCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Service:
    """Register a new service within a workspace."""
    check_workspace_role(
        workspace_id=payload.workspace_id,
        user_id=current_user.id,
        db=db,
        min_role="engineer",
    )

    # Stage 3.3 Security Boundary: demo_integration cannot be self-assigned via standard registration
    if payload.demo_integration is not None:
        logger.warning(
            "SECURITY AUDIT: Unauthorized attempt to self-assign demo_integration '%s' by user '%s' in workspace '%s'",
            payload.demo_integration,
            current_user.id,
            payload.workspace_id,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="demo_integration cannot be self-assigned through standard service registration. Use authorized demo provisioning.",
        )

    # Check for duplicate service name in same workspace
    existing = (
        db.query(Service)
        .filter(
            Service.workspace_id == payload.workspace_id,
            Service.name == payload.name,
        )
        .first()
    )
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Service with name '{payload.name}' already registered in this workspace.",
        )

    rec_endpoint = payload.recovery_endpoint
    rec_enabled = payload.recovery_enabled
    if rec_endpoint and rec_endpoint.strip():
        rec_enabled = True

    service = Service(
        workspace_id=payload.workspace_id,
        name=payload.name,
        environment=payload.environment,
        health_check_url=payload.health_check_url,
        monitoring_method=payload.monitoring_method,
        execution_policy=payload.execution_policy,
        demo_integration=None,
        recovery_endpoint=rec_endpoint,
        recovery_method=payload.recovery_method if rec_endpoint else None,
        recovery_enabled=rec_enabled,
        health_status="unknown",
    )
    db.add(service)
    db.commit()
    db.refresh(service)

    # Seed generic HTTP recovery playbook if recovery is enabled
    if service.recovery_enabled and service.recovery_endpoint:
        try:
            from app.remediation.playbook_service import PlaybookService
            PlaybookService.ensure_generic_http_recovery_playbook(
                db=db,
                workspace_id=service.workspace_id,
                service_id=service.id,
                user_id=current_user.id,
            )
        except Exception as e:
            logger.warning(
                "Failed to auto-seed generic recovery playbook for service '%s': %s",
                service.id,
                e,
            )

    return service


@router.post(
    "/provision-demo",
    response_model=ServiceResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Provision authorized Order API demo service",
    description="Server-authorized provisioning mechanism for the Order API demo integration. Restricted to workspace admin in development.",
)
def provision_demo_service(
    payload: DemoServiceProvisionRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Service:
    """Explicitly provision an authorized demo service within a workspace."""
    allowed_envs = {"development", "dev", "test", "testing", "local"}
    if settings.ENVIRONMENT.lower() not in allowed_envs or payload.environment != "development":
        logger.warning(
            "SECURITY AUDIT: Blocked demo provisioning outside development environment (app_env=%s, payload_env=%s) by user '%s' in workspace '%s'",
            settings.ENVIRONMENT,
            payload.environment,
            current_user.id,
            payload.workspace_id,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Demo service provisioning is strictly prohibited outside the development environment.",
        )

    # Enforce admin role and workspace membership
    check_workspace_role(
        workspace_id=payload.workspace_id,
        user_id=current_user.id,
        db=db,
        min_role="admin",
    )

    # Check duplicate service name in same workspace
    existing = (
        db.query(Service)
        .filter(
            Service.workspace_id == payload.workspace_id,
            Service.name == payload.name,
        )
        .first()
    )
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Service with name '{payload.name}' already registered in this workspace.",
        )

    rec_endpoint = getattr(payload, "recovery_endpoint", None)
    rec_enabled = bool(rec_endpoint)
    rec_method = (getattr(payload, "recovery_method", "POST") or "POST").upper()

    service = Service(
        workspace_id=payload.workspace_id,
        name=payload.name,
        environment=payload.environment,
        health_check_url=payload.health_check_url,
        monitoring_method=payload.monitoring_method,
        execution_policy=payload.execution_policy,
        demo_integration=payload.demo_integration,
        recovery_endpoint=rec_endpoint,
        recovery_method=rec_method,
        recovery_enabled=rec_enabled,
        health_status="unknown",
    )
    db.add(service)
    db.commit()
    db.refresh(service)

    logger.info(
        "SECURITY AUDIT: Authorized demo integration '%s' provisioned for workspace '%s' by admin user '%s'",
        payload.demo_integration,
        payload.workspace_id,
        current_user.id,
    )
    return service
