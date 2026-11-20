"""API v1 master router."""

from fastapi import APIRouter
from app.api.v1.endpoints import (
    health,
    auth,
    workspaces,
    dashboard,
    services,
    incidents,
    detector,
    investigations,
    remediation,
    playbooks,
)

api_router = APIRouter()

api_router.include_router(health.router, tags=["Health"])
api_router.include_router(auth.router, prefix="/auth", tags=["Authentication"])
api_router.include_router(workspaces.router, prefix="/workspaces", tags=["Workspaces"])
api_router.include_router(dashboard.router, prefix="/dashboard", tags=["Dashboard"])
api_router.include_router(services.router, prefix="/services", tags=["Services"])
api_router.include_router(incidents.router, prefix="/incidents", tags=["Incidents"])
api_router.include_router(detector.router, prefix="/detector", tags=["Detector"])
api_router.include_router(investigations.router, tags=["Investigations"])
api_router.include_router(remediation.router, prefix="/remediation", tags=["Remediation"])
api_router.include_router(playbooks.router, prefix="/playbooks", tags=["Playbooks"])
