"""Health check API endpoints."""

from fastapi import APIRouter
from app.core.config import settings
from app.db.session import check_db_connectivity
from app.schemas.health import HealthResponse, DatabaseHealth

router = APIRouter()


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="System and Database Health Check",
    description="Returns service status, version, and database connectivity state.",
)
def get_v1_health() -> HealthResponse:
    """Return API and database connectivity status."""
    db_ok, db_msg = check_db_connectivity()
    status = "healthy" if db_ok else "degraded"

    return HealthResponse(
        status=status,
        service=settings.PROJECT_NAME,
        version=settings.VERSION,
        database=DatabaseHealth(
            connected=db_ok,
            message=db_msg,
        ),
    )
