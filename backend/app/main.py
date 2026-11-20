"""Main FastAPI application entrypoint for SentinelOps AI."""

import time
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.core.logging import setup_logging, get_logger
from app.api.v1.router import api_router
from app.schemas.health import HealthResponse, DatabaseHealth
from app.db.session import check_db_connectivity
from app.detector.poller import detector_poller
from app.remediation.worker import remediation_worker

# Initialize structured logging
setup_logging(settings.LOG_LEVEL)
logger = get_logger("sentinelops.api")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown lifecycle management."""
    logger.info(
        "Starting %s v%s in %s mode (Debug=%s)",
        settings.PROJECT_NAME,
        settings.VERSION,
        settings.ENVIRONMENT,
        settings.DEBUG,
    )
    # Start autonomous background detector poller
    await detector_poller.start()
    # Start autonomous background remediation worker (Phase 1 / P0.3)
    await remediation_worker.start()
    try:
        yield
    finally:
        # Cancel and await tasks cleanly during application shutdown
        await remediation_worker.stop()
        await detector_poller.stop()
        logger.info("Shutting down %s", settings.PROJECT_NAME)


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="SentinelOps AI - Site Reliability Engineering platform for incident detection, investigation, safe remediation, and recovery verification.",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Request timing and structured logging middleware
@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log incoming requests with execution duration."""
    start_time = time.perf_counter()
    response = await call_next(request)
    duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
    logger.info(
        "%s %s - status %d (%s ms)",
        request.method,
        request.url.path,
        response.status_code,
        duration_ms,
    )
    return response


# Global Exception Handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Catch-all exception handler to ensure sanitized JSON error responses."""
    logger.error("Unhandled exception processing %s %s: %s", request.method, request.url.path, str(exc), exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Internal server error"},
    )


# Root Health Endpoint: GET /health
@app.get(
    "/health",
    response_model=HealthResponse,
    tags=["Health"],
    summary="Root Health Check",
    description="Returns general platform status and database diagnostics.",
)
def root_health() -> HealthResponse:
    """Root health check endpoint."""
    db_ok, db_msg = check_db_connectivity()
    status_str = "healthy" if db_ok else "degraded"

    return HealthResponse(
        status=status_str,
        service=settings.PROJECT_NAME,
        version=settings.VERSION,
        database=DatabaseHealth(
            connected=db_ok,
            message=db_msg,
        ),
    )


# Mount versioned API routes: /api/v1/... (including GET /api/v1/health)
app.include_router(api_router, prefix=settings.API_V1_STR)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)
