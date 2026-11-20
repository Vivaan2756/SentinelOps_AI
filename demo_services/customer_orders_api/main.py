"""Customer Orders API — SentinelOps Fresh Service Acceptance Fixture.

Standalone microservice for testing SentinelOps onboarding, detection,
investigation, and remediation verification on a fresh customer application.

Runs independently on 127.0.0.1:9000.
"""

from datetime import datetime, timezone
import time
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, Request, Response, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from prometheus_client import (
    CollectorRegistry,
    Counter,
    Histogram,
    generate_latest,
    CONTENT_TYPE_LATEST,
)

# -------------------------------------------------------------------
# Prometheus Telemetry Setup
# -------------------------------------------------------------------

metrics_registry = CollectorRegistry()

HTTP_REQUESTS_TOTAL = Counter(
    "http_requests_total",
    "Total count of HTTP requests processed by Customer Orders API",
    ["method", "endpoint", "status_code"],
    registry=metrics_registry,
)

HTTP_5XX_ERRORS_TOTAL = Counter(
    "http_5xx_errors_total",
    "Total count of HTTP 5xx server errors emitted by Customer Orders API",
    ["method", "endpoint"],
    registry=metrics_registry,
)

HTTP_REQUEST_DURATION_SECONDS = Histogram(
    "http_request_duration_seconds",
    "HTTP request latency in seconds for Customer Orders API endpoints",
    ["method", "endpoint"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
    registry=metrics_registry,
)

# Initialize standard labels so they appear in /metrics output immediately
HTTP_REQUESTS_TOTAL.labels(method="GET", endpoint="/health", status_code="200")
HTTP_5XX_ERRORS_TOTAL.labels(method="GET", endpoint="/health")
HTTP_REQUEST_DURATION_SECONDS.labels(method="GET", endpoint="/health")

# -------------------------------------------------------------------
# In-Memory Deterministic Failure State
# -------------------------------------------------------------------

state: Dict[str, Any] = {
    "failure_active": False,
    "failure_reason": None,
    "failure_started_at": None,
    "failure_error_count": 0,
}


def reset_failure_state() -> None:
    """Helper to reset in-memory failure state."""
    state["failure_active"] = False
    state["failure_reason"] = None
    state["failure_started_at"] = None
    state["failure_error_count"] = 0


# -------------------------------------------------------------------
# Request / Response Models
# -------------------------------------------------------------------

class SimulateFailureRequest(BaseModel):
    reason: Optional[str] = "Simulated database connection pool exhaustion"


class OrderItem(BaseModel):
    id: str
    customer_name: str
    items_count: int
    total_usd: float
    status: str
    created_at: str


# Sample order catalog
SAMPLE_ORDERS: List[Dict[str, Any]] = [
    {
        "id": "ord-001",
        "customer_name": "Acme Industries",
        "items_count": 3,
        "total_usd": 349.50,
        "status": "completed",
        "created_at": "2026-11-03T10:00:00Z",
    },
    {
        "id": "ord-002",
        "customer_name": "Global Logistics Corp",
        "items_count": 1,
        "total_usd": 1200.00,
        "status": "processing",
        "created_at": "2026-11-03T11:30:00Z",
    },
    {
        "id": "ord-003",
        "customer_name": "Nexus Retail Systems",
        "items_count": 5,
        "total_usd": 89.95,
        "status": "shipped",
        "created_at": "2026-11-03T14:15:00Z",
    },
]

# -------------------------------------------------------------------
# FastAPI Application & Telemetry Middleware
# -------------------------------------------------------------------

app = FastAPI(
    title="Customer Orders API",
    version="1.0.0",
    description="Standalone Customer Orders acceptance fixture for SentinelOps fresh service onboarding.",
)


@app.middleware("http")
async def telemetry_middleware(request: Request, call_next):
    """Accurately record request latency, response codes, and 5xx errors."""
    endpoint_path = request.url.path

    # Do not track metrics endpoint itself to avoid recursive scrape skew
    if endpoint_path == "/metrics":
        return await call_next(request)

    start_time = time.perf_counter()
    status_code = 500

    try:
        response = await call_next(request)
        status_code = response.status_code
        return response
    except Exception:
        status_code = 500
        raise
    finally:
        duration = time.perf_counter() - start_time
        method = request.method

        HTTP_REQUESTS_TOTAL.labels(
            method=method,
            endpoint=endpoint_path,
            status_code=str(status_code),
        ).inc()

        HTTP_REQUEST_DURATION_SECONDS.labels(
            method=method,
            endpoint=endpoint_path,
        ).observe(duration)

        if 500 <= status_code < 600:
            HTTP_5XX_ERRORS_TOTAL.labels(
                method=method,
                endpoint=endpoint_path,
            ).inc()


# -------------------------------------------------------------------
# Endpoints
# -------------------------------------------------------------------

@app.get(
    "/",
    summary="Service Information",
    description="Returns service identity, version, and endpoints overview.",
)
async def get_root() -> Dict[str, Any]:
    """Root endpoint identifying the service and available endpoints."""
    return {
        "service": "Customer Orders API",
        "version": "1.0.0",
        "description": "Customer Orders service acceptance fixture for SentinelOps automated monitoring, detection, and remediation validation.",
        "status": "running",
        "operational_status": "degraded" if state["failure_active"] else "operational",
        "endpoints": {
            "root": "/",
            "health": "/health",
            "demo_status": "/demo/status",
            "simulate_failure": "POST /demo/simulate-failure",
            "recovery_reset": "POST /admin/recovery/reset",
            "metrics": "/metrics",
            "orders": "/api/v1/orders",
        },
    }


@app.get(
    "/health",
    summary="Service Health Check",
    description="Returns HTTP 200 when operational; HTTP 503 when controlled failure is active.",
)
@app.get("/api/v1/health", include_in_schema=False)
async def get_health() -> JSONResponse:
    """Health check endpoint for synthetic probing and detector monitoring."""
    now_iso = datetime.now(timezone.utc).isoformat()

    if state["failure_active"]:
        state["failure_error_count"] += 1
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "status": "unhealthy",
                "service": "Customer Orders API",
                "operational_status": "degraded",
                "failure_active": True,
                "failure_reason": state["failure_reason"],
                "error_count": state["failure_error_count"],
                "timestamp": now_iso,
            },
        )

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
            "status": "healthy",
            "service": "Customer Orders API",
            "operational_status": "operational",
            "failure_active": False,
            "timestamp": now_iso,
        },
    )


@app.get(
    "/demo/status",
    summary="Failure Simulation Status",
    description="Returns current failure simulation state and error telemetry without altering status.",
)
async def get_demo_status() -> Dict[str, Any]:
    """Inspect failure simulation state."""
    return {
        "service": "Customer Orders API",
        "failure_active": state["failure_active"],
        "failure_reason": state["failure_reason"],
        "operational_status": "degraded" if state["failure_active"] else "operational",
        "error_count": state["failure_error_count"],
        "failure_started_at": state["failure_started_at"],
    }


@app.post(
    "/demo/simulate-failure",
    summary="Simulate Service Failure",
    description="Activates a deterministic simulated failure mode causing /health to return HTTP 503.",
)
async def simulate_failure(payload: Optional[SimulateFailureRequest] = None) -> Dict[str, Any]:
    """Inject a deterministic failure for incident detection testing."""
    reason = (payload.reason if payload and payload.reason else "Simulated database connection pool exhaustion")
    state["failure_active"] = True
    state["failure_reason"] = reason
    state["failure_started_at"] = datetime.now(timezone.utc).isoformat()

    return {
        "success": True,
        "failure_active": True,
        "failure_reason": state["failure_reason"],
        "message": "Deterministic simulated failure activated. /health will return HTTP 503.",
    }


@app.post(
    "/admin/recovery/reset",
    summary="Reset Simulated Failure",
    description="Resets the simulated failure state and restores healthy operational status.",
)
async def reset_recovery() -> Dict[str, Any]:
    """Controlled demo recovery endpoint restoring service to healthy status."""
    reset_failure_state()

    return {
        "success": True,
        "failure_active": False,
        "operational_status": "operational",
        "message": "Simulated failure reset successfully. Service restored to operational state.",
    }


@app.get(
    "/metrics",
    summary="Prometheus Telemetry",
    description="Exposes HTTP request counts, 5xx error counters, and latency histograms.",
)
async def get_metrics() -> Response:
    """Exposes Prometheus text format metrics for scraper ingestion."""
    return Response(
        content=generate_latest(metrics_registry),
        media_type=CONTENT_TYPE_LATEST,
    )


# -------------------------------------------------------------------
# Normal Business Domain Endpoints
# -------------------------------------------------------------------

@app.get(
    "/api/v1/orders",
    summary="List Customer Orders",
    description="Returns standard customer order catalog.",
)
@app.get("/orders", include_in_schema=False)
async def list_orders() -> List[Dict[str, Any]]:
    """Query customer orders catalog."""
    return SAMPLE_ORDERS


@app.get(
    "/api/v1/orders/{order_id}",
    summary="Get Order Detail",
    description="Returns detailed customer order record by ID.",
)
@app.get("/orders/{order_id}", include_in_schema=False)
async def get_order(order_id: str) -> JSONResponse:
    """Query specific customer order."""
    for order in SAMPLE_ORDERS:
        if order["id"] == order_id:
            return JSONResponse(status_code=status.HTTP_200_OK, content=order)

    return JSONResponse(
        status_code=status.HTTP_404_NOT_FOUND,
        content={"detail": f"Order '{order_id}' not found."},
    )
