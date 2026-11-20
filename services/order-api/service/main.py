"""Demo Order API microservice with deterministic in-memory failure injection and Prometheus telemetry.

Per Blueprint Section 6 (Example Scenario: Order API Failure) & Phase 1 requirements:
- Request counts by method, endpoint, and HTTP status code.
- 5xx error counter for alert rule evaluation.
- Latency histogram with standard duration buckets.
- GET /metrics endpoint exposing Prometheus text format.
- In-memory deterministic failure injection (no external calls or host mutation).
- Authenticated demo controls (/demo/simulate-failure, /demo/restore) protected by secret token.
- Environment-based configuration (PORT, HOST, DEMO_ADMIN_TOKEN) compatible with Render.
"""

import os
import secrets
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, HTTPException, Query, Request, Response, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from prometheus_client import (
    Counter,
    Histogram,
    generate_latest,
    CONTENT_TYPE_LATEST,
    REGISTRY,
)

app = FastAPI(
    title="Order API (Demo Microservice)",
    version="1.0.0",
    description="Sample workload for SentinelOps AI incident detection and remediation testing.",
)

# Prometheus Telemetry Definitions
HTTP_REQUESTS_TOTAL = Counter(
    "order_api_http_requests_total",
    "Total count of HTTP requests processed by Order API",
    ["method", "endpoint", "status_code"],
)

HTTP_5XX_ERRORS_TOTAL = Counter(
    "order_api_http_5xx_errors_total",
    "Total count of HTTP 5xx server errors emitted by Order API",
    ["method", "endpoint"],
)

HTTP_REQUEST_DURATION_SECONDS = Histogram(
    "order_api_http_request_duration_seconds",
    "HTTP request latency in seconds for Order API endpoints",
    ["method", "endpoint"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
)


# In-memory demo state (no system mutations or external calls)
class DemoState:
    def __init__(self):
        self.failure_active: bool = False
        self.error_count: int = 0
        self.failure_reason: str = "Database connection pool exhausted; requests timing out after 5000ms"

    def activate_failure(self, reason: Optional[str] = None):
        self.failure_active = True
        if reason:
            self.failure_reason = reason

    def restore_healthy(self):
        self.failure_active = False
        self.error_count = 0


demo_state = DemoState()


def get_configured_token() -> Optional[str]:
    """Fetch secret administrative token from environment."""
    tok = (
        os.environ.get("DEMO_ADMIN_TOKEN")
        or os.environ.get("ORDER_API_SECRET_TOKEN")
        or ""
    ).strip()
    return tok if tok else None


class SimulateFailurePayload(BaseModel):
    """Optional payload for failure simulation."""
    reason: Optional[str] = None


def verify_admin_auth(request: Request) -> None:
    """
    Verify administrative authentication token for controlled demo operations.
    Enforces strict security requirements:
    1. Fails closed if DEMO_ADMIN_TOKEN is not configured on the service.
    2. Accepts credentials strictly via X-Demo-Token or Bearer Authorization headers.
    3. Rejects query-string, request-body, and URL-path credentials.
    4. Constant-time token comparison (secrets.compare_digest) to prevent timing attacks.
    5. Preserves useful error handling without leaking secrets or expected values.
    """
    expected = get_configured_token()
    if not expected:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Administrative demo controls are disabled: admin token not configured on service.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Reject query-string credentials if passed
    if request.query_params.get("token") or request.query_params.get("secret"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized: query-string credentials are not permitted. Use X-Demo-Token or Bearer Authorization header.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    candidate: Optional[str] = None

    # 1. Header: X-Demo-Token
    x_token = request.headers.get("x-demo-token")
    if x_token:
        candidate = x_token.strip()
    else:
        # 2. Header: Authorization: Bearer <token>
        auth_header = request.headers.get("authorization", "").strip()
        if auth_header.lower().startswith("bearer "):
            candidate = auth_header[7:].strip()

    if not candidate:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized: missing administrative authentication token. Provide X-Demo-Token or Bearer Authorization header.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not secrets.compare_digest(candidate, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized: invalid administrative authentication token.",
            headers={"WWW-Authenticate": "Bearer"},
        )


# Telemetry Middleware: record latency, status codes, and 5xx errors for all requests
@app.middleware("http")
async def telemetry_middleware(request: Request, call_next):
    # Don't track /metrics scraping itself to avoid recursion/skew
    endpoint_path = request.url.path
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
            method=method, endpoint=endpoint_path, status_code=str(status_code)
        ).inc()
        HTTP_REQUEST_DURATION_SECONDS.labels(
            method=method, endpoint=endpoint_path
        ).observe(duration)
        if status_code >= 500:
            HTTP_5XX_ERRORS_TOTAL.labels(
                method=method, endpoint=endpoint_path
            ).inc()


# Schemas
class OrderCreate(BaseModel):
    customer_id: str = Field(..., json_schema_extra={"example": "cust_101"})
    items_count: int = Field(..., ge=1, json_schema_extra={"example": 3})
    total_amount: float = Field(..., gt=0.0, json_schema_extra={"example": 89.50})


class Order(BaseModel):
    id: str
    customer_id: str
    items_count: int
    total_amount: float
    status: str
    created_at: str


# In-memory orders store
orders_db: List[dict] = [
    {
        "id": "ord_001",
        "customer_id": "cust_1001",
        "items_count": 2,
        "total_amount": 45.00,
        "status": "completed",
        "created_at": "2026-10-29T10:00:00Z",
    },
    {
        "id": "ord_002",
        "customer_id": "cust_1002",
        "items_count": 1,
        "total_amount": 19.99,
        "status": "processing",
        "created_at": "2026-10-29T10:05:00Z",
    },
]


@app.get("/metrics", tags=["Telemetry"], summary="Prometheus Metrics Endpoint")
def get_metrics():
    """
    Exposes application metrics in official Prometheus exposition format.
    Compatible with any Prometheus scraper or OpenTelemetry collector.
    """
    return Response(content=generate_latest(REGISTRY), media_type=CONTENT_TYPE_LATEST)


@app.get("/health", tags=["Health"], summary="Service Health Check")
def get_health():
    """
    Returns service health status.
    If failure mode is active, returns HTTP 500 simulating database timeout.
    Publicly accessible without authentication for monitoring probes.
    """
    if demo_state.failure_active:
        demo_state.error_count += 1
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "status": "unhealthy",
                "service": "order-api",
                "error": demo_state.failure_reason,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
        )
    return {
        "status": "healthy",
        "service": "order-api",
        "version": "1.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/orders", tags=["Orders"], summary="List Orders")
def list_orders():
    """Returns orders. Fails with 500 when simulated database timeout is active."""
    if demo_state.failure_active:
        demo_state.error_count += 1
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database timeout: {demo_state.failure_reason}",
        )
    return {"orders": orders_db, "count": len(orders_db)}


@app.post("/orders", tags=["Orders"], status_code=status.HTTP_201_CREATED, summary="Create Order")
def create_order(payload: OrderCreate):
    """Creates a new order. Fails with 500 when simulated failure is active."""
    if demo_state.failure_active:
        demo_state.error_count += 1
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database timeout: {demo_state.failure_reason}",
        )
    new_order = {
        "id": f"ord_{len(orders_db) + 1:03d}",
        "customer_id": payload.customer_id,
        "items_count": payload.items_count,
        "total_amount": payload.total_amount,
        "status": "created",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    orders_db.append(new_order)
    return new_order


# Demo control endpoints
@app.get("/demo/status", tags=["Demo Controls"], summary="Check Failure Mode Status")
def demo_status():
    """Reports whether demo failure mode is active."""
    return {
        "failure_active": demo_state.failure_active,
        "failure_reason": demo_state.failure_reason if demo_state.failure_active else None,
        "error_count": demo_state.error_count,
    }


@app.post("/demo/simulate-failure", tags=["Demo Controls"], summary="Inject Simulated Failure")
async def simulate_failure(
    request: Request,
    reason: Optional[str] = Query(None, description="Optional failure reason description"),
    payload: Optional[SimulateFailurePayload] = None,
):
    """
    Deterministically enables failure mode (HTTP 500 database timeouts).
    Safe in-memory state toggle; does not mutate system or run shell commands.
    Requires administrative authentication via X-Demo-Token or Bearer Authorization header.
    """
    verify_admin_auth(request)
    effective_reason = (payload.reason if payload and payload.reason else reason) or "Database connection pool exhausted; requests timing out after 5000ms"
    demo_state.activate_failure(effective_reason)
    return {
        "status": "failure_injected",
        "failure_active": demo_state.failure_active,
        "failure_reason": demo_state.failure_reason,
        "message": "Order API is now failing with HTTP 500 database timeouts.",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.post("/demo/restore", tags=["Demo Controls"], summary="Restore Normal Healthy Operation")
async def restore_healthy(request: Request):
    """
    Safely restores Order API to normal healthy state.
    Gracefully handles repeated recovery calls:
    - If failure was active, restores healthy state and returns status='restored'.
    - If already healthy, returns status='already_healthy' with HTTP 200 OK.
    Requires administrative authentication via X-Demo-Token or Bearer Authorization header.
    """
    verify_admin_auth(request)
    was_active = demo_state.failure_active
    demo_state.restore_healthy()

    if not was_active:
        return {
            "status": "already_healthy",
            "failure_active": False,
            "message": "Order API is already operating normally. No action needed.",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    return {
        "status": "restored",
        "failure_active": False,
        "message": "Order API has been restored to normal healthy operation.",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", "8001"))
    host = os.environ.get("HOST", "0.0.0.0")
    uvicorn.run("service.main:app", host=host, port=port, reload=False)
