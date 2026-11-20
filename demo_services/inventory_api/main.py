
"""Inventory Management API.

Minimal, independently runnable microservice for SentinelOps integration testing.
Includes reversible failure simulation and Prometheus telemetry.
"""

import time
from typing import Any, Dict, List

from fastapi import FastAPI, HTTPException, Request, Response, status
from prometheus_client import (
    CollectorRegistry,
    Counter,
    Histogram,
    generate_latest,
    CONTENT_TYPE_LATEST,
)

# -------------------------------------------------------------------
# Prometheus telemetry
# -------------------------------------------------------------------

metrics_registry = CollectorRegistry()

HTTP_REQUESTS_TOTAL = Counter(
    "http_requests_total",
    "Total count of HTTP requests processed by Inventory Management API",
    ["method", "endpoint", "status_code"],
    registry=metrics_registry,
)

HTTP_5XX_ERRORS_TOTAL = Counter(
    "http_5xx_errors_total",
    "Total count of HTTP 5xx server errors emitted by Inventory Management API",
    ["method", "endpoint"],
    registry=metrics_registry,
)

HTTP_REQUEST_DURATION_SECONDS = Histogram(
    "http_request_duration_seconds",
    "HTTP request latency in seconds for Inventory Management API endpoints",
    ["method", "endpoint"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
    registry=metrics_registry,
)

HTTP_REQUESTS_TOTAL.labels(
    method="GET", endpoint="/api/v1/health", status_code="200"
)
HTTP_5XX_ERRORS_TOTAL.labels(
    method="GET", endpoint="/api/v1/health"
)
HTTP_REQUEST_DURATION_SECONDS.labels(
    method="GET", endpoint="/api/v1/health"
)

# -------------------------------------------------------------------
# Failure simulation state
# -------------------------------------------------------------------

failure_active = False
failure_reason = None
failure_started_at = None

# -------------------------------------------------------------------
# FastAPI application
# -------------------------------------------------------------------

app = FastAPI(
    title="Inventory Management API",
    version="1.0.0",
    description="Independent Inventory Management API for SentinelOps integration testing.",
)


@app.middleware("http")
async def telemetry_middleware(request: Request, call_next):
    """Record latency, status codes, and 5xx errors."""
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
            method=method,
            endpoint=endpoint_path,
            status_code=str(status_code),
        ).inc()

        HTTP_REQUEST_DURATION_SECONDS.labels(
            method=method,
            endpoint=endpoint_path,
        ).observe(duration)

        if status_code >= 500:
            HTTP_5XX_ERRORS_TOTAL.labels(
                method=method,
                endpoint=endpoint_path,
            ).inc()


# -------------------------------------------------------------------
# Root and health endpoints
# -------------------------------------------------------------------

@app.get("/", summary="Service Identification")
def get_root() -> Dict[str, Any]:
    return {
        "service": "Inventory Management API",
        "version": "1.0.0",
        "status": "running",
        "description": "Independent Inventory Management API for SentinelOps integration testing",
    }


@app.get("/api/v1/health", summary="Health Check")
def get_health() -> Dict[str, str]:
    """Returns 503 while the controlled failure is active."""
    if failure_active:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "status": "unhealthy",
                "service": "Inventory Management API",
                "reason": failure_reason,
            },
        )

    return {
        "status": "healthy",
        "service": "Inventory Management API",
    }


@app.get(
    "/health",
    summary="Health Check (Compatibility Alias)",
    include_in_schema=False,
)
def get_health_alias() -> Dict[str, str]:
    return get_health()


# -------------------------------------------------------------------
# SentinelOps demo controls
# -------------------------------------------------------------------

@app.get("/demo/status", summary="Failure Simulation Status")
def get_demo_status() -> Dict[str, Any]:
    """Always remains available so monitoring can inspect the failure."""
    return {
        "service": "Inventory Management API",
        "failure_active": failure_active,
        "failure_reason": failure_reason,
        "failure_started_at": failure_started_at,
        "operational_status": "degraded" if failure_active else "healthy",
    }


@app.post("/demo/simulate-failure", summary="Activate Demo Failure")
def simulate_failure(reason: str = "Simulated inventory database connection failure"):
    """Activate a controlled health-check failure."""
    global failure_active, failure_reason, failure_started_at

    reason = reason.strip()

    if not reason or len(reason) > 200:
        raise HTTPException(
            status_code=400,
            detail="Reason must contain between 1 and 200 characters.",
        )

    failure_active = True
    failure_reason = reason
    failure_started_at = time.time()

    return {
        "message": "Simulated failure activated",
        "failure_active": failure_active,
        "failure_reason": failure_reason,
    }


@app.post("/demo/reset", summary="Reset Demo Failure")
def reset_failure():
    """Restore the service to its normal simulated state."""
    global failure_active, failure_reason, failure_started_at

    failure_active = False
    failure_reason = None
    failure_started_at = None

    return {
        "message": "Failure simulation reset",
        "failure_active": False,
        "operational_status": "healthy",
    }


# -------------------------------------------------------------------
# Prometheus metrics
# -------------------------------------------------------------------

@app.get("/metrics", summary="Prometheus Telemetry Metrics")
def get_metrics() -> Response:
    return Response(
        content=generate_latest(metrics_registry),
        media_type=CONTENT_TYPE_LATEST,
    )


# -------------------------------------------------------------------
# Sample inventory data
# -------------------------------------------------------------------

INVENTORY_ITEMS: Dict[str, Dict[str, Any]] = {
    "inv_001": {
        "id": "inv_001",
        "sku": "SKU-WIDGET-01",
        "name": "Precision Industrial Widget",
        "quantity": 150,
        "price": 19.99,
        "in_stock": True,
    },
    "inv_002": {
        "id": "inv_002",
        "sku": "SKU-SENSOR-02",
        "name": "Environmental Sensor Node",
        "quantity": 85,
        "price": 45.50,
        "in_stock": True,
    },
    "inv_003": {
        "id": "inv_003",
        "sku": "SKU-VALVE-03",
        "name": "High-Pressure Relief Valve",
        "quantity": 20,
        "price": 120.00,
        "in_stock": True,
    },
}


@app.get("/api/v1/items", summary="List Inventory Items")
def list_inventory_items() -> List[Dict[str, Any]]:
    return list(INVENTORY_ITEMS.values())


@app.get("/api/v1/items/{item_id}", summary="Get Inventory Item Details")
def get_inventory_item(item_id: str) -> Dict[str, Any]:
    item = INVENTORY_ITEMS.get(item_id)

    if not item:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Inventory item '{item_id}' not found",
        )

    return item


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host="127.0.0.1",
        port=7000,
        log_level="info",
    )
